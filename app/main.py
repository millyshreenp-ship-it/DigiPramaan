"""FastAPI service for Evidence Intake & Integrity.

Contract for teammates:
  GET /api/cases/{id}/events      -> normalized events (timeline, graph, search)
  GET /api/cases/{id}/evidence    -> evidence inventory + integrity status
  custody.append(conn, ...)       -> log any action into the hash-chained custody log
  auth.require(*roles)            -> FastAPI dependency for role-gated endpoints
"""
import csv, hashlib, html, io, json, uuid
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from fastapi import Depends, FastAPI, File, Form, HTTPException, Request, Response, UploadFile
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles

from . import auth, config, custody, db, integrity
from .parsers import ParseContext, all_parsers, detect, get_parser
from .correlation import build_timeline, build_graph, run_investigator_query

@asynccontextmanager
async def lifespan(_app):
    db.init_db()
    yield

app = FastAPI(title="IDFF Evidence Intake & Integrity", version=config.TOOL_VERSION, lifespan=lifespan,
              docs_url=None, redoc_url=None)
STATIC = Path(__file__).resolve().parent.parent / "static"
from app.trust import routers as trust_routers, cases, rbac, anchors, certificate, tamper, sandbox_routes
app.include_router(trust_routers.router)
app.include_router(anchors.router)
app.include_router(certificate.router)
app.include_router(tamper.router)
app.include_router(cases.router)
app.include_router(sandbox_routes.router)
app.middleware("http")(rbac.case_access_middleware)

WRITE_CASE = ("admin", "investigator", "supervisor")
WRITE_EVIDENCE = ("admin", "investigator", "examiner")
ANY = Depends(auth.current_user)

@app.middleware("http")
async def security(request: Request, call_next):
    if request.url.path.startswith("/api") and request.method not in ("GET", "HEAD", "OPTIONS"):
        if request.headers.get("x-requested-with") != "idff":
            return JSONResponse({"detail": "Missing X-Requested-With header."}, status_code=403)
    resp = await call_next(request)
    resp.headers.update({"X-Content-Type-Options": "nosniff", "X-Frame-Options": "DENY", "Referrer-Policy": "no-referrer",
                         "Content-Security-Policy": "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; img-src 'self' data:; frame-ancestors 'none'"})
    if request.url.path.startswith("/api"):
        resp.headers["Cache-Control"] = "no-store"
    return resp

def _now(): return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
def _ev_public(r) -> dict:
    d = dict(r); d.pop("vault_path", None); return d
def _get_ev(conn, evidence_id):
    r = conn.execute("SELECT * FROM evidence WHERE evidence_id=?", (evidence_id,)).fetchone()
    if not r: raise HTTPException(404, "Evidence not found")
    return r
def _get_case(conn, case_id):
    r = conn.execute("SELECT * FROM cases WHERE case_id=?", (case_id,)).fetchone()
    if not r: raise HTTPException(404, "Case not found")
    return r

# ================= auth & users =================
def _set_cookie(resp: Response, token: str):
    resp.set_cookie(auth.COOKIE, token, httponly=True, samesite="strict", secure=config.COOKIE_SECURE,
                    max_age=config.SESSION_TTL_SECONDS, path="/")

@app.get("/api/auth/status")
def auth_status():
    with db.session() as c:
        return {"needs_setup": c.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 0,
                "tool": config.TOOL_NAME, "version": config.TOOL_VERSION}

@app.post("/api/auth/setup")
def auth_setup(response: Response, username: str = Form(...), full_name: str = Form(""), password: str = Form(...)):
    """First-run only: creates the initial administrator. Refuses once any user exists."""
    auth.validate_new_password(password)
    with db.session() as c:
        if c.execute("SELECT COUNT(*) FROM users").fetchone()[0] > 0:
            raise HTTPException(409, "Setup already completed.")
        cur = c.execute("INSERT INTO users(username,full_name,role,password_hash,active,created_at) VALUES(?,?,?,?,1,?)",
                        (username.strip(), full_name.strip(), "admin", auth.hash_password(password), _now()))
        custody.append(c, actor=username.strip(), action="user_created", detail={"username": username.strip(), "role": "admin", "first_run": True})
        token = auth.create_session(c, cur.lastrowid)
    _set_cookie(response, token)
    return {"ok": True}

@app.post("/api/auth/login")
def auth_login(request: Request, response: Response, username: str = Form(...), password: str = Form(...)):
    key = ((request.client.host if request.client else "?"), username.strip().lower())
    if auth.throttled(key):
        raise HTTPException(429, "Too many failed attempts. Try again in 15 minutes.")
    with db.session() as c:
        u = c.execute("SELECT * FROM users WHERE username=? AND active=1", (username.strip(),)).fetchone()
        if not u or not auth.check_password(password, u["password_hash"]):
            auth.note_failure(key)
            custody.append(c, actor=username.strip()[:64] or "unknown", action="LOGIN_FAILED", detail={"ip": key[0]})
            raise HTTPException(401, "Incorrect username or password.")
        auth.clear_failures(key)
        token = auth.create_session(c, u["user_id"])
        custody.append(c, actor=u["username"], action="login", detail={"ip": key[0]})
    _set_cookie(response, token)
    return {"username": u["username"], "full_name": u["full_name"], "role": u["role"]}

@app.post("/api/auth/logout")
def auth_logout(request: Request, response: Response, user: dict = ANY):
    with db.session() as c:
        auth.end_session(c, request.cookies.get(auth.COOKIE))
        custody.append(c, actor=user["username"], action="logout")
    response.delete_cookie(auth.COOKIE, path="/")
    return {"ok": True}

@app.get("/api/auth/me")
def auth_me(user: dict = ANY):
    return user

@app.post("/api/auth/password")
def change_password(current: str = Form(...), new: str = Form(...), user: dict = ANY):
    auth.validate_new_password(new)
    with db.session() as c:
        row = c.execute("SELECT password_hash FROM users WHERE user_id=?", (user["user_id"],)).fetchone()
        if not auth.check_password(current, row["password_hash"]):
            raise HTTPException(400, "Current password is incorrect.")
        c.execute("UPDATE users SET password_hash=? WHERE user_id=?", (auth.hash_password(new), user["user_id"]))
        custody.append(c, actor=user["username"], action="password_changed")
    return {"ok": True}

@app.get("/api/users")
def list_users(user: dict = Depends(auth.require("admin"))):
    with db.session() as c:
        return [dict(r) for r in c.execute("SELECT user_id,username,full_name,role,active,created_at FROM users ORDER BY username")]

@app.post("/api/users")
def create_user(username: str = Form(...), full_name: str = Form(""), role: str = Form(...), password: str = Form(...),
                user: dict = Depends(auth.require("admin"))):
    if role not in auth.ROLES: raise HTTPException(400, f"Role must be one of {', '.join(auth.ROLES)}")
    if not username.strip().replace("_", "").replace(".", "").replace("-", "").isalnum(): raise HTTPException(400, "Username may use letters, numbers, . _ -")
    auth.validate_new_password(password)
    with db.session() as c:
        if c.execute("SELECT 1 FROM users WHERE username=?", (username.strip(),)).fetchone():
            raise HTTPException(409, "That username is taken.")
        c.execute("INSERT INTO users(username,full_name,role,password_hash,active,created_at) VALUES(?,?,?,?,1,?)",
                  (username.strip(), full_name.strip(), role, auth.hash_password(password), _now()))
        custody.append(c, actor=user["username"], action="user_created", detail={"username": username.strip(), "role": role})
    return {"ok": True}

@app.post("/api/users/{user_id}/active")
def set_active(user_id: int, active: int = Form(...), user: dict = Depends(auth.require("admin"))):
    with db.session() as c:
        t = c.execute("SELECT * FROM users WHERE user_id=?", (user_id,)).fetchone()
        if not t: raise HTTPException(404, "User not found")
        if t["user_id"] == user["user_id"]: raise HTTPException(400, "You cannot disable your own account.")
        c.execute("UPDATE users SET active=? WHERE user_id=?", (1 if active else 0, user_id))
        if not active: auth.end_user_sessions(c, user_id)
        custody.append(c, actor=user["username"], action="user_enabled" if active else "user_disabled", detail={"username": t["username"]})
    return {"ok": True}

@app.post("/api/users/{user_id}/password")
def reset_password(user_id: int, new: str = Form(...), user: dict = Depends(auth.require("admin"))):
    auth.validate_new_password(new)
    with db.session() as c:
        t = c.execute("SELECT * FROM users WHERE user_id=?", (user_id,)).fetchone()
        if not t: raise HTTPException(404, "User not found")
        c.execute("UPDATE users SET password_hash=? WHERE user_id=?", (auth.hash_password(new), user_id))
        auth.end_user_sessions(c, user_id)
        custody.append(c, actor=user["username"], action="password_reset", detail={"username": t["username"]})
    return {"ok": True}

# ================= cases =================
# ================= acquisition =================
@app.post("/api/cases/{case_id}/evidence")
def upload_evidence(case_id: str, file: UploadFile = File(...), source_type: str = Form("log"),
                    acquisition_method: str = Form("file upload"), custodian: str = Form(""), notes: str = Form(""),
                    expected_sha256: str = Form(""), original_timestamp: str = Form(""),
                    user: dict = Depends(auth.require(*WRITE_EVIDENCE))):
    declared = integrity.normalize_hash(expected_sha256)
    if declared == "INVALID":
        raise HTTPException(400, "The declared hash must be 64 hexadecimal characters (SHA-256).")
    with db.session() as c:
        _get_case(c, case_id)
    evidence_id = integrity.new_evidence_id()
    try:
        stored = integrity.store_stream(evidence_id, file.file, file.filename or "unnamed")
    except integrity.TooLarge:
        raise HTTPException(413, f"File exceeds the {config.MAX_UPLOAD_BYTES // 1024 ** 2} MB upload limit.")
    match = None if declared is None else int(declared == stored["sha256"])
    with db.session() as c:
        dup = c.execute("SELECT evidence_id FROM evidence WHERE case_id=? AND sha256=?", (case_id, stored["sha256"])).fetchone()
        c.execute("""INSERT INTO evidence(evidence_id,case_id,filename,source_type,acquisition_method,custodian,notes,size,
                     sha256,sha512,declared_sha256,declared_match,original_timestamp,ingested_at,vault_path,integrity_status,last_verified_at)
                     VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                  (evidence_id, case_id, file.filename, source_type, acquisition_method, custodian, notes, stored["size"],
                   stored["sha256"], stored["sha512"], declared, match, original_timestamp or None, _now(),
                   stored["vault_path"], "VERIFIED", _now()))
        custody.append(c, actor=user["username"], action="evidence_acquired", case_id=case_id, evidence_id=evidence_id,
                       detail={"filename": file.filename, "size": stored["size"], "sha256": stored["sha256"],
                               "sha512": stored["sha512"], "declared_sha256": declared, "declared_match": match,
                               "custodian": custodian, "acquisition_method": acquisition_method,
                               "duplicate_of": dup["evidence_id"] if dup else None,
                               "tool": f"{config.TOOL_NAME} {config.TOOL_VERSION}"})
        row = _get_ev(c, evidence_id)
    out = _ev_public(row); out["duplicate_of"] = dup["evidence_id"] if dup else None
    return out

@app.get("/api/cases/{case_id}/evidence")
def list_evidence(case_id: str, user: dict = ANY):
    with db.session() as c:
        _get_case(c, case_id)
        return [_ev_public(r) for r in c.execute("SELECT * FROM evidence WHERE case_id=? ORDER BY ingested_at", (case_id,))]

# ================= integrity =================
def _verify_and_record(c, row, actor) -> dict:
    result = integrity.verify(row)
    c.execute("UPDATE evidence SET integrity_status=?, last_verified_at=? WHERE evidence_id=?", (result["status"], _now(), row["evidence_id"]))
    custody.append(c, actor=actor, action="integrity_verified" if result["status"] == "VERIFIED" else "INTEGRITY_FAILURE",
                   case_id=row["case_id"], evidence_id=row["evidence_id"],
                   detail={"status": result["status"], "expected_sha256": result["expected_sha256"], "actual_sha256": result["actual_sha256"]})
    return {"evidence_id": row["evidence_id"], "filename": row["filename"], **result}

@app.post("/api/evidence/{evidence_id}/verify")
def verify_one(evidence_id: str, user: dict = ANY):
    rbac.check_evidence_access(evidence_id, user)
    with db.session() as c:
        return _verify_and_record(c, _get_ev(c, evidence_id), user["username"])

@app.post("/api/cases/{case_id}/verify-all")
def verify_all(case_id: str, user: dict = ANY):
    with db.session() as c:
        _get_case(c, case_id)
        results = [_verify_and_record(c, r, user["username"]) for r in c.execute("SELECT * FROM evidence WHERE case_id=?", (case_id,)).fetchall()]
    return {"all_verified": all(r["status"] == "VERIFIED" for r in results), "results": results}

@app.get("/api/cases/{case_id}/manifest")
def manifest(case_id: str, user: dict = ANY):
    """Portable acquisition manifest; its own SHA-256 is included so it can be checked without this tool."""
    with db.session() as c:
        case = _get_case(c, case_id)
        items = [{k: r[k] for k in ("evidence_id", "filename", "size", "sha256", "sha512", "source_type", "acquisition_method",
                                    "custodian", "ingested_at", "declared_sha256", "declared_match")}
                 for r in c.execute("SELECT * FROM evidence WHERE case_id=? ORDER BY ingested_at", (case_id,))]
        chain = custody.verify_chain(c)
    body = {"case_id": case_id, "title": case["title"], "generated_at": _now(), "generated_by": user["username"],
            "tool": f"{config.TOOL_NAME} {config.TOOL_VERSION}", "evidence": items,
            "custody_chain_head": chain["head"], "custody_chain_intact": chain["intact"]}
    body["manifest_sha256"] = hashlib.sha256(json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()).hexdigest()
    return JSONResponse(body, headers={"Content-Disposition": f'attachment; filename="{case_id}-manifest.json"'})

@app.get("/api/evidence/{evidence_id}/certificate", response_class=HTMLResponse)
def certificate(evidence_id: str, user: dict = ANY):
    """Printable integrity record for one evidence item (use the browser's Print > Save as PDF)."""
    rbac.check_evidence_access(evidence_id, user)
    with db.session() as c:
        e = _get_ev(c, evidence_id); case = _get_case(c, e["case_id"])
        live = integrity.verify(e)
        log = [dict(r) for r in c.execute("SELECT * FROM custody_log WHERE evidence_id=? ORDER BY seq", (evidence_id,))]
        chain = custody.verify_chain(c)
    h = html.escape
    rows = "".join(f"<tr><td>{r['seq']}</td><td>{h(r['ts'][:19].replace('T', ' '))}</td><td>{h(r['actor'])}</td><td>{h(r['action'])}</td><td class='m'>{h(r['entry_hash'][:20])}…</td></tr>" for r in log)
    ok = live["status"] == "VERIFIED"
    page = f"""<!doctype html><html lang="en"><head><meta charset="utf-8"><title>Integrity record {h(evidence_id)}</title><style>
body{{font:14px/1.5 system-ui,sans-serif;max-width:820px;margin:30px auto;padding:0 20px;color:#16212B}}
h1{{font-size:20px;margin:0 0 4px}} h2{{font-size:15px;margin:22px 0 6px;border-bottom:1px solid #CFD7DF;padding-bottom:4px}}
dl{{display:grid;grid-template-columns:170px 1fr;gap:4px 14px}} dt{{color:#5B6B79}} dd{{margin:0;word-break:break-all}}
.m{{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:12.5px}} table{{border-collapse:collapse;width:100%}}
td,th{{border-bottom:1px solid #E1E7ED;padding:5px 8px;text-align:left;font-size:13px}}
.st{{display:inline-block;padding:2px 10px;border-radius:999px;font-weight:700;background:{'#DDF2EC' if ok else '#FBE4E1'};color:{'#0B7A62' if ok else '#B3261E'}}}
.note{{font-size:12.5px;color:#5B6B79;margin-top:26px;border-top:1px solid #CFD7DF;padding-top:10px}}
@media print{{body{{margin:0}}}}</style></head><body>
<h1>Evidence Integrity Record</h1><div>{h(case['case_id'])} · {h(case['title'])}</div>
<h2>Current status</h2><p><span class="st">{h(live['status'])}</span> re-hashed from the vault at {h(_now())} by {h(user['username'])}</p>
<h2>Evidence item</h2><dl>
<dt>Evidence ID</dt><dd class="m">{h(e['evidence_id'])}</dd><dt>File name</dt><dd>{h(e['filename'])}</dd>
<dt>Size</dt><dd>{e['size']:,} bytes</dd><dt>SHA-256 (recorded)</dt><dd class="m">{h(e['sha256'])}</dd>
<dt>SHA-256 (just computed)</dt><dd class="m">{h(live['actual_sha256'] or 'file missing')}</dd><dt>SHA-512 (recorded)</dt><dd class="m">{h(e['sha512'])}</dd>
<dt>Source / method</dt><dd>{h(e['source_type'] or '')} / {h(e['acquisition_method'] or '')}</dd><dt>Custodian</dt><dd>{h(e['custodian'] or 'not recorded')}</dd>
<dt>Acquired (UTC)</dt><dd>{h(e['ingested_at'])}</dd><dt>Hash declared by acquirer</dt><dd class="m">{h(e['declared_sha256'] or 'none supplied')}{' (matches)' if e['declared_match']==1 else ' (DOES NOT MATCH)' if e['declared_match']==0 else ''}</dd>
<dt>Notes</dt><dd>{h(e['notes'] or '')}</dd></dl>
<h2>Custody log for this item</h2><table><tr><th>#</th><th>When (UTC)</th><th>Who</th><th>Action</th><th>Entry hash</th></tr>{rows}</table>
<p>Custody chain across the whole system: <b>{'intact' if chain['intact'] else 'BROKEN at entry ' + str(chain['first_broken_seq'])}</b> ({chain['entries_checked']} entries; head {h(chain['head'][:20])}…)</p>
<p class="note">Generated by {h(config.TOOL_NAME)} {h(config.TOOL_VERSION)}. This record reports technical hash and custody facts only. Whether it satisfies Section 63 of the Bharatiya Sakshya Adhiniyam
(formerly Section 65B, Indian Evidence Act) is a legal determination: have qualified counsel review and add any certificate wording the court requires.</p></body></html>"""
    return HTMLResponse(page)

# ================= parsing =================
@app.get("/api/parsers")
def parsers(user: dict = ANY):
    return [{"name": p.name, "version": p.version, "artifact_type": p.artifact_type, "description": p.description} for p in all_parsers()]

@app.post("/api/evidence/{evidence_id}/parse")
def parse_evidence(evidence_id: str, parser: str = Form(""), tz: str = Form("Asia/Kolkata"), assume_year: int | None = Form(None),
                   user: dict = Depends(auth.require(*WRITE_EVIDENCE))):
    rbac.check_evidence_access(evidence_id, user)
    with db.session() as c:
        row = _get_ev(c, evidence_id)
        check = _verify_and_record(c, row, user["username"])    # Acquire -> Verify -> Parse gate
    if check["status"] != "VERIFIED":
        raise HTTPException(409, f"Integrity check {check['status']}: refusing to parse. Expected {check['expected_sha256']}, got {check['actual_sha256']}.")
    try:
        from zoneinfo import ZoneInfo; ZoneInfo(tz)
    except Exception:
        raise HTTPException(400, f"Unknown timezone '{tz}'.")
    path = Path(row["vault_path"])
    ctx = ParseContext(filename=row["filename"], tz=tz, assume_year=assume_year)
    if parser:
        p = get_parser(parser)
        if not p: raise HTTPException(400, f"Unknown parser '{parser}'")
        conf = None
    else:
        p, conf = detect(path, ctx)
        if not p: raise HTTPException(422, "No parser recognised this file. Choose a parser manually, or the format is not supported yet.")
    try:
        result = p.parse(path, ctx)
    except Exception as e:
        raise HTTPException(422, f"Parser '{p.name}' failed: {e}")
    ev_dicts = [e.__dict__ for e in result.events]
    derived = hashlib.sha256(json.dumps(ev_dicts, sort_keys=True, default=str).encode()).hexdigest()
    artifact_id = "ART-" + uuid.uuid4().hex[:10].upper()
    notes = list(result.notes)
    if result.lines_unparsed:
        notes.append(f"{result.lines_unparsed} of {result.lines_total} lines could not be parsed and were skipped.")
    with db.session() as c:
        old = c.execute("SELECT artifact_id FROM artifacts WHERE evidence_id=? AND status='active'", (evidence_id,)).fetchall()
        if old:   # re-parse: derived events are regenerable, so replace them; old artifact records are kept as 'superseded'
            c.execute("UPDATE artifacts SET status='superseded' WHERE evidence_id=? AND status='active'", (evidence_id,))
            c.execute("DELETE FROM events WHERE evidence_id=?", (evidence_id,))
        c.execute("INSERT INTO artifacts VALUES(?,?,?,?,?,?,?,?,?,?,?,'active')",
                  (artifact_id, evidence_id, p.artifact_type, p.name, p.version, derived, row["sha256"], len(result.events),
                   json.dumps({"tz": tz, "assume_year": assume_year}), json.dumps(notes), _now()))
        c.executemany("INSERT INTO events VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", [
            ("EVT-" + uuid.uuid4().hex[:12].upper(), row["case_id"], evidence_id, artifact_id, e.event_type, e.summary,
             e.original_time, e.normalized_time, e.timezone, e.uncertainty_seconds, e.time_quality, e.source_ref,
             e.raw, json.dumps(e.fields, default=str), json.dumps(e.entities)) for e in result.events])
        custody.append(c, actor=user["username"], action="artifact_parsed", case_id=row["case_id"], evidence_id=evidence_id,
                       detail={"artifact_id": artifact_id, "parser": p.name, "parser_version": p.version, "events": len(result.events),
                               "derived_hash": derived, "parent_sha256": row["sha256"], "tz": tz, "assume_year": assume_year,
                               "supersedes": [o["artifact_id"] for o in old]})
    return {"artifact_id": artifact_id, "parser": p.name, "parser_version": p.version, "detect_confidence": conf,
            "event_count": len(result.events), "derived_hash": derived, "parent_sha256": row["sha256"], "notes": notes}

@app.get("/api/evidence/{evidence_id}/artifacts")
def artifacts(evidence_id: str, user: dict = ANY):
    rbac.check_evidence_access(evidence_id, user)
    with db.session() as c:
        _get_ev(c, evidence_id)
        out = []
        for r in c.execute("SELECT * FROM artifacts WHERE evidence_id=? ORDER BY created_at DESC", (evidence_id,)):
            d = dict(r); d["notes"] = json.loads(d["notes"] or "[]"); d["params"] = json.loads(d["params"] or "{}"); out.append(d)
        return out

def csv_safe(v) -> str:
    """Neutralise spreadsheet formula injection: log text is attacker-controlled and exports get opened in Excel."""
    v = "" if v is None else str(v)
    return "'" + v if v[:1] in ("=", "+", "-", "@", "\t", "\r") else v

def _event_query(case_id, q, event_type, evidence_id):
    sql, args = "FROM events WHERE case_id=?", [case_id]
    if q: sql += " AND (summary LIKE ? OR raw LIKE ?)"; args += [f"%{q}%", f"%{q}%"]
    if event_type: sql += " AND event_type=?"; args.append(event_type)
    if evidence_id: sql += " AND evidence_id=?"; args.append(evidence_id)
    return sql, args

@app.get("/api/cases/{case_id}/events")
def events(case_id: str, q: str = "", event_type: str = "", evidence_id: str = "", limit: int = 200, offset: int = 0, user: dict = ANY):
    where, args = _event_query(case_id, q, event_type, evidence_id)
    with db.session() as c:
        _get_case(c, case_id)
        total = c.execute("SELECT COUNT(*) " + where, args).fetchone()[0]
        rows = c.execute("SELECT * " + where + " ORDER BY normalized_time, event_id LIMIT ? OFFSET ?", args + [max(1, min(limit, 5000)), max(0, offset)]).fetchall()
        types = [r[0] for r in c.execute("SELECT DISTINCT event_type FROM events WHERE case_id=? ORDER BY 1", (case_id,))]
    out = []
    for r in rows:
        d = dict(r); d["fields"] = json.loads(d["fields"] or "{}"); d["entities"] = json.loads(d["entities"] or "[]"); out.append(d)
    return {"total": total, "event_types": types, "events": out}

@app.get("/api/cases/{case_id}/events.csv")
def events_csv(case_id: str, q: str = "", event_type: str = "", evidence_id: str = "", user: dict = ANY):
    where, args = _event_query(case_id, q, event_type, evidence_id)
    with db.session() as c:
        _get_case(c, case_id)
        rows = c.execute("SELECT * " + where + " ORDER BY normalized_time, event_id", args).fetchall()
        custody.append(c, actor=user["username"], action="events_exported", case_id=case_id, detail={"rows": len(rows), "q": q, "event_type": event_type})
    buf = io.StringIO(); w = csv.writer(buf)
    w.writerow(["event_id", "evidence_id", "event_type", "normalized_time_utc", "original_time", "timezone", "time_quality", "source_ref", "summary", "raw"])
    for r in rows:
        w.writerow([csv_safe(r[k]) for k in ("event_id", "evidence_id", "event_type", "normalized_time", "original_time", "timezone", "time_quality", "source_ref", "summary", "raw")])
    return StreamingResponse(iter([buf.getvalue()]), media_type="text/csv",
                             headers={"Content-Disposition": f'attachment; filename="{case_id}-events.csv"'})


# ================= & Correlation =================
@app.get("/api/cases/{case_id}/timeline")
def timeline(
    case_id: str,
    bucket_seconds: int = 60,
    skew: str = "",
    q: str = "",
    event_type: str = "",
    evidence_id: str = "",
    limit: int = 5000,
    user: dict = ANY,
):
    """Unified timeline. Optional skew=evidence_id:seconds,evidence_id:seconds for clock-skew demo."""
    where, args = _event_query(case_id, q, event_type, evidence_id)
    with db.session() as c:
        _get_case(c, case_id)
        rows = c.execute(
            "SELECT * " + where + " ORDER BY normalized_time, event_id LIMIT ?",
            args + [max(1, min(limit, 10000))],
        ).fetchall()
        events = []
        for r in rows:
            d = dict(r)
            d["fields"] = json.loads(d.get("fields") or "{}")
            d["entities"] = json.loads(d.get("entities") or "[]")
            events.append(d)
        evidence_map = {
            r["evidence_id"]: dict(r)
            for r in c.execute("SELECT * FROM evidence WHERE case_id=?", (case_id,))
        }
    skew_map = {}
    if skew:
        for part in skew.split(","):
            part = part.strip()
            if ":" not in part:
                continue
            eid, sec = part.split(":", 1)
            try:
                skew_map[eid.strip()] = float(sec)
            except ValueError:
                pass
    result = build_timeline(events, evidence_map, bucket_seconds=max(1, min(bucket_seconds, 86400)), skew_map=skew_map)
    return result


@app.get("/api/cases/{case_id}/graph")
def graph(
    case_id: str,
    q: str = "",
    event_type: str = "",
    evidence_id: str = "",
    max_events: int = 500,
    sequential_window: float = 120.0,
    user: dict = ANY,
):
    """Evidence graph: nodes (evidence/event/entity) + edges (contains/mentions/sequential/same_entity)."""
    where, args = _event_query(case_id, q, event_type, evidence_id)
    with db.session() as c:
        _get_case(c, case_id)
        rows = c.execute(
            "SELECT * " + where + " ORDER BY normalized_time, event_id LIMIT ?",
            args + [max(1, min(max_events * 2, 10000))],
        ).fetchall()
        events = []
        for r in rows:
            d = dict(r)
            d["fields"] = json.loads(d.get("fields") or "{}")
            d["entities"] = json.loads(d.get("entities") or "[]")
            events.append(d)
        evidence_list = [dict(r) for r in c.execute("SELECT * FROM evidence WHERE case_id=?", (case_id,))]
    return build_graph(events, evidence_list, max_events=max(10, min(max_events, 2000)), sequential_window_seconds=sequential_window)


@app.get("/api/cases/{case_id}/query")
def investigator_query(
    case_id: str,
    q: str = "",
    event_type: str = "",
    entity: str = "",
    entity_type: str = "",
    evidence_id: str = "",
    time_from: str = "",
    time_to: str = "",
    time_quality: str = "",
    limit: int = 200,
    offset: int = 0,
    user: dict = ANY,
):
    """Investigator query interface with facets for progressive refinement."""
    types = [t.strip() for t in event_type.split(",") if t.strip()] if event_type else None
    with db.session() as c:
        _get_case(c, case_id)
        return run_investigator_query(
            c, case_id,
            q=q, event_types=types, entity=entity, entity_type=entity_type,
            evidence_id=evidence_id, time_from=time_from, time_to=time_to,
            time_quality=time_quality, limit=limit, offset=offset,
        )


# ================= custody =================
@app.get("/api/cases/{case_id}/custody")
def custody_log(case_id: str, user: dict = ANY):
    with db.session() as c:
        _get_case(c, case_id)
        rows = [dict(r) for r in c.execute("SELECT * FROM custody_log WHERE case_id=? ORDER BY seq", (case_id,))]
        for r in rows: r["detail"] = json.loads(r["detail"] or "{}")
        return {"chain": custody.verify_chain(c), "entries": rows}

@app.get("/api/custody/verify")
def custody_verify(user: dict = ANY):
    with db.session() as c:
        return custody.verify_chain(c)

@app.get("/api/health")
def health():
    return {"ok": True, "version": config.TOOL_VERSION}

app.mount("/static", StaticFiles(directory=STATIC), name="static")

@app.get("/")
def index():
    return FileResponse(STATIC / "index.html")
