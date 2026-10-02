import hashlib, importlib, io, json, os, sqlite3, sys
from pathlib import Path
import pytest
from fastapi.testclient import TestClient

ROOT = Path(__file__).resolve().parent.parent
SAMPLES = ROOT / "samples_for_testing"
sys.path.insert(0, str(ROOT))
PW = "correct-horse-battery"

def fresh_app(tmp_path, monkeypatch):
    monkeypatch.setenv("FORENSIC_DATA_DIR", str(tmp_path))
    for m in [m for m in sys.modules if m == "app" or m.startswith("app.")]:
        del sys.modules[m]
    return importlib.import_module("app.main")

@pytest.fixture()
def client(tmp_path, monkeypatch):
    """Signed-in administrator."""
    main = fresh_app(tmp_path, monkeypatch)
    with TestClient(main.app, headers={"X-Requested-With": "idff"}) as c:
        assert c.post("/api/auth/setup", data={"username": "admin", "password": PW}).status_code == 200
        yield c

@pytest.fixture()
def anon(tmp_path, monkeypatch):
    main = fresh_app(tmp_path, monkeypatch)
    with TestClient(main.app, headers={"X-Requested-With": "idff"}) as c:
        yield c

def vault_file(tmp_path, ev):
    return tmp_path / "vault" / ev / "master.bin"
def mk_case(c):
    return c.post("/api/cases", data={"title": "T"}).json()["case_id"]
def upload(c, case, name, data, **form):
    return c.post(f"/api/cases/{case}/evidence", files={"file": (name, io.BytesIO(data))}, data=form)
def tamper(tmp_path, ev):   # simulate an attacker / disk fault editing the vault file directly
    p = vault_file(tmp_path, ev); p.chmod(0o644)
    b = p.read_bytes(); p.write_bytes(bytes([b[0] ^ 1]) + b[1:])

# ---------------- auth ----------------
def test_everything_requires_login(anon):
    assert anon.get("/api/auth/status").json()["needs_setup"] is True
    for path in ("/api/cases", "/api/users", "/api/parsers", "/api/custody/verify"):
        assert anon.get(path).status_code == 401

def test_setup_only_once_and_login_flow(anon):
    assert anon.post("/api/auth/setup", data={"username": "a", "password": "short"}).status_code == 400
    assert anon.post("/api/auth/setup", data={"username": "root", "password": PW}).status_code == 200
    assert anon.post("/api/auth/setup", data={"username": "x", "password": PW}).status_code == 409
    assert anon.get("/api/auth/me").json()["role"] == "admin"
    anon.post("/api/auth/logout"); assert anon.get("/api/cases").status_code == 401
    assert anon.post("/api/auth/login", data={"username": "root", "password": "wrong-password"}).status_code == 401
    assert anon.post("/api/auth/login", data={"username": "ROOT", "password": PW}).status_code == 200

def test_login_lockout(anon):
    anon.post("/api/auth/setup", data={"username": "root", "password": PW}); anon.post("/api/auth/logout")
    for _ in range(5):
        assert anon.post("/api/auth/login", data={"username": "root", "password": "nope-nope-nope"}).status_code == 401
    assert anon.post("/api/auth/login", data={"username": "root", "password": PW}).status_code == 429

def test_csrf_header_required(client):
    r = client.post("/api/cases", data={"title": "x"}, headers={"X-Requested-With": ""})
    assert r.status_code == 403

def test_roles_enforced(client, tmp_path, monkeypatch):
    for name, role in (("aud", "auditor"), ("exam", "examiner")):
        assert client.post("/api/users", data={"username": name, "role": role, "password": PW}).status_code == 200
    case = mk_case(client)
    client.post("/api/auth/logout")
    client.post("/api/auth/login", data={"username": "aud", "password": PW})
    assert upload(client, case, "a.log", b"x").status_code == 403           # auditor: read only
    assert client.post("/api/cases", data={"title": "n"}).status_code == 403
    assert client.get("/api/users").status_code == 403
    assert client.get(f"/api/cases/{case}/evidence").status_code == 200
    client.post("/api/auth/logout")
    client.post("/api/auth/login", data={"username": "exam", "password": PW})
    ev = upload(client, case, "a.log", b"x")
    assert ev.status_code == 200
    assert client.post("/api/cases", data={"title": "n"}).status_code == 403  # examiner can't open cases

def test_disabled_user_loses_session(client):
    client.post("/api/users", data={"username": "bob", "role": "reviewer", "password": PW})
    uid = [u for u in client.get("/api/users").json() if u["username"] == "bob"][0]["user_id"]
    assert client.post(f"/api/users/{uid}/active", data={"active": 0}).status_code == 200
    me = [u for u in client.get("/api/users").json() if u["username"] == "admin"][0]["user_id"]
    assert client.post(f"/api/users/{me}/active", data={"active": 0}).status_code == 400

# ---------------- integrity ----------------
def test_hashes_match_hashlib(client):
    case = mk_case(client)
    data = os.urandom(3 * 1024 * 1024 + 17)
    r = upload(client, case, "img.dd", data).json()
    assert r["sha256"] == hashlib.sha256(data).hexdigest() and r["sha512"] == hashlib.sha512(data).hexdigest()
    assert r["size"] == len(data) and "vault_path" not in r

def test_vault_read_only_and_actor_recorded(client, tmp_path):
    case = mk_case(client)
    ev = upload(client, case, "a.log", b"hello", custodian="SI Verma").json()["evidence_id"]
    assert oct(vault_file(tmp_path, ev).stat().st_mode & 0o777) == "0o444"
    acq = [e for e in client.get(f"/api/cases/{case}/custody").json()["entries"] if e["action"] == "evidence_acquired"][0]
    assert acq["actor"] == "admin" and acq["detail"]["custodian"] == "SI Verma"

def test_declared_hash_and_duplicates(client):
    case = mk_case(client); data = b"evidence"
    good = upload(client, case, "a", data, expected_sha256=hashlib.sha256(data).hexdigest().upper()).json()
    bad = upload(client, case, "b", data, expected_sha256="0" * 64).json()
    assert good["declared_match"] == 1 and bad["declared_match"] == 0
    assert bad["duplicate_of"] == good["evidence_id"] and good["duplicate_of"] is None
    assert upload(client, case, "c", data, expected_sha256="xyz").status_code == 400

def test_upload_size_limit(tmp_path, monkeypatch):
    monkeypatch.setenv("FORENSIC_MAX_UPLOAD_BYTES", "1000")
    main = fresh_app(tmp_path, monkeypatch)
    with TestClient(main.app, headers={"X-Requested-With": "idff"}) as c:
        c.post("/api/auth/setup", data={"username": "a", "password": PW}); case = mk_case(c)
        assert upload(c, case, "big", b"x" * 5000).status_code == 413
        assert [p for p in (tmp_path / "vault").iterdir() if p.name.startswith(".incoming")] == []   # no temp leftovers

def test_verify_detects_tamper_and_blocks_parse(client, tmp_path):
    case = mk_case(client)
    ev = upload(client, case, "auth.log", (SAMPLES / "auth.log").read_bytes()).json()["evidence_id"]
    assert client.post(f"/api/evidence/{ev}/verify").json()["status"] == "VERIFIED"
    tamper(tmp_path, ev)
    v = client.post(f"/api/evidence/{ev}/verify").json()
    assert v["status"] == "TAMPERED" and v["expected_sha256"] != v["actual_sha256"]
    r = client.post(f"/api/evidence/{ev}/parse")
    assert r.status_code == 409 and "refusing to parse" in r.json()["detail"]
    assert client.post(f"/api/cases/{case}/verify-all").json()["all_verified"] is False
    assert "INTEGRITY_FAILURE" in [e["action"] for e in client.get(f"/api/cases/{case}/custody").json()["entries"]]

def test_missing_file_detected(client, tmp_path):
    case = mk_case(client); ev = upload(client, case, "a", b"x").json()["evidence_id"]
    p = vault_file(tmp_path, ev); p.chmod(0o644); p.unlink()
    assert client.post(f"/api/evidence/{ev}/verify").json()["status"] == "MISSING"

# ---------------- parsing ----------------
def test_syslog_parse_and_assumptions(client):
    case = mk_case(client)
    ev = upload(client, case, "auth.log", (SAMPLES / "auth.log").read_bytes()).json()
    r = client.post(f"/api/evidence/{ev['evidence_id']}/parse", data={"assume_year": 2026}).json()
    assert r["parser"] == "syslog" and r["event_count"] == 11 and r["parent_sha256"] == ev["sha256"]
    assert any("1 of 12 lines" in n for n in r["notes"]) and any("no year or timezone" in n for n in r["notes"])
    by = {e["event_type"]: e for e in client.get(f"/api/cases/{case}/events").json()["events"]}
    assert by["ssh_login_success"]["normalized_time"] == "2026-03-14T16:39:02Z"
    assert by["ssh_login_success"]["original_time"] == "Mar 14 22:09:02" and by["ssh_login_success"]["time_quality"] == "assumed_year_tz"
    assert by["ssh_login_failed"]["fields"]["ip"] == "203.0.113.45"
    assert "/media/usb/" in by["sudo_command"]["fields"]["command"] and by["cron_job"]["fields"]["user"] == "root"

def test_access_log_and_bodyfile(client):
    case = mk_case(client)
    a = upload(client, case, "access.log", (SAMPLES / "access.log").read_bytes()).json()["evidence_id"]
    b = upload(client, case, "fs.body", (SAMPLES / "fs.body").read_bytes()).json()["evidence_id"]
    assert client.post(f"/api/evidence/{a}/parse").json()["parser"] == "web_access_log"
    assert client.post(f"/api/evidence/{b}/parse").json()["event_count"] == 12
    e = client.get(f"/api/cases/{case}/events", params={"q": "Q4_payroll", "event_type": "http_request"}).json()["events"][0]
    assert e["time_quality"] == "exact" and e["normalized_time"] == "2026-03-14T16:49:05Z"

def test_reparse_replaces_events_and_keeps_history(client):
    case = mk_case(client)
    ev = upload(client, case, "auth.log", (SAMPLES / "auth.log").read_bytes()).json()["evidence_id"]
    client.post(f"/api/evidence/{ev}/parse", data={"assume_year": 2026})
    client.post(f"/api/evidence/{ev}/parse", data={"assume_year": 2025, "tz": "UTC"})
    assert client.get(f"/api/cases/{case}/events").json()["total"] == 11       # not 22
    arts = client.get(f"/api/evidence/{ev}/artifacts").json()
    assert sorted(a["status"] for a in arts) == ["active", "superseded"]
    assert client.post(f"/api/evidence/{ev}/parse", data={"tz": "Mars/Base"}).status_code == 400

def test_garbage_not_parsed_and_unknown_parser(client):
    case = mk_case(client); ev = upload(client, case, "x.bin", os.urandom(500)).json()["evidence_id"]
    assert client.post(f"/api/evidence/{ev}/parse").status_code == 422
    assert client.post(f"/api/evidence/{ev}/parse", data={"parser": "nope"}).status_code == 400

def test_events_sorted_paged_and_csv_safe(client):
    case = mk_case(client)
    for n in ("auth.log", "access.log", "fs.body"):
        client.post(f"/api/evidence/{upload(client, case, n, (SAMPLES / n).read_bytes()).json()['evidence_id']}/parse", data={"assume_year": 2026})
    r = client.get(f"/api/cases/{case}/events", params={"limit": 10, "offset": 10}).json()
    assert r["total"] == 28 and len(r["events"]) == 10 and "ssh_login_failed" in r["event_types"]
    times = [e["normalized_time"] for e in client.get(f"/api/cases/{case}/events", params={"limit": 100}).json()["events"]]
    assert times == sorted(times)
    csv_text = client.get(f"/api/cases/{case}/events.csv").text
    assert csv_text.count("\n") == 29

def test_csv_formula_injection_guard(client):
    main = sys.modules["app.main"]
    assert main.csv_safe("=HYPERLINK(\"http://x\")") == "'=HYPERLINK(\"http://x\")"
    assert main.csv_safe("@SUM(A1)").startswith("'") and main.csv_safe("-2+3").startswith("'")
    assert main.csv_safe("normal") == "normal" and main.csv_safe(None) == ""

# ---------------- custody / exports ----------------
def test_custody_chain_breaks_on_edit(client, tmp_path):
    case = mk_case(client); ev = upload(client, case, "a.log", b"x").json()["evidence_id"]
    client.post(f"/api/evidence/{ev}/verify")
    assert client.get("/api/custody/verify").json()["intact"] is True
    con = sqlite3.connect(tmp_path / "intake.db")
    con.execute("DROP TRIGGER IF EXISTS custody_log_no_update")
    con.execute("UPDATE custody_log SET actor='someone-else' WHERE action='evidence_acquired'"); con.commit(); con.close()
    v = client.get("/api/custody/verify").json()
    assert v["intact"] is False and v["first_broken_seq"] is not None

def test_manifest_self_hashing_and_certificate(client, tmp_path):
    case = mk_case(client); ev = upload(client, case, "a.log", b"abc", custodian="SI Verma").json()["evidence_id"]
    m = client.get(f"/api/cases/{case}/manifest").json(); claimed = m.pop("manifest_sha256")
    assert hashlib.sha256(json.dumps(m, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()).hexdigest() == claimed
    page = client.get(f"/api/evidence/{ev}/certificate")
    assert page.status_code == 200 and hashlib.sha256(b"abc").hexdigest() in page.text and "VERIFIED" in page.text
    tamper(tmp_path, ev)
    assert "TAMPERED" in client.get(f"/api/evidence/{ev}/certificate").text

def test_security_headers(anon):
    r = anon.get("/")
    assert r.status_code == 200 and r.headers["x-frame-options"] == "DENY"
