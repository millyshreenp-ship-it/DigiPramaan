from fastapi import APIRouter, Depends, Form
from app import db, auth, custody
from app.trust.rbac import require_permission
import json
from datetime import datetime, timezone

router = APIRouter()

# ================= permissions =================
@router.get("/api/permissions")
def get_permissions():
    from app.trust.rbac import PERMISSIONS
    return PERMISSIONS

# ================= members =================
@router.get("/api/cases/{case_id}/members")
def get_members(case_id: str, user: dict = Depends(require_permission("case:read"))):
    with db.session() as c:
        rows = [dict(r) for r in c.execute("""
            SELECT cm.*, u.username, u.full_name 
            FROM case_members cm 
            JOIN users u ON cm.user_id = u.user_id 
            WHERE cm.case_id = ?""", (case_id,))]
        return rows

@router.post("/api/cases/{case_id}/members")
def assign_member(case_id: str, username: str = Form(...), role: str = Form(...), user: dict = Depends(require_permission("case:assign"))):
    with db.session() as c:
        u = c.execute("SELECT user_id FROM users WHERE username=?", (username,)).fetchone()
        if not u: raise HTTPException(404, "User not found")
        now = datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
        c.execute("INSERT OR REPLACE INTO case_members (case_id, user_id, case_role, assigned_by, assigned_at) VALUES (?, ?, ?, ?, ?)",
                  (case_id, u["user_id"], role, user["username"], now))
        custody.append(c, actor=user["username"], action="MEMBER_ASSIGNED", case_id=case_id, detail={"assigned": username, "role": role})
        return {"status": "ok"}

# ================= audit =================
@router.get("/api/audit")
def global_audit_log(user: dict = Depends(require_permission("audit:read"))):
    with db.session() as c:
        rows = [dict(r) for r in c.execute("SELECT * FROM custody_log ORDER BY seq DESC LIMIT 1000")]
        for r in rows: r["detail"] = json.loads(r["detail"] or "{}")
        return {"chain": custody.verify_chain(c), "entries": rows}

@router.get("/api/audit/export")
def global_audit_export(user: dict = Depends(require_permission("audit:export"))):
    with db.session() as c:
        rows = [dict(r) for r in c.execute("SELECT * FROM custody_log ORDER BY seq")]
        for r in rows: r["detail"] = json.loads(r["detail"] or "{}")
        custody.append(c, actor=user["username"], action="GLOBAL_AUDIT_EXPORTED", detail={"rows": len(rows)})
        return {"chain": custody.verify_chain(c), "entries": rows}

# ================= sandbox =================
@router.post("/api/cases/{case_id}/sandbox/run")
def run_sandbox(case_id: str, script: str = Form(...), image: str = Form("python:3.12-slim"), user: dict = Depends(require_permission("sandbox:run"))):
    import subprocess
    from app import config
    # simplistic demo implementation for groundwork
    try:
        res = subprocess.run(["docker", "run", "--rm", "-i", "-v", f"{config.FORENSIC_DATA_DIR}:/data:ro", image, "python", "-c", script], capture_output=True, text=True, timeout=10)
        out = res.stdout + res.stderr
        exit_code = res.returncode
    except Exception as e:
        out = str(e); exit_code = -1
    
    with db.session() as c:
        import uuid
        ev_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
        c.execute("INSERT INTO evidence (evidence_id, case_id, filename, size, source_type, ingested_at) VALUES (?, ?, ?, ?, ?, ?)",
                  (ev_id, case_id, "sandbox_output.txt", len(out), "sandbox_run", now))
        custody.append(c, actor=user["username"], action="SANDBOX_RUN", case_id=case_id, evidence_id=ev_id, detail={"image": image, "exit_code": exit_code, "script_len": len(script)})
        return {"evidence_id": ev_id, "exit_code": exit_code, "output": out}
