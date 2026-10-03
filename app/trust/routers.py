from fastapi import APIRouter, Depends, Form, HTTPException
from app import db, auth, custody
from app.trust.rbac import require_permission
import json
from datetime import datetime, timezone

router = APIRouter()

# ================= permissions =================
@router.get("/api/permissions")
def get_permissions(user: dict = Depends(auth.current_user)):
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
        custody.append(c, actor=user["username"], action="member_assigned", case_id=case_id, detail={"assigned": username, "role": role})
        return {"status": "ok"}

@router.delete("/api/cases/{case_id}/members/{username}")
def remove_member(case_id: str, username: str, user: dict = Depends(require_permission("case:assign"))):
    with db.session() as c:
        u = c.execute("SELECT user_id FROM users WHERE username=?", (username,)).fetchone()
        if not u: raise HTTPException(404, "User not found")
        c.execute("DELETE FROM case_members WHERE case_id=? AND user_id=?", (case_id, u["user_id"]))
        custody.append(c, actor=user["username"], action="member_removed", case_id=case_id, detail={"removed": username})
        return {"status": "ok"}

def _redact_sensitive(detail: dict) -> dict:
    redacted = {}
    for k, v in detail.items():
        if k in ("filename", "notes", "vault_path", "declared_sha256", "title", "description", "fir_number"):
            redacted[k] = "[REDACTED]"
        elif isinstance(v, dict):
            redacted[k] = _redact_sensitive(v)
        else:
            redacted[k] = v
    return redacted

def _neutralize(val):
    if isinstance(val, str) and val.startswith(("=", "+", "-", "@")):
        return "'" + val
    return val

def _neutralize_dict(d: dict) -> dict:
    return {k: (_neutralize_dict(v) if isinstance(v, dict) else _neutralize(v)) for k, v in d.items()}

# ================= audit =================
@router.get("/api/audit")
def global_audit_log(case_id: str = None, action: str = None, user: dict = Depends(require_permission("audit:read"))):
    from app.trust.rbac import PERMISSIONS
    can_read_evidence = "evidence:read" in PERMISSIONS.get(user["role"], [])
    
    with db.session() as c:
        query = "SELECT * FROM custody_log WHERE 1=1"
        params = []
        if case_id:
            query += " AND case_id=?"
            params.append(case_id)
        if action:
            query += " AND action COLLATE NOCASE = ?"
            params.append(action)
        query += " ORDER BY seq DESC LIMIT 1000"
        
        rows = [dict(r) for r in c.execute(query, params)]
        for r in rows:
            detail = json.loads(r["detail"] or "{}")
            if not can_read_evidence:
                detail = _redact_sensitive(detail)
            r["detail"] = detail
        return {"chain": custody.verify_chain(c, case_id=case_id), "entries": rows}

@router.get("/api/audit/export")
def global_audit_export(case_id: str = None, user: dict = Depends(require_permission("audit:export"))):
    from app.trust.rbac import PERMISSIONS
    can_read_evidence = "evidence:read" in PERMISSIONS.get(user["role"], [])
    
    with db.session() as c:
        query = "SELECT * FROM custody_log"
        params = []
        if case_id:
            query += " WHERE case_id=?"
            params.append(case_id)
        query += " ORDER BY seq"
        
        rows = [dict(r) for r in c.execute(query, params)]
        for r in rows:
            detail = json.loads(r["detail"] or "{}")
            if not can_read_evidence:
                detail = _redact_sensitive(detail)
            r["detail"] = _neutralize_dict(detail)
            r["actor"] = _neutralize(r["actor"])
            r["action"] = _neutralize(r["action"])
            r["case_id"] = _neutralize(r["case_id"])
            r["evidence_id"] = _neutralize(r["evidence_id"])
            
        custody.append(c, actor=user["username"], action="GLOBAL_AUDIT_EXPORTED" if not case_id else "CASE_AUDIT_EXPORTED", case_id=case_id, detail={"rows": len(rows)})
        return {"chain": custody.verify_chain(c, case_id=case_id), "entries": rows}

@router.get("/api/audit/verify")
def verify_audit_chain(case_id: str = None, user: dict = Depends(require_permission("audit:verify"))):
    import time
    start = time.perf_counter()
    with db.session() as c:
        result = custody.verify_chain(c, case_id=case_id)
        elapsed = time.perf_counter() - start
        custody.append(c, actor=user["username"], action="audit_verified", case_id=case_id, detail={"valid": result["valid"], "entries_checked": result["entries_checked"], "elapsed_ms": round(elapsed * 1000, 2)})
        return result



