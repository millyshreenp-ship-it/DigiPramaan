import os
import re
import time
from fastapi import Request, HTTPException, Depends
from fastapi.responses import JSONResponse
from app import db, auth

PERMISSIONS = {
    "admin": ["case:create", "case:read", "case:assign", "case:update", "case:close", "evidence:upload", "evidence:read", "finding:write", "sandbox:run", "audit:read", "audit:verify", "audit:export", "user:manage"],
    "investigator": ["case:create", "case:read", "case:assign", "case:update", "case:close", "evidence:upload", "evidence:read", "finding:write", "sandbox:run"],
    "examiner": ["case:read", "evidence:upload", "evidence:read", "finding:write", "sandbox:run"],
    "supervisor": ["case:read", "case:close", "audit:read", "audit:verify"],
    "reviewer": ["case:read", "evidence:read", "finding:read", "audit:read"],
    "auditor": ["case:read", "audit:read", "audit:verify", "audit:export"],
}

def require_permission(perm: str):
    def _check(user: dict = Depends(auth.current_user)):
        role = user["role"]
        if perm not in PERMISSIONS.get(role, []):
            raise HTTPException(403, f"Role {role} lacks permission {perm}")
        return user
    return _check

def get_case_or_403(case_id: str, user: dict):
    if os.environ.get("LEGACY_OPEN_ACCESS", "0") == "1":
        return
    if user["role"] in ("admin", "auditor"):
        return
    with db.session() as c:
        row = c.execute("SELECT 1 FROM case_members WHERE case_id=? AND user_id=?", (case_id, user["user_id"])).fetchone()
        if not row:
            from app import custody
            custody.append(c, actor=user["username"], action="ACCESS_DENIED", case_id=case_id, detail={"reason": "Not assigned to case"})
            raise HTTPException(403, "Not assigned to this case.")

def check_evidence_access(evidence_id: str, user: dict):
    with db.session() as c:
        row = c.execute("SELECT case_id FROM evidence WHERE evidence_id=?", (evidence_id,)).fetchone()
        if not row:
            raise HTTPException(404, "Evidence not found")
        get_case_or_403(row["case_id"], user)

async def case_access_middleware(request: Request, call_next):
    match = re.match(r"^/api/cases/([^/]+)", request.url.path)
    if match and request.url.path != "/api/cases/":
        case_id = match.group(1)
        token = request.cookies.get(auth.COOKIE)
        if token:
            with db.session() as c:
                r = c.execute("SELECT u.user_id,u.username,u.full_name,u.role FROM sessions s JOIN users u ON u.user_id=s.user_id WHERE s.token_hash=? AND s.expires_at>? AND u.active=1", (auth._tok_hash(token), time.time())).fetchone()
            if r:
                user = dict(r)
                if os.environ.get("LEGACY_OPEN_ACCESS", "0") != "1" and user["role"] not in ("admin", "auditor"):
                    with db.session() as c2:
                        row = c2.execute("SELECT 1 FROM case_members WHERE case_id=? AND user_id=?", (case_id, user["user_id"])).fetchone()
                        if not row:
                            from app import custody
                            custody.append(c2, actor=user["username"], action="ACCESS_DENIED", case_id=case_id, detail={"path": request.url.path})
                            return JSONResponse(status_code=403, content={"detail": "Not assigned to this case."})
    return await call_next(request)
