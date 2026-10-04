from fastapi import APIRouter, Depends, Form, HTTPException, Request
from datetime import datetime, timezone
import uuid
import os
from app import db, auth, custody
from app.trust.rbac import require_permission, get_case_or_403
def _now(): return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
ANY = Depends(auth.current_user)

router = APIRouter()

@router.post("/api/cases")
def create_case(title: str = Form(...), jurisdiction: str = Form(""), investigator: str = Form(""),
                human_reference: str = Form(""), fir_number: str = Form(""), crime_category: str = Form(""),
                unit: str = Form(""), description: str = Form(""), priority: str = Form(""),
                user: dict = Depends(require_permission("case:create"))):
    if not title.strip(): raise HTTPException(400, "Case title is required.")
    case_id = "CASE-" + datetime.now().strftime("%Y%m%d") + "-" + uuid.uuid4().hex[:4].upper()
    lead = investigator.strip() or user["full_name"] or user["username"]
    with db.session() as c:
        if not human_reference:
            year = datetime.now(timezone.utc).year
            row = c.execute("SELECT human_reference FROM cases WHERE human_reference LIKE ? ORDER BY human_reference DESC LIMIT 1", (f"SUT-{year}-%",)).fetchone()
            num = int(row[0].split("-")[-1]) + 1 if row else 1
            human_reference = f"SUT-{year}-{num:04d}"
            
        c.execute("INSERT INTO cases (case_id, title, jurisdiction, investigator, status, created_at, human_reference, fir_number, crime_category, unit, description, priority, created_by, legal_hold) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                  (case_id, title.strip(), jurisdiction.strip(), lead, "Open", _now(), human_reference, fir_number, crime_category, unit, description, priority, user["username"], 0))
        c.execute("INSERT INTO case_members (case_id, user_id, case_role, assigned_by, assigned_at) VALUES (?, ?, ?, ?, ?)",
                  (case_id, user["user_id"], "lead", "system", _now()))
        custody.append(c, actor=user["username"], action="case_created", case_id=case_id, detail={"title": title.strip(), "human_reference": human_reference})
    return {"case_id": case_id}

@router.get("/api/cases")
def list_cases(request: Request, user: dict = ANY):
    page = int(request.query_params.get("page", 1))
    per_page = 20
    offset = (page - 1) * per_page
    
    q = request.query_params.get("q", "").strip()
    status = request.query_params.get("status", "")
    priority = request.query_params.get("priority", "")
    category = request.query_params.get("category", "")
    sort = request.query_params.get("sort", "created_at DESC")
    
    if sort not in ("created_at DESC", "created_at ASC"): sort = "created_at DESC"
    
    where_clauses = ["1=1"]
    params = []
    
    if q:
        where_clauses.append("(c.title LIKE ? OR c.human_reference LIKE ?)")
        params.extend(["%" + q + "%", "%" + q + "%"])
    if status:
        where_clauses.append("c.status=?")
        params.append(status)
    if priority:
        where_clauses.append("c.priority=?")
        params.append(priority)
    if category:
        where_clauses.append("c.crime_category=?")
        params.append(category)
        
    with db.session() as c_db:
        if os.environ.get("LEGACY_OPEN_ACCESS", "0") == "1" or user["role"] in ("admin", "auditor"):
            base_query = f"FROM cases c WHERE {' AND '.join(where_clauses)}"
        else:
            where_clauses.append("cm.user_id=?")
            params.append(user["user_id"])
            base_query = f"FROM cases c JOIN case_members cm ON c.case_id = cm.case_id WHERE {' AND '.join(where_clauses)}"
            
        total = c_db.execute(f"SELECT COUNT(DISTINCT c.case_id) {base_query}", params).fetchone()[0]
        items = [dict(r) for r in c_db.execute(f"SELECT DISTINCT c.* {base_query} ORDER BY c.{sort} LIMIT ? OFFSET ?", params + [per_page, offset]).fetchall()]
        
        if "page" in request.query_params:
            return {"total": total, "items": items, "page": page, "page_size": per_page}
        return items

@router.get("/api/cases/{case_id}")
def get_case(case_id: str, user: dict = Depends(require_permission("case:read"))):
    get_case_or_403(case_id, user)
    with db.session() as c:
        row = c.execute("SELECT * FROM cases WHERE case_id=?", (case_id,)).fetchone()
        if not row: raise HTTPException(404, "Case not found")
        case_data = dict(row)
        members = [dict(m) for m in c.execute("SELECT cm.*, u.username, u.full_name, u.role as platform_role FROM case_members cm JOIN users u ON cm.user_id=u.user_id WHERE cm.case_id=?", (case_id,))]
        case_data["members"] = members
        return case_data

@router.post("/api/cases/{case_id}/metadata")
def update_case_metadata(case_id: str, title: str = Form(...), human_reference: str = Form(""),
                         fir_number: str = Form(""), crime_category: str = Form(""),
                         unit: str = Form(""), jurisdiction: str = Form(""),
                         description: str = Form(""), priority: str = Form(""),
                         user: dict = Depends(require_permission("case:update"))):
    get_case_or_403(case_id, user)
    with db.session() as c:
        old = c.execute("SELECT * FROM cases WHERE case_id=?", (case_id,)).fetchone()
        if not old: raise HTTPException(404, "Case not found")
        if old["legal_hold"] or old["status"] == "Closed" or old["status"] == "Archived":
            raise HTTPException(400, "Cannot edit metadata of a closed, archived, or legally held case.")
        
        c.execute("""UPDATE cases SET title=?, human_reference=?, fir_number=?, crime_category=?, 
                     unit=?, jurisdiction=?, description=?, priority=? WHERE case_id=?""",
                  (title.strip(), human_reference, fir_number, crime_category, unit, jurisdiction, description, priority, case_id))
        
        diff = {k: {"old": old[k], "new": locals()[k]} for k in ["title", "human_reference", "fir_number", "crime_category", "unit", "jurisdiction", "description", "priority"] if old[k] != locals()[k]}
        if diff:
            custody.append(c, actor=user["username"], action="case_updated", case_id=case_id, detail={"diff": diff})
    return {"ok": True}

@router.post("/api/cases/{case_id}/status")
def change_case_status(case_id: str, status: str = Form(...), reason: str = Form(...), user: dict = Depends(auth.current_user)):
    get_case_or_403(case_id, user)
    
    with db.session() as c:
        old = c.execute("SELECT * FROM cases WHERE case_id=?", (case_id,)).fetchone()
        if not old: raise HTTPException(404, "Case not found")
        old_status = old["status"]
        
        # 1. Legal Hold blocks ALL changes
        if old["legal_hold"]:
            raise HTTPException(400, "Cannot change status of a case under legal hold.")
            
        role = user["role"]
        action = "case_status_changed"
        
        # Intercept Investigator's request to close
        if status == "Closed" and role == "investigator":
            status = "Pending Legal Review"
            action = "close_requested"
        elif status == "Closed" and role == "supervisor":
            action = "case_closed"
        elif status == "Archived":
            action = "case_archived"
            
        # 2. Permission checks
        from app.trust.rbac import PERMISSIONS
        if role == "admin" and status == "Closed":
            raise HTTPException(403, "Admin cannot close or archive alone.")
            
        if status == "Closed":
            if role != "supervisor":
                raise HTTPException(403, f"Role {role} cannot close case.")
        elif status == "Archived":
            if role not in ("supervisor", "admin"):
                raise HTTPException(403, f"Role {role} cannot archive case.")
        else:
            if "case:update" not in PERMISSIONS.get(role, []):
                raise HTTPException(403, "Lacks permission to update case.")
                
        # 3. Transition Table
        valid_transitions = {
            "Open": ["Under Analysis", "Pending Legal Review"],
            "Under Analysis": ["Open", "Pending Legal Review"],
            "Pending Legal Review": ["Under Analysis", "Closed"],
            "Closed": ["Archived"],
            "Archived": []
        }
        
        if status not in valid_transitions.get(old_status, []):
            raise HTTPException(400, f"Invalid status transition from {old_status} to {status}.")
            
        # 4. Mandatory Reason
        if not reason.strip():
            raise HTTPException(400, "Reason is required for status change.")
            
        c.execute("UPDATE cases SET status=? WHERE case_id=?", (status, case_id))
        from app import custody
        custody.append(c, actor=user["username"], action=action, case_id=case_id, detail={"old": old_status, "new": status, "reason": reason})
    return {"ok": True, "status": status}

@router.post("/api/cases/{case_id}/legal_hold")
def set_legal_hold(case_id: str, hold: int = Form(...), user: dict = Depends(require_permission("case:update"))):
    get_case_or_403(case_id, user)
    with db.session() as c:
        old = c.execute("SELECT * FROM cases WHERE case_id=?", (case_id,)).fetchone()
        if not old: raise HTTPException(404, "Case not found")
        if old["legal_hold"] == hold:
            return {"ok": True}
        c.execute("UPDATE cases SET legal_hold=? WHERE case_id=?", (hold, case_id))
        action = "legal_hold_set" if hold else "legal_hold_removed"
        custody.append(c, actor=user["username"], action=action, case_id=case_id, detail={"legal_hold": hold})
    return {"ok": True}
