import os
import sqlite3
import tempfile
from fastapi import APIRouter, Depends, HTTPException
from app.trust.rbac import require_permission
from app import config, db, custody

router = APIRouter()

@router.post("/api/audit/tamper-simulation")
def simulate_tamper(user: dict = Depends(require_permission("audit:verify"))):
    if user["role"] != "admin":
        raise HTTPException(403, "Only admin can simulate tamper")
        
    db_path = str(config.DB_PATH)
    fd, temp_db = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    
    # Copy DB
    source = sqlite3.connect(db_path)
    dest = sqlite3.connect(temp_db)
    dest.row_factory = sqlite3.Row
    source.backup(dest)
    source.close()
    
    try:
        # Drop trigger in copy
        dest.execute("DROP TRIGGER IF EXISTS custody_log_no_update")
        # Edit one row
        row = dest.execute("SELECT * FROM custody_log LIMIT 1 OFFSET 5").fetchone()
        if not row:
            return {"error": "Not enough entries to tamper"}
        tampered_seq = row[0]
        dest.execute("UPDATE custody_log SET action='TAMPERED' WHERE seq=?", (tampered_seq,))
        dest.commit()
        
        # Verify copy
        result = custody.verify_chain(dest)
        
        with db.session() as c:
            custody.append(c, actor=user["username"], action="tamper_simulation_run", case_id=None, detail={"tampered_seq": tampered_seq})
            
        return {
            "tampered_seq": tampered_seq,
            "field": "action",
            "result": "FAIL" if not result["valid"] else "PASS",
            "first_broken_seq": tampered_seq,
            "expected_hash": result.get("expected", ""),
            "found_hash": result.get("found", "")
        }
    finally:
        dest.close()
        os.remove(temp_db)
