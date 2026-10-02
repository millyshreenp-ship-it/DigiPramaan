import sys
import importlib
import pytest
from fastapi.testclient import TestClient

# Initialize globally but overwrite in fixture
from app.main import app
from app import db, custody
client = TestClient(app, headers={"X-Requested-With": "idff"})

@pytest.fixture(autouse=True)
def strict_mode(monkeypatch, tmp_path):
    monkeypatch.setenv("LEGACY_OPEN_ACCESS", "0")
    monkeypatch.setenv("FORENSIC_DATA_DIR", str(tmp_path))
    # Reload modules
    for m in [m for m in sys.modules if m == "app" or m.startswith("app.")]:
        del sys.modules[m]
    global app, db, custody, client
    app_main = importlib.import_module("app.main")
    app = app_main.app
    db = importlib.import_module("app.db")
    custody = importlib.import_module("app.custody")
    client = TestClient(app, headers={"X-Requested-With": "idff"})
    db.init_db()

import uuid

def setup_users():
    admin_name = "admin_" + uuid.uuid4().hex[:6]
    auditor_name = "auditor_" + uuid.uuid4().hex[:6]
    
    # Setup admin
    res = client.post("/api/auth/setup", data={"username": admin_name, "password": "password123", "full_name": "Admin"})
    if res.status_code == 400: # Already setup, just login
        pass
        
    admin_token = client.post("/api/auth/login", data={"username": admin_name, "password": "password123"}).cookies["idff_session"]
    
    # Create auditor
    client.post("/api/users", data={"username": auditor_name, "full_name": "Auditor", "role": "auditor", "password": "password123"}, cookies={"idff_session": admin_token})
    
    auditor_token = client.post("/api/auth/login", data={"username": auditor_name, "password": "password123"}).cookies["idff_session"]
    return auditor_token, admin_token

def test_triggers_block_tampering():
    auditor_token, admin_token = setup_users()
    with db.session() as c:
        seq = c.execute("SELECT seq FROM custody_log LIMIT 1").fetchone()["seq"]
        
        # Test DELETE
        with pytest.raises(Exception):
            c.execute("DELETE FROM custody_log WHERE seq=?", (seq,))
            
        # Test UPDATE
        with pytest.raises(Exception):
            c.execute("UPDATE custody_log SET action='TAMPER' WHERE seq=?", (seq,))

def test_verify_detects_tampering():
    auditor_token, admin_token = setup_users()
    
    # Force an update bypassing triggers (e.g. drop trigger) just to test verify function
    with db.session() as c:
        c.execute("DROP TRIGGER custody_log_no_update")
        seq = c.execute("SELECT seq FROM custody_log LIMIT 1").fetchone()["seq"]
        c.execute("UPDATE custody_log SET action='TAMPER' WHERE seq=?", (seq,))
        
    res = client.get("/api/audit/verify", cookies={"idff_session": admin_token})
    assert res.status_code == 200
    data = res.json()
    assert data["valid"] is False
    assert data["first_broken_seq"] == seq
    
    with db.session() as c:
        c.execute("CREATE TRIGGER custody_log_no_update BEFORE UPDATE ON custody_log BEGIN SELECT RAISE(ABORT, 'Updates to custody_log are prohibited'); END;")

def test_privacy_redaction():
    auditor_token, admin_token = setup_users()
    
    # Create case with admin
    res = client.post("/api/cases", data={"title": "Secret Title", "description": "Secret Description"}, cookies={"idff_session": admin_token})
    case_id = res.json()["case_id"]
    
    # Audit trail for auditor (who lacks evidence:read)
    res = client.get("/api/audit", cookies={"idff_session": auditor_token})
    assert res.status_code == 200
    entries = res.json()["entries"]
    
    # Find the case_created event
    event = next(e for e in entries if e["action"] == "case_created" and e["case_id"] == case_id)
    assert event["detail"]["title"] == "[REDACTED]"

def test_export_neutralization():
    auditor_token, admin_token = setup_users()
    
    # Insert malicious action using db
    with db.session() as c:
        custody.append(c, actor="=cmd|' /C calc'!A0", action="@malicious", detail={"notes": "+1+1", "safe": "text"})
        
    res = client.get("/api/audit/export", cookies={"idff_session": admin_token})
    assert res.status_code == 200
    entries = res.json()["entries"]
    event = next(e for e in entries if e["action"] == "'@malicious")
    assert event["actor"] == "'=cmd|' /C calc'!A0"
    assert event["detail"]["notes"] == "'+1+1"
    assert event["detail"]["safe"] == "text"

def test_atomicity():
    auditor_token, admin_token = setup_users()
    
    # Check baseline audit row count
    res = client.get("/api/audit", cookies={"idff_session": admin_token})
    initial_count = len(res.json()["entries"])
    
    # Attempt an action that will fail validation (e.g. invalid status transition)
    res = client.post("/api/cases", data={"title": "Atomic Case"}, cookies={"idff_session": admin_token})
    case_id = res.json()["case_id"]
    
    res = client.post(f"/api/cases/{case_id}/status", data={"status": "Archived", "reason": "jump"}, cookies={"idff_session": admin_token})
    assert res.status_code == 400 # Invalid transition
    
    # Verify no audit entry was created for the failed transition
    res = client.get("/api/audit", cookies={"idff_session": admin_token})
    entries = res.json()["entries"]
    assert not any(e["action"] == "case_status_changed" and e["case_id"] == case_id for e in entries)
