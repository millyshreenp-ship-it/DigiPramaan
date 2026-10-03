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

def test_atomicity_business_fail(monkeypatch):
    auditor_token, admin_token = setup_users()
    
    # Check baseline audit row count
    res = client.get("/api/audit", cookies={"idff_session": admin_token})
    initial_count = len(res.json()["entries"])
    
    # Attempt an action that fails business validation logic AFTER opening db session
    res = client.post("/api/cases", data={"title": "Atomic Case A"}, cookies={"idff_session": admin_token})
    case_id = res.json()["case_id"]
    
    # Admin is forbidden from closing the case directly. This triggers a 403 deep in the DB session logic.
    res = client.post(f"/api/cases/{case_id}/status", data={"status": "Closed", "reason": "jump"}, cookies={"idff_session": admin_token})
    assert res.status_code == 403
    
    # Verify no audit entry was created for the failed transition
    res = client.get("/api/audit", cookies={"idff_session": admin_token})
    assert len(res.json()["entries"]) == initial_count + 1 # +1 for the case_created event
    
def test_atomicity_audit_fail(monkeypatch):
    auditor_token, admin_token = setup_users()
    
    res = client.post("/api/cases", data={"title": "Atomic Case B"}, cookies={"idff_session": admin_token})
    case_id = res.json()["case_id"]
    
    # Inject failure into custody.append
    def mock_append(*args, **kwargs):
        raise ValueError("Simulated failure in custody append")
    
    from app import custody
    monkeypatch.setattr(custody, "append", mock_append)
    
    import pytest
    with pytest.raises(ValueError, match="Simulated failure"):
        client.post(f"/api/cases/{case_id}/status", data={"status": "Under Analysis", "reason": "jump"}, cookies={"idff_session": admin_token})
    
    # Verify rollback of the business action
    res = client.get(f"/api/cases/{case_id}", cookies={"idff_session": admin_token})
    assert res.json()["status"] == "Open"


def test_pre_upgrade_chain(monkeypatch, tmp_path):
    import sqlite3, json, hashlib
    # Mock db path to fresh db
    db_path = str(tmp_path / "legacy.db")
    monkeypatch.setattr("app.config.DB_PATH", db_path)
    
    # Manually create legacy schema and insert data
    conn = sqlite3.connect(db_path)
    conn.execute("""
    CREATE TABLE custody_log (
        seq INTEGER PRIMARY KEY AUTOINCREMENT,
        ts TEXT,
        actor TEXT,
        action TEXT,
        detail TEXT,
        prev_hash TEXT,
        entry_hash TEXT
    )
    """)
    
    prev = custody.GENESIS
    body = {"ts": "2023-01-01T00:00:00Z", "actor": "admin", "action": "LOGIN", "detail": {}}
    entry_hash = custody._digest(prev, body)
    conn.execute("INSERT INTO custody_log (ts, actor, action, detail, prev_hash, entry_hash) VALUES (?, ?, ?, ?, ?, ?)",
                 (body["ts"], body["actor"], body["action"], json.dumps(body["detail"]), prev, entry_hash))
    conn.commit()
    conn.close()
    
    # Run migration
    db.init_db()
    
    # Verify chain
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    res = custody.verify_chain(conn)
    assert res["valid"] is True
    assert res["entries_checked"] == 1
    
def test_system_events_null_case():
    import sqlite3
    # Insert system events via the app custody logic
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    conn.execute("""
    CREATE TABLE custody_log (
        seq INTEGER PRIMARY KEY AUTOINCREMENT,
        ts TEXT,
        case_id TEXT,
        evidence_id TEXT,
        actor TEXT,
        action TEXT,
        detail TEXT,
        prev_hash TEXT,
        entry_hash TEXT
    )
    """)
    
    custody.append(conn, actor="system", action="LOGIN_FAILED", detail={"ip": "127.0.0.1"})
    custody.append(conn, actor="system", action="ACCESS_DENIED", detail={"resource": "/secret"})
    custody.append(conn, actor="system", action="LEGACY_BACKFILL")
    
    res = custody.verify_chain(conn)
    assert res["valid"] is True
    assert res["entries_checked"] == 3
    
def test_audit_verified_audited(monkeypatch):
    auditor_token, admin_token = setup_users()
    
    res = client.get("/api/audit", cookies={"idff_session": admin_token})
    initial = len(res.json()["entries"])
    
    res = client.get("/api/audit/verify", cookies={"idff_session": auditor_token})
    assert res.status_code == 200
    
    res = client.get("/api/audit", cookies={"idff_session": admin_token})
    entries = res.json()["entries"]
    assert len(entries) == initial + 1
    assert entries[0]["action"] == "audit_verified"
    
def test_per_case_verification():
    import sqlite3
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    conn.execute("""
    CREATE TABLE custody_log (
        seq INTEGER PRIMARY KEY AUTOINCREMENT,
        ts TEXT,
        case_id TEXT,
        evidence_id TEXT,
        actor TEXT,
        action TEXT,
        detail TEXT,
        prev_hash TEXT,
        entry_hash TEXT
    )
    """)
    
    custody.append(conn, actor="admin", action="case_created", case_id="CASE-1")
    custody.append(conn, actor="admin", action="case_created", case_id="CASE-2")
    custody.append(conn, actor="admin", action="evidence_added", case_id="CASE-1")
    
    res1 = custody.verify_chain(conn, case_id="CASE-1")
    assert res1["valid"] is True
    assert res1["entries_checked"] == 2
    assert res1["global_entries_checked"] == 3
    
    res2 = custody.verify_chain(conn, case_id="CASE-2")
    assert res2["valid"] is True
    assert res2["entries_checked"] == 1
    assert res2["global_entries_checked"] == 3
    
    # Tamper with CASE-2
    conn.execute('UPDATE custody_log SET detail=\'{"bad": 1}\' WHERE case_id=\'CASE-2\'')
    
    # Verifying CASE-1 should STILL fail because the global chain is broken
    res3 = custody.verify_chain(conn, case_id="CASE-1")
    assert res3["valid"] is False
    assert res3["entries_checked"] == 1 # Checked 1 entry of CASE-1 before it hit the break at seq=2
    assert res3["global_entries_checked"] == 1 # Checked 1 entry globally before it hit the break at seq=2
    assert res3["first_broken_seq"] == 2

def test_action_name_filters(monkeypatch):
    auditor_token, admin_token = setup_users()
    
    res = client.post("/api/cases", data={"title": "Filter Test"}, cookies={"idff_session": admin_token})
    case_id = res.json()["case_id"]
    
    res = client.get("/api/audit?action=case_created", cookies={"idff_session": auditor_token})
    assert len(res.json()["entries"]) >= 1
    assert all(e["action"] == "case_created" for e in res.json()["entries"])
    
    res = client.get("/api/audit?action=CASE_CREATED", cookies={"idff_session": auditor_token})
    assert len(res.json()["entries"]) >= 1
    assert all(e["action"] == "case_created" for e in res.json()["entries"])
    
def test_timing_10k_entries():
    import sqlite3, time
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    conn.execute("""
    CREATE TABLE custody_log (
        seq INTEGER PRIMARY KEY AUTOINCREMENT,
        ts TEXT,
        case_id TEXT,
        evidence_id TEXT,
        actor TEXT,
        action TEXT,
        detail TEXT,
        prev_hash TEXT,
        entry_hash TEXT
    )
    """)
    
    # Fast bulk insert
    prev = custody.GENESIS
    rows = []
    for i in range(10000):
        body = {"ts": "2023-01-01T00:00:00Z", "case_id": "CASE-1", "actor": "admin", "action": "test", "detail": {}}
        expected = custody._digest(prev, body)
        rows.append(("2023-01-01T00:00:00Z", "CASE-1", None, "admin", "test", "{}", prev, expected))
        prev = expected
        
    conn.executemany("INSERT INTO custody_log (ts, case_id, evidence_id, actor, action, detail, prev_hash, entry_hash) VALUES (?,?,?,?,?,?,?,?)", rows)
    
    start = time.time()
    res = custody.verify_chain(conn)
    end = time.time()
    
    print(f"\n10k entries verification took: {end - start:.4f} seconds")
    assert res["valid"] is True
    assert res["entries_checked"] == 10000
    assert (end - start) < 1.0 # Should be very fast

