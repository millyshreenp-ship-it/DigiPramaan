from fastapi.testclient import TestClient
from app.main import app
import pytest
from app import db, auth

client = TestClient(app, headers={"X-Requested-With": "idff"})

@pytest.fixture(autouse=True)
def strict_mode_edge(monkeypatch, tmp_path):
    monkeypatch.setenv("FORENSIC_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("LEGACY_OPEN_ACCESS", "0")
    import sys, importlib
    for m in [m for m in sys.modules if m == "app" or m.startswith("app.")]:
        del sys.modules[m]
    global app, db, auth, client
    app_main = importlib.import_module("app.main")
    app = app_main.app
    db = importlib.import_module("app.db")
    auth = importlib.import_module("app.auth")
    client = TestClient(app, headers={"X-Requested-With": "idff"})
    db.init_db()

def setup_users():
    client.post("/api/auth/setup", data={"username": "admin", "password": "password123"})
    res = client.post("/api/auth/login", data={"username": "admin", "password": "password123"})
    admin_token = res.cookies["idff_session"]
    client.post("/api/users", data={"username": "sup", "role": "supervisor", "password": "password123"}, cookies={"idff_session": admin_token})
    client.post("/api/users", data={"username": "inv1", "role": "investigator", "password": "password123"}, cookies={"idff_session": admin_token})
    client.post("/api/users", data={"username": "inv2", "role": "investigator", "password": "password123"}, cookies={"idff_session": admin_token})
    
    res = client.post("/api/auth/login", data={"username": "inv1", "password": "password123"})
    return admin_token, res.cookies["idff_session"]

def test_case_lifecycle():
    admin_token, inv_token = setup_users()
    
    # 1. Create case with new fields
    res = client.post("/api/cases", data={
        "title": "Hackathon Breach",
        "human_reference": "SUT-2026-0001",
        "fir_number": "FIR-001",
        "crime_category": "Data Theft/Insider",
        "priority": "Critical"
    }, cookies={"idff_session": inv_token})
    assert res.status_code == 200
    case_id = res.json()["case_id"]
    
    # Verify it exists
    res = client.get(f"/api/cases/{case_id}", cookies={"idff_session": inv_token})
    assert res.status_code == 200
    data = res.json()
    assert data["human_reference"] == "SUT-2026-0001"
    assert data["status"] == "Open"
    assert data["priority"] == "Critical"
    
    # 2. Update metadata
    res = client.post(f"/api/cases/{case_id}/metadata", data={
        "title": "Hackathon Breach v2",
        "human_reference": "SUT-2026-0001",
        "fir_number": "FIR-001",
        "crime_category": "Data Theft/Insider",
        "priority": "High"
    }, cookies={"idff_session": inv_token})
    assert res.status_code == 200
    
    # 3. Status transition - legal transitions
    res = client.post(f"/api/cases/{case_id}/status", data={
        "status": "Under Analysis",
        "reason": "Starting investigation"
    }, cookies={"idff_session": inv_token})
    assert res.status_code == 200
    
    # 4. Status transition - illegal transition (skip Pending Legal Review to Closed for inv)
    # Wait, inv doesn't have case:close permission unless they are supervisor.
    res = client.post(f"/api/cases/{case_id}/status", data={
        "status": "Closed",
        "reason": "Done"
    }, cookies={"idff_session": inv_token})
    assert res.status_code == 403 # Lacks permission
    
    # Login as supervisor
    res = client.post("/api/auth/login", data={"username": "sup", "password": "password123"})
    sup_token = res.cookies["idff_session"]
    
    # Supervisor is not assigned yet! Assign them.
    res = client.post(f"/api/cases/{case_id}/members", data={
        "username": "sup", "role": "supervisor"
    }, cookies={"idff_session": inv_token})
    assert res.status_code == 200
    
    # Supervisor closes case
    res = client.post(f"/api/cases/{case_id}/status", data={
        "status": "Closed",
        "reason": "Verified"
    }, cookies={"idff_session": sup_token})
    assert res.status_code == 200
    
    # 5. Editing closed case should fail
    res = client.post(f"/api/cases/{case_id}/metadata", data={"title": "test"}, cookies={"idff_session": inv_token})
    assert res.status_code == 400
    
    # 6. Legal Hold test
    res = client.post("/api/cases", data={"title": "Hold Test"}, cookies={"idff_session": inv_token})
    case_id_2 = res.json()["case_id"]
    
    # Set legal hold
    res = client.post(f"/api/cases/{case_id_2}/legal_hold", data={"hold": 1}, cookies={"idff_session": inv_token})
    assert res.status_code == 200
    
    # Try editing metadata
    res = client.post(f"/api/cases/{case_id_2}/metadata", data={"title": "test"}, cookies={"idff_session": inv_token})
    assert res.status_code == 400
    
    # Try closing
    res = client.post(f"/api/cases/{case_id_2}/members", data={"username": "sup", "role": "supervisor"}, cookies={"idff_session": inv_token})
    res = client.post(f"/api/cases/{case_id_2}/status", data={"status": "Closed", "reason": "test"}, cookies={"idff_session": sup_token})
    assert res.status_code == 400
    
    # List filtering test
    res = client.get("/api/cases?category=Data Theft/Insider", cookies={"idff_session": inv_token})
    assert res.status_code == 200
    assert len(res.json()["items"]) == 1
    assert res.json()["items"][0]["case_id"] == case_id
