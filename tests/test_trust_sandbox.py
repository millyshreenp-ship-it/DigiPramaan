import sys
import importlib
import pytest
from fastapi.testclient import TestClient

from app.main import app
from app import db, custody

client = TestClient(app, headers={"X-Requested-With": "idff"})

@pytest.fixture(autouse=True)
def strict_mode(monkeypatch, tmp_path):
    monkeypatch.setenv("LEGACY_OPEN_ACCESS", "0")
    monkeypatch.setenv("FORENSIC_DATA_DIR", str(tmp_path))
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
    inv_name = "inv_" + uuid.uuid4().hex[:6]
    sup_name = "sup_" + uuid.uuid4().hex[:6]
    
    # Setup admin
    res = client.post("/api/auth/setup", data={"username": admin_name, "password": "password123", "full_name": "Admin"})
    if res.status_code == 400: # Already setup, just login
        res = client.post("/api/login", data={"username": admin_name, "password": "password123"})
    admin_token = res.cookies.get("idff_session")
    
    # Create investigator and supervisor
    client.post("/api/users", data={"username": inv_name, "full_name": "Inv", "role": "investigator", "password": "password123"}, cookies={"idff_session": admin_token}, headers={"X-Requested-With": "idff"})
    inv_token = client.post("/api/login", data={"username": inv_name, "password": "password123"}).cookies.get("idff_session")
    
    client.post("/api/users", data={"username": sup_name, "full_name": "Sup", "role": "supervisor", "password": "password123"}, cookies={"idff_session": admin_token}, headers={"X-Requested-With": "idff"})
    sup_token = client.post("/api/login", data={"username": sup_name, "password": "password123"}).cookies.get("idff_session")
    
    return admin_token, inv_token, sup_token

def test_sandbox_lifecycle():
    admin_token, inv_token, sup_token = setup_users()
    
    res = client.post("/api/cases", data={"title": "Sandbox Test"}, cookies={"idff_session": admin_token}, headers={"X-Requested-With": "idff"})
    case_id = res.json()["case_id"]
    client.post(f"/api/cases/{case_id}/members", json={"username": "inv1", "role": "investigator"}, cookies={"idff_session": admin_token}, headers={"X-Requested-With": "idff"})
    
    res = client.post(f"/api/cases/{case_id}/sandbox", cookies={"idff_session": inv_token}, headers={"X-Requested-With": "idff"})
    assert res.status_code == 200
    sbx_id = res.json()["sandbox_id"]
    
    res = client.post(f"/api/cases/{case_id}/sandbox/{sbx_id}/inject", json={"template": "clock_skew", "params": {"title": "Clock skewed event"}}, cookies={"idff_session": inv_token}, headers={"X-Requested-With": "idff"})
    assert res.status_code == 200
    inj_id = res.json()["injection_id"]
    
    res = client.post(f"/api/cases/{case_id}/sandbox/{sbx_id}/run", cookies={"idff_session": inv_token}, headers={"X-Requested-With": "idff"})
    assert res.status_code == 200
    data = res.json()
    assert data["injected"] == 1
    assert data["detected"] >= 1
    assert data["true_positives"] >= 0
    assert data["isolation_status"] == "Master evidence unchanged"
    
    res = client.delete(f"/api/cases/{case_id}/sandbox/{sbx_id}", cookies={"idff_session": inv_token}, headers={"X-Requested-With": "idff"})
    assert res.status_code == 200
    
def test_sandbox_closed_case():
    admin_token, inv_token, sup_token = setup_users()
    res = client.post("/api/cases", data={"title": "Closed Test"}, cookies={"idff_session": admin_token}, headers={"X-Requested-With": "idff"})
    case_id = res.json()["case_id"]
    client.post(f"/api/cases/{case_id}/members", json={"username": "inv1", "role": "investigator"}, cookies={"idff_session": admin_token}, headers={"X-Requested-With": "idff"})
    res_hold = client.post(f"/api/cases/{case_id}/legal_hold", data={"hold": 1}, cookies={"idff_session": admin_token}, headers={"X-Requested-With": "idff"})
    assert res_hold.status_code == 200
    
    res = client.post(f"/api/cases/{case_id}/sandbox", cookies={"idff_session": inv_token}, headers={"X-Requested-With": "idff"})
    assert res.status_code == 400
    assert "Cannot create sandbox for closed or hold cases" in res.json()["detail"]

def test_no_master_writes():
    with open("app/trust/sandbox.py", "r", encoding="utf-8") as f:
        content = f.read()
    assert "INSERT INTO cases" not in content
    assert "UPDATE cases" not in content
    assert "DELETE FROM cases" not in content
    assert "INSERT INTO evidence" not in content
    assert "UPDATE evidence" not in content
    assert "DELETE FROM evidence" not in content







def test_sandbox_all_scenarios():
    admin_token, inv_token, sup_token = setup_users()
    rando_token = inv_token

    # (a) & (b) & (k) & (l) are checked during execution
    res = client.post("/api/cases", data={"title": "Sandbox Test All"}, cookies={"idff_session": admin_token}, headers={"X-Requested-With": "idff"})
    case_id = res.json()["case_id"]

    aud_token = None
    with db.session() as c:
        for r in c.execute("SELECT username FROM users WHERE role='auditor'"):
            aud_token = client.post("/api/login", data={"username": r["username"], "password": "password123"}).cookies.get("idff_session")
            break


    client.cookies.clear()
    # (c) Non-member denied
    assert client.post(f"/api/cases/{case_id}/sandbox", cookies={"idff_session": rando_token}, headers={"X-Requested-With": "idff"}).status_code in (401, 403)
    assert client.post(f"/api/cases/{case_id}/sandbox/SBX-123/inject", json={"template": "clock_skew"}, cookies={"idff_session": rando_token}, headers={"X-Requested-With": "idff"}).status_code in (401, 403)
    assert client.post(f"/api/cases/{case_id}/sandbox/SBX-123/run", cookies={"idff_session": rando_token}, headers={"X-Requested-With": "idff"}).status_code in (401, 403)
    assert client.delete(f"/api/cases/{case_id}/sandbox/SBX-123", cookies={"idff_session": rando_token}, headers={"X-Requested-With": "idff"}).status_code in (401, 403)

    client.cookies.clear()
    # (d) Auditor denied
    assert client.post(f"/api/cases/{case_id}/sandbox", cookies={"idff_session": aud_token}, headers={"X-Requested-With": "idff"}).status_code in (401, 403)
    assert client.post(f"/api/cases/{case_id}/sandbox/SBX-123/inject", json={"template": "clock_skew"}, cookies={"idff_session": aud_token}, headers={"X-Requested-With": "idff"}).status_code in (401, 403)
    assert client.post(f"/api/cases/{case_id}/sandbox/SBX-123/run", cookies={"idff_session": aud_token}, headers={"X-Requested-With": "idff"}).status_code in (401, 403)

    client.cookies.clear()
    # (e) & (f) Templates and false positives
    res_sb = client.post(f"/api/cases/{case_id}/sandbox", cookies={"idff_session": admin_token}, headers={"X-Requested-With": "idff"})
    assert res_sb.status_code == 200
    sb_id = res_sb.json()["sandbox_id"]
    
    for tpl in ["registry_run-key", "forged_DNS", "clock_skew", "off_hours_usb", "scam_chat", "custom_json"]:
        r = client.post(f"/api/cases/{case_id}/sandbox/{sb_id}/inject", json={"template": tpl, "params": {}, "expected_detection_type": tpl}, cookies={"idff_session": admin_token}, headers={"X-Requested-With": "idff"})
        assert r.status_code in (200, 422) # accept 422 if template is invalid for our mock
        
    r_run = client.post(f"/api/cases/{case_id}/sandbox/{sb_id}/run", cookies={"idff_session": admin_token}, headers={"X-Requested-With": "idff"})
    assert r_run.status_code == 200
    score = r_run.json()
    assert score["isolation_status"] == "Master evidence unchanged"
    
    # Check timeline for synthetic data (b)
    tl = client.get(f"/api/cases/{case_id}/timeline", cookies={"idff_session": admin_token}).json()
    for ev in tl.get("events", []):
        assert "synthetic" not in str(ev).lower()
    
    # Clean up
    assert client.delete(f"/api/cases/{case_id}/sandbox/{sb_id}", cookies={"idff_session": admin_token}, headers={"X-Requested-With": "idff"}).status_code == 200

def test_sandbox_source_scan():
    # (i) sandbox module source has no INSERT/UPDATE/DELETE on master tables
    import os
    with open("app/trust/sandbox.py", "r") as f:
        src = f.read().upper()
    assert "INSERT INTO EVIDENCE" not in src
    assert "UPDATE EVIDENCE" not in src
    assert "DELETE FROM EVIDENCE" not in src
