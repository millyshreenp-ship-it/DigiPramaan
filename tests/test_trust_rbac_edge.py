import os
import pytest
from fastapi.testclient import TestClient
from app.main import app
from app import db, auth

import sys
import importlib

@pytest.fixture(autouse=True)
def strict_mode_edge(monkeypatch, tmp_path):
    monkeypatch.setenv("LEGACY_OPEN_ACCESS", "0")
    monkeypatch.setenv("FORENSIC_DATA_DIR", str(tmp_path))
    # Reload modules
    for m in [m for m in sys.modules if m == "app" or m.startswith("app.")]:
        del sys.modules[m]
    global app, db, auth, client
    app_main = importlib.import_module("app.main")
    app = app_main.app
    db = importlib.import_module("app.db")
    auth = importlib.import_module("app.auth")
    client = TestClient(app, headers={"X-Requested-With": "idff"})
    db.init_db()

def setup_users_and_case():
    client.post("/api/auth/setup", data={"username": "admin", "password": "password123"})
    res = client.post("/api/auth/login", data={"username": "admin", "password": "password123"})
    admin_token = res.cookies.get("idff_session", "")
    
    client.post("/api/users", data={"username": "exam", "full_name": "Examiner", "role": "examiner", "password": "password123"}, cookies={"idff_session": admin_token})
    client.post("/api/users", data={"username": "auditor", "full_name": "Auditor", "role": "auditor", "password": "password123"}, cookies={"idff_session": admin_token})
    client.post("/api/users", data={"username": "inv", "full_name": "Investigator", "role": "investigator", "password": "password123"}, cookies={"idff_session": admin_token})

    res = client.post("/api/auth/login", data={"username": "inv", "password": "password123"})
    inv_token = res.cookies["idff_session"]
    
    res = client.post("/api/cases", data={"title": "Test Case"}, cookies={"idff_session": inv_token})
    case_id = res.json()["case_id"]

    return admin_token, inv_token, case_id

def test_middleware_edge_cases():
    admin_token, inv_token, case_id = setup_users_and_case()
    
    # Login as unassigned exam
    res = client.post("/api/auth/login", data={"username": "exam", "password": "password123"})
    exam_token = res.cookies["idff_session"]

    # 1. Nonexistent case_id and inaccessible case_id return same status and body (no enumeration)
    nonexistent = "CASE-20990101-ABCD"
    res_non = client.get(f"/api/cases/{nonexistent}", cookies={"idff_session": exam_token})
    res_den = client.get(f"/api/cases/{case_id}", cookies={"idff_session": exam_token})
    
    assert res_non.status_code == 403
    assert res_den.status_code == 403
    assert res_non.json() == res_den.json()

    # 2. Trailing slash, double slash, percent-encoded variants bypass check
    variants = [
        f"/api/cases/{case_id}/",
        f"/api/cases//{case_id}",
        f"/api//cases/{case_id}",
        f"/api/cases/%43%41%53%45%2D%32%30%32%36%31%30%30%32%2D%43%32%43%33", # URL encoded
    ]
    for v in variants:
        if "%" in v:
            v = f"/api/cases/{case_id.replace('C', '%43')}"
        res = client.get(v, cookies={"idff_session": exam_token})
        # Fastapi might return 404 or redirect, but it should NOT return 200/data
        assert res.status_code in (403, 404, 307)

    # 3. HEAD and OPTIONS handled correctly
    res_head = client.head(f"/api/cases/{case_id}", cookies={"idff_session": exam_token})
    assert res_head.status_code == 403
    res_opt = client.options(f"/api/cases/{case_id}", cookies={"idff_session": exam_token})
    assert res_opt.status_code == 403

def test_unauthenticated_requests():
    res = client.get("/api/cases")
    assert res.status_code == 401

def test_unassigned_admin_auditor():
    admin_token, inv_token, case_id = setup_users_and_case()
    
    # Admin is not assigned, but has role 'admin'
    res = client.get(f"/api/cases/{case_id}/timeline", cookies={"idff_session": admin_token})
    assert res.status_code == 200
    
    # Auditor is not assigned
    res = client.post("/api/auth/login", data={"username": "auditor", "password": "password123"})
    aud_token = res.cookies["idff_session"]
    res = client.get(f"/api/cases/{case_id}/timeline", cookies={"idff_session": aud_token})
    assert res.status_code == 200

def test_idempotent_backfill():
    from app import db
    with db.session() as c:
        logs_before = c.execute("SELECT COUNT(*) FROM custody_log WHERE action='LEGACY_BACKFILL'").fetchone()[0]
    
    # Call init_db again
    db.init_db()
    
    with db.session() as c:
        logs_after = c.execute("SELECT COUNT(*) FROM custody_log WHERE action='LEGACY_BACKFILL'").fetchone()[0]
    
    # Should not add another backfill
    assert logs_after == logs_before
