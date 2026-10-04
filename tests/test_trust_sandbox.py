import sys
import importlib
import pytest
from fastapi.testclient import TestClient
import uuid
import json
import hashlib
import os

from app.main import app
from app import db

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

def setup_users():
    admin_name = "admin_" + uuid.uuid4().hex[:6]
    inv_name = "inv_" + uuid.uuid4().hex[:6]
    sup_name = "sup_" + uuid.uuid4().hex[:6]
    
    # Setup admin
    res = client.post("/api/auth/setup", data={"username": admin_name, "password": "password123", "full_name": "Admin"})
    if res.status_code == 400: # Already setup, just login
        res = client.post("/api/auth/login", data={"username": admin_name, "password": "password123"})
    admin_token = res.cookies.get("idff_session")
    
    # Create investigator and supervisor
    client.cookies.clear()
    client.cookies.update({"idff_session": admin_token})
    client.post("/api/users", data={"username": inv_name, "full_name": "Inv", "role": "investigator", "password": "password123"}, headers={"X-Requested-With": "idff"})
    client.cookies.clear()
    inv_token = client.post("/api/auth/login", data={"username": inv_name, "password": "password123"}).cookies.get("idff_session")
    
    client.cookies.clear()
    client.cookies.update({"idff_session": admin_token})
    client.post("/api/users", data={"username": sup_name, "full_name": "Sup", "role": "supervisor", "password": "password123"}, headers={"X-Requested-With": "idff"})
    client.cookies.clear()
    sup_token = client.post("/api/auth/login", data={"username": sup_name, "password": "password123"}).cookies.get("idff_session")
    
    return admin_token, inv_token, sup_token

def compute_master_manifest(case_id):
    with db.session() as conn:
        evs = conn.execute("SELECT evidence_id, filename, size FROM evidence WHERE case_id=? ORDER BY evidence_id", (case_id,)).fetchall()
        h = hashlib.sha256()
        for e in evs:
            h.update(f"{e['evidence_id']}:{e['filename']}:{e['size']}".encode())
        return h.hexdigest()

@pytest.fixture
def sandbox_env():
    admin_token, inv_token, sup_token = setup_users()
    
    # Create non-member investigator
    client.cookies.clear()
    client.cookies.update({"idff_session": admin_token})
    client.post("/api/users", data={"username": "rando_inv", "full_name": "Rando", "role": "investigator", "password": "password123"}, headers={"X-Requested-With": "idff"})
    client.cookies.clear()
    rando_token = client.post("/api/auth/login", data={"username": "rando_inv", "password": "password123"}).cookies.get("idff_session")
    
    # Create auditor and reviewer
    client.cookies.clear()
    client.cookies.update({"idff_session": admin_token})
    client.post("/api/users", data={"username": "aud_1", "full_name": "Aud", "role": "auditor", "password": "password123"}, headers={"X-Requested-With": "idff"})
    client.cookies.clear()
    aud_token = client.post("/api/auth/login", data={"username": "aud_1", "password": "password123"}).cookies.get("idff_session")
    
    client.cookies.clear()
    client.cookies.update({"idff_session": admin_token})
    client.post("/api/users", data={"username": "rev_1", "full_name": "Rev", "role": "reviewer", "password": "password123"}, headers={"X-Requested-With": "idff"})
    client.cookies.clear()
    rev_token = client.post("/api/auth/login", data={"username": "rev_1", "password": "password123"}).cookies.get("idff_session")

    client.cookies.clear()
    client.cookies.update({"idff_session": admin_token})
    res = client.post("/api/cases", data={"title": "Sandbox Separate Case"}, headers={"X-Requested-With": "idff"})
    case_id = res.json()["case_id"]

    with open("samples_for_testing/auth.log", "rb") as bf:
        real_data = bf.read()
    client.post(f"/api/cases/{case_id}/evidence", data={"source_type": "log"}, files={"file": ("auth.log", real_data)}, headers={"X-Requested-With": "idff"})
    
    return {
        "admin_token": admin_token, "rando_token": rando_token, 
        "aud_token": aud_token, "rev_token": rev_token, 
        "case_id": case_id
    }

def test_sandbox_rbac_non_member(sandbox_env):
    env = sandbox_env
    case_id = env["case_id"]
    client.cookies.clear()
    client.cookies.update({"idff_session": env["rando_token"]})
    r = client.post(f"/api/cases/{case_id}/sandbox", headers={"X-Requested-With": "idff"})
    assert r.status_code == 403
    r = client.post(f"/api/cases/{case_id}/sandbox/SBX-1/inject", json={"template": "custom JSON"}, headers={"X-Requested-With": "idff"})
    assert r.status_code == 403
    r = client.post(f"/api/cases/{case_id}/sandbox/SBX-1/run", headers={"X-Requested-With": "idff"})
    assert r.status_code == 403

def test_sandbox_rbac_auditor_reviewer(sandbox_env):
    env = sandbox_env
    case_id = env["case_id"]
    
    client.cookies.clear()
    client.cookies.update({"idff_session": env["aud_token"]})
    r = client.post(f"/api/cases/{case_id}/sandbox", headers={"X-Requested-With": "idff"})
    assert r.status_code == 403
    r = client.post(f"/api/cases/{case_id}/sandbox/SBX-1/inject", json={"template": "custom JSON"}, headers={"X-Requested-With": "idff"})
    assert r.status_code == 403
    
    client.cookies.clear()
    client.cookies.update({"idff_session": env["rev_token"]})
    r = client.post(f"/api/cases/{case_id}/sandbox", headers={"X-Requested-With": "idff"})
    assert r.status_code == 403

def test_sandbox_lifecycle_and_isolation(sandbox_env):
    env = sandbox_env
    case_id = env["case_id"]
    admin = env["admin_token"]
    
    manifest_before = compute_master_manifest(case_id)
    
    client.cookies.clear()
    client.cookies.update({"idff_session": admin})
    
    sbx_res = client.post(f"/api/cases/{case_id}/sandbox", headers={"X-Requested-With": "idff"})
    assert sbx_res.status_code == 200
    sb_id = sbx_res.json()["sandbox_id"]
    
    r_bad = client.post(f"/api/cases/{case_id}/sandbox/{sb_id}/inject", json={"template": "invalid", "params": {}, "expected_detection_type": "none"}, headers={"X-Requested-With": "idff"})
    assert r_bad.status_code == 422
    
    injections = {}
    templates = ["registry run-key", "forged DNS/DHCP", "clock-skew timestamp", "off-hours USB copy", "scam-chat pair", "custom JSON"]
    for t in templates:
        r = client.post(f"/api/cases/{case_id}/sandbox/{sb_id}/inject", json={"template": t, "params": {"marker": f"UNIQUE_MARKER_{t}"}, "expected_detection_type": t}, headers={"X-Requested-With": "idff"})
        assert r.status_code == 200
        inj_id = r.json()["injection_id"]
        assert inj_id.startswith("INJ-")
        injections[inj_id] = t
        
    os.environ["DETECTOR"] = "dummy"
    r_run = client.post(f"/api/cases/{case_id}/sandbox/{sb_id}/run", headers={"X-Requested-With": "idff"})
    assert r_run.status_code == 200
    score = r_run.json()
    print("\\nREAL SCOREBOARD:", json.dumps(score, indent=2))
    
    assert score["injected"] == 6
    assert "true_positives" in score
    assert "false_positives" in score
    assert "missed" in score
    assert "detection_rate" in score
    assert score["isolation_status"] == "Master evidence unchanged"
    
    detected_ids = {d.get("event_id") for d in score.get("detections", [])}
    missed_templates = [injections[inj_id] for inj_id in injections if inj_id not in detected_ids]
    print("\\nMISSED TEMPLATES BY FALLBACK DETECTOR:", missed_templates)
    
    assert len(missed_templates) == score["missed"]
    
    manifest_after = compute_master_manifest(case_id)
    assert manifest_before == manifest_after
    
    verify_res = client.get("/api/audit/verify", headers={"X-Requested-With": "idff"})
    assert verify_res.status_code == 200
    assert verify_res.json()["valid"] is True

def test_sandbox_no_leakage(sandbox_env):
    env = sandbox_env
    case_id = env["case_id"]
    admin = env["admin_token"]
    
    client.cookies.clear()
    client.cookies.update({"idff_session": admin})
    
    sb_id = client.post(f"/api/cases/{case_id}/sandbox", headers={"X-Requested-With": "idff"}).json()["sandbox_id"]
    client.post(f"/api/cases/{case_id}/sandbox/{sb_id}/inject", json={"template": "custom JSON", "params": {"marker": "UNIQUE_MARKER_TEST"}, "expected_detection_type": "custom JSON"}, headers={"X-Requested-With": "idff"})
    client.post(f"/api/cases/{case_id}/sandbox/{sb_id}/run", headers={"X-Requested-With": "idff"})
    
    tl = client.get(f"/api/cases/{case_id}/timeline").json()
    for ev in tl.get("events", []):
        assert "UNIQUE_MARKER" not in str(ev)
        
    g = client.get(f"/api/cases/{case_id}/graph").json()
    assert "UNIQUE_MARKER" not in str(g)
    
    q = client.post(f"/api/cases/{case_id}/query", json={"query": "SELECT * FROM events"}).json()
    assert "UNIQUE_MARKER" not in str(q)
    
    evs = client.get(f"/api/cases/{case_id}/evidence").json()
    assert "UNIQUE_MARKER" not in str(evs)
    
    cert = client.get(f"/api/cases/{case_id}/certificate")
    assert b"UNIQUE_MARKER" not in cert.content
    
    bundle = client.get("/api/audit/bundle")
    assert b"UNIQUE_MARKER" not in bundle.content

def test_sandbox_audit_events_in_transaction(sandbox_env):
    env = sandbox_env
    case_id = env["case_id"]
    admin = env["admin_token"]
    
    client.cookies.clear()
    client.cookies.update({"idff_session": admin})
    
    sb_id = client.post(f"/api/cases/{case_id}/sandbox", headers={"X-Requested-With": "idff"}).json()["sandbox_id"]
    client.post(f"/api/cases/{case_id}/sandbox/{sb_id}/inject", json={"template": "custom JSON", "params": {"marker": "UNIQUE_MARKER_TEST"}, "expected_detection_type": "custom JSON"}, headers={"X-Requested-With": "idff"})
    client.post(f"/api/cases/{case_id}/sandbox/{sb_id}/run", headers={"X-Requested-With": "idff"})
    
    from app import db
    with db.session() as conn:
        logs = conn.execute("SELECT action FROM custody_log WHERE case_id=? ORDER BY seq", (case_id,)).fetchall()
        actions = [x["action"] for x in logs]
        assert "sandbox_created" in actions
        assert "sandbox_artifact_injected" in actions
        assert "sandbox_run" in actions

def test_sandbox_closed_hold_blocks(sandbox_env):
    env = sandbox_env
    case_id = env["case_id"]
    admin = env["admin_token"]
    
    client.cookies.clear()
    client.cookies.update({"idff_session": admin})
    
    from app import db
    with db.session() as conn:
        conn.execute("UPDATE cases SET status='closed', legal_hold=1 WHERE case_id=?", (case_id,))
    assert client.post(f"/api/cases/{case_id}/sandbox", headers={"X-Requested-With": "idff"}).status_code == 400

def test_sandbox_source_scan():
    with open("app/trust/sandbox.py", "r") as f:
        src = f.read().upper()
    assert "INSERT INTO EVIDENCE" not in src
    assert "UPDATE EVIDENCE" not in src
    assert "DELETE FROM EVIDENCE" not in src
    assert "INSERT INTO CASES" not in src
    assert "UPDATE CUSTODY_LOG" not in src
