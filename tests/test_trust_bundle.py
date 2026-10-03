import os
import json
import pytest
import subprocess
from app import custody

@pytest.fixture(autouse=True)
def strict_mode(monkeypatch, tmp_path):
    monkeypatch.setenv("LEGACY_OPEN_ACCESS", "0")
    monkeypatch.setenv("FORENSIC_DATA_DIR", str(tmp_path))
    import sys
    import importlib
    for m in [m for m in sys.modules if m == "app" or m.startswith("app.")]:
        del sys.modules[m]
        
    global app, db, custody
    app_main = importlib.import_module("app.main")
    app = app_main.app
    db = importlib.import_module("app.db")
    custody = importlib.import_module("app.custody")
    config = importlib.import_module("app.config")
    
    config.DATA_DIR = tmp_path
    config.DB_PATH = tmp_path / "intake.db"
    
    db.SCHEMA = db.SCHEMA # force evaluation
    db.init_db()
    
    with db.session() as c:
        c.execute("INSERT INTO users(username, role, password_hash, created_at) VALUES('admin1', 'admin', 'x', '2023-01-01')")
        c.execute("INSERT INTO users(username, role, password_hash, created_at) VALUES('reviewer1', 'reviewer', 'x', '2023-01-01')")
    yield
    if os.path.exists(config.DB_PATH):
        os.remove(config.DB_PATH)

@pytest.fixture
def test_client():
    from fastapi.testclient import TestClient
    return TestClient(app, headers={"X-Requested-With": "idff"})

def test_export_bundle_permissions(test_client):
    import app.auth as auth
    
    with db.session() as c:
        custody.append(c, actor="tester", action="test1", detail={"sensitive": "data"})
    
    # reviewer should get 403 on unredacted
    app.dependency_overrides[auth.current_user] = lambda: {"username": "reviewer1", "role": "reviewer"}
    try:
        res = test_client.get("/api/audit/bundle")
        assert res.status_code == 403
        
        # but 200 on redacted
        res = test_client.get("/api/audit/bundle?redacted=true")
        assert res.status_code == 200
        bundle = res.json()
        assert bundle["entries"][0]["detail"] == '{"redacted": true}'
    finally:
        app.dependency_overrides.clear()

def test_verify_tool_valid_and_tampered(test_client, tmp_path):
    from app.config import ANCHOR_INTERVAL
    from app.trust.anchors import get_or_create_key
    import app.auth as auth
    
    with db.session() as c:
        for i in range(ANCHOR_INTERVAL + 5):
            custody.append(c, actor="tester", action=f"test_{i}")
            
    app.dependency_overrides[auth.current_user] = lambda: {"username": "admin1", "role": "admin"}
    try:
        res = test_client.get("/api/audit/bundle")
        assert res.status_code == 200
        bundle = res.json()
    finally:
        app.dependency_overrides.clear()
        
    bundle_path = str(tmp_path / "bundle.json")
    with open(bundle_path, "w") as f:
        json.dump(bundle, f)
        
    verify_script = os.path.abspath("tools/verify_audit.py")
    key_path = os.path.join(str(tmp_path), "keys", "audit_signing.key")
    
    # 1. Valid bundle
    res = subprocess.run(["python", verify_script, bundle_path, key_path], capture_output=True, text=True)
    assert "Verification passed" in res.stdout
    assert res.returncode == 0
    import copy
    
    # 2. Tampered leaf (modify entry hash but keep sequence intact)
    bundle_tampered = copy.deepcopy(bundle)
    bundle_tampered["entries"][0]["entry_hash"] = "0000000000000000000000000000000000000000000000000000000000000000"
    tampered_path = str(tmp_path / "bundle_tampered.json")
    with open(tampered_path, "w") as f:
        json.dump(bundle_tampered, f)
        
    res = subprocess.run(["python", verify_script, tampered_path, key_path], capture_output=True, text=True)
    assert "Verification failed" in res.stdout
    assert "Chain broken" in res.stdout
    assert res.returncode != 0
    
    # 3. Severed anchor
    bundle_severed = copy.deepcopy(bundle)
    bundle_severed["anchors"][0]["merkle_root"] = "0000000000000000000000000000000000000000000000000000000000000000"
    severed_path = str(tmp_path / "bundle_severed.json")
    with open(severed_path, "w") as f:
        json.dump(bundle_severed, f)
        
    res = subprocess.run(["python", verify_script, severed_path, key_path], capture_output=True, text=True)
    assert "Verification failed" in res.stdout
    assert "Merkle root mismatch" in res.stdout or "Signature invalid" in res.stdout
    assert res.returncode != 0
