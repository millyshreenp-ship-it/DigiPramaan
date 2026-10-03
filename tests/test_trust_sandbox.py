import os
import pytest
from app import custody, db, config

@pytest.fixture(autouse=True)
def strict_mode(monkeypatch, tmp_path):
    monkeypatch.setenv("LEGACY_OPEN_ACCESS", "0")
    monkeypatch.setenv("FORENSIC_DATA_DIR", str(tmp_path))
    import sys
    import importlib
    for m in [m for m in sys.modules if m == "app" or m.startswith("app.")]:
        del sys.modules[m]
        
    global app, test_client
    app_main = importlib.import_module("app.main")
    app = app_main.app
    from fastapi.testclient import TestClient
    test_client = TestClient(app, headers={"X-Requested-With": "idff"})
    
    import app.db as db_mod
    import app.config as config_mod
    config_mod.DATA_DIR = tmp_path
    config_mod.DB_PATH = tmp_path / "intake.db"
    
    db_mod.SCHEMA = db_mod.SCHEMA # force evaluation
    db_mod.init_db()
    
    with db_mod.session() as c:
        c.execute("INSERT INTO users(username, role, password_hash, created_at) VALUES('admin1', 'admin', 'x', '2023-01-01')")
        
    yield
    if os.path.exists(config_mod.DB_PATH):
        try:
            os.remove(config_mod.DB_PATH)
        except PermissionError:
            pass

def test_sandbox_execution():
    import app.auth as auth
    
    app.dependency_overrides[auth.current_user] = lambda: {"username": "admin1", "role": "admin", "full_name": "Admin Test", "user_id": 1}
    
    # Create a case
    res = test_client.post("/api/cases", data={"title": "Sandbox Test"})
    case_id = res.json()["case_id"]
    
    try:
        # Mock subprocess.run to avoid requiring Docker
        import subprocess
        class MockResult:
            returncode = 0
            stdout = '{"type": "hash_match", "confidence": 0.9}'
            stderr = ""
            
        original_run = subprocess.run
        subprocess.run = lambda *args, **kwargs: MockResult()
        
        script = 'print("hello")'
        res = test_client.post(f"/api/cases/{case_id}/sandbox/run", data={"script": script, "image": "python:3.12-slim"})
        
        assert res.status_code == 200
        data = res.json()
        assert data["exit_code"] == 0
        assert data["isolation_proven"] is True
        assert "evidence_id" in data
        
        # Verify findings
        assert "findings" in data
        assert data["findings"] == {"type": "hash_match", "confidence": 0.9}
        
    finally:
        subprocess.run = original_run
        app.dependency_overrides.clear()
