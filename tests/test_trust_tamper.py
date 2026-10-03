import os
import pytest
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
        c.execute("INSERT INTO users(username, role, password_hash, created_at) VALUES('inv1', 'investigator', 'x', '2023-01-01')")
        
        # Need at least 6 entries for tamper test (OFFSET 5)
        for i in range(10):
            custody.append(c, actor="admin1", action=f"action_{i}")
        
    yield
    if os.path.exists(config.DB_PATH):
        try:
            os.remove(config.DB_PATH)
        except PermissionError:
            pass

@pytest.fixture
def test_client():
    from fastapi.testclient import TestClient
    return TestClient(app, headers={"X-Requested-With": "idff"})

def test_tamper_simulation_admin(test_client):
    import app.auth as auth
    
    app.dependency_overrides[auth.current_user] = lambda: {"username": "admin1", "role": "admin"}
    try:
        res = test_client.post("/api/audit/tamper-simulation")
        assert res.status_code == 200
        data = res.json()
        assert data["result"] == "FAIL"
        assert "tampered_seq" in data
        assert "expected_hash" in data
        assert "found_hash" in data
        
        with db.session() as c:
            logs = c.execute("SELECT * FROM custody_log WHERE action='tamper_simulation_run'").fetchall()
            assert len(logs) == 1
    finally:
        app.dependency_overrides.clear()

def test_tamper_simulation_non_admin(test_client):
    import app.auth as auth
    
    app.dependency_overrides[auth.current_user] = lambda: {"username": "inv1", "role": "investigator"}
    try:
        res = test_client.post("/api/audit/tamper-simulation")
        # investigator lacks audit:verify so gets 403
        assert res.status_code == 403
    finally:
        app.dependency_overrides.clear()
