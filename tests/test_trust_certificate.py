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
        c.execute("INSERT INTO cases(case_id, title, status, created_at) VALUES('case1', 'Case 1', 'Open', '2023-01-01')")
        
    yield
    if os.path.exists(config.DB_PATH):
        os.remove(config.DB_PATH)

@pytest.fixture
def test_client():
    from fastapi.testclient import TestClient
    return TestClient(app, headers={"X-Requested-With": "idff"})

def test_certificate_generation(test_client):
    import app.auth as auth
    
    # Needs audit:export permission. Admin has it.
    app.dependency_overrides[auth.current_user] = lambda: {"username": "admin1", "role": "admin"}
    try:
        res = test_client.get("/api/cases/case1/certificate")
        assert res.status_code == 200
        assert res.headers["content-type"] == "application/pdf"
        
        # Verify custody log recorded it
        with db.session() as c:
            logs = c.execute("SELECT * FROM custody_log WHERE action='certificate_generated'").fetchall()
            assert len(logs) == 1
    finally:
        app.dependency_overrides.clear()
