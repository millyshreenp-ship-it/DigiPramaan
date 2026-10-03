import os
import pytest

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

def test_certificate_generation_admin(test_client):
    import app.auth as auth
    
    app.dependency_overrides[auth.current_user] = lambda: {"username": "admin1", "role": "admin"}
    try:
        res = test_client.get("/api/cases/case1/certificate")
        assert res.status_code == 200
        assert res.headers["content-type"] == "application/pdf"
        
        pdf_bytes = res.content
        assert b"Prototype template. Statutory wording must be validated by legal counsel." in pdf_bytes
        assert b"Section 63 Certificate" in pdf_bytes
        assert b"Evidence List \\(SHA-256/512\\):" in pdf_bytes
        assert b"Section 65B(4)" not in pdf_bytes
        assert b"Cryptographically sealed" not in pdf_bytes
        
        with db.session() as c:
            logs = c.execute("SELECT * FROM custody_log WHERE action='certificate_generated'").fetchall()
            assert len(logs) == 1
    finally:
        app.dependency_overrides.clear()

def test_certificate_generation_auditor(test_client):
    import app.auth as auth
    
    app.dependency_overrides[auth.current_user] = lambda: {"username": "auditor1", "role": "auditor"}
    try:
        res = test_client.get("/api/cases/case1/certificate")
        assert res.status_code == 200
        
        pdf_bytes = res.content
        assert b"Evidence List: REDACTED for auditor role" in pdf_bytes
    finally:
        app.dependency_overrides.clear()

def test_certificate_generation_denied(test_client):
    import app.auth as auth
    
    # user is not a member of the case
    app.dependency_overrides[auth.current_user] = lambda: {"username": "rando", "role": "reviewer", "user_id": "U999"}
    try:
        res = test_client.get("/api/cases/case1/certificate")
        assert res.status_code == 403
    finally:
        app.dependency_overrides.clear()
