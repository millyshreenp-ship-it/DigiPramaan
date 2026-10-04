import os
import pytest

app = None
db = None

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

def test_certificate_permissions(test_client):
    import app.auth as auth
    
    with db.session() as c:
        # Create roles
        for i, r in enumerate(["admin", "investigator", "supervisor", "reviewer", "examiner", "auditor"], 1):
            c.execute(f"INSERT OR IGNORE INTO users(user_id, username, role, password_hash, created_at, active) VALUES({i}, '{r}1', '{r}', 'x', CURRENT_TIMESTAMP, 1)")
            if r != "auditor":
                # Add all except auditor as member of case1
                c.execute(f"INSERT OR IGNORE INTO case_members(case_id, user_id, case_role, assigned_by, assigned_at) VALUES('case1', {i}, 'member', 'sys', CURRENT_TIMESTAMP)")
    
    def _test(username, role, expected_status, uid_override=None):
        uid = uid_override or {"admin": 1, "investigator": 2, "supervisor": 3, "reviewer": 4, "examiner": 5, "auditor": 6}[role]
        app.dependency_overrides[auth.current_user] = lambda: {"user_id": uid, "username": username, "role": role}
        res = test_client.get("/api/cases/case1/certificate")
        assert res.status_code == expected_status
        if expected_status == 200:
            assert res.content.startswith(b"%PDF")
            # PDF is binary and compressed, but string draws often show up in clear text or can be checked before compression.
            # However, reportlab compresses pages by default unless pageCompression=0.
            # certificate.py uses pageCompression=0 so we can search the bytes.
            assert b"Prototype template. Statutory wording must be validated by legal counsel." in res.content
        app.dependency_overrides.clear()
        
    _test("admin1", "admin", 200)
    _test("investigator1", "investigator", 200)
    _test("supervisor1", "supervisor", 200)
    _test("reviewer1", "reviewer", 200)
    
    _test("examiner1", "examiner", 403)
    _test("auditor1", "auditor", 403)
    
    # Non-member reviewer (create new user not in case_members)
    with db.session() as c:
        c.execute("INSERT OR IGNORE INTO users(user_id, username, role, password_hash, created_at, active) VALUES(7, 'rev2', 'reviewer', 'x', CURRENT_TIMESTAMP, 1)")
    
    _test("rev2", "reviewer", 403, uid_override=7)
    
    # Unauthenticated
    res = test_client.get("/api/cases/case1/certificate")
    assert res.status_code == 401
