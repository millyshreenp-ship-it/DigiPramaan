import os
import pytest
import sys
import hashlib

app = None
db = None
custody = None

@pytest.fixture(autouse=True)
def strict_mode(monkeypatch, tmp_path):
    monkeypatch.setenv("LEGACY_OPEN_ACCESS", "0")
    monkeypatch.setenv("FORENSIC_DATA_DIR", str(tmp_path))
    # Reload modules
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
        c.execute("INSERT INTO users(username, role, password_hash, created_at) VALUES('tester', 'investigator', 'x', '2023-01-01T00:00:00Z')")
    yield
    if os.path.exists(config.DB_PATH):
        os.remove(config.DB_PATH)

@pytest.fixture
def app_db():
    return db

def test_merkle_root_rules():
    from app.trust.anchors import compute_merkle_root
    # 1 leaf
    leaf_hash = hashlib.sha256(b"leaf1").hexdigest()
    root_1 = compute_merkle_root([leaf_hash])
    expected_leaf = b'0' + bytes.fromhex(leaf_hash)
    assert root_1 == expected_leaf.hex()
    
    # 2 leaves
    leaf2_hash = hashlib.sha256(b"leaf2").hexdigest()
    expected_leaf2 = b'0' + bytes.fromhex(leaf2_hash)
    combined = b'1' + expected_leaf + expected_leaf2
    expected_root_2 = hashlib.sha256(combined).digest().hex()
    assert compute_merkle_root([leaf_hash, leaf2_hash]) == expected_root_2
    
    # 3 leaves (odd)
    leaf3_hash = hashlib.sha256(b"leaf3").hexdigest()
    expected_leaf3 = b'0' + bytes.fromhex(leaf3_hash)
    combined_odd = b'1' + expected_leaf3 + expected_leaf3 # duplicated odd node
    level1_right = hashlib.sha256(combined_odd).digest()
    combined_root = b'1' + bytes.fromhex(expected_root_2) + level1_right
    expected_root_3 = hashlib.sha256(combined_root).digest().hex()
    assert compute_merkle_root([leaf_hash, leaf2_hash, leaf3_hash]) == expected_root_3

def test_get_or_create_key():
    import app.config
    import importlib
    app_trust_anchors = importlib.import_module("app.trust.anchors")
    importlib.reload(app_trust_anchors)
    get_or_create_key = app_trust_anchors.get_or_create_key
    
    priv1, pub1, pub_bytes1, key_id1 = get_or_create_key()
    assert os.path.exists(os.path.join(app.config.DATA_DIR, "keys", "audit_signing.key"))
    
    # stable across restarts
    priv2, pub2, pub_bytes2, key_id2 = get_or_create_key()
    assert key_id1 == key_id2
    assert pub_bytes1 == pub_bytes2

@pytest.fixture
def test_client():
    from fastapi.testclient import TestClient
    from app.main import app
    return TestClient(app, headers={"X-Requested-With": "idff"})

def test_interval_and_ondemand_creation(test_client, app_db):
    from app.config import ANCHOR_INTERVAL
    
    # Check initial entries (LEGACY_BACKFILL creates 1)
    with app_db.session() as c:
        initial_count = c.execute("SELECT COUNT(*) FROM custody_log").fetchone()[0]
        
    # create some entries below interval
    import app.custody as custody
    entries_to_add = ANCHOR_INTERVAL - initial_count - 1
    for i in range(entries_to_add):
        with app_db.session() as c:
            custody.append(c, actor="tester", action=f"test_{i}")
            
    with app_db.session() as c:
        anchors = c.execute("SELECT * FROM audit_anchors").fetchall()
        assert len(anchors) == 0 # no anchors yet
        
    # hit the interval
    with app_db.session() as c:
        custody.append(c, actor="tester", action="test_hit")
        
    with app_db.session() as c:
        anchors = c.execute("SELECT * FROM audit_anchors").fetchall()
        assert len(anchors) == 1
        assert anchors[0]["seq_to"] == ANCHOR_INTERVAL
        
    # on-demand creation
    with app_db.session() as c:
        custody.append(c, actor="tester", action="test_after")
        
    # act as auditor
    from app.auth import current_user
    app.dependency_overrides[current_user] = lambda: {"username": "auditor1", "role": "auditor"}
    try:
        res = test_client.post("/api/audit/anchor")
        assert res.status_code == 200
        assert res.json()["status"] == "anchored"
        assert res.json()["seq_from"] == ANCHOR_INTERVAL + 1 # anchor event itself is +1
    finally:
        app.dependency_overrides.clear()
        
    with app_db.session() as c:
        anchors = c.execute("SELECT * FROM audit_anchors").fetchall()
        assert len(anchors) == 2

def test_anchor_triggers(app_db):
    import app.custody as custody
    with app_db.session() as c:
        custody.append(c, actor="tester", action="test1")
        c.execute("INSERT INTO audit_anchors (seq_from, seq_to, merkle_root, created_at, signature, key_id) VALUES (1, 1, 'abc', '2020-01-01', 'sig', 'key')")
        
    with pytest.raises(Exception, match="Anchor updates are forbidden"):
        with app_db.session() as c:
            c.execute("UPDATE audit_anchors SET merkle_root='def'")
            
    with pytest.raises(Exception, match="Anchor deletes are forbidden"):
        with app_db.session() as c:
            c.execute("DELETE FROM audit_anchors")

def test_signature_verifies(app_db):
    import app.custody as custody
    import importlib
    app_trust_anchors = importlib.import_module("app.trust.anchors")
    importlib.reload(app_trust_anchors)
    
    with app_db.session() as c:
        custody.append(c, actor="tester", action="test1")
    
    _internal_create_anchor = app_trust_anchors._internal_create_anchor
    with app_db.session() as c:
        _internal_create_anchor(c, "system")
        anchor = c.execute("SELECT * FROM audit_anchors ORDER BY id DESC LIMIT 1").fetchone()
        
    priv, pub, pub_bytes, key_id = app_trust_anchors.get_or_create_key()
    assert anchor["key_id"] == key_id
    
    msg = f"{anchor['seq_from']}|{anchor['seq_to']}|{anchor['merkle_root']}|{anchor['created_at']}".encode()
    # verify signature
    pub.verify(bytes.fromhex(anchor['signature']), msg)

def test_anchor_failure_recovery(app_db, monkeypatch):
    import app.custody as custody
    from app.config import ANCHOR_INTERVAL
    import app.trust.anchors as anchors
    
    # Mock create_anchor to raise an exception
    def mock_create(*args, **kwargs):
        raise ValueError("Simulated signing error")
        
    monkeypatch.setattr(anchors, "_internal_create_anchor", mock_create)
    
    with app_db.session() as c:
        initial_count = c.execute("SELECT COUNT(*) FROM custody_log").fetchone()[0]
        
    entries_to_add = ANCHOR_INTERVAL - initial_count
    
    # Add enough entries to trigger the anchor
    with app_db.session() as c:
        for i in range(entries_to_add - 1):
            custody.append(c, actor="tester", action=f"test_{i}")
            
        # The next append will trigger the interval
        custody.append(c, actor="tester", action="trigger_action")
        
    # The original trigger_action should succeed, and an anchor_failed event should be appended!
    with app_db.session() as c:
        logs = c.execute("SELECT * FROM custody_log ORDER BY seq DESC LIMIT 2").fetchall()
        assert logs[1]["action"] == "trigger_action"
        assert logs[0]["action"] == "anchor_failed"
        assert "Simulated signing error" in logs[0]["detail"]
