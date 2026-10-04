import pytest
from fastapi.testclient import TestClient
from app.main import app
from app import db

client = TestClient(app, headers={"X-Requested-With": "idff"})

@pytest.fixture(autouse=True)
def setup_db():
    db.init_db()
    yield

def get_token(username, role):
    res = client.post("/api/auth/setup", data={"username": "admin", "password": "password123"})
    res = client.post("/api/auth/login", data={"username": "admin", "password": "password123"})
    admin_token = res.cookies.get("idff_session", "")
    
    if username != "admin":
        client.post("/api/users", data={"username": username, "full_name": username, "role": role, "password": "password123"}, cookies={"idff_session": admin_token})
        res = client.post("/api/auth/login", data={"username": username, "password": "password123"})
    
    return res.cookies["idff_session"]

@pytest.mark.parametrize("role, initial_status, target_status, expected_status_code, expected_final_status", [
    # Investigator
    ("investigator", "Open", "Closed", 200, "Pending Legal Review"), # requests closure
    ("investigator", "Pending Legal Review", "Closed", 400, None),
    ("investigator", "Closed", "Archived", 403, None),
    
    # Supervisor
    ("supervisor", "Open", "Closed", 400, None), # must be from Pending Legal Review
    ("supervisor", "Pending Legal Review", "Closed", 200, "Closed"),
    ("supervisor", "Closed", "Archived", 200, "Archived"),
    ("supervisor", "Open", "Archived", 400, None),
    
    # Admin
    ("admin", "Open", "Closed", 403, None),
    ("admin", "Pending Legal Review", "Closed", 403, None),
    ("admin", "Closed", "Archived", 200, "Archived"),
    
    # Examiner
    ("examiner", "Open", "Closed", 403, None),
])
def test_closure_transitions(role, initial_status, target_status, expected_status_code, expected_final_status):
    token = get_token(f"user_{role}", role)
    
    # Setup case as an investigator first to get it in the right state
    inv_token = get_token("inv_setup", "investigator")
    res = client.post("/api/cases", data={"title": "Test"}, cookies={"idff_session": inv_token})
    case_id = res.json()["case_id"]
    
    # Move to initial status
    if initial_status != "Open":
        # we can cheat by updating DB directly
        with db.session() as c:
            c.execute("UPDATE cases SET status=? WHERE case_id=?", (initial_status, case_id))
            
    # Assign the user to the case
    client.post(f"/api/cases/{case_id}/members", data={"username": f"user_{role}", "role": role}, cookies={"idff_session": inv_token})
    
    # Attempt transition
    res = client.post(f"/api/cases/{case_id}/status", data={"status": target_status, "reason": "Testing"}, cookies={"idff_session": token})
    
    assert res.status_code == expected_status_code
    if expected_status_code == 200:
        assert res.json()["status"] == expected_final_status
