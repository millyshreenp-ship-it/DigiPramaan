import requests
import json
import os
import sys

BASE = "http://127.0.0.1:8771"

def log(msg):
    print(msg)
    sys.stdout.flush()

def main():
    sess_admin = requests.Session()
    sess_admin.headers.update({"X-Requested-With": "idff"})
    # 1. Setup investigator and supervisor
    log("1. Setup users (admin)...")
    r_setup = sess_admin.post(f"{BASE}/api/auth/setup", data={"username": "admin", "password": "password123"})
    log(f"Setup: {r_setup.status_code} {r_setup.text}")
    r_login = sess_admin.post(f"{BASE}/api/auth/login", data={"username": "admin", "password": "password123"})
    log(f"Login: {r_login.status_code} {r_login.text}")
    
    r = sess_admin.post(f"{BASE}/api/users", data={"username": "inv", "role": "investigator", "password": "password123"})
    log(f"Create investigator: {r.status_code}")
    r = sess_admin.post(f"{BASE}/api/users", data={"username": "sup", "role": "supervisor", "password": "password123"})
    log(f"Create supervisor: {r.status_code}")
    
    # 2. Login as investigator
    log("\n2. Login as investigator...")
    sess_inv = requests.Session()
    sess_inv.headers.update({"X-Requested-With": "idff"})
    sess_inv.post(f"{BASE}/api/auth/login", data={"username": "inv", "password": "password123"})
    
    # 3. Create case
    log("\n3. Create case...")
    r = sess_inv.post(f"{BASE}/api/cases", data={"title": "E2E Case"})
    log(f"Create case: {r.status_code} {r.text}")
    case_id = r.json()["case_id"]
    
    # 4. Assign supervisor
    log("\n4. Assign supervisor...")
    r = sess_inv.post(f"{BASE}/api/cases/{case_id}/members", data={"username": "sup", "role": "supervisor"})
    log(f"Assign: {r.status_code} {r.text}")
    
    # 5. Upload evidence
    log("\n5. Upload evidence...")
    with open("samples_for_testing/make_samples.py", "rb") as f:
        r = sess_inv.post(f"{BASE}/api/cases/{case_id}/evidence", files={"file": f}, data={"description": "Test Evidence"})
    log(f"Upload: {r.status_code} {r.text}")
    evidence_id = r.json()["evidence_id"]
    
    # 6. Status: Under Analysis -> Pending Legal Review
    log("\n6. Investigator changes status...")
    r = sess_inv.post(f"{BASE}/api/cases/{case_id}/status", data={"status": "Under Analysis", "reason": "Starting"})
    log(f"Under Analysis: {r.status_code} {r.text}")
    
    # Request close -> PLR
    r = sess_inv.post(f"{BASE}/api/cases/{case_id}/status", data={"status": "Closed", "reason": "Done"})
    log(f"Closed (should be PLR): {r.status_code} {r.text}")
    
    # 7. Login as supervisor
    log("\n7. Login as supervisor...")
    sess_sup = requests.Session()
    sess_sup.headers.update({"X-Requested-With": "idff"})
    sess_sup.post(f"{BASE}/api/auth/login", data={"username": "sup", "password": "password123"})
    
    # 8. Close case
    log("\n8. Supervisor closes case...")
    r = sess_sup.post(f"{BASE}/api/cases/{case_id}/status", data={"status": "Closed", "reason": "Approved"})
    log(f"Close case: {r.status_code} {r.text}")
    
    # 9. Verify audit trail
    log("\n9. Verify audit trail...")
    r = sess_admin.get(f"{BASE}/api/audit")
    log(f"Audit log status: {r.status_code}")
    entries = r.json().get("entries", [])
    log(f"Audit log entries: {len(entries)}")
    for e in entries:
        log(f"  {e['action']} by {e['actor']}")
        
    r = sess_admin.get(f"{BASE}/api/audit/verify")
    log(f"Verify chain: {r.status_code} {r.text}")
    
    # 10. Tamper simulation
    log("\n10. Tamper simulation...")
    r = sess_admin.post(f"{BASE}/api/audit/tamper-simulation", data={"target": "evidence_metadata", "case_id": case_id})
    log(f"Tamper simulation: {r.status_code} {r.text}")
        
    r = sess_admin.get(f"{BASE}/api/audit/verify")
    log(f"Verify chain after tamper: {r.status_code} {r.text}")

if __name__ == "__main__":
    main()
