import requests
import json
import os
import sys
import tempfile
import shutil
import time
import subprocess

def log(msg):
    print(msg)
    sys.stdout.flush()

def main():
    temp_dir = tempfile.mkdtemp(prefix="digipramaan_e2e_")
    port = 8782
    BASE = f"http://127.0.0.1:{port}"
    
    # Start server in background
    server_cmd = [sys.executable, "-m", "uvicorn", "app.main:app", "--port", str(port)]
    env = os.environ.copy()
    env["FORENSIC_DATA_DIR"] = temp_dir
    proc = subprocess.Popen(server_cmd, env=env)
    
    try:
        # Wait for server
        for i in range(10):
            try:
                requests.get(BASE)
                break
            except requests.exceptions.ConnectionError:
                time.sleep(1)
        else:
            log("Server did not start")
            sys.exit(1)
            
        def create_session():
            sess = requests.Session()
            sess.headers.update({"X-Requested-With": "idff"})
            return sess

        sess_admin = create_session()
        sess_inv = create_session()
        sess_sup = create_session()
        sess_exam = create_session()
        sess_rev = create_session()
        sess_aud = create_session()
        sess_non_member = create_session()

        log("1. Setup users (admin)...")
        r = sess_admin.post(f"{BASE}/api/auth/setup", data={"username": "admin", "password": "password123"})
        log(f"Setup admin: {r.status_code} {r.text}")
        r = sess_admin.post(f"{BASE}/api/auth/login", data={"username": "admin", "password": "password123"})
        
        users = [
            ("inv", "investigator", sess_inv),
            ("sup", "supervisor", sess_sup),
            ("exam", "examiner", sess_exam),
            ("rev", "reviewer", sess_rev),
            ("aud", "auditor", sess_aud),
            ("non", "investigator", sess_non_member),
        ]
        
        for u, role, sess in users:
            r = sess_admin.post(f"{BASE}/api/users", data={"username": u, "role": role, "password": "password123"})
            log(f"Create {role}: {r.status_code}")
            sess.post(f"{BASE}/api/auth/login", data={"username": u, "password": "password123"})

        log("\n2. Investigator creates a case, uploads, verifies and parses a sample...")
        r = sess_inv.post(f"{BASE}/api/cases", data={"title": "E2E Case"})
        log(f"Create case: {r.status_code} {r.text}")
        case_id = r.json()["case_id"]
        
        with open("samples_for_testing/auth.log", "rb") as f:
            r = sess_inv.post(f"{BASE}/api/cases/{case_id}/evidence", files={"file": f}, data={"description": "Test Evidence"})
        log(f"Upload: {r.status_code} {r.text}")
        ev_id = r.json()["evidence_id"]
        
        r = sess_inv.post(f"{BASE}/api/cases/{case_id}/evidence/{ev_id}/verify")
        log(f"Verify evidence: {r.status_code} {r.text}")
        r = sess_inv.post(f"{BASE}/api/cases/{case_id}/evidence/{ev_id}/parse")
        log(f"Parse evidence: {r.status_code} {r.text}")
        
        log("\n3. Assign supervisor, examiner, and reviewer, then remove examiner...")
        for u, role in [("sup", "supervisor"), ("exam", "examiner"), ("rev", "reviewer")]:
            r = sess_inv.post(f"{BASE}/api/cases/{case_id}/members", data={"username": u, "role": role})
            log(f"Assign {role}: {r.status_code} {r.text}")
            
        r = sess_inv.delete(f"{BASE}/api/cases/{case_id}/members/exam")
        log(f"Remove examiner: {r.status_code} {r.text}")
        
        log("\n4. Edit metadata (audit diff present)...")
        r = sess_inv.post(f"{BASE}/api/cases/{case_id}/metadata", data={"title": "E2E Case Edited", "description": "Desc"})
        log(f"Edit metadata: {r.status_code} {r.text}")
        
        log("\n5. Status change with a reason; an illegal transition is rejected...")
        r = sess_inv.post(f"{BASE}/api/cases/{case_id}/status", data={"status": "Closed", "reason": "Illegal transition test"})
        log(f"Illegal transition (Open->Closed for inv): {r.status_code} {r.text}") # Wait, investigator to Closed goes to PLR directly, which is allowed from Open.
        # Wait, Open -> PLR is allowed. 
        # Let's try Open to Archived (Illegal)
        r = sess_inv.post(f"{BASE}/api/cases/{case_id}/status", data={"status": "Archived", "reason": "Illegal transition test"})
        log(f"Illegal transition (Open->Archived): {r.status_code} {r.text}")
        
        log("\n6. Closure request, admin close attempt (403), supervisor approval (Closed)...")
        r = sess_inv.post(f"{BASE}/api/cases/{case_id}/status", data={"status": "Closed", "reason": "Closure requested"})
        log(f"Closure request (inv): {r.status_code} {r.text}")
        
        r = sess_admin.post(f"{BASE}/api/cases/{case_id}/status", data={"status": "Closed", "reason": "Admin attempt"})
        log(f"Admin close attempt: {r.status_code} {r.text}")
        
        r = sess_sup.post(f"{BASE}/api/cases/{case_id}/status", data={"status": "Closed", "reason": "Approved"})
        log(f"Supervisor approval: {r.status_code} {r.text}")
        
        log("\n7. Edit of a closed case rejected...")
        r = sess_inv.post(f"{BASE}/api/cases/{case_id}/metadata", data={"title": "Try edit closed", "description": "Desc"})
        log(f"Edit closed case: {r.status_code} {r.text}")
        
        log("\n8. Legal hold blocks edits on a second case...")
        r = sess_inv.post(f"{BASE}/api/cases", data={"title": "E2E Case 2"})
        case2_id = r.json()["case_id"]
        sess_admin.post(f"{BASE}/api/cases/{case2_id}/legal_hold", data={"enabled": "true", "reason": "hold"})
        r = sess_inv.post(f"{BASE}/api/cases/{case2_id}/metadata", data={"title": "Try edit hold", "description": "Desc"})
        log(f"Edit legally held case: {r.status_code} {r.text}")
        
        log("\n9. Non-member gets 403 on timeline, graph, query, evidence, sandbox and certificate...")
        r = sess_non_member.get(f"{BASE}/api/cases/{case_id}/timeline")
        log(f"Non-member timeline: {r.status_code}")
        r = sess_non_member.get(f"{BASE}/api/cases/{case_id}/graph")
        log(f"Non-member graph: {r.status_code}")
        r = sess_non_member.get(f"{BASE}/api/cases/{case_id}/query")
        log(f"Non-member query: {r.status_code}")
        r = sess_non_member.get(f"{BASE}/api/cases/{case_id}/evidence")
        log(f"Non-member evidence: {r.status_code}")
        r = sess_non_member.get(f"{BASE}/api/cases/{case_id}/sandbox")
        log(f"Non-member sandbox: {r.status_code}")
        r = sess_non_member.get(f"{BASE}/api/cases/{case_id}/certificate")
        log(f"Non-member certificate: {r.status_code}")
        
        log("\n10. Certificate generation...")
        for u_name, sess in [("reviewer", sess_rev), ("supervisor", sess_sup), ("investigator", sess_inv)]:
            r = sess.get(f"{BASE}/api/cases/{case_id}/certificate")
            is_pdf = "%PDF" in r.text[:10]
            footer = "Prototype template. Statutory wording must be validated by legal counsel." in r.text
            log(f"{u_name} certificate: {r.status_code}, PDF: {is_pdf}, footer: {footer}")
            
        for u_name, sess in [("examiner", sess_exam), ("auditor", sess_aud)]:
            # examiner is not a member anymore, but auditor is just not allowed
            # let's add auditor as a member to be sure it's 403 because of role
            sess_inv.post(f"{BASE}/api/cases/{case_id}/members", data={"username": "aud", "role": "auditor"})
            r = sess.get(f"{BASE}/api/cases/{case_id}/certificate")
            log(f"{u_name} certificate: {r.status_code}")
            
        log("\n11. Admin creates anchor, downloads bundle, tools/verify_audit.py...")
        r = sess_admin.post(f"{BASE}/api/audit/anchor", data={})
        log(f"Create anchor: {r.status_code} {r.text}")
        
        bundle_path = os.path.join(temp_dir, "bundle_full.json")
        r = sess_admin.get(f"{BASE}/api/audit/bundle")
        with open(bundle_path, "w") as f:
            f.write(r.text)
        log(f"Download bundle admin: {r.status_code}")
        
        cmd = [sys.executable, "tools/verify_audit.py", bundle_path]
        res = subprocess.run(cmd, capture_output=True, text=True)
        log(f"Verify full bundle (exit {res.returncode}): {res.stdout.strip()}")
        
        log("\n12. Auditor redacted bundle checks...")
        r = sess_aud.get(f"{BASE}/api/audit/bundle")
        redacted_bundle = r.json()
        raw_text = r.text
        leaks = any(x in raw_text for x in ["E2E Case", "test_timeline.csv", "Starting"]) # title, filename, notes
        log(f"Auditor bundle downloaded: leaks present = {leaks}")
        redacted_path = os.path.join(temp_dir, "bundle_auditor.json")
        with open(redacted_path, "w") as f:
            f.write(r.text)
        res = subprocess.run([sys.executable, "tools/verify_audit.py", redacted_path], capture_output=True, text=True)
        log(f"Verify redacted bundle (exit {res.returncode}): {res.stdout.strip()}")
        
        log("\n13. One-character corruption...")
        corrupted = json.dumps(redacted_bundle).replace(redacted_bundle["entries"][0]["entry_hash"][:10], "0000000000")
        corr_path = os.path.join(temp_dir, "bundle_corrupt.json")
        with open(corr_path, "w") as f:
            f.write(corrupted)
        res = subprocess.run([sys.executable, "tools/verify_audit.py", corr_path], capture_output=True, text=True)
        log(f"Verify corrupted bundle (exit {res.returncode})")
        
        log("\n14. Admin tamper simulation...")
        r = sess_admin.post(f"{BASE}/api/audit/tamper-simulation", data={"target": "evidence_metadata", "case_id": case_id})
        log(f"Tamper simulation: {r.status_code} {r.text}")
        r = sess_admin.get(f"{BASE}/api/audit/verify")
        log(f"Verify chain after tamper: {r.status_code} {r.text}")
        
        log("\n15. Sandbox scoreboard...")
        r = sess_inv.post(f"{BASE}/api/cases", data={"title": "E2E Case Sandbox"})
        case3_id = r.json()["case_id"]
        
        with open("samples_for_testing/auth.log", "rb") as f:
            sess_inv.post(f"{BASE}/api/cases/{case3_id}/evidence", files={"file": f}, data={"description": "Test Evidence"})
            
        r = sess_inv.post(f"{BASE}/api/cases/{case3_id}/sandbox")
        if r.status_code == 200:
            sandbox_id = r.json()["sandbox_id"]
            
            templates = ["registry run-key", "forged DNS/DHCP", "clock-skew timestamp", "off-hours USB copy", "scam-chat pair", "custom JSON"]
            for t in templates:
                sess_inv.post(f"{BASE}/api/cases/{case3_id}/sandbox/{sandbox_id}/inject", json={"template": t, "params": {}, "expected_detection_type": "suspicious"})
                
            r = sess_inv.post(f"{BASE}/api/cases/{case3_id}/sandbox/{sandbox_id}/run")
            log(f"Sandbox run: {r.status_code} {r.text}")
        else:
            log(f"Sandbox create: {r.status_code} {r.text}")
        
        log("\n16. Synthetic marker checks...")
        r = sess_inv.get(f"{BASE}/api/cases/{case_id}/timeline")
        log(f"Marker in timeline: {'[SYNTHETIC]' in r.text}")
        
    finally:
        proc.terminate()
        proc.wait()
        shutil.rmtree(temp_dir, ignore_errors=True)
        log("Cleaned up temp dir and server.")

if __name__ == "__main__":
    main()
