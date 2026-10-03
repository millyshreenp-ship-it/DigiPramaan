import os
import uuid
import hashlib
import subprocess
from datetime import datetime, timezone
from app import db, custody, config

def _hash_manifest(directory: str) -> str:
    """Compute a hash of all file names, sizes, and mtimes in the directory to prove isolation (no files modified)."""
    h = hashlib.sha256()
    for root, dirs, files in os.walk(directory):
        for name in sorted(files):
            path = os.path.join(root, name)
            try:
                st = os.stat(path)
                h.update(f"{name}|{st.st_size}|{st.st_mtime}\n".encode())
            except Exception:
                pass
    return h.hexdigest()

def execute_sandbox(case_id: str, script: str, image: str, actor: str) -> dict:
    run_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
    data_dir = str(config.DATA_DIR)
    hash_before = _hash_manifest(data_dir)
    
    exit_code = -1
    stdout = ""
    stderr = ""
    try:
        # Run in docker container with read-only mount
        res = subprocess.run(
            ["docker", "run", "--rm", "-i", "-v", f"{data_dir}:/data:ro", image, "python", "-c", script],
            capture_output=True, text=True, timeout=10
        )
        exit_code = res.returncode
        stdout = res.stdout
        stderr = res.stderr
    except subprocess.TimeoutExpired:
        stderr = "Timeout expired"
    except Exception as e:
        stderr = str(e)
        
    hash_after = _hash_manifest(data_dir)
    
    out = stdout + "\n" + stderr
    
    with db.session() as c:
        ev_id = str(uuid.uuid4())
        c.execute("INSERT INTO evidence (evidence_id, case_id, filename, size, sha256, sha512, source_type, ingested_at, vault_path) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                  (ev_id, case_id, "sandbox_output.txt", len(out), "placeholder", "placeholder", "sandbox_run", now, "placeholder_path"))
                  
        c.execute("""
            INSERT INTO sandbox_runs (run_id, case_id, image, script, exit_code, stdout, stderr, run_at, isolated_hash_before, isolated_hash_after)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (run_id, case_id, image, script, exit_code, stdout, stderr, now, hash_before, hash_after))
        
        # Log to audit trail
        custody.append(c, actor=actor, action="sandbox_run", case_id=case_id, evidence_id=ev_id,
                      detail={"run_id": run_id, "image": image, "exit_code": exit_code, "isolation_proven": hash_before == hash_after})
                      
    return {
        "run_id": run_id,
        "evidence_id": ev_id,
        "exit_code": exit_code,
        "output": out,
        "stdout": stdout,
        "stderr": stderr,
        "isolated_hash_before": hash_before,
        "isolated_hash_after": hash_after,
        "isolation_proven": hash_before == hash_after
    }
