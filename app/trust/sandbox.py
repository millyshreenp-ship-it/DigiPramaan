import json
import uuid
import hashlib
from datetime import datetime, timezone
from fastapi import HTTPException
from app import db, custody

def _get_master_manifest(conn, case_id: str) -> str:
    evs = conn.execute("SELECT evidence_id, filename, size FROM evidence WHERE case_id=? ORDER BY evidence_id", (case_id,)).fetchall()
    h = hashlib.sha256()
    for e in evs:
        h.update(f"{e['evidence_id']}:{e['filename']}:{e['size']}".encode())
    return h.hexdigest()

def _get_chain_head(conn) -> str:
    row = conn.execute("SELECT seq, entry_hash FROM custody_log ORDER BY seq DESC LIMIT 1").fetchone()
    if row:
        return f"{row['seq']}:{row['entry_hash']}"
    return "0:"

def create_sandbox(case_id: str, user: dict) -> str:
    with db.session() as conn:
        case = conn.execute("SELECT status, legal_hold FROM cases WHERE case_id=?", (case_id,)).fetchone()
        if not case:
            raise HTTPException(404, "Case not found")
        if case["status"].lower() == "closed" or case["legal_hold"] == 1:
            raise HTTPException(400, "Cannot create sandbox for closed or hold cases")
            
        sbx_id = f"SBX-{uuid.uuid4().hex[:8]}"
        now = datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
        
        manifest_before = _get_master_manifest(conn, case_id)
        chain_before = _get_chain_head(conn)
        
        conn.execute(
            "INSERT INTO sandbox_runs (id, case_id, created_by, created_at, status, master_manifest_before, chain_head_before) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (sbx_id, case_id, user["username"], now, "active", manifest_before, chain_before)
        )
        
        custody.append(conn, actor=user["username"], action="sandbox_created", case_id=case_id, detail={"sandbox_id": sbx_id})
        
        manifest_after = _get_master_manifest(conn, case_id)
        chain_after = _get_chain_head(conn)
        
        conn.execute("UPDATE sandbox_runs SET master_manifest_after=?, chain_head_after=? WHERE id=?", (manifest_after, chain_after, sbx_id))
        
        if manifest_before != manifest_after:
            custody.append(conn, actor="system", action="ISOLATION_BROKEN", case_id=case_id, detail={"sandbox_id": sbx_id})
            raise HTTPException(500, "Isolation broken: Master evidence changed")
            
    return sbx_id

def inject_artifact(sandbox_id: str, template: str, params: dict, expected_detection: str, user: dict) -> str:
    TEMPLATES = ["registry run-key", "forged DNS/DHCP", "clock-skew timestamp", "off-hours USB copy", "scam-chat pair", "custom JSON"]
    if template not in TEMPLATES:
        raise HTTPException(422, f"Unknown template: {template}")
        
    inj_id = f"INJ-{uuid.uuid4().hex[:8]}"
    with db.session() as conn:
        run = conn.execute("SELECT case_id, status FROM sandbox_runs WHERE id=?", (sandbox_id,)).fetchone()
        if not run or run["status"] != "active":
            raise HTTPException(404, "Sandbox not found or not active")
            
        event = {
            "event_id": inj_id,
            "event_type": "sandbox_injection",
            "title": f"Injected {template} (synthetic)",
            "timestamp": params.get("timestamp", datetime.now(timezone.utc).isoformat()),
            "synthetic": True,
            "injection_id": inj_id,
            "expected_detection_type": expected_detection,
            **params
        }
        
        conn.execute(
            "INSERT INTO sandbox_artifacts (id, sandbox_id, template, params_json, event_json, expected_detection_type) VALUES (?, ?, ?, ?, ?, ?)",
            (inj_id, sandbox_id, template, json.dumps(params), json.dumps(event), expected_detection)
        )
        
        custody.append(conn, actor=user["username"], action="sandbox_artifact_injected", case_id=run["case_id"], detail={"sandbox_id": sandbox_id, "injection_id": inj_id})
        
    return inj_id

def run_sandbox(sandbox_id: str, user: dict) -> dict:
    from app.trust.detectors import detect
    with db.session() as conn:
        run = conn.execute("SELECT case_id, status FROM sandbox_runs WHERE id=?", (sandbox_id,)).fetchone()
        if not run or run["status"] != "active":
            raise HTTPException(404, "Sandbox not found or not active")
        case_id = run["case_id"]
        
        manifest_before = _get_master_manifest(conn, case_id)
        
        # Get master events (mocking timeline)
        master_events = []
        evs = conn.execute("SELECT evidence_id, filename, ingested_at FROM evidence WHERE case_id=?", (case_id,)).fetchall()
        for e in evs:
            master_events.append({
                "event_id": e["evidence_id"],
                "evidence_id": e["evidence_id"],
                "title": f"Master {e['filename']}",
                "timestamp": e["ingested_at"]
            })
            
        # Get sandbox events
        sbx_evs = conn.execute("SELECT event_json FROM sandbox_artifacts WHERE sandbox_id=?", (sandbox_id,)).fetchall()
        sandbox_events = [json.loads(e["event_json"]) for e in sbx_evs]
        
        all_events = master_events + sandbox_events
        detections = detect(all_events)
        
        # Scoreboard
        injected = len(sandbox_events)
        detected_events = {d.event_id for d in detections}
        true_positives = len([e for e in sandbox_events if e["event_id"] in detected_events])
        missed = injected - true_positives
        false_positives = len([d for d in detections if d.event_id not in [e["event_id"] for e in sandbox_events]])
        
        res = {
            "injected": injected,
            "detected": len(detections),
            "true_positives": true_positives,
            "missed": missed,
            "false_positives": false_positives,
            "detection_rate": (true_positives / injected) if injected > 0 else 0,
            "detections": [vars(d) for d in detections],
            "isolation_status": "Master evidence unchanged"
        }
        
        conn.execute("UPDATE sandbox_runs SET last_result_json=? WHERE id=?", (json.dumps(res), sandbox_id))
        custody.append(conn, actor=user["username"], action="sandbox_run", case_id=case_id, detail={"sandbox_id": sandbox_id, "score": res})
        
        manifest_after = _get_master_manifest(conn, case_id)
        if manifest_before != manifest_after:
            custody.append(conn, actor="system", action="ISOLATION_BROKEN", case_id=case_id, detail={"sandbox_id": sandbox_id})
            raise HTTPException(500, "Isolation broken: Master evidence changed")
            
        return res

def destroy_sandbox(sandbox_id: str, user: dict) -> dict:
    with db.session() as conn:
        run = conn.execute("SELECT case_id FROM sandbox_runs WHERE id=?", (sandbox_id,)).fetchone()
        if not run:
            raise HTTPException(404, "Sandbox not found")
        conn.execute("UPDATE sandbox_runs SET status='destroyed' WHERE id=?", (sandbox_id,))
        custody.append(conn, actor=user["username"], action="sandbox_destroyed", case_id=run["case_id"], detail={"sandbox_id": sandbox_id})
    return {"status": "destroyed"}
