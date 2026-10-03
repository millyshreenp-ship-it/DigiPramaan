"""Chain-of-custody log: every acquire / verify / parse action is appended as a hash-linked entry.

entry_hash = SHA256(prev_hash || canonical_json(entry)). Editing or deleting any past row breaks every
hash after it, which verify_chain() detects. This is the hook point for Person 4's audit trail."""
import hashlib, json
from datetime import datetime, timezone

GENESIS = "0" * 64

def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="microseconds")

def _digest(prev_hash: str, body: dict) -> str:
    canon = json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256((prev_hash + canon).encode("utf-8")).hexdigest()

def append(conn, *, actor: str, action: str, case_id=None, evidence_id=None, detail: dict | None = None) -> dict:
    row = conn.execute("SELECT entry_hash FROM custody_log ORDER BY seq DESC LIMIT 1").fetchone()
    prev = row["entry_hash"] if row else GENESIS
    body = {"ts": now_iso(), "actor": actor, "action": action, "detail": detail or {}}
    if case_id is not None: body["case_id"] = case_id
    if evidence_id is not None: body["evidence_id"] = evidence_id
    h = _digest(prev, body)
    conn.execute(
        "INSERT INTO custody_log(ts,case_id,evidence_id,actor,action,detail,prev_hash,entry_hash) VALUES(?,?,?,?,?,?,?,?)",
        (body["ts"], case_id, evidence_id, actor, action,
         json.dumps(body["detail"], sort_keys=True, ensure_ascii=False), prev, h))
         
    if action not in ["audit_anchor_created", "anchor_failed"]:
        seq = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
        from app.config import ANCHOR_INTERVAL
        if seq % ANCHOR_INTERVAL == 0:
            try:
                from app.trust.anchors import _internal_create_anchor
                _internal_create_anchor(conn, "system")
            except Exception as e:
                append(conn, actor="system", action="anchor_failed", detail={"error": str(e)})
            
    return {**body, "prev_hash": prev, "entry_hash": h}

def verify_chain(conn, case_id=None) -> dict:
    prev = GENESIS
    n = 0
    case_n = 0
    for r in conn.execute("SELECT * FROM custody_log ORDER BY seq"):
        body = {"ts": r["ts"], "actor": r["actor"], "action": r["action"], "detail": json.loads(r["detail"] or "{}")}
        if r["case_id"] is not None: body["case_id"] = r["case_id"]
        if r["evidence_id"] is not None: body["evidence_id"] = r["evidence_id"]
        
        expected = _digest(prev, body)
        if r["prev_hash"] != prev or expected != r["entry_hash"]:
            return {"valid": False, "intact": False, "entries_checked": case_n if case_id else n, 
                    "global_entries_checked": n,
                    "first_broken_seq": r["seq"], 
                    "expected_hash": expected, "found_hash": r["entry_hash"], "head": prev}
        
        if case_id is None or r["case_id"] == case_id:
            case_n += 1
            
        prev = r["entry_hash"]
        n += 1
        
    return {"valid": True, "intact": True, "entries_checked": case_n if case_id else n, 
            "first_broken_seq": None, "expected_hash": None, "found_hash": None,
            "global_entries_checked": n, "head": prev}
