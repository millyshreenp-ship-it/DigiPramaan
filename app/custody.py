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
    body = {"ts": now_iso(), "case_id": case_id, "evidence_id": evidence_id,
            "actor": actor, "action": action, "detail": detail or {}}
    h = _digest(prev, body)
    conn.execute(
        "INSERT INTO custody_log(ts,case_id,evidence_id,actor,action,detail,prev_hash,entry_hash) VALUES(?,?,?,?,?,?,?,?)",
        (body["ts"], case_id, evidence_id, actor, action,
         json.dumps(body["detail"], sort_keys=True, ensure_ascii=False), prev, h))
    return {**body, "prev_hash": prev, "entry_hash": h}

def verify_chain(conn) -> dict:
    prev = GENESIS
    n = 0
    for r in conn.execute("SELECT * FROM custody_log ORDER BY seq"):
        body = {"ts": r["ts"], "case_id": r["case_id"], "evidence_id": r["evidence_id"],
                "actor": r["actor"], "action": r["action"], "detail": json.loads(r["detail"] or "{}")}
        if r["prev_hash"] != prev or _digest(prev, body) != r["entry_hash"]:
            return {"intact": False, "entries_checked": n, "first_broken_seq": r["seq"], "head": prev}
        prev = r["entry_hash"]
        n += 1
    return {"intact": True, "entries_checked": n, "first_broken_seq": None, "head": prev}
