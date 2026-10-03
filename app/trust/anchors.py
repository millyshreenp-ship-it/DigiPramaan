import os
import hashlib
from datetime import datetime, timezone
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization
from fastapi import APIRouter, Depends, HTTPException
from app import config, db, custody
from app.trust.rbac import require_permission

router = APIRouter()

# Merkle rules: 
# - leaf = entry_hash bytes
# - domain separation: prefix b'0' for leaves, b'1' for inner nodes
# - odd-node handling: duplicate the last node to make pairs

def get_or_create_key():
    key_dir = os.path.join(config.DATA_DIR, "keys")
    os.makedirs(key_dir, exist_ok=True)
    key_path = os.path.join(key_dir, "audit_signing.key")
    
    if not os.path.exists(key_path):
        private_key = ed25519.Ed25519PrivateKey.generate()
        key_bytes = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        with open(key_path, "wb") as f:
            f.write(key_bytes)
        # Attempt to set permissions to 0600 (note: Windows ignores POSIX modes)
        try:
            os.chmod(key_path, 0o600)
        except:
            pass
            
    with open(key_path, "rb") as f:
        key_bytes = f.read()
    
    private_key = serialization.load_pem_private_key(key_bytes, password=None)
    public_key = private_key.public_key()
    pub_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    key_id = hashlib.sha256(pub_bytes).hexdigest()[:16]
    return private_key, public_key, pub_bytes, key_id

def compute_merkle_root(hashes):
    if not hashes:
        return ""
    
    nodes = [b'0' + bytes.fromhex(h) for h in hashes]
    while len(nodes) > 1:
        if len(nodes) % 2 != 0:
            nodes.append(nodes[-1]) # Duplicate odd node
        
        next_level = []
        for i in range(0, len(nodes), 2):
            combined = b'1' + nodes[i] + nodes[i+1]
            next_level.append(hashlib.sha256(combined).digest())
        nodes = next_level
        
    return nodes[0].hex()

@router.get("/api/audit/public-key")
def get_public_key():
    _, _, pub_bytes, key_id = get_or_create_key()
    return {"key_id": key_id, "public_key": pub_bytes.decode('utf-8')}

def _internal_create_anchor(conn, actor: str):
    # Find last anchor
    last_anchor = conn.execute("SELECT seq_to FROM audit_anchors ORDER BY id DESC LIMIT 1").fetchone()
    seq_from = (last_anchor["seq_to"] + 1) if last_anchor else 1
    
    # Get unanchored entries
    entries = conn.execute("SELECT seq, entry_hash FROM custody_log WHERE seq >= ? ORDER BY seq", (seq_from,)).fetchall()
    if not entries:
        return {"status": "up_to_date", "message": "No new entries to anchor."}
    
    seq_to = entries[-1]["seq"]
    hashes = [e["entry_hash"] for e in entries]
    root = compute_merkle_root(hashes)
    
    private_key, _, _, key_id = get_or_create_key()
    ts = datetime.now(timezone.utc).isoformat()
    
    msg = f"{seq_from}|{seq_to}|{root}|{ts}".encode()
    sig = private_key.sign(msg).hex()
    
    conn.execute("INSERT INTO audit_anchors (seq_from, seq_to, merkle_root, created_at, signature, key_id) VALUES (?,?,?,?,?,?)",
                 (seq_from, seq_to, root, ts, sig, key_id))
    
    custody.append(conn, actor=actor, action="audit_anchor_created", case_id=None, detail={"seq_from": seq_from, "seq_to": seq_to, "merkle_root": root})
    
    return {"status": "anchored", "seq_from": seq_from, "seq_to": seq_to, "merkle_root": root}

@router.post("/api/audit/anchor")
def create_anchor(user: dict = Depends(require_permission("audit:verify"))):
    with db.session() as c:
        return _internal_create_anchor(c, user["username"])

@router.get("/api/audit/bundle")
def export_bundle(redacted: bool = False, user: dict = Depends(require_permission("audit:read"))):
    from app.trust.rbac import PERMISSIONS
    
    if user["role"] == "auditor":
        redacted = True
        
    if not redacted and "audit:export" not in PERMISSIONS.get(user["role"], []):
        raise HTTPException(403, "Role lacks permission for unredacted export")
        
    _, _, pub_bytes, key_id = get_or_create_key()
    
    with db.session() as c:
        entries = [dict(r) for r in c.execute("SELECT * FROM custody_log ORDER BY seq").fetchall()]
        if redacted:
            for entry in entries:
                if entry.get("detail"):
                    entry["detail"] = '{"redacted": true}'
                    
        anchors = [dict(r) for r in c.execute("SELECT * FROM audit_anchors ORDER BY id").fetchall()]
        
        custody.append(c, actor=user["username"], action="audit_bundle_exported", case_id=None, detail={"total_entries": len(entries), "total_anchors": len(anchors), "redacted": redacted})
        
        bundle = {
            "tool": "DigiPramaan Audit Bundle Export",
            "version": "1.0",
            "hash_scheme": "SHA-256",
            "public_key": pub_bytes.decode('utf-8'),
            "key_id": key_id,
            "entries": entries,
            "anchors": anchors
        }
        return bundle
