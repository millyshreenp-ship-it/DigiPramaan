import sys
import json
import hashlib
from cryptography.hazmat.primitives import serialization # type: ignore

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

def verify_bundle(bundle_path, key_path=None):
    with open(bundle_path, 'r') as f:
        bundle = json.load(f)
        
    entries = bundle["entries"]
    anchors = bundle["anchors"]
    
    if key_path:
        with open(key_path, 'rb') as f:
            key_bytes = f.read()
            try:
                public_key = serialization.load_pem_public_key(key_bytes)
            except Exception:
                try:
                    private_key = serialization.load_pem_private_key(key_bytes, password=None)
                    public_key = private_key.public_key()
                except Exception:
                    print("Verification failed: Could not load key.")
                    sys.exit(1)
    else:
        pub_bytes = bundle["public_key"].encode('utf-8')
        public_key = serialization.load_pem_public_key(pub_bytes)
    
    prev = "0" * 64
    redacted_count = 0
    for r in entries:
        if r["detail"] == '{"redacted": true}':
            redacted_count += 1
            expected = r['entry_hash']
        else:
            body = {"ts": r["ts"], "actor": r["actor"], "action": r["action"], "detail": json.loads(r["detail"])}
            if r.get("case_id") is not None:
                body["case_id"] = r["case_id"]
            if r.get("evidence_id") is not None:
                body["evidence_id"] = r["evidence_id"]
            canon = json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
            expected = hashlib.sha256((prev + canon).encode("utf-8")).hexdigest()
            
            if expected != r['entry_hash']:
                print(f"Verification failed: Chain broken at seq {r['seq']}")
                sys.exit(1)
        prev = expected
        
    # 2. Verify anchors
    # Map entries by seq for quick slice
    entry_dict = {e["seq"]: e["entry_hash"] for e in entries}
    
    last_seq = 0
    for a in anchors:
        seq_from = a["seq_from"]
        seq_to = a["seq_to"]
        
        # Check gap
        if seq_from != last_seq + 1:
            print(f"Verification failed: Anchor coverage gap before seq {seq_from}")
            sys.exit(1)
        last_seq = seq_to
            
        # Recompute Merkle root
        hashes = []
        for i in range(seq_from, seq_to + 1):
            if i not in entry_dict:
                print(f"Verification failed: Missing entry for seq {i} covered by anchor {a['id']}")
                sys.exit(1)
            hashes.append(entry_dict[i])
            
        root = compute_merkle_root(hashes)
        if root != a["merkle_root"]:
            print(f"Verification failed: Merkle root mismatch at anchor {a['id']}")
            sys.exit(1)
            
        # Verify signature
        msg = f"{seq_from}|{seq_to}|{root}|{a['created_at']}".encode()
        try:
            public_key.verify(bytes.fromhex(a["signature"]), msg)
        except Exception:
            print(f"Verification failed: Signature invalid at anchor {a['id']}")
            sys.exit(1)
            
    if redacted_count > 0:
        print(f"content hash not recomputable for {redacted_count} redacted entries")
    print("Verification passed")
    sys.exit(0)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python verify_audit.py bundle.json [key_file]")
        sys.exit(1)
        
    bundle_file = sys.argv[1]
    key_file = sys.argv[2] if len(sys.argv) > 2 else None
    
    verify_bundle(bundle_file, key_file)
