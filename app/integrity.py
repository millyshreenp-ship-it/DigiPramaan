"""Evidence vault + integrity engine.

Rules enforced here:
  * Uploads are streamed to a temp file while SHA-256 and SHA-512 are computed in the same single pass.
  * The file is then moved into the vault and made read-only (chmod 0444). The vault copy is the master.
  * Parsers only ever *read* the vault copy; they never write to it.
  * verify() re-hashes from disk and compares to the hashes recorded at acquisition.
"""
import hashlib, os, shutil, tempfile, uuid
from pathlib import Path
from . import config

def hash_file(path: Path) -> tuple[str, str, int]:
    h256, h512, size = hashlib.sha256(), hashlib.sha512(), 0
    with open(path, "rb") as f:
        while chunk := f.read(config.CHUNK):
            h256.update(chunk); h512.update(chunk); size += len(chunk)
    return h256.hexdigest(), h512.hexdigest(), size

def new_evidence_id() -> str:
    return "EV-" + uuid.uuid4().hex[:10].upper()

class TooLarge(Exception):
    pass

def store_stream(evidence_id: str, stream, filename: str) -> dict:
    """Consume a file-like object (UploadFile.file). Returns hashes, size and the vault path."""
    config.ensure_dirs()
    h256, h512, size = hashlib.sha256(), hashlib.sha512(), 0
    fd, tmp = tempfile.mkstemp(dir=config.VAULT_DIR, prefix=".incoming-")
    try:
        with os.fdopen(fd, "wb") as out:
            while chunk := stream.read(config.CHUNK):
                h256.update(chunk); h512.update(chunk); size += len(chunk)
                if size > config.MAX_UPLOAD_BYTES:
                    raise TooLarge()
                out.write(chunk)
            out.flush(); os.fsync(out.fileno())
        ev_dir = config.VAULT_DIR / evidence_id
        ev_dir.mkdir(parents=True, exist_ok=False)
        dest = ev_dir / "master.bin"          # original filename is metadata only (avoids path tricks)
        shutil.move(tmp, dest)
        os.chmod(dest, 0o444)                 # read-only master
    except Exception:
        if os.path.exists(tmp):
            os.unlink(tmp)
        raise
    return {"sha256": h256.hexdigest(), "sha512": h512.hexdigest(), "size": size, "vault_path": str(dest)}

def verify(row) -> dict:
    """row: an evidence DB row. Returns status plus expected/actual hashes for display."""
    p = Path(row["vault_path"])
    if not p.exists():
        return {"status": "MISSING", "expected_sha256": row["sha256"], "actual_sha256": None,
                "expected_size": row["size"], "actual_size": None, "sha512_ok": False}
    a256, a512, asize = hash_file(p)
    ok = a256 == row["sha256"] and a512 == row["sha512"] and asize == row["size"]
    return {"status": "VERIFIED" if ok else "TAMPERED",
            "expected_sha256": row["sha256"], "actual_sha256": a256,
            "expected_size": row["size"], "actual_size": asize,
            "sha512_ok": a512 == row["sha512"]}

def normalize_hash(s: str | None) -> str | None:
    if not s:
        return None
    s = s.strip().lower().replace(" ", "")
    return s if len(s) == 64 and all(c in "0123456789abcdef" for c in s) else "INVALID"
