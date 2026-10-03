"""Runtime configuration (environment variables). Everything is local: no network calls anywhere."""
import os
from pathlib import Path

DATA_DIR = Path(os.environ.get("FORENSIC_DATA_DIR", Path(__file__).resolve().parent.parent / "data"))
VAULT_DIR = DATA_DIR / "vault"
DB_PATH = DATA_DIR / "intake.db"

MAX_UPLOAD_BYTES = int(os.environ.get("FORENSIC_MAX_UPLOAD_BYTES", 10 * 1024 ** 3))   # default 10 GiB
SESSION_TTL_SECONDS = int(os.environ.get("FORENSIC_SESSION_TTL", 8 * 3600))
COOKIE_SECURE = os.environ.get("FORENSIC_COOKIE_SECURE", "0") == "1"                 # set to 1 behind HTTPS
LOGIN_MAX_FAILURES = 5
LOGIN_WINDOW_SECONDS = 15 * 60

TOOL_NAME = "IDFF-Intake"
TOOL_VERSION = "1.0.0"
CHUNK = 1024 * 1024  # hashing streams 1 MiB at a time; a large image never sits in RAM
ANCHOR_INTERVAL = int(os.environ.get("ANCHOR_INTERVAL", 50))

def ensure_dirs() -> None:
    VAULT_DIR.mkdir(parents=True, exist_ok=True)
