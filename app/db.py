"""SQLite persistence. Schema mirrors the Core Data Model in the requirements doc
(Case / EvidenceItem / Artifact / Event) so Timeline & Graph can read it directly."""
import sqlite3
from contextlib import contextmanager
from . import config

SCHEMA = """
CREATE TABLE IF NOT EXISTS cases (
  case_id TEXT PRIMARY KEY, title TEXT NOT NULL, jurisdiction TEXT, investigator TEXT,
  status TEXT NOT NULL DEFAULT 'open', created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS evidence (
  evidence_id TEXT PRIMARY KEY, case_id TEXT NOT NULL REFERENCES cases(case_id),
  filename TEXT NOT NULL, source_type TEXT, acquisition_method TEXT, custodian TEXT, notes TEXT,
  size INTEGER NOT NULL, sha256 TEXT NOT NULL, sha512 TEXT NOT NULL,
  declared_sha256 TEXT, declared_match INTEGER,
  original_timestamp TEXT,
  ingested_at TEXT NOT NULL, vault_path TEXT NOT NULL,
  integrity_status TEXT NOT NULL DEFAULT 'VERIFIED',
  last_verified_at TEXT
);
CREATE TABLE IF NOT EXISTS artifacts (
  artifact_id TEXT PRIMARY KEY, evidence_id TEXT NOT NULL REFERENCES evidence(evidence_id),
  artifact_type TEXT NOT NULL, parser TEXT NOT NULL, parser_version TEXT NOT NULL,
  derived_hash TEXT NOT NULL, parent_sha256 TEXT NOT NULL,
  event_count INTEGER NOT NULL, params TEXT, notes TEXT, created_at TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'active'
);
CREATE TABLE IF NOT EXISTS events (
  event_id TEXT PRIMARY KEY, case_id TEXT NOT NULL, evidence_id TEXT NOT NULL, artifact_id TEXT NOT NULL,
  event_type TEXT NOT NULL, summary TEXT,
  original_time TEXT,
  normalized_time TEXT,
  timezone TEXT, uncertainty_seconds REAL, time_quality TEXT,
  source_ref TEXT,
  raw TEXT, fields TEXT, entities TEXT
);
CREATE INDEX IF NOT EXISTS ix_events_case_time ON events(case_id, normalized_time);
CREATE INDEX IF NOT EXISTS ix_events_type ON events(case_id, event_type);
CREATE TABLE IF NOT EXISTS users (
  user_id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT NOT NULL UNIQUE COLLATE NOCASE, full_name TEXT,
  role TEXT NOT NULL, password_hash TEXT NOT NULL, active INTEGER NOT NULL DEFAULT 1, created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS sessions (
  token_hash TEXT PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(user_id), expires_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS custody_log (
  seq INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT NOT NULL, case_id TEXT, evidence_id TEXT,
  actor TEXT NOT NULL, action TEXT NOT NULL, detail TEXT, prev_hash TEXT NOT NULL, entry_hash TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS case_members (
  case_id TEXT NOT NULL REFERENCES cases(case_id), user_id INTEGER NOT NULL REFERENCES users(user_id),
  case_role TEXT NOT NULL, assigned_by TEXT NOT NULL, assigned_at TEXT NOT NULL,
  PRIMARY KEY (case_id, user_id)
);
"""

def connect() -> sqlite3.Connection:
    config.ensure_dirs()
    conn = sqlite3.connect(config.DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys=ON")
    return conn

def init_db() -> None:
    conn = connect()
    conn.executescript(SCHEMA)
    cols = [r[1] for r in conn.execute("PRAGMA table_info(cases)").fetchall()]
    for col, ctype in [("human_ref", "TEXT"), ("fir_number", "TEXT"), ("crime_category", "TEXT"),
                       ("unit", "TEXT"), ("description", "TEXT"), ("priority", "TEXT"),
                       ("created_by", "TEXT"), ("legal_hold", "INTEGER DEFAULT 0")]:
        if col not in cols:
            conn.execute(f"ALTER TABLE cases ADD COLUMN {col} {ctype}")
    _backfill_case_members(conn)
    conn.commit()
    conn.close()

def _backfill_case_members(conn):
    count = conn.execute("SELECT COUNT(*) FROM case_members").fetchone()[0]
    if count == 0:
        cases = conn.execute("SELECT case_id FROM cases").fetchall()
        if cases:
            from datetime import datetime, timezone
            now = datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
            users = conn.execute("SELECT user_id, username, role FROM users WHERE active=1").fetchall()
            for c in cases:
                for u in users:
                    conn.execute("INSERT INTO case_members VALUES (?, ?, ?, ?, ?)", (c["case_id"], u["user_id"], u["role"], "system", now))
            from app import custody
            custody.append(conn, actor="system", action="LEGACY_BACKFILL", detail={"cases": len(cases), "users": len(users)})

@contextmanager
def session():
    conn = connect()
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()
