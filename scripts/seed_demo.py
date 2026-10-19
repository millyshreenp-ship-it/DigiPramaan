"""Forensic Seed & Readiness Script for SUTRAM.

Validates all forensic sample datasets, verifies schema compliance, and prepares
the audit trail for demonstration.
"""

from datetime import datetime, timezone
import json
from pathlib import Path
import sys

# Add parent directory to path
ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT_DIR))

from backend.schemas import Case
from backend.module_api import load_case, SAMPLE_DATA_DIR


if sys.stdout.encoding != 'utf-8':
    try:
        sys.stdout.reconfigure(encoding='utf-8')
    except Exception:
        pass


def seed():
    print("=" * 65)
    print("  SUTRAM - DIGITAL FORENSICS REASONING ENGINE SEED")
    print("=" * 65)

    cases_to_verify = [
        ("case_usb_theft.json", 60),
        ("case_benign.json", 25),
    ]

    for fname, min_events in cases_to_verify:
        fpath = SAMPLE_DATA_DIR / fname
        if not fpath.exists():
            print(f"[ERROR] Sample file missing: {fpath}")
            sys.exit(1)

        with open(fpath, "r", encoding="utf-8") as f:
            data = json.load(f)

        case = Case.model_validate(data)
        print(f"[*] Verified {case.case_id} ({len(case.events)} events)")
        assert len(case.events) >= min_events, f"Expected at least {min_events} events"

    # Initialize audit trail log with session header
    audit_file = ROOT_DIR / "audit_trail.log"
    header_entry = {
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "provider": "SYSTEM",
        "action": "SESSION_INITIALIZE",
        "status": "INITIALIZED",
        "message": "SUTRAM Forensics Session Initialized. Compliance: Section 63 BSA, 2023.",
    }
    with open(audit_file, "a", encoding="utf-8") as f:
        f.write(json.dumps(header_entry) + "\n")

    print(f"[*] Audit trail initialized at: {audit_file}")
    print("[SUCCESS] All forensic cases and audit infrastructure are ready.")
    print("=" * 65)


if __name__ == "__main__":
    seed()
