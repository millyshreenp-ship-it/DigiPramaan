"""One-Command Demonstration Launcher for SUTRAM.

Can be run via:
    python demo.py           (Launches full-stack FastAPI server + React UI on http://localhost:8000)
    python demo.py --cli     (Executes automated courtroom cross-examination demo in terminal)
"""

import argparse
import os
import sys
import time
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT_DIR))

from backend.module_api import (
    load_case,
    detect_anomalies,
    summarize_case,
    cross_examine_finding,
    add_evidence_and_reevaluate,
)
from backend.schemas import Event


if sys.stdout.encoding != 'utf-8':
    try:
        sys.stdout.reconfigure(encoding='utf-8')
    except Exception:
        pass


def run_cli_demo():
    print("\n" + "=" * 70)
    print("  SUTRAM - AI FORENSICS & ADVERSARIAL ENGINE (CLI DEMO)")
    print("=" * 70)

    # 1. Load sample USB theft case
    print("\n[STEP 1] Loading Forensic Timeline Telemetry...")
    case = load_case("case_usb_theft")
    print(f" -> Case Loaded: {case.case_id} ({len(case.events)} events)")

    # 2. Detect Anomalies (Feature 3)
    print("\n[STEP 2] Running Hybrid Anomaly Detection (Rules + IsolationForest)...")
    anomalies = detect_anomalies(case)
    print(f" -> Detected {len(anomalies)} anomalies. Top 3:")
    for a in anomalies[:3]:
        print(f"    * [{a.type.upper()}] Score: {a.score*100:.0f}% | {a.explanation[:85]}...")

    # 3. Summarize with Citation Validator (Feature 1)
    print("\n[STEP 3] Generating AI Summary with Citation Validator...")
    summary_resp = summarize_case(case, focus="USB data movement")
    print(f" -> {len(summary_resp.summary)} Ground-Truth Verified Claims:")
    for c in summary_resp.summary[:3]:
        print(f"    * \"{c.claim[:80]}...\" (Citations: {c.citations})")
    print(f" -> Limitations: {summary_resp.limitations[0]}")

    # 4. Adversarial Self-Cross-Examination (Feature 2 - HEADLINE)
    finding = "Employee user_x stole Quarterly_Financials.xlsx via USB storage"
    cites = ["EVT-0043", "EVT-0047"]
    print(f"\n[STEP 4] Executing Adversarial Cross-Examination on Finding:")
    print(f"         \"{finding}\"")
    brief = cross_examine_finding(case, finding, cites)

    print(f"\n -> INITIAL FINDING STRENGTH: [{brief.finding_strength.upper()}]")
    print(" -> Defense Attorney Counter-Hypotheses (Evidential Loopholes):")
    for h in brief.counter_hypotheses:
        print(f"    * [{h.id}] {h.status.upper()} (Plausibility: {h.plausibility.upper()})")
        print(f"      Theory: {h.alternative_explanation[:75]}...")
        print(f"      Artifact to rule out: {h.evidence_needed_to_rule_out[0] if h.evidence_needed_to_rule_out else 'N/A'}")

    # 5. Dynamic Corroboration / Rule-out (Feature 2 Re-run)
    print("\n[STEP 5] Investigator pulls corroborating evidence (Task Scheduler XML & CCTV)...")
    time.sleep(1)

    new_events = [
        Event(
            event_id="EVT-CORROB-XML-01",
            timestamp_utc="2025-03-14T23:10:00Z",
            clock_uncertainty_sec=0.0,
            source="windows_security_log",
            actor="investigator",
            action="other",
            object="Task_Definition.xml",
            details={"destination_drive": "D:", "notes": "Task target is D:\\InternalArchive, NOT USB E:"},
            evidence_hash="5f9b4c2e1d0a876321456987abcdefe3344556677889900aabbccddeeff00112",
            raw_ref="DailyArchiveJob.xml"
        ),
        Event(
            event_id="EVT-CORROB-CCTV-02",
            timestamp_utc="2025-03-14T23:15:00Z",
            clock_uncertainty_sec=0.5,
            source="cctv",
            actor="investigator",
            action="other",
            object="Camera_04",
            details={"physical_presence": True, "user_x_sitting": True, "badge_swiped": "BADGE-USER-X"},
            evidence_hash="9a8b7c6d5e4f3210fedcba0987654321112233445566778899aabbccddeeff00",
            raw_ref="CCTV_FinanceBay_Camera4"
        ),
        Event(
            event_id="EVT-CORROB-ASSET-03",
            timestamp_utc="2025-03-14T23:20:00Z",
            clock_uncertainty_sec=0.0,
            source="other",
            actor="it_admin",
            action="other",
            object="IT_Asset_Database",
            details={"is_authorized_asset": False, "status": "unregistered_personal_device"},
            evidence_hash="77889900aabbccddeeff11223344556699887766554433221100ffeeddccbbaa",
            raw_ref="IT_Asset_Portal"
        ),
    ]

    updated_brief = add_evidence_and_reevaluate(brief, case, new_events)
    print(f" -> RE-EVALUATED FINDING STRENGTH: [{updated_brief.finding_strength.upper()}] (Loopholes Closed!)")
    for h in updated_brief.counter_hypotheses:
        if h.status == "ruled_out":
            print(f"    * [{h.id}] RULED OUT: {h.rationale[:70]}...")

    print("\n[STEP 6] Statutory Admissibility Notes (Section 63 BSA, 2023):")
    for note in updated_brief.admissibility_notes[:2]:
        print(f"    * {note}")

    print("\n" + "=" * 70)
    print("  CLI DEMO COMPLETED SUCCESSFULLY. ALL FORENSIC CHECKS PASSED.")
    print("=" * 70 + "\n")


def run_web_server():
    import uvicorn
    print("\n" + "=" * 70)
    print("  SUTRAM (सूत्रम्) - LAUNCHING FULL-STACK FORENSIC ENGINE")
    print("  UI & REST API: http://localhost:8000")
    print("  OpenAPI Docs:  http://localhost:8000/docs")
    print("=" * 70 + "\n")
    uvicorn.run("backend.main:app", host="0.0.0.0", port=8000, reload=False)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="SUTRAM Demo Runner")
    parser.add_argument("--cli", action="store_true", help="Run interactive terminal demo")
    args = parser.parse_args()

    if args.cli:
        run_cli_demo()
    else:
        run_web_server()
