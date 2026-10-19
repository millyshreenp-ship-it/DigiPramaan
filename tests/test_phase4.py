"""Phase 4 Unit Tests: Adversarial Self-Cross-Examination & Dynamic Re-evaluation."""

from fastapi.testclient import TestClient
import pytest

from backend.engine.cross_examiner import (
    load_counter_hypothesis_rules,
    evaluate_rule_based_hypotheses,
    calculate_finding_strength,
    run_cross_examination,
    reevaluate_with_new_evidence,
)
from backend.main import app
from backend.module_api import load_case, cross_examine_finding
from backend.schemas import Event, RebuttalBrief


def test_yaml_counter_hypothesis_rules_load():
    """Verifies YAML counter-hypothesis templates load properly."""
    rules = load_counter_hypothesis_rules()
    assert len(rules) >= 4
    rule_ids = [r["id"] for r in rules]
    assert "CH-BACKUP" in rule_ids
    assert "CH-RDP-HIJACK" in rule_ids
    assert "CH-AUTHORIZED-DEVICE" in rule_ids


def test_rule_based_hypothesis_matching_on_usb_theft():
    """Verifies that both the scheduled backup and RDP hijack are surfaced as plausible defenses."""
    case = load_case("case_usb_theft")
    finding_text = "Employee user_x stole Quarterly_Financials.xlsx via USB drive"
    citations = ["EVT-0043", "EVT-0047"]

    hypotheses = evaluate_rule_based_hypotheses(case, finding_text, citations)
    hypo_map = {h.id: h for h in hypotheses}

    # 1. Scheduled Backup hypothesis
    assert "CH-BACKUP" in hypo_map
    backup_h = hypo_map["CH-BACKUP"]
    assert backup_h.plausibility == "high"
    assert backup_h.status == "open"
    # Must have matched EVT-0045 (DailyArchiveJob)
    assert any("EVT-0045" in eid for eid in backup_h.supporting_signals_in_case)
    assert len(backup_h.evidence_needed_to_rule_out) > 0

    # 2. Remote Desktop Hijacking hypothesis
    assert "CH-RDP-HIJACK" in hypo_map
    rdp_h = hypo_map["CH-RDP-HIJACK"]
    assert rdp_h.plausibility == "high"
    assert rdp_h.status == "open"
    # Must have matched EVT-0040 (RDP login from 198.51.100.44)
    assert any("EVT-0040" in eid for eid in rdp_h.supporting_signals_in_case)

    # 3. Objective strength score computation
    # Because high-plausibility hypotheses stand open, finding strength is weak
    strength = calculate_finding_strength(hypotheses)
    assert strength == "weak"


def test_cross_examination_brief_and_admissibility_notes():
    """Verifies full cross-examination brief generation with Indian statutory evidence requirements."""
    case = load_case("case_usb_theft")
    brief = cross_examine_finding(
        case=case,
        finding_text="Unauthorized file exfiltration of Quarterly_Financials.xlsx",
        citations=["EVT-0047"],
    )

    assert isinstance(brief, RebuttalBrief)
    assert len(brief.counter_hypotheses) >= 3
    assert brief.finding_strength in ("weak", "moderate")

    # Indian evidence requirements (BSA Section 63 / IEA Section 65B)
    assert any("Section 63" in note or "BSA" in note for note in brief.admissibility_notes)
    assert any("SHA-256" in note or "Hash" in note for note in brief.admissibility_notes)


def test_dynamic_re_evaluation_rules_out_hypotheses_and_strengthens_finding():
    """Verifies that adding corroborating artifacts rules out defense hypotheses and updates strength."""
    case = load_case("case_usb_theft")
    brief = cross_examine_finding(
        case=case,
        finding_text="Unauthorized exfiltration of financial records",
        citations=["EVT-0047"],
    )
    assert brief.finding_strength == "weak"

    # Investigator pulls new evidence 1: Task Scheduler XML proving target is D:\InternalArchive (not drive E:)
    new_event_backup = Event(
        event_id="EVT-NEW-0101",
        timestamp_utc="2025-03-14T23:00:00Z",
        clock_uncertainty_sec=0.0,
        source="windows_security_log",
        actor="forensic_examiner",
        action="other",
        object="Task_DailyArchiveJob_Definition.xml",
        details={
            "destination_drive": "D:",
            "notes": "Task Scheduler XML definition targets D:\\InternalArchive, mismatch with removable drive E:"
        },
        evidence_hash="1111222233334444555566667777888899990000aaaabbbbccccddddeeeeffff",
        raw_ref="TaskDefinition.xml:Actions"
    )

    # Investigator pulls new evidence 2: CCTV confirming user_x was physically present at terminal
    new_event_cctv = Event(
        event_id="EVT-NEW-0102",
        timestamp_utc="2025-03-14T23:05:00Z",
        clock_uncertainty_sec=0.5,
        source="cctv",
        actor="forensic_examiner",
        action="other",
        object="CCTV_FinanceBay_Camera4",
        details={
            "physical_presence": True,
            "user_x_sitting": True,
            "badge_swiped": "BADGE-USER-X",
            "notes": "CCTV footage and biometric turnstile confirms user_x physically operated the terminal."
        },
        evidence_hash="2222333344445555666677778888999900001111bbbbccccddddeeeeffff0000",
        raw_ref="CCTV_NVR_Channel4:22:25:00"
    )

    # Investigator pulls new evidence 3: IT Asset Register proving SanDisk USB is personal/unauthorized
    new_event_asset = Event(
        event_id="EVT-NEW-0103",
        timestamp_utc="2025-03-14T23:10:00Z",
        clock_uncertainty_sec=0.0,
        source="other",
        actor="it_asset_admin",
        action="other",
        object="Enterprise_Asset_Management_Database",
        details={
            "is_authorized_asset": False,
            "serial_number": "4C530001280424107192",
            "status": "unregistered_personal_device"
        },
        evidence_hash="3333444455556666777788889999000011112222ccccddddeeeeffff00001111",
        raw_ref="IT_Asset_Portal:Query_Serial_4C530001280424107192"
    )

    updated_brief = reevaluate_with_new_evidence(
        brief=brief,
        case=case,
        new_events=[new_event_backup, new_event_cctv, new_event_asset],
    )

    # Verify hypotheses have updated to "ruled_out"
    hypo_statuses = {h.id: h.status for h in updated_brief.counter_hypotheses}
    assert hypo_statuses.get("CH-BACKUP") == "ruled_out"
    assert hypo_statuses.get("CH-RDP-HIJACK") == "ruled_out"
    assert hypo_statuses.get("CH-AUTHORIZED-DEVICE") == "ruled_out"

    # With the key defense avenues forensically eliminated, the finding strength becomes STRONG!
    assert updated_brief.finding_strength == "strong"


def test_api_cross_examine_and_add_evidence_endpoint():
    """Verifies POST /api/cross-examine and POST /api/cross-examine/{id}/add-evidence."""
    client = TestClient(app)

    # Initial cross-examination
    resp1 = client.post("/api/cross-examine", json={
        "case_id": "CASE-USB-THEFT-001",
        "finding_text": "Exfiltration of financial records via removable USB",
        "citations": ["EVT-0043", "EVT-0047"],
    })
    assert resp1.status_code == 200
    brief_data = resp1.json()
    assert brief_data["finding_strength"] in ("weak", "moderate")
    assert len(brief_data["counter_hypotheses"]) > 0

    # Add evidence endpoint
    new_event = {
        "event_id": "EVT-CORROB-001",
        "timestamp_utc": "2025-03-14T23:30:00Z",
        "clock_uncertainty_sec": 0.0,
        "source": "windows_security_log",
        "actor": "investigator",
        "action": "other",
        "object": "Task_Definition.xml",
        "details": {"destination_drive": "D:", "notes": "Destination is internal archive drive D:"},
        "evidence_hash": "4444555566667777888899990000111122223333ddddeeeeffff000011112222",
        "raw_ref": "TaskDefinition.xml"
    }

    resp2 = client.post(
        "/api/cross-examine/CASE-USB-THEFT-001/add-evidence",
        json={"new_events": [new_event]}
    )
    assert resp2.status_code == 200
    updated_data = resp2.json()
    backup_h = next((h for h in updated_data["counter_hypotheses"] if h["id"] == "CH-BACKUP"), None)
    if backup_h:
        assert backup_h["status"] == "ruled_out"
