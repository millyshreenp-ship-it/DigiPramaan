"""Phase 1 Unit Tests: Scaffolding, Pydantic schemas, Sample Data, and MockProvider."""

import json
import os
from pathlib import Path
import pytest

from backend.schemas import (
    Case,
    Event,
    FindingInput,
    CounterHypothesis,
    RebuttalBrief,
    Anomaly,
    SummarizeResponse,
    SummaryClaim,
)
from backend.llm.base import AUDIT_LOG_FILE
from backend.llm.mock_provider import MockProvider
from backend.llm.factory import get_llm_provider
from backend.module_api import load_case


def test_pydantic_event_contract():
    """Verifies that the Event schema enforces the strict shared data contract."""
    raw_event = {
        "event_id": "EVT-9999",
        "timestamp_utc": "2025-03-14T17:02:11Z",
        "clock_uncertainty_sec": 0.5,
        "source": "windows_security_log",
        "actor": "user_x",
        "action": "file_copy",
        "object": "Quarterly_Financials.xlsx",
        "details": {"destination": "E:\\Backups"},
        "evidence_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "raw_ref": "Security.evtx:Record_100",
    }
    event = Event.model_validate(raw_event)
    assert event.event_id == "EVT-9999"
    assert event.clock_uncertainty_sec == 0.5
    assert event.action == "file_copy"
    assert event.details["destination"] == "E:\\Backups"


def test_load_sample_case_usb_theft():
    """Verifies sample_data/case_usb_theft.json loads cleanly and contains required incident anchors."""
    case = load_case("case_usb_theft")
    assert case.case_id == "CASE-USB-THEFT-001"
    assert len(case.events) >= 60

    # Verify scenario anchors
    actions = {e.action for e in case.events}
    assert "usb_connect" in actions
    assert "file_copy" in actions
    assert "scheduled_task" in actions
    assert "file_delete" in actions

    # Check specific events
    usb_events = [e for e in case.events if e.action == "usb_connect"]
    assert len(usb_events) >= 1
    assert "SanDisk" in usb_events[0].object

    backup_events = [e for e in case.events if e.action == "scheduled_task" and "DailyArchiveJob" in e.object]
    assert len(backup_events) >= 1

    file_copy_events = [e for e in case.events if e.action == "file_copy" and "Quarterly_Financials" in e.object]
    assert len(file_copy_events) >= 1

    rdp_events = [e for e in case.events if e.action == "login" and e.details.get("source_ip") == "198.51.100.44"]
    assert len(rdp_events) >= 1


def test_load_sample_case_benign():
    """Verifies sample_data/case_benign.json loads cleanly with expected daytime behavior."""
    case = load_case("case_benign")
    assert case.case_id == "CASE-BENIGN-002"
    assert len(case.events) == 25
    # No USB or delete actions in benign case
    actions = {e.action for e in case.events}
    assert "usb_connect" not in actions
    assert "file_delete" not in actions


def test_mock_llm_provider_and_audit_trail(tmp_path):
    """Verifies MockProvider deterministic response and chain-of-custody audit logging."""
    audit_log = tmp_path / "audit_test.log"
    os.environ["AUDIT_LOG_FILE"] = str(audit_log)

    provider = get_llm_provider("mock")
    assert isinstance(provider, MockProvider)
    assert provider.is_available() is True

    # Test summary action
    resp = provider.generate_json(
        prompt="Summarize events EVT-0040, EVT-0043, EVT-0045, EVT-0047, EVT-0049 for usb quarterly_financials",
        action_name="summarize",
        schema=SummarizeResponse,
    )
    assert "summary" in resp
    assert len(resp["summary"]) >= 4
    # All citations must be valid format
    for item in resp["summary"]:
        assert len(item["citations"]) > 0
        for cite in item["citations"]:
            assert cite.startswith("EVT-")

    # Verify audit file was written
    assert audit_log.exists()
    with open(audit_log, "r", encoding="utf-8") as f:
        lines = f.readlines()
        assert len(lines) >= 1
        last_entry = json.loads(lines[-1])
        assert last_entry["provider"] == "mock"
        assert last_entry["action"] == "summarize"
        assert last_entry["status"] == "SUCCESS"


def test_rebuttal_brief_schema():
    """Verifies RebuttalBrief schema validation and Indian evidence admissibility notes."""
    brief_data = {
        "finding": {
            "text": "user_x exfiltrated financial records via USB storage",
            "citations": ["EVT-0043", "EVT-0047"],
        },
        "counter_hypotheses": [
            {
                "id": "CH-1",
                "alternative_explanation": "Automated enterprise scheduled backup copied the files",
                "plausibility": "high",
                "supporting_signals_in_case": ["EVT-0045"],
                "evidence_needed_to_rule_out": [
                    "Inspect Task Scheduler XML definition for DailyArchiveJob",
                    "Verify target destination drive letter in backup_sync.ps1",
                ],
                "status": "open",
            }
        ],
        "finding_strength": "moderate",
        "admissibility_notes": [
            "Section 63 Bharatiya Sakshya Adhiniyam certificate required",
            "SHA-256 evidence hash verification against forensic disk image",
        ],
    }
    brief = RebuttalBrief.model_validate(brief_data)
    assert brief.finding_strength == "moderate"
    assert len(brief.counter_hypotheses) == 1
    assert brief.counter_hypotheses[0].status == "open"
