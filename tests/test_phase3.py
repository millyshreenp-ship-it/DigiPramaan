"""Phase 3 Unit Tests: AI-Assisted Summarization and Citation Validator."""

from fastapi.testclient import TestClient
import pytest

from backend.engine.citation_validator import CitationValidator
from backend.engine.summarizer import run_summarization
from backend.main import app
from backend.module_api import load_case, summarize_case
from backend.schemas import SummarizeResponse


def test_citation_validator_valid_claims():
    """Verifies that claims with genuine event IDs pass validation."""
    case = load_case("case_usb_theft")
    validator = CitationValidator(case.events)

    raw_claims = [
        {
            "claim": "Actor user_x inserted a USB device at 22:28 IST.",
            "citations": ["EVT-0043"],
            "confidence": 0.98,
        },
        {
            "claim": "Task DailyArchiveJob executed automatically at 22:30 IST.",
            "citations": ["EVT-0045"],
            "confidence": 0.94,
        },
    ]

    verified, dropped, errors = validator.validate_and_filter(raw_claims)
    assert len(verified) == 2
    assert dropped == 0
    assert len(errors) == 0
    assert verified[0].citations == ["EVT-0043"]
    assert verified[0].validation_status == "verified"


def test_citation_validator_rejects_empty_citations():
    """Verifies that unsupported claims without citations are dropped."""
    case = load_case("case_usb_theft")
    validator = CitationValidator(case.events)

    raw_claims = [
        {
            "claim": "The suspect intended to sell trade secrets to a competitor.",
            "citations": [],
            "confidence": 0.90,
        }
    ]

    # Dropped mode
    verified, dropped, errors = validator.validate_and_filter(raw_claims, drop_unsupported=True)
    assert len(verified) == 0
    assert dropped == 1
    assert len(errors) == 1

    # Flagged mode (kept but marked unsupported)
    verified_flagged, dropped_flagged, _ = validator.validate_and_filter(raw_claims, drop_unsupported=False)
    assert len(verified_flagged) == 1
    assert verified_flagged[0].validation_status == "unsupported"
    assert verified_flagged[0].confidence == 0.0


def test_citation_validator_rejects_fake_event_ids():
    """Verifies that hallucinated event IDs not present in case events are detected and dropped."""
    case = load_case("case_usb_theft")
    validator = CitationValidator(case.events)

    raw_claims = [
        {
            "claim": "Fabricated activity occurred at off-hours.",
            "citations": ["EVT-9999", "EVT-8888"],
            "confidence": 0.95,
        }
    ]

    verified, dropped, errors = validator.validate_and_filter(raw_claims)
    assert len(verified) == 0
    assert dropped == 1
    assert "EVT-9999" in errors[0]


def test_citation_validator_rejects_hallucinated_hashes():
    """Verifies that claims citing fake SHA-256 hashes not present in the cited evidence are rejected."""
    case = load_case("case_usb_theft")
    validator = CitationValidator(case.events)

    fake_hash = "deadbeef" * 8
    raw_claims = [
        {
            "claim": f"The malicious binary hash was {fake_hash}.",
            "citations": ["EVT-0043"],  # Real event, but hash deadbeef is hallucinated
            "confidence": 0.99,
        }
    ]

    verified, dropped, errors = validator.validate_and_filter(raw_claims)
    assert len(verified) == 0
    assert dropped == 1
    assert "Hallucinated evidence hash" in errors[0]


def test_end_to_end_summarization_with_citations():
    """Verifies summarizer runs on sample case and all returned claims have valid citations."""
    case = load_case("case_usb_theft")
    response = summarize_case(case, focus="USB data movement")

    assert response.case_id == case.case_id
    assert len(response.summary) >= 3

    # Every single claim citation must exist in the real case events
    real_ids = {e.event_id for e in case.events}
    for item in response.summary:
        assert len(item.citations) > 0
        for cite in item.citations:
            assert cite in real_ids

    # Indian evidence act requirement in limitations
    assert any("Section 63" in l or "BSA" in l for l in response.limitations)


def test_api_summarize_endpoint():
    """Verifies POST /api/summarize endpoint."""
    client = TestClient(app)
    resp = client.post("/api/summarize", json={"case_id": "CASE-USB-THEFT-001", "focus": "exfiltration"})
    assert resp.status_code == 200
    data = resp.json()
    assert "summary" in data
    assert "limitations" in data
    assert len(data["summary"]) > 0
