"""Phase 2 Unit Tests: Rule-Based and Statistical IsolationForest Anomaly Detection."""

from fastapi.testclient import TestClient
import pytest

from backend.engine.anomaly_detector import (
    parse_utc_to_ist,
    is_off_hours_ist,
    is_external_public_ip,
    run_rule_based_anomalies,
    run_statistical_anomalies,
    run_anomaly_detection,
)
from backend.main import app
from backend.module_api import load_case
from backend.schemas import AnomaliesRequest


def test_ist_time_and_off_hours_conversion():
    """Verifies UTC to IST conversion and working hours logic (09:30 - 18:30 IST)."""
    # 22:28 IST is 16:58 UTC
    dt_ist = parse_utc_to_ist("2025-03-14T16:58:04Z")
    assert dt_ist.hour == 22
    assert dt_ist.minute == 28
    assert is_off_hours_ist(dt_ist) is True

    # 14:00 IST is 08:30 UTC -> inside work hours
    dt_day = parse_utc_to_ist("2025-03-14T08:30:00Z")
    assert dt_day.hour == 14
    assert is_off_hours_ist(dt_day) is False


def test_public_vs_private_ip_classifier():
    """Verifies that RFC1918 private IPs are not flagged as external ingress, but public IPs are."""
    assert is_external_public_ip("198.51.100.44") is True  # Public external IP
    assert is_external_public_ip("10.0.1.45") is False     # Private LAN
    assert is_external_public_ip("192.168.1.1") is False   # Private LAN
    assert is_external_public_ip("127.0.0.1") is False     # Loopback


def test_sample_case_rule_based_anomalies():
    """Verifies all required forensic rules trigger accurately on the sample USB theft case."""
    case = load_case("case_usb_theft")
    anomalies = run_rule_based_anomalies(case)

    types = {a.type for a in anomalies}
    assert "usb_file_copy" in types
    assert "deletion_after_copy" in types
    assert "first_seen_external_ip" in types
    assert "bulk_file_copy" in types
    assert "off_hours_activity" in types

    # Inspect USB file copy anomaly
    usb_anom = next(a for a in anomalies if a.type == "usb_file_copy")
    assert "Quarterly_Financials.xlsx" in usb_anom.explanation or "Quarterly_Financials.xlsx" in usb_anom.suggested_finding
    assert any("EVT-0043" in eid for eid in usb_anom.event_ids)
    assert any("EVT-0047" in eid for eid in usb_anom.event_ids)
    assert usb_anom.score >= 0.90

    # Inspect Anti-Forensics / Deletion anomaly
    del_anom = next(a for a in anomalies if a.type == "deletion_after_copy")
    assert any("EVT-0049" in eid or "EVT-0050" in eid for eid in del_anom.event_ids)

    # Inspect First-seen public IP anomaly
    ip_anom = next(a for a in anomalies if a.type == "first_seen_external_ip")
    assert "198.51.100.44" in ip_anom.explanation


def test_isolation_forest_statistical_anomaly():
    """Verifies IsolationForest identifies user_x as an anomalous behavioral outlier."""
    case = load_case("case_usb_theft")
    stat_anomalies = run_statistical_anomalies(case)
    
    assert len(stat_anomalies) >= 1
    user_x_anom = next((a for a in stat_anomalies if "user_x" in a.anomaly_id or "user_x" in a.explanation), None)
    assert user_x_anom is not None
    assert user_x_anom.detection_method == "statistical_isolation_forest"
    assert user_x_anom.score >= 0.70
    assert "user_x" in user_x_anom.explanation


def test_benign_case_low_false_positives():
    """Verifies the anomaly engine does NOT over-accuse benign cases."""
    benign_case = load_case("case_benign")
    anomalies = run_anomaly_detection(benign_case)

    # Benign case has no USB exfiltration, no deletions, no external IPs, no off-hours user actions
    critical_anomalies = [a for a in anomalies if a.score >= 0.90]
    assert len(critical_anomalies) == 0


def test_api_anomalies_endpoint():
    """Verifies POST /api/anomalies endpoint works via FastAPI TestClient."""
    client = TestClient(app)
    response = client.post("/api/anomalies", json={"case_id": "CASE-USB-THEFT-001"})
    assert response.status_code == 200
    data = response.json()
    assert isinstance(data, list)
    assert len(data) >= 4
    # Highest score anomaly should be at top
    assert data[0]["score"] >= data[-1]["score"]
    # Check fields in response
    first = data[0]
    assert "anomaly_id" in first
    assert "event_ids" in first
    assert "score" in first
    assert "explanation" in first
    assert "suggested_finding" in first
