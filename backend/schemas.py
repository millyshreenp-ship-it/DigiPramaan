"""Pydantic v2 schemas for the AI Reasoning & Adversarial Engine.

Adheres strictly to the shared data contract for Indian law enforcement digital forensics.
"""

from typing import Any, Dict, List, Literal, Optional
from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# Core Case & Event Models (Shared Data Contract - Field names MUST NOT change)
# ---------------------------------------------------------------------------

class Event(BaseModel):
    event_id: str = Field(..., description="Unique event identifier (e.g. EVT-0001)")
    timestamp_utc: str = Field(..., description="ISO 8601 UTC timestamp")
    clock_uncertainty_sec: float = Field(default=0.0, description="Clock uncertainty window in seconds")
    source: str = Field(..., description="Source log or sensor (e.g. windows_security_log, usb_log, router_log)")
    actor: str = Field(..., description="Actor username, machine ID, or identity")
    action: str = Field(..., description="Action type (e.g. login, file_copy, usb_connect, file_delete)")
    object: str = Field(..., description="Target object (e.g. file name, IP address, process)")
    details: Dict[str, Any] = Field(default_factory=dict, description="Free-form key-value attributes")
    evidence_hash: str = Field(..., description="SHA-256 hash of the evidence source")
    raw_ref: str = Field(..., description="Source file path and line/offset reference")


class Case(BaseModel):
    case_id: str = Field(..., description="Unique case identifier (e.g. CASE-001)")
    title: Optional[str] = Field(default="Digital Forensics Investigation", description="Case title")
    description: Optional[str] = Field(default=None, description="Case briefing/context")
    events: List[Event] = Field(default_factory=list, description="Forensic events in chronological or log order")


# ---------------------------------------------------------------------------
# Feature 1: Summarization & Citations
# ---------------------------------------------------------------------------

class SummaryClaim(BaseModel):
    claim: str = Field(..., description="Factual assertion extracted from evidence")
    citations: List[str] = Field(default_factory=list, description="List of valid event_ids supporting this claim")
    confidence: float = Field(..., ge=0.0, le=1.0, description="Confidence score between 0 and 1")
    validation_status: Optional[Literal["verified", "unsupported", "flagged"]] = Field(
        default="verified", description="Outcome of the Citation Validator check"
    )


class SummarizeRequest(BaseModel):
    case_id: str = Field(..., description="Case ID to summarize")
    focus: Optional[str] = Field(default=None, description="Specific focus question or target entity")
    case_data: Optional[Case] = Field(default=None, description="Optional full case payload")


class SummarizeResponse(BaseModel):
    case_id: str
    summary: List[SummaryClaim] = Field(default_factory=list)
    limitations: List[str] = Field(default_factory=list)
    dropped_unsupported_claims: int = Field(default=0, description="Count of claims pruned due to invalid citations")


# ---------------------------------------------------------------------------
# Feature 2: Adversarial Self-Cross-Examination (Headline Feature)
# ---------------------------------------------------------------------------

class FindingInput(BaseModel):
    text: str = Field(..., description="Finding statement/accusation")
    citations: List[str] = Field(default_factory=list, description="Supporting event_ids")


class CounterHypothesis(BaseModel):
    id: str = Field(..., description="Counter-hypothesis ID (e.g. CH-1)")
    alternative_explanation: str = Field(..., description="Benign or alternate defense theory")
    plausibility: Literal["low", "medium", "high"] = Field(..., description="Plausibility assessment")
    supporting_signals_in_case: List[str] = Field(
        default_factory=list, description="Evidence IDs already in case that support this defense"
    )
    evidence_needed_to_rule_out: List[str] = Field(
        default_factory=list, description="Concrete investigative artifacts to pull immediately to verify/falsify"
    )
    status: Literal["open", "ruled_out", "stands"] = Field(
        default="open", description="Current disposition after checking available evidence"
    )
    rationale: Optional[str] = Field(
        default=None, description="Reasoning behind plausibility and status"
    )


class RebuttalBrief(BaseModel):
    finding: FindingInput
    counter_hypotheses: List[CounterHypothesis] = Field(default_factory=list)
    finding_strength: Literal["strong", "moderate", "weak"] = Field(
        ..., description="Computed objectively from counter-hypotheses and corroborating evidence"
    )
    admissibility_notes: List[str] = Field(
        default_factory=list,
        description="Indian evidence compliance (e.g. BSA Section 63 / erstwhile IEA 65B, chain of custody)",
    )


class CrossExamineRequest(BaseModel):
    case_id: str
    finding_id: Optional[str] = None
    finding_text: Optional[str] = None
    citations: Optional[List[str]] = None
    case_data: Optional[Case] = None


class AddEvidenceRequest(BaseModel):
    new_events: List[Event] = Field(..., description="New evidence items being presented")


# ---------------------------------------------------------------------------
# Feature 3: Anomaly Detection
# ---------------------------------------------------------------------------

class Anomaly(BaseModel):
    anomaly_id: str = Field(..., description="Unique anomaly ID (e.g. ANOM-001)")
    event_ids: List[str] = Field(default_factory=list, description="Relevant event_ids triggering the anomaly")
    type: str = Field(..., description="Anomaly classification tag")
    score: float = Field(..., ge=0.0, le=1.0, description="Suspicion or outlier score")
    explanation: str = Field(..., description="Human-readable rationale for investigators")
    detection_method: Literal["rule_based", "statistical_isolation_forest", "hybrid"] = "rule_based"
    suggested_finding: Optional[str] = Field(
        default=None, description="Draft finding text ready to be pre-filled into cross-examiner"
    )


class AnomaliesRequest(BaseModel):
    case_id: str
    case_data: Optional[Case] = None
