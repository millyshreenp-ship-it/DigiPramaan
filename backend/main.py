"""FastAPI application for the AI Reasoning & Adversarial Engine."""

import os
from typing import Dict, List, Optional
from fastapi import FastAPI, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware

from backend.schemas import (
    Case,
    Event,
    Anomaly,
    AnomaliesRequest,
    SummarizeRequest,
    SummarizeResponse,
    CrossExamineRequest,
    RebuttalBrief,
    AddEvidenceRequest,
    FindingInput,
)
from backend.module_api import (
    load_case,
    detect_anomalies,
    summarize_case,
    cross_examine_finding,
    add_evidence_and_reevaluate,
    SAMPLE_DATA_DIR,
)

app = FastAPI(
    title="AI Reasoning & Adversarial Engine - Digital Forensics",
    description="Courtroom-Proof Adversarial Self-Cross-Examination & Forensic Reasoning API for Indian Law Enforcement",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
)

# CORS setup for React frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

from backend.llm.egress_guard import check_and_apply_egress_policy

# Enforce zero egress air-gap policy if configured
check_and_apply_egress_policy()

# In-memory store for active briefs and cases for demo state
ACTIVE_BRIEFS: Dict[str, RebuttalBrief] = {}
ACTIVE_CASES: Dict[str, Case] = {}


def _resolve_case(case_id: str, case_data: Optional[Case] = None) -> Case:
    """Helper to resolve a case from provided payload, memory cache, or sample files."""
    if case_data:
        ACTIVE_CASES[case_data.case_id] = case_data
        return case_data
    if case_id in ACTIVE_CASES:
        return ACTIVE_CASES[case_id]
    try:
        loaded = load_case(case_id)
        ACTIVE_CASES[loaded.case_id] = loaded
        return loaded
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Case '{case_id}' could not be resolved: {str(e)}",
        )


@app.get("/api/health", tags=["System"])
def health_check():
    provider = os.getenv("LLM_PROVIDER", "mock")
    zero_egress = os.getenv("ZERO_EGRESS", "false").lower() == "true"
    return {
        "status": "healthy",
        "service": "AI Reasoning & Adversarial Engine",
        "llm_provider": provider,
        "zero_egress_mode": zero_egress,
        "active_cases": list(ACTIVE_CASES.keys()),
    }


@app.get("/api/cases", response_model=List[Dict[str, str]], tags=["Case Ingestion"])
def list_available_cases():
    """Lists preloaded forensic sample cases."""
    cases = []
    if SAMPLE_DATA_DIR.exists():
        for f in SAMPLE_DATA_DIR.glob("*.json"):
            try:
                c = load_case(f)
                cases.append({
                    "case_id": c.case_id,
                    "title": c.title or f.stem,
                    "description": c.description or "",
                    "event_count": str(len(c.events)),
                    "filename": f.name,
                })
            except Exception:
                continue
    return cases


@app.get("/api/cases/{case_id}", response_model=Case, tags=["Case Ingestion"])
def get_case_details(case_id: str):
    """Retrieves full case details including raw events."""
    return _resolve_case(case_id)


# ---------------------------------------------------------------------------
# Feature 3: Anomaly Detection
# ---------------------------------------------------------------------------

@app.post("/api/anomalies", response_model=List[Anomaly], tags=["Anomaly Detection"])
def api_detect_anomalies(request: AnomaliesRequest):
    """Detects forensic anomalies using rule-based signals and statistical Isolation Forest."""
    case = _resolve_case(request.case_id, request.case_data)
    anomalies = detect_anomalies(case)
    return anomalies


# ---------------------------------------------------------------------------
# Feature 1: AI-Assisted Summarization with Citations
# ---------------------------------------------------------------------------

@app.post("/api/summarize", response_model=SummarizeResponse, tags=["Summarization"])
def api_summarize_case(request: SummarizeRequest):
    """Generates an AI-assisted factual summary where every claim is strictly bound to event citations."""
    case = _resolve_case(request.case_id, request.case_data)
    return summarize_case(case, focus=request.focus)


# ---------------------------------------------------------------------------
# Feature 2: Adversarial Self-Cross-Examination (Headline Feature)
# ---------------------------------------------------------------------------

@app.post("/api/cross-examine", response_model=RebuttalBrief, tags=["Adversarial Cross-Examination"])
def api_cross_examine(request: CrossExamineRequest):
    """Generates an adversarial self-cross-examination brief attacking the candidate finding."""
    case = _resolve_case(request.case_id, request.case_data)

    finding_text = request.finding_text
    citations = request.citations or []

    # If only finding_id was given, try to locate it from detected anomalies
    if not finding_text and request.finding_id:
        anomalies = detect_anomalies(case)
        match = next((a for a in anomalies if a.anomaly_id == request.finding_id), None)
        if match:
            finding_text = match.suggested_finding or match.explanation
            citations = match.event_ids
        else:
            finding_text = f"Alleged irregular activity for {request.finding_id}"

    if not finding_text:
        finding_text = f"Unauthorized data exfiltration suspected for case {case.case_id}"

    brief = cross_examine_finding(case=case, finding_text=finding_text, citations=citations)

    # Store for re-evaluation
    brief_id = request.finding_id or f"BRIEF-{len(ACTIVE_BRIEFS) + 1}"
    ACTIVE_BRIEFS[brief_id] = brief
    ACTIVE_BRIEFS[case.case_id] = brief

    return brief


@app.post(
    "/api/cross-examine/{brief_id}/add-evidence",
    response_model=RebuttalBrief,
    tags=["Adversarial Cross-Examination"],
)
def api_add_evidence_and_reevaluate(brief_id: str, request: AddEvidenceRequest):
    """Re-runs cross-examination after investigator pulls new corroborating evidence to rule out defenses."""
    brief = ACTIVE_BRIEFS.get(brief_id)
    if not brief:
        # Check if brief_id is a case_id
        brief = ACTIVE_BRIEFS.get(brief_id)

    # Find the corresponding case
    case = None
    for c in ACTIVE_CASES.values():
        if any(e.event_id in brief.finding.citations for e in c.events if brief):
            case = c
            break

    if not case:
        case = load_case("case_usb_theft")

    if not brief:
        # Create a new brief from the finding in case
        brief = cross_examine_finding(
            case=case,
            finding_text="Unauthorized exfiltration of financial records",
            citations=["EVT-0047"],
        )

    updated_brief = add_evidence_and_reevaluate(brief=brief, case=case, new_events=request.new_events)
    ACTIVE_BRIEFS[brief_id] = updated_brief
    return updated_brief


# Mount React static build if available
from pathlib import Path
from fastapi.staticfiles import StaticFiles

FRONTEND_DIST = Path(__file__).resolve().parent.parent / "frontend" / "dist"
if FRONTEND_DIST.exists():
    app.mount("/", StaticFiles(directory=str(FRONTEND_DIST), html=True), name="frontend")

