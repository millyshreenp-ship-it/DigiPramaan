"""Clean Python API for teammates to directly import and call module functions.

Other modules (evidence intake, timeline UI, case management) can import this directly:
    from backend.module_api import (
        load_case,
        detect_anomalies,
        summarize_case,
        cross_examine_finding,
        add_evidence_and_reevaluate
    )
"""

import json
import os
from pathlib import Path
from typing import List, Optional, Union

from backend.schemas import (
    Case,
    Event,
    Anomaly,
    SummarizeResponse,
    RebuttalBrief,
    FindingInput,
)
from backend.llm.factory import get_llm_provider

SAMPLE_DATA_DIR = Path(__file__).resolve().parent.parent / "sample_data"


def load_case(source: Union[str, Path, dict]) -> Case:
    """Loads a Case from a file path, case_id (checked in sample_data), or raw dict."""
    if isinstance(source, dict):
        return Case.model_validate(source)

    path_obj = Path(source)
    if path_obj.is_file():
        with open(path_obj, "r", encoding="utf-8") as f:
            data = json.load(f)
            return Case.model_validate(data)

    # Check sample data directory by ID or filename
    possible_names = [
        SAMPLE_DATA_DIR / f"{source}.json",
        SAMPLE_DATA_DIR / f"case_{source}.json",
        SAMPLE_DATA_DIR / f"{source.lower().replace('-', '_')}.json",
        SAMPLE_DATA_DIR / "case_usb_theft.json" if "usb" in str(source).lower() else None,
        SAMPLE_DATA_DIR / "case_benign.json" if "benign" in str(source).lower() else None,
    ]
    for p in possible_names:
        if p and p.is_file():
            with open(p, "r", encoding="utf-8") as f:
                return Case.model_validate(json.load(f))

    # Default fallback: look for first json in sample_data
    default_case = SAMPLE_DATA_DIR / "case_usb_theft.json"
    if default_case.is_file():
        with open(default_case, "r", encoding="utf-8") as f:
            return Case.model_validate(json.load(f))

    raise FileNotFoundError(f"Case source not found: {source}")


def detect_anomalies(case: Case) -> List[Anomaly]:
    """Detects forensic anomalies using rule-based filters and Isolation Forest."""
    try:
        from backend.engine.anomaly_detector import run_anomaly_detection
        return run_anomaly_detection(case)
    except ImportError:
        # Stub for Phase 1 before Phase 2 implementation
        return []


def summarize_case(
    case: Case,
    focus: Optional[str] = None,
    provider_name: Optional[str] = None,
) -> SummarizeResponse:
    """Produces AI-assisted summary with verified citations."""
    try:
        from backend.engine.summarizer import run_summarization
        return run_summarization(case, focus=focus, provider_name=provider_name)
    except ImportError:
        # Phase 1 fallback with MockProvider
        provider = get_llm_provider(force_provider=provider_name)
        event_str = "\n".join([f"{e.event_id}: {e.action} {e.object}" for e in case.events[:15]])
        raw = provider.generate_json(
            prompt=f"Summarize case {case.case_id} focus {focus}. Events:\n{event_str}",
            action_name="summarize",
        )
        return SummarizeResponse(
            case_id=case.case_id,
            summary=raw.get("summary", []),
            limitations=raw.get("limitations", []),
        )


def cross_examine_finding(
    case: Case,
    finding_text: str,
    citations: List[str],
    provider_name: Optional[str] = None,
) -> RebuttalBrief:
    """Generates courtroom-proof adversarial self-cross-examination rebuttal brief."""
    try:
        from backend.engine.cross_examiner import run_cross_examination
        return run_cross_examination(
            case=case,
            finding_text=finding_text,
            citations=citations,
            provider_name=provider_name,
        )
    except ImportError:
        # Phase 1 fallback with MockProvider
        provider = get_llm_provider(force_provider=provider_name)
        raw = provider.generate_json(
            prompt=f"Cross examine finding '{finding_text}' with citations {citations}",
            action_name="cross_examine",
        )
        return RebuttalBrief(
            finding=FindingInput(text=finding_text, citations=citations),
            counter_hypotheses=raw.get("case_specific_counter_hypotheses", []),
            finding_strength="moderate",
            admissibility_notes=raw.get("admissibility_notes", []),
        )


def add_evidence_and_reevaluate(
    brief: RebuttalBrief,
    case: Case,
    new_events: List[Event],
) -> RebuttalBrief:
    """Re-runs cross-examination against augmented evidence pool."""
    try:
        from backend.engine.cross_examiner import reevaluate_with_new_evidence
        return reevaluate_with_new_evidence(brief=brief, case=case, new_events=new_events)
    except ImportError:
        # Append new events and return brief
        case.events.extend(new_events)
        return brief
