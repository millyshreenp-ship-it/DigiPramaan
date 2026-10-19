"""AI-assisted Summarization Engine with Strict Citation Enforcement and Retry Logic."""

import json
import logging
from typing import Any, Dict, List, Optional

from backend.schemas import Case, SummarizeResponse, SummaryClaim
from backend.engine.citation_validator import CitationValidator
from backend.llm.factory import get_llm_provider

logger = logging.getLogger(__name__)


def format_events_for_prompt(case: Case, max_events: int = 50) -> str:
    """Formats case events into compact structured text for LLM context."""
    lines = []
    # If case has many events, ensure key action events are prioritized
    events = case.events
    if len(events) > max_events:
        # Prioritize non-routine events: login, usb_connect, file_copy, file_delete, scheduled_task
        critical = [e for e in events if e.action in ("usb_connect", "file_copy", "file_delete", "scheduled_task") or "rdp" in str(e.details).lower()]
        routine = [e for e in events if e not in critical]
        events = (critical + routine)[:max_events]
        # Keep sorted by timestamp
        events.sort(key=lambda x: x.timestamp_utc)

    for e in events:
        detail_snippet = f" details={json.dumps(e.details)}" if e.details else ""
        lines.append(
            f"[{e.event_id}] {e.timestamp_utc} | src={e.source} | actor={e.actor} | "
            f"action={e.action} | obj={e.object} | hash={e.evidence_hash[:12]}...{detail_snippet}"
        )
    return "\n".join(lines)


def build_summarization_prompt(case: Case, focus: Optional[str] = None, feedback: Optional[str] = None) -> str:
    """Constructs forensic analysis prompt enforcing strict citation rules."""
    events_text = format_events_for_prompt(case)
    focus_clause = f"INVESTIGATION FOCUS: {focus}\n" if focus else ""
    feedback_clause = f"\nWARNING: PREVIOUS ATTEMPT FAILED CITATION VALIDATION:\n{feedback}\nPlease rectify and ensure every claim cites only existing event IDs from the list below.\n" if feedback else ""

    return f"""You are a Digital Forensics Examiner for Indian Law Enforcement.
Analyze the forensic timeline events below and produce an objective factual summary.

{focus_clause}{feedback_clause}
CASE EVENTS:
{events_text}

MANDATORY RULES:
1. Every claim MUST be backed by a "citations" list containing real event IDs (e.g. ["EVT-0043"]).
2. NEVER invent or hallucinate event IDs, timestamps, SHA-256 hashes, or actor names not present in the events.
3. Every claim must have a "confidence" between 0.0 and 1.0.
4. List forensic limitations (e.g., clock uncertainty, missing router logs, BSA Section 63 certificate requirements).
5. Output ONLY valid JSON matching this schema:
{{
  "summary": [
    {{
      "claim": "Detailed factual finding statement",
      "citations": ["EVT-0001", "EVT-0002"],
      "confidence": 0.95
    }}
  ],
  "limitations": [
    "Limitation note 1",
    "Limitation note 2"
  ]
}}
"""


def run_summarization(
    case: Case,
    focus: Optional[str] = None,
    provider_name: Optional[str] = None,
    drop_unsupported: bool = True,
) -> SummarizeResponse:
    """Generates AI summary with strict citation validation and 1 retry on invalid citations."""
    provider = get_llm_provider(force_provider=provider_name)
    validator = CitationValidator(case.events)

    # Initial LLM call
    prompt = build_summarization_prompt(case, focus=focus)
    raw_response = provider.generate_json(prompt=prompt, action_name="summarize")
    raw_claims = raw_response.get("summary", [])

    # Validate citations
    verified_claims, dropped_count, errors = validator.validate_and_filter(
        raw_claims, drop_unsupported=drop_unsupported
    )

    # Retry once if there were citation errors
    if errors and len(verified_claims) < len(raw_claims):
        logger.warning(f"Citation validation encountered errors. Retrying LLM once. Errors: {errors}")
        feedback_str = "\n".join(errors)
        retry_prompt = build_summarization_prompt(case, focus=focus, feedback=feedback_str)
        retry_response = provider.generate_json(prompt=retry_prompt, action_name="summarize_retry")
        retry_claims = retry_response.get("summary", [])

        retry_verified, retry_dropped, _ = validator.validate_and_filter(
            retry_claims, drop_unsupported=drop_unsupported
        )
        if len(retry_verified) >= len(verified_claims):
            verified_claims = retry_verified
            dropped_count = retry_dropped
            raw_response = retry_response

    # Compile limitations
    limitations = raw_response.get("limitations", [])
    if not any("Section 63" in l or "BSA" in l for l in limitations):
        limitations.append(
            "Admissibility Notice: All digital extractions require a certificate under Section 63 of Bharatiya Sakshya Adhiniyam, 2023 (BSA)."
        )

    return SummarizeResponse(
        case_id=case.case_id,
        summary=verified_claims,
        limitations=limitations,
        dropped_unsupported_claims=dropped_count,
    )
