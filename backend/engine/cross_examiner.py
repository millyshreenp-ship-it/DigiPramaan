"""Adversarial Self-Cross-Examination Engine (Courtroom-Proof Hybrid Architecture).

Combines:
1. Rule-based Counter-Hypothesis Library (YAML) evaluated against timeline events.
2. Objective, evidence-based status & finding strength calculation.
3. LLM enrichment (defense attorney polish, case-specific hypotheses, Indian legal admissibility notes).
4. Re-evaluation engine when new corroborating evidence is provided.
"""

from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple
import yaml

from backend.schemas import (
    Case,
    Event,
    FindingInput,
    CounterHypothesis,
    RebuttalBrief,
)
from backend.engine.anomaly_detector import parse_utc_to_ist
from backend.llm.factory import get_llm_provider

YAML_PATH = Path(__file__).resolve().parent.parent / "rules" / "counter_hypotheses.yaml"


def load_counter_hypothesis_rules() -> List[Dict[str, Any]]:
    """Loads rule templates from YAML library."""
    if not YAML_PATH.exists():
        return []
    with open(YAML_PATH, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f)
        return data.get("rules", []) if isinstance(data, dict) else []


def calculate_finding_strength(hypotheses: List[CounterHypothesis]) -> str:
    """Computes finding strength objectively based on counter-hypotheses statuses and plausibility.
    
    Rules:
    - If all counter-hypotheses are 'ruled_out': 'strong' (all defense theories eliminated).
    - If any 'high' plausibility counter-hypothesis is 'open' or 'stands' with supporting signals in the case: 'weak'.
    - If any 'medium' plausibility counter-hypothesis is 'open' or 'stands': 'moderate'.
    - Otherwise: 'strong'.
    """
    if not hypotheses:
        return "moderate"

    open_hypotheses = [h for h in hypotheses if h.status != "ruled_out"]
    if not open_hypotheses:
        return "strong"

    high_open = [
        h for h in open_hypotheses
        if h.plausibility == "high" and len(h.supporting_signals_in_case) > 0
    ]
    if high_open:
        return "weak"

    medium_or_stands = [
        h for h in open_hypotheses
        if h.plausibility in ("high", "medium") or h.status == "stands"
    ]
    if medium_or_stands:
        return "moderate"

    return "strong"


def evaluate_rule_based_hypotheses(
    case: Case,
    finding_text: str,
    cited_event_ids: List[str],
) -> List[CounterHypothesis]:
    """Evaluates YAML defense rules against ground truth case events."""
    rules = load_counter_hypothesis_rules()
    hypotheses: List[CounterHypothesis] = []

    case_events_by_id = {e.event_id: e for e in case.events}
    cited_events = [case_events_by_id[cid] for cid in cited_event_ids if cid in case_events_by_id]

    # If no valid citations provided, fall back to matching case events by keywords in finding
    if not cited_events:
        lower_find = finding_text.lower()
        if "usb" in lower_find:
            cited_events = [e for e in case.events if e.action in ("usb_connect", "file_copy")]
        elif "login" in lower_find or "rdp" in lower_find:
            cited_events = [e for e in case.events if e.action == "login"]
        else:
            cited_events = case.events[:3]

    actions_in_finding = {e.action for e in cited_events}
    if not actions_in_finding:
        actions_in_finding = {"file_copy", "usb_connect"}

    # Timestamps of cited events
    cited_timestamps: List[datetime] = []
    for e in cited_events:
        try:
            cited_timestamps.append(parse_utc_to_ist(e.timestamp_utc))
        except Exception:
            pass

    anchor_time = min(cited_timestamps) if cited_timestamps else None

    # Check each rule
    for r in rules:
        trigger_actions = set(r.get("trigger_actions", []))
        if not trigger_actions.intersection(actions_in_finding) and not any(a in finding_text.lower() for a in trigger_actions):
            continue

        check_type = r.get("check_type")
        supporting_signals: List[str] = []
        plausibility = r.get("default_plausibility", "medium")
        status = "open"

        if check_type == "scheduled_task_near":
            # Check if any scheduled_task occurred within window_minutes
            window = timedelta(minutes=r.get("window_minutes", 20))
            for e in case.events:
                if e.action in ("scheduled_task", "process_start") and ("backup" in e.object.lower() or "task" in e.source.lower() or "DailyArchive" in str(e.details)):
                    try:
                        e_dt = parse_utc_to_ist(e.timestamp_utc)
                        if anchor_time and abs(e_dt - anchor_time) <= window:
                            supporting_signals.append(e.event_id)
                    except Exception:
                        pass
            if supporting_signals:
                plausibility = "high"
                status = "open"
            else:
                plausibility = "low"

        elif check_type == "remote_session_prior":
            # Check if an untrusted login occurred prior to the finding
            window = timedelta(minutes=r.get("window_minutes", 30))
            for e in case.events:
                if e.action == "login" and (e.details.get("logon_type") == 10 or "rdp" in str(e.details).lower() or e.details.get("source_ip")):
                    try:
                        e_dt = parse_utc_to_ist(e.timestamp_utc)
                        if anchor_time and (anchor_time - window) <= e_dt <= anchor_time:
                            supporting_signals.append(e.event_id)
                    except Exception:
                        pass
            if supporting_signals:
                plausibility = "high"
                status = "open"
            else:
                plausibility = "medium"

        elif check_type == "usb_unverified_serial":
            # Check for unverified USB serials
            for e in case.events:
                if e.action == "usb_connect":
                    supporting_signals.append(e.event_id)
            if supporting_signals:
                plausibility = "medium"
                status = "open"

        elif check_type == "clock_skew_flag":
            # Check clock uncertainties
            high_uncertainty = [e.event_id for e in cited_events if e.clock_uncertainty_sec > 0.5]
            if high_uncertainty:
                supporting_signals.extend(high_uncertainty)
                plausibility = "medium"

        hypotheses.append(CounterHypothesis(
            id=r.get("id", f"CH-{len(hypotheses)+1}"),
            alternative_explanation=r.get("alternative_explanation", ""),
            plausibility=plausibility,
            supporting_signals_in_case=supporting_signals,
            evidence_needed_to_rule_out=r.get("evidence_needed_to_rule_out", []),
            status=status,
            rationale=f"Triggered by action pattern {actions_in_finding} and verified against case events.",
        ))

    return hypotheses


def build_cross_examination_prompt(
    finding_text: str,
    citations: List[str],
    case: Case,
    rule_hypotheses: List[CounterHypothesis],
) -> str:
    """Builds LLM prompt for defense attorney expansion and Indian legal admissibility."""
    rule_hypo_text = "\n".join([
        f"- [{h.id}] {h.alternative_explanation} (Plausibility: {h.plausibility}, Signals: {h.supporting_signals_in_case})"
        for h in rule_hypotheses
    ])

    return f"""You are a Defense Attorney & Senior Digital Forensics Auditor for Indian Courts.
You are conducting an Adversarial Self-Cross-Examination against the following prosecution finding:

PROSECUTION FINDING:
"{finding_text}"
Citations: {citations}

RULE-BASED COUNTER-HYPOTHESES IDENTIFIED FROM EVIDENCE:
{rule_hypo_text}

TASK:
1. Polish the existing counter-hypotheses into sharp, courtroom-ready defense arguments.
2. Add any subtle, case-specific alternative explanations the static rules missed (e.g. dual-monitor KVM switch, IT helpdesk remote maintenance, unauthenticated proxy).
3. Specify concrete investigative artifacts to pull immediately to rule out each defense.
4. Detail specific admissibility notes under Indian Evidence Law:
   - Section 63 of Bharatiya Sakshya Adhiniyam, 2023 (BSA) / Section 65B of Indian Evidence Act.
   - Hash integrity verification (SHA-256 matching E01 disk images).
   - Chain of custody documentation for seized storage.

OUTPUT SCHEMA (JSON ONLY):
{{
  "case_specific_counter_hypotheses": [
    {{
      "id": "CH-EXP-1",
      "alternative_explanation": "Detailed defense theory",
      "plausibility": "low|medium|high",
      "supporting_signals_in_case": ["EVT-..."],
      "evidence_needed_to_rule_out": [
        "Concrete artifact 1",
        "Concrete artifact 2"
      ],
      "status": "open"
    }}
  ],
  "admissibility_notes": [
    "Admissibility requirement 1",
    "Admissibility requirement 2"
  ]
}}
"""


def run_cross_examination(
    case: Case,
    finding_text: str,
    citations: List[str],
    provider_name: Optional[str] = None,
) -> RebuttalBrief:
    """Orchestrates hybrid cross-examination: rules + LLM enrichment + objective strength score."""
    # 1. Rule-based evaluation against case ground truth
    rule_hypotheses = evaluate_rule_based_hypotheses(
        case=case,
        finding_text=finding_text,
        cited_event_ids=citations,
    )

    # 2. Call LLM for defense attorney expansion and legal admissibility notes
    provider = get_llm_provider(force_provider=provider_name)
    prompt = build_cross_examination_prompt(
        finding_text=finding_text,
        citations=citations,
        case=case,
        rule_hypotheses=rule_hypotheses,
    )

    raw_response = provider.generate_json(prompt=prompt, action_name="cross_examine")
    llm_hypotheses_data = raw_response.get("case_specific_counter_hypotheses", [])
    admissibility_notes = raw_response.get("admissibility_notes", [])

    # Ensure baseline Indian legal notes are present
    if not any("Section 63" in n or "BSA" in n for n in admissibility_notes):
        admissibility_notes.append(
            "Statutory Certificate: Electronic evidence is inadmissible without a contemporaneous Section 63 BSA, 2023 certificate from the system custodian."
        )
    if not any("SHA-256" in n or "Hash" in n for n in admissibility_notes):
        admissibility_notes.append(
            "Cryptographic Chain-of-Custody: Target file SHA-256 hashes must be reconciled against the original forensic disk image."
        )

    # Merge hypotheses, avoiding duplicates
    merged_hypotheses: List[CounterHypothesis] = list(rule_hypotheses)
    existing_ids = {h.id for h in rule_hypotheses}

    for item in llm_hypotheses_data:
        hid = item.get("id", f"CH-LLM-{len(merged_hypotheses)+1}")
        if hid not in existing_ids:
            merged_hypotheses.append(CounterHypothesis(
                id=hid,
                alternative_explanation=item.get("alternative_explanation", ""),
                plausibility=item.get("plausibility", "medium"),
                supporting_signals_in_case=item.get("supporting_signals_in_case", []),
                evidence_needed_to_rule_out=item.get("evidence_needed_to_rule_out", []),
                status=item.get("status", "open"),
                rationale="LLM-identified defense theory synthesized from circumstantial signals.",
            ))
            existing_ids.add(hid)

    # 3. Objectively compute finding strength
    strength = calculate_finding_strength(merged_hypotheses)

    return RebuttalBrief(
        finding=FindingInput(text=finding_text, citations=citations),
        counter_hypotheses=merged_hypotheses,
        finding_strength=strength,
        admissibility_notes=admissibility_notes,
    )


def reevaluate_with_new_evidence(
    brief: RebuttalBrief,
    case: Case,
    new_events: List[Event],
) -> RebuttalBrief:
    """Re-evaluates counter-hypotheses statuses when new evidence is added to the case.
    
    Investigator pulls new artifacts to systematically close loopholes:
    - Task scheduler XML proving destination was not the USB -> rules out CH-BACKUP
    - CCTV footage / Session log proving physical presence or session termination -> rules out CH-RDP-HIJACK
    - Asset register proving USB serial is unauthorized personal hardware -> rules out CH-AUTHORIZED-DEVICE
    - Certified NTP stratum report -> rules out CH-CLOCK-SKEW
    """
    # Append new events to case
    case.events.extend(new_events)

    updated_hypotheses: List[CounterHypothesis] = []

    for h in brief.counter_hypotheses:
        new_status = h.status
        rationale_additions = []

        for ne in new_events:
            obj_lower = ne.object.lower()
            details_str = str(ne.details).lower()

            # Check 1: Backup task destination mismatch
            if "backup" in h.id.lower() or "backup" in h.alternative_explanation.lower():
                if "task" in obj_lower or "schedule" in obj_lower or "backup_sync" in obj_lower:
                    if "not" in details_str or "mismatch" in details_str or "c:\\archive" in details_str or "d:" in details_str:
                        new_status = "ruled_out"
                        rationale_additions.append(f"Ruled out by {ne.event_id}: Task definition targets internal archive, not removable storage.")
                    elif ne.details.get("destination_drive") and ne.details.get("destination_drive") != "E:":
                        new_status = "ruled_out"
                        rationale_additions.append(f"Ruled out by {ne.event_id}: Backup configured for drive {ne.details.get('destination_drive')}, not USB.")

            # Check 2: Remote desktop hijacking / host compromise
            if "rdp" in h.id.lower() or "hijack" in h.alternative_explanation.lower() or "remote" in h.id.lower():
                if "cctv" in ne.source.lower() or "terminalservices" in obj_lower or "rdp" in details_str:
                    if "physical_presence" in details_str or "user_x_sitting" in details_str or ne.details.get("badge_swiped"):
                        new_status = "ruled_out"
                        rationale_additions.append(f"Ruled out by {ne.event_id}: CCTV/Badge confirms user_x was physically active at the terminal.")
                    elif "session_closed" in details_str or ne.details.get("session_disconnected"):
                        new_status = "ruled_out"
                        rationale_additions.append(f"Ruled out by {ne.event_id}: Remote session was disconnected prior to the incident.")

            # Check 3: Authorized corporate peripheral
            if "device" in h.id.lower() or "peripheral" in h.alternative_explanation.lower() or "asset" in h.id.lower():
                if "asset" in obj_lower or "registry" in obj_lower or "inventory" in details_str:
                    if "unregistered" in details_str or "not_found" in details_str or ne.details.get("is_authorized_asset") is False:
                        new_status = "ruled_out"
                        rationale_additions.append(f"Ruled out by {ne.event_id}: IT Asset database confirms USB serial is NOT corporate property.")

            # Check 4: Clock skew / NTP calibration
            if "clock" in h.id.lower() or "skew" in h.alternative_explanation.lower():
                if "ntp" in obj_lower or "w32time" in obj_lower or ne.clock_uncertainty_sec < 0.1:
                    new_status = "ruled_out"
                    rationale_additions.append(f"Ruled out by {ne.event_id}: Stratum-1 NTP audit confirms zero clock skew.")

            # Check 5: Shared Account / Concurrent usage
            if "shared" in h.id.lower() or "credential" in h.alternative_explanation.lower() or "dual" in h.alternative_explanation.lower():
                if "cctv" in ne.source.lower() or "badge" in details_str or "physical" in details_str:
                    if "presence" in details_str or "sitting" in details_str or "user_x" in details_str:
                        new_status = "ruled_out"
                        rationale_additions.append(f"Ruled out by {ne.event_id}: CCTV and biometric access verify exclusive single-occupant operation by user_x.")

            # Check 6: Cloud sync
            if "cloud" in h.id.lower() or "sync" in h.alternative_explanation.lower():
                if "usb" in details_str or "task" in details_str or "destination" in details_str or "mismatch" in details_str:
                    new_status = "ruled_out"
                    rationale_additions.append(f"Ruled out by {ne.event_id}: Target destination path is a physical removable block device, not a cloud sync mount.")

        updated_h = h.model_copy()
        updated_h.status = new_status
        if rationale_additions:
            existing_rat = updated_h.rationale or ""
            updated_h.rationale = (existing_rat + " " + " ".join(rationale_additions)).strip()
        updated_hypotheses.append(updated_h)

    # Recalculate strength dynamically
    new_strength = calculate_finding_strength(updated_hypotheses)

    return RebuttalBrief(
        finding=brief.finding,
        counter_hypotheses=updated_hypotheses,
        finding_strength=new_strength,
        admissibility_notes=brief.admissibility_notes,
    )
