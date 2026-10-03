import os
import importlib
from dataclasses import dataclass
from typing import List

@dataclass
class Detection:
    event_id: str
    detection_type: str
    severity: str  # low | medium | high | critical
    reason: str
    confidence: float  # 0.0 to 1.0
    evidence_refs: List[str]

def default_rule_detector(events: list[dict]) -> List[Detection]:
    """Fallback rule-based detector."""
    detections = []
    for ev in events:
        summary = (ev.get("summary") or "").lower()
        if "delete" in summary or "clear" in summary or "wipe" in summary:
            detections.append(Detection(
                event_id=ev["event_id"],
                detection_type="Anti-Forensics / Deletion",
                severity="medium",
                reason=f"Event summary contains suspicious keywords: {summary}",
                confidence=0.8,
                evidence_refs=[ev["evidence_id"]]
            ))
    return detections

def detect(events: list[dict]) -> List[Detection]:
    """
    Main entrypoint. Pluggable via DETECTOR environment variable.
    e.g. DETECTOR=app.plugins.ai_reasoning:ai_detect
    """
    target = os.environ.get("DETECTOR")
    if target:
        mod_name, func_name = target.split(":")
        mod = importlib.import_module(mod_name)
        func = getattr(mod, func_name)
        return func(events)
    return default_rule_detector(events)
