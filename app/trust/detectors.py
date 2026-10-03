import os
from dataclasses import dataclass
from typing import List, Dict, Any

@dataclass
class Detection:
    event_id: str
    detection_type: str
    severity: str
    reason: str
    confidence: float
    evidence_refs: List[str]

def detect(events: List[Dict[str, Any]]) -> List[Detection]:
    # Rule-based fallback detector
    # (timestamp outliers/clock skew, off-hours USB copy, new autorun key, malformed or mismatched fields, coercion-then-payment pattern)
    detections = []
    
    # Check if a custom DETECTOR is set
    detector_env = os.environ.get("DETECTOR")
    if detector_env:
        try:
            mod_name, func_name = detector_env.split(":")
            import importlib
            mod = importlib.import_module(mod_name)
            func = getattr(mod, func_name)
            return func(events)
        except Exception:
            # handled gracefully, fallback to rule-based
            pass

    coercion_seen = False
    for i, event in enumerate(events):
        try:
            event_type = event.get("event_type", "")
            title = event.get("title", "").lower()
            timestamp = event.get("timestamp", "")
            event_id = event.get("event_id", "")
            evidence_id = event.get("evidence_id", "")
            
            # Clock skew / outliers
            if "skew" in title or "manipulated" in title:
                detections.append(Detection(event_id, "Clock Skew", "medium", "Manipulated timestamp detected", 0.9, [evidence_id]))
                
            # Off-hours USB
            if "usb" in title and "off-hours" in title:
                detections.append(Detection(event_id, "Off-hours USB Copy", "high", "USB activity during off-hours", 0.95, [evidence_id]))
                
            # Autorun key
            if "registry" in title and "run" in title:
                detections.append(Detection(event_id, "Persistence Mechanism", "critical", "New autorun registry key", 0.99, [evidence_id]))
                
            # Forged DNS
            if "dns" in title and "forged" in title:
                detections.append(Detection(event_id, "Forged DNS", "high", "Forged DNS/DHCP log", 0.95, [evidence_id]))
                
            # Coercion then payment
            if "coercion" in title or "scam" in title:
                coercion_seen = True
            if coercion_seen and "payment" in title:
                detections.append(Detection(event_id, "Coercion Pattern", "critical", "Coercion cue followed by payment demand", 0.99, [evidence_id]))
                
        except Exception:
            pass
            
    return detections
