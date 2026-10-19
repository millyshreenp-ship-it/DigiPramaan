"""Forensic reasoning engine package."""

from backend.engine.anomaly_detector import run_anomaly_detection
from backend.engine.citation_validator import CitationValidator
from backend.engine.summarizer import run_summarization
from backend.engine.cross_examiner import (
    run_cross_examination,
    reevaluate_with_new_evidence,
    calculate_finding_strength,
)

__all__ = [
    "run_anomaly_detection",
    "CitationValidator",
    "run_summarization",
    "run_cross_examination",
    "reevaluate_with_new_evidence",
    "calculate_finding_strength",
]
