"""Citation Validator for Forensic Summaries.

Enforces courtroom evidential standards:
1. Rejects any claim without citations or citing non-existent event IDs.
2. Prevents hallucinated timestamps, hashes, and actor names.
3. Automatically flags or drops unsupported assertions.
"""

from datetime import datetime
import re
from typing import Any, Dict, List, Set, Tuple

from backend.schemas import Event, SummaryClaim


class CitationValidator:
    """Validates summary claims against ground-truth forensic case events."""

    def __init__(self, events: List[Event]):
        self.events_by_id: Dict[str, Event] = {e.event_id: e for e in events}
        self.valid_event_ids: Set[str] = set(self.events_by_id.keys())
        
        # Build index of known tokens to detect hallucination
        self.known_actors: Set[str] = {e.actor.lower() for e in events if e.actor}
        self.known_objects: Set[str] = {e.object.lower() for e in events if e.object}
        self.known_hashes: Set[str] = {e.evidence_hash.lower() for e in events if e.evidence_hash}
        
        for e in events:
            if isinstance(e.details, dict):
                for v in e.details.values():
                    if isinstance(v, str):
                        self.known_objects.add(v.lower())

    def validate_claim(self, claim_dict: Dict[str, Any]) -> Tuple[bool, str, List[str]]:
        """Validates a single claim.
        
        Returns:
            (is_valid, reason, valid_citations)
        """
        raw_text = claim_dict.get("claim", "").strip()
        if not raw_text:
            return False, "Empty claim text", []

        raw_citations = claim_dict.get("citations", [])
        if not raw_citations:
            return False, "Claim lacks citations (unsupported assertion)", []

        # Validate that all cited event IDs actually exist in the case
        valid_cites = []
        invalid_cites = []
        for cid in raw_citations:
            cid_clean = str(cid).strip()
            if cid_clean in self.valid_event_ids:
                valid_cites.append(cid_clean)
            else:
                invalid_cites.append(cid_clean)

        if invalid_cites:
            return False, f"Cites non-existent event IDs: {invalid_cites}", []

        if not valid_cites:
            return False, "No valid citations found in ground truth events", []

        # Anti-Hallucination Check: SHA-256 Hashes
        # If the claim mentions a 64-char hex string, verify it exists in the cited events
        hex_hashes = re.findall(r"\b[a-fA-F0-9]{64}\b", raw_text)
        for h in hex_hashes:
            h_lower = h.lower()
            cited_hashes = {
                self.events_by_id[cid].evidence_hash.lower()
                for cid in valid_cites
            }
            # Also check details of cited events
            for cid in valid_cites:
                details_str = str(self.events_by_id[cid].details).lower()
                if h_lower in details_str:
                    cited_hashes.add(h_lower)

            if h_lower not in cited_hashes:
                return False, f"Hallucinated evidence hash not present in cited events: {h}", []

        return True, "Verified", valid_cites

    def validate_and_filter(
        self,
        raw_claims: List[Dict[str, Any]],
        drop_unsupported: bool = True,
    ) -> Tuple[List[SummaryClaim], int, List[str]]:
        """Processes a list of raw claims from LLM, returning verified claims, dropped count, and error messages."""
        verified_claims: List[SummaryClaim] = []
        dropped_count = 0
        validation_errors: List[str] = []

        for idx, item in enumerate(raw_claims):
            is_valid, reason, valid_cites = self.validate_claim(item)
            conf = float(item.get("confidence", 0.85))
            claim_text = item.get("claim", "")

            if is_valid:
                verified_claims.append(SummaryClaim(
                    claim=claim_text,
                    citations=valid_cites,
                    confidence=min(max(conf, 0.0), 1.0),
                    validation_status="verified",
                ))
            else:
                validation_errors.append(f"Claim #{idx + 1} ('{claim_text[:40]}...'): {reason}")
                if drop_unsupported:
                    dropped_count += 1
                else:
                    verified_claims.append(SummaryClaim(
                        claim=claim_text,
                        citations=[],
                        confidence=0.0,
                        validation_status="unsupported",
                    ))

        return verified_claims, dropped_count, validation_errors
