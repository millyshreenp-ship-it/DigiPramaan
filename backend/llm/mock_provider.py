"""Deterministic Mock LLM Provider for offline demonstrations and CI tests."""

import json
import re
import time
from typing import Any, Dict, List, Optional, Type, TypeVar
from pydantic import BaseModel

from backend.llm.base import LLMProvider, log_audit_trail

T = TypeVar("T", bound=BaseModel)


class MockProvider(LLMProvider):
    name: str = "mock"

    def is_available(self) -> bool:
        return True

    def generate_json(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        schema: Optional[Type[T]] = None,
        action_name: str = "llm_completion",
    ) -> Dict[str, Any]:
        start_time = time.perf_counter()
        
        # Detect context from prompt
        lower_prompt = prompt.lower()
        
        lower_action = action_name.lower()
        if "summar" in lower_action or "summar" in lower_prompt:
            result = self._mock_summarize(prompt)
        elif "cross" in lower_action or "adversarial" in lower_prompt or "counter" in lower_prompt or "rebuttal" in lower_prompt:
            result = self._mock_cross_examine(prompt)
        else:
            result = {
                "status": "success",
                "message": "Deterministic mock reasoning response",
                "extracted_citations": self._extract_event_ids(prompt)[:5],
            }

        # If schema is provided, validate
        if schema:
            validated = schema.model_validate(result)
            final_data = validated.model_dump()
        else:
            final_data = result

        latency_ms = (time.perf_counter() - start_time) * 1000
        log_audit_trail(
            provider_name=self.name,
            action=action_name,
            prompt=prompt,
            response_raw=json.dumps(final_data),
            parsed_json=final_data,
            latency_ms=latency_ms,
            retry_count=0,
            status="SUCCESS",
        )
        return final_data

    def _extract_event_ids(self, text: str) -> List[str]:
        """Extracts any EVT-xxxx patterns present in text."""
        return sorted(list(set(re.findall(r"EVT-\d+", text))))

    def _mock_summarize(self, prompt: str) -> Dict[str, Any]:
        present_events = self._extract_event_ids(prompt)
        
        # Check if this is the sample USB theft case
        has_usb = "usb" in prompt.lower() or "quarterly_financials" in prompt.lower()
        
        claims = []
        if has_usb and len(present_events) >= 5:
            # Match specific events if available
            rdp_evt = [e for e in present_events if "0040" in e or "0041" in e or "0042" in e] or present_events[:1]
            usb_evt = [e for e in present_events if "0043" in e or "0044" in e] or present_events[1:2]
            backup_evt = [e for e in present_events if "0045" in e or "0046" in e] or present_events[2:3]
            copy_evt = [e for e in present_events if "0047" in e or "0048" in e] or present_events[3:4]
            del_evt = [e for e in present_events if "0049" in e or "0050" in e] or present_events[4:5]

            claims.append({
                "claim": "An external inbound Remote Desktop Protocol (RDP) connection was established from unknown external IP 198.51.100.44 to workstation WS-FIN-04.",
                "citations": rdp_evt,
                "confidence": 0.94,
            })
            claims.append({
                "claim": "A SanDisk Ultra 64GB USB mass storage device was physically or logically connected to the system at 22:28 IST (off-hours).",
                "citations": usb_evt,
                "confidence": 0.98,
            })
            claims.append({
                "claim": "An automated enterprise scheduled backup task (DailyArchiveJob) executed at 22:30 IST.",
                "citations": backup_evt,
                "confidence": 0.92,
            })
            claims.append({
                "claim": "Confidential spreadsheet 'Quarterly_Financials.xlsx' was copied to external storage path at 22:32 IST under actor user_x.",
                "citations": copy_evt,
                "confidence": 0.96,
            })
            claims.append({
                "claim": "Windows Security Event Log was cleared and forensic traces purged at 22:35 IST.",
                "citations": del_evt,
                "confidence": 0.99,
            })
        else:
            # Generic case summary based on found events
            for i, evt in enumerate(present_events[:4]):
                claims.append({
                    "claim": f"Forensic event {evt} recorded verified system activity with verified SHA-256 integrity hash.",
                    "citations": [evt],
                    "confidence": 0.90 - (i * 0.05),
                })

        limitations = [
            "Source clock drift not synchronized with a certified NTP server; clock uncertainty factor applied.",
            "Bharatiya Sakshya Adhiniyam (BSA) 2023 Section 63 (erstwhile IEA 65B) certificate must be obtained from IT custodian.",
            "DHCP lease retention records from perimeter router are pending forensic imaging.",
        ]

        # Extract case_id if present in prompt
        case_id_match = re.search(r"case[-_ ]?([A-Za-z0-9\-]+)", prompt, re.IGNORECASE)
        case_id = case_id_match.group(1).upper() if case_id_match else "CASE-001"

        return {
            "case_id": case_id,
            "summary": claims,
            "limitations": limitations,
        }

    def _mock_cross_examine(self, prompt: str) -> Dict[str, Any]:
        present_events = self._extract_event_ids(prompt)
        
        return {
            "case_specific_counter_hypotheses": [
                {
                    "id": "CH-LLM-1",
                    "alternative_explanation": "Legitimate Enterprise Backup Overwrite: The file copy coincided within 2 minutes of the automated DailyArchiveJob schedule. Corporate archive scripts routinely mirror financial documents to connected storage pools.",
                    "plausibility": "high",
                    "supporting_signals_in_case": [e for e in present_events if "0045" in e or "0046" in e] or present_events[:1],
                    "evidence_needed_to_rule_out": [
                        "Extract Task Scheduler TaskDefinition.xml (Actions and Arguments).",
                        "Audit target destination path configured inside C:\\Windows\\System32\\Tasks\\DailyArchiveJob.",
                        "Inspect file hash of script backup_sync.ps1 to determine destination drive letter."
                    ],
                    "status": "open",
                },
                {
                    "id": "CH-LLM-2",
                    "alternative_explanation": "Host Hijack via Remote Desktop Session: A remote desktop session from untrusted IP 198.51.100.44 was active 3 minutes prior to the USB connection, indicating user_x's workstation was operated remotely by an adversary or proxy.",
                    "plausibility": "high",
                    "supporting_signals_in_case": [e for e in present_events if "0040" in e or "0041" in e or "0042" in e] or present_events[:1],
                    "evidence_needed_to_rule_out": [
                        "Examine Microsoft-Windows-TerminalServices-LocalSessionManager/Operational log (Event ID 21/24) for Client IP and Session ID.",
                        "Correlate firewall state table for port 3389 inbound NAT translation at 22:25 IST.",
                        "Retrieve external threat intelligence and GeoIP report for IP 198.51.100.44."
                    ],
                    "status": "open",
                },
                {
                    "id": "CH-LLM-3",
                    "alternative_explanation": "Authorized Peripheral Reassignment: The SanDisk USB device may be an official enterprise encrypted backup drive assigned to user_x under the Disaster Recovery Protocol.",
                    "plausibility": "medium",
                    "supporting_signals_in_case": [e for e in present_events if "0043" in e or "0044" in e] or present_events[:1],
                    "evidence_needed_to_rule_out": [
                        "Cross-reference USB Serial Number (from Windows SYSTEM registry USBSTOR) against Enterprise IT Asset Register.",
                        "Retrieve BitLocker To Go recovery key escrow log from Active Directory.",
                        "Review user_x's job description and signed IT Authorization Matrix for off-site data retention."
                    ],
                    "status": "open",
                }
            ],
            "investigator_brief_rewrites": "The prosecution's thesis of deliberate insider exfiltration faces severe evidential vulnerabilities. Two immediate alternative hypotheses are corroborated by the timeline itself: (1) an automated backup job ran at the identical window, and (2) an inbound remote desktop session preceded the data movement from an unverified IP address. Until these two avenues are forensically eliminated, criminal intent by user_x cannot be established beyond reasonable doubt.",
            "admissibility_notes": [
                "Mandatory Certificate: An electronic evidence certificate under Section 63 of Bharatiya Sakshya Adhiniyam, 2023 (BSA) / Section 65B of Indian Evidence Act must be secured from the Enterprise Security Officer.",
                "Chain of Custody: The SHA-256 evidence hashes recorded in raw_ref must be cross-matched against original drive acquisition images (E01/DD).",
                "Hash Verification: Any discrepancy in clock uncertainty (> 30s) could invalidate the timeline correlation before an Indian Sessions Court."
            ]
        }
