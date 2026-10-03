import json

# Built-in detection scripts
DETECTORS = {
    "hash_lookup": {
        "name": "Hash Lookup Demo",
        "script": """
import os
import sys

# Demonstration script that just checks if a specific hash exists
print(json.dumps([{"type": "hash_match", "confidence": 0.9, "message": "Matched known malicious hash"}]))
"""
    },
    "yara_scan": {
        "name": "Basic YARA Scan",
        "script": """
import os
import json

# Fake YARA scan output
print(json.dumps([{"type": "yara_match", "rule": "Suspicious_PDF", "confidence": 0.8}]))
"""
    }
}

def parse_detector_output(stdout: str) -> list:
    """Detection adapter: parses JSON output from sandbox into findings."""
    findings = []
    try:
        # Assuming the last line is the JSON output
        lines = [line.strip() for line in stdout.split('\\n') if line.strip()]
        if lines:
            findings = json.loads(lines[-1])
    except Exception:
        pass
    return findings
