# SUTRAM (सूत्रम्)
### AI Reasoning & Adversarial Engine for Digital Forensics
*Built for Indian Law Enforcement & Digital Forensic Laboratories*

[![Python](https://img.shields.io/badge/Python-3.11%20%7C%203.13-blue.svg)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115-teal.svg)](https://fastapi.tiangolo.com)
[![Pydantic](https://img.shields.io/badge/Pydantic-v2.10-red.svg)](https://docs.pydantic.dev)
[![React](https://img.shields.io/badge/React-18-blue.svg)](https://react.dev)
[![Vite](https://img.shields.io/badge/Vite-6.0-purple.svg)](https://vitejs.dev)
[![Air--Gap](https://img.shields.io/badge/Air--Gapped-Zero%20Egress%20Enforced-green.svg)](#zero-egress--air-gap-enforcement)
[![Statutory Compliance](https://img.shields.io/badge/Compliance-BSA%202023%20Sec%2063%20%2F%20IEA%2065B-gold.svg)](#statutory-admissibility--indian-evidence-law)

---

## 1. Product Overview & Headline USPs

Traditional AI in digital forensics only **accuses**—building one-sided correlation chains that crumble under aggressive defense cross-examination in court. **SUTRAM** introduces a revolutionary paradigm for cyber crime investigators:

### Headline USP: "Courtroom Proof" Adversarial Self-Cross-Examination
The AI does not stop at asserting suspicion. It immediately **acts as a defense attorney attacking its own findings**. It cross-examines the prosecution theory, surfaces plausible benign alternative explanations corroborated by timeline signals, and tells the investigator **exactly what concrete artifacts to pull immediately** to close each loophole before submitting the charge sheet.

### Secondary USP: Air-Gapped Local LLM (Zero Data Egress)
Forensic evidence handling demands strict confidentiality. SUTRAM operates completely air-gapped on local hardware with zero external data transmission. When configured with `ZERO_EGRESS=true`, socket-level guards physically prohibit any non-localhost network connections.

---

## 2. Tech Stack & Architecture

- **Backend**: Python (FastAPI, Pydantic v2, scikit-learn, pandas, PyYAML).
- **LLM Abstraction Layer**:
  - `MockProvider`: Deterministic canned reasoning for offline demos and CI (default fallback).
  - `OllamaProvider`: Air-gapped local model execution (`qwen2.5:3b`, `phi3`) over `http://localhost:11434`.
  - `GeminiProvider`: Optional cloud LLM integration via `GEMINI_API_KEY`.
- **Frontend**: Single-page dark theme dashboard built with React 18, Vite, and Tailwind CSS.
- **Audit Logging**: Every prompt, raw response, parsed JSON, latency, and model status is immutably logged to `audit_trail.log` for chain of custody and forensic peer review.
- **Verification**: 27 unit and integration tests under `pytest`.

```
Sutram/
├── backend/
│   ├── main.py                  # FastAPI server with OpenAPI docs (/docs) and static SPA mount
│   ├── schemas.py               # Strict Pydantic v2 data models conforming to shared contract
│   ├── module_api.py            # Clean Python import interface for teammates
│   ├── engine/
│   │   ├── anomaly_detector.py  # Rule-based (IST work hours) + IsolationForest outliers
│   │   ├── citation_validator.py# Strict ground-truth validation & anti-hallucination guard
│   │   ├── summarizer.py        # AI summarizer with 1-retry corrective prompting
│   │   └── cross_examiner.py    # Hybrid YAML rules + LLM adversarial cross-examiner
│   ├── rules/
│   │   └── counter_hypotheses.yaml # Forensic defense theory repository
│   └── llm/
│       ├── base.py              # LLMProvider abstract interface & audit logging
│       ├── mock_provider.py     # Deterministic offline mock provider
│       ├── ollama_provider.py   # Local Ollama provider
│       ├── gemini_provider.py   # Optional Gemini API provider
│       ├── factory.py           # Provider resolver with fallback logic
│       └── egress_guard.py      # Zero-egress network interceptor
├── frontend/                    # React + Vite + Tailwind 3-panel UI
├── sample_data/
│   ├── case_usb_theft.json      # 60-event theft case (USB, RDP ingress, scheduled task)
│   └── case_benign.json         # 25-event daytime business baseline case
├── scripts/
│   └── seed_demo.py             # Case verification & audit setup
├── tests/                       # 27 comprehensive pytest test suites
├── demo.py                      # One-command full-stack server & CLI demo launcher
├── Makefile                     # make demo, make test, make docker-up
└── docker-compose.yml           # Containerized orchestration
```

---

## 3. Shared Data Contract

SUTRAM strictly preserves the shared forensic data contract:

### Input Schema (`case.json`)
```json
{
  "case_id": "CASE-USB-THEFT-001",
  "events": [
    {
      "event_id": "EVT-0047",
      "timestamp_utc": "2025-03-14T17:02:18Z",
      "clock_uncertainty_sec": 0.5,
      "source": "windows_security_log",
      "actor": "user_x",
      "action": "file_copy",
      "object": "Quarterly_Financials.xlsx",
      "details": {
        "source_path": "C:\\Users\\user_x\\Documents\\Financials\\Quarterly_Financials.xlsx",
        "destination_path": "E:\\Backups\\Quarterly_Financials.xlsx",
        "bytes_transferred": 14852910
      },
      "evidence_hash": "a1b2c3d4e5f67890abcdef1234567890abcdef1234567890abcdef1234567890",
      "raw_ref": "Security.evtx:EventID_4663:RecordNumber_108450"
    }
  ]
}
```

---

## 4. Key Features

### Feature 1: AI-Assisted Summarization with Citation Validator
- **Endpoint**: `POST /api/summarize`
- Contextual summaries where **every claim is backed by citations to real event IDs**.
- **Citation Validator**: Inspects LLM output before presentation. Any claim with missing citations, citing non-existent event IDs, or fabricating SHA-256 hashes is dropped or flagged `unsupported`. Automatically retries the LLM once with corrective feedback upon failure.

### Feature 2: Adversarial Self-Cross-Examination (Headline Feature)
- **Endpoint**: `POST /api/cross-examine`
- **RebuttalBrief**:
  ```json
  {
    "finding": {"text": "...", "citations": ["EVT-0043", "EVT-0047"]},
    "counter_hypotheses": [
      {
        "id": "CH-BACKUP",
        "alternative_explanation": "Automated Scheduled Backup: Coincided with DailyArchiveJob...",
        "plausibility": "high",
        "supporting_signals_in_case": ["EVT-0045"],
        "evidence_needed_to_rule_out": [
          "Pull Task Scheduler XML definition to verify destination drive.",
          "Inspect backup_sync.ps1 arguments."
        ],
        "status": "open"
      }
    ],
    "finding_strength": "weak",
    "admissibility_notes": [
      "Mandatory Certificate: Electronic evidence requires Section 63 BSA, 2023 certificate."
    ]
  }
  ```
- **Objective Finding Strength**: Derived mathematically from open defense hypotheses. Initial theft accusations start as `weak` because both an automated backup and an untrusted RDP login coincide with the incident window.
- **Dynamic Re-evaluation** (`POST /api/cross-examine/{id}/add-evidence`): When investigators pull new corroborating evidence (e.g. Task XML proving internal backup target, CCTV proving physical presence, IT asset register proving personal USB), defense hypotheses transition to `ruled_out` and finding strength dynamically elevates to `strong`!

### Feature 3: Hybrid Anomaly Detection
- **Endpoint**: `POST /api/anomalies`
- **Layer 1 (Rules Engine)**:
  - IST Off-Hours Activity (configurable 09:30–18:30 IST window).
  - Removable USB connect followed by `file_copy` within 15 minutes.
  - Log tampering or `file_delete` following data movement.
  - Rapid multi-file copy bursts.
  - First-seen external public IP in remote desktop sessions.
- **Layer 2 (Statistical `IsolationForest`)**:
  - Behavioral outlier profiling across events/hour, distinct objects, off-hours ratio, byte volume, and sensitive operations. Seeded (`random_state=42`) for reproducibility.
- **Candidate Finding Pre-fill**: Each anomaly outputs a `suggested_finding` ready to be cross-examined with one click.

---

## 5. One-Command Quickstart

### Method A: Python Local (Recommended)
```bash
# 1. Seed sample cases and verify readiness
python scripts/seed_demo.py

# 2. Launch full-stack application (FastAPI + React UI)
python demo.py
```
- Open browser at **`http://localhost:8000`**
- Interactive Swagger/OpenAPI docs at **`http://localhost:8000/docs`**

### Method B: Terminal CLI Automated Demo
To run the automated forensic demonstration directly in your terminal:
```bash
python demo.py --cli
```

### Method C: Makefile
```bash
make demo        # Runs seed and starts server
make cli-demo    # Executes terminal CLI demonstration
make test        # Runs all 27 pytest tests
```

### Method D: Docker Compose
```bash
docker compose up --build
```

---

## 6. Teammate Integration Guide (`module_api.py`)

Teammates building Evidence Intake, Timeline UI, or Case Management can import SUTRAM directly in Python without running a network service:

```python
from backend.module_api import (
    load_case,
    detect_anomalies,
    summarize_case,
    cross_examine_finding,
    add_evidence_and_reevaluate
)

# 1. Load case telemetry
case = load_case("sample_data/case_usb_theft.json")

# 2. Detect anomalies
anomalies = detect_anomalies(case)

# 3. Generate summary with verified citations
summary = summarize_case(case, focus="USB data transfer")

# 4. Cross-examine candidate finding
brief = cross_examine_finding(
    case=case,
    finding_text="user_x exfiltrated financial records via USB",
    citations=["EVT-0043", "EVT-0047"]
)

print("Finding Strength:", brief.finding_strength) # 'weak'
```

---

## 7. Configuration & Environment Variables

| Variable | Values | Default | Purpose |
| :--- | :--- | :--- | :--- |
| `LLM_PROVIDER` | `mock` \| `ollama` \| `gemini` | `mock` | Selects reasoning engine; falls back to mock if Ollama unreachable |
| `ZERO_EGRESS` | `true` \| `false` | `true` | Socket-level air-gap enforcement blocking non-localhost traffic |
| `AUDIT_LOG_FILE`| File path | `audit_trail.log`| Chain of custody audit trail consumed by Person 4 |
| `OLLAMA_HOST` | URL | `http://localhost:11434`| Local Ollama service host |
| `OLLAMA_MODEL`| Model name | `qwen2.5:3b` | Target local quantized model |
| `GEMINI_API_KEY`| API Key | `""` | Optional Google Gemini key |

---

## 8. Verification & Test Suite

Run all 27 unit and integration tests:
```bash
python -m pytest
```

Coverage:
- Citation Validator (rejection of empty citations, fake IDs, hallucinated hashes).
- Counter-Hypothesis Library YAML matching against timeline events.
- Anomaly rules (IST working hours, USB bursts, log deletion, external IP).
- Scikit-learn `IsolationForest` statistical outlier profiling.
- Dynamic re-evaluation (`add-evidence` loophole closing).
- Zero-egress air-gap socket enforcement.
- LLM graceful fallback to `MockProvider`.

---

## 9. Statutory Admissibility (Indian Evidence Law)

Every output generated by SUTRAM complies with:
- **Bharatiya Sakshya Adhiniyam (BSA), 2023 — Section 63** *(formerly Section 65B of Indian Evidence Act, 1872)*.
- **Cryptographic Chain of Custody**: SHA-256 evidence hashes matched against raw forensic disk acquisitions (`E01`/`raw_ref`).
- **Export Formats**: One-click download of machine-readable `RebuttalBrief.json` and printable Indian Courtroom Rebuttal Brief HTML document with formal police emblem and statutory certificate declarations.
