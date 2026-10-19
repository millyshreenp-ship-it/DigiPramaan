# DigiPramaan — Quick Start

```bash
pip install -r requirements.txt
export LLM_PROVIDER=mock ZERO_EGRESS=true
python3 -m uvicorn backend.main:app --host 0.0.0.0 --port 8000
```

Open http://127.0.0.1:8000
