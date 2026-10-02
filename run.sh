#!/usr/bin/env bash
# Start the service. Data lives in ./data (override with FORENSIC_DATA_DIR). No internet needed once dependencies are installed.
set -e
cd "$(dirname "$0")"
python3 -m pip install -q -r requirements.txt 2>/dev/null || true
HOST="${HOST:-127.0.0.1}"; PORT="${PORT:-8000}"
echo "Open http://$HOST:$PORT  (first visit creates the administrator account)"
exec python3 -m uvicorn app.main:app --host "$HOST" --port "$PORT"
