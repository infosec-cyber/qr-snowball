#!/usr/bin/env bash
# Local dev: one uvicorn process serves the API (/api/*) and the PWA (/) on the
# same origin — which WebAuthn requires. Data persists to backend/data/ via the
# filesystem fallback (no cloud account needed). Set BLOB_READ_WRITE_TOKEN to use
# a real Vercel Blob store locally instead.
set -euo pipefail
cd "$(dirname "$0")/backend"

if [ ! -d .venv ]; then
  python3 -m venv .venv
  ./.venv/bin/pip install -q -r requirements.txt
fi

export RELAY_RP_ID="${RELAY_RP_ID:-localhost}"
export RELAY_ORIGIN="${RELAY_ORIGIN:-http://localhost:8000}"

exec ./.venv/bin/uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
