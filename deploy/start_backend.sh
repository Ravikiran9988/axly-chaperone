#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BACKEND_DIR="${SCRIPT_DIR}/../backend"
cd "${BACKEND_DIR}"

if [ ! -f ".env" ]; then
  echo "Missing backend/.env. Copy backend/.env.example or backend/.env.production.example first." >&2
  exit 1
fi

echo "Applying Alembic database migrations..."
alembic upgrade head

echo "Starting AXLY Chaperone production ASGI server..."
exec uvicorn app.main:app --host "${CHAPERONE_HOST:-0.0.0.0}" --port "${CHAPERONE_PORT:-8000}" --workers 1
