#!/bin/bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT_DIR"

if [[ -f .env ]]; then
	set -a
	source .env
	set +a
fi

export DEFAULT_ADMIN_USERNAME="${DEFAULT_ADMIN_USERNAME:-admin}"

# Allow login from Vite fallback port as well.
export ALLOWED_ORIGINS="${ALLOWED_ORIGINS:-http://localhost:3000,http://localhost:5173,http://127.0.0.1:5173,http://localhost:5174,http://127.0.0.1:5174}"

if [[ -z "${SECRET_KEY:-}" || -z "${JWT_SECRET_KEY:-}" || -z "${DEFAULT_ADMIN_PASSWORD:-}" ]]; then
	printf 'Missing SECRET_KEY, JWT_SECRET_KEY, or DEFAULT_ADMIN_PASSWORD. Set them in .env before starting.\n' >&2
	exit 1
fi

BACKEND_PYTHON="$ROOT_DIR/backend/venv/bin/python"
if [[ ! -x "$BACKEND_PYTHON" ]]; then
	printf 'Backend virtual environment is missing. Create it with: python3 -m venv backend/venv\n' >&2
	exit 1
fi

if ! "$BACKEND_PYTHON" -c 'import flask' >/dev/null 2>&1; then
	printf 'Backend dependencies are missing. Install them with: backend/venv/bin/python -m pip install -r backend/requirements.txt\n' >&2
	exit 1
fi

echo "Starting SOAR SIEM..."

# Backend
"$BACKEND_PYTHON" backend/app.py &
BACKEND_PID=$!

# Frontend
cd frontend/soc-dashboard-frontend
npm run dev &
FRONTEND_PID=$!

echo ""
echo "✅ Ready!"
echo "   Open: http://localhost:5173"
echo "   Login: ${DEFAULT_ADMIN_USERNAME} / ${DEFAULT_ADMIN_PASSWORD}"
echo ""
echo "Press Ctrl+C to stop"
wait "$BACKEND_PID" "$FRONTEND_PID"
