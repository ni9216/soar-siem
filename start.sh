#!/bin/bash

echo "Starting SOAR SIEM..."

# Keep startup credentials in sync with backend defaults.
export DEFAULT_ADMIN_USERNAME="${DEFAULT_ADMIN_USERNAME:-admin}"
export DEFAULT_ADMIN_PASSWORD="${DEFAULT_ADMIN_PASSWORD:-password}"

# Allow login from Vite fallback port as well.
export ALLOWED_ORIGINS="${ALLOWED_ORIGINS:-http://localhost:3000,http://localhost:5173,http://127.0.0.1:5173,http://localhost:5174,http://127.0.0.1:5174}"

# Backend
cd backend
source venv/bin/activate
python3 app.py &
cd ..

# Frontend
cd frontend/soc-dashboard-frontend
npm run dev &

echo ""
echo "✅ Ready!"
echo "   Open: http://localhost:5173"
echo "   Login: ${DEFAULT_ADMIN_USERNAME} / ${DEFAULT_ADMIN_PASSWORD}"
echo ""
echo "Press Ctrl+C to stop"
wait
