#!/bin/bash

echo "Starting SOAR SIEM..."

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
echo "   Login: admin / password"
echo ""
echo "Press Ctrl+C to stop"
wait
