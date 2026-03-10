#!/bin/bash

# autoMITRE Unified Startup Script

# Navigate to script directory
cd "$(dirname "$0")"

# Cleanup stale PIDs
rm -f backend/uvicorn.pid frontend/frontend.pid

echo "🚀 Starting autoMITRE Backend..."
cd backend
./venv/bin/python3 -m uvicorn main:app --host 0.0.0.0 --port 8000 > uvicorn.log 2>&1 &
BACKEND_PID=$!
echo $BACKEND_PID > uvicorn.pid
cd ..

echo "🚀 Starting autoMITRE Frontend..."
cd frontend
npm run dev > vite.log 2>&1 &
FRONTEND_PID=$!
echo $FRONTEND_PID > frontend.pid
cd ..

echo "✅ Application started!"
echo "📡 Backend: http://localhost:8000"
echo "🌐 Frontend: http://localhost:5173"
echo "📝 Logs: backend/uvicorn.log, frontend/vite.log"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Press Ctrl+C to stop both services."

# Trap Ctrl+C to kill child processes
trap "echo -e '\n🛑 Stopping services...'; kill $BACKEND_PID $FRONTEND_PID 2>/dev/null; exit" SIGINT SIGTERM

# Wait for processes
wait $BACKEND_PID $FRONTEND_PID
