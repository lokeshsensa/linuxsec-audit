#!/usr/bin/env bash
# ==============================================================================
# LinuxSecAudit Application Launcher
# ==============================================================================
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
BACKEND_DIR="$PROJECT_ROOT/backend"
FRONTEND_DIR="$PROJECT_ROOT/frontend"

VENV_PYTHON="$BACKEND_DIR/venv/bin/python"

if [ ! -f "$VENV_PYTHON" ]; then
    echo "[-] Error: Python virtual environment not found in $BACKEND_DIR/venv."
    echo "[*] Run ./scripts/install.sh first."
    exit 1
fi

echo "======================================================================"
echo "          STARTING LINUX SECURITY AUDIT TOOL (LinuxSecAudit)          "
echo "======================================================================"

cleanup() {
    echo ""
    echo "[*] Stopping LinuxSecAudit services..."
    if [ -n "$BACKEND_PID" ]; then
        kill "$BACKEND_PID" 2>/dev/null || true
    fi
    if [ -n "$FRONTEND_PID" ]; then
        kill "$FRONTEND_PID" 2>/dev/null || true
    fi
    exit 0
}

trap cleanup SIGINT SIGTERM EXIT

# 1. Start FastAPI backend on port 8000
echo "[*] Starting FastAPI Backend on http://127.0.0.1:8000..."
cd "$BACKEND_DIR"
PYTHONPATH=. "$VENV_PYTHON" -m uvicorn app.main:app --host 0.0.0.0 --port 8000 &
BACKEND_PID=$!

# Wait briefly for backend to initialize
sleep 2

# 2. Start Frontend Vite server on port 5173
echo "[*] Starting React Frontend on http://localhost:5173..."
cd "$FRONTEND_DIR"
npm run dev -- --host 0.0.0.0 --port 5173 &
FRONTEND_PID=$!

echo "======================================================================"
echo "[✓] LinuxSecAudit is running!"
echo "    Dashboard UI : http://localhost:5173"
echo "    REST API     : http://127.0.0.1:8000"
echo "    Swagger Docs : http://127.0.0.1:8000/docs"
echo "    Press [Ctrl+C] to stop all services."
echo "======================================================================"

wait
