#!/usr/bin/env bash
# ==============================================================================
# LinuxSecAudit Installation Script
# ==============================================================================
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

echo "======================================================================"
echo "          LINUX SECURITY AUDIT TOOL (LinuxSecAudit) INSTALLER         "
echo "======================================================================"

# 1. Check Python version (>= 3.11)
echo "[*] Checking Python environment..."
PYTHON_BIN=""
if command -v python3 &>/dev/null; then
    PYTHON_BIN="python3"
elif command -v python &>/dev/null; then
    PYTHON_BIN="python"
else
    echo "[-] Error: Python is not installed. Please install Python 3.11+."
    exit 1
fi

PY_VER=$($PYTHON_BIN -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
echo "[+] Detected Python version: $PY_VER"

# 2. Check Node / npm
echo "[*] Checking Node and npm environment..."
if command -v node &>/dev/null && command -v npm &>/dev/null; then
    echo "[+] Node.js $(node -v) and npm $(npm -v) detected."
else
    echo "[!] Warning: Node.js/npm not found in PATH. Pre-built frontend will be used or install node."
fi

# 3. Create virtual environment
VENV_DIR="$PROJECT_ROOT/backend/venv"
if [ ! -d "$VENV_DIR" ]; then
    echo "[*] Creating Python virtual environment in $VENV_DIR..."
    $PYTHON_BIN -m venv "$VENV_DIR"
fi

# 4. Install backend dependencies
echo "[*] Installing backend dependencies..."
"$VENV_DIR/bin/pip" install --upgrade pip -q
if [ -f "$PROJECT_ROOT/backend/requirements.txt" ]; then
    "$VENV_DIR/bin/pip" install -r "$PROJECT_ROOT/backend/requirements.txt" -q
fi

# 5. Frontend dependencies
if [ -d "$PROJECT_ROOT/frontend" ] && command -v npm &>/dev/null; then
    echo "[*] Setting up frontend dependencies..."
    cd "$PROJECT_ROOT/frontend"
    if [ ! -d "node_modules" ]; then
        npm install --silent
    fi
    npm run build --silent
    cd "$PROJECT_ROOT"
fi

# 6. Initialize database
echo "[*] Initializing SQLite database..."
cd "$PROJECT_ROOT/backend"
PYTHONPATH=. "$VENV_DIR/bin/python" -c "from app.database.database import init_db; init_db()"

echo "======================================================================"
echo "[✓] Installation completed successfully!"
echo "    Start the application: ./scripts/start.sh"
echo "    Run CLI security audit: ./scripts/run_audit.sh --demo"
echo "======================================================================"
