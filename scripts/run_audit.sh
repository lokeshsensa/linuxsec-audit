#!/usr/bin/env bash
# ==============================================================================
# LinuxSecAudit Standalone CLI Runner
# ==============================================================================
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
BACKEND_DIR="$PROJECT_ROOT/backend"
VENV_PYTHON="$BACKEND_DIR/venv/bin/python"

if [ ! -f "$VENV_PYTHON" ]; then
    echo "[-] Error: Python virtual environment not found in $BACKEND_DIR/venv."
    exit 1
fi

cd "$BACKEND_DIR"
PYTHONPATH=. "$VENV_PYTHON" -m app.cli audit "$@"
