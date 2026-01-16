#!/bin/bash
# ===========================================
# SecurityReview.ai - Stop Script (Mac/Linux)
# ===========================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "Stopping SecurityReview.ai..."

# Stop backend
if [ -f "$SCRIPT_DIR/.backend.pid" ]; then
    PID=$(cat "$SCRIPT_DIR/.backend.pid")
    if kill -0 "$PID" 2>/dev/null; then
        kill "$PID" 2>/dev/null && echo "✓ Backend stopped (PID: $PID)"
    fi
    rm -f "$SCRIPT_DIR/.backend.pid"
fi

# Stop frontend
if [ -f "$SCRIPT_DIR/.frontend.pid" ]; then
    PID=$(cat "$SCRIPT_DIR/.frontend.pid")
    if kill -0 "$PID" 2>/dev/null; then
        kill "$PID" 2>/dev/null && echo "✓ Frontend stopped (PID: $PID)"
    fi
    rm -f "$SCRIPT_DIR/.frontend.pid"
fi

# Kill any remaining processes on ports
if command -v lsof &>/dev/null; then
    lsof -ti :8000 2>/dev/null | xargs kill -9 2>/dev/null || true
    lsof -ti :3000 2>/dev/null | xargs kill -9 2>/dev/null || true
elif command -v fuser &>/dev/null; then
    fuser -k 8000/tcp 2>/dev/null || true
    fuser -k 3000/tcp 2>/dev/null || true
fi

# Stop Docker containers if running
if command -v docker &>/dev/null; then
    if docker compose -f compose.lite.yml ps 2>/dev/null | grep -q "Up"; then
        echo "Stopping Docker containers (lite)..."
        docker compose -f compose.lite.yml down 2>/dev/null || docker-compose -f compose.lite.yml down 2>/dev/null || true
    fi
    if docker compose -f compose.full.yml ps 2>/dev/null | grep -q "Up"; then
        echo "Stopping Docker containers (full)..."
        docker compose -f compose.full.yml down 2>/dev/null || docker-compose -f compose.full.yml down 2>/dev/null || true
    fi
fi

echo "✓ All services stopped"
