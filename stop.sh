#!/bin/bash
# ===========================================
# PadmaVue.ai - Stop Script (Mac/Linux)
# ===========================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Source common functions
source "$SCRIPT_DIR/scripts/common/common.sh"

echo "Stopping PadmaVue.ai..."

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
kill_port 8000
kill_port 3000

# Stop Docker containers if running
if command_exists docker; then
    compose_cmd=$(get_docker_compose_cmd 2>/dev/null || echo "docker compose")
    
    lite_compose=$(get_compose_path "compose.lite.yml")
    if $compose_cmd -f "$lite_compose" ps 2>/dev/null | grep -q "Up"; then
        echo "Stopping Docker containers (lite)..."
        $compose_cmd -f "$lite_compose" down 2>/dev/null || true
    fi
    
    full_compose=$(get_compose_path "compose.full.yml")
    if $compose_cmd -f "$full_compose" ps 2>/dev/null | grep -q "Up"; then
        echo "Stopping Docker containers (full)..."
        $compose_cmd -f "$full_compose" down 2>/dev/null || true
    fi
fi

echo "✓ All services stopped"
