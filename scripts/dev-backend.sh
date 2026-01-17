#!/bin/bash
# ===========================================
# PadmaVue.ai - Backend Development Server
# Runs with virtual environment
# ===========================================

set -euo pipefail

# Colors
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
BACKEND_DIR="$PROJECT_ROOT/backend"
VENV_DIR="$BACKEND_DIR/venv"

echo -e "${BLUE}=========================================${NC}"
echo -e "${BLUE}PadmaVue.ai - Backend Dev Server${NC}"
echo -e "${BLUE}=========================================${NC}"
echo ""

# Check if virtual environment exists
if [ ! -d "$VENV_DIR" ]; then
    echo -e "${RED}Virtual environment not found!${NC}"
    echo "Run ./scripts/setup-local.sh first"
    exit 1
fi

# Check if .env exists
if [ ! -f "$BACKEND_DIR/.env" ]; then
    echo -e "${RED}.env file not found!${NC}"
    echo "Run ./scripts/setup-local.sh first"
    exit 1
fi

cd "$BACKEND_DIR"

echo -e "${YELLOW}Activating virtual environment...${NC}"
source "$VENV_DIR/bin/activate"

echo -e "${GREEN}Starting backend server...${NC}"
echo -e "API Docs: ${BLUE}http://localhost:8000/docs${NC}"
echo -e "Health:   ${BLUE}http://localhost:8000/health${NC}"
echo ""

# Run with reload for development
exec uvicorn app.main:app \
    --reload \
    --host 0.0.0.0 \
    --port 8000 \
    --log-level info


