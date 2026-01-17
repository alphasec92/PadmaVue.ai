#!/bin/bash
# ===========================================
# PadmaVue.ai - Frontend Development Server
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
FRONTEND_DIR="$PROJECT_ROOT/frontend"

echo -e "${BLUE}=========================================${NC}"
echo -e "${BLUE}PadmaVue.ai - Frontend Dev Server${NC}"
echo -e "${BLUE}=========================================${NC}"
echo ""

# Check if node_modules exists
if [ ! -d "$FRONTEND_DIR/node_modules" ]; then
    echo -e "${RED}node_modules not found!${NC}"
    echo "Run ./scripts/setup-local.sh first"
    exit 1
fi

# Check if .env.local exists
if [ ! -f "$FRONTEND_DIR/.env.local" ]; then
    echo -e "${YELLOW}Warning: .env.local not found, using defaults${NC}"
fi

cd "$FRONTEND_DIR"

echo -e "${GREEN}Starting frontend server...${NC}"
echo -e "URL: ${BLUE}http://localhost:3000${NC}"
echo ""

exec npm run dev


