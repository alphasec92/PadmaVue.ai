#!/bin/bash
# ===========================================
# PadmaVue.ai - Test Runner
# ===========================================

set -euo pipefail

# Colors
GREEN='\033[0;32m'
BLUE='\033[0;34m'
RED='\033[0;31m'
NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

echo -e "${BLUE}=========================================${NC}"
echo -e "${BLUE}PadmaVue.ai - Test Suite${NC}"
echo -e "${BLUE}=========================================${NC}"
echo ""

# Backend Tests
echo -e "${BLUE}Running Backend Tests...${NC}"
cd "$PROJECT_ROOT/backend"

if [ -d "venv" ]; then
    source venv/bin/activate
    
    # Run pytest with coverage
    python -m pytest tests/ \
        --verbose \
        --cov=app \
        --cov-report=term-missing \
        --cov-fail-under=70 \
        || { echo -e "${RED}Backend tests failed!${NC}"; exit 1; }
    
    deactivate
    echo -e "${GREEN}Backend tests passed!${NC}"
else
    echo -e "${RED}Backend virtual environment not found!${NC}"
    exit 1
fi

echo ""

# Frontend Tests
echo -e "${BLUE}Running Frontend Tests...${NC}"
cd "$PROJECT_ROOT/frontend"

if [ -d "node_modules" ]; then
    npm test -- --coverage --passWithNoTests \
        || { echo -e "${RED}Frontend tests failed!${NC}"; exit 1; }
    echo -e "${GREEN}Frontend tests passed!${NC}"
else
    echo -e "${RED}Frontend node_modules not found!${NC}"
    exit 1
fi

echo ""
echo -e "${GREEN}=========================================${NC}"
echo -e "${GREEN}All tests passed!${NC}"
echo -e "${GREEN}=========================================${NC}"


