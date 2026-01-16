#!/bin/bash
# ===========================================
# SecurityReview.ai - Local Setup Script
# Creates virtual environment, directories, and secure configs
# ===========================================

set -euo pipefail

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
log_warning() { echo -e "${YELLOW}[WARNING]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

echo -e "${BLUE}=========================================${NC}"
echo -e "${BLUE}SecurityReview.ai - Secure Local Setup${NC}"
echo -e "${BLUE}=========================================${NC}"
echo ""

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

cd "$PROJECT_ROOT"

# ===========================================
# Prerequisites Check
# ===========================================
log_info "Checking prerequisites..."

check_command() {
    if ! command -v "$1" &> /dev/null; then
        log_error "$1 is not installed. Please install it first."
        exit 1
    fi
    log_success "$1 is installed"
}

check_command "docker"
check_command "python3"
check_command "node"
check_command "npm"

# Docker Compose
if docker compose version &> /dev/null; then
    DOCKER_COMPOSE="docker compose"
elif command -v docker-compose &> /dev/null; then
    DOCKER_COMPOSE="docker-compose"
else
    log_error "Docker Compose is not installed."
    exit 1
fi
log_success "Docker Compose is available"

echo ""

# ===========================================
# Generate Secure Secrets
# ===========================================
log_info "Generating secure secrets..."

generate_secret() {
    python3 -c "import secrets; print(secrets.token_urlsafe(32))"
}

generate_password() {
    python3 -c "import secrets; import string; chars = string.ascii_letters + string.digits; print(''.join(secrets.choice(chars) for _ in range(24)))"
}

SECRET_KEY=$(generate_secret)
NEO4J_PASSWORD=$(generate_password)

log_success "Secure secrets generated"

# ===========================================
# Create Required Directories
# ===========================================
log_info "Creating required directories..."

# Create directories with secure permissions
for dir in "data" "data/projects" "data/analyses" "data/reports" "data/exports" "logs" "uploads"; do
    mkdir -p "$PROJECT_ROOT/$dir"
    chmod 750 "$PROJECT_ROOT/$dir"
done

log_success "Directories created with secure permissions"

# ===========================================
# Create Environment Files
# ===========================================
log_info "Setting up environment files..."

# Backend .env
if [ ! -f "$PROJECT_ROOT/backend/.env" ]; then
    cat > "$PROJECT_ROOT/backend/.env" << EOF
# ===========================================
# SecurityReview.ai Backend Configuration
# Generated: $(date -u +"%Y-%m-%dT%H:%M:%SZ")
# ===========================================

# Application
APP_NAME=SecurityReview.ai
DEBUG=true
LOG_LEVEL=INFO

# Security (auto-generated)
SECRET_KEY=${SECRET_KEY}

# API
CORS_ORIGINS=http://localhost:3000,http://127.0.0.1:3000
RATE_LIMIT_PER_MINUTE=60

# Storage (Persistent)
DATA_DIR=./data
LOG_DIR=./logs
UPLOAD_DIR=./uploads

# Logging
LOG_TO_FILE=true
LOG_MAX_SIZE_MB=10
LOG_RETENTION_DAYS=30

# LLM Provider
LLM_PROVIDER=mock

# Neo4j
NEO4J_URI=bolt://localhost:7687
NEO4J_USER=neo4j
NEO4J_PASSWORD=${NEO4J_PASSWORD}

# Qdrant
QDRANT_HOST=localhost
QDRANT_PORT=6333
QDRANT_COLLECTION=security_documents

# Embeddings
EMBEDDING_PROVIDER=mock

# File Upload
MAX_FILE_SIZE=10485760
ALLOWED_EXTENSIONS=.pdf,.md,.txt,.json,.yaml,.yml,.xml,.py,.js,.ts,.tf
EOF
    chmod 600 "$PROJECT_ROOT/backend/.env"
    log_success "Created backend/.env with secure permissions"
else
    log_warning "backend/.env already exists - skipping"
fi

# Frontend .env.local
if [ ! -f "$PROJECT_ROOT/frontend/.env.local" ]; then
    cat > "$PROJECT_ROOT/frontend/.env.local" << EOF
# SecurityReview.ai Frontend Configuration
NEXT_PUBLIC_BACKEND_URL=http://localhost:8000
NEXT_PUBLIC_APP_NAME=SecurityReview.ai
EOF
    chmod 600 "$PROJECT_ROOT/frontend/.env.local"
    log_success "Created frontend/.env.local"
else
    log_warning "frontend/.env.local already exists"
fi

# Docker environment
cat > "$PROJECT_ROOT/.env" << EOF
# Docker Compose environment
NEO4J_AUTH=neo4j/${NEO4J_PASSWORD}
EOF
chmod 600 "$PROJECT_ROOT/.env"
log_success "Created .env for Docker Compose"

echo ""

# ===========================================
# Setup Backend Virtual Environment
# ===========================================
log_info "Setting up backend Python virtual environment..."

BACKEND_VENV="$PROJECT_ROOT/backend/venv"

if [ ! -d "$BACKEND_VENV" ]; then
    python3 -m venv "$BACKEND_VENV"
    log_success "Created virtual environment at backend/venv"
else
    log_warning "Virtual environment already exists"
fi

source "$BACKEND_VENV/bin/activate"
log_info "Installing backend dependencies..."
pip install --quiet --upgrade pip setuptools wheel
pip install --quiet -r "$PROJECT_ROOT/backend/requirements.txt"
log_success "Backend dependencies installed"
deactivate

echo ""

# ===========================================
# Setup Frontend Dependencies
# ===========================================
log_info "Setting up frontend dependencies..."

cd "$PROJECT_ROOT/frontend"
npm install --silent
log_success "Frontend dependencies installed"

cd "$PROJECT_ROOT"
echo ""

# ===========================================
# Display Instructions
# ===========================================
echo -e "${GREEN}=========================================${NC}"
echo -e "${GREEN}Setup Complete!${NC}"
echo -e "${GREEN}=========================================${NC}"
echo ""
echo -e "${BLUE}Directory Structure:${NC}"
echo "  data/         - Persistent data storage (projects, analyses, reports)"
echo "  logs/         - Application logs (app.log, error.log, audit.log, ai_interactions.log)"
echo "  uploads/      - Uploaded files"
echo ""
echo -e "${BLUE}To start with Docker:${NC}"
echo "  $DOCKER_COMPOSE up --build"
echo ""
echo -e "${BLUE}To start individually (development):${NC}"
echo "  1. Start databases:"
echo "     $DOCKER_COMPOSE up neo4j qdrant -d"
echo ""
echo "  2. Start backend:"
echo "     ./scripts/dev-backend.sh"
echo ""
echo "  3. Start frontend (new terminal):"
echo "     ./scripts/dev-frontend.sh"
echo ""
echo -e "${BLUE}Service URLs:${NC}"
echo "  Frontend:      http://localhost:3000"
echo "  Backend API:   http://localhost:8000"
echo "  API Docs:      http://localhost:8000/docs"
echo "  Neo4j Browser: http://localhost:7474"
echo "  Qdrant UI:     http://localhost:6333/dashboard"
echo ""
echo -e "${YELLOW}Data Persistence:${NC}"
echo "  All submitted data and AI-generated content is stored in:"
echo "  - data/projects/    - Project metadata and files"
echo "  - data/analyses/    - Analysis results"
echo "  - data/reports/     - Generated reports"
echo "  - logs/             - Application and audit logs"
echo ""
echo -e "${YELLOW}Log Files:${NC}"
echo "  - logs/app.log           - All application logs"
echo "  - logs/error.log         - Errors only"
echo "  - logs/audit.log         - Security audit trail"
echo "  - logs/ai_interactions.log - AI/LLM interactions"
echo ""
