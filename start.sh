#!/bin/bash
# ===========================================
# PadmaVue.ai - Start Script (Mac/Linux)
# ===========================================
# Usage: ./start.sh [options]
#   --backend   Start backend only
#   --frontend  Start frontend only
#   --full      Full mode with Neo4j & Qdrant (Docker)
#   --docker    Alias for --full
#   --reset     Reset and reinstall everything
#   --help      Show help
# ===========================================

set -euo pipefail

# Script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Source common functions
source "$SCRIPT_DIR/scripts/common/common.sh"

# Minimum versions
MIN_PYTHON_MAJOR=3
MIN_PYTHON_MINOR=11
MIN_NODE_MAJOR=18
MIN_NPM_MAJOR=9

# ===========================================
# Helper Functions
# ===========================================

show_help() {
    cat << EOF
Usage: ./start.sh [options]

Modes:
  (default)     Lite mode - backend + frontend only (no Neo4j/Qdrant)
  --full        Full mode - includes Neo4j + Qdrant via Docker
  --docker      Alias for --full

Options:
  --backend     Start backend only
  --frontend    Start frontend only
  --reset       Reset and reinstall everything
  --help        Show this help message

Examples:
  ./start.sh              # Lite mode: backend + frontend
  ./start.sh --full       # Full mode: + Neo4j + Qdrant
  ./start.sh --backend    # Backend only (lite mode)
  ./start.sh --reset      # Clean reinstall
EOF
    exit 0
}

version_ge() {
    # Returns 0 if $1 >= $2 (version comparison)
    [ "$(printf '%s\n' "$2" "$1" | sort -V | head -n1)" = "$2" ]
}

# ===========================================
# Dependency Checks
# ===========================================

check_dependencies() {
    print_step "Checking dependencies..."
    
    local OS
    OS=$(detect_os)
    local errors=0
    
    # Check Python
    if command_exists python3; then
        PYTHON_CMD="python3"
    elif command_exists python && python --version 2>&1 | grep -q "Python 3"; then
        PYTHON_CMD="python"
    else
        print_error "Python 3 not found"
        errors=1
    fi
    
    if [ -n "${PYTHON_CMD:-}" ]; then
        local py_version
        py_version=$($PYTHON_CMD -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
        local py_major py_minor
        py_major=$(echo "$py_version" | cut -d. -f1)
        py_minor=$(echo "$py_version" | cut -d. -f2)
        
        if [ "$py_major" -lt "$MIN_PYTHON_MAJOR" ] || { [ "$py_major" -eq "$MIN_PYTHON_MAJOR" ] && [ "$py_minor" -lt "$MIN_PYTHON_MINOR" ]; }; then
            print_error "Python $py_version found, but ${MIN_PYTHON_MAJOR}.${MIN_PYTHON_MINOR}+ required"
            errors=1
        else
            print_success "Python $py_version"
        fi
    fi
    
    # Check Node.js
    if command_exists node; then
        local node_version
        node_version=$(node --version | sed 's/v//')
        local node_major
        node_major=$(echo "$node_version" | cut -d. -f1)
        
        if [ "$node_major" -lt "$MIN_NODE_MAJOR" ]; then
            print_error "Node.js $node_version found, but ${MIN_NODE_MAJOR}+ required"
            errors=1
        else
            print_success "Node.js v$node_version"
        fi
    else
        print_error "Node.js not found"
        errors=1
    fi
    
    # Check npm
    if command_exists npm; then
        local npm_version
        npm_version=$(npm --version)
        local npm_major
        npm_major=$(echo "$npm_version" | cut -d. -f1)
        
        if [ "$npm_major" -lt "$MIN_NPM_MAJOR" ]; then
            print_warning "npm $npm_version found, ${MIN_NPM_MAJOR}+ recommended"
        else
            print_success "npm $npm_version"
        fi
    else
        print_error "npm not found"
        errors=1
    fi
    
    if [ "$errors" -ne 0 ]; then
        echo ""
        print_error "Missing or outdated dependencies. Install them first:"
        echo ""
        case "$OS" in
            mac)
                echo "  brew install python@3.11 node"
                ;;
            linux)
                echo "  # Ubuntu/Debian:"
                echo "  sudo apt update && sudo apt install python3.11 python3.11-venv nodejs npm"
                echo ""
                echo "  # Or use nvm for Node.js: https://github.com/nvm-sh/nvm"
                ;;
            *)
                echo "  Python 3.11+: https://python.org/downloads"
                echo "  Node.js 20+:  https://nodejs.org"
                ;;
        esac
        exit 1
    fi
}

# ===========================================
# Backend Setup
# ===========================================

setup_backend() {
    print_step "Setting up backend..."
    
    cd "$SCRIPT_DIR/backend"
    
    # Create venv if missing or reset requested
    if [ ! -d "venv" ] || [ "${RESET_MODE:-false}" = true ]; then
        print_info "Creating Python virtual environment..."
        $PYTHON_CMD -m venv venv
        print_success "Virtual environment created"
        rm -f venv/.packages_installed 2>/dev/null || true
    else
        print_success "Virtual environment exists"
    fi
    
    # Activate venv
    # shellcheck disable=SC1091
    source venv/bin/activate 2>/dev/null || source venv/Scripts/activate 2>/dev/null || die "Failed to activate venv"
    
    # Install packages if needed (check hash of requirements.txt)
    local req_hash
    req_hash=$(md5sum requirements.txt 2>/dev/null | cut -d' ' -f1 || md5 -q requirements.txt 2>/dev/null || echo "unknown")
    
    if [ ! -f "venv/.packages_installed" ] || [ "$(cat venv/.packages_installed 2>/dev/null)" != "$req_hash" ] || [ "${RESET_MODE:-false}" = true ]; then
        print_info "Installing Python packages (this may take 2-3 minutes on first run)..."
        pip install --upgrade pip setuptools wheel -q
        pip install -r requirements.txt -q || pip install -r requirements.txt
        echo "$req_hash" > venv/.packages_installed
        print_success "Python packages installed"
    else
        print_success "Python packages up to date"
    fi
    
    # Create .env if missing
    if [ ! -f ".env" ]; then
        print_info "Creating backend .env file..."
        cp "$SCRIPT_DIR/env-templates/backend.env" .env
        # Set STORAGE_MODE based on full mode
        if [ "${FULL_MODE:-false}" = true ]; then
            sed -i.bak 's/^STORAGE_MODE=.*/STORAGE_MODE=full/' .env 2>/dev/null || \
            sed -i '' 's/^STORAGE_MODE=.*/STORAGE_MODE=full/' .env 2>/dev/null || true
        fi
        rm -f .env.bak 2>/dev/null || true
        print_success "Backend .env created"
    fi
    
    # Create required directories
    mkdir -p data logs uploads
    
    cd "$SCRIPT_DIR"
}

# ===========================================
# Frontend Setup
# ===========================================

setup_frontend() {
    print_step "Setting up frontend..."
    
    cd "$SCRIPT_DIR/frontend"
    
    # Clean .next cache if reset requested (prevents Turbopack permission errors)
    if [ "${RESET_MODE:-false}" = true ] && [ -d ".next" ]; then
        print_info "Cleaning Next.js cache..."
        rm -rf .next
    fi
    
    # Install node_modules if missing or reset requested
    if [ ! -d "node_modules" ] || [ "${RESET_MODE:-false}" = true ]; then
        print_info "Installing Node.js packages..."
        npm install --silent 2>/dev/null || npm install
        print_success "Node.js packages installed"
    else
        print_success "Node.js packages exist"
    fi
    
    cd "$SCRIPT_DIR"
}

# ===========================================
# LLM Provider Configuration
# ===========================================

configure_llm() {
    print_step "LLM Provider Configuration"
    
    echo ""
    echo "Choose your AI provider:"
    echo ""
    echo -e "  ${GREEN}1) Mock Mode${NC}     - No AI needed, sample responses (default)"
    echo -e "  ${CYAN}2) Ollama${NC}         - Free, local (recommended)"
    echo -e "  ${CYAN}3) LM Studio${NC}      - Free, local with GUI"
    echo -e "  ${YELLOW}4) OpenAI${NC}         - GPT-4 (requires API key)"
    echo -e "  ${YELLOW}5) Anthropic${NC}      - Claude (requires API key)"
    echo -e "  ${YELLOW}6) OpenRouter${NC}     - Multiple models (requires API key)"
    echo ""
    
    read -rp "Enter choice [1-6] (default: 1): " llm_choice
    llm_choice=${llm_choice:-1}
    
    case $llm_choice in
        2) configure_ollama ;;
        3) configure_lmstudio ;;
        4) configure_openai ;;
        5) configure_anthropic ;;
        6) configure_openrouter ;;
        *) 
            print_info "Using Mock Mode"
            update_env "LLM_PROVIDER" "mock"
            ;;
    esac
}

configure_ollama() {
    print_info "Configuring Ollama..."
    
    if command_exists ollama; then
        print_success "Ollama is installed"
        
        if curl -s http://localhost:11434/api/tags >/dev/null 2>&1; then
            print_success "Ollama is running"
            
            echo ""
            echo "Available models:"
            
            # Get list of models and display with numbers
            local models=()
            local i=1
            while IFS= read -r line; do
                if [[ -n "$line" && ! "$line" =~ ^NAME ]]; then
                    local model_name_only=$(echo "$line" | awk '{print $1}')
                    models+=("$model_name_only")
                    printf "  %d) %s\n" "$i" "$line"
                    ((i++))
                fi
            done < <(ollama list 2>/dev/null)
            
            if [[ ${#models[@]} -eq 0 ]]; then
                echo "  (No models installed. Run 'ollama pull llama3.2' to download a model)"
            fi
            echo ""
            
            read -rp "Select model (number or name, default: llama3.2): " model_input
            model_input=${model_input:-llama3.2}
            
            # Check if input is a number
            if [[ "$model_input" =~ ^[0-9]+$ ]]; then
                local idx=$((model_input - 1))
                if [[ $idx -ge 0 && $idx -lt ${#models[@]} ]]; then
                    model_name="${models[$idx]}"
                else
                    print_warning "Invalid selection, using default: llama3.2"
                    model_name="llama3.2"
                fi
            else
                model_name="$model_input"
            fi
            
            if ! ollama list 2>/dev/null | grep -q "$model_name"; then
                print_info "Pulling model $model_name..."
                ollama pull "$model_name"
            fi
            
            update_env "LLM_PROVIDER" "ollama"
            update_env "OLLAMA_MODEL" "$model_name"
            print_success "Ollama configured: $model_name"
        else
            print_warning "Ollama not running. Start with: ollama serve"
            update_env "LLM_PROVIDER" "mock"
        fi
    else
        print_warning "Ollama not installed"
        echo "  Install: curl -fsSL https://ollama.com/install.sh | sh"
        update_env "LLM_PROVIDER" "mock"
    fi
}

configure_lmstudio() {
    print_info "Configuring LM Studio..."
    echo ""
    echo "  1. Download from https://lmstudio.ai"
    echo "  2. Load a model"
    echo "  3. Start the local server"
    echo ""
    read -rp "Is LM Studio running on localhost:1234? [y/N]: " lms_running
    if [[ $lms_running =~ ^[Yy]$ ]]; then
        update_env "LLM_PROVIDER" "lmstudio"
        print_success "LM Studio configured"
    else
        update_env "LLM_PROVIDER" "mock"
    fi
}

configure_openai() {
    read -rp "Enter OpenAI API key: " api_key
    if [ -n "$api_key" ]; then
        update_env "LLM_PROVIDER" "openai"
        update_env "OPENAI_API_KEY" "$api_key"
        print_success "OpenAI configured"
    else
        update_env "LLM_PROVIDER" "mock"
    fi
}

configure_anthropic() {
    read -rp "Enter Anthropic API key: " api_key
    if [ -n "$api_key" ]; then
        update_env "LLM_PROVIDER" "anthropic"
        update_env "ANTHROPIC_API_KEY" "$api_key"
        print_success "Anthropic configured"
    else
        update_env "LLM_PROVIDER" "mock"
    fi
}

configure_openrouter() {
    read -rp "Enter OpenRouter API key: " api_key
    if [ -n "$api_key" ]; then
        update_env "LLM_PROVIDER" "openrouter"
        update_env "OPENROUTER_API_KEY" "$api_key"
        print_success "OpenRouter configured"
    else
        update_env "LLM_PROVIDER" "mock"
    fi
}

update_env() {
    local key=$1
    local value=$2
    local env_file="$SCRIPT_DIR/backend/.env"
    
    if grep -q "^${key}=" "$env_file" 2>/dev/null; then
        if [[ "$(uname)" == "Darwin" ]]; then
            sed -i '' "s|^${key}=.*|${key}=${value}|" "$env_file"
        else
            sed -i "s|^${key}=.*|${key}=${value}|" "$env_file"
        fi
    else
        echo "${key}=${value}" >> "$env_file"
    fi
}

# ===========================================
# Start Services
# ===========================================

start_backend() {
    print_step "Starting backend server..."
    
    cd "$SCRIPT_DIR/backend"
    
    # Activate venv
    # shellcheck disable=SC1091
    source venv/bin/activate 2>/dev/null || source venv/Scripts/activate 2>/dev/null
    
    # Check port 8000
    if port_in_use 8000; then
        print_warning "Port 8000 in use"
        read -rp "Kill existing process? [y/N]: " kill_proc
        if [[ $kill_proc =~ ^[Yy]$ ]]; then
            kill_port 8000
            sleep 1
        else
            die "Cannot start backend - port 8000 in use"
        fi
    fi
    
    # Start backend
    print_info "Starting uvicorn on http://localhost:8000 ..."
    uvicorn app.main:app --reload --host 0.0.0.0 --port 8000 &
    local backend_pid=$!
    echo "$backend_pid" > "$SCRIPT_DIR/.backend.pid"
    
    # Wait for startup
    for _ in {1..30}; do
        if curl -s http://localhost:8000/health >/dev/null 2>&1; then
            print_success "Backend running: http://localhost:8000"
            cd "$SCRIPT_DIR"
            return 0
        fi
        sleep 1
    done
    
    die "Backend failed to start (timeout after 30s)"
}

start_frontend() {
    print_step "Starting frontend server..."
    
    cd "$SCRIPT_DIR/frontend"
    
    # Clean up stale Next.js artifacts (prevents lock file and permission errors)
    if [ -d ".next" ]; then
        # Remove stale lock file from previous crashed sessions
        rm -f .next/dev/lock 2>/dev/null
        
        # On macOS, remove quarantine attributes that can cause Turbopack permission errors
        if [[ "$(uname)" == "Darwin" ]]; then
            xattr -rd com.apple.quarantine .next 2>/dev/null || true
        fi
    fi
    
    # Check port 3000
    if port_in_use 3000; then
        print_warning "Port 3000 in use"
        read -rp "Kill existing process? [y/N]: " kill_proc
        if [[ $kill_proc =~ ^[Yy]$ ]]; then
            kill_port 3000
            sleep 1
        else
            die "Cannot start frontend - port 3000 in use"
        fi
    fi
    
    # Start frontend
    print_info "Starting Next.js on http://localhost:3000 ..."
    npm run dev &
    local frontend_pid=$!
    echo "$frontend_pid" > "$SCRIPT_DIR/.frontend.pid"
    
    # Wait for startup
    for _ in {1..30}; do
        if curl -s http://localhost:3000 >/dev/null 2>&1; then
            print_success "Frontend running: http://localhost:3000"
            cd "$SCRIPT_DIR"
            return 0
        fi
        sleep 1
    done
    
    die "Frontend failed to start (timeout after 30s)"
}

start_docker_full() {
    print_step "Starting Full Mode with Docker Compose..."
    
    if ! command_exists docker; then
        die "Docker is not installed. Install from https://docker.com"
    fi
    
    if ! docker info >/dev/null 2>&1; then
        die "Docker is not running. Please start Docker Desktop or the Docker daemon."
    fi
    
    mkdir -p data logs uploads
    
    if [ ! -f "backend/.env" ]; then
        cp env-templates/backend.env backend/.env
        # Set full mode
        if [[ "$(uname)" == "Darwin" ]]; then
            sed -i '' 's/^STORAGE_MODE=.*/STORAGE_MODE=full/' backend/.env 2>/dev/null || true
        else
            sed -i 's/^STORAGE_MODE=.*/STORAGE_MODE=full/' backend/.env 2>/dev/null || true
        fi
    fi
    
    print_info "Building and starting containers..."
    
    local compose_cmd
    compose_cmd=$(get_docker_compose_cmd)
    local compose_file
    compose_file=$(get_compose_path "compose.full.yml")
    
    $compose_cmd -f "$compose_file" up --build -d
    
    echo ""
    print_success "Full mode started with Docker!"
    echo ""
    echo "  Frontend:  http://localhost:3000"
    echo "  Backend:   http://localhost:8000"
    echo "  Neo4j:     http://localhost:7474 (user: neo4j)"
    echo "  Qdrant:    http://localhost:6333"
    echo ""
    echo "  Stop with: $compose_cmd -f $compose_file down"
    echo "  Logs:      $compose_cmd -f $compose_file logs -f"
}

# ===========================================
# Cleanup
# ===========================================

cleanup() {
    echo ""
    print_info "Shutting down..."
    
    if [ -f "$SCRIPT_DIR/.backend.pid" ]; then
        kill "$(cat "$SCRIPT_DIR/.backend.pid")" 2>/dev/null || true
        rm -f "$SCRIPT_DIR/.backend.pid"
    fi
    
    if [ -f "$SCRIPT_DIR/.frontend.pid" ]; then
        kill "$(cat "$SCRIPT_DIR/.frontend.pid")" 2>/dev/null || true
        rm -f "$SCRIPT_DIR/.frontend.pid"
    fi
    
    kill_port 8000
    kill_port 3000
    
    print_success "Services stopped"
    exit 0
}

# ===========================================
# Main
# ===========================================

main() {
    print_banner
    
    # Parse arguments
    FULL_MODE=false
    RESET_MODE=false
    BACKEND_ONLY=false
    FRONTEND_ONLY=false
    PYTHON_CMD="python3"
    
    for arg in "$@"; do
        case $arg in
            --full|--docker) FULL_MODE=true ;;
            --reset) RESET_MODE=true ;;
            --backend) BACKEND_ONLY=true ;;
            --frontend) FRONTEND_ONLY=true ;;
            --help|-h) show_help ;;
            *) print_warning "Unknown option: $arg" ;;
        esac
    done
    
    # Full mode uses Docker
    if [ "$FULL_MODE" = true ]; then
        start_docker_full
        exit 0
    fi
    
    # Lite mode (default)
    print_info "Starting in Lite Mode (no Neo4j/Qdrant)"
    echo "  Use --full for Full Mode with Neo4j + Qdrant"
    echo ""
    
    # Check dependencies
    check_dependencies
    
    # Setup
    if [ "$FRONTEND_ONLY" = false ]; then
        setup_backend
    fi
    
    if [ "$BACKEND_ONLY" = false ]; then
        setup_frontend
    fi
    
    # First run configuration
    if [ ! -f "$SCRIPT_DIR/backend/.env.configured" ]; then
        configure_llm
        touch "$SCRIPT_DIR/backend/.env.configured"
    fi
    
    # Trap for cleanup
    trap cleanup SIGINT SIGTERM
    
    # Start services
    if [ "$FRONTEND_ONLY" = false ]; then
        start_backend
    fi
    
    if [ "$BACKEND_ONLY" = false ]; then
        start_frontend
    fi
    
    # Success message
    echo ""
    echo -e "${GREEN}╔══════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║        🎉 PadmaVue.ai is running! (Lite Mode)           ║${NC}"
    echo -e "${GREEN}╚══════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "  🌐 Open: ${CYAN}http://localhost:3000${NC}"
    echo ""
    echo "  📖 API Docs: http://localhost:8000/docs"
    echo "  ⚙️  Settings: Click gear icon in the app"
    echo ""
    echo -e "  Press ${YELLOW}Ctrl+C${NC} to stop"
    echo ""
    
    wait
}

main "$@"
