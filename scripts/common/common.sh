#!/bin/bash
# ===========================================
# PadmaVue.ai - Common Shell Functions
# ===========================================

# Colors
export RED='\033[0;31m'
export GREEN='\033[0;32m'
export YELLOW='\033[1;33m'
export BLUE='\033[0;34m'
export CYAN='\033[0;36m'
export NC='\033[0m'
export BOLD='\033[1m'

# Logging functions
print_step() { echo -e "\n${BLUE}▶ ${BOLD}$1${NC}"; }
print_success() { echo -e "${GREEN}✓ $1${NC}"; }
print_warning() { echo -e "${YELLOW}⚠ $1${NC}"; }
print_error() { echo -e "${RED}✗ $1${NC}"; }
print_info() { echo -e "${CYAN}ℹ $1${NC}"; }
die() { print_error "$1"; exit 1; }

# Print banner
print_banner() {
    echo -e "${CYAN}"
    echo "╔══════════════════════════════════════════════════════════╗"
    echo "║                🛡️  PadmaVue.ai                           ║"
    echo "║          AI-Powered Threat Modeling Platform             ║"
    echo "╚══════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

# Check if a command exists
command_exists() { command -v "$1" &>/dev/null; }

# Detect OS
detect_os() {
    case "$(uname -s)" in
        Darwin*)    echo "mac" ;;
        Linux*)     echo "linux" ;;
        CYGWIN*|MINGW*|MSYS*) echo "windows" ;;
        *)          echo "unknown" ;;
    esac
}

# Get repository root directory
get_repo_root() {
    local script_dir
    if [ -n "${BASH_SOURCE[0]}" ]; then
        script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    else
        script_dir="$(pwd)"
    fi
    # Go up from scripts/common to repo root
    echo "$(cd "$script_dir/../.." && pwd)"
}

# Check if port is in use
port_in_use() {
    local port=$1
    if command_exists lsof; then
        lsof -i :"$port" >/dev/null 2>&1
    elif command_exists netstat; then
        netstat -tuln 2>/dev/null | grep -q ":$port "
    else
        return 1
    fi
}

# Kill process on port
kill_port() {
    local port=$1
    if command_exists lsof; then
        lsof -ti :"$port" | xargs kill -9 2>/dev/null || true
    elif command_exists fuser; then
        fuser -k "$port"/tcp 2>/dev/null || true
    fi
}

# Get docker compose command
get_docker_compose_cmd() {
    if docker compose version >/dev/null 2>&1; then
        echo "docker compose"
    elif command_exists docker-compose; then
        echo "docker-compose"
    else
        die "Neither 'docker compose' nor 'docker-compose' found"
    fi
}

# Compose file path helper
get_compose_path() {
    local compose_file=$1
    local repo_root
    repo_root=$(get_repo_root)
    echo "$repo_root/infra/docker/compose/$compose_file"
}
