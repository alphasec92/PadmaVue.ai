# ===========================================
# SecurityReview.ai - Start Script (Windows)
# ===========================================
# Usage: .\start.ps1 [options]
#   -Backend    Start backend only
#   -Frontend   Start frontend only
#   -Full       Full mode with Neo4j & Qdrant (Docker)
#   -Docker     Alias for -Full
#   -Reset      Reset and reinstall everything
#   -Help       Show help
# ===========================================

param(
    [switch]$Full,
    [switch]$Docker,
    [switch]$Reset,
    [switch]$Backend,
    [switch]$Frontend,
    [switch]$Help
)

$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $ScriptDir

# Minimum versions
$MinPythonMajor = 3
$MinPythonMinor = 11
$MinNodeMajor = 18
$MinNpmMajor = 9

# ===========================================
# Helper Functions
# ===========================================

function Write-Banner {
    Write-Host ""
    Write-Host "===========================================================" -ForegroundColor Cyan
    Write-Host "              SecurityReview.ai                            " -ForegroundColor Cyan
    Write-Host "          AI-Powered Threat Modeling Platform              " -ForegroundColor Cyan
    Write-Host "===========================================================" -ForegroundColor Cyan
    Write-Host ""
}

function Write-Step($message) { Write-Host "`n> $message" -ForegroundColor Blue }
function Write-Success($message) { Write-Host "[OK] $message" -ForegroundColor Green }
function Write-Warning($message) { Write-Host "[WARN] $message" -ForegroundColor Yellow }
function Write-Error($message) { Write-Host "[ERROR] $message" -ForegroundColor Red }
function Write-Info($message) { Write-Host "[INFO] $message" -ForegroundColor Cyan }

function Show-Help {
    Write-Host @"
Usage: .\start.ps1 [options]

Modes:
  (default)     Lite mode - backend + frontend only (no Neo4j/Qdrant)
  -Full         Full mode - includes Neo4j + Qdrant via Docker
  -Docker       Alias for -Full

Options:
  -Backend      Start backend only
  -Frontend     Start frontend only
  -Reset        Reset and reinstall everything
  -Help         Show this help message

Examples:
  .\start.ps1              # Lite mode: backend + frontend
  .\start.ps1 -Full        # Full mode: + Neo4j + Qdrant
  .\start.ps1 -Backend     # Backend only (lite mode)
  .\start.ps1 -Reset       # Clean reinstall
"@
    exit 0
}

function Test-Command($command) {
    return $null -ne (Get-Command $command -ErrorAction SilentlyContinue)
}

function Test-Port($port) {
    $connection = Get-NetTCPConnection -LocalPort $port -ErrorAction SilentlyContinue
    return $null -ne $connection
}

function Stop-ProcessOnPort($port) {
    $connections = Get-NetTCPConnection -LocalPort $port -ErrorAction SilentlyContinue
    foreach ($conn in $connections) {
        $process = Get-Process -Id $conn.OwningProcess -ErrorAction SilentlyContinue
        if ($process) {
            Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue
        }
    }
    Start-Sleep -Seconds 1
}

# ===========================================
# Dependency Checks
# ===========================================

function Test-Dependencies {
    Write-Step "Checking dependencies..."
    
    $errors = 0
    
    # Check Python
    if (Test-Command "python") {
        $pythonVersion = python --version 2>&1
        if ($pythonVersion -match "Python (\d+)\.(\d+)") {
            $pyMajor = [int]$Matches[1]
            $pyMinor = [int]$Matches[2]
            if ($pyMajor -lt $MinPythonMajor -or ($pyMajor -eq $MinPythonMajor -and $pyMinor -lt $MinPythonMinor)) {
                Write-Error "Python $pyMajor.$pyMinor found, but $MinPythonMajor.$MinPythonMinor+ required"
                $errors++
            } else {
                $script:PythonCmd = "python"
                Write-Success "Python $pyMajor.$pyMinor"
            }
        }
    } elseif (Test-Command "python3") {
        $script:PythonCmd = "python3"
        Write-Success "Python 3 found"
    } else {
        Write-Error "Python not found"
        $errors++
    }
    
    # Check Node.js
    if (Test-Command "node") {
        $nodeVersion = node --version
        if ($nodeVersion -match "v(\d+)") {
            $nodeMajor = [int]$Matches[1]
            if ($nodeMajor -lt $MinNodeMajor) {
                Write-Error "Node.js v$nodeMajor found, but $MinNodeMajor+ required"
                $errors++
            } else {
                Write-Success "Node.js $nodeVersion"
            }
        }
    } else {
        Write-Error "Node.js not found"
        $errors++
    }
    
    # Check npm
    if (Test-Command "npm") {
        $npmVersion = npm --version
        Write-Success "npm $npmVersion"
    } else {
        Write-Error "npm not found"
        $errors++
    }
    
    if ($errors -gt 0) {
        Write-Host ""
        Write-Error "Missing or outdated dependencies. Install them first:"
        Write-Host ""
        Write-Host "  # Using winget:"
        Write-Host "  winget install Python.Python.3.11"
        Write-Host "  winget install OpenJS.NodeJS"
        Write-Host ""
        Write-Host "  # Or download manually:"
        Write-Host "  Python 3.11+: https://python.org/downloads"
        Write-Host "  Node.js 20+:  https://nodejs.org"
        exit 1
    }
}

# ===========================================
# Backend Setup
# ===========================================

function Setup-Backend {
    Write-Step "Setting up backend..."
    
    Set-Location "$ScriptDir\backend"
    
    # Create virtual environment
    if (-not (Test-Path "venv") -or $Reset) {
        Write-Info "Creating Python virtual environment..."
        & $script:PythonCmd -m venv venv
        Write-Success "Virtual environment created"
        Remove-Item "venv\.packages_installed" -ErrorAction SilentlyContinue
    } else {
        Write-Success "Virtual environment exists"
    }
    
    # Activate virtual environment
    $activateScript = "venv\Scripts\Activate.ps1"
    if (Test-Path $activateScript) {
        & $activateScript
    } else {
        Write-Error "Failed to activate venv"
        exit 1
    }
    
    # Install packages
    if (-not (Test-Path "venv\.packages_installed") -or $Reset) {
        Write-Info "Installing Python packages (this may take 2-3 minutes on first run)..."
        pip install --upgrade pip setuptools wheel -q 2>$null
        pip install -r requirements.txt -q 2>$null
        if (-not $?) { pip install -r requirements.txt }
        New-Item -Path "venv\.packages_installed" -ItemType File -Force | Out-Null
        Write-Success "Python packages installed"
    } else {
        Write-Success "Python packages up to date"
    }
    
    # Create .env
    if (-not (Test-Path ".env")) {
        Write-Info "Creating backend .env file..."
        Copy-Item "$ScriptDir\env-templates\backend.env" ".env"
        Write-Success "Backend .env created"
    }
    
    # Create directories
    @("data", "logs", "uploads") | ForEach-Object {
        if (-not (Test-Path $_)) { New-Item -ItemType Directory -Path $_ | Out-Null }
    }
    
    Set-Location $ScriptDir
}

# ===========================================
# Frontend Setup
# ===========================================

function Setup-Frontend {
    Write-Step "Setting up frontend..."
    
    Set-Location "$ScriptDir\frontend"
    
    if (-not (Test-Path "node_modules") -or $Reset) {
        Write-Info "Installing Node.js packages..."
        npm install --silent 2>$null
        if (-not $?) { npm install }
        Write-Success "Node.js packages installed"
    } else {
        Write-Success "Node.js packages exist"
    }
    
    Set-Location $ScriptDir
}

# ===========================================
# LLM Configuration
# ===========================================

function Configure-LLM {
    Write-Step "LLM Provider Configuration"
    
    Write-Host ""
    Write-Host "Choose your AI provider:"
    Write-Host ""
    Write-Host "  1) Mock Mode     - No AI needed, sample responses (default)" -ForegroundColor Green
    Write-Host "  2) Ollama        - Free, local (recommended)" -ForegroundColor Cyan
    Write-Host "  3) LM Studio     - Free, local with GUI" -ForegroundColor Cyan
    Write-Host "  4) OpenAI        - GPT-4 (requires API key)" -ForegroundColor Yellow
    Write-Host "  5) Anthropic     - Claude (requires API key)" -ForegroundColor Yellow
    Write-Host "  6) OpenRouter    - Multiple models (requires API key)" -ForegroundColor Yellow
    Write-Host ""
    
    $choice = Read-Host "Enter choice [1-6] (default: 1)"
    if ([string]::IsNullOrWhiteSpace($choice)) { $choice = "1" }
    
    switch ($choice) {
        "2" { Configure-Ollama }
        "3" { Configure-LMStudio }
        "4" { Configure-OpenAI }
        "5" { Configure-Anthropic }
        "6" { Configure-OpenRouter }
        default {
            Write-Info "Using Mock Mode"
            Update-Env "LLM_PROVIDER" "mock"
        }
    }
}

function Configure-Ollama {
    Write-Info "Configuring Ollama..."
    
    if (Test-Command "ollama") {
        Write-Success "Ollama is installed"
        
        try {
            $null = Invoke-RestMethod -Uri "http://localhost:11434/api/tags" -TimeoutSec 2 -ErrorAction Stop
            Write-Success "Ollama is running"
            
            $model = Read-Host "Model name (default: llama3.2)"
            if ([string]::IsNullOrWhiteSpace($model)) { $model = "llama3.2" }
            
            Update-Env "LLM_PROVIDER" "ollama"
            Update-Env "OLLAMA_MODEL" $model
            Write-Success "Ollama configured: $model"
        } catch {
            Write-Warning "Ollama not running. Start with: ollama serve"
            Update-Env "LLM_PROVIDER" "mock"
        }
    } else {
        Write-Warning "Ollama not installed. Download from: https://ollama.com"
        Update-Env "LLM_PROVIDER" "mock"
    }
}

function Configure-LMStudio {
    Write-Info "Configuring LM Studio..."
    Write-Host ""
    Write-Host "  1. Download from https://lmstudio.ai"
    Write-Host "  2. Load a model"
    Write-Host "  3. Start the local server"
    Write-Host ""
    $running = Read-Host "Is LM Studio running on localhost:1234? [y/N]"
    if ($running -match "^[Yy]") {
        Update-Env "LLM_PROVIDER" "lmstudio"
        Write-Success "LM Studio configured"
    } else {
        Update-Env "LLM_PROVIDER" "mock"
    }
}

function Configure-OpenAI {
    $apiKey = Read-Host "Enter OpenAI API key"
    if (-not [string]::IsNullOrWhiteSpace($apiKey)) {
        Update-Env "LLM_PROVIDER" "openai"
        Update-Env "OPENAI_API_KEY" $apiKey
        Write-Success "OpenAI configured"
    } else {
        Update-Env "LLM_PROVIDER" "mock"
    }
}

function Configure-Anthropic {
    $apiKey = Read-Host "Enter Anthropic API key"
    if (-not [string]::IsNullOrWhiteSpace($apiKey)) {
        Update-Env "LLM_PROVIDER" "anthropic"
        Update-Env "ANTHROPIC_API_KEY" $apiKey
        Write-Success "Anthropic configured"
    } else {
        Update-Env "LLM_PROVIDER" "mock"
    }
}

function Configure-OpenRouter {
    $apiKey = Read-Host "Enter OpenRouter API key"
    if (-not [string]::IsNullOrWhiteSpace($apiKey)) {
        Update-Env "LLM_PROVIDER" "openrouter"
        Update-Env "OPENROUTER_API_KEY" $apiKey
        Write-Success "OpenRouter configured"
    } else {
        Update-Env "LLM_PROVIDER" "mock"
    }
}

function Update-Env($key, $value) {
    $envFile = "$ScriptDir\backend\.env"
    $content = Get-Content $envFile -Raw -ErrorAction SilentlyContinue
    
    if ($content -match "(?m)^$key=") {
        $content = $content -replace "(?m)^$key=.*", "$key=$value"
    } else {
        $content += "`n$key=$value"
    }
    
    Set-Content -Path $envFile -Value $content -NoNewline
}

# ===========================================
# Start Services
# ===========================================

function Start-Backend {
    Write-Step "Starting backend server..."
    
    Set-Location "$ScriptDir\backend"
    
    # Activate venv
    & "venv\Scripts\Activate.ps1"
    
    # Check port
    if (Test-Port 8000) {
        Write-Warning "Port 8000 in use"
        $kill = Read-Host "Kill existing process? [y/N]"
        if ($kill -match "^[Yy]") {
            Stop-ProcessOnPort 8000
        } else {
            Write-Error "Cannot start backend - port 8000 in use"
            exit 1
        }
    }
    
    # Start backend
    Write-Info "Starting uvicorn on http://localhost:8000 ..."
    $job = Start-Job -ScriptBlock {
        Set-Location $using:ScriptDir\backend
        & "$using:ScriptDir\backend\venv\Scripts\python.exe" -m uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
    }
    $job.Id | Out-File "$ScriptDir\.backend.pid"
    
    # Wait for startup
    for ($i = 0; $i -lt 30; $i++) {
        try {
            $null = Invoke-RestMethod -Uri "http://localhost:8000/health" -TimeoutSec 1 -ErrorAction Stop
            Write-Success "Backend running: http://localhost:8000"
            Set-Location $ScriptDir
            return $true
        } catch {
            Start-Sleep -Seconds 1
        }
    }
    
    Write-Error "Backend failed to start (timeout after 30s)"
    Set-Location $ScriptDir
    return $false
}

function Start-Frontend {
    Write-Step "Starting frontend server..."
    
    Set-Location "$ScriptDir\frontend"
    
    # Check port
    if (Test-Port 3000) {
        Write-Warning "Port 3000 in use"
        $kill = Read-Host "Kill existing process? [y/N]"
        if ($kill -match "^[Yy]") {
            Stop-ProcessOnPort 3000
        } else {
            Write-Error "Cannot start frontend - port 3000 in use"
            exit 1
        }
    }
    
    # Start frontend
    Write-Info "Starting Next.js on http://localhost:3000 ..."
    $job = Start-Job -ScriptBlock {
        Set-Location $using:ScriptDir\frontend
        npm run dev
    }
    $job.Id | Out-File "$ScriptDir\.frontend.pid"
    
    # Wait for startup
    for ($i = 0; $i -lt 30; $i++) {
        try {
            $null = Invoke-WebRequest -Uri "http://localhost:3000" -TimeoutSec 1 -ErrorAction Stop
            Write-Success "Frontend running: http://localhost:3000"
            Set-Location $ScriptDir
            return $true
        } catch {
            Start-Sleep -Seconds 1
        }
    }
    
    Write-Error "Frontend failed to start (timeout after 30s)"
    Set-Location $ScriptDir
    return $false
}

function Start-DockerFull {
    Write-Step "Starting Full Mode with Docker Compose..."
    
    if (-not (Test-Command "docker")) {
        Write-Error "Docker is not installed. Install from https://docker.com"
        exit 1
    }
    
    try {
        docker info | Out-Null
    } catch {
        Write-Error "Docker is not running. Please start Docker Desktop."
        exit 1
    }
    
    @("data", "logs", "uploads") | ForEach-Object {
        if (-not (Test-Path $_)) { New-Item -ItemType Directory -Path $_ | Out-Null }
    }
    
    if (-not (Test-Path "backend\.env")) {
        Copy-Item "env-templates\backend.env" "backend\.env"
    }
    
    Write-Info "Building and starting containers..."
    
    # Try modern docker compose first
    try {
        docker compose -f compose.full.yml up --build -d
    } catch {
        # Fall back to docker-compose
        docker-compose -f compose.full.yml up --build -d
    }
    
    Write-Host ""
    Write-Success "Full mode started with Docker!"
    Write-Host ""
    Write-Host "  Frontend:  http://localhost:3000"
    Write-Host "  Backend:   http://localhost:8000"
    Write-Host "  Neo4j:     http://localhost:7474 (user: neo4j)"
    Write-Host "  Qdrant:    http://localhost:6333"
    Write-Host ""
    Write-Host "  Stop with: docker compose -f compose.full.yml down"
    Write-Host "  Logs:      docker compose -f compose.full.yml logs -f"
}

# ===========================================
# Main
# ===========================================

if ($Help) { Show-Help }

Write-Banner

# Full mode uses Docker
if ($Full -or $Docker) {
    Start-DockerFull
    exit 0
}

# Lite mode (default)
Write-Info "Starting in Lite Mode (no Neo4j/Qdrant)"
Write-Host "  Use -Full for Full Mode with Neo4j + Qdrant"
Write-Host ""

# Check dependencies
Test-Dependencies

# Setup
if (-not $Frontend) {
    Setup-Backend
}

if (-not $Backend) {
    Setup-Frontend
}

# First run config
if (-not (Test-Path "$ScriptDir\backend\.env.configured")) {
    Configure-LLM
    New-Item -Path "$ScriptDir\backend\.env.configured" -ItemType File -Force | Out-Null
}

# Start services
if (-not $Frontend) {
    if (-not (Start-Backend)) { exit 1 }
}

if (-not $Backend) {
    if (-not (Start-Frontend)) { exit 1 }
}

# Success message
Write-Host ""
Write-Host "===========================================================" -ForegroundColor Green
Write-Host "     SecurityReview.ai is running! (Lite Mode)             " -ForegroundColor Green
Write-Host "===========================================================" -ForegroundColor Green
Write-Host ""
Write-Host "  Open: " -NoNewline
Write-Host "http://localhost:3000" -ForegroundColor Cyan
Write-Host ""
Write-Host "  API Docs: http://localhost:8000/docs"
Write-Host "  Settings: Click gear icon in the app"
Write-Host ""
Write-Host "  Press Ctrl+C to stop"
Write-Host ""

# Keep running
try {
    while ($true) { Start-Sleep -Seconds 1 }
} finally {
    Write-Host "`nStopping services..."
    Get-Job | Stop-Job -ErrorAction SilentlyContinue
    Get-Job | Remove-Job -ErrorAction SilentlyContinue
    Stop-ProcessOnPort 8000
    Stop-ProcessOnPort 3000
    Write-Success "Services stopped"
}
