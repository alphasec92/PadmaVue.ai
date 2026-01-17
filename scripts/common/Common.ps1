# ===========================================
# PadmaVue.ai - Common PowerShell Functions
# ===========================================

# Logging functions
function Write-Banner {
    Write-Host ""
    Write-Host "===========================================================" -ForegroundColor Cyan
    Write-Host "                   PadmaVue.ai                            " -ForegroundColor Cyan
    Write-Host "          AI-Powered Threat Modeling Platform              " -ForegroundColor Cyan
    Write-Host "===========================================================" -ForegroundColor Cyan
    Write-Host ""
}

function Write-Step($message) { Write-Host "`n> $message" -ForegroundColor Blue }
function Write-Success($message) { Write-Host "[OK] $message" -ForegroundColor Green }
function Write-Warning($message) { Write-Host "[WARN] $message" -ForegroundColor Yellow }
function Write-Error($message) { Write-Host "[ERROR] $message" -ForegroundColor Red }
function Write-Info($message) { Write-Host "[INFO] $message" -ForegroundColor Cyan }

# Check if command exists
function Test-Command($command) {
    return $null -ne (Get-Command $command -ErrorAction SilentlyContinue)
}

# Check if port is in use
function Test-Port($port) {
    $connection = Get-NetTCPConnection -LocalPort $port -ErrorAction SilentlyContinue
    return $null -ne $connection
}

# Stop process on port
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

# Get repository root
function Get-RepoRoot {
    $scriptDir = Split-Path -Parent $MyInvocation.ScriptName
    return (Resolve-Path "$scriptDir\..\..").Path
}

# Get compose file path
function Get-ComposePath($composeFile) {
    $repoRoot = Get-RepoRoot
    return Join-Path $repoRoot "infra\docker\compose\$composeFile"
}

# Get docker compose command
function Get-DockerComposeCmd {
    try {
        docker compose version | Out-Null
        return "docker compose"
    } catch {
        if (Test-Command "docker-compose") {
            return "docker-compose"
        }
        throw "Neither 'docker compose' nor 'docker-compose' found"
    }
}
