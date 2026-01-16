# ===========================================
# SecurityReview.ai - Stop Script (Windows)
# ===========================================

$ErrorActionPreference = "SilentlyContinue"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path

Write-Host "Stopping SecurityReview.ai..." -ForegroundColor Yellow

# Stop background jobs
Get-Job | Stop-Job
Get-Job | Remove-Job

# Stop processes on ports
function Stop-ProcessOnPort($port) {
    $connections = Get-NetTCPConnection -LocalPort $port -ErrorAction SilentlyContinue
    foreach ($conn in $connections) {
        $process = Get-Process -Id $conn.OwningProcess -ErrorAction SilentlyContinue
        if ($process) {
            Write-Host "[OK] Stopping $($process.ProcessName) on port $port" -ForegroundColor Green
            Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue
        }
    }
}

Stop-ProcessOnPort 8000
Stop-ProcessOnPort 3000

# Clean up PID files
Remove-Item "$ScriptDir\.backend.pid" -Force -ErrorAction SilentlyContinue
Remove-Item "$ScriptDir\.frontend.pid" -Force -ErrorAction SilentlyContinue

# Stop Docker containers if running
if (Get-Command "docker" -ErrorAction SilentlyContinue) {
    try {
        $liteStatus = docker compose -f compose.lite.yml ps 2>$null
        if ($liteStatus -match "Up") {
            Write-Host "Stopping Docker containers (lite)..."
            docker compose -f compose.lite.yml down 2>$null
        }
    } catch {}
    
    try {
        $fullStatus = docker compose -f compose.full.yml ps 2>$null
        if ($fullStatus -match "Up") {
            Write-Host "Stopping Docker containers (full)..."
            docker compose -f compose.full.yml down 2>$null
        }
    } catch {}
}

Write-Host "[OK] All services stopped" -ForegroundColor Green
