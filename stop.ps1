# ===========================================
# PadmaVue.ai - Stop Script (Windows)
# ===========================================

$ErrorActionPreference = "SilentlyContinue"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path

# Source common functions
. "$ScriptDir\scripts\common\Common.ps1"

Write-Host "Stopping PadmaVue.ai..." -ForegroundColor Yellow

# Stop background jobs
Get-Job | Stop-Job
Get-Job | Remove-Job

# Stop processes on ports
Stop-ProcessOnPort 8000
Stop-ProcessOnPort 3000

# Clean up PID files
Remove-Item "$ScriptDir\.backend.pid" -Force -ErrorAction SilentlyContinue
Remove-Item "$ScriptDir\.frontend.pid" -Force -ErrorAction SilentlyContinue

# Stop Docker containers if running
if (Get-Command "docker" -ErrorAction SilentlyContinue) {
    try {
        $liteCompose = Get-ComposePath "compose.lite.yml"
        $liteStatus = docker compose -f $liteCompose ps 2>$null
        if ($liteStatus -match "Up") {
            Write-Host "Stopping Docker containers (lite)..."
            docker compose -f $liteCompose down 2>$null
        }
    } catch {}
    
    try {
        $fullCompose = Get-ComposePath "compose.full.yml"
        $fullStatus = docker compose -f $fullCompose ps 2>$null
        if ($fullStatus -match "Up") {
            Write-Host "Stopping Docker containers (full)..."
            docker compose -f $fullCompose down 2>$null
        }
    } catch {}
}

Write-Host "[OK] All services stopped" -ForegroundColor Green
