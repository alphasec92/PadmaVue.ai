@echo off
REM ===========================================
REM PadmaVue.ai - Start Script (Windows CMD)
REM ===========================================
REM Usage: start.bat [options]
REM   /full      Full mode with Neo4j + Qdrant
REM   /reset     Reset and reinstall
REM   /backend   Backend only
REM   /frontend  Frontend only
REM ===========================================

echo.
echo ===========================================================
echo                   PadmaVue.ai
echo          AI-Powered Threat Modeling Platform
echo ===========================================================
echo.

REM Check if PowerShell is available
where powershell >nul 2>&1
if %errorlevel% neq 0 (
    echo ERROR: PowerShell is required but not found.
    echo Please install PowerShell or run start.ps1 directly.
    pause
    exit /b 1
)

REM Convert batch args to PowerShell args
set PSARGS=
if /i "%1"=="/full" set PSARGS=-Full
if /i "%1"=="--full" set PSARGS=-Full
if /i "%1"=="/docker" set PSARGS=-Full
if /i "%1"=="--docker" set PSARGS=-Full
if /i "%1"=="/reset" set PSARGS=-Reset
if /i "%1"=="--reset" set PSARGS=-Reset
if /i "%1"=="/backend" set PSARGS=-Backend
if /i "%1"=="--backend" set PSARGS=-Backend
if /i "%1"=="/frontend" set PSARGS=-Frontend
if /i "%1"=="--frontend" set PSARGS=-Frontend
if /i "%1"=="/help" set PSARGS=-Help
if /i "%1"=="--help" set PSARGS=-Help

REM Run the PowerShell script
powershell -ExecutionPolicy Bypass -File "%~dp0start.ps1" %PSARGS%

if %errorlevel% neq 0 (
    echo.
    echo If you see an execution policy error, run:
    echo   powershell -ExecutionPolicy Bypass -File start.ps1
    echo.
    pause
)
