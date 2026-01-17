@echo off
REM ===========================================
REM PadmaVue.ai - Stop Script (Windows CMD)
REM ===========================================

echo Stopping PadmaVue.ai...

REM Run the PowerShell script
powershell -ExecutionPolicy Bypass -File "%~dp0stop.ps1"

echo Done.
