@echo off
REM ===========================================
REM SecurityReview.ai - Stop Script (Windows CMD)
REM ===========================================

echo Stopping SecurityReview.ai...

REM Run the PowerShell script
powershell -ExecutionPolicy Bypass -File "%~dp0stop.ps1"

echo Done.
