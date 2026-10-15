@echo off
cd /d "%~dp0"
title SNI Spoofing & TCP Bypass Proxy

:: Check for Administrator privileges and auto-elevate
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo [i] Requesting Administrator privileges...
    powershell -Command "Start-Process cmd -ArgumentList '/c \"\"%~f0\"\"' -Verb RunAs"
    exit /b
)

:: Run inside virtual environment if available
if exist ".venv\Scripts\python.exe" (
    ".venv\Scripts\python.exe" main.py %*
) else (
    python main.py %*
)

if %errorLevel% neq 0 (
    echo.
    echo [!] Program exited with code %errorLevel%. Press any key to close...
    pause >nul
)
