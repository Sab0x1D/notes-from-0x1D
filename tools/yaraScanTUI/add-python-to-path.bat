@echo off
:: Run this BAT as Administrator to write to System PATH
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0add-python-to-path.ps1" -Scope System
pause
