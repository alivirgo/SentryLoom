@echo off
setlocal EnableExtensions
title SentryLoom HQ Restart

fltmc >nul 2>&1
if not "%errorlevel%"=="0" (
    echo Requesting administrator permission...
    powershell.exe -NoLogo -NoProfile -NonInteractive -Command ^
        "Start-Process -FilePath '%~f0' -WorkingDirectory '%~dp0' -Verb RunAs"
    exit /b
)

cd /d "%~dp0"

set "POWERSHELL=%ProgramFiles%\PowerShell\7\pwsh.exe"
if not exist "%POWERSHELL%" set "POWERSHELL=%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe"

echo Restarting SentryLoom HQ...
"%POWERSHELL%" -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "%~dp0Restart-SentryLoomHq.ps1"
set "RESULT=%errorlevel%"

echo.
if "%RESULT%"=="0" (
    echo SentryLoom HQ restart completed successfully.
) else (
    echo SentryLoom HQ restart failed with exit code %RESULT%.
)
echo.
pause
exit /b %RESULT%
