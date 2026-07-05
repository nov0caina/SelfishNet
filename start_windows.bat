@echo off
REM ═══════════════════════════════════════════════════════
REM  SelfishNet — Windows Launcher
REM  Runs SelfishNet as Administrator
REM ═══════════════════════════════════════════════════════

echo.
echo ╔══════════════════════════════════════╗
echo ║    SelfishNet — Windows Launcher     ║
echo ╚══════════════════════════════════════╝
echo.

REM ── Check for Administrator ──
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo [!] SelfishNet requires Administrator privileges.
    echo     Relaunching as Administrator...
    powershell -Command "Start-Process '%~f0' -Verb RunAs"
    exit /b
)

REM ── Check if built ──
if not exist "%~dp0SelfishNet\bin\Release\net8.0\SelfishNet.dll" (
    echo [ERROR] SelfishNet not built. Run install_windows.bat first.
    pause
    exit /b 1
)

REM ── Launch ──
echo [OK] Launching SelfishNet...
echo.
cd /d "%~dp0SelfishNet"
dotnet run --configuration Release --no-build

echo.
echo SelfishNet closed.
pause
