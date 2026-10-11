@echo off
REM ATS-OPSEC-Suite — lanceur TUI (double-clic ou console)
REM Utilise le binaire release s'il existe, sinon build puis lance.

setlocal
cd /d "%~dp0"

if exist "target\release\ats-opsec.exe" goto :run

echo [*] first launch - building release binary...
cargo build --release
if errorlevel 1 (
    echo [!] build failed - cargo installed ? ^(https://rustup.rs^)
    pause
    exit /b 1
)

:run
"target\release\ats-opsec.exe" %*
if errorlevel 1 pause
endlocal
