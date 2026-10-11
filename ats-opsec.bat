@echo off
REM ATS-OPSEC-Suite - lanceur TUI (double-clic ou console)
REM Rebuild le binaire release quand cargo est dispo (incremental :
REM quasi instantane si rien n'a change), puis lance.

setlocal
cd /d "%~dp0"

where cargo >nul 2>&1
if %errorlevel%==0 (
    cargo build --release >nul 2>&1
)

if not exist "target\release\ats-opsec.exe" (
    echo [*] first launch - building release binary...
    cargo build --release
    if errorlevel 1 (
        echo [!] build failed - cargo installed ? ^(https://rustup.rs^)
        pause
        exit /b 1
    )
)

"target\release\ats-opsec.exe" %*
if errorlevel 1 pause
endlocal
