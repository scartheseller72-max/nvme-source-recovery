@echo off
REM ===========================================================================
REM  run_gui.bat -- launch the NVMe Source Recovery GUI on Windows
REM
REM  Double-click this file, or run it from a Command Prompt.
REM  To read a physical drive directly (\\.\PhysicalDriveN) you must start it
REM  as Administrator. Reading a forensic .img file needs no special rights.
REM ===========================================================================
setlocal
cd /d "%~dp0"

where py >nul 2>nul
if %errorlevel%==0 (
    set "PY=py -3"
) else (
    where python >nul 2>nul
    if %errorlevel%==0 (
        set "PY=python"
    ) else (
        echo [FAIL] Python 3 not found. Install it from https://www.python.org/downloads/
        echo        and tick "Add python.exe to PATH" during setup.
        pause
        exit /b 1
    )
)

%PY% nvme_recover_gui.py
if %errorlevel% neq 0 pause
endlocal
