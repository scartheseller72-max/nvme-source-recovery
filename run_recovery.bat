@echo off
REM ===========================================================================
REM  run_recovery.bat -- one-command recovery pipeline on Windows (image only)
REM
REM  Usage:
REM     run_recovery.bat <IMAGE_OR_DEVICE> <OUTPUT_DIR> [--carve-nonresident]
REM
REM  Examples:
REM     run_recovery.bat D:\rescue.img D:\recovered
REM     run_recovery.bat \\.\PhysicalDrive2 D:\recovered     (Administrator)
REM
REM  Runs, in order: analyze -> mft -> usn -> archives -> media -> source.
REM  Everything is READ-ONLY against the input.
REM ===========================================================================
setlocal
cd /d "%~dp0"

set "IMG=%~1"
set "OUT=%~2"
set "EXTRA=%~3"

if "%IMG%"=="" goto usage
if "%OUT%"=="" goto usage

where py >nul 2>nul && (set "PY=py -3") || (set "PY=python")

set "ENGINE=nvme_recover.py"
if not exist "%ENGINE%" (
    echo [FAIL] engine not found next to this script: %ENGINE%
    pause & exit /b 1
)

if not exist "%OUT%" mkdir "%OUT%"
echo [*] input : %IMG%
echo [*] output: %OUT%
echo.

%PY% "%ENGINE%" analyze --image "%IMG%" --out "%OUT%"
set "REGIONS=%OUT%\00_analysis\regions.json"

if /I "%EXTRA%"=="--carve-nonresident" (
    %PY% "%ENGINE%" mft --image "%IMG%" --out "%OUT%" --carve-nonresident
) else (
    %PY% "%ENGINE%" mft --image "%IMG%" --out "%OUT%"
)

%PY% "%ENGINE%" usn      --image "%IMG%" --out "%OUT%" --regions "%REGIONS%"
%PY% "%ENGINE%" archives --image "%IMG%" --out "%OUT%" --regions "%REGIONS%"
%PY% "%ENGINE%" media    --image "%IMG%" --out "%OUT%" --regions "%REGIONS%"
%PY% "%ENGINE%" source   --image "%IMG%" --out "%OUT%" --regions "%REGIONS%"

echo.
echo ============================================================
echo  RECOVERY COMPLETE -- look in: %OUT%
echo    10_mft\files\            recovered deleted files (original names)
echo    10_mft\mft_manifest.csv  full list of every deleted file found
echo    20_archives\             rebuilt zip/7z + salvaged members
echo    40_media\photos^|videos\  carved photos ^& videos
echo    30_source\^<lang^>\        carved source by language
echo ============================================================
endlocal
exit /b 0

:usage
echo Usage: %~nx0 ^<IMAGE_OR_DEVICE^> ^<OUTPUT_DIR^> [--carve-nonresident]
echo Example: %~nx0 D:\rescue.img D:\recovered
exit /b 1
