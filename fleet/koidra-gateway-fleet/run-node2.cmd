@echo off
rem
rem Supervisor launch shim for koidra-gateway (Windows).
rem
rem Invoked by the scheduled task (or supervisor.vbs) as:
rem   run-node2.cmd <channel> <port> [exe-override]
rem
rem The binary to launch is resolved in this order:
rem   1. exe-override arg (%3) — set by rollout scripts for explicit version pins
rem   2. current-koidra-gateway.txt in this dir — written by the in-process updater
rem      (atomic temp+rename; see examples/koidra_gateway/updater.rs)
rem   3. hardcoded default koidra_gateway.exe — last-resort fallback
rem
rem %AUTHKEY%, %KOIDRA_MANIFEST_URL% are expected to be set in the SYSTEM env
rem (setx /M) by the installer or rollout script. %1 is the channel name
rem (primary|backup) whose identity file lives next to this script as
rem <channel>.json.

setlocal

set "DIR=%~dp0"
set "DIR=%DIR:~0,-1%"
set "EXE=%DIR%\koidra_gateway.exe"

if exist "%DIR%\current-koidra-gateway.txt" (
    set /p TARGET=<"%DIR%\current-koidra-gateway.txt"
    if not "%TARGET%"=="" set "EXE=%DIR%\%TARGET%"
)

if not "%~3"=="" set "EXE=%DIR%\%~3"

if defined KOIDRA_MANIFEST_URL (
    "%EXE%" -c "%DIR%\%~1.json" -k %AUTHKEY% --listen-port %~2 --install-dir "%DIR%" --manifest-url "%KOIDRA_MANIFEST_URL%"
) else (
    "%EXE%" -c "%DIR%\%~1.json" -k %AUTHKEY% --listen-port %~2 --install-dir "%DIR%"
)

endlocal
