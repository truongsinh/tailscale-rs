@echo off
rem
rem run-node2.cmd — koidra-gateway channel launch shim (Windows).
rem
rem Invoked by the scheduled task (admin) or supervisor.vbs (non-admin) as:
rem   run-node2.cmd <channel> <port> [exe-override]
rem     <channel>  = primary | backup   (identity file is <channel>.json here)
rem     <port>     = 22 for BOTH channels (each channel is its own tailnet IP;
rem                  no port conflict — the whole fleet dials :22)
rem     [override] = optional explicit versioned exe name (rollout version pins)
rem
rem Binary resolution order:
rem   1. exe-override arg (%3) — explicit rollout version pin
rem   2. current-koidra-gateway.txt in this dir — the authoritative pointer,
rem      seeded by the installer with the VERSIONED name and atomically
rem      rewritten by the in-process updater (temp+rename)
rem   3. default fallback = the shipped VERSIONED name (never a bare
rem      koidra_gateway.exe — a bare name hides which build is running and
rem      breaks rollback identity). Kept in sync with the installer's GW_SHA
rem      default (koidra-gateway-<sha>.exe) and the branch HEAD.
rem
rem Auth key is BAKED TO DISK (authkey.txt, written by the installer via
rem extract-authkey.ps1) and read at launch — NEVER from an env var: SYSTEM
rem scheduled-task env is stale until reboot and reboot is a hard NO on this fleet.
rem
rem TS_HOSTNAME is set here so the Windows console node name replicates the old
rem koidra-ssh name exactly (Windows node name comes from TS_HOSTNAME) — the
rem console name never churns on the rebrand.

setlocal enabledelayedexpansion

set "DIR=%~dp0"
set "DIR=%DIR:~0,-1%"

rem ---- args (channel + port; both channels :22) --------------------------- rem
set "CHAN=%~1"
set "PORT=%~2"
if "%CHAN%"=="" set "CHAN=primary"
if "%PORT%"=="" set "PORT=22"

rem ---- resolve the binary -------------------------------------------------- rem
rem Default = shipped versioned name (matches installer GW_SHA default / HEAD).
set "EXE=%DIR%\koidra-gateway-06f9a3a.exe"

rem Pointer file wins over the default. Delayed expansion (!TARGET!) is REQUIRED:
rem inside a parenthesized block %TARGET% would expand at PARSE time (before
rem set /p runs) and the pointer would be silently ignored.
if exist "%DIR%\current-koidra-gateway.txt" (
    set /p TARGET=<"%DIR%\current-koidra-gateway.txt"
    if not "!TARGET!"=="" set "EXE=%DIR%\!TARGET!"
)

rem Explicit override arg wins over everything.
if not "%~3"=="" set "EXE=%DIR%\%~3"

rem ---- auth key (from disk, never env) ------------------------------------ rem
set "AUTHKEY="
if exist "%DIR%\authkey.txt" set /p AUTHKEY=<"%DIR%\authkey.txt"

rem ---- console node name (stable across the rebrand) ---------------------- rem
set "TS_HOSTNAME=%COMPUTERNAME%-%CHAN%"

rem ---- launch ------------------------------------------------------------- rem
if defined KOIDRA_MANIFEST_URL (
    "!EXE!" -c "%DIR%\%CHAN%.json" -k !AUTHKEY! --listen-port %PORT% --install-dir "%DIR%" --manifest-url "%KOIDRA_MANIFEST_URL%"
) else (
    "!EXE!" -c "%DIR%\%CHAN%.json" -k !AUTHKEY! --listen-port %PORT% --install-dir "%DIR%"
)

endlocal
