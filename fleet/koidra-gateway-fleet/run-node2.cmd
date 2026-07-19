@echo off
rem
rem run-node2.cmd - koidra-gateway channel launch shim + SUPERVISE LOOP (Windows).
rem
rem Invoked by the scheduled task (admin) or supervisor.vbs (non-admin) as:
rem   run-node2.cmd <channel> <port> [exe-override]
rem     <channel>  = primary | backup   (identity file is <channel>.json here)
rem     <port>     = 22 for BOTH channels (each channel is its own tailnet IP;
rem                  no port conflict - the whole fleet dials :22)
rem     [override] = optional explicit versioned exe name (rollout version pins)
rem
rem SINGLE LOOP OWNER (H1 fix). This script OWNS the crash-relaunch loop for BOTH
rem layouts so admin and non-admin both recover from a process exit WITHOUT a
rem reboot (reboot is a hard NO on this fleet):
rem   * admin     : the SYSTEM scheduled task runs `cmd /c run-node2.cmd <chan> 22`
rem                 in the foreground; this :loop keeps the channel alive.
rem   * non-admin : supervisor.vbs (MASTER) spawns ONE detached
rem                 `cmd /c run-node2.cmd <chan> 22` per channel, ONCE each, and
rem                 exits. It does NOT re-launch per channel - THIS loop does, so
rem                 there is exactly ONE loop per channel (no double-loop).
rem The two channels are always separate processes: one crash-looping here can
rem never take the other down.
rem
rem Fast-exit backoff: a child that dies in < HEALTHY_SECS is treated as an
rem immediate crash and the relaunch delay backs off progressively (BASE_DELAY *
rem consecutive-fast-fails, capped at MAX_DELAY) instead of tight-spinning; a child
rem that survives HEALTHY_SECS resets the backoff to BASE_DELAY.
rem
rem Binary resolution order:
rem   1. exe-override arg (%3) - explicit rollout version pin
rem   2. current-koidra-gateway.txt - the authoritative pointer, seeded by the
rem      installer with the VERSIONED name and atomically rewritten by the
rem      in-process updater (temp+rename)
rem   3. default-koidra-gateway.txt - the installer-baked default (from -DGW_SHA);
rem      the updater NEVER rewrites this, so it survives an emptied/half-written
rem      current pointer and always names the sha the installer actually bundled
rem   4. hardcoded literal fallback - last resort ONLY if both pointer files are
rem      missing (kept in sync with the installer's GW_SHA default)
rem
rem Auth key is BAKED TO DISK (authkey.txt, written by the installer via
rem extract-authkey.ps1) and read at launch - NEVER from an env var: SYSTEM
rem scheduled-task env is stale until reboot and reboot is a hard NO on this fleet.
rem
rem TS_HOSTNAME is set here so the Windows console node name replicates the old
rem koidra-ssh name exactly (Windows node name comes from TS_HOSTNAME) - the
rem console name never churns on the rebrand.

setlocal enabledelayedexpansion

set "DIR=%~dp0"
set "DIR=%DIR:~0,-1%"

rem ---- fast-exit backoff config (mirror of the old supervisor.vbs values) --- rem
set "HEALTHY_SECS=20"
set "BASE_DELAY=5"
set "MAX_DELAY=60"

rem ---- args (channel + port; both channels :22) --------------------------- rem
set "CHAN=%~1"
set "PORT=%~2"
if "%CHAN%"=="" set "CHAN=primary"
if "%PORT%"=="" set "PORT=22"

rem ---- resolve the binary -------------------------------------------------- rem
rem Order: hardcoded literal (last resort) < installer-baked default pointer <
rem authoritative current pointer < explicit override arg. Delayed expansion
rem (!VAR!) is REQUIRED inside the parenthesized blocks: %VAR% would expand at
rem PARSE time (before set /p runs) and the pointer would be silently ignored.
set "EXE=%DIR%\koidra-gateway-06f9a3a.exe"

if exist "%DIR%\default-koidra-gateway.txt" (
    set /p DEF=<"%DIR%\default-koidra-gateway.txt"
    if not "!DEF!"=="" set "EXE=%DIR%\!DEF!"
)

if exist "%DIR%\current-koidra-gateway.txt" (
    set /p TARGET=<"%DIR%\current-koidra-gateway.txt"
    if not "!TARGET!"=="" set "EXE=%DIR%\!TARGET!"
)

if not "%~3"=="" set "EXE=%DIR%\%~3"

rem ---- console node name (stable across the rebrand) ---------------------- rem
set "TS_HOSTNAME=%COMPUTERNAME%-%CHAN%"

set "FASTFAILS=0"

rem ======================== SUPERVISE LOOP ================================= rem
:loop
    rem ---- auth key guard (H2): never launch `-k <empty>` (arg-parse crash). rem
    rem run.sh aborts loudly on an unset/empty AUTHKEY; the Windows loop instead
    rem diagnoses + backs off (so a key staged later self-heals) and NEVER dips
    rem into the crash-loop. Handles missing, empty, and whitespace-only files.
    set "AUTHKEY="
    if exist "%DIR%\authkey.txt" set /p AUTHKEY=<"%DIR%\authkey.txt"
    set "AKCHK=!AUTHKEY: =!"
    if not defined AKCHK (
        >>"%DIR%\koidra-diag.txt" echo [!DATE! !TIME!] run-node2.cmd %CHAN%: authkey.txt missing/empty/whitespace - NOT launching (would crash on bare -k); backing off %MAX_DELAY%s
        ping -n 61 127.0.0.1 >nul 2>&1
        goto loop
    )

    rem ---- start timer (seconds-since-midnight) -------------------------- rem
    rem `100<field> %% 100` yields the field's value for BOTH 1- and 2-digit fields
    rem (e.g. "9"->1009%100=9, "09"->10009%100=9, "23"->10023%100=23) and never
    rem trips set /a's octal trap on 08/09. Robust to non-zero-padded hours.
    set "T=!TIME: =0!"
    for /f "tokens=1-3 delims=:.," %%a in ("!T!") do set /a "START=(((100%%a %% 100)*60)+(100%%b %% 100))*60+(100%%c %% 100)"

    rem ---- launch (foreground; the loop relaunches on exit) --------------- rem
    if defined KOIDRA_MANIFEST_URL (
        "!EXE!" -c "%DIR%\%CHAN%.json" -k !AUTHKEY! --listen-port %PORT% --install-dir "%DIR%" --manifest-url "%KOIDRA_MANIFEST_URL%"
    ) else (
        "!EXE!" -c "%DIR%\%CHAN%.json" -k !AUTHKEY! --listen-port %PORT% --install-dir "%DIR%"
    )

    rem ---- elapsed + fast-exit backoff ----------------------------------- rem
    set "T=!TIME: =0!"
    for /f "tokens=1-3 delims=:.," %%a in ("!T!") do set /a "END=(((100%%a %% 100)*60)+(100%%b %% 100))*60+(100%%c %% 100)"
    set /a ELAPSED=END-START
    if !ELAPSED! lss 0 set /a ELAPSED+=86400

    if !ELAPSED! lss %HEALTHY_SECS% (
        set /a FASTFAILS+=1
        set /a DELAY=BASE_DELAY*FASTFAILS
        if !DELAY! gtr %MAX_DELAY% set "DELAY=%MAX_DELAY%"
    ) else (
        set "FASTFAILS=0"
        set "DELAY=%BASE_DELAY%"
    )

    >>"%DIR%\koidra-diag.txt" echo [!DATE! !TIME!] run-node2.cmd %CHAN%: exe exited after !ELAPSED!s (fastFails=!FASTFAILS!); relaunch in !DELAY!s
    set /a PINGN=DELAY+1
    ping -n !PINGN! 127.0.0.1 >nul 2>&1
    goto loop

endlocal
