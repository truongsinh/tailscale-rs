' supervisor.vbs - koidra-gateway non-admin boot launcher (Windows).
'
' Used on boxes that can't host SYSTEM scheduled tasks (non-admin install under
' %LOCALAPPDATA%\koidra-gateway\). The Startup group launches this via
' KoidraGateway.lnk.
'
' PURE LAUNCHER - it does NOT own a relaunch loop (H1 fix). run-node2.cmd is now
' the SINGLE loop owner (crash-relaunch + fast-exit backoff live there), so BOTH
' the admin and non-admin layouts recover from a process exit the same way and
' there is exactly ONE loop per channel (no double-loop). This file only SPAWNS
' the loop(s) detached, then exits.
'
' TWO MODES in one file:
'
'   * MASTER (no args): spawns ONE detached `cmd /c run-node2.cmd <chan> 22` per
'     channel (primary + backup), once each, then exits. Each run-node2.cmd is its
'     OWN detached process running its OWN loop, so a crash-loop of one channel can
'     NEVER take the other down (no shared fate). This restores the old
'     KoidraSSH.lnk "one supervisor brings up BOTH channels" contract.
'
'   * SINGLE (<channel> <port>): spawns ONE detached `cmd /c run-node2.cmd
'     <channel> <port>` and exits. A thin per-channel launch entry point (used by
'     start-*.vbs / rollback fallbacks) - still NO loop here; run-node2.cmd loops.
'
' Ports: BOTH channels on 22 (each channel is its own tailnet IP - no conflict).

Option Explicit

Dim WshShell, fso, scriptDir
Set WshShell = CreateObject("WScript.Shell")
Set fso = CreateObject("Scripting.FileSystemObject")
scriptDir = fso.GetParentFolderName(WScript.ScriptFullName)

' ---- MASTER mode: spawn both channel loops detached, then exit ------------- '
If WScript.Arguments.Count = 0 Then
    ' 0 = hidden window; False = do NOT wait - each run-node2.cmd is an
    ' independent, self-looping process.
    WshShell.Run "cmd /c """ & scriptDir & "\run-node2.cmd"" primary 22", 0, False
    WshShell.Run "cmd /c """ & scriptDir & "\run-node2.cmd"" backup 22", 0, False
    WScript.Quit 0
End If

If WScript.Arguments.Count < 2 Then
    WScript.StdErr.WriteLine "usage: supervisor.vbs                  (master; spawns BOTH channel loops)"
    WScript.StdErr.WriteLine "   or: supervisor.vbs <channel> <port>  (spawns ONE channel loop detached)"
    WScript.Quit 2
End If

' ---- SINGLE mode: spawn one channel loop detached, then exit --------------- '
Dim channel, port
channel = WScript.Arguments(0)
port    = WScript.Arguments(1)
' 0 = hidden; False = do NOT wait - run-node2.cmd owns the loop.
WshShell.Run "cmd /c """ & scriptDir & "\run-node2.cmd"" " & channel & " " & port, 0, False
WScript.Quit 0
