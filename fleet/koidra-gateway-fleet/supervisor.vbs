' supervisor.vbs — koidra-gateway non-admin boot supervisor (Windows).
'
' Used on boxes that can't host SYSTEM scheduled tasks (non-admin install under
' %LOCALAPPDATA%\koidra-gateway\). The Startup group launches this via
' KoidraGateway.lnk.
'
' TWO MODES in one file:
'
'   * MASTER (no args): spawns ONE detached per-channel relaunch loop for BOTH
'     channels (primary + backup), each on port 22, then exits. Because each
'     channel loop is its OWN detached wscript process, a crash-loop of one
'     channel can NEVER take the other down — no shared fate. This restores the
'     old KoidraSSH.lnk "one supervisor brings up BOTH channels" contract while
'     keeping the two loops independent.
'
'   * LOOP (<channel> <port>): the per-channel relaunch loop. Runs
'     run-node2.cmd, waits for it to exit, relaunches. Fast-exit backoff: if the
'     child dies in < HEALTHY_SECS it is treated as an immediate crash and the
'     relaunch delay backs off progressively (up to MAX_DELAY_MS) instead of
'     tight-spinning invisibly behind a live-looking process tree. A child that
'     survives HEALTHY_SECS resets the backoff to the base delay.
'
' Ports: BOTH channels on 22 (each channel is its own tailnet IP — no conflict).

Option Explicit

Const HEALTHY_SECS  = 20      ' child must survive this long to count as "up"
Const BASE_DELAY_MS = 5000    ' normal relaunch delay
Const MAX_DELAY_MS  = 60000   ' cap for the fast-exit backoff

Dim WshShell, fso, scriptDir, sysDir, wscriptExe
Set WshShell = CreateObject("WScript.Shell")
Set fso = CreateObject("Scripting.FileSystemObject")
scriptDir = fso.GetParentFolderName(WScript.ScriptFullName)
sysDir = fso.GetSpecialFolder(1)                       ' 1 = System32
wscriptExe = """" & fso.BuildPath(sysDir, "wscript.exe") & """"

' ---- MASTER mode: spawn both per-channel loops detached, then exit --------- '
If WScript.Arguments.Count = 0 Then
    Dim selfPath
    selfPath = """" & WScript.ScriptFullName & """"
    ' 0 = hidden window; False = do NOT wait — each loop is an independent process.
    WshShell.Run wscriptExe & " " & selfPath & " primary 22", 0, False
    WshShell.Run wscriptExe & " " & selfPath & " backup 22", 0, False
    WScript.Quit 0
End If

If WScript.Arguments.Count < 2 Then
    WScript.StdErr.WriteLine "usage: supervisor.vbs                 (master; spawns BOTH channels)"
    WScript.StdErr.WriteLine "   or: supervisor.vbs <channel> <port>  (single-channel relaunch loop)"
    WScript.Quit 2
End If

' ---- LOOP mode: one channel, relaunch with fast-exit backoff --------------- '
Dim channel, port, cmd, startT, elapsed, fastFails, delayMs
channel = WScript.Arguments(0)
port    = WScript.Arguments(1)
cmd = "cmd /c """ & scriptDir & "\run-node2.cmd"" " & channel & " " & port

fastFails = 0
Do While True
    startT = Now
    ' 0 = hidden; True = wait for the child to exit before relaunching.
    WshShell.Run cmd, 0, True
    elapsed = DateDiff("s", startT, Now)
    If elapsed < HEALTHY_SECS Then
        fastFails = fastFails + 1
        delayMs = BASE_DELAY_MS * fastFails
        If delayMs > MAX_DELAY_MS Then delayMs = MAX_DELAY_MS
    Else
        fastFails = 0
        delayMs = BASE_DELAY_MS
    End If
    WScript.Sleep delayMs
Loop
