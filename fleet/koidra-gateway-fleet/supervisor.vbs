' supervisor.vbs — 5-second relaunch loop for koidra-gateway (Windows, non-admin path).
'
' Used when the box can't host a SYSTEM scheduled task (non-admin install under
' %LOCALAPPDATA%\koidra-gateway\). The Startup group launches this script via
' KoidraGateway.lnk; it loops for the life of the session, relaunching the
' channel binary every 5 s on clean exit. The same loop in the admin path is
' provided by schtasks's Restart=on-failure equivalent.
'
' Health-gate (rollback-stack pop on fast-exit) is documented in
' .doc/2026-07-fleet-self-update.md §4 but not implemented here — production
' supervisor today is a plain 5 s relauncher. Adding the gate is tracked as
' follow-up work and will live in this file.
'
' Args: <channel> <port>

Option Explicit

Const RELAUNCH_DELAY_MS = 5000
Dim WshShell, fso, scriptDir, channel, port, cmd

If WScript.Arguments.Count < 2 Then
    WScript.StdErr.WriteLine "usage: supervisor.vbs <channel> <port>"
    WScript.Quit 2
End If

channel = WScript.Arguments(0)
port    = WScript.Arguments(1)

Set WshShell = CreateObject("WScript.Shell")
Set fso = CreateObject("Scripting.FileSystemObject")
scriptDir = fso.GetParentFolderName(WScript.ScriptFullName)

cmd = "cmd /c """ & scriptDir & "\run-node2.cmd"" " & channel & " " & port

Do While True
    ' 0 = hidden window (the binary itself is a console app but we don't want
    '     a lingering cmd prompt). True = wait for exit before looping.
    WshShell.Run cmd, 0, True
    WScript.Sleep RELAUNCH_DELAY_MS
Loop
