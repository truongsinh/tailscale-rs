' start-backup-old.vbs — ROLLBACK: detached relaunch of the OLD dir's backup channel.
'
' When the new backup channel fails the coordinator's external validation gate,
' this rolls it back with ONE detached command (no SSH-session child). It reads
' old-install-dir.txt (written beside the new launcher by the installer at stage
' time) to locate the old koidra-ssh dir, then detached-launches that dir's
' backup channel loop.
'
' NOTE (non-admin path only). ADMIN boxes roll back via the intact old task:
'     schtasks /run /tn "KoidraSSH-backup"
' (the old KoidraSSH-* tasks are LEFT INTACT until /FINALIZE — see README).
'
' CAVEAT: the old dir's supervisor.vbs contract varies per box (some launch ONE
' channel per invocation, some launch BOTH). This prefers the old per-channel
' run-node2.cmd where present to avoid double-launching the sibling; verify the
' rolled-back channel externally after running. See README "Rollback".

Option Explicit

Dim WshShell, fso, scriptDir, oldDir, ts, wscriptExe, cmd
Set WshShell = CreateObject("WScript.Shell")
Set fso = CreateObject("Scripting.FileSystemObject")
scriptDir = fso.GetParentFolderName(WScript.ScriptFullName)
wscriptExe = """" & fso.BuildPath(fso.GetSpecialFolder(1), "wscript.exe") & """"

oldDir = ""
If fso.FileExists(scriptDir & "\old-install-dir.txt") Then
    Set ts = fso.OpenTextFile(scriptDir & "\old-install-dir.txt", 1)
    If Not ts.AtEndOfStream Then oldDir = Trim(ts.ReadLine)
    ts.Close
End If
If oldDir = "" Or Not fso.FolderExists(oldDir) Then
    WScript.StdErr.WriteLine "ROLLBACK: cannot locate old koidra-ssh dir (old-install-dir.txt missing/invalid)"
    WScript.Quit 2
End If

' Prefer the old per-channel run-node2.cmd (single channel) to avoid double-launch;
' fall back to the old supervisor.vbs single-channel invocation, then bare run-node.cmd.
If fso.FileExists(oldDir & "\run-node2.cmd") Then
    cmd = "cmd /c """ & oldDir & "\run-node2.cmd"" backup 22"
ElseIf fso.FileExists(oldDir & "\supervisor.vbs") Then
    cmd = wscriptExe & " """ & oldDir & "\supervisor.vbs"" backup 22"
ElseIf fso.FileExists(oldDir & "\run-node.cmd") Then
    cmd = "cmd /c """ & oldDir & "\run-node.cmd"""
Else
    WScript.StdErr.WriteLine "ROLLBACK: no launcher (run-node2.cmd / supervisor.vbs / run-node.cmd) in " & oldDir
    WScript.Quit 3
End If

' 0 = hidden; False = do not wait — detached from the caller (SSH-safe).
WshShell.Run cmd, 0, False
WScript.Quit 0
