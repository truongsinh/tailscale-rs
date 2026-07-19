' start-primary.vbs — detached one-shot launcher for the NEW primary channel.
'
' Spawns the per-channel supervise loop (run-node2.cmd primary 22, which OWNS the
' crash-relaunch loop) DETACHED, then exits immediately. Use this to (re)launch a
' single channel over SSH WITHOUT the loop becoming a child of the SSH session — a
' session-child launch dies when the session closes (the 40-min-outage class).
' Invoke it detached from the SSH side:
'   Start-Process wscript.exe '<newdir>\start-primary.vbs'
'
' It runs the NEW dir's layout (this dir). For the rollback equivalent that
' relaunches the OLD koidra-ssh dir, see start-primary-old.vbs.

Option Explicit

Dim WshShell, fso, scriptDir
Set WshShell = CreateObject("WScript.Shell")
Set fso = CreateObject("Scripting.FileSystemObject")
scriptDir = fso.GetParentFolderName(WScript.ScriptFullName)

' 0 = hidden; False = do not wait — run-node2.cmd is now its own detached,
' self-looping process (single loop owner; no supervisor.vbs loop wrapper).
WshShell.Run "cmd /c """ & scriptDir & "\run-node2.cmd"" primary 22", 0, False
WScript.Quit 0
