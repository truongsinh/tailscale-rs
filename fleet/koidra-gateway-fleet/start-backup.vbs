' start-backup.vbs — detached one-shot launcher for the NEW backup channel.
'
' Spawns the per-channel relaunch loop (supervisor.vbs backup 22) DETACHED, then
' exits immediately. Use this to (re)launch a single channel over SSH WITHOUT the
' loop becoming a child of the SSH session — a session-child launch dies when the
' session closes (the 40-min-outage class). Invoke it detached from the SSH side:
'   Start-Process wscript.exe '<newdir>\start-backup.vbs'
'
' It runs the NEW dir's layout (this dir). For the rollback equivalent that
' relaunches the OLD koidra-ssh dir, see start-backup-old.vbs.

Option Explicit

Dim WshShell, fso, scriptDir, wscriptExe
Set WshShell = CreateObject("WScript.Shell")
Set fso = CreateObject("Scripting.FileSystemObject")
scriptDir = fso.GetParentFolderName(WScript.ScriptFullName)
wscriptExe = """" & fso.BuildPath(fso.GetSpecialFolder(1), "wscript.exe") & """"

' 0 = hidden; False = do not wait — the loop is now its own detached process.
WshShell.Run wscriptExe & " """ & scriptDir & "\supervisor.vbs"" backup 22", 0, False
WScript.Quit 0
