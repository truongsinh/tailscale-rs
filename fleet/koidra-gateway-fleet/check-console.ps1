# check-console.ps1
#
# Best-effort guard (H3): refuse to run the installer over the box's OWN koidra
# SSH channel. An over-SSH run kills its own transport mid-op (stop-old-stack
# tears down the ssh_shell* that hosts the session) => the installer dies after
# stopping the old stack and before starting the new one => both-down brick,
# recoverable only by a (banned) reboot. This is the 40-min-outage / SSH-less
# brick class the charter forbids.
#
# It walks the parent-process chain up from THIS process; if any ancestor is an
# `ssh_shell*` binary, the installer was launched under the gateway's own SSH
# session => exit 1 (installer aborts unless /CONSOLE was passed). At a real
# console (Explorer/RDP -> setup.exe -> powershell) there is no ssh_shell
# ancestor => exit 0.
#
# Best-effort only: it cannot detect every remote vector (e.g. a detached task
# spawned from an SSH session), so the README documents console-only regardless.
#
# MUST stay PowerShell 2.0 / .NET 2.0 safe (Win7): Get-WmiObject only.

$ErrorActionPreference = 'SilentlyContinue'

$byId = @{}
foreach ($p in Get-WmiObject Win32_Process) {
    $byId[[int]$p.ProcessId] = $p
}

$cur  = [int]$PID
$hops = 0
while ($cur -gt 0 -and $byId.ContainsKey($cur) -and $hops -lt 64) {
    $p = $byId[$cur]
    if ($p.Name -like 'ssh_shell*') {
        Write-Error "installer launched under an ssh_shell* ancestor (PID $($p.ProcessId), $($p.Name)) - this looks like an over-SSH run on the box's own channel"
        exit 1
    }
    $cur = [int]$p.ParentProcessId
    $hops++
}

exit 0
