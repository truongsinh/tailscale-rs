# stop-old-stack.ps1 <oldDir> <isAdmin:0|1>
#
# Stop the OLD koidra-ssh stack completely BEFORE the new koidra-gateway stack is
# started, then VERIFY zero old processes remain. Because the new channel reuses
# the byte-identical node keyfile, two processes on one keyfile = node-key
# conflict / orphan node (the hanyu lesson). This is the guard against that.
#
# Steps:
#   1. (admin) `schtasks /end` the old KoidraSSH-* tasks so they stop respawning.
#   2. Kill the supervise-loop hosts (cmd.exe / wscript.exe) whose command line
#      points at <oldDir> — otherwise they relaunch the binary in ~5s.
#   3. Kill every old binary process (ssh_shell*).
#   4. Poll up to 30s, re-killing, until zero ssh_shell* remain.
#
# Exit 0 = old stack confirmed down; exit 1 = old processes still present after
# the timeout (installer ABORTS — never start the new stack over a live old one).
#
# MUST stay PowerShell 2.0 / .NET 2.0 safe (Win7):
#   - Get-WmiObject (NOT Get-CimInstance)   for the CommandLine field
#   - Get-Process / Where-Object / Stop-Process   are all PS2.0

$ErrorActionPreference = 'SilentlyContinue'

$oldDir  = $args[0]
$isAdmin = $args[1]

function Get-OldBinaries {
    return @(Get-Process | Where-Object { $_.Name -like 'ssh_shell*' })
}

function Kill-OldBinaries {
    foreach ($pr in (Get-OldBinaries)) {
        Stop-Process -Id $pr.Id -Force
    }
}

# 1. End the old scheduled tasks (admin layout only).
if ($isAdmin -eq '1') {
    & schtasks /end /tn 'KoidraSSH-primary' 2>$null | Out-Null
    & schtasks /end /tn 'KoidraSSH-backup'  2>$null | Out-Null
}

# 2. Kill the supervise-loop hosts that reference the old dir (stop the relaunchers).
if (-not [string]::IsNullOrEmpty($oldDir)) {
    $needle = $oldDir.ToLower()
    $loops  = Get-WmiObject Win32_Process -Filter "Name='cmd.exe' or Name='wscript.exe'"
    foreach ($p in $loops) {
        if ($p.CommandLine -ne $null) {
            if ($p.CommandLine.ToLower().Contains($needle)) {
                Stop-Process -Id $p.ProcessId -Force
            }
        }
    }
}

# 3. Kill the old binary processes.
Kill-OldBinaries

# 4. Verify zero remain (poll up to ~30s, re-killing stragglers).
$deadline  = (Get-Date).AddSeconds(30)
$remaining = Get-OldBinaries
while ($remaining.Count -gt 0 -and (Get-Date) -lt $deadline) {
    Start-Sleep -Milliseconds 1000
    Kill-OldBinaries
    $remaining = Get-OldBinaries
}

if ($remaining.Count -gt 0) {
    Write-Error "old ssh_shell processes still running after 30s: $($remaining.Count) remain"
    exit 1
}

exit 0
