# stop-old-stack.ps1 <oldDir> <isAdmin:0|1> [channel:primary|backup]
#
# Stop the OLD koidra-ssh stack BEFORE the new koidra-gateway stack is started,
# then VERIFY zero matching old processes remain. Because the new channel reuses
# the byte-identical node keyfile, two processes on one keyfile = node-key
# conflict / orphan node (the hanyu lesson). This is the guard against that.
#
# PER-CHANNEL (H3 fix): when <channel> is given, this stops ONLY that channel's
# old task + loop + binary and verifies only that channel is down — so the
# installer can sequence backup-then-primary and NEVER take both channels down at
# once (>=1 channel is up at every instant of the upgrade). When <channel> is
# omitted it falls back to stopping BOTH (legacy behaviour). Channel matching is
# by the config file name in the process command line (`<channel>.json` /
# `node-<channel>.json`) plus the channel token in the loop-host command line.
#
# Steps:
#   1. (admin) `schtasks /end` the old KoidraSSH-* task(s) so they stop respawning.
#   2. Kill the supervise-loop hosts (cmd.exe / wscript.exe) whose command line
#      points at <oldDir> (and, if a channel is given, references that channel).
#   3. Kill the old binary processes (ssh_shell*), channel-filtered if given.
#   4. Poll up to 30s, re-killing, until zero matching ssh_shell* remain.
#
# Exit 0 = matching old stack confirmed down; exit 1 = old processes still present
# after the timeout (installer ABORTS — never start the new stack over a live old
# one, and never proceed to the next channel with this one still up).
#
# MUST stay PowerShell 2.0 / .NET 2.0 safe (Win7):
#   - Get-WmiObject (NOT Get-CimInstance)   for the CommandLine field
#   - Get-Process / Where-Object / Stop-Process   are all PS2.0

$ErrorActionPreference = 'SilentlyContinue'

$oldDir  = $args[0]
$isAdmin = $args[1]
$channel = $args[2]   # optional: 'primary' | 'backup'; empty = both channels

# True if $cmdline belongs to $channel (or always, when no channel was given).
function Match-Channel($cmdline) {
    if ([string]::IsNullOrEmpty($channel)) { return $true }
    if ($cmdline -eq $null) { return $false }
    $c = $cmdline.ToLower()
    if ($c.Contains("$channel.json"))      { return $true }   # -c ...\<channel>.json
    if ($c.Contains("node-$channel.json")) { return $true }   # dev-style keyfile name
    if ($c.Contains(" $channel "))         { return $true }   # ... run-node.cmd <channel> 22
    if ($c.EndsWith(" $channel"))          { return $true }   # ... run-node.cmd <channel>
    return $false
}

# Old binary processes (ssh_shell*), channel-filtered when a channel is given. Use
# WMI (not Get-Process) so the CommandLine is available for the channel match.
function Get-OldBinaries {
    $all = @(Get-WmiObject Win32_Process)
    return @($all | Where-Object { $_.Name -like 'ssh_shell*' -and (Match-Channel $_.CommandLine) })
}

function Kill-OldBinaries {
    foreach ($pr in (Get-OldBinaries)) {
        Stop-Process -Id $pr.ProcessId -Force
    }
}

# 1. End the old scheduled task(s) (admin layout only).
if ($isAdmin -eq '1') {
    if ([string]::IsNullOrEmpty($channel)) {
        & schtasks /end /tn 'KoidraSSH-primary' 2>$null | Out-Null
        & schtasks /end /tn 'KoidraSSH-backup'  2>$null | Out-Null
    } else {
        & schtasks /end /tn "KoidraSSH-$channel" 2>$null | Out-Null
    }
}

# 2. Kill the supervise-loop hosts that reference the old dir (stop the relaunchers).
#    When a channel is given, only kill the loop host that also references it — so
#    a both-channels supervisor is NOT torn down (that would drop the sibling too).
if (-not [string]::IsNullOrEmpty($oldDir)) {
    $needle = $oldDir.ToLower()
    $loops  = Get-WmiObject Win32_Process -Filter "Name='cmd.exe' or Name='wscript.exe'"
    foreach ($p in $loops) {
        if ($p.CommandLine -ne $null) {
            $cl = $p.CommandLine.ToLower()
            if ($cl.Contains($needle) -and (Match-Channel $p.CommandLine)) {
                Stop-Process -Id $p.ProcessId -Force
            }
        }
    }
}

# 3. Kill the old binary processes (channel-filtered if given).
Kill-OldBinaries

# 4. Verify zero matching remain (poll up to ~30s, re-killing stragglers).
$deadline  = (Get-Date).AddSeconds(30)
$remaining = Get-OldBinaries
while ($remaining.Count -gt 0 -and (Get-Date) -lt $deadline) {
    Start-Sleep -Milliseconds 1000
    Kill-OldBinaries
    $remaining = Get-OldBinaries
}

if ($remaining.Count -gt 0) {
    if ([string]::IsNullOrEmpty($channel)) {
        Write-Error "old ssh_shell processes still running after 30s: $($remaining.Count) remain"
    } else {
        Write-Error "old $channel ssh_shell processes still running after 30s: $($remaining.Count) remain (a both-channels supervisor may need a console stop)"
    }
    exit 1
}

exit 0
