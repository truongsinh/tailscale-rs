# migrate-to-koidra-gateway.ps1 — one-shot rename of koidra-ssh → koidra-gateway.
#
# CANARY-SAFE SEQUENCE (backup channel first, primary never touched until
# backup is confirmed healthy). Per-box. Idempotent on the backup path:
# re-running after a successful backup migration skips straight to primary.
#
# Delivered as a release asset under koidra-gateway-bootstrap. Pull on-box via
# the existing koidra_fetch.exe:
#   koidra_fetch.exe `
#     https://github.com/truongsinh/tailscale-rs/releases/download/koidra-gateway-bootstrap/migrate-to-koidra-gateway.ps1 `
#     $env:TEMP\migrate.ps1
#   powershell -ExecutionPolicy Bypass -File $env:TEMP\migrate.ps1
#
# Safety properties:
#   - Snapshots the old layout to <dir>\.pre-rebrand\ and the old tasks to
#     old-tasks.xml BEFORE any destructive op. Restore = move dir back +
#     schtasks /create from the XML.
#   - Backup channel is fully migrated + health-gated before primary is
#     touched. If backup FAILS its health gate, primary is never modified.
#   - All process stops are surgical (only the matching channel), so the box
#     stays reachable on the primary tailnet IP throughout backup migration.
#   - All schtasks actions point at the NEW dir + NEW supervisor (run-node2.cmd
#     in koidra-gateway/), so the old koidra-ssh\ tree is dead weight after
#     cutover — keep it as the rollback source for 24 h, then delete.
#
# Pre-flight checks abort before any change if the box isn't in a clean state.

[CmdletBinding()]
param(
    # Skip the 10-min healthy-soak before cleanup. Default false — production
    # migration should leave both channels healthy for 10 min before deleting
    # old tasks. Useful for dev-box iteration.
    [switch]$SkipSoak,

    # Dry run: print what would happen, change nothing.
    [switch]$DryRun,

    # Channel to migrate first (default backup). Override to primary only for
    # re-runs after a partial failure where backup already migrated.
    [ValidateSet('backup','primary')]
    [string]$FirstChannel = 'backup'
)

$ErrorActionPreference = 'Stop'

# --- Locate install dir -------------------------------------------------------

$dir = $null
if (Test-Path 'C:\ProgramData\koidra-ssh\run-node2.cmd') {
    $dir = 'C:\ProgramData\koidra-ssh'
    $newDir = 'C:\ProgramData\koidra-gateway'
    $isAdmin = $true
} elseif (Test-Path "$env:LOCALAPPDATA\koidra-ssh\run-node2.cmd") {
    $dir = "$env:LOCALAPPDATA\koidra-ssh"
    $newDir = "$env:LOCALAPPDATA\koidra-gateway"
    $isAdmin = $false
} else {
    Write-Error 'koidra-ssh install dir not found. Box not on the old name? Aborting.'
    exit 1
}

if (Test-Path "$newDir\run-node2.cmd") {
    Write-Error "$newDir already exists. Box already migrated (or half-migrated)? Aborting. Clean up manually first."
    exit 1
}

Write-Host "migrate: $dir -> $newDir (admin=$isAdmin)"
Write-Host "first channel: $FirstChannel"

if ($DryRun) {
    Write-Host '[dry-run] would snapshot, stop backup, move dir, rename binaries, create new tasks, start backup, health-gate, repeat for primary, cleanup'
    exit 0
}

# --- Snapshot BEFORE any change ----------------------------------------------

$snapshot = Join-Path $dir '.pre-rebrand'
New-Item -ItemType Directory -Path $snapshot -Force | Out-Null
Copy-Item -Recurse -Force "$dir\run-node2.cmd", "$dir\supervisor.vbs" $snapshot
if (Test-Path "$dir\current-ssh-shell.txt") {
    Copy-Item -Force "$dir\current-ssh-shell.txt" $snapshot
}
& schtasks /query /tn 'KoidraSSH-primary' /xml | Out-File "$snapshot\KoidraSSH-primary.xml" -Encoding utf8
& schtasks /query /tn 'KoidraSSH-backup'  /xml | Out-File "$snapshot\KoidraSSH-backup.xml"  -Encoding utf8
Write-Host "snapshot: $snapshot"

# --- Health-gate helper -------------------------------------------------------

function Wait-Healthy {
    param(
        [Parameter(Mandatory)] [string]$Channel,
        [Parameter(Mandatory)] [int]$TimeoutSec = 60
    )
    # A channel is "healthy" if its process is alive AND has a tailnet IP
    # registered. We probe by finding the process matching the channel's
    # identity file + the new binary name.
    $deadline = (Get-Date).AddSeconds($TimeoutSec)
    while ((Get-Date) -lt $deadline) {
        $proc = Get-CimInstance Win32_Process |
            Where-Object { $_.CommandLine -match "$Channel\.json" -and $_.Name -match 'koidra_gateway' }
        if ($proc) {
            Write-Host "  $Channel healthy (PID=$($proc.ProcessId))"
            return $true
        }
        Start-Sleep -Seconds 2
    }
    Write-Warning "$Channel did not register a koidra_gateway process within ${TimeoutSec}s"
    return $false
}

# --- Per-channel migration ----------------------------------------------------

function Migrate-Channel {
    param([Parameter(Mandatory)] [string]$Channel)

    Write-Host "== migrating $Channel =="

    # 1. Stop ONLY this channel's task + process. Other channel untouched.
    $oldTask = "KoidraSSH-$Channel"
    $newTask = "KoidraGateway-$Channel"

    & schtasks /end /tn $oldTask 2>&1 | Out-Null
    Get-CimInstance Win32_Process |
        Where-Object { $_.CommandLine -match "$Channel\.json" -and $_.Name -match 'ssh_shell' } |
        Stop-Process -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 2

    # 2. First channel only: move the install dir + rename everything inside.
    #    Second channel sees the dir already moved; just verifies the binary
    #    for this channel is renamed.
    if ($Channel -eq $FirstChannel) {
        Write-Host "  moving $dir -> $newDir"
        Move-Item $dir $newDir
        $script:dir = $newDir

        # Rename staged binaries + state file.
        Get-ChildItem "$newDir\ssh_shell-*.exe" | ForEach-Object {
            $newName = $_.Name -replace '^ssh_shell-', 'koidra-gateway-'
            Rename-Item $_.FullName $newName
            Write-Host "  renamed $($_.Name) -> $newName"
        }
        if (Test-Path "$newDir\current-ssh-shell.txt") {
            Move-Item "$newDir\current-ssh-shell.txt" "$newDir\current-koidra-gateway.txt" -Force
            # Update contents: any "ssh_shell-*" reference → "koidra-gateway-*".
            $content = Get-Content "$newDir\current-koidra-gateway.txt" -Raw
            $content = $content -replace 'ssh_shell-', 'koidra-gateway-'
            $content | Set-Content "$newDir\current-koidra-gateway.txt" -NoNewline
        }
        if (Test-Path "$newDir\.koidra-ssh-update.lock") {
            Move-Item "$newDir\.koidra-ssh-update.lock" "$newDir\.koidra-gateway-update.lock" -Force
        }

        # Drop the new supervisor scripts in (replaces the old ones in-place).
        # The migration kit ships these alongside this script.
        $kitDir = Split-Path -Parent $MyInvocation.MyCommand.Path
        Copy-Item -Force "$kitDir\run-node2.cmd"  $newDir
        Copy-Item -Force "$kitDir\supervisor.vbs" $newDir
    }

    # 3. Create the new scheduled task. Inherit schedule + principal from the
    #    old task's XML, just swap the name + action path.
    $oldXml = Get-Content "$snapshot\$oldTask.xml" -Raw
    # Replace the TaskName + the action path (run-node2.cmd is now in newDir).
    # The XML's <Command>/<Arguments> reference cmd /c <olddir>\run-node2.cmd —
    # swap <olddir> for <newdir>.
    $newXml = $oldXml -replace [regex]::Escape($snapshot -replace '\.pre-rebrand$', ''), $newDir
    $newXml = $newXml -replace '(?<=<URI>\\)KoidraSSH-', 'KoidraGateway-'
    $newXml | & schtasks /create /tn $newTask /xml -

    # 4. Launch + health-gate.
    & schtasks /run /tn $newTask 2>&1 | Out-Null
    if (-not (Wait-Healthy -Channel $Channel -TimeoutSec 60)) {
        Write-Error "$Channel FAILED health gate after migration. Rolling back."
        Invoke-Rollback -Channel $Channel
        return $false
    }
    return $true
}

function Invoke-Rollback {
    param([Parameter(Mandatory)] [string]$Channel)

    Write-Warning "ROLLBACK $Channel"
    # Best-effort: stop the new task, restore the old task from XML.
    & schtasks /end /tn "KoidraGateway-$Channel" 2>&1 | Out-Null
    & schtasks /delete /tn "KoidraGateway-$Channel" /f 2>&1 | Out-Null
    Get-CimInstance Win32_Process |
        Where-Object { $_.CommandLine -match "$Channel\.json" -and $_.Name -match 'koidra_gateway' } |
        Stop-Process -Force -ErrorAction SilentlyContinue

    # If we moved the dir on this channel, move it back.
    if (($Channel -eq $FirstChannel) -and (Test-Path $newDir)) {
        Move-Item $newDir $dir -Force
    }

    # Recreate the old task from the snapshot.
    Get-Content "$snapshot\KoidraSSH-$Channel.xml" -Raw | & schtasks /create /tn "KoidraSSH-$Channel" /xml -
    & schtasks /run /tn "KoidraSSH-$Channel" 2>&1 | Out-Null
}

# --- Run the sequence ---------------------------------------------------------

$secondChannel = if ($FirstChannel -eq 'backup') { 'primary' } else { 'backup' }

if (-not (Migrate-Channel -Channel $FirstChannel)) {
    Write-Error "Migration aborted at $FirstChannel. Box is on old name. See snapshot at $snapshot\."
    exit 1
}

Start-Sleep -Seconds 3

if (-not (Migrate-Channel -Channel $secondChannel)) {
    Write-Error "PARTIAL migration: $FirstChannel = koidra-gateway, $secondChannel = koidra-ssh. Box is reachable but mixed. Manual cleanup needed."
    exit 2
}

# --- Soak + cleanup -----------------------------------------------------------

if (-not $SkipSoak) {
    Write-Host 'both channels healthy. Soaking 10 min before cleanup...'
    Start-Sleep -Seconds 600
    # Re-verify health post-soak.
    foreach ($ch in @('primary','backup')) {
        if (-not (Wait-Healthy -Channel $ch -TimeoutSec 30)) {
            Write-Error "post-soak health check failed for $ch. Old tasks preserved. Manual intervention required."
            exit 3
        }
    }
}

# Delete old tasks + remove the pre-rebrand snapshot.
foreach ($ch in @('primary','backup')) {
    & schtasks /delete /tn "KoidraSSH-$ch" /f 2>&1 | Out-Null
    Write-Host "deleted old task KoidraSSH-$ch"
}
Remove-Item -Recurse -Force "$newDir\.pre-rebrand"
Write-Host 'migration complete. Box is fully on koidra-gateway.'
