# extract-authkey.ps1 <oldDir> <outFile>
#
# Identity-preservation helper for the koidra-gateway upgrade installer.
#
# The auth key is BAKED INTO THE OLD run-node.cmd command line on every live box
# (`-k tskey-auth-...`), NOT in an env var. This parses that token out of the old
# launcher and writes it (no trailing newline, ASCII) to <outFile> so the new
# launcher can read it from disk at launch time. NEVER via machine env — SYSTEM
# scheduled-task env is stale until reboot and reboot is a hard NO on this fleet.
#
# Exit 0 = token written; exit 1 = no token found (installer ABORTS — never ship
# an empty key / silently mint fresh identity).
#
# MUST stay PowerShell 2.0 / .NET 2.0 safe (scherze-win7, redsun-win7):
#   - no Get-Content -Raw (PS3+)      -> [System.IO.File]::ReadAllText
#   - no Get-CimInstance (PS3+)       -> not used here
#   - no ?. / ternary / [ordered]     -> not used here

$ErrorActionPreference = 'Stop'

$oldDir  = $args[0]
$outFile = $args[1]

if ([string]::IsNullOrEmpty($oldDir) -or [string]::IsNullOrEmpty($outFile)) {
    Write-Error 'usage: extract-authkey.ps1 <oldDir> <outFile>'
    exit 1
}

$token = ''
# Old admin boxes bake the key in run-node.cmd; knodt-style swaps use run-node2.cmd.
foreach ($name in @('run-node.cmd', 'run-node2.cmd')) {
    $p = Join-Path $oldDir $name
    if (Test-Path $p) {
        $content = [System.IO.File]::ReadAllText($p)
        # Match a tailscale auth key token up to the next whitespace/quote delimiter.
        $m = [regex]::Match($content, 'tskey-[^\s"'']+')
        if ($m.Success) {
            $token = $m.Value
            break
        }
    }
}

if ($token -eq '') {
    Write-Error "no baked 'tskey-...' auth key found in $oldDir\run-node.cmd or run-node2.cmd"
    exit 1
}

# UTF-8 without BOM (default for this overload) -> `set /p` reads it cleanly.
[System.IO.File]::WriteAllText($outFile, $token)
exit 0
