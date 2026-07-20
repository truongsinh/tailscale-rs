# consumer_shim.ps1 — reference consumer-side bridge for the silent-proxy on Windows.
#
# Windows PowerShell (5.1+) has no built-in SOCKS5 client. The simplest way for a script
# to dial out via the silent-proxy is:
#   1. Open `\\.\pipe\koidra-tailnet-proxy` as a FileStream.
#   2. Perform the SOCKS5 handshake (no-auth + CONNECT for the desired tailnet IP:port).
#   3. Pipe HTTP/whatever through the same stream.
#
# This file is a parameterized function (not a standalone script). Dot-source it from
# your session or script:
#
#   . .\consumer_shim.ps1
#   $sock = Open-KoidraSocksConnection -Target '100.115.1.3:22'
#   $sock | Send-KoidraSocksBytes -Data ([Text.Encoding]::ASCII.GetBytes("GET / HTTP/1.0`r`n`r`n"))
#   $bytes = Receive-KoidraSocksBytes -Socket $sock -Count 256
#
# Or use curl.exe (Win10+ ships it), which speaks SOCKS5-over-named-pipe natively:
#
#   curl.exe --proxy "socks5h://\\.\pipe\koidra-tailnet-proxy" http://100.115.1.3:8080/
#
# RECOMMENDATION: prefer curl.exe. This PowerShell shim exists for scripts that must use
# Invoke-WebRequest / Invoke-RestMethod — wrap the named pipe as an http(s) proxy via
# a local TCP forwarder if you need those cmdlets.

$PipeName = '\\.\pipe\koidra-tailnet-proxy'

# SOCKS5 protocol constants (RFC 1928).
Set-Variable -Name SOCKS_VERSION   -Value 0x05 -Option Constant
Set-Variable -Name METHOD_NO_AUTH  -Value 0x00 -Option Constant
Set-Variable -Name CMD_CONNECT     -Value 0x01 -Option Constant
Set-Variable -Name ATYP_IPV4       -Value 0x01 -Option Constant
Set-Variable -Name ATYP_DOMAIN     -Value 0x03 -Option Constant
Set-Variable -Name ATYP_IPV6       -Value 0x04 -Option Constant
Set-Variable -Name REP_SUCCEEDED   -Value 0x00 -Option Constant

function Open-KoidraSocksConnection {
    <#
        .SYNOPSIS
            Open a SOCKS5 connection through the silent-proxy named pipe.
        .PARAMETER Target
            "host:port" where host is a tailnet IPv4 (e.g. 100.115.1.3) or a tailnet
            peer hostname (peer.tail7b277.ts.net). DNS goes through the tailnet's
            peer_by_name, not the Windows resolver.
        .OUTPUTS
            A System.IO.FileStream over the named pipe. Caller owns its lifetime.
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string]$Target,

        [string]$Pipe = $PipeName
    )

    $parts = $Target -split ':'
    if ($parts.Count -ne 2) { throw "Target must be 'host:port'; got '$Target'" }
    $host_, $portStr = $parts[0], $parts[1]
    $port = [UInt16]::Parse($portStr)
    if ($port -eq 0) { throw "Port cannot be 0" }

    # Connect to the named pipe. The silent-proxy's accept loop is already waiting.
    $pipe = New-Object System.IO.Pipes.NamedPipeClientStream(
        '.', $PipeName.Substring('\\.\pipe\'.Length), [System.IO.Pipes.PipeDirection]::InOut,
        [System.IO.Pipes.PipeOptions]::Asynchronous)
    $pipe.Connect(5000)  # 5s timeout

    # --- Greeting (RFC 1928 §3): VER, NMETHODS=1, METHOD=0x00 (no auth) ---
    $greeting = [Byte[]]($SOCKS_VERSION, 1, $METHOD_NO_AUTH)
    $pipe.Write($greeting, 0, $greeting.Length)

    # Read method-select reply (VER, METHOD).
    $sel = New-Object Byte[] 2
    $n = $pipe.Read($sel, 0, 2)
    if ($n -lt 2 -or $sel[0] -ne $SOCKS_VERSION -or $sel[1] -ne $METHOD_NO_AUTH) {
        $pipe.Dispose()
        throw "SOCKS5 greeting rejected (sel=$($sel -join ','))"
    }

    # --- Request (RFC 1928 §4): VER, CMD=CONNECT, RSV=0, ATYP, ADDR, PORT ---
    $req = New-Object System.Collections.Generic.List[Byte]
    $req.Add($SOCKS_VERSION); $req.Add($CMD_CONNECT); $req.Add(0x00)
    $ip = $null
    if ([System.Net.IPAddress]::TryParse($host_, [ref]$ip)) {
        $bytes = $ip.GetAddressBytes()
        if ($bytes.Length -eq 4) {
            $req.Add($ATYP_IPV4)
        } elseif ($bytes.Length -eq 16) {
            $req.Add($ATYP_IPV6)
        } else {
            $pipe.Dispose()
            throw "Unsupported IP address family for '$host_'"
        }
        $req.AddRange($bytes)
    } else {
        # Domain: the silent-proxy resolves via Device::peer_by_name (tailnet peers only).
        $enc = [Text.Encoding]::ASCII
        $nameBytes = $enc.GetBytes($host_)
        if ($nameBytes.Length -gt 255) {
            $pipe.Dispose()
            throw "Hostname too long"
        }
        $req.Add($ATYP_DOMAIN)
        $req.Add([Byte]$nameBytes.Length)
        $req.AddRange($nameBytes)
    }
    $req.Add([Byte](($port -shr 8) -band 0xFF))
    $req.Add([Byte]($port -band 0xFF))
    $pipe.Write($req.ToArray(), 0, $req.Count)

    # Read reply (VER, REP, RSV, ATYP, BND.ADDR, BND.PORT).
    # Minimum reply length: 10 (IPv4 BND). 22 for IPv6.
    $hdr = New-Object Byte[] 4
    $n = $pipe.Read($hdr, 0, 4)
    if ($n -lt 4 -or $hdr[0] -ne $SOCKS_VERSION -or $hdr[1] -ne $REP_SUCCEEDED) {
        $rep = if ($n -ge 2) { $hdr[1] } else { -1 }
        $pipe.Dispose()
        throw "SOCKS5 CONNECT failed (REP=$rep)"
    }
    # Consume BND.ADDR + BND.PORT based on ATYP.
    $addrLen = switch ($hdr[3]) {
        $ATYP_IPV4   { 4 }
        $ATYP_IPV6   { 16 }
        $ATYP_DOMAIN { <# read 1 length byte + that many #>; 0 }  # handled below
        default      { throw "Unknown ATYP $($hdr[3]) in reply" }
    }
    if ($hdr[3] -eq $ATYP_DOMAIN) {
        $lenBuf = New-Object Byte[] 1
        [void]$pipe.Read($lenBuf, 0, 1)
        $addrLen = $lenBuf[0]
    }
    if ($addrLen -gt 0) {
        $addrBuf = New-Object Byte[] $addrLen
        [void]$pipe.Read($addrBuf, 0, $addrLen)
    }
    $portBuf = New-Object Byte[] 2
    [void]$pipe.Read($portBuf, 0, 2)
    # BND is informational only; discard.

    return $pipe
}

function Send-KoidraSocksBytes {
    param(
        [Parameter(Mandatory, ValueFromPipeline)]$Socket,
        [Parameter(Mandatory)][Byte[]]$Data
    )
    begin { $sock = if ($Input) { $Input[0] } else { $null } }
    process { if (-not $sock) { $sock = $_ }; $_.Write($Data, 0, $Data.Length) }
}

function Receive-KoidraSocksBytes {
    param(
        [Parameter(Mandatory)]$Socket,
        [int]$Count = 4096,
        [int]$TimeoutMs = 15000
    )
    $buf = New-Object Byte[] $Count
    $task = $Socket.ReadAsync($buf, 0, $Count, [System.Threading.CancellationToken]::None)
    if (-not $task.Wait($TimeoutMs)) { throw "Read timed out after ${TimeoutMs}ms" }
    $n = $task.Result
    if ($n -le 0) { return @() }
    return $buf[0..($n - 1)]
}

function Close-KoidraSocksConnection {
    param([Parameter(Mandatory)]$Socket)
    $Socket.Dispose()
}
