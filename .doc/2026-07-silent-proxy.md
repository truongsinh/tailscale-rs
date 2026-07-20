# 2026-07 · Silent SOCKS5 Proxy (Unix socket / named pipe, no TCP listener)

## Purpose

On-box scripts that need to dial OUT over the tailnet previously had no way to do so:
the fork exposed nothing to the local OS (no TUN, no proxy, no 100.x routes). The
silent-proxy closes that gap with a SOCKS5 listener on a **localhost-invisible
transport** (Unix domain socket on Linux/macOS, named pipe on Windows). No TCP port is
ever opened, so the proxy does not appear in `netstat`, `Get-NetTCPConnection`, or
`ss -ltn`.

The proxy dials tailnet peers via the fork's **existing** netstack + DERP/peer dialer
(`Device::tcp_connect`). Authorization is the tailnet ACL's job, exactly like
`serve_ssh` — the packet filter gates the dial, not the proxy.

## Files

| Path | Role |
|---|---|
| `src/silent_proxy/mod.rs` | `Device::serve_silent_proxy` entry point; accept loop; client session driver (handshake → dial → bidirectional copy). |
| `src/silent_proxy/socks5.rs` | RFC 1928 protocol implementation (pure bytes, no transport). Method-negotiation + CONNECT only; refuses BIND / UDP ASSOCIATE. |
| `src/silent_proxy/transport.rs` | Platform abstraction: `tokio::net::UnixListener` on Unix; `tokio::net::windows::named_pipe::ServerOptions` on Windows. Single `ProxyListener`/`ProxyStream` shape for the SOCKS5 driver. |
| `examples/ssh_shell/main.rs` | `--silent-proxy <path|name>` flag that spawns `serve_silent_proxy` alongside `serve_ssh`. |
| `examples/silent_proxy/consumer_shim.ps1` | Windows PowerShell reference for clients (Invoke-WebRequest has no native SOCKS5; curl.exe does). |

## Usage

### ssh_shell — enable the proxy alongside SSH

```bash
# Linux: socket path
./ssh_shell -c tsrs_keys.json -k <AUTH_KEY> --silent-proxy /run/tailscale-koidra-proxy.sock

# Linux: platform default (== /run/tailscale-koidra-proxy.sock)
./ssh_shell -c tsrs_keys.json -k <AUTH_KEY> --silent-proxy default

# Windows: named pipe name (no \\.\pipe\ prefix)
ssh_shell.exe -c tsrs_keys.json -k <AUTH_KEY> --silent-proxy koidra-tailnet-proxy
```

The env-var equivalent (`KOIDRA_SILENT_PROXY=...`) is read if the flag is omitted.

### Client side — Linux

`curl` speaks SOCKS5-over-Unix-socket natively:

```bash
curl --proxy "socks5h://unix:/run/tailscale-koidra-proxy.sock" \
     http://100.115.1.3:8080/healthz
```

`socks5h` (with the `h`) makes curl send the hostname to the proxy for resolution. The
proxy resolves tailnet peer names via `Device::peer_by_name`, so FQDNs like
`peer.tail7b277.ts.net` work:

```bash
curl --proxy "socks5h://unix:/run/tailscale-koidra-proxy.sock" \
     http://koidra-ai.tail7b277.ts.net:8080/healthz
```

For `ssh(1)`, use `ProxyCommand` with a small helper that drives SOCKS5 over the Unix
socket (`socat` 1.7.4+ supports `SOCKS5` over `UNIX-CONNECT`):

```bash
ssh -o ProxyCommand='socat - SOCKS5:unix:/run/tailscale-koidra-proxy.sock:%h:%p' \
    user@100.115.1.3
```

### Client side — Windows

`curl.exe` (shipped in Win10+) speaks SOCKS5 over named pipes natively:

```powershell
curl.exe --proxy "socks5h://\\.\pipe\koidra-tailnet-proxy" http://100.115.1.3:8080/healthz
```

For `Invoke-WebRequest` / `Invoke-RestMethod`, see
`examples/silent_proxy/consumer_shim.ps1` — there's no native SOCKS5 in PS 5.1, so the
shim wraps the named pipe into a usable client stream.

## Security model

The proxy inherits the fork's cardinal rule: **authorization is delegated entirely to
the tailnet ACL / packet filter** (see `tailscale-rs-fork-state` memory). The netstack
already gates `tcp_connect` against `map_response.packet_filter` — the proxy adds no
new network path, only a new local entry point.

Local-side: the Unix socket is `chmod 0666` so any local user can ask for a dial. To
gate which local users can even ask, set tighter permissions on the parent directory
(e.g. `/run/tailscale-*` with mode `0750` owned by a group). The named-pipe equivalent
on Windows is ACLs on the pipe object — the current implementation uses default
security; tighten with `ServerOptions::create_with_security_attributes` if a real
requirement emerges.

## Design constraints honored

- **No TCP listener, not even loopback.** Hard user constraint. The transport layer
  has no TCP code path on either platform.
- **Reuse the fork's dialer.** `handle_client` calls `dev.tcp_connect(remote)` — the
  same path `serve_ssh` uses for its own peer connections. No new network code.
- **No system DNS.** Domain names are resolved via `Device::peer_by_name` (tailnet
  peers only). The system resolver is never consulted.

## Testing

15 unit tests in `src/silent_proxy/socks5.rs` cover the protocol surface using
in-memory `tokio::io::duplex` pairs:
- happy paths: IPv4, IPv6, domain-name CONNECTs
- refusals: wrong version, no-acceptable-method, zero-methods, BIND, UDP, unknown ATYP
- edge cases: client hangup before handshake (the port-scanner probe), client hangup
  after greeting, zero methods, malformed UTF-8 in domain name

Integration test (dialing a real tailnet peer) requires a live node, so it's a manual
canary, not an automated test. Recipe: start `ssh_shell --silent-proxy <path>` on a
test node, then `curl --proxy "socks5h://unix:<path>" http://<peer-IP>:<port>/` from
the same box.

## Cross-platform status

| Target | Status |
|---|---|
| Linux musl-static | ✅ builds, ✅ 15 tests pass |
| Windows x86_64-pc-windows-gnu | ✅ builds (cross-checked in CI; named-pipe accept path exercised at compile time) |
| Windows x86_64-win7-windows-gnu | ⏳ untested at this stage — same source as the regular Windows build, expected to work (named pipes are Win2K+). |
| macOS | ⏳ untested — same source as Linux (Unix socket). |

## Out of scope

- UDP ASSOCIATE. SOCKS5-over-UDP is a separate code path with no compelling on-box
  use case today (all current scripts are TCP/HTTP).
- BIND. Same — the proxy is outbound-only by design.
- Authentication. Method negotiation accepts only `0x00` (no auth); the tailnet ACL
  is the entire authorization boundary.
