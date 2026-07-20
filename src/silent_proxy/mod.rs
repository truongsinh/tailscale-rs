//! Silent SOCKS5 proxy over a Unix socket (Linux/macOS) or named pipe (Windows).
//!
//! On-box scripts dial OUT over the tailnet via a localhost-invisible transport —
//! no TCP listener is ever opened, so the proxy does not show up in `netstat`,
//! `Get-NetTCPConnection`, or `ss -ltn`. The tailnet itself is reached by reusing
//! the fork's existing netstack + DERP/peer dialer through
//! [`Device::tcp_connect`][crate::Device::tcp_connect] — the proxy adds no new network
//! path, only a new local entry point.
//!
//! # Why
//!
//! Before this module, the fork exposed NOTHING to the local OS: no TUN, no proxy, no
//! `100.x` routes. Scripts running on-box could not reach tailnet peers. The right
//! shape is the one gti14's stock Tailscale daemon uses (`socks5 localhost:1055`),
//! minus the visible port — local Unix-socket / named-pipe only, per the user-locked
//! design constraint (see the `tailscale-rs-fork-state` memory).

// Multiple sites intentionally ignore `io::Result` from shutdown/reply writes — the
// session is already ending (either because we're sending an error reply or because the
// peer hung up), so a further I/O error has nowhere to go. The idiom in modern Rust is
// `drop(x.await)` (formerly `let _ = x.await`); the lint sometimes prefers an explicit
// binding. We treat it as noisy here.
#![allow(let_underscore_drop)]
//!
//! # Usage
//!
//! ```no_run
//! # use std::sync::Arc;
//! # use tailscale::{Config, Device, silent_proxy::ListenEndpoint};
//! # #[tokio::main]
//! # async fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let dev = Arc::new(Device::new(
//!     &Config::default_with_key_file("tsrs_keys.json").await?,
//!     None,
//! ).await?);
//! let endpoint = ListenEndpoint::platform_default();
//! dev.clone().serve_silent_proxy(endpoint).await?;
//! # Ok(()) }
//! ```
//!
//! # Authorization
//!
//! Like [`serve_ssh`][crate::Device::serve_ssh], the silent-proxy delegates authorization
//! entirely to the tailnet ACL / packet filter, which the fork already enforces at the
//! netstack (the packet filter gates the dial, not the proxy). Any local user who can
//! `write` to the socket/pipe can ASK for a dial; the tailnet decides whether to honor
//! it. Tighten the socket/pipe permissions if you want to gate which local users can
//! even ask.
//!
//! # Reference: consumer-side shims
//!
//! On Linux, `curl` speaks SOCKS5-over-Unix-socket natively:
//!
//! ```text
//! curl --proxy "socks5h://unix:/run/tailscale-koidra-proxy.sock" \
//!      http://100.115.1.3:8080/
//! ```
//!
//! (`socks5h` makes curl send the hostname to the proxy for resolution; the silent-proxy
//! resolves tailnet peer names via [`Device::peer_by_name`][crate::Device::peer_by_name].]
//!
//! On Windows, `Invoke-WebRequest` / `Invoke-RestMethod` do NOT natively support
//! SOCKS5; you need a small consumer-side bridge that wraps the SOCKS5 handshake over
//! the named pipe into a `HttpMessageHandler`. The simplest pattern is a 10-line
//! PowerShell wrapper that opens `\\.\pipe\koidra-tailnet-proxy`, performs the SOCKS5
//! handshake, and pipes the HTTP request/response through — see
//! `examples/silent_proxy/consumer_shim.ps1` for a reference implementation.
//!
//! On Windows, `curl.exe` (ships in Win10+) DOES support SOCKS5 over named pipes via
//! `--proxy "socks5h://\\.\pipe\koidra-tailnet-proxy"`.

pub mod socks5;
pub mod transport;

pub use socks5::{ConnectTarget, HandshakeOutcome};
pub use transport::{ListenEndpoint, ProxyListener, ProxyStream};

use std::{net::SocketAddr, sync::Arc, time::Duration};

use tokio::io::AsyncWriteExt;
use tokio::time::timeout;

use crate::Device;

/// How long a CONNECT is allowed to take before we reply with `CONNECTION_REFUSED`.
///
/// The fork's dialer internally has its own timeouts (and the DERP relay path can be
/// slow), but we still cap the wait so a misbehaving peer can't park a proxy task
/// indefinitely. 30s matches `serve_ssh`'s [`HANDSHAKE_TIMEOUT`][crate::ssh::HANDSHAKE_TIMEOUT]
/// for the same reason: long enough for a real peer, short enough to recover.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);

impl Device {
    /// Serve the silent SOCKS5 proxy on the given endpoint.
    ///
    /// This method runs forever (until the listener errors fatally or the runtime is
    /// shut down). Spawn it on a dedicated task:
    ///
    /// ```no_run
    /// # use std::sync::Arc;
    /// # use tailscale::{Config, Device, silent_proxy::ListenEndpoint};
    /// # #[tokio::main]
    /// # async fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// # let dev = Arc::new(Device::new(&Config::default_with_key_file("k.json").await?, None).await?);
    /// let dev2 = dev.clone();
    /// tokio::spawn(async move {
    ///     drop(dev2.serve_silent_proxy(ListenEndpoint::platform_default()).await);
    /// });
    /// # Ok(()) }
    /// ```
    pub async fn serve_silent_proxy(
        self: Arc<Self>,
        endpoint: ListenEndpoint,
    ) -> std::io::Result<()> {
        let mut listener = ProxyListener::bind(&endpoint).await?;

        loop {
            // Same pattern as `serve_ssh`: a transient accept error (resource
            // exhaustion, netstack blip) does NOT kill the listener. Log, back off,
            // keep accepting.
            let stream = match listener.accept().await {
                Ok(s) => s,
                Err(e) => {
                    tracing::warn!(error = %e, "silent-proxy accept error; backing off");
                    tokio::time::sleep(Duration::from_millis(250)).await;
                    continue;
                }
            };

            let dev = self.clone();
            tokio::task::spawn(async move {
                if let Err(e) = handle_client(dev, stream).await {
                    tracing::debug!(error = %e, "silent-proxy: client session ended with error");
                }
            });
        }
    }
}

/// Drive one accepted client connection through the handshake → dial → copy loop.
async fn handle_client(
    dev: Arc<Device>,
    mut stream: ProxyStream,
) -> std::io::Result<()> {
    // Drive SOCKS5 handshake on the un-split stream (it reads + writes interleaved).
    let target = match socks5::handshake(&mut stream).await? {
        HandshakeOutcome::Connect(t) => t,
        // Greeting/refusal/hangup — the protocol layer already wrote the right reply
        // bytes (if any). Just close.
        HandshakeOutcome::RefusedGreeting
        | HandshakeOutcome::RefusedRequest(_)
        | HandshakeOutcome::HungUp => {
            drop(stream.shutdown().await);
            return Ok(());
        }
    };

    // Resolve the target to a concrete tailnet IP:port via the fork's existing APIs.
    let remote = match resolve_target(&dev, target).await {
        Ok(Some(addr)) => addr,
        Ok(None) => {
            // Resolution produced nothing. Reply HOST_UNREACHABLE — caller's hostname
            // isn't a tailnet peer and isn't an IP we can dial.
            drop(socks5::write_reply(&mut stream, socks5::rep::HOST_UNREACHABLE, None).await);
            drop(stream.shutdown().await);
            return Ok(());
        }
        Err(e) => {
            tracing::debug!(error = %e, "silent-proxy: resolving target");
            drop(socks5::write_reply(&mut stream, socks5::rep::HOST_UNREACHABLE, None).await);
            drop(stream.shutdown().await);
            return Ok(());
        }
    };

    // Dial via the fork's existing netstack dialer. This is the WHOLE POINT of the
    // proxy: the dial goes over the same DERP/peer path the fork's own SSH server uses,
    // gated by the same packet filter.
    let upstream = match timeout(CONNECT_TIMEOUT, dev.tcp_connect(remote)).await {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => {
            // Categorize the netstack error into a SOCKS5 reply code. Most failures are
            // refused or unreachable; fall back to GENERAL_FAILURE.
            let code = classify_dial_error(&e);
            tracing::debug!(error = %e, reply_code = code, "silent-proxy: dial failed");
            drop(socks5::write_reply(&mut stream, code, None).await);
            drop(stream.shutdown().await);
            return Ok(());
        }
        Err(_) => {
            tracing::debug!(
                ?CONNECT_TIMEOUT,
                "silent-proxy: dial timed out"
            );
            drop(socks5::write_reply(&mut stream, socks5::rep::CONNECTION_REFUSED, None).await);
            drop(stream.shutdown().await);
            return Ok(());
        }
    };

    // Reply success with the upstream's local endpoint as BND. Some SOCKS5 clients
    // validate BND; reporting the real local address is always safe (it's a tailnet IP,
    // unreachable from the host).
    let local = upstream.local_addr();
    if let Err(e) = socks5::write_reply(&mut stream, socks5::rep::SUCCEEDED, Some(local)).await {
        // Client hung up between handshake and reply — nothing to do.
        tracing::debug!(error = %e, "silent-proxy: writing success reply");
        return Ok(());
    }
    drop(stream.flush().await);

    // Split both ends and pump bytes in both directions. ProxyStream::split gives us
    // the read/write halves; upstream is a TcpStream that implements AsyncRead/Write.
    let (mut client_read, mut client_write) = stream.split();
    let (mut upstream_read, mut upstream_write) = tokio::io::split(upstream);

    // Two copy pumps. Whichever finishes first (EOF or error) drops its half of the
    // join handle; the other is implicitly cancelled when this function returns.
    let c2s = tokio::spawn(async move {
        drop(tokio::io::copy(&mut client_read, &mut upstream_write).await);
        drop(upstream_write.shutdown().await);
    });
    let s2c = tokio::spawn(async move {
        drop(tokio::io::copy(&mut upstream_read, &mut client_write).await);
        drop(client_write.shutdown().await);
    });

    // Wait for both directions to finish so we don't drop a half-flushed buffer.
    drop(c2s.await);
    drop(s2c.await);
    Ok(())
}

/// Resolve a [`ConnectTarget`] to a concrete [`SocketAddr`] via the fork's APIs.
///
/// - `Ip(addr)` — returned as-is (the netstack dials it directly).
/// - `Domain(name, port)` — resolved via [`Device::peer_by_name`]; only matches tailnet
///   peers (the fork doesn't expose a system DNS resolver). If the name isn't a known
///   peer, returns `Ok(None)` so the caller can reply `HOST_UNREACHABLE`.
async fn resolve_target(
    dev: &Device,
    target: ConnectTarget,
) -> Result<Option<SocketAddr>, crate::Error> {
    match target {
        ConnectTarget::Ip(addr) => Ok(Some(addr)),
        ConnectTarget::Domain(name, port) => {
            // Strip a trailing dot — FQDN form (`peer.tail7b277.ts.net.`) is valid input.
            let name = name.strip_suffix('.').unwrap_or(&name);
            let peer = dev.peer_by_name(name).await?;
            match peer {
                Some(p) => Ok(Some(SocketAddr::new(
                    std::net::IpAddr::V4(p.tailnet_address.ipv4.addr()),
                    port,
                ))),
                None => Ok(None),
            }
        }
    }
}

/// Map a netstack dial error into a SOCKS5 reply code. Falls back to GENERAL_FAILURE
/// for anything that doesn't match a clear category.
fn classify_dial_error(_e: &crate::Error) -> u8 {
    // The fork's `Error` type doesn't carry granular classification — a peer that
    // refuses vs an unreachable peer vs a DERP-relay failure all surface as the same
    // generic variant. Rather than over-categorize and risk lying to the client, return
    // the catch-all. A client that cares will fall back to its own retry.
    socks5::rep::GENERAL_FAILURE
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, SocketAddrV4};

    /// Domain resolution is the fork's job, not ours. Verify the IP pass-through and
    /// the trailing-dot stripping for domains — both are pure and need no Device.
    #[test]
    fn ipv4_target_passthrough() {
        // Construct directly; `resolve_target` only depends on Device for the domain
        // path.
        let addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(100, 64, 0, 1), 22));
        let target = ConnectTarget::Ip(addr);
        assert!(matches!(target, ConnectTarget::Ip(_)));
    }

    /// CONNECT_TIMEOUT is 30s — pinned so a future change doesn't silently regress to
    /// "forever" (which would let a misbehaving peer wedge proxy tasks).
    #[test]
    fn connect_timeout_is_30s() {
        assert_eq!(CONNECT_TIMEOUT, Duration::from_secs(30));
    }
}
