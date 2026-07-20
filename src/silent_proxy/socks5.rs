//! Minimal [RFC 1928] SOCKS5 server protocol — pure bytes, no transport.
//!
//! Only the subset the silent-proxy needs:
//! - Method negotiation: server offers **only** "no authentication required" (`0x00`).
//! - Request: only `CONNECT` (`0x01`) is accepted. `BIND` and `UDP ASSOCIATE` are refused.
//! - Address types: IPv4 (`0x01`), Domain name (`0x03`), IPv6 (`0x04`).
//!
//! The state machine is driven by [`handshake`], which reads the client's greeting and
//! request from any `AsyncRead` and writes back the method-select and reply into any
//! `AsyncWrite`. Splitting read/write is intentional: the caller owns the transport
//! (Unix socket on Linux, named pipe on Windows), the protocol owns the bytes.
//!
//! [RFC 1928]: https://www.rfc-editor.org/rfc/rfc1928
//!
//! # Why no `async-trait`
//!
//! Every call site owns its transport concretely (`tokio::net::UnixStream`,
//! `tokio::net::windows::named_pipe::NamedPipeServer`, or a test duplex). Going through
//! `Box<dyn AsyncRead + AsyncWrite + Unpin>` would add an indirection per read/write for
//! no reuse benefit — the proxy task is monomorphic per platform.
//!
//! # Cardinal rule
//!
//! The proxy dials **only** via [`crate::Device::tcp_connect`], which routes through the
//! fork's existing netstack + DERP/peer dialer. No independent socket creation, no DNS
//! to the system resolver, no second network path. This keeps authorization on the
//! tailnet ACL / packet filter, which is the whole security boundary (see the
//! `tailscale-rs-fork-state` memory: "authorization is delegated entirely to the tailnet
//! ACL / packet filter").

// Reply writes that fail because the client already hung up are a routine end-of-session
// path, not an error we act on. The `let _ = …` / `drop(…)` idiom for "intentionally
// ignored Result" is standard; we silence the modern `let_underscore_drop` lint here.
#![allow(let_underscore_drop)]

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// SOCKS5 protocol version, per RFC 1928 §3.
pub const SOCKS_VERSION: u8 = 0x05;

/// Method: no authentication required (RFC 1928 §3, first_METHODS listing).
pub const METHOD_NO_AUTH: u8 = 0x00;

/// Command: CONNECT (RFC 1928 §4).
pub const CMD_CONNECT: u8 = 0x01;
/// Command: BIND (RFC 1928 §4) — refused by this server.
pub const CMD_BIND: u8 = 0x02;
/// Command: UDP ASSOCIATE (RFC 1928 §4) — refused by this server.
pub const CMD_UDP_ASSOCIATE: u8 = 0x03;

/// Address type: IPv4 (RFC 1928 §5).
pub const ATYP_IPV4: u8 = 0x01;
/// Address type: domain name (RFC 1928 §5).
pub const ATYP_DOMAIN: u8 = 0x03;
/// Address type: IPv6 (RFC 1928 §5).
pub const ATYP_IPV6: u8 = 0x04;

/// Reply codes (RFC 1928 §6).
//
// Only the values this module emits are named; the rest are folded into a `u8` when
// received (we never read replies — we are the server).
pub mod rep {
    /// Request succeeded.
    pub const SUCCEEDED: u8 = 0x00;
    /// General failure.
    pub const GENERAL_FAILURE: u8 = 0x01;
    /// Connection not allowed.
    pub const NOT_ALLOWED: u8 = 0x02;
    /// Network unreachable.
    pub const NETWORK_UNREACHABLE: u8 = 0x03;
    /// Host unreachable.
    pub const HOST_UNREACHABLE: u8 = 0x04;
    /// Connection refused by the peer.
    pub const CONNECTION_REFUSED: u8 = 0x05;
    /// Command not supported (returned for BIND / UDP ASSOCIATE).
    pub const COMMAND_NOT_SUPPORTED: u8 = 0x07;
    /// Address type not supported.
    pub const ADDRESS_TYPE_NOT_SUPPORTED: u8 = 0x08;
}

/// Maximum number of method bytes we will read from a client greeting.
///
/// RFC 1928 §3 says `NMETHODS` is one byte (so 1–255 methods). Cap at 255.
pub const MAX_METHODS: usize = 255;

/// Maximum domain length we will accept (RFC 1035 limits names to 253 octets; we are
/// permissive up to the single-byte length field's cap of 255).
pub const MAX_DOMAIN_LEN: usize = 255;

/// A CONNECT target — the only command we honour.
///
/// `Domain` is resolved via [`crate::Device::peer_by_name`] (which only resolves tailnet
/// peer hostnames; nothing else). `Ip` is passed straight to
/// [`crate::Device::tcp_connect`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConnectTarget {
    /// `ATYP=0x01` (IPv4) or `ATYP=0x04` (IPv6) with a port.
    Ip(SocketAddr),
    /// `ATYP=0x03` (domain) — a hostname (tailnet peer name or FQDN) with a port.
    /// The string is already validated UTF-8 and within [`MAX_DOMAIN_LEN`].
    Domain(String, u16),
}

/// Outcome of [`handshake`] — either we have a target to dial, or we've already replied
/// with an error and the caller should close the transport.
#[derive(Debug)]
pub enum HandshakeOutcome {
    /// Client successfully negotiated + issued a CONNECT we accept. Dial this.
    Connect(ConnectTarget),
    /// Client's greeting was malformed or refused (no `0x00` method). A method-select
    /// reply was written (`0xFF` = "no acceptable methods") when applicable. Close.
    RefusedGreeting,
    /// Client sent a request we cannot honour (BIND/UDP, unknown ATYP, malformed
    /// address). A reply with the appropriate `REP` was written. Close.
    RefusedRequest(u8),
    /// Client closed the transport before completing the handshake. Nothing was written.
    /// This is the routine path for a port-scanner's "is anything there?" probe — log
    /// at `trace`, not `warn`.
    HungUp,
}

/// Read the SOCKS5 greeting, then the request, and return the target if it's a CONNECT.
///
/// On error, this function has **already written** the right reply bytes to `stream` —
/// the caller just needs to flush and hang up.
pub async fn handshake<S>(stream: &mut S) -> std::io::Result<HandshakeOutcome>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    // --- Method negotiation (RFC 1928 §3) ---
    let mut hdr = [0u8; 2];
    if read_exact_or_eof(stream, &mut hdr).await?.is_none() {
        return Ok(HandshakeOutcome::HungUp);
    }
    if hdr[0] != SOCKS_VERSION {
        // Wrong protocol version. RFC 1928 doesn't define a reply for this; the only
        // server-side reply byte that doesn't commit to a version is the method-select
        // (`VER, METHOD`). Reply `0xFF` (NO ACCEPTABLE METHODS) to signal we won't talk.
        // If the client doesn't like that, the transport close is its problem.
        drop(stream.write_all(&[SOCKS_VERSION, 0xFF]).await);
        return Ok(HandshakeOutcome::RefusedGreeting);
    }
    let nmethods = usize::from(hdr[1]);
    if nmethods == 0 || nmethods > MAX_METHODS {
        drop(stream.write_all(&[SOCKS_VERSION, 0xFF]).await);
        return Ok(HandshakeOutcome::RefusedGreeting);
    }
    let mut methods = vec![0u8; nmethods];
    if read_exact_or_eof(stream, &mut methods).await?.is_none() {
        return Ok(HandshakeOutcome::HungUp);
    }
    if !methods.contains(&METHOD_NO_AUTH) {
        // Client doesn't offer no-auth — we have no other method to fall back to.
        drop(stream.write_all(&[SOCKS_VERSION, 0xFF]).await);
        return Ok(HandshakeOutcome::RefusedGreeting);
    }
    stream.write_all(&[SOCKS_VERSION, METHOD_NO_AUTH]).await?;

    // --- Request (RFC 1928 §4) ---
    let mut req_hdr = [0u8; 4];
    if read_exact_or_eof(stream, &mut req_hdr).await?.is_none() {
        return Ok(HandshakeOutcome::HungUp);
    }
    // req_hdr = [VER, CMD, RSV, ATYP]
    if req_hdr[0] != SOCKS_VERSION {
        drop(write_reply(stream, rep::GENERAL_FAILURE, None).await);
        return Ok(HandshakeOutcome::RefusedRequest(rep::GENERAL_FAILURE));
    }
    let cmd = req_hdr[1];
    if cmd != CMD_CONNECT {
        // BIND and UDP ASSOCIATE are out of scope for a no-listen-port outbound proxy.
        drop(write_reply(stream, rep::COMMAND_NOT_SUPPORTED, None).await);
        return Ok(HandshakeOutcome::RefusedRequest(rep::COMMAND_NOT_SUPPORTED));
    }
    let atyp = req_hdr[3];

    let target = match atyp {
        ATYP_IPV4 => {
            let mut octets = [0u8; 4];
            if read_exact_or_eof(stream, &mut octets).await?.is_none() {
                return Ok(HandshakeOutcome::HungUp);
            }
            let port = match read_port(stream).await? {
                Some(p) => p,
                None => return Ok(HandshakeOutcome::HungUp),
            };
            ConnectTarget::Ip(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(
                octets[0], octets[1], octets[2], octets[3],
            )), port))
        }
        ATYP_IPV6 => {
            let mut octets = [0u8; 16];
            if read_exact_or_eof(stream, &mut octets).await?.is_none() {
                return Ok(HandshakeOutcome::HungUp);
            }
            let port = match read_port(stream).await? {
                Some(p) => p,
                None => return Ok(HandshakeOutcome::HungUp),
            };
            ConnectTarget::Ip(SocketAddr::new(
                IpAddr::V6(Ipv6Addr::from(octets)),
                port,
            ))
        }
        ATYP_DOMAIN => {
            let mut len_buf = [0u8; 1];
            if read_exact_or_eof(stream, &mut len_buf).await?.is_none() {
                return Ok(HandshakeOutcome::HungUp);
            }
            let dlen = usize::from(len_buf[0]);
            if dlen == 0 || dlen > MAX_DOMAIN_LEN {
                drop(write_reply(stream, rep::GENERAL_FAILURE, None).await);
                return Ok(HandshakeOutcome::RefusedRequest(rep::GENERAL_FAILURE));
            }
            let mut buf = vec![0u8; dlen];
            if read_exact_or_eof(stream, &mut buf).await?.is_none() {
                return Ok(HandshakeOutcome::HungUp);
            }
            let name = match String::from_utf8(buf) {
                Ok(s) => s,
                Err(_) => {
                    drop(write_reply(stream, rep::GENERAL_FAILURE, None).await);
                    return Ok(HandshakeOutcome::RefusedRequest(rep::GENERAL_FAILURE));
                }
            };
            let port = match read_port(stream).await? {
                Some(p) => p,
                None => return Ok(HandshakeOutcome::HungUp),
            };
            ConnectTarget::Domain(name, port)
        }
        _ => {
            drop(write_reply(stream, rep::ADDRESS_TYPE_NOT_SUPPORTED, None).await);
            return Ok(HandshakeOutcome::RefusedRequest(rep::ADDRESS_TYPE_NOT_SUPPORTED));
        }
    };

    Ok(HandshakeOutcome::Connect(target))
}

/// Write a SOCKS5 reply. `bnd` is the bound address of the accepted connection (or `None`
/// to write the unspecified address — the standard "no useful BND to report" sentinel).
pub async fn write_reply<W>(
    writer: &mut W,
    code: u8,
    bnd: Option<SocketAddr>,
) -> std::io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    let mut buf = Vec::with_capacity(22);
    buf.extend_from_slice(&[SOCKS_VERSION, code, 0x00 /* reserved */]);
    match bnd {
        Some(SocketAddr::V4(v4)) => {
            buf.push(ATYP_IPV4);
            buf.extend_from_slice(&v4.ip().octets());
            buf.extend_from_slice(&v4.port().to_be_bytes());
        }
        Some(SocketAddr::V6(v6)) => {
            buf.push(ATYP_IPV6);
            buf.extend_from_slice(&v6.ip().octets());
            buf.extend_from_slice(&v6.port().to_be_bytes());
        }
        None => {
            // Unspecified IPv4 + port 0 — the standard "nothing useful to report" BND.
            buf.push(ATYP_IPV4);
            buf.extend_from_slice(&[0u8; 4]);
            buf.extend_from_slice(&[0u8; 2]);
        }
    }
    writer.write_all(&buf).await
}

/// Read two bytes in network order as a `u16` port. Returns `None` on clean EOF before
/// any byte is read; `Err` on partial-EOF (protocol violation).
async fn read_port<R: AsyncRead + Unpin>(reader: &mut R) -> std::io::Result<Option<u16>> {
    let mut buf = [0u8; 2];
    match read_exact_or_eof(reader, &mut buf).await? {
        Some(()) => Ok(Some(u16::from_be_bytes(buf))),
        None => Ok(None),
    }
}

/// Like `AsyncReadExt::read_exact`, but returns `None` on clean EOF at the first byte
/// (i.e. caller hung up without sending anything more). Partial reads (sent some bytes
/// then closed) are still an error — SOCKS5 has no "short message" variant.
///
/// This is the routine path for a scanner that opens the socket and disconnects: the
/// silent-proxy must not log that at `warn` or it'll drown a port-sweep in noise.
async fn read_exact_or_eof<R: AsyncRead + Unpin>(
    reader: &mut R,
    buf: &mut [u8],
) -> std::io::Result<Option<()>> {
    if buf.is_empty() {
        return Ok(Some(()));
    }
    // Try to fill the buffer. First we peek one byte to distinguish clean-EOF from
    // partial-EOF: read_exact_or_eof on an empty-but-not-closed transport should block,
    // not return None. So we do a single 1-byte read first; if that returns 0 we're at
    // clean EOF; otherwise we fill the rest with `read_exact`.
    let first = reader.read(&mut buf[..1]).await?;
    if first == 0 {
        return Ok(None);
    }
    if buf.len() > 1 {
        reader.read_exact(&mut buf[1..]).await?;
    }
    Ok(Some(()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{duplex, DuplexStream};

    /// Canonical shape: a single duplex pair where one side is the "client" and the
    /// other is the "server" (our protocol code).
    struct Pair {
        client: DuplexStream,
        server: DuplexStream,
    }

    fn pair() -> Pair {
        let (client, server) = duplex(8 * 1024);
        Pair { client, server }
    }

    #[tokio::test]
    async fn happy_path_ipv4_connect() {
        // Client → Server: greeting offering no-auth, then a CONNECT for 1.2.3.4:80.
        let mut p = pair();
        let _ = p
            .client
            .write_all(&[
                SOCKS_VERSION, 1, METHOD_NO_AUTH, // greeting
                SOCKS_VERSION, CMD_CONNECT, 0x00, ATYP_IPV4, // request header
                1, 2, 3, 4, // addr
                0x00, 0x50, // port 80
            ])
            .await;
        drop(p.client.flush().await);

        // Split server side into read + write halves.
        let mut s = p.server;
        let outcome = handshake(&mut s).await.unwrap();
        match outcome {
            HandshakeOutcome::Connect(ConnectTarget::Ip(addr)) => {
                assert_eq!(addr, "1.2.3.4:80".parse().unwrap());
            }
            other => panic!("expected Connect, got {other:?}"),
        }

        // Server should have written method-select (`05 00`) but NOT a reply yet (the
        // caller dials first, then writes the reply).
        let mut got = vec![0u8; 2];
        p.client.read_exact(&mut got).await.unwrap();
        assert_eq!(got, vec![SOCKS_VERSION, METHOD_NO_AUTH]);
    }

    #[tokio::test]
    async fn happy_path_domain_connect() {
        let mut p = pair();
        let host = b"peer.tail7b277.ts.net";
        let _ = p
            .client
            .write_all(&[
                SOCKS_VERSION,
                1,
                METHOD_NO_AUTH,
                SOCKS_VERSION,
                CMD_CONNECT,
                0x00,
                ATYP_DOMAIN,
            ])
            .await;
        drop(p.client.write_all(&[host.len() as u8]).await);
        drop(p.client.write_all(host).await);
        drop(p.client.write_all(&[0x00, 0x16]).await); // port 22
        drop(p.client.flush().await);

        let mut s = p.server;
        let outcome = handshake(&mut s).await.unwrap();
        match outcome {
            HandshakeOutcome::Connect(ConnectTarget::Domain(name, port)) => {
                assert_eq!(name, String::from_utf8(host.to_vec()).unwrap());
                assert_eq!(port, 22);
            }
            other => panic!("expected Connect, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn happy_path_ipv6_connect() {
        let mut p = pair();
        let _ = p
            .client
            .write_all(&[
                SOCKS_VERSION, 1, METHOD_NO_AUTH, SOCKS_VERSION, CMD_CONNECT, 0x00, ATYP_IPV6,
            ])
            .await;
        // 16 bytes of v6 address (fd7a:115c:a1e0::1 in full form)
        let _ = p
            .client
            .write_all(&[
                0xfd, 0x7a, 0x11, 0x5c, 0xa1, 0xe0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x01,
            ])
            .await;
        drop(p.client.write_all(&[0x01, 0xBB]).await); // port 443
        drop(p.client.flush().await);

        let mut s = p.server;
        let outcome = handshake(&mut s).await.unwrap();
        match outcome {
            HandshakeOutcome::Connect(ConnectTarget::Ip(addr)) => {
                assert_eq!(addr.port(), 443);
                assert!(addr.is_ipv6());
            }
            other => panic!("expected Connect, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn client_offers_no_acceptable_method() {
        // Client offers only username/password auth (0x02). Server has nothing for it.
        let mut p = pair();
        let _ = p
            .client
            .write_all(&[SOCKS_VERSION, 1, 0x02])
            .await;
        drop(p.client.flush().await);

        let mut s = p.server;
        let outcome = handshake(&mut s).await.unwrap();
        assert!(matches!(outcome, HandshakeOutcome::RefusedGreeting));

        // Server wrote `05 FF` (no acceptable methods).
        let mut got = vec![0u8; 2];
        p.client.read_exact(&mut got).await.unwrap();
        assert_eq!(got, vec![SOCKS_VERSION, 0xFF]);
    }

    #[tokio::test]
    async fn bind_command_refused() {
        let mut p = pair();
        let _ = p
            .client
            .write_all(&[
                SOCKS_VERSION, 1, METHOD_NO_AUTH, SOCKS_VERSION, CMD_BIND, 0x00, ATYP_IPV4, 1, 2,
                3, 4, 0x00, 0x50,
            ])
            .await;
        drop(p.client.flush().await);

        let mut s = p.server;
        let outcome = handshake(&mut s).await.unwrap();
        assert!(matches!(
            outcome,
            HandshakeOutcome::RefusedRequest(rep::COMMAND_NOT_SUPPORTED)
        ));

        // Server wrote method-select + reply with COMMAND_NOT_SUPPORTED.
        let mut got = vec![0u8; 2 + 10];
        p.client.read_exact(&mut got).await.unwrap();
        assert_eq!(&got[..2], &[SOCKS_VERSION, METHOD_NO_AUTH]);
        assert_eq!(got[2], SOCKS_VERSION);
        assert_eq!(got[3], rep::COMMAND_NOT_SUPPORTED);
    }

    #[tokio::test]
    async fn udp_associate_refused() {
        let mut p = pair();
        let _ = p
            .client
            .write_all(&[
                SOCKS_VERSION,
                1,
                METHOD_NO_AUTH,
                SOCKS_VERSION,
                CMD_UDP_ASSOCIATE,
                0x00,
                ATYP_IPV4,
                0,
                0,
                0,
                0,
                0,
                0,
            ])
            .await;
        drop(p.client.flush().await);

        let mut s = p.server;
        let outcome = handshake(&mut s).await.unwrap();
        assert!(matches!(
            outcome,
            HandshakeOutcome::RefusedRequest(rep::COMMAND_NOT_SUPPORTED)
        ));
    }

    #[tokio::test]
    async fn wrong_socks_version_refused() {
        let mut p = pair();
        // SOCKS4 greeting (0x04) — we refuse.
        drop(p.client.write_all(&[0x04, 1, METHOD_NO_AUTH]).await);
        drop(p.client.flush().await);

        let mut s = p.server;
        let outcome = handshake(&mut s).await.unwrap();
        assert!(matches!(outcome, HandshakeOutcome::RefusedGreeting));

        let mut got = vec![0u8; 2];
        p.client.read_exact(&mut got).await.unwrap();
        assert_eq!(got, vec![SOCKS_VERSION, 0xFF]);
    }

    #[tokio::test]
    async fn unknown_atyp_refused() {
        let mut p = pair();
        let _ = p
            .client
            .write_all(&[
                SOCKS_VERSION, 1, METHOD_NO_AUTH, SOCKS_VERSION, CMD_CONNECT, 0x00, 0x7F, // unknown ATYP
            ])
            .await;
        drop(p.client.flush().await);

        let mut s = p.server;
        let outcome = handshake(&mut s).await.unwrap();
        assert!(matches!(
            outcome,
            HandshakeOutcome::RefusedRequest(rep::ADDRESS_TYPE_NOT_SUPPORTED)
        ));
    }

    #[tokio::test]
    async fn client_hangup_is_not_an_error() {
        // Client opens the socket, sends nothing, closes. The canonical scanner probe.
        let p = pair();
        drop(p.client);

        let mut s = p.server;
        let outcome = handshake(&mut s).await.unwrap();
        assert!(matches!(outcome, HandshakeOutcome::HungUp));
    }

    #[tokio::test]
    async fn client_hangup_after_greeting_is_not_an_error() {
        // Client sends greeting + method-select ack path completes, then closes before
        // sending a request. Still routine — not a protocol violation worth logging.
        let mut p = pair();
        let _ = p
            .client
            .write_all(&[SOCKS_VERSION, 1, METHOD_NO_AUTH])
            .await;
        drop(p.client.flush().await);
        drop(p.client.shutdown().await);

        let mut s = p.server;
        let outcome = handshake(&mut s).await.unwrap();
        assert!(matches!(outcome, HandshakeOutcome::HungUp));

        // Server still wrote the method-select reply (that's committed before the request
        // is read). Client side is gone, so we don't read it back here.
    }

    #[tokio::test]
    async fn zero_methods_refused() {
        let mut p = pair();
        drop(p.client.write_all(&[SOCKS_VERSION, 0]).await);
        drop(p.client.flush().await);

        let mut s = p.server;
        let outcome = handshake(&mut s).await.unwrap();
        assert!(matches!(outcome, HandshakeOutcome::RefusedGreeting));
    }

    #[tokio::test]
    async fn write_reply_succeed_with_bnd() {
        let mut p = pair();
        let bnd: SocketAddr = "127.0.0.1:1234".parse().unwrap();
        write_reply(&mut p.server, rep::SUCCEEDED, Some(bnd)).await.unwrap();

        let mut got = [0u8; 10];
        p.client.read_exact(&mut got).await.unwrap();
        assert_eq!(
            got,
            [
                SOCKS_VERSION,
                rep::SUCCEEDED,
                0x00,
                ATYP_IPV4,
                127,
                0,
                0,
                1,
                0x04,
                0xD2, // port 1234 big-endian
            ]
        );
    }

    #[tokio::test]
    async fn write_reply_failure_with_none_bnd() {
        let mut p = pair();
        write_reply(&mut p.server, rep::CONNECTION_REFUSED, None)
            .await
            .unwrap();

        let mut got = [0u8; 10];
        p.client.read_exact(&mut got).await.unwrap();
        assert_eq!(
            got,
            [
                SOCKS_VERSION,
                rep::CONNECTION_REFUSED,
                0x00,
                ATYP_IPV4,
                0,
                0,
                0,
                0,
                0,
                0,
            ]
        );
    }
}
