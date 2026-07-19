//! A6/X3 harness (CI-only): rapid-connection-churn / half-open SYN-flood stress for the
//! smoltcp netstack **accept path** at production config (`tcp_rx/tx buffers = 256 KiB`,
//! `mtu = 1500` — exactly `netcore::Config::default()`, the config every deployed
//! `ssh_shell` runs).
//!
//! Field report (real greenhouse boxes): `ssh_shell` connections WEDGE under a rapid
//! number of shell connections / connection churn. This file reproduces the accept-side
//! half of that: a flood of half-open (SYN, never completed) connections driven straight
//! at the listener over the raw in-memory wire — the same accept/listen path SSH-over-DERP
//! uses.
//!
//! Failure mode exercised (`ts_netstack_smoltcp_core/src/socket_impl/tcp/listener.rs`):
//!   * Before the fix, `pump_tcp_accept` pushed every `SYN-RECEIVED` socket onto
//!     `half_open_queue` and minted a fresh 512 KiB listen socket — but NEVER reaped that
//!     queue. The only place it was serviced is inside `process_tcp_listen(Accept)`, and
//!     there a socket still stuck in `SYN-RECEIVED` is re-queued forever: there was no
//!     age-out / timeout / backlog cap.
//!   * Consequences of the unbounded backlog: (a) each half-open connection permanently
//!     leaked a `socket_set` slot + a 256 KiB + 256 KiB buffer pair (512 KiB); (b) `socket_set` is a
//!     plain `Vec` (`SocketSet::new(vec![])`, `lib.rs:111`) so `poll_egress` — which is
//!     O(sockets) and runs on every netstack poll — degraded without bound; (c) with an
//!     accept outstanding (the real `ssh_shell` server is ALWAYS mid-`accept`), every wake
//!     re-scanned the whole `half_open_queue`.
//!   * The fix caps the backlog: `pump_tcp_accept` reaps the oldest half-open(s) once
//!     `half_open_queue` exceeds `config.tcp_half_open_backlog` (default 32), and the
//!     `accept()` terminal-state arm `remove`s sockets that leave the half-open lifecycle,
//!     bounding a listener's half-open footprint regardless of flood size.
//!
//! Two tests (both gate CI):
//!   * `accept_survives_light_half_open_churn` — a small burst of half-opens must not stop
//!     the listener from accepting a subsequent real connection.
//!   * `half_open_flood_stays_within_bounded_backlog` — the discriminating repro at scale,
//!     measuring process RSS: with the backlog cap, 20 000 half-opens retain only a bounded
//!     fraction; without it they retain ~512 KiB each. GREEN with the reaper/cap in place,
//!     RED (leak reproduced) if it is reverted — so this test gates the churn fix.

use core::net::{IpAddr, Ipv4Addr, SocketAddr};
use core::time::Duration;

use ts_netstack_smoltcp::{WakingPipe, piped};
use ts_netstack_smoltcp_core::{Channel, Config, HasChannel, NetstackControl, smoltcp};
use ts_netstack_smoltcp_socket::CreateSocket;

use smoltcp::phy::ChecksumCapabilities;
use smoltcp::wire::{
    IpAddress, IpProtocol, Ipv4Packet, Ipv4Repr, TcpControl, TcpPacket, TcpRepr, TcpSeqNumber,
};

#[path = "../examples/common/mod.rs"]
pub mod common;

const SERVER_IP: Ipv4Addr = Ipv4Addr::new(192, 168, 32, 34);
const CLIENT_IP: Ipv4Addr = Ipv4Addr::new(192, 168, 32, 99);
const PORT: u16 = 1000;

fn server_endpoint() -> SocketAddr {
    (SERVER_IP, PORT).into()
}

/// Spawn a server netstack (production config) with a listener-ready command channel and
/// hand back the raw remote end of its device pipe, so the test can inject crafted TCP
/// segments and read the netstack's replies directly off the wire.
async fn spawn_server_with_wire(config: Config) -> common::Result<(Channel, WakingPipe)> {
    let (mut stack, wire) = piped(config);
    let handle = stack.command_channel();

    tokio::spawn(async move { stack.run_tokio().await });

    handle.set_ips([IpAddr::V4(SERVER_IP)]).await?;

    Ok((handle, wire))
}

/// Craft an IPv4/TCP segment `CLIENT_IP:src_port -> SERVER_IP:PORT` with correct IP and
/// TCP checksums (the netstack verifies them on ingress and silently drops a bad one).
fn build_segment(
    src_port: u16,
    control: TcpControl,
    seq: i32,
    ack: Option<i32>,
    payload: &[u8],
) -> Vec<u8> {
    let tcp = TcpRepr {
        src_port,
        dst_port: PORT,
        control,
        seq_number: TcpSeqNumber(seq),
        ack_number: ack.map(TcpSeqNumber),
        window_len: 65535,
        window_scale: None,
        max_seg_size: matches!(control, TcpControl::Syn).then_some(1460),
        sack_permitted: false,
        sack_ranges: [None, None, None],
        timestamp: None,
        payload,
    };

    let ip = Ipv4Repr {
        src_addr: CLIENT_IP,
        dst_addr: SERVER_IP,
        next_header: IpProtocol::Tcp,
        payload_len: tcp.buffer_len(),
        hop_limit: 64,
    };

    // Fill in real IP + TCP checksums: the netstack verifies them on ingress.
    let caps = ChecksumCapabilities::default();
    let mut buf = vec![0u8; ip.buffer_len() + ip.payload_len];

    let mut ip_packet = Ipv4Packet::new_unchecked(&mut buf);
    ip.emit(&mut ip_packet, &caps);
    tcp.emit(
        &mut TcpPacket::new_unchecked(ip_packet.payload_mut()),
        &IpAddress::Ipv4(CLIENT_IP),
        &IpAddress::Ipv4(SERVER_IP),
        &caps,
    );

    buf
}

fn syn(src_port: u16, seq: i32) -> Vec<u8> {
    build_segment(src_port, TcpControl::Syn, seq, None, &[])
}

/// Parsed view of a segment the server emitted toward us.
struct Seg {
    dst_port: u16,
    syn: bool,
    ack: bool,
    seq: i32,
}

fn parse_segment(pkt: &[u8]) -> Option<Seg> {
    let ip = Ipv4Packet::new_checked(pkt).ok()?;
    if ip.next_header() != IpProtocol::Tcp {
        return None;
    }
    let tcp = TcpPacket::new_checked(ip.payload()).ok()?;
    Some(Seg {
        dst_port: tcp.dst_port(),
        syn: tcp.syn(),
        ack: tcp.ack(),
        seq: tcp.seq_number().0,
    })
}

/// Drive a full three-way handshake for `probe_port` over the raw wire, returning once the
/// server-side socket is `ESTABLISHED`. Reads (and discards) any unrelated traffic —
/// e.g. queued SYN-ACKs / retransmits for the flooded half-opens — while hunting for the
/// probe's SYN-ACK.
async fn complete_handshake(
    wire_tx: &ts_netstack_smoltcp::WakingPipeSender,
    wire_rx: &mut ts_netstack_smoltcp::WakingPipeReceiver,
    probe_port: u16,
) -> common::Result<()> {
    const PROBE_ISN: i32 = 0x0100_0000;

    wire_tx.send_async(&syn(probe_port, PROBE_ISN)).await;

    // Find the server's SYN-ACK for this probe (skip flood noise).
    let server_isn = loop {
        let pkt = wire_rx
            .recv_async()
            .await
            .ok_or("wire closed before probe SYN-ACK")?;
        if let Some(seg) = parse_segment(&pkt)
            && seg.dst_port == probe_port
            && seg.syn
            && seg.ack
        {
            break seg.seq;
        }
    };

    // Complete the handshake: ACK the server's SYN. This drives the server socket to
    // ESTABLISHED, which is what a blocked `accept()` needs to return.
    wire_tx
        .send_async(&build_segment(
            probe_port,
            TcpControl::None,
            PROBE_ISN + 1,
            Some(server_isn + 1),
            &[],
        ))
        .await;

    Ok(())
}

/// Resident set size of this process, in bytes (Linux). The server netstack runs in a
/// task in this same process, so its retained socket buffers show up here.
#[cfg(target_os = "linux")]
fn rss_bytes() -> u64 {
    let statm = std::fs::read_to_string("/proc/self/statm").expect("read /proc/self/statm");
    let resident_pages: u64 = statm
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .expect("parse resident pages");
    resident_pages * 4096
}

/// Guard (always green): a light burst of half-open connections must not wedge the
/// listener — a subsequent real connection is still accepted promptly. This is the
/// healthy contract the wedge test below violates at scale.
#[tokio::test]
async fn accept_survives_light_half_open_churn() -> common::Result<()> {
    common::init();

    let (server, wire) = spawn_server_with_wire(Config::default()).await?;
    let WakingPipe {
        rx: mut wire_rx,
        tx: wire_tx,
    } = wire;

    let listener = server.tcp_listen(server_endpoint()).await?;
    let accept = tokio::spawn(async move { listener.accept().await });

    // A small burst of half-opens (SYN, never completed).
    for i in 0..64u16 {
        wire_tx.send_async(&syn(20_000 + i, i as i32)).await;
    }

    // A real connection must still get through and be accepted.
    complete_handshake(&wire_tx, &mut wire_rx, 40_000).await?;

    let accepted = tokio::time::timeout(Duration::from_secs(5), accept)
        .await
        .map_err(|_| "listener failed to accept a real connection under light churn")??;
    let stream = accepted?;
    assert_eq!(stream.remote_addr().port(), 40_000, "accepted the wrong peer");

    Ok(())
}

/// The discriminating churn repro: a large half-open flood must stay within the bounded
/// backlog, GREEN with the reaper/cap in place and RED if it is reverted.
///
/// Floods the listener with a large number of half-open connections — SYNs that never
/// complete their handshake. Each drives the listen socket to `SYN-RECEIVED`, so
/// `pump_tcp_accept` pushes it onto `half_open_queue` (with its 256 KiB + 256 KiB buffers) and
/// mints a fresh listen socket. With the fix, `pump_tcp_accept` reaps the oldest half-open
/// once the queue exceeds `config.tcp_half_open_backlog`, and `accept()` `remove`s sockets
/// that leave the half-open lifecycle — so the retained footprint is bounded. Without the
/// fix nothing reaps a socket stuck in `SYN-RECEIVED` (the queue was serviced only inside
/// `accept()`, which re-queued such sockets forever), and `socket_set` is a plain `Vec`
/// (`lib.rs:111`) that grows without limit.
///
/// The test measures process RSS: with the cap, a flood of `FLOOD` half-opens retains only
/// a small, bounded fraction; without it each of the `FLOOD` sockets permanently retains
/// ~512 KiB and `accept()` frees none of it. The assertion encodes the healthy (bounded)
/// contract — GREEN with the reaper/cap, RED (leak reproduced, ~`FLOOD * 512 KiB` retained)
/// if the backlog cap is reverted, so it gates the churn fix.
#[cfg(target_os = "linux")]
#[tokio::test]
async fn half_open_flood_stays_within_bounded_backlog() -> common::Result<()> {
    common::init();

    let (server, wire) = spawn_server_with_wire(Config::default()).await?;
    let WakingPipe {
        rx: mut wire_rx,
        tx: wire_tx,
    } = wire;

    let listener = server.tcp_listen(server_endpoint()).await?;

    // Each retained SYN-RECEIVED socket holds a 256 KiB rx + 256 KiB tx smoltcp buffer.
    const FLOOD: u32 = 20_000;
    const PER_SOCKET: u64 = 512 * 1024;

    let rss_before = rss_bytes();

    // Flood: half-open connections that never complete their handshake.
    for i in 0..FLOOD {
        wire_tx.send_async(&syn(1024 + i as u16, i as i32)).await;
    }
    tracing::info!(flood = FLOOD, "half-open flood delivered");

    // Barrier: a real connection is ordered *after* the whole flood on the wire, so its
    // acceptance proves every flooded SYN was ingested (each minting a retained socket).
    complete_handshake(&wire_tx, &mut wire_rx, 60_000).await?;
    let probe = tokio::time::timeout(Duration::from_secs(30), listener.accept())
        .await
        .map_err(|_| "listener wedged: real connection not accepted within 30s after the flood")??;
    assert_eq!(probe.remote_addr().port(), 60_000, "accepted the wrong peer");

    let rss_after_flood = rss_bytes();

    // Run the *only* reaper (accept()) many times. A socket stuck in SYN-RECEIVED is
    // re-queued forever, so this releases nothing.
    for _ in 0..64 {
        let _drained = tokio::time::timeout(Duration::from_millis(20), listener.accept()).await;
    }
    let rss_after_reap = rss_bytes();

    let grew = rss_after_flood.saturating_sub(rss_before);
    let reaped = rss_after_flood.saturating_sub(rss_after_reap);
    eprintln!(
        "backlog: flood={FLOOD} rss_before={rss_before} after_flood={rss_after_flood} \
         after_reap={rss_after_reap} grew={grew} reaped_by_accept={reaped} \
         per_socket~={}",
        grew / FLOOD as u64
    );

    // Healthy contract: a bounded backlog / half-open reaper retains only a small fraction
    // of the unbounded footprint. 25 % is a generous ceiling (accounts for allocator
    // overhead) that the current unbounded backlog blows straight past.
    let healthy_cap = (FLOOD as u64) * PER_SOCKET / 4;
    assert!(
        grew < healthy_cap,
        "LEAK REPRODUCED: {grew} bytes retained after a flood of {FLOOD} half-open \
         connections (~{} KiB/socket); a bounded backlog would hold < {} MiB. The \
         SYN-RECEIVED backlog is unbounded and never reaped \
         (ts_netstack_smoltcp_core/src/socket_impl/tcp/listener.rs: pump_tcp_accept pushes \
         but never reaps; accept() re-queues stuck SYN-RECEIVED sockets forever).",
        grew / FLOOD as u64 / 1024,
        healthy_cap / 1024 / 1024,
    );

    Ok(())
}
