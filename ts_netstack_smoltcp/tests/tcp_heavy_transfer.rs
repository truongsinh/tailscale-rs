//! Heavy-transfer stress harness for the netstack TCP bridge at **production config** —
//! `tcp_rx/tx buffers = 256 KiB`, `mtu = 1500` (exactly `netcore::Config::default()`, the
//! config every deployed `ssh_shell` runs). Reproduces the field-reported "connection
//! with heavy transfer wedges" symptom.
//!
//! These tests drive `ts_netstack_smoltcp_socket::TcpStream` (the `poll_read`/`poll_write`
//! bridge) through an in-memory pipe between two real netstacks — the same read/write path
//! SSH-over-DERP uses — so a bridge regression is caught here rather than as a corrupted
//! file (or a panicked, wedged session) on a client box.
//!
//! Three tests:
//!   * `bulk_transfer_preserves_every_byte` — happy-path byte-integrity guard: a
//!     multi-buffer unidirectional payload must arrive byte-for-byte. Green today.
//!   * `bidirectional_heavy_transfer_preserves_every_byte` — both directions saturated
//!     concurrently (the "either direction" half of the field report). Green today.
//!   * `cancelled_large_read_then_small_read_preserves_bytes` — **the reproduction**. A
//!     read cancelled while pending (a timed-out large read) leaves a `read_fut` inside
//!     the `TcpStream` sized to the LARGE `cap`; the next read into a SMALL buffer polls
//!     that stale future. Before the fix `poll_read` ran
//!     `buf[..ret.len()].copy_from_slice(&ret)` with `ret.len() > buf.len()` →
//!     out-of-bounds slice index → **panic** that unwound and wedged the SSH session. The
//!     fix re-caps the copy to `buf.len()` and stashes the untransferred tail; this test is
//!     GREEN with it and RED (panics) if reverted — so it gates the bridge fix.

use core::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use ts_netstack_smoltcp_socket::CreateSocket;

#[path = "../examples/common/mod.rs"]
pub mod common;

/// Deterministic, index-dependent payload: byte `i = (i * 31 + 7) as u8`. Reproducible
/// (no rand) and *positional* — a dropped or reordered chunk shifts the pattern, so an
/// equality check localises truncation instead of merely counting bytes.
fn payload(len: usize) -> Vec<u8> {
    (0..len)
        .map(|i| (i.wrapping_mul(31).wrapping_add(7)) as u8)
        .collect()
}

/// A bulk unidirectional transfer at production config delivers every byte in order — no
/// truncation, no reordering — across payloads that fit in one TCP buffer, span several
/// buffer refills, and span many MTU-1500 segments.
#[tokio::test]
async fn bulk_transfer_preserves_every_byte() -> common::Result<()> {
    common::init();

    // sub-buffer · fills the 256 KiB buffer exactly · overflows it (many 1500-byte segments)
    for &size in &[16 * 1024usize, 256 * 1024, 1024 * 1024] {
        let (stack1, stack2) = common::spawn_piped_netstacks(Default::default(), None).await?;
        let listener = stack2.tcp_listen(common::netstack2_endpoint()).await?;

        let expected = payload(size);
        let to_send = expected.clone();

        // Writer: accept, stream the whole payload, then drop the socket. `write_all` for a
        // payload larger than the 256 KiB send buffer only completes once the reader drains,
        // so completion proves back-pressure worked; the drop issues Close → graceful FIN.
        let writer = tokio::spawn(async move {
            let mut sock = listener.accept().await.unwrap();
            sock.write_all(&to_send).await.unwrap();
            sock.flush().await.unwrap();
        });

        let mut sock = stack1
            .tcp_connect(common::netstack_endpoint(), common::netstack2_endpoint())
            .await?;

        // Read until FIN, capturing exactly what was delivered (a short read = truncation).
        let mut got = Vec::with_capacity(size);
        let mut buf = [0u8; 4096];
        loop {
            let n = sock.read(&mut buf).await?;
            if n == 0 {
                break;
            }
            got.extend_from_slice(&buf[..n]);
        }
        writer.await.unwrap();

        assert_eq!(
            got.len(),
            size,
            "size {size}: delivered length differs (truncation)"
        );
        assert_eq!(got, expected, "size {size}: byte-integrity violated");
    }

    Ok(())
}

/// Both directions saturated concurrently — each endpoint writes a large payload while
/// reading the peer's — must preserve every byte in both directions. This is the "heavy
/// transfer in either direction" half of the field report. Each side splits its stream so
/// its write cannot deadlock against its own read under back-pressure, and reads a *known*
/// length with `read_exact` (this stream's `poll_shutdown` is a no-op, so EOF is never
/// signalled while a half is held — length-framing avoids relying on FIN).
#[tokio::test]
async fn bidirectional_heavy_transfer_preserves_every_byte() -> common::Result<()> {
    common::init();

    const SIZE: usize = 1024 * 1024; // 4 refills of the 256 KiB buffer each way

    let (stack1, stack2) = common::spawn_piped_netstacks(Default::default(), None).await?;
    let listener = stack2.tcp_listen(common::netstack2_endpoint()).await?;

    let from_server = payload(SIZE); // server -> client
    let from_client = payload(SIZE + 1234); // client -> server (distinct length + pattern offset)
    let client_len = from_client.len();

    let server_send = from_server.clone();
    let server_expect = from_client.clone();
    let server = tokio::spawn(async move {
        let sock = listener.accept().await.unwrap();
        let (mut rd, mut wr) = tokio::io::split(sock);
        let w = tokio::spawn(async move {
            wr.write_all(&server_send).await.unwrap();
            wr.flush().await.unwrap();
        });
        let mut got = vec![0u8; client_len];
        rd.read_exact(&mut got).await.unwrap();
        w.await.unwrap();
        got
    });

    let sock = stack1
        .tcp_connect(common::netstack_endpoint(), common::netstack2_endpoint())
        .await?;
    let (mut rd, mut wr) = tokio::io::split(sock);
    let client_send = from_client.clone();
    let w = tokio::spawn(async move {
        wr.write_all(&client_send).await.unwrap();
        wr.flush().await.unwrap();
    });
    let mut client_got = vec![0u8; from_server.len()];
    rd.read_exact(&mut client_got).await?;
    w.await.unwrap();

    let server_got = server.await.unwrap();

    assert_eq!(client_got.len(), from_server.len(), "client<-server length");
    assert_eq!(client_got, from_server, "client<-server byte-integrity");
    assert_eq!(server_got.len(), server_expect.len(), "server<-client length");
    assert_eq!(server_got, server_expect, "server<-client byte-integrity");

    Ok(())
}

/// **Reproduction of the heavy-transfer wedge (roadmap A0).**
///
/// A read cancelled while pending (a timed-out large read — routine on an SSH session
/// carrying a heavy interactive/scp transfer) leaves a `read_fut` inside the `TcpStream`
/// sized to the LARGE buffer's `cap`. The next read with a SMALLER buffer polls that stale
/// future; on resolution `poll_read` runs `buf[..ret.len()].copy_from_slice(&ret)`
/// (`ts_netstack_smoltcp_socket/src/tcp/stream.rs:202`) with `ret.len() > buf.len()` — an
/// out-of-bounds slice index that PANICS, unwinding the connection task and wedging the
/// session.
///
/// The correct behavior is that byte-integrity is preserved regardless of buffer-size
/// changes across a cancellation: a short read returns `<= buf.len()` bytes and stashes the
/// untransferred tail for the next poll. This test asserts that contract; it is RED
/// (panics) under the current bridge and turns green when the stash-and-drain fix lands.
#[tokio::test]
async fn cancelled_large_read_then_small_read_preserves_bytes() -> common::Result<()> {
    common::init();

    let (stack1, stack2) = common::spawn_piped_netstacks(Default::default(), None).await?;
    let listener = stack2.tcp_listen(common::netstack2_endpoint()).await?;

    let accept = tokio::spawn(async move { listener.accept().await.unwrap() });

    let mut reader = stack1
        .tcp_connect(common::netstack_endpoint(), common::netstack2_endpoint())
        .await?;
    let writer = accept.await.unwrap();

    // 1. Start a LARGE read with no data queued and cancel it via timeout, so the pending
    //    read_fut (cap = LARGE) survives inside `reader`.
    const LARGE: usize = 8 * 1024;
    let mut large = [0u8; LARGE];
    let timed = tokio::time::timeout(Duration::from_millis(50), reader.read(&mut large)).await;
    assert!(
        timed.is_err(),
        "expected the large read to time out with no data queued"
    );

    // 2. Deliver a chunk far larger than the SMALL buffer (but within the stale cap).
    const CHUNK: usize = 4 * 1024;
    let sent = payload(CHUNK);
    let mut off = 0;
    while off < sent.len() {
        off += writer.send(&sent[off..]).await?;
    }

    // 3. Read into a SMALL buffer. Correct: return <= SMALL bytes and stash the rest.
    //    Current bridge: the stale future resolves with far more than SMALL bytes and
    //    `poll_read` copies them into the SMALL buffer — panic at stream.rs:202.
    const SMALL: usize = 64;
    let mut small = [0u8; SMALL];
    let n = reader.read(&mut small).await?;
    assert!(
        n <= SMALL,
        "read returned {n} bytes into a {SMALL}-byte buffer (overflow/tail-drop)"
    );

    // 4. Drain the remainder and assert the whole chunk arrived, in order, unduplicated.
    let mut got = small[..n].to_vec();
    while got.len() < CHUNK {
        let n = reader.read(&mut small).await?;
        assert!(
            n <= SMALL,
            "read returned {n} bytes into a {SMALL}-byte buffer (overflow/tail-drop)"
        );
        if n == 0 {
            break;
        }
        got.extend_from_slice(&small[..n]);
    }

    assert_eq!(got.len(), CHUNK, "cancelled read dropped bytes (truncation)");
    assert_eq!(got, sent, "cancelled read corrupted the stream (tail-drop/reorder)");

    Ok(())
}
