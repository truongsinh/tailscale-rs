//! End-to-end SSH-layer **heavy-transfer** stress harness — the second field-reported
//! wedge trigger, at the layer users see.
//!
//! Field report (charter `tailscale-rs-autonomous-run` line 120): `ssh_shell` connections
//! wedge under "a connection with heavy transfer (either direction)". The netstack-level
//! `tcp_heavy_transfer.rs` proves the bridge `poll_read`/`poll_write` is panic-free at the
//! buffer layer; THIS harness drives a real russh server end-to-end via the exec channel
//! (the same path `ssh_shell` uses for `ssh user@host '<command>'`) so a wedge or
//! silent-truncation regression in any layer between TCP and the spawned child process
//! surfaces as a byte mismatch or a timeout.
//!
//! Contract:
//!   * `ssh_shell_round_trips_100mb_exec_channel_losslessly` — one client pushes 100 MiB
//!     of deterministic positional payload through `cat`, then verifies the exact bytes
//!     came back. FAIL = truncation, corruption, or timeout (any of the field-reported
//!     "heavy transfer wedges"). PASS = every byte round-trips.
//!
//! This also re-verifies P2 (exec-channel stdin fix, commit 8a1a151) at scale — P2's
//! repro was 10 MiB; 100 MiB at the SSH layer is a stronger gate. A regression in the
//! per-channel mpsc drain (P2 root cause) would surface here as silent truncation.
//!
//! Tunable via env:
//!   * `TS_STRESS_TRANSFER_MIB` (default 100)
//!   * `TS_STRESS_TRANSFER_TIMEOUT_SECS` (default 120)
//!
//! Server side runs `examples/ssh_shell/channel_loop.rs` — the REAL deployed per-channel
//! loop, included via `#[path]` (not a mirror): per-channel task consuming
//! `channel.wait()`, child stdin drained via unbounded mpsc, child stdout piped back via
//! `make_writer`. Same wiring as `tests/exec_stdin_integrity.rs` — extended here to the
//! 100 MiB regime.

// The REAL deployed per-channel loop (not a mirror — a mirror stays green
// while the product breaks). Same wiring as tests/ssh_channel_protocol.rs.
#[path = "../examples/ssh_shell/channel_loop.rs"]
mod channel_loop;

use std::{
    net::SocketAddr,
    sync::Arc,
    time::{Duration, Instant},
};

use russh::{
    ChannelMsg, client,
    keys::{Algorithm, PrivateKey},
    server::{self, Auth, Handler, Msg, Server as _, Session},
};

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn ssh_shell_round_trips_100mb_exec_channel_losslessly() {
    init_logging();
    let mib = env_u64("TS_STRESS_TRANSFER_MIB", 100) as usize;
    let total_bytes = mib * 1024 * 1024;
    let timeout_secs = env_u64("TS_STRESS_TRANSFER_TIMEOUT_SECS", 120);

    // CI mode = in-process cat server (hermetic). Canary mode = drive a real
    // deployed ssh_shell over the tailnet (TS_STRESS_TARGET_HOST) — proves the
    // field binary survives the same heavy-transfer load the CI server does.
    let (addr, _server_task) = target_or_loopback().await;

    let payload = deterministic_payload(total_bytes);
    tracing::info!(total_bytes, "payload generated; spawning client");

    let start = Instant::now();
    let push = tokio::time::timeout(
        Duration::from_secs(timeout_secs),
        client_push_and_collect(addr, &payload, 64 * 1024),
    );
    let received = match push.await {
        Ok(Ok(buf)) => buf,
        Ok(Err(e)) => {
            if let Some(t) = _server_task { t.abort(); }
            panic!("client push+collect failed: {e:?}");
        }
        Err(_) => {
            if let Some(t) = _server_task { t.abort(); }
            panic!(
                "100 MiB transfer did not complete within {timeout_secs}s — \
                 wedge reproduced (field symptom: heavy transfer hangs)"
            );
        }
    };
    let elapsed = start.elapsed();
    if let Some(t) = _server_task { t.abort(); }

    assert_eq!(
        received.len(),
        payload.len(),
        "truncation: expected {} bytes, got {} (silent loss of {} bytes) — \
         field symptom: heavy transfer silently drops bytes. \
         elapsed = {:?}",
        payload.len(),
        received.len(),
        payload.len() - received.len(),
        elapsed,
    );
    // Verify positional integrity (a drop or reorder shifts the pattern locally).
    assert_eq!(
        received, payload,
        "corruption: payload bytes mismatch — field symptom: heavy transfer corrupts data. \
         elapsed = {:?}",
        elapsed,
    );

    let mib_per_sec = (mib as f64) / elapsed.as_secs_f64();
    tracing::info!(
        total_bytes, elapsed_ms = elapsed.as_millis(), mib_per_sec,
        "100 MiB round-trip OK — no wedge, no truncation, no corruption",
    );
}

// === Shared helpers ===

fn env_u64(name: &str, default: u64) -> u64 {
    std::env::var(name)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

fn init_logging() {
    drop(
        tracing_subscriber::fmt()
            .with_env_filter(
                tracing_subscriber::EnvFilter::try_from_default_env()
                    .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
            )
            .try_init(),
    );
}

fn next_local_addr() -> SocketAddr {
    use std::net::TcpListener;
    TcpListener::bind(("127.0.0.1", 0))
        .unwrap()
        .local_addr()
        .unwrap()
}

/// Resolve the target address: either an external canary target (real deployed
/// ssh_shell over the tailnet — `TS_STRESS_TARGET_HOST` [+ `_PORT`, default 22])
/// or an in-process loopback CatServer (CI hermetic mode). Same shape as
/// `stress_ssh_churn::target_or_loopback` but without an accept counter (the
/// transfer harness doesn't track accepts).
async fn target_or_loopback(
) -> (SocketAddr, Option<tokio::task::JoinHandle<()>>) {
    if let Ok(host) = std::env::var("TS_STRESS_TARGET_HOST") {
        let port: u16 = std::env::var("TS_STRESS_TARGET_PORT")
            .ok()
            .and_then(|p| p.parse().ok())
            .unwrap_or(22);
        let addr: SocketAddr = format!("{host}:{port}")
            .parse()
            .unwrap_or_else(|e| panic!("invalid TS_STRESS_TARGET_HOST={host} port={port}: {e}"));
        tracing::warn!(
            %addr,
            "CANARY MODE — driving a real deployed ssh_shell (TS_STRESS_TARGET_HOST set). \
             No loopback server; the harness drives the field binary.",
        );
        match std::net::TcpStream::connect_timeout(
            &addr,
            Duration::from_secs(5),
        ) {
            Ok(_) => {}
            Err(e) => panic!("canary target {addr} unreachable (5s TCP connect): {e}"),
        }
        (addr, None)
    } else {
        let addr = next_local_addr();
        let task = tokio::spawn(cat_server(addr));
        wait_for_listen(addr).await;
        (addr, Some(task))
    }
}

async fn wait_for_listen(addr: SocketAddr) {
    for _ in 0..200 {
        if std::net::TcpStream::connect(addr).is_ok() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("server did not come up at {addr}");
}

/// Deterministic positional payload: byte `i = (i * 31 + 7) as u8`. A drop or reorder
/// shifts the pattern at the offset where it happened, so a positional diff localises
/// the failure instead of merely counting bytes.
fn deterministic_payload(n: usize) -> Vec<u8> {
    (0..n).map(|i| (i.wrapping_mul(31).wrapping_add(7)) as u8).collect()
}

// === Server side: runs ssh_shell's REAL per-channel loop (channel_loop.rs) ===

async fn cat_server(addr: SocketAddr) {
    let config = Arc::new(server::Config {
        keys: vec![PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).unwrap()],
        ..Default::default()
    });
    let mut sh = CatServer;
    sh.run_on_address(config, addr).await.unwrap();
}

#[derive(Clone)]
struct CatServer;

impl server::Server for CatServer {
    type Handler = CatHandler;

    fn new_client(&mut self, _: Option<SocketAddr>) -> Self::Handler {
        CatHandler
    }
}

#[derive(Clone)]
struct CatHandler;

impl Handler for CatHandler {
    type Error = russh::Error;

    async fn auth_none(&mut self, _user: &str) -> Result<Auth, Self::Error> {
        Ok(Auth::Accept)
    }

    async fn channel_open_session(
        &mut self,
        channel: russh::Channel<Msg>,
        session: &mut Session,
    ) -> Result<bool, Self::Error> {
        // Identical wiring to examples/ssh_shell/main.rs: per-channel task that
        // runs the REAL extracted loop, consuming the channel's mpsc via
        // `channel.wait()` (P2 fix — the data() callback path does NOT drain
        // the mpsc; see channel_loop.rs docs and commit 8a1a151).
        let handle = session.handle();
        let remote = SocketAddr::from(([127, 0, 0, 1], 0));
        tokio::spawn(async move {
            channel_loop::run_session(channel, handle, remote).await;
        });
        Ok(true)
    }
}

// === Client side ===

async fn client_push_and_collect(
    addr: SocketAddr,
    payload: &[u8],
    chunk_size: usize,
) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
    let config = Arc::new(client::Config::default());
    let mut session = client::connect(config, addr, ClientHandler).await?;
    let auth = session.authenticate_none("user").await?;
    assert!(auth.success(), "auth failed");

    let channel = session.channel_open_session().await?;
    channel.exec(true, "cat").await?;

    let (mut read, write) = channel.split();

    let write_payload = payload.to_vec();
    let (write_result, read_result) = tokio::join!(
        async {
            let mut total = 0usize;
            for chunk in write_payload.chunks(chunk_size) {
                write.data(chunk).await?;
                total += chunk.len();
                // Yield periodically so the read pump gets scheduler time on large pushes.
                if total.is_multiple_of(4 * 1024 * 1024) {
                    tokio::task::yield_now().await;
                }
            }
            write.eof().await?;
            tracing::info!(total_written = total, chunk_size, "client finished writing");
            Ok::<_, russh::Error>(total)
        },
        async {
            let mut buf = Vec::with_capacity(payload.len() + 1024);
            loop {
                let Some(msg) = read.wait().await else { break };
                match msg {
                    ChannelMsg::Data { data } => buf.extend_from_slice(&data),
                    ChannelMsg::ExtendedData { data, .. } => buf.extend_from_slice(&data),
                    ChannelMsg::Eof | ChannelMsg::Close => break,
                    ChannelMsg::ExitStatus { .. } => {}
                    _ => {}
                }
            }
            buf
        }
    );

    write_result?;
    let received = read_result;
    session
        .disconnect(russh::Disconnect::ByApplication, "", "English")
        .await?;
    Ok(received)
}

struct ClientHandler;

impl client::Handler for ClientHandler {
    type Error = russh::Error;
    async fn check_server_key(
        &mut self,
        _: &russh::keys::PublicKey,
    ) -> Result<bool, Self::Error> {
        Ok(true)
    }
}
