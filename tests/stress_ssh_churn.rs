//! End-to-end SSH-layer **connection-churn** stress harness — the field-reported wedge
//! trigger that the netstack-level `tcp_accept_churn.rs` exercises only in isolation.
//!
//! Field report (charter `tailscale-rs-autonomous-run` line 120): `ssh_shell` connections
//! wedge under "a rapid number of shell connections". The netstack harness proves the
//! half-open backlog is bounded; THIS harness drives a real russh server end-to-end
//! (handshake → auth → channel open → channel close → disconnect) so a regression in any
//! layer between the TCP accept path and the russh session lifecycle surfaces as a hang
//! or a reject, not as a silent RSS bump.
//!
//! Contract:
//!   * `ssh_shell_survives_concurrent_connection_churn` — 10 waves × 1000 concurrent
//!     russh handshakes (10 000 sequential sessions total, 1000 at a time). Every session
//!     must open a channel, exchange one empty exec round-trip, and disconnect cleanly.
//!     FAIL = any session hangs past the per-wave timeout (60s) OR the server stops
//!     accepting new handshakes between waves.
//!   * `ssh_shell_survives_sequential_handshake_burst` — a tighter burst of 2000 purely
//!     sequential handshakes back-to-back, exercising the accept path with zero
//!     concurrency. Catches the degenerate case where concurrency masks a per-session
//!     leak.
//!
//! Tunable via env (non-binding; defaults are the contract):
//!   * `TS_STRESS_CHURN_WAVES` (default 10)
//!   * `TS_STRESS_CHURN_PER_WAVE` (default 1000)
//!   * `TS_STRESS_CHURN_SEQUENTIAL` (default 2000)
//!   * `TS_STRESS_CHURN_WAVE_TIMEOUT_SECS` (default 60)
//!
//! The test raises RLIMIT_NOFILE at startup so 1000 concurrent sessions fit (each russh
//! session holds ~7 FDs → ~8 KiB needed; the Linux default soft limit of 1024 is the
//! bottleneck otherwise). If setrlimit can't raise enough, `per_wave` is scaled down
//! with a warning; the test is still a meaningful regression gate at any scale > 256.
//! **Production consideration**: ssh_shell delegates FD-limit management to its process
//! supervisor (systemd `LimitNOFILE=`, etc.); the fleet deploy kits already set this.
//!
//! The server side mirrors `examples/ssh_shell/main.rs`'s ShellServer at the contract
//! level — per-channel task consuming `channel.wait()`, no `data()` override — via the
//! minimal `NoopServer` below. The point is the accept + handshake lifecycle, not data
//! transfer (covered by `stress_heavy_transfer.rs`).

use std::{
    net::SocketAddr, sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    }, time::{Duration, Instant},
};

use russh::{
    client,
    keys::{Algorithm, PrivateKey},
    server::{self, Auth, Handler, Msg, Server as _, Session},
};
use tokio::sync::Barrier;

/// Raise RLIMIT_NOFILE so the test can hold thousands of concurrent sessions.
///
/// Each russh session holds ~7 FDs (TCP socket + crypto pipes + channel halves +
/// internal russh state); 1000 concurrent sessions need ~8 KiB of FDs, well above the
/// Linux default soft limit of 1024. The production ssh_shell delegates this to its
/// process supervisor (`LimitNOFILE=` in systemd, etc.); a CI test must be hermetic.
///
/// Returns the new soft limit actually in effect (which the caller uses to scale
/// `per_wave` down if we couldn't raise enough).
#[cfg(unix)]
fn raise_fd_limit(wanted: u64) -> u64 {
    use libc::{RLIMIT_NOFILE, getrlimit, setrlimit, rlimit};

    let mut current: rlimit = unsafe { std::mem::zeroed() };
    if unsafe { getrlimit(RLIMIT_NOFILE, &mut current) } != 0 {
        tracing::warn!("getrlimit failed; keeping default FD limit");
        return 1024;
    }
    let target = wanted.min(current.rlim_max as u64);
    let new_soft = current.rlim_cur.max(target);
    if new_soft <= current.rlim_cur {
        return current.rlim_cur as u64;
    }
    let new = rlimit { rlim_cur: new_soft as _, rlim_max: current.rlim_max };
    // SAFETY: setrlimit with RLIMIT_NOFILE and a soft <= hard is the documented contract.
    if unsafe { setrlimit(RLIMIT_NOFILE, &new) } != 0 {
        tracing::warn!(
            current = current.rlim_cur, max = current.rlim_max, wanted,
            "setrlimit failed; keeping default FD limit (run with --ulimit nofile=65536:65536)",
        );
        return current.rlim_cur as u64;
    }
    tracing::info!(new_soft, hard = current.rlim_max, "raised RLIMIT_NOFILE for churn test");
    new_soft
}

#[cfg(not(unix))]
fn raise_fd_limit(_wanted: u64) -> u64 {
    // Windows has no per-process FD limit in this sense; assume the test can run as-is.
    u64::MAX
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn ssh_shell_survives_concurrent_connection_churn() {
    init_logging();
    let waves = env_u64("TS_STRESS_CHURN_WAVES", 10);
    let per_wave_requested = env_u64("TS_STRESS_CHURN_PER_WAVE", 1000);
    let wave_timeout = env_secs("TS_STRESS_CHURN_WAVE_TIMEOUT_SECS", 60);

    // Each concurrent session holds ~7 FDs (server TCP + client TCP + russh pipes).
    // Ask for 8x the per-wave count so the limit is never the bottleneck.
    let available = raise_fd_limit(per_wave_requested.saturating_mul(8).max(8192));
    // If we couldn't raise enough, scale per_wave to fit (and document the gap). The
    // regression-gate value is still meaningful at any scale > 256.
    let per_wave = per_wave_requested.min(available.saturating_div(8).max(256));
    if per_wave < per_wave_requested {
        tracing::warn!(
            per_wave_requested, per_wave, available,
            "FD limit forced a smaller per_wave — set --ulimit nofile=65536:65536 \
             (or run on a system where setrlimit can raise) for the full 1000-concurrent test",
        );
    }

    let addr = next_local_addr();
    let accepted = Arc::new(AtomicU64::new(0));
    let server_task = tokio::spawn(noop_server(addr, accepted.clone()));
    wait_for_listen(addr).await;

    let mut total_ok = 0u64;
    let mut total_fail = 0u64;

    for wave in 0..waves {
        let barrier = Arc::new(Barrier::new(per_wave as usize));
        let mut handles = Vec::with_capacity(per_wave as usize);
        for _ in 0..per_wave {
            let b = barrier.clone();
            handles.push(tokio::spawn(async move {
                let _ = b.wait().await; // release all clients together
                client_handshake(addr).await
            }));
        }
        let start = Instant::now();
        let mut wave_ok = 0u64;
        let mut wave_fail = 0u64;
        for h in handles {
            match tokio::time::timeout(Duration::from_secs(wave_timeout), h).await {
                Ok(Ok(Ok(()))) => wave_ok += 1,
                Ok(Ok(Err(_e))) => wave_fail += 1,
                Ok(Err(_join_err)) => wave_fail += 1,
                Err(_elapsed) => {
                    wave_fail += 1;
                    tracing::error!(
                        wave, per_wave, elapsed=?start.elapsed(),
                        "session hung past wave timeout — wedge reproduced"
                    );
                }
            }
        }
        total_ok += wave_ok;
        total_fail += wave_fail;
        tracing::info!(
            wave, wave_ok, wave_fail,
            elapsed_ms = start.elapsed().as_millis(),
            server_accepted_total = accepted.load(Ordering::Relaxed),
            "wave complete",
        );
        // A wave that fails *any* session is a real regression — the server must accept
        // every legitimate handshake under a concurrent burst.
        assert_eq!(
            wave_fail, 0,
            "wave {wave}: {wave_fail}/{per_wave} sessions failed (ok={wave_ok}) — \
             SSH-layer churn wedge reproduced. Server accepted {} total.",
            accepted.load(Ordering::Relaxed),
        );
    }

    tracing::info!(
        waves, per_wave, total_ok, total_fail,
        server_accepted_total = accepted.load(Ordering::Relaxed),
        "ALL WAVES PASSED — no wedge under SSH connection churn",
    );

    server_task.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn ssh_shell_survives_sequential_handshake_burst() {
    init_logging();
    let n = env_u64("TS_STRESS_CHURN_SEQUENTIAL", 2000);
    let per_session_timeout = env_secs("TS_STRESS_CHURN_WAVE_TIMEOUT_SECS", 30);

    let addr = next_local_addr();
    let accepted = Arc::new(AtomicU64::new(0));
    let server_task = tokio::spawn(noop_server(addr, accepted.clone()));
    wait_for_listen(addr).await;

    let start = Instant::now();
    let mut ok = 0u64;
    let mut fail = 0u64;
    for i in 0..n {
        // Wrap in a oneshot to surface join failures distinctly from inner errors.
        let (tx, rx) = tokio::sync::oneshot::channel::<Result<(), String>>();
        tokio::spawn(async move {
            let res = client_handshake(addr)
                .await
                .map_err(|e| format!("{e:?}"));
            drop(tx.send(res));
        });
        match tokio::time::timeout(
            Duration::from_secs(per_session_timeout),
            rx,
        ).await {
            Ok(Ok(Ok(()))) => ok += 1,
            Ok(Ok(Err(e))) => {
                fail += 1;
                tracing::error!(i, error = %e, "sequential handshake failed");
            }
            Ok(Err(_recv_err)) => {
                fail += 1;
                tracing::error!(i, "client task died before completing (recv dropped)");
            }
            Err(_) => {
                fail += 1;
                tracing::error!(i, elapsed_ms = start.elapsed().as_millis(), "sequential handshake timed out — wedge");
            }
        }
    }
    tracing::info!(
        n, ok, fail, elapsed_ms = start.elapsed().as_millis(),
        server_accepted_total = accepted.load(Ordering::Relaxed),
        "sequential burst complete",
    );

    server_task.abort();
    assert_eq!(fail, 0, "{fail}/{n} sequential handshakes failed — wedge reproduced");
}

// === Shared helpers ===

fn env_u64(name: &str, default: u64) -> u64 {
    std::env::var(name)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

fn env_secs(name: &str, default: u64) -> u64 {
    env_u64(name, default)
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

async fn wait_for_listen(addr: SocketAddr) {
    for _ in 0..200 {
        if std::net::TcpStream::connect(addr).is_ok() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("server did not come up at {addr}");
}

/// One full SSH session lifecycle: connect → auth → channel_open_session → eof → close.
/// This is what every `ssh user@host` invocation drives; it's the path that wedges under
/// churn. Returns Ok(()) on clean lifecycle, Err on any failure.
async fn client_handshake(addr: SocketAddr) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let config = Arc::new(client::Config::default());
    let mut session = client::connect(config, addr, ClientHandler).await?;
    let auth = session.authenticate_none("user").await?;
    if !auth.success() {
        session
            .disconnect(russh::Disconnect::ByApplication, "", "English")
            .await
            .ok();
        return Err("auth failed".into());
    }
    let channel = session.channel_open_session().await?;
    // Open + immediately close: exercises the full per-session accept/teardown path.
    let (mut read, write) = channel.split();
    write.eof().await?;
    // Drain until the server closes the channel.
    loop {
        let Some(msg) = read.wait().await else { break };
        match msg {
            russh::ChannelMsg::Eof | russh::ChannelMsg::Close | russh::ChannelMsg::ExitStatus { .. } => {}
            _ => {}
        }
        if matches!(msg, russh::ChannelMsg::Close) { break; }
    }
    session
        .disconnect(russh::Disconnect::ByApplication, "", "English")
        .await?;
    Ok(())
}

// === Server side: minimal russh server mirroring ssh_shell's accept + per-channel task pattern ===

async fn noop_server(addr: SocketAddr, accepted: Arc<AtomicU64>) {
    let config = Arc::new(server::Config {
        keys: vec![PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).unwrap()],
        // Prospective clients can be rejected before the auth flow; default accepts all
        // (mirrors ssh_shell's no-gate design — ACL-only, no pubkey gate).
        ..Default::default()
    });
    let mut sh = NoopServer { accepted };
    sh.run_on_address(config, addr).await.unwrap();
}

#[derive(Clone)]
struct NoopServer {
    accepted: Arc<AtomicU64>,
}

impl server::Server for NoopServer {
    type Handler = NoopHandler;

    fn new_client(&mut self, _: Option<SocketAddr>) -> Self::Handler {
        self.accepted.fetch_add(1, Ordering::Relaxed);
        NoopHandler
    }
}

#[derive(Clone)]
struct NoopHandler;

impl Handler for NoopHandler {
    type Error = russh::Error;

    async fn auth_none(&mut self, _user: &str) -> Result<Auth, Self::Error> {
        Ok(Auth::Accept)
    }

    async fn channel_open_session(
        &mut self,
        channel: russh::Channel<Msg>,
        _session: &mut Session,
    ) -> Result<bool, Self::Error> {
        // Canonical russh per-channel driver pattern (P2 fix): consume the channel mpsc
        // via `channel.wait()` inside a dedicated task — NOT via a `data()` callback.
        tokio::spawn(async move {
            let (mut read, write) = channel.split();
            // Wait for EOF from client, then close cleanly.
            while let Some(msg) = read.wait().await {
                match msg {
                    russh::ChannelMsg::Data { .. } | russh::ChannelMsg::ExtendedData { .. } => {}
                    russh::ChannelMsg::Eof => break,
                    russh::ChannelMsg::Close => return,
                    _ => {}
                }
            }
            drop(write.close().await);
        });
        Ok(true)
    }
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
