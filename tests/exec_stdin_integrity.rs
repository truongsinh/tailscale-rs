//! Repro for the exec-channel stdin corruption seen on Win7/Win10 fleet deploys.
//!
//! `ssh_shell` spawns a child process per exec session and pipes SSH channel data
//! to the child's stdin via `stdin.write_all(data)` inside the russh `data` handler.
//! Field reports (charter `tailscale-rs-autonomous-run` line 158) show silent
//! truncation of stdin at every chunk size tested (1MB → 64KB), no error returned.
//!
//! This test runs the REAL ssh_shell per-channel loop (`channel_loop.rs`, included
//! via `#[path]`) over raw russh (no tailscale) so the bug can be reproduced in CI
//! without a real tailnet. If the byte count round-trips exactly, russh's flow
//! control and ssh_shell's wiring are healthy; if it truncates, one of them is the
//! culprit.

// The REAL deployed per-channel loop (not a mirror — a mirror stays green
// while the product breaks). Same wiring as tests/ssh_channel_protocol.rs.
#[path = "../examples/ssh_shell/channel_loop.rs"]
mod channel_loop;

use std::{
    net::{SocketAddr, TcpListener},
    sync::Arc,
    time::Duration,
};

use russh::{
    client,
    keys::{Algorithm, PrivateKey},
    server::{self, Auth, Handler, Msg, Server as _, Session},
};

/// Total bytes to push through the exec channel. Well above any plausible SSH
/// window size (default ~2MB in russh) to exercise WINDOW_ADJUST.
const TOTAL_BYTES: usize = 10 * 1024 * 1024;

/// Per-write chunk size the client uses. The field bug truncated at all sizes;
/// we sweep a few representative ones.
const CHUNK_SIZES: &[usize] = &[4 * 1024, 32 * 1024, 64 * 1024, 256 * 1024];

#[tokio::test(flavor = "multi_thread")]
async fn exec_channel_stdin_round_trips_with_real_openssh_client() {
    let _init_guard = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .try_init();

    // Skip if openssh client isn't installed (CI env without it)
    if std::process::Command::new("ssh")
        .arg("-V")
        .output()
        .is_err()
    {
        eprintln!("skipping: ssh client not available");
        return;
    }

    let addr = next_local_addr();
    let payload = deterministic_payload(TOTAL_BYTES);

    let server_handle = tokio::spawn(echo_server(addr));
    for _ in 0..100 {
        if std::net::TcpStream::connect(addr).is_ok() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    // Write payload to a temp file, ssh "cat" it back, compare
    let tempdir = std::env::temp_dir().join(format!(
        "exec-stdin-repro-{}",
        std::process::id()
    ));
    std::fs::create_dir_all(&tempdir).unwrap();
    let input_path = tempdir.join("input.bin");
    let output_path = tempdir.join("output.bin");
    std::fs::write(&input_path, &payload).unwrap();

    let port = addr.port();
    let ssh_output = std::process::Command::new("ssh")
        .args([
            "-p",
            &port.to_string(),
            "-o", "StrictHostKeyChecking=no",
            "-o", "UserKnownHostsFile=/dev/null",
            "-o", "PreferredAuthentications=none",
            "-o", "NumberOfPasswordPrompts=0",
            // Bump client window size so we test the server's flow control
            "-o", "SendEnv=TS_TEST_REPRO",
            "user@127.0.0.1",
            "cat",
        ])
        .stdin(std::fs::File::open(&input_path).unwrap())
        .stdout(std::fs::File::create(&output_path).unwrap())
        .stderr(std::process::Stdio::piped())
        .output()
        .expect("failed to spawn ssh");

    if !ssh_output.status.success() {
        let stderr = String::from_utf8_lossy(&ssh_output.stderr);
        panic!("ssh failed: {:?} stderr: {}", ssh_output.status, stderr);
    }

    server_handle.abort();

    let received = std::fs::read(&output_path).unwrap();
    std::fs::remove_dir_all(&tempdir).ok();

    assert_eq!(
        received.len(),
        payload.len(),
        "OpenSSH client → russh server: expected {} bytes, got {} (silent loss of {} bytes)",
        payload.len(),
        received.len(),
        payload.len() - received.len(),
    );
    assert_eq!(
        received, payload,
        "OpenSSH client → russh server: payload mismatch — bytes corrupted in transit",
    );
    tracing::info!(bytes = payload.len(), "OpenSSH round-trip OK");
}

#[tokio::test(flavor = "multi_thread")]
async fn exec_channel_stdin_round_trips_losslessly_at_all_chunk_sizes() {
    let _init_guard = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .try_init();

    for &chunk in CHUNK_SIZES {
        let addr = next_local_addr();
        let data = deterministic_payload(TOTAL_BYTES);

        // Server: mirrors ShellServer in examples/ssh_shell/main.rs
        let server_handle = tokio::spawn(echo_server(addr));

        // Wait for server to come up
        for _ in 0..100 {
            if std::net::TcpStream::connect(addr).is_ok() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }

        let received = client_push_and_collect(addr, &data, chunk).await.expect(
            "client push+collect failed — see error",
        );

        // Stop the server
        server_handle.abort();

        assert_eq!(
            received.len(),
            data.len(),
            "chunk={} expected {} bytes, received {} (silent loss of {} bytes)",
            chunk,
            data.len(),
            received.len(),
            data.len() - received.len(),
        );
        assert_eq!(
            received, data,
            "chunk={} payload md5 mismatch — bytes were corrupted in transit",
            chunk,
        );
        tracing::info!(chunk, bytes = data.len(), "round-trip OK");
    }
}

/// A payload that is NOT all zeros (which compress nicely and might hide drops)
/// but is deterministic (so failures are reproducible, not flaky).
fn deterministic_payload(n: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(n);
    let mut state: u64 = 0x1234_5678_9abc_def0;
    while out.len() < n {
        // xorshift64 — fast, deterministic, decent bit dispersion
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        out.extend_from_slice(&state.to_le_bytes());
    }
    out.truncate(n);
    out
}

fn next_local_addr() -> SocketAddr {
    TcpListener::bind(("127.0.0.1", 0))
        .unwrap()
        .local_addr()
        .unwrap()
}

// === Server side: runs ssh_shell's REAL per-channel loop (channel_loop.rs) ===

async fn echo_server(addr: SocketAddr) {
    let config = Arc::new(server::Config {
        keys: vec![PrivateKey::random(
            &mut rand::rng(),
            Algorithm::Ed25519,
        )
        .unwrap()],
        ..Default::default()
    });
    let mut sh = EchoServer;
    sh.run_on_address(config, addr).await.unwrap();
}

#[derive(Clone)]
struct EchoServer;

impl server::Server for EchoServer {
    type Handler = ShellHandler;

    fn new_client(&mut self, _: Option<SocketAddr>) -> Self::Handler {
        ShellHandler
    }
}

/// Per-session handler. The actual channel-driving work happens in the task
/// spawned by [`Handler::channel_open_session`] (see `channel_loop::run_session`).
#[derive(Clone)]
struct ShellHandler;

impl Handler for ShellHandler {
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
        // `channel.wait()` (the data() callback path does NOT drain the mpsc —
        // under load it fills, the dispatch loop blocks, and inbound data
        // deadlocks; see channel_loop.rs docs).
        let handle = session.handle();
        let remote = SocketAddr::from(([127, 0, 0, 1], 0));
        tokio::spawn(async move {
            channel_loop::run_session(channel, handle, remote).await;
        });
        Ok(true)
    }
}

// === Client side: send all data, collect all output, compare ===

async fn client_push_and_collect(
    addr: SocketAddr,
    payload: &[u8],
    chunk_size: usize,
) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
    let config = Arc::new(client::Config::default());

    let mut session = client::connect(config, addr, ClientHandler).await?;
    // Server accepts auth_none unconditionally (mirrors ssh_shell's no-gate design).
    let auth = session.authenticate_none("user").await?;
    assert!(auth.success(), "auth failed");

    let channel = session.channel_open_session().await?;
    channel.exec(true, "cat").await?;

    // Split into read + write halves so we can push stdin and drain stdout
    // concurrently. The whole channel cannot be borrowed twice at once.
    let (mut read, write) = channel.split();

    // Push data in chunks of `chunk_size`. Concurrent write + read so the
    // server-side pipe can drain while we keep pushing.
    let write_payload = payload.to_vec();
    let (write_result, read_result) = tokio::join!(
        async {
            let mut total = 0usize;
            for chunk in write_payload.chunks(chunk_size) {
                write.data(chunk).await?;
                total += chunk.len();
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
                    russh::ChannelMsg::Data { data } => buf.extend_from_slice(&data),
                    russh::ChannelMsg::ExtendedData { data, .. } => buf.extend_from_slice(&data),
                    russh::ChannelMsg::Eof | russh::ChannelMsg::Close => break,
                    russh::ChannelMsg::ExitStatus { .. } => {}
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
