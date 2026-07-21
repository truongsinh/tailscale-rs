//! Repro for the exec-channel stdin corruption seen on Win7/Win10 fleet deploys.
//!
//! `ssh_shell` spawns a child process per exec session and pipes SSH channel data
//! to the child's stdin via `stdin.write_all(data)` inside the russh `data` handler.
//! Field reports (charter `tailscale-rs-autonomous-run` line 158) show silent
//! truncation of stdin at every chunk size tested (1MB → 64KB), no error returned.
//!
//! This test mirrors that pattern with raw russh (no tailscale) so the bug can be
//! reproduced in CI without a real tailnet. If the byte count round-trips exactly,
//! russh's flow control is healthy and the bug is in ssh_shell's wiring; if it
//! truncates, russh itself is the culprit.

use std::{
    net::{SocketAddr, TcpListener},
    process::Stdio,
    sync::Arc,
    time::Duration,
};

use russh::{
    client,
    keys::{Algorithm, PrivateKey},
    server::{self, Auth, Handler, Msg, Server as _, Session},
};
use tokio::{
    io::AsyncWriteExt,
    process::Command,
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

// === Server side: mirrors ssh_shell's ShellServer spawn + pipe pattern ===

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
/// spawned by [`Handler::channel_open_session`] (see [`run_channel_loop`]).
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
        _session: &mut Session,
    ) -> Result<bool, Self::Error> {
        // Canonical russh pattern: spawn a per-channel task that consumes the
        // channel's mpsc via `channel.wait()` / make_reader(). The data() callback
        // path DOES NOT drain the mpsc — under load it fills (default bound 100
        // messages), the dispatch loop's `chan.send(Data).await` blocks, and the
        // inbound data path deadlocks. See commit message for full root-cause.
        tokio::spawn(async move {
            run_channel_loop(channel).await;
        });
        Ok(true)
    }
}

/// Per-channel driver. Mirrors what `ShellServer::spawn` + the `data()` callback
/// do in `examples/ssh_shell/main.rs`, but consumes inbound messages via
/// `channel.wait()` instead of the data() callback. The data() path DOES NOT
/// drain the channel's internal mpsc — under load it fills (default bound 100
/// messages), the dispatch loop's `chan.send(Data).await` blocks, and the
/// inbound data path deadlocks. See commit message for full root-cause.
async fn run_channel_loop(mut channel: russh::Channel<Msg>) {
    // Wait for an exec or shell request before spawning the child.
    let mut pending_command: Option<String> = None;
    let mut want_shell = false;
    loop {
        let Some(msg) = channel.wait().await else { return };
        match msg {
            russh::ChannelMsg::Exec { command, .. } => {
                pending_command = Some(String::from_utf8_lossy(&command).into_owned());
                break;
            }
            russh::ChannelMsg::RequestShell { .. } => {
                want_shell = true;
                break;
            }
            russh::ChannelMsg::Eof | russh::ChannelMsg::Close => return,
            _ => {}
        }
    }

    let (shell, flag, cmd_str): (&str, &str, String) = if let Some(cmd) = pending_command {
        if cfg!(windows) {
            ("cmd.exe", "/C", cmd)
        } else {
            ("/bin/sh", "-c", cmd)
        }
    } else if want_shell {
        if cfg!(windows) {
            ("cmd.exe", "", String::new())
        } else {
            ("/bin/sh", "", String::new())
        }
    } else {
        return;
    };

    let mut cmd = Command::new(shell);
    if !flag.is_empty() {
        cmd.arg(flag);
    }
    if !cmd_str.is_empty() {
        cmd.arg(&cmd_str);
    }

    let child = cmd
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn();
    let mut child = match child {
        Ok(c) => c,
        Err(_e) => {
            drop(channel.exit_status(127).await);
            drop(channel.eof().await);
            drop(channel.close().await);
            return;
        }
    };

    let child_stdin = child.stdin.take().unwrap();
    let mut child_stdout = child.stdout.take().unwrap();
    let mut child_stderr = child.stderr.take().unwrap();

    // Outbound pumps use make_writer / make_writer_ext — owned values that
    // don't borrow `channel`, so we can move them into separate tasks while
    // keeping `channel` alive for the inbound loop and final exit-status send.
    let mut channel_writer = channel.make_writer();
    let mut channel_stderr_writer = channel.make_writer_ext(Some(1));

    let stdout_task = tokio::spawn(async move {
        drop(tokio::io::copy(&mut child_stdout, &mut channel_writer).await);
    });
    let stderr_task = tokio::spawn(async move {
        drop(tokio::io::copy(&mut child_stderr, &mut channel_stderr_writer).await);
    });

    // Inbound: drain channel.wait() loop, forwarding Data to child's stdin via
    // an unbounded mpsc. The unbounded channel decouples the wait() loop from
    // the pipe-write (which can block on cat's stdin buffer), so the mpsc is
    // drained promptly even when the child is slow.
    let (stdin_tx, mut stdin_rx) = tokio::sync::mpsc::unbounded_channel::<Vec<u8>>();
    let stdin_task = tokio::spawn(async move {
        let mut stdin = child_stdin;
        while let Some(chunk) = stdin_rx.recv().await {
            if stdin.write_all(&chunk).await.is_err() {
                break;
            }
        }
        // stdin drops here → child sees EOF
    });

    // Race the client-side mpsc against child.wait() so that a child exiting
    // before the client signals Eof still drives the channel-close sequence.
    // See examples/koidra_gateway/main.rs for the full rationale.
    let mut exit_seen: Option<u32> = None;
    let mut child_exit_code: Option<u32> = None;
    loop {
        tokio::select! {
            msg = channel.wait() => {
                let Some(msg) = msg else { break };
                match msg {
                    russh::ChannelMsg::Data { data }
                        if stdin_tx.send(data.to_vec()).is_err() =>
                    {
                        break;
                    }
                    russh::ChannelMsg::Data { .. } => {}
                    russh::ChannelMsg::Eof => break,
                    russh::ChannelMsg::ExitStatus { exit_status } => {
                        exit_seen = Some(exit_status);
                    }
                    russh::ChannelMsg::Close => break,
                    _ => {}
                }
            }
            status = child.wait() => {
                child_exit_code = Some(match status {
                    Ok(s) => s.code().unwrap_or(128) as u32,
                    Err(_) => 128,
                });
                break;
            }
        }
    }
    drop(stdin_tx);
    drop(stdin_task.await);
    drop(stdout_task.await);
    drop(stderr_task.await);

    let code = if let Some(c) = child_exit_code.or(exit_seen) {
        c
    } else {
        match child.wait().await {
            Ok(s) => s.code().unwrap_or(128) as u32,
            Err(_) => 128,
        }
    };
    drop(channel.exit_status(code).await);
    drop(channel.eof().await);
    drop(channel.close().await);
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
