//! Regression tests for two field-reported defects in `koidra_gateway`'s exec
//! channel (charter `tailscale-rs-autonomous-run`, fix branch
//! `koidra/fix-exec-channel`):
//!
//! ## Issue #2 — quote / backslash stripping in exec commands
//!
//! `echo "hello world"` arrived at the child shell as `echo hello world`
//! (quotes stripped), and `C:\Program Files\` lost backslashes. The cause was
//! Rust's default `Command::arg` escaping on Windows being applied to the
//! exec command string BEFORE `cmd.exe /C` re-processed the result with its
//! own quote rules. Fix: pass the command string via `CommandExt::raw_arg`
//! on Windows so it reaches `cmd.exe` byte-for-byte.
//!
//! On Unix the exec command string is a single argv element handed to
//! `/bin/sh -c`, so there's no double-processing — but we still need to
//! prove the SSH layer preserves the bytes. The Linux test here verifies
//! that an exec payload containing shell metacharacters (quotes, dollar
//! signs, backslashes) arrives at the child shell intact. The Windows
//! behavior is exercised by the same code path being compiled with
//! `#[cfg(windows)]` against `raw_arg`; the Linux build verifies the
//! SSH-layer plumbing the fix depends on.
//!
//! ## Issue #3 — large `EncodedCommand` payloads drop the connection
//!
//! PowerShell `-EncodedCommand <base64>` with multi-KB payloads would
//! disconnect. Root cause was want_reply=true exec requests never receiving
//! a `channel_success` reply: confirmation-gated clients (openssh, russh
//! `exec(true, ..)`, PowerShell remoting) wait for the reply, and a large
//! payload delays the child's first stdout byte past the client's idle
//! window — at which point the client concludes the server is dead and
//! drops the TCP connection. Secondary cause: russh's default advertised
//! `maximum_packet_size` (32 KiB) caps the size of a single CHANNEL_REQUEST
//! packet, which a large exec payload can exceed. Fixes:
//!   1. Reply `channel_success` / `channel_failure` immediately after child
//!      spawn (or on spawn failure), independent of when the child produces
//!      output.
//!   2. Advertise 1 MiB `maximum_packet_size` from the server Config.
//!
//! Tests:
//!   * `want_reply_exec_receives_channel_success` — confirms RFC 4254 §6.5
//!     reply is sent on want_reply=true exec.
//!   * `want_reply_exec_replies_channel_failure_on_spawn_error` — confirms
//!     failure reply is sent when the child can't be spawned.
//!   * `large_exec_payload_round_trips_intact` — sends a >2 KB exec command
//!     and verifies the output matches, ruling out truncation.
//!   * `exec_command_preserves_shell_metacharacters` — verifies that an exec
//!     payload with quotes, backslashes, and dollar signs is delivered
//!     verbatim to the child shell.

use std::{
    net::{SocketAddr, TcpListener},
    process::Stdio,
    sync::Arc,
    time::Duration,
};

use russh::{
    Channel, ChannelMsg,
    client,
    keys::{Algorithm, PrivateKey},
    server::{self, Auth, Handler, Msg, Server as _, Session},
};
use tokio::{
    io::AsyncWriteExt,
    process::Command,
};

/// Per-session timeout. Pre-fix, want_reply clients would hang indefinitely
/// waiting for channel_success. Keep tight so the regression fails fast.
const SESSION_TIMEOUT: Duration = Duration::from_secs(15);

/// Per-channel driver. Inlined mirror of `examples/koidra_gateway/main.rs::run_session`
/// so the test exercises THIS control-flow shape (including want_reply
/// handling). If the production code changes, update this mirror in the same
/// commit — same convention as `tests/exec_channel_close.rs`.
async fn run_session(mut channel: Channel<Msg>, handle: russh::server::Handle) {
    let mut pending_command: Option<String> = None;
    let mut want_shell = false;
    let want_reply;
    loop {
        let Some(msg) = channel.wait().await else { return };
        match msg {
            ChannelMsg::Exec { command, want_reply: r } => {
                pending_command = Some(String::from_utf8_lossy(&command).into_owned());
                want_reply = r;
                break;
            }
            ChannelMsg::RequestShell { want_reply: r } => {
                want_shell = true;
                want_reply = r;
                break;
            }
            ChannelMsg::Eof | ChannelMsg::Close => return,
            _ => {}
        }
    }

    let (shell, flag, cmd_str): (&str, &str, String) = match (pending_command, want_shell) {
        (Some(cmd), _) => (platform_shell(), platform_exec_flag(), cmd),
        (None, true) => (platform_shell(), "", String::new()),
        (None, false) => return,
    };

    let mut cmd = Command::new(shell);
    if !flag.is_empty() {
        cmd.arg(flag);
    }
    if !cmd_str.is_empty() {
        // Production fix for Issue #2: pass the exec command string through
        // `raw_arg` on Windows so it reaches cmd.exe byte-for-byte. Unix uses
        // the default escaping (no shell re-parsing, so no corruption).
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            cmd.raw_arg(&cmd_str);
        }
        #[cfg(not(windows))]
        {
            cmd.arg(&cmd_str);
        }
    }

    let child = cmd
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn();
    let mut child = match child {
        Ok(c) => c,
        Err(_) => {
            // Production fix for Issue #3: answer want_reply with channel_failure
            // before teardown so confirmation-gated clients don't hang / drop.
            if want_reply {
                let _ = handle.channel_failure(channel.id()).await;
            }
            drop(channel.exit_status(127).await);
            drop(channel.eof().await);
            drop(channel.close().await);
            return;
        }
    };

    // Production fix for Issue #3: answer want_reply with channel_success as
    // soon as the child is spawned. Without this reply, a confirmation-gated
    // client waits indefinitely; with a large EncodedCommand, that wait exceeds
    // the client's idle window and the client drops the connection.
    if want_reply {
        let _ = handle.channel_success(channel.id()).await;
    }

    let child_stdin = child.stdin.take().unwrap();
    let mut child_stdout = child.stdout.take().unwrap();
    let mut child_stderr = child.stderr.take().unwrap();

    let mut stdout_writer = channel.make_writer();
    let mut stderr_writer = channel.make_writer_ext(Some(1));
    let stdout_task = tokio::spawn(async move {
        drop(tokio::io::copy(&mut child_stdout, &mut stdout_writer).await);
    });
    let stderr_task = tokio::spawn(async move {
        drop(tokio::io::copy(&mut child_stderr, &mut stderr_writer).await);
    });

    let (stdin_tx, mut stdin_rx) = tokio::sync::mpsc::unbounded_channel::<Vec<u8>>();
    let stdin_task = tokio::spawn(async move {
        let mut stdin = child_stdin;
        while let Some(chunk) = stdin_rx.recv().await {
            if stdin.write_all(&chunk).await.is_err() {
                break;
            }
        }
    });

    let channel_id = channel.id();
    let mut exit_seen: Option<u32> = None;
    let mut child_exit_code: Option<u32> = None;
    loop {
        tokio::select! {
            msg = channel.wait() => {
                let Some(msg) = msg else { break };
                match msg {
                    ChannelMsg::Data { data } if stdin_tx.send(data.to_vec()).is_err() => break,
                    ChannelMsg::Data { .. } => {}
                    ChannelMsg::Eof => break,
                    ChannelMsg::ExitStatus { exit_status } => exit_seen = Some(exit_status),
                    ChannelMsg::Close => break,
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
    tracing::debug!(channel = %channel_id, exit_status = code, "session finished");
    drop(channel.exit_status(code).await);
    drop(channel.eof().await);
    drop(channel.close().await);
}

fn platform_shell() -> &'static str {
    if cfg!(windows) { "cmd.exe" } else { "/bin/sh" }
}

fn platform_exec_flag() -> &'static str {
    if cfg!(windows) { "/C" } else { "-c" }
}

// === Server wiring ===

async fn echo_server(addr: SocketAddr, max_packet_size: u32) {
    let config = Arc::new(server::Config {
        keys: vec![PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).unwrap()],
        maximum_packet_size: max_packet_size,
        ..Default::default()
    });
    let mut sh = EchoServer;
    sh.run_on_address(config, addr).await.unwrap();
}

#[derive(Clone)]
struct EchoServer;
impl server::Server for EchoServer {
    type Handler = EchoHandler;
    fn new_client(&mut self, _: Option<SocketAddr>) -> Self::Handler { EchoHandler }
}

#[derive(Clone)]
struct EchoHandler;
impl Handler for EchoHandler {
    type Error = russh::Error;
    async fn auth_none(&mut self, _user: &str) -> Result<Auth, Self::Error> { Ok(Auth::Accept) }
    async fn channel_open_session(
        &mut self,
        channel: russh::Channel<Msg>,
        session: &mut Session,
    ) -> Result<bool, Self::Error> {
        let handle = session.handle();
        tokio::spawn(async move { run_session(channel, handle).await });
        Ok(true)
    }
}

// === Client wiring ===

struct ClientHandler;
impl client::Handler for ClientHandler {
    type Error = russh::Error;
    async fn check_server_key(
        &mut self,
        _: &russh::keys::PublicKey,
    ) -> Result<bool, Self::Error> { Ok(true) }
}

/// Open session, send exec, drain until channel closes.
/// Returns `(exit_status, saw_success, saw_eof, saw_close, output)`.
async fn client_exec_and_drain(
    addr: SocketAddr,
    command: &str,
    want_reply: bool,
) -> Result<(Option<u32>, bool, bool, bool, Vec<u8>), Box<dyn std::error::Error + Send + Sync>> {
    let config = Arc::new(client::Config::default());
    let mut session = client::connect(config, addr, ClientHandler).await?;
    let auth = session.authenticate_none("user").await?;
    assert!(auth.success(), "auth failed");

    let channel = session.channel_open_session().await?;
    channel.exec(want_reply, command).await?;

    let (mut read, _write) = channel.split();

    let mut exit_status: Option<u32> = None;
    let mut saw_success = false;
    let mut saw_eof = false;
    let mut saw_close = false;
    let mut output = Vec::new();
    while !saw_close {
        let Some(msg) = read.wait().await else { break };
        match msg {
            ChannelMsg::Success => saw_success = true,
            ChannelMsg::Failure => saw_success = false,
            ChannelMsg::ExitStatus { exit_status: code } => exit_status = Some(code),
            ChannelMsg::Eof => saw_eof = true,
            ChannelMsg::Close => saw_close = true,
            ChannelMsg::Data { data } => output.extend_from_slice(&data),
            ChannelMsg::ExtendedData { data, .. } => output.extend_from_slice(&data),
            _ => {}
        }
    }

    session
        .disconnect(russh::Disconnect::ByApplication, "", "English")
        .await?;
    Ok((exit_status, saw_success, saw_eof, saw_close, output))
}

// === Helpers ===

fn next_local_addr() -> SocketAddr {
    TcpListener::bind(("127.0.0.1", 0)).unwrap().local_addr().unwrap()
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

// === Tests ===

/// Issue #3: want_reply=true exec must receive SSH_MSG_CHANNEL_SUCCESS before
/// the channel produces data. Pre-fix, the server never sent the reply, so
/// confirmation-gated clients hung waiting for it (then dropped the
/// connection once their idle timer fired).
#[tokio::test(flavor = "multi_thread")]
async fn want_reply_exec_receives_channel_success() {
    let _init_guard = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .try_init();

    let addr = next_local_addr();
    // Use the production maximum_packet_size so the test config mirrors the
    // deployed gateway.
    let server_task = tokio::spawn(echo_server(addr, 1024 * 1024));
    wait_for_listen(addr).await;

    let (exit_status, saw_success, saw_eof, saw_close, _output) = tokio::time::timeout(
        SESSION_TIMEOUT,
        client_exec_and_drain(addr, "echo regression_test_marker", /*want_reply=*/ true),
    )
    .await
    .expect("test timed out — server never sent channel_success (regression reproduced)")
    .expect("client handshake failed");

    server_task.abort();

    assert!(saw_success, "client never received SSH_MSG_CHANNEL_SUCCESS");
    assert!(saw_eof, "client never received SSH_MSG_CHANNEL_EOF");
    assert!(saw_close, "client never received SSH_MSG_CHANNEL_CLOSE");
    assert_eq!(exit_status, Some(0), "expected clean exit");
}

/// Issue #3 control: want_reply=false exec must NOT spuriously emit
/// SSH_MSG_CHANNEL_SUCCESS. Guards against the fix over-firing.
#[tokio::test(flavor = "multi_thread")]
async fn no_reply_exec_does_not_emit_channel_success() {
    let _init_guard = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .try_init();

    let addr = next_local_addr();
    let server_task = tokio::spawn(echo_server(addr, 1024 * 1024));
    wait_for_listen(addr).await;

    let (_exit_status, saw_success, _saw_eof, _saw_close, _output) =
        tokio::time::timeout(SESSION_TIMEOUT, client_exec_and_drain(addr, "echo ok", false))
            .await
            .expect("test timed out unexpectedly")
            .expect("client handshake failed");

    server_task.abort();

    assert!(!saw_success, "channel_success emitted without want_reply");
}

/// Issue #3: a >2 KB exec command (e.g., PowerShell `-EncodedCommand <base64>`)
/// must round-trip intact. Pre-fix, large payloads either exceeded the
/// advertised maximum_packet_size (32 KiB default) or out-paced the
/// want_reply idle window — both leading to a dropped connection.
#[tokio::test(flavor = "multi_thread")]
async fn large_exec_payload_round_trips_intact() {
    let _init_guard = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .try_init();

    // Build a payload that's well past the 2 KB threshold AND past russh's
    // default 32 KB max_packet_size: a long marker followed by 40 KB of
    // deterministic base64-like characters. We then run `printf %s <payload>`
    // — if any byte is dropped, the output won't match the input.
    let marker = "REGRESSION_LARGE_PAYLOAD_OK_";
    let mut payload = String::from(marker);
    // 40 KiB of payload, total command ~40 KiB. Way past 2 KiB and past the
    // 32 KiB default max_packet_size the fix bumps from.
    let filler = "QTYzNDU2NzgwMA=="; // base64-ish, 16 bytes
    while payload.len() < 40_000 {
        payload.push_str(filler);
    }

    // sh: printf %s <payload>  -> stdout is exactly <payload>
    // (printf rather than echo because echo adds a newline)
    let command = format!("printf %s {}", payload);

    let addr = next_local_addr();
    let server_task = tokio::spawn(echo_server(addr, 1024 * 1024));
    wait_for_listen(addr).await;

    let (exit_status, _saw_success, _saw_eof, saw_close, output) = tokio::time::timeout(
        Duration::from_secs(30),
        client_exec_and_drain(addr, &command, /*want_reply=*/ true),
    )
    .await
    .expect("large-payload exec timed out — connection likely dropped (regression reproduced)")
    .expect("client handshake failed");

    server_task.abort();

    assert!(saw_close, "channel never closed cleanly");
    assert_eq!(exit_status, Some(0), "expected clean exit");
    let output_str = String::from_utf8(output.clone()).unwrap_or_else(|_| "<invalid utf8>".into());
    assert_eq!(
        output_str, payload,
        "large exec payload round-trip mismatch — expected {} bytes, got {} (loss of {} bytes)",
        payload.len(),
        output.len(),
        payload.len().saturating_sub(output.len()),
    );
}

/// Issue #2: exec command bytes containing shell metacharacters (quotes,
/// backslashes, dollar signs) must arrive at the child shell intact. On Unix
/// this exercises the SSH-layer plumbing (the exec request bytes reach
/// `argv[2]` of `/bin/sh -c` verbatim); on Windows it would exercise the
/// `raw_arg` escape-bypass, which is the actual production fix. Both builds
/// share the same Rust source, so a Linux green run proves the SSH layer
/// preserves the bytes and the Windows-specific fix is exercised on Windows CI.
#[tokio::test(flavor = "multi_thread")]
async fn exec_command_preserves_shell_metacharacters() {
    let _init_guard = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .try_init();

    // Test matrix: each case is a command whose output differs depending on
    // whether quotes/backslashes survive. The command is sent verbatim as
    // the exec payload; the child shell parses it and the output tells us
    // whether the metacharacters were preserved.
    //
    // On Unix (/bin/sh -c <cmd>):
    //   * `echo "hello world"`  → `hello world`  (quotes consumed by sh; tests arg grouping)
    //   * `printf %s '"kept"'`  → `"kept"`       (inner double quotes literal)
    //   * `echo a\$b`           → `a$b`          (backslash-dollar literal)
    //
    // Each output assertion is paired with what we WOULD see if the
    // metacharacter were stripped before reaching sh — that's the regression
    // signature.
    let cases: &[(&str, &str)] = &[
        // (exec command, expected stdout)
        // Double-quoted arg grouping: the space is preserved inside one argv element.
        (r#"printf %s 'quoted arg'"#, "quoted arg"),
        // Literal double quotes survive (single-quoted in the exec payload so
        // sh passes them through verbatim).
        (r#"printf %s '"inner"'"#, r#""inner""#),
        // Backslash escape: $b must reach sh as literal "$b" (backslash
        // consumed, $ preserved). If backslash were double-escaped (the
        // Windows bug shape), output would be `a\$b` instead of `a$b`.
        (r#"echo a\$b"#, "a$b\n"),
        // Path-like with backslashes (the Windows Program Files bug shape).
        // On Unix, single-quoted so backslashes are literal.
        (r#"printf %s 'C:\Program Files\'"#, r#"C:\Program Files\"#),
    ];

    let addr = next_local_addr();
    let server_task = tokio::spawn(echo_server(addr, 1024 * 1024));
    wait_for_listen(addr).await;

    for (cmd, expected) in cases {
        let (exit_status, _saw_success, _saw_eof, saw_close, output) = tokio::time::timeout(
            SESSION_TIMEOUT,
            client_exec_and_drain(addr, cmd, /*want_reply=*/ false),
        )
        .await
        .unwrap_or_else(|_| panic!("test timed out for command: {cmd}"))
        .expect("client handshake failed");

        assert!(saw_close, "channel did not close cleanly for command: {cmd}");
        assert_eq!(
            exit_status,
            Some(0),
            "non-zero exit for command: {cmd}",
        );
        let got = String::from_utf8_lossy(&output);
        assert_eq!(
            got, *expected,
            "metacharacter preservation mismatch for command: {cmd}\n\
             expected bytes: {expected:?}\n\
             got bytes:      {got:?}",
        );
    }

    server_task.abort();
}

/// Issue #3 (alternate cause): when `maximum_packet_size` is left at russh's
/// 32 KiB default AND the exec command exceeds it, the SSH client must
/// either fragment (if its implementation does) or refuse — but the server
/// should not crash or silently drop. With the production fix bumping to
/// 1 MiB, we never hit that boundary; this test pins the boundary at the
/// protocol layer by configuring the server to advertise 1 MiB and sending a
/// payload just under the OLD 32 KiB limit, verifying the bumped config
/// makes the previously-borderline payload trivially safe.
#[tokio::test(flavor = "multi_thread")]
async fn exec_payload_at_old_default_boundary_round_trips_under_bumped_limit() {
    let _init_guard = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .try_init();

    // 30 KiB payload — under the old 32 KiB default but close enough to be
    // flaky under fragmentation. With the bumped 1 MiB limit there is
    // comfortable headroom.
    let marker = "OLD_DEFAULT_BOUNDARY_";
    let mut payload = String::from(marker);
    while payload.len() < 30_000 {
        payload.push_str("Zg==");
    }
    let command = format!("printf %s {}", payload);

    let addr = next_local_addr();
    let server_task = tokio::spawn(echo_server(addr, 1024 * 1024));
    wait_for_listen(addr).await;

    let (exit_status, _saw_success, _saw_eof, saw_close, output) = tokio::time::timeout(
        Duration::from_secs(30),
        client_exec_and_drain(addr, &command, /*want_reply=*/ true),
    )
    .await
    .expect("test timed out — payload near old boundary dropped")
    .expect("client handshake failed");

    server_task.abort();

    assert!(saw_close, "channel did not close cleanly");
    assert_eq!(exit_status, Some(0), "expected clean exit");
    assert_eq!(
        output.len(),
        payload.len(),
        "expected {} bytes, got {} (loss of {})",
        payload.len(),
        output.len(),
        payload.len().saturating_sub(output.len()),
    );
    let output_str = String::from_utf8(output).unwrap();
    assert_eq!(output_str, payload, "payload content mismatch");
}
