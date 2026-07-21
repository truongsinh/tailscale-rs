//! Regression for the exec-channel session-hang bug.
//!
//! Symptom: when a process spawned via an SSH exec channel exits, the server side
//! of the russh channel never sends SSH_MSG_CHANNEL_EOF / SSH_MSG_CHANNEL_CLOSE.
//! The SSH client blocks forever waiting for the channel teardown handshake.
//!
//! Root cause: the per-channel driver loop only consumed `channel.wait()` — which
//! returns messages arriving FROM the client (Data, Eof, Close, ExitStatus). It
//! never observed the child process exiting. When the child exited before the
//! client signalled Eof (the common case for any fast command and every
//! interactive shell where the user types `exit`), the server stayed stuck in
//! `channel.wait()`, the client stayed blocked waiting for the server's
//! exit-status / EOF, and the session wedged until TCP keepalive finally reaped
//! it — minutes to hours later on a LAN.
//!
//! Fix: race `channel.wait()` against `child.wait()` in a `tokio::select!` so
//! whichever side tears down first drives the channel-close sequence. See
//! `examples/koidra_gateway/main.rs::run_session` for the production fix; the
//! same pattern is mirrored by `EchoShellHandler` below.
//!
//! These tests exercise the fix end-to-end via a real russh client driving a
//! real russh server (in-process, loopback). No openssh binary required.

use std::{
    net::{SocketAddr, TcpListener},
    process::Stdio,
    sync::Arc,
    time::Duration,
};

use russh::{
    ChannelMsg,
    client,
    keys::{Algorithm, PrivateKey},
    server::{self, Auth, Handler, Msg, Server as _, Session},
};
use tokio::{
    io::AsyncWriteExt,
    process::Command,
};

/// Per-session timeout. Pre-fix, the client would hang indefinitely because the
/// server never closed the channel. Keep this tight so the regression fails
/// fast instead of consuming the whole CI slot.
const SESSION_TIMEOUT: Duration = Duration::from_secs(15);

#[tokio::test(flavor = "multi_thread")]
async fn exec_channel_sends_eof_close_when_child_exits_without_client_eof() {
    //
    // Regression case: client opens exec channel, does NOT send Eof (mirrors an
    // interactive shell where the user hasn't closed stdin). Child runs to
    // completion on its own. The server MUST send exit-status + EOF + Close so
    // the client's `channel.wait()` loop terminates.
    //
    let _init_guard = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .try_init();

    let addr = next_local_addr();
    let server_task = tokio::spawn(echo_server(addr));
    wait_for_listen(addr).await;

    let (exit_status, saw_eof, saw_close) = tokio::time::timeout(
        SESSION_TIMEOUT,
        client_open_exec_and_drain(addr, "echo hello", /*send_eof=*/ false),
    )
    .await
    .expect("test timed out — server never closed the channel (regression reproduced)")
    .expect("client handshake failed");

    server_task.abort();

    assert_eq!(exit_status, Some(0), "expected clean exit");
    assert!(saw_eof, "client never received SSH_MSG_CHANNEL_EOF");
    assert!(saw_close, "client never received SSH_MSG_CHANNEL_CLOSE");
}

#[tokio::test(flavor = "multi_thread")]
async fn exec_channel_sends_eof_close_when_child_exits_after_client_eof() {
    //
    // Control case: client sends Eof first, child exits after. This path
    // worked pre-fix; it must keep working post-fix.
    //
    let _init_guard = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .try_init();

    let addr = next_local_addr();
    let server_task = tokio::spawn(echo_server(addr));
    wait_for_listen(addr).await;

    let (exit_status, saw_eof, saw_close) = tokio::time::timeout(
        SESSION_TIMEOUT,
        client_open_exec_and_drain(addr, "echo hello", /*send_eof=*/ true),
    )
    .await
    .expect("test timed out unexpectedly")
    .expect("client handshake failed");

    server_task.abort();

    assert_eq!(exit_status, Some(0));
    assert!(saw_eof);
    assert!(saw_close);
}

#[tokio::test(flavor = "multi_thread")]
async fn exec_channel_closes_after_child_exits_with_nonzero_status() {
    //
    // Exit status propagation through the fix: child exits non-zero, server
    // must still send exit-status + close so the client sees the real code.
    //
    let _init_guard = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .try_init();

    let addr = next_local_addr();
    let server_task = tokio::spawn(echo_server(addr));
    wait_for_listen(addr).await;

    let (exit_status, saw_eof, saw_close) = tokio::time::timeout(
        SESSION_TIMEOUT,
        client_open_exec_and_drain(addr, "exit 42", /*send_eof=*/ false),
    )
    .await
    .expect("test timed out — server never closed the channel")
    .expect("client handshake failed");

    server_task.abort();

    assert_eq!(exit_status, Some(42), "expected exit code 42");
    assert!(saw_eof);
    assert!(saw_close);
}

// === Server side: mirrors the production `run_session` pattern in
//     examples/koidra_gateway/main.rs. Carries the same fix. ===

async fn echo_server(addr: SocketAddr) {
    let config = Arc::new(server::Config {
        keys: vec![PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).unwrap()],
        ..Default::default()
    });
    let mut sh = EchoServer;
    sh.run_on_address(config, addr).await.unwrap();
}

#[derive(Clone)]
struct EchoServer;

impl server::Server for EchoServer {
    type Handler = EchoHandler;
    fn new_client(&mut self, _: Option<SocketAddr>) -> Self::Handler {
        EchoHandler
    }
}

#[derive(Clone)]
struct EchoHandler;

impl Handler for EchoHandler {
    type Error = russh::Error;
    async fn auth_none(&mut self, _user: &str) -> Result<Auth, Self::Error> {
        Ok(Auth::Accept)
    }
    async fn channel_open_session(
        &mut self,
        channel: russh::Channel<Msg>,
        _session: &mut Session,
    ) -> Result<bool, Self::Error> {
        tokio::spawn(async move { run_session(channel).await });
        Ok(true)
    }
}

/// Inlined copy of `examples/koidra_gateway/main.rs::run_session` (minus the
/// tracing flair). The point of the test is to prove THIS control-flow shape
/// closes the channel on child exit. If you change the example, change this
/// mirror in the same commit.
async fn run_session(mut channel: russh::Channel<Msg>) {
    let mut pending_command: Option<String> = None;
    let mut want_shell = false;
    loop {
        let Some(msg) = channel.wait().await else { return };
        match msg {
            ChannelMsg::Exec { command, .. } => {
                pending_command = Some(String::from_utf8_lossy(&command).into_owned());
                break;
            }
            ChannelMsg::RequestShell { .. } => {
                want_shell = true;
                break;
            }
            ChannelMsg::Eof | ChannelMsg::Close => return,
            _ => {}
        }
    }

    let (shell, flag, cmd_str): (&str, &str, String) = match (pending_command, want_shell) {
        (Some(cmd), _) => ("/bin/sh", "-c", cmd),
        (None, true) => ("/bin/sh", "", String::new()),
        (None, false) => return,
    };

    let mut cmd = Command::new(shell);
    if !flag.is_empty() {
        cmd.arg(flag);
    }
    if !cmd_str.is_empty() {
        cmd.arg(&cmd_str);
    }

    let mut child = match cmd
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
    {
        Ok(c) => c,
        Err(_) => {
            drop(channel.exit_status(127).await);
            drop(channel.eof().await);
            drop(channel.close().await);
            return;
        }
    };

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

    let mut exit_seen: Option<u32> = None;
    let mut child_exit_code: Option<u32> = None;
    loop {
        tokio::select! {
            msg = channel.wait() => {
                let Some(msg) = msg else { break };
                match msg {
                    ChannelMsg::Data { data }
                        if stdin_tx.send(data.to_vec()).is_err() =>
                    {
                        break;
                    }
                    ChannelMsg::Data { .. } => {}
                    ChannelMsg::Eof => break,
                    ChannelMsg::ExitStatus { exit_status } => {
                        exit_seen = Some(exit_status);
                    }
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
    let _ = stdin_task.await;
    let _ = stdout_task.await;
    let _ = stderr_task.await;

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

// === Client side ===

/// Open a session, send exec, optionally send Eof, then drain until the server
/// closes the channel. Returns `(exit_status, saw_eof, saw_close)`.
async fn client_open_exec_and_drain(
    addr: SocketAddr,
    command: &str,
    send_eof: bool,
) -> Result<(Option<u32>, bool, bool), Box<dyn std::error::Error + Send + Sync>> {
    let config = Arc::new(client::Config::default());
    let mut session = client::connect(config, addr, ClientHandler).await?;
    let auth = session.authenticate_none("user").await?;
    assert!(auth.success(), "auth failed");

    let channel = session.channel_open_session().await?;
    channel.exec(true, command).await?;

    let (mut read, write) = channel.split();

    // Optionally send Eof to test both branches of the fix.
    let write_handle = tokio::spawn(async move {
        if send_eof {
            write.eof().await?;
        }
        Ok::<_, russh::Error>(())
    });

    let mut exit_status: Option<u32> = None;
    let mut saw_eof = false;
    let mut saw_close = false;
    while !saw_close {
        let Some(msg) = read.wait().await else { break };
        match msg {
            ChannelMsg::ExitStatus { exit_status: code } => {
                exit_status = Some(code);
            }
            ChannelMsg::Eof => saw_eof = true,
            ChannelMsg::Close => saw_close = true,
            _ => {}
        }
    }

    write_handle.await?;
    session
        .disconnect(russh::Disconnect::ByApplication, "", "English")
        .await?;
    Ok((exit_status, saw_eof, saw_close))
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

// === helpers ===

fn next_local_addr() -> SocketAddr {
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
