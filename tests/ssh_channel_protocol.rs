//! Seam-level protocol regression tests for the REAL `ssh_shell` per-channel
//! loop (`examples/ssh_shell/channel_loop.rs`, included below via `#[path]` —
//! the same wiring `tests/bench_harness.rs` uses for the peer's `prng.rs`).
//!
//! The older SSH test files each embedded a MIRROR copy of the server shape; a
//! regression test against a mirror stays green while the deployed loop breaks.
//! These tests drive a real russh client against a real in-process server that
//! runs the extracted production loop, and pin the two protocol defects found
//! while building `tests/bench_harness.rs`:
//!
//!   1. `exec` with `want_reply=true` was never answered — RFC 4254 §6.5
//!      requires channel_success/channel_failure, and confirmation-gated
//!      clients hung forever (`exec_want_reply_is_confirmed_and_round_trips`).
//!   2. The loop only completed the channel (exit-status + eof + close) after
//!      CLIENT half-close, so an exec that expects no stdin, from a client that
//!      never sends EOF, wedged the session forever
//!      (`exec_completes_on_child_exit_without_client_eof`).
//!
//! Plus the normal-path guard: `cat` + client EOF still round-trips cleanly
//! (protects the P2 exec-stdin fix).

#[path = "../examples/ssh_shell/channel_loop.rs"]
mod channel_loop;

use std::{
    net::SocketAddr,
    sync::Arc,
    time::Duration,
};

use russh::{
    ChannelMsg, client,
    keys::{Algorithm, PrivateKey},
    server::{self, Auth, Handler, Msg, Server as _, Session},
};

/// Bound on every test: before the fixes, both defect scenarios hang forever.
const TEST_TIMEOUT: Duration = Duration::from_secs(20);

#[tokio::test(flavor = "multi_thread")]
async fn exec_want_reply_is_confirmed_and_round_trips() {
    init_logging();
    let (addr, server_task) = start_shell_server().await;

    let result = tokio::time::timeout(TEST_TIMEOUT, async {
        let (_session, mut read, write) = open_exec_channel(addr, true, "cat").await;

        // Defect 1 regression: the confirmation must arrive. Before the fix the
        // server never answered want_reply and this wait ran into the timeout.
        loop {
            match read.wait().await {
                Some(ChannelMsg::Success) => break,
                Some(ChannelMsg::Failure) => panic!("server refused the exec request"),
                Some(_) => {}
                None => panic!("channel closed before the exec confirmation arrived"),
            }
        }

        // And the exec must still be functional after the confirmation.
        write.data(&b"ping-across-the-seam"[..]).await.unwrap();
        write.eof().await.unwrap();
        collect_until_close(&mut read).await
    })
    .await
    .expect("timed out: want_reply exec confirmation never arrived (defect 1 wedge)");

    server_task.abort();
    assert_eq!(result.stdout, b"ping-across-the-seam");
    assert_eq!(result.exit_status, Some(0), "expected clean exit status");
    assert!(result.closed, "channel must be closed by the server");
}

#[tokio::test(flavor = "multi_thread")]
async fn exec_completes_on_child_exit_without_client_eof() {
    init_logging();
    let (addr, server_task) = start_shell_server().await;

    let result = tokio::time::timeout(TEST_TIMEOUT, async {
        // A no-stdin command; the client deliberately NEVER sends data or EOF.
        let (_session, mut read, _write) = open_exec_channel(addr, false, "echo hi").await;
        collect_until_close(&mut read).await
    })
    .await
    .expect(
        "timed out: channel never completed after child exit — before the fix the loop \
         waited for client EOF forever (defect 2 wedge)",
    );

    server_task.abort();
    assert_eq!(
        String::from_utf8_lossy(&result.stdout).trim(),
        "hi",
        "child stdout must be flushed before close",
    );
    assert_eq!(result.exit_status, Some(0), "expected clean exit status");
    assert!(result.closed, "channel must be closed by the server");
}

#[tokio::test(flavor = "multi_thread")]
async fn exec_cat_with_client_eof_still_round_trips_cleanly() {
    init_logging();
    let (addr, server_task) = start_shell_server().await;

    // Non-trivial payload so the child-exit select arm demonstrably doesn't
    // race the normal data path (guards the P2 stdin fix).
    let payload: Vec<u8> = (0..256 * 1024)
        .map(|i: usize| (i.wrapping_mul(31).wrapping_add(7)) as u8)
        .collect();

    let result = tokio::time::timeout(TEST_TIMEOUT, async {
        let (_session, mut read, write) = open_exec_channel(addr, false, "cat").await;
        for chunk in payload.chunks(32 * 1024) {
            write.data(chunk).await.unwrap();
        }
        write.eof().await.unwrap();
        collect_until_close(&mut read).await
    })
    .await
    .expect("timed out: normal cat + client-EOF path regressed");

    server_task.abort();
    assert_eq!(result.stdout.len(), payload.len(), "stdout truncated");
    assert_eq!(result.stdout, payload, "stdout corrupted");
    assert_eq!(result.exit_status, Some(0), "expected clean exit status");
    assert!(result.closed, "channel must be closed by the server");
}

// === Client helpers ===

struct ExecResult {
    stdout: Vec<u8>,
    exit_status: Option<u32>,
    closed: bool,
}

/// Connect, authenticate, open a session channel, and send `exec`. The
/// returned session handle must be kept alive for the duration of the exchange.
async fn open_exec_channel(
    addr: SocketAddr,
    want_reply: bool,
    command: &str,
) -> (
    client::Handle<ClientHandler>,
    russh::ChannelReadHalf,
    russh::ChannelWriteHalf<client::Msg>,
) {
    let config = Arc::new(client::Config::default());
    let mut session = client::connect(config, addr, ClientHandler)
        .await
        .expect("client connect");
    let auth = session
        .authenticate_none("user")
        .await
        .expect("authenticate_none");
    assert!(auth.success(), "auth failed");

    let channel = session
        .channel_open_session()
        .await
        .expect("channel_open_session");
    channel.exec(want_reply, command).await.expect("send exec");
    let (read, write) = channel.split();
    (session, read, write)
}

/// Drain the channel until the server closes it, collecting stdout/stderr and
/// the exit status.
async fn collect_until_close(read: &mut russh::ChannelReadHalf) -> ExecResult {
    let mut result = ExecResult {
        stdout: Vec::new(),
        exit_status: None,
        closed: false,
    };
    while let Some(msg) = read.wait().await {
        match msg {
            ChannelMsg::Data { data } => result.stdout.extend_from_slice(&data),
            ChannelMsg::ExtendedData { data, .. } => result.stdout.extend_from_slice(&data),
            ChannelMsg::ExitStatus { exit_status } => result.exit_status = Some(exit_status),
            ChannelMsg::Close => {
                result.closed = true;
                break;
            }
            _ => {}
        }
    }
    result
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

// === Server harness: the REAL extracted loop, no mirror ===

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

async fn start_shell_server() -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let addr = {
        use std::net::TcpListener;
        TcpListener::bind(("127.0.0.1", 0))
            .unwrap()
            .local_addr()
            .unwrap()
    };
    let task = tokio::spawn(async move {
        let config = Arc::new(server::Config {
            keys: vec![PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).unwrap()],
            ..Default::default()
        });
        let mut sh = ShellTestServer;
        sh.run_on_address(config, addr).await.unwrap();
    });
    for _ in 0..200 {
        if std::net::TcpStream::connect(addr).is_ok() {
            return (addr, task);
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("server did not come up at {addr}");
}

#[derive(Clone)]
struct ShellTestServer;

impl server::Server for ShellTestServer {
    type Handler = ShellTestHandler;

    fn new_client(&mut self, remote: Option<SocketAddr>) -> Self::Handler {
        ShellTestHandler {
            remote: remote.unwrap_or_else(|| ([127, 0, 0, 1], 0).into()),
        }
    }
}

#[derive(Clone)]
struct ShellTestHandler {
    remote: SocketAddr,
}

impl Handler for ShellTestHandler {
    type Error = russh::Error;

    async fn auth_none(&mut self, _user: &str) -> Result<Auth, Self::Error> {
        Ok(Auth::Accept)
    }

    async fn channel_open_session(
        &mut self,
        channel: russh::Channel<Msg>,
        session: &mut Session,
    ) -> Result<bool, Self::Error> {
        // Identical wiring to examples/ssh_shell/main.rs: per-channel task
        // running the REAL extracted loop.
        let remote = self.remote;
        let handle = session.handle();
        tokio::spawn(async move {
            channel_loop::run_session(channel, handle, remote).await;
        });
        Ok(true)
    }
}
