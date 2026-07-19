//! Per-channel session driver for the `ssh_shell` server.
//!
//! Extracted from `main.rs` so integration tests can run the REAL loop via a
//! `#[path]` include (see `tests/ssh_channel_protocol.rs`) instead of keeping a
//! mirror copy — a regression test against a mirror stays green while the
//! deployed shape breaks. Keep this module self-contained: no `crate::` /
//! `super::` references, so it compiles identically inside the example binary
//! and inside a test crate.

use std::process::Stdio;

use russh::{
    Channel, ChannelMsg,
    server::{Handle, Msg},
};
use tokio::{io::AsyncWriteExt, process::Command};

/// Platform's default shell + exec flag.
fn platform_shell() -> &'static str {
    if cfg!(windows) { "cmd.exe" } else { "/bin/sh" }
}

/// Flag that runs a single command line through [`platform_shell`].
fn platform_exec_flag() -> &'static str {
    if cfg!(windows) { "/C" } else { "-c" }
}

/// Per-channel session driver: spawn child on first exec/shell request, then
/// concurrently copy inbound data → child stdin and child stdout/stderr → client
/// until child exits or client closes.
///
/// `handle` is the session handle (`Session::handle()`), used to answer
/// `want_reply` exec/shell requests with channel_success / channel_failure
/// (RFC 4254 §6.5) — the reply goes through the session, which this loop
/// doesn't otherwise own.
pub async fn run_session(mut channel: Channel<Msg>, handle: Handle, remote: std::net::SocketAddr) {
    // Wait for an exec or shell request before spawning the child.
    let mut pending_command: Option<String> = None;
    let mut want_shell = false;
    // No dead initializer: every path that leaves the loop via `break` assigns
    // it, and every other path returns.
    let want_reply;
    loop {
        let Some(msg) = channel.wait().await else {
            return;
        };
        match msg {
            ChannelMsg::Exec { command, want_reply: reply_requested, .. } => {
                pending_command = Some(String::from_utf8_lossy(&command).into_owned());
                want_reply = reply_requested;
                break;
            }
            ChannelMsg::RequestShell { want_reply: reply_requested, .. } => {
                want_shell = true;
                want_reply = reply_requested;
                break;
            }
            ChannelMsg::Eof | ChannelMsg::Close => return,
            // PtyRequest is handled by the Handler::pty_request override in
            // main.rs (which replies through its own Session access). The
            // wait() loop just drops the message here.
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
        Err(e) => {
            tracing::error!(error = %e, channel = %channel.id(), shell, "spawning process");
            // RFC 4254 §6.5: a want_reply request must be answered. The request
            // was not honored, so reply channel_failure before tearing down.
            if want_reply {
                let _ = handle.channel_failure(channel.id()).await;
            }
            drop(channel.exit_status(127).await);
            drop(channel.eof().await);
            drop(channel.close().await);
            return;
        }
    };

    // RFC 4254 §6.5: answer a want_reply exec/shell request with
    // channel_success once the request is accepted (child spawned). Clients
    // that gate their I/O on the confirmation (openssh, russh with
    // exec(true, ..)) hang forever without this. Sent before the stdout/stderr
    // pumps start so the confirmation precedes any data.
    if want_reply {
        let _ = handle.channel_success(channel.id()).await;
    }

    tracing::info!(
        channel = %channel.id(),
        %remote,
        pid = child.id(),
        command = if cmd_str.is_empty() { shell } else { &cmd_str },
        "session started"
    );

    let child_stdin = child.stdin.take().unwrap();
    let mut child_stdout = child.stdout.take().unwrap();
    let mut child_stderr = child.stderr.take().unwrap();

    // Outbound pumps: child stdout/stderr → client via channel.make_writer_ext.
    // Owned writers; no borrow on `channel`, so they can move into separate tasks
    // while `channel` is retained for the inbound loop and final exit-status send.
    let mut stdout_writer = channel.make_writer();
    let mut stderr_writer = channel.make_writer_ext(Some(1));

    let stdout_task = tokio::spawn(async move {
        drop(tokio::io::copy(&mut child_stdout, &mut stdout_writer).await);
    });
    let stderr_task = tokio::spawn(async move {
        drop(tokio::io::copy(&mut child_stderr, &mut stderr_writer).await);
    });

    // Inbound: drain channel.wait() loop, forwarding Data to child's stdin via
    // an unbounded mpsc. The unbounded channel decouples the wait() loop from
    // the pipe-write (which can block on the child's stdin buffer), so the
    // dispatch mpsc is drained promptly even when the child is slow.
    let (stdin_tx, mut stdin_rx) = tokio::sync::mpsc::unbounded_channel::<Vec<u8>>();
    let channel_id = channel.id();
    let stdin_task = tokio::spawn(async move {
        let mut stdin = child_stdin;
        while let Some(chunk) = stdin_rx.recv().await {
            if stdin.write_all(&chunk).await.is_err() {
                break;
            }
        }
        // stdin drops here → child sees EOF on stdin
    });

    // Two independent completion triggers, either of which must be able to
    // finish the channel lifecycle (exit-status + eof + close):
    //   * client half-close (Eof/Close) — the normal `cat`-style path, where
    //     closing the child's stdin makes it exit; and
    //   * child exit — an exec that never reads stdin (`echo hi`) run by a
    //     client that never sends EOF. Waiting only for client EOF here wedged
    //     such sessions forever.
    let mut exit_seen: Option<u32> = None;
    let mut child_exit: Option<std::io::Result<std::process::ExitStatus>> = None;
    loop {
        tokio::select! {
            // Cancel-safe: tokio's Child::wait is explicitly cancel safe, and
            // mpsc recv (behind channel.wait) drops no message on cancel.
            status = child.wait() => {
                child_exit = Some(status);
                break;
            }
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
        }
    }
    drop(stdin_tx);
    drop(stdin_task.await);
    // The pumps finish when the child's pipes hit EOF, so on either trigger the
    // remaining stdout/stderr is flushed to the client before exit-status/close.
    drop(stdout_task.await);
    drop(stderr_task.await);

    let status = match child_exit {
        Some(status) => status,
        None => child.wait().await,
    };
    let code = match (exit_seen, status) {
        (Some(c), _) => c,
        (None, Ok(s)) => s.code().unwrap_or(128) as u32,
        (None, Err(_)) => 128,
    };
    tracing::info!(channel = %channel_id, exit_status = code, "session finished");
    drop(channel.exit_status(code).await);
    drop(channel.eof().await);
    drop(channel.close().await);
}
