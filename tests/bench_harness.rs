//! Tests for the SSH data-plane quality harness (`examples/ssh_bench` +
//! `examples/ssh_bench_peer`).
//!
//! Two layers:
//!   * Pure unit tests of the shared PRNG (fixture-pinned so client and peer can
//!     never drift apart silently) and the stats helpers (percentiles, stall
//!     detection, SINK-line parsing).
//!   * One in-process end-to-end test: a loopback russh server (same shape as
//!     `tests/stress_ssh_heavy_transfer.rs`, i.e. the deployed `ssh_shell` exec
//!     path) whose exec spawns the locally built `ssh_bench_peer` binary, driven
//!     by the locally built `ssh_bench` binary running `all`. Proves latency,
//!     upload, download, and duplex all complete losslessly, and prints the
//!     loopback baseline numbers.

#[path = "../examples/ssh_bench_peer/prng.rs"]
mod prng;

#[path = "../examples/ssh_bench/stats.rs"]
mod stats;

use std::{
    net::SocketAddr,
    path::PathBuf,
    process::Stdio,
    sync::Arc,
    time::Duration,
};

use russh::{
    ChannelMsg,
    keys::{Algorithm, PrivateKey},
    server::{self, Auth, Handler, Msg, Server as _, Session},
};
use sha2::{Digest, Sha256};
use tokio::{io::AsyncWriteExt, process::Command};

// === PRNG unit tests ===

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[test]
fn prng_seed42_matches_pinned_fixture() {
    // Pinned against an independent (Python) xorshift64* implementation. If this
    // fails, client and peer would still agree with each other — but any deployed
    // older binary would not: never change the generator without a fleet story.
    let mut s = prng::PrngStream::new(42);
    let mut buf = [0u8; 32];
    s.fill(&mut buf);
    assert_eq!(
        hex(&buf),
        "a0a39b71b74ace56da2dbbeb53eb41c8760298c9e06b46cadf707b4a33c7acf1",
    );
}

#[test]
fn prng_zero_seed_is_remapped_not_stuck() {
    let mut s = prng::PrngStream::new(0);
    let mut buf = [0u8; 16];
    s.fill(&mut buf);
    assert_ne!(buf, [0u8; 16], "zero seed must not produce a zero stream");
}

#[test]
fn prng_stream_is_chunking_invariant() {
    // The byte stream must not depend on the caller's buffer sizes — the client
    // writes 64 KiB chunks while verification may see arbitrary channel-sized
    // chunks.
    let mut one_shot = vec![0u8; 1000];
    prng::PrngStream::new(7).fill(&mut one_shot);

    let mut chunked = Vec::with_capacity(1000);
    let mut generator = prng::PrngStream::new(7);
    for size in [1usize, 7, 13, 64, 3, 200, 712] {
        let mut buf = vec![0u8; size];
        generator.fill(&mut buf);
        chunked.extend_from_slice(&buf);
    }
    assert_eq!(chunked.len(), 1000);
    assert_eq!(chunked, one_shot);
}

#[test]
fn prng_1mib_sha256_matches_pinned_fixture() {
    let mut buf = vec![0u8; 1024 * 1024];
    prng::PrngStream::new(42).fill(&mut buf);
    let mut hasher = Sha256::new();
    hasher.update(&buf);
    assert_eq!(
        hex(&hasher.finalize()),
        "06c21eaf6bead7a456dbe52ac5ecf207108fdc48576903e4c6875d036a6fa64f",
    );
}

// === Stats unit tests ===

#[test]
fn percentile_uses_nearest_rank() {
    let v: Vec<f64> = (1..=100).map(f64::from).collect();
    assert_eq!(stats::percentile(&v, 50.0), 50.0);
    assert_eq!(stats::percentile(&v, 95.0), 95.0);
    let small = [30.0, 10.0, 20.0];
    assert_eq!(stats::percentile(&small, 50.0), 20.0);
    assert_eq!(stats::percentile(&small, 95.0), 30.0);
}

#[test]
fn summarize_reports_min_p50_p95_max() {
    let v: Vec<f64> = (1..=20).map(f64::from).collect();
    let s = stats::summarize(&v);
    assert_eq!((s.min, s.p50, s.p95, s.max), (1.0, 10.0, 19.0, 20.0));
}

#[test]
fn find_stalls_flags_flat_windows_over_threshold_only() {
    // up flatlines from t=2 to t=10 (8 s > 5 s); down advances every second.
    let samples: Vec<stats::Sample> = (0..=10)
        .map(|t| stats::Sample {
            t: t as f64,
            up: if t < 2 { t * 100 } else { 200 },
            down: t * 50,
        })
        .collect();
    let stalls = stats::find_stalls(&samples, true, true, 5.0);
    assert_eq!(stalls.len(), 1);
    assert_eq!(stalls[0].dir, "up");
    assert_eq!(stalls[0].start_t, 2.0);
    assert_eq!(stalls[0].secs, 8.0);

    // A 3 s flat window stays under the 5 s threshold.
    let short: Vec<stats::Sample> = (0..=5)
        .map(|t| stats::Sample {
            t: t as f64,
            up: if (2..=4).contains(&t) { 200 } else { t * 100 },
            down: 0,
        })
        .collect();
    assert!(stats::find_stalls(&short, true, false, 5.0).is_empty());
}

#[test]
fn parse_sink_extracts_the_peer_report() {
    let text = "noise before\nSINK sha256=ab12 bytes=1048576 secs=1.250\n";
    assert_eq!(
        stats::parse_sink(text),
        Some(stats::SinkReport {
            sha256: "ab12".into(),
            bytes: 1_048_576,
            secs: 1.25,
        }),
    );
    assert_eq!(stats::parse_sink("no sink here\n"), None);
}

// === In-process end-to-end: loopback server + real harness binaries ===

/// Build both example binaries (debug, same profile as this test) and return
/// their paths. A no-op when the workspace pre-built them.
fn build_examples() -> (PathBuf, PathBuf) {
    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".into());
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let status = std::process::Command::new(cargo)
        .current_dir(&manifest_dir)
        .args([
            "build",
            "--features",
            "ssh",
            "--example",
            "ssh_bench",
            "--example",
            "ssh_bench_peer",
        ])
        .status()
        .expect("spawn cargo build for harness examples");
    assert!(status.success(), "cargo build of harness examples failed");

    let target = std::env::var("CARGO_TARGET_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| manifest_dir.join("target"));
    let dir = target.join("debug").join("examples");
    let exe = std::env::consts::EXE_SUFFIX;
    (
        dir.join(format!("ssh_bench{exe}")),
        dir.join(format!("ssh_bench_peer{exe}")),
    )
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn bench_harness_all_phases_pass_losslessly_on_loopback() {
    let (bench_bin, peer_bin) = build_examples();
    assert!(peer_bin.is_file(), "missing {}", peer_bin.display());

    let addr = next_local_addr();
    let server_task = tokio::spawn(exec_server(addr));
    wait_for_listen(addr).await;

    // Debug-profile crypto is slow, so keep the payload modest — this is a
    // lossless-ness gate and a first baseline, not a throughput record.
    let out = Command::new(&bench_bin)
        .args([
            "--host",
            "127.0.0.1",
            "--port",
            &addr.port().to_string(),
            "--label",
            "loopback-ci",
            "--peer-cmd",
            peer_bin.to_str().expect("utf8 peer path"),
            "--timeout-secs",
            "120",
            "all",
            "--iters",
            "5",
            "--mib",
            "8",
        ])
        .stdin(Stdio::null())
        .output()
        .await
        .expect("run ssh_bench");
    server_task.abort();

    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    println!("--- ssh_bench loopback baseline (stderr summaries) ---\n{stderr}");

    let lines: Vec<serde_json::Value> = stdout
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| serde_json::from_str(l).unwrap_or_else(|e| panic!("bad JSON line `{l}`: {e}")))
        .collect();
    let by_phase = |p: &str| -> Vec<&serde_json::Value> {
        lines.iter().filter(|l| l["phase"] == p).collect()
    };

    // The four measurement phases: exactly one line each, all ok.
    for phase in ["latency", "upload", "download", "duplex", "concurrency"] {
        let v = by_phase(phase);
        assert_eq!(v.len(), 1, "expected one `{phase}` line:\n{stdout}");
        assert_eq!(
            v[0]["ok"],
            serde_json::Value::Bool(true),
            "phase {phase} failed: {}",
            v[0],
        );
    }
    // Concurrency ladder 1,2,4,8 → 15 per-session lines, every session passing.
    let sessions = by_phase("concurrency_session");
    assert_eq!(sessions.len(), 15, "expected 15 session lines:\n{stdout}");
    for s in &sessions {
        assert_eq!(
            s["pass"],
            serde_json::Value::Bool(true),
            "concurrent session failed: {s}",
        );
    }
    let concurrency = by_phase("concurrency")[0];
    assert_eq!(concurrency["max_all_pass"], serde_json::json!(8));
    assert_eq!(concurrency["first_any_fail"], serde_json::Value::Null);
    assert!(
        out.status.success(),
        "ssh_bench exited nonzero: {:?}\n{stderr}",
        out.status,
    );

    // Surface the baseline numbers in the test log (first data point of the
    // quality charter).
    println!(
        "baseline: exec_ready_ms p50={} | upload {} MB/s | download {} MB/s | duplex up {} / down {} MB/s | concurrency max_all_pass={}",
        by_phase("latency")[0]["exec_ready_ms"]["p50"],
        by_phase("upload")[0]["mb_s"],
        by_phase("download")[0]["mb_s"],
        by_phase("duplex")[0]["up_mb_s"],
        by_phase("duplex")[0]["down_mb_s"],
        concurrency["max_all_pass"],
    );
}

// === Loopback exec server (mirrors tests/stress_ssh_heavy_transfer.rs) ===

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

async fn exec_server(addr: SocketAddr) {
    let config = Arc::new(server::Config {
        keys: vec![PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).unwrap()],
        ..Default::default()
    });
    let mut sh = ExecServer;
    sh.run_on_address(config, addr).await.unwrap();
}

#[derive(Clone)]
struct ExecServer;

impl server::Server for ExecServer {
    type Handler = ExecHandler;

    fn new_client(&mut self, _: Option<SocketAddr>) -> Self::Handler {
        ExecHandler
    }
}

#[derive(Clone)]
struct ExecHandler;

impl Handler for ExecHandler {
    type Error = russh::Error;

    async fn auth_none(&mut self, _user: &str) -> Result<Auth, Self::Error> {
        Ok(Auth::Accept)
    }

    async fn channel_open_session(
        &mut self,
        channel: russh::Channel<Msg>,
        _session: &mut Session,
    ) -> Result<bool, Self::Error> {
        // Canonical russh per-channel task pattern (P2 exec-stdin fix): consume the
        // channel mpsc via `channel.wait()` — see stress_ssh_heavy_transfer.rs.
        tokio::spawn(async move { run_channel_loop(channel).await });
        Ok(true)
    }
}

async fn run_channel_loop(mut channel: russh::Channel<Msg>) {
    let command = loop {
        let Some(msg) = channel.wait().await else { return };
        match msg {
            ChannelMsg::Exec { command, .. } => {
                break String::from_utf8_lossy(&command).into_owned();
            }
            ChannelMsg::Eof | ChannelMsg::Close => return,
            _ => {}
        }
    };

    let (shell, flag) = if cfg!(windows) {
        ("cmd.exe", "/C")
    } else {
        ("/bin/sh", "-c")
    };
    let child = Command::new(shell)
        .arg(flag)
        .arg(&command)
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

    let mut channel_writer = channel.make_writer();
    let mut channel_stderr_writer = channel.make_writer_ext(Some(1));

    let stdout_task = tokio::spawn(async move {
        drop(tokio::io::copy(&mut child_stdout, &mut channel_writer).await);
    });
    let stderr_task = tokio::spawn(async move {
        drop(tokio::io::copy(&mut child_stderr, &mut channel_stderr_writer).await);
    });

    // Decouple the inbound channel.wait() loop from the pipe-write via an unbounded
    // mpsc — same shape as the P2 fix (see exec_stdin_integrity.rs).
    let (stdin_tx, mut stdin_rx) = tokio::sync::mpsc::unbounded_channel::<Vec<u8>>();
    let stdin_task = tokio::spawn(async move {
        let mut stdin = child_stdin;
        while let Some(chunk) = stdin_rx.recv().await {
            if stdin.write_all(&chunk).await.is_err() {
                break;
            }
        }
        // stdin drops → child sees EOF
    });

    loop {
        let Some(msg) = channel.wait().await else { break };
        match msg {
            ChannelMsg::Data { data } if stdin_tx.send(data.to_vec()).is_err() => break,
            ChannelMsg::Data { .. } => {}
            ChannelMsg::Eof => break,
            ChannelMsg::Close => break,
            _ => {}
        }
    }
    drop(stdin_tx);
    drop(stdin_task.await);
    drop(stdout_task.await);
    drop(stderr_task.await);

    let status = child.wait().await.ok();
    let code = status.and_then(|s| s.code().map(|c| c as u32)).unwrap_or(128);
    drop(channel.exit_status(code).await);
    drop(channel.eof().await);
    drop(channel.close().await);
}
