//! ssh_bench — SSH data-plane QUALITY measurement harness (P2 charter).
//!
//! Measures — never stresses — the fork's SSH data plane against a deployed
//! `ssh_shell` (or any russh server with auth `none`): connection latency, bulk
//! throughput each direction, TRUE full-duplex behaviour, and end-to-end data
//! integrity. Pair it with `examples/ssh_bench_peer` running on the target box
//! (invoked via SSH exec; pass its absolute path with `--peer-cmd`).
//!
//! Phases (subcommands) — each emits ONE machine-readable JSON line to stdout and a
//! human summary to stderr; the JSON carries a per-second progress timeline that is
//! printed even on failure (that's the diagnostic gold for stalls):
//!   * `latency`   per-iteration TCP/SOCKS connect, SSH handshake+auth, and
//!     channel-open+exec-ready times; min/p50/p95/max each.
//!   * `upload`    stream N seeded bytes into `peer --mode sink`; verify the
//!     server-reported sha256; MB/s + timeline + stalls (>5 s no progress).
//!   * `download`  read N bytes from `peer --mode source`; verify against the local
//!     PRNG (first-mismatch offset on corruption); MB/s + timeline.
//!   * `duplex`    both directions at once against `peer --mode duplex`; verifies
//!     BOTH streams; per-direction MB/s + per-direction timeline — one-sided
//!     starvation or half-duplex lockstep shows up here.
//!   * `concurrency` open N SSH sessions to the target CONCURRENTLY (barrier-
//!     aligned; `--step` ladders 1,2,4,…,N), each doing a full handshake + a small
//!     integrity-verified exec round-trip. One JSON line per session (connect /
//!     handshake / exec ms + pass) plus an aggregate line (max N where ALL pass,
//!     first N where any fails) — quantifies the field defect where a channel
//!     serializes to ~1 usable session.
//!   * `all`       latency + upload + download + duplex + concurrency (1,2,4,8).
//!
//! Dial path: direct TCP, or `--socks5 host:port` for tailnets reachable only via a
//! userspace tailscaled's SOCKS5 (e.g. localhost:1055 on gti14).
//!
//! Exit code is non-zero if any phase times out or fails integrity.

mod stats;

#[path = "../ssh_bench_peer/prng.rs"]
mod prng;

use std::{
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

use clap::{Parser, Subcommand};
use prng::PrngStream;
use russh::{ChannelMsg, client};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use stats::{Sample, Summary};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};

const CHUNK: usize = 64 * 1024;
const STALL_SECS: f64 = 5.0;

#[derive(Parser)]
#[command(version, about = "SSH data-plane quality measurement harness")]
struct Cli {
    /// Target host (IP or name resolvable locally; with --socks5, resolved by the proxy).
    #[arg(long)]
    host: String,

    /// Target SSH port.
    #[arg(long, default_value_t = 22)]
    port: u16,

    /// Dial via a SOCKS5 proxy (`host:port`), e.g. 127.0.0.1:1055 for a userspace
    /// tailscaled. CONNECT only, no auth.
    #[arg(long)]
    socks5: Option<String>,

    /// Free-form label echoed into every JSON line (site name, path type, ...).
    #[arg(long, default_value = "bench")]
    label: String,

    /// Remote peer invocation (absolute path on the target box; `.exe` on Windows).
    #[arg(long, default_value = "./ssh_bench_peer")]
    peer_cmd: String,

    /// Hard per-phase timeout. On expiry the phase fails but its timeline is still printed.
    #[arg(long, default_value_t = 300)]
    timeout_secs: u64,

    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Connection-establishment latency percentiles.
    Latency {
        /// Number of full connect cycles to measure.
        #[arg(long, default_value_t = 20)]
        iters: u32,
    },
    /// Client → server bulk throughput + integrity.
    Upload {
        /// Payload size in MiB.
        #[arg(long, default_value_t = 32)]
        mib: u64,
        /// PRNG seed for the payload.
        #[arg(long, default_value_t = 42)]
        seed: u64,
    },
    /// Server → client bulk throughput + integrity.
    Download {
        /// Payload size in MiB.
        #[arg(long, default_value_t = 32)]
        mib: u64,
        /// PRNG seed for the payload.
        #[arg(long, default_value_t = 42)]
        seed: u64,
    },
    /// Simultaneous both-direction transfer + integrity of both streams.
    Duplex {
        /// Payload size PER DIRECTION in MiB.
        #[arg(long, default_value_t = 32)]
        mib: u64,
        /// PRNG seed for the client→server stream (server→client uses seed+1).
        #[arg(long, default_value_t = 42)]
        seed: u64,
    },
    /// N truly-concurrent SSH sessions, each with an integrity-verified exec round-trip.
    Concurrency {
        /// Number of concurrent sessions (the ladder top with --step).
        #[arg(long, default_value_t = 8)]
        sessions: u32,
        /// Ladder 1,2,4,… up to --sessions instead of a single rung.
        #[arg(long)]
        step: bool,
        /// Per-session handshake (and exec round-trip) timeout. Generous by
        /// default — 30 s false-fails on DERP relay paths.
        #[arg(long, default_value_t = 60)]
        handshake_timeout_secs: u64,
    },
    /// latency + upload + download + duplex + concurrency ladder 1,2,4,8.
    All {
        /// Latency iterations.
        #[arg(long, default_value_t = 20)]
        iters: u32,
        /// Payload size in MiB for each transfer phase.
        #[arg(long, default_value_t = 32)]
        mib: u64,
        /// PRNG seed.
        #[arg(long, default_value_t = 42)]
        seed: u64,
    },
}

#[derive(Clone, Copy)]
enum TransferKind {
    Upload,
    Download,
    Duplex,
}

impl TransferKind {
    fn name(self) -> &'static str {
        match self {
            TransferKind::Upload => "upload",
            TransferKind::Download => "download",
            TransferKind::Duplex => "duplex",
        }
    }
}

#[tokio::main]
async fn main() -> std::process::ExitCode {
    let cli = Cli::parse();
    let ok = match cli.cmd {
        Cmd::Latency { iters } => phase_latency(&cli, iters).await,
        Cmd::Upload { mib, seed } => phase_transfer(&cli, TransferKind::Upload, mib, seed).await,
        Cmd::Download { mib, seed } => {
            phase_transfer(&cli, TransferKind::Download, mib, seed).await
        }
        Cmd::Duplex { mib, seed } => phase_transfer(&cli, TransferKind::Duplex, mib, seed).await,
        Cmd::Concurrency {
            sessions,
            step,
            handshake_timeout_secs,
        } => phase_concurrency(&cli, sessions, step, handshake_timeout_secs).await,
        Cmd::All { iters, mib, seed } => {
            let mut ok = phase_latency(&cli, iters).await;
            ok &= phase_transfer(&cli, TransferKind::Upload, mib, seed).await;
            ok &= phase_transfer(&cli, TransferKind::Download, mib, seed).await;
            ok &= phase_transfer(&cli, TransferKind::Duplex, mib, seed).await;
            ok &= phase_concurrency(&cli, 8, true, 60).await;
            ok
        }
    };
    if ok {
        std::process::ExitCode::SUCCESS
    } else {
        std::process::ExitCode::FAILURE
    }
}

// === Dialing (direct or SOCKS5) ===

/// The connection endpoint, detached from `Cli` so concurrent session probes can
/// carry it into `'static` spawned tasks.
#[derive(Clone)]
struct Target {
    host: String,
    port: u16,
    socks5: Option<String>,
}

impl Cli {
    fn target(&self) -> Target {
        Target {
            host: self.host.clone(),
            port: self.port,
            socks5: self.socks5.clone(),
        }
    }
}

async fn dial(t: &Target) -> Result<TcpStream, String> {
    let stream = match &t.socks5 {
        None => TcpStream::connect((t.host.as_str(), t.port))
            .await
            .map_err(|e| format!("tcp connect {}:{}: {e}", t.host, t.port))?,
        Some(proxy) => socks5_connect(proxy, &t.host, t.port).await?,
    };
    drop(stream.set_nodelay(true));
    Ok(stream)
}

/// Minimal SOCKS5 CONNECT (RFC 1928), no auth, domain ATYP so the proxy resolves
/// tailnet names (MagicDNS) itself.
async fn socks5_connect(proxy: &str, host: &str, port: u16) -> Result<TcpStream, String> {
    let mut s = TcpStream::connect(proxy)
        .await
        .map_err(|e| format!("socks5 proxy connect {proxy}: {e}"))?;
    let io = |e: std::io::Error| format!("socks5 {proxy}: {e}");
    // Greeting: version 5, one method, NO AUTH.
    s.write_all(&[0x05, 0x01, 0x00]).await.map_err(io)?;
    let mut resp = [0u8; 2];
    s.read_exact(&mut resp).await.map_err(io)?;
    if resp != [0x05, 0x00] {
        return Err(format!("socks5 {proxy}: method negotiation rejected {resp:?}"));
    }
    // CONNECT to domain:port.
    let hb = host.as_bytes();
    if hb.len() > 255 {
        return Err(format!("socks5: host too long ({} bytes)", hb.len()));
    }
    let mut req = vec![0x05, 0x01, 0x00, 0x03, hb.len() as u8];
    req.extend_from_slice(hb);
    req.extend_from_slice(&port.to_be_bytes());
    s.write_all(&req).await.map_err(io)?;
    let mut head = [0u8; 4];
    s.read_exact(&mut head).await.map_err(io)?;
    if head[1] != 0x00 {
        return Err(format!(
            "socks5 CONNECT {host}:{port} refused, reply code {}",
            head[1]
        ));
    }
    // Skip the bound address (ATYP-dependent length) + port.
    let addr_len = match head[3] {
        0x01 => 4,
        0x04 => 16,
        0x03 => {
            let mut l = [0u8; 1];
            s.read_exact(&mut l).await.map_err(io)?;
            l[0] as usize
        }
        other => return Err(format!("socks5: unknown ATYP {other} in reply")),
    };
    let mut skip = vec![0u8; addr_len + 2];
    s.read_exact(&mut skip).await.map_err(io)?;
    Ok(s)
}

// === SSH client plumbing (auth `none`, mirrors tests/stress_ssh_heavy_transfer.rs) ===

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

/// Dial + SSH handshake + auth `none`. Returns the session handle and the two
/// timings (connect ms, handshake+auth ms).
async fn ssh_connect(t: &Target) -> Result<(client::Handle<ClientHandler>, f64, f64), String> {
    let t0 = Instant::now();
    let stream = dial(t).await?;
    let connect_ms = t0.elapsed().as_secs_f64() * 1e3;

    let t1 = Instant::now();
    let config = Arc::new(client::Config::default());
    let mut session = client::connect_stream(config, stream, ClientHandler)
        .await
        .map_err(|e| format!("ssh handshake: {e}"))?;
    let auth = session
        .authenticate_none("bench")
        .await
        .map_err(|e| format!("ssh auth: {e}"))?;
    if !auth.success() {
        return Err("ssh auth none rejected".into());
    }
    let handshake_ms = t1.elapsed().as_secs_f64() * 1e3;
    Ok((session, connect_ms, handshake_ms))
}

fn base_json(cli: &Cli, phase: &str) -> Value {
    json!({
        "harness": "ssh_bench",
        "label": cli.label,
        "phase": phase,
        "target": format!("{}:{}", cli.host, cli.port),
        "via_socks5": cli.socks5,
    })
}

fn emit(mut base: Value, extra: Value) {
    if let (Some(b), Some(e)) = (base.as_object_mut(), extra.as_object()) {
        for (k, v) in e {
            b.insert(k.clone(), v.clone());
        }
    }
    println!("{base}");
}

fn summary_json(s: &Summary) -> Value {
    json!({"min": round1(s.min), "p50": round1(s.p50), "p95": round1(s.p95), "max": round1(s.max)})
}

fn round1(v: f64) -> f64 {
    (v * 10.0).round() / 10.0
}

fn round2(v: f64) -> f64 {
    (v * 100.0).round() / 100.0
}

// === Phase: latency ===

async fn phase_latency(cli: &Cli, iters: u32) -> bool {
    let probe_cmd = format!("{} --mode source --bytes 0 --seed 1", cli.peer_cmd);
    let mut connect_ms = Vec::new();
    let mut handshake_ms = Vec::new();
    let mut exec_ready_ms = Vec::new();
    let mut errors: Vec<String> = Vec::new();

    let loop_all = async {
        for i in 0..iters {
            match latency_iter(cli, &probe_cmd).await {
                Ok((c, h, e)) => {
                    connect_ms.push(c);
                    handshake_ms.push(h);
                    exec_ready_ms.push(e);
                }
                Err(e) => errors.push(format!("iter {i}: {e}")),
            }
        }
    };
    let timed_out = tokio::time::timeout(Duration::from_secs(cli.timeout_secs), loop_all)
        .await
        .is_err();

    let ok = !timed_out && errors.is_empty() && !connect_ms.is_empty();
    let extra = json!({
        "ok": ok,
        "timed_out": timed_out,
        "iters_requested": iters,
        "iters_completed": connect_ms.len(),
        "connect_ms": summary_json(&stats::summarize(&connect_ms)),
        "handshake_ms": summary_json(&stats::summarize(&handshake_ms)),
        "exec_ready_ms": summary_json(&stats::summarize(&exec_ready_ms)),
        "errors": errors,
    });
    emit(base_json(cli, "latency"), extra);

    let c = stats::summarize(&connect_ms);
    let h = stats::summarize(&handshake_ms);
    let x = stats::summarize(&exec_ready_ms);
    eprintln!(
        "[latency] {}/{} iters ok={ok} connect p50={:.1}ms p95={:.1}ms | handshake p50={:.1}ms p95={:.1}ms | exec-ready p50={:.1}ms p95={:.1}ms",
        connect_ms.len(), iters, c.p50, c.p95, h.p50, h.p95, x.p50, x.p95,
    );
    ok
}

async fn latency_iter(cli: &Cli, probe_cmd: &str) -> Result<(f64, f64, f64), String> {
    let (session, connect_ms, handshake_ms) = ssh_connect(&cli.target()).await?;
    let t2 = Instant::now();
    let mut channel = session
        .channel_open_session()
        .await
        .map_err(|e| format!("channel open: {e}"))?;
    // want_reply=false: the fleet ssh_shell (per-channel-task russh pattern) never
    // answers exec requests, so a Success-wait would hang forever. Instead the
    // exec-ready timing is the full zero-byte probe round-trip: channel open +
    // exec dispatch + remote process spawn/exit + Eof back.
    channel
        .exec(false, probe_cmd)
        .await
        .map_err(|e| format!("exec: {e}"))?;
    // The server's per-channel loop (ssh_shell shape) only reaps the child and
    // sends exit/eof/close after the CLIENT half-closes — send eof immediately.
    channel.eof().await.map_err(|e| format!("eof: {e}"))?;
    while let Some(msg) = channel.wait().await {
        if matches!(msg, ChannelMsg::Eof | ChannelMsg::Close) {
            break;
        }
    }
    let exec_ready_ms = t2.elapsed().as_secs_f64() * 1e3;
    drop(
        session
            .disconnect(russh::Disconnect::ByApplication, "", "English")
            .await,
    );
    Ok((connect_ms, handshake_ms, exec_ready_ms))
}

// === Transfer phases (upload / download / duplex) ===

async fn phase_transfer(cli: &Cli, kind: TransferKind, mib: u64, seed: u64) -> bool {
    let n = mib * 1024 * 1024;
    let up = Arc::new(AtomicU64::new(0));
    let down = Arc::new(AtomicU64::new(0));
    let timeline = Arc::new(Mutex::new(Vec::<Sample>::new()));
    let start = Instant::now();

    let sampler = tokio::spawn(sampler_loop(
        start,
        up.clone(),
        down.clone(),
        timeline.clone(),
    ));
    let result = tokio::time::timeout(
        Duration::from_secs(cli.timeout_secs),
        transfer_core(cli, kind, n, seed, up.clone(), down.clone()),
    )
    .await;
    sampler.abort();
    let secs = start.elapsed().as_secs_f64();

    let mut samples = timeline.lock().expect("sampler poisoned").clone();
    samples.push(Sample {
        t: secs,
        up: up.load(Ordering::Relaxed),
        down: down.load(Ordering::Relaxed),
    });
    let (track_up, track_down) = match kind {
        TransferKind::Upload => (true, false),
        TransferKind::Download => (false, true),
        TransferKind::Duplex => (true, true),
    };
    let stalls = stats::find_stalls(&samples, track_up, track_down, STALL_SECS);

    let (extra, error) = match result {
        Err(_) => (
            json!({}),
            Some(format!(
                "timeout: phase did not complete within {}s",
                cli.timeout_secs
            )),
        ),
        Ok(Err(e)) => (json!({}), Some(e)),
        Ok(Ok(extra)) => (extra, None),
    };
    let integrity_ok = extra
        .get("integrity_ok")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let ok = error.is_none() && integrity_ok;

    let timeline_json: Vec<Value> = samples
        .iter()
        .map(|s| json!({"t": round1(s.t), "up": s.up, "down": s.down}))
        .collect();
    let stalls_json: Vec<Value> = stalls
        .iter()
        .map(|s| json!({"dir": s.dir, "start_t": round1(s.start_t), "secs": round1(s.secs)}))
        .collect();
    let mut out = json!({
        "ok": ok,
        "mib_per_direction": mib,
        "seed": seed,
        "secs": round2(secs),
        "up_bytes": up.load(Ordering::Relaxed),
        "down_bytes": down.load(Ordering::Relaxed),
        "error": error,
        "stalls": stalls_json,
        "timeline": timeline_json,
    });
    if let (Some(o), Some(e)) = (out.as_object_mut(), extra.as_object()) {
        for (k, v) in e {
            o.insert(k.clone(), v.clone());
        }
    }
    emit(base_json(cli, kind.name()), out);

    let err_str = if ok {
        String::new()
    } else {
        format!(" ERROR={}", extra.get("integrity_error").and_then(Value::as_str).unwrap_or("see json"))
    };
    eprintln!(
        "[{}] ok={ok} {}s up={}B down={}B stalls={}{}",
        kind.name(),
        round2(secs),
        up.load(Ordering::Relaxed),
        down.load(Ordering::Relaxed),
        stalls.len(),
        err_str,
    );
    ok
}

async fn sampler_loop(
    start: Instant,
    up: Arc<AtomicU64>,
    down: Arc<AtomicU64>,
    timeline: Arc<Mutex<Vec<Sample>>>,
) {
    let mut tick = tokio::time::interval(Duration::from_secs(1));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    tick.tick().await; // completes immediately; samples start at ~1s
    loop {
        tick.tick().await;
        timeline.lock().expect("sampler poisoned").push(Sample {
            t: start.elapsed().as_secs_f64(),
            up: up.load(Ordering::Relaxed),
            down: down.load(Ordering::Relaxed),
        });
    }
}

/// The remote stream of a duplex phase uses the next seed so the two directions
/// carry provably different data.
fn remote_seed(seed: u64) -> u64 {
    seed.wrapping_add(1)
}

async fn transfer_core(
    cli: &Cli,
    kind: TransferKind,
    n: u64,
    seed: u64,
    up: Arc<AtomicU64>,
    down: Arc<AtomicU64>,
) -> Result<Value, String> {
    let (session, _, _) = ssh_connect(&cli.target()).await?;
    let remote_cmd = match kind {
        TransferKind::Upload => format!("{} --mode sink --bytes {n}", cli.peer_cmd),
        TransferKind::Download => {
            format!("{} --mode source --bytes {n} --seed {seed}", cli.peer_cmd)
        }
        TransferKind::Duplex => format!(
            "{} --mode duplex --bytes {n} --seed {}",
            cli.peer_cmd,
            remote_seed(seed)
        ),
    };
    let channel = session
        .channel_open_session()
        .await
        .map_err(|e| format!("channel open: {e}"))?;
    // want_reply=false — see latency_iter: the fleet server never replies.
    channel
        .exec(false, remote_cmd.as_str())
        .await
        .map_err(|e| format!("exec `{remote_cmd}`: {e}"))?;
    let (read, write) = channel.split();

    let extra = match kind {
        TransferKind::Upload => run_upload(read, write, n, seed, up, down).await?,
        TransferKind::Download => run_download(read, write, n, seed, down).await?,
        TransferKind::Duplex => run_duplex(read, write, n, seed, up, down).await?,
    };
    drop(
        session
            .disconnect(russh::Disconnect::ByApplication, "", "English")
            .await,
    );
    Ok(extra)
}

/// Stream `n` seeded bytes into the channel, hashing locally. Returns (sha_hex, secs).
async fn push_seeded(
    write: &russh::ChannelWriteHalf<client::Msg>,
    n: u64,
    seed: u64,
    up: &AtomicU64,
) -> Result<(String, f64), String> {
    let start = Instant::now();
    let mut generator = PrngStream::new(seed);
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; CHUNK];
    let mut left = n;
    let mut sent = 0u64;
    while left > 0 {
        let take = std::cmp::min(CHUNK as u64, left) as usize;
        generator.fill(&mut buf[..take]);
        hasher.update(&buf[..take]);
        write
            .data(&buf[..take])
            .await
            .map_err(|e| format!("write after {sent} bytes: {e}"))?;
        sent += take as u64;
        left -= take as u64;
        up.fetch_add(take as u64, Ordering::Relaxed);
        // Yield periodically so the read pump gets scheduler time on large pushes
        // (same rationale as tests/stress_ssh_heavy_transfer.rs).
        if sent.is_multiple_of(4 * 1024 * 1024) {
            tokio::task::yield_now().await;
        }
    }
    write.eof().await.map_err(|e| format!("eof: {e}"))?;
    Ok((hex(hasher), start.elapsed().as_secs_f64()))
}

fn hex(hasher: Sha256) -> String {
    hasher
        .finalize()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// What the read half saw: raw stdout, stderr text, exit status.
struct ReadResult {
    stdout: Vec<u8>,
    stderr: String,
    exit_status: Option<u32>,
}

/// Drain the read half to Eof/Close, verifying the first `expect_payload` bytes
/// against `verify_seed`'s PRNG stream when set; bytes beyond the payload are kept
/// raw in `stdout` (the peer's SINK trailer). `payload_secs_out` gets the time the
/// payload completed.
async fn drain_read(
    mut read: russh::ChannelReadHalf,
    expect_payload: u64,
    verify_seed: Option<u64>,
    down: &AtomicU64,
) -> (ReadResult, u64, Option<u64>, f64) {
    let start = Instant::now();
    let mut expect_gen = verify_seed.map(PrngStream::new);
    let mut expect_buf = vec![0u8; CHUNK];
    let mut payload_seen = 0u64;
    let mut mismatch_at: Option<u64> = None;
    let mut payload_secs = 0.0f64;
    let mut out = ReadResult {
        stdout: Vec::new(),
        stderr: String::new(),
        exit_status: None,
    };
    while let Some(msg) = read.wait().await {
        match msg {
            ChannelMsg::Data { data } => {
                down.fetch_add(data.len() as u64, Ordering::Relaxed);
                let mut chunk: &[u8] = &data;
                // Split the payload prefix from any trailer.
                if payload_seen < expect_payload {
                    let take =
                        std::cmp::min(chunk.len() as u64, expect_payload - payload_seen) as usize;
                    if let Some(generator) = expect_gen.as_mut() {
                        if mismatch_at.is_none() {
                            if expect_buf.len() < take {
                                expect_buf.resize(take, 0);
                            }
                            generator.fill(&mut expect_buf[..take]);
                            if expect_buf[..take] != chunk[..take] {
                                let off = expect_buf[..take]
                                    .iter()
                                    .zip(&chunk[..take])
                                    .position(|(a, b)| a != b)
                                    .unwrap_or(0)
                                    as u64;
                                mismatch_at = Some(payload_seen + off);
                            }
                        }
                    } else {
                        // No verification requested (upload phase): payload prefix is
                        // still counted, but content is the peer's to define.
                        out.stdout.extend_from_slice(&chunk[..take]);
                    }
                    payload_seen += take as u64;
                    if payload_seen == expect_payload {
                        payload_secs = start.elapsed().as_secs_f64();
                    }
                    chunk = &chunk[take..];
                }
                if !chunk.is_empty() {
                    out.stdout.extend_from_slice(chunk);
                }
            }
            ChannelMsg::ExtendedData { data, .. } => {
                out.stderr.push_str(&String::from_utf8_lossy(&data));
            }
            ChannelMsg::ExitStatus { exit_status } => out.exit_status = Some(exit_status),
            ChannelMsg::Eof | ChannelMsg::Close => break,
            _ => {}
        }
    }
    if payload_secs == 0.0 {
        payload_secs = start.elapsed().as_secs_f64();
    }
    (out, payload_seen, mismatch_at, payload_secs)
}

async fn run_upload(
    read: russh::ChannelReadHalf,
    write: russh::ChannelWriteHalf<client::Msg>,
    n: u64,
    seed: u64,
    up: Arc<AtomicU64>,
    down: Arc<AtomicU64>,
) -> Result<Value, String> {
    let (push_res, (rres, _, _, _)) = tokio::join!(
        push_seeded(&write, n, seed, &up),
        // Upload: no payload expected back — everything on stdout is the SINK line.
        drain_read(read, 0, None, &down),
    );
    let (local_sha, push_secs) = push_res?;
    let stdout_text = String::from_utf8_lossy(&rres.stdout).into_owned();
    let sink = stats::parse_sink(&stdout_text);
    let (integrity_ok, integrity_error) = verify_sink(&sink, n, &local_sha);
    Ok(json!({
        "integrity_ok": integrity_ok,
        "integrity_error": integrity_error,
        "mb_s": round2(mb_per_sec(n, push_secs)),
        "push_secs": round2(push_secs),
        "local_sha256": local_sha,
        "sink": sink_json(&sink),
        "exit_status": rres.exit_status,
        "stderr": rres.stderr,
    }))
}

async fn run_download(
    read: russh::ChannelReadHalf,
    write: russh::ChannelWriteHalf<client::Msg>,
    n: u64,
    seed: u64,
    down: Arc<AtomicU64>,
) -> Result<Value, String> {
    // Nothing to send: close our side immediately so the peer sees stdin EOF.
    write.eof().await.map_err(|e| format!("eof: {e}"))?;
    let (rres, payload_seen, mismatch_at, payload_secs) =
        drain_read(read, n, Some(seed), &down).await;
    let mut integrity_error = None;
    if payload_seen != n {
        integrity_error = Some(format!("short read: got {payload_seen} of {n} bytes"));
    }
    if let Some(off) = mismatch_at {
        integrity_error = Some(format!("payload mismatch at byte offset {off}"));
    }
    Ok(json!({
        "integrity_ok": integrity_error.is_none(),
        "integrity_error": integrity_error,
        "mb_s": round2(mb_per_sec(payload_seen, payload_secs)),
        "payload_secs": round2(payload_secs),
        "bytes_received": payload_seen,
        "mismatch_at": mismatch_at,
        "exit_status": rres.exit_status,
        "stderr": rres.stderr,
    }))
}

async fn run_duplex(
    read: russh::ChannelReadHalf,
    write: russh::ChannelWriteHalf<client::Msg>,
    n: u64,
    seed: u64,
    up: Arc<AtomicU64>,
    down: Arc<AtomicU64>,
) -> Result<Value, String> {
    // Two truly concurrent futures over the split halves: a lockstep/half-duplex
    // regression in any layer below turns into one direction's timeline flatlining
    // while the other advances — visible in the per-second samples.
    let (push_res, (rres, payload_seen, mismatch_at, payload_secs)) = tokio::join!(
        push_seeded(&write, n, seed, &up),
        drain_read(read, n, Some(remote_seed(seed)), &down),
    );
    let (local_sha, push_secs) = push_res?;
    let stdout_text = String::from_utf8_lossy(&rres.stdout).into_owned();
    let sink = stats::parse_sink(&stdout_text);

    let mut integrity_error: Option<String> = None;
    if payload_seen != n {
        integrity_error = Some(format!("down short read: got {payload_seen} of {n} bytes"));
    }
    if let Some(off) = mismatch_at {
        integrity_error = Some(format!("down payload mismatch at byte offset {off}"));
    }
    if integrity_error.is_none() {
        let (up_ok, up_err) = verify_sink(&sink, n, &local_sha);
        if !up_ok {
            integrity_error = up_err;
        }
    }
    Ok(json!({
        "integrity_ok": integrity_error.is_none(),
        "integrity_error": integrity_error,
        "up_mb_s": round2(mb_per_sec(n, push_secs)),
        "down_mb_s": round2(mb_per_sec(payload_seen, payload_secs)),
        "push_secs": round2(push_secs),
        "payload_secs": round2(payload_secs),
        "local_sha256": local_sha,
        "sink": sink_json(&sink),
        "mismatch_at": mismatch_at,
        "exit_status": rres.exit_status,
        "stderr": rres.stderr,
    }))
}

// === Phase: concurrency ===

/// Bytes each concurrent session pushes through `--mode sink` for its
/// integrity-verified exec round-trip.
const CONCURRENCY_PROBE_BYTES: u64 = 64 * 1024;

struct SessionResult {
    session: u32,
    connect_ms: f64,
    handshake_ms: f64,
    exec_ms: f64,
    pass: bool,
    error: Option<String>,
}

async fn phase_concurrency(cli: &Cli, sessions: u32, step: bool, hs_timeout: u64) -> bool {
    let sessions = sessions.max(1);
    let ladder: Vec<u32> = if step {
        let mut v = Vec::new();
        let mut n = 1;
        while n < sessions {
            v.push(n);
            n *= 2;
        }
        v.push(sessions);
        v
    } else {
        vec![sessions]
    };

    let mut max_all_pass = 0u32;
    let mut first_any_fail: Option<u32> = None;
    for &n in &ladder {
        let results = match tokio::time::timeout(
            Duration::from_secs(cli.timeout_secs),
            concurrency_rung(cli, n, hs_timeout),
        )
        .await
        {
            Ok(r) => r,
            Err(_) => vec![SessionResult {
                session: 0,
                connect_ms: 0.0,
                handshake_ms: 0.0,
                exec_ms: 0.0,
                pass: false,
                error: Some(format!(
                    "rung of {n} sessions did not complete within {}s",
                    cli.timeout_secs
                )),
            }],
        };
        let mut passed = 0u32;
        for r in &results {
            if r.pass {
                passed += 1;
            }
            emit(
                base_json(cli, "concurrency_session"),
                json!({
                    "sessions": n,
                    "session": r.session,
                    "connect_ms": round1(r.connect_ms),
                    "handshake_ms": round1(r.handshake_ms),
                    "exec_ms": round1(r.exec_ms),
                    "pass": r.pass,
                    "error": r.error,
                }),
            );
        }
        let all_pass = passed == n && results.len() as u32 == n;
        eprintln!("[concurrency] rung {n}: {passed}/{n} sessions passed");
        if all_pass {
            max_all_pass = n;
        } else if first_any_fail.is_none() {
            first_any_fail = Some(n);
        }
    }

    let ok = first_any_fail.is_none();
    emit(
        base_json(cli, "concurrency"),
        json!({
            "ok": ok,
            "ladder": ladder,
            "max_all_pass": max_all_pass,
            "first_any_fail": first_any_fail,
            "handshake_timeout_secs": hs_timeout,
            "probe_bytes": CONCURRENCY_PROBE_BYTES,
        }),
    );
    eprintln!(
        "[concurrency] ok={ok} max_all_pass={max_all_pass} first_any_fail={first_any_fail:?}"
    );
    ok
}

/// Run one rung: `n` sessions, all released from a barrier so they dial
/// simultaneously — a target that serializes to ~1 usable session shows up as
/// n-1 handshake timeouts, not as a politely queued success.
async fn concurrency_rung(cli: &Cli, n: u32, hs_timeout: u64) -> Vec<SessionResult> {
    let barrier = Arc::new(tokio::sync::Barrier::new(n as usize));
    let mut set = tokio::task::JoinSet::new();
    for i in 0..n {
        let target = cli.target();
        let peer_cmd = cli.peer_cmd.clone();
        let barrier = barrier.clone();
        set.spawn(async move { session_probe(i, target, peer_cmd, hs_timeout, barrier).await });
    }
    let mut results = Vec::with_capacity(n as usize);
    while let Some(joined) = set.join_next().await {
        results.push(joined.unwrap_or_else(|e| SessionResult {
            session: u32::MAX,
            connect_ms: 0.0,
            handshake_ms: 0.0,
            exec_ms: 0.0,
            pass: false,
            error: Some(format!("probe task panicked: {e}")),
        }));
    }
    results.sort_by_key(|r| r.session);
    results
}

async fn session_probe(
    session_idx: u32,
    target: Target,
    peer_cmd: String,
    hs_timeout: u64,
    barrier: Arc<tokio::sync::Barrier>,
) -> SessionResult {
    let mut out = SessionResult {
        session: session_idx,
        connect_ms: 0.0,
        handshake_ms: 0.0,
        exec_ms: 0.0,
        pass: false,
        error: None,
    };
    barrier.wait().await;

    let handle = match tokio::time::timeout(
        Duration::from_secs(hs_timeout),
        ssh_connect(&target),
    )
    .await
    {
        Err(_) => {
            out.error = Some(format!("handshake timeout after {hs_timeout}s"));
            return out;
        }
        Ok(Err(e)) => {
            out.error = Some(e);
            return out;
        }
        Ok(Ok((handle, connect_ms, handshake_ms))) => {
            out.connect_ms = connect_ms;
            out.handshake_ms = handshake_ms;
            handle
        }
    };

    let seed = 0xC0FF_EE00 ^ u64::from(session_idx);
    let t0 = Instant::now();
    let exec_result = tokio::time::timeout(Duration::from_secs(hs_timeout), async {
        let channel = handle
            .channel_open_session()
            .await
            .map_err(|e| format!("channel open: {e}"))?;
        // want_reply=false — see latency_iter: the fleet server never replies.
        channel
            .exec(
                false,
                format!("{peer_cmd} --mode sink --bytes {CONCURRENCY_PROBE_BYTES}"),
            )
            .await
            .map_err(|e| format!("exec: {e}"))?;
        let (read, write) = channel.split();
        let up = AtomicU64::new(0);
        let down = AtomicU64::new(0);
        let (push_res, (rres, _, _, _)) = tokio::join!(
            push_seeded(&write, CONCURRENCY_PROBE_BYTES, seed, &up),
            drain_read(read, 0, None, &down),
        );
        let (local_sha, _) = push_res?;
        let sink = stats::parse_sink(&String::from_utf8_lossy(&rres.stdout));
        let (sha_ok, sha_err) = verify_sink(&sink, CONCURRENCY_PROBE_BYTES, &local_sha);
        if sha_ok {
            Ok(())
        } else {
            Err(sha_err.unwrap_or_else(|| "integrity failure".into()))
        }
    })
    .await;
    match exec_result {
        Err(_) => out.error = Some(format!("exec round-trip timeout after {hs_timeout}s")),
        Ok(Err(e)) => out.error = Some(e),
        Ok(Ok(())) => {
            out.exec_ms = t0.elapsed().as_secs_f64() * 1e3;
            out.pass = true;
        }
    }
    drop(
        handle
            .disconnect(russh::Disconnect::ByApplication, "", "English")
            .await,
    );
    out
}

/// Check the peer's SINK report against what we sent.
fn verify_sink(
    sink: &Option<stats::SinkReport>,
    n: u64,
    local_sha: &str,
) -> (bool, Option<String>) {
    match sink {
        None => (false, Some("no SINK line in peer stdout".into())),
        Some(s) if s.bytes != n => (
            false,
            Some(format!("peer received {} of {} bytes", s.bytes, n)),
        ),
        Some(s) if s.sha256 != local_sha => (
            false,
            Some(format!("sha mismatch: local {local_sha} != peer {}", s.sha256)),
        ),
        Some(_) => (true, None),
    }
}

fn sink_json(sink: &Option<stats::SinkReport>) -> Value {
    match sink {
        None => Value::Null,
        Some(s) => json!({"sha256": s.sha256, "bytes": s.bytes, "secs": s.secs}),
    }
}

fn mb_per_sec(bytes: u64, secs: f64) -> f64 {
    if secs <= 0.0 {
        return 0.0;
    }
    bytes as f64 / 1e6 / secs
}
