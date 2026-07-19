//! ssh_bench_peer — remote-end helper for the SSH data-plane measurement harness.
//!
//! Runs ON the target box (Linux or the Win7-target Windows fleet), invoked over SSH
//! exec by `examples/ssh_bench`. Pure std + sha2 — no async runtime, no clap — so the
//! Win7 `-Z build-std` cross build stays trivially small and portable.
//!
//! Modes:
//!   * `--mode sink   --bytes N`            read exactly N bytes from stdin, print
//!     `SINK sha256=<hex> bytes=<n> secs=<f>` at EOF (exit 2 on short read).
//!   * `--mode source --bytes N --seed S`   write N deterministic xorshift64* bytes
//!     to stdout, then exit.
//!   * `--mode duplex --bytes N --seed S`   BOTH concurrently, on two independent
//!     threads (a stall in one direction is observable, never lockstep): hash N bytes
//!     from stdin while writing N seeded bytes to stdout; after both complete, print
//!     the SINK line to stdout.
//!
//! The SINK line reports the sha256 of whatever arrived on stdin, so the client can
//! verify upload integrity without a return payload.

mod prng;

use std::io::{Read, Write};
use std::time::Instant;

use prng::PrngStream;
use sha2::{Digest, Sha256};

const CHUNK: usize = 64 * 1024;

struct Args {
    mode: String,
    bytes: u64,
    seed: u64,
}

fn parse_args() -> Result<Args, String> {
    let mut mode = None;
    let mut bytes = None;
    let mut seed = 1u64;
    let mut it = std::env::args().skip(1);
    while let Some(flag) = it.next() {
        let mut val = || it.next().ok_or_else(|| format!("{flag} needs a value"));
        match flag.as_str() {
            "--mode" => mode = Some(val()?),
            "--bytes" => bytes = Some(val()?.parse::<u64>().map_err(|e| e.to_string())?),
            "--seed" => seed = val()?.parse::<u64>().map_err(|e| e.to_string())?,
            other => return Err(format!("unknown flag {other}")),
        }
    }
    Ok(Args {
        mode: mode.ok_or("--mode is required")?,
        bytes: bytes.ok_or("--bytes is required")?,
        seed,
    })
}

fn main() {
    let args = match parse_args() {
        Ok(a) => a,
        Err(e) => {
            eprintln!("ssh_bench_peer: {e}");
            eprintln!("usage: ssh_bench_peer --mode sink|source|duplex --bytes N [--seed S]");
            std::process::exit(64);
        }
    };
    let code = match args.mode.as_str() {
        "sink" => run_sink(args.bytes),
        "source" => run_source(args.bytes, args.seed),
        "duplex" => run_duplex(args.bytes, args.seed),
        other => {
            eprintln!("ssh_bench_peer: unknown mode {other}");
            64
        }
    };
    std::process::exit(code);
}

/// Read up to `want` bytes from stdin into a sha256; returns (bytes_read, hex, secs).
/// Stops early on EOF.
fn hash_stdin(want: u64) -> (u64, String, f64) {
    let start = Instant::now();
    let stdin = std::io::stdin();
    let mut lock = stdin.lock();
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; CHUNK];
    let mut got: u64 = 0;
    while got < want {
        let cap = std::cmp::min(CHUNK as u64, want - got) as usize;
        match lock.read(&mut buf[..cap]) {
            Ok(0) => break, // EOF
            Ok(n) => {
                hasher.update(&buf[..n]);
                got += n as u64;
            }
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => {
                eprintln!("ssh_bench_peer: stdin read error after {got} bytes: {e}");
                break;
            }
        }
    }
    let hex = hasher
        .finalize()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    (got, hex, start.elapsed().as_secs_f64())
}

/// Write exactly `total` seeded bytes to stdout (flushes at the end). Returns 0/1.
fn pump_source(total: u64, seed: u64) -> i32 {
    let stdout = std::io::stdout();
    let mut lock = stdout.lock();
    let mut generator = PrngStream::new(seed);
    let mut buf = vec![0u8; CHUNK];
    let mut left = total;
    while left > 0 {
        let n = std::cmp::min(CHUNK as u64, left) as usize;
        generator.fill(&mut buf[..n]);
        if let Err(e) = lock.write_all(&buf[..n]) {
            eprintln!("ssh_bench_peer: stdout write error with {left} bytes left: {e}");
            return 1;
        }
        left -= n as u64;
    }
    if let Err(e) = lock.flush() {
        eprintln!("ssh_bench_peer: stdout flush error: {e}");
        return 1;
    }
    0
}

fn print_sink_line(got: u64, hex: &str, secs: f64) {
    // Single line, parsed by the client — keep the format stable.
    println!("SINK sha256={hex} bytes={got} secs={secs:.3}");
    drop(std::io::stdout().flush());
}

fn run_sink(want: u64) -> i32 {
    let (got, hex, secs) = hash_stdin(want);
    print_sink_line(got, &hex, secs);
    if got == want { 0 } else { 2 }
}

fn run_source(total: u64, seed: u64) -> i32 {
    pump_source(total, seed)
}

fn run_duplex(bytes: u64, seed: u64) -> i32 {
    // Two independent OS threads: a stall in one direction never blocks the other,
    // so half-duplex lockstep at any layer below shows up as one-sided starvation
    // in the client's per-direction timeline instead of being masked here.
    let reader = std::thread::spawn(move || hash_stdin(bytes));
    let writer = std::thread::spawn(move || pump_source(bytes, seed));
    let write_code = writer.join().unwrap_or(1);
    let (got, hex, secs) = match reader.join() {
        Ok(r) => r,
        Err(_) => {
            eprintln!("ssh_bench_peer: reader thread panicked");
            return 1;
        }
    };
    print_sink_line(got, &hex, secs);
    if got == bytes && write_code == 0 { 0 } else { 2 }
}
