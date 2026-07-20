//! koidra_fetch — standalone HTTPS-to-disk primitive for the Koidra fleet.
//!
//! Downloads a URL to a path using reqwest + native-tls (SChannel on Windows,
//! OpenSSL on Linux). Bypasses .NET entirely, so it works on Win7/PS2.0 boxes where
//! PowerShell's `[Net.WebClient]::DownloadFile` fails (no TLS 1.2 in .NET 2.0 CLR).
//!
//! Ships inside the upgrade kit (`koidra-gateway-fleet/upgrade-kit-*/`). After the first
//! TeamViewer delivery of the kit to a Win7 box, `koidra_fetch.exe` is on-box
//! permanently and every subsequent transfer uses it over the network — no more
//! TeamViewer per roll.
//!
//! ## Usage
//!
//! ```text
//! koidra_fetch <URL> <OUTPUT_PATH> [--sha256 <HEX>] [--timeout <SECS>]
//!
//! Exit 0 on success (prints `<sha256> <size> <url>` to stdout).
//! Exit non-zero on any failure (HTTP error, sha256 mismatch, write error).
//! ```
//!
//! ## Atomicity
//!
//! Streams to `<OUTPUT_PATH>.tmp`, then renames to `<OUTPUT_PATH>` on success. A
//! crash mid-download leaves only the temp file; the destination is never partially
//! written. On sha256 mismatch the temp file is removed.
//!
//! ## Design
//!
//! This is deliberately NOT the full P4 self-updater (no manifest, no version check,
//! no supervisor integration — see `examples/koidra_gateway/updater.rs` for that). It's
//! the minimum primitive that unblocks transfers to Win7/PS2.0 boxes. The full
//! self-updater builds on the same reqwest + sha2 pattern but adds the state machine
//! + atomic binary swap + supervisor gate.

use std::path::PathBuf;

use clap::Parser;
use sha2::{Digest, Sha256};

/// Download a URL to a file via HTTPS, verifying sha256 if requested.
#[derive(Parser)]
#[command(version, about)]
struct Args {
    /// URL to download. HTTPS strongly recommended; HTTP works but is not the
    /// intended use case (fleet updates go through GitHub releases).
    url: String,

    /// Output path. Atomic: streams to `<path>.tmp` then renames on success.
    output: PathBuf,

    /// Expected sha256 of the downloaded bytes (hex, lowercase). If set, the
    /// download is verified before the atomic rename; mismatch removes the temp
    /// file and exits non-zero.
    #[arg(long)]
    sha256: Option<String>,

    /// Per-request timeout in seconds (connect + read). Default 120 s — generous
    /// for a ~10 MB binary on a restrictive EU customer uplink.
    #[arg(long, default_value_t = 120)]
    timeout: u64,
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::builder()
                .with_default_directive(tracing::Level::INFO.into())
                .from_env_lossy(),
        )
        .init();

    let args = Args::parse();

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(args.timeout))
        .build()?;

    tracing::info!(url = %args.url, output = %args.output.display(), "fetching");

    let resp = client.get(&args.url).send().await?;
    if !resp.status().is_success() {
        tracing::error!(status = %resp.status(), url = %args.url, "HTTP error");
        std::process::exit(2);
    }

    let bytes = resp.bytes().await?;

    // Hash while writing, so we can verify without re-reading the file.
    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    let actual_sha = hex_encode(&hasher.finalize());

    // Stream to temp file.
    let tmp = args.output.with_extension("koidra_fetch.tmp");
    tokio::fs::write(&tmp, &bytes).await?;

    // Verify sha256 before rename, if requested.
    if let Some(expected) = args.sha256.as_deref() {
        if !expected.eq_ignore_ascii_case(&actual_sha) {
            tracing::error!(
                expected = expected,
                actual = %actual_sha,
                "sha256 mismatch; removing temp file"
            );
            let _ = tokio::fs::remove_file(&tmp).await;
            std::process::exit(3);
        }
        tracing::info!(sha256 = %actual_sha, "sha256 verified");
    }

    // Atomic rename.
    tokio::fs::rename(&tmp, &args.output).await?;

    // Executable bit on Unix (Windows ignores this).
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = tokio::fs::metadata(&args.output).await?.permissions();
        perms.set_mode(0o755);
        tokio::fs::set_permissions(&args.output, perms).await?;
    }

    // Machine-readable line on stdout: `<sha256> <size> <url>`. Lets the caller
    // (supervisor script, operator, CI) capture + compare without parsing logs.
    println!("{} {} {}", actual_sha, bytes.len(), args.url);
    tracing::info!(
        sha256 = %actual_sha,
        size = bytes.len(),
        path = %args.output.display(),
        "download complete"
    );

    Ok(())
}

/// Hex-encode lowercase. Inlined to avoid the `hex` crate for one call site.
fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}
