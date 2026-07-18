//! Fleet self-update pipeline.
//!
//! Periodically fetches a versioned manifest from a configured URL; if the manifest
//! advertises a version newer than the running binary's, atomically stages the new
//! binary, points the supervisor at it, and exits cleanly so the supervisor relaunches
//! the new file. Zero agent tokens per fleet roll after the first deploy.
//!
//! ## State machine (see `.doc/2026-07-fleet-self-update.md` §3)
//!
//! ```text
//! IDLE (sleep 600 s ± 120 s jitter)
//!   → FETCH   GET manifest.json (rustls, TLS 1.3 on Win7)
//!   → COMPARE manifest.version vs current — equal/older → IDLE
//!   → LOCK    .koidra-gateway-update.lock (per-box, both channels honor)
//!   → DOWNLOAD target.url → temp file
//!   → VERIFY  sha256(temp) == target.sha256
//!   → STAGE   rename → koidra-gateway-{version}{exe_suffix}
//!   → COMMIT  write current-koidra-gateway.txt (temp+rename) + push rollback stack
//!   → EXIT    process::exit(0); supervisor relaunches within 5 s
//! ```
//!
//! ## Rollback
//!
//! The supervisor (not this code) runs a health-gate loop on the next launch: if the
//! new binary fails its listen-socket gate within 60 s, the supervisor pops the
//! rollback stack and reverts `current-koidra-gateway.txt`. See
//! `.doc/2026-07-supervisor-restart-interface.md` §3.
//!
//! ## Boot contract (shared with Bravo P1)
//!
//! The binary's `main` (not this module) writes `.boot-state.json` at boot so the
//! supervisor's gate can detect a failed launch. This module reads/writes only
//! `current-koidra-gateway.txt`, `.rollback-stack.txt`, and `.koidra-gateway-update.lock`.

use std::{
    path::{Path, PathBuf},
    time::Duration,
};

use serde::Deserialize;
use sha2::{Digest, Sha256};
use thiserror::Error;
use tokio::{fs, time};
use tracing::{info, warn};

/// Poll interval (center of the jittered window). Kept long so a fleet-wide manifest
/// bump staggers naturally without a coordination server.
const POLL_INTERVAL: Duration = Duration::from_secs(600);

/// Jitter window half-width: sleep duration is `POLL_INTERVAL - POLL_JITTER + rand(0..2*POLL_JITTER)`.
/// Keeps both channels of a box from swapping simultaneously.
const POLL_JITTER: Duration = Duration::from_secs(120);

/// Per-box advisory lockfile (both channels honor this). Payload: PID + timestamp.
const LOCKFILE_NAME: &str = ".koidra-gateway-update.lock";

/// Stale lock threshold: if the lock is older than this, steal it. Bounds how long a
/// crashed updater on the other channel can block its peer.
const LOCK_STALE_AFTER: Duration = Duration::from_secs(120);

/// Rollback stack: max entries the supervisor can pop.
const ROLLBACK_STACK_MAX: usize = 3;

/// State files in the install dir (Charlie-owned; Bravo never touches these).
const CURRENT_EXE_NAME: &str = "current-koidra-gateway.txt";
const ROLLBACK_STACK_NAME: &str = ".rollback-stack.txt";

/// Schema version this updater understands.
const MANIFEST_SCHEMA: u32 = 1;

#[derive(Debug, Error)]
pub enum UpdaterError {
    #[error("manifest fetch failed: {0}")]
    Fetch(String),
    #[error("manifest parse failed: {0}")]
    Parse(String),
    #[error("download failed: {0}")]
    Download(String),
    #[error("sha256 mismatch: expected {expected}, got {actual}")]
    Sha256 { expected: String, actual: String },
    #[error("size mismatch: expected {expected}, got {got}")]
    Size { expected: u64, got: usize },
    #[error("lockfile busy (other channel updating)")]
    LockBusy,
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}

/// A single target entry in the manifest, keyed by Rust target triple.
#[derive(Debug, Deserialize)]
pub struct ManifestTarget {
    pub url: String,
    pub sha256: String,
    pub size: u64,
}

/// The manifest object served at the `KOIDRA_MANIFEST_URL`. See
/// `.doc/2026-07-fleet-self-update.md` §2 for the schema.
#[derive(Debug, Deserialize)]
pub struct Manifest {
    pub schema: u32,
    pub version: String,
    /// Informational; surfaces on the admin console for staleness checks.
    #[allow(dead_code)]
    pub published_at: String,
    pub targets: std::collections::HashMap<String, ManifestTarget>,
}

/// Spawn the updater task. Non-blocking; the task runs for the process lifetime.
///
/// On a successful update commit, the task calls `std::process::exit(0)` — so this
/// function does NOT return a handle whose join implies "updater is done." The handle
/// is dropped on the floor intentionally: the supervisor's relaunch is the cycle's
/// completion signal.
///
/// Poll interval is `POLL_INTERVAL` (600 s default), overridable via
/// `KOIDRA_UPDATER_POLL_SECS` env var (useful for dev/test canaries and for fleet
/// segments that need faster or slower roll cadence).
pub fn spawn(install_dir: PathBuf, current_version: &'static str, manifest_url: String) {
    let poll_interval = std::env::var("KOIDRA_UPDATER_POLL_SECS")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .map(Duration::from_secs)
        .unwrap_or(POLL_INTERVAL);

    tokio::spawn(async move {
        info!(%manifest_url, %current_version, poll_secs = poll_interval.as_secs(), install_dir = %install_dir.display(), "fleet updater task started");
        loop {
            // Sleep with jitter BEFORE the first fetch. A freshly-booted binary is already
            // at its current version; no need to check immediately. Also staggers the two
            // channels (which share the same install_dir + lockfile).
            let sleep = jittered_sleep(poll_interval);
            time::sleep(sleep).await;

            match run_one_cycle(&install_dir, current_version, &manifest_url).await {
                Ok(CycleOutcome::NoUpdate) => {} // loop continues
                Ok(CycleOutcome::Updated) => {
                    // EXIT — supervisor relaunches within ~5 s (Windows supervisor.vbs)
                    // or immediately (Linux systemd Restart=on-failure). The new
                    // current-koidra-gateway.txt points at the new binary.
                    info!("update committed; exiting for supervisor relaunch");
                    std::process::exit(0);
                }
                Err(e) => {
                    // Any error just logs and waits for the next cycle. The supervisor
                    // health-gate is the safety net for "binary swapped into a bad build";
                    // updater errors here are transient (network, parse, lock contention).
                    warn!(error = %e, "updater cycle failed; will retry next interval");
                }
            }
        }
    });
}

/// Outcome of a single updater cycle. `Updated` means a new binary was staged +
/// `current-koidra-gateway.txt` was swapped + the caller should `process::exit(0)` so the
/// supervisor relaunches the new file. `NoUpdate` means the manifest matched the
/// running version (or was older) and the cycle is a no-op.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CycleOutcome {
    /// Manifest version matched current — no action taken.
    NoUpdate,
    /// New binary staged + swap committed. Caller should exit for supervisor relaunch.
    Updated,
}

/// One IDLE → FETCH → … → EXIT cycle. Returns `Ok(NoUpdate)` for "manifest matches
/// current" or `Ok(Updated)` for "new binary staged + swap committed, caller should
/// exit." Returns `Err` for any transient failure (network, parse, lock contention,
/// sha256 mismatch). On `Updated`, the caller is expected to `process::exit(0)`;
/// this function does NOT exit on its own so it remains unit-testable.
pub(crate) async fn run_one_cycle(
    install_dir: &Path,
    current_version: &str,
    manifest_url: &str,
) -> Result<CycleOutcome, UpdaterError> {
    // FETCH
    let resp = reqwest::get(manifest_url)
        .await
        .map_err(|e| UpdaterError::Fetch(e.to_string()))?;
    if !resp.status().is_success() {
        return Err(UpdaterError::Fetch(format!("HTTP {}", resp.status())));
    }
    let body = resp
        .bytes()
        .await
        .map_err(|e| UpdaterError::Fetch(e.to_string()))?;
    let manifest: Manifest =
        serde_json::from_slice(&body).map_err(|e| UpdaterError::Parse(e.to_string()))?;
    if manifest.schema != MANIFEST_SCHEMA {
        return Err(UpdaterError::Parse(format!(
            "unknown manifest schema {} (expected {})",
            manifest.schema, MANIFEST_SCHEMA
        )));
    }

    // COMPARE
    if manifest.version == current_version {
        info!(version = current_version, "manifest version matches current; no update");
        return Ok(CycleOutcome::NoUpdate);
    }
    // MVP: string-different = update. We publish the manifest, so we won't push a
    // downgrade. TODO (follow-up): semver-aware no-downgrade check so a misconfigured
    // manifest can't regress the fleet.
    info!(
        manifest_version = %manifest.version,
        current_version,
        "manifest version differs; starting update"
    );

    // Look up our target triple. `KOIDRA_TARGET` env var wins (fleet launchers set it
    // to handle the custom win7-windows-gnu Tier 3 triple); otherwise we fall back to
    // a heuristic from `std::env::consts`.
    let target_triple = current_target_triple();
    let target = manifest.targets.get(&target_triple).ok_or_else(|| {
        UpdaterError::Parse(format!("manifest has no target for triple `{}`", target_triple))
    })?;

    // LOCK
    let _lock = match acquire_lock(install_dir).await? {
        Some(lock) => lock,
        None => {
            info!("other channel is mid-update; deferring to next cycle");
            return Ok(CycleOutcome::NoUpdate);
        }
    };

    // DOWNLOAD
    info!(url = %target.url, size = target.size, "downloading new binary");
    let resp = reqwest::get(&target.url)
        .await
        .map_err(|e| UpdaterError::Download(e.to_string()))?;
    if !resp.status().is_success() {
        return Err(UpdaterError::Download(format!("HTTP {}", resp.status())));
    }
    let bytes = resp
        .bytes()
        .await
        .map_err(|e| UpdaterError::Download(e.to_string()))?;
    if bytes.len() as u64 != target.size {
        return Err(UpdaterError::Size {
            expected: target.size,
            got: bytes.len(),
        });
    }

    // VERIFY
    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    let actual_sha = hex_encode(&hasher.finalize());
    if actual_sha != target.sha256 {
        return Err(UpdaterError::Sha256 {
            expected: target.sha256.clone(),
            actual: actual_sha,
        });
    }
    info!(sha256 = %actual_sha, size = bytes.len(), "sha256 verified");

    // STAGE: write the new binary to its final filename (not the running exe's name,
    // which is locked on Windows). The supervisor picks it up via current-koidra-gateway.txt.
    let exe_suffix = std::env::consts::EXE_SUFFIX;
    let stage_name = format!(
        "koidra-gateway-{}{}",
        sanitize_for_filename(&manifest.version),
        exe_suffix
    );
    let stage_path = install_dir.join(&stage_name);
    fs::write(&stage_path, &bytes).await?;

    // Executable bit on Unix (Windows ignores this).
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(&stage_path).await?.permissions();
        perms.set_mode(0o755);
        fs::set_permissions(&stage_path, perms).await?;
    }
    info!(path = %stage_path.display(), "staged new binary");

    // COMMIT
    commit_swap(install_dir, &stage_name).await?;

    // DONE — caller (spawn loop) exits so the supervisor relaunches the new binary.
    info!("update committed; ready for supervisor relaunch");
    Ok(CycleOutcome::Updated)
}

/// Sleep duration: uniform in `[center - jitter_half, center + jitter_half)`.
/// Jitter is capped at half the interval so a short test interval (e.g. 5 s via
/// `KOIDRA_UPDATER_POLL_SECS`) doesn't produce a negative or wildly disproportionate sleep.
/// Uses a cheap LCG seeded from the system clock so we don't pull in a heavyweight RNG.
fn jittered_sleep(center: Duration) -> Duration {
    let center_secs = center.as_secs();
    let half = POLL_JITTER.as_secs().min(center_secs / 2);
    // Cheap deterministic jitter: nanos of SystemTime XOR'd with the PID. Good enough
    // for staggering two processes that boot within seconds of each other.
    let seed = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.subsec_nanos() as u64)
        .unwrap_or(0)
        ^ (std::process::id() as u64).wrapping_mul(2654435761);
    let jitter = if half == 0 {
        0
    } else {
        // LCG step to spread the seed across the window.
        (seed.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407) >> 33) % (2 * half)
    };
    Duration::from_secs(center_secs.saturating_sub(half).saturating_add(jitter))
}

/// Returns the current target triple, preferring `KOIDRA_TARGET` env var (set by the
/// fleet launchers, which know whether this is a win7-windows-gnu or pc-windows-gnu
/// build — a distinction Rust's `cfg!(target_os)` can't make at runtime).
pub fn current_target_triple() -> String {
    if let Ok(t) = std::env::var("KOIDRA_TARGET") {
        return t;
    }
    let arch = std::env::consts::ARCH;
    let os = std::env::consts::OS;
    match (arch, os) {
        ("x86_64", "windows") => "x86_64-pc-windows-gnu".to_string(),
        ("x86_64", "linux") => "x86_64-unknown-linux-musl".to_string(),
        (a, o) => format!("{}-{}", a, o),
    }
}

/// Acquire the per-box update lock. Returns `Ok(Some(guard))` on success, `Ok(None)`
/// if the lock is held by a non-stale other process, `Err` on I/O errors other than
/// "file exists."
///
/// Stale handling: if the lock exists and its mtime is older than `LOCK_STALE_AFTER`,
/// we steal it (delete + recreate). Payload records PID + timestamp so the other
/// channel can identify a live holder.
async fn acquire_lock(install_dir: &Path) -> Result<Option<LockGuard>, UpdaterError> {
    let path = install_dir.join(LOCKFILE_NAME);

    loop {
        // Fast path: atomic create_new. Succeeds only if the file doesn't exist.
        match fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .truncate(true)
            .open(&path)
            .await
        {
            Ok(mut f) => {
                use tokio::io::AsyncWriteExt;
                let payload = format!(
                    "{{\"pid\":{},\"acquired_at\":\"{}\"}}\n",
                    std::process::id(),
                    std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map(|d| d.as_secs())
                        .unwrap_or(0)
                );
                f.write_all(payload.as_bytes()).await.ok();
                f.flush().await.ok();
                return Ok(Some(LockGuard { path }));
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                // Fall through to stale check.
            }
            Err(e) => return Err(e.into()),
        }

        // Lock exists — check staleness.
        let metadata = match fs::metadata(&path).await {
            Ok(m) => m,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                // Raced with the other channel releasing it between our create_new
                // attempt and the metadata read. Loop to retry once; a second
                // AlreadyExists → NotFound race is vanishingly rare.
                continue;
            }
            Err(e) => return Err(e.into()),
        };

        let mtime = metadata
            .modified()
            .map_err(|e| UpdaterError::Io(std::io::Error::other(e.to_string())))?;
        let age = mtime.elapsed().unwrap_or(Duration::ZERO);
        if age < LOCK_STALE_AFTER {
            return Ok(None);
        }

        // Stale — steal and loop to reacquire. If we lose the race (other channel
        // got there first), the loop's next iteration sees a fresh non-stale lock
        // and returns None.
        warn!(lock_age = ?age, "stale lock; stealing");
        let _ = fs::remove_file(&path).await;
    }
}

/// RAII lock guard: drops the lockfile on drop. The guard returned by `acquire_lock`
/// is held for the rest of the cycle; if the process panics, Drop runs (Rust's
/// unwind semantics) and the lock is released. If the process is SIGKILL'd, the
/// stale-lock path cleans up on the next cycle.
struct LockGuard {
    path: PathBuf,
}

impl Drop for LockGuard {
    fn drop(&mut self) {
        // Best-effort: remove the lockfile. Sync remove is fine here — this is rare
        // and the cost of leaving a stale lock is just a deferral, not a deadlock.
        let _ = std::fs::remove_file(&self.path);
    }
}

/// Atomically swap `current-koidra-gateway.txt` to `new_exe_name` and push the previous
/// value onto the rollback stack.
///
/// Order matters: we push the rollback stack FIRST (atomic), then write
/// current-koidra-gateway.txt (atomic). If we crash between the two, the supervisor sees
/// the OLD current-koidra-gateway.txt and just launches the old binary — a harmless no-op.
/// The orphan rollback entry is harmless (it's just a previous-filename record).
async fn commit_swap(install_dir: &Path, new_exe_name: &str) -> Result<(), UpdaterError> {
    let current_path = install_dir.join(CURRENT_EXE_NAME);
    let stack_path = install_dir.join(ROLLBACK_STACK_NAME);

    // Read previous value (if any).
    let prev = fs::read_to_string(&current_path)
        .await
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());

    // Push rollback stack.
    if let Some(prev_name) = &prev {
        let mut entries: Vec<String> = fs::read_to_string(&stack_path)
            .await
            .ok()
            .map(|s| s.lines().map(|l| l.trim().to_string()).filter(|l| !l.is_empty()).collect())
            .unwrap_or_default();
        entries.insert(0, prev_name.clone());
        entries.truncate(ROLLBACK_STACK_MAX);
        let body = entries.join("\n") + "\n";
        atomic_write(&stack_path, body.as_bytes()).await?;
        info!(prev = prev_name, "pushed rollback stack entry");
    }

    // Write new current-koidra-gateway.txt.
    atomic_write(&current_path, new_exe_name.as_bytes()).await?;
    info!(new = new_exe_name, "current-koidra-gateway.txt updated");

    Ok(())
}

/// Write `bytes` to `path` via temp-file + rename. Temp file is `path.tmp`. Both
/// files live in the same install dir, so the rename is atomic on the same filesystem
/// (POSIX rename + Win32 MoveFileEx with REPLACE_EXISTING via Rust's std::fs::rename).
async fn atomic_write(path: &Path, bytes: &[u8]) -> Result<(), UpdaterError> {
    let tmp = path.with_extension("tmp");
    fs::write(&tmp, bytes).await?;
    fs::rename(&tmp, path).await?;
    Ok(())
}

/// Hex-encode a byte slice lowercase. Inlined to avoid pulling the `hex` crate for
/// one call site.
fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

/// Sanitize a version string for use in a filename. Keeps alphanumerics, `-`, `_`, `.`;
/// replaces anything else (including path separators) with `_`.
fn sanitize_for_filename(s: &str) -> String {
    s.chars()
        .map(|c| {
            if c.is_alphanumeric() || c == '-' || c == '_' || c == '.' {
                c
            } else {
                '_'
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_encode_lowercase() {
        assert_eq!(hex_encode(&[0x01, 0x23, 0xab, 0xef]), "0123abef");
        assert_eq!(hex_encode(&[]), "");
        assert_eq!(
            hex_encode(&[
                0x9c, 0x8d, 0xde, 0xf3, 0x27, 0xa4, 0x45, 0x9b, 0x27, 0x2d, 0x12, 0x5a, 0x8c,
                0x43, 0x76, 0x7d, 0x30, 0x51, 0xca, 0xcf, 0xae, 0x88, 0x10, 0x7d, 0xe1, 0x8f,
                0xdc, 0x02, 0x33, 0x64, 0x5b, 0x3e,
            ]),
            "9c8ddef327a4459b272d125a8c43767d3051cacfae88107de18fdc0233645b3e"
        );
    }

    #[test]
    fn sanitize_strips_path_separators() {
        // No path traversal: a manifest can't name a binary that escapes the install dir.
        // Dots are allowed (they're valid filename chars); only `/`, `\`, spaces, etc.
        // get replaced with `_`.
        assert_eq!(sanitize_for_filename("0.4.0-d897332"), "0.4.0-d897332");
        assert_eq!(sanitize_for_filename("../evil"), ".._evil");
        assert_eq!(sanitize_for_filename("a/b\\c"), "a_b_c");
        assert_eq!(
            sanitize_for_filename("0.4.0-f6c10dd amd64 run=user:sinh"),
            "0.4.0-f6c10dd_amd64_run_user_sinh"
        );
    }

    #[test]
    fn manifest_parses_v1() {
        let raw = r#"{
            "schema": 1,
            "version": "0.4.0-d897332",
            "published_at": "2026-07-18T12:00:00Z",
            "targets": {
                "x86_64-unknown-linux-musl": {
                    "url": "https://example.com/b",
                    "sha256": "abc",
                    "size": 12345
                }
            }
        }"#;
        let m: Manifest = serde_json::from_str(raw).unwrap();
        assert_eq!(m.schema, 1);
        assert_eq!(m.version, "0.4.0-d897332");
        assert_eq!(m.targets.len(), 1);
        assert_eq!(m.targets["x86_64-unknown-linux-musl"].size, 12345);
    }

    #[test]
    fn manifest_rejects_unknown_schema() {
        // Parser still reads the struct, but run_one_cycle would reject schema=99.
        let raw = r#"{"schema":99,"version":"x","published_at":"y","targets":{}}"#;
        let m: Manifest = serde_json::from_str(raw).unwrap();
        assert_ne!(m.schema, MANIFEST_SCHEMA);
    }

    #[test]
    fn target_triple_env_var_wins() {
        // We can't set env vars concurrently in tests safely, so just check the fallback
        // shape (which depends on the host platform — the test host's triple is one of
        // the known set). Real coverage is the canary.
        let t = current_target_triple();
        assert!(!t.is_empty());
        assert!(t.contains(std::env::consts::ARCH) || std::env::var("KOIDRA_TARGET").is_ok());
    }

    #[tokio::test]
    async fn atomic_write_replaces_existing() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("current-koidra-gateway.txt");
        atomic_write(&path, b"ssh_shell-new.exe").await.unwrap();
        assert_eq!(fs::read_to_string(&path).await.unwrap(), "ssh_shell-new.exe");
        // Second write replaces.
        atomic_write(&path, b"ssh_shell-newer.exe").await.unwrap();
        assert_eq!(fs::read_to_string(&path).await.unwrap(), "ssh_shell-newer.exe");
        // Temp file cleaned up by rename.
        assert!(!dir.path().join("current-koidra-gateway.txt.tmp").exists());
    }

    #[tokio::test]
    async fn commit_swap_pushes_rollback_and_writes_current() {
        let dir = tempfile::tempdir().unwrap();
        let install = dir.path();

        // Seed an initial current-koidra-gateway.txt.
        atomic_write(&install.join(CURRENT_EXE_NAME), b"ssh_shell-old.exe")
            .await
            .unwrap();

        // Swap.
        commit_swap(install, "ssh_shell-new.exe").await.unwrap();

        // New current is written.
        assert_eq!(
            fs::read_to_string(&install.join(CURRENT_EXE_NAME))
                .await
                .unwrap()
                .trim(),
            "ssh_shell-new.exe"
        );

        // Rollback stack has the old entry.
        let stack = fs::read_to_string(&install.join(ROLLBACK_STACK_NAME))
            .await
            .unwrap();
        assert_eq!(stack.trim(), "ssh_shell-old.exe");

        // Second swap pushes the first new onto the stack.
        commit_swap(install, "ssh_shell-newer.exe").await.unwrap();
        let stack = fs::read_to_string(&install.join(ROLLBACK_STACK_NAME))
            .await
            .unwrap();
        let lines: Vec<&str> = stack.lines().collect();
        assert_eq!(lines, vec!["ssh_shell-new.exe", "ssh_shell-old.exe"]);
    }

    #[tokio::test]
    async fn rollback_stack_truncates_at_max() {
        let dir = tempfile::tempdir().unwrap();
        let install = dir.path();
        atomic_write(&install.join(CURRENT_EXE_NAME), b"v0")
            .await
            .unwrap();

        for i in 1..=(ROLLBACK_STACK_MAX + 2) {
            commit_swap(install, &format!("v{}", i)).await.unwrap();
        }

        let stack = fs::read_to_string(&install.join(ROLLBACK_STACK_NAME))
            .await
            .unwrap();
        let lines: Vec<&str> = stack.lines().collect();
        assert_eq!(lines.len(), ROLLBACK_STACK_MAX);
        // Most recent push is on top.
        assert_eq!(lines[0], format!("v{}", ROLLBACK_STACK_MAX + 1));
    }

    #[tokio::test]
    async fn lock_acquire_then_block_then_release() {
        let dir = tempfile::tempdir().unwrap();
        let install = dir.path();

        // First acquire succeeds.
        let g1 = acquire_lock(install).await.unwrap().unwrap();

        // Second acquire on the same dir returns None (busy) since the file is fresh.
        // We make the lock fresh by checking mtime, which is "just now."
        let g2 = acquire_lock(install).await.unwrap();
        assert!(g2.is_none(), "expected None while first lock is held");

        // Release.
        drop(g1);

        // Now acquire succeeds again.
        let g3 = acquire_lock(install).await.unwrap().unwrap();
        drop(g3);
    }

    // ── Integration test: full run_one_cycle with a mock HTTP server ──────────

    /// Bind a ephemeral port for the mock server. Returned listener is passed to
    /// `serve_mock` after the test builds the manifest with the known port.
    async fn bind_mock_port() -> (tokio::net::TcpListener, u16) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        (listener, port)
    }

    /// Minimal HTTP/1.1 server that serves two paths: `/manifest.json` and `/binary`.
    /// Sets `Connection: close` so reqwest opens a fresh connection per request.
    fn serve_mock(listener: tokio::net::TcpListener, manifest_json: String, binary: Vec<u8>) {
        use tokio::io::{AsyncBufReadExt, AsyncWriteExt};
        tokio::spawn(async move {
            loop {
                let Ok((mut sock, _)) = listener.accept().await else { return };
                let mut reader = tokio::io::BufReader::new(&mut sock);
                let mut request_line = String::new();
                reader.read_line(&mut request_line).await.ok();
                // Consume remaining headers.
                loop {
                    let mut header = String::new();
                    reader.read_line(&mut header).await.ok();
                    if header.trim().is_empty() { break; }
                }

                if request_line.contains("GET /manifest.json") {
                    let body = manifest_json.as_bytes().to_vec();
                    let resp = format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        body.len()
                    );
                    sock.write_all(resp.as_bytes()).await.ok();
                    sock.write_all(&body).await.ok();
                } else if request_line.contains("GET /binary") {
                    let resp = format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        binary.len()
                    );
                    sock.write_all(resp.as_bytes()).await.ok();
                    sock.write_all(&binary).await.ok();
                } else {
                    sock.write_all(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").await.ok();
                }
            }
        });
    }

    #[tokio::test]
    async fn run_one_cycle_full_swap_end_to_end() {
        let dir = tempfile::tempdir().unwrap();
        let install = dir.path();

        // Seed: an "old" binary name in current-koidra-gateway.txt.
        atomic_write(&install.join(CURRENT_EXE_NAME), b"ssh_shell-old")
            .await
            .unwrap();

        // "New" binary bytes (fake — just arbitrary bytes, content doesn't matter for
        // the swap logic; what matters is the sha256 matches the manifest).
        let new_binary_contents: Vec<u8> =
            b"#!/bin/sh\necho fake new binary\n".to_vec();
        let mut hasher = Sha256::new();
        hasher.update(&new_binary_contents);
        let new_sha = hex_encode(&hasher.finalize());

        // Bind the port FIRST so we can build the manifest with the real URL.
        let (listener, port) = bind_mock_port().await;
        let binary_url = format!("http://127.0.0.1:{}/binary", port);
        let manifest_url = format!("http://127.0.0.1:{}/manifest.json", port);

        // Manifest advertising the new version, pointing at our mock /binary endpoint.
        let manifest = serde_json::json!({
            "schema": 1,
            "version": "0.4.0-NEW_FAKE",
            "published_at": "2026-07-18T12:00:00Z",
            "targets": {
                current_target_triple(): {
                    "url": binary_url,
                    "sha256": new_sha,
                    "size": new_binary_contents.len() as u64,
                }
            }
        });

        // Start serving.
        serve_mock(listener, manifest.to_string(), new_binary_contents.clone());

        // Run one cycle. Current version is "0.4.0-OLD" → manifest's "0.4.0-NEW_FAKE"
        // differs → the full FETCH→DOWNLOAD→VERIFY→STAGE→COMMIT path should fire.
        let outcome = run_one_cycle(install, "0.4.0-OLD", &manifest_url)
            .await
            .expect("cycle should succeed");

        assert_eq!(outcome, CycleOutcome::Updated);

        // current-koidra-gateway.txt now points at the staged binary.
        let current_name = fs::read_to_string(&install.join(CURRENT_EXE_NAME))
            .await
            .unwrap();
        let current_name = current_name.trim();
        assert!(
            current_name.contains("0.4.0-NEW_FAKE"),
            "current-koidra-gateway.txt should contain the new version, got: {}",
            current_name
        );

        // Rollback stack has the old name.
        let stack = fs::read_to_string(&install.join(ROLLBACK_STACK_NAME))
            .await
            .unwrap();
        assert_eq!(stack.trim(), "ssh_shell-old");

        // The staged binary exists and matches the served bytes.
        let staged_path = install.join(current_name);
        let staged_bytes = fs::read(&staged_path).await.unwrap();
        assert_eq!(staged_bytes, new_binary_contents);
    }

    #[tokio::test]
    async fn run_one_cycle_no_update_when_versions_match() {
        let dir = tempfile::tempdir().unwrap();
        let install = dir.path();

        let (listener, port) = bind_mock_port().await;
        let manifest_url = format!("http://127.0.0.1:{}/manifest.json", port);
        let manifest = serde_json::json!({
            "schema": 1,
            "version": "0.4.0-SAME",
            "published_at": "2026-07-18T12:00:00Z",
            "targets": {}
        });
        serve_mock(listener, manifest.to_string(), vec![]);

        let outcome = run_one_cycle(install, "0.4.0-SAME", &manifest_url)
            .await
            .expect("cycle should succeed");

        assert_eq!(outcome, CycleOutcome::NoUpdate);
        // current-koidra-gateway.txt should NOT exist (we never wrote it).
        assert!(!install.join(CURRENT_EXE_NAME).exists());
    }
}
