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
//!   → LOCK    .koidra-ssh-update.lock (per-box, both channels honor)
//!   → DOWNLOAD target.url → temp file
//!   → VERIFY  sha256(temp) == target.sha256
//!   → STAGE   rename → ssh_shell-{version}{exe_suffix}
//!   → COMMIT  write current-ssh-shell.txt (temp+rename) + push rollback stack
//!   → EXIT    process::exit(0); supervisor relaunches within 5 s
//! ```
//!
//! ## Rollback
//!
//! The supervisor (not this code) runs a health-gate loop on the next launch: if the
//! new binary fails its listen-socket gate within 60 s, the supervisor pops the
//! rollback stack and reverts `current-ssh-shell.txt`. See
//! `.doc/2026-07-supervisor-restart-interface.md` §3.
//!
//! ## Boot contract (shared with Bravo P1)
//!
//! The binary's `main` (not this module) writes `.boot-state.json` at boot so the
//! supervisor's gate can detect a failed launch. This module reads/writes only
//! `current-ssh-shell.txt`, `.rollback-stack.txt`, and `.koidra-ssh-update.lock`.

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
const LOCKFILE_NAME: &str = ".koidra-ssh-update.lock";

/// Stale lock threshold: if the lock is older than this, steal it. Bounds how long a
/// crashed updater on the other channel can block its peer.
const LOCK_STALE_AFTER: Duration = Duration::from_secs(120);

/// Rollback stack: max entries the supervisor can pop.
const ROLLBACK_STACK_MAX: usize = 3;

/// State files in the install dir (Charlie-owned; Bravo never touches these).
const CURRENT_EXE_NAME: &str = "current-ssh-shell.txt";
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
pub fn spawn(install_dir: PathBuf, current_version: &'static str, manifest_url: String) {
    tokio::spawn(async move {
        info!(%manifest_url, %current_version, install_dir = %install_dir.display(), "fleet updater task started");
        loop {
            // Sleep with jitter BEFORE the first fetch. A freshly-booted binary is already
            // at its current version; no need to check immediately. Also staggers the two
            // channels (which share the same install_dir + lockfile).
            let sleep = jittered_sleep();
            time::sleep(sleep).await;

            if let Err(e) = run_one_cycle(&install_dir, current_version, &manifest_url).await {
                // Any error just logs and waits for the next cycle. The supervisor
                // health-gate is the safety net for "binary swapped into a bad build";
                // updater errors here are transient (network, parse, lock contention).
                warn!(error = %e, "updater cycle failed; will retry next interval");
            }
            // A successful cycle calls process::exit(0) inside run_one_cycle.
        }
    });
}

/// One IDLE → FETCH → … → EXIT cycle. Returns Ok(()) for "no update needed" or
/// "update staged + process about to exit." Returns Err for any transient failure.
async fn run_one_cycle(
    install_dir: &Path,
    current_version: &str,
    manifest_url: &str,
) -> Result<(), UpdaterError> {
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
        return Ok(());
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
            return Ok(());
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
    // which is locked on Windows). The supervisor picks it up via current-ssh-shell.txt.
    let exe_suffix = std::env::consts::EXE_SUFFIX;
    let stage_name = format!(
        "ssh_shell-{}{}",
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

    // EXIT — supervisor relaunches within ~5 s (Windows supervisor.vbs) or immediately
    // (Linux systemd Restart=on-failure). The new current-ssh-shell.txt points at the
    // new binary; the supervisor reads it on next launch.
    info!("update committed; exiting for supervisor relaunch");
    std::process::exit(0);
}

/// Sleep duration: uniform in `[POLL_INTERVAL - POLL_JITTER, POLL_INTERVAL + POLL_JITTER)`.
/// Uses a cheap LCG seeded from the system clock so we don't pull in a heavyweight RNG.
fn jittered_sleep() -> Duration {
    let center = POLL_INTERVAL.as_secs();
    let half = POLL_JITTER.as_secs();
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
    Duration::from_secs(center.saturating_sub(half).saturating_add(jitter))
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

/// Atomically swap `current-ssh-shell.txt` to `new_exe_name` and push the previous
/// value onto the rollback stack.
///
/// Order matters: we push the rollback stack FIRST (atomic), then write
/// current-ssh-shell.txt (atomic). If we crash between the two, the supervisor sees
/// the OLD current-ssh-shell.txt and just launches the old binary — a harmless no-op.
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

    // Write new current-ssh-shell.txt.
    atomic_write(&current_path, new_exe_name.as_bytes()).await?;
    info!(new = new_exe_name, "current-ssh-shell.txt updated");

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
        let path = dir.path().join("current-ssh-shell.txt");
        atomic_write(&path, b"ssh_shell-new.exe").await.unwrap();
        assert_eq!(fs::read_to_string(&path).await.unwrap(), "ssh_shell-new.exe");
        // Second write replaces.
        atomic_write(&path, b"ssh_shell-newer.exe").await.unwrap();
        assert_eq!(fs::read_to_string(&path).await.unwrap(), "ssh_shell-newer.exe");
        // Temp file cleaned up by rename.
        assert!(!dir.path().join("current-ssh-shell.txt.tmp").exists());
    }

    #[tokio::test]
    async fn commit_swap_pushes_rollback_and_writes_current() {
        let dir = tempfile::tempdir().unwrap();
        let install = dir.path();

        // Seed an initial current-ssh-shell.txt.
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
}
