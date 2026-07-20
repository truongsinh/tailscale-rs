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
//! ## Per-cohort manifests (split-brain fix, 2026-07-19)
//!
//! Each binary cohort (ssh_shell vs koidra-gateway) polls its OWN manifest URL —
//! `fleet-manifest-ssh.json` vs `fleet-manifest-gateway.json` on the same release tag.
//! The launcher embeds the cohort-specific URL via `--manifest-url` / `KOIDRA_MANIFEST_URL`,
//! so a box never tries to "update" to the other cohort's binary shape. See
//! `.doc/2026-07-per-cohort-manifest.md` for the full design.
//!
//! ## Downgrade protection
//!
//! The COMPARE step is semver-aware: it refuses to "update" to a version older than the
//! running one, even if the manifest string differs. Format handled (see [`Version`]):
//! `MAJOR.MINOR.PATCH` → `MAJOR.MINOR.PATCH-SEQ-gSHA` (git-describe) → bare SHA suffix
//! (legacy `0.4.0-f6c10dd`). Close the source TODO from the MVP.
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

use std::cmp::Ordering;

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

/// A parsed `ipn_version`-shaped string, used by the COMPARE step for downgrade
/// protection. See the module-level "Downgrade protection" doc for the format
/// rationale.
///
/// Total order: `(major, minor, patch, seq, sha)` compared lexicographically —
/// numeric for the first four fields, lexical (byte-compare) for the SHA tie-
/// breaker. Higher `seq` = more commits after the base tag = newer.
///
/// Two of our published binaries at the same SHA produce equal `Version`s, so
/// the updater correctly no-ops when the manifest re-advertises the running
/// version.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Version {
    major: u32,
    minor: u32,
    patch: u32,
    /// Commits after the `MAJOR.MINOR.PATCH` tag, as reported by `git describe`.
    /// Bare semver and legacy `MAJOR.MINOR.PATCH-SHA` forms parse to `0`.
    seq: u64,
    /// Trailing SHA (no `g` prefix). Empty for bare semver. Compared lexically.
    sha: String,
}

impl Ord for Version {
    fn cmp(&self, other: &Self) -> Ordering {
        self.major
            .cmp(&other.major)
            .then(self.minor.cmp(&other.minor))
            .then(self.patch.cmp(&other.patch))
            .then(self.seq.cmp(&other.seq))
            .then(self.sha.cmp(&other.sha))
    }
}

impl PartialOrd for Version {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Version {
    /// Parse an `ipn_version`-shaped string.
    ///
    /// Accepted forms (most specific first):
    /// - `MAJOR.MINOR.PATCH`                  → `(base, 0, "")`
    /// - `MAJOR.MINOR.PATCH-SEQ-gSHA`         → `(base, SEQ, SHA)` (git-describe)
    /// - `MAJOR.MINOR.PATCH-SHA`              → `(base, 0, SHA)` (legacy short)
    ///
    /// Returns `Err` on a missing/non-numeric base or non-numeric SEQ so the
    /// caller can fall back to lexical string compare with a warn log, preserving
    /// the MVP "different string = update" behaviour for unparseable inputs.
    fn parse(s: &str) -> Result<Self, VersionParseError> {
        // Split base semver from suffix at the first '-'. This is unambiguous for
        // our shapes because the base is always MAJOR.MINOR.PATCH (no '-' inside).
        let (base_part, suffix) = match s.split_once('-') {
            Some((b, suf)) => (b, Some(suf)),
            None => (s, None),
        };

        // Parse MAJOR.MINOR.PATCH — all three required, no more.
        let mut parts = base_part.split('.');
        let major = parts
            .next()
            .and_then(|p| p.parse::<u32>().ok())
            .ok_or(VersionParseError::BadBase)?;
        let minor = parts
            .next()
            .and_then(|p| p.parse::<u32>().ok())
            .ok_or(VersionParseError::BadBase)?;
        let patch = parts
            .next()
            .and_then(|p| p.parse::<u32>().ok())
            .ok_or(VersionParseError::BadBase)?;
        if parts.next().is_some() {
            return Err(VersionParseError::BadBase);
        }

        // Parse suffix: `SEQ-gSHA` (git-describe), bare SHA (legacy), or none.
        let (seq, sha) = match suffix {
            None => (0, String::new()),
            Some(suf) => match suf.split_once("-g") {
                Some((seq_str, sha_part)) => {
                    let seq = seq_str
                        .parse::<u64>()
                        .map_err(|_| VersionParseError::BadSeq(seq_str.to_string()))?;
                    (seq, sha_part.to_string())
                }
                None => (0, suf.to_string()),
            },
        };

        Ok(Self {
            major,
            minor,
            patch,
            seq,
            sha,
        })
    }
}

#[derive(Debug, Error)]
enum VersionParseError {
    #[error("missing or non-numeric MAJOR.MINOR.PATCH base")]
    BadBase,
    #[error("non-numeric SEQ in git-describe suffix: {0}")]
    BadSeq(String),
}

/// Outcome of comparing the running version against the manifest version.
#[derive(Debug, PartialEq, Eq)]
enum VersionComparison {
    /// Manifest version equals running — no action needed.
    Equal,
    /// Manifest version is strictly newer — proceed with update.
    Newer,
    /// Manifest version is strictly older — refuse to downgrade.
    Older,
    /// One or both sides failed to parse — caller falls back to lexical compare.
    Unparseable,
}

/// Compare running `current` against `manifest`. Both sides parse → strict
/// ordering by [`Version::cmp`]. Either side fails to parse → [`VersionComparison::Unparseable`],
/// signalling the caller to fall back to the MVP string-compare policy (we
/// publish the manifest, so we don't hard-block the fleet when the publisher
/// ships an exotic format).
fn compare_versions(current: &str, manifest: &str) -> VersionComparison {
    match (Version::parse(current), Version::parse(manifest)) {
        (Ok(cur), Ok(man)) => match man.cmp(&cur) {
            Ordering::Equal => VersionComparison::Equal,
            Ordering::Greater => VersionComparison::Newer,
            Ordering::Less => VersionComparison::Older,
        },
        _ => VersionComparison::Unparseable,
    }
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
                    // current-ssh-shell.txt points at the new binary.
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
/// `current-ssh-shell.txt` was swapped + the caller should `process::exit(0)` so the
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

    // COMPARE — semver-aware. Refuses to "update" to an older version so a
    // misconfigured manifest can't regress the fleet. Closes the source TODO from
    // the MVP. See [`Version`] for the format and ordering rules.
    match compare_versions(current_version, &manifest.version) {
        VersionComparison::Equal => {
            info!(version = current_version, "manifest version matches current; no update");
            return Ok(CycleOutcome::NoUpdate);
        }
        VersionComparison::Newer => {
            info!(
                manifest_version = %manifest.version,
                current_version,
                "manifest version is newer; starting update"
            );
        }
        VersionComparison::Older => {
            warn!(
                manifest_version = %manifest.version,
                current_version,
                "manifest version is OLDER than current; refusing to downgrade (skipping cycle)"
            );
            return Ok(CycleOutcome::NoUpdate);
        }
        VersionComparison::Unparseable => {
            // One or both sides didn't look like IPN_VERSION — fall back to the
            // MVP "different string = update" policy. The manifest publisher is
            // trusted, so we don't hard-block the fleet on a parse failure; we
            // still short-circuit on exact string equality so an identical
            // unparseable version is a no-op.
            if manifest.version == current_version {
                info!(version = current_version, "manifest version matches current (unparseable); no update");
                return Ok(CycleOutcome::NoUpdate);
            }
            warn!(
                manifest_version = %manifest.version,
                current_version,
                "could not parse one or both versions; falling back to string-different=update"
            );
        }
    }

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

        // Seed: an "old" binary name in current-ssh-shell.txt.
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

        // Use realistic git-describe versions so the semver comparator sees the
        // manifest as a true upgrade (higher SEQ). Older binary = seq 100, new = 200.
        let current_ver = "0.4.0-100-g0000000old";
        let manifest_ver = "0.4.0-200-g0000000new";

        // Manifest advertising the new version, pointing at our mock /binary endpoint.
        let manifest = serde_json::json!({
            "schema": 1,
            "version": manifest_ver,
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

        // Run one cycle. Manifest seq 200 > current seq 100 → upgrade path fires
        // (FETCH → DOWNLOAD → VERIFY → STAGE → COMMIT).
        let outcome = run_one_cycle(install, current_ver, &manifest_url)
            .await
            .expect("cycle should succeed");

        assert_eq!(outcome, CycleOutcome::Updated);

        // current-ssh-shell.txt now points at the staged binary.
        let current_name = fs::read_to_string(&install.join(CURRENT_EXE_NAME))
            .await
            .unwrap();
        let current_name = current_name.trim();
        assert!(
            current_name.contains(manifest_ver),
            "current-ssh-shell.txt should contain the new version, got: {}",
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
        // Realistic git-describe form: both sides equal → COMPARE returns Equal.
        let same_ver = "0.4.0-200-g00000000";
        let manifest = serde_json::json!({
            "schema": 1,
            "version": same_ver,
            "published_at": "2026-07-18T12:00:00Z",
            "targets": {}
        });
        serve_mock(listener, manifest.to_string(), vec![]);

        let outcome = run_one_cycle(install, same_ver, &manifest_url)
            .await
            .expect("cycle should succeed");

        assert_eq!(outcome, CycleOutcome::NoUpdate);
        // current-ssh-shell.txt should NOT exist (we never wrote it).
        assert!(!install.join(CURRENT_EXE_NAME).exists());
    }

    // ── Downgrade-protection (semver-aware COMPARE) ───────────────────────────

    #[test]
    fn version_parse_bare_semver() {
        let v = Version::parse("0.4.0").unwrap();
        assert_eq!((v.major, v.minor, v.patch, v.seq, v.sha.as_str()), (0, 4, 0, 0, ""));
    }

    #[test]
    fn version_parse_git_describe() {
        let v = Version::parse("0.4.0-253-g301ee7a").unwrap();
        assert_eq!((v.major, v.minor, v.patch, v.seq, v.sha.as_str()), (0, 4, 0, 253, "301ee7a"));
    }

    #[test]
    fn version_parse_legacy_bare_sha() {
        // Legacy form used by the MVP: `0.4.0-<short-sha>` (no SEQ, no `g` prefix).
        let v = Version::parse("0.4.0-f6c10dd").unwrap();
        assert_eq!((v.major, v.minor, v.patch, v.seq, v.sha.as_str()), (0, 4, 0, 0, "f6c10dd"));
    }

    #[test]
    fn version_parse_rejects_missing_or_bad_base() {
        // Too few components.
        assert!(Version::parse("1").is_err());
        assert!(Version::parse("1.2").is_err());
        // Non-numeric components.
        assert!(Version::parse("a.b.c").is_err());
        assert!(Version::parse("0.4.x").is_err());
        // Too many components.
        assert!(Version::parse("1.2.3.4").is_err());
        // Empty string.
        assert!(Version::parse("").is_err());
    }

    #[test]
    fn version_parse_rejects_bad_seq() {
        // SEQ-gSHA form but SEQ is not numeric.
        let err = Version::parse("0.4.0-abc-g1234567").unwrap_err();
        assert!(matches!(err, VersionParseError::BadSeq(_)), "got: {err:?}");
    }

    #[test]
    fn version_ordering_base_semver_numeric() {
        let a = Version::parse("0.4.0").unwrap();
        let b = Version::parse("0.4.1").unwrap();
        assert!(a < b, "{a:?} should be < {b:?}");
        let c = Version::parse("0.5.0").unwrap();
        assert!(b < c);
        let d = Version::parse("1.0.0").unwrap();
        assert!(c < d);
        // 0.10.0 > 0.9.0 (numeric, NOT lexical — guards against "9" > "10" string sort).
        let e = Version::parse("0.9.0").unwrap();
        let f = Version::parse("0.10.0").unwrap();
        assert!(e < f);
    }

    #[test]
    fn version_ordering_seq_as_tiebreak() {
        // Same base, different SEQ. Higher SEQ = more commits after tag = newer.
        let a = Version::parse("0.4.0-10-gaaaaaaa").unwrap();
        let b = Version::parse("0.4.0-253-gbbbbbbb").unwrap();
        assert!(a < b, "{a:?} should be < {b:?}");
    }

    #[test]
    fn version_ordering_sha_lexicographic_when_seq_equal() {
        let a = Version::parse("0.4.0-253-g1111111").unwrap();
        let b = Version::parse("0.4.0-253-g2222222").unwrap();
        assert!(a < b, "{a:?} should be < {b:?}");
        let c = Version::parse("0.4.0-253-g1111111").unwrap();
        assert_eq!(a, c);
    }

    #[test]
    fn version_ordering_cross_format() {
        // git-describe at seq=253 is newer than legacy bare SHA at same base.
        let legacy = Version::parse("0.4.0-f6c10dd").unwrap();
        let describe = Version::parse("0.4.0-253-g301ee7a").unwrap();
        assert!(legacy < describe);
        // Bare semver (seq=0, empty SHA) sorts BELOW a non-empty SHA at same seq
        // because "" < any non-empty string lexicographically. Edge case; accepted.
        let bare = Version::parse("0.4.0").unwrap();
        assert!(bare < legacy, "bare semver sorts below legacy SHA at same seq");
    }

    #[test]
    fn version_ordering_equal() {
        let a = Version::parse("0.4.0-253-g301ee7a").unwrap();
        let b = Version::parse("0.4.0-253-g301ee7a").unwrap();
        assert_eq!(a, b);
        assert_eq!(a.cmp(&b), Ordering::Equal);
    }

    #[test]
    fn compare_versions_classifies_upgrade() {
        // Higher SEQ = upgrade.
        assert_eq!(
            compare_versions("0.4.0-253-g301ee7a", "0.4.0-260-gabcdef0"),
            VersionComparison::Newer,
        );
        // Higher patch = upgrade, even when current has higher SEQ.
        assert_eq!(
            compare_versions("0.4.99-9999-gzzzzzzz", "0.4.100-0-g"),
            VersionComparison::Newer,
        );
    }

    #[test]
    fn compare_versions_classifies_equal() {
        assert_eq!(
            compare_versions("0.4.0-253-g301ee7a", "0.4.0-253-g301ee7a"),
            VersionComparison::Equal,
        );
    }

    #[test]
    fn compare_versions_classifies_downgrade() {
        // Lower SEQ = downgrade.
        assert_eq!(
            compare_versions("0.4.0-260-gabcdef0", "0.4.0-253-g301ee7a"),
            VersionComparison::Older,
        );
        // Lower minor = downgrade, even when manifest has higher SEQ.
        assert_eq!(
            compare_versions("0.5.0-1-g0000001", "0.4.99-9999-gffffff"),
            VersionComparison::Older,
        );
    }

    #[test]
    fn compare_versions_unparseable_when_either_side_bad() {
        assert_eq!(
            compare_versions("0.4.0-253-g301ee7a", "garbage"),
            VersionComparison::Unparseable,
        );
        assert_eq!(
            compare_versions("garbage", "0.4.0-253-g301ee7a"),
            VersionComparison::Unparseable,
        );
        // Both garbage is still unparseable — caller will lexical-compare.
        assert_eq!(
            compare_versions("foo", "foo"),
            VersionComparison::Unparseable,
        );
    }

    #[tokio::test]
    async fn run_one_cycle_refuses_downgrade() {
        // Regression guard for the source-side "no downgrade" TODO. Manifest at
        // seq=100, current at seq=253 → cycle must NoUpdate and NOT touch disk.
        let dir = tempfile::tempdir().unwrap();
        let install = dir.path();

        let (listener, port) = bind_mock_port().await;
        let manifest_url = format!("http://127.0.0.1:{}/manifest.json", port);
        // Pointless target entries — the COMPARE phase must short-circuit before
        // they're read. A regression that lets the cycle proceed would hit the
        // bogus sha256 and fail the cycle with Sha256 mismatch, which the assert
        // below distinguishes from a clean NoUpdate.
        let manifest = serde_json::json!({
            "schema": 1,
            "version": "0.4.0-100-g00000old",
            "published_at": "2026-07-18T12:00:00Z",
            "targets": {
                current_target_triple(): {
                    "url": format!("http://127.0.0.1:{}/binary", port),
                    "sha256": "deadbeef".to_string(),
                    "size": 1_u64,
                }
            }
        });
        serve_mock(listener, manifest.to_string(), vec![0u8]);

        let outcome = run_one_cycle(install, "0.4.0-253-g301ee7a", &manifest_url)
            .await
            .expect("cycle should succeed (NoUpdate path, not error)");
        assert_eq!(outcome, CycleOutcome::NoUpdate);

        // current-ssh-shell.txt should NOT exist — COMPARE short-circuited.
        assert!(!install.join(CURRENT_EXE_NAME).exists());

        // No staged binary either. (Lockfile may exist if the test ran fast
        // enough to create then drop it, but a `ssh_shell-*` stage file would
        // indicate the pipeline wrongly proceeded past COMPARE.)
        let mut entries = fs::read_dir(install).await.unwrap();
        while let Some(entry) = entries.next_entry().await.unwrap() {
            let name = entry.file_name();
            let name = name.to_string_lossy();
            assert!(
                !name.starts_with("ssh_shell-"),
                "found unexpected staged binary: {name}",
            );
        }
    }

    #[tokio::test]
    async fn run_one_cycle_unparseable_falls_back_to_string_different_update() {
        // MVP-fallback path: one side can't parse. If the strings differ we
        // still allow the update (publisher is trusted).
        let dir = tempfile::tempdir().unwrap();
        let install = dir.path();
        atomic_write(&install.join(CURRENT_EXE_NAME), b"ssh_shell-old")
            .await
            .unwrap();

        let new_binary_contents: Vec<u8> = b"#!/bin/sh\necho new\n".to_vec();
        let mut hasher = Sha256::new();
        hasher.update(&new_binary_contents);
        let new_sha = hex_encode(&hasher.finalize());

        let (listener, port) = bind_mock_port().await;
        let binary_url = format!("http://127.0.0.1:{}/binary", port);
        let manifest_url = format!("http://127.0.0.1:{}/manifest.json", port);

        // Manifest version is a non-IPN_VERSION string; current is also garbage.
        // Both fail to parse → Unparseable → fallback to "different = update".
        let manifest = serde_json::json!({
            "schema": 1,
            "version": "canary-2026-07-19",
            "published_at": "2026-07-19T00:00:00Z",
            "targets": {
                current_target_triple(): {
                    "url": binary_url,
                    "sha256": new_sha,
                    "size": new_binary_contents.len() as u64,
                }
            }
        });
        serve_mock(listener, manifest.to_string(), new_binary_contents.clone());

        let outcome = run_one_cycle(install, "canary-2026-07-18", &manifest_url)
            .await
            .expect("cycle should succeed");
        assert_eq!(outcome, CycleOutcome::Updated);

        let current = fs::read_to_string(&install.join(CURRENT_EXE_NAME))
            .await
            .unwrap();
        assert!(current.contains("canary-2026-07-19"), "got: {current}");
    }
}
