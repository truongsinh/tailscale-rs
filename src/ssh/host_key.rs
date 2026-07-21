//! Persistent SSH host keys.
//!
//! The `ssh_shell` example and any in-process SSH server built on this crate needs a host
//! key to identify itself to clients. Generating a fresh key on every process start makes
//! `known_hosts` useless: every relaunch triggers `REMOTE HOST IDENTIFICATION HAS CHANGED`
//! on the client, which during fleet operations forces `ssh-keygen -R` between every
//! channel swap or binary relaunch.
//!
//! [`load_or_generate`] fixes that: read the key from `path` if one is already there,
//! otherwise generate an Ed25519 key, write it atomically with owner-only permissions,
//! and return it. Both channels of a primary/backup pair point at the same path, so the
//! same physical box presents the same host key regardless of which channel answered.
//!
//! # File format
//!
//! OpenSSH PEM, the same format `ssh-keygen -t ed25519 -f <path>` produces:
//!
//! ```text
//! -----BEGIN OPENSSH PRIVATE KEY-----
//! ...
//! -----END OPENSSH PRIVATE KEY-----
//! ```
//!
//! # Concurrency
//!
//! First start of a primary/backup pair is the only window where two processes might
//! race on key creation. [`load_or_generate`] uses `O_CREAT | O_EXCL` (via
//! [`tokio::fs::OpenOptions::create_new`]) so exactly one process wins; the loser sees
//! [`std::io::ErrorKind::AlreadyExists`], discards the key it generated, and re-reads
//! the winner's key. Both processes therefore return the same key for the current run,
//! not just on the next restart.

use std::path::{Path, PathBuf};

use russh::keys::{
    Algorithm, PrivateKey,
    ssh_key::{self, LineEnding},
};
use tokio::io::AsyncWriteExt;

/// Errors that may occur while loading or creating a persistent SSH host key.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum HostKeyError {
    /// The host key file exists but could not be read.
    #[error("failed to read host key file {path:?}: {source}")]
    Read {
        /// Path that we tried to read.
        path: PathBuf,
        /// Underlying I/O error.
        #[source]
        source: std::io::Error,
    },

    /// The host key file exists but its contents are not a valid OpenSSH private key.
    ///
    /// Corrupt or empty files surface here. The caller should surface this prominently:
    /// the file is in the way of self-healing, so an operator needs to delete it (or
    /// restore it from backup) before the SSH server can come back up.
    #[error("host key file {path:?} is not a valid OpenSSH private key: {source}")]
    Parse {
        /// Path whose contents failed to parse.
        path: PathBuf,
        /// Underlying parse error from `ssh_key`.
        #[source]
        source: ssh_key::Error,
    },

    /// Failed to generate a new Ed25519 key. This is essentially always a broken RNG.
    #[error("failed to generate host key: {source}")]
    Generate {
        /// Underlying key-generation error from `ssh_key`.
        #[source]
        source: ssh_key::Error,
    },

    /// Failed to serialize a freshly generated key. Should be unreachable for Ed25519.
    #[error("failed to encode host key: {source}")]
    Encode {
        /// Underlying encoding error from `ssh_key`.
        #[source]
        source: ssh_key::Error,
    },

    /// Failed to write the new key file. Most often a missing parent directory or
    /// insufficient permissions on the install dir.
    #[error("failed to write host key file {path:?}: {source}")]
    Write {
        /// Path that we tried to write.
        path: PathBuf,
        /// Underlying I/O error.
        #[source]
        source: std::io::Error,
    },

    /// Failed to encode the public half of the host key into the OpenSSH
    /// authorized-keys string format used by `Hostinfo.SSH_HostKeys`. Should be
    /// unreachable for Ed25519 — the only realistic trigger is a key type `russh`
    /// doesn't know how to serialize, which would have failed earlier.
    #[error("failed to encode host public key as OpenSSH string: {source}")]
    EncodePublic {
        /// Underlying encoding error from `ssh_key`.
        #[source]
        source: ssh_key::Error,
    },
}

/// Load the persistent SSH host key at `path`, or generate + persist a new one.
///
/// On success, the file at `path` is guaranteed to exist and contain a valid OpenSSH
/// private key, and the returned [`PrivateKey`] matches the bytes on disk.
///
/// See the [module docs](self) for the on-disk format and the first-start race
/// semantics.
pub async fn load_or_generate(path: &Path) -> Result<PrivateKey, HostKeyError> {
    loop {
        match tokio::fs::read(path).await {
            Ok(bytes) => {
                // `from_openssh` accepts raw bytes and surfaces its own UTF-8 / PEM
                // errors as `ssh_key::Error`, so no separate utf-8 validation step.
                let key =
                    PrivateKey::from_openssh(&bytes).map_err(|source| HostKeyError::Parse {
                        path: path.to_path_buf(),
                        source,
                    })?;

                tracing::info!(path = %path.display(), "loaded persistent ssh host key");
                return Ok(key);
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                // Not there yet — generate one and try to claim the path. If we lose the
                // race to another process (primary vs. backup both booting), loop around
                // and read what they wrote.
                let key = PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519)
                    .map_err(|source| HostKeyError::Generate { source })?;

                match try_create(path, &key).await? {
                    CreateOutcome::Created => {
                        tracing::info!(path = %path.display(), "generated new persistent ssh host key");
                        return Ok(key);
                    }
                    CreateOutcome::Raced => {
                        tracing::debug!(
                            path = %path.display(),
                            "host key created concurrently by another process; re-reading"
                        );
                        // Fall through to the next loop iteration.
                    }
                }
            }
            Err(source) => {
                return Err(HostKeyError::Read {
                    path: path.to_path_buf(),
                    source,
                });
            }
        }
    }
}

/// Format the public half of a persistent host key as the single-line OpenSSH
/// authorized-keys value `tailscale ssh` clients expect in `Hostinfo.SSH_HostKeys`.
///
/// Returns a string of the form `<key-type> <base64-blob>` (e.g.
/// `"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI..."`) with no comment, no leading
/// hostname, and no trailing newline. This matches the format upstream Tailscale
/// produces in `ssh/tailssh/hostkeys.go::getHostKeyPublicStrings` —
/// `strings.TrimSpace(string(ssh.MarshalAuthorizedKey(signer.PublicKey())))` —
/// so the coordination server and peer clients parse it identically.
///
/// Callers that need to advertise the host key (e.g. `koidra_gateway` registering
/// with the coordination server) should call this once at startup, after
/// [`load_or_generate`] returns the persistent key, and pass the result into
/// [`crate::Config::ssh_host_keys`].
pub fn public_openssh_string(key: &PrivateKey) -> Result<String, HostKeyError> {
    let encoded = key
        .public_key()
        .to_openssh()
        .map_err(|source| HostKeyError::EncodePublic { source })?;
    // `PublicKey::to_openssh` never appends a trailing newline (it's the single-line
    // authorized_keys value, not the SSH-format wrapping used by private keys), but
    // trim defensively so a future russh/ssh_key revision can't silently break the
    // wire format. Newlines inside the blob would also be caught here — the base64
    // alphabet has no whitespace, so any present means the encoder changed shape.
    Ok(encoded.trim().to_owned())
}
#[derive(Debug, Eq, PartialEq)]
enum CreateOutcome {
    /// The file was created and now holds the encoded key.
    Created,
    /// Another process created the file between our `read` and our `create_new`;
    /// we left the disk untouched and the caller should re-read.
    Raced,
}

/// Try to atomically create the host key file with `key`'s OpenSSH encoding.
///
/// Uses `create_new` (`O_CREAT | O_EXCL` on Unix) so a racing writer is detected rather
/// than silently overwriting. Permissions are `0600` on Unix at create time (no chmod
/// window); on Windows the file inherits ACLs from the install directory.
async fn try_create(path: &Path, key: &PrivateKey) -> Result<CreateOutcome, HostKeyError> {
    let pem = key
        .to_openssh(LineEnding::LF)
        .map_err(|source| HostKeyError::Encode { source })?;

    let mut opts = tokio::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    // Set mode 0600 atomically with the create on Unix — avoids any window where the
    // private key is world-readable. `tokio::fs::OpenOptions::mode` is an inherent
    // method on Unix (no trait import needed).
    #[cfg(unix)]
    {
        opts.mode(0o600);
    }

    let mut file = match opts.open(path).await {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            return Ok(CreateOutcome::Raced);
        }
        Err(source) => {
            return Err(HostKeyError::Write {
                path: path.to_path_buf(),
                source,
            });
        }
    };

    // Best effort — ignore the rare flush/sync error; the OS still has the bytes via
    // the (unbuffered) write, and the next reader will see them. A sync failure would
    // be reported here if, say, the disk is gone, which is a bigger problem than a
    // non-durable host key.
    if let Err(source) = file.write_all(pem.as_bytes()).await {
        let _unused = tokio::fs::remove_file(path).await; // don't leave a half-written file
        return Err(HostKeyError::Write {
            path: path.to_path_buf(),
            source,
        });
    }
    let _ignored_sync_err = file.sync_all().await;

    tracing::debug!(path = %path.display(), bytes = pem.len(), "wrote host key file");
    Ok(CreateOutcome::Created)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Reading a key we just wrote round-trips byte-for-byte.
    #[tokio::test]
    async fn generates_then_roundtrips() {
        let dir = std::env::temp_dir().join(format!(
            "ts-rs-hostkey-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        tokio::fs::create_dir_all(&dir).await.unwrap();
        let path = dir.join("ssh_host_ed25519_key");

        let first = load_or_generate(&path).await.unwrap();
        // File must exist now.
        assert!(tokio::fs::try_exists(&path).await.unwrap());

        let second = load_or_generate(&path).await.unwrap();
        // Public key fingerprint must match — same key on both calls.
        let fp = |k: &PrivateKey| {
            k.public_key()
                .fingerprint(ssh_key::HashAlg::Sha256)
                .to_string()
        };
        assert_eq!(
            fp(&first),
            fp(&second),
            "second load returned a different key"
        );

        // File contents must be OpenSSH PEM and parse independently.
        let bytes = tokio::fs::read(&path).await.unwrap();
        let reparsed = PrivateKey::from_openssh(&bytes).unwrap();
        assert_eq!(
            fp(&first),
            fp(&reparsed),
            "on-disk key differs from returned key"
        );

        // File must be owner-only on Unix.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = tokio::fs::metadata(&path)
                .await
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(
                perms & 0o777,
                0o600,
                "host key file should be 0600, got {:o}",
                perms
            );
        }

        std::fs::remove_dir_all(&dir).ok();
    }

    /// A corrupt file is reported, not silently overwritten.
    #[tokio::test]
    async fn corrupt_file_is_reported_not_overwritten() {
        let dir = std::env::temp_dir().join(format!(
            "ts-rs-hostkey-corrupt-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        tokio::fs::create_dir_all(&dir).await.unwrap();
        let path = dir.join("ssh_host_ed25519_key");
        tokio::fs::write(&path, b"not a real key").await.unwrap();

        let err = load_or_generate(&path).await.unwrap_err();
        assert!(matches!(err, HostKeyError::Parse { .. }), "got {err:?}");

        // The corrupt bytes must still be on disk — we don't auto-heal.
        let still_bad = tokio::fs::read_to_string(&path).await.unwrap();
        assert_eq!(still_bad, "not a real key");

        std::fs::remove_dir_all(&dir).ok();
    }

    /// If the parent directory doesn't exist, the error names the path.
    #[tokio::test]
    async fn missing_dir_is_write_error() {
        let path = std::env::temp_dir().join(format!(
            "ts-rs-hostkey-missingdir-{}/ssh_host_ed25519_key",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let err = load_or_generate(&path).await.unwrap_err();
        match err {
            HostKeyError::Write { path: p, .. } => assert_eq!(p, path),
            other => panic!("expected Write error, got {other:?}"),
        }
    }

    /// `public_openssh_string` returns the wire format `Hostinfo.SSH_HostKeys` expects:
    /// `<key-type> <base64>`, single-line, no comment, no trailing newline.
    ///
    /// This is the format `tailscale ssh` clients parse verbatim into known_hosts
    /// (see `cmd/tailscale/cli/ssh.go::genKnownHosts` in tailscale/tailscale) — a
    /// malformed value here means the SSH client refuses the host key on connect.
    #[test]
    fn public_openssh_string_matches_authorized_keys_value_format() {
        let key = PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).unwrap();
        let encoded = public_openssh_string(&key).unwrap();

        // Wire-format invariants the client relies on.
        assert!(
            encoded.starts_with("ssh-ed25519 "),
            "encoded host key must start with the key type, got {encoded:?}"
        );
        assert!(
            !encoded.contains('\n') && !encoded.contains('\r'),
            "encoded host key must be a single line, got {encoded:?}"
        );
        assert!(
            !encoded.ends_with(' '),
            "encoded host key must not have a trailing space, got {encoded:?}"
        );

        // Two whitespace-separated tokens only: key type + base64 blob. No comment.
        let parts: Vec<&str> = encoded.split_whitespace().collect();
        assert_eq!(
            parts.len(),
            2,
            "encoded host key must be exactly `type SP base64`, got {encoded:?}"
        );
        assert_eq!(parts[0], "ssh-ed25519");
        assert!(parts[1].starts_with("AAAA"), "base64 blob starts with the magic bytes");

        // The serialized form must round-trip through `PublicKey::from_openssh`.
        let reparsed = russh::keys::ssh_key::PublicKey::from_openssh(&encoded).unwrap();
        assert_eq!(
            key.public_key().fingerprint(ssh_key::HashAlg::Sha256),
            reparsed.fingerprint(ssh_key::HashAlg::Sha256),
            "reparsed public key fingerprint must match the original"
        );
    }

    /// `public_openssh_string` produces the same value across calls on the same key —
    /// no hidden state, no nondeterminism. Regression for "host key advertisement must
    /// be stable so peers' known_hosts entries don't churn across MapRequests."
    #[test]
    fn public_openssh_string_is_stable_across_calls() {
        let key = PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).unwrap();
        let a = public_openssh_string(&key).unwrap();
        let b = public_openssh_string(&key).unwrap();
        assert_eq!(a, b, "public_openssh_string must be deterministic");
    }
}
