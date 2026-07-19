//! Run an SSH server on the tailnet that serves real `exec` and `shell` sessions.
//!
//! There is no application-level authentication: authorization is delegated entirely to
//! the tailnet ACL / packet filter. A peer that reaches the listen port has already been
//! admitted, and the server accepts it and logs who connected.
//!
//! Sessions are pipe-backed: no pty is allocated, and `pty-req` is refused. See the
//! module docs on [`ShellServer`] for why.

use std::{net::IpAddr, path::{Path, PathBuf}, sync::Arc};

use clap::Parser;
use russh::{
    Channel, ChannelId,
    keys::Algorithm,
    server::{Auth, Handler, Msg, Session},
};
use tailscale::ssh::TailnetServer;
use tokio::fs;
use tracing_subscriber::filter::LevelFilter;

// Per-channel session driver (exec/shell request → child process → pumps).
// Split out so integration tests can include the REAL loop via `#[path]`
// instead of mirroring it. See channel_loop.rs module docs.
mod channel_loop;

// Fleet self-update pipeline: manifest poll, atomic binary swap, rollback stack.
// Spawned from main() when --manifest-url is provided. See `.doc/2026-07-fleet-self-update.md`.
mod updater;

/// Run an SSH server on the tailnet serving exec and shell sessions.
///
/// There is no application-level authentication. A peer that reaches the listen port has
/// already been admitted by the tailnet packet filter, which enforces the tailnet ACL; the
/// server accepts it and logs who connected. Tighten who may reach this port in the
/// tailnet policy, not here.
#[derive(clap::Parser)]
#[command(version, about)]
struct Args {
    /// Path to a key file to use. Will be created if it doesn't exist
    #[arg(short = 'c', long, default_value = "tsrs_keys.json")]
    key_file: PathBuf,

    /// The auth key to connect with. Can be omitted if the key file is already authenticated.
    #[arg(short = 'k', long)]
    auth_key: Option<String>,

    /// Port to listen on (on tailnet IPv4)
    #[clap(short, long, default_value_t = 22)]
    listen_port: u16,

    /// URL of the fleet update manifest. If set, a background updater task is spawned
    /// that periodically checks for a newer binary and, when one is available, stages
    /// it and exits cleanly so the supervisor relaunches the new file. See
    /// `.doc/2026-07-fleet-self-update.md`.
    #[arg(long = "manifest-url", env = "KOIDRA_MANIFEST_URL")]
    manifest_url: Option<url::Url>,

    /// Install directory holding binaries + state files. Defaults to the parent of the
    /// running exe, which is correct for the standard fleet layouts. Override only for
    /// dev/test.
    #[arg(long = "install-dir", env = "KOIDRA_INSTALL_DIR")]
    install_dir: Option<PathBuf>,
}

/// An SSH server serving one connection.
///
/// # Authentication
///
/// None: authorization is delegated entirely to the tailnet ACL / packet filter. A peer
/// that reaches the listen port has already been admitted; `auth_none` resolves it only to
/// log who connected, then accepts unconditionally. `publickey` and `password` are refused
/// by leaving russh's rejecting defaults in place and advertising only `none`.
///
/// # No pty
///
/// `pty-req` is answered with a channel failure. Allocating a pty on Windows means
/// ConPTY, which does not exist before Windows 10 version 1809 -- and this tree targets
/// Windows 7 (see `docs/win7.md`). Rather than allocate a pty on the platforms that have
/// one and fail on the platform we care about, no session gets one: `exec` channels are
/// unaffected (they never needed a pty), and `shell` sessions fall back to plain pipes,
/// which costs terminal emulation but works everywhere.
///
/// # Channel data path (why `channel.wait()` and not the `data()` callback)
///
/// Each russh channel has an internal mpsc (bound 100 messages by default) that the
/// dispatch loop fills BEFORE invoking `handler.data()`. If the handler is the only
/// consumer of inbound data and writes serially to a slow sink (e.g. a child process's
/// stdin pipe), the mpsc fills, the dispatch's `chan.send(Data).await` blocks, no
/// further protocol messages are processed, and the inbound path deadlocks. With
/// OpenSSH clients this surfaces as silent truncation around ~1 MB into a multi-MB
/// transfer. The canonical russh pattern (used by `test_data_stream.rs` and here)
/// drains the mpsc via `channel.wait()` / `make_reader()` in a dedicated task; the
/// `data()` callback is left as a no-op.
struct ShellServer {
    dev: Arc<tailscale::Device>,
    remote: std::net::SocketAddr,
}

impl TailnetServer for ShellServer {
    fn new_client(dev: Arc<tailscale::Device>, addr: std::net::SocketAddr) -> Self {
        Self { dev, remote: addr }
    }
}

impl Handler for ShellServer {
    type Error = russh::Error;

    #[tracing::instrument(skip_all, fields(remote = %self.remote))]
    async fn auth_none(&mut self, _user: &str) -> Result<Auth, Self::Error> {
        let peer = self
            .dev
            .peer_by_tailnet_ip(self.remote.ip())
            .await
            .ok()
            .flatten();

        tracing::info!(
            peer = peer.as_ref().map(|p| p.fqdn(false)),
            "accepting session (tailnet-authorized)"
        );

        Ok(Auth::Accept)
    }

    async fn channel_open_session(
        &mut self,
        channel: Channel<Msg>,
        session: &mut Session,
    ) -> Result<bool, Self::Error> {
        tracing::debug!(channel = %channel.id(), remote = %self.remote, "new session");
        // Per-channel driver task. Owns the child + all copy pumps. Drains the
        // inbound mpsc via `channel.wait()` so russh's dispatch loop never blocks
        // on `chan.send(Data)` (see struct doc). The session handle lets the loop
        // answer want_reply exec/shell requests (channel_success / channel_failure).
        let remote = self.remote;
        let handle = session.handle();
        tokio::spawn(async move {
            channel_loop::run_session(channel, handle, remote).await;
        });
        Ok(true)
    }

    async fn pty_request(
        &mut self,
        channel: ChannelId,
        term: &str,
        _: u32,
        _: u32,
        _: u32,
        _: u32,
        _: &[(russh::Pty, u32)],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        // Refuse PTY allocation (see ShellServer doc: no pty). Handled here rather
        // than in the wait() loop because the reply goes through Session, which the
        // loop doesn't own.
        tracing::info!(%channel, term, "refusing pty request; sessions are pipe-backed");
        session.channel_failure(channel)?;
        Ok(())
    }
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<(), Box<dyn core::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::builder()
                .with_default_directive(LevelFilter::INFO.into())
                .from_env_lossy(),
        )
        .init();

    tracing::info!(version = tailscale::IPN_VERSION, "starting ssh_shell");

    tracing::warn!(
        "authorization is delegated to the tailnet ACL / packet filter; this server accepts \
         any peer that reaches the listen port"
    );

    let args = Args::parse();

    let dev = tailscale::Device::new(
        &tailscale::Config::default_from_env_with_key_file(&args.key_file).await?,
        args.auth_key,
    )
    .await?;

    let ipv4: IpAddr = dev.ipv4_addr().await?.into();
    let dev = Arc::new(dev);

    // Install dir = parent of the running exe by default. Override via --install-dir.
    let install_dir = args.install_dir.clone().unwrap_or_else(|| {
        std::env::current_exe()
            .ok()
            .and_then(|p| p.parent().map(|p| p.to_path_buf()))
            .unwrap_or_else(|| PathBuf::from("."))
    });

    // Boot contract — `.doc/2026-07-supervisor-restart-interface.md` §2.1.
    // Write .boot-state.json BEFORE serve_ssh so the supervisor's health-gate can
    // detect a failed launch (the gate probes TCP, but boot-state records the attempt).
    write_boot_state(&install_dir, tailscale::IPN_VERSION, ipv4).await;

    // Spawn the updater task if a manifest URL was provided. The task runs for the
    // process lifetime; on a successful update it calls process::exit(0) so the
    // supervisor relaunches the new binary. See `updater` module docs.
    if let Some(url) = args.manifest_url.clone() {
        updater::spawn(install_dir.clone(), tailscale::IPN_VERSION, url.to_string());
    }

    dev.serve_ssh::<ShellServer>(
        russh::server::Config {
            keys: vec![russh::keys::PrivateKey::random(
                &mut rand::rng(),
                Algorithm::Ed25519,
            )?],
            methods: russh::MethodSet::from(&[russh::MethodKind::None][..]),
            nodelay: true,
            ..Default::default()
        },
        (ipv4, args.listen_port).into(),
    )
    .await?;

    Ok(())
}

/// Write `.boot-state.json` atomically in the install dir.
///
/// Records `{schema, booted_at, version, target_ip}` so the supervisor's health-gate
/// can detect a failed launch (binary booted, wrote boot-state, then died within the
/// gate window — the supervisor pops the rollback stack and reverts).
///
/// Failure to write is non-fatal: the supervisor's gate just can't distinguish a
/// fresh-launch failure from a mid-run crash, which only affects automatic rollback
/// (plain crash-recovery still works via the supervisor's default restart behavior).
async fn write_boot_state(install_dir: &Path, version: &str, target_ip: IpAddr) {
    let boot_state = serde_json::json!({
        "schema": 1,
        "booted_at": chrono::Utc::now().to_rfc3339(),
        "version": version,
        "target_ip": target_ip.to_string(),
    });
    let path = install_dir.join(".boot-state.json");
    let tmp = install_dir.join(".boot-state.json.tmp");
    if let Err(e) = fs::write(&tmp, boot_state.to_string()).await {
        tracing::warn!(error = %e, path = %path.display(), "failed to write boot-state tmp");
        return;
    }
    if let Err(e) = fs::rename(&tmp, &path).await {
        tracing::warn!(error = %e, path = %path.display(), "failed to rename boot-state into place");
        // Best-effort cleanup of the orphan temp file.
        let _ = fs::remove_file(&tmp).await;
    }
    tracing::debug!(path = %path.display(), %version, "boot-state written");
}
