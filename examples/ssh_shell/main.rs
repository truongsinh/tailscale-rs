//! Run an SSH server on the tailnet that serves real `exec` and `shell` sessions,
//! authenticating clients against an `authorized_keys` file.
//!
//! Sessions are pipe-backed: no pty is allocated, and `pty-req` is refused. See the
//! module docs on [`ShellServer`] for why.

use std::{collections::HashMap, net::IpAddr, path::PathBuf, process::Stdio, sync::Arc};

use clap::Parser;
use russh::{
    Channel, ChannelId,
    keys::{Algorithm, PublicKey},
    server::{Auth, Handle, Handler, Msg, Session},
};
use tailscale::ssh::TailnetServer;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    process::{Child, ChildStdin, Command},
    task::JoinSet,
};
use tracing_subscriber::filter::LevelFilter;

mod authorized_keys;

use authorized_keys::AuthorizedKeys;

/// Run an SSH server on the tailnet serving exec and shell sessions.
///
/// Clients must authenticate with a public key listed in the --authorized-keys file;
/// password and none authentication are refused. Note that tailnet policy rules still
/// apply on top of this: a peer that policy forbids from reaching the listen port never
/// gets as far as authenticating.
#[derive(clap::Parser)]
#[command(version, about)]
struct Args {
    /// Path to a key file to use. Will be created if it doesn't exist.
    #[arg(short = 'c', long, default_value = "tsrs_keys.json")]
    key_file: PathBuf,

    /// The auth key to connect with.
    ///
    /// Can be omitted if the key file is already authenticated.
    #[arg(short = 'k', long)]
    auth_key: Option<String>,

    /// Port to listen on (on tailnet IPv4).
    #[clap(short, long, default_value_t = 22)]
    listen_port: u16,

    /// Path to an OpenSSH authorized_keys file listing the keys permitted to connect.
    #[clap(short = 'A', long)]
    authorized_keys: PathBuf,
}

/// The keys permitted to connect, and the process each session runs.
///
/// This is process-global state rather than a field threaded into the handler because
/// [`TailnetServer::new_client`] fixes the handler's constructor signature at
/// `(device, addr)`, leaving no seam to inject per-server configuration. See the README.
static AUTHORIZED_KEYS: std::sync::OnceLock<AuthorizedKeys> = std::sync::OnceLock::new();

/// An SSH server serving one connection.
///
/// # Authentication
///
/// Public key only, against [`AUTHORIZED_KEYS`]. `none` and `password` are refused by
/// leaving russh's rejecting defaults in place and advertising only `publickey`.
///
/// # No pty
///
/// `pty-req` is answered with a channel failure. Allocating a pty on Windows means
/// ConPTY, which does not exist before Windows 10 version 1809 -- and this tree targets
/// Windows 7 (see `docs/win7.md`). Rather than allocate a pty on the platforms that have
/// one and fail on the platform we care about, no session gets one: `exec` channels are
/// unaffected (they never needed a pty), and `shell` sessions fall back to plain pipes,
/// which costs terminal emulation but works everywhere.
struct ShellServer {
    dev: Arc<tailscale::Device>,
    remote: std::net::SocketAddr,
    /// stdin of the process running on each channel, once one has been started.
    stdin: HashMap<ChannelId, ChildStdin>,
    /// Pumps forwarding process output; dropped (and so aborted) with the connection.
    pumps: JoinSet<()>,
}

impl TailnetServer for ShellServer {
    fn new_client(dev: Arc<tailscale::Device>, addr: std::net::SocketAddr) -> Self {
        Self {
            dev,
            remote: addr,
            stdin: HashMap::new(),
            pumps: JoinSet::new(),
        }
    }
}

impl ShellServer {
    /// Spawn `command` on the channel and wire its stdio to the channel.
    ///
    /// `None` runs the platform's interactive shell, i.e. an SSH `shell` request; `Some`
    /// runs a single command line through it, i.e. an `exec` request.
    async fn spawn(
        &mut self,
        channel: ChannelId,
        command: Option<&str>,
        session: &mut Session,
    ) -> Result<(), <Self as Handler>::Error> {
        let (shell, exec_flag) = if cfg!(windows) {
            ("cmd.exe", "/C")
        } else {
            ("/bin/sh", "-c")
        };

        let mut cmd = Command::new(shell);
        if let Some(command) = command {
            cmd.arg(exec_flag).arg(command);
        }

        let child = cmd
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn();

        let mut child = match child {
            Ok(child) => child,
            Err(e) => {
                tracing::error!(error = %e, %channel, shell, "spawning process");
                // The client asked for something we could not deliver, so fail the request
                // rather than leave it hanging on a channel that will never produce output.
                session.channel_failure(channel)?;
                return Ok(());
            }
        };

        tracing::info!(
            %channel,
            remote = %self.remote,
            pid = child.id(),
            command = command.unwrap_or(shell),
            "session started"
        );

        if let Some(stdin) = child.stdin.take() {
            self.stdin.insert(channel, stdin);
        }

        session.channel_success(channel)?;
        self.pump(channel, child, session.handle());

        Ok(())
    }

    /// Forward the child's stdout and stderr to the channel, then report its exit status.
    fn pump(&mut self, channel: ChannelId, mut child: Child, handle: Handle) {
        let (stdout, stderr) = (child.stdout.take(), child.stderr.take());

        if let Some(stdout) = stdout {
            let handle = handle.clone();
            self.pumps.spawn(async move {
                forward(stdout, channel, &handle, DataKind::Stdout).await;
            });
        }

        if let Some(stderr) = stderr {
            let handle = handle.clone();
            self.pumps.spawn(async move {
                forward(stderr, channel, &handle, DataKind::Stderr).await;
            });
        }

        self.pumps.spawn(async move {
            let status = match child.wait().await {
                Ok(status) => status,
                Err(e) => {
                    tracing::error!(error = %e, %channel, "waiting on process");
                    let _ = handle.close(channel).await;
                    return;
                }
            };

            // A process killed by a signal has no exit code. SSH can carry the signal
            // itself, but mapping libc signal numbers to the protocol's names is more
            // ceremony than this example needs; report the shell's own convention instead.
            let code = status.code().unwrap_or(128) as u32;

            tracing::info!(%channel, exit_status = code, "session finished");

            let _ = handle.exit_status_request(channel, code).await;
            let _ = handle.eof(channel).await;
            let _ = handle.close(channel).await;
        });
    }
}

/// Which of the channel's two output streams bytes belong to.
#[derive(Copy, Clone)]
enum DataKind {
    Stdout,
    Stderr,
}

/// Copy `src` to the channel until EOF, as one SSH data message per read.
async fn forward(
    mut src: impl tokio::io::AsyncRead + Unpin,
    channel: ChannelId,
    handle: &Handle,
    kind: DataKind,
) {
    let mut buf = vec![0u8; 32 * 1024];

    loop {
        let n = match src.read(&mut buf).await {
            Ok(0) => return,
            Ok(n) => n,
            Err(e) => {
                tracing::error!(error = %e, %channel, "reading process output");
                return;
            }
        };

        let data = buf[..n].to_vec();

        // Both of these fail only once the channel is gone, which is not an error: the
        // client hung up and the process just has not noticed yet.
        let sent = match kind {
            DataKind::Stdout => handle.data(channel, data).await.map_err(|_| ()),
            // Extended data type 1 is stderr, per RFC 4254 section 5.2.
            DataKind::Stderr => handle.extended_data(channel, 1, data).await.map_err(|_| ()),
        };

        if sent.is_err() {
            tracing::debug!(%channel, "channel closed while writing output");
            return;
        }
    }
}

impl Handler for ShellServer {
    type Error = russh::Error;

    #[tracing::instrument(skip_all, fields(user = %user, remote = %self.remote))]
    async fn auth_publickey(&mut self, user: &str, key: &PublicKey) -> Result<Auth, Self::Error> {
        let peer = self
            .dev
            .peer_by_tailnet_ip(self.remote.ip())
            .await
            .ok()
            .flatten();

        let Some(keys) = AUTHORIZED_KEYS.get() else {
            tracing::error!("authorized keys unset");
            return Ok(Auth::reject());
        };

        if !keys.contains(key) {
            tracing::warn!(
                fingerprint = %key.fingerprint(Default::default()),
                peer = peer.as_ref().map(|p| p.fqdn(false)),
                "rejecting unauthorized key"
            );
            return Ok(Auth::reject());
        }

        tracing::info!(
            fingerprint = %key.fingerprint(Default::default()),
            peer = peer.as_ref().map(|p| p.fqdn(false)),
            "authenticated"
        );

        Ok(Auth::Accept)
    }

    async fn channel_open_session(
        &mut self,
        channel: Channel<Msg>,
        _session: &mut Session,
    ) -> Result<bool, Self::Error> {
        tracing::debug!(channel = %channel.id(), remote = %self.remote, "new session");

        Ok(true)
    }

    async fn shell_request(
        &mut self,
        channel: ChannelId,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.spawn(channel, None, session).await
    }

    async fn exec_request(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        let Ok(command) = str::from_utf8(data) else {
            tracing::warn!(%channel, "exec request is not utf-8");
            session.channel_failure(channel)?;
            return Ok(());
        };

        self.spawn(channel, Some(command), session).await
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
        tracing::info!(%channel, term, "refusing pty request; sessions are pipe-backed");

        session.channel_failure(channel)?;

        Ok(())
    }

    async fn data(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        let Some(stdin) = self.stdin.get_mut(&channel) else {
            tracing::debug!(%channel, "data for a channel with no process");
            return Ok(());
        };

        // The process exiting closes its stdin, and the client may not have noticed yet;
        // dropping the write matches what a shell pipeline does with EPIPE.
        if let Err(e) = stdin.write_all(data).await {
            tracing::debug!(error = %e, %channel, "writing to process stdin");
            self.stdin.remove(&channel);
        }

        Ok(())
    }

    async fn channel_eof(
        &mut self,
        channel: ChannelId,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        // Dropping stdin closes the pipe, which is how the process learns to finish. Without
        // this, `ssh host cat < file` would hang forever waiting on a stdin that never ends.
        tracing::debug!(%channel, "client eof; closing process stdin");
        self.stdin.remove(&channel);

        Ok(())
    }

    async fn channel_close(
        &mut self,
        channel: ChannelId,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        tracing::debug!(%channel, "channel closed");
        self.stdin.remove(&channel);

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

    let args = Args::parse();

    let path = args.authorized_keys.display().to_string();
    let contents = tokio::fs::read_to_string(&args.authorized_keys).await?;
    let keys = AuthorizedKeys::parse(&path, &contents)?;

    if keys.len() == 0 {
        // Every connection would be rejected, which looks like a network fault from the
        // client side. Fail loudly at startup instead.
        return Err(format!("{path}: no keys, so no client could ever authenticate").into());
    }

    tracing::info!(keys = keys.len(), path, "loaded authorized keys");

    // Nothing else ever sets this, so the only way to fail here is a bug in this function.
    AUTHORIZED_KEYS
        .set(keys)
        .expect("authorized keys are set exactly once, at startup");

    let dev = tailscale::Device::new(
        &tailscale::Config::default_with_key_file(&args.key_file).await?,
        args.auth_key,
    )
    .await?;

    let ipv4: IpAddr = dev.ipv4_addr().await?.into();
    let dev = Arc::new(dev);

    dev.serve_ssh::<ShellServer>(
        russh::server::Config {
            keys: vec![russh::keys::PrivateKey::random(
                &mut rand::rng(),
                Algorithm::Ed25519,
            )?],
            methods: russh::MethodSet::from(&[russh::MethodKind::PublicKey][..]),
            nodelay: true,
            ..Default::default()
        },
        (ipv4, args.listen_port).into(),
    )
    .await?;

    Ok(())
}
