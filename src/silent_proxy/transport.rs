//! Transport layer for the silent-proxy: a Unix domain socket on Linux/macOS, a named
//! pipe on Windows. **No TCP listener is ever opened** — that is the user-locked design
//! constraint (see the build-task brief in `tailscale-rs-fork-state`): the proxy MUST NOT
//! appear in `netstat` / `Get-NetTCPConnection` / `ss -ltn`. Both Unix sockets and named
//! pipes are invisible to those tools.
//!
//! Both transports produce a stream that implements `tokio::io::AsyncRead + AsyncWrite`,
//! so the SOCKS5 protocol code in [`super::socks5`] is fully agnostic to which one is in
//! use.
//!
//! # Paths / names
//!
//! Defaults match the convention used by gti14's real Tailscale daemon
//! (`/run/tailscale/tailscaled.sock`):
//!
//! | Platform | Default | Override |
//! |---|---|---|
//! | Linux/macOS | `/run/tailscale-koidra-proxy.sock` | `--silent-proxy-socket <path>` |
//! | Windows     | `\\.\pipe\koidra-tailnet-proxy`    | `--silent-proxy-pipe <name>` |
//!
//! On Linux the listener `chmod`s the socket to `0666` after bind so that any local user
//! can reach it — the tailnet ACL is still the only authorization boundary, exactly like
//! `serve_ssh`. Set tighter permissions at the directory level (e.g. `/run/tailscale-*`
//! with mode `0750` owned by a group) if you want to gate which local users can dial out.

use std::io;

#[cfg(unix)]
use std::path::PathBuf;

use tokio::io::{AsyncRead, AsyncWrite};

/// Backend-agnostic listener: `accept()` returns a stream that's `AsyncRead + AsyncWrite`.
///
/// We box the stream because the SOCKS5 driver is monomorphic per platform but the caller
/// (the proxy task) needs a single concrete type to move around. This is one allocation
/// per accepted connection — negligible vs. the cost of a tailnet dial.
pub struct ProxyListener {
    inner: ProxyListenerKind,
    /// The original endpoint the listener was bound to — kept for diagnostics + the
    /// Windows accept loop, which needs the pipe name to replenish its instance pool.
    endpoint: ListenEndpoint,
}

enum ProxyListenerKind {
    #[cfg(unix)]
    Unix(tokio::net::UnixListener),
    #[cfg(windows)]
    Pipe(Vec<tokio::net::windows::named_pipe::NamedPipeServer>),
    #[cfg(not(any(unix, windows)))]
    Unsupported,
}

/// A connected client stream — what `accept()` yields. Implements the read/write halves
/// the SOCKS5 protocol expects.
pub struct ProxyStream {
    inner: ProxyStreamKind,
}

enum ProxyStreamKind {
    #[cfg(unix)]
    Unix(tokio::net::UnixStream),
    #[cfg(windows)]
    Pipe(tokio::net::windows::named_pipe::NamedPipeServer),
    #[cfg(not(any(unix, windows)))]
    Unsupported,
}

/// Where to bind the silent-proxy listener.
#[derive(Debug, Clone)]
pub enum ListenEndpoint {
    /// Unix socket path (Linux/macOS).
    #[cfg(unix)]
    Unix(PathBuf),
    /// Named-pipe name (Windows). Should be a bare name like `koidra-tailnet-proxy`,
    /// not a full `\\.\pipe\...` path — the `\\.\pipe\` prefix is added by this module.
    #[cfg(windows)]
    Pipe(String),
}

impl ListenEndpoint {
    /// Display-friendly descriptor for logs.
    pub fn display(&self) -> String {
        match self {
            #[cfg(unix)]
            ListenEndpoint::Unix(p) => format!("unix:{}", p.display()),
            #[cfg(windows)]
            ListenEndpoint::Pipe(n) => format!(r"pipe:\\.\pipe\{}", n),
        }
    }

    /// Default endpoint for the host platform.
    #[cfg(unix)]
    pub fn platform_default() -> Self {
        ListenEndpoint::Unix(PathBuf::from("/run/tailscale-koidra-proxy.sock"))
    }

    /// Default endpoint for the host platform.
    #[cfg(windows)]
    pub fn platform_default() -> Self {
        ListenEndpoint::Pipe(String::from("koidra-tailnet-proxy"))
    }

    #[cfg(not(any(unix, windows)))]
    pub fn platform_default() -> Self {
        compile_error!("silent_proxy: unsupported platform (need Unix socket or named pipe)");
    }
}

/// Size of the pre-allocated Windows named-pipe instance pool. With 4 instances, up to 4
/// clients can be in-flight through `connect()` simultaneously; `accept()` replenishes
/// after each connect. Plenty for on-box scripts (which dial sequentially or with low
/// concurrency); raise if a real workload shows pipe-pool-exhaustion errors in logs.
#[cfg(windows)]
const PIPE_POOL_SIZE: usize = 4;

impl ProxyListener {
    /// Bind the listener at the given endpoint.
    ///
    /// On Unix, the socket file is removed first if it already exists (a stale socket
    /// from a previous crash). On Windows, this is a no-op — named pipes don't have a
    /// filesystem representation.
    pub async fn bind(endpoint: &ListenEndpoint) -> io::Result<Self> {
        match endpoint {
            #[cfg(unix)]
            ListenEndpoint::Unix(path) => {
                // Best-effort unlink of a stale socket from a prior crash. Ignore errors
                // — if it's a live socket, bind() will fail and surface the real error.
                drop(std::fs::remove_file(path));
                let listener = tokio::net::UnixListener::bind(path)?;
                // World read/write so any local user can dial. Authorization is the
                // tailnet ACL's job, identical to serve_ssh.
                use std::os::unix::fs::PermissionsExt;
                drop(std::fs::set_permissions(
                    path,
                    std::fs::Permissions::from_mode(0o666),
                ));
                tracing::info!(
                    path = %path.display(),
                    "silent-proxy listening on Unix socket"
                );
                Ok(Self {
                    inner: ProxyListenerKind::Unix(listener),
                    endpoint: endpoint.clone(),
                })
            }
            #[cfg(windows)]
            ListenEndpoint::Pipe(name) => {
                use tokio::net::windows::named_pipe::ServerOptions;
                let pipe_path = format!(r"\\.\pipe\{}", name);
                let mut instances = Vec::with_capacity(PIPE_POOL_SIZE);
                for _ in 0..PIPE_POOL_SIZE {
                    instances.push(
                        ServerOptions::new()
                            .first_pipe_instance(false)
                            .max_instances(255)
                            .out_buffer_size(64 * 1024)
                            .in_buffer_size(64 * 1024)
                            .create(&pipe_path)?,
                    );
                }
                tracing::info!(%pipe_path, "silent-proxy listening on named pipe");
                Ok(Self {
                    inner: ProxyListenerKind::Pipe(instances),
                    endpoint: endpoint.clone(),
                })
            }
            #[cfg(not(any(unix, windows)))]
            _ => Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "silent_proxy: no transport on this platform",
            )),
        }
    }

    /// Accept the next inbound client connection.
    pub async fn accept(&mut self) -> io::Result<ProxyStream> {
        match (&mut self.inner, &self.endpoint) {
            #[cfg(unix)]
            (ProxyListenerKind::Unix(listener), _) => {
                let (stream, peer) = listener.accept().await?;
                tracing::debug!(?peer, "silent-proxy: client connected on Unix socket");
                Ok(ProxyStream {
                    inner: ProxyStreamKind::Unix(stream),
                })
            }
            #[cfg(windows)]
            (ProxyListenerKind::Pipe(instances), ListenEndpoint::Pipe(name)) => {
                // Named-pipe accept: each pre-spawned instance completes a `connect()`
                // when a client arrives; after each accept, we push a fresh instance
                // back into the pool so the next client has something to connect to.
                let server = instances.pop().ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::Other,
                        "silent-proxy: pipe pool exhausted (busy client burst?)",
                    )
                })?;
                server.connect().await?;

                // Replenish. If this fails (e.g. the OS denied a new instance) we log
                // and keep going with a smaller pool rather than killing the listener —
                // the next accept will fail loudly if the pool truly is empty.
                let pipe_path = format!(r"\\.\pipe\{}", name);
                use tokio::net::windows::named_pipe::ServerOptions;
                match ServerOptions::new()
                    .first_pipe_instance(false)
                    .max_instances(255)
                    .out_buffer_size(64 * 1024)
                    .in_buffer_size(64 * 1024)
                    .create(&pipe_path)
                {
                    Ok(fresh) => instances.push(fresh),
                    Err(e) => {
                        tracing::warn!(
                            error = %e,
                            remaining = instances.len(),
                            "silent-proxy: named-pipe pool replenish failed; running with fewer instances"
                        );
                    }
                }

                tracing::debug!("silent-proxy: client connected on named pipe");
                Ok(ProxyStream {
                    inner: ProxyStreamKind::Pipe(server),
                })
            }
            #[cfg(not(any(unix, windows)))]
            _ => unreachable!("unsupported platform gated at bind"),
        }
    }
}

impl ProxyStream {
    /// Split into read and write halves for `tokio::io::copy` semantics.
    pub fn split(self) -> (ProxyReadHalf, ProxyWriteHalf) {
        match self.inner {
            #[cfg(unix)]
            ProxyStreamKind::Unix(s) => {
                let (r, w) = tokio::io::split(s);
                (ProxyReadHalf::Unix(r), ProxyWriteHalf::Unix(w))
            }
            #[cfg(windows)]
            ProxyStreamKind::Pipe(s) => {
                let (r, w) = tokio::io::split(s);
                (ProxyReadHalf::Pipe(r), ProxyWriteHalf::Pipe(w))
            }
            #[cfg(not(any(unix, windows)))]
            _ => unreachable!(),
        }
    }
}

/// Read half of a [`ProxyStream`].
pub enum ProxyReadHalf {
    /// Unix-socket read half (Linux/macOS).
    #[cfg(unix)]
    Unix(tokio::io::ReadHalf<tokio::net::UnixStream>),
    /// Named-pipe read half (Windows).
    #[cfg(windows)]
    Pipe(tokio::io::ReadHalf<tokio::net::windows::named_pipe::NamedPipeServer>),
    #[cfg(not(any(unix, windows)))]
    Unsupported,
}

/// Write half of a [`ProxyStream`].
pub enum ProxyWriteHalf {
    /// Unix-socket write half (Linux/macOS).
    #[cfg(unix)]
    Unix(tokio::io::WriteHalf<tokio::net::UnixStream>),
    /// Named-pipe write half (Windows).
    #[cfg(windows)]
    Pipe(tokio::io::WriteHalf<tokio::net::windows::named_pipe::NamedPipeServer>),
    #[cfg(not(any(unix, windows)))]
    Unsupported,
}

impl AsyncRead for ProxyReadHalf {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        match self.get_mut() {
            #[cfg(unix)]
            ProxyReadHalf::Unix(r) => std::pin::Pin::new(r).poll_read(cx, buf),
            #[cfg(windows)]
            ProxyReadHalf::Pipe(r) => std::pin::Pin::new(r).poll_read(cx, buf),
            #[cfg(not(any(unix, windows)))]
            ProxyReadHalf::Unsupported => {
                unreachable!("unsupported platform gated at bind")
            }
        }
    }
}

impl AsyncWrite for ProxyWriteHalf {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<io::Result<usize>> {
        match self.get_mut() {
            #[cfg(unix)]
            ProxyWriteHalf::Unix(w) => std::pin::Pin::new(w).poll_write(cx, buf),
            #[cfg(windows)]
            ProxyWriteHalf::Pipe(w) => std::pin::Pin::new(w).poll_write(cx, buf),
            #[cfg(not(any(unix, windows)))]
            ProxyWriteHalf::Unsupported => {
                unreachable!("unsupported platform gated at bind")
            }
        }
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        match self.get_mut() {
            #[cfg(unix)]
            ProxyWriteHalf::Unix(w) => std::pin::Pin::new(w).poll_flush(cx),
            #[cfg(windows)]
            ProxyWriteHalf::Pipe(w) => std::pin::Pin::new(w).poll_flush(cx),
            #[cfg(not(any(unix, windows)))]
            ProxyWriteHalf::Unsupported => {
                unreachable!("unsupported platform gated at bind")
            }
        }
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        match self.get_mut() {
            #[cfg(unix)]
            ProxyWriteHalf::Unix(w) => std::pin::Pin::new(w).poll_shutdown(cx),
            #[cfg(windows)]
            ProxyWriteHalf::Pipe(w) => std::pin::Pin::new(w).poll_shutdown(cx),
            #[cfg(not(any(unix, windows)))]
            ProxyWriteHalf::Unsupported => {
                unreachable!("unsupported platform gated at bind")
            }
        }
    }
}

// ProxyStream itself implements AsyncRead/Write by delegation, for callers that don't
// need splitting (e.g. the handshake driver, which wants a single stream).
impl AsyncRead for ProxyStream {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        match &mut self.get_mut().inner {
            #[cfg(unix)]
            ProxyStreamKind::Unix(s) => std::pin::Pin::new(s).poll_read(cx, buf),
            #[cfg(windows)]
            ProxyStreamKind::Pipe(s) => std::pin::Pin::new(s).poll_read(cx, buf),
            #[cfg(not(any(unix, windows)))]
            ProxyStreamKind::Unsupported => unreachable!(),
        }
    }
}

impl AsyncWrite for ProxyStream {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<io::Result<usize>> {
        match &mut self.get_mut().inner {
            #[cfg(unix)]
            ProxyStreamKind::Unix(s) => std::pin::Pin::new(s).poll_write(cx, buf),
            #[cfg(windows)]
            ProxyStreamKind::Pipe(s) => std::pin::Pin::new(s).poll_write(cx, buf),
            #[cfg(not(any(unix, windows)))]
            ProxyStreamKind::Unsupported => unreachable!(),
        }
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        match &mut self.get_mut().inner {
            #[cfg(unix)]
            ProxyStreamKind::Unix(s) => std::pin::Pin::new(s).poll_flush(cx),
            #[cfg(windows)]
            ProxyStreamKind::Pipe(s) => std::pin::Pin::new(s).poll_flush(cx),
            #[cfg(not(any(unix, windows)))]
            ProxyStreamKind::Unsupported => unreachable!(),
        }
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        match &mut self.get_mut().inner {
            #[cfg(unix)]
            ProxyStreamKind::Unix(s) => std::pin::Pin::new(s).poll_shutdown(cx),
            #[cfg(windows)]
            ProxyStreamKind::Pipe(s) => std::pin::Pin::new(s).poll_shutdown(cx),
            #[cfg(not(any(unix, windows)))]
            ProxyStreamKind::Unsupported => unreachable!(),
        }
    }
}
