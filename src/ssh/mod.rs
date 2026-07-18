//! Support for tailnet-native, in-process SSH servers.
//!
//! # Overview
//!
//! This module (`tailscale::ssh`) holds helpers for running SSH servers on the tailnet
//! using [`russh`]. They delegate their functionality to the [`Handler`] trait, which is
//! `russh`'s notion of a _connection_ handler, i.e. a single incoming TCP connection gets
//! a single instance of [`Handler`].
//!
//! ## Channels
//!
//! SSH has a nested notion of channels, which are multiplexed over a single connection.
//! The terminal session you open over a normal machine-to-machine ssh connection runs in a
//! channel, and in principle, you can have multiple channels open on the same connection.
//!
//! The `channel_server` module provides a [`ChannelServer`] type that separates out the
//! per-channel handler logic from `russh`'s monolithic [`Handler`]. Channel handler logic
//! is supported here by [`ChannelHandler`], which is passed into [`ChannelServer`] and
//! processes a [`ChannelEvent`] stream for each channel that's opened.
//!
//! ## Terminal applications
//!
//! Support for building per-channel terminal application is provided by [`RatatuiTerm`],
//! which implements [`ChannelHandler`] to drive a
//! [`ratatui::Terminal`][::ratatui::Terminal]. The user provides an implementation of
//! [`RatatuiApp`] that consumes input data and supports draws to the screen, and the
//! [`RatatuiTerm`] drives it automatically.

pub extern crate russh;

use std::{fmt::Debug, net::SocketAddr, sync::Arc, time::Duration};

use russh::server::Handler;

mod channel_server;
mod channel_write;
mod ratatui;

pub use channel_server::{ChannelEvent, ChannelHandler, ChannelServer};
pub use ratatui::{RatatuiApp, RatatuiEnv, RatatuiTerm};

/// How long a connection has to complete the SSH handshake before it is dropped.
///
/// [`russh::server::run_stream`] writes the server's identification string and then waits
/// for the client's, with no deadline of its own. A peer that opens a connection and never
/// speaks therefore parks a task -- and the netstack socket it holds -- indefinitely. The
/// netstack sets neither a keepalive nor a SYN-RECEIVED timeout, so nothing else reaps it
/// either; only dropping the connection does, and dropping it is what this timeout forces.
///
/// Note what this deliberately does not do: cap how many handshakes may be in flight. A cap
/// refuses connections once it is hit, and a refused connection is indistinguishable, from
/// the client's side, from the lockout this timeout exists to prevent. Bounding the time a
/// stalled handshake can hold its socket bounds the damage without ever turning a burst of
/// unauthenticated traffic into a closed door for a legitimate one.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(30);

/// Trait to construct a new [`Handler`] from a Tailscale [`Device`][crate::Device] and
/// the address of a connecting client.
///
/// Rephrasing of [`russh::server::Server`] that includes the Tailscale device as an
/// argument and skips the support for off-tailnet IP and Unix sockets.
pub trait TailnetServer {
    /// Construct a new handler.
    fn new_client(dev: Arc<crate::Device>, addr: SocketAddr) -> Self;
}

impl crate::Device {
    /// Serve an ssh service on the given TCP address.
    ///
    /// This is a minimal helper that just wires up the relevant pieces. All the
    /// authentication and actual SSH server logic must be implemented by the caller in
    /// the `TailnetServer` (`H`) and configured by `config`.
    pub async fn serve_ssh<H>(
        self: Arc<Self>,
        config: russh::server::Config,
        listen_addr: SocketAddr,
    ) -> Result<(), crate::Error>
    where
        H: TailnetServer + Handler + Send + 'static,
        H::Error: Debug,
    {
        let config = Arc::new(config);
        let listener = self.tcp_listen(listen_addr).await?;

        tracing::info!(%listen_addr, "gateway listener ready");

        loop {
            // An error here is not per-connection: the listener is gone (its handle closed,
            // or the netstack channel is shut), and every subsequent accept would fail the
            // same way. Returning surfaces that; looping would spin on it forever.
            let conn = listener.accept().await?;
            let remote = conn.remote_addr();

            let handler = H::new_client(self.clone(), remote);
            let config = config.clone();

            tokio::task::spawn(async move {
                let handshake = russh::server::run_stream(config, conn, handler);

                let sess = match tokio::time::timeout(HANDSHAKE_TIMEOUT, handshake).await {
                    Ok(Ok(sess)) => sess,
                    // Neither arm is the server's problem: a peer that hangs up mid-handshake
                    // or never speaks is routine on a reachable port, and logging it at error
                    // buries real faults in noise from anything that scans or retries.
                    Ok(Err(e)) => {
                        tracing::debug!(%remote, error = ?e, "establishing session");
                        return;
                    }
                    Err(_elapsed) => {
                        tracing::debug!(%remote, ?HANDSHAKE_TIMEOUT, "handshake timed out");
                        return;
                    }
                };

                if let Err(e) = sess.await {
                    tracing::debug!(%remote, error = ?e, "running gateway session");
                }
            });
        }
    }

    /// Serve an SSH TUI service on the given TCP address.
    ///
    /// Wrapper around [`serve_ssh`][crate::Device::serve_ssh] to specifically use
    /// [`ChannelServer`] around a [`RatatuiTerm`] using `App`.
    pub async fn serve_ssh_tui<App>(
        self: Arc<Self>,
        config: russh::server::Config,
        listen_addr: SocketAddr,
    ) -> Result<(), crate::Error>
    where
        App: RatatuiApp + Default + Send + 'static,
    {
        self.serve_ssh::<ChannelServer<RatatuiTerm<App>>>(config, listen_addr)
            .await
    }
}
