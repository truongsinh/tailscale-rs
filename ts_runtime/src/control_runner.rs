use core::{
    net::{Ipv4Addr, Ipv6Addr},
    time::Duration,
};
use std::sync::Arc;

use futures::StreamExt;
use kameo::{
    actor::{ActorRef, Spawn},
    message::{Context, StreamMessage},
    prelude::{Message, ReplySender},
    reply::DelegatedReply,
};
use tokio::task::JoinHandle;
use ts_control::{AsyncControlClient, Error as ControlError, Node, StateUpdate};

use crate::{
    derp_latency::{DerpLatencyMeasurement, DerpLatencyMeasurer},
    offtailnet_watchdog::OffTailnetWatchdog,
};

/// Stream-task return type for [`kameo::actor::ActorRef::attach_stream`].
///
/// The inner `Result<S, _>` matches the signature of `attach_stream`; we don't need the
/// inner value, only the JoinHandle itself so we can abort a stuck stream during a
/// forced reconnect.
type StreamHandle = JoinHandle<
    Result<
        std::pin::Pin<Box<dyn futures::Stream<Item = Arc<StateUpdate>> + Send>>,
        kameo::error::SendError<
            kameo::message::StreamMessage<Arc<StateUpdate>, (), ()>,
        >,
    >,
>;

/// Actor responsible for maintaining the connection to control.
///
/// This actor is responsible for proxying the map response stream onto the message bus.
pub struct ControlRunner {
    client: AsyncControlClient,
    params: Params,

    self_node: Option<Node>,
    pending: Vec<PendingRequest>,

    /// Handle to the tokio task driving the attached control stream. Retained so a
    /// [`ForceReconnect`] can abort a stuck stream (the most common silent-drop failure)
    /// before re-establishing a fresh one.
    stream_handle: Option<StreamHandle>,

    /// Earliest time a reconnect may be attempted. Bounded by `RECONNECT_BACKOFF` to
    /// prevent hot-looping if the control plane is genuinely unreachable.
    earliest_reconnect_at: Option<tokio::time::Instant>,
}

/// Message sent by [`OffTailnetWatchdog`] (or any other observer) when the control
/// stream appears stuck — no `StateUpdate` observed for the detection window.
///
/// On receipt, the runner aborts its current stream task (if any) and attempts a fresh
/// `AsyncControlClient::connect` + `attach_stream`. The fresh stream produces a new
/// `StateUpdate` (which resets the watchdog) or fails (in which case the watchdog will
/// retry after its cooldown).
#[derive(Copy, Clone, Debug)]
pub struct ForceReconnect;

/// Backoff floor between consecutive reconnect attempts. The watchdog's own cooldown
/// (`T_COOLDOWN` = 60s in [`crate::offtailnet_watchdog`]) bounds the rate of
/// `ForceReconnect`s, but a stream that repeatedly terminates (e.g. control server
/// rejecting the connection) could otherwise hot-loop via the `StreamMessage::Finished`
/// path. This floor prevents that.
const RECONNECT_BACKOFF: Duration = Duration::from_secs(5);

/// Control runner args.
#[derive(Clone)]
pub struct Params {
    /// Control config.
    pub(crate) config: ts_control::Config,

    /// Auth key (if needed).
    pub(crate) auth_key: Option<String>,

    /// The [`crate::Env`] for this actor.
    pub(crate) env: crate::Env,
}

#[doc(hidden)]
#[derive(Debug, Clone, thiserror::Error)]
pub enum ControlRunnerError {
    #[error(transparent)]
    Control(#[from] ControlError),

    #[error(transparent)]
    Crate(#[from] crate::Error),
}

impl kameo::Actor for ControlRunner {
    type Args = Params;
    type Error = ControlRunnerError;

    async fn on_start(params: Params, slf: ActorRef<Self>) -> Result<Self, Self::Error> {
        loop {
            match AsyncControlClient::check_auth(
                &params.config,
                &params.env.keys,
                params.auth_key.as_deref(),
            )
            .await
            {
                Ok(()) => break,
                Err(ControlError::MachineNotAuthorized(u)) => {
                    tracing::info!(auth_url = %u, "please authorize this machine or pass an auth key");
                    tokio::time::sleep(Duration::from_secs(5)).await;
                }
                Err(e) => return Err(e.into()),
            }
        }

        let (client, stream) = AsyncControlClient::connect(
            &params.config,
            &params.env.keys,
            params.auth_key.as_deref(),
        )
        .await?;

        params.env.subscribe::<DerpLatencyMeasurement>(&slf).await?;
        DerpLatencyMeasurer::supervise(&slf, params.env.clone())
            .spawn()
            .await;

        // Spawn the off-tailnet watchdog. It subscribes to StateUpdate on the bus and
        // sends ForceReconnect back to this actor when the stream appears stuck. Spawning
        // from ControlRunner (rather than Runtime) keeps the watchdog's lifetime tied to
        // the control-plane actor it supervises, matching the DerpLatencyMeasurer pattern.
        OffTailnetWatchdog::supervise(&slf, params.env.clone())
            .spawn()
            .await;

        let stream_handle = slf.attach_stream(stream.boxed(), (), ());
        params.env.register(None, &slf).await?;

        Ok(Self {
            client,
            params,
            self_node: None,
            pending: Default::default(),
            stream_handle: Some(stream_handle),
            earliest_reconnect_at: None,
        })
    }
}

impl ControlRunner {
    /// Attempt to re-establish the control stream: abort the current stream task, run a
    /// fresh `AsyncControlClient::connect`, and re-attach the resulting stream.
    ///
    /// Honours `RECONNECT_BACKOFF` to avoid hot-looping if the control plane is genuinely
    /// unreachable (a stuck stream that immediately re-terminates on each new attach).
    /// Returns `true` if a new stream was attached, `false` if the backoff window has not
    /// elapsed or the connect attempt failed.
    ///
    /// On failure, the caller (either the watchdog via `ForceReconnect` or the
    /// `StreamMessage::Finished` handler) is expected to retry — the watchdog does so on
    /// its `T_COOLDOWN` cadence.
    async fn try_reconnect(&mut self, slf: &ActorRef<Self>) -> bool {
        let now = tokio::time::Instant::now();

        if let Some(not_before) = self.earliest_reconnect_at
            && now < not_before
        {
            tracing::trace!(
                ?not_before,
                "reconnect suppressed by backoff; will retry after backoff window"
            );
            return false;
        }

        // Abort the in-flight stream task (if any). abort() is safe to call on a finished
        // handle and does nothing in that case.
        if let Some(handle) = self.stream_handle.take() {
            handle.abort();
        }

        tracing::info!("attempting to re-establish control stream");
        match AsyncControlClient::connect(
            &self.params.config,
            &self.params.env.keys,
            self.params.auth_key.as_deref(),
        )
        .await
        {
            Ok((_client, stream)) => {
                let handle = slf.attach_stream(stream.boxed(), (), ());
                self.stream_handle = Some(handle);
                self.earliest_reconnect_at =
                    Some(now + RECONNECT_BACKOFF);
                tracing::info!("control stream re-established");
                true
            }
            Err(e) => {
                self.earliest_reconnect_at =
                    Some(now + RECONNECT_BACKOFF);
                tracing::error!(
                    error = %e,
                    backoff_secs = RECONNECT_BACKOFF.as_secs(),
                    "reconnect attempt failed; will retry after backoff"
                );
                false
            }
        }
    }
}

impl Message<ForceReconnect> for ControlRunner {
    type Reply = ();

    async fn handle(
        &mut self,
        _: ForceReconnect,
        ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        self.try_reconnect(ctx.actor_ref()).await;
    }
}

#[kameo::messages]
impl ControlRunner {
    /// Fetch the IPv4 address for this tailscale device.
    #[message(ctx)]
    pub fn ipv4(
        &mut self,
        ctx: &mut Context<Self, DelegatedReply<Option<Ipv4Addr>>>,
    ) -> DelegatedReply<Option<Ipv4Addr>> {
        if let Some(node) = &self.self_node {
            return ctx.reply(Some(node.tailnet_address.ipv4.addr()));
        }

        let (deleg, replier) = ctx.reply_sender();
        if let Some(replier) = replier {
            self.pending.push(PendingRequest::Ipv4(replier));
        }

        deleg
    }

    /// Fetch the IPv6 address for this tailscale device.
    #[message(ctx)]
    pub fn ipv6(
        &mut self,
        ctx: &mut Context<Self, DelegatedReply<Option<Ipv6Addr>>>,
    ) -> DelegatedReply<Option<Ipv6Addr>> {
        if let Some(node) = &self.self_node {
            return ctx.reply(Some(node.tailnet_address.ipv6.addr()));
        }

        let (deleg, replier) = ctx.reply_sender();
        if let Some(replier) = replier {
            self.pending.push(PendingRequest::Ipv6(replier));
        }

        deleg
    }

    /// Fetch the self node for this tailscale device.
    #[message(ctx)]
    pub fn self_node(
        &mut self,
        ctx: &mut Context<Self, DelegatedReply<Option<Node>>>,
    ) -> DelegatedReply<Option<Node>> {
        if let Some(node) = &self.self_node {
            return ctx.reply(Some(node.clone()));
        }

        let (deleg, replier) = ctx.reply_sender();
        if let Some(replier) = replier {
            self.pending.push(PendingRequest::SelfNode(replier));
        }

        deleg
    }
}

enum PendingRequest {
    Ipv4(ReplySender<Option<Ipv4Addr>>),
    Ipv6(ReplySender<Option<Ipv6Addr>>),
    SelfNode(ReplySender<Option<Node>>),
}

impl PendingRequest {
    fn respond(self, node: &Node) {
        match self {
            PendingRequest::Ipv4(sender) => {
                sender.send(Some(node.tailnet_address.ipv4.addr()));
            }
            PendingRequest::Ipv6(sender) => {
                sender.send(Some(node.tailnet_address.ipv6.addr()));
            }
            PendingRequest::SelfNode(sender) => {
                sender.send(Some(node.clone()));
            }
        }
    }
}

impl Message<StreamMessage<Arc<StateUpdate>, (), ()>> for ControlRunner {
    type Reply = ();

    async fn handle(
        &mut self,
        msg: StreamMessage<Arc<StateUpdate>, (), ()>,
        ctx: &mut Context<Self, Self::Reply>,
    ) {
        match msg {
            StreamMessage::Started(_) => {
                tracing::trace!("started listening to state updates");
            }

            StreamMessage::Next(msg) => {
                if let Some(node) = msg.node.as_ref() {
                    self.self_node = Some(node.clone());
                }

                if let Err(e) = self.params.env.publish(msg).await {
                    tracing::error!(error = %e, "publishing netmap update");
                }
            }

            StreamMessage::Finished(_) => {
                tracing::error!("state update stream terminated; attempting reconnect");
                // The attached-stream task has already exited (that is what triggered this
                // Finished), so `stream_handle` is a completed JoinHandle. Clear it, then
                // try to re-establish. try_reconnect honours the backoff so a control plane
                // that is genuinely down does not hot-loop here; the off-tailnet watchdog
                // will keep retrying on its own cooldown regardless.
                self.stream_handle = None;
                self.try_reconnect(ctx.actor_ref()).await;
            }
        }

        if let Some(node) = &self.self_node {
            for req in self.pending.drain(..) {
                req.respond(node);
            }
        }
    }
}

impl Message<DerpLatencyMeasurement> for ControlRunner {
    type Reply = ();

    async fn handle(&mut self, msg: DerpLatencyMeasurement, _ctx: &mut Context<Self, Self::Reply>) {
        let measurements = msg.measurement.as_ref().clone();

        let Some(result) = measurements.first() else {
            tracing::debug!("derp latency measurements empty");
            return;
        };

        let iter = measurements.iter().map(|result| {
            (
                result.latency_map_key.as_str(),
                result.latency.as_secs_f64(),
            )
        });

        tracing::debug!(selected_region_id = ?result.id, "updating home region");

        self.client.set_home_region(result.id, iter).await;
    }
}
