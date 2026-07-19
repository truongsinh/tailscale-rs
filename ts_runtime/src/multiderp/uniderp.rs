use std::{
    sync::{Arc, RwLock},
    time::{Duration, Instant},
};

use futures::FutureExt;
use kameo::{
    actor::{ActorRef, Spawn, WeakActorRef},
    error::ActorStopReason,
    message::{Context, Message},
};
use smol_str::SmolStr;
use tokio::sync::{Mutex, watch};
use ts_control::DerpRegion;
use ts_dataplane::async_tokio::{FromUnderlay, Rx, ToUnderlay, Tx};
use ts_derp::RegionId;
use ts_keys::{NodeKeyPair, NodePublicKey};
use ts_packet::PacketMut;
use ts_transport::{
    BatchRecvIter, PeerId, UnderlayTransport, UnderlayTransportExt, UnderlayTransportId,
};

use crate::{
    Task,
    dataplane::{DataplaneActor, NewUnderlayTransport},
    derp_latency::DerpLatencyMeasurement,
    env::Env,
    multiderp::{Multiderp, SetRegionTransportId},
    peer_tracker::{PeerDb, PeerState},
    task::ErasedTask,
};

#[derive(Clone)]
pub struct Args {
    pub region_id: RegionId,
    pub region: DerpRegion,
    pub env: Env,
}

/// Published on the bus (non-retained) when the home derp connection is detected in an
/// rx-stall: we keep transmitting to the relay but nothing has come back for longer than
/// the configured threshold. The connection has already recycled itself locally (fresh
/// socket + Noise handshake) by the time this event is published; the
/// [`crate::offtailnet_watchdog::OffTailnetWatchdog`] consumes it to drive the
/// escalation ladder (re-netcheck → forced re-home → control reconnect).
#[derive(Clone, Debug)]
pub struct RxStallEvent {
    /// The region whose home connection stalled.
    pub region_id: RegionId,
    /// How long rx had been stalled when detection fired.
    pub stalled_for: Duration,
    /// Packets sent to the relay since the last packet received from it.
    pub pkts_sent_since_recv: u64,
}

/// Configuration for rx-stall detection. Read from the environment once per
/// [`Uniderp`] spawn; unknown/garbage values fall back to the defaults
/// (unknown-on-error — detection must never take the connection down via a config
/// parse issue).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct RxStallConfig {
    /// How long rx must be silent (while tx advances) before the home connection is
    /// declared stalled.
    pub stall_threshold: Duration,
    /// Minimum packets sent since the last recv before a stall may be declared.
    /// Guards against declaring a stall on a connection that is not actually
    /// expecting return traffic.
    pub min_tx_pkts: u64,
}

impl RxStallConfig {
    /// Default stall threshold.
    ///
    /// Deliberately conservative: field data (2026-07-18, ord/dfw/den relay handovers)
    /// shows *normal* handovers produce 1–2 minute rx dips. 180s clears the worst
    /// observed normal dip with margin, while still compressing the previously observed
    /// ~140min natural recovery to ~3 minutes.
    pub const DEFAULT_STALL_THRESHOLD: Duration = Duration::from_secs(180);
    /// Floor for the env-tunable threshold. Anything lower would false-fire on normal
    /// relay handovers or ordinary latency spikes.
    pub const MIN_STALL_THRESHOLD: Duration = Duration::from_secs(30);
    /// Default minimum tx packets since last recv.
    pub const DEFAULT_MIN_TX_PKTS: u64 = 3;

    /// Env var overriding the stall threshold, in seconds.
    pub const STALL_SECS_ENV: &str = "TS_OFFNET_RX_STALL_SECS";
    /// Env var overriding the minimum tx packet count.
    pub const MIN_TX_PKTS_ENV: &str = "TS_OFFNET_RX_STALL_MIN_TX_PKTS";

    pub fn from_env() -> Self {
        Self::from_parts(
            std::env::var(Self::STALL_SECS_ENV).ok().as_deref(),
            std::env::var(Self::MIN_TX_PKTS_ENV).ok().as_deref(),
        )
    }

    /// Pure constructor from raw env strings so parsing is unit-testable.
    /// Unparseable or out-of-range values fall back to defaults/floors.
    fn from_parts(stall_secs: Option<&str>, min_tx_pkts: Option<&str>) -> Self {
        let stall_threshold = stall_secs
            .and_then(|v| v.trim().parse::<u64>().ok())
            .map(Duration::from_secs)
            .map(|d| d.max(Self::MIN_STALL_THRESHOLD))
            .unwrap_or(Self::DEFAULT_STALL_THRESHOLD);

        let min_tx_pkts = min_tx_pkts
            .and_then(|v| v.trim().parse::<u64>().ok())
            .map(|n| n.max(1))
            .unwrap_or(Self::DEFAULT_MIN_TX_PKTS);

        Self {
            stall_threshold,
            min_tx_pkts,
        }
    }
}

/// Pure per-connection rx-stall tracker.
///
/// Tracks the receive side of a single derp connection *separately* from the mixed
/// `last_activity` used for the inactivity timeout (which advances on tx too, and so
/// can never notice a one-way connection).
///
/// The smoking-gun predicate is: **home relay AND rx silent past the threshold AND tx
/// advancing** — a connection that transmits into a relay and receives nothing back is
/// one-way-dead (return path blocked), the exact redsun/dfw failure class.
///
/// Handover-awareness (false-fire protection): the stall baseline is the *latest* of
/// (a) connection establishment, (b) last packet received, and (c) the moment this
/// connection became home. A normal relay handover creates a fresh connection and/or
/// flips the home flag, either of which resets the clock — so the 1–2 minute rx dips
/// observed during normal ord/dfw/den handovers never accumulate into a stall.
#[derive(Copy, Clone, Debug)]
pub struct RxStallTracker {
    /// Baseline instant for stall measurement: latest of connect / last recv /
    /// became-home.
    baseline: Instant,
    /// Packets sent to the relay since the last packet received from it.
    pkts_sent_since_recv: u64,
    /// Whether this connection currently serves the home region.
    is_home: bool,
}

impl RxStallTracker {
    /// Create a tracker for a connection established at `now`.
    pub fn new(now: Instant, is_home: bool) -> Self {
        Self {
            baseline: now,
            pkts_sent_since_recv: 0,
            is_home,
        }
    }

    /// Record receive activity: anything back from the relay proves the return path.
    pub fn on_recv(&mut self, now: Instant) {
        self.baseline = now;
        self.pkts_sent_since_recv = 0;
    }

    /// Record `pkts` packets sent to the relay.
    pub fn on_send(&mut self, pkts: u64) {
        self.pkts_sent_since_recv = self.pkts_sent_since_recv.saturating_add(pkts);
    }

    /// Record a home-flag change. Becoming home resets the stall clock — the
    /// connection may have been idle (legitimately rx-silent) while non-home.
    pub fn on_home_change(&mut self, is_home: bool, now: Instant) {
        if is_home && !self.is_home {
            self.baseline = now;
            self.pkts_sent_since_recv = 0;
        }
        self.is_home = is_home;
    }

    /// The smoking-gun predicate. Returns how long rx has been stalled if the
    /// connection is home, tx has advanced past the configured minimum, and rx has
    /// been silent past the threshold. `None` otherwise (including on any internal
    /// arithmetic edge — detection is best-effort and must never panic).
    pub fn stalled_for(&self, now: Instant, cfg: &RxStallConfig) -> Option<Duration> {
        if !self.is_home {
            return None;
        }
        if self.pkts_sent_since_recv < cfg.min_tx_pkts {
            return None;
        }
        let since = now.saturating_duration_since(self.baseline);
        (since >= cfg.stall_threshold).then_some(since)
    }

    /// Earliest instant at which [`Self::stalled_for`] could return `Some`, for use as
    /// a select-loop wake-up deadline. `None` when the predicate cannot currently trip
    /// (not home, or tx below minimum), or on arithmetic overflow.
    pub fn check_deadline(&self, cfg: &RxStallConfig) -> Option<Instant> {
        if !self.is_home || self.pkts_sent_since_recv < cfg.min_tx_pkts {
            return None;
        }
        self.baseline.checked_add(cfg.stall_threshold)
    }

    /// Packets sent since the last receive (for logging/telemetry).
    pub fn pkts_sent_since_recv(&self) -> u64 {
        self.pkts_sent_since_recv
    }
}

/// Single-region derp client.
pub struct Uniderp {
    /// Current state to spawn a runner task.
    ///
    /// Retained here because we may need to kill and restart the runner if we get updated region
    /// info.
    runner_state: Runner,

    /// The transport id this region is responsible for.
    transport_id: UnderlayTransportId,

    /// The task runner handling the transport for this region.
    task: ActorRef<ErasedTask>,

    home_derp_tx: watch::Sender<bool>,

    env: Env,
}

impl Uniderp {
    pub fn name(region_id: RegionId) -> SmolStr {
        smol_str::format_smolstr!("derp_region:{region_id}")
    }
}

#[kameo::messages]
impl Uniderp {
    #[message]
    pub fn transport_id(&self) -> Option<UnderlayTransportId> {
        Some(self.transport_id)
    }
}

async fn start_runner(mut runner: Runner) {
    if let Err(e) = runner.run().await {
        tracing::error!(error = %e, region_id = %runner.region_id, "running derp client");
    }
}

impl kameo::Actor for Uniderp {
    type Args = Args;
    type Error = crate::Error;

    async fn on_start(args: Self::Args, slf: ActorRef<Self>) -> Result<Self, Self::Error> {
        let (home_derp_tx, home_derp_rx) = watch::channel(false);

        let (transport_id, from_dataplane, to_dataplane) = args
            .env
            .ask::<DataplaneActor, _>(Option::<SmolStr>::None, NewUnderlayTransport, true)
            .await?;

        args.env
            .ask::<Multiderp, _>(
                None,
                SetRegionTransportId(args.region_id, Some(transport_id)),
                true,
            )
            .await?;

        let runner = Runner {
            region_id: args.region_id,
            region: args.region,
            peer_db: Arc::new(RwLock::new(None)),
            home_derp_rx,
            to_dataplane,
            keys: args.env.keys.node_keys.clone(),
            from_dataplane: Arc::new(Mutex::new(from_dataplane)),
            rx_stall_config: RxStallConfig::from_env(),
            env: args.env.clone(),
        };

        let task = Task::spawn_link(&slf, start_runner(runner.clone()).boxed()).await;

        args.env
            .subscribe::<Arc<ts_control::StateUpdate>>(&slf)
            .await?;
        args.env.subscribe::<Arc<PeerState>>(&slf).await?;
        args.env.subscribe::<DerpLatencyMeasurement>(&slf).await?;

        args.env
            .register(Some(Self::name(args.region_id)), &slf)
            .await?;

        Ok(Self {
            runner_state: runner,
            transport_id,
            home_derp_tx,
            task,
            env: args.env,
        })
    }

    async fn on_stop(
        &mut self,
        _: WeakActorRef<Self>,
        _: ActorStopReason,
    ) -> Result<(), Self::Error> {
        self.env
            .tell::<Multiderp, _>(
                None,
                SetRegionTransportId(self.runner_state.region_id, None),
            )
            .await?;

        Ok(())
    }
}

impl Message<Arc<ts_control::StateUpdate>> for Uniderp {
    type Reply = ();

    async fn handle(
        &mut self,
        msg: Arc<ts_control::StateUpdate>,
        ctx: &mut Context<Self, Self::Reply>,
    ) {
        let Some(derp) = &msg.derp else {
            return;
        };

        let Some(region) = derp.get(&self.runner_state.region_id) else {
            tracing::debug!(
                region_id = ?self.runner_state.region_id,
                "derp region disappeared from map, stopping"
            );
            ctx.stop();
            return;
        };

        if &self.runner_state.region == region {
            return;
        }

        tracing::debug!(id = %self.runner_state.region_id, "region changed, restarting task");
        self.runner_state.region = region.clone();

        self.task.unlink(ctx.actor_ref()).await;
        self.task.stop_gracefully().await.unwrap();
        self.task
            .wait_for_shutdown_with_result(|e| {
                if let Err(e) = e {
                    tracing::error!(error = ?e, "shutting down derp task on region update");
                }
            })
            .await;

        self.task = Task::spawn_link(
            ctx.actor_ref(),
            start_runner(self.runner_state.clone()).boxed(),
        )
        .await;
    }
}

impl Message<Arc<PeerState>> for Uniderp {
    type Reply = ();

    async fn handle(&mut self, msg: Arc<PeerState>, _ctx: &mut Context<Self, Self::Reply>) {
        let mut db = self.runner_state.peer_db.write().unwrap();
        *db = Some(msg.peers.clone());
    }
}

impl Message<DerpLatencyMeasurement> for Uniderp {
    type Reply = ();

    async fn handle(&mut self, msg: DerpLatencyMeasurement, _ctx: &mut Context<Self, Self::Reply>) {
        let Some(result) = msg.measurement.as_ref().first() else {
            tracing::trace!("received home derp measurement message but none was set");
            return;
        };

        self.home_derp_tx.send_if_modified(|x| {
            let new_val = result.id == self.runner_state.region_id;
            let changed = new_val != *x;
            *x = new_val;

            changed
        });
    }
}

#[derive(Clone)]
struct Runner {
    region_id: RegionId,
    region: DerpRegion,
    home_derp_rx: watch::Receiver<bool>,
    to_dataplane: Tx<FromUnderlay>,
    from_dataplane: Arc<Mutex<Rx<ToUnderlay>>>,
    peer_db: Arc<RwLock<Option<Arc<PeerDb>>>>,
    keys: NodeKeyPair,
    /// rx-stall detection thresholds (env-tunable, defaults conservative).
    rx_stall_config: RxStallConfig,
    /// Retained so the runner can publish [`RxStallEvent`]s on the bus.
    env: Env,
}

impl Runner {
    const INACTIVITY_TIMEOUT: Duration = Duration::from_secs(10);

    /// Age floor after which a live derp connection is proactively recycled (closed and
    /// re-established). Only the home connection lives long enough to hit this — non-home
    /// connections close on [`INACTIVITY_TIMEOUT`] well before. Bounding the connection lifetime
    /// sheds a home-derp socket that has silently wedged (TCP still up, no useful traffic) instead
    /// of leaving the node pinned to it indefinitely.
    const MAX_CONNECTION_AGE: Duration = Duration::from_secs(300);

    /// Initial delay before retrying a failed derp connection.
    const RECONNECT_BASE_BACKOFF: Duration = Duration::from_millis(500);
    /// Cap on the exponential reconnect backoff.
    const RECONNECT_MAX_BACKOFF: Duration = Duration::from_secs(30);

    #[tracing::instrument(skip_all, fields(region_id = %self.region_id))]
    async fn run(&mut self) -> Result<(), ts_derp::Error> {
        let mut backoff = Self::RECONNECT_BASE_BACKOFF;

        loop {
            let pending = self.wait_for_activity().await;

            // Reconnect with exponential backoff instead of letting a transient connect failure
            // tear down the whole region task (which previously died until a derp map update
            // respawned it). This keeps a region self-healing across brief derp outages.
            let transport = match self.connect(pending).await {
                Ok(transport) => {
                    backoff = Self::RECONNECT_BASE_BACKOFF;
                    transport
                }
                Err(e) => {
                    tracing::warn!(
                        region_id = %self.region_id,
                        backoff = ?backoff,
                        error = %e,
                        "derp connect failed; backing off"
                    );
                    tokio::time::sleep(backoff).await;
                    backoff = next_backoff(backoff, Self::RECONNECT_MAX_BACKOFF);
                    continue;
                }
            };

            self.run_transport(transport).await?;
        }
    }

    #[tracing::instrument(skip_all, level = "trace")]
    async fn wait_for_activity(&mut self) -> Option<(PeerId, Vec<PacketMut>)> {
        tracing::trace!("waiting for packet activity or for this to become home derp");

        let mut from_dataplane = self.from_dataplane.lock().await;

        while !*self.home_derp_rx.borrow_and_update() {
            tokio::select! {
                _ = self.home_derp_rx.changed() => {
                    tracing::trace!(is_home_derp = *self.home_derp_rx.borrow());
                },

                from_net = from_dataplane.recv() => {
                    tracing::trace!("received packet to send");
                    return from_net;
                }
            }
        }

        None
    }

    #[tracing::instrument(skip_all, level = "trace")]
    async fn connect(
        &self,
        pending: Option<(PeerId, Vec<PacketMut>)>,
    ) -> Result<
        impl UnderlayTransport<PeerKey = PeerId, Error = ts_derp::Error> + 'static,
        ts_derp::Error,
    > {
        tracing::trace!("establishing derp connection");

        let client = ts_derp::DefaultClient::connect(&self.region.servers, &self.keys).await?;
        let transport = client.with_key_lookup(PeerDbLookup(self.peer_db.clone()));

        if let Some(pending) = pending {
            tracing::trace!("sending queued packet");
            transport.send([pending]).await?;
        }

        Ok(transport)
    }

    #[tracing::instrument(skip_all, level = "trace")]
    async fn run_transport(
        &mut self,
        transport: impl UnderlayTransport<PeerKey = PeerId, Error = ts_derp::Error>,
    ) -> Result<(), ts_derp::Error> {
        let connected_at = Instant::now();
        let mut last_activity = Instant::now();
        // rx-stall tracking is deliberately SEPARATE from `last_activity`: the mixed
        // activity clock advances on tx as well, so a one-way connection (tx flowing,
        // rx dead — the redsun/dfw failure class) never trips the inactivity timeout.
        let mut rx_stall = RxStallTracker::new(connected_at, *self.home_derp_rx.borrow());
        let mut from_dataplane = self.from_dataplane.lock().await;

        loop {
            let span = tracing::trace_span!("derp_loop");

            let inactivity_timeout =
                (!*self.home_derp_rx.borrow()).then(|| last_activity + Self::INACTIVITY_TIMEOUT);

            // Recycle the connection once it is past the age floor. Returning `Ok` here drops the
            // transport and sends `run` back around to reconnect, replacing a potentially wedged
            // long-lived (home) socket with a fresh one.
            let recycle_deadline = connected_at + Self::MAX_CONNECTION_AGE;

            // Earliest instant an rx-stall could be declared; `None` while the predicate
            // cannot trip (not home / tx not advancing).
            let rx_stall_deadline = rx_stall.check_deadline(&self.rx_stall_config);

            tokio::select! {
                from_derp = transport.recv() => {
                    last_activity = Instant::now();
                    rx_stall.on_recv(last_activity);

                    for ret in from_derp.batch_iter() {
                        let (peer_id, pkts) = ret?;
                        let pkts = pkts.into_iter().collect::<Vec<_>>();

                        tracing::trace!(parent: &span, %peer_id, len = pkts.len(), "packet from derp server");

                        let Ok(()) = self.to_dataplane.send(pkts) else {
                            tracing::error!(parent: &span, "underlay receive channel closed");
                            break;
                        };
                    }
                },

                from_net = from_dataplane.recv() => {
                    last_activity = Instant::now();

                    let Some(from_net) = from_net else {
                        tracing::warn!(parent: &span, "transport queue closed");
                        return Ok(());
                    };

                    tracing::trace!(parent: &span, peer = %from_net.0, packets = from_net.1.len(), "packets to derp server");

                    rx_stall.on_send(from_net.1.len() as u64);
                    transport.send([from_net]).await?;
                },

                _ = option_timeout(inactivity_timeout) => {
                    if !*self.home_derp_rx.borrow_and_update() {
                        tracing::trace!(parent: &span, "timed out and not home derp, closing derp conn");
                        return Ok(());
                    }
                },

                _ = tokio::time::sleep_until(recycle_deadline.into()) => {
                    tracing::debug!(
                        parent: &span,
                        region_id = %self.region_id,
                        "recycling derp connection past age floor"
                    );
                    return Ok(());
                },

                _ = option_timeout(rx_stall_deadline) => {
                    // Re-verify against the live tracker state before acting: the branch
                    // only means the deadline elapsed, not that the predicate still holds.
                    if let Some(stalled_for) = rx_stall.stalled_for(Instant::now(), &self.rx_stall_config) {
                        tracing::warn!(
                            parent: &span,
                            region_id = %self.region_id,
                            stalled_secs = stalled_for.as_secs(),
                            pkts_sent_since_recv = rx_stall.pkts_sent_since_recv(),
                            "home derp rx-stall detected (tx advancing, rx silent); recycling connection"
                        );

                        // Best-effort signal to the off-tailnet watchdog for escalation
                        // accounting. A bus error must never block the local recovery.
                        if let Err(e) = self.env.publish_noretain(RxStallEvent {
                            region_id: self.region_id,
                            stalled_for,
                            pkts_sent_since_recv: rx_stall.pkts_sent_since_recv(),
                        }).await {
                            tracing::error!(parent: &span, error = %e, "publishing rx-stall event");
                        }

                        // Local recovery: drop the one-way transport and let `run` reconnect
                        // — fresh TCP socket, fresh Noise handshake, fresh NAT/firewall state.
                        return Ok(());
                    }
                },

                _ = self.home_derp_rx.changed() => {
                    let is_home = *self.home_derp_rx.borrow();
                    rx_stall.on_home_change(is_home, Instant::now());
                    tracing::trace!(is_home_derp = is_home);
                },
            }
        }
    }
}

/// Compute the next exponential backoff delay, doubling `current` and capping at `max`.
///
/// Pure helper (no clock) so the backoff schedule can be unit-tested.
fn next_backoff(current: Duration, max: Duration) -> Duration {
    current.saturating_mul(2).min(max)
}

struct PeerDbLookup(Arc<RwLock<Option<Arc<PeerDb>>>>);

impl ts_transport::PeerLookup<PeerId, NodePublicKey> for PeerDbLookup {
    fn lookup_key(&self, id: PeerId) -> Option<NodePublicKey> {
        let db = self.0.read().unwrap();
        let db = db.as_ref()?;

        let (_, node) = db.get(&id)?;
        Some(node.node_key)
    }
}

impl ts_transport::PeerLookup<NodePublicKey, PeerId> for PeerDbLookup {
    fn lookup_key(&self, key: NodePublicKey) -> Option<PeerId> {
        let db = self.0.read().unwrap();
        let db = db.as_ref()?;

        let (id, _) = db.get(&key)?;

        Some(id)
    }
}

async fn option_timeout(duration: Option<Instant>) {
    match duration {
        Some(dur) => tokio::time::sleep_until(dur.into()).await,
        None => core::future::pending().await,
    }
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant};

    use super::{Runner, RxStallConfig, RxStallTracker, next_backoff};

    fn cfg() -> RxStallConfig {
        RxStallConfig {
            stall_threshold: Duration::from_secs(180),
            min_tx_pkts: 3,
        }
    }

    fn secs(n: u64) -> Duration {
        Duration::from_secs(n)
    }

    // ---- rx-stall detection predicate (pure) ----

    #[test]
    fn rx_stall_fires_on_home_conn_with_tx_advancing_and_rx_silent() {
        // The smoking gun: home relay, tx advancing, nothing back past the threshold.
        let t0 = Instant::now();
        let mut tr = RxStallTracker::new(t0, true);
        tr.on_send(5);
        assert_eq!(tr.stalled_for(t0 + secs(180), &cfg()), Some(secs(180)));
        assert_eq!(tr.stalled_for(t0 + secs(400), &cfg()), Some(secs(400)));
    }

    #[test]
    fn rx_stall_does_not_fire_when_not_home() {
        let t0 = Instant::now();
        let mut tr = RxStallTracker::new(t0, false);
        tr.on_send(50);
        assert_eq!(tr.stalled_for(t0 + secs(600), &cfg()), None);
    }

    #[test]
    fn rx_stall_does_not_fire_without_tx() {
        // rx silent but we are not sending anything either — nothing to expect back.
        let t0 = Instant::now();
        let tr = RxStallTracker::new(t0, true);
        assert_eq!(tr.stalled_for(t0 + secs(600), &cfg()), None);
    }

    #[test]
    fn rx_stall_does_not_fire_below_min_tx_pkts() {
        let t0 = Instant::now();
        let mut tr = RxStallTracker::new(t0, true);
        tr.on_send(2); // min is 3
        assert_eq!(tr.stalled_for(t0 + secs(600), &cfg()), None);
        tr.on_send(1); // now at 3
        assert_eq!(tr.stalled_for(t0 + secs(600), &cfg()), Some(secs(600)));
    }

    #[test]
    fn rx_stall_threshold_boundary_is_geq() {
        let t0 = Instant::now();
        let mut tr = RxStallTracker::new(t0, true);
        tr.on_send(10);
        assert_eq!(tr.stalled_for(t0 + secs(179), &cfg()), None);
        assert_eq!(tr.stalled_for(t0 + secs(180), &cfg()), Some(secs(180)));
    }

    #[test]
    fn recv_resets_stall_clock_and_tx_counter() {
        let t0 = Instant::now();
        let mut tr = RxStallTracker::new(t0, true);
        tr.on_send(10);
        // A packet back at t+170 proves the return path; clock restarts.
        tr.on_recv(t0 + secs(170));
        assert_eq!(tr.stalled_for(t0 + secs(300), &cfg()), None); // tx counter reset too
        tr.on_send(10);
        assert_eq!(tr.stalled_for(t0 + secs(349), &cfg()), None); // 179s since recv
        assert_eq!(tr.stalled_for(t0 + secs(350), &cfg()), Some(secs(180)));
    }

    #[test]
    fn check_deadline_none_until_predicate_can_trip() {
        let t0 = Instant::now();
        let mut tr = RxStallTracker::new(t0, false);
        assert_eq!(tr.check_deadline(&cfg()), None); // not home
        tr.on_home_change(true, t0);
        assert_eq!(tr.check_deadline(&cfg()), None); // no tx yet
        tr.on_send(3);
        assert_eq!(tr.check_deadline(&cfg()), Some(t0 + secs(180)));
    }

    // ---- false-fire protection: normal relay handovers (1–2 min rx dips) ----

    #[test]
    fn no_false_fire_on_two_minute_rx_dip_with_default_threshold() {
        // Field data: normal ord/dfw/den relay handovers show 1–2 minute rx dips.
        // The default threshold must ride those out on a stable home connection.
        let defaults = RxStallConfig::from_parts(None, None);
        let t0 = Instant::now();
        let mut tr = RxStallTracker::new(t0, true);
        tr.on_send(100);
        assert_eq!(tr.stalled_for(t0 + secs(60), &defaults), None); // 1 min dip
        assert_eq!(tr.stalled_for(t0 + secs(120), &defaults), None); // 2 min dip
        // Dip ends within normal handover bounds — recv resets, never fired.
        tr.on_recv(t0 + secs(125));
        assert_eq!(tr.stalled_for(t0 + secs(150), &defaults), None);
    }

    #[test]
    fn no_false_fire_on_simulated_relay_handover_new_connection() {
        // A handover tears down the old connection and establishes a fresh one.
        // Even though the *node-level* rx gap spans > threshold across the handover,
        // each connection's stall clock starts at its own establishment, so no fire.
        let defaults = RxStallConfig::from_parts(None, None);
        let t0 = Instant::now();

        // Old home connection: rx dips for 100s before the handover closes it.
        let mut old_conn = RxStallTracker::new(t0, true);
        old_conn.on_send(50);
        assert_eq!(old_conn.stalled_for(t0 + secs(100), &defaults), None);

        // Handover at t+100: fresh connection to the new relay (fresh tracker,
        // exactly what run_transport constructs on connect).
        let t1 = t0 + secs(100);
        let mut new_conn = RxStallTracker::new(t1, true);
        new_conn.on_send(50);
        // Node-level rx silence is now 150s > 120s handover dip, but the new
        // connection is only 50s old — no fire.
        assert_eq!(new_conn.stalled_for(t1 + secs(50), &defaults), None);
        // New relay starts delivering — handover completed, still no fire.
        new_conn.on_recv(t1 + secs(70));
        assert_eq!(new_conn.stalled_for(t1 + secs(120), &defaults), None);
    }

    #[test]
    fn no_false_fire_when_home_moves_away_mid_dip() {
        // Handover variant where this region stops being home mid-dip: the tracker
        // must stand down immediately even if the old connection lingers.
        let defaults = RxStallConfig::from_parts(None, None);
        let t0 = Instant::now();
        let mut tr = RxStallTracker::new(t0, true);
        tr.on_send(50);
        tr.on_home_change(false, t0 + secs(90)); // home re-selected elsewhere
        assert_eq!(tr.stalled_for(t0 + secs(600), &defaults), None);
    }

    #[test]
    fn becoming_home_resets_stall_clock() {
        // A connection idle (legitimately rx-silent) while non-home must not be
        // declared stalled the moment it becomes home.
        let defaults = RxStallConfig::from_parts(None, None);
        let t0 = Instant::now();
        let mut tr = RxStallTracker::new(t0, false);
        tr.on_send(10);
        tr.on_home_change(true, t0 + secs(300));
        assert_eq!(tr.stalled_for(t0 + secs(310), &defaults), None);
        // ...but a genuine stall after becoming home still fires.
        tr.on_send(10);
        assert_eq!(
            tr.stalled_for(t0 + secs(300) + defaults.stall_threshold, &defaults),
            Some(defaults.stall_threshold)
        );
    }

    #[test]
    fn default_threshold_clears_normal_handover_dips_with_margin() {
        // Normal handovers dip 1–2 min; the default must exceed that with margin.
        assert!(RxStallConfig::DEFAULT_STALL_THRESHOLD >= Duration::from_secs(180));
        // And the tunable floor still exceeds any plausible in-flight RTT burst.
        assert!(RxStallConfig::MIN_STALL_THRESHOLD >= Duration::from_secs(30));
    }

    // ---- config parsing: unknown-on-error ----

    #[test]
    fn rx_stall_config_defaults() {
        let c = RxStallConfig::from_parts(None, None);
        assert_eq!(c.stall_threshold, RxStallConfig::DEFAULT_STALL_THRESHOLD);
        assert_eq!(c.min_tx_pkts, RxStallConfig::DEFAULT_MIN_TX_PKTS);
    }

    #[test]
    fn rx_stall_config_garbage_falls_back_to_defaults() {
        for garbage in ["", "abc", "-5", "1.5", "NaN", "9999999999999999999999"] {
            let c = RxStallConfig::from_parts(Some(garbage), Some(garbage));
            assert_eq!(
                c.stall_threshold,
                RxStallConfig::DEFAULT_STALL_THRESHOLD,
                "{garbage}"
            );
            assert_eq!(
                c.min_tx_pkts,
                RxStallConfig::DEFAULT_MIN_TX_PKTS,
                "{garbage}"
            );
        }
    }

    #[test]
    fn rx_stall_config_valid_overrides_apply() {
        let c = RxStallConfig::from_parts(Some("240"), Some("10"));
        assert_eq!(c.stall_threshold, secs(240));
        assert_eq!(c.min_tx_pkts, 10);
    }

    #[test]
    fn rx_stall_config_clamps_dangerously_low_values() {
        // A 0/low threshold would fire constantly; clamp to the floor instead.
        let c = RxStallConfig::from_parts(Some("0"), Some("0"));
        assert_eq!(c.stall_threshold, RxStallConfig::MIN_STALL_THRESHOLD);
        assert_eq!(c.min_tx_pkts, 1);
    }

    // ---- behavior harness: the redsun/dfw one-way stall timeline ----

    #[test]
    fn redsun_dfw_one_way_stall_timeline_detects_and_redetects() {
        // Field trace (redsun-win7-primary 2026-07-18): stuck on relay "dfw",
        // tx climbing continuously, rx pinned at 0, for hours. Simulate the
        // timeline: tx every 10s, no rx ever.
        let defaults = RxStallConfig::from_parts(None, None);
        let t0 = Instant::now();
        let mut tr = RxStallTracker::new(t0, true);

        let mut fired_at = None;
        for step in 1..=60u64 {
            let now = t0 + secs(step * 10);
            tr.on_send(4); // ~SSH keepalives + disco pings
            if tr.stalled_for(now, &defaults).is_some() {
                fired_at = Some(step * 10);
                break;
            }
        }
        // Fires at the first check at/after the 180s threshold — not before.
        assert_eq!(fired_at, Some(180));

        // Local recovery recycles the connection; the relay is still one-way-dead,
        // so the fresh connection re-detects after another full threshold —
        // giving the watchdog its repeated-stall escalation signal.
        let t1 = t0 + secs(180);
        let mut tr2 = RxStallTracker::new(t1, true);
        tr2.on_send(10);
        assert_eq!(tr2.stalled_for(t1 + secs(179), &defaults), None);
        assert_eq!(tr2.stalled_for(t1 + secs(180), &defaults), Some(secs(180)));
    }

    #[test]
    fn backoff_doubles_then_caps() {
        let max = Duration::from_secs(30);
        assert_eq!(
            next_backoff(Duration::from_millis(500), max),
            Duration::from_secs(1)
        );
        assert_eq!(
            next_backoff(Duration::from_secs(1), max),
            Duration::from_secs(2)
        );
        assert_eq!(next_backoff(Duration::from_secs(16), max), max);
        // Never exceeds the cap, and is idempotent once capped.
        assert_eq!(next_backoff(max, max), max);
        assert_eq!(next_backoff(Duration::from_secs(1000), max), max);
    }

    #[test]
    fn recycle_age_floor_exceeds_inactivity_timeout() {
        // The age-floor recycle must be well above the non-home inactivity timeout, so only the
        // long-lived home connection is ever recycled — non-home connections always close on
        // inactivity first and never reach the age floor.
        assert!(Runner::MAX_CONNECTION_AGE > Runner::INACTIVITY_TIMEOUT);
    }

    #[test]
    fn reconnect_backoff_bounds_are_sane() {
        assert!(Runner::RECONNECT_BASE_BACKOFF < Runner::RECONNECT_MAX_BACKOFF);
    }
}
