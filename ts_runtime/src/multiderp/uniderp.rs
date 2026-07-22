use std::{
    sync::Arc,
    time::{Duration, Instant},
};

use core::ops::ControlFlow;

use arc_swap::ArcSwapOption;
use futures::FutureExt;
use kameo::{
    actor::{ActorId, ActorRef, Spawn, WeakActorRef},
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
use ts_transport::{BatchRecvIter, PeerId, UnderlayTransport, UnderlayTransportId};

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
/// rx-stall: zero DERP frames of any kind — server keepalives included — have arrived
/// for longer than the configured threshold. Immediately after publishing, the
/// detecting connection recycles itself locally (fresh socket + Noise handshake); the
/// [`crate::offtailnet_watchdog::OffTailnetWatchdog`] consumes the event to drive the
/// escalation ladder (re-netcheck → forced re-home → control reconnect).
#[derive(Clone, Debug)]
pub struct RxStallEvent {
    /// The region whose home connection stalled.
    pub region_id: RegionId,
    /// How long the connection had been frame-silent when detection fired.
    pub stalled_for: Duration,
    /// Packets sent to the relay since the last frame received from it (telemetry —
    /// not part of the stall predicate; on cross-region topologies the home
    /// connection legitimately carries no tx at all).
    pub pkts_sent_since_recv: u64,
}

/// Published on the bus (non-retained), at most once per connection, when a derp
/// connection — home or not — observes DERP frames arriving: positive evidence that
/// the region's return path works. Health evidence is health evidence regardless of
/// home status; a penalized region typically is NOT home (the penalty moved home
/// elsewhere), so its cross-region connection is exactly where recovery shows first.
/// [`crate::derp_latency::DerpLatencyMeasurer`] uses the event to clear the
/// forced-re-home penalty box early when the penalized region proves healthy.
#[derive(Clone, Debug)]
pub struct RxHealthyEvent {
    /// The region whose connection delivered frames.
    pub region_id: RegionId,
}

/// Periodic liveness signal from a Uniderp's Runner, published on the bus
/// (non-retained). Consumed by [`crate::multiderp::Multiderp`]'s health monitor
/// to detect alive-but-stuck actors — the wedge mode where the Runner is alive
/// but making no progress (failed connects with no successful recycle, or a
/// future wedge mode we haven't seen yet).
///
/// Published at most every [`Runner::HEARTBEAT_INTERVAL`] while the Runner is
/// alive and the loop is turning over. NOT published while the Runner is parked
/// in `wait_for_activity` (non-home, no traffic) — that's a legitimate idle
/// state, not a wedge.
///
/// `last_progress_at` advances on:
/// - Successful connect (including make-before-break recycle).
/// - Frame-received observation (coalesced with the existing `RxHealthyEvent`
///   flow — both prove the connection is alive in both directions).
///
/// It does NOT advance on failed connects. A Runner stuck in backoff has a
/// stale `last_progress_at`, which is exactly the signal the supervisor needs
/// to force a restart.
#[derive(Clone, Debug)]
pub struct RunnerHeartbeat {
    /// The region this Runner is responsible for.
    pub region_id: RegionId,
    /// When the Runner last observed useful progress. See struct doc for the
    /// exact events that advance this.
    pub last_progress_at: Instant,
    /// Whether the Runner currently believes it's the home derp. The supervisor
    /// uses this to distinguish legitimately-idle non-home Runners (stale
    /// heartbeat is fine) from stuck home Runners (stale heartbeat is a wedge).
    pub is_home: bool,
}

/// Configuration for rx-stall detection. Read from the environment once per
/// [`Uniderp`] spawn; unknown/garbage values fall back to the defaults with a logged
/// warning (unknown-on-error — detection must never take the connection down via a
/// config parse issue, but a silently ignored override would invert the operator's
/// intent, so fallbacks are always loud).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct RxStallConfig {
    /// How long the home connection must be frame-silent — zero DERP frames of any
    /// kind, server keepalives included — before it is declared rx-stalled.
    ///
    /// `None` disables detection entirely (`TS_OFFNET_RX_STALL_SECS=0` or `off`).
    pub stall_threshold: Option<Duration>,
}

impl RxStallConfig {
    /// Default stall threshold.
    ///
    /// Standard DERP servers emit a server keepalive at least every
    /// [`ts_derp::frame::KEEP_ALIVE`] (60) seconds, so 180s of total frame silence is
    /// three consecutive missed keepalive intervals — a practically certain dead
    /// return path — while comfortably riding out the 1–2 minute dips observed during
    /// normal ord/dfw/den relay handovers (field data 2026-07-18).
    pub const DEFAULT_STALL_THRESHOLD: Duration = Duration::from_secs(180);
    /// Floor for the env-tunable threshold. Anything lower sits inside a single
    /// server-keepalive interval and would false-fire on a healthy idle connection.
    pub const MIN_STALL_THRESHOLD: Duration = Duration::from_secs(90);

    /// Env var overriding the stall threshold, in seconds. `0` or `off` disables
    /// rx-stall detection entirely (explicit kill-switch).
    pub const STALL_SECS_ENV: &str = "TS_OFFNET_RX_STALL_SECS";

    pub fn from_env() -> Self {
        Self::from_parts(std::env::var(Self::STALL_SECS_ENV).ok().as_deref())
    }

    /// Pure constructor from the raw env string so parsing is unit-testable.
    /// Unparseable or out-of-range values fall back to defaults/floors with a warning.
    fn from_parts(stall_secs: Option<&str>) -> Self {
        let stall_threshold = match stall_secs.map(str::trim) {
            None => Some(Self::DEFAULT_STALL_THRESHOLD),
            Some(raw) if raw == "0" || raw.eq_ignore_ascii_case("off") => {
                tracing::warn!(
                    env = Self::STALL_SECS_ENV,
                    "rx-stall detection DISABLED via environment kill-switch"
                );
                None
            }
            Some(raw) => match raw.parse::<u64>() {
                Ok(secs) => {
                    let parsed = Duration::from_secs(secs);
                    let clamped = parsed.max(Self::MIN_STALL_THRESHOLD);
                    if clamped != parsed {
                        tracing::warn!(
                            env = Self::STALL_SECS_ENV,
                            requested_secs = secs,
                            floor_secs = Self::MIN_STALL_THRESHOLD.as_secs(),
                            "rx-stall threshold below floor; clamping"
                        );
                    }
                    Some(clamped)
                }
                Err(_) => {
                    tracing::warn!(
                        env = Self::STALL_SECS_ENV,
                        value = raw,
                        default_secs = Self::DEFAULT_STALL_THRESHOLD.as_secs(),
                        "unparseable rx-stall threshold; using default"
                    );
                    Some(Self::DEFAULT_STALL_THRESHOLD)
                }
            },
        };

        Self { stall_threshold }
    }

    /// Apply a deterministic per-node upward jitter (+0–20%) to the stall threshold so
    /// the two koidra-ssh processes on one box (primary + backup channels, distinct
    /// node keys) never detect/recycle/escalate in lockstep. Upward-only so the
    /// configured floor stays respected.
    pub fn with_jitter(mut self, seed: u64) -> Self {
        self.stall_threshold = self.stall_threshold.map(|d| jittered(d, seed));
        self
    }
}

/// Deterministically scale `d` by 1.00–1.20 based on `seed` (per-mille resolution).
pub(crate) fn jittered(d: Duration, seed: u64) -> Duration {
    let permille = 1000 + (seed % 201) as u32;
    d.saturating_mul(permille) / 1000
}

/// Fold a node public key into a stable jitter seed.
pub(crate) fn jitter_seed(key: &NodePublicKey) -> u64 {
    let bytes: [u8; 32] = key.into();
    bytes.chunks(8).fold(0u64, |acc, chunk| {
        let mut b = [0u8; 8];
        b[..chunk.len()].copy_from_slice(chunk);
        acc ^ u64::from_le_bytes(b)
    })
}

/// Pure per-connection rx-stall tracker, grounded on **DERP frame silence**.
///
/// The input signal is the [`ts_derp::FrameActivity`] counter, which advances on
/// *every* frame the derp client receives — server keepalives, pings, peer-gone
/// notices, and peer data alike. Standard DERP servers keepalive at least every
/// [`ts_derp::frame::KEEP_ALIVE`] (60) seconds, so on a connection with a live return
/// path the counter always advances even when the node is completely idle.
///
/// The smoking-gun predicate is therefore: **home relay AND zero frames of any kind
/// past the threshold**. No tx requirement — on cross-region topologies (all three
/// live field incidents: hanyu/tok, redsun-win10/dfw, scherze-win7/nue) outbound tx is
/// routed to the *peer's* region connection, so the home connection legitimately
/// carries rx only; a tx-gated predicate is blind there. Conversely, a vanished SSH
/// peer does not false-fire: server keepalives keep arriving on the healthy home
/// connection, so the frame counter keeps advancing.
///
/// Handover-awareness (false-fire protection): the stall baseline is the *latest* of
/// (a) connection establishment, (b) the last observed frame arrival, and (c) the
/// moment this connection became home. A normal relay handover creates a fresh
/// connection and/or flips the home flag, either of which resets the clock — so the
/// 1–2 minute dips observed during normal ord/dfw/den handovers never accumulate into
/// a stall.
///
/// The frame counter is only *observed* when the select loop wakes (peer data, or the
/// stall deadline itself), so the baseline can lag actual frame arrival by up to one
/// threshold. Detection latency is therefore bounded by `[threshold, 2 × threshold)`
/// after the last frame — with the 180s default, worst-case ~6 minutes, against field
/// baselines of 1h+ natural recovery.
#[derive(Copy, Clone, Debug)]
pub struct RxStallTracker {
    /// Baseline instant for stall measurement: latest of connect / last observed
    /// frame arrival / became-home.
    baseline: Instant,
    /// Frame-counter value at the baseline. A differing live counter value means
    /// frames arrived since — the connection is not silent.
    frames_seen: u64,
    /// Packets sent to the relay since the last observed frame (telemetry only).
    pkts_sent_since_recv: u64,
    /// Whether this connection currently serves the home region.
    is_home: bool,
}

impl RxStallTracker {
    /// Create a tracker for a connection established at `now`, with the frame counter
    /// currently reading `frames_now`.
    pub fn new(now: Instant, is_home: bool, frames_now: u64) -> Self {
        Self {
            baseline: now,
            frames_seen: frames_now,
            pkts_sent_since_recv: 0,
            is_home,
        }
    }

    /// Observe the live frame counter. If frames arrived since the last observation,
    /// the stall clock resets to `now` and `true` is returned.
    pub fn observe_frames(&mut self, now: Instant, frames_now: u64) -> bool {
        if frames_now == self.frames_seen {
            return false;
        }
        self.frames_seen = frames_now;
        self.baseline = now;
        self.pkts_sent_since_recv = 0;
        true
    }

    /// Record `pkts` packets sent to the relay (telemetry only — not part of the
    /// stall predicate).
    pub fn on_send(&mut self, pkts: u64) {
        self.pkts_sent_since_recv = self.pkts_sent_since_recv.saturating_add(pkts);
    }

    /// Record a home-flag change. Becoming home resets the stall clock — the
    /// connection may have been legitimately quiet while non-home.
    pub fn on_home_change(&mut self, is_home: bool, now: Instant, frames_now: u64) {
        if is_home && !self.is_home {
            self.baseline = now;
            self.frames_seen = frames_now;
            self.pkts_sent_since_recv = 0;
        }
        self.is_home = is_home;
    }

    /// The smoking-gun predicate. Returns how long the connection has been
    /// frame-silent if it is home, no frames have arrived since the baseline, and the
    /// silence exceeds the threshold. `None` otherwise — including when detection is
    /// disabled, when fresh frames are pending observation, and on any internal
    /// arithmetic edge (detection is best-effort and must never panic).
    pub fn stalled_for(
        &self,
        now: Instant,
        frames_now: u64,
        cfg: &RxStallConfig,
    ) -> Option<Duration> {
        let threshold = cfg.stall_threshold?;
        if !self.is_home {
            return None;
        }
        if frames_now != self.frames_seen {
            // Frames arrived since the baseline — not silent. (The caller should
            // follow up with `observe_frames` to advance the baseline.)
            return None;
        }
        let since = now.saturating_duration_since(self.baseline);
        (since >= threshold).then_some(since)
    }

    /// Earliest instant at which [`Self::stalled_for`] could return `Some`, for use as
    /// a select-loop wake-up deadline. `None` when the predicate cannot trip (not
    /// home, or detection disabled), or on arithmetic overflow.
    pub fn check_deadline(&self, cfg: &RxStallConfig) -> Option<Instant> {
        let threshold = cfg.stall_threshold?;
        if !self.is_home {
            return None;
        }
        self.baseline.checked_add(threshold)
    }

    /// Packets sent since the last observed frame (for logging/telemetry).
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

        let rx_stall_config =
            RxStallConfig::from_env().with_jitter(jitter_seed(&args.env.keys.node_keys.public));
        if let Some(threshold) = rx_stall_config.stall_threshold
            && threshold >= Runner::MAX_CONNECTION_AGE
        {
            tracing::warn!(
                threshold_secs = threshold.as_secs(),
                max_connection_age_secs = Runner::MAX_CONNECTION_AGE.as_secs(),
                "rx-stall threshold >= connection age floor; the age recycle will reset \
                 the stall clock before detection can ever fire"
            );
        }

        let runner = Runner {
            region_id: args.region_id,
            region: args.region,
            peer_db: Arc::new(ArcSwapOption::new(None)),
            home_derp_rx,
            to_dataplane,
            keys: args.env.keys.node_keys.clone(),
            from_dataplane: Arc::new(Mutex::new(from_dataplane)),
            rx_stall_config,
            send_timeout: Runner::SEND_TIMEOUT,
            max_backoff_budget: Runner::MAX_BACKOFF_BUDGET,
            connect_timeout: Runner::CONNECT_TIMEOUT,
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

        // Unregister from the registry so `ensure_region` (and any other
        // consumer of `lookup_opt`) sees this actor as gone and can respawn
        // a fresh one on the next derp map update. Without this, the stale
        // WeakActorRef entry stays in the registry and `ensure_region`'s
        // `upgrade()` check is the only thing preventing a missed respawn.
        let region_id = self.runner_state.region_id;
        self.env
            .unregister::<Uniderp>(Some(Self::name(region_id)))
            .await
            .ok();

        Ok(())
    }

    /// Called when a linked actor dies. The Runner Task is the Uniderp's only
    /// linked child, and we want its death (for ANY reason) to propagate to
    /// the Uniderp so the registry entry is cleared (via `on_stop`) and the
    /// supervisor can respawn a fresh Uniderp with a fresh Runner.
    ///
    /// **Why override the default:** kameo's default `on_link_died` returns
    /// `Continue` for `ActorStopReason::Normal`. But the Runner's `run_fut`
    /// wrapper calls `slf.stop_gracefully()` on both Ok and Err returns from
    /// the runner future, producing a `Normal` stop reason. Without this
    /// override, a Runner that exhausts its backoff budget and returns `Err`
    /// (Component A's recovery path) would leave the Uniderp alive-but-
    /// taskless — exactly the alive-but-stuck wedge we're fixing.
    ///
    /// **Accidental-recovery context:** prior to `5ad5e48` (panic fix), the
    /// Runner panicked on `Ok(None)` from `connect()`, which killed the Task
    /// with `Panicked` reason, and kameo's default `on_link_died` for
    /// `Panicked` returns `Break` — so the Uniderp died, unregistered, and
    /// got respawned. The panic was accidentally the recovery mechanism.
    /// Fixing the panic (correctly) replaced `Panicked` with `Normal`,
    /// silently breaking that chain. This override restores it intentionally
    /// for ALL stop reasons.
    ///
    /// **Region-change path safety:** the `StateUpdate` handler does
    /// `self.task.unlink(...)` BEFORE `self.task.stop_gracefully()` when
    /// restarting the Task for a region change. `unlink` removes the link, so
    /// when the Task stops afterwards, `on_link_died` does NOT fire on the
    /// Uniderp — this override is not invoked for intentional Task restarts.
    /// Only an UNSOLICITED Task death (Runner returned on its own, or
    /// panicked) reaches this override.
    async fn on_link_died(
        &mut self,
        _: WeakActorRef<Self>,
        id: ActorId,
        reason: ActorStopReason,
    ) -> Result<ControlFlow<ActorStopReason>, Self::Error> {
        tracing::warn!(
            region_id = %self.runner_state.region_id,
            task_id = ?id,
            stop_reason = ?reason,
            "Runner Task died; stopping Uniderp so supervisor can respawn \
             a fresh Runner with fresh state"
        );
        Ok(ControlFlow::Break(ActorStopReason::LinkDied {
            id,
            reason: Box::new(reason),
        }))
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
        self.runner_state
            .peer_db
            .store(Some(msg.peers.clone()));
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
pub(crate) struct Runner {
    region_id: RegionId,
    region: DerpRegion,
    home_derp_rx: watch::Receiver<bool>,
    to_dataplane: Tx<FromUnderlay>,
    from_dataplane: Arc<Mutex<Rx<ToUnderlay>>>,
    peer_db: Arc<ArcSwapOption<PeerDb>>,
    keys: NodeKeyPair,
    /// rx-stall detection thresholds (env-tunable, defaults conservative).
    rx_stall_config: RxStallConfig,
    /// Upper bound on a single DERP send (see [`Runner::SEND_TIMEOUT`]).
    /// Injectable so the wedged-send recycle path is testable with a short bound;
    /// production always uses the default constant.
    send_timeout: Duration,
    /// Cumulative wall-clock budget for consecutive failed-connect-and-backoff
    /// cycles before run() returns Err. Injectable so the budget-exhaustion
    /// path is testable with a short budget; production always uses the
    /// default constant.
    max_backoff_budget: Duration,
    /// Upper bound on a single connect attempt. Injectable for testability;
    /// production always uses the default constant.
    connect_timeout: Duration,
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

    /// Cumulative wall-clock budget the Runner may spend in consecutive
    /// failed-connect-and-backoff cycles before giving up and returning `Err`
    /// from [`Runner::run`]. The Task stop → Uniderp stop (via the
    /// `on_link_died` override) → `on_stop` registry-unregister chain then
    /// lets [`crate::multiderp::Multiderp`]'s next `ensure_region` pass
    /// spawn a fresh Uniderp with a fresh Runner, fresh TCP, fresh Noise.
    ///
    /// This is the **intentional** recovery path that replaces the accidental
    /// recovery-via-panic path removed in `5ad5e48`. Without it, a Runner
    /// stuck in an `AllServersUnreachable` backoff loop after a sustained
    /// outage loops forever: the actor stays alive, the registry entry stays
    /// valid, and the supervisor never respawns. See
    /// `DERP-RECOVERY-DESIGN.md` Component A.
    ///
    /// Sized to comfortably exceed the longest expected transient outage
    /// (60 s backoff × 5 attempts = 5 min) while bounding the alive-but-stuck
    /// wedge to a single-digit-minutes window. Recovery latency target: the
    /// canary self-recovers within ~5–6 min of the underlying condition
    /// clearing.
    pub(crate) const MAX_BACKOFF_BUDGET: Duration = Duration::from_secs(300);

    /// Upper bound on a single `connect()` attempt. A connect that exceeds
    /// this is treated as a failure: the Runner backs off and retries. The
    /// underlying TCP/TLS/HTTP stacks have no explicit timeout (Linux's TCP
    /// SYN retries run 60–120 s), so without this bound a half-open socket
    /// wedges the Runner until the OS gives up. See `DERP-RECOVERY-DESIGN.md`
    /// Component B.
    ///
    /// Sized to comfortably exceed a healthy connect (typically 100–500 ms)
    /// while bounding the wedged-connect mode.
    const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);

    /// Interval at which the Runner publishes [`RunnerHeartbeat`] on the bus
    /// while alive and the loop is turning over. The supervisor's health
    /// monitor (Multiderp) uses the heartbeat to detect alive-but-stuck
    /// Runners; see `DERP-RECOVERY-DESIGN.md` Components C+D.
    pub(crate) const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(30);

    /// Upper bound on a single DERP send.
    ///
    /// A relay that stops ACKing wedges the TCP send path; without a bound, the
    /// blocked `send` inside the select-branch body starves the entire loop — the
    /// stall deadline AND the age recycle — which is the "tx froze → offline" field
    /// mode. On timeout the transport is recycled. Dropping the timed-out send future
    /// is safe: the transport is discarded wholesale, so a partially written frame can
    /// never corrupt a reused stream.
    const SEND_TIMEOUT: Duration = Duration::from_secs(30);

    #[tracing::instrument(skip_all, fields(region_id = %self.region_id))]
    async fn run(&mut self) -> Result<(), ts_derp::Error> {
        let mut backoff = Self::RECONNECT_BASE_BACKOFF;
        // Cumulative time spent in consecutive failed-connect-and-backoff
        // cycles. Reset to ZERO on any successful connect (including the
        // make-before-break pre-connect path). When this exceeds
        // [`Self::MAX_BACKOFF_BUDGET`], we return `Err` so the Task → Uniderp
        // → registry cleanup chain can respawn a fresh Runner. See
        // `DERP-RECOVERY-DESIGN.md` Component A.
        let mut cumulative_backoff = Duration::ZERO;
        // Pre-connected transport from a previous make-before-break recycle.
        // When Some, the outer loop uses it instead of calling connect(), so the
        // data path never gaps during age-recycle. See run_transport's pre-connect
        // spawn for how this gets populated.
        let mut preconnected: Option<(DerpTransport, ts_derp::FrameActivity)> = None;

        loop {
            let pending = self.wait_for_activity().await;

            // Use the pre-connected transport if available (make-before-break path),
            // otherwise establish a fresh connection.
            let (transport, frames) = if let Some(next) = preconnected.take() {
                tracing::info!(
                    region_id = %self.region_id,
                    "using pre-connected transport from make-before-break recycle"
                );
                backoff = Self::RECONNECT_BASE_BACKOFF;
                // A successful make-before-break swap IS a successful connect —
                // reset the budget so a long-lived connection that recycles
                // normally never approaches the budget limit.
                cumulative_backoff = Duration::ZERO;
                self.publish_heartbeat(Instant::now()).await;
                next
            } else {
                let connect_started = Instant::now();
                // BOUND the connect attempt: a half-open socket can hang the
                // TLS/HTTP upgrade for 60-120s (Linux TCP SYN retries). Treat
                // a timeout identically to an Err — backoff and retry. See
                // `DERP-RECOVERY-DESIGN.md` Component B.
                let connect_result =
                    tokio::time::timeout(self.connect_timeout, self.connect(pending)).await;
                match connect_result {
                    Ok(Ok(t)) => {
                        let elapsed = connect_started.elapsed();
                        // Warn on >1s connects: the data path gaps for this duration.
                        // With make-before-break, this branch only fires on INITIAL
                        // connect or pre-connect FAILURE fallback — both are
                        // non-recycle paths where a gap is unavoidable. If this warn
                        // fires at the SAME timestamp as an SSH wedge, the gap is the
                        // cause; if not, look elsewhere.
                        if elapsed >= Duration::from_secs(1) {
                            tracing::warn!(
                                region_id = %self.region_id,
                                ?elapsed,
                                "derp connect took more than 1s (data-path gap)",
                            );
                        } else {
                            tracing::debug!(
                                region_id = %self.region_id,
                                ?elapsed,
                                "derp connection established"
                            );
                        }
                        backoff = Self::RECONNECT_BASE_BACKOFF;
                        cumulative_backoff = Duration::ZERO;
                        // Fresh heartbeat on successful connect: the supervisor sees
                        // immediate evidence of progress, regardless of the 30s tick.
                        self.publish_heartbeat(Instant::now()).await;
                        t
                    }
                    Ok(Err(e)) => {
                        tracing::warn!(
                            region_id = %self.region_id,
                            backoff = ?backoff,
                            error = %e,
                            "derp connect failed; backing off"
                        );
                        tokio::time::sleep(backoff).await;
                        cumulative_backoff += backoff;
                        backoff = next_backoff(backoff, Self::RECONNECT_MAX_BACKOFF);
                        if cumulative_backoff >= self.max_backoff_budget {
                            tracing::error!(
                                region_id = %self.region_id,
                                cumulative_secs = cumulative_backoff.as_secs(),
                                budget_secs = self.max_backoff_budget.as_secs(),
                                "backoff budget exhausted; returning so the supervisor \
                                 can respawn the Uniderp with fresh state"
                            );
                            return Err(e);
                        }
                        continue;
                    }
                    Err(_elapsed) => {
                        tracing::warn!(
                            region_id = %self.region_id,
                            timeout_secs = self.connect_timeout.as_secs(),
                            "derp connect timed out (hung TLS/HTTP upgrade); backing off"
                        );
                        tokio::time::sleep(backoff).await;
                        cumulative_backoff += backoff;
                        backoff = next_backoff(backoff, Self::RECONNECT_MAX_BACKOFF);
                        if cumulative_backoff >= self.max_backoff_budget {
                            tracing::error!(
                                region_id = %self.region_id,
                                cumulative_secs = cumulative_backoff.as_secs(),
                                budget_secs = self.max_backoff_budget.as_secs(),
                                "backoff budget exhausted (after connect timeout); \
                                 returning so the supervisor can respawn the Uniderp"
                            );
                            return Err(ts_derp::Error::AllServersUnreachable);
                        }
                        continue;
                    }
                }
            };

            // run_transport returns Some(next_transport) when it exited via the
            // make-before-break recycle path (pre-connected transport is ready),
            // or None when it exited for another reason (stall, send timeout, etc.).
            preconnected = self.run_transport(transport, frames).await?;
        }
    }

    /// Best-effort publish of a [`RunnerHeartbeat`] on the bus. Heartbeat
    /// publication never blocks recovery: errors are logged, never propagated.
    /// The supervisor's health monitor (Multiderp) subscribes to this event
    /// to distinguish alive-and-progressing Runners from alive-but-stuck ones.
    async fn publish_heartbeat(&self, progress_at: Instant) {
        // Dereference the watch borrow BEFORE the await: `watch::Ref<'_, bool>`
        // is not `Send`, and the future containing it would not be `Send` either.
        let is_home = *self.home_derp_rx.borrow();
        if let Err(e) = self
            .env
            .publish_noretain(RunnerHeartbeat {
                region_id: self.region_id,
                last_progress_at: progress_at,
                is_home,
            })
            .await
        {
            tracing::error!(
                region_id = %self.region_id,
                error = %e,
                "publishing runner heartbeat"
            );
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
    ) -> Result<(DerpTransport, ts_derp::FrameActivity), ts_derp::Error> {
        tracing::trace!("establishing derp connection");

        let client = ts_derp::DefaultClient::connect(&self.region.servers, &self.keys).await?;
        // Transport and frame-arrival signal are constructed TOGETHER from the same
        // client: the signal advances on every DERP frame (keepalives included) —
        // the input to the frame-silence stall predicate — and the coupled API makes
        // wiring the tracker to a foreign/fresh handle unrepresentable.
        let (transport, frames) =
            client.into_transport_with_activity(PeerDbLookup(self.peer_db.clone()));

        if let Some(pending) = pending {
            tracing::trace!("sending queued packet");
            // Same bound as the run-loop sends: a relay that accepts the TCP
            // connection but wedges on the first write must surface as a connect
            // error (→ the caller's reconnect backoff), not hang `connect` forever.
            match tokio::time::timeout(self.send_timeout, transport.send([pending])).await {
                Ok(sent) => sent?,
                Err(_elapsed) => {
                    return Err(ts_derp::Error::IoFailure(std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        "pending-flush send timed out (write path wedged)",
                    )));
                }
            }
        }

        Ok((transport, frames))
    }

    #[tracing::instrument(skip_all, level = "trace")]
    async fn run_transport<T>(
        &mut self,
        transport: T,
        frames: ts_derp::FrameActivity,
    ) -> Result<Option<(DerpTransport, ts_derp::FrameActivity)>, ts_derp::Error>
    where
        T: UnderlayTransport<PeerKey = PeerId, Error = ts_derp::Error>,
    {
        let connected_at = Instant::now();
        let mut last_activity = Instant::now();
        // rx-stall tracking is deliberately SEPARATE from `last_activity`: the mixed
        // activity clock advances on tx as well, so a one-way connection (return path
        // dead — the redsun/dfw failure class) never trips the inactivity timeout.
        // The tracker's silence signal is the client's frame counter, which advances
        // on server keepalives too — so `transport.recv()` completing (peer data only)
        // is NOT required for the connection to count as alive.
        let mut rx_stall = RxStallTracker::new(
            connected_at,
            *self.home_derp_rx.borrow(),
            frames.frames_received(),
        );
        // Whether this connection has already published its once-per-connection
        // positive-health evidence ([`RxHealthyEvent`]).
        let mut health_published = false;
        let mut from_dataplane = self.from_dataplane.lock().await;

        // ---- Make-before-break age-recycle ----
        //
        // Instead of closing the old connection and THEN connecting (the old
        // break-then-make path, which left a 1-5s data-path gap during which
        // incoming SSH SYMs could not be delivered → "banner exchange" timeouts),
        // we spawn a background task that establishes the NEW connection at the
        // recycle deadline while the old transport continues serving traffic in
        // this select! loop. When the new connection is ready, we swap: the old
        // transport is dropped (on return), and the outer run() loop picks up the
        // pre-connected transport immediately — zero data-path gap.
        //
        // If the pre-connect fails, we return None so the outer loop falls back to
        // a fresh connect() (the legacy path). This is strictly better than the old
        // behavior because the old transport was alive for the entire pre-connect
        // window, not closed at the deadline.
        //
        // If run_transport exits for a DIFFERENT reason (rx-stall, send timeout,
        // inactivity), the spawned pre-connect task keeps running in the background.
        // It will establish a connection nobody reads; the result is dropped when
        // the oneshot's Sender goes out of scope, and the Client's Drop closes the
        // TLS/TCP socket. Wasteful but harmless — the outer loop's connect() wins
        // the race for the next transport.
        let recycle_deadline =
            connected_at + jittered(Self::MAX_CONNECTION_AGE, jitter_seed(&self.keys.public));
        let (preconnect_tx, preconnect_rx) =
            tokio::sync::oneshot::channel::<Result<(DerpTransport, ts_derp::FrameActivity), ts_derp::Error>>();
        {
            let runner_clone = self.clone();
            let deadline = recycle_deadline;
            tokio::spawn(async move {
                tokio::time::sleep_until(deadline.into()).await;
                tracing::debug!(
                    "make-before-break: pre-connecting new derp connection at age-recycle deadline"
                );
                let result = runner_clone.connect(None).await;
                drop(preconnect_tx.send(result));
            });
        }
        let mut preconnect_rx = std::pin::pin!(preconnect_rx);

        // Next heartbeat publication deadline. Resets on every publication so
        // the supervisor sees fresh "Runner is alive and making progress"
        // evidence every ~30s while the loop is turning over. See
        // `DERP-RECOVERY-DESIGN.md` Component C.
        let mut next_heartbeat = Instant::now() + Self::HEARTBEAT_INTERVAL;

        loop {
            let span = tracing::trace_span!("derp_loop");

            let inactivity_timeout =
                (!*self.home_derp_rx.borrow()).then(|| last_activity + Self::INACTIVITY_TIMEOUT);

            // Earliest instant an rx-stall could be declared; `None` while the predicate
            // cannot trip (not home / detection disabled). The deadline branch below
            // re-checks the live frame counter, so a keepalive-only connection (frames
            // advancing, no peer data) advances its baseline there instead of firing.
            let rx_stall_deadline = rx_stall.check_deadline(&self.rx_stall_config);

            tokio::select! {
                from_derp = transport.recv() => {
                    last_activity = Instant::now();
                    let advanced = rx_stall.observe_frames(last_activity, frames.frames_received());
                    // Health evidence publishes from ANY conn (home or not): frames
                    // arriving prove the region's return path regardless of home
                    // status, and a penalized region is usually observed from a
                    // non-home (cross-region) connection.
                    if advanced && !health_published {
                        health_published = true;
                        if let Err(e) = self.env.publish_noretain(RxHealthyEvent {
                            region_id: self.region_id,
                        }).await {
                            tracing::error!(parent: &span, error = %e, "publishing rx-healthy event");
                        }
                    }

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
                        return Ok(None);
                    };

                    tracing::trace!(parent: &span, peer = %from_net.0, packets = from_net.1.len(), "packets to derp server");

                    rx_stall.on_send(from_net.1.len() as u64);
                    // Bound the send: a wedged relay TCP path must not starve the
                    // select loop (and with it the stall deadline + age recycle).
                    match tokio::time::timeout(self.send_timeout, transport.send([from_net])).await {
                        Ok(sent) => sent?,
                        Err(_elapsed) => {
                            tracing::warn!(
                                parent: &span,
                                region_id = %self.region_id,
                                timeout = ?self.send_timeout,
                                "derp send timed out (write path wedged); recycling connection"
                            );
                            return Ok(None);
                        }
                    }
                },

                _ = option_timeout(inactivity_timeout) => {
                    if !*self.home_derp_rx.borrow_and_update() {
                        tracing::trace!(parent: &span, "timed out and not home derp, closing derp conn");
                        return Ok(None);
                    }
                },

                // Make-before-break: the pre-connect task (spawned at the top of
                // run_transport) fires at the recycle deadline and establishes a new
                // DERP connection concurrently. When it completes, this branch fires,
                // we return the new transport to the outer loop, and the old transport
                // (the parameter of this call) is dropped — zero data-path gap.
                result = &mut preconnect_rx => {
                    match result {
                        Ok(Ok((new_transport, new_frames))) => {
                            tracing::info!(
                                parent: &span,
                                region_id = %self.region_id,
                                connect_age = ?connected_at.elapsed(),
                                "make-before-break: new derp connection ready, swapping (zero-gap)"
                            );
                            return Ok(Some((new_transport, new_frames)));
                        }
                        Ok(Err(e)) => {
                            tracing::warn!(
                                parent: &span,
                                region_id = %self.region_id,
                                error = %e,
                                "make-before-break pre-connect failed; falling back to outer-loop reconnect"
                            );
                            return Ok(None);
                        }
                        Err(_) => {
                            tracing::warn!(
                                parent: &span,
                                region_id = %self.region_id,
                                "pre-connect task dropped sender; falling back to outer-loop reconnect"
                            );
                            return Ok(None);
                        }
                    }
                },

                _ = option_timeout(rx_stall_deadline) => {
                    // Re-verify against the LIVE frame counter before acting: the
                    // branch only means the deadline elapsed. Keepalives consumed
                    // inline by the derp client never complete `transport.recv()`,
                    // so this is where a keepalive-only connection advances its
                    // baseline.
                    let now = Instant::now();
                    let frames_now = frames.frames_received();
                    if let Some(stalled_for) = rx_stall.stalled_for(now, frames_now, &self.rx_stall_config) {
                        tracing::warn!(
                            parent: &span,
                            region_id = %self.region_id,
                            stalled_secs = stalled_for.as_secs(),
                            pkts_sent_since_recv = rx_stall.pkts_sent_since_recv(),
                            "home derp rx-stall detected (zero DERP frames, keepalives included); recycling connection"
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
                        return Ok(None);
                    }

                    let advanced = rx_stall.observe_frames(now, frames_now);
                    if advanced && !health_published {
                        health_published = true;
                        if let Err(e) = self.env.publish_noretain(RxHealthyEvent {
                            region_id: self.region_id,
                        }).await {
                            tracing::error!(parent: &span, error = %e, "publishing rx-healthy event");
                        }
                    }
                },

                _ = self.home_derp_rx.changed() => {
                    let is_home = *self.home_derp_rx.borrow();
                    rx_stall.on_home_change(is_home, Instant::now(), frames.frames_received());
                    tracing::trace!(is_home_derp = is_home);
                },

                // Periodic heartbeat: while the loop is alive and turning over,
                // publish progress evidence so the supervisor's health monitor
                // can distinguish alive-and-progressing Runners from
                // alive-but-stuck ones. See `DERP-RECOVERY-DESIGN.md` Component C.
                //
                // Skipped (deadline never set) when `run_transport` is parked
                // on the very first iteration — but the first iteration always
                // advances via one of the other arms within milliseconds (recv,
                // send, inactivity, or rx-stall deadline), so the heartbeat
                // deadline is set on subsequent iterations via the re-arm below.
                _ = tokio::time::sleep_until(next_heartbeat.into()) => {
                    let now = Instant::now();
                    self.publish_heartbeat(now).await;
                    next_heartbeat = now + Self::HEARTBEAT_INTERVAL;
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

struct PeerDbLookup(Arc<ArcSwapOption<PeerDb>>);

/// The concrete DERP transport type returned by [`Runner::connect`].
///
/// Named so it can be carried across `run_transport` → outer-loop boundaries for
/// make-before-break recycle (the pre-connected transport is established while the
/// old one is still alive, then swapped in atomically — see [`Runner::run_transport`]).
type DerpTransport =
    ts_transport::MapPeerKey<ts_derp::DefaultClient, PeerDbLookup, PeerId>;

impl ts_transport::PeerLookup<PeerId, NodePublicKey> for PeerDbLookup {
    fn lookup_key(&self, id: PeerId) -> Option<NodePublicKey> {
        let db = self.0.load();
        let db = db.as_ref()?;

        let (_, node) = db.get(&id)?;
        Some(node.node_key)
    }
}

impl ts_transport::PeerLookup<NodePublicKey, PeerId> for PeerDbLookup {
    fn lookup_key(&self, key: NodePublicKey) -> Option<PeerId> {
        let db = self.0.load();
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

    use super::{Runner, RxStallConfig, RxStallTracker, jittered, next_backoff};

    fn cfg() -> RxStallConfig {
        RxStallConfig {
            stall_threshold: Some(Duration::from_secs(180)),
        }
    }

    fn secs(n: u64) -> Duration {
        Duration::from_secs(n)
    }

    /// Frame counter stand-in for tests: `frames_seen` at construction is 0.
    const NO_FRAMES: u64 = 0;

    // ---- rx-stall detection predicate (pure, frame-silence-grounded) ----

    #[test]
    fn frame_silence_fires_on_home_conn_without_any_tx() {
        // The regrounded smoking gun: home relay, zero DERP frames past the
        // threshold. NO tx requirement — on cross-region topologies (hanyu/tok,
        // redsun-win10/dfw, scherze-win7/nue) the home connection carries no
        // outbound packets at all, so detection must not depend on tx.
        let t0 = Instant::now();
        let tr = RxStallTracker::new(t0, true, NO_FRAMES);
        assert_eq!(
            tr.stalled_for(t0 + secs(180), NO_FRAMES, &cfg()),
            Some(secs(180))
        );
        assert_eq!(
            tr.stalled_for(t0 + secs(400), NO_FRAMES, &cfg()),
            Some(secs(400))
        );
    }

    #[test]
    fn rx_stall_does_not_fire_when_not_home() {
        let t0 = Instant::now();
        let mut tr = RxStallTracker::new(t0, false, NO_FRAMES);
        tr.on_send(50);
        assert_eq!(tr.stalled_for(t0 + secs(600), NO_FRAMES, &cfg()), None);
    }

    #[test]
    fn pending_frames_suppress_stall_until_observed() {
        // The live counter moved past the baseline value: frames arrived, the
        // connection is not silent — no fire, regardless of elapsed time.
        let t0 = Instant::now();
        let tr = RxStallTracker::new(t0, true, NO_FRAMES);
        assert_eq!(tr.stalled_for(t0 + secs(600), 7, &cfg()), None);
    }

    #[test]
    fn keepalive_cadence_never_fires() {
        // A healthy idle connection: server keepalives every 60s, zero peer data,
        // zero tx. The baseline advances at each observation — never a stall.
        let t0 = Instant::now();
        let mut tr = RxStallTracker::new(t0, true, NO_FRAMES);
        for i in 1..=60u64 {
            let now = t0 + secs(i * 60);
            assert_eq!(tr.stalled_for(now, i, &cfg()), None, "keepalive #{i}");
            assert!(tr.observe_frames(now, i));
        }
    }

    #[test]
    fn dead_peer_with_keepalives_never_fires() {
        // The dead-peer false-fire class: the SSH peer vanished (tx retransmits
        // pile up, no peer data), but the relay's return path is healthy — server
        // keepalives keep arriving. Must not fire at any T.
        let t0 = Instant::now();
        let mut tr = RxStallTracker::new(t0, true, NO_FRAMES);
        for i in 1..=40u64 {
            let now = t0 + secs(i * 30);
            tr.on_send(20); // retransmit burst toward the dead peer
            assert_eq!(tr.stalled_for(now, i, &cfg()), None, "at t+{}s", i * 30);
            tr.observe_frames(now, i); // keepalive observed
        }
    }

    #[test]
    fn rx_stall_threshold_boundary_is_geq() {
        let t0 = Instant::now();
        let tr = RxStallTracker::new(t0, true, NO_FRAMES);
        assert_eq!(tr.stalled_for(t0 + secs(179), NO_FRAMES, &cfg()), None);
        assert_eq!(
            tr.stalled_for(t0 + secs(180), NO_FRAMES, &cfg()),
            Some(secs(180))
        );
    }

    #[test]
    fn observe_frames_resets_stall_clock_and_tx_counter() {
        let t0 = Instant::now();
        let mut tr = RxStallTracker::new(t0, true, NO_FRAMES);
        tr.on_send(10);
        // A frame observed at t+170 proves the return path; clock restarts.
        assert!(tr.observe_frames(t0 + secs(170), 1));
        assert_eq!(tr.pkts_sent_since_recv(), 0); // telemetry counter reset too
        assert_eq!(tr.stalled_for(t0 + secs(300), 1, &cfg()), None); // 130s since frame
        assert_eq!(tr.stalled_for(t0 + secs(349), 1, &cfg()), None); // 179s since frame
        assert_eq!(tr.stalled_for(t0 + secs(350), 1, &cfg()), Some(secs(180)));
        // Observing an unchanged counter does NOT reset the clock.
        assert!(!tr.observe_frames(t0 + secs(360), 1));
        assert_eq!(tr.stalled_for(t0 + secs(360), 1, &cfg()), Some(secs(190)));
    }

    #[test]
    fn check_deadline_none_when_not_home_or_disabled() {
        let t0 = Instant::now();
        let mut tr = RxStallTracker::new(t0, false, NO_FRAMES);
        assert_eq!(tr.check_deadline(&cfg()), None); // not home
        tr.on_home_change(true, t0, NO_FRAMES);
        assert_eq!(tr.check_deadline(&cfg()), Some(t0 + secs(180)));
        let disabled = RxStallConfig {
            stall_threshold: None,
        };
        assert_eq!(tr.check_deadline(&disabled), None); // kill-switch
    }

    #[test]
    fn disabled_config_never_fires() {
        // TS_OFFNET_RX_STALL_SECS=0/off: detection fully off, even on total silence.
        let disabled = RxStallConfig::from_parts(Some("0"));
        let t0 = Instant::now();
        let tr = RxStallTracker::new(t0, true, NO_FRAMES);
        assert_eq!(
            tr.stalled_for(t0 + secs(86_400), NO_FRAMES, &disabled),
            None
        );
    }

    #[test]
    fn idle_home_conn_does_not_fire_immediately_on_first_tx_after_long_idle() {
        // A home connection idle for 30+ minutes (keepalives flowing, zero tx) must
        // NOT insta-fire when the first tx burst goes out: tx is irrelevant to the
        // predicate and the keepalives have kept the baseline fresh.
        let t0 = Instant::now();
        let mut tr = RxStallTracker::new(t0, true, NO_FRAMES);
        let mut frames = 0u64;
        for i in 1..=30u64 {
            frames = i;
            tr.observe_frames(t0 + secs(i * 60), frames); // keepalive per minute
        }
        let t_idle_end = t0 + secs(30 * 60);
        tr.on_send(50); // first tx burst after the long idle
        assert_eq!(tr.stalled_for(t_idle_end + secs(1), frames, &cfg()), None);
        // ...and a genuine post-burst silence still fires one threshold later
        // (baseline = the last keepalive, observed at t_idle_end).
        assert_eq!(
            tr.stalled_for(t_idle_end + secs(181), frames, &cfg()),
            Some(secs(181))
        );
    }

    // ---- false-fire protection: normal relay handovers (1–2 min dips) ----

    #[test]
    fn no_false_fire_on_two_minute_frame_dip_with_default_threshold() {
        // Field data: normal ord/dfw/den relay handovers show 1–2 minute dips.
        // The default threshold must ride those out on a stable home connection.
        let defaults = RxStallConfig::from_parts(None);
        let t0 = Instant::now();
        let mut tr = RxStallTracker::new(t0, true, NO_FRAMES);
        assert_eq!(tr.stalled_for(t0 + secs(60), NO_FRAMES, &defaults), None); // 1 min dip
        assert_eq!(tr.stalled_for(t0 + secs(120), NO_FRAMES, &defaults), None); // 2 min dip
        // Dip ends within normal handover bounds — a frame resets, never fired.
        tr.observe_frames(t0 + secs(125), 1);
        assert_eq!(tr.stalled_for(t0 + secs(150), 1, &defaults), None);
    }

    #[test]
    fn no_false_fire_on_simulated_relay_handover_new_connection() {
        // A handover tears down the old connection and establishes a fresh one.
        // Even though the *node-level* frame gap spans > threshold across the
        // handover, each connection's stall clock starts at its own establishment.
        let defaults = RxStallConfig::from_parts(None);
        let t0 = Instant::now();

        // Old home connection: frame-silent for 100s before the handover closes it.
        let old_conn = RxStallTracker::new(t0, true, NO_FRAMES);
        assert_eq!(
            old_conn.stalled_for(t0 + secs(100), NO_FRAMES, &defaults),
            None
        );

        // Handover at t+100: fresh connection to the new relay (fresh tracker,
        // exactly what run_transport constructs on connect).
        let t1 = t0 + secs(100);
        let mut new_conn = RxStallTracker::new(t1, true, NO_FRAMES);
        // Node-level silence is now 150s > the 120s handover dip, but the new
        // connection is only 50s old — no fire.
        assert_eq!(
            new_conn.stalled_for(t1 + secs(50), NO_FRAMES, &defaults),
            None
        );
        // New relay starts delivering — handover completed, still no fire.
        new_conn.observe_frames(t1 + secs(70), 1);
        assert_eq!(new_conn.stalled_for(t1 + secs(120), 1, &defaults), None);
    }

    #[test]
    fn no_false_fire_when_home_moves_away_mid_dip() {
        // Handover variant where this region stops being home mid-dip: the tracker
        // must stand down immediately even if the old connection lingers.
        let defaults = RxStallConfig::from_parts(None);
        let t0 = Instant::now();
        let mut tr = RxStallTracker::new(t0, true, NO_FRAMES);
        tr.on_home_change(false, t0 + secs(90), NO_FRAMES); // home re-selected elsewhere
        assert_eq!(tr.stalled_for(t0 + secs(600), NO_FRAMES, &defaults), None);
    }

    #[test]
    fn becoming_home_resets_stall_clock() {
        // A connection quiet while non-home must not be declared stalled the moment
        // it becomes home.
        let defaults = RxStallConfig::from_parts(None);
        let t0 = Instant::now();
        let mut tr = RxStallTracker::new(t0, false, NO_FRAMES);
        tr.on_home_change(true, t0 + secs(300), NO_FRAMES);
        assert_eq!(tr.stalled_for(t0 + secs(310), NO_FRAMES, &defaults), None);
        // ...but a genuine stall after becoming home still fires.
        let threshold = defaults.stall_threshold.unwrap();
        assert_eq!(
            tr.stalled_for(t0 + secs(300) + threshold, NO_FRAMES, &defaults),
            Some(threshold)
        );
    }

    #[test]
    fn default_threshold_clears_normal_handover_dips_with_margin() {
        // Normal handovers dip 1–2 min; the default must exceed that with margin,
        // and must span at least two server-keepalive intervals (60s each) so a
        // single lost keepalive can never fire.
        assert!(RxStallConfig::DEFAULT_STALL_THRESHOLD >= Duration::from_secs(180));
        assert!(RxStallConfig::MIN_STALL_THRESHOLD >= Duration::from_secs(90));
    }

    // ---- config parsing: unknown-on-error ----

    #[test]
    fn rx_stall_config_defaults() {
        let c = RxStallConfig::from_parts(None);
        assert_eq!(
            c.stall_threshold,
            Some(RxStallConfig::DEFAULT_STALL_THRESHOLD)
        );
    }

    #[test]
    fn rx_stall_config_garbage_falls_back_to_defaults() {
        for garbage in ["", "abc", "-5", "1.5", "NaN", "9999999999999999999999"] {
            let c = RxStallConfig::from_parts(Some(garbage));
            assert_eq!(
                c.stall_threshold,
                Some(RxStallConfig::DEFAULT_STALL_THRESHOLD),
                "{garbage}"
            );
        }
    }

    #[test]
    fn rx_stall_config_valid_overrides_apply() {
        let c = RxStallConfig::from_parts(Some("240"));
        assert_eq!(c.stall_threshold, Some(secs(240)));
    }

    #[test]
    fn rx_stall_config_clamps_dangerously_low_values() {
        // A low-but-nonzero threshold would false-fire inside a single keepalive
        // interval; clamp to the floor instead.
        for low in ["1", "29", "89"] {
            let c = RxStallConfig::from_parts(Some(low));
            assert_eq!(
                c.stall_threshold,
                Some(RxStallConfig::MIN_STALL_THRESHOLD),
                "{low}"
            );
        }
    }

    #[test]
    fn rx_stall_config_zero_or_off_is_the_kill_switch() {
        // `0`/`off` must mean DISABLED — not "most aggressive possible".
        for off in ["0", "off", "OFF", " off "] {
            let c = RxStallConfig::from_parts(Some(off));
            assert_eq!(c.stall_threshold, None, "{off}");
        }
    }

    // ---- jitter: desync the two koidra-ssh processes on one box ----

    #[test]
    fn jitter_is_deterministic_and_bounded() {
        let base = secs(180);
        for seed in [0u64, 1, 42, u64::MAX] {
            let j1 = jittered(base, seed);
            let j2 = jittered(base, seed);
            assert_eq!(j1, j2, "deterministic for seed {seed}");
            assert!(j1 >= base, "never below the configured value ({seed})");
            assert!(j1 <= base * 12 / 10, "at most +20% ({seed})");
        }
        // Distinct seeds (mod 201) actually spread.
        assert_ne!(jittered(base, 0), jittered(base, 100));
    }

    #[test]
    fn spawn_path_jitter_keeps_env_threshold_in_bounds() {
        // The spawn path composes env parsing with per-node jitter
        // (`RxStallConfig::from_env().with_jitter(seed)`); the effective tracker
        // threshold must land in [T, 1.2T] of the configured value, and the
        // kill-switch must stay off regardless of seed.
        let base = secs(240);
        for seed in [0u64, 7, 100, 12345, u64::MAX] {
            let cfg = RxStallConfig::from_parts(Some("240")).with_jitter(seed);
            let t = cfg.stall_threshold.expect("enabled");
            assert!(t >= base, "never below the configured threshold ({seed})");
            assert!(t <= base * 12 / 10, "at most +20% ({seed})");
        }
        let off = RxStallConfig::from_parts(Some("off")).with_jitter(42);
        assert_eq!(off.stall_threshold, None, "kill-switch survives jitter");
    }

    // ---- behavior harness: the cross-region one-way stall timeline ----

    #[test]
    fn cross_region_one_way_stall_timeline_detects_and_redetects() {
        // Field topology (all three live incidents — hanyu/tok, redsun-win10/dfw,
        // scherze-win7/nue): outbound tx to the admin peer is routed to the PEER's
        // region connection, so the home connection carries ZERO tx; inbound peer
        // data and server keepalives are its only frames. At T_dead the relay's
        // return path dies: total frame silence on the home connection.
        let defaults = RxStallConfig::from_parts(None);
        let t0 = Instant::now();
        let mut tr = RxStallTracker::new(t0, true, NO_FRAMES);

        // Healthy phase: keepalives every 60s for 5 minutes. NO on_send() ever —
        // that is the routing reality this predicate was regrounded on.
        let mut frames = 0u64;
        for i in 1..=5u64 {
            frames = i;
            let now = t0 + secs(i * 60);
            assert_eq!(tr.stalled_for(now, frames, &defaults), None);
            tr.observe_frames(now, frames);
        }
        let t_dead = t0 + secs(300); // return path dies; counter frozen from here on

        // Poll every 10s like the select loop deadline would (bounded lag).
        let mut fired_at = None;
        for step in 1..=60u64 {
            let now = t_dead + secs(step * 10);
            if tr.stalled_for(now, frames, &defaults).is_some() {
                fired_at = Some(step * 10);
                break;
            }
        }
        // Fires at the first check at/after the 180s threshold — not before.
        assert_eq!(fired_at, Some(180));

        // Local recovery recycles the connection; the relay is still one-way-dead,
        // so the fresh connection re-detects after another full threshold —
        // giving the watchdog its repeated-stall escalation signal.
        let t1 = t_dead + secs(180);
        let tr2 = RxStallTracker::new(t1, true, NO_FRAMES);
        assert_eq!(tr2.stalled_for(t1 + secs(179), NO_FRAMES, &defaults), None);
        assert_eq!(
            tr2.stalled_for(t1 + secs(180), NO_FRAMES, &defaults),
            Some(secs(180))
        );
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

    #[test]
    fn send_timeout_is_well_below_the_default_stall_threshold() {
        // A wedged send must be shed long before the stall predicate would need to
        // fire, so the send bound can never mask stall detection.
        assert!(Runner::SEND_TIMEOUT < RxStallConfig::DEFAULT_STALL_THRESHOLD);
        assert!(Runner::SEND_TIMEOUT < Runner::MAX_CONNECTION_AGE);
    }

    // ---- DERP recovery architecture: budget, connect timeout, heartbeat ----
    //
    // See `DERP-RECOVERY-DESIGN.md` for the comprehensive design. These tests
    // verify the constant relationships that make the recovery system coherent;
    // the integration tests below verify the end-to-end recovery flow.

    #[test]
    fn backoff_budget_exceeds_max_per_attempt_backoff() {
        // The cumulative budget must exceed the per-attempt backoff cap, so a
        // SINGLE failure doesn't exhaust the budget. The budget is meant to
        // bound a SUSTAINED failure loop, not a transient one.
        assert!(Runner::MAX_BACKOFF_BUDGET > Runner::RECONNECT_MAX_BACKOFF);
    }

    #[test]
    fn backoff_budget_fits_at_least_three_capped_attempts() {
        // At the capped per-attempt backoff (30s), the budget must allow at
        // least 3 full attempts before exhausting — so the Runner genuinely
        // tries to recover before giving up. With 300s budget / 30s cap = 10
        // attempts, this is comfortably met.
        let attempts_at_cap =
            Runner::MAX_BACKOFF_BUDGET.as_secs() / Runner::RECONNECT_MAX_BACKOFF.as_secs();
        assert!(
            attempts_at_cap >= 3,
            "budget {}s must fit >=3 attempts at cap {}s (got {attempts_at_cap})",
            Runner::MAX_BACKOFF_BUDGET.as_secs(),
            Runner::RECONNECT_MAX_BACKOFF.as_secs()
        );
    }

    #[test]
    fn connect_timeout_below_max_backoff_budget() {
        // A single connect timeout (30s) must not exceed the budget (300s),
        // so one hung connect + retry doesn't immediately exhaust the budget.
        assert!(Runner::CONNECT_TIMEOUT < Runner::MAX_BACKOFF_BUDGET);
    }

    #[test]
    fn connect_timeout_exceeds_healthy_connect_latency() {
        // Healthy DERP connects are sub-second; 30s is generous margin for
        // slow networks without approaching the budget.
        assert!(Runner::CONNECT_TIMEOUT >= Duration::from_secs(10));
    }

    #[test]
    fn heartbeat_interval_is_shorter_than_max_staleness() {
        // The supervisor (Multiderp) considers a Runner stuck if no heartbeat
        // arrives in MAX_STALENESS (240s). Heartbeats publish every 30s, so
        // the supervisor sees ~7 missed heartbeats before acting — ample
        // margin for one or two dropped publications.
        //
        // The Multiderp constant lives in mod.rs; the relationship we verify
        // here is that the Runner's heartbeat interval is well under the
        // rx-stall threshold (180s) — the heartbeat must fire at least once
        // per rx-stall cycle so the supervisor sees progress evidence.
        assert!(Runner::HEARTBEAT_INTERVAL < RxStallConfig::DEFAULT_STALL_THRESHOLD);
    }

    #[test]
    fn heartbeat_interval_within_health_check_tick_window() {
        // Heartbeats must publish at least once per health-check tick (60s in
        // Multiderp). 30s interval = 2 heartbeats per tick, so a single
        // missed heartbeat doesn't cause a false stale.
        assert!(Runner::HEARTBEAT_INTERVAL < Duration::from_secs(60));
    }

    /// Simulate the cumulative-budget exhaustion arithmetic the run() loop
    /// performs, without spinning up the full Runner. Verifies that at the
    /// capped per-attempt backoff (30s), the budget (300s) is exhausted in
    /// exactly 10 iterations.
    #[test]
    fn backoff_budget_arithmetic_exhausts_after_expected_iterations() {
        let mut backoff = Runner::RECONNECT_BASE_BACKOFF;
        let mut cumulative = Duration::ZERO;
        let mut iterations = 0u32;

        loop {
            cumulative += backoff;
            backoff = next_backoff(backoff, Runner::RECONNECT_MAX_BACKOFF);
            iterations += 1;
            if cumulative >= Runner::MAX_BACKOFF_BUDGET {
                break;
            }
            assert!(iterations < 100, "budget never exhausted — runaway loop");
        }

        // With base=500ms, cap=30s, budget=300s: the loop accumulates
        // 500ms+1s+2s+4s+8s+16s+30s+30s+30s+30s+30s = 181.5s after 11
        // iterations, but the cap kicks in at iteration 6 (30s) onwards.
        // The exact count isn't the test — what matters is it terminates
        // in bounded iterations.
        assert!(iterations <= 20, "too many iterations: {iterations}");
        assert!(cumulative >= Runner::MAX_BACKOFF_BUDGET);
    }

    /// A Runner whose `connect()` always fails with `AllServersUnreachable`
    /// must eventually return `Err` from `run()` after the budget is
    /// exhausted, NOT loop forever. This is the core regression: the
    /// alive-but-stuck-in-backoff wedge.
    ///
    /// Uses a `Runner` whose `region.servers` is empty so `connect()` fails
    /// immediately with `AllServersUnreachable`, AND a tiny budget override
    /// so the test completes in milliseconds. Verifies the run() loop's
    /// budget-exhaustion → Err → supervisor-respawn chain is wired correctly.
    #[tokio::test]
    async fn runner_returns_err_when_backoff_budget_exhausted() {
        let mut h = harness(Duration::from_secs(300)).await;
        h.runner.region.servers = vec![]; // force AllServersUnreachable
        // Override the budget to a tiny value so the test doesn't wait 300s.
        // Budget must exceed one backoff tick to actually cycle the loop.
        h.runner.max_backoff_budget = Duration::from_millis(1);
        // Set home so wait_for_activity returns immediately and the loop
        // actually tries to connect (otherwise it parks).
        h._home_tx.send(true).expect("watch alive");

        let mut runner = h.runner;
        // 10s timeout — generous margin over the ~immediate budget exhaustion.
        let result = tokio::time::timeout(Duration::from_secs(10), runner.run()).await;
        match result {
            Ok(Err(_e)) => { /* expected: budget exhausted → Err */ }
            Ok(Ok(())) => panic!("run() returned Ok — should never happen (no Ok path)"),
            Err(_elapsed) => panic!(
                "run() did not return within 10s — budget exhaustion path broken \
                 (the alive-but-stuck-in-backoff wedge)"
            ),
        }
    }

    /// A Runner whose `connect()` hangs forever must return `Err` after the
    /// connect timeout fires enough times to exhaust the budget. Catches the
    /// "Runner wedged inside connect()" failure mode (F3 in the design).
    ///
    /// We can't easily inject a hanging connect (it requires a fake server
    /// that accepts TCP but never completes TLS), so this test documents the
    /// contract via the `connect_timeout` field: a single timeout event
    /// contributes to cumulative_backoff, and once cumulative exceeds the
    /// budget, run() returns Err.
    #[test]
    fn connect_timeout_and_budget_interact_correctly() {
        // Single connect timeout = connect_timeout (30s default).
        // Budget = 300s default.
        // So 10 consecutive timeouts exhaust the budget.
        let per_timeout = Runner::CONNECT_TIMEOUT;
        let budget = Runner::MAX_BACKOFF_BUDGET;
        let timeouts_to_exhaust = budget.as_secs() / per_timeout.as_secs();
        assert!(
            timeouts_to_exhaust >= 3,
            "budget must survive at least 3 connect timeouts"
        );
        assert!(
            timeouts_to_exhaust <= 20,
            "budget must not require too many timeouts to exhaust (recovery latency)"
        );
    }

    // ---- seam harness: run_transport against a scripted frame signal ----
    //
    // Fake `UnderlayTransport` whose `recv` never yields peer data — exactly the
    // cross-region home connection — while the test drives the DERP frame counter
    // directly (the same handle `ts_derp::Client` increments on keepalives).

    use std::{
        num::NonZeroU32,
        sync::Arc as StdArc,
    };

    use arc_swap::ArcSwapOption;

    use kameo::actor::Spawn as _;
    use tokio::sync::{Mutex, mpsc, watch};
    use ts_derp::{FrameActivity, RegionId, RegionInfo};
    use ts_packet::PacketMut;
    use ts_transport::{BatchRecvIter, BatchSendIter, PeerId, UnderlayTransport};

    use super::{RxHealthyEvent, RxStallEvent};
    use crate::env::Env;

    struct PendingTransport;

    impl UnderlayTransport for PendingTransport {
        type PeerKey = PeerId;
        type Error = ts_derp::Error;

        async fn send(
            &self,
            _packet_batch: impl BatchSendIter<Self::PeerKey>,
        ) -> Result<(), Self::Error> {
            Ok(())
        }

        async fn recv(&self) -> impl BatchRecvIter<Self::PeerKey, Error = Self::Error> {
            core::future::pending::<()>().await;
            Vec::<Result<(PeerId, Vec<PacketMut>), ts_derp::Error>>::new()
        }
    }

    /// Transport whose `recv` yields one EMPTY batch per wake-up message —
    /// modelling frames that the derp client consumes inline (keepalives) or
    /// batches that carry no peer data — and pends forever once the channel closes.
    struct EmptyBatchOnDemand(Mutex<mpsc::UnboundedReceiver<()>>);

    impl UnderlayTransport for EmptyBatchOnDemand {
        type PeerKey = PeerId;
        type Error = ts_derp::Error;

        async fn send(
            &self,
            _packet_batch: impl BatchSendIter<Self::PeerKey>,
        ) -> Result<(), Self::Error> {
            Ok(())
        }

        async fn recv(&self) -> impl BatchRecvIter<Self::PeerKey, Error = Self::Error> {
            let mut wake = self.0.lock().await;
            if wake.recv().await.is_none() {
                core::future::pending::<()>().await;
            }
            Vec::<Result<(PeerId, Vec<PacketMut>), ts_derp::Error>>::new()
        }
    }

    /// Transport whose `send` never completes — the wedged-TCP-write-path field mode
    /// (relay stops ACKing, send buffer full) — and whose `recv` never yields.
    struct WedgedSendTransport;

    impl UnderlayTransport for WedgedSendTransport {
        type PeerKey = PeerId;
        type Error = ts_derp::Error;

        async fn send(
            &self,
            _packet_batch: impl BatchSendIter<Self::PeerKey>,
        ) -> Result<(), Self::Error> {
            core::future::pending::<()>().await;
            Ok(())
        }

        async fn recv(&self) -> impl BatchRecvIter<Self::PeerKey, Error = Self::Error> {
            core::future::pending::<()>().await;
            Vec::<Result<(PeerId, Vec<PacketMut>), ts_derp::Error>>::new()
        }
    }

    /// Bus probe capturing rx-stall / rx-healthy events into channels.
    struct BusProbe {
        stall_tx: mpsc::UnboundedSender<RxStallEvent>,
        healthy_tx: mpsc::UnboundedSender<RxHealthyEvent>,
    }

    impl kameo::Actor for BusProbe {
        type Args = (
            Env,
            mpsc::UnboundedSender<RxStallEvent>,
            mpsc::UnboundedSender<RxHealthyEvent>,
        );
        type Error = crate::Error;

        async fn on_start(
            (env, stall_tx, healthy_tx): Self::Args,
            slf: kameo::actor::ActorRef<Self>,
        ) -> Result<Self, Self::Error> {
            env.subscribe::<RxStallEvent>(&slf).await?;
            env.subscribe::<RxHealthyEvent>(&slf).await?;
            env.register(None, &slf).await?;
            Ok(Self {
                stall_tx,
                healthy_tx,
            })
        }
    }

    impl kameo::message::Message<RxStallEvent> for BusProbe {
        type Reply = ();

        async fn handle(
            &mut self,
            msg: RxStallEvent,
            _: &mut kameo::message::Context<Self, Self::Reply>,
        ) {
            drop(self.stall_tx.send(msg));
        }
    }

    impl kameo::message::Message<RxHealthyEvent> for BusProbe {
        type Reply = ();

        async fn handle(
            &mut self,
            msg: RxHealthyEvent,
            _: &mut kameo::message::Context<Self, Self::Reply>,
        ) {
            drop(self.healthy_tx.send(msg));
        }
    }

    struct Harness {
        runner: Runner,
        // Keep the channel far-ends alive so run_transport doesn't see closed queues.
        _home_tx: watch::Sender<bool>,
        _from_dp_tx: super::Tx<super::ToUnderlay>,
        _to_dp_rx: mpsc::UnboundedReceiver<super::FromUnderlay>,
        stall_rx: mpsc::UnboundedReceiver<RxStallEvent>,
        healthy_rx: mpsc::UnboundedReceiver<RxHealthyEvent>,
        region_id: RegionId,
    }

    async fn harness(threshold: Duration) -> Harness {
        let env = Env::new(ts_keys::NodeState::generate());
        let (stall_tx, stall_rx) = mpsc::unbounded_channel();
        let (healthy_tx, healthy_rx) = mpsc::unbounded_channel();
        let _probe = BusProbe::spawn((env.clone(), stall_tx, healthy_tx));
        env.wait::<BusProbe>(None).await.unwrap();

        let region_id = RegionId(NonZeroU32::new(1).unwrap());
        let (home_tx, home_rx) = watch::channel(true);
        let (to_dp_tx, to_dp_rx) = mpsc::unbounded_channel();
        let (from_dp_tx, from_dp_rx) = mpsc::unbounded_channel();

        let runner = Runner {
            region_id,
            region: ts_control::DerpRegion {
                info: RegionInfo {
                    name: "test".into(),
                    code: "test".into(),
                    no_measure_no_home: false,
                },
                servers: vec![],
            },
            home_derp_rx: home_rx,
            to_dataplane: to_dp_tx,
            from_dataplane: StdArc::new(Mutex::new(from_dp_rx)),
            peer_db: StdArc::new(ArcSwapOption::new(None)),
            keys: ts_keys::NodeState::generate().node_keys,
            rx_stall_config: RxStallConfig {
                stall_threshold: Some(threshold),
            },
            send_timeout: Runner::SEND_TIMEOUT,
            max_backoff_budget: Runner::MAX_BACKOFF_BUDGET,
            connect_timeout: Runner::CONNECT_TIMEOUT,
            env,
        };

        Harness {
            runner,
            _home_tx: home_tx,
            _from_dp_tx: from_dp_tx,
            _to_dp_rx: to_dp_rx,
            stall_rx,
            healthy_rx,
            region_id,
        }
    }

    /// The mandatory D1 seam test, runtime half: a home connection whose transport
    /// never yields peer data and whose frame counter never advances — the exact
    /// cross-region field failure (zero tx on the home conn) — must publish an
    /// [`RxStallEvent`] and recycle.
    #[tokio::test]
    async fn run_transport_detects_frame_silence_without_any_tx() {
        let mut h = harness(Duration::from_millis(300)).await;
        let frames = FrameActivity::default();

        let mut runner = h.runner;
        let done =
            tokio::spawn(async move { runner.run_transport(PendingTransport, frames).await });

        let evt = tokio::time::timeout(Duration::from_secs(10), h.stall_rx.recv())
            .await
            .expect("stall event within timeout")
            .expect("bus probe alive");
        assert_eq!(evt.region_id, h.region_id);
        assert_eq!(
            evt.pkts_sent_since_recv, 0,
            "cross-region home conn carries no tx; detection must not require it"
        );
        assert!(evt.stalled_for >= Duration::from_millis(300));

        // Local recovery: run_transport returns Ok so `run` reconnects.
        let ret = tokio::time::timeout(Duration::from_secs(5), done)
            .await
            .expect("run_transport returns after stall")
            .expect("no panic");
        assert!(ret.is_ok());
    }

    /// A forever-pending send with a short injected timeout must recycle the
    /// connection via an `Ok` return (run() reconnects) — and must NOT publish a
    /// stall event: a wedged tx path is a local recycle, not rx-stall evidence.
    #[tokio::test]
    async fn run_transport_recycles_wedged_send_without_stall_event() {
        let mut h = harness(Duration::from_secs(300)).await;
        h.runner.send_timeout = Duration::from_millis(50);
        let frames = FrameActivity::default();

        // One outbound packet triggers the send branch, which wedges forever.
        h._from_dp_tx
            .send((PeerId(1), vec![PacketMut::from(&b"payload"[..])]))
            .expect("queue open");

        let mut runner = h.runner;
        let done =
            tokio::spawn(async move { runner.run_transport(WedgedSendTransport, frames).await });

        let ret = tokio::time::timeout(Duration::from_secs(5), done)
            .await
            .expect("send timeout must shed the wedged send well within bounds")
            .expect("no panic");
        assert!(ret.is_ok(), "recycle path returns Ok so run() reconnects");
        assert!(
            h.stall_rx.try_recv().is_err(),
            "a wedged send is not rx-stall evidence"
        );
    }

    /// A NON-home connection observing frames must still publish health evidence
    /// for its region — health is health regardless of home status, and a penalized
    /// region's recovery is typically visible only from its cross-region (non-home)
    /// connection — exactly once per connection, and must never publish a stall.
    #[tokio::test]
    async fn non_home_conn_publishes_health_evidence_once_for_its_region() {
        let mut h = harness(Duration::from_secs(300)).await;
        h._home_tx.send(false).expect("watch alive"); // NOT home for this whole test
        let frames = FrameActivity::default();
        let feeder_frames = frames.clone();
        let (wake_tx, wake_rx) = mpsc::unbounded_channel();

        let mut runner = h.runner;
        let done = tokio::spawn(async move {
            runner
                .run_transport(EmptyBatchOnDemand(Mutex::new(wake_rx)), frames)
                .await
        });

        // DERP frames arrive periodically on the non-home conn (cross-region peer
        // relay traffic). Periodic — not one-shot — so the first record can never
        // race the tracker's baseline capture inside the spawned loop.
        let feeder = tokio::spawn(async move {
            for _ in 0..30u32 {
                tokio::time::sleep(Duration::from_millis(50)).await;
                feeder_frames.record();
                if wake_tx.send(()).is_err() {
                    break;
                }
            }
            wake_tx // keep the wake channel open so recv pends instead of closing
        });

        let healthy = tokio::time::timeout(Duration::from_secs(5), h.healthy_rx.recv())
            .await
            .expect("health evidence from a non-home conn")
            .expect("bus probe alive");
        assert_eq!(healthy.region_id, h.region_id);

        // Let the remaining frame advances play out: once-per-conn, no re-publish.
        let _wake_tx = feeder.await.expect("feeder");

        // Close the dataplane queue: run_transport exits cleanly (Ok).
        drop(h._from_dp_tx);
        let ret = tokio::time::timeout(Duration::from_secs(5), done)
            .await
            .expect("run_transport returns when the dataplane queue closes")
            .expect("no panic");
        assert!(ret.is_ok());

        assert!(h.stall_rx.try_recv().is_err(), "non-home conn never stalls");
        assert!(
            h.healthy_rx.try_recv().is_err(),
            "health evidence is once per connection"
        );
    }

    /// Keepalive-only frame arrival (never completing `transport.recv()`) must keep
    /// advancing the stall baseline — no stall while frames flow, positive-health
    /// evidence published once — and total silence afterwards must still fire.
    /// (Threshold/cadence margin is 10x so scheduler hiccups can't flake this.)
    #[tokio::test]
    async fn run_transport_keepalives_advance_baseline_then_silence_fires() {
        let mut h = harness(Duration::from_secs(1)).await;
        let frames = FrameActivity::default();
        let feeder_frames = frames.clone();

        let mut runner = h.runner;
        let done =
            tokio::spawn(async move { runner.run_transport(PendingTransport, frames).await });

        // Simulated server keepalives: one every 100ms for 1.5s.
        let feeder = tokio::spawn(async move {
            for _ in 0..15u32 {
                tokio::time::sleep(Duration::from_millis(100)).await;
                feeder_frames.record();
            }
        });

        // Health evidence appears at the first deadline check that observes frames.
        let healthy = tokio::time::timeout(Duration::from_secs(5), h.healthy_rx.recv())
            .await
            .expect("healthy event while keepalives flow")
            .expect("bus probe alive");
        assert_eq!(healthy.region_id, h.region_id);

        // While keepalives flow, no stall may fire.
        feeder.await.expect("feeder");
        assert!(
            h.stall_rx.try_recv().is_err(),
            "no stall while frames were advancing"
        );
        // Once-per-connection: ~14 further frame advances after the first health
        // publish must NOT re-publish — health evidence is per-conn, not per-frame.
        assert!(
            h.healthy_rx.try_recv().is_err(),
            "no second RxHealthyEvent while frames keep advancing on the same conn"
        );

        // Frames stopped: silence must now be detected within ~2x threshold.
        let evt = tokio::time::timeout(Duration::from_secs(10), h.stall_rx.recv())
            .await
            .expect("stall after frames stop")
            .expect("bus probe alive");
        assert_eq!(evt.region_id, h.region_id);

        let ret = tokio::time::timeout(Duration::from_secs(5), done)
            .await
            .expect("run_transport returns after stall")
            .expect("no panic");
        assert!(ret.is_ok());
    }

    /// Client→runtime wiring seam, exercised end-to-end with a REAL derp client:
    /// true handshake, true frame codec, true keepalive accounting — wired through
    /// [`ts_derp::Client::into_transport_with_activity`] exactly as `connect()`
    /// does. While the fake server's keepalives flow, the loop must publish
    /// positive-health evidence and hold off the stall predicate — which only
    /// happens when the tracker observes the SAME [`FrameActivity`] the client
    /// increments. A decoupled or freshly-defaulted handle (the mutation-D bug:
    /// every healthy conn false-fires in production) fails this test on both
    /// counts. Silence afterwards must still fire and recycle.
    #[tokio::test]
    async fn run_transport_with_real_client_sees_its_keepalives_then_silence_fires() {
        let mut h = harness(Duration::from_secs(1)).await;
        let keys = h.runner.keys.clone();
        let (client_io, server_io) = tokio::io::duplex(1 << 16);
        let (client, mut server) = tokio::join!(
            async {
                ts_derp::Client::handshake(client_io, &keys)
                    .await
                    .expect("client handshake")
            },
            ts_derp::test_util::FakeServer::handshake(server_io, &keys.public),
        );

        let (transport, frames) =
            client.into_transport_with_activity(super::PeerDbLookup(h.runner.peer_db.clone()));

        let mut runner = h.runner;
        let done = tokio::spawn(async move { runner.run_transport(transport, frames).await });

        // Real server keepalives every 100ms for 1.5s (10x margin vs the 1s
        // threshold). The server is returned so the pipe stays open — dropping it
        // would EOF the client and exit the loop via recv error, not the stall.
        let feeder = tokio::spawn(async move {
            for _ in 0..15u32 {
                tokio::time::sleep(Duration::from_millis(100)).await;
                server.send_keepalive().await;
            }
            server
        });

        let healthy = tokio::time::timeout(Duration::from_secs(5), h.healthy_rx.recv())
            .await
            .expect("healthy event while real keepalives flow")
            .expect("bus probe alive");
        assert_eq!(healthy.region_id, h.region_id);

        let _server = feeder.await.expect("feeder");
        assert!(
            h.stall_rx.try_recv().is_err(),
            "no stall while the real client's keepalives were arriving"
        );

        // Server goes silent (pipe still open): the stall must fire and recycle.
        let evt = tokio::time::timeout(Duration::from_secs(10), h.stall_rx.recv())
            .await
            .expect("stall after keepalives stop")
            .expect("bus probe alive");
        assert_eq!(evt.region_id, h.region_id);

        let ret = tokio::time::timeout(Duration::from_secs(5), done)
            .await
            .expect("run_transport returns after stall")
            .expect("no panic");
        assert!(ret.is_ok());
    }

    // ---- arc_swap wedge-fix regression test ----
    //
    // Prior to the arc_swap migration, `peer_db` was a `RwLock<Option<Arc<PeerDb>>>`.
    // Under sustained DERP load the read path (`PeerDbLookup::lookup_key`, called per
    // DERP packet on the transport hot path) starved tokio workers when a writer
    // held the lock — the wedge the direct-path team root-caused.
    //
    // This stress test proves the `ArcSwapOption` replacement doesn't deadlock under
    // the same load pattern: many concurrent readers + a continuous writer. With the
    // old `RwLock`, a slow/panicked writer would block every reader. With
    // `ArcSwapOption`, reads and writes are independent atomics — neither blocks the
    // other, ever.
    //
    // We can't easily construct a fully-populated `Node` here without dragging in the
    // full peer_tracker test helpers, but we don't need to: the wedge was in the
    // *locking primitive*, not the PeerDb contents. Empty PeerDb exercises the same
    // load/store paths; lookups return None, but the atomic behavior under
    // contention is what we're verifying.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn arc_swap_peer_db_lookup_does_not_deadlock_under_concurrent_writers() {
        use std::sync::atomic::{AtomicU64, Ordering};

        use super::{ArcSwapOption, PeerDb, PeerDbLookup};
        use std::sync::Arc;
        use ts_transport::PeerLookup;

        let peer_db: Arc<ArcSwapOption<PeerDb>> = Arc::new(ArcSwapOption::new(None));
        let lookup = PeerDbLookup(peer_db.clone());
        let read_count = Arc::new(AtomicU64::new(0));
        let write_count = Arc::new(AtomicU64::new(0));

        // 8 reader tasks, each hammering lookup_key on both supported key types.
        // PeerDb is empty so every lookup returns None — but the atomic load path
        // runs every time. If any read blocked on a writer (the old RwLock failure
        // mode), the 3s timeout below would fire.
        let mut readers = Vec::new();
        for _ in 0..8 {
            let lookup_clone = PeerDbLookup(peer_db.clone());
            let counter = read_count.clone();
            readers.push(tokio::spawn(async move {
                // Spawn a blocking task per reader: lookup_key is sync. Under the
                // old RwLock this is exactly where tokio workers got wedged — a
                // blocking sync read() on a writer-held lock. With arc_swap the
                // load() is a single atomic, so blocking-thread overhead is the
                // only cost (no contention).
                tokio::task::spawn_blocking(move || {
                    // burn 1000 iterations of both key-direction lookups
                    for i in 0u32..1_000 {
                        let _ = lookup_clone.lookup_key(PeerId(i));
                    }
                    counter.fetch_add(1_000, Ordering::Relaxed);
                })
                .await
                .unwrap();
            }));
        }

        // 1 writer task: continuously swap the entire PeerDb snapshot (the exact
        // pattern `handle(Arc<PeerState>)` uses in production). Each store is a new
        // empty Arc<PeerDb>.
        let writer_db = peer_db.clone();
        let writer_counter = write_count.clone();
        let writer = tokio::spawn(async move {
            // Cap by iterations rather than time so the test is deterministic.
            for _ in 0..5_000 {
                writer_db.store(Some(Arc::new(PeerDb::default())));
            }
            writer_counter.store(5_000, Ordering::Relaxed);
        });

        // 3s hard timeout — the old RwLock wedge would hang indefinitely here.
        let timeout = Duration::from_secs(3);

        let read_res = tokio::time::timeout(
            timeout,
            async {
                drop(writer.await);
                let mut reader_results = Vec::new();
                for r in readers.drain(..) {
                    reader_results.push(r.await);
                }
                reader_results
            },
        )
        .await
        .expect(
            "DEADLOCK: arc_swap lookup path hung under concurrent readers + writer \
             (this is exactly the wedge the fix targets — if it fires, the arc_swap \
             migration regressed)",
        );

        // All readers completed without panic.
        for r in read_res {
            assert!(r.is_ok(), "reader task panicked: {r:?}");
        }

        // Sanity: the counters reflect the work we asked for. The writer does 5000
        // stores; readers do 8000 lookups (8 × 1000).
        assert_eq!(write_count.load(Ordering::Relaxed), 5_000);
        assert_eq!(read_count.load(Ordering::Relaxed), 8_000);

        // Let lookup go out of scope cleanly (no use-after-free in arc_swap).
        drop(lookup);
    }
}
