//! Off-tailnet watchdog.
//!
//! Detects when this node has silently drifted off the tailnet — control-plane connection
//! stuck or dead with the process still alive — and forces a [`crate::control_runner::ForceReconnect`]
//! so control re-establishes and the node re-registers.
//!
//! ## Why this exists
//!
//! The DERP-home self-heal ([`crate::derp_latency`]) and the connection-age floor
//! ([`crate::multiderp::uniderp`]) only recover failures *within* the DERP data plane.
//! They cannot recover a control-plane connection that has silently died:
//!
//! 1. Without a live control stream there are no [`StateUpdate`]s, hence no fresh derp map,
//!    so [`DerpLatencyMeasurer::measure_and_publish`] early-returns on `derp_map = None`.
//! 2. Even with a retained map, a total UDP-path drop (firewall state reaped, NAT remap)
//!    measures every region as unreachable → `best = None` → no re-home target.
//! 3. The only thing that recovers a stale-NAT/total-drop is fresh sockets + fresh Noise
//!    handshake + control re-registration — exactly what [`ControlRunner::on_start`] does
//!    on initial connect. The watchdog re-triggers that path in-process.
//!
//! ## Liveness signal
//!
//! Any [`StateUpdate`] published on the bus is proof that the control stream is alive
//! and the node is registered. The watchdog treats the time since the last
//! [`StateUpdate`] as the off-tailnet indicator: if it exceeds `T_DETECT` (default 180s,
//! env `TS_OFFNET_T_DETECT_SECS`), the node is presumed off-tailnet and a reconnect is
//! forced.
//!
//! ## rx-stall escalation
//!
//! The watchdog also subscribes to [`RxStallEvent`] — published by the home region's
//! derp task when its connection is frame-silent (zero DERP frames, server keepalives
//! included, past `TS_OFFNET_RX_STALL_SECS`); the detecting connection recycles itself
//! locally immediately after publishing. Repeated stalls walk an escalation ladder:
//! re-netcheck ([`Remeasure`]) → forced lateral re-home overriding anti-flap
//! hysteresis and penalty-boxing the stalled region ([`ForceRehome`]) → full control
//! reconnect + re-home ([`ForceReconnect`] + [`ForceRehome`]). Every action is
//! in-process and preserves established SSH sessions.
//!
//! Ladder hygiene: the stall history is per-region — a fresh home region never
//! inherits the previous region's strikes — and repeated `FullReset`s without recovery
//! back off exponentially (up to 30 min) instead of churning control registration
//! every few minutes on a box whose only reachable relay is dead. The backoff
//! survives home-region flips (two dead regions alternating as home must not re-arm
//! it per flip); only a genuinely stall-free window resets it.
//!
//! ## Hysteresis
//!
//! After firing, the watchdog enters a cooldown (`T_COOLDOWN`, default 60s) before it
//! will fire again. This prevents spamming [`ForceReconnect`] every poll while
//! ControlRunner is mid-reconnect, while still retrying if the first attempt did not
//! recover the stream. The next [`StateUpdate`] resets the state to `Idle` immediately.

use std::{
    collections::VecDeque,
    sync::Arc,
    time::{Duration, Instant},
};

use kameo::{
    actor::ActorRef,
    message::{Context, Message},
};
use ts_derp::RegionId;

use crate::{
    Error,
    control_runner::ForceReconnect,
    derp_latency::{DerpLatencyMeasurer, ForceRehome, Remeasure},
    env::Env,
    multiderp::{RxStallConfig, RxStallEvent, jitter_seed, jittered},
};

/// Poll interval for the watchdog tick.
///
/// Kept short so detection latency is bounded by `POLL_INTERVAL + T_DETECT` worst case
/// (a drop happening the instant after a poll is only noticed at the next poll).
const POLL_INTERVAL: Duration = Duration::from_secs(30);

/// Default time without a [`StateUpdate`] after which the node is considered off-tailnet.
///
/// Raised from 120s to 180s (2026-07-18): field data shows normal relay handovers
/// (ord/dfw/den) produce 1–2 minute dips; 120s risked false-firing on those, and a
/// spurious control reconnect during a handover is churn we don't want on customer
/// boxes. 180s clears the worst observed normal dip with margin.
const DEFAULT_T_DETECT: Duration = Duration::from_secs(180);

/// Floor for the env-tunable `T_DETECT`: below two poll intervals, a single missed
/// poll could trigger a false fire on the next one.
const MIN_T_DETECT: Duration = Duration::from_secs(60);

/// Cooldown after a forced reconnect before another may fire.
///
/// Must be long enough that ControlRunner's reconnect attempt has a chance to either
/// succeed (in which case a [`StateUpdate`] arrives and resets the state) or fail
/// (in which case retrying is legitimate), and short enough that a stuck control plane
/// is retried promptly.
const T_COOLDOWN: Duration = Duration::from_secs(60);

/// Environment variable override for `T_DETECT` (in seconds).
const T_DETECT_ENV: &str = "TS_OFFNET_T_DETECT_SECS";

/// Default sliding window over which rx-stall events accumulate toward escalation.
///
/// Sized so consecutive stalls of one dead relay stay in-window: with the default
/// 180s stall threshold, stall #2 lands ~3–6 min after #1 and stall #3 ~6–10 min in;
/// 15 minutes comfortably holds the whole ladder while ageing out isolated one-offs.
/// Isolated stalls also age out naturally, which doubles as the "sustained recovery"
/// decay: a stall-free window resets the ladder to its bottom rung.
const DEFAULT_STALL_ESCALATION_WINDOW: Duration = Duration::from_secs(900);

/// Cap for the env-tunable stall window: anything above a day retains strikes so long
/// that unrelated stalls days apart would compound.
const MAX_STALL_WINDOW: Duration = Duration::from_secs(24 * 60 * 60);

/// Hard cap on retained stall instants (memory bound; an env-widened window must not
/// let the history grow without limit).
const STALL_HISTORY_CAP: usize = 64;

/// Environment variable override for the stall escalation window (in seconds).
const STALL_WINDOW_ENV: &str = "TS_OFFNET_STALL_WINDOW_SECS";

/// Number of consecutive control-stall [`ForceReconnect`] firings (without an
/// intervening [`StateUpdate`]) after which the watchdog additionally forces a
/// data-path re-home — the control-stall-not-fixed-by-reconnect escalation.
const CONTROL_FIRES_BEFORE_REHOME: u32 = 3;

/// Backoff applied after a `FullReset` actually fires: the *next* FullReset may only
/// fire this long after the previous one, doubling per firing up to
/// [`FULL_RESET_MAX_BACKOFF`]. Prevents a box whose only reachable relay is dead from
/// churning control registration every stall threshold (~3 min) forever.
const FULL_RESET_BASE_BACKOFF: Duration = Duration::from_secs(300);

/// Cap on the FullReset backoff (30 minutes).
const FULL_RESET_MAX_BACKOFF: Duration = Duration::from_secs(1800);

/// Self-message driving the periodic watchdog tick.
#[derive(Copy, Clone)]
struct Tick;

/// Parse a whole-seconds duration from the environment, falling back to `default` on
/// absence or any parse error and clamping to `floor` — always loudly (a silently
/// ignored override would invert the operator's intent).
pub(crate) fn duration_from_env_or(var: &str, default: Duration, floor: Duration) -> Duration {
    duration_from_parts(var, std::env::var(var).ok().as_deref(), default, floor)
}

/// Pure body of [`duration_from_env_or`] so parsing is unit-testable.
fn duration_from_parts(
    var: &str,
    raw: Option<&str>,
    default: Duration,
    floor: Duration,
) -> Duration {
    match raw.map(str::trim) {
        None => default,
        Some(raw) => match raw.parse::<u64>() {
            Ok(secs) => {
                let parsed = Duration::from_secs(secs);
                let clamped = parsed.max(floor);
                if clamped != parsed {
                    tracing::warn!(
                        env = var,
                        requested_secs = secs,
                        floor_secs = floor.as_secs(),
                        "duration below floor; clamping"
                    );
                }
                clamped
            }
            Err(_) => {
                tracing::warn!(
                    env = var,
                    value = raw,
                    default_secs = default.as_secs(),
                    "unparseable duration; using default"
                );
                default
            }
        },
    }
}

/// Resolve the stall escalation window: env-tunable, clamped to
/// `[3 × stall threshold, 24h]` so the full ladder (three stalls at threshold
/// cadence) always fits and strikes can't compound across days.
fn stall_window_from_parts(raw: Option<&str>, threshold_basis: Duration) -> Duration {
    let floor = threshold_basis.saturating_mul(3);
    let default = DEFAULT_STALL_ESCALATION_WINDOW.max(floor);
    let window = duration_from_parts(STALL_WINDOW_ENV, raw, default, floor);
    let capped = window.min(MAX_STALL_WINDOW);
    if capped != window {
        tracing::warn!(
            env = STALL_WINDOW_ENV,
            requested_secs = window.as_secs(),
            cap_secs = MAX_STALL_WINDOW.as_secs(),
            "stall window above cap; clamping"
        );
    }
    capped
}

/// Escalation ladder for repeated rx-stalls of the home relay, keyed by how many
/// stalls landed inside the sliding window (including the one being handled).
///
/// The stalled connection recycles itself locally (fresh socket + Noise) immediately
/// after publishing the event, so stage 1 only refreshes the latency picture.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum StallEscalation {
    /// First stall in the window: local recycle already underway; force a fresh
    /// netcheck so the latency picture is current if the stall repeats.
    Remeasure,
    /// Second stall: the relay is repeatedly one-way-dead — force a lateral re-home
    /// away from it, overriding anti-flap hysteresis and penalty-boxing the region.
    ForceRehome,
    /// Third and subsequent stalls: re-homing did not stick — additionally force a
    /// full control reconnect (fresh Noise + re-registration + fresh derp map), the
    /// strongest in-process reset that preserves SSH sessions. Subject to the
    /// [`FULL_RESET_BASE_BACKOFF`] schedule; while backed off, it degrades to the
    /// `ForceRehome` action (which still refreshes the penalty box).
    FullReset,
}

/// Pure ladder decision so it can be unit-tested in isolation.
fn decide_stall_escalation(stalls_in_window: usize) -> StallEscalation {
    match stalls_in_window {
        0 | 1 => StallEscalation::Remeasure,
        2 => StallEscalation::ForceRehome,
        _ => StallEscalation::FullReset,
    }
}

/// Prune stall instants older than `window` and return the in-window count.
/// Pure with respect to the supplied `now` so it can be unit-tested.
fn prune_and_count(stalls: &mut VecDeque<Instant>, now: Instant, window: Duration) -> usize {
    while let Some(front) = stalls.front() {
        if now.saturating_duration_since(*front) > window {
            stalls.pop_front();
        } else {
            break;
        }
    }
    stalls.len()
}

/// Whether repeated control-stall firings warrant a data-path re-home escalation.
/// Pure so it can be unit-tested.
fn control_stall_escalates(consecutive_fires: u32) -> bool {
    consecutive_fires >= CONTROL_FIRES_BEFORE_REHOME
}

#[derive(Copy, Clone, Debug)]
enum State {
    /// Operational — last [`StateUpdate`] is within `t_detect`.
    Idle,
    /// A [`ForceReconnect`] has been fired; waiting for either a fresh [`StateUpdate`]
    /// (success → back to `Idle`) or `T_COOLDOWN` to elapse (retry).
    Fired(Instant),
}

/// Pure decision function — no I/O, no clock reads beyond the supplied `now`.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum Action {
    /// Do nothing this tick.
    NoOp,
    /// Fire a [`ForceReconnect`] and transition to [`State::Fired`]`(now)`.
    Fire,
}

fn decide_action(since_update: Duration, t_detect: Duration, state: State, now: Instant) -> Action {
    match state {
        State::Idle => {
            if since_update >= t_detect {
                Action::Fire
            } else {
                Action::NoOp
            }
        }
        State::Fired(fired_at) => {
            // Only retry after cooldown. A StateUpdate arriving before then resets to Idle
            // via the StateUpdate handler, so reaching this branch with cooldown elapsed
            // means the previous ForceReconnect did not recover the stream — legitimate retry.
            if since_update >= t_detect && now.saturating_duration_since(fired_at) >= T_COOLDOWN {
                Action::Fire
            } else {
                Action::NoOp
            }
        }
    }
}

/// Recovery action the core asks the actor shell to perform. The shell maps these onto
/// registry tells; the core stays pure (injected time, no I/O) so the whole ladder is
/// unit-testable.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum Command {
    /// Tell [`DerpLatencyMeasurer`] to re-run netcheck now.
    Remeasure,
    /// Tell [`DerpLatencyMeasurer`] to force a re-home, penalty-boxing `avoid`.
    ForceRehome(Option<RegionId>),
    /// Tell ControlRunner to rebuild the control connection.
    ForceReconnect,
}

/// Exponential backoff gate for `FullReset` firings.
#[derive(Copy, Clone, Debug)]
struct FullResetBackoff {
    last_fired: Option<Instant>,
    backoff: Duration,
}

impl FullResetBackoff {
    const fn new() -> Self {
        Self {
            last_fired: None,
            backoff: Duration::ZERO,
        }
    }

    fn ready(&self, now: Instant) -> bool {
        match self.last_fired {
            None => true,
            Some(last) => now.saturating_duration_since(last) >= self.backoff,
        }
    }

    fn record_fire(&mut self, now: Instant) {
        self.last_fired = Some(now);
        self.backoff = if self.backoff.is_zero() {
            FULL_RESET_BASE_BACKOFF
        } else {
            self.backoff.saturating_mul(2).min(FULL_RESET_MAX_BACKOFF)
        };
    }

    fn reset(&mut self) {
        *self = Self::new();
    }
}

/// Functional core of the watchdog: all state transitions with injected time, no I/O.
struct WatchdogCore {
    /// When the most recent [`StateUpdate`] was observed.
    last_state_update: Instant,
    /// Configured detection threshold. Overridable via `TS_OFFNET_T_DETECT_SECS`.
    t_detect: Duration,
    /// Watchdog state machine.
    state: State,
    /// Instants of recent [`RxStallEvent`]s, pruned to `stall_window` and capped at
    /// [`STALL_HISTORY_CAP`]. The count of in-window stalls drives the ladder.
    rx_stalls: VecDeque<Instant>,
    /// Sliding window for stall accumulation. Overridable via `TS_OFFNET_STALL_WINDOW_SECS`.
    stall_window: Duration,
    /// Region of the most recent stall. A stall from a *different* region clears the
    /// history — a fresh home region must not inherit the previous region's strikes.
    last_stall_region: Option<RegionId>,
    /// When the most recent stall (any region) was observed. Drives the sustained-
    /// recovery reset of the FullReset backoff: only a genuinely stall-free window
    /// re-arms it — a region *flip* does not, so two dead regions alternating as home
    /// (A↔B ping-pong) cannot reset the backoff on every flip and churn control
    /// registration each cycle.
    last_stall_at: Option<Instant>,
    /// Consecutive control-stall `ForceReconnect` firings without an intervening
    /// [`StateUpdate`]. Drives the control-stall-not-fixed-by-reconnect escalation.
    consecutive_control_fires: u32,
    /// Backoff gate for repeated `FullReset`s without recovery.
    full_reset: FullResetBackoff,
}

impl WatchdogCore {
    fn new(t_detect: Duration, stall_window: Duration, now: Instant) -> Self {
        Self {
            // Initialise to "now" so we don't fire immediately on a slow startup; the first
            // real StateUpdate will refresh it, and if none ever arrives the watchdog will
            // still fire after t_detect.
            last_state_update: now,
            t_detect,
            state: State::Idle,
            rx_stalls: VecDeque::new(),
            stall_window,
            last_stall_region: None,
            last_stall_at: None,
            consecutive_control_fires: 0,
            full_reset: FullResetBackoff::new(),
        }
    }

    /// A [`StateUpdate`] was observed: the control stream is alive. Returns whether
    /// this is a recovery (state was not idle).
    fn on_state_update(&mut self, now: Instant) -> bool {
        self.last_state_update = now;
        let recovered = !matches!(self.state, State::Idle);
        self.state = State::Idle;
        self.consecutive_control_fires = 0;
        recovered
    }

    /// An rx-stall was reported for `region`. Returns the in-window stall count, the
    /// ladder stage, and the commands to execute.
    fn on_rx_stall(
        &mut self,
        region: RegionId,
        now: Instant,
    ) -> (usize, StallEscalation, Vec<Command>) {
        // Sustained recovery: a stall-free window (across ALL regions) restarts the
        // ladder — including the FullReset backoff — from the bottom.
        if self
            .last_stall_at
            .is_some_and(|last| now.saturating_duration_since(last) > self.stall_window)
        {
            self.full_reset.reset();
        }

        if self.last_stall_region.is_some_and(|prev| prev != region) {
            // Fresh home region: strikes restart from the bottom, so ForceRehome still
            // fires per new region. The FullReset backoff deliberately SURVIVES the
            // region change: with two dead regions the home flips A↔B on every forced
            // re-home, and a per-flip backoff reset would re-arm FullReset each cycle
            // (unbounded control churn while both relays stay dead).
            self.rx_stalls.clear();
        }
        self.last_stall_region = Some(region);
        self.last_stall_at = Some(now);

        prune_and_count(&mut self.rx_stalls, now, self.stall_window);
        self.rx_stalls.push_back(now);
        while self.rx_stalls.len() > STALL_HISTORY_CAP {
            self.rx_stalls.pop_front();
        }

        let stalls = self.rx_stalls.len();
        let escalation = decide_stall_escalation(stalls);
        let commands = match escalation {
            StallEscalation::Remeasure => vec![Command::Remeasure],
            StallEscalation::ForceRehome => vec![Command::ForceRehome(Some(region))],
            StallEscalation::FullReset => {
                if self.full_reset.ready(now) {
                    self.full_reset.record_fire(now);
                    vec![Command::ForceReconnect, Command::ForceRehome(Some(region))]
                } else {
                    // Backed off: skip the control churn, but keep refreshing the
                    // penalty box so the re-home away from the dead relay sticks.
                    vec![Command::ForceRehome(Some(region))]
                }
            }
        };
        (stalls, escalation, commands)
    }

    /// Periodic tick. Returns the commands to execute.
    fn on_tick(&mut self, now: Instant) -> Vec<Command> {
        let since_update = now.saturating_duration_since(self.last_state_update);
        match decide_action(since_update, self.t_detect, self.state, now) {
            Action::NoOp => Vec::new(),
            Action::Fire => {
                self.consecutive_control_fires = self.consecutive_control_fires.saturating_add(1);
                self.state = State::Fired(now);
                let mut commands = vec![Command::ForceReconnect];
                // Control-stall not fixed by reconnect: after repeated firings without a
                // single StateUpdate landing, the problem is likely the data path rather
                // than (or in addition to) the control stream — force a re-home too so
                // fresh relay connections and fresh netcheck data get a chance.
                if control_stall_escalates(self.consecutive_control_fires) {
                    commands.push(Command::ForceRehome(None));
                }
                commands
            }
        }
    }

    fn since_update(&self, now: Instant) -> Duration {
        now.saturating_duration_since(self.last_state_update)
    }
}

/// Off-tailnet watchdog actor — thin shell around [`WatchdogCore`].
///
/// Spawned by [`crate::control_runner::ControlRunner::on_start`] alongside
/// [`crate::derp_latency::DerpLatencyMeasurer`]. Subscribes to
/// `Arc<ts_control::StateUpdate>` and [`RxStallEvent`] on the bus.
pub struct OffTailnetWatchdog {
    env: Env,
    core: WatchdogCore,
}

impl OffTailnetWatchdog {
    /// Best-effort tell to the canonical [`DerpLatencyMeasurer`]; errors are logged,
    /// never propagated — the watchdog must survive any bus/registry failure.
    async fn tell_latency_measurer<M>(&self, msg: M)
    where
        DerpLatencyMeasurer: Message<M>,
        M: Send + 'static,
    {
        if let Err(e) = self.env.tell::<DerpLatencyMeasurer, _>(None, msg).await {
            tracing::error!(error = %e, "sending message to DerpLatencyMeasurer");
        }
    }

    /// Best-effort [`ForceReconnect`] to the canonical ControlRunner.
    async fn tell_force_reconnect(&self) {
        if let Err(e) = self
            .env
            .tell::<crate::control_runner::ControlRunner, _>(None, ForceReconnect)
            .await
        {
            tracing::error!(error = %e, "sending ForceReconnect to ControlRunner");
        }
    }

    /// Execute a core-issued recovery command (best-effort, never propagates).
    async fn run_command(&self, command: Command) {
        match command {
            Command::Remeasure => self.tell_latency_measurer(Remeasure).await,
            Command::ForceRehome(avoid) => self.tell_latency_measurer(ForceRehome { avoid }).await,
            Command::ForceReconnect => self.tell_force_reconnect().await,
        }
    }
}

impl kameo::Actor for OffTailnetWatchdog {
    type Args = Env;
    type Error = Error;

    async fn on_start(env: Env, slf: ActorRef<Self>) -> Result<Self, Self::Error> {
        env.subscribe::<Arc<ts_control::StateUpdate>>(&slf).await?;
        env.subscribe::<RxStallEvent>(&slf).await?;
        env.register(None, &slf).await?;

        env.scheduler
            .tell(kameo_actors::scheduler::SetInterval::new(
                slf.downgrade(),
                POLL_INTERVAL,
                Tick,
            ))
            .await?;

        // Deterministic per-node jitter (+0–20%) so the two koidra-ssh processes on
        // one box never fire their control-reconnect ladders in lockstep.
        let seed = jitter_seed(&env.keys.node_keys.public);
        let t_detect = jittered(
            duration_from_env_or(T_DETECT_ENV, DEFAULT_T_DETECT, MIN_T_DETECT),
            seed,
        );
        let threshold_basis = RxStallConfig::from_env()
            .stall_threshold
            .unwrap_or(RxStallConfig::DEFAULT_STALL_THRESHOLD);
        let stall_window = stall_window_from_parts(
            std::env::var(STALL_WINDOW_ENV).ok().as_deref(),
            threshold_basis,
        );

        tracing::trace!(
            t_detect_secs = t_detect.as_secs(),
            stall_window_secs = stall_window.as_secs(),
            "off-tailnet watchdog running"
        );

        Ok(Self {
            env,
            core: WatchdogCore::new(t_detect, stall_window, Instant::now()),
        })
    }
}

impl Message<Arc<ts_control::StateUpdate>> for OffTailnetWatchdog {
    type Reply = ();

    async fn handle(
        &mut self,
        _msg: Arc<ts_control::StateUpdate>,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        // Any StateUpdate on the bus is proof of a live control stream. Refresh + reset.
        if self.core.on_state_update(Instant::now()) {
            tracing::info!("control stream recovered; returning to idle");
        }
    }
}

impl Message<RxStallEvent> for OffTailnetWatchdog {
    type Reply = ();

    async fn handle(
        &mut self,
        msg: RxStallEvent,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        let (stalls, escalation, commands) = self.core.on_rx_stall(msg.region_id, Instant::now());

        tracing::warn!(
            region_id = %msg.region_id,
            stalled_secs = msg.stalled_for.as_secs(),
            pkts_sent_since_recv = msg.pkts_sent_since_recv,
            stalls_in_window = stalls,
            ?escalation,
            "home derp rx-stall reported; escalating"
        );

        // Every stage is a best-effort in-process action; the connection itself
        // recycles locally (fresh socket + Noise) right after publishing the event.
        for command in commands {
            self.run_command(command).await;
        }
    }
}

impl Message<Tick> for OffTailnetWatchdog {
    type Reply = ();

    async fn handle(&mut self, _: Tick, _ctx: &mut Context<Self, Self::Reply>) -> Self::Reply {
        let now = Instant::now();
        let commands = self.core.on_tick(now);

        if commands.is_empty() {
            tracing::trace!(
                since_update_secs = self.core.since_update(now).as_secs(),
                state = ?self.core.state,
                "watchdog tick; no action"
            );
        } else {
            tracing::warn!(
                since_update_secs = self.core.since_update(now).as_secs(),
                t_detect_secs = self.core.t_detect.as_secs(),
                consecutive_fires = self.core.consecutive_control_fires,
                "off-tailnet detected (no StateUpdate within threshold); forcing control reconnect"
            );
        }

        for command in commands {
            self.run_command(command).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{
        collections::VecDeque,
        num::NonZeroU32,
        time::{Duration, Instant},
    };

    use ts_derp::RegionId;

    use super::{
        Action, CONTROL_FIRES_BEFORE_REHOME, Command, DEFAULT_STALL_ESCALATION_WINDOW,
        FULL_RESET_BASE_BACKOFF, FULL_RESET_MAX_BACKOFF, MAX_STALL_WINDOW, STALL_HISTORY_CAP,
        StallEscalation, State, T_COOLDOWN, WatchdogCore, control_stall_escalates, decide_action,
        decide_stall_escalation, duration_from_parts, prune_and_count, stall_window_from_parts,
    };

    fn now() -> Instant {
        // Stable reference; arithmetic via checked_add so tests are deterministic.
        Instant::now()
    }

    fn r(n: u32) -> RegionId {
        RegionId(NonZeroU32::new(n).unwrap())
    }

    fn secs(n: u64) -> Duration {
        Duration::from_secs(n)
    }

    fn core(t_detect: Duration, window: Duration, t0: Instant) -> WatchdogCore {
        WatchdogCore::new(t_detect, window, t0)
    }

    #[test]
    fn idle_under_threshold_does_not_fire() {
        let t = now();
        assert_eq!(
            decide_action(
                Duration::from_secs(30),
                Duration::from_secs(120),
                State::Idle,
                t
            ),
            Action::NoOp
        );
    }

    #[test]
    fn idle_at_threshold_fires() {
        let t = now();
        assert_eq!(
            decide_action(
                Duration::from_secs(120),
                Duration::from_secs(120),
                State::Idle,
                t
            ),
            Action::Fire
        );
    }

    #[test]
    fn idle_over_threshold_fires() {
        let t = now();
        assert_eq!(
            decide_action(
                Duration::from_secs(300),
                Duration::from_secs(120),
                State::Idle,
                t
            ),
            Action::Fire
        );
    }

    #[test]
    fn fired_within_cooldown_does_not_refire() {
        let t = now();
        // Was fired 10s ago — cooldown is 60s, so no refire yet even though we are still
        // past the detection threshold.
        let fired_at = t - Duration::from_secs(10);
        assert_eq!(
            decide_action(
                Duration::from_secs(300),
                Duration::from_secs(120),
                State::Fired(fired_at),
                t
            ),
            Action::NoOp
        );
    }

    #[test]
    fn fired_after_cooldown_refires() {
        let t = now();
        let fired_at = t - T_COOLDOWN - Duration::from_secs(1);
        assert_eq!(
            decide_action(
                Duration::from_secs(300),
                Duration::from_secs(120),
                State::Fired(fired_at),
                t
            ),
            Action::Fire
        );
    }

    #[test]
    fn fired_just_under_cooldown_does_not_refire() {
        let t = now();
        let fired_at = t - (T_COOLDOWN - Duration::from_secs(1));
        assert_eq!(
            decide_action(
                Duration::from_secs(300),
                Duration::from_secs(120),
                State::Fired(fired_at),
                t
            ),
            Action::NoOp
        );
    }

    #[test]
    fn fired_recovered_within_cooldown_by_lower_since_update_is_noop() {
        // This case shouldn't normally happen because a StateUpdate resets state to Idle
        // before the next tick; but if it did, the cooldown gate still protects against
        // spam. Here since_update is small (recovered), so no fire regardless of cooldown.
        let t = now();
        let fired_at = t - Duration::from_secs(120);
        assert_eq!(
            decide_action(
                Duration::from_secs(10),
                Duration::from_secs(120),
                State::Fired(fired_at),
                t
            ),
            Action::NoOp
        );
    }

    #[test]
    fn threshold_boundary_strictly_geq() {
        // 119s against 120s threshold -> NoOp (strict less-than is safe).
        let t = now();
        assert_eq!(
            decide_action(
                Duration::from_secs(119),
                Duration::from_secs(120),
                State::Idle,
                t
            ),
            Action::NoOp
        );
        // 120s exactly -> Fire.
        assert_eq!(
            decide_action(
                Duration::from_secs(120),
                Duration::from_secs(120),
                State::Idle,
                t
            ),
            Action::Fire
        );
    }

    #[test]
    fn cooldown_is_long_enough_to_let_reconnect_succeed() {
        // Cooldown must exceed a reasonable reconnect latency, otherwise the watchdog
        // would fire again before the previous attempt finished.
        assert!(T_COOLDOWN >= Duration::from_secs(30));
    }

    #[test]
    fn default_t_detect_is_conservative() {
        // The default detection threshold must be comfortably longer than the poll interval,
        // otherwise a single missed poll could trigger a false fire on the next one.
        assert!(super::DEFAULT_T_DETECT > super::POLL_INTERVAL * 2);
        // And the env floor preserves the same property.
        assert!(super::MIN_T_DETECT >= super::POLL_INTERVAL * 2);
    }

    #[test]
    fn default_t_detect_tolerates_normal_relay_handover_dips() {
        // Field data: normal ord/dfw/den relay handovers show 1–2 minute dips. The
        // control-stall threshold must ride those out (no false ForceReconnect).
        assert!(super::DEFAULT_T_DETECT >= Duration::from_secs(180));
    }

    // ---- rx-stall escalation ladder ----

    #[test]
    fn stall_escalation_ladder_maps_counts_to_stages() {
        assert_eq!(decide_stall_escalation(0), StallEscalation::Remeasure);
        assert_eq!(decide_stall_escalation(1), StallEscalation::Remeasure);
        assert_eq!(decide_stall_escalation(2), StallEscalation::ForceRehome);
        assert_eq!(decide_stall_escalation(3), StallEscalation::FullReset);
        assert_eq!(decide_stall_escalation(10), StallEscalation::FullReset);
    }

    #[test]
    fn stall_window_prunes_old_events() {
        let t0 = Instant::now();
        let window = Duration::from_secs(900);
        let mut stalls: VecDeque<Instant> = VecDeque::new();

        stalls.push_back(t0);
        stalls.push_back(t0 + Duration::from_secs(400));
        assert_eq!(
            prune_and_count(&mut stalls, t0 + Duration::from_secs(500), window),
            2
        );

        // The first stall ages out of the window; the second remains.
        assert_eq!(
            prune_and_count(&mut stalls, t0 + Duration::from_secs(1000), window),
            1
        );
        // Everything aged out.
        assert_eq!(
            prune_and_count(&mut stalls, t0 + Duration::from_secs(2000), window),
            0
        );
    }

    #[test]
    fn stall_window_prune_boundary_keeps_event_at_exactly_window_age() {
        // Boundary semantics: an event aged exactly `window` is still in-window
        // (prune uses strict `>`), one second past it is out.
        let t0 = Instant::now();
        let window = Duration::from_secs(900);
        let mut stalls: VecDeque<Instant> = VecDeque::new();
        stalls.push_back(t0);
        assert_eq!(prune_and_count(&mut stalls, t0 + window, window), 1);
        assert_eq!(
            prune_and_count(&mut stalls, t0 + window + secs(1), window),
            0
        );
    }

    #[test]
    fn isolated_stalls_never_escalate_past_remeasure() {
        // One stall per >window interval — e.g. genuinely rare blips — must always
        // stay at stage 1, never accumulate to a forced re-home.
        let t0 = Instant::now();
        let window = DEFAULT_STALL_ESCALATION_WINDOW;
        let mut c = core(secs(180), window, t0);

        for i in 0..5u64 {
            let now = t0 + (window + Duration::from_secs(60)) * (i as u32 + 1);
            let (_, escalation, commands) = c.on_rx_stall(r(1), now);
            assert_eq!(escalation, StallEscalation::Remeasure);
            assert_eq!(commands, vec![Command::Remeasure]);
        }
    }

    #[test]
    fn repeated_stalls_of_dead_relay_walk_the_full_ladder() {
        // Behavior harness (escalation side of the cross-region timeline): the home
        // relay is one-way-dead, so the connection recycles + re-stalls roughly every
        // stall-threshold. The watchdog must walk Remeasure → ForceRehome → FullReset,
        // with the re-home stages penalty-boxing the dead region.
        let t0 = Instant::now();
        let mut c = core(secs(180), DEFAULT_STALL_ESCALATION_WINDOW, t0);
        let region = r(7);

        let (_, s1, cmd1) = c.on_rx_stall(region, t0 + secs(180));
        let (_, s2, cmd2) = c.on_rx_stall(region, t0 + secs(360));
        let (_, s3, cmd3) = c.on_rx_stall(region, t0 + secs(540));

        assert_eq!(
            (s1, s2, s3),
            (
                StallEscalation::Remeasure,
                StallEscalation::ForceRehome,
                StallEscalation::FullReset,
            )
        );
        assert_eq!(cmd1, vec![Command::Remeasure]);
        assert_eq!(cmd2, vec![Command::ForceRehome(Some(region))]);
        assert_eq!(
            cmd3,
            vec![Command::ForceReconnect, Command::ForceRehome(Some(region))]
        );
    }

    #[test]
    fn stall_history_from_previous_region_is_cleared_on_region_change() {
        // Two strikes on region A, then the home moves and region B stalls: B must
        // start at the bottom of the ladder, not inherit A's count.
        let t0 = Instant::now();
        let mut c = core(secs(180), DEFAULT_STALL_ESCALATION_WINDOW, t0);
        c.on_rx_stall(r(1), t0 + secs(180));
        c.on_rx_stall(r(1), t0 + secs(360));

        let (stalls, escalation, commands) = c.on_rx_stall(r(2), t0 + secs(540));
        assert_eq!(stalls, 1);
        assert_eq!(escalation, StallEscalation::Remeasure);
        assert_eq!(commands, vec![Command::Remeasure]);
    }

    #[test]
    fn full_reset_backs_off_exponentially_on_a_dead_only_relay() {
        // Single-reachable-region box with a dead relay: stalls arrive every ~180s
        // forever. FullReset must not fire every stall — after the first, subsequent
        // ones are gated by the exponential backoff and degrade to penalty-box
        // refreshes (ForceRehome) instead of control churn.
        let t0 = Instant::now();
        let mut c = core(secs(180), DEFAULT_STALL_ESCALATION_WINDOW, t0);
        let region = r(1);

        let mut reconnects = Vec::new();
        for i in 1..=20u64 {
            let now = t0 + secs(180 * i);
            let (_, _, commands) = c.on_rx_stall(region, now);
            if commands.contains(&Command::ForceReconnect) {
                reconnects.push(180 * i);
            }
            // Every FullReset-stage stall still refreshes the penalty box.
            if i >= 2 {
                assert!(commands.contains(&Command::ForceRehome(Some(region))) || i == 2);
            }
        }

        // First FullReset at stall #3 (540s). Next allowed >= 540+300 => stall at 900s.
        // Then backoff 600 => next >= 1500 => stall at 1620s. Then 1200 => >= 2820 =>
        // stall at 2880s. Then 1800 (capped).
        assert_eq!(reconnects, vec![540, 900, 1620, 2880]);
    }

    #[test]
    fn full_reset_backoff_resets_after_a_quiet_window() {
        // A stall-free window (sustained recovery) restarts the ladder AND the
        // FullReset backoff.
        let t0 = Instant::now();
        let window = DEFAULT_STALL_ESCALATION_WINDOW;
        let mut c = core(secs(180), window, t0);
        let region = r(1);

        // Walk to FullReset once.
        c.on_rx_stall(region, t0 + secs(180));
        c.on_rx_stall(region, t0 + secs(360));
        let (_, _, cmd) = c.on_rx_stall(region, t0 + secs(540));
        assert!(cmd.contains(&Command::ForceReconnect));

        // Quiet for > window, then a fresh incident: ladder starts at Remeasure.
        let t1 = t0 + secs(540) + window + secs(60);
        let (stalls, escalation, _) = c.on_rx_stall(region, t1);
        assert_eq!((stalls, escalation), (1, StallEscalation::Remeasure));

        // And when it walks back up to FullReset, the backoff gate is fresh (fires
        // immediately again rather than being stuck at a doubled interval).
        c.on_rx_stall(region, t1 + secs(180));
        let (_, _, cmd) = c.on_rx_stall(region, t1 + secs(360));
        assert!(cmd.contains(&Command::ForceReconnect));
    }

    /// The two-dead-region flip cycle (A↔B, both one-way-dead, ~180s stall cadence):
    /// each flip clears the strike history — so the ladder still walks Remeasure →
    /// ForceRehome → FullReset per region — but the FullReset backoff must SURVIVE
    /// the flips. Resetting it per region change (the old behavior) re-armed
    /// FullReset every cycle, i.e. unbounded control churn while both relays stay
    /// dead, and made the exponential schedule unreachable.
    #[test]
    fn full_reset_backoff_survives_dead_region_flip_cycle() {
        let t0 = Instant::now();
        let mut c = core(secs(180), DEFAULT_STALL_ESCALATION_WINDOW, t0);
        let (a, b) = (r(1), r(2));

        // Stall sequence: three per region, home flipping A→B→A on each ForceRehome.
        let script: &[(u64, RegionId)] = &[
            (180, a),
            (360, a),
            (540, a), // FullReset #1 fires; backoff 300s armed
            (720, b),
            (900, b),
            (1080, b), // ladder reaches FullReset again ACROSS the flip; 540s ≥ 300s → fires
            (1260, a),
            (1440, a),
            (1620, a), // FullReset stage, but 540s < 600s backoff → degrades
            (1800, a), // 720s ≥ 600s → fires
        ];

        let mut reconnects = Vec::new();
        let mut degraded_at = Vec::new();
        for &(t, region) in script {
            let (_, escalation, commands) = c.on_rx_stall(region, t0 + secs(t));
            if commands.contains(&Command::ForceReconnect) {
                reconnects.push(t);
            } else if escalation == StallEscalation::FullReset {
                // Backed off: still refreshes the penalty box, never touches control.
                assert_eq!(commands, vec![Command::ForceRehome(Some(region))]);
                degraded_at.push(t);
            }
        }

        assert_eq!(reconnects, vec![540, 1080, 1800]);
        assert_eq!(degraded_at, vec![1620]);
    }

    #[test]
    fn stall_history_is_capped() {
        let t0 = Instant::now();
        // Absurdly wide window so nothing prunes by age.
        let mut c = core(secs(180), MAX_STALL_WINDOW, t0);
        for i in 0..(STALL_HISTORY_CAP as u64 + 40) {
            c.on_rx_stall(r(1), t0 + secs(i));
        }
        assert!(c.rx_stalls.len() <= STALL_HISTORY_CAP);
    }

    // ---- control-stall-not-fixed-by-reconnect escalation (T-F5 via the core) ----

    #[test]
    fn control_stall_escalates_only_after_repeated_failed_reconnects() {
        assert!(!control_stall_escalates(0));
        assert!(!control_stall_escalates(1));
        assert!(!control_stall_escalates(2));
        assert!(control_stall_escalates(CONTROL_FIRES_BEFORE_REHOME));
        assert!(control_stall_escalates(CONTROL_FIRES_BEFORE_REHOME + 5));
    }

    #[test]
    fn consecutive_control_fires_reset_by_state_update_between_ticks() {
        // Fire twice (cooldown-spaced), then a StateUpdate lands, then the stream
        // stalls again: the re-home escalation counter must have restarted — the
        // third and fourth fires stay plain ForceReconnects.
        let t0 = Instant::now();
        let t_detect = secs(180);
        let mut c = core(t_detect, DEFAULT_STALL_ESCALATION_WINDOW, t0);

        let cmds1 = c.on_tick(t0 + secs(180));
        assert_eq!(cmds1, vec![Command::ForceReconnect]);
        let cmds2 = c.on_tick(t0 + secs(180) + T_COOLDOWN);
        assert_eq!(cmds2, vec![Command::ForceReconnect]);

        // Control recovers briefly.
        assert!(c.on_state_update(t0 + secs(300)));

        // Stalls again: fires 1 and 2 of the *new* streak — no re-home command.
        let t1 = t0 + secs(300);
        assert_eq!(c.on_tick(t1 + t_detect), vec![Command::ForceReconnect]);
        assert_eq!(
            c.on_tick(t1 + t_detect + T_COOLDOWN),
            vec![Command::ForceReconnect]
        );
        // Third consecutive fire without recovery: now the re-home escalation joins.
        assert_eq!(
            c.on_tick(t1 + t_detect + T_COOLDOWN * 2),
            vec![Command::ForceReconnect, Command::ForceRehome(None)]
        );
    }

    #[test]
    fn stall_window_holds_the_whole_ladder_at_default_cadence() {
        // With the default 180s stall threshold, three consecutive stalls span ~540s;
        // the escalation window must keep all three in scope or FullReset is unreachable.
        assert!(DEFAULT_STALL_ESCALATION_WINDOW >= Duration::from_secs(3 * 180));
    }

    #[test]
    fn full_reset_backoff_bounds_are_sane() {
        assert!(FULL_RESET_BASE_BACKOFF >= secs(180));
        assert!(FULL_RESET_MAX_BACKOFF <= secs(1800));
        assert!(FULL_RESET_BASE_BACKOFF < FULL_RESET_MAX_BACKOFF);
    }

    // ---- env parsing: floors, caps, loud fallbacks (T-F4) ----

    #[test]
    fn duration_from_parts_parses_clamps_and_falls_back() {
        let default = secs(180);
        let floor = secs(60);
        let cases: &[(Option<&str>, Duration)] = &[
            (None, default),
            (Some("240"), secs(240)),
            (Some(" 240 "), secs(240)),
            (Some("60"), secs(60)),
            (Some("59"), floor), // below floor -> clamped
            (Some("0"), floor),  // zero -> clamped, never "instant fire"
            (Some(""), default), // garbage -> default
            (Some("abc"), default),
            (Some("-5"), default),
            (Some("1.5"), default),
            (Some("9999999999999999999999"), default), // overflow -> default
        ];
        for (raw, expected) in cases {
            assert_eq!(
                duration_from_parts("TEST_VAR", *raw, default, floor),
                *expected,
                "{raw:?}"
            );
        }
    }

    #[test]
    fn stall_window_clamps_to_ladder_floor_and_day_cap() {
        let threshold = secs(180);
        // Default basis.
        assert_eq!(
            stall_window_from_parts(None, threshold),
            DEFAULT_STALL_ESCALATION_WINDOW
        );
        // Below 3x threshold -> floored so the full ladder always fits.
        assert_eq!(stall_window_from_parts(Some("60"), threshold), secs(540));
        // Above a day -> capped.
        assert_eq!(
            stall_window_from_parts(Some("999999"), threshold),
            MAX_STALL_WINDOW
        );
        // A larger configured threshold raises the floor (and the default with it).
        assert_eq!(stall_window_from_parts(None, secs(600)), secs(1800));
    }
}

#[cfg(test)]
mod e2e_tests {
    //! End-to-end actor test: real [`Env`] (bus + registry + scheduler), real
    //! [`DerpLatencyMeasurer`], real [`OffTailnetWatchdog`] — a wiring bug (wrong
    //! event type, subscribe-after-publish, actor not spawned, registry-tell to the
    //! wrong name) must fail here even when every pure test passes.

    use std::{num::NonZeroU32, sync::Arc, time::Duration};

    use kameo::actor::Spawn as _;
    use tokio::sync::mpsc;
    use ts_derp::RegionId;

    use crate::{
        derp_latency::{DerpLatencyMeasurement, DerpLatencyMeasurer},
        env::Env,
        multiderp::RxStallEvent,
        offtailnet_watchdog::OffTailnetWatchdog,
    };

    /// Probe actor observing every published [`DerpLatencyMeasurement`].
    struct MeasurementProbe {
        tx: mpsc::UnboundedSender<DerpLatencyMeasurement>,
    }

    impl kameo::Actor for MeasurementProbe {
        type Args = (Env, mpsc::UnboundedSender<DerpLatencyMeasurement>);
        type Error = crate::Error;

        async fn on_start(
            (env, tx): Self::Args,
            slf: kameo::actor::ActorRef<Self>,
        ) -> Result<Self, Self::Error> {
            env.subscribe::<DerpLatencyMeasurement>(&slf).await?;
            env.register(None, &slf).await?;
            Ok(Self { tx })
        }
    }

    impl kameo::message::Message<DerpLatencyMeasurement> for MeasurementProbe {
        type Reply = ();

        async fn handle(
            &mut self,
            msg: DerpLatencyMeasurement,
            _: &mut kameo::message::Context<Self, Self::Reply>,
        ) {
            drop(self.tx.send(msg));
        }
    }

    fn empty_state_update() -> Arc<ts_control::StateUpdate> {
        Arc::new(ts_control::StateUpdate {
            // Empty derp map: `measure_derp_map` runs with zero probes (no network),
            // returns an empty measurement, and the measurer publishes it.
            derp: Some(ts_control::DerpMap::new()),
            node: None,
            peer_update: None,
            ping: None,
            packetfilter: None,
            pop_browser_url: None,
            dial_plan: None,
        })
    }

    async fn next_measurement(
        rx: &mut mpsc::UnboundedReceiver<DerpLatencyMeasurement>,
        env: &Env,
    ) -> DerpLatencyMeasurement {
        match tokio::time::timeout(Duration::from_secs(10), rx.recv()).await {
            Ok(m) => m.expect("probe alive"),
            Err(_) => panic!(
                "no measurement within timeout (registry alive={}, bus alive={})",
                env.registry.is_alive(),
                env.bus.is_alive()
            ),
        }
    }

    #[tokio::test]
    async fn rx_stall_ladder_drives_rehome_through_real_bus_and_registry() {
        let env = Env::new(ts_keys::NodeState::generate());

        let measurer = DerpLatencyMeasurer::spawn(env.clone());
        let watchdog = OffTailnetWatchdog::spawn(env.clone());
        let (tx, mut rx) = mpsc::unbounded_channel();
        let _probe = MeasurementProbe::spawn((env.clone(), tx));

        // All three register at the end of their on_start; waiting on the registry
        // guarantees their bus subscriptions are in place before we publish.
        env.wait::<DerpLatencyMeasurer>(None).await.unwrap();
        env.wait::<OffTailnetWatchdog>(None).await.unwrap();
        env.wait::<MeasurementProbe>(None).await.unwrap();

        // Control delivers a (derp-empty) map: measurement #1.
        env.publish(empty_state_update()).await.unwrap();
        let m1 = next_measurement(&mut rx, &env).await;
        assert!(m1.measurement.is_empty());

        let region = RegionId(NonZeroU32::new(1).unwrap());
        let stall = |n: u64| RxStallEvent {
            region_id: region,
            stalled_for: Duration::from_secs(180 * n),
            pkts_sent_since_recv: 0,
        };

        // Stall #1 → watchdog Remeasure → measurer publishes measurement #2.
        env.publish_noretain(stall(1)).await.unwrap();
        next_measurement(&mut rx, &env).await;

        // Stall #2 → watchdog ForceRehome{avoid} → measurer publishes measurement #3.
        env.publish_noretain(stall(2)).await.unwrap();
        next_measurement(&mut rx, &env).await;

        // A StateUpdate interleaved between escalations must not disturb the ladder
        // (and resets the control-fire streak): measurement #4 from the map delivery.
        env.publish(empty_state_update()).await.unwrap();
        next_measurement(&mut rx, &env).await;

        // Stall #3 → FullReset: ForceReconnect targets a ControlRunner that is NOT
        // spawned — the watchdog must survive the failed registry tell (crash-proof)
        // and still deliver the ForceRehome: measurement #5.
        env.publish_noretain(stall(3)).await.unwrap();
        next_measurement(&mut rx, &env).await;

        assert!(watchdog.is_alive(), "watchdog survived the full ladder");
        assert!(measurer.is_alive(), "measurer survived the full ladder");
        // Regression guard: the misaddressed ForceReconnect tell (no ControlRunner)
        // once killed the Registry actor via kameo's unhandled-error handling,
        // silently dropping every queued forward. The registry must survive it.
        assert!(
            env.registry.is_alive(),
            "registry survived a NotFound forward"
        );
    }
}
