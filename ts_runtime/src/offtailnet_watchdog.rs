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
//! derp task when its connection is one-way-dead (tx advancing, rx silent past
//! `TS_OFFNET_RX_STALL_SECS`). Repeated stalls walk an escalation ladder:
//! re-netcheck ([`Remeasure`]) → forced lateral re-home overriding anti-flap
//! hysteresis ([`ForceRehome`]) → full control reconnect + re-home
//! ([`ForceReconnect`] + [`ForceRehome`]). Every action is in-process and preserves
//! established SSH sessions.
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

use crate::{
    Error,
    control_runner::ForceReconnect,
    derp_latency::{DerpLatencyMeasurer, ForceRehome, Remeasure},
    env::Env,
    multiderp::RxStallEvent,
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
const DEFAULT_STALL_ESCALATION_WINDOW: Duration = Duration::from_secs(900);

/// Environment variable override for the stall escalation window (in seconds).
const STALL_WINDOW_ENV: &str = "TS_OFFNET_STALL_WINDOW_SECS";

/// Number of consecutive control-stall [`ForceReconnect`] firings (without an
/// intervening [`StateUpdate`]) after which the watchdog additionally forces a
/// data-path re-home — the control-stall-not-fixed-by-reconnect escalation.
const CONTROL_FIRES_BEFORE_REHOME: u32 = 3;

/// Self-message driving the periodic watchdog tick.
#[derive(Copy, Clone)]
struct Tick;

/// Off-tailnet watchdog actor.
///
/// Spawned by [`crate::control_runner::ControlRunner::on_start`] alongside
/// [`crate::derp_latency::DerpLatencyMeasurer`]. Subscribes to
/// `Arc<ts_control::StateUpdate>` on the bus.
pub struct OffTailnetWatchdog {
    env: Env,
    /// When the most recent [`StateUpdate`] was observed.
    last_state_update: Instant,
    /// Configured detection threshold. Overridable via `TS_OFFNET_T_DETECT_SECS`.
    t_detect: Duration,
    /// Watchdog state machine.
    state: State,
    /// Instants of recent [`RxStallEvent`]s, pruned to `stall_window`. The count of
    /// in-window stalls drives the escalation ladder.
    rx_stalls: VecDeque<Instant>,
    /// Sliding window for stall accumulation. Overridable via `TS_OFFNET_STALL_WINDOW_SECS`.
    stall_window: Duration,
    /// Consecutive control-stall `ForceReconnect` firings without an intervening
    /// [`StateUpdate`]. Drives the control-stall-not-fixed-by-reconnect escalation.
    consecutive_control_fires: u32,
}

/// Escalation ladder for repeated rx-stalls of the home relay, keyed by how many
/// stalls landed inside the sliding window (including the one being handled).
///
/// The stalled connection has already recycled itself locally (fresh socket + Noise)
/// before the event reaches the watchdog, so stage 1 only refreshes the latency picture.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum StallEscalation {
    /// First stall in the window: local recycle already happened; force a fresh
    /// netcheck so the latency picture is current if the stall repeats.
    Remeasure,
    /// Second stall: the relay is repeatedly one-way-dead — force a lateral re-home
    /// away from it, overriding anti-flap hysteresis.
    ForceRehome,
    /// Third and subsequent stalls: re-homing did not stick — additionally force a
    /// full control reconnect (fresh Noise + re-registration + fresh derp map), the
    /// strongest in-process reset that preserves SSH sessions.
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

impl OffTailnetWatchdog {
    fn t_detect_from_env_or_default() -> Duration {
        duration_from_env_or(T_DETECT_ENV, DEFAULT_T_DETECT)
    }

    fn stall_window_from_env_or_default() -> Duration {
        duration_from_env_or(STALL_WINDOW_ENV, DEFAULT_STALL_ESCALATION_WINDOW)
    }

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
}

/// Parse a whole-seconds duration from the environment, falling back to `default` on
/// absence or any parse error (unknown-on-error).
fn duration_from_env_or(var: &str, default: Duration) -> Duration {
    std::env::var(var)
        .ok()
        .and_then(|v| v.trim().parse().ok())
        .map(Duration::from_secs)
        .unwrap_or(default)
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

        tracing::trace!(
            t_detect_secs = Self::t_detect_from_env_or_default().as_secs(),
            "off-tailnet watchdog running"
        );

        Ok(Self {
            env,
            // Initialise to "now" so we don't fire immediately on a slow startup; the first
            // real StateUpdate will refresh it, and if none ever arrives the watchdog will
            // still fire after t_detect.
            last_state_update: Instant::now(),
            t_detect: Self::t_detect_from_env_or_default(),
            state: State::Idle,
            rx_stalls: VecDeque::new(),
            stall_window: Self::stall_window_from_env_or_default(),
            consecutive_control_fires: 0,
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
        self.last_state_update = Instant::now();
        if !matches!(self.state, State::Idle) {
            tracing::info!("control stream recovered; returning to idle");
        }
        self.state = State::Idle;
        self.consecutive_control_fires = 0;
    }
}

impl Message<RxStallEvent> for OffTailnetWatchdog {
    type Reply = ();

    async fn handle(
        &mut self,
        msg: RxStallEvent,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        let now = Instant::now();
        self.rx_stalls.push_back(now);
        let stalls = prune_and_count(&mut self.rx_stalls, now, self.stall_window);
        let escalation = decide_stall_escalation(stalls);

        tracing::warn!(
            region_id = %msg.region_id,
            stalled_secs = msg.stalled_for.as_secs(),
            pkts_sent_since_recv = msg.pkts_sent_since_recv,
            stalls_in_window = stalls,
            ?escalation,
            "home derp rx-stall reported; escalating"
        );

        // Every stage is a best-effort in-process action; the connection itself already
        // recycled locally (fresh socket + Noise) before this event was published.
        match escalation {
            StallEscalation::Remeasure => {
                // Refresh the latency picture (re-netcheck) so a repeat stall re-homes
                // onto current data.
                self.tell_latency_measurer(Remeasure).await;
            }
            StallEscalation::ForceRehome => {
                // Lateral relay swap, overriding anti-flap hysteresis and deprioritizing
                // the stalled region (it may still answer UDP latency probes while its
                // TCP relay return path is dead).
                self.tell_latency_measurer(ForceRehome {
                    avoid: Some(msg.region_id),
                })
                .await;
            }
            StallEscalation::FullReset => {
                // Strongest in-process reset that preserves SSH sessions: fresh control
                // connection (fresh Noise + re-registration + fresh derp map) plus a
                // forced re-home away from the stalled region.
                self.tell_force_reconnect().await;
                self.tell_latency_measurer(ForceRehome {
                    avoid: Some(msg.region_id),
                })
                .await;
            }
        }
    }
}

impl Message<Tick> for OffTailnetWatchdog {
    type Reply = ();

    async fn handle(&mut self, _: Tick, _ctx: &mut Context<Self, Self::Reply>) -> Self::Reply {
        let now = Instant::now();
        let since_update = now.duration_since(self.last_state_update);

        match decide_action(since_update, self.t_detect, self.state, now) {
            Action::NoOp => {
                tracing::trace!(
                    since_update_secs = since_update.as_secs(),
                    state = ?self.state,
                    "watchdog tick; no action"
                );
            }
            Action::Fire => {
                self.consecutive_control_fires = self.consecutive_control_fires.saturating_add(1);
                tracing::warn!(
                    since_update_secs = since_update.as_secs(),
                    t_detect_secs = self.t_detect.as_secs(),
                    consecutive_fires = self.consecutive_control_fires,
                    "off-tailnet detected (no StateUpdate within threshold); forcing control reconnect"
                );
                self.tell_force_reconnect().await;

                // Control-stall not fixed by reconnect: after repeated firings without a
                // single StateUpdate landing, the problem is likely the data path rather
                // than (or in addition to) the control stream — force a re-home too so
                // fresh relay connections and fresh netcheck data get a chance.
                if control_stall_escalates(self.consecutive_control_fires) {
                    tracing::warn!(
                        consecutive_fires = self.consecutive_control_fires,
                        "control reconnects not restoring StateUpdates; forcing derp re-home"
                    );
                    self.tell_latency_measurer(ForceRehome { avoid: None })
                        .await;
                }

                self.state = State::Fired(now);
            }
        }
    }
}

/// Pure decision function — no I/O, no clock reads beyond the supplied `now`.
///
/// Kept separate from the actor so it can be unit-tested in isolation.
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
            if since_update >= t_detect && now.duration_since(fired_at) >= T_COOLDOWN {
                Action::Fire
            } else {
                Action::NoOp
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{
        collections::VecDeque,
        time::{Duration, Instant},
    };

    use super::{
        Action, CONTROL_FIRES_BEFORE_REHOME, DEFAULT_STALL_ESCALATION_WINDOW, StallEscalation,
        State, T_COOLDOWN, control_stall_escalates, decide_action, decide_stall_escalation,
        prune_and_count,
    };

    fn now() -> Instant {
        // Stable reference; arithmetic via checked_add so tests are deterministic.
        Instant::now()
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
    fn isolated_stalls_never_escalate_past_remeasure() {
        // One stall per >window interval — e.g. genuinely rare blips — must always
        // stay at stage 1, never accumulate to a forced re-home.
        let t0 = Instant::now();
        let window = DEFAULT_STALL_ESCALATION_WINDOW;
        let mut stalls: VecDeque<Instant> = VecDeque::new();

        for i in 0..5u64 {
            let now = t0 + (window + Duration::from_secs(60)) * (i as u32 + 1);
            stalls.push_back(now);
            let count = prune_and_count(&mut stalls, now, window);
            assert_eq!(decide_stall_escalation(count), StallEscalation::Remeasure);
        }
    }

    #[test]
    fn repeated_stalls_of_dead_relay_walk_the_full_ladder() {
        // Behavior harness (escalation side of the redsun/dfw timeline): the home
        // relay is one-way-dead, so the connection recycles + re-stalls roughly every
        // stall-threshold. The watchdog must walk Remeasure → ForceRehome → FullReset.
        let t0 = Instant::now();
        let window = DEFAULT_STALL_ESCALATION_WINDOW;
        let mut stalls: VecDeque<Instant> = VecDeque::new();
        let mut stages = Vec::new();

        for i in 0..3u64 {
            let now = t0 + Duration::from_secs(180 * (i + 1)); // stall cadence ≈ threshold
            stalls.push_back(now);
            let count = prune_and_count(&mut stalls, now, window);
            stages.push(decide_stall_escalation(count));
        }

        assert_eq!(
            stages,
            vec![
                StallEscalation::Remeasure,
                StallEscalation::ForceRehome,
                StallEscalation::FullReset,
            ]
        );
    }

    // ---- control-stall-not-fixed-by-reconnect escalation ----

    #[test]
    fn control_stall_escalates_only_after_repeated_failed_reconnects() {
        assert!(!control_stall_escalates(0));
        assert!(!control_stall_escalates(1));
        assert!(!control_stall_escalates(2));
        assert!(control_stall_escalates(CONTROL_FIRES_BEFORE_REHOME));
        assert!(control_stall_escalates(CONTROL_FIRES_BEFORE_REHOME + 5));
    }

    #[test]
    fn stall_window_holds_the_whole_ladder_at_default_cadence() {
        // With the default 180s stall threshold, three consecutive stalls span ~540s;
        // the escalation window must keep all three in scope or FullReset is unreachable.
        assert!(DEFAULT_STALL_ESCALATION_WINDOW >= Duration::from_secs(3 * 180));
    }
}
