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
//! [`StateUpdate`] as the off-tailnet indicator: if it exceeds `T_DETECT` (default 120s,
//! env `TS_OFFNET_T_DETECT_SECS`), the node is presumed off-tailnet and a reconnect is
//! forced.
//!
//! ## Hysteresis
//!
//! After firing, the watchdog enters a cooldown (`T_COOLDOWN`, default 60s) before it
//! will fire again. This prevents spamming [`ForceReconnect`] every poll while
//! ControlRunner is mid-reconnect, while still retrying if the first attempt did not
//! recover the stream. The next [`StateUpdate`] resets the state to `Idle` immediately.

use std::{
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
    env::Env,
};

/// Poll interval for the watchdog tick.
///
/// Kept short so detection latency is bounded by `POLL_INTERVAL + T_DETECT` worst case
/// (a drop happening the instant after a poll is only noticed at the next poll).
const POLL_INTERVAL: Duration = Duration::from_secs(30);

/// Default time without a [`StateUpdate`] after which the node is considered off-tailnet.
const DEFAULT_T_DETECT: Duration = Duration::from_secs(120);

/// Cooldown after a forced reconnect before another may fire.
///
/// Must be long enough that ControlRunner's reconnect attempt has a chance to either
/// succeed (in which case a [`StateUpdate`] arrives and resets the state) or fail
/// (in which case retrying is legitimate), and short enough that a stuck control plane
/// is retried promptly.
const T_COOLDOWN: Duration = Duration::from_secs(60);

/// Environment variable override for `T_DETECT` (in seconds).
const T_DETECT_ENV: &str = "TS_OFFNET_T_DETECT_SECS";

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
        std::env::var(T_DETECT_ENV)
            .ok()
            .and_then(|v| v.parse().ok())
            .map(Duration::from_secs)
            .unwrap_or(DEFAULT_T_DETECT)
    }
}

impl kameo::Actor for OffTailnetWatchdog {
    type Args = Env;
    type Error = Error;

    async fn on_start(env: Env, slf: ActorRef<Self>) -> Result<Self, Self::Error> {
        env.subscribe::<Arc<ts_control::StateUpdate>>(&slf).await?;
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
                tracing::warn!(
                    since_update_secs = since_update.as_secs(),
                    t_detect_secs = self.t_detect.as_secs(),
                    "off-tailnet detected (no StateUpdate within threshold); forcing control reconnect"
                );
                if let Err(e) = self
                    .env
                    .tell::<crate::control_runner::ControlRunner, _>(None, ForceReconnect)
                    .await
                {
                    tracing::error!(error = %e, "sending ForceReconnect to ControlRunner");
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

fn decide_action(
    since_update: Duration,
    t_detect: Duration,
    state: State,
    now: Instant,
) -> Action {
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
    use std::time::{Duration, Instant};

    use super::{Action, State, T_COOLDOWN, decide_action};

    fn now() -> Instant {
        // Stable reference; arithmetic via checked_add so tests are deterministic.
        Instant::now()
    }

    #[test]
    fn idle_under_threshold_does_not_fire() {
        let t = now();
        assert_eq!(
            decide_action(Duration::from_secs(30), Duration::from_secs(120), State::Idle, t),
            Action::NoOp
        );
    }

    #[test]
    fn idle_at_threshold_fires() {
        let t = now();
        assert_eq!(
            decide_action(Duration::from_secs(120), Duration::from_secs(120), State::Idle, t),
            Action::Fire
        );
    }

    #[test]
    fn idle_over_threshold_fires() {
        let t = now();
        assert_eq!(
            decide_action(Duration::from_secs(300), Duration::from_secs(120), State::Idle, t),
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
            decide_action(Duration::from_secs(119), Duration::from_secs(120), State::Idle, t),
            Action::NoOp
        );
        // 120s exactly -> Fire.
        assert_eq!(
            decide_action(Duration::from_secs(120), Duration::from_secs(120), State::Idle, t),
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
}
