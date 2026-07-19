use std::{
    sync::Arc,
    time::{Duration, Instant},
};

use kameo::{
    actor::ActorRef,
    message::{Context, Message},
};
use tokio::time::MissedTickBehavior;
use ts_control::DerpMap;
use ts_derp::RegionId;
use ts_netcheck::RegionResult;

use crate::{Error, env::Env};

#[derive(Clone)]
pub struct DerpLatencyMeasurement {
    pub measurement: Arc<Vec<RegionResult>>,
}

/// Self-message that drives a periodic re-measurement of DERP region latencies.
///
/// The base client only measures latencies when the control plane pushes a new derp map. A node
/// whose home DERP silently degrades — or drops off the network without a corresponding map
/// update — therefore never notices and stays pinned to a bad relay. Re-measuring on a fixed
/// cadence lets the node detect a degraded/unreachable home region and reselect a healthy one
/// (DERP-home self-heal).
#[derive(Copy, Clone)]
pub struct Remeasure;

/// Force an immediate re-measure and re-home, overriding the anti-flap hysteresis for this one
/// selection. Sent by the [`crate::offtailnet_watchdog::OffTailnetWatchdog`] when the home relay
/// has repeatedly rx-stalled: the stalled region may still answer latency probes (UDP/STUN probes
/// exercise a different path than the DERP TCP relay return channel), so `avoid` deprioritizes it
/// — a different reachable region is selected if one exists; if the avoided region is the *only*
/// reachable one, it is kept (a bad home beats no home).
#[derive(Copy, Clone, Debug)]
pub struct ForceRehome {
    /// Region to move away from, if any.
    pub avoid: Option<RegionId>,
}

pub struct DerpLatencyMeasurer {
    env: Env,
    /// The most recent derp map, retained so a periodic [`Remeasure`] can run without waiting for
    /// a fresh control state update.
    derp_map: Option<DerpMap>,
    /// The region currently selected as home (lowest latency after hysteresis).
    current_home: Option<RegionId>,
    /// When the home region last changed. Used for anti-flap hysteresis on lateral swaps.
    last_home_change: Option<Instant>,
    /// One-shot forced re-home request: `Some(avoid)` makes the next selection ignore hysteresis
    /// and deprioritize `avoid`. Consumed by the next [`Self::select_home`].
    forced_rehome: Option<Option<RegionId>>,
}

impl DerpLatencyMeasurer {
    /// How often to re-measure DERP latencies to catch a degraded or unreachable home region.
    const REMEASURE_INTERVAL: Duration = Duration::from_secs(30);
    /// Minimum time between *lateral* home changes (both the old and new home reachable). Prevents
    /// flapping between two near-equal regions. A home that becomes unreachable/absent always
    /// re-homes immediately, regardless of this floor.
    const HOME_HYSTERESIS: Duration = Duration::from_secs(45);

    /// Measure the retained derp map, apply home-selection hysteresis, and publish the result.
    async fn measure_and_publish(&mut self) {
        let Some(derp_map) = self.derp_map.clone() else {
            return;
        };

        tracing::trace!("beginning derp latency measurement");
        let mut latencies = ts_netcheck::measure_derp_map(&derp_map, &Default::default()).await;
        tracing::trace!(?latencies, "measurement complete");

        // Select the home region with hysteresis, then ensure that region sits first in the
        // published vec. Both downstream consumers key off `measurement.first()` — the per-region
        // `Uniderp` tasks decide whether they are home, and `ControlRunner` reports the home region
        // to control — so putting the selected home first keeps them coherent. The full latency set
        // is still reported to control (order-independent there).
        if let Some(home) = self.select_home(&latencies)
            && let Some(pos) = latencies.iter().position(|r| r.id == home)
        {
            latencies.swap(0, pos);
        }

        if let Err(e) = self
            .env
            .publish(DerpLatencyMeasurement {
                measurement: Arc::new(latencies),
            })
            .await
        {
            tracing::error!(error = %e, "publishing");
        };
    }

    /// Select the home region from a fresh measurement, applying anti-flap hysteresis, and update
    /// the retained home state. Returns the region id that should be treated as home.
    ///
    /// A pending [`ForceRehome`] (one-shot) overrides the hysteresis for this selection and
    /// deprioritizes its `avoid` region.
    fn select_home(&mut self, results: &[RegionResult]) -> Option<RegionId> {
        let forced = self.forced_rehome.take();
        let avoid = forced.flatten();

        let best = select_best(results, avoid);
        let current_reachable = self
            .current_home
            .map(|cur| results.iter().any(|r| r.id == cur))
            .unwrap_or(false);
        let hysteresis_elapsed = forced.is_some()
            || self
                .last_home_change
                .map(|t| t.elapsed() >= Self::HOME_HYSTERESIS)
                .unwrap_or(true);

        let home = decide_home(
            self.current_home,
            current_reachable,
            best,
            hysteresis_elapsed,
        );
        self.set_home(home);
        home
    }

    fn set_home(&mut self, home: Option<RegionId>) {
        if home != self.current_home {
            if let (Some(old), Some(new)) = (self.current_home, home) {
                tracing::debug!(old_region = %old, new_region = %new, "derp home region changed");
            }
            self.current_home = home;
            self.last_home_change = Some(Instant::now());
        }
    }
}

/// Pick the best (lowest-latency) region, deprioritizing `avoid`: the best non-avoided region
/// wins; if the avoided region is the only one measured reachable, fall back to it — a bad home
/// still beats no home. Pure (no I/O, no clock) so it can be unit-tested in isolation.
fn select_best(results: &[RegionResult], avoid: Option<RegionId>) -> Option<RegionId> {
    match avoid {
        Some(a) => results
            .iter()
            .find(|r| r.id != a)
            .or(results.first())
            .map(|r| r.id),
        None => results.first().map(|r| r.id),
    }
}

/// Pure home-selection decision (no I/O, no clock) so it can be unit-tested in isolation.
///
/// * `current` — the region currently treated as home, if any.
/// * `current_reachable` — whether `current` appeared in the fresh measurement.
/// * `best` — the lowest-latency region in the fresh measurement, if any.
/// * `hysteresis_elapsed` — whether the anti-flap window has passed since the last home change.
fn decide_home(
    current: Option<RegionId>,
    current_reachable: bool,
    best: Option<RegionId>,
    hysteresis_elapsed: bool,
) -> Option<RegionId> {
    match current {
        // No home selected yet: adopt the best region.
        None => best,
        Some(cur) => {
            if !current_reachable {
                // Current home degraded/unreachable — re-home immediately (self-heal).
                best
            } else if best != Some(cur) && hysteresis_elapsed {
                // A different region is now best and the anti-flap window elapsed — switch.
                best
            } else {
                // Keep the current home: it is still reachable and either already best, or the
                // challenger has not been better long enough to justify a lateral swap.
                Some(cur)
            }
        }
    }
}

impl kameo::Actor for DerpLatencyMeasurer {
    type Args = Env;
    type Error = Error;

    async fn on_start(env: Env, slf: ActorRef<Self>) -> Result<Self, Self::Error> {
        env.subscribe::<Arc<ts_control::StateUpdate>>(&slf).await?;
        env.register(None, &slf).await?;

        // Re-measure periodically so a degraded/unreachable home region is noticed even without a
        // control-driven derp map update.
        env.scheduler
            .tell(
                kameo_actors::scheduler::SetInterval::new(
                    slf.downgrade(),
                    Self::REMEASURE_INTERVAL,
                    Remeasure,
                )
                .set_missed_tick_behaviour(MissedTickBehavior::Skip),
            )
            .await?;

        tracing::trace!("derp latency measurer running");

        Ok(Self {
            env,
            derp_map: None,
            current_home: None,
            last_home_change: None,
            forced_rehome: None,
        })
    }
}

impl Message<ForceRehome> for DerpLatencyMeasurer {
    type Reply = ();

    async fn handle(
        &mut self,
        msg: ForceRehome,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        tracing::warn!(avoid = ?msg.avoid, current_home = ?self.current_home, "forced re-home requested");
        self.forced_rehome = Some(msg.avoid);
        // Re-measure immediately; if no derp map is retained yet this is a no-op and the
        // forced flag is consumed by the next measurement that does run.
        self.measure_and_publish().await;
    }
}

impl Message<Arc<ts_control::StateUpdate>> for DerpLatencyMeasurer {
    type Reply = ();

    async fn handle(
        &mut self,
        state_update: Arc<ts_control::StateUpdate>,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        let Some(derp_map) = &state_update.derp else {
            return;
        };

        // Retain the latest map so periodic remeasures can run, then measure now.
        self.derp_map = Some(derp_map.clone());
        self.measure_and_publish().await;
    }
}

impl Message<Remeasure> for DerpLatencyMeasurer {
    type Reply = ();

    async fn handle(&mut self, _: Remeasure, _ctx: &mut Context<Self, Self::Reply>) -> Self::Reply {
        self.measure_and_publish().await;
    }
}

#[cfg(test)]
mod tests {
    use std::{num::NonZeroU32, time::Duration};

    use ts_derp::RegionId;
    use ts_netcheck::RegionResult;

    use super::{decide_home, select_best};

    fn r(n: u32) -> RegionId {
        RegionId(NonZeroU32::new(n).unwrap())
    }

    fn results(ids: &[u32]) -> Vec<RegionResult> {
        ids.iter()
            .enumerate()
            .map(|(i, &n)| RegionResult {
                latency: Duration::from_millis(10 + i as u64),
                id: r(n),
                latency_map_key: format!("region-{n}"),
                connected_remote: "127.0.0.1:3478".parse().unwrap(),
            })
            .collect()
    }

    #[test]
    fn select_best_takes_lowest_latency_without_avoid() {
        assert_eq!(select_best(&results(&[1, 2, 3]), None), Some(r(1)));
        assert_eq!(select_best(&results(&[]), None), None);
    }

    #[test]
    fn select_best_skips_avoided_region() {
        // Forced re-home away from a one-way-dead relay: the stalled region may still
        // answer latency probes, so it must be actively deprioritized.
        assert_eq!(select_best(&results(&[1, 2, 3]), Some(r(1))), Some(r(2)));
        assert_eq!(select_best(&results(&[1, 2, 3]), Some(r(2))), Some(r(1)));
    }

    #[test]
    fn select_best_falls_back_to_avoided_when_it_is_the_only_region() {
        // A bad home still beats no home — never strand the node without a relay.
        assert_eq!(select_best(&results(&[1]), Some(r(1))), Some(r(1)));
        assert_eq!(select_best(&results(&[]), Some(r(1))), None);
    }

    #[test]
    fn forced_rehome_moves_off_reachable_current_home_inside_hysteresis() {
        // Composition of the forced path: hysteresis is overridden (elapsed = true) and
        // the stalled current home is avoided, so a reachable challenger wins even
        // though a normal lateral swap would have been damped.
        let best = select_best(&results(&[1, 2]), Some(r(1)));
        assert_eq!(decide_home(Some(r(1)), true, best, true), Some(r(2)));
    }

    #[test]
    fn adopts_best_when_no_home_yet() {
        // No current home -> take the best region regardless of hysteresis.
        assert_eq!(decide_home(None, false, Some(r(1)), false), Some(r(1)));
        assert_eq!(decide_home(None, false, None, false), None);
    }

    #[test]
    fn keeps_home_when_still_best() {
        // Current home is also the best region -> keep it.
        assert_eq!(decide_home(Some(r(1)), true, Some(r(1)), true), Some(r(1)));
    }

    #[test]
    fn rehomes_immediately_when_home_unreachable() {
        // Home no longer present in the measurement (unreachable) -> switch now, even inside the
        // hysteresis window. This is the core self-heal behavior.
        assert_eq!(
            decide_home(Some(r(1)), false, Some(r(2)), false),
            Some(r(2))
        );
    }

    #[test]
    fn damps_lateral_swap_within_hysteresis_window() {
        // Home still reachable, a different region is now best, but the anti-flap window has not
        // elapsed -> stay on the current home to avoid flapping.
        assert_eq!(decide_home(Some(r(1)), true, Some(r(2)), false), Some(r(1)));
    }

    #[test]
    fn allows_lateral_swap_after_hysteresis_window() {
        // Home still reachable, a different region has been best long enough -> switch.
        assert_eq!(decide_home(Some(r(1)), true, Some(r(2)), true), Some(r(2)));
    }

    #[test]
    fn keeps_home_when_no_regions_measured() {
        // Empty measurement but home still considered reachable=false -> best is None; with a
        // current home present but unreachable we would re-home, but there is nowhere to go.
        assert_eq!(decide_home(Some(r(1)), false, None, true), None);
        // Reachable current home, no better candidate -> keep it.
        assert_eq!(decide_home(Some(r(1)), true, Some(r(1)), true), Some(r(1)));
    }
}
