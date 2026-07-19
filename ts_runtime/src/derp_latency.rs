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

use crate::{
    Error, env::Env, multiderp::RxHealthyEvent, offtailnet_watchdog::duration_from_env_or,
};

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
/// exercise a different path than the DERP TCP relay return channel), so `avoid` puts the region
/// in a **penalty box**: it is deprioritized in *every* subsequent home selection until either
/// its TTL expires or positive health evidence ([`RxHealthyEvent`]) arrives — a different
/// reachable region is selected if one exists; if the penalized region is the *only* reachable
/// one, it is kept (a bad home beats no home).
#[derive(Copy, Clone, Debug)]
pub struct ForceRehome {
    /// Region to move away from, if any.
    pub avoid: Option<RegionId>,
}

/// Penalty-box entry: `region` is deprioritized in every home selection until `until`.
#[derive(Copy, Clone, Debug)]
struct PenaltyBox {
    region: RegionId,
    until: Instant,
}

/// Home-selection state, factored out of the actor so every decision can be unit-tested with an
/// injected `now` (no clock reads inside).
struct HomeSelector {
    /// The region currently selected as home (lowest latency after hysteresis).
    current_home: Option<RegionId>,
    /// When the home region last changed. Used for anti-flap hysteresis on lateral swaps.
    last_home_change: Option<Instant>,
    /// Persistent penalty box (see [`ForceRehome`]). Unlike the previous one-shot design, this
    /// survives every periodic remeasure for its TTL, so a dead relay that still answers
    /// UDP/STUN latency probes cannot win the ranking back seconds after a forced swap
    /// (the re-home ping-pong failure mode).
    penalty: Option<PenaltyBox>,
    /// Pending one-shot hysteresis override, timestamped so it expires instead of parking
    /// forever when no derp map is retained at request time.
    force_rehome_at: Option<Instant>,
    /// Penalty-box TTL.
    avoid_ttl: Duration,
}

impl HomeSelector {
    /// How long a pending forced re-home may wait for a measurement before it lapses. Two
    /// remeasure intervals guarantee at least one periodic measurement runs in the window
    /// whenever a derp map exists at all.
    const FORCE_REHOME_EXPIRY: Duration =
        Duration::from_secs(2 * DerpLatencyMeasurer::REMEASURE_INTERVAL.as_secs());
    /// Minimum time between *lateral* home changes (both the old and new home reachable). Prevents
    /// flapping between two near-equal regions. A home that becomes unreachable/absent always
    /// re-homes immediately, regardless of this floor.
    const HOME_HYSTERESIS: Duration = Duration::from_secs(45);

    fn new(avoid_ttl: Duration) -> Self {
        Self {
            current_home: None,
            last_home_change: None,
            penalty: None,
            force_rehome_at: None,
            avoid_ttl,
        }
    }

    /// Record a forced re-home request: penalize `avoid` (if any) for the TTL and arm the
    /// one-shot hysteresis override.
    fn force_rehome(&mut self, avoid: Option<RegionId>, now: Instant) {
        if let Some(region) = avoid {
            match now.checked_add(self.avoid_ttl) {
                Some(until) => self.penalty = Some(PenaltyBox { region, until }),
                None => tracing::warn!(%region, "avoid TTL overflows the clock; not penalizing"),
            }
        }
        self.force_rehome_at = Some(now);
    }

    /// Positive health evidence for `region` (frames arriving on a home connection to it):
    /// clear its penalty early. Returns whether a penalty was cleared.
    fn on_region_healthy(&mut self, region: RegionId, _now: Instant) -> bool {
        if self.penalty.is_some_and(|p| p.region == region) {
            tracing::info!(%region, "penalized region delivering frames again; clearing penalty box early");
            self.penalty = None;
            return true;
        }
        false
    }

    /// Select the home region from a fresh measurement, applying the penalty box and anti-flap
    /// hysteresis, and update the retained home state. Returns the region id that should be
    /// treated as home.
    fn select_home(&mut self, results: &[RegionResult], now: Instant) -> Option<RegionId> {
        let forced = match self.force_rehome_at.take() {
            Some(at) if now.saturating_duration_since(at) <= Self::FORCE_REHOME_EXPIRY => true,
            Some(_) => {
                tracing::warn!(
                    "stale forced re-home expired unused (no measurement ran inside the window)"
                );
                false
            }
            None => false,
        };

        if let Some(p) = self.penalty
            && now >= p.until
        {
            tracing::info!(region = %p.region, "re-home penalty box TTL expired; region eligible again");
            self.penalty = None;
        }
        let avoid = self.penalty.map(|p| p.region);

        let best = select_best(results, avoid);
        let current_reachable = self
            .current_home
            .map(|cur| results.iter().any(|r| r.id == cur))
            .unwrap_or(false);
        let hysteresis_elapsed = forced
            || self
                .last_home_change
                .map(|t| now.saturating_duration_since(t) >= Self::HOME_HYSTERESIS)
                .unwrap_or(true);

        let home = decide_home(
            self.current_home,
            current_reachable,
            best,
            hysteresis_elapsed,
        );
        self.set_home(home, now);
        home
    }

    fn set_home(&mut self, home: Option<RegionId>, now: Instant) {
        if home != self.current_home {
            if let (Some(old), Some(new)) = (self.current_home, home) {
                tracing::debug!(old_region = %old, new_region = %new, "derp home region changed");
            }
            self.current_home = home;
            self.last_home_change = Some(now);
        }
    }
}

pub struct DerpLatencyMeasurer {
    env: Env,
    /// The most recent derp map, retained so a periodic [`Remeasure`] can run without waiting for
    /// a fresh control state update.
    derp_map: Option<DerpMap>,
    /// Home-selection state (current home, hysteresis, penalty box).
    selector: HomeSelector,
}

impl DerpLatencyMeasurer {
    /// How often to re-measure DERP latencies to catch a degraded or unreachable home region.
    const REMEASURE_INTERVAL: Duration = Duration::from_secs(30);

    /// Default penalty-box TTL for a forced re-home's avoided region. Must be at least the
    /// watchdog's stall-escalation window (900s default) so a dead relay stays deprioritized
    /// for the whole ladder — otherwise the node swaps back onto the dead relay within a
    /// remeasure interval or two and ping-pongs forever.
    const DEFAULT_AVOID_TTL: Duration = Duration::from_secs(900);
    /// Floor for the env-tunable penalty TTL: anything below one remeasure interval is
    /// indistinguishable from the broken one-shot behavior.
    const MIN_AVOID_TTL: Duration = Duration::from_secs(60);
    /// Env var overriding the penalty-box TTL, in seconds.
    const AVOID_TTL_ENV: &str = "TS_OFFNET_REHOME_AVOID_TTL_SECS";

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
        if let Some(home) = self.selector.select_home(&latencies, Instant::now())
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
        env.subscribe::<RxHealthyEvent>(&slf).await?;
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

        let avoid_ttl = duration_from_env_or(
            Self::AVOID_TTL_ENV,
            Self::DEFAULT_AVOID_TTL,
            Self::MIN_AVOID_TTL,
        );

        Ok(Self {
            env,
            derp_map: None,
            selector: HomeSelector::new(avoid_ttl),
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
        tracing::warn!(
            avoid = ?msg.avoid,
            current_home = ?self.selector.current_home,
            avoid_ttl_secs = self.selector.avoid_ttl.as_secs(),
            "forced re-home requested"
        );
        self.selector.force_rehome(msg.avoid, Instant::now());
        // Re-measure immediately; if no derp map is retained yet this is a no-op — the penalty
        // box persists regardless, and the one-shot hysteresis override is consumed by the next
        // measurement inside its expiry window.
        self.measure_and_publish().await;
    }
}

impl Message<RxHealthyEvent> for DerpLatencyMeasurer {
    type Reply = ();

    async fn handle(
        &mut self,
        msg: RxHealthyEvent,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        self.selector
            .on_region_healthy(msg.region_id, Instant::now());
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
    use std::{
        num::NonZeroU32,
        time::{Duration, Instant},
    };

    use ts_derp::RegionId;
    use ts_netcheck::RegionResult;

    use super::{DerpLatencyMeasurer, HomeSelector, decide_home, select_best};

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

    fn secs(n: u64) -> Duration {
        Duration::from_secs(n)
    }

    const TTL: Duration = DerpLatencyMeasurer::DEFAULT_AVOID_TTL;

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

    // ---- penalty box: the re-home must STICK (injected time throughout) ----

    /// The field ping-pong scenario: forced off dead-but-probe-answering region A onto B,
    /// then 30s periodic remeasures keep ranking A best. The node must NOT return to A
    /// within the TTL.
    #[test]
    fn penalty_box_prevents_return_to_stalled_region_within_ttl() {
        let t0 = Instant::now();
        let mut sel = HomeSelector::new(TTL);

        // Established home on A well before the incident.
        assert_eq!(sel.select_home(&results(&[1, 2]), t0), Some(r(1)));

        // Watchdog forces a re-home away from A at t+60.
        sel.force_rehome(Some(r(1)), t0 + secs(60));
        assert_eq!(
            sel.select_home(&results(&[1, 2]), t0 + secs(60)),
            Some(r(2))
        );

        // Every 30s remeasure for the whole TTL still ranks dead-A best (it answers
        // STUN). The old one-shot design flipped back on the second remeasure; the
        // penalty box must hold for the entire TTL.
        let mut t = t0 + secs(90);
        while t < t0 + secs(60) + TTL {
            assert_eq!(
                sel.select_home(&results(&[1, 2]), t),
                Some(r(2)),
                "must not return to the penalized region at t0+{:?}",
                t.duration_since(t0)
            );
            t += secs(30);
        }
    }

    #[test]
    fn penalty_box_expires_after_ttl() {
        let t0 = Instant::now();
        let mut sel = HomeSelector::new(TTL);
        assert_eq!(sel.select_home(&results(&[1, 2]), t0), Some(r(1)));
        sel.force_rehome(Some(r(1)), t0);
        assert_eq!(sel.select_home(&results(&[1, 2]), t0), Some(r(2)));

        // Past the TTL the region is eligible again; if it still ranks best, a
        // lateral swap back is allowed once hysteresis has elapsed.
        let after = t0 + TTL + secs(1);
        assert_eq!(sel.select_home(&results(&[1, 2]), after), Some(r(1)));
    }

    #[test]
    fn penalty_box_never_strands_when_penalized_region_is_the_only_one() {
        let t0 = Instant::now();
        let mut sel = HomeSelector::new(TTL);
        assert_eq!(sel.select_home(&results(&[1]), t0), Some(r(1)));
        sel.force_rehome(Some(r(1)), t0 + secs(10));
        // Only region measured reachable is the penalized one: keep it — a bad home
        // beats no home (single-reachable-region boxes like redsun).
        assert_eq!(sel.select_home(&results(&[1]), t0 + secs(10)), Some(r(1)));
    }

    #[test]
    fn health_evidence_clears_penalty_early() {
        let t0 = Instant::now();
        let mut sel = HomeSelector::new(TTL);
        assert_eq!(sel.select_home(&results(&[1, 2]), t0), Some(r(1)));
        sel.force_rehome(Some(r(1)), t0);
        assert_eq!(sel.select_home(&results(&[1, 2]), t0), Some(r(2)));

        // Frames arrive on a home connection to region 1 (e.g. fallback case or the
        // relay actually recovered): positive evidence clears the box early.
        assert!(sel.on_region_healthy(r(1), t0 + secs(120)));
        // Health evidence for an unrelated region is a no-op.
        assert!(!sel.on_region_healthy(r(2), t0 + secs(120)));

        // Region 1 is immediately eligible again (hysteresis elapsed: last change t0).
        assert_eq!(
            sel.select_home(&results(&[1, 2]), t0 + secs(120)),
            Some(r(1))
        );
    }

    #[test]
    fn forced_rehome_overrides_hysteresis_once_then_damps() {
        let t0 = Instant::now();
        let mut sel = HomeSelector::new(TTL);
        assert_eq!(sel.select_home(&results(&[1, 2, 3]), t0), Some(r(1)));

        // Forced swap at t+10 — inside the 45s hysteresis window — must move anyway.
        sel.force_rehome(Some(r(1)), t0 + secs(10));
        assert_eq!(
            sel.select_home(&results(&[1, 2, 3]), t0 + secs(10)),
            Some(r(2))
        );

        // The override was one-shot: 10s later a different challenger (3) may not
        // trigger another swap inside the fresh hysteresis window.
        assert_eq!(
            sel.select_home(&results(&[1, 3, 2]), t0 + secs(20)),
            Some(r(2))
        );
    }

    #[test]
    fn stale_forced_rehome_expires_instead_of_parking_forever() {
        // ForceRehome arriving while no derp map is retained: no measurement runs, the
        // flag parks. When a measurement finally happens far later, the stale override
        // must NOT bypass hysteresis — but the penalty box still applies.
        let t0 = Instant::now();
        let mut sel = HomeSelector::new(TTL);
        assert_eq!(sel.select_home(&results(&[1, 2]), t0), Some(r(1)));

        sel.force_rehome(Some(r(1)), t0 + secs(10));
        // First measurement runs 300s later (> 60s expiry): override lapsed...
        let t_late = t0 + secs(310);
        // ...but the penalty box is TTL-scoped, not one-shot: still avoiding region 1,
        // and with last_home_change at t0 the hysteresis has elapsed anyway — the swap
        // happens because of the *penalty*, not the stale override.
        assert_eq!(sel.select_home(&results(&[1, 2]), t_late), Some(r(2)));
    }

    #[test]
    fn penalty_ttl_holds_the_whole_escalation_window() {
        // The penalty must outlive the watchdog's stall-escalation window, or the node
        // can return to the dead relay mid-ladder and reset the escalation.
        assert!(DerpLatencyMeasurer::DEFAULT_AVOID_TTL >= Duration::from_secs(900));
    }
}
