//! Pure stats helpers for the ssh_bench harness: latency summaries (min/p50/p95/max)
//! and stall detection over per-second progress timelines.
//!
//! Included (via `#[path]`) from the `bench_harness` integration test so these are
//! unit-tested without any network in the loop.

/// One per-second progress sample: elapsed seconds since phase start, cumulative
/// bytes written (up) and read (down) at that instant.
#[derive(Clone, Copy, Debug)]
pub struct Sample {
    /// Seconds since the phase started.
    pub t: f64,
    /// Cumulative bytes the client has written so far.
    pub up: u64,
    /// Cumulative bytes the client has read so far.
    pub down: u64,
}

/// A detected stall: a direction made no progress for longer than the threshold.
#[derive(Clone, Debug, PartialEq)]
pub struct Stall {
    /// "up" or "down".
    pub dir: &'static str,
    /// Timeline second the stall began at.
    pub start_t: f64,
    /// Stall duration in seconds (to the sample where progress resumed, or the
    /// last sample if it never did).
    pub secs: f64,
}

/// min / p50 / p95 / max over a set of latency measurements.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Summary {
    /// Minimum.
    pub min: f64,
    /// Median (nearest-rank).
    pub p50: f64,
    /// 95th percentile (nearest-rank).
    pub p95: f64,
    /// Maximum.
    pub max: f64,
}

/// The peer's `SINK sha256=<hex> bytes=<n> secs=<f>` report, parsed from its stdout.
#[derive(Clone, Debug, PartialEq)]
pub struct SinkReport {
    /// sha256 (lowercase hex) of the bytes the peer read from stdin.
    pub sha256: String,
    /// Number of bytes the peer read before EOF.
    pub bytes: u64,
    /// Peer-side seconds from start to stdin EOF.
    pub secs: f64,
}

/// Find and parse the first SINK line in the peer's stdout text.
pub fn parse_sink(text: &str) -> Option<SinkReport> {
    for line in text.lines() {
        let Some(rest) = line.trim().strip_prefix("SINK ") else {
            continue;
        };
        let mut sha256 = None;
        let mut bytes = None;
        let mut secs = None;
        for tok in rest.split_whitespace() {
            if let Some(v) = tok.strip_prefix("sha256=") {
                sha256 = Some(v.to_string());
            } else if let Some(v) = tok.strip_prefix("bytes=") {
                bytes = v.parse().ok();
            } else if let Some(v) = tok.strip_prefix("secs=") {
                secs = v.parse().ok();
            }
        }
        return Some(SinkReport {
            sha256: sha256?,
            bytes: bytes?,
            secs: secs?,
        });
    }
    None
}

/// Nearest-rank percentile (p in 0..=100) over unsorted values. Empty input → NaN.
pub fn percentile(values: &[f64], p: f64) -> f64 {
    if values.is_empty() {
        return f64::NAN;
    }
    let mut sorted = values.to_vec();
    sorted.sort_by(|a, b| a.partial_cmp(b).expect("latency values are finite"));
    // Nearest-rank: ceil(p/100 * n), 1-based; clamp into range.
    let rank = ((p / 100.0) * sorted.len() as f64).ceil() as usize;
    sorted[rank.clamp(1, sorted.len()) - 1]
}

/// Summarize a set of latency measurements.
pub fn summarize(values: &[f64]) -> Summary {
    Summary {
        min: values.iter().copied().fold(f64::NAN, f64::min),
        p50: percentile(values, 50.0),
        p95: percentile(values, 95.0),
        max: values.iter().copied().fold(f64::NAN, f64::max),
    }
}

/// Scan a timeline for windows where a direction's byte counter did not advance for
/// strictly longer than `threshold_secs`. `track_up` / `track_down` select which
/// directions are meaningful for the phase (an upload phase's `down` counter is
/// legitimately near-idle).
pub fn find_stalls(
    samples: &[Sample],
    track_up: bool,
    track_down: bool,
    threshold_secs: f64,
) -> Vec<Stall> {
    let mut out = Vec::new();
    if track_up {
        scan_direction(samples, "up", |s| s.up, threshold_secs, &mut out);
    }
    if track_down {
        scan_direction(samples, "down", |s| s.down, threshold_secs, &mut out);
    }
    out.sort_by(|a, b| a.start_t.partial_cmp(&b.start_t).expect("finite times"));
    out
}

fn scan_direction(
    samples: &[Sample],
    dir: &'static str,
    get: impl Fn(&Sample) -> u64,
    threshold_secs: f64,
    out: &mut Vec<Stall>,
) {
    let mut flat_start: Option<usize> = None;
    for i in 1..samples.len() {
        let advanced = get(&samples[i]) > get(&samples[i - 1]);
        if !advanced {
            flat_start.get_or_insert(i - 1);
        }
        // Close a flat run when progress resumes or at the last sample.
        if (advanced || i == samples.len() - 1) && flat_start.is_some() {
            let s = flat_start.take().expect("checked is_some");
            let secs = samples[i].t - samples[s].t;
            if secs > threshold_secs {
                out.push(Stall {
                    dir,
                    start_t: samples[s].t,
                    secs,
                });
            }
        }
    }
}
