//! Build script for `ts_control`.
//!
//! Bakes the build SHA + sequential ordinal into the binary via the
//! `TS_RS_BUILD_SHA` / `TS_RS_BUILD_SEQ` compile-time env, so `HostInfo.ipn_version`
//! can report `0.4.0-<seq>-g<sha>` in the admin console's `clientVersion`.
//!
//! The values are taken from the `TS_RS_BUILD_*` *environment variables* (set by
//! CI / `bin/build-win7` / `bin/build-musl` from `git rev-parse` / `git
//! rev-list --count`), deliberately NOT from reading `.git`: a `rerun-if-changed`
//! on a loose ref never fires when the ref is packed, which would silently bake a
//! stale value. Keying the rerun on the env vars instead makes the dependency
//! explicit and always correct.

fn main() {
    bake("TS_RS_BUILD_SHA", "unknown");
    bake("TS_RS_BUILD_SEQ", "0");
}

/// Read an env var, default to `fallback` when unset/empty, and emit it as a
/// `rustc-env` line so `env!()` in `lib.rs` picks up the value at compile time.
///
/// Also emits the matching `rerun-if-env-changed` so a changed env var triggers
/// a rebuild of this crate (and therefore a re-bake of the const).
fn bake(var: &str, fallback: &str) {
    let value = std::env::var(var)
        .ok()
        .and_then(|v| v.lines().next().map(str::trim).map(str::to_owned))
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| fallback.to_owned());

    println!("cargo:rustc-env={var}={value}");
    println!("cargo:rerun-if-env-changed={var}");
}
