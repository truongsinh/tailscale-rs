//! Build script for `ts_control`.
//!
//! Bakes the build SHA into the binary via the `TS_RS_BUILD_SHA` compile-time env, so
//! `HostInfo.ipn_version` can report `0.4.0-<sha>` in the admin console's `clientVersion`.
//!
//! The value is taken from the `TS_RS_BUILD_SHA` *environment variable* (set by CI /
//! `bin/build-win7`), deliberately NOT from reading `.git`: a `rerun-if-changed` on a loose
//! ref never fires when the ref is packed, which would silently bake a stale SHA. Keying the
//! rerun on the env var instead makes the dependency explicit and always correct.

fn main() {
    let sha = std::env::var("TS_RS_BUILD_SHA")
        .ok()
        .and_then(|v| v.lines().next().map(str::trim).map(str::to_owned))
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| "unknown".to_owned());

    println!("cargo:rustc-env=TS_RS_BUILD_SHA={sha}");
    println!("cargo:rerun-if-env-changed=TS_RS_BUILD_SHA");
}
