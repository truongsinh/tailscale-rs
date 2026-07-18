use ts_capabilityversion::CapabilityVersion;
use ts_control_serde::{HostInfo, MapRequest, NetInfo};

use crate::Config;

/// Map a Rust target-arch string (as produced by [`std::env::consts::ARCH`]) to its Go
/// `GOARCH` equivalent, which is the form control (and the admin console) expect.
///
/// Unrecognised architectures pass through unchanged so a new target still reports *something*
/// rather than an empty field.
pub(crate) fn go_arch(arch: &str) -> &str {
    match arch {
        "x86_64" => "amd64",
        "aarch64" => "arm64",
        "x86" => "386",
        "arm" => "arm",
        "riscv64" => "riscv64",
        "powerpc64" => "ppc64",
        "s390x" => "s390x",
        "mips" => "mips",
        "mips64" => "mips64",
        "wasm32" => "wasm",
        "loongarch64" => "loong64",
        other => other,
    }
}

/// The composed `ipn_version` string reported to control, of the form
/// `"<pkg>-<seq>-g<sha> <goarch> run=<identity> disk=<free%>/<freeGB>"`
/// (e.g. `"0.4.0-253-g301ee7a amd64 run=user:sinh disk=29%/169GB"`).
///
/// The admin console surfaces `clientVersion` (this value) but not `app`, so the goarch,
/// run-identity, and disk summary are folded in here to make them observable. Cached for
/// the process lifetime.
fn ipn_version() -> &'static str {
    static V: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    V.get_or_init(|| {
        format!(
            "{} {} {} {}",
            crate::IPN_VERSION,
            go_arch(std::env::consts::ARCH),
            crate::run_identity::run_identity(),
            crate::disk_identity::disk_identity(),
        )
    })
}

/// Populate the [`HostInfo`] fields that every outbound request shares: hostname, app name,
/// composed `ipn_version`, and the static platform fields (`os`, `machine`, `go_arch`).
///
/// This is the single seam through which all HostInfo is populated — registration, the
/// streaming map request, and DERP rehome requests all route through it so the identity
/// reported to control is identical and survives reconnect/rehome.
///
/// `client_name` is borrowed for `'a`, so callers bind it (from [`Config::format_client_name`])
/// to a local that outlives the request.
pub(crate) fn apply_host_info<'a>(
    host_info: &mut HostInfo<'a>,
    config: &'a Config,
    client_name: &'a str,
) {
    if let Some(hostname) = config.hostname.as_deref() {
        host_info.hostname = Some(hostname);
    }
    host_info.app = client_name;
    host_info.ipn_version = ipn_version();
    host_info.os = std::env::consts::OS;
    host_info.machine = std::env::consts::ARCH;
    host_info.go_arch = go_arch(std::env::consts::ARCH);
}

/// Builder type for [`MapRequest`]s; smooths over the annoying parts of creating a request.
#[derive(Debug, Clone)]
pub struct MapRequestBuilder<'a> {
    req: MapRequest<'a>,
}

impl<'a> MapRequestBuilder<'a> {
    /// Create a new [`MapRequestBuilder`]. By default:
    /// - [`MapRequest::keep_alive`] is `false`
    /// - [`MapRequest::omit_peers`] is `true`
    /// - [`MapRequest::stream`] is `false`
    /// - [`MapRequest::host_info`]:
    ///     - [`HostInfo::hostname`] is populated from [`TailnetPeerConfig::hostname`]
    ///     - [`HostInfo::net_info`] is `None`, therefore:
    ///         - [`NetInfo::derp_latency`][crate::types::NetInfo::derp_latency] is not populated
    ///         - [`NetInfo::preferred_derp`][crate::types::NetInfo::preferred_derp] is not populated
    pub fn new(key_state: &ts_keys::NodeState) -> Self {
        Self {
            req: MapRequest {
                version: CapabilityVersion::CURRENT,

                keep_alive: false,
                omit_peers: true,
                stream: false,

                node_key: key_state.node_keys.public,
                disco_key: key_state.disco_keys.public,

                host_info: Some(HostInfo::default()),
                ..Default::default()
            },
        }
    }

    /// Consumes this [`MapRequestBuilder`] and returns a [`MapRequest`] with the configured
    /// values.
    pub fn build(self) -> MapRequest<'a> {
        self.req
    }

    /// Set the [`MapRequest::keep_alive`] field.
    pub fn keep_alive(mut self, value: bool) -> Self {
        self.req.keep_alive = value;
        self
    }

    /// Set the [`MapRequest::omit_peers`] field.
    pub fn omit_peers(mut self, value: bool) -> Self {
        self.req.omit_peers = value;
        self
    }

    /// Set the [`MapRequest::stream`] field.
    pub fn stream(mut self, value: bool) -> Self {
        self.req.stream = value;
        self
    }

    /// Populate the shared [`HostInfo`] fields (hostname, app, `ipn_version`, and the static
    /// platform fields) via [`apply_host_info`].
    ///
    /// `client_name` is borrowed for `'a`, so the caller binds it (from
    /// [`Config::format_client_name`]) to a local that outlives the request.
    pub fn host_info(mut self, config: &'a Config, client_name: &'a str) -> Self {
        apply_host_info(self.host_info_mut(), config, client_name);
        self
    }

    /// Set the [`NetInfo::preferred_derp`] field (inside [`MapRequest::host_info`] ->
    /// [`HostInfo::net_info`]).
    pub fn preferred_derp(mut self, value: ts_derp::RegionId) -> Self {
        self.net_info_mut().preferred_derp = Some(value.0.into());
        self
    }

    /// Set the [`NetInfo::derp_latency`] field (inside [`MapRequest::host_info`] ->
    /// [`HostInfo::net_info`]).
    pub fn derp_latencies(mut self, value: impl IntoIterator<Item = (&'a str, f64)>) -> Self {
        self.net_info_mut().derp_latency = Some(value.into_iter().collect());

        self
    }

    fn host_info_mut(&mut self) -> &mut HostInfo<'a> {
        self.req.host_info.get_or_insert_default()
    }

    fn net_info_mut(&mut self) -> &mut NetInfo<'a> {
        self.host_info_mut().net_info.get_or_insert_default()
    }
}

#[cfg(test)]
mod tests {
    use super::{go_arch, ipn_version};

    #[test]
    fn go_arch_maps_known_targets_and_passes_through_unknown() {
        let cases = [
            ("x86_64", "amd64"),
            ("aarch64", "arm64"),
            ("x86", "386"),
            ("riscv64", "riscv64"),
            ("loongarch64", "loong64"),
            ("some_future_arch", "some_future_arch"),
        ];
        for (input, expected) in cases {
            assert_eq!(go_arch(input), expected, "go_arch({input})");
        }
    }

    #[test]
    fn ipn_version_folds_base_version_goarch_and_run_identity() {
        let composed = ipn_version();
        let goarch = go_arch(std::env::consts::ARCH);

        assert!(
            composed.starts_with(crate::IPN_VERSION),
            "composed ipn_version {composed:?} should start with the base version {:?}",
            crate::IPN_VERSION,
        );
        assert!(
            composed.contains(" run="),
            "composed ipn_version {composed:?} should carry a run= identity token",
        );
        assert!(
            composed.contains(" disk="),
            "composed ipn_version {composed:?} should carry a disk= summary token",
        );
        assert!(
            composed.contains(goarch),
            "composed ipn_version {composed:?} should carry the goarch token {goarch:?}",
        );
    }

    #[test]
    fn ipn_version_is_cached() {
        // The OnceLock hands back the same allocation on every call.
        assert!(std::ptr::eq(ipn_version().as_ptr(), ipn_version().as_ptr()));
    }
}
