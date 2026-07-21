use core::fmt::Debug;

use url::Url;

lazy_static::lazy_static! {
    /// The default [`Url`] of the control plane server (aka "coordination server").
    pub static ref DEFAULT_CONTROL_SERVER: Url = Url::parse("https://controlplane.tailscale.com/").unwrap();
}

/// Configuration for the control server.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct Config {
    /// The URL of the control server to connect to.
    pub server_url: Url,

    /// The hostname of the current node.
    pub hostname: Option<String>,

    /// A name for this type of client.
    ///
    /// This will be reported to the control server in the `HostInfo.App` field.
    pub client_name: Option<String>,

    /// Tags to request from the control server.
    pub tags: Vec<String>,

    /// SSH host public keys to advertise to the coordination server.
    ///
    /// Each entry must be a single-line OpenSSH authorized-keys value of the form
    /// `<key-type> <base64-blob>` (e.g. `"ssh-ed25519 AAAA..."`), with no trailing
    /// comment, hostname prefix, or newline. This is the same format upstream
    /// Tailscale populates `Hostinfo.SSH_HostKeys` with (see
    /// `ssh/tailssh/hostkeys.go::getHostKeyPublicStrings` in tailscale/tailscale).
    ///
    /// When non-empty, the keys are attached to every outbound `Hostinfo` — both
    /// the initial registration and subsequent streaming `MapRequest`s — so peers
    /// running `tailscale ssh` against this node can populate their `known_hosts`
    /// automatically and verify the host key without a manual
    /// `ProxyCommand="tailscale nc %h %p"` fallback.
    ///
    /// The coordination-server transport (Noise) is itself authenticated by the
    /// node key, so the advertised SSH host keys are transitively signed by the
    /// node identity — clients trust them because they trust the node key, not
    /// because of a separate `NodeKeySignature` payload. That matches upstream's
    /// model: `SSH_HostKeys` is a hint about which SSH public keys the node will
    /// present, not a separately-signed claim.
    pub ssh_host_keys: Vec<String>,
}

impl Config {
    /// Get the full client name as a string.
    ///
    /// This takes the form `tailscale-rs ({client_name}) run={identity}`, where the
    /// parenthetical is only provided if `self.client_name` is set. The trailing `run=`
    /// token mirrors the identity folded into `HostInfo.ipn_version`; the admin console
    /// exposes `clientVersion` but not `app`, so carrying it in both is harmless redundancy
    /// that keeps the identity visible wherever the operator happens to look.
    pub fn format_client_name(&self) -> String {
        let mut full_name = "tailscale-rs".to_owned();
        if let Some(client_name) = &self.client_name {
            full_name.push_str(&format!(" ({client_name})"));
        }
        full_name.push(' ');
        full_name.push_str(crate::run_identity::run_identity());

        full_name
    }
}

impl Debug for Config {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Config")
            .field("hostname", &self.hostname)
            .field("server_url", &self.server_url.as_str())
            .field("client_name", &self.client_name)
            .finish()
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            server_url: DEFAULT_CONTROL_SERVER.clone(),
            hostname: gethostname::gethostname().into_string().ok(),
            client_name: None,
            tags: Default::default(),
            ssh_host_keys: Default::default(),
        }
    }
}
