/// Default TCP **receive** buffer size (bytes). smoltcp 0.13 derives the advertised TCP
/// window scale factor from the rx buffer capacity at socket creation
/// (`remote_win_shift = log2(rx_cap) - 16`), so this figure directly sets the advertised
/// window and thus the throughput×RTT ceiling of the *inbound* direction (admin→box push).
/// 256 KiB lifts the window well past the old 16 KiB that capped relayed SSH at ~40–70 KB/s.
pub const DEFAULT_TCP_RX_BUFFER_SIZE: usize = 256 * 1024;

/// Default TCP **transmit** buffer size (bytes). Caps how much unacknowledged data the
/// box can have in flight outbound (box→admin), i.e. the box's own send ceiling.
pub const DEFAULT_TCP_TX_BUFFER_SIZE: usize = 256 * 1024;

/// Default half-open (`SYN-RECEIVED`) backlog per TCP listener. Kept small because the
/// buffers are now 16× larger — see [`Config::tcp_half_open_backlog`] for the memory math.
pub const DEFAULT_TCP_HALF_OPEN_BACKLOG: usize = 32;

/// Environment variable overriding [`DEFAULT_TCP_RX_BUFFER_SIZE`] at [`Config::default`] time.
pub const TCP_RX_BUFFER_SIZE_ENV: &str = "TS_TCP_RX_BUFFER_SIZE";
/// Environment variable overriding [`DEFAULT_TCP_TX_BUFFER_SIZE`] at [`Config::default`] time.
pub const TCP_TX_BUFFER_SIZE_ENV: &str = "TS_TCP_TX_BUFFER_SIZE";
/// Environment variable overriding [`DEFAULT_TCP_HALF_OPEN_BACKLOG`] at [`Config::default`] time.
pub const TCP_HALF_OPEN_BACKLOG_ENV: &str = "TS_TCP_HALF_OPEN_BACKLOG";

/// Parse an optional raw environment value into a positive `usize`, falling back to
/// `default` on absence, empty/whitespace, a parse failure, or a non-positive value.
///
/// A zero-sized buffer or backlog would break smoltcp, so `0` is treated as invalid and
/// falls back — these run on customer boxes, a bad env value must never panic or wedge.
/// Pure (takes the value, not the process env) so it is unit-testable without a global
/// env race in a parallel suite.
fn parse_positive_usize(raw: Option<&str>, default: usize) -> usize {
    raw.and_then(|v| v.trim().parse::<usize>().ok())
        .filter(|&n| n > 0)
        .unwrap_or(default)
}

/// Read a positive-`usize` override from the environment, falling back to `default`.
///
/// Env reading needs `std`; under `no_std` (the default of this crate) there is no
/// process environment, so the compiled-in `default` is returned unchanged. The deployed
/// binary pulls this crate in with the `std` feature on (via
/// `ts_netstack_smoltcp[tokio]`), so production picks up the env overrides automatically.
#[cfg(feature = "std")]
fn size_from_env(name: &str, default: usize) -> usize {
    parse_positive_usize(std::env::var(name).ok().as_deref(), default)
}

#[cfg(not(feature = "std"))]
fn size_from_env(_name: &str, default: usize) -> usize {
    default
}

/// Netstack configuration.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Config {
    /// Capacity of the command channel.
    ///
    /// If `None`, the channel is unbounded.
    pub command_channel_capacity: Option<usize>,

    /// Maximum transmission unit of the underlying net device.
    pub mtu: usize,

    /// Assign the IPv4 and IPv6 loopback addresses to the interface.
    pub loopback: bool,

    /// The default size of buffer allocated for each UDP socket created.
    pub udp_buffer_size: usize,
    /// The default number of pending messages supported for each UDP socket created.
    pub udp_message_count: usize,

    /// The default **receive** buffer size allocated for each TCP socket created.
    ///
    /// smoltcp derives the advertised TCP window scale factor from this capacity at socket
    /// creation, so it sets the inbound (peer→us) throughput×RTT ceiling. This is the weak
    /// direction over a DERP relay — bigger rx buffer = bigger window = faster admin→box
    /// pushes.
    pub tcp_rx_buffer_size: usize,

    /// The default **transmit** buffer size allocated for each TCP socket created.
    ///
    /// Caps how much unacknowledged data may be in flight outbound (us→peer).
    pub tcp_tx_buffer_size: usize,

    /// Maximum number of half-open (`SYN-RECEIVED`) connections a single TCP listener will
    /// retain while awaiting completion of their three-way handshake.
    ///
    /// Each half-open connection holds a full `socket_set` slot plus a `tcp_rx_buffer_size`
    /// and a `tcp_tx_buffer_size` buffer, so an unbounded backlog lets a flood of
    /// never-completed handshakes (or a burst of clients that vanish mid-handshake — i.e.
    /// connection churn) grow memory and per-poll cost without limit. When the backlog
    /// exceeds this cap, the oldest half-open connection is reaped (its socket removed and
    /// buffers freed) to make room, bounding a listener's half-open footprint to
    /// `tcp_half_open_backlog * (tcp_rx_buffer_size + tcp_tx_buffer_size)`.
    ///
    /// Worst-case per-listener with the defaults: `32 * (256 KiB + 256 KiB) = 16 MiB`; a
    /// greenhouse box runs two `ssh_shell` processes, so `~32 MiB` — within the memory
    /// budget of an old 2–4 GiB Win7 box.
    pub tcp_half_open_backlog: usize,

    /// The default size of buffer allocated for each raw socket.
    pub raw_buffer_size: usize,
    /// The default number of pending messages supported for each raw socket.
    pub raw_message_count: usize,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            command_channel_capacity: Some(32),

            mtu: 1500,

            loopback: false,

            udp_buffer_size: 1024 * 4,
            udp_message_count: 32,

            // rx drives the advertised window (inbound ceiling); tx caps outbound in-flight.
            // Env-overridable per box (constrained box dials down, dev/Azure VM runs big);
            // a bad value falls back rather than panicking on a customer box.
            tcp_rx_buffer_size: size_from_env(TCP_RX_BUFFER_SIZE_ENV, DEFAULT_TCP_RX_BUFFER_SIZE),
            tcp_tx_buffer_size: size_from_env(TCP_TX_BUFFER_SIZE_ENV, DEFAULT_TCP_TX_BUFFER_SIZE),

            // Half-open footprint = backlog × (rx + tx). With 256 KiB buffers, 32 keeps a
            // single listener's worst case at 32 × 512 KiB = 16 MiB (× 2 processes/box =
            // 32 MiB) — still above Linux's default somaxconn of 128 for legitimate bursts
            // once handshakes complete, and env-overridable for a heavily constrained box.
            tcp_half_open_backlog: size_from_env(
                TCP_HALF_OPEN_BACKLOG_ENV,
                DEFAULT_TCP_HALF_OPEN_BACKLOG,
            ),

            raw_buffer_size: 1024 * 4,
            raw_message_count: 32,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_pins_the_256kib_window_budget() {
        // Arrange + Act: the deployed default with no env overrides set.
        let cfg = Config::default();

        // Assert: the pinned window/buffer/backlog budget the P2 baselines agreed on.
        assert_eq!(cfg.tcp_rx_buffer_size, 256 * 1024, "rx buffer = advertised window");
        assert_eq!(cfg.tcp_tx_buffer_size, 256 * 1024, "tx buffer = outbound in-flight cap");
        assert_eq!(cfg.tcp_half_open_backlog, 32, "half-open backlog");
        assert_eq!(cfg.mtu, 1500, "mtu unchanged this commit (MTU-1280 is a later canary)");
    }

    #[test]
    fn parse_positive_usize_falls_back_unless_a_positive_number_is_given() {
        let scenarios = [
            ("absent uses default", None, 256usize, 256usize),
            ("valid number overrides default", Some("1024"), 256, 1024),
            ("surrounding whitespace is trimmed", Some("  512  "), 256, 512),
            ("empty string falls back", Some(""), 256, 256),
            ("non-numeric falls back", Some("big"), 256, 256),
            ("zero falls back (would break smoltcp)", Some("0"), 256, 256),
            ("negative falls back", Some("-1"), 256, 256),
        ];
        for (desc, raw, default, expected) in scenarios {
            assert_eq!(parse_positive_usize(raw, default), expected, "{desc}");
        }
    }
}
