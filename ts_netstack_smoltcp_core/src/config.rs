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

    /// The default size of buffer allocated for each TCP socket created.
    pub tcp_buffer_size: usize,

    /// Maximum number of half-open (`SYN-RECEIVED`) connections a single TCP listener will
    /// retain while awaiting completion of their three-way handshake.
    ///
    /// Each half-open connection holds a full `socket_set` slot plus two `tcp_buffer_size`
    /// buffers, so an unbounded backlog lets a flood of never-completed handshakes (or a
    /// burst of clients that vanish mid-handshake — i.e. connection churn) grow memory and
    /// per-poll cost without limit. When the backlog exceeds this cap, the oldest half-open
    /// connection is reaped (its socket removed and buffers freed) to make room, bounding a
    /// listener's half-open footprint to `tcp_half_open_backlog * 2 * tcp_buffer_size`.
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

            tcp_buffer_size: 1024 * 16,

            // A generous SYN backlog (well above Linux's default somaxconn of 128) — large
            // enough never to reject a legitimate burst of concurrent SSH connects, small
            // enough that a flood is bounded to ~8 MiB/listener (256 * 2 * 16 KiB).
            tcp_half_open_backlog: 256,

            raw_buffer_size: 1024 * 4,
            raw_message_count: 32,
        }
    }
}
