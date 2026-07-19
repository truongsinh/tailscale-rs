use alloc::vec;

use smoltcp::socket::tcp;

use crate::Netstack;

mod listener;
mod stream;

pub use listener::{ListenerHandle, TcpListenerState};

impl Netstack {
    /// Receive buffer for a new TCP socket. Its capacity sets the advertised TCP window
    /// (smoltcp derives the window scale factor from it at socket creation), so this caps
    /// the inbound throughput×RTT ceiling.
    fn tcp_rx_buffer(&self) -> tcp::SocketBuffer<'static> {
        tcp::SocketBuffer::new(vec![0; self.config.tcp_rx_buffer_size])
    }

    /// Transmit buffer for a new TCP socket. Caps outbound unacknowledged data in flight.
    fn tcp_tx_buffer(&self) -> tcp::SocketBuffer<'static> {
        tcp::SocketBuffer::new(vec![0; self.config.tcp_tx_buffer_size])
    }
}
