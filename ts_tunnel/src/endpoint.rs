use core::time::Duration;
use std::{collections::HashMap, time::Instant};

use itertools::Itertools;
use ts_keys::{NodeKeyPair, NodePublicKey};
use ts_packet::PacketMut;
use ts_time::{Handle, Scheduler, TimeRange};
use zerocopy::IntoBytes;

use crate::{
    config::{PeerConfig, PeerId},
    handshake::{Handshake, ReceivedHandshake, initiate_handshake},
    ids::IdMap,
    macs::{MACReceiver, MACSender},
    messages::{CookieReply, HandshakeResponse, Message, MessageMut, SessionId},
    session::Session,
    time::{TAI64N, TAI64NClock},
};

/// If an endpoint hasn't sent any packets to a peer for `KEEPALIVE_TIMEOUT` after receiving a
/// packet from that peer, it must send an empty keepalive message so that the peer can distinguish
/// lack of activity from loss of session.
/// See: WireGuard spec, section 6.5
const KEEPALIVE_TIMEOUT: Duration = Duration::from_secs(10);

struct Peer {
    id: PeerId,
    config: PeerConfig,
    session: Session,
    handshake: Handshake,
    last_seen_timestamp: Option<TAI64N>,
    cookie_sender: MACSender,
    keepalive: Option<Handle<Event>>,
    session_cleanup: Option<Handle<Event>>,
    send_another_keepalive: bool,
}

impl Peer {
    fn new(id: PeerId, config: PeerConfig) -> Self {
        let macs = MACSender::new(&config.key);
        Self {
            id,
            config,
            session: Default::default(),
            handshake: Handshake::None,
            last_seen_timestamp: None,
            cookie_sender: macs,
            keepalive: None,
            session_cleanup: None,
            send_another_keepalive: false,
        }
    }

    fn schedule_keepalive(&mut self, scheduler: &mut Scheduler<Event>, now: Instant) {
        if self.keepalive.is_some() {
            self.send_another_keepalive = true;
            return;
        }
        let tr = TimeRange::new_around(now + KEEPALIVE_TIMEOUT, Duration::from_secs(1));
        self.keepalive = Some(scheduler.add(tr, Event::MaybeSendKeepalive(self.id)));
    }

    // TODO: consider replacing outparam with plain SendResult that supports merging.
    fn send(
        &mut self,
        endpoint: &mut EndpointState,
        packets: Vec<PacketMut>,
        now: Instant,
        out: &mut SendResult,
    ) {
        if let Some(mut packets) = self.session.send(packets, &mut endpoint.ids, now) {
            tracing::trace!("enqueueing packets to peer");
            out.queue_to_peer(self.id).append(&mut packets);
            // Fall through to check if the session is in need of rotation.
        }

        if self.handshake.is_active() {
            tracing::trace!("handshake is already in-flight, bail");
            return;
        }

        if !self.session.needs_handshake(now) {
            tracing::trace!("session does not need new handshake");
            return;
        }

        self.start_handshake(endpoint, now, out);
    }

    #[tracing::instrument(skip_all, fields(?session_id, n_packets = packets.len()))]
    fn recv(
        &mut self,
        endpoint: &mut EndpointState,
        session_id: SessionId,
        mut packets: Vec<PacketMut>,
        now: Instant,
        out: &mut RecvResult,
    ) {
        let pre_len = packets.len();

        packets.retain_mut(|packet| match MessageMut::try_from(packet.as_mut()) {
            Err(()) => {
                tracing::trace!("dropping invalid packet");
                false
            }
            Ok(MessageMut::TransportDataHeader(_)) => true,
            Ok(MessageMut::HandshakeResponse(resp)) => {
                self.recv_handshake_response(endpoint, resp, now, out);
                false
            }
            Ok(MessageMut::CookieReply(resp)) => {
                self.recv_cookie_reply(resp);
                false
            }
            Ok(MessageMut::HandshakeInitiation(_)) => {
                debug_assert!(
                    false,
                    "handshake initiations should have been filtered out prior to calling recv"
                );
                tracing::warn!("unexpected handshake init in recv");
                false
            }
        });

        let post_len = packets.len();
        if post_len != pre_len {
            tracing::trace!(n_dropped = pre_len - post_len, "dropped packets");
        }

        self.recv_transport_data(endpoint, session_id, packets, now, out);
    }

    fn recv_cookie_reply(&mut self, packet: &CookieReply) {
        let Handshake::Initiated(_, _, handshake_mac1) = &mut self.handshake else {
            tracing::trace!("dropping cookie reply received outside of handshake");
            return;
        };
        self.cookie_sender.receive_cookie(packet, handshake_mac1);
    }

    fn recv_handshake_response(
        &mut self,
        endpoint: &mut EndpointState,
        packet: &mut HandshakeResponse,
        now: Instant,
        out: &mut RecvResult,
    ) {
        let Some(session) = self.handshake.finish(
            packet,
            &endpoint.my_key,
            &self.config.psk,
            &endpoint.my_cookie,
            now,
        ) else {
            tracing::error!("handshake failed to complete");
            return;
        };

        let (expiry, mut packets) = self.session.activate(session, &mut endpoint.ids, now, true);
        out.queue_to_peer(self.id).append(&mut packets);
        if let Some(handle) = self.session_cleanup.take() {
            handle.cancel();
        };
        self.session_cleanup = Some(
            endpoint
                .scheduler
                .add(expiry, Event::ExpireSession(self.id)),
        );
    }

    fn recv_transport_data(
        &mut self,
        endpoint: &mut EndpointState,
        session_id: SessionId,
        packets: Vec<PacketMut>,
        now: Instant,
        out: &mut RecvResult,
    ) {
        if let Some(recv) = self.session.get_recv(session_id, &mut endpoint.ids, now) {
            let mut packets = recv.decrypt(packets);
            if !packets.is_empty() {
                out.queue_to_local(self.id).append(&mut packets);
                self.schedule_keepalive(&mut endpoint.scheduler, now);
                if self.session.needs_handshake(now) {
                    self.start_handshake(endpoint, now, out);
                }
            }
            return;
        }

        let Some((session, mut packets)) = self.handshake.confirm(session_id, packets) else {
            // TODO: log
            return;
        };

        out.queue_to_local(self.id).append(&mut packets);
        self.schedule_keepalive(&mut endpoint.scheduler, now);

        let (expiry, mut packets_for_peer) =
            self.session
                .activate(session, &mut endpoint.ids, now, false);
        if !packets_for_peer.is_empty() {
            out.queue_to_peer(self.id).append(&mut packets_for_peer);
        }
        if let Some(handle) = self.session_cleanup.take() {
            handle.cancel();
        }
        self.session_cleanup = Some(
            endpoint
                .scheduler
                .add(expiry, Event::ExpireSession(self.id)),
        );
    }

    fn respond_to_handshake(
        &mut self,
        endpoint: &mut EndpointState,
        handshake: ReceivedHandshake,
        now: Instant,
        out: &mut RecvResult,
    ) {
        if let Some(timestamp) = self.last_seen_timestamp
            && handshake.timestamp < timestamp
        {
            // Replayed handshake initiation
            // TODO: because we buffer the raw initiation packet on the sender side, we need to accept
            // initiations with an equal timestamp to the last one received. Check against reference
            // implementations and see if we should instead regenerate a fresh handshake with new timestamp
            // on retransmit.
            tracing::warn!("handshake replay detected, bailing out");
            return;
        }
        self.last_seen_timestamp = Some(handshake.timestamp);

        let session_id = endpoint.ids.allocate_session(self.id);

        let packet = self.handshake.respond(
            session_id,
            handshake,
            &self.config.psk,
            &self.cookie_sender,
            now,
        );
        out.queue_to_peer(self.id).push(packet);
    }

    fn handshake_timeout(
        &mut self,
        endpoint: &mut EndpointState,
        now: Instant,
        out: &mut EventResult,
    ) {
        if !self.handshake.is_active() {
            // Handshake completed prior to timeout firing.
            return;
        }

        endpoint.ids.remove_handshake_session(&self.handshake);
        self.handshake = Handshake::None;

        self.start_handshake(endpoint, now, out);
    }

    fn send_keepalive(
        &mut self,
        endpoint: &mut EndpointState,
        now: Instant,
        out: &mut EventResult,
    ) {
        let Some(packet) = self.session.send_keepalive(&mut endpoint.ids, now) else {
            tracing::trace!("send keepalive: session expired, skipping");
            return;
        };
        out.queue_to_peer(self.id).push(packet);

        self.keepalive = None;

        if self.send_another_keepalive {
            self.schedule_keepalive(&mut endpoint.scheduler, now);
            self.send_another_keepalive = false;
        }
    }

    fn cleanup_expired(&mut self, endpoint: &mut EndpointState, now: Instant) {
        self.session.cleanup_expired(&mut endpoint.ids, now)
    }

    fn shutdown(&mut self, endpoint: &mut EndpointState) {
        self.session.deactivate(&mut endpoint.ids);

        endpoint.ids.remove_handshake_session(&self.handshake);
        self.handshake = Handshake::None;
        if let Some(handle) = self.session_cleanup.take() {
            handle.cancel();
        }
        if let Some(handle) = self.keepalive.take() {
            handle.cancel();
        }
    }

    /// (Soft) precondition: `self.handshake == HandshakeState::None` (previous handshake is lost, but
    /// that shouldn't cause anything terrible to happen).
    fn start_handshake(
        &mut self,
        endpoint: &mut EndpointState,
        now: Instant,
        out: &mut impl QueueToPeer,
    ) {
        // TODO most of this logic might be better in the `handshake` module.
        let session_id = endpoint.ids.allocate_session(self.id);
        let (handshake, packet) = initiate_handshake(
            &endpoint.my_key,
            &self.config.key,
            session_id,
            endpoint.timestamps.now(),
        );

        let mut packet = PacketMut::from(packet.as_bytes());
        let mac = self.cookie_sender.write_macs(packet.as_mut());

        tracing::debug!(peer_id = ?self.id, ?session_id, "enqueue handshake start");

        out.queue_to_peer(self.id).push(packet);
        let tr = TimeRange::new_around(now + HANDSHAKE_TIMEOUT, Duration::from_millis(500));

        let timeout = endpoint.scheduler.add(tr, Event::HandshakeTimeout(self.id));
        self.handshake = Handshake::Initiated(handshake, timeout, mac);
    }
}

/// A WireGuard endpoint capable of communicating with multiple remote peers.
pub struct Endpoint {
    state: EndpointState,
    peers: HashMap<PeerId, Peer>,
}

struct EndpointState {
    my_key: NodeKeyPair,

    my_cookie: MACReceiver,
    ids: IdMap,
    timestamps: TAI64NClock,
    scheduler: Scheduler<Event>,
}

impl Endpoint {
    /// Construct a new endpoint with the given keypair.
    pub fn new(my_key: NodeKeyPair) -> Self {
        let my_cookie = MACReceiver::new(&my_key.public);
        Self {
            state: EndpointState {
                my_key,
                my_cookie,
                ids: Default::default(),
                timestamps: Default::default(),
                scheduler: Default::default(),
            },
            peers: HashMap::new(),
        }
    }

    /// Insert a peer if it doesn't exist, otherwise update the peer with the given `id`
    /// with the given config.
    ///
    /// Returns the old [`PeerConfig`] if there was one.
    ///
    /// # Panics
    ///
    /// If the [`NodePublicKey`] in the new [`PeerConfig`] collides with an existing key
    /// for a different [`PeerId`].
    pub fn upsert_peer(&mut self, id: PeerId, mut cfg: PeerConfig) -> Option<PeerConfig> {
        match self.peers.get_mut(&id) {
            Some(peer) => {
                if peer.config.key != cfg.key {
                    self.state.ids.remove_peer(&peer.config.key);
                    self.state.ids.add_peer(id, &cfg.key);
                }

                core::mem::swap(&mut peer.config, &mut cfg);
                Some(cfg)
            }
            None => {
                if !self.state.ids.add_peer(id, &cfg.key) {
                    panic!("nodekey collision");
                }

                self.peers.insert(id, Peer::new(id, cfg));
                None
            }
        }
    }

    /// Remove the given peer.
    ///
    /// Returns whether the peer in question existed.
    pub fn remove_peer(&mut self, peer: PeerId) -> bool {
        match self.peers.remove(&peer) {
            None => false,
            Some(mut peer) => {
                peer.shutdown(&mut self.state);
                self.state.ids.remove_peer(&peer.config.key);
                true
            }
        }
    }

    /// Send packets to peers.
    pub fn send(
        &mut self,
        now: Instant,
        packets: impl IntoIterator<Item = (PeerId, Vec<PacketMut>)>,
    ) -> SendResult {
        let mut ret = SendResult::default();
        for (peer_id, packets) in packets {
            let Some(peer) = self.peers.get_mut(&peer_id) else {
                tracing::warn!(?peer_id, "no peer stored for id");
                continue;
            };

            tracing::debug!(
                ?peer_id,
                n_packets = packets.len(),
                "processing send packets"
            );

            peer.send(&mut self.state, packets, now, &mut ret);
        }
        ret
    }

    /// Receive packets from peers.
    pub fn recv(
        &mut self,
        now: Instant,
        packets: impl IntoIterator<Item = PacketMut>,
    ) -> RecvResult {
        let mut ret = RecvResult::default();

        let mut packets = packets.into_iter().into_group_map_by(|packet| {
            u32::from(
                Message::try_from(packet.as_ref())
                    .ok()
                    .and_then(|message| message.receiver_id())
                    .unwrap_or_default(),
            )
        });

        let handshakes = packets.remove(&0).unwrap_or_default();
        if !handshakes.is_empty() {
            tracing::trace!(n = handshakes.len(), "processing handshakes");
        }

        for packet in handshakes {
            self.process_one_handshake(packet, now, &mut ret);
        }

        tracing::trace!(n = packets.len(), "processing packets");

        for (session_id, packets) in packets {
            let session_id = session_id.into();

            let Some(peer_id) = self.state.ids.get_by_session_id(&session_id) else {
                tracing::warn!(?session_id, "session not found");
                continue;
            };
            let Some(peer) = self.peers.get_mut(peer_id) else {
                tracing::warn!(?peer_id, "no peer found");
                continue;
            };

            peer.recv(&mut self.state, session_id, packets, now, &mut ret);
        }

        ret
    }

    fn process_one_handshake(&mut self, mut packet: PacketMut, now: Instant, out: &mut RecvResult) {
        let Ok(MessageMut::HandshakeInitiation(init)) = MessageMut::try_from(packet.as_mut())
        else {
            tracing::error!("message parsing failed");
            return;
        };
        let Some(handshake) =
            ReceivedHandshake::new(init, &self.state.my_key, &self.state.my_cookie)
        else {
            tracing::error!("parsing received handshake failed");
            return;
        };

        let Some(peer_id) = self.state.ids.get_by_nodekey(&handshake.peer_static()) else {
            tracing::error!(peer_key = %handshake.peer_static(), "no peer id stored for peer's key");
            return;
        };
        let Some(peer) = self.peers.get_mut(&peer_id) else {
            tracing::error!(?peer_id, "no peer entry for peer id");
            return;
        };

        peer.respond_to_handshake(&mut self.state, handshake, now, out)
    }

    /// Dispatch time-based events that are due to occur at or before the given instant.
    ///
    /// Use [`Endpoint::next_event`] to know when to call dispatch_events. It is inefficient but
    /// harmless to call it more frequently than specified by [`Endpoint::next_event`].
    pub fn dispatch_events(&mut self, now: Instant) -> EventResult {
        let mut out = EventResult::default();
        for event in self.state.scheduler.dispatch(now) {
            match event {
                Event::HandshakeTimeout(peer_id) => {
                    let Some(peer) = self.peers.get_mut(&peer_id) else {
                        continue;
                    };
                    peer.handshake_timeout(&mut self.state, now, &mut out);
                }
                Event::MaybeSendKeepalive(peer_id) => {
                    let Some(peer) = self.peers.get_mut(&peer_id) else {
                        continue;
                    };
                    peer.send_keepalive(&mut self.state, now, &mut out);
                }
                Event::ExpireSession(peer_id) => {
                    let Some(peer) = self.peers.get_mut(&peer_id) else {
                        continue;
                    };
                    peer.cleanup_expired(&mut self.state, now);
                }
            }
        }
        out
    }

    /// Returns the next time range in which [`Endpoint::dispatch_events`] should next be called to
    /// dispatch events.
    ///
    /// [`Endpoint::dispatch_events`] should be called at some point in the returned [`TimeRange`]
    /// to keep the wireguard state machine functioning correctly.
    ///
    /// See [`Scheduler::next_dispatch_range`] for additional details.
    pub fn next_event(&self) -> Option<TimeRange> {
        self.state.scheduler.next_dispatch_range()
    }

    /// Return the node key for the selected peer.
    pub fn peer_key(&self, id: PeerId) -> Option<NodePublicKey> {
        let peer = self.peers.get(&id)?;
        Some(peer.config.key)
    }

    /// Return the peer id that has the selected node key.
    pub fn peer_id(&self, key: NodePublicKey) -> Option<PeerId> {
        self.state.ids.get_by_nodekey(&key)
    }
}

trait QueueToPeer {
    fn queue_to_peer(&mut self, peer: PeerId) -> &mut Vec<PacketMut>;
}

/// The outcome of attempting to send packets to peers.
#[derive(Debug, Default, Eq, PartialEq)]
pub struct SendResult {
    /// Packets to be sent to remote peers.
    pub to_peers: HashMap<PeerId, Vec<PacketMut>>,
}

impl QueueToPeer for SendResult {
    fn queue_to_peer(&mut self, peer: PeerId) -> &mut Vec<PacketMut> {
        self.to_peers.entry(peer).or_default()
    }
}

/// The outcome of processing received packets.
#[derive(Debug, Default, Eq, PartialEq)]
pub struct RecvResult {
    /// Valid packets from peers to be delivered locally.
    pub to_local: HashMap<PeerId, Vec<PacketMut>>,
    /// Packets to be sent to remote peers.
    pub to_peers: HashMap<PeerId, Vec<PacketMut>>,
}

impl RecvResult {
    fn queue_to_local(&mut self, peer: PeerId) -> &mut Vec<PacketMut> {
        self.to_local.entry(peer).or_default()
    }
}

impl QueueToPeer for RecvResult {
    fn queue_to_peer(&mut self, peer: PeerId) -> &mut Vec<PacketMut> {
        self.to_peers.entry(peer).or_default()
    }
}

/// The outcome of processing an Event.
#[derive(Debug, Default, Eq, PartialEq)]
pub struct EventResult {
    /// Packets to be sent to remote peers.
    pub to_peers: HashMap<PeerId, Vec<PacketMut>>,
}

impl QueueToPeer for EventResult {
    fn queue_to_peer(&mut self, peer: PeerId) -> &mut Vec<PacketMut> {
        self.to_peers.entry(peer).or_default()
    }
}

/// An event that Endpoint needs to know about.
#[derive(Debug, Eq, PartialEq, PartialOrd, Ord, Copy, Clone)]
pub enum Event {
    /// Didn't receive a response to a handshake initiation.
    HandshakeTimeout(PeerId),
    /// Send a keepalive packet, if there was no recent outgoing traffic.
    MaybeSendKeepalive(PeerId),
    /// Clean up expired session state.
    ExpireSession(PeerId),
}

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);

#[cfg(test)]
mod tests {
    use zerocopy::TryFromBytes;

    use super::*;
    use crate::{
        config::PeerConfig,
        messages::{HandshakeInitiation, TransportDataHeader},
    };

    struct TestEndpoint {
        ep: Endpoint,
        public: NodePublicKey,
        next_peer_id: u32,
    }

    impl TestEndpoint {
        pub fn new() -> Self {
            let key = NodeKeyPair::new();
            let public = key.public;
            Self {
                ep: Endpoint::new(key),
                public,
                next_peer_id: 0,
            }
        }

        pub fn next_peer_id(&mut self) -> PeerId {
            let ret = PeerId(self.next_peer_id);
            self.next_peer_id += 1;
            ret
        }

        pub fn add_peer(&mut self, other: &mut TestEndpoint) -> (PeerId, PeerId) {
            let my_id = self.next_peer_id();
            let other_id = other.next_peer_id();
            let psk = rand::random();
            assert!(
                self.ep
                    .upsert_peer(
                        my_id,
                        PeerConfig {
                            key: other.public,
                            psk,
                        }
                    )
                    .is_none()
            );
            assert!(
                other
                    .ep
                    .upsert_peer(
                        other_id,
                        PeerConfig {
                            key: self.public,
                            psk,
                        }
                    )
                    .is_none()
            );
            (my_id, other_id)
        }

        pub fn send(
            &mut self,
            now: Instant,
            packets: HashMap<PeerId, Vec<PacketMut>>,
        ) -> SendResult {
            self.ep.send(now, packets)
        }

        pub fn recv(&mut self, now: Instant, packets: Vec<PacketMut>) -> RecvResult {
            self.ep.recv(now, packets)
        }
    }

    enum PacketMatcher {
        Any,
        Exact(PacketMut),
        Length(usize),
        HandshakeInitiation,
        HandshakeResponse,
        TransportData,
    }

    impl PacketMatcher {
        fn assert_matches(&self, packet: &PacketMut) {
            match self {
                PacketMatcher::Any => (),
                PacketMatcher::Length(len) => assert_eq!(packet.len(), *len),
                PacketMatcher::Exact(want) => assert_eq!(want, packet),
                PacketMatcher::HandshakeInitiation => {
                    HandshakeInitiation::try_ref_from_bytes(packet.as_ref()).unwrap();
                }
                PacketMatcher::HandshakeResponse => {
                    HandshakeResponse::try_ref_from_bytes(packet.as_ref()).unwrap();
                }
                PacketMatcher::TransportData => {
                    TransportDataHeader::try_ref_from_prefix(packet.as_ref()).unwrap();
                }
            }
        }
    }

    const HANDSHAKE_INIT: PacketMatcher = PacketMatcher::HandshakeInitiation;
    const HANDSHAKE_RESP: PacketMatcher = PacketMatcher::HandshakeResponse;
    const ENCRYPTED: PacketMatcher = PacketMatcher::TransportData;

    impl From<PacketMut> for PacketMatcher {
        fn from(v: PacketMut) -> Self {
            PacketMatcher::Exact(v)
        }
    }

    impl From<usize> for PacketMatcher {
        fn from(v: usize) -> Self {
            PacketMatcher::Length(v)
        }
    }

    impl From<()> for PacketMatcher {
        fn from(_v: ()) -> Self {
            PacketMatcher::Any
        }
    }

    #[derive(Default)]
    struct PacketMapMatcher(HashMap<PeerId, Vec<PacketMatcher>>);

    impl PacketMapMatcher {
        fn assert_matches(&self, packets: &HashMap<PeerId, Vec<PacketMut>>) {
            for (id, packets) in packets.iter() {
                let Some(matchers) = self.0.get(id) else {
                    panic!("expected packets for {:?}, found none", id);
                };
                for (packet, matcher) in packets.iter().zip(matchers) {
                    matcher.assert_matches(packet);
                }
            }
            for id in self.0.keys() {
                assert!(packets.contains_key(id));
            }
        }
    }

    macro_rules! packets {
        ($($key:expr => [$($value:expr),*]),* $(,)?) => {
            {
                let mut m: HashMap<PeerId, Vec<PacketMut>> = Default::default();
                $(m.insert($key, vec![$($value),*]);)*
                m
            }
        };
    }

    macro_rules! assert_packets {
        ($got:expr, {$($peer_id:expr => [$($matcher:expr),*]),* $(,)?}) => {
            let mut m: PacketMapMatcher = Default::default();
            $(m.0.insert($peer_id, vec![$(PacketMatcher::from($matcher)),*]);)*
            m.assert_matches(&$got);
        };
    }

    pub fn packet(v: u8) -> PacketMut {
        PacketMut::from(vec![v; 4])
    }

    struct TestClock {
        start: Instant,
    }

    impl TestClock {
        pub fn new() -> Self {
            Self {
                start: Instant::now(),
            }
        }

        pub fn at(&self, secs: u64) -> Instant {
            self.start + Duration::from_secs(secs)
        }
    }

    #[test]
    fn test_one_peer() {
        let (mut a, mut b) = (TestEndpoint::new(), TestEndpoint::new());
        let t = TestClock::new();
        let (b_id, a_id) = a.add_peer(&mut b);

        // A sends to B. Results in a handshake initiation being transmitted, not the
        // requested packet (which gets buffered internally by the endpoint).
        let a_acts = a.send(
            t.at(0),
            packets! {
                b_id => [packet(1), packet(2)]
            },
        );
        assert_packets!(a_acts.to_peers, {
            b_id => [HANDSHAKE_INIT],
        });

        // A sends another packet. No activity on the wire.
        let a_acts2 = a.send(
            t.at(1),
            packets! {
                b_id => [packet(3)],
            },
        );
        assert!(a_acts2.to_peers.is_empty());

        // B processes the handshake and responds. No packets delivered to B.
        let b_acts = b.recv(t.at(2), a_acts.to_peers[&b_id].clone());
        assert!(b_acts.to_local.is_empty());
        assert_packets!(b_acts.to_peers, {
            a_id => [HANDSHAKE_RESP],
        });

        // A processes the response, and sends its queued packets.
        let a_acts = a.recv(t.at(3), b_acts.to_peers[&a_id].clone());
        assert!(a_acts.to_local.is_empty());
        assert_packets!(a_acts.to_peers, {
            b_id => [ENCRYPTED, ENCRYPTED, ENCRYPTED],
        });

        // B receives
        let b_acts = b.recv(t.at(4), a_acts.to_peers[&b_id].clone());
        assert_packets!(b_acts.to_local, {
            a_id => [packet(1), packet(2), packet(3)],
        });
        assert!(b_acts.to_peers.is_empty());

        // B sends
        let b_acts = b.send(
            t.at(5),
            packets! {
                a_id => [packet(4)],
            },
        );
        assert_packets!(b_acts.to_peers, {
            a_id => [ENCRYPTED],
        });

        // A receives
        let a_acts = a.recv(t.at(6), b_acts.to_peers[&a_id].clone());
        assert_packets!(a_acts.to_local, {
            a_id => [packet(4)],
        });
        assert!(a_acts.to_peers.is_empty());
    }

    #[test]
    fn test_rotation_initiator() {
        let (mut a, mut b) = (TestEndpoint::new(), TestEndpoint::new());
        let t = TestClock::new();
        let (b_id, a_id) = a.add_peer(&mut b);

        // A sends a packet, which causes a handshake.
        let a_acts = a.send(
            t.at(0),
            packets! {
                b_id => [packet(1)],
            },
        );
        assert_packets!(a_acts.to_peers, {
            b_id => [HANDSHAKE_INIT],
        });

        let b_acts = b.recv(t.at(1), a_acts.to_peers[&b_id].clone());
        assert!(b_acts.to_local.is_empty());
        assert_packets!(b_acts.to_peers, {
            a_id => [HANDSHAKE_RESP],
        });

        let a_acts = a.recv(t.at(2), b_acts.to_peers[&a_id].clone());
        assert!(a_acts.to_local.is_empty());
        assert_packets!(a_acts.to_peers, {
            b_id => [ENCRYPTED],
        });

        let b_acts = b.recv(t.at(3), a_acts.to_peers[&b_id].clone());
        assert_packets!(b_acts.to_local, {
            a_id => [packet(1)],
        });
        assert!(b_acts.to_peers.is_empty());

        // After session becomes stale, A sends a packet, causing a new handshake.
        let a_acts = a.send(
            t.at(121),
            packets! {
                b_id => [packet(2)],
            },
        );
        assert_packets!(a_acts.to_peers, {
            b_id => [ENCRYPTED, HANDSHAKE_INIT],
        });

        // B receives and processes new handshake in parallel
        let b_acts = b.recv(t.at(122), a_acts.to_peers[&b_id].clone());
        assert_packets!(b_acts.to_local, {
            a_id => [packet(2)],
        });
        assert_packets!(b_acts.to_peers, {
            a_id => [HANDSHAKE_RESP],
        });

        // A completes handshake, sends empty confirmation packet
        let a_acts = a.recv(t.at(123), b_acts.to_peers[&a_id].clone());
        assert!(a_acts.to_local.is_empty());
        assert_packets!(a_acts.to_peers, {
            b_id => [ENCRYPTED],
        });

        // B finalizes rotation.
        let b_acts = a.recv(t.at(124), a_acts.to_peers[&b_id].clone());
        assert!(b_acts.to_local.is_empty());
        assert!(b_acts.to_peers.is_empty());
    }

    #[test]
    fn test_rotation_responder() {
        let (mut a, mut b) = (TestEndpoint::new(), TestEndpoint::new());
        let t = TestClock::new();
        let (b_id, a_id) = a.add_peer(&mut b);

        // A sends a packet, which causes a handshake.
        let a_acts = a.send(
            t.at(0),
            packets! {
                b_id => [packet(1)],
            },
        );
        assert_packets!(a_acts.to_peers, {
            b_id => [HANDSHAKE_INIT],
        });

        let b_acts = b.recv(t.at(1), a_acts.to_peers[&b_id].clone());
        assert!(b_acts.to_local.is_empty());
        assert_packets!(b_acts.to_peers, {
            a_id => [HANDSHAKE_RESP],
        });

        let a_acts = a.recv(t.at(2), b_acts.to_peers[&a_id].clone());
        assert!(a_acts.to_local.is_empty());
        assert_packets!(a_acts.to_peers, {
            b_id => [ENCRYPTED],
        });

        let b_acts = b.recv(t.at(3), a_acts.to_peers[&b_id].clone());
        assert_packets!(b_acts.to_local, {
            a_id => [packet(1)],
        });
        assert!(b_acts.to_peers.is_empty());

        // After session becomes stale, B sends a packet.
        let b_acts = b.send(
            t.at(121),
            packets! {
                a_id => [packet(2)],
            },
        );
        assert_packets!(b_acts.to_peers, {
            a_id => [ENCRYPTED],
        });

        // A receives and starts a new handshake.
        let a_acts = a.recv(t.at(122), b_acts.to_peers[&a_id].clone());
        assert_packets!(a_acts.to_local, {
            b_id => [packet(2)],
        });
        assert_packets!(a_acts.to_peers, {
            b_id => [HANDSHAKE_INIT],
        });

        // B processes new handshake.
        let b_acts = b.recv(t.at(123), a_acts.to_peers[&b_id].clone());
        assert!(b_acts.to_local.is_empty());
        assert_packets!(b_acts.to_peers, {
            a_id => [HANDSHAKE_RESP],
        });

        // A completes handshake, sends empty confirmation packet.
        let a_acts = a.recv(t.at(124), b_acts.to_peers[&a_id].clone());
        assert!(a_acts.to_local.is_empty());
        assert_packets!(a_acts.to_peers, {
            b_id => [ENCRYPTED],
        });

        // B finalizes handshake
        let b_acts = b.recv(t.at(125), a_acts.to_peers[&b_id].clone());
        assert!(b_acts.to_local.is_empty());
        assert!(b_acts.to_peers.is_empty());
    }
}
