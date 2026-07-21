//! Disco protocol message handler.
//!
//! Kameo actor that subscribes to [`IncomingDiscoMsg`] events published by
//! [`crate::dataplane::DataplaneActor`] on the bus and handles incoming Disco
//! messages. Currently handles [`Ping`] → [`Pong`] responses so that
//! `tailscale ping` works against this node in userspace-networking (DERP-relayed)
//! mode.
//!
//! # Architecture (post upstream sync)
//!
//! Pre-merge, the fork's [`DataplaneActor::on_start`] captured the `disco_rx`
//! channel directly and spawned this handler as a free `async fn` task that
//! polled it. Upstream commit `95a5a08` ("runtime/dataplane: forward stun, disco
//! streams") replaced that with a bus-publish pattern: the dataplane attaches the
//! `disco_rx` as a kameo `attach_stream`, decrypts each batch inline, and publishes
//! the decrypted [`Packet<Plaintext>`] to the bus as [`IncomingDiscoMsg`].
//!
//! This handler was refactored to fit that pattern: it now subscribes to
//! [`IncomingDiscoMsg`] (decrypted packets) and [`Arc<PeerState>`] (peer-db
//! snapshots used to map sender DiscoPublicKey → PeerId) instead of consuming
//! the raw channel. The parse/decrypt step is no longer needed here — upstream
//! already did it.
//!
//! # Magic bytes
//!
//! Upstream commit `87601a8` ("disco: set magic on packet encrypt") fixed
//! [`Packet::encrypt_in_place`] to call `Header::new(...)`, which sets the magic
//! bytes correctly. Before that fix, this handler had to manually pre-fill the
//! magic bytes in [`build_pong`]; that workaround is now removed (it would write
//! the same bytes twice).

use std::{
    net::{IpAddr, Ipv6Addr, SocketAddr},
    sync::{Arc, RwLock},
};

use crypto_box::aead::{AeadCore, OsRng};
use kameo::{
    actor::ActorRef,
    message::{Context, Message},
};
use ts_dataplane::async_tokio::DataPlane;
use ts_disco_protocol::{Header, MessageType, Packet, Ping, Pong};
use ts_keys::{DiscoKeyPair, DiscoPublicKey};
use ts_packet::PacketMut;
use ts_transport::PeerId;

use crate::{
    dataplane::IncomingDiscoMsg,
    env::Env,
    peer_tracker::{PeerDb, PeerState},
    Error,
};

/// Type alias for the shared peer-db handle used by the disco handler.
///
/// Mirrors the pattern in [`crate::multiderp::uniderp`]: `None` until the first
/// [`PeerState`] update arrives.
type SharedPeerDb = Arc<RwLock<Option<Arc<PeerDb>>>>;

/// Kameo actor that handles incoming Disco messages (Ping → Pong).
///
/// Subscribes to:
/// - [`IncomingDiscoMsg`] — decrypted Disco packets from [`crate::dataplane::DataplaneActor`]
/// - [`Arc<PeerState>`] — peer-db snapshots for sender-key → PeerId routing
///
/// Spawned as a supervised child of [`crate::dataplane::DataplaneActor`] in its
/// `on_start`. The disco keys and dataplane handle come from the parent; the
/// peer_db is maintained internally from bus events.
pub struct DiscoHandlerActor {
    disco_keys: DiscoKeyPair,
    peer_db: SharedPeerDb,
    dataplane: Arc<DataPlane>,
}

impl kameo::Actor for DiscoHandlerActor {
    type Args = (Env, DiscoKeyPair, Arc<DataPlane>);
    type Error = Error;

    async fn on_start(
        (env, disco_keys, dataplane): Self::Args,
        slf: ActorRef<Self>,
    ) -> Result<Self, Self::Error> {
        // Decrypted Disco packets from the dataplane's bus publish.
        env.subscribe::<IncomingDiscoMsg>(&slf).await?;
        // Peer-state updates so we can map sender DiscoKey → PeerId.
        env.subscribe::<Arc<PeerState>>(&slf).await?;

        tracing::trace!("disco handler actor started");
        Ok(Self {
            disco_keys,
            peer_db: Arc::new(RwLock::new(None)),
            dataplane,
        })
    }
}

impl Message<IncomingDiscoMsg> for DiscoHandlerActor {
    type Reply = ();

    async fn handle(
        &mut self,
        msg: IncomingDiscoMsg,
        _ctx: &mut Context<Self, Self::Reply>,
    ) {
        let pkt = msg.0.get(); // &Packet<Plaintext>
        match handle_plaintext(pkt, &self.disco_keys, &self.peer_db) {
            Ok(Some((peer_id, pong))) => {
                tracing::trace!(%peer_id, "disco Ping from peer — sending Pong");
                self.dataplane.send_raw_to_underlay(peer_id, pong).await;
            }
            Ok(None) => {
                // Not a Ping (CallMeMaybe, future message types, etc.) or peer
                // not yet known. Nothing to send back.
            }
            Err(e) => {
                tracing::trace!(error = %e, "disco handler: skipping packet");
            }
        }
    }
}

impl Message<Arc<PeerState>> for DiscoHandlerActor {
    type Reply = ();

    async fn handle(
        &mut self,
        state: Arc<PeerState>,
        _ctx: &mut Context<Self, Self::Reply>,
    ) {
        // Replace the entire peer_db snapshot on each update.
        if let Ok(mut slot) = self.peer_db.write() {
            *slot = Some(state.peers.clone());
        }
    }
}

/// Result of handling a decrypted Disco packet.
///
/// `Ok(Some((peer_id, pong_pkt)))` means the packet was a Ping from a known peer
/// and a Pong response was constructed, ready to be sent to `peer_id`.
/// `Ok(None)` means the packet needs no response (not a Ping, or peer unknown).
type HandleResult = Result<Option<(PeerId, PacketMut)>, &'static str>;

/// Handle a decrypted Disco [`Packet<Plaintext>`]. If it's a Ping from a known
/// peer, build a Pong response ready to route.
///
/// Pre-merge, this was `handle_one(&PacketMut, ...)` which did parse + decrypt;
/// upstream's #288 + #229 redesigns the dataplane to do parse + decrypt inline
/// and publish the decrypted packet to the bus, so this function takes the
/// post-decrypt shape directly.
fn handle_plaintext(
    pkt: &Packet<ts_disco_protocol::Plaintext>,
    disco_keys: &DiscoKeyPair,
    peer_db: &SharedPeerDb,
) -> HandleResult {
    // Only Ping requires a response today.
    if pkt.ty() != Some(MessageType::Ping) {
        tracing::trace!(ty = ?pkt.ty(), "disco non-Ping message — dropping");
        return Ok(None);
    }

    let ping = pkt.as_msg::<Ping>().ok_or("failed to parse Ping payload")?;
    let sender_disco: &DiscoPublicKey = pkt.sender_pubkey();

    // Look up the sender's PeerId via their DiscoPublicKey.
    let peer_id = {
        let guard = peer_db.read().map_err(|_| "peer_db lock poisoned")?;
        let Some(db) = guard.as_ref() else {
            // PeerDb not yet populated (no control-plane state update yet).
            return Ok(None);
        };
        let Some((id, _node)) = db.get(sender_disco) else {
            tracing::trace!(
                ?sender_disco,
                "disco Ping from peer not in PeerDb — cannot route Pong",
            );
            return Ok(None);
        };
        id
    };

    let pong_pkt = build_pong(&ping.tx_id, disco_keys, sender_disco)?;
    Ok(Some((peer_id, pong_pkt)))
}

/// Build an encrypted [`Pong`] packet echoing the supplied `tx_id`, encrypted from
/// `our_keys.private` to `their_disco`.
///
/// After upstream's #288 fix (`Packet::encrypt_in_place` now calls `Header::new`
/// which sets magic correctly), no manual magic pre-fill is needed.
fn build_pong(
    tx_id: &[u8; 12],
    our_keys: &DiscoKeyPair,
    their_disco: &DiscoPublicKey,
) -> Result<PacketMut, &'static str> {
    // Src: for DERP-relayed disco pings, we don't know our own source address as
    // observed by the peer through the relay, so we report the unspecified address
    // (port 0). The official Tailscale client reports the DERP magic IP + region
    // port; the field is only used for NAT traversal of direct UDP paths, which
    // DERP-relayed traffic never engages.
    let unspecified = SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0);

    let pong_size = Pong::size();
    let total = Packet::<ts_disco_protocol::Plaintext>::size_for_message(pong_size);
    let mut out = vec![0u8; total];

    // Initialize the plaintext Pong payload. init_from_bytes does not touch the
    // header; encrypt_in_place (below) sets the entire header (magic, sender_pub,
    // nonce) via Header::new() after upstream commit 87601a8.
    let pt = Packet::<ts_disco_protocol::Plaintext>::init_from_bytes::<Pong>(&mut out, |pong| {
        pong.tx_id = *tx_id;
        pong.src = unspecified.into();
    })
    .map_err(|_| "failed to init Pong plaintext")?;

    // Random nonce for this response.
    let nonce = crypto_box::SalsaBox::generate_nonce(&mut OsRng);
    let mut nonce_arr = [0u8; Header::NONCE_LEN];
    nonce_arr.copy_from_slice(nonce.as_ref());

    // Encrypt in place: our private key + their public key → ciphertext for them.
    pt.encrypt_in_place(&our_keys.private, their_disco, nonce_arr)
        .map_err(|_| "failed to encrypt Pong")?;

    Ok(PacketMut::from(out))
}

#[cfg(test)]
mod test {
    use crypto_box::aead::{AeadCore, OsRng};
    use ts_disco_protocol::{Encrypted, Header, MessageType, Packet, Ping, Pong};
    use ts_keys::{DiscoKeyPair, DiscoPublicKey};

    use super::build_pong;

    /// Build a Disco Ping packet from `sender` to `receiver`, encrypted for
    /// `receiver`'s private key. Returns the on-wire bytes.
    fn build_ping_packet(
        sender: &DiscoKeyPair,
        receiver: &DiscoPublicKey,
        tx_id: &[u8; 12],
        node_key_padding: &[u8],
    ) -> Vec<u8> {
        let ping_size = Ping::size_with_padding(node_key_padding.len());
        let total = Packet::<ts_disco_protocol::Plaintext>::size_for_message(ping_size);
        let mut buf = vec![0u8; total];

        // Pre-fill magic so the packet round-trips through from_encrypted_bytes
        // (encrypt_in_place sets it via Header::new, but only after the init step
        // reinterprets the buffer; the test needs the magic present up-front).
        buf[..Header::MAGIC.len()].copy_from_slice(&Header::MAGIC);

        let pt = Packet::<ts_disco_protocol::Plaintext>::init_from_bytes::<Ping>(&mut buf, |ping| {
            ping.tx_id = *tx_id;
            // node_key field — contents don't matter for the test, only that it
            // parses. Use a random public key from a fresh NodeKeyPair.
            ping.node_key = ts_keys::NodeKeyPair::new().public;
        })
        .expect("init Ping plaintext");

        let nonce = crypto_box::SalsaBox::generate_nonce(&mut OsRng);
        let mut nonce_arr = [0u8; Header::NONCE_LEN];
        nonce_arr.copy_from_slice(nonce.as_ref());

        pt.encrypt_in_place(&sender.private, receiver, nonce_arr)
            .expect("encrypt Ping");

        buf
    }

    /// Round-trip: sender builds a Ping, handler decrypts and produces a Pong,
    /// sender decrypts the Pong and checks tx_id.
    #[test]
    fn pong_echoes_ping_tx_id() {
        let responder_keys = DiscoKeyPair::new();
        let sender_keys = DiscoKeyPair::new();

        // Sender builds a Ping addressed to responder's disco public key.
        let tx_id = [0xAB; 12];
        let ping_bytes =
            build_ping_packet(&sender_keys, &responder_keys.public, &tx_id, &[0u8; 32]);

        // Responder's handler decrypts and builds a Pong.
        let mut buf = ping_bytes.clone();
        let enc = Packet::<Encrypted>::from_encrypted_bytes_mut(&mut buf).unwrap();
        let dec = enc.decrypt_in_place(&responder_keys.private).unwrap();
        assert_eq!(dec.ty(), Some(MessageType::Ping));

        let ping_msg = dec.as_msg::<Ping>().unwrap();
        assert_eq!(ping_msg.tx_id, tx_id);

        let pong_pkt = build_pong(&ping_msg.tx_id, &responder_keys, &sender_keys.public).unwrap();

        // Sender decrypts the Pong and checks the tx_id matches.
        let mut pong_buf = pong_pkt.as_ref().to_vec();
        let pong_enc = Packet::<Encrypted>::from_encrypted_bytes_mut(&mut pong_buf).unwrap();
        let pong_dec = pong_enc.decrypt_in_place(&sender_keys.private).unwrap();
        assert_eq!(pong_dec.ty(), Some(MessageType::Pong));

        let pong_msg = pong_dec.as_msg::<Pong>().unwrap();
        assert_eq!(pong_msg.tx_id, tx_id, "Pong tx_id must match Ping tx_id");
    }

    /// `build_pong` must always emit a packet whose header carries our disco public key.
    #[test]
    fn pong_header_carries_responder_disco_key() {
        let responder = DiscoKeyPair::new();
        let requester = DiscoKeyPair::new();

        let pong = build_pong(&[1u8; 12], &responder, &requester.public).unwrap();

        let mut buf = pong.as_ref().to_vec();
        let enc = Packet::<Encrypted>::from_encrypted_bytes_mut(&mut buf).unwrap();
        assert_eq!(
            enc.sender_pubkey(),
            &responder.public,
            "Pong sender must be the responder, not the requester",
        );
    }

    /// Two consecutive Pongs must use different nonces (OsRng not stuck).
    ///
    /// The nonce field is private to `ts_disco_protocol::Header`, so compare the raw
    /// bytes at the known offset: magic (6) + sender_pub (32) = 38, nonce is 24 bytes.
    #[test]
    fn pong_uses_fresh_nonce_per_call() {
        let responder = DiscoKeyPair::new();
        let requester = DiscoKeyPair::new();

        let p1 = build_pong(&[1u8; 12], &responder, &requester.public).unwrap();
        let p2 = build_pong(&[2u8; 12], &responder, &requester.public).unwrap();

        // Header layout: magic[6] + sender_pub[32] + nonce[24]
        const NONCE_OFFSET: usize = 6 + 32;
        const NONCE_LEN: usize = 24;

        let n1 = &p1.as_ref()[NONCE_OFFSET..NONCE_OFFSET + NONCE_LEN];
        let n2 = &p2.as_ref()[NONCE_OFFSET..NONCE_OFFSET + NONCE_LEN];

        assert_ne!(n1, n2, "nonce must not repeat across Pongs");
    }
}
