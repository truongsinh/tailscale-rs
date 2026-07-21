//! Disco protocol message handler.
//!
//! Consumes [`DiscoBatch`]es from the dataplane's `disco_out` channel and handles
//! incoming Disco messages. Currently handles [`Ping`] → [`Pong`] responses so that
//! `tailscale ping` works against this node in userspace-networking (DERP-relayed)
//! mode.
//!
//! Before this handler existed, the [`DataplaneActor`] dropped the `disco_rx` channel
//! returned by [`ts_dataplane::async_tokio::DataPlane::new`], so every incoming Disco
//! Ping was silently dropped by the dataplane's `disco_out.send()` (returning `Err`
//! with the warning "disco packets dropped: no receiver"). No Pong was ever sent,
//! causing `tailscale ping <peer>` to time out for every peer even though WireGuard
//! tunneled traffic (TCP/SSH/SOCKS5) worked fine.

use std::{
    net::{IpAddr, Ipv6Addr, SocketAddr},
    sync::{Arc, RwLock},
};

use crypto_box::aead::{AeadCore, OsRng};
use ts_dataplane::async_tokio::{DataPlane, DiscoBatch, Rx};
use ts_disco_protocol::{Encrypted, Header, MessageType, Packet, Ping, Pong};
use ts_keys::{DiscoKeyPair, DiscoPublicKey};
use ts_packet::PacketMut;
use ts_transport::PeerId;

use crate::peer_tracker::PeerDb;

/// Type alias for the shared peer-db handle used by the disco handler.
///
/// Mirrors the pattern in [`crate::multiderp::uniderp`]: `None` until the first
/// [`crate::peer_tracker::PeerState`] update arrives.
type SharedPeerDb = Arc<RwLock<Option<Arc<PeerDb>>>>;

/// Run the Disco handler loop, consuming batches from `disco_rx` until the channel
/// closes (i.e. until the dataplane shuts down).
///
/// For each incoming Disco Ping, a matching Pong is constructed, encrypted with this
/// node's Disco private key, and sent back to the originating peer via the dataplane's
/// underlay transports. Non-Ping Disco messages are logged at trace level and dropped.
pub async fn run(
    mut disco_rx: Rx<DiscoBatch>,
    disco_keys: DiscoKeyPair,
    peer_db: SharedPeerDb,
    dataplane: Arc<DataPlane>,
) {
    tracing::trace!("disco handler started");

    while let Some(batch) = disco_rx.recv().await {
        for pkt in batch {
            match handle_one(&pkt, &disco_keys, &peer_db) {
                Ok(Some((peer_id, pong))) => {
                    tracing::trace!(
                        %peer_id,
                        "disco Ping from peer — sending Pong"
                    );
                    dataplane.send_raw_to_underlay(peer_id, pong).await;
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

    tracing::trace!("disco handler stopped (channel closed)");
}

/// Result of handling a single incoming Disco packet.
///
/// `Ok(Some((peer_id, pong_pkt)))` means the packet was a Ping from a known peer
/// and a Pong response was constructed, ready to be sent to `peer_id`.
/// `Ok(None)` means the packet needs no response (not a Ping, or peer unknown).
type HandleResult = Result<Option<(PeerId, PacketMut)>, &'static str>;

/// Parse, decrypt, and (if Ping) build a Pong for a single incoming Disco packet.
///
/// Steps:
/// 1. Parse the outer encrypted Disco [`Packet`] header to recover the sender's
///    [`DiscoPublicKey`].
/// 2. Decrypt the packet with our [`DiscoKeyPair`] private key.
/// 3. If the decrypted message is a [`Ping`], look up the sender's [`PeerId`] in
///    the shared [`PeerDb`] via the Disco key index.
/// 4. Construct a [`Pong`] echoing the Ping's `tx_id`, encrypt it with our private
///    key to the sender's public key, and return it ready to route.
fn handle_one(pkt: &PacketMut, disco_keys: &DiscoKeyPair, peer_db: &SharedPeerDb) -> HandleResult {
    // Quickly reject non-disco packets — the dataplane already classified this as
    // Disco, but double-check the magic bytes before parsing.
    if !ts_disco_protocol::is_disco_message(pkt.as_ref()) {
        return Err("not a disco message (magic mismatch)");
    }

    // Copy into a mutable buffer for in-place decryption.
    let mut buf: Vec<u8> = pkt.as_ref().to_vec();
    let enc_pkt = Packet::<Encrypted>::from_encrypted_bytes_mut(&mut buf)
        .map_err(|_| "failed to parse encrypted disco packet")?;

    let sender_disco: DiscoPublicKey = *enc_pkt.sender_pubkey();

    // Decrypt in place using our private disco key.
    let dec_pkt = enc_pkt
        .decrypt_in_place(&disco_keys.private)
        .map_err(|_| "disco decrypt failed")?;

    // Only Ping requires a response today.
    if dec_pkt.ty() != Some(MessageType::Ping) {
        tracing::trace!(ty = ?dec_pkt.ty(), "disco non-Ping message — dropping");
        return Ok(None);
    }

    let ping = dec_pkt
        .as_msg::<Ping>()
        .ok_or("failed to parse Ping payload")?;

    // Look up the sender's PeerId via their DiscoPublicKey.
    let peer_id = {
        let guard = peer_db.read().map_err(|_| "peer_db lock poisoned")?;
        let Some(db) = guard.as_ref() else {
            // PeerDb not yet populated (no control-plane state update yet).
            return Ok(None);
        };
        let Some((id, _node)) = db.get(&sender_disco) else {
            tracing::trace!(
                ?sender_disco,
                "disco Ping from peer not in PeerDb — cannot route Pong",
            );
            return Ok(None);
        };
        id
    };

    // Construct and encrypt the Pong response.
    let pong_pkt = build_pong(&ping.tx_id, disco_keys, &sender_disco)?;
    Ok(Some((peer_id, pong_pkt)))
}

/// Build an encrypted [`Pong`] packet echoing the supplied `tx_id`, encrypted from
/// `our_keys.private` to `their_disco`.
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

    // Pre-fill the Header magic bytes. `init_from_bytes` reinterprets the buffer
    // as a `Packet<Plaintext>` without touching the header fields, and
    // `encrypt_in_place` sets `sender_pub` and `nonce` but not `magic`. Without
    // this pre-fill, the magic stays zero and the receiver's
    // `Packet::from_encrypted_bytes` rejects the packet with `WrongMagic`.
    out[..Header::MAGIC.len()].copy_from_slice(&Header::MAGIC);

    // Initialize the plaintext Pong payload.
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
    use ts_disco_protocol::{
        Encrypted, Header, MessageType, Packet, Ping, Pong,
    };
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

        // Pre-fill magic so the packet round-trips through from_encrypted_bytes.
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
