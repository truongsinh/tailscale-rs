use core::fmt;
use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};

use crypto_box::aead::{Aead, AeadCore, AeadMutInPlace, OsRng};
use futures::{SinkExt, StreamExt};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadHalf, WriteHalf},
    sync::Mutex,
};
use tokio_util::codec::{FramedRead, FramedWrite};
use ts_http_util::Client as _;
use ts_keys::{NodeKeyPair, NodePublicKey};
use ts_packet::PacketMut;
use ts_transport::{
    BatchRecvIter, BatchSendIter, MapPeerKey, PeerLookup, UnderlayTransport, UnderlayTransportExt,
};
use url::Url;

use crate::{
    Error, ServerConnInfo, frame,
    frame::{ClientInfo, FrameType, PeerGone, Ping, RawFrame, ServerInfo, ServerKey},
};

type DefaultIo = ts_http_util::Upgraded;

/// Type alias for the default derp client over upgraded HTTP on a tokio executor.
pub type DefaultClient = Client<DefaultIo>;

/// Shared, monotonically increasing count of DERP frames received on a [`Client`] —
/// frames of **any** type: server keepalives, pings, peer-gone notices, and peer data
/// alike.
///
/// Standard DERP servers emit a KeepAlive at least every [`frame::KEEP_ALIVE`] seconds,
/// so on a connection with a live return path this counter always advances even when no
/// peer traffic flows. Total frame silence therefore indicates a dead return path —
/// which is exactly how the runtime's rx-stall detection uses this handle
/// (frame-silence predicate). The handle stays valid and cheap to read after the
/// [`Client`] has been wrapped into other transport layers.
#[derive(Clone, Debug, Default)]
pub struct FrameActivity(Arc<AtomicU64>);

impl FrameActivity {
    /// Total number of frames received so far.
    pub fn frames_received(&self) -> u64 {
        self.0.load(Ordering::Relaxed)
    }

    /// Record the arrival of a frame.
    ///
    /// Called by [`Client`] on every frame received; public so tests and alternative
    /// transports can drive the same signal.
    pub fn record(&self) {
        self.0.fetch_add(1, Ordering::Relaxed);
    }
}

/// Single-region DERP client.
pub struct Client<Io> {
    read_conn: Mutex<FramedRead<ReadHalf<Io>, frame::Codec>>,
    write_conn: Mutex<FramedWrite<WriteHalf<Io>, frame::Codec>>,
    frame_activity: FrameActivity,
}

/// Establish and upgrade a http connection to the derp region.
#[tracing::instrument(skip_all, err)]
pub async fn connect<'c>(
    region: impl IntoIterator<Item = &'c ServerConnInfo>,
) -> Result<Option<DefaultIo>, Error> {
    let Some((conn, _, addr)) = crate::dial::dial_region_tls(region).await.unwrap() else {
        return Ok(None);
    };

    let url = Url::parse(&format!("https://{addr}/derp"))?;

    let client = ts_http_util::http1::connect(conn).await?;

    let resp = client
        .send(ts_http_util::make_upgrade_req(&url, "DERP", None)?)
        .await?;

    let upgraded = ts_http_util::do_upgrade(resp)
        .await
        .map_err(tokio::io::Error::other)
        .map_err(Error::from)?;

    Ok(Some(upgraded))
}

impl<Io> Client<Io>
where
    Io: AsyncRead + AsyncWrite,
{
    /// Perform a derp handshake over the given transport and return a [`Client`].
    #[tracing::instrument(skip_all)]
    pub async fn handshake(conn: Io, node_keypair: &NodeKeyPair) -> Result<Self, Error> {
        let (read_conn, write_conn) = tokio::io::split(conn);

        let mut fw = FramedWrite::new(write_conn, frame::Codec);
        let mut fr = FramedRead::new(read_conn, frame::Codec);

        let frame = fr.next().await.ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "stream ended before server key",
            )
        })??;
        let (sk, _rest) = frame
            .get()
            .as_type::<ServerKey>()
            .ok_or_else(|| std::io::Error::other("initial message was not serverkey"))?;

        sk.validate()?;

        tracing::trace!(
            server_public_key = %sk.key,
            "derp server public key"
        );

        let (client_info, encrypted) = make_clientinfo(node_keypair, &sk.key)?;
        tracing::trace!(?client_info);

        fw.send((
            RawFrame::from_body(&client_info, encrypted.len())?,
            encrypted.as_ref(),
        ))
        .await?;

        tracing::trace!("sent client info");

        let frame = fr.next().await.ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "stream ended before server info",
            )
        })??;
        let (si, payload) = frame
            .get()
            .as_type::<ServerInfo>()
            .ok_or_else(|| std::io::Error::other("frame was not serverinfo"))?;

        tracing::trace!(server_info = ?si, "got server info");

        let info = decrypt_server_info(node_keypair, sk, si, payload)?;
        tracing::trace!(server_info = ?info);

        Ok(Self {
            read_conn: Mutex::new(fr),
            write_conn: Mutex::new(fw),
            frame_activity: FrameActivity::default(),
        })
    }

    /// A cloneable handle to this client's frame-arrival signal.
    ///
    /// The handle keeps working after the client is wrapped (e.g. via
    /// [`ts_transport::UnderlayTransportExt::with_key_lookup`]), so callers can observe
    /// frame arrival — keepalives included — without changing the peer-data semantics
    /// of [`UnderlayTransport::recv`].
    ///
    /// Callers wrapping the client into a peer-keyed transport should prefer
    /// [`Self::into_transport_with_activity`], which yields the transport and the
    /// handle **together** so the two can never come from different clients.
    pub fn frame_activity(&self) -> FrameActivity {
        self.frame_activity.clone()
    }

    /// Consume the client into a peer-keyed transport plus **its own**
    /// frame-arrival handle.
    ///
    /// The two are constructed together, in one place, from one client — so a
    /// stall detector observing the handle while polling the transport can never
    /// be wired to a handle belonging to a different (or freshly defaulted)
    /// client. That wrong-handle bug would leave every healthy connection looking
    /// frame-silent (all keepalives invisible) and false-fire stall detection on
    /// the entire fleet; making it unrepresentable is the point of this API.
    pub fn into_transport_with_activity<DstKey, Lookup>(
        self,
        lookup: Lookup,
    ) -> (MapPeerKey<Self, Lookup, DstKey>, FrameActivity)
    where
        Io: Send,
        Lookup: PeerLookup<NodePublicKey, DstKey> + PeerLookup<DstKey, NodePublicKey> + Send + Sync,
        DstKey: Send + Sync + 'static,
    {
        let frames = self.frame_activity.clone();
        (self.with_key_lookup(lookup), frames)
    }

    /// Send a message to a nodekey on the derp server.
    pub async fn send_one(&self, node_key: NodePublicKey, msg: &[u8]) -> Result<(), Error> {
        self.send_frame_with_extra(&frame::SendPacket { dest: node_key }, msg)
            .await
    }

    /// Send a frame to the derp server.
    pub async fn send_frame(
        &self,
        frame: &(impl frame::Body + zerocopy::IntoBytes + zerocopy::Immutable + Send),
    ) -> Result<(), Error> {
        self.send_frame_with_extra(frame, &[]).await
    }

    /// Send a frame to the derp server with the specified additional payload.
    pub async fn send_frame_with_extra(
        &self,
        frame: &(impl frame::Body + zerocopy::IntoBytes + zerocopy::Immutable + Send),
        additional_payload: &[u8],
    ) -> Result<(), Error> {
        let raw = RawFrame::from_body(frame, additional_payload.len())?;

        {
            let mut wr = self.write_conn.lock().await;
            wr.send((raw, additional_payload)).await?;
        }

        Ok(())
    }

    /// Waits for a single data packet from a peer to arrive via this DERP server and returns it.
    /// DERP control messages (KeepAlive, Ping, etc) are handled inline and are not returned.
    pub async fn recv_one(&self) -> Result<(NodePublicKey, PacketMut), Error> {
        // DERP exchanges control messages (KeepAlives, Pings, etc) in-band with data messages
        // (SendPacket, RecvPacket, etc). The caller only cares about the payloads of data
        // messages, so we recv_one_raw() in a loop to handle any control messages while waiting
        // for data messages.

        loop {
            let frame = {
                let mut r = self.read_conn.lock().await;
                r.next().await.ok_or_else(|| {
                    std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "derp stream ended")
                })??
            };
            // Every frame — control messages included — is proof the server-to-client
            // path is alive; record it before dispatching on the frame type.
            self.frame_activity.record();
            let frame = frame.get();

            match frame.header.typ {
                // TODO (dylan): handle other control message types
                // TODO (dylan): handle other data message types (ForwardPacket, etc)
                #[allow(deprecated)]
                FrameType::KeepAlive => {
                    // TODO (dylan): do we need to do anything on KeepAlive other than reset a timer?
                    // TODO (dylan): handle KeepAlive timer
                    tracing::trace!("received KeepAlive frame");
                }
                FrameType::Ping => {
                    let Some((&ping, _)) = frame.as_type::<Ping>() else {
                        tracing::warn!("ping frame was not ping");
                        continue;
                    };

                    tracing::trace!(payload = ?ping.payload, "ping");

                    let pong: frame::Pong = ping.into();
                    self.send_frame(&pong).await?;

                    tracing::trace!(payload = ?pong.payload, "pong");
                }
                FrameType::PeerGone => {
                    let (gone, _rest) = frame.as_type::<PeerGone>().unwrap();

                    tracing::debug!(
                        peer = %gone.key,
                        reason = %gone.reason()?,
                        "peer gone from derp server"
                    );
                }
                FrameType::RecvPacket => {
                    let (recv, payload) = frame.as_type::<frame::RecvPacket>().unwrap();

                    return Ok((recv.src, payload.into()));
                }
                t => {
                    return Err(Error::UnexpectedRecvFrameType(t));
                }
            }
        }
    }
}

impl Client<DefaultIo> {
    /// Connect to and handshake with the derp server with the given URL over HTTP.
    pub async fn connect<'c>(
        region: impl IntoIterator<Item = &'c ServerConnInfo>,
        node_keypair: &NodeKeyPair,
    ) -> Result<Self, Error> {
        let conn = connect(region).await?.unwrap();

        Client::handshake(conn, node_keypair).await
    }
}

impl<Io> fmt::Debug for Client<Io> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

impl<Io> fmt::Display for Client<Io> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Client").finish()
    }
}

fn make_clientinfo(
    node_keypair: &NodeKeyPair,
    server_key: &ts_keys::DerpServerPublicKey,
) -> Result<(ClientInfo, Vec<u8>), Error> {
    let cbox = crypto_box::SalsaBox::new(&server_key.into(), &node_keypair.into());
    let nonce = crypto_box::SalsaBox::generate_nonce(&mut OsRng);

    let json = serde_json::to_vec(&frame::ClientInfoPayload {
        can_ack_pings: false,
        is_prober: false,
        mesh_key: "none".to_string(),
        version: 2,
    })?;
    let encrypted = cbox
        .encrypt(&nonce, &json[..])
        .map_err(|_| frame::Error::EncryptionFailed)?;

    Ok((
        ClientInfo {
            key: node_keypair.public,
            nonce: nonce.into(),
        },
        encrypted,
    ))
}

fn decrypt_server_info(
    node_keypair: &NodeKeyPair,
    sk: &ServerKey,
    server_info: &ServerInfo,
    payload: &[u8],
) -> Result<frame::ServerInfoPayload, Error> {
    let mut payload = PacketMut::from(payload);

    let mut cbox = crypto_box::SalsaBox::new(&sk.key.into(), &node_keypair.into());
    cbox.decrypt_in_place(&server_info.nonce.into(), &[], &mut payload)
        .map_err(|e| frame::Error::DecryptionFailed(format!("err: {e}")))?;

    let sip = serde_json::from_slice::<frame::ServerInfoPayload>(payload.as_ref())?;
    if sip.version() != frame::PROTOCOL_VERSION {
        return Err(Error::UnsupportedProtocolVersion(
            sip.version(),
            frame::PROTOCOL_VERSION,
        ));
    }

    Ok(sip)
}

impl<Io> UnderlayTransport for Client<Io>
where
    Io: AsyncRead + AsyncWrite + Send,
{
    type PeerKey = NodePublicKey;
    type Error = Error;

    async fn send(
        &self,
        packet_batch: impl BatchSendIter<Self::PeerKey>,
    ) -> Result<(), Self::Error> {
        for (key, pkt) in packet_batch.batch_iter() {
            for pkt in pkt {
                self.send_one(key, pkt.as_ref()).await?;
            }
        }

        Ok(())
    }

    async fn recv(&self) -> impl BatchRecvIter<Self::PeerKey, Error = Self::Error> {
        [self.recv_one().await.map(|(k, pkt)| (k, [pkt]))]
    }
}

#[cfg(test)]
mod tests {
    use std::{sync::Arc, time::Duration};

    use super::Client;
    use crate::test_util::FakeServer;

    async fn wait_for(mut cond: impl FnMut() -> bool) {
        tokio::time::timeout(Duration::from_secs(5), async {
            while !cond() {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("condition not reached within timeout");
    }

    /// Seam test for the frame-silence predicate's input signal: server KeepAlive
    /// frames — which `recv_one` swallows without returning — must still advance the
    /// [`FrameActivity`][super::FrameActivity] counter, while peer data keeps its
    /// existing recv semantics.
    #[tokio::test]
    async fn keepalive_frames_advance_frame_activity_without_peer_data() {
        let node_keys = ts_keys::NodeState::generate().node_keys;
        let (client_io, server_io) = tokio::io::duplex(1 << 16);

        let (client, mut server) = tokio::join!(
            async { Client::handshake(client_io, &node_keys).await.unwrap() },
            FakeServer::handshake(server_io, &node_keys.public),
        );
        let activity = client.frame_activity();
        assert_eq!(activity.frames_received(), 0, "no frames after handshake");

        let client = Arc::new(client);
        let recv_task = tokio::spawn({
            let client = client.clone();
            async move { client.recv_one().await }
        });

        // KeepAlives alone: the frame signal advances while recv_one keeps waiting
        // for peer data.
        server.send_keepalive().await;
        server.send_keepalive().await;
        wait_for(|| activity.frames_received() == 2).await;
        assert!(
            !recv_task.is_finished(),
            "recv_one must not return on keepalives"
        );

        // Peer data still resolves recv_one, and counts as a frame too.
        server.send_peer_packet(node_keys.public, b"hello").await;
        let (src, pkt) = tokio::time::timeout(Duration::from_secs(5), recv_task)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(src, node_keys.public);
        assert_eq!(pkt.as_ref(), b"hello");
        assert_eq!(activity.frames_received(), 3);

        // A subsequent Ping is answered with a Pong and also advances the signal.
        server.send_ping([7u8; 8]).await;
        let recv_task = tokio::spawn({
            let client = client.clone();
            async move { client.recv_one().await }
        });
        wait_for(|| activity.frames_received() == 4).await;
        assert!(!recv_task.is_finished(), "ping is handled inline");
        recv_task.abort();
    }
}
