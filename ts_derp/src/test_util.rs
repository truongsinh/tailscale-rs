//! In-process DERP server harness for tests.
//!
//! Available to downstream crates behind the `test-util` feature so integration
//! tests (e.g. ts_runtime's transport loop) can drive a **real** [`crate::Client`]
//! — true handshake, true frame codec, true keepalive accounting — without a
//! network. Not compiled into production builds.

use crypto_box::aead::{Aead, AeadCore, OsRng};
use futures::{SinkExt, StreamExt};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_util::codec::{FramedRead, FramedWrite};

#[allow(deprecated)] // KeepAlive frames are exactly what this harness scripts.
use crate::frame::KeepAlive;
use crate::frame::{self, Magic, Ping, RawFrame, RecvPacket, ServerInfo, ServerKey};

/// Minimal in-process DERP "server" end of a duplex pipe: performs the real
/// handshake wire exchange so [`crate::Client::handshake`] runs its true code path.
pub struct FakeServer<Io> {
    fw: FramedWrite<tokio::io::WriteHalf<Io>, frame::Codec>,
    /// Kept alive so the client's own writes (e.g. Pong replies) stay deliverable.
    _fr: FramedRead<tokio::io::ReadHalf<Io>, frame::Codec>,
}

impl<Io: AsyncRead + AsyncWrite> FakeServer<Io> {
    /// Run the server half of the DERP handshake against `io`.
    ///
    /// # Panics
    ///
    /// Panics on any wire error — this is a test harness; failing loudly is the point.
    pub async fn handshake(io: Io, client_public: &ts_keys::NodePublicKey) -> Self {
        let (r, w) = tokio::io::split(io);
        let mut fw = FramedWrite::new(w, frame::Codec);
        let mut fr = FramedRead::new(r, frame::Codec);

        let secret = crypto_box::SecretKey::generate(&mut OsRng);
        let server_key = ServerKey {
            magic: Magic::MAGIC,
            key: (*secret.public_key().as_bytes()).into(),
        };
        fw.send(RawFrame::from_body(&server_key, 0).unwrap())
            .await
            .unwrap();

        // Consume the ClientInfo frame; its contents are irrelevant here.
        fr.next().await.unwrap().unwrap();

        let cbox = crypto_box::SalsaBox::new(&client_public.into(), &secret);
        let nonce = crypto_box::SalsaBox::generate_nonce(&mut OsRng);
        let payload = serde_json::to_vec(&serde_json::json!({ "version": 2 })).unwrap();
        let encrypted = cbox.encrypt(&nonce, &payload[..]).unwrap();
        let si = ServerInfo {
            nonce: nonce.into(),
        };
        fw.send((
            RawFrame::from_body(&si, encrypted.len()).unwrap(),
            encrypted.as_ref(),
        ))
        .await
        .unwrap();

        Self { fw, _fr: fr }
    }

    /// Emit a server KeepAlive frame (the liveness signal standard DERP servers
    /// send at least every [`frame::KEEP_ALIVE`] seconds).
    #[allow(deprecated)] // KeepAlive frames are exactly what tests exercise.
    pub async fn send_keepalive(&mut self) {
        self.fw
            .send(RawFrame::from_body(&KeepAlive, 0).unwrap())
            .await
            .unwrap();
    }

    /// Deliver a peer data packet from `src`.
    pub async fn send_peer_packet(&mut self, src: ts_keys::NodePublicKey, payload: &[u8]) {
        self.fw
            .send((
                RawFrame::from_body(&RecvPacket { src }, payload.len()).unwrap(),
                payload,
            ))
            .await
            .unwrap();
    }

    /// Emit a Ping frame (the client answers with a Pong inline).
    pub async fn send_ping(&mut self, payload: [u8; 8]) {
        self.fw
            .send(RawFrame::from_body(&Ping { payload }, 0).unwrap())
            .await
            .unwrap();
    }
}
