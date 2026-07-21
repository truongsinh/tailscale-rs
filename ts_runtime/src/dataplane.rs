use std::{
    fmt::{Debug, Formatter},
    sync::Arc,
};

use futures_util::StreamExt;
use kameo::{
    actor::{ActorRef, Spawn},
    message::{Context, Message, StreamMessage},
};
use ts_dataplane::async_tokio::{FromOverlay, FromUnderlay, Rx, ToOverlay, ToUnderlay, Tx};
use ts_disco_protocol::{Packet, Plaintext};
use ts_packet::PacketMut;
use ts_transport::{OverlayTransportId, UnderlayTransportId};

use crate::{
    disco_handler,
    Error, Task,
    env::Env,
    packetfilter::PacketFilterState,
    peer_tracker::PeerState,
    route_updater::{PeerRouteUpdate, SelfRouteUpdate},
    src_filter::SourceFilterState,
};

pub struct DataplaneActor {
    dataplane: Arc<ts_dataplane::async_tokio::DataPlane>,
    env: Env,
}

#[kameo::messages]
impl DataplaneActor {
    #[message]
    pub async fn new_overlay_transport(
        &self,
    ) -> (OverlayTransportId, Tx<FromOverlay>, Rx<ToOverlay>) {
        self.dataplane.new_overlay_transport().await
    }

    #[message]
    pub async fn new_underlay_transport(
        &self,
    ) -> (UnderlayTransportId, Rx<ToUnderlay>, Tx<FromUnderlay>) {
        self.dataplane.new_underlay_transport().await
    }
}

pub type DiscoPacket = yoke::Yoke<&'static Packet<Plaintext>, ts_packet::Packet>;

#[derive(Clone)]
pub struct IncomingDiscoMsg(pub DiscoPacket);

impl Debug for IncomingDiscoMsg {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        self.0.get().fmt(f)
    }
}

impl AsRef<Packet<Plaintext>> for IncomingDiscoMsg {
    fn as_ref(&self) -> &Packet<Plaintext> {
        self.0.get()
    }
}

struct DiscoInternal(PacketMut);

#[derive(Debug, Clone)]
#[expect(dead_code)]
pub struct IncomingStunMsg(pub ts_packet::Packet);

struct StunInternal(PacketMut);

impl kameo::Actor for DataplaneActor {
    type Args = Env;
    type Error = Error;

    async fn on_start(env: Self::Args, slf: ActorRef<Self>) -> Result<Self, Self::Error> {
        let (dataplane, disco, stun) =
            ts_dataplane::async_tokio::DataPlane::new(env.keys.node_keys.clone());

        let dataplane = Arc::new(dataplane);

        slf.attach_stream(
            tokio_stream::wrappers::UnboundedReceiverStream::new(disco)
                .flat_map(tokio_stream::iter)
                .map(DiscoInternal),
            (),
            (),
        );

        slf.attach_stream(
            tokio_stream::wrappers::UnboundedReceiverStream::new(stun)
                .flat_map(tokio_stream::iter)
                .map(StunInternal),
            (),
            (),
        );

        env.subscribe::<PeerRouteUpdate>(&slf).await?;
        env.subscribe::<SelfRouteUpdate>(&slf).await?;
        env.subscribe::<PacketFilterState>(&slf).await?;
        env.subscribe::<SourceFilterState>(&slf).await?;
        env.subscribe::<Arc<PeerState>>(&slf).await?;

        let task_dataplane = dataplane.clone();

        Task::spawn_link(&slf, async move {
            task_dataplane.run().await;
        })
        .await;

        // Spawn the Disco Ping → Pong handler as a supervised child actor.
        // Subscribes to IncomingDiscoMsg (which we publish from the
        // StreamMessage<DiscoInternal> handler below) and Arc<PeerState>
        // (for sender DiscoKey → PeerId routing). The actor maintains its
        // own peer_db snapshot from bus events.
        disco_handler::DiscoHandlerActor::supervise(
            &slf,
            (env.clone(), env.keys.disco_keys.clone(), dataplane.clone()),
        )
        .spawn()
        .await;

        tracing::trace!("dataplane running");
        env.register(None, &slf).await?;

        Ok(Self { dataplane, env })
    }
}

impl Message<StreamMessage<DiscoInternal, (), ()>> for DataplaneActor {
    type Reply = ();

    async fn handle(
        &mut self,
        msg: StreamMessage<DiscoInternal, (), ()>,
        _ctx: &mut Context<Self, Self::Reply>,
    ) {
        let mut buf = match msg {
            StreamMessage::Next(pkt) => pkt.0,
            _ => return,
        };

        let pkt = match Packet::from_encrypted_bytes_mut(buf.as_mut()) {
            Ok(pkt) => pkt,
            Err(e) => {
                tracing::error!(error = %e, "parsing disco message");
                return;
            }
        };

        if let Err(e) = pkt.decrypt_in_place(&self.env.keys.disco_keys.private) {
            tracing::error!(error = %e, "decrypting disco message");
            return;
        };

        let pkt = yoke::Yoke::<&'static Packet<Plaintext>, _>::try_attach_to_cart(
            buf.freeze(),
            // SAFETY: we just parsed this from the same buffer, so type/version are set correctly.
            |buf| unsafe { Packet::from_bytes_unchecked(buf) },
        )
        .unwrap();
        let pkt = IncomingDiscoMsg(pkt);

        tracing::trace!(?pkt, "decrypted disco message");

        self.env.publish_noretain(pkt).await.unwrap();
    }
}

impl Message<StreamMessage<StunInternal, (), ()>> for DataplaneActor {
    type Reply = ();

    async fn handle(
        &mut self,
        msg: StreamMessage<StunInternal, (), ()>,
        _ctx: &mut Context<Self, Self::Reply>,
    ) {
        let pkt = match msg {
            StreamMessage::Next(pkt) => pkt.0,
            _ => return,
        };

        self.env
            .publish_noretain(IncomingStunMsg(pkt.freeze()))
            .await
            .unwrap();
    }
}

impl Message<PeerRouteUpdate> for DataplaneActor {
    type Reply = ();

    async fn handle(&mut self, msg: PeerRouteUpdate, _ctx: &mut Context<Self, Self::Reply>) {
        tracing::trace!("applying peer route update");

        let dp = &mut *self.dataplane.inner().await;
        dp.or_out.swap(msg.inner.overlay_out_routes.clone());

        dp.ur_out.table = msg.inner.underlay_routes.clone();
    }
}

impl Message<SelfRouteUpdate> for DataplaneActor {
    type Reply = ();

    async fn handle(&mut self, msg: SelfRouteUpdate, _ctx: &mut Context<Self, Self::Reply>) {
        {
            let dp = &mut *self.dataplane.inner().await;
            dp.or_in.swap(msg.overlay_in_routes.as_ref().clone());
        }

        tracing::trace!("applied self route update");
    }
}

impl Message<PacketFilterState> for DataplaneActor {
    type Reply = ();

    async fn handle(&mut self, msg: PacketFilterState, _ctx: &mut Context<Self, Self::Reply>) {
        {
            let dp = &mut *self.dataplane.inner().await;
            dp.packet_filter = msg.0;
        }

        tracing::trace!("applied new packet filter");
    }
}

impl Message<SourceFilterState> for DataplaneActor {
    type Reply = ();

    async fn handle(&mut self, msg: SourceFilterState, _ctx: &mut Context<Self, Self::Reply>) {
        {
            let dp = &mut *self.dataplane.inner().await;
            dp.src_filter_in = msg.0;
        }

        tracing::trace!("applied new source filter");
    }
}

impl Message<Arc<PeerState>> for DataplaneActor {
    type Reply = ();

    async fn handle(&mut self, msg: Arc<PeerState>, _ctx: &mut Context<Self, Self::Reply>) {
        {
            let mut dp = self.dataplane.inner().await;
            let wg = &mut dp.wireguard;

            for &upsert in &msg.upserts {
                let (_, node) = msg.peers.get(&upsert).unwrap();

                wg.upsert_peer(
                    ts_tunnel::PeerId(upsert.0),
                    ts_tunnel::PeerConfig {
                        key: node.node_key,
                        psk: [0u8; 32],
                    },
                );
            }

            for delete in &msg.deletions {
                wg.remove_peer(ts_tunnel::PeerId(delete.0));
            }
        }

        tracing::trace!("applied new peer state");
    }
}
