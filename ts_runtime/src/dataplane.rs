use std::sync::{Arc, RwLock};

use kameo::{
    actor::{ActorRef, Spawn},
    message::{Context, Message},
};
use ts_dataplane::async_tokio::{FromOverlay, FromUnderlay, Rx, ToOverlay, ToUnderlay, Tx};
use ts_transport::{OverlayTransportId, UnderlayTransportId};

use crate::{
    Error, Task,
    disco_handler,
    env::Env,
    packetfilter::PacketFilterState,
    peer_tracker::{PeerDb, PeerState},
    route_updater::{PeerRouteUpdate, SelfRouteUpdate},
    src_filter::SourceFilterState,
};

pub struct DataplaneActor {
    dataplane: Arc<ts_dataplane::async_tokio::DataPlane>,
    /// Latest snapshot of the peer database, shared with the Disco handler task.
    /// `None` until the first [`PeerState`] update arrives.
    peer_db: Arc<RwLock<Option<Arc<PeerDb>>>>,
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

impl kameo::Actor for DataplaneActor {
    type Args = Env;
    type Error = Error;

    async fn on_start(env: Self::Args, slf: ActorRef<Self>) -> Result<Self, Self::Error> {
        // Capture the disco_rx channel — previously dropped via `..`, which caused
        // every incoming Disco Ping to be silently discarded by the dataplane's
        // `disco_out.send()` (returning Err with "disco packets dropped: no
        // receiver"). The stun_rx is still dropped today (the Stunner actor probes
        // STUN servers out-of-band and does not consume from this channel).
        let (dataplane, disco_rx, _stun_rx) =
            ts_dataplane::async_tokio::DataPlane::new(env.keys.node_keys.clone());
        let dataplane = Arc::new(dataplane);

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

        // Spawn the Disco Ping → Pong handler. It reads from disco_rx (produced by
        // the dataplane loop above) and sends Pong responses back via the dataplane's
        // underlay transports. The handler needs our disco private key (for decrypt
        // + encrypt) and the shared peer_db snapshot (to look up the sender's
        // PeerId from their DiscoPublicKey).
        let peer_db: Arc<RwLock<Option<Arc<PeerDb>>>> =
            Arc::new(RwLock::new(None));
        let disco_keys = env.keys.disco_keys.clone();
        let handler_db = peer_db.clone();
        let handler_dp = dataplane.clone();
        Task::spawn_link(&slf, async move {
            disco_handler::run(disco_rx, disco_keys, handler_db, handler_dp).await;
        })
        .await;

        tracing::trace!("dataplane running");
        env.register(None, &slf).await?;

        Ok(Self {
            dataplane,
            peer_db,
        })
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
        // Publish the latest PeerDb snapshot to the Disco handler before touching
        // WireGuard state — ordering doesn't matter (both are independent readers),
        // but doing the write under the same actor turn keeps the snapshot fresh.
        if let Ok(mut slot) = self.peer_db.write() {
            *slot = Some(msg.peers.clone());
        }

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
