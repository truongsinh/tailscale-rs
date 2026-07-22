use core::{
    any::{Any, TypeId, type_name},
    marker::PhantomData,
};
use std::collections::HashMap;

use kameo::{
    Reply,
    actor::{ActorRef, WeakActorRef},
    error::{BoxSendError, Infallible, SendError},
    message::{Context, Message},
    reply::{BoxReplySender, DelegatedReply, ForwardedReply, ReplyError},
};
use smol_str::SmolStr;

/// Name for a canonical actor instance.
const CANONICAL: SmolStr = SmolStr::new_static("__canonical__");

/// Complete identifier for an actor registration: the actor type and the user-provided name string.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
struct Id {
    actor_ty: TypeId,
    name: SmolStr,
}

impl Id {
    fn new<A>(name: Option<SmolStr>) -> Self
    where
        A: Any,
    {
        match name {
            Some(name) => Self::named::<A>(name),
            None => Self::canonical::<A>(),
        }
    }

    const fn canonical<A>() -> Self
    where
        A: Any,
    {
        Self {
            actor_ty: TypeId::of::<A>(),
            name: CANONICAL,
        }
    }

    const fn named<A>(name: SmolStr) -> Self
    where
        A: Any,
    {
        Self {
            actor_ty: TypeId::of::<A>(),
            name,
        }
    }
}

/// [`WeakActorRef`] with erased actor type.
pub type ErasedWeakRef = Box<dyn Any + Send>;

/// An actor registry which itself runs as an actor and provides naming service for the tuple
/// `(actor_type, name)`.
///
/// # Names
///
/// When you communicate with this registry, you always explicitly name the type of actor you're
/// talking about as well as the user-provided string name. This is an affordance for type-safety;
/// kameo doesn't support fully type-erased actor references or message handlers. As a consequence,
/// names are permitted to overlap between actors of different types, as there can't be a collision
/// between them.
///
/// The conventional structure of names in this registry includes the idea of a "canonical" actor
/// which is unique. For actors expected to run as singletons or to have a single special instance,
/// the `new` function on any of the message types addresses this canonical instance. The canonical
/// name isn't privileged in any other way (e.g. the registry doesn't prevent you from spawning
/// named actors if there's a canonical one), it's just a conventional, easily-addressed name for a
/// special actor if you have one.
///
/// # Liveness
///
/// This registry does not keep actors alive; all refs are held weakly.
///
/// # Comparison to [`kameo::registry`]
///
/// We're not using the singleton [`kameo::registry::ACTOR_REGISTRY`] because it's at global scope,
/// but we need naming services to be scoped to each instance of a tailscale runtime. Rather than
/// dealing with namespace prefixes, we just run a per-runtime registry.
///
/// We don't use [`kameo::registry::ActorRegistry`] for the per-runtime registry because it doesn't
/// have any built-in synchronization, is hard to customize, and requires manual downcasting on the
/// part of the user, despite the fact that the contained actor refs are only usable if you know
/// what kind of messages they can handle (i.e. you essentially must know the actor type a priori).
#[derive(Default)]
pub struct Registry {
    actors: HashMap<Id, ErasedWeakRef>,
    pending_lookups: HashMap<Id, Vec<BoxReplySender>>,
}

impl kameo::Actor for Registry {
    type Args = ();
    type Error = Infallible;

    async fn on_start(_args: Self::Args, _actor_ref: ActorRef<Self>) -> Result<Self, Self::Error> {
        Ok(Self::default())
    }
}

/// Request to register an actor with a given name.
///
/// The registry replies with the [`WeakActorRef`] of an actor that was already registered in this
/// name if there was one.
pub struct Register<A>
where
    A: kameo::Actor,
{
    id: Id,
    aref: WeakActorRef<A>,
}

impl<A> Register<A>
where
    A: kameo::Actor + Any,
{
    /// Construct a register request for the actor of type `A` with the specified `name`, if given,
    /// or the canonical actor if not.
    pub fn new(name: Option<SmolStr>, aref: &ActorRef<A>) -> Self {
        Self {
            id: Id::new::<A>(name),
            aref: aref.downgrade(),
        }
    }
}

impl<A> Message<Register<A>> for Registry
where
    A: kameo::Actor + Any,
{
    type Reply = Option<WeakActorRef<A>>;

    async fn handle(
        &mut self,
        msg: Register<A>,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Option<WeakActorRef<A>> {
        if let Some(pending) = self.pending_lookups.remove(&msg.id) {
            for sender in pending {
                drop(sender.send(Ok(Box::new(Some(msg.aref.clone())))));
            }
        }

        let previous = self.actors.insert(msg.id, Box::new(msg.aref))?;

        // Defensive downcast: in principle the stored entry under this Id
        // (which includes TypeId::of::<A>()) was stored by a prior
        // Register<A> with the same A, so the downcast should always match.
        // But panicking here kills the Registry actor, which cascades to
        // every Uniderp (ActorGone) and silences every recovery path that
        // goes through the registry (which is all of them). Treat a
        // mismatch as "no previous entry" + a loud warn so the symptom is
        // visible without taking down the runtime's naming service.
        match previous.downcast::<WeakActorRef<A>>() {
            Ok(typed) => Some(*typed),
            Err(stale) => {
                tracing::warn!(
                    actor_ty = %type_name::<A>(),
                    "registry: Register downcast failed on previous entry; \
                     treating as no previous entry (type mismatch should be \
                     impossible — Id includes TypeId — but never panic here)"
                );
                drop(stale);
                None
            }
        }
    }
}

/// Request to unregister an actor for a given name.
///
/// The registry replies with the [`WeakActorRef`] of the unregistered actor if there was one.
pub struct Unregister<A>(Id, PhantomData<A>);

impl<A> Unregister<A>
where
    A: Any,
{
    /// Unregister an actor of type `A` if it exists in the registry. If `name` is `None`, the
    /// canonical actor is unregistered.
    pub fn new(name: Option<SmolStr>) -> Self {
        Self(Id::new::<A>(name), PhantomData)
    }
}

impl<A> Message<Unregister<A>> for Registry
where
    A: kameo::Actor,
{
    type Reply = Option<WeakActorRef<A>>;

    async fn handle(
        &mut self,
        msg: Unregister<A>,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Option<WeakActorRef<A>> {
        let previous = self.actors.remove(&msg.0)?;
        // Defensive downcast: same reasoning as Register's handler. The Id
        // (TypeId + name) is the key, so a prior insert under this Id should
        // have stored a WeakActorRef<A>. But never panic here — a panic kills
        // the Registry, cascading to every Uniderp via ActorGone and
        // preventing every recovery path that uses the registry (all of them).
        // Observed in canary: cadfddc Gate 2 died here because 0255ee7's
        // on_stop unregister + this unwrap combined to kill the Registry on
        // the first Runner-budget exhaustion.
        match previous.downcast::<WeakActorRef<A>>() {
            Ok(typed) => Some(*typed),
            Err(stale) => {
                tracing::warn!(
                    actor_ty = %type_name::<A>(),
                    "registry: Unregister downcast failed on removed entry; \
                     treating as no previous entry"
                );
                drop(stale);
                None
            }
        }
    }
}

pub struct Lookup<A> {
    id: Id,
    wait: bool,
    _phantom: PhantomData<A>,
}

impl<A> Lookup<A>
where
    A: Any,
{
    /// Look up the actor with the given `name`, or the canonical actor if `name` is `None`.
    pub fn new(name: Option<SmolStr>) -> Self {
        Self {
            id: Id::new::<A>(name),
            wait: false,
            _phantom: PhantomData,
        }
    }

    /// Wait until an actor is registered with the given name.
    pub const fn wait(mut self, wait: bool) -> Self {
        self.wait = wait;
        self
    }
}

impl<A> Message<Lookup<A>> for Registry
where
    A: kameo::Actor,
{
    type Reply = DelegatedReply<Option<WeakActorRef<A>>>;

    async fn handle(
        &mut self,
        msg: Lookup<A>,
        ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        let (deleg, sender) = ctx.reply_sender();

        if let Some(sender) = sender {
            // Defensive downcast: never panic here — a panic in the Lookup
            // handler would kill the Registry and cascade to every Uniderp
            // + every Multiderp health check + every recovery tell. A
            // mismatched entry is treated as "not found" and logged.
            let aref = self
                .actors
                .get(&msg.id)
                .and_then(|x| x.downcast_ref::<WeakActorRef<A>>())
                .cloned();

            if self.actors.get(&msg.id).is_some() && aref.is_none() {
                tracing::warn!(
                    actor_ty = %type_name::<A>(),
                    "registry: Lookup downcast failed on stored entry; \
                     treating as not found"
                );
            }

            match (&aref, msg.wait) {
                (Some(_), _) | (_, false) => {
                    sender.send(aref);
                }
                (None, true) => {
                    self.pending_lookups
                        .entry(msg.id)
                        .or_default()
                        .push(sender.boxed());
                }
            }
        };

        deleg
    }
}

/// Request to forward a message of type `M` to an actor of type `A` under a particular registered
/// name.
pub struct Forward<A, M> {
    id: Id,
    message: M,
    _phantom: PhantomData<A>,
}

impl<A, M> Forward<A, M>
where
    A: Any,
{
    /// Construct a new [`Forward`] for the message `M`.
    pub fn new(name: Option<SmolStr>, m: M) -> Self {
        Self {
            id: Id::new::<A>(name),
            message: m,
            _phantom: PhantomData,
        }
    }
}

/// Wrapper around [`ForwardedReply`] that handles forwards into the registry.
///
/// This is needed because [`ForwardedReply`] doesn't let you construct a [`SendError`] variant
/// directly.
pub enum RegistryForward<M, R>
where
    M: Send + 'static,
    R: Reply,
{
    /// The message was successfully forwarded or failed to be forwarded
    Forwarded(ForwardedReply<M, R>),
    ActorDead(M),
    NotFound(M),
}

impl<M, R> Reply for RegistryForward<M, R>
where
    M: Send + 'static,
    R: Reply,
{
    type Ok = R::Ok;
    type Error = SendError<M, R::Error>;
    type Value = Result<Self::Ok, Self::Error>;

    fn to_result(self) -> Result<Self::Ok, Self::Error> {
        match self {
            Self::Forwarded(res) => res.to_result(),
            Self::NotFound(m) => Err(SendError::ActorNotRunning(m)),
            Self::ActorDead(m) => Err(SendError::ActorNotRunning(m)),
        }
        .inspect_err(|e| {
            tracing::trace!(error = ?e, "forward error");
        })
    }

    fn into_any_err(self) -> Option<Box<dyn ReplyError>> {
        // Forward failures (missing name, dead target, closed mailbox) must NOT be
        // reported as an unhandled handler error on the tell path: kameo stops the
        // actor whose handler produced an unhandled error — i.e. the Registry itself —
        // taking down the runtime's entire naming service (and dropping every queued
        // forward) because one best-effort tell was misaddressed. Observed in the
        // watchdog e2e test: a `ForceReconnect` tell to a not-yet-registered
        // ControlRunner killed the Registry and lost the follow-up `ForceRehome`.
        //
        // Ask callers are unaffected: they receive the error through
        // [`Reply::to_result`] via their reply channel.
        // warn!, not debug!: a dropped tell is a silently-lost recovery command
        // (e.g. a watchdog `ForceRehome`) — it must be visible in default logs,
        // with the message type so the lost command is identifiable.
        match self {
            Self::Forwarded(res) => {
                if let Some(e) = res.into_any_err() {
                    tracing::warn!(
                        error = ?e,
                        msg_type = type_name::<M>(),
                        "forward failed; dropped on tell path"
                    );
                }
                None
            }
            Self::ActorDead(_) | Self::NotFound(_) => {
                tracing::warn!(
                    msg_type = type_name::<M>(),
                    "forward to unavailable actor; dropped on tell path"
                );
                None
            }
        }
    }

    fn into_value(self) -> Self::Value {
        self.to_result()
    }

    /// If the forwarded reply succeeded, then we can safely assume
    /// the `Box<dyn Any>` we have here is the ok value of the inner `R`.
    fn downcast_ok(ok: Box<dyn Any>) -> Self::Ok {
        *ok.downcast().unwrap()
    }

    /// The error is either from the inner `R`, or our outer `SendError`.
    /// We'll try both.
    fn downcast_err<N: 'static>(err: BoxSendError) -> SendError<N, Self::Error> {
        err.try_downcast::<N, R::Error>()
            .map(|err| err.map_err(SendError::HandlerError))
            .unwrap_or_else(|err| {
                err.downcast::<M, SendError<M, R::Error>>().map_msg(|_| {
                    unreachable!(
                        "forwarded reply is only an error if it failed to forward the message"
                    )
                })
            })
    }
}

impl<A, M> Message<Forward<A, M>> for Registry
where
    A: Message<M>,
    M: Send + 'static,
{
    type Reply = RegistryForward<M, A::Reply>;

    #[tracing::instrument(skip_all, fields(msgty = type_name::<M>(), actor = type_name::<A>(), name = %msg.id.name))]
    async fn handle(
        &mut self,
        msg: Forward<A, M>,
        ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        let Some(aref) = self.actors.get(&msg.id) else {
            tracing::trace!("actor not found");
            return RegistryForward::NotFound(msg.message);
        };

        // Defensive downcast: never panic here — the Forward handler is the
        // single most-used recovery path (every env.tell / env.ask /
        // env.forward goes through it). A panic kills the Registry and
        // cascades to every Uniderp via ActorGone. Treat a mismatch as
        // "actor not found" so the caller's normal not-found path runs.
        let Some(weak_aref) = aref.downcast_ref::<WeakActorRef<A>>() else {
            tracing::warn!(
                actor_ty = %type_name::<A>(),
                "registry: Forward downcast failed on stored entry; \
                 treating as not found"
            );
            return RegistryForward::NotFound(msg.message);
        };

        let Some(aref) = weak_aref.upgrade() else {
            tracing::trace!("actor dead");
            return RegistryForward::ActorDead(msg.message);
        };

        let result = ctx.try_forward(&aref, msg.message);

        RegistryForward::Forwarded(result)
    }
}

#[cfg(test)]
mod tests {
    //! Panic-hardening tests for the Registry actor.
    //!
    //! These tests verify that the recovery flow's register/unregister/lookup
    //! patterns NEVER panic the Registry actor, even under adversarial
    //! conditions (missing entries, repeated unregister, lookup of a name
    //! registered under a different type). A Registry panic cascades to
    //! every Uniderp via ActorGone and silences every recovery path — so
    //! the tests must stay green for the DERP recovery architecture to work.
    //!
    //! See `DERP-RECOVERY-DESIGN.md` and the coordinator's cadfddc Gate 2
    //! post-mortem for the specific regression that motivated this hardening.

    use std::time::Duration;

    use kameo::actor::Spawn as _;

    use super::{Lookup, Register, Unregister};
    use crate::env::Env;

    /// Two distinct actor types so we can exercise cross-type lookups
    /// (register as A, look up as B — must not panic, must return None).
    struct FakeActorA;
    impl kameo::Actor for FakeActorA {
        type Args = ();
        type Error = crate::Error;
        async fn on_start(_: (), _: kameo::actor::ActorRef<Self>) -> Result<Self, Self::Error> {
            Ok(Self)
        }
    }

    struct FakeActorB;
    impl kameo::Actor for FakeActorB {
        type Args = ();
        type Error = crate::Error;
        async fn on_start(_: (), _: kameo::actor::ActorRef<Self>) -> Result<Self, Self::Error> {
            Ok(Self)
        }
    }

    /// Register an actor, then unregister it. The registry must survive both
    /// operations without panic.
    #[tokio::test]
    async fn register_and_unregister_does_not_panic() {
        let env = Env::new(ts_keys::NodeState::generate());
        let registry = env.registry.clone();

        let actor = FakeActorA::spawn(());
        tokio::time::sleep(Duration::from_millis(50)).await;

        // Register under a named key.
        let prev: Option<kameo::actor::WeakActorRef<FakeActorA>> = registry
            .ask(Register::<FakeActorA>::new(Some("test-name".into()), &actor))
            .await
            .unwrap();
        assert!(prev.is_none(), "first register should have no previous");

        // Unregister the same name.
        let unreg: Option<kameo::actor::WeakActorRef<FakeActorA>> = registry
            .ask(Unregister::<FakeActorA>::new(Some("test-name".into())))
            .await
            .unwrap();
        assert!(unreg.is_some(), "unregister should return the previous entry");

        // Registry must still be alive.
        assert!(registry.is_alive(), "registry survived register+unregister");
    }

    /// Unregistering a name that was never registered must NOT panic —
    /// returns None cleanly.
    #[tokio::test]
    async fn unregister_nonexistent_does_not_panic() {
        let env = Env::new(ts_keys::NodeState::generate());
        let registry = env.registry.clone();

        let result: Option<kameo::actor::WeakActorRef<FakeActorA>> = registry
            .ask(Unregister::<FakeActorA>::new(Some("never-registered".into())))
            .await
            .unwrap();
        assert!(result.is_none(), "unregister of nonexistent returns None");
        assert!(registry.is_alive(), "registry survived nonexistent unregister");
    }

    /// Looking up a name registered under a DIFFERENT actor type must NOT
    /// panic — returns None cleanly. The Id includes TypeId, so the two
    /// registrations use different keys, but this test verifies the Lookup
    /// handler's defensive downcast path doesn't panic if somehow a
    /// mismatched entry is encountered.
    #[tokio::test]
    async fn cross_type_lookup_does_not_panic() {
        let env = Env::new(ts_keys::NodeState::generate());
        let registry = env.registry.clone();

        let actor_a = FakeActorA::spawn(());
        tokio::time::sleep(Duration::from_millis(50)).await;

        // Register A under "shared-name".
        registry
            .ask(Register::<FakeActorA>::new(Some("shared-name".into()), &actor_a))
            .await
            .unwrap();

        // Look up "shared-name" as FakeActorB — different TypeId, so this
        // is a different key. Returns None without panic.
        let result = registry
            .ask(Lookup::<FakeActorB>::new(Some("shared-name".into())))
            .await
            .unwrap();
        // The DelegatedReply resolves to None: no FakeActorB under this name.
        assert!(result.is_none(), "cross-type lookup returns None");

        assert!(
            registry.is_alive(),
            "registry survived a cross-type lookup"
        );
    }

    /// Re-registering the same name (same type) returns the previous entry.
    /// The downcast must not panic on the second register.
    #[tokio::test]
    async fn reregister_same_name_returns_previous_without_panic() {
        let env = Env::new(ts_keys::NodeState::generate());
        let registry = env.registry.clone();

        let actor_a1 = FakeActorA::spawn(());
        let actor_a2 = FakeActorA::spawn(());
        tokio::time::sleep(Duration::from_millis(50)).await;

        // First register.
        let prev1 = registry
            .ask(Register::<FakeActorA>::new(Some("dup".into()), &actor_a1))
            .await
            .unwrap();
        assert!(prev1.is_none());

        // Second register under the same name — returns the previous entry.
        let prev2 = registry
            .ask(Register::<FakeActorA>::new(Some("dup".into()), &actor_a2))
            .await
            .unwrap();
        assert!(
            prev2.is_some(),
            "second register returns the previous entry"
        );

        assert!(registry.is_alive(), "registry survived re-register");
    }

    /// Repeated unregister calls (more than the number of registered actors)
    /// must not panic. The recovery flow's on_stop can fire multiple times
    /// in edge cases (kameo's supervisor-restart path), and each calls
    /// unregister.
    #[tokio::test]
    async fn repeated_unregister_does_not_panic() {
        let env = Env::new(ts_keys::NodeState::generate());
        let registry = env.registry.clone();

        let actor = FakeActorA::spawn(());
        tokio::time::sleep(Duration::from_millis(50)).await;

        registry
            .ask(Register::<FakeActorA>::new(Some("rep".into()), &actor))
            .await
            .unwrap();

        // Unregister 5 times — only the first returns Some, the rest return
        // None, none panic.
        for i in 0..5u32 {
            let result: Option<kameo::actor::WeakActorRef<FakeActorA>> = registry
                .ask(Unregister::<FakeActorA>::new(Some("rep".into())))
                .await
                .unwrap();
            if i == 0 {
                assert!(result.is_some(), "first unregister returns the entry");
            } else {
                assert!(result.is_none(), "subsequent unregister #{} returns None", i);
            }
        }

        assert!(
            registry.is_alive(),
            "registry survived 5 repeated unregister calls"
        );
    }
}
