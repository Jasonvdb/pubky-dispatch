//! Explicit removal evidence across collection of the recovery opening (Switch spec 12.6).

use super::*;
use crate::Backend;
use crate::parties::{Asking, notes_protocol};
use pubky_switch_client::app::{AppConfig, AppEnv, AppError};
use pubky_switch_client::testing::TestIdentity;
use pubky_switch_client::transport::{
    BoxFuture, FirstSend, Request, Response, Transport, TransportError,
};

// Poll the in-process HTTP handler separately, as a deployed service would be.
struct ServiceTask(Arc<dyn Transport>);

impl Transport for ServiceTask {
    fn send(&self, request: Request) -> BoxFuture<'_, Result<Response, TransportError>> {
        let transport = self.0.clone();
        Box::pin(async move {
            tokio::spawn(async move { transport.send(request).await })
                .await
                .map_err(|error| TransportError::Other(error.to_string()))?
        })
    }

    fn send_before<'a>(
        &'a self,
        request: Request,
        first: &'a FirstSend,
    ) -> BoxFuture<'a, Result<Response, TransportError>> {
        self.0.send_before(request, first)
    }
}

fn app_env(world: &World, store: Arc<MemoryStore>) -> AppEnv {
    let mut env = world.app_env(store);
    env.transport = Arc::new(ServiceTask(env.transport));
    env
}

async fn join_member(
    world: &World,
    owner: &TestIdentity,
    signer: &mut Signer,
    name: &str,
    store: Arc<MemoryStore>,
) -> Result<App, Box<dyn std::error::Error>> {
    let asking = Asking::new(world.app_keys(owner, name)?)?;
    let review = signer.review(asking.request.signed(), &asking.auth)?;
    let approved = Box::pin(signer.approve(review)).await?;
    signer.claim_delivered(&approved.request).await?;
    world.advance_ms(STEP_MS);
    let app = Box::pin(App::join(
        app_env(world, store),
        notes_protocol(),
        AppConfig::default(),
        asking.join_request(owner.public(), &approved)?,
    ))
    .await?;
    Ok(app)
}

async fn delayed_opening(world: &World, follow_before_removal: bool) -> FlowResult {
    let alice = world.identity("alice")?;
    world.add_switch(ORIGIN, &[&alice]).await?;
    let mut env = world.signer_env(&alice, Arc::new(MemoryStore::new()))?;
    env.transport = Arc::new(ServiceTask(env.transport));
    let mut signer = Box::pin(Signer::create(env, world.keyring(&alice)?, ORIGIN)).await?;
    Box::pin(signer.resume()).await?;
    world.advance_ms(STEP_MS);
    let phone = Box::pin(join_member(
        world,
        &alice,
        &mut signer,
        "phone",
        Arc::new(MemoryStore::new()),
    ))
    .await?;
    let store = Arc::new(MemoryStore::new());
    let mut wallet = Box::pin(join_member(
        world,
        &alice,
        &mut signer,
        "wallet",
        store.clone(),
    ))
    .await?;
    let survivor = wallet.app_id();
    let phone = phone.app_id();
    world.lose_switch(ORIGIN);
    world.add_switch(RECOVERY_ORIGIN, &[&alice]).await?;
    let opening = Box::pin(
        signer.declare_provider_loss(RECOVERY_ORIGIN, UserConfirmed::shown_and_confirmed()),
    )
    .await?;
    world.advance_ms(STEP_MS);
    if follow_before_removal {
        world.unreachable_after("GET", "/feed", 1);
        Box::pin(follow_recovery(world, &mut wallet, "wallet", 1)).await?;
        assert_eq!(world.faults_left(), 0);
    }
    let removed =
        Box::pin(signer.revoke(phone, None, UserConfirmed::shown_and_confirmed())).await?;
    let refresh = Box::pin(wallet.refresh_identity()).await;
    if follow_before_removal {
        refresh?;
    } else {
        // The new identity is durable before its new epoch triggers a key-bundle read
        // from the old provider, which has already disappeared (Switch spec 4.3).
        assert!(matches!(
            refresh,
            Err(AppError::Transport(TransportError::Connect(_)))
        ));
    }
    assert!(removed.lists_removed(&phone));
    assert_eq!(wallet.own_identity().hash(), removed.hash());
    if follow_before_removal {
        world.unreachable("GET", "/feed");
        assert!(matches!(
            wallet.recovery_roster().await,
            Err(AppError::Transport(TransportError::Connect(_)))
        ));
        assert_eq!(world.faults_left(), 0);
    } else {
        assert!(wallet.recovery_roster().await?.is_none());
    }
    world.advance_ms(STEP_MS);
    let purged = Box::pin(signer.purge_removed(phone)).await?;
    Box::pin(wallet.refresh_identity()).await?;
    assert!(!purged.lists_removed(&phone));
    assert_eq!(wallet.own_identity().hash(), purged.hash());
    drop(wallet);

    let mut wallet = Box::pin(App::load(
        app_env(world, store),
        notes_protocol(),
        AppConfig::default(),
        survivor,
    ))
    .await?;
    if !follow_before_removal {
        Box::pin(follow_recovery(world, &mut wallet, "wallet", 1)).await?;
    }
    let roster = wallet.recovery_roster().await?.ok_or("missing opening")?;
    assert_eq!(roster.hash(), opening.hash());
    assert!(roster.listed_cert(&phone).is_some());
    assert!(roster.listed_cert(&survivor).is_some());
    assert!(wallet.recovery_removal(&survivor).await?.is_none());
    let proof = wallet
        .recovery_removal(&phone)
        .await?
        .ok_or("missing signed removal after purge and delayed opening")?;
    assert_eq!(proof.hash(), removed.hash());
    Ok(())
}

async fn check(backend: Backend, follow_before_removal: bool) -> FlowResult {
    let Some(world) = World::start(backend)? else {
        return Ok(());
    };
    let result = Box::pin(delayed_opening(&world, follow_before_removal)).await;
    world.close().await?;
    result
}

#[tokio::test]
async fn test_removal_before_opening_at_the_service() -> FlowResult {
    Box::pin(check(Backend::Service, true)).await
}

#[tokio::test]
async fn test_removal_before_opening_at_the_scripted_switch() -> FlowResult {
    Box::pin(check(Backend::Scripted, true)).await
}

#[tokio::test]
async fn test_removal_before_follow_at_the_service() -> FlowResult {
    Box::pin(check(Backend::Service, false)).await
}

#[tokio::test]
async fn test_removal_before_follow_at_the_scripted_switch() -> FlowResult {
    Box::pin(check(Backend::Scripted, false)).await
}
