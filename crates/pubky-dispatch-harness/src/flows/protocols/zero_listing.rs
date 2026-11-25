use super::*;
use crate::{Backend, run_here};
use pubky_dispatch_client::app::{
    Collection, DenyListGap, LocalWrite, MissedEntries, Outcome, Protocol, ReceiveContext,
    ReceivedMessage, ResendNeeded, StoreFailure,
};
use pubky_dispatch_client::testing::ProtocolSpec;
use pubky_dispatch_core::ident::Policy;
use pubky_dispatch_core::message::Message;
use pubky_dispatch_core::records::AppCert;
use pubky_dispatch_signer::UserConfirmed;
use std::sync::Mutex;

struct ListedProtocol {
    inner: Arc<TestProtocol>,
    gaps: Mutex<Vec<(u64, u64)>>,
}

impl Protocol for ListedProtocol {
    fn name(&self) -> String {
        self.inner.name()
    }
    fn has_keys(&self, scope: &str) -> bool {
        self.inner.has_keys(scope)
    }
    fn sent_between_own_apps(&self, kind: &str) -> bool {
        self.inner.sent_between_own_apps(kind)
    }
    fn check_scopes(
        &self,
        message: &Message,
        sender: &AppCert,
        own: &AppCert,
    ) -> Result<(), String> {
        self.inner.check_scopes(message, sender, own)
    }
    fn accepts(&self, cert: &AppCert) -> Vec<String> {
        self.inner.accepts(cert)
    }
    fn check_body(&self, message: &ReceivedMessage) -> Result<(), String> {
        self.inner.check_body(message)
    }
    fn receive(&self, message: &ReceivedMessage, cx: &mut ReceiveContext<'_>) -> Outcome {
        self.inner.receive(message, cx)
    }
    fn resend_needed(&self, needed: &ResendNeeded) -> Result<Vec<LocalWrite>, StoreFailure> {
        self.inner.resend_needed(needed)
    }
    fn missed(&self, missed: &MissedEntries) -> Result<Vec<LocalWrite>, StoreFailure> {
        self.inner.missed(missed)
    }
    fn collections(&self) -> Vec<Collection> {
        self.inner.collections()
    }
    fn deny_list_gap(&self, gap: &DenyListGap) -> Result<Vec<LocalWrite>, StoreFailure> {
        self.gaps.lock().unwrap().push((gap.generation, gap.seq));
        Ok(Vec::new())
    }
}

async fn listing_after_loss(world: &World) -> FlowResult {
    Box::pin(listing_and_gap(world, false)).await
}

async fn gap_after_restore(world: &World) -> FlowResult {
    Box::pin(listing_and_gap(world, true)).await
}

struct WaitingListing {
    wallet: App,
    signer: Signer,
    tasks: Arc<TestProtocol>,
    chat: Arc<TestProtocol>,
    listed: Arc<ListedProtocol>,
}

struct ListingSetup {
    waiting: WaitingListing,
    shop: App,
    phone: [u8; 16],
    protocols: ProtocolSet,
    identity: TestIdentity,
}

// Keep enrollment's polling frame separate from recovery and restore.
async fn prepare_listing(world: &World) -> Result<Box<ListingSetup>, Box<dyn std::error::Error>> {
    use crate::flows::recovery::SENDERS_ORIGIN;
    let alice = world.identity("alice")?;
    let bob = world.identity("bob")?;
    world.add_dispatch(ORIGIN, &[&alice]).await?;
    world.add_dispatch(SENDERS_ORIGIN, &[&bob]).await?;
    let mut alice_signer = Box::pin(enroll(world, &alice, ORIGIN)).await?;
    let mut bob_signer = Box::pin(enroll(world, &bob, SENDERS_ORIGIN)).await?;
    let tasks = Arc::new(TestProtocol::keeping(ProtocolSpec {
        name: TASKS.into(),
        keyed_scopes: vec![TASKS.into()],
        accepts: vec!["tasks.item".into()],
        collections: vec![Collection::new("task_lists", Policy::new(TASKS, &[TASKS]))],
    }));
    let listed = Arc::new(ListedProtocol {
        inner: tasks.clone(),
        gaps: Mutex::new(Vec::new()),
    });
    let chat = sample_protocol(CHAT);
    let protocols = ProtocolSet::new(vec![listed.clone(), chat.clone()])?;
    let asking = Asking::for_scopes(world.app_keys(&alice, "wallet")?, &[TASKS, CHAT])?;
    let review = alice_signer.review(asking.request.signed(), &asking.auth)?;
    let approved = Box::pin(alice_signer.approve(review)).await?;
    Box::pin(alice_signer.claim_delivered(&approved.request)).await?;
    let mut wallet = Box::pin(App::join(
        world.app_env(Arc::new(MemoryStore::new())),
        protocols.clone(),
        AppConfig::default(),
        asking.join_request(alice.public(), &approved)?,
    ))
    .await?;
    assert!(wallet.listing_owed().await?);
    Box::pin(wallet.keep_peer(&bob.public())).await?;
    let (phone_tasks, phone_chat) = both();
    let phone = Box::pin(joined_with_both(
        world,
        &alice,
        &mut alice_signer,
        "phone",
        set_of(&phone_tasks, &phone_chat)?,
    ))
    .await?;
    let (shop_tasks, shop_chat) = both();
    let shop = Box::pin(joined_with_both(
        world,
        &bob,
        &mut bob_signer,
        "shop",
        set_of(&shop_tasks, &shop_chat)?,
    ))
    .await?;
    Ok(Box::new(ListingSetup {
        waiting: WaitingListing {
            wallet,
            signer: alice_signer,
            tasks,
            chat,
            listed,
        },
        shop,
        phone: phone.app_id(),
        protocols,
        identity: alice,
    }))
}

async fn hold_listing(
    world: &World,
    setup: Box<ListingSetup>,
    restore: bool,
) -> Result<Box<WaitingListing>, Box<dyn std::error::Error>> {
    use crate::flows::recovery::RECOVERY_ORIGIN;
    let ListingSetup {
        waiting,
        mut shop,
        phone,
        protocols,
        identity: alice,
    } = *setup;
    let WaitingListing {
        mut wallet,
        signer: mut alice_signer,
        tasks,
        chat,
        listed,
    } = waiting;
    Box::pin(alice_signer.revoke(phone, None, UserConfirmed::shown_and_confirmed())).await?;
    world.lose_dispatch(ORIGIN);
    world.add_dispatch(RECOVERY_ORIGIN, &[&alice]).await?;
    Box::pin(
        alice_signer.declare_provider_loss(RECOVERY_ORIGIN, UserConfirmed::shown_and_confirmed()),
    )
    .await?;
    // Taking the new document may still try the lost provider for its keys. The
    // committed document lets the explicit provider follow proceed after that failure.
    if let Err(error) = Box::pin(wallet.refresh_identity()).await {
        assert!(matches!(
            error,
            pubky_dispatch_client::app::AppError::Transport(_)
        ));
    }
    assert_eq!(wallet.own_identity().generation(), 2);
    Box::pin(wallet.follow_provider()).await?;
    assert_eq!(wallet.cursor().seq, 0);
    assert_eq!(wallet.own_identity().data_epoch(), 2);
    assert!(wallet.scope_key(2, TASKS).is_none());
    if restore {
        let backup = Box::pin(wallet.backup_layered()).await?;
        wallet = Box::pin(App::restore(
            world.app_env(Arc::new(MemoryStore::new())),
            protocols,
            AppConfig::default(),
            &backup,
        ))
        .await?;
        assert_eq!((wallet.cursor().generation, wallet.cursor().seq), (2, 0));
        listed.gaps.lock().unwrap().clear();
    }
    for kind in ["tasks.item", "chat.item"] {
        let (_, delivery) = shop
            .send(OutgoingMessage::new(
                alice.public(),
                kind,
                serde_json::Map::new(),
            ))
            .await?;
        assert!(
            matches!(
                delivery,
                pubky_dispatch_client::app::Delivery::Accepted { .. }
            ),
            "{delivery:?}"
        );
    }
    for _ in 0..4 {
        Box::pin(wallet.receive(None)).await?;
    }
    assert!(wallet.listing_owed().await?);
    assert!(
        tasks.received().is_empty(),
        "a message preceded the required collection listing"
    );
    if restore {
        assert!(
            listed.gaps.lock().unwrap().is_empty(),
            "the listing precedes the gap"
        );
        assert!(
            chat.received().is_empty(),
            "the shared gap precedes every message"
        );
    } else {
        assert_eq!(
            chat.received().len(),
            1,
            "the independent protocol advances"
        );
    }
    Ok(Box::new(WaitingListing {
        wallet,
        signer: alice_signer,
        tasks,
        chat,
        listed,
    }))
}

async fn listing_and_gap(world: &World, restore: bool) -> FlowResult {
    let setup = Box::pin(prepare_listing(world)).await?;
    let mut waiting = Box::pin(hold_listing(world, setup, restore)).await?;
    Box::pin(waiting.signer.run_due()).await?;
    for _ in 0..4 {
        Box::pin(waiting.wallet.receive(None)).await?;
    }
    assert!(waiting.wallet.scope_key(2, TASKS).is_some());
    assert!(!waiting.wallet.listing_owed().await?);
    assert_eq!(waiting.tasks.received().len(), 1);
    assert_eq!(waiting.chat.received().len(), 1);
    if restore {
        assert_eq!(*waiting.listed.gaps.lock().unwrap(), [(2, 0)]);
    }
    Ok(())
}

#[tokio::test]
async fn test_zero_position_listing_waits_and_resumes_at_scripted_dispatch() {
    assert!(
        Box::pin(run_here(Backend::Scripted, listing_after_loss))
            .await
            .unwrap()
            .is_some()
    );
}

#[tokio::test]
async fn test_zero_position_listing_waits_and_resumes_at_service() {
    assert!(
        Box::pin(run_here(Backend::Service, listing_after_loss))
            .await
            .unwrap()
            .is_some()
    );
}

#[tokio::test]
async fn test_zero_listing_gap_restore_waits_and_resumes_at_scripted_dispatch() {
    assert!(
        Box::pin(run_here(Backend::Scripted, gap_after_restore))
            .await
            .unwrap()
            .is_some()
    );
}

#[tokio::test]
async fn test_zero_listing_gap_restore_waits_and_resumes_at_service() {
    assert!(
        Box::pin(run_here(Backend::Service, gap_after_restore))
            .await
            .unwrap()
            .is_some()
    );
}
