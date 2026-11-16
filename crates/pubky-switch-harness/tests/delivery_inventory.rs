//! Current delivery origins, inventory and the protocol gate on both services.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use pubky_switch_client::app::{
    App, AppConfig, Delivery, DeliveryOrigin, DeliveryView, LocalWrite, MissedEntries,
    OutgoingMessage, Protocol, ReceivedMessage, ResendNeeded, StoreFailure,
};
use pubky_switch_client::store::MemoryStore;
use pubky_switch_client::testing::{TestIdentity, TestProtocol};
use pubky_switch_core::message::Message;
use pubky_switch_core::records::AppCert;
use pubky_switch_harness::parties::{Asking, NOTE_KIND, notes_protocol};
use pubky_switch_harness::{Backend, World};
use pubky_switch_signer::Signer;
use serde_json::json;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

const ORIGIN: &str = "https://switch.example";

struct DeliveryPolicy {
    base: Arc<TestProtocol>,
    allow_reconstructed: AtomicBool,
}

impl Protocol for DeliveryPolicy {
    fn name(&self) -> String {
        "notes".into()
    }
    fn has_keys(&self, scope: &str) -> bool {
        self.base.has_keys(scope)
    }
    fn sent_between_own_apps(&self, kind: &str) -> bool {
        self.base.sent_between_own_apps(kind)
    }
    fn check_scopes(&self, m: &Message, s: &AppCert, o: &AppCert) -> Result<(), String> {
        self.base.check_scopes(m, s, o)
    }
    fn accepts(&self, cert: &AppCert) -> Vec<String> {
        self.base.accepts(cert)
    }
    fn check_body(&self, m: &ReceivedMessage) -> Result<(), String> {
        self.base.check_body(m)
    }
    fn resend_needed(&self, n: &ResendNeeded) -> Result<Vec<LocalWrite>, StoreFailure> {
        self.base.resend_needed(n)
    }
    fn missed(&self, m: &MissedEntries) -> Result<Vec<LocalWrite>, StoreFailure> {
        self.base.missed(m)
    }
    fn may_send(&self, delivery: &DeliveryView<'_>) -> Result<bool, StoreFailure> {
        Ok(delivery.origin() == DeliveryOrigin::Original
            || self.allow_reconstructed.load(Ordering::SeqCst))
    }
}

async fn join(world: &World, who: &TestIdentity, name: &str, protocol: Arc<dyn Protocol>) -> App {
    let mut signer = Box::pin(Signer::create(
        world.signer_env(who, Arc::new(MemoryStore::new())).unwrap(),
        world.keyring(who).unwrap(),
        ORIGIN,
    ))
    .await
    .unwrap();
    Box::pin(signer.resume()).await.unwrap();
    let asking = Asking::new(world.app_keys(who, name).unwrap()).unwrap();
    let checked = signer
        .review(asking.request.signed(), &asking.auth)
        .unwrap();
    let approved = Box::pin(signer.approve(checked)).await.unwrap();
    signer.claim_delivered(&approved.request).await.unwrap();
    let mut app = Box::pin(App::join(
        world.app_env(Arc::new(MemoryStore::new())),
        protocol,
        AppConfig::default(),
        asking.join_request(who.public(), &approved).unwrap(),
    ))
    .await
    .unwrap();
    Box::pin(app.receive(None)).await.unwrap();
    app
}

async fn flow(world: &World) -> Vec<(DeliveryOrigin, bool)> {
    let alice = world.identity("alice").unwrap();
    let bob = world.identity("bob").unwrap();
    world.add_switch(ORIGIN, &[&alice, &bob]).await.unwrap();
    let protocol = Arc::new(DeliveryPolicy {
        base: notes_protocol(),
        allow_reconstructed: AtomicBool::new(false),
    });
    let mut wallet = Box::pin(join(world, &alice, "wallet", protocol.clone())).await;
    let mut recipient = Box::pin(join(world, &bob, "recipient", protocol.clone())).await;
    Box::pin(recipient.invite(&alice.public())).await.unwrap();
    let note = |text: &str| {
        OutgoingMessage::new(
            bob.public(),
            NOTE_KIND,
            json!({"text": text}).as_object().unwrap().clone(),
        )
    };
    let original = wallet.sign_message(note("owed")).unwrap();
    let reconstructed = wallet.sign_message(note("stored")).unwrap();
    wallet.queue_signed(original.clone()).await.unwrap();
    wallet
        .queue_stored(reconstructed.plaintext())
        .await
        .unwrap();
    wallet
        .hold_message("notes", original.msg_id())
        .await
        .unwrap();
    let listed = wallet.queued_messages("notes").await.unwrap();
    assert_eq!(listed.len(), 2);
    assert!(listed.iter().all(|item| item.waits() && !item.resend));
    Box::pin(wallet.flush_outbox()).await.unwrap();
    assert!(matches!(
        wallet.delivery(original.msg_id()).await.unwrap(),
        Some(Delivery::Queued { .. })
    ));
    assert!(matches!(
        wallet.delivery(reconstructed.msg_id()).await.unwrap(),
        Some(Delivery::Queued { .. })
    ));
    let backup = wallet.backup().await.unwrap();
    drop(wallet);
    let mut restored = Box::pin(App::restore(
        world.app_env(Arc::new(MemoryStore::new())),
        protocol.clone(),
        AppConfig::default(),
        &backup,
    ))
    .await
    .unwrap();
    restored.refresh_identity().await.unwrap();
    Box::pin(restored.receive(None)).await.unwrap();
    let restored_list = restored.queued_messages("notes").await.unwrap();
    assert_eq!(restored_list.len(), 2);
    let own = restored_list
        .iter()
        .find(|item| item.msg_id == original.msg_id())
        .unwrap();
    let copy = restored_list
        .iter()
        .find(|item| item.msg_id == reconstructed.msg_id())
        .unwrap();
    assert_eq!(
        (own.origin, own.may_send, own.held),
        (DeliveryOrigin::Original, true, true)
    );
    assert_eq!(
        (copy.origin, copy.may_send, copy.held),
        (DeliveryOrigin::Reconstructed, false, false)
    );
    restored
        .release_message("notes", original.msg_id())
        .await
        .unwrap();
    Box::pin(restored.flush_outbox()).await.unwrap();
    assert!(matches!(
        restored.delivery(original.msg_id()).await.unwrap(),
        Some(Delivery::Accepted { .. })
    ));
    assert!(matches!(
        restored.delivery(reconstructed.msg_id()).await.unwrap(),
        Some(Delivery::Queued { .. })
    ));
    restored.hold_queued(&bob.public()).await.unwrap();
    Box::pin(restored.resend(original.msg_id())).await.unwrap();
    let resent = restored.queued_messages("notes").await.unwrap();
    let own = resent
        .iter()
        .find(|item| item.msg_id == original.msg_id())
        .unwrap();
    assert_eq!(
        (own.origin, own.resend, own.counterparty_held),
        (DeliveryOrigin::Original, true, true)
    );
    restored.release_queued(&bob.public()).await.unwrap();
    protocol.allow_reconstructed.store(true, Ordering::SeqCst);
    Box::pin(restored.flush_outbox()).await.unwrap();
    assert!(restored.queued_messages("notes").await.unwrap().is_empty());
    assert!(matches!(
        restored.delivery(reconstructed.msg_id()).await.unwrap(),
        Some(Delivery::Accepted { .. })
    ));
    vec![(own.origin, own.resend), (copy.origin, copy.resend)]
}

#[tokio::test]
async fn test_delivery_inventory_origin_and_restore_agree_on_both_backends() {
    let mut results = Vec::new();
    for backend in [Backend::Scripted, Backend::Service] {
        let Some(world) = World::start(backend).unwrap() else {
            return;
        };
        results.push(Box::pin(flow(&world)).await);
        world.close().await.unwrap();
    }
    assert_eq!(results[0], results[1]);
}
