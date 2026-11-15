//! Local completion and redelivery through both services (Switch spec 11).

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;
use std::sync::atomic::{AtomicU8, Ordering};

use pubky_switch_client::app::{
    App, AppConfig, Effect, LocalWrite, MissedEntries, Outcome, OutgoingMessage, Protocol,
    ReceiveContext, ReceivedMessage, ResendNeeded, StoreFailure,
};
use pubky_switch_client::store::{MemoryStore, StoreError};
use pubky_switch_client::testing::{TestIdentity, TestProtocol};
use pubky_switch_core::message::Message;
use pubky_switch_core::records::AppCert;
use pubky_switch_harness::parties::{Asking, NOTE_KIND, notes_protocol};
use pubky_switch_harness::{Backend, World};
use pubky_switch_signer::Signer;
use serde_json::json;

const ORIGIN: &str = "https://switch.example";

struct Completing {
    base: Arc<TestProtocol>,
    mode: AtomicU8,
}

impl Protocol for Completing {
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
    fn receive(&self, message: &ReceivedMessage, cx: &mut ReceiveContext<'_>) -> Outcome {
        match self.mode.load(Ordering::SeqCst) {
            0 => Outcome::Apply(Effect::default()),
            1 => Outcome::Retry(StoreFailure::of_entry(StoreError::Corrupt)),
            _ => {
                if let Some(id) = message.message.body.get("forget").and_then(|v| v.as_str()) {
                    cx.forget_processed(message.sender, id).unwrap();
                }
                let n = cx.local_get(b"completed").unwrap().map_or(0, |v| v[0]);
                cx.local(LocalWrite::Put {
                    key: b"completed".to_vec(),
                    value: vec![n + 1],
                })
                .unwrap();
                Outcome::Consume
            }
        }
    }
}

async fn join(
    world: &World,
    who: &TestIdentity,
    name: &str,
    protocol: Arc<dyn Protocol>,
    store: Arc<MemoryStore>,
) -> App {
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
        world.app_env(store),
        protocol,
        AppConfig::default(),
        asking.join_request(who.public(), &approved).unwrap(),
    ))
    .await
    .unwrap();
    Box::pin(app.receive(None)).await.unwrap();
    app
}

async fn flow(world: &World) -> Vec<u8> {
    let alice = world.identity("alice").unwrap();
    let bob = world.identity("bob").unwrap();
    world.add_switch(ORIGIN, &[&alice, &bob]).await.unwrap();
    let protocol = Arc::new(Completing {
        base: notes_protocol(),
        mode: AtomicU8::new(0),
    });
    let store = Arc::new(MemoryStore::new());
    let mut wallet = Box::pin(join(
        world,
        &alice,
        "wallet",
        protocol.clone(),
        store.clone(),
    ))
    .await;
    let mut sender = Box::pin(join(
        world,
        &bob,
        "sender",
        notes_protocol(),
        Arc::new(MemoryStore::new()),
    ))
    .await;
    wallet.add_contact(&bob.public()).await.unwrap();
    let (prior, _) = sender
        .send(OutgoingMessage::new(
            alice.public(),
            NOTE_KIND,
            json!({"text":"prior"}).as_object().unwrap().clone(),
        ))
        .await
        .unwrap();
    wallet.receive(None).await.unwrap();
    protocol.mode.store(2, Ordering::SeqCst);
    let (current, _) = sender
        .send(OutgoingMessage::new(
            alice.public(),
            NOTE_KIND,
            json!({"text":"current", "forget":prior})
                .as_object()
                .unwrap()
                .clone(),
        ))
        .await
        .unwrap();
    wallet.receive(None).await.unwrap();
    assert_eq!(
        wallet.protocol_get(b"completed").await.unwrap(),
        Some(vec![1]),
        "feed local decision commits"
    );
    wallet.flush_cursor().await.unwrap();
    let me = wallet.app_id();
    drop(wallet);
    let mut wallet = App::load(
        world.app_env(store),
        protocol.clone(),
        AppConfig::default(),
        me,
    )
    .await
    .unwrap();
    sender.resend(&current).await.unwrap();
    wallet.receive(None).await.unwrap();
    assert_eq!(
        wallet.protocol_get(b"completed").await.unwrap(),
        Some(vec![2]),
        "consumed message is delivered after reload"
    );
    sender.resend(&prior).await.unwrap();
    wallet.receive(None).await.unwrap();
    assert_eq!(
        wallet.protocol_get(b"completed").await.unwrap(),
        Some(vec![3]),
        "forgotten prior pair is delivered again"
    );
    protocol.mode.store(1, Ordering::SeqCst);
    let (stored, _) = sender
        .send(OutgoingMessage::new(
            alice.public(),
            NOTE_KIND,
            json!({"text":"stored"}).as_object().unwrap().clone(),
        ))
        .await
        .unwrap();
    wallet.receive(None).await.unwrap();
    wallet.receive(None).await.unwrap();
    assert_eq!(wallet.parked_entries().await.unwrap().len(), 1);
    protocol.mode.store(2, Ordering::SeqCst);
    wallet.receive(None).await.unwrap();
    assert_eq!(
        wallet.protocol_get(b"completed").await.unwrap(),
        Some(vec![4]),
        "stored decision commits"
    );
    assert!(
        wallet.parked_entries().await.unwrap().is_empty(),
        "stored input is retired"
    );
    sender.resend(&stored).await.unwrap();
    wallet.receive(None).await.unwrap();
    let result = wallet.protocol_get(b"completed").await.unwrap().unwrap();
    assert_eq!(
        result,
        vec![5],
        "stored completion leaves no processed pair"
    );
    result
}

#[tokio::test]
async fn test_consume_feed_and_stored_completion_agree_on_both_backends() {
    let mut results = Vec::new();
    for backend in [Backend::Scripted, Backend::Service] {
        let Some(world) = World::start(backend).unwrap() else {
            return;
        };
        // Run on this test's stack; no larger harness thread hides a deep future.
        let result = Box::pin(flow(&world)).await;
        world.close().await.unwrap();
        results.push(result);
    }
    assert_eq!(results[0], results[1]);
}
