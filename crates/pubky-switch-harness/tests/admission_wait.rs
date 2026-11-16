//! Admission custody, exact drop notices and completion on both services.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use pubky_switch_client::app::{
    App, AppConfig, AppEvent, Delivery, LocalWrite, MissedEntries, Outcome, OutgoingMessage,
    Protocol, ReceiveContext, ReceivedMessage, ResendNeeded, StoreFailure,
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
struct Admission {
    base: Arc<TestProtocol>,
    consume: AtomicBool,
}
impl Protocol for Admission {
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
    fn receive(&self, _: &ReceivedMessage, cx: &mut ReceiveContext<'_>) -> Outcome {
        let n = cx.local_get(b"completed").unwrap().map_or(0, |v| v[0]);
        cx.local(LocalWrite::Put {
            key: b"completed".to_vec(),
            value: vec![n + 1],
        })
        .unwrap();
        if self.consume.load(Ordering::SeqCst) {
            Outcome::Consume
        } else {
            Outcome::AwaitAdmission
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
    let protocol = Arc::new(Admission {
        base: notes_protocol(),
        consume: AtomicBool::new(false),
    });
    let store = Arc::new(MemoryStore::new());
    let mut wallet = Box::pin(join(world, &alice, "wallet", protocol.clone(), store)).await;
    let mut sender = Box::pin(join(
        world,
        &bob,
        "sender",
        notes_protocol(),
        Arc::new(MemoryStore::new()),
    ))
    .await;
    wallet.add_contact(&bob.public()).await.unwrap();
    let mut first = None;
    for _ in 0..65 {
        let (id, delivery) = sender
            .send(OutgoingMessage::new(
                alice.public(),
                NOTE_KIND,
                json!({"text":"waiting"}).as_object().unwrap().clone(),
            ))
            .await
            .unwrap();
        assert!(
            matches!(delivery, Delivery::Accepted { .. }),
            "{delivery:?}"
        );
        first.get_or_insert(id);
        world.advance_ms(pubky_switch_harness::flows::STEP_MS);
    }
    let mut events = Vec::new();
    for _ in 0..16 {
        let report = wallet.receive(None).await.unwrap();
        events.extend(report.events);
        if !report.more {
            break;
        }
    }
    assert_eq!(
        wallet.parked_entries().await.unwrap().len(),
        64,
        "the incoming transition enforces the sender bound on both services"
    );
    assert_eq!(
        wallet.protocol_get("notes", b"completed").await.unwrap(),
        None,
        "admission commits no callback-staged local effect"
    );
    let notices: Vec<_> = events
        .iter()
        .filter_map(|event| match event {
            AppEvent::StoredEntryDropped { id, message, .. } => Some((*id, message.msg_id.clone())),
            _ => None,
        })
        .collect();
    assert_eq!(notices.len(), 1);
    assert_eq!(Some(notices[0].1.clone()), first);
    wallet
        .ack_event_with(
            "notes",
            notices[0].0,
            &[LocalWrite::Put {
                key: b"handled".to_vec(),
                value: vec![1],
            }],
        )
        .await
        .unwrap();
    let backup = wallet.backup_layered().await.unwrap();
    let mut restored = App::restore(
        world.app_env(Arc::new(MemoryStore::new())),
        protocol.clone(),
        AppConfig::default(),
        &backup,
    )
    .await
    .unwrap();
    assert_eq!(
        restored.protocol_get("notes", b"handled").await.unwrap(),
        Some(vec![1])
    );
    assert_eq!(restored.parked_entries().await.unwrap().len(), 64);
    assert!(
        !restored
            .unacknowledged_events()
            .await
            .unwrap()
            .iter()
            .any(|event| matches!(event, AppEvent::StoredEntryDropped { .. }))
    );
    restored.refresh_identity().await.unwrap();
    protocol.consume.store(true, Ordering::SeqCst);
    for _ in 0..5 {
        restored.receive(None).await.unwrap();
    }
    assert!(
        restored.parked_entries().await.unwrap().is_empty(),
        "completion retires all admitted custody"
    );
    let completed = restored
        .protocol_get("notes", b"completed")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(completed, vec![64], "every retained input completes once");
    completed
}

#[tokio::test]
async fn test_admission_custody_notice_and_completion_agree_on_both_backends() {
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
