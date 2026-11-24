//! Restored delivery deadlines while a lagging app prepares an append (Switch spec 11).
#![allow(clippy::unwrap_used)]

use std::sync::Arc;

use pubky_switch_client::app::{App, AppConfig, OutgoingMessage};
use pubky_switch_client::clock::{Clock, TestClock};
use pubky_switch_client::store::MemoryStore;
use pubky_switch_client::testing::{TestIdentity, TestProtocol};
use pubky_switch_core::records::{CLOCK_TOLERANCE_MS, DAY_MS};
use pubky_switch_harness::parties::{Asking, NOTE_KIND, notes_protocol};
use pubky_switch_harness::{Backend, World};
use pubky_switch_signer::Signer;
use serde_json::json;

const ORIGIN: &str = "https://switch.example";
const DEVICE_LAG_MS: u64 = 120_000;

struct Behind(Arc<TestClock>);

impl Clock for Behind {
    fn now_ms(&self) -> u64 {
        self.0.now_ms() - DEVICE_LAG_MS
    }
}

async fn join(world: &World, who: &TestIdentity, name: &str) -> (App, Arc<TestProtocol>) {
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
    let protocol = notes_protocol();
    let mut app = Box::pin(App::join(
        world.app_env(Arc::new(MemoryStore::new())),
        protocol.clone(),
        AppConfig::default(),
        asking.join_request(who.public(), &approved).unwrap(),
    ))
    .await
    .unwrap();
    Box::pin(app.receive(None)).await.unwrap();
    (app, protocol)
}

async fn prepare_at_deadline(world: &World, elapsed: u64) {
    let alice = world.identity("alice").unwrap();
    let bob = world.identity("bob").unwrap();
    world.add_switch(ORIGIN, &[&alice, &bob]).await.unwrap();
    let (mut wallet, wallet_protocol) = Box::pin(join(world, &alice, "wallet")).await;
    let (mut shop, shop_protocol) = Box::pin(join(world, &bob, "shop")).await;
    Box::pin(shop.invite(&alice.public())).await.unwrap();
    let signed = wallet
        .sign_message(OutgoingMessage::new(
            bob.public(),
            NOTE_KIND,
            json!({"text": "hello"}).as_object().unwrap().clone(),
        ))
        .unwrap();
    Box::pin(wallet.queue_signed(signed.clone())).await.unwrap();
    let verified = wallet.highest_service_time().unwrap();
    let backup = Box::pin(wallet.backup()).await.unwrap();
    drop(wallet);
    let mut env = world.app_env(Arc::new(MemoryStore::new()));
    env.clock = Arc::new(Behind(world.clock().clone()));
    let mut restored = Box::pin(App::restore(
        env,
        wallet_protocol,
        AppConfig::default(),
        &backup,
    ))
    .await
    .unwrap();
    // The protocol, after its read, still wants the message the restore holds.
    for held in restored.held_messages("notes").await.unwrap() {
        restored
            .release_message(
                "notes",
                &held,
                pubky_switch_client::app::ReplyGrantOnRelease::AsTheMessageSays,
            )
            .await
            .unwrap();
    }
    let deadline = verified - CLOCK_TOLERANCE_MS + 30 * DAY_MS;
    world.advance_ms(deadline - 1 - world.now_ms());
    let reads = world.files().identity_reads(&bob.public());
    world
        .files()
        .slow_reads(bob.public(), world.clock().clone(), elapsed);
    let from = world.trace().lines.len();
    let report = Box::pin(restored.flush_outbox()).await.unwrap();
    assert_eq!(world.files().identity_reads(&bob.public()), reads + 1);
    assert_eq!(world.now_ms(), deadline - 1 + elapsed);
    let appends = world.trace().lines[from..]
        .iter()
        .filter(|line| line.label.contains(" POST ") && line.label.ends_with("/inbox"))
        .count();
    if elapsed == 1 {
        assert_eq!(appends, 1, "equality allows the prepared append");
        assert_eq!(report.done, vec![signed.msg_id().to_owned()]);
    } else {
        assert_eq!(appends, 0, "preparation exhausted the replay window");
        assert_eq!(report.unknown, vec![signed.msg_id().to_owned()]);
    }
    Box::pin(shop.receive(None)).await.unwrap();
    assert_eq!(shop_protocol.received().len(), usize::from(elapsed == 1));
}

#[tokio::test]
async fn test_replay_preparation_clock_on_both_backends() {
    for backend in [Backend::Scripted, Backend::Service] {
        for elapsed in [1, 2] {
            let Some(world) = World::start(backend).unwrap() else {
                continue;
            };
            Box::pin(prepare_at_deadline(&world, elapsed)).await;
            world.close().await.unwrap();
        }
    }
}
