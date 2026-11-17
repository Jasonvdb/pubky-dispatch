//! Relative app-record expiry with an independently regressed publisher clock.
#![allow(clippy::unwrap_used)]

use std::sync::Arc;

use pubky_switch_client::app::{App, AppConfig};
use pubky_switch_client::clock::TestClock;
use pubky_switch_client::store::MemoryStore;
use pubky_switch_core::records::{AppRecord, DAY_MS, app_record_path};
use pubky_switch_core::sig::SignedDoc;
use pubky_switch_harness::parties::{Asking, notes_protocol};
use pubky_switch_harness::{Backend, World};
use pubky_switch_signer::Signer;
use serde_json::json;

async fn rollback(world: &World) {
    let alice = world.identity("alice").unwrap();
    let origin = "https://switch.example";
    world.add_switch(origin, &[&alice]).await.unwrap();
    let mut signer = Box::pin(Signer::create(
        world
            .signer_env(&alice, Arc::new(MemoryStore::new()))
            .unwrap(),
        world.keyring(&alice).unwrap(),
        origin,
    ))
    .await
    .unwrap();
    Box::pin(signer.resume()).await.unwrap();
    let asking = Asking::new(world.app_keys(&alice, "wallet").unwrap()).unwrap();
    let checked = signer
        .review(asking.request.signed(), &asking.auth)
        .unwrap();
    let approved = Box::pin(signer.approve(checked)).await.unwrap();
    signer.claim_delivered(&approved.request).await.unwrap();
    let store = Arc::new(MemoryStore::new());
    let config = AppConfig {
        publishes_record: true,
        ..AppConfig::default()
    };
    let mut app = Box::pin(App::join(
        world.app_env(store.clone()),
        notes_protocol(),
        config.clone(),
        asking.join_request(alice.public(), &approved).unwrap(),
    ))
    .await
    .unwrap();
    app.set_protocol_member_with_lifetime(
        "notes",
        json!({"endpoint": "first"}).as_object().cloned(),
        Some(DAY_MS),
    )
    .await
    .unwrap();
    let id = app.app_id();
    let clock = Arc::new(TestClock::new(world.now_ms() - 40 * DAY_MS));
    drop(app);
    world.advance_ms(31 * DAY_MS);
    let mut env = world.app_env(store);
    env.clock = clock;
    let mut app = Box::pin(App::load(env, notes_protocol(), config, id))
        .await
        .unwrap();
    for renewal in [false, true] {
        if renewal {
            app.renew_record_with_lifetime("notes", Some(DAY_MS))
                .await
                .unwrap();
        } else {
            app.set_protocol_member_with_lifetime(
                "notes",
                json!({"endpoint": "changed"}).as_object().cloned(),
                Some(DAY_MS),
            )
            .await
            .unwrap();
        }
        let bytes = world
            .files()
            .file(alice.public(), &app_record_path(&id))
            .unwrap();
        let signed: SignedDoc = serde_json::from_slice(&bytes).unwrap();
        let read = AppRecord::verify(&signed, &alice.public()).unwrap();
        assert_eq!(read.signed(), app.record());
        assert!(read.updated_at() >= world.now_ms());
        assert!(!read.is_ahead(world.now_ms()));
        assert_eq!(read.expires_at(), Some(read.updated_at() + DAY_MS));
        assert!(read.trusted_until(86_400) > world.now_ms());
        assert_eq!(
            read.body().protocol("notes"),
            json!({"endpoint": "changed"}).as_object()
        );
    }
}

#[tokio::test]
async fn test_record_lifetime_rollback_mutation_and_renewal_on_both_backends() {
    for backend in [Backend::Scripted, Backend::Service] {
        let Some(world) = World::start(backend).unwrap() else {
            return;
        };
        Box::pin(rollback(&world)).await;
        world.close().await.unwrap();
    }
}
