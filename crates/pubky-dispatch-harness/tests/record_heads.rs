//! Every answer to an own app's record read and list page carries the head it is current at
//! (Dispatch wire 7.1, 7.4.9), on the service and on the scripted Dispatch alike: at a serving
//! account, and after a provider loss before any write at the new service.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::sync::Arc;

use pubky_dispatch_client::app::{App, AppConfig, RecordTarget};
use pubky_dispatch_client::client::{Credentials, DispatchClient};
use pubky_dispatch_client::store::MemoryStore;
use pubky_dispatch_client::testing::TestIdentity;
use pubky_dispatch_harness::parties::{Asking, notes_collection, notes_protocol_with_records};
use pubky_dispatch_harness::{Backend, World};
use pubky_dispatch_signer::{Signer, UserConfirmed};

const ORIGIN: &str = "https://switch.example";
const RECOVERY: &str = "https://recovery.example";

/// alice's wallet, joined at [`ORIGIN`], with her signer.
async fn wallet(
    world: &World,
) -> (
    TestIdentity,
    Signer,
    App,
    pubky_dispatch_core::keys::AppKeys,
) {
    let who = world.identity("alice").unwrap();
    world.add_dispatch(ORIGIN, &[&who]).await.unwrap();
    let mut signer = Box::pin(Signer::create(
        world
            .signer_env(&who, Arc::new(MemoryStore::new()))
            .unwrap(),
        world.keyring(&who).unwrap(),
        ORIGIN,
    ))
    .await
    .unwrap();
    Box::pin(signer.resume()).await.unwrap();
    let asking = Asking::new(world.app_keys(&who, "wallet").unwrap()).unwrap();
    let checked = signer
        .review(asking.request.signed(), &asking.auth)
        .unwrap();
    let approved = Box::pin(signer.approve(checked)).await.unwrap();
    signer.claim_delivered(&approved.request).await.unwrap();
    let mut app = Box::pin(App::join(
        world.app_env(Arc::new(MemoryStore::new())),
        notes_protocol_with_records(),
        AppConfig::default(),
        asking.join_request(who.public(), &approved).unwrap(),
    ))
    .await
    .unwrap();
    Box::pin(app.receive(None)).await.unwrap();
    (who, signer, app, asking.keys)
}

fn client_at(
    world: &World,
    who: &TestIdentity,
    keys: &pubky_dispatch_core::keys::AppKeys,
    app: &App,
    origin: &str,
) -> DispatchClient {
    DispatchClient::new(
        origin,
        who.public(),
        Credentials::App {
            identity: who.public(),
            keys: keys.clone(),
            cert: app.cert().clone(),
        },
        Some(app.own_identity().inbox().service_key),
        world.transport(),
        world.clock().clone(),
    )
    .unwrap()
}

/// A record read and a list page each carry the head, of the generation the account serves.
async fn read_and_page_carry_the_head(
    client: &DispatchClient,
    who: &TestIdentity,
    key: &[u8; 32],
    generation: u64,
) {
    let answer = client.record(key).await.unwrap();
    assert_eq!(answer.head.generation, generation);
    assert!(answer.head.seq >= answer.view.seq);
    let page = client
        .records(&notes_collection().id(&who.public()), None, None)
        .await
        .unwrap();
    assert_eq!(page.head.generation, generation);
    assert_eq!(page.records.len(), 1);
}

async fn heads_on_record_reads(world: &World) {
    let (who, mut signer, mut app, keys) = wallet(world).await;
    let target = RecordTarget::new(notes_collection(), b"shared");
    let key = app.record_key(&target).unwrap();
    app.put_record(&target, br#"{"n":1}"#, Vec::new())
        .await
        .unwrap();
    let client = client_at(world, &who, &keys, &app, ORIGIN);
    read_and_page_carry_the_head(&client, &who, &key, 1).await;
    // After a provider loss, before any write at the new service: the record the wallet
    // uploaded is read with the new generation's head.
    world.lose_dispatch(ORIGIN);
    world.add_dispatch(RECOVERY, &[&who]).await.unwrap();
    Box::pin(signer.declare_provider_loss(RECOVERY, UserConfirmed::shown_and_confirmed()))
        .await
        .unwrap();
    Box::pin(signer.end_staged_admission()).await.unwrap();
    Box::pin(app.refresh_identity()).await.unwrap();
    Box::pin(app.follow_provider()).await.unwrap();
    let client = client_at(world, &who, &keys, &app, RECOVERY);
    read_and_page_carry_the_head(&client, &who, &key, 2).await;
}

#[tokio::test]
async fn test_record_heads_on_reads_and_pages_service() {
    let Some(world) = World::start(Backend::Service).unwrap() else {
        return;
    };
    Box::pin(heads_on_record_reads(&world)).await;
    world.close().await.unwrap();
}

#[tokio::test]
async fn test_record_heads_on_reads_and_pages_scripted() {
    let Some(world) = World::start(Backend::Scripted).unwrap() else {
        return;
    };
    Box::pin(heads_on_record_reads(&world)).await;
    world.close().await.unwrap();
}
