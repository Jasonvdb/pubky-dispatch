//! The signer steps a browser host takes, run natively and, through `browser/test.sh`, in a
//! headless browser as wasm32-unknown-unknown: enrolling the identity and publishing its first
//! `identity.json` (Dispatch spec 4.3), approving an app that then joins (Dispatch wire 3.9,
//! 3.10), and the two ways a host starts again: opening the records its store kept, or, with the
//! identity key alone, restoring from the signer backup on the Homeserver (Dispatch spec 12.8,
//! Dispatch wire 3.13).
//!
//! Every output is checked with the core's own verification: the published `identity.json`
//! against the identity key, the backup opened with it, the companion claim verified against
//! the identity and the auth request, and the approval opened with the app's bundle key. The
//! certificate and the scope key an app gets do not depend on randomness, so both builds must
//! produce the same bytes: [`CERT_HASH`] and [`NOTES_KEY`] are that fixed vector, and a build
//! whose signing, hashing, key derivation or sealing differs fails here.
//!
//! The signer reads time only from the host's clock in its environment, never from
//! `std::time`, which panics on wasm32-unknown-unknown: these flows run with the fixtures'
//! fixed clock, so any read of the system clock on their paths would fail the browser run.

// Fixtures and tests, where a failure is a test failure: the workspace's no-panic lints don't
// apply.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use common::*;
use std::sync::Arc;

use pubky_dispatch_client::store::MemoryStore;
use pubky_dispatch_client::testing::DISPATCH_ORIGIN;
use pubky_dispatch_core::keys::{AppKeys, ScopeKeys};
use pubky_dispatch_core::records::AuthRequest;
use pubky_dispatch_signer::{Refusal, Signer, SignerError, SignerStatus, UserConfirmed};

// No `wasm_bindgen_test_configure!`: `browser/runner.mjs` picks a page or a dedicated worker
// through wasm-bindgen-test-runner's environment, so the same build runs in both.

/// The hash of the certificate the signer issues to the app of [`App::new`] for `notes`, with
/// the fixtures' identity key and clock, in lowercase hex.
const CERT_HASH: &str = "021f3d6e6b181e1e5a9a824c7f5fc43b069d91d81d1f22fa86ab76281df666a7";

/// The key of the scope `notes` at data epoch 1 that the app reads from its approval, in
/// lowercase hex.
const NOTES_KEY: &str = "56575057f55ca7f6e7abd3afc1d86f10c0f557b0e66601933cfc42ce82086c30";

fn notes_app() -> App {
    App::new(&["notes"], None, [9; 32])
}

#[cfg_attr(
    all(target_arch = "wasm32", target_os = "unknown"),
    wasm_bindgen_test::wasm_bindgen_test
)]
#[cfg_attr(not(target_arch = "wasm32"), tokio::test)]
async fn test_browser_enrollment_publishes_a_verified_identity_json() {
    let world = World::new();
    let (signer, _) = world.enrolled().await;
    assert_eq!(signer.status(), SignerStatus::Signing);
    assert_eq!(signer.identity(), world.key.public());
    let doc = signer.identity_doc().unwrap().unwrap();
    assert_eq!((doc.version(), doc.generation()), (1, 1));
    assert_eq!(doc.inbox().url, DISPATCH_ORIGIN);
    assert_eq!(doc.body().signer, signer.install_id());
    // The Homeserver's copy verifies against the identity key, and the Dispatch holds the same.
    assert_eq!(world.published().unwrap().signed(), doc.signed());
    assert_eq!(
        world.dispatch.identity_doc().unwrap().signed(),
        doc.signed()
    );
    // The backup opens with the identity key and holds that version.
    assert_eq!(world.backup().identity_doc().signed(), doc.signed());
}

#[cfg_attr(
    all(target_arch = "wasm32", target_os = "unknown"),
    wasm_bindgen_test::wasm_bindgen_test
)]
#[cfg_attr(not(target_arch = "wasm32"), tokio::test)]
async fn test_browser_enrollment_refuses_an_origin_that_isnt_a_dispatch_origin() {
    let world = World::new();
    let store = Arc::new(MemoryStore::new());
    let refused = Signer::create(world.env(store), world.keyring(), "http://dispatch.example")
        .await
        .unwrap_err();
    assert!(
        matches!(refused, SignerError::InvalidData(_)),
        "{refused:?}"
    );
}

#[cfg_attr(
    all(target_arch = "wasm32", target_os = "unknown"),
    wasm_bindgen_test::wasm_bindgen_test
)]
#[cfg_attr(not(target_arch = "wasm32"), tokio::test)]
async fn test_browser_approval_gives_the_fixed_certificate_and_scope_key() {
    let world = World::new();
    let (mut signer, _) = world.enrolled().await;
    let app = notes_app();
    let review = signer.review(&app.request, &app.auth).unwrap();
    let approved = signer.approve(review).await.unwrap();
    assert_eq!(approved.app_id, app.keys.app_id_bytes());
    signer.claim_delivered(&approved.request).await.unwrap();
    // The app verifies the claim against the identity and its auth request, opens the approval
    // with its bundle key, and delivers its record to the Dispatch with the certificate.
    let cert = world.join(&app, &approved);
    assert_eq!(hex::encode(cert.hash()), CERT_HASH);
    let held = world.approval_keys.lock().unwrap()[&app.keys.app_id_bytes()].clone();
    let notes = held.get(1, "notes").unwrap();
    let derived = ScopeKeys::derive_range(&world.key, &["notes".to_owned()], 1, 1);
    assert_eq!(Some(notes), derived.get(1, "notes"));
    assert_eq!(hex::encode(notes), NOTES_KEY);
    // The next version lists the app with that certificate, on the Homeserver too.
    let doc = signer.identity_doc().unwrap().unwrap();
    assert_eq!(doc.version(), 2);
    assert_eq!(doc.listed_cert(&app.keys.app_id_bytes()), Some(cert.hash()));
    assert_eq!(world.published().unwrap().signed(), doc.signed());
    assert!(
        signer
            .certificates()
            .unwrap()
            .iter()
            .any(|held| held.hash() == cert.hash())
    );
}

#[cfg_attr(
    all(target_arch = "wasm32", target_os = "unknown"),
    wasm_bindgen_test::wasm_bindgen_test
)]
#[cfg_attr(not(target_arch = "wasm32"), tokio::test)]
async fn test_browser_approval_refuses_a_request_bound_to_another_auth_request() {
    let world = World::new();
    let (signer, _) = world.enrolled().await;
    let app = notes_app();
    let other = AuthRequest {
        secret: [10; 32],
        ..app.auth.clone()
    };
    let refused = signer.review(&app.request, &other).unwrap_err();
    assert!(
        matches!(refused, SignerError::Refused(Refusal::AppRequest { .. })),
        "{refused:?}"
    );
}

#[cfg_attr(
    all(target_arch = "wasm32", target_os = "unknown"),
    wasm_bindgen_test::wasm_bindgen_test
)]
#[cfg_attr(not(target_arch = "wasm32"), tokio::test)]
async fn test_browser_start_up_opens_the_records_the_store_kept() {
    let world = World::new();
    let (mut signer, store) = world.enrolled().await;
    let app = notes_app();
    let before = world.approve(&mut signer, &app).await;
    let install = signer.install_id();
    signer.close().await.unwrap();

    let mut reopened = Signer::open(world.env(store), world.keyring())
        .await
        .unwrap();
    reopened.resume().await.unwrap();
    let due = reopened.run_due().await.unwrap();
    assert!(!due.more_due());
    assert_eq!(reopened.status(), SignerStatus::Signing);
    assert_eq!(reopened.install_id(), install);
    assert_eq!(
        reopened.identity_doc().unwrap().unwrap().signed(),
        before.signed()
    );
    // It goes on signing: a second app is approved as version 3.
    let second = App::with_keys(
        AppKeys::from_secrets([5; 32], [6; 32]),
        &["notes"],
        None,
        [12; 32],
    );
    let doc = world.approve(&mut reopened, &second).await;
    assert_eq!(doc.version(), 3);
}

#[cfg_attr(
    all(target_arch = "wasm32", target_os = "unknown"),
    wasm_bindgen_test::wasm_bindgen_test
)]
#[cfg_attr(not(target_arch = "wasm32"), tokio::test)]
async fn test_browser_start_up_refuses_to_open_an_empty_store() {
    let world = World::new();
    let refused = Signer::open(world.env(Arc::new(MemoryStore::new())), world.keyring())
        .await
        .unwrap_err();
    assert_eq!(refused, SignerError::Refused(Refusal::NotSetUp));
}

#[cfg_attr(
    all(target_arch = "wasm32", target_os = "unknown"),
    wasm_bindgen_test::wasm_bindgen_test
)]
#[cfg_attr(not(target_arch = "wasm32"), tokio::test)]
async fn test_browser_start_up_restores_from_the_backup_with_the_key_alone() {
    // The browser lost its store: the identity key, from the host's own secret, and the
    // backup on the Homeserver bring the signer back as a new install.
    let world = World::new();
    let (mut old, _) = world.enrolled().await;
    let app = notes_app();
    let before = world.approve(&mut old, &app).await;
    let old_install = old.install_id();
    drop(old);

    let empty = Arc::new(MemoryStore::new());
    let mut restored = Signer::restore_new(
        world.env(empty),
        world.keyring(),
        UserConfirmed::shown_and_confirmed(),
    )
    .await
    .unwrap();
    assert_eq!(restored.status(), SignerStatus::Signing);
    assert_ne!(restored.install_id(), old_install);
    let doc = restored.identity_doc().unwrap().unwrap();
    assert_eq!(doc.version(), before.version() + 1);
    assert_eq!(doc.body().signer, restored.install_id());
    assert_eq!(doc.body().apps, before.body().apps);
    assert_eq!(world.published().unwrap().signed(), doc.signed());
    assert_eq!(world.backup().identity_doc().signed(), doc.signed());
    // The restored install approves the next app.
    let second = App::with_keys(
        AppKeys::from_secrets([5; 32], [6; 32]),
        &["notes"],
        None,
        [12; 32],
    );
    let next = world.approve(&mut restored, &second).await;
    assert_eq!(next.version(), doc.version() + 1);
}

#[cfg_attr(
    all(target_arch = "wasm32", target_os = "unknown"),
    wasm_bindgen_test::wasm_bindgen_test
)]
#[cfg_attr(not(target_arch = "wasm32"), tokio::test)]
async fn test_browser_start_up_refuses_a_restore_without_a_backup() {
    let world = World::new();
    let (old, _) = world.enrolled().await;
    drop(old);
    world
        .homeserver
        .files
        .lock()
        .unwrap()
        .remove(pubky_dispatch_core::records::SIGNER_BACKUP_PATH);
    let refused = Signer::restore_new(
        world.env(Arc::new(MemoryStore::new())),
        world.keyring(),
        UserConfirmed::shown_and_confirmed(),
    )
    .await
    .unwrap_err();
    assert_eq!(refused, SignerError::Refused(Refusal::NoBackup));
}
