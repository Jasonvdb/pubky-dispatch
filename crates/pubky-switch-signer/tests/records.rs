//! Local signer records retain their error provenance and exact retry bytes.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::sync::{Arc, Mutex};

use common::*;
use pubky_switch_client::StoreError;
use pubky_switch_client::store::{
    AcquireOutcome, CommitOutcome, KeyValue, MemoryStore, StateStore, StoreOwner, WriteBatch,
};
use pubky_switch_client::testing::{Fault, Router, SWITCH_ORIGIN, ScriptedSwitch};
use pubky_switch_core::enc::{b64, unb64};
use pubky_switch_core::keys::AppKeys;
use pubky_switch_signer::state::signer_namespace;
use pubky_switch_signer::{
    CertChange, ReceivingApp, RecordsFault, Refusal, Signer, SignerError, SignerRecord,
    UserConfirmed,
};
use serde_json::Value;

fn namespace(world: &World) -> String {
    signer_namespace(&world.key.public())
}

fn snapshot(world: &World, store: &MemoryStore) -> Vec<KeyValue> {
    store.scan(&namespace(world), b"", None, 10).unwrap()
}

// Every caller drops the signer and its credentials before changing the stored bytes.
fn replace(world: &World, store: &MemoryStore, records: &[KeyValue]) {
    let ns = namespace(world);
    let mut batch = WriteBatch::new();
    batch.delete(&ns, b"state").unwrap();
    batch.delete(&ns, b"flow").unwrap();
    for (key, value) in records {
        batch.put(&ns, key.clone(), value.clone()).unwrap();
    }
    store.commit(batch).unwrap();
}

fn change(records: &[KeyValue], key: &[u8], edit: impl FnOnce(&mut Value)) -> Vec<KeyValue> {
    let mut records = records.to_vec();
    let (_, bytes) = records.iter_mut().find(|(at, _)| at == key).unwrap();
    let mut value: Value = serde_json::from_slice(bytes).unwrap();
    edit(&mut value);
    *bytes = serde_json::to_vec(&value).unwrap();
    records
}

fn break_signature(value: &mut Value) {
    let signature = value.get_mut("sig").unwrap();
    let mut bytes = unb64(signature.as_str().unwrap()).unwrap();
    bytes[0] ^= 1;
    *signature = Value::String(b64(&bytes));
}

async fn assert_stored_failure(world: &World, store: &Arc<MemoryStore>, records: &[KeyValue]) {
    replace(world, store, records);
    let sent = world.transport.requests().len();
    let error = Signer::open(world.env(store.clone()), world.keyring())
        .await
        .unwrap_err();
    assert!(matches!(error, SignerError::StoredData(_)), "{error:?}");
    assert_eq!(snapshot(world, store), records);
    assert_eq!(world.transport.requests().len(), sent);
}

#[tokio::test]
async fn test_records_decode_failure_names_the_record_without_its_content() {
    let world = World::new();
    let store = Arc::new(MemoryStore::new());
    let signer = Signer::create(world.env(store.clone()), world.keyring(), SWITCH_ORIGIN)
        .await
        .unwrap();
    assert_eq!(signer.high_water().unwrap(), None);
    drop(signer);
    let original = snapshot(&world, &store);
    for (key, record) in [
        (b"state".as_slice(), SignerRecord::State),
        (b"flow", SignerRecord::Flow),
    ] {
        let mut damaged = original.clone();
        damaged.iter_mut().find(|(at, _)| at == key).unwrap().1 =
            b"{\"secret-local-value\":".to_vec();
        replace(&world, &store, &damaged);
        let error = Signer::open(world.env(store.clone()), world.keyring())
            .await
            .unwrap_err();
        assert!(
            matches!(error, SignerError::Records(RecordsFault::Undecodable {
            record: got, line: 1, column,
        }) if got == record && column > 0),
            "{error:?}"
        );
        assert!(!error.to_string().contains("secret-local-value"));
        assert_eq!(
            Signer::restore_new(
                world.env(store.clone()),
                world.keyring(),
                UserConfirmed::shown_and_confirmed()
            )
            .await
            .unwrap_err(),
            error
        );
        assert_eq!(snapshot(&world, &store), damaged);
    }
    assert!(world.transport.requests().is_empty());
    assert!(world.homeserver.gets.lock().unwrap().is_empty());
    replace(&world, &store, &original);
    let mut signer = Signer::open(world.env(store), world.keyring())
        .await
        .unwrap();
    signer.resume().await.unwrap();
    assert_eq!(signer.high_water().unwrap().unwrap().version, 1);
}

struct ReadFailure {
    store: Arc<MemoryStore>,
    fail: Mutex<Option<(Vec<u8>, StoreError)>>,
}

impl StateStore for ReadFailure {
    fn get(&self, ns: &str, key: &[u8]) -> Result<Option<Vec<u8>>, StoreError> {
        if let Some((at, error)) = &*self.fail.lock().unwrap()
            && at == key
        {
            return Err(error.clone());
        }
        self.store.get(ns, key)
    }
    fn scan(
        &self,
        ns: &str,
        prefix: &[u8],
        after: Option<&[u8]>,
        limit: u32,
    ) -> Result<Vec<KeyValue>, StoreError> {
        self.store.scan(ns, prefix, after, limit)
    }
    fn commit(&self, batch: WriteBatch) -> Result<(), StoreError> {
        self.store.commit(batch)
    }
    fn acquire(&self, ns: &str, owner: StoreOwner) -> Result<AcquireOutcome, StoreError> {
        self.store.acquire(ns, owner)
    }
    fn commit_if(
        &self,
        ns: &str,
        owner: StoreOwner,
        batch: WriteBatch,
    ) -> Result<CommitOutcome, StoreError> {
        self.store.commit_if(ns, owner, batch)
    }
}

#[tokio::test]
async fn test_records_host_read_failure_precedes_local_decoding() {
    let world = World::new();
    let (signer, store) = world.enrolled().await;
    drop(signer);
    let original = snapshot(&world, &store);
    let mut damaged = original.clone();
    damaged
        .iter_mut()
        .find(|(key, _)| key == b"state")
        .unwrap()
        .1 = b"{".to_vec();
    replace(&world, &store, &damaged);
    let wrapper = Arc::new(ReadFailure {
        store: store.clone(),
        fail: Mutex::new(None),
    });
    let sent = world.transport.requests().len();
    for key in [b"state".as_slice(), b"flow"] {
        for error in [
            StoreError::Unavailable,
            StoreError::Corrupt,
            StoreError::Unknown,
            StoreError::Full,
            StoreError::Other("device fault".into()),
        ] {
            *wrapper.fail.lock().unwrap() = Some((key.to_vec(), error.clone()));
            assert_eq!(
                Signer::open(world.env(wrapper.clone()), world.keyring())
                    .await
                    .unwrap_err(),
                SignerError::Store(error)
            );
            assert_eq!(snapshot(&world, &store), damaged);
        }
    }
    *wrapper.fail.lock().unwrap() = None;
    assert!(matches!(
        Signer::open(world.env(wrapper.clone()), world.keyring()).await,
        Err(SignerError::Records(RecordsFault::Undecodable { .. }))
    ));
    assert_eq!(world.transport.requests().len(), sent);
    replace(&world, &store, &original);
    let signer = Signer::open(world.env(wrapper), world.keyring())
        .await
        .unwrap();
    assert_eq!(signer.high_water().unwrap().unwrap().version, 1);
}

#[tokio::test]
async fn test_records_flow_without_state_is_not_an_empty_install() {
    let world = World::new();
    let store = Arc::new(MemoryStore::new());
    let signer = Signer::create(world.env(store.clone()), world.keyring(), SWITCH_ORIGIN)
        .await
        .unwrap();
    drop(signer);
    let original = snapshot(&world, &store);
    let flow_only: Vec<_> = original
        .iter()
        .filter(|(key, _)| key == b"flow")
        .cloned()
        .collect();
    replace(&world, &store, &flow_only);
    let expected = SignerError::Records(RecordsFault::Incomplete);
    assert_eq!(
        Signer::open(world.env(store.clone()), world.keyring())
            .await
            .unwrap_err(),
        expected
    );
    assert_eq!(
        Signer::create(world.env(store.clone()), world.keyring(), SWITCH_ORIGIN)
            .await
            .unwrap_err(),
        expected
    );
    assert_eq!(
        Signer::restore_new(
            world.env(store.clone()),
            world.keyring(),
            UserConfirmed::shown_and_confirmed()
        )
        .await
        .unwrap_err(),
        expected
    );
    assert_eq!(snapshot(&world, &store), flow_only);
    assert!(world.transport.requests().is_empty());
    replace(&world, &store, &original);
    let mut signer = Signer::open(world.env(store), world.keyring())
        .await
        .unwrap();
    signer.resume().await.unwrap();
}

#[tokio::test]
async fn test_records_identity_mismatch_preserves_the_stored_pair() {
    let world = World::new();
    let (signer, store) = world.enrolled().await;
    drop(signer);
    let original = snapshot(&world, &store);
    let damaged = change(&original, b"state", |state| {
        state["identity"] = serde_json::to_value([7u8; 32]).unwrap()
    });
    replace(&world, &store, &damaged);
    assert_eq!(
        Signer::open(world.env(store.clone()), world.keyring())
            .await
            .unwrap_err(),
        SignerError::Records(RecordsFault::OtherIdentity)
    );
    assert_eq!(snapshot(&world, &store), damaged);
    replace(&world, &store, &original);
    let signer = Signer::open(world.env(store.clone()), world.keyring())
        .await
        .unwrap();
    drop(signer);
    assert_eq!(
        Signer::create(world.env(store), world.keyring(), SWITCH_ORIGIN)
            .await
            .unwrap_err(),
        SignerError::Refused(Refusal::AlreadySetUp)
    );
}

#[tokio::test]
async fn test_records_stored_identity_and_certificate_fail_locally() {
    let world = World::new();
    let (mut signer, store) = world.enrolled().await;
    let app = App::new(&["notes"], None, [9; 32]);
    world.approve(&mut signer, &app).await;
    let mark = signer.high_water().unwrap();
    let apps = signer.apps().unwrap();
    drop(signer);
    let original = snapshot(&world, &store);
    for path in ["/newest/doc", "/certs/0"] {
        let damaged = change(&original, b"state", |state| {
            break_signature(state.pointer_mut(path).unwrap())
        });
        assert_stored_failure(&world, &store, &damaged).await;
    }
    replace(&world, &store, &original);
    let signer = Signer::open(world.env(store), world.keyring())
        .await
        .unwrap();
    assert_eq!(signer.high_water().unwrap(), mark);
    assert_eq!(signer.apps().unwrap(), apps);
}

#[tokio::test]
async fn test_records_enrollment_and_delivery_copies_fail_before_retry() {
    let world = World::new();
    let store = Arc::new(MemoryStore::new());
    let signer = Signer::create(world.env(store.clone()), world.keyring(), SWITCH_ORIGIN)
        .await
        .unwrap();
    drop(signer);
    let enrolled = snapshot(&world, &store);
    let damaged = change(&enrolled, b"flow", |flow| {
        break_signature(&mut flow["Enroll"]["enrollment"])
    });
    assert_stored_failure(&world, &store, &damaged).await;
    replace(&world, &store, &enrolled);
    let mut signer = Signer::open(world.env(store.clone()), world.keyring())
        .await
        .unwrap();
    signer.resume().await.unwrap();
    *world.homeserver.failing_puts.lock().unwrap() = true;
    assert!(matches!(
        signer.set_record_max_age(Some(60)).await,
        Err(SignerError::Homeserver(_))
    ));
    drop(signer);
    let pending = snapshot(&world, &store);
    for path in ["/Deliver/doc", "/Deliver/backup"] {
        let damaged = change(&pending, b"flow", |flow| {
            break_signature(flow.pointer_mut(path).unwrap())
        });
        assert_stored_failure(&world, &store, &damaged).await;
    }
    replace(&world, &store, &pending);
    *world.homeserver.failing_puts.lock().unwrap() = false;
    let mut signer = Signer::open(world.env(store), world.keyring())
        .await
        .unwrap();
    signer.resume().await.unwrap();
    assert_eq!(
        signer
            .identity_doc()
            .unwrap()
            .unwrap()
            .body()
            .record_max_age,
        Some(60)
    );
    world.assert_no_version_sent_twice();
}

#[tokio::test]
async fn test_records_renewal_operation_authentication_precedes_retry() {
    let world = World::new();
    let (mut signer, store) = world.enrolled().await;
    let app = App::new(&["notes"], None, [9; 32]);
    world.approve(&mut signer, &app).await;
    world.switch.fail_next(Fault::Unanswered {
        path: "/ops".into(),
        after: 0,
    });
    assert!(matches!(
        signer
            .renew(
                app.keys.app_id_bytes(),
                CertChange {
                    scopes: None,
                    expires_at: Some(START_MS + 400 * 86_400_000),
                }
            )
            .await,
        Err(SignerError::Switch(_))
    ));
    drop(signer);
    let original = snapshot(&world, &store);
    let damaged = change(&original, b"flow", |flow| {
        let bytes = &mut flow["Renew"]["batches"][0]["bytes"];
        let mut batch: Value =
            serde_json::from_slice(&unb64(bytes.as_str().unwrap()).unwrap()).unwrap();
        break_signature(&mut batch["ops"][0]);
        *bytes = Value::String(b64(&serde_json::to_vec(&batch).unwrap()));
    });
    assert_stored_failure(&world, &store, &damaged).await;
    replace(&world, &store, &original);
    let mut signer = Signer::open(world.env(store), world.keyring())
        .await
        .unwrap();
    signer.resume().await.unwrap();
    world.assert_no_version_sent_twice();
}

#[tokio::test]
async fn test_records_recovery_base_and_enrollment_are_authenticated() {
    let world = World::new();
    let (signer, store) = world.enrolled().await;
    drop(signer);
    let origin = "https://recovery.example";
    let service = ScriptedSwitch::unenrolled_at(&world.key, [5; 32], world.clock.clone(), origin);
    let router = Arc::new(Router::new());
    router.add_switch(SWITCH_ORIGIN, &world.switch);
    router.add_switch(origin, &service);
    let mut env = world.env(store.clone());
    env.transport = router.clone();
    let mut signer = Signer::open(env, world.keyring()).await.unwrap();
    service.fail_next(Fault::Unanswered {
        path: "/enroll".into(),
        after: 0,
    });
    assert!(matches!(
        signer
            .declare_provider_loss(origin, UserConfirmed::shown_and_confirmed())
            .await,
        Err(SignerError::Switch(_))
    ));
    drop(signer);
    let original = snapshot(&world, &store);
    for (key, path) in [
        (b"state".as_slice(), "/recovery_base"),
        (b"flow", "/Recover/enrollment"),
    ] {
        let damaged = change(&original, key, |value| {
            break_signature(value.pointer_mut(path).unwrap())
        });
        assert_stored_failure(&world, &store, &damaged).await;
    }
    replace(&world, &store, &original);
    let mut env = world.env(store);
    env.transport = router;
    let mut signer = Signer::open(env, world.keyring()).await.unwrap();
    signer.resume().await.unwrap();
    assert_eq!(signer.high_water().unwrap().unwrap().generation, 2);
}

#[tokio::test]
async fn test_records_handover_authentication_does_not_classify_wrong_app_keys_as_corruption() {
    let world = World::new();
    let (mut old, old_store) = world.enrolled().await;
    let app = App::new(&["notes"], None, [9; 32]);
    let review = old.review(&app.request, &app.auth).unwrap();
    let approved = old.approve(review).await.unwrap();
    old.claim_delivered(&approved.request).await.unwrap();
    let cert = world.join(&app, &approved);
    old.hand_over_to(cert.app_id(), UserConfirmed::shown_and_confirmed())
        .await
        .unwrap();
    drop(old);
    let original = snapshot(&world, &old_store);
    for path in ["/handing_over/doc", "/handing_over/handover"] {
        let damaged = change(&original, b"state", |state| {
            break_signature(state.pointer_mut(path).unwrap())
        });
        assert_stored_failure(&world, &old_store, &damaged).await;
    }
    replace(&world, &old_store, &original);
    let target = ReceivingApp {
        keys: app.keys,
        cert,
        origin: SWITCH_ORIGIN.into(),
        service_key: world.switch.service_key(),
    };
    let store = Arc::new(MemoryStore::new());
    let vault = Arc::new(Vault(Mutex::new(None)));
    world.switch.fail_next(Fault::Unanswered {
        path: "/identity".into(),
        after: 0,
    });
    assert!(matches!(
        Signer::receive_hand_over(world.env(store.clone()), &target, vault.clone()).await,
        Err(SignerError::Switch(_))
    ));
    let pending = snapshot(&world, &store);
    let wrong = AppKeys::from_secrets([88; 32], [89; 32]);
    assert!(matches!(
        Signer::resume_take_over(
            world.env(store.clone()),
            world.key.public(),
            &wrong,
            vault.clone()
        )
        .await,
        Err(SignerError::InvalidData(_))
    ));
    assert_eq!(snapshot(&world, &store), pending);
    for path in ["/TakingOver/handover", "/TakingOver/delivery/doc"] {
        let damaged = change(&pending, b"flow", |flow| {
            break_signature(flow.pointer_mut(path).unwrap())
        });
        replace(&world, &store, &damaged);
        assert!(matches!(
            Signer::resume_take_over(
                world.env(store.clone()),
                world.key.public(),
                &target.keys,
                vault.clone()
            )
            .await,
            Err(SignerError::StoredData(_))
        ));
        assert_eq!(snapshot(&world, &store), damaged);
    }
    replace(&world, &store, &pending);
    let signer =
        Signer::resume_take_over(world.env(store), world.key.public(), &target.keys, vault)
            .await
            .unwrap();
    assert_eq!(
        signer.identity_doc().unwrap().unwrap().body().signer,
        signer.install_id()
    );
    world.assert_no_version_sent_twice();
}
