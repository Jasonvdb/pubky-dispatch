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
    CertChange, ReceivingApp, RecordsDiscarded, RecordsFault, Refusal, Signer, SignerError,
    SignerRecord, UserConfirmed,
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

fn discard_confirmed() -> RecordsDiscarded {
    RecordsDiscarded::shown_and_confirmed()
}

fn unreadable_state(records: &[KeyValue]) -> Vec<KeyValue> {
    let mut records = records.to_vec();
    records
        .iter_mut()
        .find(|(key, _)| key == b"state")
        .unwrap()
        .1 = b"{".to_vec();
    records
}

#[tokio::test]
async fn test_records_confirmed_restore_uses_its_owned_current_read() {
    let world = World::new();
    let (old, store) = world.enrolled().await;
    let old_install = old.install_id();
    assert_eq!(
        Signer::restore_over_unusable(
            world.env(store.clone()),
            world.keyring(),
            discard_confirmed()
        )
        .await
        .unwrap_err(),
        SignerError::Store(StoreError::InUse)
    );
    drop(old);
    let original = snapshot(&world, &store);
    let sent = world.transport.requests().len();
    assert_eq!(
        Signer::restore_over_unusable(
            world.env(store.clone()),
            world.keyring(),
            discard_confirmed()
        )
        .await
        .unwrap_err(),
        SignerError::Refused(Refusal::AlreadySetUp)
    );
    assert_eq!(
        Signer::restore_over_unusable(
            world.env(Arc::new(MemoryStore::new())),
            world.keyring(),
            discard_confirmed()
        )
        .await
        .unwrap_err(),
        SignerError::Refused(Refusal::NotSetUp)
    );
    let damaged = unreadable_state(&original);
    replace(&world, &store, &damaged);
    let wrapper = Arc::new(ReadFailure {
        store: store.clone(),
        fail: Mutex::new(None),
    });
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
                Signer::restore_over_unusable(
                    world.env(wrapper.clone()),
                    world.keyring(),
                    discard_confirmed()
                )
                .await
                .unwrap_err(),
                SignerError::Store(error)
            );
            assert_eq!(snapshot(&world, &store), damaged);
        }
    }
    *wrapper.fail.lock().unwrap() = None;
    assert_eq!(world.transport.requests().len(), sent);
    // An earlier unusable read is no authority after the actual records are repaired.
    replace(&world, &store, &original);
    assert_eq!(
        Signer::restore_over_unusable(
            world.env(wrapper.clone()),
            world.keyring(),
            discard_confirmed()
        )
        .await
        .unwrap_err(),
        SignerError::Refused(Refusal::AlreadySetUp)
    );
    replace(&world, &store, &damaged);
    let signer =
        Signer::restore_over_unusable(world.env(wrapper), world.keyring(), discard_confirmed())
            .await
            .unwrap();
    assert_ne!(signer.install_id(), old_install);
    assert_eq!(
        signer.identity_doc().unwrap().unwrap().body().signer,
        signer.install_id()
    );
    assert_eq!(signer.high_water().unwrap().unwrap().version, 2);
    assert_eq!(
        Signer::open(world.env(store.clone()), world.keyring())
            .await
            .unwrap_err(),
        SignerError::Store(StoreError::InUse)
    );
    drop(signer);
    assert_eq!(
        Signer::restore_over_unusable(
            world.env(store.clone()),
            world.keyring(),
            discard_confirmed()
        )
        .await
        .unwrap_err(),
        SignerError::Refused(Refusal::AlreadySetUp)
    );
    let signer = Signer::open(world.env(store), world.keyring())
        .await
        .unwrap();
    assert_eq!(signer.high_water().unwrap().unwrap().version, 2);
}

#[tokio::test]
async fn test_records_confirmed_restore_checks_backup_before_replacement() {
    use pubky_switch_core::records::SIGNER_BACKUP_PATH;
    let world = World::new();
    let (mut old, store) = world.enrolled().await;
    let backup = world.homeserver.file(SIGNER_BACKUP_PATH).unwrap();
    let original_doc = world.switch.identity_doc().unwrap();
    old.set_record_max_age(Some(60)).await.unwrap();
    let current_doc = world.switch.identity_doc().unwrap();
    let current_backup = world.homeserver.file(SIGNER_BACKUP_PATH).unwrap();
    drop(old);
    let damaged = unreadable_state(&snapshot(&world, &store));
    replace(&world, &store, &damaged);
    world.homeserver.set(SIGNER_BACKUP_PATH, backup.clone());
    assert_eq!(
        Signer::restore_over_unusable(
            world.env(store.clone()),
            world.keyring(),
            discard_confirmed()
        )
        .await
        .unwrap_err(),
        SignerError::Refused(Refusal::StaleBackup)
    );
    assert_eq!(snapshot(&world, &store), damaged);
    world
        .homeserver
        .files
        .lock()
        .unwrap()
        .remove(SIGNER_BACKUP_PATH);
    assert_eq!(
        Signer::restore_over_unusable(
            world.env(store.clone()),
            world.keyring(),
            discard_confirmed()
        )
        .await
        .unwrap_err(),
        SignerError::Refused(Refusal::NoBackup)
    );
    assert_eq!(snapshot(&world, &store), damaged);
    world
        .homeserver
        .set(SIGNER_BACKUP_PATH, b"unreadable".to_vec());
    assert_eq!(
        Signer::restore_over_unusable(
            world.env(store.clone()),
            world.keyring(),
            discard_confirmed()
        )
        .await
        .unwrap_err(),
        SignerError::Refused(Refusal::UnreadableBackup)
    );
    assert_eq!(snapshot(&world, &store), damaged);
    *world.homeserver.failing_read_path.lock().unwrap() = Some(SIGNER_BACKUP_PATH.into());
    assert!(matches!(
        Signer::restore_over_unusable(
            world.env(store.clone()),
            world.keyring(),
            discard_confirmed()
        )
        .await,
        Err(SignerError::Homeserver(_))
    ));
    assert_eq!(snapshot(&world, &store), damaged);
    *world.homeserver.failing_read_path.lock().unwrap() = None;
    world.homeserver.set(SIGNER_BACKUP_PATH, backup);
    world.switch.deliver_identity(&original_doc).unwrap();
    // A newer verified Homeserver copy also refuses while the service is at the backup.
    assert_eq!(
        Signer::restore_over_unusable(
            world.env(store.clone()),
            world.keyring(),
            discard_confirmed()
        )
        .await
        .unwrap_err(),
        SignerError::Refused(Refusal::StaleBackup)
    );
    assert_eq!(snapshot(&world, &store), damaged);
    world.switch.deliver_identity(&current_doc).unwrap();
    world.homeserver.set(SIGNER_BACKUP_PATH, current_backup);
    let signer = Signer::restore_over_unusable(
        world.env(store.clone()),
        world.keyring(),
        discard_confirmed(),
    )
    .await
    .unwrap();
    assert_eq!(signer.high_water().unwrap().unwrap().version, 3);
    assert_eq!(
        world.switch.identity_doc().unwrap().body().signer,
        signer.install_id()
    );
}

#[tokio::test]
async fn test_records_confirmed_restore_reopens_the_atomic_replacement() {
    use pubky_switch_client::store::{Fault as StoreFault, FaultStore};
    for (fault, committed) in [
        (Some(StoreFault::FailBefore(1)), false),
        (Some(StoreFault::FailAfter(1)), true),
        (Some(StoreFault::StopAfter(1)), true),
        (None, false),
    ] {
        let world = World::new();
        let (old, store) = world.enrolled().await;
        drop(old);
        let damaged = unreadable_state(&snapshot(&world, &store));
        replace(&world, &store, &damaged);
        let faulty: Arc<dyn StateStore> = if let Some(fault) = fault {
            Arc::new(FaultStore::new(store.clone(), fault))
        } else {
            let (_, released) = std::sync::mpsc::channel();
            Arc::new(HeldReplacement {
                inner: store.clone(),
                waiting: std::sync::atomic::AtomicBool::new(true),
                unknown_before: true,
                entered: tokio::sync::Notify::new(),
                release: Mutex::new(released),
            })
        };
        let expected = if matches!(fault, Some(StoreFault::FailAfter(_)) | None) {
            StoreError::Unknown
        } else {
            StoreError::Unavailable
        };
        assert_eq!(
            Signer::restore_over_unusable(world.env(faulty), world.keyring(), discard_confirmed())
                .await
                .unwrap_err(),
            SignerError::Store(expected)
        );
        let mut signer = if committed {
            assert_eq!(
                Signer::restore_over_unusable(
                    world.env(store.clone()),
                    world.keyring(),
                    discard_confirmed()
                )
                .await
                .unwrap_err(),
                SignerError::Refused(Refusal::AlreadySetUp)
            );
            Signer::open(world.env(store.clone()), world.keyring())
                .await
                .unwrap()
        } else {
            assert_eq!(snapshot(&world, &store), damaged);
            Signer::restore_over_unusable(
                world.env(store.clone()),
                world.keyring(),
                discard_confirmed(),
            )
            .await
            .unwrap()
        };
        signer.resume().await.unwrap();
        let doc = signer.identity_doc().unwrap().unwrap();
        assert_eq!(doc.version(), 2);
        assert_eq!(doc.body().signer, signer.install_id());
        assert_eq!(world.backup().identity_doc().signed(), doc.signed());
        world.assert_no_version_sent_twice();
    }
}

fn damaged_certificate(records: &[KeyValue]) -> Vec<KeyValue> {
    change(records, b"state", |state| {
        break_signature(&mut state["certs"][0])
    })
}

async fn assert_confirmed_refusal(
    world: &World,
    store: &Arc<MemoryStore>,
    damaged: &[KeyValue],
    expected: SignerError,
) {
    replace(world, store, damaged);
    let requests = world.transport.requests().len();
    let writes = world.homeserver.writes.lock().unwrap().len();
    let deletes = world.homeserver.deletes.lock().unwrap().len();
    assert_eq!(
        Signer::restore_over_unusable(
            world.env(store.clone()),
            world.keyring(),
            discard_confirmed()
        )
        .await
        .unwrap_err(),
        expected
    );
    assert_eq!(snapshot(world, store), damaged);
    assert!(
        world.transport.requests()[requests..]
            .iter()
            .all(|request| request.method == "GET")
    );
    assert_eq!(world.homeserver.writes.lock().unwrap().len(), writes);
    assert_eq!(world.homeserver.deletes.lock().unwrap().len(), deletes);
    assert_eq!(world.keyring().public_key(), world.key.public());
}

#[tokio::test]
async fn test_records_confirmed_restore_preserves_an_intact_flow() {
    let world = World::new();
    let (mut signer, store) = world.enrolled().await;
    let app = App::new(&["notes"], None, [9; 32]);
    world.approve(&mut signer, &app).await;
    world.switch.fail_next(Fault::Unreachable {
        path: "/identity".into(),
        after: 0,
    });
    signer.set_record_max_age(Some(60)).await.unwrap_err();
    drop(signer);
    let original = snapshot(&world, &store);
    for damaged in [damaged_certificate(&original), unreadable_state(&original)] {
        assert_confirmed_refusal(
            &world,
            &store,
            &damaged,
            SignerError::Refused(Refusal::FlowInProgress),
        )
        .await;
    }
    replace(&world, &store, &original);
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
async fn test_records_confirmed_restore_preserves_erasure_and_alarms() {
    for erased in [false, true] {
        let world = World::new();
        let (mut signer, store) = world.enrolled().await;
        let app = App::new(&["notes"], None, [9; 32]);
        world.approve(&mut signer, &app).await;
        let expected = if erased {
            signer
                .close_account(UserConfirmed::shown_and_confirmed())
                .await
                .unwrap();
            SignerError::Refused(Refusal::Erased)
        } else {
            let earlier = signer.identity_doc().unwrap().unwrap();
            signer.set_record_max_age(Some(60)).await.unwrap();
            world.switch.deliver_identity(&earlier).unwrap();
            let error = signer.set_record_max_age(Some(61)).await.unwrap_err();
            assert!(matches!(error, SignerError::Alarm(_)));
            error
        };
        drop(signer);
        let original = snapshot(&world, &store);
        assert_confirmed_refusal(&world, &store, &damaged_certificate(&original), expected).await;
        replace(&world, &store, &original);
        let signer = Signer::open(world.env(store), world.keyring())
            .await
            .unwrap();
        assert_eq!(
            signer.status(),
            if erased {
                pubky_switch_signer::SignerStatus::Erased
            } else {
                pubky_switch_signer::SignerStatus::Alarm
            }
        );
    }
}

#[tokio::test]
async fn test_records_confirmed_restore_preserves_handover_authority() {
    let world = World::new();
    let (mut old, old_store) = world.enrolled().await;
    let app = App::new(&["notes"], None, [9; 32]);
    let reviewed = old.review(&app.request, &app.auth).unwrap();
    let approved = old.approve(reviewed).await.unwrap();
    old.claim_delivered(&approved.request).await.unwrap();
    let cert = world.join(&app, &approved);
    old.hand_over_to(cert.app_id(), UserConfirmed::shown_and_confirmed())
        .await
        .unwrap();
    drop(old);
    let original = snapshot(&world, &old_store);
    assert_confirmed_refusal(
        &world,
        &old_store,
        &damaged_certificate(&original),
        SignerError::Refused(Refusal::HandingOver {
            to_app: cert.app_id(),
        }),
    )
    .await;
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
    Signer::receive_hand_over(world.env(store.clone()), &target, vault.clone())
        .await
        .unwrap_err();
    let pending = snapshot(&world, &store);
    let damaged = change(&pending, b"flow", |flow| {
        break_signature(flow.pointer_mut("/TakingOver/delivery/doc").unwrap())
    });
    assert_confirmed_refusal(
        &world,
        &store,
        &damaged,
        SignerError::Refused(Refusal::TakingOver),
    )
    .await;
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

fn remote_copies(world: &World) -> (pubky_switch_core::records::IdentityDoc, Vec<u8>, Vec<u8>) {
    use pubky_switch_core::records::{IDENTITY_PATH, SIGNER_BACKUP_PATH};
    (
        world.switch.identity_doc().unwrap(),
        world.homeserver.file(SIGNER_BACKUP_PATH).unwrap(),
        world.homeserver.file(IDENTITY_PATH).unwrap(),
    )
}

fn restore_remote_copies(
    world: &World,
    copies: &(pubky_switch_core::records::IdentityDoc, Vec<u8>, Vec<u8>),
) {
    use pubky_switch_core::records::{IDENTITY_PATH, SIGNER_BACKUP_PATH};
    world.switch.deliver_identity(&copies.0).unwrap();
    world.homeserver.set(SIGNER_BACKUP_PATH, copies.1.clone());
    world.homeserver.set(IDENTITY_PATH, copies.2.clone());
}

#[tokio::test]
async fn test_records_confirmed_restore_keeps_known_marks() {
    for behind in [false, true] {
        let world = World::new();
        let (mut signer, store) = world.enrolled().await;
        let app = App::new(&["notes"], None, [9; 32]);
        world.approve(&mut signer, &app).await;
        let earlier = remote_copies(&world);
        let earlier_records = snapshot(&world, &store);
        signer.set_record_max_age(Some(60)).await.unwrap();
        let current = remote_copies(&world);
        drop(signer);
        if behind {
            replace(&world, &store, &earlier_records);
            let mut lagging = Signer::open(world.env(store.clone()), world.keyring())
                .await
                .unwrap();
            assert_eq!(
                lagging.set_record_max_age(Some(61)).await.unwrap_err(),
                SignerError::Refused(Refusal::RecordsBehind {
                    version: current.0.version()
                })
            );
        }
        let original = snapshot(&world, &store);
        restore_remote_copies(&world, &earlier);
        assert_confirmed_refusal(
            &world,
            &store,
            &damaged_certificate(&original),
            SignerError::Refused(Refusal::StaleBackup),
        )
        .await;
        restore_remote_copies(&world, &current);
        let restored =
            Signer::restore_over_unusable(world.env(store), world.keyring(), discard_confirmed())
                .await
                .unwrap();
        assert_eq!(
            restored.identity_doc().unwrap().unwrap().version(),
            current.0.version() + 1
        );
    }
}

#[tokio::test]
async fn test_records_confirmed_restore_keeps_spent_floors() {
    let world = World::new();
    let (mut signer, store) = world.enrolled().await;
    let a = App::with_keys(
        AppKeys::from_secrets([3; 32], [4; 32]),
        &["notes", "notes_sync"],
        None,
        [9; 32],
    );
    let b = App::with_keys(
        AppKeys::from_secrets([5; 32], [6; 32]),
        &["notes", "notes_sync"],
        None,
        [10; 32],
    );
    world.approve(&mut signer, &a).await;
    world.approve(&mut signer, &b).await;
    let before = signer.identity_doc().unwrap().unwrap();
    world.switch.fail_next(Fault::Error {
        path: "/ops".into(),
        code: pubky_switch_core::http::ErrorCode::Conflict,
        current: Value::Null,
    });
    signer
        .renew(
            a.keys.app_id_bytes(),
            CertChange {
                scopes: Some(vec!["notes_sync".into()]),
                expires_at: None,
            },
        )
        .await
        .unwrap_err();
    drop(signer);
    let original = snapshot(&world, &store);
    replace(&world, &store, &damaged_certificate(&original));
    let mut restored =
        Signer::restore_over_unusable(world.env(store), world.keyring(), discard_confirmed())
            .await
            .unwrap();
    assert_eq!(
        restored.identity_doc().unwrap().unwrap().version(),
        before.version() + 2
    );
    let next = restored
        .renew(
            b.keys.app_id_bytes(),
            CertChange {
                scopes: Some(vec!["notes_sync".into()]),
                expires_at: None,
            },
        )
        .await
        .unwrap();
    assert_eq!(next.data_epoch(), 3);
    world.assert_no_version_sent_twice();
}

#[tokio::test]
async fn test_records_confirmed_restore_keeps_revocations_and_cleanup() {
    use pubky_switch_core::records::app_record_path;
    use pubky_switch_signer::Alert;
    for pending in [true, false] {
        let world = World::new();
        let (mut signer, store) = world.enrolled().await;
        let a = App::with_keys(
            AppKeys::from_secrets([3; 32], [4; 32]),
            &["notes"],
            None,
            [9; 32],
        );
        let b = App::with_keys(
            AppKeys::from_secrets([5; 32], [6; 32]),
            &["notes"],
            None,
            [10; 32],
        );
        world.approve(&mut signer, &a).await;
        world.approve(&mut signer, &b).await;
        let id = a.keys.app_id_bytes();
        world
            .homeserver
            .set(&app_record_path(&id), b"kept app record".to_vec());
        *world.homeserver.failing_path.lock().unwrap() = Some(app_record_path(&id));
        if pending {
            world.switch.fail_next(Fault::Unreachable {
                path: "/revoke".into(),
                after: 0,
            });
        }
        let distrust = START_MS - 1000;
        let result = signer
            .revoke(id, Some(distrust), UserConfirmed::shown_and_confirmed())
            .await;
        assert_eq!(result.is_err(), pending);
        drop(signer);
        let original = snapshot(&world, &store);
        replace(&world, &store, &damaged_certificate(&original));
        let mut restored =
            Signer::restore_over_unusable(world.env(store), world.keyring(), discard_confirmed())
                .await
                .unwrap();
        assert!(matches!(
            restored.review(&a.request, &a.auth),
            Err(SignerError::Refused(Refusal::AppRequest(_)))
        ));
        assert!(world.homeserver.file(&app_record_path(&id)).is_some());
        *world.homeserver.failing_path.lock().unwrap() = None;
        restored.run_due().await.unwrap();
        assert!(world.switch.app(&id).departed);
        assert!(world.homeserver.file(&app_record_path(&id)).is_none());
        assert!(
            restored
                .alerts()
                .contains(&Alert::GrantRevocationOwed { app_id: id })
        );
        assert_eq!(
            restored
                .identity_doc()
                .unwrap()
                .unwrap()
                .body()
                .removed
                .iter()
                .find(|removed| removed.app_id == id)
                .unwrap()
                .distrust_from,
            distrust
        );
    }
}

struct HeldReplacement {
    inner: Arc<MemoryStore>,
    waiting: std::sync::atomic::AtomicBool,
    unknown_before: bool,
    entered: tokio::sync::Notify,
    release: Mutex<std::sync::mpsc::Receiver<()>>,
}

impl StateStore for HeldReplacement {
    fn get(&self, ns: &str, key: &[u8]) -> Result<Option<Vec<u8>>, StoreError> {
        self.inner.get(ns, key)
    }
    fn scan(
        &self,
        ns: &str,
        prefix: &[u8],
        after: Option<&[u8]>,
        limit: u32,
    ) -> Result<Vec<KeyValue>, StoreError> {
        self.inner.scan(ns, prefix, after, limit)
    }
    fn acquire(&self, ns: &str, owner: StoreOwner) -> Result<AcquireOutcome, StoreError> {
        self.inner.acquire(ns, owner)
    }
    fn commit(&self, batch: WriteBatch) -> Result<(), StoreError> {
        self.inner.commit(batch)
    }
    fn commit_if(
        &self,
        ns: &str,
        owner: StoreOwner,
        batch: WriteBatch,
    ) -> Result<CommitOutcome, StoreError> {
        if self
            .waiting
            .swap(false, std::sync::atomic::Ordering::SeqCst)
        {
            if self.unknown_before {
                return Err(StoreError::Unknown);
            }
            self.entered.notify_one();
            self.release
                .lock()
                .unwrap()
                .recv_timeout(std::time::Duration::from_secs(20))
                .unwrap();
        }
        self.inner.commit_if(ns, owner, batch)
    }
}

#[tokio::test]
async fn test_records_confirmed_restore_cancellation_keeps_the_replacement_owned() {
    use pubky_switch_client::store::StoreHandle;
    let world = World::new();
    let (old, store) = world.enrolled().await;
    drop(old);
    let damaged = unreadable_state(&snapshot(&world, &store));
    replace(&world, &store, &damaged);
    let (release, released) = std::sync::mpsc::channel();
    let host = Arc::new(HeldReplacement {
        inner: store.clone(),
        waiting: std::sync::atomic::AtomicBool::new(true),
        unknown_before: false,
        entered: tokio::sync::Notify::new(),
        release: Mutex::new(released),
    });
    let mut env = world.env(host.clone());
    env.store = StoreHandle::blocking(host.clone());
    let requests = world.transport.requests().len();
    let remote = remote_copies(&world);
    let mut restoring = Box::pin(Signer::restore_over_unusable(
        env,
        world.keyring(),
        discard_confirmed(),
    ));
    tokio::select! { () = host.entered.notified() => {}, result = &mut restoring => panic!("replacement did not wait: {result:?}") }
    drop(restoring);
    assert_eq!(snapshot(&world, &store), damaged);
    assert!(
        world.transport.requests()[requests..]
            .iter()
            .all(|request| request.method == "GET")
    );
    assert_eq!(remote_copies(&world).0.signed(), remote.0.signed());
    assert_eq!(remote_copies(&world).1, remote.1);
    assert_eq!(remote_copies(&world).2, remote.2);
    assert_eq!(
        Signer::open(world.env(store.clone()), world.keyring())
            .await
            .unwrap_err(),
        SignerError::Store(StoreError::InUse)
    );
    release.send(()).unwrap();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
    let mut signer = loop {
        match Signer::open(world.env(store.clone()), world.keyring()).await {
            Ok(signer) => break signer,
            Err(SignerError::Store(StoreError::InUse)) => {
                assert!(std::time::Instant::now() < deadline);
                tokio::task::yield_now().await;
            }
            other => panic!("unexpected stored replacement: {other:?}"),
        }
    };
    signer.resume().await.unwrap();
    assert_eq!(signer.identity_doc().unwrap().unwrap().version(), 2);
    assert_eq!(
        world.backup().identity_doc().body().signer,
        signer.install_id()
    );
    world.assert_no_version_sent_twice();
}

#[tokio::test]
async fn test_records_confirmed_restore_reconciles_a_lost_delivery_answer() {
    let world = World::new();
    let (old, store) = world.enrolled().await;
    drop(old);
    let damaged = unreadable_state(&snapshot(&world, &store));
    replace(&world, &store, &damaged);
    world.switch.fail_next(Fault::LoseAnswer {
        path: "/identity".into(),
    });
    Signer::restore_over_unusable(
        world.env(store.clone()),
        world.keyring(),
        discard_confirmed(),
    )
    .await
    .unwrap_err();
    let accepted = world.switch.identity_doc().unwrap();
    assert_eq!(accepted.version(), 2);
    assert_eq!(
        Signer::restore_over_unusable(
            world.env(store.clone()),
            world.keyring(),
            discard_confirmed()
        )
        .await
        .unwrap_err(),
        SignerError::Refused(Refusal::AlreadySetUp)
    );
    let mut signer = Signer::open(world.env(store), world.keyring())
        .await
        .unwrap();
    signer.run_due().await.unwrap();
    assert_eq!(
        signer.identity_doc().unwrap().unwrap().signed(),
        accepted.signed()
    );
    assert_eq!(world.backup().identity_doc().signed(), accepted.signed());
    world.assert_no_version_sent_twice();
}
