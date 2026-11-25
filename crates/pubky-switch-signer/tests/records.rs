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
use pubky_switch_core::records::AppRequestStep;
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
async fn test_records_damaged_first_origin_preserves_identity_alarm_and_unsigned_setup() {
    use pubky_switch_signer::{Alert, Source};

    let world = World::new();
    let store = Arc::new(MemoryStore::new());
    let mut first = Signer::create(world.env(store.clone()), world.keyring(), SWITCH_ORIGIN)
        .await
        .unwrap();
    let unsigned = snapshot(&world, &store);
    world.switch.fail_next(Fault::Unreachable {
        path: "/v1/enroll".into(),
        after: 0,
    });
    assert!(matches!(first.resume().await, Err(SignerError::Switch(_))));
    drop(first);
    let signed = snapshot(&world, &store);
    let (_serving, _) = world.enrolled().await;
    let damage_origin =
        |flow: &mut Value| flow["Enroll"]["origin"] = "https://different.example".into();
    let damaged = change(&signed, b"flow", damage_origin);
    let alarm = Alert::Rollback {
        source: Source::Switch,
        version: None,
        generation: None,
        high_water_version: 1,
    };
    for (records, expected) in [
        (
            change(&unsigned, b"flow", |flow| {
                flow["Enroll"]["origin"] = "unreadable".into()
            }),
            Refusal::FirstEnrollmentUnavailable.into(),
        ),
        (
            change(&damaged, b"flow", |flow| {
                flow["Enroll"]["nonce"] = serde_json::to_value([0u8; 16]).unwrap()
            }),
            RecordsFault::Damaged("another initial enrollment").into(),
        ),
        (
            change(&damaged, b"state", |state| {
                state["identity"] = serde_json::to_value([9u8; 32]).unwrap()
            }),
            RecordsFault::OtherIdentity.into(),
        ),
    ] {
        assert_confirmed_refusal(&world, &store, &records, expected).await;
    }
    let equivocation = Alert::Equivocation {
        source: Source::Switch,
        version: 1,
    };
    let keep_alarm = |state: &mut Value| {
        state["alerts"] = serde_json::to_value([&alarm, &equivocation]).unwrap();
        state["switch_unconfirmed"] = true.into();
    };
    replace(&world, &store, &change(&damaged, b"state", keep_alarm));
    let requests = world.transport.requests().len();
    let repaired = Box::pin(Signer::restore_over_unusable(
        world.env(store.clone()),
        world.keyring(),
        discard_confirmed(),
    ))
    .await
    .unwrap();
    assert!(repaired.alerts().contains(&alarm));
    drop(repaired);
    let expected = change(&signed, b"state", keep_alarm);
    for (key, bytes) in expected {
        let restored = store.get(&namespace(&world), &key).unwrap().unwrap();
        assert_eq!(
            serde_json::from_slice::<Value>(&restored).unwrap(),
            serde_json::from_slice::<Value>(&bytes).unwrap()
        );
    }
    let mut signer = Signer::open(world.env(store.clone()), world.keyring())
        .await
        .unwrap();
    let before = snapshot(&world, &store);
    for retained in [&equivocation, &alarm] {
        assert_eq!(
            Box::pin(signer.clear_alert(retained)).await,
            Err(SignerError::Alarm(retained.clone()))
        );
    }
    assert!(before == snapshot(&world, &store));
    assert_eq!(
        Box::pin(signer.survey_first_enrollment_restore(SWITCH_ORIGIN))
            .await
            .unwrap_err(),
        SignerError::Alarm(alarm)
    );
    assert!(
        world.transport.requests()[requests..]
            .iter()
            .all(|r| r.method == "GET" && r.origin == SWITCH_ORIGIN)
    );
}

#[tokio::test]
async fn test_records_enrollment_and_delivery_copies_fail_before_retry() {
    let world = World::new();
    let store = Arc::new(MemoryStore::new());
    let mut signer = Signer::create(world.env(store.clone()), world.keyring(), SWITCH_ORIGIN)
        .await
        .unwrap();
    world.switch.fail_next(Fault::Unreachable {
        path: "/v1/enroll".into(),
        after: 0,
    });
    assert!(matches!(signer.resume().await, Err(SignerError::Switch(_))));
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

async fn interrupted_renewal(world: &World) -> (Arc<MemoryStore>, Vec<KeyValue>) {
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
    let original = snapshot(world, &store);
    (store, original)
}

fn damaged_renewal_batch(records: &[KeyValue]) -> Vec<KeyValue> {
    change(records, b"flow", |flow| {
        let bytes = &mut flow["Renew"]["batches"][0]["bytes"];
        let mut batch: Value =
            serde_json::from_slice(&unb64(bytes.as_str().unwrap()).unwrap()).unwrap();
        break_signature(&mut batch["ops"][0]);
        *bytes = Value::String(b64(&serde_json::to_vec(&batch).unwrap()));
    })
}

#[tokio::test]
async fn test_records_renewal_operation_authentication_precedes_retry() {
    let world = World::new();
    let (store, original) = interrupted_renewal(&world).await;
    let damaged = damaged_renewal_batch(&original);
    assert_stored_failure(&world, &store, &damaged).await;
    replace(&world, &store, &original);
    let mut signer = Signer::open(world.env(store), world.keyring())
        .await
        .unwrap();
    signer.resume().await.unwrap();
    world.assert_no_version_sent_twice();
}

#[tokio::test]
async fn test_records_renewal_binding_repair_requires_the_original_account_and_authority() {
    use pubky_switch_core::records::SIGNER_BACKUP_PATH;

    let world = World::new();
    let (store, original) = interrupted_renewal(&world).await;
    let missing = change(&original, b"state", |s| {
        s["newest"]["account"] = Value::Null
    });
    let different = change(&missing, b"flow", |f| {
        let created = &mut f["Renew"]["account"]["created"];
        *created = Value::from(created.as_u64().unwrap() + 1);
    });
    assert_confirmed_refusal(&world, &store, &different, Refusal::FlowInProgress.into()).await;
    let held = change(&missing, b"state", |s| {
        s["switch_unconfirmed"] = Value::Bool(true)
    });
    assert_confirmed_refusal(&world, &store, &held, Refusal::FlowInProgress.into()).await;
    let backup = world
        .homeserver
        .files
        .lock()
        .unwrap()
        .remove(SIGNER_BACKUP_PATH)
        .unwrap();
    assert_confirmed_refusal(&world, &store, &missing, Refusal::FlowInProgress.into()).await;
    world.homeserver.set(SIGNER_BACKUP_PATH, backup);
    replace(&world, &store, &missing);
    let signer = Box::pin(Signer::restore_over_unusable(
        world.env(store),
        world.keyring(),
        discard_confirmed(),
    ))
    .await
    .unwrap();
    assert_eq!(signer.status(), pubky_switch_signer::SignerStatus::Signing);
    world.assert_no_version_sent_twice();
}

#[tokio::test]
async fn test_records_erasure_requires_the_accepted_documents_account() {
    for missing in [true, false] {
        let world = World::new();
        let (signer, store) = world.enrolled().await;
        let original_version = signer.high_water().unwrap().unwrap().version;
        drop(signer);
        let original = snapshot(&world, &store);
        let damaged = change(&original, b"state", |state| {
            assert!(state["service"].is_object());
            let account = &mut state["newest"]["account"];
            assert!(account.is_object());
            if missing {
                *account = Value::Null;
            } else {
                account["created"] = Value::from(u64::MAX);
            }
        });
        replace(&world, &store, &damaged);
        let sent = world.transport.requests().len();
        let error = Signer::open(world.env(store.clone()), world.keyring())
            .await
            .unwrap_err();
        let invariant = if missing {
            "an owned version has no original account"
        } else {
            "invalid original account target"
        };
        assert_eq!(
            error,
            SignerError::Records(RecordsFault::Damaged(invariant))
        );
        assert_eq!(snapshot(&world, &store), damaged);
        assert_eq!(world.transport.requests().len(), sent);
        assert!(world.homeserver.deletes.lock().unwrap().is_empty());
        let restored = Signer::restore_over_unusable(
            world.env(store.clone()),
            world.keyring(),
            discard_confirmed(),
        )
        .await
        .unwrap();
        let doc = restored.identity_doc().unwrap().unwrap();
        assert_eq!(doc.version(), original_version + 1);
        assert_eq!(world.backup().identity_doc().hash(), doc.hash());
        drop(restored);
        let mut signer = Signer::open(world.env(store), world.keyring())
            .await
            .unwrap();
        let next = signer.set_record_max_age(Some(60)).await.unwrap();
        assert_eq!(next.version(), doc.version() + 1);
        world.assert_no_version_sent_twice();
    }
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
        (b"flow", "/Recover/enrollment/Ready/enrollment"),
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
    use pubky_switch_core::records::{IDENTITY_PATH, SIGNER_BACKUP_PATH};
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
    world.homeserver.set(
        IDENTITY_PATH,
        serde_json::to_vec(original_doc.signed()).unwrap(),
    );
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
    world.homeserver.set(
        IDENTITY_PATH,
        serde_json::to_vec(current_doc.signed()).unwrap(),
    );
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
    use pubky_switch_core::records::SIGNER_BACKUP_PATH;

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
    let saved_backup = world
        .homeserver
        .files
        .lock()
        .unwrap()
        .remove(SIGNER_BACKUP_PATH)
        .unwrap();
    for damaged in [
        damaged_certificate(&original),
        unreadable_state(&original),
        change(&original, b"state", |state| {
            state["newest"]["account"] = Value::Null
        }),
    ] {
        assert_confirmed_refusal(
            &world,
            &store,
            &damaged,
            SignerError::Refused(Refusal::FlowInProgress),
        )
        .await;
    }
    world.homeserver.set(SIGNER_BACKUP_PATH, saved_backup);
    replace(&world, &store, &unreadable_state(&original));
    let signer =
        Signer::restore_over_unusable(world.env(store), world.keyring(), discard_confirmed())
            .await
            .unwrap();
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
async fn test_records_repair_an_alarmed_signers_original_account() {
    use pubky_switch_core::records::SIGNER_BACKUP_PATH;
    use pubky_switch_signer::{Alert, SignerStatus, Source};

    let world = World::new();
    let (mut signer, store) = world.enrolled().await;
    let app = App::new(&["notes"], None, [9; 32]);
    let request = signer.review(&app.request, &app.auth).unwrap();
    let approval = signer.approve(request).await.unwrap();
    let earlier = remote_copies(&world);
    signer.set_record_max_age(Some(60)).await.unwrap();
    let current = remote_copies(&world);
    let install = signer.install_id();
    world.switch.deliver_identity(&earlier.0).unwrap();
    let SignerError::Alarm(
        alarm @ Alert::Rollback {
            source: Source::Switch,
            ..
        },
    ) = signer.set_record_max_age(Some(61)).await.unwrap_err()
    else {
        panic!("expected the signer's switch rollback alarm");
    };
    drop(signer);

    let original = snapshot(&world, &store);
    let damaged = change(&original, b"state", |state| {
        assert!(state["newest"]["account"].is_object());
        state["newest"]["account"] = Value::Null;
    });
    assert_confirmed_refusal(&world, &store, &damaged, SignerError::Alarm(alarm.clone())).await;
    world.switch.deliver_identity(&current.0).unwrap();
    world.homeserver.set(SIGNER_BACKUP_PATH, earlier.1);
    assert_confirmed_refusal(&world, &store, &damaged, SignerError::Alarm(alarm.clone())).await;
    world
        .homeserver
        .files
        .lock()
        .unwrap()
        .remove(SIGNER_BACKUP_PATH);
    assert_confirmed_refusal(
        &world,
        &store,
        &damaged,
        SignerError::Refused(Refusal::NoBackup),
    )
    .await;
    world.homeserver.set(SIGNER_BACKUP_PATH, current.1);
    let other_creation = change(&damaged, b"state", |state| {
        let created = state["service"]["created"].as_u64().unwrap();
        state["service"]["created"] = Value::from(created + 1);
    });
    assert_confirmed_refusal(
        &world,
        &store,
        &other_creation,
        SignerError::Alarm(alarm.clone()),
    )
    .await;
    replace(&world, &store, &damaged);
    let sent = world.transport.requests().len();
    let signer = Signer::restore_over_unusable(
        world.env(store.clone()),
        world.keyring(),
        discard_confirmed(),
    )
    .await
    .unwrap();
    assert_eq!(snapshot(&world, &store), original);
    assert!(
        world.transport.requests()[sent..]
            .iter()
            .all(|request| request.method == "GET")
    );
    drop(signer);
    let mut signer = Signer::open(world.env(store), world.keyring())
        .await
        .unwrap();
    assert_eq!(signer.install_id(), install);
    assert_eq!(signer.status(), SignerStatus::Alarm);
    assert_eq!(
        signer.set_record_max_age(Some(61)).await.unwrap_err(),
        SignerError::Alarm(alarm.clone())
    );
    signer.clear_alert(&alarm).await.unwrap();
    assert!(signer.approved(&approval.request).unwrap() == Some(approval));
    let next = signer.set_record_max_age(Some(61)).await.unwrap();
    assert_eq!(next.version(), current.0.version() + 1);
    assert_eq!(world.switch.identity_doc().unwrap().signed(), next.signed());
    assert_eq!(world.backup().identity_doc().signed(), next.signed());
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

async fn approve_two_keyed_apps(world: &World, signer: &mut Signer) -> (App, App) {
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
    world.approve(signer, &a).await;
    world.approve(signer, &b).await;
    (a, b)
}

fn reduce_to_sync() -> CertChange {
    CertChange {
        scopes: Some(vec!["notes_sync".into()]),
        expires_at: None,
    }
}

#[tokio::test]
async fn test_records_damaged_renewal_binding_and_batch_keep_signed_floors() {
    let world = World::new();
    let (mut signer, store) = world.enrolled().await;
    let (a, b) = approve_two_keyed_apps(&world, &mut signer).await;
    let before = signer.identity_doc().unwrap().unwrap();
    let old_install = signer.install_id();
    world.switch.fail_next(Fault::Unreachable {
        path: "/ops".into(),
        after: 0,
    });
    signer
        .renew(a.keys.app_id_bytes(), reduce_to_sync())
        .await
        .unwrap_err();
    drop(signer);
    let records = damaged_renewal_batch(&snapshot(&world, &store));
    let records = change(&records, b"state", |s| {
        s["newest"]["account"] = Value::Null;
        // Only the still-verifiable successor now records the spent version and epoch.
        s["signed_through"] = before.version().into();
        s["epoch_through"] = before.data_epoch().into();
    });
    replace(&world, &store, &records);
    let mut restored = Box::pin(Signer::restore_over_unusable(
        world.env(store),
        world.keyring(),
        discard_confirmed(),
    ))
    .await
    .unwrap();
    assert_ne!(restored.install_id(), old_install);
    assert_eq!(
        restored.identity_doc().unwrap().unwrap().version(),
        before.version() + 2
    );
    let next = restored
        .renew(b.keys.app_id_bytes(), reduce_to_sync())
        .await
        .unwrap();
    assert_eq!(next.data_epoch(), before.data_epoch() + 2);
    world.assert_no_version_sent_twice();
}

#[tokio::test]
async fn test_records_restore_interrupted_epoch_after_the_bundles_are_stored() {
    check_interrupted_rotation(RotationCut::StoredEpoch).await;
}

#[tokio::test]
async fn test_records_restore_interrupted_epoch_requires_the_stored_parts() {
    check_interrupted_rotation(RotationCut::MissingParts).await;
}

#[tokio::test]
async fn test_records_restore_a_departure_before_the_remaining_bundle_is_stored() {
    check_pending_removal(PendingRemoval::Departure).await;
}

#[tokio::test]
async fn test_records_restore_a_revocation_after_a_lost_bundle_answer() {
    check_pending_removal(PendingRemoval::Revocation).await;
}

#[tokio::test]
async fn test_records_restore_removal_with_a_listed_app_that_never_joined() {
    check_pending_removal(PendingRemoval::UnjoinedSurvivor).await;
}

#[derive(PartialEq)]
enum PendingRemoval {
    Departure,
    Revocation,
    UnjoinedSurvivor,
}

async fn check_pending_removal(case: PendingRemoval) {
    let revoked = case == PendingRemoval::Revocation;
    const DAY_MS: u64 = 86_400_000;
    let world = World::new();
    let (mut signer, store) = world.enrolled().await;
    let install = signer.install_id();
    let (a, b) = approve_two_keyed_apps(&world, &mut signer).await;
    let a_id = a.keys.app_id_bytes();
    let b_id = b.keys.app_id_bytes();
    let unjoined = if case == PendingRemoval::UnjoinedSurvivor {
        let app = App::with_keys(
            AppKeys::from_secrets([7; 32], [8; 32]),
            &["notes"],
            None,
            [11; 32],
        );
        let review = signer.review(&app.request, &app.auth).unwrap();
        let claim = signer.approve(review).await.unwrap();
        signer.claim_delivered(&claim.request).await.unwrap();
        Some(app.keys.app_id_bytes())
    } else {
        None
    };
    let predecessor = world.switch.identity_doc().unwrap();
    let before = world.transport.requests().len();
    world.clock.advance_ms(DAY_MS);
    let cutoff = if revoked {
        let earlier = START_MS + 1;
        world.switch.fail_next(Fault::LoseAnswer {
            path: "/ops".into(),
        });
        signer
            .revoke(a_id, Some(earlier), UserConfirmed::shown_and_confirmed())
            .await
            .unwrap_err();
        earlier
    } else {
        world.switch.leave(a_id).unwrap();
        world.switch.fail_next(Fault::Unreachable {
            path: "/ops".into(),
            after: 0,
        });
        signer.run_due().await.unwrap_err();
        START_MS + DAY_MS
    };
    drop(signer);
    let flow: Value =
        serde_json::from_slice(&store.get(&namespace(&world), b"flow").unwrap().unwrap()).unwrap();
    let signed = serde_json::from_value(flow["Renew"]["doc"].clone()).unwrap();
    let candidate =
        pubky_switch_core::records::IdentityDoc::verify(&signed, &world.key.public()).unwrap();
    assert_eq!(flow["Renew"]["sent"], 0);
    assert_eq!(candidate.body().removed.len(), 1);
    assert_eq!(candidate.body().removed[0].app_id, a_id);
    assert_eq!(candidate.body().removed[0].distrust_from, cutoff);
    assert_eq!(candidate.listed_cert(&b_id), predecessor.listed_cert(&b_id));
    assert_eq!(candidate.data_epoch(), predecessor.data_epoch() + 1);
    assert_eq!(
        world.switch.identity_doc().unwrap().signed(),
        predecessor.signed()
    );
    assert_eq!(world.backup().identity_doc().signed(), predecessor.signed());
    let damaged = change(&snapshot(&world, &store), b"state", |s| {
        s["newest"]["account"] = Value::Null
    });
    let no_cleanup = change(&damaged, b"state", |s| s["cleanup"] = serde_json::json!([]));
    assert_confirmed_refusal(&world, &store, &no_cleanup, Refusal::FlowInProgress.into()).await;
    if revoked {
        let no_choice = change(&damaged, b"state", |s| {
            s["revoking"][0]["distrust_from"] = Value::Null;
        });
        assert_confirmed_refusal(&world, &store, &no_choice, Refusal::FlowInProgress.into()).await;
    }
    let no_bundle = change(&damaged, b"flow", |flow| {
        flow["Renew"]["batches"] = serde_json::json!([]);
    });
    assert_confirmed_refusal(&world, &store, &no_bundle, Refusal::FlowInProgress.into()).await;
    replace(&world, &store, &damaged);
    let recovered = Box::pin(Signer::restore_over_unusable(
        world.env(store.clone()),
        world.keyring(),
        discard_confirmed(),
    ))
    .await
    .unwrap();
    assert_eq!(recovered.install_id(), install);
    assert_eq!(recovered.identity_doc().unwrap().unwrap().signed(), &signed);
    assert_eq!(world.switch.identity_doc().unwrap().signed(), &signed);
    let backup = world.backup();
    assert_eq!(backup.prev(), Some(predecessor.hash()));
    assert_eq!(backup.identity_doc().signed(), &signed);
    assert!(backup.revoked_apps().contains(&a_id));
    world.assert_request_attempts(before, "POST", "/ops", 2);
    world.assert_request_attempts(before, "PUT", "/identity", 1);
    assert!(
        world
            .switch
            .bundle_parts_of(&a_id)
            .iter()
            .all(|p| p.last_epoch < candidate.data_epoch())
    );
    let part = world
        .switch
        .bundle_parts_of(&b_id)
        .into_iter()
        .find(|p| p.last_epoch == candidate.data_epoch())
        .unwrap();
    let opened = part
        .bundle
        .open(&world.key.public(), &b_id, &b.keys.bundle_secret())
        .unwrap();
    assert_eq!(Some(opened.cert), candidate.listed_cert(&b_id));
    let cert = backup
        .certs()
        .iter()
        .find(|cert| cert.hash() == opened.cert)
        .unwrap();
    pubky_switch_core::records::check_bundle_keys(&opened, cert, &|s| s != "notes_tags").unwrap();
    if let Some(unjoined) = unjoined {
        assert!(candidate.listed_cert(&unjoined).is_some());
        assert_eq!(
            candidate.listed_cert(&unjoined),
            predecessor.listed_cert(&unjoined)
        );
        assert!(world.switch.bundle_parts_of(&unjoined).is_empty());
    }
    drop(recovered);
    let mut reopened = Signer::open(world.env(store), world.keyring())
        .await
        .unwrap();
    assert!(
        reopened
            .identity_doc()
            .unwrap()
            .unwrap()
            .lists_removed(&a_id)
    );
    let next = reopened.renew(b_id, reduce_to_sync()).await.unwrap();
    assert_eq!(next.data_epoch(), candidate.data_epoch() + 1);
    world.assert_no_version_sent_twice();
}

#[derive(PartialEq)]
enum RotationCut {
    StoredEpoch,
    MissingParts,
}

async fn check_interrupted_rotation(cut: RotationCut) {
    let world = World::new();
    let (mut signer, store) = world.enrolled().await;
    let (a, b) = approve_two_keyed_apps(&world, &mut signer).await;
    let a_id = a.keys.app_id_bytes();
    world.switch.fail_next(Fault::Error {
        path: "/ops".into(),
        code: pubky_switch_core::http::ErrorCode::Conflict,
        current: Value::Null,
    });
    signer.renew(a_id, reduce_to_sync()).await.unwrap_err();
    world.switch.fail_next(Fault::Unreachable {
        path: "/ops".into(),
        after: 0,
    });
    signer
        .renew(b.keys.app_id_bytes(), reduce_to_sync())
        .await
        .unwrap_err();
    drop(signer);
    let flow: Value =
        serde_json::from_slice(&store.get(&namespace(&world), b"flow").unwrap().unwrap()).unwrap();
    let signed = serde_json::from_value(flow["Renew"]["doc"].clone()).unwrap();
    let candidate =
        pubky_switch_core::records::IdentityDoc::verify(&signed, &world.key.public()).unwrap();
    assert_eq!(candidate.data_epoch(), 2);
    assert!(!candidate.lists_removed(&a_id));
    let original = snapshot(&world, &store);
    let records = change(&original, b"state", |s| {
        s["newest"]["account"] = Value::Null
    });
    assert_confirmed_refusal(&world, &store, &records, Refusal::FlowInProgress.into()).await;

    // The signer now receives the batch answer and commits its progress, then stops before
    // it can start the identity delivery. Both wallets still have their original grants.
    use pubky_switch_client::store::{Fault as StoreFault, FaultStore};
    replace(&world, &store, &original);
    let faulty = Arc::new(FaultStore::new(store.clone(), StoreFault::StopAfter(1)));
    let mut signer = Signer::open(world.env(faulty), world.keyring())
        .await
        .unwrap();
    let install = signer.install_id();
    signer.resume().await.unwrap_err();
    drop(signer);
    let pending = snapshot(&world, &store);
    let saved: Value =
        serde_json::from_slice(&pending.iter().find(|(k, _)| k == b"flow").unwrap().1).unwrap();
    assert_eq!(saved["Renew"]["sent"], 1);
    assert_eq!(saved["Renew"]["batches"].as_array().unwrap().len(), 1);
    assert_eq!(saved["Renew"]["doc"], flow["Renew"]["doc"]);
    let predecessor = world.switch.identity_doc().unwrap();
    assert_eq!(predecessor.signed(), world.backup().identity_doc().signed());
    assert_eq!(predecessor.body().apps, candidate.body().apps);
    let damaged = change(&pending, b"state", |s| s["newest"]["account"] = Value::Null);
    for app in [&a, &b] {
        let id = app.keys.app_id_bytes();
        let parts = world.switch.bundle_parts_of(&id);
        assert!(!parts.is_empty());
        for part in parts {
            let opened = part
                .bundle
                .open(&world.key.public(), &id, &app.keys.bundle_secret())
                .unwrap();
            let backup = world.backup();
            let cert = backup
                .certs()
                .iter()
                .find(|c| c.hash() == opened.cert)
                .unwrap();
            assert_eq!(Some(cert.hash()), predecessor.listed_cert(&id));
            pubky_switch_core::records::check_bundle_keys(&opened, cert, &|scope| {
                scope != "notes_tags"
            })
            .unwrap();
            assert_eq!(opened.last_epoch, candidate.data_epoch());
        }
    }
    if cut == RotationCut::MissingParts {
        world.switch.forget_bundle_parts(&a_id);
        assert_confirmed_refusal(&world, &store, &damaged, Refusal::FlowInProgress.into()).await;
        return;
    }
    let cut_off = change(&damaged, b"state", |s| {
        s["tombstones"].as_array_mut().unwrap().push(a_id.into());
    });
    assert_confirmed_refusal(&world, &store, &cut_off, Refusal::FlowInProgress.into()).await;
    let higher_floor = change(&damaged, b"state", |s| {
        s["epoch_through"] = (candidate.data_epoch() + 1).into();
    });
    assert_confirmed_refusal(
        &world,
        &store,
        &higher_floor,
        Refusal::FlowInProgress.into(),
    )
    .await;
    replace(&world, &store, &damaged);
    let before = world.transport.requests().len();
    let recovered = Box::pin(Signer::restore_over_unusable(
        world.env(store.clone()),
        world.keyring(),
        discard_confirmed(),
    ))
    .await
    .unwrap();
    assert_eq!(recovered.install_id(), install);
    assert_eq!(recovered.identity_doc().unwrap().unwrap().signed(), &signed);
    assert_eq!(world.switch.identity_doc().unwrap().signed(), &signed);
    assert_eq!(world.backup().identity_doc().signed(), &signed);
    world.assert_request_attempts(before, "PUT", "/identity", 1);
    world.assert_request_attempts(before, "POST", "/ops", 0);
    drop(recovered);
    let mut reopened = Signer::open(world.env(store), world.keyring())
        .await
        .unwrap();
    let next = reopened
        .renew(b.keys.app_id_bytes(), reduce_to_sync())
        .await
        .unwrap();
    assert_eq!(next.data_epoch(), candidate.data_epoch() + 1);
    world.assert_no_version_sent_twice();
}

#[tokio::test]
async fn test_records_confirmed_restore_keeps_spent_floors() {
    let world = World::new();
    let (mut signer, store) = world.enrolled().await;
    let (a, b) = approve_two_keyed_apps(&world, &mut signer).await;
    let before = signer.identity_doc().unwrap().unwrap();
    world.switch.fail_next(Fault::Error {
        path: "/ops".into(),
        code: pubky_switch_core::http::ErrorCode::Conflict,
        current: Value::Null,
    });
    signer
        .renew(a.keys.app_id_bytes(), reduce_to_sync())
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
        .renew(b.keys.app_id_bytes(), reduce_to_sync())
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
            Err(SignerError::Refused(Refusal::AppRequest {
                step: AppRequestStep::RemovedApp,
                ..
            }))
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

#[tokio::test]
async fn test_records_confirmed_restore_keeps_backup_revocation_alert() {
    use pubky_switch_signer::Alert;
    let world = World::new();
    let (mut first, store) = world.enrolled().await;
    let app = App::new(&["notes"], None, [9; 32]);
    world.approve(&mut first, &app).await;
    drop(first);
    let original = snapshot(&world, &store);
    let mut other = Signer::restore_new(
        world.env(Arc::new(MemoryStore::new())),
        world.keyring(),
        UserConfirmed::shown_and_confirmed(),
    )
    .await
    .unwrap();
    let id = app.keys.app_id_bytes();
    world.switch.fail_next(Fault::Unreachable {
        path: "/revoke".into(),
        after: 0,
    });
    other
        .revoke(id, None, UserConfirmed::shown_and_confirmed())
        .await
        .unwrap_err();
    other.set_record_max_age(Some(9)).await.unwrap();
    drop(other);
    replace(&world, &store, &damaged_certificate(&original));
    let mut signer =
        Signer::restore_over_unusable(world.env(store), world.keyring(), discard_confirmed())
            .await
            .unwrap();
    assert!(signer.alerts().contains(&Alert::RevocationPending {
        app_id: id,
        at_switch: false
    }));
    assert!(signer.complete_removals().await.unwrap());
    assert!(
        world
            .switch
            .identity_doc()
            .unwrap()
            .listed_cert(&id)
            .is_none()
    );
    assert!(world.switch.app(&id).revoked_at.is_some());
}

#[tokio::test]
async fn test_records_confirmed_restore_keeps_backup_epoch_warning() {
    use pubky_switch_core::keys::IdentityKey;
    use pubky_switch_core::records::{
        Limits, SIGNER_BACKUP_PATH, SignerBackup, SignerRecords, StoredPart,
    };
    use pubky_switch_signer::Alert;
    let world = World::new();
    let (mut signer, store) = world.enrolled().await;
    let app = App::new(&["notes", "notes_sync"], None, [9; 32]);
    world.approve(&mut signer, &app).await;
    let doc = signer.identity_doc().unwrap().unwrap();
    drop(signer);
    let original = snapshot(&world, &store);
    let id = app.keys.app_id_bytes();
    let cert = world.switch.app(&id).cert.unwrap();
    // The kept local pair is real; the sealed backup exaggerates the epoch of sent keys.
    let records = SignerRecords::new(
        IdentityKey::from_secret(SECRET),
        doc.clone(),
        world.backup().account_created(),
        &[],
        &[cert],
        Limits::default(),
        &[StoredPart {
            app_id: id,
            first_epoch: 2,
            last_epoch: 41,
            cert: doc.listed_cert(&id).unwrap(),
        }],
        None,
    )
    .unwrap();
    world.homeserver.set(
        SIGNER_BACKUP_PATH,
        serde_json::to_vec(&SignerBackup::seal(&world.key, &records).unwrap()).unwrap(),
    );
    replace(&world, &store, &damaged_certificate(&original));
    let mut signer =
        Signer::restore_over_unusable(world.env(store), world.keyring(), discard_confirmed())
            .await
            .unwrap();
    assert!(signer.alerts().contains(&Alert::EpochFloorBounded {
        claimed: 41,
        kept: 2
    }));
    let next = signer
        .renew(
            id,
            CertChange {
                scopes: Some(vec!["notes_sync".into()]),
                expires_at: None,
            },
        )
        .await
        .unwrap();
    assert_eq!(next.data_epoch(), 3);
}

#[tokio::test]
async fn test_signer_recovery_requires_its_original_observation() {
    let world = World::new();
    let (mut signer, store) = world.enrolled().await;
    world.switch.lose_account();
    world.clock.advance_ms(1000);
    world.switch.fail_next(Fault::LoseAnswer {
        path: "/enroll".into(),
    });
    assert!(
        signer
            .declare_provider_loss(SWITCH_ORIGIN, UserConfirmed::shown_and_confirmed())
            .await
            .is_err()
    );
    drop(signer);
    let original = snapshot(&world, &store);
    let later = world.signer_client(None).observe_account().await.unwrap();
    let damaged = change(&original, b"flow", |flow| {
        flow["Recover"]["enrollment"]["Ready"]["observation"] =
            serde_json::to_value(later.carried()).unwrap();
    });
    replace(&world, &store, &damaged);
    let sent = world.transport.requests().len();
    let error = Signer::open(world.env(store.clone()), world.keyring())
        .await
        .err()
        .unwrap();
    assert!(
        matches!(
            error,
            SignerError::Records(RecordsFault::Invariant("another recovery enrollment"))
        ),
        "{error:?}"
    );
    assert_eq!(world.transport.requests().len(), sent);
    assert_eq!(snapshot(&world, &store), damaged);
    replace(&world, &store, &original);
    let mut signer = Signer::open(world.env(store), world.keyring())
        .await
        .unwrap();
    signer.resume().await.unwrap();
    assert_eq!(world.backup().account_created(), world.switch.created());
}

#[tokio::test]
async fn test_signer_recovery_preparation_requires_ordered_exclusions() {
    let world = World::new();
    let (mut signer, store) = world.enrolled().await;
    for secret in [[87; 32], [88; 32]] {
        let app = App::with_keys(
            AppKeys::from_secrets(secret, [89; 32]),
            &["notes"],
            None,
            secret,
        );
        world.approve(&mut signer, &app).await;
        signer
            .revoke(
                app.keys.app_id_bytes(),
                None,
                UserConfirmed::shown_and_confirmed(),
            )
            .await
            .unwrap();
    }
    world.switch.fail_next(Fault::Unreachable {
        path: "/account".into(),
        after: 0,
    });
    assert!(
        signer
            .declare_provider_loss(SWITCH_ORIGIN, UserConfirmed::shown_and_confirmed())
            .await
            .is_err()
    );
    drop(signer);
    let original = snapshot(&world, &store);
    let damaged = change(&original, b"flow", |flow| {
        let excluded = &mut flow["Recover"]["enrollment"]["Preparing"]["revoked_apps"];
        let mut ids: Vec<[u8; 16]> = serde_json::from_value(excluded.clone()).unwrap();
        assert_eq!(ids.len(), 2);
        assert!(ids[0] < ids[1]);
        ids.reverse();
        *excluded = serde_json::to_value(ids).unwrap();
    });
    replace(&world, &store, &damaged);
    let sent = world.transport.requests().len();
    let error = Signer::open(world.env(store.clone()), world.keyring())
        .await
        .err()
        .unwrap();
    assert!(
        matches!(
            error,
            SignerError::Records(RecordsFault::Invariant("unordered recovery exclusions"))
        ),
        "{error:?}"
    );
    assert_eq!(world.transport.requests().len(), sent);
    assert_eq!(snapshot(&world, &store), damaged);
    replace(&world, &store, &original);
    let mut signer = Signer::open(world.env(store), world.keyring())
        .await
        .unwrap();
    signer.resume().await.unwrap();
}

#[tokio::test]
async fn test_signer_recovery_retains_permanent_exclusions() {
    for ready in [false, true] {
        let world = World::new();
        let (mut signer, store) = world.enrolled().await;
        let app = App::new(&["notes"], None, [91; 32]);
        world.approve(&mut signer, &app).await;
        let app_id = app.keys.app_id_bytes();
        signer
            .revoke(app_id, None, UserConfirmed::shown_and_confirmed())
            .await
            .unwrap();
        drop(signer);
        let origin = "https://replacement.example";
        let service =
            ScriptedSwitch::unenrolled_at(&world.key, [93; 32], world.clock.clone(), origin);
        let transport = service.transport();
        let mut env = world.env(store.clone());
        env.transport = transport.clone();
        let mut signer = Signer::open(env.clone(), world.keyring()).await.unwrap();
        service.fail_next(Fault::Unreachable {
            path: if ready { "/enroll" } else { "/account" }.into(),
            after: 0,
        });
        assert!(
            signer
                .declare_provider_loss(origin, UserConfirmed::shown_and_confirmed())
                .await
                .is_err()
        );
        drop(signer);
        let original = snapshot(&world, &store);
        let state: Value =
            serde_json::from_slice(&original.iter().find(|(key, _)| key == b"state").unwrap().1)
                .unwrap();
        let tombstones: Vec<[u8; 16]> =
            serde_json::from_value(state["tombstones"].clone()).unwrap();
        assert!(tombstones.contains(&app_id));
        let base = serde_json::from_value(state["recovery_base"].clone()).unwrap();
        let base =
            pubky_switch_core::records::IdentityDoc::verify(&base, &world.key.public()).unwrap();
        assert!(base.listed_cert(&app_id).is_none());
        let damaged = change(&original, b"flow", |flow| {
            let enrollment = &mut flow["Recover"]["enrollment"];
            if ready {
                let signed =
                    serde_json::from_value(enrollment["Ready"]["enrollment"].clone()).unwrap();
                let signed = pubky_switch_core::records::Enrollment::verify(
                    &signed,
                    &world.key.public(),
                    origin,
                )
                .unwrap();
                assert!(signed.revoked_apps().contains(&app_id));
                let mut body = signed.body().clone();
                body.revoked_apps = Some(Vec::new());
                let changed =
                    pubky_switch_core::records::Enrollment::sign(&world.key, body).unwrap();
                enrollment["Ready"]["enrollment"] = serde_json::to_value(changed.signed()).unwrap();
            } else {
                let excluded: Vec<[u8; 16]> =
                    serde_json::from_value(enrollment["Preparing"]["revoked_apps"].clone())
                        .unwrap();
                assert!(excluded.contains(&app_id));
                enrollment["Preparing"]["revoked_apps"] = serde_json::json!([]);
            }
        });
        assert_eq!(
            original.iter().find(|(key, _)| key == b"state"),
            damaged.iter().find(|(key, _)| key == b"state")
        );
        replace(&world, &store, &damaged);
        let sent = transport.requests().len();
        let error = Signer::open(env.clone(), world.keyring())
            .await
            .unwrap_err();
        assert!(
            matches!(
                error,
                SignerError::Records(RecordsFault::Invariant(
                    "recovery exclusions disagree with records"
                ))
            ),
            "{error:?}"
        );
        assert_eq!(transport.requests().len(), sent);
        assert_eq!(snapshot(&world, &store), damaged);
        // An unrelated invalid copy does not turn the inconsistent flow into permission
        // to discard it through confirmed restoration.
        let unusable = change(&damaged, b"state", |state| {
            break_signature(&mut state["newest"]["doc"]);
        });
        replace(&world, &store, &unusable);
        let error =
            Signer::restore_over_unusable(env.clone(), world.keyring(), discard_confirmed())
                .await
                .unwrap_err();
        assert!(
            matches!(
                error,
                SignerError::Records(RecordsFault::Invariant(
                    "recovery exclusions disagree with records"
                ))
            ),
            "{error:?}"
        );
        assert_eq!(transport.requests().len(), sent);
        assert_eq!(snapshot(&world, &store), unusable);
        replace(&world, &store, &original);
        let mut signer = Signer::open(env, world.keyring()).await.unwrap();
        signer.resume().await.unwrap();
        let sent = transport.requests();
        let request = sent
            .iter()
            .rev()
            .find(|r| r.path_and_query.ends_with("/enroll"))
            .unwrap();
        let enrollment = pubky_switch_core::records::Enrollment::from_request(
            &request.body,
            &world.key.public(),
            origin,
        )
        .unwrap();
        assert!(enrollment.revoked_apps().contains(&app_id));
    }
}

#[tokio::test]
async fn test_signer_recovery_defers_later_listed_revocations() {
    for ready in [false, true] {
        let world = World::new();
        let (mut signer, store) = world.enrolled().await;
        let app = App::new(&["notes"], None, [94; 32]);
        world.approve(&mut signer, &app).await;
        let app_id = app.keys.app_id_bytes();
        world.switch.fail_next(Fault::Unreachable {
            path: if ready { "/enroll" } else { "/account" }.into(),
            after: 0,
        });
        assert!(
            signer
                .declare_provider_loss(SWITCH_ORIGIN, UserConfirmed::shown_and_confirmed(),)
                .await
                .is_err()
        );
        let before = snapshot(&world, &store);
        assert!(matches!(
            signer
                .revoke(app_id, None, UserConfirmed::shown_and_confirmed(),)
                .await,
            Err(SignerError::Refused(Refusal::Recovering))
        ));
        drop(signer);
        let retained = snapshot(&world, &store);
        assert_eq!(
            before.iter().find(|(key, _)| key == b"flow"),
            retained.iter().find(|(key, _)| key == b"flow")
        );
        let state: Value =
            serde_json::from_slice(&retained.iter().find(|(key, _)| key == b"state").unwrap().1)
                .unwrap();
        let tombstones: Vec<[u8; 16]> =
            serde_json::from_value(state["tombstones"].clone()).unwrap();
        assert!(tombstones.contains(&app_id));
        let base = serde_json::from_value(state["recovery_base"].clone()).unwrap();
        let base =
            pubky_switch_core::records::IdentityDoc::verify(&base, &world.key.public()).unwrap();
        assert!(base.listed_cert(&app_id).is_some());
        let mut signer = Signer::open(world.env(store), world.keyring())
            .await
            .unwrap();
        signer.resume().await.unwrap();
        let sent = world.transport.requests();
        let request = sent
            .iter()
            .rev()
            .find(|r| r.path_and_query.ends_with("/enroll"))
            .unwrap();
        let enrollment = pubky_switch_core::records::Enrollment::from_request(
            &request.body,
            &world.key.public(),
            SWITCH_ORIGIN,
        )
        .unwrap();
        assert!(!enrollment.revoked_apps().contains(&app_id));
        if ready {
            let flow: Value =
                serde_json::from_slice(&before.iter().find(|(key, _)| key == b"flow").unwrap().1)
                    .unwrap();
            let signed = serde_json::from_value(
                flow["Recover"]["enrollment"]["Ready"]["enrollment"].clone(),
            )
            .unwrap();
            let original = pubky_switch_core::records::Enrollment::verify(
                &signed,
                &world.key.public(),
                SWITCH_ORIGIN,
            )
            .unwrap();
            assert_eq!(request.body, original.to_request_json().unwrap());
        }
    }
}
