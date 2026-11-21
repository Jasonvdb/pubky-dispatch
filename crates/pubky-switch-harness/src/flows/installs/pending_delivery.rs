//! Recover a pending signer operation after local damage (Switch spec 12.8, Switch wire 3.13).

use super::*;
use crate::Backend;
use pubky_switch_client::store::{Fault, FaultStore, StateStore, WriteBatch};
use pubky_switch_client::{ClientError, StoreError};
use pubky_switch_core::sig::SignedDoc;
use pubky_switch_signer::state::signer_namespace;
use pubky_switch_signer::{RecordsDiscarded, RecordsFault};

#[tokio::test]
async fn test_restore_pending_settings_delivery_scripted() {
    check_pending_delivery(Backend::Scripted).await;
}

#[tokio::test]
async fn test_restore_pending_settings_delivery_service() {
    check_pending_delivery(Backend::Service).await;
}

async fn check_pending_delivery(backend: Backend) {
    for applied in [false, true] {
        let result = Box::pin(crate::run_here(backend, async |world: &World| {
            Box::pin(pending_delivery(world, applied)).await
        }))
        .await;
        assert!(
            matches!(result, Ok(Some(_))),
            "applied {applied}: {result:?}"
        );
    }
}

async fn pending_delivery(world: &World, applied: bool) -> FlowResult {
    let alice = world.identity("alice")?;
    let id = alice.public();
    world.add_switch(ORIGIN, &[&alice]).await?;
    let store = Arc::new(MemoryStore::new());
    let env = world.signer_env(&alice, store.clone())?;
    let keyring = || world.keyring(&alice);
    let mut signer = Box::pin(Signer::create(env.clone(), keyring()?, ORIGIN)).await?;
    Box::pin(signer.resume()).await?;
    let first = signer.identity_doc()?.ok_or("missing first document")?;
    let backup = || {
        world
            .files()
            .file(id, SIGNER_BACKUP_PATH)
            .ok_or("missing backup")
    };
    let earlier_backup = backup()?;
    if applied {
        world.lose_answer("PUT", "/identity");
    } else {
        world.unreachable("PUT", "/identity");
    }
    assert!(matches!(
        Box::pin(signer.set_record_max_age(Some(60))).await,
        Err(SignerError::Switch(ClientError::Transport(_)))
    ));
    drop(signer);
    let saved_backup = backup()?;
    let ns = signer_namespace(&id);
    let state = store.get(&ns, b"state")?.ok_or("missing state")?;
    let flow = store.get(&ns, b"flow")?.ok_or("missing delivery")?;
    let held: Value = serde_json::from_slice(&flow)?;
    let signed: SignedDoc = serde_json::from_value(held["Deliver"]["doc"].clone())?;
    let pending = IdentityDoc::verify(&signed, &id)?;
    let mut damaged: Value = serde_json::from_slice(&state)?;
    *damaged
        .pointer_mut("/newest/account")
        .ok_or("missing original account")? = Value::Null;
    let damaged = serde_json::to_vec(&damaged)?;
    let mut write = WriteBatch::new();
    write.put(&ns, b"state", damaged.clone())?;
    store.commit(write)?;
    let confirmed = RecordsDiscarded::shown_and_confirmed;

    // An earlier genuine backup has no record of the pending settings change.
    world.files().put(id, SIGNER_BACKUP_PATH, earlier_backup);
    assert_eq!(
        Box::pin(Signer::restore_over_unusable(
            env.clone(),
            keyring()?,
            confirmed()
        ))
        .await
        .unwrap_err(),
        Refusal::FlowInProgress.into()
    );
    assert_eq!(store.get(&ns, b"state")?, Some(damaged));
    assert_eq!(store.get(&ns, b"flow")?, Some(flow));
    assert_eq!(
        world.files().identity_doc(&id).map(|doc| doc.hash()),
        Some(first.hash())
    );
    world.files().put(id, SIGNER_BACKUP_PATH, saved_backup);

    // The replacement commits, but the host loses its answer. Inspect what restart will continue.
    let faulty = Arc::new(FaultStore::new(store.clone(), Fault::FailAfter(1)));
    let result = Box::pin(Signer::restore_over_unusable(
        world.signer_env(&alice, faulty)?,
        keyring()?,
        confirmed(),
    ))
    .await;
    assert!(
        matches!(result, Err(SignerError::Store(StoreError::Unknown))),
        "replacement: {result:?}"
    );
    let mut signer = Signer::open(env, keyring()?).await?;
    assert_eq!(
        signer.identity_doc()?.as_ref().map(IdentityDoc::signed),
        Some(&signed)
    );
    let saved = store.get(&ns, b"flow")?;
    if applied {
        assert!(
            saved.is_none(),
            "the service already accepted the original delivery"
        );
    } else {
        let restored: Value = serde_json::from_slice(&saved.ok_or("missing original delivery")?)?;
        assert_eq!(
            restored, held,
            "the complete original operation survives restart"
        );
    }
    Box::pin(signer.resume()).await?;
    let next = signer.identity_doc()?.ok_or("missing restored settings")?;
    assert_eq!(next.version(), pending.version() + 1);
    assert_eq!(next.generation(), pending.generation());
    assert_eq!(next.body().record_max_age, Some(60));
    assert_eq!(
        world.files().identity_doc(&id).map(|doc| doc.hash()),
        Some(next.hash())
    );
    assert_eq!(
        Box::pin(signer.set_record_max_age(Some(120)))
            .await?
            .version(),
        next.version() + 1
    );
    Ok(())
}

#[tokio::test]
async fn test_restore_pending_renewal_scripted() {
    check_pending_change(Backend::Scripted, PendingChange::Renew).await;
}

#[tokio::test]
async fn test_restore_pending_renewal_service() {
    check_pending_change(Backend::Service, PendingChange::Renew).await;
}

#[tokio::test]
async fn test_restore_pending_removal_scripted() {
    check_pending_change(Backend::Scripted, PendingChange::Remove).await;
}

#[tokio::test]
async fn test_restore_pending_removal_service() {
    check_pending_change(Backend::Service, PendingChange::Remove).await;
}

#[derive(Clone, Copy)]
enum PendingChange {
    Renew,
    Remove,
}

async fn check_pending_change(backend: Backend, change: PendingChange) {
    for applied in [false, true] {
        let result = Box::pin(crate::run_here(backend, async |world: &World| {
            Box::pin(pending_change(world, change, applied)).await
        }))
        .await;
        if result.unwrap().is_none() {
            assert_eq!(backend, Backend::Service);
            assert!(!crate::service::database_configured().unwrap());
        }
    }
}

async fn pending_change(world: &World, change: PendingChange, applied: bool) -> FlowResult {
    let alice = world.identity("alice")?;
    let id = alice.public();
    world.add_switch(ORIGIN, &[&alice]).await?;
    let store = Arc::new(MemoryStore::new());
    let env = world.signer_env(&alice, store.clone())?;
    let key = || world.keyring(&alice);
    let mut signer = Box::pin(Signer::create(env.clone(), key()?, ORIGIN)).await?;
    Box::pin(signer.resume()).await?;
    let (mut app, _) = Box::pin(joined(world, &alice, &mut signer, "wallet")).await?;
    let leaving = match change {
        PendingChange::Renew => None,
        PendingChange::Remove => {
            let (phone, _) = Box::pin(joined(world, &alice, &mut signer, "phone")).await?;
            Some(phone.app_id())
        }
    };
    let predecessor = signer.identity_doc()?.ok_or("missing predecessor")?;
    let install = signer.install_id();
    let cutoff = world.now_ms();
    if applied {
        world.lose_answer("POST", "/ops");
    } else {
        world.unreachable("POST", "/ops");
    }
    let result = if let Some(id) = leaving {
        Box::pin(signer.revoke(id, Some(cutoff), UserConfirmed::shown_and_confirmed())).await
    } else {
        let renewal = CertChange {
            scopes: None,
            expires_at: Some(world.now_ms() + 400 * DAY_MS),
        };
        Box::pin(signer.renew(app.app_id(), renewal)).await
    };
    assert!(matches!(
        result,
        Err(SignerError::Switch(ClientError::Transport(_)))
    ));
    drop(signer);
    let ns = signer_namespace(&id);
    let state = store.get(&ns, b"state")?.ok_or("missing state")?;
    let flow = store.get(&ns, b"flow")?.ok_or("missing renewal")?;
    let held: Value = serde_json::from_slice(&flow)?;
    let signed: SignedDoc = serde_json::from_value(held["Renew"]["doc"].clone())?;
    let batches = held["Renew"]["batches"]
        .as_array()
        .ok_or("missing batches")?;
    assert_eq!(batches.len(), 1);
    let expected =
        pubky_switch_core::enc::unb64(batches[0]["bytes"].as_str().ok_or("missing signed batch")?)?;
    let mut damaged: Value = serde_json::from_slice(&state)?;
    *damaged
        .pointer_mut("/newest/account")
        .ok_or("missing original account")? = Value::Null;
    let mut write = WriteBatch::new();
    write.put(&ns, b"state", serde_json::to_vec(&damaged)?)?;
    store.commit(write)?;
    assert!(matches!(
        Box::pin(Signer::open(env.clone(), key()?)).await,
        Err(SignerError::Records(RecordsFault::Damaged(_)))
    ));

    let retries = Arc::new(std::sync::Mutex::new(Vec::new()));
    let observed = retries.clone();
    world.distort(move |request, _response| {
        if request.method == "POST" && request.path_and_query.ends_with("/ops") {
            observed.lock().unwrap().push(request.body.clone());
        }
    });
    let confirmed = RecordsDiscarded::shown_and_confirmed;
    let signer = if applied {
        // The repair commits but its answer is lost. The binding is the only field repaired.
        let faulty = Arc::new(FaultStore::new(store.clone(), Fault::FailAfter(1)));
        let result = Box::pin(Signer::restore_over_unusable(
            world.signer_env(&alice, faulty)?,
            key()?,
            confirmed(),
        ))
        .await;
        assert!(
            matches!(result, Err(SignerError::Store(StoreError::Unknown))),
            "{result:?}"
        );
        assert_eq!(store.get(&ns, b"state")?, Some(state));
        assert_eq!(store.get(&ns, b"flow")?, Some(flow));
        let mut signer = Box::pin(Signer::open(env.clone(), key()?)).await?;
        Box::pin(signer.resume()).await?;
        signer
    } else {
        Box::pin(Signer::restore_over_unusable(
            env.clone(),
            key()?,
            confirmed(),
        ))
        .await?
    };
    assert_eq!(retries.lock().unwrap().as_slice(), [expected]);
    assert_eq!(signer.install_id(), install);
    drop(signer);
    let mut signer = Box::pin(Signer::open(env, key()?)).await?;
    let renewed = signer.identity_doc()?.ok_or("missing renewed document")?;
    assert_eq!(renewed.signed(), &signed);
    assert_eq!(
        world
            .files()
            .identity_doc(&id)
            .as_ref()
            .map(IdentityDoc::signed),
        Some(&signed)
    );
    if let Some(removed) = leaving {
        use crate::parties::{NOTES, TASKS};
        assert!(renewed.listed_cert(&removed).is_none());
        assert!(
            renewed
                .body()
                .removed
                .iter()
                .any(|entry| entry.app_id == removed && entry.distrust_from == cutoff)
        );
        let bytes = world
            .files()
            .file(id, SIGNER_BACKUP_PATH)
            .ok_or("missing signer backup")?;
        let backup: SignerBackup = serde_json::from_slice(&bytes)?;
        let opened = backup.open(alice.key())?;
        assert_eq!(opened.prev(), Some(predecessor.hash()));
        assert_eq!(opened.identity_doc().signed(), &signed);
        assert!(opened.revoked_apps().contains(&removed));
        Box::pin(app.receive(None)).await?;
        Box::pin(app.fetch_key_bundle()).await?;
        let epoch = predecessor.data_epoch() + 1;
        assert_eq!(renewed.data_epoch(), epoch);
        assert_eq!(app.own_identity().signed(), &signed);
        assert!(app.scope_key(epoch, NOTES).is_some());
        assert!(app.scope_key(epoch, TASKS).is_none());
    }
    let next = Box::pin(signer.set_record_max_age(Some(120))).await?;
    assert_eq!(next.version(), renewed.version() + 1);
    assert_eq!(next.body().signer, install);
    Ok(())
}

#[tokio::test]
async fn test_restore_stored_epoch_scripted() {
    check_stored_epoch(Backend::Scripted).await;
}

#[tokio::test]
async fn test_restore_stored_epoch_service() {
    check_stored_epoch(Backend::Service).await;
}

async fn check_stored_epoch(backend: Backend) {
    let result = Box::pin(crate::run_here(backend, async |world| {
        Box::pin(stored_epoch(world)).await
    }))
    .await;
    if result.unwrap().is_none() {
        assert_eq!(backend, Backend::Service);
        assert!(!crate::service::database_configured().unwrap());
    }
}

async fn stored_epoch(world: &World) -> FlowResult {
    use crate::parties::{NOTES, NOTES_READER, TASKS};
    let alice = world.identity("alice")?;
    let id = alice.public();
    world.add_switch(ORIGIN, &[&alice]).await?;
    let store = Arc::new(MemoryStore::new());
    let env = world.signer_env(&alice, store.clone())?;
    let key = || world.keyring(&alice);
    let mut signer = Box::pin(Signer::create(env.clone(), key()?, ORIGIN)).await?;
    Box::pin(signer.resume()).await?;
    let (mut phone, _) = Box::pin(joined(world, &alice, &mut signer, "phone")).await?;
    let (mut wallet, _) = Box::pin(joined(world, &alice, &mut signer, "wallet")).await?;
    let before = signer.identity_doc()?.ok_or("missing predecessor")?;
    let install = signer.install_id();
    drop(signer);

    let backup = || -> Result<SignerBackup, Box<dyn std::error::Error>> {
        let bytes = world
            .files()
            .file(id, SIGNER_BACKUP_PATH)
            .ok_or("missing backup")?;
        Ok(serde_json::from_slice(&bytes)?)
    };
    assert_eq!(
        backup()?.open(alice.key())?.identity_doc().signed(),
        before.signed()
    );
    let ns = signer_namespace(&id);
    let record = |key: &[u8]| -> Result<Value, Box<dyn std::error::Error>> {
        Ok(serde_json::from_slice(
            &store.get(&ns, key)?.ok_or("missing signer record")?,
        )?)
    };
    let write_state = |state: &Value| -> FlowResult {
        let mut write = WriteBatch::new();
        write.put(&ns, b"state", serde_json::to_vec(state)?)?;
        store.commit(write)?;
        Ok(())
    };
    // A refused earlier reduction spent its signed version and epoch. The signer's
    // records tests exercise that refusal; start both services from the resulting floors.
    let epoch = before.data_epoch() + 1;
    let mut state = record(b"state")?;
    state["epoch_through"] = epoch.into();
    state["signed_through"] = (before.version() + 1).into();
    write_state(&state)?;
    let reduce = || CertChange {
        scopes: Some(vec![NOTES_READER.into()]),
        expires_at: None,
    };
    let mut signer = Box::pin(Signer::open(env.clone(), key()?)).await?;
    world.unreachable("POST", "/ops");
    assert!(matches!(
        Box::pin(signer.renew(phone.app_id(), reduce())).await,
        Err(SignerError::Switch(ClientError::Transport(_)))
    ));
    drop(signer);

    // Stop just after the signer writes the acknowledgment and before identity delivery.
    let faulty = Arc::new(FaultStore::new(store.clone(), Fault::StopAfter(1)));
    let mut signer = Box::pin(Signer::open(world.signer_env(&alice, faulty)?, key()?)).await?;
    let start = world.trace().lines.len();
    assert!(matches!(
        Box::pin(signer.resume()).await,
        Err(SignerError::Store(StoreError::Unavailable))
    ));
    let trace = world.trace();
    let responses: Vec<_> = trace.lines[start..]
        .iter()
        .filter(|line| line.label == "{alice} POST /v1/{alice}/ops")
        .filter_map(|line| line.facts.get("status").map(String::as_str))
        .collect();
    assert_eq!(responses, ["200"]);
    drop(signer);
    let flow = record(b"flow")?;
    let batch_count = flow["Renew"]["batches"]
        .as_array()
        .ok_or("missing batches")?
        .len();
    assert!(batch_count > 0);
    assert_eq!(flow["Renew"]["sent"], batch_count);
    let signed: SignedDoc = serde_json::from_value(flow["Renew"]["doc"].clone())?;
    let expected = IdentityDoc::verify(&signed, &id)?;
    assert_eq!(expected.data_epoch(), epoch);
    assert_eq!(expected.version(), before.version() + 2);
    assert_eq!(expected.body().apps, before.body().apps);
    let mut state = record(b"state")?;
    *state
        .pointer_mut("/newest/account")
        .ok_or("missing original account")? = Value::Null;
    write_state(&state)?;
    assert!(matches!(
        Box::pin(Signer::open(env.clone(), key()?)).await,
        Err(SignerError::Records(RecordsFault::Damaged(_)))
    ));

    let start = world.trace().lines.len();
    let signer = Box::pin(Signer::restore_over_unusable(
        env.clone(),
        key()?,
        RecordsDiscarded::shown_and_confirmed(),
    ))
    .await?;
    let trace = world.trace();
    let after = &trace.lines[start..];
    let delivery = after
        .iter()
        .filter(|line| line.label == "{alice} PUT /v1/{alice}/identity")
        .collect::<Vec<_>>();
    assert_eq!(delivery.len(), 1);
    assert_eq!(
        delivery[0].facts.get("status").map(String::as_str),
        Some("200")
    );
    assert!(
        !after
            .iter()
            .any(|line| line.label.ends_with(" POST /v1/{alice}/ops"))
    );
    assert_eq!(signer.install_id(), install);
    assert_eq!(
        signer
            .identity_doc()?
            .ok_or("missing signed epoch")?
            .signed(),
        &signed
    );
    assert_eq!(
        backup()?.open(alice.key())?.identity_doc().signed(),
        &signed
    );
    drop(signer);
    for app in [&mut phone, &mut wallet] {
        Box::pin(app.receive(None)).await?;
        Box::pin(app.fetch_key_bundle()).await?;
        assert_eq!(app.own_identity().signed(), &signed);
        assert_eq!(expected.listed_cert(&app.app_id()), Some(app.cert().hash()));
        assert!(app.scope_key(epoch, NOTES).is_some());
        assert!(app.scope_key(epoch, TASKS).is_none());
    }
    let mut signer = Box::pin(Signer::open(env, key()?)).await?;
    let next = Box::pin(signer.renew(wallet.app_id(), reduce())).await?;
    assert_eq!(next.data_epoch(), epoch + 1);
    assert_eq!(next.body().signer, install);
    Ok(())
}
