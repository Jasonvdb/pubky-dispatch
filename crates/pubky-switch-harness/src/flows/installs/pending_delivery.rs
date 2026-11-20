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
    check_pending_renewal(Backend::Scripted).await;
}

#[tokio::test]
async fn test_restore_pending_renewal_service() {
    check_pending_renewal(Backend::Service).await;
}

async fn check_pending_renewal(backend: Backend) {
    for applied in [false, true] {
        let result = Box::pin(crate::run_here(backend, async |world: &World| {
            Box::pin(pending_renewal(world, applied)).await
        }))
        .await;
        assert!(
            matches!(result, Ok(Some(_))),
            "applied {applied}: {result:?}"
        );
    }
}

async fn pending_renewal(world: &World, applied: bool) -> FlowResult {
    let alice = world.identity("alice")?;
    let id = alice.public();
    world.add_switch(ORIGIN, &[&alice]).await?;
    let store = Arc::new(MemoryStore::new());
    let env = world.signer_env(&alice, store.clone())?;
    let key = || world.keyring(&alice);
    let mut signer = Box::pin(Signer::create(env.clone(), key()?, ORIGIN)).await?;
    Box::pin(signer.resume()).await?;
    let (app, _) = Box::pin(joined(world, &alice, &mut signer, "wallet")).await?;
    let install = signer.install_id();
    if applied {
        world.lose_answer("POST", "/ops");
    } else {
        world.unreachable("POST", "/ops");
    }
    let change = CertChange {
        scopes: None,
        expires_at: Some(world.now_ms() + 400 * DAY_MS),
    };
    assert!(matches!(
        Box::pin(signer.renew(app.app_id(), change)).await,
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
    let next = Box::pin(signer.set_record_max_age(Some(120))).await?;
    assert_eq!(next.version(), renewed.version() + 1);
    assert_eq!(next.body().signer, install);
    Ok(())
}
