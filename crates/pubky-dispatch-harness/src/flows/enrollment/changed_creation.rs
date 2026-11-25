use super::{
    Arc, FlowResult, IDENTITY_PATH, IdentityDoc, MemoryStore, ORIGIN, Signer, World, enroll,
};
use crate::Backend;
use crate::flows::occurrence;
use pubky_dispatch_client::ClientError;
use pubky_dispatch_client::store::{StateStore, WriteBatch};
use pubky_dispatch_core::records::SIGNER_BACKUP_PATH;
use pubky_dispatch_signer::{
    Alert, BackupFound, KeyRecoveryConfirmed, KeyRecoveryStop, Refusal, SignerEnv, SignerError,
    SignerStatus, Source, UserConfirmed,
};

/// The selected recovery has gained only its bound enrollment answer. A changed survey
/// cannot replace the local state, signed original, selected creation or confirmation.
fn checked_enrollment_progress(
    before: &[u8],
    after: &[u8],
    identity: &[u8; 32],
    key: &[u8; 32],
) -> FlowResult {
    use pubky_dispatch_core::records::{Enrollment, EnrollmentAnswer};
    use serde_json::Value;
    let before: Value = serde_json::from_slice(before)?;
    let mut after: Value = serde_json::from_slice(after)?;
    let step = before
        .pointer("/KeyRecover/step")
        .ok_or("missing saved enrollment step")?;
    assert_eq!(step, "Sending");
    let progress = after
        .pointer_mut("/KeyRecover/step")
        .ok_or("missing resumed enrollment")?;
    let result: EnrollmentAnswer = serde_json::from_value(progress["Applied"].clone())?;
    let original =
        serde_json::from_value(before["KeyRecover"]["enrollment"]["Ready"]["enrollment"].clone())?;
    let signed = Enrollment::verify(&original, identity, ORIGIN)?;
    result.check(&signed)?;
    assert_eq!(&result.service_key, key);
    assert_eq!(Some(result.created), signed.body().intent.created());
    *progress = step.clone();
    assert_eq!(after, before);
    Ok(())
}

#[tokio::test]
async fn test_restore_changed_first_creation_scripted() {
    check_changed_creation(Backend::Scripted).await;
}

#[tokio::test]
async fn test_restore_changed_first_creation_service() {
    check_changed_creation(Backend::Service).await;
}

#[tokio::test]
async fn test_repair_first_enrollment_origin_scripted() {
    check_repaired_origin(Backend::Scripted).await;
}

#[tokio::test]
async fn test_repair_first_enrollment_origin_service() {
    check_repaired_origin(Backend::Service).await;
}

async fn check_repaired_origin(backend: Backend) {
    for retained_alarm in [false, true] {
        let result = Box::pin(crate::run_here(backend, async |world: &World| {
            Box::pin(repair_first_origin(world, retained_alarm)).await
        }))
        .await;
        assert!(result.is_ok(), "alarm {retained_alarm}: {result:?}");
        if backend == Backend::Scripted {
            assert!(result.unwrap().is_some());
        }
    }
}

async fn repair_first_origin(world: &World, retained_alarm: bool) -> FlowResult {
    use pubky_dispatch_signer::{RecordsDiscarded, RecordsFault};
    let alice = world.identity("alice")?;
    let id = alice.public();
    world.add_dispatch(ORIGIN, &[&alice]).await?;
    let store = Arc::new(MemoryStore::new());
    let env = world.signer_env(&alice, store.clone())?;
    let key = || world.keyring(&alice);
    let mut signer = Box::pin(Signer::create(env.clone(), key()?, ORIGIN)).await?;
    let install = signer.install_id();
    world.unreachable("POST", "/v1/enroll");
    assert!(matches!(
        Box::pin(signer.resume()).await,
        Err(SignerError::Dispatch(ClientError::Transport(_)))
    ));
    let mut other = Box::pin(enroll(world, &alice, ORIGIN)).await?;
    let earlier = world
        .files()
        .file(id, SIGNER_BACKUP_PATH)
        .ok_or("missing backup")?;
    let serving = Box::pin(other.set_record_max_age(Some(3600))).await?;
    let current = world
        .files()
        .file(id, SIGNER_BACKUP_PATH)
        .ok_or("missing current backup")?;
    assert!(matches!(
        Box::pin(signer.resume()).await,
        Err(SignerError::Dispatch(_))
    ));
    assert_eq!(signer.status(), SignerStatus::FirstEnrollmentHeld);
    let mut alerts = signer.alerts().to_vec();
    drop(signer);
    let ns = pubky_dispatch_signer::state::signer_namespace(&id);
    let mut state = store.get(&ns, b"state")?.ok_or("missing state")?;
    let original = store.get(&ns, b"flow")?.ok_or("missing creation")?;
    let mut damaged: serde_json::Value = serde_json::from_slice(&original)?;
    *damaged
        .pointer_mut("/Enroll/origin")
        .ok_or("missing origin")? = "unreadable".into();
    let damaged = serde_json::to_vec(&damaged)?;
    let mut write = WriteBatch::new();
    let alarm = Alert::Rollback {
        source: Source::Dispatch,
        version: None,
        generation: None,
        high_water_version: serving.version(),
    };
    if retained_alarm {
        alerts.push(alarm.clone());
        let mut held: serde_json::Value = serde_json::from_slice(&state)?;
        held["alerts"] = serde_json::to_value(&alerts)?;
        crate::flows::number_written_alerts(&mut held)?;
        held["dispatch_unconfirmed"] = true.into();
        state = serde_json::to_vec(&held)?;
        write.put(&ns, b"state", state.clone())?;
    }
    write.put(&ns, b"flow", damaged.clone())?;
    store.commit(write)?;
    let before = world.enrollments_sent();
    let confirm = RecordsDiscarded::shown_and_confirmed;
    let diagnosis = Box::pin(Signer::open(env.clone(), key()?))
        .await
        .unwrap_err();
    let start = world.trace().lines.len();
    for (backup, refusal) in [
        (None, Refusal::NoBackup),
        (Some(earlier), Refusal::StaleBackup),
    ] {
        if let Some(bytes) = backup {
            world.files().put(id, SIGNER_BACKUP_PATH, bytes);
        } else {
            world.files().remove(id, SIGNER_BACKUP_PATH);
        }
        assert_eq!(
            Box::pin(Signer::restore_over_unusable(
                env.clone(),
                key()?,
                confirm()
            ))
            .await
            .unwrap_err(),
            refusal.into()
        );
        assert_eq!(store.get(&ns, b"state")?.as_ref(), Some(&state));
        assert_eq!(store.get(&ns, b"flow")?.as_ref(), Some(&damaged));
        assert_eq!(world.enrollments_sent(), before);
    }
    world.files().put(id, SIGNER_BACKUP_PATH, current);
    let repaired = Box::pin(Signer::restore_over_unusable(
        env.clone(),
        key()?,
        confirm(),
    ))
    .await?;
    assert!(matches!(
        diagnosis,
        SignerError::Records(RecordsFault::Damaged(_))
    ));
    assert_eq!(repaired.install_id(), install);
    assert_eq!(repaired.identity(), id);
    assert_eq!(repaired.alerts(), alerts);
    let restored_state = store.get(&ns, b"state")?.ok_or("missing repaired state")?;
    if retained_alarm {
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&restored_state)?,
            serde_json::from_slice::<serde_json::Value>(&state)?
        );
    } else {
        assert_eq!(restored_state, state);
    }
    assert_eq!(store.get(&ns, b"flow")?, Some(original));
    drop(repaired);
    if retained_alarm {
        return Box::pin(resolve_first_alarm(
            world, &alice, env, &store, &alarm, &serving,
        ))
        .await;
    }
    let mut signer = Box::pin(Signer::open(env, key()?)).await?;
    assert_eq!(signer.status(), SignerStatus::FirstEnrollmentHeld);
    let shown = Box::pin(signer.survey_first_enrollment_restore(ORIGIN)).await?;
    assert_eq!(shown.identity_doc.signed(), serving.signed());
    assert_eq!(world.enrollments_sent(), before);
    assert!(
        world.trace().lines[start..]
            .iter()
            .all(|line| line.call != Some("enroll"))
    );
    Box::pin(signer.restore_first_enrollment(&shown, &[], UserConfirmed::shown_and_confirmed()))
        .await?;
    assert_eq!(signer.status(), SignerStatus::Signing);
    let next = Box::pin(signer.set_record_max_age(Some(7200))).await?;
    assert_eq!(next.body().signer, install);
    assert_eq!(next.generation(), serving.generation());
    assert_eq!(next.version(), serving.version() + 2);
    assert_eq!(world.enrollments_sent(), before);
    Ok(())
}

async fn resolve_first_alarm(
    world: &World,
    identity: &super::TestIdentity,
    env: SignerEnv,
    store: &MemoryStore,
    alarm: &Alert,
    serving: &IdentityDoc,
) -> FlowResult {
    use pubky_dispatch_client::testing::Router;
    const REPLACEMENT: &str = "https://recovery.example";
    let key = || world.keyring(identity);
    let ns = pubky_dispatch_signer::state::signer_namespace(&identity.public());
    let held = store.scan(&ns, b"", None, 64)?;
    let before = world.enrollments_sent();
    let mut signer = Box::pin(Signer::open(env.clone(), key()?)).await?;
    let install = signer.install_id();
    let first_hold = Alert::FirstEnrollmentHeld {
        reason: pubky_dispatch_signer::FirstEnrollmentStop::Changed,
    };
    assert!(signer.alerts().contains(&first_hold));
    let acknowledged = Box::pin(signer.clear_alert(&occurrence(&signer, alarm))).await;
    drop(signer);
    let mut signer = Box::pin(Signer::open(env.clone(), key()?)).await?;
    let survey = Box::pin(signer.survey_first_enrollment_restore(ORIGIN)).await;
    let expected = SignerError::Alarm(alarm.clone());
    assert_eq!(
        (acknowledged, signer.alerts().contains(alarm), survey.err()),
        (Err(expected.clone()), true, Some(expected))
    );
    assert_eq!(store.scan(&ns, b"", None, 64)?, held);
    drop(signer);

    world.add_dispatch(REPLACEMENT, &[identity]).await?;
    let shown = Box::pin(Signer::survey_provider_loss_with_key(
        env.clone(),
        key()?,
        REPLACEMENT,
    ))
    .await?;
    assert_eq!(
        (shown.generation, shown.version),
        (serving.generation(), serving.version())
    );
    let confirm = || KeyRecoveryConfirmed::shown_and_confirmed(&shown, &[]);
    let mut offline = env.clone();
    offline.transport = Arc::new(Router::new());
    let refused = Box::pin(Signer::declare_provider_loss_with_key(
        offline,
        key()?,
        confirm(),
    ))
    .await;
    assert!(
        matches!(
            refused,
            Err(SignerError::Dispatch(ClientError::Transport(_)))
        ),
        "{refused:?}"
    );
    let reopened = Box::pin(Signer::open(env.clone(), key()?)).await?;
    assert!(reopened.alerts().contains(alarm));
    assert!(reopened.alerts().contains(&first_hold));
    assert_eq!(store.scan(&ns, b"", None, 64)?, held);
    assert_eq!(world.enrollments_sent(), before);
    drop(reopened);

    world.lose_answer("POST", "/v1/enroll");
    let unanswered = Box::pin(Signer::declare_provider_loss_with_key(
        env.clone(),
        key()?,
        confirm(),
    ))
    .await;
    assert!(matches!(
        unanswered,
        Err(SignerError::Dispatch(ClientError::Transport(_)))
    ));
    let mut recovered = Box::pin(Signer::open(env, key()?)).await?;
    assert_eq!(
        recovered.status(),
        SignerStatus::Recovering {
            origin: REPLACEMENT.into()
        }
    );
    assert!(recovered.alerts().contains(alarm));
    let first_hold_after_reopen = recovered.alerts().contains(&first_hold);
    Box::pin(recovered.resume()).await?;
    let doc = recovered
        .identity_doc()?
        .ok_or("missing recovered version")?;
    assert!(!recovered.alerts().contains(alarm));
    assert_eq!(recovered.status(), SignerStatus::Signing);
    assert_eq!(
        (
            first_hold_after_reopen,
            recovered.alerts().contains(&first_hold)
        ),
        (false, false)
    );
    assert_eq!(doc.body().signer, install);
    assert_eq!(doc.inbox().url, REPLACEMENT);
    assert_eq!(doc.body().recovery_from, Some(serving.generation()));
    assert_eq!(doc.generation(), serving.generation() + 1);
    assert!(doc.version() > serving.version());
    let next = Box::pin(recovered.set_record_max_age(Some(7200))).await?;
    assert_eq!(next.version(), doc.version() + 1);
    assert_eq!(
        world
            .files()
            .identity_doc(&identity.public())
            .unwrap()
            .signed(),
        next.signed()
    );
    Ok(())
}

async fn check_changed_creation(backend: Backend) {
    for backup in [true, false] {
        let result = Box::pin(crate::run_here(backend, async |world: &World| {
            Box::pin(restore_changed_creation(world, backup)).await
        }))
        .await;
        assert!(matches!(result, Ok(Some(_))), "backup {backup}: {result:?}");
    }
    let result = Box::pin(crate::run_here(backend, restore_original_receipt)).await;
    assert!(
        matches!(result, Ok(Some(_))),
        "original receipt: {result:?}"
    );
}

async fn restore_changed_creation(world: &World, backup: bool) -> FlowResult {
    let alice = world.identity("alice")?;
    world.add_dispatch(ORIGIN, &[&alice]).await?;
    let store = Arc::new(MemoryStore::new());
    let env = world.signer_env(&alice, store.clone())?;
    let mut first = Signer::create(env.clone(), world.keyring(&alice)?, ORIGIN).await?;
    let install = first.install_id();
    world.unreachable("POST", "/v1/enroll");
    assert!(matches!(
        first.resume().await,
        Err(SignerError::Dispatch(ClientError::Transport(_)))
    ));
    let ns = pubky_dispatch_signer::state::signer_namespace(&alice.public());
    let pending = store.scan(&ns, b"", None, 64)?;
    assert_eq!(
        first.survey_first_enrollment_restore(ORIGIN).await,
        Err(Refusal::KeyRecovery(KeyRecoveryStop::NotServing).into())
    );
    assert_eq!(store.scan(&ns, b"", None, 64)?, pending);
    drop(first);

    let mut other = enroll(world, &alice, ORIGIN).await?;
    let mut first = Signer::open(env.clone(), world.keyring(&alice)?).await?;
    let old = first.survey_first_enrollment_restore(ORIGIN).await?;
    let mut predecessor = other.set_record_max_age(Some(3600)).await?;
    if !backup {
        world.files().remove(alice.public(), SIGNER_BACKUP_PATH);
        world.files().remove(alice.public(), IDENTITY_PATH);
    }
    let confirm = UserConfirmed::shown_and_confirmed;
    assert_eq!(
        Box::pin(first.restore_first_enrollment(&old, &[], confirm())).await,
        Err(Refusal::KeyRecovery(KeyRecoveryStop::SurveyChanged).into())
    );
    assert_eq!(store.scan(&ns, b"", None, 64)?, pending);
    let shown = first.survey_first_enrollment_restore(ORIGIN).await?;
    assert!(first.identity_doc()?.is_none());
    assert_eq!(shown.identity_doc.signed(), predecessor.signed());
    assert_eq!(shown.recovery.signer, predecessor.body().signer);
    assert_eq!(shown.recovery.generation, predecessor.generation());
    assert_eq!(shown.recovery.version, predecessor.version());
    assert_eq!(
        shown.recovery.backup,
        if backup {
            BackupFound::Matches
        } else {
            BackupFound::Missing
        }
    );
    world.lose_answer("POST", "/v1/enroll");
    assert!(matches!(
        Box::pin(first.restore_first_enrollment(&shown, &[], confirm())).await,
        Err(SignerError::Dispatch(ClientError::Transport(_)))
    ));
    assert_eq!(store.scan(&ns, b"", None, 64)?, pending);
    drop(first);
    let mut first = Signer::open(env.clone(), world.keyring(&alice)?).await?;
    if backup {
        world.lose_answer("PUT", "/identity");
    } else {
        world.unreachable_after("POST", "/v1/enroll", 1);
    }
    assert!(matches!(
        Box::pin(first.restore_first_enrollment(&shown, &[], confirm())).await,
        Err(SignerError::Dispatch(ClientError::Transport(_)))
    ));
    let selected = store.scan(&ns, b"", None, 64)?;
    assert_ne!(selected, pending);
    assert_eq!(
        Box::pin(first.restore_first_enrollment(&shown, &[], confirm())).await,
        Err(Refusal::FirstEnrollmentUnavailable.into())
    );
    assert_eq!(store.scan(&ns, b"", None, 64)?, selected);
    drop(first);
    let mut first = Signer::open(env.clone(), world.keyring(&alice)?).await?;
    if backup {
        Box::pin(first.resume()).await?;
    } else {
        // The serving signer made a normal change while the existing enrollment was pending.
        predecessor = other.set_record_max_age(Some(7200)).await?;
        world.files().remove(alice.public(), SIGNER_BACKUP_PATH);
        world.files().remove(alice.public(), IDENTITY_PATH);
        assert_eq!(
            Box::pin(first.resume()).await,
            Err(Refusal::KeyRecovery(KeyRecoveryStop::SurveyChanged).into())
        );
        let current = store.scan(&ns, b"", None, 64)?;
        assert_eq!(current.len(), selected.len());
        for ((name, before), (after_name, after)) in selected.iter().zip(&current) {
            assert_eq!(name, after_name);
            if name == b"flow" {
                checked_enrollment_progress(
                    before,
                    after,
                    &alice.public(),
                    &predecessor.inbox().service_key,
                )?;
            } else {
                assert_eq!(before, after);
            }
        }
        drop(first);
        first = Signer::open(env, world.keyring(&alice)?).await?;
        let updated = first.survey_key_recovery().await?;
        assert_eq!(updated.version, predecessor.version());
        let accepted =
            pubky_dispatch_signer::KeyRecoveryConfirmed::shown_and_confirmed(&updated, &[]);
        Box::pin(first.restore(accepted)).await?;
    }
    let next = first.identity_doc()?.ok_or("missing restored document")?;
    assert_eq!(first.status(), SignerStatus::Signing);
    assert_eq!(first.install_id(), install);
    assert_eq!(next.body().signer, install);
    assert_eq!(
        (next.generation(), next.version()),
        (predecessor.generation(), predecessor.version() + 1)
    );
    assert_eq!(
        next.body().record_max_age,
        predecessor.body().record_max_age
    );
    assert_eq!(next.inbox(), predecessor.inbox());
    assert_eq!(
        world
            .files()
            .identity_doc(&alice.public())
            .as_ref()
            .map(IdentityDoc::hash),
        Some(next.hash())
    );
    assert_eq!(world.enrollments_sent(), if backup { 2 } else { 3 });
    assert_eq!(world.faults_left(), 0);
    Ok(())
}

async fn restore_original_receipt(world: &World) -> FlowResult {
    let alice = world.identity("alice")?;
    world.add_dispatch(ORIGIN, &[&alice]).await?;
    let store = Arc::new(MemoryStore::new());
    let env = world.signer_env(&alice, store.clone())?;
    let mut signer = Signer::create(env, world.keyring(&alice)?, ORIGIN).await?;
    world.lose_answer("POST", "/v1/enroll");
    assert!(matches!(
        signer.resume().await,
        Err(SignerError::Dispatch(ClientError::Transport(_)))
    ));
    let ns = pubky_dispatch_signer::state::signer_namespace(&alice.public());
    let snapshot = Arc::new(MemoryStore::new());
    let mut records = WriteBatch::new();
    for (key, value) in store.scan(&ns, b"", None, 64)? {
        records.put(&ns, key, value)?;
    }
    snapshot.commit(records)?;
    // The on-device store backup predates the reply. The service still has that receipt.
    Box::pin(signer.resume()).await?;
    let original = signer.identity_doc()?.ok_or("missing original document")?;
    drop(signer);
    let env = world.signer_env(&alice, snapshot)?;
    let mut signer = Signer::open(env, world.keyring(&alice)?).await?;
    let shown = signer.survey_first_enrollment_restore(ORIGIN).await?;
    assert!(signer.identity_doc()?.is_none());
    assert_eq!(shown.identity_doc.signed(), original.signed());
    Box::pin(signer.restore_first_enrollment(&shown, &[], UserConfirmed::shown_and_confirmed()))
        .await?;
    assert_eq!(signer.status(), SignerStatus::Signing);
    assert_eq!(
        signer.identity_doc()?.map(|doc| doc.hash()),
        Some(original.hash())
    );
    assert_eq!(world.enrollments_sent(), 1);
    Ok(())
}
