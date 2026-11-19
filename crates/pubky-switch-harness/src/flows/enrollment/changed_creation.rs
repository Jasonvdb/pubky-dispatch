use super::{
    Arc, FlowResult, IDENTITY_PATH, IdentityDoc, MemoryStore, ORIGIN, Signer, World, enroll,
};
use crate::Backend;
use pubky_switch_client::ClientError;
use pubky_switch_client::store::{StateStore, WriteBatch};
use pubky_switch_core::records::SIGNER_BACKUP_PATH;
use pubky_switch_signer::{
    BackupFound, KeyRecoveryStop, Refusal, SignerError, SignerStatus, UserConfirmed,
};

/// The selected recovery has gained only its bound enrollment answer. A changed survey
/// cannot replace the local state, signed original, selected creation or confirmation.
fn checked_enrollment_progress(
    before: &[u8],
    after: &[u8],
    identity: &[u8; 32],
    key: &[u8; 32],
) -> FlowResult {
    use pubky_switch_core::records::{Enrollment, EnrollmentAnswer};
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
    world.add_switch(ORIGIN, &[&alice]).await?;
    let store = Arc::new(MemoryStore::new());
    let env = world.signer_env(&alice, store.clone())?;
    let mut first = Signer::create(env.clone(), world.keyring(&alice)?, ORIGIN).await?;
    let install = first.install_id();
    world.unreachable("POST", "/v1/enroll");
    assert!(matches!(
        first.resume().await,
        Err(SignerError::Switch(ClientError::Transport(_)))
    ));
    let ns = pubky_switch_signer::state::signer_namespace(&alice.public());
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
        Err(SignerError::Switch(ClientError::Transport(_)))
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
        Err(SignerError::Switch(ClientError::Transport(_)))
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
            pubky_switch_signer::KeyRecoveryConfirmed::shown_and_confirmed(&updated, &[]);
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
    world.add_switch(ORIGIN, &[&alice]).await?;
    let store = Arc::new(MemoryStore::new());
    let env = world.signer_env(&alice, store.clone())?;
    let mut signer = Signer::create(env, world.keyring(&alice)?, ORIGIN).await?;
    world.lose_answer("POST", "/v1/enroll");
    assert!(matches!(
        signer.resume().await,
        Err(SignerError::Switch(ClientError::Transport(_)))
    ));
    let ns = pubky_switch_signer::state::signer_namespace(&alice.public());
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
