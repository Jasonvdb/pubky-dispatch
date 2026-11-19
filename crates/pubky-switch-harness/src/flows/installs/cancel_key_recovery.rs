//! Stopping a recovery on the holder's existing account, before its document is signed
//! (Switch spec 12.8). A lost enrollment answer is resolved before the stop can take effect.

use std::sync::Arc;

use pubky_switch_client::store::{Fault, FaultStore, MemoryStore, StateStore};
use pubky_switch_core::records::{IDENTITY_PATH, SIGNER_BACKUP_PATH};
use pubky_switch_signer::IdentityKeyring;
use pubky_switch_signer::state::signer_namespace;
use pubky_switch_signer::{KeyRecoveryConfirmed, Refusal, Signer, SignerError, UserConfirmed};

use super::{ORIGIN, published};
use crate::{Backend, FlowResult, World};

async fn cancel_and_sign(world: &World) -> FlowResult {
    let alice = world.identity("alice")?;
    world.add_switch(ORIGIN, &[&alice]).await?;
    let vault = world.identity_vault(&alice);
    let keyring = || IdentityKeyring::open(vault.clone());
    let memory = Arc::new(MemoryStore::new());
    let env = world.signer_env(&alice, memory.clone())?;
    let mut owner = Box::pin(Signer::create(env.clone(), keyring()?, ORIGIN)).await?;
    Box::pin(owner.resume()).await?;
    let ns = signer_namespace(&alice.public());
    for unsent in [true, false] {
        world.files().remove(alice.public(), SIGNER_BACKUP_PATH);
        let doc = owner.identity_doc()?.ok_or("missing account document")?;
        let original = memory.get(&ns, b"state")?;
        let shown = Box::pin(owner.survey_key_recovery()).await?;
        let confirmed = KeyRecoveryConfirmed::shown_and_confirmed(&shown, &[]);
        drop(owner);
        // Lose the first local commit's reply, or lose the completed enrollment's reply.
        let store: Arc<dyn StateStore> = if unsent {
            Arc::new(FaultStore::new(memory.clone(), Fault::FailAfter(1)))
        } else {
            world.lose_answer("POST", "/enroll");
            memory.clone()
        };
        let mut signer =
            Box::pin(Signer::open(world.signer_env(&alice, store)?, keyring()?)).await?;
        assert!(Box::pin(signer.restore(confirmed)).await.is_err());
        drop(signer);
        let saved = memory
            .get(&ns, b"flow")?
            .ok_or("missing interrupted enrollment")?;
        let mut signer = Box::pin(Signer::open(env.clone(), keyring()?)).await?;
        assert_eq!(signer.pending_key_recovery(), Some(ORIGIN));
        if !unsent {
            // A normal retry receiving an unsigned intermediary answer keeps the original.
            world.refuse("POST", "/enroll", 503, "unavailable");
            assert!(Box::pin(signer.resume()).await.is_err());
            assert_eq!(memory.get(&ns, b"flow")?.as_deref(), Some(saved.as_slice()));
            world.unreachable("POST", "/enroll");
            assert!(
                Box::pin(signer.cancel_key_recovery(UserConfirmed::shown_and_confirmed()))
                    .await
                    .is_err()
            );
            assert_eq!(memory.get(&ns, b"flow")?.as_deref(), Some(saved.as_slice()));
            drop(signer);
            // Receipt for the original was verified and committed, but the local answer
            // was lost. Reopen offline and finish without another POST or survey read.
            let lost = Arc::new(FaultStore::new(memory.clone(), Fault::FailAfter(1)));
            signer = Box::pin(Signer::open(world.signer_env(&alice, lost)?, keyring()?)).await?;
            assert!(
                Box::pin(signer.cancel_key_recovery(UserConfirmed::shown_and_confirmed()))
                    .await
                    .is_err()
            );
            drop(signer);
            signer = Box::pin(Signer::open(env.clone(), keyring()?)).await?;
        }
        let requests = world.requests_sent();
        Box::pin(signer.cancel_key_recovery(UserConfirmed::shown_and_confirmed())).await?;
        assert_eq!(world.requests_sent(), requests);
        assert_eq!(signer.pending_key_recovery(), None);
        assert_eq!(memory.get(&ns, b"state")?, original);
        assert_eq!(memory.get(&ns, b"flow")?, None);
        let next = Box::pin(signer.set_record_max_age(Some(if unsent { 60 } else { 120 }))).await?;
        assert_eq!(next.version(), doc.version() + 1);
        assert_eq!(next.generation(), doc.generation());
        assert_eq!(next.body().signer, doc.body().signer);
        assert_eq!(published(world, &alice), Some(next.version()));
        owner = signer;
    }
    drop(owner);

    // A store created just for recovery returns to the normal restore choice. Opening
    // the very same identity vault supplies the key for a new confirmed recovery.
    world.files().remove(alice.public(), SIGNER_BACKUP_PATH);
    let fresh_store = Arc::new(MemoryStore::new());
    let fresh = world.signer_env(&alice, fresh_store.clone())?;
    let survey = Box::pin(Signer::survey_key_recovery_new(fresh.clone(), keyring()?)).await?;
    world.lose_answer("POST", "/enroll");
    let cut = Box::pin(Signer::restore_new(
        fresh.clone(),
        keyring()?,
        KeyRecoveryConfirmed::shown_and_confirmed(&survey, &[]),
    ))
    .await;
    assert!(cut.is_err());
    let mut interrupted = Box::pin(Signer::open(fresh.clone(), keyring()?)).await?;
    Box::pin(interrupted.cancel_key_recovery(UserConfirmed::shown_and_confirmed())).await?;
    assert!(fresh_store.scan(&ns, b"", None, 2)?.is_empty());
    assert_eq!(
        Box::pin(interrupted.resume()).await,
        Err(SignerError::Refused(Refusal::NotSetUp))
    );
    drop(interrupted);
    assert_eq!(keyring()?.public_key(), alice.public());

    // A new install that already signed its recovery version resumes that delivery.
    world.files().remove(alice.public(), SIGNER_BACKUP_PATH);
    let shown = Box::pin(Signer::survey_key_recovery_new(fresh.clone(), keyring()?)).await?;
    world.lose_answer("PUT", "/identity");
    let result = Box::pin(Signer::restore_new(
        fresh.clone(),
        keyring()?,
        KeyRecoveryConfirmed::shown_and_confirmed(&shown, &[]),
    ))
    .await;
    assert!(result.is_err());
    let mut new = Box::pin(Signer::open(fresh, keyring()?)).await?;
    assert_eq!(new.pending_key_recovery(), None);
    assert_eq!(
        Box::pin(new.cancel_key_recovery(UserConfirmed::shown_and_confirmed())).await,
        Err(SignerError::Refused(Refusal::NoPendingKeyRecovery))
    );
    Box::pin(new.resume()).await?;
    let next = Box::pin(new.set_record_max_age(Some(180))).await?;
    assert_eq!(next.version(), shown.version + 2);
    assert_eq!(published(world, &alice), Some(next.version()));
    drop(new);

    // Before a first version exists, stopping keeps the selected serving account even
    // when there is no public file left to locate it.
    world.files().remove(alice.public(), SIGNER_BACKUP_PATH);
    world.files().remove(alice.public(), IDENTITY_PATH);
    let env = world.signer_env(&alice, Arc::new(MemoryStore::new()))?;
    let mut initial = Box::pin(Signer::create(env.clone(), keyring()?, ORIGIN)).await?;
    assert_eq!(
        Box::pin(initial.resume()).await,
        Err(SignerError::Refused(Refusal::FirstAccountPresent))
    );
    let shown = Box::pin(initial.survey_key_recovery()).await?;
    world.lose_answer("POST", "/enroll");
    assert!(
        Box::pin(initial.restore(KeyRecoveryConfirmed::shown_and_confirmed(&shown, &[])))
            .await
            .is_err()
    );
    drop(initial);
    let mut initial = Box::pin(Signer::open(env, keyring()?)).await?;
    Box::pin(initial.cancel_key_recovery(UserConfirmed::shown_and_confirmed())).await?;
    assert_eq!(
        initial.status(),
        pubky_switch_signer::SignerStatus::FirstAccountPresent
    );
    let again = Box::pin(initial.survey_key_recovery()).await?;
    assert_eq!(again, shown);
    let restored =
        Box::pin(initial.restore(KeyRecoveryConfirmed::shown_and_confirmed(&again, &[]))).await?;
    assert_eq!(restored.version(), next.version() + 1);
    let last = Box::pin(initial.set_record_max_age(Some(240))).await?;
    assert_eq!(published(world, &alice), Some(last.version()));
    Ok(())
}

#[tokio::test]
async fn test_stop_interrupted_key_recovery_scripted() {
    crate::run_here(Backend::Scripted, cancel_and_sign)
        .await
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn test_stop_interrupted_key_recovery_service() {
    crate::run_here(Backend::Service, cancel_and_sign)
        .await
        .unwrap()
        .unwrap();
}
