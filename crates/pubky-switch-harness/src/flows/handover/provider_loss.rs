//! Receiving a hand-over whose service later disappears (Switch spec 12.8).

use super::*;
use crate::Backend;
use crate::flows::recovery::RECOVERY_ORIGIN;
use pubky_switch_client::store::StateStore;
use pubky_switch_client::testing::Router;
use pubky_switch_core::records::{IDENTITY_PATH, IdentityDoc, SIGNER_BACKUP_PATH};
use pubky_switch_signer::state::signer_namespace;
use pubky_switch_signer::{
    AddOutcome, IdentityKeyring, IdentitySecret, KeyError, KeyRecoveryConfirmed, SecretVault,
    SignerEnv, VaultError,
};
use std::sync::atomic::{AtomicBool, Ordering};

/// The receiving device's secure storage is locked on the first attempt to install its key.
struct LockedOnce {
    vault: Arc<dyn SecretVault>,
    locked: AtomicBool,
}

impl SecretVault for LockedOnce {
    fn load(&self) -> Result<Option<IdentitySecret>, VaultError> {
        self.vault.load()
    }

    fn add(&self, secret: &IdentitySecret) -> Result<AddOutcome, VaultError> {
        if self.locked.swap(false, Ordering::SeqCst) {
            return Err(VaultError("vault locked".into()));
        }
        self.vault.add(secret)
    }

    fn delete(&self) -> Result<(), VaultError> {
        self.vault.delete()
    }
}

#[tokio::test]
async fn test_receiving_wallet_recovers_after_its_takeover_won_scripted() {
    check_winning_receiver(Backend::Scripted).await;
}

#[tokio::test]
async fn test_receiving_wallet_recovers_after_its_takeover_won_service() {
    check_winning_receiver(Backend::Service).await;
}

async fn check_winning_receiver(backend: Backend) {
    let result = Box::pin(crate::run_here(backend, async |world: &World| {
        Box::pin(winning_receiver(world)).await
    }))
    .await;
    assert!(matches!(result, Ok(Some(_))), "{result:?}");
}

async fn offer(
    world: &World,
) -> Result<(TestIdentity, Signer, ReceivingApp), Box<dyn std::error::Error>> {
    let alice = world.identity("alice")?;
    world.add_switch(ORIGIN, &[&alice]).await?;
    let mut old = Box::pin(enroll(world, &alice, ORIGIN)).await?;
    let (wallet, _) = Box::pin(joined(world, &alice, &mut old, "wallet")).await?;
    let recipient = receiving(world, &alice, "wallet", &wallet)?;
    Box::pin(old.hand_over_to(wallet.app_id(), UserConfirmed::shown_and_confirmed())).await?;
    Ok((alice, old, recipient))
}

async fn winning_receiver(world: &World) -> FlowResult {
    let (alice, old, recipient) = Box::pin(offer(world)).await?;
    let identity = alice.public();
    let original = old.identity_doc()?.ok_or("missing original document")?;
    drop(old);
    let vault = Arc::new(LockedOnce {
        vault: world.empty_vault(),
        locked: AtomicBool::new(true),
    });
    let store = Arc::new(MemoryStore::new());
    let mut env = world.signer_env(&alice, store)?;
    let error = Box::pin(Signer::receive_hand_over(
        env.clone(),
        &recipient,
        vault.clone(),
    ))
    .await
    .unwrap_err();
    assert!(
        matches!(error, SignerError::Key(KeyError::Vault(_))),
        "{error:?}"
    );
    assert!(matches!(
        IdentityKeyring::open(vault.clone()),
        Err(KeyError::Missing)
    ));
    assert_eq!(
        world
            .files()
            .identity_doc(&identity)
            .map(|copy| copy.hash()),
        Some(original.hash())
    );

    world.add_switch(RECOVERY_ORIGIN, &[&alice]).await?;
    let replacement = Arc::new(Router::new());
    replacement.add(RECOVERY_ORIGIN, world.transport());
    env.transport = replacement;
    let resumed = Box::pin(Signer::resume_take_over(
        env.clone(),
        identity,
        &recipient.keys,
        vault.clone(),
    ))
    .await;
    // Installation finished before the ordinary publication tried to read its old service.
    assert!(
        matches!(
            resumed,
            Err(SignerError::Switch(
                pubky_switch_client::ClientError::Transport(_)
            ))
        ),
        "{resumed:?}"
    );
    let keyring = || IdentityKeyring::open(vault.clone());
    let receiver = Box::pin(Signer::open(env.clone(), keyring()?)).await?;
    let won = receiver
        .identity_doc()?
        .ok_or("missing winning hand-over")?;
    assert_eq!(won.version(), original.version() + 1);
    assert_ne!(won.body().signer, original.body().signer);
    drop(receiver);
    assert_eq!(keyring()?.public_key(), identity);
    Box::pin(recover_and_sign(
        world,
        env,
        vault,
        &won,
        recipient.cert.app_id(),
    ))
    .await
}

async fn recover_and_sign(
    world: &World,
    env: SignerEnv,
    vault: Arc<dyn SecretVault>,
    won: &IdentityDoc,
    app_id: [u8; 16],
) -> FlowResult {
    let keyring = || IdentityKeyring::open(vault.clone());
    let survey = Box::pin(Signer::survey_provider_loss_with_key(
        env.clone(),
        keyring()?,
        RECOVERY_ORIGIN,
    ))
    .await?;
    let mut recovered = Box::pin(Signer::declare_provider_loss_with_key(
        env,
        keyring()?,
        KeyRecoveryConfirmed::shown_and_confirmed(&survey, &[]),
    ))
    .await?;
    let restored = recovered
        .identity_doc()?
        .ok_or("missing restored document")?;
    assert_eq!(restored.inbox().url, RECOVERY_ORIGIN);
    assert_eq!(restored.generation(), won.generation() + 1);
    assert_eq!(restored.body().signer, won.body().signer);
    assert!(restored.version() > won.version());
    assert_eq!(restored.listed_cert(&app_id), won.listed_cert(&app_id));
    let next = Box::pin(recovered.set_record_max_age(Some(3600))).await?;
    assert_eq!(next.version(), restored.version() + 1);
    assert_eq!(next.body().record_max_age, Some(3600));
    assert_eq!(
        world
            .files()
            .identity_doc(&won.identity())
            .map(|copy| copy.hash()),
        Some(next.hash())
    );
    Ok(())
}

#[tokio::test]
async fn test_receiving_wallet_waits_without_a_takeover_result_scripted() {
    check_undecided_receiver(Backend::Scripted).await;
}

#[tokio::test]
async fn test_receiving_wallet_waits_without_a_takeover_result_service() {
    check_undecided_receiver(Backend::Service).await;
}

async fn check_undecided_receiver(backend: Backend) {
    for aborted in [false, true] {
        let result = Box::pin(crate::run_here(backend, async |world: &World| {
            Box::pin(undecided_receiver(world, aborted)).await
        }))
        .await;
        assert!(
            matches!(result, Ok(Some(_))),
            "aborted {aborted}: {result:?}"
        );
    }
}

async fn undecided_receiver(world: &World, aborted: bool) -> FlowResult {
    let (alice, mut old, recipient) = Box::pin(offer(world)).await?;
    let identity = alice.public();
    let store = Arc::new(MemoryStore::new());
    let mut env = world.signer_env(&alice, store.clone())?;
    let vault = world.empty_vault();
    world.unreachable("GET", "/apps");
    assert!(matches!(
        Box::pin(Signer::receive_hand_over(
            env.clone(),
            &recipient,
            vault.clone()
        ))
        .await,
        Err(SignerError::Switch(
            pubky_switch_client::ClientError::Transport(_)
        ))
    ));
    let files =
        || [IDENTITY_PATH, SIGNER_BACKUP_PATH].map(|path| world.files().file(identity, path));
    let before = files();
    assert!(before.iter().all(Option::is_some));
    if aborted {
        // The old service accepted the withdrawal; the answer never reached the sender.
        world.lose_answer("PUT", "/identity");
        let result = Box::pin(old.abort_hand_over(UserConfirmed::shown_and_confirmed())).await;
        assert!(
            matches!(
                result,
                Err(SignerError::Switch(
                    pubky_switch_client::ClientError::Transport(_)
                ))
            ),
            "{result:?}"
        );
        assert_eq!(world.last_fact(DELIVERY, "status").as_deref(), Some("200"));
        assert_eq!(
            world.last_fact(DELIVERY, "fault").as_deref(),
            Some("the answer was lost")
        );
    }
    drop(old);
    assert!(
        files() == before,
        "the receiver saw the same public document and backup"
    );
    let ns = signer_namespace(&identity);
    let records = || store.scan(&ns, b"", None, 10);
    let held = records()?;
    assert!(!held.is_empty());
    env.transport = Arc::new(Router::new());
    let error = Box::pin(Signer::resume_take_over(
        env,
        identity,
        &recipient.keys,
        vault.clone(),
    ))
    .await
    .unwrap_err();
    assert!(
        matches!(
            error,
            SignerError::Switch(pubky_switch_client::ClientError::Transport(_))
        ),
        "{error:?}"
    );
    assert_eq!(records()?, held);
    assert!(matches!(
        IdentityKeyring::open(vault),
        Err(KeyError::Missing)
    ));
    Ok(())
}
