//! An enrolled app restores its two protocols' progress during a provider loss.

use super::*;
use crate::flows::recovery::RECOVERY_ORIGIN;
use crate::{Backend, run_here};
use pubky_switch_client::app::{AppBackup, AppError, ProviderLoss, RecoveryStep};
use pubky_switch_client::error::StoreError;
use pubky_switch_signer::UserConfirmed;

pub(super) fn evidence(loss: &ProviderLoss) -> Vec<u8> {
    [
        loss.lost_generation,
        loss.generation,
        loss.declared_at_ms,
        loss.accepted_from_ms,
        loss.uncertain_until_ms,
    ]
    .into_iter()
    .flat_map(u64::to_be_bytes)
    .collect()
}

fn protocols(bob: [u8; 32], carol: [u8; 32], restored: bool) -> ProtocolSet {
    let protocol = |name, peer, held| {
        Arc::new(OrderedProtocol {
            inner: sample_protocol(name),
            held: AtomicBool::new(held),
            wait: WaitFor::Loss(peer),
            deny_changes: AtomicUsize::new(0),
            local_bytes: 0,
        }) as Arc<dyn pubky_switch_client::app::Protocol>
    };
    let mut members = vec![protocol(TASKS, bob, restored)];
    if restored {
        // An installed protocol whose store is unavailable must not hold the old loss.
        members.push(protocol("mail", carol, true));
    }
    members.push(protocol(CHAT, carol, !restored));
    ProtocolSet::new(members).unwrap()
}

async fn restore_answers(world: &World) -> FlowResult {
    let alice = world.identity("alice")?;
    let bob = world.identity("bob")?.public();
    let carol = world.identity("carol")?.public();
    let contact = world.identity("friend")?.public();
    let denied = world.identity("blocked")?.public();
    world.add_switch(ORIGIN, &[&alice]).await?;
    let mut signer = Box::pin(enroll(world, &alice, ORIGIN)).await?;
    let mut source = Box::pin(joined_with_both(
        world,
        &alice,
        &mut signer,
        "wallet",
        protocols(bob, carol, false),
    ))
    .await?;
    let id = source.app_id();
    Box::pin(source.add_contact(&contact)).await?;
    Box::pin(source.deny(&denied)).await?;
    world.lose_switch(ORIGIN);
    world.add_switch(RECOVERY_ORIGIN, &[&alice]).await?;
    Box::pin(signer.declare_provider_loss(RECOVERY_ORIGIN, UserConfirmed::shown_and_confirmed()))
        .await?;
    if let Err(error) = Box::pin(source.refresh_identity()).await {
        assert!(matches!(error, AppError::Transport(_)));
    }
    assert!(
        matches!(Box::pin(source.follow_provider()).await, Err(AppError::Protocol(error))
        if *error.error() == StoreError::Unavailable)
    );
    let before = source.recovery_info().await?.unwrap();
    assert_eq!(before.step, RecoveryStep::Resend);
    let bytes = Box::pin(source.backup_layered()).await?.to_bytes()?;
    drop(source);

    let env = world.app_env(Arc::new(MemoryStore::new()));
    let protocols = protocols(bob, carol, true);
    let mut wallet = Box::pin(App::restore(
        env.clone(),
        protocols.clone(),
        AppConfig::default(),
        &AppBackup::from_bytes(&bytes)?,
    ))
    .await?;
    assert_eq!(wallet.recovery_info().await?, Some(before));
    assert_eq!(
        wallet.protocol_get(TASKS, b"resend").await?,
        Some(evidence(&before.loss))
    );
    assert!(wallet.protocol_get(CHAT, b"resend").await?.is_none());
    let report = Box::pin(wallet.receive(None)).await?;
    assert_eq!(
        report
            .events
            .iter()
            .filter(|event| matches!(event, AppEvent::ProviderRecovered { generation: 2 }))
            .count(),
        1
    );
    assert_eq!(
        wallet.protocol_get(CHAT, b"resend").await?,
        Some(evidence(&before.loss))
    );
    drop(wallet);

    let mut wallet = Box::pin(App::load(env, protocols, AppConfig::default(), id)).await?;
    Box::pin(wallet.receive(None)).await?;
    assert!(wallet.recovery_info().await?.unwrap().steps_done);
    assert!(wallet.protocol_get("mail", b"resend").await?.is_none());
    let list = Box::pin(wallet.allow_list()).await?;
    assert_eq!(list.contacts, [contact]);
    assert_eq!(list.deny, [denied]);
    let mut actual: Vec<_> = list
        .conversations
        .into_iter()
        .map(|entry| entry.pubky)
        .collect();
    actual.sort();
    let mut expected = [bob, carol];
    expected.sort();
    assert_eq!(actual, expected);
    Ok(())
}

#[tokio::test]
async fn test_restore_protocol_loss_answers_at_scripted_switch() {
    assert!(
        Box::pin(run_here(Backend::Scripted, restore_answers))
            .await
            .unwrap()
            .is_some()
    );
}

#[tokio::test]
async fn test_restore_protocol_loss_answers_at_service() {
    assert!(
        Box::pin(run_here(Backend::Service, restore_answers))
            .await
            .unwrap()
            .is_some()
    );
}
