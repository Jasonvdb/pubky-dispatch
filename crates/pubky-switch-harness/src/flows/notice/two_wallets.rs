//! Two installations of one identity meet a service restored to before the second joined.

use std::sync::Arc;

use pubky_switch_client::app::{
    App, AppConfig, AppError, AppEvent, ProviderHealth, RecoveryStep, Refusal,
};
use pubky_switch_client::store::MemoryStore;
use pubky_switch_core::http::NoticeReason;
use pubky_switch_signer::{Signer, UserConfirmed};

use super::super::recovery::{app_env, join_member};
use super::{Notice, ORIGIN, STEP_MS, expect_notices, follow_recovery};
use crate::parties::notes_protocol;
use crate::world::AccountSnapshot;
use crate::{Backend, FlowResult, World};

async fn receive_notice(
    world: &World,
    mut wallet: App,
    name: &str,
    store: Arc<MemoryStore>,
) -> Result<App, Box<dyn std::error::Error>> {
    let from = world.trace().lines.len();
    let report = Box::pin(wallet.receive(None)).await?;
    assert!(report.stopped);
    let notice = wallet
        .recovery_required()
        .ok_or("missing wallet recovery notice")?;
    assert_eq!(notice.generation, 1);
    assert_eq!(notice.reason, Some(NoticeReason::Behind));
    assert!(!notice.permanent);
    assert_eq!(notice.first_seen_ms, world.now_ms());
    assert_eq!(
        wallet.provider_health(),
        ProviderHealth::RecoveryRequired(notice)
    );
    let events: Vec<_> = report
        .events
        .iter()
        .filter_map(|event| match event {
            AppEvent::RecoveryRequired {
                id,
                notice: observed,
            } if observed == &notice => Some(*id),
            _ => None,
        })
        .collect();
    assert_eq!(events.len(), 1);
    expect_notices(
        world,
        from,
        Notice {
            generation: 1,
            reason: "behind",
            permanent: false,
        },
        1,
    )?;
    let own_feed = format!("{{alice/{name}}} GET /v1/{{alice}}/feed");
    assert!(
        world.trace().lines[from..]
            .iter()
            .any(|line| line.label == own_feed)
    );
    let id = wallet.app_id();
    drop(wallet);
    let calls = world.requests_sent();
    let mut wallet = Box::pin(App::load(
        app_env(world, store),
        notes_protocol(),
        AppConfig::default(),
        id,
    ))
    .await?;
    assert_eq!(wallet.recovery_required(), Some(notice));
    assert_eq!(
        wallet.provider_health(),
        ProviderHealth::RecoveryRequired(notice)
    );
    assert!(
        wallet
            .pending_duty_events()
            .await?
            .iter()
            .any(|d| d.event.id() == events.first().copied())
    );
    for automatic in [false, true] {
        assert_eq!(
            wallet.may_attempt(automatic),
            Err(Refusal::RecoveryRequired { generation: 1 })
        );
    }
    let friend = world.identity("carol")?;
    assert!(matches!(
        wallet.keep_peer(&friend.public()).await,
        Err(AppError::Refused(Refusal::RecoveryRequired {
            generation: 1
        }))
    ));
    assert_eq!(world.requests_sent(), calls);
    Ok(wallet)
}

async fn two_wallets(world: &World) -> FlowResult {
    let alice = world.identity("alice")?;
    world.add_switch(ORIGIN, &[&alice]).await?;
    let env = world.signer_env(&alice, Arc::new(MemoryStore::new()))?;
    let mut signer = Box::pin(Signer::create(env, world.keyring(&alice)?, ORIGIN)).await?;
    Box::pin(signer.resume()).await?;
    world.advance_ms(STEP_MS);
    let first_store = Arc::new(MemoryStore::new());
    let mut first = Box::pin(join_member(
        world,
        &alice,
        &mut signer,
        "wallet",
        first_store.clone(),
    ))
    .await?;
    Box::pin(first.receive(None)).await?;
    let snapshot = Box::pin(world.snapshot_account(ORIGIN, &alice)).await?;
    let second_store = Arc::new(MemoryStore::new());
    let mut second = Box::pin(join_member(
        world,
        &alice,
        &mut signer,
        "tablet",
        second_store.clone(),
    ))
    .await?;
    Box::pin(second.receive(None)).await?;
    assert_ne!(first.app_id(), second.app_id());
    if let AccountSnapshot::Database(copy) = &snapshot {
        use sqlx::Connection;
        let mut db = sqlx::PgConnection::connect_with(copy.options()).await?;
        let apps: Vec<Vec<u8>> =
            sqlx::query_scalar("SELECT app_id FROM apps WHERE account_id = $1")
                .bind(alice.key().id())
                .fetch_all(&mut db)
                .await?;
        assert_eq!(apps, vec![first.app_id().to_vec()]);
    }
    let friend = world.identity("bob")?;
    Box::pin(first.keep_peer(&friend.public())).await?;
    Box::pin(first.receive(None)).await?;
    Box::pin(world.restore_account(ORIGIN, &alice, snapshot)).await?;
    let mut first = Box::pin(receive_notice(world, first, "wallet", first_store)).await?;
    world.advance_ms(STEP_MS);
    let mut second = Box::pin(receive_notice(world, second, "tablet", second_store)).await?;
    let recovered =
        Box::pin(signer.declare_provider_loss(ORIGIN, UserConfirmed::shown_and_confirmed()))
            .await?;
    assert_eq!(recovered.generation(), 2);
    world.advance_ms(STEP_MS);
    Box::pin(follow_recovery(world, &mut first, "wallet", 1)).await?;
    Box::pin(follow_recovery(world, &mut second, "tablet", 1)).await?;
    for wallet in [&first, &second] {
        assert_eq!(wallet.recovery_required(), None);
        assert_eq!(wallet.provider_health(), ProviderHealth::Ok);
        let recovery = wallet
            .recovery_info()
            .await?
            .ok_or("missing provider recovery progress")?;
        assert_eq!(
            (recovery.loss.lost_generation, recovery.loss.generation),
            (1, 2)
        );
        assert_eq!(recovery.step, RecoveryStep::Done);
    }
    Ok(())
}

#[tokio::test]
async fn test_both_wallets_receive_the_notice_after_the_service_restores_its_database()
-> Result<(), crate::HarnessError> {
    let _ = Box::pin(crate::run_here(Backend::Service, two_wallets)).await?;
    Ok(())
}

#[tokio::test]
async fn test_both_wallets_receive_the_notice_after_the_scripted_account_goes_back()
-> Result<(), crate::HarnessError> {
    let trace = Box::pin(crate::run_here(Backend::Scripted, two_wallets)).await?;
    assert!(trace.is_some(), "the scripted service is always available");
    Ok(())
}
