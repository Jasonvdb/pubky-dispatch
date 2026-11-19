//! Two installations of one identity meet a service restored to before the second joined.

use pubky_switch_client::ClientError;
use pubky_switch_client::app::{App, AppError};
use pubky_switch_core::http::ErrorCode;
use pubky_switch_signer::UserConfirmed;
use serde_json::json;

use super::{Notice, ORIGIN, STEP_MS, expect_notices, follow_recovery, joined, serving};
use crate::world::AccountSnapshot;
use crate::{Backend, FlowResult, World};

async fn receive_notice(world: &World, wallet: &mut App, name: &str) -> FlowResult {
    let from = world.trace().lines.len();
    let reply = Box::pin(wallet.receive(None)).await;
    let Err(AppError::Switch(ClientError::Switch {
        code: ErrorCode::RecoveryRequired,
        status: 503,
        current,
        ..
    })) = reply
    else {
        return Err(format!("{name} received {reply:?}").into());
    };
    assert_eq!(
        current,
        json!({"generation": 1, "reason": "behind", "permanent": false})
    );
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
    Ok(())
}

async fn two_wallets(world: &World) -> FlowResult {
    let alice = world.identity("alice")?;
    let (mut signer, mut first) = Box::pin(serving(world)).await?;
    let snapshot = Box::pin(world.snapshot_account(ORIGIN, &alice)).await?;
    let (mut second, _) = Box::pin(joined(world, &alice, &mut signer, "tablet")).await?;
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
    Box::pin(first.add_contact(&friend.public())).await?;
    Box::pin(first.receive(None)).await?;
    Box::pin(world.restore_account(ORIGIN, &alice, snapshot)).await?;
    Box::pin(receive_notice(world, &mut first, "wallet")).await?;
    world.advance_ms(STEP_MS);
    Box::pin(receive_notice(world, &mut second, "tablet")).await?;
    let recovered =
        Box::pin(signer.declare_provider_loss(ORIGIN, UserConfirmed::shown_and_confirmed()))
            .await?;
    assert_eq!(recovered.generation(), 2);
    world.advance_ms(STEP_MS);
    Box::pin(follow_recovery(world, &mut first, "wallet", 1)).await?;
    Box::pin(follow_recovery(world, &mut second, "tablet", 1)).await?;
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
