use super::*;
use crate::{Backend, run_here};
use pubky_switch_client::app::Collection;
use pubky_switch_client::testing::ProtocolSpec;
use pubky_switch_core::ident::Policy;
use pubky_switch_signer::UserConfirmed;

async fn listing_after_loss(world: &World) -> FlowResult {
    use crate::flows::recovery::{RECOVERY_ORIGIN, SENDERS_ORIGIN};
    let alice = world.identity("alice")?;
    let bob = world.identity("bob")?;
    world.add_switch(ORIGIN, &[&alice]).await?;
    world.add_switch(SENDERS_ORIGIN, &[&bob]).await?;
    let mut alice_signer = Box::pin(enroll(world, &alice, ORIGIN)).await?;
    let mut bob_signer = Box::pin(enroll(world, &bob, SENDERS_ORIGIN)).await?;
    let tasks = Arc::new(TestProtocol::keeping(ProtocolSpec {
        name: TASKS.into(),
        keyed_scopes: vec![TASKS.into()],
        accepts: vec!["tasks.item".into()],
        collections: vec![Collection::new("task_lists", Policy::new(TASKS, &[TASKS]))],
    }));
    let chat = sample_protocol(CHAT);
    let asking = Asking::for_scopes(world.app_keys(&alice, "wallet")?, &[TASKS, CHAT])?;
    let review = alice_signer.review(asking.request.signed(), &asking.auth)?;
    let approved = Box::pin(alice_signer.approve(review)).await?;
    Box::pin(alice_signer.claim_delivered(&approved.request)).await?;
    let mut wallet = Box::pin(App::join(
        world.app_env(Arc::new(MemoryStore::new())),
        set_of(&tasks, &chat)?,
        AppConfig::default(),
        asking.join_request(alice.public(), &approved)?,
    ))
    .await?;
    assert!(wallet.listing_owed().await?);
    Box::pin(wallet.add_contact(&bob.public())).await?;
    let (phone_tasks, phone_chat) = both();
    let phone = Box::pin(joined_with_both(
        world,
        &alice,
        &mut alice_signer,
        "phone",
        set_of(&phone_tasks, &phone_chat)?,
    ))
    .await?;
    let (shop_tasks, shop_chat) = both();
    let mut shop = Box::pin(joined_with_both(
        world,
        &bob,
        &mut bob_signer,
        "shop",
        set_of(&shop_tasks, &shop_chat)?,
    ))
    .await?;
    Box::pin(alice_signer.revoke(phone.app_id(), None, UserConfirmed::shown_and_confirmed()))
        .await?;
    world.lose_switch(ORIGIN);
    world.add_switch(RECOVERY_ORIGIN, &[&alice]).await?;
    Box::pin(
        alice_signer.declare_provider_loss(RECOVERY_ORIGIN, UserConfirmed::shown_and_confirmed()),
    )
    .await?;
    // Taking the new document may still try the lost provider for its keys. The
    // committed document lets the explicit provider follow proceed after that failure.
    if let Err(error) = Box::pin(wallet.refresh_identity()).await {
        assert!(matches!(
            error,
            pubky_switch_client::app::AppError::Transport(_)
        ));
    }
    assert_eq!(wallet.own_identity().generation(), 2);
    Box::pin(wallet.follow_provider()).await?;
    assert_eq!(wallet.cursor().seq, 0);
    assert_eq!(wallet.own_identity().data_epoch(), 2);
    assert!(wallet.scope_key(2, TASKS).is_none());
    for kind in ["tasks.item", "chat.item"] {
        let (_, delivery) = shop
            .send(OutgoingMessage::new(
                alice.public(),
                kind,
                serde_json::Map::new(),
            ))
            .await?;
        assert!(
            matches!(
                delivery,
                pubky_switch_client::app::Delivery::Accepted { .. }
            ),
            "{delivery:?}"
        );
    }
    for _ in 0..4 {
        Box::pin(wallet.receive(None)).await?;
    }
    assert!(wallet.listing_owed().await?);
    assert!(
        tasks.received().is_empty(),
        "a message preceded the required collection listing"
    );
    assert_eq!(
        chat.received().len(),
        1,
        "the independent protocol advances"
    );
    Box::pin(alice_signer.run_due()).await?;
    for _ in 0..4 {
        Box::pin(wallet.receive(None)).await?;
    }
    assert!(wallet.scope_key(2, TASKS).is_some());
    assert!(!wallet.listing_owed().await?);
    assert_eq!(tasks.received().len(), 1);
    assert_eq!(chat.received().len(), 1);
    Ok(())
}

#[tokio::test]
async fn test_zero_position_listing_waits_and_resumes_at_scripted_switch() {
    assert!(
        Box::pin(run_here(Backend::Scripted, listing_after_loss))
            .await
            .unwrap()
            .is_some()
    );
}

#[tokio::test]
async fn test_zero_position_listing_waits_and_resumes_at_service() {
    assert!(
        Box::pin(run_here(Backend::Service, listing_after_loss))
            .await
            .unwrap()
            .is_some()
    );
}
