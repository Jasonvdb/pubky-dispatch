use super::*;
use crate::{Backend, run_here};
use pubky_switch_client::app::{AppBackup, AppError};

async fn backup_layer(world: &World, corrupt: bool) -> FlowResult {
    let alice = world.identity("alice")?;
    let bob = world.identity("bob")?;
    world.add_switch(ORIGIN, &[&alice, &bob]).await?;
    let mut alice_signer = enroll(world, &alice, ORIGIN).await?;
    let mut bob_signer = enroll(world, &bob, ORIGIN).await?;
    let (tasks, chat) = both();
    let mut wallet = Box::pin(joined_with_both(
        world,
        &alice,
        &mut alice_signer,
        "wallet",
        set_of(&tasks, &chat)?,
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
    wallet.add_contact(&bob.public()).await?;
    world.advance_ms(STEP_MS);
    shop.send(OutgoingMessage::new(
        alice.public(),
        "chat.item",
        serde_json::Map::new(),
    ))
    .await?;
    world.advance_ms(STEP_MS);
    wallet.receive(None).await?;
    assert_eq!(wallet.protocol_scan(CHAT, b"").await?.len(), 1);
    let backup = wallet.backup_layered().await?;
    let mut json: Value = serde_json::from_slice(&backup.to_bytes()?)?;
    assert!(
        json["beyond_cursor"]["processed"]
            .as_array()
            .unwrap()
            .iter()
            .any(|pair| pair[1]["kind"] == "chat.item")
    );
    if corrupt {
        json["layers"]
            .as_array_mut()
            .unwrap()
            .retain(|layer| layer["name"] != CHAT);
    }
    let backup = AppBackup::from_bytes(&serde_json::to_vec(&json)?)?;
    let result = Box::pin(App::restore(
        world.app_env(Arc::new(MemoryStore::new())),
        set_of(&tasks, &chat)?,
        AppConfig::default(),
        &backup,
    ))
    .await;
    if corrupt {
        match result {
            Err(AppError::InvalidData(_)) => Ok(()),
            Ok(restored) => {
                assert!(restored.protocol_scan(CHAT, b"").await?.is_empty());
                Err("missing protocol effects were accepted with their processed markers".into())
            }
            Err(error) => Err(error.into()),
        }
    } else {
        assert_eq!(result?.protocol_scan(CHAT, b"").await?.len(), 1);
        Ok(())
    }
}

#[tokio::test]
async fn test_restore_layers_match_processed_messages_at_both_switches() {
    let scripted = Box::pin(run_here(Backend::Scripted, async |world: &World| {
        backup_layer(world, true).await
    }))
    .await;
    let service = Box::pin(run_here(Backend::Service, async |world: &World| {
        backup_layer(world, true).await
    }))
    .await;
    assert!(
        scripted.is_ok() && service.is_ok(),
        "scripted={scripted:?}; service={service:?}"
    );
}

#[tokio::test]
async fn test_restore_complete_layers_keep_processed_effects_at_both_switches() {
    for backend in [Backend::Scripted, Backend::Service] {
        assert!(
            Box::pin(run_here(backend, async |world: &World| backup_layer(
                world, false
            )
            .await))
            .await
            .unwrap()
            .is_some()
        );
    }
}
