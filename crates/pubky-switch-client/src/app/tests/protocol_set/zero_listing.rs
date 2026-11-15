use super::*;

#[derive(Clone, Copy)]
enum Continue {
    Same,
    Reload,
    Restore,
}

#[tokio::test]
async fn test_zero_position_listing_after_loss_waits_for_new_epoch_key() {
    Box::pin(wait_for_key(Continue::Same)).await;
}

#[tokio::test]
async fn test_zero_position_listing_reload_preserves_prerequisite() {
    Box::pin(wait_for_key(Continue::Reload)).await;
}

#[tokio::test]
async fn test_zero_position_listing_restore_preserves_prerequisite() {
    Box::pin(wait_for_key(Continue::Restore)).await;
}

async fn wait_for_key(continuation: Continue) {
    let p = Pair::with(
        Named {
            collections: vec![crate::app::Collection::new(
                "task_lists",
                pubky_switch_core::ident::Policy::new("tasks", &["tasks"]),
            )],
            ..named("tasks")
        },
        named("chat"),
    );
    let app = Box::pin(p.join()).await;
    assert!(app.listing_owed().await.unwrap());
    let router = super::super::moves::Router::of(&p.w);
    let key = super::super::moves::next_key();
    let next =
        ScriptedSwitch::recovering(&p.w.alice, key.to_bytes(), p.w.clock.clone(), 2, 1).unwrap();
    router.add(super::super::moves::NEXT, &next);
    p.w.next_doc(|body| body.data_epoch = 2);
    super::super::moves::publish_at(
        &p.w,
        &next,
        pubky_switch_core::records::Inbox::new(
            super::super::moves::NEXT,
            key.verifying_key().to_bytes(),
        ),
        2,
        Some(1),
    );
    let mut app = Box::pin(App::load(
        router.env(&p.w, p.store.clone()),
        p.set(),
        World::config(),
        app.app_id(),
    ))
    .await
    .unwrap();
    app.refresh_identity().await.unwrap();
    app.follow_provider().await.unwrap();
    assert_eq!(app.cursor().seq, 0);
    assert_eq!(app.own_identity().data_epoch(), 2);
    assert!(app.scope_key(2, "tasks").is_none());
    for kind in ["tasks.item", "chat.item"] {
        next.send(
            &p.w.bob,
            &p.w.bob_keys,
            &p.w.bob_cert,
            kind,
            json!({}),
            &[app.app_id()],
        )
        .unwrap();
    }
    for _ in 0..4 {
        app.receive(None).await.unwrap();
    }
    assert!(app.listing_owed().await.unwrap());
    assert!(
        p.tasks.received.lock().unwrap().is_empty(),
        "tasks was handed messages while its new-epoch listing remained owed: {:?}",
        p.tasks.received.lock().unwrap()
    );
    assert_eq!(p.chat.received.lock().unwrap().len(), 1);
    let app_id = app.app_id();
    app = match continuation {
        Continue::Same => app,
        Continue::Reload => {
            drop(app);
            App::load(
                router.env(&p.w, p.store.clone()),
                p.set(),
                World::config(),
                app_id,
            )
            .await
            .unwrap()
        }
        Continue::Restore => {
            let backup = app.backup_layered().await.unwrap();
            drop(app);
            App::restore(
                router.env(&p.w, Arc::new(MemoryStore::new())),
                p.set(),
                World::config(),
                &backup,
            )
            .await
            .unwrap()
        }
    };
    for _ in 0..3 {
        app.receive(None).await.unwrap();
    }
    assert!(app.listing_owed().await.unwrap());
    assert!(
        p.tasks.received.lock().unwrap().is_empty(),
        "the prerequisite survived the restart"
    );
    assert_eq!(
        p.chat.received.lock().unwrap().len(),
        1,
        "no repeated handover"
    );
    for part in
        pubky_switch_core::records::seal_bundle_parts(&p.w.alice, app.cert(), 1, 2, &|scope| {
            matches!(scope, "tasks" | "chat")
        })
        .unwrap()
    {
        next.signer_op(OpKind::KeyBundlePut(pubky_switch_core::ops::KeyBundlePut {
            target_app_id: app_id,
            bundle: part.bundle,
            first_epoch: part.first_epoch,
            last_epoch: part.last_epoch,
        }))
        .unwrap();
    }
    for _ in 0..4 {
        app.receive(None).await.unwrap();
    }
    assert!(app.scope_key(2, "tasks").is_some());
    assert!(
        !app.listing_owed().await.unwrap(),
        "the key lets the listing complete"
    );
    assert_eq!(
        p.tasks
            .received
            .lock()
            .unwrap()
            .iter()
            .map(|(_, kind)| kind.as_str())
            .collect::<Vec<_>>(),
        ["tasks.item"]
    );
    assert_eq!(
        p.chat.received.lock().unwrap().len(),
        1,
        "independent protocol is still handed once"
    );
}
