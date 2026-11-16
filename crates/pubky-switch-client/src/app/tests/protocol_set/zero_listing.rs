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

#[tokio::test]
async fn test_zero_listing_gap_fresh_restore_waits_and_resumes() {
    Box::pin(gap_case(false, GapContinue::Fresh)).await;
}

#[tokio::test]
async fn test_zero_listing_gap_ready_listing_allows_the_gap() {
    Box::pin(gap_case(true, GapContinue::Fresh)).await;
}

#[tokio::test]
async fn test_zero_listing_gap_reload_waits_and_resumes() {
    Box::pin(gap_case(false, GapContinue::Reload)).await;
}

#[tokio::test]
async fn test_zero_listing_gap_in_place_restore_waits_and_resumes() {
    Box::pin(gap_case(false, GapContinue::InPlace)).await;
}

#[derive(Clone, Copy)]
enum GapContinue {
    Fresh,
    Reload,
    InPlace,
}

async fn gap_case(key_before_read: bool, continuation: GapContinue) {
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
    let app = Box::pin(p.join_with(&[Permission::ListsRead])).await;
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
    let backup = app.backup_layered().await.unwrap();
    let store = match continuation {
        GapContinue::InPlace => p.store.clone(),
        GapContinue::Fresh | GapContinue::Reload => Arc::new(MemoryStore::new()),
    };
    app = App::restore(
        router.env(&p.w, store.clone()),
        p.set(),
        World::config(),
        &backup,
    )
    .await
    .unwrap();
    if matches!(continuation, GapContinue::Reload) {
        let id = app.app_id();
        drop(app);
        app = App::load(router.env(&p.w, store), p.set(), World::config(), id)
            .await
            .unwrap();
    }
    assert_eq!(app.cursor().seq, 0);
    let gap: crate::app::feed::OwedGap = app
        .reader()
        .get(crate::app::feed::DENY_GAP)
        .await
        .unwrap()
        .unwrap();
    assert_eq!((gap.generation, gap.seq), (2, 0));
    p.tasks.gaps.lock().unwrap().clear();
    p.chat.gaps.lock().unwrap().clear();
    if key_before_read {
        for part in
            pubky_switch_core::records::seal_bundle_parts(&p.w.alice, app.cert(), 1, 2, &|scope| {
                matches!(scope, "tasks" | "chat")
            })
            .unwrap()
        {
            next.signer_op(OpKind::KeyBundlePut(pubky_switch_core::ops::KeyBundlePut {
                target_app_id: app.app_id(),
                bundle: part.bundle,
                first_epoch: part.first_epoch,
                last_epoch: part.last_epoch,
            }))
            .unwrap();
        }
    }
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
    if !key_before_read {
        assert!(app.listing_owed().await.unwrap());
        assert!(
            p.tasks.gaps.lock().unwrap().is_empty(),
            "gap callback ran while sequence-zero listing was still owed: {:?}",
            p.tasks.gaps.lock().unwrap()
        );
        assert!(p.tasks.received.lock().unwrap().is_empty());
        assert!(
            p.chat.received.lock().unwrap().is_empty(),
            "shared gap holds every protocol"
        );
        for part in
            pubky_switch_core::records::seal_bundle_parts(&p.w.alice, app.cert(), 1, 2, &|scope| {
                matches!(scope, "tasks" | "chat")
            })
            .unwrap()
        {
            next.signer_op(OpKind::KeyBundlePut(pubky_switch_core::ops::KeyBundlePut {
                target_app_id: app.app_id(),
                bundle: part.bundle,
                first_epoch: part.first_epoch,
                last_epoch: part.last_epoch,
            }))
            .unwrap();
        }
        for _ in 0..4 {
            app.receive(None).await.unwrap();
        }
    }
    assert_eq!(*p.tasks.gaps.lock().unwrap(), [(0, true)]);
    assert_eq!(*p.chat.gaps.lock().unwrap(), [(0, true)]);
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
