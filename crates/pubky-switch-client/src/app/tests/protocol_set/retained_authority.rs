use super::*;

async fn restore_without_layers(remove_all: bool) {
    let p = Pair::new();
    let mut app = Box::pin(p.join()).await;
    *p.tasks.retrying.lock().unwrap() = 100;
    let held = p.send(app.app_id(), "tasks.item");
    let processed = p.send(app.app_id(), "chat.item");
    read(&mut app, 1).await;
    assert!(app.cursor().seq < held && held < processed);
    assert_eq!(app.protocol_scan("chat", b"").await.unwrap().len(), 1);
    let backup = app.backup_layered().await.unwrap();
    assert!(
        backup
            .beyond_cursor
            .as_ref()
            .unwrap()
            .seen
            .contains(&processed)
    );
    {
        let changed = edited(&backup, |layers| {
            layers.retain(|layer| !remove_all && layer["name"] != json!("chat"));
        });
        let mut result = Box::pin(App::restore(
            p.w.env_on(Arc::new(MemoryStore::new()) as Arc<dyn StateStore>),
            p.set(),
            World::config(),
            &changed,
        ))
        .await;
        if let Ok(restored) = &mut result {
            assert!(
                restored
                    .protocol_scan("chat", b"")
                    .await
                    .unwrap()
                    .is_empty()
            );
            assert!(restored.state.seen.contains(&processed));
            assert!(
                restored
                    .reader()
                    .scan::<crate::app::state::Processed>("proc/")
                    .await
                    .unwrap()
                    .iter()
                    .any(|(_, p)| p.kind == "chat.item")
            );
            *p.tasks.retrying.lock().unwrap() = 0;
            p.chat.received.lock().unwrap().clear();
            read(restored, 3).await;
            assert!(p.chat.received.lock().unwrap().is_empty());
            assert!(
                restored
                    .protocol_scan("chat", b"")
                    .await
                    .unwrap()
                    .is_empty()
            );
        }
        assert!(
            matches!(result, Err(AppError::InvalidData(_))),
            "a restore kept processed/seen chat messages while discarding their committed effects: remove_all={remove_all}, {result:?}"
        );
    }
}

#[tokio::test]
async fn test_restore_complete_protocol_layers_keep_their_processed_effects() {
    let p = Pair::new();
    let mut app = Box::pin(p.join()).await;
    *p.tasks.retrying.lock().unwrap() = 100;
    p.send(app.app_id(), "tasks.item");
    let processed = p.send(app.app_id(), "chat.item");
    read(&mut app, 1).await;
    let backup = app.backup_layered().await.unwrap();
    let restored = Box::pin(App::restore(
        p.w.env_on(Arc::new(MemoryStore::new()) as Arc<dyn StateStore>),
        p.set(),
        World::config(),
        &backup,
    ))
    .await
    .unwrap();
    assert!(restored.state.seen.contains(&processed));
    assert_eq!(restored.protocol_scan("chat", b"").await.unwrap().len(), 1);
}

#[tokio::test]
async fn test_retained_deny_validates_every_owner_before_callbacks() {
    let p = Pair::new();
    let mut app = Box::pin(p.join_with(&[Permission::ListsRead])).await;
    read(&mut app, 1).await;
    let generation = app.cursor().generation;
    let seq = app.cursor().seq;
    let mut tx = app.tx().unwrap();
    tx.put(
        &crate::app::state::key::owed(generation, seq),
        &crate::app::feed::Owed {
            to: vec!["tasks".into(), "unknown".into()],
            call: crate::app::feed::OwedCall::Deny {
                generation,
                seq,
                pubky: [92; 32],
                added: true,
                at_ms: p.w.clock.now_ms(),
            },
        },
    )
    .unwrap();
    app.commit(tx).await.unwrap();
    let before = p.tasks.denies.lock().unwrap().len();
    let result = app.receive(None).await;
    assert!(
        matches!(result, Err(AppError::Store(StoreError::Corrupt))),
        "{result:?}"
    );
    assert_eq!(
        p.tasks.denies.lock().unwrap().len(),
        before,
        "a malformed shared obligation called its first protocol before refusing the owner set"
    );
}

#[tokio::test]
async fn test_restore_processed_messages_require_their_protocol_layer() {
    Box::pin(restore_without_layers(false)).await;
}

#[tokio::test]
async fn test_restore_orphaned_beyond_cursor_requires_protocol_layers() {
    Box::pin(restore_without_layers(true)).await;
}

async fn retained_deny_for_both_owners() -> (Pair, App, App) {
    let p = Pair::new();
    let mut app = Box::pin(p.join_with(&[Permission::ListsRead])).await;
    let mut writer = Box::pin(manager(&p)).await;
    assert!(app.allow_list().await.unwrap().deny.is_empty());
    read(&mut app, 1).await;
    *p.tasks.failing_deny.lock().unwrap() = 1;
    *p.chat.failing_deny.lock().unwrap() = 1;
    writer.deny(&[92; 32]).await.unwrap();
    assert!(app.receive(None).await.unwrap().stopped);
    assert_eq!(app.owed_protocol_calls().await.unwrap(), 1);
    assert!(!app.lists_copy().await.unwrap().deny.contains(&[92; 32]));
    assert!(p.tasks.denies.lock().unwrap().is_empty());
    assert!(p.chat.denies.lock().unwrap().is_empty());
    let id = app.app_id();
    drop(app);
    let app = Box::pin(p.load(id)).await.unwrap();
    (p, app, writer)
}

#[tokio::test]
async fn test_retained_deny_registered_owners_complete() {
    let (p, mut app, _writer) = Box::pin(retained_deny_for_both_owners()).await;
    read(&mut app, 1).await;
    assert_eq!(app.owed_protocol_calls().await.unwrap(), 0);
    assert!(app.lists_copy().await.unwrap().deny.contains(&[92; 32]));
    assert_eq!(*p.tasks.denies.lock().unwrap(), [[92; 32]]);
    assert_eq!(*p.chat.denies.lock().unwrap(), [[92; 32]]);
}

#[tokio::test]
async fn test_retained_deny_registered_owners_complete_after_a_newer_list_read() {
    let (p, mut app, mut writer) = Box::pin(retained_deny_for_both_owners()).await;
    writer.undeny(&[92; 32]).await.unwrap();
    let removal = p.w.switch.seq();
    assert!(!app.allow_list().await.unwrap().deny.contains(&[92; 32]));
    // Hold the gap's next read so neither another list read nor the removal's feed
    // item can repair the copy after the original callbacks complete.
    p.w.switch.fail_next(Fault::Unreachable {
        path: "/allow".into(),
        after: 0,
    });
    assert!(app.receive(None).await.unwrap().stopped);
    assert_eq!(app.owed_protocol_calls().await.unwrap(), 0);
    assert!(app.cursor().seq < removal);
    assert_eq!(*p.tasks.denies.lock().unwrap(), [[92; 32]]);
    assert_eq!(*p.chat.denies.lock().unwrap(), [[92; 32]]);
    assert!(!app.lists_copy().await.unwrap().deny.contains(&[92; 32]));
    read(&mut app, 1).await;
    assert!(app.cursor().seq >= removal);
    assert!(!app.lists_copy().await.unwrap().deny.contains(&[92; 32]));
}

#[tokio::test]
async fn test_restore_seen_progress_requires_every_original_layer_after_pairs_expire() {
    let p = Pair::new();
    let mut app = Box::pin(p.join()).await;
    *p.tasks.retrying.lock().unwrap() = 100;
    p.send(app.app_id(), "tasks.item");
    let processed = p.send(app.app_id(), "chat.item");
    read(&mut app, 1).await;
    // Pair retention is independent of a held cursor and its seen marks.
    let mut tx = app.tx().unwrap();
    tx.delete_prefix("proc/").unwrap();
    app.commit(tx).await.unwrap();
    let backup = app.backup_layered().await.unwrap();
    assert!(backup.beyond_cursor.as_ref().unwrap().processed.is_empty());
    assert!(
        backup
            .beyond_cursor
            .as_ref()
            .unwrap()
            .seen
            .contains(&processed)
    );
    let changed = edited(&backup, |layers| {
        layers.retain(|layer| layer["name"] != "chat")
    });
    for in_place in [false, true] {
        let store = if in_place {
            p.store.clone()
        } else {
            Arc::new(MemoryStore::new())
        };
        let ns = crate::store::client_namespace(&app.app_id());
        let before = store.scan(&ns, b"", None, u32::MAX).unwrap();
        p.tasks.restored.lock().unwrap().clear();
        p.chat.restored.lock().unwrap().clear();
        let result = Box::pin(App::restore(
            p.w.env_on(store.clone()),
            p.set(),
            World::config(),
            &changed,
        ))
        .await;
        assert!(
            matches!(result, Err(AppError::InvalidData(_))),
            "{result:?}"
        );
        assert!(p.tasks.restored.lock().unwrap().is_empty());
        assert!(p.chat.restored.lock().unwrap().is_empty());
        assert_eq!(store.scan(&ns, b"", None, u32::MAX).unwrap(), before);
    }
}

#[tokio::test]
async fn test_restore_layer_roster_is_complete_unique_and_matches_processed_owners() {
    let p = Pair::new();
    let mut app = Box::pin(p.join()).await;
    p.send(app.app_id(), "chat.item");
    read(&mut app, 1).await;
    let original = app.backup_layered().await.unwrap();
    for change in 0..5 {
        let mut backup = original.clone();
        let beyond = backup.beyond_cursor.as_mut().unwrap();
        match change {
            0 => beyond.protocols.clear(),
            1 => beyond.protocols.push("tasks".into()),
            2 => beyond.protocols[1] = "unknown".into(),
            3 => beyond.protocols.retain(|name| name != "chat"),
            4 => {
                beyond.protocols.retain(|name| name != "chat");
                backup.layers.retain(|layer| layer.name != "chat");
            }
            _ => unreachable!(),
        }
        p.tasks.restored.lock().unwrap().clear();
        p.chat.restored.lock().unwrap().clear();
        let store = Arc::new(MemoryStore::new());
        let result = Box::pin(App::restore(
            p.w.env_on(store.clone()),
            p.set(),
            World::config(),
            &backup,
        ))
        .await;
        assert!(
            matches!(result, Err(AppError::InvalidData(_))),
            "change={change}: {result:?}"
        );
        assert!(store.is_empty(&crate::store::client_namespace(&app.app_id())));
        assert!(p.tasks.restored.lock().unwrap().is_empty());
        assert!(p.chat.restored.lock().unwrap().is_empty());
    }
}

#[tokio::test]
async fn test_restore_empty_layers_and_plain_backups_keep_optional_state_valid() {
    let p = Pair::new();
    let mut app = Box::pin(p.join()).await;
    for layered in [false, true] {
        let backup = if layered {
            app.backup_layered().await.unwrap()
        } else {
            app.backup().await.unwrap()
        };
        p.tasks.restored.lock().unwrap().clear();
        p.chat.restored.lock().unwrap().clear();
        let restored = Box::pin(App::restore(
            p.w.env_on(Arc::new(MemoryStore::new())),
            p.set(),
            World::config(),
            &backup,
        ))
        .await
        .unwrap();
        for protocol in [&p.tasks, &p.chat] {
            assert_eq!(*protocol.restored.lock().unwrap(), [layered]);
            assert!(
                restored
                    .protocol_scan(&protocol.name, b"")
                    .await
                    .unwrap()
                    .is_empty()
            );
        }
    }
}

fn retained_call(variant: usize, generation: u64, seq: u64) -> crate::app::feed::OwedCall {
    use crate::app::feed::OwedCall;
    match variant {
        0 => OwedCall::Deny {
            generation,
            seq,
            pubky: [92; 32],
            added: true,
            at_ms: 0,
        },
        1 => OwedCall::from(crate::app::MissedEntries {
            read_at_ms: 0,
            seq,
            entries: 1,
            accepted_from_ms: 0,
            accepted_until_ms: 1,
        }),
        2 => OwedCall::Resend {
            sender: [92; 32],
            accepted_from_ms: 0,
            accepted_until_ms: 1,
            unreadable: false,
        },
        _ => unreachable!(),
    }
}

fn notice_count(protocol: &Named) -> usize {
    protocol.denies.lock().unwrap().len()
        + protocol.missed.lock().unwrap().len()
        + *protocol.resends.lock().unwrap()
}

#[tokio::test]
async fn test_retained_calls_reject_invalid_owner_sets_before_any_effect() {
    use crate::app::{feed::Owed, state::key};
    for variant in 0..3 {
        for names in [
            vec![],
            vec!["tasks", "unknown"],
            vec!["tasks", "tasks"],
            vec!["tasks", "chat", "chat"],
        ] {
            let mut p = Pair::new();
            p.tasks = Arc::new(Named {
                notice_bytes: 256,
                ..named("tasks")
            });
            p.chat = Arc::new(Named {
                notice_bytes: 256,
                ..named("chat")
            });
            let mut app = Box::pin(p.join_with(&[Permission::ListsRead])).await;
            read(&mut app, 1).await;
            let (generation, seq) = (app.cursor().generation, app.cursor().seq);
            let mut tx = app.tx().unwrap();
            tx.put(
                &key::owed(generation, seq),
                &Owed {
                    to: names.iter().map(|name| (*name).into()).collect(),
                    call: retained_call(variant, generation, seq),
                },
            )
            .unwrap();
            app.commit(tx).await.unwrap();
            for reload in [false, true] {
                if reload {
                    app = Box::pin(App::load(p.env(), p.set(), World::config(), app.app_id()))
                        .await
                        .unwrap();
                }
                app.load_told().await.unwrap();
                let before = p.snapshot(&app.app_id());
                let positions = app.told.clone();
                let result = app.receive(None).await;
                assert!(
                    matches!(result, Err(AppError::Store(StoreError::Corrupt))),
                    "{variant}, {names:?}: {result:?}"
                );
                assert_eq!(notice_count(&p.tasks), 0);
                assert_eq!(notice_count(&p.chat), 0);
                assert_eq!(app.told, positions);
                assert_eq!(p.snapshot(&app.app_id()), before);
            }
        }
    }
}

#[tokio::test]
async fn test_retained_call_remaining_subsets_commit_once_and_survive_reload() {
    use crate::app::{feed::Owed, state::key};
    for variant in 0..3 {
        let mut p = Pair::new();
        p.tasks = Arc::new(Named {
            notice_bytes: 256,
            ..named("tasks")
        });
        p.chat = Arc::new(Named {
            notice_bytes: 256,
            ..named("chat")
        });
        let mut app = Box::pin(p.join_with(&[Permission::ListsRead])).await;
        read(&mut app, 1).await;
        let (generation, seq) = (app.cursor().generation, app.cursor().seq);
        let at = key::owed(generation, seq);
        let mut tx = app.tx().unwrap();
        tx.put(
            &at,
            &Owed {
                to: vec!["chat".into()],
                call: retained_call(variant, generation, seq),
            },
        )
        .unwrap();
        app.commit(tx).await.unwrap();
        app = Box::pin(App::load(p.env(), p.set(), World::config(), app.app_id()))
            .await
            .unwrap();
        app.receive(None).await.unwrap();
        assert_eq!(notice_count(&p.tasks), 0);
        assert_eq!(notice_count(&p.chat), 1);
        assert!(app.reader().get::<Owed>(&at).await.unwrap().is_none());
        assert!(!app.protocol_scan("chat", b"").await.unwrap().is_empty());
        app = Box::pin(App::load(p.env(), p.set(), World::config(), app.app_id()))
            .await
            .unwrap();
        app.receive(None).await.unwrap();
        assert_eq!(notice_count(&p.chat), 1);
    }
}

#[tokio::test]
async fn test_retained_queue_validates_later_calls_before_earlier_callbacks() {
    use crate::app::{feed::Owed, state::key};
    let p = Pair::new();
    let mut app = Box::pin(p.join()).await;
    read(&mut app, 1).await;
    let (generation, seq) = (app.cursor().generation, app.cursor().seq);
    assert!(seq > 0);
    let mut tx = app.tx().unwrap();
    for (at, names) in [
        (seq - 1, vec!["tasks".into()]),
        (seq, vec!["chat".into(), "unknown".into()]),
    ] {
        tx.put(
            &key::owed(generation, at),
            &Owed {
                to: names,
                call: retained_call(1, generation, at),
            },
        )
        .unwrap();
    }
    app.commit(tx).await.unwrap();
    let before = p.snapshot(&app.app_id());
    assert!(matches!(
        app.receive(None).await,
        Err(AppError::Store(StoreError::Corrupt))
    ));
    assert_eq!(notice_count(&p.tasks), 0);
    assert_eq!(notice_count(&p.chat), 0);
    assert_eq!(p.snapshot(&app.app_id()), before);
}

#[tokio::test]
async fn test_restore_counts_duplicate_call_owners_without_installing_them() {
    use crate::app::{feed::Owed, state::key};
    for in_place in [false, true] {
        let p = Pair::new();
        let mut app = Box::pin(p.join()).await;
        read(&mut app, 1).await;
        let (generation, seq) = (app.cursor().generation, app.cursor().seq);
        let mut backup = app.backup_layered().await.unwrap();
        let owed = Owed {
            to: vec!["tasks".into(), "tasks".into()],
            call: retained_call(1, generation, seq),
        };
        if in_place {
            let mut tx = app.tx().unwrap();
            tx.put(&key::owed(generation, seq), &owed).unwrap();
            app.commit(tx).await.unwrap();
        } else {
            backup.owed.push((
                format!("{generation}/{seq}"),
                serde_json::to_value(&owed).unwrap(),
            ));
        }
        let store = if in_place {
            p.store.clone()
        } else {
            Arc::new(MemoryStore::new())
        };
        let mut restored = Box::pin(App::restore(
            p.w.env_on(store),
            p.set(),
            World::config(),
            &backup,
        ))
        .await
        .unwrap();
        assert_eq!(restored.owed_protocol_calls().await.unwrap(), 0);
        assert!(restored.take_events().iter().any(|event| matches!(
            event,
            crate::app::AppEvent::RestoreLeftBehind { owed_calls: 1, .. }
        )));
        read(&mut restored, 1).await;
        assert_eq!(notice_count(&p.tasks), 0);
    }
}

#[tokio::test]
async fn test_retained_unverified_deny_checks_owners_before_verification_or_refresh() {
    use crate::app::{
        feed::{Owed, OwedCall},
        state::key,
    };
    let p = Pair::new();
    let mut app = Box::pin(p.join_with(&[Permission::ListsRead])).await;
    read(&mut app, 1).await;
    let (generation, seq) = (app.cursor().generation, app.cursor().seq);
    let op = pubky_switch_core::ops::sign_batch(
        &app.state.keys,
        &app.state.meta.identity,
        Some(app.app_id()),
        generation,
        [28; 16],
        vec![(vec![], OpKind::DenyPut { pubky: [92; 32] })],
    )
    .unwrap()
    .remove(0)
    .signed()
    .clone();
    let owed = Owed {
        to: vec!["tasks".into(), "unknown".into()],
        call: OwedCall::DenyUnverified {
            generation,
            seq,
            pubky: [92; 32],
            added: true,
            at_ms: p.w.clock.now_ms(),
            op,
        },
    };
    assert!(owed.call.kept_op_body().unwrap().is_some());
    let mut tx = app.tx().unwrap();
    tx.put(&key::owed(generation, seq), &owed).unwrap();
    // A list refresh would normally precede retained-call delivery.
    tx.delete(crate::app::admission::LISTS_AT).unwrap();
    app.commit(tx).await.unwrap();
    let before = p.snapshot(&app.app_id());
    let events = app.events.len();
    assert!(matches!(
        app.receive(None).await,
        Err(AppError::Store(StoreError::Corrupt))
    ));
    assert_eq!(p.snapshot(&app.app_id()), before);
    assert_eq!(app.events.len(), events);
    assert_eq!(notice_count(&p.tasks), 0);
    assert_eq!(notice_count(&p.chat), 0);
}
