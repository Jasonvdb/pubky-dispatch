use super::*;
use crate::store::{Fault as StoreFault, FaultStore};

async fn compatible_pair(p: &Pair) -> App {
    let request =
        p.w.signer
            .approve(&app_keys("wallet"), &AppSpec::new(&["tasks"]))
            .unwrap();
    let mut app = App::join(p.env(), p.set(), World::config(), request)
        .await
        .unwrap();
    read(&mut app, 2).await;
    p.w.clock.advance_ms(1);
    app
}

#[tokio::test]
async fn test_retire_protocol_keeps_sibling_state_on_load_and_layered_restore() {
    let p = Pair::new();
    let mut app = Box::pin(compatible_pair(&p)).await;
    let id = app.app_id();
    let received = p.send(id, "tasks.item");
    read(&mut app, 2).await;
    assert_eq!(kinds(&p.tasks), ["tasks.item"]);
    let processed = app.reader().scan_raw("proc/").await.unwrap();
    assert_eq!(processed.len(), 1);
    app.protocol_commit(
        "tasks",
        &[LocalWrite::Put {
            key: b"one".to_vec(),
            value: vec![4],
        }],
    )
    .await
    .unwrap();
    app.renew_record("chat", None).await.unwrap();
    app.retain_loss_uploads_for("chat", b"cutoff")
        .await
        .unwrap();
    app.retain_loss_uploads_for("tasks", b"one").await.unwrap();
    let before = app.backup_layered().await.unwrap();
    plant_duty(&p, &id, 1, &["tasks"]);
    let cursor = app.cursor();
    assert!(cursor.seq >= received);
    p.w.clock.advance_ms(1);
    app.retire_protocol("chat").await.unwrap();
    let mut app = App::load(p.env(), p.tasks.clone(), World::config(), id)
        .await
        .unwrap();
    assert_eq!(app.cursor(), cursor);
    assert_eq!(app.reader().scan_raw("proc/").await.unwrap(), processed);
    let checkpoints = app
        .reader()
        .scan::<Vec<u8>>("loss-checkpoint/")
        .await
        .unwrap();
    assert_eq!(checkpoints, [("tasks".to_owned(), b"one".to_vec())]);
    assert_eq!(
        app.protocol_get("tasks", b"one").await.unwrap(),
        Some(vec![4])
    );
    assert_eq!(
        app.unacknowledged_events_for("tasks").await.unwrap().len(),
        1
    );
    assert!(!app.record_expiries().await.unwrap().contains_key("chat"));
    let record = AppRecord::verify(app.record(), &app.identity()).unwrap();
    assert!(record.accepts("tasks.item"));
    assert!(!record.accepts("chat.item"));
    app.publish_record().await.unwrap();
    let fresh = || {
        p.w.env_on(Arc::new(MemoryStore::new()) as Arc<dyn StateStore>)
    };
    assert!(
        App::restore(fresh(), p.tasks.clone(), World::config(), &before)
            .await
            .is_err()
    );
    let layered = app.backup_layered().await.unwrap();
    let plain = app.backup().await.unwrap();
    for (backup, value) in [(layered, Some(vec![4])), (plain, None)] {
        let serialized = AppBackup::from_bytes(&backup.to_bytes().unwrap()).unwrap();
        let restored = App::restore(fresh(), p.tasks.clone(), World::config(), &serialized)
            .await
            .unwrap();
        assert_eq!(restored.protocols().names(), ["tasks"]);
        assert_eq!(restored.protocol_get("tasks", b"one").await.unwrap(), value);
    }
    let restored = App::restore(fresh(), p.set(), World::config(), &before)
        .await
        .unwrap();
    assert!(restored.protocols().contains("chat"));
}

#[tokio::test]
async fn test_retire_protocol_keeps_a_siblings_owed_callback_through_restore() {
    let p = Pair::new();
    let mut app = Box::pin(compatible_pair(&p)).await;
    let id = app.app_id();
    *p.tasks.failing_missed.lock().unwrap() = u32::MAX;
    let now = p.w.clock.now_ms();
    let seq = p.w.dispatch.push_missed(1, now, now);
    read(&mut app, 2).await;
    assert_eq!(*p.chat.missed.lock().unwrap(), [seq]);
    app.protocol_commit(
        "chat",
        &[LocalWrite::Delete {
            key: format!("missed/{seq}").into_bytes(),
        }],
    )
    .await
    .unwrap();
    app.retire_protocol("chat").await.unwrap();
    let mut app = App::load(p.env(), p.tasks.clone(), World::config(), id)
        .await
        .unwrap();
    assert_eq!(app.owed_protocol_calls().await.unwrap(), 1);
    let backup = app.backup_layered().await.unwrap();
    let fresh =
        p.w.env_on(Arc::new(MemoryStore::new()) as Arc<dyn StateStore>);
    let mut app = App::restore(fresh, p.tasks.clone(), World::config(), &backup)
        .await
        .unwrap();
    assert_eq!(app.owed_protocol_calls().await.unwrap(), 1);
    *p.tasks.failing_missed.lock().unwrap() = 0;
    read(&mut app, 2).await;
    assert_eq!(*p.tasks.missed.lock().unwrap(), [seq]);
    assert_eq!(app.owed_protocol_calls().await.unwrap(), 0);
}

#[tokio::test]
async fn test_retire_protocol_requires_a_compatible_certificate() {
    let p = Pair::new();
    let app = p.join().await;
    let id = app.app_id();
    let before = p.snapshot(&id);
    usage(app.retire_protocol("chat").await, "chat");
    assert_eq!(p.snapshot(&id), before);
    assert_eq!(
        p.load(id).await.unwrap().protocols().names(),
        ["tasks", "chat"]
    );
}

#[tokio::test]
async fn test_retire_protocol_checks_the_kept_certificate_after_reload() {
    let p = Pair::new();
    let mut app = Box::pin(compatible_pair(&p)).await;
    let id = app.app_id();
    let current = app.cert().hash();
    let renewal = renewal_member::cert_put(&p, &app, &["tasks", "chat"]);
    read(&mut app, 2).await;
    drop(app);

    let app = p.load(id).await.unwrap();
    assert_eq!(app.cert().hash(), current);
    assert_eq!(app.kept_renewal(), Some(&renewal));
    let before = p.snapshot(&id);
    usage(app.retire_protocol("chat").await, "chat");
    assert_eq!(p.snapshot(&id), before);
}

#[tokio::test]
async fn test_retire_protocol_commit_reopens_one_complete_roster() {
    for after in [false, true] {
        let p = Pair::new();
        let app = Box::pin(compatible_pair(&p)).await;
        let id = app.app_id();
        drop(app);
        let fault = if after {
            StoreFault::FailAfter(1)
        } else {
            StoreFault::FailBefore(1)
        };
        let store = Arc::new(FaultStore::new(p.store.clone(), fault));
        let app = App::load(p.w.env_on(store), p.set(), World::config(), id)
            .await
            .unwrap();
        assert!(app.retire_protocol("chat").await.is_err());
        let roster = if after {
            ProtocolSet::from(p.tasks.clone())
        } else {
            p.set()
        };
        let app = App::load(p.env(), roster, World::config(), id)
            .await
            .unwrap();
        assert_eq!(app.protocols().contains("chat"), !after);
        assert_eq!(
            AppRecord::verify(app.record(), &app.identity())
                .unwrap()
                .accepts("chat.item"),
            !after
        );
    }
}

#[tokio::test]
async fn test_retire_protocol_waits_for_its_saved_callback() {
    let p = Pair::new();
    let mut app = Box::pin(compatible_pair(&p)).await;
    let id = app.app_id();
    *p.chat.failing_missed.lock().unwrap() = u32::MAX;
    let now = p.w.clock.now_ms();
    let seq = p.w.dispatch.push_missed(1, now, now);
    read(&mut app, 2).await;
    let before = p.snapshot(&id);
    assert!(matches!(app.retire_protocol("chat").await,
        Err(AppError::Refused(Refusal::NotNow(why))) if why.contains("callbacks")));
    assert_eq!(p.snapshot(&id), before);
    let mut app = p.load(id).await.unwrap();
    *p.chat.failing_missed.lock().unwrap() = 0;
    read(&mut app, 2).await;
    assert_eq!(*p.chat.missed.lock().unwrap(), [seq]);
    app.protocol_commit(
        "chat",
        &[LocalWrite::Delete {
            key: format!("missed/{seq}").into_bytes(),
        }],
    )
    .await
    .unwrap();
    app.retire_protocol("chat").await.unwrap();
}

#[tokio::test]
async fn test_retire_protocol_waits_for_its_owner_and_preserves_shared_duty() {
    let p = Pair::new();
    let mut app = Box::pin(compatible_pair(&p)).await;
    let id = app.app_id();
    app.protocol_commit(
        "chat",
        &[LocalWrite::Put {
            key: b"last".to_vec(),
            value: vec![7],
        }],
    )
    .await
    .unwrap();
    app.set_protocol_member("chat", a_member(), None)
        .await
        .unwrap();
    plant_duty(&p, &id, 1, &["tasks", "chat"]);
    for reason in [
        "local state",
        "acknowledge",
        "published protocol member",
        "expiry",
    ] {
        let before = p.snapshot(&id);
        assert!(matches!(app.retire_protocol("chat").await,
            Err(AppError::Refused(Refusal::NotNow(why))) if why.contains(reason)));
        assert_eq!(p.snapshot(&id), before);
        app = p.load(id).await.unwrap();
        match reason {
            "local state" => app
                .protocol_commit(
                    "chat",
                    &[LocalWrite::Delete {
                        key: b"last".to_vec(),
                    }],
                )
                .await
                .unwrap(),
            "acknowledge" => {
                let event = app
                    .unacknowledged_events_for("chat")
                    .await
                    .unwrap()
                    .pop()
                    .unwrap();
                app.ack_events_for("chat", event.id().unwrap())
                    .await
                    .unwrap();
            }
            "published protocol member" => {
                p.w.clock.advance_ms(1);
                app.set_protocol_member("chat", None, None).await.unwrap();
                p.w.clock.advance_ms(1);
                app.renew_record_with_lifetime("chat", Some(120_000))
                    .await
                    .unwrap();
            }
            _ => {
                p.w.clock.advance_ms(1);
                app.renew_record("chat", None).await.unwrap();
            }
        }
    }
    p.w.clock.advance_ms(1);
    app.retire_protocol("chat").await.unwrap();
    let mut app = App::load(p.env(), p.tasks.clone(), World::config(), id)
        .await
        .unwrap();
    assert_eq!(
        app.unacknowledged_events_for("tasks").await.unwrap().len(),
        1
    );
}

#[tokio::test]
async fn test_retire_protocol_waits_for_its_held_record_edit() {
    // A protocol isn't retired over an edit held aside for it: its host submits or clears
    // it first, so nothing held ever names a protocol the app no longer runs.
    let p = Pair::new();
    let mut app = Box::pin(compatible_pair(&p)).await;
    let id = app.app_id();
    p.w.dispatch.fail_next(Fault::Unreachable {
        path: "/feed".into(),
        after: 0,
    });
    app.set_protocol_member("chat", a_member(), None)
        .await
        .unwrap_err();
    drop(app);
    let mut app = App::load(p.env(), p.set(), World::config(), id)
        .await
        .unwrap();
    assert!(app.held_record_edit("chat").await.unwrap().is_some());
    for event in app.take_events() {
        if let Some(event) = event.id() {
            app.ack_events_for("chat", event).await.unwrap();
        }
    }
    let refused = app.retire_protocol("chat").await;
    assert!(
        matches!(&refused, Err(AppError::Refused(Refusal::NotNow(how))) if how.contains("held record edit")),
        "{refused:?}"
    );
    let mut app = App::load(p.env(), p.set(), World::config(), id)
        .await
        .unwrap();
    app.clear_held_record_edit("chat").await.unwrap();
    // Accepted kinds held aside name the retiring protocol's too: they go with it, and
    // the backup taken after it restores.
    let mut tx = app.tx().unwrap();
    tx.put(
        crate::app::state::key::RECORD_HELD_ACCEPTS,
        &vec!["chat.item".to_string(), "tasks.item".to_string()],
    )
    .unwrap();
    app.commit(tx).await.unwrap();
    app.retire_protocol("chat").await.unwrap();
    let mut app = App::load(p.env(), p.tasks.clone(), World::config(), id)
        .await
        .unwrap();
    assert_eq!(
        app.held_accepts().await.unwrap(),
        Some(vec!["tasks.item".to_string()])
    );
    let backup = app.backup().await.unwrap();
    let mut restored = App::restore(
        p.w.env_on(Arc::new(MemoryStore::new()) as Arc<dyn StateStore>),
        p.tasks.clone(),
        World::config(),
        &backup,
    )
    .await
    .unwrap();
    assert_eq!(
        restored.held_accepts().await.unwrap(),
        Some(vec!["tasks.item".to_string()])
    );
}
