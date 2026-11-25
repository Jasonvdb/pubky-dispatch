//! A restored local choice is settled before an older accepted record is repaired.

use super::*;
use crate::app::provider::FRESH_SERVICE_TIME_MS;
use crate::error::TransportError;

enum Reopen {
    Reload,
    FreshRestore,
    RestoreInPlace,
}

enum UnsignedEdit {
    Member,
    Accepts,
}

async fn check_publication_after_reopen(reopen: Reopen, edit: Option<UnsignedEdit>) {
    let w = World::new();
    let protocol = Arc::new(Narrowing::default());
    let request = w.approve(&app_keys("wallet"), &["sample-a"]);
    let mut app = App::join(w.env(), protocol.clone(), publishing(), request)
        .await
        .unwrap();
    let id = app.app_id();
    let accepted = w.held(id).unwrap();
    let earlier = app.backup().await.unwrap();

    w.clock.advance_ms(FRESH_SERVICE_TIME_MS + 1);
    if let Some(edit) = &edit {
        w.switch.fail_next(Fault::Unreachable {
            path: "/feed".into(),
            after: 0,
        });
        let result = match edit {
            UnsignedEdit::Member => {
                app.set_protocol_member(PROTO, member(json!({ "a": 1 })), None)
                    .await
            }
            UnsignedEdit::Accepts => {
                *protocol.only.lock().unwrap() = Some(vec!["sample.note".into()]);
                app.update_accepts().await
            }
        };
        assert!(matches!(
            result,
            Err(AppError::Transport(TransportError::Connect(_)))
        ));
    }

    // Only the fresh store needs the edit in its backup.
    let backup = match reopen {
        Reopen::FreshRestore => app.backup().await.unwrap(),
        _ => earlier,
    };
    drop(app);
    let mut app = match reopen {
        Reopen::Reload => w.load_publishing_on(w.store.clone(), id).await,
        Reopen::FreshRestore => restored_publishing(&w, &backup).await,
        Reopen::RestoreInPlace => App::restore(w.env(), w.protocol.clone(), publishing(), &backup)
            .await
            .unwrap(),
    };
    assert_eq!(
        app.held_record_edit(PROTO).await.unwrap().is_some(),
        matches!(edit, Some(UnsignedEdit::Member))
    );
    assert_eq!(
        app.held_accepts().await.unwrap().is_some(),
        matches!(edit, Some(UnsignedEdit::Accepts))
    );
    assert_eq!(app.record(), &accepted);
    w.homeserver.remove(w.alice.public(), &app_record_path(&id));
    assert!(w.published(id).is_none());
    let writes = w.record_writes(id);

    assert!(!app.receive(None).await.unwrap().stopped);
    if let Some(edit) = edit {
        assert!(w.published(id).is_none());
        assert_eq!(
            app.publish_record().await.unwrap(),
            Publication::AwaitingRecord
        );
        assert!(w.published(id).is_none());
        assert_eq!(w.record_writes(id), writes);
        match edit {
            UnsignedEdit::Member => app.clear_held_record_edit(PROTO).await.unwrap(),
            UnsignedEdit::Accepts => app.clear_held_accepts().await.unwrap(),
        }
    } else {
        assert_eq!(w.published(id), Some(bytes_of(&accepted)));
    }
    assert_eq!(app.publish_record().await.unwrap(), Publication::Published);
    assert_eq!(w.published(id), Some(bytes_of(&accepted)));
    assert_eq!(w.record_writes(id), writes + 1);
}

#[tokio::test]
async fn test_publication_waits_for_a_held_member_edit_after_reload() {
    check_publication_after_reopen(Reopen::Reload, Some(UnsignedEdit::Member)).await;
}

#[tokio::test]
async fn test_publication_waits_for_a_held_member_edit_after_fresh_restore() {
    check_publication_after_reopen(Reopen::FreshRestore, Some(UnsignedEdit::Member)).await;
}

#[tokio::test]
async fn test_publication_waits_for_a_held_member_edit_after_restore_in_place() {
    check_publication_after_reopen(Reopen::RestoreInPlace, Some(UnsignedEdit::Member)).await;
}

#[tokio::test]
async fn test_publication_waits_for_held_accepts_after_reload() {
    check_publication_after_reopen(Reopen::Reload, Some(UnsignedEdit::Accepts)).await;
}

#[tokio::test]
async fn test_publication_waits_for_held_accepts_after_fresh_restore() {
    check_publication_after_reopen(Reopen::FreshRestore, Some(UnsignedEdit::Accepts)).await;
}

#[tokio::test]
async fn test_publication_waits_for_held_accepts_after_restore_in_place() {
    check_publication_after_reopen(Reopen::RestoreInPlace, Some(UnsignedEdit::Accepts)).await;
}

#[tokio::test]
async fn test_publication_repairs_a_missing_copy_without_held_edits() {
    for reopen in [Reopen::Reload, Reopen::FreshRestore, Reopen::RestoreInPlace] {
        check_publication_after_reopen(reopen, None).await;
    }
}

#[tokio::test]
async fn test_own_record_restored_withdrawal_defers_missing_or_older_public_copy() {
    for missing in [false, true] {
        let w = World::new();
        let mut app = w.join_publishing("wallet").await;
        let id = app.app_id();
        let initial = w.published(id).unwrap();
        app.set_protocol_member(PROTO, member(json!({ "a": 1 })), None)
            .await
            .unwrap();
        app.receive(None).await.unwrap();
        let accepted = app.record().clone();
        w.clock.advance_ms(1_000);
        w.switch.fail_next(Fault::Unreachable {
            path: "/ops".into(),
            after: 0,
        });
        app.set_protocol_member(PROTO, None, None)
            .await
            .unwrap_err();
        let withdrawal = app.record().clone();
        let backup = app.backup().await.unwrap();
        drop(app);
        let path = app_record_path(&id);
        let before = if missing { None } else { Some(initial) };
        match &before {
            Some(bytes) => w.homeserver.put(w.alice.public(), &path, bytes.clone()),
            None => w.homeserver.remove(w.alice.public(), &path),
        }
        let writes = w.record_writes(id);
        let mut restored = restored_publishing(&w, &backup).await;
        assert!(!restored.receive(None).await.unwrap().stopped);
        assert_eq!(w.record_writes(id), writes);
        assert_eq!(w.published(id), before);
        assert_eq!(restored.record(), &withdrawal);
        assert_eq!(w.held(id), Some(accepted));
        assert_eq!(
            restored.publish_record().await.unwrap(),
            Publication::AwaitingRecord
        );
        assert_eq!(w.record_writes(id), writes);

        // An unsuccessful reassertion still cannot repair the old offer.
        w.clock.advance_ms(1);
        w.switch.fail_next(Fault::Unreachable {
            path: "/ops".into(),
            after: 0,
        });
        restored
            .set_protocol_member(PROTO, None, None)
            .await
            .unwrap_err();
        assert_eq!(w.record_writes(id), writes);
        assert_eq!(w.published(id), before);
        restored.receive(None).await.unwrap();
        assert_eq!(w.record_writes(id), writes + 1);
        assert!(record_of(&restored).body().protocol(PROTO).is_none());
        assert_eq!(w.held(id).as_ref(), Some(restored.record()));
        assert_eq!(w.published(id), Some(bytes_of(restored.record())));
    }
}

#[tokio::test]
async fn test_own_record_accepted_only_restore_repairs_missing_public_copy() {
    let w = World::new();
    let mut app = w.join_publishing("wallet").await;
    app.set_protocol_member(PROTO, member(json!({ "a": 1 })), None)
        .await
        .unwrap();
    app.receive(None).await.unwrap();
    let id = app.app_id();
    let accepted = app.record().clone();
    let backup = app.backup().await.unwrap();
    drop(app);
    w.homeserver.remove(w.alice.public(), &app_record_path(&id));
    let writes = w.record_writes(id);
    let mut restored = restored_publishing(&w, &backup).await;
    assert!(!restored.receive(None).await.unwrap().stopped);
    assert_eq!(w.record_writes(id), writes + 1);
    assert_eq!(w.published(id), Some(bytes_of(&accepted)));
    assert_eq!(
        restored.publish_record().await.unwrap(),
        Publication::Published
    );
}

#[tokio::test]
async fn test_own_record_restored_exact_feed_acceptance_releases_publication() {
    let w = World::new();
    let mut app = w.join_publishing("wallet").await;
    app.set_protocol_member(PROTO, member(json!({ "a": 1 })), None)
        .await
        .unwrap();
    app.receive(None).await.unwrap();
    let id = app.app_id();
    w.clock.advance_ms(1_000);
    w.switch.fail_next(Fault::LoseAnswer {
        path: "/ops".into(),
    });
    app.set_protocol_member(PROTO, None, None)
        .await
        .unwrap_err();
    let withdrawal = app.record().clone();
    assert_eq!(w.held(id), Some(withdrawal.clone()));
    let backup = app.backup().await.unwrap();
    drop(app);
    w.homeserver.remove(w.alice.public(), &app_record_path(&id));
    let writes = w.record_writes(id);
    let puts = w.app_puts();
    let mut restored = restored_publishing(&w, &backup).await;
    refused_before_read(&mut restored).await;
    assert_eq!(w.record_writes(id), writes);
    restored.receive(None).await.unwrap();
    assert_eq!(restored.record(), &withdrawal);
    assert_eq!(
        w.app_puts(),
        puts,
        "the verified acceptance needs no new signature"
    );
    assert_eq!(w.record_writes(id), writes + 1);
    assert_eq!(w.published(id), Some(bytes_of(&withdrawal)));
    assert_eq!(
        restored.publish_record().await.unwrap(),
        Publication::Published
    );
}

#[tokio::test]
async fn test_own_record_public_copy_releases_only_a_superseded_local_choice() {
    let w = World::new();
    let mut app = w.join_publishing("wallet").await;
    app.receive(None).await.unwrap();
    let initial = app.backup().await.unwrap();
    let id = app.app_id();
    let mut other = restored_publishing(&w, &initial).await;
    other.receive(None).await.unwrap();
    w.clock.advance_ms(1_000);
    other
        .set_protocol_member(PROTO, member(json!({ "a": 1 })), None)
        .await
        .unwrap();
    let intermediate = other.record().clone();
    w.clock.advance_ms(1_000);
    w.switch.fail_next(Fault::Unreachable {
        path: "/ops".into(),
        after: 0,
    });
    app.set_protocol_member(PROTO, member(json!({ "a": 2 })), None)
        .await
        .unwrap_err();
    let desired = app.record().clone();
    let backup = app.backup().await.unwrap();
    drop(app);
    let mut restored = restored_publishing(&w, &backup).await;
    let writes = w.record_writes(id);
    refused_before_read(&mut restored).await;
    restored.receive(None).await.unwrap();
    assert_eq!(
        restored.publish_record().await.unwrap(),
        Publication::AwaitingRecord
    );
    assert_eq!(restored.record(), &desired);
    assert_eq!(w.published(id), Some(bytes_of(&intermediate)));
    assert_eq!(w.record_writes(id), writes);

    // A verified record later than the current choice can actually supersede it.
    w.clock.advance_ms(1_000);
    other
        .set_protocol_member(PROTO, member(json!({ "a": 3 })), None)
        .await
        .unwrap();
    let later = other.record().clone();
    let writes = w.record_writes(id);
    assert_eq!(
        restored.publish_record().await.unwrap(),
        Publication::Superseded
    );
    assert_eq!(restored.record(), &later);
    assert_eq!(w.record_writes(id), writes);
    assert_eq!(w.published(id), Some(bytes_of(&later)));
    w.homeserver.remove(w.alice.public(), &app_record_path(&id));
    assert_eq!(
        restored.publish_record().await.unwrap(),
        Publication::Published
    );
    assert_eq!(w.published(id), Some(bytes_of(&later)));
}

#[tokio::test]
async fn test_own_record_public_copy_matching_unaccepted_choice_does_not_settle_it() {
    let w = World::new();
    let mut app = w.join_publishing("wallet").await;
    w.clock.advance_ms(1_000);
    w.switch.fail_next(Fault::Unreachable {
        path: "/ops".into(),
        after: 0,
    });
    app.set_protocol_member(PROTO, member(json!({ "a": 1 })), None)
        .await
        .unwrap_err();
    let held = app.record().clone();
    let backup = app.backup().await.unwrap();
    drop(app);
    let mut restored = restored_publishing(&w, &backup).await;
    let id = restored.app_id();
    w.homeserver
        .put(w.alice.public(), &app_record_path(&id), bytes_of(&held));
    let writes = w.record_writes(id);
    refused_before_read(&mut restored).await;
    restored.receive(None).await.unwrap();
    assert_eq!(
        restored.publish_record().await.unwrap(),
        Publication::AwaitingRecord
    );
    assert_ne!(w.held(id), Some(held));
    assert_eq!(w.record_writes(id), writes);
    w.homeserver.remove(w.alice.public(), &app_record_path(&id));
    assert_eq!(
        restored.publish_record().await.unwrap(),
        Publication::AwaitingRecord
    );
    assert!(w.published(id).is_none());
}

#[tokio::test]
async fn test_own_record_non_newer_held_bytes_do_not_block_accepted_repair() {
    for equal_time in [false, true] {
        let w = World::new();
        let mut app = w.join_publishing("wallet").await;
        let earlier = record_of(&app);
        w.clock.advance_ms(1_000);
        app.set_protocol_member(PROTO, member(json!({ "a": 1 })), None)
            .await
            .unwrap();
        let accepted = record_of(&app);
        let id = app.app_id();
        let mut backup = app.backup().await.unwrap();
        let mut body = earlier.body().clone();
        if equal_time {
            body.updated_at = accepted.updated_at();
        }
        // Both carried records verify, but different bytes alone are not newer intent.
        backup.record = AppRecord::sign(&app_keys("wallet"), body)
            .unwrap()
            .signed()
            .clone();
        assert_ne!(backup.record, *accepted.signed());
        drop(app);
        w.homeserver.remove(w.alice.public(), &app_record_path(&id));
        let mut restored = restored_publishing(&w, &backup).await;
        refused_before_read(&mut restored).await;
        restored.receive(None).await.unwrap();
        assert_eq!(
            restored.publish_record().await.unwrap(),
            Publication::Published
        );
        assert_eq!(w.published(id), Some(bytes_of(accepted.signed())));
    }
}

#[tokio::test]
async fn test_own_record_restored_choice_waits_for_public_copy_clock_tolerance() {
    use pubky_switch_core::records::CLOCK_TOLERANCE_MS;

    let w = World::new();
    let mut app = w.join_publishing("wallet").await;
    app.set_protocol_member(PROTO, member(json!({ "a": 1 })), None)
        .await
        .unwrap();
    app.receive(None).await.unwrap();
    let initial = app.backup().await.unwrap();
    let mut other = restored_publishing(&w, &initial).await;
    other.receive(None).await.unwrap();
    let id = app.app_id();
    w.clock.advance_ms(1_000);
    w.switch.fail_next(Fault::Unreachable {
        path: "/ops".into(),
        after: 0,
    });
    app.set_protocol_member(PROTO, None, None)
        .await
        .unwrap_err();
    let withdrawal = app.record().clone();
    let backup = app.backup().await.unwrap();
    drop(app);

    // The restored installation reads once, which takes the switch's record as its base.
    let clock = Arc::new(TestClock::new(w.clock.now_ms()));
    let store = Arc::new(MemoryStore::new());
    let env = AppEnv {
        clock: clock.clone(),
        ..w.env_on(store.clone())
    };
    let mut restored = App::restore(env.clone(), w.protocol.clone(), publishing(), &backup)
        .await
        .unwrap();
    refused_before_read(&mut restored).await;
    restored.receive(None).await.unwrap();
    assert_eq!(restored.record(), &withdrawal);

    // Another installation publishes normally, but the restoring device's clock lags.
    w.clock.advance_ms(2 * CLOCK_TOLERANCE_MS);
    other
        .set_protocol_member(PROTO, member(json!({ "a": 2 })), None)
        .await
        .unwrap();
    let later = record_of(&other);
    clock.set_ms(later.updated_at() - CLOCK_TOLERANCE_MS - 1);
    let accepted = restored.state.accepted.clone();
    let policies = restored.record_expiries().await.unwrap();
    let writes = w.record_writes(id);
    assert!(later.is_ahead(clock.now_ms()));
    assert!(!record_of(&restored).is_ahead(clock.now_ms()));
    for reopen in [false, true] {
        if reopen {
            drop(restored);
            restored = App::load(env.clone(), w.protocol.clone(), publishing(), id)
                .await
                .unwrap();
        }
        assert_eq!(
            restored.publish_record().await.unwrap(),
            Publication::AwaitingRecord
        );
        assert_eq!(restored.record(), &withdrawal);
        assert_eq!(restored.state.accepted, accepted);
        assert_eq!(restored.record_expiries().await.unwrap(), policies);
        assert!(restored.state.pending_record.is_none());
        assert!(restored.state.pending_publish.is_none());
        assert_eq!(w.record_writes(id), writes);
        assert_eq!(w.published(id), Some(bytes_of(later.signed())));
    }

    // Exactly five minutes ahead participates; the next ordinary call settles the choice.
    clock.advance_ms(1);
    assert!(!later.is_ahead(clock.now_ms()));
    assert_eq!(
        restored.publish_record().await.unwrap(),
        Publication::Superseded
    );
    assert_eq!(restored.record(), later.signed());
    assert_eq!(restored.state.accepted.as_ref(), Some(later.signed()));
    assert_eq!(w.record_writes(id), writes);
    w.homeserver.remove(w.alice.public(), &app_record_path(&id));
    assert_eq!(
        restored.publish_record().await.unwrap(),
        Publication::Published
    );
    assert_eq!(w.record_writes(id), writes + 1);
    assert_eq!(w.published(id), Some(bytes_of(later.signed())));
}
