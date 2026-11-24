//! A member and its expiry remain one owner's choice while another owner blocks signing.

use super::*;
use crate::app::{HeldRecordEdit, ProtocolRecord, RecordExpiry};
use pubky_switch_core::ops::MAX_OP_BYTES;
use pubky_switch_core::records::DAY_MS;

fn member(value: u64) -> Option<serde_json::Map<String, serde_json::Value>> {
    Some(json!({ "value": value }).as_object().unwrap().clone())
}

fn record(app: &App) -> AppRecord {
    AppRecord::verify(app.record(), &app.identity()).unwrap()
}

async fn expired_pair(p: &Pair) -> App {
    let mut app = Box::pin(p.join()).await;
    let until = p.w.clock.now_ms() + DAY_MS;
    p.w.clock.advance_ms(1);
    app.set_protocol_member("tasks", member(1), Some(until))
        .await
        .unwrap();
    p.w.clock.advance_ms(1);
    app.set_protocol_member("chat", member(2), Some(until))
        .await
        .unwrap();
    p.w.clock.advance_ms(2 * DAY_MS);
    app
}

#[tokio::test]
async fn test_record_members_two_lapsed_owners_withdraw_and_replace() {
    for (first, second) in [("tasks", "chat"), ("chat", "tasks")] {
        let p = Pair::new();
        let mut app = Box::pin(expired_pair(&p)).await;
        let before = app.record().clone();
        usage(app.set_protocol_member(first, None, None).await, second);
        assert_eq!(app.record(), &before);
        assert_eq!(p.w.switch.app(&app.app_id()).record.as_ref(), Some(&before));
        assert_eq!(
            app.protocol_record(first).await.unwrap(),
            ProtocolRecord {
                member: None,
                expiry: RecordExpiry::Never,
                pending: true,
            }
        );
        usage(app.update_accepts().await, second);
        assert_eq!(app.record(), &before);
        assert!(app.protocol_record(first).await.unwrap().pending);
        let until = p.w.clock.now_ms() + 3 * DAY_MS;
        app.set_protocol_member_with_expiry(second, member(3), RecordExpiry::At(until))
            .await
            .unwrap();
        let signed = record(&app);
        assert!(signed.body().protocol(first).is_none());
        assert_eq!(signed.body().protocol(second), member(3).as_ref());
        assert_eq!(signed.expires_at(), Some(until));
        assert_eq!(
            p.w.switch.app(&app.app_id()).record.as_ref(),
            Some(app.record())
        );
        assert!(!app.protocol_record(first).await.unwrap().pending);
        assert!(!app.protocol_record(second).await.unwrap().pending);
    }
}

#[tokio::test]
async fn test_record_members_withdraw_before_own_cutoff_survives_sibling_renewal() {
    let p = Pair::new();
    let mut app = Box::pin(p.join()).await;
    let now = p.w.clock.now_ms();
    p.w.clock.advance_ms(1);
    app.set_protocol_member("tasks", member(1), Some(now + 5 * DAY_MS))
        .await
        .unwrap();
    p.w.clock.advance_ms(1);
    app.set_protocol_member("chat", member(2), Some(now + DAY_MS))
        .await
        .unwrap();
    p.w.clock.advance_ms(2 * DAY_MS);
    usage(
        app.set_protocol_member_with_lifetime("tasks", None, None)
            .await,
        "chat",
    );
    let held = app.record().clone();
    assert!(record(&app).body().protocol("tasks").is_some());
    app.renew_record("chat", None).await.unwrap();
    assert_ne!(app.record(), &held);
    assert!(record(&app).body().protocol("tasks").is_none());
    assert_eq!(record_expiry(&app), None);
}

#[tokio::test]
async fn test_record_members_pending_replacement_keeps_exact_cutoff() {
    let p = Pair::new();
    let mut app = Box::pin(expired_pair(&p)).await;
    let until = p.w.clock.now_ms() + 3 * DAY_MS;
    usage(
        app.set_protocol_member_with_expiry("tasks", member(4), RecordExpiry::At(until))
            .await,
        "chat",
    );
    assert_eq!(record(&app).body().protocol("tasks"), member(1).as_ref());
    assert_eq!(
        app.protocol_record("tasks").await.unwrap(),
        ProtocolRecord {
            member: member(4),
            expiry: RecordExpiry::At(until),
            pending: true,
        }
    );
    p.w.clock.advance_ms(DAY_MS);
    app.set_protocol_member("chat", None, None).await.unwrap();
    assert_eq!(record(&app).body().protocol("tasks"), member(4).as_ref());
    assert_eq!(record_expiry(&app), Some(until));
    p.w.clock.advance_ms(2 * DAY_MS);
    let signed = app.record().clone();
    usage(app.renew_record("chat", None).await, "tasks");
    assert_eq!(app.record(), &signed);
}

#[tokio::test]
async fn test_record_members_lifetime_noop_preserves_pending_pair_and_exact_retry() {
    let p = Pair::new();
    let mut app = Box::pin(expired_pair(&p)).await;
    usage(
        app.set_protocol_member_with_lifetime("tasks", member(5), Some(2 * DAY_MS))
            .await,
        "chat",
    );
    usage(
        app.set_protocol_member_with_lifetime("tasks", member(5), Some(3 * DAY_MS))
            .await,
        "chat",
    );
    assert_eq!(
        app.protocol_record("tasks").await.unwrap().expiry,
        RecordExpiry::Lifetime(2 * DAY_MS)
    );
    p.w.switch.fail_next(Fault::Unreachable {
        path: "/ops".into(),
        after: 0,
    });
    assert!(app.renew_record("chat", None).await.is_err());
    let signed = app.record().clone();
    let pending = app.state.pending_record.as_ref().unwrap().body.clone();
    assert!(!app.protocol_record("tasks").await.unwrap().pending);
    assert_eq!(record(&app).body().protocol("tasks"), member(5).as_ref());
    assert_eq!(
        record_expiry(&app),
        Some(record(&app).updated_at() + 2 * DAY_MS)
    );
    let id = app.app_id();
    drop(app);
    let mut app = p.load(id).await.unwrap();
    assert_eq!(app.state.pending_record.as_ref().unwrap().body, pending);
    app.publish_record().await.unwrap();
    assert_eq!(app.record(), &signed);
    app.set_protocol_member_with_lifetime("tasks", member(5), Some(3 * DAY_MS))
        .await
        .unwrap();
    assert_eq!(app.record(), &signed);
    assert_eq!(
        app.protocol_record("tasks").await.unwrap().expiry,
        RecordExpiry::Lifetime(2 * DAY_MS)
    );
}

fn held(value: Option<u64>, expiry: RecordExpiry) -> Option<HeldRecordEdit> {
    Some(HeldRecordEdit {
        member: value.and_then(member),
        expiry,
        renew: false,
    })
}

#[tokio::test]
async fn test_record_members_restore_holds_unsigned_edits_aside() {
    // A withdrawal waiting for a lapsed sibling isn't forgotten and isn't signed: a restore
    // in place holds the store's aside, a backup carries it and a fresh restore holds it
    // aside too, each telling its protocol, which withdraws again and clears it.
    let p = Pair::new();
    let mut app = Box::pin(expired_pair(&p)).await;
    let old = app.backup().await.unwrap();
    let signed = record(&app).body().protocol("tasks").cloned();
    usage(app.set_protocol_member("tasks", None, None).await, "chat");
    assert!(app.protocol_record("tasks").await.unwrap().pending);
    let backup = app.backup().await.unwrap();
    let backup = AppBackup::from_bytes(&backup.to_bytes().unwrap()).unwrap();
    drop(app);
    let mut in_place = App::restore(p.env(), p.set(), World::config(), &old)
        .await
        .unwrap();
    assert!(!in_place.protocol_record("tasks").await.unwrap().pending);
    assert_eq!(
        in_place.held_record_edit("tasks").await.unwrap(),
        held(None, RecordExpiry::Never)
    );
    assert!(
        in_place
            .unacknowledged_events()
            .await
            .unwrap()
            .iter()
            .any(|e| matches!(e, AppEvent::RecordEditsHeld { protocols, accepts: false, .. } if protocols == &["tasks".to_string()]))
    );
    drop(in_place);
    let mut fresh = App::restore(
        p.w.env_on(Arc::new(MemoryStore::new()) as Arc<dyn StateStore>),
        p.set(),
        World::config(),
        &backup,
    )
    .await
    .unwrap();
    assert!(!fresh.protocol_record("tasks").await.unwrap().pending);
    assert_eq!(
        fresh.held_record_edit("tasks").await.unwrap(),
        held(None, RecordExpiry::Never)
    );
    fresh.receive(None).await.unwrap();
    // `tasks`'s lapsed policy still stands: nothing of its withdrawal is signed until it
    // withdraws again.
    usage(fresh.renew_record("chat", None).await, "tasks");
    assert_eq!(record(&fresh).body().protocol("tasks").cloned(), signed);
    fresh
        .set_protocol_member("tasks", None, None)
        .await
        .unwrap();
    assert!(record(&fresh).body().protocol("tasks").is_none());
    fresh.clear_held_record_edit("tasks").await.unwrap();
    assert_eq!(fresh.held_record_edit("tasks").await.unwrap(), None);
}

#[tokio::test]
async fn test_record_members_invalid_owner_member_and_policy_leave_pair_unchanged() {
    let p = Pair::new();
    let mut app = Box::pin(expired_pair(&p)).await;
    usage(app.set_protocol_member("tasks", None, None).await, "chat");
    let desired = app.protocol_record("tasks").await.unwrap();
    let held = app.record().clone();
    usage(app.protocol_record("foreign").await, "foreign");
    usage(
        app.set_protocol_member_with_expiry(
            "tasks",
            member(8),
            RecordExpiry::At(p.w.clock.now_ms()),
        )
        .await,
        "tasks",
    );
    let huge = Some(
        json!({ "value": "x".repeat(MAX_OP_BYTES) })
            .as_object()
            .unwrap()
            .clone(),
    );
    assert!(app.set_protocol_member("tasks", huge, None).await.is_err());
    let invalid = Some(json!({ "value": 1.5 }).as_object().unwrap().clone());
    assert!(
        app.set_protocol_member("tasks", invalid, None)
            .await
            .is_err()
    );
    assert_eq!(app.protocol_record("tasks").await.unwrap(), desired);
    assert_eq!(app.record(), &held);
    app.renew_record("chat", None).await.unwrap();
    assert!(record(&app).body().protocol("tasks").is_none());
}

#[tokio::test]
async fn test_record_members_conflict_signature_applies_pending_removal() {
    let (other, current, applied) = finish_pending_removal(3).await;
    assert!(current.updated_at() > other.updated_at());
    assert_eq!(applied, 1);
}

#[tokio::test]
async fn test_record_members_identical_removal_keeps_the_applied_record() {
    let (other, current, applied) = finish_pending_removal(2).await;
    assert_eq!(current.signed(), other.signed());
    assert_eq!(applied, 0);
}

async fn finish_pending_removal(other_chat: u64) -> (AppRecord, AppRecord, u64) {
    let p = Pair::new();
    let mut app = Box::pin(p.join()).await;
    let until = p.w.clock.now_ms() + DAY_MS;
    p.w.clock.advance_ms(1);
    app.set_protocol_member("tasks", member(1), Some(until))
        .await
        .unwrap();
    p.w.clock.advance_ms(1);
    app.set_protocol_member("chat", member(2), Some(until))
        .await
        .unwrap();
    p.w.clock.advance_ms(1);
    p.w.switch.fail_next(Fault::Unreachable {
        path: "/ops".into(),
        after: 0,
    });
    assert!(app.renew_record("tasks", Some(until)).await.is_err());
    p.w.clock.advance_ms(2 * DAY_MS);
    usage(app.set_protocol_member("tasks", None, None).await, "chat");
    // Both devices remove tasks. A different chat value makes their signed records
    // distinct even when they use the same clock and expiry.
    let mut later = record(&app).body().clone();
    later.updated_at = p.w.clock.now_ms();
    later.expires_at = None;
    later.protocols.remove("tasks");
    later
        .protocols
        .insert("chat".into(), member(other_chat).unwrap());
    let later = AppRecord::sign(&app_keys("wallet"), later).unwrap();
    p.w.switch
        .app_op(
            &app_keys("wallet"),
            OpKind::AppPut {
                record: later.signed().clone(),
            },
        )
        .unwrap();
    usage(app.publish_record().await, "chat");
    assert!(app.protocol_record("tasks").await.unwrap().pending);
    let before_renewal = p.w.switch.seq();
    app.renew_record("chat", None).await.unwrap();
    let current = record(&app);
    assert!(current.body().protocol("tasks").is_none());
    assert_eq!(current.body().protocol("chat"), member(other_chat).as_ref());
    assert_eq!(
        p.w.switch.app(&app.app_id()).record.as_ref(),
        Some(current.signed())
    );
    assert_eq!(
        app.protocol_record("tasks").await.unwrap(),
        ProtocolRecord {
            member: None,
            expiry: RecordExpiry::Never,
            pending: false
        }
    );
    (later, current, p.w.switch.seq() - before_renewal)
}

#[tokio::test]
async fn test_record_members_backup_refuses_unowned_repeated_or_unpaired_edits() {
    let p = Pair::new();
    let mut app = Box::pin(expired_pair(&p)).await;
    usage(app.set_protocol_member("tasks", None, None).await, "chat");
    let backup = app.backup().await.unwrap();
    let original: serde_json::Value = serde_json::from_slice(&backup.to_bytes().unwrap()).unwrap();
    for kind in 0..3 {
        let mut edited = original.clone();
        match kind {
            0 => edited["record_members"][0][0] = json!("foreign"),
            1 => {
                let entry = edited["record_members"][0].clone();
                edited["record_members"].as_array_mut().unwrap().push(entry);
            }
            _ => edited["record_expiries"] = json!([]),
        }
        let backup = AppBackup::from_bytes(&serde_json::to_vec(&edited).unwrap()).unwrap();
        let store = Arc::new(MemoryStore::new());
        assert!(matches!(
            App::restore(
                p.w.env_on(store.clone() as Arc<dyn StateStore>),
                p.set(),
                World::config(),
                &backup,
            )
            .await,
            Err(AppError::InvalidData(_))
        ));
        assert!(store.is_empty(&crate::store::client_namespace(&app.app_id())));
    }
}

#[tokio::test]
async fn test_record_members_restore_cannot_reoffer_after_newer_signed_withdrawal() {
    for delivered in [false, true] {
        let p = Pair::new();
        let mut app = Box::pin(expired_pair(&p)).await;
        let until = p.w.clock.now_ms() + 3 * DAY_MS;
        usage(
            app.set_protocol_member_with_expiry("tasks", member(9), RecordExpiry::At(until))
                .await,
            "chat",
        );
        let old = app.backup().await.unwrap();
        usage(app.set_protocol_member("tasks", None, None).await, "chat");
        if !delivered {
            p.w.switch.fail_next(Fault::Unreachable {
                path: "/ops".into(),
                after: 0,
            });
        }
        let renewed = app.renew_record("chat", None).await;
        assert_eq!(renewed.is_ok(), delivered);
        let withdrawal = app.record().clone();
        assert!(record(&app).body().protocol("tasks").is_none());
        assert!(!app.protocol_record("tasks").await.unwrap().pending);
        if delivered {
            assert_eq!(
                p.w.switch.app(&app.app_id()).record.as_ref(),
                Some(&withdrawal)
            );
        } else {
            assert_ne!(
                p.w.switch.app(&app.app_id()).record.as_ref(),
                Some(&withdrawal)
            );
        }
        let id = app.app_id();
        drop(app);
        // The backup's offer is held aside, and the store's newer withdrawal is the base.
        let mut app = App::restore(p.env(), p.set(), World::config(), &old)
            .await
            .unwrap();
        assert_eq!(app.record(), &withdrawal);
        assert!(!app.protocol_record("tasks").await.unwrap().pending);
        assert_eq!(
            app.held_record_edit("tasks").await.unwrap(),
            held(Some(9), RecordExpiry::At(until))
        );
        app.end_reconcile(UserConfirmed::new()).await.ok();
        app.receive(None).await.unwrap();
        assert_eq!(
            app.protocol_record("tasks").await.unwrap().expiry,
            RecordExpiry::Never
        );
        p.w.clock.advance_ms(1);
        app.renew_record("chat", None).await.unwrap();
        assert!(record(&app).body().protocol("tasks").is_none());
        assert_eq!(p.w.switch.app(&id).record.as_ref(), Some(app.record()));
    }
}

#[tokio::test]
async fn test_record_members_fresh_restore_holds_the_backups_offer_aside() {
    // An offer waiting for a lapsed sibling when the backup was taken is carried, held
    // aside by the restore and signed by nothing until its protocol offers it again.
    let p = Pair::new();
    let mut app = Box::pin(expired_pair(&p)).await;
    let signed = record(&app).body().protocol("tasks").cloned();
    let until = p.w.clock.now_ms() + 3 * DAY_MS;
    usage(
        app.set_protocol_member_with_expiry("tasks", member(9), RecordExpiry::At(until))
            .await,
        "chat",
    );
    let backup = app.backup().await.unwrap();
    drop(app);
    let mut restored = App::restore(
        p.w.env_on(Arc::new(MemoryStore::new()) as Arc<dyn StateStore>),
        p.set(),
        World::config(),
        &backup,
    )
    .await
    .unwrap();
    assert!(!restored.protocol_record("tasks").await.unwrap().pending);
    let offer = restored.held_record_edit("tasks").await.unwrap().unwrap();
    assert_eq!(Some(offer.clone()), held(Some(9), RecordExpiry::At(until)));
    // The policy in force is the signed one, not the one the offer asked; a backup of the
    // restored app carries the held offer on, and a restore of it holds both the same.
    let policy = restored.protocol_record("tasks").await.unwrap().expiry;
    assert_ne!(policy, RecordExpiry::At(until));
    let again = restored.backup().await.unwrap();
    let mut second = App::restore(
        p.w.env_on(Arc::new(MemoryStore::new()) as Arc<dyn StateStore>),
        p.set(),
        World::config(),
        &again,
    )
    .await
    .unwrap();
    assert_eq!(
        second.held_record_edit("tasks").await.unwrap(),
        Some(offer.clone())
    );
    assert_eq!(
        second.protocol_record("tasks").await.unwrap().expiry,
        policy
    );
    drop(second);
    restored.receive(None).await.unwrap();
    usage(restored.renew_record("chat", None).await, "tasks");
    assert_eq!(record(&restored).body().protocol("tasks").cloned(), signed);
    // Offered again in this run, it is signed, and cleared.
    restored
        .set_protocol_member_with_expiry("tasks", offer.member.clone(), offer.expiry)
        .await
        .unwrap();
    assert_eq!(
        record(&restored).body().protocol("tasks"),
        member(9).as_ref()
    );
    assert_eq!(record_expiry(&restored), Some(until));
    assert_eq!(
        p.w.switch.app(&restored.app_id()).record.as_ref(),
        Some(restored.record())
    );
    restored.clear_held_record_edit("tasks").await.unwrap();
    assert_eq!(restored.held_record_edit("tasks").await.unwrap(), None);
}

fn payload_member(bytes: usize) -> Option<serde_json::Map<String, serde_json::Value>> {
    Some(
        json!({ "payload": "x".repeat(bytes) })
            .as_object()
            .unwrap()
            .clone(),
    )
}

fn record_fits(app: &App, bytes: usize, at: u64, expires_at: Option<u64>) -> bool {
    let mut body = record(app).body().clone();
    body.protocols
        .insert("tasks".into(), payload_member(bytes).unwrap());
    body.updated_at = at;
    body.expires_at = expires_at;
    let signed = AppRecord::sign(&app_keys("wallet"), body).unwrap();
    app.record_batch(signed.signed()).is_ok()
}

#[tokio::test]
async fn test_record_members_size_uses_actual_null_or_finite_expiry() {
    for pending in [false, true] {
        let p = Pair::new();
        let mut app = Box::pin(p.join()).await;
        p.w.clock.advance_ms(1);
        if pending {
            app.renew_record("chat", Some(p.w.clock.now_ms() + DAY_MS))
                .await
                .unwrap();
            p.w.clock.advance_ms(2 * DAY_MS);
        }
        let at = (record(&app).updated_at() + 1).max(p.w.clock.now_ms());
        let until = at + DAY_MS;
        // Find the real signed-operation boundary using the core batch constructor,
        // not the client's unsigned precheck. Only the expiry distinguishes the forms.
        let mut low = 0;
        let mut high = MAX_OP_BYTES;
        while low < high {
            let middle = low + (high - low).div_ceil(2);
            if record_fits(&app, middle, at, None) {
                low = middle;
            } else {
                high = middle - 1;
            }
        }
        assert!(record_fits(&app, low, at, None));
        assert!(!record_fits(&app, low + 1, at, None));
        assert!(!record_fits(&app, low, at, Some(until)));
        if pending {
            usage(
                app.set_protocol_member("tasks", payload_member(low), None)
                    .await,
                "chat",
            );
            let held = app.record().clone();
            let draft = app.protocol_record("tasks").await.unwrap();
            let policies = app.record_expiries().await.unwrap();
            let delivered = p.w.switch.app(&app.app_id()).record;
            assert!(draft.pending);
            usage(app.renew_record("chat", Some(until)).await, "operation");
            assert_eq!(app.record(), &held);
            assert_eq!(app.protocol_record("tasks").await.unwrap(), draft);
            assert_eq!(app.record_expiries().await.unwrap(), policies);
            assert_eq!(p.w.switch.app(&app.app_id()).record, delivered);
            assert!(app.state.pending_record.is_none());
            app.renew_record("chat", None).await.unwrap();
            assert!(!app.protocol_record("tasks").await.unwrap().pending);
        } else {
            app.set_protocol_member("tasks", payload_member(low), None)
                .await
                .unwrap();
        }
        let null_record = app.record().clone();
        assert_eq!(record_expiry(&app), None);
        assert_eq!(
            p.w.switch.app(&app.app_id()).record.as_ref(),
            Some(&null_record)
        );
        p.w.clock.advance_ms(1);
        assert!(
            app.set_protocol_member("tasks", payload_member(low), Some(until))
                .await
                .is_err()
        );
        assert_eq!(app.record(), &null_record);
        assert_eq!(
            app.protocol_record("tasks").await.unwrap().expiry,
            RecordExpiry::Never
        );
        assert!(record_fits(&app, low - 64, at + 1, Some(until)));
        app.set_protocol_member("tasks", payload_member(low - 64), Some(until))
            .await
            .unwrap();
        assert_eq!(record_expiry(&app), Some(until));
        assert_eq!(
            p.w.switch.app(&app.app_id()).record.as_ref(),
            Some(app.record())
        );
    }
}

#[tokio::test]
async fn test_record_members_pending_withdrawal_defers_accepted_repair_until_signed() {
    use crate::app::Publication;
    use pubky_switch_core::records::app_record_path;

    for owed in [false, true] {
        let p = Pair::new();
        let config = AppConfig {
            publishes_record: true,
            ..World::config()
        };
        let mut app = App::join(p.env(), p.set(), config.clone(), p.approve("wallet", &[]))
            .await
            .unwrap();
        let now = p.w.clock.now_ms();
        p.w.clock.advance_ms(1);
        app.set_protocol_member("tasks", member(1), Some(now + 5 * DAY_MS))
            .await
            .unwrap();
        if owed {
            p.w.homeserver.fail_writes(1, false);
        }
        p.w.clock.advance_ms(1);
        let publication = app
            .set_protocol_member("chat", member(2), Some(now + DAY_MS))
            .await
            .unwrap();
        assert_eq!(matches!(publication, Publication::Owed { .. }), owed);
        let pending_publish = app.state.pending_publish.clone();
        p.w.clock.advance_ms(2 * DAY_MS);
        usage(app.set_protocol_member("tasks", None, None).await, "chat");
        let id = app.app_id();
        let path = app_record_path(&id);
        let writes = p.w.homeserver.writes(&p.w.alice.public(), &path);
        assert_eq!(
            app.publish_record().await.unwrap(),
            Publication::AwaitingRecord
        );
        assert_eq!(app.state.pending_publish, pending_publish);
        assert_eq!(p.w.homeserver.writes(&p.w.alice.public(), &path), writes);
        assert_eq!(
            app.renew_record("chat", None).await.unwrap(),
            Publication::Published
        );
        assert!(record(&app).body().protocol("tasks").is_none());
        assert!(!app.protocol_record("tasks").await.unwrap().pending);
        assert_eq!(
            p.w.homeserver.writes(&p.w.alice.public(), &path),
            writes + 1
        );
        assert_eq!(
            p.w.homeserver.file(p.w.alice.public(), &path),
            Some(serde_json::to_vec(app.record()).unwrap())
        );
    }
}

#[tokio::test]
async fn test_record_members_fresh_restore_keeps_a_withdrawal_made_after_the_backup() {
    // An offer saved unsigned when the backup was taken, then withdrawn online: the app
    // restored on a fresh store signs nothing of the offer, and holds the withdrawal.
    let p = Pair::new();
    let mut app = Box::pin(p.join()).await;
    let id = app.app_id();
    p.w.clock.advance_ms(1);
    app.set_protocol_member("tasks", member(1), None)
        .await
        .unwrap();
    p.w.clock.advance_ms(1);
    p.w.switch.fail_next(Fault::Unreachable {
        path: "/feed".into(),
        after: 0,
    });
    app.set_protocol_member("tasks", member(9), None)
        .await
        .unwrap_err();
    assert!(app.protocol_record("tasks").await.unwrap().pending);
    let backup = app.backup().await.unwrap();
    p.w.clock.advance_ms(1);
    app.set_protocol_member("tasks", None, None).await.unwrap();
    let withdrawal = app.record().clone();
    drop(app);

    let mut restored = App::restore(
        p.w.env_on(Arc::new(MemoryStore::new()) as Arc<dyn StateStore>),
        p.set(),
        World::config(),
        &backup,
    )
    .await
    .unwrap();
    p.w.clock.advance_ms(1);
    restored.receive(None).await.unwrap();
    assert_eq!(p.w.switch.app(&id).record.as_ref(), Some(&withdrawal));
    assert_eq!(restored.record(), &withdrawal);
    assert_eq!(
        restored.held_record_edit("tasks").await.unwrap(),
        held(Some(9), RecordExpiry::Never)
    );
}

#[tokio::test]
async fn test_record_members_restored_app_signs_on_the_record_published_since() {
    // Another device of the app withdrew `tasks` after the backup. The restored app, on a
    // fresh store or in place, is offline at first: until its first read succeeds a change
    // is refused, saying how to go on, and nothing is kept; submitted again after the
    // read, it is signed on the record published since, so the withdrawal stands.
    for in_place in [false, true] {
        let p = Pair::new();
        let mut app = Box::pin(p.join()).await;
        let id = app.app_id();
        app.set_multi_device(true).await.unwrap();
        for (name, value) in [("tasks", 1), ("chat", 2)] {
            p.w.clock.advance_ms(1);
            app.set_protocol_member(name, member(value), None)
                .await
                .unwrap();
        }
        let backup = app.backup().await.unwrap();
        drop(app);
        let fresh = || {
            p.w.env_on(Arc::new(MemoryStore::new()) as Arc<dyn StateStore>)
        };
        let mut other = App::restore(fresh(), p.set(), World::config(), &backup)
            .await
            .unwrap();
        other.receive(None).await.unwrap();
        p.w.clock.advance_ms(1);
        other
            .set_protocol_member("tasks", None, None)
            .await
            .unwrap();
        let withdrawal = other.record().clone();
        drop(other);

        let env = if in_place { p.env() } else { fresh() };
        let mut restored = App::restore(env, p.set(), World::config(), &backup)
            .await
            .unwrap();
        p.w.clock.advance_ms(1);
        p.w.switch.fail_next(Fault::Unreachable {
            path: "/".into(),
            after: 0,
        });
        restored.receive(None).await.unwrap_err();
        let refused = restored.set_protocol_member("chat", member(3), None).await;
        assert!(
            matches!(&refused, Err(AppError::Refused(Refusal::NotNow(how))) if how.contains("receive")),
            "{refused:?}"
        );
        assert!(!restored.protocol_record("chat").await.unwrap().pending);
        assert_eq!(p.w.switch.app(&id).record.as_ref(), Some(&withdrawal));
        // The directory answers and the feed doesn't: the base is the directory's record.
        p.w.switch.fail_next(Fault::Unreachable {
            path: "/feed".into(),
            after: 0,
        });
        restored.receive(None).await.unwrap_err();
        assert_eq!(restored.record(), &withdrawal, "in place: {in_place}");
        restored
            .set_protocol_member("chat", member(3), None)
            .await
            .unwrap();
        let held = p.w.switch.app(&id).record.unwrap();
        let held = AppRecord::verify(&held, &restored.identity()).unwrap();
        assert!(held.body().protocol("tasks").is_none());
        assert_eq!(held.body().protocol("chat"), member(3).as_ref());
        assert_eq!(restored.record(), held.signed());
    }
}

#[tokio::test]
async fn test_record_members_backup_with_a_held_and_a_pending_edit_restores_both_held() {
    // An edit held aside and another protocol's pending one, each within the size of a
    // record and together over it: the backup carries both, and its restore holds both.
    let p = Pair::new();
    let mut app = Box::pin(p.join()).await;
    let id = app.app_id();
    let big = MAX_OP_BYTES * 3 / 8;
    for name in ["tasks", "chat"] {
        p.w.clock.advance_ms(1);
        p.w.switch.fail_next(Fault::Unreachable {
            path: "/feed".into(),
            after: 0,
        });
        app.set_protocol_member(name, payload_member(big), None)
            .await
            .unwrap_err();
        if name == "tasks" {
            drop(app);
            app = p.load(id).await.unwrap();
        }
    }
    assert!(app.held_record_edit("tasks").await.unwrap().is_some());
    assert!(app.protocol_record("chat").await.unwrap().pending);
    let backup = app.backup().await.unwrap();
    let backup = AppBackup::from_bytes(&backup.to_bytes().unwrap()).unwrap();
    let mut restored = App::restore(
        p.w.env_on(Arc::new(MemoryStore::new()) as Arc<dyn StateStore>),
        p.set(),
        World::config(),
        &backup,
    )
    .await
    .unwrap();
    for name in ["tasks", "chat"] {
        let edit = restored.held_record_edit(name).await.unwrap().unwrap();
        assert_eq!(edit.member, payload_member(big));
        assert!(!restored.protocol_record(name).await.unwrap().pending);
    }
}
