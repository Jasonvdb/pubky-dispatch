//! A member and its expiry remain one owner's choice while another owner blocks signing.

use super::*;
use crate::app::{ProtocolRecord, RecordExpiry};
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
    app.set_protocol_member("tasks", member(1), Some(until))
        .await
        .unwrap();
    app.set_protocol_member("chat", member(2), Some(until))
        .await
        .unwrap();
    p.w.clock.advance_ms(2 * DAY_MS);
    app
}

#[tokio::test]
async fn test_record_members_two_lapsed_owners_withdraw_and_replace_after_reopen() {
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
        let id = app.app_id();
        drop(app);
        let mut app = p.load(id).await.unwrap();
        assert!(app.protocol_record(first).await.unwrap().pending);
        let until = p.w.clock.now_ms() + 3 * DAY_MS;
        app.set_protocol_member_with_expiry(second, member(3), RecordExpiry::At(until))
            .await
            .unwrap();
        let signed = record(&app);
        assert!(signed.body().protocol(first).is_none());
        assert_eq!(signed.body().protocol(second), member(3).as_ref());
        assert_eq!(signed.expires_at(), Some(until));
        assert_eq!(p.w.switch.app(&id).record.as_ref(), Some(app.record()));
        assert!(!app.protocol_record(first).await.unwrap().pending);
        assert!(!app.protocol_record(second).await.unwrap().pending);
    }
}

#[tokio::test]
async fn test_record_members_withdraw_before_own_cutoff_survives_sibling_renewal() {
    let p = Pair::new();
    let mut app = Box::pin(p.join()).await;
    let now = p.w.clock.now_ms();
    app.set_protocol_member("tasks", member(1), Some(now + 5 * DAY_MS))
        .await
        .unwrap();
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
async fn test_record_members_pending_replacement_keeps_exact_cutoff_through_reopen() {
    let p = Pair::new();
    let mut app = Box::pin(expired_pair(&p)).await;
    let until = p.w.clock.now_ms() + 3 * DAY_MS;
    usage(
        app.set_protocol_member_with_expiry("tasks", member(4), RecordExpiry::At(until))
            .await,
        "chat",
    );
    assert_eq!(record(&app).body().protocol("tasks"), member(1).as_ref());
    let id = app.app_id();
    drop(app);
    let mut app = p.load(id).await.unwrap();
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

#[tokio::test]
async fn test_record_members_backup_restores_pair_and_refuses_overwriting_live_choice() {
    let p = Pair::new();
    let mut app = Box::pin(expired_pair(&p)).await;
    let old = app.backup().await.unwrap();
    usage(app.set_protocol_member("tasks", None, None).await, "chat");
    let backup = app.backup().await.unwrap();
    let backup = AppBackup::from_bytes(&backup.to_bytes().unwrap()).unwrap();
    let id = app.app_id();
    drop(app);
    assert!(matches!(
        App::restore(p.env(), p.set(), World::config(), &old).await,
        Err(AppError::Refused(Refusal::NotNow(_)))
    ));
    let mut app = p.load(id).await.unwrap();
    assert!(app.protocol_record("tasks").await.unwrap().pending);
    drop(app);
    let mut restored = App::restore(
        p.w.env_on(Arc::new(MemoryStore::new()) as Arc<dyn StateStore>),
        p.set(),
        World::config(),
        &backup,
    )
    .await
    .unwrap();
    assert_eq!(
        restored.protocol_record("tasks").await.unwrap(),
        ProtocolRecord {
            member: None,
            expiry: RecordExpiry::Never,
            pending: true,
        }
    );
    restored.renew_record("chat", None).await.unwrap();
    assert!(record(&restored).body().protocol("tasks").is_none());
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
    app.set_protocol_member("tasks", member(1), Some(until))
        .await
        .unwrap();
    app.set_protocol_member("chat", member(2), Some(until))
        .await
        .unwrap();
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
        assert!(matches!(
            App::restore(p.env(), p.set(), World::config(), &old).await,
            Err(AppError::Refused(Refusal::NotNow(_)))
        ));
        let mut app = p.load(id).await.unwrap();
        assert_eq!(app.record(), &withdrawal);
        assert_eq!(
            app.protocol_record("tasks").await.unwrap().expiry,
            RecordExpiry::Never
        );
        app.renew_record("chat", None).await.unwrap();
        assert!(record(&app).body().protocol("tasks").is_none());
        assert_eq!(p.w.switch.app(&id).record.as_ref(), Some(app.record()));
    }
}

#[tokio::test]
async fn test_record_members_fresh_restore_keeps_pending_offer_without_superseding_evidence() {
    let p = Pair::new();
    let mut app = Box::pin(expired_pair(&p)).await;
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
    assert_eq!(
        restored.protocol_record("tasks").await.unwrap(),
        ProtocolRecord {
            member: member(9),
            expiry: RecordExpiry::At(until),
            pending: true,
        }
    );
    restored.renew_record("chat", None).await.unwrap();
    assert_eq!(
        record(&restored).body().protocol("tasks"),
        member(9).as_ref()
    );
    assert_eq!(record_expiry(&restored), Some(until));
    assert_eq!(
        p.w.switch.app(&restored.app_id()).record.as_ref(),
        Some(restored.record())
    );
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
    for restore in [false, true] {
        let p = Pair::new();
        let mut app = Box::pin(p.join()).await;
        if restore {
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
        if restore {
            usage(
                app.set_protocol_member("tasks", payload_member(low), None)
                    .await,
                "chat",
            );
            let backup = app.backup().await.unwrap();
            drop(app);
            app = App::restore(
                p.w.env_on(Arc::new(MemoryStore::new()) as Arc<dyn StateStore>),
                p.set(),
                World::config(),
                &backup,
            )
            .await
            .unwrap();
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
