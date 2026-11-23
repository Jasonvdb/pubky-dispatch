//! Duty events a backup carries across a restore (Switch spec 12.4 "Notices owed to the
//! protocol").

use std::sync::Arc;

use pubky_switch_core::ops::RecordVersion;

use super::*;
use crate::app::events::{CertificateRefusal, ClaimAttempt, Duty, KeptRefusal};
use crate::app::records::DeleteBase;
use crate::app::state::key;
use crate::app::{AppBackup, AppError, AppEvent, ParkReason};

/// One duty event of every kind a backup carries.
fn carried_duties() -> Vec<Duty> {
    let delete = DeleteBase {
        version: RecordVersion::new(1, 4),
        item_hash: [4; 32],
    };
    vec![
        Duty::Parked {
            seq: 3,
            stored_id: 7,
            reason: ParkReason::Refused,
        },
        Duty::EffectRefused {
            seq: 3,
            stored_id: 7,
            sender: [1; 32],
            msg_id: "refused".into(),
            kind: "sample.note".into(),
            code: Some("permission_missing".into()),
        },
        Duty::EffectUncertain {
            seq: 5,
            stored_id: 8,
            sender: [1; 32],
            msg_id: "uncertain".into(),
            kind: "sample.note".into(),
            attempts: vec![ClaimAttempt {
                claim_key: [2; 32],
                attempt_id: [3; 16],
            }],
        },
        Duty::ReleasedDuplicate {
            seq: 6,
            stored_id: 9,
            sender: [1; 32],
            msg_id: "released".into(),
            conflicting: false,
        },
        Duty::KeptBatchDropped { batch_id: [5; 16] },
        Duty::BatchRefused {
            batch_id: [6; 16],
            code: "too_large".into(),
        },
        Duty::AttemptDropped {
            claim_key: [2; 32],
            attempt_id: [3; 16],
        },
        Duty::MessageUndelivered {
            msg_id: "undelivered".into(),
            resend: false,
        },
        Duty::DeliveryUnknown {
            msg_id: "unknown".into(),
        },
        Duty::RecordJobDropped {
            msg_id: "job-dropped".into(),
            batch_id: None,
        },
        Duty::PutBackWaits {
            key: [7; 32],
            delete,
        },
        Duty::PutBackRefused {
            key: [8; 32],
            delete,
            reason: "left".into(),
            batch_id: None,
        },
        Duty::RecordJobStopped {
            msg_id: "job-stopped".into(),
            key: [9; 32],
            generation: 1,
            version: 4,
            item_hash: [4; 32],
            batch_id: None,
        },
        Duty::LocalWritesRefused {
            call: KeptRefusal::Owed {
                seq: 4,
                call: crate::app::feed::OwedCall::Resend {
                    sender: [1; 32],
                    accepted_from_ms: 1,
                    accepted_until_ms: 2,
                    unreadable: false,
                },
            },
        },
        Duty::LocalWritesRefused {
            call: KeptRefusal::Loss {
                lost_generation: 1,
                generation: 2,
                declared_at_ms: 10,
                accepted_from_ms: 5,
                uncertain_until_ms: 20,
            },
        },
        Duty::RecordUncheckable {
            key: [10; 32],
            writer: [11; 16],
            generation: 1,
            version: 2,
            mark_bytes: 9_000,
        },
        Duty::SeenMarkLeftOut {
            key: [13; 32],
            mark_bytes: 9_000,
        },
        Duty::SeenMarksLeftOut { records: 3 },
        Duty::RestoreLeftBehind {
            duty_events: 1,
            owed_calls: 0,
        },
        Duty::RecordDivergent { key: [12; 32] },
        Duty::CertificateRefused {
            issued_at: 1,
            refusal: CertificateRefusal::UnownedRoot("other".into()),
        },
        Duty::MemberChanged {
            protocol: "sample".into(),
        },
        Duty::ListsUnverified {
            kept: 1,
            replies: 0,
            contributed: true,
            left_out: crate::app::ListsLeftOut::Nothing,
        },
    ]
}

/// Each kind by its place. A new kind fails to compile here until it is given a number;
/// widening the range below to it then fails the test until a list places it.
/// (`StoredEntryDropped` travels with its custody instead.)
fn kind(duty: &Duty) -> u8 {
    match duty {
        Duty::RecoveryRequired { .. } => 0,
        Duty::RecoveryNoticeCleared { .. } => 1,
        Duty::Parked { .. } => 2,
        Duty::EffectRefused { .. } => 3,
        Duty::EffectUncertain { .. } => 4,
        Duty::ReleasedDuplicate { .. } => 5,
        Duty::StoredEntryDropped { .. } => 6,
        Duty::KeptBatchDropped { .. } => 7,
        Duty::BatchRefused { .. } => 8,
        Duty::AttemptDropped { .. } => 9,
        Duty::MessageUndelivered { .. } => 10,
        Duty::DeliveryUnknown { .. } => 11,
        Duty::RecordJobDropped { .. } => 12,
        Duty::PutBackWaits { .. } => 13,
        Duty::PutBackRefused { .. } => 14,
        Duty::RecordJobStopped { .. } => 15,
        Duty::LocalWritesRefused { .. } => 16,
        Duty::RecordUncheckable { .. } => 17,
        Duty::RestoreLeftBehind { .. } => 18,
        Duty::AccountGone => 19,
        Duty::RecordDivergent { .. } => 20,
        Duty::CertificateRefused { .. } => 21,
        Duty::MemberChanged { .. } => 22,
        Duty::ListsUnverified { .. } => 23,
        Duty::SeenMarkLeftOut { .. } => 24,
        Duty::SeenMarksLeftOut { .. } => 25,
    }
}

#[test]
fn test_restore_duties_lists_place_every_kind() {
    let placed: std::collections::BTreeSet<u8> = carried_duties()
        .iter()
        .chain(own_duties().iter())
        .map(kind)
        .collect();
    let every: std::collections::BTreeSet<u8> = (0..=25).filter(|n| *n != 6).collect();
    assert_eq!(placed, every);
}

/// One duty event of every kind a backup leaves out: the installation's own standing at
/// its service, and a deny list gap's refused writes.
fn own_duties() -> Vec<Duty> {
    vec![
        Duty::RecoveryRequired {
            notice: crate::app::RecoveryNotice {
                generation: 1,
                reason: None,
                permanent: false,
                first_seen_ms: 1,
                service_time_ms: 1,
            },
        },
        Duty::RecoveryNoticeCleared { generation: 1 },
        Duty::AccountGone,
        Duty::LocalWritesRefused {
            call: KeptRefusal::DenyGap {
                generation: 1,
                seq: 2,
            },
        },
    ]
}

async fn keep(app: &mut App, duties: Vec<Duty>) {
    let to = app.protocols.names();
    let mut tx = app.tx().unwrap();
    for duty in duties {
        app.keep_duty_for(&mut tx, to.clone(), duty).unwrap();
    }
    app.commit(tx).await.unwrap();
}

async fn kept(app: &App) -> Vec<Duty> {
    app.reader()
        .scan::<crate::app::events::KeptDuty>(key::DUTY_PREFIX)
        .await
        .unwrap()
        .into_iter()
        .map(|(_, kept)| kept.duty)
        .collect()
}

fn fresh(w: &World) -> crate::app::AppEnv {
    w.env_on(Arc::new(MemoryStore::new()) as Arc<dyn StateStore>)
}

async fn restore_fresh(w: &World, backup: &AppBackup) -> App {
    App::restore(fresh(w), w.protocol.clone(), World::config(), backup)
        .await
        .unwrap()
}

/// The backup's bytes with `edit` applied to their JSON.
fn edited(backup: &AppBackup, edit: impl FnOnce(&mut serde_json::Value)) -> Vec<u8> {
    let mut value: serde_json::Value = serde_json::from_slice(&backup.to_bytes().unwrap()).unwrap();
    edit(&mut value);
    serde_json::to_vec(&value).unwrap()
}

#[tokio::test]
async fn test_restore_duties_fresh_store_tells_every_carried_kind_once() {
    let w = World::new();
    let mut app = w.join("wallet").await;
    keep(&mut app, carried_duties()).await;
    keep(&mut app, own_duties()).await;
    let mut tx = app.tx().unwrap();
    tx.put(key::CERT_REFUSED, &pubky_switch_core::enc::b64(&[13; 32]))
        .unwrap();
    app.commit(tx).await.unwrap();
    for backup in [
        app.backup().await.unwrap(),
        app.backup_layered().await.unwrap(),
    ] {
        let mut restored = restore_fresh(&w, &backup).await;
        assert_eq!(kept(&restored).await, carried_duties());
        // Each is a duty event of the new store, delivered and acknowledged there.
        let events = restored.unacknowledged_events().await.unwrap();
        assert_eq!(events.len(), carried_duties().len());
        let epoch = restored.state.duty_epoch.epoch;
        for event in &events {
            assert_eq!(event.id().unwrap().epoch(), epoch);
        }
        restored
            .ack_events(events.last().and_then(AppEvent::id).unwrap())
            .await
            .unwrap();
        assert!(restored.unacknowledged_events().await.unwrap().is_empty());
        // The refused certificate goes with its event.
        assert_eq!(
            restored
                .reader()
                .get::<String>(key::CERT_REFUSED)
                .await
                .unwrap(),
            Some(pubky_switch_core::enc::b64(&[13; 32]))
        );
    }
}

#[tokio::test]
async fn test_restore_duties_leave_out_the_installation_own_standing() {
    let w = World::new();
    let mut app = w.join("wallet").await;
    keep(&mut app, own_duties()).await;
    let backup = app.backup().await.unwrap();
    assert!(backup.duties.is_empty());
    let restored = restore_fresh(&w, &backup).await;
    assert!(kept(&restored).await.is_empty());
}

#[tokio::test]
async fn test_restore_duties_refuse_a_backup_carrying_an_own_standing_duty() {
    let w = World::new();
    let mut app = w.join("wallet").await;
    keep(&mut app, vec![Duty::AccountGone]).await;
    let mut backup = app.backup().await.unwrap();
    let to = app.protocols.names();
    for duty in own_duties() {
        backup.duties = vec![crate::app::events::KeptDuty {
            to: to.clone(),
            duty,
        }];
        let refused = App::restore(fresh(&w), w.protocol.clone(), World::config(), &backup).await;
        assert!(
            matches!(refused, Err(AppError::InvalidData(ref why)) if why.contains("installation's own")),
            "{:?}",
            refused.err()
        );
    }
}

#[tokio::test]
async fn test_restore_duties_refuse_a_backup_without_its_duties() {
    let w = World::new();
    let app = w.join("wallet").await;
    let backup = app.backup().await.unwrap();
    for member in ["duties", "duties_left_behind"] {
        let bytes = edited(&backup, |value| {
            value.as_object_mut().unwrap().remove(member);
        });
        assert!(AppBackup::from_bytes(&bytes).is_err(), "{member}");
    }
    assert!(AppBackup::from_bytes(&backup.to_bytes().unwrap()).is_ok());
}

#[tokio::test]
async fn test_restore_duties_count_what_does_not_read_or_has_no_owner() {
    let w = World::new();
    let mut app = w.join("wallet").await;
    keep(
        &mut app,
        vec![Duty::DeliveryUnknown {
            msg_id: "kept".into(),
        }],
    )
    .await;
    let damaged = app.state.next_duty;
    let mut tx = app.tx().unwrap();
    tx.put(
        &key::duty(damaged),
        &serde_json::json!({"to": ["sample"], "duty": {"PutBackRefused": {}}}),
    )
    .unwrap();
    app.commit(tx).await.unwrap();
    let backup = app.backup().await.unwrap();
    assert_eq!(backup.duties_left_behind, 1);
    // One more, for a protocol the restored app doesn't register.
    let mut backup = backup;
    backup.duties.push(crate::app::events::KeptDuty {
        to: vec!["retired".into()],
        duty: Duty::MemberChanged {
            protocol: "retired".into(),
        },
    });
    let restored = restore_fresh(&w, &backup).await;
    let told = kept(&restored).await;
    assert!(told.contains(&Duty::DeliveryUnknown {
        msg_id: "kept".into()
    }));
    assert!(told.contains(&Duty::RestoreLeftBehind {
        duty_events: 2,
        owed_calls: 0,
    }));
    assert!(
        !told
            .iter()
            .any(|duty| matches!(duty, Duty::MemberChanged { .. }))
    );
}

#[tokio::test]
async fn test_restore_duties_repeated_give_up_does_not_refuse_the_backup() {
    // The same give-up held twice is no fault of a backup: it is taken and restored, each
    // copy told, delivery being at least once.
    let w = World::new();
    let mut app = w.join("wallet").await;
    let twice = Duty::DeliveryUnknown {
        msg_id: "twice".into(),
    };
    keep(&mut app, vec![twice.clone(), twice.clone()]).await;
    let backup = app.backup().await.unwrap();
    let restored = restore_fresh(&w, &backup).await;
    let told = kept(&restored).await;
    assert_eq!(told.iter().filter(|duty| **duty == twice).count(), 2);
}

#[tokio::test]
async fn test_restore_duties_refuse_a_duty_with_no_owner_or_one_twice() {
    let w = World::new();
    let mut app = w.join("wallet").await;
    keep(&mut app, vec![Duty::DeliveryUnknown { msg_id: "x".into() }]).await;
    let backup = app.backup().await.unwrap();
    let name = backup.duties[0].to[0].clone();
    for to in [Vec::new(), vec![name.clone(), name]] {
        let mut edited = backup.clone();
        edited.duties[0].to = to;
        let refused = App::restore(fresh(&w), w.protocol.clone(), World::config(), &edited).await;
        assert!(
            matches!(refused, Err(AppError::InvalidData(ref why)) if why.contains("no owner")),
            "{:?}",
            refused.err()
        );
    }
}

#[tokio::test]
async fn test_restore_duties_named_stored_ids_are_never_given_out_again() {
    // A carried duty naming a local ID past the backup's counter keeps the restored store
    // from giving that ID out again.
    let w = World::new();
    let mut app = w.join("wallet").await;
    keep(
        &mut app,
        vec![Duty::Parked {
            seq: 3,
            stored_id: 900,
            reason: ParkReason::Refused,
        }],
    )
    .await;
    let backup = app.backup().await.unwrap();
    assert!(backup.stored_next <= 900);
    let restored = restore_fresh(&w, &backup).await;
    assert!(restored.state.next_stored_id > 900);
}

#[tokio::test]
async fn test_restore_duties_entry_not_carried_reads_as_none() {
    // A plain backup carries only entries that wait: an event naming an entry stored for
    // good comes back without it, and the entry reads as none.
    let w = World::new();
    let mut app = w.join("wallet").await;
    keep(
        &mut app,
        vec![Duty::EffectUncertain {
            seq: 5,
            stored_id: 8,
            sender: [1; 32],
            msg_id: "uncertain".into(),
            kind: "sample.note".into(),
            attempts: Vec::new(),
        }],
    )
    .await;
    let backup = app.backup().await.unwrap();
    let mut restored = restore_fresh(&w, &backup).await;
    let events = restored.unacknowledged_events().await.unwrap();
    assert!(
        events
            .iter()
            .any(|e| matches!(e, AppEvent::EffectUncertain { stored_id: 8, .. })),
        "{events:?}"
    );
    assert!(restored.parked_entry(8).await.unwrap().is_none());
}

#[tokio::test]
async fn test_restore_duties_in_place_keeps_one_copy_of_a_duty_the_store_holds() {
    let w = World::new();
    let mut app = w.join("wallet").await;
    let duty = Duty::MemberChanged {
        protocol: "sample".into(),
    };
    keep(&mut app, vec![duty.clone()]).await;
    let backup = app.backup().await.unwrap();
    drop(app);
    let mut restored = App::restore(w.env(), w.protocol.clone(), World::config(), &backup)
        .await
        .unwrap();
    assert_eq!(kept(&restored).await, vec![duty]);
    assert_eq!(restored.unacknowledged_events().await.unwrap().len(), 1);
}

#[tokio::test]
async fn test_restore_duties_second_restore_after_acknowledgement_delivers_again_once() {
    // Delivered at least once: each restore of the backup tells its duties again, once.
    let w = World::new();
    let mut app = w.join("wallet").await;
    let duty = Duty::KeptBatchDropped { batch_id: [5; 16] };
    keep(&mut app, vec![duty.clone()]).await;
    let backup = app.backup().await.unwrap();
    let store = Arc::new(MemoryStore::new());
    let env = || w.env_on(Arc::clone(&store) as Arc<dyn StateStore>);
    let mut first = App::restore(env(), w.protocol.clone(), World::config(), &backup)
        .await
        .unwrap();
    let events = first.unacknowledged_events().await.unwrap();
    assert_eq!(events.len(), 1, "{events:?}");
    first.ack_events(events[0].id().unwrap()).await.unwrap();
    assert!(kept(&first).await.is_empty());
    drop(first);
    let mut second = App::restore(env(), w.protocol.clone(), World::config(), &backup)
        .await
        .unwrap();
    assert_eq!(kept(&second).await, vec![duty]);
    assert_eq!(second.unacknowledged_events().await.unwrap().len(), 1);
}

#[tokio::test]
async fn test_restore_duties_over_one_commit_refuse_the_backup_naming_them() {
    // The carried duties go in the restore's one commit on a new device, which every backup
    // builds before it is handed out: duties too large for it refuse the backup, naming the
    // unacknowledged duties, and nothing is dropped. Acknowledged, they no longer go, and
    // the backup is taken.
    let w = World::new();
    let mut app = w.join("wallet").await;
    for n in 0..3u8 {
        let mut tx = app.tx().unwrap();
        let protocol = format!("{n}{}", "p".repeat(12 << 20));
        let to = app.protocols.names();
        app.keep_duty_for(&mut tx, to, Duty::MemberChanged { protocol })
            .unwrap();
        app.commit(tx).await.unwrap();
    }
    let plain = app.backup().await;
    assert!(
        matches!(
            plain,
            Err(AppError::Refused(crate::app::Refusal::DutiesTooLarge {
                duty_events: 3
            }))
        ),
        "{:?}",
        plain.err()
    );
    let layered = app.backup_layered().await;
    assert!(matches!(
        layered,
        Err(AppError::Refused(crate::app::Refusal::DutiesTooLarge {
            duty_events: 3
        }))
    ));
    assert!(app.take_events().iter().any(|e| matches!(
        e,
        AppEvent::BackupRefused {
            reason: crate::app::BackupRefusal::DutiesTooLarge { duty_events: 3 }
        }
    )));
    assert_eq!(kept(&app).await.len(), 3);
    let events = app.unacknowledged_events().await.unwrap();
    app.ack_events(events[1].id().unwrap()).await.unwrap();
    let backup = app.backup().await.unwrap();
    assert_eq!(backup.duties.len(), 1);
}

#[tokio::test]
async fn test_restore_duties_in_place_counts_one_unreadable_duty_once() {
    // A duty that doesn't read is counted by the backup taken from the store and by the
    // store a restore in place carries: one loss, told as one.
    let w = World::new();
    let mut app = w.join("wallet").await;
    let damaged = app.state.next_duty;
    let mut tx = app.tx().unwrap();
    tx.put(
        &key::duty(damaged),
        &serde_json::json!({"to": ["sample"], "duty": {"PutBackRefused": {}}}),
    )
    .unwrap();
    app.commit(tx).await.unwrap();
    let backup = app.backup().await.unwrap();
    assert_eq!(backup.duties_left_behind, 1);
    drop(app);
    let restored = App::restore(w.env(), w.protocol.clone(), World::config(), &backup)
        .await
        .unwrap();
    assert!(kept(&restored).await.contains(&Duty::RestoreLeftBehind {
        duty_events: 1,
        owed_calls: 0,
    }));
}

#[tokio::test]
async fn test_restore_duties_refuse_a_give_up_also_left_out() {
    // A message a backup gives up is never also one it left out, which the restore tells
    // itself: a backup that says both is refused.
    let w = World::new();
    let mut app = w.join("wallet").await;
    keep(
        &mut app,
        vec![Duty::DeliveryUnknown {
            msg_id: "both".into(),
        }],
    )
    .await;
    let mut backup = app.backup().await.unwrap();
    backup.outbox_left_out.push(("both".into(), false));
    let refused = App::restore(fresh(&w), w.protocol.clone(), World::config(), &backup).await;
    assert!(
        matches!(refused, Err(AppError::InvalidData(ref why)) if why.contains("left out")),
        "{:?}",
        refused.err()
    );
}

#[tokio::test]
async fn test_restore_duties_refuse_a_malformed_refused_certificate() {
    let w = World::new();
    let app = w.join("wallet").await;
    let mut backup = app.backup().await.unwrap();
    backup.cert_refused = Some("not a hash".into());
    let refused = App::restore(fresh(&w), w.protocol.clone(), World::config(), &backup).await;
    assert!(
        matches!(refused, Err(AppError::InvalidData(ref why)) if why.contains("certificate hash")),
        "{:?}",
        refused.err()
    );
}

#[tokio::test]
async fn test_restore_duties_in_place_keeps_the_store_refused_certificate() {
    // In place, the store's refused certificate is the newer word: it wins over the
    // backup's.
    let w = World::new();
    let mut app = w.join("wallet").await;
    let set = |app: &mut App, hash: [u8; 32]| {
        let mut tx = app.tx().unwrap();
        tx.put(key::CERT_REFUSED, &pubky_switch_core::enc::b64(&hash))
            .unwrap();
        tx
    };
    let tx = set(&mut app, [1; 32]);
    app.commit(tx).await.unwrap();
    let backup = app.backup().await.unwrap();
    let tx = set(&mut app, [2; 32]);
    app.commit(tx).await.unwrap();
    drop(app);
    let restored = App::restore(w.env(), w.protocol.clone(), World::config(), &backup)
        .await
        .unwrap();
    assert_eq!(
        restored
            .reader()
            .get::<String>(key::CERT_REFUSED)
            .await
            .unwrap(),
        Some(pubky_switch_core::enc::b64(&[2; 32]))
    );
    // Onto an empty store, the backup's goes.
    let restored = restore_fresh(&w, &backup).await;
    assert_eq!(
        restored
            .reader()
            .get::<String>(key::CERT_REFUSED)
            .await
            .unwrap(),
        Some(pubky_switch_core::enc::b64(&[1; 32]))
    );
}

#[tokio::test]
async fn test_restore_duties_refuse_a_duty_naming_the_last_local_id() {
    // No local ID past the last one exists, so a restore couldn't keep from giving it out:
    // a backup whose duty names it is refused.
    let w = World::new();
    let mut app = w.join("wallet").await;
    keep(
        &mut app,
        vec![Duty::Parked {
            seq: 3,
            stored_id: 7,
            reason: ParkReason::Refused,
        }],
    )
    .await;
    let mut backup = app.backup().await.unwrap();
    restore_fresh(&w, &backup).await;
    backup.duties[0].duty = Duty::Parked {
        seq: 3,
        stored_id: u64::MAX,
        reason: ParkReason::Refused,
    };
    let refused = App::restore(fresh(&w), w.protocol.clone(), World::config(), &backup).await;
    assert!(
        matches!(refused, Err(AppError::InvalidData(ref why)) if why.contains("last local ID")),
        "{:?}",
        refused.err()
    );
}
