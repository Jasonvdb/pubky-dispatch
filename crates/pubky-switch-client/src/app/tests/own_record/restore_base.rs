//! After a restore, a read that can't take the record the switch holds as the base leaves
//! it unread: nothing is built on the record held until a read takes one, or, for an entry
//! that doesn't verify, the user goes on from the record held (Switch spec 4.2).

use super::*;
use crate::app::RecordBaseCause;
use crate::app::state::key;

fn not_now(result: Result<impl std::fmt::Debug, AppError>, part: &str) {
    match result {
        Err(AppError::Refused(Refusal::NotNow(how))) if how.contains(part) => {}
        other => panic!("not a refusal for now naming `{part}`: {other:?}"),
    }
}

fn usage(result: Result<impl std::fmt::Debug, AppError>) {
    assert!(
        matches!(result, Err(AppError::Refused(Refusal::Usage(_)))),
        "{result:?}"
    );
}

async fn told(app: &mut App) -> Vec<RecordBaseCause> {
    app.unacknowledged_events()
        .await
        .unwrap()
        .into_iter()
        .filter_map(|e| match e {
            AppEvent::RecordBaseUnread { cause, .. } => Some(cause),
            _ => None,
        })
        .collect()
}

/// A publishing app with a member, read, and a backup of it.
async fn backed_up(w: &World) -> (App, crate::app::AppBackup) {
    let mut app = w.join_publishing("wallet").await;
    app.set_protocol_member(PROTO, member(json!({ "a": 1 })), None)
        .await
        .unwrap();
    app.receive(None).await.unwrap();
    let backup = app.backup().await.unwrap();
    (app, backup)
}

/// The switch's entry of `id` shows a receive key record that doesn't verify with the
/// record's certificate, so the whole entry doesn't (Switch spec 8.1); returns the one it
/// replaced.
fn unverifiable_entry(w: &World, id: [u8; 16]) -> Option<SignedDoc> {
    let record = w.held(id);
    let mut inner = w.switch.lock();
    let app = inner.apps.get_mut(&id).unwrap();
    std::mem::replace(&mut app.receive_key, record)
}

#[tokio::test]
async fn test_own_record_restore_over_an_entry_that_does_not_verify_leaves_the_base_unread() {
    let w = World::new();
    let (app, backup) = backed_up(&w).await;
    let id = app.app_id();
    drop(app);
    unverifiable_entry(&w, id);
    let puts = w.app_puts();
    let mut restored = restored_publishing(&w, &backup).await;
    restored.receive(None).await.unwrap();
    assert_eq!(
        told(&mut restored).await,
        [RecordBaseCause::EntryUnverified]
    );
    // No key was read: whether the restored one is current isn't known.
    assert_eq!(restored.state.restore.as_ref().unwrap().key_current, None);
    let change = member(json!({ "a": 2 }));
    not_now(
        restored
            .set_protocol_member(PROTO, change.clone(), None)
            .await,
        "build_on_held_record",
    );
    not_now(restored.publish_record().await, "build_on_held_record");
    // Each read looks again, and the cause, unchanged, is told once.
    w.clock.advance_ms(1_000);
    restored.receive(None).await.unwrap();
    assert_eq!(told(&mut restored).await.len(), 1);
    assert_eq!(w.app_puts(), puts);
    // The user goes on from the record held: the change replaces the entry.
    restored.build_on_held_record().await.unwrap();
    w.clock.advance_ms(1_000);
    restored
        .set_protocol_member(PROTO, change.clone(), None)
        .await
        .unwrap();
    assert_eq!(w.app_puts(), puts + 1);
    assert_eq!(w.held(id).as_ref(), Some(restored.record()));
    assert_eq!(record_of(&restored).body().protocol(PROTO), change.as_ref());
}

#[tokio::test]
async fn test_own_record_entry_that_verifies_again_settles_the_base() {
    let w = World::new();
    let (app, backup) = backed_up(&w).await;
    let id = app.app_id();
    drop(app);
    let shown = unverifiable_entry(&w, id);
    let mut restored = restored_publishing(&w, &backup).await;
    restored.receive(None).await.unwrap();
    assert_eq!(
        told(&mut restored).await,
        [RecordBaseCause::EntryUnverified]
    );
    w.switch.lock().apps.get_mut(&id).unwrap().receive_key = shown;
    w.clock.advance_ms(1_000);
    restored.receive(None).await.unwrap();
    assert_eq!(restored.state.base_unread, None);
    let change = member(json!({ "a": 2 }));
    restored
        .set_protocol_member(PROTO, change.clone(), None)
        .await
        .unwrap();
    assert_eq!(w.held(id).as_ref(), Some(restored.record()));
}

#[tokio::test]
async fn test_own_record_restore_under_a_refused_renewal_leaves_the_base_unread() {
    // After the backup, the signer renewed the app with a scope no registered protocol
    // owns, and another device of the app put its record under it. The restored app
    // refuses the renewal, and builds nothing on the record it holds: a record under the
    // certificate it presents is refused for good at the switch.
    let w = World::new();
    let (app, backup) = backed_up(&w).await;
    let id = app.app_id();
    let old = app.cert().clone();
    drop(app);
    w.clock.advance_ms(1_000);
    let renewed = cert_for(
        &w.alice,
        &app_keys("wallet"),
        w.clock.now_ms(),
        &["sample-a", "news"],
    );
    w.switch
        .signer_batch(vec![OpKind::CertPut {
            target_app_id: id,
            cert: renewed.signed().clone(),
        }])
        .unwrap();
    list_renewal(&w, id, &old, &renewed);
    w.clock.advance_ms(1_000);
    let body = AppRecordBody::new(&renewed, vec![], w.clock.now_ms());
    let other = AppRecord::sign(&app_keys("wallet"), body).unwrap();
    w.switch
        .app_op(
            &app_keys("wallet"),
            OpKind::AppPut {
                record: other.signed().clone(),
            },
        )
        .unwrap();
    let puts = w.app_puts();
    let mut restored = restored_publishing(&w, &backup).await;
    restored.receive(None).await.unwrap();
    assert_eq!(restored.cert().hash(), old.hash());
    assert_eq!(
        told(&mut restored).await,
        [RecordBaseCause::CertificateRefused]
    );
    not_now(
        restored
            .set_protocol_member(PROTO, member(json!({ "a": 2 })), None)
            .await,
        "renewed certificate the app refused",
    );
    usage(restored.build_on_held_record().await);
    assert_eq!(w.app_puts(), puts);
    assert_eq!(w.held(id), Some(other.signed().clone()));
}

#[tokio::test]
async fn test_own_record_restore_over_a_record_under_another_certificate_leaves_the_base_unread() {
    // The switch shows a record under a certificate the app neither presents nor refused:
    // nothing is built until a read shows a record the app can build on.
    let w = World::new();
    let (app, backup) = backed_up(&w).await;
    let id = app.app_id();
    drop(app);
    let shown = w.held(id);
    w.clock.advance_ms(1_000);
    let other_cert = cert_for(
        &w.alice,
        &app_keys("wallet"),
        w.clock.now_ms(),
        &["sample-a"],
    );
    let body = AppRecordBody::new(&other_cert, vec![], w.clock.now_ms());
    let other = AppRecord::sign(&app_keys("wallet"), body).unwrap();
    w.switch.lock().apps.get_mut(&id).unwrap().record = Some(other.signed().clone());
    let puts = w.app_puts();
    let mut restored = restored_publishing(&w, &backup).await;
    restored.receive(None).await.unwrap();
    assert_eq!(
        told(&mut restored).await,
        [RecordBaseCause::OtherCertificate]
    );
    let change = member(json!({ "a": 3 }));
    not_now(
        restored
            .set_protocol_member(PROTO, change.clone(), None)
            .await,
        "doesn't present",
    );
    usage(restored.build_on_held_record().await);
    assert_eq!(w.app_puts(), puts);

    // The switch shows the app's own record again: the base is read.
    w.switch.lock().apps.get_mut(&id).unwrap().record = shown;
    w.clock.advance_ms(1_000);
    restored.receive(None).await.unwrap();
    assert_eq!(restored.state.base_unread, None);
    restored
        .set_protocol_member(PROTO, change.clone(), None)
        .await
        .unwrap();
    assert_eq!(w.app_puts(), puts + 1);
    assert_eq!(w.held(id).as_ref(), Some(restored.record()));
}

#[tokio::test]
async fn test_own_record_base_left_unread_takes_no_renewal() {
    // A renewal the app runs with is listed since the backup, and the app's entry doesn't
    // verify: the renewal's record would build on the record held, so it isn't taken until
    // the user goes on from that record.
    let w = World::new();
    let (app, backup) = backed_up(&w).await;
    let id = app.app_id();
    let old = app.cert().clone();
    drop(app);
    w.clock.advance_ms(1_000);
    let renewed = cert_for(
        &w.alice,
        &app_keys("wallet"),
        w.clock.now_ms(),
        &["sample-a"],
    );
    w.switch
        .signer_batch(vec![OpKind::CertPut {
            target_app_id: id,
            cert: renewed.signed().clone(),
        }])
        .unwrap();
    list_renewal(&w, id, &old, &renewed);
    unverifiable_entry(&w, id);
    let puts = w.app_puts();
    let mut restored = restored_publishing(&w, &backup).await;
    for _ in 0..2 {
        w.clock.advance_ms(1_000);
        restored.receive(None).await.unwrap();
    }
    assert_eq!(
        told(&mut restored).await,
        [RecordBaseCause::EntryUnverified]
    );
    assert_eq!(
        restored.kept_renewal().map(|r| r.hash()),
        Some(renewed.hash())
    );
    assert_eq!(restored.cert().hash(), old.hash());
    assert_eq!(w.app_puts(), puts);
    restored.build_on_held_record().await.unwrap();
    w.clock.advance_ms(1_000);
    restored.receive(None).await.unwrap();
    assert_eq!(restored.cert().hash(), renewed.hash());
    assert_eq!(w.app_puts(), puts + 1);
}

#[tokio::test]
async fn test_own_record_restore_in_place_over_record_rows_that_do_not_read_counts_them() {
    // The store's own record, its expiry policies and its refused-renewal mark don't read.
    // A restore in place is how such a store is mended: it leaves them behind, counts the
    // record and the policies, and the first read takes what the switch holds.
    let w = World::new();
    let (mut app, backup) = backed_up(&w).await;
    let id = app.app_id();
    let mut tx = app.tx().unwrap();
    for row in [key::RECORD, key::RECORD_EXPIRIES, key::CERT_REFUSED] {
        tx.put_raw(row, vec![7, 7]).unwrap();
    }
    app.commit(tx).await.unwrap();
    drop(app);
    let mut restored = App::restore(w.env(), w.protocol.clone(), publishing(), &backup)
        .await
        .unwrap();
    let left = restored
        .unacknowledged_events()
        .await
        .unwrap()
        .into_iter()
        .find_map(|e| match e {
            AppEvent::RestoreLeftBehind { record_edits, .. } => Some(record_edits),
            _ => None,
        });
    assert_eq!(left, Some(2));
    restored.receive(None).await.unwrap();
    w.clock.advance_ms(1_000);
    restored
        .set_protocol_member(PROTO, member(json!({ "a": 2 })), None)
        .await
        .unwrap();
    assert_eq!(w.held(id).as_ref(), Some(restored.record()));
}

#[tokio::test]
async fn test_own_record_restore_after_a_renewal_another_device_took_builds_on_its_record() {
    // Since the backup the switch lists a renewal, and another device of the app put its
    // record under it: the restored app's first read takes the renewal from that record,
    // builds on it, and the base is known.
    let w = World::new();
    let (app, backup) = backed_up(&w).await;
    let id = app.app_id();
    let old = app.cert().clone();
    drop(app);
    w.clock.advance_ms(1_000);
    let renewed = cert_for(
        &w.alice,
        &app_keys("wallet"),
        w.clock.now_ms(),
        &["sample-a"],
    );
    w.switch
        .signer_batch(vec![OpKind::CertPut {
            target_app_id: id,
            cert: renewed.signed().clone(),
        }])
        .unwrap();
    list_renewal(&w, id, &old, &renewed);
    w.clock.advance_ms(1_000);
    let mut body = AppRecordBody::new(&renewed, w.protocol.accepts(&renewed), w.clock.now_ms());
    let theirs = member(json!({ "a": 9 })).unwrap();
    body.protocols.insert(PROTO.into(), theirs.clone());
    let other = AppRecord::sign(&app_keys("wallet"), body).unwrap();
    w.switch
        .app_op(
            &app_keys("wallet"),
            OpKind::AppPut {
                record: other.signed().clone(),
            },
        )
        .unwrap();
    let mut restored = restored_publishing(&w, &backup).await;
    restored.receive(None).await.unwrap();
    assert_eq!(restored.cert().hash(), renewed.hash());
    assert!(told(&mut restored).await.is_empty());
    assert_eq!(record_of(&restored).body().protocol(PROTO), Some(&theirs));
    w.clock.advance_ms(1_000);
    restored
        .set_protocol_member(PROTO, member(json!({ "a": 10 })), None)
        .await
        .unwrap();
    assert_eq!(w.held(id).as_ref(), Some(restored.record()));
}
