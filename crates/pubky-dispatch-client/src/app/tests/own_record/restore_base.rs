//! After a restore, a read that can't take the record the Dispatch holds as the base leaves
//! it unread: nothing is built on the record held until a read takes one, or, for an entry
//! that doesn't verify, the user goes on from the record held (Dispatch spec 4.2).

use super::*;
use crate::app::RecordBaseCause;
use crate::app::state::key;
use crate::error::StoreError;
use pubky_dispatch_core::records::AppCert;

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

/// The causes of the `RecordBaseUnread` events handed to the host since the last call.
fn handed(app: &mut App) -> Vec<RecordBaseCause> {
    causes(app.take_events())
}

/// The causes of the `RecordBaseUnread` events among `events`.
fn causes(events: Vec<AppEvent>) -> Vec<RecordBaseCause> {
    events
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

/// The Dispatch's entry of `id` shows a receive key record that doesn't verify with the
/// record's certificate, so the whole entry doesn't (Dispatch spec 8.1); returns the one it
/// replaced.
fn unverifiable_entry(w: &World, id: [u8; 16]) -> Option<SignedDoc> {
    let record = w.held(id);
    let mut inner = w.dispatch.lock();
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
    // The point every `app.put` leaves through refuses too, whatever builds the batch.
    let batch = restored.record_batch(restored.record()).unwrap();
    not_now(
        restored.submit(&batch).await.map(|_| ()),
        "build_on_held_record",
    );
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
    w.dispatch.lock().apps.get_mut(&id).unwrap().receive_key = shown;
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
    // certificate it presents is refused for good at the Dispatch. Once the signer renews
    // with a certificate the protocols run with, the read takes it, builds its record
    // over the one the Dispatch shows, and the base is known.
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
    w.dispatch
        .signer_batch(vec![OpKind::CertPut {
            target_app_id: id,
            cert: renewed.signed().clone(),
        }])
        .unwrap();
    list_renewal(&w, id, &old, &renewed);
    w.clock.advance_ms(1_000);
    let mut body = AppRecordBody::new(&renewed, vec![], w.clock.now_ms());
    let theirs = member(json!({ "a": 7 })).unwrap();
    body.protocols.insert(PROTO.into(), theirs.clone());
    let other = AppRecord::sign(&app_keys("wallet"), body).unwrap();
    w.dispatch
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

    w.clock.advance_ms(1_000);
    let runs = renew_listed_to(&w, id, &["sample-a"]);
    for _ in 0..3 {
        w.clock.advance_ms(1_000);
        restored.receive(None).await.unwrap();
    }
    assert_eq!(restored.cert().hash(), runs.hash());
    assert_eq!(restored.state.base_unread, None);
    assert_eq!(
        told(&mut restored).await,
        [RecordBaseCause::CertificateRefused]
    );
    let held = AppRecord::verify(&w.held(id).unwrap(), &w.alice.public()).unwrap();
    assert_eq!(held.cert().hash(), runs.hash());
    assert_eq!(held.body().protocol(PROTO), Some(&theirs));
}

/// The signer stores a renewal of the app to `scopes` and lists it in place of the one
/// listed; returns it.
fn renew_listed_to(w: &World, id: [u8; 16], scopes: &[&str]) -> AppCert {
    let renewed = cert_for(&w.alice, &app_keys("wallet"), w.clock.now_ms(), scopes);
    w.dispatch
        .signer_batch(vec![OpKind::CertPut {
            target_app_id: id,
            cert: renewed.signed().clone(),
        }])
        .unwrap();
    w.next_doc(|body| {
        for app in body.apps.iter_mut().filter(|app| app.app_id == id) {
            app.cert = renewed.hash();
        }
    });
    renewed
}

#[tokio::test]
async fn test_own_record_kept_renewal_on_an_unread_base_takes_the_record_under_it() {
    // The base is unread: the Dispatch shows a record under a certificate of this App ID with
    // other keys, no renewal of the one presented, so nothing is built over it. A renewal
    // is then listed and kept, and taking it builds on nothing. Once another device of the
    // app puts its record under that renewal, the read takes the renewal from that record,
    // and the base is known.
    let w = World::new();
    let (app, backup) = backed_up(&w).await;
    let id = app.app_id();
    let old = app.cert().clone();
    drop(app);
    w.clock.advance_ms(1_000);
    let unlisted = other_keys_cert(&w, &["sample-a"]);
    let body = AppRecordBody::new(&unlisted, vec![], w.clock.now_ms());
    let shown = AppRecord::sign(&app_keys("wallet"), body).unwrap();
    w.dispatch.lock().apps.get_mut(&id).unwrap().record = Some(shown.signed().clone());
    let mut restored = restored_publishing(&w, &backup).await;
    restored.receive(None).await.unwrap();
    assert_eq!(
        told(&mut restored).await,
        [RecordBaseCause::OtherCertificate]
    );

    w.clock.advance_ms(1_000);
    let renewed = cert_for(
        &w.alice,
        &app_keys("wallet"),
        w.clock.now_ms(),
        &["sample-a"],
    );
    w.dispatch
        .signer_batch(vec![OpKind::CertPut {
            target_app_id: id,
            cert: renewed.signed().clone(),
        }])
        .unwrap();
    list_renewal(&w, id, &old, &renewed);
    for _ in 0..2 {
        w.clock.advance_ms(1_000);
        restored.receive(None).await.unwrap();
    }
    assert_eq!(
        restored.kept_renewal().map(|r| r.hash()),
        Some(renewed.hash())
    );
    assert_eq!(restored.cert().hash(), old.hash());

    w.clock.advance_ms(1_000);
    let mut body = AppRecordBody::new(&renewed, vec![], w.clock.now_ms());
    let theirs = member(json!({ "a": 8 })).unwrap();
    body.protocols.insert(PROTO.into(), theirs.clone());
    let later = AppRecord::sign(&app_keys("wallet"), body).unwrap();
    w.dispatch
        .app_op(
            &app_keys("wallet"),
            OpKind::AppPut {
                record: later.signed().clone(),
            },
        )
        .unwrap();
    w.clock.advance_ms(1_000);
    restored.receive(None).await.unwrap();
    assert_eq!(restored.cert().hash(), renewed.hash());
    assert_eq!(restored.state.base_unread, None);
    assert_eq!(record_of(&restored).body().protocol(PROTO), Some(&theirs));
}

#[tokio::test]
async fn test_own_record_restore_over_a_record_under_another_certificate_leaves_the_base_unread() {
    // The Dispatch shows a record under a certificate the app neither presents nor refused:
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
    w.dispatch.lock().apps.get_mut(&id).unwrap().record = Some(other.signed().clone());
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

    // The Dispatch shows the app's own record again: the base is read.
    w.dispatch.lock().apps.get_mut(&id).unwrap().record = shown;
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
    w.dispatch
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
    // record and the policies, and the first read takes what the Dispatch holds.
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
    // The record, the policies and the mark, each once.
    assert_eq!(left, Some(3));
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
    // Since the backup the Dispatch lists a renewal, and another device of the app put its
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
    w.dispatch
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
    w.dispatch
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

#[tokio::test]
async fn test_own_record_second_refused_renewal_keeps_the_way_out() {
    // The Dispatch holds a record under a renewal the app refuses, and the signer then lists
    // a second renewal the app refuses too. The record at the Dispatch is still under a
    // refused renewal, and a third one the protocols run with is taken over it.
    let w = World::new();
    let (app, backup) = backed_up(&w).await;
    let id = app.app_id();
    let old = app.cert().clone();
    drop(app);
    w.clock.advance_ms(1_000);
    let first = cert_for(
        &w.alice,
        &app_keys("wallet"),
        w.clock.now_ms(),
        &["sample-a", "news"],
    );
    w.dispatch
        .signer_batch(vec![OpKind::CertPut {
            target_app_id: id,
            cert: first.signed().clone(),
        }])
        .unwrap();
    list_renewal(&w, id, &old, &first);
    w.clock.advance_ms(1_000);
    let body = AppRecordBody::new(&first, vec![], w.clock.now_ms());
    let other = AppRecord::sign(&app_keys("wallet"), body).unwrap();
    w.dispatch
        .app_op(
            &app_keys("wallet"),
            OpKind::AppPut {
                record: other.signed().clone(),
            },
        )
        .unwrap();
    let mut restored = restored_publishing(&w, &backup).await;
    restored.receive(None).await.unwrap();
    assert_eq!(
        told(&mut restored).await,
        [RecordBaseCause::CertificateRefused]
    );
    w.clock.advance_ms(1_000);
    renew_listed_to(&w, id, &["sample-a", "news"]);
    for _ in 0..2 {
        w.clock.advance_ms(1_000);
        restored.receive(None).await.unwrap();
    }
    assert_eq!(
        restored.state.base_unread,
        Some(RecordBaseCause::CertificateRefused)
    );
    // The way out takes no renewal the protocols refuse.
    assert_eq!(restored.cert().hash(), old.hash());
    w.clock.advance_ms(1_000);
    let runs = renew_listed_to(&w, id, &["sample-a"]);
    for _ in 0..3 {
        w.clock.advance_ms(1_000);
        restored.receive(None).await.unwrap();
    }
    assert_eq!(restored.cert().hash(), runs.hash());
    assert_eq!(restored.state.base_unread, None);
}

#[tokio::test]
async fn test_own_record_restore_in_place_counts_a_newer_record_it_cannot_keep() {
    // The store's own record is newer than the backup's and reads, but its expiry
    // policies and its refusal mark don't: the record can't be kept as the base without
    // the policies it was signed with, so it is left behind and counted, and so is the
    // mark.
    let w = World::new();
    let (mut app, backup) = backed_up(&w).await;
    w.clock.advance_ms(1_000);
    app.set_protocol_member(PROTO, member(json!({ "a": 2 })), None)
        .await
        .unwrap();
    let mut tx = app.tx().unwrap();
    for row in [key::RECORD_EXPIRIES, key::CERT_REFUSED] {
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
    assert_eq!(left, Some(3));
}

#[tokio::test]
async fn test_own_record_backup_over_a_refusal_mark_that_does_not_read() {
    // A refusal mark that doesn't read names nothing at a load; a backup reads it the
    // same way, and goes.
    let w = World::new();
    let (mut app, _) = backed_up(&w).await;
    let mut tx = app.tx().unwrap();
    tx.put_raw(key::CERT_REFUSED, vec![7, 7]).unwrap();
    app.commit(tx).await.unwrap();
    app.backup().await.unwrap();
}

#[tokio::test]
async fn test_own_record_record_under_a_certificate_with_other_keys_is_another_certificate() {
    // The Dispatch shows a record under a certificate of this App ID, later and with a scope
    // the protocols refuse, but with another bundle key: not a renewal of the one the app
    // presents, so it reads as another certificate, never as a refused renewal.
    let w = World::new();
    let (app, backup) = backed_up(&w).await;
    let id = app.app_id();
    drop(app);
    w.clock.advance_ms(1_000);
    let other_keys = other_keys_cert(&w, &["sample-a", "news"]);
    assert_eq!(other_keys.app_id(), id);
    let record = AppRecordBody::new(&other_keys, vec![], w.clock.now_ms());
    let shown = AppRecord::sign(&app_keys("wallet"), record).unwrap();
    w.dispatch.lock().apps.get_mut(&id).unwrap().record = Some(shown.signed().clone());
    let mut restored = restored_publishing(&w, &backup).await;
    restored.receive(None).await.unwrap();
    assert_eq!(
        told(&mut restored).await,
        [RecordBaseCause::OtherCertificate]
    );
}

/// A certificate of the app's App ID, issued now, with its signing key and another bundle
/// key: no renewal of the one it presents.
fn other_keys_cert(w: &World, scopes: &[&str]) -> AppCert {
    let spec = crate::app::tests::sample_app(scopes);
    let issued = w.clock.now_ms();
    let body = pubky_dispatch_core::records::AppCertBody::new(
        w.alice.public(),
        app_keys("wallet").signing_public(),
        app_keys("other").bundle_public(),
        spec.scopes.clone(),
        &spec.permissions,
        issued,
        issued + 30 * pubky_dispatch_core::records::DAY_MS,
    );
    AppCert::issue(&w.alice, body).unwrap()
}

#[tokio::test]
async fn test_own_record_renewal_is_built_over_an_unlisted_renewal_of_the_app() {
    // The Dispatch shows a record under a later certificate of the app, with its keys, that
    // is listed no more and that the protocols don't refuse: another certificate, but the
    // app's own content. A renewal listed then is built over it, and the base settles.
    let w = World::new();
    let (app, backup) = backed_up(&w).await;
    let id = app.app_id();
    drop(app);
    w.clock.advance_ms(1_000);
    let unlisted = cert_for(
        &w.alice,
        &app_keys("wallet"),
        w.clock.now_ms(),
        &["sample-a"],
    );
    let mut body = AppRecordBody::new(&unlisted, vec![], w.clock.now_ms());
    let theirs = member(json!({ "a": 6 })).unwrap();
    body.protocols.insert(PROTO.into(), theirs.clone());
    let shown = AppRecord::sign(&app_keys("wallet"), body).unwrap();
    w.dispatch.lock().apps.get_mut(&id).unwrap().record = Some(shown.signed().clone());
    let mut restored = restored_publishing(&w, &backup).await;
    restored.receive(None).await.unwrap();
    assert_eq!(
        told(&mut restored).await,
        [RecordBaseCause::OtherCertificate]
    );
    w.clock.advance_ms(1_000);
    let listed = renew_listed_to(&w, id, &["sample-a"]);
    for _ in 0..3 {
        w.clock.advance_ms(1_000);
        restored.receive(None).await.unwrap();
    }
    assert_eq!(restored.cert().hash(), listed.hash());
    assert_eq!(restored.state.base_unread, None);
    assert_eq!(record_of(&restored).body().protocol(PROTO), Some(&theirs));
}

#[tokio::test]
async fn test_own_record_go_ahead_lost_with_a_reload_is_asked_again() {
    // The user goes on from the record held over an entry that doesn't verify, and the app
    // restarts before any change goes. The base is unread again: a change is refused, the
    // cause is told again, and the go-ahead is asked again.
    let w = World::new();
    let (app, backup) = backed_up(&w).await;
    let id = app.app_id();
    drop(app);
    unverifiable_entry(&w, id);
    let store = Arc::new(MemoryStore::new());
    let mut restored = App::restore(
        w.env_on(Arc::clone(&store) as Arc<dyn StateStore>),
        w.protocol.clone(),
        publishing(),
        &backup,
    )
    .await
    .unwrap();
    restored.receive(None).await.unwrap();
    let events = restored.unacknowledged_events().await.unwrap();
    let last = events
        .iter()
        .filter_map(AppEvent::id)
        .max_by_key(|id| id.counter())
        .unwrap();
    restored.ack_events(last).await.unwrap();
    restored.build_on_held_record().await.unwrap();
    drop(restored);

    let mut restored = w
        .load_publishing_on(Arc::clone(&store) as Arc<dyn StateStore>, id)
        .await;
    let change = member(json!({ "a": 2 }));
    not_now(
        restored
            .set_protocol_member(PROTO, change.clone(), None)
            .await,
        "build_on_held_record",
    );
    assert_eq!(
        told(&mut restored).await,
        [RecordBaseCause::EntryUnverified]
    );
    restored.build_on_held_record().await.unwrap();
    w.clock.advance_ms(1_000);
    restored
        .set_protocol_member(PROTO, change.clone(), None)
        .await
        .unwrap();
    assert_eq!(w.held(id).as_ref(), Some(restored.record()));
}

/// The certificates of the table in `STATE.md`, "The restored base": P, the one presented;
/// one earlier and two later with its keys; one later with other keys.
struct Certs {
    p: AppCert,
    earlier: AppCert,
    c1: AppCert,
    c2: AppCert,
    other: AppCert,
}

impl Certs {
    fn new(w: &World) -> Self {
        let at = w.clock.now_ms();
        let cert = |issued| cert_for(&w.alice, &app_keys("wallet"), issued, &["sample-a"]);
        let other = other_keys_cert(w, &["sample-a"]);
        Self {
            p: cert(at),
            earlier: cert(at - 1_000),
            c1: cert(at + 1_000),
            c2: cert(at + 2_000),
            other,
        }
    }
}

fn record_under(cert: &AppCert) -> AppRecord {
    let body = AppRecordBody::new(cert, vec![], cert.issued_at());
    AppRecord::sign(&app_keys("wallet"), body).unwrap()
}

/// What a read shows in a row of the table.
#[derive(Clone, Copy, Debug)]
enum Shows {
    Nothing,
    Unverified,
    Earlier,
    Presented,
    C1,
    C2,
    OtherKeys,
}

#[tokio::test]
async fn test_own_record_restored_base_rows_make_nothing_pending_that_cannot_go() {
    // Every row of the read and renewal tables: what each answer settles is the table's
    // cause, and a renewal is built over the record shown only when the record built for
    // it settles the base at the next read, so a record made pending can always go.
    use crate::app::renewal::{base_cause, builds_over};
    let w = World::new();
    let c = Certs::new(&w);
    let listed_options = [c.p.clone(), c.c1.clone(), c.c2.clone()];
    let refusals: [&[&AppCert]; 4] = [&[], &[&c.c1], &[&c.c2], &[&c.c1, &c.c2]];
    let shows = [
        Shows::Nothing,
        Shows::Unverified,
        Shows::Earlier,
        Shows::Presented,
        Shows::C1,
        Shows::C2,
        Shows::OtherKeys,
    ];
    let mut rows = 0;
    for show in shows {
        let shown_cert = match show {
            Shows::Nothing | Shows::Unverified => None,
            Shows::Earlier => Some(&c.earlier),
            Shows::Presented => Some(&c.p),
            Shows::C1 => Some(&c.c1),
            Shows::C2 => Some(&c.c2),
            Shows::OtherKeys => Some(&c.other),
        };
        let shown = shown_cert.map(record_under);
        for listed in &listed_options {
            for refused in refusals {
                rows += 1;
                let refuses = |cert: &AppCert| refused.iter().any(|r| r.hash() == cert.hash());
                let row = format!(
                    "{show:?}, listed {}, refused {}",
                    listed.issued_at(),
                    refused.len()
                );
                // The read table.
                let expected = match show {
                    Shows::Nothing | Shows::Earlier | Shows::Presented => None,
                    Shows::Unverified => Some(RecordBaseCause::EntryUnverified),
                    Shows::OtherKeys => Some(RecordBaseCause::OtherCertificate),
                    Shows::C1 | Shows::C2 => match refuses(shown_cert.unwrap()) {
                        true => Some(RecordBaseCause::CertificateRefused),
                        false => Some(RecordBaseCause::OtherCertificate),
                    },
                };
                // The row "S = L, accepted": the app takes L from that record.
                let taken_from_shown = shown_cert.is_some_and(|s| {
                    s.hash() == listed.hash() && listed.hash() != c.p.hash() && !refuses(listed)
                });
                let cause = base_cause(
                    &c.p,
                    shown.as_ref(),
                    matches!(show, Shows::Unverified),
                    refuses,
                );
                if taken_from_shown {
                    let after = base_cause(listed, shown.as_ref(), false, refuses);
                    assert_eq!(after, None, "{row}: taken from the record shown");
                    continue;
                }
                assert_eq!(cause, expected, "{row}");
                // The renewal table, for a cause that a renewal is built over.
                if listed.hash() == c.p.hash()
                    || refuses(listed)
                    || !matches!(
                        cause,
                        Some(
                            RecordBaseCause::CertificateRefused | RecordBaseCause::OtherCertificate
                        )
                    )
                {
                    continue;
                }
                let shown = shown.as_ref().unwrap();
                let built = builds_over(&c.p, shown, listed);
                let s_no_later_than_l = shown.cert().issued_at() <= listed.issued_at();
                let expected_built = matches!(show, Shows::C1 | Shows::C2) && s_no_later_than_l;
                assert_eq!(built, expected_built, "{row}: built over the record shown");
                if built {
                    // P becomes L: the next unchanged read settles none, so it goes.
                    let next = base_cause(listed, Some(shown), false, refuses);
                    assert_eq!(next, None, "{row}: the record built can go");
                }
            }
        }
    }
    assert_eq!(rows, 7 * 3 * 4);
}

#[tokio::test]
async fn test_own_record_restored_base_rows_tell_the_cause_held_at_each_load() {
    // The load and rebuild rows, for every cause and every set of retained events, with and
    // without a go-ahead: while a gate is closed for a cause, an event of exactly that cause
    // is retained or told at the load or the rebuild, and an event of another cause doesn't
    // count for it.
    use crate::app::events::Duty;
    let causes = [
        RecordBaseCause::EntryUnverified,
        RecordBaseCause::CertificateRefused,
        RecordBaseCause::OtherCertificate,
    ];
    for (i, cause) in causes.into_iter().enumerate() {
        let other = causes[(i + 1) % causes.len()];
        let retained_options: [&[RecordBaseCause]; 4] = [&[], &[cause], &[other], &[cause, other]];
        for retained in retained_options {
            for (go_ahead, rebuild) in [
                (false, false),
                (false, true),
                (cause == RecordBaseCause::EntryUnverified, false),
                (cause == RecordBaseCause::EntryUnverified, true),
            ] {
                let w = World::new();
                let mut app = w.join_publishing("wallet").await;
                let id = app.app_id();
                let to = app.protocols.names();
                let mut tx = app.tx().unwrap();
                tx.put(key::RECORD_BASE, &cause).unwrap();
                for kept in retained {
                    let duty = Duty::RecordBaseUnread { cause: *kept };
                    app.keep_duty_for(&mut tx, to.clone(), duty).unwrap();
                }
                app.commit(tx).await.unwrap();
                app.state.base_unread = Some(cause);
                if go_ahead {
                    app.build_on_held_record().await.unwrap();
                }
                let row = format!(
                    "{cause:?}, retained {retained:?}, go-ahead {go_ahead}, rebuild {rebuild}"
                );
                // The state rebuilt from the store, as after a failed commit; or a load.
                let mut app = if rebuild {
                    app.reload = true;
                    app
                } else {
                    drop(app);
                    w.load_publishing_on(Arc::clone(&w.store) as Arc<dyn StateStore>, id)
                        .await
                };
                let told = told(&mut app).await;
                assert!(told.contains(&cause), "{row}: {told:?}");
                // The gate is closed for that cause.
                let refused = app
                    .set_protocol_member(PROTO, member(json!({ "a": 9 })), None)
                    .await;
                assert!(
                    matches!(&refused, Err(AppError::Refused(Refusal::NotNow(_)))),
                    "{row}: {refused:?}"
                );
            }
        }
    }
}

#[tokio::test]
async fn test_own_record_go_ahead_after_a_cause_change_and_an_exact_acknowledgement_is_asked_again()
{
    // An event of one cause is retained; the cause becomes `EntryUnverified`; the host
    // acknowledges exactly that event and goes on; the app reloads. The earlier cause's
    // event tells nothing of this one: the cause held is told again and the gate stays shut.
    let w = World::new();
    let (app, backup) = backed_up(&w).await;
    let id = app.app_id();
    drop(app);
    let shown = w.held(id);
    let other = other_keys_cert(&w, &["sample-a"]);
    w.dispatch.lock().apps.get_mut(&id).unwrap().record =
        Some(record_under(&other).signed().clone());
    let store = Arc::new(MemoryStore::new());
    let mut restored = App::restore(
        w.env_on(Arc::clone(&store) as Arc<dyn StateStore>),
        w.protocol.clone(),
        publishing(),
        &backup,
    )
    .await
    .unwrap();
    restored.receive(None).await.unwrap();
    assert_eq!(
        told(&mut restored).await,
        [RecordBaseCause::OtherCertificate]
    );
    w.dispatch.lock().apps.get_mut(&id).unwrap().record = shown;
    unverifiable_entry(&w, id);
    w.clock.advance_ms(1_000);
    restored.receive(None).await.unwrap();
    let unverified = restored
        .unacknowledged_events()
        .await
        .unwrap()
        .into_iter()
        .find_map(|e| match e {
            AppEvent::RecordBaseUnread {
                id,
                cause: RecordBaseCause::EntryUnverified,
            } => Some(id),
            _ => None,
        })
        .unwrap();
    restored
        .ack_event_with(PROTO, unverified, &[])
        .await
        .unwrap();
    restored.build_on_held_record().await.unwrap();
    drop(restored);
    let mut restored = w
        .load_publishing_on(Arc::clone(&store) as Arc<dyn StateStore>, id)
        .await;
    assert!(
        told(&mut restored)
            .await
            .contains(&RecordBaseCause::EntryUnverified)
    );
    not_now(
        restored
            .set_protocol_member(PROTO, member(json!({ "a": 2 })), None)
            .await,
        "build_on_held_record",
    );
}

#[tokio::test]
async fn test_own_record_listed_renewal_older_than_the_record_shown_makes_nothing_pending() {
    // Certificates P < C1 < C2 with the app's keys. The directory shows a record under C2,
    // and the own document lists C1. A record for C1 built over C2 would leave the base
    // unread and never go, so nothing is built: no record is made pending.
    let w = World::new();
    let (app, backup) = backed_up(&w).await;
    let id = app.app_id();
    let presented = app.cert().clone();
    drop(app);
    let c = Certs::new(&w);
    w.dispatch.lock().apps.get_mut(&id).unwrap().record =
        Some(record_under(&c.c2).signed().clone());
    let mut restored = restored_publishing(&w, &backup).await;
    restored.receive(None).await.unwrap();
    assert_eq!(
        told(&mut restored).await,
        [RecordBaseCause::OtherCertificate]
    );
    w.dispatch
        .signer_batch(vec![OpKind::CertPut {
            target_app_id: id,
            cert: c.c1.signed().clone(),
        }])
        .unwrap();
    list_renewal(&w, id, &presented, &c.c1);
    for _ in 0..3 {
        w.clock.advance_ms(1_000);
        restored.receive(None).await.unwrap();
    }
    assert_eq!(restored.state.pending_record, None);
    assert_eq!(restored.cert().hash(), presented.hash());
    assert_eq!(
        restored.state.base_unread,
        Some(RecordBaseCause::OtherCertificate)
    );
}

#[tokio::test]
async fn test_own_record_go_ahead_lost_with_a_failed_commit_is_told_again() {
    // The cause `EntryUnverified` is acknowledged and the user goes on; a later commit fails,
    // and the next call rebuilds the state from the store. The go-ahead is gone with it: the
    // cause is told again, and the setter is refused until the user goes on again.
    use crate::store::{Fault as StoreFault, FaultStore};
    let w = World::new();
    let (app, backup) = backed_up(&w).await;
    let id = app.app_id();
    drop(app);
    unverifiable_entry(&w, id);
    let store = Arc::new(FaultStore::new(
        Arc::new(MemoryStore::new()),
        StoreFault::None,
    ));
    let mut restored = App::restore(
        w.env_on(Arc::clone(&store) as Arc<dyn StateStore>),
        w.protocol.clone(),
        publishing(),
        &backup,
    )
    .await
    .unwrap();
    restored.receive(None).await.unwrap();
    let events = restored.unacknowledged_events().await.unwrap();
    let last = events
        .iter()
        .filter_map(AppEvent::id)
        .max_by_key(|id| id.counter())
        .unwrap();
    restored.ack_events(last).await.unwrap();
    restored.build_on_held_record().await.unwrap();
    // The go-ahead passes the gate.
    w.clock.advance_ms(1_000);
    restored
        .set_protocol_member(PROTO, member(json!({ "a": 2 })), None)
        .await
        .unwrap();
    restored.take_events();
    store.fail_put_once(b"");
    restored.set_multi_device(true).await.unwrap_err();
    not_now(
        restored
            .set_protocol_member(PROTO, member(json!({ "a": 3 })), None)
            .await,
        "build_on_held_record",
    );
    // Handed to the host again, not only kept.
    assert_eq!(handed(&mut restored), [RecordBaseCause::EntryUnverified]);
    assert_eq!(
        told(&mut restored).await,
        [RecordBaseCause::EntryUnverified]
    );
}

/// Restored over an entry that doesn't verify, on `store`, read, every event acknowledged,
/// and the user's go-ahead given; the events handed so far taken.
async fn restored_with_go_ahead(
    w: &World,
    store: &Arc<crate::store::FaultStore>,
) -> (App, Option<SignedDoc>) {
    let (app, backup) = backed_up(w).await;
    let id = app.app_id();
    drop(app);
    let key = unverifiable_entry(w, id);
    let mut restored = App::restore(
        w.env_on(Arc::clone(store) as Arc<dyn StateStore>),
        w.protocol.clone(),
        publishing(),
        &backup,
    )
    .await
    .unwrap();
    restored.receive(None).await.unwrap();
    if let Some(last) = restored
        .unacknowledged_events()
        .await
        .unwrap()
        .iter()
        .filter_map(AppEvent::id)
        .max_by_key(|id| id.counter())
    {
        restored.ack_events(last).await.unwrap();
    }
    restored.build_on_held_record().await.unwrap();
    restored.take_events();
    (restored, key)
}

fn fault_store() -> Arc<crate::store::FaultStore> {
    Arc::new(crate::store::FaultStore::new(
        Arc::new(MemoryStore::new()),
        crate::store::Fault::None,
    ))
}

/// The places the go-ahead is dropped (`STATE.md`, "The restored base"), and the read that
/// keeps it.
#[derive(Clone, Copy, Debug, PartialEq)]
enum GoAheadRow {
    Load,
    Rebuild,
    RebuildFailingPartWay,
    GenerationFollowed,
    GenerationChangedThenDropped,
    GenerationChangedUntold,
    EntryVerifiesUnderOtherKeys,
    NoEntryThenUnverified,
    AnswerDroppedBeforeItsSettle,
    EntryStillUnverified,
}

#[tokio::test]
async fn test_own_record_go_ahead_rows_close_the_gate_and_tell_the_cause() {
    // Every row that drops the go-ahead, after the user went on and acknowledged every
    // event: the gate stays closed for an entry that doesn't verify, an event of the cause
    // held is handed to the host after the drop, and no go-ahead is left. The read whose
    // entry still doesn't verify keeps it.
    use crate::app::GoAhead;
    for row in [
        GoAheadRow::Load,
        GoAheadRow::Rebuild,
        GoAheadRow::RebuildFailingPartWay,
        GoAheadRow::GenerationFollowed,
        GoAheadRow::GenerationChangedThenDropped,
        GoAheadRow::GenerationChangedUntold,
        GoAheadRow::EntryVerifiesUnderOtherKeys,
        GoAheadRow::NoEntryThenUnverified,
        GoAheadRow::AnswerDroppedBeforeItsSettle,
        GoAheadRow::EntryStillUnverified,
    ] {
        let w = World::new();
        let store = fault_store();
        let (mut app, key) = restored_with_go_ahead(&w, &store).await;
        let id = app.app_id();
        w.clock.advance_ms(1_000);
        let mut app = match row {
            GoAheadRow::Load => {
                drop(app);
                w.load_publishing_on(Arc::clone(&store) as Arc<dyn StateStore>, id)
                    .await
            }
            GoAheadRow::Rebuild => {
                app.reload = true;
                app
            }
            GoAheadRow::RebuildFailingPartWay => {
                app.reload = true;
                store.fail_scan(crate::app::state::key::DUTY_PREFIX.as_bytes(), 0);
                app.set_multi_device(true).await.unwrap_err();
                app
            }
            // A move's switch or a loss: the go-ahead ends before the generation changes in
            // memory, and the commit that follows tells it.
            GoAheadRow::GenerationFollowed => {
                app.go_ahead_ends();
                app.state.meta.generation += 1;
                let tx = app.tx().unwrap();
                app.commit_followed_generation(tx).await.unwrap();
                app.state.meta.generation -= 1;
                app
            }
            // The same, the call dropped before that commit.
            GoAheadRow::GenerationChangedThenDropped => {
                app.go_ahead_ends();
                app.state.meta.generation += 1;
                app
            }
            // A generation changed in memory with the go-ahead still given: the gate
            // compares generations.
            GoAheadRow::GenerationChangedUntold => {
                app.state.meta.generation += 1;
                let refused = app
                    .set_protocol_member(PROTO, member(json!({ "a": 7 })), None)
                    .await;
                assert!(
                    matches!(&refused, Err(AppError::Refused(Refusal::NotNow(_)))),
                    "{row:?}: {refused:?}"
                );
                app.state.meta.generation -= 1;
                app.go_ahead_ends();
                app
            }
            GoAheadRow::EntryVerifiesUnderOtherKeys => {
                let other = other_keys_cert(&w, &["sample-a"]);
                {
                    let mut dispatch = w.dispatch.lock();
                    let entry = dispatch.apps.get_mut(&id).unwrap();
                    entry.receive_key = key;
                    entry.record = Some(record_under(&other).signed().clone());
                }
                let report = app.receive(None).await.unwrap();
                assert_eq!(
                    causes(report.events),
                    [RecordBaseCause::OtherCertificate],
                    "{row:?}"
                );
                app
            }
            // No entry settles the base; the restore's own check is still outstanding, and a
            // later entry that doesn't verify asks again.
            GoAheadRow::NoEntryThenUnverified => {
                app.state.restore.as_mut().unwrap().key_checked = false;
                w.dispatch.lock().kept_app_ids.push(id);
                app.receive(None).await.unwrap();
                assert_eq!(app.state.base_unread, None, "{row:?}");
                w.dispatch.lock().kept_app_ids.retain(|kept| kept != &id);
                // The rebuild the read armed runs first.
                app.publish_record().await.unwrap();
                app.state.restore.as_mut().unwrap().key_checked = false;
                w.clock.advance_ms(1_000);
                let report = app.receive(None).await.unwrap();
                assert_eq!(
                    causes(report.events),
                    [RecordBaseCause::EntryUnverified],
                    "{row:?}"
                );
                app
            }
            // An answer whose entry verifies, the call dropped after it ended the go-ahead
            // and before its settle.
            GoAheadRow::AnswerDroppedBeforeItsSettle => {
                app.answer_ends_go_ahead(false);
                app
            }
            GoAheadRow::EntryStillUnverified => {
                app.receive(None).await.unwrap();
                app
            }
        };
        let told_in_row = matches!(
            row,
            GoAheadRow::EntryVerifiesUnderOtherKeys | GoAheadRow::NoEntryThenUnverified
        );
        let change = app
            .set_protocol_member(PROTO, member(json!({ "a": 7 })), None)
            .await;
        let held = app.state.base_unread;
        let handed = handed(&mut app);
        if row == GoAheadRow::EntryStillUnverified {
            assert!(change.is_ok(), "{row:?}: {change:?}");
            assert!(
                matches!(app.state.go_ahead, GoAhead::Given { .. }),
                "{row:?}"
            );
            continue;
        }
        assert_eq!(app.state.go_ahead, GoAhead::None, "{row:?}");
        let cause = held.unwrap_or_else(|| panic!("{row:?}: no cause held"));
        assert!(
            told_in_row || handed.contains(&cause),
            "{row:?}: {handed:?}"
        );
        assert!(
            matches!(&change, Err(AppError::Refused(Refusal::NotNow(_)))),
            "{row:?}: {change:?}"
        );
    }
}

#[tokio::test]
async fn test_own_record_go_ahead_lost_while_its_rebuild_fails_is_told_again() {
    // The host acknowledges `EntryUnverified` and goes on; a setter's commit fails, and the
    // next call's rebuild fails reading the kept events. That call fails with the store's
    // error, the rebuild stays due, and the call after it tells the cause again.
    let w = World::new();
    let store = fault_store();
    let (mut app, _) = restored_with_go_ahead(&w, &store).await;
    assert!(told(&mut app).await.is_empty());
    store.fail_put_once(b"");
    app.set_multi_device(true).await.unwrap_err();
    store.fail_scan(crate::app::state::key::DUTY_PREFIX.as_bytes(), 2);
    let first = app
        .set_protocol_member(PROTO, member(json!({ "a": 2 })), None)
        .await;
    assert!(
        matches!(&first, Err(AppError::Store(StoreError::Unavailable))),
        "{first:?}"
    );
    not_now(
        app.set_protocol_member(PROTO, member(json!({ "a": 2 })), None)
            .await,
        "build_on_held_record",
    );
    assert_eq!(handed(&mut app), [RecordBaseCause::EntryUnverified]);
    assert_eq!(told(&mut app).await, [RecordBaseCause::EntryUnverified]);
}

#[tokio::test]
async fn test_own_record_go_ahead_told_by_a_commit_whose_answer_was_lost_is_told_once() {
    // The rebuild's commit that tells the cause again applies, but its answer is lost. The
    // next rebuild finds that event and tells nothing more: one event for one go-ahead.
    let w = World::new();
    let store = fault_store();
    let (mut app, _) = restored_with_go_ahead(&w, &store).await;
    store.fail_put_once(b"");
    app.set_multi_device(true).await.unwrap_err();
    store.apply_put_once_as_unknown(crate::app::state::key::DUTY_PREFIX.as_bytes());
    let first = app
        .set_protocol_member(PROTO, member(json!({ "a": 2 })), None)
        .await;
    assert!(
        matches!(&first, Err(AppError::Store(StoreError::Unknown))),
        "{first:?}"
    );
    not_now(
        app.set_protocol_member(PROTO, member(json!({ "a": 2 })), None)
            .await,
        "build_on_held_record",
    );
    assert_eq!(told(&mut app).await, [RecordBaseCause::EntryUnverified]);
}

#[tokio::test]
async fn test_own_record_go_ahead_after_the_cause_returns_is_told_again_at_a_rebuild() {
    // The cause goes `EntryUnverified`, `OtherCertificate`, `EntryUnverified`. The host
    // acknowledges exactly the newest event and goes on; a rebuild drops the go-ahead. The
    // older event of the same cause, retained and handed before, doesn't stand for it: the
    // cause is handed again.
    let w = World::new();
    let (app, backup) = backed_up(&w).await;
    let id = app.app_id();
    drop(app);
    let key = unverifiable_entry(&w, id);
    let mut restored = restored_publishing(&w, &backup).await;
    restored.receive(None).await.unwrap();
    let other = other_keys_cert(&w, &["sample-a"]);
    {
        let mut dispatch = w.dispatch.lock();
        let entry = dispatch.apps.get_mut(&id).unwrap();
        entry.receive_key = key;
        entry.record = Some(record_under(&other).signed().clone());
    }
    w.clock.advance_ms(1_000);
    restored.receive(None).await.unwrap();
    unverifiable_entry(&w, id);
    w.clock.advance_ms(1_000);
    restored.receive(None).await.unwrap();
    assert_eq!(
        told(&mut restored).await,
        [
            RecordBaseCause::EntryUnverified,
            RecordBaseCause::OtherCertificate,
            RecordBaseCause::EntryUnverified
        ]
    );
    let newest = restored
        .unacknowledged_events()
        .await
        .unwrap()
        .iter()
        .filter_map(AppEvent::id)
        .max_by_key(|id| id.counter())
        .unwrap();
    restored.ack_event_with(PROTO, newest, &[]).await.unwrap();
    restored.build_on_held_record().await.unwrap();
    restored.take_events();
    restored.reload = true;
    not_now(
        restored
            .set_protocol_member(PROTO, member(json!({ "a": 2 })), None)
            .await,
        "build_on_held_record",
    );
    assert_eq!(handed(&mut restored), [RecordBaseCause::EntryUnverified]);
}

#[tokio::test]
async fn test_own_record_go_ahead_ends_before_a_verifying_answer_takes_a_kept_renewal() {
    // The user went on over an entry that doesn't verify, and a renewal is listed and kept,
    // not taken while the base is unread. The entry then verifies, with a record under a
    // certificate with other keys. The answer ends the go-ahead before it takes anything:
    // the kept renewal is not signed over the record held, nothing is sent, and the new
    // cause is told.
    let w = World::new();
    let (app, backup) = backed_up(&w).await;
    let id = app.app_id();
    let old = app.cert().clone();
    drop(app);
    let key = unverifiable_entry(&w, id);
    let mut restored = restored_publishing(&w, &backup).await;
    restored.receive(None).await.unwrap();
    w.clock.advance_ms(1_000);
    let renewed = cert_for(
        &w.alice,
        &app_keys("wallet"),
        w.clock.now_ms(),
        &["sample-a"],
    );
    w.dispatch
        .signer_batch(vec![OpKind::CertPut {
            target_app_id: id,
            cert: renewed.signed().clone(),
        }])
        .unwrap();
    list_renewal(&w, id, &old, &renewed);
    for _ in 0..2 {
        w.clock.advance_ms(1_000);
        restored.receive(None).await.unwrap();
    }
    assert_eq!(
        restored.kept_renewal().map(|r| r.hash()),
        Some(renewed.hash())
    );
    assert_eq!(restored.cert().hash(), old.hash());
    restored.build_on_held_record().await.unwrap();
    restored.take_events();
    w.clock.advance_ms(1_000);
    let other = other_keys_cert(&w, &["sample-a"]);
    {
        let mut dispatch = w.dispatch.lock();
        let entry = dispatch.apps.get_mut(&id).unwrap();
        entry.receive_key = key;
        entry.record = Some(record_under(&other).signed().clone());
    }
    let puts = w.app_puts();
    w.clock.advance_ms(1_000);
    let report = restored.receive(None).await.unwrap();
    assert_eq!(w.app_puts(), puts);
    assert_eq!(restored.cert().hash(), old.hash());
    assert_eq!(restored.state.pending_record, None);
    assert_eq!(causes(report.events), [RecordBaseCause::OtherCertificate]);
}

#[tokio::test]
async fn test_own_record_go_ahead_ends_when_the_entry_is_gone() {
    // The user went on over an entry that doesn't verify; a read then finds no entry, and a
    // later one an entry that doesn't verify again. The go-ahead ended with the first: the
    // gate is closed and the cause is told again, so the user is asked again.
    let w = World::new();
    let store = fault_store();
    let (mut app, _) = restored_with_go_ahead(&w, &store).await;
    let id = app.app_id();
    // The restore's own check still outstanding, as while it waits behind a registration at
    // a service a provider change took the app to.
    app.state.restore.as_mut().unwrap().key_checked = false;
    w.dispatch.lock().kept_app_ids.push(id);
    w.clock.advance_ms(1_000);
    app.receive(None).await.unwrap();
    assert_eq!(app.state.base_unread, None);
    w.dispatch.lock().kept_app_ids.retain(|kept| kept != &id);
    // The rebuild the read armed runs first.
    app.publish_record().await.unwrap();
    app.state.restore.as_mut().unwrap().key_checked = false;
    w.clock.advance_ms(1_000);
    let report = app.receive(None).await.unwrap();
    assert_eq!(
        app.state.base_unread,
        Some(RecordBaseCause::EntryUnverified)
    );
    assert_eq!(causes(report.events), [RecordBaseCause::EntryUnverified]);
    not_now(
        app.set_protocol_member(PROTO, member(json!({ "a": 2 })), None)
            .await,
        "build_on_held_record",
    );
}
