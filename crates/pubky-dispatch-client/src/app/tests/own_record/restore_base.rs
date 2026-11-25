//! After a restore, a read that can't take the record the Dispatch holds as the base leaves
//! it unread: nothing is built on the record held until a read takes one, or, for an entry
//! that doesn't verify, the user goes on from the record held (Dispatch spec 4.2).

use super::*;
use crate::app::RecordBaseCause;
use crate::app::state::key;
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
