//! Revocations, departures and full-bundle requests against the scripted Dispatch (Dispatch spec
//! 12.2, 12.3; Dispatch wire 3.5, 7.4.11, 7.4.12): the Dispatch revoked first, the rotation's
//! bundles for the apps that stay, the version that removes the app at the Dispatch's time, the
//! record deleted and the App ID kept for good, a revocation or a departure completed at the
//! next run, and the parts a full-bundle request lacks.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::sync::Arc;

use common::*;
use pubky_dispatch_client::store::{Fault, FaultStore, MemoryStore, StateStore};
use pubky_dispatch_client::testing::Fault as DispatchFault;
use pubky_dispatch_core::keys::{AppKeys, IdentityKey};
use pubky_dispatch_core::ops::OpKind;
use pubky_dispatch_core::records::AppRequestStep;
use pubky_dispatch_core::records::{
    IDENTITY_PATH, IdentityDoc, KeyBundleContents, Limits, RemovedApp, SIGNER_BACKUP_PATH,
    SignerBackup, SignerRecords, app_record_path,
};
use pubky_dispatch_signer::Alert;
use pubky_dispatch_signer::{
    CertChange, Refusal, Signer, SignerError, SignerStatus, UserConfirmed,
};

const DAY_MS: u64 = 86_400_000;

fn confirmed() -> UserConfirmed {
    UserConfirmed::shown_and_confirmed()
}

/// The bundle parts the Dispatch holds for `app`, opened with its bundle secret.
fn opened(world: &World, app: &App) -> Vec<KeyBundleContents> {
    let id = app.keys.app_id_bytes();
    world
        .dispatch
        .bundle_parts_of(&id)
        .iter()
        .map(|part| {
            part.bundle
                .open(&world.key.public(), &id, &app.keys.bundle_secret())
                .unwrap()
        })
        .collect()
}

/// Whether `parts` give the identity's key of `scope` at `epoch`.
fn holds(world: &World, parts: &[KeyBundleContents], epoch: u64, scope: &str) -> bool {
    parts
        .iter()
        .any(|p| p.keys.get(epoch, scope) == Some(world.key.scope_key(epoch, scope)))
}

/// Whether `signer` refuses `app`'s request as a revoked or removed App ID (Dispatch wire 3.9
/// step 4), whether or not it is still listed.
fn refused_for_good(signer: &Signer, app: &App) -> bool {
    matches!(
        signer.review(&app.request, &app.auth),
        Err(SignerError::Refused(Refusal::AppRequest {
            step: AppRequestStep::RemovedApp,
            ..
        }))
    )
}

/// Two apps, `a` and `b`, approved and joined.
async fn two_joined(world: &World, signer: &mut Signer) -> (App, App) {
    let a = App::with_keys(
        AppKeys::from_secrets([3; 32], [4; 32]),
        &["notes", "notes_sync"],
        None,
        [9; 32],
    );
    let b = App::with_keys(
        AppKeys::from_secrets([5; 32], [6; 32]),
        &["notes"],
        None,
        [10; 32],
    );
    world.approve(signer, &a).await;
    world.approve(signer, &b).await;
    (a, b)
}

#[tokio::test]
async fn test_revocation_removes_the_app_at_the_dispatchs_time_and_rotates() {
    let world = World::new();
    let (mut signer, _) = world.enrolled().await;
    let (a, b) = two_joined(&world, &mut signer).await;
    let id = a.keys.app_id_bytes();
    world
        .homeserver
        .set(&app_record_path(&id), b"a's record".to_vec());
    world.clock.advance_ms(DAY_MS);
    let removing = signer.revoke(id, None, confirmed()).await.unwrap();
    // Revoked at the Dispatch first, then removed at that time with the data epoch raised
    // (Dispatch spec 12.2 steps 1 and 3).
    assert!(world.dispatch.app(&id).departed);
    assert!(removing.listed_cert(&id).is_none());
    assert_eq!(
        removing.body().removed,
        [RemovedApp {
            app_id: id,
            distrust_from: START_MS + DAY_MS,
        }]
    );
    assert_eq!(removing.data_epoch(), 2);
    assert_eq!(world.published().unwrap().signed(), removing.signed());
    // The app that stays holds the new epoch's key; the revoked one doesn't (step 2).
    assert!(holds(&world, &opened(&world, &b), 2, "notes"));
    assert!(!holds(&world, &opened(&world, &a), 2, "notes"));
    // Its record is gone, its grant is the user's to revoke, and its App ID stays refused.
    assert!(world.homeserver.file(&app_record_path(&id)).is_none());
    assert!(
        signer
            .alerts()
            .contains(&Alert::GrantRevocationOwed { app_id: id })
    );
    assert!(refused_for_good(&signer, &a));
    world.assert_no_version_sent_twice();
}

#[tokio::test]
async fn test_revocation_takes_an_earlier_distrust_from_and_never_a_later_one() {
    for (picked, expected) in [
        (START_MS + DAY_MS - 3_600_000, START_MS + DAY_MS - 3_600_000),
        (START_MS + 2 * DAY_MS, START_MS + DAY_MS),
    ] {
        let world = World::new();
        let (mut signer, _) = world.enrolled().await;
        let (a, _) = two_joined(&world, &mut signer).await;
        world.clock.advance_ms(DAY_MS);
        let removing = signer
            .revoke(a.keys.app_id_bytes(), Some(picked), confirmed())
            .await
            .unwrap();
        assert_eq!(removing.body().removed[0].distrust_from, expected);
    }
}

#[tokio::test]
async fn test_revocation_keeps_the_app_id_before_the_dispatch_answers() {
    // The Dispatch can't be reached: the revocation is kept, so the App ID is refused already,
    // and the next run sends it.
    let world = World::new();
    let (mut signer, _) = world.enrolled().await;
    let (a, _) = two_joined(&world, &mut signer).await;
    let id = a.keys.app_id_bytes();
    world.dispatch.fail_next(DispatchFault::Unreachable {
        path: "/revoke".into(),
        after: 0,
    });
    signer.revoke(id, None, confirmed()).await.unwrap_err();
    assert!(!world.dispatch.app(&id).departed);
    assert!(refused_for_good(&signer, &a));
    signer.run_due().await.unwrap();
    assert!(world.dispatch.app(&id).departed);
    let doc = signer.identity_doc().unwrap().unwrap();
    assert!(doc.listed_cert(&id).is_none());
}

#[tokio::test]
async fn test_revocation_reaches_the_dispatch_while_an_alarm_holds_signing_back() {
    // The Dispatch went back: an alarm. The revocation still cuts the app off at the Dispatch,
    // which signs nothing new; the version that removes it waits for the alarm to be cleared.
    let world = World::new();
    let (mut signer, _) = world.enrolled().await;
    let (a, _) = two_joined(&world, &mut signer).await;
    let id = a.keys.app_id_bytes();
    let before = signer.identity_doc().unwrap().unwrap();
    signer.set_record_max_age(Some(86_400)).await.unwrap();
    world.dispatch.deliver_identity(&before).unwrap();
    let SignerError::Alarm(alarm) = signer.set_record_max_age(Some(60)).await.unwrap_err() else {
        panic!("no alarm")
    };
    let current = signer.identity_doc().unwrap().unwrap();
    world.dispatch.deliver_identity(&current).unwrap();
    let sent = world.sent_docs().len();
    assert_eq!(
        signer.revoke(id, None, confirmed()).await.unwrap_err(),
        SignerError::Alarm(alarm.clone())
    );
    assert!(world.dispatch.app(&id).departed);
    assert!(refused_for_good(&signer, &a));
    assert_eq!(world.sent_docs().len(), sent);
    // The user is told the app is cut off at the Dispatch and still listed.
    let pending = Alert::RevocationPending {
        app_id: id,
        at_dispatch: true,
    };
    assert!(signer.alerts().contains(&pending));
    // Cleared, the next run removes it, and the alert goes.
    signer
        .clear_alert(&occurrence(&signer, &alarm))
        .await
        .unwrap();
    signer.run_due().await.unwrap();
    let doc = signer.identity_doc().unwrap().unwrap();
    assert!(doc.listed_cert(&id).is_none());
    assert!(!signer.alerts().contains(&pending));
}

#[tokio::test]
async fn test_revocation_takes_the_dispatchs_time_not_the_signers_clock() {
    // The signer's clock runs ten hours ahead of the Dispatch's: `distrust_from` is the time
    // in the revocation's proof (Dispatch wire 7.4.12), and the backup keeps the App ID.
    // The apps are approved first, while the clocks agree: an approval needs them to.
    let world = World::new();
    let (mut signer, memory) = world.enrolled().await;
    let (a, _) = two_joined(&world, &mut signer).await;
    let id = a.keys.app_id_bytes();
    drop(signer);
    let mut env = world.env(memory);
    env.clock = Arc::new(pubky_dispatch_client::clock::TestClock::new(
        START_MS + 10 * 3_600_000,
    ));
    let mut signer = Signer::open(env, world.keyring()).await.unwrap();
    world.clock.advance_ms(DAY_MS);
    let removing = signer.revoke(id, None, confirmed()).await.unwrap();
    assert_eq!(removing.body().removed[0].distrust_from, START_MS + DAY_MS);
    assert!(world.backup().revoked_apps().contains(&id));
}

#[tokio::test]
async fn test_revocation_without_a_time_is_an_error_with_an_alert() {
    // A faulty Dispatch: the app is revoked already, so the answer carries no proof, and
    // `GET /apps` shows no time. The revocation isn't reported done, and the user is told.
    let world = World::new();
    let (mut signer, _) = world.enrolled().await;
    let (a, _) = two_joined(&world, &mut signer).await;
    let id = a.keys.app_id_bytes();
    world.dispatch.revoke(id).unwrap();
    world.dispatch.forget_removal_time(id);
    let error = signer.revoke(id, None, confirmed()).await.unwrap_err();
    assert!(matches!(error, SignerError::InvalidData(_)), "{error:?}");
    assert!(
        signer
            .alerts()
            .contains(&Alert::RevocationUnconfirmed { app_id: id })
    );
    let doc = signer.identity_doc().unwrap().unwrap();
    assert!(doc.listed_cert(&id).is_some());
    assert!(refused_for_good(&signer, &a));
}

#[tokio::test]
async fn test_revocation_goes_out_when_the_backup_cant_be_read() {
    // The Homeserver is down, and the Dispatch's copy is this install's mark: no other install
    // took over there, so the revocation goes out. The removal waits for the Homeserver.
    let world = World::new();
    let (mut signer, _) = world.enrolled().await;
    let (a, _) = two_joined(&world, &mut signer).await;
    let id = a.keys.app_id_bytes();
    *world.homeserver.down.lock().unwrap() = true;
    signer.revoke(id, None, confirmed()).await.unwrap_err();
    assert!(world.dispatch.app(&id).departed);
    assert!(signer.alerts().contains(&Alert::RevocationPending {
        app_id: id,
        at_dispatch: true,
    }));
    *world.homeserver.down.lock().unwrap() = false;
    signer.run_due().await.unwrap();
    assert!(
        signer
            .identity_doc()
            .unwrap()
            .unwrap()
            .listed_cert(&id)
            .is_none()
    );
}

/// Two joined apps, then a Dispatch that goes back a version and still shows it: a rollback
/// alarm is due at the next read of its copy.
async fn rolled_back(world: &World) -> (Signer, App, App) {
    let (mut signer, _) = world.enrolled().await;
    let (a, b) = two_joined(world, &mut signer).await;
    let before = signer.identity_doc().unwrap().unwrap();
    signer.set_record_max_age(Some(86_400)).await.unwrap();
    world.dispatch.deliver_identity(&before).unwrap();
    (signer, a, b)
}

/// A backup holding another install's newer version above `signer`'s newest, for its apps.
fn taken_over_backup(world: &World, signer: &Signer, apps: &[&App]) -> Vec<u8> {
    let newest = signer.identity_doc().unwrap().unwrap();
    let certs: Vec<_> = apps
        .iter()
        .map(|app| world.dispatch.app(&app.keys.app_id_bytes()).cert.unwrap())
        .collect();
    let records = SignerRecords::new(
        IdentityKey::from_secret(SECRET),
        world.other_install_version(&newest, [7; 16]),
        world.backup().account_created(),
        &[],
        &certs,
        Limits::default(),
        &[],
        Some(newest.hash()),
    )
    .unwrap();
    serde_json::to_vec(&SignerBackup::seal(&world.key, &records).unwrap()).unwrap()
}

#[tokio::test]
async fn test_revocation_under_a_rollback_goes_out_whatever_the_backup_read() {
    // The Dispatch shows a rollback, so its copy confirms nothing, and the backup gives no
    // evidence either way: unreachable, missing, or not opening. The revocation goes out in
    // each case, since a take-over shows at the Dispatch first.
    for case in ["unreachable", "missing", "unopenable"] {
        let world = World::new();
        let (mut signer, a, _) = rolled_back(&world).await;
        let id = a.keys.app_id_bytes();
        match case {
            "unreachable" => *world.homeserver.down.lock().unwrap() = true,
            "missing" => {
                world
                    .homeserver
                    .files
                    .lock()
                    .unwrap()
                    .remove(SIGNER_BACKUP_PATH);
            }
            _ => world
                .homeserver
                .set(SIGNER_BACKUP_PATH, b"not a backup".to_vec()),
        }
        signer.revoke(id, None, confirmed()).await.unwrap_err();
        assert!(world.dispatch.app(&id).departed, "{case}");
    }
}

#[tokio::test]
async fn test_revocation_under_a_rollback_isnt_sent_when_the_backup_shows_a_take_over() {
    let world = World::new();
    let (mut signer, a, b) = rolled_back(&world).await;
    let id = a.keys.app_id_bytes();
    let backup = taken_over_backup(&world, &signer, &[&a, &b]);
    world.homeserver.set(SIGNER_BACKUP_PATH, backup);
    assert_eq!(
        signer.revoke(id, None, confirmed()).await.unwrap_err(),
        SignerError::NotNamed { install: [7; 16] }
    );
    assert!(!world.dispatch.app(&id).departed);
}

#[tokio::test]
async fn test_revocation_isnt_sent_for_another_installs_document_at_the_in_flow_version() {
    // A version is in flow, not yet delivered, and the Dispatch holds another install's
    // document at that same version: it isn't the flow's own, so it took over, and no
    // revocation goes out.
    let world = World::new();
    let (mut signer, _) = world.enrolled().await;
    let (a, _) = two_joined(&world, &mut signer).await;
    let id = a.keys.app_id_bytes();
    let newest = signer.identity_doc().unwrap().unwrap();
    world.dispatch.fail_next(DispatchFault::Unreachable {
        path: "/identity".into(),
        after: 0,
    });
    signer.set_record_max_age(Some(86_400)).await.unwrap_err();
    world
        .dispatch
        .deliver_identity(&world.other_install_version(&newest, [7; 16]))
        .unwrap();
    assert_eq!(
        signer.revoke(id, None, confirmed()).await.unwrap_err(),
        SignerError::NotNamed { install: [7; 16] }
    );
    assert!(!world.dispatch.app(&id).departed);
}

#[tokio::test]
async fn test_revocation_isnt_sent_when_the_backup_shows_a_take_over() {
    // The Dispatch's copy is this install's mark, but the backup holds another install's newer
    // version: it took over, so no revocation goes out.
    let world = World::new();
    let (mut signer, _) = world.enrolled().await;
    let (a, b) = two_joined(&world, &mut signer).await;
    let id = a.keys.app_id_bytes();
    let newest = signer.identity_doc().unwrap().unwrap();
    let certs = [
        world.dispatch.app(&id).cert.unwrap(),
        world.dispatch.app(&b.keys.app_id_bytes()).cert.unwrap(),
    ];
    let records = SignerRecords::new(
        IdentityKey::from_secret(SECRET),
        world.other_install_version(&newest, [7; 16]),
        world.backup().account_created(),
        &[],
        &certs,
        Limits::default(),
        &[],
        Some(newest.hash()),
    )
    .unwrap();
    let backup = SignerBackup::seal(&world.key, &records).unwrap();
    world
        .homeserver
        .set(SIGNER_BACKUP_PATH, serde_json::to_vec(&backup).unwrap());
    assert_eq!(
        signer.revoke(id, None, confirmed()).await.unwrap_err(),
        SignerError::NotNamed { install: [7; 16] }
    );
    assert!(!world.dispatch.app(&id).departed);
}

#[tokio::test]
async fn test_revocation_while_a_delivery_answer_is_lost_goes_out_and_the_flow_recovers() {
    // A version reached the Dispatch and its answer was lost. The Dispatch's copy is that
    // version, this install's own in its flow: the revocation goes out, the records aren't
    // taken as behind, and the next run finishes the flow and removes the app.
    let world = World::new();
    let (mut signer, _) = world.enrolled().await;
    let (a, _) = two_joined(&world, &mut signer).await;
    let id = a.keys.app_id_bytes();
    world.dispatch.fail_next(DispatchFault::LoseAnswer {
        path: "/identity".into(),
    });
    signer.set_record_max_age(Some(86_400)).await.unwrap_err();
    signer.revoke(id, None, confirmed()).await.unwrap_err();
    assert!(world.dispatch.app(&id).departed);
    assert!(!matches!(
        signer.status(),
        SignerStatus::RecordsBehind { .. }
    ));
    signer.run_due().await.unwrap();
    let doc = signer.identity_doc().unwrap().unwrap();
    assert!(doc.listed_cert(&id).is_none());
    assert_eq!(doc.body().record_max_age, Some(86_400));
    assert_eq!(signer.status(), SignerStatus::Signing);
}

#[tokio::test]
async fn test_pending_revocation_on_the_error_path_with_a_lost_answer_goes_out() {
    // A revocation's first send failed, then a version's answer was lost, and the run's
    // re-delivery can't connect: the run's error path still revokes at the Dispatch, the
    // records aren't taken as behind, and the next run recovers.
    let world = World::new();
    let (mut signer, _) = world.enrolled().await;
    let (a, _) = two_joined(&world, &mut signer).await;
    let id = a.keys.app_id_bytes();
    world.dispatch.fail_next(DispatchFault::Unreachable {
        path: "/revoke".into(),
        after: 0,
    });
    signer.revoke(id, None, confirmed()).await.unwrap_err();
    world.dispatch.fail_next(DispatchFault::LoseAnswer {
        path: "/identity".into(),
    });
    signer.set_record_max_age(Some(86_400)).await.unwrap_err();
    world.dispatch.fail_next(DispatchFault::Unreachable {
        path: "/identity".into(),
        after: 0,
    });
    signer.run_due().await.unwrap_err();
    assert!(world.dispatch.app(&id).departed);
    assert!(!matches!(
        signer.status(),
        SignerStatus::RecordsBehind { .. }
    ));
    signer.run_due().await.unwrap();
    let doc = signer.identity_doc().unwrap().unwrap();
    assert!(doc.listed_cert(&id).is_none());
    assert_eq!(doc.body().record_max_age, Some(86_400));
}

#[tokio::test]
async fn test_revocation_pending_isnt_at_the_dispatch_when_nothing_was_sent() {
    // The Dispatch can't be reached for the revocation, so it doesn't take it: the alert says
    // the Dispatch still serves the app.
    let world = World::new();
    let (mut signer, _) = world.enrolled().await;
    let (a, _) = two_joined(&world, &mut signer).await;
    let id = a.keys.app_id_bytes();
    world.dispatch.fail_next(DispatchFault::Unreachable {
        path: "/revoke".into(),
        after: 0,
    });
    signer.revoke(id, None, confirmed()).await.unwrap_err();
    assert!(!world.dispatch.app(&id).departed);
    assert!(signer.alerts().contains(&Alert::RevocationPending {
        app_id: id,
        at_dispatch: false,
    }));
}

#[tokio::test]
async fn test_cooperative_closing_skips_a_cut_off_app() {
    // `a` was renewed and took its new certificate, so its renewal is closable; then its
    // revocation is kept but not yet at the Dispatch. Its renewal isn't closed: it goes with
    // the app when the app is removed.
    let world = World::new();
    let (mut signer, _) = world.enrolled().await;
    let (a, _) = two_joined(&world, &mut signer).await;
    let id = a.keys.app_id_bytes();
    let change = CertChange {
        scopes: None,
        expires_at: Some(START_MS + 400 * DAY_MS),
    };
    signer.renew(id, change).await.unwrap();
    let new = world.dispatch.app(&id).renewed.unwrap();
    world.clock.advance_ms(3_600_000);
    let record = pubky_dispatch_core::records::AppRecord::sign(
        &a.keys,
        pubky_dispatch_core::records::AppRecordBody::new(&new, Vec::new(), START_MS + 3_600_000),
    )
    .unwrap();
    world
        .dispatch
        .app_op(
            &a.keys,
            OpKind::AppPut {
                record: record.signed().clone(),
            },
        )
        .unwrap();
    world.dispatch.fail_next(DispatchFault::Unreachable {
        path: "/revoke".into(),
        after: 0,
    });
    signer.revoke(id, None, confirmed()).await.unwrap_err();
    assert!(signer.complete_renewals().await.unwrap().is_empty());
}

#[tokio::test]
async fn test_failing_record_delete_still_raises_the_grant_reminder() {
    // The record's deletion keeps failing: the grant reminder is raised all the same, the
    // run goes on, and the deletion stays owed until it succeeds.
    let world = World::new();
    let (mut signer, _) = world.enrolled().await;
    let (a, _) = two_joined(&world, &mut signer).await;
    let id = a.keys.app_id_bytes();
    world
        .homeserver
        .set(&app_record_path(&id), b"a's record".to_vec());
    *world.homeserver.failing_path.lock().unwrap() = Some(app_record_path(&id));
    signer.revoke(id, None, confirmed()).await.unwrap();
    assert!(
        signer
            .alerts()
            .contains(&Alert::GrantRevocationOwed { app_id: id })
    );
    // Raised once for the owed deletion: cleared, it stays cleared while the deletion
    // keeps failing.
    let reminder = Alert::GrantRevocationOwed { app_id: id };
    signer
        .clear_alert(&occurrence(&signer, &reminder))
        .await
        .unwrap();
    signer.run_due().await.unwrap();
    assert!(world.homeserver.file(&app_record_path(&id)).is_some());
    assert!(!signer.alerts().contains(&reminder));
    *world.homeserver.failing_path.lock().unwrap() = None;
    signer.run_due().await.unwrap();
    assert!(world.homeserver.file(&app_record_path(&id)).is_none());
    assert!(!signer.alerts().contains(&reminder));
}

#[tokio::test]
async fn test_revocation_keeps_the_time_of_its_proof() {
    // The Dispatch takes the revocation, and the delivery that removes the app fails. The time
    // was kept from the revocation's proof: it stands even if the Dispatch's list later shows
    // none.
    let world = World::new();
    let (mut signer, _) = world.enrolled().await;
    let (a, _) = two_joined(&world, &mut signer).await;
    let id = a.keys.app_id_bytes();
    world.dispatch.fail_next(DispatchFault::Unreachable {
        path: "/identity".into(),
        after: 0,
    });
    signer.revoke(id, None, confirmed()).await.unwrap_err();
    assert!(world.dispatch.app(&id).departed);
    world.clock.advance_ms(DAY_MS);
    world.dispatch.forget_removal_time(id);
    signer.run_due().await.unwrap();
    let doc = signer.identity_doc().unwrap().unwrap();
    assert!(doc.listed_cert(&id).is_none());
    assert_eq!(doc.body().removed[0].distrust_from, START_MS);
}

#[tokio::test]
async fn test_revocation_reaches_a_dispatch_that_still_shows_a_rollback() {
    // The Dispatch went back a version and still shows it when the revocation is asked: the
    // alarm doesn't stop the revocation, which signs nothing new.
    let world = World::new();
    let (mut signer, _) = world.enrolled().await;
    let (a, _) = two_joined(&world, &mut signer).await;
    let id = a.keys.app_id_bytes();
    let before = signer.identity_doc().unwrap().unwrap();
    signer.set_record_max_age(Some(86_400)).await.unwrap();
    world.dispatch.deliver_identity(&before).unwrap();
    let error = signer.revoke(id, None, confirmed()).await.unwrap_err();
    assert!(matches!(error, SignerError::Alarm(_)), "{error:?}");
    assert!(world.dispatch.app(&id).departed);
}

#[tokio::test]
async fn test_revocation_isnt_sent_once_another_install_signs() {
    // The Dispatch holds a newer version another install signed: the old signer sends no
    // revocation, and stops as an install that isn't named.
    let world = World::new();
    let (mut signer, _) = world.enrolled().await;
    let (a, _) = two_joined(&world, &mut signer).await;
    let id = a.keys.app_id_bytes();
    let newest = signer.identity_doc().unwrap().unwrap();
    world
        .dispatch
        .deliver_identity(&world.other_install_version(&newest, [7; 16]))
        .unwrap();
    assert_eq!(
        signer.revoke(id, None, confirmed()).await.unwrap_err(),
        SignerError::NotNamed { install: [7; 16] }
    );
    assert!(!world.dispatch.app(&id).departed);
    signer.run_due().await.unwrap_err();
    assert!(!world.dispatch.app(&id).departed);
}

#[tokio::test]
async fn test_revocation_pending_goes_to_the_dispatch_when_an_alarm_stops_the_run() {
    // A revocation's first send failed. Then the publication of a version finds another body
    // on the Homeserver: an alarm, which stops the run. The pending revocation still goes to
    // the Dispatch, which cuts the app off.
    let world = World::new();
    let (mut signer, _) = world.enrolled().await;
    let (a, _) = two_joined(&world, &mut signer).await;
    let id = a.keys.app_id_bytes();
    world.dispatch.fail_next(DispatchFault::Unreachable {
        path: "/revoke".into(),
        after: 0,
    });
    signer.revoke(id, None, confirmed()).await.unwrap_err();
    assert!(!world.dispatch.app(&id).departed);
    *world.homeserver.failing_path.lock().unwrap() = Some(IDENTITY_PATH.into());
    signer.set_record_max_age(Some(86_400)).await.unwrap_err();
    *world.homeserver.failing_path.lock().unwrap() = None;
    let delivered = world.dispatch.identity_doc().unwrap();
    let mut body = delivered.body().clone();
    body.record_max_age = Some(7);
    let other = IdentityDoc::sign(&world.key, body).unwrap();
    world
        .homeserver
        .set(IDENTITY_PATH, serde_json::to_vec(other.signed()).unwrap());
    let error = signer.run_due().await.unwrap_err();
    assert!(matches!(error, SignerError::Alarm(_)), "{error:?}");
    assert!(world.dispatch.app(&id).departed);
}

#[tokio::test]
async fn test_purge_doesnt_strand_the_record_cleanup() {
    // The removed app's record couldn't be deleted yet when its `removed` entry is purged: the
    // deletion still happens at a later run, and the grant reminder with it.
    let world = World::new();
    let (mut signer, _) = world.enrolled().await;
    let (a, _) = two_joined(&world, &mut signer).await;
    let id = a.keys.app_id_bytes();
    world
        .homeserver
        .set(&app_record_path(&id), b"a's record".to_vec());
    *world.homeserver.failing_path.lock().unwrap() = Some(app_record_path(&id));
    signer.revoke(id, None, confirmed()).await.unwrap();
    let _ = signer.purge_removed(id).await;
    assert!(
        world
            .dispatch
            .identity_doc()
            .unwrap()
            .body()
            .removed
            .is_empty()
    );
    assert!(world.homeserver.file(&app_record_path(&id)).is_some());
    *world.homeserver.failing_path.lock().unwrap() = None;
    signer.run_due().await.unwrap();
    assert!(world.homeserver.file(&app_record_path(&id)).is_none());
    assert!(
        signer
            .alerts()
            .contains(&Alert::GrantRevocationOwed { app_id: id })
    );
}

#[tokio::test]
async fn test_revocation_during_a_flow_is_kept_and_completed_after_it() {
    let world = World::new();
    let (mut signer, _) = world.enrolled().await;
    let (a, _) = two_joined(&world, &mut signer).await;
    let id = a.keys.app_id_bytes();
    world.dispatch.fail_next(DispatchFault::Unreachable {
        path: "/identity".into(),
        after: 0,
    });
    signer.set_record_max_age(Some(86_400)).await.unwrap_err();
    assert_eq!(
        signer.revoke(id, None, confirmed()).await.unwrap_err(),
        SignerError::Refused(Refusal::FlowInProgress)
    );
    assert!(refused_for_good(&signer, &a));
    signer.run_due().await.unwrap();
    let doc = signer.identity_doc().unwrap().unwrap();
    assert!(doc.listed_cert(&id).is_none());
    assert_eq!(doc.body().record_max_age, Some(86_400));
}

#[tokio::test]
async fn test_revoked_app_gets_no_keys_even_while_the_dispatch_still_serves_it() {
    // The revocation hasn't reached the Dispatch, which still serves the app and would take
    // its part. A rotation and a full-bundle request give it nothing all the same: the
    // signer's records decide who is cut off (Dispatch spec 12.2).
    let world = World::new();
    let (mut signer, _) = world.enrolled().await;
    let (a, b) = two_joined(&world, &mut signer).await;
    let b_id = b.keys.app_id_bytes();
    world.dispatch.fail_next(DispatchFault::Unreachable {
        path: "/revoke".into(),
        after: 0,
    });
    signer.revoke(b_id, None, confirmed()).await.unwrap_err();
    assert!(!world.dispatch.app(&b_id).departed);
    let renewing = signer
        .renew(
            a.keys.app_id_bytes(),
            CertChange {
                scopes: Some(vec!["notes_sync".into()]),
                expires_at: None,
            },
        )
        .await
        .unwrap();
    assert_eq!(renewing.data_epoch(), 2);
    assert!(!holds(&world, &opened(&world, &b), 2, "notes"));
    world.dispatch.request_full_bundle(b_id);
    assert!(signer.serve_full_bundles().await.unwrap().is_empty());
    assert!(world.dispatch.bundle_parts_of(&b_id).is_empty());
}

#[tokio::test]
async fn test_removal_the_dispatch_reports_raises_an_alert_for_a_departure() {
    // The app left: the removal takes its departure time, and the user is told an app went
    // that this signer didn't revoke.
    let world = World::new();
    let (mut signer, _) = world.enrolled().await;
    let (a, _) = two_joined(&world, &mut signer).await;
    let id = a.keys.app_id_bytes();
    world.clock.advance_ms(DAY_MS);
    world.dispatch.leave(id).unwrap();
    world.clock.advance_ms(DAY_MS);
    signer.run_due().await.unwrap();
    let doc = signer.identity_doc().unwrap().unwrap();
    assert_eq!(doc.body().removed[0].distrust_from, START_MS + DAY_MS);
    assert!(signer.alerts().contains(&Alert::RemovedAtDispatch {
        app_id: id,
        left: true,
    }));
}

#[tokio::test]
async fn test_departure_keeps_its_time_after_a_later_delivery() {
    // The app leaves on day 1, and a version that still lists it is delivered on day 2, as the
    // Dispatch allows while the departure awaits its rotation (Dispatch wire 3.3). The removal is
    // distrusted from day 1, with no alert.
    let world = World::new();
    let (mut signer, _) = world.enrolled().await;
    let (a, _) = two_joined(&world, &mut signer).await;
    let id = a.keys.app_id_bytes();
    world.clock.advance_ms(DAY_MS);
    world.dispatch.leave(id).unwrap();
    world.clock.advance_ms(DAY_MS);
    signer.set_record_max_age(Some(86_400)).await.unwrap();
    signer.run_due().await.unwrap();
    let doc = signer.identity_doc().unwrap().unwrap();
    assert_eq!(doc.body().removed[0].distrust_from, START_MS + DAY_MS);
    assert!(
        !signer
            .alerts()
            .iter()
            .any(|a| matches!(a, Alert::RemovalTimeBounded { .. }))
    );
}

#[tokio::test]
async fn test_removal_time_before_the_app_was_listed_is_raised_to_its_listing() {
    // A faulty Dispatch reports a departure before the version that first listed the app: it
    // can't have left before it was listed, so the removal counts from the listing.
    let world = World::new();
    let (mut signer, _) = world.enrolled().await;
    world.clock.advance_ms(DAY_MS);
    let (a, _) = two_joined(&world, &mut signer).await;
    let id = a.keys.app_id_bytes();
    world.clock.set_ms(START_MS);
    world.dispatch.leave(id).unwrap();
    world.clock.set_ms(START_MS + 2 * DAY_MS);
    signer.run_due().await.unwrap();
    let doc = signer.identity_doc().unwrap().unwrap();
    assert_eq!(doc.body().removed[0].distrust_from, START_MS + DAY_MS);
    assert!(signer.alerts().contains(&Alert::RemovalTimeBounded {
        app_id: id,
        reported: START_MS,
        distrust_from: START_MS + DAY_MS,
    }));
}

#[tokio::test]
async fn test_removal_time_in_the_future_is_lowered_to_the_answers_time() {
    // A faulty Dispatch reports a departure later than the answer that reports it: the removal
    // counts from the answer's time, so the app's later messages don't keep counting.
    let world = World::new();
    let (mut signer, _) = world.enrolled().await;
    let (a, _) = two_joined(&world, &mut signer).await;
    let id = a.keys.app_id_bytes();
    world.clock.set_ms(START_MS + 5 * DAY_MS);
    world.dispatch.leave(id).unwrap();
    world.clock.set_ms(START_MS + DAY_MS);
    signer.run_due().await.unwrap();
    let doc = signer.identity_doc().unwrap().unwrap();
    assert_eq!(doc.body().removed[0].distrust_from, START_MS + DAY_MS);
    assert!(signer.alerts().contains(&Alert::RemovalTimeBounded {
        app_id: id,
        reported: START_MS + 5 * DAY_MS,
        distrust_from: START_MS + DAY_MS,
    }));
}

#[tokio::test]
async fn test_renewal_of_a_cut_off_app_is_refused() {
    // The revocation is kept but hasn't reached the Dispatch: the app gets no new certificate
    // or key from a renewal either.
    let world = World::new();
    let (mut signer, _) = world.enrolled().await;
    let (a, _) = two_joined(&world, &mut signer).await;
    let id = a.keys.app_id_bytes();
    world.dispatch.fail_next(DispatchFault::Unreachable {
        path: "/revoke".into(),
        after: 0,
    });
    signer.revoke(id, None, confirmed()).await.unwrap_err();
    let sent = world.sent_docs().len();
    let change = CertChange {
        scopes: None,
        expires_at: Some(START_MS + 400 * DAY_MS),
    };
    assert_eq!(
        signer.renew(id, change).await.unwrap_err(),
        SignerError::Refused(Refusal::CutOff)
    );
    assert_eq!(world.sent_docs().len(), sent);
    assert!(world.dispatch.app(&id).renewed.is_none());
}

#[tokio::test]
async fn test_revocation_the_dispatch_refuses_doesnt_hold_back_the_run() {
    // `/revoke` keeps failing for `b`: it stays pending with its alert, while `a`'s departure
    // is still completed and the run goes on.
    let world = World::new();
    let (mut signer, _) = world.enrolled().await;
    let (a, b) = two_joined(&world, &mut signer).await;
    let (a_id, b_id) = (a.keys.app_id_bytes(), b.keys.app_id_bytes());
    world.dispatch.fail_next(DispatchFault::Unreachable {
        path: "/revoke".into(),
        after: 0,
    });
    signer.revoke(b_id, None, confirmed()).await.unwrap_err();
    let pending = Alert::RevocationPending {
        app_id: b_id,
        at_dispatch: false,
    };
    assert!(signer.alerts().contains(&pending));
    world.dispatch.leave(a_id).unwrap();
    world.dispatch.fail_next(DispatchFault::Error {
        path: "/revoke".into(),
        code: pubky_dispatch_core::http::ErrorCode::Conflict,
        current: serde_json::Value::Null,
    });
    signer.run_due().await.unwrap();
    let doc = signer.identity_doc().unwrap().unwrap();
    assert!(doc.listed_cert(&a_id).is_none());
    assert!(doc.listed_cert(&b_id).is_some());
    assert!(signer.alerts().contains(&pending));
    // Once the Dispatch takes it, the next run removes `b` and the alert goes.
    signer.run_due().await.unwrap();
    let doc = signer.identity_doc().unwrap().unwrap();
    assert!(doc.listed_cert(&b_id).is_none());
    assert!(!signer.alerts().contains(&pending));
}

#[tokio::test]
async fn test_full_bundle_request_refused_for_one_app_doesnt_hold_back_the_others() {
    // `a`'s renewal stored a newer certificate before it was given up, so the `cert.put` its
    // full-bundle answer needs is refused (`409`, Dispatch wire 6.2). `b`'s request is answered
    // all the same, and `a`'s isn't tried again until it asks anew.
    let world = World::new();
    let (mut signer, _) = world.enrolled().await;
    let (a, b) = two_joined(&world, &mut signer).await;
    let (a_id, b_id) = (a.keys.app_id_bytes(), b.keys.app_id_bytes());
    signer
        .renew(
            a_id,
            CertChange {
                scopes: None,
                expires_at: Some(START_MS + 400 * DAY_MS),
            },
        )
        .await
        .unwrap();
    world.dispatch.fail_next(DispatchFault::Error {
        path: "/identity".into(),
        code: pubky_dispatch_core::http::ErrorCode::BadRequest,
        current: serde_json::Value::Null,
    });
    signer
        .renew(
            a_id,
            CertChange {
                scopes: Some(vec!["notes".into()]),
                expires_at: None,
            },
        )
        .await
        .unwrap_err();
    world.dispatch.request_full_bundle(a_id);
    world.dispatch.request_full_bundle(b_id);
    signer.run_due().await.unwrap();
    assert!(world.dispatch.app(&b_id).full_requested.is_none());
    assert!(world.dispatch.app(&a_id).full_requested.is_some());
    assert!(
        signer
            .alerts()
            .contains(&Alert::FullBundleRefused { app_id: a_id })
    );
    let sent = world.dispatch.applied().len();
    signer.run_due().await.unwrap();
    assert_eq!(world.dispatch.applied().len(), sent);
}

#[tokio::test]
async fn test_revocation_refuses_an_app_that_isnt_listed() {
    let world = World::new();
    let (mut signer, _) = world.enrolled().await;
    let error = signer.revoke([1; 16], None, confirmed()).await.unwrap_err();
    assert_eq!(error, SignerError::Refused(Refusal::NotListed));
    assert!(world.dispatch.app(&[1; 16]).revoked_at.is_none());
}

#[tokio::test]
async fn test_revocation_cut_short_is_completed_at_the_next_run() {
    let world = World::new();
    let (mut signer, _) = world.enrolled().await;
    let (a, b) = two_joined(&world, &mut signer).await;
    let id = a.keys.app_id_bytes();
    world.dispatch.fail_next(DispatchFault::Unreachable {
        path: "/identity".into(),
        after: 0,
    });
    signer.revoke(id, None, confirmed()).await.unwrap_err();
    assert!(world.dispatch.app(&id).departed);
    signer.run_due().await.unwrap();
    let doc = signer.identity_doc().unwrap().unwrap();
    assert!(doc.listed_cert(&id).is_none());
    assert_eq!(doc.data_epoch(), 2);
    assert!(holds(&world, &opened(&world, &b), 2, "notes"));
}

#[tokio::test]
async fn test_revocation_survives_a_crash_at_every_commit() {
    // Under each fault the revocation is asked once and the store is reopened as a restarted
    // process finds it: the app is either never revoked at the Dispatch, or revoked and
    // removed, at the Dispatch's time for its revocation, and nothing is signed twice.
    let revoke = |fault| async move {
        let world = World::new();
        let (mut signer, memory) = world.enrolled().await;
        let (a, _) = two_joined(&world, &mut signer).await;
        world.clock.advance_ms(DAY_MS);
        drop(signer);

        let store = Arc::new(FaultStore::new(memory, fault));
        let mut signer = Signer::open(world.env(store.clone()), world.keyring())
            .await
            .unwrap();
        let result = signer
            .revoke(a.keys.app_id_bytes(), None, confirmed())
            .await;
        (world, a, store, result)
    };
    let commits = {
        let (world, a, store, result) = revoke(Fault::None).await;
        let doc = result.unwrap();
        let id = a.keys.app_id_bytes();
        assert!(world.dispatch.app(&id).departed);
        assert!(doc.listed_cert(&id).is_none());
        store.commits()
    };
    assert!(commits > 0, "revoking an app must commit");

    for n in 1..=commits {
        for fault in [Fault::StopBefore(n), Fault::StopAfter(n)] {
            let (world, a, store, _) = revoke(fault).await;
            assert!(store.stopped(), "{fault:?} did not fire");
            let id = a.keys.app_id_bytes();
            world.clock.advance_ms(DAY_MS);
            let mut restarted = Signer::open(world.env(store.inner()), world.keyring())
                .await
                .unwrap();
            restarted
                .run_due()
                .await
                .unwrap_or_else(|e| panic!("{fault:?}: {e:?}"));
            let doc = restarted.identity_doc().unwrap().unwrap();
            let held = world.dispatch.app(&id);
            // Once the revocation was kept, its App ID is refused, and it reaches the Dispatch.
            let kept = refused_for_good(&restarted, &a);
            assert_eq!(held.departed, kept, "{fault:?}");
            if held.departed {
                assert_eq!(
                    doc.body().removed,
                    [RemovedApp {
                        app_id: id,
                        distrust_from: held.revoked_at.unwrap(),
                    }],
                    "{fault:?}"
                );
                assert!(doc.listed_cert(&id).is_none(), "{fault:?}");
            } else {
                assert!(doc.listed_cert(&id).is_some(), "{fault:?}");
            }
            assert_eq!(
                world.dispatch.identity_doc().unwrap().signed(),
                doc.signed(),
                "{fault:?}"
            );
            world.assert_no_version_sent_twice();
        }
    }
}

#[tokio::test]
async fn test_revocation_the_signer_didnt_ask_for_is_completed_at_the_next_run() {
    // The Dispatch shows a revocation the records don't: the next run removes the app too,
    // and keeps its App ID.
    let world = World::new();
    let (mut signer, _) = world.enrolled().await;
    let (a, _) = two_joined(&world, &mut signer).await;
    let id = a.keys.app_id_bytes();
    world.clock.advance_ms(DAY_MS);
    world.dispatch.revoke(id).unwrap();
    signer.run_due().await.unwrap();
    let doc = signer.identity_doc().unwrap().unwrap();
    assert_eq!(doc.body().removed[0].distrust_from, START_MS + DAY_MS);
    assert!(refused_for_good(&signer, &a));
    assert!(signer.alerts().contains(&Alert::RemovedAtDispatch {
        app_id: id,
        left: false,
    }));
}

#[tokio::test]
async fn test_departure_is_completed_at_the_next_run_from_its_time() {
    // An app leaves (Dispatch spec 12.3): the next run removes it with the departure time as
    // `distrust_from` and rotates, and the Dispatch no longer shows it awaiting its rotation.
    let world = World::new();
    let (mut signer, _) = world.enrolled().await;
    let (a, b) = two_joined(&world, &mut signer).await;
    let id = a.keys.app_id_bytes();
    world.clock.advance_ms(DAY_MS);
    world.dispatch.leave(id).unwrap();
    world.clock.advance_ms(DAY_MS);
    signer.run_due().await.unwrap();
    let doc = signer.identity_doc().unwrap().unwrap();
    assert_eq!(
        doc.body().removed,
        [RemovedApp {
            app_id: id,
            distrust_from: START_MS + DAY_MS,
        }]
    );
    assert_eq!(doc.data_epoch(), 2);
    assert!(holds(&world, &opened(&world, &b), 2, "notes"));
    assert!(refused_for_good(&signer, &a));
    // Nothing more is owed: a second run delivers nothing.
    let sent = world.sent_docs().len();
    signer.run_due().await.unwrap();
    assert_eq!(world.sent_docs().len(), sent);
}

#[tokio::test]
async fn test_revocation_completes_a_given_up_epoch_first() {
    // A reduction's rotation is given up after its batches, so epoch 2's keys went out. The
    // revocation completes epoch 2 in a version of its own, then rotates to 3 (Dispatch spec
    // 3.2, 3.5).
    let world = World::new();
    let (mut signer, _) = world.enrolled().await;
    let (a, b) = two_joined(&world, &mut signer).await;
    world.dispatch.fail_next(DispatchFault::Error {
        path: "/identity".into(),
        code: pubky_dispatch_core::http::ErrorCode::BadRequest,
        current: serde_json::Value::Null,
    });
    signer
        .renew(
            b.keys.app_id_bytes(),
            CertChange {
                scopes: Some(vec!["notes_tags".into()]),
                expires_at: None,
            },
        )
        .await
        .unwrap_err();
    let removing = signer
        .revoke(b.keys.app_id_bytes(), None, confirmed())
        .await
        .unwrap();
    assert_eq!(removing.data_epoch(), 3);
    let completed = world
        .sent_docs()
        .into_iter()
        .find(|d| d.version() + 1 == removing.version())
        .unwrap();
    assert_eq!(completed.data_epoch(), 2);
    // `a` holds epoch 1 from its approval, and epochs 2 and 3 from the stored parts.
    assert!((2..=3).all(|epoch| holds(&world, &opened(&world, &a), epoch, "notes")));
}

#[tokio::test]
async fn test_revocation_record_cleanup_waits_for_the_homeserver() {
    // The record deletion fails: the removal stands, and the deletion is done at the next
    // run.
    let world = World::new();
    let (mut signer, _) = world.enrolled().await;
    let (a, _) = two_joined(&world, &mut signer).await;
    let id = a.keys.app_id_bytes();
    world
        .homeserver
        .set(&app_record_path(&id), b"a's record".to_vec());
    *world.homeserver.failing_path.lock().unwrap() = Some(app_record_path(&id));
    // The removal is done; only the record's deletion waits.
    signer.revoke(id, None, confirmed()).await.unwrap();
    assert!(
        world
            .dispatch
            .identity_doc()
            .unwrap()
            .listed_cert(&id)
            .is_none()
    );
    assert!(world.homeserver.file(&app_record_path(&id)).is_some());
    *world.homeserver.failing_path.lock().unwrap() = None;
    signer.run_due().await.unwrap();
    assert!(world.homeserver.file(&app_record_path(&id)).is_none());
    assert_eq!(
        world.published().unwrap().signed(),
        world.dispatch.identity_doc().unwrap().signed()
    );
}

#[tokio::test]
async fn test_purge_removed_drops_the_entry_and_keeps_the_app_id() {
    let world = World::new();
    let (mut signer, _) = world.enrolled().await;
    let (a, _) = two_joined(&world, &mut signer).await;
    let id = a.keys.app_id_bytes();
    signer.revoke(id, None, confirmed()).await.unwrap();
    let purged = signer.purge_removed(id).await.unwrap();
    assert!(purged.body().removed.is_empty());
    assert!(refused_for_good(&signer, &a));
    assert_eq!(
        signer.purge_removed(id).await.unwrap_err(),
        SignerError::Refused(Refusal::NotRemoved)
    );
}

#[tokio::test]
async fn test_full_bundle_request_gets_every_epoch_and_the_listed_certificate() {
    // `a` is renewed, and its record still carries the earlier certificate. A later
    // rotation's prune lets the signer forget the part it stored for `a`, once `a` passed it,
    // so it can't tell what `a` holds. `a` asks for its full bundle: the signer stores the
    // listed certificate again with `cert.put`, then the parts for every epoch (Dispatch wire
    // 3.5 "Full bundles on request").
    let world = World::new();
    let (mut signer, _) = world.enrolled().await;
    let (a, b) = two_joined(&world, &mut signer).await;
    let id = a.keys.app_id_bytes();
    let extend = || CertChange {
        scopes: None,
        expires_at: Some(START_MS + 400 * DAY_MS),
    };
    signer.renew(id, extend()).await.unwrap();
    signer.renew(b.keys.app_id_bytes(), extend()).await.unwrap();
    let listed = signer
        .identity_doc()
        .unwrap()
        .unwrap()
        .listed_cert(&id)
        .unwrap();
    let cert_puts = |world: &World| {
        world
            .dispatch
            .applied()
            .iter()
            .filter(|op| {
                matches!(&op.body().kind, OpKind::CertPut { target_app_id, .. } if *target_app_id == id)
            })
            .count()
    };
    let before = cert_puts(&world);
    world.dispatch.request_full_bundle(id);
    signer.run_due().await.unwrap();
    assert_eq!(cert_puts(&world), before + 1);
    assert!(world.dispatch.app(&id).full_requested.is_none());
    let parts = opened(&world, &a);
    assert!(parts.iter().any(|p| p.cert == listed));
    assert!(holds(&world, &parts, 1, "notes"));
    // The backup lists the parts, at the same version.
    let newest = signer.identity_doc().unwrap().unwrap();
    assert_eq!(world.backup().identity_doc().signed(), newest.signed());
    // Answered, nothing more is sent.
    let sent = world.dispatch.applied().len();
    signer.run_due().await.unwrap();
    assert_eq!(world.dispatch.applied().len(), sent);
}

#[tokio::test]
async fn test_full_bundle_request_after_the_approval_stores_every_epoch() {
    // The approval's bundle came in its claim, not as stored parts, so the signer can't tell
    // what the app holds: it stores every epoch, once (Dispatch wire 3.5).
    let world = World::new();
    let (mut signer, _) = world.enrolled().await;
    let (a, _) = two_joined(&world, &mut signer).await;
    let id = a.keys.app_id_bytes();
    assert!(world.dispatch.bundle_parts_of(&id).is_empty());
    world.dispatch.request_full_bundle(id);
    assert_eq!(signer.serve_full_bundles().await.unwrap(), [id]);
    assert!(holds(&world, &opened(&world, &a), 1, "notes"));
    assert!(world.dispatch.app(&id).full_requested.is_none());
    assert!(signer.serve_full_bundles().await.unwrap().is_empty());
}

#[tokio::test]
async fn test_revocation_of_an_app_whose_certificate_lapsed_isnt_unconfirmed() {
    // The Dispatch couldn't take the revocation of `a`, whose certificate merely lapsed: `a` is
    // still current in spec 3.4's sense, so this isn't a Dispatch showing no time for a removal.
    // The revocation stays pending, with no `RevocationUnconfirmed`, and the next run sends it.
    let world = World::new();
    let (mut signer, _) = world.enrolled().await;
    let (a, _) = two_joined(&world, &mut signer).await;
    let id = a.keys.app_id_bytes();
    world.clock.advance_ms(800 * DAY_MS);
    world.dispatch.fail_next(DispatchFault::Error {
        path: "/revoke".into(),
        code: pubky_dispatch_core::http::ErrorCode::Unavailable,
        current: serde_json::Value::Null,
    });
    signer.revoke(id, None, confirmed()).await.unwrap_err();
    assert!(
        !signer
            .alerts()
            .contains(&Alert::RevocationUnconfirmed { app_id: id })
    );
    assert!(signer.alerts().iter().any(|alert| matches!(
        alert,
        Alert::RevocationPending { app_id, at_dispatch: false } if *app_id == id
    )));
    assert!(
        signer
            .identity_doc()
            .unwrap()
            .unwrap()
            .listed_cert(&id)
            .is_some()
    );
    let _ = signer.run_due().await;
    let doc = signer.identity_doc().unwrap().unwrap();
    assert!(doc.listed_cert(&id).is_none());
    assert!(doc.body().removed.iter().any(|r| r.app_id == id));
    assert!(
        !signer
            .alerts()
            .contains(&Alert::RevocationUnconfirmed { app_id: id })
    );
}

#[tokio::test]
async fn test_revocation_rotation_serves_apps_by_the_dispatchs_time() {
    // The device clock runs past the other app's certificate's expiry, the Dispatch's time
    // doesn't: the revocation's rotation still gives it the new epoch's keys (Dispatch wire 3.8).
    let world = World::new();
    let (mut signer, memory) = world.enrolled().await;
    let (a, b) = two_joined(&world, &mut signer).await;
    drop(signer);
    let mut env = world.env(memory);
    env.clock = Arc::new(pubky_dispatch_client::clock::TestClock::new(
        START_MS + 400 * DAY_MS,
    ));
    let mut signer = Signer::open(env, world.keyring()).await.unwrap();
    let removing = signer
        .revoke(a.keys.app_id_bytes(), None, confirmed())
        .await
        .unwrap();
    assert_eq!(removing.data_epoch(), 2);
    assert!(holds(&world, &opened(&world, &b), 2, "notes"));
}

/// A signer for `world` on `memory` whose device clock reads `device_ms`, while the Dispatch
/// keeps `world`'s clock.
async fn with_device_clock(world: &World, memory: Arc<MemoryStore>, device_ms: u64) -> Signer {
    let mut env = world.env(memory);
    env.clock = Arc::new(pubky_dispatch_client::clock::TestClock::new(device_ms));
    Signer::open(env, world.keyring()).await.unwrap()
}

/// The default certificate lifetime, 365 days (Dispatch wire 3.1): the apps' certificates,
/// issued at the start, expire then.
const EXPIRY_MS: u64 = START_MS + 365 * DAY_MS;

#[tokio::test]
async fn test_revocation_rotation_skips_an_app_expired_by_the_dispatchs_time() {
    // Just past the other app's expiry by the Dispatch's time, with the device clock a few
    // minutes behind, within the tolerance: the Dispatch doesn't serve it, so the rotation gives
    // it no part (Dispatch wire 3.8).
    let world = World::new();
    let (mut signer, memory) = world.enrolled().await;
    let (a, b) = two_joined(&world, &mut signer).await;
    drop(signer);
    world.clock.set_ms(EXPIRY_MS + 60_000);
    let mut signer = with_device_clock(&world, memory, EXPIRY_MS - 120_000).await;
    signer
        .revoke(a.keys.app_id_bytes(), None, confirmed())
        .await
        .unwrap();
    assert!(!holds(&world, &opened(&world, &b), 2, "notes"));
}

#[tokio::test]
async fn test_full_bundle_request_is_judged_on_the_dispatchs_time() {
    // The device clock runs past the app's certificate's expiry, the Dispatch's time doesn't:
    // the app is served, and its full bundle stored. Just past its expiry by the Dispatch's
    // time, with the device clock a few minutes behind, it isn't (Dispatch wire 3.5).
    let world = World::new();
    let (mut signer, memory) = world.enrolled().await;
    let (a, _) = two_joined(&world, &mut signer).await;
    drop(signer);
    let id = a.keys.app_id_bytes();
    world.dispatch.request_full_bundle(id);
    let mut signer = with_device_clock(&world, memory.clone(), EXPIRY_MS + DAY_MS).await;
    assert_eq!(signer.serve_full_bundles().await.unwrap(), [id]);
    drop(signer);

    let world = World::new();
    let (mut signer, memory) = world.enrolled().await;
    let (a, _) = two_joined(&world, &mut signer).await;
    drop(signer);
    let id = a.keys.app_id_bytes();
    world.dispatch.request_full_bundle(id);
    world.clock.set_ms(EXPIRY_MS + 60_000);
    let mut signer = with_device_clock(&world, memory, EXPIRY_MS - 120_000).await;
    assert!(signer.serve_full_bundles().await.unwrap().is_empty());
    assert!(world.dispatch.app(&id).full_requested.is_some());
}

#[tokio::test]
async fn test_owed_record_cleanup_waits_for_a_fresh_check() {
    // A removed app's record deletion is owed; another install delivers behind this one's
    // back. The next run checks the copies before deleting: it finds the other install
    // signing, and leaves the deletion to it (Dispatch spec 4.3, 12.2 step 4).
    let world = World::new();
    let (mut signer, _) = world.enrolled().await;
    let (a, _) = two_joined(&world, &mut signer).await;
    let id = a.keys.app_id_bytes();
    world
        .homeserver
        .set(&app_record_path(&id), b"a's record".to_vec());
    *world.homeserver.failing_path.lock().unwrap() = Some(app_record_path(&id));
    signer.revoke(id, None, confirmed()).await.unwrap();
    *world.homeserver.failing_path.lock().unwrap() = None;
    let other = world.other_install_version(&signer.identity_doc().unwrap().unwrap(), [9; 16]);
    world.dispatch.deliver_identity(&other).unwrap();
    assert_eq!(
        signer.resume().await.unwrap_err(),
        SignerError::NotNamed { install: [9; 16] }
    );
    assert!(world.homeserver.file(&app_record_path(&id)).is_some());
}

#[tokio::test]
async fn test_revocation_checks_the_dispatch_again_after_completing_a_given_up_epoch() {
    // The revocation completes a given-up epoch in a version of its own, then another
    // install delivers the next version before the rotation goes out. The rotation's batches
    // check the Dispatch before each one (`send_renewal`): the other install is named, and
    // nothing more is sent, no batch and no version (Dispatch spec 4.3, 3.2).
    use pubky_dispatch_client::transport::MockTransport;
    let world = World::new();
    let (mut signer, store) = world.enrolled().await;
    let (_, b) = two_joined(&world, &mut signer).await;
    world.dispatch.fail_next(DispatchFault::Error {
        path: "/identity".into(),
        code: pubky_dispatch_core::http::ErrorCode::BadRequest,
        current: serde_json::Value::Null,
    });
    signer
        .renew(
            b.keys.app_id_bytes(),
            CertChange {
                scopes: Some(vec!["notes_tags".into()]),
                expires_at: None,
            },
        )
        .await
        .unwrap_err();
    drop(signer);
    let dispatch = Arc::clone(&world.dispatch);
    let key = IdentityKey::from_secret(world.key.secret_bytes());
    let other = [7; 16];
    let delivered = Arc::new(std::sync::Mutex::new(false));
    // The writes sent once the other install delivered.
    let after = Arc::new(std::sync::Mutex::new(Vec::new()));
    let writes = Arc::clone(&after);
    let transport = Arc::new(MockTransport::with_handler(move |request| {
        let mut delivered = delivered.lock().unwrap();
        if *delivered && request.method != "GET" {
            writes
                .lock()
                .unwrap()
                .push(format!("{} {}", request.method, request.path_and_query));
        }
        let answer = dispatch.handle(request);
        if request.method == "PUT" && request.path_and_query.ends_with("/identity") && !*delivered {
            // Right after the completing version lands, the other install delivers.
            *delivered = true;
            let mark = dispatch.identity_doc().unwrap();
            let mut body = mark.body().clone();
            body.version += 1;
            body.signer = other;
            dispatch
                .deliver_identity(&IdentityDoc::sign(&key, body).unwrap())
                .unwrap();
        }
        answer
    }));
    let mut env = world.env(store);
    env.transport = transport;
    let mut signer = Signer::open(env, world.keyring()).await.unwrap();
    let error = signer
        .revoke(b.keys.app_id_bytes(), None, confirmed())
        .await
        .unwrap_err();
    assert_eq!(error, SignerError::NotNamed { install: other }, "{error:?}");
    assert_eq!(world.dispatch.identity_doc().unwrap().body().signer, other);
    assert_eq!(
        *after.lock().unwrap(),
        Vec::<String>::new(),
        "nothing more signed"
    );
}

#[tokio::test]
async fn test_full_bundle_request_is_answered_though_the_stored_parts_cover_every_epoch() {
    // `a`'s renewal stored its full bundle, so the parts at the Dispatch already cover every
    // epoch for its listed certificate. `a` asks all the same, as an app that lost its copy
    // does: the signer stores every epoch again, which clears the request (Dispatch wire 3.5).
    let world = World::new();
    let (mut signer, _) = world.enrolled().await;
    let (a, _) = two_joined(&world, &mut signer).await;
    let id = a.keys.app_id_bytes();
    signer
        .renew(
            id,
            CertChange {
                scopes: None,
                expires_at: Some(START_MS + 400 * DAY_MS),
            },
        )
        .await
        .unwrap();
    let current = signer.identity_doc().unwrap().unwrap().data_epoch();
    assert_eq!(world.dispatch.bundles_of(&id), [(1, current)]);
    let stored = world.dispatch.bundle_parts_of(&id);
    world.dispatch.request_full_bundle(id);
    assert_eq!(signer.serve_full_bundles().await.unwrap(), [id]);
    assert!(world.dispatch.app(&id).full_requested.is_none());
    assert_ne!(world.dispatch.bundle_parts_of(&id), stored, "stored again");
    assert!(holds(&world, &opened(&world, &a), 1, "notes"));
    // Answered, nothing more is sent.
    assert!(signer.serve_full_bundles().await.unwrap().is_empty());
}

fn key_bundle_puts(world: &World, id: &[u8; 16]) -> usize {
    world
        .dispatch
        .applied()
        .iter()
        .filter(
            |op| matches!(&op.body().kind, OpKind::KeyBundlePut(put) if put.target_app_id == *id),
        )
        .count()
}

#[tokio::test]
async fn test_full_bundle_request_at_epoch_two_holds_every_epoch_from_one() {
    // A removal rotated the data epoch past 1, and the catch-up stored `a`'s part for the
    // new epoch alone. `a` asks: one range from epoch 1 to the current one, every epoch of
    // both its scopes and no other scope, the request cleared, and the backup records what
    // the Dispatch holds (Dispatch wire 3.5 "Full bundles on request").
    let world = World::new();
    let (mut signer, _) = world.enrolled().await;
    let (a, b) = two_joined(&world, &mut signer).await;
    let id = a.keys.app_id_bytes();
    signer
        .revoke(b.keys.app_id_bytes(), None, confirmed())
        .await
        .unwrap();
    signer.run_due().await.unwrap();
    let current = signer.identity_doc().unwrap().unwrap().data_epoch();
    assert!(current >= 2, "epoch {current}");
    world.dispatch.request_full_bundle(id);
    assert_eq!(signer.serve_full_bundles().await.unwrap(), [id]);
    assert!(world.dispatch.app(&id).full_requested.is_none(), "cleared");
    assert_eq!(world.dispatch.bundles_of(&id), [(1, current)]);
    let parts = opened(&world, &a);
    for epoch in 1..=current {
        assert!(holds(&world, &parts, epoch, "notes"), "notes at {epoch}");
        assert!(
            holds(&world, &parts, epoch, "notes_sync"),
            "notes_sync at {epoch}"
        );
    }
    // Only the listed certificate's scopes.
    assert!(parts.iter().all(|p| {
        p.keys
            .keys
            .iter()
            .all(|k| k.scope == "notes" || k.scope == "notes_sync")
    }));
    // The signer's record and its backup say what the Dispatch holds.
    let backup = world.backup();
    let recorded: Vec<(u64, u64)> = backup
        .bundle_parts()
        .iter()
        .filter(|p| p.app_id == id)
        .map(|p| (p.first_epoch, p.last_epoch))
        .collect();
    assert_eq!(recorded, [(1, current)]);
}

#[tokio::test]
async fn test_full_bundle_second_request_replaces_the_first() {
    // Two requests, each answered with a full bundle: the second's parts replace the first's,
    // one range, the request cleared (Dispatch wire 3.5, 6.2).
    let world = World::new();
    let (mut signer, _) = world.enrolled().await;
    let (a, _) = two_joined(&world, &mut signer).await;
    let id = a.keys.app_id_bytes();
    world.dispatch.request_full_bundle(id);
    assert_eq!(signer.serve_full_bundles().await.unwrap(), [id]);
    let first = world.dispatch.bundle_parts_of(&id);
    world.dispatch.request_full_bundle(id);
    assert_eq!(signer.serve_full_bundles().await.unwrap(), [id]);
    let second = world.dispatch.bundle_parts_of(&id);
    assert_ne!(first, second);
    assert_eq!(world.dispatch.bundles_of(&id).len(), 1);
    assert!(world.dispatch.app(&id).full_requested.is_none());
    assert!(holds(&world, &opened(&world, &a), 1, "notes"));
    assert!(signer.serve_full_bundles().await.unwrap().is_empty());
}

#[tokio::test]
async fn test_full_bundle_lost_answer_is_resumed_with_the_same_parts() {
    // The batch lands and its answer is lost: the flow keeps the signed parts, and the next
    // run sends the same bytes, which the Dispatch takes as stored once (Dispatch wire 3.5).
    let world = World::new();
    let (mut signer, _) = world.enrolled().await;
    let (a, _) = two_joined(&world, &mut signer).await;
    let id = a.keys.app_id_bytes();
    world.dispatch.request_full_bundle(id);
    let before = key_bundle_puts(&world, &id);
    world.dispatch.fail_next(DispatchFault::LoseAnswer {
        path: "/ops".into(),
    });
    signer.serve_full_bundles().await.unwrap_err();
    let landed = world.dispatch.bundle_parts_of(&id);
    assert_eq!(key_bundle_puts(&world, &id), before + landed.len());
    // A later run: the flow goes first, with the same bytes.
    assert!(
        signer.serve_full_bundles().await.is_err(),
        "a flow in progress"
    );
    signer.resume().await.unwrap();
    assert_eq!(
        world.dispatch.bundle_parts_of(&id),
        landed,
        "the same parts"
    );
    assert_eq!(
        key_bundle_puts(&world, &id),
        before + landed.len(),
        "stored once"
    );
    assert!(world.dispatch.app(&id).full_requested.is_none());
    assert!(signer.serve_full_bundles().await.unwrap().is_empty());
}

/// How many `POST /ops` the Dispatch got so far.
fn ops_sent(world: &World) -> usize {
    world
        .transport
        .requests()
        .iter()
        .filter(|r| r.method == "POST" && r.path_and_query.ends_with("/ops"))
        .count()
}

#[tokio::test]
async fn test_full_bundle_request_of_an_app_that_left_is_skipped_quietly() {
    // `b` left, and the signer hasn't processed the departure yet: the Dispatch shows it not
    // current. Its request is skipped: nothing is sent, and no refusal is raised (Dispatch wire
    // 3.5, 7.4.12).
    let world = World::new();
    let (mut signer, _) = world.enrolled().await;
    let (_, b) = two_joined(&world, &mut signer).await;
    let b_id = b.keys.app_id_bytes();
    world.dispatch.request_full_bundle(b_id);
    world.dispatch.leave(b_id).unwrap();
    let sent = ops_sent(&world);
    assert!(signer.serve_full_bundles().await.unwrap().is_empty());
    assert_eq!(ops_sent(&world), sent, "nothing sent");
    assert!(
        !signer
            .alerts()
            .contains(&Alert::FullBundleRefused { app_id: b_id })
    );
}

#[tokio::test]
async fn test_full_bundle_refused_request_isnt_sent_again() {
    // The Dispatch refuses `a`'s full bundle (`409`): the refusal is raised, and the same
    // request isn't sent again at later runs (Dispatch wire 3.5).
    let world = World::new();
    let (mut signer, _) = world.enrolled().await;
    let (a, _) = two_joined(&world, &mut signer).await;
    let a_id = a.keys.app_id_bytes();
    world.dispatch.request_full_bundle(a_id);
    world.dispatch.fail_next(DispatchFault::Error {
        path: "/ops".into(),
        code: pubky_dispatch_core::http::ErrorCode::Conflict,
        current: serde_json::Value::Null,
    });
    assert!(signer.serve_full_bundles().await.unwrap().is_empty());
    assert!(
        signer
            .alerts()
            .contains(&Alert::FullBundleRefused { app_id: a_id })
    );
    let sent = ops_sent(&world);
    for _ in 0..2 {
        assert!(signer.serve_full_bundles().await.unwrap().is_empty());
    }
    assert_eq!(ops_sent(&world), sent, "not sent again");
    assert!(world.dispatch.app(&a_id).full_requested.is_some());
}

#[tokio::test]
async fn test_revocation_shows_and_warns_of_the_open_attempts_it_orphans() {
    // Before the user confirms, the host shows how many attempts the app owns open; the
    // revocation goes on all the same, even after a compromise, and the warning stays while
    // they are open (Dispatch spec 12.2, 10.2).
    let world = World::new();
    let (mut signer, _) = world.enrolled().await;
    let app = App::new(&["notes"], None, [9; 32]);
    world.approve(&mut signer, &app).await;
    let id = app.keys.app_id_bytes();
    world.dispatch.open_attempt([1; 32], [1; 16], id).unwrap();
    world.dispatch.open_attempt([2; 32], [2; 16], id).unwrap();
    assert_eq!(signer.open_attempts(id).await.unwrap(), 2);
    let picked = pubky_dispatch_client::clock::Clock::now_ms(&*world.clock) - 1_000;
    let removed = signer
        .revoke(id, Some(picked), UserConfirmed::shown_and_confirmed())
        .await
        .unwrap();
    assert!(removed.listed_cert(&id).is_none(), "never held back");
    let warning = |open_attempts| Alert::RevokedWithOpenAttempts {
        app_id: id,
        open_attempts,
    };
    assert!(
        signer.alerts().contains(&warning(2)),
        "{:?}",
        signer.alerts()
    );
    world.dispatch.fail_attempt([1; 32], [1; 16], [7; 16]);
    world.dispatch.fail_attempt([2; 32], [2; 16], [7; 16]);
    signer.complete_removals().await.unwrap();
    assert!(
        !signer
            .alerts()
            .iter()
            .any(|alert| matches!(alert, Alert::RevokedWithOpenAttempts { .. })),
        "{:?}",
        signer.alerts()
    );
}

#[tokio::test]
async fn test_revocation_without_open_attempts_warns_of_none() {
    let world = World::new();
    let (mut signer, _) = world.enrolled().await;
    let app = App::new(&["notes"], None, [9; 32]);
    world.approve(&mut signer, &app).await;
    let id = app.keys.app_id_bytes();
    assert_eq!(signer.open_attempts(id).await.unwrap(), 0);
    signer
        .revoke(id, None, UserConfirmed::shown_and_confirmed())
        .await
        .unwrap();
    assert!(
        !signer
            .alerts()
            .iter()
            .any(|alert| matches!(alert, Alert::RevokedWithOpenAttempts { .. }))
    );
}

/// The warnings `signer` holds of a revoked app's open attempts: each app and its count.
fn revoked_warnings(signer: &Signer) -> Vec<([u8; 16], u64)> {
    signer
        .alerts()
        .iter()
        .filter_map(|alert| match alert {
            Alert::RevokedWithOpenAttempts {
                app_id,
                open_attempts,
            } => Some((*app_id, *open_attempts)),
            _ => None,
        })
        .collect()
}

#[tokio::test]
async fn test_revocation_goes_on_when_the_removal_read_fails() {
    // The revocation reaches the Dispatch, and the removal's own read of `GET /apps` doesn't
    // get through: nothing holds it back, and the next run warns of the open attempts and
    // removes the app (Dispatch spec 12.2).
    let world = World::new();
    let (mut signer, _) = world.enrolled().await;
    let app = App::new(&["notes"], None, [9; 32]);
    world.approve(&mut signer, &app).await;
    let id = app.keys.app_id_bytes();
    world.dispatch.open_attempt([1; 32], [1; 16], id).unwrap();
    // The check before the revocation and the revocation go through; the removal's read
    // doesn't.
    world.dispatch.fail_next(DispatchFault::Unreachable {
        path: "/apps".into(),
        after: 2,
    });
    signer
        .revoke(id, None, UserConfirmed::shown_and_confirmed())
        .await
        .unwrap_err();
    assert!(
        world.dispatch.app(&id).revoked_at.is_some(),
        "taken at the Dispatch"
    );
    assert!(revoked_warnings(&signer).is_empty());
    assert!(signer.complete_removals().await.unwrap());
    assert_eq!(revoked_warnings(&signer), vec![(id, 1)]);
    assert!(
        world
            .dispatch
            .identity_doc()
            .unwrap()
            .listed_cert(&id)
            .is_none()
    );
}

#[tokio::test]
async fn test_revocation_warning_stays_current_once_the_app_is_removed() {
    // Once the app is removed its revocation is no longer asked for, and the warning it left
    // is still brought up to date at each read (Dispatch spec 12.2).
    let world = World::new();
    let (mut signer, _) = world.enrolled().await;
    let app = App::new(&["notes"], None, [9; 32]);
    world.approve(&mut signer, &app).await;
    let id = app.keys.app_id_bytes();
    world.dispatch.open_attempt([1; 32], [1; 16], id).unwrap();
    world.dispatch.open_attempt([2; 32], [2; 16], id).unwrap();
    signer
        .revoke(id, None, UserConfirmed::shown_and_confirmed())
        .await
        .unwrap();
    assert_eq!(revoked_warnings(&signer), vec![(id, 2)]);
    signer.complete_removals().await.unwrap();
    signer.complete_removals().await.unwrap();
    assert_eq!(revoked_warnings(&signer), vec![(id, 2)], "still open");
    world.dispatch.fail_attempt([1; 32], [1; 16], [7; 16]);
    signer.run_due().await.unwrap();
    assert_eq!(
        revoked_warnings(&signer),
        vec![(id, 1)],
        "brought up to date"
    );
}

#[tokio::test]
async fn test_revocation_warning_keeps_its_place_among_the_alerts() {
    // Alerts are kept oldest first: a held warning brought up to date keeps its place, and a
    // run that changes nothing writes nothing (Dispatch spec 12.2).
    let world = World::new();
    let (mut signer, _) = world.enrolled().await;
    let first = App::new(&["notes"], None, [9; 32]);
    world.approve(&mut signer, &first).await;
    let second = App::with_keys(
        pubky_dispatch_core::keys::AppKeys::from_secrets([5; 32], [6; 32]),
        &["notes"],
        None,
        [8; 32],
    );
    world.approve(&mut signer, &second).await;
    let (a, b) = (first.keys.app_id_bytes(), second.keys.app_id_bytes());
    world.dispatch.open_attempt([1; 32], [1; 16], a).unwrap();
    world.dispatch.open_attempt([2; 32], [2; 16], a).unwrap();
    world.dispatch.open_attempt([3; 32], [3; 16], b).unwrap();
    for id in [a, b] {
        signer
            .revoke(id, None, UserConfirmed::shown_and_confirmed())
            .await
            .unwrap();
    }
    assert_eq!(revoked_warnings(&signer), vec![(a, 2), (b, 1)]);
    let place = |signer: &Signer| {
        signer.alerts().iter().position(
            |alert| matches!(alert, Alert::RevokedWithOpenAttempts { app_id, .. } if *app_id == a),
        )
    };
    let before = place(&signer);
    assert!(before < Some(signer.alerts().len() - 1), "not last already");
    world.dispatch.fail_attempt([1; 32], [1; 16], [7; 16]);
    signer.complete_removals().await.unwrap();
    assert_eq!(revoked_warnings(&signer), vec![(a, 1), (b, 1)], "in place");
    assert_eq!(place(&signer), before, "its place among all the alerts");
    let alerts = signer.alerts().to_vec();
    signer.complete_removals().await.unwrap();
    assert_eq!(signer.alerts(), alerts.as_slice(), "unchanged");
}

#[tokio::test]
async fn test_revocation_goes_on_when_the_first_read_fails() {
    // The read of the Dispatch's copy before the revocation is answered with an error, signed
    // or not, or never answered: the revocation isn't held back, since it may answer a
    // compromise. It goes to the Dispatch in the same call, and the version that removes the
    // app follows on the next read, which succeeds (Dispatch spec 12.2).
    use pubky_dispatch_core::http::ErrorCode;
    let faults = [
        Some(ErrorCode::Unavailable),
        Some(ErrorCode::RateLimited),
        Some(ErrorCode::StaleTimestamp),
        Some(ErrorCode::NotFound),
        Some(ErrorCode::PermissionMissing),
        None,
    ];
    for code in faults {
        let world = World::new();
        let (mut signer, _) = world.enrolled().await;
        let (a, _) = two_joined(&world, &mut signer).await;
        let id = a.keys.app_id_bytes();
        world.dispatch.fail_next(match code {
            Some(code) => DispatchFault::Error {
                path: "/apps".into(),
                code,
                current: serde_json::Value::Null,
            },
            None => DispatchFault::Unreachable {
                path: "/apps".into(),
                after: 0,
            },
        });
        let doc = signer
            .revoke(id, None, confirmed())
            .await
            .unwrap_or_else(|e| panic!("{code:?}: {e:?}"));
        assert!(world.dispatch.app(&id).departed, "{code:?}");
        assert!(doc.listed_cert(&id).is_none(), "{code:?}");
        assert!(
            doc.body().removed.iter().any(|r| r.app_id == id),
            "{code:?}"
        );
        assert!(
            !signer
                .alerts()
                .iter()
                .any(|a| matches!(a, Alert::RevocationPending { .. })),
            "{code:?}"
        );
    }
}

#[tokio::test]
async fn test_revocation_sent_without_a_read_waits_for_one_to_remove_the_app() {
    // Neither the read before the revocation nor the one after it is answered: the Dispatch
    // takes the revocation all the same, but the version that removes the app isn't signed
    // without a read of the Dispatch's copy. The revocation shows pending at the Dispatch, and
    // the next run removes the app (Dispatch spec 12.2, 4.3).
    let world = World::new();
    let (mut signer, _) = world.enrolled().await;
    let (a, _) = two_joined(&world, &mut signer).await;
    let id = a.keys.app_id_bytes();
    let before = signer.identity_doc().unwrap().unwrap();
    world.dispatch.fail_next(DispatchFault::Error {
        path: "/apps".into(),
        code: pubky_dispatch_core::http::ErrorCode::Unavailable,
        current: serde_json::Value::Null,
    });
    // Past the revocation itself, the next read.
    world.dispatch.fail_next(DispatchFault::Unreachable {
        path: "/apps".into(),
        after: 1,
    });
    signer.revoke(id, None, confirmed()).await.unwrap_err();
    assert!(world.dispatch.app(&id).departed);
    let doc = signer.identity_doc().unwrap().unwrap();
    assert_eq!(doc.hash(), before.hash(), "nothing signed");
    assert!(signer.alerts().iter().any(|alert| matches!(
        alert,
        Alert::RevocationPending { app_id, at_dispatch: true } if *app_id == id
    )));
    signer.run_due().await.unwrap();
    let doc = signer.identity_doc().unwrap().unwrap();
    assert!(doc.listed_cert(&id).is_none());
    assert!(doc.body().removed.iter().any(|r| r.app_id == id));
}

#[tokio::test]
async fn test_revocation_stops_when_the_first_read_cant_be_kept() {
    // The read before the revocation is answered, but the records can't keep what it showed:
    // its commit, which clears `AccountNotHosted`, fails. A store failure isn't a copy that
    // can't be read: the revocation stops there, with nothing sent, and goes on at the next
    // call.
    let world = World::new();
    let (mut signer, memory) = world.enrolled().await;
    let (a, _) = two_joined(&world, &mut signer).await;
    let id = a.keys.app_id_bytes();
    drop(signer);
    let dispatch = Arc::clone(&world.dispatch);
    let transport = Arc::new(
        pubky_dispatch_client::transport::MockTransport::with_handler(move |request| {
            if request.method == "GET" && request.path_and_query.ends_with("/apps") {
                return Ok(pubky_dispatch_client::transport::Response {
                    status: 404,
                    headers: Vec::new(),
                    body: b"{}".to_vec(),
                });
            }
            dispatch.handle(request)
        }),
    );
    let mut env = world.env(memory.clone());
    env.transport = transport;
    let mut signer = Signer::open(env, world.keyring()).await.unwrap();
    signer.run_due().await.unwrap_err();
    assert!(signer.alerts().contains(&Alert::AccountNotHosted));
    drop(signer);
    // Commit 1 keeps the revocation, commit 2 is the read's.
    let faulty: Arc<dyn StateStore> = Arc::new(FaultStore::new(memory, Fault::FailBefore(2)));
    let mut signer = Signer::open(world.env(faulty), world.keyring())
        .await
        .unwrap();
    let error = signer.revoke(id, None, confirmed()).await.unwrap_err();
    assert!(matches!(error, SignerError::Store(_)), "{error:?}");
    assert!(!world.dispatch.app(&id).departed);
    let doc = signer.revoke(id, None, confirmed()).await.unwrap();
    assert!(doc.listed_cert(&id).is_none());
    assert!(world.dispatch.app(&id).departed);
}

#[tokio::test]
async fn test_revocation_goes_on_past_a_copy_that_doesnt_verify() {
    // The Dispatch answers the read before the revocation with a copy of `identity.json` that
    // doesn't verify for the identity: a broken or hostile Dispatch, which shows nothing of
    // who signs. The revocation goes on, as past a copy that can't be read, and the version
    // that removes the app follows the next read, which gives the Dispatch's own copy (Dispatch
    // spec 12.2).
    let world = World::new();
    let (mut signer, _) = world.enrolled().await;
    let (a, _) = two_joined(&world, &mut signer).await;
    let id = a.keys.app_id_bytes();
    let newest = signer.identity_doc().unwrap().unwrap();
    let mut forged = world
        .other_install_version(&newest, [7; 16])
        .signed()
        .clone();
    forged.sig.clone_from(&newest.signed().sig);
    world.dispatch.fail_next(DispatchFault::Replace {
        path: "/apps".into(),
        member: "identity".into(),
        value: serde_json::to_value(&forged).unwrap(),
    });
    let doc = signer.revoke(id, None, confirmed()).await.unwrap();
    assert!(world.dispatch.app(&id).departed);
    assert!(doc.listed_cert(&id).is_none());
    assert!(doc.body().removed.iter().any(|r| r.app_id == id));
}
