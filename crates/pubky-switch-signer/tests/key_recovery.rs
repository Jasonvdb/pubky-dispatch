//! Recovering with the identity key alone against the scripted switch (Switch spec 12.8;
//! Switch wire 3.13 "Restoring"): the backup missing, unreadable, stale, or a losing
//! delivery's, on a new device, in place and over unusable records; each case ends with the
//! recovering install named and signing on. Then the rules that hold it back, what it keeps,
//! and its crash points.

// Test code: a failure is a test failure.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::sync::Arc;

use common::*;
use pubky_switch_client::store::{MemoryStore, StateStore, WriteBatch};
use pubky_switch_client::testing::{Fault as SwitchFault, Router, ScriptedSwitch};
use pubky_switch_core::http::ErrorCode;
use pubky_switch_core::keys::AppKeys;
use pubky_switch_core::records::{
    AppCert, AppRecord, AppRecordBody, IDENTITY_PATH, IdentityDoc, SIGNER_BACKUP_PATH,
    app_record_path,
};
use pubky_switch_signer::state::signer_namespace;
use pubky_switch_signer::{
    Alert, AppFate, BackupFound, KeyRecoveryConfirmed, KeyRecoveryStop, KeyRecoverySurvey,
    RecordsDiscarded, Refusal, Signer, SignerError, SignerStatus, UserConfirmed,
};

fn confirmed() -> UserConfirmed {
    UserConfirmed::shown_and_confirmed()
}

fn refused(stop: KeyRecoveryStop) -> SignerError {
    SignerError::Refused(Refusal::KeyRecovery(stop))
}

/// The survey of a recovery on the store `store`, which holds no usable records.
async fn survey(world: &World, store: &Arc<MemoryStore>) -> Result<KeyRecoverySurvey, SignerError> {
    Signer::survey_key_recovery_new(world.env(store.clone()), world.keyring()).await
}

/// A new install on a store of its own, recovered with the key alone once the user saw the
/// survey, dropping `dropped`.
async fn recovered(world: &World, dropped: &[[u8; 16]]) -> Result<Signer, SignerError> {
    let store = Arc::new(MemoryStore::new());
    let shown = survey(world, &store).await?;
    Signer::restore_new(
        world.env(store),
        world.keyring(),
        KeyRecoveryConfirmed::shown_and_confirmed(&shown, dropped),
    )
    .await
}

/// A new install on a store of its own, restored from the backup.
async fn restored(world: &World) -> Result<Signer, SignerError> {
    Signer::restore_new(
        world.env(Arc::new(MemoryStore::new())),
        world.keyring(),
        confirmed(),
    )
    .await
}

/// In place: the survey, then the restore under its confirmation.
async fn recovered_in_place(signer: &mut Signer) -> Result<IdentityDoc, SignerError> {
    let shown = signer.survey_key_recovery().await?;
    signer
        .restore(KeyRecoveryConfirmed::shown_and_confirmed(&shown, &[]))
        .await
}

/// `app` publishes its record, carrying `cert`, on the Homeserver (Switch spec 4.2).
fn publish_record(world: &World, app: &App, cert: &AppCert) {
    let record =
        AppRecord::sign(&app.keys, AppRecordBody::new(cert, Vec::new(), START_MS)).unwrap();
    world.homeserver.set(
        &app_record_path(&app.keys.app_id_bytes()),
        serde_json::to_vec(record.signed()).unwrap(),
    );
}

/// An app holding `notes`, approved and joined, its record published, with its certificate.
async fn joined(world: &World, signer: &mut Signer, seed: u8) -> (App, AppCert) {
    let app = App::with_keys(
        AppKeys::from_secrets([seed; 32], [seed.wrapping_add(1); 32]),
        &["notes", "notes_sync"],
        None,
        [seed; 32],
    );
    let review = signer.review(&app.request, &app.auth).unwrap();
    let approved = signer.approve(review).await.unwrap();
    signer.claim_delivered(&approved.request).await.unwrap();
    let cert = world.join(&app, &approved);
    publish_record(world, &app, &cert);
    (app, cert)
}

/// A racing delivery won and its owed backup write failed: an install restored on another
/// device, then lost. The backup is the one it restored from; the switch and the Homeserver
/// hold its version.
async fn racer_won_and_lost(world: &World) -> [u8; 16] {
    *world.homeserver.failing_path.lock().unwrap() = Some(SIGNER_BACKUP_PATH.to_owned());
    let racer = restored(world).await.unwrap();
    let install = racer.install_id();
    assert!(racer.alerts().contains(&Alert::BackupNotWritten));
    drop(racer);
    *world.homeserver.failing_path.lock().unwrap() = None;
    install
}

/// A backup holding `doc` and `revoked`, of the account the backup on the Homeserver names.
fn backup_holding(world: &World, doc: &IdentityDoc, revoked: &[[u8; 16]]) -> Vec<u8> {
    let records = pubky_switch_core::records::SignerRecords::new(
        pubky_switch_core::keys::IdentityKey::from_secret(SECRET),
        doc.clone(),
        world.backup().account_created(),
        revoked,
        &[],
        pubky_switch_core::records::Limits::default(),
        &[],
        None,
    )
    .unwrap();
    let backup = pubky_switch_core::records::SignerBackup::seal(&world.key, &records).unwrap();
    serde_json::to_vec(&backup).unwrap()
}

/// The version `signer` delivered last names it, at the switch and on the Homeserver, and
/// it signs on: a later ordinary version is delivered and published.
async fn signs_on(world: &World, signer: &mut Signer) {
    let doc = signer.identity_doc().unwrap().unwrap();
    assert_eq!(doc.body().signer, signer.install_id());
    assert_eq!(world.switch.identity_doc().unwrap().signed(), doc.signed());
    assert_eq!(signer.status(), SignerStatus::Signing);
    let later = signer.set_record_max_age(Some(3_600)).await.unwrap();
    assert_eq!(later.version(), doc.version() + 1);
    assert_eq!(world.published().unwrap().signed(), later.signed());
    assert_eq!(world.backup().identity_doc().signed(), later.signed());
}

#[tokio::test]
async fn test_key_recovery_new_device_after_a_racer_lost_its_backup() {
    // The original sequence of the lock-out: an install restored on another device wins its
    // delivery, its backup write fails, and it is lost. The backup is stale, so a restore is
    // refused; the recovery with the key alone builds on the racer's version.
    let world = World::new();
    let (mut first, _) = world.enrolled().await;
    let (app, _) = joined(&world, &mut first, 3).await;
    let before = first.identity_doc().unwrap().unwrap();
    drop(first);
    let racer = racer_won_and_lost(&world).await;
    // The app's certificate is in the stale backup only.
    world
        .homeserver
        .files
        .lock()
        .unwrap()
        .remove(&app_record_path(&app.keys.app_id_bytes()));
    assert_eq!(
        restored(&world).await.unwrap_err(),
        SignerError::Refused(Refusal::StaleBackup)
    );
    let store = Arc::new(MemoryStore::new());
    let shown = survey(&world, &store).await.unwrap();
    assert_eq!(shown.signer, racer);
    assert_eq!(shown.version, before.version() + 1);
    assert_eq!(
        shown.backup,
        BackupFound::Stale {
            version: before.version()
        }
    );
    assert_eq!(shown.apps, [(app.keys.app_id_bytes(), AppFate::Stays)]);
    let mut signer = Signer::restore_new(
        world.env(store),
        world.keyring(),
        KeyRecoveryConfirmed::shown_and_confirmed(&shown, &[]),
    )
    .await
    .unwrap();
    let doc = signer.identity_doc().unwrap().unwrap();
    assert_eq!(doc.version(), before.version() + 2);
    assert_eq!(doc.body().apps, before.body().apps);
    assert_eq!(doc.generation(), before.generation());
    assert_eq!(doc.data_epoch(), before.data_epoch());
    // Its backup, written once it won.
    assert_eq!(world.backup().identity_doc().signed(), doc.signed());
    signs_on(&world, &mut signer).await;
    world.assert_no_version_sent_twice();
}

#[tokio::test]
async fn test_key_recovery_in_place_after_a_racer_lost_its_backup() {
    // The install the racer took over from is not named; its restore finds the backup stale,
    // and the recovery in place makes it the signer again, as the same install.
    let world = World::new();
    let (mut first, memory) = world.enrolled().await;
    joined(&world, &mut first, 3).await;
    let install = first.install_id();
    drop(first);
    let racer = racer_won_and_lost(&world).await;
    let mut signer = Signer::open(world.env(memory), world.keyring())
        .await
        .unwrap();
    assert_eq!(
        signer.set_record_max_age(Some(60)).await.unwrap_err(),
        SignerError::NotNamed { install: racer }
    );
    assert_eq!(
        signer.restore(confirmed()).await.unwrap_err(),
        SignerError::Refused(Refusal::StaleBackup)
    );
    let doc = recovered_in_place(&mut signer).await.unwrap();
    assert_eq!(doc.body().signer, install);
    signs_on(&world, &mut signer).await;
}

#[tokio::test]
async fn test_key_recovery_over_a_losing_siblings_backup() {
    // The live install removes an app, from a time the user picked, writing its backup
    // first; its delivery doesn't arrive, and a racer's version lands at the switch on the
    // same base. The backup on the Homeserver is that losing sibling, the racer is lost
    // before its own backup, and so is the live install. The picked time is kept.
    let world = World::new();
    let (mut live, _) = world.enrolled().await;
    let (keep, _) = joined(&world, &mut live, 3).await;
    let (gone, _) = joined(&world, &mut live, 5).await;
    let base = live.identity_doc().unwrap().unwrap();
    world.switch.fail_next(SwitchFault::Unreachable {
        path: "/identity".into(),
        after: 0,
    });
    let picked = START_MS - 86_400_000;
    live.revoke(gone.keys.app_id_bytes(), Some(picked), confirmed())
        .await
        .unwrap_err();
    drop(live);
    let racing = world.other_install_version(&base, [7; 16]);
    world.switch.deliver_identity(&racing).unwrap();
    let sibling = world.backup();
    assert_eq!(sibling.identity_doc().version(), racing.version());
    assert_ne!(sibling.identity_doc().hash(), racing.hash());
    assert_eq!(
        restored(&world).await.unwrap_err(),
        SignerError::Refused(Refusal::StaleBackup)
    );
    let store = Arc::new(MemoryStore::new());
    let shown = survey(&world, &store).await.unwrap();
    assert!(shown.apps.contains(&(
        gone.keys.app_id_bytes(),
        AppFate::RemovedAtSwitch {
            distrust_from: Some(picked)
        }
    )));
    let mut signer = Signer::restore_new(
        world.env(store),
        world.keyring(),
        KeyRecoveryConfirmed::shown_and_confirmed(&shown, &[]),
    )
    .await
    .unwrap();
    // The recovery's version, on the racer's, then the removal.
    assert!(
        world
            .sent_docs()
            .iter()
            .any(|doc| doc.version() == racing.version() + 1
                && doc.body().signer == signer.install_id()
                && doc.body().apps == racing.body().apps)
    );
    let newest = signer.identity_doc().unwrap().unwrap();
    let removed: Vec<_> = newest
        .body()
        .removed
        .iter()
        .map(|r| (r.app_id, r.distrust_from))
        .collect();
    assert_eq!(removed, [(gone.keys.app_id_bytes(), picked)]);
    assert!(newest.listed_cert(&keep.keys.app_id_bytes()).is_some());
    signs_on(&world, &mut signer).await;
}

/// An identity with two apps, `kept` whose record is on the Homeserver and `lost` whose
/// record isn't, and its first install dropped.
async fn two_apps(world: &World) -> (App, App, IdentityDoc) {
    let (mut first, _) = world.enrolled().await;
    let (kept, _) = joined(world, &mut first, 3).await;
    let (lost, _) = joined(world, &mut first, 5).await;
    world
        .homeserver
        .files
        .lock()
        .unwrap()
        .remove(&app_record_path(&lost.keys.app_id_bytes()));
    let doc = first.identity_doc().unwrap().unwrap();
    drop(first);
    (kept, lost, doc)
}

#[tokio::test]
async fn test_key_recovery_with_the_backup_missing_corrupt_or_rolled_back() {
    for backup in ["missing", "corrupt", "rolled back"] {
        let world = World::new();
        let (mut first, _) = world.enrolled().await;
        let older = world.homeserver.file(SIGNER_BACKUP_PATH).unwrap();
        let (kept, _) = joined(&world, &mut first, 3).await;
        let (lost, _) = joined(&world, &mut first, 5).await;
        world
            .homeserver
            .files
            .lock()
            .unwrap()
            .remove(&app_record_path(&lost.keys.app_id_bytes()));
        let before = first.identity_doc().unwrap().unwrap();
        drop(first);
        let refusal = match backup {
            "missing" => {
                world
                    .homeserver
                    .files
                    .lock()
                    .unwrap()
                    .remove(SIGNER_BACKUP_PATH);
                Refusal::NoBackup
            }
            "corrupt" => {
                world.homeserver.set(SIGNER_BACKUP_PATH, b"{}".to_vec());
                Refusal::UnreadableBackup
            }
            _ => {
                world.homeserver.set(SIGNER_BACKUP_PATH, older.clone());
                Refusal::StaleBackup
            }
        };
        assert_eq!(
            restored(&world).await.unwrap_err(),
            refusal.into(),
            "{backup}"
        );
        let store = Arc::new(MemoryStore::new());
        let shown = survey(&world, &store).await.unwrap();
        let found = match backup {
            "missing" => BackupFound::Missing,
            "corrupt" => BackupFound::Unreadable,
            _ => BackupFound::Stale { version: 1 },
        };
        assert_eq!(shown.backup, found, "{backup}");
        assert_eq!(
            shown.apps,
            [
                (kept.keys.app_id_bytes(), AppFate::Stays),
                (lost.keys.app_id_bytes(), AppFate::CertificateNotFound)
            ],
            "{backup}"
        );
        let mut signer = Signer::restore_new(
            world.env(store),
            world.keyring(),
            KeyRecoveryConfirmed::shown_and_confirmed(&shown, &[]),
        )
        .await
        .unwrap();
        // The recovery's version, the copy's content, then the one that removes the app whose
        // certificate wasn't found, revoked at the switch first.
        let sent = world.sent_docs();
        let recovery = &sent[sent.len() - 2];
        assert_eq!(recovery.body().apps, before.body().apps, "{backup}");
        assert_eq!(recovery.body().signer, signer.install_id());
        let newest = signer.identity_doc().unwrap().unwrap();
        assert!(newest.listed_cert(&kept.keys.app_id_bytes()).is_some());
        assert!(newest.listed_cert(&lost.keys.app_id_bytes()).is_none());
        assert_eq!(newest.body().removed.len(), 1);
        assert!(
            world
                .switch
                .app(&lost.keys.app_id_bytes())
                .revoked_at
                .is_some()
        );
        assert_eq!(newest.data_epoch(), before.data_epoch() + 1);
        signs_on(&world, &mut signer).await;
    }
}

#[tokio::test]
async fn test_key_recovery_over_unusable_records_with_no_backup() {
    // The local flow doesn't decode and the backup is gone: both confirmations together
    // recover with the key alone, and the version the readable state spent stays spent.
    let world = World::new();
    let (mut first, memory) = world.enrolled().await;
    joined(&world, &mut first, 3).await;
    world.switch.fail_next(SwitchFault::Unreachable {
        path: "/identity".into(),
        after: 0,
    });
    first.set_record_max_age(Some(60)).await.unwrap_err();
    let spent = world.backup().identity_doc().version();
    drop(first);
    damage_flow(&world, &memory);
    world
        .homeserver
        .files
        .lock()
        .unwrap()
        .remove(SIGNER_BACKUP_PATH);
    let shown = survey(&world, &memory).await.unwrap();
    let mut signer = Signer::restore_over_unusable(
        world.env(memory),
        world.keyring(),
        RecordsDiscarded::shown_and_confirmed()
            .and_key_recovery(KeyRecoveryConfirmed::shown_and_confirmed(&shown, &[])),
    )
    .await
    .unwrap();
    let doc = signer.identity_doc().unwrap().unwrap();
    assert!(doc.version() > spent);
    signs_on(&world, &mut signer).await;
}

#[tokio::test]
async fn test_key_recovery_over_damaged_account_binding_without_a_backup() {
    let world = World::new();
    let (first, store) = world.enrolled().await;
    let original = first.identity_doc().unwrap().unwrap();
    drop(first);
    edit_state(&world, &store, |state| {
        state["newest"]["account"] = serde_json::Value::Null;
    });
    world
        .homeserver
        .files
        .lock()
        .unwrap()
        .remove(SIGNER_BACKUP_PATH);
    assert_eq!(
        Signer::restore_over_unusable(
            world.env(store.clone()),
            world.keyring(),
            RecordsDiscarded::shown_and_confirmed()
        )
        .await
        .unwrap_err(),
        SignerError::Refused(Refusal::NoBackup)
    );
    let shown = survey(&world, &store).await.unwrap();
    let signer = Box::pin(Signer::restore_over_unusable(
        world.env(store.clone()),
        world.keyring(),
        RecordsDiscarded::shown_and_confirmed()
            .and_key_recovery(KeyRecoveryConfirmed::shown_and_confirmed(&shown, &[])),
    ))
    .await
    .unwrap();
    let doc = signer.identity_doc().unwrap().unwrap();
    assert!(doc.version() > original.version());
    assert_eq!(doc.generation(), original.generation());
    drop(signer);
    let mut signer = Signer::open(world.env(store), world.keyring())
        .await
        .unwrap();
    signs_on(&world, &mut signer).await;
}

#[tokio::test]
async fn test_key_recovery_in_place_with_records_behind_and_no_backup() {
    // An install put back to an older state, its records behind its own newer version, and
    // the backup unreadable: it recovers in place.
    let world = World::new();
    let (mut first, memory) = world.enrolled().await;
    let (app, _) = joined(&world, &mut first, 3).await;
    world
        .homeserver
        .files
        .lock()
        .unwrap()
        .remove(&app_record_path(&app.keys.app_id_bytes()));
    let install = first.install_id();
    drop(first);
    let earlier: Vec<_> = memory
        .scan(&signer_namespace(&world.key.public()), b"", None, 10)
        .unwrap();
    let mut signer = Signer::open(world.env(memory.clone()), world.keyring())
        .await
        .unwrap();
    signer.set_record_max_age(Some(60)).await.unwrap();
    let second = signer.identity_doc().unwrap().unwrap();
    drop(signer);
    let ns = signer_namespace(&world.key.public());
    let mut batch = WriteBatch::new();
    for (key, value) in earlier {
        batch.put(&ns, key, value).unwrap();
    }
    memory.commit(batch).unwrap();
    world
        .homeserver
        .set(SIGNER_BACKUP_PATH, b"not a backup".to_vec());
    let mut signer = Signer::open(world.env(memory), world.keyring())
        .await
        .unwrap();
    signer.set_record_max_age(Some(61)).await.unwrap_err();
    assert_eq!(
        signer.status(),
        SignerStatus::RecordsBehind {
            version: second.version()
        }
    );
    assert_eq!(
        signer.restore(confirmed()).await.unwrap_err(),
        SignerError::Refused(Refusal::UnreadableBackup)
    );
    let doc = recovered_in_place(&mut signer).await.unwrap();
    assert_eq!(doc.version(), second.version() + 1);
    assert_eq!(doc.body().signer, install);
    // Its certificate came from the records.
    assert!(doc.listed_cert(&app.keys.app_id_bytes()).is_some());
    signs_on(&world, &mut signer).await;
}

#[tokio::test]
async fn test_key_recovery_leaves_a_matching_backup_to_the_restore() {
    // A backup the switch's copy matches is restored from as without the key confirmation:
    // nothing is enrolled and nothing is lost.
    let world = World::new();
    let (mut first, _) = world.enrolled().await;
    joined(&world, &mut first, 3).await;
    let before = first.identity_doc().unwrap().unwrap();
    drop(first);
    let store = Arc::new(MemoryStore::new());
    let shown = survey(&world, &store).await.unwrap();
    assert_eq!(shown.backup, BackupFound::Matches);
    let enrollments = world.distinct_requests("POST", "/enroll");
    let signer = Signer::restore_new(
        world.env(store),
        world.keyring(),
        KeyRecoveryConfirmed::shown_and_confirmed(&shown, &[]),
    )
    .await
    .unwrap();
    assert_eq!(world.distinct_requests("POST", "/enroll"), enrollments);
    let doc = signer.identity_doc().unwrap().unwrap();
    assert_eq!(doc.version(), before.version() + 1);
    assert_eq!(world.backup().identity_doc().signed(), doc.signed());
}

#[tokio::test]
async fn test_key_recovery_lost_race_ends_not_named_and_runs_again() {
    // Two new devices recover at once. The first signs its version, and its delivery doesn't
    // arrive; the second's wins. The first, resumed, finds the other install named, keeps
    // its key, and recovers again in place.
    let world = World::new();
    let (first, _) = world.enrolled().await;
    drop(first);
    world
        .homeserver
        .files
        .lock()
        .unwrap()
        .remove(SIGNER_BACKUP_PATH);
    let late_store = Arc::new(MemoryStore::new());
    let shown = survey(&world, &late_store).await.unwrap();
    world.switch.fail_next(SwitchFault::Unreachable {
        path: "/identity".into(),
        after: 0,
    });
    Signer::restore_new(
        world.env(late_store.clone()),
        world.keyring(),
        KeyRecoveryConfirmed::shown_and_confirmed(&shown, &[]),
    )
    .await
    .unwrap_err();
    let winner = recovered(&world, &[]).await.unwrap();
    let mut late = Signer::open(world.env(late_store), world.keyring())
        .await
        .unwrap();
    assert_eq!(
        late.resume().await.unwrap_err(),
        SignerError::NotNamed {
            install: winner.install_id()
        }
    );
    drop(winner);
    let doc = recovered_in_place(&mut late).await.unwrap();
    assert_eq!(doc.body().signer, late.install_id());
    signs_on(&world, &mut late).await;
}

#[tokio::test]
async fn test_key_recovery_twice_in_a_row_after_a_lost_device() {
    // A recovery wins, its backup write fails, and its device is lost; the next recovery
    // builds on its version.
    let world = World::new();
    let (first, _) = world.enrolled().await;
    drop(first);
    world
        .homeserver
        .files
        .lock()
        .unwrap()
        .remove(SIGNER_BACKUP_PATH);
    *world.homeserver.failing_path.lock().unwrap() = Some(SIGNER_BACKUP_PATH.to_owned());
    let lost = recovered(&world, &[]).await.unwrap();
    assert!(lost.alerts().contains(&Alert::BackupNotWritten));
    let lost_doc = lost.identity_doc().unwrap().unwrap();
    drop(lost);
    *world.homeserver.failing_path.lock().unwrap() = None;
    let mut signer = recovered(&world, &[]).await.unwrap();
    let doc = signer.identity_doc().unwrap().unwrap();
    assert_eq!(doc.version(), lost_doc.version() + 1);
    signs_on(&world, &mut signer).await;
}

#[tokio::test]
async fn test_key_recovery_crash_after_its_commit_resends_the_same_bytes() {
    // The version is committed with the records and sent; the switch takes it and the
    // answer is lost. Opened again, the install sends the same bytes and finds them taken.
    let world = World::new();
    let (first, _) = world.enrolled().await;
    drop(first);
    world
        .homeserver
        .files
        .lock()
        .unwrap()
        .remove(SIGNER_BACKUP_PATH);
    let store = Arc::new(MemoryStore::new());
    let shown = survey(&world, &store).await.unwrap();
    world.switch.fail_next(SwitchFault::LoseAnswer {
        path: "/identity".into(),
    });
    Signer::restore_new(
        world.env(store.clone()),
        world.keyring(),
        KeyRecoveryConfirmed::shown_and_confirmed(&shown, &[]),
    )
    .await
    .unwrap_err();
    let mut signer = Signer::open(world.env(store), world.keyring())
        .await
        .unwrap();
    signer.resume().await.unwrap();
    assert_eq!(world.distinct_requests("PUT", "/identity"), 2);
    signs_on(&world, &mut signer).await;
}

#[tokio::test]
async fn test_key_recovery_crash_before_its_version_goes_on() {
    // The enrollment is committed with fresh records, and its send doesn't arrive: resume
    // goes on with it, and so does the recovery run again on that store.
    for again in [
        "resume",
        "restore_new",
        "over unusable",
        "account unreachable",
        "apps unreachable",
        "copy gone",
    ] {
        let world = World::new();
        let (first, _) = world.enrolled().await;
        drop(first);
        world
            .homeserver
            .files
            .lock()
            .unwrap()
            .remove(SIGNER_BACKUP_PATH);
        let store = Arc::new(MemoryStore::new());
        let shown = survey(&world, &store).await.unwrap();
        let confirmation = KeyRecoveryConfirmed::shown_and_confirmed(&shown, &[]);
        world.switch.fail_next(SwitchFault::Unreachable {
            path: "/enroll".into(),
            after: 0,
        });
        Signer::restore_new(
            world.env(store.clone()),
            world.keyring(),
            confirmation.clone(),
        )
        .await
        .unwrap_err();
        assert_eq!(survey(&world, &store).await.unwrap(), shown);
        let mut signer = match again {
            "restore_new" => Signer::restore_new(world.env(store), world.keyring(), confirmation)
                .await
                .unwrap(),
            "over unusable" => Signer::restore_over_unusable(
                world.env(store),
                world.keyring(),
                RecordsDiscarded::shown_and_confirmed().and_key_recovery(confirmation),
            )
            .await
            .unwrap(),
            _ => {
                let mut signer = Signer::open(world.env(store), world.keyring())
                    .await
                    .unwrap();
                // A read the recovery makes doesn't arrive: it is kept, and goes on.
                let path = match again {
                    "account unreachable" => Some("/account"),
                    "apps unreachable" => Some("/apps"),
                    _ => None,
                };
                // The service the recovery chose stays its own, whatever copy goes since.
                if again == "copy gone" {
                    world.homeserver.files.lock().unwrap().remove(IDENTITY_PATH);
                }
                if let Some(path) = path {
                    world.switch.fail_next(SwitchFault::Unreachable {
                        path: path.into(),
                        after: 0,
                    });
                    signer.resume().await.unwrap_err();
                }
                signer.resume().await.unwrap();
                signer
            }
        };
        signs_on(&world, &mut signer).await;
    }
}

#[tokio::test]
async fn test_key_recovery_refused_before_signing_leaves_nothing() {
    // The survey changes after the enrollment is committed: the records made for the
    // recovery are deleted, and the signer reads as not set up; a new survey recovers.
    let world = World::new();
    let (mut first, _) = world.enrolled().await;
    joined(&world, &mut first, 3).await;
    drop(first);
    world
        .homeserver
        .files
        .lock()
        .unwrap()
        .remove(SIGNER_BACKUP_PATH);
    let store = Arc::new(MemoryStore::new());
    let shown = survey(&world, &store).await.unwrap();
    world.switch.fail_next(SwitchFault::Unreachable {
        path: "/enroll".into(),
        after: 0,
    });
    Signer::restore_new(
        world.env(store.clone()),
        world.keyring(),
        KeyRecoveryConfirmed::shown_and_confirmed(&shown, &[]),
    )
    .await
    .unwrap_err();
    let mut signer = Signer::open(world.env(store.clone()), world.keyring())
        .await
        .unwrap();
    // The app's record leaves the Homeserver: its certificate isn't found any more.
    world
        .homeserver
        .files
        .lock()
        .unwrap()
        .retain(|path, _| !path.contains("/apps/"));
    assert_eq!(
        signer.resume().await.unwrap_err(),
        refused(KeyRecoveryStop::SurveyChanged)
    );
    assert_eq!(
        signer.resume().await.unwrap_err(),
        SignerError::Refused(Refusal::NotSetUp)
    );
    drop(signer);
    assert!(
        store
            .scan(&signer_namespace(&world.key.public()), b"", None, 10)
            .unwrap()
            .is_empty()
    );
    let mut signer = recovered(&world, &[]).await.unwrap();
    signs_on(&world, &mut signer).await;
}

#[tokio::test]
async fn test_key_recovery_in_place_refused_keeps_the_records() {
    // In place, a survey that changed ends the recovery's flow; the records stay as they
    // were.
    let world = World::new();
    let (first, memory) = world.enrolled().await;
    drop(first);
    let racer = racer_won_and_lost(&world).await;
    let mut signer = Signer::open(world.env(memory), world.keyring())
        .await
        .unwrap();
    signer.set_record_max_age(Some(60)).await.unwrap_err();
    let shown = signer.survey_key_recovery().await.unwrap();
    world.switch.fail_next(SwitchFault::Unreachable {
        path: "/enroll".into(),
        after: 0,
    });
    signer
        .restore(KeyRecoveryConfirmed::shown_and_confirmed(&shown, &[]))
        .await
        .unwrap_err();
    let other = world.other_install_version(&world.switch.identity_doc().unwrap(), [8; 16]);
    world.switch.deliver_identity(&other).unwrap();
    assert_eq!(
        signer.resume().await.unwrap_err(),
        refused(KeyRecoveryStop::SurveyChanged)
    );
    assert_eq!(signer.status(), SignerStatus::ManagedBy { install: racer });
    // The flow ended: a restore meets the stale backup, not a flow in progress.
    assert_eq!(
        signer.restore(confirmed()).await.unwrap_err(),
        SignerError::Refused(Refusal::StaleBackup)
    );
    assert!(matches!(
        signer.set_record_max_age(Some(60)).await.unwrap_err(),
        SignerError::NotNamed { .. }
    ));
    let doc = recovered_in_place(&mut signer).await.unwrap();
    assert_eq!(doc.version(), other.version() + 1);
}

#[tokio::test]
async fn test_key_recovery_needs_the_confirmed_survey() {
    // A confirmation of another survey is refused before anything is signed or sent.
    let world = World::new();
    let (mut first, _) = world.enrolled().await;
    joined(&world, &mut first, 3).await;
    drop(first);
    world
        .homeserver
        .files
        .lock()
        .unwrap()
        .remove(SIGNER_BACKUP_PATH);
    let store = Arc::new(MemoryStore::new());
    let shown = survey(&world, &store).await.unwrap();
    world
        .homeserver
        .files
        .lock()
        .unwrap()
        .retain(|path, _| !path.contains("/apps/"));
    let enrollments = world.distinct_requests("POST", "/enroll");
    assert_eq!(
        Signer::restore_new(
            world.env(store),
            world.keyring(),
            KeyRecoveryConfirmed::shown_and_confirmed(&shown, &[]),
        )
        .await
        .unwrap_err(),
        refused(KeyRecoveryStop::SurveyChanged)
    );
    assert_eq!(world.distinct_requests("POST", "/enroll"), enrollments);
}

#[tokio::test]
async fn test_key_recovery_removes_an_app_the_user_dropped() {
    let world = World::new();
    let (mut first, _) = world.enrolled().await;
    let (dropped, _) = joined(&world, &mut first, 3).await;
    let (kept, _) = joined(&world, &mut first, 5).await;
    drop(first);
    world
        .homeserver
        .files
        .lock()
        .unwrap()
        .remove(SIGNER_BACKUP_PATH);
    // An ID the copy doesn't list is no app to drop: it isn't kept as revoked.
    let mut signer = recovered(&world, &[dropped.keys.app_id_bytes(), [9; 16]])
        .await
        .unwrap();
    let newest = signer.identity_doc().unwrap().unwrap();
    assert!(newest.listed_cert(&dropped.keys.app_id_bytes()).is_none());
    assert!(newest.listed_cert(&kept.keys.app_id_bytes()).is_some());
    assert!(!world.backup().revoked_apps().contains(&[9; 16]));
    signs_on(&world, &mut signer).await;
}

#[tokio::test]
async fn test_key_recovery_takes_no_certificate_the_copy_doesnt_name() {
    // The record on the Homeserver at the app's path carries another app's certificate,
    // valid for the identity, but not the one the copy lists: it isn't taken.
    let world = World::new();
    let (kept, lost, _) = two_apps(&world).await;
    let cert = world.switch.app(&kept.keys.app_id_bytes()).cert.unwrap();
    let record =
        AppRecord::sign(&kept.keys, AppRecordBody::new(&cert, Vec::new(), START_MS)).unwrap();
    world.homeserver.set(
        &app_record_path(&lost.keys.app_id_bytes()),
        serde_json::to_vec(record.signed()).unwrap(),
    );
    world
        .homeserver
        .files
        .lock()
        .unwrap()
        .remove(SIGNER_BACKUP_PATH);
    let store = Arc::new(MemoryStore::new());
    let shown = survey(&world, &store).await.unwrap();
    assert!(
        shown
            .apps
            .contains(&(lost.keys.app_id_bytes(), AppFate::CertificateNotFound))
    );
}

#[tokio::test]
async fn test_key_recovery_rule_1_needs_a_serving_account() {
    // The service the copy names holds no account, a staged one, only its mark, or answers
    // the account read or `GET /apps` with an error it signs: the recovery doesn't go ahead
    // there.
    for case in ["erased", "staged", "error", "account error", "mark"] {
        let world = World::new();
        let (first, _) = world.enrolled().await;
        drop(first);
        world
            .homeserver
            .files
            .lock()
            .unwrap()
            .remove(SIGNER_BACKUP_PATH);
        match case {
            "erased" => {
                let created = world.switch.created();
                let following = world.switch.identity_doc().as_ref().map(IdentityDoc::hash);
                world
                    .signer_client(Some(created))
                    .erase(Some(created), following)
                    .await
                    .unwrap();
            }
            "staged" => {
                world.create_after_erasure().await;
            }
            "mark" => world.switch.fail_next(SwitchFault::Replace {
                path: "/account".into(),
                member: "association".into(),
                value: "mark".into(),
            }),
            "account error" => world.switch.fail_next(SwitchFault::Error {
                path: "/account".into(),
                code: ErrorCode::Unavailable,
                current: serde_json::Value::Null,
            }),
            _ => world.switch.fail_next(SwitchFault::Error {
                path: "/apps".into(),
                code: ErrorCode::Staged,
                current: serde_json::Value::Null,
            }),
        }
        let store = Arc::new(MemoryStore::new());
        assert_eq!(
            survey(&world, &store).await.unwrap_err(),
            refused(KeyRecoveryStop::NotServing),
            "{case}"
        );
    }
}

#[tokio::test]
async fn test_key_recovery_rule_2_needs_the_copy_at_that_origin_and_key() {
    // The service's copy names another key, another origin, doesn't verify, or is missing.
    for case in ["key", "origin", "forged", "none", "another signature"] {
        let world = World::new();
        let (first, _) = world.enrolled().await;
        let doc = first.identity_doc().unwrap().unwrap();
        drop(first);
        world
            .homeserver
            .files
            .lock()
            .unwrap()
            .remove(SIGNER_BACKUP_PATH);
        let mut body = doc.body().clone();
        body.version += 1;
        let value = match case {
            "key" => {
                body.inbox.service_key = [9; 32];
                serde_json::to_value(IdentityDoc::sign(&world.key, body).unwrap().signed()).unwrap()
            }
            "origin" => {
                body.inbox.url = "https://other.example".into();
                serde_json::to_value(IdentityDoc::sign(&world.key, body).unwrap().signed()).unwrap()
            }
            "forged" => {
                let other = pubky_switch_core::keys::IdentityKey::from_secret([44; 32]);
                body.identity = other.public();
                serde_json::to_value(IdentityDoc::sign(&other, body).unwrap().signed()).unwrap()
            }
            _ => serde_json::Value::Null,
        };
        if case == "another signature" {
            world.switch.fail_next(SwitchFault::SignWith {
                path: "/apps".into(),
                secret: [33; 32],
            });
        } else {
            world.switch.fail_next(SwitchFault::Replace {
                path: "/apps".into(),
                member: "identity".into(),
                value,
            });
        }
        let store = Arc::new(MemoryStore::new());
        assert_eq!(
            survey(&world, &store).await.unwrap_err(),
            refused(KeyRecoveryStop::SwitchCopy),
            "{case}"
        );
    }
}

#[tokio::test]
async fn test_key_recovery_rule_3_refuses_a_copy_above_the_services() {
    // The service went back to an older version: the Homeserver's copy is newer, by version
    // or generation, or another body at its version; or the backup is above it.
    for case in [
        "version",
        "generation",
        "other body",
        "backup",
        "backup generation",
    ] {
        let world = World::new();
        let (mut first, _) = world.enrolled().await;
        let older = first.identity_doc().unwrap().unwrap();
        let older_backup = world.homeserver.file(SIGNER_BACKUP_PATH).unwrap();
        first.set_record_max_age(Some(60)).await.unwrap();
        let newer = first.identity_doc().unwrap().unwrap();
        drop(first);
        world.switch.deliver_identity(&older).unwrap();
        match case {
            "version" => world.homeserver.set(SIGNER_BACKUP_PATH, older_backup),
            "generation" => {
                // The service holds the newer version; the Homeserver a higher generation at
                // a lower one.
                world.switch.deliver_identity(&newer).unwrap();
                world.homeserver.set(SIGNER_BACKUP_PATH, older_backup);
                let mut body = older.body().clone();
                body.generation += 1;
                body.recovery_from = Some(older.generation());
                let higher = IdentityDoc::sign(&world.key, body).unwrap();
                world
                    .homeserver
                    .set(IDENTITY_PATH, serde_json::to_vec(higher.signed()).unwrap());
            }
            "other body" => {
                world.homeserver.set(SIGNER_BACKUP_PATH, older_backup);
                let mut body = older.body().clone();
                body.record_max_age = Some(7);
                let other = IdentityDoc::sign(&world.key, body).unwrap();
                world
                    .homeserver
                    .set(IDENTITY_PATH, serde_json::to_vec(other.signed()).unwrap());
            }
            "backup" => {
                // A backup above the copy that doesn't build on it: no restore delivers it.
                world
                    .homeserver
                    .set(IDENTITY_PATH, serde_json::to_vec(older.signed()).unwrap());
                let mut body = newer.body().clone();
                body.version += 1;
                let ahead = IdentityDoc::sign(&world.key, body).unwrap();
                world
                    .homeserver
                    .set(SIGNER_BACKUP_PATH, backup_holding(&world, &ahead, &[]));
            }
            _ => {
                world
                    .homeserver
                    .set(IDENTITY_PATH, serde_json::to_vec(older.signed()).unwrap());
                let mut body = older.body().clone();
                body.generation += 1;
                body.recovery_from = Some(older.generation());
                let higher = IdentityDoc::sign(&world.key, body).unwrap();
                world
                    .homeserver
                    .set(SIGNER_BACKUP_PATH, backup_holding(&world, &higher, &[]));
            }
        }
        let seen = match case {
            "version" => newer.version(),
            "backup" => newer.version() + 1,
            _ => older.version(),
        };
        let store = Arc::new(MemoryStore::new());
        assert_eq!(
            survey(&world, &store).await.unwrap_err(),
            refused(KeyRecoveryStop::ServiceBehind {
                switch_version: if case == "generation" {
                    newer.version()
                } else {
                    older.version()
                },
                seen_version: seen,
            }),
            "{case}"
        );
    }
}

/// Rewrite the stored state of `store` with `edit`.
fn edit_state(world: &World, store: &MemoryStore, edit: impl FnOnce(&mut serde_json::Value)) {
    let ns = signer_namespace(&world.key.public());
    let bytes = store.get(&ns, b"state").unwrap().unwrap();
    let mut state: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    edit(&mut state);
    let mut batch = WriteBatch::new();
    batch
        .put(&ns, b"state".to_vec(), serde_json::to_vec(&state).unwrap())
        .unwrap();
    store.commit(batch).unwrap();
}

#[tokio::test]
async fn test_key_recovery_rule_3_in_place_refuses_its_own_newer_marks() {
    // In place: the install's own mark above the service's copy, its records behind a newer
    // version than the copy, or its epochs past the copy's next one.
    for case in ["mark", "records behind", "epoch"] {
        let world = World::new();
        let (mut signer, memory) = world.enrolled().await;
        let older = signer.identity_doc().unwrap().unwrap();
        signer.set_record_max_age(Some(60)).await.unwrap();
        let newer = signer.identity_doc().unwrap().unwrap();
        drop(signer);
        world.homeserver.set(SIGNER_BACKUP_PATH, b"{}".to_vec());
        let (switch_version, seen) = match case {
            "mark" => {
                world.switch.deliver_identity(&older).unwrap();
                world
                    .homeserver
                    .set(IDENTITY_PATH, serde_json::to_vec(older.signed()).unwrap());
                (older.version(), newer.version())
            }
            "records behind" => {
                edit_state(&world, &memory, |state| {
                    state["records_behind"] = (newer.version() + 3).into();
                });
                (newer.version(), newer.version() + 3)
            }
            _ => {
                edit_state(&world, &memory, |state| {
                    state["epoch_through"] = (newer.data_epoch() + 2).into();
                });
                (newer.version(), newer.version())
            }
        };
        let mut signer = Signer::open(world.env(memory), world.keyring())
            .await
            .unwrap();
        assert_eq!(
            signer.survey_key_recovery().await.unwrap_err(),
            refused(KeyRecoveryStop::ServiceBehind {
                switch_version,
                seen_version: seen,
            }),
            "{case}"
        );
    }
}

#[tokio::test]
async fn test_key_recovery_in_place_never_clears_an_alarm_or_a_recovery() {
    // A held alarm, or a provider loss in progress, stops the recovery in place: the alarm
    // is cleared first, and the loss is declared again.
    let world = World::new();
    let (mut signer, memory) = world.enrolled().await;
    let earlier = signer.identity_doc().unwrap().unwrap();
    signer.set_record_max_age(Some(60)).await.unwrap();
    world.switch.deliver_identity(&earlier).unwrap();
    let alarm = signer.set_record_max_age(Some(61)).await.unwrap_err();
    assert!(matches!(alarm, SignerError::Alarm(_)));
    assert_eq!(signer.survey_key_recovery().await.unwrap_err(), alarm);
    drop(signer);
    edit_state(&world, &memory, |state| {
        state["newest"]["account"] = serde_json::Value::Null;
    });
    assert_eq!(survey(&world, &memory).await.unwrap_err(), alarm);

    let world = World::new();
    let (mut signer, _) = world.enrolled().await;
    signer
        .declare_provider_loss("https://nowhere.example", confirmed())
        .await
        .unwrap_err();
    assert_eq!(
        signer.survey_key_recovery().await.unwrap_err(),
        SignerError::Refused(Refusal::FlowInProgress)
    );
}

/// A status of `GET /apps` for an app it doesn't list (Switch wire 7.4.12).
fn status(app: [u8; 16], change: impl FnOnce(&mut serde_json::Value)) -> serde_json::Value {
    let mut status = serde_json::json!({
        "app_id": pubky_switch_core::enc::zbase32_encode(&app),
        "current": false,
        "last_seen": null,
        "revoked_at": null,
        "departed_at": null,
        "awaiting_rotation": false,
        "open_attempts": [],
        "unread_entries": 0,
        "sole_target_unread": 0,
        "record_cert": null,
        "record_at": null,
        "lagging": false,
        "keys_through": null,
        "full_bundle_requested": null,
        "bundle_ranges": [],
        "cert_expires_at": null,
    });
    change(&mut status);
    status
}

#[tokio::test]
async fn test_key_recovery_rule_6_takes_revoked_ids_but_not_pending_apps() {
    // The switch shows App IDs the copy neither lists nor removes: one kept with no record,
    // one revoked, one departed, all revoked for good; one that joined and isn't approved,
    // one current, and one the switch has seen, which aren't.
    let world = World::new();
    let (first, _) = world.enrolled().await;
    drop(first);
    world
        .homeserver
        .files
        .lock()
        .unwrap()
        .remove(SIGNER_BACKUP_PATH);
    let at = pubky_switch_core::time::rfc3339(START_MS);
    let hash = pubky_switch_core::enc::b64(&[1; 32]);
    world.switch.fail_next(SwitchFault::Replace {
        path: "/apps".into(),
        member: "apps".into(),
        value: serde_json::Value::Array(vec![
            status([1; 16], |_| {}),
            status([2; 16], |s| {
                s["revoked_at"] = at.clone().into();
                s["last_seen"] = at.clone().into();
            }),
            status([3; 16], |s| {
                s["departed_at"] = at.clone().into();
                s["last_seen"] = at.clone().into();
            }),
            status([4; 16], |s| s["record_cert"] = hash.clone().into()),
            status([5; 16], |s| s["current"] = true.into()),
            status([6; 16], |s| s["last_seen"] = at.clone().into()),
        ]),
    });
    let store = Arc::new(MemoryStore::new());
    let shown = survey(&world, &store).await.unwrap();
    assert_eq!(shown.revoked, [[1; 16], [2; 16], [3; 16]]);
}

#[tokio::test]
async fn test_key_recovery_owed_backup_waits_for_the_certificates() {
    // The recovery's version lists an app whose certificate wasn't found: its backup can't be
    // sealed, stays owed with the alert, and the next version, which removes that app, writes
    // its own.
    let world = World::new();
    let (_kept, lost, _) = two_apps(&world).await;
    world
        .homeserver
        .files
        .lock()
        .unwrap()
        .remove(SIGNER_BACKUP_PATH);
    // Both sends of the revocation the recovery makes.
    for _ in 0..2 {
        world.switch.fail_next(SwitchFault::Unreachable {
            path: "/revoke".into(),
            after: 0,
        });
    }
    let store = Arc::new(MemoryStore::new());
    let shown = survey(&world, &store).await.unwrap();
    Signer::restore_new(
        world.env(store.clone()),
        world.keyring(),
        KeyRecoveryConfirmed::shown_and_confirmed(&shown, &[]),
    )
    .await
    .unwrap_err();
    assert!(world.homeserver.file(SIGNER_BACKUP_PATH).is_none());
    let mut signer = Signer::open(world.env(store), world.keyring())
        .await
        .unwrap();
    assert!(signer.alerts().contains(&Alert::BackupNotWritten));
    signer.set_record_max_age(Some(60)).await.unwrap();
    let newest = signer.identity_doc().unwrap().unwrap();
    assert!(newest.listed_cert(&lost.keys.app_id_bytes()).is_none());
    assert_eq!(newest.body().record_max_age, Some(60));
    assert_eq!(world.backup().identity_doc().signed(), newest.signed());
    assert!(!signer.alerts().contains(&Alert::BackupNotWritten));
}

#[tokio::test]
async fn test_key_recovery_only_past_a_refused_backup() {
    // The restore from a backup that matches fails for another reason than the backup: the
    // error stands, and no recovery with the key alone is made.
    let world = World::new();
    let (first, _) = world.enrolled().await;
    drop(first);
    let store = Arc::new(MemoryStore::new());
    let shown = survey(&world, &store).await.unwrap();
    world.switch.fail_next(SwitchFault::Error {
        path: "/apps".into(),
        code: ErrorCode::Staged,
        current: serde_json::Value::Null,
    });
    let enrollments = world.distinct_requests("POST", "/enroll");
    let error = Signer::restore_new(
        world.env(store),
        world.keyring(),
        KeyRecoveryConfirmed::shown_and_confirmed(&shown, &[]),
    )
    .await
    .unwrap_err();
    assert!(matches!(error, SignerError::Switch(_)), "{error:?}");
    assert_eq!(world.distinct_requests("POST", "/enroll"), enrollments);
}

#[tokio::test]
async fn test_key_recovery_needs_a_store_without_usable_records() {
    // A store holding usable records is surveyed and recovered in place, not as new.
    let world = World::new();
    let (first, memory) = world.enrolled().await;
    let shown = {
        let mut first = first;
        first.survey_key_recovery().await.unwrap()
    };
    assert_eq!(
        survey(&world, &memory).await.unwrap_err(),
        SignerError::Refused(Refusal::AlreadySetUp)
    );
    assert_eq!(
        Signer::restore_new(
            world.env(memory),
            world.keyring(),
            KeyRecoveryConfirmed::shown_and_confirmed(&shown, &[]),
        )
        .await
        .unwrap_err(),
        SignerError::Refused(Refusal::AlreadySetUp)
    );
}

#[tokio::test]
async fn test_key_recovery_needs_a_copy() {
    // No copy of `identity.json` anywhere: no service to recover at.
    let world = World::new();
    let (first, _) = world.enrolled().await;
    drop(first);
    world.homeserver.files.lock().unwrap().clear();
    let store = Arc::new(MemoryStore::new());
    assert_eq!(
        survey(&world, &store).await.unwrap_err(),
        refused(KeyRecoveryStop::NoCopy)
    );
}

#[tokio::test]
async fn test_key_recovery_refused_after_its_commit_leaves_nothing() {
    // The enrollment's send doesn't arrive; then the account is erased, or the service
    // answers `GET /apps` with an error it signs. The recovery ends, and the records made for
    // it are deleted.
    for case in ["erased", "apps"] {
        let world = World::new();
        let (first, _) = world.enrolled().await;
        drop(first);
        world
            .homeserver
            .files
            .lock()
            .unwrap()
            .remove(SIGNER_BACKUP_PATH);
        let store = Arc::new(MemoryStore::new());
        let shown = survey(&world, &store).await.unwrap();
        world.switch.fail_next(SwitchFault::Unreachable {
            path: "/enroll".into(),
            after: 0,
        });
        Signer::restore_new(
            world.env(store.clone()),
            world.keyring(),
            KeyRecoveryConfirmed::shown_and_confirmed(&shown, &[]),
        )
        .await
        .unwrap_err();
        let mut signer = Signer::open(world.env(store.clone()), world.keyring())
            .await
            .unwrap();
        match case {
            "erased" => {
                let created = world.switch.created();
                let following = world.switch.identity_doc().as_ref().map(IdentityDoc::hash);
                world
                    .signer_client(Some(created))
                    .erase(Some(created), following)
                    .await
                    .unwrap();
            }
            _ => world.switch.fail_next(SwitchFault::Error {
                path: "/apps".into(),
                code: ErrorCode::Staged,
                current: serde_json::Value::Null,
            }),
        }
        assert_eq!(
            signer.resume().await.unwrap_err(),
            refused(KeyRecoveryStop::NotServing),
            "{case}"
        );
        assert!(
            store
                .scan(&signer_namespace(&world.key.public()), b"", None, 10)
                .unwrap()
                .is_empty(),
            "{case}"
        );
    }
}

#[tokio::test]
async fn test_key_recovery_saved_enrollment_cannot_move_to_a_recreated_account() {
    use pubky_switch_client::store::{Fault, FaultStore};

    let world = World::new();
    let (mut old, _) = world.enrolled().await;
    world
        .homeserver
        .files
        .lock()
        .unwrap()
        .remove(SIGNER_BACKUP_PATH);
    let memory = Arc::new(MemoryStore::new());
    let shown = survey(&world, &memory).await.unwrap();
    // The original existing enrollment succeeded; the answer is durable before the
    // signer starts reading the survey again. Its commit acknowledgement is lost.
    let cut = Arc::new(FaultStore::new(memory.clone(), Fault::FailAfter(3)));
    let result = Signer::restore_new(
        world.env(cut),
        world.keyring(),
        KeyRecoveryConfirmed::shown_and_confirmed(&shown, &[]),
    )
    .await;
    assert!(matches!(
        result,
        Err(SignerError::Store(pubky_switch_client::StoreError::Unknown))
    ));
    let created = world.switch.created();
    old.close_account(confirmed()).await.unwrap();
    world.clock.advance_ms(2000);
    let (mut current, _) = world.enrolled().await;
    assert!(world.switch.created() > created);
    world
        .homeserver
        .files
        .lock()
        .unwrap()
        .remove(SIGNER_BACKUP_PATH);
    let current_survey = survey(&world, &memory).await.unwrap();
    assert_ne!(current_survey, shown);
    let before = current.identity_doc().unwrap().unwrap();
    assert_eq!(
        Signer::restore_new(
            world.env(memory),
            world.keyring(),
            KeyRecoveryConfirmed::shown_and_confirmed(&current_survey, &[])
        )
        .await
        .unwrap_err(),
        refused(KeyRecoveryStop::SurveyChanged)
    );
    assert_eq!(
        world.switch.identity_doc().unwrap().signed(),
        before.signed()
    );
    signs_on(&world, &mut current).await;
}

#[tokio::test]
async fn test_key_recovery_in_place_goes_on_under_a_new_confirmation() {
    // In place, the recovery's enrollment doesn't arrive; the user surveys again and
    // confirms, and the recovery goes on from its flow.
    let world = World::new();
    let (first, memory) = world.enrolled().await;
    drop(first);
    racer_won_and_lost(&world).await;
    let mut signer = Signer::open(world.env(memory), world.keyring())
        .await
        .unwrap();
    signer.set_record_max_age(Some(60)).await.unwrap_err();
    let shown = signer.survey_key_recovery().await.unwrap();
    world.switch.fail_next(SwitchFault::Unreachable {
        path: "/enroll".into(),
        after: 0,
    });
    signer
        .restore(KeyRecoveryConfirmed::shown_and_confirmed(&shown, &[]))
        .await
        .unwrap_err();
    let shown = signer.survey_key_recovery().await.unwrap();
    let enrollments = world.distinct_requests("POST", "/enroll");
    signer
        .restore(KeyRecoveryConfirmed::shown_and_confirmed(&shown, &[]))
        .await
        .unwrap();
    // The same enrollment, sent again.
    assert_eq!(world.distinct_requests("POST", "/enroll"), enrollments);
    signs_on(&world, &mut signer).await;
}

/// Revoke `app` with `signer`, then purge it from `removed`: the switch keeps its App ID.
async fn revoked_and_purged(signer: &mut Signer, app: &App) {
    signer
        .revoke(app.keys.app_id_bytes(), None, confirmed())
        .await
        .unwrap();
    signer.purge_removed(app.keys.app_id_bytes()).await.unwrap();
}

/// The next `GET /apps` shows no app.
fn switch_shows_no_apps(world: &World) {
    world.switch.fail_next(SwitchFault::Replace {
        path: "/apps".into(),
        member: "apps".into(),
        value: serde_json::Value::Array(Vec::new()),
    });
}

#[tokio::test]
async fn test_key_recovery_takes_revoked_ids_from_each_source() {
    // An App ID revoked for good that only one source still shows: a copy's `removed`, a
    // stale backup's revoked App IDs, or, in place, the install's own records.
    for case in ["copy", "backup", "records"] {
        let world = World::new();
        let (mut first, memory) = world.enrolled().await;
        let (app, _) = joined(&world, &mut first, 3).await;
        let id = app.keys.app_id_bytes();
        match case {
            "copy" => {
                first.revoke(id, None, confirmed()).await.unwrap();
                world
                    .homeserver
                    .files
                    .lock()
                    .unwrap()
                    .remove(SIGNER_BACKUP_PATH);
            }
            "backup" => {
                revoked_and_purged(&mut first, &app).await;
                racer_won_and_lost(&world).await;
            }
            _ => {
                revoked_and_purged(&mut first, &app).await;
                world
                    .homeserver
                    .files
                    .lock()
                    .unwrap()
                    .remove(SIGNER_BACKUP_PATH);
            }
        }
        drop(first);
        switch_shows_no_apps(&world);
        let shown = match case {
            "records" => {
                let mut signer = Signer::open(world.env(memory), world.keyring())
                    .await
                    .unwrap();
                signer.survey_key_recovery().await.unwrap()
            }
            _ => survey(&world, &Arc::new(MemoryStore::new())).await.unwrap(),
        };
        assert!(shown.revoked.contains(&id), "{case}");
    }
}

#[tokio::test]
async fn test_key_recovery_takes_a_picked_distrust_time_from_each_source() {
    // A revocation the switch never took, with a time the user picked: a stale backup holds
    // it, or, in place, the install's own records.
    for case in ["backup", "records"] {
        let world = World::new();
        let (mut first, memory) = world.enrolled().await;
        let (app, _) = joined(&world, &mut first, 3).await;
        let id = app.keys.app_id_bytes();
        let picked = START_MS - 3_600_000;
        world.switch.fail_next(SwitchFault::Unreachable {
            path: "/revoke".into(),
            after: 0,
        });
        first
            .revoke(id, Some(picked), confirmed())
            .await
            .unwrap_err();
        // The next version's backup holds the revocation with its time.
        first.set_record_max_age(Some(60)).await.unwrap();
        drop(first);
        let shown = match case {
            "backup" => {
                racer_won_and_lost(&world).await;
                survey(&world, &Arc::new(MemoryStore::new())).await.unwrap()
            }
            _ => {
                world.homeserver.set(SIGNER_BACKUP_PATH, b"{}".to_vec());
                let mut signer = Signer::open(world.env(memory), world.keyring())
                    .await
                    .unwrap();
                signer.survey_key_recovery().await.unwrap()
            }
        };
        assert!(
            shown.apps.contains(&(
                id,
                AppFate::RevocationPending {
                    distrust_from: Some(picked)
                }
            )),
            "{case}: {:?}",
            shown.apps
        );
    }
}

#[tokio::test]
async fn test_key_recovery_drops_a_renewal_whose_earlier_certificate_is_gone() {
    // The app renewed its certificate; its record carries the new one, and the earlier one
    // is in no backup: its `renewed` entry goes, with no rotation, and the app stays.
    let world = World::new();
    let (mut first, _) = world.enrolled().await;
    let (app, _) = joined(&world, &mut first, 3).await;
    let id = app.keys.app_id_bytes();
    let change = pubky_switch_signer::CertChange {
        scopes: None,
        expires_at: Some(START_MS + 400 * 86_400_000),
    };
    first.renew(id, change).await.unwrap();
    let renewed = first.identity_doc().unwrap().unwrap();
    assert_eq!(renewed.body().renewed.len(), 1);
    let current = world.switch.app(&id).renewed.unwrap();
    publish_record(&world, &app, &current);
    drop(first);
    world
        .homeserver
        .files
        .lock()
        .unwrap()
        .remove(SIGNER_BACKUP_PATH);
    let store = Arc::new(MemoryStore::new());
    let shown = survey(&world, &store).await.unwrap();
    assert_eq!(shown.apps, [(id, AppFate::Stays)]);
    assert_eq!(shown.renewals_dropped, [id]);
    let mut signer = Signer::restore_new(
        world.env(store),
        world.keyring(),
        KeyRecoveryConfirmed::shown_and_confirmed(&shown, &[]),
    )
    .await
    .unwrap();
    let newest = signer.identity_doc().unwrap().unwrap();
    assert!(newest.body().renewed.is_empty());
    assert!(newest.listed_cert(&id).is_some());
    assert_eq!(newest.data_epoch(), renewed.data_epoch());
    assert_eq!(world.backup().identity_doc().signed(), newest.signed());
    signs_on(&world, &mut signer).await;
}

#[tokio::test]
async fn test_key_recovery_waits_for_a_removal_time_before_removing() {
    // The switch took the revocation of the app whose certificate wasn't found, but shows no
    // time for it: nothing is signed that would list it with no backup possible.
    let world = World::new();
    let (_kept, lost, _) = two_apps(&world).await;
    world
        .homeserver
        .files
        .lock()
        .unwrap()
        .remove(SIGNER_BACKUP_PATH);
    // Both sends of the revocation the recovery makes.
    for _ in 0..2 {
        world.switch.fail_next(SwitchFault::LoseAnswer {
            path: "/revoke".into(),
        });
    }
    let store = Arc::new(MemoryStore::new());
    let shown = survey(&world, &store).await.unwrap();
    let error = Signer::restore_new(
        world.env(store.clone()),
        world.keyring(),
        KeyRecoveryConfirmed::shown_and_confirmed(&shown, &[]),
    )
    .await
    .unwrap_err();
    assert!(matches!(error, SignerError::Switch(_)), "{error:?}");
    world.switch.forget_removal_time(lost.keys.app_id_bytes());
    let mut signer = Signer::open(world.env(store), world.keyring())
        .await
        .unwrap();
    let sent = world.sent_docs().len();
    let error = signer.set_record_max_age(Some(60)).await.unwrap_err();
    assert!(
        matches!(&error, SignerError::InvalidData(e) if e.to_string().contains("7.4.12")),
        "{error:?}"
    );
    assert_eq!(world.sent_docs().len(), sent);
    // Nothing is left in flight: the next call asks the switch again.
    assert_eq!(
        signer.set_record_max_age(Some(60)).await.unwrap_err(),
        error
    );
}

#[tokio::test]
async fn test_key_recovery_removes_past_an_epoch_a_given_up_rotation_sent() {
    // A reduction's rotation stored the next epoch's keys and its version never arrived; the
    // device and the backup are lost. The app whose certificate isn't found is removed at
    // that epoch, which it may hold the keys of, so one more rotation follows.
    let world = World::new();
    let (mut first, _) = world.enrolled().await;
    let (reduced, _) = joined(&world, &mut first, 3).await;
    let (lost, _) = joined(&world, &mut first, 5).await;
    let before = first.identity_doc().unwrap().unwrap();
    world.switch.fail_next(SwitchFault::Unreachable {
        path: "/identity".into(),
        after: 0,
    });
    let change = pubky_switch_signer::CertChange {
        scopes: Some(vec!["notes".into()]),
        expires_at: None,
    };
    first
        .renew(reduced.keys.app_id_bytes(), change)
        .await
        .unwrap_err();
    drop(first);
    assert_eq!(world.switch.identity_doc().unwrap().hash(), before.hash());
    world
        .homeserver
        .files
        .lock()
        .unwrap()
        .remove(SIGNER_BACKUP_PATH);
    world
        .homeserver
        .files
        .lock()
        .unwrap()
        .remove(&app_record_path(&lost.keys.app_id_bytes()));
    let mut signer = recovered(&world, &[]).await.unwrap();
    let newest = signer.identity_doc().unwrap().unwrap();
    assert!(newest.listed_cert(&lost.keys.app_id_bytes()).is_none());
    assert_eq!(newest.data_epoch(), before.data_epoch() + 2);
    signs_on(&world, &mut signer).await;
}

#[tokio::test]
async fn test_key_recovery_closes_a_reduction_after_the_removal() {
    // A reduction delivered, its closing never: the stale backup holds the earlier
    // certificate and the app's record the new one, so the closing is owed; another app's
    // certificate isn't found. The version that removes that app comes first, then the
    // closing.
    let world = World::new();
    let (mut first, _) = world.enrolled().await;
    let (reduced, _) = joined(&world, &mut first, 3).await;
    let older_backup = world.homeserver.file(SIGNER_BACKUP_PATH).unwrap();
    let (lost, _) = joined(&world, &mut first, 5).await;
    let id = reduced.keys.app_id_bytes();
    world.switch.fail_next(SwitchFault::Unreachable {
        path: "/identity".into(),
        after: 1,
    });
    let change = pubky_switch_signer::CertChange {
        scopes: Some(vec!["notes".into()]),
        expires_at: None,
    };
    first.renew(id, change).await.unwrap_err();
    drop(first);
    let open = world.switch.identity_doc().unwrap();
    assert!(
        open.body()
            .renewed
            .iter()
            .any(|r| r.app_id == id && r.until.is_none())
    );
    world.homeserver.set(SIGNER_BACKUP_PATH, older_backup);
    let current = world.switch.app(&id).renewed.unwrap();
    publish_record(&world, &reduced, &current);
    world
        .homeserver
        .files
        .lock()
        .unwrap()
        .remove(&app_record_path(&lost.keys.app_id_bytes()));
    let mut signer = recovered(&world, &[]).await.unwrap();
    let newest = signer.identity_doc().unwrap().unwrap();
    assert!(newest.listed_cert(&lost.keys.app_id_bytes()).is_none());
    assert!(newest.body().renewed.iter().all(|r| r.until.is_some()));
    signs_on(&world, &mut signer).await;
}

/// Damage the store's flow record, so the state stays readable and the records unusable.
fn damage_flow(world: &World, store: &MemoryStore) {
    let ns = signer_namespace(&world.key.public());
    let mut batch = WriteBatch::new();
    batch.put(&ns, b"flow".to_vec(), b"{".to_vec()).unwrap();
    store.commit(batch).unwrap();
}

#[tokio::test]
async fn test_key_recovery_over_unusable_records_keeps_their_floors_and_marks() {
    // The records are unusable, their state readable: its epochs past the service's next
    // one, or its own copy above the service's, stop the recovery.
    for case in ["epoch", "mark", "records behind"] {
        let world = World::new();
        let (mut first, memory) = world.enrolled().await;
        let older = first.identity_doc().unwrap().unwrap();
        first.set_record_max_age(Some(60)).await.unwrap();
        let newer = first.identity_doc().unwrap().unwrap();
        drop(first);
        world
            .homeserver
            .files
            .lock()
            .unwrap()
            .remove(SIGNER_BACKUP_PATH);
        let expected = match case {
            "epoch" => {
                edit_state(&world, &memory, |state| {
                    state["epoch_through"] = (newer.data_epoch() + 2).into();
                });
                (newer.version(), newer.version())
            }
            "records behind" => {
                let seen = newer.version() + 1;
                edit_state(&world, &memory, |state| {
                    state["records_behind"] = seen.into();
                });
                (newer.version(), seen)
            }
            _ => {
                world.switch.deliver_identity(&older).unwrap();
                world
                    .homeserver
                    .set(IDENTITY_PATH, serde_json::to_vec(older.signed()).unwrap());
                (older.version(), newer.version())
            }
        };
        damage_flow(&world, &memory);
        assert_eq!(
            survey(&world, &memory).await.unwrap_err(),
            refused(KeyRecoveryStop::ServiceBehind {
                switch_version: expected.0,
                seen_version: expected.1,
            }),
            "{case}"
        );
    }
}

#[tokio::test]
async fn test_key_recovery_over_unusable_records_keeps_the_signed_distrust_time() {
    // A replacement service started from the last backup before the revocation. The old
    // install's signed copy still holds the time the user picked, even after local damage.
    let old = World::new();
    let (mut first, store) = old.enrolled().await;
    let (app, _) = joined(&old, &mut first, 3).await;
    let id = app.keys.app_id_bytes();
    let backup = old.homeserver.file(SIGNER_BACKUP_PATH).unwrap();
    let picked = START_MS - 3_600_000;
    first.revoke(id, Some(picked), confirmed()).await.unwrap();
    drop(first);
    damage_flow(&old, &store);

    let world = World::new();
    world.homeserver.set(SIGNER_BACKUP_PATH, backup.clone());
    let replacement = Arc::new(MemoryStore::new());
    let loss = Signer::survey_provider_loss_with_key(
        world.env(replacement.clone()),
        world.keyring(),
        pubky_switch_client::testing::SWITCH_ORIGIN,
    )
    .await
    .unwrap();
    let mut signer = Box::pin(Signer::declare_provider_loss_with_key(
        world.env(replacement),
        world.keyring(),
        KeyRecoveryConfirmed::shown_and_confirmed(&loss, &[]),
    ))
    .await
    .unwrap();
    let served = signer.set_record_max_age(Some(60)).await.unwrap();
    assert!(served.listed_cert(&id).is_some());
    drop(signer);
    world
        .homeserver
        .files
        .lock()
        .unwrap()
        .remove(SIGNER_BACKUP_PATH);

    let shown = survey(&world, &store).await.unwrap();
    assert_eq!(
        shown.apps,
        [(
            id,
            AppFate::RevocationPending {
                distrust_from: Some(picked)
            }
        )]
    );
    let confirm = |shown: &KeyRecoverySurvey| {
        RecordsDiscarded::shown_and_confirmed()
            .and_key_recovery(KeyRecoveryConfirmed::shown_and_confirmed(shown, &[]))
    };
    // The older backup reappears after the first confirmation read. The enrollment
    // can go through, but the signer must still ask again before replacing the store.
    let home = Arc::clone(&world.homeserver);
    *world.homeserver.after_get.lock().unwrap() = Some((
        IDENTITY_PATH.into(),
        1,
        Box::new(move || home.set(SIGNER_BACKUP_PATH, backup)),
    ));
    let snapshot = || {
        store
            .scan(&signer_namespace(&world.key.public()), b"", None, 10)
            .unwrap()
    };
    let before = snapshot();
    let enrollments = world.distinct_requests("POST", "/enroll");
    assert_eq!(
        Signer::restore_over_unusable(world.env(store.clone()), world.keyring(), confirm(&shown))
            .await
            .unwrap_err(),
        refused(KeyRecoveryStop::SurveyChanged)
    );
    assert_eq!(world.distinct_requests("POST", "/enroll"), enrollments + 1);
    assert_eq!(snapshot(), before);
    let again = survey(&world, &store).await.unwrap();
    assert!(matches!(again.backup, BackupFound::Stale { .. }));
    assert_eq!(again.apps, shown.apps);
    let mut signer =
        Signer::restore_over_unusable(world.env(store), world.keyring(), confirm(&again))
            .await
            .unwrap();
    let newest = signer.identity_doc().unwrap().unwrap();
    assert!(
        newest
            .body()
            .removed
            .iter()
            .any(|r| r.app_id == id && r.distrust_from == picked)
    );
    signs_on(&world, &mut signer).await;
}

#[tokio::test]
async fn test_key_recovery_over_unusable_records_goes_on_at_the_service_they_named() {
    // The only copy naming the service is the unusable records' own. The recovery's
    // enrollment doesn't arrive: nothing was written over the records, and run again the
    // recovery goes ahead.
    let world = World::new();
    let (first, memory) = world.enrolled().await;
    drop(first);
    world.homeserver.files.lock().unwrap().clear();
    damage_flow(&world, &memory);
    let shown = survey(&world, &memory).await.unwrap();
    let confirmation = KeyRecoveryConfirmed::shown_and_confirmed(&shown, &[]);
    world.switch.fail_next(SwitchFault::Unreachable {
        path: "/enroll".into(),
        after: 0,
    });
    Signer::restore_over_unusable(
        world.env(memory.clone()),
        world.keyring(),
        RecordsDiscarded::shown_and_confirmed().and_key_recovery(confirmation),
    )
    .await
    .unwrap_err();
    let shown_again = survey(&world, &memory).await.unwrap();
    assert_eq!(shown_again, shown);
    let mut signer = Signer::restore_over_unusable(
        world.env(memory),
        world.keyring(),
        RecordsDiscarded::shown_and_confirmed()
            .and_key_recovery(KeyRecoveryConfirmed::shown_and_confirmed(&shown_again, &[])),
    )
    .await
    .unwrap();
    signs_on(&world, &mut signer).await;
}

#[tokio::test]
async fn test_key_recovery_flow_holds_only_an_existing_enrollment() {
    // A stored recovery whose enrollment names App IDs or a document, or another creation
    // than its observation, that isn't signed, or that has none, doesn't load.
    use pubky_switch_core::records::{
        Enrollment, EnrollmentBody, EnrollmentIntent, IdentityPolicy,
    };
    for case in [
        "revoked",
        "document",
        "creation",
        "preparing",
        "observation signature",
        "enrollment signature",
    ] {
        let world = World::new();
        let (first, _) = world.enrolled().await;
        let doc = first.identity_doc().unwrap().unwrap();
        drop(first);
        world
            .homeserver
            .files
            .lock()
            .unwrap()
            .remove(SIGNER_BACKUP_PATH);
        let store = Arc::new(MemoryStore::new());
        let shown = survey(&world, &store).await.unwrap();
        world.switch.fail_next(SwitchFault::Unreachable {
            path: "/enroll".into(),
            after: 0,
        });
        Signer::restore_new(
            world.env(store.clone()),
            world.keyring(),
            KeyRecoveryConfirmed::shown_and_confirmed(&shown, &[]),
        )
        .await
        .unwrap_err();
        let ns = signer_namespace(&world.key.public());
        let bytes = store.get(&ns, b"flow").unwrap().unwrap();
        let mut flow: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        let ready = &mut flow["KeyRecover"]["enrollment"]["Ready"];
        let created = world.switch.created();
        let mut body = EnrollmentBody {
            identity: world.key.public(),
            origin: pubky_switch_client::testing::SWITCH_ORIGIN.into(),
            nonce: [1; 16],
            intent: EnrollmentIntent::Existing { created },
            policy: IdentityPolicy::default(),
            identity_doc: None,
            revoked_apps: None,
        };
        match case {
            "revoked" => body.revoked_apps = Some(vec![[9; 16]]),
            "document" => body.identity_doc = Some(doc.signed().clone()),
            "creation" => {
                body.intent = EnrollmentIntent::Existing {
                    created: created - 1,
                }
            }
            _ => {}
        }
        let flip = |value: &mut serde_json::Value| {
            let text = value.as_str().unwrap().to_owned();
            let mut bytes = pubky_switch_core::enc::unb64(&text).unwrap();
            bytes[0] ^= 1;
            *value = pubky_switch_core::enc::b64(&bytes).into();
        };
        match case {
            "preparing" => {
                flow["KeyRecover"]["enrollment"] = serde_json::json!({ "Preparing": {
                    "nonce": vec![1u8; 16],
                    "policy": serde_json::to_value(IdentityPolicy::default()).unwrap(),
                    "revoked_apps": [],
                }});
            }
            "observation signature" => flip(&mut ready["observation"]["sig"]),
            "enrollment signature" => flip(&mut ready["enrollment"]["sig"]),
            _ => {
                let signed = Enrollment::sign(&world.key, body).unwrap();
                ready["enrollment"] = serde_json::to_value(signed.signed()).unwrap();
            }
        }
        let mut batch = WriteBatch::new();
        batch
            .put(&ns, b"flow".to_vec(), serde_json::to_vec(&flow).unwrap())
            .unwrap();
        store.commit(batch).unwrap();
        assert!(
            Signer::open(world.env(store), world.keyring())
                .await
                .is_err(),
            "{case}"
        );
    }
}

#[tokio::test]
async fn test_key_recovery_survey_binds_the_revoked_set_the_backup_and_the_copy() {
    // Between the survey and its confirmation the switch shows another revoked App ID, the
    // backup goes, or the service takes another version: the recovery is refused.
    for case in ["revoked", "backup", "copy"] {
        let world = World::new();
        let (first, _) = world.enrolled().await;
        drop(first);
        racer_won_and_lost(&world).await;
        let store = Arc::new(MemoryStore::new());
        let shown = survey(&world, &store).await.unwrap();
        match case {
            // The recovery's own read of `GET /apps` comes after the restore's.
            "revoked" => {
                for _ in 0..2 {
                    world.switch.fail_next(SwitchFault::Replace {
                        path: "/apps".into(),
                        member: "apps".into(),
                        value: serde_json::Value::Array(vec![status([1; 16], |_| {})]),
                    });
                }
            }
            "backup" => {
                world
                    .homeserver
                    .files
                    .lock()
                    .unwrap()
                    .remove(SIGNER_BACKUP_PATH);
            }
            _ => {
                let other =
                    world.other_install_version(&world.switch.identity_doc().unwrap(), [8; 16]);
                world.switch.deliver_identity(&other).unwrap();
                world
                    .homeserver
                    .set(IDENTITY_PATH, serde_json::to_vec(other.signed()).unwrap());
            }
        }
        assert_eq!(
            Signer::restore_new(
                world.env(store),
                world.keyring(),
                KeyRecoveryConfirmed::shown_and_confirmed(&shown, &[]),
            )
            .await
            .unwrap_err(),
            refused(KeyRecoveryStop::SurveyChanged),
            "{case}"
        );
    }
}

#[tokio::test]
async fn test_key_recovery_leaves_a_departure_to_the_routine_removal() {
    // A listed app left at the switch: the version after the recovery's removes it as a
    // routine run does, telling the user it left.
    let world = World::new();
    let (mut first, _) = world.enrolled().await;
    let (app, _) = joined(&world, &mut first, 3).await;
    drop(first);
    world.switch.leave(app.keys.app_id_bytes()).unwrap();
    world
        .homeserver
        .files
        .lock()
        .unwrap()
        .remove(SIGNER_BACKUP_PATH);
    let store = Arc::new(MemoryStore::new());
    let shown = survey(&world, &store).await.unwrap();
    assert_eq!(
        shown.apps,
        [(
            app.keys.app_id_bytes(),
            AppFate::RemovedAtSwitch {
                distrust_from: None
            }
        )]
    );
    assert!(!shown.revoked.contains(&app.keys.app_id_bytes()));
    let signer = Signer::restore_new(
        world.env(store),
        world.keyring(),
        KeyRecoveryConfirmed::shown_and_confirmed(&shown, &[]),
    )
    .await
    .unwrap();
    let newest = signer.identity_doc().unwrap().unwrap();
    assert!(newest.listed_cert(&app.keys.app_id_bytes()).is_none());
    assert!(signer.alerts().contains(&Alert::RemovedAtSwitch {
        app_id: app.keys.app_id_bytes(),
        left: true,
    }));
}

#[tokio::test]
async fn test_key_recovery_survey_shows_a_backup_one_version_ahead_as_matching() {
    // The backup's version was signed and not delivered: the restore delivers it first and
    // loses nothing, and the survey says so instead of refusing.
    let world = World::new();
    let (mut first, _) = world.enrolled().await;
    world.switch.fail_next(SwitchFault::Unreachable {
        path: "/identity".into(),
        after: 0,
    });
    first.set_record_max_age(Some(86_400)).await.unwrap_err();
    drop(first);
    let shown = survey(&world, &Arc::new(MemoryStore::new())).await.unwrap();
    assert_eq!(shown.backup, BackupFound::Matches);
}

#[tokio::test]
async fn test_key_recovery_then_a_provider_loss_before_the_removal() {
    // The recovery's version lists an app whose certificate wasn't found, and the service is
    // lost before the version removing it: the provider loss goes on at another service, its
    // backup written once its version has won, and the app is removed there.
    const NEW_ORIGIN: &str = "https://recovery.example";
    let world = World::new();
    let (kept, lost, _) = two_apps(&world).await;
    world
        .homeserver
        .files
        .lock()
        .unwrap()
        .remove(SIGNER_BACKUP_PATH);
    for _ in 0..2 {
        world.switch.fail_next(SwitchFault::Unreachable {
            path: "/revoke".into(),
            after: 0,
        });
    }
    let store = Arc::new(MemoryStore::new());
    let shown = survey(&world, &store).await.unwrap();
    Signer::restore_new(
        world.env(store.clone()),
        world.keyring(),
        KeyRecoveryConfirmed::shown_and_confirmed(&shown, &[]),
    )
    .await
    .unwrap_err();
    let service =
        ScriptedSwitch::unenrolled_at(&world.key, [0x5e; 32], Arc::clone(&world.clock), NEW_ORIGIN);
    let router = Arc::new(Router::new());
    router.add_switch(NEW_ORIGIN, &service);
    let mut env = world.env(store);
    env.transport = router.clone();
    let mut signer = Signer::open(env, world.keyring()).await.unwrap();
    signer
        .declare_provider_loss(NEW_ORIGIN, confirmed())
        .await
        .unwrap();
    let newest = signer.identity_doc().unwrap().unwrap();
    assert_eq!(newest.inbox().url, NEW_ORIGIN);
    assert!(newest.listed_cert(&lost.keys.app_id_bytes()).is_none());
    assert!(newest.listed_cert(&kept.keys.app_id_bytes()).is_some());
    assert_eq!(world.backup().identity_doc().signed(), newest.signed());
    let later = signer.set_record_max_age(Some(60)).await.unwrap();
    assert_eq!(world.backup().identity_doc().signed(), later.signed());
}

#[tokio::test]
async fn test_key_recovery_provider_loss_backup_waits_for_the_removal() {
    // As above, and the revocation at the new service fails too: the provider loss's version
    // is delivered, and its backup stays owed, shown, until the version removing the app
    // writes it.
    const NEW_ORIGIN: &str = "https://recovery.example";
    let world = World::new();
    let (kept, lost, _) = two_apps(&world).await;
    world
        .homeserver
        .files
        .lock()
        .unwrap()
        .remove(SIGNER_BACKUP_PATH);
    for _ in 0..2 {
        world.switch.fail_next(SwitchFault::Unreachable {
            path: "/revoke".into(),
            after: 0,
        });
    }
    let store = Arc::new(MemoryStore::new());
    let shown = survey(&world, &store).await.unwrap();
    Signer::restore_new(
        world.env(store.clone()),
        world.keyring(),
        KeyRecoveryConfirmed::shown_and_confirmed(&shown, &[]),
    )
    .await
    .unwrap_err();
    let service =
        ScriptedSwitch::unenrolled_at(&world.key, [0x5e; 32], Arc::clone(&world.clock), NEW_ORIGIN);
    let router = Arc::new(Router::new());
    router.add_switch(NEW_ORIGIN, &service);
    let mut env = world.env(store);
    env.transport = router.clone();
    let mut signer = Signer::open(env, world.keyring()).await.unwrap();
    let before = world.homeserver.file(SIGNER_BACKUP_PATH);
    for _ in 0..4 {
        service.fail_next(SwitchFault::Unreachable {
            path: "/revoke".into(),
            after: 0,
        });
    }
    signer
        .declare_provider_loss(NEW_ORIGIN, confirmed())
        .await
        .unwrap();
    let delivered = signer.identity_doc().unwrap().unwrap();
    assert_eq!(delivered.inbox().url, NEW_ORIGIN);
    assert!(delivered.listed_cert(&lost.keys.app_id_bytes()).is_some());
    assert!(signer.alerts().contains(&Alert::BackupNotWritten));
    assert_eq!(world.homeserver.file(SIGNER_BACKUP_PATH), before);
    // The revocation is sent again until the service takes it.
    let mut later = signer.set_record_max_age(Some(60)).await;
    for _ in 0..4 {
        if later.is_ok() {
            break;
        }
        later = signer.set_record_max_age(Some(60)).await;
    }
    let later = later.unwrap();
    assert!(later.listed_cert(&lost.keys.app_id_bytes()).is_none());
    assert!(later.listed_cert(&kept.keys.app_id_bytes()).is_some());
    assert_eq!(world.backup().identity_doc().signed(), later.signed());
}

#[tokio::test]
async fn test_key_recovery_counts_retained_revocations_before_taking_new_ids() {
    let world = World::new();
    let (mut first, _) = world.enrolled().await;
    let older = first.identity_doc().unwrap().unwrap();
    let (app, _) = joined(&world, &mut first, 3).await;
    revoked_and_purged(&mut first, &app).await;
    let served = first.identity_doc().unwrap().unwrap();
    drop(first);

    // Only the service still lists the revoked app. A signer with room takes its ID.
    let store = Arc::new(MemoryStore::new());
    world
        .homeserver
        .set(SIGNER_BACKUP_PATH, backup_holding(&world, &older, &[]));
    let shown = survey(&world, &store).await.unwrap();
    assert_eq!(shown.revoked, [app.keys.app_id_bytes()]);

    // This backup already accounts for more than seven eighths of a move's enrollment.
    // Its revocations stay, and recovering again leaves room to approve a new app.
    let retained: Vec<_> = (0..6_000_u128).map(u128::to_be_bytes).collect();
    let bytes = pubky_switch_core::records::Enrollment::max_request_len(
        &served.body().policy,
        Some(served.signed()),
        &retained,
    )
    .unwrap();
    let limit = pubky_switch_core::http::body_cap("POST", "/v1/enroll").unwrap();
    assert!((limit - limit / 8..limit).contains(&bytes));
    world.homeserver.set(
        SIGNER_BACKUP_PATH,
        backup_holding(&world, &older, &retained),
    );
    let shown = survey(&world, &store).await.unwrap();
    assert_eq!(shown.revoked.len(), retained.len());
    assert_eq!(shown.revoked, retained);
    let mut signer = Signer::restore_new(
        world.env(store),
        world.keyring(),
        KeyRecoveryConfirmed::shown_and_confirmed(&shown, &[]),
    )
    .await
    .unwrap();
    world
        .homeserver
        .files
        .lock()
        .unwrap()
        .remove(SIGNER_BACKUP_PATH);
    let again = signer.survey_key_recovery().await.unwrap();
    assert_eq!(again.revoked, retained);
    signer
        .restore(KeyRecoveryConfirmed::shown_and_confirmed(&again, &[]))
        .await
        .unwrap();
    let mut saved = world.backup().revoked_apps().to_vec();
    saved.sort_unstable();
    assert_eq!(saved, retained);
    joined(&world, &mut signer, 5).await;
    signs_on(&world, &mut signer).await;
}

#[tokio::test]
async fn test_key_recovery_leaves_room_for_the_identitys_own_versions() {
    // The service shows ten thousand App IDs revoked that no copy names: the recovery takes
    // no more than leave room for the identity's own later versions, and a new app is
    // approved afterwards.
    let world = World::new();
    let (first, _) = world.enrolled().await;
    drop(first);
    world
        .homeserver
        .files
        .lock()
        .unwrap()
        .remove(SIGNER_BACKUP_PATH);
    let at = pubky_switch_core::time::rfc3339(START_MS);
    let many: Vec<serde_json::Value> = (0..10_000u32)
        .map(|i| {
            let mut id = [7; 16];
            id[..4].copy_from_slice(&i.to_be_bytes());
            status(id, |s| {
                s["revoked_at"] = at.clone().into();
                s["last_seen"] = at.clone().into();
            })
        })
        .collect();
    // The survey's read, the recovery's, and its step's.
    for _ in 0..3 {
        world.switch.fail_next(SwitchFault::Replace {
            path: "/apps".into(),
            member: "apps".into(),
            value: serde_json::Value::Array(many.clone()),
        });
    }
    let mut signer = recovered(&world, &[]).await.unwrap();
    assert!(!world.backup().revoked_apps().is_empty());
    joined(&world, &mut signer, 3).await;
    signs_on(&world, &mut signer).await;
}

#[tokio::test]
async fn test_key_recovery_over_unusable_records_keeps_their_revocations() {
    // The user revoked an app, from a time they picked, and the switch never took it; then
    // the flow record is damaged and the backup is gone. The readable state binds the
    // recovery: the app is removed from the picked time, and another app, whose record is
    // gone, stays with the certificate the state holds. A refusal before the recovery's
    // commit leaves the records as found.
    let world = World::new();
    let (mut first, memory) = world.enrolled().await;
    let (app, _) = joined(&world, &mut first, 3).await;
    let (other, _) = joined(&world, &mut first, 5).await;
    world
        .homeserver
        .files
        .lock()
        .unwrap()
        .remove(&app_record_path(&other.keys.app_id_bytes()));
    let id = app.keys.app_id_bytes();
    let picked = START_MS - 3_600_000;
    world.switch.fail_next(SwitchFault::Unreachable {
        path: "/revoke".into(),
        after: 0,
    });
    first
        .revoke(id, Some(picked), confirmed())
        .await
        .unwrap_err();
    drop(first);
    damage_flow(&world, &memory);
    world
        .homeserver
        .files
        .lock()
        .unwrap()
        .remove(SIGNER_BACKUP_PATH);
    let shown = survey(&world, &memory).await.unwrap();
    assert_eq!(
        shown.apps,
        [
            (
                id,
                AppFate::RevocationPending {
                    distrust_from: Some(picked)
                }
            ),
            (other.keys.app_id_bytes(), AppFate::Stays)
        ]
    );
    let confirm = || {
        RecordsDiscarded::shown_and_confirmed()
            .and_key_recovery(KeyRecoveryConfirmed::shown_and_confirmed(&shown, &[]))
    };
    world.switch.fail_next(SwitchFault::Error {
        path: "/enroll".into(),
        code: ErrorCode::Unavailable,
        current: serde_json::Value::Null,
    });
    assert_eq!(
        Signer::restore_over_unusable(world.env(memory.clone()), world.keyring(), confirm())
            .await
            .unwrap_err(),
        refused(KeyRecoveryStop::NotServing)
    );
    assert_eq!(survey(&world, &memory).await.unwrap(), shown);
    let mut signer = Signer::restore_over_unusable(world.env(memory), world.keyring(), confirm())
        .await
        .unwrap();
    let newest = signer.identity_doc().unwrap().unwrap();
    assert!(newest.listed_cert(&id).is_none());
    assert!(newest.listed_cert(&other.keys.app_id_bytes()).is_some());
    let removed: Vec<_> = newest
        .body()
        .removed
        .iter()
        .map(|r| (r.app_id, r.distrust_from))
        .collect();
    assert_eq!(removed, [(id, picked)]);
    signs_on(&world, &mut signer).await;
}

#[tokio::test]
async fn test_key_recovery_reads_the_copy_as_signed() {
    // A copy carrying a member this signer doesn't read, signed by the identity key: at the
    // service, the recovery refuses rather than drop it; on the Homeserver, at the service's
    // version, it is another document there, though both read alike.
    for case in ["service", "homeserver"] {
        let world = World::new();
        let (first, _) = world.enrolled().await;
        let doc = first.identity_doc().unwrap().unwrap();
        drop(first);
        world
            .homeserver
            .files
            .lock()
            .unwrap()
            .remove(SIGNER_BACKUP_PATH);
        let mut body = doc.body().clone();
        body.version += 1;
        let plain = IdentityDoc::sign(&world.key, body).unwrap();
        let mut value: serde_json::Value =
            serde_json::from_slice(&plain.signed().body_bytes().unwrap()).unwrap();
        value["later_member"] = 1.into();
        let signed = world.key.sign_doc(
            pubky_switch_core::labels::sig::IDENTITY,
            &[],
            serde_json::to_vec(&value).unwrap(),
        );
        let unknown = IdentityDoc::verify(&signed, &world.key.public()).unwrap();
        assert_eq!(unknown.body(), plain.body());
        let expected = match case {
            "service" => {
                world.switch.deliver_identity(&unknown).unwrap();
                KeyRecoveryStop::UnknownMembers
            }
            _ => {
                world.switch.deliver_identity(&plain).unwrap();
                world
                    .homeserver
                    .set(IDENTITY_PATH, serde_json::to_vec(unknown.signed()).unwrap());
                KeyRecoveryStop::ServiceBehind {
                    switch_version: plain.version(),
                    seen_version: plain.version(),
                }
            }
        };
        assert_eq!(
            survey(&world, &Arc::new(MemoryStore::new()))
                .await
                .unwrap_err(),
            refused(expected),
            "{case}"
        );
    }
}

#[tokio::test]
async fn test_key_recovery_takes_a_copy_in_another_writers_encoding() {
    // Another conforming signer wrote the copy: pretty-printed, or with its members in
    // another order and an absent one written as `null`. Nothing in it is unknown, so the
    // recovery goes ahead (Switch wire 1.1).
    for case in ["pretty", "reordered"] {
        let world = World::new();
        let (first, _) = world.enrolled().await;
        let doc = first.identity_doc().unwrap().unwrap();
        drop(first);
        world
            .homeserver
            .files
            .lock()
            .unwrap()
            .remove(SIGNER_BACKUP_PATH);
        let mut body = doc.body().clone();
        body.version += 1;
        let plain = IdentityDoc::sign(&world.key, body).unwrap();
        let mut value: serde_json::Value =
            serde_json::from_slice(&plain.signed().body_bytes().unwrap()).unwrap();
        let bytes = match case {
            "pretty" => serde_json::to_vec_pretty(&value).unwrap(),
            _ => {
                value["record_max_age"] = serde_json::Value::Null;
                let mut members: Vec<(String, serde_json::Value)> =
                    value.as_object().unwrap().clone().into_iter().collect();
                members.reverse();
                let reordered = members
                    .iter()
                    .map(|(name, value)| {
                        format!("{}:{}", serde_json::to_string(name).unwrap(), value)
                    })
                    .collect::<Vec<_>>()
                    .join(",");
                format!("{{{reordered}}}").into_bytes()
            }
        };
        assert_ne!(bytes, plain.signed().body_bytes().unwrap(), "{case}");
        let signed = world
            .key
            .sign_doc(pubky_switch_core::labels::sig::IDENTITY, &[], bytes);
        let other = IdentityDoc::verify(&signed, &world.key.public()).unwrap();
        assert_eq!(other.body(), plain.body(), "{case}");
        world.switch.deliver_identity(&other).unwrap();
        world
            .homeserver
            .set(IDENTITY_PATH, serde_json::to_vec(other.signed()).unwrap());
        let mut signer = recovered(&world, &[]).await.unwrap();
        assert_eq!(
            signer.identity_doc().unwrap().unwrap().version(),
            other.version() + 1,
            "{case}"
        );
        signs_on(&world, &mut signer).await;
    }
}

#[tokio::test]
async fn test_key_recovery_past_a_backup_naming_a_service_gone() {
    // The backup was rolled back to a version that named a former service, now gone, while
    // the account is served elsewhere: under the key confirmation that backup counts as
    // stale, and the recovery goes ahead at the service the newest copy names.
    let world = World::new();
    let (mut first, _) = world.enrolled().await;
    let doc = first.identity_doc().unwrap().unwrap();
    first.set_record_max_age(Some(60)).await.unwrap();
    drop(first);
    let mut body = doc.body().clone();
    body.inbox =
        pubky_switch_core::records::Inbox::new("https://gone.example", doc.inbox().service_key);
    let former = IdentityDoc::sign(&world.key, body).unwrap();
    world
        .homeserver
        .set(SIGNER_BACKUP_PATH, backup_holding(&world, &former, &[]));
    let router = Arc::new(Router::new());
    router.add_switch(pubky_switch_client::testing::SWITCH_ORIGIN, &world.switch);
    let store = Arc::new(MemoryStore::new());
    let mut env = world.env(store.clone());
    env.transport = router.clone();
    let shown = Signer::survey_key_recovery_new(env, world.keyring())
        .await
        .unwrap();
    assert_eq!(shown.backup, BackupFound::Stale { version: 1 });
    let mut env = world.env(store);
    env.transport = router;
    let mut signer = Signer::restore_new(
        env,
        world.keyring(),
        KeyRecoveryConfirmed::shown_and_confirmed(&shown, &[]),
    )
    .await
    .unwrap();
    signs_on(&world, &mut signer).await;
}

#[tokio::test]
async fn test_key_recovery_waits_out_its_own_service_failing_for_now() {
    // The backup names the service the newest copy names, which can't be reached for now:
    // the restore returns that error, and the next try goes on, here past the stale backup.
    let world = World::new();
    let (mut first, _) = world.enrolled().await;
    let doc = first.identity_doc().unwrap().unwrap();
    first.set_record_max_age(Some(60)).await.unwrap();
    drop(first);
    world
        .homeserver
        .set(SIGNER_BACKUP_PATH, backup_holding(&world, &doc, &[]));
    let store = Arc::new(MemoryStore::new());
    let shown = survey(&world, &store).await.unwrap();
    world.switch.fail_next(SwitchFault::Unreachable {
        path: "/apps".into(),
        after: 0,
    });
    let error = Signer::restore_new(
        world.env(store.clone()),
        world.keyring(),
        KeyRecoveryConfirmed::shown_and_confirmed(&shown, &[]),
    )
    .await
    .unwrap_err();
    assert!(matches!(error, SignerError::Switch(_)), "{error:?}");
    let mut signer = Signer::restore_new(
        world.env(store),
        world.keyring(),
        KeyRecoveryConfirmed::shown_and_confirmed(&shown, &[]),
    )
    .await
    .unwrap();
    signs_on(&world, &mut signer).await;
}

#[tokio::test]
async fn test_key_recovery_takes_the_earliest_picked_time() {
    // The install's records and the backup picked different times to distrust one app from:
    // whichever holds the earlier one, the survey and the recovery take it.
    for records_earlier in [true, false] {
        let world = World::new();
        let (mut first, memory) = world.enrolled().await;
        let (app, _) = joined(&world, &mut first, 3).await;
        let id = app.keys.app_id_bytes();
        let backed_up = START_MS - 3_600_000;
        world.switch.fail_next(SwitchFault::Unreachable {
            path: "/revoke".into(),
            after: 0,
        });
        first
            .revoke(id, Some(backed_up), confirmed())
            .await
            .unwrap_err();
        // The next version's backup holds the revocation with that time.
        first.set_record_max_age(Some(60)).await.unwrap();
        drop(first);
        let own = if records_earlier {
            backed_up - 3_600_000
        } else {
            backed_up + 1_800_000
        };
        edit_state(&world, &memory, |state| {
            state["revoking"][0]["distrust_from"] = own.into();
        });
        let mut signer = Signer::open(world.env(memory), world.keyring())
            .await
            .unwrap();
        let shown = signer.survey_key_recovery().await.unwrap();
        let earliest = own.min(backed_up);
        assert!(
            shown.apps.contains(&(
                id,
                AppFate::RevocationPending {
                    distrust_from: Some(earliest)
                }
            )),
            "{records_earlier}: {:?}",
            shown.apps
        );
    }
}

#[tokio::test]
async fn test_key_recovery_at_a_service_the_user_gives() {
    // No copy names the service that serves the account: the Homeserver lost its copy and
    // the backup, or its copy names a former service. The user gives the origin; the
    // service's copy there passes every rule, and the recovery goes ahead.
    for case in ["no copy", "former service"] {
        let world = World::new();
        let (mut first, _) = world.enrolled().await;
        let (app, _) = joined(&world, &mut first, 5).await;
        let doc = first.identity_doc().unwrap().unwrap();
        drop(first);
        world
            .homeserver
            .files
            .lock()
            .unwrap()
            .remove(SIGNER_BACKUP_PATH);
        let router = Arc::new(Router::new());
        router.add_switch(pubky_switch_client::testing::SWITCH_ORIGIN, &world.switch);
        if case == "no copy" {
            world.homeserver.files.lock().unwrap().remove(IDENTITY_PATH);
        } else {
            let mut body = doc.body().clone();
            body.version -= 1;
            body.inbox = pubky_switch_core::records::Inbox::new(
                "https://former.example",
                doc.inbox().service_key,
            );
            let former = IdentityDoc::sign(&world.key, body).unwrap();
            world
                .homeserver
                .set(IDENTITY_PATH, serde_json::to_vec(former.signed()).unwrap());
        }
        let store = Arc::new(MemoryStore::new());
        let env = || {
            let mut env = world.env(store.clone());
            env.transport = router.clone();
            env
        };
        let refusal = Signer::survey_key_recovery_new(env(), world.keyring())
            .await
            .unwrap_err();
        match case {
            "no copy" => assert_eq!(refusal, refused(KeyRecoveryStop::NoCopy)),
            _ => assert!(matches!(refusal, SignerError::Switch(_)), "{refusal:?}"),
        }
        let shown = Signer::survey_key_recovery_new_at(
            env(),
            world.keyring(),
            pubky_switch_client::testing::SWITCH_ORIGIN,
        )
        .await
        .unwrap();
        assert!(shown.origin_supplied, "{case}");
        assert_eq!(shown.version, doc.version(), "{case}");
        let mut signer = Signer::restore_new(
            env(),
            world.keyring(),
            KeyRecoveryConfirmed::shown_and_confirmed(&shown, &[]),
        )
        .await
        .unwrap();
        assert!(
            signer
                .identity_doc()
                .unwrap()
                .unwrap()
                .listed_cert(&app.keys.app_id_bytes())
                .is_some(),
            "{case}"
        );
        signs_on(&world, &mut signer).await;
    }
}

#[tokio::test]
async fn test_key_recovery_at_a_given_service_keeps_the_rules() {
    // An origin the user gives is held to every rule: a service whose copy is behind the
    // Homeserver's is refused there as anywhere.
    let world = World::new();
    let (mut first, _) = world.enrolled().await;
    let doc = first.identity_doc().unwrap().unwrap();
    first.set_record_max_age(Some(60)).await.unwrap();
    drop(first);
    world
        .homeserver
        .files
        .lock()
        .unwrap()
        .remove(SIGNER_BACKUP_PATH);
    let mut body = doc.body().clone();
    body.version += 5;
    let ahead = IdentityDoc::sign(&world.key, body).unwrap();
    world
        .homeserver
        .set(IDENTITY_PATH, serde_json::to_vec(ahead.signed()).unwrap());
    let refusal = Signer::survey_key_recovery_new_at(
        world.env(Arc::new(MemoryStore::new())),
        world.keyring(),
        pubky_switch_client::testing::SWITCH_ORIGIN,
    )
    .await
    .unwrap_err();
    assert!(matches!(
        refusal,
        SignerError::Refused(Refusal::KeyRecovery(KeyRecoveryStop::ServiceBehind { .. }))
    ));
}

/// The next version after the switch's copy, its body edited by `edit` and signed by the
/// identity key, delivered to the switch and published; the backup removed.
fn copy_edited(world: &World, edit: impl FnOnce(&mut serde_json::Value)) -> IdentityDoc {
    let doc = world.switch.identity_doc().unwrap();
    let mut body = doc.body().clone();
    body.version += 1;
    let plain = IdentityDoc::sign(&world.key, body).unwrap();
    let mut value: serde_json::Value =
        serde_json::from_slice(&plain.signed().body_bytes().unwrap()).unwrap();
    edit(&mut value);
    let signed = world.key.sign_doc(
        pubky_switch_core::labels::sig::IDENTITY,
        &[],
        serde_json::to_vec(&value).unwrap(),
    );
    let edited = IdentityDoc::verify(&signed, &world.key.public()).unwrap();
    assert_eq!(edited.body(), plain.body());
    world.switch.deliver_identity(&edited).unwrap();
    world
        .homeserver
        .set(IDENTITY_PATH, serde_json::to_vec(edited.signed()).unwrap());
    world
        .homeserver
        .files
        .lock()
        .unwrap()
        .remove(SIGNER_BACKUP_PATH);
    edited
}

/// Puts a member's value somewhere in a copy's body.
type Put = fn(&mut serde_json::Value, serde_json::Value);

#[tokio::test]
async fn test_key_recovery_refuses_an_unknown_member_whatever_its_value() {
    // A member this signer doesn't read, at the top or nested in an app, the inbox, the
    // policy or a removal, is refused even when it is `null`, `[]` or `{}`: an empty list
    // may be a later signer's restriction, which the recovery's version would drop.
    let places: Vec<(&str, Put)> = vec![
        ("top", |v, x| v["later_member"] = x),
        ("app", |v, x| v["apps"][0]["later_member"] = x),
        ("inbox", |v, x| v["inbox"]["later_member"] = x),
        ("policy", |v, x| v["policy"]["later_member"] = x),
        ("connect requests", |v, x| {
            v["policy"]["connect_requests"]["later_member"] = x;
        }),
        ("removal", |v, x| v["removed"][0]["later_member"] = x),
    ];
    for (place, put) in places {
        for value in [
            serde_json::json!([]),
            serde_json::json!({}),
            serde_json::Value::Null,
        ] {
            let world = World::new();
            let (mut first, _) = world.enrolled().await;
            let (_, _) = joined(&world, &mut first, 3).await;
            let (gone, _) = joined(&world, &mut first, 5).await;
            first
                .revoke(gone.keys.app_id_bytes(), None, confirmed())
                .await
                .unwrap();
            drop(first);
            copy_edited(&world, |v| put(v, value.clone()));
            assert_eq!(
                survey(&world, &Arc::new(MemoryStore::new()))
                    .await
                    .unwrap_err(),
                refused(KeyRecoveryStop::UnknownMembers),
                "{place} {value}"
            );
        }
    }
}

#[tokio::test]
async fn test_key_recovery_takes_members_it_leaves_out_written_empty() {
    // The members this signer leaves out when absent or empty, written `null` or empty by
    // another writer, are no unknown members: the recovery goes ahead.
    let world = World::new();
    let (first, _) = world.enrolled().await;
    drop(first);
    let edited = copy_edited(&world, |v| {
        v["record_max_age"] = serde_json::Value::Null;
        v["service_keys"] = serde_json::json!([]);
        v["renewed"] = serde_json::json!([]);
    });
    let mut signer = recovered(&world, &[]).await.unwrap();
    assert_eq!(
        signer.identity_doc().unwrap().unwrap().version(),
        edited.version() + 1
    );
    signs_on(&world, &mut signer).await;
}

#[tokio::test]
async fn test_key_recovery_past_a_backup_its_service_refuses() {
    // The backup names the service and key the newest copy names, but an account creation
    // that service no longer answers for: without the key confirmation the restore returns
    // the service's refusal, as before; with it, the recovery goes ahead without the backup.
    let world = World::new();
    let (mut first, _) = world.enrolled().await;
    let doc = first.identity_doc().unwrap().unwrap();
    first.set_record_max_age(Some(60)).await.unwrap();
    drop(first);
    let records = pubky_switch_core::records::SignerRecords::new(
        pubky_switch_core::keys::IdentityKey::from_secret(SECRET),
        doc.clone(),
        world.backup().account_created() - 1_000,
        &[],
        &[],
        pubky_switch_core::records::Limits::default(),
        &[],
        None,
    )
    .unwrap();
    let backup = pubky_switch_core::records::SignerBackup::seal(&world.key, &records).unwrap();
    world
        .homeserver
        .set(SIGNER_BACKUP_PATH, serde_json::to_vec(&backup).unwrap());
    let error = restored(&world).await.unwrap_err();
    assert!(matches!(error, SignerError::Switch(_)), "{error:?}");
    let mut signer = recovered(&world, &[]).await.unwrap();
    signs_on(&world, &mut signer).await;
}

#[tokio::test]
async fn test_key_recovery_never_delivers_into_a_replaced_account() {
    // The account is erased and created again between the recovery's commit and its step:
    // its enrollment, bound to the account surveyed, is refused there, and nothing is
    // delivered into the replacement. Surveyed afresh, the replacement is shown as such.
    let world = World::new();
    let (first, _) = world.enrolled().await;
    drop(first);
    world
        .homeserver
        .files
        .lock()
        .unwrap()
        .remove(SIGNER_BACKUP_PATH);
    let store = Arc::new(MemoryStore::new());
    let shown = survey(&world, &store).await.unwrap();
    world.switch.fail_next(SwitchFault::LoseAnswer {
        path: "/enroll".into(),
    });
    Signer::restore_new(
        world.env(store.clone()),
        world.keyring(),
        KeyRecoveryConfirmed::shown_and_confirmed(&shown, &[]),
    )
    .await
    .unwrap_err();
    world.create_after_erasure().await;
    let result = Signer::restore_new(
        world.env(store.clone()),
        world.keyring(),
        KeyRecoveryConfirmed::shown_and_confirmed(&shown, &[]),
    )
    .await;
    assert!(result.is_err());
    assert!(world.switch.identity_doc().is_none());
    assert!(survey(&world, &Arc::new(MemoryStore::new())).await.is_err());
}
