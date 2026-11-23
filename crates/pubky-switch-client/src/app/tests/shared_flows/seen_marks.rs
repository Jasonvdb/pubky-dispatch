//! The seen marks a backup carries and a restore installs (Switch spec 8.2, 12.4 "Seen
//! marks").

use std::sync::atomic::Ordering::SeqCst;

use super::*;
use crate::app::AppBackup;
use crate::app::records::{SeenMark, seen_key};

/// The size of one mark at the bound.
const FULL: usize = MAX_SEEN_MARK_BYTES;

/// A writer and a reader, separate apps of one identity: the reader holds a mark of
/// `target` once it has read the writer's `items`.
async fn seen(s: &Setup, items: &[&str]) -> (App, App, RecordTarget, [u8; 32]) {
    let mut writer = s.join("writer").await;
    let mut reader = s.join("reader").await;
    let target = s.target("n1");
    let key = writer.record_key(&target).unwrap();
    writer
        .put_record(&target, &value(items), vec![])
        .await
        .unwrap();
    read_on(&mut reader).await;
    assert_eq!(
        ids(reader.record_seen(&key).await.unwrap().as_deref()),
        items
    );
    (writer, reader, target, key)
}

async fn restore_on(s: &Setup, env: AppEnv, backup: &AppBackup) -> Result<App, AppError> {
    Box::pin(App::restore(
        env,
        s.protocol.clone(),
        World::config(),
        backup,
    ))
    .await
}

async fn fresh(s: &Setup, backup: &AppBackup) -> App {
    restore_on(s, s.env_on(Arc::new(MemoryStore::new())), backup)
        .await
        .unwrap()
}

/// The backup with `edit` applied to its JSON, read back.
fn edited(
    backup: &AppBackup,
    edit: impl FnOnce(&mut serde_json::Value),
) -> Result<AppBackup, AppError> {
    let mut value: serde_json::Value = serde_json::from_slice(&backup.to_bytes().unwrap()).unwrap();
    edit(&mut value);
    AppBackup::from_bytes(&serde_json::to_vec(&value).unwrap())
}

/// `key`'s carried mark in a backup's JSON.
fn carried<'a>(value: &'a mut serde_json::Value, key: &[u8; 32]) -> &'a mut serde_json::Value {
    let key = pubky_switch_core::enc::b64(key);
    value["seen_marks"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .find(|mark| mark["key"] == json!(key))
        .unwrap()
}

/// Marks of `bytes` each, at `keys`, put in `app`'s store as a read would.
async fn put_marks(app: &mut App, keys: &[[u8; 32]], bytes: usize) {
    for chunk in keys.chunks(64) {
        let mut tx = app.tx().unwrap();
        for key in chunk {
            tx.put(
                &seen_key(key),
                &SeenMark {
                    mark: vec![b'm'; bytes],
                },
            )
            .unwrap();
        }
        app.commit(tx).await.unwrap();
    }
}

/// `n` record keys whose first byte is `first`, in ascending order.
fn keys(first: u8, n: u16) -> Vec<[u8; 32]> {
    (0..n)
        .map(|i| {
            let mut key = [0; 32];
            key[0] = first;
            key[1..3].copy_from_slice(&i.to_be_bytes());
            key
        })
        .collect()
}

/// The records the duty events kept tell uncheckable, each with its mark's size.
async fn uncheckable_records(app: &App) -> Vec<([u8; 32], u64)> {
    app.kept_duties()
        .await
        .unwrap()
        .into_iter()
        .filter_map(|event| match event {
            AppEvent::RecordUncheckable {
                key, mark_bytes, ..
            }
            | AppEvent::SeenMarkLeftOut {
                key, mark_bytes, ..
            } => Some((key, mark_bytes)),
            _ => None,
        })
        .collect()
}

#[tokio::test]
async fn test_seen_marks_fresh_restore_checks_a_write_against_the_backup_mark() {
    let s = Setup::new();
    let (mut writer, reader, target, key) = seen(&s, &["a", "b"]).await;
    let backup = reader.backup().await.unwrap();
    let mut restored = fresh(&s, &backup).await;
    assert_eq!(
        ids(restored.record_seen(&key).await.unwrap().as_deref()),
        ["a", "b"]
    );
    // A write that drops what the app saw before the backup is flagged, not taken.
    writer
        .put_record(&target, &value(&["a"]), vec![])
        .await
        .unwrap();
    restored.refresh_identity().await.unwrap();
    read_on(&mut restored).await;
    let shared = restored.shared_record(&key).await.unwrap().unwrap();
    assert!(shared.flagged, "{:?}", shared.content);
    // One that keeps it is taken.
    writer
        .put_record(&target, &value(&["a", "b", "c"]), vec![])
        .await
        .unwrap();
    read_on(&mut restored).await;
    let shared = restored.shared_record(&key).await.unwrap().unwrap();
    assert_eq!(ids(shared.content.value()), ["a", "b", "c"]);
}

#[tokio::test]
async fn test_seen_marks_fresh_restore_of_an_older_backup_installs_its_mark() {
    let s = Setup::new();
    let (mut writer, mut reader, target, key) = seen(&s, &["a", "b"]).await;
    let older = reader.backup_layered().await.unwrap();
    writer
        .put_record(&target, &value(&["a", "b", "c"]), vec![])
        .await
        .unwrap();
    read_on(&mut reader).await;
    assert_eq!(
        ids(reader.record_seen(&key).await.unwrap().as_deref()),
        ["a", "b", "c"]
    );
    let restored = fresh(&s, &older).await;
    assert_eq!(
        ids(restored.record_seen(&key).await.unwrap().as_deref()),
        ["a", "b"]
    );
}

/// A restore in place of a backup taken when the reader had seen `[a, b]` of n1 and `[x]` of
/// n2, edited to hold `[a, z]` of n1, no mark of n2 and one of a record only it holds, after
/// the reader saw `[a, b, c]` of n1: with each, n1 is held twice, n2 only by the store, and
/// the other only by the backup.
async fn restored_in_place(s: &Setup) -> (App, [u8; 32], [u8; 32], [u8; 32]) {
    let (mut writer, mut reader, target, key) = seen(s, &["a", "b"]).await;
    let other = s.target("n2");
    let live_only = writer.record_key(&other).unwrap();
    writer
        .put_record(&other, &value(&["x"]), vec![])
        .await
        .unwrap();
    read_on(&mut reader).await;
    let backup_only = [7; 32];
    let backup = edited(&reader.backup().await.unwrap(), |value| {
        carried(value, &key)["mark"] = json!(pubky_switch_core::enc::b64(&value_of(&["a", "z"])));
        let marks = value["seen_marks"].as_array_mut().unwrap();
        let live = json!(pubky_switch_core::enc::b64(&live_only));
        marks.retain(|mark| mark["key"] != live);
        marks.push(json!({
            "key": pubky_switch_core::enc::b64(&backup_only),
            "mark": pubky_switch_core::enc::b64(&value_of(&["q"])),
            "record": null,
        }));
    })
    .unwrap();
    writer
        .put_record(&target, &value(&["a", "b", "c"]), vec![])
        .await
        .unwrap();
    read_on(&mut reader).await;
    drop(reader);
    let restored = restore_on(s, s.env(), &backup).await.unwrap();
    (restored, key, live_only, backup_only)
}

fn value_of(items: &[&str]) -> Vec<u8> {
    value(items)
}

#[tokio::test]
async fn test_seen_marks_in_place_keeps_the_store_mark_and_installs_the_backup_only() {
    let s = Setup::new();
    let (restored, both, live_only, backup_only) = restored_in_place(&s).await;
    let seen = |mark: Option<Vec<u8>>| ids(mark.as_deref());
    // Held by both: the protocol doesn't merge, so the store's stands.
    assert_eq!(
        seen(restored.record_seen(&both).await.unwrap()),
        ["a", "b", "c"]
    );
    assert_eq!(seen(restored.record_seen(&live_only).await.unwrap()), ["x"]);
    assert_eq!(
        seen(restored.record_seen(&backup_only).await.unwrap()),
        ["q"]
    );
    assert!(uncheckable_records(&restored).await.is_empty());
}

#[tokio::test]
async fn test_seen_marks_in_place_installs_the_owner_merged_mark() {
    let s = Setup::new();
    s.protocol.merge_marks.store(true, SeqCst);
    let (restored, both, live_only, _) = restored_in_place(&s).await;
    assert_eq!(
        ids(restored.record_seen(&both).await.unwrap().as_deref()),
        ["a", "b", "c", "z"]
    );
    assert_eq!(
        ids(restored.record_seen(&live_only).await.unwrap().as_deref()),
        ["x"]
    );
    assert!(uncheckable_records(&restored).await.is_empty());
}

#[tokio::test]
async fn test_seen_marks_in_place_merged_over_the_bound_keeps_the_store_mark() {
    let s = Setup::new();
    s.protocol.merge_marks.store(true, SeqCst);
    s.protocol.merge_pad.store(FULL, SeqCst);
    let (restored, both, _, _) = restored_in_place(&s).await;
    let kept = restored.record_seen(&both).await.unwrap().unwrap();
    assert_eq!(ids(Some(&kept)), ["a", "b", "c"]);
    assert!(kept.len() < FULL);
    assert!(uncheckable(&restored.kept_duties().await.unwrap(), &both));
}

#[tokio::test]
async fn test_seen_marks_refuse_a_mark_over_the_bound() {
    let s = Setup::new();
    let (_, reader, _, key) = seen(&s, &["a"]).await;
    let backup = reader.backup().await.unwrap();
    let with = |bytes: usize| {
        edited(&backup, |value| {
            carried(value, &key)["mark"] = json!(pubky_switch_core::enc::b64(&vec![b' '; bytes]));
        })
        .unwrap()
    };
    let refused = restore_on(&s, s.env_on(Arc::new(MemoryStore::new())), &with(FULL + 1)).await;
    assert!(
        matches!(refused, Err(AppError::InvalidData(ref why)) if why.contains("seen mark")),
        "{:?}",
        refused.err()
    );
    // At the bound, it is installed.
    let restored = fresh(&s, &with(FULL)).await;
    assert_eq!(
        restored.record_seen(&key).await.unwrap().unwrap().len(),
        FULL
    );
}

#[tokio::test]
async fn test_seen_marks_refuse_one_record_marked_twice() {
    let s = Setup::new();
    let (_, reader, _, key) = seen(&s, &["a"]).await;
    let backup = reader.backup().await.unwrap();
    let twice = edited(&backup, |value| {
        let mark = carried(value, &key).clone();
        value["seen_marks"]
            .as_array_mut()
            .unwrap()
            .push(mark.clone());
    })
    .unwrap();
    let refused = restore_on(&s, s.env_on(Arc::new(MemoryStore::new())), &twice).await;
    assert!(matches!(refused, Err(AppError::InvalidData(_))));
    let both = edited(&backup, |value| {
        value["seen_marks_left_out"] = json!([{
            "key": pubky_switch_core::enc::b64(&key),
            "mark_bytes": 3,
            "record": null,
        }]);
    })
    .unwrap();
    let refused = restore_on(&s, s.env_on(Arc::new(MemoryStore::new())), &both).await;
    assert!(matches!(refused, Err(AppError::InvalidData(_))));
    assert!(
        restore_on(&s, s.env_on(Arc::new(MemoryStore::new())), &backup)
            .await
            .is_ok()
    );
}

#[tokio::test]
async fn test_seen_marks_refuse_a_backup_without_them() {
    let s = Setup::new();
    let (_, reader, _, _) = seen(&s, &["a"]).await;
    let backup = reader.backup().await.unwrap();
    for member in ["seen_marks", "seen_marks_left_out"] {
        let read = edited(&backup, |value| {
            value.as_object_mut().unwrap().remove(member);
        });
        assert!(
            matches!(read, Err(AppError::InvalidData(_))),
            "{member}: {:?}",
            read.err()
        );
    }
    assert!(edited(&backup, |_| {}).is_ok());
}

#[tokio::test]
async fn test_seen_marks_within_the_room_leave_nothing_out() {
    let s = Setup::new();
    let (_, mut reader, _, _) = seen(&s, &["a"]).await;
    let marks = keys(1, 10);
    put_marks(&mut reader, &marks, FULL).await;
    let backup = reader.backup_layered().await.unwrap();
    assert!(backup.seen_marks_left_out.is_empty());
    assert_eq!(backup.seen_marks.len(), 11);
    let restored = fresh(&s, &backup).await;
    for key in &marks {
        assert_eq!(
            restored.record_seen(key).await.unwrap().unwrap().len(),
            FULL
        );
    }
    assert!(uncheckable_records(&restored).await.is_empty());
}

#[tokio::test]
async fn test_seen_marks_backup_leaves_out_the_largest_first() {
    let s = Setup::new();
    let (_, mut reader, _, small) = seen(&s, &["a"]).await;
    // More than one commit takes: the full marks have the higher keys, so the size, not
    // the key, decides which go.
    let full = keys(1, 380);
    let smaller = keys(0, 20);
    put_marks(&mut reader, &full, FULL).await;
    put_marks(&mut reader, &smaller, 60_000).await;
    let backup = reader.backup().await.unwrap();
    let left: Vec<[u8; 32]> = backup
        .seen_marks_left_out
        .iter()
        .map(|left| left.key())
        .collect();
    assert!(!left.is_empty());
    // The largest, lowest keys first; the rest carried.
    assert_eq!(left, full[..left.len()]);
    assert_eq!(backup.seen_marks.len(), 401 - left.len());
    // The backup restores, and the protocol is told each record left out can't be checked.
    let restored = fresh(&s, &backup).await;
    for key in &left {
        assert_eq!(restored.record_seen(key).await.unwrap(), None);
    }
    for key in full[left.len()..].iter().chain(&smaller).chain([&small]) {
        assert!(restored.record_seen(key).await.unwrap().is_some());
    }
    let told = uncheckable_records(&restored).await;
    assert_eq!(
        told,
        left.iter()
            .map(|key| (*key, FULL as u64))
            .collect::<Vec<_>>()
    );
}

#[tokio::test]
async fn test_seen_marks_in_place_leaves_out_for_room() {
    let s = Setup::new();
    let (_, mut reader, _, _) = seen(&s, &["a"]).await;
    let first = keys(2, 200);
    put_marks(&mut reader, &first, FULL).await;
    let backup = reader.backup().await.unwrap();
    assert!(backup.seen_marks_left_out.is_empty());
    // The store sees as many more after the backup: together they are more than one
    // commit takes, and the restore in place still goes ahead.
    let later = keys(1, 200);
    put_marks(&mut reader, &later, FULL).await;
    drop(reader);
    let restored = restore_on(&s, s.env(), &backup).await.unwrap();
    let told = uncheckable_records(&restored).await;
    assert!(!told.is_empty());
    let all: Vec<[u8; 32]> = later.iter().chain(&first).copied().collect();
    assert_eq!(
        told,
        all[..told.len()]
            .iter()
            .map(|key| (*key, FULL as u64))
            .collect::<Vec<_>>()
    );
    for key in &all[..told.len()] {
        assert_eq!(restored.record_seen(key).await.unwrap(), None);
    }
    for key in &all[told.len()..] {
        assert!(restored.record_seen(key).await.unwrap().is_some());
    }
}

/// `app`'s transaction filled with writes of its own until `left` bytes remain of the
/// batch an owned store takes: [`crate::store::MAX_BATCH_BYTES`] less its namespace and
/// the 32 bytes of its condition.
fn filled(app: &mut App, left: u64) -> crate::app::state::Tx {
    let ns = app.ns.len() as u64;
    let target = crate::store::MAX_BATCH_BYTES - (ns + 32) - left;
    let mut tx = app.tx().unwrap();
    let chunk = 8 << 20;
    for n in 0u8.. {
        let key = format!("f{n}");
        let rest = target - tx.size() - ns - key.len() as u64;
        tx.put_raw(&key, vec![0; rest.min(chunk) as usize]).unwrap();
        if rest <= chunk {
            break;
        }
    }
    assert_eq!(tx.size(), target);
    tx
}

/// What the duty events of `tx` tell of records whose marks a restore didn't keep: the
/// records told one by one, and the count told together.
fn told_in(tx: &mut crate::app::state::Tx) -> (usize, u64) {
    let mut one_by_one = 0;
    let mut together = 0;
    for event in tx.take_reports() {
        match event {
            AppEvent::RecordUncheckable { .. } | AppEvent::SeenMarkLeftOut { .. } => {
                one_by_one += 1
            }
            AppEvent::SeenMarksLeftOut { records, .. } => together += records,
            _ => {}
        }
    }
    (one_by_one, together)
}

#[tokio::test]
async fn test_seen_marks_too_many_to_tell_one_by_one_are_told_together() {
    let s = Setup::new();
    let (_, mut reader, _, _) = seen(&s, &["a"]).await;
    put_marks(&mut reader, &keys(1, 5), FULL).await;
    let carried = crate::app::seen_marks::carry(&reader.reader())
        .await
        .unwrap();
    assert_eq!(carried.len(), 6);
    // Room for a few hundred bytes: no mark of 64 KiB, nor a duty event for each record.
    let mut tx = filled(&mut reader, 600);
    let installing = crate::app::seen_marks::Installing::of_backup(&carried, &[]);
    let left = installing
        .write(&mut reader, &mut tx, &Default::default())
        .unwrap();
    assert_eq!(left.len(), 5);
    let ns = reader.ns.len() as u64;
    assert!(tx.size() + ns + 32 <= crate::store::MAX_BATCH_BYTES);
    // Every record left out is told, one by one or in the one event that counts the rest.
    let (one_by_one, together) = told_in(&mut tx);
    assert_eq!(one_by_one as u64 + together, 5);
    assert!(together > 0);
}

#[tokio::test]
async fn test_seen_marks_rest_leaving_no_room_to_tell_is_refused_without_marks_too() {
    // Under the room the one event counting the records takes, the rest itself is too
    // large: a restore that leaves 100 bytes is refused with marks and without them.
    let s = Setup::new();
    let (_, mut reader, _, _) = seen(&s, &["a"]).await;
    put_marks(&mut reader, &keys(1, 5), FULL).await;
    let carried = crate::app::seen_marks::carry(&reader.reader())
        .await
        .unwrap();
    for marks in [&carried[..], &[]] {
        let mut tx = filled(&mut reader, 100);
        let installing = crate::app::seen_marks::Installing::of_backup(marks, &[]);
        let refused = installing.write(&mut reader, &mut tx, &Default::default());
        assert!(
            matches!(
                refused,
                Err(AppError::Store(crate::store::StoreError::TooLarge { .. }))
            ),
            "{} marks: {:?}",
            marks.len(),
            refused.err()
        );
    }
    // With the room for that event, it goes ahead, the marks all told.
    let mut tx = filled(&mut reader, 400);
    let installing = crate::app::seen_marks::Installing::of_backup(&carried, &[]);
    assert_eq!(
        installing
            .write(&mut reader, &mut tx, &Default::default())
            .unwrap()
            .len(),
        6
    );
    let (one_by_one, together) = told_in(&mut tx);
    assert_eq!(one_by_one as u64 + together, 6);
}

#[tokio::test]
async fn test_seen_marks_repeated_restores_tell_each_record_once() {
    let s = Setup::new();
    let (_, mut reader, _, _) = seen(&s, &["a"]).await;
    put_marks(&mut reader, &keys(1, 400), FULL).await;
    let backup = reader.backup().await.unwrap();
    let left: Vec<[u8; 32]> = backup
        .seen_marks_left_out
        .iter()
        .map(|left| left.key())
        .collect();
    assert!(!left.is_empty());
    drop(reader);
    // The store still holds the marks the backup left out: in place they are left out
    // again, and each record is told once; a second restore before any acknowledgement
    // tells none again.
    let mut first = None;
    for _ in 0..2 {
        let restored = restore_on(&s, s.env(), &backup).await.unwrap();
        let mut told = uncheckable_records(&restored).await;
        told.sort();
        let mut once = told.clone();
        once.dedup_by_key(|(key, _)| *key);
        assert_eq!(told, once);
        assert!(left.iter().all(|key| told.iter().any(|(k, _)| k == key)));
        match &first {
            None => first = Some(told),
            Some(first) => assert_eq!(&told, first),
        }
    }
}

#[tokio::test]
async fn test_seen_marks_in_place_doesnt_revive_a_mark_whose_lifetime_ended() {
    let s = Setup::new();
    s.protocol.end_mark_at_delete.store(true, SeqCst);
    let (mut writer, mut reader, target, key) = seen(&s, &["a"]).await;
    let backup = reader.backup().await.unwrap();
    writer.delete_record(&target, vec![]).await.unwrap();
    assert!(matches!(reader.read_record_fresh(&target).await.unwrap(),
        RecordRead::Fresh(r) if r.content == RecordContent::Deleted));
    assert_eq!(reader.record_seen(&key).await.unwrap(), None);
    drop(reader);
    let mut restored = restore_on(&s, s.env(), &backup).await.unwrap();
    assert_eq!(restored.record_seen(&key).await.unwrap(), None);
    // The record made anew is taken.
    writer
        .put_record(&target, &value(&["b"]), vec![])
        .await
        .unwrap();
    restored.refresh_identity().await.unwrap();
    assert!(matches!(restored.read_record_fresh(&target).await.unwrap(),
        RecordRead::Fresh(r) if ids(r.content.value()) == ["b"]));
}

#[tokio::test]
async fn test_seen_marks_older_backup_in_place_restores_a_mark_the_store_still_holds() {
    // The rule above holds only for a newer write the store took: a mark it still holds
    // stays, and one only the backup holds of a record the store holds no newer is installed.
    let s = Setup::new();
    let (_, reader, _, key) = seen(&s, &["a"]).await;
    let backup = reader.backup().await.unwrap();
    let mut tx_app = reader;
    let mut tx = tx_app.tx().unwrap();
    tx.delete(&seen_key(&key)).unwrap();
    tx_app.commit(tx).await.unwrap();
    drop(tx_app);
    let restored = restore_on(&s, s.env(), &backup).await.unwrap();
    assert_eq!(
        ids(restored.record_seen(&key).await.unwrap().as_deref()),
        ["a"]
    );
}

#[tokio::test]
async fn test_seen_marks_second_backup_keeps_the_record_for_the_owner_merge() {
    let s = Setup::new();
    s.protocol.merge_marks.store(true, SeqCst);
    let (_, reader, _, key) = seen(&s, &["a", "b"]).await;
    let first = reader.backup().await.unwrap();
    let store = Arc::new(MemoryStore::new());
    let env = || s.env_on(Arc::clone(&store) as Arc<dyn StateStore>);
    let restored = restore_on(&s, env(), &first).await.unwrap();
    // Backed up again before any read: the record its mark is of goes with it.
    let second = edited(&restored.backup().await.unwrap(), |value| {
        let mark = carried(value, &key);
        assert_ne!(mark["record"], serde_json::Value::Null);
        mark["mark"] = json!(pubky_switch_core::enc::b64(&value_of(&["a", "z"])));
    })
    .unwrap();
    drop(restored);
    let restored = restore_on(&s, env(), &second).await.unwrap();
    assert_eq!(
        ids(restored.record_seen(&key).await.unwrap().as_deref()),
        ["a", "b", "z"]
    );
    assert!(uncheckable_records(&restored).await.is_empty());
}

#[tokio::test]
async fn test_seen_marks_never_shrink_the_lists_a_backup_carries() {
    let s = Setup::new();
    let (_, mut reader, _, _) = seen(&s, &["a"]).await;
    let denied = s.w.bob.public();
    reader.deny(&denied).await.unwrap();
    put_marks(&mut reader, &keys(1, 400), FULL).await;
    for backup in [
        reader.backup().await.unwrap(),
        reader.backup_layered().await.unwrap(),
    ] {
        assert!(!backup.seen_marks_left_out.is_empty());
        assert_eq!(backup.peers.denies().len(), 1);
    }
}

#[tokio::test]
async fn test_seen_marks_debug_shows_no_mark_or_key() {
    let s = Setup::new();
    let (_, reader, _, key) = seen(&s, &["secret"]).await;
    let carried = crate::app::seen_marks::carry(&reader.reader())
        .await
        .unwrap();
    let shown = format!("{carried:?}");
    let mark = reader.record_seen(&key).await.unwrap().unwrap();
    assert!(!shown.contains(&format!("{mark:?}")), "{shown}");
    assert!(!shown.contains(&format!("{key:?}")), "{shown}");
    assert!(
        !shown.contains(&pubky_switch_core::enc::b64(&key)),
        "{shown}"
    );
    assert!(
        !shown.contains(&pubky_switch_core::enc::b64(&mark)),
        "{shown}"
    );
    let left = carried[0].left_out();
    let shown = format!("{left:?}");
    assert!(!shown.contains(&format!("{key:?}")), "{shown}");
}
