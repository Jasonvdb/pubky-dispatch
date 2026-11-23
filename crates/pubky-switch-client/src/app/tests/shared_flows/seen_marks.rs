//! The seen marks a backup carries and a restore installs (Switch spec 8.2, 12.4 "Seen
//! marks").

use std::sync::atomic::Ordering::SeqCst;

use super::*;
use crate::app::records::{SeenMark, seen_key};
use crate::app::{AppBackup, FeedPosition};
use pubky_switch_core::ops::RecordVersion as Version;

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
                &SeenMark::taken(vec![b'm'; bytes], Version::new(1, 1), "sample.items"),
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
        carried(value, &key)["entry"]["mark"] =
            json!(pubky_switch_core::enc::b64(&value_of(&["a", "z"])));
        let marks = value["seen_marks"].as_array_mut().unwrap();
        let live = json!(pubky_switch_core::enc::b64(&live_only));
        marks.retain(|mark| mark["key"] != live);
        marks.push(json!({
            "key": pubky_switch_core::enc::b64(&backup_only),
            "entry": {
                "mark": pubky_switch_core::enc::b64(&value_of(&["q"])),
                "generation": 1,
                "version": 1,
                "collection": "sample.items",
                "ended": false,
            },
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
    assert!(facts(&restored).is_empty());
}

#[tokio::test]
async fn test_seen_marks_refuse_a_mark_over_the_bound() {
    let s = Setup::new();
    let (_, reader, _, key) = seen(&s, &["a"]).await;
    let backup = reader.backup().await.unwrap();
    let with = |bytes: usize| {
        edited(&backup, |value| {
            carried(value, &key)["entry"]["mark"] =
                json!(pubky_switch_core::enc::b64(&vec![b' '; bytes]));
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
            "collection": "sample.items",
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
    for member in ["seen_marks", "seen_marks_left_out", "seen_marks_facts"] {
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
    assert!(facts(&restored).is_empty());
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
    // The backup restores, and the protocol is told how many records it left out.
    let restored = fresh(&s, &backup).await;
    for key in &left {
        assert_eq!(restored.record_seen(key).await.unwrap(), None);
    }
    for key in full[left.len()..].iter().chain(&smaller).chain([&small]) {
        assert!(restored.record_seen(key).await.unwrap().is_some());
    }
    assert_eq!(facts(&restored), [("sample".to_owned(), left.len() as u64)]);
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
    let told = facts(&restored);
    let [(to, n)] = told.as_slice() else {
        panic!("{told:?}")
    };
    assert_eq!(to, "sample");
    let n = *n as usize;
    assert!(n > 0);
    // The largest, lowest keys first.
    let all: Vec<[u8; 32]> = later.iter().chain(&first).copied().collect();
    for key in &all[..n] {
        assert_eq!(restored.record_seen(key).await.unwrap(), None);
    }
    for key in &all[n..] {
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

#[tokio::test]
async fn test_seen_marks_restore_left_out_for_room_holds_the_fact() {
    let s = Setup::new();
    let (_, mut reader, _, _) = seen(&s, &["a"]).await;
    put_marks(&mut reader, &keys(1, 5), FULL).await;
    let carried = crate::app::seen_marks::carry(&reader.reader())
        .await
        .unwrap();
    assert_eq!(carried.len(), 6);
    // Room for a few hundred bytes: no mark of 64 KiB.
    let mut tx = filled(&mut reader, 600);
    let installing =
        crate::app::seen_marks::Installing::of_backup(&carried, &[], &Default::default());
    let start = FeedPosition {
        generation: 1,
        seq: 7,
    };
    let written = installing.write(&mut reader, &mut tx, start).unwrap();
    assert_eq!(written.left.len(), 5);
    let ns = reader.ns.len() as u64;
    assert!(tx.size() + ns + 32 <= crate::store::MAX_BATCH_BYTES);
    assert_eq!(facts(&reader), [("sample".to_owned(), 5)]);
    assert_eq!(reader.state.seen_left_out["sample"].position(), (1, 7));
}

#[tokio::test]
async fn test_seen_marks_never_refuse_at_the_edge_and_hold_the_fact_only_when_left_out() {
    let s = Setup::new();
    let (_, mut reader, _, _) = seen(&s, &["a"]).await;
    let tiny = keys(3, 1);
    put_marks(&mut reader, &tiny, 8).await;
    put_marks(&mut reader, &keys(1, 5), FULL).await;
    let carried = crate::app::seen_marks::carry(&reader.reader())
        .await
        .unwrap();
    let start = FeedPosition {
        generation: 1,
        seq: 7,
    };
    let write = |reader: &mut App, marks: &[crate::app::seen_marks::CarriedMark], left: u64| {
        reader.state.seen_left_out.clear();
        let mut tx = filled(reader, left);
        let installing =
            crate::app::seen_marks::Installing::of_backup(marks, &[], &Default::default());
        let written = installing.write(reader, &mut tx, start).unwrap();
        let ns = reader.ns.len() as u64;
        assert!(tx.size() + ns + 32 <= crate::store::MAX_BATCH_BYTES);
        (written, tx)
    };
    // Nothing left out: no fact, no room kept back.
    assert!(write(&mut reader, &[], 100).0.left.is_empty());
    assert!(facts(&reader).is_empty());
    let only_tiny: Vec<_> = carried
        .iter()
        .filter(|mark| mark.key() == tiny[0])
        .cloned()
        .collect();
    assert!(write(&mut reader, &only_tiny, 300).0.left.is_empty());
    assert!(facts(&reader).is_empty());
    // Marks left out with no room even for the fact: still no refusal; the restore holds
    // the fact for its run.
    let (written, _) = write(&mut reader, &carried, 50);
    assert!(written.left.len() >= 5);
    assert_eq!(
        facts(&reader),
        [("sample".to_owned(), written.left.len() as u64)]
    );
    // With room for it, it is kept.
    let (written, tx) = write(&mut reader, &carried, 400);
    assert!(written.left.len() >= 5);
    reader.commit(tx).await.unwrap();
    let kept = crate::app::seen_marks::facts_of(&reader.reader())
        .await
        .unwrap();
    assert_eq!(kept.len(), 1);
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

/// How a backup's restore is built when the room it leaves is measured.
#[derive(Clone, Copy)]
enum Build {
    /// As a plain backup's check builds it, onto an empty store.
    Plain,
    /// As a layered backup's check builds it.
    Layered,
    /// As a restore in place of `backup` builds it, onto `app`'s store.
    InPlace,
}

/// The bytes a restore built as `build` leaves of the batch an owned store takes, without
/// the marks of `backup` (taken afresh for a check): the room the rest leaves them.
async fn room_left(app: &mut App, build: Build, backup: Option<&AppBackup>) -> i64 {
    let backup = match build {
        Build::Plain => app.backup().await.unwrap(),
        Build::Layered => app.backup_layered().await.unwrap(),
        Build::InPlace => backup.unwrap().clone(),
    };
    let without = edited(&backup, |value| {
        value["seen_marks"] = json!([]);
        value["seen_marks_left_out"] = json!([]);
        value["seen_marks_facts"] = json!({});
    })
    .unwrap();
    let (env, check) = match build {
        Build::Plain => (
            crate::app::for_a_check(&app.env),
            crate::app::LayerCheck::SizesOnly,
        ),
        Build::Layered => (
            crate::app::for_a_check(&app.env),
            crate::app::LayerCheck::Full,
        ),
        Build::InPlace => (app.env.clone(), crate::app::LayerCheck::Install),
    };
    let built = Box::pin(App::restore_commit(
        env,
        app.protocols.clone(),
        app.config.clone(),
        &without,
        check,
    ))
    .await
    .unwrap();
    let crate::app::Restorable::Ready(restored, tx, ..) = built else {
        panic!("the rest doesn't fit")
    };
    let overhead = restored.ns.len() as i64 + 32;
    crate::store::MAX_BATCH_BYTES as i64 - tx.size() as i64 - overhead
}

/// Duty events of `app` that fill a restore's commit until one built as `build` leaves
/// `left` bytes, give or take one: whole ones of 4 MiB, then one whose size is tuned.
async fn fill_to(app: &mut App, build: Build, backup: Option<&AppBackup>, left: i64) {
    let to = app.protocols.names();
    let keep = |app: &mut App, size: usize| {
        let mut tx = app.tx().unwrap();
        let id = app.state.next_duty;
        app.keep_duty_for(
            &mut tx,
            to.clone(),
            crate::app::events::Duty::MemberChanged {
                protocol: "f".repeat(size),
            },
        )
        .unwrap();
        (tx, id)
    };
    let mut room = room_left(app, build, backup).await;
    while room - left > (5 << 20) {
        let (tx, _) = keep(app, 4 << 20);
        app.commit(tx).await.unwrap();
        room = room_left(app, build, backup).await;
    }
    // A filler of `size` bytes, in place of the one before: the room it leaves.
    let mut id = None;
    let mut set = async |app: &mut App, size: i64| -> i64 {
        let (mut tx, new_id) = keep(app, size.max(0) as usize);
        if let Some(old) = id.replace(new_id) {
            tx.delete(&crate::app::state::key::duty(old)).unwrap();
        }
        app.commit(tx).await.unwrap();
        room_left(app, build, backup).await
    };
    let at_zero = set(app, 0).await;
    let guess = at_zero - left;
    let at_guess = set(app, guess).await;
    let slope = ((at_zero - at_guess) / guess.max(1)).max(1);
    let mut size = (at_zero - left) / slope;
    room = set(app, size).await;
    for _ in 0..8 {
        if (room - left).abs() <= 1 {
            return;
        }
        size += (room - left) / slope;
        room = set(app, size).await;
    }
    panic!("the room didn't settle at {left}: {room}");
}

#[tokio::test]
async fn test_seen_marks_never_refuse_or_shrink_a_backup_at_the_edge() {
    // The rest leaves 100 bytes: less than the fact takes. Both kinds of backup are taken
    // with their deny entry, the mark left out, and the backup restores, telling the fact.
    for build in [Build::Plain, Build::Layered] {
        let s = Setup::new();
        let (_, mut reader, _, key) = seen(&s, &["a"]).await;
        reader.deny(&s.w.bob.public()).await.unwrap();
        let mut tx = reader.tx().unwrap();
        tx.delete(&seen_key(&key)).unwrap();
        reader.commit(tx).await.unwrap();
        fill_to(&mut reader, build, None, 100).await;
        put_marks(&mut reader, &keys(1, 1), FULL).await;
        let backup = match build {
            Build::Plain => reader.backup().await.unwrap(),
            _ => reader.backup_layered().await.unwrap(),
        };
        assert_eq!(backup.seen_marks_left_out.len(), 1);
        assert_eq!(backup.peers.denies().len(), 1);
        assert_eq!(backup.peers.left_out(), crate::app::ListsLeftOut::Nothing);
        let mut restored = fresh(&s, &backup).await;
        assert_eq!(restored.record_seen(&keys(1, 1)[0]).await.unwrap(), None);
        let events = restored.take_events();
        assert_eq!(told_of(&events), ["sample"], "{events:?}");
        assert_eq!(facts(&restored), [("sample".to_owned(), 1)]);
    }
}

#[tokio::test]
async fn test_seen_marks_second_restore_in_place_at_the_edge_goes_ahead() {
    // 250 bytes left: one mark left out, the fact kept. The restore again, the fact the
    // store holds beside it, still goes ahead, the fact one, at the same position.
    let s = Setup::new();
    let (_, mut reader, _, key) = seen(&s, &["a"]).await;
    let mut tx = reader.tx().unwrap();
    tx.delete(&seen_key(&key)).unwrap();
    reader.commit(tx).await.unwrap();
    put_marks(&mut reader, &keys(1, 1), FULL).await;
    let backup = reader.backup().await.unwrap();
    let mut tx = reader.tx().unwrap();
    tx.delete(&seen_key(&keys(1, 1)[0])).unwrap();
    reader.commit(tx).await.unwrap();
    fill_to(&mut reader, Build::InPlace, Some(&backup), 250).await;
    drop(reader);
    let first = restore_on(&s, s.env(), &backup).await.unwrap();
    assert_eq!(facts(&first), [("sample".to_owned(), 1)]);
    let at = first.state.seen_left_out["sample"].position();
    drop(first);
    let second = restore_on(&s, s.env(), &backup).await.unwrap();
    assert_eq!(facts(&second), [("sample".to_owned(), 1)]);
    assert_eq!(second.state.seen_left_out["sample"].position(), at);
}

#[tokio::test]
async fn test_seen_marks_in_place_twice_doesnt_revive_a_mark_whose_lifetime_ended() {
    let s = Setup::new();
    s.protocol.end_mark_at_delete.store(true, SeqCst);
    let (mut writer, mut reader, target, key) = seen(&s, &["a"]).await;
    let backup = reader.backup().await.unwrap();
    writer.delete_record(&target, vec![]).await.unwrap();
    assert!(matches!(reader.read_record_fresh(&target).await.unwrap(),
        RecordRead::Fresh(r) if r.content == RecordContent::Deleted));
    drop(reader);
    drop(restore_on(&s, s.env(), &backup).await.unwrap());
    let mut restored = restore_on(&s, s.env(), &backup).await.unwrap();
    assert_eq!(restored.record_seen(&key).await.unwrap(), None);
    writer
        .put_record(&target, &value(&["b"]), vec![])
        .await
        .unwrap();
    restored.refresh_identity().await.unwrap();
    assert!(matches!(restored.read_record_fresh(&target).await.unwrap(),
        RecordRead::Fresh(r) if ids(r.content.value()) == ["b"]));
}

#[tokio::test]
async fn test_seen_marks_refused_newer_read_doesnt_suppress_the_backup_mark() {
    let s = Setup::new();
    let (mut writer, reader, target, key) = seen(&s, &["a", "b"]).await;
    let backup = reader.backup().await.unwrap();
    let store = Arc::new(MemoryStore::new());
    let env = || s.env_on(Arc::clone(&store) as Arc<dyn StateStore>);
    let mut restored = restore_on(&s, env(), &backup).await.unwrap();
    // A newer write that drops what was seen is flagged, its record held refused.
    writer
        .put_record(&target, &value(&["a"]), vec![])
        .await
        .unwrap();
    restored.refresh_identity().await.unwrap();
    read_on(&mut restored).await;
    assert!(restored.shared_record(&key).await.unwrap().unwrap().flagged);
    let mut tx = restored.tx().unwrap();
    tx.delete(&seen_key(&key)).unwrap();
    restored.commit(tx).await.unwrap();
    drop(restored);
    let restored = restore_on(&s, env(), &backup).await.unwrap();
    assert_eq!(
        ids(restored.record_seen(&key).await.unwrap().as_deref()),
        ["a", "b"]
    );
}

/// Each protocol's fact that a restore couldn't keep every mark: the count it holds, as
/// the app keeps it.
fn facts(app: &App) -> Vec<(String, u64)> {
    app.state
        .seen_left_out
        .iter()
        .map(|(name, fact)| (name.clone(), fact.records()))
        .collect()
}

/// The protocols the events tell of their facts.
fn told_of(events: &[AppEvent]) -> Vec<String> {
    events
        .iter()
        .filter_map(|event| match event {
            AppEvent::SeenMarksLeftOut { protocol, .. } => Some(protocol.clone()),
            _ => None,
        })
        .collect()
}

/// `reader`'s own mark of n1 taken away, so only the marks a test puts count.
async fn without_n1(reader: &mut App, key: &[u8; 32]) {
    let mut tx = reader.tx().unwrap();
    tx.delete(&seen_key(key)).unwrap();
    reader.commit(tx).await.unwrap();
}

#[tokio::test]
async fn test_seen_marks_restores_in_place_then_backups_neither_fail_nor_shrink() {
    // About 2,000 bytes left and 20 marks of 64 KiB: the backup leaves them all out. Three
    // restores in place without an acknowledgement, then both kinds of backup: none is
    // refused, and the deny entry stays.
    let s = Setup::new();
    let (_, mut reader, _, key) = seen(&s, &["a"]).await;
    reader.deny(&s.w.bob.public()).await.unwrap();
    without_n1(&mut reader, &key).await;
    fill_to(&mut reader, Build::Plain, None, 2_000).await;
    put_marks(&mut reader, &keys(1, 20), FULL).await;
    let first = reader.backup().await.unwrap();
    assert_eq!(first.seen_marks_left_out.len(), 20);
    drop(reader);
    let mut restored = restore_on(&s, s.env(), &first).await.unwrap();
    for _ in 0..2 {
        drop(restored);
        restored = restore_on(&s, s.env(), &first).await.unwrap();
    }
    let plain = restored.backup().await;
    let layered = restored.backup_layered().await;
    for backup in [plain, layered] {
        let backup = backup.unwrap();
        assert_eq!(backup.peers.denies().len(), 1);
        assert_eq!(backup.peers.left_out(), crate::app::ListsLeftOut::Nothing);
    }
}

#[tokio::test]
async fn test_seen_marks_notices_of_a_restore_cost_a_later_backup_no_room() {
    // A backup that leaves most of 1,000 marks out, restored in place; then normal state
    // that fits the room the rest left before the restore: both kinds of backup are taken,
    // whole, as without marks.
    let s = Setup::new();
    let (_, mut reader, _, key) = seen(&s, &["a"]).await;
    reader.deny(&s.w.bob.public()).await.unwrap();
    without_n1(&mut reader, &key).await;
    fill_to(&mut reader, Build::Plain, None, 400_000).await;
    put_marks(&mut reader, &keys(1, 1_000), 3_000).await;
    let first = reader.backup().await.unwrap();
    assert!(first.seen_marks_left_out.len() > 900);
    drop(reader);
    let mut restored = restore_on(&s, s.env(), &first).await.unwrap();
    let to = restored.protocols.names();
    let mut tx = restored.tx().unwrap();
    restored
        .keep_duty_for(
            &mut tx,
            to,
            crate::app::events::Duty::MemberChanged {
                protocol: "g".repeat(340_000),
            },
        )
        .unwrap();
    restored.commit(tx).await.unwrap();
    let plain = restored.backup().await;
    let layered = restored.backup_layered().await;
    for backup in [plain, layered] {
        let backup = backup.unwrap();
        assert_eq!(backup.peers.denies().len(), 1);
        assert_eq!(backup.peers.left_out(), crate::app::ListsLeftOut::Nothing);
    }
}

#[tokio::test]
async fn test_seen_marks_end_at_the_backup_mark_version_keeps_it_out() {
    // The backup's mark is of the very write whose deletion a proof later verified, as when
    // a delete read first without coverage is upgraded at the same version.
    let s = Setup::new();
    s.protocol.end_mark_at_delete.store(true, SeqCst);
    let (mut writer, mut reader, target, key) = seen(&s, &["a"]).await;
    let backup = reader.backup().await.unwrap();
    writer.delete_record(&target, vec![]).await.unwrap();
    assert!(matches!(reader.read_record_fresh(&target).await.unwrap(),
        RecordRead::Fresh(r) if r.content == RecordContent::Deleted));
    let ended = reader.shared_record(&key).await.unwrap().unwrap().version;
    let backup = edited(&backup, |value| {
        let record = &mut carried(value, &key)["entry"];
        record["generation"] = json!(ended.generation);
        record["version"] = json!(ended.version);
    })
    .unwrap();
    drop(reader);
    let restored = restore_on(&s, s.env(), &backup).await.unwrap();
    assert_eq!(restored.record_seen(&key).await.unwrap(), None);
}

#[tokio::test]
async fn test_seen_marks_refused_newer_write_keeps_the_end() {
    let s = Setup::new();
    s.protocol.end_mark_at_delete.store(true, SeqCst);
    let (mut writer, mut reader, target, key) = seen(&s, &["a"]).await;
    let backup = reader.backup().await.unwrap();
    writer.delete_record(&target, vec![]).await.unwrap();
    assert!(matches!(reader.read_record_fresh(&target).await.unwrap(),
        RecordRead::Fresh(r) if r.content == RecordContent::Deleted));
    drop(reader);
    let mut restored = restore_on(&s, s.env(), &backup).await.unwrap();
    // A newer write the restored app refuses: held, with no mark.
    *s.protocol.forbidden.lock().unwrap() = Some("x".into());
    writer
        .put_record(&target, &value(&["x"]), vec![])
        .await
        .unwrap();
    restored.refresh_identity().await.unwrap();
    read_on(&mut restored).await;
    assert!(restored.shared_record(&key).await.unwrap().unwrap().flagged);
    assert_eq!(restored.record_seen(&key).await.unwrap(), None);
    *s.protocol.forbidden.lock().unwrap() = None;
    drop(restored);
    let restored = restore_on(&s, s.env(), &backup).await.unwrap();
    assert_eq!(restored.record_seen(&key).await.unwrap(), None);
}

#[tokio::test]
async fn test_seen_marks_delete_that_didnt_end_the_mark_keeps_the_backup_mark() {
    // A deletion the store took without ending the mark's lifetime (here: before the
    // collection ended marks at a delete), its mark gone since: only a recorded end keeps
    // the backup's mark out.
    let s = Setup::new();
    let (mut writer, mut reader, target, key) = seen(&s, &["a"]).await;
    let backup = reader.backup().await.unwrap();
    writer.delete_record(&target, vec![]).await.unwrap();
    assert!(matches!(reader.read_record_fresh(&target).await.unwrap(),
        RecordRead::Fresh(r) if r.content == RecordContent::Deleted));
    assert!(reader.record_seen(&key).await.unwrap().is_some());
    without_n1(&mut reader, &key).await;
    s.protocol.end_mark_at_delete.store(true, SeqCst);
    drop(reader);
    let restored = restore_on(&s, s.env(), &backup).await.unwrap();
    assert_eq!(
        ids(restored.record_seen(&key).await.unwrap().as_deref()),
        ["a"]
    );
}

/// A protocol with a collection of its own and nothing else.
struct Other;

impl Protocol for Other {
    fn name(&self) -> String {
        "other".into()
    }

    fn collections(&self) -> Vec<Collection> {
        vec![Collection::new(
            "other.items",
            Policy::new("other-a", &["other-a"]),
        )]
    }

    fn has_keys(&self, _: &str) -> bool {
        false
    }

    fn sent_between_own_apps(&self, _: &str) -> bool {
        false
    }

    fn check_scopes(&self, _: &Message, _: &AppCert, _: &AppCert) -> Result<(), String> {
        Err("other: takes no messages".into())
    }

    fn accepts(&self, _: &AppCert) -> Vec<String> {
        Vec::new()
    }

    fn check_body(&self, _: &crate::app::ReceivedMessage) -> Result<(), String> {
        Err("other: takes no messages".into())
    }

    fn resend_needed(
        &self,
        _: &crate::app::ResendNeeded,
    ) -> Result<Vec<LocalWrite>, crate::app::StoreFailure> {
        Ok(Vec::new())
    }

    fn missed(
        &self,
        _: &crate::app::MissedEntries,
    ) -> Result<Vec<LocalWrite>, crate::app::StoreFailure> {
        Ok(Vec::new())
    }
}

/// `backup` naming `n` records of the sample collection it left out.
fn leaving_out(backup: &AppBackup, first: u8, n: u8) -> AppBackup {
    edited(backup, |value| {
        value["seen_marks_left_out"] = (first..first + n)
            .map(|k| {
                json!({
                    "key": pubky_switch_core::enc::b64(&[k; 32]),
                    "mark_bytes": 3,
                    "collection": "sample.items",
                })
            })
            .collect();
    })
    .unwrap()
}

#[tokio::test]
async fn test_seen_marks_fact_goes_to_the_protocols_whose_records_it_counts() {
    let s = Setup::new();
    let (_, reader, _, _) = seen(&s, &["a"]).await;
    let backup = leaving_out(&reader.backup().await.unwrap(), 9, 1);
    drop(reader);
    let protocols = crate::app::ProtocolSet::new(vec![
        s.protocol.clone() as Arc<dyn Protocol>,
        Arc::new(Other) as Arc<dyn Protocol>,
    ])
    .unwrap();
    let mut restored = Box::pin(App::restore(s.env(), protocols, World::config(), &backup))
        .await
        .unwrap();
    assert_eq!(facts(&restored), [("sample".to_owned(), 1)]);
    assert_eq!(told_of(&restored.take_events()), ["sample"]);
}

#[tokio::test]
async fn test_seen_marks_two_restores_in_place_keep_one_fact() {
    let s = Setup::new();
    let (_, reader, _, _) = seen(&s, &["a"]).await;
    let backup = leaving_out(&reader.backup().await.unwrap(), 9, 2);
    drop(reader);
    drop(restore_on(&s, s.env(), &backup).await.unwrap());
    let restored = restore_on(&s, s.env(), &backup).await.unwrap();
    assert_eq!(facts(&restored), [("sample".to_owned(), 2)]);
}

#[tokio::test]
async fn test_seen_marks_fact_costs_a_restore_in_place_no_refusal() {
    // The reviewer's second sequence, its restore branch, scaled down: a restore leaves the
    // fact; a later backup restored in place onto that store fits the commit only without
    // the fact (50 bytes left). It goes ahead, telling the fact, which it holds for its run.
    let s = Setup::new();
    let (_, mut reader, _, key) = seen(&s, &["a"]).await;
    without_n1(&mut reader, &key).await;
    let first = leaving_out(&reader.backup().await.unwrap(), 9, 2);
    drop(reader);
    let mut restored = restore_on(&s, s.env(), &first).await.unwrap();
    assert_eq!(facts(&restored), [("sample".to_owned(), 2)]);
    let second = restored.backup().await.unwrap();
    fill_to(&mut restored, Build::InPlace, Some(&second), 50).await;
    drop(restored);
    let mut again = restore_on(&s, s.env(), &second).await.unwrap();
    assert_eq!(told_of(&again.take_events()), ["sample"]);
    assert_eq!(facts(&again), [("sample".to_owned(), 2)]);
}

/// `reader`'s backup with the entry of `key` moved to the records it left out.
fn moved_out(backup: &AppBackup, key: &[u8; 32]) -> AppBackup {
    edited(backup, |value| {
        let at = json!(pubky_switch_core::enc::b64(key));
        let marks = value["seen_marks"].as_array_mut().unwrap();
        marks.retain(|mark| mark["key"] != at);
        value["seen_marks_left_out"] = json!([{
            "key": at,
            "mark_bytes": 9,
            "collection": "sample.items",
        }]);
    })
    .unwrap()
}

#[tokio::test]
async fn test_seen_marks_fact_flags_only_unmarked_records_written_before_it() {
    let s = Setup::new();
    let (mut writer, reader, _, key) = seen(&s, &["a"]).await;
    let three = s.target("n3");
    writer
        .put_record(&three, &value(&["three"]), vec![])
        .await
        .unwrap();
    let mut reader = reader;
    read_on(&mut reader).await;
    // n1's mark left out; n3's carried.
    let backup = moved_out(&reader.backup().await.unwrap(), &key);
    // n2 is written after the position the restore starts from.
    writer
        .put_record(&s.target("n2"), &value(&["two"]), vec![])
        .await
        .unwrap();
    let mut restored = fresh(&s, &backup).await;
    s.protocol.unchecked.lock().unwrap().clear();
    restored.refresh_identity().await.unwrap();
    read_on(&mut restored).await;
    let unchecked = s.protocol.unchecked.lock().unwrap().clone();
    let flag = |items: &[&str]| {
        let items: Vec<String> = items.iter().map(|i| (*i).to_owned()).collect();
        unchecked
            .iter()
            .filter(|(seen, _)| *seen == items)
            .map(|(_, flag)| *flag)
            .collect::<Vec<_>>()
    };
    assert_eq!(flag(&["a"]), [true], "{unchecked:?}");
    assert_eq!(flag(&["two"]), [false], "{unchecked:?}");
    assert!(flag(&["three"]).iter().all(|flag| !flag), "{unchecked:?}");
    // Marked since: a later write is checked as usual.
    s.protocol.unchecked.lock().unwrap().clear();
    writer
        .put_record(&s.target("n1"), &value(&["a", "b"]), vec![])
        .await
        .unwrap();
    read_on(&mut restored).await;
    let unchecked = s.protocol.unchecked.lock().unwrap().clone();
    assert!(unchecked.iter().all(|(_, flag)| !flag), "{unchecked:?}");
}

#[tokio::test]
async fn test_seen_marks_fact_survives_acknowledgement_and_a_restart() {
    let s = Setup::new();
    let (_, reader, _, _) = seen(&s, &["a"]).await;
    let backup = leaving_out(&reader.backup().await.unwrap(), 9, 1);
    drop(reader);
    let mut restored = restore_on(&s, s.env(), &backup).await.unwrap();
    let id = restored.app_id();
    assert_eq!(told_of(&restored.take_events()), ["sample"]);
    drop(restored);
    let load = || Box::pin(App::load(s.env(), s.protocol.clone(), World::config(), id));
    let mut loaded = load().await.unwrap();
    assert_eq!(told_of(&loaded.take_events()), ["sample"]);
    loaded.ack_seen_marks_left_out("sample").await.unwrap();
    drop(loaded);
    let mut loaded = load().await.unwrap();
    assert!(told_of(&loaded.take_events()).is_empty());
    assert_eq!(facts(&loaded), [("sample".to_owned(), 1)]);
    assert!(loaded.state.seen_left_out["sample"].acknowledged());
}

#[tokio::test]
async fn test_seen_marks_fact_survives_a_backup_and_a_fresh_restore() {
    let s = Setup::new();
    let (_, reader, _, _) = seen(&s, &["a"]).await;
    let backup = leaving_out(&reader.backup().await.unwrap(), 9, 2);
    drop(reader);
    let restored = restore_on(&s, s.env(), &backup).await.unwrap();
    // Taken before any acknowledgement, the next backup leaves nothing out: it carries the
    // fact.
    let next = restored.backup().await.unwrap();
    assert!(next.seen_marks_left_out.is_empty());
    let mut again = fresh(&s, &next).await;
    assert_eq!(facts(&again), [("sample".to_owned(), 2)]);
    assert_eq!(told_of(&again.take_events()), ["sample"]);
    // A backup that left nothing out and carries no fact ends it, in place.
    let clean = edited(&next, |value| value["seen_marks_facts"] = json!({})).unwrap();
    drop(again);
    let ended = restore_on(&s, s.env(), &clean).await.unwrap();
    assert!(facts(&ended).is_empty());
}

#[tokio::test]
async fn test_seen_marks_in_place_keeps_the_later_position() {
    let s = Setup::new();
    let (mut writer, reader, _, _) = seen(&s, &["a"]).await;
    let first = leaving_out(&reader.backup().await.unwrap(), 9, 2);
    drop(reader);
    let mut restored = restore_on(&s, s.env(), &first).await.unwrap();
    let early = restored.state.seen_left_out["sample"].position();
    // The feed moves on; a later backup leaves another record out.
    writer
        .put_record(&s.target("n5"), &value(&["five"]), vec![])
        .await
        .unwrap();
    restored.refresh_identity().await.unwrap();
    read_on(&mut restored).await;
    let later = leaving_out(&restored.backup().await.unwrap(), 20, 1);
    drop(restored);
    let restored = restore_on(&s, s.env(), &later).await.unwrap();
    let late = restored.state.seen_left_out["sample"].position();
    assert!(late > early, "{late:?} {early:?}");
    assert_eq!(facts(&restored), [("sample".to_owned(), 2)]);
    // Restoring the earlier backup in place again keeps the later position.
    drop(restored);
    let restored = restore_on(&s, s.env(), &first).await.unwrap();
    assert_eq!(restored.state.seen_left_out["sample"].position(), late);
}

#[tokio::test]
async fn test_seen_marks_later_version_wins_carrying_what_was_seen_before() {
    // The test protocol folds what it saw into each new mark: the later version's mark
    // holds the earlier one's items.
    let s = Setup::new();
    let (mut writer, mut reader, target, key) = seen(&s, &["a"]).await;
    let older = reader.backup().await.unwrap();
    writer
        .put_record(&target, &value(&["a", "b"]), vec![])
        .await
        .unwrap();
    read_on(&mut reader).await;
    let newer = reader.backup().await.unwrap();
    let store = Arc::new(MemoryStore::new());
    let env = || s.env_on(Arc::clone(&store) as Arc<dyn StateStore>);
    drop(restore_on(&s, env(), &older).await.unwrap());
    // The backup's later mark replaces the store's earlier one.
    let restored = restore_on(&s, env(), &newer).await.unwrap();
    assert_eq!(
        ids(restored.record_seen(&key).await.unwrap().as_deref()),
        ["a", "b"]
    );
    assert!(facts(&restored).is_empty());
    // The store's later mark stays over the backup's earlier one.
    drop(restored);
    let restored = restore_on(&s, env(), &older).await.unwrap();
    assert_eq!(
        ids(restored.record_seen(&key).await.unwrap().as_deref()),
        ["a", "b"]
    );
    // At an equal version, a different mark is one the restore couldn't keep.
    let differs = edited(&newer, |value| {
        carried(value, &key)["entry"]["mark"] =
            json!(pubky_switch_core::enc::b64(&value_of(&["a", "z"])));
    })
    .unwrap();
    drop(restored);
    let restored = restore_on(&s, env(), &differs).await.unwrap();
    assert_eq!(
        ids(restored.record_seen(&key).await.unwrap().as_deref()),
        ["a", "b"]
    );
    assert_eq!(facts(&restored), [("sample".to_owned(), 1)]);
}

#[tokio::test]
async fn test_seen_marks_ended_lifetime_isnt_revived_after_a_recreation() {
    let s = Setup::new();
    s.protocol.end_mark_at_delete.store(true, SeqCst);
    let (mut writer, mut reader, target, key) = seen(&s, &["a"]).await;
    let backup = reader.backup().await.unwrap();
    writer.delete_record(&target, vec![]).await.unwrap();
    assert!(matches!(reader.read_record_fresh(&target).await.unwrap(),
        RecordRead::Fresh(r) if r.content == RecordContent::Deleted));
    writer
        .put_record(&target, &value(&["b"]), vec![])
        .await
        .unwrap();
    assert!(matches!(reader.read_record_fresh(&target).await.unwrap(),
        RecordRead::Fresh(r) if ids(r.content.value()) == ["b"]));
    drop(reader);
    let mut restored = restore_on(&s, s.env(), &backup).await.unwrap();
    assert_eq!(
        ids(restored.record_seen(&key).await.unwrap().as_deref()),
        ["b"]
    );
    writer
        .put_record(&target, &value(&["b", "c"]), vec![])
        .await
        .unwrap();
    restored.refresh_identity().await.unwrap();
    read_on(&mut restored).await;
    let shared = restored.shared_record(&key).await.unwrap().unwrap();
    assert!(!shared.flagged);
    assert_eq!(ids(shared.content.value()), ["b", "c"]);
}
