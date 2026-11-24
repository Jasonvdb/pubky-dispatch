//! The seen marks a backup carries and every restore installs (Switch spec 8.2, 12.4 "Seen
//! marks").

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

/// Marks of `bytes` each, at `keys`, put in `app`'s store as a read would.
async fn put_marks(app: &mut App, keys: &[[u8; 32]], bytes: usize) {
    for chunk in keys.chunks(64) {
        let mut tx = app.tx().unwrap();
        for key in chunk {
            let mark = SeenMark {
                mark: vec![b'm'; bytes],
            };
            tx.put(&seen_key(key), &mark).unwrap();
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

/// The protocols the events tell their marks were incomplete.
fn incomplete(events: &[AppEvent]) -> Vec<String> {
    events
        .iter()
        .filter_map(|event| match event {
            AppEvent::SeenMarksIncomplete { protocol } => Some(protocol.clone()),
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
    assert!(incomplete(&restored.take_events()).is_empty());
    writer
        .put_record(&target, &value(&["a"]), vec![])
        .await
        .unwrap();
    restored.refresh_identity().await.unwrap();
    read_on(&mut restored).await;
    assert!(restored.shared_record(&key).await.unwrap().unwrap().flagged);
}

#[tokio::test]
async fn test_seen_marks_fresh_restore_of_an_older_backup_installs_its_mark() {
    let s = Setup::new();
    let (mut writer, mut reader, target, key) = seen(&s, &["a", "b"]).await;
    let older = reader.backup().await.unwrap();
    writer
        .put_record(&target, &value(&["a", "b", "c"]), vec![])
        .await
        .unwrap();
    read_on(&mut reader).await;
    let restored = fresh(&s, &older).await;
    assert_eq!(
        ids(restored.record_seen(&key).await.unwrap().as_deref()),
        ["a", "b"]
    );
}

#[tokio::test]
async fn test_seen_marks_in_place_replace_the_store_marks_with_the_backup_marks() {
    let s = Setup::new();
    let (mut writer, mut reader, target, key) = seen(&s, &["a"]).await;
    let backup = reader.backup().await.unwrap();
    writer
        .put_record(&target, &value(&["a", "b"]), vec![])
        .await
        .unwrap();
    read_on(&mut reader).await;
    // A mark only the store holds goes with the rest of its state.
    let only_store = keys(5, 1);
    put_marks(&mut reader, &only_store, 3).await;
    drop(reader);
    let restored = restore_on(&s, s.env(), &backup).await.unwrap();
    assert_eq!(
        ids(restored.record_seen(&key).await.unwrap().as_deref()),
        ["a"]
    );
    assert_eq!(restored.record_seen(&only_store[0]).await.unwrap(), None);
}

#[tokio::test]
async fn test_seen_marks_marks_that_dont_fit_are_left_out_and_told() {
    let s = Setup::new();
    let (_, mut reader, _, small) = seen(&s, &["a"]).await;
    // More than one commit takes: the full marks have the higher keys, so the size, not
    // the key, decides which go.
    let full = keys(1, 380);
    let smaller = keys(0, 20);
    put_marks(&mut reader, &full, FULL).await;
    put_marks(&mut reader, &smaller, 60_000).await;
    let backup = reader.backup().await.unwrap();
    assert!(backup.seen_marks_incomplete);
    let carried: Vec<[u8; 32]> = backup.seen_marks.iter().map(|mark| mark.key()).collect();
    let left = full.iter().take_while(|key| !carried.contains(key)).count();
    assert!(left > 0);
    assert_eq!(carried.len(), 401 - left);
    let mut restored = fresh(&s, &backup).await;
    assert_eq!(incomplete(&restored.take_events()), ["sample"]);
    for key in &full[..left] {
        assert_eq!(restored.record_seen(key).await.unwrap(), None);
    }
    for key in full[left..].iter().chain(&smaller).chain([&small]) {
        assert!(restored.record_seen(key).await.unwrap().is_some());
    }
}

#[tokio::test]
async fn test_seen_marks_refuse_a_backup_without_them() {
    let s = Setup::new();
    let (_, reader, _, _) = seen(&s, &["a"]).await;
    let backup = reader.backup().await.unwrap();
    for member in ["seen_marks", "seen_marks_incomplete"] {
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
async fn test_seen_marks_refuse_a_mark_over_the_bound() {
    let s = Setup::new();
    let (_, reader, _, _) = seen(&s, &["a"]).await;
    let backup = reader.backup().await.unwrap();
    let over = edited(&backup, |value| {
        value["seen_marks"][0]["mark"]["mark"] =
            json!(pubky_switch_core::enc::b64(&vec![b' '; FULL + 1]));
    })
    .unwrap();
    let refused = restore_on(&s, s.env_on(Arc::new(MemoryStore::new())), &over).await;
    assert!(matches!(refused, Err(AppError::InvalidData(_))));
}

/// How a backup's restore is built when the room it leaves is measured.
#[derive(Clone, Copy)]
enum Build {
    Plain,
    Layered,
}

/// The bytes a restore built as a backup's check builds it leaves of the batch an owned
/// store takes, without the backup's marks: the room the rest leaves them.
async fn room_left(app: &mut App, build: Build) -> i64 {
    let backup = match build {
        Build::Plain => app.backup().await.unwrap(),
        Build::Layered => app.backup_layered().await.unwrap(),
    };
    let without = edited(&backup, |value| value["seen_marks"] = json!([])).unwrap();
    let check = match build {
        Build::Plain => crate::app::LayerCheck::SizesOnly,
        Build::Layered => crate::app::LayerCheck::Full,
    };
    let built = Box::pin(App::restore_commit(
        crate::app::for_a_check(&app.env),
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
    crate::store::MAX_BATCH_BYTES as i64 - tx.size() as i64 - (restored.ns.len() as i64 + 32)
}

/// Duty events of `app` that fill a restore's commit until one built as `build` leaves
/// `left` bytes, give or take one.
async fn fill_to(app: &mut App, build: Build, left: i64) {
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
    let mut room = room_left(app, build).await;
    while room - left > (5 << 20) {
        let (tx, _) = keep(app, 4 << 20);
        app.commit(tx).await.unwrap();
        room = room_left(app, build).await;
    }
    let mut id = None;
    let mut set = async |app: &mut App, size: i64| -> i64 {
        let (mut tx, new_id) = keep(app, size.max(0) as usize);
        if let Some(old) = id.replace(new_id) {
            tx.delete(&crate::app::state::key::duty(old)).unwrap();
        }
        app.commit(tx).await.unwrap();
        room_left(app, build).await
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
    // The rest leaves 100 bytes: both kinds of backup are taken with their deny entry, the
    // mark left out, and the backup restores, telling the marks incomplete.
    for build in [Build::Plain, Build::Layered] {
        let s = Setup::new();
        let (_, mut reader, _, key) = seen(&s, &["a"]).await;
        reader.deny(&s.w.bob.public()).await.unwrap();
        let mut tx = reader.tx().unwrap();
        tx.delete(&seen_key(&key)).unwrap();
        reader.commit(tx).await.unwrap();
        fill_to(&mut reader, build, 100).await;
        put_marks(&mut reader, &keys(1, 1), FULL).await;
        let backup = match build {
            Build::Plain => reader.backup().await.unwrap(),
            Build::Layered => reader.backup_layered().await.unwrap(),
        };
        assert!(backup.seen_marks.is_empty());
        assert!(backup.seen_marks_incomplete);
        assert_eq!(backup.peers.denies().len(), 1);
        assert_eq!(backup.peers.left_out(), crate::app::ListsLeftOut::Nothing);
        let mut restored = fresh(&s, &backup).await;
        assert_eq!(incomplete(&restored.take_events()), ["sample"]);
    }
}

#[tokio::test]
async fn test_seen_marks_restores_in_place_then_backups_neither_fail_nor_shrink() {
    // About 2,000 bytes left and 20 marks of 64 KiB: the backup leaves them all out. Three
    // restores in place, then both kinds of backup: none is refused, and the deny entry
    // stays.
    let s = Setup::new();
    let (_, mut reader, _, key) = seen(&s, &["a"]).await;
    reader.deny(&s.w.bob.public()).await.unwrap();
    let mut tx = reader.tx().unwrap();
    tx.delete(&seen_key(&key)).unwrap();
    reader.commit(tx).await.unwrap();
    fill_to(&mut reader, Build::Plain, 2_000).await;
    put_marks(&mut reader, &keys(1, 20), FULL).await;
    let first = reader.backup().await.unwrap();
    assert!(first.seen_marks.is_empty() && first.seen_marks_incomplete);
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
async fn test_seen_marks_unreadable_mark_is_left_out_and_told() {
    let s = Setup::new();
    let (_, mut reader, _, key) = seen(&s, &["a"]).await;
    let mut tx = reader.tx().unwrap();
    tx.put_raw(&seen_key(&[9; 32]), b"not a mark".to_vec())
        .unwrap();
    tx.put_raw(
        "hw/not-a-key",
        serde_json::to_vec(&json!({"v": 1})).unwrap(),
    )
    .unwrap();
    reader.commit(tx).await.unwrap();
    let backup = reader.backup().await.unwrap();
    assert!(backup.seen_marks_incomplete);
    assert_eq!(backup.seen_marks.len(), 1);
    let mut restored = fresh(&s, &backup).await;
    assert_eq!(incomplete(&restored.take_events()), ["sample"]);
    assert!(restored.record_seen(&key).await.unwrap().is_some());
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

#[tokio::test]
async fn test_seen_marks_incomplete_is_for_the_protocol_it_names() {
    let s = Setup::new();
    let (_, reader, _, _) = seen(&s, &["a"]).await;
    let backup = edited(&reader.backup().await.unwrap(), |value| {
        value["seen_marks_incomplete"] = json!(true);
    })
    .unwrap();
    drop(reader);
    let protocols = crate::app::ProtocolSet::new(vec![
        s.protocol.clone() as Arc<dyn Protocol>,
        Arc::new(Other) as Arc<dyn Protocol>,
    ])
    .unwrap();
    let mut restored = Box::pin(App::restore(s.env(), protocols, World::config(), &backup))
        .await
        .unwrap();
    let events = restored.take_events();
    let told: Vec<&AppEvent> = events
        .iter()
        .filter(|event| matches!(event, AppEvent::SeenMarksIncomplete { .. }))
        .collect();
    assert_eq!(told.len(), 2);
    for event in told {
        let AppEvent::SeenMarksIncomplete { protocol } = event else {
            unreachable!()
        };
        for name in ["sample", "other"] {
            assert_eq!(restored.event_is_for(event, name), name == protocol);
        }
    }
}
