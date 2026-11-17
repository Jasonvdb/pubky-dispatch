//! Each protocol's member of the app's record is judged for a renewed certificate before
//! the record carrying it is signed (Switch spec 3.2 step 3, 4.2).

use pubky_switch_core::ops::MAX_OP_BYTES;
use pubky_switch_core::records::{AppRecordBody, ListedApp, RenewedCert, app_record_path};
use pubky_switch_core::sig::SignedDoc;
use serde_json::{Map, Value};

use super::*;
use crate::app::{AppBackup, AppConfig, Publication};
use crate::store::{MemoryStore, StateStore, Write};

/// A store that keeps every record the app commits as its own (`record`).
struct Recording {
    inner: Arc<MemoryStore>,
    records: Mutex<Vec<SignedDoc>>,
}

impl Recording {
    fn note(&self, batch: &crate::store::WriteBatch) {
        for write in batch.writes() {
            if let Write::Put { key, value, .. } = write
                && key == b"record"
            {
                let kept: Value = serde_json::from_slice(value).unwrap();
                let record = serde_json::from_value(kept["d"].clone()).unwrap();
                self.records.lock().unwrap().push(record);
            }
        }
    }
}

impl StateStore for Recording {
    fn get(&self, ns: &str, key: &[u8]) -> Result<Option<Vec<u8>>, StoreError> {
        self.inner.get(ns, key)
    }

    fn scan(
        &self,
        ns: &str,
        prefix: &[u8],
        after: Option<&[u8]>,
        limit: u32,
    ) -> Result<Vec<crate::store::KeyValue>, StoreError> {
        self.inner.scan(ns, prefix, after, limit)
    }

    fn commit(&self, batch: crate::store::WriteBatch) -> Result<(), StoreError> {
        self.note(&batch);
        self.inner.commit(batch)
    }

    fn acquire(
        &self,
        ns: &str,
        owner: crate::store::StoreOwner,
    ) -> Result<crate::store::AcquireOutcome, StoreError> {
        self.inner.acquire(ns, owner)
    }

    fn commit_if(
        &self,
        ns: &str,
        owner: crate::store::StoreOwner,
        batch: crate::store::WriteBatch,
    ) -> Result<crate::store::CommitOutcome, StoreError> {
        self.note(&batch);
        self.inner.commit_if(ns, owner, batch)
    }
}

const SCOPES: [&str; 3] = ["tasks", "tasks_assign", "chat"];

const HOUR: u64 = 3_600_000;

fn object(value: Value) -> Map<String, Value> {
    value.as_object().unwrap().clone()
}

/// `tasks`'s member names whom tasks are assigned to only under a certificate holding
/// `tasks_assign`.
fn drop_assign(
    member: Option<&Map<String, Value>>,
    cert: &AppCert,
) -> Result<Option<Map<String, Value>>, String> {
    let mut member = member.cloned();
    if !cert.holds_scope("tasks_assign")
        && let Some(member) = &mut member
    {
        member.remove("assign");
    }
    Ok(member)
}

/// A publishing app of `p` running `tasks` and `chat`, its certificate holding `SCOPES`,
/// on a store that keeps every record it commits; `tasks` and `chat` have members.
async fn join(p: &Pair) -> (App, Arc<Recording>) {
    let store = Arc::new(Recording {
        inner: Arc::clone(&p.store),
        records: Mutex::new(Vec::new()),
    });
    let request =
        p.w.signer
            .approve(
                &app_keys("wallet"),
                &AppSpec::new(&SCOPES).with_permissions(&[Permission::ConversationAdd]),
            )
            .unwrap();
    let config = AppConfig {
        publishes_record: true,
        ..World::config()
    };
    let mut app = App::join(
        p.w.env_on(Arc::clone(&store) as Arc<dyn StateStore>),
        p.set(),
        config,
        request,
    )
    .await
    .unwrap();
    let tasks = object(json!({ "list": "home", "assign": "team1" }));
    app.set_protocol_member("tasks", Some(tasks), None)
        .await
        .unwrap();
    app.set_protocol_member("chat", Some(object(json!({ "room": 1 }))), None)
        .await
        .unwrap();
    (app, store)
}

/// The signer renews `app`'s certificate without `tasks_assign` and lists it (Switch spec
/// 3.2 steps 1 and 2).
fn renew(p: &Pair, app: &App) -> AppCert {
    let me = app.app_id();
    let old = app.cert().clone();
    let renewed = issue_cert(
        &p.w.alice,
        &app_keys("wallet"),
        &AppSpec::new(&["tasks", "chat"]).with_permissions(&[Permission::ConversationAdd]),
        p.w.clock.now_ms() + 1000,
    )
    .unwrap();
    p.w.switch
        .signer_op(OpKind::CertPut {
            target_app_id: me,
            cert: renewed.signed().clone(),
        })
        .unwrap();
    p.w.next_doc(|body| {
        body.apps.retain(|a| a.app_id != me);
        body.apps.push(ListedApp {
            app_id: me,
            cert: renewed.hash(),
        });
        body.renewed.retain(|r| r.app_id != me);
        body.renewed.push(RenewedCert {
            app_id: me,
            cert: old.hash(),
            until: None,
        });
    });
    renewed
}

/// How the renewal reaches the app, and what fails after it is signed.
#[derive(Clone, Copy, Debug)]
enum Path {
    /// From its `cert.put`; the delivery of the record carrying it fails once.
    DeliveryFails,
    /// From its `cert.put`; the Homeserver write of that record fails once.
    PublicationFails,
    /// Another device took it and put its record before this app read the `cert.put`,
    /// which the feed then shows as a stub, while this app kept a change: taken from the
    /// directory, the kept change signed anew under it.
    TakenElsewhere,
}

/// The `RenewalWaits` events of `events`: the certificate's `issued_at` and the protocol.
fn waits(events: Vec<AppEvent>) -> Vec<(u64, String)> {
    events
        .into_iter()
        .filter_map(|event| match event {
            AppEvent::RenewalWaits {
                issued_at,
                protocol,
                ..
            } => Some((issued_at, protocol)),
            _ => None,
        })
        .collect()
}

/// The records of the `app.put` operations the switch applied from the `from`th on.
fn puts_from(p: &Pair, from: usize) -> Vec<SignedDoc> {
    p.w.switch.applied()[from..]
        .iter()
        .filter_map(|op| match &op.body().kind {
            OpKind::AppPut { record } => Some(record.clone()),
            _ => None,
        })
        .collect()
}

/// The protocols' members of `app`'s record.
fn members(app: &App) -> Map<String, Value> {
    let record = AppRecord::verify(app.record(), &app.state.meta.identity).unwrap();
    serde_json::to_value(&record.body().protocols)
        .unwrap()
        .as_object()
        .unwrap()
        .clone()
}

#[tokio::test]
async fn test_renewal_member_judged_for_the_new_certificate_before_signing() {
    for path in [
        Path::DeliveryFails,
        Path::PublicationFails,
        Path::TakenElsewhere,
    ] {
        let p = Pair::new();
        *p.tasks.member_for.lock().unwrap() = Some(drop_assign);
        *p.chat.member_for.lock().unwrap() = Some(|_, _| Ok(None));
        *p.tasks.assign_kind.lock().unwrap() = true;
        let (mut app, store) = join(&p).await;
        let me = app.app_id();
        let before = AppRecord::verify(app.record(), &p.w.alice.public()).unwrap();
        assert!(before.body().accepts.contains(&"tasks.assign".into()));
        p.w.clock.advance_ms(1000);
        let renewed = match path {
            Path::DeliveryFails | Path::PublicationFails => {
                let renewed = renew(&p, &app);
                if matches!(path, Path::DeliveryFails) {
                    p.w.switch.fail_next(Fault::Unreachable {
                        path: "/ops".into(),
                        after: 0,
                    });
                } else {
                    p.w.homeserver.fail_writes(1, false);
                }
                renewed
            }
            Path::TakenElsewhere => {
                // A change kept under the old certificate, not delivered yet.
                p.w.switch.fail_next(Fault::Unreachable {
                    path: "/ops".into(),
                    after: 0,
                });
                let kept = object(json!({ "list": "work", "assign": "team1" }));
                app.set_protocol_member("tasks", Some(kept), None)
                    .await
                    .unwrap_err();
                let renewed = renew(&p, &app);
                // The other device's record under the renewal, as its own hooks gave it.
                let mut body =
                    AppRecordBody::new(&renewed, p.set().accepts(&renewed), p.w.clock.now_ms() + 1);
                body.protocols
                    .insert("tasks".into(), object(json!({ "list": "home" })));
                let other = AppRecord::sign(&app_keys("wallet"), body).unwrap();
                p.w.switch
                    .app_op(
                        &app_keys("wallet"),
                        OpKind::AppPut {
                            record: other.signed().clone(),
                        },
                    )
                    .unwrap();
                renewed
            }
        };
        for _ in 0..3 {
            p.w.clock.advance_ms(1000);
            let _ = app.receive(None).await;
        }
        assert_eq!(app.cert().hash(), renewed.hash(), "{path:?}");
        // Every record under the renewal, kept, delivered or held, carries the members
        // judged for it and the kinds the protocols accept under it.
        let mut seen: Vec<SignedDoc> = store.records.lock().unwrap().clone();
        seen.extend(puts_from(&p, 0));
        seen.extend(p.w.switch.app(&me).record);
        let mut under_renewal = 0;
        for record in &seen {
            let record = AppRecord::verify(record, &p.w.alice.public()).unwrap();
            if record.cert().hash() != renewed.hash() {
                continue;
            }
            under_renewal += 1;
            let tasks = record.body().protocols.get("tasks").unwrap();
            assert!(!tasks.contains_key("assign"), "{path:?}: {tasks:?}");
            assert!(
                !record.body().protocols.contains_key("chat"),
                "{path:?}: the removed member"
            );
            assert_eq!(record.body().accepts, p.set().accepts(&renewed), "{path:?}");
        }
        assert!(under_renewal > 2, "{path:?}: {under_renewal}");
        let held = AppRecord::verify(app.record(), &p.w.alice.public()).unwrap();
        let list = match path {
            Path::TakenElsewhere => "work",
            _ => "home",
        };
        assert_eq!(
            held.body().protocols.get("tasks"),
            Some(&object(json!({ "list": list }))),
            "{path:?}"
        );
        assert_eq!(p.w.switch.app(&me).record.as_ref(), Some(app.record()));
        // The Homeserver holds that very record, after a failed write too.
        let published =
            p.w.homeserver
                .file(p.w.alice.public(), &app_record_path(&me))
                .unwrap();
        let published: SignedDoc = serde_json::from_slice(&published).unwrap();
        assert_eq!(&published, app.record(), "{path:?}");
    }
}

#[tokio::test]
async fn test_renewal_member_refused_keeps_the_held_certificate_until_a_later_read() {
    let refusals: [MemberFor; 3] = [
        |_, _| Err("tasks: no member for it".into()),
        // A member the switch would refuse (Switch wire 1.1).
        |_, _| Ok(Some(object(json!({ "n": 1.5 })))),
        // A member that makes the record's `app.put` larger than an operation may be.
        |_, _| Ok(Some(object(json!({ "blob": "a".repeat(MAX_OP_BYTES) })))),
    ];
    for refusal in refusals {
        let p = Pair::new();
        *p.tasks.member_for.lock().unwrap() = Some(refusal);
        let (mut app, store) = join(&p).await;
        let me = app.app_id();
        let old = app.cert().clone();
        let record = app.record().clone();
        p.w.clock.advance_ms(1000);
        let renewed = renew(&p, &app);
        let kept = store.records.lock().unwrap().len();
        let puts = p.w.switch.applied().len();
        // The read goes on: it takes a message sent meanwhile.
        p.send(me, "tasks.item");
        let mut told = Vec::new();
        for _ in 0..3 {
            p.w.clock.advance_ms(1000);
            let report = app.receive(None).await.unwrap();
            assert!(!report.stopped);
            told.extend(waits(report.events));
        }
        assert_eq!(p.tasks.received.lock().unwrap().len(), 1);
        // Told once, however many reads it waits.
        assert_eq!(told, [(renewed.issued_at(), "tasks".into())]);
        // Nothing signed: the certificate and record held stay, and the renewal is owed.
        assert_eq!(app.cert().hash(), old.hash());
        assert_eq!(app.record(), &record);
        assert_eq!(store.records.lock().unwrap().len(), kept);
        assert_eq!(
            app.state.renewal.as_ref().map(AppCert::hash),
            Some(renewed.hash())
        );
        // A change made meanwhile is kept and waits unsent: the switch would refuse a
        // record under the earlier certificate. The reads go on.
        let change = object(json!({ "list": "work", "assign": "team2" }));
        assert_eq!(
            app.set_protocol_member("tasks", Some(change), None)
                .await
                .unwrap(),
            Publication::RenewalWaits
        );
        p.send(me, "tasks.item");
        p.w.clock.advance_ms(1000);
        let report = app.receive(None).await.unwrap();
        assert!(waits(report.events).is_empty());
        assert_eq!(p.tasks.received.lock().unwrap().len(), 2);
        assert!(puts_from(&p, puts).is_empty());
        // A later read, the protocol giving a member, takes it, with the change.
        *p.tasks.member_for.lock().unwrap() = Some(drop_assign);
        app.receive(None).await.unwrap();
        assert_eq!(app.cert().hash(), renewed.hash());
        assert_eq!(members(&app)["tasks"], json!({ "list": "work" }));
        assert_eq!(p.w.switch.app(&me).record.as_ref(), Some(app.record()));
    }
}

/// The record under the renewal is checked whole, once every protocol gave its member: a
/// member that grows is taken when another removed makes room for it.
#[tokio::test]
async fn test_renewal_member_record_checked_whole() {
    let p = Pair::new();
    *p.tasks.member_for.lock().unwrap() = Some(|_, _| {
        Ok(Some(object(
            json!({ "blob": "a".repeat(MAX_OP_BYTES * 8 / 25) }),
        )))
    });
    *p.chat.member_for.lock().unwrap() = Some(|_, _| Ok(None));
    let (mut app, _) = join(&p).await;
    let big = object(json!({ "blob": "b".repeat(MAX_OP_BYTES * 8 / 25) }));
    app.set_protocol_member("chat", Some(big), None)
        .await
        .unwrap();
    p.w.clock.advance_ms(1000);
    let renewed = renew(&p, &app);
    let report = app.receive(None).await.unwrap();
    assert!(waits(report.events).is_empty());
    assert_eq!(app.cert().hash(), renewed.hash());
    assert!(!members(&app).contains_key("chat"));
}

/// A member a protocol removes for the renewal takes its expiry ask with it, as when the
/// protocol removes it itself: it no longer bounds the record's `expires_at`.
#[tokio::test]
async fn test_renewal_member_removed_clears_its_expiry_ask() {
    let p = Pair::new();
    *p.chat.member_for.lock().unwrap() = Some(|_, _| Ok(None));
    let (mut app, _) = join(&p).await;
    let deadline = p.w.clock.now_ms() + HOUR;
    app.set_protocol_member("chat", Some(object(json!({ "room": 2 }))), Some(deadline))
        .await
        .unwrap();
    let held = AppRecord::verify(app.record(), &p.w.alice.public()).unwrap();
    assert_eq!(held.body().expires_at, Some(deadline));
    p.w.clock.advance_ms(1000);
    let renewed = renew(&p, &app);
    app.receive(None).await.unwrap();
    assert_eq!(app.cert().hash(), renewed.hash());
    let held = AppRecord::verify(app.record(), &p.w.alice.public()).unwrap();
    assert_eq!(held.body().expires_at, None);
    assert!(!app.record_expiries().await.unwrap().contains_key("chat"));
    // The record is signed again past that deadline.
    p.w.clock.advance_ms(2 * HOUR);
    app.set_protocol_member("tasks", Some(object(json!({ "list": "later" }))), None)
        .await
        .unwrap();
}

/// A backup taken while a protocol refuses a renewal carries it: the read that refused it
/// moved the cursor past its `cert.put`, and on one device no record carries it yet.
#[tokio::test]
async fn test_renewal_member_refused_renewal_kept_across_a_backup() {
    let p = Pair::new();
    *p.tasks.member_for.lock().unwrap() = Some(|_, _| Err("tasks: not yet".into()));
    let (mut app, _) = join(&p).await;
    p.w.clock.advance_ms(1000);
    let renewed = renew(&p, &app);
    app.receive(None).await.unwrap();
    app.flush_cursor().await.unwrap();
    let backup = AppBackup::from_bytes(&app.backup().await.unwrap().to_bytes().unwrap()).unwrap();
    drop(app);
    let store = Arc::new(MemoryStore::new());
    let mut restored = App::restore(
        p.w.env_on(Arc::clone(&store) as Arc<dyn StateStore>),
        p.set(),
        AppConfig {
            publishes_record: true,
            ..World::config()
        },
        &backup,
    )
    .await
    .unwrap();
    assert_eq!(
        restored.state.renewal.as_ref().map(AppCert::hash),
        Some(renewed.hash())
    );
    *p.tasks.member_for.lock().unwrap() = Some(drop_assign);
    restored.receive(None).await.unwrap();
    assert_eq!(restored.cert().hash(), renewed.hash());
}

/// A renewal another device took, while this one keeps a change and a protocol refuses
/// it: the change waits unsent, the reads go on and take what is sent meanwhile, and the
/// next look after the protocol gives a member takes the renewal with the change.
#[tokio::test]
async fn test_renewal_member_refused_renewal_taken_elsewhere_lets_reads_go_on() {
    let p = Pair::new();
    let (mut app, _) = join(&p).await;
    let me = app.app_id();
    p.w.clock.advance_ms(1000);
    p.w.switch.fail_next(Fault::Unreachable {
        path: "/ops".into(),
        after: 0,
    });
    let kept = object(json!({ "list": "work", "assign": "team1" }));
    app.set_protocol_member("tasks", Some(kept), None)
        .await
        .unwrap_err();
    let renewed = renew(&p, &app);
    let body = AppRecordBody::new(&renewed, p.set().accepts(&renewed), p.w.clock.now_ms() + 1);
    let other = AppRecord::sign(&app_keys("wallet"), body).unwrap();
    p.w.switch
        .app_op(
            &app_keys("wallet"),
            OpKind::AppPut {
                record: other.signed().clone(),
            },
        )
        .unwrap();
    *p.tasks.member_for.lock().unwrap() = Some(|_, _| Err("tasks: not yet".into()));
    // The first read learns the listed certificate from the switch's refusal of the kept
    // record under the earlier one.
    p.w.clock.advance_ms(1000);
    app.receive(None).await.unwrap_err();
    let puts = p.w.switch.applied().len();
    let mut told = Vec::new();
    for _ in 0..3 {
        p.send(me, "tasks.item");
        p.w.clock.advance_ms(1000);
        let report = app.receive(None).await.unwrap();
        told.extend(waits(report.events));
    }
    assert_eq!(told, [(renewed.issued_at(), "tasks".into())]);
    assert_eq!(p.tasks.received.lock().unwrap().len(), 3);
    assert!(puts_from(&p, puts).is_empty());
    assert_ne!(app.cert().hash(), renewed.hash());
    *p.tasks.member_for.lock().unwrap() = Some(drop_assign);
    p.w.clock.advance_ms(crate::app::DOC_CACHE_MS + 1);
    app.receive(None).await.unwrap();
    assert_eq!(app.cert().hash(), renewed.hash());
    assert_eq!(members(&app)["tasks"], json!({ "list": "work" }));
    assert_eq!(p.w.switch.app(&me).record.as_ref(), Some(app.record()));
}

/// The same app on two devices with different protocol sets: `notes` runs on one only. A
/// renewal the other takes keeps the members of the protocols registered there, which keep
/// them by default, and drops the `notes` member, which none there can give for it, telling
/// the host once. `notes` writes its member again on its own device when it next runs.
#[tokio::test]
async fn test_renewal_member_default_keeps_registered_members_and_drops_unowned_ones() {
    let p = Pair::new();
    let notes = Arc::new(named("notes"));
    let three = ProtocolSet::new(vec![
        Arc::clone(&p.tasks) as Arc<dyn Protocol>,
        Arc::clone(&p.chat) as Arc<dyn Protocol>,
        Arc::clone(&notes) as Arc<dyn Protocol>,
    ])
    .unwrap();
    let request =
        p.w.signer
            .approve(
                &app_keys("wallet"),
                &AppSpec::new(&SCOPES).with_permissions(&[Permission::ConversationAdd]),
            )
            .unwrap();
    let store_b = Arc::new(MemoryStore::new());
    let mut b = App::join(
        p.w.env_on(Arc::clone(&store_b) as Arc<dyn StateStore>),
        three,
        World::config(),
        request,
    )
    .await
    .unwrap();
    b.set_multi_device(true).await.unwrap();
    b.set_protocol_member("tasks", Some(object(json!({ "list": "home" }))), None)
        .await
        .unwrap();
    // The device without `notes`, from the same state, in a store of its own.
    let backup = b.backup().await.unwrap();
    let store_a = Arc::new(MemoryStore::new());
    let mut a = App::restore(
        p.w.env_on(Arc::clone(&store_a) as Arc<dyn StateStore>),
        p.set(),
        World::config(),
        &backup,
    )
    .await
    .unwrap();
    a.end_reconcile(UserConfirmed::new()).await.ok();
    let note = object(json!({ "pinned": 3 }));
    b.set_protocol_member("notes", Some(note.clone()), None)
        .await
        .unwrap();
    // `b` takes a renewal, its record carrying `notes`; `a` takes that record as it is.
    p.w.clock.advance_ms(1000);
    let first = renew(&p, &b);
    b.receive(None).await.unwrap();
    assert_eq!(b.cert().hash(), first.hash());
    for _ in 0..2 {
        p.w.clock.advance_ms(1000);
        a.receive(None).await.unwrap();
    }
    assert_eq!(a.cert().hash(), first.hash());
    assert_eq!(members(&a)["notes"], json!(note));
    // `a` takes the next renewal: the record it signs drops `notes`.
    p.w.clock.advance_ms(1000);
    let second = renew(&p, &a);
    let mut dropped = Vec::new();
    for _ in 0..3 {
        p.w.clock.advance_ms(1000);
        let report = a.receive(None).await.unwrap();
        dropped.extend(report.events.into_iter().filter_map(|event| match event {
            AppEvent::MemberDropped {
                issued_at,
                protocol,
            } => Some((issued_at, protocol)),
            _ => None,
        }));
    }
    assert_eq!(a.cert().hash(), second.hash());
    assert_eq!(dropped, [(second.issued_at(), "notes".into())]);
    assert_eq!(members(&a)["tasks"], json!({ "list": "home" }));
    assert!(!members(&a).contains_key("notes"));
    // `b` takes it from the record `a` put, then `notes` writes its member again.
    for _ in 0..2 {
        p.w.clock.advance_ms(1000);
        b.receive(None).await.unwrap();
    }
    assert_eq!(b.cert().hash(), second.hash());
    assert!(!members(&b).contains_key("notes"));
    b.set_protocol_member("notes", Some(note.clone()), None)
        .await
        .unwrap();
    let held = p.w.switch.app(&b.app_id()).record.unwrap();
    let held = AppRecord::verify(&held, &p.w.alice.public()).unwrap();
    assert_eq!(held.cert().hash(), second.hash());
    assert_eq!(held.body().protocols.get("notes"), Some(&note));
}
