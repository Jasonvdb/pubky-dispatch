//! Each protocol's member of the app's record is judged for a renewed certificate before
//! the record carrying it is signed (Switch spec 3.2 step 3, 4.2).

use pubky_switch_core::ops::MAX_OP_BYTES;
use pubky_switch_core::records::{AppRecordBody, ListedApp, RenewedCert, app_record_path};
use pubky_switch_core::sig::SignedDoc;
use serde_json::{Map, Value};

use super::*;
use crate::app::{AppConfig, RecordExpiry};
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
    ask: RecordExpiry,
    cert: &AppCert,
) -> (Option<Map<String, Value>>, RecordExpiry) {
    let mut member = member.cloned();
    if !cert.holds_scope("tasks_assign")
        && let Some(member) = &mut member
    {
        member.remove("assign");
    }
    (member, ask)
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
    renew_to(p, app, &["tasks", "chat"])
}

/// The signer renews `app`'s certificate to `scopes` and lists it.
fn renew_to(p: &Pair, app: &App, scopes: &[&str]) -> AppCert {
    let me = app.app_id();
    let old = app.cert().clone();
    let renewed = issue_cert(
        &p.w.alice,
        &app_keys("wallet"),
        &AppSpec::new(scopes).with_permissions(&[Permission::ConversationAdd]),
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

/// The `MemberDropped` events of `events`.
fn dropped(events: &[AppEvent]) -> Vec<String> {
    events
        .iter()
        .filter_map(|event| match event {
            AppEvent::MemberDropped { protocol, .. } => Some(protocol.clone()),
            _ => None,
        })
        .collect()
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
        *p.chat.member_for.lock().unwrap() = Some(|_, ask, _| (None, ask));
        *p.tasks.assign_kind.lock().unwrap() = true;
        let (mut app, store) = join(&p).await;
        let me = app.app_id();
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
        // and kinds given for it.
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
        let list = match path {
            Path::TakenElsewhere => "work",
            _ => "home",
        };
        assert_eq!(members(&app)["tasks"], json!({ "list": list }), "{path:?}");
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

/// A member that breaks the JSON rules, or comes with an ask that can't be signed, is
/// dropped with its ask, the host told once; the renewal is taken.
#[tokio::test]
async fn test_renewal_member_invalid_answer_is_dropped() {
    let answers: [MemberFor; 2] = [
        |_, ask, _| (Some(object(json!({ "n": 1.5 }))), ask),
        |member, _, _| (member.cloned(), RecordExpiry::At(1)),
    ];
    for answer in answers {
        let p = Pair::new();
        *p.tasks.member_for.lock().unwrap() = Some(answer);
        let (mut app, _) = join(&p).await;
        p.w.clock.advance_ms(1000);
        let renewed = renew(&p, &app);
        let mut events = Vec::new();
        for _ in 0..2 {
            p.w.clock.advance_ms(1000);
            events.extend(app.receive(None).await.unwrap().events);
        }
        assert_eq!(app.cert().hash(), renewed.hash());
        assert_eq!(dropped(&events), ["tasks"]);
        assert!(!members(&app).contains_key("tasks"));
        assert!(members(&app).contains_key("chat"));
        assert!(!app.record_expiries().await.unwrap().contains_key("tasks"));
    }
}

/// A protocol's ask moves with its member: it keeps part of it with no expiry, or removes
/// it, its ask going with it.
#[tokio::test]
async fn test_renewal_member_ask_moves_with_the_member() {
    let answers: [MemberFor; 2] = [
        |_, _, _| (Some(object(json!({ "room": 2 }))), RecordExpiry::Never),
        |_, ask, _| (None, ask),
    ];
    for (n, answer) in answers.into_iter().enumerate() {
        let p = Pair::new();
        *p.chat.member_for.lock().unwrap() = Some(answer);
        let (mut app, _) = join(&p).await;
        let deadline = p.w.clock.now_ms() + HOUR;
        let member = object(json!({ "room": 2, "topic": "x" }));
        app.set_protocol_member("chat", Some(member), Some(deadline))
            .await
            .unwrap();
        p.w.clock.advance_ms(1000);
        let renewed = renew(&p, &app);
        app.receive(None).await.unwrap();
        assert_eq!(app.cert().hash(), renewed.hash());
        let held = AppRecord::verify(app.record(), &p.w.alice.public()).unwrap();
        assert_eq!(held.body().expires_at, None, "{n}");
        let asks = app.record_expiries().await.unwrap();
        if n == 0 {
            assert_eq!(members(&app)["chat"], json!({ "room": 2 }));
            assert_eq!(asks.get("chat"), Some(&RecordExpiry::Never));
        } else {
            assert!(!members(&app).contains_key("chat"));
            assert!(!asks.contains_key("chat"));
        }
    }
}

/// A record whose `app.put` is over the operation size fails each read, as before members
/// were judged, and nothing is taken.
#[tokio::test]
async fn test_renewal_member_oversized_record_fails_the_read() {
    let p = Pair::new();
    *p.tasks.member_for.lock().unwrap() = Some(|_, ask, _| {
        (
            Some(object(json!({ "blob": "a".repeat(MAX_OP_BYTES) }))),
            ask,
        )
    });
    let (mut app, _) = join(&p).await;
    let old = app.cert().clone();
    p.w.clock.advance_ms(1000);
    renew(&p, &app);
    for _ in 0..2 {
        p.w.clock.advance_ms(1000);
        let error = app.receive(None).await.unwrap_err();
        assert!(error.to_string().contains("512 KiB"), "{error}");
    }
    assert_eq!(app.cert().hash(), old.hash());
}

/// A member of a protocol not registered here stays through a renewal that keeps every
/// scope and permission.
#[tokio::test]
async fn test_renewal_member_unowned_kept_when_nothing_is_removed() {
    let p = Pair::new();
    let (mut app, _) = join(&p).await;
    p.w.clock.advance_ms(1000);
    // Another device's record, carrying `notes`, under a renewal holding the same rights.
    let first = renew_to(&p, &app, &SCOPES);
    let mut body = AppRecordBody::new(&first, p.set().accepts(&first), p.w.clock.now_ms() + 1);
    body.protocols
        .insert("notes".into(), object(json!({ "pinned": 3 })));
    let other = AppRecord::sign(&app_keys("wallet"), body).unwrap();
    p.w.switch
        .app_op(
            &app_keys("wallet"),
            OpKind::AppPut {
                record: other.signed().clone(),
            },
        )
        .unwrap();
    for _ in 0..2 {
        p.w.clock.advance_ms(1000);
        app.receive(None).await.unwrap();
    }
    assert_eq!(app.cert().hash(), first.hash());
    p.w.clock.advance_ms(1000);
    let second = renew_to(&p, &app, &SCOPES);
    let report = app.receive(None).await.unwrap();
    assert_eq!(app.cert().hash(), second.hash());
    assert!(dropped(&report.events).is_empty());
    assert_eq!(members(&app)["notes"], json!({ "pinned": 3 }));
}

/// The same app on two devices: `a` runs `tasks`, `b` runs `tasks` and `chat`. A renewal
/// `a` signs that removes a scope drops the `chat` member none on `a` can give for it; `b`
/// takes that record, its `chat` is told, with its ask gone, and writes its member again.
#[tokio::test]
async fn test_renewal_member_unowned_dropped_then_written_again_by_its_owner() {
    let p = Pair::new();
    let both = p.set();
    let request =
        p.w.signer
            .approve(
                &app_keys("wallet"),
                &AppSpec::new(&["tasks", "tasks_assign"])
                    .with_permissions(&[Permission::ConversationAdd]),
            )
            .unwrap();
    let mut b = App::join(
        p.w.env_on(Arc::new(MemoryStore::new()) as Arc<dyn StateStore>),
        both,
        World::config(),
        request,
    )
    .await
    .unwrap();
    b.set_multi_device(true).await.unwrap();
    b.set_protocol_member("tasks", Some(object(json!({ "list": "home" }))), None)
        .await
        .unwrap();
    let backup = b.backup().await.unwrap();
    let only_tasks = ProtocolSet::new(vec![Arc::clone(&p.tasks) as Arc<dyn Protocol>]).unwrap();
    let mut a = App::restore(
        p.w.env_on(Arc::new(MemoryStore::new()) as Arc<dyn StateStore>),
        only_tasks,
        World::config(),
        &backup,
    )
    .await
    .unwrap();
    a.end_reconcile(UserConfirmed::new()).await.ok();
    let room = object(json!({ "room": 1 }));
    b.set_protocol_member("chat", Some(room.clone()), None)
        .await
        .unwrap();
    // `b` takes a renewal with the same rights; `a` takes its record as it is.
    p.w.clock.advance_ms(1000);
    let first = renew_to(&p, &b, &["tasks", "tasks_assign"]);
    for _ in 0..2 {
        p.w.clock.advance_ms(1000);
        b.receive(None).await.unwrap();
    }
    for _ in 0..2 {
        p.w.clock.advance_ms(1000);
        a.receive(None).await.unwrap();
    }
    assert_eq!(a.cert().hash(), first.hash());
    assert_eq!(members(&a)["chat"], json!(room));
    // `a` takes a renewal without `tasks_assign`: its record drops `chat`.
    p.w.clock.advance_ms(1000);
    let second = renew_to(&p, &a, &["tasks"]);
    let report = a.receive(None).await.unwrap();
    assert_eq!(a.cert().hash(), second.hash());
    assert_eq!(dropped(&report.events), ["chat"]);
    assert!(!members(&a).contains_key("chat"));
    // `b` takes that record; `chat` is told once, its ask gone, and writes its member again.
    let mut changed = Vec::new();
    for _ in 0..2 {
        p.w.clock.advance_ms(1000);
        for event in b.receive(None).await.unwrap().events {
            if let AppEvent::MemberChanged { protocol, .. } = event {
                changed.push(protocol);
            }
        }
    }
    assert_eq!(b.cert().hash(), second.hash());
    assert_eq!(changed, ["chat"]);
    assert!(!b.record_expiries().await.unwrap().contains_key("chat"));
    b.set_protocol_member("chat", Some(room.clone()), None)
        .await
        .unwrap();
    let held = p.w.switch.app(&b.app_id()).record.unwrap();
    let held = AppRecord::verify(&held, &p.w.alice.public()).unwrap();
    assert_eq!(held.cert().hash(), second.hash());
    assert_eq!(held.body().protocols.get("chat"), Some(&room));
}
