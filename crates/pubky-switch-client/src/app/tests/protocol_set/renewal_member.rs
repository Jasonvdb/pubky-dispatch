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
    let renewed = cert_put(p, app, scopes);
    list(p, app, &renewed);
    renewed
}

/// The signer stores a renewal of `app`'s certificate to `scopes` (Switch spec 3.2 step 1).
pub(super) fn cert_put(p: &Pair, app: &App, scopes: &[&str]) -> AppCert {
    let renewed = issue_cert(
        &p.w.alice,
        &app_keys("wallet"),
        &AppSpec::new(scopes).with_permissions(&[Permission::ConversationAdd]),
        p.w.clock.now_ms() + 1000,
    )
    .unwrap();
    p.w.switch
        .signer_op(OpKind::CertPut {
            target_app_id: app.app_id(),
            cert: renewed.signed().clone(),
        })
        .unwrap();
    renewed
}

/// The signer lists `renewed` for `app` (Switch spec 3.2 step 2).
fn list(p: &Pair, app: &App, renewed: &AppCert) {
    let me = app.app_id();
    let old = app.cert().clone();
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
    let answers: [MemberFor; 3] = [
        |_, ask, _| (Some(object(json!({ "n": 1.5 }))), ask),
        |member, _, _| (member.cloned(), RecordExpiry::At(1)),
        // Within the nesting limit alone, past it where the record holds it.
        |_, ask, _| {
            let mut deep = json!(0);
            for _ in 0..126 {
                deep = json!([deep]);
            }
            (Some(object(json!({ "deep": deep }))), ask)
        },
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
    for kept in [false, true] {
        unowned_dropped_then_written_again(kept).await;
    }
}

/// [`test_renewal_member_unowned_dropped_then_written_again_by_its_owner`]; with `kept`,
/// `b` keeps a change it signs over `a`'s record, and `chat`'s ask goes with its member.
async fn unowned_dropped_then_written_again(kept: bool) {
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
    let deadline = p.w.clock.now_ms() + HOUR;
    b.set_protocol_member("chat", Some(room.clone()), Some(deadline))
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
    if kept {
        p.w.switch.fail_next(Fault::Unreachable {
            path: "/ops".into(),
            after: 0,
        });
        b.set_protocol_member("tasks", Some(object(json!({ "list": "work" }))), None)
            .await
            .unwrap_err();
    }
    // `b` takes that record; `chat` is told once, its ask gone, and writes its member again.
    let mut changed = Vec::new();
    // With a kept change, the first read learns the listed certificate from the switch's
    // refusal of that change under the earlier one.
    for _ in 0..3 {
        p.w.clock.advance_ms(1000);
        let Ok(report) = b.receive(None).await else {
            assert!(kept);
            continue;
        };
        for event in report.events {
            if let AppEvent::MemberChanged { protocol, .. } = event {
                changed.push(protocol);
            }
        }
    }
    assert_eq!(b.cert().hash(), second.hash());
    assert_eq!(changed, ["chat"], "kept: {kept}");
    assert!(!b.record_expiries().await.unwrap().contains_key("chat"));
    let signed = AppRecord::verify(b.record(), &p.w.alice.public()).unwrap();
    assert_eq!(signed.body().expires_at, None, "kept: {kept}");
    b.set_protocol_member("chat", Some(room.clone()), None)
        .await
        .unwrap();
    let held = p.w.switch.app(&b.app_id()).record.unwrap();
    let held = AppRecord::verify(&held, &p.w.alice.public()).unwrap();
    assert_eq!(held.cert().hash(), second.hash());
    assert_eq!(held.body().protocols.get("chat"), Some(&room));
}

/// The `MemberChanged` events of `events`.
fn changed(events: Vec<AppEvent>) -> Vec<String> {
    events
        .into_iter()
        .filter_map(|event| match event {
            AppEvent::MemberChanged { protocol, .. } => Some(protocol),
            _ => None,
        })
        .collect()
}

/// Two devices hold one reducing renewal from its `cert.put`: `b`, running `tasks` and
/// `chat`, takes it first; `a`, running `tasks` only, then builds on `b`'s record instead of
/// signing over it, `chat`'s member kept, with a change kept on `a` too.
#[tokio::test]
async fn test_renewal_member_second_device_builds_on_the_first() {
    for kept in [false, true] {
        let p = Pair::new();
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
            p.set(),
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
        let only_tasks =
            ProtocolSet::new(vec![Arc::new(named("tasks")) as Arc<dyn Protocol>]).unwrap();
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
        p.w.clock.advance_ms(1000);
        let renewed = cert_put(&p, &b, &["tasks"]);
        for app in [&mut a, &mut b] {
            p.w.clock.advance_ms(1000);
            app.receive(None).await.unwrap();
        }
        if kept {
            p.w.switch.fail_next(Fault::Unreachable {
                path: "/ops".into(),
                after: 0,
            });
            a.set_protocol_member("tasks", Some(object(json!({ "list": "work" }))), None)
                .await
                .unwrap_err();
        }
        list(&p, &b, &renewed);
        p.w.clock.advance_ms(1000);
        b.receive(None).await.unwrap();
        assert_eq!(b.cert().hash(), renewed.hash());
        p.w.clock.advance_ms(1000);
        let report = a.receive(None).await.unwrap();
        assert_eq!(a.cert().hash(), renewed.hash(), "kept: {kept}");
        assert!(dropped(&report.events).is_empty(), "kept: {kept}");
        let held = p.w.switch.app(&a.app_id()).record.unwrap();
        let held = AppRecord::verify(&held, &p.w.alice.public()).unwrap();
        assert_eq!(held.cert().hash(), renewed.hash());
        assert_eq!(
            held.body().protocols.get("chat"),
            Some(&room),
            "kept: {kept}"
        );
        let list = if kept { "work" } else { "home" };
        assert_eq!(
            held.body().protocols.get("tasks"),
            Some(&object(json!({ "list": list })))
        );
    }
}

/// A change another device makes under the same certificate reaches this one through
/// the feed: each protocol whose member is new or gone is told.
#[tokio::test]
async fn test_renewal_member_other_device_change_is_told() {
    let p = Pair::new();
    let (mut a, _) = join(&p).await;
    a.set_multi_device(true).await.unwrap();
    let backup = a.backup().await.unwrap();
    let mut b = App::restore(
        p.w.env_on(Arc::new(MemoryStore::new()) as Arc<dyn StateStore>),
        p.set(),
        World::config(),
        &backup,
    )
    .await
    .unwrap();
    b.end_reconcile(UserConfirmed::new()).await.ok();
    p.w.clock.advance_ms(1000);
    a.set_protocol_member("chat", None, None).await.unwrap();
    p.w.clock.advance_ms(1000);
    let report = b.receive(None).await.unwrap();
    assert_eq!(changed(report.events), ["chat"]);
    assert_eq!(b.record(), a.record());
    assert!(!members(&b).contains_key("chat"));
    // A member new there is told too.
    a.set_protocol_member("chat", Some(object(json!({ "room": 4 }))), None)
        .await
        .unwrap();
    p.w.clock.advance_ms(1000);
    assert_eq!(changed(b.receive(None).await.unwrap().events), ["chat"]);
}

/// A renewal holding a scope root no registered protocol owns is refused, also when its
/// record would be too large.
#[tokio::test]
async fn test_renewal_member_refused_certificate_before_its_record() {
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
    renew_to(&p, &app, &["tasks", "chat", "news"]);
    let report = app.receive(None).await.unwrap();
    assert!(
        report
            .events
            .iter()
            .any(|event| matches!(event, AppEvent::CertificateRefused { .. })),
        "{:?}",
        report.events
    );
    assert_eq!(app.cert().hash(), old.hash());
}

/// A change kept here that meets another device's later record under the same certificate
/// goes over it: the other device's members of protocols not changed here are kept, and
/// those protocols are told.
#[tokio::test]
async fn test_renewal_member_conflict_builds_on_the_later_record() {
    let p = Pair::new();
    let (mut app, _) = join(&p).await;
    let me = app.app_id();
    let held = AppRecord::verify(app.record(), &p.w.alice.public()).unwrap();
    let mut body = held.body().clone();
    body.updated_at = p.w.clock.now_ms() + 60_000;
    body.protocols
        .insert("tasks".into(), object(json!({ "list": "other" })));
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
    p.w.clock.advance_ms(1000);
    app.set_protocol_member("chat", Some(object(json!({ "room": 9 }))), None)
        .await
        .unwrap();
    let held = p.w.switch.app(&me).record.unwrap();
    let held = AppRecord::verify(&held, &p.w.alice.public()).unwrap();
    assert_eq!(
        held.body().protocols["tasks"],
        object(json!({ "list": "other" }))
    );
    assert_eq!(held.body().protocols["chat"], object(json!({ "room": 9 })));
    assert_eq!(
        held.body().protocols["notes"],
        object(json!({ "pinned": 3 }))
    );
    assert_eq!(changed(app.receive(None).await.unwrap().events), ["tasks"]);
}

/// A later record of the app on the Homeserver, another device's, is taken as it is by
/// the publication check.
#[tokio::test]
async fn test_renewal_member_later_published_copy_is_taken() {
    let p = Pair::new();
    let (mut app, _) = join(&p).await;
    let me = app.app_id();
    let held = AppRecord::verify(app.record(), &p.w.alice.public()).unwrap();
    let mut body = held.body().clone();
    body.updated_at = p.w.clock.now_ms() + 60_000;
    body.protocols.remove("chat");
    let other = AppRecord::sign(&app_keys("wallet"), body).unwrap();
    p.w.homeserver.put(
        p.w.alice.public(),
        &app_record_path(&me),
        serde_json::to_vec(other.signed()).unwrap(),
    );
    assert_eq!(
        app.publish_record().await.unwrap(),
        crate::app::Publication::Superseded
    );
    assert_eq!(app.record(), other.signed());
    assert_eq!(changed(app.receive(None).await.unwrap().events), ["chat"]);
}

/// An ask without a member that can't be signed under the renewal is dropped, the host
/// told, and the renewal taken.
#[tokio::test]
async fn test_renewal_member_lapsed_ask_without_member_is_dropped() {
    let p = Pair::new();
    let (mut app, _) = join(&p).await;
    app.set_protocol_member("chat", None, None).await.unwrap();
    app.renew_record("chat", Some(p.w.clock.now_ms() + 5_000))
        .await
        .unwrap();
    p.w.clock.advance_ms(10_000);
    let renewed = renew(&p, &app);
    let report = app.receive(None).await.unwrap();
    assert_eq!(app.cert().hash(), renewed.hash());
    assert_eq!(dropped(&report.events), ["chat"]);
    assert!(!app.record_expiries().await.unwrap().contains_key("chat"));
}

/// A change kept here signed over another device's later record that lacks `chat`
/// leaves `chat`'s ask out of the record and of the asks kept.
#[tokio::test]
async fn test_renewal_member_conflict_drops_the_gone_members_ask() {
    let p = Pair::new();
    let (mut app, _) = join(&p).await;
    let me = app.app_id();
    let deadline = p.w.clock.now_ms() + HOUR;
    app.set_protocol_member("chat", Some(object(json!({ "room": 1 }))), Some(deadline))
        .await
        .unwrap();
    let held = AppRecord::verify(app.record(), &p.w.alice.public()).unwrap();
    let mut body = held.body().clone();
    body.updated_at = p.w.clock.now_ms() + 60_000;
    body.expires_at = None;
    body.protocols.remove("chat");
    let other = AppRecord::sign(&app_keys("wallet"), body).unwrap();
    p.w.switch
        .app_op(
            &app_keys("wallet"),
            OpKind::AppPut {
                record: other.signed().clone(),
            },
        )
        .unwrap();
    p.w.clock.advance_ms(1000);
    app.set_protocol_member("tasks", Some(object(json!({ "list": "x" }))), None)
        .await
        .unwrap();
    let held = p.w.switch.app(&me).record.unwrap();
    let held = AppRecord::verify(&held, &p.w.alice.public()).unwrap();
    assert!(!held.body().protocols.contains_key("chat"));
    assert_eq!(held.body().expires_at, None);
    assert!(!app.record_expiries().await.unwrap().contains_key("chat"));
}

/// Asks stay with the device that asked: a member taken from another device carries no
/// ask here, so this device's next renewal signs it without that device's deadline. Its
/// protocol is told when the member arrives.
#[tokio::test]
async fn test_renewal_member_remote_deadline_is_not_carried() {
    let p = Pair::new();
    let (mut a, _) = join(&p).await;
    a.set_multi_device(true).await.unwrap();
    let backup = a.backup().await.unwrap();
    let mut b = App::restore(
        p.w.env_on(Arc::new(MemoryStore::new()) as Arc<dyn StateStore>),
        p.set(),
        World::config(),
        &backup,
    )
    .await
    .unwrap();
    b.end_reconcile(UserConfirmed::new()).await.ok();
    p.w.clock.advance_ms(1000);
    let deadline = p.w.clock.now_ms() + HOUR;
    a.set_protocol_member("chat", Some(object(json!({ "room": 5 }))), Some(deadline))
        .await
        .unwrap();
    p.w.clock.advance_ms(1000);
    assert_eq!(changed(b.receive(None).await.unwrap().events), ["chat"]);
    assert!(b.record_expiries().await.unwrap().get("chat") != Some(&RecordExpiry::At(deadline)));
    p.w.clock.advance_ms(1000);
    renew_to(&p, &b, &SCOPES);
    b.receive(None).await.unwrap();
    let held = AppRecord::verify(b.record(), &p.w.alice.public()).unwrap();
    assert_eq!(members(&b)["chat"], json!({ "room": 5 }));
    assert_ne!(held.body().expires_at, Some(deadline));
}

/// An ask whose member was absent already stays when another device's later record is
/// taken as it is.
#[tokio::test]
async fn test_renewal_member_ask_without_member_survives_a_take() {
    let p = Pair::new();
    let (mut app, _) = join(&p).await;
    let me = app.app_id();
    let deadline = p.w.clock.now_ms() + HOUR;
    app.set_protocol_member("chat", None, None).await.unwrap();
    app.renew_record("chat", Some(deadline)).await.unwrap();
    let held = AppRecord::verify(app.record(), &p.w.alice.public()).unwrap();
    let mut body = held.body().clone();
    body.updated_at = p.w.clock.now_ms() + 60_000;
    body.protocols
        .insert("tasks".into(), object(json!({ "list": "other" })));
    let other = AppRecord::sign(&app_keys("wallet"), body).unwrap();
    p.w.homeserver.put(
        p.w.alice.public(),
        &app_record_path(&me),
        serde_json::to_vec(other.signed()).unwrap(),
    );
    app.publish_record().await.unwrap();
    assert_eq!(app.record(), other.signed());
    assert_eq!(
        app.record_expiries().await.unwrap().get("chat"),
        Some(&RecordExpiry::At(deadline))
    );
}

#[tokio::test]
async fn test_renewal_member_uses_pending_choice_under_the_new_certificate() {
    let p = Pair::new();
    let (mut app, store) = Box::pin(join(&p)).await;
    let until = p.w.clock.now_ms() + HOUR;
    app.renew_record("tasks", Some(until)).await.unwrap();
    app.renew_record("chat", Some(until)).await.unwrap();
    p.w.clock.advance_ms(2 * HOUR);
    let desired = object(json!({ "list": "next", "assign": "team2" }));
    usage(
        app.set_protocol_member("tasks", Some(desired), None).await,
        "chat",
    );
    *p.tasks.member_for.lock().unwrap() = Some(drop_assign);
    *p.chat.member_for.lock().unwrap() = Some(|_, _, _| (None, RecordExpiry::Never));
    let renewed = renew(&p, &app);
    for _ in 0..3 {
        p.w.clock.advance_ms(1000);
        let _ = app.receive(None).await;
    }
    assert_eq!(app.cert().hash(), renewed.hash());
    let desired = object(json!({ "list": "next" }));
    let mut matched = 0;
    for signed in store.records.lock().unwrap().iter() {
        let record = AppRecord::verify(signed, &app.identity()).unwrap();
        if record.cert().hash() == renewed.hash() {
            matched += 1;
            assert_eq!(record.body().protocol("tasks"), Some(&desired));
            assert!(record.body().protocol("chat").is_none());
        }
    }
    assert!(matched > 0);
    assert!(!app.protocol_record("tasks").await.unwrap().pending);
}
