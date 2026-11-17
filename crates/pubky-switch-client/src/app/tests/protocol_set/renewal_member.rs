//! Each protocol's member of the app's record is judged for a renewed certificate before
//! the record carrying it is signed (Switch spec 3.2 step 3, 4.2).

use pubky_switch_core::records::{AppRecordBody, ListedApp, RenewedCert, app_record_path};
use pubky_switch_core::sig::SignedDoc;
use serde_json::{Map, Value};

use super::*;
use crate::app::AppConfig;
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
        // Every record under the renewal, kept, delivered, held or published, carries the
        // members judged for it.
        let mut seen: Vec<SignedDoc> = store.records.lock().unwrap().clone();
        seen.extend(
            p.w.switch
                .applied()
                .iter()
                .filter_map(|op| match &op.body().kind {
                    OpKind::AppPut { record } => Some(record.clone()),
                    _ => None,
                }),
        );
        seen.extend(p.w.switch.app(&me).record);
        let published =
            p.w.homeserver
                .file(p.w.alice.public(), &app_record_path(&me))
                .unwrap();
        seen.push(serde_json::from_slice(&published).unwrap());
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
    }
}

#[tokio::test]
async fn test_renewal_member_refused_keeps_the_held_certificate_until_a_later_read() {
    let refusals: [MemberFor; 2] = [
        |_, _| Err("tasks: no member for it".into()),
        // A member the switch would refuse (Switch wire 1.1).
        |_, _| Ok(Some(object(json!({ "n": 1.5 })))),
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
        let mut waits = Vec::new();
        for _ in 0..2 {
            let report = app.receive(None).await.unwrap();
            assert!(!report.stopped);
            waits.extend(report.events.into_iter().filter_map(|event| match event {
                AppEvent::RenewalWaits {
                    issued_at,
                    protocol,
                    ..
                } => Some((issued_at, protocol)),
                _ => None,
            }));
        }
        assert_eq!(p.tasks.received.lock().unwrap().len(), 1);
        assert_eq!(waits.last(), Some(&(renewed.issued_at(), "tasks".into())));
        // Nothing signed: the certificate and record held stay, and the renewal is owed.
        assert_eq!(app.cert().hash(), old.hash());
        assert_eq!(app.record(), &record);
        assert_eq!(store.records.lock().unwrap().len(), kept);
        assert!(
            p.w.switch.applied()[puts..]
                .iter()
                .all(|op| !matches!(op.body().kind, OpKind::AppPut { .. }))
        );
        assert_eq!(
            app.state.renewal.as_ref().map(AppCert::hash),
            Some(renewed.hash())
        );
        // A later read, the protocol giving a member, takes it.
        *p.tasks.member_for.lock().unwrap() = Some(drop_assign);
        app.receive(None).await.unwrap();
        assert_eq!(app.cert().hash(), renewed.hash());
        let held = AppRecord::verify(app.record(), &p.w.alice.public()).unwrap();
        assert_eq!(
            held.body().protocols.get("tasks"),
            Some(&object(json!({ "list": "home" })))
        );
        assert_eq!(p.w.switch.app(&me).record.as_ref(), Some(app.record()));
    }
}

#[tokio::test]
async fn test_renewal_member_default_keeps_every_member() {
    // The sample protocol leaves `member_for` to its default.
    let w = World::new();
    let request = w.approve(&app_keys("wallet"), &["sample-a"]);
    let mut app = App::join(w.env(), w.protocol.clone(), World::config(), request)
        .await
        .unwrap();
    let member = object(json!({ "list": "home", "assign": "team1" }));
    app.set_protocol_member("sample", Some(member), None)
        .await
        .unwrap();
    let before = AppRecord::verify(app.record(), &w.alice.public()).unwrap();
    w.clock.advance_ms(1000);
    let renewed = crate::app::tests::flows::renew_listed(&w, &app);
    app.receive(None).await.unwrap();
    assert_eq!(app.cert().hash(), renewed.hash());
    let after = AppRecord::verify(app.record(), &w.alice.public()).unwrap();
    assert_eq!(after.body().protocols, before.body().protocols);
    assert_eq!(
        w.switch.app(&app.app_id()).record.as_ref(),
        Some(app.record())
    );
}
