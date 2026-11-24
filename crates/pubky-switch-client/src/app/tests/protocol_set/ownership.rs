//! Collection identity, policy members and protocol-owned writes (Switch spec 3.3).

use super::*;
use crate::app::{Collection, ParkReason, RecordTarget};
use pubky_switch_core::ident::Policy;

fn collection(name: &str) -> Collection {
    Collection::new(&format!("{name}.list"), Policy::new(name, &[name]))
}

#[tokio::test]
async fn test_record_deletion_restore_gives_each_owner_only_its_registered_collection() {
    let family = Collection::with_sub_scopes("task_lists", Policy::new("tasks", &["tasks"]));
    let tasks = Named {
        collections: vec![family.clone()],
        ..named("tasks")
    };
    let chat = Named {
        collections: vec![collection("chat")],
        ..named("chat")
    };
    let pair = Pair::with(tasks, chat);
    let mut app = pair.join().await;
    let backup = app.backup_layered().await.unwrap();
    let target = RecordTarget::new(family.sub_scope("team").unwrap(), b"key");
    let written = app
        .put_record(&target, br#"{"issued":true}"#, vec![])
        .await
        .unwrap();
    for owner in [&pair.tasks, &pair.chat] {
        *owner.previous_collection.lock().unwrap() = Some("task_lists".into());
    }
    let restored = Box::pin(App::restore(
        pair.env(),
        pair.set(),
        World::config(),
        &backup,
    ))
    .await
    .unwrap();
    assert_eq!(
        restored
            .protocol_get("tasks", &written.key)
            .await
            .unwrap()
            .as_deref(),
        written.content.value()
    );
    assert!(
        restored
            .protocol_get("chat", &written.key)
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn test_protocol_collection_members_survive_join_reload_and_restore() {
    let family = Collection::with_sub_scopes("task_lists", Policy::new("tasks", &["tasks"]));
    let members: Vec<_> = ["alpha", "beta"]
        .into_iter()
        .map(|sub| family.sub_scope(sub).unwrap())
        .collect();
    let p = Pair::with(
        Named {
            collections: members.clone(),
            ..named("tasks")
        },
        named("chat"),
    );
    let mut app = Box::pin(p.join()).await;
    for member in &members {
        let target = RecordTarget::new(member.clone(), b"item");
        app.put_record(&target, b"{}", vec![]).await.unwrap();
    }
    app = Box::pin(p.load(app.app_id())).await.unwrap();
    read(&mut app, 1).await;
    let held = app.records_of("task_lists").await.unwrap();
    assert_eq!(held.len(), 2);
    assert_ne!(held[0].key, held[1].key);
    let backup = app.backup_layered().await.unwrap();
    for fresh in [false, true] {
        let env = if fresh {
            p.w.env_on(Arc::new(MemoryStore::new()) as Arc<dyn StateStore>)
        } else {
            p.env()
        };
        let mut restored = Box::pin(App::restore(env, p.set(), World::config(), &backup))
            .await
            .unwrap();
        read(&mut restored, 2).await;
        assert_eq!(restored.records_of("task_lists").await.unwrap().len(), 2);
    }
}

#[tokio::test]
async fn test_protocol_stopped_record_job_acknowledges_each_owner_once() {
    use super::super::{protocol_api::Pair, shared_flows};
    use crate::app::RecordJob;

    let p = Pair::new();
    let protocols = ProtocolSet::new(vec![
        Arc::new(shared_flows::ItemsProtocol::default()),
        Arc::new(named("chat")),
        Arc::new(named("news")),
    ])
    .unwrap();
    let scopes = ["sample-a", "chat"];
    let mut wallet = Box::pin(p.join_set(&p.alice, "wallet", protocols.clone(), &scopes)).await;
    let mut shop = Box::pin(p.join_set(&p.bob, "shop", protocols, &scopes)).await;
    shop.invite(&p.alice.identity().public()).await.unwrap();

    for kind in ["chat.item", "sample.note"] {
        let target = RecordTarget::new(shared_flows::items(), kind.as_bytes());
        let message = || {
            let mut outgoing = Pair::note(&p.bob, "milk");
            outgoing.kind = kind.to_owned();
            outgoing.record = Some(RecordJob {
                target: target.clone(),
                tag: vec![],
            });
            outgoing
        };
        Box::pin(wallet.put_record(&target, &shared_flows::value(&[]), vec![]))
            .await
            .unwrap();
        let (first, delivery) = Box::pin(wallet.send(message())).await.unwrap();
        assert!(matches!(delivery, Delivery::Accepted { .. }));
        Box::pin(wallet.flush_outbox()).await.unwrap();
        let written = wallet.read_record(&target).await.unwrap().unwrap();
        assert_eq!(shared_flows::ids(written.content.value()), [first]);

        let msg_id = wallet.queue(message()).await.unwrap();
        let delete = Box::pin(wallet.delete_record(&target, vec![]))
            .await
            .unwrap();
        Box::pin(wallet.flush_outbox()).await.unwrap();
        assert!(matches!(
            wallet.delivery(&msg_id).await.unwrap(),
            Some(Delivery::Accepted { .. })
        ));
        let pending = wallet.pending_duty_events().await.unwrap();
        let [stop] = pending.as_slice() else {
            panic!("{pending:?}");
        };
        assert!(matches!(
            &stop.event, AppEvent::RecordJobStopped { msg_id: stopped, key, .. }
            if stopped == &msg_id && key == &delete.key
        ));
        let id = stop.event.id().unwrap();
        let distinct = kind == "chat.item";
        assert_eq!(stop.owners.len(), if distinct { 2 } else { 1 });
        let chat = wallet.unacknowledged_events_for("chat").await.unwrap();
        assert_eq!(chat.contains(&stop.event), distinct);
        assert!(!wallet.event_is_for(&stop.event, "news"));
        if distinct {
            wallet.ack_event_with("chat", id, &[]).await.unwrap();
        }
        let records = wallet.unacknowledged_events_for("sample").await.unwrap();
        assert_eq!(records.as_slice(), std::slice::from_ref(&stop.event));
        assert_eq!(wallet.event_owners(id).unwrap(), ["sample"]);
        wallet.ack_event_with("sample", id, &[]).await.unwrap();
        assert!(wallet.pending_duty_events().await.unwrap().is_empty());
    }
}

async fn check_ownership(raw: bool) {
    // Collection identity and read-scope ownership each suffice, regardless of whether
    // the registered collection admits the supplied policy. Own and unregistered
    // collections under the caller's scope remain usable. When the collection and scope
    // have different owners, neither protocol can create the record, so test only creation.
    for (name, scope, creator) in [
        ("tasks.list", "chat", None),
        ("chat.list", "tasks", None),
        ("other.list", "tasks", Some("tasks")),
        ("chat.list", "chat", Some("chat")),
        ("other.list", "chat", Some("chat")),
    ] {
        let refused = creator != Some("chat");
        for (delete, create_with) in [(false, Some("chat")), (true, creator)] {
            if let Some(owner) = create_with {
                let p = Pair::with(
                    Named {
                        collections: vec![collection("tasks")],
                        ..named("tasks")
                    },
                    Named {
                        collections: vec![collection("chat")],
                        ..named("chat")
                    },
                );
                let mut app = Box::pin(p.join()).await;
                read(&mut app, 1).await;
                let target = RecordTarget::new(
                    Collection::new(name, Policy::new(scope, &[scope])),
                    b"owned",
                );
                let write = if delete {
                    let create = app.record_op(&target, Some(b"{}"), vec![]).await.unwrap();
                    app.submit_batch(OpBatch::for_protocol(owner).entry(create))
                        .await
                        .unwrap();
                    if name == "other.list" {
                        // An unregistered record is visible on the service, but cannot
                        // become a local record. Construct this raw delete at its signed base.
                        assert!(app.read_record(&target).await.unwrap().is_none());
                        let key = app.record_key(&target).unwrap();
                        let view = app.client.record(&key).await.unwrap().view;
                        let op = pubky_switch_core::ops::SignedOp::peek(&view.op).unwrap();
                        let OpKind::RecordPut(mut put) = op.body().kind.clone() else {
                            unreachable!()
                        };
                        put.expected_version = pubky_switch_core::ops::RecordVersion::new(
                            view.generation,
                            view.version,
                        );
                        put.value_sealed = crate::app::records::seal_record(
                            &app.state,
                            &put.policy,
                            put.expected_version,
                            &key,
                            None,
                        )
                        .unwrap();
                        (vec![], OpKind::RecordPut(put))
                    } else {
                        let held = app.read_record(&target).await.unwrap().unwrap();
                        assert_eq!(held.content.value(), Some(b"{}".as_slice()));
                        app.record_op(&target, None, vec![]).await.unwrap()
                    }
                } else {
                    app.record_op(&target, Some(b"{}"), vec![]).await.unwrap()
                };
                let OpKind::RecordPut(put) = &write.1 else {
                    unreachable!()
                };
                assert_eq!(put.expected_version.is_none(), !delete);
                let key = put.key;
                if raw {
                    p.chat.raw_ops.lock().unwrap().push(write);
                    let seq = p.send(app.app_id(), "chat.item");
                    let report = app.receive(None).await.unwrap();
                    assert_eq!(
                        report
                            .events
                            .iter()
                            .any(|event| matches!(event, AppEvent::EffectRefused { .. })),
                        refused,
                        "{name} {scope} delete={delete}: {report:?}"
                    );
                    assert_eq!(
                        app.stored_at(seq).map(|entry| entry.reason),
                        refused.then_some(ParkReason::LifecycleOperation)
                    );
                    assert_eq!(
                        app.protocol_scan("chat", b"").await.unwrap().is_empty(),
                        refused
                    );
                } else {
                    let result = app
                        .submit_batch(OpBatch::for_protocol("chat").entry(write))
                        .await;
                    if refused {
                        usage(result, "writes a record of protocol `tasks`");
                        assert!(
                            app.reader()
                                .scan::<serde_json::Value>("opq/")
                                .await
                                .unwrap()
                                .is_empty()
                        );
                    } else {
                        result.unwrap();
                    }
                }
                let expected_deleted = match (delete, refused) {
                    (false, true) => None,
                    (true, false) => Some(true),
                    _ => Some(false),
                };
                assert_eq!(
                    p.w.switch.record(&key).map(|record| record.state.deleted),
                    expected_deleted,
                    "{name} {scope} delete={delete} raw={raw}"
                );
            }
        }
    }
}

#[tokio::test]
async fn test_protocol_collection_ownership_applies_to_batches() {
    Box::pin(check_ownership(false)).await;
}

#[tokio::test]
async fn test_protocol_collection_ownership_applies_to_raw_effects() {
    Box::pin(check_ownership(true)).await;
}

#[tokio::test]
async fn test_protocol_collection_member_listing_resumes_one_union_cursor() {
    for overlap in [false, true] {
        for fail_commit in [false, true] {
            let family =
                Collection::with_sub_scopes("task_lists", Policy::new("tasks", &["tasks"]));
            let members = [
                family.sub_scope("alpha").unwrap(),
                family.sub_scope("beta").unwrap(),
            ];
            let mut registered = members.to_vec();
            registered.push(members[0].clone());
            if overlap {
                registered.push(family);
            }
            let p = Pair::with(
                Named {
                    collections: registered,
                    ..named("tasks")
                },
                named("chat"),
            );
            let mut app = Box::pin(p.join()).await;
            for n in 0..6 {
                let target =
                    RecordTarget::new(members[n % 2].clone(), format!("item{n}").as_bytes());
                app.put_record(&target, b"{}", vec![]).await.unwrap();
            }
            read(&mut app, 2).await;
            let mut tx = app.tx().unwrap();
            tx.delete_prefix("rec/").unwrap();
            app.commit(tx).await.unwrap();
            p.w.switch.lock().max_page_bytes = 1;
            let before = p.w.switch.lock().shared.listings;
            if fail_commit {
                let store = Arc::new(crate::store::FaultStore::new(
                    p.store.clone(),
                    crate::store::Fault::None,
                ));
                store.fail_put_once(b"list_at");
                app = App::load(p.w.env_on(store), p.set(), World::config(), app.app_id())
                    .await
                    .unwrap();
                assert!(app.list_collections().await.is_err());
                app = p.load(app.app_id()).await.unwrap();
                assert!(app.records_of("task_lists").await.unwrap().is_empty());
            }
            assert!(app.list_collections().await.unwrap());
            assert_eq!(app.records_of("task_lists").await.unwrap().len(), 4);
            app = p.load(app.app_id()).await.unwrap();
            assert!(!app.list_collections().await.unwrap());
            assert_eq!(app.records_of("task_lists").await.unwrap().len(), 6);
            assert_eq!(
                p.w.switch.lock().shared.listings - before,
                6 + u64::from(fail_commit)
            );
            // A caller asking for one fixed policy still gets only that member.
            let mut tx = app.tx().unwrap();
            tx.delete_prefix("rec/").unwrap();
            app.commit(tx).await.unwrap();
            while app.list_collection(&members[0]).await.unwrap().more {}
            assert_eq!(app.records_of("task_lists").await.unwrap().len(), 3);
            while app.list_collection(&members[1]).await.unwrap().more {}
            assert_eq!(app.records_of("task_lists").await.unwrap().len(), 6);
        }
    }
}
