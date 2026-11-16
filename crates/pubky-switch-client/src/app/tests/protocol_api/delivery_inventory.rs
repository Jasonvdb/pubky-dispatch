use super::*;
use crate::app::{DeliveryOrigin, QueuedMessage};

/// The `msg_id`s of `listed`, in order.
fn queued_ids(listed: &[QueuedMessage]) -> Vec<String> {
    listed.iter().map(|queued| queued.msg_id.clone()).collect()
}

/// The `msg_id`s of `listed` a flush tries now, sorted.
fn not_waiting(listed: &[QueuedMessage]) -> Vec<String> {
    let mut ids: Vec<String> = listed
        .iter()
        .filter(|queued| !queued.waits())
        .map(|queued| queued.msg_id.clone())
        .collect();
    ids.sort();
    ids
}

/// The outbox's messages owed a delivery, in the order a flush tries them, then the one a
/// kept batch puts there once it settles, each with its recipient, kind and holds: a flush
/// delivers exactly those listed as not waiting, and then only the held one is listed.
#[tokio::test]
async fn test_queued_messages_lists_the_outbox_and_a_kept_batch_with_their_holds() {
    let p = Pair::new();
    let protocol = ApiProtocol::new(Mode::Plain);
    let mut wallet = p.join(&p.alice, "wallet", &protocol).await;
    let mut shop = p.join(&p.bob, "shop", &protocol).await;
    let alice = p.alice.identity().public();
    let bob = p.bob.identity().public();
    shop.invite(&alice).await.unwrap();
    let held = wallet.sign_message(Pair::note(&p.bob, "held")).unwrap();
    wallet.queue_signed(held.clone()).await.unwrap();
    p.clock.advance_ms(1);
    let other = wallet.sign_message(Pair::note(&p.bob, "other")).unwrap();
    wallet.queue_signed(other.clone()).await.unwrap();
    let kept = wallet.sign_message(Pair::note(&p.bob, "kept")).unwrap();
    kept_with(&p, &mut wallet, &kept).await;
    assert!(wallet.hold_message("sample", held.msg_id()).await.unwrap());
    let listed = wallet.queued_messages("sample").await.unwrap();
    assert_eq!(
        queued_ids(&listed),
        [held.msg_id(), other.msg_id(), kept.msg_id()]
    );
    assert!(
        listed.iter().all(|queued| queued.to == bob
            && queued.kind == "sample.note"
            && !queued.resend
            && !queued.counterparty_held
            && queued.may_send),
        "{listed:?}"
    );
    assert_eq!(
        listed.iter().map(|queued| queued.held).collect::<Vec<_>>(),
        [true, false, false]
    );
    let Some(Delivery::Kept { batch_id }) = wallet.delivery(kept.msg_id()).await.unwrap() else {
        panic!("not kept")
    };
    assert_eq!(
        listed
            .iter()
            .map(|queued| queued.kept_batch)
            .collect::<Vec<_>>(),
        [None, None, Some(batch_id)]
    );
    // The flush sends the kept batch again first, which queues its message, then tries
    // every message not held: those the listing said.
    let report = wallet.flush_outbox().await.unwrap();
    let mut done = report.done.clone();
    done.sort();
    assert_eq!(done, not_waiting(&listed), "{report:?}");
    assert_eq!(p.bob.switch().entries_from(&alice), 2);
    assert_eq!(
        queued_ids(&wallet.queued_messages("sample").await.unwrap()),
        [held.msg_id()]
    );
    // A hold of the counterparty holds the rest: each says so, and the flush tries none.
    let more = wallet.queue(Pair::note(&p.bob, "more")).await.unwrap();
    wallet.hold_queued(&bob).await.unwrap();
    let listed = wallet.queued_messages("sample").await.unwrap();
    assert_eq!(
        queued_ids(&listed),
        [held.msg_id().to_owned(), more.clone()]
    );
    assert!(
        listed
            .iter()
            .all(|queued| queued.counterparty_held && queued.waits()),
        "{listed:?}"
    );
    assert!(not_waiting(&listed).is_empty());
    let report = wallet.flush_outbox().await.unwrap();
    assert!(report.done.is_empty(), "{report:?}");
    assert_eq!(p.bob.switch().entries_from(&alice), 2);
}

/// A re-send asked of a delivered message is owed again, and listed as a re-send until it
/// goes; the delivered message alone isn't listed.
#[tokio::test]
async fn test_queued_messages_lists_a_resend_until_it_goes() {
    let p = Pair::new();
    let protocol = ApiProtocol::new(Mode::Plain);
    let mut wallet = p.join(&p.alice, "wallet", &protocol).await;
    let mut shop = p.join(&p.bob, "shop", &protocol).await;
    let alice = p.alice.identity().public();
    let bob = p.bob.identity().public();
    shop.invite(&alice).await.unwrap();
    let (msg_id, delivery) = wallet.send(Pair::note(&p.bob, "hello")).await.unwrap();
    assert!(
        matches!(delivery, Delivery::Accepted { .. }),
        "{delivery:?}"
    );
    assert!(wallet.queued_messages("sample").await.unwrap().is_empty());
    wallet.hold_queued(&bob).await.unwrap();
    wallet.resend(&msg_id).await.unwrap();
    let listed = wallet.queued_messages("sample").await.unwrap();
    assert_eq!(queued_ids(&listed), std::slice::from_ref(&msg_id));
    assert!(
        listed[0].resend && listed[0].counterparty_held && listed[0].waits(),
        "{listed:?}"
    );
    wallet.release_queued(&bob).await.unwrap();
    assert!(
        !wallet.queued_messages("sample").await.unwrap()[0].waits(),
        "released"
    );
    wallet.flush_outbox().await.unwrap();
    assert!(wallet.queued_messages("sample").await.unwrap().is_empty());
    assert_eq!(p.bob.switch().entries_from(&alice), 2, "re-sent once");
}

/// A restore's outbox, queued by no call of the restored app, is listed with the hold the
/// backup carries.
#[tokio::test]
async fn test_queued_messages_lists_a_restored_outbox_with_its_holds() {
    let p = Pair::new();
    let protocol = ApiProtocol::new(Mode::Plain);
    let (mut wallet, _shop, signed) = wallet_with_a_queued_note(&p, &protocol).await;
    p.clock.advance_ms(1);
    let other = wallet.queue(Pair::note(&p.bob, "other")).await.unwrap();
    assert!(
        wallet
            .hold_message("sample", signed.msg_id())
            .await
            .unwrap()
    );
    let backup = wallet.backup().await.unwrap();
    drop(wallet);
    let restored = restored_wallet(&p, &protocol, &backup).await;
    let listed = restored.queued_messages("sample").await.unwrap();
    assert_eq!(queued_ids(&listed), [signed.msg_id().to_owned(), other]);
    assert_eq!(
        listed.iter().map(|queued| queued.held).collect::<Vec<_>>(),
        [true, false]
    );
    assert!(
        listed
            .iter()
            .all(|queued| !queued.resend && queued.kept_batch.is_none())
    );
}

/// Holding every listed delivery also holds a kept intent while reads or writes settle
/// its batch, and after loading and restoring the resulting outbox (Switch spec 11).
#[tokio::test]
async fn test_queued_messages_hold_kept_intents_through_read_reload_restore() {
    Box::pin(async {
        for settle_with_read in [false, true] {
            let p = Pair::new();
            let protocol = ApiProtocol::new(Mode::Plain);
            let store = Arc::new(MemoryStore::new());
            let mut wallet = p
                .join_on(
                    &p.alice,
                    "wallet",
                    protocol.clone(),
                    Arc::clone(&store) as Arc<dyn StateStore>,
                )
                .await;
            let mut shop = p.join(&p.bob, "shop", &protocol).await;
            let alice = p.alice.identity().public();
            let bob = p.bob.identity().public();
            shop.invite(&alice).await.unwrap();
            let materialized = wallet.queue(Pair::note(&p.bob, "queued")).await.unwrap();
            let kept = wallet.sign_message(Pair::note(&p.bob, "kept")).unwrap();
            kept_with(&p, &mut wallet, &kept).await;
            let listed = wallet.queued_messages("sample").await.unwrap();
            assert_eq!(
                queued_ids(&listed),
                [materialized, kept.msg_id().to_owned()]
            );
            assert!(listed.iter().all(|message| {
                message.to == bob && message.kind == "sample.note" && !message.resend
            }));
            assert!(listed[0].kept_batch.is_none());
            assert!(listed[1].kept_batch.is_some());
            for message in &listed {
                assert!(
                    wallet
                        .hold_message("sample", &message.msg_id)
                        .await
                        .unwrap()
                );
            }
            if settle_with_read {
                wallet.receive(None).await.unwrap();
            } else {
                wallet
                    .submit_batch(OpBatch::new().op(OpKind::AllowPut {
                        pubky: [8; 32],
                        kind: pubky_switch_core::ops::AllowKind::Conversation,
                    }))
                    .await
                    .unwrap();
            }
            assert!(wallet.kept_batches().await.unwrap().is_empty());
            assert_eq!(p.bob.switch().entries_from(&alice), 0);
            drop(wallet);
            let mut loaded = App::load(
                p.env(&p.alice, Arc::clone(&store) as Arc<dyn StateStore>),
                protocol.clone(),
                config(),
                p.alice.identity().app_keys("wallet").app_id_bytes(),
            )
            .await
            .unwrap();
            loaded.receive(None).await.unwrap();
            loaded.flush_outbox().await.unwrap();
            assert_eq!(p.bob.switch().entries_from(&alice), 0);
            let backup = loaded.backup().await.unwrap();
            drop(loaded);
            let mut restored = restored_wallet(&p, &protocol, &backup).await;
            restored.receive(None).await.unwrap();
            let carried = restored.queued_messages("sample").await.unwrap();
            assert_eq!(carried.len(), 2);
            assert!(
                carried
                    .iter()
                    .all(|message| message.held && message.kept_batch.is_none())
            );
            restored.flush_outbox().await.unwrap();
            assert_eq!(p.bob.switch().entries_from(&alice), 0);
            for message in &carried {
                restored
                    .release_message("sample", &message.msg_id)
                    .await
                    .unwrap();
            }
            restored.flush_outbox().await.unwrap();
            assert_eq!(p.bob.switch().entries_from(&alice), 2);
        }
    })
    .await;
}

/// What the app owes no delivery of isn't listed: a message delivered, one refused for
/// good, one withdrawn, and one whose kept batch was dropped. Nor is anything for a
/// protocol not registered.
#[tokio::test]
async fn test_queued_messages_leaves_out_what_is_owed_no_delivery() {
    let p = Pair::new();
    let protocol = ApiProtocol::new(Mode::Plain);
    let mut wallet = p.join(&p.alice, "wallet", &protocol).await;
    let mut shop = p.join(&p.bob, "shop", &protocol).await;
    shop.invite(&p.alice.identity().public()).await.unwrap();
    let (_, delivery) = wallet.send(Pair::note(&p.bob, "delivered")).await.unwrap();
    assert!(
        matches!(delivery, Delivery::Accepted { .. }),
        "{delivery:?}"
    );
    p.bob.switch().fail_next(Fault::Error {
        path: "/inbox".into(),
        code: ErrorCode::BadRequest,
        current: Value::Null,
    });
    let (failed, delivery) = wallet.send(Pair::note(&p.bob, "refused")).await.unwrap();
    assert!(matches!(delivery, Delivery::Failed { .. }), "{delivery:?}");
    let withdrawn = wallet.queue(Pair::note(&p.bob, "withdrawn")).await.unwrap();
    let signed = wallet.sign_message(Pair::note(&p.bob, "dropped")).unwrap();
    kept_with(&p, &mut wallet, &signed).await;
    assert_eq!(
        queued_ids(&wallet.queued_messages("sample").await.unwrap()),
        [withdrawn.clone(), signed.msg_id().to_owned()]
    );
    assert!(wallet.withdraw_message("sample", &withdrawn).await.unwrap());
    p.alice.switch().fail_next(Fault::Error {
        path: "ops".into(),
        code: ErrorCode::Conflict,
        current: json!({}),
    });
    wallet.receive(None).await.unwrap_or_default();
    assert!(wallet.kept_batches().await.unwrap().is_empty(), "dropped");
    assert!(wallet.outbox_record(&failed).await.is_some(), "kept failed");
    assert!(wallet.queued_messages("sample").await.unwrap().is_empty());
    let error = wallet.queued_messages("other").await.unwrap_err();
    assert!(
        matches!(error, AppError::Refused(Refusal::Usage(_))),
        "{error:?}"
    );
}

async fn queue_origin(wallet: &mut App, signed: &SignedMessage, origin: DeliveryOrigin) {
    match origin {
        DeliveryOrigin::Original => wallet.queue_signed(signed.clone()).await.unwrap(),
        DeliveryOrigin::Reconstructed => wallet.queue_stored(signed.plaintext()).await.unwrap(),
    };
}

async fn listed_origin(wallet: &App, signed: &SignedMessage) -> QueuedMessage {
    wallet
        .queued_messages("sample")
        .await
        .unwrap()
        .into_iter()
        .find(|item| item.msg_id == signed.msg_id())
        .unwrap()
}

#[tokio::test]
async fn test_delivery_origin_inventory_and_dispatch_share_the_policy() {
    let p = Pair::new();
    let protocol = ApiProtocol::new(Mode::Plain);
    *protocol.blocked_origin.lock().unwrap() = Some(DeliveryOrigin::Reconstructed);
    let mut wallet = p.join(&p.alice, "wallet", &protocol).await;
    let mut shop = p.join(&p.bob, "shop", &protocol).await;
    let alice = p.alice.identity().public();
    shop.invite(&alice).await.unwrap();
    let original = wallet.sign_message(Pair::note(&p.bob, "original")).unwrap();
    let reconstructed = wallet
        .sign_message(Pair::note(&p.bob, "reconstructed"))
        .unwrap();
    queue_origin(&mut wallet, &original, DeliveryOrigin::Original).await;
    queue_origin(&mut wallet, &reconstructed, DeliveryOrigin::Reconstructed).await;
    let before = wallet.reader().scan_raw("").await.unwrap();
    let calls = p.alice.switch().applied().len();
    let listed = wallet.queued_messages("sample").await.unwrap();
    assert_eq!(
        wallet.reader().scan_raw("").await.unwrap(),
        before,
        "inventory writes nothing"
    );
    assert_eq!(
        p.alice.switch().applied().len(),
        calls,
        "inventory settles nothing"
    );
    assert_eq!(
        p.bob.switch().entries_from(&alice),
        0,
        "inventory delivers nothing"
    );
    assert_eq!(listed.len(), 2);
    assert!(!listed_origin(&wallet, &original).await.waits());
    let blocked = listed_origin(&wallet, &reconstructed).await;
    assert_eq!(blocked.origin, DeliveryOrigin::Reconstructed);
    assert!(!blocked.resend && !blocked.may_send && blocked.waits());
    wallet.flush_outbox().await.unwrap();
    assert_eq!(
        p.bob.switch().entries_from(&alice),
        1,
        "only original work goes"
    );
    assert_eq!(
        queued_ids(&wallet.queued_messages("sample").await.unwrap()),
        [reconstructed.msg_id()]
    );
    wallet.flush_message(reconstructed.msg_id()).await.unwrap();
    assert_eq!(p.bob.switch().entries_from(&alice), 1);
    assert!(
        protocol
            .send_origins
            .lock()
            .unwrap()
            .iter()
            .any(|(id, origin)| id == reconstructed.msg_id()
                && *origin == DeliveryOrigin::Reconstructed)
    );
    *protocol.blocked_origin.lock().unwrap() = None;
    wallet.flush_message(reconstructed.msg_id()).await.unwrap();
    assert_eq!(p.bob.switch().entries_from(&alice), 2);
}

#[tokio::test]
async fn test_delivery_origin_kept_materialization_and_reconstructed_idempotence() {
    for origin in [DeliveryOrigin::Original, DeliveryOrigin::Reconstructed] {
        let p = Pair::new();
        let protocol = ApiProtocol::new(Mode::Plain);
        let mut wallet = p.join(&p.alice, "wallet", &protocol).await;
        let mut shop = p.join(&p.bob, "shop", &protocol).await;
        shop.invite(&p.alice.identity().public()).await.unwrap();
        let signed = wallet.sign_message(Pair::note(&p.bob, "kept")).unwrap();
        if origin == DeliveryOrigin::Reconstructed {
            wallet.queue_stored(signed.plaintext()).await.unwrap();
        }
        kept_with(&p, &mut wallet, &signed).await;
        assert!(
            wallet
                .hold_message("sample", signed.msg_id())
                .await
                .unwrap()
        );
        let batches = wallet.reader().scan_raw("opq/").await.unwrap();
        wallet.queue_stored(signed.plaintext()).await.unwrap();
        wallet.queue_signed(signed.clone()).await.unwrap();
        assert_eq!(
            wallet.reader().scan_raw("opq/").await.unwrap(),
            batches,
            "queuing does not settle or rewrite the retained intent"
        );
        let item = listed_origin(&wallet, &signed).await;
        assert_eq!(
            item.origin, origin,
            "kept original inherited; reconstructed never promoted"
        );
        assert!(item.held && item.kept_batch.is_none());
        wallet.receive(None).await.unwrap();
        assert!(wallet.kept_batches().await.unwrap().is_empty());
        assert_eq!(
            listed_origin(&wallet, &signed).await.origin,
            origin,
            "settlement preserves origin"
        );
        wallet.flush_outbox().await.unwrap();
        assert_eq!(p.bob.switch().entries_from(&p.alice.identity().public()), 0);
        wallet
            .release_message("sample", signed.msg_id())
            .await
            .unwrap();
        wallet.flush_outbox().await.unwrap();
        assert_eq!(p.bob.switch().entries_from(&p.alice.identity().public()), 1);
    }
}

#[tokio::test]
async fn test_delivery_origin_sent_cache_and_record_job_resends_keep_origin() {
    Box::pin(async {
        for origin in [DeliveryOrigin::Original, DeliveryOrigin::Reconstructed] {
            for with_record in [false, true] {
                let p = Pair::new();
                let protocol = ApiProtocol::new(Mode::Plain);
                let mut wallet = p.join(&p.alice, "wallet", &protocol).await;
                let mut shop = p.join(&p.bob, "shop", &protocol).await;
                let alice = p.alice.identity().public();
                let bob = p.bob.identity().public();
                shop.invite(&alice).await.unwrap();
                let mut signed = wallet.sign_message(Pair::note(&p.bob, "resend")).unwrap();
                if with_record {
                    let target = RecordTarget::new(items(), &signed.hash());
                    signed = signed.with_record(RecordJob {
                        target,
                        tag: b"sent".to_vec(),
                    });
                }
                if origin == DeliveryOrigin::Reconstructed {
                    wallet.queue_stored(signed.plaintext()).await.unwrap();
                    if with_record {
                        // A reconstructed outbox owns no record job. Keep the signed job in
                        // an unanswered batch; its matching copy must retain the same origin.
                        kept_with(&p, &mut wallet, &signed).await;
                        wallet.receive(None).await.unwrap();
                    }
                } else {
                    wallet.queue_signed(signed.clone()).await.unwrap();
                }
                if with_record && origin == DeliveryOrigin::Original {
                    p.alice.switch().fail_next(Fault::Unreachable {
                        path: "ops".into(),
                        after: 1,
                    });
                }
                wallet.flush_message(signed.msg_id()).await.unwrap();
                assert_eq!(p.bob.switch().entries_from(&alice), 1);
                p.alice.switch().lock().faults.clear();
                let before = wallet.reader().scan_raw("").await.unwrap();
                wallet.queue_stored(signed.plaintext()).await.unwrap();
                assert_eq!(
                    wallet.reader().scan_raw("").await.unwrap(),
                    before,
                    "accepted idempotence"
                );
                wallet.hold_queued(&bob).await.unwrap();
                wallet.resend(signed.msg_id()).await.unwrap();
                let resent = listed_origin(&wallet, &signed).await;
                assert_eq!(resent.origin, origin);
                assert!(resent.resend && resent.waits());
                wallet.release_queued(&bob).await.unwrap();
                wallet.flush_message(signed.msg_id()).await.unwrap();
                assert_eq!(p.bob.switch().entries_from(&alice), 2);
            }
        }
    })
    .await;
}

#[tokio::test]
async fn test_delivery_origin_reload_and_both_restore_modes_preserve_snapshot() {
    Box::pin(async {
        for origin in [DeliveryOrigin::Original, DeliveryOrigin::Reconstructed] {
            let p = Pair::new();
            let protocol = ApiProtocol::new(Mode::Plain);
            let store = Arc::new(MemoryStore::new());
            let mut wallet = p
                .join_on(&p.alice, "wallet", protocol.clone(), store.clone())
                .await;
            let signed = wallet.sign_message(Pair::note(&p.bob, "snapshot")).unwrap();
            queue_origin(&mut wallet, &signed, origin).await;
            let id = wallet.app_id();
            drop(wallet);
            let mut wallet = App::load(
                p.env(&p.alice, store.clone()),
                protocol.clone(),
                config(),
                id,
            )
            .await
            .unwrap();
            assert_eq!(listed_origin(&wallet, &signed).await.origin, origin);
            let backup = wallet.backup().await.unwrap();
            wallet
                .hold_message("sample", signed.msg_id())
                .await
                .unwrap();
            drop(wallet);
            let in_place =
                App::restore(p.env(&p.alice, store), protocol.clone(), config(), &backup)
                    .await
                    .unwrap();
            let item = listed_origin(&in_place, &signed).await;
            assert_eq!(item.origin, origin);
            assert!(item.held && !item.resend);
            assert!(
                in_place
                    .outbox_record(signed.msg_id())
                    .await
                    .unwrap()
                    .replay_until_ms()
                    .is_some()
            );
            let repeated = in_place.backup().await.unwrap();
            let fresh = restored_wallet(&p, &protocol, &repeated).await;
            assert_eq!(listed_origin(&fresh, &signed).await.origin, origin);
            assert!(listed_origin(&fresh, &signed).await.held);
            let json: Value = serde_json::from_slice(&repeated.to_bytes().unwrap()).unwrap();
            assert_eq!(
                json["outbox"][0]["origin"],
                serde_json::to_value(origin).unwrap()
            );
            for replacement in [None, Some(json!("invalid"))] {
                let mut invalid = json.clone();
                if let Some(value) = replacement {
                    invalid["outbox"][0]["origin"] = value;
                } else {
                    invalid["outbox"][0]
                        .as_object_mut()
                        .unwrap()
                        .remove("origin");
                }
                assert!(
                    AppBackup::from_bytes(&serde_json::to_vec(&invalid).unwrap()).is_err(),
                    "origin is required current state"
                );
            }
        }
    })
    .await;
}

#[tokio::test]
async fn test_delivery_origin_queue_commit_failure_keeps_origin_atomic() {
    Box::pin(async {
        for origin in [DeliveryOrigin::Original, DeliveryOrigin::Reconstructed] {
            for after in [false, true] {
                let p = Pair::new();
                let protocol = ApiProtocol::new(Mode::Plain);
                let store = Arc::new(MemoryStore::new());
                let wallet = p
                    .join_on(&p.alice, "wallet", protocol.clone(), store.clone())
                    .await;
                let signed = wallet.sign_message(Pair::note(&p.bob, "atomic")).unwrap();
                let id = wallet.app_id();
                drop(wallet);
                let fault = Arc::new(FaultStore::new(
                    store.clone(),
                    if after {
                        StoreFault::FailAfter(1)
                    } else {
                        StoreFault::FailBefore(1)
                    },
                ));
                let mut wallet = App::load(
                    p.env(&p.alice, fault.clone()),
                    protocol.clone(),
                    config(),
                    id,
                )
                .await
                .unwrap();
                let result = match origin {
                    DeliveryOrigin::Original => wallet.queue_signed(signed.clone()).await,
                    DeliveryOrigin::Reconstructed => wallet.queue_stored(signed.plaintext()).await,
                };
                assert!(matches!(result, Err(AppError::Store(_))));
                assert!(
                    matches!(
                        wallet.queued_messages("sample").await,
                        Err(AppError::Refused(Refusal::NotNow(_)))
                    ),
                    "unresolved outcome is not an absence proof"
                );
                assert_eq!(
                    fault.commits(),
                    1,
                    "listing cannot resolve a commit by writing"
                );
                wallet.protocol_commit("sample", &[]).await.unwrap();
                let listed = wallet.queued_messages("sample").await.unwrap();
                assert_eq!(listed.len(), usize::from(after));
                if after {
                    assert_eq!(listed[0].origin, origin);
                }
                drop(wallet);
                let mut fresh = App::load(p.env(&p.alice, store), protocol.clone(), config(), id)
                    .await
                    .unwrap();
                queue_origin(&mut fresh, &signed, origin).await;
                assert_eq!(listed_origin(&fresh, &signed).await.origin, origin);
            }
        }
    })
    .await;
}

#[tokio::test]
async fn test_queued_messages_repeated_batches_are_not_the_latest_status_index() {
    Box::pin(async {
        let p = Pair::new();
        let protocol = ApiProtocol::new(Mode::Plain);
        let mut wallet = p.join(&p.alice, "wallet", &protocol).await;
        let mut shop = p.join(&p.bob, "shop", &protocol).await;
        shop.invite(&p.alice.identity().public()).await.unwrap();
        let signed = wallet.sign_message(Pair::note(&p.bob, "repeated")).unwrap();
        kept_with(&p, &mut wallet, &signed).await;
        let first = wallet.kept_batches().await.unwrap()[0].0;
        let freeze = pubky_switch_core::records::Freeze::sign(
            p.alice.identity().key(),
            pubky_switch_core::records::FreezeBody {
                identity: p.alice.identity().public(),
                inbox: Inbox::new("https://next.example", [77; 32]),
                next_generation: 2,
                issued_at: p.clock.now_ms(),
                nonce: [42; 16],
            },
        )
        .unwrap();
        p.alice.switch().freeze(&freeze).unwrap();
        let error = wallet
            .submit_batch(
                OpBatch::new()
                    .op(OpKind::AllowPut {
                        pubky: [8; 32],
                        kind: pubky_switch_core::ops::AllowKind::Conversation,
                    })
                    .queue(signed.clone()),
            )
            .await
            .unwrap_err();
        let second = error.kept_batch().unwrap();
        assert_ne!(first, second);
        assert_eq!(wallet.kept_batches().await.unwrap().len(), 2);
        assert_eq!(
            wallet.delivery(signed.msg_id()).await.unwrap(),
            Some(Delivery::Kept { batch_id: second })
        );
        let before = wallet.reader().scan_raw("").await.unwrap();
        let listed = wallet.queued_messages("sample").await.unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(
            listed[0].kept_batch,
            Some(first),
            "inventory finds the oldest actual producer, not latest kbm"
        );
        assert_eq!(wallet.reader().scan_raw("").await.unwrap(), before);
        wallet
            .hold_message("sample", signed.msg_id())
            .await
            .unwrap();
        p.alice.switch().unfreeze(&freeze).unwrap();
        wallet.receive(None).await.unwrap();
        wallet.receive(None).await.unwrap();
        wallet.flush_outbox().await.unwrap();
        assert_eq!(p.bob.switch().entries_from(&p.alice.identity().public()), 0);
        assert!(listed_origin(&wallet, &signed).await.held);
        wallet
            .withdraw_message("sample", signed.msg_id())
            .await
            .unwrap();
        assert!(wallet.queued_messages("sample").await.unwrap().is_empty());
        assert!(
            wallet
                .kept_batches()
                .await
                .unwrap()
                .iter()
                .all(|(_, batch)| batch
                    .queued
                    .iter()
                    .all(|item| item.msg_id() != signed.msg_id()))
        );
        wallet.flush_outbox().await.unwrap();
        assert_eq!(p.bob.switch().entries_from(&p.alice.identity().public()), 0);
    })
    .await;
}
