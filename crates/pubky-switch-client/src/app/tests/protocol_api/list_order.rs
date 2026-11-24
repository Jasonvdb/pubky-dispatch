//! Kept peer and deny membership after signed full reads, sibling changes and unanswered writes.

use super::*;

#[tokio::test]
async fn test_project_kept_peer_writes_against_the_signed_list_position() {
    use crate::app::state::Tx;
    use pubky_switch_core::admission::PeerReason;

    let p = Pair::new();
    let protocol = ApiProtocol::new(Mode::LocalNote);
    let mut observer = p.join(&p.bob, "shop", &protocol).await;
    let mut writer = p.join(&p.bob, "till", &protocol).await;
    let earlier = p.alice.identity().public();
    let later = p.carol.identity().public();
    let add = |pubky| {
        OpBatch::new().op(OpKind::AllowPut {
            pubky,
            reason: PeerReason::Kept,
        })
    };

    let first = writer.submit_batch(add(earlier)).await.unwrap();
    let removal = writer
        .submit_batch(OpBatch::new().op(OpKind::AllowDelete {
            pubky: earlier,
            reason: PeerReason::Kept,
        }))
        .await
        .unwrap();
    assert!(
        observer
            .allow_list()
            .await
            .unwrap()
            .kept_peers()
            .next()
            .is_none()
    );
    let cutoff = observer
        .client
        .observed_allow()
        .await
        .unwrap()
        .position
        .unwrap();
    let second = writer.submit_batch(add(later)).await.unwrap();

    // Both ordinary answers bind their signed operations. The app reading the list
    // hasn't read the later operation; only its proof can move this projection forward.
    assert_eq!(first.proofs.len(), 1);
    assert_eq!(second.proofs.len(), 1);
    let before = &first.proofs[0];
    let after = &second.proofs[0];
    assert_eq!(before.envelope().generation, cutoff.generation);
    assert_eq!(after.envelope().generation, cutoff.generation);
    assert!(before.envelope().seq < cutoff.seq && cutoff.seq < after.envelope().seq);
    let applied = p.bob.switch().applied();
    let operation = |proof: &TransitionProof| {
        applied
            .iter()
            .find(|op| op.item_hash().unwrap() == proof.envelope().item_hash)
            .unwrap()
    };
    let batch = |proof| crate::client::Batch::new(vec![operation(proof).clone()], None).unwrap();
    let placed = |proof: &TransitionProof| {
        Some(crate::app::FeedPosition {
            generation: proof.envelope().generation,
            seq: proof.envelope().seq,
        })
    };
    let mut projected = Tx::new(&observer.ns);
    // A complete read without a position need not hold an older operation that
    // this peer's later authenticated removal already covers.
    let removed = placed(&removal.proofs[0]);
    assert!(
        !observer
            .after_list_observations(placed(before), Some(None), removed)
            .unwrap()
    );
    assert!(matches!(
        observer.after_list_observations(removed, Some(None), placed(before)),
        Err(AppError::Refused(Refusal::NotNow(_)))
    ));
    let ordered = [
        (batch(after), placed(after)),
        (batch(before), placed(before)),
    ];
    let plan = observer.project_old_list_batches(&ordered).await.unwrap();
    observer
        .settle_old_op(
            operation(before),
            plan.get(operation(before), 0).unwrap(),
            &mut projected,
        )
        .await
        .unwrap();
    assert!(projected.pending_writes().is_empty());
    observer
        .settle_old_op(
            operation(after),
            plan.get(operation(after), 0).unwrap(),
            &mut projected,
        )
        .await
        .unwrap();
    assert_eq!(
        projected.pending_put_keys("lc/kept/"),
        [pubky_switch_core::enc::pubky_id(&later)]
    );

    // Plan both groups before staging either one. An operation without its service
    // placement cannot be compared with the complete read, even on this generation.
    let unresolved = [(batch(after), placed(after)), (batch(before), None)];
    let mut tx = Tx::new(&observer.ns);
    let result: Result<(), AppError> = async {
        let plan = observer.project_old_list_batches(&unresolved).await?;
        for (batch, _) in &unresolved {
            let op = &batch.ops()[0];
            observer
                .settle_old_op(op, plan.get(op, 0).unwrap(), &mut tx)
                .await?;
        }
        Ok(())
    }
    .await;
    assert!(matches!(result, Err(AppError::Refused(Refusal::NotNow(_)))));
    assert!(tx.pending_writes().is_empty());
}

#[tokio::test]
async fn test_answered_deny_operations_respect_the_complete_list() {
    use crate::app::admission::deny_key;
    use crate::app::batch::PendingBatch;

    let p = Pair::new();
    let protocol = ApiProtocol::new(Mode::LocalNote);
    let mut observer = p.join(&p.bob, "shop", &protocol).await;
    let mut writer = p.join(&p.bob, "till", &protocol).await;
    let peer = p.alice.identity().public();
    let deny = || OpBatch::new().op(OpKind::DenyPut { pubky: peer });
    let older = writer.submit_batch(deny()).await.unwrap();
    writer.undeny(&peer).await.unwrap();
    assert!(!observer.allow_list().await.unwrap().deny.contains(&peer));
    let newer = writer.submit_batch(deny()).await.unwrap();
    let applied = p.bob.switch().applied();
    let mut tx = observer.tx().unwrap();
    for (answer, expected) in [(older, None), (newer, Some(true))] {
        let [proof] = answer.proofs.as_slice() else {
            panic!("one signed operation")
        };
        let op = applied
            .iter()
            .find(|op| op.item_hash().unwrap() == proof.envelope().item_hash)
            .unwrap();
        if expected.is_none() {
            // Knowing it was applied in this generation does not order it against the
            // complete read. Leave the local transaction untouched until its proof is known.
            assert!(matches!(
                observer
                    .settle_op(op, None, &PendingBatch::default(), &mut tx)
                    .await,
                Err(AppError::Refused(Refusal::NotNow(_)))
            ));
            assert!(tx.pending_writes().is_empty());
        }
        observer
            .settle_op(op, Some(proof), &PendingBatch::default(), &mut tx)
            .await
            .unwrap();
        assert_eq!(tx.pending_state(&deny_key(&peer)), expected);
    }
}

#[tokio::test]
async fn test_retry_keeps_a_siblings_later_kept_peer_after_reopen() {
    retry_after_a_sibling_sets_kept_peer(true).await;
}

#[tokio::test]
async fn test_retry_keeps_a_siblings_later_kept_peer_removal_after_reopen() {
    retry_after_a_sibling_sets_kept_peer(false).await;
}

async fn retry_after_a_sibling_sets_kept_peer(present: bool) {
    use crate::app::KeptBatchStatus;
    use crate::testing::Fault;
    use pubky_switch_core::admission::PeerReason;

    let p = Pair::new();
    let protocol = ApiProtocol::new(Mode::LocalNote);
    let store = Arc::new(MemoryStore::new());
    let mut shop = p
        .join_on(&p.bob, "shop", protocol.clone(), store.clone())
        .await;
    let mut kiosk = p.join(&p.bob, "kiosk", &protocol).await;
    let peer = p.alice.identity().public();
    let set_kept_peer = |present| {
        let reason = PeerReason::Kept;
        if present {
            OpKind::AllowPut {
                pubky: peer,
                reason,
            }
        } else {
            OpKind::AllowDelete {
                pubky: peer,
                reason,
            }
        }
    };
    if present {
        shop.keep_peer(&peer).await.unwrap();
    }
    assert_eq!(
        shop.allow_list()
            .await
            .unwrap()
            .kept_peers()
            .any(|id| id == peer),
        present
    );
    shop.receive(None).await.unwrap();

    let service = p.bob.switch();
    service.fail_next(Fault::LoseAnswer { path: "ops".into() });
    let first = shop
        .submit_batch(OpBatch::new().op(set_kept_peer(!present)))
        .await
        .unwrap_err()
        .kept_batch()
        .unwrap();
    assert_ne!(
        kiosk
            .allow_list()
            .await
            .unwrap()
            .kept_peers()
            .any(|id| id == peer),
        present
    );
    let last = kiosk
        .submit_batch(OpBatch::new().op(set_kept_peer(present)))
        .await
        .unwrap();
    let position = last.proofs[0].envelope();
    service.fail_next(Fault::LoseAnswer { path: "ops".into() });
    shop.receive(None).await.unwrap();
    assert_eq!(shop.cursor().generation, position.generation);
    assert!(shop.cursor().seq >= position.seq);
    assert_eq!(shop.admits(&peer).await.unwrap(), present);

    let id = shop.app_id();
    drop(shop);
    let mut shop = App::load(p.env(&p.bob, store), protocol, config(), id)
        .await
        .unwrap();
    assert!(matches!(
        shop.kept_batch(first).await.unwrap(),
        Some(KeptBatchStatus::Kept { .. })
    ));
    assert_eq!(shop.admits(&peer).await.unwrap(), present);
    let kept = shop.kept_batches().await.unwrap();
    let (_, original) = kept.iter().find(|(id, _)| *id == first).unwrap();
    let original = crate::client::Batch::from_body(original.body.clone()).unwrap();
    // A loss at this point would settle this same, already placed original.
    // Its sibling's applied operation is later than both it and the full read.
    assert!(matches!(
        shop.old_list_writes()
            .await
            .unwrap()
            .get(&original.ops()[0], 0),
        Some(crate::app::list_settlement::OldWrite::Covered)
    ));
    shop.flush_outbox().await.unwrap();
    assert!(matches!(
        shop.kept_batch(first).await.unwrap(),
        Some(KeptBatchStatus::Applied { .. })
    ));
    assert_eq!(
        kiosk
            .allow_list()
            .await
            .unwrap()
            .kept_peers()
            .any(|id| id == peer),
        present
    );
    assert_eq!(shop.admits(&peer).await.unwrap(), present);
}

#[tokio::test]
async fn test_kept_peer_position_is_kept_until_the_batch_and_received_effect_end() {
    use crate::app::KeptBatchStatus;
    use crate::app::list_settlement::order_key;
    use pubky_switch_core::admission::PeerReason;

    let p = Pair::new();
    let protocol = ApiProtocol::new(Mode::KeepPeer);
    let store = Arc::new(MemoryStore::new());
    let mut shop = p
        .join_on(&p.bob, "shop", protocol.clone(), store.clone())
        .await;
    let mut kiosk = p.join(&p.bob, "kiosk", &protocol).await;
    let mut sender = p
        .join(&p.alice, "wallet", &ApiProtocol::new(Mode::Plain))
        .await;
    let peer = p.alice.identity().public();
    let other = p.carol.identity().public();
    shop.keep_peer(&peer).await.unwrap();
    shop.allow_list().await.unwrap();
    shop.receive(None).await.unwrap();
    let service = p.bob.switch();
    let lost = || service.fail_next(Fault::LoseAnswer { path: "ops".into() });
    lost();
    let removal = shop
        .remove_kept_peer(&peer)
        .await
        .unwrap_err()
        .kept_batch()
        .unwrap();
    let add = |pubky| {
        OpBatch::new().op(OpKind::AllowPut {
            pubky,
            reason: PeerReason::Kept,
        })
    };
    kiosk.submit_batch(add(other)).await.unwrap();
    let joined = kiosk.submit_batch(add(peer)).await.unwrap();
    let confirmed = joined.proofs[0].envelope();
    let position = crate::app::FeedPosition {
        generation: confirmed.generation,
        seq: confirmed.seq,
    };
    let marker = order_key("kept", &peer);
    lost();
    shop.receive(None).await.unwrap();
    assert_eq!(shop.reader().get(&marker).await.unwrap(), Some(position));
    assert!(shop.admits(&other).await.unwrap());
    assert!(
        !shop
            .reader()
            .exists(&order_key("kept", &other))
            .await
            .unwrap()
    );

    assert!(matches!(
        sender.send(Pair::note(&p.bob, "hello")).await.unwrap().1,
        Delivery::Accepted { .. }
    ));
    lost();
    lost();
    assert!(matches!(
        shop.receive(None).await,
        Err(AppError::Transport(_))
    ));
    let id = shop.app_id();
    drop(shop);
    let mut shop = App::load(p.env(&p.bob, store), protocol.clone(), config(), id)
        .await
        .unwrap();
    let effect = shop.state.pending_effect.as_ref().unwrap();
    let signed = crate::client::Batch::from_body(effect.body.clone()).unwrap();
    assert!(signed.ops().iter().any(|op| matches!(op.body().kind,
        OpKind::AllowPut { pubky, reason: PeerReason::Kept } if pubky == peer)));
    assert!(matches!(
        shop.kept_batch(removal).await.unwrap(),
        Some(KeptBatchStatus::Kept { .. })
    ));
    assert_eq!(shop.reader().get(&marker).await.unwrap(), Some(position));
    let backup = shop.backup_layered().await.unwrap();
    let restored = App::restore(
        p.env(&p.bob, Arc::new(MemoryStore::new())),
        protocol,
        config(),
        &backup,
    )
    .await
    .unwrap();
    assert!(restored.kept_batch(removal).await.unwrap().is_none());
    assert!(restored.state.pending_effect.is_none());
    assert!(!restored.reader().exists(&marker).await.unwrap());
    shop.flush_outbox().await.unwrap();
    assert!(matches!(
        shop.kept_batch(removal).await.unwrap(),
        Some(KeptBatchStatus::Applied { .. })
    ));
    assert_eq!(shop.reader().get(&marker).await.unwrap(), Some(position));
    assert!(shop.admits(&peer).await.unwrap());
    shop.receive(None).await.unwrap();
    assert!(shop.state.pending_effect.is_none());
    assert!(!shop.reader().exists(&marker).await.unwrap());
    assert!(shop.admits(&peer).await.unwrap());
}

#[tokio::test]
async fn test_imported_kept_peer_effect_respects_a_newer_answered_removal() {
    use crate::app::FeedPosition;
    use crate::app::list_settlement::order_key;
    use crate::app::tests::moves::{NEXT, Router, join_on, next_key, publish_at};
    use pubky_switch_core::admission::PeerReason;

    let w = World::new();
    let router = Router::of(&w);
    let protocol = ApiProtocol::new(Mode::KeepPeer);
    let permissions = [
        Permission::ListsRead,
        Permission::ListsManage,
        Permission::ReplyAdd,
    ];
    let mut app = join_on(&w, &router, w.store.clone(), protocol, &permissions).await;
    let peer = w.bob.public();
    app.allow_list().await.unwrap();
    app.receive(None).await.unwrap();
    let full = app.list_cutoff().await.unwrap().flatten().unwrap();
    assert_eq!(full.generation, 1);
    let (seq, message) = w.note(app.app_id(), "keep the peer");
    w.switch.fail_next(Fault::LoseAnswer { path: "ops".into() });
    assert!(matches!(
        app.receive(None).await,
        Err(AppError::Transport(_))
    ));
    let original = app.state.pending_effect.as_ref().unwrap();
    assert_eq!(original.msg_id, message.msg_id);
    let batch = crate::client::Batch::from_body(original.body.clone()).unwrap();
    let id = batch.id().unwrap();
    assert!(batch.ops().iter().any(|op| matches!(op.body().kind, OpKind::AllowPut {pubky, reason:PeerReason::Kept} if pubky == peer)));
    assert!(app.kept_batches().await.unwrap().is_empty());

    let key = next_key();
    let next = w.switch.import_into_at(key.to_bytes(), NEXT);
    assert!(next.lock().batches.get(&id).unwrap().proofs.is_none());
    router.add(NEXT, &next);
    publish_at(
        &w,
        &next,
        Inbox::new(NEXT, key.verifying_key().to_bytes()),
        2,
        None,
    );
    app.refresh_identity().await.unwrap();
    app.follow_provider().await.unwrap();
    assert_eq!(
        app.state.pending_effect.as_ref().unwrap().msg_id,
        message.msg_id
    );
    let removal = app
        .submit_batch(OpBatch::new().op(OpKind::AllowDelete {
            pubky: peer,
            reason: PeerReason::Kept,
        }))
        .await
        .unwrap();
    let envelope = removal.proofs[0].envelope();
    let position = FeedPosition {
        generation: envelope.generation,
        seq: envelope.seq,
    };
    assert_eq!(position.generation, 2);
    assert_eq!(
        app.reader().get(&order_key("kept", &peer)).await.unwrap(),
        Some(position)
    );
    assert_eq!(app.list_cutoff().await.unwrap(), Some(Some(full)));
    let read = app.receive(None).await.unwrap();
    assert!(read.events.iter().any(|e| matches!(e, AppEvent::MessageReceived {seq: seen, msg_id, ..} if *seen == seq && *msg_id == message.msg_id)));
    assert!(app.state.pending_effect.is_none());
    assert!(!app.admits(&peer).await.unwrap());
    assert!(
        !app.reader()
            .exists(&order_key("kept", &peer))
            .await
            .unwrap()
    );
}

#[tokio::test]
async fn test_project_deny_changes_from_a_kept_verified_batch_after_reopen() {
    use crate::app::KeptBatchStatus;
    use crate::app::admission::deny_key;
    use crate::app::state::Tx;
    use crate::testing::Fault;

    let p = Pair::new();
    let protocol = ApiProtocol::new(Mode::LocalNote);
    let store = Arc::new(MemoryStore::new());
    let mut app = p
        .join_with(
            &p.bob,
            "till",
            protocol.clone(),
            store.clone(),
            &[Permission::ListsManage],
        )
        .await;
    let who = p.alice.identity().public();
    let other = p.carol.identity().public();
    assert!(app.list_cutoff().await.unwrap().is_none());
    let batch = OpBatch::new()
        .op(OpKind::DenyPut { pubky: who })
        .op(OpKind::DenyPut { pubky: other })
        .op(OpKind::DenyDelete { pubky: who });
    let service = p.bob.switch();
    service.fail_next(Fault::LoseAnswer { path: "ops".into() });
    let id = app
        .submit_batch(batch)
        .await
        .unwrap_err()
        .kept_batch()
        .unwrap();
    service.fail_next(Fault::LoseAnswer { path: "ops".into() });
    app.receive(None).await.unwrap();
    let own_id = app.app_id();
    drop(app);
    let mut app = App::load(p.env(&p.bob, store), protocol, config(), own_id)
        .await
        .unwrap();
    assert!(matches!(
        app.kept_batch(id).await.unwrap(),
        Some(KeptBatchStatus::Kept { .. })
    ));
    assert!(app.list_cutoff().await.unwrap().is_none());
    let plan = app.old_list_writes().await.unwrap();
    let (_, pending) = app
        .kept_batches()
        .await
        .unwrap()
        .into_iter()
        .find(|(key, _)| key == &id)
        .unwrap();
    let signed = crate::client::Batch::from_body(pending.body).unwrap();
    let mut tx = Tx::new(&app.ns);
    for (i, op) in signed.ops().iter().enumerate() {
        app.settle_old_op(op, plan.get(op, i).unwrap(), &mut tx)
            .await
            .unwrap();
    }
    assert_eq!(tx.pending_state(&deny_key(&who)), Some(false));
    assert_eq!(tx.pending_state(&deny_key(&other)), Some(true));
    assert!(matches!(
        app.kept_batch(id).await.unwrap(),
        Some(KeptBatchStatus::Kept { .. })
    ));
}
