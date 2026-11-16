use super::*;
use crate::app::{DeliveryOrigin, QueuedMessage};
use crate::error::StoreError;

#[derive(Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
struct DeliveryFact {
    owner: [u8; 32],
    app_id: [u8; 16],
    to: [u8; 32],
    hash: [u8; 32],
    cert: [u8; 32],
    key: [u8; 32],
}

fn delivery_key(id: &str) -> Vec<u8> {
    format!("delivery/{id}").into_bytes()
}

fn delivery_fact(app: &App, plaintext: &MessagePlaintext) -> DeliveryFact {
    let message = Message::parse(plaintext.json(), &[]).unwrap();
    DeliveryFact {
        owner: app.identity(),
        app_id: app.app_id(),
        to: message.to,
        hash: plaintext.hash(),
        cert: app.cert().hash(),
        key: app.blind(&delivery_key(&message.msg_id)),
    }
}

pub(super) fn has_delivery_fact(
    delivery: &crate::app::DeliveryView<'_>,
) -> Result<bool, crate::app::StoreFailure> {
    assert_eq!(format!("{delivery:?}"), "DeliveryView");
    assert_eq!(delivery.hash(), delivery.plaintext().hash());
    assert_eq!(
        *delivery.message(),
        Message::parse(delivery.plaintext().json(), &[]).unwrap()
    );
    let bytes = delivery
        .local()
        .local_get(&delivery_key(&delivery.message().msg_id))
        .map_err(|error| crate::app::StoreFailure::try_from(error).unwrap())?;
    let Some(bytes) = bytes else { return Ok(false) };
    let Ok(fact) = serde_json::from_slice::<DeliveryFact>(&bytes) else {
        return Ok(false);
    };
    Ok(fact
        == DeliveryFact {
            owner: delivery.local().identity(),
            app_id: delivery.local().app_id(),
            to: delivery.message().to,
            hash: delivery.hash(),
            cert: delivery.cert().hash(),
            key: delivery.blind(&delivery_key(&delivery.message().msg_id)),
        })
}

fn fact_write(id: &str, fact: &DeliveryFact) -> LocalWrite {
    LocalWrite::Put {
        key: delivery_key(id),
        value: serde_json::to_vec(fact).unwrap(),
    }
}

/// Only the delivery's own local fact is unavailable; other durable work stays readable.
struct DeliveryReadFault {
    inner: Arc<MemoryStore>,
    key: Vec<u8>,
    fail: std::sync::atomic::AtomicBool,
    reads: std::sync::atomic::AtomicUsize,
}

impl StateStore for DeliveryReadFault {
    fn get(&self, ns: &str, key: &[u8]) -> Result<Option<Vec<u8>>, StoreError> {
        if key == self.key && self.fail.load(std::sync::atomic::Ordering::SeqCst) {
            self.reads.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            return Err(StoreError::Unavailable);
        }
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
        self.inner.commit_if(ns, owner, batch)
    }
}

#[tokio::test]
async fn test_delivery_view_uses_original_signed_bytes_and_exact_local_fact() {
    Box::pin(async {
        let p = Pair::new();
        let protocol = ApiProtocol::new(Mode::Plain);
        protocol
            .require_send_fact
            .store(true, std::sync::atomic::Ordering::SeqCst);
        let mut wallet = p.join(&p.alice, "wallet", &protocol).await;
        let mut shop = p.join(&p.bob, "shop", &protocol).await;
        shop.invite(&p.alice.identity().public()).await.unwrap();
        let signed = wallet.sign_message(Pair::note(&p.bob, "bytes")).unwrap();
        let json: Value = serde_json::from_slice(signed.plaintext().json()).unwrap();
        let pretty = MessagePlaintext::sign_json(
            &p.alice.identity().app_keys("wallet"),
            serde_json::to_vec_pretty(&json).unwrap(),
            &[],
        )
        .unwrap();
        assert_eq!(
            Message::parse(pretty.json(), &[]).unwrap(),
            Message::parse(signed.plaintext().json(), &[]).unwrap()
        );
        assert_ne!(pretty.hash(), signed.hash());
        wallet.queue_stored(&pretty).await.unwrap();
        let correct = delivery_fact(&wallet, &pretty);
        let mut wrong_owner = correct.clone();
        wrong_owner.owner = [1; 32];
        let mut wrong_app = correct.clone();
        wrong_app.app_id = [2; 16];
        let mut wrong_to = correct.clone();
        wrong_to.to = [3; 32];
        let mut wrong_key = correct.clone();
        wrong_key.key = wallet.blind(b"another local binding");
        assert_ne!(wrong_key.key, correct.key);
        let mut wrong_cert = correct.clone();
        wrong_cert.cert = shop.cert().hash();
        assert_ne!(wrong_cert.cert, correct.cert);
        let variants = [
            None,
            Some(b"not JSON".to_vec()),
            Some(serde_json::to_vec(&delivery_fact(&wallet, signed.plaintext())).unwrap()),
            Some(serde_json::to_vec(&wrong_owner).unwrap()),
            Some(serde_json::to_vec(&wrong_app).unwrap()),
            Some(serde_json::to_vec(&wrong_to).unwrap()),
            Some(serde_json::to_vec(&wrong_key).unwrap()),
            Some(serde_json::to_vec(&wrong_cert).unwrap()),
        ];
        for bytes in variants {
            let write = match bytes {
                Some(value) => LocalWrite::Put {
                    key: delivery_key(signed.msg_id()),
                    value,
                },
                None => LocalWrite::Delete {
                    key: delivery_key(signed.msg_id()),
                },
            };
            wallet.protocol_commit("sample", &[write]).await.unwrap();
            let before = wallet.reader().scan_raw("").await.unwrap();
            let routed = p.router.log();
            let item = listed_origin(&wallet, &signed).await;
            assert_eq!(
                item.hash,
                pretty.hash(),
                "inventory retains original JSON hash"
            );
            assert_eq!(item.origin, DeliveryOrigin::Reconstructed);
            assert!(
                !item.may_send && item.waits(),
                "missing or mismatched evidence holds"
            );
            assert_eq!(wallet.reader().scan_raw("").await.unwrap(), before);
            assert_eq!(p.router.log(), routed, "inventory does not route");
            wallet.flush_message(signed.msg_id()).await.unwrap();
            assert_eq!(p.router.log(), routed, "held delivery does not route");
            assert!(wallet.outbox_record(signed.msg_id()).await.is_some());
            assert_eq!(p.bob.switch().entries_from(&p.alice.identity().public()), 0);
        }
        wallet
            .protocol_commit("sample", &[fact_write(signed.msg_id(), &correct)])
            .await
            .unwrap();
        assert!(listed_origin(&wallet, &signed).await.may_send);
        assert!(matches!(
            wallet.flush_message(signed.msg_id()).await.unwrap(),
            Some(Delivery::Accepted { .. })
        ));
        assert_eq!(p.bob.switch().entries_from(&p.alice.identity().public()), 1);
    })
    .await;
}

#[tokio::test]
async fn test_delivery_view_unavailable_local_fact_holds_only_its_delivery() {
    Box::pin(async {
        let p = Pair::new();
        let protocol = ApiProtocol::new(Mode::Plain);
        protocol
            .require_send_fact
            .store(true, std::sync::atomic::Ordering::SeqCst);
        let store = Arc::new(MemoryStore::new());
        let mut wallet = p
            .join_on(&p.alice, "wallet", protocol.clone(), store.clone())
            .await;
        let mut shop = p.join(&p.bob, "shop", &protocol).await;
        shop.invite(&p.alice.identity().public()).await.unwrap();
        let blocked = wallet.sign_message(Pair::note(&p.bob, "blocked")).unwrap();
        let other = wallet.sign_message(Pair::note(&p.bob, "other")).unwrap();
        for signed in [&blocked, &other] {
            wallet.queue_signed(signed.clone()).await.unwrap();
            wallet
                .protocol_commit(
                    "sample",
                    &[fact_write(
                        signed.msg_id(),
                        &delivery_fact(&wallet, signed.plaintext()),
                    )],
                )
                .await
                .unwrap();
        }
        let id = wallet.app_id();
        drop(wallet);
        let local = crate::app::protocols::qualified_key("sample", &delivery_key(blocked.msg_id()));
        let fault = Arc::new(DeliveryReadFault {
            inner: store.clone(),
            key: [b"p/".as_slice(), local.as_slice()].concat(),
            fail: std::sync::atomic::AtomicBool::new(true),
            reads: std::sync::atomic::AtomicUsize::new(0),
        });
        let mut wallet = App::load(
            p.env(&p.alice, fault.clone()),
            protocol.clone(),
            config(),
            id,
        )
        .await
        .unwrap();
        let before = wallet.reader().scan_raw("").await.unwrap();
        let routed = p.router.log();
        assert!(!listed_origin(&wallet, &blocked).await.may_send);
        assert!(listed_origin(&wallet, &other).await.may_send);
        assert_eq!(wallet.reader().scan_raw("").await.unwrap(), before);
        assert_eq!(p.router.log(), routed);
        let report = wallet.flush_outbox().await.unwrap();
        assert_eq!(report.done, [other.msg_id()]);
        assert!(fault.reads.load(std::sync::atomic::Ordering::SeqCst) > 0);
        assert_eq!(p.bob.switch().entries_from(&p.alice.identity().public()), 1);
        assert!(wallet.outbox_record(blocked.msg_id()).await.is_some());
        assert!(matches!(
            wallet.delivery(blocked.msg_id()).await.unwrap(),
            Some(Delivery::Queued { .. })
        ));
        drop(wallet);
        let mut wallet = App::load(p.env(&p.alice, fault.clone()), protocol, config(), id)
            .await
            .unwrap();
        wallet.flush_message(blocked.msg_id()).await.unwrap();
        assert_eq!(p.bob.switch().entries_from(&p.alice.identity().public()), 1);
        fault.fail.store(false, std::sync::atomic::Ordering::SeqCst);
        assert!(listed_origin(&wallet, &blocked).await.may_send);
        wallet.flush_message(blocked.msg_id()).await.unwrap();
        assert_eq!(p.bob.switch().entries_from(&p.alice.identity().public()), 2);
    })
    .await;
}

#[tokio::test]
async fn test_delivery_view_kept_local_state_and_restored_original_bytes() {
    Box::pin(async {
        for origin in [DeliveryOrigin::Original, DeliveryOrigin::Reconstructed] {
            let p = Pair::new();
            let protocol = ApiProtocol::new(Mode::Plain);
            protocol
                .require_send_fact
                .store(true, std::sync::atomic::Ordering::SeqCst);
            let store = Arc::new(MemoryStore::new());
            let mut wallet = p
                .join_on(&p.alice, "wallet", protocol.clone(), store.clone())
                .await;
            let signed = wallet
                .sign_message(Pair::note(&p.bob, "kept fact"))
                .unwrap();
            let fact = delivery_fact(&wallet, signed.plaintext());
            if origin == DeliveryOrigin::Reconstructed {
                wallet.queue_stored(signed.plaintext()).await.unwrap();
            }
            p.alice.switch().fail_next(Fault::Unanswered {
                path: "ops".into(),
                after: 0,
            });
            wallet
                .submit_batch(
                    OpBatch::for_protocol("sample")
                        .op(OpKind::AllowPut {
                            pubky: [9; 32],
                            kind: pubky_switch_core::ops::AllowKind::Conversation,
                        })
                        .local(fact_write(signed.msg_id(), &fact))
                        .queue(signed.clone()),
                )
                .await
                .unwrap_err()
                .kept_batch()
                .unwrap();
            let item = listed_origin(&wallet, &signed).await;
            assert!(
                !item.may_send,
                "uncommitted batch locals cannot permit delivery"
            );
            assert_eq!(item.hash, signed.hash());
            assert_eq!(
                item.kept_batch.is_some(),
                origin == DeliveryOrigin::Original
            );
            assert_eq!(item.origin, origin);
            wallet
                .protocol_commit("sample", &[fact_write(signed.msg_id(), &fact)])
                .await
                .unwrap();
            assert!(listed_origin(&wallet, &signed).await.may_send);
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
            assert!(listed_origin(&wallet, &signed).await.may_send);
            // Backups carry materialized deliveries. Materializing a kept original
            // keeps its origin and unanswered batch; it adds no backup scope.
            let pending = wallet.kept_batches().await.unwrap().len();
            wallet.queue_stored(signed.plaintext()).await.unwrap();
            assert_eq!(wallet.kept_batches().await.unwrap().len(), pending);
            assert_eq!(listed_origin(&wallet, &signed).await.origin, origin);
            let backup = wallet.backup_layered().await.unwrap();
            wallet
                .protocol_commit(
                    "sample",
                    &[LocalWrite::Delete {
                        key: delivery_key(signed.msg_id()),
                    }],
                )
                .await
                .unwrap();
            assert!(!listed_origin(&wallet, &signed).await.may_send);
            drop(wallet);
            let restored =
                App::restore(p.env(&p.alice, store), protocol.clone(), config(), &backup)
                    .await
                    .unwrap();
            let item = listed_origin(&restored, &signed).await;
            assert_eq!(
                (item.hash, item.origin, item.may_send),
                (signed.hash(), origin, true)
            );
            drop(restored);
            let fresh = App::restore(
                p.env(&p.alice, Arc::new(MemoryStore::new())),
                protocol,
                config(),
                &backup,
            )
            .await
            .unwrap();
            let item = listed_origin(&fresh, &signed).await;
            assert_eq!(
                (item.hash, item.origin, item.may_send),
                (signed.hash(), origin, true)
            );
        }
    })
    .await;
}

/// Fail the outcome transaction itself, independently of earlier read bookkeeping.
struct SettlementFault {
    inner: Arc<MemoryStore>,
    after: bool,
    fired: std::sync::atomic::AtomicBool,
}

impl SettlementFault {
    fn completes(&self, batch: &crate::store::WriteBatch) -> bool {
        let local = crate::app::protocols::qualified_key("sample", b"settled");
        let target = [b"p/".as_slice(), local.as_slice()].concat();
        batch.writes().iter().any(|write| {
            matches!(write,
            crate::store::Write::Put { key, .. } if *key == target)
        }) && !self.fired.swap(true, std::sync::atomic::Ordering::SeqCst)
    }
}

impl StateStore for SettlementFault {
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
        if self.completes(&batch) {
            if self.after {
                self.inner.commit(batch)?;
                return Err(StoreError::Unknown);
            }
            return Err(StoreError::Unavailable);
        }
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
        if self.completes(&batch) {
            if self.after {
                return match self.inner.commit_if(ns, owner, batch)? {
                    crate::store::CommitOutcome::Applied => Err(StoreError::Unknown),
                    outcome => Ok(outcome),
                };
            }
            return Err(StoreError::Unavailable);
        }
        self.inner.commit_if(ns, owner, batch)
    }
}

fn assert_corrupt<T: std::fmt::Debug>(result: Result<T, AppError>) {
    assert!(
        matches!(result, Err(AppError::Store(StoreError::Corrupt))),
        "{result:?}"
    );
}

#[tokio::test]
async fn test_delivery_origin_overlapping_copies_refuse_before_effects() {
    Box::pin(async {
        for sent in [false, true] {
            let p = Pair::new();
            let protocol = ApiProtocol::new(Mode::Plain);
            let store = Arc::new(MemoryStore::new());
            let mut wallet = p
                .join_on(&p.alice, "wallet", protocol.clone(), store.clone())
                .await;
            let signed = wallet.sign_message(Pair::note(&p.bob, "overlap")).unwrap();
            kept_with(&p, &mut wallet, &signed).await;
            wallet.queue_stored(signed.plaintext()).await.unwrap();
            let (id, _) = wallet.kept_batches().await.unwrap().pop().unwrap();
            let key = format!("opq/{}", pubky_switch_core::enc::b64(&id));
            let mut pending: Value = wallet.reader().get(&key).await.unwrap().unwrap();
            if sent {
                let mut shop = p.join(&p.bob, "shop", &protocol).await;
                shop.invite(&p.alice.identity().public()).await.unwrap();
                wallet.receive(None).await.unwrap();
                wallet.flush_message(signed.msg_id()).await.unwrap();
                assert!(wallet.outbox_record(signed.msg_id()).await.is_none());
                assert!(
                    wallet
                        .reader()
                        .exists(&format!("sent/{}", signed.msg_id()))
                        .await
                        .unwrap()
                );
            }
            pending["queued"][0]["origin"] = json!("Reconstructed");
            let mut tx = wallet.tx().unwrap();
            tx.put(&key, &pending).unwrap();
            wallet.commit(tx).await.unwrap();
            let before = wallet.reader().scan_raw("").await.unwrap();
            let own_operations = p.alice.switch().applied().len();
            let appends = p.bob.switch().entries_from(&p.alice.identity().public());
            assert_corrupt(wallet.queued_messages("sample").await);
            assert_corrupt(wallet.hold_message("sample", signed.msg_id()).await);
            assert_corrupt(wallet.queue_stored(signed.plaintext()).await);
            assert_corrupt(wallet.queue_signed(signed.clone()).await);
            assert_corrupt(wallet.flush_outbox().await);
            assert_corrupt(wallet.withdraw_message("sample", signed.msg_id()).await);
            assert_corrupt(wallet.kept_batches().await);
            assert_eq!(
                wallet.reader().scan_raw("").await.unwrap(),
                before,
                "invalid overlap cannot mutate retained work"
            );
            assert_eq!(p.alice.switch().applied().len(), own_operations);
            assert_eq!(
                p.bob.switch().entries_from(&p.alice.identity().public()),
                appends
            );
            let app_id = wallet.app_id();
            drop(wallet);
            assert!(matches!(
                App::load(p.env(&p.alice, store), protocol, config(), app_id).await,
                Err(AppError::Store(StoreError::Corrupt))
            ));
        }
    })
    .await;
}

#[tokio::test]
async fn test_delivery_origin_authenticated_same_id_different_bytes_refuses() {
    Box::pin(async {
        for kept in [false, true] {
            let p = Pair::new();
            let protocol = ApiProtocol::new(Mode::Plain);
            let mut wallet = p.join(&p.alice, "wallet", &protocol).await;
            let signed = wallet.sign_message(Pair::note(&p.bob, "first")).unwrap();
            if kept {
                kept_with(&p, &mut wallet, &signed).await;
            } else {
                wallet.queue_signed(signed.clone()).await.unwrap();
            }
            let mut json: Value = serde_json::from_slice(signed.plaintext().json()).unwrap();
            json["body"]["text"] = json!("different");
            let changed = MessagePlaintext::sign_json(
                &p.alice.identity().app_keys("wallet"),
                serde_json::to_vec(&json).unwrap(),
                &[],
            )
            .unwrap();
            assert_ne!(changed.hash(), signed.hash());
            let before = wallet.reader().scan_raw("").await.unwrap();
            assert_corrupt(wallet.queue_stored(&changed).await);
            assert_eq!(wallet.reader().scan_raw("").await.unwrap(), before);
            assert_eq!(
                listed_origin(&wallet, &signed).await.origin,
                DeliveryOrigin::Original
            );
        }
    })
    .await;
}

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
    let requests = p.router.log();
    let listed = wallet.queued_messages("sample").await.unwrap();
    assert_eq!(p.router.log(), requests, "inventory makes no request");
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
                if origin == DeliveryOrigin::Reconstructed && with_record {
                    continue;
                }
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
                assert_eq!(
                    wallet.outbox_record(signed.msg_id()).await.is_some(),
                    with_record
                );
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
async fn test_delivery_origin_kept_settlement_commits_local_and_origin_together() {
    Box::pin(async {
        for origin in [DeliveryOrigin::Original, DeliveryOrigin::Reconstructed] {
            for after in [false, true] {
                let p = Pair::new();
                let protocol = ApiProtocol::new(Mode::Plain);
                let store = Arc::new(MemoryStore::new());
                let mut wallet = p
                    .join_on(&p.alice, "wallet", protocol.clone(), store.clone())
                    .await;
                let signed = wallet
                    .sign_message(Pair::note(&p.bob, "settlement"))
                    .unwrap();
                if origin == DeliveryOrigin::Reconstructed {
                    wallet.queue_stored(signed.plaintext()).await.unwrap();
                }
                p.alice.switch().fail_next(Fault::Unanswered {
                    path: "ops".into(),
                    after: 0,
                });
                wallet
                    .submit_batch(
                        OpBatch::for_protocol("sample")
                            .op(OpKind::AllowPut {
                                pubky: [9; 32],
                                kind: pubky_switch_core::ops::AllowKind::Conversation,
                            })
                            .local(LocalWrite::Put {
                                key: b"settled".to_vec(),
                                value: b"yes".to_vec(),
                            })
                            .queue(signed.clone()),
                    )
                    .await
                    .unwrap_err()
                    .kept_batch()
                    .unwrap();
                wallet
                    .hold_message("sample", signed.msg_id())
                    .await
                    .unwrap();
                let id = wallet.app_id();
                drop(wallet);
                let fault = Arc::new(SettlementFault {
                    inner: store.clone(),
                    after,
                    fired: std::sync::atomic::AtomicBool::new(false),
                });
                let mut wallet = App::load(
                    p.env(&p.alice, fault.clone()),
                    protocol.clone(),
                    config(),
                    id,
                )
                .await
                .unwrap();
                let result = wallet.receive(None).await;
                assert!(
                    matches!(&result, Err(error) if matches!(error.unkept(), AppError::Store(_))),
                    "{result:?}; fault fired: {}",
                    fault.fired.load(std::sync::atomic::Ordering::SeqCst)
                );
                assert!(fault.fired.load(std::sync::atomic::Ordering::SeqCst));
                assert!(matches!(
                    wallet.queued_messages("sample").await,
                    Err(AppError::Refused(Refusal::NotNow(_)))
                ));
                drop(wallet);
                let mut wallet = App::load(p.env(&p.alice, store), protocol, config(), id)
                    .await
                    .unwrap();
                assert_eq!(
                    wallet
                        .protocol_get("sample", b"settled")
                        .await
                        .unwrap()
                        .is_some(),
                    after
                );
                assert_eq!(wallet.kept_batches().await.unwrap().is_empty(), after);
                let listed = listed_origin(&wallet, &signed).await;
                assert_eq!((listed.origin, listed.held), (origin, true));
                assert_eq!(
                    listed.kept_batch.is_none(),
                    after || origin == DeliveryOrigin::Reconstructed
                );
                wallet.receive(None).await.unwrap();
                assert_eq!(
                    wallet.protocol_get("sample", b"settled").await.unwrap(),
                    Some(b"yes".to_vec())
                );
                assert!(wallet.kept_batches().await.unwrap().is_empty());
                assert_eq!(
                    (
                        listed_origin(&wallet, &signed).await.origin,
                        listed_origin(&wallet, &signed).await.held
                    ),
                    (origin, true)
                );
            }
        }
    })
    .await;
}

#[tokio::test]
async fn test_delivery_origin_fresh_restore_commit_is_atomic() {
    Box::pin(async {
        for origin in [DeliveryOrigin::Original, DeliveryOrigin::Reconstructed] {
            for after in [false, true] {
                let p = Pair::new();
                let protocol = ApiProtocol::new(Mode::Plain);
                let mut wallet = p.join(&p.alice, "wallet", &protocol).await;
                let signed = wallet
                    .sign_message(Pair::note(&p.bob, "restore commit"))
                    .unwrap();
                queue_origin(&mut wallet, &signed, origin).await;
                wallet
                    .hold_message("sample", signed.msg_id())
                    .await
                    .unwrap();
                let backup = wallet.backup().await.unwrap();
                let app_id = wallet.app_id();
                let store = Arc::new(MemoryStore::new());
                let fault = Arc::new(FaultStore::new(
                    store.clone(),
                    if after {
                        StoreFault::FailAfter(1)
                    } else {
                        StoreFault::FailBefore(1)
                    },
                ));
                let restored = App::restore(
                    p.env(&p.alice, fault.clone()),
                    protocol.clone(),
                    config(),
                    &backup,
                )
                .await;
                assert!(matches!(restored, Err(AppError::Store(_))));
                assert_eq!(fault.commits(), 1);
                let loaded = App::load(
                    p.env(&p.alice, store.clone()),
                    protocol.clone(),
                    config(),
                    app_id,
                )
                .await;
                if after {
                    let loaded = loaded.unwrap();
                    let item = listed_origin(&loaded, &signed).await;
                    assert_eq!((item.origin, item.held), (origin, true));
                    drop(loaded);
                } else {
                    assert!(
                        loaded.is_err(),
                        "a refused first commit leaves no partial app"
                    );
                }
                let restored = App::restore(p.env(&p.alice, store), protocol, config(), &backup)
                    .await
                    .unwrap();
                let item = listed_origin(&restored, &signed).await;
                assert_eq!((item.origin, item.held), (origin, true));
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

#[tokio::test]
async fn test_queued_messages_keeps_a_producer_after_the_latest_end_expires() {
    Box::pin(async {
        let p = Pair::new();
        let protocol = ApiProtocol::new(Mode::Plain);
        let store = Arc::new(MemoryStore::new());
        let mut wallet = p
            .join_on(&p.alice, "wallet", protocol.clone(), store.clone())
            .await;
        let signed = wallet.sign_message(Pair::note(&p.bob, "delayed")).unwrap();
        p.alice.switch().fail_next(Fault::Unreachable {
            path: "feed".into(),
            after: 0,
        });
        p.alice.switch().fail_next(Fault::Unreachable {
            path: "ops".into(),
            after: 0,
        });
        let first = wallet
            .submit_batch(
                OpBatch::new()
                    .op(OpKind::AllowPut {
                        pubky: [9; 32],
                        kind: pubky_switch_core::ops::AllowKind::Conversation,
                    })
                    .queue(signed.clone()),
            )
            .await
            .unwrap_err()
            .kept_batch()
            .unwrap();
        p.alice.switch().lock().faults.clear();
        assert_eq!(wallet.kept_batches().await.unwrap()[0].1.kept_ms, None);
        let freeze = pubky_switch_core::records::Freeze::sign(
            p.alice.identity().key(),
            pubky_switch_core::records::FreezeBody {
                identity: p.alice.identity().public(),
                inbox: Inbox::new("https://recovered.example", [77; 32]),
                next_generation: 2,
                issued_at: p.clock.now_ms(),
                nonce: [43; 16],
            },
        )
        .unwrap();
        p.alice.switch().freeze(&freeze).unwrap();
        let error = wallet
            .submit_batch(
                OpBatch::new()
                    .op(ClaimOp::attempt(CLAIM, 0, ATTEMPT, 3600, None).kind())
                    .queue(signed.clone()),
            )
            .await
            .unwrap_err();
        let second = error
            .kept_batch()
            .unwrap_or_else(|| panic!("second batch was not retained: {error:?}"));
        assert_ne!(first, second);
        assert_eq!(wallet.kept_batches().await.unwrap().len(), 2);
        p.router.remove(SWITCH_ORIGIN);
        wallet
            .hold_message("sample", signed.msg_id())
            .await
            .unwrap();
        let next_origin = "https://recovered.example";
        let next =
            ScriptedSwitch::recovering(p.alice.identity().key(), [77; 32], p.clock.clone(), 2, 1)
                .unwrap();
        let doc = p
            .alice
            .sign_next(|body| {
                body.generation = 2;
                body.recovery_from = Some(1);
                body.inbox = Inbox::new(next_origin, next.service_key());
            })
            .unwrap();
        next.deliver_identity(&doc).unwrap();
        // Discovery is public; the unavailable new route leaves registration pending.
        wallet.refresh_identity().await.unwrap();
        let _ = wallet.receive(None).await;
        assert_eq!(wallet.cursor().generation, 2);
        let kept = wallet.kept_batches().await.unwrap();
        assert_eq!(kept.len(), 1);
        assert_eq!((kept[0].0, kept[0].1.kept_ms), (first, None));
        assert!(matches!(
            wallet.delivery(signed.msg_id()).await.unwrap(),
            Some(Delivery::Failed { .. })
        ));
        p.clock.advance_ms(SENT_RETENTION_MS + 1);
        let app_id = wallet.app_id();
        drop(wallet);
        let mut wallet = App::load(p.env(&p.alice, store), protocol, config(), app_id)
            .await
            .unwrap();
        assert_eq!(wallet.delivery(signed.msg_id()).await.unwrap(), None);
        let before = wallet.reader().scan_raw("").await.unwrap();
        let requests = p.router.log();
        let listed = wallet.queued_messages("sample").await.unwrap();
        assert_eq!(listed.len(), 1, "an older producer survives the latest end");
        assert_eq!(
            (
                listed[0].msg_id.as_str(),
                listed[0].kept_batch,
                listed[0].origin,
                listed[0].held
            ),
            (signed.msg_id(), Some(first), DeliveryOrigin::Original, true)
        );
        assert_eq!(wallet.reader().scan_raw("").await.unwrap(), before);
        assert_eq!(p.router.log(), requests);
        p.router.add_switch(next_origin, &next);
        for _ in 0..4 {
            wallet.receive(None).await.unwrap();
        }
        assert!(wallet.kept_batches().await.unwrap().is_empty());
        let listed = listed_origin(&wallet, &signed).await;
        assert_eq!(
            (listed.kept_batch, listed.origin, listed.held),
            (None, DeliveryOrigin::Original, true)
        );
        wallet
            .withdraw_message("sample", signed.msg_id())
            .await
            .unwrap();
        assert!(wallet.queued_messages("sample").await.unwrap().is_empty());
    })
    .await;
}
