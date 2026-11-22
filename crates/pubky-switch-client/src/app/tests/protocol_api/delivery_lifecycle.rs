use super::*;
use crate::StoreError;
use crate::app::StoreFailure;

async fn accepted_resend_message(
    p: &Pair,
    protocol: &Arc<ApiProtocol>,
    with_record: bool,
) -> (App, SignedMessage) {
    let mut wallet = p.join(&p.alice, "wallet", protocol).await;
    let mut shop = p.join(&p.bob, "shop", protocol).await;
    shop.invite(&p.alice.identity().public()).await.unwrap();
    let mut signed = wallet.sign_message(Pair::note(&p.bob, "accepted")).unwrap();
    if with_record {
        let target = RecordTarget::new(items(), &signed.hash());
        signed = signed.with_record(RecordJob {
            target,
            tag: b"sent".to_vec(),
        });
        p.alice.switch().fail_next(Fault::Unreachable {
            path: "ops".into(),
            after: 1,
        });
    }
    wallet.queue_signed(signed.clone()).await.unwrap();
    assert!(matches!(
        wallet.flush_message(signed.msg_id()).await.unwrap(),
        Some(Delivery::Accepted { .. })
    ));
    assert_eq!(p.bob.switch().entries_from(&p.alice.identity().public()), 1);
    let item = wallet.outbox_record(signed.msg_id()).await;
    assert_eq!(item.is_some(), with_record);
    assert!(item.is_none_or(|item| !item.delivery_owed()));
    p.alice.switch().lock().faults.clear();
    wallet.take_events();
    (wallet, signed)
}

async fn queue_and_hold_resend(p: &Pair, wallet: &mut App, msg_id: &str, with_record: bool) {
    if with_record {
        p.alice.switch().fail_next(Fault::Unreachable {
            path: "ops".into(),
            after: 0,
        });
    }
    p.bob.switch().fail_next(Fault::Unreachable {
        path: "inbox".into(),
        after: 0,
    });
    assert!(matches!(
        wallet.resend(msg_id).await.unwrap(),
        Delivery::Queued { .. }
    ));
    assert!(wallet.outbox_record(msg_id).await.unwrap().delivery_owed());
    assert_eq!(p.bob.switch().entries_from(&p.alice.identity().public()), 1);
    p.alice.switch().lock().faults.clear();
    p.bob.switch().lock().faults.clear();
    assert!(wallet.hold_message("sample", msg_id).await.unwrap());
    wallet.take_events();
}

async fn withdrawn_explicit_resend(with_record: bool, reachable: bool) {
    let p = Pair::new();
    let protocol = ApiProtocol::new(Mode::Plain);
    let (mut wallet, signed) = accepted_resend_message(&p, &protocol, with_record).await;
    let msg_id = signed.msg_id();
    queue_and_hold_resend(&p, &mut wallet, msg_id, with_record).await;
    assert!(wallet.withdraw_message("sample", msg_id).await.unwrap());
    assert!(wallet.held_messages("sample").await.unwrap().is_empty());
    assert!(
        crate::app::send::given_up(&wallet.reader(), msg_id, p.clock.now_ms())
            .await
            .unwrap()
    );
    let item = wallet.outbox_record(msg_id).await;
    assert_eq!(item.is_some(), with_record);
    assert!(item.is_none_or(|item| !item.delivery_owed()));
    assert_eq!(undelivered(&wallet.take_events(), msg_id), [true]);
    assert_eq!(
        undelivered(
            &crate::app::tests::pending_events(&mut wallet)
                .await
                .unwrap(),
            msg_id
        ),
        [true]
    );
    assert!(
        wallet
            .sent_to(&p.bob.identity().public(), 0, p.clock.now_ms())
            .await
            .unwrap()
            .iter()
            .any(|message| message.msg_id == msg_id)
    );
    if with_record {
        p.alice.switch().fail_next(Fault::Unreachable {
            path: "ops".into(),
            after: 0,
        });
    }
    if !reachable {
        p.bob.switch().fail_next(Fault::Unreachable {
            path: "inbox".into(),
            after: 0,
        });
    }
    let appends_before = inbox_appends(&p);
    let result = wallet.resend(msg_id).await;
    let fresh_notices = undelivered(&wallet.take_events(), msg_id);
    let notices = undelivered(
        &crate::app::tests::pending_events(&mut wallet)
            .await
            .unwrap(),
        msg_id,
    );
    let delivery_owed = wallet
        .outbox_record(msg_id)
        .await
        .is_some_and(|item| item.delivery_owed());
    assert_eq!(
        (
            inbox_appends(&p) - appends_before,
            p.bob.switch().entries_from(&p.alice.identity().public()),
            delivery_owed,
            notices,
            fresh_notices,
        ),
        (0, 1, false, vec![true], Vec::<bool>::new()),
        "append attempts, accepted entries, delivery owed, durable notices, new notices; resend: {result:?}"
    );
}

#[tokio::test]
async fn test_explicit_resend_withdrawn_sent_message_stays_ended() {
    Box::pin(withdrawn_explicit_resend(false, true)).await;
}

#[tokio::test]
async fn test_explicit_resend_withdrawn_sent_message_stays_unqueued() {
    Box::pin(withdrawn_explicit_resend(false, false)).await;
}

#[tokio::test]
async fn test_explicit_resend_withdrawn_record_message_stays_ended() {
    Box::pin(withdrawn_explicit_resend(true, true)).await;
}

#[tokio::test]
async fn test_explicit_resend_withdrawn_record_message_stays_unqueued() {
    Box::pin(withdrawn_explicit_resend(true, false)).await;
}

#[tokio::test]
async fn test_explicit_resend_expired_record_message_keeps_one_notice() {
    Box::pin(async {
        let p = Pair::new();
        let protocol = ApiProtocol::new(Mode::Plain);
        let (mut wallet, signed) = accepted_resend_message(&p, &protocol, true).await;
        let msg_id = signed.msg_id();
        queue_and_hold_resend(&p, &mut wallet, msg_id, true).await;
        p.clock.advance_ms(SENT_RETENTION_MS + DAY_MS);
        wallet.flush_message(msg_id).await.unwrap();
        assert!(!wallet.outbox_record(msg_id).await.unwrap().delivery_owed());
        assert!(wallet.held_messages("sample").await.unwrap().is_empty());
        assert!(
            crate::app::send::given_up(&wallet.reader(), msg_id, p.clock.now_ms())
                .await
                .unwrap()
        );
        assert_eq!(undelivered(&wallet.take_events(), msg_id), [true]);
        assert_eq!(
            undelivered(&crate::app::tests::pending_events(&mut wallet).await.unwrap(), msg_id),
            [true]
        );
        let appends_before = inbox_appends(&p);
        let result = wallet.resend(msg_id).await;
        let fresh_notices = undelivered(&wallet.take_events(), msg_id);
        let notices = undelivered(&crate::app::tests::pending_events(&mut wallet).await.unwrap(), msg_id);
        let delivery_owed = wallet
            .outbox_record(msg_id)
            .await
            .is_some_and(|item| item.delivery_owed());
        assert_eq!(
            (
                inbox_appends(&p) - appends_before,
                p.bob.switch().entries_from(&p.alice.identity().public()),
                delivery_owed,
                notices,
                fresh_notices,
            ),
            (0, 1, false, vec![true], Vec::<bool>::new()),
            "append attempts, accepted entries, delivery owed, durable notices, new notices; resend: {result:?}"
        );
    })
    .await;
}

#[tokio::test]
async fn test_explicit_resend_before_withdrawal_delivers_again() {
    Box::pin(async {
        for with_record in [false, true] {
            let p = Pair::new();
            let protocol = ApiProtocol::new(Mode::Plain);
            let (mut wallet, signed) = accepted_resend_message(&p, &protocol, with_record).await;
            p.clock.advance_ms(MINUTE);
            assert!(matches!(
                wallet.resend(signed.msg_id()).await.unwrap(),
                Delivery::Accepted { .. }
            ));
            assert_eq!(p.bob.switch().entries_from(&p.alice.identity().public()), 2);
            assert!(
                undelivered(
                    &crate::app::tests::pending_events(&mut wallet)
                        .await
                        .unwrap(),
                    signed.msg_id()
                )
                .is_empty()
            );
        }
    })
    .await;
}

#[tokio::test]
async fn test_explicit_resend_from_restored_host_delivers_again() {
    Box::pin(async {
        let p = Pair::new();
        let protocol = ApiProtocol::new(Mode::Plain);
        let (mut wallet, signed) = accepted_resend_message(&p, &protocol, false).await;
        queue_and_hold_resend(&p, &mut wallet, signed.msg_id(), false).await;
        let backup = wallet.backup().await.unwrap();
        drop(wallet);
        p.clock.advance_ms(MINUTE);
        let mut restored = restored_wallet(&p, &protocol, &backup).await;
        assert_eq!(
            restored.held_messages("sample").await.unwrap(),
            [signed.msg_id()]
        );
        restored
            .release_message("sample", signed.msg_id())
            .await
            .unwrap();
        assert!(matches!(
            restored.resend(signed.msg_id()).await.unwrap(),
            Delivery::Accepted { .. }
        ));
        assert_eq!(p.bob.switch().entries_from(&p.alice.identity().public()), 2);
        assert!(
            undelivered(
                &crate::app::tests::pending_events(&mut restored)
                    .await
                    .unwrap(),
                signed.msg_id()
            )
            .is_empty()
        );
    })
    .await;
}

#[tokio::test]
async fn test_explicit_resend_terminal_mark_outlives_retained_plaintext() {
    Box::pin(async {
        for with_record in [false, true] {
            let p = Pair::new();
            let protocol = ApiProtocol::new(Mode::Plain);
            let (mut wallet, signed) = accepted_resend_message(&p, &protocol, with_record).await;
            let msg_id = signed.msg_id();
            queue_and_hold_resend(&p, &mut wallet, msg_id, with_record).await;
            assert!(wallet.withdraw_message("sample", msg_id).await.unwrap());
            assert_eq!(undelivered(&wallet.take_events(), msg_id), [true]);
            p.clock.advance_ms(SENT_RETENTION_MS + DAY_MS);
            let env = wallet.env.clone();
            let app_id = wallet.app_id();
            drop(wallet);
            let mut loaded = App::load(env, protocol.clone(), config(), app_id)
                .await
                .unwrap();
            assert_eq!(undelivered(&loaded.take_events(), msg_id), [true]);
            let appends_before = inbox_appends(&p);
            let result = loaded.resend(msg_id).await;
            loaded
                .resend_since(&p.bob.identity().public(), 0)
                .await
                .unwrap();
            assert_eq!(
                (
                    inbox_appends(&p) - appends_before,
                    loaded
                        .outbox_record(msg_id)
                        .await
                        .is_some_and(|item| item.delivery_owed()),
                    undelivered(
                        &crate::app::tests::pending_events(&mut loaded)
                            .await
                            .unwrap(),
                        msg_id
                    ),
                    undelivered(&loaded.take_events(), msg_id),
                ),
                (0, false, vec![true], Vec::<bool>::new()),
                "retained terminal delivery after reload; record: {with_record}; resend: {result:?}"
            );
        }
    })
    .await;
}

#[tokio::test]
async fn test_explicit_resend_bounded_flush_keeps_terminal_record_mark() {
    Box::pin(async {
        let p = Pair::new();
        let protocol = ApiProtocol::new(Mode::Plain);
        let (mut wallet, signed) = accepted_resend_message(&p, &protocol, true).await;
        let msg_id = signed.msg_id();
        for _ in 0..4 {
            p.alice.switch().fail_next(Fault::Unreachable {
                path: "ops".into(),
                after: 0,
            });
        }
        wallet.flush_outbox().await.unwrap();
        p.alice.switch().lock().faults.clear();
        assert!(wallet.outbox_record(msg_id).await.is_some());
        queue_and_hold_resend(&p, &mut wallet, msg_id, true).await;
        assert!(wallet.withdraw_message("sample", msg_id).await.unwrap());
        p.clock.advance_ms(MINUTE);
        let other = wallet.sign_message(Pair::note(&p.bob, "next")).unwrap();
        wallet.queue_signed(other).await.unwrap();
        p.clock.advance_ms(SENT_RETENTION_MS + DAY_MS);
        wallet.config.call_budget_ms = 0;
        let report = wallet.flush_outbox().await.unwrap();
        assert!(report.more);
        assert!(wallet.outbox_record(msg_id).await.is_some());
        assert!(
            wallet
                .sent_to(&p.bob.identity().public(), 0, u64::MAX)
                .await
                .unwrap()
                .is_empty()
        );
        wallet.take_events();
        let appends_before = inbox_appends(&p);
        let result = wallet.resend(msg_id).await;
        assert_eq!(
            (
                inbox_appends(&p) - appends_before,
                wallet
                    .outbox_record(msg_id)
                    .await
                    .is_some_and(|item| item.delivery_owed()),
                undelivered(
                    &crate::app::tests::pending_events(&mut wallet)
                        .await
                        .unwrap(),
                    msg_id
                ),
                undelivered(&wallet.take_events(), msg_id),
            ),
            (0, false, vec![true], Vec::<bool>::new()),
            "a bounded flush retained the record job; resend: {result:?}"
        );
    })
    .await;
}

async fn keep_unsent(p: &Pair, wallet: &mut App, batch: OpBatch, first: bool) {
    for path in ["feed", "ops"] {
        p.alice.switch().fail_next(Fault::Unreachable {
            path: path.into(),
            after: 0,
        });
    }
    let result = if first {
        wallet.submit_batch(batch).await
    } else {
        wallet.submit_new(batch).await
    };
    assert!(result.unwrap_err().kept_batch().is_some());
    p.alice.switch().lock().faults.clear();
    assert!(
        wallet
            .kept_batches()
            .await
            .unwrap()
            .iter()
            .all(|(_, batch)| batch.kept_ms.is_none())
    );
}

#[tokio::test]
async fn test_withdraw_message_removes_every_retained_copy_before_expiry() {
    Box::pin(async {
        for by_recipient in [false, true] {
            for materialized in [false, true] {
                let p = Pair::new();
                let protocol = ApiProtocol::new(Mode::Plain);
                let mut wallet = p.join(&p.alice, "wallet", &protocol).await;
                let signed = wallet
                    .sign_message(Pair::note(&p.bob, "withdrawn"))
                    .unwrap();
                let other = wallet.sign_message(Pair::note(&p.carol, "kept")).unwrap();
                if materialized {
                    wallet.queue_signed(signed.clone()).await.unwrap();
                }
                for n in 0..2 {
                    let batch = OpBatch::for_protocol("sample")
                        .op(OpKind::AllowPut {
                            pubky: [8 + n; 32],
                            reason: pubky_switch_core::admission::PeerReason::Reply,
                        })
                        .local(LocalWrite::Put {
                            key: vec![n],
                            value: vec![n],
                        })
                        .queue(signed.clone())
                        .queue(other.clone());
                    keep_unsent(&p, &mut wallet, batch, n == 0).await;
                }
                assert!(
                    wallet
                        .hold_message("sample", signed.msg_id())
                        .await
                        .unwrap()
                );
                wallet.take_events();
                if by_recipient {
                    assert_eq!(
                        wallet
                            .withdraw_queued(&p.bob.identity().public())
                            .await
                            .unwrap(),
                        [signed.msg_id()]
                    );
                } else {
                    assert!(
                        wallet
                            .withdraw_message("sample", signed.msg_id())
                            .await
                            .unwrap()
                    );
                }
                assert_eq!(undelivered(&wallet.take_events(), signed.msg_id()), [false]);
                p.clock.advance_ms(SENT_RETENTION_MS + DAY_MS);
                assert!(
                    !wallet
                        .withdraw_message("sample", signed.msg_id())
                        .await
                        .unwrap(),
                    "a retained producer cannot recreate an ended delivery"
                );
                assert!(undelivered(&wallet.take_events(), signed.msg_id()).is_empty());
                assert!(
                    wallet
                        .kept_batches()
                        .await
                        .unwrap()
                        .iter()
                        .all(|(_, batch)| batch.queued.len() == 1
                            && batch.queued[0].msg_id() == other.msg_id()),
                    "withdrawal removes only its own retained plaintext"
                );
                wallet.resume_batches().await.unwrap();
                assert!(wallet.kept_batches().await.unwrap().is_empty());
                assert!(wallet.delivery(signed.msg_id()).await.unwrap().is_none());
                assert!(wallet.outbox_record(other.msg_id()).await.is_some());
                for n in 0..2 {
                    assert_eq!(
                        wallet
                            .reader()
                            .get_raw(&[b"p/sample/".as_slice(), &[n]].concat())
                            .await
                            .unwrap(),
                        Some(vec![n])
                    );
                }
                assert_eq!(p.bob.switch().entries_from(&p.alice.identity().public()), 0);
            }
        }
    })
    .await;
}

#[tokio::test]
async fn test_hold_message_restore_rejects_conflicting_outbox_identities() {
    Box::pin(async {
        for conflict in ["overlap", "carried_twice", "omitted_twice"] {
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
            let signed = wallet.sign_message(Pair::note(&p.bob, "held")).unwrap();
            wallet.queue_signed(signed.clone()).await.unwrap();
            let backup = wallet.backup().await.unwrap();
            let other = wallet.sign_message(Pair::note(&p.bob, "omitted")).unwrap();
            assert!(
                wallet
                    .hold_message("sample", signed.msg_id())
                    .await
                    .unwrap()
            );
            let app_id = wallet.app_id();
            drop(wallet);
            let mut value: Value = serde_json::from_slice(&backup.to_bytes().unwrap()).unwrap();
            match conflict {
                "carried_twice" => {
                    let item = value["outbox"][0].clone();
                    value["outbox"].as_array_mut().unwrap().push(item);
                }
                "omitted_twice" => {
                    value["outbox_left_out"] =
                        json!([[other.msg_id(), false], [other.msg_id(), false]]);
                }
                _ => value["outbox_left_out"] = json!([[signed.msg_id(), false]]),
            }
            let backup = AppBackup::from_bytes(&serde_json::to_vec(&value).unwrap()).unwrap();
            for target in [Arc::new(MemoryStore::new()), Arc::clone(&store)] {
                let result = App::restore(
                    p.env(&p.alice, target as Arc<dyn StateStore>),
                    protocol.clone(),
                    config(),
                    &backup,
                )
                .await;
                assert!(
                    matches!(result, Err(AppError::InvalidData(_))),
                    "conflicting outbox identities must be refused: {result:?}"
                );
            }
            let loaded = App::load(
                p.env(&p.alice, store as Arc<dyn StateStore>),
                protocol.clone(),
                config(),
                app_id,
            )
            .await
            .unwrap();
            assert_eq!(
                loaded.held_messages("sample").await.unwrap(),
                [signed.msg_id()]
            );
        }
    })
    .await;
}

#[tokio::test]
async fn test_hold_message_restore_checks_signed_message_metadata() {
    Box::pin(async {
        for field in ["kind", "unowned_kind", "msg_id", "to", "plaintext"] {
            let p = Pair::new();
            let protocol = ApiProtocol::new(Mode::Plain);
            let set =
                crate::app::ProtocolSet::new(vec![protocol.clone(), Arc::new(Retired)]).unwrap();
            let mut wallet = p
                .join_set(&p.alice, "wallet", set.clone(), &["sample-a"])
                .await;
            let env = wallet.env.clone();
            let app_id = wallet.app_id();
            let signed = wallet.sign_message(Pair::note(&p.bob, "held")).unwrap();
            wallet.queue_signed(signed.clone()).await.unwrap();
            assert!(
                wallet
                    .hold_message("sample", signed.msg_id())
                    .await
                    .unwrap()
            );
            let backup = wallet.backup().await.unwrap();
            let mut value: Value = serde_json::from_slice(&backup.to_bytes().unwrap()).unwrap();
            match field {
                "kind" => value["outbox"][0][field] = json!("retired.note"),
                "unowned_kind" => value["outbox"][0]["kind"] = json!("other.note"),
                "msg_id" => {
                    let other = wallet.sign_message(Pair::note(&p.bob, "other")).unwrap();
                    value["outbox"][0][field] = json!(other.msg_id());
                    value["held_messages"] = json!([other.msg_id()]);
                }
                "to" => {
                    value["outbox"][0][field] =
                        json!(pubky_switch_core::enc::b64(&p.carol.identity().public()))
                }
                _ => {
                    let other = wallet.sign_message(Pair::note(&p.bob, "other")).unwrap();
                    value["outbox"][0][field] =
                        json!(pubky_switch_core::enc::b64(&other.plaintext().encode()));
                }
            }
            let backup = AppBackup::from_bytes(&serde_json::to_vec(&value).unwrap()).unwrap();
            drop(wallet);
            for target in [p.env(&p.alice, Arc::new(MemoryStore::new())), env.clone()] {
                let result = App::restore(target, set.clone(), config(), &backup).await;
                assert!(
                    matches!(result, Err(AppError::InvalidData(_))),
                    "{field} must agree with the authenticated plaintext: {result:?}"
                );
            }
            let loaded = App::load(env, set, config(), app_id).await.unwrap();
            assert_eq!(
                loaded.held_messages("sample").await.unwrap(),
                [signed.msg_id()]
            );
        }
    })
    .await;
}

struct Retired;

impl Protocol for Retired {
    fn opaque_members(&self) -> Vec<crate::app::OpaqueRule> {
        vec![crate::app::OpaqueRule {
            kind: Some("retired.note".into()),
            member: "data".into(),
        }]
    }
    fn resend_needed(&self, _: &ResendNeeded) -> Result<Vec<LocalWrite>, StoreFailure> {
        Ok(Vec::new())
    }
    fn missed(&self, _: &MissedEntries) -> Result<Vec<LocalWrite>, StoreFailure> {
        Ok(Vec::new())
    }
    fn name(&self) -> String {
        "retired".into()
    }
    fn has_keys(&self, _: &str) -> bool {
        false
    }
    fn sent_between_own_apps(&self, _: &str) -> bool {
        false
    }
    fn check_scopes(&self, _: &Message, _: &AppCert, _: &AppCert) -> Result<(), String> {
        Ok(())
    }
    fn accepts(&self, _: &AppCert) -> Vec<String> {
        Vec::new()
    }
    fn check_body(&self, _: &ReceivedMessage) -> Result<(), String> {
        Ok(())
    }
}

pub(super) async fn orphaned_kind() {
    let p = Pair::new();
    let protocol = ApiProtocol::new(Mode::Plain);
    let set = crate::app::ProtocolSet::new(vec![protocol.clone(), Arc::new(Retired)]).unwrap();
    let mut wallet = p.join_set(&p.alice, "wallet", set, &["sample-a"]).await;
    let signed = wallet
        .sign_message(OutgoingMessage::new(
            p.bob.identity().public(),
            "retired.note",
            json!({"data": {"fraction": 1.5}})
                .as_object()
                .unwrap()
                .clone(),
        ))
        .unwrap();
    wallet.queue_signed(signed.clone()).await.unwrap();
    assert!(
        wallet
            .hold_message("retired", signed.msg_id())
            .await
            .unwrap()
    );
    let backup = wallet.backup().await.unwrap();
    assert!(backup.layers().unwrap().is_empty());
    assert!(backup.beyond_cursor.is_none());
    drop(wallet);
    let mut restored = App::restore(
        p.env(&p.alice, Arc::new(MemoryStore::new())),
        protocol.clone(),
        config(),
        &backup,
    )
    .await
    .unwrap();
    assert_eq!(
        restored.held_messages("sample").await.unwrap(),
        [signed.msg_id()]
    );
    restored
        .release_message("sample", signed.msg_id())
        .await
        .unwrap();
    assert!(restored.held_messages("sample").await.unwrap().is_empty());
}

#[tokio::test]
async fn test_hold_message_load_rejects_routing_metadata_mismatch() {
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
    let signed = wallet.sign_message(Pair::note(&p.bob, "held")).unwrap();
    wallet.queue_signed(signed.clone()).await.unwrap();
    let app_id = wallet.app_id();
    let key = format!("out/{}", signed.msg_id());
    let mut item: Value = wallet.reader().get(&key).await.unwrap().unwrap();
    item["kind"] = json!("other.note");
    let mut tx = wallet.tx().unwrap();
    tx.put(&key, &item).unwrap();
    wallet.commit(tx).await.unwrap();
    assert!(matches!(
        wallet.hold_message("sample", signed.msg_id()).await,
        Err(AppError::Store(StoreError::Corrupt))
    ));
    assert!(matches!(
        wallet.flush_outbox().await,
        Err(AppError::Store(StoreError::Corrupt))
    ));
    drop(wallet);
    let result = App::load(
        p.env(&p.alice, store as Arc<dyn StateStore>),
        protocol,
        config(),
        app_id,
    )
    .await;
    assert!(matches!(result, Err(AppError::Store(StoreError::Corrupt))));
}

#[tokio::test]
async fn test_hold_message_kept_settlement_rejects_routing_metadata_mismatch() {
    let p = Pair::new();
    let protocol = ApiProtocol::new(Mode::Plain);
    let mut wallet = p.join(&p.alice, "wallet", &protocol).await;
    let signed = wallet.sign_message(Pair::note(&p.bob, "held")).unwrap();
    kept_with(&p, &mut wallet, &signed).await;
    let (id, _) = wallet.kept_batches().await.unwrap().pop().unwrap();
    let key = format!("opq/{}", pubky_switch_core::enc::b64(&id));
    let mut pending: Value = wallet.reader().get(&key).await.unwrap().unwrap();
    pending["queued"][0]["kind"] = json!("other.note");
    let mut tx = wallet.tx().unwrap();
    tx.put(&key, &pending).unwrap();
    wallet.commit(tx).await.unwrap();
    assert!(matches!(
        wallet.receive(None).await,
        Err(AppError::Store(StoreError::Corrupt))
    ));
    assert!(wallet.outbox_record(signed.msg_id()).await.is_none());
}

async fn mismatched_index(p: &Pair, protocol: &Arc<ApiProtocol>) -> (App, String) {
    let mut wallet = p.join(&p.alice, "wallet", protocol).await;
    let first = wallet.sign_message(Pair::note(&p.bob, "held")).unwrap();
    let second = wallet
        .sign_message(Pair::note(&p.bob, "different"))
        .unwrap();
    wallet.queue_signed(first.clone()).await.unwrap();
    wallet.hold_message("sample", first.msg_id()).await.unwrap();
    wallet.queue_signed(second.clone()).await.unwrap();
    let item = wallet.outbox_record(second.msg_id()).await.unwrap();
    let mut tx = wallet.tx().unwrap();
    tx.put(&format!("out/{}", first.msg_id()), &item).unwrap();
    tx.delete(&format!("out/{}", second.msg_id())).unwrap();
    wallet.commit(tx).await.unwrap();
    (wallet, first.msg_id().to_owned())
}

#[tokio::test]
async fn test_hold_message_backup_rejects_mismatched_outbox_index() {
    let p = Pair::new();
    let protocol = ApiProtocol::new(Mode::Plain);
    let (wallet, _) = mismatched_index(&p, &protocol).await;
    assert!(
        matches!(
            wallet.backup().await,
            Err(AppError::Store(StoreError::Corrupt))
        ),
        "a backup must not turn a mismatched index into an unheld delivery"
    );
}

#[tokio::test]
async fn test_hold_message_dispatch_rejects_mismatched_outbox_index() {
    let p = Pair::new();
    let protocol = ApiProtocol::new(Mode::Plain);
    let (mut wallet, id) = mismatched_index(&p, &protocol).await;
    assert!(
        matches!(
            wallet.flush_message(&id).await,
            Err(AppError::Store(StoreError::Corrupt))
        ),
        "dispatch must not use another message's hold identity"
    );
    assert_eq!(p.bob.switch().entries_from(&p.alice.identity().public()), 0);
}

#[tokio::test]
async fn test_withdraw_message_commits_retained_copies_with_its_notice() {
    Box::pin(async {
        for by_recipient in [false, true] {
            for applied in [false, true] {
                let p = Pair::new();
                let protocol = ApiProtocol::new(Mode::Plain);
                let inner = Arc::new(MemoryStore::new());
                let mut wallet = p
                    .join_on(
                        &p.alice,
                        "wallet",
                        protocol.clone(),
                        Arc::clone(&inner) as Arc<dyn StateStore>,
                    )
                    .await;
                let signed = wallet
                    .sign_message(Pair::note(&p.bob, "withdrawn"))
                    .unwrap();
                wallet.queue_signed(signed.clone()).await.unwrap();
                let batch = OpBatch::for_protocol("sample")
                    .op(OpKind::AllowPut {
                        pubky: [8; 32],
                        reason: pubky_switch_core::admission::PeerReason::Reply,
                    })
                    .queue(signed.clone());
                keep_unsent(&p, &mut wallet, batch, true).await;
                wallet
                    .hold_message("sample", signed.msg_id())
                    .await
                    .unwrap();
                let app_id = wallet.app_id();
                drop(wallet);
                let fault = if applied {
                    StoreFault::FailAfter(1)
                } else {
                    StoreFault::FailBefore(1)
                };
                let faulty = Arc::new(FaultStore::new(
                    Arc::clone(&inner) as Arc<dyn StateStore>,
                    fault,
                ));
                let mut wallet = App::load(
                    p.env(&p.alice, Arc::clone(&faulty) as Arc<dyn StateStore>),
                    protocol.clone(),
                    config(),
                    app_id,
                )
                .await
                .unwrap();
                let result = if by_recipient {
                    wallet
                        .withdraw_queued(&p.bob.identity().public())
                        .await
                        .map(|_| ())
                } else {
                    wallet
                        .withdraw_message("sample", signed.msg_id())
                        .await
                        .map(|_| ())
                };
                assert!(matches!(result, Err(AppError::Store(_))));
                assert_eq!(faulty.commits(), 1);
                drop(wallet);
                let mut loaded = App::load(
                    p.env(&p.alice, Arc::clone(&inner) as Arc<dyn StateStore>),
                    protocol.clone(),
                    config(),
                    app_id,
                )
                .await
                .unwrap();
                let retained =
                    loaded
                        .kept_batches()
                        .await
                        .unwrap()
                        .into_iter()
                        .any(|(_, pending)| {
                            pending
                                .queued
                                .iter()
                                .any(|item| item.msg_id() == signed.msg_id())
                        });
                assert_eq!(
                    retained, !applied,
                    "plaintext and delivery end commit together"
                );
                assert_eq!(
                    loaded.outbox_record(signed.msg_id()).await.is_some(),
                    !applied
                );
                assert_eq!(
                    !loaded.held_messages("sample").await.unwrap().is_empty(),
                    !applied
                );
                assert_eq!(
                    undelivered(
                        &crate::app::tests::pending_events(&mut loaded)
                            .await
                            .unwrap(),
                        signed.msg_id()
                    ),
                    if applied { vec![false] } else { vec![] }
                );
                assert_eq!(
                    loaded
                        .withdraw_message("sample", signed.msg_id())
                        .await
                        .unwrap(),
                    !applied
                );
                assert_eq!(
                    undelivered(
                        &crate::app::tests::pending_events(&mut loaded)
                            .await
                            .unwrap(),
                        signed.msg_id()
                    ),
                    [false]
                );
            }
        }
    })
    .await;
}

#[tokio::test]
async fn test_hold_message_rejects_a_substituted_cached_envelope() {
    Box::pin(async {
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
        shop.invite(&p.alice.identity().public()).await.unwrap();
        let held = wallet.sign_message(Pair::note(&p.bob, "held")).unwrap();
        wallet.queue_signed(held.clone()).await.unwrap();
        p.bob.switch().fail_next(Fault::Unreachable {
            path: "inbox".into(),
            after: 0,
        });
        assert!(matches!(
            wallet.flush_message(held.msg_id()).await.unwrap(),
            Some(Delivery::Queued { .. })
        ));
        p.bob.switch().lock().faults.clear();
        assert_eq!(p.bob.switch().entries_from(&p.alice.identity().public()), 0);
        wallet.hold_message("sample", held.msg_id()).await.unwrap();
        let other = wallet.sign_message(Pair::note(&p.bob, "unheld")).unwrap();
        wallet.queue_signed(other.clone()).await.unwrap();
        let mut backup: Value =
            serde_json::from_slice(&wallet.backup().await.unwrap().to_bytes().unwrap()).unwrap();
        let cached = backup["outbox"]
            .as_array()
            .unwrap()
            .iter()
            .find(|item| item["msg_id"] == held.msg_id())
            .unwrap()["sealed"]
            .clone();
        assert!(!cached.is_null());
        let item = backup["outbox"]
            .as_array_mut()
            .unwrap()
            .iter_mut()
            .find(|item| item["msg_id"] == other.msg_id())
            .unwrap();
        item["sealed"] = cached;
        let backup = AppBackup::from_bytes(&serde_json::to_vec(&backup).unwrap()).unwrap();
        for target in [Arc::new(MemoryStore::new()), Arc::clone(&store)] {
            let result = App::restore(
                p.env(&p.alice, target as Arc<dyn StateStore>),
                protocol.clone(),
                config(),
                &backup,
            )
            .await;
            match result {
                Err(AppError::InvalidData(_)) => {}
                Ok(mut restored) => {
                    restored.flush_message(other.msg_id()).await.unwrap();
                    shop.receive(None).await.unwrap();
                    assert!(
                        !protocol
                            .seen()
                            .iter()
                            .any(|message| message.msg_id == held.msg_id()),
                        "another outbox item's cache delivered a held message"
                    );
                    panic!("a substituted cached envelope was accepted");
                }
                other => panic!("unexpected restore result: {other:?}"),
            }
        }
        assert_eq!(
            wallet.held_messages("sample").await.unwrap(),
            [held.msg_id()]
        );
    })
    .await;
}

#[tokio::test]
async fn test_hold_message_expiry_removes_retained_producers_past_give_up_retention() {
    Box::pin(async {
        let p = Pair::new();
        let protocol = ApiProtocol::new(Mode::Plain);
        let mut wallet = p.join(&p.alice, "wallet", &protocol).await;
        let signed = wallet.sign_message(Pair::note(&p.bob, "expires")).unwrap();
        let other = wallet
            .sign_message(Pair::note(&p.carol, "retained"))
            .unwrap();
        let batch = OpBatch::for_protocol("sample")
            .op(OpKind::AllowPut {
                pubky: [8; 32],
                reason: pubky_switch_core::admission::PeerReason::Reply,
            })
            .local(LocalWrite::Put {
                key: b"kept".to_vec(),
                value: vec![1],
            })
            .queue(signed.clone())
            .queue(other.clone());
        keep_unsent(&p, &mut wallet, batch, true).await;
        wallet.queue_stored(signed.plaintext()).await.unwrap();
        wallet
            .hold_message("sample", signed.msg_id())
            .await
            .unwrap();
        p.clock.advance_ms(SENT_RETENTION_MS + DAY_MS);
        wallet.flush_message(signed.msg_id()).await.unwrap();
        assert!(wallet.outbox_record(signed.msg_id()).await.is_none());
        assert!(wallet.held_messages("sample").await.unwrap().is_empty());
        assert_eq!(
            unknown(
                &crate::app::tests::pending_events(&mut wallet)
                    .await
                    .unwrap(),
                signed.msg_id()
            ),
            1
        );
        p.clock.advance_ms(SENT_RETENTION_MS + DAY_MS);
        wallet.resume_batches().await.unwrap();
        assert!(
            wallet.delivery(signed.msg_id()).await.unwrap().is_none(),
            "an expired delivery was recreated by its retained producer"
        );
        assert!(wallet.outbox_record(other.msg_id()).await.is_some());
        assert_eq!(
            wallet.protocol_get("sample", b"kept").await.unwrap(),
            Some(vec![1])
        );
        assert_eq!(
            unknown(
                &crate::app::tests::pending_events(&mut wallet)
                    .await
                    .unwrap(),
                signed.msg_id()
            ),
            1
        );
    })
    .await;
}

#[tokio::test]
async fn test_resend_rejects_a_mismatched_outbox_index_before_writing() {
    Box::pin(async {
        let p = Pair::new();
        let protocol = ApiProtocol::new(Mode::Plain);
        let mut wallet = p.join(&p.alice, "wallet", &protocol).await;
        let mut shop = p.join(&p.bob, "shop", &protocol).await;
        shop.invite(&p.alice.identity().public()).await.unwrap();
        let first = wallet.sign_message(Pair::note(&p.bob, "held")).unwrap();
        wallet.queue_signed(first.clone()).await.unwrap();
        wallet.hold_message("sample", first.msg_id()).await.unwrap();
        let second = wallet.sign_message(Pair::note(&p.bob, "accepted")).unwrap();
        let second = second.clone().with_record(RecordJob {
            target: RecordTarget::new(items(), &second.hash()),
            tag: b"sent".to_vec(),
        });
        wallet.queue_signed(second.clone()).await.unwrap();
        p.alice.switch().fail_next(Fault::Unreachable {
            path: "ops".into(),
            after: 1,
        });
        assert!(matches!(
            wallet.flush_message(second.msg_id()).await.unwrap(),
            Some(Delivery::Accepted { .. })
        ));
        p.alice.switch().lock().faults.clear();
        let item = wallet.outbox_record(second.msg_id()).await.unwrap();
        let mut tx = wallet.tx().unwrap();
        tx.put(&format!("out/{}", first.msg_id()), &item).unwrap();
        tx.delete(&format!("out/{}", second.msg_id())).unwrap();
        wallet.commit(tx).await.unwrap();
        assert!(matches!(
            wallet.resend(first.msg_id()).await,
            Err(AppError::Store(StoreError::Corrupt))
        ));
        assert!(
            wallet.outbox_record(second.msg_id()).await.is_none(),
            "resend wrote under an unvalidated cached identity before refusing its index"
        );
    })
    .await;
}

#[derive(Clone, Copy, Debug)]
enum TerminalDelivery {
    Accepted,
    Refused,
    Undeliverable,
    TooLarge,
}

async fn terminal_delivery_keeps_unrelated_work(terminal: TerminalDelivery) {
    let p = Pair::new();
    let protocol = ApiProtocol::new(Mode::Plain);
    let store = Arc::new(FaultStore::new(
        Arc::new(MemoryStore::new()),
        StoreFault::None,
    ));
    let mut wallet = p
        .join_on(
            &p.alice,
            "wallet",
            protocol.clone(),
            Arc::clone(&store) as Arc<dyn StateStore>,
        )
        .await;
    let mut shop = p.join(&p.bob, "shop", &protocol).await;
    if !matches!(terminal, TerminalDelivery::Undeliverable) {
        shop.invite(&p.alice.identity().public()).await.unwrap();
    }
    // Establish the conversation before keeping an unrelated unanswered operation.
    wallet.send(Pair::note(&p.bob, "first")).await.unwrap();
    let signed = wallet.sign_message(Pair::note(&p.bob, "finished")).unwrap();
    let other = wallet
        .sign_message(Pair::note(&p.carol, "retained"))
        .unwrap();
    for n in 0..2 {
        let batch = OpBatch::for_protocol("sample")
            .op(OpKind::AllowPut {
                pubky: [8 + n; 32],
                reason: pubky_switch_core::admission::PeerReason::Reply,
            })
            .local(LocalWrite::Put {
                key: vec![n],
                value: vec![n],
            })
            .queue(signed.clone())
            .queue(other.clone());
        keep_unsent(&p, &mut wallet, batch, n == 0).await;
    }
    wallet.queue_signed(signed.clone()).await.unwrap();
    wallet.hold_message("sample", other.msg_id()).await.unwrap();
    match terminal {
        TerminalDelivery::Refused => p.bob.switch().fail_next(Fault::Error {
            path: "inbox".into(),
            code: ErrorCode::TooLarge,
            current: Value::Null,
        }),
        TerminalDelivery::TooLarge => {
            store.refuse_puts_as_too_large(Some(format!("out/{}", signed.msg_id()).as_bytes()));
        }
        _ => {}
    }
    let result = wallet.flush_message(signed.msg_id()).await.unwrap();
    match terminal {
        TerminalDelivery::Accepted => assert!(matches!(result, Some(Delivery::Accepted { .. }))),
        TerminalDelivery::Refused => assert!(matches!(result, Some(Delivery::Failed { .. }))),
        TerminalDelivery::TooLarge => assert!(result.is_none()),
        TerminalDelivery::Undeliverable => {
            assert!(matches!(result, Some(Delivery::Queued { .. })));
            wallet
                .hold_message("sample", signed.msg_id())
                .await
                .unwrap();
            p.clock.advance_ms(45 * DAY_MS);
            assert!(
                wallet
                    .flush_message(signed.msg_id())
                    .await
                    .unwrap()
                    .is_none()
            );
        }
    }
    let pending = wallet.kept_batches().await.unwrap();
    assert_eq!(pending.len(), 2);
    assert!(
        pending.iter().all(|(_, batch)| {
            batch
                .queued
                .iter()
                .all(|item| item.msg_id() != signed.msg_id())
        }),
        "{terminal:?} left a retained producer for the ended delivery"
    );
    assert!(pending.iter().all(|(_, batch)| {
        batch
            .queued
            .iter()
            .any(|item| item.msg_id() == other.msg_id())
    }));
    wallet.resume_batches().await.unwrap();
    for n in 0..2 {
        assert_eq!(
            wallet.protocol_get("sample", &[n]).await.unwrap(),
            Some(vec![n])
        );
    }
    assert!(wallet.outbox_record(other.msg_id()).await.is_some());
    assert_eq!(wallet.held_messages("sample").await.unwrap().len(), 1);
    assert_eq!(
        undelivered(
            &crate::app::tests::pending_events(&mut wallet)
                .await
                .unwrap(),
            signed.msg_id()
        ),
        if matches!(
            terminal,
            TerminalDelivery::Undeliverable | TerminalDelivery::TooLarge
        ) {
            vec![false]
        } else {
            vec![]
        }
    );
}

#[tokio::test]
async fn test_delivery_lifecycle_acceptance_retires_all_retained_producers() {
    Box::pin(terminal_delivery_keeps_unrelated_work(
        TerminalDelivery::Accepted,
    ))
    .await;
}

#[tokio::test]
async fn test_delivery_lifecycle_refusal_retires_all_retained_producers() {
    Box::pin(terminal_delivery_keeps_unrelated_work(
        TerminalDelivery::Refused,
    ))
    .await;
}

#[tokio::test]
async fn test_delivery_lifecycle_undeliverable_retires_all_retained_producers() {
    Box::pin(terminal_delivery_keeps_unrelated_work(
        TerminalDelivery::Undeliverable,
    ))
    .await;
}

#[tokio::test]
async fn test_delivery_lifecycle_store_bound_retires_all_retained_producers() {
    Box::pin(terminal_delivery_keeps_unrelated_work(
        TerminalDelivery::TooLarge,
    ))
    .await;
}

#[tokio::test]
async fn test_resend_rejects_sent_identity_before_queueing() {
    Box::pin(async {
        for changed in ["index", "kind", "to", "plaintext"] {
            let p = Pair::new();
            let protocol = ApiProtocol::new(Mode::Plain);
            let mut wallet = p.join(&p.alice, "wallet", &protocol).await;
            let mut shop = p.join(&p.bob, "shop", &protocol).await;
            shop.invite(&p.alice.identity().public()).await.unwrap();
            let first = wallet.sign_message(Pair::note(&p.bob, "other")).unwrap();
            let second = wallet.sign_message(Pair::note(&p.bob, "accepted")).unwrap();
            wallet.queue_signed(second.clone()).await.unwrap();
            assert!(matches!(
                wallet.flush_message(second.msg_id()).await.unwrap(),
                Some(Delivery::Accepted { .. })
            ));
            let mut sent: Value = wallet
                .reader()
                .get(&format!("sent/{}", second.msg_id()))
                .await
                .unwrap()
                .unwrap();
            let msg_id = if changed == "index" {
                first.msg_id()
            } else {
                second.msg_id()
            };
            match changed {
                "index" => {}
                "kind" => sent["kind"] = Value::String("retired.note".into()),
                "to" => {
                    sent["to"] =
                        Value::String(pubky_switch_core::enc::b64(&p.carol.identity().public()))
                }
                "plaintext" => {
                    sent["plaintext"] =
                        Value::String(pubky_switch_core::enc::b64(&first.plaintext().encode()))
                }
                _ => unreachable!(),
            }
            let mut tx = wallet.tx().unwrap();
            tx.put(&format!("sent/{msg_id}"), &sent).unwrap();
            wallet.commit(tx).await.unwrap();
            assert!(
                matches!(
                    wallet.resend(msg_id).await,
                    Err(AppError::Store(StoreError::Corrupt))
                ),
                "{changed}"
            );
            assert!(
                wallet.outbox_record(second.msg_id()).await.is_none(),
                "{changed} queued before identity validation"
            );
            assert!(wallet.outbox_record(first.msg_id()).await.is_none());
        }
    })
    .await;
}

async fn cached_outbox(p: &Pair, wallet: &mut App, signed: &SignedMessage) -> Value {
    wallet.queue_signed(signed.clone()).await.unwrap();
    p.bob.switch().fail_next(Fault::Unreachable {
        path: "inbox".into(),
        after: 0,
    });
    assert!(matches!(
        wallet.flush_message(signed.msg_id()).await.unwrap(),
        Some(Delivery::Queued { .. })
    ));
    p.bob.switch().lock().faults.clear();
    let item: Value = wallet
        .reader()
        .get(&format!("out/{}", signed.msg_id()))
        .await
        .unwrap()
        .unwrap();
    assert!(!item["sealed"].is_null());
    item
}

#[tokio::test]
async fn test_hold_message_cached_restore_preserves_exact_retry_bytes() {
    Box::pin(async {
        for in_place in [false, true] {
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
            shop.invite(&p.alice.identity().public()).await.unwrap();
            let signed = wallet
                .sign_message(Pair::note(&p.bob, "same bytes"))
                .unwrap();
            let cached = cached_outbox(&p, &mut wallet, &signed).await;
            let expected = pubky_switch_core::enc::unb64(
                cached["sealed"]["envelope"]["bytes"].as_str().unwrap(),
            )
            .unwrap();
            wallet
                .hold_message("sample", signed.msg_id())
                .await
                .unwrap();
            let backup = wallet.backup().await.unwrap();
            drop(wallet);
            let target = if in_place {
                store
            } else {
                Arc::new(MemoryStore::new())
            };
            let mut restored = App::restore(
                p.env(&p.alice, target as Arc<dyn StateStore>),
                protocol.clone(),
                config(),
                &backup,
            )
            .await
            .unwrap();
            restored.flush_message(signed.msg_id()).await.unwrap();
            assert_eq!(p.bob.switch().entries_from(&p.alice.identity().public()), 0);
            restored
                .release_message("sample", signed.msg_id())
                .await
                .unwrap();
            p.bob.switch().fail_next(Fault::Unreachable {
                path: "inbox".into(),
                after: 0,
            });
            restored.flush_message(signed.msg_id()).await.unwrap();
            assert_eq!(p.bob.switch().unreached_bodies().last(), Some(&expected));
            p.bob.switch().lock().faults.clear();
            assert!(matches!(
                restored.flush_message(signed.msg_id()).await.unwrap(),
                Some(Delivery::Accepted { .. })
            ));
            shop.receive(None).await.unwrap();
            assert_eq!(
                protocol
                    .seen()
                    .iter()
                    .filter(|message| message.msg_id == signed.msg_id())
                    .count(),
                1
            );
        }
    })
    .await;
}

#[tokio::test]
async fn test_hold_message_cached_identity_is_checked_at_live_and_load_boundaries() {
    Box::pin(async {
        for path in ["load", "reload", "flush", "resend", "backup", "hold"] {
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
            shop.invite(&p.alice.identity().public()).await.unwrap();
            let held = wallet.sign_message(Pair::note(&p.bob, "held")).unwrap();
            let cached = cached_outbox(&p, &mut wallet, &held).await;
            wallet.hold_message("sample", held.msg_id()).await.unwrap();
            let other = wallet.sign_message(Pair::note(&p.bob, "unheld")).unwrap();
            wallet.queue_signed(other.clone()).await.unwrap();
            let mut item: Value = wallet
                .reader()
                .get(&format!("out/{}", other.msg_id()))
                .await
                .unwrap()
                .unwrap();
            item["sealed"] = cached["sealed"].clone();
            let mut tx = wallet.tx().unwrap();
            tx.put(&format!("out/{}", other.msg_id()), &item).unwrap();
            wallet.commit(tx).await.unwrap();
            let result = match path {
                "load" => App::load(
                    p.env(&p.alice, store as Arc<dyn StateStore>),
                    protocol.clone(),
                    config(),
                    wallet.app_id(),
                )
                .await
                .map(|_| ()),
                "reload" => wallet.reload_now().await,
                "flush" => wallet.flush_message(other.msg_id()).await.map(|_| ()),
                "resend" => wallet.resend(other.msg_id()).await.map(|_| ()),
                "backup" => wallet.backup().await.map(|_| ()),
                "hold" => wallet
                    .hold_message("sample", other.msg_id())
                    .await
                    .map(|_| ()),
                _ => unreachable!(),
            };
            assert!(
                matches!(result, Err(AppError::Store(StoreError::Corrupt))),
                "{path}: {result:?}"
            );
            assert_eq!(p.bob.switch().entries_from(&p.alice.identity().public()), 0);
        }
    })
    .await;
}

#[tokio::test]
async fn test_delivery_lifecycle_expired_resend_keeps_its_record_without_requeueing() {
    Box::pin(async {
        let p = Pair::new();
        let protocol = ApiProtocol::new(Mode::Plain);
        let mut wallet = p.join(&p.alice, "wallet", &protocol).await;
        let mut shop = p.join(&p.bob, "shop", &protocol).await;
        shop.invite(&p.alice.identity().public()).await.unwrap();
        let signed = wallet.sign_message(Pair::note(&p.bob, "accepted")).unwrap();
        let signed = signed.clone().with_record(RecordJob {
            target: RecordTarget::new(items(), &signed.hash()),
            tag: b"sent".to_vec(),
        });
        wallet.queue_signed(signed.clone()).await.unwrap();
        p.alice.switch().fail_next(Fault::Unreachable {
            path: "ops".into(),
            after: 1,
        });
        assert!(matches!(
            wallet.flush_message(signed.msg_id()).await.unwrap(),
            Some(Delivery::Accepted { .. })
        ));
        p.alice.switch().lock().faults.clear();
        // Keep the accepted item's record job pending while its re-send is queued.
        p.alice.switch().fail_next(Fault::Unreachable {
            path: "ops".into(),
            after: 0,
        });
        p.bob.switch().fail_next(Fault::Unreachable {
            path: "inbox".into(),
            after: 0,
        });
        wallet.resend(signed.msg_id()).await.unwrap();
        p.alice.switch().lock().faults.clear();
        p.bob.switch().lock().faults.clear();
        wallet
            .hold_message("sample", signed.msg_id())
            .await
            .unwrap();
        p.clock.advance_ms(SENT_RETENTION_MS + DAY_MS);
        wallet.flush_message(signed.msg_id()).await.unwrap();
        let item = wallet.outbox_record(signed.msg_id()).await.unwrap();
        assert!(!item.delivery_owed());
        assert_eq!(
            undelivered(
                &crate::app::tests::pending_events(&mut wallet)
                    .await
                    .unwrap(),
                signed.msg_id()
            ),
            [true]
        );
        wallet
            .resend_since(&p.bob.identity().public(), 0)
            .await
            .unwrap();
        assert!(
            !wallet
                .outbox_record(signed.msg_id())
                .await
                .unwrap()
                .delivery_owed(),
            "an automatic resend recreated a delivery whose record job remained owed"
        );
    })
    .await;
}

#[tokio::test]
async fn test_delivery_lifecycle_expiry_commits_producers_with_its_notice() {
    Box::pin(async {
        for (fault, applied) in [
            (StoreFault::FailBefore(1), false),
            (StoreFault::FailAfter(1), true),
        ] {
            let p = Pair::new();
            let protocol = ApiProtocol::new(Mode::Plain);
            let inner = Arc::new(MemoryStore::new());
            let mut wallet = p
                .join_on(
                    &p.alice,
                    "wallet",
                    protocol.clone(),
                    Arc::clone(&inner) as Arc<dyn StateStore>,
                )
                .await;
            let signed = wallet.sign_message(Pair::note(&p.bob, "expires")).unwrap();
            let batch = OpBatch::for_protocol("sample")
                .op(OpKind::AllowPut {
                    pubky: [8; 32],
                    reason: pubky_switch_core::admission::PeerReason::Reply,
                })
                .local(LocalWrite::Put {
                    key: b"kept".to_vec(),
                    value: vec![1],
                })
                .queue(signed.clone());
            keep_unsent(&p, &mut wallet, batch, true).await;
            wallet.queue_stored(signed.plaintext()).await.unwrap();
            wallet
                .hold_message("sample", signed.msg_id())
                .await
                .unwrap();
            let app_id = wallet.app_id();
            p.clock.advance_ms(SENT_RETENTION_MS + DAY_MS);
            drop(wallet);
            let faulty = Arc::new(FaultStore::new(
                Arc::clone(&inner) as Arc<dyn StateStore>,
                fault,
            ));
            let mut wallet = App::load(
                p.env(&p.alice, faulty as Arc<dyn StateStore>),
                protocol.clone(),
                config(),
                app_id,
            )
            .await
            .unwrap();
            assert!(matches!(
                wallet.flush_message(signed.msg_id()).await,
                Err(AppError::Store(_))
            ));
            drop(wallet);
            let mut loaded = App::load(
                p.env(&p.alice, inner as Arc<dyn StateStore>),
                protocol.clone(),
                config(),
                app_id,
            )
            .await
            .unwrap();
            let retained = loaded
                .kept_batches()
                .await
                .unwrap()
                .iter()
                .any(|(_, batch)| {
                    batch
                        .queued
                        .iter()
                        .any(|item| item.msg_id() == signed.msg_id())
                });
            assert_eq!(retained, !applied);
            assert_eq!(
                loaded.outbox_record(signed.msg_id()).await.is_some(),
                !applied
            );
            assert_eq!(
                !loaded.held_messages("sample").await.unwrap().is_empty(),
                !applied
            );
            assert_eq!(
                unknown(
                    &crate::app::tests::pending_events(&mut loaded)
                        .await
                        .unwrap(),
                    signed.msg_id()
                ),
                usize::from(applied)
            );
        }
    })
    .await;
}

#[tokio::test]
async fn test_hold_message_current_input_completion_preserves_delivery_hold() {
    Box::pin(async {
        for mode in [Mode::Consume, Mode::AwaitAdmission] {
            let p = Pair::new();
            let protocol = ApiProtocol::new(mode);
            let peer = ApiProtocol::new(Mode::Plain);
            let mut wallet = p.join(&p.alice, "wallet", &protocol).await;
            let mut shop = p.join(&p.bob, "shop", &peer).await;
            wallet.invite(&p.bob.identity().public()).await.unwrap();
            shop.invite(&p.alice.identity().public()).await.unwrap();
            let signed = wallet.sign_message(Pair::note(&p.bob, "held")).unwrap();
            wallet.queue_signed(signed.clone()).await.unwrap();
            assert!(
                wallet
                    .hold_message("sample", signed.msg_id())
                    .await
                    .unwrap()
            );
            let (incoming, delivery) = shop.send(Pair::note(&p.alice, "input")).await.unwrap();
            assert!(matches!(delivery, Delivery::Accepted { .. }));
            wallet.receive(None).await.unwrap();
            assert!(protocol.seen().iter().any(|seen| seen.msg_id == incoming));
            let local = wallet
                .protocol_get("sample", format!("notes/{incoming}").as_bytes())
                .await
                .unwrap();
            assert_eq!(local, (mode == Mode::Consume).then(|| b"1".to_vec()));
            assert!(
                !wallet
                    .reader()
                    .exists(&crate::app::state::key::processed(
                        &p.bob.identity().public(),
                        &incoming
                    ))
                    .await
                    .unwrap()
            );
            assert_eq!(
                wallet.parked_entries().await.unwrap().len(),
                usize::from(mode == Mode::AwaitAdmission)
            );
            wallet.flush_outbox().await.unwrap();
            assert_eq!(p.bob.switch().entries_from(&p.alice.identity().public()), 0);
            assert_eq!(
                wallet.held_messages("sample").await.unwrap(),
                [signed.msg_id()]
            );
            wallet
                .release_message("sample", signed.msg_id())
                .await
                .unwrap();
            assert!(matches!(
                wallet.flush_message(signed.msg_id()).await.unwrap(),
                Some(Delivery::Accepted { .. })
            ));
            assert_eq!(p.bob.switch().entries_from(&p.alice.identity().public()), 1);
        }
    })
    .await;
}

#[tokio::test]
async fn test_hold_message_backup_keeps_admission_custody_and_notice() {
    Box::pin(async {
        for in_place in [false, true] {
            let p = Pair::new();
            let protocol = ApiProtocol::new(Mode::AwaitAdmission);
            let peer = ApiProtocol::new(Mode::Plain);
            let store = Arc::new(MemoryStore::new());
            let mut wallet = p.join_on(&p.alice, "wallet", protocol.clone(), store.clone()).await;
            let mut shop = p.join(&p.bob, "shop", &peer).await;
            wallet.invite(&p.bob.identity().public()).await.unwrap();
            shop.invite(&p.alice.identity().public()).await.unwrap();
            let (expired, delivery) = shop.send(Pair::note(&p.alice, "old input")).await.unwrap();
            assert!(matches!(delivery, Delivery::Accepted { .. }));
            wallet.receive(None).await.unwrap();
            assert_eq!(wallet.parked_entries().await.unwrap().len(), 1);
            p.clock.advance_ms(crate::app::MAX_UNVERIFIED_AGE_MS + 1);
            wallet.receive(None).await.unwrap();
            wallet.receive(None).await.unwrap();
            let old_notice = wallet.unacknowledged_events().await.unwrap().into_iter().find_map(|event| match event {
                AppEvent::StoredEntryDropped { message, receipt, notice_id, .. } if message.msg_id == expired => Some((message, receipt, notice_id)),
                _ => None,
            }).unwrap();
            assert!(wallet.parked_entries().await.unwrap().is_empty());
            let (waiting, delivery) = shop.send(Pair::note(&p.alice, "current input")).await.unwrap();
            assert!(matches!(delivery, Delivery::Accepted { .. }));
            wallet.receive(None).await.unwrap();
            let custody = wallet.parked_entries().await.unwrap();
            assert_eq!(custody.len(), 1);
            let receipt = wallet.stored_at(custody[0].seq).unwrap().receipt;
            let signed = wallet.sign_message(Pair::note(&p.bob, "held output")).unwrap();
            wallet.queue_signed(signed.clone()).await.unwrap();
            assert!(wallet.hold_message("sample", signed.msg_id()).await.unwrap());
            let backup = wallet.backup().await.unwrap();
            drop(wallet);
            let target = if in_place { store } else { Arc::new(MemoryStore::new()) };
            let mut restored = App::restore(p.env(&p.alice, target), protocol.clone(), config(), &backup).await.unwrap();
            assert_eq!(restored.held_messages("sample").await.unwrap(), [signed.msg_id()]);
            let custody = restored.parked_entries().await.unwrap();
            assert_eq!(custody.len(), 1);
            assert_eq!(restored.stored_at(custody[0].seq).unwrap().receipt, receipt);
            let restored_notice = restored.unacknowledged_events().await.unwrap().into_iter().find_map(|event| match event {
                AppEvent::StoredEntryDropped { id, message, receipt, notice_id, .. } if message.msg_id == expired => Some((id, (message, receipt, notice_id))),
                _ => None,
            });
            assert_eq!(restored_notice.as_ref().map(|(_, notice)| notice), Some(&old_notice), "the backup retains the exact owed notice beside the held delivery");
            let (id, _) = restored_notice.unwrap();
            restored.ack_event_with("sample", id, &[LocalWrite::Put { key: b"handled-drop".to_vec(), value: vec![1] }]).await.unwrap();
            assert_eq!(restored.protocol_get("sample", b"handled-drop").await.unwrap(), Some(vec![1]));
            assert!(!restored.unacknowledged_events().await.unwrap().iter().any(|event| matches!(event, AppEvent::StoredEntryDropped { message, .. } if message.msg_id == expired)));
            *protocol.mode.lock().unwrap() = Mode::Consume;
            p.clock.advance_ms(10_000);
            restored.receive(None).await.unwrap();
            assert!(restored.parked_entries().await.unwrap().is_empty());
            assert!(!restored.reader().exists(&crate::app::state::key::processed(&p.bob.identity().public(), &waiting)).await.unwrap());
            restored.flush_outbox().await.unwrap();
            assert_eq!(p.bob.switch().entries_from(&p.alice.identity().public()), 0);
            assert_eq!(restored.held_messages("sample").await.unwrap(), [signed.msg_id()]);
            restored.release_message("sample", signed.msg_id()).await.unwrap();
            assert!(matches!(restored.flush_message(signed.msg_id()).await.unwrap(), Some(Delivery::Accepted { .. })));
            assert_eq!(p.bob.switch().entries_from(&p.alice.identity().public()), 1);
        }
    }).await;
}
