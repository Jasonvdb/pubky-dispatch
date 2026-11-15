use super::*;
use crate::StoreError;
use crate::app::StoreFailure;

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
                            kind: pubky_switch_core::ops::AllowKind::Conversation,
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
                        kind: pubky_switch_core::ops::AllowKind::Conversation,
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
                        &loaded.pending_duty_events().await.unwrap(),
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
                        &loaded.pending_duty_events().await.unwrap(),
                        signed.msg_id()
                    ),
                    [false]
                );
            }
        }
    })
    .await;
}
