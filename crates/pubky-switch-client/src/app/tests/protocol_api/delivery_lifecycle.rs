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
                        .queue(signed.clone());
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
                        .all(|(_, batch)| batch.queued.is_empty()),
                    "withdrawal removes retained plaintext"
                );
                wallet.resume_batches().await.unwrap();
                assert!(wallet.kept_batches().await.unwrap().is_empty());
                assert!(wallet.delivery(signed.msg_id()).await.unwrap().is_none());
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
        for duplicate in [false, true] {
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
            assert!(
                wallet
                    .hold_message("sample", signed.msg_id())
                    .await
                    .unwrap()
            );
            let app_id = wallet.app_id();
            drop(wallet);
            let mut value: Value = serde_json::from_slice(&backup.to_bytes().unwrap()).unwrap();
            if duplicate {
                let item = value["outbox"][0].clone();
                value["outbox"].as_array_mut().unwrap().push(item);
            } else {
                value["outbox_left_out"] = json!([[signed.msg_id(), false]]);
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
            let mut wallet = p.join_set(&p.alice, "wallet", set, &["sample-a"]).await;
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
            let result = App::restore(
                p.env(&p.alice, Arc::new(MemoryStore::new())),
                protocol.clone(),
                config(),
                &backup,
            )
            .await;
            assert!(
                matches!(result, Err(AppError::InvalidData(_))),
                "{field} must agree with the authenticated plaintext: {result:?}"
            );
        }
    })
    .await;
}

struct Retired;

impl Protocol for Retired {
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
            Map::new(),
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
