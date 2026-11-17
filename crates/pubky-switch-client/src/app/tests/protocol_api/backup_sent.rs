//! Sent messages across a backup and a restore (Switch spec 12.4 "Sent messages").

use super::*;
use crate::app::MAX_CARRIED_SENT_BYTES;

/// Alice's wallet and bob's shop admitting her, and `n` notes of `text` the wallet sent
/// that bob's inbox accepted, oldest first, as `sent_to` lists them.
async fn wallet_with_sent_notes(
    p: &Pair,
    protocol: &Arc<ApiProtocol>,
    n: usize,
    text: &str,
) -> (App, App, Vec<SentMessage>) {
    let mut wallet = p.join(&p.alice, "wallet", protocol).await;
    let mut shop = p.join(&p.bob, "shop", protocol).await;
    shop.invite(&p.alice.identity().public()).await.unwrap();
    let mut msg_ids = Vec::new();
    for _ in 0..n {
        let (msg_id, delivery) = wallet.send(Pair::note(&p.bob, text)).await.unwrap();
        assert!(
            matches!(delivery, Delivery::Accepted { .. }),
            "{delivery:?}"
        );
        assert!(
            wallet.outbox_record(&msg_id).await.is_none(),
            "out of the outbox"
        );
        msg_ids.push(msg_id);
        p.clock.advance_ms(1);
    }
    let mut sent = wallet
        .sent_to(&p.bob.identity().public(), 0, u64::MAX)
        .await
        .unwrap();
    sent.sort_by_key(|sent| msg_ids.iter().position(|id| *id == sent.msg_id));
    wallet.take_events();
    (wallet, shop, sent)
}

/// A message delivered before the backup, and no longer in the outbox, is never told
/// undelivered by the restored app: the protocol's reconcile queues it again from its
/// stored plaintext, and nothing is queued, delivered or given up.
#[tokio::test]
async fn test_backup_sent_message_is_never_told_undelivered_after_a_restore() {
    Box::pin(async {
        for layered in [false, true] {
            let p = Pair::new();
            let protocol = ApiProtocol::new(Mode::Plain);
            let (mut wallet, _shop, sent) = wallet_with_sent_notes(&p, &protocol, 1, "hi").await;
            let note = &sent[0];
            let backup = if layered {
                wallet.backup_layered().await.unwrap()
            } else {
                wallet.backup().await.unwrap()
            };
            drop(wallet);
            let mut restored = restored_wallet(&p, &protocol, &backup).await;
            let delivery = restored.delivery(&note.msg_id).await.unwrap();
            assert_eq!(
                restored.queue_stored(&note.plaintext).await.unwrap(),
                note.msg_id
            );
            let mut events = restored.take_events();
            // Past the copy's replay window, a copy still queued would be given up.
            p.clock.advance_ms(SENT_RETENTION_MS + MINUTE);
            restored.flush_outbox().await.unwrap();
            events.extend(restored.take_events());
            assert_eq!(
                undelivered(&events, &note.msg_id),
                Vec::<bool>::new(),
                "layered: {layered}"
            );
            assert_eq!(
                delivery,
                Some(Delivery::Accepted {
                    accepted_at_ms: note.accepted_at_ms.unwrap()
                })
            );
            assert_eq!(p.bob.switch().entries_from(&p.alice.identity().public()), 1);
        }
    })
    .await;
}

/// A backup's sent messages read back whole: the restored app lists each with every
/// acceptance time, and answers a re-send with the same signed plaintext.
#[tokio::test]
async fn test_backup_sent_messages_read_back_whole_after_a_restore() {
    Box::pin(async {
        let p = Pair::new();
        let protocol = ApiProtocol::new(Mode::Plain);
        let (mut wallet, _shop, sent) = wallet_with_sent_notes(&p, &protocol, 2, "hi").await;
        p.clock.advance_ms(MINUTE);
        wallet.resend(&sent[0].msg_id).await.unwrap();
        let bob = p.bob.identity().public();
        let before = wallet.sent_to(&bob, 0, u64::MAX).await.unwrap();
        let backup = wallet.backup().await.unwrap();
        drop(wallet);
        let mut restored = restored_wallet(&p, &protocol, &backup).await;
        let shown = |list: &[SentMessage]| {
            let mut out: Vec<_> = list
                .iter()
                .map(|sent| {
                    (
                        sent.msg_id.clone(),
                        sent.plaintext.encode(),
                        sent.accepted_times_ms(),
                    )
                })
                .collect();
            out.sort();
            out
        };
        let after = restored.sent_to(&bob, 0, u64::MAX).await.unwrap();
        assert_eq!(shown(&after), shown(&before));
        assert_eq!(
            before[0].accepted_times_ms().len() + before[1].accepted_times_ms().len(),
            3
        );
        let entries = p.bob.switch().entries_from(&p.alice.identity().public());
        p.clock.advance_ms(MINUTE);
        assert!(matches!(
            restored.resend(&sent[1].msg_id).await.unwrap(),
            Delivery::Accepted { .. }
        ));
        assert_eq!(
            p.bob.switch().entries_from(&p.alice.identity().public()),
            entries + 1
        );
    })
    .await;
}

/// Past [`MAX_CARRIED_SENT_BYTES`] a backup carries the oldest acceptances without their
/// plaintext, and counts what it leaves out: a restored app reads such a message as
/// accepted, gives a re-send of it up as a re-send, and is told how many were left out.
#[tokio::test]
async fn test_backup_sent_messages_over_the_bound_keep_their_acceptances() {
    Box::pin(async {
        let p = Pair::new();
        let protocol = ApiProtocol::new(Mode::Plain);
        let text = "x".repeat(40_000);
        let n = usize::try_from(MAX_CARRIED_SENT_BYTES / 40_000).unwrap() + 10;
        let (wallet, _shop, sent) = wallet_with_sent_notes(&p, &protocol, n, &text).await;
        let backup = wallet.backup().await.unwrap();
        drop(wallet);
        let value: Value = serde_json::from_slice(&backup.to_bytes().unwrap()).unwrap();
        let carried = value["sent"].as_array().unwrap();
        let whole = |msg_id: &str| {
            carried
                .iter()
                .find(|record| record["msg_id"] == msg_id)
                .map(|record| !record["plaintext"].is_null())
        };
        let (oldest, newest) = (&sent[0], &sent[n - 1]);
        assert_eq!(carried.len(), n, "every acceptance fits");
        assert_eq!(value["sent_left_out"], 0);
        assert_eq!(whole(&newest.msg_id), Some(true));
        assert_eq!(whole(&oldest.msg_id), Some(false), "past the bound, bare");

        // What a backup left out is told at the restore, by count.
        let mut value = value.clone();
        value["sent_left_out"] = json!(2);
        let counted = AppBackup::from_bytes(&serde_json::to_vec(&value).unwrap()).unwrap();
        let mut restored = restored_wallet(&p, &protocol, &counted).await;
        assert!(
            restored.take_events().iter().any(|e| matches!(
                e,
                AppEvent::RestoreLeftBehind {
                    sent_messages: 2,
                    ..
                }
            )),
            "the left-out count is told"
        );
        drop(restored);

        let mut restored = restored_wallet(&p, &protocol, &backup).await;
        restored.take_events();
        let bob = p.bob.identity().public();
        let accepted = |sent: &SentMessage| {
            Some(Delivery::Accepted {
                accepted_at_ms: sent.accepted_at_ms.unwrap(),
            })
        };
        assert_eq!(
            restored.delivery(&oldest.msg_id).await.unwrap(),
            accepted(oldest)
        );
        let listed = restored.sent_to(&bob, 0, u64::MAX).await.unwrap();
        assert!(listed.iter().any(|sent| sent.msg_id == newest.msg_id));
        assert!(listed.iter().all(|sent| sent.msg_id != oldest.msg_id));
        // Known as sent, it isn't queued again from its plaintext.
        assert_eq!(
            restored.queue_stored(&oldest.plaintext).await.unwrap(),
            oldest.msg_id
        );
        assert!(restored.outbox_record(&oldest.msg_id).await.is_none());
        // A re-send can't go without the plaintext: given up, told once as a re-send.
        for _ in 0..2 {
            assert!(matches!(
                restored.resend(&oldest.msg_id).await,
                Err(AppError::Refused(Refusal::WontDeliver(
                    WontDeliver::GivenUp
                )))
            ));
        }
        assert_eq!(
            undelivered(&restored.take_events(), &oldest.msg_id),
            vec![true]
        );
        assert_eq!(
            restored.delivery(&oldest.msg_id).await.unwrap(),
            accepted(oldest)
        );
    })
    .await;
}

/// A backup whose sent messages no writer produces is refused as damaged, before
/// anything is written.
#[tokio::test]
async fn test_backup_sent_messages_no_writer_produces_are_refused() {
    Box::pin(async {
        let p = Pair::new();
        let protocol = ApiProtocol::new(Mode::Plain);
        let (mut wallet, _shop, _) = wallet_with_sent_notes(&p, &protocol, 1, "hi").await;
        // A second note queued and never accepted.
        let queued = wallet.sign_message(Pair::note(&p.bob, "queued")).unwrap();
        wallet.queue_signed(queued.clone()).await.unwrap();
        let backup = wallet.backup().await.unwrap();
        drop(wallet);
        let original: Value = serde_json::from_slice(&backup.to_bytes().unwrap()).unwrap();
        // As taken, it restores.
        restored_wallet(&p, &protocol, &backup).await;
        // A sent record of the queued note, as its accepted copy would be.
        let item = original["outbox"][0].clone();
        assert_eq!(item["msg_id"], queued.msg_id());
        let record_of_queued = json!({
            "origin": item["origin"],
            "to": item["to"],
            "kind": item["kind"],
            "msg_id": item["msg_id"],
            "plaintext": item["plaintext"],
            "first_ms": START,
            "resent": [],
        });
        let mut installed = Vec::new();
        for case in [
            "twice",
            "past its retention at the backup",
            "not signed for its recipient",
            "beside a queued copy never accepted",
            "beside a message left out as never accepted",
            "another origin than its queued copy",
            "over the bound",
        ] {
            let mut value = original.clone();
            let mut record = record_of_queued.clone();
            match case {
                "twice" => record = value["sent"][0].clone(),
                "past its retention at the backup" => {
                    let taken = value["taken_ms"].as_u64().unwrap();
                    record = value["sent"][0].take();
                    record["first_ms"] = json!(taken - SENT_RETENTION_MS);
                    value["sent"] = json!([]);
                }
                "not signed for its recipient" => {
                    record = value["sent"][0].take();
                    record["to"] = json!(pubky_switch_core::enc::b64(&p.carol.identity().public()));
                    value["sent"] = json!([]);
                }
                "beside a queued copy never accepted" => {}
                "beside a message left out as never accepted" => {
                    value["outbox"] = json!([]);
                    value["outbox_left_out"] = json!([[queued.msg_id(), false]]);
                }
                "another origin than its queued copy" => {
                    value["outbox"][0]["accepted_at_ms"] = json!(START);
                    record["origin"] = json!("Reconstructed");
                }
                _ => {
                    record = value["sent"][0].clone();
                    record["msg_id"] = json!("over");
                    record["plaintext"] = Value::Null;
                    record["kind"] =
                        json!("x".repeat(usize::try_from(MAX_CARRIED_SENT_BYTES).unwrap()));
                }
            }
            value["sent"].as_array_mut().unwrap().push(record);
            let damaged = AppBackup::from_bytes(&serde_json::to_vec(&value).unwrap()).unwrap();
            let env = p.env(&p.alice, Arc::new(MemoryStore::new()));
            match App::restore(env, protocol.clone(), config(), &damaged).await {
                Err(AppError::InvalidData(_)) => {}
                other => installed.push(format!("{case}: {other:?}")),
            }
        }
        assert!(installed.is_empty(), "restored: {installed:?}");
    })
    .await;
}

/// A message queued and held when the backup was taken, and accepted since: a restore in
/// place from that backup keeps the store's acceptance, so it delivers nothing again, never
/// tells the message undelivered, and ends its hold. A backup whose copy of that message
/// isn't the store's is refused, the store untouched.
#[tokio::test]
async fn test_backup_sent_restore_in_place_keeps_an_acceptance_since_the_backup() {
    Box::pin(async {
        let p = Pair::new();
        let protocol = ApiProtocol::new(Mode::Plain);
        let store = Arc::new(MemoryStore::new());
        let on_store = || p.env(&p.alice, Arc::clone(&store) as Arc<dyn StateStore>);
        let mut wallet = p
            .join_on(
                &p.alice,
                "wallet",
                protocol.clone(),
                Arc::clone(&store) as Arc<dyn StateStore>,
            )
            .await;
        let mut shop = p.join(&p.bob, "shop", &protocol).await;
        let signed = wallet.sign_message(Pair::note(&p.bob, "hello")).unwrap();
        let msg_id = wallet.queue_signed(signed).await.unwrap();
        wallet.flush_outbox().await.unwrap();
        assert!(wallet.hold_message("sample", &msg_id).await.unwrap());
        let backup = wallet.backup().await.unwrap();
        wallet.release_message("sample", &msg_id).await.unwrap();
        shop.invite(&p.alice.identity().public()).await.unwrap();
        assert_eq!(
            wallet.flush_outbox().await.unwrap().done,
            vec![msg_id.clone()]
        );
        let accepted = wallet.delivery(&msg_id).await.unwrap();
        assert!(matches!(accepted, Some(Delivery::Accepted { .. })));
        drop(wallet);

        // Another origin than the store's sent copy: no writer gives one `msg_id` two.
        let mut value: Value = serde_json::from_slice(&backup.to_bytes().unwrap()).unwrap();
        value["outbox"][0]["origin"] = json!("Reconstructed");
        let other = AppBackup::from_bytes(&serde_json::to_vec(&value).unwrap()).unwrap();
        let refused = App::restore(on_store(), protocol.clone(), config(), &other).await;
        assert!(
            matches!(refused, Err(AppError::InvalidData(_))),
            "{refused:?}"
        );

        let alice = p.alice.identity().public();
        let entries = p.bob.switch().entries_from(&alice);
        let mut restored = App::restore(on_store(), protocol.clone(), config(), &backup)
            .await
            .unwrap();
        let mut events = restored.take_events();
        let delivery = restored.delivery(&msg_id).await.unwrap();
        restored.flush_outbox().await.unwrap();
        // Past the put-back's replay deadline, a delivery still owed would be given up.
        p.clock.advance_ms(SENT_RETENTION_MS + MINUTE);
        restored.flush_outbox().await.unwrap();
        events.extend(restored.take_events());
        assert_eq!(
            p.bob.switch().entries_from(&alice),
            entries,
            "not delivered again"
        );
        assert_eq!(undelivered(&events, &msg_id), Vec::<bool>::new());
        assert_eq!(delivery, accepted);
        assert!(restored.outbox_record(&msg_id).await.is_none());
        assert!(restored.held_messages("sample").await.unwrap().is_empty());
    })
    .await;
}
