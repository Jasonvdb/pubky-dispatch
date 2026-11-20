//! The records an owning protocol reads at each append of its signed message.

use super::*;
use crate::app::{AppendDecision, DeliveryView, KeptReason, RecordRead};

pub(super) struct Gate {
    collections: Vec<Collection>,
    observed: Mutex<Vec<([u8; 32], Option<u64>)>>,
    regress_clock: Mutex<Option<Arc<crate::clock::TestClock>>>,
}

impl Gate {
    fn new() -> Self {
        let temporary = Collection::new("sample.pending", Policy::new("sample-a", &["sample-a"]));
        let permanent = Collection::new(
            "sample.completed",
            Policy::new("sample-a", &["sample-a"]).permanent(None),
        );
        Self {
            collections: vec![temporary, permanent],
            observed: Mutex::new(Vec::new()),
            regress_clock: Mutex::new(None),
        }
    }

    pub(super) fn targets(&self, id: &[u8]) -> Vec<RecordTarget> {
        self.collections
            .iter()
            .map(|c| RecordTarget::new(c.clone(), id))
            .collect()
    }

    pub(super) fn decide(
        &self,
        d: &DeliveryView<'_>,
        records: &[(RecordTarget, RecordRead)],
    ) -> AppendDecision {
        if let Some(clock) = self.regress_clock.lock().unwrap().take() {
            clock.set_ms(clock.now_ms() - 1);
        }
        self.observed
            .lock()
            .unwrap()
            .push((d.hash(), d.recovery_from()));
        let id = d.message().msg_id.as_str();
        let targets = self.targets(id.as_bytes());
        let [(pending, first), (completed, second)] = records else {
            return AppendDecision::Hold;
        };
        assert_eq!([pending, completed], [&targets[0], &targets[1]]);
        let holds = |read: &RecordRead| {
            matches!(read, RecordRead::Fresh(r) if !r.flagged && !r.not_taken
            && !r.different_write_at_held_version && !r.divergent && ids(r.content.value()) == [id])
        };
        if holds(first) && holds(second) {
            AppendDecision::Withdraw
        } else if holds(first)
            && matches!(
                second,
                RecordRead::Kept {
                    reason: KeptReason::NotFound,
                    ..
                }
            )
        {
            AppendDecision::Send
        } else {
            AppendDecision::Hold
        }
    }
}

fn requests(pair: &Pair, from: usize) -> Vec<String> {
    pair.router
        .log()
        .into_iter()
        .skip(from)
        .filter_map(|line| {
            if line.starts_with(&format!("GET {SWITCH_ORIGIN} ")) {
                return line.split_once("/records/").map(|(_, key)| key.to_owned());
            }
            (line.starts_with(&format!("POST {BOB_ORIGIN} ")) && line.contains("/inbox"))
                .then(|| "append".into())
        })
        .collect()
}

struct Sending {
    pair: Pair,
    protocol: Arc<ApiProtocol>,
    gate: Arc<Gate>,
    store: Arc<MemoryStore>,
    wallet: App,
    signed: SignedMessage,
    keys: Vec<String>,
}

impl Sending {
    async fn new() -> Self {
        let pair = Pair::new();
        let protocol = ApiProtocol::new(Mode::Plain);
        let gate = Arc::new(Gate::new());
        *protocol.collections.lock().unwrap() = gate.collections.clone();
        let store = Arc::new(MemoryStore::new());
        let mut wallet = pair
            .join_on(&pair.alice, "wallet", protocol.clone(), store.clone())
            .await;
        let mut recipient = pair.join(&pair.bob, "shop", &protocol).await;
        recipient
            .invite(&pair.alice.identity().public())
            .await
            .unwrap();
        let signed = wallet
            .sign_message(OutgoingMessage::new(
                pair.bob.identity().public(),
                "sample.note",
                json!({"text":"hello"}).as_object().unwrap().clone(),
            ))
            .unwrap();
        let targets = gate.targets(signed.msg_id().as_bytes());
        let keys = targets
            .iter()
            .map(|target| pubky_switch_core::enc::b64(&wallet.record_key(target).unwrap()))
            .collect();
        wallet
            .put_record(&targets[0], &value(&[signed.msg_id()]), vec![])
            .await
            .unwrap();
        wallet.queue_signed(signed.clone()).await.unwrap();
        *protocol.append_gate.lock().unwrap() = Some(gate.clone());
        Self {
            pair,
            protocol,
            gate,
            store,
            wallet,
            signed,
            keys,
        }
    }
}

#[tokio::test]
async fn test_append_records_are_local_during_enumeration_and_read_for_each_timestamp_attempt() {
    Box::pin(async {
        let mut setup = Sending::new().await;
        let from = setup.pair.router.log().len();
        let queued = setup.wallet.queued_messages("sample").await.unwrap();
        assert_eq!(queued.len(), 1);
        assert!(requests(&setup.pair, from).is_empty());
        assert!(setup.gate.observed.lock().unwrap().is_empty());
        let server_time = pubky_switch_core::time::rfc3339(setup.pair.clock.now_ms());
        setup.pair.bob.switch().fail_next(Fault::Error {
            path: "/inbox".into(),
            code: ErrorCode::StaleTimestamp,
            current: json!({"server_time": server_time}),
        });
        let status = setup
            .wallet
            .flush_message(setup.signed.msg_id())
            .await
            .unwrap();
        assert!(
            matches!(status, Some(Delivery::Accepted { .. })),
            "{status:?}"
        );
        let round = vec![
            setup.keys[0].clone(),
            setup.keys[1].clone(),
            "append".into(),
        ];
        assert_eq!(requests(&setup.pair, from), [round.clone(), round].concat());
        assert_eq!(
            *setup.gate.observed.lock().unwrap(),
            [(setup.signed.plaintext().hash(), None); 2]
        );
    })
    .await;
}

#[tokio::test]
async fn test_delivery_view_tracks_the_signed_recovery_cutoff_after_reload() {
    Box::pin(async {
        let mut setup = Sending::new().await;
        let observed = Arc::new(Mutex::new(Vec::new()));
        let captured = observed.clone();
        *setup.protocol.delivery_check.lock().unwrap() = Some(Arc::new(move |delivery| {
            captured.lock().unwrap().push(delivery.recovery_from());
            Ok(false)
        }));
        let app_id = setup.wallet.app_id();
        for (lost, origin) in [(1, "https://second.example"), (2, "https://third.example")] {
            let next = ScriptedSwitch::recovering(
                setup.pair.alice.identity().key(),
                [lost as u8; 32],
                setup.pair.clock.clone(),
                lost + 1,
                lost,
            )
            .unwrap();
            let doc = setup
                .pair
                .alice
                .sign_next(|body| {
                    body.generation = lost + 1;
                    body.recovery_from = Some(lost);
                    body.inbox = Inbox::new(origin, next.service_key());
                })
                .unwrap();
            next.deliver_identity(&doc).unwrap();
            setup.pair.router.add_switch(origin, &next);
            setup.wallet.refresh_identity().await.unwrap();
            setup.wallet.receive(None).await.unwrap();
            drop(setup.wallet);
            setup.wallet = App::load(
                setup.pair.env(&setup.pair.alice, setup.store.clone()),
                setup.protocol.clone(),
                config(),
                app_id,
            )
            .await
            .unwrap();
            observed.lock().unwrap().clear();
            let queued = setup.wallet.queued_messages("sample").await.unwrap();
            assert!(queued.iter().any(|m| m.msg_id == setup.signed.msg_id()));
            assert_eq!(*observed.lock().unwrap(), [Some(lost)]);
        }
    })
    .await;
}

#[tokio::test]
async fn test_append_records_withdraw_a_retry_after_reload_and_keep_prior_delivery_unknown() {
    Box::pin(async {
        let mut setup = Sending::new().await;
        let id = setup.signed.msg_id();
        setup.pair.bob.switch().fail_next(Fault::LoseAnswer {
            path: "/inbox".into(),
        });
        let from = setup.pair.router.log().len();
        assert!(matches!(
            setup.wallet.flush_message(id).await.unwrap(),
            Some(Delivery::Queued { .. })
        ));
        assert_eq!(
            requests(&setup.pair, from),
            [setup.keys[0].as_str(), setup.keys[1].as_str(), "append"]
        );
        let target = setup.gate.targets(id.as_bytes())[1].clone();
        setup
            .wallet
            .put_record(&target, &value(&[id]), vec![])
            .await
            .unwrap();
        let sender = setup.wallet.app_id();
        drop(setup.wallet);
        let mut wallet = App::load(
            setup.pair.env(&setup.pair.alice, setup.store),
            setup.protocol,
            config(),
            sender,
        )
        .await
        .unwrap();
        let from = setup.pair.router.log().len();
        wallet.flush_message(id).await.unwrap();
        assert_eq!(requests(&setup.pair, from), setup.keys);
        assert!(wallet.queued_messages("sample").await.unwrap().is_empty());
        assert!(
            wallet
                .unacknowledged_events()
                .await
                .unwrap()
                .iter()
                .any(|e| matches!(e,AppEvent::DeliveryUnknown { msg_id,.. } if msg_id == id))
        );
        assert_eq!(
            setup
                .pair
                .bob
                .switch()
                .entries_from(&setup.pair.alice.identity().public()),
            1
        );
    })
    .await;
}

#[tokio::test]
async fn test_append_records_terminal_replay_decision_survives_a_clock_jump() {
    Box::pin(async {
        for expired in [false, true] {
            let mut setup = Sending::new().await;
            let id = setup.signed.msg_id();
            if !expired {
                let target = setup.gate.targets(id.as_bytes())[1].clone();
                setup
                    .wallet
                    .put_record(&target, &value(&[id]), vec![])
                    .await
                    .unwrap();
            }
            let backup = setup.wallet.backup().await.unwrap();
            drop(setup.wallet);
            let device = Arc::new(crate::clock::TestClock::new(setup.pair.clock.now_ms()));
            let mut env = setup
                .pair
                .env(&setup.pair.alice, Arc::new(MemoryStore::new()));
            env.clock = device.clone();
            let mut restored = App::restore(env, setup.protocol, config(), &backup)
                .await
                .unwrap();
            let deadline = restored
                .outbox_record(id)
                .await
                .unwrap()
                .replay_until_ms()
                .unwrap();
            if expired {
                setup.pair.clock.set_ms(deadline - 1);
                device.set_ms(deadline - 1);
                setup.pair.bob.homeserver().slow_reads(
                    setup.pair.bob.identity().public(),
                    setup.pair.clock.clone(),
                    2,
                );
            }
            *setup.gate.regress_clock.lock().unwrap() = Some(device);
            let from = setup.pair.router.log().len();
            restored.flush_message(id).await.unwrap();
            assert!(setup.gate.regress_clock.lock().unwrap().is_none());
            assert_eq!(requests(&setup.pair, from), setup.keys, "no inbox POST");
            if expired {
                assert!(restored.highest_service_time().unwrap() > deadline);
            }
            assert!(restored.outbox_record(id).await.is_none());
            assert!(restored.queued_messages("sample").await.unwrap().is_empty());
            assert_eq!(
                restored
                    .unacknowledged_events()
                    .await
                    .unwrap()
                    .iter()
                    .filter(
                        |e| matches!(e, AppEvent::DeliveryUnknown { msg_id, .. } if msg_id == id)
                    )
                    .count(),
                1
            );
        }
    })
    .await;
}

#[tokio::test]
async fn test_append_records_hold_on_an_unavailable_read_and_an_unregistered_policy() {
    Box::pin(async {
        let mut setup = Sending::new().await;
        let id = setup.signed.msg_id();
        let from = setup.pair.router.log().len();
        setup.pair.alice.switch().fail_next(Fault::Unreachable {
            path: "/records/".into(),
            after: 0,
        });
        let held = setup.wallet.flush_message(id).await.unwrap();
        assert!(matches!(held, Some(Delivery::Queued { .. })), "{held:?}");
        assert_eq!(requests(&setup.pair, from), setup.keys);
        let mut unregistered = Gate::new();
        unregistered.collections[1].policy.permanent = None;
        let mut repeated = Gate::new();
        repeated.collections[1] = repeated.collections[0].clone();
        let mut over_limit = Gate::new();
        over_limit
            .collections
            .push(over_limit.collections[1].clone());
        for invalid in [unregistered, repeated, over_limit] {
            *setup.protocol.append_gate.lock().unwrap() = Some(Arc::new(invalid));
            let from = setup.pair.router.log().len();
            setup.wallet.flush_message(id).await.unwrap();
            assert!(requests(&setup.pair, from).is_empty());
        }
        assert_eq!(
            setup.wallet.queued_messages("sample").await.unwrap().len(),
            1
        );
        assert_eq!(
            setup
                .pair
                .bob
                .switch()
                .entries_from(&setup.pair.alice.identity().public()),
            0
        );
    })
    .await;
}

#[tokio::test]
async fn test_append_records_withdraw_before_any_append_reports_definite_non_delivery() {
    Box::pin(async {
        let mut setup = Sending::new().await;
        let id = setup.signed.msg_id();
        let completed = setup.gate.targets(id.as_bytes())[1].clone();
        setup
            .wallet
            .put_record(&completed, &value(&[id]), vec![])
            .await
            .unwrap();
        let from = setup.pair.router.log().len();
        setup.wallet.flush_message(id).await.unwrap();
        assert_eq!(requests(&setup.pair, from), setup.keys);
        assert!(
            setup
                .wallet
                .queued_messages("sample")
                .await
                .unwrap()
                .is_empty()
        );
        let events = setup.wallet.unacknowledged_events().await.unwrap();
        assert!(events.iter().any(|e| matches!(
            e, AppEvent::MessageUndelivered { msg_id, resend: false, .. } if msg_id == id
        )));
        assert!(!events.iter().any(|e| matches!(
            e, AppEvent::DeliveryUnknown { msg_id, .. } if msg_id == id
        )));
        assert_eq!(
            setup
                .pair
                .bob
                .switch()
                .entries_from(&setup.pair.alice.identity().public()),
            0
        );
    })
    .await;
}

#[tokio::test]
async fn test_append_records_rechecks_a_local_hold_after_the_reads() {
    Box::pin(async {
        let mut setup = Sending::new().await;
        let from = setup.pair.router.log().len();
        let router = setup.pair.router.clone();
        let last_read = format!("/records/{}", setup.keys[1]);
        *setup.protocol.delivery_check.lock().unwrap() = Some(Arc::new(move |_| {
            Ok(!router
                .log()
                .iter()
                .skip(from)
                .any(|line| line.ends_with(&last_read)))
        }));
        let status = setup
            .wallet
            .flush_message(setup.signed.msg_id())
            .await
            .unwrap();
        assert!(matches!(status, Some(Delivery::Queued { .. })));
        assert_eq!(requests(&setup.pair, from), setup.keys);
        assert!(setup.gate.observed.lock().unwrap().is_empty());
        assert_eq!(
            setup.wallet.queued_messages("sample").await.unwrap().len(),
            1
        );
    })
    .await;
}
