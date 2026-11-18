//! Every individually valid callback fits, however many protocols share its notice.

use super::*;
use crate::store::{Fault as StoreFault, FaultStore};

const NAMES: [&str; 9] = [
    "tasks", "chat", "alpha", "bravo", "charlie", "delta", "echo", "foxtrot", "golf",
];

struct Many {
    pair: Pair,
    protocols: Vec<Arc<Named>>,
    set: ProtocolSet,
    app: App,
    manager: App,
}

impl Many {
    async fn new(count: usize, gap: bool, retry: bool) -> Self {
        Box::pin(Self::with_last_size(
            count,
            gap,
            retry,
            MAX_STEP_LOCAL_BYTES,
        ))
        .await
    }

    async fn with_last_size(count: usize, gap: bool, retry: bool, last: usize) -> Self {
        let pair = Pair::new();
        let protocols: Vec<_> = NAMES[..count]
            .iter()
            .enumerate()
            .map(|(index, name)| {
                let bytes = if index + 1 == count {
                    last
                } else {
                    MAX_STEP_LOCAL_BYTES
                };
                Arc::new(Named {
                    gap_bytes: if gap { bytes } else { 0 },
                    notice_bytes: if gap { 0 } else { bytes },
                    keep_gap: true,
                    failing_deny: Mutex::new(u32::from(retry)),
                    failing_missed: Mutex::new(u32::from(retry)),
                    ..named(name)
                })
            })
            .collect();
        let set = ProtocolSet::new(
            protocols
                .iter()
                .map(|p| p.clone() as Arc<dyn Protocol>)
                .collect(),
        )
        .unwrap();
        let app = Box::pin(App::join(
            pair.env(),
            set.clone(),
            World::config(),
            pair.approve("wallet", &[Permission::ListsRead]),
        ))
        .await
        .unwrap();
        let manager = Box::pin(manager(&pair)).await;
        Self {
            pair,
            protocols,
            set,
            app,
            manager,
        }
    }

    async fn reload(&mut self) {
        self.app = App::load(
            self.pair.env(),
            self.set.clone(),
            World::config(),
            self.app.app_id(),
        )
        .await
        .unwrap();
    }

    async fn fault(&mut self, fault: StoreFault) -> Arc<FaultStore> {
        let store = Arc::new(FaultStore::new(self.pair.store.clone(), fault));
        self.app = App::load(
            self.pair.w.env_on(store.clone() as Arc<dyn StateStore>),
            self.set.clone(),
            World::config(),
            self.app.app_id(),
        )
        .await
        .unwrap();
        store
    }

    async fn gap_is(&mut self, denied: &[[u8; 32]]) {
        read(&mut self.app, 3).await;
        assert!(
            !self
                .app
                .reader()
                .exists(crate::app::feed::DENY_GAP)
                .await
                .unwrap()
        );
        assert!(
            self.app
                .reader()
                .exists(crate::app::admission::LISTS_AT)
                .await
                .unwrap()
        );
        assert_eq!(self.app.lists_copy().await.unwrap().deny, denied);
        for protocol in &self.protocols {
            let bytes = self
                .app
                .protocol_get(&protocol.name, b"gap")
                .await
                .unwrap()
                .unwrap();
            let (read, actual): (bool, Vec<[u8; 32]>) = serde_json::from_slice(&bytes).unwrap();
            assert!(read);
            assert_eq!(actual, denied);
        }
    }

    fn unopenable(&self) -> u64 {
        use pubky_switch_core::envelope::Recipient;
        use pubky_switch_core::keys::ReceiveKey;
        use pubky_switch_core::message::Sender;
        let key = ReceiveKey::from_secret(9, [45; 32]);
        let message = Message::new(
            "tasks.item",
            Sender::of_app(self.pair.w.bob.public(), &self.pair.w.bob_keys),
            self.pair.w.alice.public(),
            self.pair.w.clock.now_ms(),
            vec![],
            serde_json::Map::new(),
        )
        .unwrap();
        let sealed = message
            .sign(&self.pair.w.bob_keys)
            .unwrap()
            .seal(
                &self.pair.w.alice.public(),
                &[Recipient::new(key.public)],
                false,
            )
            .unwrap();
        self.pair.w.switch.send_envelope(
            self.pair.w.bob.public(),
            &self.pair.w.bob_cert,
            sealed,
            &[self.app.app_id()],
        )
    }
}

#[tokio::test]
async fn test_callback_batches_valid_gaps_complete_at_the_transaction_boundary() {
    for count in [2, 7, 8, 9] {
        let mut c = Box::pin(Many::new(count, true, false)).await;
        c.app.receive(None).await.unwrap();
        c.reload().await;
        assert!(
            !c.app
                .reader()
                .exists(crate::app::feed::DENY_GAP)
                .await
                .unwrap()
        );
        assert!(
            c.app
                .reader()
                .exists(crate::app::admission::LISTS_AT)
                .await
                .unwrap()
        );
        for protocol in &c.protocols {
            assert_eq!(protocol.gaps.lock().unwrap().len(), 1);
            assert!(
                c.app
                    .protocol_get(&protocol.name, b"gap")
                    .await
                    .unwrap()
                    .is_some()
            );
        }
    }
}

async fn notices(deny: bool, retry: bool) {
    let mut c = Box::pin(Many::new(9, false, retry)).await;
    c.app.receive(None).await.unwrap();
    let seq = if deny {
        c.manager.deny(&[83; 32]).await.unwrap();
        c.pair.w.switch.seq()
    } else {
        let now = c.pair.w.clock.now_ms();
        c.pair.w.switch.push_missed(1, now, now)
    };
    c.app.receive(None).await.unwrap();
    c.reload().await;
    read(&mut c.app, 2).await;
    assert_eq!(c.app.owed_protocol_calls().await.unwrap(), 0);
    assert!(c.app.cursor().seq >= seq);
    for protocol in &c.protocols {
        if deny {
            assert_eq!(*protocol.denies.lock().unwrap(), [[83; 32]]);
            assert_eq!(
                c.app.protocol_get(&protocol.name, b"deny").await.unwrap(),
                Some(vec![1])
            );
        } else {
            assert_eq!(*protocol.missed.lock().unwrap(), [seq]);
            assert_eq!(
                c.app
                    .protocol_get(&protocol.name, format!("missed/{seq}").as_bytes())
                    .await
                    .unwrap(),
                Some(b"1".to_vec())
            );
        }
    }
}

#[tokio::test]
async fn test_callback_batches_valid_denies_complete() {
    Box::pin(notices(true, false)).await;
}

#[tokio::test]
async fn test_callback_batches_valid_missed_notices_complete() {
    Box::pin(notices(false, false)).await;
}

#[tokio::test]
async fn test_callback_batches_valid_retained_notices_complete() {
    for deny in [false, true] {
        Box::pin(notices(deny, true)).await;
    }
}

#[tokio::test]
async fn test_callback_batches_valid_resend_notices_complete() {
    let mut c = Box::pin(Many::new(9, false, false)).await;
    c.app.receive(None).await.unwrap();
    let seq = c.unopenable();
    c.app.receive(None).await.unwrap();
    c.reload().await;
    c.app.receive(None).await.unwrap();
    assert!(c.app.cursor().seq >= seq);
    for protocol in &c.protocols {
        assert_eq!(*protocol.resends.lock().unwrap(), 1);
        assert_eq!(
            c.app.protocol_get(&protocol.name, b"resend").await.unwrap(),
            Some(vec![1])
        );
    }
}

async fn pending_notice(deny: bool, retry: bool) -> (Many, u64) {
    let mut c = Box::pin(Many::new(9, false, retry)).await;
    c.app.receive(None).await.unwrap();
    // Pre-existing page work must commit with its own progress before callbacks split.
    c.pair.send(c.app.app_id(), "tasks.item");
    let seq = if deny {
        c.manager.deny(&[83; 32]).await.unwrap();
        c.pair.w.switch.seq()
    } else {
        let now = c.pair.w.clock.now_ms();
        c.pair.w.switch.push_missed(1, now, now)
    };
    if retry {
        c.app.receive(None).await.unwrap();
    }
    c.pair.send(c.app.app_id(), "chat.item");
    (c, seq)
}

#[tokio::test]
async fn test_callback_batches_crashes_preserve_completed_owners_and_the_barrier() {
    for (deny, retry) in [(true, false), (false, false), (true, true), (false, true)] {
        let count = {
            let (mut c, _) = Box::pin(pending_notice(deny, retry)).await;
            let store = c.fault(StoreFault::None).await;
            c.app.receive(None).await.unwrap();
            store.commits()
        };
        assert!(count > 9);
        for nth in 1..=count {
            for fault in [
                StoreFault::FailBefore(nth),
                StoreFault::FailAfter(nth),
                StoreFault::StopBefore(nth),
                StoreFault::StopAfter(nth),
            ] {
                let (mut c, seq) = Box::pin(pending_notice(deny, retry)).await;
                let store = c.fault(fault).await;
                let _ = c.app.receive(None).await;
                assert!(store.commits() >= nth, "{fault:?}");
                c.reload().await;
                let key = if deny {
                    "deny".to_owned()
                } else {
                    format!("missed/{seq}")
                };
                let mut completed = Vec::new();
                for protocol in &c.protocols {
                    if c.app
                        .protocol_get(&protocol.name, key.as_bytes())
                        .await
                        .unwrap()
                        .is_some()
                    {
                        let calls = if deny {
                            protocol.denies.lock().unwrap().len()
                        } else {
                            protocol.missed.lock().unwrap().len()
                        };
                        completed.push((protocol.clone(), calls));
                    }
                }
                if !deny && !completed.is_empty() && c.app.cursor().seq < seq {
                    assert!(
                        c.app
                            .reader()
                            .exists(crate::app::records::LIST_DUE)
                            .await
                            .unwrap()
                    );
                }
                if deny && completed.len() < c.protocols.len() {
                    assert!(
                        !c.app
                            .reader()
                            .exists(&crate::app::admission::deny_key(&[83; 32]))
                            .await
                            .unwrap()
                    );
                    assert!(c.protocols[1].received.lock().unwrap().is_empty());
                }
                read(&mut c.app, 3).await;
                assert_eq!(c.app.owed_protocol_calls().await.unwrap(), 0);
                assert!(c.app.cursor().seq >= seq);
                for (protocol, calls) in completed {
                    assert_eq!(
                        if deny {
                            protocol.denies.lock().unwrap().len()
                        } else {
                            protocol.missed.lock().unwrap().len()
                        },
                        calls,
                        "{}: {fault:?}",
                        protocol.name
                    );
                }
                for protocol in &c.protocols {
                    assert!(
                        c.app
                            .protocol_get(&protocol.name, key.as_bytes())
                            .await
                            .unwrap()
                            .is_some()
                    );
                }
            }
        }
    }
}

async fn pending_gap() -> Many {
    let mut c = Box::pin(Many::new(9, true, false)).await;
    c.app.receive(None).await.unwrap();
    c.app.allow_list().await.unwrap();
    c.manager.deny(&[83; 32]).await.unwrap();
    c
}

#[tokio::test]
async fn test_callback_batches_interrupted_gap_restarts_from_one_fresh_answer() {
    let count = {
        let mut c = Box::pin(pending_gap()).await;
        let store = c.fault(StoreFault::None).await;
        c.app.receive(None).await.unwrap();
        store.commits()
    };
    assert!(count > 9);
    for nth in 1..=count {
        for fault in [
            StoreFault::FailBefore(nth),
            StoreFault::FailAfter(nth),
            StoreFault::StopBefore(nth),
            StoreFault::StopAfter(nth),
        ] {
            let mut c = Box::pin(pending_gap()).await;
            let store = c.fault(fault).await;
            let _ = c.app.receive(None).await;
            assert!(store.commits() >= nth, "{fault:?}");
            c.reload().await;
            let owed = c
                .app
                .reader()
                .exists(crate::app::feed::DENY_GAP)
                .await
                .unwrap();
            let known = c
                .app
                .reader()
                .exists(crate::app::admission::LISTS_AT)
                .await
                .unwrap();
            if !owed && known {
                assert_eq!(c.app.lists_copy().await.unwrap().deny, [[83; 32]]);
                for protocol in &c.protocols {
                    let bytes = c
                        .app
                        .protocol_get(&protocol.name, b"gap")
                        .await
                        .unwrap()
                        .unwrap();
                    let baseline: (bool, Vec<[u8; 32]>) = serde_json::from_slice(&bytes).unwrap();
                    assert_eq!(baseline, (true, vec![[83; 32]]));
                }
            }
            c.manager.undeny(&[83; 32]).await.unwrap();
            c.manager.deny(&[84; 32]).await.unwrap();
            // An unfinished pass refreshes itself. A finished pass needs a new gap to
            // establish another whole baseline instead of following individual changes.
            if !owed && known {
                c.app.allow_list().await.unwrap();
            }
            c.gap_is(&[[84; 32]]).await;
        }
    }
}

#[tokio::test]
async fn test_callback_batches_partial_gap_restores_every_protocol_from_current_lists() {
    for fresh in [false, true] {
        let mut c = Box::pin(pending_gap()).await;
        *c.protocols[4].failing_gap.lock().unwrap() = 1;
        c.pair.send(c.app.app_id(), "tasks.item");
        assert!(c.app.receive(None).await.unwrap().stopped);
        assert!(c.protocols[0].received.lock().unwrap().is_empty());
        assert!(
            c.app
                .reader()
                .exists(crate::app::feed::DENY_GAP)
                .await
                .unwrap()
        );
        assert!(c.app.lists_copy().await.unwrap().deny.is_empty());
        let backup = c.app.backup_layered().await.unwrap();
        c.manager.undeny(&[83; 32]).await.unwrap();
        c.manager.deny(&[84; 32]).await.unwrap();
        if fresh {
            c.pair.store = Arc::new(MemoryStore::new());
        }
        c.app = Box::pin(App::restore(
            c.pair.env(),
            c.set.clone(),
            World::config(),
            &backup,
        ))
        .await
        .unwrap();
        c.gap_is(&[[84; 32]]).await;
        assert_eq!(c.protocols[0].received.lock().unwrap().len(), 1);
    }
}

#[tokio::test]
async fn test_callback_batches_only_the_over_limit_response_is_refused() {
    for gap in [false, true] {
        let mut c = Box::pin(Many::with_last_size(
            9,
            gap,
            false,
            MAX_STEP_LOCAL_BYTES + 1,
        ))
        .await;
        c.app.receive(None).await.unwrap();
        if !gap {
            c.manager.deny(&[83; 32]).await.unwrap();
            c.app.receive(None).await.unwrap();
        }
        c.reload().await;
        let duties = crate::app::tests::pending_events(&mut c.app).await.unwrap();
        assert_eq!(
            duties
                .iter()
                .filter(|e| matches!(e, AppEvent::LocalWritesRefused { .. }))
                .count(),
            1
        );
        let key = if gap {
            b"gap".as_slice()
        } else {
            b"deny".as_slice()
        };
        for (index, protocol) in c.protocols.iter().enumerate() {
            assert_eq!(
                c.app
                    .protocol_get(&protocol.name, key)
                    .await
                    .unwrap()
                    .is_some(),
                index < 8
            );
        }
        assert!(
            !c.app
                .reader()
                .exists(crate::app::feed::DENY_GAP)
                .await
                .unwrap()
        );
        assert_eq!(c.app.owed_protocol_calls().await.unwrap(), 0);
    }
}

#[tokio::test]
async fn test_callback_batches_failed_gap_reloads_all_owners_from_the_new_answer() {
    let mut c = Box::pin(pending_gap()).await;
    *c.protocols[4].failing_gap.lock().unwrap() = 1;
    assert!(c.app.receive(None).await.unwrap().stopped);
    c.manager.undeny(&[83; 32]).await.unwrap();
    c.manager.deny(&[84; 32]).await.unwrap();
    c.reload().await;
    c.gap_is(&[[84; 32]]).await;
}

#[tokio::test]
async fn test_resend_callback_crash_keeps_the_first_feed_observation() {
    let mut c = Box::pin(Many::with_last_size(3, false, false, 1)).await;
    c.app.receive(None).await.unwrap();
    let store = c.fault(StoreFault::None).await;
    *c.protocols[2].retrying.lock().unwrap() = 2;
    let held = c.pair.send(c.app.app_id(), "alpha.item");
    let seq = c.unopenable();
    let observed_at = c.pair.w.clock.now_ms();
    store.fail_put_once(format!("p/{}/resend", NAMES[1]).as_bytes());
    assert!(c.app.receive(None).await.is_err());
    c.reload().await;
    assert!(c.app.cursor().seq < held && held < seq);
    assert!(c.app.state.held.contains_key(&held));
    assert!(c.app.state.asked.contains(&seq));
    assert_eq!(
        c.app.protocol_get(NAMES[0], b"resend").await.unwrap(),
        Some(vec![1])
    );
    let kept = c
        .app
        .state
        .held
        .get(&seq)
        .expect("first resend callback committed ahead of cursor without its feed observation");
    assert_eq!(kept.receipt.read_at_ms, observed_at);
    assert_eq!(kept.accepted_at_ms, observed_at);
}
