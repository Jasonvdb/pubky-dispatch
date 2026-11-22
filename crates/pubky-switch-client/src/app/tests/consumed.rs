//! Atomic local completion without a processed pair (Switch spec 11).

use super::*;
use crate::app::state::key;
use crate::app::{MAX_STEP_LOCAL_BYTES, ParkReason, ReceiveContext, StoreFailure};
use crate::error::StoreError;
use crate::store::{Fault as StoreFault, FaultStore};
use crate::testing::Fault;
use pubky_switch_core::records::DAY_MS;

#[derive(Clone, Copy)]
enum Mode {
    Consume,
    Apply,
    Retry,
    Pass,
}

struct Consuming {
    sample: SampleProtocol,
    mode: Mutex<Mode>,
    calls: Mutex<Vec<(String, bool, bool)>>,
    forgets: Mutex<Vec<Result<bool, crate::app::AppError>>>,
}

impl Consuming {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            sample: SampleProtocol::default(),
            mode: Mutex::new(Mode::Consume),
            calls: Mutex::new(Vec::new()),
            forgets: Mutex::new(Vec::new()),
        })
    }

    fn set(&self, mode: Mode) {
        *self.mode.lock().unwrap() = mode;
    }

    fn calls(&self, id: &str) -> usize {
        self.calls
            .lock()
            .unwrap()
            .iter()
            .filter(|(m, _, _)| m == id)
            .count()
    }
}

impl Protocol for Consuming {
    fn name(&self) -> String {
        "sample".into()
    }
    fn has_keys(&self, scope: &str) -> bool {
        self.sample.has_keys(scope)
    }
    fn sent_between_own_apps(&self, kind: &str) -> bool {
        self.sample.sent_between_own_apps(kind)
    }
    fn check_scopes(&self, m: &Message, s: &AppCert, o: &AppCert) -> Result<(), String> {
        self.sample.check_scopes(m, s, o)
    }
    fn accepts(&self, cert: &AppCert) -> Vec<String> {
        self.sample.accepts(cert)
    }
    fn check_body(&self, m: &ReceivedMessage) -> Result<(), String> {
        self.sample.check_body(m)
    }
    fn resend_needed(&self, needed: &ResendNeeded) -> Result<Vec<LocalWrite>, StoreFailure> {
        self.sample.resend_needed(needed)
    }
    fn missed(&self, missed: &MissedEntries) -> Result<Vec<LocalWrite>, StoreFailure> {
        self.sample.missed(missed)
    }
    fn receive(&self, m: &ReceivedMessage, cx: &mut ReceiveContext<'_>) -> Outcome {
        self.calls
            .lock()
            .unwrap()
            .push((m.message.msg_id.clone(), m.parked, m.released));
        if m.message.body.get("park").is_some() {
            return Outcome::Retry(StoreFailure::of_entry(StoreError::Corrupt));
        }
        match *self.mode.lock().unwrap() {
            Mode::Apply => return self.sample.receive(m, cx),
            Mode::Retry => return Outcome::Retry(StoreFailure::of_entry(StoreError::Corrupt)),
            Mode::Consume | Mode::Pass => {}
        }
        if let Some(id) = m.message.body.get("forget").and_then(Value::as_str) {
            let sender = if m.message.body.get("other_sender").is_some() {
                [0; 32]
            } else {
                m.sender
            };
            self.forgets
                .lock()
                .unwrap()
                .push(cx.forget_processed(sender, id));
            cx.local(LocalWrite::Delete {
                key: format!("notes/{id}").into_bytes(),
            })
            .unwrap();
        }
        if let Some(bytes) = m.message.body.get("bytes").and_then(Value::as_u64) {
            // A refused write poisons the whole local decision even if the protocol ignores it.
            let _ = cx.local(LocalWrite::Put {
                key: b"sized".to_vec(),
                value: vec![1; bytes as usize],
            });
        } else {
            let count = cx
                .local_get(b"consumed")
                .unwrap()
                .map_or(0, |bytes| bytes[0]);
            cx.local(LocalWrite::Put {
                key: b"consumed".to_vec(),
                value: vec![count + 1],
            })
            .unwrap();
            // An app-state-looking key still belongs to this protocol's local namespace.
            cx.local(LocalWrite::Put {
                key: key::CURSOR.as_bytes().to_vec(),
                value: b"local".to_vec(),
            })
            .unwrap();
        }
        // This operation must never accompany the local completion.
        cx.op(
            Vec::new(),
            OpKind::AllowPut {
                pubky: m.sender,
                reason: PeerReason::Reply,
            },
        )
        .unwrap();
        match *self.mode.lock().unwrap() {
            Mode::Pass => Outcome::Pass,
            _ => Outcome::Consume,
        }
    }
}

async fn wallet(w: &World, p: &Arc<Consuming>, store: Arc<dyn StateStore>) -> App {
    let request = w.approve(&app_keys("wallet"), &["sample-a"]);
    let mut app = App::join(w.env_on(store), p.clone(), World::config(), request)
        .await
        .unwrap();
    app.receive(None).await.unwrap();
    app
}

fn note(w: &World, app: &App, body: Value) -> (u64, Message) {
    w.switch
        .send(
            &w.bob,
            &w.bob_keys,
            &w.bob_cert,
            "sample.note",
            body,
            &[app.app_id()],
        )
        .unwrap()
}

fn resend(w: &World, app: &App, m: &Message) -> u64 {
    w.switch
        .send_plaintext(
            w.bob.public(),
            &w.bob_cert,
            &m.sign(&w.bob_keys).unwrap(),
            &[app.app_id()],
        )
        .unwrap()
}

async fn pair(app: &App, w: &World, m: &Message) -> bool {
    app.reader()
        .exists(&key::processed(&w.bob.public(), &m.msg_id))
        .await
        .unwrap()
}

async fn consumed(app: &App) -> Option<Vec<u8>> {
    app.protocol_get("sample", b"consumed").await.unwrap()
}

#[tokio::test]
async fn test_consume_feed_locals_forgets_and_resend() {
    let w = World::new();
    let p = Consuming::new();
    let mut app = wallet(&w, &p, w.store.clone()).await;
    p.set(Mode::Apply);
    let (_, old) = w.note(app.app_id(), "old");
    app.receive(None).await.unwrap();
    assert!(pair(&app, &w, &old).await);
    let effects = w.effects();
    p.set(Mode::Consume);
    let (_, current) = note(&w, &app, json!({"text":"consume", "forget":old.msg_id}));
    let copy = resend(&w, &app, &current);
    app.receive(None).await.unwrap();
    assert!(
        !pair(&app, &w, &current).await,
        "the consumed pair is not recorded"
    );
    assert_eq!(
        consumed(&app).await,
        Some(vec![2]),
        "both local decisions commit"
    );
    assert!(!pair(&app, &w, &old).await, "the prior pair is forgotten");
    assert_eq!(
        app.protocol_get("sample", format!("notes/{}", old.msg_id).as_bytes())
            .await
            .unwrap(),
        None
    );
    assert!(app.cursor().seq >= copy);
    assert_eq!(
        app.protocol_get("sample", key::CURSOR.as_bytes())
            .await
            .unwrap(),
        Some(b"local".to_vec())
    );
    assert_eq!(
        w.effects(),
        effects,
        "context remote operations are discarded"
    );
    assert_eq!(p.calls(&current.msg_id), 2);
    app.flush_cursor().await.unwrap();
    let me = app.app_id();
    drop(app);
    let mut app = App::load(w.env(), p.clone(), World::config(), me)
        .await
        .unwrap();
    resend(&w, &app, &current);
    app.receive(None).await.unwrap();
    assert_eq!(
        consumed(&app).await,
        Some(vec![3]),
        "a re-send after restart is delivered"
    );
    assert_eq!(w.effects(), effects);
}

#[tokio::test]
async fn test_consume_stored_retry_retires_atomically_and_preserves_duties() {
    let w = World::new();
    let p = Consuming::new();
    let mut app = wallet(&w, &p, w.store.clone()).await;
    p.set(Mode::Retry);
    let (seq, message) = w.note(app.app_id(), "stored");
    app.receive(None).await.unwrap();
    app.receive(None).await.unwrap();
    let id = app.stored_id_at(seq).unwrap();
    assert!(app.state.stored_retries.contains_key(&id));
    let duties = app.reader().scan_raw("duty/").await.unwrap();
    p.set(Mode::Pass);
    app.receive(None).await.unwrap();
    assert_eq!(app.stored_id_at(seq), Some(id));
    assert_eq!(consumed(&app).await, None, "Pass still discards locals");
    p.set(Mode::Consume);
    app.receive(None).await.unwrap();
    assert_eq!(consumed(&app).await, Some(vec![1]));
    assert_eq!(
        app.stored_id_at(seq),
        None,
        "the consumed stored input is retired"
    );
    assert!(!app.state.stored_retries.contains_key(&id));
    assert!(!app.reader().exists(&key::stored_retry(id)).await.unwrap());
    assert!(!app.reader().exists(&key::parked(id)).await.unwrap());
    assert!(!pair(&app, &w, &message).await);
    assert_eq!(app.reader().scan_raw("duty/").await.unwrap(), duties);
    resend(&w, &app, &message);
    app.receive(None).await.unwrap();
    assert_eq!(consumed(&app).await, Some(vec![2]));
    assert_eq!(w.effects(), 0);
}

#[tokio::test]
async fn test_consume_unanswered_uncertain_and_released_input() {
    let w = World::new();
    let p = Consuming::new();
    let mut app = wallet(&w, &p, w.store.clone()).await;
    p.set(Mode::Apply);
    let (seq, message) = w.note(app.app_id(), "unanswered");
    w.switch.fail_next(Fault::Unanswered {
        path: "ops".into(),
        after: 0,
    });
    assert!(app.receive(None).await.is_err());
    assert!(app.state.pending_effect.is_some());
    p.set(Mode::Consume);
    w.switch.fail_next(Fault::Unanswered {
        path: "ops".into(),
        after: 0,
    });
    assert!(app.receive(None).await.is_err());
    assert_eq!(
        p.calls(&message.msg_id),
        1,
        "unanswered input is not offered again"
    );
    assert_eq!(consumed(&app).await, None);
    w.clock.advance_ms(31 * DAY_MS);
    app.receive(None).await.unwrap();
    let id = app.stored_id_at(seq).unwrap();
    let stored = app
        .parked_entries()
        .await
        .unwrap()
        .into_iter()
        .find(|e| e.stored_id == id)
        .unwrap();
    assert_eq!(stored.reason, ParkReason::Uncertain);
    assert_eq!(
        p.calls(&message.msg_id),
        1,
        "uncertain input is not offered"
    );
    let duties = app.unacknowledged_events().await.unwrap();
    assert!(!duties.is_empty());
    assert_eq!(
        w.effects(),
        0,
        "the host can establish the effect was not applied"
    );
    app.release_parked(id, &stored.hash).await.unwrap();
    app.receive(None).await.unwrap();
    assert_eq!(
        consumed(&app).await,
        Some(vec![1]),
        "eligible release can finish locally"
    );
    assert_eq!(app.stored_id_at(seq), None, "the released input is retired");
    assert!(!pair(&app, &w, &message).await);
    assert_eq!(
        app.unacknowledged_events().await.unwrap(),
        duties,
        "owed duties survive retirement"
    );
    assert_eq!(
        p.calls.lock().unwrap().last(),
        Some(&(message.msg_id.clone(), true, true))
    );
}

#[tokio::test]
async fn test_consume_commit_failure_keeps_locals_pairs_and_stored_retry_together() {
    for stored in [false, true] {
        let w = World::new();
        let p = Consuming::new();
        let fault = Arc::new(FaultStore::new(w.store.clone(), StoreFault::None));
        let mut app = wallet(&w, &p, fault.clone()).await;
        p.set(Mode::Apply);
        let (_, old) = w.note(app.app_id(), "old");
        app.receive(None).await.unwrap();
        if stored {
            p.set(Mode::Retry);
        } else {
            p.set(Mode::Consume);
        }
        let (seq, current) = note(&w, &app, json!({"text":"consume", "forget":old.msg_id}));
        if stored {
            app.receive(None).await.unwrap();
            app.receive(None).await.unwrap();
        }
        let id = app.stored_id_at(seq);
        p.set(Mode::Consume);
        fault.fail_put_once(b"p/sample/consumed");
        assert!(app.receive(None).await.is_err());
        assert_eq!(consumed(&app).await, None);
        assert!(
            pair(&app, &w, &old).await,
            "failed completion keeps the prior pair"
        );
        assert!(!pair(&app, &w, &current).await);
        if let Some(id) = id {
            assert!(app.reader().exists(&key::parked(id)).await.unwrap());
            assert!(app.reader().exists(&key::stored_retry(id)).await.unwrap());
        } else {
            assert!(
                app.reader()
                    .get::<super::super::state::Cursor>(key::CURSOR)
                    .await
                    .unwrap()
                    .unwrap()
                    .seq
                    < seq
            );
        }
        // The same App reloads before retrying after a failed commit.
        app.receive(None).await.unwrap();
        assert_eq!(
            consumed(&app).await,
            Some(vec![1]),
            "the local decision is retried"
        );
        assert!(!pair(&app, &w, &old).await);
        assert!(!pair(&app, &w, &current).await);
        assert_eq!(app.stored_id_at(seq), None);
        assert!(app.no_retries());
    }
}

#[tokio::test]
async fn test_consume_local_bound_is_atomic() {
    for over in [false, true] {
        let w = World::new();
        let p = Consuming::new();
        let mut app = wallet(&w, &p, w.store.clone()).await;
        let bytes = MAX_STEP_LOCAL_BYTES - b"sized".len() - crate::app::LOCAL_WRITE_OVERHEAD_BYTES
            + usize::from(over);
        let (seq, message) = note(&w, &app, json!({"text":"sized", "bytes":bytes}));
        app.receive(None).await.unwrap();
        let value = app.protocol_get("sample", b"sized").await.unwrap();
        if over {
            assert_eq!(
                value, None,
                "an over-bound decision commits no partial locals"
            );
            let id = app
                .stored_id_at(seq)
                .expect("over-bound input remains stored");
            assert_eq!(app.state.parked[&id].reason, ParkReason::EffectTooLarge);
        } else {
            assert_eq!(value.unwrap().len(), bytes, "the exact bound commits");
            assert!(app.stored_id_at(seq).is_none());
        }
        assert!(!pair(&app, &w, &message).await);
        assert_eq!(w.effects(), 0);
    }
}

/// Fail exactly the completion commit, before applying it or after it is durable.
struct CompletionFailure {
    inner: Arc<MemoryStore>,
    after: bool,
    fired: std::sync::atomic::AtomicBool,
}

impl StateStore for CompletionFailure {
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
        use std::sync::atomic::Ordering;
        let completion = batch.writes().iter().any(
            |w| matches!(w, crate::store::Write::Put { key, .. } if key == b"p/sample/consumed"),
        );
        if completion && !self.fired.swap(true, Ordering::SeqCst) {
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
    ) -> Result<crate::store::AcquireOutcome, crate::store::StoreError> {
        self.inner.acquire(ns, owner)
    }

    fn commit_if(
        &self,
        ns: &str,
        owner: crate::store::StoreOwner,
        batch: crate::store::WriteBatch,
    ) -> Result<crate::store::CommitOutcome, crate::store::StoreError> {
        use std::sync::atomic::Ordering;
        let completion = batch.writes().iter().any(
            |w| matches!(w, crate::store::Write::Put { key, .. } if key == b"p/sample/consumed"),
        );
        if completion && !self.fired.swap(true, Ordering::SeqCst) {
            if self.after {
                self.inner.commit_if(ns, owner, batch)?;
                return Err(StoreError::Unknown);
            }
            return Err(StoreError::Unavailable);
        }
        self.inner.commit_if(ns, owner, batch)
    }
}

#[tokio::test]
async fn test_consume_crash_before_and_after_commit_reopens_one_complete_decision() {
    for stored in [false, true] {
        for after in [false, true] {
            let w = World::new();
            let p = Consuming::new();
            let failing = Arc::new(CompletionFailure {
                inner: w.store.clone(),
                after,
                fired: false.into(),
            });
            let mut app = wallet(&w, &p, failing.clone()).await;
            p.set(Mode::Apply);
            let (_, old) = w.note(app.app_id(), "old");
            app.receive(None).await.unwrap();
            p.set(if stored { Mode::Retry } else { Mode::Consume });
            let (seq, current) = note(&w, &app, json!({"text":"consume", "forget":old.msg_id}));
            if stored {
                app.receive(None).await.unwrap();
                app.receive(None).await.unwrap();
            }
            let id = app.stored_id_at(seq);
            let me = app.app_id();
            p.set(Mode::Consume);
            assert!(app.receive(None).await.is_err());
            assert!(failing.fired.load(std::sync::atomic::Ordering::SeqCst));
            drop(app);
            let mut app = App::load(w.env(), p.clone(), World::config(), me)
                .await
                .unwrap();
            assert_eq!(consumed(&app).await.is_some(), after);
            assert_eq!(
                pair(&app, &w, &old).await,
                !after,
                "crash keeps the pair with the local decision"
            );
            assert!(!pair(&app, &w, &current).await);
            if let Some(id) = id {
                assert_eq!(app.reader().exists(&key::parked(id)).await.unwrap(), !after);
                assert_eq!(
                    app.reader().exists(&key::stored_retry(id)).await.unwrap(),
                    !after
                );
            } else {
                assert_eq!(app.cursor().seq >= seq, after);
            }
            app.receive(None).await.unwrap();
            assert_eq!(
                consumed(&app).await,
                Some(vec![1]),
                "one complete decision survives restart"
            );
            assert!(!pair(&app, &w, &old).await);
            assert!(!pair(&app, &w, &current).await);
            assert_eq!(app.stored_id_at(seq), None);
            resend(&w, &app, &current);
            app.receive(None).await.unwrap();
            assert_eq!(consumed(&app).await, Some(vec![2]));
        }
    }
}

#[tokio::test]
async fn test_consume_forget_without_pair_keeps_stored_input_and_matches_sender() {
    let w = World::new();
    let p = Consuming::new();
    let mut app = wallet(&w, &p, w.store.clone()).await;
    p.set(Mode::Apply);
    let (_, prior) = w.note(app.app_id(), "prior");
    app.receive(None).await.unwrap();
    p.set(Mode::Consume);
    let (_, wrong) = note(
        &w,
        &app,
        json!({"text":"consume", "forget":prior.msg_id, "other_sender":true}),
    );
    app.receive(None).await.unwrap();
    assert_eq!(p.forgets.lock().unwrap().last(), Some(&Ok(false)));
    assert!(
        pair(&app, &w, &prior).await,
        "another sender does not select this pair"
    );
    assert!(!pair(&app, &w, &wrong).await);
    let (seq, held) = note(&w, &app, json!({"text":"held", "park":true}));
    app.receive(None).await.unwrap();
    let id = app.stored_id_at(seq).unwrap();
    let (_, current) = note(&w, &app, json!({"text":"consume", "forget":held.msg_id}));
    app.receive(None).await.unwrap();
    assert_eq!(
        p.forgets.lock().unwrap().last(),
        Some(&Ok(false)),
        "an absent prior pair permits the current local decision"
    );
    assert_eq!(
        consumed(&app).await,
        Some(vec![2]),
        "the independent current input completes"
    );
    assert!(!pair(&app, &w, &current).await);
    assert_eq!(
        app.stored_id_at(seq),
        Some(id),
        "a prior unprocessed input remains stored"
    );
    assert!(app.state.stored_retries.contains_key(&id));
}

#[tokio::test]
async fn test_consume_requires_authenticated_input_and_preserves_applied_identity() {
    let w = World::new();
    let p = Consuming::new();
    let mut app = wallet(&w, &p, w.store.clone()).await;
    let (_, message) = w.note(app.app_id(), "valid");
    let signed = message.sign(&w.bob_keys).unwrap();
    let mut signature = signed.signature();
    signature[0] ^= 1;
    let forged = pubky_switch_core::message::MessagePlaintext::from_parts(
        signed.sender_app_id(),
        signature,
        signed.json().to_vec(),
    )
    .unwrap();
    w.switch
        .send_plaintext(w.bob.public(), &w.bob_cert, &forged, &[app.app_id()])
        .unwrap();
    app.receive(None).await.unwrap();
    assert_eq!(
        p.calls(&message.msg_id),
        1,
        "the bad signature never reaches the protocol"
    );
    assert_eq!(consumed(&app).await, Some(vec![1]));
    assert!(!pair(&app, &w, &message).await);
    p.set(Mode::Apply);
    resend(&w, &app, &message);
    app.receive(None).await.unwrap();
    assert!(pair(&app, &w, &message).await);
    p.set(Mode::Consume);
    resend(&w, &app, &message);
    app.receive(None).await.unwrap();
    assert_eq!(
        consumed(&app).await,
        Some(vec![1]),
        "an applied identity is not offered for consumption"
    );
    assert_eq!(p.calls(&message.msg_id), 2);
    assert_eq!(w.effects(), 1);
}
