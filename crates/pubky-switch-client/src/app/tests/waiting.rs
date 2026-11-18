//! Protocol admission shares bounded custody with sender and key waiting.

use super::*;
use crate::app::state::key;
use crate::app::{
    AppBackup, AppEvent, DropReason, EntryReceipt, EventId, MAX_STEP_LOCAL_BYTES,
    MAX_UNVERIFIED_AGE_MS, ParkReason, ReceiveContext, StoreFailure, WaitingReason,
};
use crate::error::StoreError;
use crate::store::{Fault as StoreFault, FaultStore};
use std::sync::atomic::{AtomicBool, Ordering};

#[derive(Clone, Copy)]
enum Mode {
    Wait,
    Apply,
    Consume,
    Key(u64),
}

struct Admission {
    sample: SampleProtocol,
    mode: Mutex<Mode>,
    hold: AtomicBool,
    calls: Mutex<Vec<(String, EntryReceipt)>>,
    /// The body members it names opaque, which a host update may change.
    opaque: Mutex<Vec<crate::app::OpaqueRule>>,
}

impl Admission {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            sample: SampleProtocol::default(),
            mode: Mutex::new(Mode::Wait),
            hold: AtomicBool::new(false),
            calls: Mutex::new(Vec::new()),
            opaque: Mutex::new(Vec::new()),
        })
    }
    fn set(&self, mode: Mode) {
        *self.mode.lock().unwrap() = mode;
    }
    fn set_opaque(&self, members: &[&str]) {
        *self.opaque.lock().unwrap() = members
            .iter()
            .map(|member| crate::app::OpaqueRule {
                kind: None,
                member: (*member).into(),
            })
            .collect();
    }
}

impl Protocol for Admission {
    fn name(&self) -> String {
        "sample".into()
    }
    fn has_keys(&self, scope: &str) -> bool {
        self.sample.has_keys(scope)
    }
    fn sent_between_own_apps(&self, kind: &str) -> bool {
        self.sample.sent_between_own_apps(kind)
    }
    fn opaque_members(&self) -> Vec<crate::app::OpaqueRule> {
        self.opaque.lock().unwrap().clone()
    }
    fn check_scopes(&self, m: &Message, s: &AppCert, o: &AppCert) -> Result<(), String> {
        self.sample.check_scopes(m, s, o)
    }
    fn accepts(&self, c: &AppCert) -> Vec<String> {
        self.sample.accepts(c)
    }
    fn check_body(&self, m: &ReceivedMessage) -> Result<(), String> {
        self.sample.check_body(m)
    }
    fn missed(&self, m: &MissedEntries) -> Result<Vec<LocalWrite>, StoreFailure> {
        self.sample.missed(m)
    }
    fn resend_needed(&self, m: &ResendNeeded) -> Result<Vec<LocalWrite>, StoreFailure> {
        self.sample.resend_needed(m)
    }
    fn receive(&self, m: &ReceivedMessage, cx: &mut ReceiveContext<'_>) -> Outcome {
        self.calls
            .lock()
            .unwrap()
            .push((m.message.msg_id.clone(), m.receipt));
        if m.message.body["text"] == "held" && self.hold.load(Ordering::SeqCst) {
            return Outcome::Retry(StoreFailure::unavailable(StoreError::Unavailable));
        }
        if matches!(*self.mode.lock().unwrap(), Mode::Apply) || m.message.body["text"] == "free" {
            return self.sample.receive(m, cx);
        }
        if let Mode::Key(data_epoch) = *self.mode.lock().unwrap()
            && !cx.holds_scope_key("sample-a", data_epoch)
        {
            return Outcome::AwaitKey { data_epoch };
        }
        if m.message.body["text"] == "key" && !cx.holds_scope_key("sample-a", 2) {
            return Outcome::AwaitKey { data_epoch: 2 };
        }
        if let Some(id) = m.message.body.get("forget").and_then(Value::as_str) {
            assert!(cx.forget_processed(m.sender, id).unwrap());
        }
        if m.message.body["text"] == "unsealed" {
            let target = crate::app::RecordTarget::new(
                super::shared_flows::items(),
                m.message.msg_id.as_bytes(),
            );
            assert!(matches!(
                cx.put_record(
                    &target,
                    &super::shared_flows::value(&[&m.message.msg_id]),
                    Vec::new(),
                ),
                Err(crate::app::AppError::Refused(crate::app::Refusal::NotNow(
                    _
                )))
            ));
        }
        if m.message.body["text"] == "large" {
            let target = crate::app::RecordTarget::new(
                super::shared_flows::items(),
                m.message.msg_id.as_bytes(),
            );
            cx.put_record(
                &target,
                &super::shared_flows::value(&[&m.message.msg_id]),
                Vec::new(),
            )
            .unwrap();
            cx.claim(
                crate::app::ClaimOp::attempt([3; 32], 0, [4; 16], 3600, None),
                Vec::new(),
                crate::app::ObligationDeadline::NoDeadline,
            )
            .unwrap();
        }
        let bytes = if m.message.body["text"] == "large" {
            MAX_STEP_LOCAL_BYTES + 1
        } else {
            1
        };
        let _ = cx.local(LocalWrite::Put {
            key: b"admission-write".to_vec(),
            value: vec![1; bytes],
        });
        cx.op(
            Vec::new(),
            OpKind::AllowPut {
                pubky: m.sender,
                kind: AllowKind::Conversation,
            },
        )
        .unwrap();
        match *self.mode.lock().unwrap() {
            Mode::Consume => Outcome::Consume,
            _ => Outcome::AwaitAdmission,
        }
    }
}

async fn wallet(w: &World, p: &Arc<Admission>) -> App {
    let request = w.approve(&app_keys("wallet"), &["sample-a"]);
    let mut app = App::join(w.env(), p.clone(), World::config(), request)
        .await
        .unwrap();
    app.receive(None).await.unwrap();
    app
}

async fn pair(app: &App, w: &World, m: &Message) -> bool {
    app.reader()
        .exists(&key::processed(&w.bob.public(), &m.msg_id))
        .await
        .unwrap()
}

async fn expire(w: &World, app: &mut App) -> Vec<AppEvent> {
    w.clock.advance_ms(MAX_UNVERIFIED_AGE_MS + 1);
    for _ in 0..2 {
        app.receive(None).await.unwrap();
    }
    app.unacknowledged_events().await.unwrap()
}

fn dropped(events: &[AppEvent]) -> Vec<(EventId, EventId, u64, String)> {
    events
        .iter()
        .filter_map(|e| match e {
            AppEvent::StoredEntryDropped {
                id,
                notice_id,
                seq,
                message,
                ..
            } => Some((*id, *notice_id, *seq, message.msg_id.clone())),
            _ => None,
        })
        .collect()
}

#[tokio::test]
async fn test_admission_discards_staged_effects_and_allows_independent_progress() {
    let w = World::new();
    let p = Admission::new();
    let mut app = wallet(&w, &p).await;
    p.set(Mode::Apply);
    let (_, old) = w.note(app.app_id(), "old");
    app.receive(None).await.unwrap();
    let effects = w.effects();
    p.set(Mode::Wait);
    let (seq, waiting) = w
        .switch
        .send(
            &w.bob,
            &w.bob_keys,
            &w.bob_cert,
            "sample.note",
            json!({"text":"large", "forget":old.msg_id}),
            &[app.app_id()],
        )
        .unwrap();
    let (_, free) = w.note(app.app_id(), "free");
    let report = app.receive(None).await.unwrap();
    assert_eq!(
        app.stored_at(seq).unwrap().reason,
        ParkReason::AwaitingAdmission,
        "admission discards even the staged local-bound marker"
    );
    assert_eq!(
        app.protocol_get("sample", b"admission-write")
            .await
            .unwrap(),
        None,
        "admission commits no staged local write"
    );
    assert!(
        pair(&app, &w, &old).await,
        "admission commits no staged pair forget"
    );
    assert!(!pair(&app, &w, &waiting).await, "waiting is not processing");
    assert!(
        pair(&app, &w, &free).await,
        "an unrelated eligible input progresses"
    );
    assert_eq!(
        w.effects(),
        effects + 1,
        "only the eligible input sends its effect"
    );
    assert!(!report.more, "capacity alone requests no immediate repeat");
}

#[tokio::test]
async fn test_admission_discards_the_context_missing_key_marker() {
    let w = World::new();
    let p = Admission::new();
    let mut app = wallet(&w, &p).await;
    w.next_doc(|body| body.data_epoch = 2);
    app.refresh_identity().await.unwrap();
    let effects = w.effects();
    let (seq, message) = w.note(app.app_id(), "unsealed");
    app.receive(None).await.unwrap();
    assert_eq!(
        app.stored_at(seq).map(|stored| stored.reason),
        Some(ParkReason::AwaitingAdmission),
        "admission discards the staged missing-key marker"
    );
    assert_eq!(
        app.protocol_get("sample", b"admission-write")
            .await
            .unwrap(),
        None
    );
    assert!(!pair(&app, &w, &message).await);
    assert_eq!(w.effects(), effects);
}

#[tokio::test]
async fn test_admission_incoming_oldest_is_dropped_with_its_cursor() {
    let w = World::new();
    let p = Admission::new();
    let mut app = wallet(&w, &p).await;
    p.hold.store(true, Ordering::SeqCst);
    let (first, message) = w.note(app.app_id(), "held");
    w.clock.advance_ms(1);
    let later: Vec<_> = (0..64).map(|_| w.note(app.app_id(), "wait").0).collect();
    app.receive(None).await.unwrap();
    assert_eq!(app.state.parked.len(), 64);
    let receipt = app.state.held[&first].receipt;
    p.hold.store(false, Ordering::SeqCst);
    let report = app.receive(None).await.unwrap();
    assert!(
        app.stored_at(first).is_none(),
        "the incoming earliest input is the selected victim"
    );
    assert_eq!(
        app.state.parked.len(),
        64,
        "the incoming input never expands committed custody"
    );
    assert!(later.iter().all(|seq| app.stored_at(*seq).is_some()));
    assert!(app.cursor().seq >= *later.last().unwrap());
    assert!(report.events.iter().any(|event| matches!(event,
        AppEvent::StoredEntryDropped { seq, message: id, receipt: kept, waiting: WaitingReason::Admission, .. }
        if *seq == first && id.msg_id == message.msg_id && *kept == receipt)),
        "the cursor and exact incoming-copy notice commit together");
    assert!(!pair(&app, &w, &message).await);
}

#[tokio::test]
async fn test_admission_held_backup_restore_keeps_the_first_observation() {
    for layered in [false, true] {
        let w = World::new();
        let p = Admission::new();
        let mut app = wallet(&w, &p).await;
        p.hold.store(true, Ordering::SeqCst);
        let (seq, _) = w.note(app.app_id(), "held");
        let (ahead, _) = w.note(app.app_id(), "free");
        app.receive(None).await.unwrap();
        let receipt = app.state.held[&seq].receipt;
        let processed_ahead = app.state.held[&ahead];
        let backup = if layered {
            app.backup_layered().await.unwrap()
        } else {
            app.backup().await.unwrap()
        };
        let fresh = Arc::new(MemoryStore::new());
        let mut restored = App::restore(w.env_on(fresh), p.clone(), World::config(), &backup)
            .await
            .unwrap();
        assert_eq!(
            restored.state.held.get(&seq).map(|held| held.receipt),
            Some(receipt),
            "a backup retains the original held observation"
        );
        assert_eq!(
            restored.state.held.get(&ahead),
            Some(&processed_ahead),
            "and that of an entry processed ahead of the cursor"
        );
        w.clock.advance_ms(10_000);
        p.hold.store(false, Ordering::SeqCst);
        restored.refresh_identity().await.unwrap();
        restored.receive(None).await.unwrap();
        assert_eq!(
            restored.stored_at(seq).unwrap().receipt,
            receipt,
            "later parking retains the original held response time"
        );
        assert!(restored.highest_service_time().unwrap() > receipt.read_at_ms);
    }
}

#[tokio::test]
async fn test_admission_entries_consumed_ahead_keep_their_observations_until_passed() {
    let w = World::new();
    let p = Admission::new();
    let mut app = wallet(&w, &p).await;
    let me = app.app_id();
    p.hold.store(true, Ordering::SeqCst);
    let (held, _) = w.note(me, "held");
    let (parked, _) = w.note(me, "wait");
    app.receive(None).await.unwrap();
    let first = app.stored_at(parked).unwrap().receipt;
    p.set(Mode::Consume);
    w.clock.advance_ms(1);
    let (direct, message) = w.note(me, "consume");
    app.receive(None).await.unwrap();
    assert!(app.cursor().seq < held);
    assert!(app.stored_at(parked).is_none());
    assert!(
        p.calls
            .lock()
            .unwrap()
            .iter()
            .any(|(id, _)| id == &message.msg_id)
    );
    assert!(app.state.seen.contains(&direct));
    drop(app);

    let mut app = App::load(w.env(), p.clone(), World::config(), me)
        .await
        .unwrap();
    assert_eq!(app.state.held[&parked].receipt, first);
    assert!(app.state.held.contains_key(&direct));
    p.hold.store(false, Ordering::SeqCst);
    app.receive(None).await.unwrap();
    assert!(app.cursor().seq >= direct);
    assert!(app.state.held.is_empty());
}

#[tokio::test]
async fn test_admission_backup_checks_the_first_observation() {
    let w = World::new();
    let p = Admission::new();
    let mut app = wallet(&w, &p).await;
    let me = app.app_id();
    p.hold.store(true, Ordering::SeqCst);
    let (held, _) = w.note(me, "held");
    let (parked, _) = w.note(me, "wait");
    app.receive(None).await.unwrap();
    let backup = app.backup().await.unwrap();
    let first = app.stored_at(parked).unwrap().receipt;
    assert!(
        backup
            .waiting
            .held
            .iter()
            .any(|(seq, observation)| *seq == parked && observation.receipt == first)
    );

    let mut timing = backup.clone();
    let (_, observation) = timing
        .waiting
        .held
        .iter_mut()
        .find(|(seq, _)| *seq == held)
        .unwrap();
    observation.accepted_at_ms = observation.receipt.read_at_ms + 1;
    assert!(timing.waiting.validate(&timing, &app.protocols).is_err());

    let mut custody = backup;
    let (_, stored) = custody
        .waiting
        .entries
        .iter_mut()
        .find(|(_, stored)| stored.seq == parked)
        .unwrap();
    stored.receipt.entry_id[0] ^= 1;
    assert!(custody.waiting.validate(&custody, &app.protocols).is_err());
}

#[tokio::test]
async fn test_admission_retry_is_fair_and_keeps_receipts_across_reload() {
    let w = World::new();
    let p = Admission::new();
    let mut app = wallet(&w, &p).await;
    let initial: Vec<_> = (0..24).map(|_| w.note(app.app_id(), "wait")).collect();
    app.receive(None).await.unwrap();
    let before: Vec<_> = initial
        .iter()
        .map(|(seq, _)| (*seq, app.stored_at(*seq).unwrap().receipt))
        .collect();
    p.calls.lock().unwrap().clear();
    let me = app.app_id();
    for _ in 0..3 {
        let prior = p.calls.lock().unwrap().len();
        app.receive(None).await.unwrap();
        assert!(
            p.calls.lock().unwrap().len() - prior <= 16,
            "one due pass is bounded"
        );
        drop(app);
        app = App::load(w.env(), p.clone(), World::config(), me)
            .await
            .unwrap();
    }
    let calls = p.calls.lock().unwrap();
    assert!(
        initial
            .iter()
            .all(|(_, message)| calls.iter().any(|(id, _)| id == &message.msg_id)),
        "durable retry position reaches every original waiting input"
    );
    for (seq, receipt) in before {
        assert_eq!(app.stored_at(seq).unwrap().receipt, receipt);
    }
}

#[tokio::test]
async fn test_admission_acknowledgment_is_exact_atomic_and_never_absence_success() {
    for after in [false, true] {
        for reload in [false, true] {
            let w = World::new();
            let p = Admission::new();
            let mut app = wallet(&w, &p).await;
            w.note(app.app_id(), "wait");
            w.note(app.app_id(), "wait");
            app.receive(None).await.unwrap();
            let notices = dropped(&expire(&w, &mut app).await);
            assert_eq!(notices.len(), 2);
            let id = notices[0].0;
            let other = notices[1].0;
            let me = app.app_id();
            drop(app);
            let fault = if after {
                StoreFault::FailAfter(1)
            } else {
                StoreFault::FailBefore(1)
            };
            let store = Arc::new(FaultStore::new(w.store.clone(), fault));
            let mut app = App::load(w.env_on(store), p.clone(), World::config(), me)
                .await
                .unwrap();
            let local = [LocalWrite::Put {
                key: b"handled".to_vec(),
                value: vec![1],
            }];
            assert!(
                app.ack_event_with("sample", id, &local).await.is_err(),
                "inspection/loading is not delivery"
            );
            app.unacknowledged_events().await.unwrap();
            assert!(
                app.ack_event_with("sample", id, &local).await.is_err(),
                "the selected commit fault is reached"
            );
            if reload {
                drop(app);
                app = App::load(w.env(), p.clone(), World::config(), me)
                    .await
                    .unwrap();
            }
            let kept = app.unacknowledged_events().await.unwrap();
            assert_eq!(
                app.protocol_get("sample", b"handled").await.unwrap(),
                after.then_some(vec![1]),
                "local handling and exact acknowledgment have the same durable outcome"
            );
            assert!(
                kept.iter().any(|e| e.id() == Some(other)),
                "another duty remains owed"
            );
            assert_eq!(kept.iter().any(|e| e.id() == Some(id)), !after);
            if !after {
                app.ack_event_with("sample", id, &local).await.unwrap();
            }
            let replacement = [LocalWrite::Put {
                key: b"handled".to_vec(),
                value: vec![2],
            }];
            assert!(
                app.ack_event_with("sample", id, &replacement)
                    .await
                    .is_err(),
                "an absent event always refuses"
            );
            assert_eq!(
                app.protocol_get("sample", b"handled").await.unwrap(),
                Some(vec![1])
            );
        }
    }
}

#[tokio::test]
async fn test_admission_backup_restores_custody_or_the_same_payload_free_notice() {
    for layered in [false, true] {
        let w = World::new();
        let p = Admission::new();
        let mut app = wallet(&w, &p).await;
        let (seq, _) = w.note(app.app_id(), "secret body");
        app.receive(None).await.unwrap();
        let original = app.stored_at(seq).unwrap().clone();
        let backup = if layered {
            app.backup_layered().await.unwrap()
        } else {
            app.backup().await.unwrap()
        };
        let mut restored = App::restore(
            w.env_on(Arc::new(MemoryStore::new())),
            p.clone(),
            World::config(),
            &backup,
        )
        .await
        .unwrap();
        assert_eq!(
            restored.stored_at(seq),
            Some(&original),
            "the snapshot retains exact custody"
        );
        restored.refresh_identity().await.unwrap();
        let notices = expire(&w, &mut restored).await;
        let original_notice = dropped(&notices);
        assert_eq!(original_notice.len(), 1);
        let backup = if layered {
            restored.backup_layered().await.unwrap()
        } else {
            restored.backup().await.unwrap()
        };
        let bytes = backup.to_bytes().unwrap();
        assert!(
            !String::from_utf8(bytes.clone())
                .unwrap()
                .contains("secret body")
        );
        let read = AppBackup::from_bytes(&bytes).unwrap();
        let mut again = App::restore(
            w.env_on(Arc::new(MemoryStore::new())),
            p.clone(),
            World::config(),
            &read,
        )
        .await
        .unwrap();
        assert!(again.state.parked.is_empty());
        let replay = dropped(&again.unacknowledged_events().await.unwrap());
        assert_eq!(
            replay.first().map(|notice| notice.1),
            Some(original_notice[0].1),
            "a restore retains the immutable notice identity"
        );
        assert_ne!(
            replay[0].0, original_notice[0].0,
            "fresh storage has a new delivery identity"
        );
    }
}

#[tokio::test]
async fn test_admission_completion_retires_custody_with_the_existing_semantics() {
    for consume in [false, true] {
        let w = World::new();
        let p = Admission::new();
        let mut app = wallet(&w, &p).await;
        let (seq, message) = w.note(app.app_id(), "wait");
        app.receive(None).await.unwrap();
        let id = app.stored_id_at(seq).unwrap();
        p.set(if consume { Mode::Consume } else { Mode::Apply });
        app.receive(None).await.unwrap();
        assert!(
            !app.state.parked.contains_key(&id),
            "completion retires the waiting input"
        );
        assert_eq!(
            pair(&app, &w, &message).await,
            !consume,
            "Consume remains distinct from processing"
        );
        assert_eq!(w.effects(), usize::from(!consume));
    }
}

/// Fail the exact custody transaction, before or after it reaches the durable store.
struct CustodyFault {
    inner: Arc<MemoryStore>,
    after: bool,
    armed: AtomicBool,
    fired: AtomicBool,
}

impl StateStore for CustodyFault {
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
        let custody = batch.writes().iter().any(|write| {
            matches!(write,
            crate::store::Write::Put { key, value, .. } if key.starts_with(b"duty/")
                && crate::app::state::decode::<crate::app::events::KeptDuty>(value).is_ok_and(|duty|
                    matches!(duty.duty, crate::app::events::Duty::StoredEntryDropped { .. })))
        });
        if custody && self.armed.load(Ordering::SeqCst) && !self.fired.swap(true, Ordering::SeqCst)
        {
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
        let custody = batch.writes().iter().any(|write| {
            matches!(write,
            crate::store::Write::Put { key, value, .. } if key.starts_with(b"duty/")
                && crate::app::state::decode::<crate::app::events::KeptDuty>(value).is_ok_and(|duty|
                    matches!(duty.duty, crate::app::events::Duty::StoredEntryDropped { .. })))
        });
        if custody && self.armed.load(Ordering::SeqCst) && !self.fired.swap(true, Ordering::SeqCst)
        {
            if self.after {
                return match self.inner.commit_if(ns, owner, batch)? {
                    crate::store::CommitOutcome::Applied => Err(StoreError::Unknown),
                    result => Ok(result),
                };
            }
            return Err(StoreError::Unavailable);
        }
        self.inner.commit_if(ns, owner, batch)
    }
}

#[tokio::test]
async fn test_admission_custody_failure_keeps_payload_notice_and_cursor_atomic() {
    for after in [false, true] {
        for reload in [false, true] {
            let w = World::new();
            let p = Admission::new();
            let store = Arc::new(CustodyFault {
                inner: w.store.clone(),
                after,
                armed: AtomicBool::new(false),
                fired: AtomicBool::new(false),
            });
            let request = w.approve(&app_keys("wallet"), &["sample-a"]);
            let mut app = App::join(w.env_on(store.clone()), p.clone(), World::config(), request)
                .await
                .unwrap();
            app.receive(None).await.unwrap();
            p.hold.store(true, Ordering::SeqCst);
            let (first, _) = w.note(app.app_id(), "held");
            w.clock.advance_ms(1);
            for _ in 0..64 {
                w.note(app.app_id(), "wait");
            }
            app.receive(None).await.unwrap();
            let old_cursor = app.cursor();
            let me = app.app_id();
            p.hold.store(false, Ordering::SeqCst);
            store.armed.store(true, Ordering::SeqCst);
            assert!(app.receive(None).await.is_err());
            assert!(store.fired.load(Ordering::SeqCst));
            let reader = crate::app::state::Reader {
                ns: app.ns.clone(),
                store: w.env().store,
            };
            let cursor: crate::app::state::Cursor = reader.get(key::CURSOR).await.unwrap().unwrap();
            let notices = crate::app::unverified::waiting_notices(&reader)
                .await
                .unwrap();
            assert_eq!(
                notices.len(),
                usize::from(after),
                "a failed custody commit loses no required notice"
            );
            assert_eq!(
                cursor.seq > old_cursor.seq,
                after,
                "cursor progress has the notice's durable outcome"
            );
            assert_eq!(reader.scan_numbers("parked/").await.unwrap().len(), 64);
            if reload {
                drop(app);
                app = App::load(w.env(), p.clone(), World::config(), me)
                    .await
                    .unwrap();
            }
            app.receive(None).await.unwrap();
            assert!(app.stored_at(first).is_none());
            assert_eq!(
                dropped(&app.unacknowledged_events().await.unwrap()).len(),
                1,
                "recovery keeps exactly the same completed custody decision"
            );
            assert_eq!(app.state.parked.len(), 64);
        }
    }
}

#[tokio::test]
async fn test_admission_acknowledgment_refusals_do_not_write_locals() {
    let w = World::new();
    let p = Admission::new();
    let mut app = wallet(&w, &p).await;
    w.note(app.app_id(), "wait");
    app.receive(None).await.unwrap();
    let events = expire(&w, &mut app).await;
    let id = dropped(&events)[0].0;
    let huge = [LocalWrite::Put {
        key: b"refused".to_vec(),
        value: vec![1; MAX_STEP_LOCAL_BYTES + 1],
    }];
    assert!(app.ack_event_with("sample", id, &huge).await.is_err());
    let local = [LocalWrite::Put {
        key: b"refused".to_vec(),
        value: vec![1],
    }];
    let foreign = EventId::new([99; 16], id.counter());
    assert!(app.ack_event_with("sample", foreign, &local).await.is_err());
    assert_eq!(app.protocol_get("sample", b"refused").await.unwrap(), None);
    assert!(
        crate::app::tests::pending_events(&mut app)
            .await
            .unwrap()
            .iter()
            .any(|e| e.id() == Some(id))
    );
}

#[tokio::test]
async fn test_admission_restore_rejects_invalid_custody_before_installing() {
    let w = World::new();
    let p = Admission::new();
    let mut app = wallet(&w, &p).await;
    w.note(app.app_id(), "wait");
    app.receive(None).await.unwrap();
    let backup = app.backup_layered().await.unwrap();
    let mut changed = Vec::new();
    let mut bad = backup.clone();
    bad.waiting.entries[0].1.plaintext[20] ^= 1;
    changed.push(bad);
    let mut bad = backup.clone();
    bad.waiting.entries[0].1.sender = [7; 32];
    changed.push(bad);
    let mut bad = backup.clone();
    bad.waiting.entries.push(bad.waiting.entries[0].clone());
    changed.push(bad);
    let mut bad = backup.clone();
    bad.waiting.entries[0].1.receipt.read_at_ms = 0;
    changed.push(bad);
    for bad in changed {
        let fresh = Arc::new(MemoryStore::new());
        assert!(
            App::restore(w.env_on(fresh.clone()), p.clone(), World::config(), &bad)
                .await
                .is_err(),
            "invalid retained signed custody is refused before installation"
        );
        assert!(fresh.is_empty(&app.ns));
    }
    let mut value: Value = serde_json::from_slice(&backup.to_bytes().unwrap()).unwrap();
    value.as_object_mut().unwrap().remove("waiting");
    assert!(
        AppBackup::from_bytes(&serde_json::to_vec(&value).unwrap()).is_err(),
        "required waiting state never defaults to an empty queue"
    );
}

#[tokio::test]
async fn test_admission_restore_deduplicates_exact_notices_and_rejects_conflicts() {
    let w = World::new();
    let p = Admission::new();
    let mut app = wallet(&w, &p).await;
    w.note(app.app_id(), "wait");
    app.receive(None).await.unwrap();
    expire(&w, &mut app).await;
    let backup = app.backup_layered().await.unwrap();
    let mut twice = backup.clone();
    twice.waiting.notices.push(twice.waiting.notices[0].clone());
    let mut restored = App::restore(w.env(), p.clone(), World::config(), &twice)
        .await
        .unwrap();
    let notices = dropped(&restored.unacknowledged_events().await.unwrap());
    assert_eq!(
        notices.len(),
        1,
        "identical backup and in-place obligations are one notice"
    );
    let local = [LocalWrite::Put {
        key: b"handled".to_vec(),
        value: vec![1],
    }];
    restored
        .ack_event_with("sample", notices[0].0, &local)
        .await
        .unwrap();
    let mut replay = App::restore(w.env(), p.clone(), World::config(), &backup)
        .await
        .unwrap();
    assert_eq!(
        replay.protocol_get("sample", b"handled").await.unwrap(),
        None
    );
    assert_eq!(
        dropped(&replay.unacknowledged_events().await.unwrap())[0].1,
        notices[0].1,
        "restoring older local effects owes the immutable notice again"
    );
    let mut conflict = backup.clone();
    if let crate::app::events::Duty::StoredEntryDropped { message, .. } =
        &mut conflict.waiting.notices[0].duty
    {
        message.hash[0] ^= 1;
    }
    assert!(
        App::restore(w.env(), p.clone(), World::config(), &conflict)
            .await
            .is_err(),
        "the same immutable notice ID cannot name different content"
    );
    let mut malformed = backup.clone();
    if let crate::app::events::Duty::StoredEntryDropped { message, .. } =
        &mut malformed.waiting.notices[0].duty
    {
        message.msg_id = "not an identity".into();
    }
    assert!(
        App::restore(
            w.env_on(Arc::new(MemoryStore::new())),
            p.clone(),
            World::config(),
            &malformed
        )
        .await
        .is_err(),
        "payload-free notices validate their structure, not an absent signature"
    );
}

#[tokio::test]
async fn test_admission_sender_key_and_admission_share_the_total_selector() {
    let w = World::new();
    let p = Admission::new();
    let mut app = wallet(&w, &p).await;
    let unknown = super::unverified::peer(&w, "unavailable");
    let known = super::awaiting_key::published_peer(&w, "carol");
    let mut sender_seqs = Vec::new();
    let mut key_seqs = Vec::new();
    let mut admission_seqs = Vec::new();
    for _ in 0..10 {
        w.clock.advance_ms(1);
        sender_seqs.push(
            w.switch
                .send(
                    &unknown.identity,
                    &unknown.keys,
                    &unknown.cert,
                    "sample.note",
                    json!({"text":"sender"}),
                    &[app.app_id()],
                )
                .unwrap()
                .0,
        );
    }
    for _ in 0..64 {
        w.clock.advance_ms(1);
        key_seqs.push(w.note(app.app_id(), "key").0);
    }
    for _ in 0..64 {
        w.clock.advance_ms(1);
        admission_seqs.push(
            w.switch
                .send(
                    &known.identity,
                    &known.keys,
                    &known.cert,
                    "sample.note",
                    json!({"text":"wait"}),
                    &[app.app_id()],
                )
                .unwrap()
                .0,
        );
    }
    app.receive(None).await.unwrap();
    w.clock.advance_ms(World::config().park_after_ms + 1);
    app.receive(None).await.unwrap();
    assert_eq!(
        app.state.parked.len(),
        128,
        "all three reasons use one total bound"
    );
    assert!(sender_seqs.iter().all(|seq| {
        app.stored_at(*seq)
            .is_some_and(|s| s.reason == ParkReason::Unverifiable)
    }));
    assert!(
        key_seqs[..5]
            .iter()
            .chain(&admission_seqs[..5])
            .all(|seq| app.stored_at(*seq).is_none()),
        "the largest-holder selector removes the exact oldest five from each larger holder"
    );
    assert!(
        key_seqs[5..]
            .iter()
            .chain(&admission_seqs[5..])
            .all(|seq| app.stored_at(*seq).is_some())
    );
    let notices = dropped(&app.unacknowledged_events().await.unwrap());
    assert_eq!(notices.len(), 10);
}

#[tokio::test]
async fn test_admission_reason_changes_keep_id_age_and_observation() {
    let w = World::new();
    let p = Admission::new();
    let mut app = wallet(&w, &p).await;
    w.homeserver.set_down(true);
    let (seq, message) = w.note(app.app_id(), "wait");
    app.receive(None).await.unwrap();
    let receipt = app.state.held[&seq].receipt;
    w.clock.advance_ms(World::config().park_after_ms + 1);
    app.receive(None).await.unwrap();
    let id = app.stored_id_at(seq).unwrap();
    let accepted = app.state.parked[&id].accepted_at_ms;
    assert_eq!(app.state.parked[&id].reason, ParkReason::Unverifiable);
    w.homeserver.set_down(false);
    p.set(Mode::Key(2));
    app.receive(None).await.unwrap();
    assert_eq!(
        app.state.parked[&id].reason,
        ParkReason::AwaitingKey { data_epoch: 2 }
    );
    w.next_doc(|body| body.data_epoch = 2);
    super::awaiting_key::store_parts(&w, app.app_id(), app.cert(), 1, 2);
    p.set(Mode::Wait);
    let before = p.calls.lock().unwrap().len();
    app.receive(None).await.unwrap();
    assert_eq!(app.state.parked[&id].reason, ParkReason::AwaitingAdmission);
    assert_eq!(
        app.state.parked[&id].receipt, receipt,
        "reason changes never substitute a later verified stamp"
    );
    assert_eq!(app.state.parked[&id].accepted_at_ms, accepted);
    assert_eq!(
        p.calls.lock().unwrap().len() - before,
        1,
        "admission refusal does not repeat in the key-driven pass"
    );
    assert!(!pair(&app, &w, &message).await);
    p.set(Mode::Key(3));
    app.receive(None).await.unwrap();
    assert_eq!(app.stored_id_at(seq), Some(id));
    assert_eq!(
        app.state.parked[&id].reason,
        ParkReason::AwaitingKey { data_epoch: 3 }
    );
    assert_eq!(app.state.parked[&id].receipt, receipt);
}

#[tokio::test]
async fn test_admission_spent_budget_and_new_arrivals_do_not_starve_waiting_inputs() {
    let w = World::new();
    let p = Admission::new();
    let mut app = wallet(&w, &p).await;
    let initial: Vec<_> = (0..24)
        .map(|_| w.note(app.app_id(), "wait").1.msg_id)
        .collect();
    app.receive(None).await.unwrap();
    p.calls.lock().unwrap().clear();
    let me = app.app_id();
    for _ in 0..3 {
        for _ in 0..4 {
            w.note(app.app_id(), "wait");
        }
        app.receive(None).await.unwrap();
        drop(app);
        app = App::load(w.env(), p.clone(), World::config(), me)
            .await
            .unwrap();
    }
    assert!(
        initial.iter().all(|id| p
            .calls
            .lock()
            .unwrap()
            .iter()
            .any(|(called, _)| called == id)),
        "continuous arrivals do not starve the original due round"
    );
    app.config.call_budget_ms = 0;
    for _ in 0..3 {
        let before = p.calls.lock().unwrap().len();
        app.receive(None).await.unwrap();
        assert_eq!(
            p.calls.lock().unwrap().len() - before,
            1,
            "an exhausted budget still attempts one due input"
        );
    }
}

#[tokio::test]
async fn test_admission_restore_commit_failure_leaves_one_complete_snapshot() {
    for after in [false, true] {
        let w = World::new();
        let p = Admission::new();
        let mut app = wallet(&w, &p).await;
        w.note(app.app_id(), "wait");
        app.receive(None).await.unwrap();
        let backup = app.backup_layered().await.unwrap();
        let me = app.app_id();
        let fresh = Arc::new(MemoryStore::new());
        let fault = if after {
            StoreFault::FailAfter(1)
        } else {
            StoreFault::FailBefore(1)
        };
        let store = Arc::new(FaultStore::new(fresh.clone(), fault));
        assert!(
            App::restore(w.env_on(store), p.clone(), World::config(), &backup)
                .await
                .is_err()
        );
        if after {
            let loaded = App::load(w.env_on(fresh), p.clone(), World::config(), me)
                .await
                .unwrap();
            assert_eq!(
                loaded.state.parked.len(),
                1,
                "an unknown restore installed complete custody"
            );
        } else {
            assert!(
                fresh.is_empty(&app.ns),
                "a failed restore installed nothing"
            );
        }
    }
}

/// Kept custody is read by its authenticated common fields, never judged again under the
/// protocol's current body rules: inputs whose body only the protocol's former rules allow
/// load, reload, back up, restore and have their drop notice built; the next retry of one
/// judges the current rules and drops it at check 5, a custody drop with its durable notice.
#[tokio::test]
async fn test_waiting_custody_outside_current_body_rules_loads_and_drops() {
    let w = World::new();
    let p = Admission::new();
    p.set_opaque(&["score"]);
    let mut app = wallet(&w, &p).await;
    let me = app.app_id();
    let fraction = |text: &str| {
        w.switch
            .send(
                &w.bob,
                &w.bob_keys,
                &w.bob_cert,
                "sample.note",
                json!({ "text": text, "score": 1.5 }),
                &[me],
            )
            .unwrap()
    };
    // One waits for a key that never comes, so only a bound drops it; one waits for
    // admission, so the next read tries it again.
    p.set(Mode::Key(9));
    let (keyed, keyed_message) = fraction("keyed");
    app.receive(None).await.unwrap();
    p.set(Mode::Wait);
    let (admitted, admitted_message) = fraction("admitted");
    app.receive(None).await.unwrap();
    assert!(app.stored_at(keyed).is_some() && app.stored_at(admitted).is_some());
    // A host update narrows the protocol's opaque members.
    p.set_opaque(&[]);
    drop(app);
    let mut app = App::load(w.env(), p.clone(), World::config(), me)
        .await
        .expect("kept custody loads under the narrowed rules");
    let id = app.stored_id_at(keyed).unwrap();
    assert!(
        app.parked_entry(id)
            .await
            .unwrap()
            .unwrap()
            .message
            .is_some(),
        "the host still reads the kept message"
    );
    let backup = app.backup().await.unwrap();
    let fresh = Arc::new(MemoryStore::new());
    let mut app = App::restore(w.env_on(fresh.clone()), p.clone(), World::config(), &backup)
        .await
        .expect("kept custody restores under the narrowed rules");
    app.refresh_identity().await.unwrap();
    let report = app.receive(None).await.unwrap();
    assert!(
        report.events.iter().any(|event| matches!(event,
            AppEvent::MessageDropped { seq, check: 5, .. } if *seq == admitted)),
        "the retry judges the current rules and drops the input at check 5"
    );
    assert!(app.stored_at(admitted).is_none());
    assert!(
        app.stored_at(keyed).is_some(),
        "the other input still waits"
    );
    // The custody drop's durable notice was committed with it: it survives a reload.
    drop(app);
    let mut app = App::load(w.env_on(fresh), p.clone(), World::config(), me)
        .await
        .unwrap();
    let kept = app.unacknowledged_events().await.unwrap();
    assert!(
        kept.iter().any(|event| matches!(event,
            AppEvent::StoredEntryDropped { seq, reason: DropReason::Rules { check: 5 },
                waiting: WaitingReason::Admission, message, .. }
            if *seq == admitted && message.msg_id == admitted_message.msg_id)),
        "the retry's custody drop keeps its durable notice: {kept:?}"
    );
    let notices = dropped(&expire(&w, &mut app).await);
    assert_eq!(
        notices
            .iter()
            .map(|notice| (notice.2, notice.3.clone()))
            .collect::<Vec<_>>(),
        vec![
            (admitted, admitted_message.msg_id),
            (keyed, keyed_message.msg_id)
        ],
        "the bound's drop notice is built without the current rules"
    );
    assert!(app.stored_at(keyed).is_none());
}

/// The service's facts about an entry are checked when its page is read, before anything
/// of the entry is kept: a page showing it accepted after the page's own time is refused.
/// So no kept observation ever precedes its entry's acceptance, and none is judged again as
/// a store fault.
#[tokio::test]
async fn test_waiting_page_contradicting_an_entrys_acceptance_is_refused() {
    let w = World::new();
    let p = Admission::new();
    let mut app = wallet(&w, &p).await;
    let me = app.app_id();
    let cursor = app.cursor().seq;
    w.clock.advance_ms(10_000);
    let (seq, message) = w.note(me, "held");
    w.clock.set_ms(w.clock.now_ms() - 5_000);
    let error = app.receive(None).await.unwrap_err();
    assert!(
        matches!(&error,
            crate::app::AppError::Switch(crate::error::ClientError::InvalidResponse(why))
                if why.contains("accepted after the page's time")),
        "{error:?}"
    );
    drop(app);
    let app = App::load(w.env(), p.clone(), World::config(), me)
        .await
        .expect("a refused page leaves a store that loads");
    assert!(app.stored_at(seq).is_none(), "no custody of the entry");
    assert!(!pair(&app, &w, &message).await, "not processed");
    assert_eq!(app.cursor().seq, cursor, "the cursor stays before it");
    // Since no writer keeps one, kept custody whose observation precedes its acceptance
    // is a corrupt store.
    let w = World::new();
    let p = Admission::new();
    let mut app = wallet(&w, &p).await;
    let me = app.app_id();
    let (seq, _) = w.note(me, "wait");
    app.receive(None).await.unwrap();
    let id = app.stored_id_at(seq).unwrap();
    let mut stored = app.stored_at(seq).unwrap().clone();
    stored.receipt.read_at_ms = stored.accepted_at_ms - 1;
    let mut tx = app.tx().unwrap();
    tx.put(&key::parked(id), &stored).unwrap();
    app.commit(tx).await.unwrap();
    drop(app);
    assert!(matches!(
        App::load(w.env(), p.clone(), World::config(), me).await,
        Err(crate::app::AppError::Store(StoreError::Corrupt))
    ));
}

/// Two signed pages that contradict each other at a `seq` tell two histories, a rollback or
/// fork: where the app keeps the first observation of an entry an earlier page showed, a
/// later page that shows anything but that entry accepted by then, whatever the item's type,
/// raises the rollback alarm once, before anything of the page is kept. The cursor and the
/// observation stay as they were, the alarm survives a reload, and later reads stop on it
/// instead of failing at the same page again (Switch spec 10.1, wire 7.4.4).
#[tokio::test]
async fn test_waiting_page_contradicting_a_kept_observation_raises_the_rollback_alarm() {
    #[derive(Clone, Copy, Debug)]
    enum Shown {
        OtherEntry,
        EntryAcceptedLater,
        Unreadable,
        Missed,
        Chain,
        Stub,
        OtherThanAStoredEntry,
        OtherThanAnEntryProcessedAhead,
    }
    for shown in [
        Shown::OtherEntry,
        Shown::EntryAcceptedLater,
        Shown::Unreadable,
        Shown::Missed,
        Shown::Chain,
        Shown::Stub,
        Shown::OtherThanAStoredEntry,
        Shown::OtherThanAnEntryProcessedAhead,
    ] {
        let w = World::new();
        let p = Admission::new();
        let mut app = wallet(&w, &p).await;
        let me = app.app_id();
        w.clock.advance_ms(10_000);
        // An entry held at the first page, before an entry the read stores past it and one
        // it processes past it.
        let (held_seq, message) = w.note(me, "held");
        let (stored_seq, _) = w.note(me, "wait");
        let (ahead_seq, _) = w.note(me, "free");
        p.hold.store(true, Ordering::SeqCst);
        app.receive(None).await.unwrap();
        p.hold.store(false, Ordering::SeqCst);
        let cursor = app.cursor();
        assert!(cursor.seq < held_seq && app.stored_at(stored_seq).is_some());
        assert!(app.state.seen.contains(&ahead_seq));
        let observed = app.state.held[&held_seq];
        let now = w.clock.now_ms();
        // The observation an earlier page left at `at`, which the next page contradicts.
        let mut tx = app.tx().unwrap();
        let at = match shown {
            Shown::OtherEntry | Shown::EntryAcceptedLater => {
                let mut held = observed;
                match shown {
                    Shown::OtherEntry => held.receipt.entry_id[0] ^= 1,
                    _ => held.accepted_at_ms -= 1,
                }
                tx.put(&key::held(held_seq), &held).unwrap();
                held_seq
            }
            Shown::OtherThanAnEntryProcessedAhead => {
                let mut ahead = app.state.held[&ahead_seq];
                ahead.receipt.entry_id[0] ^= 1;
                tx.put(&key::held(ahead_seq), &ahead).unwrap();
                ahead_seq
            }
            Shown::OtherThanAStoredEntry => {
                let id = app.stored_id_at(stored_seq).unwrap();
                let mut stored = app.stored_at(stored_seq).unwrap().clone();
                stored.receipt.entry_id[0] ^= 1;
                tx.put(&key::parked(id), &stored).unwrap();
                stored_seq
            }
            Shown::Unreadable | Shown::Missed | Shown::Chain | Shown::Stub => {
                match shown {
                    Shown::Unreadable => {
                        w.switch.push_unreadable(w.bob.public(), now);
                    }
                    Shown::Missed => {
                        w.switch.push_missed(1, now, now);
                    }
                    // The signer's new `identity.json`, which every own app reads in full.
                    Shown::Chain => w.switch.deliver_identity(&w.next_doc(|_| {})).unwrap(),
                    // A deny list change, which an app without `lists.read` reads as a stub.
                    _ => {
                        let manager = w.other_app("manager", &[Permission::ListsManage]);
                        w.switch
                            .app_op(&manager, OpKind::DenyPut { pubky: [9; 32] })
                            .unwrap();
                    }
                }
                let at = w.switch.seq();
                tx.put(&key::held(at), &observed).unwrap();
                at
            }
        };
        let item_type = match shown {
            Shown::Unreadable => "unreadable",
            Shown::Missed => "missed",
            Shown::Chain => "chain",
            Shown::Stub => "stub",
            _ => "entry",
        };
        assert!(
            w.switch
                .shown(me)
                .iter()
                .any(|item| item["seq"] == at && item["type"] == item_type),
            "{shown:?}: the page shows a `{item_type}` item at {at}"
        );
        app.commit(tx).await.unwrap();
        drop(app);
        let mut app = App::load(w.env(), p.clone(), World::config(), me)
            .await
            .unwrap();
        let kept = (
            app.state.held.get(&at).copied(),
            app.stored_at(at).map(|stored| stored.receipt),
        );
        let error = app.receive(None).await.unwrap_err();
        let alarm = app.alarm().cloned();
        let Some(crate::app::Alarm::Rollback { reason }) = &alarm else {
            panic!("{shown:?}: no rollback alarm: {error:?}");
        };
        let alarm = alarm.clone().unwrap();
        assert!(reason.contains(&format!("seq {at}")), "{shown:?}: {reason}");
        assert_eq!(
            error,
            crate::app::AppError::Alarm(alarm.clone()),
            "{shown:?}"
        );
        for _ in 0..2 {
            drop(app);
            app = App::load(w.env(), p.clone(), World::config(), me)
                .await
                .unwrap();
            assert_eq!(app.alarm(), Some(&alarm), "{shown:?}: the alarm is kept");
            assert_eq!(app.cursor(), cursor, "{shown:?}: the cursor stays");
            assert_eq!(
                (
                    app.state.held.get(&at).copied(),
                    app.stored_at(at).map(|stored| stored.receipt)
                ),
                kept,
                "{shown:?}: the observation stays as evidence"
            );
            assert!(
                !pair(&app, &w, &message).await,
                "{shown:?}: nothing processed"
            );
            // Later reads stop on the alarm, raised once, rather than on the page.
            assert_eq!(
                app.receive(None).await.unwrap_err(),
                crate::app::AppError::Refused(crate::app::Refusal::Stopped),
                "{shown:?}"
            );
            assert_eq!(app.alarm(), Some(&alarm), "{shown:?}");
        }
    }
}

/// A page shows one item per `seq`: a page that shows another entry at the `seq` of one it
/// holds is refused before anything of it is kept. So the other entry is never handed the
/// held one's receipt, nor taken as the held one handled, and the held entry is processed
/// once its store is back (Switch wire 7.4.4).
#[tokio::test]
async fn test_waiting_page_with_two_items_at_one_seq_is_refused() {
    let w = World::new();
    let p = Admission::new();
    let mut app = wallet(&w, &p).await;
    let me = app.app_id();
    let cursor = app.cursor();
    let (seq, held) = w.note(me, "held");
    let (own_seq, other) = w.note(me, "free");
    // Moves the last entry at `from` to `to`.
    let at = |from: u64, to: u64| {
        for item in w.switch.lock().items.iter_mut().rev() {
            if let crate::testing::Item::Entry { seq, .. } = item
                && *seq == from
            {
                *seq = to;
                break;
            }
        }
    };
    // The other entry shown at the held entry's `seq` too, right after it.
    at(own_seq, seq);
    p.hold.store(true, Ordering::SeqCst);
    let error = app.receive(None).await.unwrap_err();
    assert!(
        matches!(&error,
            crate::app::AppError::Switch(crate::error::ClientError::InvalidResponse(why))
                if why.contains("increasing seq order")),
        "{error:?}"
    );
    assert!(p.calls.lock().unwrap().is_empty(), "nothing handed");
    assert_eq!(app.cursor(), cursor, "the cursor stays");
    assert!(app.state.held.is_empty(), "nothing held");
    at(seq, own_seq);
    p.hold.store(false, Ordering::SeqCst);
    p.set(Mode::Apply);
    app.receive(None).await.unwrap();
    assert!(pair(&app, &w, &held).await, "the held entry is processed");
    assert!(pair(&app, &w, &other).await, "and the other");
}

/// A cooperative move continues the sequence: an entry stored locally before the move, at a
/// `seq` the cursor hasn't passed, is compared with what the next service's page shows there,
/// as at the service it was read from (Switch wire 7.4.4).
#[tokio::test]
async fn test_waiting_stored_entry_observation_is_compared_after_a_move() {
    use super::moves::{self, Router};
    let w = World::new();
    let router = Router::of(&w);
    let p = Admission::new();
    let store = Arc::clone(&w.store) as Arc<dyn StateStore>;
    let mut app = moves::join_on(
        &w,
        &router,
        store,
        p.clone(),
        &[Permission::ConversationAdd],
    )
    .await;
    app.receive(None).await.unwrap();
    let me = app.app_id();
    // An entry held, before an entry the read stores past it.
    let (held_seq, _) = w.note(me, "held");
    let (stored_seq, _) = w.note(me, "wait");
    p.hold.store(true, Ordering::SeqCst);
    app.receive(None).await.unwrap();
    assert!(app.cursor().seq < held_seq && app.stored_at(stored_seq).is_some());
    let n_key = moves::next_key();
    w.switch.freeze(&moves::freeze_for(&w, &n_key, 2)).unwrap();
    let next = w.switch.import_into(n_key.to_bytes());
    router.add(moves::NEXT, &next);
    let _ = app.receive(None).await;
    // The observation an earlier page left, which the next service's page contradicts.
    let id = app.stored_id_at(stored_seq).unwrap();
    let mut stored = app.stored_at(stored_seq).unwrap().clone();
    stored.receipt.entry_id[0] ^= 1;
    let mut tx = app.tx().unwrap();
    tx.put(&key::parked(id), &stored).unwrap();
    app.commit(tx).await.unwrap();
    app.state.parked.insert(id, stored);
    moves::publish_at(
        &w,
        &next,
        Inbox::new(moves::NEXT, n_key.verifying_key().to_bytes()),
        2,
        None,
    );
    let _ = app.receive(None).await;
    assert_eq!(app.cursor().generation, 2);
    let Some(crate::app::Alarm::Rollback { reason }) = app.alarm() else {
        panic!("no rollback alarm: {:?}", app.alarm());
    };
    assert!(reason.contains(&format!("seq {stored_seq}")), "{reason}");
}

/// A custody drop's notice names one of the recipient checks a stored input can fail when
/// tried again, 2 to 8 (Switch wire 5.1): no writer keeps another, so a notice naming one is
/// a corrupt store, at a load and at a restore alike.
#[tokio::test]
async fn test_waiting_drop_notice_check_outside_recipient_checks_is_corrupt() {
    let w = World::new();
    let p = Admission::new();
    let mut app = wallet(&w, &p).await;
    let me = app.app_id();
    w.note(me, "wait");
    app.receive(None).await.unwrap();
    expire(&w, &mut app).await;
    let backup = app.backup_layered().await.unwrap();
    drop(app);
    // The notice as a backup carries it, and as a store keeps it.
    let with_check = |mut kept: crate::app::events::KeptDuty, check: u8| {
        let crate::app::events::Duty::StoredEntryDropped { reason, .. } = &mut kept.duty else {
            unreachable!()
        };
        *reason = DropReason::Rules { check };
        kept
    };
    for check in [0, 1, 2, 8, 9] {
        let shape = (2..=8).contains(&check);
        let mut restored = backup.clone();
        restored.waiting.notices[0] = with_check(restored.waiting.notices[0].clone(), check);
        let result = App::restore(
            w.env_on(Arc::new(MemoryStore::new())),
            p.clone(),
            World::config(),
            &restored,
        )
        .await;
        assert_eq!(result.is_ok(), shape, "restore, check {check}");
        assert!(
            shape
                || matches!(
                    result,
                    Err(crate::app::AppError::Store(StoreError::Corrupt))
                ),
            "restore, check {check}"
        );
        let store = Arc::new(MemoryStore::new());
        let mut app = App::restore(w.env_on(store.clone()), p.clone(), World::config(), &backup)
            .await
            .unwrap();
        let (at, bytes) = app
            .reader()
            .scan_raw(key::DUTY_PREFIX)
            .await
            .unwrap()
            .into_iter()
            .find(|(_, bytes)| crate::app::unverified::waiting_record(bytes))
            .unwrap();
        let kept = with_check(crate::app::state::decode(&bytes).unwrap(), check);
        let mut tx = app.tx().unwrap();
        tx.put(&format!("{}{at}", key::DUTY_PREFIX), &kept).unwrap();
        app.commit(tx).await.unwrap();
        drop(app);
        let loaded = App::load(w.env_on(store), p.clone(), World::config(), me).await;
        assert_eq!(loaded.is_ok(), shape, "load, check {check}");
        assert!(
            shape
                || matches!(
                    loaded,
                    Err(crate::app::AppError::Store(StoreError::Corrupt))
                ),
            "load, check {check}"
        );
    }
}
