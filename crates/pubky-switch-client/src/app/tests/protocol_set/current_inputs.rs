//! Current input completion and bounded custody across protocol owners.

use super::*;
use crate::app::state::key;
use crate::app::{EntryReceipt, EventId, MAX_UNVERIFIED_AGE_MS, ParkReason, ReceiveContext};
use crate::store::{Fault as CommitFault, FaultStore};

#[derive(Clone, Copy)]
enum Decision {
    Apply,
    Consume,
    Wait,
    Retry,
    Wide,
}

struct Input {
    base: Named,
    decision: Mutex<Decision>,
    calls: Mutex<Vec<(String, EntryReceipt)>>,
    retry_released: Mutex<bool>,
}

impl Input {
    fn new(name: &str) -> Arc<Self> {
        Arc::new(Self {
            base: named(name),
            decision: Mutex::new(Decision::Wait),
            calls: Mutex::new(Vec::new()),
            retry_released: Mutex::new(false),
        })
    }

    fn set(&self, decision: Decision) {
        *self.decision.lock().unwrap() = decision;
    }
}

impl Protocol for Input {
    fn name(&self) -> String {
        self.base.name()
    }
    fn has_keys(&self, scope: &str) -> bool {
        self.base.has_keys(scope)
    }
    fn sent_between_own_apps(&self, kind: &str) -> bool {
        self.base.sent_between_own_apps(kind)
    }
    fn check_scopes(
        &self,
        message: &Message,
        sender: &AppCert,
        own: &AppCert,
    ) -> Result<(), String> {
        self.base.check_scopes(message, sender, own)
    }
    fn accepts(&self, cert: &AppCert) -> Vec<String> {
        self.base.accepts(cert)
    }
    fn opaque_members(&self) -> Vec<crate::app::OpaqueRule> {
        if self.base.name == "tasks" {
            vec![crate::app::OpaqueRule {
                kind: None,
                member: "score".into(),
            }]
        } else {
            Vec::new()
        }
    }
    fn check_body(&self, message: &ReceivedMessage) -> Result<(), String> {
        self.base.check_body(message)
    }
    fn resend_needed(&self, needed: &ResendNeeded) -> Result<Vec<LocalWrite>, StoreFailure> {
        self.base.resend_needed(needed)
    }
    fn missed(&self, missed: &MissedEntries) -> Result<Vec<LocalWrite>, StoreFailure> {
        self.base.missed(missed)
    }
    fn restore_layer(
        &self,
        layer: Option<&ProtocolLayer>,
        context: &RestoreContext<'_>,
    ) -> Result<Vec<LocalWrite>, String> {
        self.base.restore_layer(layer, context)
    }
    fn receive(&self, message: &ReceivedMessage, cx: &mut ReceiveContext<'_>) -> Outcome {
        self.calls
            .lock()
            .unwrap()
            .push((message.message.msg_id.clone(), message.receipt));
        if message.released && *self.retry_released.lock().unwrap() {
            return Outcome::Retry(StoreFailure::unavailable(StoreError::Unavailable));
        }
        if let Some(id) = message.message.body.get("forget").and_then(Value::as_str) {
            cx.forget_processed(message.sender, id).unwrap();
        }
        let count = cx.local_get(b"count").unwrap().map_or(0, |value| value[0]);
        cx.local(LocalWrite::Put {
            key: b"count".to_vec(),
            value: vec![count + 1],
        })
        .unwrap();
        cx.op(
            Vec::new(),
            OpKind::AllowPut {
                pubky: message.sender,
                reason: PeerReason::Reply,
            },
        )
        .unwrap();
        match *self.decision.lock().unwrap() {
            Decision::Apply => Outcome::Apply(Effect::default()),
            Decision::Wide => Outcome::Apply(Effect {
                ops: vec![
                    (
                        Vec::new(),
                        OpKind::AllowPut {
                            pubky: message.sender,
                            reason: PeerReason::Reply
                        }
                    );
                    pubky_switch_core::ops::MAX_BATCH_ENTRIES
                ],
                local: Vec::new(),
            }),
            Decision::Consume => Outcome::Consume,
            Decision::Wait => Outcome::AwaitAdmission,
            Decision::Retry => Outcome::Retry(StoreFailure::unavailable(StoreError::Unavailable)),
        }
    }
}

struct Inputs {
    pair: Pair,
    tasks: Arc<Input>,
    chat: Arc<Input>,
}

impl Inputs {
    fn new() -> Self {
        Self {
            pair: Pair::new(),
            tasks: Input::new("tasks"),
            chat: Input::new("chat"),
        }
    }
    fn set(&self) -> ProtocolSet {
        ProtocolSet::new(vec![
            self.tasks.clone() as Arc<dyn Protocol>,
            self.chat.clone(),
        ])
        .unwrap()
    }
    async fn join(&self) -> App {
        let request = self.pair.approve("wallet", &[]);
        let mut app = App::join(self.pair.env(), self.set(), World::config(), request)
            .await
            .unwrap();
        app.receive(None).await.unwrap();
        app
    }
    async fn load(&self, id: [u8; 16]) -> App {
        App::load(self.pair.env(), self.set(), World::config(), id)
            .await
            .unwrap()
    }
    fn send(&self, app: &App, kind: &str, body: Value) -> (u64, Message) {
        let w = &self.pair.w;
        w.switch
            .send(
                &w.bob,
                &w.bob_keys,
                &w.bob_cert,
                kind,
                body,
                &[app.app_id()],
            )
            .unwrap()
    }
    async fn held_pair(&self, app: &App, message: &Message) -> bool {
        app.reader()
            .exists(&key::processed(&self.pair.w.bob.public(), &message.msg_id))
            .await
            .unwrap()
    }
    async fn expire(&self, app: &mut App) -> Vec<AppEvent> {
        self.pair.w.clock.advance_ms(MAX_UNVERIFIED_AGE_MS + 1);
        read(app, 2).await;
        app.unacknowledged_events().await.unwrap()
    }
    async fn orphan_notice(&self, app: &mut App) -> EventId {
        self.pair.w.homeserver.set_down(true);
        let (seq, _) = self.send(app, "orphan.item", json!({"text":"waiting"}));
        read(app, 1).await;
        self.pair
            .w
            .clock
            .advance_ms(World::config().park_after_ms + 1);
        read(app, 1).await;
        assert_eq!(app.stored_at(seq).unwrap().reason, ParkReason::Unverifiable);
        let events = self.expire(app).await;
        self.pair.w.homeserver.set_down(false);
        let id = events
            .iter()
            .find_map(|event| match event {
                AppEvent::StoredEntryDropped { id, message, .. }
                    if message.kind == "orphan.item" =>
                {
                    Some(*id)
                }
                _ => None,
            })
            .unwrap();
        assert_eq!(app.event_owners(id).unwrap(), app.protocols.names());
        id
    }
}

async fn count(app: &App, owner: &str) -> Option<Vec<u8>> {
    app.protocol_get(owner, b"count").await.unwrap()
}

fn local(key: &[u8], value: u8) -> [LocalWrite; 1] {
    [LocalWrite::Put {
        key: key.to_vec(),
        value: vec![value],
    }]
}

#[tokio::test]
async fn test_protocol_inputs_consume_isolates_locals_and_prior_pairs() {
    let inputs = Inputs::new();
    inputs.tasks.set(Decision::Apply);
    inputs.chat.set(Decision::Apply);
    let mut app = inputs.join().await;
    let (_, tasks) = inputs.send(&app, "tasks.item", json!({"text":"old"}));
    let (_, chat) = inputs.send(&app, "chat.item", json!({"text":"old"}));
    read(&mut app, 1).await;
    assert!(inputs.held_pair(&app, &tasks).await && inputs.held_pair(&app, &chat).await);
    let before = inputs.pair.snapshot(&app.app_id());
    assert!(matches!(
        app.forget_processed(
            "tasks",
            inputs.pair.w.bob.public(),
            &chat.msg_id,
            &local(b"foreign", 1)
        )
        .await,
        Err(AppError::Refused(Refusal::Usage(_)))
    ));
    assert_eq!(
        inputs.pair.snapshot(&app.app_id()),
        before,
        "foreign pair refusal changes no owner"
    );
    let effects = inputs.pair.w.effects();
    inputs.tasks.set(Decision::Consume);
    let (_, current) = inputs.send(
        &app,
        "tasks.item",
        json!({"text":"consume", "forget":tasks.msg_id}),
    );
    read(&mut app, 1).await;
    assert_eq!(
        (count(&app, "tasks").await, count(&app, "chat").await),
        (Some(vec![2]), Some(vec![1])),
        "each local effect belongs to its owner"
    );
    assert!(!inputs.held_pair(&app, &tasks).await && !inputs.held_pair(&app, &current).await);
    assert!(
        inputs.held_pair(&app, &chat).await,
        "consumption cannot forget another owner's pair"
    );
    assert_eq!(
        inputs.pair.w.effects(),
        effects,
        "Consume discards the staged remote operation"
    );
}

#[tokio::test]
async fn test_protocol_inputs_admission_advances_handover_and_keeps_original_receipt() {
    let inputs = Inputs::new();
    inputs.tasks.set(Decision::Apply);
    inputs.chat.set(Decision::Consume);
    let mut app = inputs.join().await;
    let (_, prior) = inputs.send(&app, "tasks.item", json!({"text":"old"}));
    read(&mut app, 1).await;
    let effects = inputs.pair.w.effects();
    inputs.tasks.set(Decision::Wait);
    let (seq, waiting) = inputs.send(
        &app,
        "tasks.item",
        json!({"text":"wait", "forget":prior.msg_id}),
    );
    let (_, later) = inputs.send(&app, "chat.item", json!({"text":"ready"}));
    read(&mut app, 1).await;
    let held = app.stored_at(seq).unwrap();
    let original = held.receipt;
    let id = *app
        .state
        .parked
        .iter()
        .find(|(_, entry)| entry.seq == seq)
        .unwrap()
        .0;
    assert_eq!(
        count(&app, "chat").await,
        Some(vec![1]),
        "ready owner progresses after another declines admission"
    );
    assert_eq!(
        count(&app, "tasks").await,
        Some(vec![1]),
        "admission discards its staged local effect"
    );
    assert!(
        inputs.held_pair(&app, &prior).await,
        "admission discards staged pair forgets"
    );
    assert!(!inputs.held_pair(&app, &waiting).await && !inputs.held_pair(&app, &later).await);
    assert_eq!(inputs.pair.w.effects(), effects);
    let me = app.app_id();
    drop(app);
    inputs.pair.w.clock.advance_ms(10_000);
    let mut app = inputs.load(me).await;
    inputs.tasks.set(Decision::Consume);
    read(&mut app, 1).await;
    assert!(app.stored_at(seq).is_none());
    assert!(!app.state.parked.contains_key(&id));
    assert_eq!(count(&app, "tasks").await, Some(vec![2]));
    let observations: Vec<_> = inputs
        .tasks
        .calls
        .lock()
        .unwrap()
        .iter()
        .filter(|(message, _)| message == &waiting.msg_id)
        .map(|(_, receipt)| *receipt)
        .collect();
    assert!(observations.len() >= 2);
    assert!(
        observations.iter().all(|receipt| *receipt == original),
        "owner retries retain the original authenticated observation"
    );
}

#[tokio::test]
async fn test_protocol_inputs_drop_notice_routes_after_payload_deletion() {
    let inputs = Inputs::new();
    let mut app = inputs.join().await;
    let (seq, message) = inputs.send(&app, "tasks.item", json!({"text":"wait"}));
    read(&mut app, 1).await;
    let events = inputs.expire(&mut app).await;
    assert!(app.stored_at(seq).is_none());
    let id = events
        .iter()
        .find_map(|event| match event {
            AppEvent::StoredEntryDropped {
                id,
                message: identity,
                ..
            } if identity.msg_id == message.msg_id => Some(*id),
            _ => None,
        })
        .unwrap();
    assert_eq!(
        app.event_owners(id).unwrap(),
        ["tasks"],
        "the retained kind owns the notice after custody is gone"
    );
    let before = inputs.pair.snapshot(&app.app_id());
    assert!(matches!(
        app.ack_event_with("chat", id, &local(b"handled", 1)).await,
        Err(AppError::Refused(Refusal::Usage(_)))
    ));
    assert_eq!(inputs.pair.snapshot(&app.app_id()), before);
    app.ack_event_with("tasks", id, &local(b"handled", 1))
        .await
        .unwrap();
    assert_eq!(
        app.protocol_get("tasks", b"handled").await.unwrap(),
        Some(vec![1])
    );
    assert_eq!(app.protocol_get("chat", b"handled").await.unwrap(), None);
    assert!(
        !app.unacknowledged_events()
            .await
            .unwrap()
            .iter()
            .any(|event| event.id() == Some(id))
    );
}

#[tokio::test]
async fn test_ack_events_for_after_a_lost_answer_preserves_the_other_owner() {
    let inputs = Inputs::new();
    let mut app = inputs.join().await;
    let id = inputs.orphan_notice(&mut app).await;
    let me = app.app_id();
    drop(app);
    let store = Arc::new(FaultStore::new(
        inputs.pair.store.clone(),
        CommitFault::FailAfter(1),
    ));
    let mut app = App::load(
        inputs.pair.w.env_on(store),
        inputs.set(),
        World::config(),
        me,
    )
    .await
    .unwrap();
    app.unacknowledged_events().await.unwrap();
    assert!(matches!(
        app.ack_events_for("tasks", id).await,
        Err(AppError::Store(StoreError::Unknown))
    ));
    let pending = app.pending_duty_events().await.unwrap();
    let duty = pending
        .iter()
        .find(|duty| duty.event.id() == Some(id))
        .unwrap();
    assert_eq!(duty.owners, ["chat"]);
    app.ack_events_for("tasks", id).await.unwrap();
    assert!(
        app.unacknowledged_events_for("tasks")
            .await
            .unwrap()
            .iter()
            .all(|event| event.id() != Some(id))
    );
    assert!(
        app.unacknowledged_events_for("chat")
            .await
            .unwrap()
            .iter()
            .any(|event| event.id() == Some(id))
    );
}

#[tokio::test]
async fn test_protocol_inputs_exact_ack_commits_only_one_remaining_owner() {
    for after in [false, true] {
        for reload in [false, true] {
            let inputs = Inputs::new();
            let mut app = inputs.join().await;
            let id = inputs.orphan_notice(&mut app).await;
            let me = app.app_id();
            drop(app);
            let fault = if after {
                CommitFault::FailAfter(1)
            } else {
                CommitFault::FailBefore(1)
            };
            let store = Arc::new(FaultStore::new(inputs.pair.store.clone(), fault));
            let mut app = App::load(
                inputs.pair.w.env_on(store),
                inputs.set(),
                World::config(),
                me,
            )
            .await
            .unwrap();
            assert!(
                app.ack_event_with("tasks", id, &local(b"handled", 1))
                    .await
                    .is_err(),
                "load does not hand the event to its owner"
            );
            app.unacknowledged_events().await.unwrap();
            assert!(
                app.ack_event_with("tasks", id, &local(b"handled", 1))
                    .await
                    .is_err(),
                "the selected acknowledgment fault is reached"
            );
            if reload {
                drop(app);
                app = inputs.load(me).await;
            }
            app.unacknowledged_events().await.unwrap();
            assert_eq!(
                app.protocol_get("tasks", b"handled").await.unwrap(),
                after.then_some(vec![1])
            );
            assert_eq!(
                app.event_owners(id).unwrap(),
                if after {
                    vec!["chat"]
                } else {
                    vec!["tasks", "chat"]
                },
                "one owner and its local decision have one durable outcome"
            );
            if !after {
                app.ack_event_with("tasks", id, &local(b"handled", 1))
                    .await
                    .unwrap();
            }
            assert!(
                app.ack_event_with("tasks", id, &local(b"handled", 2))
                    .await
                    .is_err(),
                "an owner no longer owed cannot overwrite its handling state"
            );
            assert_eq!(
                app.protocol_get("tasks", b"handled").await.unwrap(),
                Some(vec![1])
            );
            app.ack_event_with("chat", id, &local(b"handled", 3))
                .await
                .unwrap();
            assert_eq!(
                app.protocol_get("chat", b"handled").await.unwrap(),
                Some(vec![3])
            );
            assert!(
                !app.unacknowledged_events()
                    .await
                    .unwrap()
                    .iter()
                    .any(|event| event.id() == Some(id))
            );
        }
    }
}

#[tokio::test]
async fn test_protocol_inputs_restore_preserves_remaining_notice_owners_and_locals() {
    let inputs = Inputs::new();
    let mut app = inputs.join().await;
    let id = inputs.orphan_notice(&mut app).await;
    let before = app.backup_layered().await.unwrap();
    app.ack_event_with("tasks", id, &local(b"handled", 1))
        .await
        .unwrap();
    assert_eq!(
        app.event_owners(id).map(|owners| owners.to_vec()),
        Some(vec!["chat".to_owned()]),
        "acknowledgment retires only its owner"
    );
    let after = app.backup_layered().await.unwrap();
    let fresh = Arc::new(MemoryStore::new());
    let mut restored = App::restore(
        inputs.pair.w.env_on(fresh),
        inputs.set(),
        World::config(),
        &after,
    )
    .await
    .unwrap();
    let events = restored.unacknowledged_events().await.unwrap();
    let id = events
        .iter()
        .find_map(|event| {
            matches!(event, AppEvent::StoredEntryDropped { .. }).then(|| event.id().unwrap())
        })
        .unwrap();
    assert_eq!(
        restored.event_owners(id).unwrap(),
        ["chat"],
        "the completed owner's effect and remaining recipients restore together"
    );
    assert_eq!(
        restored.protocol_get("tasks", b"handled").await.unwrap(),
        Some(vec![1])
    );
    assert!(
        restored
            .ack_event_with("tasks", id, &local(b"handled", 2))
            .await
            .is_err()
    );
    drop(app);
    let mut restored = App::restore(inputs.pair.env(), inputs.set(), World::config(), &before)
        .await
        .unwrap();
    let events = restored.unacknowledged_events().await.unwrap();
    let notices: Vec<_> = events
        .iter()
        .filter(|event| matches!(event, AppEvent::StoredEntryDropped { .. }))
        .collect();
    assert_eq!(
        notices.len(),
        1,
        "identical immutable notices coalesce across snapshots"
    );
    assert_eq!(
        restored.event_owners(notices[0].id().unwrap()).unwrap(),
        ["chat", "tasks"]
    );
    assert_eq!(
        restored.protocol_get("tasks", b"handled").await.unwrap(),
        None,
        "an older layer re-owes the handling effect it does not contain"
    );
}

#[tokio::test]
async fn test_protocol_inputs_backup_checks_custody_and_notice_owners_before_hooks() {
    let inputs = Inputs::new();
    let mut app = inputs.join().await;
    let (seq, _) = inputs.send(&app, "tasks.item", json!({"text":"wait"}));
    read(&mut app, 1).await;
    let original = app.stored_at(seq).unwrap().receipt;
    let backups = [
        app.backup().await.unwrap(),
        app.backup_layered().await.unwrap(),
    ];
    let me = app.app_id();
    drop(app);
    for backup in backups {
        for in_place in [false, true] {
            let store = if in_place {
                inputs.pair.store.clone()
            } else {
                Arc::new(MemoryStore::new())
            };
            let restored = App::restore(
                inputs.pair.w.env_on(store),
                inputs.set(),
                World::config(),
                &backup,
            )
            .await
            .unwrap();
            assert_eq!(restored.stored_at(seq).unwrap().receipt, original);
            assert_eq!(
                restored.state.parked.len(),
                1,
                "common custody is restored once across all layers"
            );
            drop(restored);
        }
    }
    let mut app = inputs.load(me).await;
    let events = inputs.expire(&mut app).await;
    assert!(
        events
            .iter()
            .any(|event| matches!(event, AppEvent::StoredEntryDropped { .. }))
    );
    let backup = app.backup_layered().await.unwrap();
    for owners in [
        Vec::new(),
        vec!["tasks".into(), "tasks".into()],
        vec!["missing".into()],
    ] {
        let mut corrupt = backup.clone();
        corrupt.waiting.notices[0].to = owners;
        let before = (
            inputs.tasks.base.restored.lock().unwrap().len(),
            inputs.chat.base.restored.lock().unwrap().len(),
        );
        let store = Arc::new(MemoryStore::new());
        assert!(
            App::restore(
                inputs.pair.w.env_on(store.clone()),
                inputs.set(),
                World::config(),
                &corrupt
            )
            .await
            .is_err()
        );
        assert_eq!(
            (
                inputs.tasks.base.restored.lock().unwrap().len(),
                inputs.chat.base.restored.lock().unwrap().len()
            ),
            before,
            "invalid recipient state is rejected before any owner hook"
        );
        assert!(store.scan(&app.ns, b"", None, u32::MAX).unwrap().is_empty());
    }
}

fn send_copy(inputs: &Inputs, app: &App, message: &Message) -> u64 {
    let w = &inputs.pair.w;
    w.switch
        .send_plaintext(
            w.bob.public(),
            &w.bob_cert,
            &message.sign(&w.bob_keys).unwrap(),
            &[app.app_id()],
        )
        .unwrap()
}

#[tokio::test]
async fn test_protocol_inputs_held_restore_keeps_its_observation_before_admission() {
    for layered in [false, true] {
        let inputs = Inputs::new();
        inputs.tasks.set(Decision::Retry);
        inputs.chat.set(Decision::Consume);
        let mut app = inputs.join().await;
        let (seq, _) = inputs.send(&app, "tasks.item", json!({"text":"held"}));
        inputs.send(&app, "chat.item", json!({"text":"ready"}));
        read(&mut app, 1).await;
        let receipt = app.state.held[&seq].receipt;
        assert_eq!(count(&app, "chat").await, Some(vec![1]));
        let backup = if layered {
            app.backup_layered().await.unwrap()
        } else {
            app.backup().await.unwrap()
        };
        let mut restored = App::restore(
            inputs.pair.w.env_on(Arc::new(MemoryStore::new())),
            inputs.set(),
            World::config(),
            &backup,
        )
        .await
        .unwrap();
        assert_eq!(restored.state.held[&seq].receipt, receipt);
        inputs.pair.w.clock.advance_ms(10_000);
        inputs.tasks.set(Decision::Wait);
        restored.refresh_identity().await.unwrap();
        read(&mut restored, 1).await;
        assert_eq!(
            restored.stored_at(seq).unwrap().receipt,
            receipt,
            "the original owner observation survives held-to-custody restore"
        );
        assert!(restored.highest_service_time().unwrap() > receipt.read_at_ms);
        assert_eq!(count(&restored, "tasks").await, None);
    }
}

#[tokio::test]
async fn test_protocol_inputs_completion_retires_released_copy_for_its_owner() {
    let inputs = Inputs::new();
    inputs.tasks.set(Decision::Apply);
    let mut app = inputs.join().await;
    let (_, message) = inputs.send(&app, "tasks.item", json!({"text":"applied"}));
    inputs
        .pair
        .w
        .switch
        .fail_next(Fault::LoseAnswer { path: "ops".into() });
    assert!(app.receive(None).await.is_err());
    let backup = app.backup_layered().await.unwrap();
    let mut app = App::restore(
        inputs.pair.w.env_on(Arc::new(MemoryStore::new())),
        inputs.set(),
        World::config(),
        &backup,
    )
    .await
    .unwrap();
    read(&mut app, 1).await;
    let copy = app
        .parked_entries()
        .await
        .unwrap()
        .into_iter()
        .find(|entry| entry.reason == ParkReason::Uncertain)
        .unwrap();
    let earlier = app.unacknowledged_events().await.unwrap();
    app.release_parked(copy.stored_id, &copy.hash)
        .await
        .unwrap();
    *inputs.tasks.retry_released.lock().unwrap() = true;
    let (chat_seq, _) = inputs.send(&app, "chat.item", json!({"text":"waiting"}));
    send_copy(&inputs, &app, &message);
    read(&mut app, 1).await;
    assert!(
        app.parked_entries()
            .await
            .unwrap()
            .iter()
            .all(|entry| entry.stored_id != copy.stored_id),
        "completion retires the eligible released copy"
    );
    assert_eq!(
        app.stored_at(chat_seq).unwrap().reason,
        ParkReason::AwaitingAdmission
    );
    let events = app.unacknowledged_events().await.unwrap();
    assert!(earlier.iter().all(|event| events.contains(event)));
    let id = events
        .iter()
        .find_map(|event| match event {
            AppEvent::ReleasedDuplicate { id, stored_id, .. } if *stored_id == copy.stored_id => {
                Some(*id)
            }
            _ => None,
        })
        .unwrap();
    assert_eq!(
        app.event_owners(id).unwrap(),
        ["tasks"],
        "release completion belongs to the input owner after payload deletion"
    );
    assert_eq!(count(&app, "chat").await, None);
    assert!(inputs.held_pair(&app, &message).await);
}

#[tokio::test]
async fn test_protocol_inputs_ordinary_loss_completes_only_the_applied_owner() {
    use super::super::moves::{NEXT, Router, freeze_for, next_key, publish_at};
    let inputs = Inputs::new();
    let mut app = inputs.join().await;
    let router = Router::of(&inputs.pair.w);
    let (_, message) = inputs.send(&app, "tasks.item", json!({"text":"stored"}));
    send_copy(&inputs, &app, &message);
    let (chat_seq, _) = inputs.send(&app, "chat.item", json!({"text":"waiting"}));
    read(&mut app, 1).await;
    assert_eq!(app.parked_entries().await.unwrap().len(), 3);
    inputs.tasks.set(Decision::Apply);
    send_copy(&inputs, &app, &message);
    inputs
        .pair
        .w
        .switch
        .fail_next(Fault::LoseAnswer { path: "ops".into() });
    assert!(app.receive(None).await.is_err());
    app.ready_local().await.unwrap();
    assert!(app.state.pending_effect.is_some());
    let me = app.app_id();
    let store = Arc::new(FaultStore::new(
        inputs.pair.store.clone(),
        CommitFault::None,
    ));
    store.fail_put_once(key::processed(&inputs.pair.w.bob.public(), &message.msg_id).as_bytes());
    drop(app);
    let mut app = App::load(
        router.env(&inputs.pair.w, store),
        inputs.set(),
        World::config(),
        me,
    )
    .await
    .unwrap();
    let key = next_key();
    inputs
        .pair
        .w
        .switch
        .freeze(&freeze_for(&inputs.pair.w, &key, 2))
        .unwrap();
    let next = inputs.pair.w.switch.import_into(key.to_bytes());
    router.add(NEXT, &next);
    publish_at(
        &inputs.pair.w,
        &next,
        Inbox::new(NEXT, key.verifying_key().to_bytes()),
        2,
        None,
    );
    assert!(app.receive(None).await.is_err());
    drop(app);
    let mut app = App::load(
        router.env(&inputs.pair.w, inputs.pair.store.clone()),
        inputs.set(),
        World::config(),
        me,
    )
    .await
    .unwrap();
    assert_eq!(app.state.meta.generation, 1);
    assert!(app.state.pending_effect.is_some());
    let key = next_key();
    let next = ScriptedSwitch::recovering(
        &inputs.pair.w.alice,
        key.to_bytes(),
        inputs.pair.w.clock.clone(),
        3,
        1,
    )
    .unwrap();
    router.add(NEXT, &next);
    publish_at(
        &inputs.pair.w,
        &next,
        Inbox::new(NEXT, key.verifying_key().to_bytes()),
        3,
        Some(1),
    );
    inputs.pair.w.switch.lock().not_hosted_unpinned = true;
    app.refresh_identity().await.unwrap();
    read(&mut app, 1).await;
    drop(app);
    let mut app = App::load(
        router.env(&inputs.pair.w, inputs.pair.store.clone()),
        inputs.set(),
        World::config(),
        me,
    )
    .await
    .unwrap();
    assert_eq!(app.state.meta.generation, 3);
    assert!(app.state.pending_effect.is_none());
    assert!(inputs.held_pair(&app, &message).await);
    assert_eq!(
        count(&app, "tasks").await,
        Some(vec![1]),
        "known-applied completion commits exactly one owner effect before loss"
    );
    assert_eq!(count(&app, "chat").await, None);
    assert_eq!(app.parked_entries().await.unwrap().len(), 1);
    assert!(
        app.parked_entries()
            .await
            .unwrap()
            .iter()
            .all(|entry| entry.seq == chat_seq),
        "completion retires only its owner's eligible copies"
    );
    assert_eq!(
        inputs.pair.w.effects(),
        1,
        "loss retries never repeat the completed remote effect"
    );
}

#[tokio::test]
async fn test_protocol_inputs_opaque_custody_restores_with_only_its_owner_rules() {
    let inputs = Inputs::new();
    let mut app = inputs.join().await;
    let (tasks_seq, tasks) = inputs.send(&app, "tasks.item", json!({"score":1.5}));
    let (chat_seq, _) = inputs.send(&app, "chat.item", json!({"score":1.5}));
    read(&mut app, 1).await;
    let original = app
        .parked_entry(app.stored_id_at(tasks_seq).unwrap())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(original.message.unwrap().body["score"], json!(1.5));
    assert!(app.stored_at(chat_seq).is_none());
    assert!(
        inputs.chat.calls.lock().unwrap().is_empty(),
        "another owner's opaque rule cannot authorize this body"
    );
    for layered in [false, true] {
        let backup = if layered {
            app.backup_layered().await.unwrap()
        } else {
            app.backup().await.unwrap()
        };
        let mut restored = App::restore(
            inputs.pair.w.env_on(Arc::new(MemoryStore::new())),
            inputs.set(),
            World::config(),
            &backup,
        )
        .await
        .unwrap();
        let stored = restored.parked_entries().await.unwrap();
        assert_eq!(stored.len(), 1);
        let entry = restored
            .parked_entry(stored[0].stored_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(entry.message.unwrap().msg_id, tasks.msg_id);
        assert_eq!(
            entry.receipt, original.receipt,
            "owned opaque custody keeps its authenticated identity and observation"
        );
    }
}

async fn duplicate_carried_recipients(waiting: bool) {
    use crate::app::events::KeptDuty;
    use crate::store::WriteBatch;
    let inputs = Inputs::new();
    let mut app = inputs.join().await;
    let backup = app.backup_layered().await.unwrap();
    let id = if waiting {
        inputs.orphan_notice(&mut app).await
    } else {
        inputs.tasks.set(Decision::Wide);
        let (seq, _) = inputs.send(&app, "tasks.item", json!({"text":"unavailable"}));
        read(&mut app, 1).await;
        app.unacknowledged_events()
            .await
            .unwrap()
            .iter()
            .find_map(|event| match event {
                AppEvent::EffectRefused {
                    id, seq: parked, ..
                } if *parked == seq => Some(*id),
                _ => None,
            })
            .unwrap()
    };
    app.protocol_commit("tasks", &local(b"sentinel", 9))
        .await
        .unwrap();
    let ns = app.ns.clone();
    let me = app.app_id();
    let duty_key = key::duty(id.counter());
    let mut duty: KeptDuty = app.reader().get(&duty_key).await.unwrap().unwrap();
    duty.to = vec!["tasks".into(), "tasks".into()];
    let mut corrupt = WriteBatch::new();
    corrupt
        .put(
            &ns,
            duty_key.into_bytes(),
            crate::app::state::encode(&duty).unwrap(),
        )
        .unwrap();
    inputs.pair.store.commit(corrupt).unwrap();
    let before = inputs.pair.snapshot(&me);
    let hooks = (
        inputs.tasks.base.restored.lock().unwrap().len(),
        inputs.chat.base.restored.lock().unwrap().len(),
    );
    drop(app);
    let result = App::restore(inputs.pair.env(), inputs.set(), World::config(), &backup).await;
    assert!(
        matches!(result, Err(AppError::Store(StoreError::Corrupt))),
        "duplicate carried recipients are corrupt"
    );
    let unchanged = inputs.pair.snapshot(&me) == before;
    let sentinel = inputs.pair.store.get(&ns, b"p/tasks/sentinel").unwrap() == Some(vec![9]);
    let untouched_hooks = (
        inputs.tasks.base.restored.lock().unwrap().len(),
        inputs.chat.base.restored.lock().unwrap().len(),
    ) == hooks;
    let load_refuses = matches!(
        App::load(inputs.pair.env(), inputs.set(), World::config(), me).await,
        Err(AppError::Store(StoreError::Corrupt))
    );
    assert_eq!(
        (unchanged, sentinel, untouched_hooks, load_refuses),
        (true, true, true, true),
        "invalid carried recipients refuse before replacement or restore hooks"
    );
}

#[tokio::test]
async fn test_protocol_inputs_restore_rejects_duplicate_carried_notice_before_replacement() {
    duplicate_carried_recipients(true).await;
}

#[tokio::test]
async fn test_protocol_inputs_restore_rejects_duplicate_carried_duty_before_replacement() {
    duplicate_carried_recipients(false).await;
}

#[tokio::test]
async fn test_protocol_inputs_restore_intersects_carried_recipients_before_validation() {
    let inputs = Inputs::new();
    let mut app = inputs.join().await;
    let original = app.backup_layered().await.unwrap();
    drop(app);
    let news = Input::new("news");
    let expanded = ProtocolSet::new(vec![
        inputs.tasks.clone() as Arc<dyn Protocol>,
        inputs.chat.clone(),
        news,
    ])
    .unwrap();
    let mut app = App::restore(inputs.pair.env(), expanded, World::config(), &original)
        .await
        .unwrap();
    let id = inputs.orphan_notice(&mut app).await;
    assert_eq!(app.event_owners(id).unwrap(), ["tasks", "chat", "news"]);
    drop(app);
    let mut app = App::restore(inputs.pair.env(), inputs.set(), World::config(), &original)
        .await
        .unwrap();
    let events = app.unacknowledged_events().await.unwrap();
    let notices: Vec<_> = events
        .iter()
        .filter_map(|event| match event {
            AppEvent::StoredEntryDropped { id, .. } => Some(*id),
            _ => None,
        })
        .collect();
    assert_eq!(notices.len(), 1);
    assert_eq!(
        app.event_owners(notices[0]).unwrap(),
        ["tasks", "chat"],
        "valid old recipients are intersected with the restored registration"
    );
}
