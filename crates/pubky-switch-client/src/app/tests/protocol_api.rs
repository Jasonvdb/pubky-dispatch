//! What a protocol does through the app's public API: effects that write their records in
//! the batch that moves the cursor, its own local state, messages signed before they are
//! queued, the attempt checks of its batches, counterparties' `identity.json`, the highest
//! service time, collections with a policy per sub-scope, and two identities messaging each
//! other, each on its own scripted switch.

mod append_records;
mod delivery_inventory;
mod delivery_lifecycle;
mod list_order;

use std::sync::{Arc, Mutex};

use pubky_switch_core::chain::TransitionProof;
use pubky_switch_core::claims::ClaimStatus;
use pubky_switch_core::http::ErrorCode;
use pubky_switch_core::ident::Policy;
use pubky_switch_core::message::{MessagePlaintext, Sender};
use pubky_switch_core::ops::{Condition, KeyBundlePut, OpKind, RecordVersion};
use pubky_switch_core::records::{
    CLOCK_TOLERANCE_MS, DAY_MS, IdentityDoc, Inbox, seal_bundle_parts,
};
use pubky_switch_core::scopes::Permission;
use pubky_switch_core::sig::SignedDoc;
use serde_json::{Map, Value, json};

use super::shared_flows::{ItemsProtocol, ids, items, value};
use super::*;
use crate::app::{
    AppBackup, AppError, AppEvent, ClaimOp, Collection, DOC_CACHE_MS, Delivery,
    LISTS_TOO_LARGE_RETRY_MS, MAX_CURSOR_DEFER_MS, MAX_SEEN_MARK_BYTES, ObligationDeadline,
    OpBatch, OutgoingMessage, PolicyFamily, ReceiveContext, RecordJob, RecordTarget, Refusal,
    ReplyGrantOnRelease, SENT_RETENTION_MS, SenderDisposition, SentMessage, SignedMessage,
    SwitchCopy, WontDeliver,
};
use crate::store::{Fault as StoreFault, FaultStore};
use crate::testing::{Fault, Router, SWITCH_ORIGIN, ScriptedSwitch};
use crate::transport::Transport;

const MINUTE: u64 = 60_000;
pub(super) const BOB_ORIGIN: &str = "https://bob-switch.example";
const CAROL_ORIGIN: &str = "https://carol-switch.example";
const CLAIM: [u8; 32] = [5; 32];
const ATTEMPT: [u8; 16] = [6; 16];

/// What [`ApiProtocol`]'s receive step does with a note.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Mode {
    /// [`ItemsProtocol`]'s effect, through the plain `receive`.
    Plain,
    /// Add the note's `msg_id` to the record `inbox`, through the context.
    Record,
    /// The same, then write the record a second time in the batch.
    RecordTwice,
    /// The same, then drop the message.
    DropAfterWrite,
    /// An `attempt` on [`CLAIM`] through the context.
    Attempt,
    /// A write of a record whose policy names a write scope the app doesn't hold.
    OtherWriteScope,
    /// A write of `inbox` with a value that isn't JSON.
    NotJson,
    /// Keep the received note locally, without changing service admission.
    LocalNote,
    /// Keep the sender of an accepted note as a peer.
    KeepPeer,
    /// Complete the input's local handling without a processed pair.
    Consume,
    /// Keep the input in admission custody without its staged local write.
    AwaitAdmission,
}

/// What one call of the receive step saw.
#[derive(Clone, Debug)]
struct Seen {
    msg_id: String,
    /// The message hash of the signed plaintext it was handed.
    hash: [u8; 32],
    /// The version of `inbox` the app held.
    held: Option<RecordVersion>,
    conflict: bool,
    /// The context's answers to the writes, as text.
    writes: Vec<Result<(), String>>,
    invite_code_hash: Option<[u8; 32]>,
    /// What the context knew of the sender's standing in the lists.
    disposition: Option<SenderDisposition>,
    /// The condition the context named on `inbox`, in the record modes.
    condition: Option<Condition>,
}

type DeliveryCheck =
    dyn Fn(&crate::app::DeliveryView<'_>) -> Result<bool, crate::app::StoreFailure> + Send + Sync;

/// [`ItemsProtocol`], with a receive step that uses the [`ReceiveContext`].
struct ApiProtocol {
    items: ItemsProtocol,
    mode: Mutex<Mode>,
    collections: Mutex<Vec<Collection>>,
    seen: Mutex<Vec<Seen>>,
    /// How many of the next receive steps the store rejects for their entry, which is then
    /// stored locally ([`StoreFailure::of_entry`]).
    reject: Mutex<u32>,
    /// The body members it names opaque.
    opaque: Mutex<Vec<crate::app::OpaqueRule>>,
    blocked_origin: Mutex<Option<crate::app::DeliveryOrigin>>,
    send_origins: Mutex<Vec<(String, crate::app::DeliveryOrigin)>>,
    require_send_fact: std::sync::atomic::AtomicBool,
    delivery_check: Mutex<Option<Arc<DeliveryCheck>>>,
    append_gate: Mutex<Option<Arc<append_records::Gate>>>,
}

impl ApiProtocol {
    fn new(mode: Mode) -> Arc<Self> {
        Arc::new(Self {
            items: ItemsProtocol::default(),
            mode: Mutex::new(mode),
            collections: Mutex::new(vec![items()]),
            seen: Mutex::new(Vec::new()),
            reject: Mutex::new(0),
            opaque: Mutex::new(Vec::new()),
            blocked_origin: Mutex::new(None),
            send_origins: Mutex::new(Vec::new()),
            require_send_fact: std::sync::atomic::AtomicBool::new(false),
            delivery_check: Mutex::new(None),
            append_gate: Mutex::new(None),
        })
    }

    fn seen(&self) -> Vec<Seen> {
        self.seen.lock().unwrap().clone()
    }
}

fn inbox() -> RecordTarget {
    RecordTarget::new(items(), b"inbox")
}

fn text(result: Result<[u8; 32], AppError>) -> Result<(), String> {
    result.map(|_| ()).map_err(|e| e.to_string())
}

impl Protocol for ApiProtocol {
    fn may_send(
        &self,
        delivery: &crate::app::DeliveryView<'_>,
    ) -> Result<bool, crate::app::StoreFailure> {
        self.send_origins
            .lock()
            .unwrap()
            .push((delivery.message().msg_id.clone(), delivery.origin()));
        if self
            .require_send_fact
            .load(std::sync::atomic::Ordering::SeqCst)
            && !delivery_inventory::has_delivery_fact(delivery)?
        {
            return Ok(false);
        }
        let check = self.delivery_check.lock().unwrap().clone();
        if let Some(check) = check
            && !check(delivery)?
        {
            return Ok(false);
        }
        Ok(*self.blocked_origin.lock().unwrap() != Some(delivery.origin()))
    }

    fn append_records(
        &self,
        delivery: &crate::app::DeliveryView<'_>,
    ) -> Result<Vec<RecordTarget>, crate::app::StoreFailure> {
        Ok(self
            .append_gate
            .lock()
            .unwrap()
            .as_ref()
            .map_or_else(Vec::new, |g| {
                g.targets(delivery.message().msg_id.as_bytes())
            }))
    }

    fn judge_append(
        &self,
        delivery: &crate::app::DeliveryView<'_>,
        records: &[(RecordTarget, crate::app::RecordRead)],
    ) -> Result<crate::app::AppendDecision, crate::app::StoreFailure> {
        Ok(self
            .append_gate
            .lock()
            .unwrap()
            .as_ref()
            .unwrap()
            .decide(delivery, records))
    }

    fn name(&self) -> String {
        "sample".into()
    }

    fn has_keys(&self, scope: &str) -> bool {
        self.items.has_keys(scope)
    }

    fn sent_between_own_apps(&self, kind: &str) -> bool {
        self.items.sent_between_own_apps(kind)
    }

    fn check_scopes(
        &self,
        message: &Message,
        sender: &AppCert,
        own: &AppCert,
    ) -> Result<(), String> {
        self.items.check_scopes(message, sender, own)
    }

    fn accepts(&self, cert: &AppCert) -> Vec<String> {
        self.items.accepts(cert)
    }

    /// Plain and locally kept notes use [`ItemsProtocol`]'s body checks.
    fn check_body(&self, message: &ReceivedMessage) -> Result<(), String> {
        if matches!(
            *self.mode.lock().unwrap(),
            Mode::Plain | Mode::LocalNote | Mode::KeepPeer
        ) {
            self.items.check_body(message)
        } else {
            Ok(())
        }
    }

    fn receive(&self, message: &ReceivedMessage, cx: &mut ReceiveContext<'_>) -> Outcome {
        let mode = *self.mode.lock().unwrap();
        let msg_id = message.message.msg_id.clone();
        let mut seen = Seen {
            msg_id: msg_id.clone(),
            hash: message.plaintext.hash(),
            held: None,
            conflict: message.conflict.is_some(),
            writes: Vec::new(),
            invite_code_hash: message.receipt.invite_code_hash,
            disposition: cx.sender_disposition(&message.sender).ok(),
            condition: None,
        };
        {
            let mut reject = self.reject.lock().unwrap();
            if *reject > 0 {
                *reject -= 1;
                self.seen.lock().unwrap().push(seen);
                return Outcome::Retry(crate::app::StoreFailure::of_entry(
                    crate::error::StoreError::Corrupt,
                ));
            }
        }
        let outcome = match mode {
            Mode::Plain => self.items.receive(message, cx),
            Mode::KeepPeer => {
                cx.op(
                    Vec::new(),
                    OpKind::AllowPut {
                        pubky: message.sender,
                        reason: pubky_switch_core::admission::PeerReason::Kept,
                    },
                )
                .unwrap();
                Outcome::Apply(Effect::default())
            }
            Mode::LocalNote | Mode::Consume | Mode::AwaitAdmission => {
                cx.local(LocalWrite::Put {
                    key: format!("notes/{msg_id}").into_bytes(),
                    value: b"1".to_vec(),
                })
                .unwrap();
                match mode {
                    Mode::Consume => Outcome::Consume,
                    Mode::AwaitAdmission => Outcome::AwaitAdmission,
                    _ => Outcome::Apply(Effect::default()),
                }
            }
            Mode::Record | Mode::RecordTwice | Mode::DropAfterWrite => {
                let held = cx.record(&inbox()).unwrap();
                seen.held = held.as_ref().map(|r| r.version);
                let key = cx.record_key(&inbox()).unwrap();
                seen.condition = Some(cx.record_condition(&key).unwrap());
                let mut all = ids(held.as_ref().and_then(|r| r.content.value()));
                if !all.contains(&msg_id) {
                    // A record that reflects the message already needs no write (Switch
                    // spec 8.2).
                    all.push(msg_id.clone());
                    let all: Vec<&str> = all.iter().map(String::as_str).collect();
                    seen.writes
                        .push(text(cx.put_record(&inbox(), &value(&all), vec![])));
                    if mode == Mode::RecordTwice {
                        seen.writes
                            .push(text(cx.put_record(&inbox(), &value(&all), vec![])));
                    }
                }
                cx.local(LocalWrite::Put {
                    key: format!("notes/{msg_id}").into_bytes(),
                    value: b"1".to_vec(),
                })
                .unwrap();
                if mode == Mode::DropAfterWrite {
                    Outcome::Drop {
                        reason: "sample: dropped after writing".into(),
                    }
                } else {
                    Outcome::Apply(Effect::default())
                }
            }
            Mode::OtherWriteScope => {
                let target = RecordTarget::new(
                    Collection::new("sample.other", Policy::new("sample-a", &["sample-b"])),
                    b"x",
                );
                seen.writes
                    .push(text(cx.put_record(&target, &value(&["x"]), vec![])));
                Outcome::Apply(Effect::default())
            }
            Mode::NotJson => {
                seen.writes
                    .push(text(cx.put_record(&inbox(), b"not json", vec![])));
                Outcome::Apply(Effect::default())
            }
            Mode::Attempt => {
                let step = cx.claim_view(&CLAIM).unwrap().map_or(0, |v| v.step);
                let result = cx.claim(
                    ClaimOp::attempt(CLAIM, step, ATTEMPT, 3600, None),
                    vec![cx.claim_condition(&CLAIM).unwrap()],
                    ObligationDeadline::NoDeadline,
                );
                seen.writes.push(result.map_err(|e| e.to_string()));
                Outcome::Apply(Effect::default())
            }
        };
        self.seen.lock().unwrap().push(seen);
        outcome
    }

    fn resend_needed(
        &self,
        needed: &ResendNeeded,
    ) -> Result<Vec<LocalWrite>, crate::app::StoreFailure> {
        self.items.resend_needed(needed)
    }

    fn missed(&self, missed: &MissedEntries) -> Result<Vec<LocalWrite>, crate::app::StoreFailure> {
        self.items.missed(missed)
    }

    fn adds_reply(&self, kind: &str) -> bool {
        self.items.adds_reply(kind)
    }

    fn opaque_members(&self) -> Vec<crate::app::OpaqueRule> {
        self.opaque.lock().unwrap().clone()
    }

    fn collections(&self) -> Vec<Collection> {
        self.collections.lock().unwrap().clone()
    }

    fn record_seen(&self, c: &str, seen: Option<&[u8]>, value: Option<&[u8]>) -> Option<Vec<u8>> {
        self.items.record_seen(c, seen, value)
    }

    fn record_regression(
        &self,
        c: &str,
        seen: Option<&[u8]>,
        value: Option<&[u8]>,
        base: crate::app::WriteBase,
    ) -> Option<String> {
        self.items.record_regression(c, seen, value, base)
    }

    fn sent_record(
        &self,
        job: &RecordJob,
        sent: &SentMessage,
        current: Option<&[u8]>,
    ) -> Option<Vec<u8>> {
        self.items.sent_record(job, sent, current)
    }
}

/// A cursor move that waits for the next batch as long as it may: one the switch holds came
/// with an effect.
pub(super) fn config() -> AppConfig {
    AppConfig {
        cursor_defer_ms: MAX_CURSOR_DEFER_MS,
        ..AppConfig::default()
    }
}

async fn join_on(
    w: &World,
    protocol: &Arc<ApiProtocol>,
    name: &str,
    scopes: &[&str],
    store: Arc<dyn StateStore>,
) -> App {
    let app = AppSpec::new(scopes).with_permissions(&Permission::ALL);
    let request = w.signer.approve(&app_keys(name), &app).unwrap();
    App::join(w.env_on(store), protocol.clone(), config(), request)
        .await
        .unwrap()
}

async fn join(w: &World, protocol: &Arc<ApiProtocol>, name: &str) -> App {
    join_on(
        w,
        protocol,
        name,
        &["sample-a"],
        Arc::new(MemoryStore::new()),
    )
    .await
}

fn record_puts(w: &World) -> usize {
    w.switch
        .applied()
        .iter()
        .filter(|op| matches!(op.body().kind, OpKind::RecordPut(_)))
        .count()
}

// -------------------------------------------------------------------------------------
// The receive context (Switch spec 8.2)

#[tokio::test]
async fn test_receive_context_writes_the_record_with_the_cursor_move() {
    let w = World::new();
    let protocol = ApiProtocol::new(Mode::Record);
    let mut app = join(&w, &protocol, "wallet").await;
    let (seq, note) = w.note(app.app_id(), "hello");
    app.receive(None).await.unwrap();
    // One batch: the record write, carrying the cursor past the entry.
    assert_eq!(record_puts(&w), 1);
    assert_eq!(w.switch.app(&app.app_id()).cursor, seq);
    assert_eq!(app.service_cursor().seq, seq);
    let key = app.record_key(&inbox()).unwrap();
    let record = app.shared_record(&key).await.unwrap().unwrap();
    assert_eq!(ids(record.content.value()), vec![note.msg_id.clone()]);
    assert!(record.authenticated, "settled from the effect's proof");
    let local = format!("notes/{}", note.msg_id);
    assert!(
        app.protocol_get("sample", local.as_bytes())
            .await
            .unwrap()
            .is_some()
    );
    // The message seen again writes nothing more.
    assert!(protocol.seen()[0].held.is_none());
}

#[tokio::test]
async fn test_receive_context_condition_names_zero_for_a_held_delete() {
    // The receive step's condition on a record: `{0, 0}` for one the app holds nothing of
    // and for one it holds as deleted, which `{0, 0}` matches as it matches a forgotten key
    // (Switch wire 6.3, spec 10.3); the held version for a live one.
    let w = World::new();
    let protocol = ApiProtocol::new(Mode::Record);
    let mut app = join(&w, &protocol, "wallet").await;
    let key = app.record_key(&inbox()).unwrap();
    let zero = Condition::RecordVersion {
        key,
        version: RecordVersion::NONE,
    };
    w.note(app.app_id(), "one");
    app.receive(None).await.unwrap();
    let live = app.shared_record(&key).await.unwrap().unwrap().version;
    w.note(app.app_id(), "two");
    app.receive(None).await.unwrap();
    let deleted = app.delete_record(&inbox(), vec![]).await.unwrap().version;
    w.note(app.app_id(), "three");
    app.receive(None).await.unwrap();
    let seen = protocol.seen();
    assert_eq!(seen.len(), 3, "{seen:?}");
    assert_eq!(seen[0].condition, Some(zero), "absent");
    assert_eq!(
        seen[1].condition,
        Some(Condition::RecordVersion { key, version: live }),
        "live"
    );
    assert_eq!(
        seen[2].condition,
        Some(Condition::RecordVersion {
            key,
            version: deleted
        }),
        "held as deleted: named by its version"
    );
}

#[tokio::test]
async fn test_receive_context_second_message_builds_on_the_first() {
    let w = World::new();
    let protocol = ApiProtocol::new(Mode::Record);
    let mut app = join(&w, &protocol, "wallet").await;
    let (_, first) = w.note(app.app_id(), "one");
    let (second_seq, second) = w.note(app.app_id(), "two");
    app.receive(None).await.unwrap();
    assert_eq!(record_puts(&w), 2);
    let seen = protocol.seen();
    assert_eq!(seen.len(), 2, "no conflict: {seen:?}");
    assert!(seen.iter().all(|s| !s.conflict));
    assert!(
        seen[1].held.is_some(),
        "the second effect built on the first"
    );
    let key = app.record_key(&inbox()).unwrap();
    let record = app.shared_record(&key).await.unwrap().unwrap();
    assert_eq!(
        ids(record.content.value()),
        vec![first.msg_id, second.msg_id]
    );
    assert_eq!(app.service_cursor().seq, second_seq);
}

#[tokio::test]
async fn test_receive_context_conflict_reads_again_and_builds_again() {
    conflict_reads_again_and_builds_again().await;
}

/// An entry whose effect, built on what the app holds, meets `409 conflict`: it reads the
/// record again and builds again. Also run on a small stack.
async fn conflict_reads_again_and_builds_again() {
    let w = World::new();
    let protocol = ApiProtocol::new(Mode::Record);
    let store = Arc::new(MemoryStore::new()) as Arc<dyn StateStore>;
    let mut wallet = join_on(&w, &protocol, "wallet", &["sample-a"], store).await;
    let mut phone = join(&w, &protocol, "phone").await;
    wallet.receive(None).await.unwrap();
    let (_, note) = w.note(wallet.app_id(), "hello");
    // Another own app writes the record after the note: the wallet's effect, built on
    // what it holds, meets `409 conflict`.
    phone
        .put_record(&inbox(), &value(&["other"]), vec![])
        .await
        .unwrap();
    wallet.receive(None).await.unwrap();
    let seen: Vec<Seen> = protocol
        .seen()
        .into_iter()
        .filter(|s| s.msg_id == note.msg_id)
        .collect();
    assert_eq!(seen.len(), 2, "{seen:?}");
    assert!(!seen[0].conflict && seen[0].held.is_none());
    assert!(
        seen[1].conflict && seen[1].held.is_some(),
        "read again first"
    );
    let key = wallet.record_key(&inbox()).unwrap();
    let record = wallet.shared_record(&key).await.unwrap().unwrap();
    assert_eq!(
        ids(record.content.value()),
        vec!["other".to_owned(), note.msg_id]
    );
}

#[tokio::test]
async fn test_receive_context_without_the_current_key_waits_for_it() {
    let w = World::new();
    let protocol = ApiProtocol::new(Mode::Record);
    let mut app = join(&w, &protocol, "wallet").await;
    let cert = app.cert().clone();
    // A new data epoch whose keys haven't reached the app yet.
    w.next_doc(|body| body.data_epoch = 2);
    let (seq, note) = w.note(app.app_id(), "hello");
    app.receive(None).await.unwrap();
    assert_eq!(record_puts(&w), 0);
    // The entry waits for the key stored locally, with the cursor past it.
    assert_eq!(
        app.stored_at(seq).map(|stored| stored.reason),
        Some(crate::app::ParkReason::AwaitingKey { data_epoch: 2 })
    );
    assert!(app.cursor().seq >= seq, "the cursor passes the entry");
    // Once the bundle is there, the entry is handed over again and written.
    let has_keys = |scope: &str| SampleProtocol::default().has_keys(scope);
    for part in seal_bundle_parts(&w.alice, &cert, 1, 2, &has_keys).unwrap() {
        w.switch
            .signer_op(OpKind::KeyBundlePut(KeyBundlePut {
                target_app_id: app.app_id(),
                bundle: part.bundle,
                first_epoch: part.first_epoch,
                last_epoch: part.last_epoch,
            }))
            .unwrap();
    }
    app.receive(None).await.unwrap();
    assert_eq!(record_puts(&w), 1);
    assert!(app.stored_at(seq).is_none());
    let key = app.record_key(&inbox()).unwrap();
    let record = app.shared_record(&key).await.unwrap().unwrap();
    assert_eq!(ids(record.content.value()), vec![note.msg_id]);
}

#[tokio::test]
async fn test_receive_context_refuses_a_second_write_of_one_record() {
    let w = World::new();
    let protocol = ApiProtocol::new(Mode::RecordTwice);
    let mut app = join(&w, &protocol, "wallet").await;
    w.note(app.app_id(), "hello");
    app.receive(None).await.unwrap();
    let seen = protocol.seen();
    assert!(seen[0].writes[0].is_ok());
    let second = seen[0].writes[1].as_ref().unwrap_err();
    assert!(second.contains("one write per record"), "{second}");
    assert_eq!(record_puts(&w), 1);
}

#[tokio::test]
async fn test_receive_context_without_a_write_scope_is_refused() {
    let w = World::new();
    // The record's policy writes under `sample-b`, which the app doesn't hold.
    let protocol = ApiProtocol::new(Mode::OtherWriteScope);
    let mut app = join(&w, &protocol, "wallet").await;
    let (seq, _) = w.note(app.app_id(), "hello");
    app.receive(None).await.unwrap();
    let seen = protocol.seen();
    let refused = seen[0].writes[0].as_ref().unwrap_err();
    assert!(
        refused.contains(
            "Switch spec 10.3: the certificate lacks the scope required for the record write"
        ),
        "{refused}"
    );
    assert_eq!(record_puts(&w), 0);
    // The effect without the write still applies: the cursor passes the entry.
    assert_eq!(app.cursor().seq, seq);
}

#[tokio::test]
async fn test_receive_context_write_whose_mark_wont_fit_is_refused() {
    let w = World::new();
    let protocol = ApiProtocol::new(Mode::Record);
    let mut app = join(&w, &protocol, "wallet").await;
    *protocol.items.pad.lock().unwrap() = MAX_SEEN_MARK_BYTES;
    let (seq, _) = w.note(app.app_id(), "hello");
    app.receive(None).await.unwrap();
    let refused = protocol.seen()[0].writes[0].clone().unwrap_err();
    assert!(refused.contains("mark"), "{refused}");
    assert_eq!(record_puts(&w), 0);
    assert_eq!(app.cursor().seq, seq);
}

#[tokio::test]
async fn test_receive_context_value_that_isnt_json_is_refused_before_the_mark() {
    let w = World::new();
    let protocol = ApiProtocol::new(Mode::NotJson);
    let mut app = join(&w, &protocol, "wallet").await;
    // The mark queued for the next write is still there after the refusal: the protocol
    // was never asked to mark the value.
    protocol.items.pads.lock().unwrap().push_back(0);
    w.note(app.app_id(), "hello");
    app.receive(None).await.unwrap();
    let refused = protocol.seen()[0].writes[0].clone().unwrap_err();
    assert!(refused.contains("JSON"), "{refused}");
    assert_eq!(protocol.items.pads.lock().unwrap().len(), 1);
    assert_eq!(record_puts(&w), 0);
}

#[tokio::test]
async fn test_receive_context_writes_go_only_with_apply() {
    let w = World::new();
    let protocol = ApiProtocol::new(Mode::DropAfterWrite);
    let mut app = join(&w, &protocol, "wallet").await;
    let (seq, note) = w.note(app.app_id(), "hello");
    let report = app.receive(None).await.unwrap();
    assert!(
        report
            .events
            .iter()
            .any(|e| matches!(e, AppEvent::MessageDropped { seq: s, check: 10, .. } if *s == seq))
    );
    assert_eq!(record_puts(&w), 0);
    let local = format!("notes/{}", note.msg_id);
    assert!(
        app.protocol_get("sample", local.as_bytes())
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(app.cursor().seq, seq);
}

#[tokio::test]
async fn test_receive_context_claim_goes_in_the_effect_and_is_checked() {
    let w = World::new();
    let protocol = ApiProtocol::new(Mode::Attempt);
    let mut app = join(&w, &protocol, "wallet").await;
    let (seq, _) = w.note(app.app_id(), "done");
    let report = app.receive(None).await.unwrap();
    assert!(protocol.seen()[0].writes[0].is_ok());
    assert!(
        !report
            .events
            .iter()
            .any(|e| matches!(e, AppEvent::AttemptNotHeld { .. })),
        "{:?}",
        report.events
    );
    let evidence = app.claim_evidence(&CLAIM).await.unwrap().unwrap();
    assert_eq!(evidence.view.status, ClaimStatus::Attempting);
    assert_eq!(evidence.own_deadline, ObligationDeadline::NoDeadline);
    assert_eq!(w.switch.app(&app.app_id()).cursor, seq);
}

#[tokio::test]
async fn test_receive_context_attempt_refused_in_reconcile_mode() {
    let w = World::new();
    let protocol = ApiProtocol::new(Mode::Attempt);
    let app = join(&w, &protocol, "wallet").await;
    let backup = app.backup().await.unwrap();
    drop(app);
    let store = Arc::new(MemoryStore::new()) as Arc<dyn StateStore>;
    let mut app = App::restore(w.env_on(store), protocol.clone(), config(), &backup)
        .await
        .unwrap();
    assert!(app.reconcile_mode());
    w.note(app.app_id(), "done");
    app.receive(None).await.unwrap();
    let refused = protocol.seen()[0].writes[0].clone().unwrap_err();
    assert!(refused.contains("no attempt"), "{refused}");
    assert!(w.switch.claim(&CLAIM).is_none());
}

/// One run of the receiving scenario: join, two notes from bob, read them. Returns at the
/// first error, as a process that died.
async fn receive_scenario(
    w: &World,
    protocol: &Arc<ApiProtocol>,
    store: Arc<dyn StateStore>,
    sent: &mut Vec<(u64, String)>,
    approval: &mut Option<JoinRequest>,
) -> Result<(), AppError> {
    let keys = app_keys("wallet");
    let env = w.env_on(Arc::clone(&store));
    let mut app =
        match App::load(env.clone(), protocol.clone(), config(), keys.app_id_bytes()).await {
            Ok(app) => app,
            Err(AppError::Refused(Refusal::NotJoined)) => {
                let request = approval
                    .get_or_insert_with(|| w.approve(&keys, &["sample-a"]))
                    .clone();
                App::join(env, protocol.clone(), config(), request).await?
            }
            Err(error) => return Err(error),
        };
    app.receive(None).await?;
    while sent.len() < 2 {
        let (seq, note) = w.note(app.app_id(), &format!("note {}", sent.len()));
        sent.push((seq, note.msg_id));
    }
    app.receive(None).await?;
    app.receive(None).await?;
    Ok(())
}

#[tokio::test]
async fn test_receive_context_crash_at_each_commit_point_writes_each_effect_once() {
    let commits = {
        let w = World::new();
        let counting = Arc::new(FaultStore::new(
            Arc::new(MemoryStore::new()) as Arc<dyn StateStore>,
            StoreFault::None,
        ));
        receive_scenario(
            &w,
            &ApiProtocol::new(Mode::Record),
            Arc::clone(&counting) as Arc<dyn StateStore>,
            &mut Vec::new(),
            &mut None,
        )
        .await
        .unwrap();
        counting.commits()
    };
    assert!(commits > 6, "the scenario commits {commits} times");
    for stop_after in [false, true] {
        for n in 1..=commits {
            let w = World::new();
            let protocol = ApiProtocol::new(Mode::Record);
            let inner = Arc::new(MemoryStore::new());
            let fault = Arc::new(FaultStore::new(
                Arc::clone(&inner) as Arc<dyn StateStore>,
                if stop_after {
                    StoreFault::StopAfter(n)
                } else {
                    StoreFault::StopBefore(n)
                },
            ));
            let mut sent = Vec::new();
            let mut approval = None;
            let first = receive_scenario(
                &w,
                &protocol,
                Arc::clone(&fault) as Arc<dyn StateStore>,
                &mut sent,
                &mut approval,
            )
            .await;
            assert!(fault.stopped(), "commit {n} of {commits} is reached");
            assert!(first.is_err());
            receive_scenario(
                &w,
                &protocol,
                Arc::clone(&inner) as Arc<dyn StateStore>,
                &mut sent,
                &mut approval,
            )
            .await
            .unwrap_or_else(|e| panic!("restart after commit {n} ({stop_after}): {e}"));
            let app = App::load(
                w.env_on(Arc::clone(&inner) as Arc<dyn StateStore>),
                protocol.clone(),
                config(),
                app_keys("wallet").app_id_bytes(),
            )
            .await
            .unwrap();
            // Each note's record write applied once, both in the record, the cursor past.
            assert_eq!(record_puts(&w), 2, "commit {n} ({stop_after})");
            let key = app.record_key(&inbox()).unwrap();
            let record = app.shared_record(&key).await.unwrap().unwrap();
            let expected: Vec<String> = sent.iter().map(|(_, id)| id.clone()).collect();
            assert_eq!(
                ids(record.content.value()),
                expected,
                "commit {n} ({stop_after})"
            );
            assert!(app.cursor().seq >= sent[1].0, "commit {n} ({stop_after})");
            for (_, msg_id) in &sent {
                let local = format!("notes/{msg_id}");
                assert!(
                    app.protocol_get("sample", local.as_bytes())
                        .await
                        .unwrap()
                        .is_some()
                );
            }
        }
    }
}

// -------------------------------------------------------------------------------------
// The protocol's local state

#[tokio::test]
async fn test_protocol_commit_and_scan_in_key_order() {
    let w = World::new();
    let mut app = join(&w, &ApiProtocol::new(Mode::Plain), "wallet").await;
    let put = |key: &str, value: &str| LocalWrite::Put {
        key: key.as_bytes().to_vec(),
        value: value.as_bytes().to_vec(),
    };
    app.protocol_commit(
        "sample",
        &[put("a/2", "two"), put("b/1", "x"), put("a/1", "one")],
    )
    .await
    .unwrap();
    let scanned = app.protocol_scan("sample", b"a/").await.unwrap();
    assert_eq!(
        scanned,
        vec![
            (b"a/1".to_vec(), b"one".to_vec()),
            (b"a/2".to_vec(), b"two".to_vec())
        ]
    );
    app.protocol_commit(
        "sample",
        &[LocalWrite::DeletePrefix {
            prefix: b"a/".to_vec(),
        }],
    )
    .await
    .unwrap();
    assert!(app.protocol_scan("sample", b"a/").await.unwrap().is_empty());
    assert_eq!(app.protocol_scan("sample", b"").await.unwrap().len(), 1);
}

#[tokio::test]
async fn test_protocol_commit_refused_once_the_keys_are_deleted() {
    let w = World::new();
    let mut app = join(&w, &ApiProtocol::new(Mode::Plain), "wallet").await;
    app.leave(crate::app::LeaveMode::Immediate(
        crate::app::UserConfirmed::new(),
    ))
    .await
    .unwrap();
    let error = app
        .protocol_commit(
            "sample",
            &[LocalWrite::Put {
                key: b"k".to_vec(),
                value: b"v".to_vec(),
            }],
        )
        .await
        .unwrap_err();
    assert_eq!(error, AppError::Refused(Refusal::Left));
}

#[tokio::test]
async fn test_batch_local_writes_commit_with_the_answer_only() {
    let w = World::new();
    let mut app = join(&w, &ApiProtocol::new(Mode::Plain), "wallet").await;
    let write = |key: &str| LocalWrite::Put {
        key: key.as_bytes().to_vec(),
        value: b"1".to_vec(),
    };
    app.submit_batch(
        OpBatch::for_protocol("sample")
            .op(OpKind::DenyPut { pubky: [9; 32] })
            .local(write("applied")),
    )
    .await
    .unwrap();
    assert!(
        app.protocol_get("sample", b"applied")
            .await
            .unwrap()
            .is_some()
    );
    // A batch refused for good commits none of its local writes.
    let key = app.record_key(&inbox()).unwrap();
    let wrong = Condition::RecordVersion {
        key,
        version: RecordVersion::new(1, 99),
    };
    let entry = app
        .record_op(&inbox(), Some(&value(&["a"])), vec![wrong])
        .await
        .unwrap();
    let error = app
        .submit_batch(
            OpBatch::for_protocol("sample")
                .entry(entry)
                .locals([write("refused")]),
        )
        .await
        .unwrap_err();
    assert_eq!(error.code(), Some(ErrorCode::Conflict));
    assert!(
        app.protocol_get("sample", b"refused")
            .await
            .unwrap()
            .is_none()
    );
}

// -------------------------------------------------------------------------------------
// The attempts of a protocol's own batches (Switch wire 6.5 "Binding")

#[tokio::test]
async fn test_submit_batch_checks_its_attempt_with_another_write() {
    let w = World::new();
    let mut app = join(&w, &ApiProtocol::new(Mode::Plain), "wallet").await;
    let entry = app
        .record_op(&inbox(), Some(&value(&["working"])), vec![])
        .await
        .unwrap();
    let attempt = ClaimOp::attempt(CLAIM, 0, ATTEMPT, 3600, None);
    let submitted = app
        .submit_batch(OpBatch::new().op(attempt.kind()).entry(entry))
        .await
        .unwrap();
    assert_eq!(submitted.proofs.len(), 2);
    let claim = w.switch.claim(&CLAIM).unwrap();
    assert_eq!(claim.step, 1);
}

/// An own attempt and a record write, signed by the app and sent apart from
/// [`App::submit_batch`]: the batch and its verified answer.
async fn send_apart(
    app: &mut App,
    orphan_after_s: u64,
) -> (crate::client::Batch, crate::client::Submitted) {
    let entry = app
        .record_op(&inbox(), Some(&value(&["working"])), vec![])
        .await
        .unwrap();
    let attempt = ClaimOp::attempt(CLAIM, 0, ATTEMPT, orphan_after_s, None);
    let batch = app
        .sign_ops(vec![(Vec::new(), attempt.kind()), entry], None)
        .unwrap();
    let submitted = app.submit(&batch).await.unwrap();
    (batch, submitted)
}

#[tokio::test]
async fn test_check_attempt_takes_the_proof_bound_to_its_operation() {
    let w = World::new();
    let mut app = join(&w, &ApiProtocol::new(Mode::Plain), "wallet").await;
    let (batch, submitted) = send_apart(&mut app, 3600).await;
    let (op, proof) = (batch.ops()[0].signed(), submitted.proofs[0].signed());
    let view = app.check_attempt(op, proof).await.unwrap();
    assert_eq!(view.owner, Some(app.app_id()));
    assert_eq!(view.status, ClaimStatus::Attempting);
    // The record write's own proof, with the record write: not an attempt.
    let error = app
        .check_attempt(batch.ops()[1].signed(), submitted.proofs[1].signed())
        .await
        .unwrap_err();
    assert!(matches!(error, AppError::Refused(Refusal::Usage(_))));
}

#[tokio::test]
async fn test_check_attempt_refuses_a_proof_of_another_operation() {
    let w = World::new();
    let mut app = join(&w, &ApiProtocol::new(Mode::Plain), "wallet").await;
    let (batch, submitted) = send_apart(&mut app, 3600).await;
    let proof = submitted.proofs[0].signed();
    // The same attempt, orphaned after another time: another operation the switch never took.
    let other = ClaimOp::attempt(CLAIM, 0, ATTEMPT, 1200, None);
    let unsent = app
        .sign_ops(vec![(Vec::new(), other.kind())], None)
        .unwrap();
    let error = app
        .check_attempt(unsent.ops()[0].signed(), proof)
        .await
        .unwrap_err();
    assert!(matches!(error, AppError::InvalidData(_)), "{error:?}");
    // The proof of the other operation in the same batch.
    let error = app
        .check_attempt(batch.ops()[0].signed(), submitted.proofs[1].signed())
        .await
        .unwrap_err();
    assert!(matches!(error, AppError::InvalidData(_)), "{error:?}");
    // Nothing was written: the attempt is still open, and its own proof still passes.
    assert_eq!(w.switch.claim(&CLAIM).unwrap().step, 1);
    app.check_attempt(batch.ops()[0].signed(), proof)
        .await
        .unwrap();
}

#[tokio::test]
async fn test_check_attempt_refuses_a_proof_that_doesnt_verify() {
    let w = World::new();
    let mut app = join(&w, &ApiProtocol::new(Mode::Plain), "wallet").await;
    let (batch, submitted) = send_apart(&mut app, 3600).await;
    let op = batch.ops()[0].signed();
    let genuine = &submitted.proofs[0];
    // A signature that doesn't verify.
    let mut sig = genuine.signed().sig_bytes().unwrap();
    sig[0] ^= 1;
    let tampered = SignedDoc::from_parts(&genuine.signed().body_bytes().unwrap(), &sig);
    let error = app.check_attempt(op, &tampered).await.unwrap_err();
    assert!(matches!(error, AppError::InvalidData(_)), "{error:?}");
    // The same body, signed by another key.
    let other_key = ed25519_dalek::SigningKey::from_bytes(&[9; 32]);
    let forged =
        TransitionProof::sign(&other_key, &w.alice.public(), genuine.body().clone()).unwrap();
    let error = app.check_attempt(op, forged.signed()).await.unwrap_err();
    assert!(matches!(error, AppError::InvalidData(_)), "{error:?}");
    // An operation that isn't signed by the app's key.
    let mut op_sig = op.sig_bytes().unwrap();
    op_sig[0] ^= 1;
    let unsigned = SignedDoc::from_parts(&op.body_bytes().unwrap(), &op_sig);
    let error = app
        .check_attempt(&unsigned, genuine.signed())
        .await
        .unwrap_err();
    assert!(matches!(error, AppError::Refused(Refusal::Usage(_))));
    // Nothing was written.
    assert_eq!(w.switch.claim(&CLAIM).unwrap().step, 1);
    app.check_attempt(op, genuine.signed()).await.unwrap();
}

#[tokio::test]
async fn test_check_attempt_writes_failed_for_a_bound_proof_of_another_state() {
    let w = World::new();
    let mut app = join(&w, &ApiProtocol::new(Mode::Plain), "wallet").await;
    let (batch, submitted) = send_apart(&mut app, 3600).await;
    // A proof the service key signed that binds the attempt but shows the claim settled.
    let service = ed25519_dalek::SigningKey::from_bytes(&identity("alice").service_secret());
    assert_eq!(service.verifying_key().to_bytes(), w.switch.service_key());
    let mut body = submitted.proofs[0].body().clone();
    body.state["state"] = "SETTLED".into();
    let shown = TransitionProof::sign(&service, &w.alice.public(), body).unwrap();
    let error = app
        .check_attempt(batch.ops()[0].signed(), shown.signed())
        .await
        .unwrap_err();
    assert!(matches!(error, AppError::InvalidData(_)), "{error:?}");
    // Written failed after the attempt.
    let claim = w.switch.claim(&CLAIM).unwrap();
    assert_eq!(claim.step, 2);
}

/// Stop `app` on equivocation: another body at the version of its own `identity.json`.
async fn stop_on_equivocation(w: &World, app: &mut App) {
    let doc = w.next_doc(|_| {});
    app.receive(None).await.unwrap();
    let mut body = doc.body().clone();
    body.data_epoch += 1;
    w.switch
        .deliver_identity(&IdentityDoc::sign(&w.alice, body).unwrap())
        .unwrap();
    let error = app.receive(None).await.unwrap_err();
    assert!(matches!(error, AppError::Alarm(_)), "{error:?}");
    assert_eq!(app.may_attempt(false), Err(Refusal::Stopped));
}

#[tokio::test]
async fn test_check_attempt_refuses_a_stopped_app() {
    let w = World::new();
    let mut app = join(&w, &ApiProtocol::new(Mode::Plain), "wallet").await;
    let (batch, submitted) = send_apart(&mut app, 3600).await;
    stop_on_equivocation(&w, &mut app).await;
    let op = batch.ops()[0].signed();
    // The genuine proof isn't taken.
    let error = app
        .check_attempt(op, submitted.proofs[0].signed())
        .await
        .unwrap_err();
    assert_eq!(error, AppError::Refused(Refusal::Stopped));
    // Nor is a proof of another state, and nothing is written failed.
    let service = ed25519_dalek::SigningKey::from_bytes(&identity("alice").service_secret());
    let mut body = submitted.proofs[0].body().clone();
    body.state["state"] = "SETTLED".into();
    let shown = TransitionProof::sign(&service, &w.alice.public(), body).unwrap();
    let error = app.check_attempt(op, shown.signed()).await.unwrap_err();
    assert_eq!(error, AppError::Refused(Refusal::Stopped));
    assert_eq!(w.switch.claim(&CLAIM).unwrap().step, 1);
}

#[tokio::test]
async fn test_record_op_and_key_fetch_refuse_a_stopped_app() {
    let w = World::new();
    let mut app = join(&w, &ApiProtocol::new(Mode::Plain), "wallet").await;
    app.record_op(&inbox(), Some(&value(&["a"])), vec![])
        .await
        .unwrap();
    app.fetch_key_bundle().await.unwrap();
    stop_on_equivocation(&w, &mut app).await;
    let error = app
        .record_op(&inbox(), Some(&value(&["a"])), vec![])
        .await
        .unwrap_err();
    assert_eq!(error, AppError::Refused(Refusal::Stopped));
    let error = app
        .put_record(&inbox(), &value(&["a"]), vec![])
        .await
        .unwrap_err();
    assert_eq!(error, AppError::Refused(Refusal::Stopped));
    assert_eq!(
        app.fetch_key_bundle().await.unwrap_err(),
        AppError::Refused(Refusal::Stopped)
    );
}

#[tokio::test]
async fn test_submit_batch_refuses_an_attempt_in_reconcile_mode() {
    let w = World::new();
    let app = join(&w, &ApiProtocol::new(Mode::Plain), "wallet").await;
    let backup = app.backup().await.unwrap();
    let mut app = App::restore(
        w.env_on(Arc::new(MemoryStore::new())),
        ApiProtocol::new(Mode::Plain),
        config(),
        &backup,
    )
    .await
    .unwrap();
    let attempt = ClaimOp::attempt(CLAIM, 0, ATTEMPT, 3600, None);
    let error = app
        .submit_batch(
            OpBatch::new()
                .op(OpKind::DenyPut { pubky: [9; 32] })
                .op(attempt.kind()),
        )
        .await
        .unwrap_err();
    assert!(
        matches!(error, AppError::Refused(Refusal::NotNow(_))),
        "{error:?}"
    );
    assert!(w.switch.claim(&CLAIM).is_none());
}

// -------------------------------------------------------------------------------------
// The highest verified service time (Switch spec 10.1)

#[tokio::test]
async fn test_highest_service_time_follows_verified_answers() {
    let w = World::new();
    let mut app = join(&w, &ApiProtocol::new(Mode::Plain), "wallet").await;
    assert_eq!(app.highest_service_time(), Some(START));
    w.clock.advance_ms(MINUTE);
    app.receive(None).await.unwrap();
    assert_eq!(app.highest_service_time(), Some(START + MINUTE));
    // A restored app has verified nothing yet.
    let backup = app.backup().await.unwrap();
    let restored = App::restore(
        w.env_on(Arc::new(MemoryStore::new())),
        ApiProtocol::new(Mode::Plain),
        config(),
        &backup,
    )
    .await
    .unwrap();
    assert_eq!(restored.highest_service_time(), None);
}

// -------------------------------------------------------------------------------------
// A policy per sub-scope (Switch spec 3.3, 10.3)

fn family() -> Collection {
    Collection::with_sub_scopes("sample.items", Policy::new("sample-a", &["sample-a"]))
}

#[tokio::test]
async fn test_policy_family_lists_and_takes_a_sub_scope_record() {
    let w = World::new();
    let protocol = ApiProtocol::new(Mode::Plain);
    *protocol.collections.lock().unwrap() = vec![family()];
    let mut wallet = join(&w, &protocol, "wallet").await;
    let mut kiosk = join_on(
        &w,
        &protocol,
        "kiosk",
        &["sample-a:kiosk"],
        Arc::new(MemoryStore::new()),
    )
    .await;
    let target = RecordTarget::new(family().sub_scope("kiosk").unwrap(), b"k1");
    let written = kiosk
        .put_record(&target, &value(&["first"]), vec![])
        .await
        .unwrap();
    assert_eq!(written.policy, family().sub_scope_policy("kiosk").unwrap());
    // Listed by the name scope's holder, under the family.
    assert_eq!(wallet.list_collection(&family()).await.unwrap().records, 1);
    let held = wallet.records_of("sample.items").await.unwrap();
    assert_eq!(held.len(), 1);
    assert_eq!(ids(held[0].content.value()), vec!["first".to_owned()]);
    assert!(wallet.flagged_writes().await.unwrap().is_empty());
    // And from the feed, by a later write.
    kiosk
        .put_record(&target, &value(&["first", "second"]), vec![])
        .await
        .unwrap();
    wallet.receive(None).await.unwrap();
    let key = wallet.record_key(&target).unwrap();
    let record = wallet.shared_record(&key).await.unwrap().unwrap();
    assert_eq!(ids(record.content.value()).len(), 2);
}

#[tokio::test]
async fn test_policy_family_fixed_collection_flags_a_sub_scope_record() {
    let w = World::new();
    let protocol = ApiProtocol::new(Mode::Plain);
    let mut wallet = join(&w, &protocol, "wallet").await;
    let mut kiosk = join_on(
        &w,
        &protocol,
        "kiosk",
        &["sample-a:kiosk"],
        Arc::new(MemoryStore::new()),
    )
    .await;
    let target = RecordTarget::new(family().sub_scope("kiosk").unwrap(), b"k1");
    kiosk
        .put_record(&target, &value(&["first"]), vec![])
        .await
        .unwrap();
    // The fixed policy alone: the sub-scope's write isn't the collection's.
    assert_eq!(wallet.list_collection(&items()).await.unwrap().records, 1);
    assert!(wallet.records_of("sample.items").await.unwrap().is_empty());
    let flagged = wallet.flagged_writes().await.unwrap();
    assert_eq!(flagged.len(), 1);
    assert!(flagged[0].reason.contains("step 3"), "{flagged:?}");
}

#[test]
fn test_policy_family_named_permanent_generations_checks_every_policy_member() {
    let family = Collection::with_permanent_generations("c", "name", &["name", "other"]);
    for generation in [1, 2, pubky_switch_core::json::MAX_INT] {
        assert!(family.admits(&family.policy.clone().permanent(Some(generation))));
    }
    for policy in [
        family.policy.clone(),
        family.policy.clone().permanent(None),
        family.policy.clone().permanent(Some(0)),
        family
            .policy
            .clone()
            .permanent(Some(pubky_switch_core::json::MAX_INT + 1)),
        Policy::new("else", &["name", "other"]).permanent(Some(1)),
        Policy::new("name", &["name"]).permanent(Some(1)),
        Policy::new("name", &["name", "other", "another"]).permanent(Some(1)),
    ] {
        assert!(!family.admits(&policy), "{policy:?}");
    }
}

#[test]
fn test_policy_family_members_follow_the_scope_rule() {
    let family = Collection {
        name: "c".into(),
        policy: Policy::new("name", &["name", "other"]),
        family: PolicyFamily::SubScopes,
    };
    let sub = family.sub_scope_policy("shop").unwrap();
    assert_eq!(sub, Policy::new("name:shop", &["name:shop", "other"]));
    assert_eq!(family.member(&sub), Some(Some("shop".into())));
    assert_eq!(family.member(&family.policy), Some(None));
    // Not members: another name's sub-scope, another write scope, a bad sub-scope.
    assert!(!family.admits(&Policy::new("else:shop", &["else:shop", "other"])));
    assert!(!family.admits(&Policy::new("name:shop", &["name:shop"])));
    assert!(family.sub_scope_policy("Bad Sub").is_err());
    // A fixed collection has no sub-scope policies.
    let fixed = Collection::new("c", Policy::new("name", &["name"]));
    assert!(fixed.sub_scope_policy("shop").is_err());
    assert!(!fixed.admits(&Policy::new("name:shop", &["name:shop"])));
    // Nor does a family whose fixed read scope is a sub-scope itself.
    let nested = Collection::with_sub_scopes("c", Policy::new("name:x", &["name:x"]));
    assert!(nested.sub_scope_policy("shop").is_err());
}

#[test]
fn test_policy_family_readable_by_a_sub_scope_holder() {
    let alice = identity("alice");
    let sub = cert_for(alice.key(), &app_keys("kiosk"), START, &["sample-a:kiosk"]);
    let other = cert_for(alice.key(), &app_keys("other"), START, &["sample-b"]);
    assert!(family().readable_by(&sub));
    assert!(!items().readable_by(&sub));
    assert!(!family().readable_by(&other));
}

// -------------------------------------------------------------------------------------
// Two identities, each on its own scripted switch (Switch spec 7; Switch wire 7.4.3)

/// Alice, bob and carol, each with a signer and a scripted switch at an origin of its own,
/// a router between them, and one Homeserver.
pub(super) struct Pair {
    pub(super) clock: Arc<crate::clock::TestClock>,
    pub(super) alice: TestSigner,
    pub(super) bob: TestSigner,
    pub(super) carol: TestSigner,
    pub(super) router: Arc<Router>,
}

impl Pair {
    pub(super) fn new() -> Self {
        let clock = Arc::new(crate::clock::TestClock::new(START));
        let homeserver = Arc::new(TestHomeserver::new());
        let signer = |name: &str, origin: &str| {
            TestSigner::at(
                identity(name),
                origin,
                Arc::clone(&clock),
                Arc::clone(&homeserver),
                sample_spec(),
            )
        };
        let alice = signer("alice", SWITCH_ORIGIN);
        let bob = signer("bob", BOB_ORIGIN);
        let carol = signer("carol", CAROL_ORIGIN);
        let router = Arc::new(Router::new());
        router.add_switch(SWITCH_ORIGIN, alice.switch());
        router.add_switch(BOB_ORIGIN, bob.switch());
        router.add_switch(CAROL_ORIGIN, carol.switch());
        Self {
            clock,
            alice,
            bob,
            carol,
            router,
        }
    }

    pub(super) async fn join_on(
        &self,
        signer: &TestSigner,
        name: &str,
        protocol: Arc<dyn Protocol>,
        store: Arc<dyn StateStore>,
    ) -> App {
        self.join_with(signer, name, protocol, store, &Permission::ALL)
            .await
    }

    /// `name` of `signer`'s identity on `store`, with `permissions`.
    async fn join_with(
        &self,
        signer: &TestSigner,
        name: &str,
        protocol: Arc<dyn Protocol>,
        store: Arc<dyn StateStore>,
        permissions: &[Permission],
    ) -> App {
        let keys = signer.identity().app_keys(name);
        let app = AppSpec::new(&["sample-a"]).with_permissions(permissions);
        let request = signer.approve(&keys, &app).unwrap();
        App::join(self.env(signer, store), protocol, config(), request)
            .await
            .unwrap()
    }

    fn env(&self, signer: &TestSigner, store: Arc<dyn StateStore>) -> AppEnv {
        signer.env_with(store, Arc::clone(&self.router) as Arc<dyn Transport>)
    }

    /// `name` of `signer`'s identity on a store of its own, with every permission, running
    /// `protocols` with the scopes `scopes`.
    pub(super) async fn join_set(
        &self,
        signer: &TestSigner,
        name: &str,
        protocols: crate::app::ProtocolSet,
        scopes: &[&str],
    ) -> App {
        let keys = signer.identity().app_keys(name);
        let app = AppSpec::new(scopes).with_permissions(&Permission::ALL);
        let request = signer.approve(&keys, &app).unwrap();
        let store = Arc::new(MemoryStore::new()) as Arc<dyn StateStore>;
        App::join(self.env(signer, store), protocols, config(), request)
            .await
            .unwrap()
    }

    async fn join(&self, signer: &TestSigner, name: &str, protocol: &Arc<ApiProtocol>) -> App {
        self.join_on(signer, name, protocol.clone(), Arc::new(MemoryStore::new()))
            .await
    }

    pub(super) fn note(to: &TestSigner, text: &str) -> OutgoingMessage {
        let mut body = Map::new();
        body.insert("text".into(), json!(text));
        OutgoingMessage::new(to.identity().public(), "sample.note", body)
    }
}

fn queued_with(delivery: &Delivery, code: &str) -> bool {
    matches!(delivery, Delivery::Queued { last_error: Some(e), .. } if e.contains(code))
}

#[tokio::test]
async fn test_scripted_inbox_refuses_a_sender_not_admitted() {
    let p = Pair::new();
    let protocol = ApiProtocol::new(Mode::Plain);
    let mut wallet = p.join(&p.alice, "wallet", &protocol).await;
    let _shop = p.join(&p.bob, "shop", &protocol).await;
    let (_, delivery) = wallet.send(Pair::note(&p.bob, "hello")).await.unwrap();
    assert!(queued_with(&delivery, "not_admitted"), "{delivery:?}");
    assert_eq!(p.bob.switch().entries_from(&p.alice.identity().public()), 0);
}

#[tokio::test]
async fn test_outbox_try_too_large_for_the_store_gives_the_message_up() {
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
    let _shop = p.join(&p.bob, "shop", &protocol).await;
    let (msg_id, delivery) = wallet.send(Pair::note(&p.bob, "hello")).await.unwrap();
    assert!(queued_with(&delivery, "not_admitted"), "{delivery:?}");
    wallet.take_events();
    // Every write of the message is now over the store's sizes: no try can be kept.
    store.refuse_puts_as_too_large(Some(b"out/"));
    let report = wallet.flush_outbox().await.unwrap();
    assert_eq!(report.undelivered, vec![msg_id.clone()]);
    assert!(
        wallet.take_events().iter().any(|e| matches!(
            e,
            AppEvent::MessageUndelivered { msg_id: m, resend: false, .. } if *m == msg_id
        )),
        "the protocol is told"
    );
    // Given up for good: later flushes go on, and don't try it again.
    let appends = p.bob.switch().entries_from(&p.alice.identity().public());
    let report = wallet.flush_outbox().await.unwrap();
    assert!(
        report.queued.is_empty() && report.undelivered.is_empty(),
        "{report:?}"
    );
    assert_eq!(wallet.delivery(&msg_id).await.unwrap(), None);
    assert_eq!(
        p.bob.switch().entries_from(&p.alice.identity().public()),
        appends
    );
}

/// A transport for bob's switch that fails its next inbox appends as unreachable, one for
/// each of `texts`, with that text.
struct FailingWith {
    inner: Arc<dyn Transport>,
    texts: Mutex<std::collections::VecDeque<String>>,
}

impl FailingWith {
    fn at(p: &Pair, texts: impl IntoIterator<Item = String>) {
        p.router.add(
            BOB_ORIGIN,
            Arc::new(Self {
                inner: p.bob.switch().transport(),
                texts: Mutex::new(texts.into_iter().collect()),
            }),
        );
    }
}

impl Transport for FailingWith {
    fn send(
        &self,
        request: crate::transport::Request,
    ) -> crate::transport::BoxFuture<
        '_,
        Result<crate::transport::Response, crate::transport::TransportError>,
    > {
        Box::pin(async move {
            if request.method == "POST"
                && request.path_and_query.contains("/inbox")
                && let Some(text) = self.texts.lock().unwrap().pop_front()
            {
                return Err(crate::transport::TransportError::Connect(text));
            }
            self.inner.send(request).await
        })
    }
}

/// Whether `events` tell a delivery given up.
fn tells_a_give_up(events: &[AppEvent]) -> bool {
    events.iter().any(|e| {
        matches!(
            e,
            AppEvent::MessageUndelivered { .. } | AppEvent::DeliveryUnknown { .. }
        )
    })
}

/// A try that fails with a text longer than a store value takes leaves the message queued,
/// its failure kept cut short: what a failure says never decides whether a queued message
/// survives. The next try delivers it.
#[tokio::test]
async fn test_outbox_try_failing_with_a_very_long_text_keeps_the_message() {
    let p = Pair::new();
    let protocol = ApiProtocol::new(Mode::Plain);
    let mut app = p.join(&p.alice, "sender", &protocol).await;
    let mut peer = p.join(&p.bob, "recipient", &protocol).await;
    let alice = p.alice.identity().public();
    peer.invite(&alice).await.unwrap();
    let signed = app.sign_message(Pair::note(&p.bob, "hello")).unwrap();
    let msg_id = app.queue_signed(signed).await.unwrap();
    let long = "x".repeat(usize::try_from(crate::store::MAX_VALUE_BYTES).unwrap() + 1);
    FailingWith::at(&p, [long]);
    let report = app.flush_outbox().await.unwrap();
    assert!(
        report.undelivered.is_empty() && report.unknown.is_empty(),
        "{report:?}"
    );
    let delivery = app.delivery(&msg_id).await.unwrap();
    assert!(
        matches!(&delivery, Some(Delivery::Queued { last_error: Some(e), .. })
            if e.contains("connection failed: x")
                && e.len() == crate::app::send::MAX_DIAGNOSTIC_BYTES),
        "still queued, its failure cut short"
    );
    assert!(!tells_a_give_up(&app.take_events()));
    assert_eq!(p.bob.switch().entries_from(&alice), 0);
    p.clock.advance_ms(10 * MINUTE);
    app.flush_outbox().await.unwrap();
    assert_eq!(p.bob.switch().entries_from(&alice), 1, "delivered");
}

/// An outbox record the store takes only without its last failure's text is written
/// without it: the message stays queued, and the next try delivers it.
#[tokio::test]
async fn test_outbox_record_that_fits_only_without_its_failure_text_is_kept() {
    let p = Pair::new();
    let protocol = ApiProtocol::new(Mode::Plain);
    let (mut app, mut peer, store) = wallet_on_a_fault_store(&p, &protocol).await;
    let alice = p.alice.identity().public();
    peer.invite(&alice).await.unwrap();
    let signed = app.sign_message(Pair::note(&p.bob, "hello")).unwrap();
    let msg_id = app.queue_signed(signed).await.unwrap();
    FailingWith::at(&p, ["down".to_owned(), "y".repeat(300)]);
    app.flush_outbox().await.unwrap();
    // The store takes the record as it is after the first failure, and none larger.
    let record = app.reader().scan_raw("out/").await.unwrap();
    store.refuse_puts_as_too_large_over(Some(b"out/"), record[0].1.len());
    p.clock.advance_ms(10 * MINUTE);
    let report = app.flush_outbox().await.unwrap();
    assert!(
        report.undelivered.is_empty() && report.unknown.is_empty(),
        "{report:?}"
    );
    assert!(
        matches!(
            app.delivery(&msg_id).await.unwrap(),
            Some(Delivery::Queued {
                tries: 2,
                last_error: None,
                ..
            })
        ),
        "still queued, tried twice, without the text that didn't fit"
    );
    assert!(!tells_a_give_up(&app.take_events()));
    p.clock.advance_ms(10 * MINUTE);
    app.flush_outbox().await.unwrap();
    assert_eq!(p.bob.switch().entries_from(&alice), 1, "delivered");
}

#[tokio::test]
async fn test_outbox_message_too_large_for_the_store_holds_up_no_later_one() {
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
    let (first, _) = wallet.send(Pair::note(&p.bob, "first")).await.unwrap();
    let (second, _) = wallet.send(Pair::note(&p.bob, "second")).await.unwrap();
    // Only the first message's own writes are over the store's sizes now.
    store.refuse_puts_as_too_large(Some(format!("out/{first}").as_bytes()));
    shop.invite(&p.alice.identity().public()).await.unwrap();
    let report = wallet.flush_outbox().await.unwrap();
    assert_eq!(report.undelivered, vec![first.clone()]);
    // The flush went on to the later message, which is delivered.
    assert_eq!(report.done, vec![second.clone()], "{report:?}");
    assert!(matches!(
        wallet.delivery(&second).await.unwrap(),
        Some(Delivery::Accepted { .. })
    ));
}

#[tokio::test]
async fn test_send_to_a_directory_too_large_to_cache_goes_and_caches_its_stub() {
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
    shop.invite(&p.alice.identity().public()).await.unwrap();
    // Bob's directory doesn't fit one value of the wallet's store; its stub does.
    store.refuse_puts_as_too_large_over(Some(b"dir/"), 1024);
    let reads = directory_reads(&p);
    for text in ["one", "two"] {
        let (msg_id, delivery) = wallet.send(Pair::note(&p.bob, text)).await.unwrap();
        assert!(
            matches!(delivery, Delivery::Accepted { .. }),
            "{delivery:?}"
        );
        assert!(matches!(
            wallet.delivery(&msg_id).await.unwrap(),
            Some(Delivery::Accepted { .. })
        ));
    }
    // Only its stub cached, with no apps and stale: each send read it again.
    assert_eq!(directory_reads(&p), reads + 2);
    let ns = crate::store::client_namespace(&wallet.app_id());
    let kept = store.inner().scan(&ns, b"dir/", None, 10).unwrap();
    assert_eq!(kept.len(), 1);
    let stub: crate::app::directory::CachedDirectory =
        crate::app::state::decode(&kept[0].1).unwrap();
    assert!(stub.apps.is_empty() && stub.stale);
}

/// Alice's wallet on a [`FaultStore`] over a new store, and bob's shop admitting her.
async fn wallet_on_a_fault_store(
    p: &Pair,
    protocol: &Arc<ApiProtocol>,
) -> (App, App, Arc<FaultStore>) {
    let store = Arc::new(FaultStore::new(
        Arc::new(MemoryStore::new()),
        StoreFault::None,
    ));
    let wallet = p
        .join_on(
            &p.alice,
            "wallet",
            protocol.clone(),
            Arc::clone(&store) as Arc<dyn StateStore>,
        )
        .await;
    let mut shop = p.join(&p.bob, "shop", protocol).await;
    shop.invite(&p.alice.identity().public()).await.unwrap();
    (wallet, shop, store)
}

#[tokio::test]
async fn test_outbox_give_up_of_an_accepted_message_keeps_its_owed_record_job() {
    let p = Pair::new();
    let protocol = ApiProtocol::new(Mode::Plain);
    let (mut wallet, _shop, store) = wallet_on_a_fault_store(&p, &protocol).await;
    let signed = wallet.sign_message(Pair::note(&p.bob, "hello")).unwrap();
    let target = RecordTarget::new(items(), &signed.hash());
    let signed = signed.with_record(RecordJob {
        target: target.clone(),
        tag: b"sent".to_vec(),
    });
    let msg_id = wallet.queue_signed(signed).await.unwrap();
    // Accepted, its record job failing for now (its batch, after the reply grant's,
    // can't reach the switch): kept, the record job owed.
    let unreachable = |after| Fault::Unreachable {
        path: "ops".into(),
        after,
    };
    p.alice.switch().fail_next(unreachable(1));
    wallet.flush_outbox().await.unwrap();
    assert!(matches!(
        wallet.delivery(&msg_id).await.unwrap(),
        Some(Delivery::Accepted { .. })
    ));
    // The next try's own write is too large, with its failure's text and without it: only
    // the re-send is given up.
    p.alice.switch().lock().faults.clear();
    p.alice.switch().fail_next(unreachable(0));
    store.refuse_puts_as_too_large_times(format!("out/{msg_id}").as_bytes(), 2);
    wallet.take_events();
    let report = wallet.flush_outbox().await.unwrap();
    assert_eq!(report.undelivered, vec![msg_id.clone()]);
    assert!(wallet.take_events().iter().any(|e| matches!(
        e,
        AppEvent::MessageUndelivered { msg_id: m, resend: true, .. } if *m == msg_id
    )));
    assert!(matches!(
        wallet.delivery(&msg_id).await.unwrap(),
        Some(Delivery::Accepted { .. })
    ));
    // Its outbox record stays while the record job is owed, as `drop_undeliverable` keeps it.
    let ns = crate::store::client_namespace(&wallet.app_id());
    let out = format!("out/{msg_id}");
    assert!(store.inner().get(&ns, out.as_bytes()).unwrap().is_some());
    // Its record job is still made.
    p.alice.switch().lock().faults.clear();
    wallet.flush_outbox().await.unwrap();
    let key = wallet.record_key(&target).unwrap();
    let record = wallet.shared_record(&key).await.unwrap().unwrap();
    assert_eq!(ids(record.content.value()), vec![msg_id]);
}

/// A record job whose try left its batch kept, and that is given up at the sent retention,
/// names that batch in its duty event: it may still apply, and its end tells.
#[tokio::test]
async fn test_outbox_record_job_given_up_names_the_batch_it_left_kept() {
    let p = Pair::new();
    let protocol = ApiProtocol::new(Mode::Plain);
    let (mut wallet, _shop, _store) = wallet_on_a_fault_store(&p, &protocol).await;
    let signed = wallet.sign_message(Pair::note(&p.bob, "hello")).unwrap();
    let target = RecordTarget::new(items(), &signed.hash());
    let signed = signed.with_record(RecordJob {
        target,
        tag: b"sent".to_vec(),
    });
    let msg_id = wallet.queue_signed(signed).await.unwrap();
    // Accepted; the record job's batch, after the reply grant's, is sent and never
    // answered: kept, stamped, unapplied.
    p.alice.switch().fail_next(Fault::Unanswered {
        path: "ops".into(),
        after: 1,
    });
    wallet.flush_outbox().await.unwrap();
    let Some(Delivery::Accepted { accepted_at_ms }) = wallet.delivery(&msg_id).await.unwrap()
    else {
        panic!("accepted");
    };
    let kept = wallet.kept_batches().await.unwrap();
    assert_eq!(kept.len(), 1);
    let batch_id = kept[0].0;
    // At the retention the kept batch is past its window, and the job is given up.
    p.alice.switch().lock().faults.clear();
    for _ in 0..8 {
        p.alice.switch().fail_next(Fault::Unreachable {
            path: "ops".into(),
            after: 0,
        });
    }
    p.clock
        .set_ms(accepted_at_ms + crate::app::SENT_RETENTION_MS);
    wallet.flush_outbox().await.unwrap();
    // A flush sends no kept batch itself: the next read does, and past its window drops it.
    wallet.receive(None).await.unwrap();
    let events = wallet.unacknowledged_events().await.unwrap();
    assert!(
        events.iter().any(|e| matches!(
            e,
            AppEvent::RecordJobDropped { msg_id: m, batch_id: Some(b), .. }
                if *m == msg_id && *b == batch_id
        )),
        "{events:?}"
    );
    // Its end tells what became of it: sent once, then past the window a resend tells in.
    assert!(matches!(
        wallet.kept_batch(batch_id).await.unwrap(),
        Some(crate::app::KeptBatchStatus::Dropped {
            reason: crate::app::KeptBatchDrop::Uncertain,
            ..
        })
    ));
}

#[tokio::test]
async fn test_outbox_give_up_reads_state_again_before_going_on() {
    let p = Pair::new();
    let protocol = ApiProtocol::new(Mode::Plain);
    let (mut wallet, _shop, store) = wallet_on_a_fault_store(&p, &protocol).await;
    // Queued: bob's switch can't be reached.
    p.bob.switch().fail_next(Fault::Unreachable {
        path: "inbox".into(),
        after: 0,
    });
    let (msg_id, delivery) = wallet.send(Pair::note(&p.bob, "hello")).await.unwrap();
    // Queued for the network, not for admission: no time of a first `403 not_admitted`.
    assert!(
        matches!(
            delivery,
            Delivery::Queued {
                undeliverable_since_ms: None,
                undeliverable_reason: None,
                ..
            }
        ),
        "{delivery:?}"
    );
    p.bob.switch().lock().faults.clear();
    // The next try's own write is refused as too large: given up.
    store.refuse_puts_as_too_large_once(format!("out/{msg_id}").as_bytes());
    let report = wallet.flush_outbox().await.unwrap();
    assert_eq!(report.unknown, vec![msg_id]);
    // The refused commit was read past: what the app holds is the store's again, so a
    // backup, only ever of committed state, is given at once.
    assert!(
        wallet.backup().await.is_ok(),
        "{:?}",
        wallet.backup().await.err()
    );
}

#[tokio::test]
async fn test_send_after_a_recipients_provider_loss_resends_with_a_directory_too_large_to_cache() {
    let p = Pair::new();
    let protocol = ApiProtocol::new(Mode::Plain);
    let (mut wallet, _shop, store) = wallet_on_a_fault_store(&p, &protocol).await;
    // Bob's directory is over what the wallet's store keeps: only its stub is cached.
    store.refuse_puts_as_too_large_over(Some(b"dir/"), 1024);
    let (first, delivery) = wallet.send(Pair::note(&p.bob, "one")).await.unwrap();
    assert!(
        matches!(delivery, Delivery::Accepted { .. }),
        "{delivery:?}"
    );
    // Bob loses his provider and recovers at another.
    const RECOVERED: &str = "https://bob-recovered.example";
    let recovered =
        ScriptedSwitch::recovering(p.bob.identity().key(), [9; 32], Arc::clone(&p.clock), 2, 1)
            .unwrap();
    p.router.add_switch(RECOVERED, &recovered);
    let doc = p
        .bob
        .sign_next(|body| {
            body.generation = 2;
            body.inbox = Inbox::new(RECOVERED, recovered.service_key());
            body.recovery_from = Some(1);
        })
        .unwrap();
    recovered.deliver_identity(&doc).unwrap();
    // Bob's kept peers came back with his recovery: alice is admitted there.
    recovered
        .lock()
        .shared
        .keep_peer(p.alice.identity().public());
    p.clock.advance_ms(DOC_CACHE_MS + MINUTE);
    wallet.take_events();
    let _ = wallet.send(Pair::note(&p.bob, "two")).await;
    // The stub held the switch and generation the directory was read under: the loss is
    // found, and what bob's lost switch accepted is sent again.
    assert!(
        wallet.take_events().iter().any(|e| matches!(
            e,
            AppEvent::ResendAfterLoss { identity, messages: 1 } if *identity == p.bob.identity().public()
        )),
        "the re-send after the loss"
    );
    assert!(wallet.delivery(&first).await.unwrap().is_some());
}

#[tokio::test]
async fn test_scripted_inbox_admits_after_an_invite_and_delivers() {
    let p = Pair::new();
    let protocol = ApiProtocol::new(Mode::Plain);
    let mut wallet = p.join(&p.alice, "wallet", &protocol).await;
    let mut shop = p.join(&p.bob, "shop", &protocol).await;
    shop.invite(&p.alice.identity().public()).await.unwrap();
    let (msg_id, delivery) = wallet.send(Pair::note(&p.bob, "hello")).await.unwrap();
    assert!(
        matches!(delivery, Delivery::Accepted { .. }),
        "{delivery:?}"
    );
    let alice = p.alice.identity().public();
    assert_eq!(
        p.bob.switch().peer_copy(&alice).unwrap().version(),
        wallet.own_identity().version()
    );
    // A retry of the same bytes gets the original answer, and no second entry. The entry is
    // counted before its reader passes it, which is when the switch lets it go.
    assert_eq!(p.bob.switch().entries_from(&alice), 1);
    shop.receive(None).await.unwrap();
    let seen = protocol.seen();
    assert_eq!(seen.last().unwrap().msg_id, msg_id);
}

#[tokio::test]
async fn test_scripted_inbox_invite_code_admits_once_with_its_hash() {
    let p = Pair::new();
    let protocol = ApiProtocol::new(Mode::Plain);
    let mut wallet = p.join(&p.alice, "wallet", &protocol).await;
    let mut shop = p.join(&p.bob, "shop", &protocol).await;
    let code = shop.register_invite_code(START + DAY_MS, 1).await.unwrap();
    let mut first = Pair::note(&p.bob, "order");
    first.invite_code = Some(code.code.clone());
    let (_, delivery) = wallet.send(first).await.unwrap();
    assert!(
        matches!(delivery, Delivery::Accepted { .. }),
        "{delivery:?}"
    );
    assert_eq!(p.bob.switch().invite_uses_left(&code.code), Some(0));
    shop.receive(None).await.unwrap();
    let seen = protocol.seen();
    assert_eq!(seen.last().unwrap().invite_code_hash, Some(code.code_hash));
    // The service's reply grant admits the sender from then on, without the code.
    let (_, delivery) = wallet.send(Pair::note(&p.bob, "again")).await.unwrap();
    assert!(
        matches!(delivery, Delivery::Accepted { .. }),
        "{delivery:?}"
    );
    // A code used up admits nobody else.
    let mut carol_app = p.join(&p.carol, "phone", &protocol).await;
    let mut late = Pair::note(&p.bob, "late");
    late.invite_code = Some(code.code);
    let (_, delivery) = carol_app.send(late).await.unwrap();
    assert!(queued_with(&delivery, "not_admitted"), "{delivery:?}");
}

/// An accepted outbox item with an owed record job resends under ordinary admission.
/// An unanswered first append retries the invited envelope and its single-use code.
#[tokio::test]
async fn test_invited_append_retry_and_resend_with_an_owed_record() {
    let p = Pair::new();
    let protocol = ApiProtocol::new(Mode::Plain);
    let mut wallet = p.join(&p.alice, "wallet", &protocol).await;
    let mut shop = p.join(&p.bob, "shop", &protocol).await;
    let code = shop.register_invite_code(START + DAY_MS, 1).await.unwrap();
    let mut note = Pair::note(&p.bob, "order");
    note.invite_code = Some(code.code.clone());
    let signed = wallet.sign_message(note).unwrap().with_record(RecordJob {
        target: inbox(),
        tag: b"sent".to_vec(),
    });
    let id = wallet.queue_signed(signed).await.unwrap();

    p.bob.switch().fail_next(Fault::LoseAnswer {
        path: "inbox".into(),
    });
    let first = wallet.flush_message(&id).await.unwrap();
    assert!(matches!(first, Some(Delivery::Queued { .. })), "{first:?}");
    let alice = p.alice.identity().public();
    assert_eq!(p.bob.switch().entries_from(&alice), 1);
    assert_eq!(p.bob.switch().invite_uses_left(&code.code), Some(0));

    p.alice
        .switch()
        .fail_next(Fault::LoseAnswer { path: "ops".into() });
    let confirmed = wallet.flush_message(&id).await.unwrap();
    assert!(
        matches!(confirmed, Some(Delivery::Accepted { .. })),
        "{confirmed:?}"
    );
    assert_eq!(p.bob.switch().entries_from(&alice), 1);
    assert!(
        wallet.outbox_record(&id).await.is_some(),
        "the accepted record job is owed"
    );

    let resent = wallet.resend(&id).await.unwrap();
    assert!(matches!(resent, Delivery::Accepted { .. }), "{resent:?}");
    assert_eq!(p.bob.switch().entries_from(&alice), 2);
    shop.receive(None).await.unwrap();
    let seen = protocol.seen();
    assert_eq!(seen.len(), 1, "the same signed message is applied once");
    assert_eq!(seen[0].msg_id, id);
    assert_eq!(seen[0].invite_code_hash, Some(code.code_hash));
}

/// Both targets read each delivery's redeemed code, including a wallet restored from
/// before the codes were registered. An already-admitted sender may redeem a second code.
#[tokio::test]
async fn test_scripted_inbox_invitations_reach_both_targets_and_a_restored_wallet() {
    let p = Pair::new();
    let sender = ApiProtocol::new(Mode::Plain);
    let managing = ApiProtocol::new(Mode::LocalNote);
    let sibling = ApiProtocol::new(Mode::LocalNote);
    let mut wallet = p.join(&p.alice, "wallet", &sender).await;
    let mut shop = p.join(&p.bob, "shop", &managing).await;
    let mut till = p
        .join_with(
            &p.bob,
            "till",
            sibling.clone(),
            Arc::new(MemoryStore::new()),
            &[],
        )
        .await;
    shop.receive(None).await.unwrap();
    let backup = shop.backup().await.unwrap();
    let first = shop.register_invite_code(START + DAY_MS, 1).await.unwrap();
    let second = shop.register_invite_code(START + DAY_MS, 1).await.unwrap();
    assert_ne!(first.code_hash, second.code_hash);
    drop(shop);

    let mut expected = Vec::new();
    for (text, code) in [
        ("first", Some(&first)),
        ("second", Some(&second)),
        ("ordinary", None),
    ] {
        let mut note = Pair::note(&p.bob, text);
        note.invite_code = code.map(|invite| invite.code.clone());
        let (id, sent) = wallet.send(note).await.unwrap();
        assert!(matches!(sent, Delivery::Accepted { .. }), "{sent:?}");
        expected.push((id, code.map(|invite| invite.code_hash)));
    }
    assert_eq!(p.bob.switch().invite_uses_left(&first.code), Some(0));
    assert_eq!(p.bob.switch().invite_uses_left(&second.code), Some(0));

    let mut restored = App::restore(
        p.env(&p.bob, Arc::new(MemoryStore::new())),
        managing.clone(),
        config(),
        &backup,
    )
    .await
    .unwrap();
    for (app, protocol) in [(&mut till, &sibling), (&mut restored, &managing)] {
        let mut delivered = Vec::new();
        for _ in 0..3 {
            let report = app.receive(None).await.unwrap();
            delivered.extend(report.events.into_iter().filter_map(|event| match event {
                AppEvent::MessageReceived {
                    msg_id, receipt, ..
                } => Some((msg_id, receipt.invite_code_hash)),
                _ => None,
            }));
            if delivered.len() == expected.len() {
                break;
            }
        }
        assert_eq!(delivered, expected);
        let observed: Vec<_> = protocol
            .seen()
            .into_iter()
            .map(|seen| (seen.msg_id, seen.invite_code_hash))
            .collect();
        assert_eq!(observed, expected);
    }
    let lists = restored.allow_list().await.unwrap();
    let [peer] = lists.peers.as_slice() else {
        panic!("{lists:?}");
    };
    assert_eq!(peer.pubky, p.alice.identity().public());
    assert!(!peer.kept);
    assert_eq!(
        peer.reply.unwrap().origin,
        pubky_switch_core::admission::ReplyOrigin::Invite(first.code_hash)
    );
    let mut spent = Pair::note(&p.bob, "spent");
    spent.invite_code = Some(first.code);
    let (_, sent) = wallet.send(spent).await.unwrap();
    assert!(queued_with(&sent, "not_admitted"), "{sent:?}");
}

#[tokio::test]
async fn test_peer_removal_precedes_replayed_grants_until_the_feed_catches_up() {
    use pubky_switch_core::admission::PeerReason;

    let p = Pair::new();
    let protocol = ApiProtocol::new(Mode::LocalNote);
    let store = Arc::new(MemoryStore::new());
    let mut app = p
        .join_on(&p.bob, "shop", protocol.clone(), store.clone())
        .await;
    let mut sibling = p.join(&p.bob, "till", &protocol).await;
    let peer = p.alice.identity().public();
    let other = p.carol.identity().public();
    app.receive(None).await.unwrap();
    let before = sibling
        .submit_batch(OpBatch::new().op(OpKind::AllowPut {
            pubky: peer,
            reason: PeerReason::Reply,
        }))
        .await
        .unwrap();
    let grant = before.proofs[0].envelope().seq;
    for _ in 0..crate::app::FEED_PAGES_PER_READ {
        sibling.keep_peer(&other).await.unwrap();
    }
    let removed = app
        .submit_batch(OpBatch::new().op(OpKind::AllowDelete {
            pubky: peer,
            reason: PeerReason::Reply,
        }))
        .await
        .unwrap();
    let receipt = removed.proofs[0].envelope();
    let removal = receipt.seq;
    let id = app.app_id();
    drop(app);
    let mut bounded = config();
    bounded.page_size = 1;
    let mut app = App::load(p.env(&p.bob, store), protocol.clone(), bounded.clone(), id)
        .await
        .unwrap();
    assert!(!app.admits(&peer).await.unwrap());
    let read = app.receive(None).await.unwrap();
    assert!(read.more);
    assert!(
        grant <= app.cursor().seq && app.cursor().seq < removal,
        "grant {grant}, cursor {:?}, removal {removal}",
        app.cursor()
    );
    assert!(!app.admits(&peer).await.unwrap());
    assert!(app.admits(&other).await.unwrap());
    let marker = crate::app::list_settlement::order_key("reply", &peer);
    let backup = app.backup().await.unwrap();
    let mut restored = App::restore(
        p.env(&p.bob, Arc::new(MemoryStore::new())),
        protocol,
        bounded,
        &backup,
    )
    .await
    .unwrap();
    for client in [&mut app, &mut restored] {
        assert!(!client.admits(&peer).await.unwrap());
        assert_eq!(
            client
                .reader()
                .get::<crate::app::FeedPosition>(&marker)
                .await
                .unwrap(),
            Some(crate::app::FeedPosition {
                generation: receipt.generation,
                seq: removal
            })
        );
        for _ in 0..10 {
            client.receive(None).await.unwrap();
            if client.cursor().seq >= removal {
                break;
            }
        }
        assert!(client.cursor().seq >= removal);
        assert!(!client.admits(&peer).await.unwrap());
        assert!(!client.reader().exists(&marker).await.unwrap());
    }
    sibling.invite(&peer).await.unwrap();
    for client in [&mut app, &mut restored] {
        client.receive(None).await.unwrap();
        assert!(client.admits(&peer).await.unwrap());
    }
}

#[tokio::test]
async fn test_peer_reply_repeat_preserves_the_invitation_and_regrant_starts_a_new_lifetime() {
    use pubky_switch_core::admission::{PeerReason, ReplyOrigin};

    let p = Pair::new();
    let protocol = ApiProtocol::new(Mode::LocalNote);
    let mut wallet = p.join(&p.alice, "wallet", &protocol).await;
    let mut shop = p.join(&p.bob, "shop", &protocol).await;
    let peer = p.alice.identity().public();
    let code = shop.register_invite_code(START + DAY_MS, 1).await.unwrap();
    let mut note = Pair::note(&p.bob, "first");
    note.invite_code = Some(code.code);
    assert!(matches!(
        wallet.send(note).await.unwrap().1,
        Delivery::Accepted { .. }
    ));
    p.clock.advance_ms(MINUTE);
    assert!(matches!(
        wallet.send(Pair::note(&p.bob, "second")).await.unwrap().1,
        Delivery::Accepted { .. }
    ));
    let original_list = shop.allow_list().await.unwrap();
    let [first] = original_list.peers.as_slice() else {
        panic!("{original_list:?}");
    };
    assert_eq!(first.pubky, peer);
    assert!(!first.kept);
    let original = first.reply.as_ref().unwrap();
    assert_eq!(original.origin, ReplyOrigin::Invite(code.code_hash));
    assert_eq!(original.at, START);
    assert_eq!(original.last_used, Some(START + MINUTE));

    shop.keep_peer(&peer).await.unwrap();
    shop.invite(&peer).await.unwrap();
    let listed = shop.allow_list().await.unwrap();
    assert_eq!(listed.peers.len(), 1);
    assert!(listed.peers[0].kept);
    assert_eq!(listed.peers[0].reply.as_ref(), Some(original));

    shop.submit_batch(
        OpBatch::new()
            .op(OpKind::AllowDelete {
                pubky: peer,
                reason: PeerReason::Reply,
            })
            .op(OpKind::AllowPut {
                pubky: peer,
                reason: PeerReason::Reply,
            }),
    )
    .await
    .unwrap();
    let listed = shop.allow_list().await.unwrap();
    let [kept] = listed.peers.as_slice() else {
        panic!("{listed:?}");
    };
    assert!(kept.kept);
    let new = kept.reply.as_ref().unwrap();
    assert_eq!(new.origin, ReplyOrigin::App(shop.app_id()));
    assert_eq!(new.at, START + MINUTE);
    assert_eq!(new.last_used, None);

    shop.remove_kept_peer(&peer).await.unwrap();
    let listed = shop.allow_list().await.unwrap();
    assert!(!listed.peers[0].kept);
    assert_eq!(listed.peers[0].reply.as_ref(), Some(new));
    assert!(shop.admits(&peer).await.unwrap());
    shop.keep_peer(&peer).await.unwrap();
    shop.remove_reply(&peer).await.unwrap();
    let listed = shop.allow_list().await.unwrap();
    assert!(listed.peers[0].kept);
    assert_eq!(listed.peers[0].reply, None);
    assert!(shop.admits(&peer).await.unwrap());
    shop.remove_kept_peer(&peer).await.unwrap();
    assert!(shop.allow_list().await.unwrap().peers.is_empty());
    assert!(!shop.admits(&peer).await.unwrap());
}

async fn reply_observation(
    app: &App,
    who: &[u8; 32],
) -> Option<crate::app::admission::observations::ReplyObservation> {
    use crate::app::admission::observations::{ReplyObservation, reply_key};
    app.reader()
        .get_raw(reply_key(who).as_bytes())
        .await
        .unwrap()
        .map(|value| ReplyObservation::read_row(&value).unwrap().0)
}

#[tokio::test]
async fn test_peer_grant_observation_survives_reopen_backup_and_older_feed_items() {
    use pubky_switch_core::admission::ReplyOrigin;

    let p = Pair::new();
    let protocol = ApiProtocol::new(Mode::LocalNote);
    let store = Arc::new(MemoryStore::new());
    let mut shop = p
        .join_on(&p.bob, "shop", protocol.clone(), store.clone())
        .await;
    let mut sender = p.join(&p.alice, "wallet", &protocol).await;
    let peer = p.alice.identity().public();
    let code = shop.register_invite_code(START + DAY_MS, 1).await.unwrap();
    let mut note = Pair::note(&p.bob, "invited");
    note.invite_code = Some(code.code);
    assert!(matches!(
        sender.send(note).await.unwrap().1,
        Delivery::Accepted { .. }
    ));
    p.clock.advance_ms(MINUTE);
    assert!(matches!(
        sender.send(Pair::note(&p.bob, "ordinary")).await.unwrap().1,
        Delivery::Accepted { .. }
    ));
    shop.keep_peer(&peer).await.unwrap();
    let lists = shop.allow_list().await.unwrap();
    let grant = lists.peers[0].reply.unwrap();
    assert_eq!(grant.origin, ReplyOrigin::Invite(code.code_hash));
    assert_eq!(grant.last_used, Some(START + MINUTE));
    let backup = shop.backup().await.unwrap();
    let observed = crate::app::admission::observations::ReplyObservation::Observed {
        grant,
        as_of_ms: START + MINUTE,
    };
    assert_eq!(reply_observation(&shop, &peer).await, Some(observed));
    let app_id = shop.app_id();
    drop(shop);
    let backup = AppBackup::from_bytes(&backup.to_bytes().unwrap()).unwrap();
    let mut reopened = App::load(p.env(&p.bob, store), protocol.clone(), config(), app_id)
        .await
        .unwrap();
    let mut restored = App::restore(
        p.env(&p.bob, Arc::new(MemoryStore::new())),
        protocol,
        config(),
        &backup,
    )
    .await
    .unwrap();
    for (app, restore) in [(&mut reopened, false), (&mut restored, true)] {
        // A restored row admits only once a list read or a change verifies it.
        assert_eq!(app.admits(&peer).await.unwrap(), !restore);
        assert_eq!(reply_observation(app, &peer).await, Some(observed));
        app.receive(None).await.unwrap();
        assert_eq!(reply_observation(app, &peer).await, Some(observed));
        let again = app.allow_list().await.unwrap();
        assert!(app.admits(&peer).await.unwrap());
        assert_eq!(again.peers[0].reply, Some(grant));
        assert!(again.peers[0].kept);
    }
}

#[tokio::test]
async fn test_peer_backup_with_invalid_observation_preserves_the_destination() {
    use crate::app::admission::observations::ReplyObservation;
    use pubky_switch_core::time::MAX_TIME_MS;

    let p = Pair::new();
    let protocol = ApiProtocol::new(Mode::LocalNote);
    let store = Arc::new(MemoryStore::new());
    let mut shop = p
        .join_on(&p.bob, "shop", protocol.clone(), store.clone())
        .await;
    let who = p.alice.identity().public();
    shop.invite(&who).await.unwrap();
    let grant = shop.allow_list().await.unwrap().peers[0].reply.unwrap();
    let saved = serde_json::to_value(shop.backup().await.unwrap()).unwrap();
    let newer = p.carol.identity().public();
    shop.keep_peer(&newer).await.unwrap();
    let id = shop.app_id();
    drop(shop);
    let invalid = MAX_TIME_MS + 1;
    let bytes = ReplyObservation::Observed {
        grant,
        as_of_ms: invalid,
    }
    .bytes();
    for (path, value) in [
        (
            "/peers/replies/0/observation",
            json!(pubky_switch_core::enc::b64(&bytes)),
        ),
        ("/peers/last_read", json!({ "generation": 99, "seq": 1 })),
    ] {
        let mut source = saved.clone();
        *source.pointer_mut(path).unwrap() = value;
        let backup = AppBackup::from_bytes(&serde_json::to_vec(&source).unwrap()).unwrap();
        assert!(matches!(
            App::restore(
                p.env(&p.bob, store.clone()),
                protocol.clone(),
                config(),
                &backup
            )
            .await,
            Err(AppError::InvalidData(_))
        ));
        let reopened = App::load(p.env(&p.bob, store.clone()), protocol.clone(), config(), id)
            .await
            .unwrap();
        assert!(reopened.admits(&who).await.unwrap());
        assert!(reopened.admits(&newer).await.unwrap());
    }
}

#[tokio::test]
async fn test_peer_invitation_feed_preserves_the_original_grant_after_repeat() {
    use crate::app::admission::observations::ReplyObservation;
    use pubky_switch_core::admission::{ReplyGrant, ReplyOrigin};

    let p = Pair::new();
    let protocol = ApiProtocol::new(Mode::LocalNote);
    let mut shop = p.join(&p.bob, "shop", &protocol).await;
    let mut wallet = p.join(&p.alice, "wallet", &protocol).await;
    let who = p.alice.identity().public();
    let code = shop.register_invite_code(START + DAY_MS, 1).await.unwrap();
    shop.receive(None).await.unwrap();
    assert!(reply_observation(&shop, &who).await.is_none());
    let mut note = Pair::note(&p.bob, "hello");
    note.invite_code = Some(code.code);
    assert!(matches!(
        wallet.send(note).await.unwrap().1,
        Delivery::Accepted { .. }
    ));
    shop.receive(None).await.unwrap();
    let original = ReplyObservation::Observed {
        grant: ReplyGrant {
            origin: ReplyOrigin::Invite(code.code_hash),
            at: START,
            last_used: None,
        },
        as_of_ms: START,
    };
    assert_eq!(reply_observation(&shop, &who).await, Some(original));
    shop.invite(&who).await.unwrap();
    assert_eq!(reply_observation(&shop, &who).await, Some(original));
    shop.remove_reply(&who).await.unwrap();
    assert!(reply_observation(&shop, &who).await.is_none());
    shop.invite(&who).await.unwrap();
    assert_eq!(
        reply_observation(&shop, &who).await,
        Some(ReplyObservation::Present)
    );
}

#[tokio::test]
async fn test_peer_list_replacement_after_store_refusal_preserves_the_previous_observation() {
    use pubky_switch_core::admission::ReplyOrigin;
    let p = Pair::new();
    let protocol = ApiProtocol::new(Mode::LocalNote);
    let store = Arc::new(MemoryStore::new());
    let fault = Arc::new(FaultStore::new(store.clone(), StoreFault::None));
    let mut shop = p
        .join_on(&p.bob, "shop", protocol.clone(), fault.clone())
        .await;
    let mut till = p.join(&p.bob, "till", &protocol).await;
    let peer = p.alice.identity().public();
    shop.invite(&peer).await.unwrap();
    shop.keep_peer(&peer).await.unwrap();
    let old = shop.allow_list().await.unwrap().peers;
    assert_eq!(
        old[0].reply.unwrap().origin,
        ReplyOrigin::App(shop.app_id())
    );
    let original = shop.backup().await.unwrap();
    let saved = serde_json::to_value(&original).unwrap()["peers"].clone();
    p.clock.advance_ms(MINUTE);
    till.remove_reply(&peer).await.unwrap();
    till.invite(&peer).await.unwrap();
    fault.fail_put_once(b"lc/r/");
    assert!(matches!(
        shop.allow_list().await,
        Err(AppError::Store(crate::error::StoreError::Unavailable))
    ));
    let id = shop.app_id();
    drop(shop);
    let mut reopened = App::load(p.env(&p.bob, store), protocol.clone(), config(), id)
        .await
        .unwrap();
    let mut restored = App::restore(
        p.env(&p.bob, Arc::new(MemoryStore::new())),
        protocol,
        config(),
        &original,
    )
    .await
    .unwrap();
    for app in [&mut reopened, &mut restored] {
        assert_eq!(
            serde_json::to_value(app.backup().await.unwrap()).unwrap()["peers"],
            saved
        );
        assert!(
            app.reader()
                .get_raw(crate::app::admission::LISTS_AT.as_bytes())
                .await
                .unwrap()
                .is_none()
        );
        let fresh = app.allow_list().await.unwrap();
        let [row] = fresh.peers.as_slice() else {
            panic!("{fresh:?}")
        };
        assert!(row.kept);
        let grant = row.reply.unwrap();
        assert_eq!(
            (grant.origin, grant.at, grant.last_used),
            (ReplyOrigin::App(till.app_id()), START + MINUTE, None)
        );
    }
}

#[tokio::test]
async fn test_peer_reply_writer_without_list_read_knows_membership_until_a_full_observation() {
    use pubky_switch_core::admission::ReplyOrigin;
    let p = Pair::new();
    let protocol = ApiProtocol::new(Mode::LocalNote);
    let mut shop = p.join(&p.bob, "shop", &protocol).await;
    let mut wallet = p.join(&p.alice, "wallet", &protocol).await;
    let peer = p.alice.identity().public();
    let code = shop.register_invite_code(START + DAY_MS, 1).await.unwrap();
    let mut note = Pair::note(&p.bob, "invited");
    note.invite_code = Some(code.code);
    assert!(matches!(
        wallet.send(note).await.unwrap().1,
        Delivery::Accepted { .. }
    ));
    let mut till = p
        .join_with(
            &p.bob,
            "till",
            protocol,
            Arc::new(MemoryStore::new()),
            &[Permission::ReplyAdd],
        )
        .await;
    till.invite(&peer).await.unwrap();
    assert!(till.admits(&peer).await.unwrap());
    assert!(matches!(
        till.allow_list().await,
        Err(AppError::Refused(Refusal::Usage(_)))
    ));
    assert_eq!(
        reply_observation(&till, &peer).await,
        Some(crate::app::admission::observations::ReplyObservation::Present)
    );
    let actual = shop.allow_list().await.unwrap();
    assert_eq!(
        actual.peers[0].reply.unwrap().origin,
        ReplyOrigin::Invite(code.code_hash)
    );
}

#[tokio::test]
async fn test_peer_reason_limits_are_independent_and_refusals_leave_prior_rows() {
    use pubky_switch_core::admission::PeerReason;
    let p = Pair::new();
    let proto = ApiProtocol::new(Mode::LocalNote);
    let mut shop = p.join(&p.bob, "shop", &proto).await;
    let alice = p.alice.identity().public();
    let carol = p.carol.identity().public();
    {
        let service = p.bob.switch();
        let mut inner = service.lock();
        inner.max_kept_peers = 1;
        inner.max_reply_peers = 1;
    }
    shop.keep_peer(&alice).await.unwrap();
    shop.invite(&carol).await.unwrap();
    shop.invite(&carol).await.unwrap();
    shop.keep_peer(&alice).await.unwrap();
    let before = shop.allow_list().await.unwrap().peers;
    for (peer, reason, limit) in [
        (alice, PeerReason::Reply, "reply_peers"),
        (carol, PeerReason::Kept, "kept_peers"),
    ] {
        let mut other = p.join(&p.bob, limit, &proto).await;
        let error = other
            .submit_batch(OpBatch::new().op(OpKind::AllowPut {
                pubky: peer,
                reason,
            }))
            .await
            .unwrap_err();
        let AppError::Switch(crate::error::ClientError::Switch {
            code: ErrorCode::QuotaExceeded,
            current,
            ..
        }) = error.unkept()
        else {
            panic!("{error:?}")
        };
        assert_eq!(current["limit"], limit);
        assert_eq!(shop.allow_list().await.unwrap().peers, before);
    }
    shop.remove_reply(&carol).await.unwrap();
    shop.invite(&alice).await.unwrap();
    let after = shop.allow_list().await.unwrap().peers;
    assert_eq!(after.len(), 1);
    assert!(after[0].kept && after[0].reply.is_some());
}

#[tokio::test]
async fn test_scripted_inbox_stale_key_names_an_app_added_since() {
    let p = Pair::new();
    let protocol = ApiProtocol::new(Mode::Plain);
    let mut wallet = p.join(&p.alice, "wallet", &protocol).await;
    let mut shop = p.join(&p.bob, "shop", &protocol).await;
    shop.invite(&p.alice.identity().public()).await.unwrap();
    wallet.send(Pair::note(&p.bob, "one")).await.unwrap();
    // Bob adds an app; alice's cached directory predates it.
    let mut kiosk = p.join(&p.bob, "kiosk", &protocol).await;
    let appends_before = inbox_appends(&p);
    let (second, delivery) = wallet.send(Pair::note(&p.bob, "two")).await.unwrap();
    assert!(
        matches!(delivery, Delivery::Accepted { .. }),
        "{delivery:?}"
    );
    // Refused with the app's records, sealed again, accepted.
    assert_eq!(inbox_appends(&p) - appends_before, 2);
    kiosk.receive(None).await.unwrap();
    assert!(protocol.seen().iter().any(|s| s.msg_id == second));
}

fn inbox_appends(p: &Pair) -> usize {
    p.router
        .log()
        .iter()
        .filter(|line| line.starts_with(&format!("POST {BOB_ORIGIN}")) && line.contains("/inbox"))
        .count()
}

fn directory_reads(p: &Pair) -> usize {
    p.router
        .log()
        .iter()
        .filter(|line| {
            line.starts_with(&format!("GET {BOB_ORIGIN}")) && line.contains("/directory")
        })
        .count()
}

#[tokio::test]
async fn test_stale_key_answer_missing_a_member_reads_the_directory_again() {
    let members = [
        "receive_keys",
        "not_current",
        "unknown_kids",
        "added_apps",
        "apps_version",
    ];
    for member in members {
        for null in [false, true] {
            let p = Pair::new();
            let protocol = ApiProtocol::new(Mode::Plain);
            let mut wallet = p.join(&p.alice, "wallet", &protocol).await;
            let mut shop = p.join(&p.bob, "shop", &protocol).await;
            shop.invite(&p.alice.identity().public()).await.unwrap();
            wallet.send(Pair::note(&p.bob, "one")).await.unwrap();
            let mut current = json!({
                "receive_keys": [], "not_current": [], "unknown_kids": [], "added_apps": [],
                "apps_version": 1,
            });
            if null {
                current[member] = Value::Null;
            } else {
                current.as_object_mut().unwrap().remove(member);
            }
            p.bob.switch().fail_next(Fault::Error {
                path: "/inbox".into(),
                code: ErrorCode::StaleKey,
                current,
            });
            let reads = directory_reads(&p);
            let (_, delivery) = wallet.send(Pair::note(&p.bob, "two")).await.unwrap();
            assert!(
                matches!(delivery, Delivery::Accepted { .. }),
                "{member}, null {null}: {delivery:?}"
            );
            // Nothing taken from the answer: sealed again for the directory read again.
            assert_eq!(directory_reads(&p), reads + 1, "{member}, null {null}");
        }
    }
}

#[tokio::test]
async fn test_scripted_inbox_identity_needed_delivers_the_copy_again() {
    let p = Pair::new();
    let protocol = ApiProtocol::new(Mode::Plain);
    let mut wallet = p.join(&p.alice, "wallet", &protocol).await;
    let mut shop = p.join(&p.bob, "shop", &protocol).await;
    shop.invite(&p.alice.identity().public()).await.unwrap();
    wallet.send(Pair::note(&p.bob, "one")).await.unwrap();
    let alice = p.alice.identity().public();
    p.bob.switch().forget_peer_copy(&alice);
    let (_, delivery) = wallet.send(Pair::note(&p.bob, "two")).await.unwrap();
    assert!(
        matches!(delivery, Delivery::Accepted { .. }),
        "{delivery:?}"
    );
    assert!(p.bob.switch().peer_copy(&alice).is_some());
    assert_eq!(p.bob.switch().entries_from(&alice), 2);
}

#[tokio::test]
async fn test_scripted_inbox_connect_requests_follow_the_policy() {
    let p = Pair::new();
    let protocol = ApiProtocol::new(Mode::Plain);
    let mut wallet = p.join(&p.alice, "wallet", &protocol).await;
    let _shop = p.join(&p.bob, "shop", &protocol).await;
    let bob = p.bob.identity().public();
    let alice = p.alice.identity().public();
    // Off by default: a stranger can't ask.
    let error = wallet.ask_to_connect(&bob).await.unwrap_err();
    assert_eq!(error.code(), Some(ErrorCode::NotAdmitted));
    assert!(p.bob.switch().connects().is_empty());
    // On: the stranger's document is taken and its request kept, once.
    p.bob
        .next_doc(|body| body.policy.connect_requests.enabled = true)
        .unwrap();
    assert!(wallet.ask_to_connect(&bob).await.unwrap());
    assert!(wallet.ask_to_connect(&bob).await.unwrap());
    assert_eq!(p.bob.switch().connects(), vec![alice]);
    assert!(p.bob.switch().peer_copy(&alice).is_some());
}

#[tokio::test]
async fn test_scripted_inbox_connect_requests_full_refuse_before_the_deny_list() {
    // At `max_pending` 0 the list is always full: `429 quota_exceeded` naming connect
    // requests, the same for a denied sender, as at the service (Switch wire 7.4.7).
    let p = Pair::new();
    let protocol = ApiProtocol::new(Mode::Plain);
    let mut wallet = p.join(&p.alice, "wallet", &protocol).await;
    let mut shop = p.join(&p.bob, "shop", &protocol).await;
    let bob = p.bob.identity().public();
    let alice = p.alice.identity().public();
    p.bob
        .next_doc(|body| {
            body.policy.connect_requests.enabled = true;
            body.policy.connect_requests.max_pending = 0;
        })
        .unwrap();
    let error = wallet.ask_to_connect(&bob).await.unwrap_err();
    assert_eq!(error.code(), Some(ErrorCode::QuotaExceeded));
    p.bob.switch().lock().shared.deny.insert(alice);
    let denied = wallet.ask_to_connect(&bob).await.unwrap_err();
    assert_eq!(denied.code(), Some(ErrorCode::QuotaExceeded));
    let list = shop.connect_requests().await.unwrap();
    assert_eq!((list.max_pending, list.full), (0, true));
    assert!(p.bob.switch().connects().is_empty());
}

#[tokio::test]
async fn test_scripted_inbox_connect_request_of_a_denied_sender_is_pending_and_not_kept() {
    // A denied sender is answered as anyone else, and its request isn't kept.
    let p = Pair::new();
    let protocol = ApiProtocol::new(Mode::Plain);
    let mut wallet = p.join(&p.alice, "wallet", &protocol).await;
    let mut shop = p.join(&p.bob, "shop", &protocol).await;
    let bob = p.bob.identity().public();
    p.bob
        .next_doc(|body| body.policy.connect_requests.enabled = true)
        .unwrap();
    p.bob
        .switch()
        .lock()
        .shared
        .deny
        .insert(p.alice.identity().public());
    assert!(wallet.ask_to_connect(&bob).await.unwrap());
    assert!(p.bob.switch().connects().is_empty());
    let list = shop.connect_requests().await.unwrap();
    assert_eq!((list.max_pending, list.full), (50, false));
}

#[tokio::test]
async fn test_scripted_inbox_connect_requests_full_keep_the_one_waiting() {
    // At `max_pending` 1 the one waiting fills the list, stays, and asking again is
    // answered pending.
    let p = Pair::new();
    let protocol = ApiProtocol::new(Mode::Plain);
    let mut wallet = p.join(&p.alice, "wallet", &protocol).await;
    let mut shop = p.join(&p.bob, "shop", &protocol).await;
    let bob = p.bob.identity().public();
    p.bob
        .next_doc(|body| {
            body.policy.connect_requests.enabled = true;
            body.policy.connect_requests.max_pending = 1;
        })
        .unwrap();
    assert!(wallet.ask_to_connect(&bob).await.unwrap());
    assert!(shop.connect_requests().await.unwrap().full);
    assert!(wallet.ask_to_connect(&bob).await.unwrap());
    assert_eq!(p.bob.switch().connects(), vec![p.alice.identity().public()]);
}

#[tokio::test]
async fn test_scripted_inbox_connect_request_is_answered_by_each_entry_and_a_decline() {
    // As at the service: a kept peer, a reply grant, a deny list entry, a decline and
    // the reply grant an invite code's first append writes each answer the request;
    // a sender the lists admit asks without a request kept.
    let p = Pair::new();
    let protocol = ApiProtocol::new(Mode::Plain);
    let mut wallet = p.join(&p.alice, "wallet", &protocol).await;
    let mut shop = p.join(&p.bob, "shop", &protocol).await;
    let bob = p.bob.identity().public();
    let alice = p.alice.identity().public();
    p.bob
        .next_doc(|body| body.policy.connect_requests.enabled = true)
        .unwrap();
    let asked = |p: &Pair| p.bob.switch().connects() == vec![alice];
    assert!(wallet.ask_to_connect(&bob).await.unwrap());
    assert!(asked(&p));
    shop.keep_peer(&alice).await.unwrap();
    assert!(p.bob.switch().connects().is_empty(), "a kept peer");
    assert!(wallet.ask_to_connect(&bob).await.unwrap());
    assert!(
        p.bob.switch().connects().is_empty(),
        "admitted: nothing kept"
    );
    shop.remove_kept_peer(&alice).await.unwrap();

    assert!(wallet.ask_to_connect(&bob).await.unwrap());
    assert!(asked(&p));
    shop.invite(&alice).await.unwrap();
    assert!(p.bob.switch().connects().is_empty(), "a reply grant");
    shop.remove_reply(&alice).await.unwrap();

    assert!(wallet.ask_to_connect(&bob).await.unwrap());
    assert!(asked(&p));
    shop.deny(&alice).await.unwrap();
    assert!(p.bob.switch().connects().is_empty(), "a deny list entry");
    shop.undeny(&alice).await.unwrap();

    assert!(wallet.ask_to_connect(&bob).await.unwrap());
    assert!(asked(&p));
    shop.decline_connect(&alice).await.unwrap();
    assert!(p.bob.switch().connects().is_empty(), "a decline");

    assert!(wallet.ask_to_connect(&bob).await.unwrap());
    assert!(asked(&p));
    let code = shop.register_invite_code(START + DAY_MS, 1).await.unwrap();
    let mut first = Pair::note(&p.bob, "order");
    first.invite_code = Some(code.code.clone());
    let (_, delivery) = wallet.send(first).await.unwrap();
    assert!(
        matches!(delivery, Delivery::Accepted { .. }),
        "{delivery:?}"
    );
    assert!(
        p.bob.switch().connects().is_empty(),
        "an invite code's entry"
    );
}

#[tokio::test]
async fn test_scripted_inbox_takes_own_apps_kinds_between_them() {
    let p = Pair::new();
    let protocol = ApiProtocol::new(Mode::Plain);
    let mut wallet = p.join(&p.alice, "wallet", &protocol).await;
    let mut phone = p.join(&p.alice, "phone", &protocol).await;
    let mut body = Map::new();
    body.insert("text".into(), json!("to my other app"));
    let notice = OutgoingMessage::new(p.alice.identity().public(), "sample.notice", body);
    // The wallet's own identity.json predates the phone: the own directory brings the newer
    // one, which lists it.
    assert!(wallet.own_identity().listed_cert(&phone.app_id()).is_none());
    let (msg_id, delivery) = wallet.send(notice).await.unwrap();
    assert!(wallet.own_identity().listed_cert(&phone.app_id()).is_some());
    assert!(
        matches!(delivery, Delivery::Accepted { .. }),
        "{delivery:?}"
    );
    phone.receive(None).await.unwrap();
    assert!(protocol.seen().iter().any(|s| s.msg_id == msg_id));
    // The sending app isn't among the targets: its own copy isn't in its feed.
    let before = protocol.seen().len();
    wallet.receive(None).await.unwrap();
    assert_eq!(protocol.seen().len(), before);
}

// -------------------------------------------------------------------------------------
// Messages signed before they are queued (Switch spec 8.2, 11)

#[tokio::test]
async fn test_signed_message_queued_with_the_record_built_from_its_hash() {
    let p = Pair::new();
    let protocol = ApiProtocol::new(Mode::Plain);
    let mut wallet = p.join(&p.alice, "wallet", &protocol).await;
    let mut shop = p.join(&p.bob, "shop", &protocol).await;
    shop.invite(&p.alice.identity().public()).await.unwrap();
    let signed = wallet.sign_message(Pair::note(&p.bob, "hello")).unwrap();
    // Nothing is kept by signing.
    assert!(wallet.delivery(signed.msg_id()).await.unwrap().is_none());
    let target = RecordTarget::new(items(), &signed.hash());
    let entry = wallet
        .record_op(&target, Some(&value(&[signed.msg_id()])), vec![])
        .await
        .unwrap();
    wallet
        .submit_batch(OpBatch::new().entry(entry).queue(signed.clone()))
        .await
        .unwrap();
    // Queued with the batch's answer, the record written in it.
    assert!(matches!(
        wallet.delivery(signed.msg_id()).await.unwrap(),
        Some(Delivery::Queued { tries: 0, .. })
    ));
    let key = wallet.record_key(&target).unwrap();
    assert!(wallet.shared_record(&key).await.unwrap().is_some());
    let delivery = wallet.flush_message(signed.msg_id()).await.unwrap();
    assert!(
        matches!(delivery, Some(Delivery::Accepted { .. })),
        "{delivery:?}"
    );
    shop.receive(None).await.unwrap();
    assert!(protocol.seen().iter().any(|s| s.msg_id == signed.msg_id()));
}

#[tokio::test]
async fn test_signed_message_not_queued_when_its_batch_is_refused() {
    let p = Pair::new();
    let protocol = ApiProtocol::new(Mode::Plain);
    let mut wallet = p.join(&p.alice, "wallet", &protocol).await;
    let signed = wallet.sign_message(Pair::note(&p.bob, "hello")).unwrap();
    let target = RecordTarget::new(items(), &signed.hash());
    let key = wallet.record_key(&target).unwrap();
    let wrong = Condition::RecordVersion {
        key,
        version: RecordVersion::new(1, 99),
    };
    let entry = wallet
        .record_op(&target, Some(&value(&["x"])), vec![wrong])
        .await
        .unwrap();
    let error = wallet
        .submit_batch(OpBatch::new().entry(entry).queue(signed.clone()))
        .await
        .unwrap_err();
    assert_eq!(error.code(), Some(ErrorCode::Conflict));
    // Never queued: its batch was refused, at this time.
    let delivery = wallet.delivery(signed.msg_id()).await.unwrap();
    assert!(
        matches!(
            &delivery,
            Some(Delivery::Failed { reason, failed_at_ms })
                if reason.contains("conflict") && *failed_at_ms == p.clock.now_ms()
        ),
        "{delivery:?}"
    );
    // The same signed message goes in the batch built again.
    let entry = wallet
        .record_op(&target, Some(&value(&["x"])), vec![])
        .await
        .unwrap();
    wallet
        .submit_batch(OpBatch::new().entry(entry).queue(signed.clone()))
        .await
        .unwrap();
    assert!(matches!(
        wallet.delivery(signed.msg_id()).await.unwrap(),
        Some(Delivery::Queued { .. } | Delivery::Accepted { .. })
    ));
}

#[tokio::test]
async fn test_signed_message_record_job_from_its_own_hash() {
    let p = Pair::new();
    let protocol = ApiProtocol::new(Mode::Plain);
    let mut wallet = p.join(&p.alice, "wallet", &protocol).await;
    let mut shop = p.join(&p.bob, "shop", &protocol).await;
    shop.invite(&p.alice.identity().public()).await.unwrap();
    let signed = wallet.sign_message(Pair::note(&p.bob, "hello")).unwrap();
    let target = RecordTarget::new(items(), &signed.hash());
    let signed = signed.with_record(RecordJob {
        target: target.clone(),
        tag: b"sent".to_vec(),
    });
    let msg_id = wallet.queue_signed(signed.clone()).await.unwrap();
    // Queued once: queueing it again changes nothing.
    assert_eq!(wallet.queue_signed(signed).await.unwrap(), msg_id);
    let report = wallet.flush_outbox().await.unwrap();
    assert_eq!(report.done, vec![msg_id.clone()]);
    let key = wallet.record_key(&target).unwrap();
    let record = wallet.shared_record(&key).await.unwrap().unwrap();
    assert_eq!(ids(record.content.value()), vec![msg_id]);
}

#[tokio::test]
async fn test_signed_message_of_another_app_is_refused() {
    let p = Pair::new();
    let protocol = ApiProtocol::new(Mode::Plain);
    let wallet = p.join(&p.alice, "wallet", &protocol).await;
    let mut phone = p.join(&p.alice, "phone", &protocol).await;
    let signed = wallet.sign_message(Pair::note(&p.bob, "hello")).unwrap();
    let error = phone.queue_signed(signed).await.unwrap_err();
    assert!(
        matches!(error, AppError::Refused(Refusal::Usage(_))),
        "{error:?}"
    );
}

/// The signed plaintext a record of [`items`] stores, as [`stored_value`] wrote it.
fn stored_plaintext(record: Option<&[u8]>) -> MessagePlaintext {
    let text = ids(record).pop().unwrap();
    MessagePlaintext::decode(&pubky_switch_core::enc::unb64(&text).unwrap()).unwrap()
}

/// A record value of [`items`] that stores the signed plaintext of `signed`.
fn stored_value(signed: &SignedMessage) -> Vec<u8> {
    value(&[&pubky_switch_core::enc::b64(&signed.plaintext().encode())])
}

/// Switch spec 11 "Queued again by its signer": a batch writing a record that stores a
/// message, and queueing it, is applied but its answer lost; a backup taken while it is
/// kept doesn't carry it, so the restored app's outbox doesn't hold the message though its
/// record does. Queued again from the record's plaintext, it is delivered once, with the
/// same `msg_id` and bytes.
#[tokio::test]
async fn test_queue_stored_restored_app_delivers_a_kept_batchs_message_once() {
    let p = Pair::new();
    let protocol = ApiProtocol::new(Mode::Plain);
    let mut wallet = p.join(&p.alice, "wallet", &protocol).await;
    let mut shop = p.join(&p.bob, "shop", &protocol).await;
    shop.invite(&p.alice.identity().public()).await.unwrap();
    let signed = wallet.sign_message(Pair::note(&p.bob, "hello")).unwrap();
    let target = RecordTarget::new(items(), &signed.hash());
    let entry = wallet
        .record_op(&target, Some(&stored_value(&signed)), vec![])
        .await
        .unwrap();
    p.alice
        .switch()
        .fail_next(Fault::LoseAnswer { path: "ops".into() });
    let error = wallet
        .submit_batch(OpBatch::new().entry(entry).queue(signed.clone()))
        .await
        .unwrap_err();
    assert!(error.kept_batch().is_some(), "{error:?}");
    assert!(matches!(
        wallet.delivery(signed.msg_id()).await.unwrap(),
        Some(Delivery::Kept { .. })
    ));
    let backup = wallet.backup().await.unwrap();
    drop(wallet);
    let mut restored = App::restore(
        p.env(&p.alice, Arc::new(MemoryStore::new())),
        protocol.clone(),
        config(),
        &backup,
    )
    .await
    .unwrap();
    restored.receive(None).await.unwrap();
    // The record holds the message; no outbox does, and nothing delivered it.
    assert_eq!(restored.delivery(signed.msg_id()).await.unwrap(), None);
    let key = restored.record_key(&target).unwrap();
    let record = restored.shared_record(&key).await.unwrap().unwrap();
    let plaintext = stored_plaintext(record.content.value());
    assert_eq!(plaintext, *signed.plaintext());
    let alice = p.alice.identity().public();
    assert_eq!(p.bob.switch().entries_from(&alice), 0);
    let msg_id = restored.queue_stored(&plaintext).await.unwrap();
    assert_eq!(msg_id, signed.msg_id());
    let delivery = restored.flush_message(&msg_id).await.unwrap();
    assert!(
        matches!(delivery, Some(Delivery::Accepted { .. })),
        "{delivery:?}"
    );
    // Queued again, it is left as it is: sent, it goes once.
    assert_eq!(restored.queue_stored(&plaintext).await.unwrap(), msg_id);
    restored.flush_outbox().await.unwrap();
    assert_eq!(p.bob.switch().entries_from(&alice), 1);
    shop.receive(None).await.unwrap();
    let seen: Vec<Seen> = protocol
        .seen()
        .into_iter()
        .filter(|s| s.msg_id == msg_id)
        .collect();
    assert_eq!(seen.len(), 1);
    assert_eq!(seen[0].hash, signed.hash());
}

/// Only a message this app signed is queued again: one another app of the identity
/// signed, one of another identity, one naming another App ID in its plaintext or another
/// app or identity in `from` though this app's key signed it, and one whose signature
/// isn't this app's are refused, and nothing is queued.
#[tokio::test]
async fn test_queue_stored_refuses_a_message_this_app_didnt_sign() {
    let p = Pair::new();
    let protocol = ApiProtocol::new(Mode::Plain);
    let mut wallet = p.join(&p.alice, "wallet", &protocol).await;
    let phone = p.join(&p.alice, "phone", &protocol).await;
    let shop = p.join(&p.bob, "shop", &protocol).await;
    let alice = p.alice.identity().public();
    let other_app = phone
        .sign_message(Pair::note(&p.bob, "hello"))
        .unwrap()
        .plaintext()
        .clone();
    let other_identity = shop
        .sign_message(Pair::note(&p.alice, "hello"))
        .unwrap()
        .plaintext()
        .clone();
    let keys = p.alice.identity().app_keys("wallet");
    let mut body = Map::new();
    body.insert("text".into(), json!("hello"));
    let from_other = Message::new(
        "sample.note",
        Sender {
            identity: p.bob.identity().public(),
            app_id: keys.app_id_bytes(),
        },
        p.bob.identity().public(),
        p.clock.now_ms(),
        vec![],
        body,
    )
    .unwrap()
    .sign(&keys)
    .unwrap();
    let own = wallet.sign_message(Pair::note(&p.bob, "hello")).unwrap();
    let forged = MessagePlaintext::from_parts(
        own.plaintext().sender_app_id(),
        other_app.signature(),
        own.plaintext().json().to_vec(),
    )
    .unwrap();
    let other_app_id = MessagePlaintext::from_parts(
        phone.app_id(),
        own.plaintext().signature(),
        own.plaintext().json().to_vec(),
    )
    .unwrap();
    let mut body = Map::new();
    body.insert("text".into(), json!("hello"));
    let json = Message::new(
        "sample.note",
        Sender {
            identity: alice,
            app_id: phone.app_id(),
        },
        p.bob.identity().public(),
        p.clock.now_ms(),
        vec![],
        body,
    )
    .unwrap()
    .to_json()
    .unwrap();
    let bob = p.bob.identity().public();
    let signature = keys.sign(pubky_switch_core::labels::sig::MSG, &[&bob, &json]);
    let from_other_app =
        MessagePlaintext::from_parts(keys.app_id_bytes(), signature, json).unwrap();
    for (name, plaintext) in [
        ("another app", other_app),
        ("another identity", other_identity),
        ("another App ID in the plaintext", other_app_id),
        ("from another app", from_other_app),
        ("from another identity", from_other),
        ("another signature", forged),
    ] {
        let error = wallet.queue_stored(&plaintext).await.unwrap_err();
        assert!(
            matches!(error, AppError::Refused(Refusal::Usage(_))),
            "{name}: {error:?}"
        );
        let msg_id = Message::parse(plaintext.json(), &[]).unwrap().msg_id;
        assert_eq!(wallet.delivery(&msg_id).await.unwrap(), None, "{name}");
    }
    assert_eq!(
        wallet.flush_outbox().await.unwrap().done,
        Vec::<String>::new()
    );
    assert_eq!(p.bob.switch().entries_from(&alice), 0);
}

/// A message the outbox holds, or that was sent, is left as it is: queued again it isn't
/// queued twice, and goes once.
#[tokio::test]
async fn test_queue_stored_leaves_a_message_the_outbox_holds_or_sent() {
    let p = Pair::new();
    let protocol = ApiProtocol::new(Mode::Plain);
    let mut wallet = p.join(&p.alice, "wallet", &protocol).await;
    let mut shop = p.join(&p.bob, "shop", &protocol).await;
    let alice = p.alice.identity().public();
    // Queued: the recipient doesn't admit the sender yet.
    let signed = wallet.sign_message(Pair::note(&p.bob, "hello")).unwrap();
    let plaintext = signed.plaintext().clone();
    let msg_id = wallet.queue_signed(signed).await.unwrap();
    let delivery = wallet.flush_message(&msg_id).await.unwrap().unwrap();
    assert!(queued_with(&delivery, "not_admitted"), "{delivery:?}");
    assert_eq!(wallet.queue_stored(&plaintext).await.unwrap(), msg_id);
    assert_eq!(wallet.delivery(&msg_id).await.unwrap(), Some(delivery));
    shop.invite(&alice).await.unwrap();
    wallet.flush_outbox().await.unwrap();
    assert_eq!(p.bob.switch().entries_from(&alice), 1);
    // Sent: left as it is too.
    assert_eq!(wallet.queue_stored(&plaintext).await.unwrap(), msg_id);
    let report = wallet.flush_outbox().await.unwrap();
    assert!(
        report.done.is_empty() && report.queued.is_empty(),
        "{report:?}"
    );
    assert_eq!(p.bob.switch().entries_from(&alice), 1);
    shop.receive(None).await.unwrap();
    assert_eq!(
        protocol
            .seen()
            .iter()
            .filter(|s| s.msg_id == msg_id)
            .count(),
        1
    );
}

/// A recipient keeps a processed pair only so long, so a message queued again goes only
/// until 30 days from its `created_at`, less the clock tolerance: past that it is given up
/// unsent, and the protocol told.
#[tokio::test]
async fn test_queue_stored_past_the_replay_window_is_refused_and_queues_nothing() {
    let p = Pair::new();
    let protocol = ApiProtocol::new(Mode::Plain);
    let mut wallet = p.join(&p.alice, "wallet", &protocol).await;
    let mut shop = p.join(&p.bob, "shop", &protocol).await;
    let alice = p.alice.identity().public();
    shop.invite(&alice).await.unwrap();
    let signed = wallet.sign_message(Pair::note(&p.bob, "old")).unwrap();
    p.clock
        .advance_ms(SENT_RETENTION_MS - CLOCK_TOLERANCE_MS + MINUTE);
    wallet.take_events();
    let error = wallet.queue_stored(signed.plaintext()).await.unwrap_err();
    assert!(
        matches!(
            error,
            AppError::Refused(Refusal::WontDeliver(WontDeliver::PastReplayWindow { .. }))
        ),
        "{error:?}"
    );
    assert!(wallet.take_events().is_empty());
    assert_eq!(wallet.delivery(signed.msg_id()).await.unwrap(), None);
    let report = wallet.flush_outbox().await.unwrap();
    assert!(report.undelivered.is_empty() && report.done.is_empty());
    assert!(wallet.unacknowledged_events().await.unwrap().is_empty());
    assert_eq!(p.bob.switch().entries_from(&alice), 0);
    // Within it, the same message goes.
    let fresh = wallet.sign_message(Pair::note(&p.bob, "fresh")).unwrap();
    p.clock
        .advance_ms(SENT_RETENTION_MS - CLOCK_TOLERANCE_MS - MINUTE);
    let msg_id = wallet.queue_stored(fresh.plaintext()).await.unwrap();
    let delivery = wallet.flush_message(&msg_id).await.unwrap();
    assert!(
        matches!(delivery, Some(Delivery::Accepted { .. })),
        "{delivery:?}"
    );
}

/// How many [`AppEvent::DeliveryUnknown`] events for `msg_id` are among `events`.
fn unknown(events: &[AppEvent], msg_id: &str) -> usize {
    events
        .iter()
        .filter(|e| matches!(e, AppEvent::DeliveryUnknown { msg_id: m, .. } if m == msg_id))
        .count()
}

/// The `MessageUndelivered` events for `msg_id` among `events`, with their `resend`.
fn undelivered(events: &[AppEvent], msg_id: &str) -> Vec<bool> {
    events
        .iter()
        .filter_map(|e| match e {
            AppEvent::MessageUndelivered {
                msg_id: m, resend, ..
            } if m == msg_id => Some(*resend),
            _ => None,
        })
        .collect()
}

#[tokio::test]
async fn test_queue_stored_given_up_once_is_refused_after() {
    // Queued within its window to a recipient that doesn't admit the sender, so it stays
    // queued until the deadline: given up once, the protocol told once; every later call is
    // refused, queues nothing and tells nothing.
    let p = Pair::new();
    let protocol = ApiProtocol::new(Mode::Plain);
    let mut wallet = p.join(&p.alice, "wallet", &protocol).await;
    let _shop = p.join(&p.bob, "shop", &protocol).await;
    let alice = p.alice.identity().public();
    let signed = wallet.sign_message(Pair::note(&p.bob, "old")).unwrap();
    p.clock.advance_ms(25 * DAY_MS);
    let msg_id = wallet.queue_stored(signed.plaintext()).await.unwrap();
    wallet.flush_outbox().await.unwrap();
    p.clock.advance_ms(5 * DAY_MS);
    let report = wallet.flush_outbox().await.unwrap();
    assert_eq!(report.unknown, vec![msg_id.clone()]);
    assert_eq!(unknown(&wallet.take_events(), &msg_id), 1);
    for _ in 0..2 {
        let error = wallet.queue_stored(signed.plaintext()).await.unwrap_err();
        assert!(
            matches!(
                error,
                AppError::Refused(Refusal::WontDeliver(WontDeliver::GivenUp))
            ),
            "{error:?}"
        );
        let report = wallet.flush_outbox().await.unwrap();
        assert!(report.undelivered.is_empty(), "{report:?}");
    }
    assert!(wallet.take_events().is_empty());
    assert_eq!(
        unknown(&wallet.unacknowledged_events().await.unwrap(), &msg_id),
        1,
        "one duty event"
    );
    assert_eq!(p.bob.switch().entries_from(&alice), 0);
    // Past the mark's month, the replay deadline refuses it.
    p.clock.advance_ms(SENT_RETENTION_MS + MINUTE);
    wallet.flush_outbox().await.unwrap();
    let error = wallet.queue_stored(signed.plaintext()).await.unwrap_err();
    assert!(
        matches!(
            error,
            AppError::Refused(Refusal::WontDeliver(WontDeliver::PastReplayWindow { .. }))
        ),
        "{error:?}"
    );
}

#[tokio::test]
async fn test_queue_stored_resend_past_the_deadline_is_given_up() {
    // The copy is accepted at day 25. Ten days later a re-send asked of it is past the
    // message's replay deadline: given up with `resend: true`, nothing delivered again.
    let p = Pair::new();
    let protocol = ApiProtocol::new(Mode::Plain);
    let mut wallet = p.join(&p.alice, "wallet", &protocol).await;
    let mut shop = p.join(&p.bob, "shop", &protocol).await;
    let alice = p.alice.identity().public();
    shop.invite(&alice).await.unwrap();
    let signed = wallet.sign_message(Pair::note(&p.bob, "hello")).unwrap();
    p.clock.advance_ms(25 * DAY_MS);
    let msg_id = wallet.queue_stored(signed.plaintext()).await.unwrap();
    let delivery = wallet.flush_message(&msg_id).await.unwrap();
    assert!(
        matches!(delivery, Some(Delivery::Accepted { .. })),
        "{delivery:?}"
    );
    assert_eq!(p.bob.switch().entries_from(&alice), 1);
    p.clock.advance_ms(10 * DAY_MS);
    wallet.take_events();
    wallet.resend(&msg_id).await.unwrap();
    assert_eq!(undelivered(&wallet.take_events(), &msg_id), vec![true]);
    assert_eq!(
        p.bob.switch().entries_from(&alice),
        1,
        "not delivered again"
    );
    // Within the deadline a re-send goes.
    let fresh = wallet.sign_message(Pair::note(&p.bob, "fresh")).unwrap();
    let msg_id = wallet.queue_stored(fresh.plaintext()).await.unwrap();
    wallet.flush_message(&msg_id).await.unwrap();
    p.clock.advance_ms(DAY_MS);
    let delivery = wallet.resend(&msg_id).await.unwrap();
    assert!(
        matches!(delivery, Delivery::Accepted { .. }),
        "{delivery:?}"
    );
    assert_eq!(p.bob.switch().entries_from(&alice), 3);
}

#[tokio::test]
async fn test_queue_stored_after_the_sent_copy_is_forgotten_is_refused() {
    // The copy is accepted, and forgotten from the sent messages 30 days later: by then it
    // is past the replay deadline, so a later call is refused and tells nothing.
    let p = Pair::new();
    let protocol = ApiProtocol::new(Mode::Plain);
    let mut wallet = p.join(&p.alice, "wallet", &protocol).await;
    let mut shop = p.join(&p.bob, "shop", &protocol).await;
    let alice = p.alice.identity().public();
    shop.invite(&alice).await.unwrap();
    let signed = wallet.sign_message(Pair::note(&p.bob, "hello")).unwrap();
    let msg_id = wallet.queue_stored(signed.plaintext()).await.unwrap();
    let delivery = wallet.flush_message(&msg_id).await.unwrap();
    assert!(
        matches!(delivery, Some(Delivery::Accepted { .. })),
        "{delivery:?}"
    );
    p.clock.advance_ms(SENT_RETENTION_MS + MINUTE);
    wallet.flush_outbox().await.unwrap();
    assert_eq!(wallet.delivery(&msg_id).await.unwrap(), None);
    wallet.take_events();
    let error = wallet.queue_stored(signed.plaintext()).await.unwrap_err();
    assert!(
        matches!(
            error,
            AppError::Refused(Refusal::WontDeliver(WontDeliver::PastReplayWindow { .. }))
        ),
        "{error:?}"
    );
    wallet.flush_outbox().await.unwrap();
    assert!(undelivered(&wallet.take_events(), &msg_id).is_empty());
    assert_eq!(p.bob.switch().entries_from(&alice), 1);
}

#[tokio::test]
async fn test_queue_stored_refuses_a_plaintext_that_isnt_a_message() {
    let p = Pair::new();
    let protocol = ApiProtocol::new(Mode::Plain);
    let mut wallet = p.join(&p.alice, "wallet", &protocol).await;
    let keys = p.alice.identity().app_keys("wallet");
    let bob = p.bob.identity().public();
    let json = br#"{"v":1,"kind":"sample.note"}"#.to_vec();
    let signature = keys.sign(pubky_switch_core::labels::sig::MSG, &[&bob, &json]);
    let plaintext = MessagePlaintext::from_parts(wallet.app_id(), signature, json).unwrap();
    let error = wallet.queue_stored(&plaintext).await.unwrap_err();
    assert!(
        matches!(&error, AppError::Refused(Refusal::Usage(why)) if why.contains("without valid message fields")),
        "{error:?}"
    );
}

#[tokio::test]
async fn test_queue_stored_reads_the_protocols_opaque_members() {
    // A body member the protocol names opaque may hold any number, such as a fraction: the
    // stored message reads as the protocol signed it, and is queued.
    let p = Pair::new();
    let protocol = ApiProtocol::new(Mode::Plain);
    *protocol.opaque.lock().unwrap() = vec![crate::app::OpaqueRule {
        kind: None,
        member: "score".into(),
    }];
    let mut wallet = p.join(&p.alice, "wallet", &protocol).await;
    let mut body = Map::new();
    body.insert("score".into(), json!(1.5));
    let message = OutgoingMessage::new(p.bob.identity().public(), "sample.note", body);
    let signed = wallet.sign_message(message).unwrap();
    let msg_id = wallet.queue_stored(signed.plaintext()).await.unwrap();
    assert_eq!(msg_id, signed.msg_id());
    assert!(wallet.outbox_record(&msg_id).await.is_some());
}

/// A queued message is read by its signed common fields, so a host update that narrows
/// the protocol's opaque members doesn't stop its delivery.
#[tokio::test]
async fn test_queue_stored_narrowed_opaque_members_still_deliver() {
    let p = Pair::new();
    let protocol = ApiProtocol::new(Mode::Plain);
    *protocol.opaque.lock().unwrap() = vec![crate::app::OpaqueRule {
        kind: None,
        member: "score".into(),
    }];
    let mut wallet = p.join(&p.alice, "wallet", &protocol).await;
    let mut shop = p.join(&p.bob, "shop", &protocol).await;
    shop.invite(&p.alice.identity().public()).await.unwrap();
    let mut body = Map::new();
    body.insert("score".into(), json!(1.5));
    let message = OutgoingMessage::new(p.bob.identity().public(), "sample.note", body);
    let signed = wallet.sign_message(message).unwrap();
    protocol.opaque.lock().unwrap().clear();
    let msg_id = wallet.queue_stored(signed.plaintext()).await.unwrap();
    let delivery = wallet.flush_message(&msg_id).await;
    assert!(
        matches!(delivery, Ok(Some(Delivery::Accepted { .. }))),
        "{delivery:?}"
    );
}

#[tokio::test]
async fn test_queue_stored_copy_notifies_and_adds_the_reply_grant() {
    let p = Pair::new();
    let protocol = ApiProtocol::new(Mode::Plain);
    let mut wallet = p.join(&p.alice, "wallet", &protocol).await;
    let mut shop = p.join(&p.bob, "shop", &protocol).await;
    let alice = p.alice.identity().public();
    let bob = p.bob.identity().public();
    shop.invite(&alice).await.unwrap();
    let signed = wallet.sign_message(Pair::note(&p.bob, "hello")).unwrap();
    let msg_id = wallet.queue_stored(signed.plaintext()).await.unwrap();
    let item = wallet.outbox_record(&msg_id).await.unwrap();
    assert_eq!(item.notify_and_grant_reply(), (true, true));
    wallet.flush_message(&msg_id).await.unwrap();
    let entries = p
        .alice
        .switch()
        .applied()
        .iter()
        .filter(|op| {
            matches!(
                op.body().kind,
                OpKind::AllowPut { pubky, reason: pubky_switch_core::admission::PeerReason::Reply }
                    if pubky == bob
            )
        })
        .count();
    assert_eq!(entries, 1, "the reply grant its kind needs");
}

/// A copy given up within its window because its try is too large for the store is
/// refused by its mark, not queued again.
#[tokio::test]
async fn test_queue_stored_after_a_too_large_give_up_is_refused() {
    let p = Pair::new();
    let protocol = ApiProtocol::new(Mode::Plain);
    let (mut wallet, _shop, store) = wallet_on_a_fault_store(&p, &protocol).await;
    let signed = wallet.sign_message(Pair::note(&p.bob, "hello")).unwrap();
    let msg_id = wallet.queue_stored(signed.plaintext()).await.unwrap();
    store.refuse_puts_as_too_large_once(format!("out/{msg_id}").as_bytes());
    wallet.take_events();
    let report = wallet.flush_outbox().await.unwrap();
    assert_eq!(report.unknown, vec![msg_id.clone()], "{report:?}");
    assert_eq!(unknown(&wallet.take_events(), &msg_id), 1);
    let error = wallet.queue_stored(signed.plaintext()).await.unwrap_err();
    assert!(
        matches!(
            error,
            AppError::Refused(Refusal::WontDeliver(WontDeliver::GivenUp))
        ),
        "{error:?}"
    );
    // A message whose own record doesn't fit: refused, nothing written, nothing told.
    store.refuse_puts_as_too_large(Some(b"out/"));
    let fresh = wallet.sign_message(Pair::note(&p.bob, "fresh")).unwrap();
    let error = wallet.queue_stored(fresh.plaintext()).await.unwrap_err();
    assert!(
        matches!(
            error,
            AppError::Refused(Refusal::WontDeliver(WontDeliver::TooLarge))
        ),
        "{error:?}"
    );
    store.refuse_puts_as_too_large(None);
    assert_eq!(wallet.delivery(fresh.msg_id()).await.unwrap(), None);
    assert!(undelivered(&wallet.take_events(), fresh.msg_id()).is_empty());
}

/// A message a restore left out of its outbox is refused by its mark.
#[tokio::test]
async fn test_queue_stored_left_out_by_a_restore_is_refused() {
    let p = Pair::new();
    let protocol = ApiProtocol::new(Mode::Plain);
    let mut wallet = p.join(&p.alice, "wallet", &protocol).await;
    let text = "x".repeat(40_000);
    let mut last = None;
    for _ in 0..260 {
        let signed = wallet.sign_message(Pair::note(&p.bob, &text)).unwrap();
        last = Some(signed.plaintext().clone());
        wallet.queue_signed(signed).await.unwrap();
        p.clock.advance_ms(1);
    }
    let last = last.unwrap();
    let msg_id = Message::parse(last.json(), &[]).unwrap().msg_id;
    let backup = wallet.backup().await.unwrap();
    drop(wallet);
    let mut restored = restored_wallet(&p, &protocol, &backup).await;
    assert_eq!(restored.delivery(&msg_id).await.unwrap(), None);
    let error = restored.queue_stored(&last).await.unwrap_err();
    assert!(
        matches!(
            error,
            AppError::Refused(Refusal::WontDeliver(WontDeliver::GivenUp))
        ),
        "{error:?}"
    );
}

/// On the device that keeps the batch, a copy given up at its deadline, then the kept batch
/// settling: the message isn't queued again, and doesn't go.
#[tokio::test]
async fn test_queue_stored_given_up_then_its_kept_batch_settles_queues_nothing() {
    let p = Pair::new();
    let protocol = ApiProtocol::new(Mode::Plain);
    let mut wallet = p.join(&p.alice, "wallet", &protocol).await;
    let shop = p.join(&p.bob, "shop", &protocol).await;
    let alice = p.alice.identity().public();
    let start = p.clock.now_ms();
    let signed = wallet.sign_message(Pair::note(&p.bob, "hello")).unwrap();
    p.clock.advance_ms(120 * MINUTE);
    let target = RecordTarget::new(items(), &signed.hash());
    let entry = wallet
        .record_op(&target, Some(&stored_value(&signed)), vec![])
        .await
        .unwrap();
    p.alice
        .switch()
        .fail_next(Fault::LoseAnswer { path: "ops".into() });
    let error = wallet
        .submit_batch(OpBatch::new().entry(entry).queue(signed.clone()))
        .await
        .unwrap_err();
    assert!(error.kept_batch().is_some(), "{error:?}");
    let msg_id = wallet.queue_stored(signed.plaintext()).await.unwrap();
    p.clock.set_ms(start + SENT_RETENTION_MS);
    for _ in 0..6 {
        p.alice.switch().fail_next(Fault::Unreachable {
            path: "ops".into(),
            after: 0,
        });
    }
    wallet.take_events();
    let report = wallet.flush_outbox().await.unwrap();
    assert_eq!(report.unknown, vec![msg_id.clone()], "{report:?}");
    assert_eq!(unknown(&wallet.take_events(), &msg_id), 1);
    p.alice.switch().lock().faults.clear();
    let mut shop = shop;
    shop.invite(&alice).await.unwrap();
    let report = wallet.flush_outbox().await.unwrap();
    let events = wallet.take_events();
    let accepted = events
        .iter()
        .any(|e| matches!(e, AppEvent::MessageAccepted { msg_id: m, .. } if *m == msg_id));
    assert!(
        !accepted && p.bob.switch().entries_from(&alice) == 0,
        "given up, and not delivered {} after the message was signed: {report:?}",
        p.clock.now_ms() - start
    );
}

/// A plain message's re-send queued 29 days after its first acceptance, and kept from going
/// by the network, is given up 30 days after it, not delivered at 40.
#[tokio::test]
async fn test_resend_past_30_days_from_first_acceptance_is_given_up() {
    let p = Pair::new();
    let protocol = ApiProtocol::new(Mode::Plain);
    let mut wallet = p.join(&p.alice, "wallet", &protocol).await;
    let mut shop = p.join(&p.bob, "shop", &protocol).await;
    let alice = p.alice.identity().public();
    shop.invite(&alice).await.unwrap();
    let (msg_id, delivery) = wallet.send(Pair::note(&p.bob, "hello")).await.unwrap();
    let Delivery::Accepted { accepted_at_ms } = delivery else {
        panic!("{delivery:?}");
    };
    p.clock.set_ms(accepted_at_ms + 29 * DAY_MS);
    for _ in 0..4 {
        p.bob.switch().fail_next(Fault::Unreachable {
            path: "inbox".into(),
            after: 0,
        });
    }
    let delivery = wallet.resend(&msg_id).await.unwrap();
    assert!(matches!(delivery, Delivery::Queued { .. }), "{delivery:?}");
    p.bob.switch().lock().faults.clear();
    p.clock.set_ms(accepted_at_ms + 40 * DAY_MS);
    wallet.take_events();
    wallet.flush_outbox().await.unwrap();
    assert_eq!(
        p.bob.switch().entries_from(&alice),
        1,
        "not re-sent 40 days after its first acceptance"
    );
    assert_eq!(undelivered(&wallet.take_events(), &msg_id), vec![true]);
}

#[tokio::test]
async fn test_queue_stored_give_up_mark_is_pruned_after_its_month() {
    let p = Pair::new();
    let protocol = ApiProtocol::new(Mode::Plain);
    let mut wallet = p.join(&p.alice, "wallet", &protocol).await;
    let _shop = p.join(&p.bob, "shop", &protocol).await;
    let signed = wallet.sign_message(Pair::note(&p.bob, "old")).unwrap();
    p.clock.advance_ms(25 * DAY_MS);
    wallet.queue_stored(signed.plaintext()).await.unwrap();
    p.clock.advance_ms(5 * DAY_MS);
    wallet.flush_outbox().await.unwrap();
    let marks = |app: &App| {
        let app = app.reader();
        async move { app.scan_raw("outgone/").await.unwrap().len() }
    };
    assert_eq!(marks(&wallet).await, 1);
    p.clock.advance_ms(SENT_RETENTION_MS - MINUTE);
    wallet.flush_outbox().await.unwrap();
    assert_eq!(marks(&wallet).await, 1, "kept its month");
    p.clock.advance_ms(2 * MINUTE);
    wallet.flush_outbox().await.unwrap();
    assert_eq!(marks(&wallet).await, 0, "pruned after it");
}

/// One run of the scenario of a message signed, its record written from its hash in the
/// batch that queues it, then delivered. Returns at the first error, as a process that
/// died.
async fn signed_scenario(
    p: &Pair,
    protocol: &Arc<ApiProtocol>,
    store: Arc<dyn StateStore>,
    approval: &mut Option<JoinRequest>,
    msg_id: &mut Option<String>,
) -> Result<(), AppError> {
    let keys = p.alice.identity().app_keys("wallet");
    let env = p.alice.env_with(
        Arc::clone(&store),
        Arc::clone(&p.router) as Arc<dyn Transport>,
    );
    let mut app =
        match App::load(env.clone(), protocol.clone(), config(), keys.app_id_bytes()).await {
            Ok(app) => app,
            Err(AppError::Refused(Refusal::NotJoined)) => {
                let app = AppSpec::new(&["sample-a"]).with_permissions(&Permission::ALL);
                let request = approval
                    .get_or_insert_with(|| p.alice.approve(&keys, &app).unwrap())
                    .clone();
                App::join(env, protocol.clone(), config(), request).await?
            }
            Err(error) => return Err(error),
        };
    app.receive(None).await?;
    // A kept batch is sent again, and what it queued delivered.
    app.flush_outbox().await?;
    let kept = match msg_id {
        Some(id) => app.delivery(id).await?.is_some(),
        None => false,
    };
    if !kept {
        let signed = app.sign_message(Pair::note(&p.bob, "hello"))?;
        *msg_id = Some(signed.msg_id().to_owned());
        let target = RecordTarget::new(items(), &signed.hash());
        let entry = app
            .record_op(&target, Some(&value(&[signed.msg_id()])), vec![])
            .await?;
        app.submit_batch(OpBatch::new().entry(entry).queue(signed))
            .await?;
        app.flush_outbox().await?;
    }
    Ok(())
}

#[tokio::test]
async fn test_signed_message_crash_at_each_commit_point_sends_and_writes_once() {
    let setup = || async {
        let p = Pair::new();
        let protocol = ApiProtocol::new(Mode::Plain);
        let mut shop = p.join(&p.bob, "shop", &protocol).await;
        shop.invite(&p.alice.identity().public()).await.unwrap();
        (p, protocol)
    };
    let commits = {
        let (p, protocol) = setup().await;
        let counting = Arc::new(FaultStore::new(
            Arc::new(MemoryStore::new()) as Arc<dyn StateStore>,
            StoreFault::None,
        ));
        signed_scenario(
            &p,
            &protocol,
            Arc::clone(&counting) as Arc<dyn StateStore>,
            &mut None,
            &mut None,
        )
        .await
        .unwrap();
        counting.commits()
    };
    assert!(commits > 6, "the scenario commits {commits} times");
    for stop_after in [false, true] {
        for n in 1..=commits {
            let (p, protocol) = setup().await;
            let inner = Arc::new(MemoryStore::new());
            let fault = Arc::new(FaultStore::new(
                Arc::clone(&inner) as Arc<dyn StateStore>,
                if stop_after {
                    StoreFault::StopAfter(n)
                } else {
                    StoreFault::StopBefore(n)
                },
            ));
            let mut approval = None;
            let mut msg_id = None;
            let first = signed_scenario(
                &p,
                &protocol,
                Arc::clone(&fault) as Arc<dyn StateStore>,
                &mut approval,
                &mut msg_id,
            )
            .await;
            assert!(fault.stopped(), "commit {n} of {commits} is reached");
            assert!(first.is_err());
            signed_scenario(
                &p,
                &protocol,
                Arc::clone(&inner) as Arc<dyn StateStore>,
                &mut approval,
                &mut msg_id,
            )
            .await
            .unwrap_or_else(|e| panic!("restart after commit {n} ({stop_after}): {e}"));
            let alice = p.alice.identity().public();
            assert_eq!(
                p.bob.switch().entries_from(&alice),
                1,
                "commit {n} ({stop_after})"
            );
            let puts = p
                .alice
                .switch()
                .applied()
                .iter()
                .filter(|op| matches!(op.body().kind, OpKind::RecordPut(_)))
                .count();
            assert_eq!(puts, 1, "commit {n} ({stop_after})");
            let app = App::load(
                p.alice
                    .env_with(inner.clone(), Arc::clone(&p.router) as Arc<dyn Transport>),
                protocol.clone(),
                config(),
                p.alice.identity().app_keys("wallet").app_id_bytes(),
            )
            .await
            .unwrap();
            let msg_id = msg_id.clone().unwrap();
            assert!(matches!(
                app.delivery(&msg_id).await.unwrap(),
                Some(Delivery::Accepted { .. })
            ));
        }
    }
}

// -------------------------------------------------------------------------------------
// A counterparty's identity.json (Switch spec 4.3, "The switch's copy")

#[tokio::test]
async fn test_identity_of_takes_the_switch_copy_when_higher() {
    let p = Pair::new();
    let protocol = ApiProtocol::new(Mode::Plain);
    let mut wallet = p.join(&p.alice, "wallet", &protocol).await;
    let _shop = p.join(&p.bob, "shop", &protocol).await;
    // The switch holds a version the Homeserver doesn't publish yet.
    let mut body = p.bob.body();
    body.version += 1;
    let newer = IdentityDoc::sign(p.bob.identity().key(), body).unwrap();
    p.bob.switch().deliver_identity(&newer).unwrap();
    let bob = p.bob.identity().public();
    let found = wallet.identity_of(&bob, false).await.unwrap();
    assert_eq!(found.doc.version(), newer.version());
    assert_eq!(found.switch_copy, SwitchCopy::Read);
    assert_eq!(found.read_at_ms, Some(START));
    // Within 10 minutes the copy held is used, nothing read.
    let reads = p.router.log().len();
    p.clock.advance_ms(9 * MINUTE);
    let cached = wallet.identity_of(&bob, false).await.unwrap();
    assert_eq!(cached.doc.version(), newer.version());
    assert_eq!(p.router.log().len(), reads);
    // After them, read again.
    p.clock.advance_ms(2 * MINUTE);
    wallet.identity_of(&bob, false).await.unwrap();
    assert!(p.router.log().len() > reads);
}

#[tokio::test]
async fn test_identity_of_without_the_switch_stands_on_the_homeserver() {
    let p = Pair::new();
    let protocol = ApiProtocol::new(Mode::Plain);
    let mut wallet = p.join(&p.alice, "wallet", &protocol).await;
    let _shop = p.join(&p.bob, "shop", &protocol).await;
    p.router.remove(BOB_ORIGIN);
    let bob = p.bob.identity().public();
    let found = wallet.identity_of(&bob, true).await.unwrap();
    assert_eq!(found.switch_copy, SwitchCopy::Unavailable);
    assert_eq!(found.doc.version(), p.bob.body().version);
    // The failed lookup counts until the copy is 10 minutes old.
    p.router.add_switch(BOB_ORIGIN, p.bob.switch());
    let again = wallet.identity_of(&bob, false).await.unwrap();
    assert_eq!(again.switch_copy, SwitchCopy::Unavailable);
    let refreshed = wallet.identity_of(&bob, true).await.unwrap();
    assert_eq!(refreshed.switch_copy, SwitchCopy::Read);
}

#[tokio::test]
async fn test_identity_of_refuses_an_equivocating_counterparty() {
    let p = Pair::new();
    let protocol = ApiProtocol::new(Mode::Plain);
    let mut wallet = p.join(&p.alice, "wallet", &protocol).await;
    let _shop = p.join(&p.bob, "shop", &protocol).await;
    // Another body at the version the Homeserver publishes.
    let mut body = p.bob.body();
    body.apps.clear();
    let other = IdentityDoc::sign(p.bob.identity().key(), body).unwrap();
    p.bob.switch().deliver_identity(&other).unwrap();
    let bob = p.bob.identity().public();
    let error = wallet.identity_of(&bob, false).await.unwrap_err();
    assert!(
        matches!(error, AppError::Refused(Refusal::NotNow(_))),
        "{error:?}"
    );
    assert!(
        wallet
            .take_events()
            .iter()
            .any(|e| matches!(e, AppEvent::PeerEquivocation { .. }))
    );
    // From then on no copy of it is used.
    assert!(wallet.identity_of(&bob, true).await.is_err());
    // Nor is the own identity looked up so.
    let alice = p.alice.identity().public();
    let own = wallet.identity_of(&alice, false).await.unwrap_err();
    assert!(matches!(own, AppError::Refused(Refusal::Usage(_))));
}

// -------------------------------------------------------------------------------------
// A sender's standing in the lists, as a receive step reads it (Switch spec 7 "Spam")

/// The disposition the receive step saw for the last message.
fn last_disposition(protocol: &ApiProtocol) -> SenderDisposition {
    protocol.seen().last().unwrap().disposition.unwrap()
}

/// Bob's shop with alice invited, and a note from alice's wallet waiting in its inbox.
async fn shop_with_a_note(p: &Pair, protocol: &Arc<ApiProtocol>) -> App {
    let mut wallet = p.join(&p.alice, "wallet", protocol).await;
    let mut shop = p.join(&p.bob, "shop", protocol).await;
    shop.invite(&p.alice.identity().public()).await.unwrap();
    let (_, delivery) = wallet.send(Pair::note(&p.bob, "hello")).await.unwrap();
    assert!(
        matches!(delivery, Delivery::Accepted { .. }),
        "{delivery:?}"
    );
    shop
}

#[tokio::test]
async fn test_sender_disposition_neither_after_a_refresh() {
    let p = Pair::new();
    let protocol = ApiProtocol::new(Mode::Plain);
    let mut shop = shop_with_a_note(&p, &protocol).await;
    // Another sender is flagged and blocked; alice is neither.
    let carol = p.carol.identity().public();
    p.bob.switch().lock().shared.flagged.insert(carol, 3);
    shop.deny(&carol).await.unwrap();
    shop.allow_list().await.unwrap();
    let as_of = shop.highest_service_time();
    shop.receive(None).await.unwrap();
    let seen = last_disposition(&protocol);
    assert!(!seen.blocked && !seen.flagged, "{seen:?}");
    assert!(as_of.is_some());
    assert_eq!(seen.lists_as_of_ms, as_of);
}

#[tokio::test]
async fn test_sender_disposition_blocked() {
    let p = Pair::new();
    let protocol = ApiProtocol::new(Mode::Plain);
    let mut shop = shop_with_a_note(&p, &protocol).await;
    // Denied after the inbox accepted the note.
    shop.deny(&p.alice.identity().public()).await.unwrap();
    shop.allow_list().await.unwrap();
    shop.receive(None).await.unwrap();
    let seen = last_disposition(&protocol);
    assert!(seen.blocked && !seen.flagged, "{seen:?}");
}

#[tokio::test]
async fn test_sender_disposition_flagged() {
    let p = Pair::new();
    let protocol = ApiProtocol::new(Mode::Plain);
    let mut shop = shop_with_a_note(&p, &protocol).await;
    let alice = p.alice.identity().public();
    p.bob.switch().lock().shared.flagged.insert(alice, 4);
    let list = shop.allow_list().await.unwrap();
    assert_eq!(list.flagged.len(), 1);
    shop.receive(None).await.unwrap();
    let seen = last_disposition(&protocol);
    assert!(seen.flagged && !seen.blocked, "{seen:?}");
    assert!(seen.lists_as_of_ms.is_some());
}

#[tokio::test]
async fn test_sender_disposition_refresh_clears_a_flag() {
    let p = Pair::new();
    let protocol = ApiProtocol::new(Mode::Plain);
    let mut shop = shop_with_a_note(&p, &protocol).await;
    let alice = p.alice.identity().public();
    p.bob.switch().lock().shared.flagged.insert(alice, 3);
    shop.allow_list().await.unwrap();
    let first = shop.highest_service_time().unwrap();
    // The service drops the flag; the next refresh replaces the copy.
    p.bob.switch().lock().shared.flagged.clear();
    p.clock.advance_ms(MINUTE);
    shop.allow_list().await.unwrap();
    shop.receive(None).await.unwrap();
    let seen = last_disposition(&protocol);
    assert!(!seen.flagged && !seen.blocked, "{seen:?}");
    assert!(seen.lists_as_of_ms.unwrap() >= first + MINUTE, "{seen:?}");
}

#[tokio::test]
async fn test_sender_disposition_never_refreshed_shows_only_own_deny_changes() {
    let p = Pair::new();
    let protocol = ApiProtocol::new(Mode::Plain);
    let mut wallet = p.join(&p.alice, "wallet", &protocol).await;
    // Without `lists.read` the shop never reads its lists.
    let mut shop = p
        .join_with(
            &p.bob,
            "shop",
            protocol.clone(),
            Arc::new(MemoryStore::new()),
            &[Permission::ListsManage, Permission::ReplyAdd],
        )
        .await;
    let alice = p.alice.identity().public();
    shop.invite(&alice).await.unwrap();
    wallet.send(Pair::note(&p.bob, "hello")).await.unwrap();
    // The service flags alice; only the shop's own deny shows, and the copy is unknown.
    p.bob.switch().lock().shared.flagged.insert(alice, 3);
    shop.deny(&alice).await.unwrap();
    shop.receive(None).await.unwrap();
    let seen = last_disposition(&protocol);
    assert_eq!(seen.lists_as_of_ms, None);
    assert!(seen.blocked && !seen.flagged, "{seen:?}");
}

#[tokio::test]
async fn test_sender_disposition_first_read_refreshes_a_copy_never_refreshed() {
    let p = Pair::new();
    let protocol = ApiProtocol::new(Mode::Plain);
    let mut shop = shop_with_a_note(&p, &protocol).await;
    let alice = p.alice.identity().public();
    p.bob.switch().lock().shared.flagged.insert(alice, 3);
    // No allow_list(): the read refreshes the copy before it hands the note over.
    shop.receive(None).await.unwrap();
    let seen = last_disposition(&protocol);
    assert!(seen.flagged, "{seen:?}");
    assert!(seen.lists_as_of_ms.is_some());
}

#[tokio::test]
async fn test_sender_disposition_lists_as_of_is_service_time() {
    let p = Pair::new();
    let protocol = ApiProtocol::new(Mode::Plain);
    let mut wallet = p.join(&p.alice, "wallet", &protocol).await;
    // The shop's device clock runs two minutes ahead of the service, within the timestamp
    // tolerance.
    let keys = p.bob.identity().app_keys("shop");
    let request = p
        .bob
        .approve(
            &keys,
            &AppSpec::new(&["sample-a"]).with_permissions(&Permission::ALL),
        )
        .unwrap();
    let mut env = p.env(&p.bob, Arc::new(MemoryStore::new()));
    let device = Arc::new(crate::clock::TestClock::new(p.clock.now_ms() + 2 * MINUTE));
    env.clock = device.clone();
    let mut shop = App::join(env, protocol.clone(), config(), request)
        .await
        .unwrap();
    shop.invite(&p.alice.identity().public()).await.unwrap();
    wallet.send(Pair::note(&p.bob, "hello")).await.unwrap();
    shop.allow_list().await.unwrap();
    shop.receive(None).await.unwrap();
    let as_of = last_disposition(&protocol).lists_as_of_ms.unwrap();
    assert_eq!(as_of, p.clock.now_ms());
    assert_ne!(as_of, device.now_ms());
}

#[tokio::test]
async fn test_sender_disposition_answer_without_flagged_replaces_nothing() {
    let p = Pair::new();
    let protocol = ApiProtocol::new(Mode::Plain);
    let mut shop = shop_with_a_note(&p, &protocol).await;
    let alice = p.alice.identity().public();
    p.bob.switch().lock().shared.flagged.insert(alice, 3);
    shop.allow_list().await.unwrap();
    // The read tells the gap `allow_list` owes, the copy taken again from its answer.
    shop.receive(None).await.unwrap();
    let as_of = shop.highest_service_time();
    // A faulty answer leaves `flagged` out: malformed, so the copy stays as it was.
    p.clock.advance_ms(MINUTE);
    p.bob.switch().lock().allow = Some(json!({
        "peers": [], "deny": [], "invite_codes": []
    }));
    let error = shop.allow_list().await.unwrap_err();
    assert!(
        matches!(
            error,
            AppError::Switch(crate::ClientError::InvalidResponse(_))
        ),
        "{error:?}"
    );
    shop.receive(None).await.unwrap();
    let seen = last_disposition(&protocol);
    assert!(seen.flagged, "{seen:?}");
    assert_eq!(seen.lists_as_of_ms, as_of);
}

/// A restore of bob's shop after it denied alice: her note, accepted before the deny, is
/// stored locally, and the shop's feed read has passed the deny. Returns the restored shop,
/// on the returned new store, with alice's note to be tried again.
async fn shop_restored_after_a_deny(
    p: &Pair,
    protocol: &Arc<ApiProtocol>,
    permissions: &[Permission],
) -> (App, Arc<MemoryStore>) {
    let mut wallet = p.join(&p.alice, "wallet", protocol).await;
    let mut shop = p
        .join_with(
            &p.bob,
            "shop",
            protocol.clone(),
            Arc::new(MemoryStore::new()),
            permissions,
        )
        .await;
    let alice = p.alice.identity().public();
    shop.invite(&alice).await.unwrap();
    wallet.send(Pair::note(&p.bob, "hello")).await.unwrap();
    // The store rejects the note: it is stored locally, and stays so at the next read.
    *protocol.reject.lock().unwrap() = 2;
    shop.receive(None).await.unwrap();
    shop.deny(&alice).await.unwrap();
    shop.receive(None).await.unwrap();
    let backup = shop.backup_layered().await.unwrap();
    let backup = AppBackup::from_bytes(&backup.to_bytes().unwrap()).unwrap();
    protocol.seen.lock().unwrap().clear();
    let store = Arc::new(MemoryStore::new());
    let restored = App::restore(
        p.env(&p.bob, Arc::clone(&store) as Arc<dyn StateStore>),
        protocol.clone(),
        config(),
        &backup,
    )
    .await
    .unwrap();
    (restored, store)
}

/// Whether `shop`'s copy of the lists holds a refresh time.
fn refreshed(store: &MemoryStore, shop: &App) -> bool {
    let ns = crate::store::client_namespace(&shop.app_id());
    store.get(&ns, b"lc/lists_at").unwrap().is_some()
}

/// The disposition the receive step saw for alice's note after the restore, read until it
/// is handed over.
async fn restored_disposition(shop: &mut App, protocol: &ApiProtocol) -> SenderDisposition {
    for _ in 0..3 {
        shop.receive(None).await.unwrap();
        if let Some(seen) = protocol.seen().last() {
            return seen.disposition.unwrap();
        }
    }
    panic!("the stored note was never tried again");
}

#[tokio::test]
async fn test_sender_disposition_after_a_restore_refreshes_before_a_stored_entry() {
    let p = Pair::new();
    let protocol = ApiProtocol::new(Mode::Plain);
    let (mut shop, _) = shop_restored_after_a_deny(&p, &protocol, &Permission::ALL).await;
    let seen = restored_disposition(&mut shop, &protocol).await;
    assert!(seen.blocked, "{seen:?}");
    assert!(seen.lists_as_of_ms.is_some());
}

#[tokio::test]
async fn test_sender_disposition_after_a_restore_without_lists_read_keeps_the_backups_deny() {
    let p = Pair::new();
    let protocol = ApiProtocol::new(Mode::Plain);
    let (mut shop, store) = shop_restored_after_a_deny(
        &p,
        &protocol,
        &[Permission::ListsManage, Permission::ReplyAdd],
    )
    .await;
    // The backup retains the app's deny. Its list is still incomplete without a signed read.
    let seen = restored_disposition(&mut shop, &protocol).await;
    assert_eq!(seen.lists_as_of_ms, None);
    assert!(seen.blocked, "{seen:?}");
    assert!(!refreshed(&store, &shop));
}

#[tokio::test]
async fn test_sender_disposition_failed_refresh_after_a_restore_holds_the_read() {
    // A restore with `lists.read` owes the protocol a deny list gap, told with the lists
    // read for it: while that read fails, the read holds and hands nothing, so no entry is
    // handed with the copy unknown. The next read tells the gap and takes the copy.
    let p = Pair::new();
    let protocol = ApiProtocol::new(Mode::Plain);
    let (mut shop, store) = shop_restored_after_a_deny(&p, &protocol, &Permission::ALL).await;
    p.bob.switch().fail_next(Fault::Error {
        path: "allow".into(),
        code: ErrorCode::Unavailable,
        current: json!(null),
    });
    let held = shop.receive(None).await.unwrap();
    assert!(held.stopped);
    assert!(protocol.seen().is_empty());
    assert!(!refreshed(&store, &shop));
    let seen = restored_disposition(&mut shop, &protocol).await;
    assert!(seen.blocked, "{seen:?}");
    assert!(seen.lists_as_of_ms.is_some());
    assert!(refreshed(&store, &shop));
}

#[tokio::test]
async fn test_sender_disposition_lists_too_large_for_one_commit_let_the_read_go_on() {
    let p = Pair::new();
    let protocol = ApiProtocol::new(Mode::Plain);
    let mut shop = shop_with_a_note(&p, &protocol).await;
    // More flagged senders than one commit's batch size holds, as at raised limits.
    {
        let mut switch = p.bob.switch().lock();
        for n in 0..310_000u32 {
            let mut pubky = [9u8; 32];
            pubky[..4].copy_from_slice(&n.to_be_bytes());
            switch.shared.flagged.insert(pubky, 3);
        }
    }
    // The owed refresh fails the same way at every read, and the reads go on.
    for _ in 0..2 {
        let result = shop.receive(None).await;
        assert!(result.is_ok(), "the read goes on: {result:?}");
    }
    let seen = last_disposition(&protocol);
    assert_eq!(seen.lists_as_of_ms, None);
    // The host's own refresh gets the refusal.
    let error = shop.allow_list().await.unwrap_err();
    assert!(
        matches!(
            error,
            AppError::Store(crate::error::StoreError::TooLarge { .. })
        ),
        "{error:?}"
    );
}

/// How many `GET /allow` calls the router carried.
fn allow_reads(p: &Pair) -> usize {
    p.router
        .log()
        .iter()
        .filter(|line| line.starts_with("GET ") && line.ends_with("/allow"))
        .count()
}

/// Whether the copy of the lists in `store` holds `key`.
fn lists_key(store: &MemoryStore, shop: &App, key: &[u8]) -> bool {
    let ns = crate::store::client_namespace(&shop.app_id());
    store.get(&ns, key).unwrap().is_some()
}

/// Bob's shop on `store`, with a note from alice waiting, whose first read found its lists
/// too large for one commit: the refusal is kept.
async fn shop_with_lists_too_large(
    p: &Pair,
    protocol: &Arc<ApiProtocol>,
    store: &Arc<MemoryStore>,
) -> App {
    let mut wallet = p.join(&p.alice, "wallet", protocol).await;
    let mut shop = p
        .join_on(
            &p.bob,
            "shop",
            protocol.clone(),
            Arc::clone(store) as Arc<dyn StateStore>,
        )
        .await;
    shop.invite(&p.alice.identity().public()).await.unwrap();
    wallet.send(Pair::note(&p.bob, "hello")).await.unwrap();
    {
        let mut switch = p.bob.switch().lock();
        for n in 0..310_000u32 {
            let mut pubky = [9u8; 32];
            pubky[..4].copy_from_slice(&n.to_be_bytes());
            switch.shared.flagged.insert(pubky, 3);
        }
    }
    let before = allow_reads(p);
    shop.receive(None).await.unwrap();
    assert_eq!(allow_reads(p), before + 1);
    assert!(lists_key(store, &shop, b"lc/too_large"));
    assert!(!lists_key(store, &shop, b"lc/lists_at"));
    shop
}

/// The service's flagged senders shrink to fit one commit.
fn lists_fit_again(p: &Pair) {
    p.bob.switch().lock().shared.flagged.clear();
}

#[tokio::test]
async fn test_lists_too_large_refresh_isnt_tried_again_by_the_next_read() {
    let p = Pair::new();
    let protocol = ApiProtocol::new(Mode::Plain);
    let store = Arc::new(MemoryStore::new());
    let mut shop = shop_with_lists_too_large(&p, &protocol, &store).await;
    let reads = allow_reads(&p);
    shop.receive(None).await.unwrap();
    assert_eq!(allow_reads(&p), reads);
    // Still nothing known, so still `None`.
    assert_eq!(last_disposition(&protocol).lists_as_of_ms, None);
}

#[tokio::test]
async fn test_lists_too_large_refresh_is_tried_again_after_a_day() {
    let p = Pair::new();
    let protocol = ApiProtocol::new(Mode::Plain);
    let store = Arc::new(MemoryStore::new());
    let mut shop = shop_with_lists_too_large(&p, &protocol, &store).await;
    lists_fit_again(&p);
    let reads = allow_reads(&p);
    p.clock.advance_ms(LISTS_TOO_LARGE_RETRY_MS - MINUTE);
    shop.receive(None).await.unwrap();
    assert_eq!(allow_reads(&p), reads, "not before a day");
    p.clock.advance_ms(2 * MINUTE);
    // The day is judged on the highest service time verified, which this read's page
    // moves on: the next read refreshes.
    shop.receive(None).await.unwrap();
    assert_eq!(
        allow_reads(&p),
        reads,
        "judged on the time before this read"
    );
    shop.receive(None).await.unwrap();
    assert_eq!(allow_reads(&p), reads + 1);
    assert!(lists_key(&store, &shop, b"lc/lists_at"));
    assert!(!lists_key(&store, &shop, b"lc/too_large"));
}

#[tokio::test]
async fn test_lists_too_large_explicit_refresh_is_always_tried() {
    let p = Pair::new();
    let protocol = ApiProtocol::new(Mode::Plain);
    let store = Arc::new(MemoryStore::new());
    let mut shop = shop_with_lists_too_large(&p, &protocol, &store).await;
    let reads = allow_reads(&p);
    let error = shop.allow_list().await.unwrap_err();
    assert!(
        matches!(
            error,
            AppError::Store(crate::error::StoreError::TooLarge { .. })
        ),
        "{error:?}"
    );
    assert_eq!(allow_reads(&p), reads + 1);
    assert!(lists_key(&store, &shop, b"lc/too_large"));
    lists_fit_again(&p);
    shop.allow_list().await.unwrap();
    assert!(lists_key(&store, &shop, b"lc/lists_at"));
    assert!(!lists_key(&store, &shop, b"lc/too_large"));
}

#[tokio::test]
async fn test_lists_too_large_refresh_is_tried_again_after_a_restore() {
    let p = Pair::new();
    let protocol = ApiProtocol::new(Mode::Plain);
    let store = Arc::new(MemoryStore::new());
    let mut shop = shop_with_lists_too_large(&p, &protocol, &store).await;
    lists_fit_again(&p);
    // Held back at the app's own store.
    let reads = allow_reads(&p);
    shop.receive(None).await.unwrap();
    assert_eq!(allow_reads(&p), reads);
    let backup = shop.backup_layered().await.unwrap();
    let backup = AppBackup::from_bytes(&backup.to_bytes().unwrap()).unwrap();
    let restored_store = Arc::new(MemoryStore::new());
    let mut restored = App::restore(
        p.env(&p.bob, Arc::clone(&restored_store) as Arc<dyn StateStore>),
        protocol.clone(),
        config(),
        &backup,
    )
    .await
    .unwrap();
    let reads = allow_reads(&p);
    restored.receive(None).await.unwrap();
    assert_eq!(allow_reads(&p), reads + 1);
    assert!(lists_key(&restored_store, &restored, b"lc/lists_at"));
}

#[tokio::test]
async fn test_sender_disposition_sees_an_undeny_earlier_in_the_same_read() {
    let p = Pair::new();
    let protocol = ApiProtocol::new(Mode::Plain);
    let mut wallet = p.join(&p.alice, "wallet", &protocol).await;
    let mut shop = p.join(&p.bob, "shop", &protocol).await;
    let mut kiosk = p.join(&p.bob, "kiosk", &protocol).await;
    let alice = p.alice.identity().public();
    shop.invite(&alice).await.unwrap();
    shop.deny(&alice).await.unwrap();
    // Another of bob's apps lifts the block; alice writes again.
    kiosk.undeny(&alice).await.unwrap();
    let (msg_id, delivery) = wallet.send(Pair::note(&p.bob, "hello")).await.unwrap();
    assert!(
        matches!(delivery, Delivery::Accepted { .. }),
        "{delivery:?}"
    );
    // The shop's copy still holds its own deny until the feed's undeny commits, which is in
    // the same read as the note.
    shop.receive(None).await.unwrap();
    let seen = protocol.seen();
    let seen = seen.iter().find(|s| s.msg_id == msg_id).unwrap();
    assert!(!seen.disposition.unwrap().blocked, "{seen:?}");
}

#[tokio::test]
async fn test_sender_disposition_flagged_list_is_kept_whole() {
    // `max_flags` at the default limits (Switch wire 9.2), and one more, as a service with a
    // raised limit may answer: every flagged sender is kept, as every entry of the other
    // lists is.
    const MAX_FLAGS: u32 = 1_000;
    let p = Pair::new();
    let protocol = ApiProtocol::new(Mode::Plain);
    let store = Arc::new(MemoryStore::new());
    let mut wallet = p.join(&p.alice, "wallet", &protocol).await;
    let mut shop = p
        .join_on(
            &p.bob,
            "shop",
            protocol.clone(),
            Arc::clone(&store) as Arc<dyn StateStore>,
        )
        .await;
    let alice = p.alice.identity().public();
    shop.invite(&alice).await.unwrap();
    wallet.send(Pair::note(&p.bob, "hello")).await.unwrap();
    {
        let mut switch = p.bob.switch().lock();
        for n in 0..MAX_FLAGS {
            let mut pubky = [7u8; 32];
            pubky[..4].copy_from_slice(&n.to_be_bytes());
            switch.shared.flagged.insert(pubky, 3);
        }
        switch.shared.flagged.insert(alice, 3);
    }
    let list = shop.allow_list().await.unwrap();
    assert_eq!(list.flagged.len(), 1_001);
    let ns = crate::store::client_namespace(&shop.app_id());
    let kept = store.scan(&ns, b"lc/flag/", None, 10_000).unwrap();
    assert_eq!(kept.len(), 1_001);
    shop.receive(None).await.unwrap();
    assert!(last_disposition(&protocol).flagged);
}

// -------------------------------------------------------------------------------------
// The futures of the app's calls (debug builds keep every call's state on the caller's
// stack unless it is boxed)

#[tokio::test]
async fn test_app_call_futures_are_boxed_at_the_boundary() {
    let w = World::new();
    let protocol = ApiProtocol::new(Mode::Plain);
    let mut app = join(&w, &protocol, "wallet").await;
    let bound = 256;
    let receive = std::mem::size_of_val(&app.receive(None));
    assert!(receive <= bound, "receive: {receive} bytes");
    let flush = std::mem::size_of_val(&app.flush_outbox());
    assert!(flush <= bound, "flush_outbox: {flush} bytes");
    let batch = std::mem::size_of_val(&app.submit_batch(OpBatch::new()));
    assert!(batch <= bound, "submit_batch: {batch} bytes");
    let read = std::mem::size_of_val(&app.read_record(&inbox()));
    assert!(read <= bound, "read_record: {read} bytes");
    let claim = std::mem::size_of_val(&app.read_claim(&CLAIM));
    assert!(claim <= bound, "read_claim: {claim} bytes");
    let message = Pair::note(&w.signer, "x");
    let queue = std::mem::size_of_val(&app.queue(message));
    assert!(queue <= 512, "queue: {queue} bytes");
}

#[tokio::test]
async fn test_scripted_feed_visibility_by_kind_and_currency() {
    // Switch wire 7.5: for each kind of chain item, readers shown it in full and readers
    // shown its stub; then items whose document is no longer current, a stub to their
    // readers too, the writer included (6.8 "Tombstones", 3.8).
    use pubky_switch_core::claims::Basis;
    use pubky_switch_core::records::{
        AppRecord, AppRecordBody, ListedApp, RenewedCert, seal_bundle_parts,
    };
    let p = Pair::new();
    let protocol = ApiProtocol::new(Mode::Plain);
    let mut wallet = p.join(&p.alice, "wallet", &protocol).await;
    let mut shop = p.join(&p.bob, "shop", &protocol).await;
    let switch = Arc::clone(p.bob.switch());
    let bob = p.bob.identity().clone();
    let register = |name: &str, scopes: &[&str], permissions: &[Permission]| {
        let keys = bob.app_keys(name);
        let spec = AppSpec::new(scopes).with_permissions(permissions);
        let cert = p.bob.register_app(&keys, &spec).unwrap();
        (keys, cert, switch.seq())
    };
    let (_, plain_cert, _) = register("plain", &["sample-a"], &[]);
    let (claims_keys, claims_cert, claims_put) =
        register("claims", &["sample-b"], &[Permission::ClaimsRead]);
    let (_, lists_cert, _) = register("lists", &["sample-b"], &[Permission::ListsRead]);
    let (adder_keys, adder_cert, _) = register("adder", &["sample-b"], &[Permission::ReplyAdd]);
    let (renewing_keys, renewing_cert, _) = register("renewing", &["sample-b"], &[]);
    let (plain, claims, lists, adder) = (
        plain_cert.app_id(),
        claims_cert.app_id(),
        lists_cert.app_id(),
        adder_cert.app_id(),
    );
    // (what, seq, item type, shown in full to, shown as a stub to)
    type Apps = Vec<[u8; 16]>;
    let mut rows: Vec<(&str, u64, &str, Apps, Apps)> = Vec::new();
    // A claim entry: `claims.read`.
    let attempt = |key: [u8; 32]| ClaimOp::attempt(key, 0, ATTEMPT, 3600, None);
    shop.write_claim(attempt(CLAIM), vec![], ObligationDeadline::NoDeadline)
        .await
        .unwrap();
    rows.push(("claim", switch.seq(), "op", vec![claims], vec![plain]));
    // A record write: the read scope (`sample-a`), not another scope.
    shop.put_record(&inbox(), &value(&["a"]), vec![])
        .await
        .unwrap();
    rows.push((
        "record.put",
        switch.seq(),
        "op",
        vec![plain, shop.app_id()],
        vec![claims],
    ));
    // An invite code: `lists.read` or `reply.add`, each alone.
    let code = shop.register_invite_code(START + DAY_MS, 1).await.unwrap();
    rows.push((
        "invite_code.put",
        switch.seq(),
        "op",
        vec![lists, adder],
        vec![plain],
    ));
    // The service's reply grant for a sender the code admitted: `lists.read` only.
    let before = switch.seq();
    let mut note = Pair::note(&p.bob, "hello");
    note.invite_code = Some(code.code);
    let (_, delivery) = wallet.send(note).await.unwrap();
    assert!(
        matches!(delivery, Delivery::Accepted { .. }),
        "{delivery:?}"
    );
    let added = switch
        .shown(lists)
        .into_iter()
        .find(|i| i["seq"].as_u64().unwrap() > before && i["item_type"] == "service")
        .expect("the reply.add")["seq"]
        .as_u64()
        .unwrap();
    rows.push(("reply.add", added, "service", vec![lists], vec![adder]));
    // A key bundle part: its target only.
    let part = |cert: &AppCert| {
        let sealed = seal_bundle_parts(bob.key(), cert, 1, 1, &|s: &str| s == "sample-a");
        OpKind::KeyBundlePut(KeyBundlePut {
            target_app_id: cert.app_id(),
            bundle: sealed.unwrap().remove(0).bundle,
            first_epoch: 1,
            last_epoch: 1,
        })
    };
    switch.signer_op(part(&plain_cert)).unwrap();
    let replaced_part = switch.seq();
    switch.signer_op(part(&plain_cert)).unwrap();
    rows.push((
        "key_bundle.put",
        switch.seq(),
        "op",
        vec![plain],
        vec![claims],
    ));
    rows.push((
        "key_bundle.put replaced",
        replaced_part,
        "op",
        vec![],
        vec![plain],
    ));
    // A superseded record write, to its writer too.
    let other = RecordTarget::new(items(), b"other");
    shop.put_record(&other, &value(&["a"]), vec![])
        .await
        .unwrap();
    let superseded = switch.seq();
    shop.put_record(&other, &value(&["a", "b"]), vec![])
        .await
        .unwrap();
    rows.push((
        "record.put superseded",
        superseded,
        "op",
        vec![],
        vec![plain, shop.app_id()],
    ));
    // A compacted claim's entries: stubs to every app, the claim's own writer included.
    let compacted = [9; 32];
    shop.write_claim(attempt(compacted), vec![], ObligationDeadline::NoDeadline)
        .await
        .unwrap();
    let compacted_attempt = switch.seq();
    let condition = shop.claim_condition(&compacted).await.unwrap();
    let done = ClaimOp::done(compacted, 1, ATTEMPT, Basis::Owner, None).unwrap();
    shop.write_claim(done, vec![condition], ObligationDeadline::NoDeadline)
        .await
        .unwrap();
    rows.push((
        "claim compacted",
        compacted_attempt,
        "op",
        vec![],
        vec![claims, shop.app_id()],
    ));
    rows.push((
        "claim compacted, its last",
        switch.seq(),
        "op",
        vec![],
        vec![claims, shop.app_id()],
    ));
    // An app record: every app while it is held; a superseded one is a stub.
    p.clock.advance_ms(1000);
    let newer = AppRecord::sign(
        &claims_keys,
        AppRecordBody::new(&claims_cert, Vec::new(), p.clock.now_ms()),
    )
    .unwrap();
    let record = newer.signed().clone();
    switch
        .app_op(&claims_keys, OpKind::AppPut { record })
        .unwrap();
    rows.push(("app.put", switch.seq(), "op", vec![plain], vec![]));
    rows.push(("app.put superseded", claims_put, "op", vec![], vec![plain]));
    // A renewed certificate: every app while stored; one the app's record carries is a stub.
    let renew = |keys: &AppKeys| {
        let spec = AppSpec::new(&["sample-b"]);
        let renewed = issue_cert(bob.key(), keys, &spec, p.clock.now_ms()).unwrap();
        switch
            .signer_op(OpKind::CertPut {
                target_app_id: renewed.app_id(),
                cert: renewed.signed().clone(),
            })
            .unwrap();
        renewed
    };
    renew(&adder_keys);
    rows.push(("cert.put", switch.seq(), "op", vec![plain], vec![]));
    let renewed = renew(&renewing_keys);
    let carried = switch.seq();
    let renewing = renewing_cert.app_id();
    p.bob
        .next_doc(|body| {
            body.apps.retain(|a| a.app_id != renewing);
            body.apps.push(ListedApp {
                app_id: renewing,
                cert: renewed.hash(),
            });
            body.renewed.push(RenewedCert {
                app_id: renewing,
                cert: renewing_cert.hash(),
                until: None,
            });
        })
        .unwrap();
    p.clock.advance_ms(1000);
    let record = AppRecord::sign(
        &renewing_keys,
        AppRecordBody::new(&renewed, Vec::new(), p.clock.now_ms()),
    )
    .unwrap();
    switch
        .app_op(
            &renewing_keys,
            OpKind::AppPut {
                record: record.signed().clone(),
            },
        )
        .unwrap();
    rows.push((
        "cert.put carried by the record",
        carried,
        "op",
        vec![],
        vec![plain],
    ));
    for (what, seq, item_type, full, stub) in &rows {
        let shown = |app: &[u8; 16]| {
            switch
                .shown(*app)
                .into_iter()
                .find(|item| item["seq"] == *seq)
                .unwrap_or_else(|| panic!("{what}: no item at {seq}"))
        };
        for app in full {
            let item = shown(app);
            assert_eq!(item["type"], "chain", "{what}, in full: {item}");
            assert_eq!(item["item_type"], *item_type, "{what}: {item}");
        }
        for app in stub {
            let item = shown(app);
            assert_eq!(item["type"], "stub", "{what}, a stub: {item}");
        }
    }
}

// -------------------------------------------------------------------------------------
// The outbox across a backup and a restore

/// Alice's wallet, with a note to bob queued and refused `403 not_admitted`, bob's shop, and
/// that note as signed.
async fn wallet_with_a_queued_note(
    p: &Pair,
    protocol: &Arc<ApiProtocol>,
) -> (App, App, SignedMessage) {
    let mut wallet = p.join(&p.alice, "wallet", protocol).await;
    let shop = p.join(&p.bob, "shop", protocol).await;
    let signed = wallet.sign_message(Pair::note(&p.bob, "hello")).unwrap();
    wallet.queue_signed(signed.clone()).await.unwrap();
    let delivery = wallet
        .flush_message(signed.msg_id())
        .await
        .unwrap()
        .unwrap();
    assert!(queued_with(&delivery, "not_admitted"), "{delivery:?}");
    (wallet, shop, signed)
}

/// `backup` restored for alice's wallet onto a new store.
async fn restored_wallet(p: &Pair, protocol: &Arc<ApiProtocol>, backup: &AppBackup) -> App {
    let backup = AppBackup::from_bytes(&backup.to_bytes().unwrap()).unwrap();
    let env = p.env(&p.alice, Arc::new(MemoryStore::new()));
    App::restore(env, protocol.clone(), config(), &backup)
        .await
        .unwrap()
}

/// How many messages each [`AppEvent::MessagesHeldAtRestore`] among `events` holds.
fn held_at_restore(events: &[AppEvent]) -> Vec<u64> {
    events
        .iter()
        .filter_map(|e| match e {
            AppEvent::MessagesHeldAtRestore { held, .. } => Some(*held),
            _ => None,
        })
        .collect()
}

/// Release every message `app` holds for `protocol`, as a protocol does after a
/// restore for each its own read of the shared state still wants.
async fn release_held(app: &mut App, protocol: &str) {
    for msg_id in app.held_messages(protocol).await.unwrap() {
        app.release_message(protocol, &msg_id, crate::app::ReplyGrantOnRelease::IfOwed)
            .await
            .unwrap();
    }
}

/// A restore puts a queued message back held, tells its protocol so once, and delivers it
/// only once the protocol releases it (Switch spec 12.4).
#[tokio::test]
async fn test_backup_outbox_restore_holds_a_queued_message_until_released() {
    let p = Pair::new();
    let protocol = ApiProtocol::new(Mode::Plain);
    let (wallet, mut shop, signed) = wallet_with_a_queued_note(&p, &protocol).await;
    let backup = wallet.backup().await.unwrap();
    drop(wallet);
    shop.invite(&p.alice.identity().public()).await.unwrap();
    let mut restored = restored_wallet(&p, &protocol, &backup).await;
    let msg_id = signed.msg_id().to_owned();
    assert!(
        matches!(
            restored.delivery(&msg_id).await.unwrap(),
            Some(Delivery::Queued { .. })
        ),
        "the restore put the message back in the outbox"
    );
    assert_eq!(held_at_restore(&restored.take_events()), vec![1]);
    assert_eq!(
        restored.held_messages("sample").await.unwrap(),
        vec![msg_id.clone()]
    );
    let report = restored.flush_outbox().await.unwrap();
    assert!(report.done.is_empty(), "{report:?}");
    assert_eq!(p.bob.switch().entries_from(&p.alice.identity().public()), 0);
    release_held(&mut restored, "sample").await;
    assert!(restored.take_events().is_empty(), "a release tells nothing");
    let report = restored.flush_outbox().await.unwrap();
    assert_eq!(report.done, vec![msg_id.clone()], "{report:?}");
    // The same signed plaintext, so the same `msg_id` and hash.
    let sent = restored
        .sent_to(&p.bob.identity().public(), 0, u64::MAX)
        .await
        .unwrap();
    assert_eq!(sent.len(), 1);
    assert_eq!(sent[0].plaintext.encode(), signed.plaintext().encode());
    shop.receive(None).await.unwrap();
    let seen = protocol.seen();
    assert_eq!(seen.len(), 1);
    assert_eq!(seen[0].msg_id, msg_id);
}

#[tokio::test]
async fn test_backup_outbox_message_delivered_since_the_backup_is_a_harmless_duplicate() {
    let p = Pair::new();
    let protocol = ApiProtocol::new(Mode::Plain);
    let (mut wallet, mut shop, signed) = wallet_with_a_queued_note(&p, &protocol).await;
    let backup = wallet.backup_layered().await.unwrap();
    // The wallet delivers the note after the backup, and bob's app processes it.
    shop.invite(&p.alice.identity().public()).await.unwrap();
    let report = wallet.flush_outbox().await.unwrap();
    assert_eq!(report.done, vec![signed.msg_id().to_owned()]);
    shop.receive(None).await.unwrap();
    assert_eq!(protocol.seen().len(), 1);
    // Read, the entry is gone from bob's inbox.
    let alice = p.alice.identity().public();
    assert_eq!(p.bob.switch().entries_from(&alice), 0);
    // The restore from before the delivery puts it back held; released, it goes again:
    // bob's switch, which no longer holds the entry, takes it as new, and bob's app drops it
    // by its processed pair.
    drop(wallet);
    let mut restored = restored_wallet(&p, &protocol, &backup).await;
    release_held(&mut restored, "sample").await;
    let report = restored.flush_outbox().await.unwrap();
    assert_eq!(report.done, vec![signed.msg_id().to_owned()]);
    assert_eq!(p.bob.switch().entries_from(&alice), 1);
    shop.receive(None).await.unwrap();
    assert_eq!(protocol.seen().len(), 1, "applied once");
    assert!(
        protocol.seen().iter().all(|seen| !seen.conflict),
        "the second copy is a duplicate, not a conflict"
    );
}

/// Whether the events tell the protocol, once, that `msg_id` wasn't delivered, as a re-send
/// or not.
fn undelivered_once(events: &[AppEvent], msg_id: &str, resend: bool) -> bool {
    events
        .iter()
        .filter(|e| matches!(e, AppEvent::MessageUndelivered { msg_id: m, resend: r, .. } if m == msg_id && *r == resend))
        .count()
        == 1
}

#[tokio::test]
async fn test_backup_outbox_past_the_window_gives_the_delivery_up() {
    let p = Pair::new();
    let protocol = ApiProtocol::new(Mode::Plain);
    let (wallet, mut shop, signed) = wallet_with_a_queued_note(&p, &protocol).await;
    let backup = wallet.backup().await.unwrap();
    drop(wallet);
    shop.invite(&p.alice.identity().public()).await.unwrap();
    // A first try more than 30 days after the backup: bob's app may hold the processed pair
    // of a delivery since no longer.
    p.clock.advance_ms(SENT_RETENTION_MS + MINUTE);
    let mut restored = restored_wallet(&p, &protocol, &backup).await;
    let msg_id = signed.msg_id().to_owned();
    restored.take_events();
    let report = restored.flush_outbox().await.unwrap();
    assert_eq!(report.unknown, vec![msg_id.clone()]);
    let events = restored.take_events();
    assert_eq!(unknown(&events, &msg_id), 1);
    assert!(undelivered(&events, &msg_id).is_empty());
    assert_eq!(restored.delivery(&msg_id).await.unwrap(), None);
    restored.flush_outbox().await.unwrap();
    assert!(restored.take_events().is_empty(), "told once");
    assert_eq!(p.bob.switch().entries_from(&p.alice.identity().public()), 0);
}

/// A message withdrawn after the backup, whose give-up the restored store can't know, is
/// held, and the protocol that withdraws it again after its own read is the only one that
/// decides: it is never delivered.
#[tokio::test]
async fn test_backup_outbox_restore_never_delivers_a_message_withdrawn_since() {
    let p = Pair::new();
    let protocol = ApiProtocol::new(Mode::Plain);
    let (mut wallet, mut shop, signed) = wallet_with_a_queued_note(&p, &protocol).await;
    let msg_id = signed.msg_id().to_owned();
    let backup = wallet.backup().await.unwrap();
    assert!(wallet.withdraw_message("sample", &msg_id).await.unwrap());
    drop(wallet);
    shop.invite(&p.alice.identity().public()).await.unwrap();
    let mut restored = restored_wallet(&p, &protocol, &backup).await;
    assert_eq!(held_at_restore(&restored.take_events()), vec![1]);
    let report = restored.flush_outbox().await.unwrap();
    assert!(report.done.is_empty(), "{report:?}");
    assert!(restored.withdraw_message("sample", &msg_id).await.unwrap());
    // The device the backup came from may have delivered it: unknown, told once.
    assert_eq!(unknown(&restored.take_events(), &msg_id), 1);
    restored.flush_outbox().await.unwrap();
    assert_eq!(restored.delivery(&msg_id).await.unwrap(), None);
    assert_eq!(p.bob.switch().entries_from(&p.alice.identity().public()), 0);
}

/// A held message no protocol releases or withdraws is given up at its replay deadline, as
/// any held message is: told unknown once, never delivered. The message was never tried,
/// so the deadline is the one the restore gives it.
#[tokio::test]
async fn test_backup_outbox_restore_held_message_is_given_up_at_its_deadline() {
    let p = Pair::new();
    let protocol = ApiProtocol::new(Mode::Plain);
    let mut wallet = p.join(&p.alice, "wallet", &protocol).await;
    let mut shop = p.join(&p.bob, "shop", &protocol).await;
    let msg_id = wallet.queue(Pair::note(&p.bob, "hello")).await.unwrap();
    assert_eq!(
        wallet
            .outbox_record(&msg_id)
            .await
            .unwrap()
            .replay_until_ms(),
        None,
        "never tried"
    );
    let backup = wallet.backup().await.unwrap();
    drop(wallet);
    shop.invite(&p.alice.identity().public()).await.unwrap();
    let mut restored = restored_wallet(&p, &protocol, &backup).await;
    restored.take_events();
    p.clock.advance_ms(SENT_RETENTION_MS + MINUTE);
    let report = restored.flush_outbox().await.unwrap();
    assert_eq!(report.unknown, vec![msg_id.clone()]);
    assert_eq!(unknown(&restored.take_events(), &msg_id), 1);
    assert!(restored.held_messages("sample").await.unwrap().is_empty());
    assert_eq!(p.bob.switch().entries_from(&p.alice.identity().public()), 0);
}

/// Alice's wallet on `store` queues a note to bob, who admits her, and flushes it: the
/// wallet, the note's ID, the commits made once it is queued, and what the flush returned.
async fn queued_note_flush(
    p: &Pair,
    protocol: &Arc<ApiProtocol>,
    store: &Arc<FaultStore>,
) -> (App, String, u64, Result<crate::app::OutboxReport, AppError>) {
    let mut wallet = p
        .join_on(
            &p.alice,
            "wallet",
            protocol.clone(),
            Arc::clone(store) as Arc<dyn StateStore>,
        )
        .await;
    let mut shop = p.join(&p.bob, "shop", protocol).await;
    shop.invite(&p.alice.identity().public()).await.unwrap();
    let signed = wallet.sign_message(Pair::note(&p.bob, "hello")).unwrap();
    wallet.queue_signed(signed.clone()).await.unwrap();
    let queued = store.commits();
    let flushed = wallet.flush_outbox().await;
    (wallet, signed.msg_id().to_owned(), queued, flushed)
}

/// A crash at any commit of a delivery, once the recipient's switch holds the message, leaves
/// a store that knows an envelope of it was sent: the flag is committed with the envelope,
/// before the append. Withdrawn after the restart, the message is told unknown.
#[tokio::test]
async fn test_outbox_crash_after_the_append_keeps_the_envelope_sent() {
    let protocol = ApiProtocol::new(Mode::Plain);
    let (first, last) = {
        let p = Pair::new();
        let store = Arc::new(FaultStore::new(
            Arc::new(MemoryStore::new()),
            StoreFault::None,
        ));
        let (_, _, queued, flushed) = queued_note_flush(&p, &protocol, &store).await;
        assert!(flushed.unwrap().done.len() == 1);
        (queued + 1, store.commits())
    };
    let mut crashed_after_the_append = 0;
    for n in first..=last {
        let p = Pair::new();
        let inner = Arc::new(MemoryStore::new());
        let store = Arc::new(FaultStore::new(
            Arc::clone(&inner) as Arc<dyn StateStore>,
            StoreFault::StopBefore(n),
        ));
        let (wallet, msg_id, _, flushed) = queued_note_flush(&p, &protocol, &store).await;
        assert!(store.stopped() && flushed.is_err(), "commit {n}");
        let alice = p.alice.identity().public();
        let app_id = wallet.app_id();
        drop(wallet);
        let env = p.env(&p.alice, Arc::clone(&inner) as Arc<dyn StateStore>);
        let mut loaded = App::load(env, protocol.clone(), config(), app_id)
            .await
            .unwrap();
        let queued = matches!(
            loaded.delivery(&msg_id).await.unwrap(),
            Some(Delivery::Queued { .. })
        );
        if p.bob.switch().entries_from(&alice) == 0 || !queued {
            continue;
        }
        crashed_after_the_append += 1;
        loaded.take_events();
        assert!(loaded.withdraw_message("sample", &msg_id).await.unwrap());
        assert_eq!(unknown(&loaded.take_events(), &msg_id), 1, "commit {n}");
    }
    assert!(crashed_after_the_append > 0);
}

/// A try whose answer was lost may have been accepted: withdrawing the message then tells
/// "unknown", and here the recipient's switch does hold it.
#[tokio::test]
async fn test_withdraw_message_after_a_lost_answer_is_unknown() {
    let p = Pair::new();
    let protocol = ApiProtocol::new(Mode::Plain);
    let mut wallet = p.join(&p.alice, "wallet", &protocol).await;
    let mut shop = p.join(&p.bob, "shop", &protocol).await;
    let alice = p.alice.identity().public();
    shop.invite(&alice).await.unwrap();
    p.bob.switch().fail_next(Fault::LoseAnswer {
        path: "inbox".into(),
    });
    let (msg_id, delivery) = wallet.send(Pair::note(&p.bob, "hello")).await.unwrap();
    assert!(matches!(delivery, Delivery::Queued { .. }), "{delivery:?}");
    assert_eq!(p.bob.switch().entries_from(&alice), 1);
    wallet.take_events();
    assert!(wallet.withdraw_message("sample", &msg_id).await.unwrap());
    let events = wallet.take_events();
    assert_eq!(unknown(&events, &msg_id), 1);
    assert!(undelivered(&events, &msg_id).is_empty());
}

/// An original message whose first send's answer is lost commits a replay deadline from
/// that first possible send; once the clock passes day 30 less the clock tolerance, the
/// message is given up as unknown and is not sent a second time.
#[tokio::test]
async fn test_outbox_first_send_lost_answer_gives_up_as_unknown_past_replay_deadline() {
    let p = Pair::new();
    let protocol = ApiProtocol::new(Mode::Plain);
    let mut wallet = p.join(&p.alice, "wallet", &protocol).await;
    let mut shop = p.join(&p.bob, "shop", &protocol).await;
    let alice = p.alice.identity().public();
    shop.invite(&alice).await.unwrap();
    p.bob.switch().fail_next(Fault::LoseAnswer {
        path: "inbox".into(),
    });
    let (msg_id, delivery) = wallet.send(Pair::note(&p.bob, "hello")).await.unwrap();
    assert!(matches!(delivery, Delivery::Queued { .. }), "{delivery:?}");
    assert_eq!(p.bob.switch().entries_from(&alice), 1);
    let expected_deadline = START - CLOCK_TOLERANCE_MS + SENT_RETENTION_MS;
    assert_eq!(
        wallet
            .outbox_record(&msg_id)
            .await
            .unwrap()
            .replay_until_ms(),
        Some(expected_deadline)
    );
    shop.receive(None).await.unwrap();
    assert_eq!(protocol.seen().len(), 1);
    assert_eq!(p.bob.switch().entries_from(&alice), 0);
    // Just past day 30 less the clock tolerance from the first possible send, the message
    // is given up as unknown without another append.
    p.clock.set_ms(expected_deadline + 1);
    let from = p.router.log().len();
    wallet.take_events();
    let report = wallet.flush_outbox().await.unwrap();
    assert_eq!(report.unknown, vec![msg_id.clone()], "{report:?}");
    assert!(report.undelivered.is_empty() && report.done.is_empty());
    assert_eq!(wallet.delivery(&msg_id).await.unwrap(), None);
    let events = wallet.take_events();
    assert_eq!(unknown(&events, &msg_id), 1);
    assert!(undelivered(&events, &msg_id).is_empty());
    let appends = p
        .router
        .log()
        .into_iter()
        .skip(from)
        .filter(|line| line.starts_with(&format!("POST {BOB_ORIGIN} ")))
        .filter(|line| line.contains("/inbox"))
        .count();
    assert_eq!(appends, 0);
    assert_eq!(p.bob.switch().entries_from(&alice), 0);
    shop.receive(None).await.unwrap();
    assert_eq!(protocol.seen().len(), 1, "not applied a second time");
}

/// Retrying, reopening, or restoring from a later backup before the deadline does not move
/// the clock-anchored replay deadline committed on an original message's first send.
#[tokio::test]
async fn test_outbox_first_send_retry_reopen_and_restore_keep_replay_deadline() {
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
    shop.invite(&alice).await.unwrap();
    p.bob.switch().fail_next(Fault::LoseAnswer {
        path: "inbox".into(),
    });
    let (msg_id, delivery) = wallet.send(Pair::note(&p.bob, "hello")).await.unwrap();
    assert!(matches!(delivery, Delivery::Queued { .. }), "{delivery:?}");
    let deadline = START - CLOCK_TOLERANCE_MS + SENT_RETENTION_MS;
    assert_eq!(
        wallet
            .outbox_record(&msg_id)
            .await
            .unwrap()
            .replay_until_ms(),
        Some(deadline)
    );
    // Advancing the clock and retrying keeps the first send's deadline rather than moving it.
    p.clock.advance_ms(5 * DAY_MS);
    p.bob.switch().fail_next(Fault::Unreachable {
        path: "inbox".into(),
        after: 0,
    });
    let report = wallet.flush_outbox().await.unwrap();
    assert_eq!(report.queued, vec![msg_id.clone()], "{report:?}");
    assert_eq!(
        wallet
            .outbox_record(&msg_id)
            .await
            .unwrap()
            .replay_until_ms(),
        Some(deadline)
    );
    // Reopening the store after another clock advance and retrying still keeps the deadline.
    p.clock.advance_ms(5 * DAY_MS);
    let app_id = wallet.app_id();
    drop(wallet);
    let mut loaded = App::load(
        p.env(&p.alice, Arc::clone(&store) as Arc<dyn StateStore>),
        protocol.clone(),
        config(),
        app_id,
    )
    .await
    .unwrap();
    assert_eq!(
        loaded
            .outbox_record(&msg_id)
            .await
            .unwrap()
            .replay_until_ms(),
        Some(deadline)
    );
    p.bob.switch().fail_next(Fault::Unreachable {
        path: "inbox".into(),
        after: 0,
    });
    let report = loaded.flush_outbox().await.unwrap();
    assert_eq!(report.queued, vec![msg_id.clone()], "{report:?}");
    assert_eq!(
        loaded
            .outbox_record(&msg_id)
            .await
            .unwrap()
            .replay_until_ms(),
        Some(deadline)
    );
    // A backup taken later and restored does not extend the deadline to the backup's window.
    p.clock.advance_ms(5 * DAY_MS);
    loaded.receive(None).await.unwrap();
    let backup = loaded.backup().await.unwrap();
    drop(loaded);
    let mut restored = restored_wallet(&p, &protocol, &backup).await;
    assert_eq!(
        restored
            .outbox_record(&msg_id)
            .await
            .unwrap()
            .replay_until_ms(),
        Some(deadline)
    );
    p.clock.set_ms(deadline + 1);
    restored.take_events();
    let report = restored.flush_outbox().await.unwrap();
    assert_eq!(report.unknown, vec![msg_id.clone()], "{report:?}");
    assert_eq!(unknown(&restored.take_events(), &msg_id), 1);
}

/// If the pre-transport hold fires right after `envelope_sent` and its replay deadline are
/// committed, no transport call follows and the rollback restores the prior deadline.
#[tokio::test]
async fn test_outbox_first_send_pre_transport_hold_restores_replay_deadline() {
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
    shop.invite(&alice).await.unwrap();
    let signed = wallet.sign_message(Pair::note(&p.bob, "hello")).unwrap();
    let msg_id = wallet.queue_signed(signed).await.unwrap();
    assert_eq!(
        wallet
            .outbox_record(&msg_id)
            .await
            .unwrap()
            .replay_until_ms(),
        None
    );
    let try_at = START + 3 * DAY_MS;
    p.clock.set_ms(try_at);
    let ns = crate::store::client_namespace(&wallet.app_id());
    let store_for_check = Arc::clone(&store);
    let observed_deadline: Arc<Mutex<Option<Option<u64>>>> = Arc::new(Mutex::new(None));
    let observed_for_check = Arc::clone(&observed_deadline);
    *protocol.delivery_check.lock().unwrap() = Some(Arc::new(move |delivery| {
        let key = format!("out/{}", delivery.message().msg_id);
        let sent = store_for_check
            .get(&ns, key.as_bytes())
            .unwrap()
            .and_then(|bytes| crate::app::state::decode::<Value>(&bytes).ok())
            .is_some_and(|item| {
                let sent = item["envelope_sent"].as_bool() == Some(true);
                if sent {
                    *observed_for_check.lock().unwrap() = Some(item["replay_until_ms"].as_u64());
                }
                sent
            });
        Ok(!sent)
    }));
    let delivery = wallet.flush_message(&msg_id).await.unwrap();
    assert!(
        matches!(delivery, Some(Delivery::Queued { .. })),
        "{delivery:?}"
    );
    assert_eq!(
        *observed_deadline.lock().unwrap(),
        Some(Some(try_at - CLOCK_TOLERANCE_MS + SENT_RETENTION_MS)),
        "envelope_sent and replay_until_ms commit together before transport"
    );
    assert_eq!(p.bob.switch().entries_from(&alice), 0);
    assert_eq!(
        wallet
            .outbox_record(&msg_id)
            .await
            .unwrap()
            .replay_until_ms(),
        None,
        "pre-transport rollback restores the previous deadline"
    );
    *protocol.delivery_check.lock().unwrap() = None;
    wallet.take_events();
    assert!(wallet.withdraw_message("sample", &msg_id).await.unwrap());
    let events = wallet.take_events();
    assert_eq!(undelivered(&events, &msg_id), vec![false]);
    assert_eq!(unknown(&events, &msg_id), 0);
}

/// If a lost-answer first send is accepted as a fresh entry on a later retry, the sent copy
/// retains the first attempt's replay deadline rather than extending re-sends from the
/// retry's acceptance time.
#[tokio::test]
async fn test_outbox_first_send_lost_answer_accepted_on_retry_keeps_replay_deadline() {
    let p = Pair::new();
    let protocol = ApiProtocol::new(Mode::Plain);
    let mut wallet = p.join(&p.alice, "wallet", &protocol).await;
    let mut shop = p.join(&p.bob, "shop", &protocol).await;
    let alice = p.alice.identity().public();
    shop.invite(&alice).await.unwrap();
    p.bob.switch().fail_next(Fault::LoseAnswer {
        path: "inbox".into(),
    });
    let (msg_id, delivery) = wallet.send(Pair::note(&p.bob, "hello")).await.unwrap();
    assert!(matches!(delivery, Delivery::Queued { .. }), "{delivery:?}");
    let deadline = START - CLOCK_TOLERANCE_MS + SENT_RETENTION_MS;
    assert_eq!(
        wallet
            .outbox_record(&msg_id)
            .await
            .unwrap()
            .replay_until_ms(),
        Some(deadline)
    );
    // Bob processes the first delivery so his switch drops the inbox entry. Clear the
    // scripted switch's content-retry map to match the service dropping a passed entry's
    // stored answer (Switch spec 11).
    shop.receive(None).await.unwrap();
    assert_eq!(protocol.seen().len(), 1);
    assert_eq!(p.bob.switch().entries_from(&alice), 0);
    p.bob.switch().lock().appended.clear();
    // A retry on day 10 is accepted as a new entry with a day-10 `accepted_at`.
    let retry_at = START + 10 * DAY_MS;
    p.clock.set_ms(retry_at);
    let report = wallet.flush_outbox().await.unwrap();
    assert_eq!(report.done, vec![msg_id.clone()], "{report:?}");
    assert_eq!(p.bob.switch().entries_from(&alice), 1);
    assert_eq!(
        wallet.delivery(&msg_id).await.unwrap(),
        Some(Delivery::Accepted {
            accepted_at_ms: retry_at,
        })
    );
    assert_eq!(wallet.sent_replay_until_ms(&msg_id).await, Some(deadline));
    // Past the original deadline (day 31, only 21 days after the retry acceptance), a
    // re-send is given up rather than delivered past Bob's duplicate window.
    p.clock.set_ms(deadline + DAY_MS);
    wallet.take_events();
    wallet.resend(&msg_id).await.unwrap();
    assert_eq!(undelivered(&wallet.take_events(), &msg_id), vec![true]);
    assert_eq!(p.bob.switch().entries_from(&alice), 1, "not re-sent");
}

/// A clean first acceptance clears the pre-send replay deadline from both `out/` and
/// `sent/`, so a re-send just inside 30 days from acceptance goes even past the pre-send
/// clock-tolerance margin.
#[tokio::test]
async fn test_send_clean_first_acceptance_clears_replay_deadline() {
    let p = Pair::new();
    let protocol = ApiProtocol::new(Mode::Plain);
    let mut wallet = p.join(&p.alice, "wallet", &protocol).await;
    let mut shop = p.join(&p.bob, "shop", &protocol).await;
    let alice = p.alice.identity().public();
    let bob = p.bob.identity().public();
    shop.invite(&alice).await.unwrap();
    wallet.keep_peer(&bob).await.unwrap();
    // With an owed record job that fails once so `out/` stays after acceptance.
    let signed_with_job = wallet.sign_message(Pair::note(&p.bob, "with job")).unwrap();
    let target = RecordTarget::new(items(), &signed_with_job.hash());
    let signed_with_job = signed_with_job.with_record(RecordJob {
        target,
        tag: b"sent".to_vec(),
    });
    let job_msg_id = wallet.queue_signed(signed_with_job).await.unwrap();
    p.alice.switch().fail_next(Fault::Unreachable {
        path: "ops".into(),
        after: 0,
    });
    let delivery = wallet.flush_message(&job_msg_id).await.unwrap();
    assert_eq!(
        delivery,
        Some(Delivery::Accepted {
            accepted_at_ms: START,
        })
    );
    assert!(p.alice.switch().lock().faults.is_empty());
    assert_eq!(
        wallet
            .outbox_record(&job_msg_id)
            .await
            .unwrap()
            .replay_until_ms(),
        None,
        "clean first acceptance clears replay_until_ms on out/"
    );
    assert_eq!(
        wallet.sent_replay_until_ms(&job_msg_id).await,
        None,
        "clean first acceptance clears replay_until_ms on sent/"
    );
    // Plain message without a record job.
    let (msg_id, delivery) = wallet.send(Pair::note(&p.bob, "plain")).await.unwrap();
    assert_eq!(
        delivery,
        Delivery::Accepted {
            accepted_at_ms: START,
        }
    );
    assert!(wallet.outbox_record(&msg_id).await.is_none());
    assert_eq!(wallet.sent_replay_until_ms(&msg_id).await, None);
    assert_eq!(p.bob.switch().entries_from(&alice), 2);
    // Past the pre-send margin (`START + 30d - 5m`) yet inside 30 days from acceptance,
    // re-sends from both `sent/` and `out/` still go.
    p.clock.set_ms(START + SENT_RETENTION_MS - MINUTE);
    wallet.take_events();
    let resent = wallet.resend(&msg_id).await.unwrap();
    assert!(matches!(resent, Delivery::Accepted { .. }), "{resent:?}");
    assert!(undelivered(&wallet.take_events(), &msg_id).is_empty());
    assert_eq!(p.bob.switch().entries_from(&alice), 3);
    wallet.take_events();
    let resent_job = wallet.resend(&job_msg_id).await.unwrap();
    assert!(
        matches!(resent_job, Delivery::Accepted { .. }),
        "{resent_job:?}"
    );
    assert!(undelivered(&wallet.take_events(), &job_msg_id).is_empty());
    assert_eq!(p.bob.switch().entries_from(&alice), 4);
}

/// A brand-new first send does not enforce its newly committed replay deadline within the
/// same call, so it succeeds right after a reload without fetching fresh service time from
/// its own switch, including across a verified `401 stale_timestamp` retry.
#[tokio::test]
async fn test_send_first_attempt_succeeds_without_fresh_service_time() {
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
    wallet.keep_peer(&bob).await.unwrap();
    let app_id = wallet.app_id();
    drop(wallet);
    let mut loaded = App::load(
        p.env(&p.alice, Arc::clone(&store) as Arc<dyn StateStore>),
        protocol.clone(),
        config(),
        app_id,
    )
    .await
    .unwrap();
    assert!(loaded.time_fresh_at.is_none());
    p.alice.switch().fail_next(Fault::Unreachable {
        path: String::new(),
        after: 0,
    });
    let (first_id, delivery) = loaded.send(Pair::note(&p.bob, "first")).await.unwrap();
    assert!(
        matches!(delivery, Delivery::Accepted { .. }),
        "{delivery:?}"
    );
    assert!(loaded.time_fresh_at.is_none());
    assert_eq!(p.bob.switch().entries_from(&alice), 1);
    assert_eq!(
        p.alice.switch().lock().faults.len(),
        1,
        "own switch was not contacted"
    );
    assert_eq!(loaded.sent_replay_until_ms(&first_id).await, None);
    // A verified `401 stale_timestamp` retry inside the same first send also runs without
    // fresh service time and still clears the pre-send deadline on acceptance.
    p.bob.switch().fail_next(Fault::Error {
        path: "/inbox".into(),
        code: ErrorCode::StaleTimestamp,
        current: json!({"server_time": pubky_switch_core::time::rfc3339(START)}),
    });
    let (second_id, delivery) = loaded.send(Pair::note(&p.bob, "second")).await.unwrap();
    assert!(
        matches!(delivery, Delivery::Accepted { .. }),
        "{delivery:?}"
    );
    assert!(p.bob.switch().lock().faults.is_empty());
    assert!(loaded.time_fresh_at.is_none());
    assert_eq!(p.bob.switch().entries_from(&alice), 2);
    assert_eq!(p.alice.switch().lock().faults.len(), 1);
    assert_eq!(loaded.sent_replay_until_ms(&second_id).await, None);
}

/// A message held before its first attempt carries no replay deadline while untried and
/// gets the full window anchored at its first possible send, not its creation time.
#[tokio::test]
async fn test_send_held_before_first_attempt_gets_full_replay_window_from_first_send() {
    let p = Pair::new();
    let protocol = ApiProtocol::new(Mode::Plain);
    let mut wallet = p.join(&p.alice, "wallet", &protocol).await;
    let mut shop = p.join(&p.bob, "shop", &protocol).await;
    let alice = p.alice.identity().public();
    shop.invite(&alice).await.unwrap();
    let signed = wallet.sign_message(Pair::note(&p.bob, "held")).unwrap();
    let msg_id = wallet.queue_signed(signed).await.unwrap();
    assert!(wallet.hold_message("sample", &msg_id).await.unwrap());
    assert_eq!(
        wallet
            .outbox_record(&msg_id)
            .await
            .unwrap()
            .replay_until_ms(),
        None
    );
    // Held for 20 days: flushing does not attach a deadline.
    let first_send_at = START + 20 * DAY_MS;
    p.clock.set_ms(first_send_at);
    let report = wallet.flush_outbox().await.unwrap();
    assert_eq!(report.queued, vec![msg_id.clone()], "{report:?}");
    assert_eq!(
        wallet
            .outbox_record(&msg_id)
            .await
            .unwrap()
            .replay_until_ms(),
        None
    );
    // Released on day 20 and first attempted with a lost answer: the deadline anchors at
    // day 20, not day 0 (`created_at`).
    wallet
        .release_message("sample", &msg_id, crate::app::ReplyGrantOnRelease::IfOwed)
        .await
        .unwrap();
    p.bob.switch().fail_next(Fault::LoseAnswer {
        path: "inbox".into(),
    });
    let report = wallet.flush_outbox().await.unwrap();
    assert_eq!(report.queued, vec![msg_id.clone()], "{report:?}");
    let deadline = first_send_at - CLOCK_TOLERANCE_MS + SENT_RETENTION_MS;
    assert_eq!(
        wallet
            .outbox_record(&msg_id)
            .await
            .unwrap()
            .replay_until_ms(),
        Some(deadline)
    );
    // On day 31 (past `created_at + 30d`, inside `first_send_at + 30d - tolerance`), retries
    // still attempt delivery rather than giving up.
    p.clock.set_ms(START + 31 * DAY_MS);
    p.bob.switch().fail_next(Fault::Unreachable {
        path: "inbox".into(),
        after: 0,
    });
    let report = wallet.flush_outbox().await.unwrap();
    assert_eq!(report.queued, vec![msg_id.clone()], "{report:?}");
    assert!(p.bob.switch().lock().faults.is_empty());
    assert_eq!(
        wallet
            .outbox_record(&msg_id)
            .await
            .unwrap()
            .replay_until_ms(),
        Some(deadline)
    );
    // Past day 50 less clock tolerance, the delivery is given up as unknown.
    p.clock.set_ms(deadline + 1);
    wallet.take_events();
    let report = wallet.flush_outbox().await.unwrap();
    assert_eq!(report.unknown, vec![msg_id.clone()], "{report:?}");
    assert_eq!(unknown(&wallet.take_events(), &msg_id), 1);
    assert_eq!(wallet.delivery(&msg_id).await.unwrap(), None);
}

/// An unsent item put back by a restore keeps its existing replay deadline when first
/// attempted later rather than replacing it with a newer deadline from the device clock.
#[tokio::test]
async fn test_outbox_first_send_preserves_existing_restored_replay_deadline() {
    let p = Pair::new();
    let protocol = ApiProtocol::new(Mode::Plain);
    let (wallet, mut shop, signed) = wallet_with_a_queued_note(&p, &protocol).await;
    let msg_id = signed.msg_id().to_owned();
    let backup = wallet.backup().await.unwrap();
    drop(wallet);
    shop.invite(&p.alice.identity().public()).await.unwrap();
    p.clock.advance_ms(15 * DAY_MS);
    let mut restored = restored_wallet(&p, &protocol, &backup).await;
    let restored_deadline = START - CLOCK_TOLERANCE_MS + SENT_RETENTION_MS;
    assert_eq!(
        restored
            .outbox_record(&msg_id)
            .await
            .unwrap()
            .replay_until_ms(),
        Some(restored_deadline)
    );
    p.bob.switch().fail_next(Fault::LoseAnswer {
        path: "inbox".into(),
    });
    let report = restored.flush_outbox().await.unwrap();
    assert_eq!(report.queued, vec![msg_id.clone()], "{report:?}");
    assert_eq!(
        restored
            .outbox_record(&msg_id)
            .await
            .unwrap()
            .replay_until_ms(),
        Some(restored_deadline),
        "first attempt preserves the restored deadline"
    );
    p.clock.set_ms(restored_deadline + 1);
    restored.take_events();
    let report = restored.flush_outbox().await.unwrap();
    assert_eq!(report.unknown, vec![msg_id.clone()], "{report:?}");
    assert_eq!(unknown(&restored.take_events(), &msg_id), 1);
}

/// Outbox validation accepts an attempted item with a replay deadline and an accepted item
/// whose pre-send deadline was cleared, and refuses an item with `envelope_sent` set, no
/// `replay_until_ms`, and a delivery still owed.
#[tokio::test]
async fn test_outbox_validation_refuses_attempted_item_without_replay_deadline() {
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
    wallet.keep_peer(&bob).await.unwrap();
    // Valid attempted item: `envelope_sent` is true and `replay_until_ms` is set.
    p.bob.switch().fail_next(Fault::LoseAnswer {
        path: "inbox".into(),
    });
    let (msg_id, delivery) = wallet.send(Pair::note(&p.bob, "attempted")).await.unwrap();
    assert!(matches!(delivery, Delivery::Queued { .. }), "{delivery:?}");
    // Valid accepted item with an owed record job and cleared pre-send deadline:
    // `envelope_sent` is true, `replay_until_ms` is None, and no delivery is owed.
    let signed = wallet.sign_message(Pair::note(&p.bob, "with job")).unwrap();
    let target = RecordTarget::new(items(), &signed.hash());
    let signed = signed.with_record(RecordJob {
        target,
        tag: b"sent".to_vec(),
    });
    let job_msg_id = wallet.queue_signed(signed).await.unwrap();
    p.alice.switch().fail_next(Fault::Unreachable {
        path: "ops".into(),
        after: 0,
    });
    assert_eq!(
        wallet.flush_message(&job_msg_id).await.unwrap(),
        Some(Delivery::Accepted {
            accepted_at_ms: START,
        })
    );
    assert!(p.alice.switch().lock().faults.is_empty());
    let app_id = wallet.app_id();
    let backup = wallet.backup().await.unwrap();
    drop(wallet);
    // Both valid items pass outbox validation on load and on restore.
    let mut loaded = App::load(
        p.env(&p.alice, Arc::clone(&store) as Arc<dyn StateStore>),
        protocol.clone(),
        config(),
        app_id,
    )
    .await
    .unwrap();
    assert!(
        loaded
            .outbox_record(&msg_id)
            .await
            .unwrap()
            .replay_until_ms()
            .is_some()
    );
    assert_eq!(
        loaded
            .outbox_record(&job_msg_id)
            .await
            .unwrap()
            .replay_until_ms(),
        None
    );
    let _ = restored_wallet(&p, &protocol, &backup).await;
    // Strip `replay_until_ms` from the attempted, unaccepted outbox item in the store.
    let key = format!("out/{msg_id}");
    let mut stored: Value = loaded.reader().get(&key).await.unwrap().unwrap();
    assert_eq!(stored["envelope_sent"], json!(true));
    assert!(
        stored
            .as_object_mut()
            .unwrap()
            .remove("replay_until_ms")
            .is_some()
    );
    let mut tx = loaded.tx().unwrap();
    tx.put(&key, &stored).unwrap();
    loaded.commit(tx).await.unwrap();
    assert!(matches!(
        loaded.flush_outbox().await,
        Err(AppError::Store(crate::error::StoreError::Corrupt))
    ));
    assert!(matches!(
        loaded.delivery(&msg_id).await,
        Err(AppError::Store(crate::error::StoreError::Corrupt))
    ));
    assert!(matches!(
        loaded.backup().await,
        Err(AppError::Store(crate::error::StoreError::Corrupt))
    ));
    drop(loaded);
    let reopened = App::load(
        p.env(&p.alice, Arc::clone(&store) as Arc<dyn StateStore>),
        protocol.clone(),
        config(),
        app_id,
    )
    .await;
    assert!(matches!(
        reopened,
        Err(AppError::Store(crate::error::StoreError::Corrupt))
    ));
    // A backup carrying that same invalid item is refused by restore.
    let mut bad: Value = serde_json::from_slice(&backup.to_bytes().unwrap()).unwrap();
    let entry = bad["outbox"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .find(|item| item["msg_id"] == msg_id.as_str())
        .unwrap();
    assert!(
        entry
            .as_object_mut()
            .unwrap()
            .remove("replay_until_ms")
            .is_some()
    );
    let bad_backup = AppBackup::from_bytes(&serde_json::to_vec(&bad).unwrap()).unwrap();
    let restored = App::restore(
        p.env(&p.alice, Arc::new(MemoryStore::new())),
        protocol,
        config(),
        &bad_backup,
    )
    .await
    .err();
    assert!(
        matches!(restored, Some(AppError::InvalidData(_))),
        "{restored:?}"
    );
}

/// Every retry of an attempted message checks its replay deadline against a fresh service
/// time verified from the app's own switch; while that switch is unreachable, the retry
/// waits with `last_error` recorded even when the recipient's switch is reachable.
#[tokio::test]
async fn test_outbox_first_send_retry_waits_when_own_switch_is_unreachable() {
    let p = Pair::new();
    let protocol = ApiProtocol::new(Mode::Plain);
    let mut wallet = p.join(&p.alice, "wallet", &protocol).await;
    let mut shop = p.join(&p.bob, "shop", &protocol).await;
    let alice = p.alice.identity().public();
    shop.invite(&alice).await.unwrap();
    // First send commits `envelope_sent` and its replay deadline, then fails at bob's inbox.
    p.bob.switch().fail_next(Fault::Unreachable {
        path: "inbox".into(),
        after: 0,
    });
    let (msg_id, delivery) = wallet
        .send(Pair::note(&p.bob, "wait for time"))
        .await
        .unwrap();
    assert!(matches!(delivery, Delivery::Queued { .. }), "{delivery:?}");
    assert!(p.bob.switch().lock().faults.is_empty());
    assert_eq!(p.bob.switch().entries_from(&alice), 0);
    let deadline = START - CLOCK_TOLERANCE_MS + SENT_RETENTION_MS;
    assert_eq!(
        wallet
            .outbox_record(&msg_id)
            .await
            .unwrap()
            .replay_until_ms(),
        Some(deadline)
    );
    // Past the cached service-time freshness window yet inside the replay deadline, alice's
    // own switch cannot supply a fresh service time while bob's switch is up.
    p.clock.set_ms(START + DAY_MS);
    p.alice.switch().fail_next(Fault::Unreachable {
        path: "feed".into(),
        after: 0,
    });
    let appends_before = inbox_appends(&p);
    let report = wallet.flush_outbox().await.unwrap();
    assert!(p.alice.switch().lock().faults.is_empty());
    assert_eq!(report.queued, vec![msg_id.clone()], "{report:?}");
    assert!(report.done.is_empty() && report.unknown.is_empty());
    assert_eq!(
        inbox_appends(&p),
        appends_before,
        "retry must not deliver without fresh verified service time"
    );
    assert_eq!(p.bob.switch().entries_from(&alice), 0);
    assert!(matches!(
        wallet.delivery(&msg_id).await.unwrap(),
        Some(Delivery::Queued {
            last_error: Some(_),
            ..
        })
    ));
    // Once alice's own switch supplies fresh service time, the retry delivers and keeps the
    // first send's deadline on `sent/`.
    let report = wallet.flush_outbox().await.unwrap();
    assert_eq!(report.done, vec![msg_id.clone()], "{report:?}");
    assert_eq!(p.bob.switch().entries_from(&alice), 1);
    assert_eq!(wallet.sent_replay_until_ms(&msg_id).await, Some(deadline));
}

/// A `403 not_admitted` answer on the append itself comes after the first possible send,
/// so the replay deadline fires before the 30-day 403 bound and reports the delivery as
/// unknown without another append.
#[tokio::test]
async fn test_outbox_first_send_403_on_append_gives_up_at_replay_deadline() {
    let p = Pair::new();
    let protocol = ApiProtocol::new(Mode::Plain);
    let mut wallet = p.join(&p.alice, "wallet", &protocol).await;
    let mut shop = p.join(&p.bob, "shop", &protocol).await;
    let alice = p.alice.identity().public();
    shop.invite(&alice).await.unwrap();
    // Directory read succeeds, the envelope commits with its replay deadline, and the
    // append itself receives `403 not_admitted`.
    p.bob.switch().fail_next(Fault::Error {
        path: "/inbox".into(),
        code: ErrorCode::NotAdmitted,
        current: json!(null),
    });
    let (msg_id, delivery) = wallet
        .send(Pair::note(&p.bob, "refused append"))
        .await
        .unwrap();
    assert!(
        matches!(
            delivery,
            Delivery::Queued {
                undeliverable_since_ms: Some(START),
                undeliverable_reason: Some(crate::app::UndeliverableReason::NotAdmitted),
                ..
            }
        ),
        "{delivery:?}"
    );
    assert!(p.bob.switch().lock().faults.is_empty());
    let deadline = START - CLOCK_TOLERANCE_MS + SENT_RETENTION_MS;
    assert_eq!(
        wallet
            .outbox_record(&msg_id)
            .await
            .unwrap()
            .replay_until_ms(),
        Some(deadline)
    );
    // Spaced retries before the replay deadline stay queued and keep counting 403 answers.
    for _ in 2..crate::app::UNDELIVERABLE_TRIES {
        p.clock.advance_ms(crate::app::UNDELIVERABLE_TRY_SPACING_MS);
        p.bob.switch().fail_next(Fault::Error {
            path: "/inbox".into(),
            code: ErrorCode::NotAdmitted,
            current: json!(null),
        });
        let report = wallet.flush_outbox().await.unwrap();
        assert_eq!(report.queued, vec![msg_id.clone()], "{report:?}");
        assert!(p.bob.switch().lock().faults.is_empty());
    }
    // Past the replay deadline (still before the 30-day 403 bound), the message is given
    // up as delivery unknown without sending another append.
    p.clock.set_ms(deadline + 1);
    p.bob.switch().fail_next(Fault::Error {
        path: "/inbox".into(),
        code: ErrorCode::NotAdmitted,
        current: json!(null),
    });
    wallet.take_events();
    let report = wallet.flush_outbox().await.unwrap();
    assert_eq!(report.unknown, vec![msg_id.clone()], "{report:?}");
    assert!(report.undelivered.is_empty() && report.done.is_empty());
    assert_eq!(wallet.delivery(&msg_id).await.unwrap(), None);
    let events = wallet.take_events();
    assert_eq!(unknown(&events, &msg_id), 1);
    assert!(undelivered(&events, &msg_id).is_empty());
    assert_eq!(
        p.bob.switch().lock().faults.len(),
        1,
        "replay deadline ends delivery before another append"
    );
    assert_eq!(p.bob.switch().entries_from(&alice), 0);
}

/// A verified `409 stale_key` reseal and acceptance inside the try that first sent the
/// message still clears the pre-send replay deadline from both `out/` and `sent/`, so
/// re-sends run for 30 days from that acceptance.
#[tokio::test]
async fn test_send_first_try_stale_key_reseal_clears_replay_deadline() {
    let p = Pair::new();
    let protocol = ApiProtocol::new(Mode::Plain);
    let mut wallet = p.join(&p.alice, "wallet", &protocol).await;
    let mut shop = p.join(&p.bob, "shop", &protocol).await;
    let alice = p.alice.identity().public();
    let bob = p.bob.identity().public();
    shop.invite(&alice).await.unwrap();
    wallet.keep_peer(&bob).await.unwrap();
    // Cache bob's directory before a second recipient app joins.
    wallet.send(Pair::note(&p.bob, "warmup")).await.unwrap();
    let mut kiosk = p.join(&p.bob, "kiosk", &protocol).await;
    // Queue a message with an owed record job that fails once so `out/` stays after
    // acceptance alongside `sent/`.
    let signed = wallet.sign_message(Pair::note(&p.bob, "resealed")).unwrap();
    let target = RecordTarget::new(items(), &signed.hash());
    let signed = signed.with_record(RecordJob {
        target,
        tag: b"sent".to_vec(),
    });
    let msg_id = wallet.queue_signed(signed).await.unwrap();
    p.alice.switch().fail_next(Fault::Unreachable {
        path: "ops".into(),
        after: 0,
    });
    let appends_before = inbox_appends(&p);
    let delivery = wallet.flush_message(&msg_id).await.unwrap();
    assert_eq!(
        delivery,
        Some(Delivery::Accepted {
            accepted_at_ms: START,
        })
    );
    assert_eq!(
        inbox_appends(&p) - appends_before,
        2,
        "409 stale_key resealed and retried within the first try"
    );
    assert!(p.alice.switch().lock().faults.is_empty());
    assert_eq!(
        wallet
            .outbox_record(&msg_id)
            .await
            .unwrap()
            .replay_until_ms(),
        None
    );
    assert_eq!(wallet.sent_replay_until_ms(&msg_id).await, None);
    kiosk.receive(None).await.unwrap();
    assert!(protocol.seen().iter().any(|s| s.msg_id == msg_id));
    // Past the pre-send margin (`START + 30d - 5m`) yet inside 30 days from acceptance,
    // a re-send still goes.
    p.clock.set_ms(START + SENT_RETENTION_MS - MINUTE);
    wallet.take_events();
    let resent = wallet.resend(&msg_id).await.unwrap();
    assert!(matches!(resent, Delivery::Accepted { .. }), "{resent:?}");
    assert!(undelivered(&wallet.take_events(), &msg_id).is_empty());
    assert_eq!(inbox_appends(&p) - appends_before, 3);
}

/// A restored app knows of no acceptance of a message the backup carried, and the device
/// the backup came from may have delivered it: giving it up tells "unknown", even for one
/// no try of this store ever sent. A message no request can have carried, withdrawn before
/// any try, is still told undelivered.
#[tokio::test]
async fn test_backup_outbox_give_up_without_a_known_acceptance_is_unknown() {
    let p = Pair::new();
    let protocol = ApiProtocol::new(Mode::Plain);
    let mut wallet = p.join(&p.alice, "wallet", &protocol).await;
    let _shop = p.join(&p.bob, "shop", &protocol).await;
    let mut ids = Vec::new();
    for text in ["carried", "gone"] {
        let signed = wallet.sign_message(Pair::note(&p.bob, text)).unwrap();
        wallet.queue_signed(signed.clone()).await.unwrap();
        ids.push(signed.msg_id().to_owned());
    }
    let [carried, withdrawn]: [String; 2] = ids.try_into().unwrap();
    wallet.take_events();
    assert!(wallet.withdraw_message("sample", &withdrawn).await.unwrap());
    let events = wallet.take_events();
    assert_eq!(undelivered(&events, &withdrawn), vec![false]);
    assert_eq!(unknown(&events, &withdrawn), 0);
    // A backup that carries the other message, never tried.
    let backup = wallet.backup().await.unwrap();
    drop(wallet);
    let mut restored = restored_wallet(&p, &protocol, &backup).await;
    restored.take_events();
    // Past the replay deadline, the carried message is given up untried.
    p.clock.advance_ms(SENT_RETENTION_MS + MINUTE);
    let report = restored.flush_outbox().await.unwrap();
    assert_eq!(report.unknown, vec![carried.clone()]);
    assert!(report.undelivered.is_empty(), "{report:?}");
    let events = restored.take_events();
    assert_eq!(unknown(&events, &carried), 1);
    assert!(undelivered(&events, &carried).is_empty());
}

/// The deadline is checked at every try, not at the restore: a message put back 29 days
/// after the backup, and first tried two days later, isn't sent.
#[tokio::test]
async fn test_backup_outbox_restored_in_time_and_tried_past_the_window_isnt_sent() {
    let p = Pair::new();
    let protocol = ApiProtocol::new(Mode::Plain);
    let (mut wallet, mut shop, signed) = wallet_with_a_queued_note(&p, &protocol).await;
    let backup = wallet.backup().await.unwrap();
    shop.invite(&p.alice.identity().public()).await.unwrap();
    assert_eq!(wallet.flush_outbox().await.unwrap().done.len(), 1);
    shop.receive(None).await.unwrap();
    drop(wallet);
    p.clock.advance_ms(29 * DAY_MS);
    let mut restored = restored_wallet(&p, &protocol, &backup).await;
    assert!(matches!(
        restored.delivery(signed.msg_id()).await.unwrap(),
        Some(Delivery::Queued { .. })
    ));
    p.clock.advance_ms(2 * DAY_MS);
    let report = restored.flush_outbox().await.unwrap();
    assert_eq!(report.unknown, vec![signed.msg_id().to_owned()]);
    shop.receive(None).await.unwrap();
    assert_eq!(protocol.seen().len(), 1, "applied once");
}

/// A device clock behind doesn't hold the window open: the deadline is judged at the later
/// of the device clock and the service time the flush verifies.
#[tokio::test]
async fn test_backup_outbox_window_holds_on_a_device_clock_behind() {
    let p = Pair::new();
    let protocol = ApiProtocol::new(Mode::Plain);
    let (wallet, mut shop, signed) = wallet_with_a_queued_note(&p, &protocol).await;
    let backup = wallet.backup().await.unwrap();
    drop(wallet);
    shop.invite(&p.alice.identity().public()).await.unwrap();
    p.clock.advance_ms(32 * DAY_MS);
    let backup = AppBackup::from_bytes(&backup.to_bytes().unwrap()).unwrap();
    let mut env = p.env(&p.alice, Arc::new(MemoryStore::new()));
    env.clock = Arc::new(crate::clock::TestClock::new(p.clock.now_ms() - 3 * DAY_MS))
        as Arc<dyn crate::clock::Clock>;
    let mut restored = App::restore(env, protocol.clone(), config(), &backup)
        .await
        .unwrap();
    release_held(&mut restored, "sample").await;
    let report = restored.flush_outbox().await.unwrap();
    assert_eq!(report.unknown, vec![signed.msg_id().to_owned()]);
    assert_eq!(p.bob.switch().entries_from(&p.alice.identity().public()), 0);
}

/// A restored note tried at `offset` from its replay deadline: whether it went.
async fn tried_at_the_deadline(offset: i64) -> bool {
    let p = Pair::new();
    let protocol = ApiProtocol::new(Mode::Plain);
    let (wallet, mut shop, signed) = wallet_with_a_queued_note(&p, &protocol).await;
    let backup = wallet.backup().await.unwrap();
    drop(wallet);
    shop.invite(&p.alice.identity().public()).await.unwrap();
    let mut restored = restored_wallet(&p, &protocol, &backup).await;
    release_held(&mut restored, "sample").await;
    let deadline = restored
        .outbox_record(signed.msg_id())
        .await
        .unwrap()
        .replay_until_ms()
        .unwrap();
    p.clock.set_ms(deadline.saturating_add_signed(offset));
    let report = restored.flush_outbox().await.unwrap();
    report.done == vec![signed.msg_id().to_owned()]
}

#[tokio::test]
async fn test_backup_outbox_window_ends_at_its_deadline() {
    assert!(tried_at_the_deadline(0).await, "at the deadline, it goes");
    assert!(!tried_at_the_deadline(1).await, "past it, it doesn't");
}

#[tokio::test]
async fn test_backup_replay_deadline_is_checked_after_recipient_preparation() {
    for elapsed in [1, 2] {
        let p = Pair::new();
        let protocol = ApiProtocol::new(Mode::Plain);
        let (wallet, mut shop, signed) = wallet_with_a_queued_note(&p, &protocol).await;
        let backup = wallet.backup().await.unwrap();
        drop(wallet);
        shop.invite(&p.alice.identity().public()).await.unwrap();
        let mut restored = restored_wallet(&p, &protocol, &backup).await;
        release_held(&mut restored, "sample").await;
        let deadline = restored
            .outbox_record(signed.msg_id())
            .await
            .unwrap()
            .replay_until_ms()
            .unwrap();
        p.clock.set_ms(deadline - 1);
        let bob = p.bob.identity().public();
        let reads = p.bob.homeserver().identity_reads(&bob);
        p.bob.homeserver().slow_reads(bob, p.clock.clone(), elapsed);
        let from = p.router.log().len();
        let report = restored.flush_outbox().await.unwrap();
        assert_eq!(p.bob.homeserver().identity_reads(&bob), reads + 1);
        assert_eq!(p.clock.now_ms(), deadline - 1 + elapsed);
        let appends = p
            .router
            .log()
            .into_iter()
            .skip(from)
            .filter(|line| line.starts_with(&format!("POST {BOB_ORIGIN} ")))
            .filter(|line| line.contains("/inbox"))
            .count();
        if elapsed == 1 {
            assert_eq!(appends, 1, "equality still permits the append");
            assert_eq!(report.done, vec![signed.msg_id().to_owned()]);
        } else {
            assert_eq!(appends, 0, "preparation used the remaining replay window");
            assert_eq!(report.unknown, vec![signed.msg_id().to_owned()]);
        }
    }
}

#[tokio::test]
async fn test_backup_replay_deadline_is_checked_before_timestamp_retry() {
    use crate::transport::{BoxFuture, Request, Response, TransportError};

    struct Answering {
        inner: Arc<dyn Transport>,
        clock: Arc<crate::clock::TestClock>,
        elapsed: Mutex<Option<u64>>,
    }
    impl Transport for Answering {
        fn send(&self, request: Request) -> BoxFuture<'_, Result<Response, TransportError>> {
            Box::pin(async move {
                let append = request.method == "POST" && request.path_and_query.contains("/inbox");
                let answer = self.inner.send(request).await;
                if append && let Some(elapsed) = self.elapsed.lock().unwrap().take() {
                    self.clock.advance_ms(elapsed);
                }
                answer
            })
        }
    }

    for elapsed in [1, 2] {
        let p = Pair::new();
        let protocol = ApiProtocol::new(Mode::Plain);
        let (wallet, mut shop, signed) = wallet_with_a_queued_note(&p, &protocol).await;
        let backup = wallet.backup().await.unwrap();
        drop(wallet);
        shop.invite(&p.alice.identity().public()).await.unwrap();
        let mut restored = restored_wallet(&p, &protocol, &backup).await;
        release_held(&mut restored, "sample").await;
        let deadline = restored
            .outbox_record(signed.msg_id())
            .await
            .unwrap()
            .replay_until_ms()
            .unwrap();
        p.clock.set_ms(deadline - 1);
        p.bob.switch().fail_next(Fault::Error {
            path: "/inbox".into(),
            code: ErrorCode::StaleTimestamp,
            current: json!({"server_time": pubky_switch_core::time::rfc3339(deadline - 1)}),
        });
        p.router.add(
            BOB_ORIGIN,
            Arc::new(Answering {
                inner: p.bob.switch().transport(),
                clock: p.clock.clone(),
                elapsed: Mutex::new(Some(elapsed)),
            }),
        );
        let from = p.router.log().len();
        let report = restored.flush_outbox().await.unwrap();
        assert!(p.bob.switch().lock().faults.is_empty());
        assert_eq!(p.clock.now_ms(), deadline - 1 + elapsed);
        let appends = p
            .router
            .log()
            .into_iter()
            .skip(from)
            .filter(|line| line.starts_with(&format!("POST {BOB_ORIGIN} ")))
            .filter(|line| line.contains("/inbox"))
            .count();
        if elapsed == 1 {
            assert_eq!(appends, 2, "the timestamp retry still fits at equality");
            assert_eq!(report.done, vec![signed.msg_id().to_owned()]);
        } else {
            assert_eq!(
                appends, 1,
                "the refused first attempt used the replay window"
            );
            assert_eq!(report.unknown, vec![signed.msg_id().to_owned()]);
            assert_eq!(p.bob.switch().entries_from(&p.alice.identity().public()), 0);
        }
    }
}

#[tokio::test]
async fn test_backup_replay_deadline_advances_during_preparation_on_a_lagging_device() {
    struct Behind(Arc<crate::clock::TestClock>);
    impl crate::clock::Clock for Behind {
        fn now_ms(&self) -> u64 {
            self.0.now_ms() - 2 * MINUTE
        }
    }

    for elapsed in [1, 2] {
        let p = Pair::new();
        let protocol = ApiProtocol::new(Mode::Plain);
        let (wallet, mut shop, signed) = wallet_with_a_queued_note(&p, &protocol).await;
        let backup = wallet.backup().await.unwrap();
        drop(wallet);
        shop.invite(&p.alice.identity().public()).await.unwrap();
        let mut env = p.env(&p.alice, Arc::new(MemoryStore::new()));
        env.clock = Arc::new(Behind(p.clock.clone()));
        let mut restored = App::restore(env, protocol, config(), &backup)
            .await
            .unwrap();
        release_held(&mut restored, "sample").await;
        let deadline = restored
            .outbox_record(signed.msg_id())
            .await
            .unwrap()
            .replay_until_ms()
            .unwrap();
        p.clock.set_ms(deadline - 1);
        let bob = p.bob.identity().public();
        let reads = p.bob.homeserver().identity_reads(&bob);
        p.bob.homeserver().slow_reads(bob, p.clock.clone(), elapsed);
        let from = p.router.log().len();
        let report = restored.flush_outbox().await.unwrap();
        assert_eq!(p.bob.homeserver().identity_reads(&bob), reads + 1);
        assert_eq!(p.clock.now_ms(), deadline - 1 + elapsed);
        assert_eq!(restored.now(), deadline - 1 + elapsed - 2 * MINUTE);
        assert_eq!(
            restored.state.service_time.unwrap().highest_ms,
            deadline - 1
        );
        let appends = p
            .router
            .log()
            .into_iter()
            .skip(from)
            .filter(|line| line.starts_with(&format!("POST {BOB_ORIGIN} ")))
            .filter(|line| line.contains("/inbox"))
            .count();
        if elapsed == 1 {
            assert_eq!(appends, 1, "the advancing service sample permits equality");
            assert_eq!(report.done, vec![signed.msg_id().to_owned()]);
        } else {
            assert_eq!(appends, 0, "the verified sample advances with preparation");
            assert_eq!(report.unknown, vec![signed.msg_id().to_owned()]);
        }
    }
}

#[tokio::test]
async fn test_backup_replay_waits_after_a_clock_jump_and_reopens_with_a_fresh_sample() {
    use crate::app::HomeserverReader;
    use crate::transport::{BoxFuture, TransportError};

    struct Backwards {
        inner: Arc<dyn HomeserverReader>,
        device: Arc<crate::clock::TestClock>,
        target: Mutex<Option<[u8; 32]>>,
    }
    impl HomeserverReader for Backwards {
        fn get(
            &self,
            identity: [u8; 32],
            path: String,
        ) -> BoxFuture<'_, Result<Option<Vec<u8>>, TransportError>> {
            Box::pin(async move {
                let answer = self.inner.get(identity, path).await;
                let mut target = self.target.lock().unwrap();
                if *target == Some(identity) {
                    self.device.set_ms(self.device.now_ms() - 2);
                    *target = None;
                }
                answer
            })
        }
    }

    let p = Pair::new();
    let protocol = ApiProtocol::new(Mode::Plain);
    let (wallet, mut shop, signed) = wallet_with_a_queued_note(&p, &protocol).await;
    let backup = wallet.backup().await.unwrap();
    drop(wallet);
    shop.invite(&p.alice.identity().public()).await.unwrap();
    let device = Arc::new(crate::clock::TestClock::new(p.clock.now_ms() - 2 * MINUTE));
    let mut env = p.env(&p.alice, Arc::new(MemoryStore::new()));
    env.clock = device.clone();
    let homeserver = Arc::new(Backwards {
        inner: env.homeserver.clone(),
        device: device.clone(),
        target: Mutex::new(None),
    });
    env.homeserver = homeserver.clone();
    let mut restored = App::restore(env.clone(), protocol.clone(), config(), &backup)
        .await
        .unwrap();
    release_held(&mut restored, "sample").await;
    let deadline = restored
        .outbox_record(signed.msg_id())
        .await
        .unwrap()
        .replay_until_ms()
        .unwrap();
    p.clock.set_ms(deadline - 10);
    device.set_ms(deadline - 10 - 2 * MINUTE);
    *homeserver.target.lock().unwrap() = Some(p.bob.identity().public());
    let report = restored.flush_outbox().await.unwrap();
    assert!(homeserver.target.lock().unwrap().is_none());
    assert_eq!(device.now_ms(), deadline - 12 - 2 * MINUTE);
    assert!(report.done.is_empty() && report.unknown.is_empty());
    assert_eq!(p.bob.switch().entries_from(&p.alice.identity().public()), 0);
    assert!(matches!(
        restored.delivery(signed.msg_id()).await.unwrap(),
        Some(Delivery::Queued { .. })
    ));
    let id = restored.app_id();
    drop(restored);
    let mut loaded = App::load(env, protocol, config(), id).await.unwrap();
    assert!(loaded.time_fresh_at.is_none());
    let report = loaded.flush_outbox().await.unwrap();
    assert_eq!(report.done, vec![signed.msg_id().to_owned()]);
    assert_eq!(p.bob.switch().entries_from(&p.alice.identity().public()), 1);
}

/// The deadline is the backup's time less the clock tolerance, plus 30 days, and a later
/// backup and restore carry it, never moved on.
#[tokio::test]
async fn test_backup_outbox_deadline_survives_a_later_backup() {
    let p = Pair::new();
    let protocol = ApiProtocol::new(Mode::Plain);
    let (wallet, mut shop, signed) = wallet_with_a_queued_note(&p, &protocol).await;
    let backup = wallet.backup().await.unwrap();
    drop(wallet);
    let first = restored_wallet(&p, &protocol, &backup).await;
    let deadline = first
        .outbox_record(signed.msg_id())
        .await
        .unwrap()
        .replay_until_ms()
        .unwrap();
    assert!(deadline <= START + SENT_RETENTION_MS - CLOCK_TOLERANCE_MS);
    p.clock.advance_ms(20 * DAY_MS);
    let later = first.backup().await.unwrap();
    drop(first);
    let mut second = restored_wallet(&p, &protocol, &later).await;
    assert_eq!(
        second
            .outbox_record(signed.msg_id())
            .await
            .unwrap()
            .replay_until_ms(),
        Some(deadline)
    );
    shop.invite(&p.alice.identity().public()).await.unwrap();
    p.clock.advance_ms(11 * DAY_MS);
    let report = second.flush_outbox().await.unwrap();
    assert_eq!(report.unknown, vec![signed.msg_id().to_owned()]);
}

/// A message a restore put back, accepted only after the restore: a re-send of it goes by
/// the deadline the restore gave it, not 30 days from that later acceptance.
#[tokio::test]
async fn test_backup_outbox_resend_after_its_deadline_is_given_up() {
    let p = Pair::new();
    let protocol = ApiProtocol::new(Mode::Plain);
    let (wallet, mut shop, signed) = wallet_with_a_queued_note(&p, &protocol).await;
    let alice = p.alice.identity().public();
    let backup = wallet.backup().await.unwrap();
    drop(wallet);
    shop.invite(&alice).await.unwrap();
    let mut restored = restored_wallet(&p, &protocol, &backup).await;
    release_held(&mut restored, "sample").await;
    let deadline = restored
        .outbox_record(signed.msg_id())
        .await
        .unwrap()
        .replay_until_ms()
        .unwrap();
    p.clock.set_ms(deadline - 5 * DAY_MS);
    let report = restored.flush_outbox().await.unwrap();
    assert_eq!(report.done, vec![signed.msg_id().to_owned()]);
    assert_eq!(p.bob.switch().entries_from(&alice), 1);
    p.clock.set_ms(deadline + DAY_MS);
    restored.take_events();
    restored.resend(signed.msg_id()).await.unwrap();
    assert_eq!(
        undelivered(&restored.take_events(), signed.msg_id()),
        vec![true]
    );
    assert_eq!(
        p.bob.switch().entries_from(&alice),
        1,
        "not delivered again"
    );
}

/// A re-send queued from `sent/` and given up past the window is told as a re-send.
#[tokio::test]
async fn test_backup_outbox_resend_given_up_says_resend() {
    let p = Pair::new();
    let protocol = ApiProtocol::new(Mode::Plain);
    let mut wallet = p.join(&p.alice, "wallet", &protocol).await;
    let mut shop = p.join(&p.bob, "shop", &protocol).await;
    shop.invite(&p.alice.identity().public()).await.unwrap();
    let (msg_id, delivery) = wallet.send(Pair::note(&p.bob, "hello")).await.unwrap();
    assert!(
        matches!(delivery, Delivery::Accepted { .. }),
        "{delivery:?}"
    );
    p.bob.switch().fail_next(Fault::Unreachable {
        path: "inbox".into(),
        after: 0,
    });
    let delivery = wallet.resend(&msg_id).await.unwrap();
    assert!(matches!(delivery, Delivery::Queued { .. }), "{delivery:?}");
    let backup = wallet.backup().await.unwrap();
    drop(wallet);
    p.clock.advance_ms(SENT_RETENTION_MS + MINUTE);
    let mut restored = restored_wallet(&p, &protocol, &backup).await;
    restored.take_events();
    restored.flush_outbox().await.unwrap();
    assert!(undelivered_once(&restored.take_events(), &msg_id, true));
}

/// A message refused for good is carried as it stands: the restored app reports it failed.
/// The refusal answers only the try it ends, which was sent: an earlier copy may have been
/// accepted, so the protocol is told the delivery is unknown, and a backup taken before it
/// acknowledged that carries it, for the restore to tell again.
#[tokio::test]
async fn test_backup_outbox_carries_failed_messages() {
    let p = Pair::new();
    let protocol = ApiProtocol::new(Mode::Plain);
    let mut wallet = p.join(&p.alice, "wallet", &protocol).await;
    let mut shop = p.join(&p.bob, "shop", &protocol).await;
    shop.invite(&p.alice.identity().public()).await.unwrap();
    p.bob.switch().fail_next(Fault::Error {
        path: "/inbox".into(),
        code: ErrorCode::BadRequest,
        current: Value::Null,
    });
    let (msg_id, delivery) = wallet.send(Pair::note(&p.bob, "hello")).await.unwrap();
    assert!(matches!(delivery, Delivery::Failed { .. }), "{delivery:?}");
    let events = wallet.take_events();
    assert_eq!(unknown(&events, &msg_id), 1);
    assert!(undelivered(&events, &msg_id).is_empty());
    let backup = wallet.backup().await.unwrap();
    drop(wallet);
    let mut restored = restored_wallet(&p, &protocol, &backup).await;
    assert!(matches!(
        restored.delivery(&msg_id).await.unwrap(),
        Some(Delivery::Failed { .. })
    ));
    assert_eq!(unknown(&restored.take_events(), &msg_id), 1);
}

/// A restore in place keeps the give-ups the store told: the backup's older copy of a
/// message withdrawn since is neither put back nor told again.
#[tokio::test]
async fn test_backup_outbox_restore_in_place_keeps_a_give_up_told_since() {
    let p = Pair::new();
    let protocol = ApiProtocol::new(Mode::Plain);
    let (mut wallet, _shop, store) = wallet_on_a_fault_store(&p, &protocol).await;
    let signed = wallet.sign_message(Pair::note(&p.bob, "gone")).unwrap();
    wallet.queue_signed(signed.clone()).await.unwrap();
    let msg_id = signed.msg_id().to_owned();
    let backup = wallet.backup().await.unwrap();
    assert!(wallet.withdraw_message("sample", &msg_id).await.unwrap());
    drop(wallet);
    let env = p.env(&p.alice, Arc::clone(&store) as Arc<dyn StateStore>);
    let mut restored = App::restore(env, protocol.clone(), config(), &backup)
        .await
        .unwrap();
    assert_eq!(restored.delivery(&msg_id).await.unwrap(), None);
    let pending = crate::app::tests::pending_events(&mut restored)
        .await
        .unwrap();
    assert_eq!(undelivered(&pending, &msg_id), vec![false]);
    assert_eq!(unknown(&pending, &msg_id), 0);
}

/// A restore in place over a store that gave up the re-send of an accepted message puts
/// the message back for its owed record job, its delivery still given up.
#[tokio::test]
async fn test_backup_outbox_restore_in_place_keeps_the_record_job_of_a_given_up_resend() {
    let p = Pair::new();
    let protocol = ApiProtocol::new(Mode::Plain);
    let (mut wallet, _shop, store) = wallet_on_a_fault_store(&p, &protocol).await;
    let signed = wallet.sign_message(Pair::note(&p.bob, "hello")).unwrap();
    let target = RecordTarget::new(items(), &signed.hash());
    let signed = signed.with_record(RecordJob {
        target,
        tag: b"sent".to_vec(),
    });
    let msg_id = wallet.queue_signed(signed).await.unwrap();
    // Accepted, its record job failing for now: the switch's batches can't be sent.
    p.alice.switch().fail_next(Fault::Unreachable {
        path: "ops".into(),
        after: 1,
    });
    for _ in 0..4 {
        p.alice.switch().fail_next(Fault::Unreachable {
            path: "ops".into(),
            after: 0,
        });
    }
    wallet.flush_outbox().await.unwrap();
    // A re-send that can't reach bob, withdrawn: only the re-send is given up.
    p.bob.switch().fail_next(Fault::Unreachable {
        path: "inbox".into(),
        after: 0,
    });
    wallet.resend(&msg_id).await.unwrap();
    assert!(wallet.withdraw_message("sample", &msg_id).await.unwrap());
    let backup = wallet.backup().await.unwrap();
    drop(wallet);
    let env = p.env(&p.alice, Arc::clone(&store) as Arc<dyn StateStore>);
    let mut restored = App::restore(env, protocol.clone(), config(), &backup)
        .await
        .unwrap();
    let kept = restored
        .outbox_record(&msg_id)
        .await
        .expect("its record job");
    assert!(!kept.delivery_owed());
    assert!(matches!(
        restored.delivery(&msg_id).await.unwrap(),
        Some(Delivery::Accepted { .. })
    ));
    let pending = crate::app::tests::pending_events(&mut restored)
        .await
        .unwrap();
    assert_eq!(undelivered(&pending, &msg_id), vec![true]);
}

/// A restore in place over a store that told a refusal for good as unknown keeps the
/// refused record: the restored app still reports it failed, told once.
#[tokio::test]
async fn test_backup_outbox_restore_in_place_keeps_a_refused_record_told_unknown() {
    let p = Pair::new();
    let protocol = ApiProtocol::new(Mode::Plain);
    let (mut wallet, _shop, store) = wallet_on_a_fault_store(&p, &protocol).await;
    p.bob.switch().fail_next(Fault::Error {
        path: "/inbox".into(),
        code: ErrorCode::BadRequest,
        current: Value::Null,
    });
    let (msg_id, delivery) = wallet.send(Pair::note(&p.bob, "hello")).await.unwrap();
    assert!(matches!(delivery, Delivery::Failed { .. }), "{delivery:?}");
    let backup = wallet.backup().await.unwrap();
    drop(wallet);
    let env = p.env(&p.alice, Arc::clone(&store) as Arc<dyn StateStore>);
    let mut restored = App::restore(env, protocol.clone(), config(), &backup)
        .await
        .unwrap();
    assert!(matches!(
        restored.delivery(&msg_id).await.unwrap(),
        Some(Delivery::Failed { .. })
    ));
    let pending = crate::app::tests::pending_events(&mut restored)
        .await
        .unwrap();
    assert_eq!(unknown(&pending, &msg_id), 1);
}

/// An outbox over the byte budget is carried oldest first; the rest are told to the
/// protocol as unknown, since the device the backup came from may deliver them, and the
/// restore fits one commit.
#[tokio::test]
async fn test_backup_outbox_over_its_budget_carries_the_oldest() {
    let p = Pair::new();
    let protocol = ApiProtocol::new(Mode::Plain);
    let mut wallet = p.join(&p.alice, "wallet", &protocol).await;
    let text = "x".repeat(40_000);
    let mut queued = Vec::new();
    for _ in 0..260 {
        let signed = wallet.sign_message(Pair::note(&p.bob, &text)).unwrap();
        queued.push(wallet.queue_signed(signed).await.unwrap());
        p.clock.advance_ms(1);
    }
    let backup = wallet.backup().await.unwrap();
    drop(wallet);
    let mut restored = restored_wallet(&p, &protocol, &backup).await;
    let first = queued.first().unwrap();
    let last = queued.last().unwrap();
    assert!(restored.delivery(first).await.unwrap().is_some());
    assert_eq!(restored.delivery(last).await.unwrap(), None);
    let events = restored.take_events();
    assert_eq!(unknown(&events, last), 1, "{} events", events.len());
    let mut carried = 0;
    for msg_id in &queued {
        if restored.delivery(msg_id).await.unwrap().is_some() {
            carried += 1;
        } else {
            assert_eq!(unknown(&events, msg_id), 1);
            assert!(undelivered(&events, msg_id).is_empty());
        }
    }
    assert!(carried > 0 && carried < queued.len(), "{carried}");
    // Each give-up told leaves its mark, so a later restore doesn't tell or undo it.
    let marks = restored.reader().scan_raw("outgone/").await.unwrap();
    assert_eq!(marks.len(), queued.len() - carried);
    // Every message it carries is held, its protocol told once, however many.
    assert_eq!(held_at_restore(&events), vec![carried as u64]);
    assert_eq!(
        restored.held_messages("sample").await.unwrap().len(),
        carried
    );
}

/// Alice's wallet on `store`, `count` notes of 40,000 bytes queued in it to bob, who
/// doesn't admit her: the wallet, the store, a backup taken before the first, and the
/// notes' IDs, oldest first.
async fn wallet_with_queued_notes(
    p: &Pair,
    protocol: &Arc<ApiProtocol>,
    count: usize,
) -> (App, Arc<MemoryStore>, AppBackup, Vec<String>) {
    let store = Arc::new(MemoryStore::new());
    let mut wallet = p
        .join_on(
            &p.alice,
            "wallet",
            protocol.clone(),
            Arc::clone(&store) as Arc<dyn StateStore>,
        )
        .await;
    let backup = wallet.backup().await.unwrap();
    let text = "x".repeat(40_000);
    let mut queued = Vec::new();
    for _ in 0..count {
        let signed = wallet.sign_message(Pair::note(&p.bob, &text)).unwrap();
        queued.push(wallet.queue_signed(signed).await.unwrap());
        p.clock.advance_ms(1);
    }
    (wallet, store, backup, queued)
}

/// A restore in place from a backup taken before a full outbox was queued, more than a
/// backup carries, keeps every message of it, each held, its protocol told once.
#[tokio::test]
async fn test_backup_outbox_restore_in_place_holds_a_full_outbox() {
    let p = Pair::new();
    let protocol = ApiProtocol::new(Mode::Plain);
    let (wallet, store, backup, queued) = wallet_with_queued_notes(&p, &protocol, 260).await;
    assert!(
        !wallet.backup().await.unwrap().outbox_left_out.is_empty(),
        "more than a backup carries"
    );
    drop(wallet);
    let env = p.env(&p.alice, Arc::clone(&store) as Arc<dyn StateStore>);
    let mut restored = App::restore(env, protocol.clone(), config(), &backup)
        .await
        .unwrap();
    let events = restored.take_events();
    assert_eq!(held_at_restore(&events), vec![queued.len() as u64]);
    let mut held = restored.held_messages("sample").await.unwrap();
    held.sort();
    let mut expected = queued.clone();
    expected.sort();
    assert_eq!(held, expected);
    assert!(queued.iter().all(|msg_id| unknown(&events, msg_id) == 0));
}

/// A restore in place over an outbox larger than one commit takes keeps every message of
/// it, held: the store's records stay where they are, and the restore writes only a hold
/// for each, so it isn't refused for how much the store queues.
#[tokio::test]
async fn test_backup_outbox_restore_in_place_holds_an_outbox_larger_than_one_commit() {
    let p = Pair::new();
    let protocol = ApiProtocol::new(Mode::Plain);
    let (wallet, store, backup, queued) = wallet_with_queued_notes(&p, &protocol, 700).await;
    drop(wallet);
    let env = p.env(&p.alice, Arc::clone(&store) as Arc<dyn StateStore>);
    let mut restored = App::restore(env, protocol.clone(), config(), &backup)
        .await
        .unwrap();
    let events = restored.take_events();
    assert_eq!(held_at_restore(&events), vec![queued.len() as u64]);
    assert_eq!(
        restored.held_messages("sample").await.unwrap().len(),
        queued.len()
    );
    assert!(
        queued
            .iter()
            .all(|msg_id| undelivered(&events, msg_id).is_empty() && unknown(&events, msg_id) == 0)
    );
}

/// The deadline's base is the service time the backup's app had verified, not its device
/// clock: a device clock ahead at the backup doesn't move the window on.
#[tokio::test]
async fn test_backup_outbox_deadline_starts_at_the_verified_service_time() {
    let p = Pair::new();
    let protocol = ApiProtocol::new(Mode::Plain);
    let _shop = p.join(&p.bob, "shop", &protocol).await;
    // The wallet's device clock runs four minutes ahead of its switch.
    let ahead = Arc::new(crate::clock::TestClock::new(START + 4 * MINUTE));
    let keys = p.alice.identity().app_keys("wallet");
    let request = p
        .alice
        .approve(
            &keys,
            &AppSpec::new(&["sample-a"]).with_permissions(&Permission::ALL),
        )
        .unwrap();
    let mut env = p.env(&p.alice, Arc::new(MemoryStore::new()));
    env.clock = Arc::clone(&ahead) as Arc<dyn crate::clock::Clock>;
    let mut wallet = App::join(env, protocol.clone(), config(), request)
        .await
        .unwrap();
    wallet.receive(None).await.unwrap();
    let signed = wallet.sign_message(Pair::note(&p.bob, "hello")).unwrap();
    wallet.queue_signed(signed.clone()).await.unwrap();
    let backup = wallet.backup().await.unwrap();
    drop(wallet);
    let restored = restored_wallet(&p, &protocol, &backup).await;
    let deadline = restored
        .outbox_record(signed.msg_id())
        .await
        .unwrap()
        .replay_until_ms()
        .unwrap();
    assert_eq!(deadline, START + SENT_RETENTION_MS - CLOCK_TOLERANCE_MS);
}

#[tokio::test]
async fn test_backup_layered_clock_existing_deadline_and_no_fresh_time() {
    let p = Pair::new();
    let protocol = ApiProtocol::new(Mode::Plain);
    let (mut wallet, mut shop, existing) = wallet_with_a_queued_note(&p, &protocol).await;
    let alice = p.alice.identity().public();
    let initial = wallet.backup().await.unwrap();
    // Original device delivers `existing` at START and bob processes it once.
    shop.invite(&alice).await.unwrap();
    assert_eq!(
        wallet.flush_outbox().await.unwrap().done,
        vec![existing.msg_id().to_owned()]
    );
    shop.receive(None).await.unwrap();
    assert_eq!(protocol.seen().len(), 1);
    drop(wallet);

    // Restore `initial` onto a running wallet with its own clock so `existing` carries an
    // existing earlier replay deadline `D_old`.
    let earlier_deadline = START + SENT_RETENTION_MS - CLOCK_TOLERANCE_MS;
    let running_clock = Arc::new(crate::clock::TestClock::new(START + 60 * MINUTE));
    p.clock.set_ms(START + 60 * MINUTE);
    let mut running_env = p.env(&p.alice, Arc::new(MemoryStore::new()));
    running_env.clock = Arc::clone(&running_clock) as Arc<dyn crate::clock::Clock>;
    let initial = AppBackup::from_bytes(&initial.to_bytes().unwrap()).unwrap();
    let mut running = App::restore(running_env, protocol.clone(), config(), &initial)
        .await
        .unwrap();
    release_held(&mut running, "sample").await;
    assert_eq!(
        running
            .outbox_record(existing.msg_id())
            .await
            .unwrap()
            .replay_until_ms(),
        Some(earlier_deadline)
    );
    // Persist an older snapshot service time `stored_time` and queue a fresh message.
    let stored_time = START + 60 * MINUTE;
    running.receive(None).await.unwrap();
    let fresh = running.sign_message(Pair::note(&p.bob, "fresh")).unwrap();
    running.queue_signed(fresh.clone()).await.unwrap();
    assert_eq!(
        running
            .reader()
            .get::<crate::app::state::ServiceTime>(crate::app::state::key::SERVICE_TIME)
            .await
            .unwrap()
            .map(|time| time.highest_ms),
        Some(stored_time)
    );

    // Advance the service to a newer verified time `live_time` (device clock 4 min ahead),
    // observed only via a read-only call so `service_time` stays dirty against the store.
    let live_time = START + 5 * DAY_MS;
    p.clock.set_ms(live_time);
    running_clock.set_ms(live_time + 4 * MINUTE);
    running.check_for_move().await.unwrap();
    assert_eq!(running.highest_service_time(), Some(live_time));
    assert!(running.service_time_dirty);
    assert_eq!(
        running
            .reader()
            .get::<crate::app::state::ServiceTime>(crate::app::state::key::SERVICE_TIME)
            .await
            .unwrap()
            .map(|time| time.highest_ms),
        Some(stored_time),
        "saved snapshot still holds the older service time"
    );

    let layered = running.backup_layered().await.unwrap();
    let layered = AppBackup::from_bytes(&layered.to_bytes().unwrap()).unwrap();
    drop(running);

    // Real time moves past `earlier_deadline` and bob's processed-pair retention expires.
    p.clock.set_ms(START + 32 * DAY_MS);
    shop.receive(None).await.unwrap();

    // Restore onto a device whose clock is behind `earlier_deadline` and whose own switch
    // is unreachable, so the restored wallet has no fresh trusted time.
    let mut behind_env = p.env(&p.alice, Arc::new(MemoryStore::new()));
    behind_env.clock =
        Arc::new(crate::clock::TestClock::new(START + 29 * DAY_MS)) as Arc<dyn crate::clock::Clock>;
    let mut restored = App::restore(behind_env, protocol.clone(), config(), &layered)
        .await
        .unwrap();
    release_held(&mut restored, "sample").await;
    assert_eq!(restored.highest_service_time(), None);
    assert_eq!(
        restored
            .outbox_record(existing.msg_id())
            .await
            .unwrap()
            .replay_until_ms(),
        Some(earlier_deadline),
        "existing earlier deadline survives a layered backup taken at a newer live service time"
    );
    assert_eq!(
        restored
            .outbox_record(fresh.msg_id())
            .await
            .unwrap()
            .replay_until_ms(),
        Some(live_time + SENT_RETENTION_MS - CLOCK_TOLERANCE_MS),
        "fresh item anchors to the live verified service time, not stale snapshot or skewed clock"
    );

    // Own switch unreachable: the restored wallet cannot fetch fresh trusted time.
    for _ in 0..2 {
        p.alice.switch().fail_next(Fault::Unreachable {
            path: String::new(),
            after: 0,
        });
    }
    let report = restored.flush_outbox().await.unwrap();
    assert!(
        p.alice.switch().lock().faults.is_empty(),
        "each replay-bounded delivery attempted one fresh_service_time read"
    );
    shop.receive(None).await.unwrap();
    assert!(
        report.done.is_empty() && report.unknown.is_empty(),
        "replay-bounded deliveries must wait without fresh trusted time: {report:?}"
    );
    assert!(
        report.queued.contains(&existing.msg_id().to_owned())
            && report.queued.contains(&fresh.msg_id().to_owned()),
        "both items remain queued while own service time is unavailable: {report:?}"
    );
    assert!(
        matches!(
            restored.delivery(existing.msg_id()).await.unwrap(),
            Some(Delivery::Queued {
                last_error: Some(_),
                ..
            })
        ),
        "unavailable service time records last_error on the queued delivery"
    );
    assert_eq!(
        protocol.seen().len(),
        1,
        "bob must not apply the already-processed message a second time"
    );

    // Once the own switch answers at START + 32d, `existing` is past `earlier_deadline`
    // (given up as unknown) while `fresh` is still inside its live-time window
    // (`live_time + 30d - 5m`) and delivers once.
    p.alice.switch().lock().faults.clear();
    let report = restored.flush_outbox().await.unwrap();
    assert_eq!(
        report.unknown,
        vec![existing.msg_id().to_owned()],
        "{report:?}"
    );
    assert_eq!(report.done, vec![fresh.msg_id().to_owned()], "{report:?}");
    shop.receive(None).await.unwrap();
    let seen: Vec<String> = protocol.seen().into_iter().map(|m| m.msg_id).collect();
    assert_eq!(
        seen,
        vec![existing.msg_id().to_owned(), fresh.msg_id().to_owned()],
        "existing was never re-applied and fresh delivered once inside its live-time window"
    );

    // The preceding flush advanced the own switch's committed stamp to START + 32d. On a
    // headless signed refusal from the own feed at that stamp, its verified service-time
    // lower bound still gives up `existing` past `earlier_deadline`, while `fresh` stays
    // queued rather than delivering without a fresh stamped time.
    let mut refused_env = p.env(&p.alice, Arc::new(MemoryStore::new()));
    refused_env.clock =
        Arc::new(crate::clock::TestClock::new(START + 29 * DAY_MS)) as Arc<dyn crate::clock::Clock>;
    let mut refused = App::restore(refused_env, protocol.clone(), config(), &layered)
        .await
        .unwrap();
    release_held(&mut refused, "sample").await;
    for _ in 0..2 {
        p.alice.switch().fail_next(Fault::Error {
            path: "feed".into(),
            code: ErrorCode::BadSignature,
            current: Value::Null,
        });
    }
    let report = refused.flush_outbox().await.unwrap();
    assert!(p.alice.switch().lock().faults.is_empty());
    assert_eq!(
        report.unknown,
        vec![existing.msg_id().to_owned()],
        "{report:?}"
    );
    assert_eq!(report.queued, vec![fresh.msg_id().to_owned()], "{report:?}");
    assert!(report.done.is_empty(), "{report:?}");
}

#[tokio::test]
async fn test_backup_clock_unreachable_time_still_drops_expired_record_job() {
    let p = Pair::new();
    let protocol = ApiProtocol::new(Mode::Plain);
    let mut wallet = p.join(&p.alice, "wallet", &protocol).await;
    let mut shop = p.join(&p.bob, "shop", &protocol).await;
    let alice = p.alice.identity().public();
    shop.invite(&alice).await.unwrap();

    // Send a message with a post-acceptance record job; bob's inbox accepts at START while
    // alice's own `/ops` write for the record job fails, leaving the record job pending.
    let signed = wallet.sign_message(Pair::note(&p.bob, "record")).unwrap();
    let target = RecordTarget::new(items(), &signed.hash());
    let signed = signed.with_record(RecordJob {
        target,
        tag: b"sent".to_vec(),
    });
    let msg_id = wallet.queue_signed(signed).await.unwrap();
    // Skip the reply grant `/ops` write (`after: 1`) and fail the record job `/ops`.
    p.alice.switch().fail_next(Fault::Unreachable {
        path: "ops".into(),
        after: 1,
    });
    wallet.flush_outbox().await.unwrap();
    assert!(matches!(
        wallet.delivery(&msg_id).await.unwrap(),
        Some(Delivery::Accepted { .. })
    ));
    assert_eq!(p.bob.switch().entries_from(&alice), 1);

    // Queue a re-send (`delivery_owed() == true`, `replay_until_ms = Some(START + 30d)`) while
    // both bob's inbox and alice's `/ops` stay unreachable so the record job remains pending.
    p.bob.switch().fail_next(Fault::Unreachable {
        path: "inbox".into(),
        after: 0,
    });
    p.alice.switch().fail_next(Fault::Unreachable {
        path: "ops".into(),
        after: 0,
    });
    let delivery = wallet.resend(&msg_id).await.unwrap();
    assert!(matches!(delivery, Delivery::Queued { .. }), "{delivery:?}");
    assert!(p.alice.switch().lock().faults.is_empty());

    // At the exact 30-day retention boundary (`kept_window_now() == deadline`), alice's own
    // switch is unreachable: `flush_outbox`'s kept-batch stamp and `try_item`'s replay-window
    // check both fail on `feed`, so the re-send waits (no delivery without fresh time), while
    // the accepted message's expired record job must still be dropped locally.
    p.clock.set_ms(START + SENT_RETENTION_MS);
    for _ in 0..2 {
        p.alice.switch().fail_next(Fault::Unreachable {
            path: "feed".into(),
            after: 0,
        });
    }
    wallet.take_events();
    let report = wallet.flush_outbox().await.unwrap();
    assert!(p.alice.switch().lock().faults.is_empty());
    assert_eq!(report.queued, vec![msg_id.clone()], "{report:?}");
    assert!(report.done.is_empty(), "{report:?}");
    assert_eq!(
        p.bob.switch().entries_from(&alice),
        1,
        "re-send must not deliver without fresh verified service time"
    );
    let events = wallet.take_events();
    assert!(
        events.iter().any(|event| matches!(
            event,
            AppEvent::RecordJobDropped { msg_id: id, .. } if id == &msg_id
        )),
        "accepted message's expired record job must still drop: {events:?}"
    );
    assert!(
        matches!(
            wallet.delivery(&msg_id).await.unwrap(),
            Some(Delivery::Queued {
                last_error: Some(_),
                ..
            })
        ),
        "re-send remains queued with last_error recorded"
    );
}

#[tokio::test]
async fn test_backup_clock_waiting_resend_completes_an_accepted_record_job() {
    let p = Pair::new();
    let protocol = ApiProtocol::new(Mode::Plain);
    let mut wallet = p.join(&p.alice, "wallet", &protocol).await;
    let mut shop = p.join(&p.bob, "shop", &protocol).await;
    let alice = p.alice.identity().public();
    shop.invite(&alice).await.unwrap();
    let signed = wallet.sign_message(Pair::note(&p.bob, "record")).unwrap();
    let target = RecordTarget::new(items(), &signed.hash());
    let key = wallet.record_key(&target).unwrap();
    let signed = signed.with_record(RecordJob {
        target,
        tag: b"sent".to_vec(),
    });
    let msg_id = wallet.queue_signed(signed).await.unwrap();
    // The message is accepted, but its record write remains kept after failing to connect.
    p.alice.switch().fail_next(Fault::Unreachable {
        path: "ops".into(),
        after: 1,
    });
    wallet.flush_outbox().await.unwrap();
    assert!(p.alice.switch().lock().faults.is_empty());
    assert!(matches!(
        wallet.delivery(&msg_id).await.unwrap(),
        Some(Delivery::Accepted { .. })
    ));
    assert!(wallet.shared_record(&key).await.unwrap().is_none());
    assert!(wallet.kept_ahead().await.unwrap().is_some());

    p.clock.advance_ms(DAY_MS);
    p.alice.switch().fail_next(Fault::Unreachable {
        path: "feed".into(),
        after: 0,
    });
    wallet.take_events();
    let from = p.router.log().len();
    let delivery = wallet.resend(&msg_id).await.unwrap();
    assert!(p.alice.switch().lock().faults.is_empty());
    assert!(
        matches!(
            delivery,
            Delivery::Queued {
                last_error: Some(_),
                ..
            }
        ),
        "{delivery:?}"
    );
    assert!(!p.router.log().into_iter().skip(from).any(|line|
        line.starts_with(&format!("POST {BOB_ORIGIN} ")) && line.contains("/inbox")));
    assert_eq!(p.bob.switch().entries_from(&alice), 1);
    let record = wallet.shared_record(&key).await.unwrap().unwrap();
    assert_eq!(ids(record.content.value()), vec![msg_id]);
    assert!(wallet.kept_ahead().await.unwrap().is_none());
    assert!(!wallet.take_events().iter().any(|event| matches!(
        event,
        AppEvent::RecordJobDropped { .. } | AppEvent::RecordJobStopped { .. }
    )));
}

#[tokio::test]
async fn test_backup_clock_unreachable_time_still_drops_firm_undeliverable() {
    let p = Pair::new();
    let protocol = ApiProtocol::new(Mode::Plain);
    let (mut wallet, _shop, signed) = wallet_with_a_queued_note(&p, &protocol).await;
    let msg_id = signed.msg_id().to_owned();

    // Advance to day 20, verify service time, take a layered backup, and restore so the
    // replay deadline (`START + 50d - 5m`) lies beyond the 45-day firm undeliverable bound.
    p.clock.set_ms(START + 20 * DAY_MS);
    wallet.receive(None).await.unwrap();
    let backup = wallet.backup_layered().await.unwrap();
    drop(wallet);
    let mut restored = restored_wallet(&p, &protocol, &backup).await;
    release_held(&mut restored, "sample").await;
    assert_eq!(
        restored
            .outbox_record(&msg_id)
            .await
            .unwrap()
            .replay_until_ms(),
        Some(START + 50 * DAY_MS - CLOCK_TOLERANCE_MS)
    );

    // At day 45 (`UNDELIVERABLE_MAX_MS`, still inside the 50-day replay window) with own
    // switch unreachable, the firm undeliverable bound must still drop plaintext and emit
    // DeliveryUnknown.
    p.clock.set_ms(START + crate::app::UNDELIVERABLE_MAX_MS);
    p.alice.switch().fail_next(Fault::Unreachable {
        path: "feed".into(),
        after: 0,
    });
    restored.take_events();
    let report = restored.flush_outbox().await.unwrap();
    assert!(p.alice.switch().lock().faults.is_empty());
    assert_eq!(report.unknown, vec![msg_id.clone()], "{report:?}");
    assert_eq!(restored.delivery(&msg_id).await.unwrap(), None);
    assert_eq!(unknown(&restored.take_events(), &msg_id), 1);
}

#[tokio::test]
async fn test_scripted_invite_codes_spent_or_expired_go_at_the_minutes_sweep() {
    // As at the service (Switch wire 9.1): once a minute of the switch's clock, at a
    // request, the codes that expired or ran out go; a live one stays, and a spent one
    // stays until the next sweep.
    let p = Pair::new();
    let protocol = ApiProtocol::new(Mode::Plain);
    let mut wallet = p.join(&p.alice, "wallet", &protocol).await;
    let mut shop = p.join(&p.bob, "shop", &protocol).await;
    let spent = shop.register_invite_code(START + DAY_MS, 1).await.unwrap();
    let expiring = shop
        .register_invite_code(START + 10 * MINUTE, 1)
        .await
        .unwrap();
    let live = shop.register_invite_code(START + DAY_MS, 2).await.unwrap();
    let mut first = Pair::note(&p.bob, "order");
    first.invite_code = Some(spent.code.clone());
    let (_, delivery) = wallet.send(first).await.unwrap();
    assert!(
        matches!(delivery, Delivery::Accepted { .. }),
        "{delivery:?}"
    );
    shop.receive(None).await.unwrap();
    assert_eq!(p.bob.switch().invite_uses_left(&spent.code), Some(0));
    // A code expiring at the very time of the sweep is expired then, as at the service.
    let at_the_sweep = shop
        .register_invite_code(p.clock.now_ms() + 11 * MINUTE, 1)
        .await
        .unwrap();
    p.clock.advance_ms(11 * MINUTE);
    shop.receive(None).await.unwrap();
    let left = |code: &str| p.bob.switch().invite_uses_left(code);
    assert_eq!(left(&spent.code), None);
    assert_eq!(left(&expiring.code), None);
    assert_eq!(left(&at_the_sweep.code), None);
    assert_eq!(left(&live.code), Some(2));
}

#[tokio::test]
async fn test_scripted_invite_codes_sweep_with_the_clock_behind_its_mark() {
    // A minute's mark ahead of the switch's clock, left before the clock stepped back, is
    // due at once, as at the service: an expired code goes at the next request.
    let p = Pair::new();
    let protocol = ApiProtocol::new(Mode::Plain);
    let mut shop = p.join(&p.bob, "shop", &protocol).await;
    let code = shop.register_invite_code(START + MINUTE, 1).await.unwrap();
    p.bob.switch().lock().shared.swept_at = Some(START + DAY_MS);
    p.clock.advance_ms(2 * MINUTE);
    shop.receive(None).await.unwrap();
    assert_eq!(p.bob.switch().invite_uses_left(&code.code), None);
}

// -------------------------------------------------------------------------------------
// Holding and withdrawing the messages queued to a counterparty

#[tokio::test]
async fn test_hold_queued_holds_a_message_until_released() {
    let p = Pair::new();
    let protocol = ApiProtocol::new(Mode::Plain);
    let mut wallet = p.join(&p.alice, "wallet", &protocol).await;
    let mut shop = p.join(&p.bob, "shop", &protocol).await;
    let alice = p.alice.identity().public();
    let bob = p.bob.identity().public();
    shop.invite(&alice).await.unwrap();
    wallet.hold_queued(&bob).await.unwrap();
    assert_eq!(wallet.held_counterparties().await.unwrap(), vec![bob]);
    let (msg_id, delivery) = wallet.send(Pair::note(&p.bob, "hello")).await.unwrap();
    assert!(matches!(delivery, Delivery::Queued { .. }), "{delivery:?}");
    let report = wallet.flush_outbox().await.unwrap();
    assert_eq!(report.queued, vec![msg_id.clone()]);
    assert_eq!(p.bob.switch().entries_from(&alice), 0, "held");
    wallet.release_queued(&bob).await.unwrap();
    assert!(wallet.held_counterparties().await.unwrap().is_empty());
    let report = wallet.flush_outbox().await.unwrap();
    assert_eq!(report.done, vec![msg_id]);
    assert_eq!(
        p.bob.switch().entries_from(&alice),
        1,
        "released, delivered once"
    );
}

/// A batch that queues a message to a held counterparty, its answer lost: once it settles
/// the message is in the outbox, held, while the batch's other operation is applied.
#[tokio::test]
async fn test_hold_queued_holds_what_a_kept_batch_queues() {
    let p = Pair::new();
    let protocol = ApiProtocol::new(Mode::Plain);
    let mut wallet = p.join(&p.alice, "wallet", &protocol).await;
    let mut shop = p.join(&p.bob, "shop", &protocol).await;
    let alice = p.alice.identity().public();
    let bob = p.bob.identity().public();
    shop.invite(&alice).await.unwrap();
    let signed = wallet.sign_message(Pair::note(&p.bob, "hello")).unwrap();
    p.alice
        .switch()
        .fail_next(Fault::LoseAnswer { path: "ops".into() });
    let batch = OpBatch::new()
        .op(OpKind::AllowPut {
            pubky: [9; 32],
            reason: pubky_switch_core::admission::PeerReason::Reply,
        })
        .queue(signed.clone());
    assert!(
        wallet
            .submit_batch(batch)
            .await
            .unwrap_err()
            .kept_batch()
            .is_some()
    );
    wallet.hold_queued(&bob).await.unwrap();
    wallet.receive(None).await.unwrap();
    assert!(wallet.kept_batches().await.unwrap().is_empty(), "settled");
    assert!(matches!(
        wallet.delivery(signed.msg_id()).await.unwrap(),
        Some(Delivery::Queued { .. })
    ));
    wallet.flush_outbox().await.unwrap();
    assert_eq!(p.bob.switch().entries_from(&alice), 0, "held");
    wallet.release_queued(&bob).await.unwrap();
    wallet.flush_outbox().await.unwrap();
    assert_eq!(p.bob.switch().entries_from(&alice), 1);
}

/// Withdrawing gives up the messages queued to the counterparty and those a kept batch
/// would queue, each told once; none is delivered or queued again.
#[tokio::test]
async fn test_withdraw_queued_gives_up_queued_and_kept_batch_messages() {
    let p = Pair::new();
    let protocol = ApiProtocol::new(Mode::Plain);
    let mut wallet = p.join(&p.alice, "wallet", &protocol).await;
    let mut shop = p.join(&p.bob, "shop", &protocol).await;
    let alice = p.alice.identity().public();
    let bob = p.bob.identity().public();
    wallet.hold_queued(&bob).await.unwrap();
    let first = wallet.sign_message(Pair::note(&p.bob, "first")).unwrap();
    wallet.queue_signed(first.clone()).await.unwrap();
    let second = wallet.sign_message(Pair::note(&p.bob, "second")).unwrap();
    p.alice
        .switch()
        .fail_next(Fault::LoseAnswer { path: "ops".into() });
    let batch = OpBatch::new()
        .op(OpKind::AllowPut {
            pubky: [9; 32],
            reason: pubky_switch_core::admission::PeerReason::Reply,
        })
        .queue(second.clone());
    assert!(
        wallet
            .submit_batch(batch)
            .await
            .unwrap_err()
            .kept_batch()
            .is_some()
    );
    wallet.take_events();
    let withdrawn = wallet.withdraw_queued(&bob).await.unwrap();
    assert_eq!(
        withdrawn,
        vec![first.msg_id().to_owned(), second.msg_id().to_owned()]
    );
    let events = wallet.take_events();
    assert_eq!(undelivered(&events, first.msg_id()), vec![false]);
    assert_eq!(undelivered(&events, second.msg_id()), vec![false]);
    // The kept batch settles; neither message goes, even released and admitted.
    shop.invite(&alice).await.unwrap();
    wallet.release_queued(&bob).await.unwrap();
    wallet.receive(None).await.unwrap();
    wallet.flush_outbox().await.unwrap();
    assert_eq!(p.bob.switch().entries_from(&alice), 0);
    assert!(
        wallet
            .take_events()
            .iter()
            .all(|e| !matches!(e, AppEvent::MessageUndelivered { .. })),
        "told once"
    );
    let error = wallet.queue_stored(first.plaintext()).await.unwrap_err();
    assert!(
        matches!(
            error,
            AppError::Refused(Refusal::WontDeliver(WontDeliver::GivenUp))
        ),
        "{error:?}"
    );
}

/// A backup carries the hold: the restored app holds the counterparty and delivers none of
/// its messages. A restore in place also keeps a hold the host set after the backup.
#[tokio::test]
async fn test_hold_queued_survives_a_restore() {
    let p = Pair::new();
    let protocol = ApiProtocol::new(Mode::Plain);
    let (mut wallet, mut shop, signed) = wallet_with_a_queued_note(&p, &protocol).await;
    let alice = p.alice.identity().public();
    let bob = p.bob.identity().public();
    wallet.hold_queued(&bob).await.unwrap();
    let backup = wallet.backup().await.unwrap();
    drop(wallet);
    shop.invite(&alice).await.unwrap();
    let mut restored = restored_wallet(&p, &protocol, &backup).await;
    assert_eq!(restored.held_counterparties().await.unwrap(), vec![bob]);
    restored.flush_outbox().await.unwrap();
    assert_eq!(
        p.bob.switch().entries_from(&alice),
        0,
        "held after the restore"
    );
    assert!(matches!(
        restored.delivery(signed.msg_id()).await.unwrap(),
        Some(Delivery::Queued { .. })
    ));
    // In place: a backup taken before the hold, restored over a store that holds it.
    restored.release_queued(&bob).await.unwrap();
    let before = restored.backup().await.unwrap();
    restored.hold_queued(&bob).await.unwrap();
    let store = Arc::new(MemoryStore::new());
    drop(restored);
    let env = p.env(&p.alice, Arc::clone(&store) as Arc<dyn StateStore>);
    let before = AppBackup::from_bytes(&before.to_bytes().unwrap()).unwrap();
    let mut first = App::restore(env, protocol.clone(), config(), &before)
        .await
        .unwrap();
    first.hold_queued(&bob).await.unwrap();
    drop(first);
    let env = p.env(&p.alice, Arc::clone(&store) as Arc<dyn StateStore>);
    let in_place = App::restore(env, protocol.clone(), config(), &before)
        .await
        .unwrap();
    assert_eq!(in_place.held_counterparties().await.unwrap(), vec![bob]);
}

/// A held copy's replay deadline still runs: past it the copy is given up, once, though
/// held.
#[tokio::test]
async fn test_hold_queued_copy_past_its_deadline_is_given_up_once() {
    let p = Pair::new();
    let protocol = ApiProtocol::new(Mode::Plain);
    let mut wallet = p.join(&p.alice, "wallet", &protocol).await;
    let mut shop = p.join(&p.bob, "shop", &protocol).await;
    let alice = p.alice.identity().public();
    let bob = p.bob.identity().public();
    shop.invite(&alice).await.unwrap();
    let signed = wallet.sign_message(Pair::note(&p.bob, "old")).unwrap();
    p.clock.advance_ms(25 * DAY_MS);
    let msg_id = wallet.queue_stored(signed.plaintext()).await.unwrap();
    wallet.hold_queued(&bob).await.unwrap();
    wallet.flush_outbox().await.unwrap();
    p.clock.advance_ms(6 * DAY_MS);
    wallet.take_events();
    let report = wallet.flush_outbox().await.unwrap();
    assert_eq!(report.unknown, vec![msg_id.clone()]);
    assert_eq!(unknown(&wallet.take_events(), &msg_id), 1);
    wallet.release_queued(&bob).await.unwrap();
    wallet.flush_outbox().await.unwrap();
    assert_eq!(p.bob.switch().entries_from(&alice), 0);
}

/// A re-send asked while the counterparty is held isn't delivered until the release; then it
/// goes once.
#[tokio::test]
async fn test_hold_queued_holds_a_resend_until_released() {
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
    let before = p.bob.switch().entries_from(&alice);
    wallet.hold_queued(&bob).await.unwrap();
    wallet.resend(&msg_id).await.unwrap();
    wallet.flush_message(&msg_id).await.unwrap();
    wallet.flush_outbox().await.unwrap();
    assert_eq!(p.bob.switch().entries_from(&alice), before, "held");
    wallet.release_queued(&bob).await.unwrap();
    wallet.flush_outbox().await.unwrap();
    wallet.flush_outbox().await.unwrap();
    assert_eq!(
        p.bob.switch().entries_from(&alice),
        before + 1,
        "released, re-sent once"
    );
}

/// A held message's tries aren't counted, and the reply grant it owes waits with its
/// delivery.
#[tokio::test]
async fn test_hold_queued_counts_no_try_and_writes_no_reply_grant() {
    let p = Pair::new();
    let protocol = ApiProtocol::new(Mode::Plain);
    let mut wallet = p.join(&p.alice, "wallet", &protocol).await;
    let mut shop = p.join(&p.bob, "shop", &protocol).await;
    let alice = p.alice.identity().public();
    let bob = p.bob.identity().public();
    shop.invite(&alice).await.unwrap();
    let entries = |w: &ScriptedSwitch| {
        w.applied()
            .iter()
            .filter(|op| {
                matches!(op.body().kind, OpKind::AllowPut { pubky, reason: pubky_switch_core::admission::PeerReason::Reply } if pubky == bob)
            })
            .count()
    };
    wallet.hold_queued(&bob).await.unwrap();
    let (msg_id, _) = wallet.send(Pair::note(&p.bob, "hello")).await.unwrap();
    wallet.flush_outbox().await.unwrap();
    wallet.flush_outbox().await.unwrap();
    assert!(
        matches!(
            wallet.delivery(&msg_id).await.unwrap(),
            Some(Delivery::Queued { tries: 0, .. })
        ),
        "{:?}",
        wallet.delivery(&msg_id).await.unwrap()
    );
    assert_eq!(entries(p.alice.switch()), 0, "no reply grant while held");
    wallet.release_queued(&bob).await.unwrap();
    wallet.flush_outbox().await.unwrap();
    assert_eq!(p.bob.switch().entries_from(&alice), 1);
    assert_eq!(
        entries(p.alice.switch()),
        1,
        "the reply grant, with the delivery"
    );
}

/// A kept batch that a later write settles, not a read: its message goes into the outbox
/// held.
#[tokio::test]
async fn test_hold_queued_holds_what_a_kept_batch_queues_when_a_write_settles_it() {
    let p = Pair::new();
    let protocol = ApiProtocol::new(Mode::Plain);
    let mut wallet = p.join(&p.alice, "wallet", &protocol).await;
    let mut shop = p.join(&p.bob, "shop", &protocol).await;
    let alice = p.alice.identity().public();
    let bob = p.bob.identity().public();
    shop.invite(&alice).await.unwrap();
    let signed = wallet.sign_message(Pair::note(&p.bob, "hello")).unwrap();
    p.alice
        .switch()
        .fail_next(Fault::LoseAnswer { path: "ops".into() });
    let batch = OpBatch::new()
        .op(OpKind::AllowPut {
            pubky: [9; 32],
            reason: pubky_switch_core::admission::PeerReason::Reply,
        })
        .queue(signed.clone());
    assert!(
        wallet
            .submit_batch(batch)
            .await
            .unwrap_err()
            .kept_batch()
            .is_some()
    );
    wallet.hold_queued(&bob).await.unwrap();
    wallet
        .submit_batch(OpBatch::new().op(OpKind::AllowPut {
            pubky: [8; 32],
            reason: pubky_switch_core::admission::PeerReason::Reply,
        }))
        .await
        .unwrap();
    assert!(wallet.kept_batches().await.unwrap().is_empty(), "settled");
    wallet.flush_message(signed.msg_id()).await.unwrap();
    wallet.flush_outbox().await.unwrap();
    assert_eq!(p.bob.switch().entries_from(&alice), 0, "held");
    wallet.release_queued(&bob).await.unwrap();
    wallet.flush_outbox().await.unwrap();
    assert_eq!(p.bob.switch().entries_from(&alice), 1);
}

/// A backup taken before the hold doesn't carry it: restored on another store, the message
/// isn't held, and goes at the first flush unless the host holds again first.
#[tokio::test]
async fn test_hold_queued_set_after_a_backup_isnt_carried_to_another_store() {
    let p = Pair::new();
    let protocol = ApiProtocol::new(Mode::Plain);
    let (mut wallet, mut shop, _signed) = wallet_with_a_queued_note(&p, &protocol).await;
    let alice = p.alice.identity().public();
    let bob = p.bob.identity().public();
    let backup = wallet.backup().await.unwrap();
    wallet.hold_queued(&bob).await.unwrap();
    drop(wallet);
    shop.invite(&alice).await.unwrap();
    let mut restored = restored_wallet(&p, &protocol, &backup).await;
    release_held(&mut restored, "sample").await;
    assert!(restored.held_counterparties().await.unwrap().is_empty());
    restored.flush_outbox().await.unwrap();
    assert_eq!(
        p.bob.switch().entries_from(&alice),
        1,
        "not held on the new store"
    );
}

/// A re-send given up by `withdraw_queued` isn't queued again when a send later finds the
/// counterparty's provider loss (`resend_since`).
#[tokio::test]
async fn test_withdraw_queued_resend_isnt_queued_again_after_a_provider_loss() {
    let p = Pair::new();
    let protocol = ApiProtocol::new(Mode::Plain);
    let mut wallet = p.join(&p.alice, "wallet", &protocol).await;
    let mut shop = p.join(&p.bob, "shop", &protocol).await;
    let alice = p.alice.identity().public();
    let bob = p.bob.identity().public();
    shop.invite(&alice).await.unwrap();
    let (first, delivery) = wallet.send(Pair::note(&p.bob, "one")).await.unwrap();
    assert!(
        matches!(delivery, Delivery::Accepted { .. }),
        "{delivery:?}"
    );
    // A re-send asked while held, then withdrawn.
    wallet.hold_queued(&bob).await.unwrap();
    wallet.resend(&first).await.unwrap();
    wallet.take_events();
    let withdrawn = wallet.withdraw_queued(&bob).await.unwrap();
    assert_eq!(withdrawn, vec![first.clone()]);
    assert_eq!(undelivered(&wallet.take_events(), &first), vec![true]);
    wallet.release_queued(&bob).await.unwrap();
    // Bob loses his provider and recovers at another.
    const RECOVERED: &str = "https://bob-recovered.example";
    let recovered =
        ScriptedSwitch::recovering(p.bob.identity().key(), [9; 32], Arc::clone(&p.clock), 2, 1)
            .unwrap();
    p.router.add_switch(RECOVERED, &recovered);
    let doc = p
        .bob
        .sign_next(|body| {
            body.generation = 2;
            body.inbox = Inbox::new(RECOVERED, recovered.service_key());
            body.recovery_from = Some(1);
        })
        .unwrap();
    recovered.deliver_identity(&doc).unwrap();
    recovered
        .lock()
        .shared
        .keep_peer(p.alice.identity().public());
    p.clock.advance_ms(DOC_CACHE_MS + MINUTE);
    let two = wallet.send(Pair::note(&p.bob, "two")).await;
    let report = wallet.flush_outbox().await.unwrap();
    let events = wallet.take_events();
    assert!(
        matches!(
            wallet.delivery(&first).await.unwrap(),
            Some(Delivery::Accepted { .. })
        ),
        "the withdrawn re-send is in the outbox again: {:?}; two: {two:?}; report: {report:?}; entries at the recovered switch: {}",
        wallet.delivery(&first).await.unwrap(),
        recovered.entries_from(&alice)
    );
    assert!(
        !events
            .iter()
            .any(|e| matches!(e, AppEvent::ResendAfterLoss { .. })),
        "the withdrawn re-send is queued again: {events:?}"
    );
}

/// A withdrawn re-send that keeps its record job stays in the outbox with a give-up mark, so
/// a send that later finds the counterparty's provider loss doesn't queue it again.
#[tokio::test]
async fn test_withdraw_queued_resend_with_a_record_job_isnt_queued_again_after_a_provider_loss() {
    let p = Pair::new();
    let protocol = ApiProtocol::new(Mode::Plain);
    let mut wallet = p.join(&p.alice, "wallet", &protocol).await;
    let mut shop = p.join(&p.bob, "shop", &protocol).await;
    let alice = p.alice.identity().public();
    let bob = p.bob.identity().public();
    shop.invite(&alice).await.unwrap();
    wallet.send(Pair::note(&p.bob, "zero")).await.unwrap();
    // Accepted, its record write's answer lost: the record job stays owed.
    let signed = wallet
        .sign_message(Pair::note(&p.bob, "one"))
        .unwrap()
        .with_record(crate::app::RecordJob {
            target: inbox(),
            tag: b"sent".to_vec(),
        });
    let one = wallet.queue_signed(signed).await.unwrap();
    p.alice
        .switch()
        .fail_next(Fault::LoseAnswer { path: "ops".into() });
    let delivery = wallet.flush_message(&one).await.unwrap();
    assert!(
        matches!(delivery, Some(Delivery::Accepted { .. })),
        "{delivery:?}"
    );
    assert!(
        wallet.outbox_record(&one).await.is_some(),
        "the record job is owed"
    );
    wallet.hold_queued(&bob).await.unwrap();
    // The record write fails again at the re-send's try, so the job is still owed.
    p.alice.switch().fail_next(Fault::Unreachable {
        path: "ops".into(),
        after: 0,
    });
    wallet.resend(&one).await.unwrap();
    wallet.take_events();
    assert_eq!(
        wallet.withdraw_queued(&bob).await.unwrap(),
        vec![one.clone()]
    );
    assert_eq!(undelivered(&wallet.take_events(), &one), vec![true]);
    assert!(
        wallet.outbox_record(&one).await.is_some(),
        "kept for its record job"
    );
    wallet.release_queued(&bob).await.unwrap();
    // Bob loses his provider and recovers at another.
    const RECOVERED: &str = "https://bob-recovered.example";
    let recovered =
        ScriptedSwitch::recovering(p.bob.identity().key(), [9; 32], Arc::clone(&p.clock), 2, 1)
            .unwrap();
    p.router.add_switch(RECOVERED, &recovered);
    let doc = p
        .bob
        .sign_next(|body| {
            body.generation = 2;
            body.inbox = Inbox::new(RECOVERED, recovered.service_key());
            body.recovery_from = Some(1);
        })
        .unwrap();
    recovered.deliver_identity(&doc).unwrap();
    recovered.lock().shared.keep_peer(alice);
    p.clock.advance_ms(DOC_CACHE_MS + MINUTE);
    wallet.send(Pair::note(&p.bob, "two")).await.unwrap();
    let events = wallet.take_events();
    // Only the message not given up is sent again.
    assert!(
        events
            .iter()
            .any(|e| matches!(e, AppEvent::ResendAfterLoss { messages: 1, .. })),
        "{events:?}"
    );
    assert!(
        wallet
            .outbox_record(&one)
            .await
            .is_none_or(|item| !item.delivery_owed()),
        "no re-send of the withdrawn message is owed"
    );
}

#[tokio::test]
async fn test_hold_queued_refuses_the_own_identity() {
    let p = Pair::new();
    let protocol = ApiProtocol::new(Mode::Plain);
    let mut wallet = p.join(&p.alice, "wallet", &protocol).await;
    let alice = p.alice.identity().public();
    let error = wallet.hold_queued(&alice).await.unwrap_err();
    assert!(
        matches!(error, AppError::Refused(Refusal::Usage(_))),
        "{error:?}"
    );
    assert!(wallet.held_counterparties().await.unwrap().is_empty());
}

// -------------------------------------------------------------------------------------
// Holding and withdrawing one queued message

/// Two messages queued to one counterparty: the held one waits while the other goes, and
/// goes once released.
#[tokio::test]
async fn test_hold_message_holds_one_message_while_another_to_the_counterparty_goes() {
    let p = Pair::new();
    let protocol = ApiProtocol::new(Mode::Plain);
    let mut wallet = p.join(&p.alice, "wallet", &protocol).await;
    let mut shop = p.join(&p.bob, "shop", &protocol).await;
    let alice = p.alice.identity().public();
    shop.invite(&alice).await.unwrap();
    let held = wallet.sign_message(Pair::note(&p.bob, "held")).unwrap();
    wallet.queue_signed(held.clone()).await.unwrap();
    let other = wallet.sign_message(Pair::note(&p.bob, "other")).unwrap();
    wallet.queue_signed(other.clone()).await.unwrap();
    assert!(wallet.hold_message("sample", held.msg_id()).await.unwrap());
    assert_eq!(
        wallet.held_messages("sample").await.unwrap(),
        vec![held.msg_id().to_owned()]
    );
    assert!(wallet.held_counterparties().await.unwrap().is_empty());
    let report = wallet.flush_outbox().await.unwrap();
    assert_eq!(report.done, vec![other.msg_id().to_owned()]);
    assert_eq!(report.queued, vec![held.msg_id().to_owned()]);
    assert_eq!(p.bob.switch().entries_from(&alice), 1, "only the other");
    // A send or a flush of the held message itself doesn't pass the hold either.
    wallet.flush_message(held.msg_id()).await.unwrap();
    assert!(matches!(
        wallet.delivery(held.msg_id()).await.unwrap(),
        Some(Delivery::Queued { tries: 0, .. })
    ));
    wallet
        .release_message(
            "sample",
            held.msg_id(),
            crate::app::ReplyGrantOnRelease::IfOwed,
        )
        .await
        .unwrap();
    assert!(wallet.held_messages("sample").await.unwrap().is_empty());
    let report = wallet.flush_outbox().await.unwrap();
    assert_eq!(report.done, vec![held.msg_id().to_owned()]);
    assert_eq!(p.bob.switch().entries_from(&alice), 2, "released, once");
}

/// A message the app owes no delivery of isn't held, and nothing is written: one delivered,
/// one never queued here.
#[tokio::test]
async fn test_hold_message_of_a_message_not_owed_holds_nothing() {
    let p = Pair::new();
    let protocol = ApiProtocol::new(Mode::Plain);
    let mut wallet = p.join(&p.alice, "wallet", &protocol).await;
    let mut shop = p.join(&p.bob, "shop", &protocol).await;
    let alice = p.alice.identity().public();
    shop.invite(&alice).await.unwrap();
    let (delivered, delivery) = wallet.send(Pair::note(&p.bob, "hello")).await.unwrap();
    assert!(
        matches!(delivery, Delivery::Accepted { .. }),
        "{delivery:?}"
    );
    assert!(!wallet.hold_message("sample", &delivered).await.unwrap());
    let signed = wallet.sign_message(Pair::note(&p.bob, "unqueued")).unwrap();
    assert!(
        !wallet
            .hold_message("sample", signed.msg_id())
            .await
            .unwrap()
    );
    assert!(
        wallet
            .reader()
            .scan_raw(super::super::send::MESSAGE_HOLD_PREFIX)
            .await
            .unwrap()
            .is_empty()
    );
}

/// A re-send asked after the message was delivered, and not tried yet, is owed again: held
/// by itself, it waits until its own release, whatever holds its counterparty.
#[tokio::test]
async fn test_hold_message_holds_a_resend_until_released() {
    let p = Pair::new();
    let protocol = ApiProtocol::new(Mode::Plain);
    let mut wallet = p.join(&p.alice, "wallet", &protocol).await;
    let mut shop = p.join(&p.bob, "shop", &protocol).await;
    let alice = p.alice.identity().public();
    shop.invite(&alice).await.unwrap();
    let signed = wallet.sign_message(Pair::note(&p.bob, "hello")).unwrap();
    wallet.queue_signed(signed.clone()).await.unwrap();
    wallet.flush_outbox().await.unwrap();
    let before = p.bob.switch().entries_from(&alice);
    assert_eq!(before, 1);
    // Delivered, nothing is owed: not held.
    assert!(
        !wallet
            .hold_message("sample", signed.msg_id())
            .await
            .unwrap()
    );
    // The re-send is asked while its counterparty is held, so it isn't tried; then the
    // message is held by itself and the counterparty released.
    let bob = p.bob.identity().public();
    wallet.hold_queued(&bob).await.unwrap();
    wallet.resend(signed.msg_id()).await.unwrap();
    assert!(
        wallet
            .hold_message("sample", signed.msg_id())
            .await
            .unwrap()
    );
    wallet.release_queued(&bob).await.unwrap();
    wallet.flush_outbox().await.unwrap();
    wallet.flush_message(signed.msg_id()).await.unwrap();
    assert_eq!(p.bob.switch().entries_from(&alice), before, "held");
    wallet
        .release_message(
            "sample",
            signed.msg_id(),
            crate::app::ReplyGrantOnRelease::IfOwed,
        )
        .await
        .unwrap();
    wallet.flush_outbox().await.unwrap();
    wallet.flush_outbox().await.unwrap();
    assert_eq!(
        p.bob.switch().entries_from(&alice),
        before + 1,
        "released, re-sent once"
    );
}

/// A message a kept batch puts in the outbox once it settles is held, while the batch's
/// other operation is applied.
#[tokio::test]
async fn test_hold_message_holds_what_a_kept_batch_queues() {
    let p = Pair::new();
    let protocol = ApiProtocol::new(Mode::Plain);
    let mut wallet = p.join(&p.alice, "wallet", &protocol).await;
    let mut shop = p.join(&p.bob, "shop", &protocol).await;
    let alice = p.alice.identity().public();
    shop.invite(&alice).await.unwrap();
    let signed = wallet.sign_message(Pair::note(&p.bob, "hello")).unwrap();
    p.alice
        .switch()
        .fail_next(Fault::LoseAnswer { path: "ops".into() });
    let batch = OpBatch::new()
        .op(OpKind::AllowPut {
            pubky: [9; 32],
            reason: pubky_switch_core::admission::PeerReason::Reply,
        })
        .queue(signed.clone());
    assert!(
        wallet
            .submit_batch(batch)
            .await
            .unwrap_err()
            .kept_batch()
            .is_some()
    );
    assert!(
        wallet
            .hold_message("sample", signed.msg_id())
            .await
            .unwrap()
    );
    assert_eq!(
        wallet.held_messages("sample").await.unwrap(),
        vec![signed.msg_id().to_owned()]
    );
    wallet.receive(None).await.unwrap();
    assert!(wallet.kept_batches().await.unwrap().is_empty(), "settled");
    wallet.flush_outbox().await.unwrap();
    assert_eq!(p.bob.switch().entries_from(&alice), 0, "held");
    wallet
        .release_message(
            "sample",
            signed.msg_id(),
            crate::app::ReplyGrantOnRelease::IfOwed,
        )
        .await
        .unwrap();
    wallet.flush_outbox().await.unwrap();
    assert_eq!(p.bob.switch().entries_from(&alice), 1);
}

/// A held message's replay deadline still runs: past it the message is given up, once,
/// and its hold ends with the give-up.
#[tokio::test]
async fn test_hold_message_past_its_deadline_is_given_up_and_the_hold_ends() {
    let p = Pair::new();
    let protocol = ApiProtocol::new(Mode::Plain);
    let mut wallet = p.join(&p.alice, "wallet", &protocol).await;
    let mut shop = p.join(&p.bob, "shop", &protocol).await;
    let alice = p.alice.identity().public();
    shop.invite(&alice).await.unwrap();
    let signed = wallet.sign_message(Pair::note(&p.bob, "old")).unwrap();
    p.clock.advance_ms(25 * DAY_MS);
    let msg_id = wallet.queue_stored(signed.plaintext()).await.unwrap();
    assert!(wallet.hold_message("sample", &msg_id).await.unwrap());
    wallet.flush_outbox().await.unwrap();
    p.clock.advance_ms(6 * DAY_MS);
    wallet.take_events();
    let report = wallet.flush_outbox().await.unwrap();
    assert_eq!(report.unknown, vec![msg_id.clone()]);
    assert_eq!(unknown(&wallet.take_events(), &msg_id), 1);
    assert!(
        wallet
            .reader()
            .scan_raw(super::super::send::MESSAGE_HOLD_PREFIX)
            .await
            .unwrap()
            .is_empty(),
        "the hold ends in the give-up's commit"
    );
    wallet.flush_outbox().await.unwrap();
    assert_eq!(p.bob.switch().entries_from(&alice), 0);
}

/// A backup carries the hold of a message it carries; a restore in place also keeps a hold
/// set after the backup.
#[tokio::test]
async fn test_hold_message_survives_a_restore() {
    let p = Pair::new();
    let protocol = ApiProtocol::new(Mode::Plain);
    let (mut wallet, mut shop, signed) = wallet_with_a_queued_note(&p, &protocol).await;
    let alice = p.alice.identity().public();
    assert!(
        wallet
            .hold_message("sample", signed.msg_id())
            .await
            .unwrap()
    );
    let backup = wallet.backup().await.unwrap();
    drop(wallet);
    shop.invite(&alice).await.unwrap();
    let mut restored = restored_wallet(&p, &protocol, &backup).await;
    assert!(
        held_at_restore(&restored.take_events()).is_empty(),
        "the protocol's own hold isn't counted as the restore's"
    );
    assert_eq!(
        restored.held_messages("sample").await.unwrap(),
        vec![signed.msg_id().to_owned()]
    );
    restored.flush_outbox().await.unwrap();
    assert_eq!(
        p.bob.switch().entries_from(&alice),
        0,
        "held after the restore"
    );
    // In place: a backup taken before the hold, restored over a store that holds it.
    restored
        .release_message(
            "sample",
            signed.msg_id(),
            crate::app::ReplyGrantOnRelease::IfOwed,
        )
        .await
        .unwrap();
    let before = restored.backup().await.unwrap();
    assert!(
        AppBackup::from_bytes(&before.to_bytes().unwrap())
            .unwrap()
            .held_messages
            .is_empty()
    );
    let store = Arc::new(MemoryStore::new());
    drop(restored);
    let env = p.env(&p.alice, Arc::clone(&store) as Arc<dyn StateStore>);
    let before = AppBackup::from_bytes(&before.to_bytes().unwrap()).unwrap();
    let mut first = App::restore(env, protocol.clone(), config(), &before)
        .await
        .unwrap();
    // The restore holds it, and the protocol, after its read, releases it, then holds it
    // again.
    assert_eq!(
        first.held_messages("sample").await.unwrap(),
        vec![signed.msg_id().to_owned()]
    );
    release_held(&mut first, "sample").await;
    assert!(first.held_messages("sample").await.unwrap().is_empty());
    assert!(first.hold_message("sample", signed.msg_id()).await.unwrap());
    drop(first);
    let env = p.env(&p.alice, Arc::clone(&store) as Arc<dyn StateStore>);
    let mut in_place = App::restore(env, protocol.clone(), config(), &before)
        .await
        .unwrap();
    assert_eq!(
        in_place.held_messages("sample").await.unwrap(),
        vec![signed.msg_id().to_owned()]
    );
    in_place.flush_outbox().await.unwrap();
    assert_eq!(p.bob.switch().entries_from(&alice), 0, "held in place");
}

/// A backup whose held message isn't one of its outbox owed a delivery is refused: no
/// writer carries such a hold.
#[tokio::test]
async fn test_hold_message_backup_naming_a_message_outside_its_outbox_is_refused() {
    let p = Pair::new();
    let protocol = ApiProtocol::new(Mode::Plain);
    let (mut wallet, _shop, signed) = wallet_with_a_queued_note(&p, &protocol).await;
    assert!(
        wallet
            .hold_message("sample", signed.msg_id())
            .await
            .unwrap()
    );
    let mut backup =
        AppBackup::from_bytes(&wallet.backup().await.unwrap().to_bytes().unwrap()).unwrap();
    backup.held_messages.push("not-in-the-outbox".into());
    let env = p.env(&p.alice, Arc::new(MemoryStore::new()));
    let error = App::restore(env, protocol.clone(), config(), &backup)
        .await
        .unwrap_err();
    assert!(matches!(error, AppError::InvalidData(_)), "{error:?}");
}

/// A kept batch that queues `signed` to bob, its first send unanswered, so it is kept.
async fn kept_with(p: &Pair, wallet: &mut App, signed: &SignedMessage) {
    p.alice.switch().fail_next(Fault::Unanswered {
        path: "ops".into(),
        after: 0,
    });
    let batch = OpBatch::new()
        .op(OpKind::AllowPut {
            pubky: [9; 32],
            reason: pubky_switch_core::admission::PeerReason::Reply,
        })
        .queue(signed.clone());
    assert!(
        wallet
            .submit_batch(batch)
            .await
            .unwrap_err()
            .kept_batch()
            .is_some()
    );
}

async fn hold_marks_of(app: &App) -> usize {
    app.reader()
        .scan_raw(super::super::send::MESSAGE_HOLD_PREFIX)
        .await
        .unwrap()
        .len()
}

/// A message held while a kept batch would queue it stays held when the protocol queues it
/// again itself, with either call: queuing ends no hold.
#[tokio::test]
async fn test_hold_message_of_a_kept_batch_message_holds_its_copy_queued_again() {
    for signed_again in [false, true] {
        kept_batch_message_queued_again(signed_again).await;
    }
}

async fn kept_batch_message_queued_again(signed_again: bool) {
    let p = Pair::new();
    let protocol = ApiProtocol::new(Mode::Plain);
    let mut wallet = p.join(&p.alice, "wallet", &protocol).await;
    let mut shop = p.join(&p.bob, "shop", &protocol).await;
    let alice = p.alice.identity().public();
    shop.invite(&alice).await.unwrap();
    let signed = wallet.sign_message(Pair::note(&p.bob, "hello")).unwrap();
    kept_with(&p, &mut wallet, &signed).await;
    assert!(
        wallet
            .hold_message("sample", signed.msg_id())
            .await
            .unwrap()
    );
    if signed_again {
        wallet.queue_signed(signed.clone()).await.unwrap();
    } else {
        wallet.queue_stored(signed.plaintext()).await.unwrap();
    }
    assert_eq!(
        wallet.held_messages("sample").await.unwrap(),
        vec![signed.msg_id().to_owned()]
    );
    for _ in 0..3 {
        wallet.flush_outbox().await.unwrap();
    }
    wallet.receive(None).await.unwrap();
    wallet.flush_outbox().await.unwrap();
    assert_eq!(p.bob.switch().entries_from(&alice), 0, "held");
    wallet
        .release_message(
            "sample",
            signed.msg_id(),
            crate::app::ReplyGrantOnRelease::IfOwed,
        )
        .await
        .unwrap();
    wallet.flush_outbox().await.unwrap();
    assert_eq!(p.bob.switch().entries_from(&alice), 1);
}

/// A kept batch refused for good on its re-send ends the hold of the message it would have
/// queued: rebuilt with the same signed message, the batch puts it in the outbox unheld.
#[tokio::test]
async fn test_hold_message_of_a_dropped_kept_batch_ends_with_it() {
    let p = Pair::new();
    let protocol = ApiProtocol::new(Mode::Plain);
    let mut wallet = p.join(&p.alice, "wallet", &protocol).await;
    let mut shop = p.join(&p.bob, "shop", &protocol).await;
    let alice = p.alice.identity().public();
    shop.invite(&alice).await.unwrap();
    let signed = wallet.sign_message(Pair::note(&p.bob, "hello")).unwrap();
    kept_with(&p, &mut wallet, &signed).await;
    assert!(
        wallet
            .hold_message("sample", signed.msg_id())
            .await
            .unwrap()
    );
    p.alice.switch().fail_next(Fault::Error {
        path: "ops".into(),
        code: ErrorCode::Conflict,
        current: json!({}),
    });
    wallet.receive(None).await.unwrap_or_default();
    assert!(wallet.kept_batches().await.unwrap().is_empty(), "dropped");
    assert_eq!(
        hold_marks_of(&wallet).await,
        0,
        "the hold ended with the batch"
    );
    let batch = OpBatch::new()
        .op(OpKind::AllowPut {
            pubky: [8; 32],
            reason: pubky_switch_core::admission::PeerReason::Reply,
        })
        .queue(signed.clone());
    wallet.submit_batch(batch).await.unwrap();
    assert!(wallet.held_messages("sample").await.unwrap().is_empty());
    wallet.flush_outbox().await.unwrap();
    assert_eq!(p.bob.switch().entries_from(&alice), 1, "delivered unheld");
}

/// A kept batch dropped while the outbox holds the message it would queue leaves the hold:
/// the outbox's delivery goes on, held.
#[tokio::test]
async fn test_hold_message_outlives_a_dropped_kept_batch_while_the_outbox_holds_it() {
    let p = Pair::new();
    let protocol = ApiProtocol::new(Mode::Plain);
    let mut wallet = p.join(&p.alice, "wallet", &protocol).await;
    let mut shop = p.join(&p.bob, "shop", &protocol).await;
    let alice = p.alice.identity().public();
    shop.invite(&alice).await.unwrap();
    let signed = wallet.sign_message(Pair::note(&p.bob, "hello")).unwrap();
    kept_with(&p, &mut wallet, &signed).await;
    wallet.queue_signed(signed.clone()).await.unwrap();
    assert!(
        wallet
            .hold_message("sample", signed.msg_id())
            .await
            .unwrap()
    );
    p.alice.switch().fail_next(Fault::Error {
        path: "ops".into(),
        code: ErrorCode::Conflict,
        current: json!({}),
    });
    wallet.receive(None).await.unwrap_or_default();
    assert!(wallet.kept_batches().await.unwrap().is_empty(), "dropped");
    assert_eq!(
        wallet.held_messages("sample").await.unwrap(),
        vec![signed.msg_id().to_owned()]
    );
    wallet.flush_outbox().await.unwrap();
    assert_eq!(p.bob.switch().entries_from(&alice), 0, "still held");
}

/// A restore in place from a backup taken before a message was queued keeps that message,
/// held, its protocol told; once released, it is delivered once.
#[tokio::test]
async fn test_backup_outbox_restore_in_place_holds_a_message_queued_since() {
    let p = Pair::new();
    let protocol = ApiProtocol::new(Mode::Plain);
    let (mut wallet, _shop, store) = wallet_on_a_fault_store(&p, &protocol).await;
    let alice = p.alice.identity().public();
    let before = wallet.backup().await.unwrap();
    let signed = wallet.sign_message(Pair::note(&p.bob, "hello")).unwrap();
    let msg_id = wallet.queue_signed(signed).await.unwrap();
    drop(wallet);
    let env = p.env(&p.alice, Arc::clone(&store) as Arc<dyn StateStore>);
    let mut wallet = App::restore(env, protocol.clone(), config(), &before)
        .await
        .unwrap();
    assert!(matches!(
        wallet.delivery(&msg_id).await.unwrap(),
        Some(Delivery::Queued { .. })
    ));
    assert_eq!(held_at_restore(&wallet.take_events()), vec![1]);
    wallet.flush_outbox().await.unwrap();
    assert_eq!(p.bob.switch().entries_from(&alice), 0, "held");
    // A second restore finds it held by the store: it stays held, and nothing new is told.
    drop(wallet);
    let env = p.env(&p.alice, Arc::clone(&store) as Arc<dyn StateStore>);
    let mut wallet = App::restore(env, protocol.clone(), config(), &before)
        .await
        .unwrap();
    let pending = crate::app::tests::pending_events(&mut wallet)
        .await
        .unwrap();
    assert_eq!(held_at_restore(&pending), vec![1]);
    assert_eq!(
        wallet.held_messages("sample").await.unwrap(),
        vec![msg_id.clone()]
    );
    release_held(&mut wallet, "sample").await;
    wallet.flush_outbox().await.unwrap();
    assert_eq!(
        p.bob.switch().entries_from(&alice),
        1,
        "delivered once released"
    );
}

/// A restore in place keeps a give-up the store told and the protocol acknowledged: the
/// backup's older copy of the message is neither delivered, held nor told again.
#[tokio::test]
async fn test_backup_outbox_restore_in_place_keeps_an_acknowledged_give_up() {
    let p = Pair::new();
    let protocol = ApiProtocol::new(Mode::Plain);
    let (mut wallet, _shop, store) = wallet_on_a_fault_store(&p, &protocol).await;
    let signed = wallet.sign_message(Pair::note(&p.bob, "gone")).unwrap();
    let msg_id = wallet.queue_signed(signed).await.unwrap();
    let backup = wallet.backup().await.unwrap();
    assert!(wallet.withdraw_message("sample", &msg_id).await.unwrap());
    let told = wallet.unacknowledged_events().await.unwrap();
    assert_eq!(undelivered(&told, &msg_id), vec![false]);
    wallet
        .ack_events(told.last().unwrap().id().unwrap())
        .await
        .unwrap();
    drop(wallet);
    let env = p.env(&p.alice, Arc::clone(&store) as Arc<dyn StateStore>);
    let mut restored = App::restore(env, protocol.clone(), config(), &backup)
        .await
        .unwrap();
    assert_eq!(restored.delivery(&msg_id).await.unwrap(), None);
    let pending = crate::app::tests::pending_events(&mut restored)
        .await
        .unwrap();
    assert!(undelivered(&pending, &msg_id).is_empty());
    assert_eq!(unknown(&pending, &msg_id), 0);
    assert!(held_at_restore(&pending).is_empty());
    restored.flush_outbox().await.unwrap();
    assert_eq!(p.bob.switch().entries_from(&p.alice.identity().public()), 0);
    // The store's mark of the give-up outlives the restore: a second one finds it too.
    drop(restored);
    let env = p.env(&p.alice, Arc::clone(&store) as Arc<dyn StateStore>);
    let mut again = App::restore(env, protocol.clone(), config(), &backup)
        .await
        .unwrap();
    assert_eq!(again.delivery(&msg_id).await.unwrap(), None);
    let pending = crate::app::tests::pending_events(&mut again).await.unwrap();
    assert!(held_at_restore(&pending).is_empty());
    assert!(again.held_messages("sample").await.unwrap().is_empty());
}

/// A restore in place over a store that had a message accepted since the backup puts it
/// back without its delivery, its owed record job kept: not held, not told, not delivered
/// again, and the job still runs.
#[tokio::test]
async fn test_backup_outbox_restore_in_place_keeps_the_record_job_of_a_message_accepted_since() {
    let p = Pair::new();
    let protocol = ApiProtocol::new(Mode::Plain);
    let (mut wallet, _shop, store) = wallet_on_a_fault_store(&p, &protocol).await;
    let signed = wallet.sign_message(Pair::note(&p.bob, "hello")).unwrap();
    let target = RecordTarget::new(items(), &signed.hash());
    let signed = signed.with_record(RecordJob {
        target,
        tag: b"sent".to_vec(),
    });
    let msg_id = wallet.queue_signed(signed).await.unwrap();
    let backup = wallet.backup().await.unwrap();
    // Accepted, its record job failing for now: the switch's batches can't be sent.
    p.alice.switch().fail_next(Fault::Unreachable {
        path: "ops".into(),
        after: 1,
    });
    for _ in 0..4 {
        p.alice.switch().fail_next(Fault::Unreachable {
            path: "ops".into(),
            after: 0,
        });
    }
    wallet.flush_outbox().await.unwrap();
    let alice = p.alice.identity().public();
    assert_eq!(p.bob.switch().entries_from(&alice), 1);
    drop(wallet);
    let env = p.env(&p.alice, Arc::clone(&store) as Arc<dyn StateStore>);
    let mut restored = App::restore(env, protocol.clone(), config(), &backup)
        .await
        .unwrap();
    let kept = restored
        .outbox_record(&msg_id)
        .await
        .expect("its record job");
    assert!(!kept.delivery_owed());
    assert!(matches!(
        restored.delivery(&msg_id).await.unwrap(),
        Some(Delivery::Accepted { .. })
    ));
    let pending = crate::app::tests::pending_events(&mut restored)
        .await
        .unwrap();
    assert!(held_at_restore(&pending).is_empty());
    assert!(undelivered(&pending, &msg_id).is_empty());
    assert_eq!(unknown(&pending, &msg_id), 0);
    restored.flush_outbox().await.unwrap();
    p.alice.switch().lock().faults.clear();
    p.clock.advance_ms(10 * MINUTE);
    restored.flush_outbox().await.unwrap();
    assert!(
        restored.outbox_record(&msg_id).await.is_none(),
        "the job ran"
    );
    assert_eq!(
        p.bob.switch().entries_from(&alice),
        1,
        "not delivered again"
    );
}

/// A restore in place keeps the owed record job of a message only the store queued, whose
/// re-send the store gave up: the job stays, the give-up is told once, as the store told it.
#[tokio::test]
async fn test_backup_outbox_restore_in_place_keeps_the_record_job_of_a_message_queued_since() {
    let p = Pair::new();
    let protocol = ApiProtocol::new(Mode::Plain);
    let (mut wallet, _shop, store) = wallet_on_a_fault_store(&p, &protocol).await;
    let backup = wallet.backup().await.unwrap();
    let signed = wallet.sign_message(Pair::note(&p.bob, "hello")).unwrap();
    let target = RecordTarget::new(items(), &signed.hash());
    let signed = signed.with_record(RecordJob {
        target,
        tag: b"sent".to_vec(),
    });
    let msg_id = wallet.queue_signed(signed).await.unwrap();
    // Accepted, its record job failing for now: the switch's batches can't be sent.
    p.alice.switch().fail_next(Fault::Unreachable {
        path: "ops".into(),
        after: 1,
    });
    for _ in 0..4 {
        p.alice.switch().fail_next(Fault::Unreachable {
            path: "ops".into(),
            after: 0,
        });
    }
    wallet.flush_outbox().await.unwrap();
    // A re-send that can't reach bob, withdrawn: only the re-send is given up.
    p.bob.switch().fail_next(Fault::Unreachable {
        path: "inbox".into(),
        after: 0,
    });
    wallet.resend(&msg_id).await.unwrap();
    assert!(wallet.withdraw_message("sample", &msg_id).await.unwrap());
    drop(wallet);
    let env = p.env(&p.alice, Arc::clone(&store) as Arc<dyn StateStore>);
    let mut restored = App::restore(env, protocol.clone(), config(), &backup)
        .await
        .unwrap();
    let kept = restored
        .outbox_record(&msg_id)
        .await
        .expect("its record job");
    assert!(!kept.delivery_owed());
    let pending = crate::app::tests::pending_events(&mut restored)
        .await
        .unwrap();
    assert_eq!(undelivered(&pending, &msg_id), vec![true]);
    assert!(held_at_restore(&pending).is_empty());
}

/// A restore in place doesn't bring back a record job the store finished since the backup:
/// the store's mark of the accepted message, with no outbox record left, says nothing of it
/// is owed.
#[tokio::test]
async fn test_backup_outbox_restore_in_place_leaves_a_record_job_the_store_finished() {
    let p = Pair::new();
    let protocol = ApiProtocol::new(Mode::Plain);
    let (mut wallet, _shop, store) = wallet_on_a_fault_store(&p, &protocol).await;
    let signed = wallet.sign_message(Pair::note(&p.bob, "hello")).unwrap();
    let target = RecordTarget::new(items(), &signed.hash());
    let signed = signed.with_record(RecordJob {
        target,
        tag: b"sent".to_vec(),
    });
    let msg_id = wallet.queue_signed(signed).await.unwrap();
    // Accepted, its record job failing for now: the switch's batches can't be sent.
    p.alice.switch().fail_next(Fault::Unreachable {
        path: "ops".into(),
        after: 1,
    });
    for _ in 0..4 {
        p.alice.switch().fail_next(Fault::Unreachable {
            path: "ops".into(),
            after: 0,
        });
    }
    wallet.flush_outbox().await.unwrap();
    let backup = wallet.backup().await.unwrap();
    assert!(
        backup
            .outbox
            .iter()
            .any(|item| item.msg_id() == msg_id && !item.delivery_owed()),
        "the backup carries the job"
    );
    p.alice.switch().lock().faults.clear();
    p.clock.advance_ms(10 * MINUTE);
    wallet.flush_outbox().await.unwrap();
    assert!(wallet.outbox_record(&msg_id).await.is_none(), "the job ran");
    drop(wallet);
    let env = p.env(&p.alice, Arc::clone(&store) as Arc<dyn StateStore>);
    let restored = App::restore(env, protocol.clone(), config(), &backup)
        .await
        .unwrap();
    assert!(restored.outbox_record(&msg_id).await.is_none());
}

/// A restore in place from a backup newer than the store keeps the backup's word on a
/// message it carries refused for good: the store's older copy, still owed there, isn't
/// delivered in its place.
#[tokio::test]
async fn test_backup_outbox_restore_in_place_keeps_a_refusal_over_an_older_owed_copy() {
    let p = Pair::new();
    let protocol = ApiProtocol::new(Mode::Plain);
    let (mut wallet, _shop, store) = wallet_on_a_fault_store(&p, &protocol).await;
    let signed = wallet.sign_message(Pair::note(&p.bob, "hello")).unwrap();
    let msg_id = wallet.queue_signed(signed).await.unwrap();
    let older = wallet.backup().await.unwrap();
    drop(wallet);
    // On another device the message is released and refused for good.
    let mut other = restored_wallet(&p, &protocol, &older).await;
    release_held(&mut other, "sample").await;
    p.bob.switch().fail_next(Fault::Error {
        path: "/inbox".into(),
        code: ErrorCode::BadRequest,
        current: Value::Null,
    });
    other.flush_outbox().await.unwrap();
    assert!(matches!(
        other.delivery(&msg_id).await.unwrap(),
        Some(Delivery::Failed { .. })
    ));
    let newer = other.backup().await.unwrap();
    drop(other);
    let newer = AppBackup::from_bytes(&newer.to_bytes().unwrap()).unwrap();
    let env = p.env(&p.alice, Arc::clone(&store) as Arc<dyn StateStore>);
    let mut restored = App::restore(env, protocol.clone(), config(), &newer)
        .await
        .unwrap();
    assert!(matches!(
        restored.delivery(&msg_id).await.unwrap(),
        Some(Delivery::Failed { .. })
    ));
    restored.flush_outbox().await.unwrap();
    assert_eq!(p.bob.switch().entries_from(&p.alice.identity().public()), 0);
}

/// A restore in place isn't stopped by an outbox record of the store it can't take: one
/// that doesn't read or sits under another message's key is left behind, and one the
/// restored app doesn't sign for is dropped, its protocol told.
#[tokio::test]
async fn test_backup_outbox_restore_in_place_leaves_a_record_it_cant_take() {
    let p = Pair::new();
    let protocol = ApiProtocol::new(Mode::Plain);
    let (mut wallet, _shop, store) = wallet_on_a_fault_store(&p, &protocol).await;
    let backup = wallet.backup().await.unwrap();
    let good = wallet.queue(Pair::note(&p.bob, "good")).await.unwrap();
    let altered = wallet.queue(Pair::note(&p.bob, "altered")).await.unwrap();
    let carrying = wallet.backup().await.unwrap();
    let mut record: Value = wallet
        .reader()
        .get(&format!("out/{altered}"))
        .await
        .unwrap()
        .unwrap();
    record["kind"] = json!("sample.other");
    let copy: Value = wallet
        .reader()
        .get(&format!("out/{good}"))
        .await
        .unwrap()
        .unwrap();
    let mut tx = wallet.tx().unwrap();
    tx.put(&format!("out/{altered}"), &record).unwrap();
    tx.put("out/elsewhere", &copy).unwrap();
    tx.put_raw("out/unreadable", b"{".to_vec()).unwrap();
    wallet.commit(tx).await.unwrap();
    drop(wallet);
    let env = p.env(&p.alice, Arc::clone(&store) as Arc<dyn StateStore>);
    let mut restored = App::restore(env, protocol.clone(), config(), &backup)
        .await
        .unwrap();
    let events = restored.take_events();
    assert_eq!(held_at_restore(&events), vec![1]);
    assert_eq!(
        restored.held_messages("sample").await.unwrap(),
        vec![good.clone()]
    );
    assert_eq!(undelivered(&events, &altered), vec![false]);
    let outbox = restored.reader().scan_raw("out/").await.unwrap();
    assert_eq!(outbox.len(), 1, "only the record it can take");
    // The give-up it told leaves its mark: a later restore of a backup that carries the
    // message owed neither holds nor delivers it.
    let marked: Option<u64> = restored
        .reader()
        .get(&format!("outgone/{altered}"))
        .await
        .unwrap();
    assert!(marked.is_some());
    drop(restored);
    let env = p.env(&p.alice, Arc::clone(&store) as Arc<dyn StateStore>);
    let again = App::restore(env, protocol.clone(), config(), &carrying)
        .await
        .unwrap();
    assert_eq!(again.held_messages("sample").await.unwrap(), vec![good]);
    assert!(again.outbox_record(&altered).await.is_none());
}

/// Alice's wallet on a store, a note to bob with a record job accepted there while the job
/// can't be written, bob's shop, the store, and the note's ID.
async fn wallet_with_an_accepted_note_owed_its_record(
    p: &Pair,
    protocol: &Arc<ApiProtocol>,
) -> (App, App, Arc<FaultStore>, String) {
    let (mut wallet, shop, store) = wallet_on_a_fault_store(p, protocol).await;
    let signed = wallet.sign_message(Pair::note(&p.bob, "hello")).unwrap();
    let target = RecordTarget::new(items(), &signed.hash());
    let signed = signed.with_record(RecordJob {
        target,
        tag: b"sent".to_vec(),
    });
    let msg_id = wallet.queue_signed(signed).await.unwrap();
    // Accepted, its record job failing for now: the switch's batches can't be sent.
    p.alice.switch().fail_next(Fault::Unreachable {
        path: "ops".into(),
        after: 1,
    });
    for _ in 0..4 {
        p.alice.switch().fail_next(Fault::Unreachable {
            path: "ops".into(),
            after: 0,
        });
    }
    wallet.flush_outbox().await.unwrap();
    assert!(!wallet.outbox_record(&msg_id).await.unwrap().delivery_owed());
    (wallet, shop, store, msg_id)
}

/// Ask `wallet` to send `msg_id` again while bob can't be reached: the re-send stays owed.
async fn resend_left_owed(p: &Pair, wallet: &mut App, msg_id: &str) {
    p.bob.switch().fail_next(Fault::Unreachable {
        path: "inbox".into(),
        after: 0,
    });
    wallet.resend(msg_id).await.unwrap();
    let listed = wallet.queued_messages("sample").await.unwrap();
    assert!(
        listed.iter().any(|q| q.msg_id == msg_id && q.resend),
        "the re-send is owed"
    );
}

/// A re-send the store queued after the backup, of a message the backup carries accepted,
/// doesn't vanish in a restore in place: it stays a re-send, held, its protocol told.
#[tokio::test]
async fn test_backup_outbox_restore_in_place_holds_a_resend_queued_since() {
    let p = Pair::new();
    let protocol = ApiProtocol::new(Mode::Plain);
    let (mut wallet, _shop, store, msg_id) =
        wallet_with_an_accepted_note_owed_its_record(&p, &protocol).await;
    let backup = wallet.backup().await.unwrap();
    resend_left_owed(&p, &mut wallet, &msg_id).await;
    drop(wallet);
    let env = p.env(&p.alice, Arc::clone(&store) as Arc<dyn StateStore>);
    let mut restored = App::restore(env, protocol.clone(), config(), &backup)
        .await
        .unwrap();
    assert_eq!(held_at_restore(&restored.take_events()), vec![1]);
    let listed = restored.queued_messages("sample").await.unwrap();
    assert_eq!(listed.len(), 1);
    assert_eq!(
        (listed[0].msg_id.as_str(), listed[0].resend, listed[0].held),
        (msg_id.as_str(), true, true)
    );
    let alice = p.alice.identity().public();
    let before = p.bob.switch().entries_from(&alice);
    restored.flush_outbox().await.unwrap();
    assert_eq!(p.bob.switch().entries_from(&alice), before, "held");
    release_held(&mut restored, "sample").await;
    restored.flush_outbox().await.unwrap();
    assert!(
        restored.queued_messages("sample").await.unwrap().is_empty(),
        "the re-send went once released"
    );
}

/// A message accepted since the backup, whose re-send the store still owes, is never put
/// back as a first delivery by a restore in place: the store's record stays, a re-send,
/// its sent copy with it, and goes on.
#[tokio::test]
async fn test_backup_outbox_restore_in_place_keeps_a_resend_of_a_message_accepted_since() {
    let p = Pair::new();
    let protocol = ApiProtocol::new(Mode::Plain);
    let (mut wallet, _shop, store) = wallet_on_a_fault_store(&p, &protocol).await;
    let msg_id = wallet.queue(Pair::note(&p.bob, "hello")).await.unwrap();
    let backup = wallet.backup().await.unwrap();
    let report = wallet.flush_outbox().await.unwrap();
    assert_eq!(report.done, vec![msg_id.clone()]);
    resend_left_owed(&p, &mut wallet, &msg_id).await;
    drop(wallet);
    let env = p.env(&p.alice, Arc::clone(&store) as Arc<dyn StateStore>);
    let mut restored = App::restore(env, protocol.clone(), config(), &backup)
        .await
        .unwrap();
    assert!(held_at_restore(&restored.take_events()).is_empty());
    let listed = restored.queued_messages("sample").await.unwrap();
    assert_eq!(listed.len(), 1);
    assert_eq!(
        (listed[0].msg_id.as_str(), listed[0].resend, listed[0].held),
        (msg_id.as_str(), true, false),
        "still a re-send, not a first delivery"
    );
    let bob = p.bob.identity().public();
    assert_eq!(
        restored.sent_to(&bob, 0, u64::MAX).await.unwrap().len(),
        1,
        "its sent copy stays"
    );
    // Given up, it is told as a re-send: the first acceptance stands.
    assert!(restored.withdraw_message("sample", &msg_id).await.unwrap());
    let events = restored.take_events();
    assert_eq!(undelivered(&events, &msg_id), vec![true]);
    assert_eq!(unknown(&events, &msg_id), 0);
}

/// A message accepted since the backup, with nothing left owed, stays so through any two
/// restores in place, from a backup that carries it owed and one that carries it accepted
/// with its record job, in either order: the store's sent copy outlives each restore, so
/// the message is neither delivered, held nor told again, nor its finished job run again.
#[tokio::test]
async fn test_backup_outbox_restore_in_place_twice_leaves_an_accepted_message() {
    for order in [[0, 0], [0, 1], [1, 0], [1, 1]] {
        let p = Pair::new();
        let protocol = ApiProtocol::new(Mode::Plain);
        let (mut wallet, _shop, store) = wallet_on_a_fault_store(&p, &protocol).await;
        let signed = wallet.sign_message(Pair::note(&p.bob, "hello")).unwrap();
        let target = RecordTarget::new(items(), &signed.hash());
        let signed = signed.with_record(RecordJob {
            target,
            tag: b"sent".to_vec(),
        });
        let msg_id = wallet.queue_signed(signed).await.unwrap();
        let owed = wallet.backup().await.unwrap();
        p.alice.switch().fail_next(Fault::Unreachable {
            path: "ops".into(),
            after: 1,
        });
        for _ in 0..4 {
            p.alice.switch().fail_next(Fault::Unreachable {
                path: "ops".into(),
                after: 0,
            });
        }
        wallet.flush_outbox().await.unwrap();
        let accepted = wallet.backup().await.unwrap();
        p.alice.switch().lock().faults.clear();
        p.clock.advance_ms(10 * MINUTE);
        wallet.flush_outbox().await.unwrap();
        assert!(wallet.outbox_record(&msg_id).await.is_none(), "the job ran");
        drop(wallet);
        let backups = [&owed, &accepted];
        let alice = p.alice.identity().public();
        let bob = p.bob.identity().public();
        for which in order {
            let env = p.env(&p.alice, Arc::clone(&store) as Arc<dyn StateStore>);
            let mut restored = App::restore(env, protocol.clone(), config(), backups[which])
                .await
                .unwrap();
            assert!(restored.outbox_record(&msg_id).await.is_none(), "{order:?}");
            let pending = crate::app::tests::pending_events(&mut restored)
                .await
                .unwrap();
            assert!(held_at_restore(&pending).is_empty(), "{order:?}");
            assert!(
                restored.held_messages("sample").await.unwrap().is_empty(),
                "{order:?}"
            );
            assert_eq!(
                restored.sent_to(&bob, 0, u64::MAX).await.unwrap().len(),
                1,
                "{order:?}"
            );
            restored.flush_outbox().await.unwrap();
            assert_eq!(p.bob.switch().entries_from(&alice), 1, "{order:?}");
        }
    }
}

/// A restore in place gives the store's record of a message both still owed the earliest
/// replay deadline: here the backup's copy, restored and backed up again on another store,
/// carries an earlier one than the store's record or the backup's time give.
#[tokio::test]
async fn test_backup_outbox_restore_in_place_keeps_the_earliest_deadline_of_both_copies() {
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
    let msg_id = wallet.queue(Pair::note(&p.bob, "hello")).await.unwrap();
    let first = wallet.backup().await.unwrap();
    drop(wallet);
    let other = restored_wallet(&p, &protocol, &first).await;
    let earliest = other
        .outbox_record(&msg_id)
        .await
        .unwrap()
        .replay_until_ms()
        .expect("the restore's deadline");
    p.clock.advance_ms(60 * MINUTE);
    let second = other.backup().await.unwrap();
    drop(other);
    let second = AppBackup::from_bytes(&second.to_bytes().unwrap()).unwrap();
    let env = p.env(&p.alice, Arc::clone(&store) as Arc<dyn StateStore>);
    let restored = App::restore(env, protocol.clone(), config(), &second)
        .await
        .unwrap();
    assert_eq!(
        restored
            .outbox_record(&msg_id)
            .await
            .unwrap()
            .replay_until_ms(),
        Some(earliest)
    );
}

/// The restore's hold and its duty event are in its one commit: an app loaded after a
/// crash right after it still holds the message and tells the duty again; a second restore
/// over that store keeps it held.
#[tokio::test]
async fn test_backup_outbox_restore_hold_survives_a_crash_and_a_second_restore() {
    let p = Pair::new();
    let protocol = ApiProtocol::new(Mode::Plain);
    let (wallet, mut shop, signed) = wallet_with_a_queued_note(&p, &protocol).await;
    let msg_id = signed.msg_id().to_owned();
    let backup = wallet.backup().await.unwrap();
    let backup = AppBackup::from_bytes(&backup.to_bytes().unwrap()).unwrap();
    drop(wallet);
    shop.invite(&p.alice.identity().public()).await.unwrap();
    let store = Arc::new(MemoryStore::new());
    let env = p.env(&p.alice, Arc::clone(&store) as Arc<dyn StateStore>);
    let restored = App::restore(env, protocol.clone(), config(), &backup)
        .await
        .unwrap();
    let id = restored.app_id();
    drop(restored);
    let env = p.env(&p.alice, Arc::clone(&store) as Arc<dyn StateStore>);
    let mut loaded = App::load(env, protocol.clone(), config(), id)
        .await
        .unwrap();
    let pending = crate::app::tests::pending_events(&mut loaded)
        .await
        .unwrap();
    assert_eq!(held_at_restore(&pending), vec![1]);
    assert_eq!(
        loaded.held_messages("sample").await.unwrap(),
        vec![msg_id.clone()]
    );
    drop(loaded);
    let env = p.env(&p.alice, Arc::clone(&store) as Arc<dyn StateStore>);
    let mut again = App::restore(env, protocol.clone(), config(), &backup)
        .await
        .unwrap();
    assert_eq!(again.held_messages("sample").await.unwrap(), vec![msg_id]);
    // The store already held it: the second restore counts nothing new, and the first
    // one's event, not acknowledged, is still owed once.
    let pending = crate::app::tests::pending_events(&mut again).await.unwrap();
    assert_eq!(held_at_restore(&pending), vec![1]);
    again.flush_outbox().await.unwrap();
    assert_eq!(p.bob.switch().entries_from(&p.alice.identity().public()), 0);
}

/// A restore in place of a backup that tells a message's give-up ends the delivery the
/// store still owed: the message is neither held nor queued, and its give-up is told once.
#[tokio::test]
async fn test_backup_outbox_restore_in_place_ends_a_delivery_its_backup_gave_up() {
    let p = Pair::new();
    let protocol = ApiProtocol::new(Mode::Plain);
    let (mut wallet, _shop, signed) = wallet_with_a_queued_note(&p, &protocol).await;
    let msg_id = signed.msg_id().to_owned();
    let owed = wallet.backup().await.unwrap();
    assert!(wallet.withdraw_message("sample", &msg_id).await.unwrap());
    let given_up = wallet.backup().await.unwrap();
    let given_up = AppBackup::from_bytes(&given_up.to_bytes().unwrap()).unwrap();
    drop(wallet);
    // A store that still owes the delivery: the earlier backup, restored onto it.
    let store = Arc::new(MemoryStore::new());
    let env = p.env(&p.alice, Arc::clone(&store) as Arc<dyn StateStore>);
    let earlier = App::restore(env, protocol.clone(), config(), &owed)
        .await
        .unwrap();
    assert_eq!(
        earlier.held_messages("sample").await.unwrap(),
        vec![msg_id.clone()]
    );
    drop(earlier);
    let env = p.env(&p.alice, Arc::clone(&store) as Arc<dyn StateStore>);
    let mut restored = App::restore(env, protocol.clone(), config(), &given_up)
        .await
        .unwrap();
    assert_eq!(restored.delivery(&msg_id).await.unwrap(), None);
    assert!(restored.held_messages("sample").await.unwrap().is_empty());
    let pending = crate::app::tests::pending_events(&mut restored)
        .await
        .unwrap();
    assert_eq!(
        undelivered(&pending, &msg_id).len() + unknown(&pending, &msg_id),
        1
    );
    restored.flush_outbox().await.unwrap();
    assert_eq!(p.bob.switch().entries_from(&p.alice.identity().public()), 0);
}

/// A restore in place of a backup that left messages out past its budget keeps each as the
/// store has it, held, and tells no give-up of it: the store still holds the message.
#[tokio::test]
async fn test_backup_outbox_restore_in_place_keeps_a_message_its_backup_left_out() {
    let p = Pair::new();
    let protocol = ApiProtocol::new(Mode::Plain);
    let (wallet, store, _before, queued) = wallet_with_queued_notes(&p, &protocol, 260).await;
    let backup = wallet.backup().await.unwrap();
    let left_out: Vec<String> = backup
        .outbox_left_out
        .iter()
        .map(|(msg_id, _)| msg_id.clone())
        .collect();
    assert!(!left_out.is_empty() && left_out.len() < queued.len());
    drop(wallet);
    let env = p.env(&p.alice, Arc::clone(&store) as Arc<dyn StateStore>);
    let mut restored = App::restore(env, protocol.clone(), config(), &backup)
        .await
        .unwrap();
    let events = restored.take_events();
    for msg_id in &left_out {
        assert!(matches!(
            restored.delivery(msg_id).await.unwrap(),
            Some(Delivery::Queued { .. })
        ));
        assert_eq!(unknown(&events, msg_id), 0);
        assert!(undelivered(&events, msg_id).is_empty());
    }
    // Those the backup carries go on; only the ones it left out are held.
    assert_eq!(held_at_restore(&events), vec![left_out.len() as u64]);
    let mut held = restored.held_messages("sample").await.unwrap();
    held.sort();
    let mut expected = left_out.clone();
    expected.sort();
    assert_eq!(held, expected);
}

/// The reply grants for `pubky` among the operations `switch` applied: those added and
/// those removed.
fn reply_grants_for(switch: &ScriptedSwitch, pubky: [u8; 32]) -> (usize, usize) {
    use pubky_switch_core::admission::PeerReason;
    let applied = switch.applied();
    let count = |added: bool| {
        applied
            .iter()
            .filter(|op| match op.body().kind {
                OpKind::AllowPut {
                    pubky: who,
                    reason: PeerReason::Reply,
                } => added && who == pubky,
                OpKind::AllowDelete {
                    pubky: who,
                    reason: PeerReason::Reply,
                } => !added && who == pubky,
                _ => false,
            })
            .count()
    };
    (count(true), count(false))
}

/// Alice's wallet restored onto `store` from a backup carrying one note to bob that was
/// never tried, so its reply grant is still owed: the restored wallet, which holds the
/// note, bob's shop, and the note's ID. Bob admits alice when `admitted`.
async fn restored_with_a_held_note(
    p: &Pair,
    protocol: &Arc<ApiProtocol>,
    store: &Arc<MemoryStore>,
    admitted: bool,
) -> (App, App, String) {
    let mut wallet = p.join(&p.alice, "wallet", protocol).await;
    let mut shop = p.join(&p.bob, "shop", protocol).await;
    if admitted {
        shop.invite(&p.alice.identity().public()).await.unwrap();
    }
    let signed = wallet.sign_message(Pair::note(&p.bob, "hello")).unwrap();
    let msg_id = wallet.queue_signed(signed).await.unwrap();
    let backup = wallet.backup().await.unwrap();
    let backup = AppBackup::from_bytes(&backup.to_bytes().unwrap()).unwrap();
    drop(wallet);
    let env = p.env(&p.alice, Arc::clone(store) as Arc<dyn StateStore>);
    let restored = App::restore(env, protocol.clone(), config(), &backup)
        .await
        .unwrap();
    assert_eq!(
        restored.held_messages("sample").await.unwrap(),
        vec![msg_id.clone()]
    );
    (restored, shop, msg_id)
}

/// A message a restore held, released with its reply grant if owed, is delivered with the
/// grant its protocol says it adds, as a message never held.
#[tokio::test]
async fn test_release_message_if_owed_writes_its_reply_grant() {
    let p = Pair::new();
    let protocol = ApiProtocol::new(Mode::Plain);
    let store = Arc::new(MemoryStore::new());
    let (mut restored, _shop, msg_id) =
        restored_with_a_held_note(&p, &protocol, &store, true).await;
    let (alice, bob) = (p.alice.identity().public(), p.bob.identity().public());
    restored
        .release_message("sample", &msg_id, ReplyGrantOnRelease::IfOwed)
        .await
        .unwrap();
    restored.flush_outbox().await.unwrap();
    assert_eq!(p.bob.switch().entries_from(&alice), 1, "delivered");
    assert_eq!(reply_grants_for(p.alice.switch(), bob), (1, 0));
}

/// A message a restore held, released with its reply grant withheld, is delivered at its
/// first try with no entry written for its recipient (Switch spec 12.4).
#[tokio::test]
async fn test_release_message_withheld_delivers_without_a_reply_grant() {
    let p = Pair::new();
    let protocol = ApiProtocol::new(Mode::Plain);
    let store = Arc::new(MemoryStore::new());
    let (mut restored, _shop, msg_id) =
        restored_with_a_held_note(&p, &protocol, &store, true).await;
    let (alice, bob) = (p.alice.identity().public(), p.bob.identity().public());
    restored
        .release_message("sample", &msg_id, ReplyGrantOnRelease::Withheld)
        .await
        .unwrap();
    restored.flush_outbox().await.unwrap();
    assert_eq!(p.bob.switch().entries_from(&alice), 1, "delivered");
    assert_eq!(reply_grants_for(p.alice.switch(), bob), (0, 0));
}

/// A withheld reply grant stays withheld through a failed try and its retry, and through
/// a later release that asks for the grant if owed.
#[tokio::test]
async fn test_release_message_withheld_stays_so_through_a_failed_try() {
    let p = Pair::new();
    let protocol = ApiProtocol::new(Mode::Plain);
    let store = Arc::new(MemoryStore::new());
    let (mut restored, mut shop, msg_id) =
        restored_with_a_held_note(&p, &protocol, &store, false).await;
    let (alice, bob) = (p.alice.identity().public(), p.bob.identity().public());
    restored
        .release_message("sample", &msg_id, ReplyGrantOnRelease::Withheld)
        .await
        .unwrap();
    let delivery = restored.flush_message(&msg_id).await.unwrap().unwrap();
    assert!(queued_with(&delivery, "not_admitted"), "{delivery:?}");
    assert_eq!(reply_grants_for(p.alice.switch(), bob), (0, 0));
    // Held and released again, the grant asked for if owed this time: it stays withheld.
    assert!(restored.hold_message("sample", &msg_id).await.unwrap());
    restored
        .release_message("sample", &msg_id, ReplyGrantOnRelease::IfOwed)
        .await
        .unwrap();
    shop.invite(&alice).await.unwrap();
    p.clock.advance_ms(crate::app::UNDELIVERABLE_TRY_SPACING_MS);
    restored.flush_outbox().await.unwrap();
    assert_eq!(p.bob.switch().entries_from(&alice), 1, "delivered");
    assert_eq!(reply_grants_for(p.alice.switch(), bob), (0, 0));
}

/// A withheld reply grant is in the release's commit: an app loaded between the release
/// and the delivery still writes none. Nor does a restore in place from a backup that
/// carries the message with its grant owed: the store's record goes on, not the backup's.
#[tokio::test]
async fn test_release_message_withheld_survives_a_reload_and_a_restore_in_place() {
    let p = Pair::new();
    let protocol = ApiProtocol::new(Mode::Plain);
    let store = Arc::new(MemoryStore::new());
    let (mut restored, _shop, msg_id) =
        restored_with_a_held_note(&p, &protocol, &store, true).await;
    let (alice, bob) = (p.alice.identity().public(), p.bob.identity().public());
    // A backup of the message held, its reply grant still owed.
    let backup = restored.backup().await.unwrap();
    restored
        .release_message("sample", &msg_id, ReplyGrantOnRelease::Withheld)
        .await
        .unwrap();
    let id = restored.app_id();
    drop(restored);
    let env = p.env(&p.alice, Arc::clone(&store) as Arc<dyn StateStore>);
    let loaded = App::load(env, protocol.clone(), config(), id)
        .await
        .unwrap();
    assert!(loaded.held_messages("sample").await.unwrap().is_empty());
    drop(loaded);
    // Both the store and the backup owe the delivery: the store's record goes on, under
    // the hold the backup carries.
    let env = p.env(&p.alice, Arc::clone(&store) as Arc<dyn StateStore>);
    let mut again = App::restore(env, protocol.clone(), config(), &backup)
        .await
        .unwrap();
    assert_eq!(
        again.held_messages("sample").await.unwrap(),
        vec![msg_id.clone()]
    );
    again
        .release_message("sample", &msg_id, ReplyGrantOnRelease::IfOwed)
        .await
        .unwrap();
    again.flush_outbox().await.unwrap();
    assert_eq!(p.bob.switch().entries_from(&alice), 1, "delivered");
    assert_eq!(reply_grants_for(p.alice.switch(), bob), (0, 0));
}

/// A withheld reply grant leaves the grant the recipient already holds as it is: a restore
/// brought its row back unverified, and the delivery neither writes it again nor removes
/// it.
#[tokio::test]
async fn test_release_message_withheld_leaves_an_existing_reply_grant() {
    let p = Pair::new();
    let protocol = ApiProtocol::new(Mode::Plain);
    let mut wallet = p.join(&p.alice, "wallet", &protocol).await;
    let mut shop = p.join(&p.bob, "shop", &protocol).await;
    let (alice, bob) = (p.alice.identity().public(), p.bob.identity().public());
    shop.invite(&alice).await.unwrap();
    wallet.invite(&bob).await.unwrap();
    assert_eq!(reply_grants_for(p.alice.switch(), bob), (1, 0));
    let backup = wallet.backup().await.unwrap();
    drop(wallet);
    for (choice, added) in [
        (ReplyGrantOnRelease::Withheld, 1),
        (ReplyGrantOnRelease::IfOwed, 2),
    ] {
        let mut restored = restored_wallet(&p, &protocol, &backup).await;
        let signed = restored.sign_message(Pair::note(&p.bob, "hello")).unwrap();
        let msg_id = restored.queue_signed(signed).await.unwrap();
        assert!(restored.hold_message("sample", &msg_id).await.unwrap());
        restored
            .release_message("sample", &msg_id, choice)
            .await
            .unwrap();
        restored.flush_outbox().await.unwrap();
        assert!(matches!(
            restored.delivery(&msg_id).await.unwrap(),
            Some(Delivery::Accepted { .. })
        ));
        // Written again only if owed is asked: the restored row isn't verified.
        assert_eq!(
            reply_grants_for(p.alice.switch(), bob),
            (added, 0),
            "{choice:?}"
        );
    }
}

/// A withheld reply grant holds for the copy a kept batch puts in the outbox once it
/// settles.
#[tokio::test]
async fn test_release_message_withheld_holds_for_a_kept_batchs_copy() {
    let p = Pair::new();
    let protocol = ApiProtocol::new(Mode::Plain);
    let mut wallet = p.join(&p.alice, "wallet", &protocol).await;
    let mut shop = p.join(&p.bob, "shop", &protocol).await;
    let (alice, bob) = (p.alice.identity().public(), p.bob.identity().public());
    shop.invite(&alice).await.unwrap();
    let signed = wallet.sign_message(Pair::note(&p.bob, "hello")).unwrap();
    kept_with(&p, &mut wallet, &signed).await;
    assert!(
        wallet
            .hold_message("sample", signed.msg_id())
            .await
            .unwrap()
    );
    wallet
        .release_message("sample", signed.msg_id(), ReplyGrantOnRelease::Withheld)
        .await
        .unwrap();
    wallet.receive(None).await.unwrap();
    wallet.flush_outbox().await.unwrap();
    assert_eq!(p.bob.switch().entries_from(&alice), 1, "delivered");
    assert_eq!(reply_grants_for(p.alice.switch(), bob), (0, 0));
}

/// A reply grant withheld on a kept batch's copy of a message stays withheld when the
/// message is queued again before the batch settles, from its signed copy or its stored
/// plaintext: the choice holds for the message, whichever path queues it next.
#[tokio::test]
async fn test_release_message_withheld_holds_for_a_copy_queued_before_the_batch_settles() {
    for signed_again in [false, true] {
        let p = Pair::new();
        let protocol = ApiProtocol::new(Mode::Plain);
        let mut wallet = p.join(&p.alice, "wallet", &protocol).await;
        let mut shop = p.join(&p.bob, "shop", &protocol).await;
        let (alice, bob) = (p.alice.identity().public(), p.bob.identity().public());
        shop.invite(&alice).await.unwrap();
        let signed = wallet.sign_message(Pair::note(&p.bob, "hello")).unwrap();
        kept_with(&p, &mut wallet, &signed).await;
        assert!(
            wallet
                .hold_message("sample", signed.msg_id())
                .await
                .unwrap()
        );
        wallet
            .release_message("sample", signed.msg_id(), ReplyGrantOnRelease::Withheld)
            .await
            .unwrap();
        if signed_again {
            wallet.queue_signed(signed.clone()).await.unwrap();
        } else {
            wallet.queue_stored(signed.plaintext()).await.unwrap();
        }
        wallet.flush_outbox().await.unwrap();
        wallet.receive(None).await.unwrap();
        wallet.flush_outbox().await.unwrap();
        assert_eq!(p.bob.switch().entries_from(&alice), 1, "delivered");
        assert_eq!(
            reply_grants_for(p.alice.switch(), bob),
            (0, 0),
            "queued from its signed copy: {signed_again}"
        );
    }
}

/// Alice's wallet with a note to bob accepted and its re-send left owed, and two backups
/// of it: one taken while the first delivery was owed, an hour before it was accepted,
/// and one taken with the re-send owed. Returns them with the note's ID.
async fn backups_before_and_after_a_resend(
    p: &Pair,
    protocol: &Arc<ApiProtocol>,
) -> (AppBackup, AppBackup, String) {
    let (mut wallet, _shop, _store) = wallet_on_a_fault_store(p, protocol).await;
    let msg_id = wallet.queue(Pair::note(&p.bob, "hello")).await.unwrap();
    let older = wallet.backup().await.unwrap();
    p.clock.advance_ms(60 * MINUTE);
    let report = wallet.flush_outbox().await.unwrap();
    assert_eq!(report.done, vec![msg_id.clone()]);
    resend_left_owed(p, &mut wallet, &msg_id).await;
    let newer = wallet.backup().await.unwrap();
    (older, newer, msg_id)
}

/// A restore of a newer backup, which carries a message's re-send, over a store that
/// still owes its first delivery never moves the replay deadline later: the re-send goes
/// back by the store's earlier deadline, under the store's hold.
#[tokio::test]
async fn test_backup_outbox_restore_of_a_newer_backup_keeps_the_stores_earlier_deadline() {
    let p = Pair::new();
    let protocol = ApiProtocol::new(Mode::Plain);
    let (older, newer, msg_id) = backups_before_and_after_a_resend(&p, &protocol).await;
    let store = Arc::new(MemoryStore::new());
    let env = p.env(&p.alice, Arc::clone(&store) as Arc<dyn StateStore>);
    let first = App::restore(env, protocol.clone(), config(), &older)
        .await
        .unwrap();
    let until = first
        .outbox_record(&msg_id)
        .await
        .unwrap()
        .replay_until_ms()
        .unwrap();
    drop(first);
    let env = p.env(&p.alice, Arc::clone(&store) as Arc<dyn StateStore>);
    let restored = App::restore(env, protocol.clone(), config(), &newer)
        .await
        .unwrap();
    let listed = restored.queued_messages("sample").await.unwrap();
    assert_eq!(listed.len(), 1);
    assert_eq!(
        (listed[0].msg_id.as_str(), listed[0].resend, listed[0].held),
        (msg_id.as_str(), true, true),
        "the backup's re-send, under the store's hold"
    );
    assert_eq!(
        restored
            .outbox_record(&msg_id)
            .await
            .unwrap()
            .replay_until_ms(),
        Some(until)
    );
    // The backup's own deadline is the later one.
    let alone = restored_wallet(&p, &protocol, &newer).await;
    let later = alone
        .outbox_record(&msg_id)
        .await
        .unwrap()
        .replay_until_ms()
        .unwrap();
    assert!(later > until, "{later} {until}");
}

/// A restore of a newer backup, which carries a message's re-send, over a store that
/// accepted the message and never knew the re-send holds it for its protocol: only the
/// backup owes it, so it is neither delivered on the restore's own word nor lost.
#[tokio::test]
async fn test_backup_outbox_restore_of_a_newer_backup_holds_a_resend_the_store_never_knew() {
    let p = Pair::new();
    let protocol = ApiProtocol::new(Mode::Plain);
    let (older, newer, msg_id) = backups_before_and_after_a_resend(&p, &protocol).await;
    let alice = p.alice.identity().public();
    // A store that delivered the message and owes nothing more of it.
    let store = Arc::new(MemoryStore::new());
    let env = p.env(&p.alice, Arc::clone(&store) as Arc<dyn StateStore>);
    let mut first = App::restore(env, protocol.clone(), config(), &older)
        .await
        .unwrap();
    release_held(&mut first, "sample").await;
    first.flush_outbox().await.unwrap();
    assert!(matches!(
        first.delivery(&msg_id).await.unwrap(),
        Some(Delivery::Accepted { .. })
    ));
    assert!(first.queued_messages("sample").await.unwrap().is_empty());
    drop(first);
    let delivered = p.bob.switch().entries_from(&alice);
    let env = p.env(&p.alice, Arc::clone(&store) as Arc<dyn StateStore>);
    let mut restored = App::restore(env, protocol.clone(), config(), &newer)
        .await
        .unwrap();
    let listed = restored.queued_messages("sample").await.unwrap();
    assert_eq!(listed.len(), 1, "the re-send isn't lost");
    assert_eq!(
        (listed[0].msg_id.as_str(), listed[0].resend, listed[0].held),
        (msg_id.as_str(), true, true)
    );
    // Told beside the first restore's notice, which nobody acknowledged.
    let pending = crate::app::tests::pending_events(&mut restored)
        .await
        .unwrap();
    assert_eq!(held_at_restore(&pending), vec![1, 1]);
    restored.flush_outbox().await.unwrap();
    assert_eq!(p.bob.switch().entries_from(&alice), delivered, "held");
}

/// A give-up already told is never undone, whatever the backup carries: a backup that
/// carries a message's re-send owed and the duty event telling it given up, restored over a
/// store that owes the first delivery, ends the delivery. The record stays for the record
/// job the backup's copy knows is owed.
#[tokio::test]
async fn test_backup_outbox_restore_in_place_never_undoes_a_give_up_over_a_resend() {
    let p = Pair::new();
    let protocol = ApiProtocol::new(Mode::Plain);
    let (mut wallet, _shop, _store) = wallet_on_a_fault_store(&p, &protocol).await;
    let alice = p.alice.identity().public();
    let signed = wallet.sign_message(Pair::note(&p.bob, "hello")).unwrap();
    let target = RecordTarget::new(items(), &signed.hash());
    let signed = signed.with_record(RecordJob {
        target,
        tag: b"sent".to_vec(),
    });
    let msg_id = wallet.queue_signed(signed).await.unwrap();
    let older = wallet.backup().await.unwrap();
    // Accepted, its record job failing for now: the switch's batches can't be sent.
    p.alice.switch().fail_next(Fault::Unreachable {
        path: "ops".into(),
        after: 1,
    });
    for _ in 0..4 {
        p.alice.switch().fail_next(Fault::Unreachable {
            path: "ops".into(),
            after: 0,
        });
    }
    wallet.flush_outbox().await.unwrap();
    resend_left_owed(&p, &mut wallet, &msg_id).await;
    let owed: Value =
        serde_json::from_slice(&wallet.backup().await.unwrap().to_bytes().unwrap()).unwrap();
    assert!(wallet.withdraw_message("sample", &msg_id).await.unwrap());
    let told: Value =
        serde_json::from_slice(&wallet.backup().await.unwrap().to_bytes().unwrap()).unwrap();
    drop(wallet);
    // The re-send owed, and its give-up told.
    let mut both = owed.clone();
    both["duties"] = told["duties"].clone();
    let both = AppBackup::from_bytes(&serde_json::to_vec(&both).unwrap()).unwrap();
    // A store that owes the first delivery, released by its protocol.
    let store = Arc::new(MemoryStore::new());
    let env = p.env(&p.alice, Arc::clone(&store) as Arc<dyn StateStore>);
    let mut first = App::restore(env, protocol.clone(), config(), &older)
        .await
        .unwrap();
    release_held(&mut first, "sample").await;
    drop(first);
    let delivered = p.bob.switch().entries_from(&alice);
    let env = p.env(&p.alice, Arc::clone(&store) as Arc<dyn StateStore>);
    let mut restored = App::restore(env, protocol.clone(), config(), &both)
        .await
        .unwrap();
    assert!(restored.queued_messages("sample").await.unwrap().is_empty());
    assert!(restored.held_messages("sample").await.unwrap().is_empty());
    let kept = restored
        .outbox_record(&msg_id)
        .await
        .expect("its record job");
    assert!(!kept.delivery_owed());
    let pending = crate::app::tests::pending_events(&mut restored)
        .await
        .unwrap();
    assert_eq!(undelivered(&pending, &msg_id), vec![true]);
    p.clock.advance_ms(10 * MINUTE);
    restored.flush_outbox().await.unwrap();
    assert_eq!(p.bob.switch().entries_from(&alice), delivered);
}

/// A restore in place keeps what the store knows of a message queued and accepted after
/// the backup was taken, of which the backup carries nothing: its sent copy stays, so its
/// delivery still reads accepted at the same time, `sent_to` still lists it, and queueing
/// its stored plaintext again queues nothing. A protocol that counts what it sent by
/// `sent_to` counts it after the restore too.
#[tokio::test]
async fn test_backup_outbox_restore_in_place_keeps_the_sent_copy_of_a_message_accepted_since() {
    let p = Pair::new();
    let protocol = ApiProtocol::new(Mode::Plain);
    let (mut wallet, _shop, store) = wallet_on_a_fault_store(&p, &protocol).await;
    let (alice, bob) = (p.alice.identity().public(), p.bob.identity().public());
    let backup = wallet.backup().await.unwrap();
    let signed = wallet.sign_message(Pair::note(&p.bob, "hello")).unwrap();
    let msg_id = wallet.queue_signed(signed.clone()).await.unwrap();
    let report = wallet.flush_outbox().await.unwrap();
    assert_eq!(report.done, vec![msg_id.clone()]);
    let accepted = wallet.delivery(&msg_id).await.unwrap();
    assert!(matches!(accepted, Some(Delivery::Accepted { .. })));
    drop(wallet);
    let env = p.env(&p.alice, Arc::clone(&store) as Arc<dyn StateStore>);
    let mut restored = App::restore(env, protocol.clone(), config(), &backup)
        .await
        .unwrap();
    assert_eq!(restored.delivery(&msg_id).await.unwrap(), accepted);
    let sent = restored.sent_to(&bob, 0, u64::MAX).await.unwrap();
    assert_eq!(sent.len(), 1);
    assert_eq!(sent[0].msg_id, msg_id);
    let events = restored.take_events();
    assert!(held_at_restore(&events).is_empty());
    assert!(undelivered(&events, &msg_id).is_empty() && unknown(&events, &msg_id) == 0);
    // Queued again from its stored plaintext, it is known as sent: nothing is queued.
    assert_eq!(
        restored.queue_stored(signed.plaintext()).await.unwrap(),
        msg_id
    );
    assert!(restored.queued_messages("sample").await.unwrap().is_empty());
    restored.flush_outbox().await.unwrap();
    assert_eq!(p.bob.switch().entries_from(&alice), 1, "delivered once");
}

/// A restore in place keeps a give-up of a re-send the store told and its protocol
/// acknowledged: the store's mark says it, so the backup's older copy of the re-send is
/// neither held, delivered nor told again, with the message's record job owed or not.
#[tokio::test]
async fn test_backup_outbox_restore_in_place_keeps_an_acknowledged_give_up_of_a_resend() {
    for with_job in [false, true] {
        let p = Pair::new();
        let protocol = ApiProtocol::new(Mode::Plain);
        let (mut wallet, store, msg_id) = if with_job {
            let (wallet, _shop, store, msg_id) =
                wallet_with_an_accepted_note_owed_its_record(&p, &protocol).await;
            (wallet, store, msg_id)
        } else {
            let (mut wallet, _shop, store) = wallet_on_a_fault_store(&p, &protocol).await;
            let msg_id = wallet.queue(Pair::note(&p.bob, "hello")).await.unwrap();
            let report = wallet.flush_outbox().await.unwrap();
            assert_eq!(report.done, vec![msg_id.clone()]);
            (wallet, store, msg_id)
        };
        resend_left_owed(&p, &mut wallet, &msg_id).await;
        let backup = wallet.backup().await.unwrap();
        assert!(wallet.withdraw_message("sample", &msg_id).await.unwrap());
        let told = wallet.unacknowledged_events().await.unwrap();
        assert_eq!(undelivered(&told, &msg_id), vec![true]);
        wallet
            .ack_events(told.last().unwrap().id().unwrap())
            .await
            .unwrap();
        drop(wallet);
        let alice = p.alice.identity().public();
        let delivered = p.bob.switch().entries_from(&alice);
        let env = p.env(&p.alice, Arc::clone(&store) as Arc<dyn StateStore>);
        let mut restored = App::restore(env, protocol.clone(), config(), &backup)
            .await
            .unwrap();
        assert!(
            restored.queued_messages("sample").await.unwrap().is_empty(),
            "with its record job owed: {with_job}"
        );
        assert!(restored.held_messages("sample").await.unwrap().is_empty());
        let pending = crate::app::tests::pending_events(&mut restored)
            .await
            .unwrap();
        assert!(held_at_restore(&pending).is_empty());
        assert!(undelivered(&pending, &msg_id).is_empty());
        restored.flush_outbox().await.unwrap();
        assert_eq!(p.bob.switch().entries_from(&alice), delivered);
    }
}

/// A restore in place clears the marks of the delivery state it leaves that don't read: a
/// sent copy and its index entry go, a give-up mark is written again with a time, and the
/// restored app works on what is left.
#[tokio::test]
async fn test_backup_outbox_restore_in_place_clears_marks_that_dont_read() {
    let p = Pair::new();
    let protocol = ApiProtocol::new(Mode::Plain);
    let (mut wallet, _shop, store) = wallet_on_a_fault_store(&p, &protocol).await;
    let backup = wallet.backup().await.unwrap();
    let mut tx = wallet.tx().unwrap();
    tx.put_raw("sent/unreadable", b"{".to_vec()).unwrap();
    tx.put_raw("sentt/1/unreadable", b"{".to_vec()).unwrap();
    tx.put_raw("outgone/untimed", b"\"soon\"".to_vec()).unwrap();
    wallet.commit(tx).await.unwrap();
    drop(wallet);
    let env = p.env(&p.alice, Arc::clone(&store) as Arc<dyn StateStore>);
    let mut restored = App::restore(env, protocol.clone(), config(), &backup)
        .await
        .unwrap();
    let reader = restored.reader();
    assert!(reader.scan_raw("sent/").await.unwrap().is_empty());
    assert!(reader.scan_raw("sentt/").await.unwrap().is_empty());
    let until: u64 = reader.get("outgone/untimed").await.unwrap().unwrap();
    assert!(
        until > p.clock.now_ms(),
        "the give-up stays told for its time"
    );
    restored.flush_outbox().await.unwrap();
    let bob = p.bob.identity().public();
    assert!(
        restored
            .sent_to(&bob, 0, u64::MAX)
            .await
            .unwrap()
            .is_empty()
    );
}

/// A restore onto a store that isn't this installation's wipes whatever delivery state it
/// holds with the rest: only a restore in place leaves it.
#[tokio::test]
async fn test_backup_outbox_restore_onto_another_store_wipes_its_delivery_state() {
    let p = Pair::new();
    let protocol = ApiProtocol::new(Mode::Plain);
    let (wallet, _shop, signed) = wallet_with_a_queued_note(&p, &protocol).await;
    let backup = wallet.backup().await.unwrap();
    let backup = AppBackup::from_bytes(&backup.to_bytes().unwrap()).unwrap();
    let store = Arc::new(MemoryStore::new());
    let mut left = crate::store::WriteBatch::new();
    for key in ["out/left", "sent/left", "sentt/1/left", "outgone/left"] {
        left.put(&wallet.ns, key.as_bytes().to_vec(), b"{}".to_vec())
            .unwrap();
    }
    store.commit(left).unwrap();
    drop(wallet);
    let env = p.env(&p.alice, Arc::clone(&store) as Arc<dyn StateStore>);
    let restored = App::restore(env, protocol.clone(), config(), &backup)
        .await
        .unwrap();
    let reader = restored.reader();
    let outbox = reader.scan_raw("out/").await.unwrap();
    assert_eq!(outbox.len(), 1);
    assert_eq!(outbox[0].0, signed.msg_id());
    for prefix in ["sent/", "sentt/", "outgone/"] {
        assert!(
            reader.scan_raw(prefix).await.unwrap().is_empty(),
            "{prefix}"
        );
    }
}

/// A backup listing a held message twice is checked against the copy the restore puts
/// back, the last: one delivered there carries no hold. So is one listing a held message as
/// left out past its budget.
#[tokio::test]
async fn test_hold_message_backup_whose_held_message_is_not_carried_owed_is_refused() {
    let p = Pair::new();
    let protocol = ApiProtocol::new(Mode::Plain);
    let (mut wallet, _shop, signed) = wallet_with_a_queued_note(&p, &protocol).await;
    assert!(
        wallet
            .hold_message("sample", signed.msg_id())
            .await
            .unwrap()
    );
    let bytes = wallet.backup().await.unwrap().to_bytes().unwrap();
    let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    let restore = |value: &serde_json::Value| {
        let backup = AppBackup::from_bytes(&serde_json::to_vec(value).unwrap()).unwrap();
        let env = p.env(&p.alice, Arc::new(MemoryStore::new()));
        let protocol = protocol.clone();
        async move { App::restore(env, protocol, config(), &backup).await }
    };
    assert!(restore(&value).await.is_ok(), "as taken, it restores");
    // Twice, the last copy accepted already.
    let mut twice = value.clone();
    let mut accepted = twice["outbox"][0].clone();
    accepted["accepted_at_ms"] = json!(START);
    twice["outbox"].as_array_mut().unwrap().push(accepted);
    let error = restore(&twice).await.unwrap_err();
    assert!(matches!(error, AppError::InvalidData(_)), "{error:?}");
    // Carried and named as left out.
    let mut left = value.clone();
    left["outbox_left_out"] = json!([[signed.msg_id(), false]]);
    let error = restore(&left).await.unwrap_err();
    assert!(matches!(error, AppError::InvalidData(_)), "{error:?}");
}

/// A held message of a kind no registered protocol owns, as a restore with another set of
/// protocols brings back, is any protocol's to list and release.
#[tokio::test]
async fn test_hold_message_of_a_kind_no_protocol_owns_is_any_protocols() {
    delivery_lifecycle::orphaned_kind().await;
}

/// The per-message calls name a registered protocol.
#[tokio::test]
async fn test_hold_message_of_an_unregistered_protocol_is_refused() {
    let p = Pair::new();
    let protocol = ApiProtocol::new(Mode::Plain);
    let mut wallet = p.join(&p.alice, "wallet", &protocol).await;
    let signed = wallet.sign_message(Pair::note(&p.bob, "hello")).unwrap();
    wallet.queue_signed(signed.clone()).await.unwrap();
    let error = wallet
        .hold_message("other", signed.msg_id())
        .await
        .unwrap_err();
    assert!(
        matches!(error, AppError::Refused(Refusal::Usage(_))),
        "{error:?}"
    );
    assert!(wallet.held_messages("other").await.is_err());
    assert!(
        wallet
            .hold_message("sample", signed.msg_id())
            .await
            .unwrap()
    );
    assert!(
        wallet
            .withdraw_message("other", signed.msg_id())
            .await
            .is_err()
    );
    assert_eq!(
        wallet.held_messages("sample").await.unwrap(),
        vec![signed.msg_id().to_owned()]
    );
}

/// Withdrawing one message gives it up, told once, and never queued again, while another
/// to the same counterparty still goes; its hold ends with it.
#[tokio::test]
async fn test_withdraw_message_gives_up_one_message() {
    let p = Pair::new();
    let protocol = ApiProtocol::new(Mode::Plain);
    let mut wallet = p.join(&p.alice, "wallet", &protocol).await;
    let mut shop = p.join(&p.bob, "shop", &protocol).await;
    let alice = p.alice.identity().public();
    let gone = wallet.sign_message(Pair::note(&p.bob, "gone")).unwrap();
    wallet.queue_signed(gone.clone()).await.unwrap();
    let other = wallet.sign_message(Pair::note(&p.bob, "other")).unwrap();
    wallet.queue_signed(other.clone()).await.unwrap();
    assert!(wallet.hold_message("sample", gone.msg_id()).await.unwrap());
    wallet.take_events();
    assert!(
        wallet
            .withdraw_message("sample", gone.msg_id())
            .await
            .unwrap()
    );
    assert_eq!(
        undelivered(&wallet.take_events(), gone.msg_id()),
        vec![false]
    );
    assert!(wallet.held_messages("sample").await.unwrap().is_empty());
    assert!(
        !wallet
            .withdraw_message("sample", gone.msg_id())
            .await
            .unwrap(),
        "once"
    );
    assert!(wallet.take_events().is_empty());
    shop.invite(&alice).await.unwrap();
    let report = wallet.flush_outbox().await.unwrap();
    assert_eq!(report.done, vec![other.msg_id().to_owned()]);
    assert_eq!(p.bob.switch().entries_from(&alice), 1);
    let error = wallet.queue_stored(gone.plaintext()).await.unwrap_err();
    assert!(
        matches!(
            error,
            AppError::Refused(Refusal::WontDeliver(WontDeliver::GivenUp))
        ),
        "{error:?}"
    );
}

/// Withdrawing a message a kept batch would queue: once the batch settles its other
/// operation is applied and the message isn't queued.
#[tokio::test]
async fn test_withdraw_message_gives_up_a_kept_batch_message() {
    let p = Pair::new();
    let protocol = ApiProtocol::new(Mode::Plain);
    let mut wallet = p.join(&p.alice, "wallet", &protocol).await;
    let mut shop = p.join(&p.bob, "shop", &protocol).await;
    let alice = p.alice.identity().public();
    shop.invite(&alice).await.unwrap();
    let signed = wallet.sign_message(Pair::note(&p.bob, "hello")).unwrap();
    p.alice
        .switch()
        .fail_next(Fault::LoseAnswer { path: "ops".into() });
    let batch = OpBatch::new()
        .op(OpKind::AllowPut {
            pubky: [9; 32],
            reason: pubky_switch_core::admission::PeerReason::Reply,
        })
        .queue(signed.clone());
    assert!(
        wallet
            .submit_batch(batch)
            .await
            .unwrap_err()
            .kept_batch()
            .is_some()
    );
    wallet.take_events();
    assert!(
        wallet
            .withdraw_message("sample", signed.msg_id())
            .await
            .unwrap()
    );
    assert_eq!(
        undelivered(&wallet.take_events(), signed.msg_id()),
        vec![false]
    );
    assert!(
        !wallet
            .hold_message("sample", signed.msg_id())
            .await
            .unwrap()
    );
    wallet.receive(None).await.unwrap();
    assert!(wallet.kept_batches().await.unwrap().is_empty(), "settled");
    wallet.flush_outbox().await.unwrap();
    assert_eq!(p.bob.switch().entries_from(&alice), 0);
    assert!(wallet.delivery(signed.msg_id()).await.unwrap().is_none());
}

/// Withdrawing a message the app owes no delivery of changes nothing.
#[tokio::test]
async fn test_withdraw_message_of_a_delivered_message_changes_nothing() {
    let p = Pair::new();
    let protocol = ApiProtocol::new(Mode::Plain);
    let mut wallet = p.join(&p.alice, "wallet", &protocol).await;
    let mut shop = p.join(&p.bob, "shop", &protocol).await;
    let alice = p.alice.identity().public();
    shop.invite(&alice).await.unwrap();
    let (msg_id, _) = wallet.send(Pair::note(&p.bob, "hello")).await.unwrap();
    wallet.take_events();
    assert!(!wallet.withdraw_message("sample", &msg_id).await.unwrap());
    assert!(
        !wallet
            .withdraw_message("sample", "never-queued")
            .await
            .unwrap()
    );
    assert!(wallet.take_events().is_empty());
    assert!(matches!(
        wallet.delivery(&msg_id).await.unwrap(),
        Some(Delivery::Accepted { .. })
    ));
}

// -------------------------------------------------------------------------------------
// The rollback alarm a protocol raises

/// A protocol's rollback alarm is kept and told, stops the app, holds after a reload, and
/// a second one leaves the first as it was.
#[tokio::test]
async fn test_raise_rollback_stops_the_app_and_is_kept() {
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
    wallet.take_events();
    let long = "x".repeat(300);
    let alarm = wallet.raise_rollback("sample", long).await.unwrap();
    let crate::app::Alarm::ProtocolRollback {
        protocol: raised_by,
        reason,
    } = &alarm
    else {
        panic!("{alarm:?}");
    };
    assert_eq!(raised_by, "sample");
    assert_eq!(reason.len(), crate::app::MAX_REGRESSION_REASON_BYTES);
    assert_eq!(wallet.alarm(), Some(&alarm));
    assert!(
        wallet
            .take_events()
            .iter()
            .any(|e| matches!(e, AppEvent::Alarm(a) if *a == alarm))
    );
    let error = wallet.flush_outbox().await.unwrap_err();
    assert!(
        matches!(error, AppError::Refused(Refusal::Stopped)),
        "{error:?}"
    );
    let second = wallet
        .raise_rollback("sample", "another rule")
        .await
        .unwrap();
    assert_eq!(second, alarm, "the first alarm stays");
    assert!(wallet.take_events().is_empty());
    drop(wallet);
    let loaded = App::load(
        p.env(&p.alice, Arc::clone(&store) as Arc<dyn StateStore>),
        protocol.clone(),
        config(),
        p.alice.identity().app_keys("wallet").app_id_bytes(),
    )
    .await
    .unwrap();
    assert_eq!(loaded.alarm(), Some(&alarm));
}

/// A commit that fails leaves no alarm, so the host raises it again, and that one is kept.
#[tokio::test]
async fn test_raise_rollback_store_failure_leaves_no_alarm() {
    let p = Pair::new();
    let protocol = ApiProtocol::new(Mode::Plain);
    let faulty = Arc::new(FaultStore::new(
        Arc::new(MemoryStore::new()) as Arc<dyn StateStore>,
        StoreFault::None,
    ));
    let mut wallet = p
        .join_on(
            &p.alice,
            "wallet",
            protocol.clone(),
            Arc::clone(&faulty) as Arc<dyn StateStore>,
        )
        .await;
    wallet.take_events();
    faulty.fail_put_once(b"alarm");
    let error = wallet.raise_rollback("sample", "a rule").await.unwrap_err();
    assert!(matches!(error, AppError::Store(_)), "{error:?}");
    assert_eq!(wallet.alarm(), None);
    assert!(wallet.take_events().is_empty());
    wallet.flush_outbox().await.unwrap();
    let alarm = wallet.raise_rollback("sample", "a rule").await.unwrap();
    assert_eq!(wallet.alarm(), Some(&alarm));
}

/// Run `body` on a thread with a stack of `bytes`, in a runtime of that thread alone, as a
/// host on small threads does.
fn on_a_small_stack<F>(bytes: usize, body: impl FnOnce() -> F + Send + 'static)
where
    F: std::future::Future<Output = ()>,
{
    std::thread::Builder::new()
        .stack_size(bytes)
        .spawn(move || {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(body());
        })
        .unwrap()
        .join()
        .expect("the read runs within the stack");
}

#[test]
fn test_receive_runs_on_a_one_mebibyte_stack() {
    // In a debug build, on a 1 MiB stack: a read whose entry's effect writes a record
    // through the context, one whose effect makes an attempt, one whose effect meets `409
    // conflict` and builds again, and the read that follows a move and sends the writes
    // kept during the freeze.
    on_a_small_stack(1 << 20, conflict_reads_again_and_builds_again);
    on_a_small_stack(1 << 20, || {
        super::moves::writes_kept_during_a_freeze_reach_the_next_service()
    });
    for mode in [Mode::Record, Mode::Attempt] {
        on_a_small_stack(1 << 20, move || async move {
            let w = World::new();
            let protocol = ApiProtocol::new(mode);
            let mut app = join(&w, &protocol, "wallet").await;
            w.note(app.app_id(), "hello");
            app.receive(None).await.unwrap();
            assert!(!protocol.seen().is_empty());
        });
    }
}
