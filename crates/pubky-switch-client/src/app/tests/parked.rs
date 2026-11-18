//! What a host sees and settles of the entries stored locally (Switch spec 8.2): listing
//! and viewing them, forgetting one that isn't tried again, and releasing one whose effect
//! was uncertain to be tried once more; each change in one commit.

use std::sync::{Arc, Mutex};

use pubky_switch_core::message::Message;
use pubky_switch_core::ops::OpKind;
use pubky_switch_core::records::DAY_MS;

use super::flows::received;
use super::moves::has;
use super::*;
use crate::app::{AppError, AppEvent, ParkReason, ParkedSummary, Refusal, StoreFailure};
use crate::error::StoreError;
use crate::store::{Fault as StoreFault, FaultStore};
use crate::testing::Fault;

/// What [`ParkingProtocol`]'s receive step does with a note.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Mode {
    /// The sample protocol's effect.
    Plain,
    /// The sample protocol's local effect without remote operations.
    Local,
    /// Reject the message in the receive callback.
    Drop,
    /// Reject the message's body before the receive callback.
    RejectBody,
    /// Eight operations: more than one batch takes, stored and not tried again.
    Wide,
    /// The store fails for the entry: stored and tried again.
    Rejected,
    /// The sample protocol's effect, but a run the host released is declined.
    DeclineReleased,
    /// The sample protocol's effect, but the first run of an entry stored locally can't
    /// finish ([`Outcome::Retry`]).
    RetryFirstStoredRun,
    /// The protocol's store is unavailable: held, then stored after the bounded wait.
    Unavailable,
}

/// The sample protocol, whose receive step follows [`Mode`].
struct ParkingProtocol {
    sample: SampleProtocol,
    mode: Mutex<Mode>,
    /// [`ReceivedMessage::released`] at each receive step, in order.
    released: Mutex<Vec<bool>>,
    /// How many runs of entries stored locally there were.
    stored_runs: Mutex<u32>,
}

impl ParkingProtocol {
    fn new(mode: Mode) -> Arc<Self> {
        Arc::new(Self {
            sample: SampleProtocol::default(),
            mode: Mutex::new(mode),
            released: Mutex::new(Vec::new()),
            stored_runs: Mutex::new(0),
        })
    }

    fn set(&self, mode: Mode) {
        *self.mode.lock().unwrap() = mode;
    }

    /// How many times a note was handed over.
    fn handed(&self) -> usize {
        self.sample.received.lock().unwrap().len()
    }

    fn released(&self) -> Vec<bool> {
        self.released.lock().unwrap().clone()
    }
}

impl Protocol for ParkingProtocol {
    fn name(&self) -> String {
        "sample".into()
    }

    fn has_keys(&self, scope: &str) -> bool {
        self.sample.has_keys(scope)
    }

    fn sent_between_own_apps(&self, kind: &str) -> bool {
        self.sample.sent_between_own_apps(kind)
    }

    fn check_scopes(
        &self,
        message: &Message,
        sender: &AppCert,
        own: &AppCert,
    ) -> Result<(), String> {
        self.sample.check_scopes(message, sender, own)
    }

    fn accepts(&self, cert: &AppCert) -> Vec<String> {
        self.sample.accepts(cert)
    }

    fn check_body(&self, message: &ReceivedMessage) -> Result<(), String> {
        if *self.mode.lock().unwrap() == Mode::RejectBody {
            return Err("the message is not needed".into());
        }
        self.sample.check_body(message)
    }

    fn receive(
        &self,
        message: &ReceivedMessage,
        cx: &mut crate::app::ReceiveContext<'_>,
    ) -> Outcome {
        self.released.lock().unwrap().push(message.released);
        let mode = *self.mode.lock().unwrap();
        match mode {
            Mode::Plain => self.sample.receive(message, cx),
            Mode::Drop => Outcome::Drop {
                reason: "the message is not needed".into(),
            },
            Mode::RejectBody => unreachable!(),
            Mode::Local => {
                let Outcome::Apply(mut effect) = self.sample.receive(message, cx) else {
                    unreachable!()
                };
                effect.ops.clear();
                Outcome::Apply(effect)
            }
            Mode::Wide => {
                self.sample.received.lock().unwrap().push((
                    message.seq,
                    message.message.msg_id.clone(),
                    false,
                ));
                Outcome::Apply(Effect {
                    ops: (0..8u8)
                        .map(|n| (Vec::new(), OpKind::DenyPut { pubky: [n; 32] }))
                        .collect(),
                    local: Vec::new(),
                })
            }
            Mode::Rejected => Outcome::Retry(StoreFailure::of_entry(StoreError::Corrupt)),
            Mode::Unavailable => Outcome::Retry(StoreError::Unavailable.into()),
            Mode::DeclineReleased if message.released => Outcome::Drop {
                reason: "sample: it may have been applied".into(),
            },
            Mode::DeclineReleased => self.sample.receive(message, cx),
            Mode::RetryFirstStoredRun => {
                if message.parked {
                    let mut runs = self.stored_runs.lock().unwrap();
                    *runs += 1;
                    if *runs == 1 {
                        return Outcome::Retry(StoreError::Unavailable.into());
                    }
                }
                self.sample.receive(message, cx)
            }
        }
    }

    fn resend_needed(&self, needed: &ResendNeeded) -> Result<Vec<LocalWrite>, StoreFailure> {
        self.sample.resend_needed(needed)
    }

    fn missed(&self, missed: &MissedEntries) -> Result<Vec<LocalWrite>, StoreFailure> {
        self.sample.missed(missed)
    }
}

/// Alice's wallet with `protocol`, on `store`.
async fn wallet_on(w: &World, protocol: &Arc<ParkingProtocol>, store: Arc<dyn StateStore>) -> App {
    let request = w.approve(&app_keys("wallet"), &["sample-a"]);
    App::join(w.env_on(store), protocol.clone(), World::config(), request)
        .await
        .unwrap()
}

/// The wallet loaded again on `store`.
async fn load_on(w: &World, protocol: &Arc<ParkingProtocol>, store: Arc<dyn StateStore>) -> App {
    App::load(
        w.env_on(store),
        protocol.clone(),
        World::config(),
        app_keys("wallet").app_id_bytes(),
    )
    .await
    .unwrap()
}

/// The entry stored locally at local ID `id`, as listed.
async fn listed(app: &mut App, id: u64) -> Option<ParkedSummary> {
    let entries = app.parked_entries().await.unwrap();
    entries.into_iter().find(|entry| entry.stored_id == id)
}

/// The reasons the entries stored locally were stored for, by local ID.
async fn reasons(app: &mut App) -> Vec<(u64, ParkReason)> {
    let entries = app.parked_entries().await.unwrap();
    entries.iter().map(|e| (e.stored_id, e.reason)).collect()
}

/// A note from bob stored as `mode` makes it. Returns its listing and message.
async fn parked_as(
    w: &World,
    app: &mut App,
    protocol: &ParkingProtocol,
    mode: Mode,
) -> (ParkedSummary, Message) {
    protocol.set(mode);
    let (seq, message) = w.note(app.app_id(), "parked note");
    app.receive(None).await.unwrap();
    protocol.set(Mode::Plain);
    let id = app.stored_id_at(seq).unwrap();
    (listed(app, id).await.unwrap(), message)
}

/// A note whose effect was applied but whose answer was lost, kept past the window in
/// which a resend tells: stored as uncertain. Returns its listing and message.
async fn uncertain(w: &World, app: &mut App) -> (ParkedSummary, Message) {
    let (seq, message) = w.note(app.app_id(), "uncertain note");
    w.switch.fail_next(Fault::LoseAnswer { path: "ops".into() });
    assert!(app.receive(None).await.is_err());
    w.clock.advance_ms(31 * DAY_MS);
    w.switch.lock().batches.clear();
    app.receive(None).await.unwrap();
    let id = app.stored_id_at(seq).unwrap();
    let entry = listed(app, id).await.unwrap();
    assert_eq!(entry.reason, ParkReason::Uncertain);
    assert!(
        !app.state.held.contains_key(&seq),
        "stored, its feed observation goes"
    );
    (entry, message)
}

/// Bob sends `message` again; returns its `seq`.
fn resend(w: &World, app: &App, message: &Message) -> u64 {
    let plaintext = message.sign(&w.bob_keys).unwrap();
    w.switch
        .send_plaintext(w.bob.public(), &w.bob_cert, &plaintext, &[app.app_id()])
        .unwrap()
}

/// Bob sends `message` again; returns whether the read took it as a duplicate.
async fn resent_is_duplicate(w: &World, app: &mut App, message: &Message) -> bool {
    let again = resend(w, app, message);
    let report = app.receive(None).await.unwrap();
    has(
        &report.events,
        |e| matches!(e, AppEvent::Duplicate { seq, conflicting: false } if *seq == again),
    )
}

/// The host acknowledges every duty event it was handed.
async fn ack_all(app: &mut App) {
    let events = app.unacknowledged_events().await.unwrap();
    if let Some(last) = events.iter().filter_map(AppEvent::id).next_back() {
        app.ack_events(last).await.unwrap();
    }
}

fn usage<T: std::fmt::Debug>(result: Result<T, AppError>) -> bool {
    matches!(result, Err(AppError::Refused(Refusal::Usage(_))))
}

#[tokio::test]
async fn test_parked_entries_are_listed_and_viewed_by_local_id() {
    let w = World::new();
    let protocol = ParkingProtocol::new(Mode::Plain);
    let mut app = wallet_on(&w, &protocol, Arc::clone(&w.store) as Arc<dyn StateStore>).await;
    let (wide, message) = parked_as(&w, &mut app, &protocol, Mode::Wide).await;
    let (rejected, _) = parked_as(&w, &mut app, &protocol, Mode::Rejected).await;
    assert!(wide.stored_id < rejected.stored_id && wide.seq < rejected.seq);
    assert_eq!(
        reasons(&mut app).await,
        vec![
            (wide.stored_id, ParkReason::TooManyOperations),
            (rejected.stored_id, ParkReason::StoreRejected)
        ]
    );
    let plaintext = message.sign(&w.bob_keys).unwrap();
    assert_eq!(wide.hash, plaintext.hash());
    assert!(wide.readable);
    assert_eq!(wide.generation, 1);
    let view = app.parked_entry(wide.stored_id).await.unwrap().unwrap();
    assert_eq!((view.stored_id, view.seq), (wide.stored_id, wide.seq));
    assert_eq!(view.sender, w.bob.public());
    assert!(view.sender_verified);
    assert_eq!(view.reason, ParkReason::TooManyOperations);
    let read = view.message.clone().unwrap();
    assert_eq!(read.msg_id, message.msg_id);
    assert_eq!(read.kind, "sample.note");
    assert_eq!(view.plaintext.hash(), plaintext.hash());
    assert_eq!(view.retry_reads, 0);
    // Its Debug names the entry, never its content.
    let shown = format!("{view:?}");
    assert!(shown.contains(&message.msg_id) && shown.contains("TooManyOperations"));
    assert!(!shown.contains("parked note"), "{shown}");
}

#[tokio::test]
async fn test_parked_forget_of_a_final_entry_keeps_its_message_a_duplicate() {
    let w = World::new();
    let protocol = ParkingProtocol::new(Mode::Plain);
    let mut app = wallet_on(&w, &protocol, Arc::clone(&w.store) as Arc<dyn StateStore>).await;
    let (wide, message) = parked_as(&w, &mut app, &protocol, Mode::Wide).await;
    let handed = protocol.handed();
    ack_all(&mut app).await;
    assert_eq!(
        app.forget_parked(wide.stored_id, &wide.hash).await.unwrap(),
        1
    );
    assert!(app.parked_entries().await.unwrap().is_empty());
    assert!(app.parked_entry(wide.stored_id).await.unwrap().is_none());
    // So it stays after a reload, and a re-send of the message is a duplicate.
    let mut app = load_on(&w, &protocol, Arc::clone(&w.store) as Arc<dyn StateStore>).await;
    assert!(app.parked_entries().await.unwrap().is_empty());
    assert!(resent_is_duplicate(&w, &mut app, &message).await);
    assert_eq!(protocol.handed(), handed);
}

#[tokio::test]
async fn test_parked_forget_removes_every_stored_copy_of_the_message() {
    let w = World::new();
    let protocol = ParkingProtocol::new(Mode::Plain);
    let mut app = wallet_on(&w, &protocol, Arc::clone(&w.store) as Arc<dyn StateStore>).await;
    // The message stored as refused, then a re-send of it stored for the store's failure.
    let (wide, message) = parked_as(&w, &mut app, &protocol, Mode::Wide).await;
    protocol.set(Mode::Rejected);
    let again = resend(&w, &app, &message);
    app.receive(None).await.unwrap();
    protocol.set(Mode::Plain);
    let copy = app.stored_id_at(again).unwrap();
    assert_eq!(
        reasons(&mut app).await,
        vec![
            (wide.stored_id, ParkReason::TooManyOperations),
            (copy, ParkReason::StoreRejected)
        ]
    );
    // An entry of another message stays.
    let (other, _) = parked_as(&w, &mut app, &protocol, Mode::Rejected).await;
    ack_all(&mut app).await;
    let handed = protocol.handed();
    assert_eq!(
        app.forget_parked(wide.stored_id, &wide.hash).await.unwrap(),
        2
    );
    assert_eq!(
        reasons(&mut app).await,
        vec![(other.stored_id, ParkReason::StoreRejected)]
    );
    // Both copies went in the commit: none is left to run after a reload.
    let mut app = load_on(&w, &protocol, Arc::clone(&w.store) as Arc<dyn StateStore>).await;
    assert_eq!(app.stored_id_at(again), None);
    app.receive(None).await.unwrap();
    assert_eq!(protocol.handed(), handed + 1);
}

#[tokio::test]
async fn test_parked_forget_while_a_duty_event_names_it_is_refused() {
    let w = World::new();
    let protocol = ParkingProtocol::new(Mode::Plain);
    let mut app = wallet_on(&w, &protocol, Arc::clone(&w.store) as Arc<dyn StateStore>).await;
    let (wide, _) = parked_as(&w, &mut app, &protocol, Mode::Wide).await;
    // `EffectRefused` and `Parked` name the entry and aren't acknowledged yet.
    let kept = app.unacknowledged_events().await.unwrap();
    assert!(has(&kept, |e| matches!(
        e,
        AppEvent::EffectRefused { stored_id, .. } if *stored_id == wide.stored_id
    )));
    assert!(usage(app.forget_parked(wide.stored_id, &wide.hash).await));
    assert_eq!(reasons(&mut app).await.len(), 1);
    ack_all(&mut app).await;
    assert_eq!(
        app.forget_parked(wide.stored_id, &wide.hash).await.unwrap(),
        1
    );
}

#[tokio::test]
async fn test_parked_forget_with_another_hash_is_refused() {
    let w = World::new();
    let protocol = ParkingProtocol::new(Mode::Plain);
    let mut app = wallet_on(&w, &protocol, Arc::clone(&w.store) as Arc<dyn StateStore>).await;
    let (wide, _) = parked_as(&w, &mut app, &protocol, Mode::Wide).await;
    let (uncertain, _) = uncertain(&w, &mut app).await;
    ack_all(&mut app).await;
    // Each named with the other's hash.
    assert!(usage(
        app.forget_parked(wide.stored_id, &uncertain.hash).await
    ));
    assert!(usage(
        app.release_parked(uncertain.stored_id, &wide.hash).await
    ));
    assert_eq!(reasons(&mut app).await.len(), 2);
    assert_eq!(listed(&mut app, uncertain.stored_id).await, Some(uncertain));
}

/// The host forgets `entry` once the duty events are acknowledged: it goes alone, and a
/// re-send of `message` is a duplicate.
async fn forgotten(w: &World, app: &mut App, entry: ParkedSummary, message: &Message) {
    ack_all(app).await;
    assert_eq!(
        app.forget_parked(entry.stored_id, &entry.hash)
            .await
            .unwrap(),
        1
    );
    assert!(app.parked_entries().await.unwrap().is_empty(), "{entry:?}");
    assert!(resent_is_duplicate(w, app, message).await, "{entry:?}");
}

#[tokio::test]
async fn test_parked_forget_of_an_entry_stored_for_any_reason() {
    let w = World::new();
    let protocol = ParkingProtocol::new(Mode::Plain);
    let mut app = wallet_on(&w, &protocol, Arc::clone(&w.store) as Arc<dyn StateStore>).await;
    // Tried again: a write over the quota.
    let (seq, message) = w.note(app.app_id(), "over the quota");
    w.switch.fail_next(Fault::Error {
        path: "ops".into(),
        code: pubky_switch_core::http::ErrorCode::QuotaExceeded,
        current: serde_json::json!({}),
    });
    app.receive(None).await.unwrap();
    let id = app.stored_id_at(seq).unwrap();
    let quota = listed(&mut app, id).await.unwrap();
    assert_eq!(quota.reason, ParkReason::Quota);
    forgotten(&w, &mut app, quota, &message).await;
    // Tried again: the protocol's store refused the entry.
    let (rejected, message) = parked_as(&w, &mut app, &protocol, Mode::Rejected).await;
    assert_eq!(rejected.reason, ParkReason::StoreRejected);
    forgotten(&w, &mut app, rejected, &message).await;
    // Tried again: the protocol's store unavailable past the bounded wait.
    protocol.set(Mode::Unavailable);
    let (seq, message) = w.note(app.app_id(), "unavailable");
    app.receive(None).await.unwrap();
    w.clock.advance_ms(World::config().park_after_ms + 1);
    app.receive(None).await.unwrap();
    protocol.set(Mode::Plain);
    let id = app.stored_id_at(seq).unwrap();
    let unavailable = listed(&mut app, id).await.unwrap();
    assert_eq!(unavailable.reason, ParkReason::StoreUnavailable);
    // Stored after the app's checks of its sender passed.
    let view = app
        .parked_entry(unavailable.stored_id)
        .await
        .unwrap()
        .unwrap();
    assert!(view.sender_verified);
    forgotten(&w, &mut app, unavailable, &message).await;
    // Not tried again: an uncertain effect.
    let (uncertain_entry, message) = uncertain(&w, &mut app).await;
    forgotten(&w, &mut app, uncertain_entry, &message).await;
    // Tried again: an uncertain one the host released.
    let (released, message) = uncertain(&w, &mut app).await;
    app.release_parked(released.stored_id, &released.hash)
        .await
        .unwrap();
    let released = listed(&mut app, released.stored_id).await.unwrap();
    assert_eq!(released.reason, ParkReason::Released);
    forgotten(&w, &mut app, released, &message).await;
}

#[tokio::test]
async fn test_parked_forget_of_an_unverifiable_copy_keeps_a_checked_message_processed() {
    let w = World::new();
    let protocol = ParkingProtocol::new(Mode::Plain);
    let mut app = wallet_on(&w, &protocol, Arc::clone(&w.store) as Arc<dyn StateStore>).await;
    // The message stored once with its sender checked, its effect over one batch.
    let (wide, message) = parked_as(&w, &mut app, &protocol, Mode::Wide).await;
    // A re-send of it stored once more, its sender's standing not checked.
    w.homeserver.set_down(true);
    w.clock.advance_ms(11 * 60_000);
    let again = resend(&w, &app, &message);
    app.receive(None).await.unwrap();
    w.clock.advance_ms(25 * 3_600_000);
    app.receive(None).await.unwrap();
    let id = app.stored_id_at(again).unwrap();
    let unverified = listed(&mut app, id).await.unwrap();
    assert_eq!(unverified.reason, ParkReason::Unverifiable);
    assert_eq!(unverified.hash, wide.hash);
    // Forgetting the unverified copy is being done with the message: both go, and since
    // one of them was checked, the message stays processed.
    ack_all(&mut app).await;
    let handed = protocol.handed();
    assert_eq!(
        app.forget_parked(unverified.stored_id, &unverified.hash)
            .await
            .unwrap(),
        2
    );
    assert!(app.parked_entries().await.unwrap().is_empty());
    w.homeserver.set_down(false);
    assert!(resent_is_duplicate(&w, &mut app, &message).await);
    assert_eq!(protocol.handed(), handed);
}

#[tokio::test]
async fn test_parked_forget_of_an_unverifiable_entry_keeps_no_processed_pair() {
    let w = World::new();
    let protocol = ParkingProtocol::new(Mode::Plain);
    let mut app = wallet_on(&w, &protocol, Arc::clone(&w.store) as Arc<dyn StateStore>).await;
    w.homeserver.set_down(true);
    let (seq, message) = w.note(app.app_id(), "unverifiable note");
    app.receive(None).await.unwrap();
    w.clock.advance_ms(25 * 3_600_000);
    app.receive(None).await.unwrap();
    let id = app.stored_id_at(seq).unwrap();
    let entry = listed(&mut app, id).await.unwrap();
    assert_eq!(entry.reason, ParkReason::Unverifiable);
    // Its sender wasn't checked: the view says so.
    let view = app.parked_entry(id).await.unwrap().unwrap();
    assert!(!view.sender_verified);
    assert!(format!("{view:?}").contains("sender_verified: false"));
    let handed = protocol.handed();
    assert_eq!(app.forget_parked(id, &entry.hash).await.unwrap(), 1);
    assert!(app.parked_entries().await.unwrap().is_empty());
    // A re-send once the sender can be checked is checked and applied as new.
    w.homeserver.set_down(false);
    w.clock.advance_ms(DAY_MS);
    assert!(!resent_is_duplicate(&w, &mut app, &message).await);
    assert_eq!(protocol.handed(), handed + 1);
}

#[tokio::test]
async fn test_parked_forget_of_a_corrupt_entry_removes_it() {
    let w = World::new();
    let protocol = ParkingProtocol::new(Mode::Plain);
    let mut app = wallet_on(&w, &protocol, Arc::clone(&w.store) as Arc<dyn StateStore>).await;
    let (rejected, _) = parked_as(&w, &mut app, &protocol, Mode::Rejected).await;
    // Its stored plaintext no longer reads.
    let mut stored = app.state.parked.get(&rejected.stored_id).unwrap().clone();
    stored.plaintext = b"not a plaintext".to_vec();
    let mut tx = app.tx().unwrap();
    tx.put(&crate::app::state::key::parked(rejected.stored_id), &stored)
        .unwrap();
    app.commit(tx).await.unwrap();
    app.state.parked.insert(rejected.stored_id, stored);
    let entry = listed(&mut app, rejected.stored_id).await.unwrap();
    assert!(!entry.readable);
    assert_eq!(
        entry.hash,
        pubky_switch_core::message::message_hash(b"not a plaintext")
    );
    assert!(matches!(
        app.parked_entry(rejected.stored_id).await,
        Err(AppError::Store(StoreError::Corrupt))
    ));
    assert!(usage(
        app.forget_parked(rejected.stored_id, &rejected.hash).await
    ));
    assert_eq!(
        app.forget_parked(rejected.stored_id, &entry.hash)
            .await
            .unwrap(),
        1
    );
    assert!(app.parked_entries().await.unwrap().is_empty());
}

#[tokio::test]
async fn test_parked_release_of_an_uncertain_entry_runs_it_once() {
    let w = World::new();
    let protocol = ParkingProtocol::new(Mode::Plain);
    let mut app = wallet_on(&w, &protocol, Arc::clone(&w.store) as Arc<dyn StateStore>).await;
    let (entry, message) = uncertain(&w, &mut app).await;
    let id = entry.stored_id;
    // Before the release, a re-send is a duplicate.
    assert!(resent_is_duplicate(&w, &mut app, &message).await);
    let handed = protocol.handed();
    app.release_parked(id, &entry.hash).await.unwrap();
    assert_eq!(reasons(&mut app).await, vec![(id, ParkReason::Released)]);
    // The next read runs it as a fresh receive, once, telling the protocol it was released.
    let report = app.receive(None).await.unwrap();
    assert!(
        has(
            &report.events,
            |e| matches!(e, AppEvent::Unparked { stored_id, .. } if *stored_id == id)
        ),
        "{:?}",
        report.events
    );
    assert_eq!(protocol.handed(), handed + 1);
    assert_eq!(protocol.released().last(), Some(&true));
    assert!(app.parked_entries().await.unwrap().is_empty());
    app.receive(None).await.unwrap();
    assert_eq!(protocol.handed(), handed + 1);
    // After its run, a re-send is a duplicate again, and not a released run.
    assert!(resent_is_duplicate(&w, &mut app, &message).await);
    assert_eq!(protocol.handed(), handed + 1);
    assert_eq!(protocol.released().iter().filter(|r| **r).count(), 1);
}

#[tokio::test]
async fn test_parked_release_declined_by_the_protocol_stays_processed() {
    let w = World::new();
    let protocol = ParkingProtocol::new(Mode::Plain);
    let mut app = wallet_on(&w, &protocol, Arc::clone(&w.store) as Arc<dyn StateStore>).await;
    let (entry, message) = uncertain(&w, &mut app).await;
    protocol.set(Mode::DeclineReleased);
    let handed = protocol.handed();
    app.release_parked(entry.stored_id, &entry.hash)
        .await
        .unwrap();
    let report = app.receive(None).await.unwrap();
    assert!(has(&report.events, |e| matches!(
        e,
        AppEvent::MessageDropped { check: 10, .. }
    )));
    assert_eq!(protocol.handed(), handed);
    assert!(app.parked_entries().await.unwrap().is_empty());
    // Declined, the message stays processed: a re-send is a duplicate.
    assert!(resent_is_duplicate(&w, &mut app, &message).await);
    assert_eq!(protocol.handed(), handed);
}

/// An uncertain entry released, then a re-send of its message that arrives before the
/// released entry's run finishes: its first run can't finish, so the re-send is applied
/// first. Returns the entry's listing and the effects applied.
async fn resent_before_the_released_run(
    w: &World,
    app: &mut App,
    protocol: &ParkingProtocol,
) -> (ParkedSummary, usize) {
    let (entry, message) = uncertain(w, app).await;
    ack_all(app).await;
    protocol.set(Mode::RetryFirstStoredRun);
    let applied = w.effects();
    app.release_parked(entry.stored_id, &entry.hash)
        .await
        .unwrap();
    let again = resend(w, app, &message);
    let report = app.receive(None).await.unwrap();
    assert!(received(&report.events, again), "{:?}", report.events);
    assert_eq!(w.effects(), applied + 1);
    (entry, applied + 1)
}

#[tokio::test]
async fn test_parked_resend_between_release_and_run_is_applied_once() {
    let w = World::new();
    let protocol = ParkingProtocol::new(Mode::Plain);
    let mut app = wallet_on(&w, &protocol, Arc::clone(&w.store) as Arc<dyn StateStore>).await;
    let (_, applied) = resent_before_the_released_run(&w, &mut app, &protocol).await;
    // The released entry runs next, and is a duplicate: not applied again.
    app.receive(None).await.unwrap();
    assert_eq!(w.effects(), applied, "applied twice");
    assert!(app.parked_entries().await.unwrap().is_empty());
}

#[tokio::test]
async fn test_parked_released_entry_run_as_a_duplicate_keeps_a_duty_event() {
    let w = World::new();
    let protocol = ParkingProtocol::new(Mode::Plain);
    let mut app = wallet_on(&w, &protocol, Arc::clone(&w.store) as Arc<dyn StateStore>).await;
    let (entry, _) = resent_before_the_released_run(&w, &mut app, &protocol).await;
    app.receive(None).await.unwrap();
    // Kept, so the host learns how its release ended after a reload too.
    let mut app = load_on(&w, &protocol, Arc::clone(&w.store) as Arc<dyn StateStore>).await;
    let kept = app.unacknowledged_events().await.unwrap();
    assert!(
        has(&kept, |e| matches!(
            e,
            AppEvent::ReleasedDuplicate { stored_id, seq, conflicting: false, .. }
                if *stored_id == entry.stored_id && *seq == entry.seq
        )),
        "{kept:?}"
    );
}

#[tokio::test]
async fn test_parked_release_of_another_reason_is_refused() {
    let w = World::new();
    let protocol = ParkingProtocol::new(Mode::Plain);
    let mut app = wallet_on(&w, &protocol, Arc::clone(&w.store) as Arc<dyn StateStore>).await;
    let (wide, _) = parked_as(&w, &mut app, &protocol, Mode::Wide).await;
    let (rejected, _) = parked_as(&w, &mut app, &protocol, Mode::Rejected).await;
    assert!(usage(app.release_parked(wide.stored_id, &wide.hash).await));
    assert!(usage(
        app.release_parked(rejected.stored_id, &rejected.hash).await
    ));
    assert_eq!(
        reasons(&mut app).await,
        vec![
            (wide.stored_id, ParkReason::TooManyOperations),
            (rejected.stored_id, ParkReason::StoreRejected)
        ]
    );
}

#[tokio::test]
async fn test_parked_unknown_id_is_refused() {
    let w = World::new();
    let protocol = ParkingProtocol::new(Mode::Plain);
    let mut app = wallet_on(&w, &protocol, Arc::clone(&w.store) as Arc<dyn StateStore>).await;
    assert!(app.parked_entry(99).await.unwrap().is_none());
    assert!(usage(app.forget_parked(99, &[0; 32]).await));
    assert!(usage(app.release_parked(99, &[0; 32]).await));
}

/// The store's keys for the wallet, to compare before and after a change.
fn snapshot(store: &MemoryStore) -> Vec<(Vec<u8>, Vec<u8>)> {
    let ns = crate::store::client_namespace(&app_keys("wallet").app_id_bytes());
    store.scan(&ns, b"", None, u32::MAX).unwrap()
}

#[tokio::test]
async fn test_parked_forget_crash_is_all_or_nothing() {
    let w = World::new();
    let protocol = ParkingProtocol::new(Mode::Plain);
    let mut app = wallet_on(&w, &protocol, Arc::clone(&w.store) as Arc<dyn StateStore>).await;
    let (entry, message) = parked_as(&w, &mut app, &protocol, Mode::Wide).await;
    ack_all(&mut app).await;
    drop(app);
    let before = snapshot(&w.store);
    // The process stops before the forget's commit: nothing of it happened.
    let fault = Arc::new(FaultStore::new(
        Arc::clone(&w.store) as Arc<dyn StateStore>,
        StoreFault::StopBefore(1),
    ));
    let mut app = load_on(&w, &protocol, fault.clone() as Arc<dyn StateStore>).await;
    assert!(
        app.forget_parked(entry.stored_id, &entry.hash)
            .await
            .is_err()
    );
    assert_eq!(fault.commits(), 1);
    assert_eq!(snapshot(&w.store), before);
    // It stops after the commit: all of it happened.
    let fault = Arc::new(FaultStore::new(
        Arc::clone(&w.store) as Arc<dyn StateStore>,
        StoreFault::StopAfter(1),
    ));
    let mut app = load_on(&w, &protocol, fault.clone() as Arc<dyn StateStore>).await;
    assert!(
        app.forget_parked(entry.stored_id, &entry.hash)
            .await
            .is_err()
    );
    let mut app = load_on(&w, &protocol, Arc::clone(&w.store) as Arc<dyn StateStore>).await;
    assert!(app.parked_entries().await.unwrap().is_empty());
    assert!(resent_is_duplicate(&w, &mut app, &message).await);
}

#[tokio::test]
async fn test_parked_release_crash_is_all_or_nothing() {
    let w = World::new();
    let protocol = ParkingProtocol::new(Mode::Plain);
    let mut app = wallet_on(&w, &protocol, Arc::clone(&w.store) as Arc<dyn StateStore>).await;
    let (entry, _) = uncertain(&w, &mut app).await;
    drop(app);
    let before = snapshot(&w.store);
    let fault = Arc::new(FaultStore::new(
        Arc::clone(&w.store) as Arc<dyn StateStore>,
        StoreFault::StopBefore(1),
    ));
    let mut app = load_on(&w, &protocol, fault.clone() as Arc<dyn StateStore>).await;
    assert!(
        app.release_parked(entry.stored_id, &entry.hash)
            .await
            .is_err()
    );
    assert_eq!(fault.commits(), 1);
    assert_eq!(snapshot(&w.store), before);
    let fault = Arc::new(FaultStore::new(
        Arc::clone(&w.store) as Arc<dyn StateStore>,
        StoreFault::StopAfter(1),
    ));
    let mut app = load_on(&w, &protocol, fault.clone() as Arc<dyn StateStore>).await;
    assert!(
        app.release_parked(entry.stored_id, &entry.hash)
            .await
            .is_err()
    );
    let mut app = load_on(&w, &protocol, Arc::clone(&w.store) as Arc<dyn StateStore>).await;
    assert_eq!(
        reasons(&mut app).await,
        vec![(entry.stored_id, ParkReason::Released)]
    );
    // The processed pair went in the same commit: the next read runs the entry.
    let handed = protocol.handed();
    app.receive(None).await.unwrap();
    assert_eq!(protocol.handed(), handed + 1);
}

#[tokio::test]
async fn test_parked_forget_while_its_effect_is_kept_is_refused_until_a_read_settles_it() {
    let w = World::new();
    let protocol = ParkingProtocol::new(Mode::Plain);
    let mut app = wallet_on(&w, &protocol, Arc::clone(&w.store) as Arc<dyn StateStore>).await;
    let (entry, _) = parked_as(&w, &mut app, &protocol, Mode::Rejected).await;
    assert_eq!(entry.reason, ParkReason::StoreRejected);
    // Its retry builds the effect, keeps it and sends it: applied, the answer lost.
    w.switch.fail_next(Fault::LoseAnswer { path: "ops".into() });
    assert!(app.receive(None).await.is_err());
    ack_all(&mut app).await;
    let error = app
        .forget_parked(entry.stored_id, &entry.hash)
        .await
        .unwrap_err();
    assert!(
        matches!(&error, AppError::Refused(Refusal::NotNow(why)) if why.contains("kept unanswered")),
        "{error:?}"
    );
    assert_eq!(listed(&mut app, entry.stored_id).await, Some(entry));
    // The next read settles it: the effect applied, the entry is processed and gone.
    let report = app.receive(None).await.unwrap();
    assert!(
        has(&report.events, |e| matches!(
            e,
            AppEvent::MessageReceived { .. }
        )),
        "{:?}",
        report.events
    );
    assert_eq!(listed(&mut app, entry.stored_id).await, None);
    assert!(usage(app.forget_parked(entry.stored_id, &entry.hash).await));
}

/// Bob's note `message` again under the same `msg_id` with other bytes, signed by an app of
/// his that isn't listed: stored as unverifiable while his Homeserver can't be reached.
async fn forged_copy(w: &World, app: &mut App, message: &Message) -> ParkedSummary {
    let keys = app_keys("removed-app");
    let cert = cert_for(&w.bob, &keys, w.clock.now_ms(), &["sample-a"]);
    let mut forged = message.clone();
    forged.from = pubky_switch_core::message::Sender::of_app(w.bob.public(), &keys);
    forged
        .body
        .insert("text".into(), serde_json::Value::from("forged"));
    let plaintext = forged.sign(&keys).unwrap();
    w.homeserver.set_down(true);
    w.clock.advance_ms(11 * 60_000);
    let seq = w
        .switch
        .send_plaintext(w.bob.public(), &cert, &plaintext, &[app.app_id()])
        .unwrap();
    app.receive(None).await.unwrap();
    w.clock.advance_ms(25 * 3_600_000);
    app.receive(None).await.unwrap();
    w.homeserver.set_down(false);
    let id = app.stored_id_at(seq).unwrap();
    let entry = listed(app, id).await.unwrap();
    assert_eq!(entry.reason, ParkReason::Unverifiable);
    entry
}

async fn processed(app: &App, message: &Message) -> bool {
    let pair = crate::app::state::key::processed(&message.from.identity, &message.msg_id);
    app.reader().exists(&pair).await.unwrap()
}

#[tokio::test]
async fn test_parked_forget_of_a_forgery_keeps_the_genuine_copy() {
    let w = World::new();
    let protocol = ParkingProtocol::new(Mode::Plain);
    let mut app = wallet_on(&w, &protocol, Arc::clone(&w.store) as Arc<dyn StateStore>).await;
    // The genuine message, checked and stored for good; a forgery under its `msg_id`.
    let (genuine, message) = parked_as(&w, &mut app, &protocol, Mode::Wide).await;
    let forgery = forged_copy(&w, &mut app, &message).await;
    assert_ne!(forgery.hash, genuine.hash);
    ack_all(&mut app).await;
    // Forgetting the forgery takes it alone, and leaves the message unprocessed.
    assert_eq!(
        app.forget_parked(forgery.stored_id, &forgery.hash)
            .await
            .unwrap(),
        1
    );
    assert_eq!(listed(&mut app, genuine.stored_id).await, Some(genuine));
    assert!(!processed(&app, &message).await);
}

#[tokio::test]
async fn test_parked_forget_of_a_genuine_copy_takes_a_forgery_under_its_msg_id() {
    let w = World::new();
    let protocol = ParkingProtocol::new(Mode::Plain);
    let mut app = wallet_on(&w, &protocol, Arc::clone(&w.store) as Arc<dyn StateStore>).await;
    let (genuine, message) = parked_as(&w, &mut app, &protocol, Mode::Wide).await;
    let forgery = forged_copy(&w, &mut app, &message).await;
    ack_all(&mut app).await;
    // Forgetting the checked copy is being done with its message, as the processed pairs
    // name it: the forgery under its `msg_id` goes too, and the message stays processed.
    assert_eq!(
        app.forget_parked(genuine.stored_id, &genuine.hash)
            .await
            .unwrap(),
        2
    );
    assert!(listed(&mut app, forgery.stored_id).await.is_none());
    assert!(processed(&app, &message).await);
}

/// An uncertain entry the host released, whose released run is stored again for `again`:
/// a quota the switch answers, a store that refuses the entry's state, or a sender that
/// can't be checked. Returns its listing.
async fn released_then_stored(
    w: &World,
    app: &mut App,
    protocol: &ParkingProtocol,
    again: ParkReason,
) -> ParkedSummary {
    let (entry, _) = uncertain(w, app).await;
    app.release_parked(entry.stored_id, &entry.hash)
        .await
        .unwrap();
    match again {
        ParkReason::Quota => w.switch.fail_next(Fault::Error {
            path: "ops".into(),
            code: pubky_switch_core::http::ErrorCode::QuotaExceeded,
            current: serde_json::json!({}),
        }),
        ParkReason::StoreRejected => protocol.set(Mode::Rejected),
        ParkReason::Unverifiable => w.homeserver.set_down(true),
        _ => unreachable!(),
    }
    let _ = app.receive(None).await;
    protocol.set(Mode::Plain);
    w.homeserver.set_down(false);
    // A quota stores it again for its own reason; a store that refuses its state, or a
    // sender that can't be checked, leaves it stored as released, tried again.
    let stored = match again {
        ParkReason::Quota => ParkReason::Quota,
        _ => ParkReason::Released,
    };
    assert_eq!(reasons(app).await, vec![(entry.stored_id, stored)]);
    entry
}

/// The next run of `entry` is handed over as released: a protocol that declines released
/// runs drops it, and its effect isn't applied again.
async fn next_run_is_released(
    w: &World,
    app: &mut App,
    protocol: &ParkingProtocol,
    entry: &ParkedSummary,
) {
    protocol.set(Mode::DeclineReleased);
    let effects = w.effects();
    app.receive(None).await.unwrap();
    assert_eq!(protocol.released().last(), Some(&true));
    assert_eq!(w.effects(), effects);
    assert!(listed(app, entry.stored_id).await.is_none());
}

#[tokio::test]
async fn test_parked_release_survives_a_quota() {
    let w = World::new();
    let protocol = ParkingProtocol::new(Mode::Plain);
    let mut app = wallet_on(&w, &protocol, Arc::clone(&w.store) as Arc<dyn StateStore>).await;
    let entry = released_then_stored(&w, &mut app, &protocol, ParkReason::Quota).await;
    next_run_is_released(&w, &mut app, &protocol, &entry).await;
}

#[tokio::test]
async fn test_parked_release_survives_a_store_that_refuses() {
    let w = World::new();
    let protocol = ParkingProtocol::new(Mode::Plain);
    let mut app = wallet_on(&w, &protocol, Arc::clone(&w.store) as Arc<dyn StateStore>).await;
    let entry = released_then_stored(&w, &mut app, &protocol, ParkReason::StoreRejected).await;
    next_run_is_released(&w, &mut app, &protocol, &entry).await;
}

#[tokio::test]
async fn test_parked_release_survives_an_unverifiable_sender() {
    let w = World::new();
    let protocol = ParkingProtocol::new(Mode::Plain);
    let mut app = wallet_on(&w, &protocol, Arc::clone(&w.store) as Arc<dyn StateStore>).await;
    let entry = released_then_stored(&w, &mut app, &protocol, ParkReason::Unverifiable).await;
    next_run_is_released(&w, &mut app, &protocol, &entry).await;
}

#[tokio::test]
async fn test_parked_release_survives_a_backup_and_restore() {
    let w = World::new();
    let protocol = ParkingProtocol::new(Mode::Plain);
    let mut app = wallet_on(&w, &protocol, Arc::clone(&w.store) as Arc<dyn StateStore>).await;
    let entry = released_then_stored(&w, &mut app, &protocol, ParkReason::Quota).await;
    let backup = app.backup_layered().await.unwrap();
    drop(app);
    let restored_protocol = ParkingProtocol::new(Mode::Plain);
    let mut restored = App::restore(
        w.env_on(Arc::new(MemoryStore::new()) as Arc<dyn StateStore>),
        restored_protocol.clone(),
        World::config(),
        &backup,
    )
    .await
    .unwrap();
    assert!(listed(&mut restored, entry.stored_id).await.is_some());
    next_run_is_released(&w, &mut restored, &restored_protocol, &entry).await;
}

#[tokio::test]
async fn test_parked_backup_of_a_kept_effect_whose_stored_entry_is_gone_is_corrupt() {
    // A kept effect names an entry stored locally that the store no longer holds, which no
    // path leaves: the backup is refused as a corrupt store, never given a made-up ID.
    let w = World::new();
    let protocol = ParkingProtocol::new(Mode::Plain);
    let mut app = wallet_on(&w, &protocol, Arc::clone(&w.store) as Arc<dyn StateStore>).await;
    let (entry, _) = uncertain(&w, &mut app).await;
    app.release_parked(entry.stored_id, &entry.hash)
        .await
        .unwrap();
    w.switch.fail_next(Fault::LoseAnswer { path: "ops".into() });
    assert!(app.receive(None).await.is_err());
    let mut tx = app.tx().unwrap();
    tx.delete(&crate::app::state::key::parked(entry.stored_id))
        .unwrap();
    app.commit(tx).await.unwrap();
    let error = app.backup_layered().await.unwrap_err();
    assert_eq!(error, AppError::Store(crate::error::StoreError::Corrupt));
}

#[tokio::test]
async fn test_parked_release_survives_a_backup_of_its_kept_effect() {
    // A released entry whose run applies its effect and loses the answer: the effect is
    // kept, and a backup holds the entry as uncertain, still released.
    let w = World::new();
    let protocol = ParkingProtocol::new(Mode::Plain);
    let mut app = wallet_on(&w, &protocol, Arc::clone(&w.store) as Arc<dyn StateStore>).await;
    let (entry, _) = uncertain(&w, &mut app).await;
    app.release_parked(entry.stored_id, &entry.hash)
        .await
        .unwrap();
    w.switch.fail_next(Fault::LoseAnswer { path: "ops".into() });
    assert!(app.receive(None).await.is_err());
    assert_eq!(
        app.state.pending_effect.as_ref().and_then(|p| p.stored),
        Some(entry.stored_id)
    );
    let backup = app.backup_layered().await.unwrap();
    let restored = App::restore(
        w.env_on(Arc::new(MemoryStore::new()) as Arc<dyn StateStore>),
        ParkingProtocol::new(Mode::Plain),
        World::config(),
        &backup,
    )
    .await
    .unwrap();
    let copy = restored.state.parked.get(&entry.stored_id).unwrap();
    assert_eq!(copy.reason, ParkReason::Uncertain);
    assert!(copy.released, "the copy lost its release");
}

#[tokio::test]
async fn test_parked_backup_of_a_kept_effect_never_hands_its_entry_over_again() {
    // A feed entry's effect is applied and its answer lost: the effect is kept. A backup
    // then holds the entry as uncertain. Restored after the processed pair of its message
    // has aged out, the app still never hands the entry over again by itself; the host's
    // release of the stored copy hands it over once.
    let w = World::new();
    let protocol = ParkingProtocol::new(Mode::Plain);
    let mut app = wallet_on(&w, &protocol, Arc::clone(&w.store) as Arc<dyn StateStore>).await;
    let (seq, _) = w.note(app.app_id(), "kept note");
    w.switch.fail_next(Fault::LoseAnswer { path: "ops".into() });
    assert!(app.receive(None).await.is_err());
    assert!(
        app.state
            .pending_effect
            .as_ref()
            .is_some_and(|p| p.seq == seq && p.stored.is_none())
    );
    let backup = app.backup_layered().await.unwrap();
    drop(app);
    // Past the processed pair's 30 days and the tolerance.
    w.clock.advance_ms(31 * DAY_MS);
    w.switch.lock().batches.clear();
    let restored_protocol = ParkingProtocol::new(Mode::Plain);
    let mut restored = App::restore(
        w.env_on(Arc::new(MemoryStore::new()) as Arc<dyn StateStore>),
        restored_protocol.clone(),
        World::config(),
        &backup,
    )
    .await
    .unwrap();
    restored.receive(None).await.unwrap();
    assert_eq!(
        restored_protocol.handed(),
        0,
        "the entry was handed over again"
    );
    restored.receive(None).await.unwrap();
    assert_eq!(
        restored_protocol.handed(),
        0,
        "the entry was handed over again"
    );
    let id = restored.stored_id_at(seq).unwrap();
    let entry = listed(&mut restored, id).await.unwrap();
    assert_eq!(entry.reason, ParkReason::Uncertain);
    restored
        .release_parked(entry.stored_id, &entry.hash)
        .await
        .unwrap();
    restored.receive(None).await.unwrap();
    assert_eq!(restored_protocol.handed(), 1);
    assert_eq!(restored_protocol.released(), vec![true]);
}

#[tokio::test]
async fn test_parked_backup_of_a_released_kept_effect_never_hands_its_entry_over_again() {
    // A released entry's run applies its effect and loses the answer: the backup's copy is
    // uncertain (released kept). Restored past 31 days, its feed entry and its copy are
    // never handed over again until the host releases the copy again.
    let w = World::new();
    let protocol = ParkingProtocol::new(Mode::Plain);
    let mut app = wallet_on(&w, &protocol, Arc::clone(&w.store) as Arc<dyn StateStore>).await;
    let (entry, _) = uncertain(&w, &mut app).await;
    app.release_parked(entry.stored_id, &entry.hash)
        .await
        .unwrap();
    w.switch.fail_next(Fault::LoseAnswer { path: "ops".into() });
    assert!(app.receive(None).await.is_err());
    assert_eq!(
        app.state.pending_effect.as_ref().and_then(|p| p.stored),
        Some(entry.stored_id)
    );
    let effects = w.effects();
    let backup = app.backup_layered().await.unwrap();
    drop(app);
    w.clock.advance_ms(31 * DAY_MS);
    w.switch.lock().batches.clear();
    let restored_protocol = ParkingProtocol::new(Mode::Plain);
    let mut restored = App::restore(
        w.env_on(Arc::new(MemoryStore::new()) as Arc<dyn StateStore>),
        restored_protocol.clone(),
        World::config(),
        &backup,
    )
    .await
    .unwrap();
    assert!(!restored.state.seen.contains(&entry.seq));
    assert!(restored.cursor().seq >= entry.seq, "the entry was passed");
    restored.receive(None).await.unwrap();
    restored.receive(None).await.unwrap();
    assert_eq!(restored_protocol.handed(), 0, "handed over again");
    assert_eq!(w.effects(), effects);
    let copy = listed(&mut restored, entry.stored_id).await.unwrap();
    assert_eq!(copy.reason, ParkReason::Uncertain);
    restored
        .release_parked(copy.stored_id, &copy.hash)
        .await
        .unwrap();
    restored.receive(None).await.unwrap();
    assert_eq!(restored_protocol.handed(), 1);
    assert_eq!(restored_protocol.released(), vec![true]);
}

#[tokio::test]
async fn test_parked_backup_of_a_kept_effect_leaves_the_live_store_to_settle_it() {
    // The backup puts the kept effect's `seq` in its own `seen`, never the live one; the
    // live app's next read settles the effect, handing nothing over again.
    let w = World::new();
    let protocol = ParkingProtocol::new(Mode::Plain);
    let mut app = wallet_on(&w, &protocol, Arc::clone(&w.store) as Arc<dyn StateStore>).await;
    let (seq, _) = w.note(app.app_id(), "kept note");
    w.switch.fail_next(Fault::LoseAnswer { path: "ops".into() });
    assert!(app.receive(None).await.is_err());
    assert!(
        app.state
            .pending_effect
            .as_ref()
            .is_some_and(|p| p.seq == seq && p.stored.is_none())
    );
    let seen_before = app.state.seen.clone();
    let stored_before = app.reader().scan_numbers("seen/").await.unwrap();
    let backup = app.backup_layered().await.unwrap();
    assert!(
        backup
            .beyond_cursor
            .as_ref()
            .is_some_and(|beyond| beyond.seen.contains(&seq)),
        "the backup's seen lacks the kept effect's seq"
    );
    assert_eq!(app.state.seen, seen_before);
    assert!(!app.state.seen.contains(&seq));
    assert_eq!(
        app.reader().scan_numbers("seen/").await.unwrap(),
        stored_before
    );
    assert!(app.state.pending_effect.is_some());
    let report = app.receive(None).await.unwrap();
    assert!(app.state.pending_effect.is_none(), "the kept effect stayed");
    assert!(app.cursor().seq >= seq);
    assert!(has(
        &report.events,
        |e| matches!(e, AppEvent::MessageReceived { seq: s, .. } if *s == seq)
    ));
    assert_eq!(protocol.handed(), 1, "handed over again");
    assert_eq!(w.effects(), 1);
    // A load of the live store reads the same.
    drop(app);
    let app = load_on(&w, &protocol, Arc::clone(&w.store) as Arc<dyn StateStore>).await;
    assert!(app.state.pending_effect.is_none());
    assert!(!app.state.seen.contains(&seq));
}

async fn stored_copies(w: &World, app: &mut App, protocol: &ParkingProtocol) -> Message {
    let (_, message) = parked_as(w, app, protocol, Mode::Wide).await;
    protocol.set(Mode::Wide);
    let mut different = message.clone();
    different
        .body
        .insert("text".into(), Value::from("another body"));
    resend(w, app, &different);
    app.receive(None).await.unwrap();
    assert_eq!(app.parked_entries().await.unwrap().len(), 2);
    message
}

#[tokio::test]
async fn test_parked_processing_retires_all_copies_with_local_effect() {
    let w = World::new();
    let protocol = ParkingProtocol::new(Mode::Wide);
    let mut app = wallet_on(&w, &protocol, w.store.clone()).await;
    let (before, _) = parked_as(&w, &mut app, &protocol, Mode::Wide).await;
    let (_, message) = parked_as(&w, &mut app, &protocol, Mode::Wide).await;
    protocol.set(Mode::Wide);
    resend(&w, &app, &message);
    app.receive(None).await.unwrap();
    let (after, _) = parked_as(&w, &mut app, &protocol, Mode::Wide).await;
    let duties = app.unacknowledged_events().await.unwrap();
    let handed = protocol.handed();
    protocol.set(Mode::Local);
    resend(&w, &app, &message);
    app.receive(None).await.unwrap();
    assert_eq!(
        reasons(&mut app).await,
        vec![
            (before.stored_id, ParkReason::TooManyOperations),
            (after.stored_id, ParkReason::TooManyOperations),
        ]
    );
    assert_eq!(app.unacknowledged_events().await.unwrap(), duties);
    assert_eq!(protocol.handed(), handed + 1);
    assert!(processed(&app, &message).await);
    assert!(
        app.forget_processed("sample", w.bob.public(), &message.msg_id, &[])
            .await
            .unwrap()
    );
}

#[tokio::test]
async fn test_parked_processing_retires_conflicting_copies_after_effect_settles() {
    let w = World::new();
    let protocol = ParkingProtocol::new(Mode::Wide);
    let mut app = wallet_on(&w, &protocol, w.store.clone()).await;
    let message = stored_copies(&w, &mut app, &protocol).await;
    protocol.set(Mode::Plain);
    resend(&w, &app, &message);
    w.switch.fail_next(Fault::LoseAnswer { path: "ops".into() });
    assert!(app.receive(None).await.is_err());
    assert_eq!(app.parked_entries().await.unwrap().len(), 2);
    assert!(!processed(&app, &message).await);
    let applied = w.effects();
    let mut app = load_on(&w, &protocol, w.store.clone()).await;
    app.receive(None).await.unwrap();
    assert!(app.parked_entries().await.unwrap().is_empty());
    assert_eq!(w.effects(), applied);
    assert!(processed(&app, &message).await);
}

#[tokio::test]
async fn test_parked_processing_from_a_retry_retires_other_copies() {
    let w = World::new();
    let protocol = ParkingProtocol::new(Mode::Wide);
    let mut app = wallet_on(&w, &protocol, w.store.clone()).await;
    let (_, message) = parked_as(&w, &mut app, &protocol, Mode::Wide).await;
    protocol.set(Mode::Rejected);
    resend(&w, &app, &message);
    app.receive(None).await.unwrap();
    assert_eq!(app.parked_entries().await.unwrap().len(), 2);
    protocol.set(Mode::Local);
    app.receive(None).await.unwrap();
    assert!(app.parked_entries().await.unwrap().is_empty());
    assert!(processed(&app, &message).await);
}

#[tokio::test]
async fn test_parked_processed_copy_waiting_for_sender_is_dropped() {
    let w = World::new();
    let protocol = ParkingProtocol::new(Mode::Local);
    let mut app = wallet_on(&w, &protocol, w.store.clone()).await;
    let (_, message) = w.note(app.app_id(), "kept");
    app.receive(None).await.unwrap();
    w.homeserver.set_down(true);
    w.clock.advance_ms(11 * 60_000);
    let seq = resend(&w, &app, &message);
    let report = app.receive(None).await.unwrap();
    assert!(has(
        &report.events,
        |e| matches!(e, AppEvent::Duplicate { seq: got, conflicting: false } if *got == seq)
    ));
    assert!(app.state.held.is_empty());
    assert!(app.parked_entries().await.unwrap().is_empty());
}

#[tokio::test]
async fn test_parked_unprocessed_copy_does_not_prevent_forgetting_no_pair() {
    let w = World::new();
    let protocol = ParkingProtocol::new(Mode::Wide);
    let mut app = wallet_on(&w, &protocol, w.store.clone()).await;
    let (entry, message) = parked_as(&w, &mut app, &protocol, Mode::Wide).await;
    assert!(!processed(&app, &message).await);
    assert!(
        !app.forget_processed(
            "sample",
            w.bob.public(),
            &message.msg_id,
            &[LocalWrite::Put {
                key: b"evicted".to_vec(),
                value: b"yes".to_vec(),
            }]
        )
        .await
        .expect("an absent pair permits locals beside ordinary stored input")
    );
    assert!(listed(&mut app, entry.stored_id).await.is_some());
    assert_eq!(
        app.protocol_get("sample", b"evicted").await.unwrap(),
        Some(b"yes".to_vec())
    );
}

#[tokio::test]
async fn test_parked_processing_retires_copies_atomically_at_every_commit() {
    for stop_after in [false, true] {
        for n in 1..=8 {
            let w = World::new();
            let protocol = ParkingProtocol::new(Mode::Wide);
            let mut app = wallet_on(&w, &protocol, w.store.clone()).await;
            let message = stored_copies(&w, &mut app, &protocol).await;
            protocol.set(Mode::Local);
            resend(&w, &app, &message);
            let fault = Arc::new(FaultStore::new(
                w.store.clone(),
                if stop_after {
                    StoreFault::StopAfter(n)
                } else {
                    StoreFault::StopBefore(n)
                },
            ));
            let mut app = load_on(&w, &protocol, fault).await;
            let _ = app.receive(None).await;
            let mut app = load_on(&w, &protocol, w.store.clone()).await;
            let applied = processed(&app, &message).await;
            assert_eq!(
                app.parked_entries().await.unwrap().len(),
                if applied { 0 } else { 2 },
                "commit {n}, after {stop_after}"
            );
            let local = app
                .reader()
                .get_raw(format!("p/sample/notes/{}", message.msg_id).as_bytes())
                .await
                .unwrap();
            assert_eq!(
                local.is_some(),
                applied,
                "the processed pair and local effect share the completion commit"
            );
            app.receive(None).await.unwrap();
            assert!(app.parked_entries().await.unwrap().is_empty());
            assert!(processed(&app, &message).await);
        }
    }
}

#[tokio::test]
async fn test_parked_processing_keeps_the_same_id_from_another_sender() {
    let w = World::new();
    let phone = app_keys("phone");
    let phone_app = w.join("phone").await;
    let protocol = ParkingProtocol::new(Mode::Wide);
    let mut app = wallet_on(&w, &protocol, w.store.clone()).await;
    let message = stored_copies(&w, &mut app, &protocol).await;
    let mut own = message.clone();
    own.kind = "sample.notice".into();
    own.from = pubky_switch_core::message::Sender::of_app(w.alice.public(), &phone);
    let cert = phone_app.cert().clone();
    let seq = w
        .switch
        .send_plaintext(
            w.alice.public(),
            &cert,
            &own.sign(&phone).unwrap(),
            &[app.app_id()],
        )
        .unwrap();
    app.receive(None).await.unwrap();
    let other = app.stored_id_at(seq).unwrap();
    protocol.set(Mode::Local);
    resend(&w, &app, &message);
    let report = app.receive(None).await.unwrap();
    assert!(has(&report.events, |event| matches!(
        event,
        AppEvent::Duplicate {
            conflicting: true,
            ..
        }
    )));
    assert_eq!(
        reasons(&mut app).await,
        vec![(other, ParkReason::TooManyOperations)]
    );
}

#[tokio::test]
async fn test_parked_processed_pair_drops_unchecked_changed_bytes_without_conflict() {
    let w = World::new();
    let protocol = ParkingProtocol::new(Mode::Local);
    let mut app = wallet_on(&w, &protocol, w.store.clone()).await;
    let (_, message) = w.note(app.app_id(), "kept");
    app.receive(None).await.unwrap();
    let keys = app_keys("unlisted-app");
    let cert = cert_for(&w.bob, &keys, w.clock.now_ms(), &["sample-a"]);
    let mut changed = message.clone();
    changed.from = pubky_switch_core::message::Sender::of_app(w.bob.public(), &keys);
    changed.body.insert("text".into(), Value::from("changed"));
    w.homeserver.set_down(true);
    w.clock.advance_ms(11 * 60_000);
    let seq = w
        .switch
        .send_plaintext(
            w.bob.public(),
            &cert,
            &changed.sign(&keys).unwrap(),
            &[app.app_id()],
        )
        .unwrap();
    let report = app.receive(None).await.unwrap();
    assert!(has(
        &report.events,
        |e| matches!(e, AppEvent::MessageDropped { seq: got, check: 9, .. } if *got == seq)
    ));
    assert!(!has(&report.events, |e| matches!(
        e,
        AppEvent::Duplicate {
            conflicting: true,
            ..
        }
    )));
    assert!(app.state.held.is_empty());
    assert!(app.parked_entries().await.unwrap().is_empty());
    assert_eq!(protocol.handed(), 1);
}

#[tokio::test]
async fn test_parked_processing_refused_effect_keeps_copies_until_success() {
    let w = World::new();
    let protocol = ParkingProtocol::new(Mode::Wide);
    let mut app = wallet_on(&w, &protocol, w.store.clone()).await;
    let message = stored_copies(&w, &mut app, &protocol).await;
    protocol.set(Mode::Plain);
    resend(&w, &app, &message);
    w.switch.fail_next(Fault::Error {
        path: "ops".into(),
        code: pubky_switch_core::http::ErrorCode::QuotaExceeded,
        current: serde_json::json!({}),
    });
    app.receive(None).await.unwrap();
    assert_eq!(app.parked_entries().await.unwrap().len(), 3);
    assert!(!processed(&app, &message).await);
    protocol.set(Mode::Local);
    app.receive(None).await.unwrap();
    assert!(app.parked_entries().await.unwrap().is_empty());
    assert!(processed(&app, &message).await);
}

#[tokio::test]
async fn test_parked_processing_backup_keeps_unknown_effect_and_copies() {
    let w = World::new();
    let protocol = ParkingProtocol::new(Mode::Wide);
    let mut app = wallet_on(&w, &protocol, w.store.clone()).await;
    let message = stored_copies(&w, &mut app, &protocol).await;
    protocol.set(Mode::Plain);
    resend(&w, &app, &message);
    w.switch.fail_next(Fault::LoseAnswer { path: "ops".into() });
    assert!(app.receive(None).await.is_err());
    let backup = app.backup_layered().await.unwrap();
    let mut restored = App::restore(
        w.env_on(Arc::new(MemoryStore::new())),
        protocol.clone(),
        World::config(),
        &backup,
    )
    .await
    .unwrap();
    let applied = w.effects();
    restored.receive(None).await.unwrap();
    let entries = restored.parked_entries().await.unwrap();
    assert_eq!(entries.len(), 3);
    assert_eq!(
        entries
            .iter()
            .filter(|entry| entry.reason == ParkReason::Uncertain)
            .count(),
        1
    );
    assert_eq!(w.effects(), applied);
    assert!(matches!(
        restored
            .forget_processed("sample", w.bob.public(), &message.msg_id, &[])
            .await,
        Err(AppError::Refused(Refusal::NotNow(_)))
    ));
    app.receive(None).await.unwrap();
    assert!(app.parked_entries().await.unwrap().is_empty());
    assert_eq!(w.effects(), applied);
}

async fn rejected_completion(mode: Mode) {
    let w = World::new();
    let protocol = ParkingProtocol::new(Mode::Wide);
    let mut app = wallet_on(&w, &protocol, w.store.clone()).await;
    let message = stored_copies(&w, &mut app, &protocol).await;
    let duties = app.unacknowledged_events().await.unwrap();
    protocol.set(mode);
    resend(&w, &app, &message);
    app.receive(None).await.unwrap();
    assert!(
        app.parked_entries().await.unwrap().is_empty(),
        "rejection completes all eligible copies"
    );
    assert!(processed(&app, &message).await);
    assert_eq!(app.unacknowledged_events().await.unwrap(), duties);
    assert_eq!(w.effects(), 0);
}

#[tokio::test]
async fn test_parked_drop_completion_retires_other_copies() {
    rejected_completion(Mode::Drop).await;
}

#[tokio::test]
async fn test_parked_body_rejection_retires_other_copies() {
    rejected_completion(Mode::RejectBody).await;
}

#[tokio::test]
async fn test_parked_absent_pair_locals_commit_atomically_across_reload() {
    for after in [false, true] {
        let w = World::new();
        let protocol = ParkingProtocol::new(Mode::Wide);
        let mut app = wallet_on(&w, &protocol, w.store.clone()).await;
        let (entry, message) = parked_as(&w, &mut app, &protocol, Mode::Wide).await;
        let duties = app.unacknowledged_events().await.unwrap();
        app.protocol_commit(
            "sample",
            &[LocalWrite::Put {
                key: b"retained".to_vec(),
                value: b"old".to_vec(),
            }],
        )
        .await
        .unwrap();
        let fault = Arc::new(FaultStore::new(
            w.store.clone(),
            if after {
                StoreFault::FailAfter(1)
            } else {
                StoreFault::FailBefore(1)
            },
        ));
        let mut app = load_on(&w, &protocol, fault.clone()).await;
        let local = [
            LocalWrite::Put {
                key: b"evicted".to_vec(),
                value: b"yes".to_vec(),
            },
            LocalWrite::Delete {
                key: b"retained".to_vec(),
            },
        ];
        let result = app
            .forget_processed("sample", w.bob.public(), &message.msg_id, &local)
            .await;
        assert!(
            matches!(
                result,
                Err(AppError::Store(
                    StoreError::Unknown | StoreError::Unavailable
                ))
            ),
            "{result:?}"
        );
        assert_eq!(
            fault.commits(),
            1,
            "the local decision reached its atomic commit"
        );
        let restored = load_on(&w, &protocol, w.store.clone()).await;
        assert_eq!(
            restored
                .protocol_get("sample", b"evicted")
                .await
                .unwrap()
                .is_some(),
            after
        );
        assert_eq!(
            restored
                .protocol_get("sample", b"retained")
                .await
                .unwrap()
                .is_none(),
            after,
            "the retained value and its drop mark change in one local decision"
        );
        assert!(!processed(&restored, &message).await);
        assert!(
            !app.forget_processed("sample", w.bob.public(), &message.msg_id, &local)
                .await
                .unwrap()
        );
        assert_eq!(
            app.protocol_get("sample", b"evicted").await.unwrap(),
            Some(b"yes".to_vec())
        );
        assert!(listed(&mut app, entry.stored_id).await.is_some());
        assert_eq!(app.unacknowledged_events().await.unwrap(), duties);
        let backup = app.backup_layered().await.unwrap();
        let mut restored = App::restore(
            w.env_on(Arc::new(MemoryStore::new())),
            protocol,
            World::config(),
            &backup,
        )
        .await
        .unwrap();
        assert!(listed(&mut restored, entry.stored_id).await.is_some());
        assert!(!processed(&restored, &message).await);
        assert_eq!(
            restored.protocol_get("sample", b"evicted").await.unwrap(),
            Some(b"yes".to_vec())
        );
    }
}

#[tokio::test]
async fn test_parked_forget_preserves_pending_and_uncertain_effect_locals() {
    let w = World::new();
    let protocol = ParkingProtocol::new(Mode::Plain);
    let mut app = wallet_on(&w, &protocol, w.store.clone()).await;
    let (_, message) = w.note(app.app_id(), "pending");
    w.switch.fail_next(Fault::LoseAnswer { path: "ops".into() });
    assert!(app.receive(None).await.is_err());
    assert!(!processed(&app, &message).await);
    let local = [LocalWrite::Put {
        key: b"evicted".to_vec(),
        value: b"yes".to_vec(),
    }];
    assert!(
        matches!(
            app.forget_processed("sample", w.bob.public(), &message.msg_id, &local)
                .await,
            Err(AppError::Refused(Refusal::NotNow(_)))
        ),
        "pending effect protects the absent pair"
    );
    assert!(
        app.protocol_get("sample", b"evicted")
            .await
            .unwrap()
            .is_none()
    );
    let backup = app.backup_layered().await.unwrap();
    let mut restored = App::restore(
        w.env_on(Arc::new(MemoryStore::new())),
        protocol,
        World::config(),
        &backup,
    )
    .await
    .unwrap();
    restored.receive(None).await.unwrap();
    let entry = restored.parked_entries().await.unwrap().pop().unwrap();
    assert_eq!(entry.reason, ParkReason::Uncertain);
    assert!(
        matches!(
            restored
                .forget_processed("sample", w.bob.public(), &message.msg_id, &local)
                .await,
            Err(AppError::Refused(Refusal::NotNow(_)))
        ),
        "uncertainty protects its held pair"
    );
    assert!(
        restored
            .protocol_get("sample", b"evicted")
            .await
            .unwrap()
            .is_none()
    );
    w.clock.advance_ms(super::super::PROCESSED_RETENTION_MS + 1);
    restored.receive(None).await.unwrap();
    assert!(
        !processed(&restored, &message).await,
        "the ordinary retention path removes the pair"
    );
    assert!(
        matches!(
            restored
                .forget_processed("sample", w.bob.public(), &message.msg_id, &local)
                .await,
            Err(AppError::Refused(Refusal::NotNow(_)))
        ),
        "uncertainty still protects locals after pair retention"
    );
    assert!(
        restored
            .protocol_get("sample", b"evicted")
            .await
            .unwrap()
            .is_none()
    );
    assert!(listed(&mut restored, entry.stored_id).await.is_some());
}

#[tokio::test]
async fn test_parked_completion_keeps_release_ended_and_existing_duties() {
    let w = World::new();
    let protocol = ParkingProtocol::new(Mode::Wide);
    let mut app = wallet_on(&w, &protocol, w.store.clone()).await;
    let message = stored_copies(&w, &mut app, &protocol).await;
    protocol.set(Mode::Plain);
    resend(&w, &app, &message);
    w.switch.fail_next(Fault::LoseAnswer { path: "ops".into() });
    assert!(app.receive(None).await.is_err());
    let backup = app.backup_layered().await.unwrap();
    let mut restored = App::restore(
        w.env_on(Arc::new(MemoryStore::new())),
        protocol.clone(),
        World::config(),
        &backup,
    )
    .await
    .unwrap();
    restored.receive(None).await.unwrap();
    let entry = restored
        .parked_entries()
        .await
        .unwrap()
        .into_iter()
        .find(|entry| entry.reason == ParkReason::Uncertain)
        .unwrap();
    let duties = restored.unacknowledged_events().await.unwrap();
    restored
        .release_parked(entry.stored_id, &entry.hash)
        .await
        .unwrap();
    protocol.set(Mode::RetryFirstStoredRun);
    resend(&w, &restored, &message);
    restored.receive(None).await.unwrap();
    assert!(
        restored.parked_entries().await.unwrap().is_empty(),
        "the completed copy retires the released sibling"
    );
    let owed = restored.unacknowledged_events().await.unwrap();
    assert!(
        duties.iter().all(|duty| owed.contains(duty)),
        "earlier duties stay owed"
    );
    assert!(
        has(
            &owed,
            |event| matches!(event, AppEvent::ReleasedDuplicate { stored_id, .. } if *stored_id == entry.stored_id)
        ),
        "retired release keeps its durable completion notice"
    );
}

#[tokio::test]
async fn test_parked_completion_keeps_an_independently_uncertain_copy() {
    let w = World::new();
    let protocol = ParkingProtocol::new(Mode::Plain);
    let mut app = wallet_on(&w, &protocol, w.store.clone()).await;
    let (_, mut message) = w.note(app.app_id(), "uncertain");
    w.switch.fail_next(Fault::LoseAnswer { path: "ops".into() });
    assert!(app.receive(None).await.is_err());
    let backup = app.backup_layered().await.unwrap();
    let mut restored = App::restore(
        w.env_on(Arc::new(MemoryStore::new())),
        protocol.clone(),
        World::config(),
        &backup,
    )
    .await
    .unwrap();
    restored.receive(None).await.unwrap();
    let original = restored.parked_entries().await.unwrap().pop().unwrap();
    assert_eq!(original.reason, ParkReason::Uncertain);
    w.clock.advance_ms(super::super::PROCESSED_RETENTION_MS + 1);
    restored.receive(None).await.unwrap();
    assert!(!processed(&restored, &message).await);
    // A newly signed copy after pair retention is judged by the protocol's own state.
    message.created_at_ms = w.clock.now_ms();
    message
        .body
        .insert("text".into(), Value::from("a new copy"));
    protocol.set(Mode::Local);
    resend(&w, &restored, &message);
    restored.receive(None).await.unwrap();
    assert!(
        processed(&restored, &message).await,
        "the eligible new copy completed"
    );
    let kept = listed(&mut restored, original.stored_id).await;
    assert_eq!(
        kept,
        Some(original),
        "completion cannot resolve an independently uncertain effect"
    );
}

#[tokio::test]
async fn test_parked_move_settlement_retires_prior_copies() {
    use super::moves::{NEXT, Router, freeze_for, next_key, publish_at};

    let w = World::new();
    let router = Router::of(&w);
    let protocol = ParkingProtocol::new(Mode::Wide);
    let request = w.approve(&app_keys("wallet"), &["sample-a"]);
    let mut app = App::join(
        router.env(&w, w.store.clone()),
        protocol.clone(),
        World::config(),
        request,
    )
    .await
    .unwrap();
    let message = stored_copies(&w, &mut app, &protocol).await;
    let stored = app.parked_entries().await.unwrap();
    let duties = app.unacknowledged_events().await.unwrap();
    assert_eq!(stored.len(), 2);
    assert!(
        stored
            .iter()
            .all(|entry| entry.reason == ParkReason::TooManyOperations)
    );
    assert!(!processed(&app, &message).await);

    protocol.set(Mode::Plain);
    let seq = resend(&w, &app, &message);
    w.switch.fail_next(Fault::LoseAnswer { path: "ops".into() });
    assert!(app.receive(None).await.is_err());
    app.ready_local().await.unwrap();
    assert_eq!(app.parked_entries().await.unwrap(), stored);
    assert!(!processed(&app, &message).await);
    let pending = app.state.pending_effect.as_ref().unwrap();
    assert_eq!(pending.seq, seq);
    assert_eq!(pending.stored, None);
    let effects = w.effects();
    assert_eq!(effects, 1);

    let n_key = next_key();
    w.switch.freeze(&freeze_for(&w, &n_key, 2)).unwrap();
    let next = w.switch.import_into(n_key.to_bytes());
    router.add(NEXT, &next);
    publish_at(
        &w,
        &next,
        Inbox::new(NEXT, n_key.verifying_key().to_bytes()),
        2,
        None,
    );
    let report = app.receive(None).await.unwrap();
    assert!(has(&report.events, |event| matches!(
        event,
        AppEvent::ProviderFollowed { generation: 2 }
    )));
    assert!(has(&report.events, |event| matches!(
        event,
        AppEvent::MessageReceived { seq: got, .. } if *got == seq
    )));
    assert!(app.state.pending_effect.is_none());
    assert!(processed(&app, &message).await);
    assert_eq!(w.effects(), effects);
    assert_eq!(
        app.protocol_get("sample", format!("notes/{}", message.msg_id).as_bytes())
            .await
            .unwrap(),
        Some(b"parked note".to_vec())
    );
    assert_eq!(app.unacknowledged_events().await.unwrap(), duties);

    let me = app.app_id();
    let mut loaded = App::load(
        router.env(&w, w.store.clone()),
        protocol,
        World::config(),
        me,
    )
    .await
    .unwrap();
    assert!(processed(&loaded, &message).await);
    assert!(
        loaded.parked_entries().await.unwrap().is_empty(),
        "provider settlement retires eligible prior copies with its completed local effect"
    );
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CompletionPoint {
    Effect,
    Provider,
}

/// Observe the separate effect and provider transactions and fail exactly the chosen one.
struct CompletionStore {
    inner: Arc<dyn StateStore>,
    pair: Vec<u8>,
    fault: Mutex<StoreFault>,
    at: CompletionPoint,
    completed: Mutex<Vec<crate::store::WriteBatch>>,
    providers: Mutex<Vec<crate::store::WriteBatch>>,
}

impl CompletionStore {
    fn new(
        inner: Arc<dyn StateStore>,
        message: &Message,
        fault: StoreFault,
        at: CompletionPoint,
    ) -> Arc<Self> {
        Arc::new(Self {
            inner,
            pair: crate::app::state::key::processed(&message.from.identity, &message.msg_id)
                .into_bytes(),
            fault: Mutex::new(fault),
            at,
            completed: Mutex::new(Vec::new()),
            providers: Mutex::new(Vec::new()),
        })
    }
}

impl StateStore for CompletionStore {
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
        use crate::store::Write;
        let puts = |wanted: &[u8]| {
            batch
                .writes()
                .iter()
                .any(|write| matches!(write, Write::Put { key, .. } if key == wanted))
        };
        let point = if puts(&self.pair) {
            self.completed.lock().unwrap().push(batch.clone());
            Some(CompletionPoint::Effect)
        } else if puts(crate::app::state::key::META.as_bytes()) {
            self.providers.lock().unwrap().push(batch.clone());
            Some(CompletionPoint::Provider)
        } else {
            None
        };
        if point != Some(self.at) {
            return self.inner.commit(batch);
        }
        let fault = std::mem::replace(&mut *self.fault.lock().unwrap(), StoreFault::None);
        match fault {
            StoreFault::FailBefore(1) => Err(StoreError::Unavailable),
            StoreFault::FailAfter(1) => {
                self.inner.commit(batch)?;
                Err(StoreError::Unknown)
            }
            StoreFault::None => self.inner.commit(batch),
            _ => panic!("the completion store fails only its selected transaction"),
        }
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
        use crate::store::Write;
        let puts = |wanted: &[u8]| {
            batch
                .writes()
                .iter()
                .any(|write| matches!(write, Write::Put { key, .. } if key == wanted))
        };
        let point = if puts(&self.pair) {
            self.completed.lock().unwrap().push(batch.clone());
            Some(CompletionPoint::Effect)
        } else if puts(crate::app::state::key::META.as_bytes()) {
            self.providers.lock().unwrap().push(batch.clone());
            Some(CompletionPoint::Provider)
        } else {
            None
        };
        if point != Some(self.at) {
            return self.inner.commit_if(ns, owner, batch);
        }
        let fault = std::mem::replace(&mut *self.fault.lock().unwrap(), StoreFault::None);
        match fault {
            StoreFault::FailBefore(1) => Err(StoreError::Unavailable),
            StoreFault::FailAfter(1) => {
                self.inner.commit_if(ns, owner, batch)?;
                Err(StoreError::Unknown)
            }
            StoreFault::None => self.inner.commit_if(ns, owner, batch),
            _ => panic!("the completion store fails only its selected transaction"),
        }
    }
}

struct PendingCompletion {
    world: World,
    router: super::moves::Router,
    protocol: Arc<ParkingProtocol>,
    app: App,
    message: Message,
    store: Arc<dyn StateStore>,
}

impl PendingCompletion {
    async fn new() -> Self {
        let world = World::new();
        let router = super::moves::Router::of(&world);
        let protocol = ParkingProtocol::new(Mode::Wide);
        let store: Arc<dyn StateStore> = world.store.clone();
        let request = world.approve(&app_keys("wallet"), &["sample-a"]);
        let mut app = App::join(
            router.env(&world, store.clone()),
            protocol.clone(),
            World::config(),
            request,
        )
        .await
        .unwrap();
        let message = stored_copies(&world, &mut app, &protocol).await;
        Self {
            world,
            router,
            protocol,
            app,
            message,
            store,
        }
    }

    async fn send_without_answer(&mut self) {
        self.protocol.set(Mode::Plain);
        resend(&self.world, &self.app, &self.message);
        self.world
            .switch
            .fail_next(Fault::LoseAnswer { path: "ops".into() });
        assert!(self.app.receive(None).await.is_err());
        self.app.ready_local().await.unwrap();
        assert!(self.app.state.pending_effect.is_some());
        assert!(!processed(&self.app, &self.message).await);
    }

    fn publish_move(&self) {
        use super::moves::{NEXT, freeze_for, next_key, publish_at};
        let key = next_key();
        self.world
            .switch
            .freeze(&freeze_for(&self.world, &key, 2))
            .unwrap();
        let next = self.world.switch.import_into(key.to_bytes());
        self.router.add(NEXT, &next);
        publish_at(
            &self.world,
            &next,
            Inbox::new(NEXT, key.verifying_key().to_bytes()),
            2,
            None,
        );
    }

    async fn reload(&mut self, store: Arc<dyn StateStore>) {
        self.app = App::load(
            self.router.env(&self.world, store),
            self.protocol.clone(),
            World::config(),
            self.app.app_id(),
        )
        .await
        .unwrap();
    }

    async fn add_uncertain_copy(&mut self) -> ParkedSummary {
        self.send_without_answer().await;
        let backup = self.app.backup_layered().await.unwrap();
        self.store = Arc::new(MemoryStore::new());
        self.app = App::restore(
            self.router.env(&self.world, self.store.clone()),
            self.protocol.clone(),
            World::config(),
            &backup,
        )
        .await
        .unwrap();
        self.app.receive(None).await.unwrap();
        let copy = self
            .app
            .parked_entries()
            .await
            .unwrap()
            .into_iter()
            .find(|entry| entry.reason == ParkReason::Uncertain)
            .unwrap();
        self.world
            .clock
            .advance_ms(crate::app::PROCESSED_RETENTION_MS + 1);
        self.app.receive(None).await.unwrap();
        assert!(!processed(&self.app, &self.message).await);
        self.message.created_at_ms = self.world.clock.now_ms();
        copy
    }
}

#[tokio::test]
async fn test_provider_completion_preserves_independent_uncertainty() {
    let mut pending = PendingCompletion::new().await;
    let uncertain = pending.add_uncertain_copy().await;
    pending.send_without_answer().await;
    let duties = pending.app.unacknowledged_events().await.unwrap();
    let effects = pending.world.effects();
    pending.publish_move();
    pending.app.receive(None).await.unwrap();
    pending.reload(pending.store.clone()).await;
    assert!(processed(&pending.app, &pending.message).await);
    assert!(pending.app.state.pending_effect.is_none());
    assert_eq!(pending.world.effects(), effects);
    assert_eq!(
        pending.app.parked_entries().await.unwrap(),
        vec![uncertain],
        "provider completion preserves the independently uncertain copy only"
    );
    assert_eq!(pending.app.unacknowledged_events().await.unwrap(), duties);
}

#[tokio::test]
async fn test_provider_completion_release_remains_owed() {
    let mut pending = PendingCompletion::new().await;
    let uncertain = pending.add_uncertain_copy().await;
    // The effect's pre-send reservation includes this later host release.
    pending.send_without_answer().await;
    pending
        .app
        .release_parked(uncertain.stored_id, &uncertain.hash)
        .await
        .unwrap();
    let duties = pending.app.unacknowledged_events().await.unwrap();
    let store = CompletionStore::new(
        pending.store.clone(),
        &pending.message,
        StoreFault::None,
        CompletionPoint::Effect,
    );
    pending.reload(store.clone()).await;
    pending.publish_move();
    pending.app.receive(None).await.unwrap();
    pending.reload(pending.store.clone()).await;
    assert!(
        pending.app.parked_entries().await.unwrap().is_empty(),
        "provider completion retires the released copy"
    );
    let owed = pending.app.unacknowledged_events().await.unwrap();
    assert!(duties.iter().all(|duty| owed.contains(duty)));
    assert!(
        has(
            &owed,
            |event| matches!(event, AppEvent::ReleasedDuplicate { stored_id, .. }
        if *stored_id == uncertain.stored_id)
        ),
        "provider retirement keeps the release-ended duty"
    );
    let batches = store.completed.lock().unwrap();
    assert_eq!(batches.len(), 1);
    let batch = &batches[0];
    use crate::store::Write;
    assert!(
        !batch
            .writes()
            .iter()
            .any(|write| matches!(write, Write::Put { key, .. } if key == b"meta")),
        "effect completion precedes the provider transaction"
    );
    assert!(batch.writes().iter().any(
        |write| matches!(write, Write::Put { key, .. } if key.starts_with(b"p/sample/notes/"))
    ));
    assert!(
        batch
            .writes()
            .iter()
            .any(|write| matches!(write, Write::Delete { key, .. } if key.starts_with(b"parked/")))
    );
    assert!(
        batch
            .writes()
            .iter()
            .any(|write| matches!(write, Write::Put { key, .. } if key.starts_with(b"duty/")))
    );
    let retirement: u64 = batch
        .writes()
        .iter()
        .filter(|write| match write {
            Write::Delete { key, .. } => key.starts_with(b"parked/") || key.starts_with(b"sretry/"),
            Write::Put { key, .. } => {
                key.starts_with(b"duty/") || key == crate::app::state::key::DUTY_NEXT.as_bytes()
            }
            _ => false,
        })
        .map(Write::size)
        .sum();
    assert!(retirement > 0);
    assert!(
        batch
            .writes()
            .iter()
            .any(|write| matches!(write, Write::Delete { key, .. }
        if key == crate::app::state::key::PENDING_EFFECT.as_bytes()))
    );
    assert_eq!(store.providers.lock().unwrap().len(), 1);
    assert!(batch.size() <= crate::store::MAX_BATCH_BYTES);
}

#[tokio::test]
async fn test_provider_completion_failure_and_unknown_are_atomic() {
    for at in [CompletionPoint::Effect, CompletionPoint::Provider] {
        for fault in [StoreFault::FailBefore(1), StoreFault::FailAfter(1)] {
            for fresh in [false, true] {
                let mut pending = PendingCompletion::new().await;
                let released = pending.add_uncertain_copy().await;
                pending.send_without_answer().await;
                pending
                    .app
                    .release_parked(released.stored_id, &released.hash)
                    .await
                    .unwrap();
                let effects = pending.world.effects();
                let before = pending.app.parked_entries().await.unwrap();
                let duties = pending.app.unacknowledged_events().await.unwrap();
                let cursor_to = pending
                    .app
                    .state
                    .pending_effect
                    .as_ref()
                    .unwrap()
                    .cursor_to
                    .unwrap();
                let store =
                    CompletionStore::new(pending.store.clone(), &pending.message, fault, at);
                pending.reload(store.clone()).await;
                pending.publish_move();
                let error = pending.app.receive(None).await.unwrap_err();
                assert!(matches!(
                    error,
                    AppError::Store(StoreError::Unavailable | StoreError::Unknown)
                ));
                assert_eq!(
                    store.completed.lock().unwrap().len(),
                    1,
                    "the effect commit was reached"
                );
                assert_eq!(
                    store.providers.lock().unwrap().len(),
                    usize::from(at == CompletionPoint::Provider),
                    "the provider commit follows successful effect completion"
                );
                let mut loaded = App::load(
                    pending.router.env(&pending.world, store.clone()),
                    pending.protocol.clone(),
                    World::config(),
                    pending.app.app_id(),
                )
                .await
                .unwrap();
                let effect_done =
                    at == CompletionPoint::Provider || matches!(fault, StoreFault::FailAfter(_));
                let provider_done =
                    at == CompletionPoint::Provider && matches!(fault, StoreFault::FailAfter(_));
                assert_eq!(processed(&loaded, &pending.message).await, effect_done);
                assert_eq!(
                    loaded
                        .protocol_get(
                            "sample",
                            format!("notes/{}", pending.message.msg_id).as_bytes()
                        )
                        .await
                        .unwrap()
                        .is_some(),
                    effect_done
                );
                assert_eq!(
                    loaded.parked_entries().await.unwrap(),
                    if effect_done { vec![] } else { before },
                    "pair, local effect and eligible retirement share the standalone completion"
                );
                assert_eq!(
                    loaded.state.meta.generation,
                    if provider_done { 2 } else { 1 }
                );
                assert_eq!(loaded.state.pending_effect.is_none(), effect_done);
                if effect_done {
                    assert!(
                        loaded.state.cursor.at_service >= cursor_to,
                        "completion preserves the applied pending cursor move"
                    );
                }
                let owed = loaded.unacknowledged_events().await.unwrap();
                assert!(duties.iter().all(|duty| owed.contains(duty)));
                assert_eq!(
                    has(
                        &owed,
                        |event| matches!(event, AppEvent::ReleasedDuplicate { stored_id, .. }
                    if *stored_id == released.stored_id)
                    ),
                    effect_done,
                    "the release-ended duty shares the completion commit"
                );
                if fresh {
                    pending.app = loaded;
                }
                pending.app.receive(None).await.unwrap();
                assert!(pending.app.parked_entries().await.unwrap().is_empty());
                assert!(processed(&pending.app, &pending.message).await);
                assert_eq!(
                    pending.world.effects(),
                    effects,
                    "recovery never repeats the remote effect"
                );
                // A failed effect commit retries it; a committed effect is never written again.
                let expected = if at == CompletionPoint::Effect
                    && matches!(fault, StoreFault::FailBefore(_))
                {
                    2
                } else {
                    1
                };
                assert_eq!(
                    store.completed.lock().unwrap().len(),
                    expected,
                    "a durable local completion is not repeated"
                );
            }
        }
    }
}

#[tokio::test]
async fn test_provider_loss_completion_retires_prior_copies() {
    let mut pending = PendingCompletion::new().await;
    pending.send_without_answer().await;
    let store = CompletionStore::new(
        pending.store.clone(),
        &pending.message,
        StoreFault::FailBefore(1),
        CompletionPoint::Effect,
    );
    pending.reload(store.clone()).await;
    pending.publish_move();
    assert!(pending.app.receive(None).await.is_err());
    assert_eq!(store.completed.lock().unwrap().len(), 1);
    // The old authenticated chain is retained, but neither completion nor the provider
    // transaction committed. A declared loss supersedes the follow (Switch spec 12.6).
    pending.reload(pending.store.clone()).await;
    assert_eq!(pending.app.state.meta.generation, 1);
    assert!(pending.app.state.pending_effect.is_some());
    let key = super::moves::next_key();
    let next = ScriptedSwitch::recovering(
        &pending.world.alice,
        key.to_bytes(),
        pending.world.clock.clone(),
        3,
        1,
    )
    .unwrap();
    pending.router.add(super::moves::NEXT, &next);
    super::moves::publish_at(
        &pending.world,
        &next,
        Inbox::new(super::moves::NEXT, key.verifying_key().to_bytes()),
        3,
        Some(1),
    );
    pending.world.switch.lock().not_hosted_unpinned = true;
    pending.app.refresh_identity().await.unwrap();
    pending.app.receive(None).await.unwrap();
    pending.reload(pending.store.clone()).await;
    assert_eq!(pending.app.state.meta.generation, 3);
    assert!(processed(&pending.app, &pending.message).await);
    assert!(pending.app.state.pending_effect.is_none());
    assert!(
        pending.app.parked_entries().await.unwrap().is_empty(),
        "ordinary loss settlement retires eligible prior copies"
    );
    assert_eq!(pending.world.effects(), 1);
}
