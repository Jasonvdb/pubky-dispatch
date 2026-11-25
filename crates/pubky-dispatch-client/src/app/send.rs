//! Sending (Dispatch spec 7, 8.1, 8.2, 11; Dispatch wire 4.3, 5.1, 7.4.3, 7.4.5).
//!
//! A message is signed once and recorded in the durable outbox (`out/<msg_id>`) before
//! anything is sent, with its jobs: the reply grant a first message to a
//! counterparty that isn't a kept peer needs when the protocol admits it, the
//! delivery, and the matching shared record write the protocol names. Each job is retried
//! until it completes or a bound ends it, at the flushes of the outbox
//! ([`App::flush_outbox`], which goes round it at most [`OUTBOX_TRIES_PER_FLUSH`] messages
//! a call); every step commits before the next one acts on the network:
//!
//! 1. **The reply grant** (`allow.put`, kept under `opq/` until answered, Dispatch spec
//!    7) is written before the message is sent.
//! 2. **The own `identity.json`** goes to the counterparty's Dispatch before the first append
//!    there (Dispatch spec 6.1).
//! 3. **Sealing**: the signed plaintext is sealed to every recipient app the directory gives
//!    (Dispatch spec 8.1), and the envelope is committed with the `apps_version` it was sealed
//!    for before it is sent. Immediately before the first transport append, `envelope_sent`
//!    and a replay deadline (`SENT_RETENTION_MS` less `CLOCK_TOLERANCE_MS` from the device
//!    clock then, unless the item already carries one from a restore, [`App::queue_stored`],
//!    or a re-send) commit together; a message never yet tried has no replay deadline. Every
//!    retry sends those bytes, so a Dispatch that took it answers the original result while it
//!    still holds the entry (Dispatch wire 7.4.3 step 1): a crash never sends twice. Later
//!    retries check the deadline against the later of device time and verified service time,
//!    and past it give the delivery up as [`AppEvent::DeliveryUnknown`] (or
//!    [`AppEvent::MessageUndelivered`] with `resend: true` for a re-send), because the
//!    recipient may no longer keep the processed pair (Dispatch spec 11).
//! 4. **The append** names the `apps_version`. `409 stale_key` has the records checked and
//!    the same signed plaintext sealed again; `409 identity_needed` has the own
//!    `identity.json` delivered and the append retried; `410 moved` has the counterparty's
//!    `identity.json` read again; `429` and `503` wait for the next flush.
//! 5. **The record job** builds the record's next value through the protocol
//!    ([`super::Protocol::sent_record`]), compare-and-swap. One still not made
//!    [`SENT_RETENTION_MS`] after the message's first acceptance, such as one whose held
//!    value waits for a key that never comes, is given up, and the protocol told
//!    ([`AppEvent::RecordJobDropped`]): the outbox doesn't keep the message for ever. A
//!    job whose earlier try left a batch kept settles it first: once it applied, the job is
//!    done. A job never writes over a delete its protocol hasn't seen: when the app takes a
//!    delete of the record that the job wasn't queued against, the job stops and the
//!    protocol is told ([`AppEvent::RecordJobStopped`]), to decide again.
//!
//! The acceptance is committed as soon as the append is answered, before anything else is
//! done with the answer, so a crash never sends the same bytes again: with it the message
//! goes to `sent/<msg_id>`, kept 30 days from its first acceptance for re-sends (Dispatch spec
//! 11), which seal the same signed plaintext to the current keys ([`App::resend`]), also
//! while its record job is still owed. When an item with no earlier deadline is accepted in
//! the try that first sent it, every earlier append of that try a verified refusal (`401
//! stale_timestamp`, `409 stale_key`, `409 identity_needed`), the pre-send replay deadline
//! is cleared so re-sends run for 30 days from that acceptance; otherwise the deadline stays
//! on `sent/<msg_id>` to bound re-sends. The message leaves the outbox once every job is
//! done.
//!
//! Only a refusal for good marks a message failed: the Retry column of Dispatch spec 6.4 says
//! "No". `403 not_admitted` and `403 not_current` stay queued, as admission changes when the
//! counterparty adds a kept peer or an invite, and a certificate renewal makes the app current
//! again (Dispatch spec 7, Dispatch wire 3.8), but only for [`UNDELIVERABLE_MS`] from the
//! first such answer: once a try is answered so again past that time, at
//! [`UNDELIVERABLE_TRIES`] tries spread over it, the message is deleted, plaintext and all,
//! and the protocol is told (Dispatch spec 11): [`AppEvent::MessageUndelivered`] when no try
//! of it can have reached the recipient's Dispatch, else [`AppEvent::DeliveryUnknown`]. Whatever the
//! tries, it is deleted so at [`UNDELIVERABLE_MAX_MS`] from that first answer, at the next
//! flush, without another try: plaintext at rest has a firm bound, and a forward jump of
//! the clock shorter than that still deletes nothing. A failed message
//! is forgotten, plaintext and all, after the retention of sent messages.

use std::collections::{BTreeMap, BTreeSet};

use pubky_dispatch_core::admission::PeerReason;
use pubky_dispatch_core::enc::{serde_b64, serde_b64_vec};
use pubky_dispatch_core::http::{ErrorCode, Retry};
use pubky_dispatch_core::ident::NamingKey;
use pubky_dispatch_core::message::{Message, MessagePlaintext, Sender};
use pubky_dispatch_core::ops::OpKind;
use pubky_dispatch_core::records::{AppCert, CLOCK_TOLERANCE_MS, DAY_MS, IdentityDoc};
use pubky_dispatch_core::scopes::Permission;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use super::batch::OpBatch;
use super::directory::Route;
use super::error::{Refusal, WontDeliver};
use super::events::{AppEvent, Duty};
use super::records::{Collection, DeleteBase, RecordTarget};
use super::state::key;
use super::{App, AppError, LocalWrite, MAX_STEP_LOCAL_BYTES, local_writes_bytes};
use crate::client::answers::AppendAnswer;
use crate::error::{ClientError, StoreError};

/// How long a sent message is kept for re-sends: 30 days from its first acceptance (Dispatch
/// spec 11).
pub const SENT_RETENTION_MS: u64 = 30 * DAY_MS;

/// How long a message answered `403 not_admitted` or `403 not_current` stays queued, from
/// the first such answer: 30 days (Dispatch spec 11).
pub const UNDELIVERABLE_MS: u64 = 30 * DAY_MS;

/// How many tries answered `403 not_admitted` or `403 not_current`, each at least
/// [`UNDELIVERABLE_TRY_SPACING_MS`] after the one counted before, a message needs before it
/// is given up: the 30 days are measured on the app's clock, and spread over separate tries
/// one forward jump of it counts one try, never the whole wait.
pub const UNDELIVERABLE_TRIES: u32 = 5;

/// The least time, app clock, between two tries [`UNDELIVERABLE_TRIES`] counts.
pub const UNDELIVERABLE_TRY_SPACING_MS: u64 = UNDELIVERABLE_MS / 4;

/// The longest a message answered `403 not_admitted` or `403 not_current` stays queued, app
/// clock, from the first such answer, however few tries confirmed [`UNDELIVERABLE_MS`]: 45
/// days. Then it is deleted, plaintext and all, without another try.
pub const UNDELIVERABLE_MAX_MS: u64 = 45 * DAY_MS;

/// How many times one delivery seals again after `409 stale_key` before it waits for the
/// next flush.
const RESEALS: usize = 2;

const OUT_PREFIX: &str = "out/";
const SENT_PREFIX: &str = "sent/";
const SENT_TIME_PREFIX: &str = "sentt/";
/// A message whose delivery the app gave up, with the time until which
/// [`App::queue_stored`] refuses it (`STATE.md`).
const GIVEN_UP_PREFIX: &str = "outgone/";
/// A counterparty whose messages the app holds ([`App::hold_queued`]).
pub(crate) const HOLD_PREFIX: &str = "outhold/";

fn hold_key(pubky: &[u8; 32]) -> String {
    format!("{HOLD_PREFIX}{}", pubky_dispatch_core::enc::b64(pubky))
}

/// Hold `pubky`'s messages, in `tx` ([`App::hold_queued`]): a restore's commit.
pub(crate) fn put_hold(tx: &mut super::state::Tx, pubky: &[u8; 32]) -> Result<(), AppError> {
    tx.put(&hold_key(pubky), &())
}

/// A message the app holds ([`App::hold_message`]), by `msg_id`.
pub(crate) const MESSAGE_HOLD_PREFIX: &str = "outheld/";

/// Remove sent and queued plaintexts, their retention index and delivery holds on leave.
pub(super) fn clear_on_leave(tx: &mut super::state::Tx) -> Result<(), AppError> {
    tx.delete_prefixes(&[
        OUT_PREFIX,
        SENT_PREFIX,
        SENT_TIME_PREFIX,
        GIVEN_UP_PREFIX,
        HOLD_PREFIX,
        MESSAGE_HOLD_PREFIX,
    ])
}

fn message_hold_key(msg_id: &str) -> String {
    format!("{MESSAGE_HOLD_PREFIX}{msg_id}")
}

/// Hold the message `msg_id`, in `tx` ([`App::hold_message`]): a restore's commit.
pub(crate) fn put_message_hold(tx: &mut super::state::Tx, msg_id: &str) -> Result<(), AppError> {
    tx.put(&message_hold_key(msg_id), &())
}

/// End the hold of the message `msg_id`, in `tx`: in the commit that gives its delivery up.
pub(crate) fn end_message_hold(tx: &mut super::state::Tx, msg_id: &str) -> Result<(), AppError> {
    tx.delete(&message_hold_key(msg_id))
}

/// The kind of the message `msg_id` when `reader` owes its delivery at `now`: the outbox
/// holds it with a delivery owed and not refused for good, or, absent from the outbox and
/// not kept as sent, one of `kept`, the messages kept batches put there once they settle,
/// is it, its delivery not given up. What [`App::hold_message`] and
/// [`App::withdraw_message`] act on.
async fn owed_kind(
    reader: &super::state::Reader,
    msg_id: &str,
    now: u64,
    kept: &[OutboxItem],
) -> Result<Option<String>, AppError> {
    if let Some(item) = reader.get::<OutboxItem>(&out_key(msg_id)).await? {
        return Ok(item.delivery_pending().then_some(item.kind));
    }
    if !kept_message_owed(reader, msg_id, now).await? {
        return Ok(None);
    }
    Ok(kept
        .iter()
        .find(|item| item.msg_id == msg_id)
        .map(|item| item.kind.clone()))
}

/// The messages `reader` holds ([`App::hold_message`]) whose delivery it owes at `now`,
/// each with its kind, in `msg_id` order. Every commit that ends a delivery ends its hold,
/// so none is left over; one that is isn't listed or carried.
pub(crate) async fn held_messages_of(
    reader: &super::state::Reader,
    now: u64,
) -> Result<Vec<(String, String)>, AppError> {
    let marks = reader.scan::<()>(MESSAGE_HOLD_PREFIX).await?;
    if marks.is_empty() {
        return Ok(Vec::new());
    }
    let kept = super::batch::kept_queued(reader).await?;
    let mut held = Vec::new();
    for (msg_id, ()) in marks {
        if let Some(kind) = owed_kind(reader, &msg_id, now, &kept).await? {
            held.push((msg_id, kind));
        }
    }
    Ok(held)
}

/// The delivery state a restore in place leaves as the store holds it (Dispatch spec 12.4):
/// the outbox, the sent copies with their index, and the give-up marks. They say what the
/// world already saw of each message, which no backup can take back, so the restore changes
/// them only where [`restored`] says so.
pub(crate) const KEPT_IN_PLACE: [&str; 4] =
    [OUT_PREFIX, SENT_PREFIX, SENT_TIME_PREFIX, GIVEN_UP_PREFIX];

/// What the store a restore replaces in place holds of one message.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum LiveCopy {
    /// No outbox record and no mark.
    Nothing,
    /// No outbox record, and its sent copy: accepted, with nothing else owed.
    Accepted,
    /// No outbox record, and its give-up mark: its protocol was told.
    GivenUp,
    /// An outbox record owed its first delivery.
    FirstSend,
    /// An outbox record owed a re-send of a message accepted before.
    Resend,
    /// An outbox record owed no delivery: accepted with a record job owed, or refused for
    /// good.
    Settled,
}

/// What a backup carries of one message in its outbox.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum BackupCopy {
    /// Nothing, or only its name among those left out.
    Nothing,
    /// A record owed its first delivery.
    FirstSend,
    /// A record owed a re-send of a message accepted before.
    Resend,
    /// A record owed no delivery: accepted with a record job owed, or refused for good.
    Settled,
}

/// What a restore does with one message's outbox record.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Restored {
    /// What the store holds of it stands as it is, and nothing of the backup's goes back.
    Stands,
    /// The store's record stands and its delivery is held: the store owes a delivery the
    /// restored protocol state doesn't know.
    StandsHeld,
    /// The store's record goes on, by the earliest replay deadline of both copies and of
    /// the backup's time: both still owed the delivery.
    GoesOn,
    /// The backup's record goes on over the store's, by the earliest replay deadline of
    /// both copies and of the backup's time: both still owed a delivery, and the backup's
    /// record knows the acceptance the store's doesn't.
    BackupGoesOn,
    /// The backup's record goes back, held: only the backup owes the delivery.
    BackupHeld,
    /// The backup's record goes back as it is, owed no delivery, over a first delivery the
    /// store still owed if it holds one: a record of a message accepted or refused for
    /// good is the later word on it, and its first delivery is never owed again.
    Backup,
    /// No delivery is owed, a give-up already told: the record that knows most of the
    /// message stays without its delivery, for what else it owes.
    Ended,
}

/// What a restore writes at a message's outbox key ([`Restored::record`]).
#[derive(Clone, PartialEq, Eq)]
pub(crate) enum Rewrite {
    /// Nothing: what the store holds there stays.
    Leave,
    /// This record.
    Put(Box<OutboxItem>),
    /// The store's record goes.
    Delete,
}

impl Restored {
    /// Whether the delivery is held for its protocol to decide.
    pub(crate) fn holds(self) -> bool {
        matches!(self, Self::StandsHeld | Self::BackupHeld)
    }

    /// What the restore writes at the message's outbox key, from the store's record
    /// (`newest`), the backup's (`carried`) and the backup's time less the clock tolerance
    /// (`baseline`). A record that goes back owed a delivery takes the earliest replay
    /// deadline of every copy and of the backup's time: a restore never moves one later.
    pub(crate) fn record(
        self,
        newest: Option<&OutboxItem>,
        carried: Option<&OutboxItem>,
        baseline: u64,
    ) -> Rewrite {
        // The record that goes back or on, and the other copy, whose deadline bounds it.
        let (record, other) = match self {
            Self::Stands | Self::StandsHeld => return Rewrite::Leave,
            Self::GoesOn => (newest, carried),
            Self::BackupGoesOn | Self::BackupHeld | Self::Backup => (carried, newest),
            // The copy that knows the message accepted is the one whose other jobs count.
            Self::Ended => match (newest, carried) {
                (Some(newest), Some(carried))
                    if newest.accepted_at_ms.is_none() && carried.accepted_at_ms.is_some() =>
                {
                    (Some(carried), Some(newest))
                }
                (Some(newest), _) => (Some(newest), carried),
                (None, carried) => (carried, None),
            },
        };
        let Some(record) = record else {
            return Rewrite::Leave;
        };
        if self == Self::Ended {
            return match record.clone().without_delivery() {
                Some(kept) if Some(&kept) == newest => Rewrite::Leave,
                Some(kept) => Rewrite::Put(Box::new(kept)),
                None if newest.is_some() => Rewrite::Delete,
                None => Rewrite::Leave,
            };
        }
        let mut item = record.clone();
        if item.delivery_owed() {
            item.replay_until(baseline);
            if let Some(other) = other {
                item.replay_no_later_than(other);
            }
        }
        if Some(&item) == newest {
            Rewrite::Leave
        } else {
            Rewrite::Put(Box::new(item))
        }
    }
}

/// The one decision of a restore about a message's outbox record (Dispatch spec 12.4), from
/// what the store it replaces in place holds of it (`live`, [`LiveCopy::Nothing`] for
/// every message of a fresh restore), what the backup carries of it (`backup`), and whether
/// its delivery was told given up (`told`): by a duty event the backup carries, one the
/// store still owes, or the store's give-up mark. The table is in `STATE.md`.
///
/// Four rules decide every cell:
///
/// - a give-up already told is never undone: no cell delivers or holds its message;
/// - a message is delivered on the restore's own word only where both the store and the
///   backup owe a delivery of it;
/// - a delivery only one of them owes is held for its protocol, unless the other holds a
///   later word that ends it: an acceptance, a refusal for good or a give-up of a first
///   delivery, a give-up of a re-send;
/// - nothing owed vanishes: a record either stands, goes on, is held, or is told.
pub(crate) fn restored(live: LiveCopy, backup: BackupCopy, told: bool) -> Restored {
    use BackupCopy as B;
    use LiveCopy as L;
    match (live, backup) {
        // The store ended the delivery, and the backup owes none the store doesn't know.
        (L::GivenUp, B::Nothing | B::FirstSend | B::Resend | B::Settled)
        | (L::Accepted | L::Settled, B::Nothing | B::FirstSend | B::Settled)
        | (L::Nothing, B::Nothing) => Restored::Stands,
        // A record owed no delivery, over nothing or a first delivery.
        (L::Nothing | L::FirstSend, B::Settled) => Restored::Backup,
        (L::Accepted | L::Settled, B::Resend) if told => Restored::Stands,
        (L::Nothing | L::FirstSend, B::FirstSend | B::Resend)
        | (L::FirstSend, B::Nothing)
        | (L::Resend, B::Nothing | B::FirstSend | B::Resend | B::Settled)
            if told =>
        {
            Restored::Ended
        }
        // Only the backup owes the delivery: a re-send the store never knew included.
        (L::Nothing, B::FirstSend | B::Resend) | (L::Accepted | L::Settled, B::Resend) => {
            Restored::BackupHeld
        }
        // Both owe it.
        (L::FirstSend, B::Resend) => Restored::BackupGoesOn,
        (L::FirstSend, B::FirstSend) | (L::Resend, B::FirstSend | B::Resend) => Restored::GoesOn,
        // Only the store owes it.
        (L::FirstSend, B::Nothing) | (L::Resend, B::Nothing | B::Settled) => Restored::StandsHeld,
    }
}

/// What the store a restore replaces in place holds of its outgoing messages (Dispatch spec
/// 12.4): the outbox records the restored app can take, the messages it had accepted
/// (`sent/`) and those it gave up (`outgone/`, the protocol told, acknowledged or not). A
/// fresh restore holds none of them.
#[derive(Default)]
pub(crate) struct LiveOutbox {
    items: BTreeMap<String, OutboxItem>,
    accepted: BTreeSet<String>,
    given_up: BTreeSet<String>,
    /// The outbox records the restored app doesn't sign for or can't keep
    /// ([`validate_outbox`]): deleted, their protocol told.
    refused: Vec<OutboxItem>,
    /// The keys of that state that don't read, sit under another message's key, or disagree
    /// with the outbox record of their message: deleted, as the restore's wipe took them
    /// before it left this state in place.
    unreadable: Vec<String>,
    /// The give-up marks whose time doesn't read: written again.
    unread_marks: Vec<String>,
}

impl LiveOutbox {
    /// Read what `reader`, the store a restore in place replaces, holds, as the app of
    /// `meta` and `cert` takes it: the restore fails on none of it.
    pub(crate) async fn read(
        reader: &super::state::Reader,
        meta: &super::state::Meta,
        cert: &pubky_dispatch_core::records::AppCert,
    ) -> Result<Self, AppError> {
        let mut live = Self::default();
        for (msg_id, bytes) in reader.scan_raw(OUT_PREFIX).await? {
            match super::state::decode::<OutboxItem>(&bytes) {
                Ok(item) if item.msg_id == msg_id => {
                    if item.is_own(meta, cert) && item.has_valid_deadline() {
                        live.items.insert(msg_id, item);
                    } else {
                        live.unreadable.push(out_key(&msg_id));
                        live.refused.push(item);
                    }
                }
                _ => live.unreadable.push(format!("{OUT_PREFIX}{msg_id}")),
            }
        }
        for (msg_id, bytes) in reader.scan_raw(SENT_PREFIX).await? {
            let agrees = |sent: &SentStored| {
                live.items.get(&msg_id).is_none_or(|item| {
                    DeliveryCopy::of(item)
                        == DeliveryCopy {
                            to: sent.to,
                            kind: sent.kind.clone(),
                            plaintext: sent.plaintext.clone(),
                            origin: sent.origin,
                        }
                })
            };
            match super::state::decode::<SentStored>(&bytes) {
                Ok(sent) if sent.msg_id == msg_id && sent.is_own(meta, cert) && agrees(&sent) => {
                    live.accepted.insert(msg_id);
                }
                _ => live.unreadable.push(format!("{SENT_PREFIX}{msg_id}")),
            }
        }
        for (rest, bytes) in reader.scan_raw(SENT_TIME_PREFIX).await? {
            if super::state::decode::<()>(&bytes).is_err() {
                live.unreadable.push(format!("{SENT_TIME_PREFIX}{rest}"));
            }
        }
        for (msg_id, bytes) in reader.scan_raw(GIVEN_UP_PREFIX).await? {
            // A mark that doesn't read still says the delivery was given up.
            if super::state::decode::<u64>(&bytes).is_err() {
                live.unread_marks.push(msg_id.clone());
            }
            live.given_up.insert(msg_id);
        }
        Ok(live)
    }

    /// Delete in `tx` what the restored app can't take of the state the restore leaves in
    /// place, and write again, from `now`, the give-up marks whose time doesn't read.
    pub(crate) fn repair(&self, tx: &mut super::state::Tx, now: u64) -> Result<(), AppError> {
        for key in &self.unreadable {
            tx.delete(key)?;
        }
        for msg_id in &self.unread_marks {
            note_given_up(tx, msg_id, now)?;
        }
        Ok(())
    }

    /// The outbox records the restored app doesn't sign for or can't keep, which
    /// [`LiveOutbox::repair`] deletes.
    pub(crate) fn refused(&self) -> &[OutboxItem] {
        &self.refused
    }

    /// The store's outbox record of `msg_id`.
    pub(crate) fn item(&self, msg_id: &str) -> Option<&OutboxItem> {
        self.items.get(msg_id)
    }

    /// The store's outbox records, oldest queued first, as a backup takes them.
    pub(crate) fn items(&self) -> Vec<&OutboxItem> {
        let mut items: Vec<&OutboxItem> = self.items.values().collect();
        items.sort_by_key(|item| item.queued_ms);
        items
    }

    /// Whether the store marks the delivery of `msg_id` given up, its protocol told.
    pub(crate) fn gave_up(&self, msg_id: &str) -> bool {
        self.given_up.contains(msg_id)
    }

    /// Whether the store holds anything of `msg_id`: an outbox record or a mark.
    pub(crate) fn knows(&self, msg_id: &str) -> bool {
        self.copy(msg_id) != LiveCopy::Nothing
    }

    /// What the store holds of `msg_id`. Its outbox record is the newest word on the
    /// message where it holds one; without one, its marks are.
    pub(crate) fn copy(&self, msg_id: &str) -> LiveCopy {
        match self.items.get(msg_id) {
            Some(item) if !item.delivery_pending() => LiveCopy::Settled,
            Some(item) if item.is_resend() => LiveCopy::Resend,
            Some(_) => LiveCopy::FirstSend,
            None if self.accepted.contains(msg_id) => LiveCopy::Accepted,
            None if self.given_up.contains(msg_id) => LiveCopy::GivenUp,
            None => LiveCopy::Nothing,
        }
    }
}

/// Delete the outbox record of `msg_id`, in `tx`: a restore's commit.
pub(crate) fn delete_outbox_item(tx: &mut super::state::Tx, msg_id: &str) -> Result<(), AppError> {
    tx.delete(&out_key(msg_id))
}

pub(crate) fn out_key(msg_id: &str) -> String {
    format!("{OUT_PREFIX}{msg_id}")
}

fn sent_key(msg_id: &str) -> String {
    format!("{SENT_PREFIX}{msg_id}")
}

fn sent_time_key(at: u64, msg_id: &str) -> String {
    format!("{SENT_TIME_PREFIX}{}/{msg_id}", key::num(at))
}

fn given_up_key(msg_id: &str) -> String {
    format!("{GIVEN_UP_PREFIX}{msg_id}")
}

/// Whether the app gave up the delivery of `msg_id` and its mark still stands at `now`
/// ([`note_given_up`]). A retained outbox item or sent copy keeps the mark effective until
/// it goes too: neither may recreate an ended delivery (Dispatch spec 11).
pub(crate) async fn given_up(
    reader: &super::state::Reader,
    msg_id: &str,
    now: u64,
) -> Result<bool, AppError> {
    let until: Option<u64> = reader.get(&given_up_key(msg_id)).await?;
    let Some(until) = until else {
        return Ok(false);
    };
    Ok(now <= until
        || reader.exists(&out_key(msg_id)).await?
        || reader.exists(&sent_key(msg_id)).await?)
}

/// Note in `tx` that the delivery of `msg_id` was given up at `now`, in the commit that
/// gives it up and tells the protocol: [`App::queue_stored`] refuses the message from then
/// until [`SENT_RETENTION_MS`] later, and while the outbox or sent copies keep its plaintext.
/// Past that window its replay deadline refuses it anyway, so the protocol is told once.
pub(crate) fn note_given_up(
    tx: &mut super::state::Tx,
    msg_id: &str,
    now: u64,
) -> Result<(), AppError> {
    tx.put(
        &given_up_key(msg_id),
        &now.saturating_add(SENT_RETENTION_MS),
    )
}

/// The retained local origin of an outgoing message (Dispatch spec 11).
///
/// This is independent of prior acceptance, a re-send, and permission to deliver.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum DeliveryOrigin {
    /// Work queued directly, including an intent retained in an unanswered batch.
    Original,
    /// A copy reconstructed from signed plaintext without a retained original intent.
    Reconstructed,
}

/// The most own records a protocol can request before one append (Dispatch spec 8.2, 11).
pub const MAX_APPEND_RECORDS: usize = 2;

/// The owning protocol's decision for one append of an authenticated message.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AppendDecision {
    /// Permit this transport attempt. A later attempt checks again.
    Send,
    /// Keep the signed message queued for another try.
    Hold,
    /// Give up this outstanding delivery, preserving uncertainty about earlier attempts
    /// and any record job still owed for a previously accepted message.
    Withdraw,
}

/// An authenticated outgoing message and its owning protocol's committed local state.
///
/// The plaintext retains the exact signed JSON bytes. Its hash and origin are the same
/// facts exposed by [`QueuedMessage`] (Dispatch spec 11).
pub struct DeliveryView<'a> {
    message: &'a Message,
    plaintext: &'a MessagePlaintext,
    origin: DeliveryOrigin,
    resend: bool,
    local: super::LocalView<'a>,
    cert: &'a AppCert,
    recovery_from: Option<u64>,
    naming: &'a NamingKey,
    store: &'a dyn crate::store::StateStore,
    ns: &'a str,
    clock: &'a dyn crate::clock::Clock,
}

impl std::fmt::Debug for DeliveryView<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("DeliveryView")
    }
}

impl<'a> DeliveryView<'a> {
    /// The parsed authenticated message.
    pub fn message(&self) -> &Message {
        self.message
    }

    /// The retained signed plaintext, including its original JSON bytes.
    pub fn plaintext(&self) -> &MessagePlaintext {
        self.plaintext
    }

    /// The hash of the original signed JSON (Dispatch wire 5.1).
    pub fn hash(&self) -> [u8; 32] {
        self.plaintext.hash()
    }

    /// The current copy's retained origin, independently of acceptance or a re-send.
    pub fn origin(&self) -> DeliveryOrigin {
        self.origin
    }

    /// Whether this delivery is a re-send of a message this app retained as accepted.
    ///
    /// An unaccepted delivery retry is not a re-send. This is the same retained attempt
    /// fact as [`QueuedMessage::resend`], independently of [`Self::origin`].
    pub fn resend(&self) -> bool {
        self.resend
    }

    /// Only the owning protocol's local state, as committed.
    pub fn local(&self) -> &super::LocalView<'a> {
        &self.local
    }

    /// The app's current certificate, as [`App::cert`] gives it.
    pub fn cert(&self) -> &AppCert {
        self.cert
    }

    /// The lost generation named by the app's current signed identity document
    /// (Dispatch wire 3.3), or `None` when no provider loss is recorded.
    pub fn recovery_from(&self) -> Option<u64> {
        self.recovery_from
    }

    /// `blind(input)` under the app's naming key (Dispatch wire 1.5), as [`App::blind`]
    /// gives it, without exposing the key.
    pub fn blind(&self, input: &[u8]) -> [u8; 32] {
        self.naming.blind(input)
    }

    /// The current host wall time in Unix milliseconds, sampled on each call.
    ///
    /// This is the app's [`crate::clock::Clock`], not a verified service time.
    pub fn now_ms(&self) -> u64 {
        self.clock.now_ms()
    }

    /// The current status of a known batch ID in this app, as [`App::kept_batch`] gives it.
    ///
    /// This reads app-wide metadata, without exposing the batch or another protocol's
    /// local state. An absent or expired status is not evidence that nothing was sent.
    /// No request, settlement or pruning is performed.
    ///
    /// # Errors
    ///
    /// A store failure, or a kept batch that doesn't read, as for [`App::kept_batch`].
    pub fn kept_batch(
        &self,
        batch_id: [u8; 16],
    ) -> Result<Option<super::KeptBatchStatus>, AppError> {
        super::kept::read_kept_batch(self.store, self.ns, self.clock, batch_id)
    }
}

/// What releasing a message does about the reply grant its delivery would write
/// ([`App::release_message`]): the entry that lets the recipient write back (Dispatch spec 7).
/// There is no default: the protocol chooses at each release. The choice lasts as long as
/// the delivery, as a hold does.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReplyGrantOnRelease {
    /// The delivery writes the reply grant if one is owed: the message's protocol says
    /// the message adds one, and the app holds no grant for the recipient that it has
    /// verified, as for a message that was never held. A grant withheld at an earlier
    /// release stays withheld.
    ///
    /// After a restore this can write a grant the user removed: the grants a restore
    /// brings back count as not verified, so the delivery writes the grant again even if
    /// it was removed after the backup was taken. A protocol releasing a message carried
    /// through a restore passes [`ReplyGrantOnRelease::Withheld`] unless it has current
    /// evidence that the grant is still wanted.
    IfOwed,
    /// No reply grant: the delivery writes no entry for the recipient, at this try or any
    /// later one, and a grant the recipient already holds is neither renewed nor removed.
    /// For a message whose recipient may no longer be meant to write back, such as one a
    /// restore held (Dispatch spec 12.4): the backup can't say what was removed since. A
    /// copy of the message queued again while a kept batch still holds a withheld one
    /// stays withheld.
    Withheld,
}

/// A message whose delivery is owed, including intents in unanswered batches.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct QueuedMessage {
    /// The message's identifier, as the per-message hold and withdrawal calls use it.
    pub msg_id: String,
    /// The recipient identity.
    pub to: [u8; 32],
    /// The authenticated message kind.
    pub kind: String,
    /// The hash of the original signed JSON, as the delivery gate receives it.
    pub hash: [u8; 32],
    /// Its retained local origin, as every protocol delivery gate receives it.
    pub origin: DeliveryOrigin,
    /// A re-send of a message accepted before, independently of its origin.
    pub resend: bool,
    /// The earliest retained batch that will materialize it; none if already in the outbox.
    pub kept_batch: Option<[u8; 16]>,
    /// The per-message hold is set.
    pub held: bool,
    /// The recipient-wide hold is set.
    pub counterparty_held: bool,
    /// The owning protocol currently permits this delivery; true for an unowned kind.
    pub may_send: bool,
}

impl QueuedMessage {
    /// Whether a message, recipient or protocol hold prevents delivery now.
    pub fn waits(&self) -> bool {
        self.held || self.counterparty_held || !self.may_send
    }
}

struct DeliveryHolds {
    message: bool,
    counterparty: bool,
    may_send: bool,
}

impl DeliveryHolds {
    fn any(&self) -> bool {
        self.message || self.counterparty || !self.may_send
    }
}

/// The shared record a sent message is written into (Dispatch spec 8.2), and the protocol's
/// tag for how, such as the message's role in the record. Its `Debug` shows no key.
#[derive(Clone, PartialEq, Eq)]
pub struct RecordJob {
    /// The record.
    pub target: RecordTarget,
    /// The protocol's opaque tag.
    pub tag: Vec<u8>,
}

impl std::fmt::Debug for RecordJob {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "RecordJob({:?})", self.target)
    }
}

/// A message to send. Its `Debug` shows only the kind.
#[derive(Clone)]
pub struct OutgoingMessage {
    /// The recipient identity.
    pub to: [u8; 32],
    /// The kind, `<prefix>.<name>`.
    pub kind: String,
    /// The hashes of the messages it refers to.
    pub refs: Vec<[u8; 32]>,
    /// The body.
    pub body: Map<String, Value>,
    /// Whether the Dispatch pushes it (Dispatch spec 5.1 `notify`).
    pub notify: bool,
    /// An invite code that admits the app at the recipient's Dispatch (Dispatch spec 7).
    pub invite_code: Option<String>,
    /// The shared record write that goes with it.
    pub record: Option<RecordJob>,
}

impl std::fmt::Debug for OutgoingMessage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "OutgoingMessage({})", self.kind)
    }
}

impl OutgoingMessage {
    /// A message of `kind` to `to` with `body`, pushed, without refs, code or record.
    pub fn new(to: [u8; 32], kind: &str, body: Map<String, Value>) -> Self {
        Self {
            to,
            kind: kind.to_owned(),
            refs: Vec::new(),
            body,
            notify: true,
            invite_code: None,
            record: None,
        }
    }
}

/// A message signed once and not yet queued ([`App::sign_message`]): its signed plaintext
/// and hash are known before anything is kept, so a protocol builds from them the shared
/// record write and claim entries that go with it, in the batch that queues it
/// ([`super::OpBatch::queue`]), or queues it alone ([`App::queue_signed`]). Its `Debug`
/// shows only the kind and `msg_id`.
#[derive(Clone, PartialEq, Eq)]
pub struct SignedMessage {
    to: [u8; 32],
    signing_cert: [u8; 32],
    kind: String,
    msg_id: String,
    plaintext: MessagePlaintext,
    notify: bool,
    invite_code: Option<String>,
    grant_reply: bool,
    record: Option<RecordJob>,
}

impl std::fmt::Debug for SignedMessage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SignedMessage({}, {})", self.kind, self.msg_id)
    }
}

impl SignedMessage {
    /// The recipient identity.
    pub fn to(&self) -> [u8; 32] {
        self.to
    }

    /// The kind.
    pub fn kind(&self) -> &str {
        &self.kind
    }

    /// The message ID.
    pub fn msg_id(&self) -> &str {
        &self.msg_id
    }

    /// The signed plaintext, as it is sealed and as a record stores it (Dispatch spec 8.2).
    pub fn plaintext(&self) -> &MessagePlaintext {
        &self.plaintext
    }

    /// The message hash (Dispatch wire 4.5), which a message referring to it names.
    pub fn hash(&self) -> [u8; 32] {
        self.plaintext.hash()
    }

    /// The shared record write that goes with it once the recipient's inbox accepts it,
    /// built through [`super::Protocol::sent_record`], if any.
    pub fn record(&self) -> Option<&RecordJob> {
        self.record.as_ref()
    }

    /// The same message with the record job `job`, whose target may derive from the
    /// message's own hash: the plaintext isn't signed again.
    #[must_use]
    pub fn with_record(mut self, job: RecordJob) -> Self {
        self.record = Some(job);
        self
    }
}

/// A message the app sent, kept for re-sends. Its `Debug` shows no content.
#[derive(Clone, PartialEq, Eq)]
pub struct SentMessage {
    /// The recipient identity.
    pub to: [u8; 32],
    /// The kind.
    pub kind: String,
    /// The message ID.
    pub msg_id: String,
    /// The signed plaintext, as sent.
    pub plaintext: MessagePlaintext,
    /// When the recipient's inbox first accepted it, the recipient's service time; `None`
    /// while it is queued.
    pub accepted_at_ms: Option<u64>,
    /// When the recipient's inbox accepted each re-send of it since, ascending, in the same
    /// clock. A re-send request's times select by these as well as the first (Dispatch spec
    /// 11).
    pub resent_at_ms: Vec<u64>,
}

impl SentMessage {
    /// Every acceptance time of the message, ascending: the first, then each accepted
    /// re-send's.
    pub fn accepted_times_ms(&self) -> Vec<u64> {
        let mut times: Vec<u64> = self
            .accepted_at_ms
            .into_iter()
            .chain(self.resent_at_ms.iter().copied())
            .collect();
        times.sort_unstable();
        times.dedup();
        times
    }
}

impl std::fmt::Debug for SentMessage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SentMessage({}, {})", self.kind, self.msg_id)
    }
}

/// Where a message is (Dispatch spec 11).
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Delivery {
    /// In the outbox, to be tried again.
    Queued {
        /// How many times it was tried.
        tries: u64,
        /// The last failure, without content: at most 512 bytes of its text, and `None`
        /// when the record didn't fit the store with it.
        last_error: Option<String>,
        /// When a delivery was first answered `403 not_admitted` or `403 not_current`, app
        /// clock: the start of the time the message stays queued so before it is given up
        /// ([`UNDELIVERABLE_MS`], Dispatch spec 11). `None` while no delivery of it was
        /// answered so.
        undeliverable_since_ms: Option<u64>,
        /// Which of the two the last such answer was: the recipient not admitting the
        /// sender, or the sender's own certificate not current. `None` while no delivery of
        /// it was answered so.
        undeliverable_reason: Option<UndeliverableReason>,
    },
    /// The recipient's inbox accepted it: delivery is complete.
    Accepted {
        /// The acceptance time.
        accepted_at_ms: u64,
    },
    /// Refused for good, or never queued: the kept batch that would have queued it was
    /// dropped ([`super::App::kept_batch`]). Answered for [`SENT_RETENTION_MS`] from its
    /// time, then forgotten. A refusal answers only the try it ends: when an earlier try
    /// may have been accepted, the app told [`AppEvent::DeliveryUnknown`] too.
    Failed {
        /// Why, without content: at most 512 bytes of the refusal's text.
        reason: String,
        /// When, app clock: when it was refused, or its batch dropped.
        failed_at_ms: u64,
    },
    /// In a kept batch, not yet in the outbox: it is queued once the batch is applied, and
    /// fails with it if the batch is dropped (Dispatch spec 8.2, [`super::OpBatch::queue`]).
    Kept {
        /// The batch ID it is kept under ([`super::App::kept_batch`]).
        batch_id: [u8; 16],
    },
}

/// Why a delivery stays queued for a bounded time before the message is given up
/// ([`Delivery::Queued`], Dispatch spec 11).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum UndeliverableReason {
    /// `403 not_admitted`: the recipient doesn't admit the sender, until it adds a kept peer
    /// or an invite (Dispatch spec 7).
    NotAdmitted,
    /// `403 not_current`: the sender's own certificate isn't current, until a renewal makes
    /// it current again (Dispatch wire 3.8). Nothing about the recipient.
    NotCurrent,
}

/// The most messages one flush of the outbox tries ([`App::flush_outbox`]): the next
/// flush goes on with the rest, from where this one stopped ([`OutboxReport::more`]).
pub const OUTBOX_TRIES_PER_FLUSH: usize = 4;

/// Where flushing the outbox stands (`outnext`, `STATE.md`).
const OUT_NEXT: &str = "outnext";

/// `outnext`: where flushing the outbox stands. A flush tries messages in queue order from
/// after `last`, round the queue, so no message waits for ever behind others that keep
/// failing. A pass goes once round: while `open`, a flush its budget stopped left messages of
/// the pass untried, and the next flush tries only those, the ones after `last` and before
/// `pass_first` (every one while the pass has tried none). The flush that ends the pass says
/// no more, and the next flush starts a new one, together with a pass of the owed
/// deliveries of the own `identity.json` ([`App::deliver_to_recent_peers`]).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct OutNext {
    /// The queue time and ID of the last message tried.
    last: (u64, String),
    /// The first message the pass under way tried; `None` while it has tried none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pass_first: Option<(u64, String)>,
    /// A pass is under way: a flush its budget stopped left messages of it untried.
    open: bool,
}

/// Whether `key` comes after `from` and before `to`, going round the queue from `from`.
fn between(from: &(u64, String), key: &(u64, String), to: &(u64, String)) -> bool {
    if from < to {
        from < key && key < to
    } else {
        key > from || key < to
    }
}

/// What a flush of the outbox did.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct OutboxReport {
    /// The messages whose every job completed.
    pub done: Vec<String>,
    /// The messages still queued.
    pub queued: Vec<String>,
    /// The messages refused for good.
    pub failed: Vec<String>,
    /// The messages whose delivery was given up although known not delivered, or only a
    /// re-send of them, each told with [`AppEvent::MessageUndelivered`]: after
    /// [`UNDELIVERABLE_MS`] of `403 not_admitted` or `403 not_current` (Dispatch spec 11),
    /// a re-send past its replay deadline, or because a try's writes were too large for the
    /// store ([`StoreError::TooLarge`]).
    pub undelivered: Vec<String>,
    /// The messages whose delivery was given up, or refused for good, while they may have
    /// been delivered, each told with [`AppEvent::DeliveryUnknown`]: a host must not take
    /// them as undelivered.
    pub unknown: Vec<String>,
    /// The flush stopped on its budget, [`OUTBOX_TRIES_PER_FLUSH`] messages or the call's
    /// time ([`super::AppConfig::call_budget_ms`]), with messages of its pass, or owed
    /// deliveries of the own `identity.json`, it didn't try: the host flushes again at once,
    /// and the next flush tries only those. It is `false` once the pass is over, every
    /// message queued and every owed delivery tried in it, so a host that flushes while it is
    /// `true` stops after one pass, even with messages still queued; it flushes again on its
    /// own triggers ([`App::flush_outbox`]).
    pub more: bool,
}

/// The envelope sealed for one try, and where.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
struct Sealed {
    envelope: pubky_dispatch_core::envelope::SealedEnvelope,
    apps_version: u64,
    origin: String,
    generation: u64,
}

/// The record job, as kept.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
struct KeptJob {
    collection: String,
    policy: pubky_dispatch_core::ident::Policy,
    #[serde(with = "serde_b64_vec")]
    natural_key: Vec<u8>,
    #[serde(with = "serde_b64_vec")]
    tag: Vec<u8>,
    /// The delete the record's next write built on when the job was queued
    /// ([`super::records::HeldRecord::delete_base`]); `None` when it built on no delete.
    #[serde(deserialize_with = "Option::deserialize")]
    delete_base: Option<DeleteBase>,
}

impl KeptJob {
    fn of(job: &RecordJob, delete_base: Option<DeleteBase>) -> Self {
        Self {
            collection: job.target.collection.name.clone(),
            policy: job.target.collection.policy.clone(),
            natural_key: job.target.natural_key.clone(),
            tag: job.tag.clone(),
            delete_base,
        }
    }

    fn job(&self) -> RecordJob {
        RecordJob {
            target: RecordTarget::new(
                Collection::new(&self.collection, self.policy.clone()),
                &self.natural_key,
            ),
            tag: self.tag.clone(),
        }
    }
}

/// `out/<msg_id>`: a queued message and its jobs. Sensitive: it holds the message and any
/// invite code.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct OutboxItem {
    origin: DeliveryOrigin,
    #[serde(with = "serde_b64")]
    to: [u8; 32],
    kind: String,
    msg_id: String,
    #[serde(with = "serde_b64_vec")]
    plaintext: Vec<u8>,
    notify: bool,
    invite_code: Option<String>,
    /// The reply grant is owed.
    grant_reply: bool,
    sealed: Option<Sealed>,
    record: Option<KeptJob>,
    record_done: bool,
    accepted_at_ms: Option<u64>,
    /// Refused for good: why, without content, and when, app clock. It is forgotten after
    /// the retention of sent messages.
    failed: Option<(String, u64)>,
    last_error: Option<String>,
    /// Job tries begun while unheld; delivery retries share this count. A hold
    /// discovered after earlier work does not undo that work or its try.
    tries: u64,
    queued_ms: u64,
    /// An accepted message is to be sent again, sealed to the current keys (Dispatch spec 11).
    resend: bool,
    /// The first `403 not_admitted` or `403 not_current` answer to a delivery, app clock.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    undeliverable_ms: Option<u64>,
    /// Which of the two the last such answer was.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    undeliverable_reason: Option<UndeliverableReason>,
    /// The last such answer counted, app clock.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    undeliverable_last_ms: Option<u64>,
    /// The such answers counted ([`UNDELIVERABLE_TRIES`]).
    undeliverable_tries: u32,
    /// A re-send queued from `sent/`: the recipient accepted the message before.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    resend_queued: bool,
    /// The last time a delivery may go, for a message whose envelope may already have been
    /// sent, one a restore put back, one [`App::queue_stored`] queued, or a re-send: past
    /// it, the recipient may have forgotten the processed pair of an earlier copy (Dispatch
    /// spec 11). Kept through retries, reloads and later backups without moving later,
    /// cleared only when an item with no earlier deadline is accepted in the try that first
    /// sent it with every earlier append a verified refusal (`401 stale_timestamp`, `409
    /// stale_key`, `409 identity_needed`) (or rolled back if a pre-transport hold stops the
    /// first send before any transport call), and otherwise carried into `sent/` so future
    /// re-sends stay bounded by it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    replay_until_ms: Option<u64>,
    /// The batch a try of the record job left kept, the latest one, in base64: settled
    /// before the next try, and named when the job is given up
    /// ([`AppEvent::RecordJobDropped`]) or stopped ([`AppEvent::RecordJobStopped`]) while it
    /// may have applied.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    record_batch: Option<String>,
    /// An envelope of it was committed to be sent, so a request carrying it may have
    /// reached the recipient's Dispatch, its answer lost. Committed together with a replay
    /// deadline right before the first transport call (and rolled back if a pre-transport
    /// hold stops that call). Once a transport call is attempted, this stays set for a
    /// give-up ([`OutboxItem::give_up_duty`]). Always written: a record without it is
    /// refused, never read as never sent.
    envelope_sent: bool,
}

impl std::fmt::Debug for OutboxItem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "OutboxItem({}, {})", self.kind, self.msg_id)
    }
}

impl OutboxItem {
    pub(crate) fn msg_id(&self) -> &str {
        &self.msg_id
    }

    pub(crate) fn kind(&self) -> &str {
        &self.kind
    }

    /// The cached routing fields agree with the plaintext authenticated by this app
    /// (Dispatch wire 5.1). Body rules are not needed to retain an unregistered kind.
    pub(crate) fn is_own(
        &self,
        meta: &super::state::Meta,
        cert: &pubky_dispatch_core::records::AppCert,
    ) -> bool {
        self.signed_message(meta, cert).is_some()
            && self.sealed.as_ref().is_none_or(|sealed| {
                sealed
                    .envelope
                    .matches_plaintext(&self.plaintext)
                    .unwrap_or(false)
            })
    }

    fn signed_message(&self, meta: &super::state::Meta, cert: &AppCert) -> Option<Message> {
        own_message(&self.plaintext, &self.to, meta, cert)
            .filter(|message| message.kind == self.kind && message.msg_id == self.msg_id)
    }

    fn complete(&self) -> bool {
        self.accepted_at_ms.is_some() && !self.resend && (self.record.is_none() || self.record_done)
    }

    fn is_resend(&self) -> bool {
        self.accepted_at_ms.is_some() || self.resend_queued
    }

    /// Whether a delivery is owed: never accepted, or a re-send asked since.
    pub(crate) fn delivery_owed(&self) -> bool {
        self.accepted_at_ms.is_none() || self.resend
    }

    /// Whether a delivery is owed and the message wasn't refused for good: what a hold
    /// ([`App::hold_message`]) holds.
    pub(crate) fn delivery_pending(&self) -> bool {
        self.failed.is_none() && self.delivery_owed()
    }

    /// An attempted item whose delivery is still owed always carries a replay deadline
    /// committed before its first transport append (Dispatch spec 11).
    pub(crate) fn has_valid_deadline(&self) -> bool {
        !(self.envelope_sent && self.replay_until_ms.is_none() && self.delivery_owed())
    }

    /// Count a `403 not_admitted` or `403 not_current` answer at `now`, for `reason`: the
    /// first starts the wait, a later one counts once [`UNDELIVERABLE_TRY_SPACING_MS`]
    /// passed since the last counted, and a clock gone back starts the wait over. The reason
    /// is the last answer's.
    fn count_undeliverable(&mut self, now: u64, reason: UndeliverableReason) {
        self.undeliverable_reason = Some(reason);
        match (self.undeliverable_ms, self.undeliverable_last_ms) {
            (Some(since), last) if now >= since && last.is_none_or(|last| now >= last) => {
                let last = last.unwrap_or(since);
                if now.saturating_sub(last) >= UNDELIVERABLE_TRY_SPACING_MS {
                    self.undeliverable_last_ms = Some(now);
                    self.undeliverable_tries = self.undeliverable_tries.saturating_add(1);
                }
            }
            _ => {
                self.undeliverable_ms = Some(now);
                self.undeliverable_last_ms = Some(now);
                self.undeliverable_tries = 1;
            }
        }
    }

    fn clear_undeliverable(&mut self) {
        self.undeliverable_ms = None;
        self.undeliverable_reason = None;
        self.undeliverable_last_ms = None;
        self.undeliverable_tries = 0;
    }

    fn plaintext(&self) -> Result<MessagePlaintext, AppError> {
        MessagePlaintext::decode(&self.plaintext).map_err(|_| store_corrupt())
    }

    /// The item that stays once its owed delivery is given up past its replay deadline
    /// ([`OutboxItem::replay_until`]), as [`App::drop_undeliverable`] gives one up, and the
    /// duty event that tells the protocol: a message never accepted goes, plaintext and
    /// all; one accepted before stays while its record job is owed, its sealed envelope
    /// dropped. `None` for nothing left.
    pub(crate) fn give_up_delivery(mut self) -> (Option<Self>, Duty) {
        let duty = self.give_up_duty(self.accepted_at_ms.is_some() || self.resend_queued);
        self.resend = false;
        self.resend_queued = false;
        self.sealed = None;
        self.clear_undeliverable();
        let kept = (self.accepted_at_ms.is_some() && !self.complete()).then_some(self);
        (kept, duty)
    }

    /// The item as it stays once its delivery was given up elsewhere, with its duty event
    /// told there: one refused for good stays as it is, reported failed; one accepted before
    /// stays while its record job is owed, as [`OutboxItem::give_up_delivery`] keeps it.
    /// `None` for nothing left.
    pub(crate) fn without_delivery(self) -> Option<Self> {
        if self.failed.is_some() {
            return Some(self);
        }
        self.give_up_delivery().0
    }

    /// The duty event that tells the protocol this delivery is given up (Dispatch spec 11).
    /// With `accepted_before`, this app had the message accepted, and only a re-send ends.
    /// Otherwise the message is told undelivered only when no request carrying it can have
    /// reached the recipient's Dispatch: this app committed no envelope of it to be sent
    /// (`envelope_sent` is false) and it carries no replay deadline (neither from an earlier
    /// send attempt, a restore putting it back, nor [`App::queue_stored`]). Else its
    /// delivery is unknown.
    pub(crate) fn give_up_duty(&self, accepted_before: bool) -> Duty {
        let msg_id = self.msg_id.clone();
        if accepted_before {
            Duty::MessageUndelivered {
                msg_id,
                resend: true,
            }
        } else if self.envelope_sent || self.replay_until_ms.is_some() {
            Duty::DeliveryUnknown { msg_id }
        } else {
            Duty::MessageUndelivered {
                msg_id,
                resend: false,
            }
        }
    }

    /// The replay deadline a restore gives the item (Dispatch spec 11): the earliest of the
    /// one it carries, its first acceptance plus [`SENT_RETENTION_MS`] for a message
    /// accepted before, and `baseline` plus [`SENT_RETENTION_MS`], where `baseline` is when
    /// the backup was taken, less the clock tolerance. A recipient keeps a processed pair
    /// 30 days and the tolerance from when it processed the message, which is at or after
    /// its first acceptance. A message whose envelope may already have been sent before the
    /// backup already carries the deadline from that first possible send; one never tried
    /// before the backup has its first acceptance at or after the backup. So a copy
    /// delivered by the deadline is one the recipient drops. The deadline only ever comes
    /// earlier.
    pub(crate) fn replay_until(&mut self, baseline: u64) {
        let deadlines = [
            self.replay_until_ms,
            self.accepted_at_ms
                .map(|at| at.saturating_add(SENT_RETENTION_MS)),
            Some(baseline.saturating_add(SENT_RETENTION_MS)),
        ];
        self.replay_until_ms = deadlines.into_iter().flatten().min();
    }

    /// Keep the earlier replay deadline of this copy of the message and of `other`, another
    /// copy of it: neither copy's deadline moves later (Dispatch spec 11).
    pub(crate) fn replay_no_later_than(&mut self, other: &Self) {
        self.replay_until_ms = [self.replay_until_ms, other.replay_until_ms]
            .into_iter()
            .flatten()
            .min();
    }

    /// What a backup that carries this record carries of the message.
    pub(crate) fn backup_copy(&self) -> BackupCopy {
        if !self.delivery_pending() {
            BackupCopy::Settled
        } else if self.is_resend() {
            BackupCopy::Resend
        } else {
            BackupCopy::FirstSend
        }
    }

    /// The duty events that tell the protocol what ends when the item is dropped whole,
    /// nothing of it kept: its delivery, if one is pending, as
    /// [`OutboxItem::give_up_delivery`] tells it, and its record job, if one is owed, as
    /// [`App::drop_record_job`] tells it.
    pub(crate) fn drop_duties(&self) -> Vec<Duty> {
        let mut duties = Vec::new();
        if self.delivery_pending() {
            duties.push(self.give_up_duty(self.is_resend()));
        }
        if self.accepted_at_ms.is_some() && self.record.is_some() && !self.record_done {
            duties.push(Duty::RecordJobDropped {
                msg_id: self.msg_id.clone(),
                batch_id: self.record_batch.clone(),
            });
        }
        duties
    }

    /// The item's replay deadline, if set.
    #[cfg(test)]
    pub(crate) fn replay_until_ms(&self) -> Option<u64> {
        self.replay_until_ms
    }

    /// End the reply grant the delivery owes without writing it
    /// ([`ReplyGrantOnRelease::Withheld`]); returns whether it was owed. A try only ever narrows
    /// what the item owes, so nothing brings the grant back for this delivery.
    pub(crate) fn withhold_reply_grant(&mut self) -> bool {
        std::mem::take(&mut self.grant_reply)
    }

    /// Whether the delivery notifies the recipient, and whether it owes a reply grant
    /// entry.
    #[cfg(test)]
    pub(crate) fn notify_and_grant_reply(&self) -> (bool, bool) {
        (self.notify, self.grant_reply)
    }

    /// The bytes the item takes in the store.
    fn stored_bytes(&self) -> u64 {
        super::state::encode(self).map_or(u64::MAX, |bytes| {
            u64::try_from(bytes.len()).unwrap_or(u64::MAX)
        })
    }
}

/// The most bytes of outbox records a backup carries, so the restore's one commit fits the
/// store's batch size beside the app's own state: 8 MiB.
pub const MAX_CARRIED_OUTBOX_BYTES: u64 = 8 * 1024 * 1024;

/// The outbox a backup carries (Dispatch spec 11, 12.4).
#[derive(Clone, Debug, Default)]
pub(crate) struct CarriedOutbox {
    /// The records, oldest queued first.
    pub(crate) items: Vec<OutboxItem>,
    /// The messages left out past [`MAX_CARRIED_OUTBOX_BYTES`], and whether each is a
    /// re-send of a message accepted before.
    pub(crate) left_out: Vec<(String, bool)>,
}

/// The queued messages a backup carries (Dispatch spec 11, 12.4): every record in the outbox,
/// as it stands, its signed plaintext and the envelope sealed for its last try included, so
/// a restore delivers each with the same `msg_id` and bytes; a message refused for good is
/// carried too, so the restored app still reports it failed until it is forgotten. Oldest
/// queued first, within [`MAX_CARRIED_OUTBOX_BYTES`]: the rest are named, so the restore
/// tells the protocol it won't deliver them. A message whose give-up the protocol hasn't
/// acknowledged isn't named: the backup carries that duty event, which a restore tells
/// again.
pub(crate) async fn carried_outbox(
    reader: &super::state::Reader,
) -> Result<CarriedOutbox, AppError> {
    let mut carried = CarriedOutbox::default();
    let mut given_up = std::collections::BTreeSet::new();
    for (_, bytes) in reader.scan_raw(key::DUTY_PREFIX).await? {
        if let Ok(kept) = super::state::decode::<super::events::KeptDuty>(&bytes)
            && let Some(msg_id) = kept.duty.given_up()
        {
            given_up.insert(msg_id.to_owned());
        }
    }
    let mut items: Vec<OutboxItem> = reader
        .scan::<OutboxItem>(OUT_PREFIX)
        .await?
        .into_iter()
        .map(|(_, item)| item)
        .collect();
    items.sort_by_key(|item| item.queued_ms);
    let mut bytes = 0u64;
    for item in items {
        let size = item.stored_bytes();
        match bytes.checked_add(size) {
            Some(total) if total <= MAX_CARRIED_OUTBOX_BYTES => {
                bytes = total;
                carried.items.push(item);
            }
            // One given up already is told again as that, not as left out.
            _ if given_up.contains(&item.msg_id) => {}
            _ => carried.left_out.push((
                item.msg_id.clone(),
                item.accepted_at_ms.is_some() || item.resend_queued,
            )),
        }
    }
    Ok(carried)
}

/// `sent/<msg_id>`: a sent message, kept 30 days. Sensitive.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
struct SentStored {
    origin: DeliveryOrigin,
    #[serde(with = "serde_b64")]
    to: [u8; 32],
    kind: String,
    msg_id: String,
    #[serde(with = "serde_b64_vec")]
    plaintext: Vec<u8>,
    /// The first acceptance, from which retention runs.
    first_ms: u64,
    /// The acceptances of re-sends.
    resent: Vec<u64>,
    /// The last time a re-send may go, carried from an outbox item whose acceptance here
    /// may be later than its first acceptance anywhere, such as one whose earlier send's
    /// answer was lost or unverified, one a restore put back, or one [`App::queue_stored`]
    /// queued ([`OutboxItem::replay_until`]): the retention of this copy doesn't bound its
    /// re-sends (Dispatch spec 11).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    replay_until_ms: Option<u64>,
}

impl SentStored {
    fn is_own(
        &self,
        meta: &super::state::Meta,
        cert: &pubky_dispatch_core::records::AppCert,
    ) -> bool {
        own_message(&self.plaintext, &self.to, meta, cert)
            .is_some_and(|message| message.kind == self.kind && message.msg_id == self.msg_id)
    }

    /// The re-sends' acceptance times, ascending.
    fn resent_ascending(&self) -> Vec<u64> {
        let mut times = self.resent.clone();
        times.sort_unstable();
        times
    }
}

impl std::fmt::Debug for SentStored {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SentStored({}, {})", self.kind, self.msg_id)
    }
}

#[cfg(test)]
impl App {
    /// The outbox record of `msg_id`.
    pub(crate) async fn outbox_record(&self, msg_id: &str) -> Option<OutboxItem> {
        self.reader().get(&out_key(msg_id)).await.ok().flatten()
    }

    /// The replay deadline stored on the `sent/` record of `msg_id`, if any.
    pub(crate) async fn sent_replay_until_ms(&self, msg_id: &str) -> Option<u64> {
        self.reader()
            .get::<SentStored>(&sent_key(msg_id))
            .await
            .ok()
            .flatten()
            .and_then(|sent| sent.replay_until_ms)
    }
}

/// Put a queued message in the outbox, in `tx`.
pub(crate) fn put_outbox_item(
    tx: &mut super::state::Tx,
    item: &OutboxItem,
) -> Result<(), AppError> {
    tx.put(&out_key(&item.msg_id), item)
}

/// What one delivery try came to.
enum Tried {
    /// The current hold decision stopped the remaining delivery work, without an answer.
    Held,
    Withdraw,
    Accepted(AppendAnswer),
    Queued(String),
    /// Queued after `403 not_admitted` or `403 not_current`, for a bounded time.
    Undeliverable(String, UndeliverableReason),
    Failed(String),
}

/// Read this app's authenticated common message fields without requiring the original
/// protocol to remain registered (Dispatch wire 5.1).
fn own_message(
    bytes: &[u8],
    to: &[u8; 32],
    meta: &super::state::Meta,
    cert: &pubky_dispatch_core::records::AppCert,
) -> Option<Message> {
    let plaintext = MessagePlaintext::decode(bytes).ok()?;
    if plaintext.sender_app_id() != meta.app_id
        || plaintext.verify_signature(&cert.signing_key(), to).is_err()
    {
        return None;
    }
    // Only the common fields are read from these already-authenticated bytes.
    let message = super::protocols::kept_message(plaintext.json())?;
    (message.to == *to
        && message.from.identity == meta.identity
        && message.from.app_id == meta.app_id)
        .then_some(message)
}

fn store_corrupt() -> AppError {
    AppError::Store(crate::error::StoreError::Corrupt)
}

fn replay_deadline(since_ms: u64) -> u64 {
    since_ms
        .saturating_sub(CLOCK_TOLERANCE_MS)
        .saturating_add(SENT_RETENTION_MS)
}

/// The immutable parts shared by every retained copy of one outgoing message.
#[derive(PartialEq, Eq)]
struct DeliveryCopy {
    to: [u8; 32],
    kind: String,
    plaintext: Vec<u8>,
    origin: DeliveryOrigin,
}

impl DeliveryCopy {
    fn of(item: &OutboxItem) -> Self {
        Self {
            to: item.to,
            kind: item.kind.clone(),
            plaintext: item.plaintext.clone(),
            origin: item.origin,
        }
    }

    fn remember(self, msg_id: String, copies: &mut BTreeMap<String, Self>) -> Result<(), AppError> {
        match copies.entry(msg_id) {
            std::collections::btree_map::Entry::Occupied(entry) if entry.get() != &self => {
                Err(store_corrupt())
            }
            std::collections::btree_map::Entry::Occupied(_) => Ok(()),
            std::collections::btree_map::Entry::Vacant(entry) => {
                entry.insert(self);
                Ok(())
            }
        }
    }
}

/// Authenticate every retained copy and require overlapping copies to agree before use.
async fn retained_copies(
    reader: &super::state::Reader,
    meta: &super::state::Meta,
    cert: &pubky_dispatch_core::records::AppCert,
) -> Result<BTreeMap<String, DeliveryCopy>, AppError> {
    let mut copies = BTreeMap::new();
    for (msg_id, item) in reader.scan::<OutboxItem>(OUT_PREFIX).await? {
        if msg_id != item.msg_id || !item.is_own(meta, cert) || !item.has_valid_deadline() {
            return Err(store_corrupt());
        }
        DeliveryCopy::of(&item).remember(msg_id, &mut copies)?;
    }
    for (msg_id, sent) in reader.scan::<SentStored>(SENT_PREFIX).await? {
        if msg_id != sent.msg_id || !sent.is_own(meta, cert) {
            return Err(store_corrupt());
        }
        DeliveryCopy {
            to: sent.to,
            kind: sent.kind,
            plaintext: sent.plaintext,
            origin: sent.origin,
        }
        .remember(msg_id, &mut copies)?;
    }
    for item in super::batch::kept_queued(reader).await? {
        if !item.is_own(meta, cert) || !item.has_valid_deadline() {
            return Err(store_corrupt());
        }
        DeliveryCopy::of(&item).remember(item.msg_id, &mut copies)?;
    }
    Ok(copies)
}

pub(crate) async fn validate_outbox(
    reader: &super::state::Reader,
    meta: &super::state::Meta,
    cert: &pubky_dispatch_core::records::AppCert,
) -> Result<(), AppError> {
    retained_copies(reader, meta, cert).await.map(|_| ())
}

impl App {
    /// Queued and sent copies may still need their original protocol on a resend (Dispatch spec 11).
    pub(super) async fn has_retained_messages_for(&self, protocol: &str) -> Result<bool, AppError> {
        let copies = retained_copies(&self.reader(), &self.state.meta, &self.state.cert).await?;
        Ok(copies.values().any(|copy| {
            self.protocols
                .of_kind(&copy.kind)
                .is_some_and(|owner| owner.name == protocol)
        }))
    }
}

/// The exact condition under which settlement can materialize a retained queued intent.
pub(crate) async fn kept_message_owed(
    reader: &super::state::Reader,
    msg_id: &str,
    now: u64,
) -> Result<bool, AppError> {
    Ok(!reader.exists(&out_key(msg_id)).await?
        && !reader.exists(&sent_key(msg_id)).await?
        && !given_up(reader, msg_id, now).await?)
}

impl App {
    async fn read_outbox(&self, msg_id: &str) -> Result<Option<OutboxItem>, AppError> {
        validate_outbox(&self.reader(), &self.state.meta, &self.state.cert).await?;
        let item = self.reader().get::<OutboxItem>(&out_key(msg_id)).await?;
        if item.as_ref().is_some_and(|item| {
            item.msg_id != msg_id
                || !item.is_own(&self.state.meta, &self.state.cert)
                || !item.has_valid_deadline()
        }) {
            return Err(store_corrupt());
        }
        Ok(item)
    }

    async fn read_sent(&self, msg_id: &str) -> Result<Option<SentStored>, AppError> {
        validate_outbox(&self.reader(), &self.state.meta, &self.state.cert).await?;
        let sent = self.reader().get::<SentStored>(&sent_key(msg_id)).await?;
        if sent.as_ref().is_some_and(|sent| {
            sent.msg_id != msg_id || !sent.is_own(&self.state.meta, &self.state.cert)
        }) {
            return Err(store_corrupt());
        }
        Ok(sent)
    }

    /// Give a new outbox record what the copies the app already retains of its message
    /// say (`copies`, and `kept`, those of kept batches): its origin, and a reply grant
    /// withheld on a kept batch's copy ([`ReplyGrantOnRelease::Withheld`]), which stays
    /// withheld whichever path queues the message next.
    fn inherit_retained(
        &self,
        item: &mut OutboxItem,
        copies: &mut BTreeMap<String, DeliveryCopy>,
        kept: &[OutboxItem],
    ) -> Result<(), AppError> {
        if !item.is_own(&self.state.meta, &self.state.cert) {
            return Err(Refusal::Usage("a message this app did not sign".into()).into());
        }
        if let Some(retained) = copies.get(&item.msg_id) {
            item.origin = retained.origin;
        }
        // Only ever narrowed: a copy that owes no grant never gains one here.
        item.grant_reply &= kept
            .iter()
            .filter(|kept| kept.msg_id == item.msg_id)
            .all(|kept| kept.grant_reply);
        DeliveryCopy::of(item).remember(item.msg_id.clone(), copies)
    }

    pub(crate) async fn outbox_items(
        &self,
        messages: &[SignedMessage],
    ) -> Result<Vec<OutboxItem>, AppError> {
        let mut copies =
            retained_copies(&self.reader(), &self.state.meta, &self.state.cert).await?;
        let kept = super::batch::kept_queued(&self.reader()).await?;
        let mut items = Vec::new();
        for message in messages {
            let mut item = self.outbox_item(message).await?;
            self.inherit_retained(&mut item, &mut copies, &kept)?;
            items.push(item);
        }
        Ok(items)
    }

    // ---------------------------------------------------------------------------------
    // Queueing

    /// Sign `message` once, record it in the outbox with its jobs, then try them once
    /// (module docs). Returns the `msg_id` and where the message is.
    ///
    /// The try is one unit, as in [`App::flush_outbox`]: the reply grant, one round of
    /// the delivery, and the record job, each a bounded call of its own, so the call's worst
    /// case is theirs. Each write the try makes sends one batch kept from an earlier call
    /// first, as every write does. A message returned [`Delivery::Accepted`] may still owe
    /// its record job, when that write failed: the next pass of the flushes tries it again,
    /// and the
    /// flush's report lists the message under `queued` until then.
    ///
    /// # Errors
    ///
    /// [`Refusal::Stopped`] or [`Refusal::Left`]; [`AppError::InvalidData`] for a message
    /// the core refuses (its kind, its size); a store failure. Failures to deliver aren't
    /// errors: the message stays queued, or is marked failed for good.
    pub async fn send(&mut self, message: OutgoingMessage) -> Result<(String, Delivery), AppError> {
        Box::pin(async move {
            let msg_id = self.queue(message).await?;
            self.flush_item(&msg_id).await?;
            let delivery = self
                .delivery(&msg_id)
                .await?
                .ok_or_else(|| AppError::InvalidData("the message left the outbox".into()))?;
            Ok((msg_id, delivery))
        })
        .await
    }

    /// Sign `message` once and record it in the outbox, sending nothing. Returns its
    /// `msg_id`.
    ///
    /// # Errors
    ///
    /// As [`App::send`].
    pub async fn queue(&mut self, message: OutgoingMessage) -> Result<String, AppError> {
        Box::pin(async move {
            self.ready_local().await?;
            let signed = self.sign_message(message)?;
            self.queue_signed(signed).await
        })
        .await
    }

    /// Sign `message` once, keeping nothing and sending nothing: its plaintext and hash are
    /// known before it is queued, with [`App::queue_signed`] or in a batch
    /// ([`super::OpBatch::queue`]). A signed message that is never queued was never sent.
    ///
    /// # Errors
    ///
    /// [`Refusal::Stopped`] or [`Refusal::Left`]; [`AppError::InvalidData`] for a message
    /// the core refuses (its kind, its size) or an invite code that isn't one.
    /// Returns [`Refusal::NotNow`] after a failed or interrupted save until a call such
    /// as [`App::receive`] reloads the stored state.
    pub fn sign_message(&self, message: OutgoingMessage) -> Result<SignedMessage, AppError> {
        self.require_loaded()?;
        self.refuse_when_stopped()?;
        if let Some(code) = &message.invite_code {
            pubky_dispatch_core::ident::invite_code_hash(code)?;
        }
        let me = self.state.meta.identity;
        let built = Message::new(
            &message.kind,
            Sender {
                identity: me,
                app_id: self.state.meta.app_id,
            },
            message.to,
            self.now(),
            message.refs,
            message.body,
        )?;
        let plaintext = built.sign(&self.state.keys)?;
        Ok(SignedMessage {
            to: message.to,
            signing_cert: self.state.cert.hash(),
            grant_reply: message.to != me && self.protocols.adds_reply(&built, &plaintext),
            kind: message.kind,
            msg_id: built.msg_id,
            plaintext,
            notify: message.notify,
            invite_code: message.invite_code,
            record: message.record,
        })
    }

    /// Hold every message to `pubky` that isn't delivered yet, such as when the user blocks
    /// that counterparty, until [`App::release_queued`]. Local only: it sends nothing.
    /// [`App::withdraw_queued`] gives the held messages up instead, and
    /// [`App::hold_message`] holds one message alone.
    ///
    /// - **What is held:** no flush or send delivers a message to `pubky`, a first delivery
    ///   or a re-send, nor writes the reply grant a first message to it needs. The
    ///   messages stay queued, untried, and their tries aren't counted. Those a batch kept
    ///   from an earlier call puts in the outbox once it settles are held too.
    /// - **What isn't held:** the record job of a message the counterparty's inbox already
    ///   accepted, which is the app's own record write. The own `identity.json` that a flush
    ///   delivers to the Dispatches the app wrote to lately after an app's removal or a closed
    ///   renewal (Dispatch spec 12.2 step 5): it tells the counterparty's Dispatch that a removed
    ///   app's signature no longer counts, which protects the user whatever the hold. And
    ///   the calls the host makes itself: [`App::ask_to_connect`], and the directory reads
    ///   of [`App::recipients_for`].
    /// - **The replay deadline keeps running** ([`App::queue_stored`]): a message still held
    ///   past it is given up and the protocol told ([`AppEvent::DeliveryUnknown`]).
    /// - **Where it holds:** in this app's store. Another app or device of the same identity
    ///   has an outbox of its own, and keeps delivering until its host holds there too.
    /// - **A backup carries it**, so an app restored from that backup holds it too. A restore
    ///   keeps the store's holds as well as the backup's, so a release made after the backup
    ///   is undone by a restore in place: the host releases again. A backup taken before the
    ///   hold doesn't carry it: restored on another store, the message isn't held. The client
    ///   delivers nothing during [`App::restore`], [`App::load`] or [`App::receive`], only in
    ///   [`App::flush_outbox`], [`App::flush_message`], [`App::send`] and [`App::resend`], so a
    ///   host that holds again before it calls any of those leaves no window.
    ///
    /// # Errors
    ///
    /// [`Refusal::Usage`] for the app's own identity, whose messages go to the identity's
    /// other apps; [`Refusal::Stopped`] or [`Refusal::Left`]; a store failure.
    pub async fn hold_queued(&mut self, pubky: &[u8; 32]) -> Result<(), AppError> {
        Box::pin(async move {
            self.ready_local().await?;
            self.refuse_when_stopped()?;
            if *pubky == self.state.meta.identity {
                return Err(
                    Refusal::Usage("the app's own identity isn't a counterparty".into()).into(),
                );
            }
            let mut tx = self.tx()?;
            tx.put(&hold_key(pubky), &())?;
            self.commit(tx).await
        })
        .await
    }

    /// Lift [`App::hold_queued`] for `pubky`: its messages go again from the next flush.
    /// Releasing a counterparty that isn't held changes nothing.
    ///
    /// # Errors
    ///
    /// [`Refusal::Stopped`] or [`Refusal::Left`]; a store failure.
    pub async fn release_queued(&mut self, pubky: &[u8; 32]) -> Result<(), AppError> {
        Box::pin(async move {
            self.ready_local().await?;
            self.refuse_when_stopped()?;
            let mut tx = self.tx()?;
            tx.delete(&hold_key(pubky))?;
            self.commit(tx).await
        })
        .await
    }

    /// The counterparties whose messages the app holds ([`App::hold_queued`]).
    ///
    /// # Errors
    ///
    /// A store failure.
    pub async fn held_counterparties(&self) -> Result<Vec<[u8; 32]>, AppError> {
        let held = self.reader().scan_raw(HOLD_PREFIX).await?;
        held.into_iter()
            .map(|(rest, _)| {
                pubky_dispatch_core::enc::unb64_array::<32>(&rest)
                    .map_err(|_| AppError::Store(StoreError::Corrupt))
            })
            .collect()
    }

    /// Hold the message `msg_id` of the protocol `protocol`, queued and not delivered yet,
    /// until [`App::release_message`]: for a protocol that holds some messages to a
    /// counterparty while others to it still go, such as those of one side of a flow. A
    /// protocol holds only its own messages, those of its kinds. Local only: it sends
    /// nothing. [`App::withdraw_message`] gives the message up instead. Returns whether it
    /// holds it: `false`, writing nothing, when the app owes no delivery of `msg_id`, such
    /// as for a message delivered, given up, refused for good or never queued here.
    ///
    /// It holds as [`App::hold_queued`] holds a counterparty's messages, for this message
    /// alone, whichever of the two holds:
    /// - **What is held:** no flush or send delivers it, a first delivery or a re-send, nor
    ///   writes the reply grant it needs. It stays queued, untried, and its tries
    ///   aren't counted. A message a batch kept from an earlier call puts in the outbox once
    ///   it settles is held too, and so is the copy of it [`App::queue_signed`] or
    ///   [`App::queue_stored`] queues meanwhile.
    /// - **What isn't held:** its record job, once the counterparty's inbox accepted it, and
    ///   the app's other messages to the same counterparty.
    /// - **The replay deadline keeps running** ([`App::queue_stored`]): a message still held
    ///   past it is given up and the protocol told ([`AppEvent::DeliveryUnknown`]).
    /// - **It lasts as long as the delivery:** it ends with the release, and in the commit
    ///   that ends the delivery, whatever ends it: the message delivered, refused for good,
    ///   given up or withdrawn, the kept batch that would queue it dropped (unless the
    ///   outbox or another kept batch holds it), or a restore whose outbox doesn't owe it.
    ///   Nothing else ends it, and a message queued again after its delivery ended starts
    ///   unheld.
    /// - **Where it holds:** in this app's store: another app or device of the same
    ///   identity has an outbox of its own.
    /// - **A backup carries it** for a message the backup carries in its outbox. A restore
    ///   keeps the store's holds of the messages its outbox owes as well as the backup's, so
    ///   a release made after the backup is undone by a restore in place: the protocol
    ///   releases again. A restore also holds, itself, each delivery that only one of the
    ///   backup and the store it replaces still owed
    ///   ([`AppEvent::MessagesHeldAtRestore`]). A backup
    ///   taken before the hold doesn't carry it, nor one taken while the message was only
    ///   in a kept batch: the client delivers nothing during
    ///   [`App::restore`], [`App::load`] or [`App::receive`], so a protocol that holds again
    ///   before the host calls [`App::flush_outbox`], [`App::flush_message`], [`App::send`]
    ///   or [`App::resend`] leaves no window.
    /// - **A try in flight:** after a crash during a delivery's try, the message may have
    ///   reached the counterparty's inbox although the outbox still owes it; a hold then
    ///   holds a re-try that the inbox drops as a duplicate.
    ///
    /// # Errors
    ///
    /// [`Refusal::Usage`] for a protocol not registered, or a message of another
    /// protocol's kind; [`Refusal::Stopped`] or [`Refusal::Left`]; a store failure.
    pub async fn hold_message(&mut self, protocol: &str, msg_id: &str) -> Result<bool, AppError> {
        Box::pin(async move {
            self.ready_local().await?;
            self.refuse_when_stopped()?;
            if self.owned_owed(protocol, msg_id).await?.is_none() {
                return Ok(false);
            }
            let mut tx = self.tx()?;
            put_message_hold(&mut tx, msg_id)?;
            self.commit(tx).await?;
            Ok(true)
        })
        .await
    }

    /// Lift [`App::hold_message`] of the protocol `protocol` for `msg_id`: it goes again
    /// from the next flush, unless its counterparty is held ([`App::hold_queued`]).
    /// Releasing a message that isn't held lifts nothing.
    ///
    /// `reply_grant` is the protocol's choice for the reply grant the delivery would write
    /// ([`ReplyGrantOnRelease`]): what the recipient may write to this identity can have changed
    /// since the message was queued, as after a restore, and only the protocol can tell.
    /// [`ReplyGrantOnRelease::Withheld`] is written to the queued message in the release's commit,
    /// held or not, and nothing brings the grant back for that delivery.
    ///
    /// # Errors
    ///
    /// [`Refusal::Usage`] for a protocol not registered, or a message of another
    /// protocol's kind; [`Refusal::Stopped`] or [`Refusal::Left`]; a store failure.
    pub async fn release_message(
        &mut self,
        protocol: &str,
        msg_id: &str,
        reply_grant: ReplyGrantOnRelease,
    ) -> Result<(), AppError> {
        Box::pin(async move {
            self.ready_local().await?;
            self.refuse_when_stopped()?;
            let owed = self.owned_owed(protocol, msg_id).await?;
            let mut tx = self.tx()?;
            if owed.is_some() && reply_grant == ReplyGrantOnRelease::Withheld {
                // The queued copy, and the one a kept batch puts in the outbox once it
                // settles: whichever the delivery is tried from carries the choice.
                if let Some(mut item) = self.read_outbox(msg_id).await?
                    && item.withhold_reply_grant()
                {
                    tx.put(&out_key(msg_id), &item)?;
                }
                self.withhold_kept_reply_grant(msg_id, &mut tx).await?;
            }
            end_message_hold(&mut tx, msg_id)?;
            self.commit(tx).await
        })
        .await
    }

    /// The messages of the protocol `protocol` the app holds ([`App::hold_message`]) and
    /// still owes a delivery of, in `msg_id` order.
    ///
    /// # Errors
    ///
    /// [`Refusal::Usage`] for a protocol not registered; a store failure.
    pub async fn held_messages(&self, protocol: &str) -> Result<Vec<String>, AppError> {
        self.check_registered(protocol)?;
        validate_outbox(&self.reader(), &self.state.meta, &self.state.cert).await?;
        Ok(held_messages_of(&self.reader(), self.now())
            .await?
            .into_iter()
            .filter(|(_, kind)| self.owns_kind(protocol, kind))
            .map(|(msg_id, _)| msg_id)
            .collect())
    }

    /// Whether `kind` is a kind of the protocol `protocol`, or of no registered protocol,
    /// as a message a restore with another set of protocols brings back: any protocol may
    /// then act on it, so its hold can still be released.
    fn owns_kind(&self, protocol: &str, kind: &str) -> bool {
        self.protocols
            .of_kind(kind)
            .is_none_or(|owner| owner.name == protocol)
    }

    /// List every owed delivery of `protocol`, including every retained batch producer
    /// and kinds no registered protocol owns (Dispatch spec 11). Materialized items come
    /// first by queue time and ID, then kept intents by batch order, each message once.
    /// Holds, a protocol refusal to send, and elapsed replay deadlines do not hide work
    /// that has not yet ended. `kept_batch` names its earliest remaining producer.
    ///
    /// This reads local state only: it writes nothing, settles no batch and sends no
    /// request. The protocol decision is the same one dispatch asks. For a local cleanup
    /// based on absence, the host must resolve earlier writes and retain exclusive App
    /// namespace ownership across this read, a fresh [`App::delivery`] and
    /// [`App::protocol_commit`], with no intervening producer or restore call.
    ///
    /// # Errors
    ///
    /// [`Refusal::Usage`] for an unregistered protocol; [`Refusal::NotNow`] while a failed
    /// commit requires reload; a store failure or inconsistent retained copies.
    pub async fn queued_messages(&self, protocol: &str) -> Result<Vec<QueuedMessage>, AppError> {
        self.check_registered(protocol)?;
        self.require_loaded()?;
        validate_outbox(&self.reader(), &self.state.meta, &self.state.cert).await?;
        let reader = self.reader();
        let mut outbox = reader.scan::<OutboxItem>(OUT_PREFIX).await?;
        outbox.sort_by(|a, b| (a.1.queued_ms, &a.0).cmp(&(b.1.queued_ms, &b.0)));
        let mut owed: Vec<_> = outbox
            .into_iter()
            .filter(|(_, item)| item.delivery_pending())
            .map(|(_, item)| (item, None))
            .collect();
        let mut batches = self.kept_batches().await?;
        batches.sort_by_key(|(id, pending)| (pending.queued_n, *id));
        let mut listed = BTreeSet::new();
        for (batch_id, pending) in batches {
            for item in pending.queued {
                if kept_message_owed(&reader, &item.msg_id, self.now()).await?
                    && listed.insert(item.msg_id.clone())
                {
                    owed.push((item, Some(batch_id)));
                }
            }
        }
        let mut result = Vec::new();
        for (item, kept_batch) in owed {
            if !self.owns_kind(protocol, &item.kind) {
                continue;
            }
            let holds = self.delivery_holds(&item).await?;
            let hash = item.plaintext()?.hash();
            let resend = item.is_resend();
            result.push(QueuedMessage {
                msg_id: item.msg_id,
                to: item.to,
                kind: item.kind,
                hash,
                origin: item.origin,
                resend,
                kept_batch,
                held: holds.message,
                counterparty_held: holds.counterparty,
                may_send: holds.may_send,
            });
        }
        Ok(result)
    }

    /// The kind of the message `msg_id` when the app owes its delivery, checked to be a
    /// message of the protocol `protocol`: what the per-message calls act on.
    ///
    /// # Errors
    ///
    /// [`Refusal::Usage`] for a protocol not registered, or a message of another kind than
    /// its own; a store failure.
    async fn owned_owed(&self, protocol: &str, msg_id: &str) -> Result<Option<String>, AppError> {
        self.check_registered(protocol)?;
        let reader = self.reader();
        validate_outbox(&reader, &self.state.meta, &self.state.cert).await?;
        let kept = super::batch::kept_queued(&reader).await?;
        let kind = owed_kind(&reader, msg_id, self.now(), &kept).await?;
        match kind {
            Some(kind) if !self.owns_kind(protocol, &kind) => Err(Refusal::Usage(format!(
                "`{msg_id}` is a message of no kind of `{protocol}`"
            ))
            .into()),
            kind => Ok(kind),
        }
    }

    /// Give up every message to `pubky` that isn't delivered yet, held or not: each is
    /// deleted from the outbox, plaintext and all, and the protocol told once
    /// ([`AppEvent::MessageUndelivered`], a duty event, `resend: true` for a re-send of one
    /// accepted before, which keeps its record job; [`AppEvent::DeliveryUnknown`] for one
    /// that may have been delivered, such as one tried before). So is each message to `pubky` that a
    /// batch kept from an earlier call would put in the outbox once it settles: the batch's
    /// other operations still go, and the message isn't queued. A message given up so is
    /// never queued again by this store: [`App::queue_stored`] refuses it, and a re-send
    /// after the counterparty's provider loss leaves it out. [`App::resend`] refuses
    /// it too. Returns the messages given up: those of the outbox in queue order,
    /// then those of kept batches. The retained queued copies and
    /// their delivery index are removed in the same commit, leaving the batch's other
    /// operations and local writes intact. Local only: it sends nothing.
    ///
    /// # Errors
    ///
    /// [`Refusal::Stopped`] or [`Refusal::Left`]; a store failure, after which the messages
    /// given up before it stay given up.
    pub async fn withdraw_queued(&mut self, pubky: &[u8; 32]) -> Result<Vec<String>, AppError> {
        Box::pin(async move {
            self.ready_local().await?;
            self.refuse_when_stopped()?;
            self.withdraw_where(|item| item.to == *pubky).await
        })
        .await
    }

    /// Give up the message `msg_id` of the protocol `protocol`, held or not, as
    /// [`App::withdraw_queued`] gives up each message to a counterparty, with the same
    /// exceptions (a re-send whose record job is still owed keeps its outbox item for that
    /// job; [`App::queue_signed`] checks no give-up): its delivery ends, in the outbox or in
    /// what a batch kept from an earlier call puts there once it settles, and the protocol
    /// is told once ([`AppEvent::MessageUndelivered`] or [`AppEvent::DeliveryUnknown`]); its
    /// hold, if any, ends. Returns
    /// whether it gave it up: `false`, changing nothing, when the app owes no delivery of
    /// `msg_id`. Local only: it sends nothing.
    ///
    /// # Errors
    ///
    /// [`Refusal::Usage`] for a protocol not registered, or a message of another
    /// protocol's kind; [`Refusal::Stopped`] or [`Refusal::Left`]; a store failure.
    pub async fn withdraw_message(
        &mut self,
        protocol: &str,
        msg_id: &str,
    ) -> Result<bool, AppError> {
        Box::pin(async move {
            self.ready_local().await?;
            self.refuse_when_stopped()?;
            if self.owned_owed(protocol, msg_id).await?.is_none() {
                return Ok(false);
            }
            let withdrawn = self.withdraw_where(|item| item.msg_id == msg_id).await?;
            Ok(!withdrawn.is_empty())
        })
        .await
    }

    /// End this materialized outbox delivery with the same custody information as an
    /// explicit withdrawal or an expired replay deadline (Dispatch spec 11).
    async fn give_up_outbox(&mut self, item: OutboxItem) -> Result<Duty, AppError> {
        let msg_id = item.msg_id.clone();
        let to = self.owners_of_kind(&item.kind);
        let (kept, duty) = item.give_up_delivery();
        let mut tx = self.tx()?;
        match &kept {
            Some(kept) => tx.put(&out_key(&msg_id), kept)?,
            None => tx.delete(&out_key(&msg_id))?,
        }
        self.end_delivery(&msg_id, &mut tx).await?;
        self.keep_duty_for(&mut tx, to, duty.clone())?;
        self.commit(tx).await?;
        Ok(duty)
    }

    /// Give up every message `matches` takes whose delivery is owed, as
    /// [`App::withdraw_queued`] says: those of the outbox in queue order, each in a commit of
    /// its own, then those of kept batches.
    async fn withdraw_where(
        &mut self,
        matches: impl Fn(&OutboxItem) -> bool,
    ) -> Result<Vec<String>, AppError> {
        validate_outbox(&self.reader(), &self.state.meta, &self.state.cert).await?;
        let now = self.now();
        let mut items: Vec<OutboxItem> = self
            .reader()
            .scan::<OutboxItem>(OUT_PREFIX)
            .await?
            .into_iter()
            .map(|(_, item)| item)
            .filter(|item| matches(item) && item.failed.is_none() && item.delivery_owed())
            .collect();
        items.sort_by_key(|item| item.queued_ms);
        let mut withdrawn = Vec::new();
        for item in items {
            let msg_id = item.msg_id.clone();
            self.give_up_outbox(item).await?;
            withdrawn.push(msg_id);
        }
        // The messages kept batches would queue once they settle: never in an outbox, so
        // never sent.
        for (_, pending) in self.kept_batches().await? {
            for item in pending.queued.iter().filter(|item| matches(item)) {
                let msg_id = item.msg_id.clone();
                if self.knows_message(&msg_id).await?
                    || given_up(&self.reader(), &msg_id, now).await?
                {
                    continue;
                }
                let mut tx = self.tx()?;
                self.end_delivery(&msg_id, &mut tx).await?;
                let to = self.owners_of_kind(&item.kind);
                self.keep_duty_for(
                    &mut tx,
                    to,
                    Duty::MessageUndelivered {
                        msg_id: msg_id.clone(),
                        resend: false,
                    },
                )?;
                self.commit(tx).await?;
                withdrawn.push(msg_id);
            }
        }
        Ok(withdrawn)
    }

    /// Record a message signed by [`App::sign_message`] in the outbox, with its jobs,
    /// sending nothing. Returns its `msg_id`. A message already in the outbox, or sent, is
    /// left as it is.
    ///
    /// It is for a message just signed. It checks neither a give-up nor the message's age,
    /// so a host doesn't queue a kept [`SignedMessage`] again once its delivery was given up
    /// ([`AppEvent::MessageUndelivered`], [`AppEvent::DeliveryUnknown`]), or 30 days after
    /// it was signed: past that a
    /// recipient that processed it may have forgotten the pair, and would process it as new
    /// (Dispatch spec 11). A message signed before is queued again with [`App::queue_stored`],
    /// which refuses those.
    ///
    /// # Errors
    ///
    /// [`Refusal::Stopped`] or [`Refusal::Left`]; [`Refusal::Usage`] for a message another
    /// app signed; a store failure.
    pub async fn queue_signed(&mut self, message: SignedMessage) -> Result<String, AppError> {
        Box::pin(async move {
            self.ready_local().await?;
            self.refuse_when_stopped()?;
            let mut item = self.outbox_item(&message).await?;
            let mut copies =
                retained_copies(&self.reader(), &self.state.meta, &self.state.cert).await?;
            let kept = super::batch::kept_queued(&self.reader()).await?;
            self.inherit_retained(&mut item, &mut copies, &kept)?;
            if self.knows_message(&item.msg_id).await? {
                return Ok(item.msg_id);
            }
            let mut tx = self.tx()?;
            put_outbox_item(&mut tx, &item)?;
            self.commit(tx).await?;
            Ok(item.msg_id)
        })
        .await
    }

    /// Queue a freshly signed original with its owning protocol's local writes in one
    /// store commit, without sending it (Dispatch spec 8.2, 11). On success the original
    /// outbox item and the writes are durable together. Use the original live decision
    /// to enqueue. If the commit outcome is unknown, reopen the store and check the
    /// protocol state and [`App::delivery`] before retrying. An older backup can lack
    /// evidence of a later delivery. For delivery conditional on a service operation,
    /// use [`OpBatch::queue`] and [`OpBatch::locals`].
    ///
    /// # Errors
    ///
    /// [`Refusal::Usage`] for a kind outside the registered protocol, a foreign signature,
    /// a changed signing certificate, an already retained ID (including an ended batch),
    /// or local writes exceeding [`MAX_STEP_LOCAL_BYTES`]. A given-up or expired original returns
    /// [`Refusal::WontDeliver`]. A refusal leaves the protocol writes untouched.
    /// Stopped apps and store failures propagate as for [`App::queue_signed`].
    pub async fn queue_signed_with(
        &mut self,
        protocol: &str,
        message: SignedMessage,
        local: &[LocalWrite],
    ) -> Result<String, AppError> {
        Box::pin(async move {
            self.ready_local().await?;
            self.refuse_when_stopped()?;
            if self
                .protocols
                .of_kind(message.kind())
                .is_none_or(|owner| owner.name != protocol)
            {
                return Err(
                    Refusal::Usage("the protocol does not own this message kind".into()).into(),
                );
            }
            if local_writes_bytes(local) > MAX_STEP_LOCAL_BYTES {
                return Err(Refusal::Usage(
                    "the local queue writes exceed their byte bound".into(),
                )
                .into());
            }
            if message.signing_cert != self.state.cert.hash() {
                return Err(
                    Refusal::Usage("the signing certificate is no longer current".into()).into(),
                );
            }
            let item = self.outbox_item(&message).await?;
            let signed = item
                .signed_message(&self.state.meta, &self.state.cert)
                .ok_or_else(|| Refusal::Usage("a message this app did not sign".into()))?;
            let until_ms = replay_deadline(signed.created_at_ms);
            let reader = self.reader();
            if given_up(&reader, &item.msg_id, self.now()).await? {
                return Err(Refusal::WontDeliver(WontDeliver::GivenUp).into());
            }
            if self.kept_window_now() > until_ms {
                return Err(
                    Refusal::WontDeliver(WontDeliver::PastReplayWindow { until_ms }).into(),
                );
            }
            let copies = retained_copies(&reader, &self.state.meta, &self.state.cert).await?;
            if copies.contains_key(&item.msg_id)
                || self.batch_for_message(&item.msg_id).await?.is_some()
            {
                return Err(Refusal::Usage("the message ID is already retained".into()).into());
            }
            let mut tx = self.tx()?;
            put_outbox_item(&mut tx, &item)?;
            tx.local(&super::protocols::qualify(protocol, local.iter().cloned()))?;
            self.commit(tx).await?;
            Ok(item.msg_id)
        })
        .await
    }

    /// Queue again a message this app signed itself, from its stored signed plaintext, with
    /// the same bytes and so the same `msg_id`, sending nothing (Dispatch spec 11 "Queued
    /// again by its signer"). Returns its `msg_id`.
    ///
    /// It is for a message no outbox holds although the protocol's records show it sent. A
    /// batch that queues a message ([`super::OpBatch::queue`]) puts it in the outbox only
    /// with the batch's answer, and a backup doesn't carry a batch kept unanswered. So
    /// after a restore from a backup taken while such a batch was kept, if the batch was
    /// applied, the record it wrote stores the message while neither the outbox nor the
    /// sent messages hold it. The protocol queues it again from that record.
    ///
    /// The plaintext must be signed with this app's key, the one its certificate names,
    /// with the App ID and `from` of this app and identity; the recipient, the kind and the
    /// `msg_id` are the message's. It is queued as [`App::queue_signed`] queues one, with
    /// the reply grant its signed content calls for, and no record job, since the record holds it
    /// already. The copy carries no invite code and notifies the recipient: a first message
    /// that needed an invite code is for the host to send again with one.
    ///
    /// The call queues the message once however often it is made, while the outbox holds
    /// it or the app keeps it as sent; it then returns the `msg_id` and changes nothing.
    /// After that it is refused with [`Refusal::WontDeliver`], and queues nothing and raises
    /// no event:
    ///
    /// - [`WontDeliver::PastReplayWindow`]: past [`SENT_RETENTION_MS`] from the message's
    ///   `created_at`, less the clock tolerance, by the later of the device clock and a
    ///   service time the app verified. A recipient that processed the message drops a copy
    ///   as a duplicate only while it keeps the pair, so a copy, and any re-send of it, goes
    ///   only until then; one queued in time and still undelivered then is given up, and
    ///   [`AppEvent::DeliveryUnknown`] tells the protocol, once: an earlier copy may have
    ///   been delivered.
    /// - [`WontDeliver::GivenUp`]: the app gave its delivery up already, and told the
    ///   protocol then.
    /// - [`WontDeliver::TooLarge`]: its outbox record is over the store's sizes.
    ///
    /// So for one message, within one store, the call never leads to a second give-up event,
    /// nor to [`AppEvent::MessageUndelivered`] with `resend: false`. A backup carries neither the sent messages nor the give-up
    /// marks, so a restored app may queue again a message given up or accepted before the
    /// backup: within its window it goes again. A recipient that processed a copy accepted
    /// before the backup drops it as a duplicate; a message given up before the backup goes
    /// as a first delivery.
    ///
    /// # Errors
    ///
    /// [`Refusal::Stopped`] or [`Refusal::Left`]; [`Refusal::WontDeliver`] as above;
    /// [`Refusal::Usage`] for a plaintext that doesn't read as a message, or that this app
    /// didn't sign; a store failure.
    pub async fn queue_stored(&mut self, plaintext: &MessagePlaintext) -> Result<String, AppError> {
        Box::pin(async move {
            self.ready_local().await?;
            self.refuse_when_stopped()?;
            let mut item = self.stored_item(plaintext)?;
            let mut copies =
                retained_copies(&self.reader(), &self.state.meta, &self.state.cert).await?;
            let kept = super::batch::kept_queued(&self.reader()).await?;
            self.inherit_retained(&mut item, &mut copies, &kept)?;
            if self.knows_message(&item.msg_id).await? {
                return Ok(item.msg_id);
            }
            let refused = |why| Err(AppError::Refused(Refusal::WontDeliver(why)));
            if given_up(&self.reader(), &item.msg_id, self.now()).await? {
                return refused(WontDeliver::GivenUp);
            }
            if let Some(until_ms) = item.replay_until_ms
                && self.kept_window_now() > until_ms
            {
                return refused(WontDeliver::PastReplayWindow { until_ms });
            }
            let written = async {
                let mut tx = self.tx()?;
                put_outbox_item(&mut tx, &item)?;
                self.commit(tx).await
            }
            .await;
            match written {
                Err(AppError::Store(StoreError::TooLarge { .. })) => {
                    self.reload_now().await?;
                    refused(WontDeliver::TooLarge)
                }
                committed => committed.map(|()| item.msg_id),
            }
        })
        .await
    }

    /// The outbox item of a message this app signed, read from its signed plaintext
    /// ([`App::queue_stored`]).
    fn stored_item(&self, plaintext: &MessagePlaintext) -> Result<OutboxItem, AppError> {
        let not_ours = || AppError::from(Refusal::Usage("a message this app didn't sign".into()));
        let me = self.state.meta.identity;
        let app_id = self.state.meta.app_id;
        if plaintext.sender_app_id() != app_id {
            return Err(not_ours());
        }
        let message = super::protocols::kept_message(plaintext.json()).ok_or_else(|| {
            Refusal::Usage("a stored plaintext without valid message fields".into())
        })?;
        if message.from.identity != me || message.from.app_id != app_id {
            return Err(not_ours());
        }
        // Dispatch wire 5.1 check 4, as the recipient makes it: the key the certificate names,
        // over the recipient identity and the JSON bytes.
        plaintext
            .verify_signature(&self.state.cert.signing_key(), &message.to)
            .map_err(|_| not_ours())?;
        let deadline = replay_deadline(message.created_at_ms);
        Ok(OutboxItem {
            origin: DeliveryOrigin::Reconstructed,
            to: message.to,
            grant_reply: message.to != me && self.protocols.adds_reply(&message, plaintext),
            kind: message.kind,
            msg_id: message.msg_id,
            plaintext: plaintext.encode(),
            notify: true,
            invite_code: None,
            sealed: None,
            record: None,
            record_done: false,
            accepted_at_ms: None,
            failed: None,
            last_error: None,
            tries: 0,
            queued_ms: self.now(),
            resend: false,
            undeliverable_ms: None,
            undeliverable_reason: None,
            undeliverable_last_ms: None,
            undeliverable_tries: 0,
            resend_queued: false,
            replay_until_ms: Some(deadline),
            record_batch: None,
            envelope_sent: false,
        })
    }

    /// Whether the outbox holds the message `msg_id`, or the app keeps it as sent.
    pub(crate) async fn knows_message(&self, msg_id: &str) -> Result<bool, AppError> {
        let reader = self.reader();
        Ok(reader.exists(&out_key(msg_id)).await? || reader.exists(&sent_key(msg_id)).await?)
    }

    /// The outbox item of a signed message, its jobs owed; a record job keeps the delete
    /// its record's next write builds on now, if any.
    pub(crate) async fn outbox_item(
        &self,
        message: &SignedMessage,
    ) -> Result<OutboxItem, AppError> {
        if message.plaintext.sender_app_id() != self.state.meta.app_id {
            return Err(Refusal::Usage("a message this app didn't sign".into()).into());
        }
        let record = match &message.record {
            Some(job) => {
                let key = self.record_key(&job.target)?;
                let held = self.held_record(&key).await?;
                let delete_base = held.and_then(|held| held.delete_base());
                Some(KeptJob::of(job, delete_base))
            }
            None => None,
        };
        Ok(OutboxItem {
            origin: DeliveryOrigin::Original,
            to: message.to,
            kind: message.kind.clone(),
            msg_id: message.msg_id.clone(),
            plaintext: message.plaintext.encode(),
            notify: message.notify,
            invite_code: message.invite_code.clone(),
            grant_reply: message.grant_reply,
            sealed: None,
            record,
            record_done: false,
            accepted_at_ms: None,
            failed: None,
            last_error: None,
            tries: 0,
            queued_ms: self.now(),
            resend: false,
            undeliverable_ms: None,
            undeliverable_reason: None,
            undeliverable_last_ms: None,
            undeliverable_tries: 0,
            resend_queued: false,
            replay_until_ms: None,
            record_batch: None,
            envelope_sent: false,
        })
    }

    /// Try the jobs of the queued message `msg_id` once, as [`App::flush_outbox`] does for
    /// every message, and return where it is; `None` for one the app doesn't keep. The try
    /// is one unit, as [`App::send`]'s. A try whose reply grant is owed sends one kept
    /// batch first, and the entry is written only once no batch is kept; otherwise the call
    /// sends no kept batch beyond the one each write of the try sends first. A read, a write
    /// or the flushes' passes send the rest.
    ///
    /// # Errors
    ///
    /// As [`App::flush_outbox`].
    pub async fn flush_message(&mut self, msg_id: &str) -> Result<Option<Delivery>, AppError> {
        Box::pin(async move {
            self.ready_local().await?;
            self.refuse_when_stopped()?;
            self.flush_item(msg_id).await?;
            self.delivery(msg_id).await
        })
        .await
    }

    /// Send again a message sent in the last 30 days: the same signed plaintext, and so the
    /// same `msg_id`, sealed to the recipient's current keys (Dispatch spec 11). It adds no
    /// reply grant and writes no record. A re-send goes only within 30 days of the
    /// message's first acceptance, and by its replay deadline when it has one; past it the
    /// re-send is given up ([`AppEvent::MessageUndelivered`] with `resend: true`), and the
    /// call still returns the earlier acceptance ([`Delivery::Accepted`]). The try is one
    /// unit, as [`App::send`]'s.
    ///
    /// # Errors
    ///
    /// [`Refusal::WontDeliver`] with [`WontDeliver::GivenUp`] for a delivery the app gave
    /// up; [`Refusal::Usage`] for a message the app doesn't keep; as [`App::send`].
    pub async fn resend(&mut self, msg_id: &str) -> Result<Delivery, AppError> {
        Box::pin(async move {
            self.ready_local().await?;
            self.refuse_when_stopped()?;
            if !self.prepare_resend(msg_id).await? {
                return Err(AppError::Refused(Refusal::WontDeliver(
                    WontDeliver::GivenUp,
                )));
            }
            self.flush_item(msg_id).await?;
            self.delivery(msg_id)
                .await?
                .ok_or_else(|| AppError::InvalidData("the message left the outbox".into()))
        })
        .await
    }

    /// Prepare either retained copy for a re-send, unless its delivery was given up.
    /// Check before changing an accepted item's jobs or queuing its sent copy, so a repeated
    /// request neither delivers it nor reports it undelivered again (Dispatch spec 11).
    async fn prepare_resend(&mut self, msg_id: &str) -> Result<bool, AppError> {
        if given_up(&self.reader(), msg_id, self.now()).await? {
            return Ok(false);
        }
        if !self.ask_resend_of_queued(msg_id).await? {
            let sent = self.read_sent(msg_id).await?.ok_or_else(|| {
                AppError::Refused(Refusal::Usage("no sent message with this msg_id".into()))
            })?;
            self.queue_resend(&sent).await?;
        }
        Ok(true)
    }

    /// A message still in the outbox: one already accepted, whose other jobs are owed, is
    /// marked to be sealed and sent again. Returns whether it is in the outbox.
    async fn ask_resend_of_queued(&mut self, msg_id: &str) -> Result<bool, AppError> {
        let Some(mut item) = self.read_outbox(msg_id).await? else {
            return Ok(false);
        };
        if let Some(accepted) = item.accepted_at_ms
            && !item.resend
        {
            item.resend = true;
            item.sealed = None;
            // A re-send goes only while the recipient keeps the processed pair, 30 days from
            // the first acceptance (Dispatch spec 11).
            item.replay_until_ms = [
                item.replay_until_ms,
                Some(accepted.saturating_add(SENT_RETENTION_MS)),
            ]
            .into_iter()
            .flatten()
            .min();
            self.save_item(&item).await?;
        }
        Ok(true)
    }

    async fn queue_resend(&mut self, sent: &SentStored) -> Result<(), AppError> {
        let item = OutboxItem {
            origin: sent.origin,
            to: sent.to,
            kind: sent.kind.clone(),
            msg_id: sent.msg_id.clone(),
            plaintext: sent.plaintext.clone(),
            notify: false,
            invite_code: None,
            grant_reply: false,
            sealed: None,
            record: None,
            record_done: false,
            accepted_at_ms: None,
            failed: None,
            last_error: None,
            tries: 0,
            queued_ms: self.now(),
            resend: false,
            undeliverable_ms: None,
            undeliverable_reason: None,
            undeliverable_last_ms: None,
            undeliverable_tries: 0,
            resend_queued: true,
            // Only while the recipient keeps the processed pair: 30 days from the first
            // acceptance, and by the deadline the message came with (Dispatch spec 11).
            replay_until_ms: [
                sent.replay_until_ms,
                Some(sent.first_ms.saturating_add(SENT_RETENTION_MS)),
            ]
            .into_iter()
            .flatten()
            .min(),
            record_batch: None,
            envelope_sent: false,
        };
        let mut tx = self.tx()?;
        tx.put(&out_key(&item.msg_id), &item)?;
        self.commit(tx).await
    }

    /// Send again what `pubky`'s old Dispatch accepted since `since_ms` (app clock of the
    /// previous check), after a provider loss (Dispatch spec 8.1), but no message whose
    /// delivery the app gave up while its give-up mark stands.
    pub(crate) async fn resend_since(
        &mut self,
        pubky: &[u8; 32],
        since_ms: u64,
    ) -> Result<(), AppError> {
        let mut queued = 0u64;
        for (msg_id, sent) in self.reader().scan::<SentStored>(SENT_PREFIX).await? {
            if msg_id != sent.msg_id || !sent.is_own(&self.state.meta, &self.state.cert) {
                return Err(store_corrupt());
            }
            let last = sent
                .resent
                .iter()
                .copied()
                .max()
                .unwrap_or(sent.first_ms)
                .max(sent.first_ms);
            if sent.to != *pubky || last < since_ms {
                continue;
            }
            if self.prepare_resend(&sent.msg_id).await? {
                queued = queued.saturating_add(1);
            }
        }
        if queued > 0 {
            self.events.push(AppEvent::ResendAfterLoss {
                identity: *pubky,
                messages: queued,
            });
        }
        Ok(())
    }

    // ---------------------------------------------------------------------------------
    // State

    /// Where the message `msg_id` is: in the outbox, sent, or in a kept batch that queues it
    /// ([`Delivery::Kept`], and [`Delivery::Failed`] once that batch is dropped); `None` for
    /// one the app doesn't keep. `None` never says the message was never sent: one
    /// accepted or ended longer than [`SENT_RETENTION_MS`] ago, or queued before a
    /// restore, isn't known here. The protocol reads its shared state then.
    ///
    /// # Errors
    ///
    /// A store failure.
    pub async fn delivery(&self, msg_id: &str) -> Result<Option<Delivery>, AppError> {
        if let Some(item) = self.read_outbox(msg_id).await? {
            return Ok(Some(match (&item.failed, item.accepted_at_ms) {
                (Some((reason, failed_at_ms)), _) => Delivery::Failed {
                    reason: reason.clone(),
                    failed_at_ms: *failed_at_ms,
                },
                (None, Some(accepted_at_ms)) if !item.resend => {
                    Delivery::Accepted { accepted_at_ms }
                }
                (None, _) => Delivery::Queued {
                    tries: item.tries,
                    last_error: item.last_error.clone(),
                    undeliverable_since_ms: item.undeliverable_ms,
                    undeliverable_reason: item.undeliverable_reason,
                },
            }));
        }
        if let Some(sent) = self.read_sent(msg_id).await? {
            return Ok(Some(Delivery::Accepted {
                accepted_at_ms: sent.first_ms,
            }));
        }
        self.kept_delivery(msg_id).await
    }

    /// The messages sent to `pubky` that its inbox accepted within `[from_ms, until_ms]`,
    /// first acceptances and re-sends, for the protocol's answer to a re-send request
    /// (Dispatch spec 11). Each carries every acceptance time the app kept
    /// ([`SentMessage::accepted_times_ms`]).
    ///
    /// # Errors
    ///
    /// A store failure, or a kept message that doesn't read.
    pub async fn sent_to(
        &self,
        pubky: &[u8; 32],
        from_ms: u64,
        until_ms: u64,
    ) -> Result<Vec<SentMessage>, AppError> {
        let mut out = Vec::new();
        for (msg_id, sent) in self.reader().scan::<SentStored>(SENT_PREFIX).await? {
            if msg_id != sent.msg_id || !sent.is_own(&self.state.meta, &self.state.cert) {
                return Err(store_corrupt());
            }
            let within = std::iter::once(sent.first_ms)
                .chain(sent.resent.iter().copied())
                .any(|at| at >= from_ms && at <= until_ms);
            if sent.to == *pubky && within {
                out.push(SentMessage {
                    to: sent.to,
                    kind: sent.kind.clone(),
                    msg_id: sent.msg_id.clone(),
                    plaintext: MessagePlaintext::decode(&sent.plaintext)
                        .map_err(|_| store_corrupt())?,
                    accepted_at_ms: Some(sent.first_ms),
                    resent_at_ms: sent.resent_ascending(),
                });
            }
        }
        Ok(out)
    }

    // ---------------------------------------------------------------------------------
    // Flushing

    /// Try queued messages' jobs once each (Dispatch spec 11: on start, on returning to the
    /// foreground, when the network comes back), after the deliveries of the own
    /// `identity.json` owed, and forget sent messages past their retention, and the ends of
    /// kept batches past theirs ([`super::App::kept_batch`]).
    ///
    /// The call is bounded:
    /// - Its work goes in units: a delivery of the own `identity.json` to one Dispatch, or
    ///   one message's try (its reply grant, one delivery round and its record job,
    ///   each a bounded call of its own), or, at the start of a pass, one kept batch sent
    ///   again. A unit once begun goes whole. The call starts no unit once its time budget
    ///   ([`super::AppConfig::call_budget_ms`]) is spent, but its first. So its worst case is
    ///   the budget and one unit begun within it.
    /// - Delivering the own `identity.json` uses a bulk call. A message's try can also
    ///   read the service time for its replay deadline, write its reply grant,
    ///   fetch the recipient's identity and directory, append its envelope and run its
    ///   record job ([`super::App::update_record`]). A Dispatch call can repeat once
    ///   after a verified timestamp correction. Each HTTP send has its own deadline
    ///   ([`crate::transport::HttpConfig`]). Before retrying an append with a corrected
    ///   timestamp, the app checks whether the delivery is held. The round's time budget
    ///   governs a reseal after `stale_key`, identity delivery after `identity_needed`
    ///   and a reread of the peer identity after an unverified answer.
    /// - It tries at most [`OUTBOX_TRIES_PER_FLUSH`] messages. What is left stays owed, and
    ///   [`OutboxReport::more`] says so: the host flushes again at once.
    /// - It sends one batch kept from an earlier call again, oldest first, as the first unit
    ///   of each pass, and none otherwise. A message whose reply grant is owed goes
    ///   once no batch is kept: with k kept batches, in the k-th pass, sooner when a read or
    ///   another write sends them. A batch past its answer window gets its end in the pass that sends it
    ///   ([`super::App::kept_batch`]). Reads send kept batches
    ///   too ([`super::App::receive`]), and so does each write a message's try makes, one
    ///   first, as every write does. One that keeps failing holds the others behind it until
    ///   its answer window ends, by design: no write overtakes another. A reply grant
    ///   entry is written only once no batch is kept ahead of it, and the holds are read
    ///   after the kept batch its write sends: a settlement that holds the message holds
    ///   its entry too.
    /// - The next flush starts after the last message this one tried, by queue time, and
    ///   goes round, so a message that keeps failing holds up none behind it.
    /// - Flushes go in passes, each trying every queued message and every owed delivery
    ///   once. While a pass is under way, a flush tries only what it hasn't reached; the
    ///   deliveries and the messages start a pass together, and a flush that goes on with
    ///   one starts no new pass of the other. The flush that ends both says `more` false.
    ///   An owed delivery that failed goes behind those not tried yet. A held message
    ///   ([`App::hold_queued`]) makes no request for its delivery and doesn't count towards
    ///   the four.
    /// - Where a pass got is committed after each message's try, so a flush cut short goes
    ///   on from after the last try it finished. A try that a failure or a crash cut short
    ///   goes again first.
    ///
    /// After a pass, messages still queued wait for the host's next flush, on the triggers of
    /// Dispatch spec 11: on start, on returning to the foreground, when the network comes back,
    /// or on a timer of the host's own. A send, a resend or a read doesn't flush the others.
    ///
    /// # Errors
    ///
    /// A store failure, or an alarm. A message that can't be delivered now stays queued.
    pub async fn flush_outbox(&mut self) -> Result<OutboxReport, AppError> {
        Box::pin(async move {
            self.ready_local().await?;
            self.refuse_when_stopped()?;
            validate_outbox(&self.reader(), &self.state.meta, &self.state.cert).await?;
            let budget = self.begin_budget();
            // The units this flush started: a delivery of the own `identity.json` or a
            // message's try. Past the budget none starts but the flush's first.
            let mut units = 0usize;
            let next: Option<OutNext> = self.reader().get(OUT_NEXT).await?;
            let messages_open = next.as_ref().is_some_and(|next| next.open);
            // The two passes go together: a flush that continues one starts no new pass of
            // the other, so a loop "flush while more" tries each delivery and message once.
            let peers_open = self.peers_pass_open().await?;
            let start = !messages_open && !peers_open;
            // A pass begins with one kept batch sent again, oldest first, as before any write:
            // a message whose reply grant is in it, or that it would queue, goes with
            // the pass that follows, and one past its answer window gets its end.
            if start && !self.kept_batches().await?.is_empty() {
                units += 1;
                match self
                    .resume_kept(super::batch::KEPT_RESENDS_PER_WRITE, None)
                    .await
                {
                    Err(error) if is_local(&error) => return Err(error),
                    _ => {}
                }
            }
            let peers_left = if peers_open || start {
                self.deliver_to_recent_peers(&budget, &mut units).await?
            } else {
                false
            };
            let mut items = self.reader().scan::<OutboxItem>(OUT_PREFIX).await?;
            items
                .sort_by(|(a_id, a), (b_id, b)| a.queued_ms.cmp(&b.queued_ms).then(a_id.cmp(b_id)));
            // From after the last message the flush before tried, round the queue.
            if let Some(OutNext { last: (at, id), .. }) = &next {
                let start = items
                    .iter()
                    .position(|(msg_id, item)| (item.queued_ms, msg_id) > (*at, id))
                    .unwrap_or(0);
                items.rotate_left(start);
            }
            let run_messages = messages_open || start;
            // A pass under way tries only the messages it hasn't reached yet.
            let in_pass = |key: &(u64, String)| match &next {
                Some(OutNext {
                    last,
                    pass_first: Some(first),
                    open: true,
                }) => between(last, key, first),
                _ => true,
            };
            let mut report = OutboxReport::default();
            let cutoff = self.now().saturating_sub(SENT_RETENTION_MS);
            let mut tried = 0usize;
            let mut messages_left = false;
            // What the store holds of it, as each try's commit changes it.
            let mut stored = next.clone();
            let mut pass = OutNext {
                last: next
                    .as_ref()
                    .map_or((0, String::new()), |next| next.last.clone()),
                pass_first: next
                    .as_ref()
                    .filter(|next| next.open)
                    .and_then(|next| next.pass_first.clone()),
                open: true,
            };
            for (msg_id, item) in items {
                if let Some((_, failed_ms)) = &item.failed {
                    // Forgotten, plaintext and all, after the retention of sent messages.
                    if *failed_ms <= cutoff {
                        let mut tx = self.tx()?;
                        tx.delete(&out_key(&msg_id))?;
                        self.commit(tx).await?;
                    } else {
                        report.failed.push(msg_id);
                    }
                    continue;
                }
                let key = (item.queued_ms, msg_id.clone());
                // Tried already in this pass, or no pass of the messages in this flush.
                if !run_messages || !in_pass(&key) {
                    report.queued.push(msg_id);
                    continue;
                }
                // At most OUTBOX_TRIES_PER_FLUSH a flush, and no unit past its time but its
                // first: the next flush goes on from here.
                if tried >= OUTBOX_TRIES_PER_FLUSH || (units > 0 && self.spent(&budget)) {
                    messages_left = true;
                    report.queued.push(msg_id);
                    continue;
                }
                // A held message makes no request for its delivery: it doesn't count towards
                // the four.
                let held = self.delivery_waits(&item).await?;
                if !held {
                    tried += 1;
                }
                units += 1;
                let gave_up = self.flush_item(&msg_id).await?;
                // Kept once the try is done, so a flush cut short goes on from after the
                // last try it finished; one a failure or a crash cut short goes again first.
                pass.pass_first.get_or_insert_with(|| key.clone());
                pass.last = key;
                let mut tx = self.tx()?;
                tx.put(OUT_NEXT, &pass)?;
                self.commit(tx).await?;
                stored = Some(pass.clone());
                match gave_up {
                    Some(Duty::DeliveryUnknown { .. }) => {
                        report.unknown.push(msg_id);
                        continue;
                    }
                    Some(_) => {
                        report.undelivered.push(msg_id);
                        continue;
                    }
                    None => {}
                }
                match self.delivery(&msg_id).await? {
                    Some(Delivery::Failed { .. }) => report.failed.push(msg_id),
                    Some(Delivery::Queued { .. }) => report.queued.push(msg_id),
                    _ if self.reader().exists(&out_key(&msg_id)).await? => {
                        report.queued.push(msg_id);
                    }
                    _ => report.done.push(msg_id),
                }
            }
            // Messages of the pass left untried keep it open; otherwise it is over.
            if run_messages {
                if !messages_left {
                    pass.pass_first = None;
                    pass.open = false;
                }
                if stored.as_ref() != Some(&pass) {
                    let mut tx = self.tx()?;
                    tx.put(OUT_NEXT, &pass)?;
                    self.commit(tx).await?;
                }
            }
            report.more = peers_left || messages_left;
            self.prune_sent().await?;
            self.prune_kept_ends().await?;
            Ok(report)
        })
        .await
    }

    /// One try of each job of one message. Returns whether a delivery was given up as
    /// undeliverable.
    ///
    /// A try whose own writes are over the store's sizes ([`StoreError::TooLarge`]), the
    /// message's outbox record or its sent copy, would be refused the same way at every
    /// flush: the delivery is given up for good, as [`App::drop_undeliverable`] gives one
    /// up, and the flush goes on. Only the message's own bytes decide that: a failure's
    /// text is cut where it is taken ([`diagnostic`]) and left out of a record that
    /// doesn't fit with it ([`App::save_item`]). A counterparty's directory too large to cache isn't one
    /// of its writes: it is read again at each send instead (`directory.rs`).
    async fn flush_item(&mut self, msg_id: &str) -> Result<Option<Duty>, AppError> {
        match self.try_item(msg_id).await {
            Err(AppError::Store(StoreError::TooLarge { .. })) => {
                // The refused commit may have left memory ahead of the store: read it again
                // before going on.
                self.reload_now().await?;
                self.give_up_too_large(msg_id).await
            }
            tried => tried,
        }
    }

    /// Give up the delivery of a message whose try is too large for the store, in one
    /// commit with its duty event ([`OutboxItem::give_up_duty`]): a
    /// message never accepted is deleted, plaintext and all; one accepted before keeps its
    /// record while its record job is owed, and only the re-send is given up.
    async fn give_up_too_large(&mut self, msg_id: &str) -> Result<Option<Duty>, AppError> {
        let Some(mut item) = self.read_outbox(msg_id).await? else {
            return Ok(None);
        };
        let duty =
            item.give_up_duty(item.is_resend() || self.reader().exists(&sent_key(msg_id)).await?);
        item.resend = false;
        item.sealed = None;
        item.clear_undeliverable();
        let fits = u64::try_from(super::state::encode(&item)?.len())
            .is_ok_and(|size| size <= crate::store::MAX_VALUE_BYTES);
        let mut gone = item.accepted_at_ms.is_none() || item.complete() || !fits;
        loop {
            let mut tx = self.tx()?;
            if gone {
                tx.delete(&out_key(msg_id))?;
            } else {
                tx.put(&out_key(msg_id), &item)?;
            }
            self.end_delivery(msg_id, &mut tx).await?;
            let to = self.owners_of_kind(&item.kind);
            self.keep_duty_for(&mut tx, to, duty.clone())?;
            match self.commit(tx).await {
                // A record that still doesn't fit goes too, its record job with it.
                Err(AppError::Store(StoreError::TooLarge { .. })) if !gone => {
                    self.reload_now().await?;
                    gone = true;
                }
                committed => return committed.map(|()| Some(duty)),
            }
        }
    }

    /// One try of each job of one message, as one unit: the reply grant, one round of
    /// the delivery, and the record job. Each is a bounded call of its own. A new hold
    /// stops the remaining delivery work, preserving jobs already completed and allowing
    /// an accepted message's record job to continue.
    async fn try_item(&mut self, msg_id: &str) -> Result<Option<Duty>, AppError> {
        let Some(mut item) = self.read_outbox(msg_id).await? else {
            return Ok(None);
        };
        if item.failed.is_some() {
            return Ok(None);
        }
        // A delivery to a counterparty the host holds, of a message it holds, or one its
        // protocol holds back, isn't tried, a first one or a re-send ([`App::hold_queued`],
        // [`App::hold_message`], [`super::Protocol::may_send`]);
        // its replay deadline still runs, and its record job goes.
        let mut held = self.delivery_waits(&item).await?;
        // A delivery with a replay deadline, one whose envelope may already have been sent,
        // one a restore put back, one `queue_stored` queued, or a re-send, goes only by it,
        // judged at the later of the device clock and a service time verified in this call
        // (Dispatch spec 11). Without fresh verified service time, delivery waits rather than
        // trusting the device clock alone (Dispatch spec 10.1), while firm undeliverable and
        // post-acceptance record-job upkeep still run.
        let mut time_error = None;
        if item.delivery_owed()
            && let Some(deadline) = item.replay_until_ms
        {
            if !held && self.kept_window_now() <= deadline {
                match self.fresh_service_time().await {
                    Ok(()) => {}
                    Err(error) if is_local(&error) => return Err(error),
                    Err(error) => time_error = Some(error),
                }
            }
            if self.kept_window_now() > deadline {
                return self.give_up_outbox(item).await.map(Some);
            }
        }
        // Past the firm bound, the message goes before it is tried again.
        if item
            .undeliverable_ms
            .is_some_and(|since| self.now().saturating_sub(since) >= UNDELIVERABLE_MAX_MS)
            && let Some(duty) = self.drop_undeliverable(&mut item).await?
        {
            return Ok(Some(duty));
        }
        if let Some(error) = time_error {
            item.last_error = Some(diagnostic(&error));
            self.save_item(&item).await?;
            held = true;
        }
        // The reply grant is a write, and a write first sends a batch kept from an
        // earlier call, whose settlement may commit local policy the holds read. So that
        // batch goes first and the holds are read again after it: the entry and the
        // delivery go by this one decision, with nothing kept settled after it.
        if item.grant_reply && !held {
            // A backup or a kept batch may carry an outstanding entry. Only this message's
            // signed content can authorize it, even on the first try after a restore.
            let plaintext = item.plaintext()?;
            let message =
                super::protocols::kept_message(plaintext.json()).ok_or_else(store_corrupt)?;
            item.grant_reply = !item.is_resend()
                && message.to != self.state.meta.identity
                && self.protocols.adds_reply(&message, &plaintext);
        }
        let mut settled = Ok(());
        if item.grant_reply && !held && self.reply_grant_owed(&item.to).await? {
            match self
                .resume_kept(super::batch::KEPT_RESENDS_PER_WRITE, None)
                .await
            {
                Err(error) if is_local(&error) => return Err(error),
                resumed => settled = resumed.map(|_| ()),
            }
            held = self.delivery_waits(&item).await?;
        }
        if !held {
            item.tries = item.tries.saturating_add(1);
        }
        if item.grant_reply && !held {
            let entry = match settled {
                Ok(()) => self.grant_reply_if_owed(&item.to).await,
                Err(error) => Err(error),
            };
            match entry {
                Ok(()) => item.grant_reply = false,
                Err(error) if is_local(&error) => return Err(error),
                Err(error) => {
                    item.last_error = Some(diagnostic(&error));
                    self.save_item(&item).await?;
                    return Ok(None);
                }
            }
            self.save_item(&item).await?;
        }
        if item.delivery_owed() && !held {
            match self.deliver(&mut item).await? {
                Tried::Held => self.save_item(&item).await?,
                Tried::Withdraw => return self.give_up_outbox(item).await.map(Some),
                Tried::Accepted(answer) => self.accept(&mut item, &answer).await?,
                Tried::Queued(why) => {
                    item.last_error = Some(why);
                    self.save_item(&item).await?;
                }
                Tried::Undeliverable(why, reason) => {
                    item.last_error = Some(why);
                    item.count_undeliverable(self.now(), reason);
                    self.save_item(&item).await?;
                    if let Some(duty) = self.drop_undeliverable(&mut item).await? {
                        return Ok(Some(duty));
                    }
                }
                Tried::Failed(why) => {
                    // Refused for good: the delivery ends, and its hold with it.
                    item.failed = Some((why, self.now()));
                    let mut tx = self.tx()?;
                    tx.put(&out_key(&item.msg_id), &item)?;
                    self.end_delivery(&item.msg_id, &mut tx).await?;
                    // The refusal answers only this try: an earlier one may have been
                    // accepted with its answer lost, and then the protocol is told so.
                    let duty = item.give_up_duty(item.is_resend());
                    let unknown = matches!(duty, Duty::DeliveryUnknown { .. });
                    if unknown {
                        let to = self.owners_of_kind(&item.kind);
                        self.keep_duty_for(&mut tx, to, duty.clone())?;
                    }
                    self.commit(tx).await?;
                    if unknown {
                        return Ok(Some(duty));
                    }
                }
            }
        }
        if let Some(accepted) = item.accepted_at_ms
            && !item.record_done
            && let Some(job) = item.record.clone()
        {
            if accepted <= self.now().saturating_sub(SENT_RETENTION_MS) {
                self.drop_record_job(item).await?;
                return Ok(None);
            }
            // The batch an earlier try left kept is settled first: once it applied, the
            // job's write is made, and a later write of the record is another writer's,
            // which the protocol sees in the record.
            let tried = match self.settle_job_batch(&mut item).await? {
                JobBatch::Applied => Ok(None),
                JobBatch::Waits => {
                    self.save_item(&item).await?;
                    return Ok(None);
                }
                JobBatch::NotApplied | JobBatch::Unknown => self.record_job(&item, &job).await,
            };
            match tried {
                Ok(None) => item.record_done = true,
                Ok(Some(deleted)) => {
                    self.stop_record_job(&mut item, &job, deleted).await?;
                    if item.complete() {
                        self.finish_item(&item).await?;
                    }
                    return Ok(None);
                }
                Err(error) if is_local(&error) => return Err(error),
                Err(error) => {
                    if let Some(batch_id) = error.kept_batch() {
                        item.record_batch = Some(pubky_dispatch_core::enc::b64(&batch_id));
                    }
                    item.last_error = Some(diagnostic(&error));
                }
            }
            self.save_item(&item).await?;
        }
        if item.complete() {
            self.finish_item(&item).await?;
        }
        Ok(None)
    }

    /// End a delivery answered `403 not_admitted` or `403 not_current` for
    /// [`UNDELIVERABLE_MS`], at [`UNDELIVERABLE_TRIES`] spaced tries, the last one this
    /// flush's, or for [`UNDELIVERABLE_MAX_MS`] however few tries (Dispatch spec 11): a
    /// message never accepted is deleted, plaintext and all; a re-send is no longer owed.
    /// The protocol is told. Returns the duty event that tells it, if the delivery was
    /// given up.
    async fn drop_undeliverable(
        &mut self,
        item: &mut OutboxItem,
    ) -> Result<Option<Duty>, AppError> {
        let Some(since) = item.undeliverable_ms else {
            return Ok(None);
        };
        let elapsed = self.now().saturating_sub(since);
        let confirmed =
            item.undeliverable_tries >= UNDELIVERABLE_TRIES && elapsed >= UNDELIVERABLE_MS;
        if !confirmed && elapsed < UNDELIVERABLE_MAX_MS {
            return Ok(None);
        }
        // A re-send: of an item accepted before, or queued again from `sent/`.
        let duty = item
            .give_up_duty(item.is_resend() || self.reader().exists(&sent_key(&item.msg_id)).await?);
        item.resend = false;
        item.clear_undeliverable();
        let gone = item.accepted_at_ms.is_none() || item.complete();
        let mut tx = self.tx()?;
        if gone {
            tx.delete(&out_key(&item.msg_id))?;
        } else {
            tx.put(&out_key(&item.msg_id), &*item)?;
        }
        self.end_delivery(&item.msg_id, &mut tx).await?;
        // A duty event for the protocol of the message's kind, kept in the commit that
        // gives the delivery up.
        let to = self.owners_of_kind(&item.kind);
        self.keep_duty_for(&mut tx, to, duty.clone())?;
        self.commit(tx).await?;
        Ok(Some(duty))
    }

    /// Write the outbox record `item` after a try. A record the store refuses for its size
    /// with the last failure's text is written without it: the text never decides whether
    /// the message stays queued. One still refused doesn't fit by the message's own bytes,
    /// and the refusal is the caller's ([`App::flush_item`]).
    async fn save_item(&mut self, item: &OutboxItem) -> Result<(), AppError> {
        match self.put_item(item).await {
            Err(AppError::Store(StoreError::TooLarge { .. })) if item.last_error.is_some() => {
                // The refused commit may have left memory ahead of the store.
                self.reload_now().await?;
                let mut bare = item.clone();
                bare.last_error = None;
                self.put_item(&bare).await
            }
            saved => saved,
        }
    }

    async fn put_item(&mut self, item: &OutboxItem) -> Result<(), AppError> {
        let mut tx = self.tx()?;
        tx.put(&out_key(&item.msg_id), item)?;
        self.commit(tx).await
    }

    /// The counterparty's inbox accepted the message: its acceptance is committed at once,
    /// with the sent message kept for re-sends and what the answer shows of the counterparty's
    /// Dispatch, before anything else is done (Dispatch spec 11). Then what the answer asks for:
    /// the directory read again, the own `identity.json` delivered.
    async fn accept(
        &mut self,
        item: &mut OutboxItem,
        answer: &AppendAnswer,
    ) -> Result<(), AppError> {
        let at = answer.accepted_at;
        let first = *item.accepted_at_ms.get_or_insert(at);
        // The verified append spent this envelope's invitation. A later re-send uses
        // ordinary admission, including when a record job keeps the message in the outbox.
        item.invite_code = None;
        item.resend = false;
        item.last_error = None;
        item.clear_undeliverable();
        let mut tx = self.tx()?;
        tx.put(&out_key(&item.msg_id), &*item)?;
        // No retained producer can recreate this completed delivery after retention.
        self.end_delivery(&item.msg_id, &mut tx).await?;
        let sent = match self.read_sent(&item.msg_id).await? {
            Some(mut sent) => {
                if at != sent.first_ms && !sent.resent.contains(&at) {
                    sent.resent.push(at);
                }
                sent.replay_until_ms = [sent.replay_until_ms, item.replay_until_ms]
                    .into_iter()
                    .flatten()
                    .min();
                sent
            }
            None => {
                tx.put(&sent_time_key(first, &item.msg_id), &())?;
                SentStored {
                    origin: item.origin,
                    to: item.to,
                    kind: item.kind.clone(),
                    msg_id: item.msg_id.clone(),
                    plaintext: item.plaintext.clone(),
                    first_ms: first,
                    resent: if at == first { Vec::new() } else { vec![at] },
                    replay_until_ms: item.replay_until_ms,
                }
            }
        };
        tx.put(&sent_key(&item.msg_id), &sent)?;
        let own = item.to == self.state.meta.identity;
        if !own {
            let mut peer = self.peer_dispatch(&item.to).await?;
            peer.last_sent_ms = Some(self.now());
            peer.known_version = answer.known_version;
            super::directory::put_peer(&mut tx, &item.to, &peer)?;
        }
        self.commit(tx).await?;
        self.events.push(AppEvent::MessageAccepted {
            msg_id: item.msg_id.clone(),
            accepted_at_ms: at,
        });
        if !own {
            self.after_accepted(&item.to, answer).await?;
        }
        Ok(())
    }

    /// Give up the record job of `item`, still owed [`SENT_RETENTION_MS`] after its first
    /// acceptance, such as one whose held value waits for a key that never comes: in one
    /// commit with [`AppEvent::RecordJobDropped`], the item kept only while a re-send of it
    /// is owed, so its plaintext doesn't stay, nor go into every later backup, for ever.
    async fn drop_record_job(&mut self, mut item: OutboxItem) -> Result<(), AppError> {
        item.record = None;
        let mut tx = self.tx()?;
        if item.complete() {
            tx.delete(&out_key(&item.msg_id))?;
        } else {
            tx.put(&out_key(&item.msg_id), &item)?;
        }
        let to = self.owners_of_kind(&item.kind);
        self.keep_duty_for(
            &mut tx,
            to,
            Duty::RecordJobDropped {
                msg_id: item.msg_id.clone(),
                batch_id: item.record_batch.clone(),
            },
        )?;
        self.commit(tx).await
    }

    /// What became of the batch the latest try of `item`'s record job left kept
    /// (`item.record_batch`): a batch still kept is sent again first, in the order of the
    /// kept batches, and waits when that doesn't settle it. One known never applied is
    /// cleared from `item`, so a stop names only a batch that may have applied.
    async fn settle_job_batch(&mut self, item: &mut OutboxItem) -> Result<JobBatch, AppError> {
        Box::pin(async move {
            use super::{KeptBatchDrop, KeptBatchStatus};
            let Some(named) = &item.record_batch else {
                return Ok(JobBatch::NotApplied);
            };
            let id = pubky_dispatch_core::enc::unb64_array::<16>(named)
                .map_err(|_| AppError::Store(StoreError::Corrupt))?;
            let mut status = self.kept_batch(id).await?;
            if matches!(status, Some(KeptBatchStatus::Kept { .. })) {
                match self
                    .resume_kept(super::batch::KEPT_RESENDS_PER_WRITE, None)
                    .await
                {
                    Err(error) if is_local(&error) => return Err(error),
                    Err(error) => item.last_error = Some(diagnostic(&error)),
                    Ok(_) => {}
                }
                status = self.kept_batch(id).await?;
            }
            Ok(match status {
                Some(KeptBatchStatus::Applied { .. }) => JobBatch::Applied,
                Some(KeptBatchStatus::Kept { .. }) => JobBatch::Waits,
                Some(KeptBatchStatus::Dropped {
                    reason: KeptBatchDrop::Refused { .. } | KeptBatchDrop::Unsent,
                    ..
                }) => {
                    item.record_batch = None;
                    JobBatch::NotApplied
                }
                Some(KeptBatchStatus::Dropped { .. }) | None => JobBatch::Unknown,
            })
        })
        .await
    }

    /// Stop the record job of `item` at `deleted`, a delete of its record the job wasn't
    /// queued against ([`App::record_job`]): in one commit with
    /// [`AppEvent::RecordJobStopped`], which names the record, the delete, and the batch an
    /// earlier try left kept whose fate isn't known, so the protocol decides again.
    async fn stop_record_job(
        &mut self,
        item: &mut OutboxItem,
        job: &KeptJob,
        deleted: DeleteBase,
    ) -> Result<(), AppError> {
        let key = self.record_key(&job.job().target)?;
        item.record = None;
        item.record_done = true;
        let mut tx = self.tx()?;
        tx.put(&out_key(&item.msg_id), &*item)?;
        let mut to = self.owners_of_kind(&item.kind);
        if let Some(owner) = self.protocols.of_collection(&job.collection)
            && !to.contains(&owner.name)
        {
            to.push(owner.name.clone());
        }
        self.keep_duty_for(
            &mut tx,
            to,
            Duty::RecordJobStopped {
                msg_id: item.msg_id.clone(),
                key,
                generation: deleted.version.generation,
                version: deleted.version.version,
                item_hash: deleted.item_hash,
                batch_id: item.record_batch.clone(),
            },
        )?;
        self.commit(tx).await
    }

    /// A complete item leaves the outbox; its sent message is kept from its acceptance.
    async fn finish_item(&mut self, item: &OutboxItem) -> Result<(), AppError> {
        let mut tx = self.tx()?;
        tx.delete(&out_key(&item.msg_id))?;
        self.commit(tx).await
    }

    /// Forget sent messages 30 days after their first acceptance, oldest first.
    async fn prune_sent(&mut self) -> Result<(), AppError> {
        let cutoff = self.now().saturating_sub(SENT_RETENTION_MS);
        let mut tx = self.tx()?;
        for (rest, ()) in self.reader().scan::<()>(SENT_TIME_PREFIX).await? {
            let Some((at, msg_id)) = rest.split_once('/') else {
                continue;
            };
            let Ok(at) = super::state::parse_num(at) else {
                continue;
            };
            if at > cutoff {
                break;
            }
            tx.delete(&sent_key(msg_id))?;
            tx.delete(&sent_time_key(at, msg_id))?;
        }
        let now = self.now();
        for (msg_id, until) in self.reader().scan::<u64>(GIVEN_UP_PREFIX).await? {
            // A retained item may still await its turn in a bounded flush. Keep its mark
            // until neither stored copy can produce a re-send, even if this commit removes
            // the sent copy: the next prune can remove the mark.
            if until < now
                && !self.reader().exists(&out_key(&msg_id)).await?
                && !self.reader().exists(&sent_key(&msg_id)).await?
            {
                tx.delete(&given_up_key(&msg_id))?;
            }
        }
        if !tx.is_empty() {
            self.commit(tx).await?;
        }
        Ok(())
    }

    // ---------------------------------------------------------------------------------
    // The jobs

    /// Whether the reply grant for `pubky` is still to be written: the app knows it
    /// holds none and no kept peer (Dispatch spec 7), and its certificate has `reply.add`. A row
    /// a restore brought back that nothing verified since doesn't count (Dispatch spec 12.4).
    pub(super) async fn reply_grant_owed(&self, pubky: &[u8; 32]) -> Result<bool, AppError> {
        use super::admission::observations::verified_row;
        if !self.state.cert.has_permission(Permission::ReplyAdd) {
            return Ok(false);
        }
        let reader = self.reader();
        // A restored row nothing verified since doesn't count as held (Dispatch spec 12.4).
        Ok(!verified_row(&reader, false, pubky).await?
            && !verified_row(&reader, true, pubky).await?)
    }

    /// The reply grant for `pubky`, unless it isn't owed ([`App::reply_grant_owed`]). It is
    /// written only with no batch kept from an earlier call ahead of it: otherwise the call
    /// fails with [`Refusal::NotNow`] and the item is tried again once they are answered.
    /// A kept batch's settlement may close the delivery's holds, so the entry is never kept
    /// behind one, decided before that settlement ([`App::try_item`] sends one kept batch
    /// first and reads the holds after it).
    async fn grant_reply_if_owed(&mut self, pubky: &[u8; 32]) -> Result<(), AppError> {
        if !self.reply_grant_owed(pubky).await? {
            return Ok(());
        }
        if self.kept_ahead().await?.is_some() {
            return Err(Refusal::NotNow(
                "the reply grant waits for the batches kept ahead of it".into(),
            )
            .into());
        }
        self.submit_batch(OpBatch::new().op(OpKind::AllowPut {
            pubky: *pubky,
            reason: PeerReason::Reply,
        }))
        .await?;
        Ok(())
    }

    /// One delivery try (module docs, steps 2 to 4): under the copy of the recipient's
    /// `identity.json` held ([`App::deliver_under`]), and once more after reading the newest
    /// one when an answer of its Dispatch didn't verify with the service key that copy names
    /// and the newest names another key or Dispatch
    /// (Dispatch spec 4.3: a copy is re-fetched after any failure). The reads are bounded
    /// ([`App::reread_after_unverified`]); an answer that still doesn't verify is queued as
    /// any other.
    ///
    /// An unverified answer allows one peer identity reread for retry. The round's budget controls
    /// that reread, resealing after `409 stale_key` and delivery of the own identity after
    /// `409 identity_needed`. A timestamp correction inside a Dispatch call is a separate
    /// HTTP send. The append checks delivery holds before its timestamp retry.
    async fn deliver(&mut self, item: &mut OutboxItem) -> Result<Tried, AppError> {
        // The outer delivery retries share the time budget of this round.
        let round = self.begin_budget();
        let mut reread = false;
        // Whether `try_item` fetched fresh service time for a deadline already on `item`.
        let enforce_deadline = item.replay_until_ms.is_some();
        // True while this store has committed no earlier envelope send and holds no prior
        // replay deadline for `item` (from a restore, `queue_stored`, or a re-send). This
        // reflects only this store's own history.
        let mut first_try = !item.envelope_sent && item.replay_until_ms.is_none();
        loop {
            // Reply grant settlement or a prior retry may have committed new local
            // policy. Re-read the common holds before further delivery work.
            if self.delivery_waits(item).await? {
                return Ok(Tried::Held);
            }
            match Box::pin(self.deliver_under(item, &round, enforce_deadline)).await? {
                Delivered::Tried(Tried::Accepted(answer)) => {
                    if first_try {
                        // Every earlier append in this call, if any (such as `401
                        // stale_timestamp`, `409 stale_key`, or `409 identity_needed`), was
                        // a verified refusal that appended nothing, and this store holds no
                        // earlier send or prior deadline for `item`. Clear the pre-send
                        // bound so `accept` records `out/` and `sent/` without one and
                        // future re-sends run for `SENT_RETENTION_MS` from `accepted_at`
                        // (Dispatch spec 11).
                        item.replay_until_ms = None;
                    }
                    return Ok(Tried::Accepted(answer));
                }
                Delivered::Tried(tried) => return Ok(tried),
                // At most once a round, however long its requests take, and within its time.
                Delivered::Unverified { held, error } => {
                    if item.envelope_sent {
                        first_try = false;
                    }
                    if reread
                        || self.spent(&round)
                        || !Box::pin(self.reread_after_unverified(&item.to, &held)).await?
                    {
                        return queued_or(error);
                    }
                    reread = true;
                }
            }
        }
    }

    /// Read the newest `identity.json` of `to` after an answer of its Dispatch didn't verify
    /// with the service key the copy `held` names, as after a provider loss in place, whose
    /// new key a sender within its cache of the earlier document doesn't know (Dispatch spec
    /// 4.3: a copy is re-fetched after any failure; 12.6). At most one such read per
    /// identity per [`super::SENDER_REREAD_MS`], kept in memory, so a Dispatch answering under
    /// keys no document names makes the app read no more; a read whose copy failed to
    /// commit doesn't count. Returns whether the newest copy
    /// names another Dispatch or key, under which the delivery is tried again; a newer copy
    /// has the directory read again (Dispatch spec 8.1).
    async fn reread_after_unverified(
        &mut self,
        to: &[u8; 32],
        held: &IdentityDoc,
    ) -> Result<bool, AppError> {
        let now = self.now();
        let lately = |at: u64| at <= now && now - at < super::SENDER_REREAD_MS;
        if self.peer_rereads.get(to).is_some_and(|at| lately(*at)) {
            return Ok(false);
        }
        let read = self.peer_identity(to, true).await;
        // The read counts once what it took is committed, an unreadable copy included. A
        // newer copy whose commit failed leaves the held one, and the next try reads again
        // rather than wait out the window under a key that no longer verifies.
        if !matches!(read, Err(AppError::Store(_))) {
            self.peer_rereads.retain(|_, at| lately(*at));
            self.peer_rereads.insert(*to, now);
        }
        let newer = match read {
            Ok(doc) => doc,
            Err(AppError::Store(error)) => return Err(error.into()),
            Err(_) => return Ok(false),
        };
        Ok(newer.inbox() != held.inbox())
    }

    /// One try of the delivery under the recipient's `identity.json` held.
    async fn deliver_under(
        &mut self,
        item: &mut OutboxItem,
        round: &super::CallBudget,
        enforce_deadline: bool,
    ) -> Result<Delivered, AppError> {
        let to = item.to;
        let own = to == self.state.meta.identity;
        let invite = item.invite_code.clone();
        let doc = match self.peer_identity(&to, false).await {
            Ok(doc) => doc,
            Err(error) => return queued_or(error).map(Delivered::Tried),
        };
        // An answer of the recipient's Dispatch that doesn't verify with the key `doc` names.
        let failed = |error: AppError| -> Result<Delivered, AppError> {
            if is_unverified(&error) {
                return Ok(Delivered::Unverified {
                    held: Box::new(doc.clone()),
                    error,
                });
            }
            queued_or(error).map(Delivered::Tried)
        };
        if let Some(sealed) = &item.sealed
            && (sealed.origin != doc.inbox().url || sealed.generation != doc.generation())
        {
            item.sealed = None;
        }
        if !own
            && let Err(error) = self
                .deliver_own_identity(&to, invite.as_deref(), false)
                .await
        {
            return failed(error);
        }
        if item.sealed.is_none()
            && let Err(error) = self.seal(item, invite.as_deref()).await
        {
            return failed(error);
        }
        let mut resealed = 0usize;
        let mut redelivered = false;
        loop {
            let Some(sealed) = item.sealed.clone() else {
                return Ok(Delivered::Tried(Tried::Queued("not sealed".into())));
            };
            // Identity delivery, sealing and retry preparation may write state. The
            // owning protocol checks the resulting state before each actual append,
            // including every retry, for both own and peer recipients.
            if let Some(stopped) = self.before_append(item, enforce_deadline).await? {
                return Ok(Delivered::Tried(stopped));
            }
            // A prepared envelope can be held or withdrawn before its first attempt.
            // Commit possible delivery and its replay deadline (anchored at this first
            // possible send unless the item already carries one) immediately before the
            // first transport call, so a crash or lost answer can neither be reported as
            // definite non-delivery nor outlive the duplicate window (Dispatch spec 11).
            if !item.envelope_sent {
                let previous_deadline = item.replay_until_ms;
                if item.replay_until_ms.is_none() {
                    item.replay_until_ms = Some(replay_deadline(self.now()));
                }
                item.envelope_sent = true;
                self.save_item(item).await?;
                if self.delivery_waits(item).await? {
                    // No transport call followed this new mark. Restore the known
                    // non-delivery and any earlier deadline before exposing the stopped
                    // item to another caller.
                    item.envelope_sent = false;
                    item.replay_until_ms = previous_deadline;
                    self.save_item(item).await?;
                    return Ok(Delivered::Tried(Tried::Held));
                }
            }
            // Persisting the possible send may also have used the remaining window.
            if enforce_deadline && let Some(stopped) = self.replay_deadline_decision(item, None) {
                return Ok(Delivered::Tried(stopped));
            }
            let peer = if own {
                None
            } else {
                Some(self.peer_client(&to, &doc)?)
            };
            let started = peer
                .as_ref()
                .unwrap_or(&self.client)
                .start_append(
                    sealed.envelope.as_bytes().to_vec(),
                    sealed.apps_version,
                    if own { None } else { invite.as_deref() },
                )
                .await;
            let started = if own {
                self.take(started).await
            } else {
                started.map_err(AppError::from)
            };
            let result = match started {
                Ok(call) => {
                    if call.needs_retry() {
                        // Keep the first authenticated response before another decision;
                        // a withheld timestamp retry is not a failed or accepted delivery.
                        if own {
                            self.keep_observations().await?;
                        }
                        if let Some(stopped) = self.before_append(item, enforce_deadline).await? {
                            return Ok(Delivered::Tried(stopped));
                        }
                    }
                    let answer = peer
                        .as_ref()
                        .unwrap_or(&self.client)
                        .finish_append(call)
                        .await;
                    if own {
                        self.take(answer).await
                    } else {
                        answer.map_err(AppError::from)
                    }
                }
                Err(error) => Err(error),
            };
            match result {
                Ok(answer) => return Ok(Delivered::Tried(Tried::Accepted(answer))),
                Err(AppError::Dispatch(ClientError::Dispatch {
                    code: ErrorCode::StaleKey,
                    current,
                    ..
                })) if resealed < RESEALS => {
                    resealed = resealed.saturating_add(1);
                    self.take_stale_key(&to, &current).await?;
                    // Past the round's time the reseal waits for the next try, which seals
                    // to the keys just taken on its first attempt.
                    if self.spent(round) {
                        item.sealed = None;
                        return Ok(Delivered::Tried(Tried::Queued(
                            "409 stale_key: sealed again at the next try".into(),
                        )));
                    }
                    if let Err(error) = self.seal(item, invite.as_deref()).await {
                        return failed(error);
                    }
                }
                Err(AppError::Dispatch(ClientError::Dispatch {
                    code: ErrorCode::IdentityNeeded,
                    ..
                })) if !redelivered && !own => {
                    redelivered = true;
                    // Past the round's time the delivery of the own `identity.json` waits
                    // for the next try, whose first attempt makes it: the Dispatch's copy is
                    // taken as unknown.
                    if self.spent(round) {
                        self.note_known_version(&to, None).await?;
                        return Ok(Delivered::Tried(Tried::Queued(
                            "409 identity_needed: delivered at the next try".into(),
                        )));
                    }
                    if let Err(error) = self
                        .deliver_own_identity(&to, invite.as_deref(), true)
                        .await
                    {
                        return failed(error);
                    }
                }
                Err(AppError::Dispatch(ClientError::Dispatch {
                    code: ErrorCode::Moved,
                    ..
                })) => {
                    // Sent at the new service once the recipient's identity.json names it
                    // (Dispatch spec 11).
                    self.peer_identity(&to, true).await.ok();
                    self.mark_directory_stale(&to).await?;
                    return Ok(Delivered::Tried(Tried::Queued("moved".into())));
                }
                Err(error) => return failed(error),
            }
        }
    }

    /// Whether the delivery of an outbox message waits: one is owed, and the host holds its
    /// counterparty ([`App::hold_queued`]) or the message itself ([`App::hold_message`]), or
    /// its protocol holds it back ([`super::Protocol::may_send`]). Every call that tries a
    /// delivery ([`App::send`], [`App::flush_message`], [`App::resend`],
    /// [`App::flush_outbox`]) goes through `try_item`, which asks this, so no call passes
    /// any of the holds.
    async fn delivery_waits(&self, item: &OutboxItem) -> Result<bool, AppError> {
        if item.to == self.state.meta.identity && self.recovery_required().is_some() {
            return Ok(true);
        }
        Ok(item.delivery_owed() && self.delivery_holds(item).await?.any())
    }

    async fn delivery_holds(&self, item: &OutboxItem) -> Result<DeliveryHolds, AppError> {
        let reader = self.reader();
        Ok(DeliveryHolds {
            message: reader.exists(&message_hold_key(&item.msg_id)).await?,
            counterparty: reader.exists(&hold_key(&item.to)).await?,
            may_send: self.may_send(item),
        })
    }

    /// Whether the protocol of an outbox message's kind lets it go out now
    /// ([`super::Protocol::may_send`]). A message whose kind no protocol owns goes to its
    /// try; unreadable plaintext or unavailable protocol evidence keeps the delivery held.
    fn may_send(&self, item: &OutboxItem) -> bool {
        // Retained-copy validation binds this routing kind to the authenticated JSON.
        // An absent owner supplies no body rules and imposes no protocol hold.
        let Some(owner) = self.protocols.of_kind(&item.kind) else {
            return true;
        };
        self.with_delivery(item, owner, |delivery| {
            owner.protocol.may_send(delivery).unwrap_or(false)
        })
        .unwrap_or(false)
    }

    fn with_delivery<T>(
        &self,
        item: &OutboxItem,
        owner: &super::protocols::Registered,
        use_view: impl FnOnce(&DeliveryView<'_>) -> T,
    ) -> Option<T> {
        let plaintext = item.plaintext().ok()?;
        // Retained copies use the authenticated common fields even when the owner's body
        // rules have changed since the message was signed.
        let message = super::protocols::kept_message(plaintext.json())?;
        let local = super::LocalView::new(
            self.state.meta.identity,
            self.state.meta.app_id,
            self.env.store.store().as_ref(),
            &self.ns,
            &owner.name,
        );
        let delivery = DeliveryView {
            message: &message,
            plaintext: &plaintext,
            origin: item.origin,
            resend: item.is_resend(),
            local,
            cert: &self.state.cert,
            recovery_from: self.state.own_doc.body().recovery_from,
            naming: &self.state.naming,
            store: self.env.store.store().as_ref(),
            ns: &self.ns,
            clock: self.env.clock.as_ref(),
        };
        Some(use_view(&delivery))
    }

    fn replay_deadline_decision(
        &self,
        item: &OutboxItem,
        decision: Option<Tried>,
    ) -> Option<Tried> {
        if matches!(decision, Some(Tried::Withdraw)) {
            return decision;
        }
        let Some(until) = item.replay_until_ms else {
            return decision;
        };
        if self.kept_window_now() > until {
            return Some(Tried::Withdraw);
        }
        let advanced = self.time_fresh_at.as_ref().and_then(|sample| {
            let elapsed = self.clock.elapsed(&sample.local)?;
            Some(
                sample
                    .service_ms
                    .saturating_add(elapsed)
                    .max(sample.local.at_ms.saturating_add(elapsed)),
            )
        });
        let Some(now) = advanced else {
            return decision.or_else(|| {
                Some(Tried::Queued(
                    "a fresh service clock sample is needed".into(),
                ))
            });
        };
        if now > until {
            Some(Tried::Withdraw)
        } else {
            decision
        }
    }

    /// Check every append's replay deadline after preparation, including a signed timestamp
    /// retry and a protocol that requests no records (Dispatch spec 11).
    async fn before_append(
        &mut self,
        item: &OutboxItem,
        enforce_deadline: bool,
    ) -> Result<Option<Tried>, AppError> {
        let decision = self.append_decision(item).await?;
        if enforce_deadline {
            Ok(self.replay_deadline_decision(item, decision))
        } else {
            Ok(decision)
        }
    }

    /// Read only this message owner's registered policies and keep their observations
    /// in this attempt. A retry, including the signed timestamp retry, starts here anew.
    async fn append_decision(&mut self, item: &OutboxItem) -> Result<Option<Tried>, AppError> {
        if self.delivery_waits(item).await? {
            return Ok(Some(Tried::Held));
        }
        let Some(owner) = self.protocols.of_kind(&item.kind).cloned() else {
            return Ok(None);
        };
        let Some(Ok(targets)) =
            self.with_delivery(item, &owner, |d| owner.protocol.append_records(d))
        else {
            return Ok(Some(Tried::Held));
        };
        if targets.is_empty() {
            return Ok(None);
        }
        let members = owner.protocol.collections();
        if targets.len() > MAX_APPEND_RECORDS
            || targets.iter().enumerate().any(|(i, target)| {
                let collection = &target.collection;
                targets[..i].contains(target)
                    || collection.family != super::PolicyFamily::Fixed
                    || !self.state.cert.holds_scope(&collection.policy.read_scope)
                    || self
                        .protocols
                        .foreign_owner(
                            &owner.name,
                            Some(&collection.name),
                            &collection.policy.read_scope,
                        )
                        .is_some()
                    || !members
                        .iter()
                        .any(|m| m.name == collection.name && m.admits(&collection.policy))
            })
        {
            return Ok(Some(Tried::Held));
        }
        let authority = (self.state.own_doc.hash(), self.state.cert.hash());
        let mut records = Vec::with_capacity(targets.len());
        for target in targets {
            let read = Box::pin(self.read_record_fresh(&target)).await?;
            records.push((target, read));
        }
        if authority != (self.state.own_doc.hash(), self.state.cert.hash())
            || self.delivery_waits(item).await?
        {
            return Ok(Some(Tried::Held));
        }
        Ok(
            match self.with_delivery(item, &owner, |d| owner.protocol.judge_append(d, &records)) {
                Some(Ok(AppendDecision::Send)) => None,
                Some(Ok(AppendDecision::Withdraw)) => Some(Tried::Withdraw),
                _ => Some(Tried::Held),
            },
        )
    }

    /// Seal the item's signed plaintext to the recipient apps, and commit the envelope
    /// before it is sent.
    async fn seal(&mut self, item: &mut OutboxItem, invite: Option<&str>) -> Result<(), AppError> {
        let plaintext = item.plaintext()?;
        // Read by its signed common fields, as every kept copy is ([`own_message`]): the
        // body rules judged it when it was queued, and a changed rule never stops it.
        let message = super::protocols::kept_message(plaintext.json()).ok_or_else(store_corrupt)?;
        let (routes, apps_version) = self.routes(&item.to, &message, invite).await?;
        let recipients: Vec<_> = routes.iter().map(|r: &Route| r.recipient).collect();
        let envelope = pubky_dispatch_core::envelope::seal_retained(
            &item.to,
            &recipients,
            &plaintext.encode(),
            item.notify,
        )?;
        let doc = self.peer_identity(&item.to, false).await?;
        item.sealed = Some(Sealed {
            envelope,
            apps_version,
            origin: doc.inbox().url.clone(),
            generation: doc.generation(),
        });
        self.save_item(item).await
    }

    /// An append the counterparty's inbox accepted, its acceptance committed: what its
    /// answer shows about the directory and the own `identity.json` there.
    async fn after_accepted(
        &mut self,
        to: &[u8; 32],
        answer: &AppendAnswer,
    ) -> Result<(), AppError> {
        if let Some(cached) = self.cached_directory(to).await?
            && answer.directory_version > cached.directory_version
        {
            self.mark_directory_stale(to).await?;
        }
        // Delivered again whenever the Dispatch shows an older version (Dispatch spec 6.1); a
        // failure here leaves it to the next send.
        let _ = self.deliver_own_identity(to, None, false).await;
        Ok(())
    }

    /// The record job: the protocol builds the record's next value from what the app holds,
    /// written compare-and-swap, from the delete the job was queued against
    /// ([`App::update_record_on`]). It never writes over another delete, which the protocol
    /// hasn't seen (Dispatch spec 10.3): at any try it returns that delete instead.
    async fn record_job(
        &mut self,
        item: &OutboxItem,
        job: &KeptJob,
    ) -> Result<Option<DeleteBase>, AppError> {
        let kept = self.read_sent(&item.msg_id).await?;
        let sent = SentMessage {
            to: item.to,
            kind: item.kind.clone(),
            msg_id: item.msg_id.clone(),
            plaintext: item.plaintext()?,
            accepted_at_ms: kept
                .as_ref()
                .map(|sent| sent.first_ms)
                .or(item.accepted_at_ms),
            resent_at_ms: kept
                .as_ref()
                .map(SentStored::resent_ascending)
                .unwrap_or_default(),
        };
        let base = Some(job.delete_base);
        let job = job.job();
        let protocols = self.protocols.clone();
        let updated = self
            .update_record_on(&job.target, Vec::new(), base, |current| {
                protocols.sent_record(&job, &sent, current)
            })
            .await?;
        Ok(match updated {
            super::records::Updated::Written(_) => None,
            super::records::Updated::Stopped { deleted, .. } => Some(deleted),
        })
    }
}

/// What became of the batch a try of a record job left kept ([`App::settle_job_batch`]).
enum JobBatch {
    /// Applied: the job's write is made.
    Applied,
    /// Still kept after a send that didn't settle it: the job waits for a later flush.
    Waits,
    /// None was kept, or the one kept was never applied.
    NotApplied,
    /// Its fate can't be known any more: dropped after a send that wasn't answered, or
    /// ended before a restore or longer ago than the store keeps.
    Unknown,
}

/// What one try of a delivery came to.
enum Delivered {
    /// Held, or tried: accepted, queued, undeliverable or failed.
    Tried(Tried),
    /// An answer of the recipient's Dispatch that didn't verify with the service key of the
    /// copy `held` of its `identity.json`.
    Unverified {
        held: Box<IdentityDoc>,
        error: AppError,
    },
}

/// Whether `error` is an answer whose service signature is missing or doesn't verify with
/// the key pinned (Dispatch wire 7.1).
fn is_unverified(error: &AppError) -> bool {
    matches!(
        error.unkept(),
        AppError::Dispatch(ClientError::BadServiceSignature { .. })
    )
}

/// The most bytes of a failure's text an outbox record keeps (`last_error`, a refusal's
/// reason): the text is for a person to read, and comes from the transport or a service,
/// so nothing bounds it before here.
pub(crate) const MAX_DIAGNOSTIC_BYTES: usize = 512;

/// A failure's text as an outbox record keeps it: cut to [`MAX_DIAGNOSTIC_BYTES`] at a
/// character boundary. What a failure says must never decide whether the message it
/// answers stays queued: every text a record takes from an error goes through here.
fn diagnostic(error: &impl std::fmt::Display) -> String {
    let mut text = error.to_string();
    if text.len() > MAX_DIAGNOSTIC_BYTES {
        let mut end = MAX_DIAGNOSTIC_BYTES;
        while !text.is_char_boundary(end) {
            end = end.saturating_sub(1);
        }
        text.truncate(end);
    }
    text
}

/// Whether an error is the app's own (an alarm, the store, a refusal of the app's rules)
/// rather than the network's or the Dispatch's, which the outbox retries.
fn is_local(error: &AppError) -> bool {
    matches!(error.unkept(), AppError::Alarm(_) | AppError::Store(_))
}

/// A failed try: failed for good only when the Dispatch refused it for good, the Retry column
/// of Dispatch spec 6.4 saying "No"; queued again for everything else (the network, `429`,
/// `503`, a refusal of the app's rules that may lift). `403 not_admitted` and `403
/// not_current` stay queued for a bounded time: admission changes when the counterparty adds
/// a kept peer or an invite (Dispatch spec 7), and a renewal makes a certificate current again
/// (Dispatch wire 3.8).
fn queued_or(error: AppError) -> Result<Tried, AppError> {
    match &error {
        AppError::Alarm(_) | AppError::Store(_) => Err(error),
        AppError::Dispatch(ClientError::Dispatch {
            code: ErrorCode::NotAdmitted,
            ..
        }) => Ok(Tried::Undeliverable(
            diagnostic(&error),
            UndeliverableReason::NotAdmitted,
        )),
        AppError::Dispatch(ClientError::Dispatch {
            code: ErrorCode::NotCurrent,
            ..
        }) => Ok(Tried::Undeliverable(
            diagnostic(&error),
            UndeliverableReason::NotCurrent,
        )),
        AppError::Dispatch(ClientError::Dispatch { code, .. }) if code.retry() == Retry::No => {
            Ok(Tried::Failed(diagnostic(&error)))
        }
        _ => Ok(Tried::Queued(diagnostic(&error))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_send_failures_split_into_retry_and_refusal() {
        let dispatch = |code: ErrorCode| {
            AppError::Dispatch(ClientError::Dispatch {
                status: code.status(),
                code,
                message: String::new(),
                current: Value::Null,
                known_version: None,
                retry_after: None,
            })
        };
        assert!(matches!(
            queued_or(dispatch(ErrorCode::RateLimited)),
            Ok(Tried::Queued(_))
        ));
        assert!(matches!(
            queued_or(dispatch(ErrorCode::Unavailable)),
            Ok(Tried::Queued(_))
        ));
        assert!(matches!(
            queued_or(dispatch(ErrorCode::NotAdmitted)),
            Ok(Tried::Undeliverable(_, UndeliverableReason::NotAdmitted))
        ));
        assert!(matches!(
            queued_or(dispatch(ErrorCode::NotCurrent)),
            Ok(Tried::Undeliverable(_, UndeliverableReason::NotCurrent))
        ));
        assert!(matches!(
            queued_or(dispatch(ErrorCode::Conflict)),
            Ok(Tried::Queued(_))
        ));
        assert!(matches!(
            queued_or(dispatch(ErrorCode::TooLarge)),
            Ok(Tried::Failed(_))
        ));
        assert!(matches!(
            queued_or(dispatch(ErrorCode::PermissionMissing)),
            Ok(Tried::Failed(_))
        ));
        assert!(matches!(
            queued_or(AppError::Transport(crate::error::TransportError::Timeout)),
            Ok(Tried::Queued(_))
        ));
        assert!(queued_or(AppError::Store(crate::error::StoreError::Unavailable)).is_err());
    }

    /// Every kind of failed try keeps its service's or transport's text cut to the bound,
    /// its code still first.
    #[test]
    fn test_send_failures_keep_a_long_text_cut_short() {
        let long = "m".repeat(MAX_DIAGNOSTIC_BYTES * 4);
        let dispatch = |code: ErrorCode| {
            AppError::Dispatch(ClientError::Dispatch {
                status: code.status(),
                code,
                message: long.clone(),
                current: Value::Null,
                known_version: None,
                retry_after: None,
            })
        };
        let connect = AppError::Transport(crate::error::TransportError::Connect(long.clone()));
        for (error, code) in [
            (dispatch(ErrorCode::Unavailable), "unavailable"),
            (dispatch(ErrorCode::NotAdmitted), "not_admitted"),
            (dispatch(ErrorCode::NotCurrent), "not_current"),
            (dispatch(ErrorCode::PermissionMissing), "permission_missing"),
            (connect, "connection failed"),
        ] {
            let (Ok(Tried::Queued(text))
            | Ok(Tried::Undeliverable(text, _))
            | Ok(Tried::Failed(text))) = queued_or(error)
            else {
                panic!("{code}: not a failed try");
            };
            assert_eq!(text.len(), MAX_DIAGNOSTIC_BYTES, "{code}");
            assert!(text.contains(code), "{code}");
        }
    }

    #[test]
    fn test_send_outgoing_debug_shows_only_the_kind() {
        let mut body = Map::new();
        body.insert("text".into(), Value::String("secret".into()));
        let message = OutgoingMessage::new([1; 32], "sample.note", body);
        assert_eq!(format!("{message:?}"), "OutgoingMessage(sample.note)");
    }

    /// A queued message accepted once, with a record job owed and an envelope sealed for
    /// its re-send.
    fn accepted_item() -> OutboxItem {
        OutboxItem {
            origin: DeliveryOrigin::Original,
            to: [1; 32],
            kind: "sample.note".into(),
            msg_id: "m1".into(),
            plaintext: Vec::new(),
            notify: false,
            invite_code: None,
            grant_reply: false,
            sealed: Some(Sealed {
                envelope: pubky_dispatch_core::envelope::seal_retained(
                    &[1; 32],
                    &[pubky_dispatch_core::envelope::Recipient::new(
                        pubky_dispatch_core::keys::ReceiveKey::generate(0)
                            .unwrap()
                            .public,
                    )],
                    &[],
                    false,
                )
                .unwrap(),
                apps_version: 1,
                origin: "https://bob.example".into(),
                generation: 1,
            }),
            record: Some(KeptJob {
                collection: "sample.items".into(),
                policy: pubky_dispatch_core::ident::Policy::new("scope-a", &["scope-a"]),
                natural_key: b"n1".to_vec(),
                tag: Vec::new(),
                delete_base: None,
            }),
            record_done: false,
            accepted_at_ms: Some(1_000),
            failed: None,
            last_error: None,
            tries: 1,
            queued_ms: 500,
            resend: true,
            undeliverable_ms: None,
            undeliverable_reason: None,
            undeliverable_last_ms: None,
            undeliverable_tries: 0,
            resend_queued: false,
            replay_until_ms: None,
            record_batch: None,
            envelope_sent: true,
        }
    }

    #[test]
    fn test_outbox_record_job_requires_its_delete_base() {
        let mut stored = serde_json::to_value(accepted_item()).unwrap();
        assert!(serde_json::from_value::<OutboxItem>(stored.clone()).is_ok());
        assert_eq!(
            stored["record"]
                .as_object_mut()
                .unwrap()
                .remove("delete_base"),
            Some(Value::Null)
        );
        assert!(serde_json::from_value::<OutboxItem>(stored).is_err());
    }

    #[test]
    fn test_outbox_give_up_keeps_an_owed_record_job_without_the_envelope() {
        let (kept, duty) = accepted_item().give_up_delivery();
        let kept = kept.expect("the record job is owed");
        assert!(!kept.delivery_owed());
        assert!(
            kept.sealed.is_none(),
            "the envelope sealed for the re-send goes"
        );
        assert!(!kept.record_done);
        assert!(matches!(
            duty,
            Duty::MessageUndelivered { resend: true, .. }
        ));
        // Never accepted: nothing stays.
        let mut never = accepted_item();
        never.accepted_at_ms = None;
        never.resend = false;
        let (kept, _) = never.give_up_delivery();
        assert!(kept.is_none());
    }

    /// Every row of the restore's table (`STATE.md`, "A restore decides on each message"):
    /// what the store holds of the message down, what the backup carries of it across.
    #[test]
    fn test_outbox_restored_decides_every_row_of_the_table() {
        use BackupCopy as B;
        use LiveCopy as L;
        use Restored::{Backup, BackupGoesOn, BackupHeld, Ended, GoesOn, Stands, StandsHeld};
        let backups = [B::Nothing, B::FirstSend, B::Resend, B::Settled];
        let table = [
            (L::Nothing, [Stands, BackupHeld, BackupHeld, Backup]),
            (L::Accepted, [Stands, Stands, BackupHeld, Stands]),
            (L::GivenUp, [Stands; 4]),
            (L::FirstSend, [StandsHeld, GoesOn, BackupGoesOn, Backup]),
            (L::Resend, [StandsHeld, GoesOn, GoesOn, StandsHeld]),
            (L::Settled, [Stands, Stands, BackupHeld, Stands]),
        ];
        // The same, where the delivery was told given up: none is owed, and what the store
        // ended or the backup carries settled stands.
        let told = [
            (L::Nothing, [Stands, Ended, Ended, Backup]),
            (L::Accepted, [Stands; 4]),
            (L::GivenUp, [Stands; 4]),
            (L::FirstSend, [Ended, Ended, Ended, Backup]),
            (L::Resend, [Ended; 4]),
            (L::Settled, [Stands; 4]),
        ];
        for (rows, is_told) in [(table, false), (told, true)] {
            for (live, outcomes) in rows {
                for (backup, outcome) in backups.into_iter().zip(outcomes) {
                    assert_eq!(
                        restored(live, backup, is_told),
                        outcome,
                        "{live:?}, {backup:?}, told: {is_told}"
                    );
                }
            }
        }
    }

    /// An outbox record of each shape a store or a backup holds: owed its first delivery,
    /// owed a re-send (accepted before, or queued again from the sent copy), accepted with
    /// its record job owed, and refused for good.
    fn shapes() -> Vec<OutboxItem> {
        let first = || {
            let mut item = accepted_item();
            item.accepted_at_ms = None;
            item.resend = false;
            item
        };
        let mut from_sent = first();
        from_sent.resend_queued = true;
        let mut job_only = accepted_item();
        job_only.resend = false;
        let mut failed = first();
        failed.failed = Some(("bad_request".into(), 1));
        vec![first(), accepted_item(), from_sent, job_only, failed]
    }

    /// The rules of a restore hold in every cell of its table, checked on the record each
    /// cell leaves and not on the table: for every shape of the store's record or mark,
    /// every shape of the backup's record, told or not, and either copy's deadline the
    /// earlier.
    #[test]
    fn test_outbox_restored_keeps_its_rules_in_every_cell() {
        const BASELINE: u64 = 1_000_000;
        // What the store holds: a record, or only a mark.
        let mut stores: Vec<(LiveCopy, Option<OutboxItem>)> = vec![
            (LiveCopy::Nothing, None),
            (LiveCopy::Accepted, None),
            (LiveCopy::GivenUp, None),
        ];
        for item in shapes() {
            let store = LiveOutbox {
                items: [(item.msg_id.clone(), item.clone())].into_iter().collect(),
                ..LiveOutbox::default()
            };
            stores.push((store.copy(&item.msg_id), Some(item)));
        }
        let mut backups: Vec<Option<OutboxItem>> = vec![None];
        backups.extend(shapes().into_iter().map(Some));
        let pending =
            |item: &Option<OutboxItem>| item.as_ref().is_some_and(|i| i.delivery_pending());
        // A copy that says the recipient accepted the message before.
        let accepted = |item: &Option<OutboxItem>| item.as_ref().is_some_and(|i| i.is_resend());
        // A copy that owes something besides its delivery: a record job. A record refused
        // for good owes nothing.
        let other_jobs = |item: &Option<OutboxItem>| {
            item.clone()
                .filter(|i| i.failed.is_none())
                .and_then(OutboxItem::without_delivery)
                .is_some()
        };
        let mut cells = BTreeSet::new();
        for (live, newest) in &stores {
            for carried in &backups {
                for told in [false, true] {
                    for (store_until, backup_until) in
                        [(Some(300), Some(500)), (Some(500), Some(300)), (None, None)]
                    {
                        // Each copy with its own deadline and its own count of tries, so
                        // the record a cell leaves says which copy it came from.
                        let newest = newest.clone().map(|mut item| {
                            item.replay_until_ms = store_until.map(|ms| BASELINE + ms);
                            item.tries = 7;
                            item
                        });
                        let carried = carried.clone().map(|mut item| {
                            item.replay_until_ms = backup_until.map(|ms| BASELINE + ms);
                            item.tries = 3;
                            item
                        });
                        let backup = carried
                            .as_ref()
                            .map_or(BackupCopy::Nothing, OutboxItem::backup_copy);
                        let decision = restored(*live, backup, told);
                        let cell = format!("{live:?}, {backup:?}, told: {told}: {decision:?}");
                        cells.insert((format!("{live:?}"), format!("{backup:?}"), told));
                        let result =
                            match decision.record(newest.as_ref(), carried.as_ref(), BASELINE) {
                                Rewrite::Leave => newest.clone(),
                                Rewrite::Put(item) => Some(*item),
                                Rewrite::Delete => None,
                            };
                        let (live_owes, backup_owes, owes) =
                            (pending(&newest), pending(&carried), pending(&result));
                        let held = owes && decision.holds();
                        // A give-up already told is never undone: no delivery is owed,
                        // held or not.
                        assert!(!told || !owes, "told, and owed again: {cell}");
                        // Delivered on the restore's own word only where both owe it.
                        assert!(
                            !owes || held || (live_owes && backup_owes),
                            "delivered where one side doesn't owe it: {cell}"
                        );
                        // A delivery the store owes doesn't vanish: it stays owed, unless it
                        // was told given up, or the backup knows a first delivery settled.
                        if live_owes && !told {
                            let settled_since = !accepted(&newest)
                                && carried.as_ref().is_some_and(|c| !c.delivery_pending());
                            assert!(
                                owes || settled_since,
                                "the store's delivery is lost: {cell}"
                            );
                            // Then the backup's record is the one that stays.
                            let tries = |item: &Option<OutboxItem>| item.as_ref().map(|i| i.tries);
                            assert!(
                                !settled_since || tries(&result) == tries(&carried),
                                "{cell}"
                            );
                        }
                        // Nor does one the backup owes: it stays owed, unless it was told
                        // given up, the store gave it up, or the store knows a first
                        // delivery settled.
                        if backup_owes && !told {
                            let settled_since = !accepted(&carried)
                                && matches!(live, LiveCopy::Accepted | LiveCopy::Settled);
                            assert!(
                                owes || *live == LiveCopy::GivenUp || settled_since,
                                "the backup's delivery is lost: {cell}"
                            );
                        }
                        // A record goes only when no copy of it owes anything else; a store
                        // that keeps nothing but a mark has finished with the message.
                        if result.is_none() && newest.is_some() {
                            assert!(
                                told && !other_jobs(&newest) && !other_jobs(&carried),
                                "{cell}"
                            );
                        }
                        if result.is_none() && newest.is_none() && other_jobs(&carried) {
                            assert!(
                                matches!(live, LiveCopy::Accepted | LiveCopy::GivenUp),
                                "the backup's other jobs are lost: {cell}"
                            );
                        }
                        // What else the record owes survives a give-up, from the copy that
                        // knows the message accepted.
                        if told && newest.is_some() && (other_jobs(&newest) || other_jobs(&carried))
                        {
                            assert!(result.is_some(), "the record's other jobs are lost: {cell}");
                        }
                        // A restore never moves a replay deadline later: the record it
                        // leaves owed goes by the earliest deadline of every copy owed a
                        // delivery, and of the backup's time for one the backup brings.
                        if let Some(result) = result.as_ref().filter(|_| owes) {
                            let until = result.replay_until_ms;
                            let no_later = |bound: u64| until.is_some_and(|until| until <= bound);
                            for copy in [&newest, &carried].into_iter().flatten() {
                                if let Some(bound) =
                                    copy.replay_until_ms.filter(|_| copy.delivery_pending())
                                {
                                    assert!(no_later(bound), "{cell}");
                                }
                            }
                            if backup_owes {
                                assert!(no_later(BASELINE + SENT_RETENTION_MS), "{cell}");
                            }
                            // The store's record is the one that stays, but where the
                            // backup's knows an acceptance the store's doesn't.
                            let from = match (&newest, &carried) {
                                (Some(newest), Some(carried))
                                    if !newest.is_resend() && carried.is_resend() =>
                                {
                                    carried
                                }
                                (Some(newest), _) if newest.delivery_pending() => newest,
                                (_, Some(carried)) => carried,
                                (Some(newest), None) => newest,
                                (None, None) => unreachable!("a record from no copy"),
                            };
                            assert_eq!(result.tries, from.tries, "{cell}");
                        }
                    }
                }
            }
        }
        assert_eq!(cells.len(), 48, "every cell of the table");
    }

    /// A record is read as the copy the table takes it for, in the store and in a backup.
    #[test]
    fn test_outbox_copy_of_a_record_is_its_place_in_the_table() {
        let first = || {
            let mut item = accepted_item();
            item.accepted_at_ms = None;
            item.resend = false;
            item
        };
        let mut from_sent = first();
        from_sent.resend_queued = true;
        let mut job_only = accepted_item();
        job_only.resend = false;
        let mut failed = first();
        failed.failed = Some(("bad_request".into(), 1));
        let cases = [
            (first(), LiveCopy::FirstSend, BackupCopy::FirstSend),
            (accepted_item(), LiveCopy::Resend, BackupCopy::Resend),
            (from_sent, LiveCopy::Resend, BackupCopy::Resend),
            (job_only, LiveCopy::Settled, BackupCopy::Settled),
            (failed, LiveCopy::Settled, BackupCopy::Settled),
        ];
        for (item, live, backup) in cases {
            assert_eq!(item.backup_copy(), backup);
            let store = LiveOutbox {
                items: [(item.msg_id.clone(), item)].into_iter().collect(),
                // Its marks don't speak over its record.
                accepted: ["m1".to_owned()].into_iter().collect(),
                given_up: ["m1".to_owned()].into_iter().collect(),
                ..LiveOutbox::default()
            };
            assert_eq!(store.copy("m1"), live);
        }
        let marks = |accepted: bool, given_up: bool| LiveOutbox {
            accepted: accepted.then(|| "m1".to_owned()).into_iter().collect(),
            given_up: given_up.then(|| "m1".to_owned()).into_iter().collect(),
            ..LiveOutbox::default()
        };
        assert_eq!(marks(false, false).copy("m1"), LiveCopy::Nothing);
        assert_eq!(marks(true, false).copy("m1"), LiveCopy::Accepted);
        assert_eq!(marks(false, true).copy("m1"), LiveCopy::GivenUp);
        assert_eq!(marks(true, true).copy("m1"), LiveCopy::Accepted);
    }

    #[test]
    fn test_outbox_drop_duties_tell_the_delivery_and_the_record_job_apart() {
        // A re-send pending and a record job owed: both end.
        let duties = accepted_item().drop_duties();
        assert!(matches!(
            duties.as_slice(),
            [
                Duty::MessageUndelivered { resend: true, .. },
                Duty::RecordJobDropped { .. }
            ]
        ));
        // Only the record job owed: no delivery is told given up.
        let mut job_only = accepted_item();
        job_only.resend = false;
        assert!(matches!(
            job_only.drop_duties().as_slice(),
            [Duty::RecordJobDropped { msg_id, batch_id: None }] if msg_id == "m1"
        ));
        // Never accepted: its record job isn't owed yet, only the delivery ends.
        let mut never = accepted_item();
        never.accepted_at_ms = None;
        never.resend = false;
        never.replay_until_ms = Some(9_000);
        assert!(matches!(
            never.drop_duties().as_slice(),
            [Duty::DeliveryUnknown { .. }]
        ));
        // Nothing owed: nothing told.
        let mut done = accepted_item();
        done.resend = false;
        done.record_done = true;
        assert!(done.drop_duties().is_empty());
    }

    #[test]
    fn test_outbox_replay_no_later_than_keeps_the_earlier_deadline() {
        let with = |deadline| {
            let mut item = accepted_item();
            item.replay_until_ms = deadline;
            item
        };
        for (own, other, kept) in [
            (Some(9_000), Some(5_000), Some(5_000)),
            (Some(5_000), Some(9_000), Some(5_000)),
            (None, Some(5_000), Some(5_000)),
            (Some(5_000), None, Some(5_000)),
            (None, None, None),
        ] {
            let mut item = with(own);
            item.replay_no_later_than(&with(other));
            assert_eq!(item.replay_until_ms, kept, "{own:?} and {other:?}");
        }
    }

    #[test]
    fn test_outbox_give_up_is_unknown_unless_no_request_can_have_carried_it() {
        // A message never accepted here, never sealed, and held by no other store.
        let unsent = || {
            let mut item = accepted_item();
            item.accepted_at_ms = None;
            item.resend = false;
            item.sealed = None;
            item.envelope_sent = false;
            item
        };
        let restored = || {
            let mut item = unsent();
            item.replay_until(5_000);
            item
        };
        let mut sent = unsent();
        sent.envelope_sent = true;
        let mut stored_copy = unsent();
        stored_copy.origin = DeliveryOrigin::Reconstructed;
        stored_copy.replay_until_ms = Some(9_000);
        let mut resend_of_restored = restored();
        resend_of_restored.resend_queued = true;
        // `Some(resend)` for `MessageUndelivered`, `None` for `DeliveryUnknown`.
        let cases = [
            ("every try refused before sending", unsent(), Some(false)),
            ("a 403 or withdrawal after a sent try", sent, None),
            ("put back by a restore", restored(), None),
            ("a queue_stored copy", stored_copy, None),
            (
                "a re-send of a restored copy",
                resend_of_restored,
                Some(true),
            ),
        ];
        for (case, item, expected) in cases {
            let (_, duty) = item.give_up_delivery();
            let told = match duty {
                Duty::MessageUndelivered { resend, .. } => Some(resend),
                Duty::DeliveryUnknown { .. } => None,
                other => panic!("{case}: {other:?}"),
            };
            assert_eq!(told, expected, "{case}");
        }
    }

    #[test]
    fn test_outbox_replay_deadline_only_comes_earlier() {
        let mut item = accepted_item();
        // The first acceptance's window comes before the backup's.
        item.replay_until(5_000);
        assert_eq!(item.replay_until_ms, Some(1_000 + SENT_RETENTION_MS));
        // A later baseline doesn't move it on; an earlier one brings it forward.
        item.accepted_at_ms = None;
        item.replay_until(9_000);
        assert_eq!(item.replay_until_ms, Some(1_000 + SENT_RETENTION_MS));
        item.replay_until(100);
        assert_eq!(item.replay_until_ms, Some(100 + SENT_RETENTION_MS));
    }

    #[test]
    fn test_outbox_has_valid_deadline() {
        let mut untried = accepted_item();
        untried.accepted_at_ms = None;
        untried.resend = false;
        untried.envelope_sent = false;
        untried.replay_until_ms = None;
        assert!(untried.has_valid_deadline());

        let mut attempted = untried.clone();
        attempted.envelope_sent = true;
        attempted.replay_until_ms = Some(10_000);
        assert!(attempted.has_valid_deadline());
        attempted.replay_until_ms = None;
        assert!(!attempted.has_valid_deadline());

        let mut accepted = accepted_item();
        accepted.resend = false;
        accepted.replay_until_ms = None;
        assert!(accepted.has_valid_deadline());
        accepted.resend = true;
        assert!(!accepted.has_valid_deadline());
        accepted.replay_until_ms = Some(10_000);
        assert!(accepted.has_valid_deadline());
    }
    /// A failure's text is kept up to its bound, cut at a character boundary.
    #[test]
    fn test_outbox_diagnostic_is_cut_at_a_character_boundary() {
        assert_eq!(diagnostic(&"refused"), "refused");
        let exact = "x".repeat(MAX_DIAGNOSTIC_BYTES);
        assert_eq!(diagnostic(&exact), exact);
        // A two-byte character across the bound goes whole.
        let across = format!("{}\u{e9}tail", "x".repeat(MAX_DIAGNOSTIC_BYTES - 1));
        let cut = diagnostic(&across);
        assert_eq!(cut.len(), MAX_DIAGNOSTIC_BYTES - 1);
        assert!(across.starts_with(&cut));
    }
}
