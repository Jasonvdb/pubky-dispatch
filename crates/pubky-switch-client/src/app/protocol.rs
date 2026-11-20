//! The protocol an app is built with: the [`Protocol`] trait.
//!
//! The Switch knows no protocol (Switch spec 1): scopes, message kinds and collections are
//! opaque strings to it. A protocol on the Switch supplies what the app layer can't know:
//! the opaque members of its message bodies, which of its scopes have keys, its kind rules
//! for the recipient checks 6 and 8 (Switch wire 5.1), and what a received message does.
//!
//! The trait is object-safe and takes and returns plain owned types, so a binding can
//! implement it across a language boundary.
//!
//! - **Receiving** ([`Protocol::check_body`], then [`Protocol::receive`]): the app hands
//!   over each message that passed checks 1 to 9. The protocol checks the body (check 10)
//!   on its own, without effects, which is also what a push extension's peek runs; for a
//!   body that passes, it adds, through the [`ReceiveContext`], the shared record writes and
//!   claim entries the app builds and signs for it, all committed in the same batch as the
//!   cursor move, and the writes of its own local state to commit with the outcome (Switch
//!   spec 8.2: "writes the effect to its shared record and advances its cursor in one
//!   batch").
//! - **Re-sends** ([`Protocol::resend_needed`], [`Protocol::missed`]): the kind that asks a
//!   counterparty to send again is a protocol's (Switch spec 11), so the app hands over
//!   what it needs and the protocol queues its request with the local writes it returns.
//!   A protocol that can't read its own state for it says so with a [`StoreFailure`]: the app
//!   keeps what it handed over and hands it over again later, so nothing is lost to a
//!   default.
//! - **Deny list changes** ([`Protocol::deny_list_changed`]): each one the feed shows, in
//!   feed order, with the local writes the protocol returns to keep it, held back and
//!   handed over again as re-sends are, and in the same order (Switch spec 8.3).
//!
//! The protocol's local state lives in the app's namespace under [`LocalWrite`] keys, which
//! the app keeps apart from its own (`STATE.md`).
//!
//! Feed order is per protocol (Switch spec 8.3). The shared deny copy changes only after
//! every protocol has taken the preceding items and the deny change itself; the read
//! stops there while any protocol waits. Entries reached in order but held for sender
//! validation, a key or a retry follow Section 8.2 and may run under a later deny copy.
//! Other shared views are current observations:
//! claims and records, including another protocol's records, may be newer than the
//! message. Use their conditions when a write depends on them; a foreign record does not
//! prove that its protocol has handled it. The certificate, identity, data epoch and keys
//! are the current verified authority, never restored to earlier authority for an older
//! message. Allowlist entries and sender flags are current copies; an explicit list read
//! or gap supplies a current baseline. Reconcile mode and provider-loss restrictions
//! apply immediately to all protocols, and the highest verified service time remains
//! current. None of these current views establishes cross-protocol event order.

use pubky_switch_core::message::{Message, MessagePlaintext};
use pubky_switch_core::ops::{Condition, OpKind, RecordVersion};
use pubky_switch_core::records::{AppCert, AppRecord, Standing};
use serde_json::{Map, Value};

use super::context::{LocalView, ReceiveContext, RestoreContext};
use super::error::{AppError, Refusal};
use super::own_record::RecordExpiry;
use super::records::Collection;
use super::recovery::{LossActions, ProviderLoss};
use super::send::{RecordJob, SentMessage};
use crate::error::StoreError;
use crate::store::KeyValue;

/// What a newer write of a record builds on, and when it was made, as the reading app sees
/// it ([`Protocol::record_regression`], Switch spec 8.2, 10.3).
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct WriteBase {
    /// The evidence of a repair over a held record that directly answered a deletion.
    /// Present only when both signed writes name their exact predecessors and the
    /// collection owner accepted this application for that deletion as `Covered`.
    pub repair: Option<RecordRepair>,
    /// The version the write builds on: the `expected_version` its operation signed,
    /// `{0, 0}` for a create.
    pub expected_version: RecordVersion,
    /// Whether the app holds that version: the write it holds of the record is at
    /// `expected_version`, a delete's included, or, for a create (`{0, 0}`), it holds none or
    /// holds the record deleted: a create applies only where the service holds nothing, so
    /// over a delete the app holds it follows the service forgetting that delete (Switch
    /// wire 6.2).
    /// `false` when the write builds on a version the app never took, such as one it skipped
    /// by reading the record's current view, or on a write it refused and only follows. The
    /// held version is the one the app holds, authenticated by a proof or a stub or only the
    /// record view's word, and whether its value opened doesn't count: a write held not
    /// open ([`super::RecordContent::Unreadable`]) is held at its version.
    pub held: bool,
    /// The conditions the write's operation signed (Switch wire 6.3), in its order, such as
    /// a `claim_step` on a claim its change depends on. The service checked them when it
    /// applied the write; a protocol's reader rule may require one, such as a condition on
    /// the claim of what the write drops, and flag a write without it (Switch spec 8.2).
    pub conditions: Vec<Condition>,
    /// The service time, in Unix milliseconds, the write's verified chain stub or transition
    /// proof dates it at (Switch spec 8.2, 10.3 check 2): an earlier generation's proof that
    /// verifies with the key the newest own `identity.json` lists for it dates it too, a lost
    /// generation's never. `None` when nothing dates it, as for a record taken from a
    /// recovery upload (Switch spec 12.6). For a rule from one version to the next that
    /// depends on when the write was made.
    pub written_at_ms: Option<u64>,
}

/// A record deletion offered to its collection's protocol (Switch spec 8.2, 10.3).
/// Its mark, predecessor and base describe what the app held before the delete, including
/// when the collection owner takes the observation on a later read.
#[non_exhaustive]
pub struct RecordDeletion<'a> {
    /// The collection that registered the callback.
    pub collection: &'a str,
    /// The deleted record.
    pub key: &'a [u8; 32],
    /// The version of the delete.
    pub version: RecordVersion,
    /// The delete's verified application is its original version, in the same
    /// generation as its signature and the app's current service. A later recovery
    /// upload or a version reported without a proof or verified stub does not qualify.
    pub original_in_current_generation: bool,
    /// The app that signed the deletion.
    pub writer: [u8; 16],
    /// The delete's signed item hash.
    pub item_hash: [u8; 32],
    /// The verified server time of the feed page on which the app took the delete.
    /// A delete seen only in a record view has no such observation.
    pub page_time_ms: Option<u64>,
    /// The policy of a readable, authenticated record held before this delete.
    /// With no such source the policy is unknown.
    pub policy: Option<&'a pubky_switch_core::ident::Policy>,
    /// The protocol's last mark before the delete.
    pub seen: Option<&'a [u8]>,
    /// The readable value of the authenticated write this delete builds on. It can
    /// differ from the protocol's mark or exceed its bound. An older or unopened
    /// predecessor, or a different application at the same version, gives no value.
    pub exact_value: Option<&'a [u8]>,
    /// A verified transition proof or chain stub bound the complete predecessor's
    /// item hash to the version the deletion signed as its expected version.
    pub exact_version_authenticated: bool,
    /// The version and conditions the deletion signed.
    pub base: WriteBase,
}

/// The physical key and policy of a value the collection owner is asked to mark.
#[non_exhaustive]
pub struct RecordMarkContext<'a> {
    /// The physical key at which the app will write or observed the value.
    pub key: [u8; 32],
    /// The registered collection with the concrete policy of this write.
    pub collection: &'a super::Collection,
    pub(crate) naming: &'a pubky_switch_core::ident::NamingKey,
}

impl RecordMarkContext<'_> {
    /// Derive a target's physical key with this app's naming key (Switch spec 13.3).
    ///
    /// # Errors
    ///
    /// A policy whose write scopes are not sorted and unique.
    pub fn record_key(&self, target: &super::RecordTarget) -> Result<[u8; 32], super::AppError> {
        target.key_with(self.naming)
    }
}

/// A readable record application verified by the client (Switch spec 8.2, 10.3).
/// The protocol can keep what it learned in its own backup layer.
#[non_exhaustive]
pub struct RecordObservation<'a> {
    /// The accepted record, including the key, policy, signer and content.
    pub record: &'a super::SharedRecord,
    /// The record held immediately before this observation, if any.
    pub previous: Option<&'a super::SharedRecord>,
    /// The verified signed operation carrying this value.
    pub operation: &'a pubky_switch_core::sig::SignedDoc,
    /// The service application of the operation.
    pub application: pubky_switch_core::shared::ApplicationRef,
    /// Whether this observation covers the record's pending uploads in the current
    /// generation. The record itself also reports its divergence and content status.
    pub current: bool,
}

/// The two complete record values a reader can compare with a proposed repair.
/// Both signed writes are authenticated in the deletion's original generation.
#[derive(Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct RecordRepair {
    /// The record both operations changed.
    pub key: [u8; 32],
    /// The deletion over which the held record was written.
    pub deletion: pubky_switch_core::shared::ApplicationRef,
    /// The read and write policy all three operations share.
    pub policy: pubky_switch_core::ident::Policy,
    /// The complete authenticated value on which the deletion was built.
    pub prior_value: Vec<u8>,
    /// The complete authenticated value of the write that answered the deletion.
    pub held_value: Vec<u8>,
}

impl std::fmt::Debug for RecordRepair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RecordRepair")
            .field("deletion", &self.deletion)
            .field("prior_bytes", &self.prior_value.len())
            .field("held_bytes", &self.held_value.len())
            .finish_non_exhaustive()
    }
}

/// How a protocol answers a record deletion (Switch spec 8.2, 10.3).
#[non_exhaustive]
pub enum PutBack {
    /// Pass this deletion and keep the owner's observation.
    Observe {
        /// The owner's local writes for the first observation, or to enrich a held
        /// view when its first verified feed page supplies the time.
        observed: Vec<LocalWrite>,
    },
    /// Keep the deletion while its owner gathers evidence outside this callback.
    /// The owner receives [`super::AppEvent::PutBackWaits`]. It can use
    /// [`super::App::ack_event_with`] to save its checked decision in its own local
    /// state, keyed by the record and delete. Each receive calls back with that state.
    Prepare {
        /// The owner's local writes for the first observation, or to enrich a held
        /// view when its first verified feed page supplies the time.
        observed: Vec<LocalWrite>,
    },
    /// Publish the complete value over this exact signed deletion (Switch spec 10.3).
    Write {
        /// Local writes committed when the owner first observes the deletion.
        observed: Vec<LocalWrite>,
        /// Complete replacement as strict JSON.
        value: Vec<u8>,
    },
}

/// A readable, authenticated live application after a deletion of the same record.
/// The protocol can inspect it even when its ordinary regression rule rejects the value.
#[non_exhaustive]
pub struct RecordSuccessor<'a> {
    /// The original and held values when this candidate repairs the held write
    /// over this deletion. The owner compares both with `value`.
    pub repair: Option<&'a RecordRepair>,
    /// The complete opened JSON value.
    pub value: &'a [u8],
    /// The logical version of this write.
    pub version: RecordVersion,
    /// The exact application of this signed write.
    pub revision: pubky_switch_core::shared::ApplicationRef,
    /// The app that signed the write.
    pub writer: [u8; 16],
    /// The version the writer signed as its predecessor.
    pub expected_version: RecordVersion,
    /// Conditions carried by the signed write.
    pub conditions: &'a [Condition],
    /// The record's authenticated policy.
    pub policy: &'a pubky_switch_core::ident::Policy,
}

/// The collection owner's publication decision for one deletion and one live successor.
#[non_exhaustive]
pub enum PutBackSuccessor {
    /// Keep the duty and its service cursor while evidence or a repair is unavailable.
    Wait,
    /// This applied value already contains everything required for this deletion.
    Covered,
    /// Publish the combined value, conditional on this exact live application.
    Merge {
        /// Complete strict JSON, including the successor's additional members.
        value: Vec<u8>,
    },
}

/// An opaque member of a protocol's message bodies (Switch wire 1.1): its numbers aren't
/// checked against the integer range.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OpaqueRule {
    /// The kind the rule applies to, or `None` for every kind of the protocol that gives
    /// the rule.
    pub kind: Option<String>,
    /// The member of `body`.
    pub member: String,
}

/// The original observation of an inbox input in a verified feed response (Switch spec
/// 8.2). This is retained metadata, not a portable signed proof of acceptance.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct EntryReceipt {
    /// The inbox entry's ID.
    #[serde(with = "pubky_switch_core::enc::serde_b64")]
    pub entry_id: [u8; 16],
    /// The pinned service key that verified the feed response.
    #[serde(with = "pubky_switch_core::enc::serde_b64")]
    pub service_key: [u8; 32],
    /// The time stamped on that response, in Unix milliseconds. A retained input keeps
    /// this value through retries, reload and restore; a later answer does not replace it.
    pub read_at_ms: u64,
}

/// A message that passed the recipient checks 1 to 9 (Switch wire 5.1), handed to the
/// protocol for check 10 ([`Protocol::check_body`]) and its effect ([`Protocol::receive`]).
#[derive(Clone, Debug)]
pub struct ReceivedMessage {
    /// The original verified feed observation of this input.
    pub receipt: EntryReceipt,
    /// The `seq` the entry was read at, in [`ReceivedMessage::generation`]. A stored
    /// entry's handle is its local ID ([`super::AppEvent::Parked`]), not this `seq`.
    pub seq: u64,
    /// The generation the entry was read at: the current one for an entry of the feed, and
    /// for one stored locally (`parked`) the one it was first read at, which a provider
    /// change since may have left behind; a retry reports the same pair every time. With
    /// `seq` it is the entry's position in the inbox, by which a protocol orders what it
    /// keeps: a move or a key change continues the sequence under the next generation, and
    /// a provider loss starts a new one, so two entries can share a `seq` in different
    /// generations.
    pub generation: u64,
    /// The sender identity.
    pub sender: [u8; 32],
    /// When the inbox accepted it, service time in Unix milliseconds.
    pub accepted_at_ms: u64,
    /// The message's common fields and body.
    pub message: Message,
    /// The signed plaintext, kept for verifiable copies (Switch spec 8.2).
    pub plaintext: MessagePlaintext,
    /// The sender's certificate, verified.
    pub cert: AppCert,
    /// The sender app's standing when the message was accepted.
    pub standing: Standing,
    /// The invite code's context, if one admitted the entry; opaque.
    pub context: Option<Value>,
    /// Whether the entry was stored locally before and the cursor is past it already.
    pub parked: bool,
    /// Whether the host released the entry ([`super::App::release_parked`]) after its
    /// effect was uncertain ([`super::AppEvent::EffectUncertain`]): the app no longer counts
    /// it processed, and builds its effect again. The host releases it only once it knows
    /// the effect wasn't applied; a protocol that may have compensated from its own state
    /// since, or can't tell, declines with [`Outcome::Drop`], which keeps the message
    /// processed.
    ///
    /// The service refuses an effect run again this way where an operation depends on what
    /// its first application changed, such as a record write's expected version or a
    /// claim's step, and it checks conditions for the whole batch (Switch spec 8.2, 10.1);
    /// otherwise its operations, and its local writes, may apply twice.
    pub released: bool,
    /// After a `409 conflict` on the effect's batch: the answer's `current`, so the
    /// protocol builds its effect again on what the service holds now.
    pub conflict: Option<Value>,
}

impl ReceivedMessage {
    /// The entry's position in the inbox: [`ReceivedMessage::generation`] and
    /// [`ReceivedMessage::seq`]. Two positions compare in feed order with
    /// [`super::App::received_order`] or [`super::ReceiveContext::received_order`], not as
    /// a plain pair.
    pub fn position(&self) -> FeedPosition {
        FeedPosition {
            generation: self.generation,
            seq: self.seq,
        }
    }
}

/// A position in the app's feed: the generation an item was read at and its `seq` there
/// (Switch spec 8.3 "One order per generation"). It has no order of its own: a cooperative
/// move and a key change in place continue the sequence under the next generation, and only
/// a provider loss starts a new one, so a plain `(generation, seq)` comparison puts an
/// entry read before a move after one read since. [`super::App::received_order`] compares
/// two in feed order.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct FeedPosition {
    /// The generation the item was read at.
    pub generation: u64,
    /// The item's `seq` in that generation.
    pub seq: u64,
}

/// The most bytes of local writes a protocol or host hands over at once: one receive step,
/// one [`Protocol::resend_needed`], [`Protocol::missed`] or [`Protocol::deny_list_changed`]
/// answer, or one
/// [`super::OpBatch`]'s local writes ([`Protocol`], "Limits a receive step plans for").
/// 4 MiB, counted by [`local_writes_bytes`].
///
/// It is chosen so that whatever the app keeps or commits with such writes fits the store
/// ([`crate::store::MAX_VALUE_BYTES`] 16 MiB per value, [`crate::store::MAX_BATCH_BYTES`]
/// 32 MiB per commit):
///
/// - **Kept, in base64:** each write is kept qualified, its key or prefix after the
///   protocol's name and `/` (at most 33 bytes), as `{"Put":{"key":"...","value":"..."}},`,
///   its key and value in base64url: at most `4/3 (k + 33 + v) + 40 = 4/3 (k + v) + 84`
///   bytes, which is under `4/3 (k + v + 72)` since 4/3 x 72 = 96. So writes at the bound
///   keep in at most 4/3 x 4 MiB = 5.34 MiB.
/// - **A kept effect** (`pending/effect`) adds its batch, at most the 4 MiB `POST /ops`
///   body (Switch wire 7.1), 5.34 MiB in base64, and its entry: the plaintext (at most the
///   64 KiB envelope, 87 KiB in base64), the certificate (under 33 KiB) and a context (1
///   KiB), with under 8 KiB of other fields: under 10.9 MiB, below the 16 MiB value size.
///   A kept batch (`opq/`) carries the same body and writes, and the messages it queues.
/// - **Committed:** each write takes its key and value, the namespace (at most 33 bytes),
///   the `p/` prefix and the protocol's name and `/` (at most 33 bytes), under
///   `k + v + 72`: at most 4 MiB. An applied effect's outcome
///   adds at most 7 cached record writes (each under 1.2 MiB with its proof and opened
///   value), under 13 MiB in all, below the 32 MiB batch size.
/// - **Several protocols:** each callback commits separately with its remaining owners
///   and progress. Valid responses do not have to fit together in one transaction. A
///   shared deny barrier stays until every callback completes; an interrupted gap is
///   told to all protocols again from one fresh list answer.
pub const MAX_STEP_LOCAL_BYTES: usize = 4 * 1024 * 1024;

/// The most bytes a [`Protocol::record_seen`] mark takes: 64 KiB, 85.6 KiB as stored in
/// base64 with its key. The commits that keep marks stay within the 32 MiB batch size: a
/// feed item or a listed record caches at most one record write with its mark (1.2 MiB
/// and 85.6 KiB, within a read's 12 MiB room for one item); an applied effect's outcome at
/// most 7, with its 4 MiB of local writes and what its entry writes (256 KiB): 4 MiB + 7 x
/// (1.2 MiB + 85.6 KiB) + 256 KiB = 13.2 MiB; and a batch's answer at most 8, with what the
/// batch kept (under 12 MiB) and 1 MiB more: 12 MiB + 8 x (1.2 MiB + 85.6 KiB) + 1 MiB =
/// 23.3 MiB. The `const` assertions of `feed.rs`, `records.rs` and `batch.rs` check each.
pub const MAX_SEEN_MARK_BYTES: usize = 64 * 1024;

/// The most bytes a [`Protocol::record_regression`] rule takes: 256. A longer one is cut
/// there.
pub const MAX_REGRESSION_REASON_BYTES: usize = 256;

/// The most counterparties a [`LossActions::conversations`](super::LossActions) list takes:
/// 100,000, the `max_conversations` a service keeps at its default limits (Switch wire
/// 9.2). The app adds back the first this many, in key order, and no more.
pub const MAX_LOSS_CONVERSATIONS: usize = 100_000;

/// What each write counts against [`MAX_STEP_LOCAL_BYTES`] beside its key and value: the
/// room its stored and kept forms take around them.
pub const LOCAL_WRITE_OVERHEAD_BYTES: usize = 72;

/// The bytes `writes` count against [`MAX_STEP_LOCAL_BYTES`]: for each write, the raw
/// length of its key (a prefix for [`LocalWrite::DeletePrefix`]) and of its value, plus
/// [`LOCAL_WRITE_OVERHEAD_BYTES`].
pub fn local_writes_bytes(writes: &[LocalWrite]) -> usize {
    writes.iter().fold(0usize, |total, write| {
        let bytes = match write {
            LocalWrite::Put { key, value } => key.len().saturating_add(value.len()),
            LocalWrite::Delete { key } => key.len(),
            LocalWrite::DeletePrefix { prefix } => prefix.len(),
        };
        total.saturating_add(bytes.saturating_add(LOCAL_WRITE_OVERHEAD_BYTES))
    })
}

/// A write of the protocol's own local state, under keys the app prefixes so they never
/// meet its own (`STATE.md`).
#[derive(Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum LocalWrite {
    /// Set `key` to `value`.
    Put {
        /// The key, in the protocol's key space.
        key: Vec<u8>,
        /// The value.
        value: Vec<u8>,
    },
    /// Remove `key`.
    Delete {
        /// The key, in the protocol's key space.
        key: Vec<u8>,
    },
    /// Remove every key starting with `prefix`.
    DeletePrefix {
        /// The prefix, in the protocol's key space.
        prefix: Vec<u8>,
    },
}

impl std::fmt::Debug for LocalWrite {
    // Values may hold message content: only sizes are shown.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LocalWrite::Put { key, value } => {
                write!(
                    f,
                    "Put({} key bytes, {} value bytes)",
                    key.len(),
                    value.len()
                )
            }
            LocalWrite::Delete { key } => write!(f, "Delete({} key bytes)", key.len()),
            LocalWrite::DeletePrefix { prefix } => {
                write!(f, "DeletePrefix({} prefix bytes)", prefix.len())
            }
        }
    }
}

/// A protocol's layer of an app backup (Switch spec 12.4): its own local state, such as
/// its journal, in a form it chooses ([`Protocol::backup_layer`]), carried in the
/// [`super::AppBackup`] ([`super::App::backup_layered`]), one layer per protocol, and
/// installed by [`super::App::restore`] in the same commit as the app's own state
/// ([`Protocol::restore_layer`]). Opaque to the app.
/// Sensitive: its `Debug` shows only the protocol's name and the data's size.
#[derive(Clone, PartialEq, Eq)]
pub struct ProtocolLayer {
    /// The protocol that made it, as its [`Protocol::name`] gives it: a restore hands the
    /// layer only to the protocol registered under that name.
    pub protocol: String,
    /// The protocol's data.
    pub data: Vec<u8>,
}

impl std::fmt::Debug for ProtocolLayer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "ProtocolLayer({}, {} bytes)",
            self.protocol,
            self.data.len()
        )
    }
}

/// A protocol's local state as the default [`Protocol::backup_layer`] writes it: each key
/// and value length-prefixed, in order.
pub fn encode_local_state(state: &[KeyValue]) -> Vec<u8> {
    let parts: Vec<&[u8]> = state
        .iter()
        .flat_map(|(key, value)| [key.as_slice(), value.as_slice()])
        .collect();
    pubky_switch_core::enc::lp(&parts)
}

/// The local state [`encode_local_state`] wrote, or `None` for bytes it didn't write.
pub fn decode_local_state(bytes: &[u8]) -> Option<Vec<KeyValue>> {
    let parts = pubky_switch_core::enc::split_lp(bytes)?;
    if parts.len() % 2 != 0 {
        return None;
    }
    let mut parts = parts.into_iter();
    let mut state = Vec::new();
    while let (Some(key), Some(value)) = (parts.next(), parts.next()) {
        state.push((key, value));
    }
    Some(state)
}

/// What a received message does: the operations committed in one batch with the cursor
/// move, and the protocol's local writes committed with the outcome. The writes added
/// through the [`ReceiveContext`] come first, then these.
#[derive(Clone, Debug, Default)]
pub struct Effect {
    /// Signed by the app and sent in one batch with the cursor move, after the context's:
    /// at most 7 in all, the cursor taking the eighth entry (Switch wire 6.4). Empty, with
    /// nothing added through the context, when the message has no lasting effect, or another
    /// own app applied it already: only the cursor moves.
    pub ops: Vec<(Vec<Condition>, OpKind)>,
    /// The protocol's local writes, committed once the batch is answered, with the
    /// processed pair and the cursor.
    pub local: Vec<LocalWrite>,
}

/// The most claims the app reads from the switch for one entry's receive step
/// ([`Outcome::Need`]), over all its calls: a step that asks for more is stored locally and
/// passed ([`super::ParkReason::TooManyReads`]).
pub const MAX_CLAIM_READS: usize = 4;

/// What a receive step needs read from the switch before it can build its effect
/// ([`Outcome::Need`]).
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Need {
    /// The claim of this key, as `GET /claims/{claim_key}` gives it (Switch wire 7.4.8),
    /// checked as [`super::App::read_claim`] checks it. Its view is kept, so the context's
    /// [`ReceiveContext::claim_view`] and [`ReceiveContext::claim_condition`] show it, and
    /// the answer itself is in [`ReceiveContext::switch_claim`].
    Claim([u8; 32]),
}

/// The reads of the feed in a row, each ending in [`Outcome::Retry`] at one held entry,
/// after which the app raises [`super::AppEvent::StoreFailing`] for it, on that read and
/// every later one until the entry is processed or stored locally.
pub const RETRY_EVENT_READS: u32 = 3;

/// The most entries stored locally that one read tries again: the next read goes on after
/// the last one tried, in `seq` order and round again, so each is reached in turn.
pub const PARKED_RETRIES_PER_READ: usize = 16;

/// A failure of the store or the host that kept a receive step from finishing
/// ([`Outcome::Retry`]). It is built only from a [`StoreError`]: what the host's
/// [`crate::store::StateStore`] answers, through the [`ReceiveContext`]'s or a
/// [`LocalView`]'s reads or a store handle of the protocol's own, or what a binding maps
/// its own host's storage failure to. A protocol never builds one for a message it can't
/// handle: that is an [`Outcome::Drop`].
///
/// It is of one of two kinds, which decide how long the entry waits:
///
/// - **The store is unavailable for now** ([`StoreFailure::unavailable`]): the entry is
///   held, up to the bounded wait an entry whose sender can't be checked gets
///   ([`super::AppConfig::park_after_ms`]), then stored locally and passed
///   ([`super::ParkReason::StoreUnavailable`]).
/// - **The store fails for this entry** ([`StoreFailure::of_entry`]), whatever the time,
///   such as a corrupt value it holds or a write it refuses: retrying on the feed can't
///   help, so the entry is stored locally and passed at once
///   ([`super::ParkReason::StoreRejected`]).
///
/// Either way the entry is never dropped: an entry stored locally is tried again at every
/// read, and processed once the store works.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoreFailure {
    error: StoreError,
    of_entry: bool,
}

impl StoreFailure {
    /// The store, or the host, is unavailable for now, and may work at a later read.
    pub fn unavailable(error: StoreError) -> Self {
        Self {
            error,
            of_entry: false,
        }
    }

    /// The store fails for this entry every time, such as a corrupt value it holds or a
    /// write of the entry's state it refuses.
    pub fn of_entry(error: StoreError) -> Self {
        Self {
            error,
            of_entry: true,
        }
    }

    /// The store's error.
    pub fn error(&self) -> &StoreError {
        &self.error
    }

    /// Whether the store fails for this entry every time ([`StoreFailure::of_entry`]),
    /// rather than for now.
    pub fn is_of_entry(&self) -> bool {
        self.of_entry
    }
}

impl From<StoreError> for StoreFailure {
    /// [`StoreError::Corrupt`] and [`StoreError::TooLarge`] fail for the entry
    /// ([`StoreFailure::of_entry`]), the same every time; every other error is the store
    /// unavailable for now ([`StoreFailure::unavailable`]), bounded by the wait.
    fn from(error: StoreError) -> Self {
        match error {
            StoreError::Corrupt | StoreError::TooLarge { .. } => Self::of_entry(error),
            error => Self::unavailable(error),
        }
    }
}

impl TryFrom<AppError> for StoreFailure {
    /// Any other error, given back: it isn't a failure of the store.
    type Error = AppError;

    /// The failure of an [`AppError::Store`], such as a [`ReceiveContext::local_get`] whose
    /// store failed, of the kind [`StoreFailure::from`] gives it; any other error is given
    /// back.
    fn try_from(error: AppError) -> Result<Self, AppError> {
        match error {
            AppError::Store(error) => Ok(error.into()),
            other => Err(other),
        }
    }
}

impl std::fmt::Display for StoreFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.error.fmt(f)
    }
}

/// Local writes that must commit even while ordinary admission of the input waits
/// (Switch spec 8.2). On each retry the protocol returns only writes still owed.
/// It must be safe to apply them again after another input changed its state.
///
/// ```
/// use pubky_switch_client::app::{AdmissionCustody, LocalWrite, Outcome, Refusal};
///
/// fn wait_with_evidence(key: Vec<u8>, evidence: Vec<u8>) -> Result<Outcome, Refusal> {
///     let mut custody = AdmissionCustody::default();
///     custody.try_push(LocalWrite::Put { key, value: evidence })?;
///     Ok(Outcome::AwaitAdmissionWithCustody(custody))
/// }
/// ```
#[derive(Clone, Debug, Default)]
pub struct AdmissionCustody {
    writes: Vec<LocalWrite>,
    bytes: usize,
}

impl AdmissionCustody {
    /// Add an exact-key put or deletion to commit with the waiting input or its drop notice.
    /// Add mandatory writes before optional cleanup.
    ///
    /// # Errors
    ///
    /// [`Refusal::Usage`] for a prefix deletion or a write that would exceed
    /// [`MAX_STEP_LOCAL_BYTES`]. On refusal, all previously added writes remain.
    pub fn try_push(&mut self, write: LocalWrite) -> Result<(), Refusal> {
        if matches!(write, LocalWrite::DeletePrefix { .. }) {
            return Err(Refusal::Usage(
                "admission custody requires an exact key".into(),
            ));
        }
        let bytes = self
            .bytes
            .saturating_add(local_writes_bytes(std::slice::from_ref(&write)));
        if bytes > MAX_STEP_LOCAL_BYTES {
            return Err(Refusal::Usage(format!(
                "admission custody writes at most {MAX_STEP_LOCAL_BYTES} bytes of local state"
            )));
        }
        self.writes.push(write);
        self.bytes = bytes;
        Ok(())
    }

    pub(super) fn into_writes(self) -> Vec<LocalWrite> {
        self.writes
    }
}

/// When an unprocessed input waiting for protocol data goes into retriable local storage.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeferCustody {
    /// Hold it on the feed until the configured bounded wait expires.
    AfterBoundedWait,
    /// Save it locally before passing its feed position on this read.
    Immediate,
}

/// The protocol's answer for a received message. Later versions may add answers: a host
/// that matches on it keeps a catch-all arm.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub enum Outcome {
    /// Apply the effect.
    Apply(Effect),
    /// A rule the protocol states for the kind fails (Switch wire 5.1 check 10), one that
    /// [`Protocol::check_body`] couldn't judge: the entry is dropped, kept as processed, and
    /// the cursor moves past it.
    Drop {
        /// The rule, without content.
        reason: String,
    },
    /// The step needs these read from the switch first, such as the claim a message gives
    /// evidence for when the app keeps no view of it (Switch spec 10.2). What the context
    /// added is discarded; the app reads them, then calls [`Protocol::receive`] again
    /// with them in the context. Reads are bounded: every call for one entry together reads
    /// at most [`MAX_CLAIM_READS`] claims, and a `Need` that names nothing new or goes past
    /// the bound stores the entry locally and passes it
    /// ([`super::ParkReason::TooManyReads`]). A read that fails for now (the network, `429`,
    /// `503`) leaves the entry waiting for the next read of the feed.
    Need(Vec<Need>),
    /// The step couldn't finish because the protocol's store or the host failed, such as a
    /// read of its own state: never for a message the protocol can't handle, which is an
    /// [`Outcome::Drop`]. A valid message is never consumed by a store failure (Switch spec
    /// 8.2): the app keeps no processed pair for the entry and commits nothing the step
    /// built (what the context added is discarded). What happens to the entry depends on
    /// the [`StoreFailure`]'s kind:
    ///
    /// - **Unavailable for now:** the entry is held, as an entry whose sender can't be
    ///   checked yet is. The cursor stays before it; the read goes on with later items, which
    ///   are processed past it and remembered; the entry comes again at the next read of the
    ///   feed, never twice in one read, and the step runs again from the start. The app
    ///   counts the reads in a row that end so, in its own store; from the
    ///   [`RETRY_EVENT_READS`]th on it raises [`super::AppEvent::StoreFailing`] on each, so
    ///   the host learns its store is failing. Once the entry has waited the bounded wait
    ///   ([`super::AppConfig::park_after_ms`]) since its first retry, it is stored locally
    ///   and the cursor passes it ([`super::ParkReason::StoreUnavailable`]), so a store
    ///   that stays down never pins the cursor.
    /// - **Of the entry:** retrying on the feed can't help, so the entry is stored locally
    ///   and the cursor passes it at once ([`super::ParkReason::StoreRejected`]).
    ///
    /// An entry stored locally is tried again at every read, and processed once its step
    /// finishes. A retry of an entry stored locally before ([`ReceivedMessage::parked`])
    /// leaves it stored, for the next read, and counts on: the count of reads in a row is
    /// kept from the feed into local storage until the entry is processed, so a store that
    /// stays down raises [`super::AppEvent::StoreFailing`] whichever way the entry waits. Claims read for the step ([`Outcome::Need`])
    /// stay kept, in their own commits. A push extension's peek runs no receive step, so a
    /// retry doesn't change what it shows.
    Retry(StoreFailure),
    /// Required protocol data is unavailable (Switch spec 8.2). Discard all staged work
    /// and keep this delivery unprocessed. Other eligible protocols may continue. The
    /// host sees the reason on each deferral in [`super::AppEvent::ProtocolDeferred`].
    /// A saved input retains its acceptance time and is tried on the stored-input schedule.
    Defer {
        /// A protocol-defined label for the missing prerequisite, without message content.
        reason: &'static str,
        /// When the input should leave the feed for durable local storage.
        custody: DeferCustody,
    },
    /// Passed, not processed: the protocol can't take the message now, such as a reply its
    /// own store bounds out, and wants a later re-send of it delivered again. The cursor
    /// moves past the entry as past a processed one, but no processed pair is kept (Switch
    /// spec 11), so a re-send of the same `msg_id` comes to the protocol as a new entry, not
    /// as a duplicate. What the context added is discarded; nothing is stored locally and no
    /// duty event is kept. Once the service's cursor passes the entry it is gone: only a
    /// re-send brings the message back.
    ///
    /// Only an entry read from the feed is passed so. For an entry stored locally
    /// ([`ReceivedMessage::parked`], a released one included) a `Pass` changes nothing: it
    /// stays stored, with what it counts, and is tried again at a later read; a protocol done
    /// with it returns [`Outcome::Drop`] or [`Outcome::Consume`]. No entry whose effect the
    /// app must keep is asked about: one whose effect was applied is a duplicate before its receive step (check
    /// 9), and a kept effect goes again before the feed is read; after `409 conflict` on the
    /// effect's batch ([`ReceivedMessage::conflict`]) nothing of it was applied, so a `Pass`
    /// then passes the entry.
    Pass,
    /// Consume this input and commit only the context's local writes and eligible forgets
    /// of earlier processed pairs, atomically (Switch spec 11). No processed pair is added
    /// for this message: a re-sent copy is delivered again. A feed entry is passed; a
    /// stored input, including an eligible released input, is removed with its retry state.
    /// Duties already owed remain owed. An unanswered or uncertain effect is never offered
    /// to the receive step for this decision.
    ///
    /// No remote operation is part of this outcome. Operations added to the context are
    /// discarded; only its local writes and forgets are used. They share the same
    /// [`MAX_STEP_LOCAL_BYTES`] bound as an [`Outcome::Apply`], and an over-bound step is
    /// stored and passed as too large without committing any of its local changes.
    Consume,
    /// The protocol cannot admit this input within its retained-state bound without
    /// discarding protected state (Switch spec 8.2). All operations, local
    /// writes and processed-pair forgets staged by this callback are discarded. No pair
    /// is added. Before its cursor passes, the input or its payload-free drop notice is
    /// kept in the same transaction as the shared waiting-pool selection.
    ///
    /// Only this input enters custody; already admitted protocol payloads and protected
    /// effects remain unchanged. A later scheduled retry runs the decision again against
    /// current state, retaining the input's original receipt and storage order. This is
    /// neither a storage failure nor an immediate request to repeat the read.
    AwaitAdmission,
    /// Wait as for [`Outcome::AwaitAdmission`], committing the designated protocol-local
    /// writes together with the waiting input or its drop notice. All work staged through
    /// [`ReceiveContext`] is discarded. The input stays unprocessed (Switch spec 8.2).
    AwaitAdmissionWithCustody(AdmissionCustody),
    /// The step needs a scope key of `data_epoch` that the app doesn't hold yet (Switch
    /// spec 3.5, 8.2), such as to read a record held sealed at that epoch
    /// ([`super::Unopened::KeyNotHeld`]) or to write while the app lacks the current data
    /// epoch's key ([`ReceiveContext::holds_scope_key`], [`ReceiveContext::data_epoch`]).
    /// What the context added is discarded. When a key the app's certificate is given is
    /// missing at an epoch up to the current one, and no full bundle is asked for yet, the
    /// app fetches its key bundle once, asking for a full bundle if a key is still missing,
    /// and runs the step again if the epoch's keys came; otherwise the entry is stored
    /// locally and the cursor passes it at once ([`super::ParkReason::AwaitingKey`]), with
    /// no bounded wait and no [`super::AppEvent::StoreFailing`]. It is tried again once the
    /// app holds every key of `data_epoch` its certificate is given and a key came since
    /// the step last ran, so a key the certificate is never given runs it again only when
    /// another key comes; in the read whose
    /// fetch brought them, after the listing a read owes first, or at a later read; it is
    /// bounded with the entries whose sender couldn't be checked and dropped past the
    /// bounds ([`super::AppEvent::StoredEntryDropped`]). Each read's report names the
    /// epochs waited for ([`super::AppEvent::AwaitingKeys`]). An effect applied with a
    /// write the context refused for want of the key ([`ReceiveContext::put_record`]) ends
    /// the same way, waiting for the current data epoch.
    AwaitKey {
        /// The data epoch whose key the step waits for.
        data_epoch: u64,
    },
}

/// Entries the app can't read and whose senders it asks to send again (Switch spec 8.2):
/// the acceptance times to ask for. The app never asks for a time before its cursor's, less
/// the clock tolerance.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResendNeeded {
    /// The sender to ask.
    pub sender: [u8; 32],
    /// The first acceptance time to ask for, service time in Unix milliseconds.
    pub accepted_from_ms: u64,
    /// The last acceptance time to ask for.
    pub accepted_until_ms: u64,
    /// Why: an entry wrapped to a key the app doesn't hold, or one a departed own app left
    /// unread.
    pub reason: ResendReason,
}

/// Why the app asks for a re-send.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ResendReason {
    /// The entry is wrapped to a key the app doesn't hold (after a restore).
    Unopenable,
    /// A departed own app left the entry unread.
    Unreadable,
}

/// Entries the service deleted while the app was lagging (Switch spec 8.2): the protocol
/// asks the counterparties of its unfinished activity to re-send what their inboxes
/// accepted from `accepted_from_ms`, through `accepted_until_ms` if it bounds its
/// re-sends, and lists its collections again.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct MissedEntries {
    /// The authenticated service time of the feed page that first incurred this call.
    /// A retry or restore keeps that page's time, including Unix epoch zero.
    pub read_at_ms: u64,
    /// The item's `seq`, in the sequence of the generation the app read it at: a call made
    /// again after a provider change keeps it, as information only.
    pub seq: u64,
    /// How many entries were missed.
    pub entries: u64,
    /// The time to ask from: the later of the item's first acceptance time and the cursor's
    /// time, less the clock tolerance.
    pub accepted_from_ms: u64,
    /// The item's last acceptance time, `accepted_until` (Switch wire 7.5), raised to
    /// `accepted_from_ms` when it is earlier. The service writes it, and the app can't
    /// check it. For a gap the service's cursor shows ahead of the app's position
    /// (Switch spec 8.3), no end is known: it is `u64::MAX`.
    pub accepted_until_ms: u64,
}

/// A change to the identity's deny list, as the feed shows it to an app holding `lists.read`
/// (Switch spec 8.3): a `deny.put` or a `deny.delete` whose signature the app verified, made
/// by an app of the identity whose certificate holds `lists.manage`, this one included. One
/// the app can't verify so, such as one whose writer's certificate it can't find, is neither
/// handed nor applied to the app's copy of the lists, and names nobody. The protocol gets each in feed order ([`Protocol::deny_list_changed`]),
/// so one restored from a backup rebuilds who was denied since the backup's cursor; where
/// that history has a gap, it is told so instead ([`Protocol::deny_list_gap`]).
///
/// A genuine change the service shows again reads as a new one (Switch spec 13.5): a
/// protocol takes a change as setting a state, `pubky` denied or not, rather than as a
/// count.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct DenyListChange {
    /// The generation of the feed item.
    pub generation: u64,
    /// The item's `seq` in that generation.
    pub seq: u64,
    /// The pubky the change is about.
    pub pubky: [u8; 32],
    /// `true` when the pubky was added to the deny list, `false` when it was removed.
    pub added: bool,
    /// The item's service time, in Unix milliseconds.
    pub at_ms: u64,
}

/// A gap in the deny list's history (Switch spec 8.3, 12.4, 12.6): changes after
/// `generation` and `seq` may never reach the protocol, as after a restore from a backup
/// older than the retained history, or after a provider loss. `denied` is the deny list as
/// the service holds it now, read with `GET /allow` (Switch wire 7.4.11), so the protocol
/// can start again from it, or hold what the gap covers ([`Protocol::deny_list_gap`]).
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct DenyListGap {
    /// The generation of the last position the history is known complete through.
    pub generation: u64,
    /// That position's `seq`.
    pub seq: u64,
    /// The deny list now, empty when `list_read` is false.
    pub denied: Vec<[u8; 32]>,
    /// Whether the lists were read for the gap. `false` when the service's answer couldn't
    /// be read: the protocol then knows only that the history has a gap, and fails closed
    /// for it.
    pub list_read: bool,
}

/// A protocol on the Switch, as the app layer uses it. Object-safe; the app holds each
/// protocol it runs as an `Arc<dyn Protocol>` in its [`super::ProtocolSet`].
///
/// # Several protocols on one app
///
/// One app may run several protocols, each registered under its [`Protocol::name`]
/// (Switch spec 3.2, wire 3.1 "Several protocols"); the app routes each callback to one of
/// them, or hands it to each ([`super::ProtocolSet`]). A protocol keeps to these rules, so
/// that no protocol's answer reaches another's messages, keys or state:
///
/// - **Kinds** are prefixed by the protocol's name, or by one of its roots (Switch wire
///   3.1 "Scope roots", 5.1): the app routes a message by its kind's prefix, and drops a
///   kind no registered protocol owns at check 8.
/// - **[`Protocol::accepts`] and [`Protocol::check_scopes`]** cover only the protocol's own
///   kinds: the app leaves out of its record a kind another protocol owns, and never asks
///   one protocol about another's kinds.
/// - **An [`OpaqueRule`] for every kind** (`kind: None`) covers every kind of this
///   protocol, and no other's.
/// - **[`Protocol::has_keys`]** is asked only about the protocol's own roots.
/// - **Collection names** are unique across the protocols of one app: the set refuses two
///   protocols giving one name, and routes marks, regressions and sent records by it.
/// - **Inputs to `blind`** are domain-separated, such as by a label naming the protocol,
///   so two protocols never derive the same record or claim key from their own inputs.
/// - **Local state**: each protocol reads and writes only its own key space, which the app
///   keeps under `p/<name>/`; a `DeletePrefix` of the empty prefix clears that protocol's
///   state alone.
/// - **What carries no kind**, such as [`Protocol::resend_needed`], [`Protocol::missed`],
///   the deny list calls and [`Protocol::provider_lost`], is handed to every protocol, and
///   each protocol's failure is kept for it alone. A protocol is told things in feed order,
///   each once: until it takes a re-send or missed call kept for it, it is told nothing
///   later, while the read goes on for the others. Its entries and its records' writes
///   wait, its later calls are kept for it, the listing a later item owes is made for it
///   once it has taken what comes before, and its records an upload marked wait unread; a
///   deny list change or gap waits for every protocol; with no protocol left in step the
///   read stops, as with one protocol.
/// - **Records**: a protocol's receive step, and a batch of its own, write only that
///   protocol's records: a target in a collection another registered protocol gives, or
///   under a scope whose root another owns, is refused ([`super::Refusal::Usage`]). So no
///   protocol's step changes what another is told.
/// - **Duty events** name the protocols they are for ([`super::App::ack_events_for`]): the
///   protocol of the kind, collection, stored entry or kept batch they name, every protocol
///   otherwise.
///
/// # Callbacks and the store
///
/// Every callback is synchronous and runs on the app's task, in the middle of one of its
/// calls. A callback may read the host's store synchronously: the receive step through its
/// [`ReceiveContext`], [`Protocol::sends_to`] and [`Protocol::provider_lost`]
/// through a [`LocalView`], any callback through a handle of its own on the host's store.
/// No callback writes the store: the app commits the protocol's local state only as the
/// [`LocalWrite`]s a callback returns, or a batch or [`super::App::protocol_commit`]
/// carries, each at the commit point its crash rules give it (`STATE.md`). A write made
/// beside them could land without the outcome it belongs to, or after a crash that
/// discards it.
///
/// # Limits a receive step plans for
///
/// - **Operations:** at most 7 beside the cursor move (Switch wire 6.4).
/// - **Local writes:** at most [`MAX_STEP_LOCAL_BYTES`], 4 MiB, counted as
///   [`local_writes_bytes`] counts them, for each set of local writes handed over at once.
///   The bound keeps every set within what the app's store keeps and commits, whatever
///   else the read holds; a protocol keeps larger state in its own store. Over it:
///   - **a receive step**, its [`ReceiveContext::local`] writes and its [`Effect`]'s
///     together: a write that would take [`ReceiveContext::local`] past it is refused
///     there, and an effect over it is stored and passed as
///     [`super::ParkReason::EffectTooLarge`], with [`super::AppEvent::EffectRefused`],
///     never applied (Switch spec 8.2);
///   - **[`Protocol::resend_needed`], [`Protocol::missed`] and
///     [`Protocol::deny_list_changed`]**, made at once or again
///     later: the writes aren't committed and the call isn't made again, since the same
///     answer would come; the item is passed, and the protocol told with
///     [`super::AppEvent::LocalWritesRefused`], a duty event;
///   - **an [`super::OpBatch`]'s local writes**: [`super::App::submit_batch`] refuses the
///     batch before it signs or keeps it ([`super::Refusal::Usage`]).
///
/// # Duty events
///
/// What the app must tell its protocol outside a callback comes as a duty event
/// ([`super::AppEvent::is_duty`]), which the host relays. Delivery is at least once: a
/// duty event comes again after any load until the host acknowledges it
/// ([`super::App::ack_events`]), so a protocol tolerates seeing one twice, and acts on it
/// by its [`super::EventId`] or by the state it names.
pub trait Protocol: Send + Sync {
    /// The protocol's name (Switch wire 3.1 "Scope roots"): 1 to 32 characters of `a-z`
    /// and `0-9`, starting with a letter, the prefix of its kinds and the root of its
    /// scopes. The app keeps the protocol's local state under it (`p/<name>/`), names the
    /// protocol's backup layer by it ([`ProtocolLayer::protocol`]), and keeps the names
    /// it was set up with, so a later [`super::App::load`] takes only a set that registers
    /// each of them. It never changes for a protocol.
    fn name(&self) -> String;

    /// Whether the app's own certificate is one the protocol runs with, beyond the
    /// Switch's checks, such as scopes or permissions it requires: checked by
    /// [`super::App::join`] and [`super::App::restore`] before they write anything, and by
    /// [`super::App::load`]. Every certificate by default.
    ///
    /// # Errors
    ///
    /// The rule the certificate breaks, without content: the call is refused
    /// ([`super::Refusal::Certificate`]) and nothing is written.
    fn check_own_certificate(&self, cert: &AppCert) -> Result<(), String> {
        let _ = cert;
        Ok(())
    }

    /// Whether a message of the protocol's that the outbox holds goes out now: asked before
    /// every try of its delivery, a first one or a re-send, whichever call makes it
    /// ([`super::App::send`], [`super::App::flush_message`], [`super::App::resend`],
    /// [`super::App::flush_outbox`]). `Ok(false)` keeps it queued, with its `msg_id` and bytes,
    /// for a later try, as a hold of its counterparty does ([`super::App::hold_queued`]):
    /// its conversation entry waits with it, its replay deadline still runs, and the
    /// messages of the app's other protocols go on. Asked only about the protocol's own
    /// messages; every message by default.
    /// The view supplies its original signed plaintext, current origin and only this
    /// protocol's committed local state, with the app's certificate and naming-key
    /// blinding to check their binding. It also reads a known batch's current app-wide
    /// status and the app's current host clock. Its hash and origin are the same facts exposed
    /// by [`super::QueuedMessage`], independent of acceptance and re-send status.
    /// The decision is read again after internal settlement and before each append or
    /// retry; work already completed stays durable when a later decision holds delivery.
    /// [`super::App::queued_messages`] asks this same decision without sending anything,
    /// including for retained intents not yet materialized in the outbox.
    ///
    /// # Errors
    ///
    /// A failure to read required local evidence also holds the delivery for a later try.
    /// Ordinary policy refusal is `Ok(false)`, not a fabricated store failure.
    fn may_send(&self, delivery: &super::DeliveryView<'_>) -> Result<bool, StoreFailure> {
        let _ = delivery;
        Ok(true)
    }

    /// The owning protocol's records to read in order before one transport attempt for
    /// this authenticated message (Switch spec 8.2, 11). Each target must select a fixed
    /// policy registered by this owner and readable by the current certificate. At most
    /// [`super::MAX_APPEND_RECORDS`] distinct targets are read. Empty by default.
    ///
    /// Queued-message enumeration does not call this hook. A retry asks again.
    ///
    /// # Errors
    ///
    /// A local read failure holds the message for another try.
    fn append_records(
        &self,
        delivery: &super::DeliveryView<'_>,
    ) -> Result<Vec<super::RecordTarget>, StoreFailure> {
        let _ = delivery;
        Ok(Vec::new())
    }

    /// Decide one append using the exact targets requested by [`Self::append_records`] and
    /// their checked read outcomes, in order (Switch spec 8.2, 11). Called once the reads
    /// have finished. The decision expires with this transport attempt. A protocol that
    /// asks for records holds its message until it explicitly permits or withdraws it.
    ///
    /// # Errors
    ///
    /// A local read failure holds the delivery and leaves the signed message queued.
    fn judge_append(
        &self,
        delivery: &super::DeliveryView<'_>,
        records: &[(super::RecordTarget, super::RecordRead)],
    ) -> Result<super::AppendDecision, StoreFailure> {
        let _ = (delivery, records);
        Ok(super::AppendDecision::Hold)
    }

    /// The opaque members of the protocol's message bodies (Switch wire 1.1). None by
    /// default.
    fn opaque_members(&self) -> Vec<OpaqueRule> {
        Vec::new()
    }

    /// Whether `scope`, a scope of a certificate (a name, or a name and a sub-scope), has
    /// Shared Data Keys (Switch spec 3.5). A sub-scope's keys are its sub-scope keys.
    fn has_keys(&self, scope: &str) -> bool;

    /// Whether the protocol sends `kind` between apps of one identity (Switch wire 5.1
    /// check 6).
    fn sent_between_own_apps(&self, kind: &str) -> bool;

    /// Check 8 (Switch wire 5.1): the sender's certificate holds a scope that sends the
    /// kind, and the own certificate one that receives it, with the protocol's narrower
    /// rules.
    ///
    /// # Errors
    ///
    /// The rule the message breaks, without content: the entry is dropped.
    fn check_scopes(
        &self,
        message: &Message,
        sender: &AppCert,
        own: &AppCert,
    ) -> Result<(), String>;

    /// The kinds the app's record lists in `accepts` for a certificate: never wider than
    /// what its scopes receive (Switch spec 3.4).
    fn accepts(&self, cert: &AppCert) -> Vec<String>;

    /// The protocol's member of the app's record, and its expiry ask, under `cert`, a
    /// renewal the app takes, from `member` and `ask`, the ones it has now (Switch spec 3.2
    /// step 3, 4.2). The app builds the record carrying `cert` from these answers alone and
    /// signs it once, in the commit that takes `cert`: a member whose content `cert` no
    /// longer covers, such as one naming a scope it dropped, is changed or removed here, and
    /// the earlier member is never signed under `cert`. `None` removes the member and its
    /// ask. A member that breaks the JSON rules (Switch wire 1.1), or an ask that can't be
    /// signed, removes the member and its ask ([`super::AppEvent::MemberDropped`]). A member
    /// of a protocol not registered here stays while `cert` holds every scope and
    /// permission of the one before, and is removed otherwise, for its protocol to write
    /// again where it runs. Keeps both by default, so a protocol whose member depends on
    /// the certificate's scopes overrides this. Pure and synchronous: it reads no store,
    /// writes nothing, and must not panic, which would unwind through the read.
    fn member_for(
        &self,
        member: Option<&Map<String, Value>>,
        ask: RecordExpiry,
        cert: &AppCert,
    ) -> (Option<Map<String, Value>>, RecordExpiry) {
        let _ = cert;
        (member.cloned(), ask)
    }

    /// Check 10 (Switch wire 5.1) of a message that passed checks 1 to 9, with no effect:
    /// the body parses as its kind's body, the members read have their types, and the
    /// protocol's rules for the kind hold. The app runs it before [`Protocol::receive`],
    /// and a push extension's peek runs it alone (Switch spec 9 step 5), so it must refuse
    /// every body that the receive step would drop for its shape, and change nothing.
    ///
    /// # Errors
    ///
    /// The rule the body breaks, without content: the entry is dropped, and a peek shows a
    /// generic notification for it.
    fn check_body(&self, message: &ReceivedMessage) -> Result<(), String>;

    /// The effect of a message whose body passed [`Protocol::check_body`], with the app's
    /// state at hand (Switch spec 8.2): `cx` derives record keys and blinded inputs, reads
    /// the writes the app holds and the claims it keeps, and adds record writes and claim
    /// entries to the effect's batch, which carries the cursor move. A protocol that needs
    /// nothing of the app's state ignores `cx`. What `cx` added goes with
    /// [`Outcome::Apply`], or its local writes and forgets alone with [`Outcome::Consume`];
    /// an [`Outcome::Drop`], an [`Outcome::Need`], an [`Outcome::Retry`], an [`Outcome::Pass`]
    /// or an [`Outcome::AwaitKey`] discards it. After an
    /// [`Outcome::Need`] the app reads what it names and calls this again, the answers in
    /// [`ReceiveContext::switch_claim`]. A step that can't finish because the protocol's
    /// store or the host failed returns [`Outcome::Retry`], never [`Outcome::Drop`]: a read
    /// of the context, or of the protocol's own store, that fails with a store error is an
    /// [`Outcome::Retry`] ([`StoreFailure::try_from`]), and the entry is held for a later
    /// read, or stored locally and tried again at a later read. After `409 conflict` on the
    /// batch the app reads the records and claims `cx` wrote again and calls this once more,
    /// with [`ReceivedMessage::conflict`] set. By default it drops every message.
    fn receive(&self, message: &ReceivedMessage, cx: &mut ReceiveContext<'_>) -> Outcome {
        let _ = (message, cx);
        Outcome::Drop {
            reason: "the protocol takes no messages".into(),
        }
    }

    /// Entries the app can't read: the protocol queues its re-send request and returns the
    /// local writes that queue it, committed with the cursor passing the entries.
    ///
    /// # Errors
    ///
    /// A [`StoreFailure`] when the protocol can't build its writes now, such as when its own
    /// state can't be read, of either kind. The cursor still passes the entries, and the app
    /// keeps `needed` in that same commit, owed to this protocol alone, and calls this again
    /// with it at the start of each later read, across loads, before anything else is
    /// handed to this protocol, until it returns writes; while it fails, the read hands
    /// this protocol nothing after it, of any kind, and goes on for the app's other
    /// protocols (Switch spec 8.3) ([`super::App::owed_protocol_calls`]).
    fn resend_needed(&self, needed: &ResendNeeded) -> Result<Vec<LocalWrite>, StoreFailure>;

    /// Entries missed while lagging: as [`Protocol::resend_needed`], failure included.
    ///
    /// # Errors
    ///
    /// As [`Protocol::resend_needed`].
    fn missed(&self, missed: &MissedEntries) -> Result<Vec<LocalWrite>, StoreFailure>;

    /// A change to the deny list the feed shows (Switch spec 8.3): the protocol keeps what
    /// it needs of it and returns the local writes that keep it, committed with the cursor
    /// passing the item. Nothing by default.
    ///
    /// - **Who gets them:** an app holding `lists.read`, its own changes included, which
    ///   come back by its feed. An app without it gets none.
    /// - **Order:** feed order, across everything the app hands over. While a change is
    ///   owed, the read hands nothing after it: no later item, owed call or entry stored
    ///   locally. So an undeny is seen before the message after it. Calls owed from a
    ///   sequence a provider loss ended come before those of the current sequence, and
    ///   among themselves in the order (generation, seq): two of one lost sequence owed at
    ///   different generations, as across a key change in place, may come out of feed
    ///   order. The gap the loss leaves follows them, with the full list
    ///   ([`Protocol::deny_list_gap`]). A change owed that the app's position is already
    ///   past, as after a restore in place from a newer backup, or one of a lost sequence
    ///   once the app reads the next, isn't made: it would come after later changes, so
    ///   the protocol is told a gap at that position instead.
    ///   With several protocols, the change waits until every protocol has taken the
    ///   preceding items. The shared deny copy changes in the commit of the last
    ///   successful callback; no later item is handed to any protocol while one fails.
    /// - **After a restore:** a backup holds the protocol's layer as committed when it was
    ///   taken, and none of the changes or gaps owed then. So every restore tells every
    ///   protocol a gap at the backup's position, with the full list, whatever the backup
    ///   held, after the owed calls the restore carries up to that position; the
    ///   changes after it come as the feed hands them.
    /// - **Again:** a change may come twice, after a crash before its commit and after a
    ///   restore, whose feed hands it again; its writes commit once. A protocol keys what it
    ///   keeps by the change's place, or takes it as setting a state.
    /// - **Before and after:** an entry reached in order but held for its sender, a key
    ///   or a retry, or stored locally, may be tried after a later change and sees the
    ///   current copy then (Switch spec 8.2). The barrier protects an eligible entry
    ///   not yet handed because its protocol is behind.
    ///
    /// # Errors
    ///
    /// As [`Protocol::resend_needed`], but for every protocol: a failed change is owed to
    /// the protocol that failed it, and made again for it alone at the start of each later
    /// read, before anything else is handed; the read stops there for every protocol while
    /// it fails, and after [`RETRY_EVENT_READS`] such reads the app tells the host
    /// ([`super::AppEvent::OwedCallHeld`]). Writes over [`MAX_STEP_LOCAL_BYTES`] aren't
    /// committed and the change isn't made again, with
    /// [`super::AppEvent::LocalWritesRefused`].
    fn deny_list_changed(&self, change: &DenyListChange) -> Result<Vec<LocalWrite>, StoreFailure> {
        let _ = change;
        Ok(Vec::new())
    }

    /// A gap in the deny list's history, with the list as it stands now ([`DenyListGap`]):
    /// the protocol starts again from it, or fails closed for what the gap covers
    /// (Switch spec 8.3). Made by a read, after the owed calls and before any later change
    /// or item is handed, once the app has read the list for the gap (`GET /allow`).
    ///
    /// A gap comes after a restore, a provider loss, a checkpoint past the cursor, a change
    /// whose writer the directory no longer lists, a join, a renewal that adds `lists.read`
    /// and every [`super::App::allow_list`]: whenever the app's copy of
    /// the lists is taken whole from a list read, every protocol is given that list as a
    /// gap. It is told to every protocol in turn, each response in a separate commit.
    /// The gap stays owed to all until one complete pass takes the same answer. The
    /// final callback's commit then deletes the gap and marks the copy of the
    /// lists unknown. The copy is then replaced from the same answer in a commit of its
    /// own, best effort. A failed replacement leaves the copy unknown after reload too;
    /// the next read owes a fresh gap, except while a whole copy that was too large waits
    /// for its retry time ([`super::App::allow_list`]). When one protocol fails,
    /// the writes of those that took it remain committed with the gap still owed to every
    /// protocol, so a later read tells it to each again, with the list the copy is then
    /// taken from, and the read holds meanwhile. A gap waits, and the read holds, while a
    /// call or a listing from at or before it is kept for a protocol.
    /// A failed or uncertain commit interrupts the pass too: after reload every protocol
    /// is told again from the list read for the next pass, including protocols whose
    /// earlier writes committed. No partially completed pass establishes a baseline.
    ///
    /// A gap may be told again at the same position, each time with the full list, which
    /// sets the same state: every gap noted is told to every protocol, one that took an
    /// earlier gap still owed to another included. One told with `list_read` false, the
    /// answer not readable, is owed again at the next read, as long as the answer can't be
    /// read, also while another protocol still owes it. Writes over
    /// [`MAX_STEP_LOCAL_BYTES`] aren't committed: the gap is refused with
    /// [`super::AppEvent::LocalWritesRefused`] and counts as told, and no further gap
    /// follows for it. Nothing by default.
    ///
    /// # Errors
    ///
    /// A [`StoreFailure`]: the copy isn't taken, and the call is made again at the next
    /// read, which hands nothing else meanwhile, as for [`Protocol::deny_list_changed`].
    fn deny_list_gap(&self, gap: &DenyListGap) -> Result<Vec<LocalWrite>, StoreFailure> {
        let _ = gap;
        Ok(Vec::new())
    }

    /// A provider loss the app follows (Switch spec 12.6 steps 2 and 4): the protocol queues
    /// its re-send requests to the counterparties of its unfinished activity, for what their
    /// inboxes accepted from [`ProviderLoss::accepted_from_ms`] on, and names the
    /// counterparties whose conversation entries the app adds back, at most
    /// [`MAX_LOSS_CONVERSATIONS`]: how many past it were left out is kept with the loss
    /// ([`super::RecoveryInfo::conversations_left_out`]). The app commits the local writes
    /// once, with the protocol's name as asked; a crash before that commit calls it again.
    /// Each protocol of the app is asked in registration order, its answer committed on its
    /// own, and the counterparties all of them name are added back together. Writes over
    /// [`MAX_STEP_LOCAL_BYTES`] aren't committed and the loss goes on, with
    /// [`super::AppEvent::LocalWritesRefused`]. `view` reads the protocol's local state,
    /// read-only, such as to find the counterparties of its unfinished activity; a protocol
    /// that needs none of it ignores it. Nothing by default.
    ///
    /// # Errors
    ///
    /// A [`StoreFailure`] when the protocol can't build its actions now, such as when its own
    /// state can't be read. The recovery stays at this step, which its record keeps, and the
    /// app's call fails with [`super::AppError::Protocol`], apart from the app's own store
    /// failing; the next call asks again, the protocols that answered before it not.
    fn provider_lost(
        &self,
        loss: &ProviderLoss,
        view: &LocalView<'_>,
    ) -> Result<LossActions, StoreFailure> {
        let _ = (loss, view);
        Ok(LossActions::default())
    }

    /// Whether a certificate's scopes allow its app to receive `kind`, which a sender checks
    /// before wrapping a message to the app (Switch spec 3.4). By default, whether the kinds
    /// [`Protocol::accepts`] gives for the certificate list it, which are never wider than
    /// what its scopes receive.
    fn receives(&self, kind: &str, cert: &AppCert) -> bool {
        self.accepts(cert).iter().any(|k| k == kind)
    }

    /// The protocol's narrower rule for senders (Switch spec 3.4): whether `message` goes to
    /// the app whose record is `recipient`, beyond its certificate and `accepts`, with the
    /// protocol's local state at hand, read-only (`view`); a protocol that needs none of it
    /// ignores it. Every app by default.
    fn sends_to(&self, message: &Message, recipient: &AppRecord, view: &LocalView<'_>) -> bool {
        let _ = (message, recipient, view);
        true
    }

    /// Whether a first message of `kind` to a counterparty that isn't a contact adds a
    /// conversation entry before it is sent (Switch spec 7): every kind but the protocol's
    /// re-send request, which answers entries the app can't check. Every kind by default.
    fn adds_conversation(&self, kind: &str) -> bool {
        let _ = kind;
        true
    }

    /// Whether the content of this signed first message admits its recipient to the
    /// sender's conversation list (Switch spec 7). Called only for kinds for which
    /// [`Protocol::adds_conversation`] returns true. By default every such message does.
    ///
    /// Decide from the signed content alone: the app uses the same rule when rebuilding
    /// a delivery from its plaintext. `plaintext.json()` holds the exact signed JSON,
    /// including opaque body members. Returning false omits the sender's conversation
    /// entry and leaves the delivery and the recipient's admission checks in place.
    fn message_adds_conversation(&self, _message: &Message, _plaintext: &MessagePlaintext) -> bool {
        true
    }

    /// The protocol's collections, each with its fixed policy (Switch spec 10.3). The app
    /// lists those it may read at join and after a `missed` item, and takes writes to them
    /// from the feed; writes to any other collection are left alone. None by default.
    fn collections(&self) -> Vec<Collection> {
        Vec::new()
    }

    /// What the app has seen of a record, its high water (Switch spec 8.2): the protocol's
    /// mark after `value`, from the mark held (`None` for a write of the app's own, built on
    /// what it trusts), or `None` to keep no mark. None by default. It isn't called for the
    /// app's own delete. The previous mark is kept by default. A collection whose
    /// record lifetime ends at a delete can select [`Self::mark_ends_at_delete`].
    ///
    /// A mark is at most [`MAX_SEEN_MARK_BYTES`], 64 KiB. Past it, nothing is silent:
    ///
    /// - **The app's own write**, built through [`super::App::put_record`],
    ///   [`super::App::record_op`] or [`super::ReceiveContext::put_record`]: the write is
    ///   refused there, before anything is signed ([`super::Refusal::Usage`]), since the
    ///   protocol's own value gives a mark it can't keep.
    /// - **An own write whose mark is over it only once taken**, such as a kept batch
    ///   answered after the protocol's marks grew: the mark held goes, as for `None`, so it
    ///   never stands for the own write, and the protocol is told the record can't be
    ///   checked from that write on ([`super::AppEvent::RecordUncheckable`], a duty event).
    /// - **Another app's write:** the record keeps the mark it held, so what was seen before
    ///   is still checked against later writes, and the protocol is told the same way.
    ///
    /// It is called once more for every own write, when the write is built, to refuse one
    /// whose mark won't fit, and again when the write is taken: it has no side effects, and
    /// gives the same mark for the same arguments.
    fn record_seen(
        &self,
        collection: &str,
        seen: Option<&[u8]>,
        value: Option<&[u8]>,
    ) -> Option<Vec<u8>> {
        let _ = (collection, seen, value);
        None
    }

    /// Qualify a readable value at its actual record key before writing it or
    /// replacing the previously qualified mark (Switch spec 8.2, 10.3).
    /// Return `None` for collections using the ordinary seen and regression rules.
    /// For a participating collection return its new mark, or a content-free
    /// refusal when its signed contents belong elsewhere or drop a known role.
    /// This check is pure and can run again on the same value. It applies to
    /// other installations of this app as well as to other apps.
    fn qualify_record_mark(
        &self,
        input: &RecordMarkContext<'_>,
        seen: Option<&[u8]>,
        value: &[u8],
    ) -> Option<Result<Vec<u8>, String>> {
        let _ = (input, seen, value);
        None
    }

    /// Observe an authenticated, readable write in one of the protocol's collections,
    /// including one made by another installation of this app. An equal read can
    /// confirm a previously uncertain application. The protocol returns idempotent
    /// changes to its own local state, committed with the record and the read's progress.
    /// Earlier local changes in this transaction are visible through `context`.
    /// No changes by default. An absence, delete or unopened value makes no call.
    ///
    /// # Errors
    ///
    /// A [`StoreFailure`] leaves the observation pending. Changes exceeding
    /// [`MAX_STEP_LOCAL_BYTES`] also hold the read before its progress commits.
    fn observe_record(
        &self,
        observation: &RecordObservation<'_>,
        context: &ReceiveContext<'_>,
    ) -> Result<Vec<LocalWrite>, StoreFailure> {
        let _ = (observation, context);
        Ok(Vec::new())
    }

    /// Whether the seen mark of records in this collection lasts until a verified
    /// current deletion (Switch spec 8.2). The client clears it in the same commit
    /// that takes the deletion. A live unreadable value keeps its previous mark.
    fn mark_ends_at_delete(&self, collection: &str) -> bool {
        let _ = collection;
        false
    }

    /// Update this collection owner's local state when a verified current deletion ends
    /// the record's mark lifetime (Switch spec 8.2). The deletion may be this app's own.
    /// A later read may first establish coverage or confirm the same deletion again.
    /// Return idempotent writes bound to this key and deletion version. They commit with
    /// the native mark change, including when the app holds no mark for this key.
    /// A failure or writes exceeding [`MAX_STEP_LOCAL_BYTES`] hold the change for retry.
    fn record_lifetime_ended(
        &self,
        record: &RecordMarkContext<'_>,
        version: RecordVersion,
        context: &ReceiveContext<'_>,
    ) -> Result<Vec<LocalWrite>, StoreFailure> {
        let _ = (record, version, context);
        Ok(Vec::new())
    }

    /// Observe another app's verified deletion of a record in this collection. The
    /// callback follows the regression check and sees the evidence from before the
    /// delete. Its bounded local writes commit under this protocol's namespace.
    /// A store failure leaves the observation owed before later handovers to its owner.
    /// Return [`PutBack::Prepare`] to keep the service cursor before this deletion
    /// while another writer publishes an acceptable record, or return [`PutBack::Write`]
    /// to condition the owner's complete value on this exact deletion.
    fn record_put_back(
        &self,
        deletion: &RecordDeletion<'_>,
        context: &ReceiveContext<'_>,
    ) -> Result<Option<PutBack>, StoreFailure> {
        let _ = (deletion, context);
        Ok(None)
    }

    /// Decide whether a verified later application covers an outstanding deletion.
    /// This separate decision does not repeat the original observation's local writes.
    fn record_put_back_successor(
        &self,
        deletion: &RecordDeletion<'_>,
        successor: &RecordSuccessor<'_>,
        context: &ReceiveContext<'_>,
    ) -> Result<PutBackSuccessor, StoreFailure> {
        let _ = (deletion, successor, context);
        Ok(PutBackSuccessor::Wait)
    }

    /// Whether a newer write of a record goes back on what the app has seen there, or fails
    /// another of the protocol's checks (Switch spec 8.2), such as dropping or replacing a
    /// message of a role it saw: the rule it breaks, without content, and the write is
    /// flagged with the app that signed it and not acted on. `seen` is the protocol's mark
    /// of what the app has seen of the record ([`Protocol::record_seen`]), `None` when it
    /// has seen nothing yet, such as at the first read of a record: every write of another
    /// app the app would take is checked, the first included. `value` is `None` for a
    /// delete or an unreadable value. Never by default.
    ///
    /// `base` tells what the newer write builds on ([`WriteBase`]): its `expected_version`,
    /// whether the app holds that version, the conditions its operation signed, and the
    /// service time its stub or proof dates it at, if anything dates it. A
    /// protocol whose rules hold only for a writer that built on the value the app holds,
    /// such as one that may drop only what it held itself, applies them when `base.held`;
    /// one whose rule fences a change on a condition, such as a `claim_step` on the claim of
    /// what the write drops, finds it in `base.conditions`. A protocol whose rules don't
    /// depend on the base ignores it.
    ///
    /// The rule is at most [`MAX_REGRESSION_REASON_BYTES`], 256 bytes; a longer one is cut
    /// there, at a character boundary.
    fn record_regression(
        &self,
        collection: &str,
        seen: Option<&[u8]>,
        value: Option<&[u8]>,
        base: WriteBase,
    ) -> Option<String> {
        let _ = (collection, seen, value, base);
        None
    }

    /// The bytes of the protocol's backup layer from its local state as committed: every
    /// key and value it holds, in key order, read by [`super::App::backup_layered`] in the
    /// same call as the app's own state. [`Protocol::restore_layer`] reads them back. By
    /// default the whole state, as [`encode_local_state`] gives it.
    ///
    /// # Errors
    ///
    /// Why the state can't be backed up, without content: the backup is refused.
    fn backup_layer(&self, state: Vec<KeyValue>) -> Result<Vec<u8>, String> {
        Ok(encode_local_state(&state))
    }

    /// The writes that install a backup's protocol layer at a restore (Switch spec 12.4),
    /// or that a backup without one, `None`, needs. [`super::App::restore`] calls it once,
    /// after it checked the backup's own state and the layer's name and before it writes
    /// anything, and commits the writes in the one commit that installs its own restored
    /// state, after it cleared the app's namespace: so the protocol starts from an empty
    /// local state and its writes stay under its prefix. It checks the layer in full here;
    /// nothing is written until it returns. [`super::App::backup_layered`] calls it too,
    /// writing nothing, to check that the backup can be restored, so it has no effect of
    /// its own. By default it reads the layer as the default [`Protocol::backup_layer`]
    /// writes it ([`decode_local_state`]) and puts every key back, and needs no writes for a
    /// backup without a layer.
    ///
    /// It runs at every restore and at every [`super::App::backup_layered`], so it has no
    /// side effects: it returns the writes, and the app commits them or doesn't.
    ///
    /// `restoring` gives the identity, the App ID, the certificate and `blind` under the
    /// naming key of the backup, the ones the restored app goes on with
    /// ([`RestoreContext`]), so the protocol can check its layer and the backup against
    /// them here, rather than after the restore commits: such as that each claim key it
    /// keeps is the one its inputs blind to, or that the certificate holds the scopes and
    /// permissions the protocol requires. In [`super::App::backup_layered`]'s check it gives
    /// the app's current ones, which the backup carries. The default ignores it.
    ///
    /// # Errors
    ///
    /// Why the layer, or a backup without one, can't be installed, without content: the
    /// restore is refused and nothing is written.
    fn restore_layer(
        &self,
        layer: Option<&ProtocolLayer>,
        restoring: &RestoreContext<'_>,
    ) -> Result<Vec<LocalWrite>, String> {
        let _ = restoring;
        let Some(layer) = layer else {
            return Ok(Vec::new());
        };
        let state = decode_local_state(&layer.data)
            .ok_or_else(|| String::from("the layer doesn't read as local state"))?;
        Ok(state
            .into_iter()
            .map(|(key, value)| LocalWrite::Put { key, value })
            .collect())
    }

    /// Build the shared record's next value for a sent message (Switch spec 8.2).
    /// `current` is `None` for an absent, deleted or unreadable record. The client can call
    /// this hook again for the same message after a write conflict or when the outcome of
    /// an earlier write is unknown. Make the update idempotent by returning `None` when
    /// the current value already reflects the message. The default returns `None`.
    fn sent_record(
        &self,
        job: &RecordJob,
        sent: &SentMessage,
        current: Option<&[u8]>,
    ) -> Option<Vec<u8>> {
        let _ = (job, sent, current);
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_admission_custody_refuses_unbounded_cleanup_without_losing_the_replacement() {
        let mut custody = AdmissionCustody::default();
        let deletion = LocalWrite::Delete {
            key: b"old".to_vec(),
        };
        let key = b"new".to_vec();
        let value_len = MAX_STEP_LOCAL_BYTES
            - LOCAL_WRITE_OVERHEAD_BYTES
            - key.len()
            - local_writes_bytes(std::slice::from_ref(&deletion));
        let replacement = LocalWrite::Put {
            key,
            value: vec![7; value_len],
        };
        custody.try_push(replacement.clone()).unwrap();
        assert!(matches!(
            custody.try_push(LocalWrite::DeletePrefix { prefix: Vec::new() }),
            Err(Refusal::Usage(_))
        ));
        custody.try_push(deletion.clone()).unwrap();
        assert!(matches!(
            custody.try_push(deletion.clone()),
            Err(Refusal::Usage(_))
        ));
        assert_eq!(custody.into_writes(), [replacement, deletion]);
    }

    #[test]
    fn test_local_write_debug_hides_values() {
        let write = LocalWrite::Put {
            key: b"note".to_vec(),
            value: b"secret-body".to_vec(),
        };
        let text = format!("{write:?}");
        assert!(!text.contains("secret"), "{text}");
        assert!(text.contains("11 value bytes"));
    }
}
