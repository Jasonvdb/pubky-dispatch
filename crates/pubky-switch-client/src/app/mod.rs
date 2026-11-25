//! The app layer: one app of an identity, run on top of the Switch.
//!
//! An [`App`] holds the app's keys, certificate and record, its own `identity.json`, its
//! receive keys, its scope keys and naming key, its view of the chain and its cursor, and
//! follows its feed. Every durable change lives in the host's [`crate::store::StateStore`]
//! under the namespace `client/<app_id>`, one record per key (`STATE.md` lists them), and
//! every change that goes with a network effect is committed in one write batch at the
//! moment the spec's crash rules give it:
//!
//! - a signed artifact (a registration, a record, an effect's batch) is committed before it
//!   is first sent, and resent byte for byte until answered (Switch wire 2.1 "Sign once");
//! - the cursor moves only with, or after, the effects it covers (Switch spec 8.2, 11);
//! - a retired receive key is deleted only once the cursor has passed the next key's
//!   registration (Switch spec 3.6).
//!
//! The protocol the app is built with ([`Protocol`]) gives the kind rules and the effects of
//! received messages; the Switch gives them no meaning (Switch spec 1). Its receive step
//! builds a message's record writes and claim entries through a [`ReceiveContext`], into the
//! batch that moves the cursor (Switch spec 8.2); its other writes go in batches of its own
//! ([`OpBatch`]), with its local writes and the messages it signed before queueing them
//! ([`App::sign_message`]), or alone ([`App::protocol_commit`]).
//!
//! Async is used only at the network edge: the switch, through the base client, the store,
//! through [`StoreHandle`], and the Homeserver, through [`HomeserverReader`] and, for an
//! app that publishes its record, [`HomeserverWriter`].
//!
//! Moves, provider loss and recovery, revocation and erasure as an app sees them, and push
//! with its peek, are in `provider.rs`, `recovery.rs`, `push.rs` and `peek.rs`.
//!
//! Sending with the outbox and directories, admission, shared records and claims, batches
//! with conditions, and the receive context are in `send.rs`, `directory.rs`,
//! `admission.rs`, `records.rs`, `claims.rs`, `batch.rs` and `context.rs`. `STATE.md` lists
//! the store keys each part keeps.
//!
//! Every call that reaches the network returns a boxed future at its boundary, so a caller's
//! stack holds only a pointer to the call's state, debug builds included.

mod chain;
mod deletion;
mod display;
mod error;
mod events;
mod feed;
mod forget;
mod health;
mod held_cursor;
mod identity;
mod kept;
mod keys;
mod next_body;
mod order;
mod own_record;
mod parked;
mod peek;
mod protocol;
mod protocols;
mod provider;
mod push;
mod put_back;
mod record_members;
mod recovery;
mod renewal;
mod retirement;
mod rotation;
mod seen_marks;
mod state;
mod unverified;
mod uploaded;
mod wait;
mod writer_certs;

mod admission;
mod batch;
mod claims;
mod context;
mod directory;
mod list_settlement;
mod records;
mod send;

#[cfg(test)]
mod tests;

pub use chain::{HELD_MARKS, STUBS_KEPT_FOR_MS};
pub use display::{DisplayRead, DisplayReceipt};
pub use error::{Alarm, AppError, KeptAhead, Refusal, WontDeliver};
pub use events::{
    AppEvent, BackupRefusal, CertificateRefusal, ClaimAttempt, DropReason, EVENT_ID_LEN, EventId,
    EventIdError, ListsLeftOut, ParkReason, PendingDuty, RecordBaseCause, RefusedCall,
    StoredMessageIdentity, WaitingReason,
};
pub use feed::{FEED_PAGES_PER_READ, ReceiveReport, SENDER_REREAD_MS};
pub use health::{ProviderHealth, RecoveryNotice};
pub use held_cursor::HeldCursor;
pub use identity::{DOC_CACHE_MS, HomeserverReader, IdentityRefresh, REVALIDATION_MS};
pub use kept::{KeptBatch, KeptBatchDrop, KeptBatchStatus};
pub use own_record::{HomeserverWriter, PUBLISHED_CHECK_MS, Publication, RecordExpiry};
pub use parked::{ParkedMessage, ParkedSummary};
pub use peek::{PEEK_PAGES, PeekReport, Peeked};
pub use protocol::{
    AdmissionCustody, DeferCustody, DenyListChange, DenyListGap, Effect, EntryReceipt,
    FeedPosition, LOCAL_WRITE_OVERHEAD_BYTES, LocalWrite, MAX_CLAIM_READS, MAX_LOSS_REPLY_PEERS,
    MAX_REGRESSION_REASON_BYTES, MAX_SEEN_MARK_BYTES, MAX_STEP_LOCAL_BYTES, MissedEntries, Need,
    OpaqueRule, Outcome, PARKED_RETRIES_PER_READ, Protocol, ProtocolLayer, PutBack,
    PutBackSuccessor, RETRY_EVENT_READS, ReceivedMessage, RecordDeletion, RecordMarkContext,
    RecordObservation, RecordRepair, RecordSuccessor, ResendNeeded, ResendReason, StoreFailure,
    WriteBase, decode_local_state, encode_local_state, local_writes_bytes,
};
pub use protocols::ProtocolSet;
pub use provider::{KEPT_BATCH_ANSWER_MS, KEPT_BATCH_MARGIN_MS, ProviderStatus};
pub use push::{MAX_HANDLE_BYTES, MAX_HANDLES, PushHandles, PushRegistration, PushRelay};
pub use record_members::{HeldRecordEdit, ProtocolRecord};
pub use recovery::inventory::{
    LossCheckpoint, LossInventoryDetails, LossUpload, LossUploadOutcome, OmittedClaimEntry,
};
pub use recovery::lists::RecoveryDenyEntry;
pub use recovery::{
    Evidence, LossActions, ProviderLoss, RESIDUAL_WINDOW_MS, RecoveryInfo, RecoveryStep,
};
pub use state::{PROTOCOL_PREFIX, SCHEMA_VERSION};
pub use unverified::{
    MAX_UNVERIFIED_AGE_MS, MAX_UNVERIFIED_PER_SENDER, MAX_UNVERIFIED_TOTAL,
    UNVERIFIED_DROPS_PER_COMMIT,
};
pub use uploaded::{MAX_RECORD_MARKS, RECORD_REREADS_PER_READ};
pub use wait::{
    FeedWait, MAX_PAUSE_MS, MAX_WAIT_SECONDS, MIN_PAUSE_MS, UPKEEP_READ_MS, WaitPace, Woken,
};

pub use admission::{INVITE_CODE_BYTES, InviteCode, LISTS_TOO_LARGE_RETRY_MS, SenderDisposition};
pub use batch::{
    KEPT_RESENDS_PER_READ, KEPT_RESENDS_PER_WRITE, MAX_KEPT_BATCHES_BYTES, OpBatch, server_time_in,
};
pub use claims::{
    CLAIM_REREADS_PER_READ, ClaimDoubt, ClaimEntryRead, ClaimEvidence, ClaimOp, ClaimRead,
    ClaimWritten, ObligationDeadline, claim_conflict,
};
pub use context::{ClaimFetch, LocalView, ReceiveContext, RestoreContext};
pub use directory::{
    HomeserverCopy, IdentityLookup, Initiator, MayAct, PEER_DELIVERY_MS, PeerIdentity,
    SwitchAnswer, SwitchCopy, SwitchLookup,
};
pub use records::{
    Collection, CollectionListed, CurrentCollection, FlaggedWrite, KeptOp, KeptReason,
    LISTING_PAGES_PER_READ, LossRecordApplication, PolicyFamily, RecordApplication, RecordContent,
    RecordRead, RecordTarget, SharedEvidence, SharedRecord, ShownWrite, Unopened,
};
pub use send::{
    AppendDecision, Delivery, DeliveryOrigin, DeliveryView, MAX_APPEND_RECORDS,
    MAX_CARRIED_OUTBOX_BYTES, OUTBOX_TRIES_PER_FLUSH, OutboxReport, OutgoingMessage, QueuedMessage,
    RecordJob, ReplyGrantOnRelease, SENT_RETENTION_MS, SentMessage, SignedMessage,
    UNDELIVERABLE_MAX_MS, UNDELIVERABLE_MS, UNDELIVERABLE_TRIES, UNDELIVERABLE_TRY_SPACING_MS,
    UndeliverableReason,
};

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::Arc;

use pubky_switch_core::chain::TransitionProof;
use pubky_switch_core::enc::zbase32_encode;
use pubky_switch_core::ident::NamingKey;
use pubky_switch_core::keys::{AppKeys, ReceiveKey, ScopeKey, ScopeKeys};
use pubky_switch_core::ops::{Condition, OpKind, Position};
use pubky_switch_core::records::{
    AppCert, AppRecord, AppRequest, Approval, CLOCK_TOLERANCE_MS, DAY_MS, IdentityDoc,
    ReceiveKeyBody, ReceiveKeyRecord,
};
use pubky_switch_core::scopes::Permission;
use pubky_switch_core::sig::SignedDoc;
use serde::{Deserialize, Serialize};

use self::chain::ChainView;
use self::state::{
    BundleState, CachedDoc, Cursor, Device, HeldEntry, HeldKey, JoinStep, KnownKid, LeaveState,
    Meta, ParkedEntry, PendingEffect, PendingRecord, Processed, Reader, Registration,
    RestorePending, RestoreState, RetryEntry, Rotation, ServiceTime, Tx, key,
};
use crate::client::{Batch, Credentials, Submitted, SwitchClient};
use crate::clock::{AppClock, Clock, ClockSample};
use crate::error::{ClientError, StoreError};
use crate::store::{StoreHandle, client_namespace};
use crate::transport::Transport;

/// How many entries of the protocol's local state one store scan reads.
const PROTOCOL_SCAN_PAGE: u32 = 256;

/// The default receive key rotation interval: a day (Switch spec 3.6).
pub const DEFAULT_ROTATION_MS: u64 = DAY_MS;

/// The shortest rotation interval: an hour (Switch spec 3.6).
pub const MIN_ROTATION_MS: u64 = 3_600_000;

/// The default bounded wait for a sender that can't be checked, after which the entry is
/// stored locally and the cursor moves past it: 24 hours (Switch spec 8.2, the app's
/// choice).
pub const DEFAULT_PARK_AFTER_MS: u64 = DAY_MS;

/// The default time a cursor-only move waits for the app's next batch (Switch spec 8.2).
pub const DEFAULT_CURSOR_DEFER_MS: u64 = 2_000;

/// The longest a cursor-only move may be deferred while the app runs (Switch spec 8.2).
pub const MAX_CURSOR_DEFER_MS: u64 = 10_000;

/// How long processed (sender, `msg_id`) pairs are kept: 30 days plus the clock tolerance
/// (Switch spec 11).
pub const PROCESSED_RETENTION_MS: u64 = 30 * DAY_MS + CLOCK_TOLERANCE_MS;

/// How long a two-step leave waits after the app's removal is published before it deletes
/// its keys: the readers' 10-minute cache (Switch spec 12.3).
pub const LEAVE_CACHE_MS: u64 = 10 * 60_000;

/// A service time this far ahead of the device clock is shown to the user (Switch spec
/// 10.1).
pub const SERVICE_TIME_AHEAD_MS: u64 = DAY_MS;

/// The integrator's choices for one app.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AppConfig {
    /// The receive key rotation interval, at least [`MIN_ROTATION_MS`].
    pub rotation_interval_ms: u64,
    /// The bounded wait before an entry whose sender can't be checked is stored locally.
    pub park_after_ms: u64,
    /// How long a cursor-only move waits for the next batch, at most
    /// [`MAX_CURSOR_DEFER_MS`].
    pub cursor_defer_ms: u64,
    /// Items per feed page, 1 to 500.
    pub page_size: u32,
    /// Whether the app publishes its record on the Homeserver, as an app whose protocol
    /// needs public data does (Switch spec 4.2); such an app leaves in two steps (Switch spec
    /// 12.3). It needs [`AppEnv::homeserver_writer`].
    pub publishes_record: bool,
    /// The time budget of each bounded call, in milliseconds by the app's clock: 20 s by
    /// default. Once it has passed since the call began:
    /// - [`App::receive`]'s looping steps start no further request, each after its first,
    ///   and the read says [`ReceiveReport::more`], what is left kept for the next read;
    /// - [`App::update_record`] tries no further write;
    /// - [`App::flush_outbox`] starts no further unit after its first, and says
    ///   [`OutboxReport::more`];
    /// - [`App::list_collection`] and [`App::list_collections`] ask for no further page
    ///   after their first, and [`App::peek`] reads no further page.
    ///
    /// Each in-flight HTTP send has its own timeout. [`App::submit_batch`] bounds its
    /// work by the calls it makes. One message's delivery round ([`App::send`],
    /// [`App::resend`], [`App::flush_message`]) checks elapsed time before retrying a
    /// stale key, delivering a needed identity or rereading after an unverified answer. A signed
    /// timestamp correction can add an HTTP send within a call. The message's record
    /// job uses the separate budget of [`App::update_record`].
    pub call_budget_ms: u64,
}

/// [`AppConfig::call_budget_ms`] by default.
pub const DEFAULT_CALL_BUDGET_MS: u64 = 20_000;

/// The time budget of one bounded call ([`AppConfig::call_budget_ms`]): when it began, by
/// the app's clock. Passed down to the loops of the call, so a call made inside another
/// keeps its own and a dropped call leaves nothing behind.
#[derive(Clone, Copy, Debug)]
pub(crate) struct CallBudget {
    began_ms: u64,
    budget_ms: u64,
}

impl CallBudget {
    /// Whether the call has spent its budget at `now_ms`: it starts no further request.
    pub(crate) fn spent(&self, now_ms: u64) -> bool {
        now_ms.saturating_sub(self.began_ms) >= self.budget_ms
    }
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            rotation_interval_ms: DEFAULT_ROTATION_MS,
            park_after_ms: DEFAULT_PARK_AFTER_MS,
            cursor_defer_ms: DEFAULT_CURSOR_DEFER_MS,
            page_size: 100,
            publishes_record: false,
            call_budget_ms: DEFAULT_CALL_BUDGET_MS,
        }
    }
}

impl AppConfig {
    fn rotation_ms(&self) -> u64 {
        self.rotation_interval_ms.max(MIN_ROTATION_MS)
    }

    fn defer_ms(&self) -> u64 {
        self.cursor_defer_ms.min(MAX_CURSOR_DEFER_MS)
    }

    fn page(&self) -> u32 {
        self.page_size.clamp(1, 500)
    }
}

/// What an app runs on: the host's store, the transport to its switch, the clock, the
/// Homeserver reader and, for an app that publishes its record, the Homeserver writer.
#[derive(Clone)]
pub struct AppEnv {
    /// The host's store.
    pub store: StoreHandle,
    /// The transport to the switch.
    pub transport: Arc<dyn Transport>,
    /// The app's clock.
    pub clock: Arc<dyn Clock>,
    /// Reads of Homeservers.
    pub homeserver: Arc<dyn HomeserverReader>,
    /// Writes to the own identity's Homeserver, for an app that publishes its record
    /// ([`AppConfig::publishes_record`]); `None` for one that doesn't.
    pub homeserver_writer: Option<Arc<dyn HomeserverWriter>>,
}

impl AppEnv {
    fn observe_clock(&mut self) -> Arc<AppClock> {
        let clock = Arc::new(AppClock::new(Arc::clone(&self.clock)));
        self.clock = Arc::clone(&clock) as Arc<dyn Clock>;
        clock
    }
}

impl std::fmt::Debug for AppEnv {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "AppEnv({:?})", self.store)
    }
}

/// A new app's approval, as it joins (Switch spec 12.1).
#[derive(Clone)]
pub struct JoinRequest {
    /// The identity that approved the app.
    pub identity: [u8; 32],
    /// The app's keys, the ones its request named.
    pub keys: AppKeys,
    /// The app request it sent.
    pub request: AppRequest,
    /// The approval's JSON bytes, from the companion claim whose signature the caller
    /// verified (Switch wire 3.10).
    pub approval: Vec<u8>,
}

impl std::fmt::Debug for JoinRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "JoinRequest({:?})", self.keys)
    }
}

/// A token the host makes only after it showed the user what the call does.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UserConfirmed(());

impl UserConfirmed {
    /// The user confirmed.
    pub fn new() -> Self {
        Self(())
    }
}

impl Default for UserConfirmed {
    fn default() -> Self {
        Self::new()
    }
}

/// How the app leaves (Switch spec 12.3).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LeaveMode {
    /// Call `leave`, and delete the keys only once the signer published the app as
    /// removed and readers' caches passed: for an app whose record readers act on.
    TwoStep,
    /// Call `leave` and delete the keys at once, for example on uninstall. The user was
    /// warned that what readers do with the app's record may still reach it.
    Immediate(UserConfirmed),
}

/// Where a leave stands.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LeaveReport {
    /// The app left; the signer hasn't published it as removed yet.
    AwaitingRemoval,
    /// Published as removed; the keys go at this app-clock time.
    Removed {
        /// When.
        delete_keys_at_ms: u64,
    },
    /// The keys are deleted.
    Done,
}

/// The keys a device of the app shares with the app's other devices through the app's own
/// device sync (Switch spec 3.1, 3.6). Sensitive: its `Debug` shows no key.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceKeys {
    receive_keys: Vec<HeldKeyOut>,
    known: Vec<(String, u64)>,
    rotation_ms: u64,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
struct HeldKeyOut {
    key: ReceiveKey,
    record: SignedDoc,
}

impl std::fmt::Debug for DeviceKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "DeviceKeys({} keys)", self.receive_keys.len())
    }
}

/// An app's backup (Switch spec 12.4), as the app's own backup scheme stores it, encrypted
/// under a key the app or its user holds. It holds the signing key: apps should keep it out
/// of routine backups or encrypt it apart (Switch spec 12.4). Its `Debug` shows no key.
#[derive(Clone, Serialize, Deserialize)]
pub struct AppBackup {
    v: u32,
    meta: Meta,
    keys: AppKeys,
    cert: SignedDoc,
    /// The record the app presents, which may be one the switch hasn't accepted yet.
    record: SignedDoc,
    /// The newest record the switch accepted from the app (`record/accepted`), apart from
    /// `record`: a restore publishes only accepted bytes, deferring repair while a newer
    /// local record choice is unresolved (Switch spec 4.2). Absent from
    /// a backup of an app the switch accepted no record from that it knows of.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    accepted: Option<SignedDoc>,
    naming: NamingKey,
    scope_keys: Vec<ScopeKey>,
    own_doc: SignedDoc,
    receive_keys: Vec<HeldKey>,
    known: Vec<(String, u64)>,
    rotation: Rotation,
    device: Device,
    cursor: Cursor,
    chain: state::ChainRecord,
    chain_at: Vec<(u64, String)>,
    chain_batches: Vec<(String, u64)>,
    departed: Vec<(String, u64)>,
    bundle: BundleState,
    /// The local ID the next entry stored locally takes (`parkid`), so a restore gives out
    /// none the app gave out before the backup, whether or not the backup carries its entry.
    stored_next: u64,
    /// Unprocessed custody and its owed drop notices, independent of a protocol layer.
    waiting: unverified::WaitingOut,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    deletions: Vec<deletion::Observation>,
    put_backs: Vec<put_back::RecordHold>,
    record_settlements: Vec<batch::PendingBatch>,
    peers: admission::observations::SavedPeers,
    loss_lists: Option<recovery::lists::SavedLists>,
    loss_answers: Option<recovery::answers::SavedAnswers>,
    finished_list_upload: Option<u64>,
    /// Every duty event the protocols hadn't acknowledged, with the protocols each is for,
    /// but those [`events::Duty::backup_carries`] leaves out: a restore tells each again, to
    /// the protocols it registers (Switch spec 12.4 "Notices owed to the protocol").
    duties: Vec<events::KeptDuty>,
    /// How many duty events the backup's store held that didn't read: a restore tells
    /// the protocols how many are lost ([`AppEvent::RestoreLeftBehind`]).
    duties_left_behind: u64,
    /// The hash of the renewed certificate the app refused (`cert/refused`), `None` when
    /// it refused none: a restore keeps it with the carried [`AppEvent::CertificateRefused`],
    /// so the same certificate is refused without telling it twice.
    cert_refused: Option<String>,
    /// When the backup was taken, the app's clock: a restore reinstalls the messages whose
    /// delivery is owed only within [`SENT_RETENTION_MS`] of it.
    taken_ms: u64,
    /// The highest service time the app had verified when the backup was taken, the base of
    /// the outbox's replay deadline in place of `taken_ms`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    taken_service_ms: Option<u64>,
    /// The outbox (`out/`), oldest first, within its byte budget (`send::carried_outbox`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    outbox: Vec<send::OutboxItem>,
    /// The messages of the outbox left out past the budget, and whether each is a re-send.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    outbox_left_out: Vec<(String, bool)>,
    /// The counterparties whose messages the app holds ([`App::hold_queued`]), in base64:
    /// a restore holds them too, so it delivers none of their messages.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    held_counterparties: Vec<String>,
    /// The messages of `outbox` the app holds ([`App::hold_message`]), by `msg_id`: a
    /// restore holds them too.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    held_messages: Vec<String>,
    /// Each protocol's expiry policy (`rexp`), retained on restore: fixed deadlines stay
    /// fixed and lifetimes resolve from each new signed timestamp. The earliest resolved
    /// finite policy is the record's expiry. Empty while no protocol asked for one.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    record_expiries: Vec<(String, own_record::RecordExpiry)>,
    /// Unsigned member edits, paired with their owners' expiry choices above: every
    /// restore holds them aside, and signs none.
    record_members: Vec<(String, Option<serde_json::Map<String, serde_json::Value>>)>,
    #[serde(
        default,
        skip_serializing_if = "record_members::RecordChanges::is_empty"
    )]
    record_changes: record_members::RecordChanges,
    /// The protocols' layers of a layered backup ([`App::backup_layered`]), one per
    /// protocol, in registration order; absent from a plain backup's bytes.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    layers: Vec<LayerOut>,
    /// What the app's feed held beyond its cursor when a layered backup was taken; absent
    /// from a plain backup's bytes, present in every layered one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    beyond_cursor: Option<BeyondCursor>,
    /// The re-send and missed-entries calls owed when the backup was taken (`owed/`), each
    /// by its key after the prefix, with its value as stored, the protocols it is owed to
    /// among it. Most are at or behind the backup's cursor, which the restored feed never
    /// shows again; one may be ahead of it, carried ahead by an earlier restore in place,
    /// and waits for the feed to reach its item. A deny list call is left out: every
    /// restore tells every protocol a deny list gap at the restored cursor, whose full list
    /// covers it.
    owed: Vec<(String, serde_json::Value)>,
    /// The seen mark of every record the app holds one for (`hw/`), as the store holds it,
    /// but those that didn't fit the restore's one commit: every restore installs them in
    /// place of the store's own (Switch spec 8.2, 12.4 "Seen marks").
    seen_marks: Vec<seen_marks::CarriedMark>,
    /// Whether the backup's marks are incomplete: some didn't fit and were left out, or one
    /// couldn't be read when the backup was taken and was skipped. The restore tells each
    /// protocol so once ([`AppEvent::SeenMarksIncomplete`]), as it does when the marks don't
    /// all fit its own commit.
    seen_marks_incomplete: bool,
}

/// A [`ProtocolLayer`] as a backup's bytes carry it: the protocol's name and its data in
/// base64.
#[derive(Clone, Serialize, Deserialize)]
struct LayerOut {
    name: String,
    data: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    deletions: Vec<deletion::Receipt>,
}

/// What the app's feed holds beyond its cursor at the moment of a layered backup: the
/// entries processed past a held one, the entries stored locally, and the processed pairs
/// (Switch spec 11). The protocols' layers reflect those entries, so a restore that brought
/// them back without these would hand the entries to the protocols again.
#[derive(Clone, Serialize, Deserialize)]
struct BeyondCursor {
    /// The registered protocols whose layers and feed progress were taken together.
    protocols: Vec<String>,
    /// Missed items already handed beyond the committed cursor.
    missed: Vec<u64>,
    /// The sequence and highest held cursor already handed to these layers.
    held_gap: Option<(u64, u64)>,
    seen: Vec<u64>,
    parked: Vec<(u64, ParkedEntry)>,
    /// Each pair's key after `proc/`, and its record.
    processed: Vec<(String, Processed)>,
}

impl std::fmt::Debug for AppBackup {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "AppBackup({})", zbase32_encode(&self.meta.app_id))
    }
}

impl AppBackup {
    /// The backup's bytes.
    ///
    /// # Errors
    ///
    /// [`AppError::Store`] if it can't be written.
    pub fn to_bytes(&self) -> Result<Vec<u8>, AppError> {
        serde_json::to_vec(self)
            .map_err(|_| AppError::Store(StoreError::Other("the backup can't be written".into())))
    }

    /// Read a backup's bytes. A layered backup is told by its `layers` and `beyond_cursor`
    /// members, under the same version as a plain one.
    ///
    /// # Errors
    ///
    /// [`AppError::InvalidData`] if they don't read as a backup, or their version isn't
    /// [`SCHEMA_VERSION`].
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, AppError> {
        #[derive(Deserialize)]
        struct Version {
            v: u32,
        }
        let version: Version = serde_json::from_slice(bytes)
            .map_err(|_| AppError::InvalidData("the backup doesn't read".into()))?;
        if version.v != SCHEMA_VERSION {
            return Err(AppError::InvalidData(
                "the backup is of another schema version".into(),
            ));
        }
        serde_json::from_slice(bytes)
            .map_err(|_| AppError::InvalidData("the backup doesn't read".into()))
    }

    /// Leave out the marks `left` that didn't fit the restore's one commit, the backup then
    /// incomplete (Switch spec 12.4 "Seen marks").
    fn leave_out_marks(&mut self, left: &[[u8; 32]]) {
        if !left.is_empty() {
            let left: std::collections::BTreeSet<&[u8; 32]> = left.iter().collect();
            self.seen_marks.retain(|mark| !left.contains(&mark.key()));
            self.seen_marks_incomplete = true;
        }
    }

    /// The protocols' layers the backup holds, one per protocol, in the order they were
    /// registered when it was taken; none for a plain backup.
    ///
    /// # Errors
    ///
    /// [`AppError::InvalidData`] if a layer's data doesn't read, or two layers name one
    /// protocol.
    pub fn layers(&self) -> Result<Vec<ProtocolLayer>, AppError> {
        let mut out: Vec<ProtocolLayer> = Vec::with_capacity(self.layers.len());
        for layer in &self.layers {
            if out.iter().any(|held| held.protocol == layer.name) {
                return Err(AppError::InvalidData(
                    "the backup: two layers name one protocol".into(),
                ));
            }
            out.push(ProtocolLayer {
                protocol: layer.name.clone(),
                data: pubky_switch_core::enc::unb64(&layer.data).map_err(|_| {
                    AppError::InvalidData("the backup: a protocol layer doesn't read".into())
                })?,
            });
        }
        Ok(out)
    }
}

/// A restore, built: the app and its one commit, or the error of a write the store can't
/// take in one batch: of the backup's own state, or of what a restore in place carries
/// beside it ([`Refusal::CarriedTooLarge`]).
enum Restorable {
    /// The app, its commit, and the seen marks it left out.
    Ready(Box<App>, Tx, seen_marks::Installed),
    TooLarge(AppError),
    CarriedTooLarge {
        duty_events: u64,
        owed_calls: u64,
    },
}

/// How a restore's build treats the protocol's check of its layer: in full, for a restore
/// and a layered backup, or, for a plain backup's own check, only for the sizes, a refusal
/// counting as no layer writes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum LayerCheck {
    Install,
    Full,
    SizesOnly,
}

/// What made a backup too large for its restore's one commit.
enum TooLargeFor {
    /// Its duty events not acknowledged, this many: it fits without them.
    Duties(u64),
    /// The rest of it, with the store's size refusal.
    Rest(AppError),
}

impl TooLargeFor {
    fn reason(&self) -> BackupRefusal {
        match self {
            Self::Duties(duty_events) => BackupRefusal::DutiesTooLarge {
                duty_events: *duty_events,
            },
            Self::Rest(_) => BackupRefusal::TooLarge,
        }
    }

    fn into_error(self) -> AppError {
        match self {
            Self::Duties(duty_events) => Refusal::DutiesTooLarge { duty_events }.into(),
            Self::Rest(error) => error,
        }
    }
}

/// `env` over an empty store, as on a new device: a backup's check builds its restore there,
/// so it reads nothing of the store it was taken from (Switch spec 12.4).
fn on_empty_store(env: &AppEnv) -> AppEnv {
    let mut empty = env.clone();
    empty.store = StoreHandle::inline(Arc::new(crate::store::MemoryStore::new()));
    empty
}

/// The latest time a clock can say. A backup's check builds its restore with it, so the
/// times any restoring device writes take no more digits than the check's (Switch spec 12.4).
struct LatestClock;

impl Clock for LatestClock {
    fn now_ms(&self) -> u64 {
        u64::MAX
    }
}

/// `env` as a backup's check builds a restore: over an empty store, as on a new device, and
/// with [`LatestClock`].
fn for_a_check(env: &AppEnv) -> AppEnv {
    let mut check = on_empty_store(env);
    check.clock = Arc::new(LatestClock);
    check
}

/// A backup's check builds onto an empty store, which carries nothing of an earlier
/// installation: a refusal that says it does fails the check closed.
fn carried_by_a_check() -> AppError {
    AppError::InvalidData("the backup's check carried an earlier installation's state".into())
}

/// The error of building a restore's commit: [`Restorable::TooLarge`] for writes over the
/// store's sizes ([`StoreError::TooLarge`]), which [`App::backup_layered`] reports as
/// [`BackupRefusal::TooLarge`]; any other error is returned as it is, unlabelled.
fn restore_build_error(error: AppError) -> Result<Restorable, AppError> {
    match error {
        AppError::Store(StoreError::TooLarge { .. }) => Ok(Restorable::TooLarge(error)),
        error => Err(error),
    }
}

/// The app's state in memory, as the store holds it.
#[derive(Clone, Debug)]
pub(crate) struct AppState {
    pub(crate) meta: Meta,
    pub(crate) keys: AppKeys,
    pub(crate) cert: AppCert,
    pub(crate) renewal: Option<renewal::KeptRenewal<AppCert>>,
    pub(crate) record: SignedDoc,
    pub(crate) naming: NamingKey,
    pub(crate) scope_keys: ScopeKeys,
    pub(crate) bundle: BundleState,
    pub(crate) own_doc: IdentityDoc,
    pub(crate) receive_keys: BTreeMap<u64, HeldKey>,
    pub(crate) known_kids: BTreeMap<[u8; 8], u64>,
    pub(crate) registrations: BTreeMap<u64, Registration>,
    pub(crate) rotation: Rotation,
    pub(crate) device: Device,
    pub(crate) cursor: Cursor,
    pub(crate) chain: Option<ChainView>,
    pub(crate) held: BTreeMap<u64, HeldEntry>,
    deletions: deletion::Observations,
    deletion_receipts: deletion::Receipts,
    put_backs: put_back::Holds,
    pub(crate) retries: BTreeMap<u64, RetryEntry>,
    /// The counts of the store's retries at entries stored locally, by local ID.
    pub(crate) stored_retries: BTreeMap<u64, RetryEntry>,
    /// The local ID the next entry stored locally takes (`parkid`): it only goes up.
    pub(crate) next_stored_id: u64,
    /// Where the retries of stored entries stand in their round (`parkn`), so a bounded
    /// number each read reaches every one in turn.
    pub(crate) parked_round: state::ParkedRound,
    pub(crate) seen: BTreeSet<u64>,
    pub(crate) asked: BTreeSet<u64>,
    pub(crate) parked: BTreeMap<u64, ParkedEntry>,
    pub(crate) departed: BTreeMap<[u8; 16], u64>,
    pub(crate) join: JoinStep,
    pub(crate) pending_effect: Option<PendingEffect>,
    pub(crate) pending_record: Option<PendingRecord>,
    /// The record the switch holds and the Homeserver is still owed (`pending/publish`).
    pub(crate) pending_publish: Option<SignedDoc>,
    /// The newest record the switch accepted from the app (`record/accepted`), the one a
    /// publication writes.
    pub(crate) accepted: Option<SignedDoc>,
    pub(crate) alarm: Option<Alarm>,
    pub(crate) restore: Option<RestoreState>,
    /// After a restore, why a read didn't take the record the switch holds as the base
    /// (`rbase`, [`RecordBaseCause`]); `None` once one did, or after no restore. Kept apart
    /// from `restore`, which reconciliation's end removes: no record is built on an unread
    /// base after it either.
    pub(crate) base_unread: Option<RecordBaseCause>,
    /// The renewed certificate the app refused (`cert/refused`), as stored: kept here so the
    /// gates where a record is signed or sent read it. One that doesn't read names nothing.
    pub(crate) cert_refused: Option<String>,
    /// The last restore's check of the cursor the service holds (`hcur`).
    pub(crate) restore_cursor: Option<held_cursor::RestoreCursor>,
    pub(crate) leave: Option<LeaveState>,
    pub(crate) service_time: Option<ServiceTime>,
    /// The app isn't current any more, or its account is gone: every read stops.
    pub(crate) gone: Option<provider::GoneRecord>,
    pub(crate) health: health::ServiceHealth,
    display_read: Option<DisplayRead>,
    /// The ID the next duty event takes (`dutyn`).
    pub(crate) next_duty: u64,
    /// The store's event epoch (`dutye`).
    pub(crate) duty_epoch: state::DutyEpoch,
    /// The wait before the account counts as erased, while it runs.
    pub(crate) erasing: Option<provider::ErasingRecord>,
}

struct ServiceTimeSample {
    local: ClockSample,
    service_ms: u64,
}

/// Permission and notification changes saved with a renewed certificate.
#[derive(Debug, Default)]
struct RenewalChanges {
    removed: Vec<deletion::Id>,
    receipts: deletion::Receipts,
    cursor: Cursor,
    next_duty: u64,
    duty_owners: BTreeMap<u64, Vec<String>>,
}

/// One app of an identity, on top of the Switch.
pub struct App {
    env: AppEnv,
    clock: Arc<AppClock>,
    protocols: ProtocolSet,
    config: AppConfig,
    ns: String,
    state: AppState,
    client: SwitchClient,
    /// The next state-changing call must reload from the store.
    reload: bool,
    /// A failed or interrupted save may have left memory and the store out of sync.
    save_needs_reload: bool,
    /// The service time record changed and goes with the next commit.
    service_time_dirty: bool,
    /// The held alarm still needs a confirmed durable commit.
    alarm_dirty: bool,
    /// A verified health change awaiting its durable state and duty commit.
    pending_health: Option<health::ServiceHealth>,
    /// Device-clock interval for reporting a sustained outage (Switch spec 12.6).
    unreachable_after_ms: u64,
    /// The last Homeserver read that confirmed the own `identity.json`; kept in memory only.
    identity_confirmed: Option<identity::Confirmed>,
    /// The listed certificates the own directory answered a read for, to judge a record
    /// write: each is read for once while the app runs. Kept in memory only.
    directory_asked: Vec<[u8; 32]>,
    /// When such a read last failed, device clock: none again for [`SENDER_REREAD_MS`],
    /// then a later write's judging reads again. Cleared by a read that answers. In memory
    /// only.
    directory_failed_ms: Option<u64>,
    events: Vec<AppEvent>,
    /// Whether an owed call holds the read, as the last retry of `owed/` left it, and set as
    /// calls are owed. In memory only.
    owed_known: Option<bool>,
    /// How far each protocol has been told, (generation, `seq`), as `told/<name>` keeps it
    /// and as the read under way moved it (`order` module): a protocol is told nothing past
    /// the item right after its position ([`App::may_tell`]).
    told: order::Positions,
    /// The positions as the store holds them, so a commit writes only those that moved.
    told_kept: order::Positions,
    /// Whether the positions were read from the store since the last reload.
    told_loaded: bool,
    /// Where the walk of the read under way stands, inside a page ([`App::may_tell`]). In
    /// memory only.
    walk: Option<order::Walk>,
    /// The collection prerequisites (`list_due`), as the read's last listing step left
    /// them: each protocol waits at its listing's position, including sequence zero
    /// ([`App::may_tell`]). In memory only.
    listing_due: records::ListDue,
    /// Calls still owed to each protocol, derived from the retained queue and updated as
    /// the read keeps a call. They remain prerequisites even at zero (`order` module).
    pending_calls: Vec<order::Kept>,
    /// How many reads in a row stopped at an owed call or deny list gap the protocol didn't
    /// take ([`AppEvent::OwedCallHeld`]). In memory only.
    owed_held_reads: u32,
    /// The calls and listings kept past the cursor, by their item's `seq` in the cursor's
    /// sequence, which a move or a key change in place continues under the next generation,
    /// each with the protocols it names, as a restore in place carries a call: the feed
    /// passes such an item without handing it, the kept form being that item's notice, and
    /// the protocols it names stay before it, so each takes it in feed order, once, when a
    /// read's start finds the cursor there. It may be any distance ahead. Set at each read's
    /// start. In memory only.
    kept_ahead: std::collections::BTreeMap<u64, order::KeptAhead>,
    /// The read (by [`App::receive`]'s count) the own directory was read in for a deny list
    /// change's writer, and whether it answered: once a read. In memory only.
    deny_directory_read: Option<(u64, bool)>,
    /// The highest duty event counter queued in `events` since the app was made: a kept one
    /// above it is queued after a reload (`events` module, "Duty events").
    duty_queued: u64,
    /// The highest duty event counter handed to the host since the app was made: no
    /// acknowledgement removes one above it.
    duty_handed: u64,
    /// The protocols each duty event reported or listed by this app value is for, by its
    /// counter, until they acknowledge it ([`App::event_owners`]). In memory only.
    duty_owners: BTreeMap<u64, Vec<String>>,
    /// The verified service time and its device-clock sample in this call
    /// ([`App::fresh_service_time`]). Never restored from a backup or reopened store.
    time_fresh_at: Option<ServiceTimeSample>,
    /// When a kept batch was last answered `429 rate_limited`, and the end of the wait its
    /// `retry_after` asked, both device clock: no read sends the kept batches again in
    /// between (`App::resume_batches_before_feed`). Kept in memory only: a restart sends
    /// them at its first read.
    kept_rate_limited: Option<(u64, u64)>,
    /// The end of the wait a recovery upload's `429 rate_limited` asked, device clock: no
    /// upload of a provider loss's steps goes before it. In memory only.
    loss_upload_wait: Option<u64>,
    /// When a failed check 7 last had each sender's `identity.json` read again
    /// (`feed.rs`, [`SENDER_REREAD_MS`]). Kept in memory only: it bounds the reads, and a
    /// restart may read once more.
    sender_rereads: HashMap<[u8; 32], feed::SenderReread>,
    /// When an answer of each recipient's switch that didn't verify last had its
    /// `identity.json` read again (`send.rs`, [`SENDER_REREAD_MS`]), device clock. Kept in
    /// memory only: it bounds the reads, and a restart may read once more.
    peer_rereads: HashMap<[u8; 32], u64>,
    /// How many reads ([`App::receive`]) this app began since it was loaded.
    reads_begun: u64,
    /// The worst held-cursor verdict of the read under way's pages ([`HeldCursor::worse`]),
    /// taken into its report. In memory only.
    held_cursor_read: Option<HeldCursor>,
    last_collection_read: Option<Arc<feed::ReadCoverage>>,
    /// Which local certificate a checked own directory establishes at one signed service head.
    record_page_reader: Option<records::PageReader>,
    /// The sequence and highest held cursor reported ahead with
    /// [`AppEvent::HeldCursorAhead`], so a report isn't told again at every page; cleared by
    /// a page that isn't ahead. In memory only.
    held_ahead_told: Option<(u64, u64)>,
    /// The read under way made a listing before handing any item: it covers a gap ahead its
    /// first page shows (`feed.rs`). In memory only.
    listed_before_items: bool,
    /// Whether a protocol's listing waits for a scope key while the read under way goes on
    /// for the others, as its listing step left it. In memory only.
    listing_waits: bool,
    /// Whether the read under way made its listing for every protocol. In memory only.
    listed_every: bool,
    /// How many times an owed reopening failed in the read under way ([`App::receive`]):
    /// after [`records::REOPEN_TRIES_PER_READ`], it is left for the next read. In memory
    /// only.
    reopen_failures: u32,
    /// The earliest list position kept ahead of the cursor, once known; `Some(None)` when
    /// none is kept. A commit that only advances the cursor scans the kept positions once the
    /// cursor reaches it (Switch spec 7, 8.3).
    retained_floor: Option<Option<FeedPosition>>,
    /// Set while a read follows a provider change: a loss's list step then waits until the
    /// read's feed is read (`App::list_step_after_read`).
    defer_list_step: bool,
    /// Set by a read that stops short of its feed for what the next read ends, not a
    /// protocol: a deny gap's list read or a deny change's check that failed for now, a gap
    /// in the feed's history, a deny change that can't be checked or an upload that added to
    /// the lists, each told at the next read, a freeze, or the app's own removal. Its list step waits for a read that reads on.
    read_short: bool,
    /// The device-clock time and signature of the accepted record last confirmed published.
    published_check: Option<(u64, String)>,
    /// When this app last asked for its full key bundle, device clock (`keys.rs`,
    /// [`keys::KEY_REQUEST_RETRY_MS`]). In memory only.
    bundle_asked_ms: Option<u64>,
    /// When a read last looked in the directory for a renewal the own `identity.json` lists
    /// and the app holds no `cert.put` for, without finding it, device clock
    /// ([`App::take_renewal_listed_elsewhere`]). In memory only.
    renewal_looked_ms: Option<u64>,
    /// Where a wait for the feed starts, as the last read left it ([`App::feed_wait`]). In
    /// memory only: a restart waits from the cursor.
    next_wait: wait::NextWait,
    /// The device time the last read that succeeded ended, in memory only: a quiet wait
    /// past [`UPKEEP_READ_MS`] after it is a read ([`App::feed_wait`]).
    read_done_ms: Option<u64>,
}

impl std::fmt::Debug for App {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "App({})", zbase32_encode(&self.state.meta.app_id))
    }
}

fn corrupt() -> AppError {
    AppError::Store(StoreError::Corrupt)
}

/// The ID of a store's first duty event.
const FIRST_DUTY: u64 = 1;

/// What a restore in place carries of what the app owes its protocol
/// ([`App::kept_for_protocol`]).
#[derive(Default)]
struct Carried {
    /// The store's epoch; `None` for one that didn't read, which a new epoch replaces.
    epoch: Option<state::DutyEpoch>,
    /// The counter the next duty event takes.
    next_duty: u64,
    /// The kept duty events and owed calls that read, by key, as stored.
    values: Vec<(String, serde_json::Value)>,
    /// The kept duty events left behind, their values unreadable.
    lost_duties: u64,
    /// The owed calls left behind, their values unreadable.
    lost_owed: u64,
    /// One past every local ID of an entry stored locally that a carried duty event names.
    stored_past: u64,
    /// The messages whose give-up a kept duty event that reads tells, carried or left
    /// behind for a protocol no longer registered: the store ended their delivery.
    given_up: BTreeSet<String>,
}

/// An owed call both a backup and the store restored in place hold under one key: the
/// store's value, owed to every protocol either names (`to`), in registration order
/// (`names`). The restore puts each protocol's layer back as the backup holds it, so a
/// protocol the backup names that answered the call since is owed it again, its writes
/// gone with the state it had; one only the store names is owed it still. Both values were
/// read whole, each naming registered protocols only.
fn union_owners(
    backup: &serde_json::Value,
    store: &serde_json::Value,
    names: &[String],
) -> Result<serde_json::Value, AppError> {
    let from_backup =
        serde_json::from_value::<feed::Owed>(backup.clone()).map_err(|_| corrupt())?;
    let mut owed = serde_json::from_value::<feed::Owed>(store.clone()).map_err(|_| corrupt())?;
    owed.to = names
        .iter()
        .filter(|name| owed.to.contains(name) || from_backup.to.contains(name))
        .cloned()
        .collect();
    serde_json::to_value(&owed).map_err(|_| corrupt())
}

/// A carried owed call `value`, owed to every protocol of `names`.
fn owed_to_every(
    value: &serde_json::Value,
    names: &[String],
) -> Result<serde_json::Value, AppError> {
    let mut owed = serde_json::from_value::<feed::Owed>(value.clone()).map_err(|_| corrupt())?;
    owed.to = names.to_vec();
    serde_json::to_value(&owed).map_err(|_| corrupt())
}

/// The entry a kept effect belongs to, as a backup holds it: stored as
/// [`ParkReason::Uncertain`], under its local ID if it was stored before (its flags kept),
/// else under `reserved`, the ID the live store reserved for it, built from what the kept
/// effect keeps of it.
fn uncertain_copy(
    state: &AppState,
    pending: &PendingEffect,
    reserved: Option<u64>,
) -> Result<(u64, ParkedEntry), AppError> {
    // An entry stored locally under a kept effect is kept until the effect settles
    // (`STATE.md`, `parked/`), and an entry read from the feed has its ID reserved: either
    // missing is a corrupt store.
    if let Some(id) = pending.stored {
        let stored = state.parked.get(&id).ok_or_else(missing)?;
        return Ok((
            id,
            ParkedEntry {
                reason: ParkReason::Uncertain,
                ..stored.clone()
            },
        ));
    }
    Ok((
        reserved.ok_or_else(missing)?,
        ParkedEntry {
            receipt: pending.entry.receipt,
            seq: pending.seq,
            generation: pending.generation,
            sender: pending.sender,
            cert: pending.entry.cert.clone(),
            accepted_at_ms: pending.accepted_at_ms,
            plaintext: pending.entry.plaintext.clone(),
            reason: ParkReason::Uncertain,
            round: state.parked_round.number,
            released: false,
            keys_at: None,
        },
    ))
}

fn missing() -> AppError {
    AppError::Store(StoreError::Corrupt)
}

/// Refuse a set of protocols that isn't the one the app was set up with (`protos`): one
/// that lacks a protocol the app runs would leave that protocol's state, owed calls and
/// duty events unattended, and one with another protocol would start it without a join.
fn check_protocol_names(stored: &[String], protocols: &ProtocolSet) -> Result<(), AppError> {
    if let Some(name) = stored.iter().find(|name| !protocols.contains(name)) {
        return Err(Refusal::Usage(format!(
            "the app runs the protocol `{name}`, which the set doesn't register"
        ))
        .into());
    }
    if let Some(name) = protocols.names().into_iter().find(|n| !stored.contains(n)) {
        return Err(Refusal::Usage(format!(
            "the set registers the protocol `{name}`, which the app wasn't set up with: a \
             restore adds it"
        ))
        .into());
    }
    Ok(())
}

impl App {
    // ---------------------------------------------------------------------------------
    // Joining, loading and restoring (Switch spec 12.1, 12.4)

    /// Join from an approval (Switch spec 12.1): read the approval by the app's checks
    /// (Switch wire 3.10), keep the keys, scope keys, naming key and certificate, then
    /// deliver the app record and register the first receive key in one batch. The batch
    /// is committed before it is first sent, so a crash resends the same bytes ([`App::load`]
    /// then [`App::receive`] finish it).
    ///
    /// Reading the current shared records before following the feed (Switch spec 12.1 step
    /// 3) is the records layer's; this follows the feed from the registration.
    ///
    /// # Errors
    ///
    /// [`Refusal::Approval`] for an approval that fails a check, or an error from the store
    /// or registration. If the initial commit returns [`StoreError::Unknown`], use
    /// [`App::load`] to learn whether it kept the app. After that commit, load the app and
    /// call [`App::receive`] to resume any unfinished registration.
    pub async fn join(
        mut env: AppEnv,
        protocols: impl Into<ProtocolSet>,
        config: AppConfig,
        request: JoinRequest,
    ) -> Result<App, AppError> {
        Box::pin(async move {
            let clock = env.observe_clock();
            let protocols: ProtocolSet = protocols.into();
            protocols.validate()?;
            own_record::check_publisher(&env, &config)?;
            let read = |has_keys: &dyn Fn(&str) -> bool| {
                Approval::read(
                    &request.approval,
                    &request.request,
                    &request.identity,
                    &request.keys.bundle_secret(),
                    has_keys,
                )
            };
            let approved = match read(&|scope| protocols.has_keys(scope)) {
                Ok(approved) => approved,
                Err(error) => {
                    // An approval whose bundle holds keys of a root no registered protocol
                    // owns reads once those roots are taken as keyed: the set lacks a
                    // protocol, and the refusal names its root.
                    if let Ok(approved) = read(&|scope| {
                        protocols.has_keys(scope) || protocols.of_scope(scope).is_none()
                    }) {
                        protocols.check_cert(&approved.cert)?;
                    }
                    return Err(Refusal::Approval(error.to_string()).into());
                }
            };
            let keys = request.keys;
            let cert = approved.cert;
            // Every scope of the certificate is a registered protocol's, and each protocol
            // runs with it, before anything is written.
            protocols.check_cert(&cert)?;
            protocols.check_own_certificate(&cert)?;
            let doc = approved.identity;
            let now = env.clock.now_ms();
            let inbox = doc.inbox().clone();
            let meta = Meta {
                identity: request.identity,
                app_id: cert.app_id(),
                origin: inbox.url.clone(),
                service_key: inbox.service_key,
                generation: doc.generation(),
            };
            let ns = client_namespace(&meta.app_id);
            let reader = Reader {
                ns: ns.clone(),
                store: env.store.clone(),
            };
            if reader.exists(key::META).await? {
                return Err(Refusal::Usage("the app joined already; load it".into()).into());
            }
            let first = ReceiveKey::generate(0)?;
            let key_record =
                ReceiveKeyRecord::sign(&keys, &cert, ReceiveKeyBody::new(&cert, &first))?;
            let record = next_body::CertBody::first(&cert, protocols.accepts(&cert))
                .sign(&keys, now, None)?;
            let mut client = Self::client_for(&env, &meta, &keys, &cert)?;
            client.follow_own_reads(meta.generation, None, None);
            let batch = client.sign_batch(
                meta.generation,
                vec![
                    (
                        Vec::<Condition>::new(),
                        OpKind::AppPut {
                            record: record.signed().clone(),
                        },
                    ),
                    (
                        Vec::new(),
                        OpKind::ReceiveKeyPut {
                            record: key_record.signed().clone(),
                        },
                    ),
                ],
                None,
            )?;
            let held = HeldKey {
                key: first.clone(),
                record: key_record.signed().clone(),
                reg_seq: None,
                reg_time_ms: None,
                pending: Vec::new(),
            };
            let state = AppState {
                meta: meta.clone(),
                keys: keys.clone(),
                cert: cert.clone(),
                renewal: None,
                record: record.signed().clone(),
                naming: approved.naming_key.clone(),
                scope_keys: approved.keys.clone(),
                bundle: BundleState::default(),
                own_doc: doc.clone(),
                receive_keys: BTreeMap::from([(0, held.clone())]),
                known_kids: BTreeMap::from([(first.kid, 0)]),
                registrations: BTreeMap::new(),
                rotation: Rotation {
                    last_ms: now,
                    opened_since: false,
                },
                device: Device::default(),
                cursor: Cursor {
                    generation: meta.generation,
                    ..Cursor::default()
                },
                chain: None,
                held: BTreeMap::new(),
                deletions: BTreeMap::new(),
                deletion_receipts: BTreeMap::new(),
                put_backs: BTreeMap::new(),
                retries: BTreeMap::new(),
                stored_retries: BTreeMap::new(),
                next_stored_id: FIRST_STORED_ID,
                parked_round: state::ParkedRound::default(),
                seen: BTreeSet::new(),
                asked: BTreeSet::new(),
                parked: BTreeMap::new(),
                departed: BTreeMap::new(),
                join: JoinStep::Registering {
                    body: batch.body().to_vec(),
                },
                pending_effect: None,
                pending_record: None,
                pending_publish: None,
                accepted: None,
                alarm: None,
                restore: None,
                base_unread: None,
                cert_refused: None,
                restore_cursor: None,
                leave: None,
                service_time: None,
                health: health::ServiceHealth::default(),
                display_read: None,
                gone: None,
                next_duty: FIRST_DUTY,
                duty_epoch: state::DutyEpoch::random()?,
                erasing: None,
            };
            let mut app = App {
                env,
                clock,
                protocols,
                config,
                ns,
                state,
                client,
                reload: false,
                save_needs_reload: false,
                service_time_dirty: false,
                alarm_dirty: false,
                pending_health: None,
                unreachable_after_ms: health::DEFAULT_UNREACHABLE_MS,
                identity_confirmed: None,
                directory_asked: Vec::new(),
                directory_failed_ms: None,
                events: Vec::new(),
                owed_known: None,
                told: order::Positions::new(),
                told_kept: order::Positions::new(),
                told_loaded: false,
                walk: None,
                listing_due: records::ListDue::default(),
                pending_calls: Vec::new(),
                owed_held_reads: 0,
                kept_ahead: std::collections::BTreeMap::new(),
                deny_directory_read: None,
                duty_queued: 0,
                duty_handed: 0,
                duty_owners: BTreeMap::new(),
                time_fresh_at: None,
                kept_rate_limited: None,
                loss_upload_wait: None,
                sender_rereads: HashMap::new(),
                published_check: None,
                bundle_asked_ms: None,
                renewal_looked_ms: None,
                next_wait: wait::NextWait::Cursor,
                read_done_ms: None,
                peer_rereads: HashMap::new(),
                reads_begun: 0,
                held_cursor_read: None,
                last_collection_read: None,
                record_page_reader: None,
                held_ahead_told: None,
                listed_before_items: false,
                listing_waits: false,
                listed_every: false,
                reopen_failures: 0,
                retained_floor: None,
                defer_list_step: false,
                read_short: false,
            };
            app.update_keys_through();
            app.events.clear();
            let mut tx = Tx::new(&app.ns);
            tx.put(key::META, &meta)?;
            tx.put(key::PROTOCOLS, &app.protocols.names())?;
            tx.put(key::KEYS, &keys)?;
            tx.put(key::CERT, cert.signed())?;
            tx.put(key::RECORD, record.signed())?;
            tx.put(key::NAMING, &approved.naming_key)?;
            for scope_key in &approved.keys.keys {
                tx.put(
                    &key::scope(scope_key.data_epoch, &scope_key.scope),
                    scope_key,
                )?;
            }
            tx.put(key::BUNDLE, &app.state.bundle)?;
            let taken =
                identity::take_copy(&app.reader(), &mut tx, &doc, None, Default::default()).await?;
            if taken.is_err() {
                return Err(AppError::InvalidData(
                    "Switch spec 4.3: the approval's identity.json equivocates".into(),
                ));
            }
            tx.put(&key::receive_key(0), &held)?;
            tx.put(&key::kid(&first.kid), &KnownKid { n: 0 })?;
            tx.put(key::ROTATION, &app.state.rotation)?;
            tx.put(key::DEVICE, &app.state.device)?;
            tx.put(key::CURSOR, &app.state.cursor)?;
            tx.put(key::JOIN, &app.state.join)?;
            records::owe_listing(&mut tx, &app.protocols.names())?;
            tx.put(key::DUTY_EPOCH, &app.state.duty_epoch)?;
            tx.commit(&app.env.store).await?;
            app.finish_join().await?;
            Ok(app)
        })
        .await
    }

    /// Send the registration batch kept at join until it is answered, then follow the feed
    /// from the registration (Switch spec 8.3, 12.1 step 2).
    async fn finish_join(&mut self) -> Result<(), AppError> {
        let JoinStep::Registering { body } = &self.state.join else {
            return Ok(());
        };
        let batch = Batch::from_body(body.clone())?;
        let submitted = self.submit(&batch).await?;
        let [app_proof, key_proof] = submitted.proofs.as_slice() else {
            return Err(AppError::InvalidData(
                "Switch wire 6.5: the registration's answer carries no proof per operation".into(),
            ));
        };
        let app_env = app_proof.envelope();
        let anchor = app_env.seq.checked_sub(1).ok_or_else(|| {
            AppError::InvalidData("Switch wire 6.6: a registration at seq 0".into())
        })?;
        let mut view = ChainView::anchored(app_env.generation, anchor, app_env.prev_chain_hash);
        let head = submitted.head;
        view.observe_head(head)?;
        if let Some(time) = self.client.last_server_time() {
            view.note_held(head.seq, time);
        }
        let key_seq = key_proof.envelope().seq;
        if let Some(held) = self.state.receive_keys.get_mut(&0) {
            held.reg_seq = Some(key_seq);
            held.reg_time_ms = Some(key_proof.envelope().server_time);
            held.pending.clear();
        }
        self.state.cursor = Cursor {
            generation: app_env.generation,
            seq: anchor,
            at_service: anchor,
            deferred_since_ms: None,
            time_ms: 0,
            sent: 0,
        };
        self.state.join = JoinStep::Done;
        let mut tx = self.tx()?;
        view.write_all(&mut tx)?;
        if let Some(held) = self.state.receive_keys.get(&0) {
            tx.put(&key::receive_key(0), held)?;
        }
        tx.put(key::CURSOR, &self.state.cursor)?;
        tx.put(key::JOIN, &self.state.join)?;
        // The switch holds the record now: an app that publishes owes it to the Homeserver
        // (Switch spec 12.1 step 2).
        let record = renewal::delivered_record(&batch)?;
        self.note_accepted(&record, &mut tx)?;
        self.state.chain = Some(view);
        self.commit(tx).await?;
        self.took_accepted(record);
        self.publish_owed(false, true).await?;
        Ok(())
    }

    /// Load an app from the store alone: nothing is sent. Work left by a crash (a
    /// registration, an effect, a record delivery) resumes at the next network call.
    ///
    /// # Errors
    ///
    /// [`Refusal::NotJoined`] when the store holds no such app, [`Refusal::Left`] once it
    /// deleted its keys, and [`AppError::Store`] for a store failure or a corrupt record.
    pub async fn load(
        mut env: AppEnv,
        protocols: impl Into<ProtocolSet>,
        config: AppConfig,
        app_id: [u8; 16],
    ) -> Result<App, AppError> {
        Box::pin(async move {
            let clock = env.observe_clock();
            let protocols: ProtocolSet = protocols.into();
            protocols.validate()?;
            own_record::check_publisher(&env, &config)?;
            let ns = client_namespace(&app_id);
            let reader = Reader {
                ns: ns.clone(),
                store: env.store.clone(),
            };
            let state = Self::read_state(&reader).await?;
            // The protocols the app was set up with are all registered, and nothing else:
            // a protocol joins an app only at a join or a restore. Refused before anything
            // is written.
            let names: Vec<String> = reader.get(key::PROTOCOLS).await?.ok_or_else(missing)?;
            check_protocol_names(&names, &protocols)?;
            protocols.check_cert(&state.cert)?;
            protocols.check_own_certificate(&state.cert)?;
            let mut client = Self::client_for(&env, &state.meta, &state.keys, &state.cert)?;
            client.follow_own_reads(state.meta.generation, state.health.notice, None);
            display::restore(&client, &state)?;
            let mut app = App {
                env,
                clock,
                protocols,
                config,
                ns,
                state,
                client,
                reload: false,
                save_needs_reload: false,
                service_time_dirty: false,
                alarm_dirty: false,
                pending_health: None,
                unreachable_after_ms: health::DEFAULT_UNREACHABLE_MS,
                identity_confirmed: None,
                directory_asked: Vec::new(),
                directory_failed_ms: None,
                events: Vec::new(),
                owed_known: None,
                told: order::Positions::new(),
                told_kept: order::Positions::new(),
                told_loaded: false,
                walk: None,
                listing_due: records::ListDue::default(),
                pending_calls: Vec::new(),
                owed_held_reads: 0,
                kept_ahead: std::collections::BTreeMap::new(),
                deny_directory_read: None,
                duty_queued: 0,
                duty_handed: 0,
                duty_owners: BTreeMap::new(),
                time_fresh_at: None,
                kept_rate_limited: None,
                loss_upload_wait: None,
                sender_rereads: HashMap::new(),
                published_check: None,
                bundle_asked_ms: None,
                renewal_looked_ms: None,
                next_wait: wait::NextWait::Cursor,
                read_done_ms: None,
                peer_rereads: HashMap::new(),
                reads_begun: 0,
                held_cursor_read: None,
                last_collection_read: None,
                record_page_reader: None,
                held_ahead_told: None,
                listed_before_items: false,
                listing_waits: false,
                listed_every: false,
                reopen_failures: 0,
                retained_floor: None,
                defer_list_step: false,
                read_short: false,
            };
            for observed in app.state.deletions.values() {
                observed.check(&app.protocols, &app.state.meta.identity)?;
            }
            app.validate_waiting_state()?;
            for hold in app.state.put_backs.values() {
                hold.check(&app.protocols, &app.state.meta.identity, &app.state.cert)?;
            }
            // Duty events not acknowledged before are delivered again (`events` module).
            let kept = app.kept_duties_noted().await?;
            app.queue_duties(kept);
            // What an earlier run kept unsigned is that run's: held aside, and told.
            app.hold_earlier_record_edits().await?;
            Ok(app)
        })
        .await
    }

    async fn read_state(reader: &Reader) -> Result<AppState, AppError> {
        let meta: Meta = reader
            .get(key::META)
            .await?
            .ok_or(AppError::Refused(Refusal::NotJoined))?;
        let leave: Option<LeaveState> = reader.get(key::LEAVE).await?;
        if leave.is_some_and(|l| l.keys_deleted_ms.is_some()) {
            return Err(Refusal::Left.into());
        }
        let keys: AppKeys = reader.get(key::KEYS).await?.ok_or_else(missing)?;
        let cert_doc: SignedDoc = reader.get(key::CERT).await?.ok_or_else(missing)?;
        let cert = AppCert::verify(&cert_doc, &meta.identity).map_err(|_| corrupt())?;
        send::validate_outbox(reader, &meta, &cert).await?;
        let renewal = match reader
            .get::<renewal::KeptRenewal<SignedDoc>>(key::CERT_RENEWAL)
            .await?
        {
            None => None,
            Some(kept) => Some(renewal::KeptRenewal {
                cert: AppCert::verify(&kept.cert, &meta.identity).map_err(|_| corrupt())?,
                at: kept.at,
            }),
        };
        let mut scope_keys = ScopeKeys::default();
        for (_, scope_key) in reader.scan::<ScopeKey>("scope/").await? {
            scope_keys.keys.push(scope_key);
        }
        let (own_doc, _) = identity::held_copy(reader, &meta.identity)
            .await?
            .ok_or_else(missing)?;
        let mut known_kids = BTreeMap::new();
        for (rest, known) in reader.scan::<KnownKid>("kid/").await? {
            let kid = pubky_switch_core::enc::unb64_array::<8>(&rest).map_err(|_| corrupt())?;
            known_kids.insert(kid, known.n);
        }
        let mut departed = BTreeMap::new();
        for (rest, at) in reader.scan::<u64>("departed/").await? {
            let app = pubky_switch_core::enc::app_id_decode(&rest).map_err(|_| corrupt())?;
            departed.insert(app, at);
        }
        let parked: BTreeMap<u64, ParkedEntry> = reader.scan_numbered("parked/").await?;
        let next_stored_id = next_stored_id(reader.get::<u64>(key::STORED_NEXT).await?, &parked);
        let health = health::ServiceHealth::read(reader, meta.generation).await?;
        let display_read = display::load(reader, &meta, health.display_id).await?;
        Ok(AppState {
            keys,
            cert,
            renewal,
            record: reader.get(key::RECORD).await?.ok_or_else(missing)?,
            naming: reader.get(key::NAMING).await?.ok_or_else(missing)?,
            scope_keys,
            bundle: reader.get(key::BUNDLE).await?.ok_or_else(missing)?,
            own_doc,
            receive_keys: reader.scan_numbered("rk/").await?,
            known_kids,
            registrations: reader.scan_numbered("reg/").await?,
            rotation: reader.get(key::ROTATION).await?.ok_or_else(missing)?,
            device: reader.get(key::DEVICE).await?.ok_or_else(missing)?,
            cursor: reader.get(key::CURSOR).await?.ok_or_else(missing)?,
            chain: ChainView::load(reader).await?,
            held: reader.scan_numbered("held/").await?,
            deletions: deletion::load(reader).await?,
            deletion_receipts: deletion::load_receipts(reader).await?,
            put_backs: put_back::load(reader).await?,
            retries: reader.scan_numbered("retry/").await?,
            stored_retries: reader.scan_numbered("sretry/").await?,
            next_stored_id,
            parked_round: reader.get(key::PARKED_NEXT).await?.unwrap_or_default(),
            seen: reader.scan_numbers("seen/").await?,
            asked: reader.scan_numbers("asked/").await?,
            parked,
            departed,
            join: reader.get(key::JOIN).await?.ok_or_else(missing)?,
            pending_effect: reader.get(key::PENDING_EFFECT).await?,
            pending_record: reader.get(key::PENDING_RECORD).await?,
            pending_publish: reader.get(key::PENDING_PUBLISH).await?,
            accepted: reader.get(key::ACCEPTED_RECORD).await?,
            alarm: reader.get(key::ALARM).await?,
            restore: reader.get(key::RESTORE).await?,
            base_unread: reader.get(key::RECORD_BASE).await?,
            cert_refused: match reader.get_raw(key::CERT_REFUSED.as_bytes()).await? {
                Some(bytes) => state::decode(&bytes).ok(),
                None => None,
            },
            restore_cursor: reader.get(key::RESTORE_CURSOR).await?,
            leave,
            service_time: reader.get(key::SERVICE_TIME).await?,
            gone: reader.get(provider::keys::GONE).await?,
            health,
            display_read,
            next_duty: Self::next_duty(reader).await?,
            duty_epoch: reader.get(key::DUTY_EPOCH).await?.ok_or_else(missing)?,
            erasing: reader.get(provider::keys::ERASING).await?,
            meta,
        })
    }

    /// The app's backup (Switch spec 12.4): its keys, certificate and record, scope keys
    /// and naming key, its receive keys and the kids it knows, its cursor and chain view,
    /// its outbox, and the re-send and missed-entries calls it owes its protocol
    /// ([`AppBackup`]). The app should take one at every rotation, replacing the previous
    /// one (Switch spec 3.6).
    ///
    /// During provider-loss recovery it keeps the answers committed after the list step,
    /// the protocols that still owe an answer and any pending batch of reply grants.
    /// Use [`App::backup_layered`] to keep the protocols' local writes with their answers.
    ///
    /// The backup takes outbox items oldest first within [`MAX_CARRIED_OUTBOX_BYTES`]
    /// (8 MiB), including messages refused for good. Restore reports each omitted message
    /// ID, as [`AppEvent::DeliveryUnknown`] since the source device may still deliver it,
    /// or [`AppEvent::MessageUndelivered`] with `resend: true` for a re-send of a message it
    /// had accepted. Each carried item keeps its signed
    /// plaintext and any sealed envelope. If the original device delivered it after the
    /// backup, the restored app may send the same `msg_id` and plaintext again. The recipient's
    /// switch answers a retry of the same envelope with its first answer while it holds the
    /// entry (Switch wire 7.4.3 step 1), and the recipient's apps drop a second copy by its
    /// processed pair, kept at least 30 days from the first acceptance plus the clock
    /// tolerance (Switch spec 11). Restore sets a replay deadline on each owed delivery.
    /// A flush that reaches it past that deadline gives it up: the source device may have
    /// delivered it, so a first delivery is told [`AppEvent::DeliveryUnknown`].
    ///
    /// A backup is only ever of committed state. After a failed commit the app's memory may
    /// be ahead of its store, such as a cursor past an entry whose processed pair and local
    /// writes weren't written, until its next call reads the store again: until then this
    /// refuses, since a backup of that memory would restore past an entry never processed.
    ///
    /// # Errors
    ///
    /// [`Refusal::Stopped`] or [`Refusal::Left`] when there is nothing to back up;
    /// [`Refusal::NotNow`] after a failed commit, until the app's next call reads its store
    /// again; a store failure reading the outbox; [`Refusal::DutiesTooLarge`] when the duty
    /// events not acknowledged don't fit the restore's one commit on a new device, and the
    /// store's size refusal ([`AppError::Store`]) when the rest of it doesn't.
    pub async fn backup(&self) -> Result<AppBackup, AppError> {
        if self.state.leave.is_some() {
            return Err(Refusal::Left.into());
        }
        self.require_loaded()?;
        let reader = self.reader();
        // An interrupted feed page may have advanced the cursor in memory before its save.
        let stored;
        let state = if self.reload {
            stored = Self::read_state(&reader).await?;
            &stored
        } else {
            &self.state
        };
        let mut backup = self.backup_of(state, self.highest_service_time())?;
        self.carry_outbox(&reader, state, &mut backup).await?;
        // The restore is built, not committed, as for a layered backup: one that can never
        // be installed is refused now.
        // A protocol may refuse to restore without its layer, its host restoring from a
        // layered backup: the sizes are checked with no layer writes then.
        loop {
            let restorable = Self::restore_commit(
                for_a_check(&self.env),
                self.protocols.clone(),
                self.config.clone(),
                &backup,
                LayerCheck::SizesOnly,
            )
            .await?;
            match restorable {
                // Lists too large to carry never refuse the backup: it carries the deny entries
                // alone, and then none, and the restored app reads them first (Switch spec 7).
                Restorable::TooLarge(_) if !backup.peers.is_empty() => {
                    backup.peers = backup.peers.smaller();
                }
                Restorable::TooLarge(error) => {
                    return Err(self
                        .too_large_for(&backup, LayerCheck::SizesOnly, error)
                        .await?
                        .into_error());
                }
                Restorable::Ready(_, _, marks) => {
                    // The marks that didn't fit the commit the check built are left out: the
                    // rest of the backup takes no room from them (Switch spec 12.4).
                    backup.leave_out_marks(&marks.left);
                    return Ok(backup);
                }
                Restorable::CarriedTooLarge { .. } => return Err(carried_by_a_check()),
            }
        }
    }

    /// Why a backup too large for its restore's one commit is refused: its duty events not
    /// acknowledged, when it fits without them ([`Refusal::DutiesTooLarge`]), else `error`
    /// itself, the store's size refusal.
    async fn too_large_for(
        &self,
        backup: &AppBackup,
        check: LayerCheck,
        error: AppError,
    ) -> Result<TooLargeFor, AppError> {
        if backup.duties.is_empty() {
            return Ok(TooLargeFor::Rest(error));
        }
        let mut without = backup.clone();
        without.duties.clear();
        let restorable = Self::restore_commit(
            for_a_check(&self.env),
            self.protocols.clone(),
            self.config.clone(),
            &without,
            check,
        )
        .await?;
        Ok(match restorable {
            Restorable::Ready(..) => {
                TooLargeFor::Duties(u64::try_from(backup.duties.len()).unwrap_or(u64::MAX))
            }
            Restorable::TooLarge(_) | Restorable::CarriedTooLarge { .. } => {
                TooLargeFor::Rest(error)
            }
        })
    }

    /// The backup of `state`, taken now, recording `taken_service_ms` as the highest verified
    /// service time at backup (Switch spec 8.2, 11).
    fn backup_of(
        &self,
        state: &AppState,
        taken_service_ms: Option<u64>,
    ) -> Result<AppBackup, AppError> {
        if state.leave.is_some() {
            return Err(Refusal::Left.into());
        }
        let chain = state
            .chain
            .as_ref()
            .ok_or_else(|| AppError::Refused(Refusal::NotNow("the app isn't registered".into())))?;
        let (record, at, batches) = chain.export();
        Ok(AppBackup {
            v: SCHEMA_VERSION,
            meta: state.meta.clone(),
            keys: state.keys.clone(),
            cert: state.cert.signed().clone(),
            record: state.record.clone(),
            accepted: state.accepted.clone(),
            naming: state.naming.clone(),
            scope_keys: state.scope_keys.keys.clone(),
            own_doc: state.own_doc.signed().clone(),
            receive_keys: state.receive_keys.values().cloned().collect(),
            known: state
                .known_kids
                .iter()
                .map(|(kid, n)| (pubky_switch_core::enc::b64(kid), *n))
                .collect(),
            rotation: state.rotation,
            device: state.device,
            cursor: state.cursor,
            chain: record,
            chain_at: at
                .into_iter()
                .map(|(seq, hash)| (seq, pubky_switch_core::enc::b64(&hash)))
                .collect(),
            chain_batches: batches
                .into_iter()
                .map(|(id, t)| (pubky_switch_core::enc::b64(&id), t))
                .collect(),
            departed: state
                .departed
                .iter()
                .map(|(app, at)| (zbase32_encode(app), *at))
                .collect(),
            bundle: state.bundle.clone(),
            stored_next: state.next_stored_id,
            waiting: unverified::WaitingOut::of(state),
            deletions: state.deletions.values().cloned().collect(),
            put_backs: state.put_backs.values().cloned().collect(),
            record_settlements: Vec::new(),
            peers: admission::observations::SavedPeers::default(),
            loss_lists: None,
            loss_answers: None,
            finished_list_upload: None,
            duties: Vec::new(),
            duties_left_behind: 0,
            cert_refused: None,
            taken_ms: self.now(),
            taken_service_ms,
            outbox: Vec::new(),
            outbox_left_out: Vec::new(),
            held_counterparties: Vec::new(),
            held_messages: Vec::new(),
            record_expiries: Vec::new(),
            record_members: Vec::new(),
            record_changes: Default::default(),
            layers: Vec::new(),
            beyond_cursor: None,
            owed: Vec::new(),
            seen_marks: Vec::new(),
            seen_marks_incomplete: false,
        })
    }

    /// Put a backup's outbox back, in the restore's commit `tx` (Switch spec 11, 12.4): for
    /// each message the backup carries or the store a restore in place replaces (`live`)
    /// queues, what [`send::restored`] decides from what each holds of it and from whether
    /// its give-up was told: by a duty event the backup carries or the store still owes
    /// (`told`), or by the store's own mark. The record each decision leaves is
    /// [`send::Restored::record`]. A fresh restore holds nothing of any message, so every
    /// record of the backup goes back, held where a delivery is owed.
    ///
    /// In place the store's outbox, sent copies and give-up marks stay as they are
    /// ([`send::KEPT_IN_PLACE`]), so a record that stands costs the commit nothing, and what
    /// the world saw of a message is never undone. A record of the backup that goes back
    /// owed a delivery gets its replay deadline ([`send::OutboxItem::replay_until`]) from the
    /// backup's verified service time, or its device time without one, less the clock
    /// tolerance, and never later than either copy's own. A delivery held here that
    /// neither the backup (`AppBackup::held_messages`) nor the store (`store_held`) held
    /// is counted for its protocols, each told once
    /// ([`AppEvent::MessagesHeldAtRestore`]); the store's own holds stay for the deliveries
    /// still owed. The messages the backup left out, with nothing of them in `live`, are
    /// told to the protocol, in the same commit.
    fn reinstall_outbox(
        &mut self,
        backup: &AppBackup,
        told: &BTreeSet<String>,
        live: &send::LiveOutbox,
        store_held: &BTreeSet<String>,
        tx: &mut Tx,
    ) -> Result<(), AppError> {
        let baseline = backup
            .taken_service_ms
            .unwrap_or(backup.taken_ms)
            .saturating_sub(CLOCK_TOLERANCE_MS);
        // Each give-up the backup tells stays one, so neither `queue_stored` nor a re-send
        // after a loss delivers the message again; the store's own marks stay in place.
        for msg_id in told {
            send::note_given_up(tx, msg_id, self.now())?;
        }
        live.repair(tx, self.now())?;
        // The record the restore decides on for a message is the last the backup lists.
        let carried: BTreeMap<&str, &send::OutboxItem> = backup
            .outbox
            .iter()
            .map(|item| (item.msg_id(), item))
            .collect();
        let mut messages: Vec<(&str, Option<&send::OutboxItem>)> = carried
            .iter()
            .map(|(msg_id, item)| (*msg_id, Some(*item)))
            .collect();
        messages.extend(
            live.items()
                .into_iter()
                .filter(|item| !carried.contains_key(item.msg_id()))
                .map(|item| (item.msg_id(), None)),
        );
        // The deliveries owed once restored, and those newly held per protocol.
        let mut owed = BTreeSet::new();
        let mut held: BTreeMap<String, u64> = BTreeMap::new();
        for (msg_id, carried) in messages {
            let newest = live.item(msg_id);
            let backup_copy = carried.map_or(send::BackupCopy::Nothing, |item| item.backup_copy());
            // A give-up the backup's duty events tell, one the store still owes, or the
            // store's own mark of one: told once, it is never undone.
            let told = told.contains(msg_id) || live.gave_up(msg_id);
            let decision = send::restored(live.copy(msg_id), backup_copy, told);
            let rewrite = decision.record(newest, carried, baseline);
            // The message's record once restored.
            let record = match &rewrite {
                send::Rewrite::Leave => newest,
                send::Rewrite::Put(item) => Some(&**item),
                send::Rewrite::Delete => None,
            };
            if let Some(record) = record.filter(|record| record.delivery_pending()) {
                owed.insert(msg_id);
                // One the store or the backup held already stays held with their other
                // holds, below, and isn't counted again.
                if decision.holds()
                    && !store_held.contains(msg_id)
                    && !backup.held_messages.iter().any(|h| h == msg_id)
                {
                    self.count_held(record, &mut held);
                    send::put_message_hold(tx, msg_id)?;
                }
            }
            match rewrite {
                send::Rewrite::Leave => {}
                send::Rewrite::Put(item) => send::put_outbox_item(tx, &item)?,
                send::Rewrite::Delete => send::delete_outbox_item(tx, msg_id)?,
            }
        }
        // A record of the store the restored app doesn't sign for went with the repair
        // above: its protocol is told what ended with it, unless the backup carries the
        // message, whose record then says what becomes of it.
        for item in live.refused() {
            if !carried.contains_key(item.msg_id()) {
                let to = self.owners_of_kind(item.kind());
                for duty in item.drop_duties() {
                    self.keep_duty_for(tx, to.clone(), duty)?;
                }
            }
        }
        for rest in &backup.held_counterparties {
            let pubky = pubky_switch_core::enc::unb64_array::<32>(rest)
                .map_err(|_| AppError::InvalidData("a backup's held counterparty".into()))?;
            send::put_hold(tx, &pubky)?;
        }
        // The store's holds of the deliveries still owed: a hold lasts as long as its
        // delivery, and the restore's wipe took the marks.
        for msg_id in store_held {
            if owed.contains(msg_id.as_str()) {
                send::put_message_hold(tx, msg_id)?;
            }
        }
        // Each held message is one of the outbox the backup carries, its delivery owed: no
        // writer carries the hold of another.
        for msg_id in &backup.held_messages {
            // A message the backup left out past its budget isn't one it carries.
            if !carried
                .get(msg_id.as_str())
                .is_some_and(|item| item.delivery_pending())
                || backup
                    .outbox_left_out
                    .iter()
                    .any(|(left, _)| left == msg_id)
            {
                return Err(AppError::InvalidData(
                    "a backup's held message isn't one of its outbox owed a delivery".into(),
                ));
            }
            if owed.contains(msg_id.as_str()) {
                send::put_message_hold(tx, msg_id)?;
            }
        }
        // The device the backup came from still holds each message it left out, and may
        // deliver it: only one it had accepted is known delivered (Switch spec 11). One the
        // store holds anything of goes by that, above.
        for (msg_id, resend) in &backup.outbox_left_out {
            if told.contains(msg_id) || live.knows(msg_id) {
                continue;
            }
            let msg_id = msg_id.clone();
            let duty = if *resend {
                events::Duty::MessageUndelivered {
                    msg_id,
                    resend: true,
                }
            } else {
                events::Duty::DeliveryUnknown { msg_id }
            };
            self.keep_duty(tx, duty)?;
        }
        for (protocol, held) in held {
            self.keep_duty_for(
                tx,
                vec![protocol.clone()],
                events::Duty::MessagesHeldAtRestore { protocol, held },
            )?;
        }
        Ok(())
    }

    /// Count `item` held for each protocol its kind's events go to.
    fn count_held(&self, item: &send::OutboxItem, held: &mut BTreeMap<String, u64>) {
        for owner in self.owners_of_kind(item.kind()) {
            let n = held.entry(owner).or_insert(0);
            *n = n.saturating_add(1);
        }
    }

    /// Put the outbox in `backup`, as `reader` holds it (Switch spec 11): every message the
    /// app still owes a job, so a restore delivers what was queued before the backup with
    /// the same `msg_id` and bytes.
    /// The expiries the protocols asked of the record go with it.
    async fn carry_outbox(
        &self,
        reader: &Reader,
        state: &AppState,
        backup: &mut AppBackup,
    ) -> Result<(), AppError> {
        send::validate_outbox(reader, &state.meta, &state.cert).await?;
        backup.waiting.notices = unverified::waiting_notices(reader).await?;
        backup.record_settlements = put_back::settlements(reader).await?;
        backup.peers = admission::observations::SavedPeers::collect(
            state,
            reader,
            FeedPosition {
                generation: backup.cursor.generation,
                seq: backup.cursor.seq,
            },
        )
        .await?;
        backup.loss_lists = recovery::lists::SavedLists::read(reader).await?;
        backup.loss_answers = reader
            .get(recovery::keys::LOSS)
            .await?
            .and_then(recovery::answers::SavedAnswers::capture);
        backup.finished_list_upload = reader.get(recovery::lists::FINISHED).await?;
        // Every duty event goes, but those that report the installation's own standing: a
        // duty can't be rebuilt from the service, so none is left out for room; a backup
        // they don't fit is refused, naming them (`Refusal::DutiesTooLarge`). One that
        // doesn't read is counted, as a restore in place counts it; an unreadable drop
        // notice refused the backup above, with the custody it reports.
        for (_, value) in reader.scan_raw(key::DUTY_PREFIX).await? {
            match state::decode::<events::KeptDuty>(&value) {
                Ok(kept) if kept.duty.backup_carries() => backup.duties.push(kept),
                Ok(_) => {}
                Err(_) => backup.duties_left_behind = backup.duties_left_behind.saturating_add(1),
            }
        }
        backup.cert_refused = reader.get(key::CERT_REFUSED).await?;
        let carried = send::carried_outbox(reader).await?;
        backup.held_messages = send::held_messages_of(reader, self.now())
            .await?
            .into_iter()
            .map(|(msg_id, _)| msg_id)
            .filter(|msg_id| carried.items.iter().any(|item| item.msg_id() == msg_id))
            .collect();
        backup.outbox = carried.items;
        backup.outbox_left_out = carried.left_out;
        backup.held_counterparties = reader
            .scan_raw(send::HOLD_PREFIX)
            .await?
            .into_iter()
            .map(|(rest, _)| rest)
            .collect();
        let (edits, expiries) = self.carried_record_edits().await?;
        backup.record_expiries = expiries.into_iter().collect();
        backup.record_members = edits.members.into_iter().collect();
        backup.record_changes = edits.changes;
        // The owed re-send and missed-entries calls, as stored, each with its owners. One
        // that doesn't read as a call fails every read of this store already; it isn't a
        // call to carry.
        backup.owed = reader
            .scan_raw(key::OWED_PREFIX)
            .await?
            .into_iter()
            .filter_map(|(rest, bytes)| {
                let owed = state::decode::<feed::Owed>(&bytes).ok()?;
                let carried = matches!(
                    owed.call,
                    feed::OwedCall::Resend { .. } | feed::OwedCall::Missed { .. }
                );
                let value = state::decode::<serde_json::Value>(&bytes).ok()?;
                carried.then_some((rest, value))
            })
            .collect();
        // The marks, which the backup's check leaves out of where they don't fit.
        (backup.seen_marks, backup.seen_marks_incomplete) = seen_marks::carry(reader).await?;
        Ok(())
    }

    /// The app's backup with one layer per protocol (Switch spec 12.4), the layers taken
    /// by the app itself, so they are always of the same moment as the rest. In this one
    /// call, which holds the app exclusively so no other call writes its store meanwhile,
    /// the app reads from its store: its committed state (never memory that a failed commit
    /// left ahead of the store), each protocol's whole local state, which its
    /// [`Protocol::backup_layer`] turns into its layer's bytes under its
    /// [`Protocol::name`], and what the feed holds beyond the cursor that the layers may
    /// reflect: the entries processed past a held one, the entries stored locally, and
    /// the processed pairs, so a restore hands none of those messages to the protocol
    /// again. It carries the outbox of the same moment, as [`App::backup`] does.
    /// [`App::restore`] installs it all in one commit.
    ///
    /// The restore of the backup is built, without writing anything, before it is
    /// returned: [`Protocol::restore_layer`] checks the layer, and the one commit that would
    /// install it must fit the store's sizes ([`crate::store::MAX_VALUE_BYTES`] for each
    /// value, [`crate::store::MAX_BATCH_BYTES`], 32 MiB, for the whole).
    ///
    /// That commit holds, beside the app's own state and the layer, every entry stored
    /// locally and every processed pair the app keeps (for 30 days plus the clock
    /// tolerance). While they add up to more than the batch size, every layered backup is
    /// refused, with [`AppEvent::BackupRefused`] for the host, until they drain: entries
    /// stored locally as they are processed, processed pairs as they age out. It applies the
    /// shared sender/key/admission bounds first, as a read does (Switch spec 8.2), even
    /// while an alarm stops intake. Pending and independently uncertain inputs stay
    /// protected. The backup carries retained waiting payloads and their owed drop
    /// notices. It needs a writable store, and drops remain committed if the backup is
    /// then refused; local bookkeeping never clears the alarm.
    ///
    /// It makes no network call. A kept effect isn't settled first, and a restore never
    /// carries one: the backup holds the effect's entry as what it is once the effect is
    /// gone, one whose effect's fate is unknown, stored as [`ParkReason::Uncertain`] (its
    /// flags, such as a release, kept) with the processed pair of its message, an entry read
    /// from the feed included. The restored app's bounds never drop it and its host may
    /// release it. Its read passes the feed entry, whose `seq` the backup's `seen` holds,
    /// with no event and no second application; the processed pair still catches a re-send
    /// of the message at a new `seq` within 30 days.
    /// The live store keeps the kept effect, which the app's next read settles. An entry
    /// read from the feed takes a local ID the live store reserves for it first, by moving
    /// its stored-entry counter on (`parkid`), on a halted app too: the backup's counter is
    /// one past it, and the live store never gives that ID to another entry, which a restore
    /// in place would install the copy over. The counter is the one write of its own; its
    /// commit also keeps a service time verified earlier and not yet committed, as every
    /// commit does. Neither changes anything a read or the protocol sees.
    ///
    /// The restored app tells its protocol of the copy as stored `Uncertain`
    /// ([`AppEvent::Parked`]), but not which of the kept batch's attempts are uncertain, as
    /// [`AppEvent::EffectUncertain`] would: the restore's reconcile mode covers that, since
    /// the protocol makes no new attempt until it has reconciled from the claims.
    ///
    /// # Errors
    ///
    /// [`Refusal::Left`] or [`Refusal::NotNow`] when there is nothing to back up; a store failure; as
    /// [`App::restore`] for a backup it would refuse, such as a layer the protocol refuses
    /// ([`AppError::InvalidData`]) or one over the store's sizes ([`AppError::Store`], with
    /// [`AppEvent::BackupRefused`]); [`Refusal::DutiesTooLarge`], with that event, when the
    /// duty events not acknowledged are what doesn't fit.
    pub async fn backup_layered(&mut self) -> Result<AppBackup, AppError> {
        Box::pin(async move {
            // Local waiting bounds precede backup, including while an alarm stops intake
            // (Switch spec 8.2). The common commit preserves the alarm.
            self.ready_local().await?;
            self.bound_unverified().await?;
            // The local ID the copy of a kept effect's feed entry takes is reserved in the
            // live store first, for a halted app too (its commit also keeps a service
            // time not yet committed), which changes
            // nothing a read or the protocol sees. Without it, the next entry the
            // live store stored would take the same ID, and a restore in place would install
            // the copy under an ID its carried duty events give another message.
            let reserved = if self
                .state
                .pending_effect
                .as_ref()
                .is_some_and(|pending| pending.stored.is_none())
            {
                let mut tx = self.tx()?;
                let id = self.new_stored_id(&mut tx)?;
                self.commit(tx).await?;
                Some(id)
            } else {
                None
            };
            let reader = self.reader();
            let state = Self::read_state(&reader).await?;
            // Carry the live verified high-water time rather than the stored snapshot's older
            // `service_time`, matching the waiting bounds enforced above.
            let mut backup = self.backup_of(&state, self.highest_service_time())?;
            self.carry_outbox(&reader, &state, &mut backup).await?;
            let mut processed = reader.scan::<Processed>("proc/").await?;
            let waiting_ids: BTreeSet<u64> =
                backup.waiting.entries.iter().map(|(id, _)| *id).collect();
            let mut parked: BTreeMap<_, _> = state
                .parked
                .iter()
                .filter(|(id, _)| !waiting_ids.contains(id))
                .map(|(id, entry)| (*id, entry.clone()))
                .collect();
            let mut seen = state.seen.clone();
            if let Some(pending) = &state.pending_effect {
                // A restore never carries a kept effect, so the backup holds its entry as
                // what it is once the effect is gone: one whose effect's fate is unknown,
                // stored as `Uncertain` with the processed pair of its message, as the app
                // itself stores it when it can't tell (`feed.rs`, `park_uncertain`). The
                // bounds never drop it and the host may release it. A read passes its feed
                // entry (its `seq` is put in `seen` below), with no event and no second
                // application; the processed pair still catches a re-send at a new `seq`
                // within 30 days. The live store isn't touched.
                let (id, entry) = uncertain_copy(&state, pending, reserved)?;
                parked.insert(id, entry);
                // Its feed `seq` is passed, as the app passes it when it stores an entry: the
                // processed pair ages out after 30 days, and a restore from an older backup
                // must still never hand the entry over again unless the host releases the
                // stored copy. An entry stored before was passed when it was stored.
                if pending.stored.is_none() {
                    seen.insert(pending.seq);
                }
                let pair = key::processed(&pending.sender, &pending.msg_id);
                let rest = pair.strip_prefix("proc/").unwrap_or(&pair).to_owned();
                processed.retain(|(held, _)| *held != rest);
                processed.push((
                    rest,
                    Processed {
                        kind: pending.kind.clone(),
                        hash: pending.hash,
                        at_ms: self.now(),
                    },
                ));
            }
            // One layer per protocol, each over its own local state, read in this call.
            for registered in self.protocols.iter() {
                let local = self.protocol_scan(&registered.name, b"").await?;
                let data = registered.protocol.backup_layer(local).map_err(|why| {
                    AppError::InvalidData(format!(
                        "the backup layer of `{}`: {why}",
                        registered.name
                    ))
                })?;
                backup.layers.push(LayerOut {
                    name: registered.name.clone(),
                    data: pubky_switch_core::enc::b64(&data),
                    deletions: state
                        .deletion_receipts
                        .values()
                        .filter(|r| r.owner == registered.name)
                        .cloned()
                        .collect(),
                });
            }
            backup.beyond_cursor = Some(BeyondCursor {
                protocols: self.protocols.names(),
                missed: reader
                    .scan::<bool>("asked/")
                    .await?
                    .into_iter()
                    .filter(|(_, missed)| *missed)
                    .map(|(rest, _)| state::parse_num(&rest))
                    .collect::<Result<_, _>>()?,
                held_gap: reader.get(held_cursor::GAP_HANDED).await?,
                seen: seen.into_iter().collect(),
                parked: parked.into_iter().collect(),
                processed,
            });
            // The restore is built, not committed, so a layer the protocol refuses, or one
            // over the store's sizes, is refused now rather than at a restore that can
            // never succeed. What this store would carry beside it at a restore in place
            // doesn't refuse the backup, which fits on its own: that restore is refused
            // until the host acknowledges, or restores onto an empty store.
            loop {
                let restorable = Self::restore_commit(
                    for_a_check(&self.env),
                    self.protocols.clone(),
                    self.config.clone(),
                    &backup,
                    LayerCheck::Full,
                )
                .await?;
                match restorable {
                    // As for a plain backup, lists too large to carry are left out.
                    Restorable::TooLarge(_) if !backup.peers.is_empty() => {
                        backup.peers = backup.peers.smaller();
                    }
                    Restorable::TooLarge(error) => {
                        let refused = self.too_large_for(&backup, LayerCheck::Full, error).await?;
                        self.events.push(AppEvent::BackupRefused {
                            reason: refused.reason(),
                        });
                        return Err(refused.into_error());
                    }
                    Restorable::Ready(_, _, marks) => {
                        // The marks that didn't fit the commit the check built are left out: the
                        // rest of the backup takes no room from them (Switch spec 12.4).
                        backup.leave_out_marks(&marks.left);
                        return Ok(backup);
                    }
                    Restorable::CarriedTooLarge { .. } => return Err(carried_by_a_check()),
                }
            }
        })
        .await
    }

    /// Restore from a backup (Switch spec 12.4) into the store, replacing whatever the store
    /// holds for the app. The host asked the user first whether the device the backup came
    /// from is still in the user's hands; for a lost or stolen one it revokes the app and
    /// joins a new one instead.
    ///
    /// The app enters reconcile mode. At its next call it takes the certificate its current
    /// `identity.json` lists, read with its own record from the directory, if the backup
    /// predates a renewal, another device's included, checks its receive key
    /// record, registers a fresh key if it rotated after the backup, and asks the user
    /// about registrations it can't account for ([`App::restore_question`]).
    ///
    /// The host calls [`App::refresh_identity`] after the restore and before the first
    /// [`App::receive`]: only a page read once the newest `identity.json` is confirmed
    /// settles the restore's held cursor ([`App::restore_held_cursor`]).
    ///
    /// The backup's outbox goes back in with the same `msg_id` and bytes, each message owed
    /// a delivery held ([`App::hold_message`]): the protocol state the backup brings back
    /// may no longer want it, so each protocol with messages held is told once
    /// ([`AppEvent::MessagesHeldAtRestore`]) and, after its own read of the shared state,
    /// releases ([`App::release_message`]) or withdraws ([`App::withdraw_message`]) each.
    /// Nothing held is delivered until then. Onto the store of the same installation, that
    /// store's outbox, sent copies and give-up marks stay as they are, and each message is
    /// decided from both sides (`STATE.md`, "A restore decides on each message"): a
    /// delivery both that store and the backup still owed goes by the next flush as before;
    /// one only that store owed, such as a message queued or a re-send asked after the
    /// backup, stays and is held; one whose delivery that store ended isn't delivered, held
    /// or told again, and keeps only an owed record job.
    /// Past [`SENT_RETENTION_MS`] from the backup, a delivery still owed, held or not, is
    /// given up, with [`AppEvent::DeliveryUnknown`] ([`App::backup`]).
    ///
    /// The protocols' layers ([`App::backup_layered`]) are installed with the app's own
    /// state, and with the entries and processed pairs of the same moment that the backup
    /// carries beside them, in one commit: the app checks its own state, that every scope
    /// of the certificate is a registered protocol's and each protocol runs with it
    /// ([`Protocol::check_own_certificate`]), that each layer names a registered protocol,
    /// and that a layered snapshot's original protocol roster matches its layers and
    /// processed owners, before any restore callback. It then has each registered
    /// protocol's [`Protocol::restore_layer`] check its own layer, or `None` for a newly
    /// registered protocol or a plain backup, with the backup's identity and `blind`
    /// under its naming key ([`RestoreContext`]), and give its writes, which land under its
    /// own prefix, all before it writes anything. The app keeps the names it registers
    /// (`protos`) for later loads. One commit installs every layer. If it returns
    /// [`StoreError::Unknown`], the host loads the app ([`App::load`]) to learn whether
    /// the restore was installed. A read failure after installation leaves the layers in place.
    ///
    /// What the store holds that the app still owes its protocols stays, a layered
    /// restore's included, for the protocols it registers: the duty events not
    /// acknowledged, with their IDs, delivered again as after [`App::load`], and the
    /// protocol calls they couldn't answer, made again by the next read. One owed to none
    /// of them is left behind and counted in [`AppEvent::RestoreLeftBehind`]. Carried
    /// notices, including a refused provider-loss callback's local writes, get new IDs
    /// on a store without an epoch, which starts a fresh event epoch ([`EventId`]).
    /// Every restore takes the re-send
    /// and missed-entries calls the backup carries ([`App::backup`]), each checked as a
    /// carried call is and kept for the protocols it registers, one that isn't whole or is
    /// owed to none of them left behind and counted in [`AppEvent::RestoreLeftBehind`]. A
    /// call the store made after the backup is made again: the restore replaces each
    /// protocol's state with its layer, or with none, which lacks its writes. A restore in
    /// place adds the store's own calls, the store's value winning for a key both hold. For
    /// an app holding `lists.read`, the commit also owes every protocol a deny list gap at
    /// the backup's position, whatever the backup held, told by the next read with the
    /// full list ([`Protocol::deny_list_gap`], Switch spec 8.3).
    ///
    /// # Errors
    ///
    /// [`AppError::InvalidData`] for a backup that doesn't verify, for a layer of a protocol
    /// not registered, or for one its protocol refuses; [`Refusal::Usage`] for a certificate
    /// holding a scope root no registered protocol owns; [`Refusal::Certificate`] for one a
    /// protocol refuses; [`Refusal::CarriedTooLarge`] for a restore in place whose backup fits one
    /// commit on its own, built onto an empty store, but not with what the store holds of the
    /// earlier installation beside it;
    /// [`Refusal::Usage`] for an app that publishes its record without a Homeserver writer
    /// ([`AppEnv::homeserver_writer`]); a store failure, writes over the store's sizes
    /// included. Validation and size refusals leave the store as it was.
    pub async fn restore(
        env: AppEnv,
        protocols: impl Into<ProtocolSet>,
        config: AppConfig,
        backup: &AppBackup,
    ) -> Result<App, AppError> {
        Box::pin(async move {
            let protocols: ProtocolSet = protocols.into();
            protocols.validate()?;
            let again = (env.clone(), protocols.clone(), config.clone());
            match Self::restore_commit(env, protocols, config, backup, LayerCheck::Install).await? {
                Restorable::Ready(app, tx, marks) => {
                    let (app, marks) = match tx.commit(&app.env.store).await {
                        Ok(()) => (app, marks),
                        // Out of space with the marks: the restore is taken once more without
                        // them, as it was before backups carried marks, the marks then
                        // incomplete (Switch spec 12.4).
                        Err(AppError::Store(StoreError::Full)) if !backup.seen_marks.is_empty() => {
                            let mut without = backup.clone();
                            without.seen_marks.clear();
                            without.seen_marks_incomplete = true;
                            let (env, protocols, config) = again;
                            let Restorable::Ready(app, tx, marks) = Self::restore_commit(
                                env,
                                protocols,
                                config,
                                &without,
                                LayerCheck::Install,
                            )
                            .await?
                            else {
                                return Err(AppError::Store(StoreError::Full));
                            };
                            tx.commit(&app.env.store).await?;
                            (app, marks)
                        }
                        Err(error) => return Err(error),
                    };
                    let mut app = *app;
                    // Committed: a failure here leaves the rest to the next read.
                    let _ = app.retell_restored().await;
                    let kept = app.kept_duties_noted().await?;
                    app.queue_duties(kept);
                    // Marks left out: each protocol is told once (Switch spec 12.4).
                    if marks.incomplete {
                        for protocol in app.protocols.names() {
                            app.events.push(AppEvent::SeenMarksIncomplete { protocol });
                        }
                    }
                    Ok(app)
                }
                Restorable::TooLarge(error) => Err(error),
                Restorable::CarriedTooLarge {
                    duty_events,
                    owed_calls,
                } => Err(Refusal::CarriedTooLarge {
                    duty_events,
                    owed_calls,
                }
                .into()),
            }
        })
        .await
    }

    /// The app a backup restores and the one commit that installs it, checked and built
    /// within the store's sizes; nothing is written.
    async fn restore_commit(
        mut env: AppEnv,
        protocols: ProtocolSet,
        config: AppConfig,
        backup: &AppBackup,
        layer_check: LayerCheck,
    ) -> Result<Restorable, AppError> {
        Box::pin(async move {
            let clock = env.observe_clock();
            // As at a join and a load: an app that publishes needs its writer.
            own_record::check_publisher(&env, &config)?;
            // An install too large for its one commit is told apart by the same backup built
            // onto an empty store, which carries nothing of an earlier installation.
            let alone = (layer_check == LayerCheck::Install)
                .then(|| (on_empty_store(&env), protocols.clone(), config.clone()));
            let meta = backup.meta.clone();
            let invalid = |why: &str| AppError::InvalidData(format!("the backup: {why}"));
            let cert = AppCert::verify(&backup.cert, &meta.identity)
                .map_err(|_| invalid("its certificate doesn't verify"))?;
            if cert.app_id() != meta.app_id || cert.signing_key() != backup.keys.signing_public() {
                return Err(invalid("its certificate isn't its keys'"));
            }
            let mut carried_ids = BTreeSet::new();
            for item in &backup.outbox {
                if !carried_ids.insert(item.msg_id()) || !item.is_own(&meta, &cert) {
                    return Err(invalid(
                        "its outbox identity or signed message is inconsistent",
                    ));
                }
                if !item.has_valid_deadline() {
                    return Err(invalid(
                        "its attempted outbox item is missing a replay deadline",
                    ));
                }
            }
            let mut omitted_ids = BTreeSet::new();
            for (msg_id, _) in &backup.outbox_left_out {
                if carried_ids.contains(msg_id.as_str()) || !omitted_ids.insert(msg_id) {
                    return Err(invalid(
                        "its outbox identities are both carried and omitted or repeated",
                    ));
                }
            }
            // Each duty it carries is one a backup carries, for owners named once each, and a
            // message it gives up isn't one it left out, which the restore tells instead. A
            // give-up told twice is no fault: delivery is at least once.
            for kept in &backup.duties {
                if !kept.duty.backup_carries() {
                    return Err(invalid("it carries a duty event of the installation's own"));
                }
                let mut owners = BTreeSet::new();
                if kept.to.is_empty() || !kept.to.iter().all(|name| owners.insert(name)) {
                    return Err(invalid(
                        "a duty event it carries names no owner, or one twice",
                    ));
                }
                // The restore gives out no local ID a carried duty names: the last ID has
                // none past it.
                if kept.duty.stored_id() == Some(u64::MAX) {
                    return Err(invalid("a duty event it carries names the last local ID"));
                }
                if let Some(msg_id) = kept.duty.given_up()
                    && backup
                        .outbox_left_out
                        .iter()
                        .any(|(left, _)| left == msg_id)
                {
                    return Err(invalid("a message it gives up is also one it left out"));
                }
            }
            // The app record the restore installs carries that very certificate, so what the
            // protocol checks below is all that is installed: the app writes the two
            // together, at a join and when it takes a certificate, so they never differ in a
            // backup it took.
            let record = AppRecord::verify(&backup.record, &meta.identity)
                .map_err(|_| invalid("its app record doesn't verify"))?;
            if record.cert().hash() != cert.hash() {
                return Err(invalid("its app record carries another certificate"));
            }
            // The newest record the switch accepted is the app's own, signed with its key.
            if let Some(accepted) = &backup.accepted {
                let accepted = AppRecord::verify(accepted, &meta.identity)
                    .map_err(|_| invalid("its accepted app record doesn't verify"))?;
                if accepted.cert().app_id() != meta.app_id
                    || accepted.cert().signing_key() != backup.keys.signing_public()
                {
                    return Err(invalid("its accepted app record isn't its keys'"));
                }
            }
            let own_doc = IdentityDoc::verify(&backup.own_doc, &meta.identity)
                .map_err(|_| invalid("its identity.json doesn't verify"))?;
            if backup
                .cert_refused
                .as_deref()
                .is_some_and(|hash| pubky_switch_core::enc::unb64_array::<32>(hash).is_err())
            {
                return Err(invalid("its refused certificate isn't a certificate hash"));
            }
            if backup
                .finished_list_upload
                .is_some_and(|end| end > meta.generation || own_doc.body().recovery_from.is_none())
            {
                return Err(invalid(
                    "its completed list upload is ahead of its provider",
                ));
            }
            if let Some(saved) = &backup.loss_lists {
                saved.check(backup, &own_doc)?;
            }
            if let Some(answers) = &backup.loss_answers {
                answers.check(backup, &own_doc, &cert, &protocols)?;
            }
            let mut at = BTreeMap::new();
            for (seq, hash) in &backup.chain_at {
                at.insert(
                    *seq,
                    pubky_switch_core::enc::unb64_array::<32>(hash)
                        .map_err(|_| invalid("chain"))?,
                );
            }
            let mut batches = BTreeMap::new();
            for (id, time) in &backup.chain_batches {
                batches.insert(
                    pubky_switch_core::enc::unb64_array::<16>(id).map_err(|_| invalid("chain"))?,
                    *time,
                );
            }
            let mut chain = ChainView::import(backup.chain.clone(), at, batches)?;
            // The cursor moves made after the backup are lost with it: missing stubs aren't a
            // rollback until the service holds a cursor this app moved and it read after that.
            chain.restore = Some(RestorePending::Cursor);
            let mut known_kids = BTreeMap::new();
            for (kid, n) in &backup.known {
                known_kids.insert(
                    pubky_switch_core::enc::unb64_array::<8>(kid).map_err(|_| invalid("kids"))?,
                    *n,
                );
            }
            let mut departed = BTreeMap::new();
            for (app, time) in &backup.departed {
                departed.insert(
                    pubky_switch_core::enc::app_id_decode(app)
                        .map_err(|_| invalid("departures"))?,
                    *time,
                );
            }
            let receive_keys: BTreeMap<u64, HeldKey> = backup
                .receive_keys
                .iter()
                .map(|held| (held.key.n, held.clone()))
                .collect();
            let n_floor = receive_keys.keys().next_back().copied().unwrap_or(0);
            let mut cursor = backup.cursor;
            // The service may hold a later cursor: the first move after the restore is sent.
            cursor.at_service = 0;
            cursor.deferred_since_ms = Some(env.clock.now_ms());
            // Every scope of the certificate is a registered protocol's, and each protocol
            // runs with it, before anything is written.
            protocols.check_cert(&cert)?;
            protocols.check_own_certificate(&cert)?;
            // The layers, checked before anything is written: a layer of a protocol not
            // registered here refuses the restore, rather than drop that data, and so does
            // a layer its protocol refuses. A registered protocol without a layer is handed
            // none.
            let layers = backup.layers()?;
            if let Some(layer) = layers.iter().find(|l| !protocols.contains(&l.protocol)) {
                return Err(invalid(&format!(
                    "its layer of `{}` is of no registered protocol",
                    layer.protocol
                )));
            }
            // So is an expiry of the record a protocol not registered here asked for.
            if let Some((name, _)) = backup
                .record_expiries
                .iter()
                .find(|(name, _)| !protocols.contains(name))
            {
                return Err(invalid(&format!(
                    "its record expiry of `{name}` is of no registered protocol"
                )));
            }
            let mut expiry_owners = std::collections::BTreeSet::new();
            if backup
                .record_expiries
                .iter()
                .any(|(name, expiry)| !expiry.valid() || !expiry_owners.insert(name))
            {
                return Err(invalid(
                    "its record expiry policies are invalid or repeated",
                ));
            }
            let pending = record_members::RecordEdits {
                members: backup.record_members.iter().cloned().collect(),
                changes: backup.record_changes.clone(),
            };
            let pending_members = &pending.members;
            if pending_members.len() != backup.record_members.len()
                || pending_members
                    .keys()
                    .any(|name| !expiry_owners.contains(name))
            {
                return Err(invalid(
                    "its pending record members are repeated or lack an expiry",
                ));
            }
            record_members::check_carried(&pending, &protocols)
                .map_err(|_| invalid("its pending record members are invalid or too large"))?;
            // The backup's unsigned edits are held aside, never pending: no restore signs
            // one, and its protocol decides (`App::held_record_edit`). The policies go in as
            // the backup's signed record has them.
            let carried: own_record::RecordExpiries =
                backup.record_expiries.iter().cloned().collect();
            let mut held_edits = record_members::HeldEdits::default();
            pending.hold(&carried, &mut held_edits);
            // The unsigned edits the restore can't hold aside, and leaves behind.
            let mut edits_left_behind = 0u64;
            let mut expiries = pending.without(carried);
            if !layers.is_empty() && backup.beyond_cursor.is_none() {
                return Err(invalid(
                    "its layers come without the feed beyond its cursor",
                ));
            }
            if let Some(beyond) = &backup.beyond_cursor {
                // Seen marks can outlive processed pairs. The whole original roster,
                // rather than just kinds still held in `proc/`, binds this progress to
                // its layers. An empty layer still has an entry; a new registration has
                // neither an original layer nor original progress (Switch spec 12.4).
                let owners: BTreeSet<_> = beyond.protocols.iter().collect();
                if owners.is_empty()
                    || owners.len() != beyond.protocols.len()
                    || owners.len() != layers.len()
                    || layers.iter().any(|layer| !owners.contains(&layer.protocol))
                    || beyond.processed.iter().any(|(_, pair)| {
                        protocols
                            .of_kind(&pair.kind)
                            .is_some_and(|owner| !owners.contains(&owner.name))
                    })
                {
                    return Err(invalid("its feed progress and protocol layers disagree"));
                }
            }
            backup.waiting.validate(backup, &protocols)?;
            seen_marks::check(&backup.seen_marks)?;
            let ns = client_namespace(&meta.app_id);
            // A restore in place keeps the store's event epoch and counter, and what the store
            // holds of what the app still owes its protocol: the duty events not
            // acknowledged and the calls the protocol couldn't answer. A store with no epoch,
            // on another device or wiped, starts a new epoch at the first counter. A store
            // that can't be read fails the restore (`STATE.md`, "What the app owes its
            // protocol").
            // A backup's own check is given an empty store ([`on_empty_store`]): a backup
            // must install on a new device, its carried duty events and all (Switch spec
            // 12.4). What a store would carry beside it in place is that restore's own
            // refusal ([`Refusal::CarriedTooLarge`]).
            let old = Reader {
                ns: ns.clone(),
                store: env.store.clone(),
            };
            let installation = old
                .get::<Meta>(key::META)
                .await?
                .filter(|m| m.identity == meta.identity && m.app_id == meta.app_id);
            let same_installation = installation.is_some();
            let mut finished_list_upload = backup.finished_list_upload;
            // The store's mark of a refused renewal, read as it is: one that doesn't read
            // names nothing, and the backup's stands; a read that meets the renewal again
            // refuses it again and tells it.
            let live_refused = match old.get_raw(key::CERT_REFUSED.as_bytes()).await? {
                Some(bytes) => state::decode::<String>(&bytes).ok(),
                None => None,
            };
            let cert_refused = match live_refused {
                Some(live) if same_installation => Some(live),
                _ => backup.cert_refused.clone(),
            };
            let mut newer_held = None;
            if same_installation {
                if let Some(live) = old.get(recovery::keys::LOSS).await? {
                    recovery::answers::SavedAnswers::check_destination(&live, backup, &own_doc)?;
                }
                finished_list_upload = recovery::lists::SavedLists::check_destination(
                    &old,
                    backup.loss_lists.as_ref(),
                    meta.generation,
                    backup.finished_list_upload,
                )
                .await?;
                // The store's own unsigned edits, those it held aside already and those
                // its last run kept, are later than the backup's: held aside over them. One
                // that doesn't read is left behind and counted, never the restore's error.
                let live = match old.get_raw(key::RECORD_MEMBERS.as_bytes()).await? {
                    None => record_members::RecordEdits::default(),
                    Some(bytes) => state::decode(&bytes).unwrap_or_else(|_| {
                        edits_left_behind = edits_left_behind.saturating_add(1);
                        record_members::RecordEdits::default()
                    }),
                };
                // The store's expiry policies: the asks of its unsigned edits, and the
                // policies its own record was signed with. Policies that don't read leave
                // both unknown, so neither is kept: its edits are left behind, and its
                // record isn't taken over the backup's.
                let live_expiries = match old.get_raw(key::RECORD_EXPIRIES.as_bytes()).await? {
                    None => Some(own_record::RecordExpiries::default()),
                    Some(bytes) => state::decode::<own_record::RecordExpiries>(&bytes).ok(),
                };
                let (held_before, unread) =
                    record_members::HeldEdits::read(&old, &protocols).await?;
                edits_left_behind = edits_left_behind.saturating_add(unread);
                held_edits.members.extend(held_before.members);
                held_edits.accepts = held_before.accepts.or(held_edits.accepts.take());
                match &live_expiries {
                    Some(live_expiries) => live.hold(live_expiries, &mut held_edits),
                    None => {
                        let edits =
                            live.members.len() + usize::from(live.changes.accepts.is_some());
                        let edits = u64::try_from(edits).unwrap_or(u64::MAX);
                        edits_left_behind =
                            edits_left_behind.saturating_add(edits).saturating_add(1);
                    }
                }
                // The base a later record builds on: the store's own held record when it is
                // newer than the backup's under the same certificate (the later `updated_at`
                // wins, Switch spec 4.2), with the expiry policies it was signed with; the
                // published one is read before any record is signed. One that doesn't read
                // is left behind and counted: the first read takes what the switch holds.
                let live_record = match old.get_raw(key::RECORD.as_bytes()).await? {
                    None => None,
                    Some(bytes) => {
                        let held = state::decode::<SignedDoc>(&bytes).ok().and_then(|signed| {
                            AppRecord::verify(&signed, &meta.identity)
                                .ok()
                                .map(|held| (signed, held))
                        });
                        if held.is_none() {
                            edits_left_behind = edits_left_behind.saturating_add(1);
                        }
                        held
                    }
                };
                if let (Some((signed, held)), Some(live_expiries)) = (live_record, live_expiries)
                    && held.cert().hash() == cert.hash()
                    && held.updated_at() > record.updated_at()
                {
                    expiries = live.without(live_expiries);
                    newer_held = Some(signed);
                }
            }
            // Only what a registered protocol can read and decide is kept; the rest is
            // left behind, and counted.
            let (held_edits, unfit) = held_edits.fit(&protocols);
            let edits_left_behind = edits_left_behind.saturating_add(unfit);
            expiries.retain(|name, policy| protocols.contains(name) && policy.valid());
            let mut deletions = deletion::restore(
                &old,
                &backup.deletions,
                &protocols,
                same_installation,
                &own_doc,
            )
            .await?;
            let deletion_receipts = deletion::layer_receipts(&backup.layers, &mut deletions)?;
            let previous = same_installation.then_some(&old);
            let previous_health = if installation.is_some_and(|live| {
                live.generation == meta.generation
                    && live.service_key == meta.service_key
                    && live.origin == meta.origin
            }) {
                health::ServiceHealth::read(&old, meta.generation).await?
            } else {
                health::ServiceHealth::default()
            };
            let put_backs = put_back::restore(
                previous,
                &backup.put_backs,
                &protocols,
                &backup.meta,
                &cert,
                &own_doc,
                &layers,
            )
            .await?;
            let mut carried = Self::kept_for_protocol(&old, &protocols)
                .await?
                .unwrap_or_default();
            // Each protocol checks its layer against the identity's naming key, the one the
            // restored app goes on with, before anything is written; its writes land under
            // its own prefix.
            let mut layer_writes = Vec::new();
            for registered in protocols.iter() {
                let mut restoring =
                    RestoreContext::new(meta.identity, meta.app_id, &backup.naming, &cert);
                if same_installation && layer_check == LayerCheck::Install {
                    restoring.previous = Some(context::PreviousInstallation {
                        local: LocalView::new(
                            meta.identity,
                            meta.app_id,
                            env.store.store().as_ref(),
                            &ns,
                            &registered.name,
                        ),
                        protocols: &protocols,
                    });
                }
                let layer = layers.iter().find(|l| l.protocol == registered.name);
                match registered.protocol.restore_layer(layer, &restoring) {
                    Ok(writes) => layer_writes.extend(protocols::qualify(&registered.name, writes)),
                    Err(_) if layer_check == LayerCheck::SizesOnly => {}
                    Err(why) => {
                        return Err(AppError::InvalidData(format!(
                            "the backup layer of `{}`: {why}",
                            registered.name
                        )));
                    }
                }
            }
            let (mut seen, mut parked, processed) = match &backup.beyond_cursor {
                Some(layer) => (
                    layer.seen.iter().copied().collect::<BTreeSet<u64>>(),
                    layer.parked.iter().cloned().collect::<BTreeMap<_, _>>(),
                    layer
                        .processed
                        .iter()
                        .map(|(rest, record)| {
                            let (sender, msg_id) = rest
                                .split_once('/')
                                .filter(|(_, msg_id)| !msg_id.is_empty())
                                .ok_or_else(|| invalid("processed pairs"))?;
                            let sender = pubky_switch_core::enc::pubky_key(sender)
                                .map_err(|_| invalid("processed pairs"))?;
                            pubky_switch_core::message::check_kind(&record.kind)
                                .map_err(|_| invalid("processed message kind"))?;
                            Ok((sender, msg_id.to_owned(), record.clone()))
                        })
                        .collect::<Result<Vec<_>, AppError>>()?,
                ),
                None => (BTreeSet::new(), BTreeMap::new(), Vec::new()),
            };
            for (id, entry) in &backup.waiting.entries {
                parked.insert(*id, entry.clone());
                if entry.generation == backup.cursor.generation {
                    seen.insert(entry.seq);
                }
            }
            for notice in &backup.waiting.notices {
                if let events::Duty::StoredEntryDropped {
                    seq, generation, ..
                } = &notice.duty
                    && *generation == backup.cursor.generation
                {
                    seen.insert(*seq);
                }
            }
            // An entry the cursor passed needs no mark.
            let seen: BTreeSet<u64> = seen
                .into_iter()
                .filter(|seq| *seq > backup.cursor.seq)
                .collect();
            let state = AppState {
                meta: meta.clone(),
                keys: backup.keys.clone(),
                cert: cert.clone(),
                renewal: None,
                record: newer_held.unwrap_or_else(|| backup.record.clone()),
                naming: backup.naming.clone(),
                scope_keys: ScopeKeys {
                    keys: backup.scope_keys.clone(),
                },
                // A full-bundle request the backup holds may have been answered and its
                // parts read and dropped since, by the device it came from, leaving the
                // feed only stubs: the restore drops it, so the first read fetches and asks
                // once if a key is still missing. A repeated request keeps the service's
                // first time while it is pending, so a restore adds one request at most
                // (Switch wire 7.4.11).
                bundle: BundleState {
                    full_requested_ms: None,
                    ..backup.bundle.clone()
                },
                own_doc: own_doc.clone(),
                receive_keys,
                known_kids,
                registrations: BTreeMap::new(),
                rotation: backup.rotation,
                device: backup.device,
                cursor,
                chain: Some(chain),
                held: backup.waiting.held.iter().copied().collect(),
                deletions,
                deletion_receipts,
                put_backs,
                retries: backup.waiting.feed_retries.iter().copied().collect(),
                stored_retries: backup.waiting.retries.iter().copied().collect(),
                next_stored_id: next_stored_id(None, &parked),
                parked_round: backup.waiting.round,
                seen,
                asked: backup
                    .beyond_cursor
                    .iter()
                    .flat_map(|layer| layer.missed.iter().copied())
                    .collect(),
                parked,
                departed,
                join: JoinStep::Done,
                pending_effect: None,
                pending_record: None,
                pending_publish: None,
                // The newest record the switch accepted, as the backup carries it apart from
                // the record held, which may be one whose `app.put` was refused or never
                // answered: repair of the accepted one waits for newer local intent to
                // settle, and never overwrites a later Homeserver copy (Switch spec 4.2).
                // The record held goes to the switch again
                // only with the next change the protocol makes (`own_record.rs`).
                accepted: backup.accepted.clone(),
                alarm: None,
                restore: Some(RestoreState {
                    n_floor,
                    key_checked: false,
                    own_key_n: None,
                    reconcile: true,
                    key_current: None,
                    held_taken: false,
                }),
                base_unread: None,
                cert_refused: cert_refused.clone(),
                // Checked at the first page after the restore, against the backup's
                // committed position (Switch spec 12.4 "The held cursor").
                restore_cursor: Some(held_cursor::RestoreCursor {
                    generation: backup.cursor.generation,
                    seq: backup.cursor.seq,
                    restored_at_ms: env.clock.now_ms(),
                    verdict: None,
                }),
                leave: None,
                service_time: None,
                health: previous_health,
                display_read: if previous_health.display_id.is_some() {
                    display::load(&old, &meta, previous_health.display_id).await?
                } else {
                    None
                },
                gone: None,
                next_duty: FIRST_DUTY,
                duty_epoch: state::DutyEpoch::random()?,
                erasing: None,
            };
            // Every restore takes the backup's owed calls, each checked as a carried one is
            // and keeping only the protocols registered here; one that isn't whole, or is
            // owed to none of them, is left behind and counted. The restore replaces each
            // protocol's local state with its layer, or with nothing, so a call the store
            // made after the backup is owed again: its writes are gone with that state. A
            // restore in place also carries the store's own calls; for a key both hold, the
            // missed notices follow the layer's completed effects and each recipient's
            // original read. Other calls keep the union of the two owner sets.
            let from_backup = Self::owed_of_backup(backup, &protocols);
            let mut waiting_notices = Vec::new();
            for notice in &backup.waiting.notices {
                unverified::merge_notice(&mut waiting_notices, notice.clone())?;
            }
            // The store's duty events the backup carries too, by stored key: the backup's own,
            // not counted as what the store adds beside it.
            let mut shared_duties = BTreeSet::new();
            // The store's owed calls the restore doesn't owe again, by stored key.
            let mut dropped_owed = BTreeSet::new();
            // An identical notice keeps every outstanding owner from both snapshots.
            for (key, value) in &mut carried.values {
                if !key.starts_with(key::DUTY_PREFIX) {
                    continue;
                }
                let mut held: events::KeptDuty =
                    serde_json::from_value(value.clone()).map_err(|_| corrupt())?;
                if !matches!(held.duty, events::Duty::StoredEntryDropped { .. }) {
                    continue;
                }
                let id = unverified::notice_id(&held.duty)?;
                if let Some(index) = waiting_notices.iter().position(|notice| {
                    unverified::notice_id(&notice.duty).is_ok_and(|other| other == id)
                }) {
                    let notice = waiting_notices.remove(index);
                    let mut joined = vec![held];
                    unverified::merge_notice(&mut joined, notice)?;
                    held = joined.remove(0);
                    *value = serde_json::to_value(held).map_err(|_| corrupt())?;
                    shared_duties.insert(key.clone());
                }
            }
            // A restore in place keeps the store's holds beside the backup's: a hold the host
            // set after the backup still holds (`App::hold_queued`).
            let old_holds: Vec<String> = old
                .scan_raw(send::HOLD_PREFIX)
                .await?
                .into_iter()
                .map(|(rest, _)| rest)
                .collect();
            // What the store restored in place holds of its messages, which stays as it is:
            // the restore decides on each message from it (Switch spec 12.4). A fresh
            // restore holds nothing of any, and holds every delivery it puts back.
            let live_outbox = if same_installation {
                send::LiveOutbox::read(&old, &meta, &cert).await?
            } else {
                send::LiveOutbox::default()
            };
            // The store's message holds, kept for the deliveries the restored outbox owes.
            let store_held: BTreeSet<String> = send::held_messages_of(&old, env.clock.now_ms())
                .await?
                .into_iter()
                .map(|(msg_id, _)| msg_id)
                .collect();
            // No local ID is given out twice: past the backup's counter, the counter of the
            // store restored in place, every ID a carried duty event names, and every entry
            // the backup brings back.
            let old_next = Self::stored_next_of(&old).await?;
            let duties_past = backup
                .duties
                .iter()
                .filter_map(|kept| kept.duty.stored_id())
                .map(|id| id.saturating_add(1))
                .max()
                .unwrap_or(0);
            let next_stored_id = state
                .next_stored_id
                .max(backup.stored_next)
                .max(old_next)
                .max(carried.stored_past)
                .max(duties_past);
            let state = AppState {
                duty_epoch: carried.epoch.unwrap_or(state.duty_epoch),
                next_duty: carried.next_duty.max(FIRST_DUTY),
                next_stored_id,
                ..state
            };
            let mut client = Self::client_for(&env, &meta, &backup.keys, &cert)?;
            client.follow_own_reads(meta.generation, state.health.notice, None);
            let protocols_names = protocols.names();
            display::restore(&client, &state)?;
            let mut app = App {
                env,
                clock,
                protocols,
                config,
                ns,
                state,
                client,
                reload: false,
                save_needs_reload: false,
                service_time_dirty: false,
                alarm_dirty: false,
                pending_health: None,
                unreachable_after_ms: health::DEFAULT_UNREACHABLE_MS,
                identity_confirmed: None,
                directory_asked: Vec::new(),
                directory_failed_ms: None,
                events: Vec::new(),
                owed_known: None,
                told: order::Positions::new(),
                told_kept: order::Positions::new(),
                told_loaded: false,
                walk: None,
                listing_due: records::ListDue::default(),
                pending_calls: Vec::new(),
                owed_held_reads: 0,
                kept_ahead: std::collections::BTreeMap::new(),
                deny_directory_read: None,
                duty_queued: 0,
                duty_handed: 0,
                duty_owners: BTreeMap::new(),
                time_fresh_at: None,
                kept_rate_limited: None,
                loss_upload_wait: None,
                sender_rereads: HashMap::new(),
                published_check: None,
                bundle_asked_ms: None,
                renewal_looked_ms: None,
                next_wait: wait::NextWait::Cursor,
                read_done_ms: None,
                peer_rereads: HashMap::new(),
                reads_begun: 0,
                held_cursor_read: None,
                last_collection_read: None,
                record_page_reader: None,
                held_ahead_told: None,
                listed_before_items: false,
                listing_waits: false,
                listed_every: false,
                reopen_failures: 0,
                retained_floor: None,
                defer_list_step: false,
                read_short: false,
            };
            // The backup's duty events, each for the protocols registered here; one for none of
            // them is left behind, and counted (Switch spec 12.4 "Notices owed to the
            // protocol"). Each is matched against the store's before anything is written, so
            // what the store adds beside the backup is known wherever a write over the sizes
            // stops the build.
            let mut backup_notices = Vec::new();
            let mut duties_left_behind = backup.duties_left_behind;
            for kept in &backup.duties {
                let mut kept = kept.clone();
                kept.to.retain(|name| app.protocols.contains(name));
                if kept.to.is_empty() {
                    duties_left_behind = duties_left_behind.saturating_add(1);
                    continue;
                }
                kept.check_owners(&app.protocols)?;
                backup_notices.push(kept);
            }
            // The store's duty events, each read once and keyed by what it says: a backup's
            // copy of one of them is looked up, not searched for.
            let mut held_duties = std::collections::HashMap::new();
            for (index, (key, value)) in carried.values.iter().enumerate() {
                if key.starts_with(key::DUTY_PREFIX)
                    && let Ok(held) = serde_json::from_value::<events::KeptDuty>(value.clone())
                {
                    let said = serde_json::to_string(&held.duty).map_err(|_| corrupt())?;
                    held_duties.entry(said).or_insert((index, held));
                }
            }
            // The store restored in place holds the same event: one copy, owed to the owners
            // of both, since the layers go back to the backup's, before any acknowledgement
            // the store took since.
            let mut join_held =
                |notice: &events::KeptDuty, carried: &mut Carried| -> Result<bool, AppError> {
                    let said = serde_json::to_string(&notice.duty).map_err(|_| corrupt())?;
                    let Some((index, held)) = held_duties.get_mut(&said) else {
                        return Ok(false);
                    };
                    held.to = protocols_names
                        .iter()
                        .filter(|name| held.to.contains(name) || notice.to.contains(name))
                        .cloned()
                        .collect();
                    let value = serde_json::to_value(&*held).map_err(|_| corrupt())?;
                    if let Some((stored, slot)) = carried.values.get_mut(*index) {
                        *slot = value;
                        shared_duties.insert(stored.clone());
                    }
                    Ok(true)
                };
            let mut own_notices = Vec::new();
            for notice in &backup_notices {
                if !join_held(notice, &mut carried)? {
                    own_notices.push(notice.clone());
                }
            }
            // Each missed-entries call the store owes, as the restore owes it again or not,
            // also worked out before anything is written: one owed no more is nothing the
            // store adds, wherever the build stops.
            let mut missed_again = std::collections::HashMap::new();
            for (stored, value) in &carried.values {
                let Some(rest) = stored.strip_prefix(key::OWED_PREFIX) else {
                    continue;
                };
                let live: feed::Owed =
                    serde_json::from_value(value.clone()).map_err(|_| corrupt())?;
                if !matches!(live.call, feed::OwedCall::Missed { .. }) {
                    continue;
                }
                let place = live.check_place(rest)?;
                let original = from_backup
                    .0
                    .iter()
                    .find_map(|(key, kept)| (key == stored).then_some(kept))
                    .cloned()
                    .map(serde_json::from_value::<feed::Owed>)
                    .transpose()
                    .map_err(|_| corrupt())?;
                let again = app.restore_missed(backup, place, original.as_ref(), &live);
                if again.is_none() {
                    dropped_owed.insert(stored.clone());
                }
                missed_again.insert(stored.clone(), (place, original, again));
            }
            // Every write of the one commit; what fails here is mostly a write the store
            // can't take in one batch, over its sizes.
            // A deny the store holds is kept beside the backup's on a restore in place, so a
            // deny made after the backup still wins locally before the next list read (Switch
            // spec 7, 12.4). Only the installation itself takes them: a backup's own checks
            // build its restore onto an empty store.
            let mut held_denies = Vec::new();
            if same_installation && layer_check == LayerCheck::Install {
                for (id, _) in app.reader().scan_raw("lc/deny/").await? {
                    pubky_switch_core::enc::pubky_key(&id).map_err(|_| corrupt())?;
                    held_denies.push(id);
                }
            }
            let mut marks = seen_marks::Installed::default();
            let mut tx = Tx::new(&app.ns);
            let built: Result<(), AppError> = async {
                // In place, the delivery state stays: what the world saw of a message is
                // no state a backup takes back (Switch spec 12.4). Onto any other store it
                // goes with the rest. Both wipes are the same writes but the last, so a
                // backup whose own check fits, built onto an empty store, fits in place.
                tx.delete_all_but(&send::KEPT_IN_PLACE)?;
                if !same_installation {
                    tx.delete_prefixes(&send::KEPT_IN_PLACE)?;
                }
                // The certificate refused goes with its carried duty event, so a read that
                // finds it again refuses it with no second event; the store's own, newer in
                // place, wins.
                if let Some(hash) = cert_refused.as_ref() {
                    tx.put(key::CERT_REFUSED, hash)?;
                }
                if let Some(generation) = finished_list_upload {
                    tx.put(recovery::lists::FINISHED, &generation)?;
                }
                if let Some(saved) = &backup.loss_lists {
                    saved.restore(&mut tx)?;
                }
                if let Some(answers) = &backup.loss_answers {
                    tx.put(recovery::keys::LOSS, answers.loss())?;
                }
                // Age and capacity selection use the backup's verified observation, never
                // the restoring device's clock. Selection joins the installation commit.
                let drops = app.waiting_drops_at(None, backup.taken_service_ms);
                let change = app.waiting_change(None, None, &drops)?;
                change.stage(&mut app, &mut tx)?;
                app.restore_record_settlements(&backup.record_settlements, previous, &mut tx)
                    .await?;
                app.write_all(&mut tx).await?;
                backup.peers.install(&mut tx, backup.meta.generation)?;
                // The host is told what the restore brought back unverified, and what the
                // backup left out, until it acknowledges (Switch spec 7, 12.4): one of the
                // backup's own writes, so its size is the backup's.
                let (kept, replies) = backup.peers.unverified_counts();
                let left_out = backup.peers.left_out();
                if kept > 0 || replies > 0 || left_out != ListsLeftOut::Nothing {
                    app.keep_duty(
                        &mut tx,
                        events::Duty::ListsUnverified {
                            kept,
                            replies,
                            contributed: false,
                            left_out,
                        },
                    )?;
                }
                let mut held_gap = backup
                    .beyond_cursor
                    .as_ref()
                    .and_then(|layer| layer.held_gap);
                for notice in &own_notices {
                    app.keep_duty_for(&mut tx, notice.to.clone(), notice.duty.clone())?;
                }
                // The waits the restored holds re-offer, once their settlements are restored,
                // which can end a hold: each joins the store's copy as the backup's do. A hold
                // of an earlier generation can only end, so its wait isn't told again.
                let mut protocol_notices = Vec::new();
                for hold in app
                    .state
                    .put_backs
                    .values()
                    .filter(|h| h.waited && !app.can_only_end(h))
                {
                    // The protocol's local preparation may have been acknowledged after
                    // this backup, or left behind with a layer. Reoffer the same delete.
                    let notice = events::KeptDuty {
                        to: vec![hold.observation.owner.clone()],
                        duty: events::Duty::PutBackWaits {
                            key: hold.observation.key,
                            delete: hold.observation.delete,
                        },
                    };
                    if !backup_notices.contains(&notice) && !protocol_notices.contains(&notice) {
                        protocol_notices.push(notice);
                    }
                }
                for notice in &protocol_notices {
                    notice.check_owners(&app.protocols)?;
                    if !join_held(notice, &mut carried)? {
                        app.keep_duty_for(&mut tx, notice.to.clone(), notice.duty.clone())?;
                    }
                }
                for notice in &waiting_notices {
                    app.keep_duty_for(&mut tx, notice.to.clone(), notice.duty.clone())?;
                }
                for (sender, msg_id, record) in &processed {
                    feed::processed_writes(
                        &mut tx,
                        sender,
                        msg_id,
                        &record.kind,
                        record.hash,
                        record.at_ms,
                    )?;
                }
                records::owe_listing(&mut tx, &protocols_names)?;
                // The entries it brings back are told to the protocol again, in steps after
                // the restore commits (Switch spec 12.4).
                parked::Retell::start(&app.state, &mut tx)?;
                // The give-ups the store restored in place still tells, and those the backup
                // carries as duty events: such a message isn't delivered or told again.
                let mut told = carried.given_up.clone();
                told.extend(
                    backup
                        .duties
                        .iter()
                        .filter_map(|kept| kept.duty.given_up().map(str::to_owned)),
                );
                app.reinstall_outbox(backup, &told, &live_outbox, &store_held, &mut tx)?;
                // One the backup holds too is put back with its outbox.
                for rest in old_holds
                    .iter()
                    .filter(|rest| !backup.held_counterparties.contains(rest))
                {
                    if let Ok(pubky) = pubky_switch_core::enc::unb64_array::<32>(rest) {
                        send::put_hold(&mut tx, &pubky)?;
                    }
                }
                tx.local(&layer_writes)?;
                tx.put(key::PROTOCOLS, &protocols_names)?;
                if !expiries.is_empty() {
                    tx.put(key::RECORD_EXPIRIES, &expiries)?;
                }
                // The store is written anew: every held edit goes back, once, and all are
                // told in one event, in place of what the store told of them before.
                held_edits.put(&mut tx)?;
                app.tell_held_record_edits(&mut tx, &held_edits)?;
                // Each protocol's layer is its state as committed when the backup was taken,
                // which may lack a deny list change or gap it was owed then: a backup
                // carries no deny list call and no gap, and the feed doesn't hand again what
                // the backup's cursor passed. So every restore by an app holding
                // `lists.read` notes a gap in the deny list's history at the restored
                // cursor, owed to every protocol, in this commit, and each is told the full
                // list after the carried calls (Switch spec 8.3). The namespace's delete
                // above takes the `dgap` the store held, so no earlier gap moves it.
                if app.state.cert.has_permission(Permission::ListsRead) {
                    tx.put(
                        feed::DENY_GAP,
                        &feed::OwedGap {
                            generation: backup.cursor.generation,
                            seq: backup.cursor.seq,
                            to: protocols_names.clone(),
                        },
                    )?;
                }
                tx.put(key::DUTY_NEXT, &app.state.next_duty)?;
                tx.put(key::DUTY_EPOCH, &app.state.duty_epoch)?;
                let current_sequence = app.state.own_doc.body().recovery_from.unwrap_or(0);
                let mut retain_gap = |generation: u64, held: Option<u64>| {
                    if generation > current_sequence
                        && let Some(held) = held
                    {
                        let previous = held_gap
                            .filter(|(sequence, _)| *sequence == current_sequence)
                            .map_or(0, |(_, seq)| seq);
                        held_gap = Some((current_sequence, previous.max(held)));
                    }
                };
                for (stored, value) in &from_backup.0 {
                    let (generation, seq) = feed::owed_place(
                        stored.strip_prefix(key::OWED_PREFIX).ok_or_else(corrupt)?,
                    )?;
                    let owed: feed::Owed =
                        serde_json::from_value(value.clone()).map_err(|_| corrupt())?;
                    retain_gap(generation, owed.call.held_gap(seq));
                    tx.put(stored, value)?;
                }
                for id in held_denies
                    .iter()
                    .filter(|id| backup.peers.denies().binary_search(id).is_err())
                {
                    tx.put_raw(&format!("lc/deny/{id}"), Vec::new())?;
                }
                for (stored, value) in &carried.values {
                    // Written once: a key the backup carried with the same value is in.
                    let in_backup = from_backup
                        .0
                        .iter()
                        .find_map(|(key, kept)| (key == stored).then_some(kept));
                    if let Some((place, original, again)) = missed_again.get(stored) {
                        if let Some(owed) = again {
                            retain_gap(place.0, owed.call.held_gap(place.1));
                            // The backup's identical call is written already.
                            if original.as_ref() != Some(owed) {
                                tx.put(stored, owed)?;
                            }
                        }
                        continue;
                    }
                    match in_backup {
                        Some(kept) if kept == value => {}
                        Some(kept) => {
                            tx.put(stored, &union_owners(kept, value, &protocols_names)?)?;
                        }
                        // A call only the store holds, past the backup's cursor, came after
                        // the backup: every layer is put back to a moment before it, so a
                        // protocol that took it lost its writes with that state and is owed
                        // it again. Every registered protocol is (Switch spec 8.3).
                        None if app.owed_after(stored, backup.cursor) => {
                            tx.put(stored, &owed_to_every(value, &protocols_names)?)?;
                        }
                        None => tx.put(stored, value)?,
                    }
                }
                if let Some(gap) = held_gap {
                    tx.put(held_cursor::GAP_HANDED, &gap)?;
                }
                // What didn't read is left behind, and the protocol told how much.
                let lost_owed = carried.lost_owed.saturating_add(from_backup.1);
                // In place the store counts what didn't read in it, which the backup counted
                // too when it came from that store: the larger count, never both.
                let lost_duties = if same_installation {
                    carried.lost_duties.max(duties_left_behind)
                } else {
                    carried.lost_duties.saturating_add(duties_left_behind)
                };
                if lost_duties > 0 || lost_owed > 0 || edits_left_behind > 0 {
                    app.keep_duty(
                        &mut tx,
                        events::Duty::RestoreLeftBehind {
                            duty_events: lost_duties,
                            owed_calls: lost_owed,
                            record_edits: edits_left_behind,
                        },
                    )?;
                }
                // Last, in the room the rest leaves: the backup's marks, in place of the store's
                // own, which the namespace's delete above took (Switch spec 12.4).
                let ns = app.ns.clone();
                let left = seen_marks::write(&ns, &mut tx, &backup.seen_marks)?;
                marks = seen_marks::Installed {
                    incomplete: backup.seen_marks_incomplete || !left.is_empty(),
                    left,
                };
                Ok(())
            }
            .await;
            match built {
                Ok(()) => Ok(Restorable::Ready(Box::new(app), tx, marks)),
                // Over the sizes: the backup's own refusal, unless the backup fits on its own,
                // built onto an empty store as its check builds it. Then what this store holds
                // of an earlier installation beside it is what doesn't fit, whatever the order
                // of the writes.
                Err(error @ AppError::Store(StoreError::TooLarge { .. })) => {
                    let Some((empty, protocols, config)) = alone else {
                        return restore_build_error(error);
                    };
                    // One that fails there for any reason doesn't fit on its own.
                    let on_its_own =
                        Self::restore_commit(empty, protocols, config, backup, LayerCheck::Full)
                            .await;
                    if !matches!(on_its_own, Ok(Restorable::Ready(..))) {
                        return restore_build_error(error);
                    }
                    // What the store adds beside the backup: its duty events and owed calls
                    // the backup doesn't carry itself.
                    let count = |prefix: &str| {
                        let n = carried
                            .values
                            .iter()
                            .filter(|(stored, _)| {
                                stored.starts_with(prefix)
                                    && !shared_duties.contains(stored)
                                    && !dropped_owed.contains(stored)
                                    && !from_backup.0.iter().any(|(key, _)| key == stored)
                            })
                            .count();
                        u64::try_from(n).unwrap_or(u64::MAX)
                    };
                    Ok(Restorable::CarriedTooLarge {
                        duty_events: count(key::DUTY_PREFIX),
                        owed_calls: count(key::OWED_PREFIX),
                    })
                }
                Err(error) => restore_build_error(error),
            }
        })
        .await
    }

    /// Every record of the state, after a full delete of the namespace in the same commit.
    async fn write_all(&mut self, tx: &mut Tx) -> Result<(), AppError> {
        let s = &mut self.state;
        tx.put(key::META, &s.meta)?;
        s.health.write(tx)?;
        if let Some(read) = &s.display_read {
            tx.put(display::PENDING, read)?;
        }
        tx.put(key::KEYS, &s.keys)?;
        tx.put(key::CERT, s.cert.signed())?;
        tx.put(key::RECORD, &s.record)?;
        if let Some(accepted) = &s.accepted {
            tx.put(key::ACCEPTED_RECORD, accepted)?;
        }
        tx.put(key::NAMING, &s.naming)?;
        for scope_key in &s.scope_keys.keys {
            tx.put(
                &key::scope(scope_key.data_epoch, &scope_key.scope),
                scope_key,
            )?;
        }
        tx.put(key::BUNDLE, &s.bundle)?;
        let doc = s.own_doc.clone();
        tx.put(
            &key::ident_doc(&s.meta.identity),
            &CachedDoc {
                doc: doc.signed().clone(),
                reads: Default::default(),
            },
        )?;
        tx.put(
            &key::ident_floor(&s.meta.identity),
            &state::Floor {
                version: doc.version(),
                generation: doc.generation(),
            },
        )?;
        tx.put(
            &key::ident_body(&s.meta.identity, doc.version()),
            &pubky_switch_core::enc::b64(&doc.body_hash()),
        )?;
        for (n, held) in &s.receive_keys {
            tx.put(&key::receive_key(*n), held)?;
        }
        for (kid, n) in &s.known_kids {
            tx.put(&key::kid(kid), &KnownKid { n: *n })?;
        }
        tx.put(key::ROTATION, &s.rotation)?;
        tx.put(key::DEVICE, &s.device)?;
        tx.put(key::CURSOR, &s.cursor)?;
        for (app, at) in &s.departed {
            tx.put(&key::departed(app), at)?;
        }
        for seq in &s.asked {
            tx.put(&key::asked(*seq), &true)?;
        }
        for seq in &s.seen {
            tx.put(&key::seen(*seq), &())?;
        }
        for (id, parked) in &s.parked {
            tx.put(&key::parked(*id), parked)?;
        }
        for observed in s.deletions.values() {
            tx.put(&observed.store_key(), observed)?;
        }
        for receipt in s.deletion_receipts.values() {
            tx.put(&receipt.store_key(), receipt)?;
        }
        for hold in s.put_backs.values() {
            tx.put(&hold.store_key(), hold)?;
        }
        for (seq, held) in &s.held {
            tx.put(&key::held(*seq), held)?;
        }
        for (seq, retry) in &s.retries {
            tx.put(&key::retry(*seq), retry)?;
        }
        for (id, retry) in &s.stored_retries {
            tx.put(&key::stored_retry(*id), retry)?;
        }
        tx.put(key::PARKED_NEXT, &s.parked_round)?;
        tx.put(key::STORED_NEXT, &s.next_stored_id)?;
        tx.put(key::JOIN, &s.join)?;
        if let Some(check) = &s.restore_cursor {
            tx.put(key::RESTORE_CURSOR, check)?;
        }
        if let Some(restore) = &s.restore {
            tx.put(key::RESTORE, restore)?;
        }
        if let Some(chain) = s.chain.as_mut() {
            chain.write_all(tx)?;
        }
        Ok(())
    }

    // ---------------------------------------------------------------------------------
    // Accessors

    /// The App ID.
    pub fn app_id(&self) -> [u8; 16] {
        self.state.meta.app_id
    }

    /// The identity.
    pub fn identity(&self) -> [u8; 32] {
        self.state.meta.identity
    }

    /// The certificate the app presents.
    pub fn cert(&self) -> &AppCert {
        &self.state.cert
    }

    /// The app's signed record, as the service holds it or is being delivered.
    pub fn record(&self) -> &SignedDoc {
        &self.state.record
    }

    /// The newest own `identity.json` held.
    pub fn own_identity(&self) -> &IdentityDoc {
        &self.state.own_doc
    }

    /// The data epoch of the newest own `identity.json`.
    pub fn data_epoch(&self) -> u64 {
        self.state.own_doc.data_epoch()
    }

    /// The scope key of `scope` at `data_epoch`, a sub-scope's derived from its parent's
    /// (Switch spec 3.5). Sensitive.
    pub fn scope_key(&self, data_epoch: u64, scope: &str) -> Option<[u8; 32]> {
        self.state.scope_keys.get(data_epoch, scope)
    }

    /// The naming key (Switch spec 3.5). Sensitive.
    pub fn naming_key(&self) -> &NamingKey {
        &self.state.naming
    }

    /// `blind(input)` under the identity's naming key: `derive("pubky-switch/v1/name",
    /// naming_key, input)` (Switch wire 1.5). Every app of the identity gets the same output
    /// for the same input, so a protocol derives from it the keys its apps share, such as
    /// its claim keys (Switch spec 10.2, 13.3), without holding the naming key itself.
    pub fn blind(&self, input: &[u8]) -> [u8; 32] {
        self.state.naming.blind(input)
    }

    /// The newest data epoch through which the app holds every scope key.
    pub fn keys_through(&self) -> u64 {
        self.state.bundle.keys_through
    }

    /// The position the app has processed to.
    pub fn cursor(&self) -> Position {
        Position {
            generation: self.state.cursor.generation,
            seq: self.state.cursor.seq,
        }
    }

    /// The cursor the service holds, as the app last confirmed it.
    pub fn service_cursor(&self) -> Position {
        Position {
            generation: self.state.cursor.generation,
            seq: self.state.cursor.at_service,
        }
    }

    /// The `n` of each receive key the app holds.
    pub fn receive_key_numbers(&self) -> Vec<u64> {
        self.state.receive_keys.keys().copied().collect()
    }

    /// The alarm that stopped the app, if any.
    pub fn alarm(&self) -> Option<&Alarm> {
        self.state.alarm.as_ref()
    }

    /// After an unexpected registration: the `distrust_from` the app asks the signer to
    /// revoke it from, the service time at which that registration was accepted (Switch
    /// spec 3.6).
    pub fn compromise_distrust_from(&self) -> Option<u64> {
        match &self.state.alarm {
            Some(Alarm::Compromise { distrust_from, .. }) => *distrust_from,
            _ => None,
        }
    }

    /// Whether the app is in reconcile mode: after a restore, or with continuity unverified
    /// (Switch spec 8.3, 12.4). The protocol makes no new attempts until its reconciliation
    /// ends it ([`App::end_reconcile`]).
    pub fn reconcile_mode(&self) -> bool {
        self.state.restore.as_ref().is_some_and(|r| r.reconcile)
            || self.state.chain.as_ref().is_some_and(|c| c.gap.is_some())
    }

    /// Whether the app may make an attempt now (Switch spec 3.6, 10.1, 12.4): no alarm, not
    /// left, no restore question open, not in reconcile mode, and, for an automatic attempt,
    /// the device clock within the clock tolerance of the service's.
    ///
    /// # Errors
    ///
    /// The [`Refusal`] that holds the attempt back.
    pub fn may_attempt(&self, automatic: bool) -> Result<(), Refusal> {
        self.may_write_own()?;
        if self.state.alarm.is_some() {
            return Err(Refusal::Stopped);
        }
        if self.state.leave.is_some() {
            return Err(Refusal::Left);
        }
        if !self.restore_question().is_empty() {
            return Err(Refusal::RestoreQuestionOpen);
        }
        if self.reconcile_mode() {
            return Err(Refusal::NotNow("reconcile mode".into()));
        }
        if automatic
            && self
                .clock_skew_ms()
                .is_some_and(|skew| skew > CLOCK_TOLERANCE_MS)
        {
            return Err(Refusal::NotNow(
                "the device clock and the service's differ by more than the tolerance".into(),
            ));
        }
        Ok(())
    }

    /// The greater of the last sampled clock difference and the verified service time's
    /// lead over the device clock (Switch spec 10.1). Without a stamped sample, this is
    /// only a lower bound; `None` before any comparable answer.
    pub fn clock_skew_ms(&self) -> Option<u64> {
        let time = self.state.service_time?;
        let ahead = time.highest_ms.saturating_sub(self.now());
        Some(
            time.offset_ms
                .map_or(ahead, |offset| offset.unsigned_abs().max(ahead)),
        )
    }

    /// The protocol `protocol` finished its reconciliation (Switch spec 12.4 step 2.4):
    /// reconcile mode is the app's, so it ends, as [`App::end_reconcile`] ends it, once
    /// every registered protocol has ended it; until then the app stays in it, and the
    /// protocols that ended it are kept across loads. Whether the mode ended. Outside
    /// reconcile mode nothing is kept, and it returns `true`.
    ///
    /// # Errors
    ///
    /// [`Refusal::Usage`] for a protocol not registered; as [`App::end_reconcile`].
    pub async fn end_reconcile_for(
        &mut self,
        protocol: &str,
        confirmed: UserConfirmed,
    ) -> Result<bool, AppError> {
        Box::pin(async move {
            self.check_registered(protocol)?;
            self.ready_local().await?;
            if !self.reconcile_mode() {
                return Ok(true);
            }
            if !self.restore_question().is_empty() {
                return Err(Refusal::RestoreQuestionOpen.into());
            }
            self.refuse_before_upload().await?;
            let mut ended: Vec<String> = self
                .reader()
                .get(key::RECONCILED)
                .await?
                .unwrap_or_default();
            if !ended.iter().any(|name| name == protocol) {
                ended.push(protocol.to_owned());
            }
            if self
                .protocols
                .names()
                .iter()
                .all(|name| ended.contains(name))
            {
                self.end_reconcile(confirmed).await?;
                return Ok(true);
            }
            let mut tx = self.tx()?;
            tx.put(key::RECONCILED, &ended)?;
            self.commit(tx).await?;
            Ok(false)
        })
        .await
    }

    /// Reconciliation finished (Switch spec 12.4 step 2.4): reconcile mode ends, and with it
    /// the unverified continuity, if any, for every protocol at once.
    ///
    /// # Errors
    ///
    /// [`Refusal::RestoreQuestionOpen`] while the restore question is open;
    /// [`Refusal::NotNow`] while a provider loss is followed and the app's evidence isn't
    /// uploaded yet (Switch spec 12.6 step 3); a store failure.
    pub async fn end_reconcile(&mut self, _confirmed: UserConfirmed) -> Result<(), AppError> {
        Box::pin(async move {
            self.ready_local().await?;
            if !self.restore_question().is_empty() {
                return Err(Refusal::RestoreQuestionOpen.into());
            }
            self.refuse_before_upload().await?;
            let mut tx = self.tx()?;
            // With its key check done and nothing left to ask, the restore is over: its
            // record goes, and no registration is judged by the restore rule again.
            let over = self.state.restore.as_ref().is_some_and(|r| r.key_checked);
            if over {
                tx.delete(key::RESTORE)?;
                tx.delete(key::RESTORE_CURSOR)?;
            } else if let Some(restore) = self.state.restore.as_mut() {
                restore.reconcile = false;
                tx.put(key::RESTORE, restore)?;
            }
            if let Some(chain) = self.state.chain.as_mut() {
                chain.gap = None;
                chain.write(&mut tx)?;
            }
            tx.delete(key::RECONCILED)?;
            self.commit(tx).await?;
            if over {
                self.state.restore = None;
                self.state.restore_cursor = None;
            }
            Ok(())
        })
        .await
    }

    /// Take the events collected since the last call. Duty events among them stay kept
    /// until [`App::ack_events`] acknowledges them (`events` module, "Duty events").
    pub fn take_events(&mut self) -> Vec<AppEvent> {
        let events = std::mem::take(&mut self.events);
        for id in events.iter().filter_map(AppEvent::id) {
            self.duty_handed = self.duty_handed.max(id.counter());
        }
        events
    }

    /// Queue `event`, a stop the host acts on (`Removed`, `ProviderChanged`), unless it is
    /// already queued and not yet taken: several steps of one call may find the same stop,
    /// and the host is told once.
    pub(crate) fn push_once(&mut self, event: AppEvent) {
        if !self.events.contains(&event) {
            self.events.push(event);
        }
    }

    /// Queue duty events for the host, in order, and keep how far they go.
    fn queue_duties(&mut self, duties: Vec<AppEvent>) {
        for id in duties.iter().filter_map(AppEvent::id) {
            self.duty_queued = self.duty_queued.max(id.counter());
        }
        self.events.extend(duties);
    }

    /// After a reload: the kept duty events no call queued, such as those of a commit that
    /// answered [`StoreError::Unknown`] and was applied, queued now.
    async fn queue_unreported_duties(&mut self) -> Result<(), AppError> {
        let queued = self.duty_queued;
        let kept: Vec<AppEvent> = self
            .kept_duties_noted()
            .await?
            .into_iter()
            .filter(|event| event.id().is_some_and(|id| id.counter() > queued))
            .collect();
        self.queue_duties(kept);
        Ok(())
    }

    /// How many protocol calls the protocol answered with an error and the app still owes
    /// it ([`Protocol::resend_needed`], [`Protocol::missed`], [`Protocol::deny_list_changed`],
    /// with the deny list changes owed behind one): each read makes them again,
    /// so a count that stays up shows a protocol that keeps failing.
    ///
    /// # Errors
    ///
    /// A failed store read.
    pub async fn owed_protocol_calls(&self) -> Result<u64, AppError> {
        let owed = self.reader().scan_raw(key::OWED_PREFIX).await?;
        Ok(u64::try_from(owed.len()).unwrap_or(u64::MAX))
    }

    /// Inspect the duty events kept and not acknowledged yet, by ascending ID, each with
    /// the protocols it is for that haven't acknowledged it ([`PendingDuty::owners`]).
    ///
    /// After a failed commit, this first reloads the durable state and queues any duty
    /// events still owed to the host, just as the next app call would. Inspection does
    /// not hand events to the host, remove events from the next report or make their IDs
    /// eligible for [`App::ack_events`]. Repeated inspections return the same events
    /// until the kept duties change.
    ///
    /// A protocol can use this snapshot before acting on current state without consuming
    /// the host's reports. The host still takes a call's report, [`App::take_events`] or
    /// [`App::unacknowledged_events`], acts on every duty through an ID, and acknowledges
    /// that ID only after its protocol has kept what those duties say. Inspection adds
    /// no stored queue and imposes no retention limit (the `events` module, "Duty events").
    ///
    /// # Errors
    ///
    /// A failed store read or reload. An error hands no events to the host.
    pub async fn pending_duty_events(&mut self) -> Result<Vec<PendingDuty>, AppError> {
        self.ready_local().await?;
        self.kept_duties_owned().await
    }

    /// The duty events kept and not acknowledged yet, by ascending ID: what a host that
    /// lost its copy of the reports still has to act on. Nothing but [`App::ack_events`]
    /// shortens this list (`events` module, "Duty events"). Listing them hands them to the
    /// host, as [`App::take_events`] does, so an acknowledgement up to the last of them
    /// removes them all. Use [`App::pending_duty_events`] to inspect without handing them
    /// over or changing the next report.
    ///
    /// # Errors
    ///
    /// A failed store read.
    pub async fn unacknowledged_events(&mut self) -> Result<Vec<AppEvent>, AppError> {
        // A reload owed first, so what it queues is listed here, once.
        self.ready_local().await?;
        let kept = self.kept_duties_noted().await?;
        for id in kept.iter().filter_map(AppEvent::id) {
            self.duty_handed = self.duty_handed.max(id.counter());
        }
        // Handed over here, so not again by the next report.
        let handed = self.duty_handed;
        self.events
            .retain(|event| event.id().is_none_or(|id| id.counter() > handed));
        Ok(kept)
    }

    /// The duty events kept for `protocol` and not acknowledged by it yet, by ascending
    /// ID ([`App::ack_events_for`]). Listing them hands every kept duty event to the host,
    /// as [`App::unacknowledged_events`] does, so a host that lists by protocol lists for
    /// each of its protocols.
    ///
    /// # Errors
    ///
    /// [`Refusal::Usage`] for a protocol not registered; a failed store read.
    pub async fn unacknowledged_events_for(
        &mut self,
        protocol: &str,
    ) -> Result<Vec<AppEvent>, AppError> {
        self.check_registered(protocol)?;
        let all = self.unacknowledged_events().await?;
        Ok(all
            .into_iter()
            .filter(|event| self.event_is_for(event, protocol))
            .collect())
    }

    /// Whether `event` is for `protocol`: an informational event is for every protocol, but
    /// [`AppEvent::SeenMarksIncomplete`], for the one it names, and a duty event for those it
    /// names ([`App::event_owners`]).
    pub fn event_is_for(&self, event: &AppEvent, protocol: &str) -> bool {
        match event.id() {
            // Marks incomplete are told to the protocol the event names alone.
            None => match event {
                AppEvent::SeenMarksIncomplete { protocol: named } => named == protocol,
                _ => true,
            },
            Some(id) => self
                .event_owners(id)
                .is_some_and(|to| to.iter().any(|name| name == protocol)),
        }
    }

    /// The protocols a duty event this app value reported or listed is for and that
    /// haven't acknowledged it yet; `None` for an ID it doesn't know.
    pub fn event_owners(&self, id: EventId) -> Option<&[String]> {
        if id.epoch() != self.state.duty_epoch.epoch {
            return None;
        }
        self.duty_owners.get(&id.counter()).map(Vec::as_slice)
    }

    /// The duty events kept, by ascending ID, without handing them to the host.
    ///
    /// # Errors
    ///
    /// [`StoreError::Corrupt`] for one for no protocol, or for one that isn't registered
    /// ([`App::kept_duty_owned`]).
    pub(crate) async fn kept_duties(&self) -> Result<Vec<AppEvent>, AppError> {
        Ok(self
            .kept_duties_owned()
            .await?
            .into_iter()
            .map(|pending| pending.event)
            .collect())
    }

    /// The duty events kept, by ascending ID, each with the protocols it is for, without
    /// handing them to the host or noting their owners for [`App::event_owners`].
    ///
    /// # Errors
    ///
    /// As [`App::kept_duties`].
    async fn kept_duties_owned(&self) -> Result<Vec<PendingDuty>, AppError> {
        let kept = self
            .reader()
            .scan_numbered::<events::KeptDuty>(key::DUTY_PREFIX)
            .await?;
        kept.into_iter()
            .map(|(n, kept)| {
                self.kept_duty_owned(&kept)?;
                Ok(PendingDuty {
                    event: kept
                        .duty
                        .event(EventId::new(self.state.duty_epoch.epoch, n)),
                    owners: kept.to,
                })
            })
            .collect()
    }

    /// Every writer names a duty event's protocols, each registered, as the load checks the
    /// set: an event for none, or for a protocol not registered, which no acknowledgement
    /// could ever remove, is a corrupt store (fail closed), as an owed call or a deny list
    /// gap of either is. A restore in place is the way out: it carries such an event only
    /// for the registered protocols it names, and leaves one for none of them behind,
    /// counted.
    fn kept_duty_owned(&self, kept: &events::KeptDuty) -> Result<(), AppError> {
        if matches!(kept.duty, events::Duty::StoredEntryDropped { .. }) {
            unverified::notice_id(&kept.duty)?;
        }
        kept.check_owners(&self.protocols)
    }

    /// The duty events kept, as [`App::kept_duties`] lists them, their owners noted for
    /// [`App::event_owners`].
    pub(crate) async fn kept_duties_noted(&mut self) -> Result<Vec<AppEvent>, AppError> {
        let kept = self
            .reader()
            .scan_numbered::<events::KeptDuty>(key::DUTY_PREFIX)
            .await?;
        let mut out = Vec::with_capacity(kept.len());
        for kept in kept.values() {
            self.kept_duty_owned(kept)?;
        }
        for (n, kept) in kept {
            self.duty_owners.insert(n, kept.to);
            out.push(
                kept.duty
                    .event(EventId::new(self.state.duty_epoch.epoch, n)),
            );
        }
        Ok(out)
    }

    /// Acknowledge every duty event up to and including `up_to`: the host and its protocol
    /// kept what they say, and the store no longer keeps them, so no later
    /// [`App::load`] delivers them again. IDs rise in the order the events are reported,
    /// so a host acknowledges after acting on every duty event it took up to that ID. An
    /// ID no event has yet acknowledges only those before it. IDs compare only within one
    /// store ([`EventId::cmp_same_store`]). Only events this app value handed to the host,
    /// by [`App::take_events`], [`App::unacknowledged_events`] or a call's report, are
    /// removed. Inspection with [`App::pending_duty_events`] is not delivery: one kept but not yet taken,
    /// such as one queued after a reload, stays until it is taken and acknowledged.
    ///
    /// It acknowledges for every protocol at once: each event goes for all the protocols
    /// it is for, whichever of them acted on it. A host that hands its protocols their
    /// events apart acknowledges each protocol's with [`App::ack_events_for`] instead.
    ///
    /// The host must call this once it has handed the events to its protocol and the
    /// protocol has kept what they say: nothing else removes a kept duty event, so a host
    /// that never acknowledges keeps them all, without limit (`events` module, "Duty
    /// events").
    ///
    /// # Errors
    ///
    /// [`Refusal::Usage`] for an ID of another store, such as one from before a restore on
    /// another device. On a refusal or read error the duties stay as they were. If the
    /// commit returns [`StoreError::Unknown`], it may already have acknowledged every
    /// handed duty through `up_to`. Read [`App::pending_duty_events`] to see what is
    /// still owed before retrying. Other commit errors leave the duties unchanged.
    pub async fn ack_events(&mut self, up_to: EventId) -> Result<(), AppError> {
        Box::pin(async move {
            self.ready_local().await?;
            self.check_event_store(up_to)?;
            // Only what the host was handed: a kept event it never took stays.
            let through = up_to.counter().min(self.duty_handed);
            let kept = self.reader().scan_numbers(key::DUTY_PREFIX).await?;
            let mut tx = self.tx()?;
            for n in kept.range(..=through) {
                tx.delete(&key::duty(*n))?;
            }
            self.commit(tx).await?;
            self.duty_owners.retain(|n, _| *n > through);
            Ok(())
        })
        .await
    }

    /// Acknowledge, for the protocol `protocol` alone, every duty event up to and including
    /// `up_to` that is for it: as [`App::ack_events`], but each event stays kept for the
    /// other protocols it is for until each of them acknowledges it, across loads. An event
    /// that isn't for `protocol` is left as it is.
    ///
    /// # Errors
    ///
    /// [`Refusal::Usage`] for an unregistered protocol or an ID of another store. The
    /// store errors are those of [`App::ack_events`]. After [`StoreError::Unknown`],
    /// read [`App::pending_duty_events`] and its [`PendingDuty::owners`] to see which
    /// duties are still owed to this protocol. Other owners keep their duties.
    pub async fn ack_events_for(&mut self, protocol: &str, up_to: EventId) -> Result<(), AppError> {
        Box::pin(async move {
            self.check_registered(protocol)?;
            self.ready_local().await?;
            if up_to.epoch() != self.state.duty_epoch.epoch {
                return Err(Refusal::Usage(
                    "an event ID of another store: nothing acknowledged".into(),
                )
                .into());
            }
            let through = up_to.counter().min(self.duty_handed);
            let kept = self
                .reader()
                .scan_numbered::<events::KeptDuty>(key::DUTY_PREFIX)
                .await?;
            let mut tx = self.tx()?;
            let mut left = Vec::new();
            for (n, mut kept) in kept.into_iter().filter(|(n, _)| *n <= through) {
                let before = kept.to.len();
                kept.to.retain(|name| name != protocol);
                if kept.to.len() == before {
                    continue;
                }
                if kept.to.is_empty() {
                    tx.delete(&key::duty(n))?;
                } else {
                    tx.put(&key::duty(n), &kept)?;
                }
                left.push((n, kept.to));
            }
            self.commit(tx).await?;
            for (n, to) in left {
                if to.is_empty() {
                    self.duty_owners.remove(&n);
                } else {
                    self.duty_owners.insert(n, to);
                }
            }
            Ok(())
        })
        .await
    }

    /// Acknowledge exactly one delivered, still-owed event with bounded protocol-local
    /// writes in the same commit (Switch spec 8.2, 11). No other event is acknowledged.
    ///
    /// After an unknown commit outcome, reload durable local handling state before acting
    /// again. An absent event always refuses; absence alone is not proof it was handled.
    /// A handler can keep its own idempotence marker with these writes, keyed by the
    /// notice's stable identity when delivery IDs may change across restore.
    ///
    /// # Errors
    ///
    /// [`Refusal::Usage`] for an absent, foreign or undelivered ID or oversized local writes;
    /// [`Refusal::Left`] for nonempty local writes after the keys were deleted; a store error.
    /// On refusal neither the acknowledgment nor the local writes is applied.
    pub async fn ack_event_with(
        &mut self,
        protocol: &str,
        id: EventId,
        local: &[LocalWrite],
    ) -> Result<(), AppError> {
        self.ready_local().await?;
        self.check_registered(protocol)?;
        self.check_event_store(id)?;
        let at = key::duty(id.counter());
        let mut kept: events::KeptDuty = self.reader().get(&at).await?.ok_or_else(|| {
            AppError::from(Refusal::Usage(
                "the event is absent or was not delivered".into(),
            ))
        })?;
        self.kept_duty_owned(&kept)?;
        if id.counter() > self.duty_handed || !kept.to.iter().any(|name| name == protocol) {
            return Err(Refusal::Usage("the event is absent or was not delivered".into()).into());
        }
        if local_writes_bytes(local) > MAX_STEP_LOCAL_BYTES {
            return Err(
                Refusal::Usage("the local acknowledgment exceeds its byte bound".into()).into(),
            );
        }
        if !local.is_empty()
            && self
                .state
                .leave
                .is_some_and(|leave| leave.keys_deleted_ms.is_some())
        {
            return Err(Refusal::Left.into());
        }
        let mut tx = self.tx()?;
        tx.local(&protocols::qualify(protocol, local.to_vec()))?;
        kept.to.retain(|name| name != protocol);
        if kept.to.is_empty() {
            tx.delete(&at)?;
        } else {
            tx.put(&at, &kept)?;
        }
        self.commit(tx).await?;
        if kept.to.is_empty() {
            self.duty_owners.remove(&id.counter());
        } else {
            self.duty_owners.insert(id.counter(), kept.to);
        }
        Ok(())
    }

    fn check_event_store(&self, id: EventId) -> Result<(), AppError> {
        if id.epoch() != self.state.duty_epoch.epoch {
            return Err(Refusal::Usage(
                "an event ID of another store: nothing acknowledged".into(),
            )
            .into());
        }
        Ok(())
    }

    /// Keep a duty event in `tx`, under the next ID: written in the commit of the change it
    /// reports, and reported once that commit is done (`events` module, "Duty events").
    pub(crate) fn keep_duty(&mut self, tx: &mut Tx, duty: events::Duty) -> Result<(), AppError> {
        let to = self.duty_to(&duty);
        self.keep_duty_for(tx, to, duty)
    }

    /// Keep a duty event for the protocols `to`, as [`App::keep_duty`] does. One raised in
    /// a read is kept inside a step the order rule admitted for those protocols, or is about
    /// an entry stored at or before their positions (`order` module).
    pub(crate) fn keep_duty_for(
        &mut self,
        tx: &mut Tx,
        to: Vec<String>,
        duty: events::Duty,
    ) -> Result<(), AppError> {
        let n = tx
            .renewal
            .as_ref()
            .map_or(self.state.next_duty, |r| r.next_duty);
        let next = n.checked_add(1).ok_or_else(corrupt)?;
        // A message's hold ends in the commit that tells it undelivered: its delivery is no
        // longer owed (`App::hold_message`).
        if let Some(msg_id) = duty.given_up() {
            send::end_message_hold(tx, msg_id)?;
            // Retaining an accepted item's record job never queues its ended delivery
            // again through the sent-message cache (Switch spec 11).
            send::note_given_up(tx, msg_id, self.now())?;
        }
        let kept = events::KeptDuty { to, duty };
        tx.put(&key::duty(n), &kept)?;
        tx.put(key::DUTY_NEXT, &next)?;
        if let Some(renewal) = &mut tx.renewal {
            renewal.next_duty = next;
            renewal.duty_owners.insert(n, kept.to);
        } else {
            self.state.next_duty = next;
            self.duty_owners.insert(n, kept.to);
        }
        tx.report(
            kept.duty
                .event(EventId::new(self.state.duty_epoch.epoch, n)),
        );
        Ok(())
    }

    /// The protocols a kept batch's duty events are for: its protocol, or every protocol
    /// for a batch of the host's own.
    pub(crate) fn batch_owners(&self, pending: &batch::PendingBatch) -> Vec<String> {
        match &pending.protocol {
            Some(name) => vec![name.clone()],
            None => self.protocols.names(),
        }
    }

    /// The protocols a duty event about an item of `kind` is for: the kind's owner, or
    /// every protocol when none owns it.
    pub(crate) fn owners_of_kind(&self, kind: &str) -> Vec<String> {
        match self.protocols.of_kind(kind) {
            Some(owner) => vec![owner.name.clone()],
            None => self.protocols.names(),
        }
    }

    /// The protocols a duty event about a record of the collection `name` is for: the
    /// collection's owner, or every protocol when none owns it.
    pub(crate) fn owners_of_collection(&self, name: &str) -> Vec<String> {
        match self.protocols.of_collection(name) {
            Some(owner) => vec![owner.name.clone()],
            None => self.protocols.names(),
        }
    }

    /// The protocols a duty event is for: the protocol of the kind it names, or of the
    /// message of the entry stored locally it names; every protocol otherwise.
    fn duty_to(&self, duty: &events::Duty) -> Vec<String> {
        let kind = match duty {
            events::Duty::StoredEntryDropped { message, .. } => Some(message.kind.clone()),
            events::Duty::EffectRefused { kind, .. }
            | events::Duty::EffectUncertain { kind, .. } => Some(kind.clone()),
            _ => duty
                .stored_id()
                .and_then(|id| self.state.parked.get(&id))
                .and_then(|stored| protocols::kind_of_plaintext(&stored.plaintext)),
        };
        match kind
            .as_deref()
            .and_then(|kind| self.protocols.of_kind(kind))
        {
            Some(owner) => vec![owner.name.clone()],
            None => self.protocols.names(),
        }
    }

    /// What a restore in place carries across. `None` for a store that holds no epoch. A
    /// failed store read is the error: the restore can be tried again. A value that reads
    /// but doesn't decode is left behind and counted; a damaged epoch or counter starts a
    /// new epoch, since the kept counters may then be below IDs the host acknowledged.
    async fn kept_for_protocol(
        reader: &Reader,
        protocols: &ProtocolSet,
    ) -> Result<Option<Carried>, AppError> {
        let Some(epoch) = reader.get_raw(key::DUTY_EPOCH.as_bytes()).await? else {
            return Ok(None);
        };
        let epoch = state::decode::<state::DutyEpoch>(&epoch).ok();
        let counter = match reader.get_raw(key::DUTY_NEXT.as_bytes()).await? {
            None => Some(FIRST_DUTY),
            Some(bytes) => state::decode::<u64>(&bytes).ok(),
        };
        let mut carried = Carried::default();
        let mut past_kept = FIRST_DUTY;
        for (rest, bytes) in reader.scan_raw(key::DUTY_PREFIX).await? {
            let read = state::parse_num(&rest).and_then(|n| {
                let kept = state::decode::<events::KeptDuty>(&bytes)?;
                Ok((n, kept))
            });
            match read {
                Ok((n, mut kept)) => {
                    if matches!(kept.duty, events::Duty::StoredEntryDropped { .. }) {
                        unverified::notice_id(&kept.duty)?;
                    }
                    past_kept = past_kept.max(n.checked_add(1).ok_or_else(corrupt)?);
                    if let Some(msg_id) = kept.duty.given_up() {
                        carried.given_up.insert(msg_id.to_owned());
                    }
                    if let Some(id) = kept.duty.stored_id() {
                        carried.stored_past = carried.stored_past.max(id.saturating_add(1));
                    }
                    // The restore tells every record edit it holds aside itself, the store's
                    // too: what the store told of them before isn't kept beside that.
                    if matches!(kept.duty, events::Duty::RecordEditsHeld { .. }) {
                        continue;
                    }
                    // An event goes on only for the protocols registered here; one for none
                    // of them is left behind, and counted.
                    kept.to.retain(|name| protocols.contains(name));
                    if kept.to.is_empty() {
                        carried.lost_duties = carried.lost_duties.saturating_add(1);
                        continue;
                    }
                    kept.check_owners(protocols)?;
                    let value = serde_json::to_value(&kept).map_err(|_| corrupt())?;
                    carried
                        .values
                        .push((format!("{}{rest}", key::DUTY_PREFIX), value));
                }
                Err(error) if unverified::waiting_record(&bytes) => return Err(error),
                Err(_) => carried.lost_duties = carried.lost_duties.saturating_add(1),
            }
        }
        for (rest, bytes) in reader.scan_raw(key::OWED_PREFIX).await? {
            // Carried only when whole, as the queue reads it: a key that names a feed
            // position, and a change not checked yet that keeps its own operation. One that
            // isn't would fail every read of the restored store; it is counted as left
            // behind instead, so the restore repairs the store.
            // Each keeps only the protocols registered here; one owed to none of them is
            // left behind, and counted.
            let read = feed::owed_place(&rest)
                .and_then(|_| state::decode::<feed::Owed>(&bytes))
                .and_then(|owed| {
                    owed.check_place(&rest)?;
                    owed.call.kept_op_body().map(|_| owed)
                });
            match read {
                Ok(mut owed) => {
                    owed.to.retain(|name| protocols.contains(name));
                    owed.call.retain_owners(&owed.to);
                    if owed.check_owners(protocols).is_err() {
                        carried.lost_owed = carried.lost_owed.saturating_add(1);
                        continue;
                    }
                    let value = serde_json::to_value(&owed).map_err(|_| corrupt())?;
                    carried
                        .values
                        .push((format!("{}{rest}", key::OWED_PREFIX), value));
                }
                Err(_) => carried.lost_owed = carried.lost_owed.saturating_add(1),
            }
        }
        match (epoch, counter) {
            (Some(epoch), Some(counter)) => {
                carried.epoch = Some(epoch);
                carried.next_duty = counter.max(past_kept);
            }
            _ => carried.next_duty = past_kept,
        }
        Ok(Some(carried))
    }

    /// A missed call follows the installed layer. A live call supplies the original
    /// observation for an owner whose installed state has yet to see the occurrence.
    fn restore_missed(
        &self,
        backup: &AppBackup,
        place: (u64, u64),
        original: Option<&feed::Owed>,
        live: &feed::Owed,
    ) -> Option<feed::Owed> {
        let (generation, seq) = place;
        let after_cursor = self.feed_order(generation, seq)
            > self.feed_order(backup.cursor.generation, backup.cursor.seq);
        let gap = live.call.held_gap(seq);
        let sequence = self.state.own_doc.body().recovery_from.unwrap_or(0);
        let seen = |layer: &BeyondCursor| match gap {
            Some(held) => layer.held_gap.is_some_and(|(s, last)| {
                s == sequence && self.current_sequence(generation) && last >= held
            }),
            None => {
                !after_cursor
                    || (generation == backup.cursor.generation && layer.missed.contains(&seq))
            }
        };
        let mut reads = Vec::new();
        for name in self.protocols.names() {
            if let Some(from_backup) = original.filter(|owed| owed.to.contains(&name)) {
                reads.push((name.clone(), from_backup.call.missed_for(&name)?.clone()));
                continue;
            }
            let installed = backup
                .beyond_cursor
                .as_ref()
                .filter(|layer| layer.protocols.contains(&name));
            if installed.is_some_and(|layer| original.is_some() || seen(layer)) {
                continue;
            }
            let later =
                original.is_none() && (after_cursor || (gap.is_some() && installed.is_some()));
            if live.to.contains(&name) || later {
                reads.push((name.clone(), live.call.missed_for(&name)?.clone()));
            }
        }
        feed::Owed::missed_owners(reads)
    }

    /// The owed calls a backup carries, by stored key, each whole as a carried one must be
    /// and owed only to the protocols registered here ([`App::kept_for_protocol`]), and how
    /// many are left behind: those that aren't whole, those owed to none of them, and a
    /// deny list change, which no backup carries (the restore's own gap covers it), so one
    /// there isn't a backup's whole.
    fn owed_of_backup(
        backup: &AppBackup,
        protocols: &ProtocolSet,
    ) -> (Vec<(String, serde_json::Value)>, u64) {
        let mut whole = Vec::new();
        let mut lost = 0u64;
        for (rest, value) in &backup.owed {
            let read = feed::owed_place(rest).and_then(|_| {
                serde_json::from_value::<feed::Owed>(value.clone()).map_err(|_| corrupt())
            });
            let mut owed = match read {
                Ok(owed)
                    if matches!(
                        owed.call,
                        feed::OwedCall::Resend { .. } | feed::OwedCall::Missed { .. }
                    ) =>
                {
                    owed
                }
                _ => {
                    lost = lost.saturating_add(1);
                    continue;
                }
            };
            if owed.check_place(rest).is_err() {
                lost = lost.saturating_add(1);
                continue;
            }
            owed.to.retain(|name| protocols.contains(name));
            owed.call.retain_owners(&owed.to);
            if owed.check_owners(protocols).is_err() {
                lost = lost.saturating_add(1);
                continue;
            }
            match serde_json::to_value(&owed) {
                Ok(value) => whole.push((format!("{}{rest}", key::OWED_PREFIX), value)),
                Err(_) => lost = lost.saturating_add(1),
            }
        }
        (whole, lost)
    }

    /// The local ID the store's next entry stored locally would take, for a restore in
    /// place: its counter (`parkid`) and, past it, every `parked/` and `sretry/` key it
    /// holds. A counter that doesn't read, from a store that was damaged or of another
    /// schema, gives way to those keys rather than to the first ID.
    async fn stored_next_of(reader: &Reader) -> Result<u64, AppError> {
        let counter = match reader.get_raw(key::STORED_NEXT.as_bytes()).await? {
            Some(bytes) => state::decode::<u64>(&bytes).ok(),
            None => None,
        };
        let mut next = counter.unwrap_or(FIRST_STORED_ID);
        for prefix in ["parked/", "sretry/"] {
            for (rest, _) in reader.scan_raw(prefix).await? {
                if let Ok(id) = state::parse_num(&rest) {
                    next = next.max(id.saturating_add(1));
                }
            }
        }
        Ok(next)
    }

    /// The ID the next duty event takes: past the counter and every kept event.
    async fn next_duty(reader: &Reader) -> Result<u64, AppError> {
        let counter: u64 = reader.get(key::DUTY_NEXT).await?.unwrap_or(FIRST_DUTY);
        let kept = reader.scan_numbers(key::DUTY_PREFIX).await?;
        let past_kept = match kept.last() {
            Some(last) => last.checked_add(1).ok_or_else(corrupt)?,
            None => FIRST_DUTY,
        };
        Ok(counter.max(past_kept))
    }

    /// The highest service time the app verified, Unix milliseconds (Switch spec 10.1): a
    /// protocol checks its deadlines against it rather than the device clock. `None` before
    /// any verified answer.
    pub fn highest_service_time(&self) -> Option<u64> {
        self.state.service_time.map(|time| time.highest_ms)
    }

    /// [`Refusal::Usage`] for a name no protocol of the app is registered under.
    pub(crate) fn check_registered(&self, protocol: &str) -> Result<(), AppError> {
        if self.protocols.contains(protocol) {
            Ok(())
        } else {
            Err(Refusal::Usage(format!("no protocol `{protocol}` is registered")).into())
        }
    }

    /// A value of the local state of the protocol `protocol`, under its key space.
    ///
    /// # Errors
    ///
    /// [`Refusal::Usage`] for a protocol not registered; a store failure.
    pub async fn protocol_get(
        &self,
        protocol: &str,
        key: &[u8],
    ) -> Result<Option<Vec<u8>>, AppError> {
        self.check_registered(protocol)?;
        self.reader()
            .get_raw(&[PROTOCOL_PREFIX, &protocols::qualified_key(protocol, key)].concat())
            .await
    }

    /// Every value of the local state of the protocol `protocol` whose key starts with
    /// `prefix`, with its key in the protocol's key space, in key order.
    ///
    /// # Errors
    ///
    /// [`Refusal::Usage`] for a protocol not registered; a store failure.
    pub async fn protocol_scan(
        &self,
        protocol: &str,
        prefix: &[u8],
    ) -> Result<Vec<crate::store::KeyValue>, AppError> {
        self.check_registered(protocol)?;
        let own = [PROTOCOL_PREFIX, &protocols::qualified_key(protocol, b"")].concat();
        let full = [own.as_slice(), prefix].concat();
        let mut out = Vec::new();
        let mut after: Option<Vec<u8>> = None;
        loop {
            let page = self
                .env
                .store
                .scan(&self.ns, &full, after.as_deref(), PROTOCOL_SCAN_PAGE)
                .await?;
            let more = page.len() >= usize::try_from(PROTOCOL_SCAN_PAGE).unwrap_or(usize::MAX);
            for (key, value) in page {
                if let Some(rest) = key.get(own.len()..) {
                    out.push((rest.to_vec(), value));
                }
                after = Some(key);
            }
            if !more {
                return Ok(out);
            }
        }
    }

    /// Commit writes of the local state of the protocol `protocol` on their own, in one
    /// store commit, under that protocol's prefix.
    /// Writes that go with a batch's outcome go in the batch instead
    /// ([`OpBatch::local`]), and those of a received message's effect with it
    /// ([`Effect::local`], [`ReceiveContext::local`]).
    ///
    /// # Errors
    ///
    /// [`Refusal::Usage`] for a protocol not registered, [`Refusal::Left`] once the app
    /// deleted its keys, or a store error. If the commit returns [`StoreError::Unknown`],
    /// it applied all the writes or none. Read the durable protocol state before retrying.
    /// Any other commit error leaves these writes unapplied. The app reloads its state
    /// before its next mutation after a failed commit.
    pub async fn protocol_commit(
        &mut self,
        protocol: &str,
        writes: &[LocalWrite],
    ) -> Result<(), AppError> {
        Box::pin(async move {
            self.check_registered(protocol)?;
            self.ready_local().await?;
            if self
                .state
                .leave
                .is_some_and(|l| l.keys_deleted_ms.is_some())
            {
                return Err(Refusal::Left.into());
            }
            let mut tx = self.tx()?;
            tx.local(&protocols::qualify(protocol, writes.iter().cloned()))?;
            self.commit(tx).await
        })
        .await
    }

    /// The protocols the app runs.
    pub fn protocols(&self) -> &ProtocolSet {
        &self.protocols
    }

    // ---------------------------------------------------------------------------------
    // Leaving (Switch spec 12.3)

    /// Leave the identity (Switch spec 12.3): `leave` at the service, then the keys go: at
    /// once for [`LeaveMode::Immediate`], or once the signer published the app as removed
    /// and readers' caches passed for [`LeaveMode::TwoStep`] ([`App::finish_leave`]).
    /// An app that publishes its record deletes it from the Homeserver first, and publishes
    /// nothing from the commit that starts the leave on, across a restart too (Switch spec
    /// 12.3).
    ///
    /// # Errors
    ///
    /// A failed call; the leave is tried again by the next call to `leave`.
    pub async fn leave(&mut self, mode: LeaveMode) -> Result<LeaveReport, AppError> {
        Box::pin(async move {
            self.ready_local().await?;
            let two_step = matches!(mode, LeaveMode::TwoStep);
            self.leave_at_service(two_step, false).await?;
            match mode {
                LeaveMode::Immediate(_) => {
                    self.destroy_keys().await?;
                    Ok(LeaveReport::Done)
                }
                LeaveMode::TwoStep => self.finish_leave().await,
            }
        })
        .await
    }

    /// The second step of a two-step leave: once the own `identity.json` on the Homeserver
    /// lists the app in `removed`, wait [`LEAVE_CACHE_MS`] from when it was first seen, then
    /// delete the keys.
    ///
    /// # Errors
    ///
    /// [`Refusal::NotNow`] if the app hasn't left; a failed read.
    pub async fn finish_leave(&mut self) -> Result<LeaveReport, AppError> {
        Box::pin(async move {
            self.ready_local().await?;
            let Some(leave) = self.state.leave else {
                return Err(Refusal::NotNow("the app hasn't left".into()).into());
            };
            if leave.left_at_ms.is_none() {
                return Err(Refusal::NotNow("the leave hasn't reached the service".into()).into());
            }
            if leave.keys_deleted_ms.is_some() {
                return Ok(LeaveReport::Done);
            }
            let now = self.now();
            let seen = match leave.removed_seen_ms {
                Some(seen) => seen,
                None => {
                    let identity = self.state.meta.identity;
                    let doc =
                        identity::read_homeserver(self.env.homeserver.as_ref(), &identity).await?;
                    let removed = doc
                        .as_ref()
                        .is_some_and(|d| d.lists_removed(&self.state.meta.app_id));
                    if !removed {
                        return Ok(LeaveReport::AwaitingRemoval);
                    }
                    let mut tx = self.tx()?;
                    let leave = self.state.leave.get_or_insert_with(LeaveState::default);
                    leave.removed_seen_ms = Some(now);
                    tx.put(key::LEAVE, leave)?;
                    self.commit(tx).await?;
                    now
                }
            };
            let at = seen.saturating_add(LEAVE_CACHE_MS);
            if now < at {
                return Ok(LeaveReport::Removed {
                    delete_keys_at_ms: at,
                });
            }
            self.destroy_keys().await?;
            Ok(LeaveReport::Done)
        })
        .await
    }

    /// `leave` at the service, once: the intent is committed first, so a crash calls it
    /// again; an app the service already counts as departed is answered `403 not_current`,
    /// which is the leave done.
    async fn leave_at_service(&mut self, two_step: bool, compromise: bool) -> Result<(), AppError> {
        if self.state.leave.is_some_and(|l| l.left_at_ms.is_some()) {
            return Ok(());
        }
        if self.state.leave.is_none() {
            let mut tx = self.tx()?;
            let leave = LeaveState {
                compromise,
                ..LeaveState::default()
            };
            tx.put(key::LEAVE, &leave)?;
            self.state.leave = Some(leave);
            self.commit(tx).await?;
        }
        // A publishing app deletes its Homeserver record first (Switch spec 12.3); the leave
        // committed above stops every publication from here on. Only a two-step leave waits
        // for the delete: an immediate leave, and a compromise's, which leaves at once
        // (Switch spec 3.6), go on without it, the failure reported, and the signer's
        // clean-up deletes the record (Switch spec 12.2 step 4). This call's mode decides,
        // so an immediate leave asked for after a two-step one whose delete failed goes on
        // too; and once a compromise started the leave, every later call is a leave after
        // a compromise.
        let waits = two_step && !self.state.leave.is_some_and(|leave| leave.compromise);
        match self.unpublish_to_leave().await {
            Ok(()) => {}
            Err(AppError::Transport(error)) if !waits => {
                self.events.push(AppEvent::RecordPublishFailed {
                    error: error.to_string(),
                });
            }
            Err(error) => return Err(error),
        }
        let result = self.client.leave().await;
        let answered = match self.take(result).await {
            Ok(answer) => {
                if let Err(alarm) = self.note_answer_head(answer.head, &answer.proofs) {
                    return Err(self.raise(alarm).await);
                }
                true
            }
            Err(error) if error.code() == Some(pubky_switch_core::http::ErrorCode::NotCurrent) => {
                true
            }
            Err(error) => return Err(error),
        };
        if answered {
            self.release_put_backs_on_leave().await?;
            let now = self.now();
            let mut tx = self.tx()?;
            let leave = self.state.leave.get_or_insert_with(LeaveState::default);
            leave.left_at_ms = Some(now);
            tx.put(key::LEAVE, leave)?;
            self.commit(tx).await?;
            self.events.push(AppEvent::Left);
        }
        Ok(())
    }

    /// Delete the keys, in the sense of Switch spec 3.1: every record that holds one, and
    /// the parked plaintexts. The store deletes them for real.
    async fn destroy_keys(&mut self) -> Result<(), AppError> {
        let now = self.now();
        let mut tx = Tx::new(&self.ns);
        tx.delete(key::KEYS)?;
        tx.delete(key::NAMING)?;
        tx.delete_prefixes(&["rk/", "scope/", "parked/", "pending/", "p/"])?;
        order::clear_on_leave(&mut tx)?;
        deletion::clear_on_leave(&mut tx)?;
        records::clear_on_leave(&mut tx)?;
        recovery::inventory::clear_on_leave(&mut tx)?;
        recovery::lists::clear_on_leave(&mut tx)?;
        send::clear_on_leave(&mut tx)?;
        admission::clear_on_leave(&mut tx)?;
        kept::clear_on_leave(&mut tx)?;
        let mut leave = self.state.leave.unwrap_or_default();
        leave.keys_deleted_ms = Some(now);
        tx.put(key::LEAVE, &leave)?;
        self.commit(tx).await?;
        self.state.leave = Some(leave);
        self.state.receive_keys.clear();
        self.state.scope_keys = ScopeKeys::default();
        self.state.parked.clear();
        self.state.deletions.clear();
        self.state.deletion_receipts.clear();
        self.events.push(AppEvent::KeysDestroyed);
        Ok(())
    }

    /// After a compromise: stop, and leave at once (Switch spec 3.6). The keys stay for the
    /// user; the leave is irreversible, so the copy holding the same signing key is refused
    /// from now on. A failed call is tried again at the next call.
    async fn leave_on_compromise(&mut self) {
        if self.state.leave.is_some_and(|l| l.left_at_ms.is_some()) {
            return;
        }
        // A failure leaves the leave owed: the next call reads the store again and tries it
        // again.
        if self.leave_at_service(false, true).await.is_err() {
            self.reload = true;
        }
    }

    // ---------------------------------------------------------------------------------
    // Internals

    fn client_for(
        env: &AppEnv,
        meta: &Meta,
        keys: &AppKeys,
        cert: &AppCert,
    ) -> Result<SwitchClient, AppError> {
        Ok(SwitchClient::new(
            &meta.origin,
            meta.identity,
            Credentials::App {
                identity: meta.identity,
                keys: keys.clone(),
                cert: cert.clone(),
            },
            Some(meta.service_key),
            Arc::clone(&env.transport),
            Arc::clone(&env.clock),
        )?)
    }

    fn own_read_client(&self) -> Result<SwitchClient, AppError> {
        self.own_read_client_for(&self.state.cert)
    }

    fn own_read_client_for(&self, cert: &AppCert) -> Result<SwitchClient, AppError> {
        let mut client = Self::client_for(&self.env, &self.state.meta, &self.state.keys, cert)?;
        client.follow_own_reads(
            self.state.meta.generation,
            self.state.health.notice,
            Some(&self.client),
        );
        Ok(client)
    }

    /// The app's device clock. A host checking an action against the app's own
    /// identity uses this clock so both observe the same backwards adjustments.
    pub fn clock(&self) -> Arc<dyn Clock> {
        Arc::clone(&self.env.clock)
    }

    /// The reader this app uses for Homeserver files.
    pub fn homeserver_reader(&self) -> Arc<dyn HomeserverReader> {
        Arc::clone(&self.env.homeserver)
    }

    /// Whether this app is configured to publish its record on its Homeserver.
    pub fn publishes_record(&self) -> bool {
        self.config.publishes_record
    }

    pub(crate) fn now(&self) -> u64 {
        self.env.clock.now_ms()
    }

    pub(crate) fn reader(&self) -> Reader {
        Reader {
            ns: self.ns.clone(),
            store: self.env.store.clone(),
        }
    }

    /// A transaction, carrying the service time record when it changed.
    pub(crate) fn tx(&mut self) -> Result<Tx, AppError> {
        let mut tx = Tx::new(&self.ns);
        if self.service_time_dirty
            && let Some(time) = &self.state.service_time
        {
            tx.put(key::SERVICE_TIME, time)?;
        }
        Ok(tx)
    }

    /// Commit; after a failure the app reads its state again before going on.
    pub(crate) async fn commit(&mut self, mut tx: Tx) -> Result<(), AppError> {
        // Dropping the future can lose the store's answer. A successful save resolves
        // only this transaction, even when it runs during a reload.
        let reload = std::mem::replace(&mut self.reload, true);
        let save_needs_reload = std::mem::replace(&mut self.save_needs_reload, true);
        let duties = tx.take_reports();
        let renewal = tx.renewal.take();
        // Box the list checks and store write so a nested receive step can save on a small stack.
        let result = Box::pin(async {
            if let Err(error) = self.retain_list_positions(&mut tx).await {
                self.retained_floor = None;
                return Err(error);
            }
            // An alarm may be raised after this transaction was built. Carry its exact
            // evidence in every commit until one confirms it durable (Switch spec 10.1).
            if self.alarm_dirty
                && let Some(alarm) = &self.state.alarm
            {
                tx.put(key::ALARM, alarm)?;
            }
            tx.commit(&self.env.store).await
        })
        .await;
        match result {
            Ok(()) => {
                self.reload = reload;
                self.save_needs_reload = save_needs_reload;
                self.service_time_dirty = false;
                self.alarm_dirty = false;
                if let Some(changes) = renewal {
                    self.state.cursor = changes.cursor;
                    self.state.next_duty = changes.next_duty;
                    self.duty_owners.extend(changes.duty_owners);
                    self.state.deletion_receipts.extend(changes.receipts);
                    for key in changes.removed {
                        self.state.put_backs.remove(&key);
                    }
                }
                self.queue_duties(duties);
                Ok(())
            }
            Err(error) => Err(error),
        }
    }

    /// The time budget of a call that begins now ([`AppConfig::call_budget_ms`]).
    pub(crate) fn begin_budget(&self) -> CallBudget {
        CallBudget {
            began_ms: self.now(),
            budget_ms: self.config.call_budget_ms,
        }
    }

    /// Whether `budget` is spent now.
    pub(crate) fn spent(&self, budget: &CallBudget) -> bool {
        budget.spent(self.now())
    }

    /// Refuse reads after a failed or interrupted save until the app reloads from the store.
    fn require_loaded(&self) -> Result<(), AppError> {
        if self.save_needs_reload {
            return Err(Refusal::NotNow(
                "call receive to reload local state after a failed or interrupted save".into(),
            )
            .into());
        }
        Ok(())
    }

    async fn reload_if_needed(&mut self) -> Result<(), AppError> {
        if self.reload {
            Box::pin(self.ready_local()).await?;
        }
        Ok(())
    }

    /// Reload after a failed commit, and refuse calls the app's state forbids.
    async fn ready_local(&mut self) -> Result<(), AppError> {
        // Each call takes a service time of its own before it judges a kept batch's age.
        self.time_fresh_at = None;
        let told = self.reload || !self.told_loaded;
        if self.reload {
            // Keep verified time and a pending alarm before replacing memory with the
            // stored state. A failed retry leaves both held and stops this call.
            self.keep_observations().await?;
            self.state = Self::read_state(&self.reader()).await?;
            self.validate_waiting_state()?;
            self.client = self.own_read_client()?;
            display::restore(&self.client, &self.state)?;
            self.service_time_dirty = false;
            // The reload is done only once the kept duty events it may owe the host are
            // queued: a replay that fails is made again by the next call.
            self.queue_unreported_duties().await?;
            self.reload = false;
            self.save_needs_reload = false;
        }
        self.keep_read_decisions().await?;
        self.client
            .hold_own_writes(self.recovery_required().map(|n| n.generation));
        if told {
            self.load_told().await?;
        }
        Ok(())
    }

    /// Raise the rollback alarm for the protocol `protocol` on its evidence
    /// ([`Alarm::ProtocolRollback`], Switch spec 10.1): for a protocol that finds, in what
    /// the service signed for its own data, that the service went back on it or contradicts
    /// itself, such as a shared record write that breaks a rule only the service's state
    /// could break. The app keeps the alarm and stops, as for one it found itself: every
    /// later call is refused, for every protocol of the app, not only the one that raised
    /// it, until the user resolves it, by moving to another provider or declaring a provider
    /// loss. The store keeps it: only a restore or a fresh join, on a store without it,
    /// starts again without it. So a protocol raises it only on evidence the service
    /// signed, never on a doubt of its own.
    ///
    /// `reason` names the rule broken, without content: it is kept and shown, cut to
    /// [`MAX_REGRESSION_REASON_BYTES`], 256 bytes, at a character boundary. Returns the
    /// alarm the app holds: this one, kept and told ([`AppEvent::Alarm`], naming
    /// `protocol`) in the commit that raises it, or the alarm it held already, which stays
    /// as it was. A protocol that finds the evidence in a receive step answers it so the
    /// read doesn't pass the entry, and the host raises it after the read returns.
    ///
    /// # Errors
    ///
    /// [`Refusal::Usage`] for a protocol not registered, [`Refusal::Left`] for an app that
    /// left, or a store error. After a failed commit, raise the alarm again. The app reloads
    /// its state and returns an alarm the store already kept.
    pub async fn raise_rollback(
        &mut self,
        protocol: &str,
        reason: impl Into<String>,
    ) -> Result<Alarm, AppError> {
        Box::pin(async move {
            self.ready_local().await?;
            self.check_registered(protocol)?;
            if self.state.leave.is_some() {
                return Err(Refusal::Left.into());
            }
            if let Some(held) = &self.state.alarm {
                return Ok(held.clone());
            }
            let alarm = Alarm::ProtocolRollback {
                protocol: protocol.to_owned(),
                reason: records::cut_reason(reason.into()),
            };
            let mut tx = self.tx()?;
            tx.put(key::ALARM, &alarm)?;
            self.commit(tx).await?;
            self.state.alarm = Some(alarm.clone());
            self.events.push(AppEvent::Alarm(alarm.clone()));
            Ok(alarm)
        })
        .await
    }

    /// Raise an alarm: keep it, stop, and return it as the error.
    pub(crate) async fn raise(&mut self, alarm: Alarm) -> AppError {
        if self.state.alarm.is_none() {
            self.state.alarm = Some(alarm.clone());
            self.alarm_dirty = true;
            self.events.push(AppEvent::Alarm(alarm.clone()));
            if let Ok(tx) = self.tx() {
                // Keep the pending evidence after any failure, including an unknown
                // outcome; a later commit retries it before any reload can discard it.
                let _ = self.commit(tx).await;
            }
        }
        AppError::Alarm(alarm)
    }

    /// Take a call's result: note the service time of a checked answer, raise an alarm for
    /// a time that went back, and a rollback for an answer that contradicts itself (Switch
    /// spec 10.1).
    pub(crate) async fn take<T>(&mut self, result: Result<T, ClientError>) -> Result<T, AppError> {
        if Box::pin(self.observe_own_answer()).await?.is_some() {
            return Err(Self::later_generation_answer());
        }
        self.take_answer(result, true).await
    }

    fn later_generation_answer() -> AppError {
        Refusal::NotNow("the service answered for a later generation".into()).into()
    }

    /// [`App::take`] for an answer that binds no request of the app's, the public read's
    /// (Switch wire 7.1 "Identical requests"): it may be an earlier answer sent again, so it
    /// shows nothing about the account now, and starts no erasure wait over.
    pub(crate) async fn take_unbound<T>(
        &mut self,
        result: Result<T, ClientError>,
    ) -> Result<T, AppError> {
        self.take_answer(result, false).await
    }

    async fn take_answer<T>(
        &mut self,
        result: Result<T, ClientError>,
        bound: bool,
    ) -> Result<T, AppError> {
        if let Some(alarm) = self.note_service_time() {
            return Err(self.raise(alarm).await);
        }
        // An answer verified with the pinned key, an error answer included, to a request the
        // app signed: the account is there, and the erasure wait starts over (Switch spec
        // 12.7).
        if bound && matches!(result, Ok(_) | Err(ClientError::Switch { .. })) {
            self.clear_erasing().await?;
        }
        if result.is_err() {
            self.keep_observations().await?;
        }
        match result {
            Ok(value) => Ok(value),
            Err(ClientError::Chain(error)) => Err(self
                .raise(Alarm::Rollback {
                    reason: error.to_string(),
                })
                .await),
            Err(error) => Err(error.into()),
        }
    }

    /// Keep comparison and alarm evidence even when no other state needs a commit.
    async fn keep_observations(&mut self) -> Result<(), AppError> {
        if self.service_time_dirty || self.alarm_dirty {
            let tx = self.tx()?;
            self.commit(tx).await?;
        }
        Ok(())
    }

    /// Keep every comparable answer, independently of the latest stamped clock sample
    /// (Switch spec 10.1). The first backward answer of an internal retry also counts.
    fn note_service_time(&mut self) -> Option<Alarm> {
        let compared = self.client.compared_times()?;
        let key = self.state.meta.service_key;
        let held = self.state.service_time.filter(|held| held.key == key);
        let backwards = held
            .filter(|held| compared.first < held.highest_ms)
            .map(|held| (held.highest_ms, compared.first))
            .or(compared.backwards);
        let alarm =
            backwards.map(|(highest, signed)| Alarm::ServiceTimeBackwards { highest, signed });
        let highest_ms = held.map_or(compared.highest, |held| {
            held.highest_ms.max(compared.highest)
        });
        // A headless refusal supplies a lower bound, never a clock-offset sample: on an
        // idle account its last committed time may be days old (Switch wire 7.1).
        let stamped = self
            .client
            .latest_compared_time()
            .and(self.client.latest_server_time());
        let offset_ms = match stamped {
            Some(time) => {
                let local = self.clock.sample();
                let now = local.at_ms;
                self.time_fresh_at = Some(ServiceTimeSample {
                    local,
                    service_ms: time,
                });
                Some(
                    i64::try_from(time)
                        .unwrap_or(i64::MAX)
                        .saturating_sub(i64::try_from(now).unwrap_or(i64::MAX)),
                )
            }
            None => held.and_then(|held| held.offset_ms),
        };
        let record = ServiceTime {
            key,
            highest_ms,
            offset_ms,
        };
        if self.state.service_time != Some(record) {
            self.state.service_time = Some(record);
            self.service_time_dirty = true;
        }
        // The same bound governs automatic attempts and their warning. A headless answer
        // can prove the service ahead without measuring an offset (Switch spec 10.1).
        self.warn_clock_skew();
        alarm
    }

    fn warn_clock_skew(&mut self) {
        if let Some(skew_ms) = self.clock_skew_ms()
            && skew_ms > CLOCK_TOLERANCE_MS
        {
            let event = AppEvent::ClockSkew { skew_ms };
            if !self.events.contains(&event) {
                self.events.push(event);
            }
        }
    }

    /// `POST /ops` with a batch whose body the caller committed: the answer's head goes to
    /// the chain view, and a signed answer that contradicts itself is a rollback. Nothing
    /// but a provider loss's registration goes before the loss's upload (Switch spec 12.6
    /// step 3). A kept batch signed for an earlier generation has its proofs checked with
    /// that generation's key (Switch wire 6.4 step 6).
    pub(crate) async fn submit(&mut self, batch: &Batch) -> Result<Submitted, AppError> {
        let bounded = self.bound_service_cursor(batch, None)?;
        self.submit_body(bounded.as_ref().unwrap_or(batch), None)
            .await
    }

    /// Submit these exact bytes, including the selected service cursor.
    async fn submit_body(
        &mut self,
        batch: &Batch,
        first: Option<&crate::transport::FirstSend>,
    ) -> Result<Submitted, AppError> {
        self.refuse_before_upload_of(Some(batch)).await?;
        if batch
            .ops()
            .iter()
            .any(|op| matches!(op.body().kind, OpKind::AppPut { .. }))
        {
            self.record_send_gate()?;
        }
        self.note_cursor_sent(batch).await?;
        let generation = batch_generation(batch);
        let earlier_key = match generation.filter(|g| *g < self.state.meta.generation) {
            Some(earlier) => self.service_key_of(earlier).await?,
            None => None,
        };
        let result = match earlier_key.or_else(|| self.client.pinned_key()) {
            Some(key) => self.client.submit_before(batch, &key, first).await,
            None => Err(ClientError::Unpinned.into()),
        };
        let (result, error_head) = match result {
            Ok(submitted) => (Ok(submitted), None),
            Err(failure) => (Err(failure.error), failure.head),
        };
        let result = self.take(result).await;
        if let Err(AppError::Switch(ClientError::Switch {
            status: 409,
            code: pubky_switch_core::http::ErrorCode::Conflict,
            current,
            ..
        })) = &result
        {
            Box::pin(self.note_record_conflict(batch, current, error_head.as_deref())).await?;
        }
        let submitted = result?;
        if let Err(alarm) = self.note_answer_head(submitted.head, &submitted.proofs) {
            return Err(self.raise(alarm).await);
        }
        if let Some(position) = batch.cursor()
            && position.generation == self.state.cursor.generation
        {
            self.state.cursor.at_service = self.state.cursor.at_service.max(position.seq);
            if self.state.cursor.at_service >= self.state.cursor.seq {
                self.state.cursor.deferred_since_ms = None;
            }
            if let Some(chain) = self.state.chain.as_mut()
                && chain.restore == Some(RestorePending::Cursor)
            {
                chain.restore = Some(RestorePending::Read);
            }
        }
        Ok(submitted)
    }

    /// The head and proof stubs of a write answer: checked against the chain, and held as
    /// evidence until the feed reaches them (Switch wire 7.4.4).
    fn note_answer_head(
        &mut self,
        head: pubky_switch_core::chain::SignedHead,
        proofs: &[TransitionProof],
    ) -> Result<(), Alarm> {
        let time = self.client.last_server_time();
        let Some(chain) = self.state.chain.as_mut() else {
            return Ok(());
        };
        chain.observe_head(head).map_err(|error| match error {
            AppError::Alarm(alarm) => alarm,
            other => Alarm::Rollback {
                reason: other.to_string(),
            },
        })?;
        if let Some(time) = time {
            chain.note_held(head.seq, time);
            for proof in proofs {
                chain.note_held(proof.envelope().seq, time);
            }
        }
        Ok(())
    }

    /// The batch's operations, signed for the generation the app follows, with the
    /// deferred cursor move when there is room for it (Switch spec 8.2).
    pub(crate) fn sign_ops(
        &self,
        ops: Vec<(Vec<Condition>, OpKind)>,
        cursor_to: Option<u64>,
    ) -> Result<Batch, AppError> {
        let cursor = cursor_to
            .filter(|seq| *seq > self.state.cursor.at_service)
            .map(|seq| seq.min(self.put_back_limit(None)))
            .map(|seq| Position {
                generation: self.state.cursor.generation,
                seq,
            });
        Ok(self
            .client
            .sign_batch(self.state.meta.generation, ops, cursor)?)
    }

    /// The certificate changed: requests present the new one from now on.
    pub(crate) fn rebuild_client(&mut self) -> Result<(), AppError> {
        // A time an answer of the client before brought may be of another service: the
        // next stamp or window reads one from this client's service.
        self.time_fresh_at = None;
        let client = self.own_read_client()?;
        self.install_client(client);
        Ok(())
    }

    fn install_client(&mut self, client: SwitchClient) {
        self.client = client;
        self.client
            .hold_own_writes(self.recovery_required().map(|n| n.generation));
    }
}

/// The generation a batch's signed operations name; `None` for a cursor-only batch.
pub(crate) fn batch_generation(batch: &Batch) -> Option<u64> {
    batch.ops().first().map(|op| op.body().generation)
}

/// The local ID the first entry stored locally takes.
const FIRST_STORED_ID: u64 = 1;

/// The local ID the next entry stored locally takes: the one kept, and in any case past
/// every one taken, so none is used twice.
fn next_stored_id(kept: Option<u64>, parked: &BTreeMap<u64, ParkedEntry>) -> u64 {
    let past = parked
        .keys()
        .next_back()
        .map_or(FIRST_STORED_ID, |id| id.saturating_add(1));
    kept.unwrap_or(FIRST_STORED_ID).max(past)
}
