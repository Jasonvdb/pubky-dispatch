//! The account state a batch is checked against and changes (Dispatch wire 6.2 to 6.4), held
//! in memory: no HTTP, no storage, no clock.
//!
//! The endpoint loads from the store only what one batch can touch, which [`Needs`] names:
//! every app (an account holds at most its app limit), every registered kid, and the records,
//! claims, list entries, invite codes and key bundle parts the batch's operations and
//! conditions name. What the per-kind limits count over the rest of the account comes as
//! [`Totals`]. The batch is applied to a copy ([`super::apply`]), and the endpoint writes
//! back what the copy changed, all in the account's transaction.

use std::collections::{BTreeMap, BTreeSet};

use pubky_dispatch_core::{
    admission::{PeerEntry, PeerReason},
    claims::{Claim, ClaimTally},
    ops::{
        Condition, ConditionState, Held, KeyBundlePut, OpKind, Position, RecordVersion, SignedOp,
    },
    records::{AppCert, AppRecord, IdentityDoc, ReceiveKeyRecord, Standing},
    recovery::UploadBase,
    scopes::Permission,
    shared::{ApplicationRef, CurrentRecord, RecordState},
    sig::SignedDoc,
};
use serde_json::Value;

/// An own app as the account holds it.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct HeldApp {
    /// The app record the newest `app.put` stored, verified.
    pub record: Option<AppRecord>,
    /// When the service took it.
    pub record_at: Option<u64>,
    /// The renewed certificate a `cert.put` stored (Dispatch wire 3.8).
    pub renewed: Option<AppCert>,
    /// The current receive key record.
    pub receive_key: Option<ReceiveKeyRecord>,
    /// The app's cursor.
    pub cursor: Option<Position>,
    /// The `apps_version` at which it became reachable (Dispatch wire 7.4.10).
    pub reachable_since: Option<u64>,
    /// When a full key bundle was requested for it, while not yet covered.
    pub full_requested: Option<u64>,
    /// The `seq` of the part that completed its last full-bundle request (Dispatch wire 6.2).
    pub full_completed: Option<u64>,
}

impl HeldApp {
    pub(super) fn current_in(&self, doc: &IdentityDoc, app: &[u8; 16]) -> bool {
        let record_cert = self.record.as_ref().map(AppRecord::cert);
        [self.renewed.as_ref(), record_cert]
            .into_iter()
            .flatten()
            .any(|cert| doc.current_now(app, &cert.hash()))
    }
}

/// A shared record as the account holds it.
#[derive(Clone, Debug, PartialEq)]
pub struct HeldRecord {
    /// Its key, collection, policy, version and whether it is deleted.
    pub state: RecordState,
    /// The exact receiving application (Dispatch wire 6.3).
    pub revision: ApplicationRef,
    /// The bytes its value counts against the storage quota: its `ct`, 0 for a delete
    /// (Dispatch wire 9.1).
    pub value_bytes: u64,
    /// The writing app.
    pub writer: [u8; 16],
    /// The certificate the write was checked against.
    pub cert: SignedDoc,
    /// The signed `record.put`.
    pub op: SignedDoc,
    /// Where the write came from.
    pub origin: HeldOrigin,
    /// Uploads conflict with it (Dispatch wire 7.4.9 `divergent`); a write here clears them.
    pub divergent: bool,
}

/// Where a held record's current write came from (Dispatch wire 7.4.14, 10.3).
#[derive(Clone, Debug, PartialEq)]
pub enum HeldOrigin {
    /// A write made here.
    Written {
        /// Its transition proof; `None` only for a write of this batch, before it is signed.
        proof: Option<SignedDoc>,
        /// The uploaded version the first write here built on, with its operation's hash
        /// (Dispatch wire 10.3 `upload_base`).
        upload_base: Option<UploadBase>,
    },
    /// Taken from a recovery upload: no proof.
    Uploaded {
        /// The `upload` transition's `seq`.
        seq: u64,
        /// The lost service's proof gave its version.
        exact: bool,
        /// The proved immediate predecessor of this recovered write.
        parent: Option<[u8; 32]>,
    },
}

impl HeldRecord {
    /// The uploaded version that a write here on this record builds on, with its operation,
    /// which later uploads are compared with (Dispatch wire 7.4.14 "Writes at N win"): this
    /// record's when it was taken from an upload, else the one the writes here already built
    /// on. `None` for an uploaded record whose operation doesn't encode, which then counts
    /// as built on no upload, the stricter side.
    pub fn upload_base(&self) -> Option<UploadBase> {
        match &self.origin {
            HeldOrigin::Uploaded { .. } => Some(UploadBase {
                version: self.state.version,
                op_hash: self.op.doc_hash().ok()?,
            }),
            HeldOrigin::Written { upload_base, .. } => *upload_base,
        }
    }

    /// Its transition proof, once signed, for a write made here.
    pub fn proof(&self) -> Option<&SignedDoc> {
        match &self.origin {
            HeldOrigin::Written { proof, .. } => proof.as_ref(),
            HeldOrigin::Uploaded { .. } => None,
        }
    }
}

impl From<crate::store::StoredRecord> for HeldRecord {
    fn from(record: crate::store::StoredRecord) -> Self {
        use crate::store::RecordOrigin;
        Self {
            state: record.state,
            revision: record.revision,
            value_bytes: record.value_bytes,
            writer: record.writer,
            cert: record.cert,
            op: record.op,
            origin: match record.origin {
                RecordOrigin::Written { proof, upload_base } => HeldOrigin::Written {
                    proof: Some(proof),
                    upload_base,
                },
                RecordOrigin::Uploaded { seq, exact, parent } => {
                    HeldOrigin::Uploaded { seq, exact, parent }
                }
            },
            divergent: record.divergent,
        }
    }
}

/// An invite code as the account holds it.
#[derive(Clone, Debug, PartialEq)]
pub struct HeldInvite {
    /// How many appends it admits.
    pub max_uses: u64,
    /// How many it admitted.
    pub uses: u64,
    /// The writing app.
    pub writer: [u8; 16],
    /// When it expires.
    pub expires_at: u64,
}

impl HeldInvite {
    /// Whether it still admits: uses left, and not expired at `now`.
    pub fn live(&self, now: u64) -> bool {
        self.uses < self.max_uses && now < self.expires_at
    }
}

/// A key bundle part as the account holds it.
#[derive(Clone, Debug, PartialEq)]
pub struct HeldPart {
    /// The part.
    pub put: KeyBundlePut,
    /// The `seq` it was stored at.
    pub seq: u64,
    /// The signed `key_bundle.put`.
    pub op: SignedDoc,
}

/// A claim entry this batch wrote, kept for `GET /claims` once its proof is signed.
#[derive(Clone, Debug, PartialEq)]
pub struct NewClaimEntry {
    /// The claim key.
    pub claim_key: [u8; 32],
    /// The claim's step before the entry.
    pub step: u64,
    /// The entry's `seq`.
    pub seq: u64,
    /// The signed `claim`.
    pub op: SignedDoc,
}

/// What the per-kind limits count over the objects the state doesn't hold (Dispatch wire 9.3).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Totals {
    /// Live record keys.
    pub live_record_keys: u64,
    /// The bytes their values count.
    pub record_bytes: u64,
    /// The claims, and those of the batch's writer.
    pub claims: ClaimTally,
    /// Explicitly kept peers.
    pub kept: u64,
    /// Reply grants.
    pub replies: u64,
    /// Deny list entries.
    pub deny: u64,
    /// Live invite codes.
    pub live_invites: u64,
}

/// What a batch can touch, for the endpoint to load (Dispatch wire 6.2, 6.3).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Needs {
    /// Record keys its `record.put`s and conditions name.
    pub records: BTreeSet<[u8; 32]>,
    /// Claim keys its entries and conditions name.
    pub claims: BTreeSet<[u8; 32]>,
    /// Pubky IDs its list operations name.
    pub pubkys: BTreeSet<[u8; 32]>,
    /// Code hashes its invite code operations name.
    pub invites: BTreeSet<[u8; 32]>,
    /// Target apps of its `key_bundle.put`s.
    pub targets: BTreeSet<[u8; 16]>,
    /// Kids its `receive_key.put`s name, as their bodies read before they verify.
    pub kids: BTreeSet<[u8; 8]>,
}

/// The kid a receive key record names, read from its body before it verifies; `None` for
/// a body over its size cap, which is checked first and never read (Dispatch wire 3.4 Size),
/// or one that doesn't read, which its verification then refuses.
fn peek_kid(record: &SignedDoc) -> Option<[u8; 8]> {
    ReceiveKeyRecord::check_size(record).ok()?;
    let body: Value = serde_json::from_slice(&record.body_bytes().ok()?).ok()?;
    pubky_dispatch_core::enc::unb64_array::<8>(body.get("kid")?.as_str()?).ok()
}

impl Needs {
    /// What `ops` can touch.
    pub fn of(ops: &[SignedOp]) -> Self {
        let mut needs = Self::default();
        for op in ops {
            let body = op.body();
            for condition in &body.conditions {
                match condition {
                    Condition::RecordVersion { key, .. } | Condition::RecordCurrent { key, .. } => {
                        needs.records.insert(*key);
                    }
                    Condition::ClaimStep { claim_key, .. } => {
                        needs.claims.insert(*claim_key);
                    }
                    Condition::ServerTimeIn { .. } => {}
                }
            }
            match &body.kind {
                OpKind::RecordPut(put) => {
                    needs.records.insert(put.key);
                }
                OpKind::Claim(fields) => {
                    // A key of the wrong length is a shape refusal later; nothing to load.
                    if let Ok(key) = <[u8; 32]>::try_from(fields.claim_key.as_slice()) {
                        needs.claims.insert(key);
                    }
                }
                OpKind::AllowPut { pubky, .. }
                | OpKind::AllowDelete { pubky, .. }
                | OpKind::DenyPut { pubky }
                | OpKind::DenyDelete { pubky } => {
                    needs.pubkys.insert(*pubky);
                }
                OpKind::InviteCodePut(put) => {
                    needs.invites.insert(put.code_hash);
                }
                OpKind::InviteCodeDelete { code_hash } => {
                    needs.invites.insert(*code_hash);
                }
                OpKind::KeyBundlePut(put) => {
                    needs.targets.insert(put.target_app_id);
                }
                OpKind::ReceiveKeyPut { record } => {
                    needs.kids.extend(peek_kid(record));
                }
                OpKind::AppPut { .. } | OpKind::CertPut { .. } => {}
            }
        }
        needs
    }
}

/// The account state a batch is checked against and changes.
#[derive(Clone, Debug, PartialEq)]
pub struct OpsState {
    /// The account's identity key.
    pub identity: [u8; 32],
    /// The generation the account serves.
    pub generation: u64,
    /// The newest `seq` given out before the batch.
    pub newest_seq: u64,
    /// The service time of the batch.
    pub now: u64,
    /// The newest `identity.json` the account holds.
    pub doc: Option<IdentityDoc>,
    /// The account is recovering from a provider loss, so a first receive key may have any
    /// `n` (Dispatch spec 3.6).
    pub recovering: bool,
    /// Every own app it holds.
    pub apps: BTreeMap<[u8; 16], HeldApp>,
    /// App IDs kept for good: revoked, departed, or named by an enrollment.
    pub kept: BTreeSet<[u8; 16]>,
    /// The kids the batch names that some app registered, and those the batch registers.
    pub kids: BTreeSet<[u8; 8]>,
    /// The receive keys the batch registers, in order: each is kept, so no kid is
    /// registered twice (Dispatch spec 3.6).
    pub new_receive_keys: Vec<([u8; 16], ReceiveKeyRecord)>,
    /// The key bundle parts of the batch's targets, in `first_epoch` order.
    pub parts: BTreeMap<[u8; 16], Vec<HeldPart>>,
    /// Where each of the batch's targets' `keys_through` starts: the data epoch of the first
    /// `identity.json` that listed it, raised as the key bundle parts it passed went (Dispatch
    /// wire 7.4.12). A target no document listed here, or one purged, has none.
    pub listed_epochs: BTreeMap<[u8; 16], u64>,
    /// The records the batch names that exist.
    pub records: BTreeMap<[u8; 32], HeldRecord>,
    /// The claims the batch names that exist.
    pub claims: BTreeMap<[u8; 32], Claim>,
    /// Admission rows for the peers this batch names.
    pub peers: BTreeMap<[u8; 32], PeerEntry>,
    /// Denied peers named by the batch.
    pub deny: BTreeSet<[u8; 32]>,
    /// Pending connect requests answered by the batch, including a grant later removed.
    pub answered_connect: BTreeSet<[u8; 32]>,
    /// The invite codes the batch names that exist.
    pub invites: BTreeMap<[u8; 32], HeldInvite>,
    /// What the limits count over everything else.
    pub totals: Totals,
    /// The directory's versions (Dispatch wire 7.4.10).
    pub directory_version: u64,
    /// The version of the set of reachable apps.
    pub apps_version: u64,
    /// The claim entries the batch wrote.
    pub new_entries: Vec<NewClaimEntry>,
}

impl OpsState {
    /// An account's state with nothing loaded yet.
    pub fn new(identity: [u8; 32], generation: u64, newest_seq: u64, now: u64) -> Self {
        Self {
            identity,
            generation,
            newest_seq,
            now,
            doc: None,
            recovering: false,
            apps: BTreeMap::new(),
            kept: BTreeSet::new(),
            kids: BTreeSet::new(),
            new_receive_keys: Vec::new(),
            parts: BTreeMap::new(),
            listed_epochs: BTreeMap::new(),
            records: BTreeMap::new(),
            claims: BTreeMap::new(),
            peers: BTreeMap::new(),
            deny: BTreeSet::new(),
            answered_connect: BTreeSet::new(),
            invites: BTreeMap::new(),
            totals: Totals::default(),
            directory_version: 0,
            apps_version: 0,
            new_entries: Vec::new(),
        }
    }

    /// The account's current data epoch: the newest `identity.json`'s, 1 before any.
    pub fn data_epoch(&self) -> u64 {
        self.doc.as_ref().map_or(1, IdentityDoc::data_epoch)
    }

    /// The certificate an own app is checked against (Dispatch wire 3.8 "Which certificate"):
    /// its stored renewed certificate once the newest `identity.json` lists it, else its
    /// record's. `None` for an app without a record.
    pub fn checked_cert(&self, app: &[u8; 16]) -> Option<&AppCert> {
        let held = self.apps.get(app)?;
        let record_cert = held.record.as_ref().map(AppRecord::cert);
        match (&held.renewed, &self.doc) {
            (Some(renewed), Some(doc))
                if doc.standing(app, &renewed.hash()) == Standing::Listed =>
            {
                Some(renewed)
            }
            _ => record_cert,
        }
    }

    /// Whether `app` is served now: judged on the certificate it is checked against
    /// ([`Self::checked_cert`], wire 3.8 "Which certificate"), the one authentication uses:
    /// neither revoked nor departed, that certificate listed or in an open renewal in the
    /// newest `identity.json`, and unexpired (check 3). Not on whichever of the app's
    /// certificates passes: while a renewal's closing is pending, an earlier certificate
    /// still open must not keep an app served whose listed renewal has expired, since its
    /// requests are refused. Only the claim rules take it, for which an expired app counts
    /// as not current (spec 3.2, 10.2).
    pub fn is_served(&self, app: &[u8; 16]) -> bool {
        let (Some(doc), Some(cert)) = (&self.doc, self.checked_cert(app)) else {
            return false;
        };
        !self.kept.contains(app) && doc.current_now(app, &cert.hash()) && !cert.expired_at(self.now)
    }

    /// Whether `app` is current (Dispatch spec 3.4): neither revoked nor departed, and its
    /// record's certificate, or a renewed one, listed or in an open renewal in the newest
    /// `identity.json` (wire 3.8's standing, check 5). Expiry isn't part of it: a lapsed
    /// certificate stops the app being served (check 3), not current, and a renewal brings
    /// it back with nothing lost. So entries wait for it (wire 9.1), and an append's targets
    /// (7.4.3 check 5), `stale_key`'s members (7.6) and the directory (7.4.10) take it.
    pub fn is_current(&self, app: &[u8; 16]) -> bool {
        let (Some(held), Some(doc)) = (self.apps.get(app), &self.doc) else {
            return false;
        };
        if self.kept.contains(app) {
            return false;
        }
        held.current_in(doc, app)
    }

    /// The App IDs reachable (Dispatch wire 7.4.10): current ([`Self::is_current`]) and with
    /// a receive key.
    pub fn reachable_app_ids(&self) -> BTreeSet<[u8; 16]> {
        self.apps
            .iter()
            .filter(|(app, held)| held.receive_key.is_some() && self.is_current(app))
            .map(|(app, _)| *app)
            .collect()
    }

    /// The App IDs the directory lists (Dispatch wire 7.4.10): current, with a record.
    pub fn listed_app_ids(&self) -> BTreeSet<[u8; 16]> {
        self.apps
            .iter()
            .filter(|(app, held)| held.record.is_some() && self.is_current(app))
            .map(|(app, _)| *app)
            .collect()
    }

    /// After a change from `before`, the directory's two versions (Dispatch wire 7.4.10):
    /// - `directory_version` moves if the directory's apps changed and nothing this change
    ///   did moved it already (an app record, a receive key, a delivery or a revocation
    ///   does), as when a `cert.put` makes an app current or stops it being so;
    /// - `apps_version` moves once if the set of reachable apps changed, and only then, and
    ///   each app that became reachable takes the new version as its `reachable_since`, the
    ///   version from which a sender must wrap to it (7.4.3 check 5).
    pub fn settle_directory(&mut self, before: &OpsState) {
        if self.directory_version == before.directory_version
            && self.listed_app_ids() != before.listed_app_ids()
        {
            self.directory_version = self.directory_version.saturating_add(1);
        }
        let (was, now) = (before.reachable_app_ids(), self.reachable_app_ids());
        if now == was {
            return;
        }
        self.apps_version = self.apps_version.saturating_add(1);
        let version = self.apps_version;
        for app in now.difference(&was) {
            if let Some(held) = self.apps.get_mut(app) {
                held.reachable_since = Some(version);
            }
        }
    }

    /// The App IDs current ([`Self::is_current`]), expired ones included: the targets an
    /// inbox entry waits for (Dispatch wire 9.1) and the current targets of
    /// `sole_target_unread` (7.4.12).
    pub fn current_app_ids(&self) -> Vec<[u8; 16]> {
        self.apps
            .keys()
            .filter(|app| self.is_current(app))
            .copied()
            .collect()
    }

    /// The writer's view of a record, as `GET /records` returns it and a `409`'s
    /// `record_view` carries it (Dispatch wire 7.4.9).
    pub fn record_view(&self, key: &[u8; 32]) -> Option<Value> {
        self.records.get(key).map(record_view)
    }

    /// The claim tally the per-app limits compare an entry by `writer` with (Dispatch wire 6.8).
    pub fn claim_tally(&self, writer: &[u8; 16]) -> ClaimTally {
        let held = ClaimTally::count(self.claims.values(), writer);
        let totals = self.totals.claims;
        ClaimTally {
            claims: totals.claims.saturating_add(held.claims),
            created_by_writer: totals
                .created_by_writer
                .saturating_add(held.created_by_writer),
            open_attempts_of_writer: totals
                .open_attempts_of_writer
                .saturating_add(held.open_attempts_of_writer),
        }
    }

    /// Live record keys and the bytes they count, over the whole account.
    pub fn record_usage(&self) -> (u64, u64) {
        self.records
            .values()
            .filter(|held| !held.state.deleted)
            .fold(
                (self.totals.live_record_keys, self.totals.record_bytes),
                |(keys, bytes), held| {
                    (
                        keys.saturating_add(1),
                        bytes.saturating_add(held.value_bytes),
                    )
                },
            )
    }

    /// Live invite codes over the whole account.
    pub fn live_invites(&self) -> u64 {
        let held = self.invites.values().filter(|i| i.live(self.now)).count();
        self.totals
            .live_invites
            .saturating_add(u64::try_from(held).unwrap_or(u64::MAX))
    }
}

/// A record view (Dispatch wire 7.4.9).
pub fn record_view(held: &HeldRecord) -> Value {
    use pubky_dispatch_core::enc::{b64, zbase32_encode};
    let mut view = serde_json::json!({
        "key": b64(&held.state.key),
        "collection": b64(&held.state.collection),
        "read_scope": held.state.policy.read_scope,
        "write_scopes": held.state.policy.write_scopes,
        "generation": held.state.version.generation,
        "version": held.state.version.version,
        "revision": {
            "generation": held.revision.generation,
            "seq": held.revision.seq,
            "item_hash": b64(&held.revision.item_hash),
        },
        "seq": match held.origin {
            HeldOrigin::Uploaded { seq, .. } => seq,
            HeldOrigin::Written { .. } => held.state.version.version,
        },
        "deleted": held.state.deleted,
        "writer": zbase32_encode(&held.writer),
        "op": held.op,
        "divergent": held.divergent,
        "cert": held.cert,
    });
    if let Some(proof) = held.proof() {
        view["proof"] = serde_json::json!(proof);
    }
    view
}

impl Held for OpsState {
    fn app_record(&self, app_id: &[u8; 16]) -> Option<SignedDoc> {
        Some(self.apps.get(app_id)?.record.as_ref()?.signed().clone())
    }

    fn receive_key(&self, app_id: &[u8; 16]) -> Option<SignedDoc> {
        Some(
            self.apps
                .get(app_id)?
                .receive_key
                .as_ref()?
                .signed()
                .clone(),
        )
    }

    fn renewed_cert(&self, app_id: &[u8; 16]) -> Option<SignedDoc> {
        Some(self.apps.get(app_id)?.renewed.as_ref()?.signed().clone())
    }

    fn record_cert(&self, app_id: &[u8; 16]) -> Option<SignedDoc> {
        Some(
            self.apps
                .get(app_id)?
                .record
                .as_ref()?
                .cert()
                .signed()
                .clone(),
        )
    }

    fn holds_bundle_part(&self, part: &KeyBundlePut) -> bool {
        self.parts
            .get(&part.target_app_id)
            .is_some_and(|parts| parts.iter().any(|held| &held.put == part))
    }

    fn record_live(&self, key: &[u8; 32]) -> bool {
        self.records
            .get(key)
            .is_some_and(|held| !held.state.deleted)
    }

    fn allowed(&self, pubky: &[u8; 32], reason: PeerReason) -> bool {
        self.peers
            .get(pubky)
            .is_some_and(|peer| peer.has_reason(reason))
    }

    fn denied(&self, pubky: &[u8; 32]) -> bool {
        self.deny.contains(pubky)
    }
}

/// The state before a batch as its writer sees it, for its conditions (Dispatch wire 6.3).
pub struct Before<'a> {
    /// The state before the batch.
    pub state: &'a OpsState,
    /// The writer's certificate; `None` for the signer, who reads everything.
    pub writer: Option<&'a AppCert>,
}

impl ConditionState for Before<'_> {
    fn record_current(&self, key: &[u8; 32]) -> Option<CurrentRecord> {
        self.state.records.get(key).map(|held| CurrentRecord {
            revision: held.revision,
            deleted: held.state.deleted,
        })
    }

    fn record_view(&self, key: &[u8; 32]) -> Option<Value> {
        self.state.record_view(key)
    }

    fn record_version(&self, key: &[u8; 32]) -> RecordVersion {
        self.state
            .records
            .get(key)
            .map_or(RecordVersion::NONE, |held| held.state.version)
    }

    fn may_read_record(&self, key: &[u8; 32]) -> bool {
        self.state.records.get(key).is_none_or(|held| {
            self.writer
                .is_none_or(|cert| cert.holds_scope(&held.state.policy.read_scope))
        })
    }

    fn claim_step(&self, claim_key: &[u8; 32]) -> u64 {
        self.state
            .claims
            .get(claim_key)
            .map_or(0, |claim| claim.step)
    }

    fn claim_view(&self, claim_key: &[u8; 32]) -> Option<Value> {
        let current = |app: &[u8; 16]| self.state.is_served(app);
        self.state
            .claims
            .get(claim_key)
            .map(|claim| claim.view(claim_key, self.state.now, &current).to_value())
    }

    fn may_read_claims(&self) -> bool {
        self.writer
            .is_none_or(|cert| cert.has_permission(Permission::ClaimsRead))
    }

    fn server_time(&self) -> u64 {
        self.state.now
    }
}

#[cfg(test)]
mod tests {
    use pubky_dispatch_core::ops::sign_batch;
    use pubky_dispatch_core::records::MAX_RECEIVE_KEY_BODY_BYTES;

    use super::*;

    /// A batch with one `receive_key.put` whose record's body names a kid and is padded with
    /// whitespace to `len` bytes.
    fn put(len: usize) -> Vec<SignedOp> {
        let kid = pubky_dispatch_core::enc::b64(&[7; 8]);
        let mut body = format!(r#"{{"kid":"{kid}""#).into_bytes();
        body.resize(len - 1, b' ');
        body.push(b'}');
        let record = SignedDoc::from_parts(&body, &[0; 64]);
        let key = ed25519_dalek::SigningKey::from_bytes(&[1; 32]);
        let kinds = vec![(Vec::new(), OpKind::ReceiveKeyPut { record })];
        let identity = key.verifying_key().to_bytes();
        sign_batch(&key, &identity, None, 1, [4; 16], kinds).unwrap()
    }

    /// A record over its size cap is never read, so its kid never reaches the storage query
    /// the batch's state is loaded with (Dispatch wire 3.4 Size).
    #[test]
    fn test_needs_reads_no_kid_of_a_receive_key_record_over_its_size_cap() {
        let at_cap = Needs::of(&put(MAX_RECEIVE_KEY_BODY_BYTES));
        assert_eq!(at_cap.kids, BTreeSet::from([[7; 8]]));
        assert!(
            Needs::of(&put(MAX_RECEIVE_KEY_BODY_BYTES + 1))
                .kids
                .is_empty()
        );
    }
}
