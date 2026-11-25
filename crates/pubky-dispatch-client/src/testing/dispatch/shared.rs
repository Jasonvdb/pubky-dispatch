//! The scripted Dispatch's shared state: shared records, claims, the lists, invite codes and
//! connect requests, their reads (Dispatch wire 7.4.6 to 7.4.9), and the rules of their
//! operations (Dispatch wire 6.2, 6.8), which are the core's.

use std::collections::{BTreeMap, BTreeSet};

use pubky_dispatch_core::admission::PeerReason;
use pubky_dispatch_core::admission::{PeerEntry, ReplyGrant, ReplyOrigin};
use pubky_dispatch_core::chain::{ItemType, ProofState, TransitionProof, item_hash};
use pubky_dispatch_core::claims::{
    Claim, ClaimFields, ClaimLimits, ClaimTally, EntryContext, MAX_CLAIM_AGE_MS, apply_entry,
};
use pubky_dispatch_core::enc::{b64, pubky_id, unb64_array, zbase32_encode};
use pubky_dispatch_core::http::ErrorCode;
use pubky_dispatch_core::ops::OpKind;
use pubky_dispatch_core::ops::{
    ConditionState, InviteCodePut, MAX_INVITE_USES, Position, RecordPut, RecordVersion, Refusal,
    SignedOp, StateAfter, check_invite_code_put, proof_state,
};
use pubky_dispatch_core::records::AppCert;
use pubky_dispatch_core::recovery::{
    CheckedRecord, CheckedUpload, HeldRecord as MergeHeld, RecordDate, RecordSource, UploadBase,
    UploadBody, UploadChanges, UploadContext, UploadLists, merge_checked_record,
    merge_upload_claim,
};
use pubky_dispatch_core::scopes::Permission;
use pubky_dispatch_core::shared::{ApplicationRef, CurrentRecord, RecordState, check_record_put};
use pubky_dispatch_core::sig::SignedDoc;
use pubky_dispatch_core::time::rfc3339;
use serde_json::{Value, json};

use super::{Answer, DispatchApp, Inner, ScriptedDispatch, bad, parse_query};
use crate::clock::Clock;
use crate::transport::Request;

/// Divergent uploads kept per record: the wire's default `max_divergent_uploads` (Dispatch
/// wire 9.2).
const MAX_DIVERGENT_UPLOADS: usize = 8;

/// A shared record as the Dispatch holds it, with what its reads return (Dispatch wire 7.4.9).
#[derive(Clone, Debug)]
pub struct HeldRecord {
    /// The record's state after its newest write.
    pub state: RecordState,
    /// The actual receiving application (Dispatch wire 6.3).
    pub revision: ApplicationRef,
    /// The newest write's signed `record.put`.
    pub op: SignedDoc,
    /// The write's transition proof; `None` for a record taken from a recovery upload
    /// (Dispatch wire 7.4.9).
    pub proof: Option<SignedDoc>,
    /// The App ID that wrote it.
    pub writer: [u8; 16],
    /// The writer's certificate the Dispatch checked the write against, kept with the record:
    /// a renewal or revocation later doesn't change it (Dispatch wire 7.4.9). `None` for a
    /// record held without it, whose view carries the certificate of the writer's record.
    pub cert: Option<SignedDoc>,
    /// The write's `seq`; for a record taken from a recovery upload, the `upload`
    /// transition's.
    pub seq: u64,
    /// For a record taken from a recovery upload: whether the lost service's proof gave its
    /// version (Dispatch wire 7.4.14).
    pub uploaded: Option<bool>,
    /// The proved immediate predecessor of this recovered write.
    pub proved_parent: Option<[u8; 32]>,
    pub(crate) parent_copy: Option<Box<CheckedRecord>>,
    /// The uploaded version the first write here built on, with its operation's hash
    /// (Dispatch wire 10.3 `upload_base`).
    pub upload_base: Option<UploadBase>,
}

impl HeldRecord {
    fn recovered(&self) -> pubky_dispatch_core::Result<Option<CheckedRecord>> {
        let Some(exact) = self.uploaded else {
            return Ok(None);
        };
        let cert = self.cert.clone().ok_or_else(|| {
            pubky_dispatch_core::Error::Invalid("missing uploaded certificate".into())
        })?;
        CheckedRecord::from_storage(
            self.op.clone(),
            cert,
            exact.then_some(self.state.version.version),
        )
        .map(Some)
    }
}

/// An uploaded conflict, or the marker installed by the scripted divergence fixture.
#[derive(Clone, Debug)]
pub(crate) enum Retained {
    Upload(Box<CheckedRecord>),
    Marker([u8; 32]),
}

impl Retained {
    pub(super) fn hash(&self) -> [u8; 32] {
        match self {
            Self::Upload(record) => record.uploaded.op_hash,
            Self::Marker(hash) => *hash,
        }
    }

    pub(crate) fn record(&self) -> Option<&CheckedRecord> {
        match self {
            Self::Upload(record) => Some(record),
            Self::Marker(_) => None,
        }
    }
}

impl From<[u8; 32]> for Retained {
    fn from(hash: [u8; 32]) -> Self {
        Self::Marker(hash)
    }
}

/// An invite code the Dispatch holds (Dispatch spec 7).
#[derive(Clone, Debug)]
pub(crate) struct Invite {
    pub(crate) max_uses: u64,
    pub(crate) uses: u64,
    pub(crate) writer: [u8; 16],
    pub(crate) expires_at: u64,
}

/// One claim entry as `GET /claims` returns it.
#[derive(Clone, Debug)]
pub(crate) struct HeldEntry {
    step: u64,
    seq: u64,
    op: SignedDoc,
    proof: SignedDoc,
}

#[derive(Clone, Debug, Default)]
pub(crate) struct Shared {
    pub(crate) records: BTreeMap<[u8; 32], HeldRecord>,
    pub(crate) claims: BTreeMap<[u8; 32], Claim>,
    entries: BTreeMap<[u8; 32], Vec<HeldEntry>>,
    pub(crate) connect: Vec<([u8; 32], u64)>,
    /// By code hash.
    pub(crate) invites: BTreeMap<[u8; 32], Invite>,
    pub(crate) kept: BTreeSet<[u8; 32]>,
    /// The original writer and last use of each continuous reply grant.
    reply_grants: BTreeMap<[u8; 32], ReplyGrant>,
    pub(crate) deny: BTreeSet<[u8; 32]>,
    /// The bounded divergent operations kept for each key (Dispatch wire 7.4.14).
    pub(crate) divergent: BTreeMap<[u8; 32], Vec<Retained>>,
    /// Original dates established by matching receipts during recovery.
    record_dates: BTreeMap<[u8; 32], RecordDate>,
    /// The flagged senders `GET /allow` shows, with their hits (Dispatch wire 7.4.6).
    pub(crate) flagged: BTreeMap<[u8; 32], u64>,
    /// Answer the next record read without its proof, as after a recovery upload.
    pub(crate) hide_proofs: bool,
    /// A faulty listing: every page names these two keys as `next` in turn, for the first
    /// 50 pages.
    pub(crate) alternate_next: Option<([u8; 32], [u8; 32])>,
    /// Record keys requested, in order.
    #[cfg(test)]
    pub(crate) record_reads: Vec<[u8; 32]>,
    /// Listing pages answered.
    pub(crate) listings: u64,
    /// The service time of the last minute's sweep (Dispatch wire 9.1); none yet.
    pub(crate) swept_at: Option<u64>,
}

#[cfg(test)]
impl Shared {
    /// Hold an invite code as if `writer` had registered it, for a faulty service's export.
    pub(crate) fn plant_invite(&mut self, code_hash: [u8; 32], max_uses: u64, writer: [u8; 16]) {
        self.invites.insert(
            code_hash,
            Invite {
                max_uses,
                uses: 0,
                writer,
                expires_at: u64::MAX,
            },
        );
    }
}

/// What a shared operation is checked and applied with.
pub(super) struct OpContext<'a> {
    pub(super) limits: pubky_dispatch_core::ops::Limits,
    /// The writing app; `None` for the signer.
    pub(super) writer: Option<[u8; 16]>,
    /// The certificate the writer is checked against; `None` for the signer.
    pub(super) cert: Option<&'a AppCert>,
    /// The account's apps, for record views and claim views.
    pub(super) apps: &'a BTreeMap<[u8; 16], DispatchApp>,
    /// Whether an app is current (Dispatch spec 3.4).
    pub(super) is_current: &'a dyn Fn(&[u8; 16]) -> bool,
    /// The service time of the batch.
    pub(super) now: u64,
    /// The account's current data epoch.
    pub(super) data_epoch: u64,
}

impl OpContext<'_> {
    /// Whether the writer may read a record of `read_scope` (the signer reads everything).
    fn may_read(&self, read_scope: &str) -> bool {
        self.cert.is_none_or(|cert| cert.holds_scope(read_scope))
    }

    /// Whether the writer holds `claims.read`.
    fn may_read_claims(&self) -> bool {
        self.cert
            .is_none_or(|cert| cert.has_permission(Permission::ClaimsRead))
    }
}

/// The state before a batch, for its conditions (Dispatch wire 6.3).
pub(super) struct Before<'a> {
    pub(super) shared: &'a Shared,
    pub(super) cx: &'a OpContext<'a>,
}

impl ConditionState for Before<'_> {
    fn record_current(&self, key: &[u8; 32]) -> Option<CurrentRecord> {
        self.shared.records.get(key).map(|held| CurrentRecord {
            revision: held.revision,
            deleted: held.state.deleted,
        })
    }

    fn record_view(&self, key: &[u8; 32]) -> Option<Value> {
        self.shared.records.get(key).map(|held| {
            record_view(
                held,
                self.cx.apps,
                true,
                self.shared.divergent.contains_key(key),
            )
        })
    }

    fn record_version(&self, key: &[u8; 32]) -> RecordVersion {
        self.shared
            .records
            .get(key)
            .map_or(RecordVersion::NONE, |held| held.state.version)
    }

    fn may_read_record(&self, key: &[u8; 32]) -> bool {
        self.shared
            .records
            .get(key)
            .is_none_or(|held| self.cx.may_read(&held.state.policy.read_scope))
    }

    fn claim_step(&self, claim_key: &[u8; 32]) -> u64 {
        self.shared
            .claims
            .get(claim_key)
            .map_or(0, |claim| claim.step)
    }

    fn claim_view(&self, claim_key: &[u8; 32]) -> Option<Value> {
        self.shared.claims.get(claim_key).map(|claim| {
            claim
                .view(claim_key, self.cx.now, self.cx.is_current)
                .to_value()
        })
    }

    fn may_read_claims(&self) -> bool {
        self.cx.may_read_claims()
    }

    fn server_time(&self) -> u64 {
        self.cx.now
    }
}

/// A record's view, as `GET /records` returns it (Dispatch wire 7.4.9): its `cert` is the one
/// the write was checked against, or for a record held without it, the one the writer's
/// record carries.
fn record_view(
    held: &HeldRecord,
    apps: &BTreeMap<[u8; 16], DispatchApp>,
    proof: bool,
    divergent: bool,
) -> Value {
    let cert = held.cert.clone().or_else(|| {
        apps.get(&held.writer)
            .and_then(|app| app.cert.clone())
            .map(|cert| cert.signed().clone())
    });
    let mut view = json!({
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
        "seq": held.seq,
        "deleted": held.state.deleted,
        "writer": zbase32_encode(&held.writer),
        "op": held.op,
        "divergent": divergent,
        "cert": cert,
    });
    if proof && let Some(signed) = &held.proof {
        view["proof"] = json!(signed);
    }
    view
}

/// The rules of the shared operations, each against the state the earlier operations of its
/// batch left. Records and claim entries are kept once their proof is signed, by
/// [`Shared::record_written`] and [`Shared::claim_written`].
impl Shared {
    /// `record.put` (Dispatch wire 6.2, Dispatch spec 10.3), by [`check_record_put`].
    pub(super) fn record_put(
        &self,
        op: &SignedOp,
        cx: &OpContext<'_>,
        generation: u64,
        seq: u64,
    ) -> Result<ProofState, Refusal> {
        let OpKind::RecordPut(put) = &op.body().kind else {
            return Err(Refusal::bad_request(
                "Dispatch wire 6.2: a record write is required",
            ));
        };
        let held = self.records.get(&put.key);
        let divergent = self.divergent.contains_key(&put.key);
        let view = held.map(|h| record_view(h, cx.apps, true, divergent));
        check_record_put(
            put,
            &op.body().conditions,
            held.map(|h| (&h.state, h.revision)),
            cx.data_epoch,
            cx.may_read(&put.policy.read_scope),
            view.as_ref(),
        )?;
        proof_state(op, &StateAfter::Record(RecordVersion::new(generation, seq)))
            .map_err(Refusal::from)
    }

    /// The generations the kept proofs name (Dispatch wire 3.3 "Service keys"): each held
    /// record's current write's proof, and each entry proof of a live claim, not a
    /// tombstone. A proof that doesn't read is left out.
    pub(crate) fn kept_proof_generations(&self) -> (Vec<u64>, Vec<u64>) {
        let generation = |proof: &SignedDoc| {
            TransitionProof::peek(proof)
                .ok()
                .map(|p| p.envelope().generation)
        };
        let records = self
            .records
            .values()
            .filter_map(|held| held.proof.as_ref().and_then(generation))
            .collect();
        let entries = self
            .entries
            .iter()
            .filter(|(key, _)| self.claims.get(*key).is_some_and(|c| !c.tombstone))
            .flat_map(|(_, entries)| entries.iter().filter_map(|e| generation(&e.proof)))
            .collect();
        (records, entries)
    }

    /// Whether the entry at `seq` belongs to the claim held at `claim_key`, and that claim
    /// isn't a tombstone: a compacted or deleted claim's entries are gone (Dispatch wire 6.8
    /// "Tombstones", 7.5).
    pub(super) fn claim_entry_current(&self, claim_key: &[u8; 32], seq: u64) -> bool {
        self.claims.get(claim_key).is_some_and(|c| !c.tombstone)
            && self
                .entries
                .get(claim_key)
                .is_some_and(|entries| entries.iter().any(|e| e.seq == seq))
    }

    /// Keep a written record with its proof. A write here clears the record's divergent
    /// uploads, and builds on the upload it replaces (Dispatch wire 7.4.14 "Writes at N win").
    pub(super) fn record_written(
        &mut self,
        put: &RecordPut,
        written: Written<'_>,
    ) -> pubky_dispatch_core::Result<()> {
        let upload_base = self
            .records
            .get(&put.key)
            .and_then(|held| match held.uploaded {
                Some(_) => Some(UploadBase {
                    version: held.state.version,
                    op_hash: held.op.doc_hash().ok()?,
                }),
                None => held.upload_base,
            });
        self.divergent.remove(&put.key);
        self.records.insert(
            put.key,
            HeldRecord {
                state: RecordState::after(put, written.generation, written.seq),
                revision: ApplicationRef {
                    generation: written.generation,
                    seq: written.seq,
                    item_hash: written.op.item_hash()?,
                },
                op: written.op.signed().clone(),
                proof: Some(written.proof.clone()),
                writer: written.writer,
                cert: written.cert.map(|cert| cert.signed().clone()),
                seq: written.seq,
                uploaded: None,
                proved_parent: None,
                parent_copy: None,
                upload_base,
            },
        );
        Ok(())
    }

    /// Withdraw disqualified provisional writes before ordering the remaining uploads
    /// (Dispatch wire 7.4.14).
    pub(super) fn review_record_uploads(
        &mut self,
        checked: &mut CheckedUpload,
        upload: &UploadBody,
        cx: &UploadContext<'_>,
        changes: &mut UploadChanges,
    ) -> pubky_dispatch_core::Result<()> {
        let keys: BTreeSet<_> = checked
            .record_proofs
            .keys()
            .copied()
            .chain(checked.record_candidates().map(|r| r.put.key))
            .collect();
        let mut children = Vec::new();
        let mut held = Vec::new();
        for key in &keys {
            if let Some(row) = self.records.get(key)
                && let Some(record) = row.recovered()?
            {
                if row.proved_parent.is_some() && !record.uploaded.version.exact {
                    children.push(record);
                } else {
                    held.push(record);
                }
            }
            held.extend(
                self.divergent
                    .get(key)
                    .into_iter()
                    .flatten()
                    .filter_map(Retained::record)
                    .cloned(),
            );
        }
        let needed =
            checked.needed_parents(&children, &self.record_dates, cx.removed, cx.renewed)?;
        let mut missing = BTreeSet::new();
        for child in &children {
            let key = child.put.key;
            let Some(row) = self.records.get_mut(&key) else {
                continue;
            };
            if !needed.contains(&child.uploaded.op_hash) {
                row.parent_copy = None;
                continue;
            }
            let parent = row.parent_copy.as_deref().and_then(|p| {
                CheckedRecord::verified_parent(
                    p.op.clone(),
                    p.cert.clone(),
                    cx.identity,
                    &key,
                    child.uploaded.built_on,
                    row.proved_parent?,
                )
                .filter(|verified| verified == p)
            });
            if let Some(parent) = parent {
                held.push(parent);
            } else {
                missing.insert(key);
                row.proved_parent = None;
                row.parent_copy = None;
            }
        }
        let review = checked.review_available_records(
            children.iter().chain(&held),
            &self.record_dates,
            cx.removed,
            cx.renewed,
            &missing,
            &upload.records,
        )?;
        for (hash, date) in review.record_dates {
            self.record_dates.entry(hash).or_insert(date);
        }
        changes.unverified = review.unverified;
        changes.distrusted = review.distrusted;
        let mut remaining = Vec::new();
        for key in keys {
            let remove = self
                .records
                .get(&key)
                .filter(|r| r.uploaded.is_some())
                .map(|r| r.op.doc_hash())
                .transpose()?
                .is_some_and(|hash| review.discard.contains(&hash));
            if let Some(record) = self.records.get_mut(&key)
                && record
                    .parent_copy
                    .as_ref()
                    .is_some_and(|r| review.discard.contains(&r.uploaded.op_hash))
            {
                record.parent_copy = None;
                record.proved_parent = None;
            }
            if remove {
                remaining.extend(
                    self.records
                        .remove(&key)
                        .and_then(|r| r.parent_copy)
                        .map(|r| *r),
                );
                remaining.extend(
                    self.divergent
                        .remove(&key)
                        .into_iter()
                        .flatten()
                        .filter_map(|r| match r {
                            Retained::Upload(r)
                                if !review.discard.contains(&r.uploaded.op_hash) =>
                            {
                                Some(*r)
                            }
                            Retained::Upload(_) | Retained::Marker(_) => None,
                        }),
                );
                changes.record(key);
            } else if let Some(entries) = self.divergent.get_mut(&key) {
                let count = entries.len();
                entries.retain(|r| !review.discard.contains(&r.hash()));
                if entries.len() != count {
                    changes.record(key);
                }
                if entries.is_empty() {
                    self.divergent.remove(&key);
                }
            }
        }
        remaining.extend(review.records);
        checked.records = remaining;
        Ok(())
    }

    /// `429 quota_exceeded` (`deny`, with `over`) when the upload's new deny entries would
    /// take the deny list past its fixed limit, as the service judges it before anything
    /// merges (Dispatch wire 7.4.14 "Lists").
    pub(super) fn deny_room(
        &self,
        lists: Option<&UploadLists>,
    ) -> Result<(), pubky_dispatch_core::ops::Refusal> {
        let Some(deny) = lists.and_then(|lists| lists.deny.as_ref()) else {
            return Ok(());
        };
        let held = u64::try_from(self.deny.len()).unwrap_or(u64::MAX);
        pubky_dispatch_core::recovery::check_deny_room(held, deny, |pubky| {
            self.deny.contains(pubky)
        })
    }

    /// Merge what counted in a recovery upload after a provider loss, as the service does
    /// (Dispatch wire 7.4.14): records taken at `seq`, the `upload` transition's, or kept as
    /// divergent; claims; and the lists, only added to: kept peers up to `max_kept_peers`,
    /// and every deny entry, which [`Self::deny_room`] has checked fits.
    pub(super) fn merge_upload(
        &mut self,
        checked: &CheckedUpload,
        lists: Option<&UploadLists>,
        max_kept_peers: u64,
        position: Position,
        now: u64,
        changes: &mut UploadChanges,
    ) -> pubky_dispatch_core::Result<()> {
        let seq = position.seq;
        for record in &checked.records {
            let key = record.put.key;
            let kept = self
                .divergent
                .get(&key)
                .map(Vec::as_slice)
                .unwrap_or_default();
            let hashes: Vec<_> = kept.iter().map(Retained::hash).collect();
            let held = self.records.get(&key);
            let current = held.map(HeldRecord::recovered).transpose()?.flatten();
            let view = match (&current, held) {
                (Some(r), _) => MergeHeld::FromUpload {
                    op_hash: r.uploaded.op_hash,
                    built_on: r.uploaded.built_on,
                    version: r.uploaded.version,
                    divergent: &hashes,
                },
                (_, Some(h)) => MergeHeld::WrittenHere {
                    upload_base: h.upload_base,
                    divergent: &hashes,
                },
                _ => MergeHeld::Lacking,
            };
            let parent = held.and_then(|h| h.proved_parent);
            let comparison = merge_checked_record(
                &view,
                held.map(|h| &h.state),
                parent,
                kept.iter()
                    .enumerate()
                    .filter_map(|(i, r)| Some((i, r.record()?))),
                record,
                MAX_DIVERGENT_UPLOADS,
            );
            let source = |s| {
                match s {
                    RecordSource::Incoming => Some(record),
                    RecordSource::Current => current.as_ref(),
                    RecordSource::Retained(i) => kept.get(i).and_then(Retained::record),
                }
                .ok_or_else(|| {
                    pubky_dispatch_core::Error::Invalid("missing retained record".into())
                })
            };
            let install = comparison.install.map(source).transpose()?.cloned();
            let parent_copy = comparison
                .reinstate
                .map(source)
                .transpose()?
                .cloned()
                .map(Box::new)
                .or_else(|| {
                    held.filter(|_| parent == comparison.parent)
                        .and_then(|h| h.parent_copy.clone())
                });
            if let Some((slot, s)) = comparison.keep {
                let retained = Retained::Upload(Box::new(source(s)?.clone()));
                let entries = self.divergent.entry(key).or_default();
                if slot == entries.len() {
                    entries.push(retained);
                } else {
                    entries[slot] = retained;
                }
            }
            for slot in comparison.remove {
                let entries = self.divergent.get_mut(&key).ok_or_else(|| {
                    pubky_dispatch_core::Error::Invalid("missing retained record".into())
                })?;
                entries.remove(slot);
                if entries.is_empty() {
                    self.divergent.remove(&key);
                }
            }
            if let Some(selected) = install {
                let revision = ApplicationRef {
                    generation: position.generation,
                    seq,
                    item_hash: item_hash(ItemType::Op, &selected.op.doc_bytes()?),
                };
                revision.check()?;
                let state = RecordState {
                    version: selected.uploaded.version.version,
                    ..RecordState::after(&selected.put, 0, 0)
                };
                self.records.insert(
                    key,
                    HeldRecord {
                        state,
                        revision,
                        op: selected.op,
                        proof: None,
                        writer: selected.writer,
                        cert: Some(selected.cert),
                        seq,
                        uploaded: Some(selected.uploaded.version.exact),
                        proved_parent: comparison.parent,
                        parent_copy: parent_copy.filter(|_| !selected.uploaded.version.exact),
                        upload_base: None,
                    },
                );
                changes.record(key);
            } else if parent != comparison.parent
                && let Some(held) = self.records.get_mut(&key)
            {
                held.proved_parent = comparison.parent;
                held.parent_copy = parent_copy;
            }
            if comparison.divergent {
                changes.divergent_record(key);
            }
        }
        let keys: BTreeSet<[u8; 32]> = checked
            .claims
            .keys()
            .chain(checked.settled.keys())
            .copied()
            .collect();
        for key in keys {
            let entries = checked.claims.get(&key).map_or(&[][..], Vec::as_slice);
            let merge = merge_upload_claim(
                self.claims.get(&key),
                checked.settled.get(&key),
                entries,
                now,
                ClaimLimits::default().max_attempts_per_claim,
            );
            if merge.changed
                && let Some(claim) = &merge.claim
            {
                self.claims.insert(key, claim.clone());
            }
            changes.claim(key, &merge);
        }
        if let Some(lists) = lists {
            for (list, entries, max) in [
                (&mut self.kept, &lists.kept, max_kept_peers),
                (&mut self.deny, &lists.deny, u64::MAX),
            ] {
                // Kept peers past their limit are dropped; deny entries never are (Dispatch wire
                // 7.4.14 "Lists"). Each entry the merge writes answers the sender's connect
                // request, as any list entry does (7.4.7).
                for pubky in entries.iter().flatten() {
                    if !list.contains(pubky) && u64::try_from(list.len()).unwrap_or(u64::MAX) < max
                    {
                        list.insert(*pubky);
                        self.connect.retain(|(pending, _)| pending != pubky);
                        changes.lists = true;
                    }
                }
            }
        }
        Ok(())
    }

    /// A claim entry (Dispatch wire 6.8), by [`apply_entry`] with the default limits.
    pub(super) fn claim(
        &mut self,
        fields: &ClaimFields,
        cx: &OpContext<'_>,
    ) -> Result<ProofState, Refusal> {
        let entry = fields.check()?;
        let writer = cx.writer.unwrap_or_default();
        let entry_cx = EntryContext {
            writer,
            now: cx.now,
            can_read: cx.may_read_claims(),
            is_current: cx.is_current,
            limits: ClaimLimits::default(),
            tally: ClaimTally::count(self.claims.values(), &writer),
        };
        let claim = apply_entry(self.claims.get(&entry.claim_key), &entry, &entry_cx)?;
        let view = claim
            .view(&entry.claim_key, cx.now, cx.is_current)
            .to_value();
        self.claims.insert(entry.claim_key, claim);
        Ok(ProofState::Claim(view))
    }

    /// Keep a claim entry with its proof, for `GET /claims`.
    pub(super) fn claim_written(&mut self, fields: &ClaimFields, written: Written<'_>) {
        let Ok(entry) = fields.check() else {
            return;
        };
        self.entries
            .entry(entry.claim_key)
            .or_default()
            .push(HeldEntry {
                step: fields.expected_step,
                seq: written.seq,
                op: written.op.signed().clone(),
                proof: written.proof.clone(),
            });
    }

    /// `invite_code.put` (Dispatch wire 6.2), by [`check_invite_code_put`].
    pub(super) fn invite_code_put(
        &mut self,
        put: &InviteCodePut,
        cx: &OpContext<'_>,
    ) -> Result<ProofState, Refusal> {
        check_invite_code_put(
            put,
            MAX_INVITE_USES,
            self.invites.contains_key(&put.code_hash),
        )?;
        self.invites.insert(
            put.code_hash,
            Invite {
                max_uses: put.max_uses,
                uses: 0,
                writer: cx.writer.unwrap_or_default(),
                expires_at: put.expires_at,
            },
        );
        Ok(ProofState::InviteCodePut {
            max_uses: put.max_uses,
        })
    }

    /// `invite_code.delete` (Dispatch wire 6.2): the core has no rule for it that needs state;
    /// a code that isn't registered is `404`.
    pub(super) fn invite_code_delete(
        &mut self,
        code_hash: &[u8; 32],
    ) -> Result<ProofState, Refusal> {
        if self.invites.remove(code_hash).is_none() {
            return Err(Refusal::new(
                ErrorCode::NotFound,
                "Dispatch wire 6.2: no such invite code",
            ));
        }
        Ok(ProofState::InviteCodeDelete)
    }

    /// `allow.put` (Dispatch wire 6.2): the entry, and the sender's connect request goes
    /// (Dispatch wire 7.4.7).
    pub(super) fn allow_put(
        &mut self,
        pubky: &[u8; 32],
        reason: PeerReason,
        cx: &OpContext<'_>,
    ) -> Result<ProofState, Refusal> {
        self.check_peer_capacity(pubky, reason, &cx.limits)?;
        match reason {
            PeerReason::Kept => {
                self.kept.insert(*pubky);
            }
            PeerReason::Reply => {
                self.grant_reply(
                    *pubky,
                    ReplyOrigin::App(cx.writer.unwrap_or_default()),
                    cx.now,
                );
            }
        }
        self.connect.retain(|(p, _)| p != pubky);
        Ok(ProofState::Allow {
            reason,
            present: true,
        })
    }

    /// A kept peer the account holds without an operation that wrote it, as an upload after a
    /// provider loss brings one back (Dispatch spec 12.6 step 2).
    #[cfg(test)]
    pub(crate) fn keep_peer(&mut self, pubky: [u8; 32]) {
        self.kept.insert(pubky);
    }

    pub(super) fn grant_reply(&mut self, pubky: [u8; 32], origin: ReplyOrigin, at: u64) {
        self.reply_grants.entry(pubky).or_insert(ReplyGrant {
            origin,
            at,
            last_used: None,
        });
    }

    /// Note an admitted append's time on `sender`'s reply grant, an app's or the
    /// service's, if it has one (Dispatch spec 7 "Pruning", Dispatch wire 7.4.6 `last_used`).
    pub(super) fn note_reply_grant_used(&mut self, sender: &[u8; 32], at: u64) {
        if let Some(grant) = self.reply_grants.get_mut(sender) {
            grant.last_used = Some(at);
        }
    }

    /// `allow.delete` (Dispatch wire 6.2); a reply grant goes whoever wrote it.
    pub(super) fn allow_delete(&mut self, pubky: &[u8; 32], kind: PeerReason) -> ProofState {
        match kind {
            PeerReason::Kept => self.kept.remove(pubky),
            PeerReason::Reply => self.reply_grants.remove(pubky).is_some(),
        };
        ProofState::Allow {
            reason: kind,
            present: false,
        }
    }

    /// `deny.put` and `deny.delete` (Dispatch wire 6.2); a denial ends the connect request.
    /// A `deny.put` or `deny.delete`. A new entry past the deny limit is `429
    /// quota_exceeded` (`deny`), as at the service; a delete always passes (Dispatch wire 9.3).
    pub(super) fn deny(&mut self, pubky: &[u8; 32], denied: bool) -> Result<ProofState, Refusal> {
        if denied {
            use pubky_dispatch_core::ops::{List, Quota, check_quota};
            check_quota(
                &Quota::List {
                    list: List::Deny,
                    entries: u64::try_from(self.deny.len()).unwrap_or(u64::MAX),
                    present: self.deny.contains(pubky),
                },
                &pubky_dispatch_core::ops::Limits::default(),
            )?;
            self.deny.insert(*pubky);
            self.connect.retain(|(p, _)| p != pubky);
        } else {
            self.deny.remove(pubky);
        }
        Ok(ProofState::Deny { denied })
    }

    /// Whether a record's current write isn't a delete.
    pub(super) fn record_live(&self, key: &[u8; 32]) -> bool {
        self.records
            .get(key)
            .is_some_and(|held| !held.state.deleted)
    }

    /// Whether the allowlist holds the entry.
    pub(super) fn allowed(&self, pubky: &[u8; 32], kind: PeerReason) -> bool {
        match kind {
            PeerReason::Kept => self.kept.contains(pubky),
            PeerReason::Reply => self.reply_grants.contains_key(pubky),
        }
    }

    pub(super) fn check_peer_capacity(
        &self,
        pubky: &[u8; 32],
        reason: PeerReason,
        limits: &pubky_dispatch_core::ops::Limits,
    ) -> Result<(), Refusal> {
        use pubky_dispatch_core::ops::{List, Quota, check_quota};
        let (list, count) = match reason {
            PeerReason::Kept => (List::KeptPeers, self.kept.len()),
            PeerReason::Reply => (List::ReplyPeers, self.reply_grants.len()),
        };
        check_quota(
            &Quota::List {
                list,
                entries: u64::try_from(count).unwrap_or(u64::MAX),
                present: self.allowed(pubky, reason),
            },
            limits,
        )
    }

    /// Whether the deny list holds the Pubky ID.
    pub(super) fn denied(&self, pubky: &[u8; 32]) -> bool {
        self.deny.contains(pubky)
    }
}

/// `403 permission_missing`, for a read the caller may not make.
fn permission_missing(message: &str) -> Answer {
    bad(ErrorCode::PermissionMissing, message, json!(null))
}

/// A written operation, once its proof is signed.
pub(super) struct Written<'a> {
    pub(super) op: &'a SignedOp,
    pub(super) proof: &'a SignedDoc,
    pub(super) writer: [u8; 16],
    /// The certificate the writer was checked against; `None` for the signer.
    pub(super) cert: Option<&'a AppCert>,
    pub(super) generation: u64,
    pub(super) seq: u64,
}

impl ScriptedDispatch {
    /// A pending connect request from `pubky` (Dispatch wire 7.4.7).
    pub fn push_connect(&self, pubky: [u8; 32]) {
        let mut inner = self.lock();
        let now = inner.clock.now_ms();
        inner.shared.connect.push((pubky, now));
    }

    /// The identities with a pending connect request.
    pub fn connects(&self) -> Vec<[u8; 32]> {
        self.lock().shared.connect.iter().map(|(p, _)| *p).collect()
    }

    /// The shared record the Dispatch holds at `key`, deleted or not.
    pub fn record(&self, key: &[u8; 32]) -> Option<HeldRecord> {
        self.lock().shared.records.get(key).cloned()
    }

    /// The claim the Dispatch holds for `claim_key`.
    pub fn claim(&self, claim_key: &[u8; 32]) -> Option<Claim> {
        self.lock().shared.claims.get(claim_key).cloned()
    }
}

impl Inner {
    /// Whether own app `caller` holds `permission` by the certificate its record carries;
    /// never for the signer (`None`).
    fn caller_holds(&self, caller: Option<[u8; 16]>, permission: Permission) -> bool {
        caller
            .and_then(|app| self.apps.get(&app))
            .and_then(|app| app.cert.as_ref())
            .is_some_and(|cert| cert.has_permission(permission))
    }

    /// The reads of the shared state, for `caller` (`None` for the signer); `None` for any
    /// other route.
    pub(super) fn route_shared(
        &mut self,
        request: &Request,
        caller: Option<[u8; 16]>,
        rest: &str,
    ) -> Option<Answer> {
        let (route, query) = rest.split_once('?').unwrap_or((rest, ""));
        Some(match (request.method.as_str(), route) {
            // Own apps holding `lists.read` only, as at the service
            // (`crates/pubky-dispatch/src/service/allow.rs`), whatever the answer.
            ("GET", "allow") if !self.caller_holds(caller, Permission::ListsRead) => bad(
                ErrorCode::PermissionMissing,
                "7.4.6: reading the lists needs lists.read",
                json!(null),
            ),
            // A scripted answer, for a faulty service, takes precedence.
            ("GET", "allow") if self.allow.is_none() => self.allow_list(),
            // Apps of another identity ask to connect (`inbox.rs`); the account's own apps
            // and its signer don't.
            ("POST", "connect") => bad(
                ErrorCode::PermissionMissing,
                "7.4.7: apps of another identity ask to connect",
                json!(null),
            ),
            // Own apps only, each with its permission, as at the service
            // (`crates/pubky-dispatch/src/service/connect.rs`).
            ("GET", "connect") => {
                if !self.caller_holds(caller, Permission::ListsRead) {
                    return Some(bad(
                        ErrorCode::PermissionMissing,
                        "7.4.7: reading connect requests needs lists.read",
                        json!(null),
                    ));
                }
                let requests: Vec<Value> = self
                    .shared
                    .connect
                    .iter()
                    .map(|(pubky, at)| json!({ "pubky": pubky_id(pubky), "at": rfc3339(*at) }))
                    .collect();
                let max_pending = self.connect_cap();
                let full = u64::try_from(requests.len()).unwrap_or(u64::MAX) >= max_pending;
                (
                    200,
                    json!({ "requests": requests, "max_pending": max_pending, "full": full }),
                )
            }
            ("DELETE", r) if r.starts_with("connect/") => {
                if !self.caller_holds(caller, Permission::ReplyAdd) {
                    return Some(bad(
                        ErrorCode::PermissionMissing,
                        "7.4.7: declining a connect request needs reply.add",
                        json!(null),
                    ));
                }
                let id = r.trim_start_matches("connect/");
                let pubky = pubky_dispatch_core::enc::pubky_key(id).ok()?;
                let before = self.shared.connect.len();
                self.shared.connect.retain(|(p, _)| *p != pubky);
                if self.shared.connect.len() == before {
                    return Some(bad(ErrorCode::NotFound, "no request", json!(null)));
                }
                (200, json!({ "declined": id }))
            }
            ("GET", "records") => self.list_records(caller, query),
            ("GET", r) if r.starts_with("records/") => {
                self.record_answer(caller, r.trim_start_matches("records/"))
            }
            ("GET", r) if r.starts_with("claims/") => {
                // Only an own app holding `claims.read`, before the key is read
                // (`crates/pubky-dispatch/src/service/claims.rs`, `get_claim`).
                let reads = caller
                    .and_then(|app| self.checked_cert(&app))
                    .is_some_and(|cert| cert.has_permission(Permission::ClaimsRead));
                if !reads {
                    return Some(permission_missing(
                        "7.4.8: reading claims needs claims.read",
                    ));
                }
                match unb64_array::<32>(r.trim_start_matches("claims/")) {
                    Ok(claim_key) => self.claim_answer(&claim_key),
                    Err(_) => bad(ErrorCode::BadRequest, "a claim key is b64(32)", json!(null)),
                }
            }
            _ => return None,
        })
    }

    /// The certificate an own app's record reads are checked against (Dispatch wire 7.4.9),
    /// the one the Dispatch checks the app against; the signer reads no records (`403
    /// permission_missing`, `crates/pubky-dispatch/src/service/records.rs`, `only_apps`).
    fn record_reader(&self, caller: Option<[u8; 16]>) -> Result<Option<AppCert>, Answer> {
        match caller {
            Some(app) => Ok(self.checked_cert(&app)),
            None => Err(permission_missing(
                "7.4.9: apps read records; the signer doesn't",
            )),
        }
    }

    /// `GET /records/{key}` (Dispatch wire 7.4.9), in the service's order
    /// (`crates/pubky-dispatch/src/service/records.rs`, `get_record`): the signer refused, the
    /// key read (`400`), the record found (`404`), then its `read_scope` held by the reader's
    /// certificate (`403 permission_missing`). An own app the Dispatch holds no certificate
    /// for holds no scope.
    fn record_answer(&mut self, caller: Option<[u8; 16]>, key: &str) -> Answer {
        let cert = match self.record_reader(caller) {
            Ok(cert) => cert,
            Err(refused) => return refused,
        };
        let Ok(key) = unb64_array::<32>(key) else {
            return bad(
                ErrorCode::BadRequest,
                "a record key is b64(32)",
                json!(null),
            );
        };
        #[cfg(test)]
        self.shared.record_reads.push(key);
        let Some(held) = self.shared.records.get(&key) else {
            return bad(ErrorCode::NotFound, "no record", json!(null));
        };
        if !cert.is_some_and(|cert| cert.holds_scope(&held.state.policy.read_scope)) {
            return permission_missing("7.4.9: reading the record needs its read_scope");
        }
        let divergent = self.shared.divergent.contains_key(&key);
        (
            200,
            record_view(held, &self.apps, !self.shared.hide_proofs, divergent),
        )
    }

    /// `GET /records?collection=&after=&limit=` (Dispatch wire 7.4.9), its query read as the
    /// service reads it (`crates/pubky-dispatch/src/service/records.rs`,
    /// `RecordsQuery::parse`): `collection` required and `b64(32)`, `after` a record key,
    /// its text the one keys compare with, and `limit` digits only, 1 to 1000; other
    /// parameters ignored. The records shown are those whose `read_scope` the reader's
    /// certificate holds.
    fn list_records(&mut self, caller: Option<[u8; 16]>, query: &str) -> Answer {
        // The query is read before the caller is: percent-decoded, a parameter given twice
        // refused (`crates/pubky-dispatch/src/http/route.rs`, `parse_query`; Dispatch wire 7.1).
        let Some(params) = parse_query(query) else {
            return bad(
                ErrorCode::BadRequest,
                "the query doesn't decode",
                json!(null),
            );
        };
        let cert = match self.record_reader(caller) {
            Ok(cert) => cert,
            Err(refused) => return refused,
        };
        let param = |name: &str| params.get(name).map(String::as_str);
        let Some(collection) = param("collection") else {
            return bad(ErrorCode::BadRequest, "collection is required", json!(null));
        };
        let Ok(collection) = unb64_array::<32>(collection) else {
            return bad(ErrorCode::BadRequest, "collection", json!(null));
        };
        // A key has one text (Dispatch wire 1.2): the one given, read, is what keys compare
        // with, as unpadded base64url text in ASCII order.
        let after = match param("after").map(unb64_array::<32>) {
            None => None,
            Some(Ok(key)) => Some(b64(&key)),
            Some(Err(_)) => return bad(ErrorCode::BadRequest, "after", json!(null)),
        };
        let limit = match param("limit") {
            None => 1000,
            Some(text) => match text.parse::<usize>() {
                Ok(value @ 1..=1000)
                    if text.len() <= 16 && text.bytes().all(|b| b.is_ascii_digit()) =>
                {
                    value
                }
                _ => return bad(ErrorCode::BadRequest, "limit", json!(null)),
            },
        };
        // Ordered by the base64url text of their keys, after `after` (Dispatch wire 7.4.9).
        let mut listed: Vec<(String, Value)> = self
            .shared
            .records
            .values()
            .filter(|held| held.state.collection == collection && !held.state.deleted)
            .filter(|held| {
                cert.as_ref()
                    .is_some_and(|cert| cert.holds_scope(&held.state.policy.read_scope))
            })
            .map(|held| {
                (
                    b64(&held.state.key),
                    record_view(
                        held,
                        &self.apps,
                        !self.shared.hide_proofs,
                        self.shared.divergent.contains_key(&held.state.key),
                    ),
                )
            })
            .filter(|(key, _)| after.as_ref().is_none_or(|after| key > after))
            .collect();
        listed.sort_by(|a, b| a.0.cmp(&b.0));
        let mut views = Vec::new();
        let mut bytes = 0usize;
        let mut last = None;
        let mut more = false;
        for (key, view) in listed {
            let size = view.to_string().len();
            // `limit`, or the byte budget, ends the page; its first view is shown whatever
            // its size.
            if views.len() >= limit
                || (!views.is_empty() && bytes.saturating_add(size) > self.max_page_bytes)
            {
                more = true;
                break;
            }
            bytes = bytes.saturating_add(size);
            views.push(view);
            last = Some(key);
        }
        self.shared.listings += 1;
        let next = match self.shared.alternate_next {
            Some((a, b)) if self.shared.listings <= 50 => {
                json!(b64(if self.shared.listings % 2 == 1 {
                    &a
                } else {
                    &b
                }))
            }
            _ if more => json!(last),
            _ => json!(null),
        };
        (
            200,
            json!({ "records": views, "seq": self.seq, "next": next }),
        )
    }

    fn claim_answer(&mut self, claim_key: &[u8; 32]) -> Answer {
        let now = self.now();
        if self
            .shared
            .claims
            .get(claim_key)
            .is_some_and(|claim| claim.deletable(Some(now), MAX_CLAIM_AGE_MS))
        {
            self.shared.claims.remove(claim_key);
            self.shared.entries.remove(claim_key);
        }
        let Some(claim) = self.shared.claims.get(claim_key) else {
            return bad(ErrorCode::NotFound, "no claim", json!(null));
        };
        let current = |app: &[u8; 16]| self.app_current(&self.apps, app);
        let view = claim.view(claim_key, now, &current).to_value();
        let entries: Vec<Value> = if claim.tombstone {
            Vec::new()
        } else {
            self.shared
                .entries
                .get(claim_key)
                .into_iter()
                .flatten()
                .map(|e| json!({ "step": e.step, "seq": e.seq, "op": e.op, "proof": e.proof }))
                .collect()
        };
        (200, json!({ "claim": view, "entries": entries }))
    }

    fn allow_list(&self) -> Answer {
        let now = self.now();
        let codes: Vec<Value> = self
            .shared
            .invites
            .iter()
            .filter(|(_, invite)| invite.uses < invite.max_uses && now < invite.expires_at)
            .map(|(hash, invite)| {
                json!({ "code_hash": b64(hash), "expires_at": rfc3339(invite.expires_at),
                        "max_uses": invite.max_uses, "uses": invite.uses,
                        "written_by": zbase32_encode(&invite.writer) })
            })
            .collect();
        let mut rows: BTreeMap<_, _> = self
            .shared
            .kept
            .iter()
            .map(|id| {
                (
                    pubky_id(id),
                    PeerEntry {
                        pubky: *id,
                        kept: true,
                        reply: None,
                    },
                )
            })
            .collect();
        for (id, grant) in &self.shared.reply_grants {
            rows.entry(pubky_id(id))
                .or_insert(PeerEntry {
                    pubky: *id,
                    kept: false,
                    reply: None,
                })
                .reply = Some(*grant);
        }
        let peers = rows
            .into_values()
            .map(|peer| serde_json::from_slice::<Value>(&peer.to_json().ok()?).ok())
            .collect::<Option<Vec<_>>>();
        let Some(peers) = peers else {
            return bad(ErrorCode::Unavailable, "invalid peer entry", json!(null));
        };
        (
            200,
            json!({
                "peers": peers,
                "deny": self.shared.deny.iter().map(pubky_id).collect::<Vec<_>>(),
                "flagged": self
                    .shared
                    .flagged
                    .iter()
                    .map(|(pubky, hits)| json!({ "pubky": pubky_id(pubky), "hits": hits }))
                    .collect::<Vec<_>>(),
                "invite_codes": codes,
            }),
        )
    }
}
