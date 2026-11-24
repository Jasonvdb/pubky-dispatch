//! A collection owner's observation of a signed record deletion (Switch spec 8.2).

use std::collections::{BTreeMap, BTreeSet, btree_map::Entry};

use pubky_switch_core::enc::{b64, serde_b64};
use pubky_switch_core::ops::{Condition, OpKind, RecordVersion, SignedOp};
use pubky_switch_core::records::{AppCert, IdentityDoc};
use pubky_switch_core::sig::SignedDoc;
use serde::{Deserialize, Serialize};

use super::events::Duty;
use super::order::{Handover, Kept};
use super::put_back::RecordHold;
use super::records::{self, DeleteBase};
use super::state::{Reader, Tx};
use super::{App, AppError, FeedPosition, ProtocolSet, PutBack};

pub(super) const PREFIX: &str = "delobs/";
pub(super) const RECEIPTS: &str = "delack/";

pub(super) fn clear_on_leave(tx: &mut Tx) -> Result<(), AppError> {
    tx.delete_prefixes(&[PREFIX, RECEIPTS])
}

/// Space for the signed delete, sealed predecessor, their certificates and proof,
/// the outstanding signed batch, its successor merge, the owner's local writes and mark.
pub(super) const ROOM: u64 = 8 << 20;
const _: () = assert!(
    2 * pubky_switch_core::ops::MAX_OP_BYTES as u64
        + (128 << 10)
        + ((2 * pubky_switch_core::ops::MAX_OP_BYTES
            + super::MAX_STEP_LOCAL_BYTES
            + super::MAX_SEEN_MARK_BYTES) as u64
            * 4
            / 3)
        < ROOM
        && ROOM < crate::store::MAX_VALUE_BYTES
);

#[derive(Clone, Serialize, Deserialize)]
pub(super) struct Predecessor {
    pub(super) source: records::KeptOp,
    pub(super) exact: bool,
    pub(super) dated_at_expected: bool,
    /// The predecessor's time from its verified stub or proof (Switch wire 6.2).
    pub(super) written_at_ms: Option<u64>,
}

/// The immutable evidence still owed to the collection's owner.
#[derive(Clone, Serialize, Deserialize)]
pub(super) struct Observation {
    #[serde(with = "serde_b64")]
    pub(super) key: [u8; 32],
    pub(super) owner: String,
    pub(super) collection: String,
    pub(super) delete: DeleteBase,
    pub(super) operation: SignedDoc,
    pub(super) proof: Option<SignedDoc>,
    pub(super) authenticated: bool,
    pub(super) cert: SignedDoc,
    pub(super) generation: u64,
    pub(super) seq: u64,
    pub(super) page_time_ms: Option<u64>,
    pub(super) held: bool,
    pub(super) seen: Option<records::SeenMark>,
    pub(super) predecessor: Option<Predecessor>,
    pub(super) written_at_ms: Option<u64>,
    /// A verified stub or receipt established the callback time here (Switch spec 12.4).
    #[serde(default)]
    pub(super) time_proved: bool,
}

impl std::fmt::Debug for Observation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Observation")
            .field("owner", &self.owner)
            .field("seq", &self.seq)
            .finish_non_exhaustive()
    }
}

/// Original times available to every copy of a duty during this restore (Switch spec 12.4).
pub(super) struct RestoreGrants<'a> {
    pub(super) doc: &'a IdentityDoc,
    dates: BTreeMap<[u8; 32], u64>,
}

impl<'a> RestoreGrants<'a> {
    pub(super) fn new<'b>(
        doc: &'a IdentityDoc,
        local: impl Iterator<Item = &'b Observation>,
        backup: impl Iterator<Item = &'b Observation>,
    ) -> Result<Self, AppError> {
        let mut dates = BTreeMap::new();
        for (observed, local) in local.map(|o| (o, true)).chain(backup.map(|o| (o, false))) {
            let deletion = SignedOp::peek(&observed.operation).map_err(|_| super::corrupt())?;
            let time = (local && observed.time_proved)
                .then_some(observed.written_at_ms)
                .flatten()
                .or_else(|| observed.portable_date(&deletion, doc).map(|d| d.time));
            if let Some(time) = time {
                dates.entry(deletion.item_hash()?).or_insert(time);
            }
        }
        Ok(Self { doc, dates })
    }
}

impl Observation {
    pub(super) fn date(&mut self, time: u64) -> bool {
        let changed = self.written_at_ms != Some(time) || !self.time_proved;
        self.written_at_ms = Some(time);
        self.time_proved = true;
        changed
    }

    fn portable_date(
        &self,
        op: &SignedOp,
        doc: &IdentityDoc,
    ) -> Option<pubky_switch_core::shared::Dated> {
        pubky_switch_core::shared::date_write(self.proof.as_ref()?, op, doc).ok()
    }

    pub(super) fn revision(&self) -> pubky_switch_core::shared::ApplicationRef {
        pubky_switch_core::shared::ApplicationRef {
            generation: self.generation,
            seq: self.seq,
            item_hash: self.delete.item_hash,
        }
    }

    pub(super) fn put(&self) -> Result<pubky_switch_core::ops::RecordPut, AppError> {
        let op = SignedOp::peek(&self.operation).map_err(|_| super::corrupt())?;
        match &op.body().kind {
            OpKind::RecordPut(put) => Ok(put.clone()),
            _ => Err(super::corrupt()),
        }
    }

    pub(super) fn id(&self) -> ([u8; 32], RecordVersion, [u8; 32]) {
        (self.key, self.delete.version, self.delete.item_hash)
    }

    pub(super) fn store_key(&self) -> String {
        self.key_in(PREFIX)
    }

    pub(super) fn key_in(&self, prefix: &str) -> String {
        format!(
            "{prefix}{}/{}/{}/{}",
            b64(&self.key),
            self.delete.version.generation,
            self.delete.version.version,
            b64(&self.delete.item_hash)
        )
    }

    fn prior_write(
        &self,
        doc: &IdentityDoc,
        deletion: &SignedOp,
    ) -> Result<Option<SignedOp>, AppError> {
        let Some(prior) = &self.predecessor else {
            return Ok(None);
        };
        let identity = doc.identity();
        let cert = AppCert::verify(&prior.source.cert, &identity).map_err(|_| super::corrupt())?;
        let op = SignedOp::verify(
            &prior.source.op,
            &cert.signing_key(),
            &identity,
            Some(&cert.app_id()),
        )
        .map_err(|_| super::corrupt())?;
        let (OpKind::RecordPut(put), OpKind::RecordPut(d)) =
            (&op.body().kind, &deletion.body().kind)
        else {
            return Err(super::corrupt());
        };
        if put.key != self.key
            || put.collection != d.collection
            || put.policy != d.policy
            || put.policy.read_scope != put.value_sealed.scope
            || put.value_sealed.looks_like_delete()
            || (!put.policy.has_operation_scopes() && !put.allows_writer(&cert))
        {
            return Err(super::corrupt());
        }
        if put.policy.has_operation_scopes() {
            let time = prior
                .source
                .proof
                .as_ref()
                .and_then(|proof| pubky_switch_core::shared::date_write(proof, &op, doc).ok())
                .map(|dated| dated.time)
                .or(prior.written_at_ms);
            if time.is_some_and(|at| !records::in_force(doc, &cert, Some(at)))
                || !records::holds_write_role(&cert, put, time)
            {
                return Ok(None);
            }
        }
        Ok(Some(op))
    }

    /// An imported mark or a claimed version cannot authenticate the predecessor. A
    /// delete can name its application directly. Otherwise its service proof must
    /// establish the signed predecessor at the delete's expected version.
    pub(super) fn restore_evidence(
        &mut self,
        grants: &RestoreGrants<'_>,
        writer: &AppCert,
    ) -> Result<bool, AppError> {
        let doc = grants.doc;
        let deletion = SignedOp::peek(&self.operation).map_err(|_| super::corrupt())?;
        let OpKind::RecordPut(d) = &deletion.body().kind else {
            return Err(super::corrupt());
        };
        let dated = self.portable_date(&deletion, doc);
        self.authenticated &= dated.and_then(|dated| dated.version) == Some(self.delete.version);
        if let Some(&time) = grants.dates.get(&self.delete.item_hash) {
            self.date(time);
        } else {
            self.time_proved = false;
        }
        if !self.role_counts(writer, Some(doc))? {
            return Ok(false);
        }
        // The backup needs a separate receipt to date the predecessor. Naming its
        // operation supplies no time for its writer's grant (Switch wire 6.2).
        if let Some(prior) = &mut self.predecessor {
            prior.written_at_ms = None;
        }
        let Some(op) = self.prior_write(doc, &deletion)? else {
            self.predecessor = None;
            return Ok(true);
        };
        let hash = op.item_hash()?;
        let named: Vec<_> = deletion
            .body()
            .conditions
            .iter()
            .filter_map(|c| match c {
                Condition::RecordCurrent {
                    key,
                    revision,
                    deleted,
                } if *key == self.key => Some((revision, deleted)),
                _ => None,
            })
            .collect();
        let prior = self.predecessor.as_mut().ok_or_else(super::corrupt)?;
        let dated = prior
            .source
            .proof
            .as_ref()
            .and_then(|proof| pubky_switch_core::shared::date_write(proof, &op, doc).ok());
        prior.written_at_ms = dated.map(|d| d.time);
        let version = dated.and_then(|d| d.version);
        prior.dated_at_expected = version == Some(d.expected_version);
        let named_match = !named.is_empty()
            && named
                .iter()
                .all(|(revision, deleted)| !**deleted && revision.item_hash == hash);
        if !named_match && version.is_none_or(|v| v > d.expected_version) {
            self.predecessor = None;
        } else {
            prior.exact &= named_match
                || (named.is_empty()
                    && version == Some(d.expected_version)
                    && doc
                        .body()
                        .recovery_from
                        .is_none_or(|lost| d.expected_version.generation > lost));
        }
        Ok(true)
    }

    pub(super) fn check(
        &self,
        protocols: &ProtocolSet,
        identity: &[u8; 32],
    ) -> Result<AppCert, AppError> {
        let owner = protocols
            .of_collection(&self.collection)
            .ok_or_else(super::corrupt)?;
        if owner.name != self.owner
            || self.delete.version.is_none()
            || self.seq == 0
            || self
                .seen
                .as_ref()
                .is_some_and(|m| m.mark.len() > super::MAX_SEEN_MARK_BYTES)
        {
            return Err(super::corrupt());
        }
        let cert = AppCert::verify(&self.cert, identity).map_err(|_| super::corrupt())?;
        let signed = SignedOp::verify(
            &self.operation,
            &cert.signing_key(),
            identity,
            Some(&cert.app_id()),
        )
        .map_err(|_| super::corrupt())?;
        let OpKind::RecordPut(deletion) = &signed.body().kind else {
            return Err(super::corrupt());
        };
        if signed.item_hash()? != self.delete.item_hash
            || deletion.key != self.key
            || !deletion.value_sealed.looks_like_delete()
            || !owner.protocol.collections().iter().any(|c| {
                c.name == self.collection
                    && c.id(identity) == deletion.collection
                    && c.admits(&deletion.policy)
            })
        {
            return Err(super::corrupt());
        }
        Ok(cert)
    }

    /// Recheck grants using the verified times available on restore, preserving
    /// locally authenticated predecessor evidence (Switch wire 6.2).
    pub(super) fn retain_local(
        &mut self,
        grants: &RestoreGrants<'_>,
        writer: &AppCert,
    ) -> Result<bool, AppError> {
        let doc = grants.doc;
        if let Some(&time) = grants.dates.get(&self.delete.item_hash) {
            self.date(time);
        }
        if !self.role_counts(writer, Some(doc))? {
            return Ok(false);
        }
        if self.predecessor.is_some() && self.put()?.policy.has_operation_scopes() {
            let deletion = SignedOp::peek(&self.operation).map_err(|_| super::corrupt())?;
            if self.prior_write(doc, &deletion)?.is_none() {
                self.predecessor = None;
            }
        }
        Ok(true)
    }

    /// Check the role at the verified write time. Loading or restoring also checks
    /// the writer's standing in the newest held identity document (Switch wire 6.2).
    pub(super) fn role_counts(
        &self,
        cert: &AppCert,
        doc: Option<&IdentityDoc>,
    ) -> Result<bool, AppError> {
        let op = SignedOp::peek(&self.operation).map_err(|_| super::corrupt())?;
        let OpKind::RecordPut(put) = &op.body().kind else {
            return Err(super::corrupt());
        };
        let time = self
            .written_at_ms
            .filter(|_| self.time_proved)
            .or_else(|| self.portable_date(&op, doc?).map(|d| d.time));
        Ok(
            pubky_switch_core::ops::check_permanent(put, op.body().generation).is_ok()
                && records::holds_write_role(cert, put, time)
                && (!put.policy.has_operation_scopes()
                    || time.is_none()
                    || doc.is_none_or(|doc| records::in_force(doc, cert, time))),
        )
    }
}

pub(super) type Id = ([u8; 32], RecordVersion, [u8; 32]);
pub(super) type Observations = BTreeMap<Id, Observation>;
pub(super) type Receipts = BTreeMap<Id, Receipt>;

/// Identifies the owner's already committed writes while the delete can be read again.
/// The owner keeps the contents in its own state.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub(super) struct Receipt {
    #[serde(with = "serde_b64")]
    key: [u8; 32],
    delete: DeleteBase,
    pub(super) owner: String,
    read_scope: String,
    generation: u64,
    seq: u64,
}

impl Receipt {
    fn id(&self) -> Id {
        (self.key, self.delete.version, self.delete.item_hash)
    }

    pub(super) fn store_key(&self) -> String {
        format!(
            "{RECEIPTS}{}/{}/{}/{}",
            b64(&self.key),
            self.delete.version.generation,
            self.delete.version.version,
            b64(&self.delete.item_hash)
        )
    }

    fn valid(&self) -> bool {
        self.seq != 0
            && !self.delete.version.is_none()
            && pubky_switch_core::scopes::is_scope(&self.read_scope)
    }
}

pub(super) async fn load_receipts(reader: &Reader) -> Result<Receipts, AppError> {
    let mut receipts = Receipts::new();
    for (suffix, receipt) in reader.scan::<Receipt>(RECEIPTS).await? {
        if !receipt.valid() || receipt.store_key().strip_prefix(RECEIPTS) != Some(&suffix) {
            return Err(super::corrupt());
        }
        receipts.insert(receipt.id(), receipt);
    }
    Ok(receipts)
}

pub(super) fn layer_receipts(
    layers: &[super::LayerOut],
    pending: &mut Observations,
) -> Result<Receipts, AppError> {
    let mut receipts = Receipts::new();
    for layer in layers {
        for receipt in &layer.deletions {
            if receipt.owner != layer.name
                || !receipt.valid()
                || receipts.insert(receipt.id(), receipt.clone()).is_some()
            {
                return Err(super::corrupt());
            }
            pending.remove(&receipt.id());
        }
    }
    Ok(receipts)
}

pub(super) async fn load(reader: &Reader) -> Result<Observations, AppError> {
    let mut retained = Observations::new();
    for (suffix, observation) in reader.scan::<Observation>(PREFIX).await? {
        if observation.store_key().strip_prefix(PREFIX) != Some(&suffix) {
            return Err(super::corrupt());
        }
        retained.insert(observation.id(), observation);
    }
    Ok(retained)
}

pub(super) fn restore(
    local: Observations,
    backup: &[Observation],
    protocols: &ProtocolSet,
    grants: &RestoreGrants<'_>,
) -> Result<(Observations, BTreeSet<Id>), AppError> {
    let mut retained = Observations::new();
    let mut skipped = BTreeSet::new();
    for observed in backup {
        let mut observed = observed.clone();
        let cert = observed.check(protocols, &grants.doc.identity())?;
        if !observed.restore_evidence(grants, &cert)? {
            skipped.insert(observed.id());
            continue;
        }
        if retained.insert(observed.id(), observed).is_some() {
            return Err(super::corrupt());
        }
    }
    for (id, mut local) in local {
        let cert = local.check(protocols, &grants.doc.identity())?;
        if !local.retain_local(grants, &cert)? {
            skipped.insert(id);
            continue;
        }
        local.page_time_ms = local
            .page_time_ms
            .or_else(|| retained.get(&id).and_then(|b| b.page_time_ms));
        retained.insert(id, local);
    }
    Ok((retained, skipped))
}

impl App {
    /// Drop stored calls whose writer no longer qualifies and report the loss in
    /// the same commit, so reopening cannot deliver or count them twice (Switch spec 12.4).
    pub(super) async fn check_stored_deletions(&mut self) -> Result<(), AppError> {
        let mut skipped = BTreeSet::new();
        let mut skipped_holds = Vec::new();
        let doc = &self.state.own_doc;
        for (id, observed) in &self.state.deletions {
            let writer = observed.check(&self.protocols, &doc.identity())?;
            if !observed.role_counts(&writer, Some(doc))? {
                skipped.insert(*id);
            }
        }
        for (id, hold) in &self.state.put_backs {
            let writer = hold.check(&self.protocols, &doc.identity(), &self.state.cert)?;
            if !hold.observation.role_counts(&writer, Some(doc))? {
                skipped_holds.push(*id);
            }
        }
        if !skipped.is_empty() || !skipped_holds.is_empty() {
            let mut tx = self.tx()?;
            for id in &skipped {
                if let Some(observed) = self.state.deletions.remove(id) {
                    tx.delete(&observed.store_key())?;
                }
            }
            for id in skipped_holds {
                if let Some(mut hold) = self.state.put_backs.get(&id).cloned() {
                    self.displace_publication(&mut hold, None, &mut tx).await?;
                }
                self.forget_put_back(&id, &mut tx)?;
                skipped.insert(id);
            }
            skipped.retain(|id| {
                !self.state.deletions.contains_key(id) && !self.state.put_backs.contains_key(id)
            });
            if !skipped.is_empty() {
                self.keep_duty(
                    &mut tx,
                    Duty::RestoreLeftBehind {
                        duty_events: 0,
                        owed_calls: skipped.len() as u64,
                    },
                )?;
            }
            self.commit(tx).await?;
        }
        Ok(())
    }

    pub(super) fn consult_deletion(
        &self,
        hold: &Observation,
        deletion: &SignedOp,
        tx: &Tx,
    ) -> Result<Option<PutBack>, AppError> {
        self.with_deletion(hold, deletion, tx, |owner, input, cx| {
            owner.record_put_back(input, cx)
        })
    }

    pub(super) fn with_deletion<T>(
        &self,
        hold: &Observation,
        deletion: &SignedOp,
        tx: &Tx,
        consult: impl FnOnce(
            &dyn super::Protocol,
            &super::RecordDeletion<'_>,
            &super::ReceiveContext<'_>,
        ) -> Result<T, super::StoreFailure>,
    ) -> Result<T, AppError> {
        let owner = self
            .protocols
            .of_collection(&hold.collection)
            .ok_or_else(super::corrupt)?;
        let OpKind::RecordPut(put) = &deletion.body().kind else {
            return Err(super::corrupt());
        };
        let prior = hold.prior_write(&self.state.own_doc, deletion)?;
        let opened = prior.as_ref().and_then(|op| {
            let OpKind::RecordPut(put) = &op.body().kind else {
                return None;
            };
            match put
                .value_sealed
                .open_with(&self.state.scope_keys, &self.state.meta.identity, &hold.key)
                .ok()?
            {
                pubky_switch_core::sealed::RecordValue::Json(value) => Some(value),
                _ => None,
            }
        });
        let input = super::RecordDeletion {
            collection: &hold.collection,
            key: &hold.key,
            version: hold.delete.version,
            original_in_current_generation: hold.authenticated
                && hold.generation == self.state.meta.generation
                && deletion.body().generation == hold.generation
                && hold.delete.version == RecordVersion::new(hold.generation, hold.seq),
            writer: deletion.body().app_id.ok_or_else(super::corrupt)?,
            item_hash: hold.delete.item_hash,
            seen: hold.seen.as_ref().map(|m| m.mark.as_slice()),
            page_time_ms: hold.page_time_ms,
            policy: opened.as_ref().map(|_| &put.policy),
            exact_version_authenticated: opened.is_some()
                && hold
                    .predecessor
                    .as_ref()
                    .is_some_and(|prior| prior.exact && prior.dated_at_expected),
            exact_value: opened
                .as_deref()
                .filter(|_| hold.predecessor.as_ref().is_some_and(|prior| prior.exact)),
            base: super::WriteBase {
                repair: None,
                expected_version: put.expected_version,
                held: hold.held,
                conditions: deletion.body().conditions.clone(),
                written_at_ms: hold.written_at_ms,
            },
        };
        let cx = super::ReceiveContext::new(
            &self.state,
            &self.protocols,
            &hold.owner,
            self.env.store.store().as_ref(),
            &self.ns,
            false,
            &[],
            tx.pending_local(),
            tx.pending_writes(),
        );
        consult(owner.protocol.as_ref(), &input, &cx).map_err(AppError::Protocol)
    }

    pub(super) fn owed_deletions(&self) -> impl Iterator<Item = &Observation> {
        let restored = self
            .state
            .put_backs
            .values()
            .filter(|h| h.observing)
            .map(|h| &h.observation);
        self.state.deletions.values().chain(restored)
    }

    pub(super) fn deletion_positions(&self) -> impl Iterator<Item = Kept> + '_ {
        self.owed_deletions().map(|d| Kept {
            generation: d.generation,
            seq: d.seq,
            names: vec![d.owner.clone()],
            call: false,
            held_gap: None,
            deny: false,
        })
    }

    /// Only a later authenticated write, a current view, or a hosted absence in our
    /// read scope settles that this delete is no longer current. A listing may omit it.
    pub(super) fn retire_deletion_receipts(
        &mut self,
        key: [u8; 32],
        successor: Option<([u8; 32], RecordVersion)>,
        tx: &mut Tx,
    ) -> Result<(), AppError> {
        self.retire_receipts_where(key, tx, |app, r| match successor {
            Some((hash, at)) => {
                hash != r.delete.item_hash
                    && app.feed_order(at.generation, at.version)
                        >= app.feed_order(r.generation, r.seq)
            }
            None => app.state.cert.holds_scope(&r.read_scope),
        })
    }

    /// Absence at a verified head covers only deletes already applied by that position.
    pub(super) fn retire_absent_receipts(
        &mut self,
        key: [u8; 32],
        at: FeedPosition,
        tx: &mut Tx,
    ) -> Result<(), AppError> {
        self.retire_receipts_where(key, tx, |app, r| {
            app.state.cert.holds_scope(&r.read_scope)
                && app
                    .received_order(
                        at,
                        FeedPosition {
                            generation: r.generation,
                            seq: r.seq,
                        },
                    )
                    .is_some_and(std::cmp::Ordering::is_ge)
        })
    }

    fn retire_receipts_where(
        &mut self,
        key: [u8; 32],
        tx: &mut Tx,
        obsolete: impl Fn(&Self, &Receipt) -> bool,
    ) -> Result<(), AppError> {
        let first = (key, RecordVersion::NONE, [0; 32]);
        let obsolete: Vec<_> = self
            .state
            .deletion_receipts
            .range(first..)
            .take_while(|(id, _)| id.0 == key)
            .filter(|(_, r)| obsolete(self, r))
            .map(|(id, _)| *id)
            .collect();
        for id in obsolete {
            if let Some(receipt) = self.state.deletion_receipts.remove(&id) {
                tx.delete(&receipt.store_key())?;
            }
        }
        Ok(())
    }

    /// Keep, in `tx`, that the owner was told its wait for `observed` ended: a feed page or
    /// a view that shows the same delete again starts no second wait (`records.rs`). The
    /// receipt goes as any does, once a later write or a covering absence retires it.
    pub(super) fn keep_ended_receipt(
        &mut self,
        observed: &Observation,
        tx: &mut Tx,
    ) -> Result<(), AppError> {
        let receipt = Receipt {
            owner: observed.owner.clone(),
            key: observed.key,
            delete: observed.delete,
            generation: observed.generation,
            seq: observed.seq,
            read_scope: observed.put()?.policy.read_scope.clone(),
        };
        tx.put(&receipt.store_key(), &receipt)?;
        let receipts = tx
            .renewal
            .as_mut()
            .map_or(&mut self.state.deletion_receipts, |r| &mut r.receipts);
        receipts.insert(receipt.id(), receipt);
        Ok(())
    }

    pub(super) fn deletion_hold(&self, observed: Observation) -> RecordHold {
        let protects =
            observed.page_time_ms.is_some() && observed.seq > self.state.cursor.at_service;
        RecordHold {
            observation: observed,
            protects,
            needs_cursor: false,
            pending: None,
            cursor_generation: None,
            waited: false,
            observing: false,
        }
    }

    /// First observation of the delete, or the first feed page for a retained record
    /// view. A retry of either sees its observation already committed.
    pub(super) fn take_put_back_observation(
        &mut self,
        mut hold: RecordHold,
        tx: &mut Tx,
    ) -> Result<(), AppError> {
        use PutBack::{Observe, Prepare, Write};
        let observed = &hold.observation;
        let deletion = SignedOp::peek(&observed.operation).map_err(|_| super::corrupt())?;
        let answer = match self.consult_deletion(observed, &deletion, tx) {
            Ok(mut answer) => {
                let writes = match &mut answer {
                    Some(Observe { observed } | Prepare { observed } | Write { observed, .. }) => {
                        std::mem::take(observed)
                    }
                    None => vec![],
                };
                let bytes = super::local_writes_bytes(&writes);
                if bytes > super::MAX_STEP_LOCAL_BYTES {
                    return self.await_put_back_observation(hold, tx);
                }
                if !writes.is_empty() {
                    let OpKind::RecordPut(put) = &deletion.body().kind else {
                        return Err(super::corrupt());
                    };
                    let receipt = Receipt {
                        owner: observed.owner.clone(),
                        key: observed.key,
                        delete: observed.delete,
                        generation: observed.generation,
                        seq: observed.seq,
                        read_scope: put.policy.read_scope.clone(),
                    };
                    tx.local(&super::protocols::qualify(&observed.owner, writes))?;
                    tx.put(&receipt.store_key(), &receipt)?;
                    self.state.deletion_receipts.insert(receipt.id(), receipt);
                }
                answer
            }
            Err(AppError::Protocol(_)) => return self.await_put_back_observation(hold, tx),
            Err(error) => return Err(error),
        };
        if self.state.deletions.remove(&observed.id()).is_some() {
            tx.delete(&observed.store_key())?;
        }
        hold.observing = false;
        // A wait for a deletion of an earlier generation is never kept (Switch spec 10.3):
        // no later write of that generation can follow. One first seen after a move, a key
        // change in place or a provider loss, or answered only after it, ends at once and its
        // owner is told; a replacement signed and never sent goes with it. A hold with a
        // replacement sent is kept for its next try, which ends it and keeps or drops that
        // submission (`App::end_earlier_put_backs`).
        let keeps = match &answer {
            Some(Prepare { .. } | Write { .. }) => true,
            None => self.state.put_backs.contains_key(&observed.id()),
            _ => false,
        };
        if keeps
            && hold.pending.as_ref().is_none_or(|p| p.kept_ms.is_none())
            && self.can_only_end(&hold)
        {
            let reason = self.generation_end(observed.generation).reason();
            let duty = Duty::PutBackRefused {
                key: observed.key,
                delete: observed.delete,
                reason: reason.to_owned(),
                batch_id: None,
            };
            self.keep_duty_for(tx, vec![observed.owner.clone()], duty)?;
            self.keep_ended_receipt(observed, tx)?;
            return self.forget_put_back(&observed.id(), tx);
        }
        // A later view or the first feed page can enrich an existing observation.
        // Settle an already-sent operation against the current record on retry.
        if hold
            .pending
            .as_ref()
            .is_some_and(|pending| pending.kept_ms.is_some())
        {
            return self.keep_put_back(hold, tx);
        }
        match answer {
            Some(Prepare { .. }) => self.keep_waiting(hold, tx),
            Some(Write { .. }) => self.keep_put_back(hold, tx),
            None if self.state.put_backs.contains_key(&observed.id()) => {
                self.keep_waiting(hold, tx)
            }
            _ => self.forget_put_back(&observed.id(), tx),
        }
    }

    fn await_put_back_observation(
        &mut self,
        mut hold: RecordHold,
        tx: &mut Tx,
    ) -> Result<(), AppError> {
        if self.state.put_backs.contains_key(&hold.observation.id()) {
            hold.observing = true;
            // One of an earlier generation can only end: its observation is owed again, and
            // no wait is told for it.
            if self.can_only_end(&hold) {
                return self.keep_put_back(hold, tx);
            }
            return self.keep_waiting(hold, tx);
        }
        let observed = hold.observation;
        if let Entry::Vacant(entry) = self.state.deletions.entry(observed.id()) {
            tx.put(&observed.store_key(), &observed)?;
            entry.insert(observed);
        }
        Ok(())
    }

    pub(super) async fn retry_deletions(
        &mut self,
        budget: &super::CallBudget,
    ) -> Result<(), AppError> {
        let mut due: Vec<_> = self
            .owed_deletions()
            .map(|d| (self.feed_order(d.generation, d.seq), d.id()))
            .collect();
        due.sort_unstable();
        for (index, (order, id)) in due.into_iter().enumerate() {
            if index > 0 && self.spent(budget) {
                break;
            }
            let hold = self.state.put_backs.get(&id).filter(|h| h.observing);
            let Some(observed) = hold
                .map(|h| &h.observation)
                .or_else(|| self.state.deletions.get(&id))
            else {
                continue;
            };
            if self.ready_at(&observed.owner, order, Handover::Call) {
                let hold = hold
                    .cloned()
                    .unwrap_or_else(|| self.deletion_hold(observed.clone()));
                let mut tx = self.tx()?;
                self.take_put_back_observation(hold, &mut tx)?;
                if self.state.deletion_receipts.contains_key(&id) {
                    self.retire_completed_deletion(id.0, &mut tx).await?;
                }
                if !tx.is_empty() {
                    self.commit(tx).await?;
                }
            }
        }
        Ok(())
    }
}
