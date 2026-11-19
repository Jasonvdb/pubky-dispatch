//! Holding the service cursor until the collection owner verifies publication (Switch spec 8.2, 10.3).

use std::collections::BTreeMap;

use super::deletion::{Id, Observation};

use pubky_switch_core::http::{ErrorCode, Retry};
use pubky_switch_core::ops::{RecordVersion, SignedOp};
use pubky_switch_core::records::{AppCert, IdentityDoc};
use pubky_switch_core::shared::ApplicationRef;
use serde::{Deserialize, Serialize};

use super::events::Duty;
use super::order::Handover;
use super::records::{self, DeleteBase};
use super::state::{Reader, Tx};
use super::{Alarm, App, AppError, Batch, Position, ProtocolSet, PutBack, Refusal};

pub(super) const PREFIX: &str = "hold/";

/// A collection waiting for publication at an exact signed deletion.
#[derive(Clone, Serialize, Deserialize, Debug)]
pub(super) struct RecordHold {
    pub(super) observation: Observation,
    pub(super) protects: bool,
    pub(super) needs_cursor: bool,
    pub(super) waited: bool,
    /// The owner has yet to save its first observation.
    pub(super) observing: bool,
}

impl RecordHold {
    pub(super) fn store_key(&self) -> String {
        self.observation.key_in(PREFIX)
    }

    fn writable(&self, cert: &AppCert) -> Result<bool, AppError> {
        let policy = self.observation.put()?.policy;
        Ok(policy
            .write_scopes
            .iter()
            .any(|scope| cert.holds_scope(scope)))
    }
}

/// Whether this observation may proceed to the ordinary record check.
pub(super) enum Publication {
    PendingObservation,
    Observed,
    Covered(ApplicationRef),
}

pub(super) type Holds = BTreeMap<Id, RecordHold>;

pub(super) fn at_key<'a>(
    holds: &'a Holds,
    key: &'a [u8; 32],
) -> impl Iterator<Item = &'a RecordHold> {
    holds
        .range((*key, RecordVersion::NONE, [0; 32])..)
        .take_while(move |(id, _)| &id.0 == key)
        .map(|(_, hold)| hold)
}

pub(super) async fn load(reader: &Reader) -> Result<Holds, AppError> {
    let mut holds = Holds::new();
    for (suffix, hold) in reader.scan::<RecordHold>(PREFIX).await? {
        if hold.store_key().strip_prefix(PREFIX) != Some(&suffix)
            || holds.insert(hold.observation.id(), hold).is_some()
        {
            return Err(super::corrupt());
        }
    }
    Ok(holds)
}

/// An in-place restore keeps the work the installation accepted after the backup as
/// well as the backup's. The next verified page reconciles its service cursor.
pub(super) async fn restore(
    previous: Option<&Reader>,
    backed_up: &[RecordHold],
    protocols: &ProtocolSet,
    meta: &super::state::Meta,
    doc: &IdentityDoc,
    layers: &[super::ProtocolLayer],
) -> Result<Holds, AppError> {
    let mut holds = Holds::new();
    for hold in backed_up {
        hold.observation.check(protocols, &meta.identity)?;
        let mut hold = hold.clone();
        hold.observation.restore_predecessor(doc)?;
        hold.observing |= !layers
            .iter()
            .any(|layer| layer.protocol == hold.observation.owner);
        if holds.insert(hold.observation.id(), hold).is_some() {
            return Err(super::corrupt());
        }
    }
    if let Some(reader) = previous {
        let local_holds = load(reader).await?;
        let lost = super::identity::held_copy(reader, &meta.identity)
            .await?
            .and_then(|(doc, _)| doc.body().recovery_from);
        let cursor: Option<super::state::Cursor> = reader.get(super::key::CURSOR).await?;
        for deletion in backed_up.iter().map(|h| &h.observation) {
            // An unanswered local observation may precede the backed-up duty.
            // A completed release or provider loss ends it.
            let passed = cursor
                .is_some_and(|c| c.generation >= deletion.generation && c.seq >= deletion.seq);
            if lost.is_some_and(|g| deletion.generation <= g)
                || (!local_holds.contains_key(&deletion.id())
                    && !reader.exists(&deletion.store_key()).await?
                    && (passed
                        || reader
                            .get::<records::HeldRecord>(&records::record_key_of(&deletion.key))
                            .await?
                            .and_then(|r| r.delete_base())
                            == Some(deletion.delete)))
            {
                holds.remove(&deletion.id());
            }
        }
        for (key, mut hold) in local_holds {
            hold.observation.check(protocols, &meta.identity)?;
            let same = holds.get(&key);
            if let Some(backup) = same {
                if hold.observation.page_time_ms.is_none()
                    && backup.observation.page_time_ms.is_some()
                {
                    hold.observation.page_time_ms = backup.observation.page_time_ms;
                    hold.protects = backup.protects;
                }
            }
            hold.observing = same.is_none_or(|backup| {
                backup.observing || backup.observation.page_time_ms != hold.observation.page_time_ms
            });
            holds.insert(key, hold);
        }
    }
    let mut positions = std::collections::BTreeSet::new();
    for hold in holds.values_mut() {
        if hold.protects && !positions.insert(hold.observation.seq) {
            return Err(super::corrupt());
        }
        hold.needs_cursor = hold.protects;
    }
    Ok(holds)
}

fn waits(error: &AppError) -> bool {
    matches!(
        error,
        AppError::Transport(_) | AppError::Refused(Refusal::NotNow(_))
    ) || error
        .code()
        .is_some_and(|code| code == ErrorCode::TooLarge || code.retry() != Retry::No)
}

impl App {
    pub(super) async fn retry_put_backs(
        &mut self,
        attempted: &mut std::collections::BTreeSet<Id>,
        budget: &super::CallBudget,
    ) -> Result<(), AppError> {
        let mut due: Vec<_> = self
            .state
            .put_backs
            .values()
            .map(|hold| (hold.observation.seq, hold.observation.id()))
            .collect();
        due.sort_unstable();
        for (_, key) in due {
            let Some(hold) = self.state.put_backs.get(&key).cloned() else {
                continue;
            };
            if hold.needs_cursor || hold.observing || attempted.contains(&key) {
                continue;
            }
            if self.spent(budget) {
                break;
            }
            attempted.insert(key);
            Box::pin(self.try_put_back(hold)).await?;
        }
        Ok(())
    }

    pub(super) fn saw_put_back_write(
        &mut self,
        key: &[u8; 32],
        due: Option<&Id>,
        revision: ApplicationRef,
        write: Option<(&records::Accepted, Option<&super::RecordRepair>)>,
        feed_time: Option<u64>,
        tx: &mut Tx,
    ) -> Result<Publication, AppError> {
        let id = due.copied().or_else(|| {
            at_key(&self.state.put_backs, key)
                .find(|h| {
                    h.observation.generation == revision.generation
                        && h.observation.seq == revision.seq
                })
                .or_else(|| at_key(&self.state.put_backs, key).next())
                .map(|h| h.observation.id())
        });
        let Some(mut hold) = id.and_then(|id| self.state.put_backs.get(&id)).cloned() else {
            return Ok(Publication::Observed);
        };
        let original = &hold.observation;
        if revision.generation == original.generation
            && revision.seq == original.seq
            && revision.item_hash == original.delete.item_hash
        {
            if !hold.protects
                && let Some(time) = feed_time
                && revision.seq > self.state.cursor.seq
            {
                hold.protects = true;
                if let Some((write, _)) = write {
                    write.confirm_deletion(&mut hold.observation);
                } else {
                    // The feed has verified the chain stub at this hash and position.
                    hold.observation.authenticated = true;
                }
                hold.observation.page_time_ms = Some(time);
                self.take_put_back_observation(hold, tx)?;
            }
        } else if let Some((write, repair)) = write
            && write.value().is_some()
            && self.feed_order(revision.generation, revision.seq)
                > self.feed_order(original.generation, original.seq)
        {
            if hold.observing {
                return Ok(Publication::PendingObservation);
            }
            if hold.protects
                || hold.observation.page_time_ms.is_some()
                || hold.observation.seq <= self.state.cursor.seq
            {
                match write.check_publication(self, &hold.observation, repair, tx) {
                    Ok(super::PutBackSuccessor::Covered) => {
                        self.forget_put_back(&original.id(), tx)?;
                        return Ok(Publication::Covered(original.revision()));
                    }
                    Ok(super::PutBackSuccessor::Wait) | Err(AppError::Protocol(_)) => (),
                    Err(error) => return Err(error),
                }
            }
        }
        Ok(Publication::Observed)
    }

    pub(super) async fn try_put_back(&mut self, mut hold: RecordHold) -> Result<(), AppError> {
        if hold.observation.generation > self.state.meta.generation {
            return Ok(());
        }
        if !hold.writable(&self.state.cert)? {
            return self
                .refuse_put_back(hold.observation.id(), "permission_missing")
                .await;
        }
        if hold.protects
            && !self.ready_at(
                &hold.observation.owner,
                self.feed_order(hold.observation.generation, hold.observation.seq),
                Handover::Through,
            )
        {
            return Ok(());
        }
        if !hold.protects
            && hold.observation.page_time_ms.is_none()
            && hold.observation.seq > self.state.cursor.seq
        {
            return Ok(());
        }
        let write = match self.current_put_back_write(&hold.observation).await {
            Ok(Some(write)) => write,
            Ok(None) => return Ok(()),
            Err(error) if waits(&error) || error.code() == Some(ErrorCode::PermissionMissing) => {
                return Ok(());
            }
            Err(error) => return Err(error),
        };
        let id = hold.observation.id();
        let mut tx = self.tx()?;
        if write.revision() == hold.observation.revision() {
            let changed = write.confirm_deletion(&mut hold.observation);
            let signed =
                SignedOp::peek(&hold.observation.operation).map_err(|_| super::corrupt())?;
            match self.consult_deletion(&hold.observation, &signed, &tx) {
                Ok(Some(PutBack::Observe { .. })) => self.forget_put_back(&id, &mut tx)?,
                Ok(_) | Err(AppError::Protocol(_)) if changed => {
                    self.keep_put_back(hold, &mut tx)?
                }
                Ok(_) | Err(AppError::Protocol(_)) => (),
                Err(error) => return Err(error),
            }
        } else {
            self.take_publication_candidate(write, &id, &mut tx).await?;
        }
        if !tx.is_empty() {
            self.commit(tx).await?;
        }
        Ok(())
    }

    pub(super) async fn release_put_backs_on_leave(&mut self) -> Result<(), AppError> {
        while let Some(&key) = self.state.put_backs.keys().next() {
            self.refuse_put_back(key, "left").await?;
        }
        Ok(())
    }

    /// Release a record replacement after its protocol was told that the write waits
    /// and the owner agrees it may pass that deletion (Switch spec 10.3).
    ///
    /// # Errors
    ///
    /// A usage refusal if this signed deletion has no waiting replacement, or a store failure.
    pub async fn release_put_back(
        &mut self,
        key: &[u8; 32],
        version: RecordVersion,
        item_hash: &[u8; 32],
    ) -> Result<(), AppError> {
        self.ready_local().await?;
        let delete = DeleteBase {
            version,
            item_hash: *item_hash,
        };
        let id = (*key, delete.version, delete.item_hash);
        let Some(hold) = self
            .state
            .put_backs
            .get(&id)
            .filter(|hold| hold.waited && !hold.observing)
            .cloned()
        else {
            return Err(Refusal::Usage("no waiting replacement at this record".into()).into());
        };
        let mut tx = self.tx()?;
        let op = SignedOp::peek(&hold.observation.operation).map_err(|_| super::corrupt())?;
        if !matches!(
            self.consult_deletion(&hold.observation, &op, &tx)?,
            Some(PutBack::Observe { .. })
        ) {
            return Err(Refusal::NotNow("the collection still requires publication".into()).into());
        }
        self.forget_put_back(&id, &mut tx)?;
        self.commit(tx).await
    }

    /// A protected deletion sets the earliest position that can speak for this key.
    /// At or beyond that point the service still owes the record (Switch spec 10.3).
    pub(super) async fn put_back_absence_is_current(
        &mut self,
        key: &[u8; 32],
        through: super::FeedPosition,
    ) -> Result<bool, AppError> {
        let mut current = true;
        let mut protected = false;
        for hold in at_key(&self.state.put_backs, key).filter(|h| h.protects) {
            if !self
                .state
                .cert
                .holds_scope(&hold.observation.put()?.policy.read_scope)
            {
                return Ok(false);
            }
            let at = super::FeedPosition {
                generation: hold.observation.generation,
                seq: hold.observation.seq,
            };
            if hold.needs_cursor || !self.covers(through, at) {
                current = false;
                continue;
            }
            protected = true;
            break;
        }
        if protected {
            let reason = "Switch spec 10.3: a record held for replacement is absent".into();
            return Err(self.raise(Alarm::Rollback { reason }).await);
        }
        Ok(current)
    }

    pub(super) fn keep_waiting(
        &mut self,
        mut hold: RecordHold,
        tx: &mut Tx,
    ) -> Result<(), AppError> {
        if !hold.waited {
            let duty = Duty::PutBackWaits {
                key: hold.observation.key,
                delete: hold.observation.delete,
            };
            self.keep_duty_for(tx, vec![hold.observation.owner.clone()], duty)?;
            hold.waited = true;
        }
        self.keep_put_back(hold, tx)
    }

    async fn refuse_put_back(&mut self, key: Id, reason: &str) -> Result<(), AppError> {
        let mut tx = self.tx()?;
        self.discard_put_back(key, reason, &mut tx)?;
        self.commit(tx).await
    }

    fn discard_put_back(&mut self, key: Id, reason: &str, tx: &mut Tx) -> Result<(), AppError> {
        let deletion = &self
            .state
            .put_backs
            .get(&key)
            .ok_or_else(super::corrupt)?
            .observation;
        let duty = Duty::PutBackRefused {
            key: key.0,
            delete: deletion.delete,
            reason: reason.to_owned(),
        };
        self.keep_duty_for(tx, vec![deletion.owner.clone()], duty)?;
        self.forget_put_back(&key, tx)
    }

    pub(super) fn put_backs_after_renewal(&mut self, tx: &mut Tx) -> Result<(), AppError> {
        let keys: Vec<_> = self.state.put_backs.keys().copied().collect();
        for key in keys {
            if !self.state.put_backs[&key].writable(&self.state.cert)? {
                self.discard_put_back(key, "permission_missing", tx)?;
            }
        }
        Ok(())
    }

    /// A delete passed by another copy of this app can only be replaced best effort.
    pub(super) async fn note_put_backs_passed(&mut self, cursor: u64) -> Result<(), AppError> {
        let passed: Vec<_> = self
            .state
            .put_backs
            .values()
            .filter(|h| {
                h.observation.generation <= self.state.meta.generation
                    && (h.needs_cursor || (h.protects && h.observation.seq <= cursor))
            })
            .map(|h| h.observation.id())
            .collect();
        for key in passed {
            let mut hold = self.state.put_backs[&key].clone();
            let mut tx = self.tx()?;
            hold.needs_cursor = false;
            hold.protects &= hold.observation.seq > cursor;
            self.keep_put_back(hold, &mut tx)?;
            self.commit(tx).await?;
        }
        Ok(())
    }

    /// The earliest pending deletion bounds every service cursor request.
    pub(super) fn put_back_limit(&self) -> u64 {
        let authorized = self
            .state
            .put_backs
            .values()
            .filter(|h| h.protects && h.observation.generation <= self.state.meta.generation)
            .map(|h| &h.observation);
        let cursor = self.state.cursor;
        let undecided = self.state.deletions.values().filter(|d| {
            d.page_time_ms.is_some()
                && d.generation == cursor.generation
                && d.seq > cursor.at_service
        });
        authorized
            .chain(undecided)
            .map(|d| d.seq.saturating_sub(1))
            .min()
            .unwrap_or(u64::MAX)
    }

    pub(super) fn bound_service_cursor(&self, batch: &Batch) -> Result<Option<Batch>, AppError> {
        let Some(position) = batch.cursor() else {
            return Ok(None);
        };
        let limit = self.put_back_limit();
        if position.seq <= limit || position.generation != self.state.cursor.generation {
            return Ok(None);
        }
        let cursor = Some(Position {
            generation: position.generation,
            seq: limit,
        });
        Ok(Some(Batch::new(batch.ops().to_vec(), cursor)?))
    }

    pub(super) fn keep_put_back(&mut self, hold: RecordHold, tx: &mut Tx) -> Result<(), AppError> {
        hold.observation
            .check(&self.protocols, &self.state.meta.identity)?;
        let at = hold.store_key();
        tx.put(&at, &hold)?;
        self.state.put_backs.insert(hold.observation.id(), hold);
        Ok(())
    }

    pub(super) fn forget_put_back(&mut self, key: &Id, tx: &mut Tx) -> Result<(), AppError> {
        if let Some(hold) = self.state.put_backs.remove(key) {
            tx.delete(&hold.store_key())?;
        }
        Ok(())
    }
}
