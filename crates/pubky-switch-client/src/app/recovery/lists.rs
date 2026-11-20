//! The contacts and denies this installation can contribute after a provider loss
//! (Switch spec 8.3, 12.6 step 2).

use std::collections::BTreeSet;

use pubky_switch_core::enc::{pubky_id, pubky_key, serde_b64_vec};
use serde::{Deserialize, Serialize};

use super::{App, AppError, LossRecord, RecoveryStep, Refusal, corrupt, keys};
use crate::app::state::{Reader, Tx};
use crate::store::Write;

const CONTACTS: &str = "lc/contact/";
const DENIES: &str = "lc/deny/";
const INPUT: &str = "loss/list-input";
const REMAINING: &str = "loss/list-remaining";
const REMOVED: &str = "loss/list-removed/";

/// The original contribution. Its packed, sorted IDs are independent of both
/// the replacement's signed list and later per-peer changes at that service.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(in crate::app) struct ListInput {
    source: u64,
    target: u64,
    #[serde(with = "serde_b64_vec")]
    contacts: Vec<u8>,
    #[serde(with = "serde_b64_vec")]
    deny: Vec<u8>,
}

fn packed(ids: BTreeSet<[u8; 32]>) -> Vec<u8> {
    ids.into_iter().flatten().collect()
}

fn ids(bytes: &[u8]) -> Result<&[[u8; 32]], AppError> {
    let (rows, remainder) = bytes.as_chunks::<32>();
    if !remainder.is_empty() || rows.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err(corrupt());
    }
    Ok(rows)
}

impl ListInput {
    fn check(&self) -> Result<(), AppError> {
        if self.source >= self.target {
            return Err(corrupt());
        }
        ids(&self.contacts)?;
        ids(&self.deny)?;
        Ok(())
    }

    pub(super) fn has_denies(&self) -> bool {
        !self.deny.is_empty()
    }

    pub(super) fn upload(
        &self,
        manage: bool,
    ) -> Result<crate::client::answers::UploadLists, AppError> {
        let wire_order = |bytes: &[u8]| -> Result<Vec<[u8; 32]>, AppError> {
            let mut ordered = ids(bytes)?.to_vec();
            ordered.sort_by_cached_key(pubky_id);
            Ok(ordered)
        };
        Ok(crate::client::answers::UploadLists {
            contacts: manage.then(|| wire_order(&self.contacts)).transpose()?,
            deny: wire_order(&self.deny)?,
        })
    }

    pub(super) fn install(&self, tx: &mut Tx) -> Result<(), AppError> {
        tx.put(INPUT, self)
    }
}

fn removed_prefix(peers: &str) -> String {
    format!("{REMOVED}{peers}")
}

/// Read one list as the transaction will leave it, including signed changes
/// it already settled. Prefix deletes are ordered with the exact puts/deletes.
async fn members(reader: &Reader, tx: &Tx, prefix: &str) -> Result<BTreeSet<[u8; 32]>, AppError> {
    let mut keys: BTreeSet<Vec<u8>> = reader
        .scan_raw(prefix)
        .await?
        .into_iter()
        .map(|(key, _)| key.into_bytes())
        .collect();
    let prefix = prefix.as_bytes();
    for write in tx.pending_writes() {
        match write {
            Write::Put { key, .. } => {
                if let Some(id) = key.strip_prefix(prefix) {
                    keys.insert(id.to_vec());
                }
            }
            Write::Delete { key, .. } => {
                if let Some(id) = key.strip_prefix(prefix) {
                    keys.remove(id);
                }
            }
            Write::DeletePrefix {
                prefix: removed, ..
            } => {
                if prefix.starts_with(removed) {
                    keys.clear();
                } else if let Some(tail) = removed.strip_prefix(prefix) {
                    keys.retain(|key| !key.starts_with(tail));
                }
            }
        }
    }
    keys.into_iter()
        .map(|key| {
            pubky_key(std::str::from_utf8(&key).map_err(|_| corrupt())?).map_err(|_| corrupt())
        })
        .collect()
}

async fn collect(
    reader: &Reader,
    source: u64,
    target: u64,
    tx: &Tx,
    previous: Option<&ListInput>,
) -> Result<ListInput, AppError> {
    let mut contacts = members(reader, tx, CONTACTS).await?;
    let mut deny = members(reader, tx, DENIES).await?;
    if let Some(previous) = previous {
        previous.check()?;
        if previous.target > target {
            return Err(corrupt());
        }
        // An aggregate answer identifies no individual accepted member.
        // Keep the old contribution until a subsequent full observation,
        // except for individually removed peers. A new loss can supersede
        // the old one even before its list upload has received an answer.
        for (current, prefix, old) in [
            (&mut contacts, CONTACTS, &previous.contacts),
            (&mut deny, DENIES, &previous.deny),
        ] {
            let removed = members(reader, tx, &removed_prefix(prefix)).await?;
            current.extend(ids(old)?.iter().filter(|id| !removed.contains(*id)));
        }
    }
    Ok(ListInput {
        source,
        target,
        contacts: packed(contacts),
        deny: packed(deny),
    })
}

async fn fallback(reader: &Reader) -> Result<Option<ListInput>, AppError> {
    match reader.get(REMAINING).await? {
        Some(reduced) => Ok(Some(reduced)),
        None => reader.get(INPUT).await,
    }
}

impl App {
    pub(super) async fn collect_loss_lists(
        &self,
        source: u64,
        target: u64,
        tx: &Tx,
    ) -> Result<ListInput, AppError> {
        let reader = self.reader();
        let previous = fallback(&reader).await?;
        collect(&reader, source, target, tx, previous.as_ref()).await
    }

    /// A subsequent removal narrows what can be contributed to another loss;
    /// it does not edit the still-owed original POST. Retain a removal only for
    /// a member of that snapshot, so distinct unrelated removes cannot grow it.
    pub(in crate::app) async fn note_loss_list_change(
        &self,
        key: &str,
        pubky: &[u8; 32],
        present: bool,
        tx: &mut Tx,
    ) -> Result<(), AppError> {
        let removed = format!("{REMOVED}{key}");
        if present {
            if self.read_in::<()>(&removed, tx).await?.is_some() {
                tx.delete(&removed)?;
            }
        } else if let Some(input) = fallback(&self.reader()).await? {
            let prior = if key.starts_with(CONTACTS) {
                &input.contacts
            } else {
                &input.deny
            };
            if ids(prior)?.binary_search(pubky).is_ok() {
                tx.put(&removed, &())?;
            }
        }
        Ok(())
    }

    pub(in crate::app) async fn list_read_after_upload(&self, tx: &mut Tx) -> Result<(), AppError> {
        let reader = self.reader();
        if !reader.exists(PENDING).await?
            && reader.exists(INPUT).await?
            && self
                .loss_record()
                .await?
                .is_none_or(|loss| loss.step > RecoveryStep::Lists)
        {
            tx.delete(INPUT)?;
            tx.delete(REMAINING)?;
            tx.delete_prefix(REMOVED)?;
        }
        Ok(())
    }

    pub(super) async fn original_list_input(
        &self,
        loss: &LossRecord,
    ) -> Result<ListInput, AppError> {
        let input: ListInput = self.reader().get(INPUT).await?.ok_or_else(corrupt)?;
        if (input.source, input.target) != (loss.lost_generation, loss.generation) {
            return Err(corrupt());
        }
        Ok(input)
    }
}

/// The recoverable list input in a plain or layered backup. Only the Lists step
/// can resume from these fields: it has already registered and uploaded the
/// evidence it held. Later steps retain only the locally recoverable membership.
#[derive(Clone, Serialize, Deserialize)]
pub(in crate::app) struct SavedLists {
    input: ListInput,
    waiting: Option<ListResume>,
    remaining: Option<ListInput>,
}

/// The completed registration and evidence steps leave just these values for
/// the remaining callbacks and their public recovery information. No earlier
/// signed batch or evidence upload is replayed from this checkpoint.
#[derive(Clone, Serialize, Deserialize)]
struct ListResume {
    key_n: u64,
    declared_at_ms: u64,
    cursor_time_ms: u64,
    clock_offset_ms: u64,
    claim_entries_left_out: u64,
}

impl ListResume {
    fn of(loss: &LossRecord) -> Result<Self, AppError> {
        if loss.step != RecoveryStep::Lists
            || !loss.batch.is_empty()
            || !loss.asked.is_empty()
            || !loss.conversations.is_empty()
        {
            return Err(corrupt());
        }
        Ok(Self {
            key_n: loss.key_n,
            declared_at_ms: loss.declared_at_ms.ok_or_else(corrupt)?,
            cursor_time_ms: loss.cursor_time_ms,
            clock_offset_ms: loss.clock_offset_ms,
            claim_entries_left_out: loss.claim_entries_left_out,
        })
    }

    fn resume(&self, input: &ListInput) -> LossRecord {
        LossRecord {
            lost_generation: input.source,
            generation: input.target,
            step: RecoveryStep::Lists,
            newest_head: None,
            cursor_time_ms: self.cursor_time_ms,
            declared_at_ms: Some(self.declared_at_ms),
            old_offset_ms: None,
            clock_offset_ms: self.clock_offset_ms,
            key_n: self.key_n,
            batch: Vec::new(),
            conversations: Vec::new(),
            conversations_left_out: 0,
            claim_entries_left_out: self.claim_entries_left_out,
            asked: Vec::new(),
        }
    }
}

pub(super) const PENDING: &str = "loss/lists-pending";
pub(in crate::app) const FINISHED: &str = "loss-lists-finished";

impl SavedLists {
    pub(in crate::app) async fn read(reader: &Reader) -> Result<Option<Self>, AppError> {
        let Some(input) = reader.get::<ListInput>(INPUT).await? else {
            return Ok(None);
        };
        input.check()?;
        let loss = reader.get::<LossRecord>(keys::LOSS).await?;
        let waiting = if reader.exists(PENDING).await? {
            let loss = loss.ok_or_else(corrupt)?;
            if loss.step < RecoveryStep::Lists {
                // Restoring the preceding registration or evidence step requires
                // its own inputs. Neither is represented as an applied list step.
                return Ok(None);
            }
            if loss.step != RecoveryStep::Lists
                || (loss.lost_generation, loss.generation) != (input.source, input.target)
            {
                return Err(corrupt());
            }
            Some(ListResume::of(&loss)?)
        } else {
            if reader.get::<u64>(FINISHED).await? != Some(input.target) {
                return Ok(None);
            }
            None
        };
        // Pack the net recoverable membership rather than installing a store
        // write for every removed or added peer during a restore. It does not
        // establish present admission. The original POST remains unchanged.
        let fallback: Option<ListInput> = reader.get(REMAINING).await?;
        let current = collect(
            reader,
            input.source,
            input.target,
            &Tx::new(&reader.ns),
            Some(fallback.as_ref().unwrap_or(&input)),
        )
        .await?;
        let remaining = (current != input).then_some(current);
        Ok(Some(Self {
            input,
            waiting,
            remaining,
        }))
    }

    pub(in crate::app) fn check(
        &self,
        backup: &crate::app::AppBackup,
        own: &pubky_switch_core::records::IdentityDoc,
    ) -> Result<(), AppError> {
        let invalid = || AppError::InvalidData("the backup's list recovery is inconsistent".into());
        self.input.check().map_err(|_| invalid())?;
        let source = self.input.source;
        let target = self.input.target;
        if target > backup.meta.generation
            || own.generation() < target
            || own.body().recovery_from.is_none_or(|lost| {
                lost < source || (own.generation() == backup.meta.generation && lost >= target)
            })
        {
            return Err(invalid());
        }
        if let Some(remaining) = &self.remaining {
            remaining.check().map_err(|_| invalid())?;
            if (remaining.source, remaining.target) != (source, target) {
                return Err(invalid());
            }
        }
        let completed = backup.finished_list_upload == Some(target);
        if self.waiting.is_none() != completed
            || backup
                .finished_list_upload
                .is_some_and(|done| done > target)
        {
            return Err(invalid());
        }
        if let Some(loss) = &self.waiting {
            let max_time = pubky_switch_core::time::MAX_TIME_MS;
            if loss.declared_at_ms > max_time || loss.cursor_time_ms > max_time {
                return Err(invalid());
            }
        }
        Ok(())
    }

    pub(in crate::app) async fn check_destination(
        reader: &Reader,
        incoming: Option<&Self>,
        incoming_generation: u64,
        incoming_finished: Option<u64>,
    ) -> Result<Option<u64>, AppError> {
        let live = reader.get::<LossRecord>(keys::LOSS).await?;
        let finished = reader.get::<u64>(FINISHED).await?;
        let pending = incoming
            .filter(|saved| saved.waiting.is_some())
            .map(|saved| saved.input.target);
        let held = || {
            AppError::from(Refusal::NotNow(
                "the backup predates the installation's list recovery".into(),
            ))
        };
        if finished.is_some_and(|done| done > incoming_generation)
            || pending.is_some_and(|next| finished.is_some_and(|done| done >= next))
        {
            return Err(held());
        }
        if let Some(live) = live
            && reader.exists(PENDING).await?
            && live.step == RecoveryStep::Lists
            && pending.is_none_or(|next| next < live.generation)
        {
            return Err(held());
        }
        if let Some(current) = Self::read(reader).await? {
            match incoming {
                Some(next) if next.input.target > current.input.target => {}
                Some(next)
                    if next.input == current.input && next.remaining == current.remaining => {}
                _ => return Err(held()),
            }
        } else if incoming
            .is_some_and(|next| finished.is_some_and(|done| done >= next.input.target))
        {
            // A signed full read retired the fallback held by this backup.
            return Err(held());
        }
        Ok(finished.max(incoming_finished))
    }

    pub(in crate::app) fn restore(&self, tx: &mut Tx) -> Result<(), AppError> {
        self.input.install(tx)?;
        if let Some(remaining) = &self.remaining {
            tx.put(REMAINING, remaining)?;
        }
        if let Some(loss) = &self.waiting {
            tx.put(keys::LOSS, &loss.resume(&self.input))?;
            tx.put(PENDING, &())?;
        }
        Ok(())
    }
}

pub(super) fn pending(tx: &mut Tx) -> Result<(), AppError> {
    tx.put(PENDING, &())
}

pub(super) fn submitted(tx: &mut Tx, generation: u64) -> Result<(), AppError> {
    tx.delete(PENDING)?;
    tx.put(FINISHED, &generation)
}

pub(in crate::app) fn clear_on_leave(tx: &mut Tx) -> Result<(), AppError> {
    tx.delete(INPUT)?;
    tx.delete(REMAINING)?;
    tx.delete(PENDING)?;
    tx.delete(FINISHED)?;
    tx.delete_prefix(REMOVED)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::MAX_BATCH_BYTES;

    #[test]
    fn test_default_recovery_lists_fit_as_original_and_reduced_backup_inputs() {
        // Switch wire 9.1: the default quotas permit 100,000 contacts and denies
        // each. Two complete sets can coexist if observations changed before
        // the Lists-step backup. Use the actual protected value and batch codec.
        let peers = |domain: u8| {
            let mut result = Vec::with_capacity(100_000 * 32);
            for n in 0u32..100_000 {
                let mut peer = [domain; 32];
                peer[28..].copy_from_slice(&n.to_be_bytes());
                result.extend_from_slice(&peer);
            }
            result
        };
        let input = ListInput {
            source: 1,
            target: 2,
            contacts: peers(1),
            deny: peers(2),
        };
        let remaining = ListInput {
            source: 1,
            target: 2,
            contacts: peers(3),
            deny: peers(4),
        };
        input.check().unwrap();
        remaining.check().unwrap();
        let mut tx = Tx::new(&"a".repeat(120));
        input.install(&mut tx).unwrap();
        tx.put(REMAINING, &remaining).unwrap();
        tx.put(PENDING, &()).unwrap();
        assert!(tx.size() < MAX_BATCH_BYTES);
        assert!(tx.size() > 16 * 1024 * 1024);
    }
}
