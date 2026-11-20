//! Order of contact and deny writes against a signed list read and observed operations.

use std::collections::{BTreeMap, BTreeSet};

use pubky_switch_core::enc::b64;
use pubky_switch_core::ops::{AllowKind, OpKind, SignedOp};

use super::batch::{PENDING_PREFIX, PendingBatch};
use super::chain::PageCheck;
use super::error::Refusal;
use super::state::{PendingEffect, Tx, key};
use super::{App, AppError, FeedPosition};
use crate::client::Batch;
use crate::store::Write;

/// Evidence for the order of one applied list write (Switch spec 8.3, 12.5).
#[derive(Clone, Copy)]
pub(super) enum ListPlacement {
    /// A verified operation proof or feed envelope.
    At(FeedPosition),
    /// Application is known at the original service, but its position is unavailable.
    Generation(u64),
    /// The loss transaction already compared the old originals and complete read.
    Ordered(Option<FeedPosition>),
}

pub(super) fn placement_key(id: &[u8; 16]) -> String {
    format!("chain/list-batch/{}", b64(id))
}

const EFFECT_CUTOFF: &str = "chain/list-effect/";

pub(super) fn order_key(kind: &str, who: &[u8; 32]) -> String {
    format!("{EFFECT_CUTOFF}{kind}/{}", b64(who))
}

#[derive(Clone, Copy)]
pub(super) enum ListKey<'a> {
    Contact(&'a [u8; 32]),
    Deny(&'a [u8; 32]),
}

impl<'a> ListKey<'a> {
    pub(super) fn change(kind: &'a OpKind) -> Option<(Self, bool)> {
        match kind {
            OpKind::AllowPut {
                pubky,
                kind: AllowKind::Contact,
            } => Some((Self::Contact(pubky), true)),
            OpKind::AllowDelete {
                pubky,
                kind: AllowKind::Contact,
            } => Some((Self::Contact(pubky), false)),
            OpKind::DenyPut { pubky } => Some((Self::Deny(pubky), true)),
            OpKind::DenyDelete { pubky } => Some((Self::Deny(pubky), false)),
            _ => None,
        }
    }

    fn order_key(self) -> String {
        match self {
            Self::Contact(who) => order_key("contact", who),
            Self::Deny(who) => order_key("deny", who),
        }
    }

    fn local_key(self) -> String {
        match self {
            Self::Contact(who) => super::admission::allow_key(AllowKind::Contact, who),
            Self::Deny(who) => super::admission::deny_key(who),
        }
    }
}

fn unplaced() -> AppError {
    Refusal::NotNow("the old service's list writes cannot yet be ordered".into()).into()
}

#[derive(Clone, Copy)]
pub(super) enum OldWrite {
    Covered,
    Apply(Option<FeedPosition>),
}

#[derive(Default)]
pub(super) struct OldListWrites {
    by_op: BTreeMap<([u8; 16], usize), OldWrite>,
}

impl OldListWrites {
    pub(super) fn get(&self, op: &SignedOp, index: usize) -> Option<OldWrite> {
        self.by_op.get(&(op.body().batch.id, index)).copied()
    }
}

// Only stubs from signed verified pages, belonging to a batch still of interest.
// Separate pages may cover different members. The envelope binds the generation,
// sequence, batch ID, count and exact signed operation hash.
type Members = BTreeMap<u64, (u64, String)>;

impl App {
    async fn outstanding_list_batches(&self, tx: Option<&Tx>) -> Result<Vec<Batch>, AppError> {
        let mut result = Vec::new();
        let mut kept = self.reader().scan::<PendingBatch>(PENDING_PREFIX).await?;
        let effect = if let Some(tx) = tx {
            kept.retain(|(id, _)| tx.pending_state(&format!("{PENDING_PREFIX}{id}")).is_none());
            for id in tx.pending_put_keys(PENDING_PREFIX) {
                if let Some(Some(pending)) = tx.pending_get(&format!("{PENDING_PREFIX}{id}"))? {
                    kept.push((id, pending));
                }
            }
            self.read_in::<PendingEffect>(key::PENDING_EFFECT, tx)
                .await?
        } else {
            self.state.pending_effect.clone()
        };
        let bodies = kept.into_iter().map(|(_, pending)| pending.body);
        for body in bodies.chain(effect.into_iter().map(|p| p.body)) {
            let batch = Batch::from_body(body)?;
            if batch
                .ops()
                .iter()
                .any(|op| ListKey::change(&op.body().kind).is_some())
            {
                result.push(batch);
            }
        }
        Ok(result)
    }

    // Save the applied per-key order in the same commit as the local list. A
    // position is needed only while a still-unanswered submission on that key
    // could replace it. A receive effect and a kept batch can overlap.
    pub(super) async fn retain_list_positions(&self, tx: &mut Tx) -> Result<(), AppError> {
        let changed = tx.pending_writes().iter().any(|write| match write {
            Write::Delete { key: k, .. } => {
                k.starts_with(PENDING_PREFIX.as_bytes()) || k == key::PENDING_EFFECT.as_bytes()
            }
            Write::DeletePrefix { prefix, .. } => {
                EFFECT_CUTOFF.as_bytes().starts_with(prefix)
                    || key::PENDING_EFFECT.as_bytes().starts_with(prefix)
                    || PENDING_PREFIX.as_bytes().starts_with(prefix)
                    || prefix.starts_with(PENDING_PREFIX.as_bytes())
            }
            _ => false,
        });
        let saved = if changed {
            self.reader().scan::<FeedPosition>(EFFECT_CUTOFF).await?
        } else {
            Vec::new()
        };
        if saved.is_empty() && tx.list_positions.is_empty() {
            return Ok(());
        }
        let batches = self.outstanding_list_batches(Some(tx)).await?;
        let needed: BTreeSet<_> = batches
            .iter()
            .flat_map(|batch| batch.ops())
            .filter_map(|op| ListKey::change(&op.body().kind).map(|(key, _)| key.order_key()))
            .collect();
        let mut observed = std::mem::take(&mut tx.list_positions);
        for (suffix, position) in saved {
            let key = format!("{EFFECT_CUTOFF}{suffix}");
            if !needed.contains(&key) {
                tx.delete(&key)?;
            } else if tx.pending_state(&key) == Some(false) {
                // A rewritten chain prefix must carry the marker of an open original.
                observed.entry(key).or_insert(position);
            }
        }
        for (key, position) in observed {
            if needed.contains(&key) {
                tx.put(&key, &position)?;
            }
        }
        Ok(())
    }

    pub(super) async fn keep_list_placements(
        &self,
        page: &PageCheck,
        tx: &mut Tx,
    ) -> Result<(), AppError> {
        if !page.envelopes.values().any(|env| env.batch.is_some()) {
            return Ok(());
        }
        let mut waiting = BTreeMap::new();
        for batch in self.outstanding_list_batches(None).await? {
            if let Some(first) = batch.ops().first() {
                waiting.insert(
                    first.body().batch.id,
                    (first.body().batch, first.body().generation, Vec::new()),
                );
            }
        }
        if waiting.is_empty() {
            return Ok(());
        }
        for env in page.envelopes.values() {
            if let Some(tag) = env.batch
                && let Some((expected, generation, stubs)) = waiting.get_mut(&tag.id)
            {
                if tag != *expected || env.generation != *generation {
                    return Err(unplaced());
                }
                stubs.push(*env);
            }
        }
        for (id, (tag, _, stubs)) in waiting {
            if stubs.is_empty() {
                continue;
            }
            let key = placement_key(&id);
            let mut members: Members = self.read_in(&key, tx).await?.unwrap_or_default();
            for envelope in stubs {
                let member = (envelope.generation, b64(&envelope.item_hash));
                if let Some(previous) = members.insert(envelope.seq, member.clone())
                    && previous != member
                {
                    return Err(unplaced());
                }
            }
            if u64::try_from(members.len()).map_err(|_| unplaced())? > tag.count {
                return Err(unplaced());
            }
            tx.put(&key, &members)?;
        }
        Ok(())
    }

    // The batch ID in the verifier establishes application; by itself it carries
    // no sequence. Recheck the exact members in their original signed order.
    async fn list_batch_start(&self, batch: &Batch) -> Result<Option<FeedPosition>, AppError> {
        let Some(id) = batch.id() else {
            return Ok(None);
        };
        let Some(members) = self.reader().get::<Members>(&placement_key(&id)).await? else {
            return Ok(None);
        };
        let Some((&first, (generation, _))) = members.first_key_value() else {
            return Ok(None);
        };
        let first = FeedPosition {
            generation: *generation,
            seq: first,
        };
        let ops = batch.ops();
        if members.len() != ops.len() {
            return Err(unplaced());
        }
        for ((index, op), (seq, (generation, hash))) in ops.iter().enumerate().zip(members) {
            if Some(seq)
                != first
                    .seq
                    .checked_add(u64::try_from(index).map_err(|_| unplaced())?)
                || generation != op.body().generation
                || hash != b64(&op.item_hash()?)
            {
                return Err(unplaced());
            }
        }
        Ok(Some(first))
    }

    /// Either a full read or a later operation on this key can cover the original.
    /// To advance the view, every observation must precede it.
    pub(super) fn after_list_observations(
        &self,
        position: Option<FeedPosition>,
        full: Option<Option<FeedPosition>>,
        key: Option<FeedPosition>,
    ) -> Result<bool, AppError> {
        let mut ordered = true;
        for cutoff in full.into_iter().chain(key.map(Some)) {
            match position
                .zip(cutoff)
                .and_then(|(a, b)| self.received_order(a, b))
            {
                Some(std::cmp::Ordering::Greater) => {}
                Some(_) => return Ok(false),
                None => ordered = false,
            }
        }
        ordered.then_some(true).ok_or_else(unplaced)
    }

    pub(super) async fn list_cutoff(&self) -> Result<Option<Option<FeedPosition>>, AppError> {
        self.reader().get(super::admission::LIST_POSITION).await
    }

    /// Apply a change only when both the complete read and the latest observation
    /// for the same key permit it (Switch spec 8.3, 12.5).
    pub(super) async fn apply_list_change(
        &self,
        key: ListKey<'_>,
        present: bool,
        placement: ListPlacement,
        tx: &mut Tx,
    ) -> Result<(), AppError> {
        let position = match placement {
            ListPlacement::Ordered(position) => position,
            ListPlacement::At(position) => Some(position),
            ListPlacement::Generation(_) => None,
        };
        let prequalified = matches!(placement, ListPlacement::Ordered(_));
        let full = if prequalified {
            None
        } else {
            self.read_in(super::admission::LIST_POSITION, tx).await?
        };
        let order = key.order_key();
        let previous = match tx.list_positions.get(&order) {
            Some(previous) => Some(*previous),
            None if prequalified => None,
            None => self.read_in::<FeedPosition>(&order, tx).await?,
        };
        // An imported ID proves application in its original generation without a
        // sequence. A later generation's full read or same-key change covers it.
        if let ListPlacement::Generation(generation) = placement
            && full
                .flatten()
                .into_iter()
                .chain(previous)
                .any(|cutoff| generation < cutoff.generation)
        {
            return Ok(());
        }
        if self.after_list_observations(position, full, previous)? {
            let local = key.local_key();
            if present {
                tx.put(&local, &())?;
            } else {
                tx.delete(&local)?;
            }
            if let Some(position) = position {
                tx.list_positions.insert(order, position);
            }
        }
        Ok(())
    }

    // Decide every affected operation before retiring any batch or mutating the
    // followed generation. Only the last applicable operation on each list key
    // determines its contribution. Local storage key order says nothing about it.
    pub(super) async fn old_list_writes(&self) -> Result<OldListWrites, AppError> {
        let mut placed = Vec::new();
        for batch in self.outstanding_list_batches(None).await? {
            let Some(id) = batch.id() else { continue };
            if !self
                .state
                .chain
                .as_ref()
                .is_some_and(|chain| chain.holds_batch(&id))
            {
                continue;
            }
            let start = self.list_batch_start(&batch).await?;
            placed.push((batch, start));
        }
        self.project_old_list_batches(&placed).await
    }

    pub(super) async fn project_old_list_batches(
        &self,
        placed: &[(Batch, Option<FeedPosition>)],
    ) -> Result<OldListWrites, AppError> {
        let mut plan = OldListWrites::default();
        if placed.is_empty() {
            return Ok(plan);
        }
        let mut winners = BTreeMap::<String, (([u8; 16], usize), Option<FeedPosition>)>::new();
        let cutoff = self.list_cutoff().await?;
        for (batch, start) in placed {
            let Some(id) = batch.id() else { continue };
            for (index, op) in batch.ops().iter().enumerate() {
                let Some((key, _)) = ListKey::change(&op.body().kind) else {
                    continue;
                };
                let pos = match start {
                    Some(first) => Some(FeedPosition {
                        seq: first
                            .seq
                            .checked_add(u64::try_from(index).map_err(|_| unplaced())?)
                            .ok_or_else(unplaced)?,
                        ..*first
                    }),
                    None => None,
                };
                let slot = (id, index);
                plan.by_op.insert(slot, OldWrite::Covered);
                let key = key.order_key();
                let previous = self.reader().get::<FeedPosition>(&key).await?;
                if !self.after_list_observations(pos, cutoff, previous)? {
                    continue;
                }
                if let Some((older, previous)) = winners.get(&key) {
                    let relative = pos
                        .zip(*previous)
                        .and_then(|(a, b)| self.received_order(a, b));
                    if !relative.ok_or_else(unplaced)?.is_gt() {
                        continue;
                    }
                    plan.by_op.insert(*older, OldWrite::Covered);
                }
                winners.insert(key, (slot, pos));
                plan.by_op.insert(slot, OldWrite::Apply(pos));
            }
        }
        Ok(plan)
    }
}
