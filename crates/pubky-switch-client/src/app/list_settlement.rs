//! Order of kept peer and deny writes against a signed list read and observed operations.

use std::collections::{BTreeMap, BTreeSet};

use super::admission::observations::ReplyObservation;
use pubky_switch_core::admission::{PeerReason, ReplyGrant};
use pubky_switch_core::enc::b64;
use pubky_switch_core::ops::{OpKind, SignedOp};

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

pub(super) const EFFECT_CUTOFF: &str = "chain/list-effect/";

pub(super) fn order_key(kind: &str, who: &[u8; 32]) -> String {
    format!("{EFFECT_CUTOFF}{kind}/{}", b64(who))
}

#[derive(Clone, Copy)]
pub(super) enum ListKey<'a> {
    Kept(&'a [u8; 32]),
    Reply(&'a [u8; 32], Option<ReplyGrant>),
    Deny(&'a [u8; 32]),
}

impl<'a> ListKey<'a> {
    pub(super) fn change(kind: &'a OpKind) -> Option<(Self, bool)> {
        match kind {
            OpKind::AllowPut {
                pubky,
                reason: PeerReason::Kept,
            } => Some((Self::Kept(pubky), true)),
            OpKind::AllowDelete {
                pubky,
                reason: PeerReason::Kept,
            } => Some((Self::Kept(pubky), false)),
            OpKind::AllowPut {
                pubky,
                reason: PeerReason::Reply,
            } => Some((Self::Reply(pubky, None), true)),
            OpKind::AllowDelete {
                pubky,
                reason: PeerReason::Reply,
            } => Some((Self::Reply(pubky, None), false)),
            OpKind::DenyPut { pubky } => Some((Self::Deny(pubky), true)),
            OpKind::DenyDelete { pubky } => Some((Self::Deny(pubky), false)),
            _ => None,
        }
    }

    fn order_key(self) -> String {
        match self {
            Self::Kept(who) => order_key("kept", who),
            Self::Reply(who, _) => order_key("reply", who),
            Self::Deny(who) => order_key("deny", who),
        }
    }

    pub(super) fn local_key(self) -> String {
        match self {
            Self::Kept(who) => super::admission::allow_key(PeerReason::Kept, who),
            Self::Reply(who, _) => super::admission::observations::reply_key(who),
            Self::Deny(who) => super::admission::deny_key(who),
        }
    }
}

/// The most kept list positions one commit removes: about 1 MB of deletions.
const MAX_POSITION_DELETES: usize = 10_000;

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
    pub(super) async fn outstanding_list_batches(
        &self,
        tx: Option<&Tx>,
    ) -> Result<Vec<Batch>, AppError> {
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
    // position protects the observation from an earlier feed item as well as an
    // unanswered submission on the same key (Switch spec 7, 8.3).
    pub(super) async fn retain_list_positions(&mut self, tx: &mut Tx) -> Result<(), AppError> {
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
        let cursor = self
            .read_in::<super::state::Cursor>(key::CURSOR, tx)
            .await?
            .unwrap_or_default();
        let through = FeedPosition {
            generation: cursor.generation,
            seq: cursor.seq,
        };
        // A position kept ahead of the cursor can go only once the cursor reaches it: a
        // commit that just moves the cursor scans them when it reaches the earliest.
        let reached = match self.retained_floor {
            None => true,
            Some(None) => false,
            Some(Some(floor)) => self.feed_covers(through, floor),
        };
        let scanned = changed || (tx.advanced_list_cursor && reached);
        let saved = if scanned {
            self.reader().scan::<FeedPosition>(EFFECT_CUTOFF).await?
        } else {
            Vec::new()
        };
        if saved.is_empty() && tx.list_positions.is_empty() {
            if scanned {
                self.retained_floor = Some(None);
            }
            return Ok(());
        }
        let batches = self.outstanding_list_batches(Some(tx)).await?;
        let needed: BTreeSet<_> = batches
            .iter()
            .flat_map(|batch| batch.ops())
            .filter_map(|op| ListKey::change(&op.body().kind).map(|(key, _)| key.order_key()))
            .collect();
        let keep =
            |key: &str, position| needed.contains(key) || !self.feed_covers(through, position);
        let mut observed = std::mem::take(&mut tx.list_positions);
        let mut kept = Vec::new();
        // A commit removes a bounded number of positions, so a long backlog never takes it
        // past the store's batch size; the next commit goes on with the rest.
        let mut room = MAX_POSITION_DELETES;
        for (suffix, position) in saved {
            let key = format!("{EFFECT_CUTOFF}{suffix}");
            let latest = observed.get(&key).copied().unwrap_or(position);
            if !keep(&key, latest) && room > 0 {
                tx.delete(&key)?;
                room -= 1;
            } else if !keep(&key, latest) {
                kept.push(position);
            } else if tx.pending_state(&key) == Some(false) {
                // A chain rewrite retains an observation the cursor or an original still needs.
                observed.entry(key).or_insert(position);
            } else if !observed.contains_key(&key) {
                kept.push(position);
            }
        }
        for (key, position) in observed {
            if keep(&key, position) {
                tx.put(&key, &position)?;
                kept.push(position);
            }
        }
        let earliest = kept
            .into_iter()
            .reduce(|a, b| match self.received_order(a, b) {
                Some(std::cmp::Ordering::Greater) => b,
                _ => a,
            });
        self.retained_floor = match (scanned, self.retained_floor, earliest) {
            // Positions past the deletion bound are still to go: the next commit scans again.
            (true, _, _) if room == 0 => None,
            (true, _, earliest) => Some(earliest),
            (false, Some(Some(floor)), Some(new)) => Some(Some(
                if self.received_order(floor, new) == Some(std::cmp::Ordering::Greater) {
                    new
                } else {
                    floor
                },
            )),
            (false, Some(None), new) => Some(new),
            (false, floor, None) => floor,
            (false, None, Some(_)) => None,
        };
        Ok(())
    }

    pub(super) fn feed_covers(&self, cursor: FeedPosition, position: FeedPosition) -> bool {
        self.received_order(cursor, position)
            .is_some_and(|order| order.is_ge())
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
            // Only kept and deny writes are placed: no reader orders a reply write by it.
            let placed = batch.ops().iter().any(|op| {
                matches!(
                    ListKey::change(&op.body().kind),
                    Some((ListKey::Kept(_) | ListKey::Deny(_), _))
                )
            });
            if !placed {
                continue;
            }
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
        // A reply change applied at no position the app can order against what it has seen,
        // as after an unseen move, only drops the local row, unless a later generation's
        // read or change already covers it: the next send repeats the grant if it is still
        // owed, and the service takes a held reason again as a repeat (Switch spec 7). It
        // never waits for an order, so receiving and sending go on.
        if let (ListKey::Reply(..), ListPlacement::Generation(_)) = (&key, placement) {
            tx.delete(&key.local_key())?;
            return Ok(());
        }
        let applies = self.after_list_observations(position, full, previous)?;
        // A removal seen at the new service is left out of a provider loss's owed list upload
        // even when a complete read already covers it: the read took the lists as they were
        // then, and the upload must not put the entry back. Leaving out only narrows (Switch
        // spec 12.6 step 3).
        if !applies
            && !present
            && let ListKey::Kept(who) | ListKey::Deny(who) = key
        {
            self.note_loss_list_change(&key.local_key(), who, false, tx)
                .await?;
        }
        if applies {
            let local = key.local_key();
            match key {
                ListKey::Kept(who) | ListKey::Deny(who) => {
                    // Written without a restore's mark: the change verifies the row.
                    self.note_loss_list_change(&local, who, present, tx).await?;
                    if present {
                        tx.put_raw(&local, Vec::new())?;
                    } else {
                        tx.delete(&local)?;
                    }
                }
                ListKey::Reply(_, _) if !present => {
                    tx.delete(&local)?;
                }
                ListKey::Reply(_, Some(grant)) => {
                    let observed = ReplyObservation::Observed {
                        grant,
                        as_of_ms: grant.at,
                    };
                    tx.put_raw(&local, observed.bytes())?;
                }
                ListKey::Reply(who, None) => {
                    // An idempotent app grant gives no new evidence about its first writer:
                    // a verified row keeps its observation. Any other row is written as
                    // membership alone: a restored one, whose observation may be of a grant
                    // removed since, and one that doesn't read back.
                    let verified = match tx.pending_state(&local) {
                        Some(written) => written,
                        None => {
                            super::admission::observations::verified_row(&self.reader(), false, who)
                                .await?
                        }
                    };
                    if !verified {
                        tx.put_raw(&local, ReplyObservation::Present.bytes())?;
                    }
                }
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
            // A reply operation of the old service is never placed: a loss discards every
            // reply row, and a move or key change drops the row the operation touched
            // ([`App::settle_old_op`]). Only kept and deny writes contribute to the
            // replacement, and need their original placements.
            let needs_position = batch.ops().iter().any(|op| {
                matches!(
                    ListKey::change(&op.body().kind),
                    Some((ListKey::Kept(_) | ListKey::Deny(_), _))
                )
            });
            let start = if needs_position {
                self.list_batch_start(&batch).await?
            } else {
                None
            };
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
                if matches!(key, ListKey::Reply(_, _)) {
                    continue;
                }
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
