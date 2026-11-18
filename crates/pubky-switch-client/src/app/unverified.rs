//! One bounded custody pool for inputs waiting on sender standing, a scope key or protocol
//! admission (Switch spec 8.2). The age, sender and total selector counts an
//! incoming input before it is passed. Payload deletion and its payload-free notice are
//! one transaction; notices never assert that another copy or effect is absent.
//!
//! Unresolved pending effects and independently uncertain copies are protected. Upkeep
//! admits no new input and may drop in chunks. An input-inclusive selection is indivisible.

use std::collections::BTreeMap;

use pubky_switch_core::message::{MessagePlaintext, VerifiedSender};
use pubky_switch_core::records::{AppCert, DAY_MS};

use super::ProtocolSet;
use super::events::{
    AppEvent, DropReason, Duty, EventId, KeptDuty, ParkReason, StoredMessageIdentity,
};
use super::protocols::OpaqueBody;
use super::state::{HeldEntry, ParkedEntry, ParkedRound, Reader, RetryEntry, Tx, key};
use super::{App, AppError};
use serde::{Deserialize, Serialize};

/// How long an input waiting on sender standing, a key or protocol admission
/// is kept from its acceptance: 21 days, judged on the highest service time the app
/// verified, so the sender, which answers re-sends for 30 days from a message's first
/// acceptance (Switch spec 11), still can when the protocol asks.
pub const MAX_UNVERIFIED_AGE_MS: u64 = 21 * DAY_MS;

/// The most entries in the shared waiting pool the app keeps for one sender identity, the identity the entry's certificate
/// names: 64.
pub const MAX_UNVERIFIED_PER_SENDER: usize = 64;

/// The most entries in the shared waiting pool the app keeps in all: 128. The actual restore transaction must also fit the store byte bound.
pub const MAX_UNVERIFIED_TOTAL: usize = 128;

/// The most entries one upkeep commit drops. Actual encoded deletes and notices must
/// fit the store byte bound; a read takes as many upkeep steps as needed.
pub const UNVERIFIED_DROPS_PER_COMMIT: usize = 64;

/// One entry the bounds count: its local ID, sender identity and acceptance time.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Counted {
    pub(crate) id: u64,
    pub(crate) sender: [u8; 32],
    pub(crate) accepted_at_ms: u64,
}

impl Counted {
    /// The order entries go in: accepted earliest first, and of entries accepted at the
    /// same time, the one with the lowest local ID, which was stored first.
    fn order(&self) -> (u64, u64) {
        (self.accepted_at_ms, self.id)
    }
}

/// The entries past the bounds, in the order they are dropped, each with the bound it is
/// past, given every sender/key/admission input the bounds count and the highest service
/// time the app verified (`None` before any verified answer: then none is dropped for its
/// age, since the device clock alone doesn't judge it).
///
/// - **Age:** every entry kept longer than [`MAX_UNVERIFIED_AGE_MS`] from its acceptance.
/// - **Per sender:** of what is left, past a sender's [`MAX_UNVERIFIED_PER_SENDER`], that
///   sender's entries accepted earliest, sender by sender in the order of their
///   identities' bytes.
/// - **Total:** of what is left, past [`MAX_UNVERIFIED_TOTAL`], one entry at a time: the
///   one accepted earliest of the sender identity that holds the most. Of identities that
///   hold as many, the one whose newest entry is newest in the entries' order
///   ([`Counted::order`]: accepted latest, then the highest local ID), so a sender whose
///   entries began earlier, as an honest one's do when its outage began first, doesn't
///   lose the tie to identities that piled up later.
pub(crate) fn over_bounds(entries: &[Counted], verified_ms: Option<u64>) -> Vec<(u64, DropReason)> {
    let mut sorted = entries.to_vec();
    sorted.sort_by_key(Counted::order);
    let mut drops = Vec::new();
    // Each sender's entries, in the entries' order.
    let mut by_sender: BTreeMap<[u8; 32], Vec<Counted>> = BTreeMap::new();
    for entry in &sorted {
        let aged = verified_ms
            .is_some_and(|now| now.saturating_sub(entry.accepted_at_ms) > MAX_UNVERIFIED_AGE_MS);
        if aged {
            drops.push((entry.id, DropReason::Age));
        } else {
            by_sender.entry(entry.sender).or_default().push(*entry);
        }
    }
    for held in by_sender.values_mut() {
        let over = held.len().saturating_sub(MAX_UNVERIFIED_PER_SENDER);
        for entry in held.drain(..over) {
            drops.push((entry.id, DropReason::PerSender));
        }
    }
    let mut total: usize = by_sender.values().map(Vec::len).sum();
    while total > MAX_UNVERIFIED_TOTAL {
        let largest = by_sender
            .values_mut()
            .filter(|held| !held.is_empty())
            .min_by_key(|held| {
                (
                    std::cmp::Reverse(held.len()),
                    std::cmp::Reverse(held.last().map(Counted::order)),
                )
            });
        let Some(held) = largest else {
            break;
        };
        let entry = held.remove(0);
        drops.push((entry.id, DropReason::Total));
        total -= 1;
    }
    drops
}

/// A complete custody change, sized before it changes the app's in-memory state.
pub(crate) struct WaitingChange {
    tx: Tx,
    candidate: Option<(u64, ParkedEntry)>,
    removed: Vec<u64>,
    retry_remove: Vec<u64>,
    retry_move: Option<(u64, RetryEntry)>,
    feed: Option<u64>,
    next_stored_id: u64,
    next_duty: u64,
    duty_owners: Vec<(u64, Vec<String>)>,
}

impl WaitingChange {
    pub(crate) fn size(&self) -> u64 {
        self.tx.size()
    }

    pub(crate) fn retained(&self, id: u64) -> bool {
        self.candidate.as_ref().is_some_and(|(kept, _)| *kept == id)
    }

    /// The writes fit before any matching in-memory change takes effect.
    pub(crate) fn stage(self, app: &mut App, tx: &mut Tx) -> Result<(), AppError> {
        tx.append(self.tx)?;
        for id in self.removed {
            app.state.parked.remove(&id);
        }
        for id in self.retry_remove {
            app.state.stored_retries.remove(&id);
        }
        if let Some(seq) = self.feed {
            app.state.retries.remove(&seq);
        }
        if let Some((id, retry)) = self.retry_move {
            app.state.stored_retries.insert(id, retry);
        }
        if let Some((id, stored)) = self.candidate {
            app.state.parked.insert(id, stored);
        }
        app.state.next_stored_id = self.next_stored_id;
        app.state.next_duty = self.next_duty;
        app.duty_owners.extend(self.duty_owners);
        Ok(())
    }
}

impl App {
    pub(super) fn validate_waiting_state(&self) -> Result<(), AppError> {
        for held in self.state.held.values() {
            held.validate()?;
        }
        for stored in self
            .state
            .parked
            .values()
            .filter(|stored| stored.reason.bounded())
        {
            if stored.seq == 0
                || stored.generation == 0
                || stored.accepted_at_ms > stored.receipt.read_at_ms
                || (stored.reason.awaited_epoch().is_none() && stored.keys_at.is_some())
            {
                return Err(super::corrupt());
            }
            self.waiting_identity(stored)?;
        }
        Ok(())
    }

    /// Apply the shared sender/key/admission bounds before retry or backup. A pending
    /// effect's input is protected until its outcome settles (Switch spec 8.2, 11).
    pub(crate) async fn bound_unverified(&mut self) -> Result<(), AppError> {
        loop {
            let drops = self.waiting_drops(None);
            if drops.is_empty() {
                return Ok(());
            }
            let step = &drops[..drops.len().min(UNVERIFIED_DROPS_PER_COMMIT)];
            let change = self.waiting_change(None, None, step)?;
            let mut tx = self.tx()?;
            change.stage(self, &mut tx)?;
            self.commit(tx).await?;
        }
    }

    /// Whether the entry stored at `id` is in the shared waiting custody: stored for a
    /// bounded reason and not the input of a kept effect, which Switch spec 11 protects.
    pub(crate) fn in_custody(&self, id: u64) -> bool {
        self.state.parked.get(&id).is_some_and(|stored| {
            stored.reason.bounded()
                && self
                    .state
                    .pending_effect
                    .as_ref()
                    .is_none_or(|effect| effect.stored != Some(id))
        })
    }

    /// Drop the input stored at `id` from custody for `reason`, its durable notice in `tx`:
    /// the same change the bounds stage ([`App::waiting_change`]).
    pub(crate) fn drop_waiting(
        &mut self,
        id: u64,
        reason: DropReason,
        tx: &mut Tx,
    ) -> Result<(), AppError> {
        self.waiting_change(None, None, &[(id, reason)])?
            .stage(self, tx)
    }

    /// Count the currently staged pool and the incoming input together. No protected
    /// pending input is made evictable by a change of its cached waiting reason.
    pub(crate) fn waiting_drops(
        &self,
        candidate: Option<(u64, &ParkedEntry)>,
    ) -> Vec<(u64, DropReason)> {
        self.waiting_drops_at(candidate, self.highest_service_time())
    }

    pub(super) fn waiting_drops_at(
        &self,
        candidate: Option<(u64, &ParkedEntry)>,
        verified_ms: Option<u64>,
    ) -> Vec<(u64, DropReason)> {
        let pending = self
            .state
            .pending_effect
            .as_ref()
            .and_then(|effect| effect.stored);
        let mut counted: Vec<Counted> = self
            .state
            .parked
            .iter()
            .filter(|(id, stored)| {
                stored.reason.bounded()
                    && Some(**id) != pending
                    && candidate.is_none_or(|(incoming, _)| incoming != **id)
            })
            .map(|(id, stored)| counted_entry(*id, stored))
            .collect();
        if let Some((id, stored)) = candidate {
            counted.push(counted_entry(id, stored));
        }
        over_bounds(&counted, verified_ms)
    }

    /// Stage one indivisible input-inclusive selection, or an upkeep-only set of drops.
    /// `feed` is present only for a new local ID taken by an input still on the feed.
    pub(crate) fn waiting_change(
        &self,
        candidate: Option<(u64, ParkedEntry)>,
        feed: Option<u64>,
        drops: &[(u64, DropReason)],
    ) -> Result<WaitingChange, AppError> {
        let mut change = WaitingChange {
            tx: Tx::new(&self.ns),
            candidate,
            removed: Vec::new(),
            retry_remove: Vec::new(),
            retry_move: None,
            feed,
            next_stored_id: self.state.next_stored_id,
            next_duty: self.state.next_duty,
            duty_owners: Vec::new(),
        };
        if let Some((id, stored)) = &change.candidate {
            if !stored.reason.bounded()
                || self
                    .state
                    .pending_effect
                    .as_ref()
                    .is_some_and(|effect| effect.stored == Some(*id))
                || self
                    .state
                    .parked
                    .get(id)
                    .is_some_and(|old| old.reason == ParkReason::Uncertain)
            {
                return Err(super::corrupt());
            }
            self.waiting_identity(stored)?;
            if let Some(seq) = feed {
                if *id != self.state.next_stored_id || self.state.parked.contains_key(id) {
                    return Err(super::corrupt());
                }
                change.next_stored_id = id.checked_add(1).ok_or_else(super::corrupt)?;
                change.tx.put(key::STORED_NEXT, &change.next_stored_id)?;
                change.tx.delete(&key::retry(seq))?;
            } else if !self.state.parked.contains_key(id) {
                return Err(super::corrupt());
            }
            if !drops.iter().any(|(dropped, _)| dropped == id) {
                change.tx.put(&key::parked(*id), stored)?;
                if stored.reason == ParkReason::Unverifiable {
                    if let Some(retry) = feed.and_then(|seq| self.state.retries.get(&seq)).copied()
                    {
                        change.tx.put(&key::stored_retry(*id), &retry)?;
                        change.retry_move = Some((*id, retry));
                    }
                } else {
                    change.tx.delete(&key::stored_retry(*id))?;
                    change.retry_remove.push(*id);
                }
                if self
                    .state
                    .parked
                    .get(id)
                    .is_none_or(|old| old.reason != stored.reason)
                {
                    change.tx.report(AppEvent::Parked {
                        id: None,
                        seq: stored.seq,
                        stored_id: *id,
                        reason: stored.reason,
                    });
                }
            }
        }
        for (id, reason) in drops {
            if self
                .state
                .pending_effect
                .as_ref()
                .is_some_and(|effect| effect.stored == Some(*id))
            {
                return Err(super::corrupt());
            }
            let stored = change
                .candidate
                .as_ref()
                .filter(|(incoming, _)| incoming == id)
                .map(|(_, stored)| stored)
                .or_else(|| self.state.parked.get(id))
                .ok_or_else(super::corrupt)?;
            let event = EventId::new(self.state.duty_epoch.epoch, change.next_duty);
            let duty = self.waiting_notice(*id, stored, *reason, event)?;
            let to = self.duty_to(&duty);
            let kept = KeptDuty {
                to: to.clone(),
                duty,
            };
            change.tx.put(&key::duty(change.next_duty), &kept)?;
            change.duty_owners.push((change.next_duty, to));
            change.next_duty = change.next_duty.checked_add(1).ok_or_else(super::corrupt)?;
            change.tx.report(kept.duty.event(event));
            change.tx.delete(&key::parked(*id))?;
            change.tx.delete(&key::stored_retry(*id))?;
            change.removed.push(*id);
            change.retry_remove.push(*id);
        }
        if change.next_duty != self.state.next_duty {
            change.tx.put(key::DUTY_NEXT, &change.next_duty)?;
        }
        if change
            .candidate
            .as_ref()
            .is_some_and(|(id, _)| change.removed.contains(id))
        {
            change.candidate = None;
        }
        Ok(change)
    }

    /// Revalidate retained signed bytes without requiring current sender standing.
    /// A notice carries only the resulting identity, never these bytes (Switch spec 8.2).
    pub(crate) fn waiting_identity(
        &self,
        stored: &ParkedEntry,
    ) -> Result<StoredMessageIdentity, AppError> {
        waiting_identity(stored, &self.state.meta.identity)
    }

    pub(crate) fn waiting_notice(
        &self,
        id: u64,
        stored: &ParkedEntry,
        reason: DropReason,
        notice_id: EventId,
    ) -> Result<Duty, AppError> {
        Ok(Duty::StoredEntryDropped {
            stored_id: id,
            seq: stored.seq,
            generation: stored.generation,
            sender: stored.sender,
            accepted_at_ms: stored.accepted_at_ms,
            reason,
            waiting: stored.reason.waiting().ok_or_else(super::corrupt)?,
            message: self.waiting_identity(stored)?,
            sender_verified: stored.reason != ParkReason::Unverifiable,
            receipt: stored.receipt,
            notice_id,
        })
    }
}

/// Unprocessed custody and its obligations, common to plain and layered backups.
#[derive(Clone, Serialize, Deserialize)]
pub(super) struct WaitingOut {
    pub(super) entries: Vec<(u64, ParkedEntry)>,
    pub(super) retries: Vec<(u64, RetryEntry)>,
    pub(super) round: ParkedRound,
    pub(super) held: Vec<(u64, HeldEntry)>,
    pub(super) feed_retries: Vec<(u64, RetryEntry)>,
    pub(super) notices: Vec<KeptDuty>,
}

impl WaitingOut {
    pub(super) fn of(state: &super::AppState) -> Self {
        let pending = state.pending_effect.as_ref();
        let entries: Vec<_> = state
            .parked
            .iter()
            .filter(|(id, stored)| {
                stored.reason.bounded() && pending.is_none_or(|effect| effect.stored != Some(**id))
            })
            .map(|(id, stored)| (*id, stored.clone()))
            .collect();
        let held: Vec<_> = state
            .held
            .iter()
            .filter(|(seq, _)| **seq > state.cursor.seq)
            .map(|(seq, held)| (*seq, *held))
            .collect();
        Self {
            retries: state
                .stored_retries
                .iter()
                .filter(|(id, _)| entries.iter().any(|(kept, _)| kept == *id))
                .map(|(id, retry)| (*id, *retry))
                .collect(),
            feed_retries: state
                .retries
                .iter()
                .filter(|(seq, _)| held.iter().any(|(kept, _)| kept == *seq))
                .map(|(seq, retry)| (*seq, *retry))
                .collect(),
            entries,
            round: state.parked_round,
            held,
            notices: Vec::new(),
        }
    }

    /// Validate before the protocol's restore hook or any installation can use this data.
    pub(super) fn validate(
        &self,
        backup: &super::AppBackup,
        protocols: &ProtocolSet,
    ) -> Result<(), AppError> {
        let mut ids = std::collections::BTreeSet::new();
        for (id, stored) in &self.entries {
            if *id == 0
                || *id >= backup.stored_next
                || !ids.insert(*id)
                || !stored.reason.bounded()
                || stored.seq == 0
                || stored.generation == 0
                || stored.round > self.round.number
                || stored.accepted_at_ms > stored.receipt.read_at_ms
                || (stored.reason.awaited_epoch().is_none() && stored.keys_at.is_some())
            {
                return Err(super::corrupt());
            }
            waiting_identity(stored, &backup.meta.identity)?;
        }
        let mut retried = std::collections::BTreeSet::new();
        for (id, _) in &self.retries {
            if !ids.contains(id) || !retried.insert(*id) {
                return Err(super::corrupt());
            }
        }
        if let Some(layer) = &backup.beyond_cursor {
            for (id, stored) in &layer.parked {
                if *id == 0
                    || *id >= backup.stored_next
                    || !ids.insert(*id)
                    || stored.reason.bounded()
                {
                    return Err(super::corrupt());
                }
            }
        }
        let mut held = BTreeMap::new();
        for (seq, observation) in &self.held {
            observation.validate()?;
            if *seq <= backup.cursor.seq || held.insert(*seq, observation).is_some() {
                return Err(super::corrupt());
            }
        }
        // Local custody may end ahead of the cursor. While both copies are present,
        // they must describe the same observation.
        let disagrees = |generation, seq, receipt, accepted_at| {
            generation == backup.cursor.generation
                && held.get(&seq).is_some_and(|observation| {
                    observation.receipt != receipt || observation.accepted_at_ms != accepted_at
                })
        };
        let layered = backup.beyond_cursor.iter().flat_map(|layer| &layer.parked);
        if self.entries.iter().chain(layered).any(|(_, entry)| {
            disagrees(
                entry.generation,
                entry.seq,
                entry.receipt,
                entry.accepted_at_ms,
            )
        }) || self.notices.iter().any(|notice| {
            matches!(&notice.duty,
                Duty::StoredEntryDropped { seq, generation, receipt, accepted_at_ms, .. }
                if disagrees(*generation, *seq, *receipt, *accepted_at_ms))
        }) {
            return Err(super::corrupt());
        }
        let mut retries = std::collections::BTreeSet::new();
        for (seq, _) in &self.feed_retries {
            if !held.contains_key(seq) || !retries.insert(*seq) {
                return Err(super::corrupt());
            }
        }
        let mut notices = Vec::new();
        for notice in &self.notices {
            notice.check_owners(protocols)?;
            merge_notice(&mut notices, notice.clone())?;
        }
        Ok(())
    }
}

/// The identity of a retained input, for its notice and the bounds: the bytes are
/// authenticated again, by the certificate they carry, and read for their common fields
/// only (checks 2 to 6, every body member opaque: [`OpaqueBody`]). Nothing here judges
/// current protocol policy:
/// that is judged when the input is next tried, where one that no longer passes is dropped
/// as any message failing a recipient check is, so a host that changes a protocol's rules
/// never makes kept custody, or the notice of its drop, unreadable. Nor are the
/// service's facts judged here: they are checked when the page is read, so no writer keeps
/// an observation that precedes its entry's acceptance, and the structural checks beside
/// this refuse one. A failure here is stored bytes no writer produces.
pub(super) fn waiting_identity(
    stored: &ParkedEntry,
    own: &[u8; 32],
) -> Result<StoredMessageIdentity, AppError> {
    let sender = AppCert::verify(&stored.cert, &stored.sender).map_err(|_| super::corrupt())?;
    if sender.expired_at(stored.accepted_at_ms) {
        return Err(super::corrupt());
    }
    let plaintext = MessagePlaintext::decode(&stored.plaintext).map_err(|_| super::corrupt())?;
    let body = OpaqueBody::of(plaintext.json()).ok_or_else(super::corrupt)?;
    let message = plaintext
        .check(
            own,
            &stored.sender,
            &VerifiedSender::from_cert(&sender),
            &body.members(),
        )
        .map_err(|_| super::corrupt())?;
    Ok(StoredMessageIdentity {
        app_id: message.from.app_id,
        msg_id: message.msg_id,
        kind: message.kind,
        hash: plaintext.hash(),
        certificate_hash: sender.hash(),
    })
}

/// Hashes in a payload-free notice are identifiers, not a proof of the absent signature.
/// Check only the shape and relationships its retained fields can establish.
pub(super) fn notice_id(duty: &Duty) -> Result<EventId, AppError> {
    let Duty::StoredEntryDropped {
        stored_id,
        seq,
        generation,
        accepted_at_ms,
        reason,
        waiting,
        message,
        sender_verified,
        receipt,
        notice_id,
        ..
    } = duty
    else {
        return Err(super::corrupt());
    };
    if *stored_id == 0
        || *seq == 0
        || *generation == 0
        || notice_id.counter() == 0
        || *accepted_at_ms > receipt.read_at_ms
        || *sender_verified != !matches!(waiting, super::events::WaitingReason::Sender)
        // A stored input is open already: a drop on its retry fails one of recipient checks
        // 2 to 8, never check 1 or the deduplication of check 9 (Switch wire 5.1).
        || matches!(reason, DropReason::Rules { check } if !(2..=8).contains(check))
    {
        return Err(super::corrupt());
    }
    pubky_switch_core::message::check_kind(&message.kind).map_err(|_| super::corrupt())?;
    pubky_switch_core::json::check_uuid_v4(&message.msg_id).map_err(|_| super::corrupt())?;
    Ok(*notice_id)
}

pub(super) fn merge_notice(notices: &mut Vec<KeptDuty>, notice: KeptDuty) -> Result<(), AppError> {
    let id = notice_id(&notice.duty)?;
    for held in notices.iter_mut() {
        if notice_id(&held.duty)? == id {
            if held.duty != notice.duty {
                return Err(super::corrupt());
            }
            for name in notice.to {
                if !held.to.contains(&name) {
                    held.to.push(name);
                }
            }
            return Ok(());
        }
    }
    notices.push(notice);
    Ok(())
}

/// An identifiable required obligation must not turn into the generic corrupt-duty count.
pub(super) fn waiting_record(bytes: &[u8]) -> bool {
    let tag = b"StoredEntryDropped";
    bytes.windows(tag.len()).any(|part| part == tag)
}

pub(super) async fn waiting_notices(reader: &Reader) -> Result<Vec<KeptDuty>, AppError> {
    let mut notices = Vec::new();
    for (_, bytes) in reader.scan_raw(key::DUTY_PREFIX).await? {
        match super::state::decode::<KeptDuty>(&bytes) {
            Ok(kept) if matches!(kept.duty, Duty::StoredEntryDropped { .. }) => {
                merge_notice(&mut notices, kept)?;
            }
            Err(error) if waiting_record(&bytes) => return Err(error),
            _ => {}
        }
    }
    Ok(notices)
}

fn counted_entry(id: u64, stored: &ParkedEntry) -> Counted {
    Counted {
        id,
        sender: stored.sender,
        accepted_at_ms: stored.accepted_at_ms,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(id: u64, sender: u8, accepted_at_ms: u64) -> Counted {
        Counted {
            id,
            sender: [sender; 32],
            accepted_at_ms,
        }
    }

    fn reasons(drops: &[(u64, DropReason)]) -> Vec<DropReason> {
        drops.iter().map(|(_, reason)| *reason).collect()
    }

    #[test]
    fn test_unverified_bound_tie_goes_against_the_holder_whose_newest_entry_is_newest() {
        // An honest sender whose outage began first and a hostile one that piled up later,
        // 64 each, and a third holder of 1: one over. The hostile one, whose newest entry
        // is newest, loses the tie, its accepted earliest.
        let mut entries: Vec<Counted> = (0..64).map(|n| entry(1 + n, 1, 1_000 + n)).collect();
        entries.extend((0..64).map(|n| entry(100 + n, 2, 2_000 + n)));
        entries.push(entry(300, 3, 5_000));
        let drops = over_bounds(&entries, None);
        assert_eq!(drops, vec![(100, DropReason::Total)]);
        // The same entries in another order give the same drops.
        entries.reverse();
        assert_eq!(over_bounds(&entries, None), drops);
    }

    #[test]
    fn test_unverified_bound_tie_on_the_newest_times_goes_by_local_id() {
        // Two holders of 64, their entries accepted at the same times, and a third of 2: two
        // over. The holder whose newest entry has the higher local ID goes first, then the
        // other, which now holds the most.
        let mut entries: Vec<Counted> = (0..64).map(|n| entry(200 + n, 2, 1_000 + n)).collect();
        entries.extend((0..64).map(|n| entry(100 + n, 1, 1_000 + n)));
        entries.extend([entry(1, 3, 5_000), entry(2, 3, 5_001)]);
        let drops = over_bounds(&entries, None);
        assert_eq!(
            drops,
            vec![(200, DropReason::Total), (100, DropReason::Total)]
        );
        entries.reverse();
        assert_eq!(over_bounds(&entries, None), drops);
    }

    #[test]
    fn test_unverified_bound_per_sender_goes_before_the_total() {
        // 66 of one sender: the two accepted earliest go for the sender's bound, whatever
        // their local IDs.
        let entries: Vec<Counted> = (0..66).map(|n| entry(300 - n, 1, 1_000 + n)).collect();
        assert_eq!(
            over_bounds(&entries, None),
            vec![(300, DropReason::PerSender), (299, DropReason::PerSender)]
        );
    }

    #[test]
    fn test_unverified_bound_without_verified_time_drops_none_for_age() {
        let entries = [entry(1, 1, 0)];
        assert!(over_bounds(&entries, None).is_empty());
        assert_eq!(
            reasons(&over_bounds(&entries, Some(MAX_UNVERIFIED_AGE_MS + 1))),
            vec![DropReason::Age]
        );
        assert!(over_bounds(&entries, Some(MAX_UNVERIFIED_AGE_MS)).is_empty());
    }
}
