//! The bounds on entries stored because their sender's standing couldn't be checked
//! (Switch spec 8.2, [`ParkReason::Unverifiable`]), and on entries stored because they
//! wait for a scope key ([`ParkReason::AwaitingKey`]), the two counted together: at most
//! [`MAX_UNVERIFIED_AGE_MS`] from acceptance, [`MAX_UNVERIFIED_PER_SENDER`] per sender
//! identity and [`MAX_UNVERIFIED_TOTAL`] in all. Past them the app drops entries without
//! processing them and tells its protocol ([`AppEvent::StoredEntryDropped`]), which may ask
//! the sender to send them again (Switch spec 11).
//!
//! The bounds apply at the start of every read, before entries stored locally are tried
//! again, and before a layered backup is taken, to every such entry the store holds: those
//! stored before too, as after a restore from an older backup (Switch spec 12.4), which
//! brings dropped entries back to be dropped, and told, again. Entries stored
//! for any other reason are neither counted nor dropped.
//!
//! **What the total can't do.** Dropping from the identity that holds the most keeps a
//! hostile identity from pushing out an honest sender alone, but identities are cheap:
//! against `k` admitted identities that keep as many entries stored, an honest sender
//! keeps about `128 / (k + 1)`, and about 100 identities holding one or two entries each
//! leave it one. Admission is the only defence: who may write to the inbox at all, by the
//! lists and invite codes (Switch spec 7).
//!
//! **An entry whose effect is being settled.** A stored entry is counted by the reason it
//! was stored for until a later read changes it. When a retry passes the checks of its
//! sender and keeps its effect, and that effect is refused once it is sent again, the entry
//! stays stored as [`ParkReason::Unverifiable`] until its next retry stores it for the
//! refusal; the bounds can drop it in between, as an entry whose sender couldn't be
//! checked, and tell the protocol so ([`AppEvent::StoredEntryDropped`]).

use std::collections::BTreeMap;

use pubky_switch_core::message::{MessagePlaintext, VerifiedSender};
use pubky_switch_core::records::{AppCert, DAY_MS};

use super::events::{AppEvent, DropReason, Duty, EventId, ParkReason, StoredMessageIdentity};
use super::protocol::Rules;
use super::state::{ParkedEntry, RetryEntry, Tx, key};
use super::{App, AppError};

/// How long an entry stored as [`ParkReason::Unverifiable`] or [`ParkReason::AwaitingKey`]
/// is kept from its acceptance: 21 days, judged on the highest service time the app
/// verified, so the sender, which answers re-sends for 30 days from a message's first
/// acceptance (Switch spec 11), still can when the protocol asks.
pub const MAX_UNVERIFIED_AGE_MS: u64 = 21 * DAY_MS;

/// The most entries stored as [`ParkReason::Unverifiable`] or [`ParkReason::AwaitingKey`],
/// together, the app keeps for one sender identity, the identity the entry's certificate
/// names: 64.
pub const MAX_UNVERIFIED_PER_SENDER: usize = 64;

/// The most entries stored as [`ParkReason::Unverifiable`] or [`ParkReason::AwaitingKey`],
/// together, the app keeps in all: 128, at most about 16 MiB as stored of what a restore
/// commits at once.
pub const MAX_UNVERIFIED_TOTAL: usize = 128;

/// The most entries one commit drops: each drop deletes the entry and its retry count and
/// keeps a duty event, under 1 KiB in all, so a step stays well within one commit however
/// many entries are over the bounds at once; a read takes as many steps as it needs.
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
/// past, given every entry the bounds count ([`ParkReason::Unverifiable`] and
/// [`ParkReason::AwaitingKey`]) and the highest service
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
            app.state.held.remove(&seq);
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
        Ok(())
    }
}

impl App {
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

    /// Count the currently staged pool and the incoming input together. No protected
    /// pending input is made evictable by a change of its cached waiting reason.
    pub(crate) fn waiting_drops(
        &self,
        candidate: Option<(u64, &ParkedEntry)>,
    ) -> Vec<(u64, DropReason)> {
        let pending = self.state.pending_effect.as_ref().and_then(|effect| effect.stored);
        let mut counted: Vec<Counted> = self.state.parked.iter()
            .filter(|(id, stored)| stored.reason.bounded() && Some(**id) != pending
                && candidate.is_none_or(|(incoming, _)| incoming != **id))
            .map(|(id, stored)| counted_entry(*id, stored))
            .collect();
        if let Some((id, stored)) = candidate {
            counted.push(counted_entry(id, stored));
        }
        over_bounds(&counted, self.highest_service_time())
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
            tx: Tx::new(&self.ns), candidate, removed: Vec::new(),
            retry_remove: Vec::new(), retry_move: None, feed,
            next_stored_id: self.state.next_stored_id, next_duty: self.state.next_duty,
        };
        if let Some((id, stored)) = &change.candidate {
            if !stored.reason.bounded()
                || self.state.pending_effect.as_ref().is_some_and(|effect| effect.stored == Some(*id))
                || self.state.parked.get(id).is_some_and(|old| old.reason == ParkReason::Uncertain)
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
                change.tx.delete(&key::held(seq))?;
                change.tx.delete(&key::retry(seq))?;
            } else if !self.state.parked.contains_key(id) {
                return Err(super::corrupt());
            }
            if !drops.iter().any(|(dropped, _)| dropped == id) {
                change.tx.put(&key::parked(*id), stored)?;
                if stored.reason == ParkReason::Unverifiable {
                    if let Some(retry) = feed.and_then(|seq| self.state.retries.get(&seq)).copied() {
                        change.tx.put(&key::stored_retry(*id), &retry)?;
                        change.retry_move = Some((*id, retry));
                    }
                } else {
                    change.tx.delete(&key::stored_retry(*id))?;
                    change.retry_remove.push(*id);
                }
                if self.state.parked.get(id).is_none_or(|old| old.reason != stored.reason) {
                    change.tx.report(AppEvent::Parked {
                        id: None, seq: stored.seq, stored_id: *id, reason: stored.reason,
                    });
                }
            }
        }
        for (id, reason) in drops {
            let stored = change.candidate.as_ref().filter(|(incoming, _)| incoming == id)
                .map(|(_, stored)| stored).or_else(|| self.state.parked.get(id))
                .ok_or_else(super::corrupt)?;
            let event = EventId::new(self.state.duty_epoch.epoch, change.next_duty);
            let duty = self.waiting_notice(*id, stored, *reason, event)?;
            change.tx.put(&key::duty(change.next_duty), &duty)?;
            change.next_duty = change.next_duty.checked_add(1).ok_or_else(super::corrupt)?;
            change.tx.report(duty.event(event));
            change.tx.delete(&key::parked(*id))?;
            change.tx.delete(&key::stored_retry(*id))?;
            change.removed.push(*id);
            change.retry_remove.push(*id);
        }
        if change.next_duty != self.state.next_duty {
            change.tx.put(key::DUTY_NEXT, &change.next_duty)?;
        }
        if change.candidate.as_ref().is_some_and(|(id, _)| change.removed.contains(id)) {
            change.candidate = None;
        }
        Ok(change)
    }

    /// Revalidate retained signed bytes without requiring current sender standing.
    /// A notice carries only the resulting identity, never these bytes (Switch spec 8.2).
    pub(crate) fn waiting_identity(&self, stored: &ParkedEntry) -> Result<StoredMessageIdentity, AppError> {
        let cert = AppCert::verify(&stored.cert, &stored.sender).map_err(|_| super::corrupt())?;
        if cert.expired_at(stored.accepted_at_ms) || stored.accepted_at_ms > stored.receipt.read_at_ms {
            return Err(super::corrupt());
        }
        let plaintext = MessagePlaintext::decode(&stored.plaintext).map_err(|_| super::corrupt())?;
        let opaque = self.protocol.opaque_members();
        let rules = Rules::new(self.protocol.as_ref(), &self.state.cert, &opaque);
        let message = plaintext.check(&self.state.meta.identity, &stored.sender,
            &VerifiedSender::from_cert(&cert), &rules.opaque).map_err(|_| super::corrupt())?;
        Ok(StoredMessageIdentity {
            app_id: message.from.app_id, msg_id: message.msg_id, kind: message.kind,
            hash: plaintext.hash(), certificate_hash: cert.hash(),
        })
    }

    pub(crate) fn waiting_notice(
        &self, id: u64, stored: &ParkedEntry, reason: DropReason, notice_id: EventId,
    ) -> Result<Duty, AppError> {
        Ok(Duty::StoredEntryDropped {
            stored_id: id, seq: stored.seq, generation: stored.generation, sender: stored.sender,
            accepted_at_ms: stored.accepted_at_ms, reason,
            waiting: stored.reason.waiting().ok_or_else(super::corrupt)?,
            message: self.waiting_identity(stored)?,
            sender_verified: stored.reason != ParkReason::Unverifiable,
            receipt: stored.receipt, notice_id,
        })
    }
}

fn counted_entry(id: u64, stored: &ParkedEntry) -> Counted {
    Counted { id, sender: stored.sender, accepted_at_ms: stored.accepted_at_ms }
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
