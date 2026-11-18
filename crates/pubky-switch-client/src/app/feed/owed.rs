//! Retained protocol calls and their completion (Switch spec 8.3).

use pubky_switch_core::ops::{OpKind, SignedOp};
use pubky_switch_core::scopes::Permission;
use pubky_switch_core::sig::SignedDoc;

use super::super::events::{AppEvent, Duty, KeptRefusal, RefusedCall};
use super::super::order::{Handover, Kept};
use super::super::protocol::{
    DenyListChange, LocalWrite, MAX_STEP_LOCAL_BYTES, MissedEntries, Protocol, ResendNeeded,
    ResendReason, StoreFailure, local_writes_bytes,
};
use super::super::state::{self, key};
use super::{App, AppError, DenyCheck, Read};

/// `owed/<generation>/<seq>`: a protocol call about a feed item (`Protocol::resend_needed`,
/// `Protocol::missed`, `Protocol::deny_list_changed`), kept for the protocols that couldn't
/// answer it, or whose position was behind its item when it came, each until it answers.
/// Every writer names them; one that answers is taken out in the commit of its writes and
/// of its position, so no protocol is handed the call twice.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub(crate) struct Owed {
    /// The protocols it is owed to, in registration order, each once.
    pub(crate) to: Vec<String>,
    /// The call.
    pub(crate) call: OwedCall,
}

impl Owed {
    /// A remaining-owner set is nonempty, unique and registered. Completed owners may
    /// be absent: their effects and removal committed together (Switch spec 8.3).
    pub(crate) fn check_owners(
        &self,
        protocols: &super::super::ProtocolSet,
    ) -> Result<(), AppError> {
        let mut names = std::collections::BTreeSet::new();
        if self.to.is_empty()
            || self
                .to
                .iter()
                .any(|name| !protocols.contains(name) || !names.insert(name))
        {
            return Err(AppError::Store(crate::error::StoreError::Corrupt));
        }
        Ok(())
    }
}

/// A call about a feed item, as [`Owed`] keeps it.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub(crate) enum OwedCall {
    Resend {
        #[serde(with = "pubky_switch_core::enc::serde_b64")]
        sender: [u8; 32],
        accepted_from_ms: u64,
        accepted_until_ms: u64,
        /// Whether the entry was one a departed own app left unread, rather than one
        /// wrapped to a key the app doesn't hold.
        unreadable: bool,
    },
    Missed {
        seq: u64,
        entries: u64,
        accepted_from_ms: u64,
        accepted_until_ms: u64,
    },
    /// A deny list change, owed in feed order: the calls behind it wait for it.
    Deny {
        generation: u64,
        seq: u64,
        #[serde(with = "pubky_switch_core::enc::serde_b64")]
        pubky: [u8; 32],
        added: bool,
        at_ms: u64,
    },
    /// A deny list change whose writer's certificate couldn't be looked up yet, the
    /// directory read failing: verified again, and handed or refused, at a later read.
    DenyUnverified {
        generation: u64,
        seq: u64,
        #[serde(with = "pubky_switch_core::enc::serde_b64")]
        pubky: [u8; 32],
        added: bool,
        at_ms: u64,
        /// The operation, as the feed showed it.
        op: SignedDoc,
    },
}

impl From<&ResendNeeded> for OwedCall {
    fn from(needed: &ResendNeeded) -> Self {
        Self::Resend {
            sender: needed.sender,
            accepted_from_ms: needed.accepted_from_ms,
            accepted_until_ms: needed.accepted_until_ms,
            unreadable: needed.reason == ResendReason::Unreadable,
        }
    }
}

impl From<&DenyListChange> for OwedCall {
    fn from(change: &DenyListChange) -> Self {
        Self::Deny {
            generation: change.generation,
            seq: change.seq,
            pubky: change.pubky,
            added: change.added,
            at_ms: change.at_ms,
        }
    }
}

/// The feed position an owed call's key names (`owed/<generation>/<seq>`, given without
/// its prefix). Every call is keyed so: a key that names none has no place in feed order,
/// and the store is corrupt.
pub(crate) fn owed_place(rest: &str) -> Result<(u64, u64), AppError> {
    let (generation, seq) = rest
        .split_once('/')
        .ok_or(AppError::Store(crate::error::StoreError::Corrupt))?;
    Ok((state::parse_num(generation)?, state::parse_num(seq)?))
}

impl OwedCall {
    /// The operation a deny list change not checked yet keeps, as the feed showed it, read
    /// for its check; `None` for any other call. The change kept beside it is read from that
    /// operation: one that doesn't parse, or isn't that change, is a corrupt store.
    pub(crate) fn kept_op_body(&self) -> Result<Option<pubky_switch_core::ops::OpBody>, AppError> {
        let Self::DenyUnverified {
            pubky, added, op, ..
        } = self
        else {
            return Ok(None);
        };
        let body = SignedOp::peek(op)
            .map_err(|_| AppError::Store(crate::error::StoreError::Corrupt))?
            .body()
            .clone();
        let kept = match body.kind {
            OpKind::DenyPut { pubky } => Some((pubky, true)),
            OpKind::DenyDelete { pubky } => Some((pubky, false)),
            _ => None,
        };
        if kept != Some((*pubky, *added)) {
            return Err(AppError::Store(crate::error::StoreError::Corrupt));
        }
        Ok(Some(body))
    }

    /// Whether it is a deny list change, which every protocol must take before anything
    /// later is handed to any (Switch spec 8.3).
    pub(crate) fn is_deny(&self) -> bool {
        matches!(self, Self::Deny { .. } | Self::DenyUnverified { .. })
    }

    /// The call, made.
    pub(super) fn make(&self, protocol: &dyn Protocol) -> Result<Vec<LocalWrite>, StoreFailure> {
        match self.refused(0) {
            RefusedCall::ResendNeeded { needed, .. } => protocol.resend_needed(&needed),
            RefusedCall::Missed(missed) => protocol.missed(&missed),
            RefusedCall::DenyListChanged(change) => protocol.deny_list_changed(&change),
            _ => Ok(Vec::new()),
        }
    }

    /// The call as the protocol is handed it, about the feed item at `seq`.
    pub(crate) fn refused(&self, seq: u64) -> RefusedCall {
        match *self {
            Self::Resend {
                sender,
                accepted_from_ms,
                accepted_until_ms,
                unreadable,
            } => RefusedCall::ResendNeeded {
                seq,
                needed: ResendNeeded {
                    sender,
                    accepted_from_ms,
                    accepted_until_ms,
                    reason: if unreadable {
                        ResendReason::Unreadable
                    } else {
                        ResendReason::Unopenable
                    },
                },
            },
            Self::Missed {
                seq,
                entries,
                accepted_from_ms,
                accepted_until_ms,
            } => RefusedCall::Missed(MissedEntries {
                seq,
                entries,
                accepted_from_ms,
                accepted_until_ms,
            }),
            Self::Deny {
                generation,
                seq,
                pubky,
                added,
                at_ms,
            }
            | Self::DenyUnverified {
                generation,
                seq,
                pubky,
                added,
                at_ms,
                ..
            } => RefusedCall::DenyListChanged(DenyListChange {
                generation,
                seq,
                pubky,
                added,
                at_ms,
            }),
        }
    }
}

impl App {
    /// A call the protocols `to` couldn't answer, or weren't told through everything
    /// before: kept in the commit that passes its item, and made again at the start of
    /// later reads ([`App::retry_owed`]), so the cursor never passes what a protocol wasn't
    /// told. Those protocols stay right before the item, and are handed nothing later until
    /// they take it; a deny list change stops the page after its item, so nothing later is
    /// handed to any protocol before it (Switch spec 8.3).
    pub(super) fn owe(
        &mut self,
        seq: u64,
        to: Vec<String>,
        call: OwedCall,
        read: &mut Read,
    ) -> Result<(), AppError> {
        if self.owed_held_reads == 0 {
            // The first of the reads that end with a call kept.
            self.owed_held_reads = 1;
        }
        read.left.extend(to.iter().cloned());
        self.note_pending_call(Kept {
            generation: self.state.cursor.generation,
            seq,
            names: to.clone(),
            call: true,
            deny: call.is_deny(),
        });
        if call.is_deny() {
            read.held_after = true;
            self.owed_known = Some(true);
        }
        read.tx.put(
            &key::owed(self.state.cursor.generation, seq),
            &Owed { to, call },
        )
    }

    /// Read and validate the complete retained-call set before it supplies ordering,
    /// readiness or callbacks. Valid remaining owners need not include completed ones.
    pub(crate) async fn owed_calls(&self) -> Result<Vec<(String, Owed)>, AppError> {
        let owed = self.reader().scan::<Owed>(key::OWED_PREFIX).await?;
        for (rest, call) in &owed {
            owed_place(rest)?;
            call.check_owners(&self.protocols)?;
            call.call.kept_op_body()?;
        }
        Ok(owed)
    }

    /// The calls kept for protocols, made again in feed order ([`App::feed_order`]), each
    /// for the protocols it names whose position has reached it: those told through
    /// everything before its item, and owed no listing at or before it. Each goes in one
    /// commit with their writes, their names taken out and their positions, so none is
    /// handed a call twice. A protocol that fails one stays right before it, and is handed
    /// nothing later; a deny list change a protocol fails, or can't take yet behind an
    /// earlier call, holds every later call of every protocol, and the read hands nothing
    /// after it (Switch spec 8.3). A deny list change kept for its check is checked again
    /// first: handed, refused with an event, kept still, or noted as a gap. A deny list
    /// change behind the cursor is noted as a gap at the cursor instead.
    ///
    /// A call past the cursor, as a restore in place carries one, waits until the read
    /// reaches its item: the protocols it names are told the items before it first, and
    /// are told it at the start of the read after, whether or not the cursor got there.
    ///
    /// Returns whether a protocol failed a call in this pass.
    pub(super) async fn retry_owed(&mut self) -> Result<bool, AppError> {
        let owed = self.owed_calls().await?;
        let due: super::super::records::ListDue = self
            .reader()
            .get(super::super::records::LIST_DUE)
            .await?
            .unwrap_or_default();
        let mut held = false;
        let mut failed_any = false;
        let cursor = self.state.cursor;
        let cursor_at = self.feed_order(cursor.generation, cursor.seq);
        // In feed order, not key order: the keys name the generation each item was read
        // at, and a restore in place carries calls of a generation the sequence went on
        // from. Every call is keyed by its feed position (`owed/<generation>/<seq>`): a
        // key that doesn't name one has no place in that order, so the store is corrupt,
        // and no call is made out of order or dropped.
        let mut queue = owed
            .into_iter()
            .map(|(rest, owed)| {
                let place = owed_place(&rest)?;
                let order = self.feed_order(place.0, place.1);
                Ok((order, place, rest, owed))
            })
            .collect::<Result<Vec<_>, AppError>>()?;
        queue.sort_by_key(|(order, ..)| *order);
        let mut kept = due.kept();
        kept.extend(self.deletion_positions());
        kept.extend(queue.iter().map(|(_, (generation, seq), _, owed)| Kept {
            generation: *generation,
            seq: *seq,
            names: owed.to.clone(),
            call: true,
            deny: owed.call.is_deny(),
        }));
        kept.sort_by_key(|item| self.feed_order(item.generation, item.seq));
        for (order, (generation, seq), rest, Owed { to, call }) in queue {
            // The positions, by what is still kept: a protocol that took a call is told
            // through to right before the next thing kept for it.
            self.settle_told(&kept);
            let at = format!("{}{rest}", key::OWED_PREFIX);
            // Whose turn it is: a protocol told through everything before the call's item,
            // and owed no listing at or before it, which goes first.
            let ready: Vec<String> = to
                .iter()
                .filter(|name| self.ready_at(name, order, Handover::Call))
                .cloned()
                .collect();
            // The cursor hasn't passed its item: once the call is gone, the read still
            // meets the item, and passes it without handling it again.
            let ahead = order > cursor_at && self.same_sequence(generation, cursor.generation);
            if call.is_deny() && ready.len() < to.len() {
                // A deny list change goes to no protocol while one it is for can't take it:
                // behind an earlier call it failed, the read holds for every protocol; past
                // the cursor, it waits for the read to bring every one of them to its item.
                if order <= cursor_at {
                    held = true;
                    break;
                }
                continue;
            }
            if ready.is_empty() {
                continue;
            }
            // Neither dropped nor handed while the store is corrupt (fail closed).
            let kept_body = call.kept_op_body()?;
            let mut tx = self.tx()?;
            // A deny list change behind the cursor, as a restore in place from a newer
            // backup carries one, or one of a sequence a provider loss ended once the
            // cursor follows the next: the feed handed the later changes before it, and
            // won't hand them again. Handed now, or applied to the copy of the lists, it
            // would set an older state over them, so it is a gap in the deny list's
            // history at the cursor instead: the protocol and the copy both take the list
            // as it stands (Switch spec 8.3). A change not checked yet is checked first, as
            // at the cursor: one that isn't genuine is refused with its event, never made a
            // gap, and one that can't be checked yet stays owed and holds the rest.
            if order < cursor_at
                && matches!(
                    call,
                    OwedCall::Deny { .. } | OwedCall::DenyUnverified { .. }
                )
            {
                if let OwedCall::DenyUnverified {
                    generation,
                    seq,
                    at_ms,
                    op,
                    ..
                } = &call
                {
                    let Some(body) = &kept_body else {
                        return Err(AppError::Store(crate::error::StoreError::Corrupt));
                    };
                    match self.check_deny_op(op, body, *at_ms, &tx).await? {
                        DenyCheck::NotGenuine(reason) => {
                            self.events.push(AppEvent::DenyListChangeRefused {
                                generation: *generation,
                                seq: *seq,
                                reason: reason.into(),
                            });
                            self.kept_gone(&at, (*generation, *seq), false, &mut kept, &mut tx)?;
                            self.commit(tx).await?;
                            continue;
                        }
                        DenyCheck::NotYet => {
                            held = true;
                            break;
                        }
                        DenyCheck::Genuine | DenyCheck::Unverifiable => {}
                    }
                }
                self.note_deny_gap(cursor.generation, cursor.seq, &mut tx)
                    .await?;
                self.kept_gone(&at, (generation, seq), false, &mut kept, &mut tx)?;
                self.commit(tx).await?;
                continue;
            }
            let call = match call {
                OwedCall::DenyUnverified {
                    generation,
                    seq,
                    pubky,
                    added,
                    at_ms,
                    op,
                } => {
                    let Some(body) = kept_body else {
                        return Err(AppError::Store(crate::error::StoreError::Corrupt));
                    };
                    match self.check_deny_op(&op, &body, at_ms, &tx).await? {
                        DenyCheck::Genuine => {
                            if !self.state.cert.has_permission(Permission::ListsRead) {
                                self.note_list_op(&body, &mut tx)?;
                                self.kept_gone(&at, (generation, seq), ahead, &mut kept, &mut tx)?;
                                self.commit(tx).await?;
                                continue;
                            }
                            OwedCall::Deny {
                                generation,
                                seq,
                                pubky,
                                added,
                                at_ms,
                            }
                        }
                        DenyCheck::NotGenuine(reason) => {
                            self.events.push(AppEvent::DenyListChangeRefused {
                                generation,
                                seq,
                                reason: reason.into(),
                            });
                            self.kept_gone(&at, (generation, seq), ahead, &mut kept, &mut tx)?;
                            self.commit(tx).await?;
                            continue;
                        }
                        DenyCheck::NotYet => {
                            held = true;
                            break;
                        }
                        DenyCheck::Unverifiable => {
                            self.note_deny_gap(generation, seq.saturating_sub(1), &mut tx)
                                .await?;
                            self.kept_gone(&at, (generation, seq), ahead, &mut kept, &mut tx)?;
                            self.commit(tx).await?;
                            continue;
                        }
                    }
                }
                // A change is applied below with the last successful callback, so the
                // shared copy never moves ahead of a protocol (Switch spec 8.3).
                // An app that no longer holds `lists.read`, a renewal having removed it, is
                // handed no deny list change (Switch spec 8.3): the copy still takes it, and
                // the call is gone, as for a change checked here.
                call @ OwedCall::Deny { pubky, added, .. } => {
                    if !self.state.cert.has_permission(Permission::ListsRead) {
                        self.note_deny_change(&pubky, added, &mut tx)?;
                        self.kept_gone(&at, (generation, seq), ahead, &mut kept, &mut tx)?;
                        self.commit(tx).await?;
                        continue;
                    }
                    call
                }
                call => call,
            };
            let mut left = to.clone();
            for name in to {
                if !ready.contains(&name) {
                    continue;
                }
                let Some(protocol) = self.protocols.get(&name).cloned() else {
                    return Err(AppError::Store(crate::error::StoreError::Corrupt));
                };
                let Ok(writes) = call.make(protocol.as_ref()) else {
                    failed_any = true;
                    continue;
                };
                if local_writes_bytes(&writes) > MAX_STEP_LOCAL_BYTES {
                    // Over the bound: not committed, and the call made no more, since the
                    // same answer would come at every read; the protocol is told.
                    self.keep_duty_for(
                        &mut tx,
                        vec![name.clone()],
                        Duty::LocalWritesRefused {
                            call: KeptRefusal::Owed {
                                seq,
                                call: call.clone(),
                            },
                        },
                    )?;
                } else {
                    tx.local(&super::super::protocols::qualify(&name, writes))?;
                }
                left.retain(|owner| owner != &name);
                if left.is_empty() {
                    if let OwedCall::Deny { pubky, added, .. } = &call {
                        self.note_deny_change(pubky, *added, &mut tx)?;
                    }
                    self.kept_gone(&at, (generation, seq), ahead, &mut kept, &mut tx)?;
                } else {
                    for item in &mut kept {
                        if item.call && (item.generation, item.seq) == (generation, seq) {
                            item.names.clone_from(&left);
                        }
                    }
                    tx.put(
                        &at,
                        &Owed {
                            to: left.clone(),
                            call: call.clone(),
                        },
                    )?;
                }
                // One valid response and its progress fit independently of every other
                // protocol's response; commit them together before taking the next.
                self.told_through(&name, generation, seq);
                self.put_told(&mut tx)?;
                self.commit(tx).await?;
                tx = self.tx()?;
            }
            // A deny list change one failed: nothing later is made for any protocol.
            if call.is_deny() && !left.is_empty() {
                held = true;
                break;
            }
        }
        // What is kept past the cursor, by the `seq` of its item in the cursor's sequence:
        // the walk leaves the protocols it names right before it.
        self.settle_told(&kept);
        self.kept_ahead.clear();
        for thing in &kept {
            if self.feed_order(thing.generation, thing.seq) > cursor_at
                && self.same_sequence(thing.generation, cursor.generation)
            {
                let ahead = self.kept_ahead.entry(thing.seq).or_default();
                for name in &thing.names {
                    if !ahead.names.contains(name) {
                        ahead.names.push(name.clone());
                    }
                }
                ahead.call |= thing.call;
                ahead.deny |= thing.deny;
            }
        }
        // Every protocol held at something kept for it: nothing can be handed, and the read
        // stops, as with one protocol that fails a call.
        let stuck = self.stuck_on(&kept);
        let every_stuck = self
            .protocols
            .iter()
            .all(|registered| stuck.contains(&registered.name));
        self.owed_known = Some(held || every_stuck);
        Ok(failed_any)
    }
}
