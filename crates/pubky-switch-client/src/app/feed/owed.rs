//! Retained protocol calls and their completion (Switch spec 8.3).

use pubky_switch_core::ops::{OpKind, SignedOp};
use pubky_switch_core::scopes::Permission;
use pubky_switch_core::sig::SignedDoc;

use super::super::events::{AppEvent, Duty, KeptRefusal, RefusedCall};
use super::super::protocol::{
    DenyListChange, LocalWrite, MAX_STEP_LOCAL_BYTES, MissedEntries, Protocol, ResendNeeded,
    ResendReason, StoreFailure, local_writes_bytes,
};
use super::super::state::{self, key};
use super::{App, AppError, DenyCheck, Read};

/// `owed/<generation>/<seq>`: a protocol call about a feed item that the protocol couldn't
/// answer (`Protocol::resend_needed`, `Protocol::missed`, `Protocol::deny_list_changed`),
/// kept until it does.
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

    /// The call, made again.
    fn make(&self, protocol: &dyn Protocol) -> Result<Vec<LocalWrite>, StoreFailure> {
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

impl App {
    /// A call whose answer's local writes are over [`MAX_STEP_LOCAL_BYTES`]: not committed,
    /// and not owed, since making it again would bring the same answer; the protocol is
    /// told in the commit that passes its item.
    pub(super) fn local_writes_refused(
        &mut self,
        seq: u64,
        call: OwedCall,
        read: &mut Read,
    ) -> Result<(), AppError> {
        self.keep_duty(
            &mut read.tx,
            Duty::LocalWritesRefused {
                call: KeptRefusal::Owed { seq, call },
            },
        )
    }

    /// A call the protocol couldn't answer: kept in the commit that passes its item, and
    /// made again by later reads ([`App::retry_owed`]), so the cursor never passes what the
    /// protocol wasn't told. The page stops after its item: nothing later is handed before
    /// it (Switch spec 8.3).
    pub(super) fn owe(
        &mut self,
        seq: u64,
        call: OwedCall,
        read: &mut Read,
    ) -> Result<(), AppError> {
        read.held_after = true;
        self.owed_known = Some(true);
        if self.owed_held_reads == 0 {
            // This read stops at it: the first of the reads held there.
            self.owed_held_reads = 1;
        }
        read.tx
            .put(&key::owed(self.state.cursor.generation, seq), &call)
    }

    /// The calls the protocol couldn't answer before, made again in feed order
    /// ([`App::feed_order`]), each answered one committing its writes and going in one
    /// commit. One that fails again holds every later one back, of any kind, and the read
    /// hands nothing after it (Switch spec 8.3). A deny list change owed for its check is
    /// checked again first: handed, refused with an event, owed still, or noted as a gap.
    /// A deny list change behind the cursor is noted as a gap at the cursor instead.
    pub(super) async fn retry_owed(&mut self) -> Result<(), AppError> {
        let owed = self.reader().scan::<OwedCall>(key::OWED_PREFIX).await?;
        let mut held = false;
        let cursor = self.state.cursor;
        let cursor_at = self.feed_order(cursor.generation, cursor.seq);
        self.owed_ahead = None;
        // In feed order, not key order: the keys name the generation each item was read
        // at, and a restore in place carries calls of a generation the sequence went on
        // from. Every call is keyed by its feed position (`owed/<generation>/<seq>`): a
        // key that doesn't name one has no place in that order, so the store is corrupt,
        // and no call is made out of order or dropped.
        let mut owed = owed
            .into_iter()
            .map(|(rest, call)| {
                let place = owed_place(&rest)?;
                let order = self.feed_order(place.0, place.1);
                Ok((order, place, rest, call))
            })
            .collect::<Result<Vec<_>, AppError>>()?;
        owed.sort_by_key(|(order, ..)| *order);
        for (order, (generation, seq), rest, call) in owed {
            let at = format!("{}{rest}", key::OWED_PREFIX);
            // A call past the cursor, as a restore in place carries one, waits for the
            // feed to reach its item: the feed stops before anything later.
            if order > cursor_at {
                if self.same_sequence(generation, cursor.generation) {
                    self.owed_ahead = Some(seq);
                }
                break;
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
                            tx.delete(&at)?;
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
                tx.delete(&at)?;
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
                            self.note_list_op(&body, &mut tx)?;
                            if !self.state.cert.has_permission(Permission::ListsRead) {
                                tx.delete(&at)?;
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
                            tx.delete(&at)?;
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
                            tx.delete(&at)?;
                            self.commit(tx).await?;
                            continue;
                        }
                    }
                }
                // At the cursor: the copy of the lists takes the change in the commit that
                // hands it to the protocol, so the two never disagree after a crash. Where
                // the feed applied it when the call was owed, this sets the same state
                // again; after a restore in place, whose feed passes the carried call's
                // item without applying it, this is where the copy takes it, after the
                // changes the feed handed before it (Switch spec 8.3).
                // An app that no longer holds `lists.read`, a renewal having removed it, is
                // handed no deny list change (Switch spec 8.3): the copy still takes it, and
                // the call is gone, as for a change checked here.
                call @ OwedCall::Deny { pubky, added, .. } => {
                    self.note_deny_change(&pubky, added, &mut tx)?;
                    if !self.state.cert.has_permission(Permission::ListsRead) {
                        tx.delete(&at)?;
                        self.commit(tx).await?;
                        continue;
                    }
                    call
                }
                call => call,
            };
            let Ok(writes) = call.make(self.protocol.as_ref()) else {
                held = true;
                break;
            };
            if local_writes_bytes(&writes) > MAX_STEP_LOCAL_BYTES {
                // Over the bound: not committed, and the call made no more, since the same
                // answer would come at every read; the protocol is told.
                self.keep_duty(
                    &mut tx,
                    Duty::LocalWritesRefused {
                        call: KeptRefusal::Owed { seq, call },
                    },
                )?;
            } else {
                tx.local(&writes)?;
            }
            tx.delete(&at)?;
            self.commit(tx).await?;
        }
        self.owed_known = Some(held);
        Ok(())
    }
}
