//! The protocol answers an app carries across restore after the registration,
//! evidence and list steps of provider loss (Dispatch spec 12.4, 12.6).

use std::collections::BTreeSet;

use super::{AppError, Batch, LossRecord, MAX_BATCH_ENTRIES, MAX_LOSS_REPLY_PEERS, RecoveryStep};
use crate::app::{AppBackup, ProtocolSet, Refusal};
use pubky_dispatch_core::admission::PeerReason;
use pubky_dispatch_core::enc::{pubky_id, pubky_key};
use pubky_dispatch_core::ops::{OpKind, SignedOp};
use pubky_dispatch_core::records::{AppCert, IdentityDoc};
use serde::{Deserialize, Serialize};

/// Whether `next`, a loss record at its reply-grant step from a backup, is at least as far as
/// `live`, the store's: it owes a part of what `live` owes; `live`'s signed batch is `next`'s
/// too or was answered, none of its peers left; and any other peer `next` no longer owes
/// after the first it still owes was left out as denied (`denied`, in the backup's copy or
/// contribution). Each signed batch then has one answer, and no grant is skipped.
pub(in crate::app) fn reply_peers_cover(
    live: &LossRecord,
    next: &LossRecord,
    denied: impl Fn(&str) -> bool,
) -> bool {
    let owed = |record: &LossRecord, who: &String| record.reply_peers.binary_search(who).is_ok();
    let live_batch: &[String] = if live.batch.is_empty() {
        &[]
    } else {
        live.reply_peers
            .get(..live.reply_peers.len().min(MAX_BATCH_ENTRIES))
            .unwrap_or_default()
    };
    let first = next
        .reply_peers
        .first()
        .and_then(|first| live.reply_peers.binary_search(first).ok())
        .unwrap_or(live.reply_peers.len());
    next.reply_peers.iter().all(|who| owed(live, who))
        && (live.batch == next.batch || live_batch.iter().all(|who| !owed(next, who)))
        && live.reply_peers.iter().enumerate().all(|(at, who)| {
            owed(next, who) || at < first || live_batch.contains(who) || denied(who)
        })
}

#[derive(Clone, Serialize, Deserialize)]
pub(in crate::app) struct SavedAnswers {
    loss: LossRecord,
}

impl SavedAnswers {
    pub(in crate::app) fn capture(mut loss: LossRecord) -> Option<Self> {
        if loss.step < RecoveryStep::Resend {
            return None;
        }
        // The head was for the evidence upload. Registration already used the
        // old clock sample to determine the residual window.
        loss.newest_head = None;
        loss.old_offset_ms = None;
        Some(Self { loss })
    }

    pub(in crate::app) fn check(
        &self,
        backup: &AppBackup,
        own: &IdentityDoc,
        cert: &AppCert,
        protocols: &ProtocolSet,
    ) -> Result<(), AppError> {
        let invalid =
            || AppError::InvalidData("the backup's provider loss answers are inconsistent".into());
        let loss = &self.loss;
        if loss.lost_generation >= loss.generation
            || loss.generation > backup.meta.generation
            || own.generation() < backup.meta.generation
            || own.body().recovery_from.is_none_or(|old| {
                old < loss.lost_generation
                    || (own.generation() == backup.meta.generation && old >= loss.generation)
            })
            || loss
                .declared_at_ms
                .is_none_or(|t| t > pubky_dispatch_core::time::MAX_TIME_MS)
            || loss.cursor_time_ms > pubky_dispatch_core::time::MAX_TIME_MS
            || loss.newest_head.is_some()
            || loss.old_offset_ms.is_some()
            || loss.reply_peers.len() > MAX_LOSS_REPLY_PEERS
            || !loss
                .reply_peers
                .windows(2)
                .all(|pair| pair.first() < pair.last())
            || loss
                .reply_peers
                .iter()
                .any(|who| !pubky_key(who).is_ok_and(|key| key != backup.meta.identity))
            || backup
                .loss_lists
                .as_ref()
                .is_some_and(|lists| lists.waiting_for_upload())
        {
            return Err(invalid());
        }
        match loss.step {
            RecoveryStep::Resend => {
                let mut names = BTreeSet::new();
                if !loss.batch.is_empty()
                    || loss.answered >= loss.callback_owners.len()
                    || loss
                        .callback_owners
                        .iter()
                        .any(|name| !protocols.contains(name) || !names.insert(name))
                    || backup.beyond_cursor.as_ref().is_some_and(|feed| {
                        loss.callback_owners
                            .iter()
                            .any(|name| !feed.protocols.contains(name))
                    })
                {
                    return Err(invalid());
                }
            }
            RecoveryStep::ReplyPeers | RecoveryStep::Done => {
                if !loss.callback_owners.is_empty()
                    || loss.answered != 0
                    || (loss.done() && !loss.reply_peers.is_empty())
                {
                    return Err(invalid());
                }
                if !loss.batch.is_empty() {
                    let batch = Batch::from_body(loss.batch.clone()).map_err(|_| invalid())?;
                    if batch.cursor().is_some()
                        || batch.ops().is_empty()
                        || batch.ops().len() != loss.reply_peers.len().min(MAX_BATCH_ENTRIES)
                    {
                        return Err(invalid());
                    }
                    for (op, who) in batch.ops().iter().zip(&loss.reply_peers) {
                        let verified =
                            SignedOp::verify_with_cert(op.signed(), cert, &backup.meta.identity)
                                .map_err(|_| invalid())?;
                        let body = verified.body();
                        if body.generation != backup.meta.generation
                            || !body.conditions.is_empty()
                            || !matches!(&body.kind, OpKind::AllowPut {pubky, reason: PeerReason::Reply} if pubky_id(pubky) == *who)
                        {
                            return Err(invalid());
                        }
                    }
                }
            }
            _ => return Err(invalid()),
        }
        Ok(())
    }

    pub(in crate::app) fn loss(&self) -> &LossRecord {
        &self.loss
    }

    /// Keep answers that reached this installation after an older backup.
    /// At the reply peers step the client removes only a submitted prefix.
    pub(in crate::app) fn check_destination(
        live: &LossRecord,
        backup: &AppBackup,
        own: &IdentityDoc,
    ) -> Result<(), AppError> {
        let held = || {
            AppError::from(Refusal::NotNow(
                "the backup predates the installation's provider loss answers".into(),
            ))
        };
        if live.step < RecoveryStep::Resend {
            if backup.loss_answers.as_ref().is_some_and(|saved| {
                saved.loss.generation < live.generation
                    || (saved.loss.generation == live.generation
                        && saved.loss.lost_generation != live.lost_generation)
            }) {
                return Err(held());
            }
            return Ok(());
        }
        // Restoring the lost generation starts from that backup's protocol
        // state. A finished loss no longer has an answer or batch to resume.
        if live.done() && backup.meta.generation <= live.lost_generation {
            return Ok(());
        }
        let Some(next) = backup.loss_answers.as_ref().map(Self::loss) else {
            return if backup.meta.generation > live.generation
                && own
                    .body()
                    .recovery_from
                    .is_some_and(|lost| lost >= live.generation)
            {
                Ok(())
            } else {
                Err(held())
            };
        };
        if next.lost_generation >= live.generation {
            return Ok(());
        }
        if next.view() != live.view()
            || next.step < live.step
            || next.claim_entries_left_out != live.claim_entries_left_out
            || next.reply_peers_left_out < live.reply_peers_left_out
            || (live.step >= RecoveryStep::ReplyPeers
                && next.reply_peers_left_out != live.reply_peers_left_out)
        {
            return Err(held());
        }
        if next.step != live.step {
            return Ok(());
        }
        let covers = match live.step {
            RecoveryStep::Resend if next.answered == live.answered => {
                next.callback_owners == live.callback_owners
                    && next.reply_peers == live.reply_peers
                    && next.reply_peers_left_out == live.reply_peers_left_out
            }
            RecoveryStep::Resend => {
                next.callback_owners == live.callback_owners
                    && next.answered > live.answered
                    && live.reply_peers.iter().all(|who| {
                        next.reply_peers.binary_search(who).is_ok()
                            || (next.reply_peers.len() == MAX_LOSS_REPLY_PEERS
                                && next.reply_peers.last().is_some_and(|last| last < who))
                    })
            }
            // A later record has granted a prefix of the peers, and left out any denied
            // since: what it still owes is a part of what this one owes.
            RecoveryStep::ReplyPeers => {
                let contributed: BTreeSet<String> = backup
                    .loss_lists
                    .iter()
                    .flat_map(super::lists::SavedLists::deny_ids)
                    .map(|who| pubky_id(&who))
                    .collect();
                reply_peers_cover(live, next, |who| {
                    backup.peers.denies().binary_search(&who.to_owned()).is_ok()
                        || contributed.contains(who)
                })
            }
            RecoveryStep::Done => true,
            _ => false,
        };
        if covers { Ok(()) } else { Err(held()) }
    }
}
