//! The protocol answers an app carries across restore after the registration,
//! evidence and list steps of provider loss (Switch spec 12.4, 12.6).

use std::collections::BTreeSet;

use super::{AppError, Batch, LossRecord, MAX_BATCH_ENTRIES, MAX_LOSS_CONVERSATIONS, RecoveryStep};
use crate::app::{AppBackup, ProtocolSet, Refusal};
use pubky_switch_core::enc::{pubky_id, pubky_key};
use pubky_switch_core::ops::{AllowKind, OpKind, SignedOp};
use pubky_switch_core::records::{AppCert, IdentityDoc};
use serde::{Deserialize, Serialize};

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
                .is_none_or(|t| t > pubky_switch_core::time::MAX_TIME_MS)
            || loss.cursor_time_ms > pubky_switch_core::time::MAX_TIME_MS
            || loss.newest_head.is_some()
            || loss.old_offset_ms.is_some()
            || loss.conversations.len() > MAX_LOSS_CONVERSATIONS
            || !loss
                .conversations
                .windows(2)
                .all(|pair| pair.first() < pair.last())
            || loss
                .conversations
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
            RecoveryStep::Conversations | RecoveryStep::Done => {
                if !loss.callback_owners.is_empty()
                    || loss.answered != 0
                    || (loss.done() && !loss.conversations.is_empty())
                {
                    return Err(invalid());
                }
                if !loss.batch.is_empty() {
                    let batch = Batch::from_body(loss.batch.clone()).map_err(|_| invalid())?;
                    if batch.cursor().is_some()
                        || batch.ops().is_empty()
                        || batch.ops().len() != loss.conversations.len().min(MAX_BATCH_ENTRIES)
                    {
                        return Err(invalid());
                    }
                    for (op, who) in batch.ops().iter().zip(&loss.conversations) {
                        let verified =
                            SignedOp::verify_with_cert(op.signed(), cert, &backup.meta.identity)
                                .map_err(|_| invalid())?;
                        let body = verified.body();
                        if body.generation != backup.meta.generation
                            || !body.conditions.is_empty()
                            || !matches!(&body.kind, OpKind::AllowPut {pubky, kind: AllowKind::Conversation} if pubky_id(pubky) == *who)
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
    /// At the conversation step the client removes only a submitted prefix.
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
            || next.conversations_left_out < live.conversations_left_out
            || (live.step >= RecoveryStep::Conversations
                && next.conversations_left_out != live.conversations_left_out)
        {
            return Err(held());
        }
        if next.step != live.step {
            return Ok(());
        }
        let covers = match live.step {
            RecoveryStep::Resend if next.answered == live.answered => {
                next.callback_owners == live.callback_owners
                    && next.conversations == live.conversations
                    && next.conversations_left_out == live.conversations_left_out
            }
            RecoveryStep::Resend => {
                next.callback_owners == live.callback_owners
                    && next.answered > live.answered
                    && live.conversations.iter().all(|who| {
                        next.conversations.binary_search(who).is_ok()
                            || (next.conversations.len() == MAX_LOSS_CONVERSATIONS
                                && next.conversations.last().is_some_and(|last| last < who))
                    })
            }
            RecoveryStep::Conversations => {
                live.conversations.ends_with(&next.conversations)
                    && (next.conversations.len() < live.conversations.len()
                        || live.batch.is_empty()
                        || live.batch == next.batch)
            }
            RecoveryStep::Done => true,
            _ => false,
        };
        if covers { Ok(()) } else { Err(held()) }
    }
}
