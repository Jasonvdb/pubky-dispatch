//! What this installation learned from its own signed requests (Dispatch spec 12.6).

use serde::{Deserialize, Serialize};

use super::App;
use super::error::{Alarm, AppError, Refusal};
use super::events::Duty;
use super::state::{Reader, Tx};
use crate::client::OwnAnswer;

pub use crate::client::own::RecoveryNotice;

/// How the followed service answers this installation (Dispatch spec 12.6).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ProviderHealth {
    /// No recovery notice or established outage.
    Ok,
    /// The service has not answered for the configured interval and at least three tries.
    Unreachable {
        /// Device-clock time of the first failed try, in Unix milliseconds.
        since_ms: u64,
    },
    /// The app refuses own writes and attempts until verified evidence clears the notice.
    RecoveryRequired(RecoveryNotice),
}

/// Default time before three or more unanswered calls constitute a sustained outage.
pub(super) const DEFAULT_UNREACHABLE_MS: u64 = 15 * 60 * 1000;

const HEALTH: &str = "service_health";

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct Outage {
    since_ms: u64,
    tries: u8,
}

/// Kept in this installation's store, apart from backups.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct ServiceHealth {
    pub(super) notice: Option<RecoveryNotice>,
    outage: Option<Outage>,
    pub(super) display_id: Option<[u8; 16]>,
}

impl ServiceHealth {
    pub(super) async fn read(reader: &Reader, generation: u64) -> Result<Self, AppError> {
        let health: Self = reader.get(HEALTH).await?.unwrap_or_default();
        if health
            .notice
            .is_some_and(|n| n.generation != generation || (n.permanent && n.reason.is_none()))
            || health.outage.is_some_and(|o| !(1..=3).contains(&o.tries))
        {
            return Err(super::corrupt());
        }
        Ok(health)
    }

    pub(super) fn write(self, tx: &mut Tx) -> Result<(), AppError> {
        if self == Self::default() {
            tx.delete(HEALTH)
        } else {
            tx.put(HEALTH, &self)
        }
    }
}

impl App {
    /// This installation's verified notice, held across a restart (Dispatch spec 12.6).
    pub fn recovery_required(&self) -> Option<RecoveryNotice> {
        self.client
            .own_reads
            .as_ref()
            .and_then(|reads| reads.notice())
            .or_else(|| self.pending_health.and_then(|state| state.notice))
            .or(self.state.health.notice)
    }

    /// Set how long three or more unsuccessful calls to this installation's service
    /// must span before the host sees it as unreachable. Defaults to 15 minutes on
    /// join, reopen and restore (Dispatch spec 12.6).
    pub fn set_unreachable_after_ms(&mut self, duration_ms: u64) {
        self.unreachable_after_ms = duration_ms;
    }

    /// Whether the followed service answered, is unreachable, or requires recovery.
    pub fn provider_health(&self) -> ProviderHealth {
        if let Some(notice) = self.recovery_required() {
            return ProviderHealth::RecoveryRequired(notice);
        }
        if let Some(outage) = self.state.health.outage
            && outage.tries >= 3
            && self.now().saturating_sub(outage.since_ms) >= self.unreachable_after_ms
        {
            return ProviderHealth::Unreachable {
                since_ms: outage.since_ms,
            };
        }
        ProviderHealth::Ok
    }

    pub(super) fn may_write_own(&self) -> Result<(), Refusal> {
        if self.client.own_reads.as_ref().is_some_and(|r| r.rollback()) {
            return Err(Refusal::Stopped);
        }
        if let Some(notice) = self.recovery_required() {
            return Err(Refusal::RecoveryRequired {
                generation: notice.generation,
            });
        }
        if self.state.health.display_id.is_some()
            || self
                .client
                .own_reads
                .as_ref()
                .is_some_and(|r| r.display_pending())
        {
            return Err(Refusal::NotNow(
                "the display read is awaiting its original response".into(),
            ));
        }
        Ok(())
    }

    /// The durable notice and its host duty share a commit. On an unknown result a
    /// reload compares the desired state with what actually committed before retrying.
    pub(super) async fn keep_health(&mut self) -> Result<(), AppError> {
        let Some(next) = self.pending_health else {
            return Ok(());
        };
        if self.state.health != next {
            let mut tx = self.tx()?;
            next.write(&mut tx)?;
            if self.state.health.display_id.is_some() && next.display_id.is_none() {
                tx.delete(super::display::PENDING)?;
            }
            match (self.state.health.notice, next.notice) {
                (before, Some(notice))
                    if before.is_none_or(|old| old.permanent != notice.permanent) =>
                {
                    self.keep_duty(&mut tx, Duty::RecoveryRequired { notice })?;
                }
                (Some(old), None) => {
                    self.keep_duty(
                        &mut tx,
                        Duty::RecoveryNoticeCleared {
                            generation: old.generation,
                        },
                    )?;
                }
                _ => {}
            }
            self.commit(tx).await?;
            self.state.health = next;
            if next.display_id.is_none() {
                self.state.display_read = None;
            }
        }
        self.client
            .hold_own_writes(next.notice.map(|notice| notice.generation));
        if let Some(reads) = &self.client.own_reads {
            reads.stored_display(next.display_id.is_some(), next.notice);
        }
        self.pending_health = None;
        Ok(())
    }

    /// Persist verified decisions from the app and its detached reads before other effects.
    pub(super) async fn keep_read_decisions(&mut self) -> Result<(), AppError> {
        self.keep_health().await?;
        let Some(reads) = self.client.own_reads.clone() else {
            return Ok(());
        };
        while let Some(decision) = reads.first() {
            if !self.provider_superseded() {
                match decision {
                    crate::client::own::Decision::Notice(notice) => {
                        self.pending_health = Some(ServiceHealth {
                            notice,
                            outage: None,
                            ..self.state.health
                        });
                        self.keep_health().await?;
                    }
                    crate::client::own::Decision::Rollback => {
                        return Err(self.recovery_rollback().await);
                    }
                }
            }
            reads.committed();
        }
        Ok(())
    }

    pub(super) async fn recovery_rollback(&mut self) -> AppError {
        self.raise(Alarm::Rollback {
            reason: "Dispatch spec 12.6: a retired generation answered with a current head".into(),
        })
        .await
    }

    /// A later head requires a verified identity change before the caller can use its answer
    /// (Dispatch wire 7.1). The own directory can supply that identity itself.
    pub(super) async fn observe_own_answer(&mut self) -> Result<Option<u64>, AppError> {
        let Some(answer) = self.client.take_own_answer() else {
            return Ok(None);
        };
        self.keep_read_decisions().await?;
        let next = self.health_after(answer, self.now()).await?;
        if let OwnAnswer::Success(Some(generation)) = answer
            && generation > self.state.meta.generation
        {
            return Ok(Some(generation));
        }
        self.pending_health = Some(next);
        self.keep_health().await?;
        Ok(None)
    }

    pub(super) async fn health_after(
        &mut self,
        answer: OwnAnswer,
        now: u64,
    ) -> Result<ServiceHealth, AppError> {
        let generation = self.state.meta.generation;
        let mut next = self.state.health;
        let named_generation = match answer {
            OwnAnswer::Notice {
                notice: Some(notice),
                ..
            } => Some(notice.generation),
            OwnAnswer::Success(seen) => seen,
            _ => None,
        };
        if named_generation.is_some_and(|seen| seen > generation) {
            Box::pin(self.read_provider_document(named_generation)).await?;
            return Ok(next);
        }
        if matches!(answer, OwnAnswer::NotHosted)
            && !Box::pin(self.read_provider_document(None)).await?
        {
            return Ok(next);
        }
        match answer {
            OwnAnswer::Success(Some(seen)) if seen != generation => return Ok(next),
            OwnAnswer::Notice { .. } | OwnAnswer::Success(_) | OwnAnswer::Answered => {
                next.outage = None
            }
            OwnAnswer::Unavailable | OwnAnswer::NotHosted => {
                let outage = next.outage.get_or_insert(Outage {
                    since_ms: now,
                    tries: 0,
                });
                outage.tries = outage.tries.saturating_add(1).min(3);
            }
        }
        Ok(next)
    }

    pub(super) async fn commit_followed_generation(&mut self, mut tx: Tx) -> Result<(), AppError> {
        if let Some(old) = self.state.health.notice {
            self.keep_duty(
                &mut tx,
                Duty::RecoveryNoticeCleared {
                    generation: old.generation,
                },
            )?;
        }
        if self.state.health != ServiceHealth::default() {
            ServiceHealth::default().write(&mut tx)?;
            tx.delete(super::display::PENDING)?;
        }
        self.commit(tx).await?;
        self.state.health = ServiceHealth::default();
        self.state.display_read = None;
        self.pending_health = None;
        self.client
            .follow_own_reads(self.state.meta.generation, None, None);
        self.client.hold_own_writes(None);
        Ok(())
    }
}
