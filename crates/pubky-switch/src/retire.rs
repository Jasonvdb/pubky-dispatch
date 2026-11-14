//! The operator's retirement of a generation (Switch spec 6.5, "Retiring a generation";
//! Switch wire 7.3, Table 3, "The operator retires a generation"):
//! `pubky-switch retire <identity> <generation>`.
//!
//! A retirement says the loss is permanent: the operator can no longer bring back a state
//! at or past the identity's mark, so its notice carries `permanent: true` from then on. It
//! is one-way: nothing removes it but a rebuilt mark store (Switch wire 7.3, Table 3).
//!
//! The step refuses, and records nothing, unless the generation is above 0 and the target
//! is a failing account that its newest `identity.json` names (serving or frozen), or a
//! lost identity: no account, with a mark that records a head. Every staged account and
//! every healthy one is refused: a staged account's ways out stay the abort and the erasure
//! (Switch wire 7.3, Table 2). The generation retired is the mark's, or the account's
//! (Switch wire 7.6) where the mark is lost; the one given must be that one.
//!
//! **Order.** It takes the key store's directory lock ([`FileKeyStore::lock_dir`]), so it
//! refuses while the service runs on that key store, whose mark store keeps the
//! retirements in memory. Under the lock it judges the identity reading only, as
//! `check-marks` does ([`crate::check_marks`]) and so as the service does at a request,
//! and only then writes the retirement ([`MarkStore::retire`]).

use std::{fmt, path::PathBuf};

use pubky_switch_core::http::RecoveryNotice;
use serde::Serialize;
use sqlx::postgres::PgConnectOptions;

use crate::{
    check_marks::{self, CheckError, CheckOptions, Judged},
    config::Config,
    keys::{FileKeyStore, KeyStoreError, KeyStoreView},
    marks::{MarkStore, MarkStoreError, MarkView},
    service::verdict::{AccountState, MarkInput, Verdict},
    store::heads,
};

/// What the retirement reads and writes.
#[derive(Clone, Debug)]
pub struct RetireOptions {
    /// The database to read.
    pub database: PgConnectOptions,
    /// The key store's directory, where the marks and retirements lie.
    pub key_dir: PathBuf,
    /// This service's origin (`server.origin`), to tell serving accounts.
    pub origin: String,
    /// The identity's Pubky ID.
    pub identity: String,
    /// The generation to retire.
    pub generation: u64,
}

impl RetireOptions {
    /// The options `config` gives, for `identity` and `generation`.
    pub fn from_config(
        config: &Config,
        identity: &str,
        generation: u64,
    ) -> Result<Self, RetireError> {
        let check = CheckOptions::from_config(config, None, false)?;
        Ok(Self {
            database: check.database,
            key_dir: check.key_dir,
            origin: check.origin,
            identity: identity.to_string(),
            generation,
        })
    }
}

/// Why a retirement is refused. Nothing is recorded.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Refusal {
    /// Generation 0 is never retired.
    GenerationZero,
    /// No key store lies at the configured directory.
    NoKeyStore(String),
    /// The service runs on the key store: it holds the directory's lock.
    ServiceRunning(String),
    /// The identity isn't one a mark can be kept for.
    InvalidIdentity,
    /// No account and no mark that records a head, or only an erasure's leftover.
    NotHosted,
    /// The account was created at or before an erasure's record: the service erases it
    /// again.
    ErasedAgain,
    /// The account's state is at or past its mark.
    Healthy,
    /// The account is staged: its newest `identity.json` doesn't name this service.
    Staged,
    /// The mark store can't be read.
    MarkStoreUnreadable,
    /// The generation given isn't the one the identity's retirement is of.
    WrongGeneration {
        /// The generation given.
        given: u64,
        /// The mark's generation, or the account's where the mark is lost.
        retirable: u64,
    },
}

impl fmt::Display for Refusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::GenerationZero => f.write_str("generation 0 is never retired"),
            Self::NoKeyStore(path) => write!(f, "no key store at {path}"),
            Self::ServiceRunning(path) => write!(
                f,
                "the service holds the key store at {path}: stop it first, then retire, then \
                 start it again"
            ),
            Self::InvalidIdentity => f.write_str("not a Pubky ID a mark is kept for"),
            Self::NotHosted => f.write_str(
                "the service doesn't host the identity: no account, and no mark that records a \
                 head",
            ),
            Self::ErasedAgain => f.write_str(
                "the account was created at or before an erasure's record, and is erased again \
                 at the next request or start",
            ),
            Self::Healthy => {
                f.write_str("the account is healthy: its state is at or past its mark")
            }
            Self::Staged => f.write_str(
                "the account is staged (its newest identity.json doesn't name this service): \
                 its ways out are the abort and the erasure",
            ),
            Self::MarkStoreUnreadable => f.write_str("the mark store can't be read"),
            Self::WrongGeneration { given, retirable } => write!(
                f,
                "generation {given} isn't the one to retire: the identity's is {retirable}"
            ),
        }
    }
}

/// What the retirement can fail at.
#[derive(Debug, thiserror::Error)]
pub enum RetireError {
    /// Refused: nothing is recorded.
    #[error("refused: {0}")]
    Refused(Refusal),
    /// The configuration, the key store or the database failed to read.
    #[error(transparent)]
    Check(#[from] CheckError),
    /// The key store failed.
    #[error("key store: {0}")]
    Keys(#[from] KeyStoreError),
    /// The mark store failed, to read or to record the retirement.
    #[error("mark store: {0}")]
    Marks(#[from] MarkStoreError),
    /// The result didn't encode.
    #[error("writing the result: {0}")]
    Encode(#[from] serde_json::Error),
}

/// A recorded retirement.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Retired {
    /// The identity's Pubky ID.
    pub account: String,
    /// The generation retired.
    pub retired: u64,
    /// The generation was retired already: nothing changed.
    pub already_retired: bool,
    /// The recovery notice the identity's requests now get (Switch wire 7.6).
    pub notice: RecoveryNotice,
}

impl Retired {
    /// The result as one JSON line.
    pub fn to_json_line(&self) -> Result<String, RetireError> {
        let mut line = serde_json::to_string(self)?;
        line.push('\n');
        Ok(line)
    }
}

/// The generation the identity's retirement is of, where it may be retired (Switch wire
/// 7.3, Table 3): a failing account its newest `identity.json` names, at the mark's
/// generation or the account's where the mark is lost; a lost identity, at the mark's.
/// With it, the notice the identity answers.
pub(crate) fn retirable(
    judged: &Judged,
    mark: &MarkInput,
) -> Result<(u64, RecoveryNotice), Refusal> {
    if judged.judgement.erase_account_again {
        return Err(Refusal::ErasedAgain);
    }
    let mark = match mark {
        MarkInput::Mark(mark) => Some(mark),
        MarkInput::Missing | MarkInput::NotAMark | MarkInput::StoreUnreadable => None,
    };
    let generation = match judged.judgement.verdict {
        Verdict::Unknown => return Err(Refusal::MarkStoreUnreadable),
        Verdict::NotHosted { .. } => return Err(Refusal::NotHosted),
        Verdict::Healthy => return Err(Refusal::Healthy),
        Verdict::Staged | Verdict::Bounded { .. } => return Err(Refusal::Staged),
        Verdict::Failing { .. } => {
            let Some(account) = judged.account else {
                return Err(Refusal::NotHosted);
            };
            match account.state {
                AccountState::Serving(_) | AccountState::Frozen(_) => {}
                AccountState::StagedNoChain | AccountState::StagedImport(_) => {
                    return Err(Refusal::Staged);
                }
            }
            mark.map_or(account.generation(), |mark| mark.generation)
        }
        Verdict::Lost { .. } => match mark {
            Some(mark) if mark.records_head() => mark.generation,
            _ => return Err(Refusal::NotHosted),
        },
    };
    let notice = check_marks::notice_of(&judged.judgement.verdict).ok_or(Refusal::Healthy)?;
    Ok((generation, notice))
}

/// Retire the generation for the identity, under the key store's lock: the judgement
/// first, reading only, then the write.
pub async fn run(options: &RetireOptions) -> Result<Retired, RetireError> {
    if options.generation == 0 {
        return Err(RetireError::Refused(Refusal::GenerationZero));
    }
    let key_dir = &options.key_dir;
    // The lock would make the directory.
    if !key_dir.is_dir() {
        return Err(RetireError::Refused(Refusal::NoKeyStore(
            key_dir.display().to_string(),
        )));
    }
    let _lock = match FileKeyStore::lock_dir(key_dir) {
        Ok(lock) => lock,
        Err(KeyStoreError::InUse(path)) => {
            return Err(RetireError::Refused(Refusal::ServiceRunning(path)));
        }
        Err(error) => return Err(error.into()),
    };
    let keys = KeyStoreView::open(key_dir)?;
    let view = MarkView::open(key_dir)?;
    if matches!(
        view.read(&options.identity),
        Err(MarkStoreError::InvalidIdentity)
    ) {
        return Err(RetireError::Refused(Refusal::InvalidIdentity));
    }
    let service_key = keys.service_key()?.ok_or(CheckError::NoServiceKey)?;
    let mut conn = heads::open_read_only_with(&options.database)
        .await
        .map_err(CheckError::from)?;
    let read = check_marks::read_identity(&mut conn, &view, &options.identity).await;
    let _ = sqlx::Connection::close(conn).await;
    let read = read?;
    let mut retired = view.retired(&options.identity);
    let judge = |retired: &[u64]| {
        check_marks::judge_identity(
            &options.identity,
            read.head.as_ref(),
            &read.mark,
            read.stub_at_mark,
            &keys,
            retired,
            &options.origin,
            &service_key,
        )
    };
    let (generation, notice) =
        retirable(&judge(&retired), &read.mark).map_err(RetireError::Refused)?;
    if generation != options.generation {
        return Err(RetireError::Refused(Refusal::WrongGeneration {
            given: options.generation,
            retirable: generation,
        }));
    }
    let already_retired = retired.contains(&generation);
    if !already_retired {
        // The view found the store, so opening it for the write makes none.
        MarkStore::open(key_dir.clone())?
            .retire(&options.identity, generation)
            .await?;
        retired.push(generation);
        retired.sort_unstable();
    }
    // The retirement changes only `permanent` (Switch wire 7.3, Table 1).
    let notice = check_marks::notice_of(&judge(&retired).judgement.verdict).unwrap_or(notice);
    Ok(Retired {
        account: options.identity.clone(),
        retired: generation,
        already_retired,
        notice,
    })
}

#[cfg(test)]
mod tests {
    use pubky_switch_core::chain::ChainTip;

    use super::*;
    use crate::{
        marks::AccountMark,
        service::verdict::{self, Account, Inputs},
    };

    const KEY: [u8; 32] = [7; 32];

    fn mark(generation: u64, seq: u64) -> MarkInput {
        MarkInput::Mark(AccountMark {
            generation,
            seq,
            chain_hash: [1; 32],
            key: KEY,
            created_at_ms: 10,
        })
    }

    fn account(state: AccountState) -> Account {
        Account {
            state,
            created_at_ms: 10,
            document_generation: Some(2),
            named_key: Some(KEY),
            enrolled_generation: 2,
        }
    }

    fn tip(seq: u64) -> ChainTip {
        ChainTip {
            generation: 2,
            seq,
            chain_hash: [1; 32],
        }
    }

    fn judged(account: Option<Account>, mark: &MarkInput) -> Judged {
        Judged {
            judgement: verdict::judge(&Inputs {
                account: account.as_ref(),
                mark,
                stub_at_mark: None,
                erasure_at_ms: None,
                retired: &[],
                current_key: KEY,
            }),
            account,
            serving: account.is_some_and(|account| account.named_key.is_some()),
        }
    }

    #[test]
    fn test_retire_failing_frozen_account_is_retirable() {
        // A frozen account behind its mark fails stop, and is retired at the mark's
        // generation; at its mark it is healthy, and refused.
        let behind = mark(2, 5);
        let frozen = account(AccountState::Frozen(tip(3)));
        assert_eq!(
            retirable(&judged(Some(frozen), &behind), &behind).map(|(generation, _)| generation),
            Ok(2)
        );
        let at = mark(2, 3);
        assert_eq!(
            retirable(&judged(Some(frozen), &at), &at),
            Err(Refusal::Healthy)
        );
    }

    #[test]
    fn test_retire_mark_lost_takes_the_account_generation() {
        let serving = account(AccountState::Serving(tip(3)));
        assert_eq!(
            retirable(
                &judged(Some(serving), &MarkInput::Missing),
                &MarkInput::Missing
            )
            .map(|(generation, _)| generation),
            Ok(2)
        );
    }

    #[test]
    fn test_retire_staged_failing_account_is_refused() {
        let behind = mark(2, 5);
        let staged = account(AccountState::StagedImport(tip(3)));
        assert_eq!(
            retirable(&judged(Some(staged), &behind), &behind),
            Err(Refusal::Staged)
        );
    }
}
