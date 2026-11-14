//! The operator's check of every account against its mark, after a database restore or
//! before a failover (Switch spec 6.5, Switch wire 7.3 "Accounts and marks"):
//! `pubky-switch check-marks`.
//!
//! Each account and each mark without an account is judged as the service judges it at a
//! request ([`crate::service`]'s verdict of Table 1), and reported by its verdict. The check
//! reads the database on one read-only connection ([`heads`]) and the key store through a
//! [`KeyStoreView`] and a [`MarkView`], and writes nothing to either, so it runs beside a
//! running service, or against a standby to choose the database to fail over to.
//!
//! **No false `behind` beside a running service.** A mark moves only after the head it
//! names is committed (Switch wire 7.3, "Moving it"), so the check reads each account's mark
//! before its head: a head read after its mark is at the mark or past it, unless state was
//! lost.

use std::{
    collections::{BTreeMap, HashSet},
    path::PathBuf,
    str::FromStr,
};

use pubky_switch_core::{http::RecoveryNotice, records::IdentityBody, sig::SignedDoc};
use serde::Serialize;
use sqlx::{PgConnection, postgres::PgConnectOptions};

use crate::{
    config::Config,
    keys::{KeyStoreError, KeyStoreView},
    marks::{MarkRead, MarkStoreError, MarkView},
    service::verdict::{self, Account, AccountState, Inputs, Judgement, MarkInput, Verdict},
    store::{
        StoreError,
        heads::{self, StoredHead},
    },
};

/// The environment variable that names the replica `--replica` checks.
pub const REPLICA_URL_ENV: &str = "PUBKY_SWITCH_REPLICA_URL";

/// How many accounts one page reads. A page holds each account's `identity.json`, so it
/// stays small.
const PAGE: u32 = 100;

/// An account's or a mark's state, by the verdict of Table 1 (Switch wire 7.3).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MarkState {
    /// The state is at or past the mark.
    Healthy,
    /// A staged account at its (0, 0) mark.
    Staged,
    /// A staged account holding no chain, bounded by its mark.
    Bounded,
    /// The state is behind the mark.
    Behind,
    /// The state is at the mark's pair, or past it, with another chain hash.
    Fork,
    /// The account's mark is missing or doesn't read as a mark.
    MarkLost,
    /// A mark that records a head, with no account and no erasure's record covering it.
    Lost,
    /// A mark an erasure's record covers, with no account: deleted at the next request or
    /// start.
    Leftover,
    /// An account created at or before an erasure's record: erased again at the next
    /// request or start.
    ErasedAgain,
}

impl MarkState {
    /// Every state, in the order the summary lists them.
    pub const ALL: [Self; 9] = [
        Self::Healthy,
        Self::Staged,
        Self::Bounded,
        Self::Behind,
        Self::Fork,
        Self::MarkLost,
        Self::Lost,
        Self::Leftover,
        Self::ErasedAgain,
    ];
}

/// Whether a state needs the operator: every one but `healthy` and `staged`. A database to
/// fail over to must hold what the service signed for every account (Switch spec 6.5).
pub fn needs_attention(state: MarkState) -> bool {
    !matches!(state, MarkState::Healthy | MarkState::Staged)
}

/// Which database the check read.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DatabaseChoice {
    /// The configured one (`database.url`, or `PUBKY_SWITCH_DATABASE_URL`).
    Configured,
    /// The one `--replica` named.
    Replica,
}

/// What the check reads.
#[derive(Clone, Debug)]
pub struct CheckOptions {
    /// The database to read.
    pub database: PgConnectOptions,
    /// Which one it is, for the summary.
    pub choice: DatabaseChoice,
    /// The key store's directory.
    pub key_dir: PathBuf,
    /// This service's origin (`server.origin`), to tell serving accounts.
    pub origin: String,
    /// Report every account, not only those that need attention.
    pub all: bool,
}

impl CheckOptions {
    /// The options `config` gives, reading `replica` instead of the configured database
    /// when one is named.
    pub fn from_config(
        config: &Config,
        replica: Option<&str>,
        all: bool,
    ) -> Result<Self, CheckError> {
        let key_dir = config.keys.path.clone().ok_or(CheckError::NoKeyStore)?;
        // Without it no account reads as serving.
        let origin = config.server.origin.clone().ok_or(CheckError::NoOrigin)?;
        let (url, choice) = match replica.filter(|url| !url.is_empty()) {
            Some(url) => (url.to_string(), DatabaseChoice::Replica),
            None => (
                config.database.effective_url().ok_or(StoreError::NoUrl)?,
                DatabaseChoice::Configured,
            ),
        };
        Ok(Self {
            database: PgConnectOptions::from_str(&url).map_err(StoreError::from)?,
            choice,
            key_dir,
            origin,
            all,
        })
    }
}

/// What the check can fail at.
#[derive(Debug, thiserror::Error)]
pub enum CheckError {
    /// No key store is configured.
    #[error("no key store: set keys.path")]
    NoKeyStore,
    /// No origin is configured, so serving accounts can't be told.
    #[error("no origin: set server.origin, which tells serving accounts")]
    NoOrigin,
    /// The key store failed to read.
    #[error("key store: {0}")]
    Keys(#[from] KeyStoreError),
    /// The mark store failed to read.
    #[error("mark store: {0}")]
    Marks(#[from] MarkStoreError),
    /// The key store holds no service key.
    #[error("the key store holds no service key")]
    NoServiceKey,
    /// The database failed to read.
    #[error(transparent)]
    Store(#[from] StoreError),
    /// The report didn't encode.
    #[error("writing the report: {0}")]
    Encode(#[from] serde_json::Error),
}

/// One line of the report: an account, or a mark without one.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct AccountReport {
    /// The identity's Pubky ID.
    pub account: String,
    /// Whether the database holds an account for it.
    pub hosted: bool,
    /// Whether the account serves: its newest `identity.json` names this service.
    pub serving: bool,
    /// Its state.
    pub state: MarkState,
    /// The generation the recovery notice names, where the verdict gives one (Switch wire
    /// 7.6).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub generation: Option<u64>,
    /// The operator retired that generation (Switch spec 6.5).
    pub permanent: bool,
    /// The generations the operator retired for the identity, ascending (Switch spec 6.5,
    /// `pubky-switch retire`).
    pub retired: Vec<u64>,
    /// The head's `seq`; `None` without an account or before the first chain item.
    pub head_seq: Option<u64>,
    /// The mark's `seq`; `None` without a mark.
    pub mark_seq: Option<u64>,
}

impl AccountReport {
    /// Whether the line needs attention ([`needs_attention`]).
    pub fn needs_attention(&self) -> bool {
        needs_attention(self.state)
    }
}

/// The counts of a check.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Summary {
    /// The database read.
    pub database: DatabaseChoice,
    /// The accounts checked.
    pub accounts: u64,
    /// Of them, the serving ones.
    pub serving: u64,
    /// The lines that need attention, marks without an account included.
    pub needs_attention: u64,
    /// The lines in each state, every state listed.
    pub states: BTreeMap<MarkState, u64>,
}

/// The result of a check.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Report {
    /// The lines reported: those that need attention, or every one with
    /// [`CheckOptions::all`]; the accounts in the order of their IDs, then the marks without
    /// one.
    pub accounts: Vec<AccountReport>,
    /// The counts over every line checked.
    pub summary: Summary,
}

impl Report {
    fn new(database: DatabaseChoice) -> Self {
        Self {
            accounts: Vec::new(),
            summary: Summary {
                database,
                accounts: 0,
                serving: 0,
                needs_attention: 0,
                states: MarkState::ALL.iter().map(|state| (*state, 0)).collect(),
            },
        }
    }

    /// Whether any line needs attention.
    pub fn needs_attention(&self) -> bool {
        self.summary.needs_attention > 0
    }

    /// The report as JSON lines: one object per line reported, then the summary.
    pub fn to_json_lines(&self) -> Result<String, CheckError> {
        #[derive(Serialize)]
        struct SummaryLine<'a> {
            summary: &'a Summary,
        }
        let mut out = String::new();
        for account in &self.accounts {
            out.push_str(&serde_json::to_string(account)?);
            out.push('\n');
        }
        out.push_str(&serde_json::to_string(&SummaryLine {
            summary: &self.summary,
        })?);
        out.push('\n');
        Ok(out)
    }

    fn add(&mut self, line: AccountReport, all: bool) {
        let summary = &mut self.summary;
        if line.hosted {
            summary.accounts = summary.accounts.saturating_add(1);
        }
        if line.serving {
            summary.serving = summary.serving.saturating_add(1);
        }
        let attention = line.needs_attention();
        if attention {
            summary.needs_attention = summary.needs_attention.saturating_add(1);
        }
        let count = summary.states.entry(line.state).or_insert(0);
        *count = count.saturating_add(1);
        if attention || all {
            self.accounts.push(line);
        }
    }
}

/// The state a verdict reports; `None` for a verdict that reports nothing: an identity
/// the service doesn't host, with no leftover.
pub fn state_of(verdict: &Verdict, erased_again: bool) -> Option<MarkState> {
    use pubky_switch_core::http::NoticeReason;
    if erased_again {
        return Some(MarkState::ErasedAgain);
    }
    let reason = |reason| match reason {
        NoticeReason::Behind => MarkState::Behind,
        NoticeReason::Fork => MarkState::Fork,
        NoticeReason::MarkLost => MarkState::MarkLost,
    };
    match verdict {
        Verdict::NotHosted { delete_mark: true } => Some(MarkState::Leftover),
        Verdict::NotHosted { delete_mark: false } | Verdict::Unknown => None,
        Verdict::Staged => Some(MarkState::Staged),
        Verdict::Healthy => Some(MarkState::Healthy),
        Verdict::Bounded { .. } => Some(MarkState::Bounded),
        Verdict::Failing { notice, .. } => Some(reason(notice.reason)),
        Verdict::Lost { .. } => Some(MarkState::Lost),
    }
}

/// The account the verdict judges, as the service judges it ([`Account::judged`]): its
/// newest `identity.json` naming `origin` and a key the key store holds, `service_key`, its
/// one key. Returns it and whether it serves.
fn account_of(head: &StoredHead, origin: &str, service_key: &[u8; 32]) -> (Account, bool) {
    let body = head
        .identity_doc
        .as_deref()
        .and_then(|bytes| serde_json::from_slice::<SignedDoc>(bytes).ok())
        .and_then(|doc| doc.peek::<IdentityBody>().ok());
    let account = Account::judged(
        origin,
        |key| key == service_key,
        head.generation,
        head.chain,
        head.created_at_ms,
        body.as_ref(),
    );
    let serving = matches!(account.state, AccountState::Serving(_));
    (account, serving)
}

/// One identity as the check judges it.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Judged {
    /// The verdict's judgement.
    pub(crate) judgement: Judgement,
    /// The account, as the verdict took it, if the database holds one.
    pub(crate) account: Option<Account>,
    /// Whether the account serves: its newest `identity.json` names this service.
    pub(crate) serving: bool,
}

/// Judge one identity as the service does at a request: `head` its account, if the
/// database holds one, read after `mark`; `stub_at_mark` the hash of the stub it holds at
/// the mark's `seq`, if any; `retired` its retired generations.
#[allow(clippy::too_many_arguments)]
pub(crate) fn judge_identity(
    identity: &str,
    head: Option<&StoredHead>,
    mark: &MarkInput,
    stub_at_mark: Option<[u8; 32]>,
    keys: &KeyStoreView,
    retired: &[u64],
    origin: &str,
    service_key: &[u8; 32],
) -> Judged {
    let judged = head.map(|head| account_of(head, origin, service_key));
    let judgement = verdict::judge(&Inputs {
        account: judged.as_ref().map(|(account, _)| account),
        mark,
        stub_at_mark,
        erasure_at_ms: keys.erasure(identity),
        retired,
        current_key: *service_key,
    });
    Judged {
        judgement,
        account: judged.map(|(account, _)| account),
        serving: judged.is_some_and(|(_, serving)| serving),
    }
}

/// The notice a verdict answers, where it gives one.
pub(crate) fn notice_of(verdict: &Verdict) -> Option<RecoveryNotice> {
    match *verdict {
        Verdict::Bounded { notice, .. }
        | Verdict::Failing { notice, .. }
        | Verdict::Lost { notice } => Some(notice),
        _ => None,
    }
}

/// Judge one identity into its report line ([`judge_identity`]).
#[allow(clippy::too_many_arguments)]
fn judge_line(
    identity: &str,
    head: Option<&StoredHead>,
    mark: &MarkInput,
    stub_at_mark: Option<[u8; 32]>,
    keys: &KeyStoreView,
    marks: &MarkView,
    origin: &str,
    service_key: &[u8; 32],
) -> Option<AccountReport> {
    let retired = marks.retired(identity);
    let judged = judge_identity(
        identity,
        head,
        mark,
        stub_at_mark,
        keys,
        &retired,
        origin,
        service_key,
    );
    let state = state_of(
        &judged.judgement.verdict,
        judged.judgement.erase_account_again,
    )?;
    let notice = notice_of(&judged.judgement.verdict);
    let mark_seq = match mark {
        MarkInput::Mark(mark) => Some(mark.seq),
        _ => None,
    };
    Some(AccountReport {
        account: identity.to_string(),
        hosted: head.is_some(),
        serving: judged.serving,
        state,
        generation: notice.map(|notice| notice.generation),
        permanent: notice.is_some_and(|notice| notice.permanent),
        retired,
        head_seq: head.and_then(|head| head.chain.map(|(seq, _)| seq)),
        mark_seq,
    })
}

/// One identity as the check reads it ([`read_identity`]).
#[derive(Clone, Debug)]
pub(crate) struct IdentityRead {
    /// Its mark.
    pub(crate) mark: MarkInput,
    /// Its account, read after the mark, if the database holds one.
    pub(crate) head: Option<StoredHead>,
    /// The hash of the stub the account holds at the mark's `seq`, where that counts.
    pub(crate) stub_at_mark: Option<[u8; 32]>,
}

/// Read one identity: its mark, then its account, then the stub at the mark.
pub(crate) async fn read_identity(
    conn: &mut PgConnection,
    marks: &MarkView,
    identity: &str,
) -> Result<IdentityRead, CheckError> {
    let mark = mark_input(marks, identity)?;
    let head = heads::heads(conn, &[identity.to_string()])
        .await?
        .into_iter()
        .find(|head| head.id == identity);
    let stub_at_mark = match &head {
        Some(head) => stub_at(conn, head, &mark).await?,
        None => None,
    };
    Ok(IdentityRead {
        mark,
        head,
        stub_at_mark,
    })
}

/// Run the check. It writes nothing: the key store is opened as a [`KeyStoreView`] and the
/// mark store as a [`MarkView`], before the database.
pub async fn run(options: &CheckOptions) -> Result<Report, CheckError> {
    let keys = KeyStoreView::open(&options.key_dir)?;
    let marks = MarkView::open(&options.key_dir)?;
    let service_key = keys.service_key()?.ok_or(CheckError::NoServiceKey)?;
    let mut conn = heads::open_read_only_with(&options.database).await?;
    let report = check(
        &mut conn,
        &keys,
        &marks,
        &options.origin,
        &service_key,
        options,
    )
    .await;
    let _ = sqlx::Connection::close(conn).await;
    report
}

async fn check(
    conn: &mut PgConnection,
    keys: &KeyStoreView,
    marks: &MarkView,
    origin: &str,
    service_key: &[u8; 32],
    options: &CheckOptions,
) -> Result<Report, CheckError> {
    let mut report = Report::new(options.choice);
    let mut seen = HashSet::new();
    let mut after: Option<String> = None;
    loop {
        let ids = heads::ids_after(conn, after.as_deref(), PAGE).await?;
        let Some(last) = ids.last().cloned() else {
            break;
        };
        // Each mark before its head.
        let mut read = Vec::with_capacity(ids.len());
        for id in &ids {
            read.push(mark_input(marks, id)?);
        }
        let found = heads::heads(conn, &ids).await?;
        for (id, mark) in ids.iter().zip(&read) {
            seen.insert(id.clone());
            // An account gone since the page was read is judged with the marks below.
            let Some(head) = found.iter().find(|head| head.id == *id) else {
                seen.remove(id);
                continue;
            };
            let stub = stub_at(conn, head, mark).await?;
            if let Some(line) =
                judge_line(id, Some(head), mark, stub, keys, marks, origin, service_key)
            {
                report.add(line, options.all);
            }
        }
        after = Some(last);
    }
    // The marks without an account: lost accounts and erasures' leftovers.
    for identity in marks.list()? {
        if seen.contains(&identity) {
            continue;
        }
        // Read again: one made meanwhile is a new account's.
        let read = read_identity(conn, marks, &identity).await?;
        if let Some(line) = judge_line(
            &identity,
            read.head.as_ref(),
            &read.mark,
            read.stub_at_mark,
            keys,
            marks,
            origin,
            service_key,
        ) {
            report.add(line, options.all);
        }
    }
    Ok(report)
}

/// The stub `head`'s account holds at the mark's `seq`, where its state is past the mark in
/// the mark's generation, as the service reads it.
async fn stub_at(
    conn: &mut PgConnection,
    head: &StoredHead,
    mark: &MarkInput,
) -> Result<Option<[u8; 32]>, CheckError> {
    let MarkInput::Mark(held) = mark else {
        return Ok(None);
    };
    let past = head.chain.is_some_and(|(seq, _)| {
        held.records_head() && head.generation == held.generation && seq > held.seq
    });
    if !past {
        return Ok(None);
    }
    Ok(heads::stub_hash_at(conn, &head.id, held.generation, held.seq).await?)
}

/// The identity's mark as the verdict takes it.
fn mark_input(marks: &MarkView, identity: &str) -> Result<MarkInput, CheckError> {
    Ok(match marks.read(identity) {
        Ok(MarkRead::Mark(mark)) => MarkInput::Mark(mark),
        Ok(MarkRead::NotAMark) => MarkInput::NotAMark,
        Ok(MarkRead::Missing) | Err(MarkStoreError::InvalidIdentity) => MarkInput::Missing,
        Err(error) => return Err(error.into()),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::marks::AccountMark;
    use pubky_switch_core::chain::ChainTip;

    const KEY: [u8; 32] = [7; 32];

    fn mark(generation: u64, seq: u64, hash: u8) -> MarkInput {
        MarkInput::Mark(AccountMark {
            generation,
            seq,
            chain_hash: [hash; 32],
            key: KEY,
            created_at_ms: 10,
        })
    }

    fn serving(seq: u64, hash: u8) -> Account {
        Account {
            state: AccountState::Serving(ChainTip {
                generation: 1,
                seq,
                chain_hash: [hash; 32],
            }),
            created_at_ms: 10,
            document_generation: Some(1),
            named_key: Some(KEY),
            enrolled_generation: 1,
        }
    }

    fn state(
        account: Option<Account>,
        mark: &MarkInput,
        erasure: Option<u64>,
    ) -> Option<MarkState> {
        let judgement = verdict::judge(&Inputs {
            account: account.as_ref(),
            mark,
            stub_at_mark: None,
            erasure_at_ms: erasure,
            retired: &[],
            current_key: KEY,
        });
        state_of(&judgement.verdict, judgement.erase_account_again)
    }

    #[test]
    fn test_check_marks_states_follow_the_verdict() {
        assert_eq!(
            state(Some(serving(5, 1)), &mark(1, 5, 1), None),
            Some(MarkState::Healthy)
        );
        assert_eq!(
            state(Some(serving(6, 2)), &mark(1, 5, 1), None),
            Some(MarkState::Healthy)
        );
        assert_eq!(
            state(Some(serving(4, 1)), &mark(1, 5, 1), None),
            Some(MarkState::Behind)
        );
        assert_eq!(
            state(Some(serving(5, 2)), &mark(1, 5, 1), None),
            Some(MarkState::Fork)
        );
        assert_eq!(
            state(Some(serving(5, 1)), &MarkInput::Missing, None),
            Some(MarkState::MarkLost)
        );
        assert_eq!(state(None, &mark(1, 5, 1), None), Some(MarkState::Lost));
        assert_eq!(
            state(None, &mark(1, 5, 1), Some(20)),
            Some(MarkState::Leftover)
        );
        assert_eq!(state(None, &MarkInput::Missing, None), None);
        assert_eq!(
            state(Some(serving(5, 1)), &mark(1, 5, 1), Some(20)),
            Some(MarkState::ErasedAgain)
        );
    }

    #[test]
    fn test_check_marks_needs_attention() {
        for state in MarkState::ALL {
            assert_eq!(
                needs_attention(state),
                !matches!(state, MarkState::Healthy | MarkState::Staged),
                "{state:?}"
            );
        }
    }
}
