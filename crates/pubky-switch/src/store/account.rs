//! The account and its transaction.
//!
//! An [`AccountTxn`] is one request's view of one account: it holds the account's lock from
//! [`Store::begin`](super::Store::begin) until it commits or is dropped. It hands out
//! `seq`s, moves the chain head and stamps the service time, and writes them back when it
//! commits. Dropping it without committing, or a process that dies before the commit,
//! rolls everything back.

use sqlx::{PgConnection, Postgres, Row, Transaction};

use super::{StoreError, from_db, to_db};
use pubky_switch_core::{records::AccountActivation, sig::SignedDoc};

use crate::keys::KeyId;

/// A new account, at enrollment (Switch wire 7.4.1).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NewAccount {
    /// The activation required by this account's initial state (Switch account binding 3.1).
    pub activation: AccountActivation,
    /// The identity's Pubky ID.
    pub id: String,
    /// The identity's Ed25519 public key.
    pub identity_key: [u8; 32],
    /// The generation the account starts at.
    pub generation: u64,
    /// The service time of the enrollment.
    pub created_at_ms: u64,
    /// The limits the enrollment announces, kept for every later enrollment.
    pub limits: pubky_switch_core::records::Limits,
    /// The `identity.json` the enrollment carried, for a new provider (Switch wire 3.7).
    pub identity_doc: Option<SignedDoc>,
    /// The App IDs the enrollment's `revoked_apps` names, kept for good from the start
    /// (Switch wire 3.7).
    pub revoked_apps: Vec<[u8; 16]>,
    /// The document hash of the enrollment that creates the account, whose answer the
    /// account keeps (Switch wire 3.7).
    pub enrollment_hash: [u8; 32],
    /// The confirmed mark-store identity associated with the creating enrollment.
    pub enrollment_store_id: [u8; 16],
    /// Its first stamped service time: the creation time, or the time floor of a mark it
    /// takes over where that is later (Switch wire 7.3, "Trusted time").
    pub stamped_time_ms: u64,
    /// The run of the service that creates it, which commits that time (Switch wire 7.3,
    /// "Trusted time").
    pub stamped_by: [u8; 16],
}

/// One run of the service, from one start to its stop, named by a random id (Switch wire
/// 7.3, "Trusted time"). A state is restored or failed over only across a restart, so a
/// state a run committed itself is no restored one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ServiceRun {
    id: [u8; 16],
    /// Whether the id came from the system's randomness; without it no state counts as
    /// this run's, so each stamp takes the mark's time floor.
    random: bool,
}

impl ServiceRun {
    /// A new run, with a random id.
    pub fn start() -> Self {
        let mut id = [0u8; 16];
        let random = getrandom::fill(&mut id).is_ok();
        Self { id, random }
    }

    /// The id the states it stamps record.
    pub fn id(&self) -> [u8; 16] {
        self.id
    }

    /// Whether this run committed a state that records `stamped_by`.
    pub fn stamped(&self, stamped_by: &[u8; 16]) -> bool {
        self.random && *stamped_by == self.id
    }
}

/// The last time the service committed for an account, as answers show it and the next
/// stamp starts from (Switch wire 7.1 Timestamp, 7.3 "Trusted time"): the time it stamped,
/// `stamped_time_ms`, where `run` stamped it, `stamped_by`; otherwise, as for a restored
/// state, that time or its mark's time floor, `mark_floor_ms`, whichever is later, so
/// service time never goes back for the identity. With the mark lost there is no floor. A
/// reader before the account's lock reads the mark before the state: a floor it reads, a
/// state it then reads that another run stamped committed no time after it since.
pub fn committed_time_ms(
    stamped_time_ms: u64,
    stamped_by: &[u8; 16],
    run: ServiceRun,
    mark_floor_ms: Option<u64>,
) -> u64 {
    match mark_floor_ms {
        Some(floor) if !run.stamped(stamped_by) => stamped_time_ms.max(floor),
        _ => stamped_time_ms,
    }
}

/// An account's position: its generation and key, the last `seq` given out, the chain head,
/// its count of changed commits, the stamped service time and the run that stamped it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AccountHead {
    /// The persisted activation requirement of this lifetime.
    pub activation: AccountActivation,
    /// The identity's Pubky ID.
    pub id: String,
    /// The identity's Ed25519 public key.
    pub identity_key: [u8; 32],
    /// The generation the account serves.
    pub generation: u64,
    /// The last `seq` given out, shared by inbox entries and chain items; 0 before any.
    pub last_seq: u64,
    /// The newest chain item's `seq` and the chain hash there; `None` before the first.
    pub chain: Option<(u64, [u8; 32])>,
    /// The account's count of changed commits: one more for each commit that changed any of
    /// its counted state, never reset while the account lasts (Switch wire 7.3, "The state").
    pub state_version: u64,
    /// The random tag written with the count's last move, the zero tag before the first:
    /// with the count, it tells two histories apart (Switch wire 7.3, "The state").
    pub state_tag: [u8; 16],
    /// The last service time the account stamped.
    pub stamped_time_ms: u64,
    /// The run of the service that stamped it (Switch wire 7.3, "Trusted time").
    pub stamped_by: [u8; 16],
    /// When the account was created.
    pub created_at_ms: u64,
}

impl AccountHead {
    /// The last time the service committed for the account in `run`, under the mark's time
    /// floor `mark_floor_ms` ([`committed_time_ms`]).
    pub fn committed_ms(&self, run: ServiceRun, mark_floor_ms: Option<u64>) -> u64 {
        committed_time_ms(self.stamped_time_ms, &self.stamped_by, run, mark_floor_ms)
    }

    /// Its count of changed commits with their tag (Switch wire 7.3, "The state").
    pub fn count(&self) -> crate::account::Count {
        crate::account::Count {
            version: self.state_version,
            tag: self.state_tag,
        }
    }

    /// The chain tip the next chain item links to: the newest item's `seq` and chain hash,
    /// or `seq` 0 and the zero hash before any (Switch wire 6.6).
    pub fn chain_tip(&self) -> pubky_switch_core::chain::ChainTip {
        let (seq, chain_hash) = self
            .chain
            .unwrap_or((0, pubky_switch_core::chain::ZERO_HASH));
        pubky_switch_core::chain::ChainTip {
            generation: self.generation,
            seq,
            chain_hash,
        }
    }

    /// Where the mark moves once this position is durable (Switch wire 7.3, "Moving it"):
    /// the chain head with the count and its tag; at a serving account before its first
    /// chain item, its generation, `seq` 0 and the zero hash with the count, once the count
    /// has moved. `None` where there is nothing to cover.
    pub fn mark_target(&self, serving: bool) -> Option<crate::marks::MarkTarget> {
        crate::marks::MarkTarget::of(
            self.chain_tip(),
            self.state_version,
            self.state_tag,
            self.stamped_time_ms,
            serving,
        )
    }

    /// The chain head, `None` before the first chain item.
    pub fn head_tip(&self) -> Option<pubky_switch_core::chain::ChainTip> {
        self.chain
            .map(|(seq, chain_hash)| pubky_switch_core::chain::ChainTip {
                generation: self.generation,
                seq,
                chain_hash,
            })
    }
}

/// The position this request will cover before releasing its answer (Switch wire 7.3).
#[derive(Clone, Copy)]
pub(crate) enum MarkCoverage {
    None,
    ChainHead,
    ServingPosition,
}

/// Net changes under the identity lock, after superseded documents and savepoint rollbacks.
pub(crate) struct PendingChanges {
    moved: bool,
    pub(crate) counts: bool,
    pub(crate) recovery_changed: bool,
}

/// A committed request: what it committed is durable, so its answer may go out once the
/// mark has moved to its head and count (Switch wire 7.3 step 10, "Moving it"). Only
/// [`AccountTxn::commit`] makes one.
#[derive(Debug)]
pub struct Committed {
    pub(crate) mark_target: Option<crate::marks::MarkTarget>,
    head: AccountHead,
    counted: bool,
}

impl Committed {
    /// The account's position as committed.
    pub fn head(&self) -> &AccountHead {
        &self.head
    }

    /// Whether the commit changed counted state, and so moved the account's count (Switch
    /// wire 7.3, "The state").
    pub fn counted(&self) -> bool {
        self.counted
    }
}

/// An erasure that failed, retaining the account lock when its deletion was rolled back.
/// The caller can withdraw its erasure record before another request judges that account
/// (Switch wire 7.3, Table 3). A failed commit may have committed and retains no lock.
#[derive(Debug, thiserror::Error)]
#[error("{error}")]
pub struct ErasureFailure {
    #[source]
    error: StoreError,
    account: Option<Box<AccountTxn>>,
}

impl ErasureFailure {
    /// The storage error and, when rollback succeeded, the still-locked account.
    /// Without that account, the caller must acquire the identity lock and check whether
    /// deletion committed before withdrawing its record.
    pub fn into_parts(self) -> (StoreError, Option<Box<AccountTxn>>) {
        (self.error, self.account)
    }
}

/// Where a request's endpoint started, so a refusal can undo what it wrote
/// ([`AccountTxn::rollback_to`]).
#[derive(Debug)]
pub struct Savepoint {
    head: AccountHead,
    changed: bool,
    owed: usize,
}

/// One request's transaction on one account, holding the account's lock.
pub struct AccountTxn {
    creation_origin: Option<[u8; 32]>,
    covered_version: u64,
    tx: Transaction<'static, Postgres>,
    head: AccountHead,
    loaded: AccountHead,
    changed: bool,
    last_seen: Option<([u8; 16], u64)>,
    /// Sender identities that hit an append limit in this request (Switch wire 9.4 Flags).
    flag_hits: Vec<[u8; 32]>,
    /// The flagged senders kept (`max_flags`), for the hits above.
    max_flags: u64,
    /// The push keys this request owes deleting once it commits (`store::push`).
    pub(super) owed: Vec<KeyId>,
    /// Chain items this request may have superseded, whose documents go before the commit
    /// if no app may read them any more (`documents.rs`).
    pub(super) superseded: std::collections::BTreeSet<u64>,
    /// Apps whose record or renewed certificate this request may have changed.
    pub(super) documents_of_apps: std::collections::BTreeSet<[u8; 16]>,
    /// A transaction on the reader pool, begun before the lock, to export this one's
    /// snapshot to ([`AccountTxn::snapshot_read`]).
    pub(super) reader: Option<Transaction<'static, Postgres>>,
    /// The reader, once this transaction's snapshot is exported to it.
    pub(super) snapshot: Option<super::SnapshotRead>,
    /// The account's one read after the lock, until it is handed to the reader.
    pub(super) read_turn: Option<super::snapshot::ReadTurn>,
    /// How long importing the snapshot may take, under the lock: `lock_timeout_ms`.
    pub(super) import_timeout_ms: u64,
    /// For tests: where that read waits before it reads.
    #[cfg(any(test, feature = "test-util"))]
    pub(super) snapshot_pause: Option<super::testing::SnapshotPause>,
}

impl std::fmt::Debug for AccountTxn {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AccountTxn")
            .field("head", &self.head)
            .finish_non_exhaustive()
    }
}

/// An account inserted under its identity's lock and not committed yet
/// ([`super::IdentityLock::create`]): it commits at the creation time asked for, which the
/// caller read under the same lock past every erasure's record and every mark it takes over
/// (Switch wire 7.3, "The mark").
pub struct Creation {
    tx: Transaction<'static, Postgres>,
    account: NewAccount,
    kept: Vec<super::KeptAppId>,
}

impl std::fmt::Debug for Creation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Creation")
            .field("id", &self.account.id)
            .finish_non_exhaustive()
    }
}

/// Insert an account in `tx`, which holds its identity's lock, unless one exists: `None` if
/// one does.
pub(super) async fn create(
    mut tx: Transaction<'static, Postgres>,
    account: &NewAccount,
) -> Result<Option<Creation>, StoreError> {
    let identity_doc = account
        .identity_doc
        .as_ref()
        .map(super::identity::encode_doc)
        .transpose()?;
    let created = sqlx::query(
        "INSERT INTO accounts (id, identity_key, generation, created_at_ms, \
         stamped_time_ms, stamped_by, announced_limits, identity_doc, activation_requirement) \
         VALUES ($1, $2, $3, $4, $9, $8, $5, $6, $7) ON CONFLICT (id) DO NOTHING",
    )
    .bind(&account.id)
    .bind(account.identity_key.as_slice())
    .bind(to_db(account.generation, "generation")?)
    .bind(to_db(account.created_at_ms, "created_at_ms")?)
    .bind(
        serde_json::to_vec(&account.limits)
            .map_err(|_| StoreError::Corrupt("the announced limits don't encode"))?,
    )
    .bind(identity_doc)
    .bind(account.activation.as_str())
    .bind(account.stamped_by.as_slice())
    .bind(to_db(account.stamped_time_ms, "stamped_time_ms")?)
    .execute(&mut *tx)
    .await
    .map_err(StoreError::from_db)?
    .rows_affected();
    if created != 1 {
        return Ok(None);
    }
    Ok(Some(Creation {
        tx,
        account: account.clone(),
        kept: Vec::new(),
    }))
}

impl Creation {
    /// Commit the account, at the creation time asked for, and let its identity's lock go.
    pub async fn commit(mut self) -> Result<(), StoreError> {
        self.populate().await?;
        self.tx.commit().await.map_err(StoreError::from_db)
    }

    /// Materialize the fresh account and its immutable witness, still under the identity lock.
    pub(crate) async fn prepare_fresh(
        mut self,
    ) -> Result<
        (
            Transaction<'static, Postgres>,
            super::creation_anchor::OpeningContents,
        ),
        StoreError,
    > {
        self.populate().await?;
        let opening = super::creation_anchor::contents(
            &mut self.tx,
            &self.account.id,
            self.account.enrollment_store_id,
            self.account.enrollment_hash,
            true,
        )
        .await?;
        sqlx::query(
            "UPDATE accounts SET creation_anchor = $2, opening_material = $3 WHERE id = $1",
        )
        .bind(&self.account.id)
        .bind(opening.anchor.as_slice())
        .bind(opening.material.as_slice())
        .execute(&mut *self.tx)
        .await
        .map_err(StoreError::from_db)?;
        Ok((self.tx, opening))
    }

    async fn populate(&mut self) -> Result<(), StoreError> {
        let account = &self.account;
        let created_at_ms = account.created_at_ms;
        for kept in &self.kept {
            let reason = match kept.reason {
                super::KeptReason::Revoked => "revoked",
                super::KeptReason::Departed => "departed",
                super::KeptReason::Enrolled => "enrolled",
                super::KeptReason::Document => "document",
            };
            sqlx::query(
                "INSERT INTO kept_app_ids (account_id, app_id, reason, at_ms, data_epoch, rotated) \
                 VALUES ($1, $2, $3, $4, $5, $6)",
            )
            .bind(&account.id)
            .bind(kept.app_id.as_slice())
            .bind(reason)
            .bind(kept.at_ms.map(|at| to_db(at, "at_ms")).transpose()?)
            .bind(
                kept.data_epoch
                    .map(|epoch| to_db(epoch, "data_epoch"))
                    .transpose()?,
            )
            .bind(kept.rotated)
            .execute(&mut *self.tx)
            .await
            .map_err(StoreError::from_db)?;
        }
        for app_id in &account.revoked_apps {
            sqlx::query(
                "INSERT INTO kept_app_ids (account_id, app_id, reason, at_ms) \
                 VALUES ($1, $2, 'enrolled', $3) ON CONFLICT DO NOTHING",
            )
            .bind(&account.id)
            .bind(app_id.as_slice())
            .bind(to_db(created_at_ms, "created_at_ms")?)
            .execute(&mut *self.tx)
            .await
            .map_err(StoreError::from_db)?;
        }
        // The apps the enrollment's identity.json lists are listed for the first time here
        // (Switch wire 7.4.12 keys_through).
        if let Some(doc) = &account.identity_doc {
            let doc = pubky_switch_core::records::IdentityDoc::verify(doc, &account.identity_key)
                .map_err(|_| StoreError::Corrupt("the enrollment's identity.json"))?;
            super::apps::note_removed(&mut self.tx, &account.id, &doc).await?;
            if account.activation == AccountActivation::Ordinary {
                let listed = super::apps::newly_listed(None, &doc);
                super::apps::note_listings(&mut self.tx, &account.id, &listed, doc.data_epoch())
                    .await?;
            }
        }
        // The first enrollment's answer: an account keeps far fewer than any limit allows.
        super::enrollments::keep(
            &mut self.tx,
            &account.id,
            &account.enrollment_hash,
            &super::enrollments::EnrollmentReceipt {
                created_at_ms,
                store_id: account.enrollment_store_id,
                answered_at_ms: created_at_ms,
            },
            u64::MAX >> 1,
            true,
        )
        .await?;
        Ok(())
    }
}

impl AccountTxn {
    /// Replace this proven-older lifetime with an empty, recovery-only account in the
    /// same transaction, retaining its exclusions and push-key deletion obligations
    /// (Switch account binding 3.1). The caller has durably taken the exact newer mark.
    pub async fn replace_for_recovery(
        mut self,
        account: &NewAccount,
    ) -> Result<Creation, StoreError> {
        if account.id != self.head.id
            || account.identity_key != self.head.identity_key
            || account.activation != AccountActivation::Recovery
            || account.created_at_ms <= self.head.created_at_ms
            || account.created_at_ms < self.head.stamped_time_ms
            || account.generation < self.head.generation
        {
            return Err(StoreError::Corrupt(
                "an invalid recovery-only account replacement",
            ));
        }
        let held = self.held_identity().await?;
        if held.as_ref().map(|held| &held.doc) != account.identity_doc.as_ref() {
            return Err(StoreError::Corrupt(
                "a replacement changed its retained document",
            ));
        }
        self.join_held_revoked_apps(account.created_at_ms).await?;
        let kept = self.kept_entries().await?;
        self.delete_account(account.created_at_ms).await?;
        let mut creation = create(self.tx, account).await?.ok_or(StoreError::Corrupt(
            "an account appeared under its identity lock",
        ))?;
        creation.kept = kept;
        Ok(creation)
    }

    /// Lock account `id` in `tx` and read its position.
    pub(super) async fn lock(
        mut tx: Transaction<'static, Postgres>,
        id: &str,
    ) -> Result<Option<Self>, StoreError> {
        let row = sqlx::query(
            "SELECT id, identity_key, generation, last_seq, chain_seq, chain_hash, state_version, \
             state_tag, stamped_time_ms, stamped_by, created_at_ms, activation_requirement, \
             creation_anchor, (SELECT h.creation_anchor FROM state_history h WHERE \
             h.account_id = accounts.id AND h.state_version = accounts.state_version AND \
             h.state_tag = accounts.state_tag) AS history_origin FROM accounts \
             WHERE id = $1 FOR UPDATE",
        )
        .bind(id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(StoreError::from_db)?;
        let Some(row) = row else {
            return Ok(None);
        };
        let identity_key: Vec<u8> = row.try_get("identity_key")?;
        let chain = super::chain_head(&row, "chain head")?;
        let head = AccountHead {
            activation: AccountActivation::parse(row.try_get("activation_requirement")?)
                .map_err(|_| StoreError::Corrupt("activation_requirement"))?,
            id: row.try_get("id")?,
            identity_key: <[u8; 32]>::try_from(identity_key.as_slice())
                .map_err(|_| StoreError::Corrupt("identity_key"))?,
            generation: from_db(row.try_get("generation")?, "generation")?,
            last_seq: from_db(row.try_get("last_seq")?, "last_seq")?,
            chain,
            state_version: from_db(row.try_get("state_version")?, "state_version")?,
            state_tag: super::state_tag(row.try_get("state_tag")?)?,
            stamped_time_ms: from_db(row.try_get("stamped_time_ms")?, "stamped_time_ms")?,
            stamped_by: stamped_by(&row)?,
            created_at_ms: from_db(row.try_get("created_at_ms")?, "created_at_ms")?,
        };
        let stored: Option<Vec<u8>> = row.try_get("creation_anchor")?;
        let creation_origin = match stored.as_deref() {
            Some(stored) if head.state_version == 0 && head.last_seq == 0 => {
                super::creation_anchor::opening_origin(&mut tx, &head, stored).await?
            }
            Some(stored) if head.state_version > 0 => {
                let previous: Option<Vec<u8>> = row.try_get("history_origin")?;
                previous
                    .filter(|origin| origin == stored)
                    .and_then(|origin| origin.try_into().ok())
            }
            _ => None,
        };
        Ok(Some(Self {
            tx,
            creation_origin,
            covered_version: 0,
            loaded: head.clone(),
            head,
            changed: false,
            last_seen: None,
            flag_hits: Vec::new(),
            max_flags: 0,
            owed: Vec::new(),
            superseded: std::collections::BTreeSet::new(),
            documents_of_apps: std::collections::BTreeSet::new(),
            reader: None,
            snapshot: None,
            read_turn: None,
            import_timeout_ms: 0,
            #[cfg(any(test, feature = "test-util"))]
            snapshot_pause: None,
        }))
    }

    /// The original SQL contents from which the locked transaction descends. The
    /// consumer must match this value with evidence outside SQL (account binding 3).
    pub(crate) fn creation_origin(&self) -> Option<[u8; 32]> {
        self.creation_origin
    }

    /// The account's position, with this request's changes.
    pub fn head(&self) -> &AccountHead {
        &self.head
    }

    pub(crate) fn retain_from_mark(&mut self, mark: Option<&crate::marks::AccountMark>) {
        if let Some(mark) = mark.filter(|mark| {
            mark.created_at_ms == self.loaded.created_at_ms
                && mark.state_version <= self.loaded.state_version
        }) {
            self.covered_version = mark.state_version;
        }
    }

    /// Stamp the service time `time_ms` for this request in `run`, or the last time the
    /// account stamped if that is later, so service time never goes back for an identity
    /// (Switch spec 10.1, Switch wire 7.3 step 3, "Trusted time"); the state records that
    /// `run` stamped it. Kept only if the request commits. The time stamped.
    pub fn stamp(&mut self, time_ms: u64, run: ServiceRun) -> u64 {
        self.head.stamped_time_ms = self.head.stamped_time_ms.max(time_ms);
        self.head.stamped_by = run.id();
        self.head.stamped_time_ms
    }

    /// Give out the next `seq` (Switch spec 6.3).
    pub fn next_seq(&mut self) -> Result<u64, StoreError> {
        let seq = self
            .head
            .last_seq
            .checked_add(1)
            .filter(|seq| i64::try_from(*seq).is_ok())
            .ok_or(StoreError::OutOfRange("seq"))?;
        self.head.last_seq = seq;
        Ok(seq)
    }

    /// Move the chain head to the chain item at `seq`, whose chain hash is `chain_hash`.
    /// `seq` must have been given out by this request, after the current chain head: in a
    /// generation this request started (`start_head`), every `seq` is.
    pub fn set_chain_head(&mut self, seq: u64, chain_hash: [u8; 32]) -> Result<(), StoreError> {
        let after_head = self.head.chain.is_none_or(|(head, _)| seq > head);
        let given_before =
            self.head.generation == self.loaded.generation && seq <= self.loaded.last_seq;
        if !after_head || given_before || seq > self.head.last_seq {
            return Err(StoreError::OutOfRange("chain head seq"));
        }
        self.head.chain = Some((seq, chain_hash));
        Ok(())
    }

    /// Note that this request changes the account, so its commit wakes the requests
    /// waiting on it ([`crate::changes`]). A request that gives out a `seq` or moves the
    /// chain head counts as a change without this; one that only stamps the time doesn't.
    pub fn note_change(&mut self) {
        self.changed = true;
    }

    /// Note an own app's authenticated request at `at_ms` (Switch wire 7.3 step 6). It is
    /// written with the commit, also when the endpoint is refused and rolled back.
    pub fn note_last_seen(&mut self, app_id: [u8; 16], at_ms: u64) {
        self.last_seen = Some((app_id, at_ms));
    }

    /// Note a hit of `sender` against an append limit (Switch wire 9.4 Flags). It is written
    /// with the commit, also when the append is refused and rolled back, as the refusal is
    /// what it counts.
    pub fn note_flag_hit(&mut self, sender: [u8; 32], max_flags: u64) {
        self.flag_hits.push(sender);
        self.max_flags = max_flags;
    }

    /// Mark the start of the request's endpoint. Everything it writes after this, its
    /// `seq`s and chain head included, can be undone with [`AccountTxn::rollback_to`],
    /// while the stamped time stays.
    pub async fn savepoint(&mut self) -> Result<Savepoint, StoreError> {
        sqlx::query("SAVEPOINT endpoint")
            .execute(&mut *self.tx)
            .await
            .map_err(StoreError::from_db)?;
        Ok(Savepoint {
            head: self.head.clone(),
            changed: self.changed,
            owed: self.owed.len(),
        })
    }

    /// Undo everything written since `savepoint`, keeping the time this request stamped and
    /// the run that stamped it: a refused request commits its stamp and nothing else
    /// (Switch wire 7.3 steps 3 and 10). If this fails the transaction must not be
    /// committed.
    pub async fn rollback_to(&mut self, savepoint: Savepoint) -> Result<(), StoreError> {
        sqlx::query("ROLLBACK TO SAVEPOINT endpoint")
            .execute(&mut *self.tx)
            .await
            .map_err(StoreError::from_db)?;
        let stamped_time_ms = self.head.stamped_time_ms;
        let stamped_by = self.head.stamped_by;
        self.head = AccountHead {
            stamped_time_ms,
            stamped_by,
            ..savepoint.head
        };
        self.changed = savepoint.changed;
        self.owed.truncate(savepoint.owed);
        Ok(())
    }

    /// The transaction's connection, for the queries of the account's other state. Every
    /// query on it is part of this request, and commits or rolls back with it.
    pub fn conn(&mut self) -> &mut PgConnection {
        &mut self.tx
    }

    /// Commit the request. Once this returns, what it committed is durable; its answer goes
    /// out once the mark has moved to its head and count (Switch wire 7.3 step 10, "Moving
    /// it").
    ///
    /// The account's count moves by one where the request changed counted state: a row the
    /// schema's count trigger saw change, or the account's position other than its stamp.
    /// Each move writes a fresh random tag beside the count. It is read after the superseded
    /// documents go and before the request's last-seen time and flags are written, which
    /// count nothing (Switch wire 7.3, "The state").
    pub async fn commit(self) -> Result<Committed, StoreError> {
        self.commit_with_mark(MarkCoverage::None).await
    }

    pub(crate) async fn commit_with_mark(
        mut self,
        coverage: MarkCoverage,
    ) -> Result<Committed, StoreError> {
        let changes = self.pending_changes(false).await?;
        self.commit_prepared(coverage, changes).await
    }

    pub(crate) async fn pending_changes(
        &mut self,
        check_recovery: bool,
    ) -> Result<PendingChanges, StoreError> {
        self.drop_stale_documents().await?;
        let moved = self.head.generation != self.loaded.generation
            || self.head.last_seq != self.loaded.last_seq
            || self.head.chain != self.loaded.chain;
        let (retained, recovery_changed) = if check_recovery {
            sqlx::query_as("SELECT retained_state_change(), retained_recovery_change()")
                .fetch_one(&mut *self.tx)
                .await?
        } else if moved {
            (true, false)
        } else {
            (
                sqlx::query_scalar("SELECT retained_state_change()")
                    .fetch_one(&mut *self.tx)
                    .await?,
                false,
            )
        };
        Ok(PendingChanges {
            counts: moved || retained,
            moved,
            recovery_changed: recovery_changed || self.head.generation != self.loaded.generation,
        })
    }

    /// Commit the prepared transaction after any read of the facts it will cover.
    pub(crate) async fn commit_prepared(
        mut self,
        coverage: MarkCoverage,
        changes: PendingChanges,
    ) -> Result<Committed, StoreError> {
        let PendingChanges { moved, counts, .. } = changes;
        let chain_seq = self
            .head
            .chain
            .map(|(seq, _)| to_db(seq, "chain_seq"))
            .transpose()?;
        let chain_hash = self.head.chain.map(|(_, hash)| hash.to_vec());
        // An overflow of the count is the database's error: the commit fails.
        let loaded_count = || -> Result<(i64, Vec<u8>), StoreError> {
            Ok((
                to_db(self.loaded.state_version, "state_version")?,
                self.loaded.state_tag.to_vec(),
            ))
        };
        let count: Option<(i64, Vec<u8>)> = if self.head == self.loaded && !counts {
            Some(loaded_count()?)
        } else {
            // The tag: a version 4 UUID's 16 bytes, 122 of them random.
            sqlx::query_as(
                "UPDATE accounts SET last_seq = $2, chain_seq = $3, chain_hash = $4, \
                 stamped_time_ms = $5, stamped_by = $7, \
                 state_version = CASE WHEN $6 THEN state_version + 1 \
                 ELSE state_version END, \
                 state_tag = CASE WHEN $6 THEN uuid_send(gen_random_uuid()) \
                 ELSE state_tag END \
                 WHERE id = $1 RETURNING state_version, state_tag",
            )
            .bind(&self.head.id)
            .bind(to_db(self.head.last_seq, "last_seq")?)
            .bind(chain_seq)
            .bind(chain_hash)
            .bind(to_db(self.head.stamped_time_ms, "stamped_time_ms")?)
            .bind(counts)
            .bind(self.head.stamped_by.as_slice())
            .fetch_optional(&mut *self.tx)
            .await
            .map_err(StoreError::from_db)?
        };
        let (state_version, state_tag) = match count {
            Some(count) => count,
            // The row this transaction deleted, its position unchanged, has no count to move.
            None if self.head == self.loaded => loaded_count()?,
            None => return Err(StoreError::Corrupt("account row vanished under its lock")),
        };
        self.head.state_version = from_db(state_version, "state_version")?;
        self.head.state_tag = super::state_tag(state_tag)?;
        let mark_target = match coverage {
            MarkCoverage::None => None,
            MarkCoverage::ChainHead => self.head.mark_target(false),
            MarkCoverage::ServingPosition => self.head.mark_target(true),
        };
        let counted = self.head.state_version != self.loaded.state_version;
        if counted {
            sqlx::query("DELETE FROM state_history WHERE account_id = $1 AND state_version < $2")
                .bind(&self.head.id)
                .bind(to_db(self.covered_version, "state_version")?)
                .execute(&mut *self.tx)
                .await
                .map_err(StoreError::from_db)?;
            // Keep the final slot for a commit that has a position to publish. A staged
            // receipt or sweep must leave room for the first identity delivery.
            const HISTORY_LIMIT: i64 = 1024;
            let limit = HISTORY_LIMIT - i64::from(mark_target.is_none());
            let inserted = sqlx::query(
                "INSERT INTO state_history (account_id, state_version, state_tag, creation_anchor) \
                 SELECT $1, $2, $3, $6 WHERE NOT EXISTS (SELECT 1 FROM state_history \
                 WHERE account_id = $1 AND state_version > $4 LIMIT 1 OFFSET $5)",
            )
            .bind(&self.head.id)
            .bind(state_version)
            .bind(self.head.state_tag.as_slice())
            .bind(to_db(self.covered_version, "state_version")?)
            .bind(limit - 1)
            .bind(
                self.creation_origin
                    .as_ref()
                    .map(|origin| origin.as_slice()),
            )
            .execute(&mut *self.tx)
            .await
            .map_err(StoreError::from_db)?;
            if inserted.rows_affected() == 0 {
                return Err(StoreError::Raced(
                    "the rollback mark must advance before another write",
                ));
            }
        }
        // A new seq or chain head is a change waiting readers care about; a stamped time
        // alone, which every request may move, isn't.
        if moved {
            self.changed = true;
        }
        if let Some((app_id, at_ms)) = self.last_seen {
            sqlx::query("UPDATE apps SET last_seen_ms = $3 WHERE account_id = $1 AND app_id = $2")
                .bind(&self.head.id)
                .bind(app_id.as_slice())
                .bind(to_db(at_ms, "last_seen_ms")?)
                .execute(&mut *self.tx)
                .await
                .map_err(StoreError::from_db)?;
        }
        let flag_hits = std::mem::take(&mut self.flag_hits);
        for sender in &flag_hits {
            sqlx::query(
                "INSERT INTO sender_flags (account_id, pubky, hits, last_hit_ms) \
                 VALUES ($1, $2, 1, $3) ON CONFLICT (account_id, pubky) DO UPDATE \
                 SET hits = sender_flags.hits + 1, last_hit_ms = $3",
            )
            .bind(&self.head.id)
            .bind(sender.as_slice())
            .bind(to_db(self.head.stamped_time_ms, "last_hit_ms")?)
            .execute(&mut *self.tx)
            .await
            .map_err(StoreError::from_db)?;
        }
        // At most `max_flags` flagged senders, the least frequent dropping, and of those
        // equally frequent the one hit longest ago (Switch wire 9.1).
        if !flag_hits.is_empty() {
            sqlx::query(
                "DELETE FROM sender_flags WHERE account_id = $1 AND pubky IN ( \
                     SELECT pubky FROM sender_flags WHERE account_id = $1 \
                     ORDER BY hits DESC, last_hit_ms DESC, pubky OFFSET $2)",
            )
            .bind(&self.head.id)
            .bind(to_db(self.max_flags, "max_flags")?)
            .execute(&mut *self.tx)
            .await
            .map_err(StoreError::from_db)?;
        }
        if self.changed {
            // Sent with the commit, and only if it commits.
            sqlx::query("SELECT pg_notify($1, $2)")
                .bind(crate::changes::CHANNEL)
                .bind(&self.head.id)
                .execute(&mut *self.tx)
                .await
                .map_err(StoreError::from_db)?;
        }
        self.tx.commit().await.map_err(StoreError::from_db)?;
        Ok(Committed {
            mark_target,
            head: self.head,
            counted,
        })
    }

    /// Erase the account (Switch wire 7.4.16): delete its row, and with it every row of its
    /// state, which all reference it with `ON DELETE CASCADE`; owe the deletion of its apps'
    /// push keys (Switch wire 8.1) in `erased_keys`, stamped `erased_at`; then commit. A
    /// request waiting on the account's changes wakes, and finds it gone. The push keys go
    /// after the commit: a key deleted first, by an erasure that then failed to commit, would
    /// leave a registration no key signs for.
    pub async fn erase(self, erased_at: u64) -> Result<(), ErasureFailure> {
        self.erase_with_outcome(erased_at, None, None).await
    }

    /// Delete and record the exact external attempt in the same commit.
    pub(crate) async fn erase_recorded(
        self,
        attempt: &crate::marks::ErasureAttempt,
        freshness: Option<&super::LockFreshness>,
    ) -> Result<(), ErasureFailure> {
        self.erase_with_outcome(attempt.erased_at_ms, Some(attempt), freshness)
            .await
    }

    async fn erase_with_outcome(
        mut self,
        erased_at: u64,
        attempt: Option<&crate::marks::ErasureAttempt>,
        freshness: Option<&super::LockFreshness>,
    ) -> Result<(), ErasureFailure> {
        let savepoint = self.savepoint().await.map_err(|error| ErasureFailure {
            error,
            account: None,
        })?;
        let deleted = async {
            super::erasure::require_fresh(freshness)?;
            self.delete_account(erased_at).await?;
            if let Some(attempt) = attempt {
                super::erasure::record(&mut self.tx, &self.head.id, attempt, true).await?;
                super::erasure::require_fresh(freshness)?;
            }
            Ok::<(), StoreError>(())
        }
        .await;
        if let Err(error) = deleted {
            let account = self
                .rollback_to(savepoint)
                .await
                .ok()
                .map(|()| Box::new(self));
            return Err(ErasureFailure { error, account });
        }
        self.tx.commit().await.map_err(|error| ErasureFailure {
            error: StoreError::from_db(error),
            account: None,
        })
    }

    /// Delete the account and owe its push keys, within the erasure's savepoint.
    async fn delete_account(&mut self, erased_at: u64) -> Result<(), StoreError> {
        sqlx::query(
            "INSERT INTO erased_keys (key_id, account_id, erased_at_ms) \
             SELECT push_key_id, account_id, $2 FROM push_registrations \
             WHERE account_id = $1 ON CONFLICT (key_id) DO NOTHING",
        )
        .bind(&self.head.id)
        .bind(to_db(erased_at, "erased_at_ms")?)
        .execute(&mut *self.tx)
        .await
        .map_err(StoreError::from_db)?;
        let deleted = sqlx::query("DELETE FROM accounts WHERE id = $1")
            .bind(&self.head.id)
            .execute(&mut *self.tx)
            .await
            .map_err(StoreError::from_db)?
            .rows_affected();
        if deleted != 1 {
            return Err(StoreError::Corrupt("account row vanished under its lock"));
        }
        sqlx::query("SELECT pg_notify($1, $2)")
            .bind(crate::changes::CHANNEL)
            .bind(&self.head.id)
            .execute(&mut *self.tx)
            .await
            .map_err(StoreError::from_db)?;
        Ok(())
    }

    /// Take `generation` as the account's position, its chain empty and no `seq` given out
    /// yet, as at a generation start: the next chain item is the new generation's first.
    /// What the store holds changes with the caller's own writes, in this transaction; a
    /// rollback to a savepoint before it undoes both.
    /// Update the transaction's head after writing an authorized recovery start. The
    /// activation requirement changes durably only with that same SQL commit.
    pub(super) fn start_recovery_head(&mut self, generation: u64) {
        self.start_head(generation);
        self.head.activation = AccountActivation::Ordinary;
    }

    pub(super) fn start_head(&mut self, generation: u64) {
        self.head.generation = generation;
        self.head.last_seq = 0;
        self.head.chain = None;
    }

    /// The account's position as this request loaded it, before its changes.
    pub fn loaded(&self) -> &AccountHead {
        &self.loaded
    }
}

/// The run that stamped the account row `row` (Switch wire 7.3, "Trusted time").
pub(super) fn stamped_by(row: &sqlx::postgres::PgRow) -> Result<[u8; 16], StoreError> {
    let stamped_by: Vec<u8> = row.try_get("stamped_by")?;
    <[u8; 16]>::try_from(stamped_by.as_slice()).map_err(|_| StoreError::Corrupt("stamped_by"))
}
