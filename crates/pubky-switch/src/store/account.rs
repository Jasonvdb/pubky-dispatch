//! The account and its transaction.
//!
//! An [`AccountTxn`] is one request's view of one account: it holds the account's lock from
//! [`Store::begin`](super::Store::begin) until it commits or is dropped. It hands out
//! `seq`s, moves the chain head and stamps the service time, and writes them back when it
//! commits. Dropping it without committing, or a process that dies before the commit,
//! rolls everything back.

use sqlx::{PgConnection, Postgres, Row, Transaction};

use super::{StoreError, from_db, to_db};
use pubky_switch_core::sig::SignedDoc;

use crate::keys::KeyId;

/// A new account, at enrollment (Switch wire 7.4.1).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NewAccount {
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
}

/// An account's position: its generation and key, the last `seq` given out, the chain head
/// and the stamped service time.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AccountHead {
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
    /// The last service time the account stamped.
    pub stamped_time_ms: u64,
    /// When the account was created.
    pub created_at_ms: u64,
}

impl AccountHead {
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

    /// The chain head, `None` before the first chain item: where the mark moves once it is
    /// durable (Switch wire 7.3, "Moving it").
    pub fn head_tip(&self) -> Option<pubky_switch_core::chain::ChainTip> {
        self.chain
            .map(|(seq, chain_hash)| pubky_switch_core::chain::ChainTip {
                generation: self.generation,
                seq,
                chain_hash,
            })
    }
}

/// A committed request: what it committed is durable, so an answer carrying a `seq`, a
/// proof or a head may go out once the mark has moved to its head (Switch wire 7.3 step 10).
/// Only [`AccountTxn::commit`] makes one.
#[derive(Debug)]
pub struct Committed {
    head: AccountHead,
}

impl Committed {
    /// The account's position as committed.
    pub fn head(&self) -> &AccountHead {
        &self.head
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
         stamped_time_ms, announced_limits, identity_doc) VALUES ($1, $2, $3, $4, $4, $5, $6) \
         ON CONFLICT (id) DO NOTHING",
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
    }))
}

impl Creation {
    /// Commit the account, at the creation time asked for, and let its identity's lock go.
    pub async fn commit(mut self) -> Result<(), StoreError> {
        let account = &self.account;
        let created_at_ms = account.created_at_ms;
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
            let listed = super::apps::newly_listed(None, &doc);
            super::apps::note_listings(&mut self.tx, &account.id, &listed, doc.data_epoch())
                .await?;
        }
        // The first enrollment's answer: an account keeps far fewer than any limit allows.
        super::enrollments::keep(
            &mut self.tx,
            &account.id,
            &account.enrollment_hash,
            created_at_ms,
            u64::MAX >> 1,
            true,
        )
        .await?;
        self.tx.commit().await.map_err(StoreError::from_db)?;
        Ok(())
    }
}

impl AccountTxn {
    /// Lock account `id` in `tx` and read its position.
    pub(super) async fn lock(
        mut tx: Transaction<'static, Postgres>,
        id: &str,
    ) -> Result<Option<Self>, StoreError> {
        let row = sqlx::query(
            "SELECT id, identity_key, generation, last_seq, chain_seq, chain_hash, \
             stamped_time_ms, created_at_ms FROM accounts WHERE id = $1 FOR UPDATE",
        )
        .bind(id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(StoreError::from_db)?;
        let Some(row) = row else {
            return Ok(None);
        };
        let identity_key: Vec<u8> = row.try_get("identity_key")?;
        let chain_seq: Option<i64> = row.try_get("chain_seq")?;
        let chain_hash: Option<Vec<u8>> = row.try_get("chain_hash")?;
        let chain = match (chain_seq, chain_hash) {
            (Some(seq), Some(hash)) => Some((
                from_db(seq, "chain_seq")?,
                <[u8; 32]>::try_from(hash.as_slice())
                    .map_err(|_| StoreError::Corrupt("chain_hash"))?,
            )),
            (None, None) => None,
            _ => return Err(StoreError::Corrupt("chain head")),
        };
        let head = AccountHead {
            id: row.try_get("id")?,
            identity_key: <[u8; 32]>::try_from(identity_key.as_slice())
                .map_err(|_| StoreError::Corrupt("identity_key"))?,
            generation: from_db(row.try_get("generation")?, "generation")?,
            last_seq: from_db(row.try_get("last_seq")?, "last_seq")?,
            chain,
            stamped_time_ms: from_db(row.try_get("stamped_time_ms")?, "stamped_time_ms")?,
            created_at_ms: from_db(row.try_get("created_at_ms")?, "created_at_ms")?,
        };
        Ok(Some(Self {
            tx,
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

    /// The account's position, with this request's changes.
    pub fn head(&self) -> &AccountHead {
        &self.head
    }

    /// Stamp the service time for this request: the time base, or the last time the account
    /// stamped if the time base is earlier, so service time never goes back for an
    /// identity (Switch spec 10.1, Switch wire 7.3 step 3). Kept only if the request commits.
    pub fn stamp(&mut self, base_ms: u64) -> u64 {
        self.head.stamped_time_ms = self.head.stamped_time_ms.max(base_ms);
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

    /// Undo everything written since `savepoint`, keeping the time this request stamped:
    /// a refused request commits its stamp and nothing else (Switch wire 7.3 steps 3 and
    /// 10). If this fails the transaction must not be committed.
    pub async fn rollback_to(&mut self, savepoint: Savepoint) -> Result<(), StoreError> {
        sqlx::query("ROLLBACK TO SAVEPOINT endpoint")
            .execute(&mut *self.tx)
            .await
            .map_err(StoreError::from_db)?;
        let stamped_time_ms = self.head.stamped_time_ms;
        self.head = AccountHead {
            stamped_time_ms,
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

    /// Commit the request. Once this returns, what it committed is durable; an answer that
    /// carries a head goes out once the mark has moved to it (Switch wire 7.3 step 10).
    pub async fn commit(mut self) -> Result<Committed, StoreError> {
        // The documents this request superseded go with it (Switch wire 7.5).
        self.drop_stale_documents().await?;
        if self.head != self.loaded {
            let chain_seq = self
                .head
                .chain
                .map(|(seq, _)| to_db(seq, "chain_seq"))
                .transpose()?;
            let chain_hash = self.head.chain.map(|(_, hash)| hash.to_vec());
            let updated = sqlx::query(
                "UPDATE accounts SET last_seq = $2, chain_seq = $3, chain_hash = $4, \
                 stamped_time_ms = $5 WHERE id = $1",
            )
            .bind(&self.head.id)
            .bind(to_db(self.head.last_seq, "last_seq")?)
            .bind(chain_seq)
            .bind(chain_hash)
            .bind(to_db(self.head.stamped_time_ms, "stamped_time_ms")?)
            .execute(&mut *self.tx)
            .await
            .map_err(StoreError::from_db)?
            .rows_affected();
            if updated != 1 {
                return Err(StoreError::Corrupt("account row vanished under its lock"));
            }
            // A new seq or chain head is a change waiting readers care about; a stamped
            // time alone, which every request may move, isn't.
            if self.head.last_seq != self.loaded.last_seq || self.head.chain != self.loaded.chain {
                self.changed = true;
            }
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
        Ok(Committed { head: self.head })
    }

    /// Erase the account (Switch wire 7.4.16): delete its row, and with it every row of its
    /// state, which all reference it with `ON DELETE CASCADE`; owe the deletion of its apps'
    /// push keys (Switch wire 8.1) in `erased_keys`, stamped `erased_at`; then commit. A
    /// request waiting on the account's changes wakes, and finds it gone. The push keys go
    /// after the commit: a key deleted first, by an erasure that then failed to commit, would
    /// leave a registration no key signs for.
    pub async fn erase(mut self, erased_at: u64) -> Result<(), ErasureFailure> {
        let savepoint = self.savepoint().await.map_err(|error| ErasureFailure {
            error,
            account: None,
        })?;
        if let Err(error) = self.delete_account(erased_at).await {
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
