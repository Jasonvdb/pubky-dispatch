//! Durable storage in PostgreSQL.
//!
//! **One account at a time.** Every request to an account runs in one database transaction
//! that first takes its identity's lock, then locks the account's row ([`Store::begin`]), so
//! one account's operations are serialized while other accounts proceed in parallel (Switch
//! spec 6.5). What a request changes commits all at once or not at all: a batch that fails,
//! or a process that dies before the commit, leaves no trace.
//!
//! **One identity at a time.** Everything that creates, takes over, deletes or re-keys an
//! identity's mark or account runs under the identity's lock ([`Store::lock_identity`]), a
//! transaction-level advisory lock on the identity, held until its transaction ends: an
//! enrollment from the mark's write through the account's insert, an erasure from its
//! record through the deletion's commit, and the deletion of a leftover mark. The order is
//! always the same: the identity's lock first, then the account's row, so two of them never
//! wait for each other (Switch wire 7.3, Table 3).
//!
//! **Durable, then answered** (Switch wire 7.3 step 10). A request's answer carries a `seq`,
//! a transition proof or a signed head only once [`AccountTxn::commit`] has returned, which
//! it does once PostgreSQL has made the commit durable. The service refuses to use a
//! database where commits may not be durable: `fsync` must be on and `synchronous_commit`
//! must not be `off`. With synchronous replicas, `synchronous_commit` should be `on` or
//! `remote_apply`, so a commit is durable on every replica that could be promoted; an
//! asynchronous replica must never be promoted to serve writes (Switch spec 6.5).
//!
//! **The account's mark** (Switch spec 6.5) lives beside the key store, apart from the
//! database and its backups ([`crate::marks`]): the service moves it once a commit is
//! durable, and judges every state against it (Switch wire 7.3, "Accounts and marks").

mod account;
mod allow;
mod apps;
mod chain;
mod claim_codec;
mod connect;
mod creation_anchor;
mod documents;
mod enrollments;
pub use enrollments::EnrollmentReceipt;
mod erasure;
mod feed;
mod handover;
pub mod heads;
mod identity;
mod inbox;
mod instance;
mod ops;
mod peers;
mod push;
mod push_queue;
mod records;
mod recovery;
mod retention;
mod snapshot;
mod sweeps;
#[cfg(any(test, feature = "test-util"))]
pub mod testing;

use std::{str::FromStr, time::Duration};

use serde::{Deserialize, Serialize};
use sqlx::{
    Connection, Executor, PgConnection, PgPool, Row,
    postgres::{PgConnectOptions, PgPoolOptions},
};

pub(crate) use account::MarkCoverage;
pub use account::{
    AccountHead, AccountTxn, Committed, Creation, ErasureFailure, NewAccount, Savepoint,
    ServiceRun, committed_time_ms,
};
pub use allow::{AllowEntry, AllowInvite};
pub use apps::{AppsView, KeptAppId, KeptReason, OpenAttempt, PartSpan, newly_listed};
pub use chain::NewChainItem;
pub use connect::ConnectRequest;
pub use feed::{AppDocs, CurrentDocs, FeedRow, FeedSnapshot, PageReader};
pub use handover::StoredHandover;
pub use identity::HeldIdentity;
pub use inbox::{InboxItem, InboxUsage, NewEntry, StoredEntry};
pub use instance::{InstanceLock, InstanceLockLost, LockFreshness, LockTiming};
pub use ops::{
    DivergentUpload, ListName, RecordOrigin, StoredApp, StoredBundlePart, StoredClaimEntry,
    StoredInvite, StoredListEntry, StoredRecord,
};
pub use peers::{HeldPeer, PeerFloor};
pub use push::{OwedKey, PushRegistration};
pub use push_queue::{
    HOLD_LOCK_TIMEOUT_MS, HeldRegistration, PUSH_LEASE_MS, PUSH_PER_ACCOUNT, PUSH_PER_HOST,
    PUSH_RETRY_MS, PUSH_WINDOW_MS, QueuedPush,
};
pub use recovery::{RECOVERY_KEEPS, Recovery, recovery_clears};
pub use retention::{ChainRetention, KeptStub};
pub use snapshot::SnapshotRead;

use crate::admin::{CheckFuture, ReadinessCheck};

/// The environment variable that overrides `database.url`.
pub const DATABASE_URL_ENV: &str = "PUBKY_SWITCH_DATABASE_URL";

/// A key store entry an erasure still owes deleting (Switch wire 7.4.16).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ErasedKey {
    /// The key's ID in the key store.
    pub key: crate::keys::KeyId,
    /// The account that let it go.
    pub account: String,
    /// When it was let go, in the account's service time.
    pub erased_at_ms: u64,
}

/// The schema migrations, applied in order.
pub static MIGRATIONS: sqlx::migrate::Migrator = sqlx::migrate!("./migrations");

/// The database settings.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct DatabaseConfig {
    /// The PostgreSQL connection URL. `PUBKY_SWITCH_DATABASE_URL` overrides it; prefer the
    /// variable, so the password stays out of the file.
    pub url: Option<String>,
    /// Most connections in the pool.
    pub max_connections: u32,
    /// How long a request waits for a free connection.
    pub acquire_timeout_ms: u64,
    /// How long a request waits for its account's lock before it gives up with
    /// `503 unavailable`.
    pub lock_timeout_ms: u64,
    /// Apply pending schema migrations at start.
    pub migrate_on_start: bool,
    /// Most reads at once that run after the account's lock on a snapshot of the state
    /// under it (`GET /allow`), each on a connection of its own, on top
    /// of `max_connections`. A request waits for one before it takes the lock.
    pub snapshot_readers: u32,
    /// How long the service keeps trying to reach the database at start, while it refuses
    /// connections or is still starting up, before it gives up and exits.
    pub connect_retry_ms: u64,
}

impl Default for DatabaseConfig {
    fn default() -> Self {
        Self {
            url: None,
            max_connections: 16,
            acquire_timeout_ms: 5_000,
            lock_timeout_ms: 10_000,
            migrate_on_start: true,
            snapshot_readers: 4,
            connect_retry_ms: 30_000,
        }
    }
}

impl std::fmt::Debug for DatabaseConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DatabaseConfig")
            .field("url", &self.url.as_ref().map(|_| "[redacted]"))
            .field("max_connections", &self.max_connections)
            .field("acquire_timeout_ms", &self.acquire_timeout_ms)
            .field("lock_timeout_ms", &self.lock_timeout_ms)
            .field("migrate_on_start", &self.migrate_on_start)
            .field("snapshot_readers", &self.snapshot_readers)
            .field("connect_retry_ms", &self.connect_retry_ms)
            .finish()
    }
}

/// A database setting that breaks a rule.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[error("database.{name}: {reason}")]
pub struct DatabaseConfigError {
    /// The setting's name.
    pub name: &'static str,
    /// What is wrong with it.
    pub reason: &'static str,
}

impl DatabaseConfig {
    /// Check the settings.
    pub fn validate(&self) -> Result<(), DatabaseConfigError> {
        let fail = |name, reason| Err(DatabaseConfigError { name, reason });
        if self.max_connections == 0 {
            return fail("max_connections", "must be at least 1");
        }
        if self.acquire_timeout_ms == 0 {
            return fail("acquire_timeout_ms", "must be at least 1");
        }
        if self.lock_timeout_ms == 0 {
            return fail("lock_timeout_ms", "must be at least 1");
        }
        if self.snapshot_readers == 0 {
            return fail("snapshot_readers", "must be at least 1");
        }
        if let Some(url) = &self.url
            && (!(url.starts_with("postgres://") || url.starts_with("postgresql://"))
                || PgConnectOptions::from_str(url).is_err())
        {
            return fail("url", "not a PostgreSQL connection URL");
        }
        Ok(())
    }

    /// The URL to connect to: `PUBKY_SWITCH_DATABASE_URL`, or `url`.
    pub fn effective_url(&self) -> Option<String> {
        std::env::var(DATABASE_URL_ENV)
            .ok()
            .filter(|url| !url.is_empty())
            .or_else(|| self.url.clone())
    }
}

/// What the store can fail at.
#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    /// The database failed, or a statement was refused.
    #[error("database: {0}")]
    Database(#[from] sqlx::Error),
    /// A schema migration failed.
    #[error("migration: {0}")]
    Migrate(#[from] sqlx::migrate::MigrateError),
    /// The database may acknowledge a commit before it is durable.
    #[error("the database doesn't make commits durable: {0}")]
    NotDurable(String),
    /// The account's lock wasn't free within `lock_timeout_ms`.
    #[error("the account is busy")]
    LockTimeout,
    /// A concurrent change took what the request relied on; a retry finds the new state.
    #[error("raced: {0}")]
    Raced(&'static str),
    /// A value doesn't fit what the database stores, or the reverse.
    #[error("value out of range: {0}")]
    OutOfRange(&'static str),
    /// A stored value breaks an invariant.
    #[error("corrupt account state: {0}")]
    Corrupt(&'static str),
    /// No database URL is configured.
    #[error("no database URL: set database.url or {DATABASE_URL_ENV}")]
    NoUrl,
    /// No try at the instance lock got an answer within its wait
    /// ([`Store::hold_instance_lock`]).
    #[error("the database didn't answer a take of the instance lock in time")]
    LockUnanswered,
    /// Another process serves this database ([`Store::hold_instance_lock`]): the session
    /// that holds its lock.
    #[error("another process serves this database: {0}")]
    InUse(String),
}

/// PostgreSQL's code for a lock that wasn't free within `lock_timeout`.
const LOCK_NOT_AVAILABLE: &str = "55P03";

/// Whether an answer of `ERROR` severity (`error`) with SQLSTATE `code` proves nothing was
/// committed ([`StoreError::is_refused`]): not a connection's failure (class `08`), an
/// operator's intervention such as a shutdown (`57`), a system error (`58`) or an internal
/// one (`XX`).
fn refused_answer(error: bool, code: &str) -> bool {
    error
        && code != "40003"
        && !["08", "57", "58", "XX"]
            .iter()
            .any(|class| code.starts_with(class))
}

impl StoreError {
    /// Whether the database refused what failed, so it is known not to have committed: an
    /// `ERROR` of the statement or the commit itself (a constraint, a deferred trigger, a
    /// serialization failure, a lock timeout). Anything else may follow a commit that landed:
    /// a lost connection, a protocol failure, and the answers a server or a pooler between
    /// it and the service gives when a connection breaks or the server stops (`FATAL` or
    /// `PANIC`, and SQLSTATE classes `08`, `57`, `58` and `XX`: PgBouncer answers `08P01`
    /// for a server connection it lost, perhaps after the commit).
    pub fn is_refused(&self) -> bool {
        match self {
            Self::LockTimeout => true,
            Self::Database(sqlx::Error::Database(db)) => db
                .try_downcast_ref::<sqlx::postgres::PgDatabaseError>()
                .is_some_and(|pg| {
                    refused_answer(
                        matches!(pg.severity(), sqlx::postgres::PgSeverity::Error),
                        pg.code(),
                    )
                }),
            _ => false,
        }
    }

    /// Map a database error, telling a lock timeout apart.
    pub(crate) fn from_db(error: sqlx::Error) -> Self {
        match &error {
            sqlx::Error::Database(db) if db.code().as_deref() == Some(LOCK_NOT_AVAILABLE) => {
                Self::LockTimeout
            }
            _ => Self::Database(error),
        }
    }
}

/// The durability settings of a database connection.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DurabilitySettings {
    /// `fsync`.
    pub fsync: String,
    /// `synchronous_commit`.
    pub synchronous_commit: String,
    /// `synchronous_standby_names`.
    pub synchronous_standby_names: String,
}

impl DurabilitySettings {
    /// Read the settings in force on `conn`.
    pub async fn read(conn: &mut PgConnection) -> Result<Self, sqlx::Error> {
        let row = sqlx::query(
            "SELECT current_setting('fsync'), current_setting('synchronous_commit'), \
             current_setting('synchronous_standby_names')",
        )
        .fetch_one(conn)
        .await?;
        Ok(Self {
            fsync: row.try_get(0)?,
            synchronous_commit: row.try_get(1)?,
            synchronous_standby_names: row.try_get(2)?,
        })
    }

    /// Refuse settings under which a commit can return before it is durable.
    pub fn check(&self) -> Result<(), String> {
        if self.fsync != "on" {
            return Err(format!("fsync is {}", self.fsync));
        }
        if self.synchronous_commit == "off" {
            return Err("synchronous_commit is off".into());
        }
        Ok(())
    }

    /// Settings that are durable on this server but may not be on a synchronous replica:
    /// `local` or `remote_write` with synchronous standbys configured.
    pub fn replica_warning(&self) -> Option<String> {
        let weak = matches!(self.synchronous_commit.as_str(), "local" | "remote_write");
        (weak && !self.synchronous_standby_names.is_empty()).then(|| {
            format!(
                "synchronous_commit is {} with synchronous standbys: a commit may not be \
                 durable on a replica that could be promoted",
                self.synchronous_commit
            )
        })
    }
}

/// The service's database.
#[derive(Clone, Debug)]
pub struct Store {
    pool: PgPool,
    /// The connections reads after the lock use, apart from `pool`, so a request holding
    /// an account's lock never waits for one (`snapshot_readers`).
    readers: PgPool,
    /// The accounts with a read after the lock in flight: one each.
    reading: snapshot::Reading,
    lock_timeout_ms: u64,
    /// For tests: the next read after the lock waits here ([`testing::SnapshotPause`]).
    #[cfg(any(test, feature = "test-util"))]
    pub(crate) snapshot_pause: std::sync::Arc<std::sync::Mutex<Option<testing::SnapshotPause>>>,
}

impl Store {
    /// Connect with `config`. Every connection is checked for durable commits before use.
    pub async fn connect(config: &DatabaseConfig) -> Result<Self, StoreError> {
        let url = config.effective_url().ok_or(StoreError::NoUrl)?;
        let options = PgConnectOptions::from_str(&url)?;
        Self::connect_with(options, config).await
    }

    /// Connect to `options` with the pool settings of `config`.
    pub async fn connect_with(
        options: PgConnectOptions,
        config: &DatabaseConfig,
    ) -> Result<Self, StoreError> {
        // Check once on a connection of its own, so a database that would acknowledge
        // commits before they are durable is refused at start with the reason. The pool
        // checks every later connection too, in case the settings change.
        let mut first = connect_first(&options, config.connect_retry_ms).await?;
        let settings = DurabilitySettings::read(&mut first).await?;
        settings.check().map_err(StoreError::NotDurable)?;
        if let Some(warning) = settings.replica_warning() {
            tracing::warn!(%warning, "database durability");
        }
        first.close().await?;
        let pool = PgPoolOptions::new()
            .max_connections(config.max_connections)
            .acquire_timeout(Duration::from_millis(config.acquire_timeout_ms))
            .after_connect(|conn, _meta| {
                Box::pin(async move {
                    let settings = DurabilitySettings::read(conn).await?;
                    settings.check().map_err(|reason| {
                        sqlx::Error::Configuration(StoreError::NotDurable(reason).into())
                    })?;
                    // READ COMMITTED whatever the database's default: a statement that waits
                    // for a lock then reads what the holder committed, where a snapshot taken
                    // before the wait would fail the request instead (Switch spec 6.5, order
                    // per account).
                    conn.execute("SET default_transaction_isolation = 'read committed'")
                        .await?;
                    Ok(())
                })
            })
            .connect_with(options.clone())
            .await?;
        // Read only, so their commits need no durability check.
        let readers = PgPoolOptions::new()
            .max_connections(config.snapshot_readers)
            .acquire_timeout(Duration::from_millis(config.acquire_timeout_ms))
            .connect_lazy_with(options);
        Ok(Self {
            pool,
            readers,
            reading: snapshot::Reading::default(),
            lock_timeout_ms: config.lock_timeout_ms,
            #[cfg(any(test, feature = "test-util"))]
            snapshot_pause: std::sync::Arc::default(),
        })
    }

    /// Apply pending schema migrations. Safe to run from several processes at once.
    pub async fn migrate(&self) -> Result<(), StoreError> {
        let mut conn = self.pool.acquire().await.map_err(StoreError::from_db)?;
        if let Err(error) = MIGRATIONS.run(&mut *conn).await {
            // A failed run keeps the migrator's lock on its connection: close it rather
            // than hand it back to the pool.
            let _ = conn.detach().close().await;
            return Err(error.into());
        }
        Ok(())
    }

    /// Take `id`'s identity lock (the module's "One identity at a time"): a transaction
    /// holding a transaction-level advisory lock on the identity until it ends. Waits at most
    /// `lock_timeout_ms` for a request, an enrollment or an erasure of the identity that
    /// holds it ([`StoreError::LockTimeout`]). The transaction is marked as one holding an
    /// identity's lock, the only kind the schema's count trigger lets write an account's
    /// state, so every such write is counted with its account's commit (Switch wire 7.3,
    /// "The state").
    pub async fn lock_identity(&self, id: &str) -> Result<IdentityLock, StoreError> {
        let mut tx = self.pool.begin().await.map_err(StoreError::from_db)?;
        // READ COMMITTED whatever the pool's default, so what is read under the lock includes
        // everything committed before it was taken. `SET` takes no bind parameters; the
        // values are numbers we format.
        tx.execute(
            format!(
                "SET TRANSACTION ISOLATION LEVEL READ COMMITTED; \
                 SET LOCAL lock_timeout = {}; \
                 SELECT pg_advisory_xact_lock({}); \
                 SELECT set_config('switch.locked', 'on', true)",
                self.lock_timeout_ms,
                identity_lock_key(id)
            )
            .as_str(),
        )
        .await
        .map_err(StoreError::from_db)?;
        Ok(IdentityLock {
            tx,
            id: id.to_string(),
        })
    }

    /// For tests: create an account; `false`, changing nothing, when one exists. The
    /// service creates through [`IdentityLock::create`], once the mark is written.
    #[cfg(any(test, feature = "test-util"))]
    pub async fn create_account(&self, account: &NewAccount) -> Result<bool, StoreError> {
        match self
            .lock_identity(&account.id)
            .await?
            .create(account)
            .await?
        {
            Some(creation) => creation.commit().await.map(|()| true),
            None => Ok(false),
        }
    }

    /// The push keys owed deleting, oldest first (Switch wire 8.1).
    pub async fn erased_keys(&self) -> Result<Vec<ErasedKey>, StoreError> {
        let rows = sqlx::query(
            "SELECT key_id, account_id, erased_at_ms FROM erased_keys \
             ORDER BY erased_at_ms, key_id",
        )
        .fetch_all(&self.pool)
        .await
        .map_err(StoreError::from_db)?;
        rows.iter()
            .map(|row| {
                let key: String = row.try_get("key_id")?;
                Ok(ErasedKey {
                    key: crate::keys::KeyId::parse(&key)
                        .map_err(|_| StoreError::Corrupt("erased_keys.key_id"))?,
                    account: row.try_get("account_id")?,
                    erased_at_ms: from_db(row.try_get("erased_at_ms")?, "erased_at_ms")?,
                })
            })
            .collect()
    }

    /// Look account `id` up without taking its lock: what the verdict of its account and
    /// mark reads (Switch wire 7.3 step 2) and the service time it last committed, for the
    /// checks that come before the lock (Switch wire 7.2 Order).
    pub async fn lookup(&self, id: &str) -> Result<Option<FoundAccount>, StoreError> {
        Self::lookup_with(&self.pool, id).await
    }

    pub(crate) async fn lookup_with<'a>(
        reader: impl sqlx::PgExecutor<'a>,
        id: &str,
    ) -> Result<Option<FoundAccount>, StoreError> {
        let row = sqlx::query(
            "SELECT generation, chain_seq, chain_hash, state_version, state_tag, stamped_time_ms, \
             stamped_by, created_at_ms, identity_doc, activation_requirement FROM accounts WHERE id = $1",
        )
        .bind(id)
        .fetch_optional(reader)
        .await
        .map_err(StoreError::from_db)?;
        let Some(row) = row else {
            return Ok(None);
        };
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
        let doc: Option<Vec<u8>> = row.try_get("identity_doc")?;
        Ok(Some(FoundAccount {
            activation: pubky_switch_core::records::AccountActivation::parse(
                row.try_get("activation_requirement")?,
            )
            .map_err(|_| StoreError::Corrupt("activation_requirement"))?,
            generation: from_db(row.try_get("generation")?, "generation")?,
            chain,
            state_version: from_db(row.try_get("state_version")?, "state_version")?,
            state_tag: state_tag(row.try_get("state_tag")?)?,
            stamped_time_ms: from_db(row.try_get("stamped_time_ms")?, "stamped_time_ms")?,
            stamped_by: account::stamped_by(&row)?,
            created_at_ms: from_db(row.try_get("created_at_ms")?, "created_at_ms")?,
            identity_doc: doc
                .map(|doc| identity::decode_doc(&doc, "identity_doc"))
                .transpose()?,
        }))
    }

    /// The chain hash of the stub account `id` still holds at `generation` and `seq`, if it
    /// holds one: where it does, a state past the mark with another hash there is a fork
    /// (Switch wire 7.3, Table 1).
    pub async fn stub_hash_at(
        &self,
        id: &str,
        generation: u64,
        seq: u64,
    ) -> Result<Option<[u8; 32]>, StoreError> {
        let hash: Option<Vec<u8>> = sqlx::query_scalar(
            "SELECT chain_hash FROM chain_items WHERE account_id = $1 AND generation = $2 \
             AND seq = $3",
        )
        .bind(id)
        .bind(to_db(generation, "generation")?)
        .bind(to_db(seq, "seq")?)
        .fetch_optional(&self.pool)
        .await
        .map_err(StoreError::from_db)?;
        hash.map(|hash| {
            <[u8; 32]>::try_from(hash.as_slice()).map_err(|_| StoreError::Corrupt("chain_hash"))
        })
        .transpose()
    }

    /// Of `erased`, identities with the time of an erasure's record the mark store holds,
    /// those whose account here was created at or before that time: accounts a database
    /// restored from a backup brought back, to erase again before they serve (Switch spec
    /// 6.5). An account created after its identity's erasure is a new one and isn't listed.
    pub async fn restored_erased(
        &self,
        erased: &[(String, u64)],
    ) -> Result<Vec<(String, u64)>, StoreError> {
        let mut ids = Vec::with_capacity(erased.len());
        let mut times = Vec::with_capacity(erased.len());
        for (id, at) in erased {
            ids.push(id.clone());
            times.push(to_db(*at, "erased_at_ms")?);
        }
        let rows = sqlx::query(
            "SELECT a.id, e.erased_at_ms FROM accounts a \
             JOIN unnest($1::TEXT[], $2::BIGINT[]) AS e(id, erased_at_ms) ON e.id = a.id \
             WHERE a.created_at_ms <= e.erased_at_ms ORDER BY a.id",
        )
        .bind(&ids)
        .bind(&times)
        .fetch_all(&self.pool)
        .await
        .map_err(StoreError::from_db)?;
        rows.iter()
            .map(|row| {
                Ok((
                    row.try_get("id")?,
                    from_db(row.try_get("erased_at_ms")?, "erased_at_ms")?,
                ))
            })
            .collect()
    }

    /// The app row account `id` holds for `app_id`, read without the account's lock, for
    /// the checks of an own app's request before it (Switch wire 7.2 Order). A plain read
    /// doesn't wait for the lock; the endpoint checks again under it.
    pub async fn app_row(
        &self,
        id: &str,
        app_id: &[u8; 16],
    ) -> Result<Option<StoredApp>, StoreError> {
        ops::app_row(&self.pool, id, app_id).await
    }

    /// What an own app's checks before the lock read, in one statement: account `id`'s
    /// newest `identity.json`, the row of `app_id`, and whether it is kept for good (Switch
    /// wire 7.2 Order). `None` for an account that isn't there.
    pub async fn own_app_view(
        &self,
        id: &str,
        app_id: &[u8; 16],
    ) -> Result<
        Option<(
            Option<pubky_switch_core::sig::SignedDoc>,
            Option<StoredApp>,
            bool,
        )>,
        StoreError,
    > {
        ops::own_app_view(&self.pool, id, app_id).await
    }

    /// The first `steps` entries of claim `claim_key` at account `id`, by step, read without
    /// the account's lock (Switch wire 7.4.8): entries never change once written.
    pub async fn claim_entries_before(
        &self,
        id: &str,
        claim_key: &[u8; 32],
        steps: u64,
    ) -> Result<Vec<StoredClaimEntry>, StoreError> {
        ops::claim_entries_before(&self.pool, id, claim_key, steps).await
    }

    /// Read a feed page of account `id` from one snapshot, without the account's lock
    /// (Switch wire 7.4.4): the sequence, then the chain items after `after`, up to
    /// `positions` positions on and `batch_tail` more to finish a batch, each given to
    /// `take`, which answers whether the page wants the next. `None` for an account that
    /// isn't there.
    #[allow(clippy::too_many_arguments)]
    pub async fn read_feed(
        &self,
        id: &str,
        reader: &[u8; 16],
        after: Option<pubky_switch_core::ops::Position>,
        positions: u64,
        batch_tail: u64,
        page: &mut impl PageReader,
    ) -> Result<Option<FeedSnapshot>, StoreError> {
        feed::read_feed(&self.pool, id, reader, after, positions, batch_tail, page).await
    }

    /// Start a request to account `id`: a transaction holding the identity's lock and the
    /// account's, in that order, until it commits or is dropped. `None` when there is no
    /// such account. Waits at most `lock_timeout_ms` for each lock
    /// ([`StoreError::LockTimeout`]).
    pub async fn begin(&self, id: &str) -> Result<Option<AccountTxn>, StoreError> {
        self.lock_identity(id).await?.account().await
    }

    /// [`Store::begin`], with a transaction on the reader pool begun first, before the lock
    /// is waited for, so the request waits for a free reader without holding the lock;
    /// [`AccountTxn::snapshot_read`] hands it the locked transaction's snapshot.
    ///
    /// One such read of an account runs at a time in this process; the next ones wait for
    /// their turn in order, before they take a reader and holding no connection, at most
    /// `lock_timeout_ms` ([`StoreError::LockTimeout`] after it, and at once past 8
    /// waiting). So the readers every account shares can't all be held by one account's
    /// reads. The read is `app`'s, an own app whose request signature verified with the key
    /// the account holds for it; whether it may make the read is judged under the lock.
    /// Each app holds at most one place in its account's queue: a second read of the same
    /// app while its first holds or waits for one is refused at once, so no one app, however
    /// many requests it sends, can keep the other apps' reads waiting past one place.
    pub async fn begin_reading(
        &self,
        id: &str,
        app: [u8; 16],
    ) -> Result<Option<AccountTxn>, StoreError> {
        let wait = Duration::from_millis(self.lock_timeout_ms);
        let turn = snapshot::ReadTurn::wait(&self.reading, id, app, wait).await?;
        let reader = self.readers.begin().await.map_err(StoreError::from_db)?;
        let Some(mut txn) = self.begin(id).await? else {
            return Ok(None);
        };
        txn.reader = Some(reader);
        txn.read_turn = Some(turn);
        txn.import_timeout_ms = self.lock_timeout_ms;
        #[cfg(any(test, feature = "test-util"))]
        {
            txn.snapshot_pause = self
                .snapshot_pause
                .lock()
                .map_err(|_| StoreError::Corrupt("a test pause"))?
                .take();
        }
        Ok(Some(txn))
    }

    /// The connection pool, for the store's own modules.
    pub(crate) fn pool(&self) -> &PgPool {
        &self.pool
    }

    /// The most connections the request pool holds (`database.max_connections`).
    pub fn max_connections(&self) -> u32 {
        self.pool.options().get_max_connections()
    }

    /// Close every connection.
    pub async fn close(&self) {
        self.pool.close().await;
        self.readers.close().await;
    }
}

/// PostgreSQL's code for a server that is starting up or shutting down.
const CANNOT_CONNECT_NOW: &str = "57P03";

/// Whether a failed connection may succeed if tried again: a server not listening yet, or
/// one still starting up. Refused credentials and other errors aren't retried.
fn retryable(error: &sqlx::Error) -> bool {
    match error {
        sqlx::Error::Io(_) | sqlx::Error::PoolTimedOut => true,
        sqlx::Error::Database(db) => db.code().as_deref() == Some(CANNOT_CONNECT_NOW),
        _ => false,
    }
}

/// Open the first connection, trying again while the database isn't up yet, for at most
/// `retry_ms`. A database started at the same time as the service, by an orchestrator or a
/// container runtime, is often not listening for its first second or two.
async fn connect_first(
    options: &PgConnectOptions,
    retry_ms: u64,
) -> Result<PgConnection, StoreError> {
    let deadline = tokio::time::Instant::now() + Duration::from_millis(retry_ms);
    let mut backoff = Duration::from_millis(100);
    loop {
        match PgConnection::connect_with(options).await {
            Ok(conn) => return Ok(conn),
            Err(error) if retryable(&error) && tokio::time::Instant::now() < deadline => {
                tracing::warn!(%error, "the database isn't reachable yet; trying again");
                let left = deadline.saturating_duration_since(tokio::time::Instant::now());
                tokio::time::sleep(backoff.min(left)).await;
                backoff = (backoff * 2).min(Duration::from_secs(2));
            }
            Err(error) => return Err(error.into()),
        }
    }
}

/// An account found by [`Store::lookup`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FoundAccount {
    /// The persisted activation requirement of the selected account lifetime.
    pub activation: pubky_switch_core::records::AccountActivation,
    /// The generation it holds.
    pub generation: u64,
    /// Its newest chain item's `seq` and the chain hash there; `None` before the first.
    pub chain: Option<(u64, [u8; 32])>,
    /// Its count of changed commits (Switch wire 7.3, "The state").
    pub state_version: u64,
    /// The tag written with the count's last move (Switch wire 7.3, "The state").
    pub state_tag: [u8; 16],
    /// The service time it last committed.
    pub stamped_time_ms: u64,
    /// The run of the service that stamped it (Switch wire 7.3, "Trusted time").
    pub stamped_by: [u8; 16],
    /// When it was created, in service time.
    pub created_at_ms: u64,
    /// The newest `identity.json` it holds, as signed; it was verified when it was taken.
    pub identity_doc: Option<pubky_switch_core::sig::SignedDoc>,
}

impl FoundAccount {
    /// The last time the service committed for it in `run`, under the mark's time floor
    /// `mark_floor_ms` ([`committed_time_ms`]).
    pub fn committed_ms(&self, run: ServiceRun, mark_floor_ms: Option<u64>) -> u64 {
        committed_time_ms(self.stamped_time_ms, &self.stamped_by, run, mark_floor_ms)
    }
}

/// The readiness check of the database: a round trip on a pooled connection.
#[derive(Clone, Debug)]
pub struct StoreReadiness(pub Store);

/// The advisory lock key of `id`'s identity lock: the hash of a label of its own and the
/// identity, apart from every other advisory lock of the service.
fn identity_lock_key(id: &str) -> i64 {
    let mut input = b"pubky-switch/identity-lock/".to_vec();
    input.extend_from_slice(id.as_bytes());
    let digest = pubky_switch_core::enc::hash(&input);
    let mut bytes = [0u8; 8];
    bytes.copy_from_slice(&digest[..8]);
    i64::from_be_bytes(bytes)
}

/// An identity's lock ([`Store::lock_identity`]): held until it is dropped, committed, or
/// handed to the account's transaction or a creation, which hold it on.
pub struct IdentityLock {
    tx: sqlx::Transaction<'static, sqlx::Postgres>,
    id: String,
}

impl std::fmt::Debug for IdentityLock {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IdentityLock")
            .field("id", &self.id)
            .finish_non_exhaustive()
    }
}

impl IdentityLock {
    pub(crate) fn conn(&mut self) -> &mut PgConnection {
        &mut self.tx
    }

    /// Lock the identity's account's row too, the lock held on in the account's
    /// transaction; `None`, letting the identity's lock go, when there is no account.
    pub async fn account(self) -> Result<Option<AccountTxn>, StoreError> {
        AccountTxn::lock(self.tx, &self.id).await
    }

    /// Whether the identity has an account, read under the lock.
    pub async fn has_account(&mut self) -> Result<bool, StoreError> {
        let found: Option<i32> = sqlx::query_scalar("SELECT 1 FROM accounts WHERE id = $1")
            .bind(&self.id)
            .fetch_optional(&mut *self.tx)
            .await
            .map_err(StoreError::from_db)?;
        Ok(found.is_some())
    }

    /// The creation time of the identity's account, read under the lock; `None` without an
    /// account.
    pub async fn account_created_at(&mut self) -> Result<Option<u64>, StoreError> {
        let found: Option<i64> =
            sqlx::query_scalar("SELECT created_at_ms FROM accounts WHERE id = $1")
                .bind(&self.id)
                .fetch_optional(&mut *self.tx)
                .await
                .map_err(StoreError::from_db)?;
        found.map(|at| from_db(at, "created_at_ms")).transpose()
    }

    /// Insert `account`, the identity's, the lock held on until [`Creation::commit`]: `None`,
    /// changing nothing and letting the lock go, when one exists.
    pub async fn create(self, account: &NewAccount) -> Result<Option<Creation>, StoreError> {
        if account.id != self.id {
            return Err(StoreError::Corrupt(
                "an account created under another identity's lock",
            ));
        }
        account::create(self.tx, account).await
    }
}

impl ReadinessCheck for StoreReadiness {
    fn name(&self) -> &str {
        "database"
    }

    fn check(&self) -> CheckFuture<'_> {
        Box::pin(async move {
            let mut conn = self
                .0
                .pool()
                .acquire()
                .await
                .map_err(|_| "no database connection".to_string())?;
            conn.ping()
                .await
                .map_err(|_| "the database doesn't answer".to_string())
        })
    }
}

/// Convert a `u64` to the `BIGINT` the database stores.
pub(crate) fn to_db(value: u64, what: &'static str) -> Result<i64, StoreError> {
    i64::try_from(value).map_err(|_| StoreError::OutOfRange(what))
}

/// Read a stored count's tag (Switch wire 7.3, "The state").
pub(crate) fn state_tag(value: Vec<u8>) -> Result<[u8; 16], StoreError> {
    <[u8; 16]>::try_from(value.as_slice()).map_err(|_| StoreError::Corrupt("state_tag"))
}

/// Convert a stored `BIGINT` back to a `u64`.
pub(crate) fn from_db(value: i64, what: &'static str) -> Result<u64, StoreError> {
    u64::try_from(value).map_err(|_| StoreError::Corrupt(what))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn settings(fsync: &str, commit: &str, standbys: &str) -> DurabilitySettings {
        DurabilitySettings {
            fsync: fsync.into(),
            synchronous_commit: commit.into(),
            synchronous_standby_names: standbys.into(),
        }
    }

    #[test]
    fn test_store_refused_answer_only_an_error_of_the_statement() {
        // A constraint, a deferred trigger at the commit, a serialization failure: nothing
        // committed.
        for code in ["23505", "P0001", "40001", "55P03"] {
            assert!(refused_answer(true, code), "{code}");
        }
        // A lost connection, as PgBouncer answers one (`08P01`), a shutdown or an internal
        // error may follow a commit that landed, and so may a `FATAL` of any class.
        for code in [
            "08P01", "08006", "40003", "57P01", "57014", "58030", "XX000",
        ] {
            assert!(!refused_answer(true, code), "{code}");
        }
        assert!(!refused_answer(false, "23505"));
    }

    #[test]
    fn test_durability_settings_check() {
        assert_eq!(settings("on", "on", "").check(), Ok(()));
        assert_eq!(settings("on", "remote_apply", "s1").check(), Ok(()));
        assert_eq!(settings("on", "local", "").check(), Ok(()));
        assert!(settings("off", "on", "").check().is_err());
        assert!(settings("on", "off", "").check().is_err());
    }

    #[test]
    fn test_durability_settings_replica_warning() {
        assert_eq!(settings("on", "on", "s1").replica_warning(), None);
        assert_eq!(settings("on", "remote_write", "").replica_warning(), None);
        assert!(
            settings("on", "remote_write", "s1")
                .replica_warning()
                .is_some()
        );
        assert!(
            settings("on", "local", "ANY 1 (s1)")
                .replica_warning()
                .is_some()
        );
    }

    #[test]
    fn test_database_config_validation() {
        assert_eq!(DatabaseConfig::default().validate(), Ok(()));
        let bad_url = DatabaseConfig {
            url: Some("mysql://x".into()),
            ..DatabaseConfig::default()
        };
        assert_eq!(bad_url.validate().expect_err("url").name, "url");
        let no_pool = DatabaseConfig {
            max_connections: 0,
            ..DatabaseConfig::default()
        };
        assert_eq!(
            no_pool.validate().expect_err("pool").name,
            "max_connections"
        );
    }

    #[tokio::test]
    async fn test_store_connect_retries_then_gives_up() {
        // A port nothing listens on: refused at once, so every attempt is retried until the
        // bound, and then the error is returned.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = listener.local_addr().expect("addr").port();
        drop(listener);
        let options = PgConnectOptions::new().host("127.0.0.1").port(port);
        let started = std::time::Instant::now();
        let error = connect_first(&options, 400)
            .await
            .expect_err("nothing listens");
        let elapsed = started.elapsed();
        assert!(
            matches!(error, StoreError::Database(sqlx::Error::Io(_))),
            "{error:?}"
        );
        assert!(elapsed >= Duration::from_millis(400), "{elapsed:?}");
        assert!(elapsed < Duration::from_secs(5), "{elapsed:?}");
    }

    #[test]
    fn test_store_retryable_errors() {
        assert!(retryable(&sqlx::Error::Io(std::io::Error::from(
            std::io::ErrorKind::ConnectionRefused
        ))));
        assert!(retryable(&sqlx::Error::PoolTimedOut));
        assert!(!retryable(&sqlx::Error::Configuration("bad".into())));
        assert!(!retryable(&sqlx::Error::RowNotFound));
    }

    #[test]
    fn test_database_config_debug_redacts_url() {
        let config = DatabaseConfig {
            url: Some("postgres://switch:secret@db/switch".into()),
            ..DatabaseConfig::default()
        };
        let text = format!("{config:?}");
        assert!(!text.contains("secret"), "{text}");
        assert!(text.contains("[redacted]"));
    }
}
