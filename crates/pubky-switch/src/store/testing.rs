//! A fresh database per test.
//!
//! Tests that need PostgreSQL connect with `PUBKY_SWITCH_TEST_DATABASE_URL`, a URL whose
//! user may create databases. Each test creates its own database, so tests run in parallel
//! without seeing each other. Without the variable such a test is skipped, unless
//! `PUBKY_SWITCH_REQUIRE_DB` is set, as CI sets it: then a missing database fails the test.
//!
//! A test database is dropped by [`TestDatabase::drop_database`], or, when a test panics or
//! forgets to, when the [`TestDatabase`] is dropped. Each name carries its creation time
//! (`switch_test_<unix seconds>_<random>`), and the first database a test process creates
//! sweeps away the ones left from earlier runs: older than [`STALE_AFTER_SECS`] with no
//! connection, so a parallel run's databases are never touched.
//!
//! Many test processes share one server. A process makes at most [`MAX_CREATING`] test
//! databases at once, and each step of making one (connecting, `CREATE DATABASE`, opening
//! its store, migrating) is tried again on its own, with a short capped back-off, when the
//! server answers that it has too many clients or that the template database is in use. A
//! test's own work is never tried again.

use std::str::FromStr;

use sqlx::{Connection, Executor, PgConnection, postgres::PgConnectOptions};

use super::{DatabaseConfig, Store, StoreError};

/// The environment variable with the test server's URL.
pub const TEST_DATABASE_URL_ENV: &str = "PUBKY_SWITCH_TEST_DATABASE_URL";

/// The environment variable that turns a skipped database test into a failure.
pub const REQUIRE_DB_ENV: &str = "PUBKY_SWITCH_REQUIRE_DB";

/// How old a test database with no connection must be before a test run drops it.
pub const STALE_AFTER_SECS: u64 = 30 * 60;

/// Whether this process has swept stale test databases yet.
static SWEPT: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// The most test databases one process makes at once. A creation briefly holds up to three
/// connections (the server's, the store's first and the one its migration runs on), so a
/// process's creations take at most 12 at a time, whatever its test threads.
pub const MAX_CREATING: usize = 4;

/// The creations in progress in this process ([`MAX_CREATING`]).
static CREATING: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(MAX_CREATING);

/// How many times one creation step is tried while the server is busy, and the longest
/// wait between two tries: about 20 seconds in all.
const BUSY_TRIES: u32 = 12;
const BUSY_WAIT_MAX: std::time::Duration = std::time::Duration::from_secs(2);

/// PostgreSQL's `too_many_connections` and `object_in_use`, the second for a template
/// database another session has open while `CREATE DATABASE` copies it.
const TOO_MANY_CONNECTIONS: &str = "53300";
const OBJECT_IN_USE: &str = "55006";

/// Whether `error` says the server is busy rather than that the step is wrong: a step that
/// failed so is tried again ([`MAX_CREATING`]).
fn server_busy(error: &StoreError) -> bool {
    let db = match error {
        StoreError::Database(sqlx::Error::Database(db))
        | StoreError::Migrate(sqlx::migrate::MigrateError::Execute(sqlx::Error::Database(db))) => {
            db
        }
        _ => return false,
    };
    matches!(
        db.code().as_deref(),
        Some(TOO_MANY_CONNECTIONS | OBJECT_IN_USE)
    )
}

/// Run one creation step, trying it again while the server is busy ([`server_busy`]): at
/// most [`BUSY_TRIES`] times, waiting 50 ms and doubling up to [`BUSY_WAIT_MAX`].
async fn while_busy<T, F, Fut>(mut step: F) -> Result<T, StoreError>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Result<T, StoreError>>,
{
    let mut wait = std::time::Duration::from_millis(50);
    let mut tries = 1;
    loop {
        match step().await {
            Err(error) if server_busy(&error) && tries < BUSY_TRIES => {
                tries += 1;
                tokio::time::sleep(wait).await;
                wait = (wait * 2).min(BUSY_WAIT_MAX);
            }
            result => return result,
        }
    }
}

/// A database created for one test, migrated, with a [`Store`] on it. Dropped with it.
#[derive(Debug)]
pub struct TestDatabase {
    admin: PgConnectOptions,
    name: String,
    options: PgConnectOptions,
    store: Store,
    /// Set once [`TestDatabase::drop_database`] has dropped it.
    dropped: bool,
}

impl Drop for TestDatabase {
    /// Drop the database when its test unwinds or didn't drop it, from a thread with a
    /// runtime of its own, since `drop` can't wait on the test's.
    fn drop(&mut self) {
        if self.dropped {
            return;
        }
        let admin = self.admin.clone();
        let name = self.name.clone();
        let dropped = std::thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()?;
            runtime.block_on(async {
                let mut conn = PgConnection::connect_with(&admin).await?;
                conn.execute(format!("DROP DATABASE IF EXISTS {name} WITH (FORCE)").as_str())
                    .await?;
                Ok::<(), sqlx::Error>(())
            })?;
            Ok::<(), Box<dyn std::error::Error + Send + Sync>>(())
        })
        .join();
        if !matches!(dropped, Ok(Ok(()))) {
            eprintln!("a test database wasn't dropped: {}", self.name);
        }
    }
}

/// The creation time a test database's name carries, in Unix seconds.
fn created_secs(name: &str) -> Option<u64> {
    let rest = name.strip_prefix("switch_test_")?;
    let (secs, random) = rest.split_once('_')?;
    (random.len() == 16 && random.bytes().all(|b| b.is_ascii_hexdigit()))
        .then(|| secs.parse().ok())
        .flatten()
}

/// Drop the test databases left from earlier runs: older than [`STALE_AFTER_SECS`] by
/// their names, with no connection. A database a run is using has connections; one being
/// created is new. Errors are reported, not raised: a sweep never fails a test.
async fn sweep_stale(admin: &PgConnectOptions) {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |since| since.as_secs());
    let result = async {
        let mut conn = PgConnection::connect_with(admin).await?;
        let names: Vec<String> = sqlx::query_scalar(
            "SELECT d.datname FROM pg_database d WHERE d.datname LIKE 'switch\\_test\\_%' \
             AND NOT EXISTS (SELECT 1 FROM pg_stat_activity a WHERE a.datname = d.datname)",
        )
        .fetch_all(&mut conn)
        .await?;
        for name in names {
            let stale = created_secs(&name)
                .is_some_and(|created| now.saturating_sub(created) > STALE_AFTER_SECS);
            if stale {
                // Without FORCE: a run that connected meanwhile keeps its database.
                let _ = conn
                    .execute(format!("DROP DATABASE IF EXISTS {name}").as_str())
                    .await;
            }
        }
        conn.close().await?;
        Ok::<(), sqlx::Error>(())
    }
    .await;
    if let Err(error) = result {
        eprintln!("sweeping stale test databases: {error}");
    }
}

/// Why a test database couldn't be made.
#[derive(Debug, thiserror::Error)]
pub enum TestDatabaseError {
    /// `PUBKY_SWITCH_TEST_DATABASE_URL` isn't set, and `PUBKY_SWITCH_REQUIRE_DB` isn't
    /// either: the test is skipped.
    #[error("{TEST_DATABASE_URL_ENV} is not set")]
    Skipped,
    /// `PUBKY_SWITCH_REQUIRE_DB` is set, and `PUBKY_SWITCH_TEST_DATABASE_URL` isn't.
    #[error("{REQUIRE_DB_ENV} is set, but {TEST_DATABASE_URL_ENV} is not")]
    Required,
    /// The server refused.
    #[error(transparent)]
    Store(#[from] StoreError),
}

impl TestDatabase {
    /// Create a database with `config`'s pool settings, and migrate it.
    pub async fn create(config: &DatabaseConfig) -> Result<Self, TestDatabaseError> {
        let url = match std::env::var(TEST_DATABASE_URL_ENV) {
            Ok(url) if !url.is_empty() => url,
            _ if std::env::var_os(REQUIRE_DB_ENV).is_some() => {
                return Err(TestDatabaseError::Required);
            }
            _ => return Err(TestDatabaseError::Skipped),
        };
        let admin = PgConnectOptions::from_str(&url).map_err(StoreError::Database)?;
        if !SWEPT.swap(true, std::sync::atomic::Ordering::SeqCst) {
            sweep_stale(&admin).await;
        }
        Self::create_on(admin, config, None)
            .await
            .map_err(Into::into)
    }

    /// Copy this test's stopped database and reopen its store with the given pool settings.
    /// Both databases are independently owned and removed by their usual cleanup.
    pub async fn snapshot(&mut self, config: &DatabaseConfig) -> Result<Self, StoreError> {
        self.store.close().await;
        let copy = async {
            // A stopped listener returns its connection to its private pool asynchronously.
            // Disconnect the sessions of this isolated test database before using it as a template.
            sqlx::query(
                "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = $1",
            )
            .bind(&self.name)
            .execute(&mut self.admin().await?)
            .await?;
            Self::create_on(self.admin.clone(), config, Some(&self.name)).await
        }
        .await;
        self.store = Store::connect_with(self.store_options(), config).await?;
        copy
    }

    async fn create_on(
        admin: PgConnectOptions,
        config: &DatabaseConfig,
        template: Option<&str>,
    ) -> Result<Self, StoreError> {
        // Held until the database is made and migrated; the test itself runs without it.
        let _creating = CREATING
            .acquire()
            .await
            .map_err(|_| StoreError::Corrupt("the creation bound was closed"))?;
        let mut suffix = [0u8; 8];
        getrandom::fill(&mut suffix)
            .map_err(|_| StoreError::Corrupt("no randomness for a database name"))?;
        let created = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |since| since.as_secs());
        let name = format!("switch_test_{created}_{}", hex::encode(suffix));
        let mut create = format!("CREATE DATABASE {name}");
        if let Some(template) = template {
            // Both names were generated above for a test database.
            create.push_str(" TEMPLATE ");
            create.push_str(template);
        }
        // A busy answer comes before the database exists: from the connection, or from
        // `CREATE DATABASE` refusing while the template is in use. Either is tried again.
        while_busy(|| async {
            let mut conn = PgConnection::connect_with(&admin)
                .await
                .map_err(StoreError::Database)?;
            conn.execute(create.as_str())
                .await
                .map_err(StoreError::Database)?;
            conn.close().await.map_err(StoreError::Database)
        })
        .await?;
        let options = admin.clone().database(&name);
        let store = while_busy(|| Store::connect_with(options.clone(), config)).await?;
        while_busy(|| store.migrate()).await?;
        // A test's own connections write an account's state directly, as a restore or a
        // fault would: they carry the identity lock's mark for their whole session, which
        // the schema's count trigger requires of every such write. The store's don't.
        let options = options.options([("switch.locked", "on")]);
        Ok(Self {
            admin,
            name,
            options,
            store,
            dropped: false,
        })
    }

    /// The store on the test database.
    pub fn store(&self) -> &Store {
        &self.store
    }

    /// The disposable store without a lock, for tests that simulate concurrent service runs.
    pub fn service_store(&self) -> super::ServiceStore {
        let mut store = self.store.clone();
        store.stopping = tokio::sync::watch::Sender::new(false);
        super::ServiceStore {
            store,
            keeper: None,
        }
    }

    /// Options to open more connections to the test database, which may write an account's
    /// state directly: outside the service's lock, and counted toward nothing.
    pub fn options(&self) -> &PgConnectOptions {
        &self.options
    }

    /// The test database's name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Options to open a connection to the test database as the service's store does, which
    /// may write an account's state only under an identity's lock.
    pub fn store_options(&self) -> PgConnectOptions {
        self.admin.clone().database(&self.name)
    }

    /// Open a connection to the server that may manage the test database.
    pub async fn admin(&self) -> Result<PgConnection, StoreError> {
        Ok(PgConnection::connect_with(&self.admin).await?)
    }

    /// Delete account `id`'s shared record at `key`, as a faulty service that lost it would:
    /// reads answer `404` and listings leave it out (Switch spec 10.3.1 "Absence"). Written
    /// directly, outside the service's lock, so it moves no count. Whether there was one.
    pub async fn drop_record(&self, id: &str, key: &[u8; 32]) -> Result<bool, StoreError> {
        let mut conn = PgConnection::connect_with(&self.options).await?;
        let dropped = sqlx::query("DELETE FROM shared_records WHERE account_id = $1 AND key = $2")
            .bind(id)
            .bind(key.as_slice())
            .execute(&mut conn)
            .await?;
        let _ = conn.close().await;
        Ok(dropped.rows_affected() == 1)
    }

    /// Give out account `id`'s next `seq` without a chain item, as an inbox entry takes
    /// one (Switch spec 6.3), and commit.
    pub async fn give_out_seq(&self, id: &str) -> Result<u64, StoreError> {
        let mut txn = self
            .store
            .begin(id)
            .await?
            .ok_or(StoreError::Corrupt("no such account"))?;
        let seq = txn.next_seq()?;
        txn.commit().await?;
        Ok(seq)
    }

    /// Make the next read after the lock on this database wait, once its request has
    /// committed, until the pause's `resume` is notified: for a test that writes in between.
    ///
    /// # Panics
    ///
    /// When another test thread poisoned the slot. For tests only.
    pub fn pause_next_snapshot_read(&self) -> SnapshotPause {
        let pause = SnapshotPause::default();
        #[allow(clippy::expect_used)]
        let mut slot = self.store.snapshot_pause.lock().expect("pause slot");
        *slot = Some(pause.clone());
        pause
    }

    /// How many reads after the lock of account `id` hold or wait for its turn
    /// ([`Store::begin_reading`]). For tests only.
    pub fn queued_reads(&self, id: &str) -> usize {
        super::snapshot::queued(&self.store.reading, id)
    }

    /// Close the store and drop the database.
    pub async fn drop_database(mut self) -> Result<(), StoreError> {
        self.store.close().await;
        let mut conn = self.admin().await?;
        conn.execute(format!("DROP DATABASE IF EXISTS {} WITH (FORCE)", self.name).as_str())
            .await?;
        self.dropped = true;
        Ok(())
    }
}

/// Where the next read after the lock waits ([`TestDatabase::pause_next_snapshot_read`]):
/// it notifies `reached` once its request has committed, and reads once `resume` is
/// notified.
#[derive(Clone, Debug, Default)]
pub struct SnapshotPause {
    /// Notified when the read is about to start, its request committed.
    pub reached: std::sync::Arc<tokio::sync::Notify>,
    /// Notify it to let the read go on.
    pub resume: std::sync::Arc<tokio::sync::Notify>,
}

/// Create a test database, or `None` when the test is to be skipped.
///
/// # Panics
///
/// When the database can't be made, or is required and not configured. For tests only.
pub async fn test_database() -> Option<TestDatabase> {
    test_database_with(&DatabaseConfig::default()).await
}

/// [`test_database`] with `config`'s pool settings.
///
/// # Panics
///
/// As [`test_database`]. For tests only.
pub async fn test_database_with(config: &DatabaseConfig) -> Option<TestDatabase> {
    match TestDatabase::create(config).await {
        Ok(db) => Some(db),
        Err(TestDatabaseError::Skipped) => {
            eprintln!("skipped: set {TEST_DATABASE_URL_ENV} to run this test against PostgreSQL");
            None
        }
        #[allow(clippy::panic)]
        Err(error) => panic!("test database: {error}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_testing_names_carry_their_creation_time() {
        assert_eq!(
            created_secs("switch_test_1700000000_0123456789abcdef"),
            Some(1_700_000_000)
        );
        // An old-style name, without a time, is never swept: its age can't be told.
        assert_eq!(created_secs("switch_test_0123456789abcdef"), None);
        assert_eq!(created_secs("other_1700000000_0123456789abcdef"), None);
    }

    /// A server error with a given SQLSTATE, as PostgreSQL answers one.
    #[derive(Debug)]
    struct ServerError(&'static str);

    impl std::fmt::Display for ServerError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "server error {}", self.0)
        }
    }

    impl std::error::Error for ServerError {}

    impl sqlx::error::DatabaseError for ServerError {
        fn message(&self) -> &str {
            "server error"
        }

        fn code(&self) -> Option<std::borrow::Cow<'_, str>> {
            Some(self.0.into())
        }

        fn as_error(&self) -> &(dyn std::error::Error + Send + Sync + 'static) {
            self
        }

        fn as_error_mut(&mut self) -> &mut (dyn std::error::Error + Send + Sync + 'static) {
            self
        }

        fn into_error(self: Box<Self>) -> Box<dyn std::error::Error + Send + Sync + 'static> {
            self
        }

        fn kind(&self) -> sqlx::error::ErrorKind {
            sqlx::error::ErrorKind::Other
        }
    }

    fn answered(code: &'static str) -> StoreError {
        StoreError::Database(sqlx::Error::Database(Box::new(ServerError(code))))
    }

    /// A step that answers `answers` in turn, then succeeds; how many times it ran.
    async fn run_step(answers: Vec<StoreError>) -> (Result<(), StoreError>, usize) {
        let answers = std::sync::Mutex::new(answers.into_iter());
        let runs = std::sync::atomic::AtomicUsize::new(0);
        let result = while_busy(|| async {
            runs.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            #[allow(clippy::unwrap_used)]
            let next = answers.lock().unwrap().next();
            next.map_or(Ok(()), Err)
        })
        .await;
        (result, runs.load(std::sync::atomic::Ordering::SeqCst))
    }

    #[tokio::test(start_paused = true)]
    async fn test_testing_busy_server_steps_are_tried_again() {
        let (result, runs) = run_step(vec![
            answered(TOO_MANY_CONNECTIONS),
            answered(OBJECT_IN_USE),
        ])
        .await;
        assert!(result.is_ok());
        assert_eq!(runs, 3);
        // In a migration too.
        let migrating = StoreError::Migrate(sqlx::migrate::MigrateError::Execute(
            sqlx::Error::Database(Box::new(ServerError(TOO_MANY_CONNECTIONS))),
        ));
        let (result, runs) = run_step(vec![migrating]).await;
        assert!(result.is_ok());
        assert_eq!(runs, 2);
    }

    #[tokio::test(start_paused = true)]
    async fn test_testing_other_failures_are_not_tried_again() {
        // A duplicate name, a syntax error and a refused login are the step's own.
        for code in ["42P04", "42601", "28P01"] {
            let (result, runs) = run_step(vec![answered(code)]).await;
            assert!(matches!(result, Err(StoreError::Database(_))), "{code}");
            assert_eq!(runs, 1, "{code}");
        }
        let (result, runs) = run_step(vec![StoreError::Corrupt("not the server")]).await;
        assert!(result.is_err());
        assert_eq!(runs, 1);
    }

    #[tokio::test(start_paused = true)]
    async fn test_testing_busy_tries_stop_at_their_bound() {
        let started = tokio::time::Instant::now();
        let busy = (0..BUSY_TRIES + 3)
            .map(|_| answered(TOO_MANY_CONNECTIONS))
            .collect();
        let (result, runs) = run_step(busy).await;
        assert!(result.is_err_and(|error| server_busy(&error)));
        assert_eq!(runs, BUSY_TRIES as usize);
        // 50 ms doubling to 2 s between the tries: under 20 s in all.
        assert!(started.elapsed() < std::time::Duration::from_secs(20));
    }

    #[tokio::test]
    async fn test_testing_creation_waits_for_a_free_slot() {
        if std::env::var(TEST_DATABASE_URL_ENV).map_or(true, |url| url.is_empty()) {
            return;
        }
        // Every slot taken: a creation waits, and goes on once one is free. The test's own
        // work never holds a slot, or it couldn't make its database at all.
        #[allow(clippy::unwrap_used)]
        let held = CREATING.acquire_many(MAX_CREATING as u32).await.unwrap();
        let creating = test_database();
        tokio::pin!(creating);
        // Long enough for an unbounded creation to finish on a local server.
        assert!(
            tokio::time::timeout(std::time::Duration::from_secs(2), &mut creating)
                .await
                .is_err(),
            "a creation ran with every slot taken"
        );
        drop(held);
        if let Some(db) = creating.await {
            let _ = db.drop_database().await;
        }
    }

    async fn exists(conn: &mut PgConnection, name: &str) -> bool {
        sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM pg_database WHERE datname = $1)")
            .bind(name)
            .fetch_one(conn)
            .await
            .unwrap_or(true)
    }

    #[tokio::test]
    async fn test_testing_drops_a_database_its_test_left() {
        let Some(db) = test_database().await else {
            return;
        };
        let name = db.name().to_string();
        let Ok(mut admin) = db.admin().await else {
            return;
        };
        // As when a test panics before drop_database.
        drop(db);
        assert!(!exists(&mut admin, &name).await, "{name} was left behind");
    }

    #[tokio::test]
    async fn test_testing_sweeps_only_stale_unconnected_databases() {
        let Some(db) = test_database().await else {
            return;
        };
        let Ok(mut admin) = db.admin().await else {
            return;
        };
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |since| since.as_secs());
        let stale = format!(
            "switch_test_{}_00000000000000aa",
            now - STALE_AFTER_SECS - 60
        );
        let recent = format!("switch_test_{now}_00000000000000bb");
        for name in [&stale, &recent] {
            let _ = admin
                .execute(format!("CREATE DATABASE {name}").as_str())
                .await;
        }
        sweep_stale(&db.admin).await;
        assert!(
            !exists(&mut admin, &stale).await,
            "the stale one is dropped"
        );
        assert!(exists(&mut admin, &recent).await, "a recent one is kept");
        // The test's own database, connected, is kept too.
        assert!(exists(&mut admin, db.name()).await);
        let _ = admin
            .execute(format!("DROP DATABASE IF EXISTS {recent}").as_str())
            .await;
        let _ = db.drop_database().await;
    }
}
