//! Transactions that a dropped caller can't leave open.
//!
//! A request's future is dropped when its client disconnects, and other futures are dropped
//! at a timeout or a shutdown. sqlx 0.8 counts a transaction only once the database has
//! answered its `BEGIN`: a future dropped between the two hands its connection back to the
//! pool with the transaction still open on the server. Every later statement on that
//! connection would then run inside it: an autocommit write would answer success and be
//! lost when the transaction ends, a later `SET TRANSACTION` would fail, and one failed
//! statement would leave the connection refusing everything until it closed.
//!
//! Two things keep that out of the store:
//! - [`begin`] runs `BEGIN` on a task of its own, so it always finishes; a transaction whose
//!   caller has gone is dropped and rolled back. The wait for a connection stays the
//!   caller's, so a caller that goes holds no place in the pool's queue.
//! - [`still_clean`] runs as each pool's release check, and closes a connection handed back
//!   inside a transaction, whatever opened it.

use sqlx::{Executor, PgConnection, PgPool, Postgres, Row, Transaction};

use super::StoreError;

/// Begin a transaction on a connection of `pool`, the `BEGIN` on a task of its own so that
/// the caller being dropped can't cut it short (the module's doc). This is what
/// `PgPool::begin` does, with only the `BEGIN` moved to the task.
pub(crate) async fn begin(pool: &PgPool) -> Result<Transaction<'static, Postgres>, StoreError> {
    let conn = pool.acquire().await.map_err(StoreError::from_db)?;
    match tokio::spawn(Transaction::begin(conn, None)).await {
        Ok(begun) => begun.map_err(StoreError::from_db),
        Err(error) if error.is_panic() => std::panic::resume_unwind(error.into_panic()),
        Err(_) => Err(StoreError::Database(sqlx::Error::WorkerCrashed)),
    }
}

/// The release check of both pools: whether `conn`, handed back to its pool, is outside any
/// transaction, so it may be used again. A connection inside one is closed instead.
///
/// The query runs in the simple protocol (a query string with no arguments), as one
/// statement of its own implicit transaction: there both times are the statement's start,
/// and inside a transaction begun earlier they differ. Through the extended protocol they
/// would differ for every query. A transaction a dropped transaction left to roll back is
/// rolled back first, since the queued `ROLLBACK` goes ahead of this query. On a connection
/// whose transaction failed, the query itself fails, and the pool closes the connection too.
pub(super) async fn still_clean(conn: &mut PgConnection) -> Result<bool, sqlx::Error> {
    let row = conn
        .fetch_one("SELECT transaction_timestamp() <> statement_timestamp()")
        .await?;
    let in_transaction: bool = row.try_get(0)?;
    Ok(!in_transaction)
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::Duration;

    use sqlx::postgres::{PgConnectOptions, PgSslMode};
    use sqlx::{Connection, PgConnection};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};
    use tokio::sync::{Notify, watch};

    use super::super::testing::{TestDatabase, test_database_with};
    use super::super::{DatabaseConfig, FeedRow, FeedSnapshot, InboxItem, PageReader, Store};

    const LONG_ENOUGH: Duration = Duration::from_secs(3);

    fn config() -> DatabaseConfig {
        DatabaseConfig {
            max_connections: 1,
            snapshot_readers: 1,
            acquire_timeout_ms: 5_000,
            ..DatabaseConfig::default()
        }
    }

    /// A TCP relay to PostgreSQL. Once armed, it holds the server's answers from the moment
    /// a client sends `BEGIN` until it is released, so a test can drop a caller while its
    /// `BEGIN` has reached the server and its answer hasn't come back.
    struct Relay {
        addr: SocketAddr,
        armed: Arc<AtomicBool>,
        hold: watch::Sender<bool>,
        began: Arc<Notify>,
    }

    impl Relay {
        async fn start(db: &TestDatabase) -> Self {
            let options = db.store_options();
            let host = match options.get_host() {
                "localhost" => "127.0.0.1",
                host => host,
            };
            let upstream: SocketAddr = format!("{host}:{}", options.get_port())
                .parse()
                .expect("database address");
            let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
            let relay = Self {
                addr: listener.local_addr().expect("address"),
                armed: Arc::new(AtomicBool::new(false)),
                hold: watch::channel(false).0,
                began: Arc::new(Notify::new()),
            };
            let (armed, hold, began) =
                (relay.armed.clone(), relay.hold.clone(), relay.began.clone());
            tokio::spawn(async move {
                while let Ok((client, _)) = listener.accept().await {
                    let Ok(server) = TcpStream::connect(upstream).await else {
                        continue;
                    };
                    let (mut from_client, mut to_client) = client.into_split();
                    let (mut from_server, mut to_server) = server.into_split();
                    let (armed, hold_set, began) = (armed.clone(), hold.clone(), began.clone());
                    tokio::spawn(async move {
                        let mut buf = vec![0u8; 64 * 1024];
                        while let Ok(n @ 1..) = from_client.read(&mut buf).await {
                            let chunk = buf.get(..n).unwrap_or_default();
                            // A simple-protocol query whose text is `BEGIN`: its answer is
                            // held from now on, and the test told once it is on its way.
                            let begins = chunk.windows(6).any(|w| w == b"BEGIN\0")
                                && armed.swap(false, Ordering::SeqCst);
                            if begins {
                                hold_set.send_replace(true);
                            }
                            if to_server.write_all(chunk).await.is_err() {
                                return;
                            }
                            if begins {
                                began.notify_one();
                            }
                        }
                    });
                    let mut held = hold.subscribe();
                    tokio::spawn(async move {
                        let mut buf = vec![0u8; 64 * 1024];
                        while let Ok(n @ 1..) = from_server.read(&mut buf).await {
                            if held.wait_for(|held| !*held).await.is_err() {
                                return;
                            }
                            let chunk = buf.get(..n).unwrap_or_default();
                            if to_client.write_all(chunk).await.is_err() {
                                return;
                            }
                        }
                    });
                }
            });
            relay
        }

        fn options(&self, db: &TestDatabase) -> PgConnectOptions {
            db.store_options()
                .host("127.0.0.1")
                .port(self.addr.port())
                .ssl_mode(PgSslMode::Disable)
        }

        /// A store whose connections all go through the relay.
        async fn store(&self, db: &TestDatabase) -> Store {
            Store::connect_with(self.options(db), &config())
                .await
                .expect("store through the relay")
        }

        fn arm(&self) {
            self.armed.store(true, Ordering::SeqCst);
        }

        fn release(&self) {
            self.hold.send_replace(false);
        }

        /// Run `call` until its `BEGIN` has reached the server, drop it there, and let the
        /// server's answers through again once the server is inside that transaction.
        async fn cut_at_begin<T>(
            &self,
            call: impl std::future::Future<Output = T>,
            observer: &mut PgConnection,
            db: &TestDatabase,
        ) {
            self.arm();
            tokio::select! {
                _ = call => panic!("the call finished while its BEGIN was held"),
                () = self.began.notified() => {}
            }
            self.release_once_begun(observer, db).await;
        }

        /// Let the server's answers through once a backend is inside the held `BEGIN`'s
        /// transaction.
        async fn release_once_begun(&self, observer: &mut PgConnection, db: &TestDatabase) {
            let deadline = tokio::time::Instant::now() + LONG_ENOUGH;
            while open_transactions(observer, db).await == 0 {
                assert!(
                    tokio::time::Instant::now() < deadline,
                    "the server never began"
                );
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
            self.release();
        }
    }

    /// A direct connection to look at the test database's backends from outside.
    async fn observer(db: &TestDatabase) -> PgConnection {
        PgConnection::connect_with(db.options())
            .await
            .expect("observer")
    }

    /// How many of the database's other backends are inside a transaction.
    async fn open_transactions(observer: &mut PgConnection, db: &TestDatabase) -> i64 {
        sqlx::query_scalar(
            "SELECT count(*) FROM pg_stat_activity WHERE datname = $1 \
             AND pid <> pg_backend_pid() AND state LIKE 'idle in transaction%'",
        )
        .bind(db.name())
        .fetch_one(observer)
        .await
        .expect("backends")
    }

    /// Wait until no other backend of the database is inside a transaction; `false` when
    /// one still is after a few seconds.
    async fn none_left_open(observer: &mut PgConnection, db: &TestDatabase) -> bool {
        let deadline = tokio::time::Instant::now() + LONG_ENOUGH;
        loop {
            if open_transactions(observer, db).await == 0 {
                return true;
            }
            if tokio::time::Instant::now() >= deadline {
                return false;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }

    struct NoPage;

    impl PageReader for NoPage {
        fn begin(&mut self, _: &FeedSnapshot) -> bool {
            false
        }
        fn take(&mut self, _: &FeedSnapshot, _: FeedRow) -> bool {
            false
        }
        fn take_entry(&mut self, _: &FeedSnapshot, _: InboxItem) -> bool {
            false
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_pool_begin_cut_short_by_its_caller_leaves_no_transaction() {
        let Some(db) = test_database_with(&config()).await else {
            return;
        };
        let relay = Relay::start(&db).await;
        let store = relay.store(&db).await;
        let mut watch = observer(&db).await;
        relay
            .cut_at_begin(store.lock_identity("someone"), &mut watch, &db)
            .await;
        assert!(none_left_open(&mut watch, &db).await);
        // The pool's connection takes a statement and then a repeatable-read snapshot.
        let _: i32 = sqlx::query_scalar("SELECT 1")
            .fetch_one(store.pool())
            .await
            .expect("select");
        let read = store
            .read_feed("nobody", &[0; 16], None, 1, 0, &mut NoPage)
            .await;
        assert!(matches!(read, Ok(None)), "{read:?}");
        store.close().await;
        drop(watch);
        db.drop_database().await.expect("drop");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_pool_begin_finishes_on_its_own_task_when_its_caller_goes() {
        let Some(db) = test_database_with(&config()).await else {
            return;
        };
        let relay = Relay::start(&db).await;
        // A pool without the release check: `begin` alone leaves nothing open.
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(1)
            .connect_with(relay.options(&db))
            .await
            .expect("pool");
        let mut watch = observer(&db).await;
        relay
            .cut_at_begin(super::begin(&pool), &mut watch, &db)
            .await;
        assert!(none_left_open(&mut watch, &db).await);
        pool.close().await;
        drop(watch);
        db.drop_database().await.expect("drop");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_pool_begin_whose_caller_goes_while_waiting_for_a_connection_sends_nothing() {
        let Some(db) = test_database_with(&config()).await else {
            return;
        };
        let relay = Relay::start(&db).await;
        let store = relay.store(&db).await;
        // The pool's one connection is taken, so the next begin waits for it.
        let taken = store.pool().acquire().await.expect("acquire");
        relay.arm();
        let waited =
            tokio::time::timeout(Duration::from_millis(200), super::begin(store.pool())).await;
        assert!(waited.is_err(), "the begin had no connection to take");
        drop(taken);
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert!(
            relay.armed.load(Ordering::SeqCst),
            "a begin whose caller went still took the connection"
        );
        store.close().await;
        db.drop_database().await.expect("drop");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_pool_autocommit_write_after_a_cut_begin_is_committed() {
        let Some(db) = test_database_with(&config()).await else {
            return;
        };
        let relay = Relay::start(&db).await;
        let store = relay.store(&db).await;
        let mut watch = observer(&db).await;
        relay
            .cut_at_begin(store.lock_identity("someone"), &mut watch, &db)
            .await;
        let key = crate::keys::KeyId::parse("0123456789abcdef0123456789abcdef").expect("key id");
        store
            .owe_push_key("someone", &key, 1)
            .await
            .expect("owe the key");
        // Seen at once from another connection, and still there once the store is closed.
        let owed = || {
            sqlx::query_scalar::<_, i64>("SELECT count(*) FROM erased_keys WHERE key_id = $1")
                .bind(key.as_str())
        };
        assert_eq!(owed().fetch_one(&mut watch).await.expect("count"), 1);
        store.close().await;
        assert_eq!(owed().fetch_one(&mut watch).await.expect("count"), 1);
        drop(watch);
        db.drop_database().await.expect("drop");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_pool_failed_statement_after_a_cut_begin_leaves_the_pool_usable() {
        let Some(db) = test_database_with(&config()).await else {
            return;
        };
        let relay = Relay::start(&db).await;
        let store = relay.store(&db).await;
        let mut watch = observer(&db).await;
        relay
            .cut_at_begin(store.lock_identity("someone"), &mut watch, &db)
            .await;
        assert!(
            sqlx::query("SELECT 1 / 0")
                .execute(store.pool())
                .await
                .is_err()
        );
        let after: Result<i32, _> = sqlx::query_scalar("SELECT 1").fetch_one(store.pool()).await;
        assert!(after.is_ok(), "{after:?}");
        let lock = store.lock_identity("someone").await;
        assert!(lock.is_ok(), "{:?}", lock.err());
        drop(lock);
        store.close().await;
        drop(watch);
        db.drop_database().await.expect("drop");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_pool_reader_begin_cut_short_leaves_no_transaction() {
        let Some(db) = test_database_with(&config()).await else {
            return;
        };
        let relay = Relay::start(&db).await;
        let store = relay.store(&db).await;
        let mut watch = observer(&db).await;
        // The read's first `BEGIN` is its reader's.
        relay
            .cut_at_begin(store.begin_reading("nobody", [0; 16]), &mut watch, &db)
            .await;
        assert!(none_left_open(&mut watch, &db).await);
        let read = store.begin_reading("nobody", [0; 16]).await;
        assert!(matches!(read, Ok(None)), "{:?}", read.map(|_| ()));
        store.close().await;
        drop(watch);
        db.drop_database().await.expect("drop");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_pool_closes_a_connection_handed_back_inside_a_transaction() {
        let Some(db) = test_database_with(&config()).await else {
            return;
        };
        let store = db.store().clone();
        let mut watch = observer(&db).await;
        for pool in [store.pool(), &store.readers] {
            let mut conn = pool.acquire().await.expect("acquire");
            let pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
                .fetch_one(&mut *conn)
                .await
                .expect("pid");
            // A transaction the pool doesn't know of.
            sqlx::Executor::execute(&mut *conn, "BEGIN")
                .await
                .expect("begin");
            drop(conn);
            assert!(none_left_open(&mut watch, &db).await);
            let mut conn = pool.acquire().await.expect("acquire");
            let next: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
                .fetch_one(&mut *conn)
                .await
                .expect("pid");
            assert_ne!(next, pid);
        }
        drop(watch);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_pool_keeps_connections_handed_back_clean() {
        let Some(db) = test_database_with(&config()).await else {
            return;
        };
        let store = db.store().clone();
        for pool in [store.pool(), &store.readers] {
            let mut pids = std::collections::BTreeSet::new();
            for _ in 0..50 {
                let pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
                    .fetch_one(pool)
                    .await
                    .expect("pid");
                pids.insert(pid);
                let mut tx = super::begin(pool).await.expect("begin");
                sqlx::Executor::execute(&mut *tx, "SELECT 1")
                    .await
                    .expect("select");
                tx.commit().await.expect("commit");
                // Dropped without a commit: rolled back.
                let mut tx = super::begin(pool).await.expect("begin");
                sqlx::Executor::execute(&mut *tx, "SELECT 1")
                    .await
                    .expect("select");
                drop(tx);
            }
            assert_eq!(pids.len(), 1, "{pids:?}");
        }
    }

    /// A handler that takes an identity's lock, so its request waits inside `BEGIN`.
    struct Locking {
        store: Store,
    }

    impl Locking {
        fn work(&self) -> crate::http::HandlerFuture<'_> {
            Box::pin(async move {
                drop(self.store.lock_identity("someone").await);
                crate::http::SwitchResponse {
                    status: 200,
                    headers: Vec::new(),
                    body: b"{}".to_vec(),
                }
            })
        }
    }

    impl crate::http::Handler for Locking {
        fn handle(&self, _: crate::http::SwitchRequest) -> crate::http::HandlerFuture<'_> {
            self.work()
        }

        fn refuse(&self, _: crate::http::Refusal) -> crate::http::HandlerFuture<'_> {
            self.work()
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_pool_client_disconnect_inside_begin_leaves_no_transaction() {
        let Some(db) = test_database_with(&config()).await else {
            return;
        };
        let relay = Relay::start(&db).await;
        let store = relay.store(&db).await;
        let mut watch = observer(&db).await;
        let handler = Arc::new(Locking {
            store: store.clone(),
        });
        let router = crate::http::router(handler, crate::http::source::ProxyConfig::default());
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("address");
        let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
        let server = tokio::spawn(crate::http::serve(listener, router, async move {
            let _ = stopped.await;
        }));
        relay.arm();
        let mut client = TcpStream::connect(addr).await.expect("connect");
        client
            .write_all(b"GET /v1/feed HTTP/1.1\r\nHost: switch\r\ncontent-length: 0\r\n\r\n")
            .await
            .expect("send");
        tokio::time::timeout(LONG_ENOUGH, relay.began.notified())
            .await
            .expect("the handler reaches BEGIN");
        // The client goes while the handler waits for the answer to its `BEGIN`.
        drop(client);
        tokio::time::sleep(Duration::from_millis(100)).await;
        relay.release_once_begun(&mut watch, &db).await;
        assert!(none_left_open(&mut watch, &db).await);
        let read = store
            .read_feed("nobody", &[0; 16], None, 1, 0, &mut NoPage)
            .await;
        assert!(matches!(read, Ok(None)), "{read:?}");
        let _ = stop.send(());
        let _ = tokio::time::timeout(LONG_ENOUGH, server).await;
        store.close().await;
        drop(watch);
        db.drop_database().await.expect("drop");
    }
}
