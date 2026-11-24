//! One process per database (docs/configuration.md, "Topology"): the service's binary holds a
//! session-level advisory lock in the database for as long as it serves, so a second process
//! on the same database refuses to start.
//!
//! The lock lives with its session. The process never terminates a backend, its own or
//! another's, and never tells its own sessions from others'. Instead the lock's session asks
//! the server to close it soon after its client is gone: an idle timeout for a client that
//! sends nothing, and TCP keepalives and a user timeout for a peer that stopped answering.
//! [`InstanceLock::keep`] asks the session at every check whether it still holds the lock,
//! which also keeps a live session from going idle, and stops serving at the first check
//! that can't confirm it, or that runs late: the lock may have been free in the gap, and
//! another process may have taken it. A start takes the lock afresh, waiting a bounded time
//! for the server to close an earlier run's session.

use std::time::{Duration, Instant};

use sqlx::{Connection, Executor, PgConnection, Row, postgres::PgConnectOptions};
use tokio::{sync::watch, task::JoinHandle};

use super::{Store, StoreError};

/// The advisory lock key of the service's one process: "pubkyswi".
const INSTANCE_LOCK_KEY: i64 = 0x7075_626b_7973_7769;

/// The key's halves, as `pg_locks` shows a `bigint` advisory lock: `classid` and `objid`.
const LOCK_CLASSID: i64 = INSTANCE_LOCK_KEY >> 32;
const LOCK_OBJID: i64 = INSTANCE_LOCK_KEY & 0xffff_ffff;

/// The session that holds the lock, if any, among those of this key. A column the database
/// hides from this role reads as null.
const HOLDER: &str = "SELECT l.pid, a.pid IS NOT NULL AS present, \
     a.backend_start::TEXT AS started, host(a.client_addr) AS addr \
     FROM pg_locks l LEFT JOIN pg_stat_activity a ON a.pid = l.pid \
     WHERE l.locktype = 'advisory' AND l.granted AND l.classid::BIGINT = $1 \
     AND l.objid::BIGINT = $2 AND l.objsubid = 1 \
     AND l.database = (SELECT oid FROM pg_database WHERE datname = current_database())";

/// The times of the database lock, all set by how often it is checked.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LockTiming {
    every: Duration,
}

impl LockTiming {
    /// The service's: a check every 5 seconds, each answered within 5, so the process stops
    /// at most 10 seconds after the lock was last confirmed. The server closes the lock's
    /// session 15 seconds after its last statement ended, and about 15 seconds after a TCP
    /// peer stopped answering: after the process has stopped. A start waits up to 25
    /// seconds for the lock (docs/configuration.md, "Topology").
    pub const SERVICE: Self = Self {
        every: Duration::from_secs(5),
    };

    /// Timing with a check every `every`, for tests.
    #[cfg(any(test, feature = "test-util"))]
    pub fn checking_every(every: Duration) -> Self {
        Self { every }
    }

    /// How long the server lets the lock's session sit idle before it closes it: three
    /// checks, so a live session, asked at every check, never comes near it.
    fn idle(self) -> Duration {
        self.every.saturating_mul(3)
    }

    /// How long a start waits for the lock: past the idle close, with two checks to spare.
    pub fn wait(self) -> Duration {
        self.every.saturating_mul(5)
    }

    /// The longest the process serves past the last confirmed check: the next check's sleep
    /// and its answer. Nothing is answered past it, so the process has stopped before the
    /// server closes a silent session, at three checks.
    fn overdue(self) -> Duration {
        self.every.saturating_mul(2)
    }

    /// The lock session's settings, so the server closes it once its client is gone, but
    /// only after the client would have stopped: an idle timeout of three checks; TCP
    /// keepalives after one quiet check, one a second, as many as the seconds of three
    /// checks; a user timeout of three checks, which on Linux closes a peer that stopped
    /// answering, keepalives or data, after it (a server that doesn't take it closes on the
    /// keepalives, after four checks); and no statement past one check.
    fn session_settings(self) -> String {
        let every_ms = self.every.as_millis().max(1);
        let keepalive_s = self.every.as_secs().max(1);
        format!(
            "SET idle_session_timeout = {idle}; SET tcp_keepalives_idle = {keepalive_s}; \
             SET tcp_keepalives_interval = 1; SET tcp_keepalives_count = {count}; \
             SET tcp_user_timeout = {user}; SET statement_timeout = {every_ms}",
            idle = self.idle().as_millis().max(1),
            count = keepalive_s.saturating_mul(3),
            user = every_ms.saturating_mul(3),
        )
    }
}

/// Why [`InstanceLock::keep`] ended: the process can no longer tell that it holds the
/// database alone.
#[derive(Debug, thiserror::Error)]
pub enum InstanceLockLost {
    /// A check got no answer in time, or found the lock gone from the session.
    #[error("the lock on this database couldn't be confirmed")]
    Unconfirmed,
    /// A check ran later than two checks after the last confirmed one, as after a pause of
    /// the process.
    #[error("the lock on this database went unchecked for {0:?}")]
    Overdue(Duration),
}

/// A session that holds the lock.
#[derive(Clone, Debug)]
struct Holder {
    pid: i32,
    /// Whether its backend still has a status entry: one that ended between the reads of
    /// the locks and of the sessions has none, and its lock is going.
    present: bool,
    started: Option<String>,
    addr: Option<String>,
}

impl Holder {
    /// The holder as the operator needs it to find it.
    fn describe(&self) -> String {
        format!(
            "the session of backend pid {} from {}, connected since {}",
            self.pid,
            self.addr
                .as_deref()
                .unwrap_or("an address not shown to this role"),
            self.started
                .as_deref()
                .unwrap_or("a time not shown to this role"),
        )
    }
}

/// Why one try at the lock failed.
enum TakeError {
    /// Another session holds it.
    Held(Holder),
    /// The holder let go between the reads: try again.
    Busy,
    /// The database failed.
    Store(StoreError),
}

impl From<StoreError> for TakeError {
    fn from(error: StoreError) -> Self {
        Self::Store(error)
    }
}

/// A moment on two clocks: the monotonic one, which a stopped VM, a system suspend or a
/// checkpoint restore may not advance, and the wall clock, which those do advance once the
/// host has set it again.
#[derive(Clone, Copy, Debug)]
struct Stamp {
    monotonic: Instant,
    wall: std::time::SystemTime,
}

impl Stamp {
    fn now() -> Self {
        Self {
            monotonic: Instant::now(),
            wall: std::time::SystemTime::now(),
        }
    }

    /// The time from `self` to `later`, the longer of the two clocks: a gap on either one
    /// counts. A wall clock set back counts nothing; one set forward only makes the gap
    /// look longer, which stops a healthy process, never keeps a stale one serving.
    fn until(self, later: Stamp) -> Duration {
        let monotonic = later.monotonic.saturating_duration_since(self.monotonic);
        let wall = later.wall.duration_since(self.wall).unwrap_or_default();
        monotonic.max(wall)
    }
}

/// Where the keeper reads the time: the system's clocks, or a test's.
type Clock = std::sync::Arc<dyn Fn() -> Stamp + Send + Sync>;

/// The system's clocks.
fn system_clock() -> Clock {
    std::sync::Arc::new(Stamp::now)
}

/// The database held by this process alone, as long as this lives.
pub struct InstanceLock {
    conn: Option<PgConnection>,
    /// The backend of the session that holds the lock.
    pid: i32,
    timing: LockTiming,
    /// When the check that last confirmed the lock was sent, or when the take that was
    /// granted the lock asked for it: the session held the lock at least until then. Shared
    /// with the request path's [`LockFreshness`].
    confirmed: std::sync::Arc<parking_lot::Mutex<Stamp>>,
    clock: Clock,
}

impl std::fmt::Debug for InstanceLock {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InstanceLock")
            .field("pid", &self.pid)
            .field("timing", &self.timing)
            .field("confirmed", &self.confirmed)
            .finish_non_exhaustive()
    }
}

impl Store {
    /// Take the instance lock for one service, before migrating, and start the task that
    /// keeps it ([`Store::hold_instance_lock`], [`InstanceLock::keep`]). Pass the result to
    /// [`crate::service::Service::new`], which then owns the keeper. If the keeper can't
    /// confirm the lock while its owner runs or drains, it ends the whole process with exit
    /// status 1 at once. Await [`ServiceStore::shutdown`] or
    /// [`crate::service::Service::shutdown`] before closing the database. The service runs
    /// on connections of its own, with this store's settings; this store's stay open.
    ///
    /// # Errors
    ///
    /// As [`Store::hold_instance_lock`]: [`StoreError::InUse`] when another session, this
    /// process's own included, holds the lock through the start-up wait.
    pub async fn lock_for_service(&self) -> Result<ServiceStore, StoreError> {
        let lock = self.hold_instance_lock(LockTiming::SERVICE).await?;
        Ok(self.with_service_lock(lock))
    }

    fn with_service_lock(&self, lock: InstanceLock) -> ServiceStore {
        let mut freshness = lock.freshness();
        let state = watch::Sender::new(Keeping::Armed);
        let watched = state.clone();
        let task = tokio::spawn(async move {
            let (lost, held) = lock.keep().await;
            tracing::error!(failure = %lost, "the instance lock: lost");
            {
                // Read under the state's lock, held through the exit: a disarm set before
                // this read is never taken for a lost lock, and none can race the exit.
                let keeping = watched.borrow();
                if *keeping == Keeping::Armed {
                    std::process::exit(1);
                }
            }
            watched.send_replace(Keeping::Stopped);
            held
        });
        // Pools of its own, which its shutdown closes before the lock goes.
        let mut store = self.with_own_pools();
        store.stopping = watch::Sender::new(false);
        freshness.keeping = Some(state.subscribe());
        freshness.work = Some(store.stopping.clone());
        store.lock_freshness = Some(freshness);
        ServiceStore {
            keeper: Some(LockKeeper {
                state,
                store: store.clone(),
                runtime: tokio::runtime::Handle::current(),
                task: tokio::sync::Mutex::new(Some(task)),
            }),
            store,
        }
    }

    /// Hold the database for this process alone: a session-level advisory lock on a
    /// connection of its own, outside the pools. While another session holds it, the take
    /// is tried again for up to [`LockTiming::wait`], long enough for the server to close a
    /// session whose client is gone, such as an earlier run's.
    ///
    /// # Errors
    ///
    /// [`StoreError::InUse`], naming the session that holds it, when the last try that got
    /// an answer found another one holding it; [`StoreError::LockUnanswered`] when no try got
    /// an answer in time; a database error otherwise, also when the server refuses the lock
    /// session's settings.
    pub async fn hold_instance_lock(&self, timing: LockTiming) -> Result<InstanceLock, StoreError> {
        let options = (*self.pool.connect_options()).clone();
        let lock = InstanceLock::wait_for(&options, timing, &system_clock()).await?;
        tracing::info!(
            backend_pid = lock.pid,
            "holding the database's instance lock"
        );
        Ok(lock)
    }
}

impl InstanceLock {
    /// Try the lock on new connections until it is taken, or until [`LockTiming::wait`] has
    /// passed: then what the last try that got an answer found. No try runs past the wait.
    async fn wait_for(
        options: &PgConnectOptions,
        timing: LockTiming,
        clock: &Clock,
    ) -> Result<Self, StoreError> {
        let deadline = Instant::now() + timing.wait();
        let mut last = None;
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            let bound = timing.every.min(left).max(Duration::from_millis(1));
            match tokio::time::timeout(bound, Self::take(options, timing, clock)).await {
                Ok(Ok(lock)) => return Ok(lock),
                Ok(Err(TakeError::Held(holder))) => {
                    last = Some(StoreError::InUse(holder.describe()));
                }
                Ok(Err(TakeError::Busy)) | Err(_) => {}
                Ok(Err(TakeError::Store(error))) => last = Some(error),
            }
            if Instant::now() >= deadline {
                return Err(last.unwrap_or(StoreError::LockUnanswered));
            }
            let left = deadline.saturating_duration_since(Instant::now());
            tokio::time::sleep(Duration::from_millis(200).min(timing.every).min(left)).await;
        }
    }

    /// One try at the lock, on a new connection.
    async fn take(
        options: &PgConnectOptions,
        timing: LockTiming,
        clock: &Clock,
    ) -> Result<Self, TakeError> {
        let mut conn = PgConnection::connect_with(options)
            .await
            .map_err(StoreError::from)?;
        match Self::take_on(&mut conn, timing, clock).await {
            Ok((pid, asked)) => Ok(Self {
                conn: Some(conn),
                pid,
                timing,
                confirmed: std::sync::Arc::new(parking_lot::Mutex::new(asked)),
                clock: clock.clone(),
            }),
            Err(error) => {
                let _ = conn.close().await;
                Err(error)
            }
        }
    }

    /// The lock on `conn`'s session: its backend, and when the lock was asked for, which is
    /// as late as the grant is known to hold.
    async fn take_on(
        conn: &mut PgConnection,
        timing: LockTiming,
        clock: &Clock,
    ) -> Result<(i32, Stamp), TakeError> {
        // The settings come first: a session that holds the lock is one the server closes
        // soon after its client is gone.
        conn.execute(timing.session_settings().as_str())
            .await
            .map_err(StoreError::from_db)?;
        let asked = clock();
        let locked: bool = sqlx::query_scalar("SELECT pg_try_advisory_lock($1)")
            .bind(INSTANCE_LOCK_KEY)
            .fetch_one(&mut *conn)
            .await
            .map_err(StoreError::from_db)?;
        if locked {
            let pid = sqlx::query_scalar("SELECT pg_backend_pid()")
                .fetch_one(&mut *conn)
                .await
                .map_err(StoreError::from_db)?;
            return Ok((pid, asked));
        }
        match holder(conn).await? {
            Some(holder) if holder.present => Err(TakeError::Held(holder)),
            _ => Err(TakeError::Busy),
        }
    }

    /// Whether this lock's session holds the lock, asked of the session itself: not only
    /// that the connection answers. The question also keeps the session from going idle.
    async fn confirm(conn: &mut PgConnection) -> Result<bool, StoreError> {
        sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM pg_locks WHERE locktype = 'advisory' AND granted \
             AND pid = pg_backend_pid() AND classid::BIGINT = $1 AND objid::BIGINT = $2 \
             AND objsubid = 1)",
        )
        .bind(LOCK_CLASSID)
        .bind(LOCK_OBJID)
        .fetch_one(conn)
        .await
        .map_err(StoreError::from_db)
    }

    /// Check the lock at every check of its timing, and return at the first check that
    /// can't confirm it within what is left of two checks since the last confirmed one, so
    /// the caller stops serving. Time is read on two clocks, and a gap on either counts
    /// (the monotonic one and the wall clock): a check that starts, or an answer that comes, more than two checks
    /// after the last confirmed check was sent, as after a pause of the process, stops it
    /// too, and an answer confirms the lock only as of the moment its check was sent. So
    /// the process serves on without a confirmed lock for at most two checks (10 seconds
    /// with the service's timing) while its timers run, and a pause is caught at the first
    /// timer that fires after it. It never takes the lock again: the lock may have been free
    /// in the gap, and another process may have held it and served. A start takes it
    /// afresh. The lock comes back with the reason, still held if its session lives, so the
    /// caller can stop before it lets go.
    pub async fn keep(mut self) -> (InstanceLockLost, Self) {
        let every = self.timing.every;
        let overdue = self.timing.overdue();
        loop {
            // Measured before the sleep too: a pause since the lock was asked for, or since
            // the last confirmed check was sent, stops it at once.
            let since = self.confirmed().until((self.clock)());
            if since > overdue {
                return (InstanceLockLost::Overdue(since), self);
            }
            tokio::time::sleep(every.saturating_sub(since)).await;
            let sent = (self.clock)();
            let since = self.confirmed().until(sent);
            let Some(left) = overdue.checked_sub(since) else {
                return (InstanceLockLost::Overdue(since), self);
            };
            let Some(conn) = self.conn.as_mut() else {
                return (InstanceLockLost::Unconfirmed, self);
            };
            match tokio::time::timeout(left, Self::confirm(conn)).await {
                Ok(Ok(true)) => {
                    // An answer that waited out a pause of this process says nothing about
                    // the time since it was sent.
                    let since = self.confirmed().until((self.clock)());
                    if since > overdue {
                        return (InstanceLockLost::Overdue(since), self);
                    }
                    *self.confirmed.lock() = sent;
                }
                Ok(Ok(false)) | Err(_) => return (InstanceLockLost::Unconfirmed, self),
                Ok(Err(failure)) => {
                    tracing::warn!(%failure, "checking the instance lock");
                    return (InstanceLockLost::Unconfirmed, self);
                }
            }
        }
    }
}

impl InstanceLock {
    /// When the lock was last confirmed.
    fn confirmed(&self) -> Stamp {
        *self.confirmed.lock()
    }

    /// A cheap shared view of when the lock was last confirmed, for the request path: it
    /// follows every check [`InstanceLock::keep`] confirms.
    pub fn freshness(&self) -> LockFreshness {
        LockFreshness {
            keeping: None,
            work: None,
            confirmed: self.confirmed.clone(),
            overdue: self.timing.overdue(),
            clock: self.clock.clone(),
        }
    }
}

/// A store reserved for one [`crate::service::Service`] by [`Store::lock_for_service`], and
/// the owner of its lock keeper, until the service is built on it.
#[derive(Debug)]
pub struct ServiceStore {
    pub(crate) store: Store,
    pub(crate) keeper: Option<LockKeeper>,
}

impl ServiceStore {
    /// Refuse new work, let accepted work end with the lock still confirmed, close the
    /// service's own connections, then stop the lock keeper and wait for it. Concurrent and
    /// repeated calls wait for the same shutdown.
    pub async fn shutdown(&self) {
        self.store.shutdown_service(self.keeper.as_ref()).await;
    }

    /// The database's readiness check on the pools the service's requests use, so a
    /// readiness probe sees them exhausted as the requests do.
    pub fn readiness(&self) -> super::StoreReadiness {
        super::StoreReadiness(self.store.clone())
    }
}

impl Store {
    /// Admit an operation: each holds a receiver until its work ends, even if its caller
    /// goes away. `None` once shutdown has begun.
    pub(crate) fn begin_work(&self) -> Option<watch::Receiver<bool>> {
        let stopping = self.stopping.borrow();
        (!*stopping).then(|| self.stopping.subscribe())
    }

    /// Whether shutdown has begun: work that can be left for the next start stops here.
    pub(crate) fn is_closing(&self) -> bool {
        *self.stopping.borrow()
    }

    /// Spawn work that an admitted operation starts, counted before it is spawned so a
    /// dropped caller can't hide it from shutdown. It is counted even once shutdown has
    /// begun, since the operation that starts it was admitted. `None` without a runtime.
    pub(crate) fn spawn_work<T: Send + 'static>(
        &self,
        work: impl Future<Output = T> + Send + 'static,
    ) -> Option<JoinHandle<T>> {
        let runtime = tokio::runtime::Handle::try_current().ok()?;
        let active = self.stopping.subscribe();
        Some(runtime.spawn(async move {
            let _active = active;
            work.await
        }))
    }

    /// Close admission, wait for the admitted work, close the connections, then stop the
    /// keeper. The keeper confirms the lock through the wait, so admitted work commits as
    /// it would have, and a lock lost meanwhile ends the process as it does while serving.
    /// Closing the pools waits for every connection in use, the ones no work counts
    /// included (a dropped request's `COMMIT`), so none ends after the lock goes.
    pub(crate) async fn shutdown_service(&self, keeper: Option<&LockKeeper>) {
        self.stopping.send_replace(true);
        self.stopping.closed().await;
        self.close().await;
        if let Some(keeper) = keeper {
            keeper.stop().await;
        }
    }
}

/// Where the keeper stands.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Keeping {
    /// Confirming the lock; a lost lock ends the process.
    Armed,
    /// Confirming the lock for work its dropped owner left; a lost lock stops the keeper.
    Disarmed,
    /// Stopped: nothing that needs the lock commits.
    Stopped,
}

/// The task that keeps the instance lock, owned by one service.
pub(crate) struct LockKeeper {
    state: watch::Sender<Keeping>,
    /// The service's store: its admitted work and its own pools.
    store: Store,
    /// The runtime the keeper runs on, which ends it whatever thread drops its owner.
    runtime: tokio::runtime::Handle,
    task: tokio::sync::Mutex<Option<JoinHandle<InstanceLock>>>,
}

impl std::fmt::Debug for LockKeeper {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LockKeeper")
            .field("state", &*self.state.borrow())
            .finish_non_exhaustive()
    }
}

impl LockKeeper {
    /// Stop the keeper and wait until its task has ended and its session is closed. The
    /// handle stays in its slot across the wait, so a cancelled call can be made again.
    async fn stop(&self) {
        self.state.send_replace(Keeping::Stopped);
        let mut task = self.task.lock().await;
        if let Some(running) = task.as_mut() {
            running.abort();
            let _ = running.await;
            *task = None;
        }
    }
}

impl Drop for LockKeeper {
    /// An owner dropped without shutdown, a cancelled start included, may close the
    /// database next: a check that fails from here on stops the keeper rather than the
    /// process. Admission closes, and the keeper keeps the lock until the work already
    /// admitted has ended and the service's connections are closed, so that work commits
    /// under it as it would have.
    fn drop(&mut self) {
        self.store.stopping.send_replace(true);
        self.state.send_if_modified(|keeping| {
            let armed = *keeping == Keeping::Armed;
            if armed {
                *keeping = Keeping::Disarmed;
            }
            armed
        });
        let Some(task) = self.task.get_mut().take() else {
            return;
        };
        let (state, store) = (self.state.clone(), self.store.clone());
        // A runtime already shut down has ended the keeper with it.
        self.runtime.spawn(async move {
            store.stopping.closed().await;
            store.close().await;
            state.send_replace(Keeping::Stopped);
            task.abort();
            let _ = task.await;
        });
    }
}

/// When the instance lock was last confirmed, read on both clocks as the keeper reads them:
/// a request refuses a commit that gives out a `seq`, signs a head or moves a mark once the
/// last confirmed check is older than two checks ([`LockFreshness::is_fresh`]), so no such
/// commit lands while another process may hold the lock (Switch spec 6.5).
#[derive(Clone)]
pub struct LockFreshness {
    /// Where the service's keeper stands; `None` for a view without a keeper.
    keeping: Option<watch::Receiver<Keeping>>,
    /// The service's admitted work, which a blocking mark write joins.
    work: Option<watch::Sender<bool>>,
    confirmed: std::sync::Arc<parking_lot::Mutex<Stamp>>,
    overdue: Duration,
    clock: Clock,
}

impl std::fmt::Debug for LockFreshness {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LockFreshness")
            .field("confirmed", &*self.confirmed.lock())
            .field("overdue", &self.overdue)
            .finish_non_exhaustive()
    }
}

impl LockFreshness {
    /// Count a blocking mark write until its worker returns.
    pub(crate) fn track_work(&self) -> Option<watch::Receiver<bool>> {
        self.work.as_ref().map(watch::Sender::subscribe)
    }

    /// Whether the keeper still runs and confirmed the lock within the last two checks.
    pub fn is_fresh(&self) -> bool {
        self.keeping
            .as_ref()
            .is_none_or(|keeping| *keeping.borrow() != Keeping::Stopped)
            && self.confirmed.lock().until((self.clock)()) <= self.overdue
    }

    /// A view whose lock was last confirmed `ago` before now, checked every `timing`, for
    /// tests of what a stale lock refuses.
    #[cfg(any(test, feature = "test-util"))]
    pub fn confirmed_ago(ago: Duration, timing: LockTiming) -> Self {
        let now = Stamp::now();
        let then = Stamp {
            monotonic: now.monotonic.checked_sub(ago).unwrap_or(now.monotonic),
            wall: now.wall.checked_sub(ago).unwrap_or(now.wall),
        };
        Self {
            keeping: None,
            work: None,
            confirmed: std::sync::Arc::new(parking_lot::Mutex::new(then)),
            overdue: timing.overdue(),
            clock: system_clock(),
        }
    }
}

/// The session that holds the lock, if one does.
async fn holder(conn: &mut PgConnection) -> Result<Option<Holder>, StoreError> {
    let row = sqlx::query(HOLDER)
        .bind(LOCK_CLASSID)
        .bind(LOCK_OBJID)
        .fetch_optional(conn)
        .await
        .map_err(StoreError::from_db)?;
    row.map(|row| {
        Ok(Holder {
            pid: row.try_get("pid")?,
            present: row.try_get("present")?,
            started: row.try_get("started")?,
            addr: row.try_get("addr")?,
        })
    })
    .transpose()
}

#[cfg(test)]
mod tests {
    use std::sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    };

    use super::*;
    use crate::store::testing::TestDatabase;

    /// Timing for tests: a check every second, the idle close at 3 s, a start's wait of 5 s.
    fn fast() -> LockTiming {
        LockTiming::checking_every(Duration::from_secs(1))
    }

    /// The pids of the sessions that hold the lock.
    async fn holders(db: &TestDatabase) -> Vec<i32> {
        let mut conn = PgConnection::connect_with(db.options())
            .await
            .expect("conn");
        let pids = sqlx::query_scalar(
            "SELECT pid FROM pg_locks WHERE locktype = 'advisory' AND granted \
             AND classid::BIGINT = $1 AND objid::BIGINT = $2 AND objsubid = 1 \
             AND database = (SELECT oid FROM pg_database WHERE datname = current_database())",
        )
        .bind(LOCK_CLASSID)
        .bind(LOCK_OBJID)
        .fetch_all(&mut conn)
        .await
        .expect("holders");
        conn.close().await.expect("close");
        pids
    }

    /// End the lock session, as a database restart or a failover does.
    async fn end_session(options: &PgConnectOptions, pid: i32) {
        let mut other = PgConnection::connect_with(options).await.expect("conn");
        let ended: bool = sqlx::query_scalar("SELECT pg_terminate_backend($1)")
            .bind(pid)
            .fetch_one(&mut other)
            .await
            .expect("terminate");
        assert!(ended);
        other.close().await.expect("close");
    }

    /// A TCP proxy to the test database whose first connection can be frozen: it stops
    /// forwarding and keeps both its sockets open, while later connections pass.
    async fn freezing_proxy(db: &TestDatabase) -> (PgConnectOptions, Arc<AtomicBool>) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let target = format!("{}:{}", db.options().get_host(), db.options().get_port());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let port = listener.local_addr().expect("addr").port();
        let frozen = Arc::new(AtomicBool::new(false));
        let freeze = frozen.clone();
        tokio::spawn(async move {
            let mut first = true;
            while let Ok((client, _)) = listener.accept().await {
                let Ok(server) = tokio::net::TcpStream::connect(&target).await else {
                    continue;
                };
                let gate = first.then(|| freeze.clone());
                first = false;
                let (client_read, client_write) = client.into_split();
                let (server_read, server_write) = server.into_split();
                for (mut from, mut to, gate) in [
                    (
                        Box::new(client_read) as Box<dyn tokio::io::AsyncRead + Send + Unpin>,
                        Box::new(server_write) as Box<dyn tokio::io::AsyncWrite + Send + Unpin>,
                        gate.clone(),
                    ),
                    (Box::new(server_read), Box::new(client_write), gate),
                ] {
                    tokio::spawn(async move {
                        let mut buf = vec![0u8; 8192];
                        loop {
                            let Ok(read) = from.read(&mut buf).await else {
                                return;
                            };
                            if read == 0 {
                                return;
                            }
                            if gate
                                .as_ref()
                                .is_some_and(|gate| gate.load(Ordering::SeqCst))
                            {
                                // Frozen: hold both sockets open and forward nothing.
                                std::future::pending::<()>().await;
                            }
                            if to.write_all(&buf[..read]).await.is_err() {
                                return;
                            }
                        }
                    });
                }
            }
        });
        (db.options().clone().host("127.0.0.1").port(port), frozen)
    }

    #[test]
    fn test_store_instance_lock_service_timing() {
        let timing = LockTiming::SERVICE;
        assert_eq!(timing.idle(), Duration::from_secs(15));
        assert_eq!(timing.wait(), Duration::from_secs(25));
        assert_eq!(timing.overdue(), Duration::from_secs(10));
        assert_eq!(
            timing.session_settings(),
            "SET idle_session_timeout = 15000; SET tcp_keepalives_idle = 5; \
             SET tcp_keepalives_interval = 1; SET tcp_keepalives_count = 15; \
             SET tcp_user_timeout = 15000; SET statement_timeout = 5000"
        );
    }

    #[tokio::test]
    async fn test_store_instance_lock_session_has_its_settings_on_tcp() {
        // Over TCP the server takes every setting, so it closes the session itself once its
        // client is gone.
        let Some(db) = crate::store::testing::test_database().await else {
            return;
        };
        let mut held = db
            .store()
            .hold_instance_lock(LockTiming::SERVICE)
            .await
            .expect("lock");
        let conn = held.conn.as_mut().expect("held");
        let tcp: bool = sqlx::query_scalar("SELECT inet_client_addr() IS NOT NULL")
            .fetch_one(&mut *conn)
            .await
            .expect("tcp");
        assert!(tcp, "the test database is reached over TCP");
        for (name, value) in [
            ("idle_session_timeout", "15s"),
            ("tcp_keepalives_idle", "5"),
            ("tcp_keepalives_interval", "1"),
            ("tcp_keepalives_count", "15"),
            ("tcp_user_timeout", "15000"),
            ("statement_timeout", "5s"),
        ] {
            let shown: String = sqlx::query_scalar(&format!("SHOW {name}"))
                .fetch_one(&mut *conn)
                .await
                .expect("show");
            assert_eq!(shown, value, "{name}");
        }
        drop(held);
        db.drop_database().await.expect("drop");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_store_instance_lock_second_process_never_serves() {
        // A second process waits out its start's wait and is refused, naming the session
        // that holds the lock, which the first's keeper keeps live; the first serves on.
        let Some(db) = crate::store::testing::test_database().await else {
            return;
        };
        let held = db.store().hold_instance_lock(fast()).await.expect("lock");
        let pid = held.pid;
        let keeper = tokio::spawn(async move { held.keep().await.0 });
        let started = Instant::now();
        match db.store().hold_instance_lock(fast()).await {
            Err(StoreError::InUse(holder)) => {
                assert!(holder.contains(&format!("pid {pid} ")), "{holder}");
            }
            other => panic!("{other:?}"),
        }
        assert!(started.elapsed() >= fast().wait(), "waited");
        assert_eq!(holders(&db).await, vec![pid]);
        assert!(!keeper.is_finished(), "the first serves on");
        keeper.abort();
        let _ = keeper.await;
        db.drop_database().await.expect("drop");
    }

    async fn start_embedded(
        db: &TestDatabase,
        dir: &std::path::Path,
    ) -> Result<crate::service::Service, StoreError> {
        use crate::{keys::FileKeyStore, marks::MarkStore, service::Service, time};

        Service::start(
            "https://inbox.example".into(),
            db.store().clone(),
            Arc::new(FileKeyStore::open(dir).expect("keys")),
            MarkStore::open(dir).expect("marks"),
            Arc::new(time::TrustedTime::new(
                Default::default(),
                Arc::new(time::SystemClock),
            )),
            Default::default(),
        )
        .await
    }

    #[tokio::test]
    async fn test_embedder_lock_serves_with_free_database() {
        use crate::http::{Handler, SwitchRequest, route::route};

        let Some(db) = crate::store::testing::test_database().await else {
            return;
        };
        let dir = tempfile::tempdir().expect("directory");
        let service = start_embedded(&db, dir.path()).await.expect("start");
        assert_eq!(holders(&db).await.len(), 1);
        let identity = pubky_switch_core::enc::pubky_id(&[1; 32]);
        let path = format!("/v1/{identity}/identity");
        let answer = service
            .handle(SwitchRequest {
                route: route("GET", &path).expect("route"),
                method: "GET".into(),
                path_and_query: path,
                headers: Default::default(),
                body: Default::default(),
                source: None,
            })
            .await;
        assert_eq!(answer.status, 404);
        let body: serde_json::Value = serde_json::from_slice(&answer.body).expect("answer");
        assert_eq!(body["current"]["hosted"], false);
        drop(service);
        let next = db
            .store()
            .hold_instance_lock(fast())
            .await
            .expect("released");
        drop(next);
        db.drop_database().await.expect("drop");
    }

    #[tokio::test]
    async fn test_embedder_lock_refuses_second_holder() {
        let Some(db) = crate::store::testing::test_database().await else {
            return;
        };
        let dir = tempfile::tempdir().expect("directory");
        let first = db.store().lock_for_service().await.expect("first holder");
        let pids = holders(&db).await;
        let [pid] = pids.as_slice() else {
            panic!("holders: {pids:?}")
        };
        let error = start_embedded(&db, dir.path())
            .await
            .expect_err("second holder");
        assert!(
            matches!(error, StoreError::InUse(holder) if holder.contains(&format!("pid {pid} ")))
        );
        assert_eq!(holders(&db).await, pids);
        drop(first);
        db.drop_database().await.expect("drop");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_embedder_shutdown_joins_active_poll() {
        use futures_util::FutureExt;

        let Some(db) = crate::store::testing::test_database().await else {
            return;
        };
        let mut lock = db.store().hold_instance_lock(fast()).await.expect("lock");
        let entered = Arc::new(tokio::sync::Notify::new());
        let checking = entered.clone();
        let (release, wait) = std::sync::mpsc::channel();
        let wait = parking_lot::Mutex::new(Some(wait));
        lock.clock = Arc::new(move || {
            if let Some(wait) = wait.lock().take() {
                checking.notify_one();
                wait.recv_timeout(Duration::from_secs(10))
                    .expect("release keeper");
            }
            Stamp::now()
        });

        let instance = db.store().with_service_lock(lock);
        tokio::time::timeout(Duration::from_secs(5), entered.notified())
            .await
            .expect("keeper polling");
        // Both calls must wait for the active poll, including a retry after the first was dropped.
        assert!(instance.shutdown().now_or_never().is_none());
        let mut shutdown = Box::pin(instance.shutdown());
        assert!((&mut shutdown).now_or_never().is_none());
        release.send(()).expect("resume keeper");
        tokio::time::timeout(Duration::from_secs(5), shutdown)
            .await
            .expect("keeper joined");
        db.drop_database().await.expect("drop");
        instance.shutdown().await;
    }

    #[tokio::test]
    async fn test_embedder_lock_loss_during_drain_exits_host() {
        // The lock is confirmed until the drain ends: losing it meanwhile is a real loss.
        check_host_exit(Exit::Draining).await;
    }

    #[tokio::test]
    async fn test_embedder_lock_loss_after_drop_leaves_host_running() {
        // A host that dropped its service may close the database while accepted work ends.
        check_host_exit(Exit::Dropped).await;
    }

    #[tokio::test]
    async fn test_embedder_shutdown_keeps_the_lock_while_a_connection_is_in_use() {
        // A connection a dropped request left mid-`COMMIT` is counted by no work; the lock
        // stays until the store's connections have ended.
        let Some(db) = crate::store::testing::test_database().await else {
            return;
        };
        let store = Store::connect_with(db.options().clone(), &Default::default())
            .await
            .expect("store");
        let instance = store.lock_for_service().await.expect("lock");
        let conn = instance.store.pool.acquire().await.expect("connection");
        let mut shutdown = Box::pin(instance.shutdown());
        assert!(
            tokio::time::timeout(Duration::from_millis(300), &mut shutdown)
                .await
                .is_err()
        );
        assert_eq!(holders(&db).await.len(), 1, "the lock is kept");
        drop(conn);
        tokio::time::timeout(Duration::from_secs(10), shutdown)
            .await
            .expect("shutdown ends");
        assert!(holders(&db).await.is_empty(), "the lock is let go");
        db.drop_database().await.expect("drop");
    }

    #[tokio::test]
    async fn test_embedder_readiness_sees_the_service_pools_exhausted() {
        use crate::admin::ReadinessCheck;

        let Some(db) = crate::store::testing::test_database().await else {
            return;
        };
        let config = crate::store::DatabaseConfig {
            max_connections: 2,
            acquire_timeout_ms: 300,
            ..Default::default()
        };
        let store = Store::connect_with(db.options().clone(), &config)
            .await
            .expect("store");
        let instance = store.lock_for_service().await.expect("lock");
        let readiness = instance.readiness();
        readiness.check().await.expect("ready");
        let held = [
            instance.store.pool.acquire().await.expect("connection"),
            instance.store.pool.acquire().await.expect("connection"),
        ];
        assert!(
            readiness.check().await.is_err(),
            "the requests' pool is exhausted"
        );
        // The caller's store, which the executable probed before, still answers ready.
        crate::store::StoreReadiness(store.clone())
            .check()
            .await
            .expect("another pool");
        drop(held);
        readiness.check().await.expect("ready again");
        instance.shutdown().await;
        store.close().await;
        db.drop_database().await.expect("drop");
    }

    #[tokio::test]
    async fn test_embedder_cancelled_start_lets_a_retry_start() {
        // A `Service::start` dropped part-way, at whatever point, leaves no lock behind
        // once its spawned work ends: a retry starts.
        let Some(db) = crate::store::testing::test_database().await else {
            return;
        };
        let dir = tempfile::tempdir().expect("directory");
        for after_ms in [0, 5, 20, 100] {
            let start = start_embedded(&db, dir.path());
            let _ = tokio::time::timeout(Duration::from_millis(after_ms), start).await;
            let service =
                tokio::time::timeout(Duration::from_secs(30), start_embedded(&db, dir.path()))
                    .await
                    .expect("the retry starts in time")
                    .expect("the retry takes the lock");
            assert_eq!(holders(&db).await.len(), 1);
            service.shutdown().await;
        }
        db.drop_database().await.expect("drop");
    }

    #[tokio::test]
    async fn test_embedder_store_serves_again_after_a_shutdown() {
        // The service runs on pools of its own: its shutdown leaves the caller's store open,
        // and a new service on it can take the lock and connect.
        let Some(db) = crate::store::testing::test_database().await else {
            return;
        };
        let store = Store::connect_with(db.options().clone(), &Default::default())
            .await
            .expect("store");
        let first = store.lock_for_service().await.expect("lock");
        first.shutdown().await;
        let second = store.lock_for_service().await.expect("lock again");
        second
            .store
            .pool
            .acquire()
            .await
            .expect("the new service connects");
        store
            .pool
            .acquire()
            .await
            .expect("the caller's store connects");
        second.shutdown().await;
        store.close().await;
        db.drop_database().await.expect("drop");
    }

    #[tokio::test]
    async fn test_embedder_dropped_service_keeps_the_lock_until_its_work_ends() {
        let Some(db) = crate::store::testing::test_database().await else {
            return;
        };
        let instance = db.store().lock_for_service().await.expect("lock");
        let freshness = instance.store.lock_freshness.clone().expect("freshness");
        let blocked = Arc::new(tokio::sync::Notify::new());
        let waiting = blocked.clone();
        // As the start-up sweep's task does, the work holds a clone of the store.
        let store = instance.store.clone();
        let detached = instance
            .store
            .spawn_work(async move {
                let _store = store;
                waiting.notified().await;
            })
            .expect("detached work");
        // A cancelled start or a dropped service leaves accepted work running; the owner
        // may be dropped on a thread outside the runtime.
        std::thread::spawn(move || drop(instance))
            .join()
            .expect("dropped");
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert_eq!(holders(&db).await.len(), 1, "the work still holds the lock");
        assert!(freshness.is_fresh(), "and commits under it");
        blocked.notify_one();
        detached.await.expect("detached work ends");
        let next = db
            .store()
            .hold_instance_lock(fast())
            .await
            .expect("the lock is let go once the work ends");
        assert!(!freshness.is_fresh());
        drop(next);
        db.drop_database().await.expect("drop");
    }

    #[tokio::test]
    async fn test_embedder_shutdown_keeps_the_lock_fresh_while_draining() {
        use futures_util::FutureExt;

        let Some(db) = crate::store::testing::test_database().await else {
            return;
        };
        let instance = db.store().lock_for_service().await.expect("lock");
        let freshness = instance.store.lock_freshness.clone().expect("freshness");
        let active = instance.store.begin_work().expect("accepted work");
        let mut shutdown = Box::pin(instance.shutdown());
        assert!((&mut shutdown).now_or_never().is_none());
        assert!(instance.store.begin_work().is_none(), "admission is closed");
        assert!(freshness.is_fresh(), "accepted work still commits");
        // Work an accepted request spawns is counted, not refused.
        let (finish, finished) = tokio::sync::oneshot::channel::<()>();
        let nested = instance
            .store
            .spawn_work(async move {
                let _ = finished.await;
            })
            .expect("nested work runs");
        drop(active);
        assert!(
            (&mut shutdown).now_or_never().is_none(),
            "nested work drains"
        );
        finish.send(()).expect("finish");
        nested.await.expect("nested work ends");
        tokio::time::timeout(Duration::from_secs(5), shutdown)
            .await
            .expect("drained");
        assert!(!freshness.is_fresh(), "no commit after the keeper stops");
        db.drop_database().await.expect("drop");
    }

    #[tokio::test]
    async fn test_embedder_lock_loss_exits_host() {
        check_host_exit(Exit::Serving).await;
    }

    /// Where the service stands when its lock is lost.
    #[derive(Clone, Copy, PartialEq)]
    enum Exit {
        Serving,
        Draining,
        Dropped,
    }

    async fn check_host_exit(at: Exit) {
        const CHILD_DATABASE: &str = "PUBKY_SWITCH_LOCK_TEST_CHILD_DATABASE";
        if let Ok(name) = std::env::var(CHILD_DATABASE) {
            let url =
                std::env::var(crate::store::testing::TEST_DATABASE_URL_ENV).expect("database URL");
            let options = url
                .parse::<PgConnectOptions>()
                .expect("database options")
                .database(&name);
            let store = Store::connect_with(options.clone(), &Default::default())
                .await
                .expect("store");
            let instance = store.lock_for_service().await.expect("instance lock");
            let mut conn = PgConnection::connect_with(&options)
                .await
                .expect("connection");
            let pid = holder(&mut conn)
                .await
                .expect("query")
                .expect("lock holder")
                .pid;
            let active = instance.store.begin_work().expect("accepted work");
            if at == Exit::Dropped {
                let freshness = instance.store.lock_freshness.clone().expect("freshness");
                drop(instance);
                end_session(&options, pid).await;
                tokio::time::timeout(Duration::from_secs(20), async {
                    while freshness.is_fresh() {
                        tokio::time::sleep(Duration::from_millis(50)).await;
                    }
                })
                .await
                .expect("the keeper stopped");
                drop(active);
                return;
            }
            let mut shutdown = Box::pin(instance.shutdown());
            if at == Exit::Draining {
                assert!(futures_util::FutureExt::now_or_never(&mut shutdown).is_none());
                assert!(instance.store.begin_work().is_none());
            }
            end_session(&options, pid).await;
            // The keeper's next check finds the lock gone and ends the process.
            tokio::time::sleep(Duration::from_secs(20)).await;
            drop((active, shutdown));
            panic!("the host survived a lost lock");
        }

        // The parent owns the database so it can remove it even when the child exits.
        let Some(db) = crate::store::testing::test_database().await else {
            return;
        };
        let test = match at {
            Exit::Serving => "test_embedder_lock_loss_exits_host",
            Exit::Draining => "test_embedder_lock_loss_during_drain_exits_host",
            Exit::Dropped => "test_embedder_lock_loss_after_drop_leaves_host_running",
        };
        let output = std::process::Command::new(std::env::current_exe().expect("test executable"))
            .args(["--exact", &format!("store::instance::tests::{test}")])
            .env(CHILD_DATABASE, db.name())
            .output()
            .expect("child");
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(stdout.contains("running 1 test"), "{stdout} {stderr}");
        let code = if at == Exit::Dropped { 0 } else { 1 };
        assert_eq!(output.status.code(), Some(code), "{stdout} {stderr}");
        db.drop_database().await.expect("drop");
    }

    #[tokio::test]
    async fn test_store_instance_lock_start_waits_for_a_session_that_lets_go() {
        let Some(db) = crate::store::testing::test_database().await else {
            return;
        };
        let earlier = db.store().hold_instance_lock(fast()).await.expect("lock");
        let letting_go = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(500)).await;
            drop(earlier);
        });
        db.store()
            .hold_instance_lock(fast())
            .await
            .expect("taken once the earlier session let go");
        letting_go.await.expect("join");
        db.drop_database().await.expect("drop");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_store_instance_lock_keeper_stops_when_its_session_ends() {
        // The database ends the lock's session, as a restart or a failover does, and another
        // process takes the lock: the keeper stops at its next check, without taking the lock
        // again, and the other serves on.
        let Some(db) = crate::store::testing::test_database().await else {
            return;
        };
        let first = db.store().hold_instance_lock(fast()).await.expect("lock");
        end_session(db.options(), first.pid).await;
        let second = db
            .store()
            .hold_instance_lock(fast())
            .await
            .expect("the other process takes it");
        let second_pid = second.pid;
        let second_keeper = tokio::spawn(async move { second.keep().await.0 });
        let started = Instant::now();
        let lost = tokio::time::timeout(Duration::from_secs(20), async { first.keep().await.0 })
            .await
            .expect("the keeper stops");
        assert!(
            matches!(
                lost,
                InstanceLockLost::Unconfirmed | InstanceLockLost::Overdue(_)
            ),
            "{lost:?}"
        );
        assert!(
            started.elapsed() <= fast().overdue() + fast().every,
            "at its next check"
        );
        assert_eq!(holders(&db).await, vec![second_pid]);
        assert!(!second_keeper.is_finished(), "the other serves on");
        second_keeper.abort();
        let _ = second_keeper.await;
        db.drop_database().await.expect("drop");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_store_instance_lock_frozen_session_is_closed_by_the_server() {
        // The lock's connection stops answering while its socket stays open, so no TCP
        // keepalive fails. The keeper stops within two checks, ending no session; the
        // server closes the frozen session once it has been idle, and a restart's start
        // then takes the lock within its wait.
        let Some(db) = crate::store::testing::test_database().await else {
            return;
        };
        let (options, frozen) = freezing_proxy(&db).await;
        let held = InstanceLock::wait_for(&options, fast(), &system_clock())
            .await
            .expect("lock");
        let old = held.pid;
        frozen.store(true, Ordering::SeqCst);
        let started = Instant::now();
        let lost = tokio::time::timeout(Duration::from_secs(20), async { held.keep().await.0 })
            .await
            .expect("the keeper stops");
        assert!(matches!(lost, InstanceLockLost::Unconfirmed), "{lost:?}");
        assert!(
            started.elapsed() <= fast().overdue() + fast().every,
            "within two checks"
        );
        let restarted = db
            .store()
            .hold_instance_lock(fast())
            .await
            .expect("a restart takes the lock");
        assert_eq!(holders(&db).await, vec![restarted.pid]);
        assert_ne!(restarted.pid, old);
        db.drop_database().await.expect("drop");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_store_instance_lock_copy_facing_a_live_original_stops() {
        // A copy of the running process has no usable connection of its own: its keeper
        // stops at its first check, and its restart finds the lock held by the original's
        // live session and is refused; the original serves on.
        let Some(db) = crate::store::testing::test_database().await else {
            return;
        };
        let original = db.store().hold_instance_lock(fast()).await.expect("lock");
        let original_pid = original.pid;
        let copy = InstanceLock {
            conn: None,
            pid: original.pid,
            timing: original.timing,
            confirmed: std::sync::Arc::new(parking_lot::Mutex::new(original.confirmed())),
            clock: original.clock.clone(),
        };
        let original_keeper = tokio::spawn(async move { original.keep().await.0 });
        let lost = tokio::time::timeout(Duration::from_secs(20), async { copy.keep().await.0 })
            .await
            .expect("the copy stops");
        assert!(matches!(lost, InstanceLockLost::Unconfirmed), "{lost:?}");
        assert!(matches!(
            db.store().hold_instance_lock(fast()).await,
            Err(StoreError::InUse(_))
        ));
        assert!(!original_keeper.is_finished(), "the original serves on");
        assert_eq!(holders(&db).await, vec![original_pid]);
        original_keeper.abort();
        let _ = original_keeper.await;
        db.drop_database().await.expect("drop");
    }

    #[tokio::test]
    async fn test_store_instance_lock_freshness_follows_the_keeper() {
        // Fresh while the keeper confirms the lock; stale once the last confirmed check is
        // older than two checks, as when the keeper has stopped.
        let Some(db) = crate::store::testing::test_database().await else {
            return;
        };
        let held = db.store().hold_instance_lock(fast()).await.expect("lock");
        let freshness = held.freshness();
        assert!(freshness.is_fresh());
        let keeper = tokio::spawn(async move { held.keep().await });
        tokio::time::sleep(fast().overdue() + fast().every).await;
        assert!(freshness.is_fresh(), "the keeper confirmed it meanwhile");
        keeper.abort();
        let _ = keeper.await;
        tokio::time::sleep(fast().overdue() + fast().every).await;
        assert!(!freshness.is_fresh(), "nothing confirmed it since");
        assert!(!LockFreshness::confirmed_ago(fast().overdue() * 2, fast()).is_fresh());
        assert!(LockFreshness::confirmed_ago(Duration::ZERO, fast()).is_fresh());
        db.drop_database().await.expect("drop");
    }

    #[tokio::test]
    async fn test_store_instance_lock_keeper_stops_after_a_pause() {
        // The process was paused longer than two checks: the server may have closed the
        // session and another process taken the lock, so the keeper stops without asking.
        let Some(db) = crate::store::testing::test_database().await else {
            return;
        };
        let held = db.store().hold_instance_lock(fast()).await.expect("lock");
        held.confirmed.lock().monotonic = Instant::now() - fast().overdue() - fast().every;
        let lost = tokio::time::timeout(Duration::from_secs(20), async { held.keep().await.0 })
            .await
            .expect("the keeper stops");
        assert!(matches!(lost, InstanceLockLost::Overdue(_)), "{lost:?}");
        db.drop_database().await.expect("drop");
    }

    #[tokio::test]
    async fn test_store_instance_lock_start_without_an_answer_says_so() {
        // A server that takes the connection and never answers: the start gives up after
        // its wait and says that no try was answered.
        let Some(db) = crate::store::testing::test_database().await else {
            return;
        };
        let silent = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let port = silent.local_addr().expect("addr").port();
        tokio::spawn(async move {
            let mut held = Vec::new();
            while let Ok((socket, _)) = silent.accept().await {
                held.push(socket);
            }
        });
        let options = db.options().clone().host("127.0.0.1").port(port);
        let started = Instant::now();
        assert!(matches!(
            InstanceLock::wait_for(&options, fast(), &system_clock()).await,
            Err(StoreError::LockUnanswered)
        ));
        let waited = started.elapsed();
        assert!(
            waited >= fast().wait() && waited < fast().wait() + fast().every,
            "{waited:?}"
        );
        db.drop_database().await.expect("drop");
    }

    /// A clock that jumps `monotonic` and `wall` ahead from its `from`-th reading on, as a
    /// pause of the process would.
    fn jumping(from: usize, monotonic: Duration, wall: Duration) -> Clock {
        let readings = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        Arc::new(move || {
            let now = Stamp::now();
            if readings.fetch_add(1, Ordering::SeqCst) + 1 >= from {
                Stamp {
                    monotonic: now.monotonic + monotonic,
                    wall: now.wall + wall,
                }
            } else {
                now
            }
        })
    }

    #[tokio::test]
    async fn test_store_instance_lock_keeper_stops_after_a_suspension_only_the_wall_clock_saw() {
        // The host was suspended: the monotonic clock didn't move, the wall clock did. The
        // keeper stops at its next check, without asking.
        let Some(db) = crate::store::testing::test_database().await else {
            return;
        };
        let mut held = db.store().hold_instance_lock(fast()).await.expect("lock");
        held.clock = jumping(1, Duration::ZERO, fast().overdue() + fast().every);
        let lost = tokio::time::timeout(Duration::from_secs(20), async { held.keep().await.0 })
            .await
            .expect("the keeper stops");
        assert!(matches!(lost, InstanceLockLost::Overdue(_)), "{lost:?}");
        db.drop_database().await.expect("drop");
    }

    #[tokio::test]
    async fn test_store_instance_lock_keeper_stops_after_a_stall_during_its_check() {
        // The process stalled while its check was in flight: the answer waiting in the
        // socket says nothing about the stall, so the keeper stops as the answer comes in,
        // not one check later.
        let Some(db) = crate::store::testing::test_database().await else {
            return;
        };
        let mut held = db.store().hold_instance_lock(fast()).await.expect("lock");
        // The first reading is the check's sending, the second its answer.
        let stall = fast().overdue() + fast().every;
        held.clock = jumping(2, stall, stall);
        let started = Instant::now();
        let lost = tokio::time::timeout(Duration::from_secs(20), async { held.keep().await.0 })
            .await
            .expect("the keeper stops");
        assert!(matches!(lost, InstanceLockLost::Overdue(_)), "{lost:?}");
        assert!(
            started.elapsed() < fast().every * 2,
            "at the answer of its first check"
        );
        db.drop_database().await.expect("drop");
    }

    #[tokio::test]
    async fn test_store_instance_lock_keeper_stops_after_a_stall_during_the_take() {
        // The process stalled after the take asked for the lock: the grant holds only as of
        // the asking, so the keeper stops at its first step, before any sleep.
        let Some(db) = crate::store::testing::test_database().await else {
            return;
        };
        // The first reading is the take's asking, the second the keeper's first step.
        let stall = fast().overdue() + fast().every;
        let clock = jumping(2, stall, stall);
        let held =
            InstanceLock::wait_for(db.store().pool.connect_options().as_ref(), fast(), &clock)
                .await
                .expect("lock");
        let started = Instant::now();
        let lost = tokio::time::timeout(Duration::from_secs(20), async { held.keep().await.0 })
            .await
            .expect("the keeper stops");
        assert!(matches!(lost, InstanceLockLost::Overdue(_)), "{lost:?}");
        assert!(started.elapsed() < fast().every, "at its first step");
        db.drop_database().await.expect("drop");
    }

    #[test]
    fn test_store_instance_lock_gap_counts_the_longer_clock() {
        let then = Stamp::now();
        let ahead = |monotonic: u64, wall: u64| Stamp {
            monotonic: then.monotonic + Duration::from_secs(monotonic),
            wall: then.wall + Duration::from_secs(wall),
        };
        assert_eq!(then.until(ahead(3, 1)), Duration::from_secs(3));
        assert_eq!(then.until(ahead(1, 30)), Duration::from_secs(30));
        let set_back = Stamp {
            monotonic: then.monotonic + Duration::from_secs(2),
            wall: then.wall - Duration::from_secs(60),
        };
        assert_eq!(then.until(set_back), Duration::from_secs(2));
    }
}
