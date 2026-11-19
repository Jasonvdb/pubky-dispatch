//! The service, in process, behind the client's [`Transport`].
//!
//! [`ServiceTransport`] hands each request to the service's own router
//! ([`pubky_switch::http::router`]), so a request takes the path a network request takes:
//! routing, the body caps, the refusals before the handler, and the handler's processing
//! order (Switch wire 7.1 to 7.4). No socket is opened.

use std::net::SocketAddr;
use std::path::Path;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use axum::body::Body;
use axum::extract::connect_info::MockConnectInfo;
use axum::http::{Request as HttpRequest, header};
use pubky_switch::changes::{ChangeHub, ChangeListener};
use pubky_switch::http::source::ProxyConfig;
use pubky_switch::keys::FileKeyStore;
use pubky_switch::limits::Limits;
use pubky_switch::marks::{AccountMark, Advance, MarkRead, MarkStore, MarkTarget};
use pubky_switch::retire::{self, RetireOptions};
use pubky_switch::service::Service;
use pubky_switch::store::Store;
use pubky_switch::store::testing::{
    REQUIRE_DB_ENV, TEST_DATABASE_URL_ENV, TestDatabase, test_database,
};
use pubky_switch::time::{Clock as ServiceClock, TimeSample, TrustedTime, TrustedTimeConfig};
use pubky_switch_client::TransportError;
use pubky_switch_client::clock::{Clock, TestClock};
use pubky_switch_client::transport::{BoxFuture, FirstSend, Header, Request, Response, Transport};
use pubky_switch_core::chain::ChainTip;
use tower::ServiceExt;

use crate::HarnessError;

/// The largest answer the adapter reads: above every page and directory the service builds.
const MAX_ANSWER_BYTES: usize = 256 * 1024 * 1024;

/// The address requests seem to come from: the service's source-based limits count them as
/// one network source (Switch wire 9.4).
const PEER: ([u8; 4], u16) = ([127, 0, 0, 1], 4000);

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// The service's clock, read from the test clock the client and the signer use, so one clock
/// moves every party.
struct SharedClock {
    clock: Arc<TestClock>,
    start_ms: u64,
}

impl ServiceClock for SharedClock {
    fn now_ms(&self) -> u64 {
        self.clock.now_ms()
    }

    fn monotonic_ms(&self) -> u64 {
        self.clock.now_ms().saturating_sub(self.start_ms)
    }
}

/// Whether a test database is configured: `false` when the service's half of a test is to be
/// skipped, as the service's own tests are (see [`pubky_switch::store::testing`]).
///
/// # Errors
///
/// When a test database is required and not configured.
pub fn database_configured() -> Result<bool, HarnessError> {
    if std::env::var(TEST_DATABASE_URL_ENV).is_ok_and(|url| !url.is_empty()) {
        return Ok(true);
    }
    if std::env::var_os(REQUIRE_DB_ENV).is_some() {
        return Err(HarnessError::Setup(format!(
            "{REQUIRE_DB_ENV} is set, but {TEST_DATABASE_URL_ENV} is not"
        )));
    }
    Ok(false)
}

/// A [`Transport`] to a service in this process; while the service is stopped, every
/// request to it fails to connect.
pub struct ServiceTransport {
    origin: String,
    router: Mutex<Option<axum::Router>>,
}

impl std::fmt::Debug for ServiceTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ServiceTransport({})", self.origin)
    }
}

impl ServiceTransport {
    /// A transport to `service`, which serves `origin`.
    pub fn new(origin: &str, service: Service) -> Self {
        Self {
            origin: origin.to_owned(),
            router: Mutex::new(Some(Self::router_of(service))),
        }
    }

    fn router_of(service: Service) -> axum::Router {
        pubky_switch::http::router(Arc::new(service), ProxyConfig::default())
            .layer(MockConnectInfo(SocketAddr::from(PEER)))
    }

    /// The service stops: the transport drops it, and with it its key store and its mark
    /// store, as a process that ends.
    fn stop(&self) {
        *lock(&self.router) = None;
    }

    /// `service` serves from now on, in place of the one stopped.
    fn serve(&self, service: Service) {
        *lock(&self.router) = Some(Self::router_of(service));
    }

    async fn carry(
        &self,
        request: Request,
        first: Option<&FirstSend>,
    ) -> Result<Response, TransportError> {
        if request.origin != self.origin {
            return Err(TransportError::Connect(format!(
                "no service at {}",
                request.origin
            )));
        }
        let invalid = |error: axum::http::Error| TransportError::InvalidRequest(error.to_string());
        let mut builder = HttpRequest::builder()
            .method(request.method.as_str())
            .uri(request.path_and_query.as_str())
            .header(header::CONTENT_LENGTH, request.body.len());
        for Header { name, value } in &request.headers {
            builder = builder.header(name.as_str(), value.as_str());
        }
        let request = builder.body(Body::from(request.body)).map_err(invalid)?;
        let mut router = lock(&self.router).clone().ok_or_else(|| {
            TransportError::Connect(format!("the service at {} is stopped", self.origin))
        })?;
        let ready = match ServiceExt::<HttpRequest<Body>>::ready(&mut router).await {
            Ok(ready) => ready,
            Err(never) => match never {},
        };
        if let Some(first) = first {
            first.check()?;
        }
        let answer = match tower::Service::call(ready, request).await {
            Ok(answer) => answer,
            Err(never) => match never {},
        };
        let status = answer.status().as_u16();
        let mut headers = Vec::with_capacity(answer.headers().len());
        for (name, value) in answer.headers() {
            let value = value
                .to_str()
                .map_err(|_| TransportError::Other("an answer header that isn't text".into()))?;
            headers.push(Header::new(name.as_str(), value));
        }
        let body = axum::body::to_bytes(answer.into_body(), MAX_ANSWER_BYTES)
            .await
            .map_err(|error| TransportError::Other(error.to_string()))?;
        Ok(Response {
            status,
            headers,
            body: body.to_vec(),
        })
    }
}

impl Transport for ServiceTransport {
    fn send(&self, request: Request) -> BoxFuture<'_, Result<Response, TransportError>> {
        Box::pin(self.carry(request, None))
    }

    fn send_before<'a>(
        &'a self,
        request: Request,
        first: &'a FirstSend,
    ) -> BoxFuture<'a, Result<Response, TransportError>> {
        Box::pin(self.carry(request, Some(first)))
    }
}

/// A service at one origin, on its own test database, with the keys and the clock a test
/// gives it.
pub struct RealSwitch {
    origin: String,
    /// The test database, until it is dropped.
    database: Option<TestDatabase>,
    time: Arc<TrustedTime>,
    clock: Arc<SharedClock>,
    transport: Arc<ServiceTransport>,
    /// The task that forwards the database's change notifications to the service, which
    /// wake its waiting feed reads (Switch wire 7.4.4), as the service's own `main` runs it.
    listening: Option<tokio::task::JoinHandle<()>>,
    /// The service's hub of waiting feed reads.
    changes: Arc<ChangeHub>,
    erasure_faults: pubky_switch::service::ErasureFaults,
    /// The seed of the service key, for a key store opened again on the key directory.
    service_secret: [u8; 32],
    limits: Limits,
    key_dir: tempfile::TempDir,
}

impl std::fmt::Debug for RealSwitch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "RealSwitch({}, {})", self.origin, self.database_name())
    }
}

/// A service on `store` and the key directory `key_dir`, as the service's binary opens one:
/// its key store, and its mark store beside it (Switch wire 7.3).
fn open_service(
    origin: &str,
    store: &Store,
    key_dir: &Path,
    service_secret: [u8; 32],
    time: Arc<TrustedTime>,
    limits: Limits,
) -> Result<Service, HarnessError> {
    let keys = Arc::new(
        FileKeyStore::open_with_service_seed(key_dir, service_secret)
            .map_err(|error| HarnessError::Setup(error.to_string()))?,
    );
    let marks = MarkStore::open(key_dir).map_err(|error| HarnessError::Setup(error.to_string()))?;
    Ok(
        Service::new(origin.to_owned(), store.clone(), keys, marks, time, limits)
            .with_isolated_relays(),
    )
}

/// Forward the database's change notifications to `service`'s hub, as the service's own
/// `main` does.
async fn listen(
    store: &Store,
    service: &Service,
) -> Result<(tokio::task::JoinHandle<()>, Arc<ChangeHub>), HarnessError> {
    let listener = ChangeListener::connect(store)
        .await
        .map_err(|error| HarnessError::Setup(error.to_string()))?;
    let changes = service.changes();
    let listening = tokio::spawn(listener.run(changes.clone(), std::future::pending()));
    Ok((listening, changes))
}

fn setup(error: impl std::fmt::Display) -> HarnessError {
    HarnessError::Setup(error.to_string())
}

impl RealSwitch {
    /// A service at `origin` on a fresh test database, or `None` when no test database is
    /// configured and the test is to be skipped (see [`pubky_switch::store::testing`]).
    ///
    /// It signs with the service key `service_secret` makes, for every account it hosts and
    /// every answer it can't tie to an account (Switch wire 7.1), and keeps its marks beside
    /// that key (Switch wire 7.3). It requires trusted time, as in production, and holds a
    /// sample taken from `clock`.
    ///
    /// # Errors
    ///
    /// When the key store or the mark store can't be made, or the change listener can't
    /// connect.
    pub async fn start(
        origin: &str,
        clock: Arc<TestClock>,
        service_secret: [u8; 32],
        limits: Limits,
    ) -> Result<Option<Self>, HarnessError> {
        let Some(database) = test_database().await else {
            return Ok(None);
        };
        let key_dir = tempfile::tempdir().map_err(setup)?;
        let start_ms = clock.now_ms();
        let clock = Arc::new(SharedClock { clock, start_ms });
        let time = Arc::new(TrustedTime::new(
            TrustedTimeConfig::default(),
            clock.clone(),
        ));
        let service = open_service(
            origin,
            database.store(),
            key_dir.path(),
            service_secret,
            time.clone(),
            limits.clone(),
        )?;
        let (listening, changes) = listen(database.store(), &service).await?;
        let switch = Self {
            origin: origin.to_owned(),
            database: Some(database),
            time,
            clock,
            erasure_faults: service.erasure_faults(),
            transport: Arc::new(ServiceTransport::new(origin, service)),
            listening: Some(listening),
            changes,
            service_secret,
            limits,
            key_dir,
        };
        switch.sample_time();
        Ok(Some(switch))
    }

    /// Stop the service, make `change` to what it leaves, its database and its key
    /// directory, and start it again on both, as an operator does with the service's own
    /// tools: the service drops what it held in memory, its marks and retirements among
    /// them, and reads them anew. Every request meanwhile fails to connect.
    async fn while_stopped<T>(
        &mut self,
        change: impl AsyncFnOnce(&mut TestDatabase, &Path) -> Result<T, HarnessError>,
    ) -> Result<T, HarnessError> {
        let mut database = self
            .database
            .take()
            .ok_or_else(|| setup("the service's database is dropped"))?;
        self.transport.stop();
        if let Some(listening) = self.listening.take() {
            listening.abort();
            // Its end, aborted or not, is all this waits for.
            let _ = listening.await;
        }
        let changed = change(&mut database, self.key_dir.path()).await;
        let started = self.serve_again(&database).await;
        self.database = Some(database);
        started?;
        changed
    }

    #[cfg(test)]
    pub(crate) async fn snapshot_database(&mut self) -> Result<TestDatabase, HarnessError> {
        self.while_stopped(async |db, _| {
            db.snapshot(&pubky_switch::store::DatabaseConfig::default())
                .await
                .map_err(setup)
        })
        .await
    }

    #[cfg(test)]
    pub(crate) async fn restore_database(
        &mut self,
        backup: TestDatabase,
    ) -> Result<(), HarnessError> {
        self.while_stopped(async |db, _| {
            let later = std::mem::replace(db, backup);
            later.drop_database().await.map_err(setup)
        })
        .await
    }

    async fn serve_again(&mut self, database: &TestDatabase) -> Result<(), HarnessError> {
        let service = open_service(
            &self.origin,
            database.store(),
            self.key_dir.path(),
            self.service_secret,
            self.time.clone(),
            self.limits.clone(),
        )?;
        let (listening, changes) = listen(database.store(), &service).await?;
        self.listening = Some(listening);
        self.changes = changes;
        self.erasure_faults = service.erasure_faults();
        self.transport.serve(service);
        Ok(())
    }

    /// Retain a controlled durable erasure outcome after its normal checks.
    pub fn fail_next_erasure(&self, outcome: pubky_switch::service::ErasureOutcome) {
        self.erasure_faults.next(outcome);
    }

    /// The mark `identity` has, which the change needs.
    async fn mark_of(marks: &MarkStore, identity: &str) -> Result<AccountMark, HarnessError> {
        match marks.read(identity).await.map_err(setup)? {
            MarkRead::Mark(mark) => Ok(mark),
            other => Err(setup(format!(
                "{identity} has no mark to change: {other:?}"
            ))),
        }
    }

    /// A restore of `identity`'s state to one write before its mark (Switch wire 7.3,
    /// Table 3, "A restore of the state"), while the service is stopped: its mark moves one
    /// `seq` past the state, with a chain hash no head has, which is what a state restored a
    /// write back shows against its mark. Table 1 judges the account `behind`.
    ///
    /// # Errors
    ///
    /// When the identity has no mark, or the service can't be started again.
    pub async fn restore_behind_mark(&mut self, identity: &str) -> Result<(), HarnessError> {
        self.while_stopped(async |_, key_dir| {
            let marks = MarkStore::open(key_dir).map_err(setup)?;
            let mark = Self::mark_of(&marks, identity).await?;
            let past = MarkTarget {
                head: ChainTip {
                    generation: mark.generation,
                    seq: mark.seq + 1,
                    chain_hash: [0x5a; 32],
                },
                state_version: mark.state_version + 1,
                state_tag: mark.state_tag,
                stamped_ms: mark.time_floor_ms,
            };
            match marks
                .advance(identity, past, mark.key, mark.created_at_ms)
                .await
                .map_err(setup)?
            {
                Advance::Moved(_) => Ok(()),
                other => Err(setup(format!("the mark didn't move: {other:?}"))),
            }
        })
        .await
    }

    /// `identity`'s mark records another chain hash at its pair, as after a restore that
    /// took other writes up to the mark's `seq` (Switch wire 7.3, Table 1: `fork`), while
    /// the service is stopped. Its key and creation time stay.
    ///
    /// # Errors
    ///
    /// When the identity has no mark, or the service can't be started again.
    pub async fn fork_mark(&mut self, identity: &str) -> Result<(), HarnessError> {
        self.while_stopped(async |_, key_dir| {
            let marks = MarkStore::open(key_dir).map_err(setup)?;
            let mark = Self::mark_of(&marks, identity).await?;
            let mut other = MarkTarget {
                head: mark.head(),
                state_version: mark.state_version,
                state_tag: mark.state_tag,
                stamped_ms: mark.time_floor_ms,
            };
            other.head.chain_hash[0] ^= 0xff;
            marks.delete(identity).await.map_err(setup)?;
            marks
                .write_anew(identity, other, mark.key, mark.created_at_ms)
                .await
                .map_err(setup)?;
            Ok(())
        })
        .await
    }

    /// `identity`'s mark is lost from a store that reads (Switch wire 7.3, Table 1:
    /// `mark_lost`), while the service is stopped.
    ///
    /// # Errors
    ///
    /// When the mark can't be deleted, or the service can't be started again.
    pub async fn lose_mark(&mut self, identity: &str) -> Result<(), HarnessError> {
        self.while_stopped(async |_, key_dir| {
            let marks = MarkStore::open(key_dir).map_err(setup)?;
            marks.delete(identity).await.map_err(setup)
        })
        .await
    }

    /// `identity`'s account is lost from the database, its mark staying, as after a restore
    /// to before the enrollment or a lost database (Switch wire 7.3, Table 1, row "None"),
    /// while the service is stopped: the store deletes the account's row and, by its
    /// cascade, every row of its state. Nothing goes to the mark store, so no erasure's
    /// record names the identity.
    ///
    /// # Errors
    ///
    /// When the database has no such account, or the service can't be started again.
    pub async fn lose_account(&mut self, identity: &str) -> Result<(), HarnessError> {
        let now_ms = self.clock.now_ms();
        self.while_stopped(async |database, _| {
            let account = database
                .store()
                .begin(identity)
                .await
                .map_err(setup)?
                .ok_or_else(|| setup(format!("no account {identity}")))?;
            account.erase(now_ms).await.map_err(setup)
        })
        .await
    }

    /// `identity`'s record at `key` is dropped from the database, while the service is
    /// stopped, as a faulty service that lost it would: reads answer `404` and listings
    /// leave it out (Switch spec 10.3.1 "Absence").
    ///
    /// # Errors
    ///
    /// When the database holds no such record, or the service can't be started again.
    pub async fn drop_record(
        &mut self,
        identity: &str,
        key: &[u8; 32],
    ) -> Result<(), HarnessError> {
        self.while_stopped(async |database, _| {
            if database.drop_record(identity, key).await.map_err(setup)? {
                Ok(())
            } else {
                Err(setup(format!("{identity} holds no record at the key")))
            }
        })
        .await
    }

    /// The operator retires `generation` for `identity` with the service's own step
    /// ([`pubky_switch::retire`]), the service stopped as the step requires (Switch spec
    /// 6.5; Switch wire 7.3, Table 3).
    ///
    /// # Errors
    ///
    /// When the step refuses or fails, or the service can't be started again.
    pub async fn retire(&mut self, identity: &str, generation: u64) -> Result<(), HarnessError> {
        let origin = self.origin.clone();
        self.while_stopped(async |database, key_dir| {
            let options = RetireOptions {
                database: database.options().clone(),
                key_dir: key_dir.to_path_buf(),
                origin,
                identity: identity.to_owned(),
                generation,
            };
            retire::run(&options).await.map(|_| ()).map_err(setup)
        })
        .await
    }

    /// The origin it serves.
    pub fn origin(&self) -> &str {
        &self.origin
    }

    /// The transport to it.
    pub fn transport(&self) -> Arc<ServiceTransport> {
        self.transport.clone()
    }

    /// Give the service a time sample that agrees with the clock, as its time source would
    /// (Switch spec 10.1). Call it after moving the clock, so the sample never gets too old.
    pub fn sample_time(&self) {
        self.time.note(
            TimeSample {
                utc_ms: self.clock.now_ms(),
                uncertainty_ms: 0,
            },
            self.clock.monotonic_ms(),
        );
    }

    /// How many accounts have a feed read held at the service now, waiting for a change
    /// (Switch wire 7.4.4 `wait`). A read counts from before its first look at the account,
    /// so a change made once it counts is one the read sees.
    pub fn held_reads(&self) -> usize {
        self.changes.waiting()
    }

    /// Close the service's connections to its database, as a server that takes no more:
    /// every later request fails in the service's storage. For a test of how that shows.
    pub async fn close_connections(&self) {
        if let Some(store) = self.store() {
            store.close().await;
        }
    }

    #[cfg(test)]
    pub(crate) fn push_service(&self, relay: SocketAddr) -> Result<Service, HarnessError> {
        let store = self
            .store()
            .ok_or_else(|| setup("the database is closed"))?;
        Ok(open_service(
            &self.origin,
            &store,
            self.key_dir.path(),
            self.service_secret,
            self.time.clone(),
            self.limits.clone(),
        )?
        .with_relay_route(Arc::new(move |_| Some(relay))))
    }

    /// The service's store; `None` once its database is dropped.
    pub(crate) fn store(&self) -> Option<Store> {
        self.database
            .as_ref()
            .map(|database| database.store().clone())
    }

    /// The test database's name; empty once it is dropped.
    pub fn database_name(&self) -> &str {
        self.database.as_ref().map_or("", TestDatabase::name)
    }

    /// Drop the test database, and wait until it is gone. A switch that goes away without
    /// this, as when its test panics, still drops its database: the test database drops
    /// itself ([`pubky_switch::store::testing::TestDatabase`]).
    ///
    /// # Errors
    ///
    /// When the server refuses.
    pub async fn close(mut self) -> Result<(), HarnessError> {
        // The listener goes first: left running, it would try to connect to a database
        // that is gone.
        if let Some(listening) = self.listening.take() {
            listening.abort();
            // Its end, aborted or not, is all this waits for.
            let _ = listening.await;
        }
        match self.database.take() {
            Some(database) => database
                .drop_database()
                .await
                .map_err(|error| HarnessError::Setup(error.to_string())),
            None => Ok(()),
        }
    }
}

impl Drop for RealSwitch {
    fn drop(&mut self) {
        // A switch dropped without `close`, as when its test panics: the listener stops
        // with it.
        if let Some(listening) = self.listening.take() {
            listening.abort();
        }
    }
}
