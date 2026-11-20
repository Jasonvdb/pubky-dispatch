//! The Switch service: the processing order of every request (Switch wire 7.3) and the
//! endpoints, as the [`Handler`] behind the HTTP transport.
//!
//! Each request to an account runs in one transaction on it ([`crate::store`]): its time is
//! stamped, its caller authenticated, the staged gate applied, then the endpoint. The
//! account and its mark are judged together first, before the lock and again under it
//! (Switch wire 7.3 steps 2 and 10, `marking`). Every answer is signed with the service key,
//! the one key the service signs with, by the key the verdict gives (Switch wire 7.1, 7.3
//! Table 2). An answer that carries a `seq`, a proof or a head is signed under the account's
//! lock and goes out only once the commit is durable and the account's mark has moved to its
//! head (Switch wire 7.3 step 10).
//!
//! Served so far: `POST /v1/enroll`, `PUT /v1/{id}/identity`, the public
//! `GET /v1/{id}/identity`, `POST /v1/{id}/ops`, `GET /v1/{id}/feed`,
//! `POST /v1/{id}/inbox`, `PUT /v1/{id}/peers`, `GET /v1/{id}/claims/{claim_key}`,
//! `GET /v1/{id}/records/{key}` and `GET /v1/{id}/records`, `GET /v1/{id}/allow`,
//! `POST`, `GET` and `DELETE /v1/{id}/connect`, `GET /v1/{id}/apps`,
//! `POST /v1/{id}/apps/{app_id}/revoke`, `GET /v1/{id}/directory`,
//! `GET` and `POST /v1/{id}/apps/{app_id}/keys`, `POST /v1/{id}/apps/{app_id}/leave`,
//! `POST /v1/{id}/recovery/admission` and `POST /v1/{id}/recovery/upload`,
//! `PUT` and `GET /v1/{id}/handover`, `POST /v1/{id}/erase`, and `PUT /v1/{id}/push`.
//! Notifying entries and eligible connect requests queue webhooks in their own transaction.
//! [`Service::deliver_pushes_until`] sends them to the relays. The freeze, the export and
//! the import are answered `503 unavailable`.
//!
//! An account a restored database brought back after its erasure is erased again at its
//! judgement, before anything is served or signed for it (Switch wire 7.3, Table 1;
//! `erase`).

mod account;
mod admission;
mod allow;
mod app_keys;
mod apps;
pub mod batch;
mod claims;
mod connect;
mod directory;
mod enroll;
mod erase;
#[cfg(any(test, feature = "test-util"))]
mod erasure_testing;
#[cfg(any(test, feature = "test-util"))]
pub use erasure_testing::{ErasureFaults, ErasureOutcome};
mod feed;
mod handover;
mod identity;
mod inbox;
mod marking;
mod peers;
mod purge;
mod push;
mod records;
mod recovery;
mod retention;
pub mod rules;
mod signed;
mod sweeps;
mod upload;
pub(crate) mod verdict;
mod webhooks;

#[cfg(any(test, feature = "test-util"))]
pub use marking::RequestPause;
pub use push::Resolver;
pub use recovery::AdmissionEnd;
pub use webhooks::PushRound;
#[cfg(any(test, feature = "test-util"))]
pub use webhooks::RelayRoute;

use std::sync::Arc;

use pubky_switch_core::{
    chain::SignedHead,
    http::{self as wire_http, RequestTarget, header},
    records::{AppCert, IdentityDoc},
};

use crate::{
    changes::ChangeHub,
    http::{
        Handler, HandlerFuture, Refusal, SwitchRequest, SwitchResponse,
        error::{ApiError, ErrorCode, is_failed_authentication},
        route::Call,
        source::NetworkSource,
    },
    keys::{KeyStore, ServiceSigner},
    limits::Limits,
    marks::MarkStore,
    ratelimit::{FailedAuthentications, KeyedWindows, MinuteWindows},
    store::{AccountTxn, LockFreshness, MarkCoverage, ServiceRun, Store, StoreError},
    time::TrustedTime,
};

use self::rules::{Caller, Claimed, decode_claim, names_this_service, staged_gate};
use self::signed::{AnswerTime, Asked, Received, sign_answer};
use self::verdict::{RequestClass, Route};
use pubky_switch_core::http::Uncompared;

/// How many claims whose time has passed one request deletes at most (Switch wire 7.3
/// step 4); the rest go with the next requests.
const DUE_CLAIMS_PER_REQUEST: u64 = 64;

/// The service.
pub struct Service {
    origin: String,
    store: Store,
    keys: Arc<dyn KeyStore>,
    /// The per-account marks, the retirements and the store's identity (Switch wire 7.3).
    marks: MarkStore,
    /// This run of the service, which the states it stamps record (Switch wire 7.3,
    /// "Trusted time").
    run: ServiceRun,
    /// When the instance lock was last confirmed, where the service holds one: a commit that
    /// gives out a `seq`, signs a head or moves a mark is refused once it is stale.
    lock_freshness: Option<LockFreshness>,
    time: Arc<TrustedTime>,
    limits: Limits,
    failed_auth: FailedAuthentications,
    reads_per_source: MinuteWindows<(String, NetworkSource)>,
    reads_per_account: MinuteWindows<String>,
    operation_rate: KeyedWindows<(String, [u8; 16])>,
    control_rate: KeyedWindows<(String, [u8; 16])>,
    invite_rate: KeyedWindows<(String, [u8; 32])>,
    stranger_rate: KeyedWindows<String>,
    /// Connect requests per sender identity, per account (Switch wire 9.4).
    connect_rate: KeyedWindows<(String, [u8; 32])>,
    sender_rate: KeyedWindows<(String, [u8; 32])>,
    sender_app_rate: KeyedWindows<(String, [u8; 16])>,
    notify_rate: KeyedWindows<(String, [u8; 32])>,
    /// Recovery uploads per app per hour (Switch wire 7.4.14).
    upload_rate: KeyedWindows<(String, [u8; 16])>,
    /// The `(account, app)` whose recovery upload's items are being judged before the lock:
    /// one at a time for each.
    upload_judging: parking_lot::Mutex<std::collections::HashSet<(String, [u8; 16])>>,
    /// Recovery uploads whose items were judged before the account's lock, and under it.
    judged_before_lock: std::sync::atomic::AtomicU64,
    judged_under_lock: std::sync::atomic::AtomicU64,
    /// Requests answered with the recovery notice (Switch wire 7.3, 7.6), and the accounts
    /// whose notice was logged.
    mark_refusals: std::sync::atomic::AtomicU64,
    mark_refused_accounts: parking_lot::Mutex<std::collections::HashSet<String>>,
    /// Whether a notice found the logged accounts full and said so, once.
    mark_refusals_overflowed: std::sync::atomic::AtomicBool,
    /// Requests refused because they depend on the service's time and trusted time is
    /// missing (Switch spec 10.1).
    time_refusals: std::sync::atomic::AtomicU64,
    changes: Arc<ChangeHub>,
    /// Where entry IDs come from: random, opaque to senders (Switch wire 1.7).
    entry_ids: EntryIds,
    /// Whether the service takes push registrations (Switch wire 8.1); off, every one is
    /// `400`, as a service that sends no pushes answers.
    push_enabled: bool,
    /// Resolves relay hosts for the address check (Switch wire 8.1, 8.2).
    resolver: Resolver,
    /// How many webhooks delivery sends at once (`push.concurrency`).
    push_concurrency: usize,
    /// How long the mark store keeps an erasure's record: the age of the oldest database backup
    /// kept (`keys.backup_retention_days`); `None` keeps it for good (Switch spec 6.5).
    backup_retention_ms: Option<u64>,
    /// Turns to hold a registration while its webhook is signed, each on a connection of the
    /// request pool: a quarter of the pool, at least one, so requests keep the rest.
    push_holds: tokio::sync::Semaphore,
    /// Where webhooks connect in tests.
    #[cfg(any(test, feature = "test-util"))]
    relay_route: Option<webhooks::RelayRoute>,
    /// Whether test relays require an explicit route to a loopback listener.
    #[cfg(any(test, feature = "test-util"))]
    isolated_relays: bool,
    /// A pause before the next mark move, for tests of what lands between a commit and
    /// its move.
    #[cfg(any(test, feature = "test-util"))]
    mark_move_pause: parking_lot::Mutex<Option<RequestPause>>,
    /// A pause after a request's commit and mark move, before its answer is released.
    #[cfg(any(test, feature = "test-util"))]
    release_pause: parking_lot::Mutex<Option<RequestPause>>,
    /// A pause after a feed's mark move and before its final signing turn.
    #[cfg(any(test, feature = "test-util"))]
    feed_sign_pause: parking_lot::Mutex<Option<RequestPause>>,
    /// A pause after a feed's final checks, with its account lock still held.
    #[cfg(any(test, feature = "test-util"))]
    feed_locked_pause: parking_lot::Mutex<Option<RequestPause>>,
    /// A pause after retention's reads and before its checkpoint signature.
    #[cfg(any(test, feature = "test-util"))]
    checkpoint_sign_pause: parking_lot::Mutex<Option<RequestPause>>,
    /// A pause before withdrawing an erasure whose deletion failed.
    #[cfg(any(test, feature = "test-util"))]
    erase_failure_pause: parking_lot::Mutex<Option<RequestPause>>,
    #[cfg(any(test, feature = "test-util"))]
    erasure_faults: ErasureFaults,
}

/// A source of entry IDs.
type EntryIds = Arc<dyn Fn() -> [u8; 16] + Send + Sync>;

/// A random entry ID; all zeros only if the system has no randomness, which the service's
/// own keys would have failed on first.
fn random_entry_id() -> [u8; 16] {
    let mut id = [0u8; 16];
    let _ = getrandom::fill(&mut id);
    id
}

impl std::fmt::Debug for Service {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Service")
            .field("origin", &self.origin)
            .finish_non_exhaustive()
    }
}

/// An answer before it is signed.
#[derive(Debug)]
struct Answer {
    status: u16,
    body: Vec<u8>,
    head: Option<SignedHead>,
    retry_after: Option<u64>,
    cacheable: bool,
    /// Never cached: `Cache-Control: no-store`.
    no_store: bool,
    /// The key the account is answered with once the request commits, where the request
    /// changes it: a delivery that starts a generation names its own (Switch wire 7.3 under
    /// Table 2).
    key: Option<[u8; 32]>,
    /// The request starts a generation (Switch wire 3.3): where the mark is lost, it is
    /// written anew at the new generation's first head (Table 3).
    starts_generation: bool,
}

/// How a request completes once its endpoint has run under the account lock (Switch wire 7.3).
enum AccountOutcome {
    Commit(AfterCommit),
    Erase(erase::Erasure),
}

/// What to answer once the account commit and mark move have finished.
enum AfterCommit {
    Ready(Answer),
    Page {
        read: Box<PageRead>,
        head: SignedHead,
    },
    Feed(Box<feed::FeedRead>),
}

impl AccountOutcome {
    fn ready(answer: Answer) -> Self {
        Self::Commit(AfterCommit::Ready(answer))
    }

    fn page(read: PageRead, head: SignedHead) -> Self {
        Self::Commit(AfterCommit::Page {
            read: Box::new(read),
            head,
        })
    }
}

/// A page read after commit, returned with the head signed under the account lock.
enum PageRead {
    /// A `GET /claims` answer's entries.
    Claim(claims::ClaimRead),
    /// `GET /allow`'s lists, from the snapshot of the state under the lock.
    Allow(allow::AllowRead),
    /// A `GET /records` page, from the snapshot of the state under the lock.
    Records(records::RecordsRead),
}

impl Answer {
    fn ok(body: Vec<u8>) -> Self {
        Self {
            status: 200,
            body,
            head: None,
            retry_after: None,
            cacheable: false,
            no_store: false,
            key: None,
            starts_generation: false,
        }
    }

    fn error(error: &ApiError) -> Self {
        Self {
            status: error.status(),
            body: error.body(),
            head: None,
            retry_after: error.retry_after,
            cacheable: false,
            no_store: false,
            key: None,
            starts_generation: false,
        }
    }

    fn with_head(mut self, head: Option<SignedHead>) -> Self {
        self.head = head;
        self
    }
}

/// A refusal under the account's lock: the error, and whether the answer may carry the
/// current head.
#[derive(Debug)]
struct Refused {
    error: ApiError,
    head: bool,
}

impl Refused {
    fn with_head(error: ApiError) -> Self {
        Self { error, head: true }
    }
}

/// What a request's caller proved before the account's lock (Switch wire 7.2 Order).
#[derive(Default)]
struct PreLock {
    /// The caller its headers claim, for a call that isn't the public read.
    caller: Option<Claimed>,
    /// An own app whose request verified.
    verified: Option<batch::VerifiedApp>,
    /// An app of another identity's certificate, checked.
    other: Option<AppCert>,
}

/// Delivery, upload or push work prepared before taking the account lock (Switch wire 7.2).
enum Prepared {
    /// A delivered `identity.json`, read and verified (Switch wire 7.4.5).
    Delivery(Box<Result<peers::Delivered, ApiError>>),
    /// A recovery upload's rate slot and its items, judged against the account as it stood
    /// before the lock (Switch wire 7.4.14).
    Upload(Box<upload::PreparedUpload>),
    /// A push registration's body, checked, and the key minted for a start (Switch wire 8.1).
    Push(Box<push::PreparedPush>),
}

fn store_error(error: &StoreError) -> ApiError {
    tracing::warn!(%error, "storage");
    ApiError::unavailable("7.6: a temporary failure")
}

impl Service {
    /// A service at `origin`, the switch origin `identity.json` names, with the default
    /// settings, [`Service::started`]. The binary sets its settings first, then runs
    /// [`Service::started`] itself.
    pub async fn start(
        origin: String,
        store: Store,
        keys: Arc<dyn KeyStore>,
        marks: MarkStore,
        time: Arc<TrustedTime>,
        limits: Limits,
    ) -> Self {
        Self::new(origin, store, keys, marks, time, limits)
            .started()
            .await
    }

    /// The passes a service runs once, before it takes requests, after its settings: the
    /// push keys left owed go (Switch wire 8.1), then the accounts a restored database
    /// brought back after their erasure, and the erasures' leftover marks (Switch wire 7.3,
    /// Table 1; the check at each request covers a failure here), then the erasures' records
    /// past `keys.backup_retention_days`.
    pub async fn started(self) -> Self {
        let _ = self.sweep_erased_keys().await;
        self.reconcile_erasure_outcomes().await;
        let _ = self.erase_restored_accounts().await;
        self.delete_leftover_marks().await;
        self.forget_aged_erasures().await;
        self
    }

    /// The service holding the instance lock that `freshness` follows: a commit that gives
    /// out a `seq`, signs a head or moves a mark is refused once its last confirmed check is
    /// older than two checks (Switch spec 6.5).
    #[must_use]
    pub fn with_lock_freshness(mut self, freshness: LockFreshness) -> Self {
        // Every mark write waits for no stale check, whatever path makes it.
        self.marks = self.marks.gated(freshness.clone());
        self.lock_freshness = Some(freshness);
        self
    }

    /// Keep the erasures' records for `days` after their erasure, the age of the
    /// oldest database backup the operator keeps (`keys.backup_retention_days`, Switch spec
    /// 6.5); `None` keeps them for good.
    #[must_use]
    pub fn with_backup_retention_days(mut self, days: Option<u64>) -> Self {
        self.backup_retention_ms = days.map(|days| days.saturating_mul(24 * 60 * 60 * 1000));
        self
    }

    /// A service at `origin`, the switch origin `identity.json` names.
    ///
    /// Push is on, as `push.enabled` defaults: a service that takes registrations must also
    /// run [`Service::deliver_pushes_until`], as the binary does, to send queued webhooks and
    /// drop those past their minute. [`Service::with_push`] turns it
    /// off.
    pub fn new(
        origin: String,
        store: Store,
        keys: Arc<dyn KeyStore>,
        marks: MarkStore,
        time: Arc<TrustedTime>,
        limits: Limits,
    ) -> Self {
        // The refusal counters start at 0, each label there from the start, so a rule on
        // their increase sees the first refusal too.
        for reason in ["behind", "fork", "mark_lost"] {
            metrics::counter!("pubky_switch_mark_refusals_total", "reason" => reason).increment(0);
        }
        for call in ["ops", "append", "directory", "put_peers"] {
            metrics::counter!("pubky_switch_time_refusals_total", "call" => call).increment(0);
        }
        let failed_auth = FailedAuthentications::new(limits.auth_failures_per_source_per_min);
        let push_holds = tokio::sync::Semaphore::new(
            usize::try_from(store.max_connections() / 4)
                .unwrap_or(1)
                .max(1),
        );
        Self {
            origin,
            store,
            keys,
            marks,
            run: ServiceRun::start(),
            lock_freshness: None,
            time,
            limits,
            failed_auth,
            reads_per_source: MinuteWindows::default(),
            reads_per_account: MinuteWindows::default(),
            operation_rate: KeyedWindows::default(),
            control_rate: KeyedWindows::default(),
            invite_rate: KeyedWindows::default(),
            stranger_rate: KeyedWindows::default(),
            connect_rate: KeyedWindows::default(),
            sender_rate: KeyedWindows::default(),
            sender_app_rate: KeyedWindows::default(),
            notify_rate: KeyedWindows::default(),
            upload_rate: KeyedWindows::hours(),
            upload_judging: parking_lot::Mutex::default(),
            judged_before_lock: std::sync::atomic::AtomicU64::new(0),
            judged_under_lock: std::sync::atomic::AtomicU64::new(0),
            mark_refusals: std::sync::atomic::AtomicU64::new(0),
            mark_refused_accounts: parking_lot::Mutex::default(),
            mark_refusals_overflowed: std::sync::atomic::AtomicBool::new(false),
            time_refusals: std::sync::atomic::AtomicU64::new(0),
            changes: ChangeHub::new(),
            entry_ids: Arc::new(random_entry_id),
            push_enabled: crate::config::PushConfig::default().enabled,
            resolver: push::system_resolver(),
            push_concurrency: crate::config::PushConfig::default().concurrency,
            backup_retention_ms: None,
            push_holds,
            #[cfg(any(test, feature = "test-util"))]
            relay_route: None,
            #[cfg(any(test, feature = "test-util"))]
            isolated_relays: false,
            #[cfg(any(test, feature = "test-util"))]
            mark_move_pause: parking_lot::Mutex::default(),
            #[cfg(any(test, feature = "test-util"))]
            release_pause: parking_lot::Mutex::default(),
            #[cfg(any(test, feature = "test-util"))]
            feed_sign_pause: parking_lot::Mutex::default(),
            #[cfg(any(test, feature = "test-util"))]
            feed_locked_pause: parking_lot::Mutex::default(),
            #[cfg(any(test, feature = "test-util"))]
            checkpoint_sign_pause: parking_lot::Mutex::default(),
            #[cfg(any(test, feature = "test-util"))]
            erase_failure_pause: parking_lot::Mutex::default(),
            #[cfg(any(test, feature = "test-util"))]
            erasure_faults: ErasureFaults::default(),
        }
    }

    /// The service with push registrations on or off (`push.enabled`, Switch wire 8.1): off,
    /// `PUT /push` is `400`, as at a service that sends no pushes, and no entry queues a
    /// webhook.
    #[must_use]
    pub fn with_push(mut self, enabled: bool) -> Self {
        self.push_enabled = enabled;
        self
    }

    /// The service sending at most `concurrency` webhooks at once (`push.concurrency`).
    #[must_use]
    pub fn with_push_concurrency(mut self, concurrency: usize) -> Self {
        self.push_concurrency = concurrency.max(1);
        self
    }

    /// The service connecting webhooks, over plain HTTP, to the listener `route` maps each
    /// checked address to, for tests whose relays run in process.
    #[cfg(any(test, feature = "test-util"))]
    #[must_use]
    pub fn with_relay_route(mut self, route: webhooks::RelayRoute) -> Self {
        self.relay_route = Some(route);
        self
    }

    /// The service registering test relays without DNS and delivering only through an
    /// explicit [`Self::with_relay_route`] to loopback listeners. Without a route,
    /// delivery is refused. Later resolver or route changes retain this restriction.
    ///
    /// Relay names resolve to a documentation address, accepted only in this mode;
    /// production relay validation is unchanged (Switch wire 8.1, 8.2).
    #[cfg(any(test, feature = "test-util"))]
    #[must_use]
    pub fn with_isolated_relays(mut self) -> Self {
        self.isolated_relays = true;
        self.resolver =
            Arc::new(|_host| Box::pin(async { Ok(vec![push::ISOLATED_RELAY_ADDRESS]) }));
        self
    }

    /// The service resolving relay hosts with `resolver`, for tests whose relays have no
    /// DNS names.
    #[cfg(any(test, feature = "test-util"))]
    #[must_use]
    pub fn with_resolver(mut self, resolver: Resolver) -> Self {
        self.resolver = resolver;
        self
    }

    /// Pause the next mark move, after its commit, until [`RequestPause::release`], for
    /// tests of what lands between a commit and its move (Switch wire 7.3, "Moving it").
    #[cfg(any(test, feature = "test-util"))]
    pub fn pause_next_mark_move(&self) -> RequestPause {
        let pause = RequestPause::default();
        *self.mark_move_pause.lock() = Some(pause.clone());
        pause
    }

    /// Pause the next answer of a request under an account's lock once its commit and mark
    /// move are done, before it is released, until [`RequestPause::release`]: for tests of
    /// a crash in between (Switch wire 7.3, "Moving it").
    #[cfg(any(test, feature = "test-util"))]
    pub fn pause_next_release(&self) -> RequestPause {
        let pause = RequestPause::default();
        *self.release_pause.lock() = Some(pause.clone());
        pause
    }

    /// Pause the next feed answer after its mark move and before its final account lock,
    /// for tests of erasure and generation changes before signing (Switch wire 7.3).
    #[cfg(any(test, feature = "test-util"))]
    pub fn pause_next_feed_sign(&self) -> RequestPause {
        let pause = RequestPause::default();
        *self.feed_sign_pause.lock() = Some(pause.clone());
        pause
    }

    /// Pause the next feed after its final lifecycle checks, while it holds the account
    /// lock, for tests that transitions cannot overtake its signatures (Switch wire 7.3).
    #[cfg(any(test, feature = "test-util"))]
    pub fn pause_next_feed_sign_locked(&self) -> RequestPause {
        let pause = RequestPause::default();
        *self.feed_locked_pause.lock() = Some(pause.clone());
        pause
    }

    /// Pause the next checkpoint after retention's reads, for tests of an instance lock
    /// that expires while a request waits for storage (Switch spec 6.5).
    #[cfg(any(test, feature = "test-util"))]
    pub fn pause_next_checkpoint_sign(&self) -> RequestPause {
        let pause = RequestPause::default();
        *self.checkpoint_sign_pause.lock() = Some(pause.clone());
        pause
    }

    /// Pause after an erasure's deletion fails and before its record is withdrawn, for
    /// tests of requests waiting on that identity (Switch wire 7.3, Table 3).
    #[cfg(any(test, feature = "test-util"))]
    pub fn pause_next_erase_failure(&self) -> RequestPause {
        let pause = RequestPause::default();
        *self.erase_failure_pause.lock() = Some(pause.clone());
        pause
    }

    /// The service with entry IDs from `ids`, for tests that replay the vectors' fixed ones.
    #[cfg(any(test, feature = "test-util"))]
    #[must_use]
    pub fn with_entry_ids(mut self, ids: impl Fn() -> [u8; 16] + Send + Sync + 'static) -> Self {
        self.entry_ids = Arc::new(ids);
        self
    }

    /// This run of the service, for tests that make accounts it stamped (Switch wire 7.3,
    /// "Trusted time").
    #[cfg(any(test, feature = "test-util"))]
    pub fn run(&self) -> ServiceRun {
        self.run
    }

    /// How many recovery uploads had their items judged before the account's lock, and how
    /// many under it, for tests of what a refused upload costs (Switch wire 7.4.14).
    #[cfg(any(test, feature = "test-util"))]
    pub fn upload_judgments(&self) -> (u64, u64) {
        use std::sync::atomic::Ordering::Relaxed;
        (
            self.judged_before_lock.load(Relaxed),
            self.judged_under_lock.load(Relaxed),
        )
    }

    /// How many requests were answered with the recovery notice
    /// (`pubky_switch_mark_refusals_total`).
    pub fn mark_refusals(&self) -> u64 {
        self.mark_refusals
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    /// How many requests were refused for lack of trusted time
    /// (`pubky_switch_time_refusals_total`).
    pub fn time_refusals(&self) -> u64 {
        self.time_refusals
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    /// The refusal of a request that depends on the service's time while trusted time is
    /// missing (Switch spec 10.1), counted by `call` apart from every other `503`.
    pub(super) fn refused_without_trusted_time(
        &self,
        call: &'static str,
        message: &'static str,
    ) -> ApiError {
        metrics::counter!("pubky_switch_time_refusals_total", "call" => call).increment(1);
        self.time_refusals
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        ApiError::unavailable(message)
    }

    /// How many counts of its rate limits and of failed authentications the service keeps
    /// for `account`, for tests of what an erasure forgets (Switch wire 7.4.16, 9.4).
    #[cfg(any(test, feature = "test-util"))]
    pub fn counted_at(&self, account: &str) -> usize {
        self.failed_auth.counted_at(account)
            + self.reads_per_source.counted(|(at, _)| at == account)
            + self.reads_per_account.counted(|at| at == account)
            + self.operation_rate.counted(|(at, _)| at == account)
            + self.control_rate.counted(|(at, _)| at == account)
            + self.invite_rate.counted(|(at, _)| at == account)
            + self.stranger_rate.counted(|at| at == account)
            + self.connect_rate.counted(|(at, _)| at == account)
            + self.sender_rate.counted(|(at, _)| at == account)
            + self.sender_app_rate.counted(|(at, _)| at == account)
            + self.notify_rate.counted(|(at, _)| at == account)
            + self.upload_rate.counted(|(at, _)| at == account)
    }

    /// The hub that wakes waiting feed reads. Run a [`crate::changes::ChangeListener`]
    /// into it, so every committed change wakes them.
    pub fn changes(&self) -> Arc<ChangeHub> {
        self.changes.clone()
    }

    /// The failed-authentication counts, for monitoring.
    pub fn failed_authentications(&self) -> &FailedAuthentications {
        &self.failed_auth
    }

    async fn serve(&self, request: SwitchRequest) -> SwitchResponse {
        // One reading gives both the time base and whether it is trusted, so nothing that
        // waits for trusted time runs on a base read without it.
        let reading = self.time.read();
        let base_ms = reading.base_ms;
        let due = reading.trusted.then_some(base_ms);
        // The request as received, which every answer to it signs (Switch wire 7.1).
        let received = Received::read(&request, &self.origin);
        let asked = received.asked();
        // A signed request header sent more than once, or present with a value empty or not
        // printable ASCII, is refused before the account is looked up and before any
        // signature work: the service never chooses between two signed values, nor reads one
        // otherwise than its answer binds it. The public read uses none of them (Switch wire
        // 7.1 "Each header once, as text").
        if let Some(reason) = received.broken_header_rule()
            && request.route.call != Call::GetIdentity
        {
            // Enrollment and erasure exclude every answer from time comparison, even
            // when the request breaks the header rule (Switch wire 7.1 Timestamp).
            let at = match request.route.call {
                Call::Enroll => AnswerTime::TimeBase(base_ms, Uncompared::Enrollment),
                Call::GetAccount => AnswerTime::TimeBase(base_ms, Uncompared::AccountDiscovery),
                Call::Erase => AnswerTime::TimeBase(base_ms, Uncompared::Erasure),
                _ => AnswerTime::Unbound(base_ms),
            };
            return self.service_error(asked, at, &ApiError::bad_request(reason));
        }
        if request.route.call == Call::Enroll {
            return self.enroll(&request, base_ms, asked).await;
        }
        if request.route.call == Call::GetAccount {
            return self.get_account(&request, base_ms, asked).await;
        }
        // Step 1: an unknown route, signed with the service key like every answer.
        let Some(account) = request.route.account.clone() else {
            let error = ApiError::not_found("no such route");
            return self.service_error(asked, AnswerTime::Unbound(base_ms), &error);
        };
        let call = &request.route.call;
        if *call == Call::Erase {
            match self.reconcile_erasure(&account).await {
                Ok(false) => return self.retry_erasure(&account, &request, base_ms, asked).await,
                Ok(true) => {}
                Err(error) => {
                    return self.service_error(
                        asked,
                        AnswerTime::TimeBase(base_ms, Uncompared::Erasure),
                        &error,
                    );
                }
            }
        }
        // Step 2: the account and its mark, judged together, before the lock (Switch wire
        // 7.3, Table 1). A failure here is a `503 unavailable`, which counts in no comparison
        // (Switch wire 7.1 Timestamp).
        let (found, judged) = match self.judge_at_step_two(&account).await {
            Ok(judged) => judged,
            Err(error) => {
                let at = AnswerTime::TimeBase(base_ms, Uncompared::Unavailable);
                return self.service_error(asked, at, &error);
            }
        };
        let class = marking::class_of(&request);
        let routed = verdict::answer(&judged.judgement, &class, self.current_key());
        // The last time the service committed for the identity: the time an answer that
        // commits nothing carries, so none shows a time later than the next commit stamps,
        // even after the time base went back. An identity without an account has none: every
        // answer to it counts in no comparison and carries the time base (Switch wire 7.1
        // Timestamp, spec 10.1). A state another run of the service stamped, as a restored
        // one, takes its mark's time floor where that is later, so no answer's time goes back
        // across a restore; the mark was read before the account (Switch wire 7.3, "Trusted
        // time").
        let mark_floor_ms = judged.time_floor_ms();
        let committed_ms = found
            .as_ref()
            .map(|found| found.committed_ms(self.run, mark_floor_ms));
        // The identity's service time (step 3), which the checks before the lock that depend
        // on time take: the time base, or the last time it stamped where the time base is
        // earlier.
        let service_ms = committed_ms.map_or(base_ms, |committed| base_ms.max(committed));
        if matches!(routed.route, Route::Notice(_))
            || (matches!(routed.route, Route::NotHosted)
                && judged.mark().is_some()
                && matches!(
                    judged.judgement.decision.verdict,
                    verdict::Verdict::NotHosted { delete_mark: false }
                ))
        {
            // A surviving zero mark also supplies a creation for the authenticated
            // comparison before its not-hosted answer (Switch account binding 1).
            // The notice replaces every later answer, a `401` and a `403` before
            // authentication included, but a `429` answered before it at an account the
            // service holds, which commits nothing and carries the last committed time; a
            // request that would have been a `401` still counts against its source. At an
            // identity without an account, which has no committed time, the notice answers
            // in place of that `429` too, with no signature work (Switch wire 7.1 Timestamp,
            // 7.3 under Table 2, 9.4).
            let limited = self.limited_before_authentication(&account, &request, base_ms);
            match (limited, committed_ms) {
                (Some(limited), Some(committed_ms)) => {
                    let at = AnswerTime::Account(committed_ms);
                    return self.keyed_error(&routed.key, asked, at, &limited);
                }
                (Some(_), None) => {}
                (None, _) if *call != Call::GetIdentity => {
                    if let Ok(pre) = self.pre_lock(&account, &request, base_ms, service_ms).await
                        && pre
                            .caller
                            .is_some_and(|claimed| claimed.caller == Caller::Signer)
                    {
                        return self
                            .signer_notice_under_lock(&account, &request, &class, asked, base_ms)
                            .await;
                    }
                }
                (None, _) => {}
            }
        }
        if let Some(answer) = self.verdict_answer(&account, &routed, asked, base_ms, committed_ms) {
            return answer;
        }
        let Some(committed_ms) = committed_ms else {
            // An identity without an account that the verdict lets through: the erasure at
            // a lost identity (Switch wire 7.4.16, 7.3 Table 2).
            return self
                .erase_without_account(&account, &request, &routed, base_ms, asked)
                .await;
        };
        // An answer before the account's lock commits nothing: signed with the verdict's key,
        // at the last time the service committed for the identity (Switch wire 7.1
        // Timestamp).
        let refused_early = |error: ApiError| {
            self.keyed_error(
                &routed.key,
                asked,
                AnswerTime::Account(committed_ms),
                &error,
            )
        };
        // Everything that needs no account state comes before the lock: the limits that
        // apply before authentication, the headers and the signature (Switch wire 7.2).
        let PreLock {
            caller,
            verified,
            other,
        } = match self.pre_lock(&account, &request, base_ms, service_ms).await {
            Ok(pre) => pre,
            Err(error) => return refused_early(error),
        };
        // A delivered identity.json is read and verified before the lock too: signature work
        // needs no account state (Switch wire 7.2 Order). Its refusal is answered under the
        // lock, after the caller's own checks, with the head an own app's refusal carries.
        // So is a recovery upload's from an own app, which the endpoint takes under the lock
        // only if what it was judged against is unchanged (Switch wire 7.4.14).
        let prepared = match call {
            Call::PutPeers => {
                let other = match caller.as_ref().map(|claimed| &claimed.caller) {
                    Some(Caller::OtherApp { identity, .. }) => Some(*identity),
                    _ => None,
                };
                let account_key = pubky_switch_core::enc::pubky_key(&account).unwrap_or([0; 32]);
                Some(Prepared::Delivery(Box::new(peers::verify_delivery(
                    &request.body,
                    &account_key,
                    other.as_ref(),
                ))))
            }
            Call::RecoveryUpload => match verified.as_ref() {
                Some(app) => Some(Prepared::Upload(Box::new(
                    self.prepare_upload(&account, app, &request.body, service_ms)
                        .await,
                ))),
                None => None,
            },
            Call::PutPush => match verified.as_ref() {
                Some(app) => Some(Prepared::Push(Box::new(
                    self.prepare_push(&account, &app.app_id(), &request.body, service_ms)
                        .await,
                ))),
                None => None,
            },
            _ => None,
        };
        let response = async {
            // The reads that run after the lock on its snapshot take their account's turn and
            // their reader first, so the lock is never held waiting for one. Only an own app's
            // request whose signature verified takes them, one place per app: the signer's is
            // refused under the lock without a read, and an app of another identity's was
            // refused above. Whether the app is current and may read is judged under the lock.
            let reading_app = verified
                .as_ref()
                .filter(|_| matches!(call, Call::GetAllow | Call::ListRecords))
                .map(batch::VerifiedApp::app_id);
            let begun = if let Some(app) = reading_app {
                self.store.begin_reading(&account, app).await
            } else {
                self.store.begin(&account).await
            };
            let txn = match begun {
                Ok(Some(txn)) => txn,
                Ok(None) => {
                    return self
                        .answer_after_account_change(
                            &account,
                            &class,
                            asked,
                            base_ms,
                            None,
                            caller
                                .as_ref()
                                .is_some_and(|claimed| claimed.caller == Caller::Signer)
                                .then_some(&request),
                        )
                        .await;
                }
                Err(error) => return refused_early(store_error(&error)),
            };
            self.at_account(
                txn,
                &request,
                base_ms,
                mark_floor_ms,
                due,
                asked,
                &class,
                caller.as_ref(),
                verified.as_ref(),
                other.as_ref(),
                prepared.as_ref(),
            )
            .await
        }
        .await;
        // A key minted for a start goes once the request is over, unless its commit took it
        // (Switch wire 8.1, `store::push`); a request dropped before this deletes it as
        // `prepared` drops.
        if let Some(Prepared::Push(push)) = prepared {
            push.done().await;
        }
        response
    }

    /// The service's current key.
    fn current_key(&self) -> [u8; 32] {
        self.keys.current().public_key_bytes()
    }

    /// The `429` a request gets before it is authenticated, if any: the public read's limits,
    /// or the network source's failed authentications (Switch wire 9.4).
    fn limited_before_authentication(
        &self,
        account: &str,
        request: &SwitchRequest,
        base_ms: u64,
    ) -> Option<ApiError> {
        if request.route.call == Call::GetIdentity {
            return self
                .public_read_limits(account, request.source, base_ms)
                .err();
        }
        self.failed_auth
            .check(request.source, base_ms)
            .err()
            .map(|retry_after| {
                ApiError::rate_limited(
                    "9.4: too many failed authentications from this network source",
                    retry_after,
                )
            })
    }

    /// The caller's authentication before the account's lock (Switch wire 7.2 Order), by the
    /// call: the public read's limits; the signer's signature; an own app's signature, with
    /// the key the account holds for it; an app of another identity's certificate.
    async fn pre_lock(
        &self,
        account: &str,
        request: &SwitchRequest,
        base_ms: u64,
        service_time_ms: u64,
    ) -> Result<PreLock, ApiError> {
        let call = &request.route.call;
        let mut pre = PreLock::default();
        match call {
            Call::GetIdentity => self.public_read_limits(account, request.source, base_ms)?,
            // Verify the signature before taking the account lock. Check an own app's
            // current authority under the lock (Switch wire 7.2).
            Call::PutIdentity
            | Call::Revoke(_)
            | Call::GetApps
            | Call::PutHandover
            | Call::GetHandover
            | Call::RecoveryAdmission
            | Call::Erase => {
                let (claimed, app, cert) = self
                    .authenticate_signer(account, request, base_ms, service_time_ms)
                    .await?;
                pre.verified = app;
                pre.other = cert;
                pre.caller = Some(claimed);
            }
            Call::Ops
            | Call::GetClaim(_)
            | Call::Feed
            | Call::PutPeers
            | Call::Append
            | Call::Directory
            | Call::GetKeys(_)
            | Call::RequestKeys(_)
            | Call::Leave(_)
            | Call::RecoveryUpload
            | Call::GetRecord(_)
            | Call::ListRecords
            | Call::GetAllow
            | Call::PostConnect
            | Call::GetConnect
            | Call::DeleteConnect(_)
            | Call::PutPush => {
                let (claimed, cert) =
                    self.authenticate_caller(account, request, base_ms, service_time_ms)?;
                pre.other = cert;
                // An own app's request is verified here too, so nothing unverified takes the
                // lock (Switch wire 7.2 Order).
                if let Caller::OwnApp(app) = &claimed.caller {
                    let batch = *call == Call::Ops;
                    let app = self
                        .verify_own_app(account, request, &claimed, app, batch, base_ms)
                        .await
                        .inspect_err(|error| {
                            if is_failed_authentication(error.code) {
                                self.record_failure(request, account.to_string());
                            }
                        })?;
                    pre.verified = Some(app);
                }
                pre.caller = Some(claimed);
            }
            // Enrollment and account discovery are handled in serve before pre_lock.
            Call::Enroll
            | Call::GetAccount
            | Call::Freeze
            | Call::Unfreeze
            | Call::Export
            | Call::ExportChunk(_)
            | Call::Import
            | Call::ImportChunk(_)
            | Call::ImportActivate => {
                return Err(ApiError::unavailable("7.4: this call isn't served yet"));
            }
        }
        Ok(pre)
    }

    /// The signer's authentication, before the account's lock (Switch wire 7.2 Order): the
    /// network source's failed-authentication limit, then the headers, the timestamp and
    /// the request signature, verified with the identity key `{id}` names. An own app's
    /// request is verified as at its own calls, then refused: `403 permission_missing`
    /// for a call only the signer makes (7.6).
    async fn authenticate_signer(
        &self,
        account: &str,
        request: &SwitchRequest,
        base_ms: u64,
        service_time_ms: u64,
    ) -> Result<(Claimed, Option<batch::VerifiedApp>, Option<AppCert>), ApiError> {
        if let Err(retry_after) = self.failed_auth.check(request.source, base_ms) {
            return Err(ApiError::rate_limited(
                "9.4: too many failed authentications from this network source",
                retry_after,
            ));
        }
        let identity_key = pubky_switch_core::enc::pubky_key(account)
            .map_err(|_| ApiError::not_found("no such account"))?;
        let claimed = self
            .authenticate(&identity_key, request, base_ms)
            .inspect_err(|error| {
                if is_failed_authentication(error.code) {
                    self.record_failure(request, account.to_string());
                }
            })?;
        match &claimed.caller {
            // Verified as at its own calls, then refused under the lock, where the refusal
            // carries the head like every refusal to a verified own app (Switch wire 7.1).
            Caller::OwnApp(app) => {
                let verified = self
                    .verify_own_app(account, request, &claimed, app, false, base_ms)
                    .await
                    .inspect_err(|error| {
                        if is_failed_authentication(error.code) {
                            self.record_failure(request, account.to_string());
                        }
                    })?;
                Ok((claimed, Some(verified), None))
            }
            // Its certificate first, in 7.2's order (`400`, `401`), then its expiry, then
            // the refusal (3.8).
            Caller::OtherApp { app, .. } => {
                let cert =
                    self.other_app_before_lock(account, request, &claimed, app, service_time_ms)?;
                Ok((claimed, None, Some(cert)))
            }
            Caller::Signer => Ok((claimed, None, None)),
        }
    }

    /// Verify an app of another identity by the certificate it sends (Switch wire 7.2):
    /// `Switch-Cert` present (`400`), verifying for `Switch-Identity` and naming
    /// `Switch-App` (`401 bad_signature`), and the request signed with its key (`401`).
    fn verify_other_app(
        &self,
        request: &SwitchRequest,
        claimed: &Claimed,
        app: &str,
    ) -> Result<AppCert, ApiError> {
        let bad = |why: &'static str| ApiError::new(ErrorCode::BadSignature, why);
        let text = claimed.headers.cert.as_deref().ok_or_else(|| {
            ApiError::bad_request("7.2: an app of another identity sends Switch-Cert")
        })?;
        let signed = pubky_switch_core::sig::SignedDoc::from_compact(text)
            .map_err(|_| bad("7.2: Switch-Cert isn't a signed certificate"))?;
        let cert = AppCert::verify(&signed, &claimed.identity_key)
            .map_err(|_| bad("7.2: Switch-Cert doesn't verify for Switch-Identity"))?;
        let named = pubky_switch_core::enc::app_id_decode(app)
            .map_err(|_| bad("7.2: Switch-Cert doesn't name Switch-App"))?;
        if cert.app_id() != named {
            return Err(bad("7.2: Switch-Cert doesn't name Switch-App"));
        }
        let target = RequestTarget {
            method: &request.method,
            path_and_query: &request.path_and_query,
            body: &request.body,
            origin: &self.origin,
        };
        wire_http::verify_request(
            &cert.signing_key(),
            &target,
            &claimed.headers,
            &claimed.signature,
        )
        .map_err(|_| bad("7.1: the request signature doesn't verify"))?;
        Ok(cert)
    }

    /// The public read's limits (Switch wire 9.4), before the account's lock: per network
    /// source per account, then the account's backstop, which a source's refused reads
    /// don't count against.
    fn public_read_limits(
        &self,
        account: &str,
        source: Option<NetworkSource>,
        base_ms: u64,
    ) -> Result<(), ApiError> {
        if let Some(source) = source
            && let Err(retry_after) = self.reads_per_source.take(
                (account.to_string(), source),
                self.limits.identity_reads_per_source_per_min,
                base_ms,
            )
        {
            return Err(ApiError::rate_limited(
                "9.4: public identity.json reads from this network source",
                retry_after,
            ));
        }
        if let Err(retry_after) = self.reads_per_account.take(
            account.to_string(),
            self.limits.identity_reads_per_min,
            base_ms,
        ) {
            return Err(ApiError::rate_limited(
                "9.4: public identity.json reads of this account",
                retry_after,
            ));
        }
        Ok(())
    }

    /// The processing order under the account's lock (Switch wire 7.3 steps 3 to 10), for a
    /// request authenticated as far as needs no account state, or the public read: judged
    /// again first, since the state may have changed while the request waited.
    #[allow(clippy::too_many_arguments)]
    async fn at_account(
        &self,
        mut txn: AccountTxn,
        request: &SwitchRequest,
        base_ms: u64,
        mark_floor_ms: Option<u64>,
        due: Option<u64>,
        asked: Asked<'_>,
        class: &RequestClass,
        caller: Option<&Claimed>,
        verified: Option<&batch::VerifiedApp>,
        other: Option<&AppCert>,
        prepared: Option<&Prepared>,
    ) -> SwitchResponse {
        let unavailable = || ApiError::unavailable("7.6: a temporary failure");
        let identity = txn.head().id.clone();
        let identity_key = txn.head().identity_key;
        // The time the account last committed: what an answer that commits nothing carries
        // (Switch wire 7.1 Timestamp), under the time floor of the mark read before the lock
        // (Switch wire 7.3, "Trusted time").
        let committed_ms = txn.head().committed_ms(self.run, mark_floor_ms);
        let bound_signer = caller.is_some_and(|claimed| claimed.caller == Caller::Signer);
        let store_id = if bound_signer {
            match self.marks.identity().await {
                Ok(id) => Some(id),
                Err(_) => {
                    return self.service_error(
                        asked,
                        AnswerTime::Account(committed_ms),
                        &unavailable(),
                    );
                }
            }
        } else {
            None
        };
        let held = match txn.held_identity().await {
            Ok(Some(held)) => match IdentityDoc::verify(&held.doc, &identity_key) {
                Ok(doc) => Some(doc),
                Err(_) => {
                    tracing::error!("a held identity.json doesn't verify");
                    return self.service_error(
                        asked,
                        AnswerTime::Account(committed_ms),
                        &unavailable(),
                    );
                }
            },
            Ok(None) => None,
            Err(error) => {
                return self.service_error(
                    asked,
                    AnswerTime::Account(committed_ms),
                    &store_error(&error),
                );
            }
        };
        // The verdict again, under the lock (Switch wire 7.3 step 2).
        let head = txn.head().clone();
        let account = self.account_input(
            head.generation,
            head.chain,
            head.count(),
            head.created_at_ms,
            held.as_ref().map(IdentityDoc::body),
            head.activation,
        );
        let judged = self.judge(&mut txn, &identity, Some(account)).await;
        txn.retain_from_mark(judged.mark());
        // The mark read under the lock may hold a later floor than the one read before it.
        let committed_ms =
            committed_ms.max(txn.head().committed_ms(self.run, judged.time_floor_ms()));
        if let Some(store_id) = store_id
            && self.marks.identity().await.ok() != Some(store_id)
        {
            return self.service_error(asked, AnswerTime::Account(committed_ms), &unavailable());
        }
        if judged.judgement.decision.erase_account_again {
            drop(txn);
            return self
                .answer_after_account_change(
                    &identity,
                    class,
                    asked,
                    base_ms,
                    Some(committed_ms),
                    bound_signer.then_some(request),
                )
                .await;
        }
        let routed = verdict::answer(&judged.judgement, class, self.current_key());
        if bound_signer
            && !matches!(routed.route, Route::Unavailable)
            && let Err(error) = account::check_creation(request, &judged)
        {
            return self.keyed_error(
                &routed.key,
                asked,
                AnswerTime::TimeBase(base_ms, Uncompared::CreationConflict),
                &error,
            );
        }
        if let Some(answer) =
            self.verdict_answer(&identity, &routed, asked, base_ms, Some(committed_ms))
        {
            return answer;
        }
        let Some(signer) = self.signer_of(&routed.key) else {
            return self.service_error(asked, AnswerTime::Account(committed_ms), &unavailable());
        };
        // Only an answer the verdict lets carry a head carries one (Switch wire 7.3 under
        // Table 2): the start of a generation carries its own.
        let carries_head = matches!(routed.route, Route::Proceed { head: true });
        let healthy = matches!(judged.judgement.decision.verdict, verdict::Verdict::Healthy);
        // Step 3: the identity's service time, which never goes back, also across a restore
        // of the state; the mark's time floor rises first where it passes it (Switch wire
        // 7.3, "Trusted time"). An erasure's stamp too: a refused one commits it.
        let time_ms = match self
            .stamp_under_lock(&mut txn, base_ms, judged.mark())
            .await
        {
            Ok(time_ms) => time_ms,
            Err(error) => {
                drop(txn);
                return Self::signed_error(
                    &signer,
                    asked,
                    AnswerTime::Account(committed_ms),
                    &error,
                );
            }
        };
        // A failure under the lock: the transaction is dropped, nothing of it stays, and the
        // answer is signed at the time last committed.
        let failed = |txn: AccountTxn| {
            drop(txn);
            Self::signed_error(
                &signer,
                asked,
                AnswerTime::Account(committed_ms),
                &unavailable(),
            )
        };
        // Step 4, with trusted time only, for a caller that has verified: a bounded batch of
        // the claims whose time has passed goes, by the time base (Switch wire 7.3), and the
        // sweeps of 9.1 run (`sweeps.rs`). It comes before the endpoint, so a refusal doesn't
        // undo it; an unauthenticated request, or the public read, pays for none of it. A
        // claim a request reads or writes goes when it is due, whatever the batch reached.
        // Chain stub retention comes last (`retention.rs`). What they delete counts toward
        // the account's count like any other write (Switch wire 7.3, "The state").
        // A failing or bounded account cannot cover maintenance in the state it is
        // recovering from. Its authorized recovery or erasure makes its own changes.
        if let (Some(base), Some(_)) = (due, caller)
            && !matches!(
                judged.judgement.decision.verdict,
                verdict::Verdict::Failing { .. } | verdict::Verdict::Bounded { .. }
            )
        {
            let swept = match self.step_four(&mut txn, base).await {
                Ok(()) => self.retain_chain(&mut txn, &signer, healthy, base).await,
                Err(error) => Err(error),
            };
            if let Err(error) = swept {
                let _ = store_error(&error);
                return failed(txn);
            }
        }
        // A read after the lock takes this transaction's snapshot now, outside the endpoint's
        // savepoint, which can't export one.
        if let Err(failure) = txn.prepare_snapshot().await {
            tracing::error!(%failure, "a snapshot for a read after the lock");
            return failed(txn);
        }
        // What the endpoint writes is undone if it is refused, whatever step refuses it: a
        // refusal commits the stamped time and nothing else, so no later request can build
        // on a write it was never answered for (step 10).
        let savepoint = match txn.savepoint().await {
            Ok(savepoint) => savepoint,
            Err(error) => {
                let _ = store_error(&error);
                return failed(txn);
            }
        };
        let reply = match self
            .run_at_account(
                &mut txn,
                &signer,
                request,
                held.as_ref(),
                &judged,
                &routed,
                verified,
                other,
                prepared,
                due,
                time_ms,
            )
            .await
        {
            Ok(AccountOutcome::Commit(reply)) => reply,
            Ok(AccountOutcome::Erase(erasure)) => {
                return self
                    .finish_erasure(txn, &signer, asked, committed_ms, time_ms, erasure)
                    .await;
            }
            Err(Refused { error, head }) => {
                if let Err(failure) = txn.rollback_to(savepoint).await {
                    // Dropped uncommitted: nothing of the request stays, the stamp included.
                    tracing::error!(%failure, "rolling back a refused request");
                    return failed(txn);
                }
                // Every 401 counts against the network source, whatever the step: a request
                // signature, an operation's, a first call's record (Switch wire 7.2, 9.4).
                if is_failed_authentication(error.code) {
                    self.record_failure(request, identity.clone());
                }
                // An error to the authenticated signer or own app carries the current head
                // (Switch wire 7.1), where the verdict lets the answer carry one. Not to an
                // app of another identity, which no answer shows the head. No answer to an
                // erasure carries one, an error included (7.4.16).
                let own = caller.is_some_and(|c| !matches!(c.caller, Caller::OtherApp { .. }));
                let head = if own && head && carries_head && request.route.call != Call::Erase {
                    self.head(&txn, &signer).await
                } else {
                    None
                };
                AfterCommit::Ready(Answer::error(&error).with_head(head))
            }
        };
        // Reads that fail after commit answer with this request's head (Switch wire 7.1).
        let fallback_head = if carries_head && !matches!(reply, AfterCommit::Ready(_)) {
            self.head(&txn, &signer).await
        } else {
            None
        };
        // A delivery that starts a generation uses its own service key (Switch wire 7.3).
        let (answer_key, starts_generation, has_head) = match &reply {
            AfterCommit::Ready(answer) => (
                answer.key.unwrap_or(routed.key),
                answer.starts_generation,
                answer.head.is_some(),
            ),
            AfterCommit::Page { .. } => (routed.key, false, true),
            AfterCommit::Feed(_) => (routed.key, false, false),
        };
        let answer_signer = if answer_key == routed.key {
            signer.clone()
        } else {
            match self.signer_of(&answer_key) {
                Some(signer) => signer,
                None => return failed(txn),
            }
        };
        // A serving account before its first chain item has a position to move the mark to
        // too (Switch wire 7.3, "The mark").
        let has_position = txn.head().head_tip().is_some() || healthy;
        // A commit that gives out a `seq`, signs a head or may move a mark waits for no stale
        // instance lock: another process may hold the database by now (Switch spec 6.5).
        let gives = txn.head().last_seq != txn.loaded().last_seq
            || txn.head().chain != txn.loaded().chain
            || has_head
            || fallback_head.is_some()
            || ((healthy || carries_head || starts_generation) && has_position);
        if gives && !self.lock_is_fresh() {
            tracing::error!("the instance lock isn't confirmed: a commit refused");
            return failed(txn);
        }
        let created_at_ms = txn.head().created_at_ms;
        // The push keys the request let go (Switch wire 8.1), deleted once the mark covers
        // its commit: a restore to the state the mark covers may still name one.
        let owed = txn.owed_keys().to_vec();
        // Durable, then answered (step 10). An answer is sent even when the request only
        // stamped the time, which must be durable before it is shown. The commit runs to its
        // end in a task of its own, also when the request is dropped meanwhile (a client that
        // hangs up).
        let coverage = if healthy {
            MarkCoverage::ServingPosition
        } else if carries_head || starts_generation {
            MarkCoverage::ChainHead
        } else {
            MarkCoverage::None
        };
        let marks = self.marks.clone();
        let prior = judged
            .mark()
            .filter(|_| {
                healthy
                    || (matches!(judged.judgement.decision.verdict, verdict::Verdict::Staged)
                        && !matches!(coverage, MarkCoverage::None))
            })
            .copied();
        let commit = async move {
            Self::commit_marked(&marks, txn, coverage, prior, false)
                .await
                .map_err(|failure| {
                    tracing::error!(?failure, "commit");
                })
        };
        let Ok((committed, update)) = erase::to_the_end(commit).await.unwrap_or(Err(())) else {
            // Nothing committed, the stamp included: the mark doesn't move.
            return Self::signed_error(
                &signer,
                asked,
                AnswerTime::Account(committed_ms),
                &unavailable(),
            );
        };
        // The mark moves to the committed position, its head or the position before the
        // first, with its count and tag, durably, before the answer is released: after a
        // commit at a healthy account, one whose answer carries a head, or a generation
        // start. This includes a refused erasure that committed the sweep before its
        // savepoint (Switch wire 7.3). No answer carries a head where the verdict is behind or a fork,
        // so no mark moves there but by a start. A commit that held whose mark didn't move
        // answers `503`, and its retry is answered as a retry (Switch wire 7.3, "Moving it").
        let target = committed.mark_target;
        if let Some(target) = target {
            let moved = if starts_generation
                && matches!(routed.route, Route::StartAfresh)
                && let Some(old) = judged
                    .mark()
                    .filter(|old| old.created_at_ms < created_at_ms)
            {
                match store_id {
                    Some(store_id) => {
                        self.recover_older_mark(
                            &identity,
                            target,
                            answer_key,
                            created_at_ms,
                            *old,
                            store_id,
                        )
                        .await
                    }
                    None => marking::MarkMove::Failed,
                }
            } else {
                self.move_mark_with_source(
                    &identity,
                    target,
                    answer_key,
                    created_at_ms,
                    starts_generation,
                    update,
                )
                .await
            };
            if moved != marking::MarkMove::Done {
                // The keys stay owed, for the deletion at the next start.
                return Self::signed_error(
                    &answer_signer,
                    asked,
                    AnswerTime::Account(time_ms),
                    &unavailable(),
                );
            }
        }
        if target.is_some() && !owed.is_empty() {
            // In a task of its own, so a request dropped meanwhile leaves no key to the next
            // start's deletion.
            let (store, keys) = (self.store.clone(), self.keys.clone());
            let _ = erase::to_the_end(erase::delete_owed(store, keys, owed)).await;
        }
        #[cfg(any(test, feature = "test-util"))]
        {
            let pause = self.release_pause.lock().take();
            if let Some(pause) = pause {
                pause.wait().await;
            }
        }
        let answer = match reply {
            AfterCommit::Ready(answer) => answer,
            AfterCommit::Page { read, head } => {
                let body = match *read {
                    PageRead::Claim(read) => self.claim_body(&read).await,
                    PageRead::Allow(read) => Self::allow_body(read).await,
                    PageRead::Records(read) => Self::records_body(read).await,
                };
                match body {
                    Ok(body) => Answer::ok(body).with_head(Some(head)),
                    Err(error) => Answer::error(&error).with_head(fallback_head),
                }
            }
            AfterCommit::Feed(read) => {
                let result = self.feed_page(&read).await;
                if let Err(feed::FeedStop::Refused(refusal)) = &result
                    && is_failed_authentication(refusal.error.code)
                {
                    self.record_failure(request, identity.clone());
                }
                return self.feed_answer(&read, result, fallback_head, asked).await;
            }
        };
        // The response signature is made last, over the whole body (Switch wire 7.1).
        sign_answer(&answer_signer, asked, AnswerTime::Account(time_ms), answer)
    }
    /// Steps 4 to 9 under the lock, under the verdict `judged` and its answer `routed`.
    // The request's verified callers and times, each from a different step of 7.3.
    #[allow(clippy::too_many_arguments)]
    async fn run_at_account(
        &self,
        txn: &mut AccountTxn,
        signer: &ServiceSigner,
        request: &SwitchRequest,
        held: Option<&IdentityDoc>,
        judged: &marking::Judged,
        routed: &verdict::Answer,
        verified: Option<&batch::VerifiedApp>,
        other: Option<&AppCert>,
        prepared: Option<&Prepared>,
        due: Option<u64>,
        time_ms: u64,
    ) -> Result<AccountOutcome, Refused> {
        let call = &request.route.call;
        let serving = names_this_service(held, &self.origin, &signer.public_key_bytes());

        if *call == Call::GetIdentity {
            return self
                .public_identity(held, serving)
                .map(AccountOutcome::ready)
                .map_err(Refused::with_head);
        }

        // Step 5 comes before the staged gate: an own app is authenticated in full first.
        let stop = |stop: batch::Stop| match stop {
            batch::Stop::Refused(error) => Refused::with_head(error),
            // Not authenticated: no head.
            batch::Stop::Unauthenticated(error) => Refused { error, head: false },
        };
        let writer = match self.own_app_writer(txn, held, verified, time_ms).await {
            Ok(writer) => writer,
            Err(error) => return Err(stop(error)),
        };
        // Check 3 of an app of another identity, at the identity's service time (Switch wire
        // 7.2): its certificate hasn't expired. The refusal commits this time and is signed
        // at it. Then, at a call it doesn't make, the refusal it would have got before the
        // lock (3.8: expiry first).
        if let Some(cert) = other {
            if cert.expired_at(time_ms) {
                return Err(Refused::with_head(ApiError::new(
                    ErrorCode::CertExpired,
                    "3.8: the certificate has expired",
                )));
            }
            if !rules::takes_other_apps(call) {
                return Err(Refused::with_head(rules::other_app_refusal(call)));
            }
        }
        // A call only the signer makes, from an own app that verified: refused with the head
        // (Switch wire 7.4, 7.1).
        if writer.is_some()
            && matches!(
                call,
                Call::PutIdentity
                    | Call::Revoke(_)
                    | Call::GetApps
                    | Call::PutHandover
                    | Call::RecoveryAdmission
                    | Call::Erase
            )
        {
            return Err(Refused::with_head(ApiError::new(
                ErrorCode::PermissionMissing,
                "7.4: a call only the signer may make",
            )));
        }
        // Step 7: the staged gate. Step 9: the endpoint.
        staged_gate(call, !serving).map_err(Refused::with_head)?;
        let answer = match call {
            Call::Ops => {
                return self
                    .post_ops(
                        txn,
                        signer,
                        request,
                        held,
                        verified,
                        writer.as_ref(),
                        due,
                        time_ms,
                    )
                    .await
                    .map(AccountOutcome::ready)
                    .map_err(stop);
            }
            Call::GetAllow => {
                return self
                    .get_allow(txn, signer, writer.as_ref(), time_ms)
                    .await
                    .map_err(Refused::with_head);
            }
            Call::GetRecord(key) => self.get_record(txn, signer, writer.as_ref(), key).await,
            Call::ListRecords => {
                let query = request.route.query.as_ref().map_err(|_| {
                    Refused::with_head(ApiError::bad_request("7.1: the query doesn't decode"))
                })?;
                return self
                    .list_records(txn, signer, writer.as_ref(), query)
                    .await
                    .map_err(Refused::with_head);
            }
            Call::GetClaim(claim_key) => {
                return self
                    .get_claim(txn, signer, held, writer.as_ref(), claim_key, due, time_ms)
                    .await
                    .map_err(Refused::with_head);
            }
            Call::Append => {
                let appender = match (writer.as_ref(), other) {
                    (Some(cert), _) => inbox::Appender::OwnApp(cert),
                    (None, Some(cert)) => inbox::Appender::OtherApp(cert),
                    (None, None) => {
                        return Err(Refused::with_head(ApiError::new(
                            ErrorCode::PermissionMissing,
                            "7.4.3: apps append; the signer doesn't",
                        )));
                    }
                };
                let query = request.route.query.as_ref().map_err(|_| {
                    Refused::with_head(ApiError::bad_request("7.1: the query doesn't decode"))
                })?;
                let headers = request.signed_headers();
                let invite_code = headers.text(header::INVITE_CODE);
                self.append(
                    txn,
                    signer,
                    held,
                    appender,
                    &request.body,
                    query,
                    invite_code,
                    due.is_some(),
                    time_ms,
                )
                .await
            }
            Call::PostConnect => {
                // Apps of another identity ask to connect; the account's own don't.
                let Some(cert) = other.filter(|_| writer.is_none()) else {
                    return Err(Refused::with_head(ApiError::new(
                        ErrorCode::PermissionMissing,
                        "7.4.7: apps of another identity ask to connect",
                    )));
                };
                self.post_connect(txn, held, cert, time_ms).await
            }
            Call::GetConnect => self.get_connect(txn, signer, held, writer.as_ref()).await,
            Call::DeleteConnect(pubky) => {
                self.delete_connect(txn, signer, writer.as_ref(), pubky)
                    .await
            }
            Call::Directory => {
                let reader = match (writer.as_ref(), other) {
                    (Some(_), _) => directory::Reader::OwnApp,
                    (None, Some(cert)) => directory::Reader::OtherApp(cert),
                    (None, None) => {
                        return Err(Refused::with_head(ApiError::new(
                            ErrorCode::PermissionMissing,
                            "7.4.10: apps read the directory; the signer doesn't",
                        )));
                    }
                };
                let headers = request.signed_headers();
                let invite_code = headers.text(header::INVITE_CODE);
                self.directory(
                    txn,
                    signer,
                    held,
                    reader,
                    invite_code,
                    due.is_some(),
                    time_ms,
                )
                .await
            }
            Call::PutPeers => {
                let deliverer = match (writer.as_ref(), other) {
                    (Some(_), _) => peers::Deliverer::OwnApp,
                    (None, Some(cert)) => peers::Deliverer::OtherApp(cert),
                    (None, None) => {
                        return Err(Refused::with_head(ApiError::new(
                            ErrorCode::PermissionMissing,
                            "7.4.5: apps deliver peers' documents",
                        )));
                    }
                };
                let delivered = match prepared {
                    Some(Prepared::Delivery(delivered)) => Some(&**delivered),
                    _ => None,
                };
                let delivered = delivered
                    .ok_or_else(|| {
                        Refused::with_head(ApiError::unavailable("7.6: a temporary failure"))
                    })?
                    .as_ref()
                    .map_err(|error| Refused::with_head(error.clone()))?;
                let headers = request.signed_headers();
                let invite_code = headers.text(header::INVITE_CODE);
                self.put_peers(
                    txn,
                    signer,
                    held,
                    deliverer,
                    delivered,
                    invite_code,
                    due.is_some(),
                    time_ms,
                )
                .await
            }
            Call::GetApps => self.get_apps(txn, signer, held, time_ms).await,
            Call::Feed => {
                let read = self
                    .feed(
                        txn.head(),
                        judged.time_floor_ms(),
                        signer.public_key_bytes(),
                        writer.as_ref(),
                        &request.route.query,
                        time_ms,
                    )
                    .map_err(Refused::with_head)?;
                // The reader's feed read ends its lagging mark, unless it reads no entry
                // (`limit=0`, Switch wire 7.4.4).
                if read.reads_items()
                    && let Some(reader) = writer.as_ref()
                {
                    txn.set_lagging(&[reader.app_id()], false)
                        .await
                        .map_err(|error| Refused::with_head(store_error(&error)))?;
                }
                return Ok(AccountOutcome::Commit(AfterCommit::Feed(read)));
            }
            Call::Leave(app_id) => {
                // Only the app itself leaves (Switch wire 7.4.12).
                let Some(caller) = writer.as_ref() else {
                    return Err(Refused::with_head(ApiError::new(
                        ErrorCode::PermissionMissing,
                        "7.4.12: only the app itself leaves",
                    )));
                };
                self.leave(
                    txn,
                    signer,
                    held,
                    caller,
                    app_id,
                    &request.body,
                    due.is_some(),
                    time_ms,
                )
                .await
            }
            Call::RecoveryUpload => {
                // An own app uploads (Switch wire 7.4.14); a staged service's uploads, in a
                // cooperative move, aren't served yet.
                let Some(caller) = writer.as_ref() else {
                    return Err(Refused::with_head(ApiError::new(
                        ErrorCode::PermissionMissing,
                        "7.4.14: an own app uploads",
                    )));
                };
                if !serving {
                    return Err(Refused::with_head(ApiError::unavailable(
                        "7.4.14: this stage isn't served yet",
                    )));
                }
                let prepared = match prepared {
                    Some(Prepared::Upload(prepared)) => Some(&**prepared),
                    _ => None,
                };
                self.recovery_upload(txn, signer, held, caller, &request.body, prepared, time_ms)
                    .await
            }
            Call::GetKeys(app_id) | Call::RequestKeys(app_id) => {
                // Only the app itself; the signer stores the parts with `key_bundle.put`
                // (Switch wire 7.4.11).
                let Some(caller) = writer.as_ref() else {
                    return Err(Refused::with_head(app_keys::only_that_app()));
                };
                let keys_call = if matches!(call, Call::GetKeys(_)) {
                    app_keys::KeysCall::Read
                } else {
                    app_keys::KeysCall::Request
                };
                self.app_keys(
                    txn,
                    signer,
                    caller,
                    app_id,
                    &request.body,
                    keys_call,
                    time_ms,
                )
                .await
            }
            Call::Erase => {
                return erase::erasure_binding(request, held, judged)
                    .map(AccountOutcome::Erase)
                    .map_err(|error| Refused { error, head: false });
            }
            Call::PutHandover => {
                self.put_handover(txn, signer, held, &request.body, time_ms)
                    .await
            }
            Call::GetHandover => {
                // The signer, or the own app it is for (Switch wire 7.4.17). An app of another
                // identity was refused above; refused here too, so the read fails closed.
                let reader = match (writer.as_ref(), other) {
                    (Some(app), _) => handover::Reader::OwnApp(app),
                    (None, None) => handover::Reader::Signer,
                    (None, Some(_)) => {
                        return Err(Refused::with_head(rules::other_app_refusal(call)));
                    }
                };
                self.get_handover(txn, signer, reader).await
            }
            Call::PutPush => {
                // An app can change only its own push registration (Switch wire 8.1).
                let Some(caller) = writer.as_ref() else {
                    return Err(Refused::with_head(rules::other_app_refusal(call)));
                };
                let prepared = match prepared {
                    Some(Prepared::Push(prepared)) => Some(&**prepared),
                    _ => None,
                };
                self.put_push(txn, signer, caller.app_id(), prepared, time_ms)
                    .await
            }
            Call::RecoveryAdmission => {
                self.recovery_admission(txn, signer, &request.body, time_ms)
                    .await
            }
            Call::Revoke(app_id) => {
                self.revoke(
                    txn,
                    signer,
                    held,
                    app_id,
                    &request.body,
                    due.is_some(),
                    time_ms,
                )
                .await
            }
            Call::PutIdentity => {
                let afresh = matches!(routed.route, verdict::Route::StartAfresh);
                return self
                    .put_identity(
                        txn,
                        signer,
                        request,
                        held,
                        judged,
                        afresh,
                        due.is_some(),
                        time_ms,
                    )
                    .await
                    .map(AccountOutcome::ready)
                    .map_err(|error| Refused {
                        // Only its own `200` carries a head where the account fails stop or is bounded
                        // (Switch wire 7.1, 7.3 under Table 2).
                        head: !afresh,
                        error,
                    });
            }
            // Enrollment and discovery run in serve, and the public identity read runs
            // before app checks above. The move endpoints are refused in pre_lock.
            Call::Enroll
            | Call::GetAccount
            | Call::GetIdentity
            | Call::Freeze
            | Call::Unfreeze
            | Call::Export
            | Call::ExportChunk(_)
            | Call::Import
            | Call::ImportChunk(_)
            | Call::ImportActivate => {
                Err(ApiError::unavailable("7.4: this call isn't served here"))
            }
        }
        .map_err(Refused::with_head)?;
        Ok(AccountOutcome::ready(answer))
    }

    /// Authenticate the caller of a call the signer or an own app makes, as far as needs no
    /// account state (Switch wire 7.2 Order): the network source's failed-authentication
    /// limit, the headers and the timestamp, and the signer's signature. The caller of this helper verifies an own app
    /// before taking the account lock. The locked dispatch checks the app's current standing.
    /// Other apps follow the certificate and endpoint checks in `other_app_before_lock`.
    fn authenticate_caller(
        &self,
        account: &str,
        request: &SwitchRequest,
        base_ms: u64,
        service_time_ms: u64,
    ) -> Result<(Claimed, Option<AppCert>), ApiError> {
        if let Err(retry_after) = self.failed_auth.check(request.source, base_ms) {
            return Err(ApiError::rate_limited(
                "9.4: too many failed authentications from this network source",
                retry_after,
            ));
        }
        let identity_key = pubky_switch_core::enc::pubky_key(account)
            .map_err(|_| ApiError::not_found("no such account"))?;
        let claimed = self
            .authenticate(&identity_key, request, base_ms)
            .inspect_err(|error| {
                if is_failed_authentication(error.code) {
                    self.record_failure(request, account.to_string());
                }
            })?;
        let cert = match &claimed.caller {
            Caller::OtherApp { app, .. } => Some(self.other_app_before_lock(
                account,
                request,
                &claimed,
                app,
                service_time_ms,
            )?),
            _ => None,
        };
        Ok((claimed, cert))
    }

    /// An app of another identity before the lock (Switch wire 7.2): its certificate
    /// checked (`400`, `401`, counted against the network source), then the call. A call
    /// it makes goes on, its expiry judged under the lock. At any other call it is refused
    /// here (`rules::other_app_refusal`), unless its certificate has expired by the
    /// identity's service time as far as it is known before the lock: expiry comes before
    /// that refusal (3.8), so it goes on to the lock too, where its `403 cert_expired` is
    /// judged and signed at the time the refusal commits.
    fn other_app_before_lock(
        &self,
        account: &str,
        request: &SwitchRequest,
        claimed: &Claimed,
        app: &str,
        service_time_ms: u64,
    ) -> Result<AppCert, ApiError> {
        let cert = self
            .verify_other_app(request, claimed, app)
            .inspect_err(|error| {
                if is_failed_authentication(error.code) {
                    self.record_failure(request, account.to_string());
                }
            })?;
        let call = &request.route.call;
        if rules::takes_other_apps(call) || cert.expired_at(service_time_ms) {
            return Ok(cert);
        }
        Err(rules::other_app_refusal(call))
    }

    /// Decode the caller and verify signer requests with the identity key (Switch wire 7.2).
    /// Own-app requests use the signing key in the stored or first-call app record.
    /// Requests from another identity's app use the key in its supplied certificate.
    fn authenticate(
        &self,
        account: &[u8; 32],
        request: &SwitchRequest,
        base_ms: u64,
    ) -> Result<Claimed, ApiError> {
        let claimed = decode_claim(account, &request.signed_headers(), base_ms)?;
        if claimed.caller != Caller::Signer && claimed.headers.created.is_some() {
            return Err(ApiError::bad_request(
                "account binding: an app carries no creation header",
            ));
        }
        if claimed.caller == Caller::Signer {
            let text = claimed.headers.created.as_deref().ok_or_else(|| {
                ApiError::bad_request("account binding: Switch-Created is missing")
            })?;
            let created = wire_http::parse_created(text)
                .map_err(|_| ApiError::bad_request("account binding: invalid creation"))?;
            if request.route.call == Call::Erase {
                let named = wire_http::parse_erase_body(&request.body)
                    .map_err(|error| ApiError::bad_request(error.to_string()))?;
                if named.created != Some(created) {
                    return Err(ApiError::bad_request(
                        "account binding: erasure body and header differ",
                    ));
                }
            }
            let target = RequestTarget {
                method: &request.method,
                path_and_query: &request.path_and_query,
                body: &request.body,
                origin: &self.origin,
            };
            wire_http::verify_request(
                &claimed.identity_key,
                &target,
                &claimed.headers,
                &claimed.signature,
            )
            .map_err(|_| {
                ApiError::new(
                    ErrorCode::BadSignature,
                    "7.1: the request signature doesn't verify",
                )
            })?;
        }
        Ok(claimed)
    }

    fn record_failure(&self, request: &SwitchRequest, account: String) {
        let headers = request.signed_headers();
        let claimed_identity = headers
            .text(header::IDENTITY)
            .unwrap_or_default()
            .to_string();
        let claimed_app = headers.text(header::APP).map(str::to_string);
        let base_ms = self.time.peek().base_ms;
        self.failed_auth.record(
            request.source,
            (account, claimed_identity, claimed_app),
            base_ms,
        );
    }
}

impl Handler for Service {
    fn handle(&self, request: SwitchRequest) -> HandlerFuture<'_> {
        Box::pin(self.serve(request))
    }

    fn refuse(&self, refusal: Refusal) -> HandlerFuture<'_> {
        Box::pin(async move {
            let base_ms = self.time.read().base_ms;
            let error = match &refusal {
                Refusal::UnknownRoute { .. } => ApiError::not_found("no such route"),
                Refusal::TooLarge { cap, .. } => ApiError::body_too_large(*cap),
            };
            let received = Received::refused(&refusal, &self.origin);
            // An unknown route binds a request no client sends; a body over its cap is
            // answered before the body is read (Switch wire 7.1 Timestamp).
            let at = match refusal {
                Refusal::UnknownRoute { .. } => AnswerTime::Unbound(base_ms),
                Refusal::TooLarge { .. } => AnswerTime::TimeBase(base_ms, Uncompared::BodyUnread),
            };
            self.service_error(received.asked(), at, &error)
        })
    }
}

/// The service key's public key, as the core's signer reports it.
trait PublicKeyBytes {
    fn public_key_bytes(&self) -> [u8; 32];
}

impl PublicKeyBytes for ServiceSigner {
    fn public_key_bytes(&self) -> [u8; 32] {
        pubky_switch_core::signing::Signs::public_key(self)
    }
}
