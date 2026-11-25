//! The signer of one identity, on one install (Switch spec 4.3).

use crate::store::{HostStore, StoreFailure, blocking_store, store_id};
use crate::vault::native_keyring;
use crate::{HostVault, SignerEnvironment, SignerFfiError, runtime};
use pubky_switch_client::store::{StoreError, StoreHandle};
use pubky_switch_signer::{Signer as NativeSigner, SignerEnv, SignerStatus as NativeStatus};
use std::collections::BTreeMap;
use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex as StdMutex, MutexGuard as StdMutexGuard, PoisonError};
use std::time::Duration;
use tokio::sync::{Notify, Semaphore, mpsc, watch};

/// Where the signer stands (Switch spec 4.3).
#[derive(Clone, PartialEq, Eq, uniffi::Enum)]
pub enum SignerStatus {
    /// Set up, but no switch has accepted a first `identity.json` yet, and `resume` finishes
    /// the enrollment (Switch wire 7.4.1).
    Enrolling,
    /// Setup waits at the original step (Switch account binding 3).
    FirstEnrollmentHeld,
    /// The selected service already held an account or its mark before this install signed
    /// a creation (Switch account binding 3).
    FirstAccountPresent,
    /// This install signs for the identity (Switch spec 4.3).
    Signing,
    /// Another install is the identity's signer, and this one signs nothing until the user
    /// has it take over (Switch spec 4.3, 12.8).
    ManagedBy {
        /// That install's signer ID (Switch spec 4.3).
        install: Vec<u8>,
    },
    /// The switch or the Homeserver holds a newer version this install signed itself, and
    /// it signs nothing until its records are restored from the signer backup (Switch spec 4.3).
    RecordsBehind {
        /// That version (Switch spec 4.3).
        version: u64,
    },
    /// This install is handing the identity over to the app `to_app`, until the hand-over
    /// takes effect or is aborted (Switch wire 3.12).
    HandingOver {
        /// The new signer's App ID (Switch wire 3.12).
        to_app: Vec<u8>,
    },
    /// This install is taking the identity over, until its first delivery has won
    /// (Switch wire 3.12).
    TakingOver,
    /// A rollback or an equivocation was seen and its alert is held, or the switch hasn't
    /// confirmed since that it holds this signer's newest version (Switch spec 4.3).
    Alarm,
    /// The identity's account at its switch is being erased (Switch spec 12.7).
    Erasing,
    /// The erasure's request may have landed, and a check or a retry met an unsigned
    /// `404` at `since_ms`, with the erasure unconfirmed until the `404` has held for 24 hours
    /// without an answer the pinned key signs (Switch wire 7.4.16, spec 12.7 step 5).
    ErasedUnconfirmed {
        /// When a check first met the `404`, in Unix milliseconds, by the device clock
        /// (Switch wire 7.4.16).
        since_ms: u64,
    },
    /// The identity's account at its switch is erased (Switch spec 12.7).
    Erased,
    /// A provider loss is declared and the service at `origin` hasn't taken the recovery's
    /// version yet (Switch spec 12.6 step 1).
    Recovering {
        /// The service the recovery goes to (Switch spec 12.6).
        origin: String,
    },
    /// The service at `origin` refused the recovery's version for good (Switch spec 12.6
    /// step 1).
    RecoveryRefused {
        /// The service that refused it (Switch spec 12.6).
        origin: String,
    },
    /// A status these bindings don't name (Switch spec 4.3).
    Unknown,
}

impl fmt::Debug for SignerStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SignerStatus(..)")
    }
}

impl From<NativeStatus> for SignerStatus {
    fn from(status: NativeStatus) -> Self {
        match status {
            NativeStatus::Enrolling => Self::Enrolling,
            NativeStatus::FirstEnrollmentHeld => Self::FirstEnrollmentHeld,
            NativeStatus::FirstAccountPresent => Self::FirstAccountPresent,
            NativeStatus::Signing => Self::Signing,
            NativeStatus::ManagedBy { install } => Self::ManagedBy {
                install: install.to_vec(),
            },
            NativeStatus::RecordsBehind { version } => Self::RecordsBehind { version },
            NativeStatus::HandingOver { to_app } => Self::HandingOver {
                to_app: to_app.to_vec(),
            },
            NativeStatus::TakingOver => Self::TakingOver,
            NativeStatus::Alarm => Self::Alarm,
            NativeStatus::Erasing => Self::Erasing,
            NativeStatus::ErasedUnconfirmed { since_ms } => Self::ErasedUnconfirmed { since_ms },
            NativeStatus::Erased => Self::Erased,
            NativeStatus::Recovering { origin } => Self::Recovering { origin },
            NativeStatus::RecoveryRefused { origin } => Self::RecoveryRefused { origin },
            _ => Self::Unknown,
        }
    }
}

/// The signer of one identity, on one install (Switch spec 4.3). A handle: every handle of one
/// signer reaches the same open signer, which [`shutdown_signers`] can end without one.
///
/// A call made from inside one of the host callbacks that serve the call this signer is
/// running waits for that call, but for the reads, and for [`Signer::shutdown`], which
/// stops that call:
/// [signer host guide, 2.4](https://github.com/pubky/pubky-switch/blob/main/docs/signer-host-guide.md#24-the-homeserver-and-the-store).
#[derive(Clone, uniffi::Object)]
pub struct Signer {
    entry: Arc<Entry>,
    identity: [u8; 32],
    install_id: [u8; 16],
    _handles: Arc<Handles>,
}

impl fmt::Debug for Signer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Signer(..)")
    }
}

/// How long a shutdown waits for the signer to be closed and its store's records released
/// before it answers [`SignerFfiError::Closing`].
const SHUTDOWN_WAIT: Duration = Duration::from_secs(30);

/// The life of one signer in this process (Switch spec 3.1). It only moves forward:
/// `Opening`, `Open`, `Closing`, `Closed`.
enum State {
    /// The native create or open is running: it may hold the store's records already.
    Opening {
        /// A shutdown arrived meanwhile: the signer is closed as soon as it is open.
        close_asked: bool,
    },
    /// Open. The signer is absent while a call runs it.
    Open {
        signer: Option<NativeSigner>,
        /// The status as of the open or the last call that ended.
        status: SignerStatus,
        /// Answers the release of the store's records, once the signer has let them go.
        released: Released,
    },
    /// Being closed: no call starts, and the closer takes the signer once the call that
    /// had it has given it back.
    Closing { signer: Option<NativeSigner> },
    /// Closed, with the close's failure or the release's. The store's records are released,
    /// or their release is recorded as owed.
    Closed(Result<(), SignerFfiError>),
}

/// The stage of a [`State`], as its waiters see it.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Stage {
    Opening,
    Open,
    Closing,
    Closed,
}

type Released = mpsc::UnboundedReceiver<Result<(), StoreFailure>>;

/// One signer, from before it takes the store's records until they are released: it is in
/// [`OPEN`] for exactly that long, so the records are never held without an entry a host can
/// reach through the store.
///
/// `state` is the one thing that decides what happens to it. Its lock is taken only inside
/// [`Entry::with`], by the short functions of this type, none of which awaits or calls the
/// host: it is never held across an await or a host callback.
struct Entry {
    /// The id of the store whose records it owns.
    store_id: String,
    state: StdMutex<State>,
    /// The state's stage, for those who wait for it to change. A call selects on it, so it
    /// sees a close however late it looks.
    stage: watch::Sender<Stage>,
    /// One call at a time, in the order they came. Closed with the move to `Closing`:
    /// every call waiting its turn then answers as on a closed signer, without running.
    turn: Arc<Semaphore>,
    /// Wakes the closer when the call that had the signer gives it back.
    given_back: Notify,
}

impl Entry {
    fn with<T>(&self, change: impl FnOnce(&mut State) -> T) -> T {
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        let answer = change(&mut state);
        let stage = match *state {
            State::Opening { .. } => Stage::Opening,
            State::Open { .. } => Stage::Open,
            State::Closing { .. } => Stage::Closing,
            State::Closed(_) => Stage::Closed,
        };
        self.stage
            .send_if_modified(|seen| std::mem::replace(seen, stage) != stage);
        answer
    }

    /// The status, while the signer is open.
    fn status(&self) -> Result<SignerStatus, SignerFfiError> {
        self.with(|state| match state {
            State::Open { status, .. } => Ok(status.clone()),
            _ => Err(closed()),
        })
    }

    /// The opener's signer: the entry is open, or, with a close asked meanwhile, closing.
    /// Returns what the closer needs, if one is to start.
    fn opened(&self, signer: NativeSigner, released: Released) -> Option<Released> {
        self.with(|state| {
            let close_asked = matches!(state, State::Opening { close_asked: true });
            if close_asked {
                *state = State::Closing {
                    signer: Some(signer),
                };
                self.turn.close();
                return Some(released);
            }
            *state = State::Open {
                status: signer.status().into(),
                signer: Some(signer),
                released,
            };
            None
        })
    }

    /// Take the signer out for a call.
    fn take(&self) -> Result<NativeSigner, SignerFfiError> {
        self.with(|state| match state {
            State::Open { signer, .. } => signer.take().ok_or_else(closed),
            _ => Err(closed()),
        })
    }

    /// The call's signer comes back: to the open entry, or to the closer.
    fn give_back(&self, returned: NativeSigner) {
        self.with(|state| match state {
            State::Open { signer, status, .. } => {
                *status = returned.status().into();
                *signer = Some(returned);
            }
            State::Closing { signer } => {
                *signer = Some(returned);
                self.given_back.notify_one();
            }
            // No call has a signer out of an entry in another state.
            State::Opening { .. } | State::Closed(_) => {}
        });
    }

    /// Move to `Closing`. Returns what the closer needs, if this call started the close.
    fn start_closing(&self) -> Option<Released> {
        self.with(|state| match state {
            State::Opening { close_asked } => {
                *close_asked = true;
                None
            }
            State::Open { .. } => {
                let open = std::mem::replace(state, State::Closing { signer: None });
                let State::Open {
                    signer, released, ..
                } = open
                else {
                    return None;
                };
                *state = State::Closing { signer };
                self.turn.close();
                self.given_back.notify_one();
                Some(released)
            }
            State::Closing { .. } | State::Closed(_) => None,
        })
    }

    /// The closer's signer, once the call that had it has given it back.
    fn take_closing(&self) -> Option<NativeSigner> {
        self.with(|state| match state {
            State::Closing { signer } => signer.take(),
            _ => None,
        })
    }

    /// Closed: its records are released, or their release is owed.
    fn finish(self: &Arc<Self>, outcome: Result<(), SignerFfiError>) {
        self.with(|state| *state = State::Closed(outcome));
        let mut open = open_signers();
        if let Some(entries) = open.get_mut(&self.store_id) {
            entries.retain(|held| !Arc::ptr_eq(held, self));
            if entries.is_empty() {
                open.remove(&self.store_id);
            }
        }
    }

    /// Wait until the entry's stage is one `wanted` takes. It is level-triggered: a stage
    /// reached before the wait began is seen.
    async fn reached(&self, wanted: impl Fn(Stage) -> bool) {
        let mut stage = self.stage.subscribe();
        // The sender is the entry's own, so the wait only ends by the stage.
        let _ = stage.wait_for(|stage| wanted(*stage)).await;
    }

    /// The outcome of a closed entry.
    fn outcome(&self) -> Option<Result<(), SignerFfiError>> {
        self.with(|state| match state {
            State::Closed(outcome) => Some(outcome.clone()),
            _ => None,
        })
    }
}

/// The signers of this process that may hold a store's records, by the store's id.
static OPEN: StdMutex<BTreeMap<String, Vec<Arc<Entry>>>> = StdMutex::new(BTreeMap::new());

fn open_signers() -> StdMutexGuard<'static, BTreeMap<String, Vec<Arc<Entry>>>> {
    OPEN.lock().unwrap_or_else(PoisonError::into_inner)
}

/// A new entry, in [`OPEN`] before its signer takes the store's records.
fn opening(store_id: String) -> Arc<Entry> {
    let entry = Arc::new(Entry {
        store_id,
        state: StdMutex::new(State::Opening { close_asked: false }),
        stage: watch::Sender::new(Stage::Opening),
        turn: Arc::new(Semaphore::new(1)),
        given_back: Notify::new(),
    });
    open_signers()
        .entry(entry.store_id.clone())
        .or_default()
        .push(entry.clone());
    entry
}

/// The entries of the same store that are closing.
fn closing_beside(entry: &Arc<Entry>) -> Vec<Arc<Entry>> {
    let open = open_signers();
    let others = open.get(&entry.store_id).into_iter().flatten();
    others
        .filter(|other| !Arc::ptr_eq(other, entry) && *other.stage.borrow() == Stage::Closing)
        .cloned()
        .collect()
}

/// Close the entry: the one way a signer ends, whoever asks (a shutdown, an end through the
/// store, the last handle's drop). The first to ask starts the closer; the others find it
/// closing. Nothing here waits.
fn close(entry: &Arc<Entry>) {
    if let Some(released) = entry.start_closing() {
        start_closer(entry.clone(), released);
    }
}

/// The closer: wait for the signer, close it, which waits for any store call a stopped call
/// left running, wait for the release of the store's records, and record the outcome.
fn start_closer(entry: Arc<Entry>, mut released: Released) {
    let closing = entry.clone();
    let closer = async move {
        let entry = closing;
        let signer = loop {
            if let Some(signer) = entry.take_closing() {
                break signer;
            }
            entry.given_back.notified().await;
        };
        let closing = signer.close().await;
        // The signer's lease let go: the release ran, and one that failed stays owed.
        let release = released.recv().await.unwrap_or(Err(StoreFailure::Unknown));
        entry.finish(
            closing
                .map_err(SignerFfiError::from)
                .and(release.map_err(|failure| StoreError::from(failure).into())),
        );
    };
    match runtime::spawn(closer) {
        Ok(()) => {}
        // No runtime to close it on: the signer was opened on one, so this isn't reached.
        Err(failure) => entry.finish(Err(failure)),
    }
}

/// Wait for the entry to be closed, and answer its outcome. One still closing at `until`
/// answers [`SignerFfiError::Closing`], and goes on closing.
async fn closed_by(entry: &Entry, until: tokio::time::Instant) -> Result<(), SignerFfiError> {
    let closed = entry.reached(|stage| stage == Stage::Closed);
    if tokio::time::timeout_at(until, closed).await.is_err() {
        return Err(SignerFfiError::Closing);
    }
    entry.outcome().unwrap_or(Err(SignerFfiError::Closing))
}

/// What every handle of one signer shares. When the last handle goes, the signer is closed
/// as a shutdown closes it, with nobody waiting for the answer: a release that isn't
/// confirmed stays owed.
struct Handles(Arc<Entry>);

impl Drop for Handles {
    fn drop(&mut self) {
        close(&self.0);
    }
}

#[uniffi::export]
impl SignerEnvironment {
    /// Set up the signer of a new identity, whose key the vault holds, to enroll at the
    /// service at `origin`: commit this install's signer ID and enrollment nonce before
    /// discovery (Switch spec 4.3, account binding 2-3). Nothing is sent.
    pub async fn create_signer(
        &self,
        vault: Box<dyn HostVault>,
        store: Box<dyn HostStore>,
        origin: String,
    ) -> Result<Arc<Signer>, SignerFfiError> {
        bind_signer(|handle| self.signer_env(handle), store, vault, Some(origin)).await
    }

    /// The signer whose records the store holds for the identity the vault holds the key of
    /// (Switch spec 4.3). Nothing is sent.
    pub async fn open_signer(
        &self,
        vault: Box<dyn HostVault>,
        store: Box<dyn HostStore>,
    ) -> Result<Arc<Signer>, SignerFfiError> {
        bind_signer(|handle| self.signer_env(handle), store, vault, None).await
    }
}

/// The signer whose records the store holds, or a new signer enrolling at `origin`
/// (Switch spec 4.3). `environment` builds the signer's environment around the store. A
/// failure after the store's records were taken waits for their release.
pub(crate) async fn bind_signer(
    environment: impl FnOnce(StoreHandle) -> SignerEnv,
    store: Box<dyn HostStore>,
    vault: Box<dyn HostVault>,
    origin: Option<String>,
) -> Result<Arc<Signer>, SignerFfiError> {
    let host: Arc<dyn HostStore> = Arc::from(store);
    let (notice, released) = mpsc::unbounded_channel();
    let env = environment(blocking_store(host.clone(), Some(notice)));
    runtime::run(async move {
        let store_id = runtime::blocking(move || store_id(host.as_ref()))
            .await?
            .map_err(StoreError::from)?;
        open_entry(store_id, released, open_native(env, vault, origin)).await
    })
    .await
}

/// The native signer, created or opened. The environment, and with it the store's handle,
/// is gone when this has answered a failure.
async fn open_native(
    env: SignerEnv,
    vault: Box<dyn HostVault>,
    origin: Option<String>,
) -> Result<NativeSigner, SignerFfiError> {
    let keyring = runtime::blocking(move || native_keyring(vault)).await??;
    let opened = runtime::run_call(async move {
        match origin {
            Some(origin) => NativeSigner::create(env, keyring, &origin).await,
            None => NativeSigner::open(env, keyring).await,
        }
    });
    Ok(opened.await??)
}

/// Run `open` as the opening of a new entry of the store `store_id`: the entry is in
/// [`OPEN`] before `open` starts, and leaves it only closed. An `open` that fails, or is
/// dropped part way, ends closed once the release of whatever it took has answered.
async fn open_entry(
    store_id: String,
    released: Released,
    open: impl Future<Output = Result<NativeSigner, SignerFfiError>>,
) -> Result<Arc<Signer>, SignerFfiError> {
    /// Ends an opening that didn't end open.
    struct Opening(Arc<Entry>, Option<Released>);
    impl Opening {
        /// Wait for the release of what the opening took, and close the entry.
        async fn settle(entry: Arc<Entry>, mut released: Released) {
            // No answer means no lease was taken; a failure means a release is owed.
            let release = released.recv().await.unwrap_or(Ok(()));
            entry.finish(release.map_err(|failure| StoreError::from(failure).into()));
        }
    }
    impl Drop for Opening {
        fn drop(&mut self) {
            if let Some(released) = self.1.take() {
                let entry = self.0.clone();
                if runtime::spawn(Self::settle(entry, released)).is_err() {
                    self.0.finish(Err(SignerFfiError::RuntimeUnavailable));
                }
            }
        }
    }

    let mut opening = Opening(opening(store_id), Some(released));
    let entry = opening.0.clone();
    // A signer of this store that is closing lets its records go first, so an open right
    // after a drop or a shutdown finds them free. One that doesn't close in time is left
    // to the store, which answers that the records are in use.
    let until = tokio::time::Instant::now() + SHUTDOWN_WAIT;
    for other in closing_beside(&entry) {
        let _ = closed_by(&other, until).await;
    }
    let signer = match open.await {
        Ok(signer) => signer,
        Err(failure) => {
            if let Some(released) = opening.1.take() {
                Opening::settle(entry, released).await;
            }
            return Err(failure);
        }
    };
    let (identity, install_id) = (signer.identity(), signer.install_id());
    let released = opening.1.take().ok_or(SignerFfiError::RuntimeUnavailable)?;
    if let Some(released) = entry.opened(signer, released) {
        // A shutdown through the store arrived while this was opening: it wins.
        start_closer(entry, released);
        return Err(closed());
    }
    Ok(Arc::new(Signer {
        _handles: Arc::new(Handles(entry.clone())),
        entry,
        identity,
        install_id,
    }))
}

fn closed() -> SignerFfiError {
    SignerFfiError::InvalidInput {
        reason: "the signer is closed".into(),
    }
}

/// A call's work on the open signer.
pub(crate) type SignerWork<'s, T> =
    Pin<Box<dyn Future<Output = Result<T, SignerFfiError>> + Send + 's>>;

impl Signer {
    /// Run `work` on the open signer, on the bindings' runtime, one call at a time. A
    /// shutdown that arrives while it runs, or while it waits its turn, stops it, and it
    /// answers as on a closed signer (Switch spec 4.3).
    pub(crate) async fn call<T, W>(&self, work: W) -> Result<T, SignerFfiError>
    where
        T: Send + 'static,
        W: for<'s> FnOnce(&'s mut NativeSigner) -> SignerWork<'s, T> + Send + 'static,
    {
        /// Gives the signer back when the call ends, however it ends.
        struct Held(Arc<Entry>, Option<NativeSigner>);
        impl Drop for Held {
            fn drop(&mut self) {
                if let Some(signer) = self.1.take() {
                    self.0.give_back(signer);
                }
            }
        }

        let handle = self.clone();
        runtime::run(async move {
            let entry = handle.entry.clone();
            let turn = entry.turn.clone().acquire_owned();
            let turn = turn.await.map_err(|_| closed())?;
            let call = entry.clone();
            let running = runtime::run_call(async move {
                // The handle and the turn are the call's for as long as it runs.
                let (_handle, _turn) = (handle, turn);
                let mut held = Held(call.clone(), Some(call.take()?));
                let signer = held.1.as_mut().ok_or_else(closed)?;
                // The signer's own rule: a call whose future is dropped part way leaves its
                // records to be read again before the next step, and a store call it left
                // running is waited for at close (Switch spec 3.1).
                tokio::select! {
                    biased;
                    () = call.reached(|stage| stage != Stage::Open) => Err(closed()),
                    answer = work(signer) => answer,
                }
            });
            // A close answers this call at once, also while it waits for a thread: the
            // call's own thread sees the close too, and gives the signer back.
            tokio::select! {
                biased;
                () = entry.reached(|stage| stage != Stage::Open) => Err(closed()),
                answer = running => answer?,
            }
        })
        .await
    }

    /// [`Signer::shutdown`], waiting at most `wait` for the close.
    async fn shutdown_within(&self, wait: Duration) -> Result<(), SignerFfiError> {
        let entry = self.entry.clone();
        runtime::run(async move {
            if entry.outcome().is_some() {
                return Err(closed());
            }
            close(&entry);
            closed_by(&entry, tokio::time::Instant::now() + wait).await
        })
        .await
    }
}

#[uniffi::export]
impl Signer {
    /// Finish the flow in progress, resending what it signed, then publish the newest
    /// version if it isn't published yet (Switch spec 4.3).
    pub async fn resume(&self) -> Result<(), SignerFfiError> {
        self.call(|signer| Box::pin(async move { Ok(signer.resume().await?) }))
            .await
    }

    /// Close the signer and wait for the release of the store's records (Switch spec 3.1).
    /// From the moment it is called, every call answers as on a closed signer: the call the
    /// signer is running is stopped, and the calls waiting their turn don't run. The step a
    /// stopped call was in may or may not have reached the service: the next open and
    /// `resume` read the records again and go on from them.
    ///
    /// It answers the close's failure, else the release's; the signer is closed either way.
    /// If the close isn't done in 30 seconds it answers [`SignerFfiError::Closing`], and the
    /// close goes on. A shutdown of a signer already closed answers as on a closed signer.
    /// What a host does in each case:
    /// [signer host guide, 2.4](https://github.com/pubky/pubky-switch/blob/main/docs/signer-host-guide.md#24-the-homeserver-and-the-store).
    pub async fn shutdown(&self) -> Result<(), SignerFfiError> {
        self.shutdown_within(SHUTDOWN_WAIT).await
    }

    /// The identity (Switch spec 4.3). Answered at once, also while a call runs.
    pub fn identity(&self) -> Result<Vec<u8>, SignerFfiError> {
        self.entry.status()?;
        Ok(self.identity.to_vec())
    }

    /// This install's signer ID (Switch spec 4.3). Answered at once, also while a call runs.
    pub fn install_id(&self) -> Result<Vec<u8>, SignerFfiError> {
        self.entry.status()?;
        Ok(self.install_id.to_vec())
    }

    /// Where the signer stands, as of the open or the last call that ended (Switch spec
    /// 4.3). Answered at once, also while a call runs, whose changes it doesn't show yet.
    pub fn status(&self) -> Result<SignerStatus, SignerFfiError> {
        self.entry.status()
    }
}

/// Shut down every signer this process holds on the store, as [`Signer::shutdown`] does,
/// whether or not a handle to it is left, one still being created or opened included
/// (Switch spec 3.1). It is for a signer the host holds no handle to, as after a cancelled
/// `create_signer` or `open_signer`. Afterwards every handle of those signers answers as on
/// a closed signer.
///
/// It answers success only when every one of them is closed and its records released;
/// otherwise the first failure, [`SignerFfiError::Closing`] for one not closed within 30
/// seconds. With none, it returns at once, having asked the store for its id only. Signers
/// are found by the store's id: two stores given one id are the host's error, and this then
/// shuts down the signers of both. What a host does:
/// [signer host guide, 2.4](https://github.com/pubky/pubky-switch/blob/main/docs/signer-host-guide.md#24-the-homeserver-and-the-store).
#[uniffi::export]
pub async fn shutdown_signers(store: Box<dyn HostStore>) -> Result<(), SignerFfiError> {
    shutdown_signers_within(store, SHUTDOWN_WAIT).await
}

async fn shutdown_signers_within(
    store: Box<dyn HostStore>,
    wait: Duration,
) -> Result<(), SignerFfiError> {
    let host: Arc<dyn HostStore> = Arc::from(store);
    runtime::run(async move {
        let store_id = runtime::blocking(move || store_id(host.as_ref()))
            .await?
            .map_err(StoreError::from)?;
        let entries = open_signers().get(&store_id).cloned().unwrap_or_default();
        for entry in &entries {
            close(entry);
        }
        let until = tokio::time::Instant::now() + wait;
        let mut first = Ok(());
        for entry in &entries {
            let ended = closed_by(entry, until).await;
            if first.is_ok() {
                first = ended;
            }
        }
        first
    })
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_host::{Held, MemoryHost};
    use crate::{
        CoreFailure, HomeserverFailure, HostHomeserver, KeyFailure, RefusalKind, StoreErrorKind,
        TransportOptions, VaultAddOutcome, VaultFailure, protocol, release_owed_locks,
    };
    use tokio::sync::Notify;

    // The first identity in spec/vectors/keys.json, also used by the host programs.
    const SEED: [u8; 32] = [
        0xf6, 0x98, 0x6c, 0xa5, 0x7b, 0xe7, 0x38, 0xd6, 0x81, 0x45, 0xe3, 0xc0, 0x6e, 0xf2, 0xd1,
        0xdc, 0x30, 0x25, 0x95, 0x2f, 0xc2, 0xbe, 0x9d, 0x62, 0x46, 0xc6, 0x49, 0x74, 0x10, 0x51,
        0x91, 0x42,
    ];
    const ORIGIN: &str = "https://switch.example";
    const WAIT: Duration = Duration::from_secs(10);
    /// Long enough for work that isn't held to have answered.
    const SETTLE: Duration = Duration::from_millis(150);

    // Creating and opening a signer only need read access to its existing identity.
    struct Vault(Option<[u8; 32]>);

    impl HostVault for Vault {
        fn load(&self) -> Result<Option<Vec<u8>>, VaultFailure> {
            Ok(self.0.map(Vec::from))
        }
        fn add(&self, _: Vec<u8>) -> Result<VaultAddOutcome, VaultFailure> {
            Err(VaultFailure::Locked)
        }
        fn delete(&self, _: Vec<u8>) -> Result<(), VaultFailure> {
            Err(VaultFailure::Locked)
        }
    }

    fn vault() -> Box<dyn HostVault> {
        Box::new(Vault(Some(SEED)))
    }

    #[derive(Default)]
    struct WriteGate {
        entered: Notify,
        release: Notify,
    }

    #[derive(Default)]
    struct Home {
        files: StdMutex<BTreeMap<String, Vec<u8>>>,
        first_write: StdMutex<Option<Arc<WriteGate>>>,
        /// The writes asked of it, and those it made.
        puts: Arc<std::sync::atomic::AtomicUsize>,
        written: Arc<std::sync::atomic::AtomicUsize>,
    }

    #[async_trait::async_trait]
    impl HostHomeserver for Home {
        async fn get(
            &self,
            path: String,
            limit: u64,
        ) -> Result<Option<Vec<u8>>, HomeserverFailure> {
            let files = self.files.lock().unwrap();
            let bytes = files.get(&path);
            if bytes.is_some_and(|bytes| bytes.len() as u64 > limit) {
                return Err(HomeserverFailure::TooLarge { limit });
            }
            Ok(bytes.cloned())
        }
        async fn put(&self, path: String, bytes: Vec<u8>) -> Result<(), HomeserverFailure> {
            self.puts.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let gate = self.first_write.lock().unwrap().take();
            if let Some(gate) = gate {
                gate.entered.notify_one();
                gate.release.notified().await;
            }
            self.files.lock().unwrap().insert(path, bytes);
            self.written
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(())
        }
        async fn delete(&self, path: String) -> Result<(), HomeserverFailure> {
            self.files.lock().unwrap().remove(&path);
            Ok(())
        }
    }

    /// An environment whose service is never reached: enough to set up and open.
    fn offline() -> Arc<SignerEnvironment> {
        protocol::sample().unwrap();
        SignerEnvironment::new(Box::<Home>::default(), TransportOptions::default()).unwrap()
    }

    fn assert_closed<T>(result: Result<T, SignerFfiError>) {
        assert!(
            matches!(result, Err(SignerFfiError::InvalidInput { ref reason }) if reason == "the signer is closed"),
            "{:?}",
            result.err()
        );
    }

    fn assert_store<T>(result: Result<T, SignerFfiError>, expected: StoreErrorKind) {
        assert!(
            matches!(result, Err(SignerFfiError::Store { kind, .. }) if kind == expected),
            "{:?}",
            result.err()
        );
    }

    /// Whether `task` is still running after work that isn't held would have answered.
    async fn held_up<T>(task: &mut tokio::task::JoinHandle<T>) -> bool {
        tokio::time::timeout(SETTLE, task).await.is_err()
    }

    async fn answer<T>(task: tokio::task::JoinHandle<T>) -> T {
        tokio::time::timeout(WAIT, task).await.unwrap().unwrap()
    }

    async fn entered(gate: &Notify) {
        tokio::time::timeout(WAIT, gate.notified()).await.unwrap();
    }

    #[tokio::test]
    async fn test_signer_setup_refusals() {
        let environment = offline();
        let host = MemoryHost::default();
        assert!(matches!(
            environment.open_signer(vault(), host.boxed()).await,
            Err(SignerFfiError::Refused {
                kind: RefusalKind::NotSetUp,
                ..
            })
        ));
        assert!(!host.held(), "a failed open waits for its release");
        let signer = environment
            .create_signer(vault(), host.boxed(), ORIGIN.into())
            .await
            .unwrap();
        assert_store(
            environment.open_signer(vault(), host.boxed()).await,
            StoreErrorKind::InUse,
        );
        signer.shutdown().await.unwrap();
        assert!(matches!(
            environment
                .create_signer(vault(), host.boxed(), ORIGIN.into())
                .await,
            Err(SignerFfiError::Refused {
                kind: RefusalKind::AlreadySetUp,
                ..
            })
        ));
        assert!(!host.held(), "a failed creation waits for its release");
    }

    #[tokio::test]
    async fn test_signer_invalid_origin_and_empty_vault() {
        let environment = offline();
        let host = MemoryHost::default();
        assert!(matches!(
            environment
                .create_signer(vault(), host.boxed(), "no origin".into())
                .await,
            Err(SignerFfiError::InvalidData {
                kind: CoreFailure::Invalid
            })
        ));
        assert!(matches!(
            environment
                .create_signer(Box::new(Vault(None)), host.boxed(), ORIGIN.into())
                .await,
            Err(SignerFfiError::Key {
                kind: KeyFailure::Missing
            })
        ));
        assert!(!host.held());
        let signer = environment
            .create_signer(vault(), host.boxed(), ORIGIN.into())
            .await
            .unwrap();
        signer.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn test_signer_failed_open_answers_after_its_release() {
        // An open that fails after it took the records: its release is held, and neither
        // the open nor a shutdown through the store answers before it.
        let environment = offline();
        let host = MemoryHost::default();
        let (released, go) = host.gate(Held::Release);
        let opening = environment.clone();
        let store = host.boxed();
        let mut open = tokio::spawn(async move { opening.open_signer(vault(), store).await });
        entered(&released).await;
        assert!(
            held_up(&mut open).await,
            "the open answered before its release"
        );
        let store = host.boxed();
        let mut ending = tokio::spawn(shutdown_signers(store));
        assert!(
            held_up(&mut ending).await,
            "a shutdown answered during the opening"
        );
        go.send(None).unwrap();
        assert!(matches!(
            answer(open).await,
            Err(SignerFfiError::Refused {
                kind: RefusalKind::NotSetUp,
                ..
            })
        ));
        answer(ending).await.unwrap();
        assert!(!host.held());
    }

    #[tokio::test]
    async fn test_signer_dropped_opening_ends_closed() {
        // An opening whose future is dropped part way: the entry stays until the release
        // of what it took has answered, and a shutdown through the store answers only then.
        let host = MemoryHost::default();
        let id = host.store_id().unwrap();
        let (lease, released) = mpsc::unbounded_channel();
        let opening = tokio::spawn(open_entry(id, released, std::future::pending()));
        tokio::time::sleep(SETTLE).await;
        let short = Duration::from_millis(100);
        let pending = shutdown_signers_within(host.boxed(), short).await;
        assert!(
            matches!(pending, Err(SignerFfiError::Closing)),
            "{pending:?}"
        );
        opening.abort();
        assert!(opening.await.unwrap_err().is_cancelled());
        // Dropped, with its lease not released yet.
        let pending = shutdown_signers_within(host.boxed(), short).await;
        assert!(
            matches!(pending, Err(SignerFfiError::Closing)),
            "{pending:?}"
        );
        lease.send(Err(StoreFailure::Unavailable)).unwrap();
        drop(lease);
        // The release answered, with a failure: whoever is waiting for the entry then gets
        // that failure, and once it is closed nothing is left to shut down.
        let ended = tokio::time::timeout(WAIT, async {
            loop {
                match shutdown_signers_within(host.boxed(), short).await {
                    Err(SignerFfiError::Closing) => {}
                    ended => break ended,
                }
            }
        })
        .await
        .unwrap();
        match ended {
            Ok(()) => {}
            failed => assert_store(failed, StoreErrorKind::Unavailable),
        }
        shutdown_signers(host.boxed()).await.unwrap();
    }

    #[tokio::test]
    async fn test_signer_shutdown_during_opening_wins() {
        // A create held at the store's acquisition: a shutdown through the store waits for
        // it, and the create answers as on a closed signer.
        let environment = offline();
        let host = MemoryHost::default();
        let (acquiring, go) = host.gate(Held::Acquire);
        let creating = environment.clone();
        let store = host.boxed();
        let mut create =
            tokio::spawn(
                async move { creating.create_signer(vault(), store, ORIGIN.into()).await },
            );
        entered(&acquiring).await;
        let mut ending = tokio::spawn(shutdown_signers(host.boxed()));
        assert!(
            held_up(&mut ending).await,
            "a shutdown answered during the opening"
        );
        assert!(held_up(&mut create).await);
        go.send(None).unwrap();
        assert_closed(answer(create).await);
        answer(ending).await.unwrap();
        assert!(!host.held());
        // The signer the create set up is the store's: it opens.
        let signer = environment
            .open_signer(vault(), host.boxed())
            .await
            .unwrap();
        signer.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn test_signer_closed_answers() {
        let environment = offline();
        let host = MemoryHost::default();
        let signer = environment
            .create_signer(vault(), host.boxed(), ORIGIN.into())
            .await
            .unwrap();
        let id = signer.install_id().unwrap();
        let identity = signer.identity().unwrap();
        signer.shutdown().await.unwrap();
        assert_closed(signer.resume().await);
        assert_closed(signer.status());
        assert_closed(signer.identity());
        assert_closed(signer.install_id());
        assert_closed(signer.shutdown().await);
        assert!(!host.held());

        let reopened = environment
            .open_signer(vault(), host.boxed())
            .await
            .unwrap();
        assert_eq!(reopened.install_id().unwrap(), id);
        assert_eq!(reopened.identity().unwrap(), identity);
        drop(reopened);
        // The last handle's drop closes the signer, and an open right after it waits for
        // that close.
        environment
            .open_signer(vault(), host.boxed())
            .await
            .unwrap()
            .shutdown()
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn test_signer_shutdown_waits_for_the_release() {
        let environment = offline();
        let host = MemoryHost::default();
        let signer = environment
            .create_signer(vault(), host.boxed(), ORIGIN.into())
            .await
            .unwrap();
        let (releasing, go) = host.gate(Held::Release);
        let ending = signer.clone();
        let mut shutdown = tokio::spawn(async move { ending.shutdown().await });
        entered(&releasing).await;
        assert!(
            held_up(&mut shutdown).await,
            "shutdown answered before the release"
        );
        // Closed for every call from the moment the shutdown began.
        assert_closed(signer.status());
        assert_closed(signer.identity());
        assert_closed(signer.resume().await);
        // A second shutdown and one through the store join the same close.
        let again = signer.clone();
        let mut second = tokio::spawn(async move { again.shutdown().await });
        let mut through_store = tokio::spawn(shutdown_signers(host.boxed()));
        assert!(held_up(&mut second).await);
        assert!(held_up(&mut through_store).await);
        go.send(None).unwrap();
        answer(shutdown).await.unwrap();
        answer(second).await.unwrap();
        answer(through_store).await.unwrap();
        assert!(!host.held());
        assert_closed(signer.shutdown().await);
    }

    #[tokio::test]
    async fn test_signer_shutdown_answers_the_release_failure() {
        let environment = offline();
        let host = MemoryHost::default();
        let signer = environment
            .create_signer(vault(), host.boxed(), ORIGIN.into())
            .await
            .unwrap();
        host.state().fail_release = Some(StoreFailure::Unavailable);
        assert_store(signer.shutdown().await, StoreErrorKind::Unavailable);
        assert_closed(signer.status());
        assert_closed(signer.shutdown().await);
        // The release stays owed until the host's own call settles it.
        assert!(host.held());
        release_owed_locks(host.boxed()).await.unwrap();
        assert!(!host.held());
        environment
            .open_signer(vault(), host.boxed())
            .await
            .unwrap()
            .shutdown()
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn test_signer_status_variants() {
        use NativeStatus as N;
        use SignerStatus as S;
        let id = [7; 16];
        for (native, expected) in [
            (N::Enrolling, S::Enrolling),
            (N::FirstEnrollmentHeld, S::FirstEnrollmentHeld),
            (N::FirstAccountPresent, S::FirstAccountPresent),
            (N::Signing, S::Signing),
            (
                N::ManagedBy { install: id },
                S::ManagedBy {
                    install: id.to_vec(),
                },
            ),
            (
                N::RecordsBehind { version: 31 },
                S::RecordsBehind { version: 31 },
            ),
            (
                N::HandingOver { to_app: id },
                S::HandingOver {
                    to_app: id.to_vec(),
                },
            ),
            (N::TakingOver, S::TakingOver),
            (N::Alarm, S::Alarm),
            (N::Erasing, S::Erasing),
            (
                N::ErasedUnconfirmed { since_ms: 987 },
                S::ErasedUnconfirmed { since_ms: 987 },
            ),
            (N::Erased, S::Erased),
            (
                N::Recovering {
                    origin: ORIGIN.into(),
                },
                S::Recovering {
                    origin: ORIGIN.into(),
                },
            ),
            (
                N::RecoveryRefused {
                    origin: ORIGIN.into(),
                },
                S::RecoveryRefused {
                    origin: ORIGIN.into(),
                },
            ),
        ] {
            assert_eq!(SignerStatus::from(native), expected);
        }
    }

    #[cfg(feature = "test-fixtures")]
    mod scripted {
        use super::*;
        use crate::{FixtureService, ServiceFailure, TransportFailure};

        /// A vault whose reads wait for the test once it is armed.
        #[derive(Clone, Default)]
        struct SlowVault {
            armed: Arc<std::sync::atomic::AtomicBool>,
            entered: Arc<Notify>,
            release: Arc<StdMutex<Option<std::sync::mpsc::Receiver<()>>>>,
        }

        impl HostVault for SlowVault {
            fn load(&self) -> Result<Option<Vec<u8>>, VaultFailure> {
                if self.armed.swap(false, std::sync::atomic::Ordering::SeqCst) {
                    self.entered.notify_one();
                    let release = self.release.lock().unwrap().take();
                    if let Some(release) = release {
                        let _ = release.recv();
                    }
                }
                Ok(Some(SEED.to_vec()))
            }
            fn add(&self, _: Vec<u8>) -> Result<VaultAddOutcome, VaultFailure> {
                Err(VaultFailure::Locked)
            }
            fn delete(&self, _: Vec<u8>) -> Result<(), VaultFailure> {
                Err(VaultFailure::Locked)
            }
        }

        fn service(home: Home) -> Arc<FixtureService> {
            protocol::sample().unwrap();
            FixtureService::new(SEED.to_vec(), Box::new(home)).unwrap()
        }

        /// A service whose Homeserver holds its first write, with the writes asked of it
        /// and the writes it made.
        fn gated() -> (
            Arc<FixtureService>,
            Arc<WriteGate>,
            [Arc<std::sync::atomic::AtomicUsize>; 2],
        ) {
            let gate = Arc::new(WriteGate::default());
            let home = Home {
                first_write: StdMutex::new(Some(gate.clone())),
                ..Home::default()
            };
            let counts = [home.puts.clone(), home.written.clone()];
            (service(home), gate, counts)
        }

        async fn create(service: &FixtureService, host: &MemoryHost) -> Arc<Signer> {
            service
                .create_signer(vault(), host.boxed(), ORIGIN.into())
                .await
                .unwrap()
        }

        fn resuming(signer: &Arc<Signer>) -> tokio::task::JoinHandle<Result<(), SignerFfiError>> {
            let running = signer.clone();
            tokio::spawn(async move { running.resume().await })
        }

        /// Open the store's signer again and finish its enrollment: sent once in all.
        async fn enrolls_once(service: &FixtureService, host: &MemoryHost) {
            let reopened = service.open_signer(vault(), host.boxed()).await.unwrap();
            reopened.resume().await.unwrap();
            assert_eq!(reopened.status().unwrap(), SignerStatus::Signing);
            assert_eq!(service.enrollments(), 1);
            reopened.shutdown().await.unwrap();
        }

        #[tokio::test]
        async fn test_signer_enrollment() {
            let service = service(Home::default());
            let host = MemoryHost::default();
            let signer = create(&service, &host).await;
            assert_eq!(service.enrollments(), 0);
            assert_eq!(signer.status().unwrap(), SignerStatus::Enrolling);
            let key = crate::open_keyring(vault()).await.unwrap().public_key();
            assert_eq!(signer.identity().unwrap(), key);
            assert_eq!(signer.install_id().unwrap().len(), 16);
            signer.resume().await.unwrap();
            assert_eq!(signer.status().unwrap(), SignerStatus::Signing);
            signer.shutdown().await.unwrap();
            let reopened = service.open_signer(vault(), host.boxed()).await.unwrap();
            assert_eq!(reopened.status().unwrap(), SignerStatus::Signing);
            reopened.shutdown().await.unwrap();
        }

        #[tokio::test]
        async fn test_signer_lost_enrollment_answer() {
            let service = service(Home::default());
            let host = MemoryHost::default();
            let signer = create(&service, &host).await;
            let id = signer.install_id().unwrap();
            service.lose_next_enroll_answer();
            assert!(matches!(
                signer.resume().await,
                Err(SignerFfiError::Service {
                    kind: ServiceFailure::Transport,
                    transport: Some(TransportFailure::Timeout),
                    ..
                })
            ));
            assert_eq!(service.enrollments(), 1);
            signer.shutdown().await.unwrap();
            let reopened = service.open_signer(vault(), host.boxed()).await.unwrap();
            assert_eq!(reopened.install_id().unwrap(), id);
            reopened.resume().await.unwrap();
            assert_eq!(reopened.status().unwrap(), SignerStatus::Signing);
            assert_eq!(service.enrollments(), 1);
            reopened.shutdown().await.unwrap();
        }

        #[tokio::test]
        async fn test_signer_reads_answer_while_a_call_runs() {
            let (service, gate, _) = gated();
            let host = MemoryHost::default();
            let signer = create(&service, &host).await;
            let resume = resuming(&signer);
            entered(&gate.entered).await;
            // The resume has the signer, and the reads don't wait for it.
            assert_eq!(signer.status().unwrap(), SignerStatus::Enrolling);
            assert_eq!(signer.install_id().unwrap().len(), 16);
            assert_eq!(signer.identity().unwrap().len(), 32);
            gate.release.notify_one();
            answer(resume).await.unwrap();
            // The status is the one the call left.
            assert_eq!(signer.status().unwrap(), SignerStatus::Signing);
            signer.shutdown().await.unwrap();
        }

        #[tokio::test]
        async fn test_signer_shutdown_stops_the_running_and_the_waiting_call() {
            let (service, gate, [puts, written]) = gated();
            let host = MemoryHost::default();
            let signer = create(&service, &host).await;
            let mut resume = resuming(&signer);
            entered(&gate.entered).await;
            // A second call waits its turn behind the one held at the Homeserver.
            let mut waiting = resuming(&signer);
            assert!(held_up(&mut waiting).await);
            assert!(held_up(&mut resume).await);
            tokio::time::timeout(WAIT, signer.shutdown())
                .await
                .unwrap()
                .unwrap();
            assert_closed(answer(resume).await);
            // The waiting call never ran: the Homeserver was asked for the one write the
            // stopped call was held at, and no other.
            assert_closed(answer(waiting).await);
            assert_eq!(puts.load(std::sync::atomic::Ordering::SeqCst), 1);
            // That write is still held, and was never let go: the call's own thread dropped
            // its future where it waited, and the signer was closed and released without it.
            assert_eq!(written.load(std::sync::atomic::Ordering::SeqCst), 0);
            assert!(!host.held());
            // The next signer reads the records again and finishes the step.
            enrolls_once(&service, &host).await;
        }

        #[tokio::test]
        async fn test_signer_shutdown_answers_what_a_stopped_call_left() {
            let service = service(Home::default());
            let host = MemoryHost::default();
            let signer = create(&service, &host).await;
            let (writing, go) = host.gate(Held::Commit);
            let resume = resuming(&signer);
            entered(&writing).await;
            // The resume is stopped while its write is with the host: the close waits for
            // that write and answers its failure.
            let ending = signer.clone();
            let mut shutdown = tokio::spawn(async move { ending.shutdown().await });
            assert_closed(answer(resume).await);
            assert!(
                held_up(&mut shutdown).await,
                "shutdown answered before the write it waits for"
            );
            assert!(host.held());
            go.send(Some(StoreFailure::Unknown)).unwrap();
            assert_store(answer(shutdown).await, StoreErrorKind::Unknown);
            assert!(!host.held());
            enrolls_once(&service, &host).await;
        }

        #[tokio::test]
        async fn test_signer_last_handle_drop_waits_for_a_stopped_write() {
            // Only the running call holds a handle; the signer is stopped through the
            // store while its write is with the host. The call's handle goes, and the
            // close still waits for that write: no answer and no release before it.
            let service = service(Home::default());
            let host = MemoryHost::default();
            let signer = create(&service, &host).await;
            let (writing, go) = host.gate(Held::Commit);
            let resume = resuming(&signer);
            drop(signer);
            entered(&writing).await;
            let mut ending = tokio::spawn(shutdown_signers(host.boxed()));
            assert_closed(answer(resume).await);
            assert!(
                held_up(&mut ending).await,
                "the store's signers were reported closed with a write still running"
            );
            assert!(host.held());
            go.send(None).unwrap();
            answer(ending).await.unwrap();
            assert!(!host.held());
            enrolls_once(&service, &host).await;
        }

        #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
        async fn test_signer_shutdown_awaited_by_a_store_callback_answers_closing() {
            // A store callback of the running call waits, on another thread, for the
            // signer's shutdown. The shutdown can't finish before the callback returns, so
            // it answers that the signer is closing; the close ends once the callback has
            // returned.
            let service = service(Home::default());
            let host = MemoryHost::default();
            let signer = create(&service, &host).await;
            let (told, heard) = std::sync::mpsc::channel();
            let ending = signer.clone();
            let runtime = tokio::runtime::Handle::current();
            host.state().in_commit = Some(Box::new(move || {
                let waited = std::thread::spawn(move || {
                    runtime.block_on(ending.shutdown_within(Duration::from_millis(300)))
                });
                told.send(waited.join().unwrap()).unwrap();
            }));
            assert_closed(signer.resume().await);
            let from_callback = tokio::task::spawn_blocking(move || heard.recv_timeout(WAIT))
                .await
                .unwrap()
                .unwrap();
            assert!(
                matches!(from_callback, Err(SignerFfiError::Closing)),
                "{from_callback:?}"
            );
            // The callback has returned: the close ends, and a shutdown through the store
            // answers its outcome.
            shutdown_signers(host.boxed()).await.unwrap();
            assert!(!host.held());
            assert_closed(signer.shutdown().await);
            enrolls_once(&service, &host).await;
        }

        #[tokio::test]
        async fn test_signer_vault_calls_never_hold_the_runtime() {
            // As many signers as calls may run at once, each in a vault call that the host
            // holds. A signer's call, and the vault callbacks it makes, has a thread of its
            // own, so the runtime's workers still serve a timer and the wait of one more
            // caller, who is given up without having started.
            let _alone = runtime::CALLS_FILLED.lock().await;
            let mut held = Vec::new();
            for _ in 0..4 {
                let service = service(Home::default());
                let host = MemoryHost::default();
                let (release, wait) = std::sync::mpsc::channel();
                let vault = SlowVault::default();
                *vault.release.lock().unwrap() = Some(wait);
                let signer = service
                    .create_signer(Box::new(vault.clone()), host.boxed(), ORIGIN.into())
                    .await
                    .unwrap();
                vault.armed.store(true, std::sync::atomic::Ordering::SeqCst);
                let resume = resuming(&signer);
                entered(&vault.entered).await;
                held.push((signer, resume, release));
            }
            let timer = runtime::run(async {
                tokio::time::sleep(Duration::from_millis(20)).await;
                Ok(7)
            });
            assert_eq!(tokio::time::timeout(WAIT, timer).await.unwrap().unwrap(), 7);
            let ran = Arc::new(std::sync::atomic::AtomicBool::new(false));
            let begun = ran.clone();
            let fifth = runtime::run(async move {
                let wait = Duration::from_millis(200);
                runtime::run_call_within(wait, async move {
                    begun.store(true, std::sync::atomic::Ordering::SeqCst);
                })
                .await
            });
            assert!(matches!(
                tokio::time::timeout(WAIT, fifth).await.unwrap(),
                Err(SignerFfiError::RuntimeUnavailable)
            ));
            assert!(!ran.load(std::sync::atomic::Ordering::SeqCst));
            for (signer, resume, release) in held {
                release.send(()).unwrap();
                answer(resume).await.unwrap();
                assert_eq!(signer.status().unwrap(), SignerStatus::Signing);
                signer.shutdown().await.unwrap();
            }
        }

        #[tokio::test]
        async fn test_signer_shutdown_signers_ends_a_signer_without_a_handle() {
            let service = service(Home::default());
            let host = MemoryHost::default();
            service
                .create_signer_losing_handle(vault(), host.boxed(), ORIGIN.into())
                .await
                .unwrap();
            assert_store(
                service.open_signer(vault(), host.boxed()).await,
                StoreErrorKind::InUse,
            );
            // Owed releases can't free it: none is owed.
            release_owed_locks(host.boxed()).await.unwrap();
            assert!(host.held());
            shutdown_signers(host.boxed()).await.unwrap();
            assert!(!host.held());
            let signer = service.open_signer(vault(), host.boxed()).await.unwrap();
            // A signer with handles left: every handle answers as closed.
            let other = signer.clone();
            shutdown_signers(host.boxed()).await.unwrap();
            assert_closed(other.status());
            assert_closed(signer.shutdown().await);
            // Nothing open: nothing to shut down, and nothing asked of the store but its id.
            let calls = host.state().calls;
            shutdown_signers(host.boxed()).await.unwrap();
            assert_eq!(host.state().calls, calls);
            service
                .open_signer(vault(), host.boxed())
                .await
                .unwrap()
                .shutdown()
                .await
                .unwrap();
        }

        #[tokio::test]
        async fn test_signer_debug_omits_records_and_keys() {
            let service = service(Home::default());
            let signer = create(&service, &MemoryHost::default()).await;
            assert_eq!(format!("{service:?}"), "FixtureService(..)");
            assert_eq!(format!("{signer:?}"), "Signer(..)");
            let status = SignerStatus::Recovering {
                origin: ORIGIN.into(),
            };
            assert_eq!(format!("{status:?}"), "SignerStatus(..)");
            signer.shutdown().await.unwrap();
        }
    }
}
