//! The bindings' own runtime. Every asynchronous call runs on its threads, never on the
//! thread a host calls from: a host thread only waits for the answer, and no call blocks a
//! foreign thread for long.

use crate::SignerFfiError;
use std::cell::Cell;
use std::future::Future;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

/// The stack of every runtime thread, room for the deepest signer flow in a debug build.
const THREAD_STACK_BYTES: usize = 4 * 1024 * 1024;

const WORKER_THREADS: usize = 2;

/// The signer calls that run at once, over every signer of the process ([`run_call`]).
const SIGNER_CALLS: usize = 4;

/// The most threads for the host's synchronous callbacks and for the signer calls that make
/// them: a phone's budget, not the runtime's default of hundreds. A running signer call
/// holds one, on which its vault callbacks run too, and one more for each store call it
/// makes, one at a time. So this carries [`SIGNER_CALLS`] calls each in a store call, with
/// two left for the store's releases and a keyring's calls.
const BLOCKING_THREADS: usize = 2 * SIGNER_CALLS + 2;

/// How long work that calls the host waits for a blocking thread to take it up
/// ([`blocking`]).
const BLOCKING_START_WAIT: Duration = Duration::from_secs(30);

fn runtime() -> Result<&'static tokio::runtime::Runtime, SignerFfiError> {
    static RUNTIME: OnceLock<tokio::runtime::Runtime> = OnceLock::new();
    static STARTING: Mutex<()> = Mutex::new(());
    if let Some(runtime) = RUNTIME.get() {
        return Ok(runtime);
    }
    // One builder at a time, so a second runtime is never built and then dropped, which
    // would block inside the caller's asynchronous context.
    let _starting = STARTING
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if let Some(runtime) = RUNTIME.get() {
        return Ok(runtime);
    }
    let built = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(WORKER_THREADS)
        .max_blocking_threads(BLOCKING_THREADS)
        .thread_stack_size(THREAD_STACK_BYTES)
        .thread_name("pubky-switch-signer")
        .enable_all()
        .build()
        .map_err(|_| SignerFfiError::RuntimeUnavailable)?;
    Ok(RUNTIME.get_or_init(|| built))
}

/// Run `work` on the bindings' runtime and wait for its answer. A host that stops waiting
/// only stops this wait: `work` runs on, to its end or until its signer is shut down.
///
/// A call started from inside a host callback is refused ([`refuse_reentry`]) before
/// `work` starts. An export that takes any state before it gets here, such as a secret
/// used once, calls [`refuse_reentry`] first, so a refused call changes nothing.
pub(crate) async fn run<F, T>(work: F) -> Result<T, SignerFfiError>
where
    F: Future<Output = Result<T, SignerFfiError>> + Send + 'static,
    T: Send + 'static,
{
    refuse_reentry()?;
    runtime()?.spawn(work).await.map_err(stopped)?
}

/// Start `work` on the bindings' runtime, from any thread, and leave it to run.
pub(crate) fn spawn(work: impl Future<Output = ()> + Send + 'static) -> Result<(), SignerFfiError> {
    drop(runtime()?.spawn(work));
    Ok(())
}

/// Run a signer's call: `work`, which is the signer's asynchronous code, and which calls the
/// host's vault synchronously on the way. Called from a task on the runtime.
///
/// The call gets a blocking thread of its own, which drives `work` to its end; the network
/// and the timers it waits for stay with the runtime's workers. Its vault callbacks run on
/// that thread, so the workers never wait for the host, whatever a vault does and however
/// long it takes.
///
/// At most [`SIGNER_CALLS`] calls run at once, so a store call a running call makes always
/// finds a thread ([`BLOCKING_THREADS`]). One more waits for its turn, holding no thread,
/// for [`BLOCKING_START_WAIT`] at most, and then fails with
/// [`SignerFfiError::RuntimeUnavailable`], having started nothing.
pub(crate) async fn run_call<T: Send + 'static>(
    work: impl Future<Output = T> + Send + 'static,
) -> Result<T, SignerFfiError> {
    run_call_within(BLOCKING_START_WAIT, work).await
}

pub(crate) async fn run_call_within<T: Send + 'static>(
    wait: Duration,
    work: impl Future<Output = T> + Send + 'static,
) -> Result<T, SignerFfiError> {
    static RUNNING: OnceLock<Arc<tokio::sync::Semaphore>> = OnceLock::new();
    let running = RUNNING
        .get_or_init(|| Arc::new(tokio::sync::Semaphore::new(SIGNER_CALLS)))
        .clone();
    let Ok(Ok(running)) = tokio::time::timeout(wait, running.acquire_owned()).await else {
        return Err(SignerFfiError::RuntimeUnavailable);
    };
    let runtime = tokio::runtime::Handle::current();
    // The call's place goes with its thread: it is free again only when the thread is,
    // also when nobody waits for the answer any more.
    blocking(move || {
        let _running = running;
        runtime.block_on(work)
    })
    .await
}

/// Held by a test while it takes every place a signer call can run in, so that two such
/// tests don't each hold some and wait for the rest.
#[cfg(test)]
pub(crate) static CALLS_FILLED: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// The failure of work that didn't reach its end.
fn stopped(failed: tokio::task::JoinError) -> SignerFfiError {
    if failed.is_panic() {
        // A defect, not the runtime's state: the call's failure, with no inner text.
        SignerFfiError::Unknown {
            reason: "the call stopped unexpectedly".to_owned(),
        }
    } else {
        SignerFfiError::RuntimeUnavailable
    }
}

/// Run `work`, which calls the host's synchronous callbacks, on one of the runtime's few
/// blocking threads, and wait for its answer. Called from a task on the runtime.
///
/// A callback that waits, on another thread, for a call into the bindings holds its
/// blocking thread while that call needs one too, and a slow callback holds its own. Once
/// every blocking thread is held, work waits for one. Work that no thread has taken up
/// within [`BLOCKING_START_WAIT`] is given up before it starts, and its call fails with
/// [`SignerFfiError::RuntimeUnavailable`]: a callback waiting for it gets that answer.
///
/// Work a thread has taken up always runs to its end, however long the host takes. So this
/// ends no wait for work already taken up: a callback that waits for a call whose own
/// callbacks then wait for something the first one holds, such as a lock of the host's,
/// never returns, and both threads stay held. Nothing here can end the host's own deadlock.
pub(crate) async fn blocking<T: Send + 'static>(
    work: impl FnOnce() -> T + Send + 'static,
) -> Result<T, SignerFfiError> {
    blocking_within(BLOCKING_START_WAIT, work).await
}

async fn blocking_within<T: Send + 'static>(
    wait: Duration,
    work: impl FnOnce() -> T + Send + 'static,
) -> Result<T, SignerFfiError> {
    const WAITING: u8 = 0;
    const STARTED: u8 = 1;
    const GIVEN_UP: u8 = 2;
    // Exactly one of the two sides moves the state on: the thread that takes the work up,
    // or this wait when its time runs out.
    let state = Arc::new(AtomicU8::new(WAITING));
    let claim = |state: &AtomicU8, next| {
        state
            .compare_exchange(WAITING, next, Ordering::SeqCst, Ordering::SeqCst)
            .is_ok()
    };
    let taken = state.clone();
    let mut job = tokio::task::spawn_blocking(move || claim(&taken, STARTED).then(work));
    let joined = match tokio::time::timeout(wait, &mut job).await {
        Ok(joined) => joined,
        Err(_) if claim(&state, GIVEN_UP) => return Err(SignerFfiError::RuntimeUnavailable),
        // Taken up, and still with the host.
        Err(_) => job.await,
    };
    joined
        .map_err(stopped)?
        .ok_or(SignerFfiError::RuntimeUnavailable)
}

thread_local! {
    static IN_CALLBACK: Cell<u32> = const { Cell::new(0) };
}

/// Run `call`, a synchronous host callback, marking this thread for exactly as long as the
/// host's code is on its stack ([`refuse_reentry`]).
pub(crate) fn in_callback<T>(call: impl FnOnce() -> T) -> T {
    struct Leave;
    impl Drop for Leave {
        fn drop(&mut self) {
            IN_CALLBACK.with(|depth| depth.set(depth.get().saturating_sub(1)));
        }
    }
    IN_CALLBACK.with(|depth| depth.set(depth.get().saturating_add(1)));
    let _leave = Leave;
    call()
}

/// Refuse a call into the bindings that is started on a thread while a synchronous host
/// callback is on that thread's stack: the callback started it, and a callback that waited
/// for it would hold one of the few blocking threads while the call waits for another.
///
/// The bindings can't tell whether the callback waits, so such a call is refused either
/// way: a host starts it on another thread, or after the callback returned. Nothing else
/// is refused: only the host's own code runs on a blocking thread during its callback. A
/// callback that waits for a call started on another thread isn't seen here; [`blocking`]
/// bounds what that can cost.
pub(crate) fn refuse_reentry() -> Result<(), SignerFfiError> {
    if IN_CALLBACK.with(Cell::get) > 0 {
        return Err(SignerFfiError::InvalidInput {
            reason: "a call from inside a host callback".to_owned(),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test(flavor = "current_thread")]
    async fn test_runtime_runs_work_on_its_own_threads() {
        let caller = std::thread::current().id();
        let (thread, name) = run(async {
            let here = std::thread::current();
            Ok((here.id(), here.name().map(str::to_owned)))
        })
        .await
        .unwrap();
        assert_ne!(thread, caller);
        assert_eq!(name.as_deref(), Some("pubky-switch-signer"));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn test_runtime_passes_a_failure_through() {
        let failed = run(async { Err::<(), _>(SignerFfiError::RuntimeUnavailable) }).await;
        assert!(matches!(failed, Err(SignerFfiError::RuntimeUnavailable)));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn test_runtime_panic_is_the_unknown_failure() {
        let failed = run(async {
            if std::hint::black_box(true) {
                panic!("a defect");
            }
            Ok(())
        })
        .await;
        assert!(
            matches!(failed, Err(SignerFfiError::Unknown { .. })),
            "{failed:?}"
        );
        assert!(!format!("{failed:?}").contains("a defect"));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn test_runtime_refuses_a_call_from_inside_a_callback() {
        let refused = in_callback(|| {
            let mut call = Box::pin(run(async { Ok(()) }));
            let waker = std::task::Waker::noop();
            call.as_mut()
                .poll(&mut std::task::Context::from_waker(waker))
        });
        assert!(matches!(
            refused,
            std::task::Poll::Ready(Err(SignerFfiError::InvalidInput { .. }))
        ));
        // The mark goes with the callback: a call after it runs.
        run(async { Ok(()) }).await.unwrap();
    }

    /// A runtime with one blocking thread, so a test fills it without touching the
    /// bindings' own.
    fn one_blocking_thread() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_current_thread()
            .max_blocking_threads(1)
            .enable_time()
            .build()
            .unwrap()
    }

    #[test]
    fn test_runtime_blocking_work_no_thread_takes_up_is_given_up() {
        one_blocking_thread().block_on(async {
            let (release, held) = std::sync::mpsc::channel::<()>();
            let (started, holding) = tokio::sync::oneshot::channel();
            // The one thread is held, as by a callback that waits for the call below.
            let holder = tokio::spawn(blocking_within(Duration::from_secs(60), move || {
                started.send(()).unwrap();
                held.recv().unwrap();
            }));
            holding.await.unwrap();
            let ran = Arc::new(AtomicU8::new(0));
            let mark = ran.clone();
            let late = blocking_within(Duration::from_millis(50), move || {
                mark.store(1, Ordering::SeqCst);
            });
            // Bounded here too, so a wait that never gives up fails the test.
            let given_up = tokio::time::timeout(Duration::from_secs(10), late)
                .await
                .expect("the wait for a thread is bounded");
            assert!(matches!(given_up, Err(SignerFfiError::RuntimeUnavailable)));
            // The thread comes free: work given up is never run late, and new work runs.
            release.send(()).unwrap();
            holder.await.unwrap().unwrap();
            blocking_within(Duration::from_secs(60), || ())
                .await
                .unwrap();
            assert_eq!(ran.load(Ordering::SeqCst), 0);
        });
    }

    #[test]
    fn test_runtime_blocking_work_taken_up_runs_to_its_end() {
        one_blocking_thread().block_on(async {
            // Far longer with the host than the wait for a thread: still its answer.
            let slow = blocking_within(Duration::from_millis(10), || {
                std::thread::sleep(Duration::from_millis(200));
                7
            })
            .await;
            assert_eq!(slow.unwrap(), 7);
        });
    }

    #[tokio::test(flavor = "current_thread")]
    async fn test_runtime_blocking_panic_is_the_unknown_failure() {
        let failed = blocking(|| {
            if std::hint::black_box(true) {
                panic!("a defect");
            }
        })
        .await;
        assert!(
            matches!(failed, Err(SignerFfiError::Unknown { .. })),
            "{failed:?}"
        );
    }

    #[test]
    fn test_runtime_mark_goes_with_a_callback_that_panics() {
        let panicked = std::panic::catch_unwind(|| {
            in_callback(|| {
                if std::hint::black_box(true) {
                    panic!("a defect");
                }
            });
        });
        assert!(panicked.is_err());
        // The thread isn't left marked: a call from it is taken.
        refuse_reentry().unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    async fn test_runtime_call_runs_off_the_workers_and_waits_for_them() {
        // Started from the one worker, as an export's task starts it.
        let (worker, ran) = tokio::spawn(async {
            let worker = std::thread::current().id();
            let ran = run_call(async {
                // Asynchronous waits inside the call are served by the runtime's workers.
                tokio::time::sleep(Duration::from_millis(10)).await;
                let joined = tokio::spawn(async { 7 }).await.unwrap();
                // What is synchronous in the call, as a vault callback is, holds this
                // thread only: the one worker goes on.
                let (told, heard) = std::sync::mpsc::channel();
                drop(tokio::spawn(async move { told.send(8).unwrap() }));
                let meanwhile = heard.recv_timeout(Duration::from_secs(10));
                (std::thread::current().id(), joined, meanwhile)
            });
            (worker, ran.await.unwrap())
        })
        .await
        .unwrap();
        assert_ne!(ran.0, worker);
        assert_eq!((ran.1, ran.2), (7, Ok(8)));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_runtime_calls_past_the_limit_wait_and_are_given_up() {
        let _alone = CALLS_FILLED.lock().await;
        // Every place is taken by a call that is held.
        let (release, held) = tokio::sync::watch::channel(false);
        let (started, mut starts) = tokio::sync::mpsc::unbounded_channel();
        let mut running = Vec::new();
        for _ in 0..SIGNER_CALLS {
            let (mut held, started) = (held.clone(), started.clone());
            running.push(tokio::spawn(run_call(async move {
                started.send(()).unwrap();
                let _ = held.wait_for(|released| *released).await;
            })));
        }
        for _ in 0..SIGNER_CALLS {
            tokio::time::timeout(Duration::from_secs(60), starts.recv())
                .await
                .unwrap();
        }
        // One more waits, and is given up without having started.
        let ran = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let begun = ran.clone();
        let over = run_call_within(Duration::from_millis(200), async move {
            begun.store(true, Ordering::SeqCst);
        });
        assert!(matches!(
            over.await,
            Err(SignerFfiError::RuntimeUnavailable)
        ));
        assert!(!ran.load(Ordering::SeqCst));
        // A place freed, the next call runs.
        release.send(true).unwrap();
        for call in running {
            call.await.unwrap().unwrap();
        }
        run_call(async {}).await.unwrap();
    }

    #[test]
    fn test_runtime_is_built_once() {
        let first = runtime().unwrap() as *const _;
        let second = runtime().unwrap() as *const _;
        assert_eq!(first, second);
    }
}
