//! The bindings' own runtime. Every asynchronous call runs on its threads, never on the
//! thread a host calls from: a host thread only waits for the answer, and no call blocks a
//! foreign thread for long.

use crate::SignerFfiError;
use std::cell::Cell;
use std::future::Future;
use std::sync::{Mutex, OnceLock};

/// The stack of every runtime thread, room for the deepest signer flow in a debug build.
const THREAD_STACK_BYTES: usize = 4 * 1024 * 1024;

const WORKER_THREADS: usize = 2;

/// The most threads for the host's synchronous callbacks, such as the vault's: a phone's
/// budget, not the runtime's default of hundreds.
const BLOCKING_THREADS: usize = 4;

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
/// only stops this wait: `work` runs to its end, so a signer step is never cut in half.
pub(crate) async fn run<F, T>(work: F) -> Result<T, SignerFfiError>
where
    F: Future<Output = Result<T, SignerFfiError>> + Send + 'static,
    T: Send + 'static,
{
    refuse_reentry()?;
    runtime()?.spawn(work).await.map_err(|failed| {
        if failed.is_panic() {
            // A defect, not the runtime's state: the call's failure, with no inner text.
            SignerFfiError::Unknown {
                reason: "the call stopped unexpectedly".to_owned(),
            }
        } else {
            SignerFfiError::RuntimeUnavailable
        }
    })?
}

thread_local! {
    static IN_CALLBACK: Cell<u32> = const { Cell::new(0) };
}

/// Run `call`, a synchronous host callback, marking this thread for its duration: a call
/// into the bindings that the host makes and waits for from inside it is refused
/// ([`refuse_reentry`]), where it would otherwise hold one of the few blocking threads while
/// waiting for another.
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

/// Refuse a call made from inside a synchronous host callback on this thread.
fn refuse_reentry() -> Result<(), SignerFfiError> {
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

    #[test]
    fn test_runtime_is_built_once() {
        let first = runtime().unwrap() as *const _;
        let second = runtime().unwrap() as *const _;
        assert_eq!(first, second);
    }
}
