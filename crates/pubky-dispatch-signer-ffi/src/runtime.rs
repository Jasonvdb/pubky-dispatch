//! The bindings' own runtime. Every asynchronous call runs on its threads, never on the
//! thread a host calls from: a host thread only waits for the answer, and no call blocks a
//! foreign thread for long.

use crate::SignerFfiError;
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
        .thread_name("pubky-dispatch-signer")
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
        assert_eq!(name.as_deref(), Some("pubky-dispatch-signer"));
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

    #[test]
    fn test_runtime_is_built_once() {
        let first = runtime().unwrap() as *const _;
        let second = runtime().unwrap() as *const _;
        assert_eq!(first, second);
    }
}
