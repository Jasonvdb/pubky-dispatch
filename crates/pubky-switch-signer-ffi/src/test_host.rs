//! A host store in memory for the crate's tests, with gates and faults a test sets
//! (Switch spec 3.1).

use crate::store::{HostStore, StoreAcquire, StoreCommit, StoreEntry, StoreFailure, StoreWrite};
use pubky_switch_client::store::{MemoryStore, StateStore, StoreError, Write, WriteBatch};
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc as sync_channel;
use std::sync::{Arc, Mutex as StdMutex, MutexGuard as StdMutexGuard};
use tokio::sync::Notify;

/// Holds a host call until the test lets it go.
pub(crate) struct Gate {
    entered: Arc<Notify>,
    go: sync_channel::Receiver<Option<StoreFailure>>,
}

#[derive(Default)]
pub(crate) struct HostState {
    pub(crate) records: MemoryStore,
    pub(crate) owners: BTreeMap<String, Vec<u8>>,
    /// The next release fails so, once.
    pub(crate) fail_release: Option<StoreFailure>,
    /// The next release, owned commit or acquisition waits for the test.
    pub(crate) release_gate: Option<Gate>,
    pub(crate) commit_gate: Option<Gate>,
    pub(crate) acquire_gate: Option<Gate>,
    /// Run inside the next owned commit, before it is applied.
    pub(crate) in_commit: Option<Box<dyn FnOnce() + Send>>,
    /// The calls made, other than for the store's id.
    pub(crate) calls: usize,
    id: u64,
}

/// A host store in memory; clones are handles of one store.
#[derive(Clone)]
pub(crate) struct MemoryHost(Arc<StdMutex<HostState>>);

impl Default for MemoryHost {
    fn default() -> Self {
        // An id no other store of this process ever had: a release one test leaves owed is
        // kept by its store's id, and must never be settled through another test's store.
        static NEXT: AtomicU64 = AtomicU64::new(0);
        Self(Arc::new(StdMutex::new(HostState {
            id: NEXT.fetch_add(1, Ordering::Relaxed),
            ..HostState::default()
        })))
    }
}

impl MemoryHost {
    pub(crate) fn state(&self) -> StdMutexGuard<'_, HostState> {
        self.0.lock().unwrap()
    }

    pub(crate) fn call(&self) -> StdMutexGuard<'_, HostState> {
        let mut state = self.state();
        state.calls += 1;
        state
    }

    pub(crate) fn held(&self) -> bool {
        !self.state().owners.is_empty()
    }

    pub(crate) fn boxed(&self) -> Box<dyn HostStore> {
        Box::new(self.clone())
    }

    /// Hold the next call of `which` until the returned sender answers.
    pub(crate) fn gate(
        &self,
        which: Held,
    ) -> (Arc<Notify>, sync_channel::Sender<Option<StoreFailure>>) {
        let entered = Arc::new(Notify::new());
        let (go, wait) = sync_channel::channel();
        let gate = Some(Gate {
            entered: entered.clone(),
            go: wait,
        });
        let mut state = self.state();
        match which {
            Held::Release => state.release_gate = gate,
            Held::Commit => state.commit_gate = gate,
            Held::Acquire => state.acquire_gate = gate,
        }
        (entered, go)
    }
}

/// The host call a test holds.
#[derive(Clone, Copy)]
pub(crate) enum Held {
    Release,
    // Only the tests with a scripted service get as far as a write they can hold.
    #[cfg_attr(not(feature = "test-fixtures"), allow(dead_code))]
    Commit,
    Acquire,
}

/// Wait at the gate, if one is set: the test's answer is the call's failure, if any.
fn pass(gate: Option<Gate>) -> Result<(), StoreFailure> {
    let Some(gate) = gate else { return Ok(()) };
    gate.entered.notify_one();
    match gate.go.recv() {
        Ok(Some(failure)) => Err(failure),
        _ => Ok(()),
    }
}

fn apply(records: &MemoryStore, writes: Vec<StoreWrite>) -> Result<(), StoreFailure> {
    let mut batch = WriteBatch::new();
    for write in writes.into_iter().map(Write::from) {
        match write {
            Write::Put { ns, key, value } => batch.put(&ns, key, value),
            Write::Delete { ns, key } => batch.delete(&ns, key),
            Write::DeletePrefix { ns, prefix } => batch.delete_prefix(&ns, prefix),
        }
        .map_err(StoreError::from)?;
    }
    Ok(records.commit(batch)?)
}

impl HostStore for MemoryHost {
    fn store_id(&self) -> Result<String, StoreFailure> {
        Ok(format!("memory-host-{}", self.state().id))
    }
    fn get(&self, ns: String, key: Vec<u8>) -> Result<Option<Vec<u8>>, StoreFailure> {
        Ok(self.call().records.get(&ns, &key)?)
    }
    fn scan(
        &self,
        ns: String,
        prefix: Vec<u8>,
        after: Option<Vec<u8>>,
        limit: u32,
    ) -> Result<Vec<StoreEntry>, StoreFailure> {
        let rows = self
            .call()
            .records
            .scan(&ns, &prefix, after.as_deref(), limit)?;
        Ok(rows.into_iter().map(Into::into).collect())
    }
    fn commit(&self, writes: Vec<StoreWrite>) -> Result<(), StoreFailure> {
        let state = self.call();
        apply(&state.records, writes)
    }
    fn acquire(&self, ns: String, owner: Vec<u8>) -> Result<StoreAcquire, StoreFailure> {
        let gate = self.call().acquire_gate.take();
        pass(gate)?;
        let mut state = self.state();
        if state.owners.contains_key(&ns) {
            return Ok(StoreAcquire::Busy);
        }
        state.owners.insert(ns, owner);
        Ok(StoreAcquire::Acquired)
    }
    fn release(&self, ns: String, owner: Vec<u8>) -> Result<(), StoreFailure> {
        let gate = self.call().release_gate.take();
        pass(gate)?;
        let mut state = self.state();
        if let Some(failure) = state.fail_release.take() {
            return Err(failure);
        }
        if state.owners.get(&ns) == Some(&owner) {
            state.owners.remove(&ns);
        }
        Ok(())
    }
    fn commit_if(
        &self,
        ns: String,
        owner: Vec<u8>,
        writes: Vec<StoreWrite>,
    ) -> Result<StoreCommit, StoreFailure> {
        let (gate, hook) = {
            let mut state = self.call();
            (state.commit_gate.take(), state.in_commit.take())
        };
        pass(gate)?;
        if let Some(hook) = hook {
            hook();
        }
        let state = self.state();
        if state.owners.get(&ns) != Some(&owner) {
            return Ok(StoreCommit::NotOwner);
        }
        apply(&state.records, writes)?;
        Ok(StoreCommit::Applied)
    }
}
