//! Durable completion of a deny list gap and its replacement baseline (Dispatch spec 8.3).

use super::*;
use crate::app::admission::{LISTS_AT, LISTS_TOO_LARGE, deny_key};
use crate::app::feed::DENY_GAP;
use crate::store::{Fault as StoreFault, FaultStore};

#[tokio::test]
async fn test_protocol_gap_current_obligation_requires_every_registered_owner() {
    let mut c = Box::pin(GapCase::new()).await;
    let mut owed: crate::app::feed::OwedGap = c.app.reader().get(DENY_GAP).await.unwrap().unwrap();
    owed.to.retain(|name| name == "tasks");
    let mut tx = c.app.tx().unwrap();
    tx.put(DENY_GAP, &owed).unwrap();
    c.app.commit(tx).await.unwrap();
    c.reload().await;
    let result = c.app.receive(None).await;
    if result.is_ok() {
        assert!(!c.app.reader().exists(DENY_GAP).await.unwrap());
        assert!(c.app.reader().exists(LISTS_AT).await.unwrap());
        assert_eq!(c.baseline("tasks").await, (true, vec![c.denied]));
        assert_eq!(c.baseline("chat").await, (true, vec![]));
        assert!(c.app.lists_copy().await.unwrap().deny.contains(&c.denied));
    }
    assert!(
        matches!(result, Err(AppError::Store(StoreError::Corrupt))),
        "a current gap cannot complete after losing an owner: {result:?}"
    );
}

struct GapCase {
    pair: Pair,
    app: App,
    manager: App,
    denied: [u8; 32],
}

impl GapCase {
    async fn new() -> Self {
        let pair = Pair::with(
            Named {
                keep_gap: true,
                ..named("tasks")
            },
            Named {
                keep_gap: true,
                ..named("chat")
            },
        );
        let mut app = pair.join_with(&[Permission::ListsRead]).await;
        let mut manager = manager(&pair).await;
        read(&mut app, 1).await;
        app.allow_list().await.unwrap();
        assert!(app.reader().exists(LISTS_AT).await.unwrap());
        assert!(app.reader().exists(DENY_GAP).await.unwrap());
        let denied = [47; 32];
        manager.deny(&denied).await.unwrap();
        Self {
            pair,
            app,
            manager,
            denied,
        }
    }

    async fn fault(&mut self, fault: StoreFault) -> Arc<FaultStore> {
        let store = Arc::new(FaultStore::new(self.pair.store.clone(), fault));
        self.app = App::load(
            self.pair.w.env_on(store.clone() as Arc<dyn StateStore>),
            self.pair.set(),
            World::config(),
            self.app.app_id(),
        )
        .await
        .unwrap();
        store
    }

    async fn reload(&mut self) {
        self.app = self.pair.load(self.app.app_id()).await.unwrap();
    }

    async fn baseline(&self, name: &str) -> (bool, Vec<[u8; 32]>) {
        serde_json::from_slice(&self.app.protocol_get(name, b"gap").await.unwrap().unwrap())
            .unwrap()
    }

    async fn complete(&mut self, denied: &[[u8; 32]]) {
        read(&mut self.app, 2).await;
        assert!(!self.app.reader().exists(DENY_GAP).await.unwrap());
        assert!(self.app.reader().exists(LISTS_AT).await.unwrap());
        for name in ["tasks", "chat"] {
            let (read, actual) = self.baseline(name).await;
            assert!(read);
            assert_eq!(actual.len(), denied.len());
            for pubky in denied {
                assert!(actual.contains(pubky));
                assert!(self.app.reader().exists(&deny_key(pubky)).await.unwrap());
            }
        }
    }

    async fn assert_boundary(&self) {
        // Until the copy and every protocol agree, a gap is owed or the baseline is unknown.
        if !self.app.reader().exists(DENY_GAP).await.unwrap()
            && self.app.reader().exists(LISTS_AT).await.unwrap()
        {
            assert!(
                self.app
                    .reader()
                    .exists(&deny_key(&self.denied))
                    .await
                    .unwrap()
            );
            for name in ["tasks", "chat"] {
                let (read, denied) = self.baseline(name).await;
                assert!(read && denied.contains(&self.denied));
            }
        }
    }
}

#[tokio::test]
async fn test_protocol_gap_replacement_failure_invalidates_the_previous_copy() {
    for reload in [false, true] {
        let mut c = Box::pin(GapCase::new()).await;
        let store = c.fault(StoreFault::None).await;
        store.fail_put_once(LISTS_AT.as_bytes());
        assert!(matches!(
            c.app.receive(None).await,
            Err(AppError::Store(StoreError::Unavailable))
        ));
        // A public local read reloads automatically after a failed commit.
        crate::app::tests::pending_events(&mut c.app).await.unwrap();
        assert!(!c.app.lists_copy().await.unwrap().deny.contains(&c.denied));
        assert!(!c.app.reader().exists(LISTS_AT).await.unwrap());
        assert!(!c.app.reader().exists(DENY_GAP).await.unwrap());
        for name in ["tasks", "chat"] {
            assert_eq!(c.baseline(name).await, (true, vec![c.denied]));
        }
        if reload {
            c.reload().await;
        }
        let later = [48; 32];
        c.manager.deny(&later).await.unwrap();
        let denied = [c.denied, later];
        c.complete(&denied).await;
    }
}

#[tokio::test]
async fn test_protocol_gap_completion_survives_every_commit_failure() {
    let count = {
        let mut c = Box::pin(GapCase::new()).await;
        let store = c.fault(StoreFault::None).await;
        c.app.receive(None).await.unwrap();
        c.assert_boundary().await;
        store.commits()
    };
    assert!(count >= 2);
    for nth in 1..=count {
        for fault in [
            StoreFault::FailBefore(nth),
            StoreFault::FailAfter(nth),
            StoreFault::StopBefore(nth),
            StoreFault::StopAfter(nth),
        ] {
            let mut c = Box::pin(GapCase::new()).await;
            let store = c.fault(fault).await;
            let _ = c.app.receive(None).await;
            assert!(store.commits() >= nth, "{fault:?} was reached");
            if !store.stopped() {
                crate::app::tests::pending_events(&mut c.app).await.unwrap();
                c.assert_boundary().await;
            }
            c.reload().await;
            c.assert_boundary().await;
            let denied = [c.denied];
            c.complete(&denied).await;
        }
    }
}

#[tokio::test]
async fn test_protocol_gap_partial_callbacks_keep_the_shared_obligation() {
    let mut c = Box::pin(GapCase::new()).await;
    *c.pair.chat.failing_gap.lock().unwrap() = 1;
    assert!(c.app.receive(None).await.unwrap().stopped);
    assert_eq!(c.baseline("tasks").await, (true, vec![c.denied]));
    assert_eq!(c.baseline("chat").await, (true, vec![]));
    assert!(c.app.reader().exists(DENY_GAP).await.unwrap());
    assert!(c.app.reader().exists(LISTS_AT).await.unwrap());
    assert!(!c.app.reader().exists(&deny_key(&c.denied)).await.unwrap());
    let later = [48; 32];
    c.manager.deny(&later).await.unwrap();
    let store = c.fault(StoreFault::None).await;
    store.fail_put_once(LISTS_AT.as_bytes());
    assert!(c.app.receive(None).await.is_err());
    c.reload().await;
    c.assert_boundary().await;
    for name in ["tasks", "chat"] {
        let (read, denied) = c.baseline(name).await;
        assert!(read && denied.contains(&c.denied) && denied.contains(&later));
    }
    // Repeated explicit refreshes still owe the shared gap; a newer answer is handed to
    // every protocol when that gap completes.
    c.app.allow_list().await.unwrap();
    c.app.allow_list().await.unwrap();
    c.manager.undeny(&c.denied).await.unwrap();
    c.complete(&[later]).await;
    assert!(!c.app.reader().exists(&deny_key(&c.denied)).await.unwrap());
}

#[tokio::test]
async fn test_protocol_gap_oversized_copy_stays_unknown_until_refresh() {
    for fail_mark in [false, true] {
        let mut c = Box::pin(GapCase::new()).await;
        let store = c.fault(StoreFault::None).await;
        store.refuse_puts_as_too_large(Some(LISTS_AT.as_bytes()));
        if fail_mark {
            store.fail_put_once(LISTS_TOO_LARGE.as_bytes());
        }
        let result = c.app.receive(None).await;
        assert_eq!(result.is_err(), fail_mark);
        c.reload().await;
        assert!(!c.app.reader().exists(LISTS_AT).await.unwrap());
        assert!(!c.app.reader().exists(DENY_GAP).await.unwrap());
        assert_eq!(
            c.app.reader().exists(LISTS_TOO_LARGE).await.unwrap(),
            !fail_mark
        );
        for name in ["tasks", "chat"] {
            assert_eq!(c.baseline(name).await, (true, vec![c.denied]));
        }
        if !fail_mark {
            let told = c.pair.tasks.gaps.lock().unwrap().len();
            read(&mut c.app, 2).await;
            assert_eq!(c.pair.tasks.gaps.lock().unwrap().len(), told);
            assert!(!c.app.reader().exists(LISTS_AT).await.unwrap());
            // An explicit refresh is permitted before the bounded automatic retry time.
            c.app.allow_list().await.unwrap();
        }
        let denied = [c.denied];
        c.complete(&denied).await;
    }
}

#[tokio::test]
async fn test_protocol_gap_unreadable_copy_retries_after_reload() {
    let mut c = Box::pin(GapCase::new()).await;
    c.pair.w.dispatch.fail_next(Fault::LeaveOut {
        path: "/allow".into(),
        member: "deny".into(),
    });
    c.app.receive(None).await.unwrap();
    c.reload().await;
    assert!(!c.app.reader().exists(LISTS_AT).await.unwrap());
    assert!(!c.app.reader().exists(LISTS_TOO_LARGE).await.unwrap());
    for name in ["tasks", "chat"] {
        assert_eq!(c.baseline(name).await, (false, vec![]));
    }
    let denied = [c.denied];
    c.complete(&denied).await;
}

#[tokio::test]
async fn test_protocol_gap_failed_replacement_restores_a_fresh_baseline() {
    for fresh in [false, true] {
        let mut c = Box::pin(GapCase::new()).await;
        let store = c.fault(StoreFault::None).await;
        store.fail_put_once(LISTS_AT.as_bytes());
        assert!(c.app.receive(None).await.is_err());
        c.reload().await;
        c.assert_boundary().await;
        let backup = c.app.backup_layered().await.unwrap();
        if fresh {
            c.pair.store = Arc::new(MemoryStore::new());
        }
        c.app = Box::pin(App::restore(
            c.pair.env(),
            c.pair.set(),
            World::config(),
            &backup,
        ))
        .await
        .unwrap();
        let later = [48; 32];
        c.manager.deny(&later).await.unwrap();
        c.manager.undeny(&c.denied).await.unwrap();
        c.complete(&[later]).await;
        assert!(!c.app.reader().exists(&deny_key(&c.denied)).await.unwrap());
    }
}

#[tokio::test]
async fn test_protocol_gap_owner_set_is_checked_before_any_callback() {
    for owners in [
        vec![],
        vec!["tasks"],
        vec!["tasks", "tasks"],
        vec!["tasks", "news"],
        vec!["tasks", "chat", "tasks"],
    ] {
        let mut c = Box::pin(GapCase::new()).await;
        let before = [
            c.pair.tasks.gaps.lock().unwrap().len(),
            c.pair.chat.gaps.lock().unwrap().len(),
        ];
        let mut owed: crate::app::feed::OwedGap =
            c.app.reader().get(DENY_GAP).await.unwrap().unwrap();
        owed.to = owners.into_iter().map(str::to_owned).collect();
        let mut tx = c.app.tx().unwrap();
        tx.put(DENY_GAP, &owed).unwrap();
        c.app.commit(tx).await.unwrap();
        for _ in 0..2 {
            c.reload().await;
            assert!(matches!(
                c.app.receive(None).await,
                Err(AppError::Store(StoreError::Corrupt))
            ));
            assert_eq!(
                c.app
                    .reader()
                    .get::<crate::app::feed::OwedGap>(DENY_GAP)
                    .await
                    .unwrap(),
                Some(owed.clone())
            );
            assert_eq!(c.pair.tasks.gaps.lock().unwrap().len(), before[0]);
            assert_eq!(c.pair.chat.gaps.lock().unwrap().len(), before[1]);
            assert_eq!(c.baseline("tasks").await, (true, vec![]));
            assert_eq!(c.baseline("chat").await, (true, vec![]));
        }
    }
    let mut valid = Box::pin(GapCase::new()).await;
    *valid.pair.chat.failing_gap.lock().unwrap() = 1;
    assert!(valid.app.receive(None).await.unwrap().stopped);
    let owed: crate::app::feed::OwedGap = valid.app.reader().get(DENY_GAP).await.unwrap().unwrap();
    assert_eq!(owed.to, valid.pair.set().names());
    valid.reload().await;
    let denied = valid.denied;
    valid.complete(&[denied]).await;
}
