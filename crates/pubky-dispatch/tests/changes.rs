//! Change notifications through PostgreSQL: a committed change wakes the requests waiting
//! on its account, wherever they wait; a change that rolls back wakes nobody.
//!
//! Set `PUBKY_DISPATCH_TEST_DATABASE_URL` to run them; see `store::testing`.

// Test helpers fail the test on any error.
#![allow(clippy::expect_used)]

use std::time::Duration;

use pubky_dispatch::{
    changes::{ChangeHub, ChangeListener},
    store::{NewAccount, Store, testing::test_database},
};
use tokio::sync::{oneshot, watch};

const ID_A: &str = "6frao8w9ss5cn544qd64hynikrbr97ae1s5941c7ma5e1epifhgy";
const ID_B: &str = "7p4fn44qoshcwgfndz5grt7fyyz1eycqyduxdqe8o58of1byzodo";
// An account whose changes mark a point in the listener's order: one connection delivers
// notifications in commit order, so once its change wakes its waiter, every change committed
// before it has been delivered too.
const ID_MARK: &str = "8um71us3fyw6h8wbcxb5ar3rwusy1a6u49956ikzojg3gcwd1dty";

async fn woken(receiver: &mut watch::Receiver<u64>, within: Duration) -> bool {
    tokio::time::timeout(within, receiver.changed())
        .await
        .map(|change| change.expect("change notification channel closed while waiting"))
        .is_ok()
}

/// Commit a change to the marking account and wait for it: what was committed before has been
/// delivered.
async fn delivered(store: &Store, marked: &mut watch::Receiver<u64>) {
    let mut txn = store.begin(ID_MARK).await.expect("begin").expect("account");
    txn.note_change();
    txn.commit().await.expect("commit");
    assert!(woken(marked, Duration::from_secs(5)).await);
}

#[tokio::test]
#[should_panic(expected = "change notification channel closed while waiting")]
async fn test_waiting_for_a_change_rejects_a_closed_notification_channel() {
    let (sender, mut receiver) = watch::channel(0);
    drop(sender);
    woken(&mut receiver, Duration::from_secs(1)).await;
}

#[tokio::test]
async fn test_changes_committed_change_wakes_its_account_only() {
    let Some(db) = test_database().await else {
        return;
    };
    for id in [ID_A, ID_B, ID_MARK] {
        db.store()
            .create_account(&NewAccount {
                activation: pubky_dispatch_core::records::AccountActivation::Ordinary,
                id: id.into(),
                identity_key: [1; 32],
                generation: 1,
                created_at_ms: 0,
                limits: pubky_dispatch_core::records::Limits::default(),
                identity_doc: None,
                revoked_apps: Vec::new(),
                enrollment_hash: [0; 32],
                enrollment_store_id: [1; 16],
                stamped_time_ms: 0,
                stamped_by: [2; 16],
            })
            .await
            .expect("create");
    }
    let hub = ChangeHub::new();
    let listener = ChangeListener::connect(db.store()).await.expect("listen");
    let (stop, stopped) = oneshot::channel::<()>();
    let task = tokio::spawn(listener.run(hub.clone(), async {
        let _ = stopped.await;
    }));
    let mut waiting_a = hub.subscribe(ID_A);
    let mut waiting_b = hub.subscribe(ID_B);
    let mut marked = hub.subscribe(ID_MARK);

    // A change to B wakes B, not A.
    let mut txn = db
        .store()
        .begin(ID_B)
        .await
        .expect("begin")
        .expect("account");
    txn.next_seq().expect("seq");
    txn.commit().await.expect("commit");
    assert!(woken(&mut waiting_b, Duration::from_secs(5)).await);
    delivered(db.store(), &mut marked).await;
    assert!(
        !waiting_a.has_changed().expect("open"),
        "a change to B woke A"
    );

    // A change that rolls back wakes nobody.
    let mut txn = db
        .store()
        .begin(ID_A)
        .await
        .expect("begin")
        .expect("account");
    txn.next_seq().expect("seq");
    txn.note_change();
    drop(txn);
    delivered(db.store(), &mut marked).await;
    assert!(
        !waiting_a.has_changed().expect("open"),
        "a rolled back change woke A"
    );

    // A request that changes the account's other state, without moving its position.
    let mut txn = db
        .store()
        .begin(ID_A)
        .await
        .expect("begin")
        .expect("account");
    txn.note_change();
    txn.commit().await.expect("commit");
    assert!(woken(&mut waiting_a, Duration::from_secs(5)).await);

    // A request that changes nothing, or only stamps a later time, wakes nobody.
    let begin = || async {
        db.store()
            .begin(ID_A)
            .await
            .expect("begin")
            .expect("account")
    };
    begin().await.commit().await.expect("commit");
    let mut txn = begin().await;
    txn.stamp(60_000, pubky_dispatch::store::ServiceRun::start());
    txn.commit().await.expect("commit");
    delivered(db.store(), &mut marked).await;
    assert!(
        !waiting_a.has_changed().expect("open"),
        "an unchanged or stamped account woke A"
    );
    assert_eq!(
        begin().await.head().stamped_time_ms,
        60_000,
        "the stamp itself is kept"
    );

    let _ = stop.send(());
    task.await.expect("listener stops");
    db.drop_database().await.expect("drop");
}

/// The listener holds a connection of its own, outside the request pool: with a pool of one
/// connection, requests still get it.
#[tokio::test]
#[allow(clippy::panic)]
async fn test_changes_listener_leaves_a_one_connection_pool_to_requests() {
    use pubky_dispatch::store::{DatabaseConfig, testing::TestDatabase};
    let config = DatabaseConfig {
        max_connections: 1,
        acquire_timeout_ms: 2_000,
        ..DatabaseConfig::default()
    };
    let db = match TestDatabase::create(&config).await {
        Ok(db) => db,
        Err(pubky_dispatch::store::testing::TestDatabaseError::Skipped) => return,
        Err(error) => panic!("test database: {error}"),
    };
    let hub = ChangeHub::new();
    let listener = ChangeListener::connect(db.store()).await.expect("listen");
    let (stop, stopped) = oneshot::channel::<()>();
    let task = tokio::spawn(listener.run(hub.clone(), async {
        let _ = stopped.await;
    }));
    // A request's query, on the pool's one connection, answers.
    let found = tokio::time::timeout(Duration::from_secs(5), db.store().lookup(ID_A))
        .await
        .expect("not starved")
        .expect("lookup");
    assert!(found.is_none());
    let _ = stop.send(());
    task.await.expect("listener");
    db.drop_database().await.expect("drop");
}
