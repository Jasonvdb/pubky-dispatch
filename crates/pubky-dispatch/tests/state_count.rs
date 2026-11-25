//! The account's count of changed commits (Dispatch wire 7.3, "The state"): the schema's row
//! trigger on every account table, the one list of what the count leaves out, and how a
//! commit moves the count. Against the live PostgreSQL schema.
//!
//! Set `PUBKY_DISPATCH_TEST_DATABASE_URL` to run them; see `store::testing`.

#![allow(clippy::expect_used, clippy::panic)]

use pubky_dispatch::store::{
    NewAccount,
    testing::{TestDatabase, test_database},
};
use sqlx::{Connection, PgConnection};

const ID: &str = "6frao8w9ss5cn544qd64hynikrbr97ae1s5941c7ma5e1epifhgy";
const T0: u64 = 1_767_225_600_000;

/// A row of `state_uncounted()`: its kind, table, column and reason.
type Listing = (String, Option<String>, Option<String>, Option<String>);

async fn with_account() -> Option<TestDatabase> {
    let db = test_database().await?;
    let account = NewAccount {
        activation: pubky_dispatch_core::records::AccountActivation::Ordinary,
        id: ID.into(),
        identity_key: pubky_dispatch_core::keys::IdentityKey::from_secret([7; 32]).public(),
        generation: 1,
        created_at_ms: T0,
        limits: pubky_dispatch_core::records::Limits::default(),
        identity_doc: None,
        revoked_apps: Vec::new(),
        enrollment_hash: [0; 32],
        enrollment_store_id: [1; 16],
        stamped_time_ms: T0,
        stamped_by: [2; 16],
    };
    assert!(db.store().create_account(&account).await.expect("create"));
    Some(db)
}

/// Run `sql`, with `$1` bound to the account, in a request's transaction, and commit it:
/// whether the commit moved the count.
async fn commit_with(db: &TestDatabase, sql: &str) -> bool {
    let mut txn = db.store().begin(ID).await.expect("begin").expect("account");
    sqlx::query(sql)
        .bind(ID)
        .execute(txn.conn())
        .await
        .expect("write");
    let committed = txn.commit().await.expect("commit");
    committed.counted()
}

/// What is wrong with the schema's count trigger, read from the live schema: a table with
/// an account column, or `accounts`, without the trigger; one whose trigger doesn't fire
/// after every insert, update and delete of each row, or fires only `WHEN` a condition holds;
/// a trigger anywhere else, or of another name; a listed column or table that doesn't exist,
/// or a listing without a reason or of an unknown kind.
async fn trigger_problems(conn: &mut PgConnection) -> Vec<String> {
    let mut problems = Vec::new();
    let account_tables: Vec<String> = sqlx::query_scalar(
        "SELECT table_name::text FROM information_schema.columns \
         WHERE table_schema = current_schema() AND column_name = 'account_id' \
         UNION SELECT 'accounts' ORDER BY 1",
    )
    .fetch_all(&mut *conn)
    .await
    .expect("tables");
    let triggers: Vec<(String, String, String)> = sqlx::query_as(
        "SELECT c.relname::text, t.tgname::text, p.proname::text FROM pg_trigger t \
         JOIN pg_class c ON c.oid = t.tgrelid JOIN pg_proc p ON p.oid = t.tgfoid \
         WHERE NOT t.tgisinternal ORDER BY 1",
    )
    .fetch_all(&mut *conn)
    .await
    .expect("triggers");
    for table in &account_tables {
        let has = triggers.iter().any(|(on, name, function)| {
            on == table && name == "count_state_change" && function == "count_state_change"
        });
        if !has {
            problems.push(format!("{table} has no count trigger"));
        }
    }
    for (on, name, function) in &triggers {
        if !account_tables.contains(on) || name != "count_state_change" {
            problems.push(format!("an extra trigger {name} ({function}) on {on}"));
        }
    }
    let wrong_keys: Vec<String> = sqlx::query_scalar(
        "SELECT c.relname::text FROM pg_trigger t JOIN pg_class c ON c.oid = t.tgrelid \
         WHERE t.tgname = 'count_state_change' AND t.tgargs IS DISTINCT FROM \
         (SELECT string_agg(convert_to(a.attname::text, 'UTF8') || decode('00', 'hex'), \
         ''::bytea ORDER BY a.attnum) FROM pg_index i JOIN pg_attribute a \
         ON a.attrelid = i.indrelid AND a.attnum = ANY(i.indkey) \
         WHERE i.indrelid = c.oid AND i.indisprimary)",
    )
    .fetch_all(&mut *conn)
    .await
    .expect("count trigger keys");
    for table in wrong_keys {
        problems.push(format!(
            "{table}'s count trigger does not use its primary key"
        ));
    }
    // How each count trigger fires: its events, one row each, its timing and orientation,
    // and any `WHEN` condition.
    let firing: Vec<(String, String, String, String, Option<String>)> = sqlx::query_as(
        "SELECT event_object_table::text, event_manipulation::text, action_timing::text, \
         action_orientation::text, action_condition::text FROM information_schema.triggers \
         WHERE trigger_schema = current_schema() AND trigger_name = 'count_state_change' \
         ORDER BY 1, 2",
    )
    .fetch_all(&mut *conn)
    .await
    .expect("trigger events");
    for table in &account_tables {
        let rows: Vec<_> = firing.iter().filter(|row| &row.0 == table).collect();
        if rows.is_empty() {
            continue;
        }
        let events: Vec<&str> = rows.iter().map(|row| row.1.as_str()).collect();
        if events != ["DELETE", "INSERT", "UPDATE"] {
            problems.push(format!("{table}'s count trigger fires on {events:?}"));
        }
        for (_, event, timing, orientation, condition) in rows {
            if timing != "AFTER" || orientation != "ROW" {
                problems.push(format!(
                    "{table}'s count trigger fires {timing} each {orientation}"
                ));
            }
            if let Some(condition) = condition {
                problems.push(format!(
                    "{table}'s count trigger on {event} has WHEN {condition}"
                ));
            }
        }
    }
    let listed: Vec<Listing> =
        sqlx::query_as("SELECT kind, tab, col, reason FROM state_uncounted()")
            .fetch_all(&mut *conn)
            .await
            .expect("list");
    for (kind, tab, col, reason) in listed {
        if reason
            .as_deref()
            .is_none_or(|reason| reason.trim().is_empty())
        {
            problems.push(format!("{kind} {tab:?} {col:?} has no reason"));
        }
        match (kind.as_str(), tab, col) {
            ("column", Some(tab), Some(col)) => {
                if !account_tables.contains(&tab) {
                    problems.push(format!("{tab} isn't an account table"));
                } else if col != "*" {
                    let exists: bool = sqlx::query_scalar(
                        "SELECT EXISTS (SELECT 1 FROM information_schema.columns \
                         WHERE table_schema = current_schema() AND table_name = $1 \
                         AND column_name = $2)",
                    )
                    .bind(&tab)
                    .bind(&col)
                    .fetch_one(&mut *conn)
                    .await
                    .expect("column");
                    if !exists {
                        problems.push(format!("{tab}.{col} doesn't exist"));
                    }
                }
            }
            ("background", Some(tab), None) => {
                if !account_tables.contains(&tab) {
                    problems.push(format!("{tab} isn't an account table"));
                }
            }
            (kind, tab, col) => problems.push(format!("a listing {kind} {tab:?} {col:?}")),
        }
    }
    problems
}

#[tokio::test]
async fn test_state_count_every_account_table_has_the_trigger() {
    let Some(db) = test_database().await else {
        return;
    };
    let mut conn = PgConnection::connect_with(db.options())
        .await
        .expect("conn");
    assert_eq!(trigger_problems(&mut conn).await, Vec::<String>::new());
    // An account table added without the trigger fails the check, as does a listing of a
    // column that doesn't exist.
    sqlx::query("CREATE TABLE added_state (account_id TEXT PRIMARY KEY, value BIGINT)")
        .execute(&mut conn)
        .await
        .expect("table");
    assert_eq!(
        trigger_problems(&mut conn).await,
        vec!["added_state has no count trigger".to_string()]
    );
    sqlx::query(
        "CREATE TRIGGER count_state_change AFTER INSERT OR UPDATE OR DELETE ON added_state \
         FOR EACH ROW EXECUTE FUNCTION count_state_change('account_id')",
    )
    .execute(&mut conn)
    .await
    .expect("trigger");
    assert_eq!(trigger_problems(&mut conn).await, Vec::<String>::new());
    // A trigger without its update event, or one that fires only when a condition holds,
    // fails it too.
    for (trigger, problem) in [
        (
            "AFTER INSERT OR DELETE ON added_state FOR EACH ROW",
            "added_state's count trigger fires on [\"DELETE\", \"INSERT\"]",
        ),
        (
            "AFTER INSERT OR UPDATE OR DELETE ON added_state FOR EACH ROW \
             WHEN (pg_trigger_depth() < 1)",
            "added_state's count trigger on DELETE has WHEN (pg_trigger_depth() < 1)",
        ),
    ] {
        sqlx::query("DROP TRIGGER count_state_change ON added_state")
            .execute(&mut conn)
            .await
            .expect("drop trigger");
        sqlx::query(&format!(
            "CREATE TRIGGER count_state_change {trigger} EXECUTE FUNCTION count_state_change('account_id')"
        ))
        .execute(&mut conn)
        .await
        .expect("changed trigger");
        let problems = trigger_problems(&mut conn).await;
        assert!(problems.contains(&problem.to_string()), "{problems:?}");
    }
    sqlx::query("DROP TRIGGER count_state_change ON added_state")
        .execute(&mut conn)
        .await
        .expect("drop trigger");
    sqlx::query(
        "CREATE TRIGGER count_state_change AFTER INSERT OR UPDATE OR DELETE ON added_state \
         FOR EACH ROW EXECUTE FUNCTION count_state_change('account_id')",
    )
    .execute(&mut conn)
    .await
    .expect("trigger again");
    assert_eq!(trigger_problems(&mut conn).await, Vec::<String>::new());
    sqlx::query(
        "CREATE TRIGGER other AFTER INSERT ON erasure_outcomes \
         FOR EACH ROW EXECUTE FUNCTION count_state_change()",
    )
    .execute(&mut conn)
    .await
    .expect("other trigger");
    assert_eq!(
        trigger_problems(&mut conn).await,
        vec!["an extra trigger other (count_state_change) on erasure_outcomes".to_string()]
    );
    conn.close().await.expect("close");
    db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_state_count_moves_once_for_a_changed_commit_and_not_otherwise() {
    let Some(db) = with_account().await else {
        return;
    };
    let insert_app = "INSERT INTO apps (account_id, app_id) VALUES ($1, '\\x0101010101010101\
                      0101010101010101')";
    // A row that changes counts, once however many rows change.
    assert!(commit_with(&db, insert_app).await);
    assert!(commit_with(&db, "UPDATE apps SET lagging = true WHERE account_id = $1").await);
    let before = db
        .store()
        .lookup(ID)
        .await
        .expect("lookup")
        .expect("account");
    assert!(
        commit_with(
            &db,
            "UPDATE apps SET lagging = false, full_requested_ms = 5 WHERE account_id = $1",
        )
        .await
    );
    let after = db
        .store()
        .lookup(ID)
        .await
        .expect("lookup")
        .expect("account");
    assert_eq!(after.state_version, before.state_version + 1);
    // An update that changes nothing, as a no-op upsert, counts nothing; nor does a change
    // of a column the list leaves out, nor a commit that only stamps the time.
    let no_op = "UPDATE apps SET lagging = lagging, full_requested_ms = full_requested_ms \
                 WHERE account_id = $1";
    assert!(!commit_with(&db, no_op).await);
    assert!(
        !commit_with(
            &db,
            "UPDATE apps SET last_seen_ms = 9 WHERE account_id = $1"
        )
        .await
    );
    let mut txn = db.store().begin(ID).await.expect("begin").expect("account");
    txn.stamp(T0 + 1_000, pubky_dispatch::store::ServiceRun::start());
    assert!(!txn.commit().await.expect("commit").counted());
    assert_eq!(
        db.store()
            .lookup(ID)
            .await
            .expect("lookup")
            .expect("account")
            .state_version,
        after.state_version
    );
    db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_state_count_compares_the_rows_retained_at_commit() {
    let Some(db) = with_account().await else {
        return;
    };
    let mut txn = db.store().begin(ID).await.expect("begin").expect("account");
    for sql in [
        "UPDATE accounts SET admission_staged = true WHERE id = $1",
        "INSERT INTO connect_requests (account_id, pubky, at_ms) VALUES ($1, decode(repeat('09', 32), 'hex'), 1)",
        "UPDATE connect_requests SET pubky = decode(repeat('0a', 32), 'hex') WHERE account_id = $1",
        "DELETE FROM connect_requests WHERE account_id = $1",
        "UPDATE accounts SET admission_staged = false WHERE id = $1",
    ] {
        sqlx::query(sql)
            .bind(ID)
            .execute(txn.conn())
            .await
            .expect("write");
    }
    let committed = txn.commit().await.expect("commit");
    assert!(!committed.counted());
    assert_eq!(committed.head().state_version, 0);
    assert!(
        commit_with(
            &db,
            "UPDATE accounts SET admission_staged = true WHERE id = $1"
        )
        .await
    );
    let mut txn = db.store().begin(ID).await.expect("begin").expect("account");
    sqlx::query("UPDATE accounts SET admission_staged = false WHERE id = $1")
        .bind(ID)
        .execute(txn.conn())
        .await
        .expect("change");
    let savepoint = txn.savepoint().await.expect("savepoint");
    sqlx::query("UPDATE accounts SET admission_staged = true WHERE id = $1")
        .bind(ID)
        .execute(txn.conn())
        .await
        .expect("undo");
    txn.rollback_to(savepoint).await.expect("rollback");
    assert_eq!(txn.commit().await.expect("commit").head().state_version, 2);
    db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_state_count_refused_write_rolled_back_counts_nothing() {
    let Some(db) = with_account().await else {
        return;
    };
    // The endpoint's write, undone at its refusal: the commit keeps only the stamp, and
    // counts nothing.
    let mut txn = db.store().begin(ID).await.expect("begin").expect("account");
    txn.stamp(T0 + 1_000, pubky_dispatch::store::ServiceRun::start());
    let savepoint = txn.savepoint().await.expect("savepoint");
    sqlx::query("INSERT INTO connect_requests (account_id, pubky, at_ms) VALUES ($1, $2, 1)")
        .bind(ID)
        .bind([3u8; 32].as_slice())
        .execute(txn.conn())
        .await
        .expect("write");
    txn.rollback_to(savepoint).await.expect("rollback");
    assert!(!txn.commit().await.expect("commit").counted());
    // The same write, kept, counts.
    assert!(
        commit_with(
            &db,
            "INSERT INTO connect_requests (account_id, pubky, at_ms) \
             VALUES ($1, '\\x0303030303030303030303030303030303030303030303030303030303030303', 1)",
        )
        .await
    );
    db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_state_count_sweep_minute_and_deleted_rows() {
    let Some(db) = with_account().await else {
        return;
    };
    assert!(commit_with(&db, "UPDATE accounts SET swept_at_ms = 5 WHERE id = $1").await);
    assert!(!commit_with(&db, "UPDATE accounts SET swept_at_ms = 5 WHERE id = $1").await);
    assert!(
        commit_with(
            &db,
            "INSERT INTO connect_requests (account_id, pubky, at_ms) \
             VALUES ($1, '\\x0303030303030303030303030303030303030303030303030303030303030303', 1)",
        )
        .await
    );
    let mut txn = db.store().begin(ID).await.expect("begin").expect("account");
    for sql in [
        "UPDATE accounts SET swept_at_ms = 6 WHERE id = $1",
        "DELETE FROM connect_requests WHERE account_id = $1",
    ] {
        sqlx::query(sql)
            .bind(ID)
            .execute(txn.conn())
            .await
            .expect("sweep");
    }
    assert!(txn.commit().await.expect("commit").counted());
    db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_state_count_enrollment_with_only_the_creating_receipt() {
    let Some(db) = with_account().await else {
        return;
    };
    let mut txn = db.store().begin(ID).await.expect("begin").expect("account");
    txn.keep_enrollment_answer(&[4; 32], T0, 1, [1; 16])
        .await
        .expect("keep");
    assert!(
        txn.enrollment_answer(&[4; 32])
            .await
            .expect("lookup")
            .is_none()
    );
    assert!(
        txn.enrollment_answer(&[0; 32])
            .await
            .expect("creating")
            .is_some()
    );
    assert!(!txn.commit().await.expect("commit").counted());
    db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_state_count_each_move_writes_a_fresh_tag() {
    let Some(db) = with_account().await else {
        return;
    };
    let tag = |db: &TestDatabase| {
        let store = db.store().clone();
        async move {
            let found = store.lookup(ID).await.expect("lookup").expect("account");
            (found.state_version, found.state_tag)
        }
    };
    assert_eq!(tag(&db).await, (0, [0; 16]));
    assert!(
        commit_with(
            &db,
            "UPDATE accounts SET admission_staged = true WHERE id = $1"
        )
        .await
    );
    let (one, first) = tag(&db).await;
    assert_eq!(one, 1);
    assert_ne!(first, [0; 16]);
    // A commit that counts nothing keeps the tag; the next move writes another.
    assert!(
        !commit_with(
            &db,
            "UPDATE accounts SET admission_staged = true WHERE id = $1"
        )
        .await
    );
    assert_eq!(tag(&db).await, (1, first));
    assert!(
        commit_with(
            &db,
            "UPDATE accounts SET admission_staged = false WHERE id = $1"
        )
        .await
    );
    let (two, second) = tag(&db).await;
    assert_eq!(two, 2);
    assert_ne!(second, first);
    db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_state_count_write_outside_the_lock_raises() {
    let Some(db) = with_account().await else {
        return;
    };
    // A connection as the service's store opens one, writing outside an identity's lock.
    let mut conn = PgConnection::connect_with(&db.store_options())
        .await
        .expect("conn");
    for sql in [
        "UPDATE accounts SET swept_at_ms = 5 WHERE id = $1",
        "INSERT INTO connect_requests (account_id, pubky, at_ms) \
         VALUES ($1, '\\x0303030303030303030303030303030303030303030303030303030303030303', 1)",
        "INSERT INTO sender_flags (account_id, pubky, hits, last_hit_ms) \
         VALUES ($1, '\\x0303030303030303030303030303030303030303030303030303030303030303', 1, 1)",
    ] {
        let raised = sqlx::query(sql).bind(ID).execute(&mut conn).await;
        let message = raised.expect_err(sql).to_string();
        assert!(message.contains("outside an identity's lock"), "{message}");
    }
    // A background-written table takes the background work's writes.
    sqlx::query("INSERT INTO erased_keys (key_id, account_id, erased_at_ms) VALUES ('k', $1, 1)")
        .bind(ID)
        .execute(&mut conn)
        .await
        .expect("background write");
    sqlx::query("DELETE FROM erased_keys WHERE key_id = 'k'")
        .execute(&mut conn)
        .await
        .expect("background delete");
    conn.close().await.expect("close");
    db.drop_database().await.expect("drop");
}
