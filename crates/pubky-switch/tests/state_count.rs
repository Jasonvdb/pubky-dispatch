//! The account's count of changed commits (Switch wire 7.3, "The state"): the schema's row
//! trigger on every account table, the one list of what the count leaves out, and how a
//! commit moves the count. Against the live PostgreSQL schema.
//!
//! Set `PUBKY_SWITCH_TEST_DATABASE_URL` to run them; see `store::testing`.

#![allow(clippy::expect_used, clippy::panic)]

use pubky_switch::store::{
    NewAccount, StoreError,
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
        activation: pubky_switch_core::records::AccountActivation::Ordinary,
        id: ID.into(),
        identity_key: pubky_switch_core::keys::IdentityKey::from_secret([7; 32]).public(),
        generation: 1,
        created_at_ms: T0,
        limits: pubky_switch_core::records::Limits::default(),
        identity_doc: None,
        revoked_apps: Vec::new(),
        enrollment_hash: [0; 32],
        enrollment_store_id: [1; 16],
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
/// an account column, or `accounts`, without the trigger; a trigger anywhere else, or of
/// another name; a listed column or table that doesn't exist, or a listing without a
/// reason or of an unknown kind.
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
            ("scope", None, Some(_)) => {}
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
    sqlx::query("CREATE TABLE added_state (account_id TEXT NOT NULL, value BIGINT)")
        .execute(&mut conn)
        .await
        .expect("table");
    assert_eq!(
        trigger_problems(&mut conn).await,
        vec!["added_state has no count trigger".to_string()]
    );
    sqlx::query(
        "CREATE TRIGGER count_state_change AFTER INSERT OR UPDATE OR DELETE ON added_state \
         FOR EACH ROW EXECUTE FUNCTION count_state_change()",
    )
    .execute(&mut conn)
    .await
    .expect("trigger");
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
    txn.stamp(T0 + 1_000);
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
async fn test_state_count_refused_write_rolled_back_counts_nothing() {
    let Some(db) = with_account().await else {
        return;
    };
    // The endpoint's write, undone at its refusal: the commit keeps only the stamp, and
    // counts nothing.
    let mut txn = db.store().begin(ID).await.expect("begin").expect("account");
    txn.stamp(T0 + 1_000);
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
async fn test_state_count_uncounted_writes_need_a_listed_reason() {
    let Some(db) = with_account().await else {
        return;
    };
    let mut txn = db.store().begin(ID).await.expect("begin").expect("account");
    txn.uncounted("step 4", async |txn| {
        sqlx::query("UPDATE accounts SET swept_at_ms = 5 WHERE id = $1")
            .bind(ID)
            .execute(txn.conn())
            .await
            .map_err(StoreError::Database)?;
        Ok(())
    })
    .await
    .expect("swept");
    assert!(!txn.commit().await.expect("commit").counted());
    // A reason the list doesn't name raises.
    let mut txn = db.store().begin(ID).await.expect("begin").expect("account");
    let unlisted = txn
        .uncounted("a reason nobody listed", async |txn| {
            sqlx::query("UPDATE accounts SET swept_at_ms = 6 WHERE id = $1")
                .bind(ID)
                .execute(txn.conn())
                .await
                .map_err(StoreError::Database)?;
            Ok(())
        })
        .await;
    assert!(unlisted.is_err(), "{unlisted:?}");
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
