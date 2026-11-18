//! Every account's chain head, read without the account's lock, for an operator's check of
//! the heads against their marks after a restore (Switch spec 6.5).
//!
//! These reads run on one plain connection whose session is read only, so they need no
//! durability check, no migration and no instance lock, and run beside a running service or
//! against a hot standby. They change nothing.

use std::str::FromStr;

use sqlx::{Connection, Executor, PgConnection, Row, postgres::PgConnectOptions};

use super::{StoreError, from_db, to_db};

/// An account's head as the database holds it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoredHead {
    /// The current account's persisted activation requirement.
    pub activation: pubky_switch_core::records::AccountActivation,
    /// The identity's Pubky ID.
    pub id: String,
    /// The identity's Ed25519 public key.
    pub identity_key: [u8; 32],
    /// The generation the account serves.
    pub generation: u64,
    /// The newest chain item's `seq` and the chain hash there; `None` before the first.
    pub chain: Option<(u64, [u8; 32])>,
    /// The account's count of changed commits (Switch wire 7.3, "The state").
    pub state_version: u64,
    /// The tag written with the count's last move (Switch wire 7.3, "The state").
    pub state_tag: [u8; 16],
    /// When the account was created, in service time.
    pub created_at_ms: u64,
    /// The newest `identity.json` the account holds, in the carrying form the store keeps,
    /// not decoded: one that doesn't decode is the caller's to judge.
    pub identity_doc: Option<Vec<u8>>,
}

impl StoredHead {
    /// Its count of changed commits with their tag (Switch wire 7.3, "The state").
    pub fn count(&self) -> crate::account::Count {
        crate::account::Count {
            version: self.state_version,
            tag: self.state_tag,
        }
    }
}

/// Open one connection to `url` with a read-only session: every transaction on it is read
/// only, so it works against a hot standby and writes nothing.
pub async fn open_read_only(url: &str) -> Result<PgConnection, StoreError> {
    let options = PgConnectOptions::from_str(url)?;
    open_read_only_with(&options).await
}

/// Open one connection to `options` with a read-only session ([`open_read_only`]).
pub async fn open_read_only_with(options: &PgConnectOptions) -> Result<PgConnection, StoreError> {
    let mut conn = PgConnection::connect_with(options).await?;
    if let Err(error) = conn
        .execute("SET SESSION CHARACTERISTICS AS TRANSACTION READ ONLY")
        .await
    {
        let _ = conn.close().await;
        return Err(StoreError::from_db(error));
    }
    Ok(conn)
}

/// Up to `limit` account IDs after `after`, in order: one page of every account.
pub async fn ids_after(
    conn: &mut PgConnection,
    after: Option<&str>,
    limit: u32,
) -> Result<Vec<String>, StoreError> {
    let rows = sqlx::query(
        "SELECT id FROM accounts WHERE $1::TEXT IS NULL OR id > $1 ORDER BY id LIMIT $2",
    )
    .bind(after)
    .bind(to_db(u64::from(limit), "limit")?)
    .fetch_all(conn)
    .await
    .map_err(StoreError::from_db)?;
    rows.iter().map(|row| Ok(row.try_get("id")?)).collect()
}

/// The chain hash of the stub account `id` holds at `generation` and `seq`, if it holds one
/// (Switch wire 7.3, Table 1: a state past the mark with another hash there is a fork).
pub async fn stub_hash_at(
    conn: &mut PgConnection,
    id: &str,
    generation: u64,
    seq: u64,
) -> Result<Option<[u8; 32]>, StoreError> {
    let hash: Option<Vec<u8>> = sqlx::query_scalar(
        "SELECT chain_hash FROM chain_items WHERE account_id = $1 AND generation = $2 \
         AND seq = $3",
    )
    .bind(id)
    .bind(to_db(generation, "generation")?)
    .bind(to_db(seq, "seq")?)
    .fetch_optional(conn)
    .await
    .map_err(StoreError::from_db)?;
    hash.map(|hash| {
        <[u8; 32]>::try_from(hash.as_slice()).map_err(|_| StoreError::Corrupt("chain_hash"))
    })
    .transpose()
}

/// What the selected SQL lifetime retains at the mark's position.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct MarkEvidence {
    pub(crate) stub: Option<[u8; 32]>,
    pub(crate) tag: Option<[u8; 16]>,
}

pub(crate) async fn evidence_at<'a>(
    reader: impl sqlx::PgExecutor<'a>,
    id: &str,
    stub: Option<(u64, u64)>,
    mark: &crate::marks::AccountMark,
) -> Result<MarkEvidence, StoreError> {
    if stub.is_none() && mark.state_version == 0 {
        return Ok(MarkEvidence::default());
    }
    let mut query = sqlx::QueryBuilder::new("SELECT ");
    if let Some((generation, seq)) = stub {
        query
            .push("(SELECT chain_hash FROM chain_items WHERE account_id = a.id AND generation = ")
            .push_bind(to_db(generation, "generation")?)
            .push(" AND seq = ")
            .push_bind(to_db(seq, "seq")?)
            .push(")");
    } else {
        query.push("NULL::bytea");
    }
    query.push(" AS stub, (SELECT state_tag FROM state_history WHERE account_id = a.id AND state_version = ")
        .push_bind(to_db(mark.state_version, "state_version")?)
        .push(") AS tag FROM accounts a WHERE a.id = ").push_bind(id)
        .push(" AND a.created_at_ms = ").push_bind(to_db(mark.created_at_ms, "created_at_ms")?);
    let row = query
        .build()
        .fetch_optional(reader)
        .await
        .map_err(StoreError::from_db)?;
    let Some(row) = row else {
        return Ok(MarkEvidence::default());
    };
    let stub: Option<Vec<u8>> = row.try_get("stub")?;
    let tag: Option<Vec<u8>> = row.try_get("tag")?;
    Ok(MarkEvidence {
        stub: stub
            .map(|hash| {
                hash.try_into()
                    .map_err(|_| StoreError::Corrupt("chain_hash"))
            })
            .transpose()?,
        tag: tag.map(super::state_tag).transpose()?,
    })
}

/// The heads of the accounts `ids` names that are there now, in the order of their IDs.
pub async fn heads(conn: &mut PgConnection, ids: &[String]) -> Result<Vec<StoredHead>, StoreError> {
    let rows = sqlx::query(
        "SELECT id, identity_key, generation, chain_seq, chain_hash, state_version, state_tag, \
         created_at_ms, activation_requirement, identity_doc FROM accounts WHERE id = ANY($1) ORDER BY id",
    )
    .bind(ids)
    .fetch_all(conn)
    .await
    .map_err(StoreError::from_db)?;
    rows.iter()
        .map(|row| {
            let identity_key: Vec<u8> = row.try_get("identity_key")?;
            let chain_seq: Option<i64> = row.try_get("chain_seq")?;
            let chain_hash: Option<Vec<u8>> = row.try_get("chain_hash")?;
            let chain = match (chain_seq, chain_hash) {
                (Some(seq), Some(hash)) => Some((
                    from_db(seq, "chain_seq")?,
                    <[u8; 32]>::try_from(hash.as_slice())
                        .map_err(|_| StoreError::Corrupt("chain_hash"))?,
                )),
                (None, None) => None,
                _ => return Err(StoreError::Corrupt("chain_seq and chain_hash")),
            };
            Ok(StoredHead {
                id: row.try_get("id")?,
                identity_key: <[u8; 32]>::try_from(identity_key.as_slice())
                    .map_err(|_| StoreError::Corrupt("identity_key"))?,
                generation: from_db(row.try_get("generation")?, "generation")?,
                chain,
                state_version: from_db(row.try_get("state_version")?, "state_version")?,
                state_tag: super::state_tag(row.try_get("state_tag")?)?,
                created_at_ms: from_db(row.try_get("created_at_ms")?, "created_at_ms")?,
                activation: pubky_switch_core::records::AccountActivation::parse(
                    row.try_get("activation_requirement")?,
                )
                .map_err(|_| StoreError::Corrupt("activation_requirement"))?,
                identity_doc: row.try_get("identity_doc")?,
            })
        })
        .collect()
}
