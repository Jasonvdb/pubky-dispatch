//! The SQL contents of a fresh account before its first counted write (Switch account
//! binding 3). An identical creation time or an empty chain does not identify those rows.

use futures_util::TryStreamExt;
use pubky_switch_core::enc::lp;
use pubky_switch_core::records::{IdentityDoc, Limits, MAX_ENROLLMENT_BYTES};
use pubky_switch_core::sig::SignedDoc;
use sqlx::{PgConnection, Row};

use super::{AccountTxn, StoreError, from_db};

// Each distinct exclusion in the creating enrollment needs at least its 16 raw ID bytes.
// The complete signed enrollment, including its optional signed identity, fits 256 KiB.
const MAX_ROWS: i64 = MAX_ENROLLMENT_BYTES as i64 / 16;

pub(super) async fn contents(
    conn: &mut PgConnection,
    id: &str,
    store_id: [u8; 16],
    enrollment: [u8; 32],
) -> Result<[u8; 32], StoreError> {
    let corrupt = StoreError::Corrupt("fresh enrollment contents");
    let row = sqlx::query(
        "SELECT identity_key, created_at_ms, generation, announced_limits, identity_doc, \
         directory_version, apps_version, activation_requirement, \
         EXISTS (SELECT 1 FROM apps WHERE account_id = $1) AS has_apps, \
         EXISTS (SELECT 1 FROM held_revoked_apps WHERE account_id = $1) AS has_held \
         FROM accounts WHERE id = $1 AND octet_length(announced_limits) <= 1024 \
         AND (identity_doc IS NULL OR octet_length(identity_doc) <= $2)",
    )
    .bind(id)
    .bind(MAX_ENROLLMENT_BYTES as i64)
    .fetch_one(&mut *conn)
    .await?;
    let identity: [u8; 32] = row
        .try_get::<Vec<u8>, _>("identity_key")?
        .try_into()
        .map_err(|_| corrupt)?;
    let limits: Limits = serde_json::from_slice(&row.try_get::<Vec<u8>, _>("announced_limits")?)
        .map_err(|_| StoreError::Corrupt("announced limits"))?;
    let doc = row
        .try_get::<Option<Vec<u8>>, _>("identity_doc")?
        .map(|bytes| {
            let signed: SignedDoc =
                serde_json::from_slice(&bytes).map_err(|_| StoreError::Corrupt("identity_doc"))?;
            IdentityDoc::verify(&signed, &identity).map_err(|_| StoreError::Corrupt("identity_doc"))
        })
        .transpose()?;
    let directory: i64 = row.try_get("directory_version")?;
    let apps: i64 = row.try_get("apps_version")?;
    if directory != 0
        || apps != 0
        || row.try_get::<bool, _>("has_apps")?
        || row.try_get::<bool, _>("has_held")?
        || row.try_get::<String, _>("activation_requirement")? != "ordinary"
    {
        return Err(StoreError::Corrupt(
            "fresh enrollment directory or exclusions",
        ));
    }
    let created = from_db(row.try_get("created_at_ms")?, "created_at_ms")?;
    let generation = from_db(row.try_get("generation")?, "generation")?;
    let doc_hash = doc.as_ref().map(IdentityDoc::hash);
    let mut hash = blake3::Hasher::new();
    hash.update(&lp(&[
        b"pubky-switch/v1/creation-anchor",
        &store_id,
        &identity,
        &enrollment,
        &created.to_be_bytes(),
        &generation.to_be_bytes(),
        doc_hash.as_ref().map_or(&[][..], |bytes| bytes.as_slice()),
        &limits.app_limit.to_be_bytes(),
        &limits.max_envelope.to_be_bytes(),
        &limits.max_sealed_value.to_be_bytes(),
        &limits.quota_bytes.to_be_bytes(),
        &limits.max_batch.to_be_bytes(),
        &limits.record_quota_bytes.to_be_bytes(),
        &limits.max_import_bytes.to_be_bytes(),
        &directory.to_be_bytes(),
        &apps.to_be_bytes(),
        &[0],
    ]));
    let mut rows = sqlx::query(
        "SELECT app_id, reason, at_ms, data_epoch, rotated FROM kept_app_ids \
         WHERE account_id = $1 ORDER BY app_id LIMIT $2",
    )
    .bind(id)
    .bind(MAX_ROWS + 1)
    .fetch(&mut *conn);
    let mut count = 0;
    while let Some(row) = rows.try_next().await? {
        count += 1;
        if count > MAX_ROWS {
            return Err(StoreError::Corrupt("fresh enrollment exclusion bound"));
        }
        let app: Vec<u8> = row.try_get("app_id")?;
        let reason: String = row.try_get("reason")?;
        let at: Option<i64> = row.try_get("at_ms")?;
        let epoch: Option<i64> = row.try_get("data_epoch")?;
        let rotated: bool = row.try_get("rotated")?;
        let time = at.map(i64::to_be_bytes);
        let epoch = epoch.map(i64::to_be_bytes);
        hash.update(&lp(&[
            &app,
            reason.as_bytes(),
            time.as_ref().map_or(&[][..], |n| n.as_slice()),
            epoch.as_ref().map_or(&[][..], |n| n.as_slice()),
            &[u8::from(rotated)],
        ]));
    }
    let anchor = *hash.finalize().as_bytes();
    if anchor == [0; 32] {
        return Err(StoreError::Corrupt("zero creation anchor"));
    }
    Ok(anchor)
}

impl AccountTxn {
    /// Check a pristine creating receipt against the durable contents and the mark
    /// outside SQL. Later receipts have their own covered position.
    pub(crate) async fn matches_creation_anchor(
        &mut self,
        store_id: [u8; 16],
        enrollment: [u8; 32],
        marked: [u8; 32],
    ) -> Result<bool, StoreError> {
        let id = self.head().id.clone();
        let stored: Option<Vec<u8>> =
            sqlx::query_scalar("SELECT creation_anchor FROM accounts WHERE id = $1")
                .bind(&id)
                .fetch_one(self.conn())
                .await?;
        if stored.as_deref() != Some(marked.as_slice()) || marked == [0; 32] {
            return Ok(false);
        }
        Ok(contents(self.conn(), &id, store_id, enrollment).await? == marked)
    }
}
