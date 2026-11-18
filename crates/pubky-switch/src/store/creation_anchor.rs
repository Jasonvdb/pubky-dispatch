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

/// Recover the SQL witness before this transaction can change the opening contents.
/// The unique creating receipt supplies the original store and document hash. The mark
/// remains the independent authority for using the resulting commitment.
pub(super) async fn opening_origin(
    conn: &mut PgConnection,
    head: &super::AccountHead,
    stored: &[u8],
) -> Result<Option<[u8; 32]>, StoreError> {
    let receipt: Option<(Vec<u8>, Vec<u8>)> = sqlx::query_as(
        "SELECT store_id, enrollment_hash FROM enrollment_answers \
         WHERE account_id = $1 AND creating AND created_at_ms = $2",
    )
    .bind(&head.id)
    .bind(super::to_db(head.created_at_ms, "created_at_ms")?)
    .fetch_optional(&mut *conn)
    .await?;
    let Some((store, enrollment)) = receipt else {
        return Ok(None);
    };
    let (Ok(store), Ok(enrollment)) = (store.try_into(), enrollment.try_into()) else {
        return Ok(None);
    };
    match contents(conn, &head.id, store, enrollment).await {
        Ok(origin) => Ok((origin.as_slice() == stored).then_some(origin)),
        Err(
            StoreError::Corrupt(_)
            | StoreError::OutOfRange(_)
            | StoreError::Database(sqlx::Error::RowNotFound),
        ) => Ok(None),
        Err(error) => Err(error),
    }
}

impl AccountTxn {
    /// Verify the opening receipt against the creation and actual retained positions.
    /// The account's common verdict separately checks the chain at the mark.
    pub(crate) async fn covers_opening_receipt(
        &mut self,
        store_id: [u8; 16],
        enrollment: [u8; 32],
        mark: &crate::marks::AccountMark,
    ) -> Result<bool, StoreError> {
        let head = self.head();
        let Some(anchor) = mark.creation_anchor.for_creation(head.created_at_ms) else {
            return Ok(false);
        };
        if mark.created_at_ms != head.created_at_ms
            || self.creation_origin() != Some(anchor)
            || mark.state_version > head.state_version
        {
            return Ok(false);
        }
        if head.state_version == 0 && (mark.generation != 0 || head.last_seq != 0) {
            return Ok(false);
        }
        let id = head.id.clone();
        // A positive marked position must carry this same origin at its tagged history
        // row. A zero mark can attest to the immutable opening receipt only; it never
        // establishes coverage of later exclusion changes.
        let covered: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM enrollment_answers WHERE account_id = $1 AND \
             enrollment_hash = $2 AND store_id = $3 AND creating) AND ($4::bigint = 0 OR EXISTS( \
             SELECT 1 FROM state_history WHERE account_id = $1 AND state_version = $4 \
             AND state_tag = $5 AND creation_anchor = $6))",
        )
        .bind(id)
        .bind(enrollment.as_slice())
        .bind(store_id.as_slice())
        .bind(super::to_db(mark.state_version, "state_version")?)
        .bind(mark.state_tag.as_slice())
        .bind(anchor.as_slice())
        .fetch_one(self.conn())
        .await?;
        Ok(covered)
    }
}
