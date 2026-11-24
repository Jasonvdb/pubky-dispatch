//! The state signed operations change (Switch wire 6.2, 6.8): apps, receive keys, key bundle
//! parts, shared records, claims and their entries, the lists, invite codes and batch
//! records. Every read and write runs in the request's transaction, under the account's
//! lock, so a batch sees one consistent state and commits all of its changes or none.
//!
//! Signed documents are stored in their carrying form, as received. Sealed values stay
//! sealed: nothing here opens or interprets them (Switch spec 1).

use futures_util::TryStreamExt;
use pubky_switch_core::{
    chain::{ItemType, TransitionProof, item_hash},
    claims::{Claim, ClaimTally},
    ident::Policy,
    ops::{BatchRecord, OpKind, Position, RecordVersion, SignedOp},
    records::IdentityDoc,
    recovery::{CheckedRecord, RecordDate, UploadBase},
    shared::{ApplicationRef, RecordState},
    sig::SignedDoc,
};
use sqlx::Row;

use super::{
    AccountTxn, KeptReason, StoreError, claim_codec, from_db,
    identity::{decode_doc, encode_doc},
    to_db,
};

/// An own app as stored.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct StoredApp {
    /// The App ID.
    pub app_id: [u8; 16],
    /// Its newest app record.
    pub record: Option<SignedDoc>,
    /// When the service took it.
    pub record_at_ms: Option<u64>,
    /// The renewed certificate a `cert.put` stored.
    pub renewed_cert: Option<SignedDoc>,
    /// Its current receive key record.
    pub receive_key: Option<SignedDoc>,
    /// Its cursor.
    pub cursor: Option<Position>,
    /// The `apps_version` at which it became reachable.
    pub reachable_since: Option<u64>,
    /// When a full key bundle was requested for it, while not yet covered.
    pub full_requested_ms: Option<u64>,
    /// The `seq` of the part that completed its last full-bundle request: the request stays
    /// in force for dropping parts until its cursor has passed it (Switch wire 6.2).
    pub full_completed_seq: Option<u64>,
}

/// A key bundle part as stored.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoredBundlePart {
    /// Its first data epoch.
    pub first_epoch: u64,
    /// Its last data epoch.
    pub last_epoch: u64,
    /// The `seq` of its `key_bundle.put`.
    pub seq: u64,
    /// The signed `key_bundle.put`.
    pub op: SignedDoc,
}

/// A shared record as stored.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoredRecord {
    /// Its key, collection, policy, version and whether it is deleted.
    pub state: RecordState,
    /// The exact receiving application, not the source version (Switch wire 6.3).
    pub revision: ApplicationRef,
    /// The bytes its value counts against the storage quota.
    pub value_bytes: u64,
    /// The writing app.
    pub writer: [u8; 16],
    /// The certificate the write was checked against.
    pub cert: SignedDoc,
    /// The signed `record.put`.
    pub op: SignedDoc,
    /// Where the write came from: made here, with its transition proof, or taken from a
    /// recovery upload.
    pub origin: RecordOrigin,
    /// Uploads conflict with it (Switch wire 7.4.9 `divergent`): read from the divergent
    /// uploads the account keeps for its key. [`AccountTxn::put_record`] ignores it: a write
    /// made here clears them, and [`AccountTxn::put_divergent_upload`] adds one.
    pub divergent: bool,
}

impl StoredRecord {
    fn check_revision(&self) -> Result<(), StoreError> {
        let corrupt = || StoreError::Corrupt("a record's application contradicts its write");
        self.revision.check().map_err(|_| corrupt())?;
        let bytes = self.op.doc_bytes().map_err(|_| corrupt())?;
        if self.revision.item_hash != item_hash(ItemType::Op, &bytes) {
            return Err(corrupt());
        }
        let op = SignedOp::peek(&self.op).map_err(|_| corrupt())?;
        let OpKind::RecordPut(put) = &op.body().kind else {
            return Err(corrupt());
        };
        if put.key != self.state.key
            || put.collection != self.state.collection
            || put.policy != self.state.policy
            || put.value_sealed.looks_like_delete() != self.state.deleted
            || op.body().generation != self.state.version.generation
        {
            return Err(corrupt());
        }
        let matches = match &self.origin {
            RecordOrigin::Written { proof, .. } => {
                self.revision.generation == self.state.version.generation
                    && self.revision.seq == self.state.version.version
                    && TransitionProof::peek(proof).ok().and_then(|p| {
                        p.check_binds(&op)
                            .ok()
                            .and_then(|()| p.record_revision().ok())
                    }) == Some(self.revision)
            }
            RecordOrigin::Uploaded { seq, .. } => {
                self.revision.seq == *seq
                    && self.revision.generation > self.state.version.generation
            }
        };
        if !matches {
            return Err(corrupt());
        }
        Ok(())
    }
}

/// Where a shared record's current write came from (Switch wire 7.4.14, 10.3).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RecordOrigin {
    /// A write made at this service.
    Written {
        /// Its transition proof.
        proof: SignedDoc,
        /// The uploaded version the first write here built on, with its operation's hash,
        /// or `None` when the writes here built on none (Switch wire 10.3 `upload_base`).
        upload_base: Option<UploadBase>,
    },
    /// Taken from a recovery upload after a provider loss. It has no proof: the lost
    /// service's proofs date nothing here (Switch wire 7.4.9 `proof`).
    Uploaded {
        /// The `seq` of the `upload` transition that listed it, its record view's `seq`.
        seq: u64,
        /// The lost service's proof gave its version; otherwise it is the lower bound.
        exact: bool,
        /// The signed base's proved operation, when the recovery comparison identified it.
        parent: Option<[u8; 32]>,
    },
}

impl RecordOrigin {
    /// The write's transition proof, for a write made here.
    pub fn proof(&self) -> Option<&SignedDoc> {
        match self {
            RecordOrigin::Written { proof, .. } => Some(proof),
            RecordOrigin::Uploaded { .. } => None,
        }
    }
}

/// An upload that conflicts with a record (Switch spec 12.6 step 3), at its place among the
/// record's divergent uploads.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DivergentUpload {
    /// Its place, from 0 (Switch wire 10.3 `divergent` part `index`).
    pub position: u64,
    /// The uploaded signed `record.put`.
    pub op: SignedDoc,
    /// The writer's certificate supplied with the operation.
    pub cert: SignedDoc,
    /// The lost service's proved version, if held.
    pub proved_version: Option<u64>,
    /// The operation's `doc_hash`.
    pub op_hash: [u8; 32],
}

/// A claim entry as stored, for `GET /claims` (Switch wire 7.4.8).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoredClaimEntry {
    /// The claim's step before the entry.
    pub step: u64,
    /// The entry's `seq`.
    pub seq: u64,
    /// The signed `claim`.
    pub op: SignedDoc,
    /// Its transition proof.
    pub proof: SignedDoc,
}

/// An invite code as stored.
#[derive(Clone, Debug, PartialEq)]
pub struct StoredInvite {
    /// `hash(code bytes)`.
    pub code_hash: [u8; 32],
    /// How many appends it admits.
    pub max_uses: u64,
    /// How many it admitted.
    pub uses: u64,
    /// The writing app.
    pub writer: [u8; 16],
    /// When it expires.
    pub expires_at_ms: u64,
}

fn array<const N: usize>(bytes: &[u8], what: &'static str) -> Result<[u8; N], StoreError> {
    <[u8; N]>::try_from(bytes).map_err(|_| StoreError::Corrupt(what))
}

fn opt_u64(value: Option<i64>, what: &'static str) -> Result<Option<u64>, StoreError> {
    value.map(|v| from_db(v, what)).transpose()
}

fn opt_to_db(value: Option<u64>, what: &'static str) -> Result<Option<i64>, StoreError> {
    value.map(|v| to_db(v, what)).transpose()
}

fn opt_doc(bytes: Option<Vec<u8>>, what: &'static str) -> Result<Option<SignedDoc>, StoreError> {
    bytes.map(|b| decode_doc(&b, what)).transpose()
}

pub(super) fn keys<const N: usize>(keys: &[[u8; N]]) -> Vec<Vec<u8>> {
    keys.iter().map(|key| key.to_vec()).collect()
}

fn db(error: sqlx::Error) -> StoreError {
    StoreError::from_db(error)
}

impl AccountTxn {
    /// The directory's versions: `directory_version` and `apps_version` (Switch wire 7.4.10).
    pub async fn directory_versions(&mut self) -> Result<(u64, u64), StoreError> {
        let id = self.head().id.clone();
        let row = sqlx::query("SELECT directory_version, apps_version FROM accounts WHERE id = $1")
            .bind(id)
            .fetch_one(self.conn())
            .await
            .map_err(db)?;
        Ok((
            from_db(row.try_get("directory_version")?, "directory_version")?,
            from_db(row.try_get("apps_version")?, "apps_version")?,
        ))
    }

    /// Set the directory's versions.
    pub async fn set_directory_versions(
        &mut self,
        directory_version: u64,
        apps_version: u64,
    ) -> Result<(), StoreError> {
        let id = self.head().id.clone();
        sqlx::query("UPDATE accounts SET directory_version = $2, apps_version = $3 WHERE id = $1")
            .bind(id)
            .bind(to_db(directory_version, "directory_version")?)
            .bind(to_db(apps_version, "apps_version")?)
            .execute(self.conn())
            .await
            .map_err(db)?;
        Ok(())
    }

    /// Every own app the account holds, by App ID.
    pub async fn apps(&mut self) -> Result<Vec<StoredApp>, StoreError> {
        let id = self.head().id.clone();
        let rows = sqlx::query(
            "SELECT app_id, record, record_at_ms, renewed_cert, receive_key, cursor_generation, \
             cursor_seq, reachable_since, full_requested_ms, full_completed_seq FROM apps \
             WHERE account_id = $1 ORDER BY app_id",
        )
        .bind(id)
        .fetch_all(self.conn())
        .await
        .map_err(db)?;
        rows.iter().map(app_of).collect()
    }

    /// Whether any listed app with a receive key and no permanent exclusion passes the
    /// caller's certificate check (Switch wire 7.4.10). Read one candidate at a time.
    pub(crate) async fn any_listed_receiver(
        &mut self,
        doc: &IdentityDoc,
        current: impl Fn(&StoredApp) -> Result<bool, StoreError>,
    ) -> Result<bool, StoreError> {
        let mut rows = sqlx::query(
            "SELECT app_id, record, record_at_ms, renewed_cert, receive_key, cursor_generation, \
             cursor_seq, reachable_since, full_requested_ms, full_completed_seq FROM apps a \
             WHERE account_id = $1 AND app_id = ANY($2::bytea[]) AND receive_key IS NOT NULL \
             AND NOT EXISTS (SELECT FROM kept_app_ids k WHERE k.account_id = a.account_id AND k.app_id = a.app_id)",
        )
        .bind(self.head().id.clone())
        .bind(super::identity::listed_ids(doc))
        .fetch(self.conn());
        while let Some(row) = rows.try_next().await? {
            if current(&app_of(&row)?)? {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Store an own app, replacing what the account held for it.
    pub async fn put_app(&mut self, app: &StoredApp) -> Result<(), StoreError> {
        let id = self.head().id.clone();
        let doc = |doc: &Option<SignedDoc>| doc.as_ref().map(encode_doc).transpose();
        sqlx::query(
            "INSERT INTO apps (account_id, app_id, record, record_at_ms, renewed_cert, \
             receive_key, cursor_generation, cursor_seq, reachable_since, full_requested_ms, \
             full_completed_seq) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11) \
             ON CONFLICT (account_id, app_id) DO UPDATE SET record = $3, record_at_ms = $4, \
             renewed_cert = $5, receive_key = $6, cursor_generation = $7, cursor_seq = $8, \
             reachable_since = $9, full_requested_ms = $10, full_completed_seq = $11",
        )
        .bind(id)
        .bind(app.app_id.as_slice())
        .bind(doc(&app.record)?)
        .bind(opt_to_db(app.record_at_ms, "record_at_ms")?)
        .bind(doc(&app.renewed_cert)?)
        .bind(doc(&app.receive_key)?)
        .bind(opt_to_db(
            app.cursor.map(|c| c.generation),
            "cursor_generation",
        )?)
        .bind(opt_to_db(app.cursor.map(|c| c.seq), "cursor_seq")?)
        .bind(opt_to_db(app.reachable_since, "reachable_since")?)
        .bind(opt_to_db(app.full_requested_ms, "full_requested_ms")?)
        .bind(opt_to_db(app.full_completed_seq, "full_completed_seq")?)
        .execute(self.conn())
        .await
        .map_err(db)?;
        // A new record or renewed certificate supersedes the earlier one's document. Noted
        // at every app row write, a cursor move included: bounded, at one indexed lookup of
        // the app's `app.put` and `cert.put` items and one read of the account's app rows
        // before the commit.
        self.note_app_documents(app.app_id);
        self.note_change();
        Ok(())
    }

    /// Which of `kids` some app of the account registered.
    pub async fn registered_kids(&mut self, kids: &[[u8; 8]]) -> Result<Vec<[u8; 8]>, StoreError> {
        let id = self.head().id.clone();
        let rows: Vec<Vec<u8>> = sqlx::query_scalar(
            "SELECT kid FROM receive_keys WHERE account_id = $1 AND kid = ANY($2)",
        )
        .bind(id)
        .bind(keys(kids))
        .fetch_all(self.conn())
        .await
        .map_err(db)?;
        rows.iter().map(|kid| array(kid, "kid")).collect()
    }

    /// Keep a registered receive key record.
    pub async fn add_receive_key(
        &mut self,
        app_id: &[u8; 16],
        n: u64,
        kid: &[u8; 8],
        record: &SignedDoc,
    ) -> Result<(), StoreError> {
        let id = self.head().id.clone();
        sqlx::query(
            "INSERT INTO receive_keys (account_id, kid, app_id, n, record) \
             VALUES ($1, $2, $3, $4, $5)",
        )
        .bind(id)
        .bind(kid.as_slice())
        .bind(app_id.as_slice())
        .bind(to_db(n, "n")?)
        .bind(encode_doc(record)?)
        .execute(self.conn())
        .await
        .map_err(db)?;
        Ok(())
    }

    /// The key bundle parts stored for `target`, in `first_epoch` order.
    pub async fn bundle_parts(
        &mut self,
        target: &[u8; 16],
    ) -> Result<Vec<StoredBundlePart>, StoreError> {
        let id = self.head().id.clone();
        let rows = sqlx::query(
            "SELECT first_epoch, last_epoch, seq, op FROM key_bundle_parts \
             WHERE account_id = $1 AND target_app_id = $2 ORDER BY first_epoch",
        )
        .bind(id)
        .bind(target.as_slice())
        .fetch_all(self.conn())
        .await
        .map_err(db)?;
        rows.iter()
            .map(|row| {
                let op: Vec<u8> = row.try_get("op")?;
                Ok(StoredBundlePart {
                    first_epoch: from_db(row.try_get("first_epoch")?, "first_epoch")?,
                    last_epoch: from_db(row.try_get("last_epoch")?, "last_epoch")?,
                    seq: from_db(row.try_get("seq")?, "seq")?,
                    op: decode_doc(&op, "key bundle part")?,
                })
            })
            .collect()
    }

    /// Replace the key bundle parts stored for `target` with `parts`.
    pub async fn set_bundle_parts(
        &mut self,
        target: &[u8; 16],
        parts: &[StoredBundlePart],
    ) -> Result<(), StoreError> {
        let id = self.head().id.clone();
        // A part no longer stored shows as its stub; one stored again keeps its document.
        let gone: Vec<i64> = sqlx::query_scalar(
            "DELETE FROM key_bundle_parts WHERE account_id = $1 AND target_app_id = $2 \
             RETURNING seq",
        )
        .bind(&id)
        .bind(target.as_slice())
        .fetch_all(self.conn())
        .await
        .map_err(db)?;
        let gone: Vec<u64> = gone
            .into_iter()
            .map(|seq| from_db(seq, "seq"))
            .collect::<Result<_, _>>()?;
        self.note_superseded(gone);
        for part in parts {
            sqlx::query(
                "INSERT INTO key_bundle_parts (account_id, target_app_id, first_epoch, \
                 last_epoch, seq, op) VALUES ($1, $2, $3, $4, $5, $6)",
            )
            .bind(&id)
            .bind(target.as_slice())
            .bind(to_db(part.first_epoch, "first_epoch")?)
            .bind(to_db(part.last_epoch, "last_epoch")?)
            .bind(to_db(part.seq, "seq")?)
            .bind(encode_doc(&part.op)?)
            .execute(self.conn())
            .await
            .map_err(db)?;
        }
        Ok(())
    }

    /// The shared records at `keys` that the account holds.
    pub async fn records(&mut self, keys_: &[[u8; 32]]) -> Result<Vec<StoredRecord>, StoreError> {
        let id = self.head().id.clone();
        let rows = sqlx::query(&format!(
            "SELECT {RECORD_COLUMNS} FROM shared_records WHERE account_id = $1 AND key = ANY($2)"
        ))
        .bind(id)
        .bind(keys(keys_))
        .fetch_all(self.conn())
        .await
        .map_err(db)?;
        rows.iter().map(record_of).collect()
    }

    /// Live record keys and the bytes their values count, over the records not at `excluding`.
    pub async fn record_totals(
        &mut self,
        excluding: &[[u8; 32]],
    ) -> Result<(u64, u64), StoreError> {
        let id = self.head().id.clone();
        let row = sqlx::query(
            "SELECT count(*) AS keys, coalesce(sum(value_bytes), 0)::BIGINT AS bytes \
             FROM shared_records WHERE account_id = $1 AND NOT deleted \
             AND NOT (key = ANY($2))",
        )
        .bind(id)
        .bind(keys(excluding))
        .fetch_one(self.conn())
        .await
        .map_err(db)?;
        Ok((
            from_db(row.try_get("keys")?, "record keys")?,
            from_db(row.try_get("bytes")?, "record bytes")?,
        ))
    }

    /// Store a shared record's newest write. A write made here clears the record's divergent
    /// uploads: it is a newer version at this service (Switch spec 12.6 step 3).
    ///
    /// # Errors
    ///
    /// [`StoreError::Corrupt`] for a write of another collection or policy than the record
    /// held at its key, a deleted one included, which nothing stores: the record's collection
    /// and policy are fixed at creation (Switch wire 6.2, Switch spec 10.3.1), and the row
    /// would keep the old ones beside the new write.
    pub async fn put_record(&mut self, record: &StoredRecord) -> Result<(), StoreError> {
        self.put_record_with_parent(record, None).await
    }

    pub(crate) async fn put_record_with_parent(
        &mut self,
        record: &StoredRecord,
        parent_copy: Option<&CheckedRecord>,
    ) -> Result<(), StoreError> {
        record.check_revision()?;
        let id = self.head().id.clone();
        let state = &record.state;
        // The write it replaces shows as its stub from now on (Switch wire 7.5).
        let replaced = sqlx::query(
            "SELECT generation, version, collection, read_scope, write_scopes, create_scope, delete_scope, permanent, \
             permanent_generation FROM shared_records WHERE account_id = $1 AND key = $2",
        )
        .bind(&id)
        .bind(state.key.as_slice())
        .fetch_optional(self.conn())
        .await
        .map_err(db)?;
        if let Some(row) = replaced {
            let collection: Vec<u8> = row.try_get("collection")?;
            let read_scope: String = row.try_get("read_scope")?;
            let write_scopes: Vec<String> = row.try_get("write_scopes")?;
            let permanent: bool = row.try_get("permanent")?;
            let named: Option<i64> = row.try_get("permanent_generation")?;
            let named = named
                .map(|g| from_db(g, "permanent_generation"))
                .transpose()?;
            if collection != state.collection
                || read_scope != state.policy.read_scope
                || write_scopes != state.policy.write_scopes
                || row.try_get::<Option<&str>, _>("create_scope")?
                    != state.policy.create_scope.as_deref()
                || row.try_get::<Option<&str>, _>("delete_scope")?
                    != state.policy.delete_scope.as_deref()
                || permanent != state.policy.permanent.is_some()
                || named != state.policy.permanent.and_then(|p| p.generation)
            {
                return Err(StoreError::Corrupt(
                    "a record write of another collection or policy than the record it replaces",
                ));
            }
            let generation: i64 = row.try_get("generation")?;
            if from_db(generation, "generation")? == self.head().generation {
                let version: i64 = row.try_get("version")?;
                self.note_superseded([from_db(version, "version")?]);
            }
        }
        let (proof, upload_seq, exact, base, parent) = match &record.origin {
            RecordOrigin::Written { proof, upload_base } => {
                (Some(encode_doc(proof)?), None, true, *upload_base, None)
            }
            RecordOrigin::Uploaded { seq, exact, parent } => (
                None,
                Some(to_db(*seq, "upload_seq")?),
                *exact,
                None,
                *parent,
            ),
        };
        if parent_copy.map(|r| r.uploaded.op_hash) != parent.filter(|_| !exact)
            || parent_copy.is_some_and(|r| r.put.key != state.key)
        {
            return Err(StoreError::Corrupt(
                "the record's parent copy doesn't match its proved parent",
            ));
        }
        let parent_copy = parent_copy
            .map(|r| serde_json::to_vec(&(&r.op, &r.cert)))
            .transpose()
            .map_err(|_| StoreError::Corrupt("invalid parent copy"))?;
        let base_generation = base
            .map(|b| to_db(b.version.generation, "upload_base_generation"))
            .transpose()?;
        let base_version = base
            .map(|b| to_db(b.version.version, "upload_base_version"))
            .transpose()?;
        let base_hash = base.map(|b| b.op_hash.to_vec());
        sqlx::query(
            "INSERT INTO shared_records (account_id, key, collection, read_scope, write_scopes, \
             generation, version, deleted, value_bytes, writer, cert, op, proof, from_upload, \
             upload_seq, version_exact, upload_base_generation, upload_base_version, \
             upload_base_op_hash, application_generation, application_seq, application_item_hash, \
             permanent, permanent_generation, proved_parent_hash, create_scope, delete_scope, parent_copy) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, \
             $17, $18, $19, $20, $21, $22, $23, $24, $25, $26, $27, $28) \
             ON CONFLICT (account_id, key) DO UPDATE SET generation = $6, version = $7, \
             deleted = $8, value_bytes = $9, writer = $10, cert = $11, op = $12, proof = $13, \
             from_upload = $14, upload_seq = $15, version_exact = $16, \
             upload_base_generation = $17, upload_base_version = $18, \
             upload_base_op_hash = $19, application_generation = $20, application_seq = $21, \
             application_item_hash = $22, proved_parent_hash = $25, \
             parent_copy = $28",
        )
        .bind(id)
        .bind(state.key.as_slice())
        .bind(state.collection.as_slice())
        .bind(&state.policy.read_scope)
        .bind(&state.policy.write_scopes)
        .bind(to_db(state.version.generation, "generation")?)
        .bind(to_db(state.version.version, "version")?)
        .bind(state.deleted)
        .bind(to_db(record.value_bytes, "value_bytes")?)
        .bind(record.writer.as_slice())
        .bind(encode_doc(&record.cert)?)
        .bind(encode_doc(&record.op)?)
        .bind(proof)
        .bind(matches!(record.origin, RecordOrigin::Uploaded { .. }))
        .bind(upload_seq)
        .bind(exact)
        .bind(base_generation)
        .bind(base_version)
        .bind(base_hash)
        .bind(to_db(record.revision.generation, "application_generation")?)
        .bind(to_db(record.revision.seq, "application_seq")?)
        .bind(record.revision.item_hash.as_slice())
        .bind(state.policy.permanent.is_some())
        .bind(
            state
                .policy
                .permanent
                .and_then(|p| p.generation)
                .map(|g| to_db(g, "permanent_generation"))
                .transpose()?,
        )
        .bind(parent.as_ref().map(|hash| hash.as_slice()))
        .bind(state.policy.create_scope.as_deref())
        .bind(state.policy.delete_scope.as_deref())
        .bind(parent_copy)
        .execute(self.conn())
        .await
        .map_err(db)?;
        if matches!(record.origin, RecordOrigin::Written { .. }) {
            let id = self.head().id.clone();
            sqlx::query("DELETE FROM divergent_uploads WHERE account_id = $1 AND key = $2")
                .bind(id)
                .bind(state.key.as_slice())
                .execute(self.conn())
                .await
                .map_err(db)?;
        }
        Ok(())
    }

    /// The divergent uploads the account keeps for the record at `key`, in order.
    pub async fn divergent_uploads(
        &mut self,
        key: &[u8; 32],
    ) -> Result<Vec<DivergentUpload>, StoreError> {
        let id = self.head().id.clone();
        let rows = sqlx::query(
            "SELECT position, op, op_hash, cert, proved_version FROM divergent_uploads \
             WHERE account_id = $1 AND key = $2 ORDER BY position",
        )
        .bind(id)
        .bind(key.as_slice())
        .fetch_all(self.conn())
        .await
        .map_err(db)?;
        rows.iter()
            .map(|row| {
                let position: i16 = row.try_get("position")?;
                let op: Vec<u8> = row.try_get("op")?;
                let op_hash: Vec<u8> = row.try_get("op_hash")?;
                Ok(DivergentUpload {
                    position: u64::try_from(position)
                        .map_err(|_| StoreError::Corrupt("a divergent upload's position"))?,
                    op: decode_doc(&op, "divergent upload")?,
                    op_hash: array(&op_hash, "divergent upload hash")?,
                    cert: decode_doc(
                        &row.try_get::<Vec<u8>, _>("cert")?,
                        "divergent upload certificate",
                    )?,
                    proved_version: row
                        .try_get::<Option<i64>, _>("proved_version")?
                        .map(|v| from_db(v, "proved_version"))
                        .transpose()?,
                })
            })
            .collect()
    }

    pub(crate) async fn parent_copy(
        &mut self,
        key: &[u8; 32],
        version: RecordVersion,
        hash: [u8; 32],
    ) -> Result<Option<CheckedRecord>, StoreError> {
        let bytes: Option<Vec<u8>> = sqlx::query_scalar(
            "SELECT parent_copy FROM shared_records WHERE account_id=$1 AND key=$2",
        )
        .bind(self.head().id.clone())
        .bind(key.as_slice())
        .fetch_one(self.conn())
        .await
        .map_err(db)?;
        Ok(bytes.and_then(|bytes| {
            let (op, cert) = serde_json::from_slice(&bytes).ok()?;
            CheckedRecord::verified_parent(op, cert, &self.head().identity_key, key, version, hash)
        }))
    }

    /// Original dates established for writes during this recovery.
    pub(crate) async fn record_dates(
        &mut self,
        hashes: &[[u8; 32]],
    ) -> Result<std::collections::BTreeMap<[u8; 32], RecordDate>, StoreError> {
        let id = self.head().id.clone();
        let rows = sqlx::query(
            "SELECT op_hash, version, written_at_ms FROM record_dates
             WHERE account_id = $1 AND op_hash = ANY($2)",
        )
        .bind(id)
        .bind(keys(hashes))
        .fetch_all(self.conn())
        .await
        .map_err(db)?;
        rows.iter()
            .map(|r| {
                Ok((
                    array(&r.try_get::<Vec<u8>, _>("op_hash")?, "dated operation")?,
                    RecordDate {
                        version: from_db(r.try_get("version")?, "version")?,
                        time: from_db(r.try_get("written_at_ms")?, "written_at_ms")?,
                    },
                ))
            })
            .collect()
    }

    /// Keep the authenticated original date across repeats with any certificate.
    pub(crate) async fn keep_record_date(
        &mut self,
        hash: &[u8; 32],
        date: RecordDate,
    ) -> Result<(), StoreError> {
        let id = self.head().id.clone();
        sqlx::query(
            "INSERT INTO record_dates (account_id, op_hash, version, written_at_ms)
             VALUES ($1, $2, $3, $4) ON CONFLICT DO NOTHING",
        )
        .bind(id)
        .bind(hash.as_slice())
        .bind(to_db(date.version, "version")?)
        .bind(to_db(date.time, "written_at_ms")?)
        .execute(self.conn())
        .await
        .map_err(db)?;
        Ok(())
    }

    /// Remove a disqualified current upload. Its surviving conflicts are merged again
    /// in their original order in this transaction (Switch wire 7.4.14).
    pub(crate) async fn remove_current_upload(&mut self, key: &[u8; 32]) -> Result<(), StoreError> {
        let id = self.head().id.clone();
        sqlx::query("DELETE FROM shared_records WHERE account_id=$1 AND key=$2 AND from_upload")
            .bind(id)
            .bind(key.as_slice())
            .execute(self.conn())
            .await
            .map_err(db)?;
        Ok(())
    }

    /// Keep an operation in its resolved position among the record's divergent uploads.
    pub async fn put_divergent_upload(
        &mut self,
        key: &[u8; 32],
        position: usize,
        op: &SignedDoc,
        cert: &SignedDoc,
        hash: &[u8; 32],
        proved_version: Option<u64>,
    ) -> Result<(), StoreError> {
        let id = self.head().id.clone();
        let position = i16::try_from(position)
            .map_err(|_| StoreError::Corrupt("a divergent upload's position"))?;
        sqlx::query(
            "INSERT INTO divergent_uploads (account_id, key, position, op, cert, op_hash, proved_version) \
             VALUES ($1, $2, $3, $4, $5, $6, $7) ON CONFLICT (account_id, key, position) DO UPDATE SET \
             op = EXCLUDED.op, cert = EXCLUDED.cert, op_hash = EXCLUDED.op_hash, proved_version = EXCLUDED.proved_version",
        )
        .bind(id)
        .bind(key.as_slice())
        .bind(position)
        .bind(encode_doc(op)?)
        .bind(encode_doc(cert)?)
        .bind(hash.as_slice())
        .bind(proved_version.map(|v| to_db(v, "proved_version")).transpose()?)
        .execute(self.conn())
        .await
        .map_err(db)?;
        Ok(())
    }

    /// Remove a resolved conflict and preserve the order of the remaining export positions.
    pub(crate) async fn remove_divergent_upload(
        &mut self,
        key: &[u8; 32],
        position: usize,
        count: usize,
    ) -> Result<(), StoreError> {
        let id = self.head().id.clone();
        for slot in position..count {
            let at = i16::try_from(slot)
                .map_err(|_| StoreError::Corrupt("a divergent upload's position"))?;
            let query = if slot == position {
                "DELETE FROM divergent_uploads WHERE account_id=$1 AND key=$2 AND position=$3"
            } else {
                "UPDATE divergent_uploads SET position=position-1 WHERE account_id=$1 AND key=$2 AND position=$3"
            };
            sqlx::query(query)
                .bind(&id)
                .bind(key.as_slice())
                .bind(at)
                .execute(self.conn())
                .await
                .map_err(db)?;
        }
        Ok(())
    }

    /// The claims at `claim_keys` that the account holds.
    pub async fn claims(
        &mut self,
        claim_keys: &[[u8; 32]],
    ) -> Result<Vec<([u8; 32], Claim)>, StoreError> {
        let id = self.head().id.clone();
        let rows = sqlx::query(
            "SELECT claim_key, state FROM claims WHERE account_id = $1 AND claim_key = ANY($2)",
        )
        .bind(id)
        .bind(keys(claim_keys))
        .fetch_all(self.conn())
        .await
        .map_err(db)?;
        rows.iter()
            .map(|row| {
                let key: Vec<u8> = row.try_get("claim_key")?;
                let state: Vec<u8> = row.try_get("state")?;
                Ok((array(&key, "claim_key")?, claim_codec::decode(&state)?))
            })
            .collect()
    }

    /// What the per-app claim limits count for `writer` over the claims not at `excluding`
    /// (Switch wire 6.8 "Per app").
    pub async fn claim_tally(
        &mut self,
        writer: &[u8; 16],
        excluding: &[[u8; 32]],
    ) -> Result<ClaimTally, StoreError> {
        let id = self.head().id.clone();
        let row = sqlx::query(
            "SELECT count(*) AS claims, \
             count(*) FILTER (WHERE creator = $2) AS created, \
             coalesce(sum(cardinality(array_positions(open_owners, $2))), 0)::BIGINT AS open \
             FROM claims WHERE account_id = $1 AND NOT (claim_key = ANY($3))",
        )
        .bind(id)
        .bind(writer.as_slice())
        .bind(keys(excluding))
        .fetch_one(self.conn())
        .await
        .map_err(db)?;
        Ok(ClaimTally {
            claims: from_db(row.try_get("claims")?, "claims")?,
            created_by_writer: from_db(row.try_get("created")?, "claims created")?,
            open_attempts_of_writer: from_db(row.try_get("open")?, "open attempts")?,
        })
    }

    /// Store a claim's state, with when it may be deleted (Switch wire 6.8).
    pub async fn put_claim(
        &mut self,
        claim_key: &[u8; 32],
        claim: &Claim,
    ) -> Result<(), StoreError> {
        let id = self.head().id.clone();
        sqlx::query(
            "INSERT INTO claims (account_id, claim_key, state, creator, tombstone, open_owners, \
             delete_after_ms, delete_after_entry_ms) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8) \
             ON CONFLICT (account_id, claim_key) DO UPDATE SET state = $3, creator = $4, \
             tombstone = $5, open_owners = $6, delete_after_ms = $7, \
             delete_after_entry_ms = $8",
        )
        .bind(id)
        .bind(claim_key.as_slice())
        .bind(claim_codec::encode(claim)?)
        .bind(claim.creator.map(|c| c.to_vec()))
        .bind(claim.tombstone)
        .bind(claim_codec::open_owners(claim))
        .bind(opt_to_db(
            claim_codec::deletion(claim).0,
            "delete_after_ms",
        )?)
        .bind(opt_to_db(
            claim_codec::deletion(claim).1,
            "delete_after_entry_ms",
        )?)
        .execute(self.conn())
        .await
        .map_err(db)?;
        // A tombstone's entries are compacted away (Switch wire 6.8, 7.4.8 "A tombstone has
        // no entries"): their documents go, and so do their rows, each entry's op and proof
        // with it. No read of a tombstone needs them: `GET /claims` reads none for it, and
        // the feed, `GET /apps`' proof generations and the documents' rule count only a live
        // claim's. A recovery upload that reopens it rebuilds it from the upload, with no
        // entries of its own from before.
        if claim.tombstone {
            let entries = self.entry_seqs(&[claim_key.to_vec()]).await?;
            self.note_superseded(entries);
            let id = self.head().id.clone();
            sqlx::query("DELETE FROM claim_entries WHERE account_id = $1 AND claim_key = $2")
                .bind(id)
                .bind(claim_key.as_slice())
                .execute(self.conn())
                .await
                .map_err(db)?;
        }
        Ok(())
    }

    /// The `seq`s of the entries of the claims at `claim_keys`.
    async fn entry_seqs(&mut self, claim_keys: &[Vec<u8>]) -> Result<Vec<u64>, StoreError> {
        let id = self.head().id.clone();
        let seqs: Vec<i64> = sqlx::query_scalar(
            "SELECT seq FROM claim_entries WHERE account_id = $1 AND claim_key = ANY($2)",
        )
        .bind(id)
        .bind(claim_keys)
        .fetch_all(self.conn())
        .await
        .map_err(db)?;
        seqs.into_iter().map(|seq| from_db(seq, "seq")).collect()
    }

    /// Delete up to `bound` claims that may be deleted at `base_ms`, the time base, with
    /// their entries (Switch wire 7.3 step 4). Returns how many went.
    pub async fn delete_due_claims(
        &mut self,
        base_ms: u64,
        max_claim_age_ms: u64,
        bound: u64,
    ) -> Result<u64, StoreError> {
        let id = self.head().id.clone();
        // A last entry this long ago or more has aged out; none has before the epoch.
        let aged_before = base_ms
            .checked_sub(max_claim_age_ms)
            .map_or(Ok(-1), |at| to_db(at, "time"))?;
        // The entries' seqs are read in the same statement, from the snapshot before the
        // deletion cascades to them, so their documents go too (Switch wire 7.5).
        let row = sqlx::query(
            "WITH doomed AS (SELECT claim_key FROM claims WHERE account_id = $1 \
                 AND (delete_after_ms <= $2 OR delete_after_entry_ms <= $3) \
                 LIMIT $4), \
             entries AS (SELECT seq FROM claim_entries WHERE account_id = $1 \
                 AND claim_key IN (SELECT claim_key FROM doomed)), \
             gone AS (DELETE FROM claims WHERE account_id = $1 \
                 AND claim_key IN (SELECT claim_key FROM doomed) RETURNING claim_key) \
             SELECT (SELECT count(*) FROM gone) AS deleted, \
                 (SELECT coalesce(array_agg(seq), '{}') FROM entries) AS seqs",
        )
        .bind(&id)
        .bind(to_db(base_ms, "time")?)
        .bind(aged_before)
        .bind(to_db(bound, "bound")?)
        .fetch_one(self.conn())
        .await
        .map_err(db)?;
        let deleted = from_db(row.try_get("deleted")?, "deleted")?;
        let seqs: Vec<i64> = row.try_get("seqs")?;
        let seqs: Vec<u64> = seqs
            .into_iter()
            .map(|seq| from_db(seq, "seq"))
            .collect::<Result<_, _>>()?;
        self.note_superseded(seqs);
        if deleted > 0 {
            self.note_change();
        }
        Ok(deleted)
    }

    /// How many entries the claim at `claim_key` holds before `steps`, and the `seq` of the
    /// last of them.
    pub async fn claim_entry_tally(
        &mut self,
        claim_key: &[u8; 32],
        steps: u64,
    ) -> Result<(u64, Option<u64>), StoreError> {
        let id = self.head().id.clone();
        let (count, seq): (i64, Option<i64>) = sqlx::query_as(
            "SELECT count(*), (array_agg(seq ORDER BY step DESC))[1] FROM claim_entries \
             WHERE account_id = $1 AND claim_key = $2 AND step < $3",
        )
        .bind(id)
        .bind(claim_key.as_slice())
        .bind(to_db(steps, "steps")?)
        .fetch_one(self.conn())
        .await
        .map_err(db)?;
        Ok((
            from_db(count, "claim entries")?,
            seq.map(|seq| from_db(seq, "seq")).transpose()?,
        ))
    }

    /// Delete the claim at `claim_key`, with its entries, as step 4 would.
    pub async fn delete_claim(&mut self, claim_key: &[u8; 32]) -> Result<(), StoreError> {
        let entries = self.entry_seqs(&[claim_key.to_vec()]).await?;
        self.note_superseded(entries);
        let id = self.head().id.clone();
        sqlx::query("DELETE FROM claims WHERE account_id = $1 AND claim_key = $2")
            .bind(id)
            .bind(claim_key.as_slice())
            .execute(self.conn())
            .await
            .map_err(db)?;
        self.note_change();
        Ok(())
    }

    /// Keep `app_id` for good as removed for `reason`, revoked or departed, at `at_ms` and
    /// the newest document's `data_epoch`, a departure awaiting its rotation above it, and
    /// withdraw the invite codes it registered: a leave is treated exactly as a revocation
    /// (Switch spec 7, 12.2, 12.3; Switch wire 7.4.12, 9.1).
    pub async fn keep_removed(
        &mut self,
        app_id: &[u8; 16],
        reason: KeptReason,
        at_ms: u64,
        data_epoch: u64,
    ) -> Result<(), StoreError> {
        let reason = match reason {
            KeptReason::Revoked => "revoked",
            KeptReason::Departed => "departed",
            // An enrollment's App IDs are kept when it is taken, never removed here.
            KeptReason::Enrolled | KeptReason::Document => {
                return Err(StoreError::Corrupt("not a removal"));
            }
        };
        let id = self.head().id.clone();
        sqlx::query(
            "INSERT INTO kept_app_ids (account_id, app_id, reason, at_ms, data_epoch) \
             VALUES ($1, $2, $3, $4, $5)",
        )
        .bind(&id)
        .bind(app_id.as_slice())
        .bind(reason)
        .bind(to_db(at_ms, "time")?)
        .bind(to_db(data_epoch, "data_epoch")?)
        .execute(self.conn())
        .await
        .map_err(db)?;
        sqlx::query("DELETE FROM invite_codes WHERE account_id = $1 AND writer = $2")
            .bind(&id)
            .bind(app_id.as_slice())
            .execute(self.conn())
            .await
            .map_err(db)?;
        self.note_change();
        Ok(())
    }

    /// Keep a claim entry with its proof, unless its claim is a tombstone, which keeps no
    /// entries (Switch wire 7.4.8): the entry that compacts it, or one on it already.
    pub async fn add_claim_entry(
        &mut self,
        claim_key: &[u8; 32],
        entry: &StoredClaimEntry,
    ) -> Result<(), StoreError> {
        let id = self.head().id.clone();
        sqlx::query(
            "INSERT INTO claim_entries (account_id, claim_key, step, seq, op, proof) \
             SELECT $1, $2, $3, $4, $5, $6 WHERE NOT EXISTS (SELECT 1 FROM claims \
             WHERE account_id = $1 AND claim_key = $2 AND tombstone)",
        )
        .bind(id)
        .bind(claim_key.as_slice())
        .bind(to_db(entry.step, "step")?)
        .bind(to_db(entry.seq, "seq")?)
        .bind(encode_doc(&entry.op)?)
        .bind(encode_doc(&entry.proof)?)
        .execute(self.conn())
        .await
        .map_err(db)?;
        // The entry that settles a claim compacts it in the same request, whichever of the
        // two the batch stores first: its own document goes with the others then.
        self.note_superseded([entry.seq]);
        Ok(())
    }

    /// The invite codes at `code_hashes` that the account holds.
    pub async fn invites(
        &mut self,
        code_hashes: &[[u8; 32]],
    ) -> Result<Vec<StoredInvite>, StoreError> {
        let id = self.head().id.clone();
        let rows = sqlx::query(
            "SELECT code_hash, max_uses, uses, writer, expires_at_ms FROM invite_codes \
             WHERE account_id = $1 AND code_hash = ANY($2)",
        )
        .bind(id)
        .bind(keys(code_hashes))
        .fetch_all(self.conn())
        .await
        .map_err(db)?;
        rows.iter()
            .map(|row| {
                let hash: Vec<u8> = row.try_get("code_hash")?;
                let writer: Vec<u8> = row.try_get("writer")?;
                Ok(StoredInvite {
                    code_hash: array(&hash, "code_hash")?,
                    max_uses: from_db(row.try_get("max_uses")?, "max_uses")?,
                    uses: from_db(row.try_get("uses")?, "uses")?,
                    writer: array(&writer, "writer")?,
                    expires_at_ms: from_db(row.try_get("expires_at_ms")?, "expires_at_ms")?,
                })
            })
            .collect()
    }

    /// The registered expiry of a code with a remaining use (Switch wire 7.2).
    pub async fn unspent_invite_expiry(
        &mut self,
        code_hash: &[u8; 32],
    ) -> Result<Option<u64>, StoreError> {
        let id = self.head().id.clone();
        let expiry: Option<i64> = sqlx::query_scalar(
            "SELECT expires_at_ms FROM invite_codes WHERE account_id = $1 AND code_hash = $2 AND uses < max_uses",
        )
        .bind(id)
        .bind(code_hash.as_slice())
        .fetch_optional(self.conn())
        .await
        .map_err(db)?;
        expiry.map(|ms| from_db(ms, "expires_at_ms")).transpose()
    }

    /// Live invite codes, with uses left and unexpired at `now_ms`, not at `excluding`.
    pub async fn live_invites(
        &mut self,
        now_ms: u64,
        excluding: &[[u8; 32]],
    ) -> Result<u64, StoreError> {
        let id = self.head().id.clone();
        let count: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM invite_codes WHERE account_id = $1 AND uses < max_uses \
             AND expires_at_ms > $2 AND NOT (code_hash = ANY($3))",
        )
        .bind(id)
        .bind(to_db(now_ms, "time")?)
        .bind(keys(excluding))
        .fetch_one(self.conn())
        .await
        .map_err(db)?;
        from_db(count, "invite codes")
    }

    /// Store an invite code, replacing one at its hash.
    pub async fn put_invite(&mut self, invite: &StoredInvite) -> Result<(), StoreError> {
        let id = self.head().id.clone();
        sqlx::query(
            "INSERT INTO invite_codes (account_id, code_hash, max_uses, uses, writer, \
             expires_at_ms) VALUES ($1, $2, $3, $4, $5, $6) \
             ON CONFLICT (account_id, code_hash) DO UPDATE SET max_uses = $3, uses = $4, \
             writer = $5, expires_at_ms = $6",
        )
        .bind(id)
        .bind(invite.code_hash.as_slice())
        .bind(to_db(invite.max_uses, "max_uses")?)
        .bind(to_db(invite.uses, "uses")?)
        .bind(invite.writer.as_slice())
        .bind(to_db(invite.expires_at_ms, "expires_at_ms")?)
        .execute(self.conn())
        .await
        .map_err(db)?;
        Ok(())
    }

    /// Withdraw the invite code at `code_hash`.
    pub async fn delete_invite(&mut self, code_hash: &[u8; 32]) -> Result<(), StoreError> {
        let id = self.head().id.clone();
        sqlx::query("DELETE FROM invite_codes WHERE account_id = $1 AND code_hash = $2")
            .bind(id)
            .bind(code_hash.as_slice())
            .execute(self.conn())
            .await
            .map_err(db)?;
        Ok(())
    }

    /// The batch record the account holds for `batch_id`.
    pub async fn batch_record(
        &mut self,
        batch_id: &[u8; 16],
    ) -> Result<Option<BatchRecord>, StoreError> {
        let id = self.head().id.clone();
        let row = sqlx::query(
            "SELECT ops_hash, proofs, at_ms, first_seq, last_seq FROM batches \
             WHERE account_id = $1 AND batch_id = $2",
        )
        .bind(id)
        .bind(batch_id.as_slice())
        .fetch_optional(self.conn())
        .await
        .map_err(db)?;
        let Some(row) = row else {
            return Ok(None);
        };
        let hash: Vec<u8> = row.try_get("ops_hash")?;
        let proofs: Option<Vec<u8>> = row.try_get("proofs")?;
        Ok(Some(BatchRecord {
            ops_hash: array(&hash, "ops_hash")?,
            proofs: proofs
                .map(|bytes| {
                    serde_json::from_slice::<Vec<SignedDoc>>(&bytes)
                        .map_err(|_| StoreError::Corrupt("a batch's proofs"))
                })
                .transpose()?,
            at: from_db(row.try_get("at_ms")?, "at_ms")?,
            first_seq: from_db(row.try_get("first_seq")?, "first_seq")?,
            last_seq: from_db(row.try_get("last_seq")?, "last_seq")?,
        }))
    }

    /// Keep a batch record, for the account's current generation.
    pub async fn put_batch(
        &mut self,
        batch_id: &[u8; 16],
        record: &BatchRecord,
    ) -> Result<(), StoreError> {
        let head = self.head().clone();
        let proofs = record
            .proofs
            .as_ref()
            .map(|proofs| {
                serde_json::to_vec(proofs).map_err(|_| StoreError::Corrupt("proofs don't encode"))
            })
            .transpose()?;
        sqlx::query(
            "INSERT INTO batches (account_id, batch_id, ops_hash, proofs, at_ms, generation, \
             first_seq, last_seq) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
        )
        .bind(&head.id)
        .bind(batch_id.as_slice())
        .bind(record.ops_hash.as_slice())
        .bind(proofs)
        .bind(to_db(record.at, "at_ms")?)
        .bind(to_db(head.generation, "generation")?)
        .bind(to_db(record.first_seq, "first_seq")?)
        .bind(to_db(record.last_seq, "last_seq")?)
        .execute(self.conn())
        .await
        .map_err(db)?;
        Ok(())
    }
}

/// The columns [`record_of`] reads.
pub(super) const RECORD_COLUMNS: &str = "key, collection, read_scope, write_scopes, create_scope, delete_scope, permanent, \
     permanent_generation, generation, \
     version, deleted, value_bytes, writer, cert, op, proof, from_upload, upload_seq, \
     version_exact, proved_parent_hash, upload_base_generation, upload_base_version, upload_base_op_hash, \
     application_generation, application_seq, application_item_hash, \
     EXISTS (SELECT 1 FROM \
     divergent_uploads d WHERE d.account_id = shared_records.account_id \
     AND d.key = shared_records.key) AS divergent";

/// A stored policy's permanent member (Switch wire 6.2), from its two columns.
fn permanent_of(
    permanent: bool,
    generation: Option<i64>,
) -> Result<Option<pubky_switch_core::ident::Permanent>, StoreError> {
    match (permanent, generation) {
        (false, None) => Ok(None),
        (false, Some(_)) => Err(StoreError::Corrupt(
            "a permanent generation on an ordinary policy",
        )),
        (true, generation) => Ok(Some(pubky_switch_core::ident::Permanent {
            generation: generation
                .map(|g| from_db(g, "permanent_generation"))
                .transpose()?,
        })),
    }
}

pub(super) fn record_of(row: &sqlx::postgres::PgRow) -> Result<StoredRecord, StoreError> {
    let key: Vec<u8> = row.try_get("key")?;
    let collection: Vec<u8> = row.try_get("collection")?;
    let writer: Vec<u8> = row.try_get("writer")?;
    let cert: Vec<u8> = row.try_get("cert")?;
    let op: Vec<u8> = row.try_get("op")?;
    let proof: Option<Vec<u8>> = row.try_get("proof")?;
    let origin = if row.try_get("from_upload")? {
        let seq: Option<i64> = row.try_get("upload_seq")?;
        RecordOrigin::Uploaded {
            seq: from_db(
                seq.ok_or(StoreError::Corrupt("an uploaded record without its seq"))?,
                "upload_seq",
            )?,
            exact: row.try_get("version_exact")?,
            parent: row
                .try_get::<Option<Vec<u8>>, _>("proved_parent_hash")?
                .map(|hash| array(&hash, "proved parent hash"))
                .transpose()?,
        }
    } else {
        let proof = proof.ok_or(StoreError::Corrupt("a record write without its proof"))?;
        let generation: Option<i64> = row.try_get("upload_base_generation")?;
        let version: Option<i64> = row.try_get("upload_base_version")?;
        let hash: Option<Vec<u8>> = row.try_get("upload_base_op_hash")?;
        let upload_base = match (generation, version, hash) {
            (Some(g), Some(v), Some(hash)) => Some(UploadBase {
                version: pubky_switch_core::ops::RecordVersion::new(
                    from_db(g, "upload_base_generation")?,
                    from_db(v, "upload_base_version")?,
                ),
                op_hash: array(&hash, "upload_base_op_hash")?,
            }),
            (None, None, None) => None,
            _ => return Err(StoreError::Corrupt("part of an upload base")),
        };
        RecordOrigin::Written {
            proof: decode_doc(&proof, "record proof")?,
            upload_base,
        }
    };
    let record = StoredRecord {
        state: RecordState {
            key: array(&key, "record key")?,
            collection: array(&collection, "collection")?,
            policy: Policy {
                read_scope: row.try_get("read_scope")?,
                write_scopes: row.try_get("write_scopes")?,
                create_scope: row.try_get("create_scope")?,
                delete_scope: row.try_get("delete_scope")?,
                permanent: permanent_of(
                    row.try_get("permanent")?,
                    row.try_get("permanent_generation")?,
                )?,
            },
            version: pubky_switch_core::ops::RecordVersion::new(
                from_db(row.try_get("generation")?, "generation")?,
                from_db(row.try_get("version")?, "version")?,
            ),
            deleted: row.try_get("deleted")?,
        },
        value_bytes: from_db(row.try_get("value_bytes")?, "value_bytes")?,
        revision: ApplicationRef {
            generation: from_db(
                row.try_get("application_generation")?,
                "application_generation",
            )?,
            seq: from_db(row.try_get("application_seq")?, "application_seq")?,
            item_hash: array(
                &row.try_get::<Vec<u8>, _>("application_item_hash")?,
                "application_item_hash",
            )?,
        },
        writer: array(&writer, "writer")?,
        cert: decode_doc(&cert, "record cert")?,
        op: decode_doc(&op, "record op")?,
        origin,
        divergent: row.try_get("divergent")?,
    };
    record.check_revision()?;
    Ok(record)
}

/// The first `steps` entries of a claim, by step (Switch wire 7.4.8).
pub(super) async fn claim_entries_before(
    pool: &sqlx::PgPool,
    id: &str,
    claim_key: &[u8; 32],
    steps: u64,
) -> Result<Vec<StoredClaimEntry>, StoreError> {
    let rows = sqlx::query(
        "SELECT step, seq, op, proof FROM claim_entries \
         WHERE account_id = $1 AND claim_key = $2 AND step < $3 ORDER BY step",
    )
    .bind(id)
    .bind(claim_key.as_slice())
    .bind(to_db(steps, "steps")?)
    .fetch_all(pool)
    .await
    .map_err(db)?;
    rows.iter()
        .map(|row| {
            let op: Vec<u8> = row.try_get("op")?;
            let proof: Vec<u8> = row.try_get("proof")?;
            Ok(StoredClaimEntry {
                step: from_db(row.try_get("step")?, "step")?,
                seq: from_db(row.try_get("seq")?, "seq")?,
                op: decode_doc(&op, "claim entry")?,
                proof: decode_doc(&proof, "claim entry proof")?,
            })
        })
        .collect()
}

/// An `apps` row as a [`StoredApp`].
fn app_of(row: &sqlx::postgres::PgRow) -> Result<StoredApp, StoreError> {
    let app_id: Vec<u8> = row.try_get("app_id")?;
    let cursor = match (
        opt_u64(row.try_get("cursor_generation")?, "cursor_generation")?,
        opt_u64(row.try_get("cursor_seq")?, "cursor_seq")?,
    ) {
        (Some(generation), Some(seq)) => Some(Position { generation, seq }),
        (None, None) => None,
        _ => return Err(StoreError::Corrupt("an app's cursor")),
    };
    Ok(StoredApp {
        app_id: array(&app_id, "app_id")?,
        record: opt_doc(row.try_get("record")?, "app record")?,
        record_at_ms: opt_u64(row.try_get("record_at_ms")?, "record_at_ms")?,
        renewed_cert: opt_doc(row.try_get("renewed_cert")?, "renewed cert")?,
        receive_key: opt_doc(row.try_get("receive_key")?, "receive key")?,
        cursor,
        reachable_since: opt_u64(row.try_get("reachable_since")?, "reachable_since")?,
        full_requested_ms: opt_u64(row.try_get("full_requested_ms")?, "full_requested_ms")?,
        full_completed_seq: opt_u64(row.try_get("full_completed_seq")?, "full_completed_seq")?,
    })
}

/// What an own app's checks before the lock read (Switch wire 7.2 Order), in one statement
/// so they see one state: the account's newest `identity.json`, the app's row, and whether
/// its App ID is kept for good. `None` for an account that isn't there.
pub(super) async fn own_app_view(
    pool: &sqlx::PgPool,
    id: &str,
    app_id: &[u8; 16],
) -> Result<Option<(Option<SignedDoc>, Option<StoredApp>, bool)>, StoreError> {
    let row = sqlx::query(
        "SELECT a.identity_doc, p.app_id, p.record, p.record_at_ms, p.renewed_cert, \
         p.receive_key, p.cursor_generation, p.cursor_seq, p.reachable_since, \
         p.full_requested_ms, p.full_completed_seq, EXISTS (SELECT 1 FROM kept_app_ids k \
         WHERE k.account_id = a.id AND k.app_id = $2) AS kept \
         FROM accounts a LEFT JOIN apps p ON p.account_id = a.id AND p.app_id = $2 \
         WHERE a.id = $1",
    )
    .bind(id)
    .bind(app_id.as_slice())
    .fetch_optional(pool)
    .await
    .map_err(db)?;
    let Some(row) = row else {
        return Ok(None);
    };
    let doc = opt_doc(row.try_get("identity_doc")?, "identity_doc")?;
    let app: Option<Vec<u8>> = row.try_get("app_id")?;
    let app = app.map(|_| app_of(&row)).transpose()?;
    Ok(Some((doc, app, row.try_get("kept")?)))
}

/// The `apps` row of `app_id` at account `id`, read without the account's lock.
pub(super) async fn app_row<'c>(
    conn: impl sqlx::PgExecutor<'c>,
    id: &str,
    app_id: &[u8; 16],
) -> Result<Option<StoredApp>, StoreError> {
    let row = sqlx::query(
        "SELECT app_id, record, record_at_ms, renewed_cert, receive_key, cursor_generation, \
         cursor_seq, reachable_since, full_requested_ms, full_completed_seq FROM apps \
         WHERE account_id = $1 AND app_id = $2",
    )
    .bind(id)
    .bind(app_id.as_slice())
    .fetch_optional(conn)
    .await
    .map_err(db)?;
    row.as_ref().map(app_of).transpose()
}
