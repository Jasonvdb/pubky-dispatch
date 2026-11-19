//! The local inputs and checked answer of the ordinary loss upload (Switch spec 12.6 step 3).

use pubky_switch_core::chain::{ItemType, ServiceTransition, SignedHead, TransitionProof};
use pubky_switch_core::enc::{b64, hash};
use pubky_switch_core::http::ErrorCode;
use pubky_switch_core::records::IdentityDoc;
use pubky_switch_core::recovery::UploadBody;
use pubky_switch_core::sig::SignedDoc;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::{App, AppError, LossRecord, corrupt, keys};
use crate::client::answers::{UploadAnswer, UploadChanges};
use crate::client::read::Obj;

/// A retained claim entry the evidence step could not include with a verifying certificate.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OmittedClaimEntry {
    /// The retained signed entry.
    pub op: SignedDoc,
    /// The proof held with it.
    pub proof: SignedDoc,
}

impl std::fmt::Debug for OmittedClaimEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("OmittedClaimEntry")
    }
}

/// A protocol-local continuity checkpoint read on either side of an inventory scan.
/// The protocol maintains its checkpoint atomically with the protective work it covers.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LossCheckpoint {
    /// The registered protocol.
    pub protocol: String,
    /// The checkpoint key in that protocol's local store.
    pub key: Vec<u8>,
    /// Hash of the checkpoint before enumeration, if held.
    pub before: Option<[u8; 32]>,
    /// Hash of the checkpoint after enumeration, if held.
    pub after: Option<[u8; 32]>,
}

/// Record applications and omissions from the pass that collected the signed upload.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct LossInventoryDetails {
    /// The checkpoints the host registered for this scan. A missing or changed checkpoint cannot establish a stable cutoff.
    pub checkpoints: Vec<LossCheckpoint>,
    /// The retained and followed applications, including deletes whose content was refused.
    pub records: Vec<crate::app::LossRecordApplication>,
    /// Entries that lacked a verifying writer certificate.
    pub omitted: Vec<OmittedClaimEntry>,
}

/// The observed result for one exact set of evidence (Switch wire 7.4.14).
#[derive(Clone, Debug, PartialEq)]
#[non_exhaustive]
pub enum LossUploadOutcome {
    /// No qualifying authenticated answer has been kept, including after an interrupted send.
    Pending,
    /// No record, claim, proof or head was available to send. The omission list still applies.
    NoRequest,
    /// The submitted body exceeded the request size limit, before sending.
    TooLarge,
    /// The service returned this final authenticated refusal.
    Refused(ErrorCode),
    /// The pinned service's checked response to these bytes. The signed transition describes
    /// its changes. Each input's actual effect still requires verification.
    Answered {
        /// The head at the upload transition.
        head: SignedHead,
        /// Its proof, including the uploader and the service's changes.
        proof: Box<TransitionProof>,
    },
}

/// A locally recorded loss evidence step. The inputs include heads and evidence of every
/// protocol. Inventory continuity, local protective work and decisions about successor
/// values belong to the calling protocol (Switch spec 12.6).
#[derive(Clone, Debug, PartialEq)]
pub struct LossUpload {
    /// The account.
    pub identity: [u8; 32],
    /// The submitting installation's App ID.
    pub app_id: [u8; 16],
    /// The loss the current identity document declares.
    pub recovery_from: u64,
    /// The generation at which the app ran the step.
    pub generation: u64,
    /// Its pinned service key.
    pub service_key: [u8; 32],
    /// Hash of the signed opening identity when available at capture.
    /// Compare the full loss context with the verified opening roster before using the result.
    pub opening_hash: Option<[u8; 32]>,
    /// Hash of the exact request body, or of the enumerated upload when no request was needed.
    pub body_hash: [u8; 32],
    /// Hash of the record applications and omitted entries from the same pass.
    pub details_hash: [u8; 32],
    /// The outcome observed for these inputs. It grants no disposition to individual items.
    pub outcome: LossUploadOutcome,
}

#[derive(Clone, Copy, Serialize, Deserialize)]
struct Blob {
    hash: [u8; 32],
    size: usize,
}

impl Blob {
    fn of(bytes: &[u8]) -> Self {
        Self {
            hash: hash(bytes),
            size: bytes.len(),
        }
    }

    fn chunks(self) -> usize {
        self.size.div_ceil(CHUNK)
    }

    fn key(self, generation: u64, part: usize) -> String {
        format!("loss-data/{generation}/{}/{part}", b64(&self.hash))
    }
}

// Small enough that each exact byte slice and the app's normal commit metadata fit in a
// store transaction. A refused oversized body is retained by the same path.
const CHUNK: usize = 1024 * 1024;

#[derive(Serialize, Deserialize)]
pub(super) struct Attempt {
    identity: [u8; 32],
    app_id: [u8; 16],
    generation: u64,
    recovery_from: u64,
    service_key: [u8; 32],
    opening_hash: Option<[u8; 32]>,
    body: Blob,
    omitted: Blob,
    outcome: StoredOutcome,
}

#[derive(Serialize, Deserialize)]
enum StoredOutcome {
    Pending,
    NoRequest,
    TooLarge,
    Refused(String),
    Answered { head: Value, proof: SignedDoc },
}

impl Attempt {
    fn key(&self) -> String {
        format!(
            "loss-upload/{}/{}/{}",
            self.generation,
            b64(&self.body.hash),
            b64(&self.omitted.hash)
        )
    }

    fn matches_proof(&self, head: &SignedHead, proof: &TransitionProof) -> bool {
        let env = proof.envelope();
        matches!(ServiceTransition::from_value(&proof.body().state),
            Ok(ServiceTransition::Upload { by, at, .. }) if by == self.app_id && at == env.server_time)
            && head.generation == self.generation
            && env.generation == self.generation
            && env.item_type == ItemType::Service
            && proof.body().object == "upload"
            && env.seq == head.seq
            && proof.body().chain.chain_hash == head.chain_hash
    }

    fn outcome(&self) -> Result<LossUploadOutcome, AppError> {
        Ok(match &self.outcome {
            StoredOutcome::Pending => LossUploadOutcome::Pending,
            StoredOutcome::NoRequest => LossUploadOutcome::NoRequest,
            StoredOutcome::TooLarge => LossUploadOutcome::TooLarge,
            StoredOutcome::Refused(code) => {
                LossUploadOutcome::Refused(ErrorCode::parse(code).ok_or_else(corrupt)?)
            }
            StoredOutcome::Answered { head, proof } => {
                let head = SignedHead::from_value(head)?;
                head.verify(&self.service_key, &self.identity)?;
                let proof = TransitionProof::verify(proof, &self.service_key, &self.identity)?;
                if !self.matches_proof(&head, &proof) {
                    return Err(corrupt());
                }
                LossUploadOutcome::Answered {
                    head,
                    proof: Box::new(proof),
                }
            }
        })
    }
}

pub(super) enum UploadReply {
    Answered(Box<UploadAnswer>),
    Refused(ErrorCode),
    TooLarge,
}

impl App {
    /// Start keeping the exact inputs and checked answer of future ordinary loss evidence
    /// steps for this installation (Switch spec 12.6). This preference survives reload.
    /// Call before following a loss. An earlier step cannot be reconstructed by enabling it
    /// later. The protocol supplies its own continuity checkpoint and outstanding duties.
    ///
    /// # Errors
    ///
    /// A failed store read or commit.
    pub async fn retain_loss_uploads(&mut self) -> Result<(), AppError> {
        self.ready_local().await?;
        if self.reader().get::<bool>("retain-loss-uploads").await? == Some(true) {
            return Ok(());
        }
        let mut tx = self.tx()?;
        tx.put("retain-loss-uploads", &true)?;
        self.commit(tx).await
    }

    /// Capture a protocol-local checkpoint with future loss uploads. The protocol commits
    /// a unique new checkpoint with each material change to its duties, including restore.
    /// The app hashes its value before and after enumeration. The protocol verifies the
    /// checkpoint's continuity, accounts for later work and supplies its own declaration.
    ///
    /// # Errors
    ///
    /// An unregistered protocol, or a store failure.
    pub async fn retain_loss_uploads_for(
        &mut self,
        protocol: &str,
        key: &[u8],
    ) -> Result<(), AppError> {
        self.ready_local().await?;
        self.check_registered(protocol)?;
        let mut tx = self.tx()?;
        tx.put(&format!("loss-checkpoint/{protocol}"), &key)?;
        tx.put("retain-loss-uploads", &true)?;
        self.commit(tx).await
    }

    pub(super) async fn loss_checkpoints(&self) -> Result<Vec<LossCheckpoint>, AppError> {
        let mut checkpoints = Vec::new();
        for (protocol, key) in self.reader().scan::<Vec<u8>>("loss-checkpoint/").await? {
            let before = self.checkpoint_hash(&protocol, &key).await?;
            checkpoints.push(LossCheckpoint {
                protocol,
                key,
                before,
                after: None,
            });
        }
        Ok(checkpoints)
    }

    pub(super) async fn checkpoint_hash(
        &self,
        protocol: &str,
        key: &[u8],
    ) -> Result<Option<[u8; 32]>, AppError> {
        if !self.protocols.contains(protocol) {
            return Ok(None);
        }
        Ok(self.protocol_get(protocol, key).await?.as_deref().map(hash))
    }

    /// Discard this installation's observations for one generation once its protocols
    /// have durably accounted for all their duties. This also discards the exact inputs.
    /// Other generations and future capture are independent (Switch spec 12.6).
    ///
    /// # Errors
    ///
    /// A failed store read or commit.
    pub async fn forget_loss_uploads(&mut self, generation: u64) -> Result<(), AppError> {
        self.ready_local().await?;
        let mut tx = self.tx()?;
        tx.delete_prefix(&format!("loss-upload/{generation}/"))?;
        tx.delete_prefix(&format!("loss-data/{generation}/"))?;
        self.commit(tx).await
    }

    async fn keep_loss_bytes(
        &mut self,
        generation: u64,
        blob: Blob,
        bytes: &[u8],
    ) -> Result<(), AppError> {
        for (part, chunk) in bytes.chunks(CHUNK).enumerate() {
            let key = blob.key(generation, part);
            if !self.reader().exists(&key).await? {
                let mut tx = self.tx()?;
                tx.put_raw(&key, chunk.to_vec())?;
                self.commit(tx).await?;
            }
        }
        Ok(())
    }

    async fn loss_bytes(&self, generation: u64, blob: Blob) -> Result<Vec<u8>, AppError> {
        let mut bytes = Vec::new();
        for part in 0..blob.chunks() {
            let key = blob.key(generation, part);
            let chunk = self
                .reader()
                .get_raw(key.as_bytes())
                .await?
                .ok_or_else(corrupt)?;
            if chunk.len() != CHUNK.min(blob.size - bytes.len()) {
                return Err(corrupt());
            }
            bytes.extend_from_slice(&chunk);
        }
        if hash(&bytes) != blob.hash {
            return Err(corrupt());
        }
        Ok(bytes)
    }

    pub(super) async fn keep_loss_inputs(
        &mut self,
        loss: &LossRecord,
        bytes: &[u8],
        omitted: &LossInventoryDetails,
        send: bool,
    ) -> Result<Attempt, AppError> {
        let detail_bytes = serde_json::to_vec(omitted).map_err(|_| corrupt())?;
        let body = Blob::of(bytes);
        let omitted = Blob::of(&detail_bytes);
        let opening = self.reader().get::<SignedDoc>(keys::OPENING).await?;
        let mut entry = Attempt {
            identity: self.identity(),
            app_id: self.app_id(),
            generation: loss.generation,
            recovery_from: self
                .state
                .own_doc
                .body()
                .recovery_from
                .ok_or_else(corrupt)?,
            service_key: self.state.meta.service_key,
            opening_hash: opening
                .as_ref()
                .map(|signed| IdentityDoc::verify(signed, &self.identity()).map(|doc| doc.hash()))
                .transpose()?,
            body,
            omitted,
            outcome: StoredOutcome::Pending,
        };
        let key = entry.key();
        if let Some(prior) = self.reader().get::<Attempt>(&key).await? {
            if prior.identity != entry.identity
                || prior.app_id != entry.app_id
                || prior.recovery_from != entry.recovery_from
                || prior.service_key != entry.service_key
                || prior.key() != key
            {
                return Err(corrupt());
            }
            entry = prior;
            // A retry can land even when the service refused an earlier send of the same body.
            if send
                && matches!(
                    entry.outcome,
                    StoredOutcome::Refused(_) | StoredOutcome::TooLarge
                )
            {
                entry.outcome = StoredOutcome::Pending;
                let mut tx = self.tx()?;
                tx.put(&key, &entry)?;
                self.commit(tx).await?;
            }
        } else {
            // An interrupted capture remains visible even if the next pass sees fewer items.
            let mut tx = self.tx()?;
            tx.put(&key, &entry)?;
            self.commit(tx).await?;
        }
        self.keep_loss_bytes(loss.generation, body, bytes).await?;
        self.keep_loss_bytes(loss.generation, omitted, &detail_bytes)
            .await?;
        if !send && matches!(entry.outcome, StoredOutcome::Pending) {
            entry.outcome = StoredOutcome::NoRequest;
            let mut tx = self.tx()?;
            tx.put(&key, &entry)?;
            self.commit(tx).await?;
        }
        Ok(entry)
    }

    pub(super) async fn keep_loss_answer(
        &mut self,
        mut entry: Attempt,
        reply: UploadReply,
    ) -> Result<(), AppError> {
        if matches!(entry.outcome, StoredOutcome::Answered { .. }) {
            return Ok(());
        }
        entry.outcome = match reply {
            UploadReply::TooLarge => StoredOutcome::TooLarge,
            UploadReply::Refused(code) => StoredOutcome::Refused(code.as_str().to_owned()),
            UploadReply::Answered(answer) => {
                let (Some(head), Some(proof), Some(result)) =
                    (answer.head, answer.proof, answer.result)
                else {
                    return Ok(());
                };
                let Some(changes) = proof.body().state.get("changes") else {
                    return Ok(());
                };
                if !entry.matches_proof(&head, &proof)
                    || Obj::of(changes, "Switch wire 7.4.14: upload changes")
                        .and_then(UploadChanges::read)
                        .ok()
                        .as_ref()
                        != Some(&result)
                {
                    return Ok(());
                }
                StoredOutcome::Answered {
                    head: head.to_value(),
                    proof: proof.signed().clone(),
                }
            }
        };
        let mut tx = self.tx()?;
        tx.put(&entry.key(), &entry)?;
        self.commit(tx).await
    }

    /// The distinct inputs this app retained before its ordinary evidence step in the
    /// given generation, including interrupted attempts (Switch spec 12.6 step 3).
    /// Older installations can have no observations. An empty result establishes no
    /// inventory or continuity. A later loss leaves earlier observations available.
    ///
    /// # Errors
    ///
    /// A failed read or invalid retained evidence.
    pub async fn loss_uploads(&self, generation: u64) -> Result<Vec<LossUpload>, AppError> {
        let prefix = format!("loss-upload/{generation}/");
        self.reader()
            .scan::<Attempt>(&prefix)
            .await?
            .into_iter()
            .map(|(suffix, entry)| {
                if entry.identity != self.identity()
                    || entry.app_id != self.app_id()
                    || entry.generation != generation
                    || entry.key() != format!("{prefix}{suffix}")
                {
                    return Err(corrupt());
                }
                Ok(LossUpload {
                    identity: entry.identity,
                    app_id: entry.app_id,
                    recovery_from: entry.recovery_from,
                    generation,
                    service_key: entry.service_key,
                    opening_hash: entry.opening_hash,
                    body_hash: entry.body.hash,
                    details_hash: entry.omitted.hash,
                    outcome: entry.outcome()?,
                })
            })
            .collect()
    }

    /// The exact records, claims, heads and proofs enumerated for this observation, and
    /// the signed entries whose verifying certificates were unavailable in that pass.
    /// Earlier inputs remain readable after local evidence is retired (Switch spec 12.6).
    ///
    /// # Errors
    ///
    /// The observation is unavailable in this store, or its retained bytes fail verification.
    pub async fn loss_upload_inputs(
        &self,
        upload: &LossUpload,
    ) -> Result<(UploadBody, LossInventoryDetails), AppError> {
        let key = format!(
            "loss-upload/{}/{}/{}",
            upload.generation,
            b64(&upload.body_hash),
            b64(&upload.details_hash)
        );
        let entry = self
            .reader()
            .get::<Attempt>(&key)
            .await?
            .ok_or_else(corrupt)?;
        if entry.key() != key
            || entry.identity != self.identity()
            || entry.app_id != self.app_id()
            || entry.identity != upload.identity
            || entry.app_id != upload.app_id
            || entry.service_key != upload.service_key
            || entry.recovery_from != upload.recovery_from
            || entry.opening_hash != upload.opening_hash
        {
            return Err(corrupt());
        }
        let body = UploadBody::parse(&self.loss_bytes(entry.generation, entry.body).await?)
            .map_err(|_| corrupt())?;
        let omitted =
            serde_json::from_slice(&self.loss_bytes(entry.generation, entry.omitted).await?)
                .map_err(|_| corrupt())?;
        Ok((body, omitted))
    }
}
