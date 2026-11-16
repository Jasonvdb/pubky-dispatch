use serde_json::Value;

use super::{ApplicationRef, LineageDescriptor, bytes32, integer, member, members, positive, text};
use crate::chain::SignedHead;
use crate::enc::{b64, pubky_id, pubky_key};
use crate::error::{Result, SizeRefusal, invalid};
use crate::json::{MAX_INT, parse_json};
use crate::labels;
use crate::ops::body::Obj;
use crate::ops::carrying_len;
use crate::records::IdentityDoc;
use crate::sig::SignedDoc;
use crate::signing::Signs;
use crate::time::{MAX_TIME_MS, parse_rfc3339, rfc3339};

/// Maximum compact lineage statement carrying bytes for protected forms (record origins 6).
pub const MAX_PROTECTED_LINEAGE_STATEMENT_BYTES: usize = 4_096;

/// The current lineage statement body (Switch record lineage 3).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LineageStatementBody {
    /// Account identity.
    pub identity: [u8; 32],
    /// This service account's creation time, in Unix milliseconds.
    pub created: u64,
    /// Hash of the held identity document.
    pub identity_hash: [u8; 32],
    /// Generation of the authenticated snapshot.
    pub generation: u64,
    /// Sequence of the snapshot head.
    pub seq: u64,
    /// Chain hash of that head.
    pub chain_hash: [u8; 32],
    /// The record key.
    pub key: [u8; 32],
    /// The record's retained lineage identifier.
    pub lineage_id: [u8; 32],
    /// The current application reference.
    pub current: ApplicationRef,
    /// Hash of the exact descriptor bytes.
    pub descriptor_hash: [u8; 32],
}

impl LineageStatementBody {
    /// Encode compact statement body bytes (Switch record lineage 3).
    ///
    /// # Errors
    ///
    /// [`crate::Error::Invalid`] for out-of-range integers, references or account creation time.
    pub fn to_json(&self) -> Result<Vec<u8>> {
        positive(self.generation)?;
        if self.seq > MAX_INT || self.created > MAX_TIME_MS {
            return invalid("Switch record lineage 3: invalid statement sequence or time");
        }
        let mut out = Obj::new();
        out.int("v", 1)
            .str("kind", "pubky-switch.record_lineage")
            .str("identity", &pubky_id(&self.identity))
            .str("created", &rfc3339(self.created))
            .str("identity_hash", &b64(&self.identity_hash))
            .int("generation", self.generation)
            .int("seq", self.seq)
            .str("chain_hash", &b64(&self.chain_hash))
            .str("key", &b64(&self.key))
            .str("lineage_id", &b64(&self.lineage_id))
            .raw("current", &self.current.to_json()?)
            .str("descriptor_hash", &b64(&self.descriptor_hash));
        Ok(out.finish())
    }

    fn read(bytes: &[u8]) -> Result<Self> {
        let value: Value = parse_json(bytes)?;
        members(
            &value,
            &[
                "v",
                "kind",
                "identity",
                "created",
                "identity_hash",
                "generation",
                "seq",
                "chain_hash",
                "key",
                "lineage_id",
                "current",
                "descriptor_hash",
            ],
        )?;
        if integer(member(&value, "v")?)? != 1
            || text(member(&value, "kind")?)? != "pubky-switch.record_lineage"
        {
            return invalid("Switch record lineage 3: invalid statement tag");
        }
        let body = Self {
            identity: pubky_key(text(member(&value, "identity")?)?)?,
            created: parse_rfc3339(text(member(&value, "created")?)?)?,
            identity_hash: bytes32(member(&value, "identity_hash")?)?,
            generation: integer(member(&value, "generation")?)?,
            seq: integer(member(&value, "seq")?)?,
            chain_hash: bytes32(member(&value, "chain_hash")?)?,
            key: bytes32(member(&value, "key")?)?,
            lineage_id: bytes32(member(&value, "lineage_id")?)?,
            current: ApplicationRef::read(member(&value, "current")?)?,
            descriptor_hash: bytes32(member(&value, "descriptor_hash")?)?,
        };
        body.to_json()?;
        Ok(body)
    }
}

/// A parsed lineage statement preserving its exact signed bytes (record lineage 3).
/// Parsing does not authenticate the statement or establish record authority.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LineageStatement {
    body: LineageStatementBody,
    signed: SignedDoc,
}

impl LineageStatement {
    /// Parse the signed document, checking its signature encoding and strict body shape.
    ///
    /// No signature verification is performed. Protected callers additionally use
    /// [`Self::check_protected_size`]; ordinary callers enforce enclosing view/part bounds.
    ///
    /// # Errors
    ///
    /// [`crate::Error::Invalid`] for malformed encodings or statement fields.
    pub fn parse(signed: &SignedDoc) -> Result<Self> {
        signed.sig_bytes()?;
        let body = LineageStatementBody::read(&signed.body_bytes()?)?;
        Ok(Self {
            body,
            signed: signed.clone(),
        })
    }

    /// Parse an exact signed-document carrying object, rejecting extra or absent members.
    ///
    /// # Errors
    ///
    /// [`crate::Error::Invalid`] for malformed JSON, wrapper or statement fields.
    pub fn from_json(bytes: &[u8]) -> Result<Self> {
        let value: Value = parse_json(bytes)?;
        members(&value, &["body", "sig"])?;
        Self::parse(&SignedDoc {
            body: text(member(&value, "body")?)?.to_owned(),
            sig: text(member(&value, "sig")?)?.to_owned(),
        })
    }

    /// Encode compact carrying JSON without altering the signed body or signature.
    pub fn to_json(&self) -> Vec<u8> {
        let mut out = Obj::new();
        out.str("body", &self.signed.body)
            .str("sig", &self.signed.sig);
        out.finish()
    }

    /// Sign the supplied metadata under the lineage statement label.
    ///
    /// The caller must establish durable snapshot and account authority first (wire 7.3).
    /// Signing alone establishes neither that authority nor complete reader authority.
    ///
    /// # Errors
    ///
    /// [`crate::Error::Invalid`] for invalid body fields.
    pub fn sign(key: &impl Signs, body: LineageStatementBody) -> Result<Self> {
        let bytes = body.to_json()?;
        let signature = key.sign_fields(
            labels::sig::RECORD_LINEAGE_STATEMENT,
            &[&body.identity, &bytes],
        );
        Ok(Self {
            body,
            signed: SignedDoc::from_parts(&bytes, &signature),
        })
    }

    /// Parsed metadata without a freshness or authority assertion.
    pub fn body(&self) -> &LineageStatementBody {
        &self.body
    }

    /// The unchanged signed document.
    pub fn signed(&self) -> &SignedDoc {
        &self.signed
    }

    /// Authenticate with the supplied identity document's current service key.
    ///
    /// The caller revalidates the document. This checks identity, document hash and
    /// generation, not request freshness, certificate standing, permissions or continuity.
    ///
    /// # Errors
    ///
    /// [`crate::Error::Signature`] for an invalid signature; [`crate::Error::Invalid`] for a binding mismatch.
    pub fn verify_signature(&self, identity: &IdentityDoc) -> Result<()> {
        if self.body.identity != identity.identity()
            || self.body.identity_hash != identity.hash()
            || self.body.generation != identity.generation()
        {
            return invalid("Switch record lineage 3: statement identity or generation mismatch");
        }
        self.signed.verify(
            &identity.inbox().service_key,
            labels::sig::RECORD_LINEAGE_STATEMENT,
            &[&identity.identity()],
        )?;
        Ok(())
    }

    /// Authenticate and associate metadata with a supplied snapshot and descriptor.
    ///
    /// The caller supplies the actual authenticated request/response head, revalidated
    /// identity document and account creation time (record lineage 4). A matching cached
    /// snapshot also passes; this does not establish currentness. Node hashes, operations,
    /// certificates, record-view agreement, continuity and recovery checks remain separate.
    ///
    /// # Errors
    ///
    /// [`crate::Error::Signature`] for an invalid head or statement signature; [`crate::Error::Invalid`]
    /// for any snapshot, requested key or descriptor association mismatch.
    pub fn check_snapshot(
        &self,
        identity: &IdentityDoc,
        created: u64,
        head: &SignedHead,
        requested_key: &[u8; 32],
        descriptor: &LineageDescriptor,
    ) -> Result<()> {
        self.verify_signature(identity)?;
        head.verify(&identity.inbox().service_key, &identity.identity())?;
        if self.body.created != created
            || self.body.generation != head.generation
            || self.body.seq != head.seq
            || self.body.chain_hash != head.chain_hash
            || &self.body.key != requested_key
            || self.body.key != descriptor.body().key
            || self.body.lineage_id != descriptor.body().lineage_id
            || self.body.current != descriptor.body().current.reference
            || self.body.descriptor_hash != descriptor.hash()
        {
            return invalid("Switch record lineage 3: statement snapshot or descriptor mismatch");
        }
        Ok(())
    }

    /// Check protected-form carrying size and base64/signature encodings, without normalization.
    ///
    /// # Errors
    ///
    /// [`SizeRefusal::TooLarge`] above 4,096 compact carrying bytes;
    /// [`SizeRefusal::BadRequest`] for malformed base64url or signature length. A caller maps
    /// write size excess to 413 and import excess to 400 (record origins 6).
    pub fn check_protected_size(signed: &SignedDoc) -> std::result::Result<(), SizeRefusal> {
        if carrying_len(&signed.body, &signed.sig) > MAX_PROTECTED_LINEAGE_STATEMENT_BYTES {
            return Err(SizeRefusal::TooLarge(
                "Switch record origins 6: lineage statement exceeds 4096 bytes".into(),
            ));
        }
        signed
            .body_bytes()
            .map_err(|e| SizeRefusal::BadRequest(e.to_string()))?;
        signed
            .sig_bytes()
            .map_err(|e| SizeRefusal::BadRequest(e.to_string()))?;
        Ok(())
    }
}
