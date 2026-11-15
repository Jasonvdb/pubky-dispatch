use serde_json::Value;

use super::{OriginSlot, bytes32, integer, member, members, positive, text};
use crate::chain::SignedHead;
use crate::enc::{b64, pubky_id, pubky_key, unb64};
use crate::error::{Error, Result, SizeRefusal, invalid};
use crate::json::{MAX_INT, parse_json};
use crate::labels;
use crate::ops::body::Obj;
use crate::ops::carrying_len;
use crate::records::IdentityDoc;
use crate::sig::SignedDoc;
use crate::signing::Signs;
use crate::time::{MAX_TIME_MS, parse_rfc3339, rfc3339};

/// Maximum compact signed origin statement carrying bytes (Switch record origins 6).
pub const MAX_ORIGIN_STATEMENT_BYTES: usize = 1_024;
/// Maximum compact origin object carrying bytes (Switch record origins 6).
pub const MAX_ORIGIN_OBJECT_BYTES: usize = 2_048;

/// The exact current origin statement body (Switch record origins 5).
///
/// These fields are data, not an assertion that the supplied snapshot is current.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OriginStatementBody {
    /// Account identity.
    pub identity: [u8; 32],
    /// Creation time of this service account, in Unix milliseconds.
    pub created: u64,
    /// Document hash of the held signed identity document.
    pub identity_hash: [u8; 32],
    /// Generation of the authenticated snapshot.
    pub generation: u64,
    /// Sequence of the authenticated snapshot head.
    pub seq: u64,
    /// Chain hash of that head.
    pub chain_hash: [u8; 32],
    /// Requested parent or child key.
    pub key: [u8; 32],
    /// Parent origin key.
    pub origin_key: [u8; 32],
    /// Digest of the decoded retained slot.
    pub slot_hash: [u8; 32],
}

impl OriginStatementBody {
    /// Write compact JSON in the exact specified member order.
    ///
    /// # Errors
    ///
    /// [`Error::Invalid`] for an invalid generation, sequence or account creation time.
    pub fn to_json(&self) -> Result<Vec<u8>> {
        positive(self.generation)?;
        if self.seq > MAX_INT || self.created > MAX_TIME_MS {
            return invalid("Switch record origins 5: invalid statement sequence or time");
        }
        let mut out = Obj::new();
        out.int("v", 1)
            .str("kind", "pubky-switch.record_origin")
            .str("identity", &pubky_id(&self.identity))
            .str("created", &rfc3339(self.created))
            .str("identity_hash", &b64(&self.identity_hash))
            .int("generation", self.generation)
            .int("seq", self.seq)
            .str("chain_hash", &b64(&self.chain_hash))
            .str("key", &b64(&self.key))
            .str("origin_key", &b64(&self.origin_key))
            .str("slot_hash", &b64(&self.slot_hash));
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
                "origin_key",
                "slot_hash",
            ],
        )?;
        if integer(member(&value, "v")?)? != 1
            || text(member(&value, "kind")?)? != "pubky-switch.record_origin"
        {
            return invalid("Switch record origins 5: invalid statement tag");
        }
        let body = Self {
            identity: pubky_key(text(member(&value, "identity")?)?)?,
            created: parse_rfc3339(text(member(&value, "created")?)?)?,
            identity_hash: bytes32(member(&value, "identity_hash")?)?,
            generation: integer(member(&value, "generation")?)?,
            seq: integer(member(&value, "seq")?)?,
            chain_hash: bytes32(member(&value, "chain_hash")?)?,
            key: bytes32(member(&value, "key")?)?,
            origin_key: bytes32(member(&value, "origin_key")?)?,
            slot_hash: bytes32(member(&value, "slot_hash")?)?,
        };
        if body.to_json()? != bytes {
            return invalid(
                "Switch record origins 5: statement body is not in compact member order",
            );
        }
        Ok(body)
    }
}

/// A parsed origin statement, preserving its exact signed bytes. Construction or parsing
/// does not verify a signature and confers no record authority (Switch record origins 5).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OriginStatement {
    body: OriginStatementBody,
    signed: SignedDoc,
}

impl OriginStatement {
    /// Check the carrying size without normalizing the signed body.
    ///
    /// # Errors
    ///
    /// [`SizeRefusal::TooLarge`] above 1,024 bytes. [`SizeRefusal::BadRequest`] for
    /// malformed base64url or a signature of the wrong size.
    pub fn check_size(signed: &SignedDoc) -> std::result::Result<(), SizeRefusal> {
        if carrying_len(&signed.body, &signed.sig) > MAX_ORIGIN_STATEMENT_BYTES {
            return Err(SizeRefusal::TooLarge(
                "Switch record origins 6: statement exceeds 1024 bytes".into(),
            ));
        }
        signed.body_bytes().map_err(bad_shape)?;
        signed.sig_bytes().map_err(bad_shape)?;
        Ok(())
    }

    /// Parse the complete current statement format without verifying its signature.
    ///
    /// # Errors
    ///
    /// [`Error::Invalid`] for malformed, noncanonical or oversized input.
    pub fn parse(signed: &SignedDoc) -> Result<Self> {
        Self::check_size(signed)?;
        let body = OriginStatementBody::read(&signed.body_bytes()?)?;
        Ok(Self {
            body,
            signed: signed.clone(),
        })
    }

    /// Sign the exact body using the supplied service key (Switch record origins 5).
    ///
    /// The caller must first establish durable snapshot and account authority under wire
    /// 7.3. Possession of a signing key or this function's success does not establish it.
    ///
    /// # Errors
    ///
    /// [`Error::Invalid`] for an invalid body or oversized carrying form.
    pub fn sign(key: &impl Signs, body: OriginStatementBody) -> Result<Self> {
        let bytes = body.to_json()?;
        let signature = key.sign_fields(
            labels::sig::RECORD_ORIGIN_STATEMENT,
            &[&body.identity, &bytes],
        );
        let signed = SignedDoc::from_parts(&bytes, &signature);
        Self::check_size(&signed)?;
        Ok(Self { body, signed })
    }

    /// The parsed statement body, without an authority assertion.
    pub fn body(&self) -> &OriginStatementBody {
        &self.body
    }

    /// The unchanged signed document.
    pub fn signed(&self) -> &SignedDoc {
        &self.signed
    }

    /// Verify signature, identity, generation and document hash using only this document's
    /// current service key. The caller must independently revalidate the identity document.
    ///
    /// This checks authentication, not freshness, record permissions or reader authority.
    ///
    /// # Errors
    ///
    /// [`Error::Signature`] for an invalid signature; [`Error::Invalid`] for mismatched
    /// identity, generation or document hash.
    pub fn verify_signature(&self, identity: &IdentityDoc) -> Result<()> {
        if self.body.identity != identity.identity()
            || self.body.generation != identity.generation()
            || self.body.identity_hash != identity.hash()
        {
            return invalid("Switch record origins 5: statement identity or generation mismatch");
        }
        self.signed.verify(
            &identity.inbox().service_key,
            labels::sig::RECORD_ORIGIN_STATEMENT,
            &[&identity.identity()],
        )?;
        Ok(())
    }

    /// Authenticate the statement and check its association with a supplied snapshot and
    /// decoded slot (Switch record origins 5, record lineage 4).
    ///
    /// The caller must authenticate the actual request and response and supply their head,
    /// revalidated identity document and account creation time. A cached signed head and
    /// statement can pass this association check: that does not make them current. This
    /// method checks no node set, certificate standing, permission, recovery or continuity.
    /// An unknown slot remains restrictive, even when its statement authenticates.
    ///
    /// # Errors
    ///
    /// [`Error::Signature`] for an invalid statement or head signature;
    /// [`Error::Invalid`] for any association mismatch or invalid slot.
    pub fn check_snapshot(
        &self,
        identity: &IdentityDoc,
        created: u64,
        head: &SignedHead,
        requested_key: &[u8; 32],
        slot: &OriginSlot,
    ) -> Result<()> {
        self.verify_signature(identity)?;
        head.verify(&identity.inbox().service_key, &identity.identity())?;
        if self.body.created != created
            || self.body.generation != head.generation
            || self.body.seq != head.seq
            || self.body.chain_hash != head.chain_hash
            || &self.body.key != requested_key
            || self.body.origin_key != slot.parent_key
            || self.body.slot_hash != slot.hash()?
        {
            return invalid("Switch record origins 5: statement snapshot or slot mismatch");
        }
        if let super::OriginState::Known(known) = &slot.state
            && requested_key != &slot.parent_key
        {
            let child_key = match &known.child {
                super::ChildState::Standalone => None,
                super::ChildState::Vacant(child)
                | super::ChildState::Initialized {
                    declaration: child, ..
                } => Some(&child.key),
            };
            if child_key != Some(requested_key) {
                return invalid("Switch record origins 5: requested key is not the declared child");
            }
        }
        Ok(())
    }
}

/// The current origin object's decoded slot and parsed statement (Switch record origins 5).
/// Neither parsing nor this type supplies complete reader authority.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OriginEvidence {
    /// The slot's decoded retained facts, possibly unknown or recovered.
    pub slot: OriginSlot,
    /// A parsed statement whose signature and snapshot association still need checking.
    pub statement: OriginStatement,
}

impl OriginEvidence {
    /// Read the exact carrying object and signed wrapper, enforcing their component caps.
    ///
    /// # Errors
    ///
    /// [`Error::Invalid`] for malformed, noncanonical or oversized input.
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        let value: Value = parse_json(bytes)?;
        members(&value, &["slot", "statement"])?;
        let slot = text(member(&value, "slot")?)?;
        let statement = member(&value, "statement")?;
        members(statement, &["body", "sig"])?;
        let signed = SignedDoc {
            body: text(member(statement, "body")?)?.to_owned(),
            sig: text(member(statement, "sig")?)?.to_owned(),
        };
        check_origin_sizes(slot, &signed)?;
        Ok(Self {
            slot: OriginSlot::from_base64(slot)?,
            statement: OriginStatement::parse(&signed)?,
        })
    }

    /// Write the compact carrying object while preserving signed body bytes exactly.
    ///
    /// # Errors
    ///
    /// [`Error::Invalid`] for invalid slot facts or a size violation.
    pub fn to_json(&self) -> Result<Vec<u8>> {
        let slot = self.slot.to_base64()?;
        check_origin_sizes(&slot, self.statement.signed())?;
        let mut out = Obj::new();
        out.str("slot", &slot)
            .raw("statement", &serde_json::to_vec(self.statement.signed())?);
        Ok(out.finish())
    }
}

fn bad_shape(_: Error) -> SizeRefusal {
    SizeRefusal::BadRequest("Switch record origins 6: malformed carrying encoding".into())
}

/// Check slot, statement and complete compact carrying sizes without normalizing signed
/// bodies. This is a component check, not full-view or import validation (record origins 6).
///
/// Callers retain the refusal class: writes use `413` for size, recovery leaves an item
/// unaccounted, and import uses `400`. This function performs no such state transition.
///
/// # Errors
///
/// [`SizeRefusal::TooLarge`] for any cap violation; [`SizeRefusal::BadRequest`] for malformed
/// base64url or a signature of the wrong length. Slot semantics and signatures are separate.
pub fn check_origin_sizes(
    slot: &str,
    statement: &SignedDoc,
) -> std::result::Result<(), SizeRefusal> {
    if slot.len() > 770 {
        return Err(SizeRefusal::TooLarge(
            "Switch record origins 6: slot exceeds 770 encoded bytes".into(),
        ));
    }
    OriginSlot::check_size(&unb64(slot).map_err(bad_shape)?)?;
    OriginStatement::check_size(statement)?;
    // The base64url strings need no JSON escaping. Compact outer punctuation takes 24 bytes.
    let length = 24usize
        .saturating_add(slot.len())
        .saturating_add(carrying_len(&statement.body, &statement.sig));
    if length > MAX_ORIGIN_OBJECT_BYTES {
        return Err(SizeRefusal::TooLarge(
            "Switch record origins 6: origin object exceeds 2048 bytes".into(),
        ));
    }
    Ok(())
}
