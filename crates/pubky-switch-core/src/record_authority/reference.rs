use serde_json::Value;

use super::{bytes32, integer, member, members, positive};
use crate::enc::b64;
use crate::error::Result;
use crate::json::parse_json;
use crate::ops::body::Obj;

/// An exact application, ordered by generation, sequence, then decoded item hash
/// (Switch record lineage 1, 3). Its shape alone does not prove an application occurred.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ApplicationRef {
    /// Positive application generation, at most the wire integer maximum.
    pub generation: u64,
    /// Positive sequence within that generation, at most the wire integer maximum.
    pub seq: u64,
    /// Hash of the full applied item.
    pub item_hash: [u8; 32],
}

impl ApplicationRef {
    /// Read an exact reference object under the strict JSON rules.
    ///
    /// # Errors
    ///
    /// [`crate::Error::Invalid`] for malformed members or an invalid reference.
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        Self::read(&parse_json(bytes)?)
    }

    pub(super) fn read(value: &Value) -> Result<Self> {
        members(value, &["generation", "seq", "item_hash"])?;
        let reference = Self {
            generation: integer(member(value, "generation")?)?,
            seq: integer(member(value, "seq")?)?,
            item_hash: bytes32(member(value, "item_hash")?)?,
        };
        reference.check()?;
        Ok(reference)
    }

    pub(super) fn check(&self) -> Result<()> {
        positive(self.generation)?;
        positive(self.seq)?;
        Ok(())
    }

    /// Write the reference in member order (Switch record lineage 1).
    ///
    /// # Errors
    ///
    /// [`crate::Error::Invalid`] for a zero or out-of-range integer.
    pub fn to_json(&self) -> Result<Vec<u8>> {
        self.check()?;
        let mut out = Obj::new();
        out.int("generation", self.generation)
            .int("seq", self.seq)
            .str("item_hash", &b64(&self.item_hash));
        Ok(out.finish())
    }

    /// The 48 bytes `u64(generation) || u64(seq) || item_hash`.
    ///
    /// # Errors
    ///
    /// [`crate::Error::Invalid`] for a zero or out-of-range integer.
    pub fn to_bytes(&self) -> Result<[u8; 48]> {
        self.check()?;
        let mut bytes = [0; 48];
        bytes[..8].copy_from_slice(&self.generation.to_be_bytes());
        bytes[8..16].copy_from_slice(&self.seq.to_be_bytes());
        bytes[16..].copy_from_slice(&self.item_hash);
        Ok(bytes)
    }

    /// Read exactly 48 reference bytes (Switch record lineage 3).
    ///
    /// # Errors
    ///
    /// [`crate::Error::Invalid`] for the wrong length or invalid integers.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let bytes: &[u8; 48] = bytes.try_into().map_err(|_| {
            crate::Error::Invalid("Switch record lineage 3: reference length".into())
        })?;
        let mut generation = [0; 8];
        generation.copy_from_slice(&bytes[..8]);
        let mut seq = [0; 8];
        seq.copy_from_slice(&bytes[8..16]);
        let mut item_hash = [0; 32];
        item_hash.copy_from_slice(&bytes[16..]);
        let reference = Self {
            generation: u64::from_be_bytes(generation),
            seq: u64::from_be_bytes(seq),
            item_hash,
        };
        reference.check()?;
        Ok(reference)
    }

    /// Encode a nullable reference as `00` or `01 || reference`.
    ///
    /// # Errors
    ///
    /// [`crate::Error::Invalid`] for an invalid present reference.
    pub fn optional_bytes(reference: Option<&Self>) -> Result<Vec<u8>> {
        match reference {
            None => Ok(vec![0]),
            Some(reference) => {
                let mut out = vec![1];
                out.extend_from_slice(&reference.to_bytes()?);
                Ok(out)
            }
        }
    }
}
