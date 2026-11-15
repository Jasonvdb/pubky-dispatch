use std::collections::BTreeSet;

use serde_json::Value;

use super::{ApplicationRef, bytes32, integer, member, members, text};
use crate::enc::{b64, hash, lp};
use crate::error::{Result, SizeRefusal, invalid};
use crate::json::parse_json;
use crate::labels;
use crate::ops::body::{Obj, array, quote};
use crate::time::{MAX_TIME_MS, parse_rfc3339, rfc3339};

/// Maximum retained deletion capsules (Switch record lineage 2).
pub const MAX_DELETION_CAPSULES: usize = 4;
/// Maximum distinct required nodes, including the current write (Switch record lineage 3).
pub const MAX_LINEAGE_NODES: usize = 14;
/// Maximum exact descriptor bytes for a protected record (Switch record origins 6).
pub const MAX_PROTECTED_DESCRIPTOR_BYTES: usize = 16_384;

/// The first non-delete application of an incarnation (Switch record lineage 2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Incarnation {
    /// The incarnation began at the service-established absence origin.
    Absent(ApplicationRef),
    /// The incarnation replaced a retained delete.
    Replacement(ApplicationRef),
}

impl Incarnation {
    fn read(value: &Value) -> Result<Self> {
        members(value, &["kind", "ref"])?;
        let reference = ApplicationRef::read(member(value, "ref")?)?;
        match text(member(value, "kind")?)? {
            "absent" => Ok(Self::Absent(reference)),
            "replacement" => Ok(Self::Replacement(reference)),
            _ => invalid("Switch record lineage 2: invalid incarnation kind"),
        }
    }

    fn to_json(self) -> Result<Vec<u8>> {
        let (kind, reference) = match self {
            Self::Absent(reference) => ("absent", reference),
            Self::Replacement(reference) => ("replacement", reference),
        };
        let mut out = Obj::new();
        out.str("kind", kind).raw("ref", &reference.to_json()?);
        Ok(out.finish())
    }
}

/// A retained delete and its preceding facts (Switch record lineage 2).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeletionCapsule {
    /// The delete's exact application.
    pub delete: ApplicationRef,
    /// The application that delete replaced, when known.
    pub predecessor: Option<ApplicationRef>,
    /// The preceding incarnation, when known.
    pub incarnation: Option<Incarnation>,
}

impl DeletionCapsule {
    fn read(value: &Value) -> Result<Self> {
        members(value, &["delete", "predecessor", "incarnation"])?;
        Ok(Self {
            delete: ApplicationRef::read(member(value, "delete")?)?,
            predecessor: nullable(member(value, "predecessor")?, ApplicationRef::read)?,
            incarnation: nullable(member(value, "incarnation")?, Incarnation::read)?,
        })
    }

    fn to_json(&self) -> Result<Vec<u8>> {
        let mut out = Obj::new();
        out.raw("delete", &self.delete.to_json()?)
            .raw("predecessor", &optional_ref(self.predecessor)?)
            .raw("incarnation", &optional_incarnation(self.incarnation)?);
        Ok(out.finish())
    }
}

/// The descriptor's current application metadata (Switch record lineage 3).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CurrentApplication {
    /// The current application reference.
    pub reference: ApplicationRef,
    /// The preceding current application, when known.
    pub previous: Option<ApplicationRef>,
    /// Original applied service time in Unix milliseconds, when authenticated.
    pub applied_at: Option<u64>,
}

impl CurrentApplication {
    fn read(value: &Value) -> Result<Self> {
        members(value, &["ref", "previous", "applied_at"])?;
        Ok(Self {
            reference: ApplicationRef::read(member(value, "ref")?)?,
            previous: nullable(member(value, "previous")?, ApplicationRef::read)?,
            applied_at: nullable(member(value, "applied_at")?, |v| parse_rfc3339(text(v)?))?,
        })
    }

    fn to_json(self) -> Result<Vec<u8>> {
        let mut out = Obj::new();
        out.raw("ref", &self.reference.to_json()?)
            .raw("previous", &optional_ref(self.previous)?);
        match self.applied_at {
            Some(ms) if ms <= MAX_TIME_MS => out.str("applied_at", &rfc3339(ms)),
            Some(_) => return invalid("Switch record lineage 3: unrepresentable applied time"),
            None => out.null("applied_at"),
        };
        Ok(out.finish())
    }
}

/// The descriptor's typed data, without a node or authority assertion (Switch record lineage 3).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LineageDescriptorBody {
    /// The record key.
    pub key: [u8; 32],
    /// The service-assigned retained lineage identifier.
    pub lineage_id: [u8; 32],
    /// Service-established absence origin, when available.
    pub origin: Option<ApplicationRef>,
    /// Current or most recently deleted incarnation, when known.
    pub incarnation: Option<Incarnation>,
    /// Metadata for the current write.
    pub current: CurrentApplication,
    /// The current write has a sealed tag of delete length; opening it is a separate check.
    pub deleted: bool,
    /// An older deletion capsule was removed.
    pub truncated: bool,
    /// Lineage crossed loss or was rebuilt from unavailable facts.
    pub recovered: bool,
    /// At most four capsules in application-reference order.
    pub deletions: Vec<DeletionCapsule>,
    /// Unique node digests, in the order of [`Self::required_references`].
    pub nodes: Vec<[u8; 32]>,
}

impl LineageDescriptorBody {
    /// Project the exact required reference union, sorted with aliases counted once.
    ///
    /// An absence origin or absent incarnation alone adds no node. This does not verify
    /// that a digest hashes a node or that any application occurred (record lineage 3).
    pub fn required_references(&self) -> Vec<ApplicationRef> {
        let mut references = BTreeSet::from([self.current.reference]);
        let mut incarnation = |value| {
            if let Some(Incarnation::Replacement(reference)) = value {
                references.insert(reference);
            }
        };
        incarnation(self.incarnation);
        for capsule in &self.deletions {
            incarnation(capsule.incarnation);
        }
        for capsule in &self.deletions {
            references.insert(capsule.delete);
            references.extend(capsule.predecessor);
        }
        references.into_iter().collect()
    }

    fn read(value: &Value) -> Result<Self> {
        members(
            value,
            &[
                "v",
                "key",
                "lineage_id",
                "origin",
                "incarnation",
                "current",
                "deleted",
                "truncated",
                "recovered",
                "deletions",
                "nodes",
            ],
        )?;
        if integer(member(value, "v")?)? != 1 {
            return invalid("Switch record lineage 3: invalid descriptor version");
        }
        let deletions = items(member(value, "deletions")?)?;
        let nodes = items(member(value, "nodes")?)?;
        if deletions.len() > MAX_DELETION_CAPSULES || nodes.len() > MAX_LINEAGE_NODES {
            return invalid("Switch record lineage 3: descriptor count exceeds its bound");
        }
        Ok(Self {
            key: bytes32(member(value, "key")?)?,
            lineage_id: bytes32(member(value, "lineage_id")?)?,
            origin: nullable(member(value, "origin")?, ApplicationRef::read)?,
            incarnation: nullable(member(value, "incarnation")?, Incarnation::read)?,
            current: CurrentApplication::read(member(value, "current")?)?,
            deleted: boolean(member(value, "deleted")?)?,
            truncated: boolean(member(value, "truncated")?)?,
            recovered: boolean(member(value, "recovered")?)?,
            deletions: deletions
                .iter()
                .map(DeletionCapsule::read)
                .collect::<Result<_>>()?,
            nodes: nodes.iter().map(bytes32).collect::<Result<_>>()?,
        })
    }

    /// Encode the current descriptor shape, checking its structural bounds and references.
    ///
    /// Node signatures, their digest association and state-transition relationships require
    /// the complete bundle and record context; this function checks none of them.
    ///
    /// # Errors
    ///
    /// [`crate::Error::Invalid`] for invalid references/times, capsule order, duplicate
    /// digests, excess counts or a digest count different from the required reference union.
    pub fn to_json(&self) -> Result<Vec<u8>> {
        if self.deletions.len() > MAX_DELETION_CAPSULES
            || self.nodes.len() > MAX_LINEAGE_NODES
            || self
                .deletions
                .windows(2)
                .any(|pair| pair[0].delete >= pair[1].delete)
            || self.nodes.iter().collect::<BTreeSet<_>>().len() != self.nodes.len()
            || self.nodes.len() != self.required_references().len()
        {
            return invalid("Switch record lineage 3: invalid capsule order or node set shape");
        }
        let mut out = Obj::new();
        out.int("v", 1)
            .str("key", &b64(&self.key))
            .str("lineage_id", &b64(&self.lineage_id))
            .raw("origin", &optional_ref(self.origin)?)
            .raw("incarnation", &optional_incarnation(self.incarnation)?)
            .raw("current", &self.current.to_json()?)
            .raw("deleted", bool_bytes(self.deleted))
            .raw("truncated", bool_bytes(self.truncated))
            .raw("recovered", bool_bytes(self.recovered));
        let deletions = self
            .deletions
            .iter()
            .map(DeletionCapsule::to_json)
            .collect::<Result<Vec<_>>>()?;
        let nodes: Vec<_> = self
            .nodes
            .iter()
            .map(|digest| quote(&b64(digest)).into_bytes())
            .collect();
        out.raw("deletions", &array(&deletions))
            .raw("nodes", &array(&nodes));
        Ok(out.finish())
    }
}

/// A parsed descriptor together with its unchanged exact bytes (Switch record lineage 3).
/// This is metadata, not verified lineage or a current record authority token.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LineageDescriptor {
    body: LineageDescriptorBody,
    bytes: Vec<u8>,
}

impl LineageDescriptor {
    /// Encode typed data into a retained descriptor.
    ///
    /// # Errors
    ///
    /// [`crate::Error::Invalid`] when [`LineageDescriptorBody::to_json`] refuses its shape.
    pub fn new(body: LineageDescriptorBody) -> Result<Self> {
        let bytes = body.to_json()?;
        Ok(Self { body, bytes })
    }

    /// Parse strict descriptor data while preserving every input byte.
    ///
    /// Protected admission additionally calls [`Self::check_protected_size`]. Ordinary
    /// callers enforce their actual enclosing view/part bounds (record lineage 5).
    ///
    /// # Errors
    ///
    /// [`crate::Error::Invalid`] for malformed JSON, members or structural constraints.
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        let body = LineageDescriptorBody::read(&parse_json(bytes)?)?;
        body.to_json()?;
        Ok(Self {
            body,
            bytes: bytes.to_vec(),
        })
    }

    /// The parsed metadata, without a node or authority assertion.
    pub fn body(&self) -> &LineageDescriptorBody {
        &self.body
    }

    /// The unchanged exact bytes used by hashing and cooperative transfer.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Hash the exact descriptor bytes, without reserialization (record lineage 3).
    pub fn hash(&self) -> [u8; 32] {
        hash(&lp(&[
            labels::derive::RECORD_LINEAGE.as_bytes(),
            &self.bytes,
        ]))
    }

    /// Check the protected-form descriptor cap, separately from generic parsing.
    ///
    /// # Errors
    ///
    /// [`SizeRefusal::TooLarge`] above 16,384 exact bytes. This does not validate JSON.
    /// Writes map size excess to 413, imports to 400 (record origins 6).
    pub fn check_protected_size(bytes: &[u8]) -> std::result::Result<(), SizeRefusal> {
        if bytes.len() > MAX_PROTECTED_DESCRIPTOR_BYTES {
            return Err(SizeRefusal::TooLarge(
                "Switch record origins 6: descriptor exceeds 16384 bytes".into(),
            ));
        }
        Ok(())
    }
}

fn nullable<T>(value: &Value, read: impl FnOnce(&Value) -> Result<T>) -> Result<Option<T>> {
    if value.is_null() {
        Ok(None)
    } else {
        read(value).map(Some)
    }
}

fn optional_ref(value: Option<ApplicationRef>) -> Result<Vec<u8>> {
    value.map_or_else(|| Ok(b"null".to_vec()), |v| v.to_json())
}

fn optional_incarnation(value: Option<Incarnation>) -> Result<Vec<u8>> {
    value.map_or_else(|| Ok(b"null".to_vec()), Incarnation::to_json)
}

fn items(value: &Value) -> Result<&Vec<Value>> {
    value
        .as_array()
        .ok_or_else(|| crate::Error::Invalid("Switch record lineage 3: expected an array".into()))
}

fn boolean(value: &Value) -> Result<bool> {
    value
        .as_bool()
        .ok_or_else(|| crate::Error::Invalid("Switch record lineage 3: expected a boolean".into()))
}

fn bool_bytes(value: bool) -> &'static [u8] {
    if value { b"true" } else { b"false" }
}
