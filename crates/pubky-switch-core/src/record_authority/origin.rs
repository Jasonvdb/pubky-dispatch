use super::{ApplicationRef, ChildDeclaration, positive, scope};
use crate::enc::{b64, hash, lp, unb64};
use crate::error::{Error, Result, SizeRefusal, invalid};
use crate::json::MAX_INT;
use crate::labels;
use crate::sealed::SealedValue;

/// Maximum canonical slot payload and logical reservation (Switch record origins 3, 6).
pub const MAX_ORIGIN_SLOT_BYTES: usize = 577;
const MAX_SLOT_BASE64_BYTES: usize = 770;

/// The immutable facts installed by atomic child initialization (Switch record origins 3).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Initialization {
    /// Application of the indexed companion parent put.
    pub parent_acceptance: ApplicationRef,
    /// Application of the complete initializer operation.
    pub child_first: ApplicationRef,
    /// Newly assigned child lineage identifier.
    pub child_lineage_id: [u8; 32],
    /// Digest of the initially sealed child value.
    pub initial_value_hash: [u8; 32],
    /// Opaque binding from the initializer.
    pub binding: [u8; 32],
}

impl Initialization {
    // The retained pair comes from one atomic batch; these checks need no account state
    // or certificate authority (Switch record origins 4, Switch wire 6.4).
    fn check(
        &self,
        original: &ApplicationRef,
        parent_key: &[u8; 32],
        declaration: &ChildDeclaration,
    ) -> Result<()> {
        let parent = &self.parent_acceptance;
        let child = &self.child_first;
        let gap = child.seq.checked_sub(parent.seq);
        if parent.generation != child.generation
            || !gap.is_some_and(|n| n > 0 && n < crate::ops::MAX_BATCH_ENTRIES as u64)
        {
            return invalid(
                "Switch record origins 4: initialization references are not in batch order",
            );
        }
        let origin_position = (original.generation, original.seq);
        let acceptance_position = (parent.generation, parent.seq);
        if origin_position > acceptance_position
            || (origin_position == acceptance_position && original != parent)
        {
            return invalid(
                "Switch record origins 4: original does not precede or equal acceptance",
            );
        }
        if &declaration.key == parent_key {
            return invalid("Switch record origins 4: initialized child is its parent");
        }
        Ok(())
    }
}

/// A standalone origin or its one declared child (Switch record origins 3).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ChildState {
    /// The original declaration deliberately has no child.
    Standalone,
    /// A child was declared and has not been initialized.
    Vacant(ChildDeclaration),
    /// The declared child's first initialization facts.
    Initialized {
        /// The unchanged original declaration.
        declaration: ChildDeclaration,
        /// The atomic initialization's retained facts.
        initialization: Initialization,
    },
}

/// Known slot facts; their encoding alone supplies no authority (Switch record origins 3).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KnownOrigin {
    /// The parent's original lineage identifier.
    pub lineage_id: [u8; 32],
    /// The parent's original application.
    pub original: ApplicationRef,
    /// The original put's binding.
    pub binding: [u8; 32],
    /// The immutable declaration and its initialization state.
    pub child: ChildState,
    /// Whether the ordinary parent material was forgotten, retaining this slot.
    pub retired: bool,
    /// Whether facts crossed recovery or unavailable history.
    pub recovered: bool,
}

/// Slot completeness, independent of cryptographic authentication (Switch record origins 3).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OriginState {
    /// Only restrictive policy facts remain; this never establishes absence or an origin.
    Unknown,
    /// The full retained facts, which still need the applicable authority checks.
    Known(Box<KnownOrigin>),
}

/// Canonical retained origin slot (Switch record origins 3). Decoding does not establish
/// that its facts came from valid retained evidence or that the account retained every slot.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OriginSlot {
    /// The parent record key.
    pub parent_key: [u8; 32],
    /// The parent record's collection.
    pub parent_collection: [u8; 32],
    /// The complete parent policy hash.
    pub parent_policy_hash: [u8; 32],
    /// The original's optional birth restriction.
    pub birth_generation: Option<u64>,
    /// Parent read scope; unavailable only in the unknown form.
    pub parent_read_scope: Option<String>,
    /// Unknown or complete retained facts.
    pub state: OriginState,
}

impl OriginSlot {
    /// Check the decoded payload's byte cap without assigning an endpoint's error policy.
    ///
    /// # Errors
    ///
    /// [`SizeRefusal::TooLarge`] above 577 bytes.
    pub fn check_size(bytes: &[u8]) -> std::result::Result<(), SizeRefusal> {
        if bytes.len() > MAX_ORIGIN_SLOT_BYTES {
            return Err(SizeRefusal::TooLarge(
                "Switch record origins 6: slot exceeds 577 bytes".into(),
            ));
        }
        Ok(())
    }

    /// Encode the canonical binary slot, validating constructed values too.
    ///
    /// # Errors
    ///
    /// [`Error::Invalid`] for invalid scopes, references, initialization order or keys,
    /// or a birth/original mismatch.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        if let Some(generation) = self.birth_generation {
            positive(generation)?;
        }
        if let Some(read_scope) = &self.parent_read_scope {
            scope(read_scope)?;
        } else if matches!(self.state, OriginState::Known(_)) {
            return invalid("Switch record origins 3: known slot requires its read scope");
        }
        let mut out = Vec::with_capacity(MAX_ORIGIN_SLOT_BYTES);
        out.push(1);
        for value in [
            &self.parent_key,
            &self.parent_collection,
            &self.parent_policy_hash,
        ] {
            out.extend_from_slice(value);
        }
        out.push(u8::from(self.birth_generation.is_some()));
        if let Some(generation) = self.birth_generation {
            out.extend_from_slice(&generation.to_be_bytes());
        }
        let read_scope = self.parent_read_scope.as_deref().unwrap_or("");
        out.push(read_scope.len() as u8);
        out.extend_from_slice(read_scope.as_bytes());
        match &self.state {
            OriginState::Unknown => out.push(0),
            OriginState::Known(known) => {
                if self
                    .birth_generation
                    .is_some_and(|g| g != known.original.generation)
                {
                    return invalid(
                        "Switch record origins 3: birth and original generations differ",
                    );
                }
                out.push(1);
                out.extend_from_slice(&known.lineage_id);
                out.extend_from_slice(&known.original.to_bytes()?);
                out.extend_from_slice(&known.binding);
                match &known.child {
                    ChildState::Standalone => out.extend_from_slice(&[0, 0]),
                    ChildState::Vacant(declaration) => {
                        write_declaration(&mut out, declaration);
                        out.push(0);
                    }
                    ChildState::Initialized {
                        declaration,
                        initialization,
                    } => {
                        initialization.check(&known.original, &self.parent_key, declaration)?;
                        write_declaration(&mut out, declaration);
                        out.push(1);
                        out.extend_from_slice(&initialization.parent_acceptance.to_bytes()?);
                        out.extend_from_slice(&initialization.child_first.to_bytes()?);
                        out.extend_from_slice(&initialization.child_lineage_id);
                        out.extend_from_slice(&initialization.initial_value_hash);
                        out.extend_from_slice(&initialization.binding);
                    }
                }
                out.extend_from_slice(&[u8::from(known.retired), u8::from(known.recovered)]);
            }
        }
        Self::check_size(&out)?;
        Ok(out)
    }

    /// Decode exactly one canonical slot; unknown and recovered forms stay restrictive.
    ///
    /// # Errors
    ///
    /// [`Error::Invalid`] for invalid tags, lengths, scopes, integers or combinations.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        Self::check_size(bytes)?;
        let mut input = Input(bytes);
        if input.array::<1>()? != [1] {
            return invalid("Switch record origins 3: invalid slot format");
        }
        let parent_key = input.array()?;
        let parent_collection = input.array()?;
        let parent_policy_hash = input.array()?;
        let birth_generation = if input.flag()? {
            Some(positive(u64::from_be_bytes(input.array()?))?)
        } else {
            None
        };
        let [scope_len] = input.array()?;
        let scope_bytes = input.take(usize::from(scope_len))?;
        let parent_read_scope = if scope_bytes.is_empty() {
            None
        } else {
            Some(
                std::str::from_utf8(scope_bytes)
                    .map_err(|_| {
                        Error::Invalid("Switch record origins 3: invalid read scope".into())
                    })?
                    .to_owned(),
            )
        };
        let state = if input.flag()? {
            let lineage_id = input.array()?;
            let original = input.reference()?;
            let binding = input.array()?;
            let declaration = if input.flag()? {
                Some(ChildDeclaration {
                    slot: input.array()?,
                    key: input.array()?,
                    policy_hash: input.array()?,
                })
            } else {
                None
            };
            let initialized = input.flag()?;
            let child = match (declaration, initialized) {
                (None, false) => ChildState::Standalone,
                (None, true) => {
                    return invalid("Switch record origins 3: standalone slot is initialized");
                }
                (Some(declaration), false) => ChildState::Vacant(declaration),
                (Some(declaration), true) => ChildState::Initialized {
                    declaration,
                    initialization: Initialization {
                        parent_acceptance: input.reference()?,
                        child_first: input.reference()?,
                        child_lineage_id: input.array()?,
                        initial_value_hash: input.array()?,
                        binding: input.array()?,
                    },
                },
            };
            OriginState::Known(Box::new(KnownOrigin {
                lineage_id,
                original,
                binding,
                child,
                retired: input.flag()?,
                recovered: input.flag()?,
            }))
        } else {
            OriginState::Unknown
        };
        if !input.0.is_empty() {
            return invalid("Switch record origins 3: trailing slot bytes");
        }
        let slot = Self {
            parent_key,
            parent_collection,
            parent_policy_hash,
            birth_generation,
            parent_read_scope,
            state,
        };
        // The same invariant check governs stored input and locally constructed output.
        slot.to_bytes()?;
        Ok(slot)
    }

    /// Decode the unpadded base64url carrying form with the slot's byte cap.
    ///
    /// # Errors
    ///
    /// [`Error::Invalid`] for malformed or oversized input.
    pub fn from_base64(text: &str) -> Result<Self> {
        if text.len() > MAX_SLOT_BASE64_BYTES {
            return invalid("Switch record origins 6: encoded slot exceeds 770 bytes");
        }
        Self::from_bytes(&unb64(text)?)
    }

    /// The canonical unpadded base64url carrying form.
    ///
    /// # Errors
    ///
    /// [`Error::Invalid`] for invalid constructed slot facts.
    pub fn to_base64(&self) -> Result<String> {
        Ok(b64(&self.to_bytes()?))
    }

    /// Hash the canonical decoded slot under its specified label.
    ///
    /// # Errors
    ///
    /// [`Error::Invalid`] for invalid constructed slot facts.
    pub fn hash(&self) -> Result<[u8; 32]> {
        Ok(hash(&lp(&[
            labels::derive::RECORD_ORIGIN.as_bytes(),
            &self.to_bytes()?,
        ])))
    }
}

fn write_declaration(out: &mut Vec<u8>, declaration: &ChildDeclaration) {
    out.push(1);
    for value in [
        &declaration.slot,
        &declaration.key,
        &declaration.policy_hash,
    ] {
        out.extend_from_slice(value);
    }
}

struct Input<'a>(&'a [u8]);

impl<'a> Input<'a> {
    fn take(&mut self, len: usize) -> Result<&'a [u8]> {
        let (value, rest) = self
            .0
            .split_at_checked(len)
            .ok_or_else(|| Error::Invalid("Switch record origins 3: truncated slot".into()))?;
        self.0 = rest;
        Ok(value)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N]> {
        self.take(N)?
            .try_into()
            .map_err(|_| Error::Invalid("Switch record origins 3: truncated field".into()))
    }

    fn flag(&mut self) -> Result<bool> {
        match self.array()? {
            [0] => Ok(false),
            [1] => Ok(true),
            _ => invalid("Switch record origins 3: invalid presence or boolean tag"),
        }
    }

    fn reference(&mut self) -> Result<ApplicationRef> {
        ApplicationRef::from_bytes(self.take(48)?)
    }
}

/// Hash a non-delete sealed child's initial value (Switch record origins 4).
///
/// This checks the public sealed shape, not decryption, current epoch, permissions or an
/// actual initialization. The complete reader must also check the plaintext padding.
///
/// # Errors
///
/// [`SizeRefusal::TooLarge`] for oversized ciphertext; [`SizeRefusal::BadRequest`] for
/// a malformed scope, epoch or ciphertext shape, a scope mismatch, or a delete.
pub fn initial_value_hash(
    value: &SealedValue,
    read_scope: &str,
) -> std::result::Result<[u8; 32], SizeRefusal> {
    value.check_shape(read_scope)?;
    if value.data_epoch > MAX_INT || scope(&value.scope).is_err() || value.looks_like_delete() {
        return Err(SizeRefusal::BadRequest(
            "Switch record origins 4: invalid initial sealed value".into(),
        ));
    }
    Ok(hash(&lp(&[
        labels::derive::INITIAL_RECORD_VALUE.as_bytes(),
        &value.data_epoch.to_be_bytes(),
        value.scope.as_bytes(),
        &value.nonce,
        &value.ct,
    ])))
}
