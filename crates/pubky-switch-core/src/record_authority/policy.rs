use serde_json::Value;

use super::{birth, bytes32, member, members, positive, scope, text};
use crate::enc::{b64, hash, lp};
use crate::error::{Result, invalid};
use crate::ident::Policy;
use crate::json::parse_json;
use crate::labels;
use crate::ops::body::Obj;

/// The protected-policy union (Switch record origins 1).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Protection {
    /// One non-recycling origin, optionally restricted to its first generation.
    Origin {
        /// Required nullable wire member; a present generation is positive.
        birth_generation: Option<u64>,
    },
    /// A child created through its parent's reserved declaration.
    InitializedChild {
        /// The parent record's key.
        parent_key: [u8; 32],
        /// The parent record's collection.
        parent_collection: [u8; 32],
        /// Hash of the complete parent policy.
        parent_policy_hash: [u8; 32],
        /// The parent's declared child slot identifier.
        slot: [u8; 32],
    },
}

impl Protection {
    /// Read the strict protection union, including required nullable birth generation.
    ///
    /// # Errors
    ///
    /// [`crate::Error::Invalid`] for malformed input or an invalid union member.
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        Self::read(&parse_json(bytes)?)
    }

    fn read(value: &Value) -> Result<Self> {
        match text(member(value, "kind")?)? {
            "origin" => {
                members(value, &["kind", "birth_generation"])?;
                Ok(Self::Origin {
                    birth_generation: birth(member(value, "birth_generation")?)?,
                })
            }
            "initialized_child" => {
                members(
                    value,
                    &[
                        "kind",
                        "parent_key",
                        "parent_collection",
                        "parent_policy_hash",
                        "slot",
                    ],
                )?;
                Ok(Self::InitializedChild {
                    parent_key: bytes32(member(value, "parent_key")?)?,
                    parent_collection: bytes32(member(value, "parent_collection")?)?,
                    parent_policy_hash: bytes32(member(value, "parent_policy_hash")?)?,
                    slot: bytes32(member(value, "slot")?)?,
                })
            }
            _ => invalid("Switch record origins 1: invalid protection kind"),
        }
    }

    /// The exact protection bytes committed by the policy hash.
    ///
    /// # Errors
    ///
    /// [`crate::Error::Invalid`] for a zero or out-of-range birth generation.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        match self {
            Self::Origin { birth_generation } => {
                out.extend_from_slice(&[1, u8::from(birth_generation.is_some())]);
                if let Some(generation) = birth_generation {
                    out.extend_from_slice(&positive(*generation)?.to_be_bytes());
                }
            }
            Self::InitializedChild {
                parent_key,
                parent_collection,
                parent_policy_hash,
                slot,
            } => {
                out.push(2);
                for value in [parent_key, parent_collection, parent_policy_hash, slot] {
                    out.extend_from_slice(value);
                }
            }
        }
        Ok(out)
    }

    /// Write the complete protection object (Switch record origins 1).
    ///
    /// # Errors
    ///
    /// [`crate::Error::Invalid`] for an invalid birth generation.
    pub fn to_json(&self) -> Result<Vec<u8>> {
        let mut out = Obj::new();
        match self {
            Self::Origin { birth_generation } => {
                out.str("kind", "origin");
                if let Some(generation) = birth_generation {
                    out.int("birth_generation", positive(*generation)?);
                } else {
                    out.null("birth_generation");
                }
            }
            Self::InitializedChild {
                parent_key,
                parent_collection,
                parent_policy_hash,
                slot,
            } => {
                out.str("kind", "initialized_child")
                    .str("parent_key", &b64(parent_key))
                    .str("parent_collection", &b64(parent_collection))
                    .str("parent_policy_hash", &b64(parent_policy_hash))
                    .str("slot", &b64(slot));
            }
        }
        Ok(out.finish())
    }
}

/// A complete protected policy, distinct from the ordinary policy hash (Switch record
/// origins 1). Parsing does not sort scopes or change the policy's input.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProtectedPolicy {
    /// The read and write scopes, with write scopes already sorted and unique.
    pub scopes: Policy,
    /// The required protection committed by the hash.
    pub protection: Protection,
}

impl ProtectedPolicy {
    /// Read exactly `read_scope`, `write_scopes` and `protection`.
    ///
    /// # Errors
    ///
    /// [`crate::Error::Invalid`] for malformed input or a policy rule violation.
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        let value: Value = parse_json(bytes)?;
        members(&value, &["read_scope", "write_scopes", "protection"])?;
        let writes = member(&value, "write_scopes")?.as_array().ok_or_else(|| {
            crate::Error::Invalid("Switch record origins 1: write scopes must be an array".into())
        })?;
        let policy = Self {
            scopes: Policy {
                read_scope: text(member(&value, "read_scope")?)?.to_owned(),
                write_scopes: writes
                    .iter()
                    .map(|v| text(v).map(str::to_owned))
                    .collect::<Result<_>>()?,
            },
            protection: Protection::read(member(&value, "protection")?)?,
        };
        policy.check()?;
        Ok(policy)
    }

    fn check(&self) -> Result<()> {
        scope(&self.scopes.read_scope)?;
        if !(1..=32).contains(&self.scopes.write_scopes.len())
            || self
                .scopes
                .write_scopes
                .windows(2)
                .any(|pair| pair[0] >= pair[1])
        {
            return invalid("Switch record origins 1: require 1 to 32 sorted unique write scopes");
        }
        for write in &self.scopes.write_scopes {
            scope(write)?;
        }
        Ok(())
    }

    /// The protected-policy hash, including its binary protection (Switch record origins 1).
    ///
    /// # Errors
    ///
    /// [`crate::Error::Invalid`] for an invalid scope list or protection.
    pub fn hash(&self) -> Result<[u8; 32]> {
        self.check()?;
        let count = (self.scopes.write_scopes.len() as u64).to_be_bytes();
        let protection = self.protection.to_bytes()?;
        let mut parts = vec![
            labels::derive::PROTECTED_POLICY.as_bytes(),
            self.scopes.read_scope.as_bytes(),
            &count,
        ];
        parts.extend(self.scopes.write_scopes.iter().map(String::as_bytes));
        parts.push(&protection);
        Ok(hash(&lp(&parts)))
    }

    /// Write the complete protected policy, without altering its scopes.
    ///
    /// # Errors
    ///
    /// [`crate::Error::Invalid`] for an invalid scope list or protection.
    pub fn to_json(&self) -> Result<Vec<u8>> {
        self.check()?;
        let mut out = Obj::new();
        out.str("read_scope", &self.scopes.read_scope)
            .raw(
                "write_scopes",
                &serde_json::to_vec(&self.scopes.write_scopes)?,
            )
            .raw("protection", &self.protection.to_json()?);
        Ok(out.finish())
    }
}

/// An immutable declared child (Switch record origins 2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ChildDeclaration {
    /// The opaque slot identifier.
    pub slot: [u8; 32],
    /// The derived child record key.
    pub key: [u8; 32],
    /// Hash of the child's complete protected policy.
    pub policy_hash: [u8; 32],
}

impl ChildDeclaration {
    fn read(value: &Value) -> Result<Self> {
        members(value, &["slot", "key", "policy_hash"])?;
        Ok(Self {
            slot: bytes32(member(value, "slot")?)?,
            key: bytes32(member(value, "key")?)?,
            policy_hash: bytes32(member(value, "policy_hash")?)?,
        })
    }

    fn to_json(self) -> Vec<u8> {
        let mut out = Obj::new();
        out.str("slot", &b64(&self.slot))
            .str("key", &b64(&self.key))
            .str("policy_hash", &b64(&self.policy_hash));
        out.finish()
    }
}

/// The original put's binding and required nullable child declaration (Switch record
/// origins 2). This object's shape does not establish original admission.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OriginDeclaration {
    /// The original put's opaque binding.
    pub binding: [u8; 32],
    /// Null selects a standalone origin; it is not a vacant declared child.
    pub child: Option<ChildDeclaration>,
}

impl OriginDeclaration {
    /// Read the exact declaration, requiring `child` even when null.
    ///
    /// # Errors
    ///
    /// [`crate::Error::Invalid`] for malformed input or missing members.
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        let value: Value = parse_json(bytes)?;
        members(&value, &["binding", "child"])?;
        let child = member(&value, "child")?;
        Ok(Self {
            binding: bytes32(member(&value, "binding")?)?,
            child: if child.is_null() {
                None
            } else {
                Some(ChildDeclaration::read(child)?)
            },
        })
    }

    /// Write the required binding and child members (Switch record origins 2).
    pub fn to_json(&self) -> Vec<u8> {
        let mut out = Obj::new();
        out.str("binding", &b64(&self.binding));
        if let Some(child) = self.child {
            out.raw("child", &child.to_json());
        } else {
            out.null("child");
        }
        out.finish()
    }
}
