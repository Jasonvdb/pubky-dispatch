//! Protected record encodings and origin statement authentication (Switch wire 6.9,
//! record origins 1, 3 and 5).
//!
//! Parsing or authenticating these facts does not establish admission, absence, current
//! initial authority, certificate standing, continuity or recovery completeness. A reader
//! also needs the request-bound current response and the complete record lineage checks
//! (Switch record lineage 4). These types do not perform account state transitions.

mod origin;
mod policy;
mod reference;
mod statement;

pub use origin::{
    ChildState, Initialization, KnownOrigin, MAX_ORIGIN_SLOT_BYTES, OriginSlot, OriginState,
    initial_value_hash,
};
pub use policy::{ChildDeclaration, OriginDeclaration, ProtectedPolicy, Protection};
pub use reference::ApplicationRef;
pub use statement::{
    MAX_ORIGIN_OBJECT_BYTES, MAX_ORIGIN_STATEMENT_BYTES, OriginEvidence, OriginStatement,
    OriginStatementBody, check_origin_sizes,
};

use serde_json::Value;

use crate::enc::unb64_array;
use crate::error::{Result, invalid};
use crate::json::{MAX_INT, reject_unknown_members};

fn members(value: &Value, names: &[&str]) -> Result<()> {
    reject_unknown_members(value, names, "record authority object")?;
    for name in names {
        member(value, name)?;
    }
    Ok(())
}

// Required nullable fields use this presence check, without collapsing null and absence.
fn member<'a>(value: &'a Value, name: &str) -> Result<&'a Value> {
    value
        .get(name)
        .ok_or_else(|| crate::Error::Invalid(format!("Switch wire 6.9: missing member {name}")))
}

fn text(value: &Value) -> Result<&str> {
    value
        .as_str()
        .ok_or_else(|| crate::Error::Invalid("Switch wire 6.9: expected a string".into()))
}

fn bytes32(value: &Value) -> Result<[u8; 32]> {
    unb64_array(text(value)?)
}

fn positive(value: u64) -> Result<u64> {
    if value == 0 || value > MAX_INT {
        return invalid("Switch wire 6.9: expected a positive wire integer");
    }
    Ok(value)
}

fn integer(value: &Value) -> Result<u64> {
    match value.as_u64() {
        Some(n) if n <= MAX_INT => Ok(n),
        _ => invalid("Switch wire 6.9: expected a wire integer"),
    }
}

fn birth(value: &Value) -> Result<Option<u64>> {
    if value.is_null() {
        Ok(None)
    } else {
        Ok(Some(positive(integer(value)?)?))
    }
}

fn scope(value: &str) -> Result<()> {
    if !value.is_ascii() || value.len() > 65 || !crate::scopes::is_scope(value) {
        return invalid("Switch record origins 1: invalid protected scope");
    }
    Ok(())
}

#[cfg(test)]
mod tests;
