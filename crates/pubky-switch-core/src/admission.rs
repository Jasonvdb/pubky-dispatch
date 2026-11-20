//! The admission state kept for one peer (Switch spec 7).

use serde_json::Value;

use crate::enc::{app_id_decode, unb64_array};
use crate::error::{Error, Result, invalid};
use crate::ops::AllowKind;
use crate::time::parse_rfc3339;

/// Who first granted the current reply reason (Switch wire 7.4.6).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReplyOrigin {
    /// The App ID that granted reply access.
    App([u8; 16]),
    /// The code hash of the invitation the service redeemed to grant reply access.
    Invite([u8; 32]),
}

/// One continuous grant of reply access to a peer (Switch wire 7.4.6).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReplyGrant {
    /// The grant's original writer.
    pub origin: ReplyOrigin,
    /// When the grant was created, in Unix milliseconds.
    pub at: u64,
    /// When an append last used the grant, in Unix milliseconds, at or after its creation.
    pub last_used: Option<u64>,
}

/// The reasons a single peer has admission (Switch wire 7.4.6, 10.3).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PeerEntry {
    /// The peer's Pubky ID.
    pub pubky: [u8; 32],
    /// Whether a managing app explicitly kept the peer.
    pub kept: bool,
    /// The current reply grant, when one exists.
    pub reply: Option<ReplyGrant>,
}

impl PeerEntry {
    /// Whether the peer holds this particular admission reason.
    pub fn has_reason(&self, reason: AllowKind) -> bool {
        match reason {
            AllowKind::Contact => self.kept,
            AllowKind::Conversation => self.reply.is_some(),
        }
    }
}

fn string<'a>(value: &'a Value, member: &str) -> Result<&'a str> {
    value
        .get(member)
        .and_then(Value::as_str)
        .ok_or_else(|| Error::Invalid(format!("Switch wire 7.4.6: expected a string for {member}")))
}

impl ReplyGrant {
    /// Read the reply grant from its authenticated writer and time fields (Switch wire 7.4.6).
    ///
    /// # Errors
    ///
    /// [`Error::Invalid`] for a missing or malformed writer or time, a service grant
    /// without its invitation hash, an app grant carrying a hash, or a last use before
    /// the grant.
    pub fn from_value(value: &Value) -> Result<Self> {
        let origin = match string(value, "written_by")? {
            "service" => ReplyOrigin::Invite(unb64_array(string(value, "code_hash")?)?),
            app => {
                if value.get("code_hash").is_some() {
                    return invalid(
                        "Switch wire 7.4.6: an app reply grant cannot carry a code hash",
                    );
                }
                ReplyOrigin::App(app_id_decode(app)?)
            }
        };
        let at = parse_rfc3339(string(value, "at")?)?;
        let last_used = match value.get("last_used") {
            None => None,
            Some(Value::String(time)) => Some(parse_rfc3339(time)?),
            Some(_) => return invalid("Switch wire 7.4.6: expected a last_used time"),
        };
        if last_used.is_some_and(|last| last < at) {
            return invalid("Switch wire 7.4.6: reply last_used precedes its grant");
        }
        Ok(Self {
            origin,
            at,
            last_used,
        })
    }
}
