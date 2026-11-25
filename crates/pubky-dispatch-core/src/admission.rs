//! Peer admission reasons and their representation in list answers and exports (Dispatch
//! wire 6.2, 7.4.6, 10.3).

use serde_json::Value;

use crate::enc::{Obj, app_id_decode, b64, pubky_id, pubky_key, unb64_array, zbase32_encode};
use crate::error::{Error, Result, invalid};
use crate::time::{parse_rfc3339, rfc3339};

/// A reason the service admits a peer (Dispatch spec 7).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum PeerReason {
    /// Explicitly kept by a managing app.
    Kept,
    /// Allowed to reply by an app or through an invitation.
    Reply,
}

impl PeerReason {
    /// The reason as a signed operation or proof writes it.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Kept => "kept",
            Self::Reply => "reply",
        }
    }

    /// Read an admission reason (Dispatch wire 6.2).
    ///
    /// # Errors
    ///
    /// [`Error::Invalid`] for an unknown reason.
    pub fn parse(text: &str) -> Result<Self> {
        match text {
            "kept" => Ok(Self::Kept),
            "reply" => Ok(Self::Reply),
            _ => invalid("Dispatch wire 6.2: unknown peer admission reason"),
        }
    }
}

/// Who first granted the current reply reason (Dispatch wire 7.4.6).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReplyOrigin {
    /// The App ID that granted reply access.
    App([u8; 16]),
    /// The code hash of the invitation the service redeemed to grant reply access.
    Invite([u8; 32]),
}

/// One continuous grant of reply access to a peer (Dispatch wire 7.4.6).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReplyGrant {
    /// The grant's original writer.
    pub origin: ReplyOrigin,
    /// When the grant was created, in Unix milliseconds.
    pub at: u64,
    /// When an append last used the grant, in Unix milliseconds, at or after its creation.
    pub last_used: Option<u64>,
}

/// The reasons a single peer has admission (Dispatch wire 7.4.6, 10.3).
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
    pub fn has_reason(&self, reason: PeerReason) -> bool {
        match reason {
            PeerReason::Kept => self.kept,
            PeerReason::Reply => self.reply.is_some(),
        }
    }

    /// Read a peer row from a strictly parsed list answer or export part (Dispatch wire 1.1).
    ///
    /// # Errors
    ///
    /// [`Error::Invalid`] for a malformed member or reply grant, or a row with neither reason.
    pub fn from_value(value: &Value) -> Result<Self> {
        let pubky = pubky_key(string(value, "pubky")?)?;
        let kept = value
            .get("kept")
            .and_then(Value::as_bool)
            .ok_or_else(|| Error::Invalid("Dispatch wire 7.4.6: expected a kept flag".into()))?;
        let reply = match value.get("reply") {
            Some(Value::Null) => None,
            Some(grant) => Some(ReplyGrant::from_value(grant)?),
            None => return invalid("Dispatch wire 7.4.6: missing reply member"),
        };
        let entry = Self { pubky, kept, reply };
        entry.check()?;
        Ok(entry)
    }

    fn check(&self) -> Result<()> {
        if !self.kept && self.reply.is_none() {
            return invalid("Dispatch wire 7.4.6: a peer row requires an admission reason");
        }
        Ok(())
    }

    /// The row in the member order of Dispatch wire 7.4.6.
    ///
    /// # Errors
    ///
    /// [`Error::Invalid`] for a row with neither reason or a reply grant with a last use
    /// before its creation.
    pub fn to_json(&self) -> Result<Vec<u8>> {
        let mut obj = Obj::new();
        self.write(&mut obj)?;
        Ok(obj.finish())
    }

    pub(crate) fn write(&self, obj: &mut Obj) -> Result<()> {
        self.check()?;
        obj.str("pubky", &pubky_id(&self.pubky))
            .raw("kept", if self.kept { b"true" } else { b"false" });
        match self.reply {
            Some(grant) => obj.raw("reply", &grant.to_json()?),
            None => obj.null("reply"),
        };
        Ok(())
    }
}

fn string<'a>(value: &'a Value, member: &str) -> Result<&'a str> {
    value.get(member).and_then(Value::as_str).ok_or_else(|| {
        Error::Invalid(format!(
            "Dispatch wire 7.4.6: expected a string for {member}"
        ))
    })
}

impl ReplyGrant {
    /// Read the reply grant from its authenticated writer and time fields (Dispatch wire 7.4.6).
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
                if value.get("code_hash").is_some_and(|hash| !hash.is_null()) {
                    return invalid(
                        "Dispatch wire 7.4.6: an app reply grant cannot carry a code hash",
                    );
                }
                ReplyOrigin::App(app_id_decode(app)?)
            }
        };
        let at = parse_rfc3339(string(value, "at")?)?;
        let last_used = match value.get("last_used") {
            None | Some(Value::Null) => None,
            Some(Value::String(time)) => Some(parse_rfc3339(time)?),
            Some(_) => return invalid("Dispatch wire 7.4.6: expected a last_used time"),
        };
        let grant = Self {
            origin,
            at,
            last_used,
        };
        grant.check_times()?;
        Ok(grant)
    }

    /// Write the grant as the `reply` object of Dispatch wire 7.4.6.
    ///
    /// # Errors
    ///
    /// [`Error::Invalid`] if the last use precedes the grant.
    pub fn to_json(self) -> Result<Vec<u8>> {
        self.check_times()?;
        let mut obj = Obj::new();
        match self.origin {
            ReplyOrigin::App(app) => obj.str("written_by", &zbase32_encode(&app)),
            ReplyOrigin::Invite(hash) => obj
                .str("written_by", "service")
                .str("code_hash", &b64(&hash)),
        };
        obj.str("at", &rfc3339(self.at));
        if let Some(last_used) = self.last_used {
            obj.str("last_used", &rfc3339(last_used));
        }
        Ok(obj.finish())
    }

    fn check_times(&self) -> Result<()> {
        if self.last_used.is_some_and(|last_used| last_used < self.at) {
            return invalid("Dispatch wire 7.4.6: reply last_used precedes its grant");
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_reply_grant_last_use_at_or_after_creation() {
        use crate::export::Part;

        for (last_used, valid) in [
            (None, true),
            (Some(10), true),
            (Some(11), true),
            (Some(9), false),
        ] {
            let grant = ReplyGrant {
                origin: ReplyOrigin::App([2; 16]),
                at: 10,
                last_used,
            };
            let peer = PeerEntry {
                pubky: [1; 32],
                kept: true,
                reply: Some(grant),
            };
            let mut wire = json!({"written_by": zbase32_encode(&[2; 16]), "at": rfc3339(10)});
            if let Some(time) = last_used {
                wire["last_used"] = rfc3339(time).into();
            }
            assert_eq!(ReplyGrant::from_value(&wire).ok(), valid.then_some(grant));
            assert_eq!(grant.to_json().is_ok(), valid);

            let row = json!({"part": "admission", "pubky": pubky_id(&peer.pubky), "kept": true, "reply": wire});
            assert_eq!(PeerEntry::from_value(&row).ok(), valid.then_some(peer));
            assert_eq!(peer.to_json().is_ok(), valid);
            assert_eq!(
                Part::read(&row).ok(),
                valid.then_some(Part::Admission(peer))
            );
            assert_eq!(Part::Admission(peer).to_json().is_ok(), valid);
        }
    }

    #[test]
    fn test_peer_entry_keeps_each_reason_and_reply_origin() {
        let app = ReplyGrant {
            origin: ReplyOrigin::App([2; 16]),
            at: 1,
            last_used: None,
        };
        let invite = ReplyGrant {
            origin: ReplyOrigin::Invite([3; 32]),
            at: 2,
            last_used: Some(3),
        };
        for (kept, reply) in [
            (true, None),
            (false, Some(app)),
            (true, Some(app)),
            (false, Some(invite)),
            (true, Some(invite)),
        ] {
            let row = PeerEntry {
                pubky: [1; 32],
                kept,
                reply,
            };
            assert_eq!(row.has_reason(PeerReason::Kept), kept);
            assert_eq!(row.has_reason(PeerReason::Reply), reply.is_some());
            let mut value: Value = crate::json::parse_json(&row.to_json().unwrap()).unwrap();
            assert_eq!(value["pubky"], pubky_id(&row.pubky));
            assert_eq!(value["kept"], kept);
            match reply {
                None => assert_eq!(value.get("reply"), Some(&Value::Null)),
                Some(ReplyGrant {
                    origin: ReplyOrigin::App(id),
                    ..
                }) => assert_eq!(
                    value["reply"],
                    json!({"written_by": zbase32_encode(&id), "at": rfc3339(1)})
                ),
                Some(ReplyGrant {
                    origin: ReplyOrigin::Invite(hash),
                    ..
                }) => assert_eq!(
                    value["reply"],
                    json!({"written_by": "service", "code_hash": b64(&hash), "at": rfc3339(2), "last_used": rfc3339(3)})
                ),
            }
            value["extension"] = true.into();
            assert_eq!(PeerEntry::from_value(&value).unwrap(), row);
        }
    }

    #[test]
    fn test_peer_entry_writes_optional_grant_fields_only_when_present() {
        let peer = pubky_id(&[1; 32]);
        let app = zbase32_encode(&[2; 16]);
        let at = rfc3339(10);
        let row = json!({
            "pubky": peer, "kept": true,
            "reply": {"written_by": app, "code_hash": null, "at": at, "last_used": null}
        });
        let decoded = PeerEntry::from_value(&row).unwrap();
        assert_eq!(decoded.reply.unwrap().origin, ReplyOrigin::App([2; 16]));
        assert_eq!(decoded.reply.unwrap().last_used, None);
        let bytes = format!(
            r#"{{"pubky":"{peer}","kept":true,"reply":{{"written_by":"{app}","at":"{at}"}}}}"#
        );
        assert_eq!(decoded.to_json().unwrap(), bytes.as_bytes());
    }

    #[test]
    fn test_peer_entry_requires_a_reason_and_complete_reply_origin() {
        let row = PeerEntry {
            pubky: [1; 32],
            kept: false,
            reply: None,
        };
        assert!(row.to_json().is_err());
        let mut value = json!({"pubky": pubky_id(&row.pubky), "kept": false, "reply": null});
        assert!(PeerEntry::from_value(&value).is_err());
        value["kept"] = true.into();
        assert!(PeerEntry::from_value(&value).is_ok());
        for member in ["pubky", "kept", "reply"] {
            let mut missing = value.clone();
            missing.as_object_mut().unwrap().remove(member);
            assert!(PeerEntry::from_value(&missing).is_err(), "{member}");
        }
        let at = rfc3339(10);
        let app = zbase32_encode(&[1; 16]);
        for grant in [
            json!({"written_by": "service", "at": at}),
            json!({"written_by": "service", "code_hash": b64(&[1; 31]), "at": at}),
            json!({"written_by": app, "code_hash": b64(&[1; 32]), "at": at}),
            json!({"written_by": "service", "code_hash": null, "at": at}),
            json!({"written_by": "unknown", "at": at}),
            json!({"written_by": app}),
            json!({"written_by": app, "at": at, "last_used": 2}),
        ] {
            value["reply"] = grant;
            assert!(PeerEntry::from_value(&value).is_err());
        }
    }
}
