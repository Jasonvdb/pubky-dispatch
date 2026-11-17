//! The body of the app's next own record, and the rule on its certificate: each protocol's
//! member is judged for the certificate a record carries before that record is signed
//! (Switch spec 3.2, 4.2).
//!
//! A [`NextBody`] is built in two ways only: from a record of the app, keeping its
//! certificate with the members judged for it when that record was signed
//! ([`NextBody::of`]), or for another certificate, asking every registered protocol for its
//! member under it ([`NextBody::for_cert`]). Nothing else sets its certificate, and the app
//! signs its own records only from one ([`NextBody::sign`]), so no path signs a member under
//! a certificate its protocol did not judge it for.

use pubky_switch_core::keys::AppKeys;
use pubky_switch_core::records::{AppCert, AppRecord, AppRecordBody};
use serde_json::{Map, Value};

use super::protocols::ProtocolSet;

/// The body of the app's next record.
pub(super) struct NextBody(AppRecordBody);

/// A registered protocol that refused to give a member for a certificate, or whose member
/// the record check refused ([`super::Protocol::member_for`]).
pub(super) struct MemberRefusal {
    /// The protocol's name.
    pub(super) protocol: String,
    /// Its reason, or the check's, without content.
    pub(super) reason: String,
}

impl NextBody {
    /// The body of `record`, a record of the app, under the certificate it carries.
    pub(super) fn of(record: &AppRecord) -> Self {
        Self(record.body().clone())
    }

    /// The body of `record` under `cert`, another certificate: `accepts` as the protocols
    /// give it for `cert` ([`ProtocolSet::accepts`]), and each registered protocol's member
    /// as it gives it for `cert` ([`super::Protocol::member_for`]). `check` refuses a body
    /// the app would not sign or send, as for a member a protocol sets; it runs at each
    /// member that changes, so a refusal names the protocol whose member made it.
    pub(super) fn for_cert(
        record: &AppRecord,
        cert: &AppCert,
        protocols: &ProtocolSet,
        check: impl Fn(&AppRecordBody) -> Result<(), String>,
    ) -> Result<Self, MemberRefusal> {
        let mut body = record.body().clone();
        body.cert = cert.signed().clone();
        body.accepts = protocols.accepts(cert);
        for name in protocols.names() {
            let Some(protocol) = protocols.get(&name) else {
                continue;
            };
            let refused = |reason| MemberRefusal {
                protocol: name.clone(),
                reason,
            };
            let member = protocol
                .member_for(body.protocols.get(&name), cert)
                .map_err(refused)?;
            if body.protocols.get(&name) == member.as_ref() {
                continue;
            }
            match member {
                Some(member) => body.protocols.insert(name.clone(), member),
                None => body.protocols.remove(&name),
            };
            check(&body).map_err(refused)?;
        }
        Ok(Self(body))
    }

    /// The body as it stands.
    pub(super) fn body(&self) -> &AppRecordBody {
        &self.0
    }

    /// Set `protocol`'s member, or remove it with `None`, under the certificate the body
    /// carries.
    pub(super) fn set_member(&mut self, protocol: String, member: Option<Map<String, Value>>) {
        match member {
            Some(member) => self.0.protocols.insert(protocol, member),
            None => self.0.protocols.remove(&protocol),
        };
    }

    /// Set the kinds the record accepts.
    pub(super) fn set_accepts(&mut self, accepts: Vec<String>) {
        self.0.accepts = accepts;
    }

    /// Set the record's `expires_at`.
    pub(super) fn set_expires_at(&mut self, expires_at: Option<u64>) {
        self.0.expires_at = expires_at;
    }

    /// Sign the body as the app's record at `updated_at`, expiring at `expires_at`.
    pub(super) fn sign(
        mut self,
        keys: &AppKeys,
        updated_at: u64,
        expires_at: Option<u64>,
    ) -> pubky_switch_core::Result<AppRecord> {
        self.0.updated_at = updated_at;
        self.0.expires_at = expires_at;
        AppRecord::sign(keys, self.0)
    }
}
