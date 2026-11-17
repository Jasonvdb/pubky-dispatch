//! The body of the app's next own record, and the rule on its certificate: each protocol's
//! member is judged for the certificate a record carries before that record is signed
//! (Switch spec 3.2, 4.2).
//!
//! The app signs its own records here only: nothing else in it calls [`AppRecord::sign`].
//! A body to sign is one of two kinds:
//!
//! - a [`NextBody`], the body of the record the app holds ([`NextBody::held`]), under the
//!   certificate that record carries, whose members were given for it; its members, kinds
//!   and expiry may change before it is signed;
//! - a [`CertBody`], a body under a certificate the record held doesn't carry: the first
//!   record of a join, which has no member ([`CertBody::first`]), or the record held under
//!   a renewed certificate, with only the members the registered protocols gave for it
//!   ([`CertBody::judged`]). Nothing of it changes before it is signed.
//!
//! So the app signs no member under a certificate its protocol didn't give it for.

use pubky_switch_core::keys::AppKeys;
use pubky_switch_core::records::{AppCert, AppRecord, AppRecordBody};
use serde_json::{Map, Value};

use super::AppState;
use super::protocols::ProtocolSet;

/// The body of the app's next record under the certificate of the record it holds.
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
    /// The body of the record the app holds.
    pub(super) fn held(state: &AppState) -> pubky_switch_core::Result<Self> {
        let record = AppRecord::verify(&state.record, &state.meta.identity)?;
        Ok(Self(record.body().clone()))
    }

    /// The body as it stands.
    pub(super) fn body(&self) -> &AppRecordBody {
        &self.0
    }

    /// Set `protocol`'s member, or remove it with `None`.
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
        self,
        keys: &AppKeys,
        updated_at: u64,
        expires_at: Option<u64>,
    ) -> pubky_switch_core::Result<AppRecord> {
        sign(keys, self.0, updated_at, expires_at)
    }
}

/// The body of a record under a certificate the record held doesn't carry.
pub(super) struct CertBody {
    body: AppRecordBody,
    /// The registered protocols that had a member and gave none for the certificate.
    removed: Vec<String>,
    /// The protocols not registered here whose member was dropped.
    dropped: Vec<String>,
}

impl CertBody {
    /// The first record of an app joining under `cert`: it accepts `accepts`, and no
    /// protocol has a member yet.
    pub(super) fn first(cert: &AppCert, accepts: Vec<String>, label: Option<String>) -> Self {
        let mut body = AppRecordBody::new(cert, accepts, 0);
        body.label = label;
        Self {
            body,
            removed: Vec::new(),
            dropped: Vec::new(),
        }
    }

    /// `held` under `cert`, a renewed certificate: `accepts` as the protocols give it for
    /// `cert` ([`ProtocolSet::accepts`]), and as members only those the registered
    /// protocols give for it ([`super::Protocol::member_for`]), each asked with the member it
    /// has in `held`. A member of a protocol not registered here is dropped: no protocol
    /// here can give it for `cert`. The first refusal, in registration order, is returned.
    pub(super) fn judged(
        held: NextBody,
        cert: &AppCert,
        protocols: &ProtocolSet,
    ) -> Result<Self, MemberRefusal> {
        let mut body = held.0;
        body.cert = cert.signed().clone();
        body.accepts = protocols.accepts(cert);
        let carried = std::mem::take(&mut body.protocols);
        let mut removed = Vec::new();
        for name in protocols.names() {
            let Some(protocol) = protocols.get(&name) else {
                continue;
            };
            let member = protocol
                .member_for(carried.get(&name), cert)
                .map_err(|reason| MemberRefusal {
                    protocol: name.clone(),
                    reason,
                })?;
            match member {
                Some(member) => {
                    body.protocols.insert(name, member);
                }
                None if carried.contains_key(&name) => removed.push(name),
                None => {}
            }
        }
        let dropped = carried
            .into_keys()
            .filter(|name| !protocols.contains(name))
            .collect();
        Ok(Self {
            body,
            removed,
            dropped,
        })
    }

    /// The registered protocols whose member the body no longer has.
    pub(super) fn removed(&self) -> &[String] {
        &self.removed
    }

    /// The protocols not registered here whose member the body no longer has.
    pub(super) fn dropped(&self) -> &[String] {
        &self.dropped
    }

    /// The body with `protocol`'s member alone, if it has one: it holds nothing the
    /// protocols didn't give for its certificate, so it may be signed to check that member
    /// apart from the others.
    pub(super) fn only(&self, protocol: &str) -> Option<Self> {
        let member = self.body.protocols.get(protocol)?;
        let mut body = self.body.clone();
        body.protocols = [(protocol.to_owned(), member.clone())].into();
        Some(Self {
            body,
            removed: Vec::new(),
            dropped: Vec::new(),
        })
    }

    /// The length of `protocol`'s member as JSON, 0 for none.
    pub(super) fn member_len(&self, protocol: &str) -> usize {
        self.body
            .protocols
            .get(protocol)
            .and_then(|member| serde_json::to_vec(member).ok())
            .map_or(0, |bytes| bytes.len())
    }

    /// Sign the body as the app's record at `updated_at`, expiring at `expires_at`.
    pub(super) fn sign(
        &self,
        keys: &AppKeys,
        updated_at: u64,
        expires_at: Option<u64>,
    ) -> pubky_switch_core::Result<AppRecord> {
        sign(keys, self.body.clone(), updated_at, expires_at)
    }
}

fn sign(
    keys: &AppKeys,
    mut body: AppRecordBody,
    updated_at: u64,
    expires_at: Option<u64>,
) -> pubky_switch_core::Result<AppRecord> {
    body.updated_at = updated_at;
    body.expires_at = expires_at;
    AppRecord::sign(keys, body)
}
