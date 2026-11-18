//! The body of the app's next own record (Switch spec 3.2 step 3, 4.2). The app signs its
//! own records only here: a [`NextBody`] is the record it holds, under that record's
//! certificate, and a [`CertBody`] a record under a certificate the held one doesn't
//! carry, the first at a join or the record held under a renewal with each member as its
//! protocol gives it for the renewal. So no member is signed under a certificate its
//! protocol didn't give it for.

use pubky_switch_core::json::check_json;
use pubky_switch_core::keys::AppKeys;
use pubky_switch_core::records::{AppCert, AppRecord, AppRecordBody};
use pubky_switch_core::scopes::holds;
use serde_json::{Map, Value};

use super::AppState;
use super::own_record::{RecordExpiries, RecordExpiry};
use super::protocols::ProtocolSet;

/// The body of the app's next record under the certificate of the record it holds.
pub(super) struct NextBody(AppRecordBody);

impl NextBody {
    /// The body of the record the app holds.
    pub(super) fn held(state: &AppState) -> pubky_switch_core::Result<Self> {
        let record = AppRecord::verify(&state.record, &state.meta.identity)?;
        Ok(Self(record.body().clone()))
    }

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

    pub(super) fn set_accepts(&mut self, accepts: Vec<String>) {
        self.0.accepts = accepts;
    }

    pub(super) fn set_expires_at(&mut self, expires_at: Option<u64>) {
        self.0.expires_at = expires_at;
    }

    pub(super) fn sign(
        self,
        keys: &AppKeys,
        updated_at: u64,
        expires_at: Option<u64>,
    ) -> pubky_switch_core::Result<AppRecord> {
        sign(keys, self.0, updated_at, expires_at)
    }
}

/// A body under a certificate the record held doesn't carry; nothing of it changes before
/// it is signed.
pub(super) struct CertBody(AppRecordBody);

/// [`CertBody::judged`]: the body, the expiry asks it is signed with, and the protocols
/// whose member it dropped.
pub(super) struct Judging {
    pub(super) body: CertBody,
    pub(super) asks: RecordExpiries,
    pub(super) dropped: Vec<String>,
}

impl CertBody {
    /// The first record of an app joining under `cert`: no protocol has a member yet.
    pub(super) fn first(cert: &AppCert, accepts: Vec<String>, label: Option<String>) -> Self {
        let mut body = AppRecordBody::new(cert, accepts, 0);
        body.label = label;
        Self(body)
    }

    /// `held`, the record held under `old`, under `cert`, its renewal: `accepts` and each
    /// registered protocol's member and expiry ask as it gives them for `cert`
    /// ([`super::Protocol::member_for`]). A member that breaks the JSON rules (Switch wire
    /// 1.1), or whose ask isn't `writable`, is dropped with its ask; `None` drops the ask.
    /// A member of a protocol not registered here is kept when `cert` holds every scope and
    /// permission of `old`, and dropped otherwise.
    pub(super) fn judged(
        held: NextBody,
        old: &AppCert,
        cert: &AppCert,
        protocols: &ProtocolSet,
        asks: &RecordExpiries,
        writable: impl Fn(RecordExpiry) -> bool,
    ) -> Judging {
        let mut body = held.0;
        body.cert = cert.signed().clone();
        body.accepts = protocols.accepts(cert);
        let carried = std::mem::take(&mut body.protocols);
        let mut judging_asks = RecordExpiries::new();
        let mut dropped = Vec::new();
        for name in protocols.names() {
            let Some(protocol) = protocols.get(&name) else {
                continue;
            };
            let ask = asks.get(&name).copied().unwrap_or(RecordExpiry::Never);
            let (member, ask) = protocol.member_for(carried.get(&name), ask, cert);
            let Some(member) = member else {
                continue;
            };
            let json = serde_json::to_vec(&member).ok();
            if json.is_some_and(|json| check_json(&json).is_ok()) && ask.valid() && writable(ask) {
                body.protocols.insert(name.clone(), member);
                judging_asks.insert(name, ask);
            } else {
                dropped.push(name);
            }
        }
        let covers = old.scopes().iter().all(|s| holds(cert.scopes(), s))
            && old.permissions().iter().all(|p| cert.has_permission(*p));
        for (name, member) in carried {
            if !protocols.contains(&name) {
                if covers {
                    body.protocols.insert(name, member);
                } else {
                    dropped.push(name);
                }
            }
        }
        Judging {
            body: Self(body),
            asks: judging_asks,
            dropped,
        }
    }

    pub(super) fn sign(
        self,
        keys: &AppKeys,
        updated_at: u64,
        expires_at: Option<u64>,
    ) -> pubky_switch_core::Result<AppRecord> {
        sign(keys, self.0, updated_at, expires_at)
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
