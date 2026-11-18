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

/// The body of the app's next record under the certificate of the record it holds, and
/// the certificate its members were given for.
pub(super) struct NextBody(AppRecordBody, Box<AppCert>);

impl NextBody {
    /// The body of the record the app holds.
    pub(super) fn held(state: &AppState) -> pubky_switch_core::Result<Self> {
        let record = AppRecord::verify(&state.record, &state.meta.identity)?;
        Ok(Self(record.body().clone(), Box::new(record.cert().clone())))
    }

    pub(super) fn body(&self) -> &AppRecordBody {
        &self.0
    }

    /// The members of `later`, a later record of the app another device signed, with the
    /// changes made here since `accepted`, the newest record of this device the switch
    /// accepted: each registered protocol's member as held when it differs from `accepted`,
    /// else as in `later`; the others as in `later`. Also the registered protocols whose
    /// member held is now another, gone or new.
    pub(super) fn over(
        mut self,
        accepted: Option<&AppRecordBody>,
        later: &AppRecord,
        protocols: &ProtocolSet,
    ) -> (Self, Vec<String>) {
        let later_cert = Box::new(later.cert().clone());
        let later = later.body();
        let mut members = later.protocols.clone();
        let mut changed = Vec::new();
        for name in protocols.names() {
            let mine = self.0.protocols.get(&name);
            let member = match accepted {
                Some(accepted) if accepted.protocols.get(&name) == mine => {
                    later.protocols.get(&name)
                }
                _ => mine,
            };
            if member != mine {
                changed.push(name.clone());
            }
            match member.cloned() {
                Some(member) => members.insert(name, member),
                None => members.remove(&name),
            };
        }
        self.0.protocols = members;
        // The members not given here were given for the later record's certificate.
        self.1 = later_cert;
        (self, changed)
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

    /// `held` under `cert`, a renewal of the certificate its members were given for: `accepts` and each
    /// registered protocol's member and expiry ask as it gives them for `cert`
    /// ([`super::Protocol::member_for`]). A member that breaks the JSON rules (Switch wire
    /// 1.1), or whose ask isn't `writable`, is dropped with its ask; `None` drops the ask.
    /// A member of a protocol not registered here is kept when `cert` holds every scope and
    /// permission of `old`, and dropped otherwise.
    pub(super) fn judged(
        held: NextBody,
        cert: &AppCert,
        protocols: &ProtocolSet,
        asks: &RecordExpiries,
        writable: impl Fn(RecordExpiry) -> bool,
    ) -> Judging {
        let NextBody(mut body, old) = held;
        body.cert = cert.signed().clone();
        body.accepts = protocols.accepts(cert);
        let carried = std::mem::take(&mut body.protocols);
        let mut judging_asks = RecordExpiries::new();
        let mut dropped = Vec::new();
        for name in protocols.names() {
            let Some(protocol) = protocols.get(&name) else {
                continue;
            };
            // An ask or a member without the other is carried as it is; a member the
            // protocol removes takes its ask with it.
            let had = asks.get(&name).copied();
            let before = carried.get(&name);
            let (member, ask) =
                protocol.member_for(before, had.unwrap_or(RecordExpiry::Never), cert);
            let keeps_ask = had.is_some() || ask != RecordExpiry::Never;
            let Some(member) = member else {
                if before.is_none() && keeps_ask {
                    if ask.valid() && writable(ask) {
                        judging_asks.insert(name, ask);
                    } else {
                        dropped.push(name);
                    }
                }
                continue;
            };
            // Checked at the depth the record holds it (Switch wire 1.1).
            let json = serde_json::to_vec(&serde_json::json!({ "r": { "p": &member } })).ok();
            if json.is_some_and(|json| check_json(&json).is_ok()) && ask.valid() && writable(ask) {
                body.protocols.insert(name.clone(), member);
                if keeps_ask {
                    judging_asks.insert(name, ask);
                }
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
    check_json(&body.to_json()?)?;
    AppRecord::sign(keys, body)
}
