//! The scripted Dispatch as a sender at another identity sees it: admission, the directory
//! with `known_version`, the peer copies of senders' `identity.json`, connect requests, and
//! the inbox, with its retry by content, `identity_needed`, `stale_key` and invite codes
//! (Dispatch spec 7; Dispatch wire 7.4.3, 7.4.5, 7.4.7, 7.4.10). Own apps append to it too, for
//! the kinds their protocol sends between own apps. It checks what a sender relies on, and
//! nothing the service alone answers for, such as rate limits and quotas; `FAKES.md` lists
//! what it leaves out.

use std::collections::BTreeSet;

use pubky_dispatch_core::admission::PeerReason;
use pubky_dispatch_core::chain::ServiceTransition;
use pubky_dispatch_core::enc::{app_id_decode, b64, pubky_key, unb64_array, zbase32_encode};
use pubky_dispatch_core::envelope::parse_header;
use pubky_dispatch_core::http::{ErrorCode, header};
use pubky_dispatch_core::ident::invite_code_hash;
use pubky_dispatch_core::records::{AppCert, IdentityDoc, Standing};
use pubky_dispatch_core::sig::SignedDoc;
use pubky_dispatch_core::time::rfc3339;
use serde_json::{Value, json};

use super::{Answer, Inner, Item, ScriptedDispatch, bad};
use crate::testing::ScriptError;
use crate::transport::Request;

/// Who a request to the inbox routes comes from.
pub(super) struct Sender {
    /// The sender identity.
    pub(super) identity: [u8; 32],
    /// The sender app.
    pub(super) app: Option<[u8; 16]>,
    /// The invite code it presents.
    pub(super) code: Option<String>,
}

impl Sender {
    /// The caller of `request` when it is an app of another identity than `account`.
    pub(super) fn foreign(request: &Request, account: &[u8; 32]) -> Option<Self> {
        let identity = request
            .header(header::IDENTITY)
            .and_then(|text| pubky_key(text).ok())?;
        if identity == *account {
            return None;
        }
        Some(Self {
            identity,
            app: request
                .header(header::APP)
                .and_then(|text| app_id_decode(text).ok()),
            code: request.header(header::INVITE_CODE).map(str::to_owned),
        })
    }
}

impl ScriptedDispatch {
    /// Admit every sender, or only those the lists and invite codes admit (Dispatch spec 7),
    /// the default.
    pub fn admit_everyone(&self, open: bool) {
        self.lock().open_admission = open;
    }

    /// The peer copy of `identity`'s `identity.json` the Dispatch holds (Dispatch wire 7.4.5).
    pub fn peer_copy(&self, identity: &[u8; 32]) -> Option<IdentityDoc> {
        self.lock().peers.get(identity).cloned()
    }

    /// How many entries the inbox accepted from `sender`.
    pub fn entries_from(&self, sender: &[u8; 32]) -> usize {
        self.lock()
            .items
            .iter()
            .filter(|item| matches!(item, Item::Entry { sender: s, .. } if s == sender))
            .count()
    }

    /// Drop the peer copy of `identity`'s `identity.json`, as a Dispatch beyond its peer
    /// limit does: its apps' next appends get `409 identity_needed` (Dispatch wire 7.4.5).
    pub fn forget_peer_copy(&self, identity: &[u8; 32]) {
        self.lock().peers.remove(identity);
    }

    /// The `apps_version`: how often an app became reachable or stopped being so (Dispatch
    /// wire 7.4.10).
    pub fn apps_version(&self) -> u64 {
        self.lock().apps_version
    }

    /// The uses left of the invite code `code`, if the Dispatch holds it.
    pub fn invite_uses_left(&self, code: &str) -> Option<u64> {
        let hash = invite_code_hash(code).ok()?;
        self.lock()
            .shared
            .invites
            .get(&hash)
            .map(|invite| invite.max_uses.saturating_sub(invite.uses))
    }
}

/// The wire's default `max_connect_pending` (Dispatch wire 9.2), the most pending connect
/// requests any policy gets.
const MAX_CONNECT_PENDING: u64 = 1_000;

impl Inner {
    /// The routes an app of another identity calls; for every other call of Dispatch wire 7.4
    /// `403 permission_missing` (one only another caller makes, 7.6), at a batch `403
    /// not_admitted` (6.4 step 1), and at a route that isn't one `404`, as at the service.
    pub(super) fn route_foreign(
        &mut self,
        request: &Request,
        sender: &Sender,
        rest: &str,
    ) -> Result<Answer, ScriptError> {
        let (route, query) = rest.split_once('?').unwrap_or((rest, ""));
        Ok(match (request.method.as_str(), route) {
            ("GET", "directory") => {
                if !self.admits(sender) {
                    return Ok(self.not_admitted_now());
                }
                let (status, mut body) = self.directory();
                body["known_version"] = self.known(&sender.identity);
                (status, body)
            }
            // Where connect requests are on, a stranger delivers its document too, and asks
            // to connect (Dispatch wire 7.4.5, 7.4.7).
            ("PUT", "peers") => {
                // While admission is staged, a sender it can't otherwise admit waits, a
                // stranger asking to connect included (Dispatch spec 12.6 step 2).
                if !self.admits(sender) && (self.admission_staged || !self.connect_requests_on()) {
                    return Ok(self.not_admitted_now());
                }
                self.peers_put(&sender.identity, &request.body)
            }
            ("POST", "inbox") => self.append(request, Some(sender), query)?,
            ("POST", "connect") => self.connect(request, sender),
            // The feed, the claims, the lists and the records are read only by the account's
            // own apps; a batch is `not_admitted`; every other call of Dispatch wire 7.4 only an
            // own app or the signer makes (7.6; `crates/pubky-dispatch/src/service/rules.rs`,
            // `other_app_refusal`); and a route that isn't one is `404`, as at the service.
            ("GET", "feed" | "allow" | "records") => own_reads_only(),
            ("GET", r) if r.starts_with("claims/") || r.starts_with("records/") => own_reads_only(),
            ("POST", "ops") => not_admitted(),
            (method, route) if is_route(method, route) => bad(
                ErrorCode::PermissionMissing,
                "7.4: a call only an own app or the signer makes",
                json!(null),
            ),
            _ => bad(ErrorCode::NotFound, "no such route", json!(null)),
        })
    }

    /// The version of `sender`'s `identity.json` the Dispatch holds, for `known_version`.
    fn known(&self, sender: &[u8; 32]) -> Value {
        self.peers
            .get(sender)
            .map_or(Value::Null, |doc| json!(doc.version()))
    }

    /// The allowlist and deny list (Dispatch spec 7): whether `pubky` is a kept peer or has a
    /// reply grant, an app's or the service's, and whether it is denied.
    fn listed(&self, pubky: &[u8; 32]) -> (bool, bool) {
        let listed = self.shared.allowed(pubky, PeerReason::Kept)
            || self.shared.allowed(pubky, PeerReason::Reply);
        (listed, self.shared.denied(pubky))
    }

    /// The invite code `sender` presents, when it is live: its hash.
    fn live_code(&self, sender: &Sender) -> Option<[u8; 32]> {
        let hash = invite_code_hash(sender.code.as_deref()?).ok()?;
        let invite = self.shared.invites.get(&hash)?;
        (invite.uses < invite.max_uses && self.now() < invite.expires_at).then_some(hash)
    }

    /// The answer to a sender not admitted: `503 staged` while admission is staged after a
    /// provider loss, so it retries, `403 not_admitted` otherwise (Dispatch spec 12.6 step 2).
    fn not_admitted_now(&self) -> Answer {
        if self.admission_staged {
            bad(
                ErrorCode::Staged,
                "admission is staged after a provider loss",
                json!(null),
            )
        } else {
            not_admitted()
        }
    }

    /// Whether `sender` is admitted (Dispatch spec 7): a kept peer, a reply grant or a live
    /// invite code, the deny list overriding all three.
    fn admits(&self, sender: &Sender) -> bool {
        let (listed, denied) = self.listed(&sender.identity);
        if denied {
            return false;
        }
        self.open_admission || listed || self.live_code(sender).is_some()
    }

    /// `PUT /peers` from an app of another identity (Dispatch wire 7.4.5).
    fn peers_put(&mut self, sender: &[u8; 32], body: &[u8]) -> Answer {
        let Ok(signed) = serde_json::from_slice::<SignedDoc>(body) else {
            return bad(ErrorCode::BadRequest, "peers", json!(null));
        };
        let Ok(doc) = IdentityDoc::verify(&signed, sender) else {
            return not_admitted();
        };
        if let Some(held) = self.peers.get(sender) {
            if held.version() == doc.version() && held.body_hash() != doc.body_hash() {
                return bad(
                    ErrorCode::StaleIdentity,
                    "equivocation",
                    json!({ "version": held.version(), "identity": held.signed() }),
                );
            }
            if held.version() > doc.version() || held.generation() > doc.generation() {
                return bad(
                    ErrorCode::StaleIdentity,
                    "older",
                    json!({ "version": held.version() }),
                );
            }
        }
        let version = doc.version();
        // A new copy changes what admits the sender: counted, as at the service (Dispatch
        // wire 7.3, "The state").
        if self
            .peers
            .get(sender)
            .is_none_or(|held| held.body_hash() != doc.body_hash())
        {
            self.count_change();
        }
        self.peers.insert(*sender, doc);
        (200, json!({ "version": version, "known_version": version }))
    }

    /// Whether the peer copy of `sender`'s `identity.json` lists `app` with `cert` and not
    /// as removed.
    fn listed_in_copy(&self, sender: &[u8; 32], app: &[u8; 16], cert: &[u8; 32]) -> bool {
        self.peers
            .get(sender)
            .is_some_and(|doc| doc.listed_cert(app) == Some(*cert) && !doc.lists_removed(app))
    }

    /// Whether the account's `identity.json` turns connect requests on (Dispatch spec 7).
    fn connect_requests_on(&self) -> bool {
        self.doc
            .as_ref()
            .is_some_and(|doc| doc.body().policy.connect_requests.enabled)
    }

    /// The pending connect requests' cap that applies: the policy's `max_pending`, at most
    /// the wire's default `max_connect_pending` (Dispatch wire 3.3, 9.2).
    pub(super) fn connect_cap(&self) -> u64 {
        self.doc.as_ref().map_or(0, |doc| {
            doc.body()
                .policy
                .connect_requests
                .max_pending
                .min(MAX_CONNECT_PENDING)
        })
    }

    /// `POST /connect` (Dispatch wire 7.4.7), in the service's order
    /// (`crates/pubky-dispatch/src/service/connect.rs`): `503 staged` while admission is
    /// staged, whatever the policy; `not_admitted` while the policy turns connect requests
    /// off; check 5 against the sender's certificate, as at the service; a
    /// sender already pending, or one the allowlist admits, answered `pending`, nothing kept
    /// for the admitted one; a full list `429 quota_exceeded`, before
    /// the deny list; a denied sender answered `pending`, its request not kept.
    fn connect(&mut self, request: &Request, sender: &Sender) -> Answer {
        if self.admission_staged {
            return self.not_admitted_now();
        }
        if !self.connect_requests_on() {
            return not_admitted();
        }
        // Check 5 (Dispatch wire 7.2), as at the service: the copy lists the app with this
        // very certificate, or a renewal of it still open; a closed renewal is `403
        // not_current`; otherwise `409 identity_needed`, naming the held version unless the
        // copy lists the app as removed, which is answered like a stranger with no copy.
        let cert = request
            .header(header::CERT)
            .and_then(|text| SignedDoc::from_compact(text).ok())
            .and_then(|signed| AppCert::verify(&signed, &sender.identity).ok());
        let Some(cert) = cert.filter(|cert| Some(cert.app_id()) == sender.app) else {
            return bad(ErrorCode::BadRequest, "Dispatch-Cert", json!(null));
        };
        let copy = self.peers.get(&sender.identity);
        match copy.map(|doc| doc.standing(&cert.app_id(), &cert.hash())) {
            Some(Standing::Listed | Standing::RenewedOpen) => {}
            Some(Standing::RenewedClosed { .. }) => {
                return bad(
                    ErrorCode::NotCurrent,
                    "3.8: the certificate's renewal has closed",
                    json!(null),
                );
            }
            Some(Standing::Removed { .. }) => return identity_needed(None),
            Some(Standing::None) | None => {
                return identity_needed(copy.map(IdentityDoc::version));
            }
        }
        let pending = (
            200,
            json!({ "pending": true, "known_version": self.known(&sender.identity) }),
        );
        // A sender already pending, or one the allowlist already admits, which nothing is
        // kept for.
        let (listed, denied) = self.listed(&sender.identity);
        if (listed && !denied)
            || self
                .shared
                .connect
                .iter()
                .any(|(pubky, _)| *pubky == sender.identity)
        {
            return pending;
        }
        let count = u64::try_from(self.shared.connect.len()).unwrap_or(u64::MAX);
        if count >= self.connect_cap() {
            return bad(
                ErrorCode::QuotaExceeded,
                "9.3: the connect request list is full",
                json!({ "limit": "connect_requests" }),
            );
        }
        if !denied {
            let now = self.now();
            self.shared.connect.push((sender.identity, now));
        }
        pending
    }

    /// The app holding receive key `kid`, current or not.
    fn holder_of(&self, kid: &[u8; 8]) -> Option<[u8; 16]> {
        self.kids.get(kid).copied()
    }

    /// The current kid of `app`'s receive key.
    fn current_kid(&self, app: &[u8; 16]) -> Option<[u8; 8]> {
        let record = self.apps.get(app)?.receive_key.as_ref()?;
        let value: Value = record.peek().ok()?;
        unb64_array::<8>(value["kid"].as_str()?).ok()
    }

    /// The apps a sender reaches: current, with a receive key.
    fn reachable(&self) -> Vec<[u8; 16]> {
        self.apps
            .iter()
            .filter(|(_, app)| !app.departed && app.receive_key.is_some())
            .map(|(id, _)| *id)
            .collect()
    }

    /// `POST /inbox` (Dispatch wire 7.4.3), from an app of another identity (`sender`) or an
    /// own app. `query` carries the `apps_version` the envelope was sealed for.
    pub(super) fn append(
        &mut self,
        request: &Request,
        sender: Option<&Sender>,
        query: &str,
    ) -> Result<Answer, ScriptError> {
        let identity = match sender {
            Some(sender) => sender.identity,
            None => self.identity.public(),
        };
        let app = match sender {
            Some(sender) => sender.app,
            None => request
                .header(header::APP)
                .and_then(|text| app_id_decode(text).ok()),
        };
        let Some(app) = app else {
            return Ok(bad(ErrorCode::BadRequest, "no app", json!(null)));
        };
        // The query is read before the endpoint's checks, as at the service
        // (`crates/pubky-dispatch/src/service/mod.rs`, `Call::Append`).
        let Some(params) = super::parse_query(query) else {
            return Ok(bad(
                ErrorCode::BadRequest,
                "the query doesn't decode",
                json!(null),
            ));
        };
        // Step 1: a retry by content returns the original answer.
        if let Some(answer) = self.appended.get(&(identity, request.body.clone())) {
            return Ok((200, answer.clone()));
        }
        let Some(sealed_for) = params
            .get("apps_version")
            .and_then(|value| super::decimal(value))
        else {
            return Ok(bad(ErrorCode::BadRequest, "apps_version", json!(null)));
        };
        // The sender app's certificate, which the entry carries.
        let cert = match sender {
            Some(_) => {
                let cert = request
                    .header(header::CERT)
                    .and_then(|text| SignedDoc::from_compact(text).ok())
                    .and_then(|signed| AppCert::verify(&signed, &identity).ok());
                match cert {
                    Some(cert) if cert.app_id() == app => cert,
                    _ => return Ok(bad(ErrorCode::BadRequest, "Dispatch-Cert", json!(null))),
                }
            }
            None => match self.apps.get(&app).and_then(|held| held.cert.clone()) {
                Some(cert) => cert,
                None => return Ok(bad(ErrorCode::NotCurrent, "not current", json!(null))),
            },
        };
        // Step 2: admission, then the listing in the peer copy (Dispatch wire 7.4.3).
        let mut invite_code_hash = None;
        let mut add_reply_grant = false;
        if let Some(sender) = sender {
            let (listed, denied) = self.listed(&identity);
            let admitted = listed || self.open_admission;
            if denied {
                return Ok(self.not_admitted_now());
            }
            if sender.code.is_some() {
                let Some(hash) = self.live_code(sender) else {
                    return Ok(self.not_admitted_now());
                };
                invite_code_hash = Some(hash);
                add_reply_grant = !admitted;
            } else if !admitted {
                return Ok(self.not_admitted_now());
            }
            if !self.listed_in_copy(&identity, &app, &cert.hash()) {
                let version = self
                    .peers
                    .get(&identity)
                    .filter(|doc| !doc.lists_removed(&app))
                    .map(IdentityDoc::version);
                return Ok(identity_needed(version));
            }
        }
        // Step 3: the header.
        let Ok(parsed) = parse_header(&request.body) else {
            return Ok(bad(ErrorCode::BadRequest, "envelope", json!(null)));
        };
        let kids: Vec<[u8; 8]> = parsed.kids().collect();
        // Step 5: every kid the current key of a current app, every app added since among
        // the targets.
        let mut stale = Vec::new();
        let mut not_current = BTreeSet::new();
        let mut unknown = Vec::new();
        let mut targets = Vec::new();
        for kid in &kids {
            match self.holder_of(kid) {
                Some(holder) if self.apps.get(&holder).is_some_and(|a| a.departed) => {
                    not_current.insert(zbase32_encode(&holder));
                }
                Some(holder) if self.current_kid(&holder) == Some(*kid) => {
                    targets.push(holder);
                }
                Some(holder) => {
                    let record = self.apps.get(&holder).and_then(|a| a.receive_key.clone());
                    stale.push(json!({ "app_id": zbase32_encode(&holder), "record": record }));
                }
                None => unknown.push(b64(kid)),
            }
        }
        let added: Vec<Value> = self
            .reachable()
            .into_iter()
            .filter(|reached| {
                self.reachable_since
                    .get(reached)
                    .is_some_and(|since| *since > sealed_for)
                    && !targets.contains(reached)
                    && !(sender.is_none() && *reached == app)
            })
            .filter_map(|reached| {
                let held = self.apps.get(&reached)?;
                Some(json!({ "app_id": zbase32_encode(&reached),
                             "app_record": held.record.clone()?,
                             "record": held.receive_key.clone()? }))
            })
            .collect();
        if !stale.is_empty() || !not_current.is_empty() || !unknown.is_empty() || !added.is_empty()
        {
            return Ok(bad(
                ErrorCode::StaleKey,
                "stale key",
                json!({ "receive_keys": stale, "not_current": not_current,
                        "unknown_kids": unknown, "added_apps": added,
                        "apps_version": self.apps_version }),
            ));
        }
        // The append brings the pressure: the lagging marks are judged first, so a lagging
        // app stops holding the quota before it is counted (Dispatch wire 7.4.4).
        self.judge_lagging();
        // A fresh append spends its named code even if admission already existed.
        let accepted_at = self.now().max(self.stamped_ms);
        if let Some(hash) = invite_code_hash {
            if add_reply_grant {
                if let Err(refusal) = self.shared.check_peer_capacity(
                    &identity,
                    PeerReason::Reply,
                    &self.admission_limits(),
                ) {
                    return Ok(super::batch::refused(&refusal));
                }
                self.service_transition(ServiceTransition::ReplyAdd {
                    pubky: identity,
                    code_hash: hash,
                    at: accepted_at,
                })?;
                self.shared.grant_reply(
                    identity,
                    pubky_dispatch_core::admission::ReplyOrigin::Invite(hash),
                    accepted_at,
                );
                self.shared.connect.retain(|(pubky, _)| *pubky != identity);
            }
            let invite = self.shared.invites.get_mut(&hash).ok_or_else(|| {
                ScriptError::Missing("the code selected for this append is absent".into())
            })?;
            invite.uses += 1;
        }
        if sender.is_some() && !add_reply_grant {
            self.shared.note_reply_grant_used(&identity, accepted_at);
        }
        let seq = self.next_seq();
        self.items.push(Item::Entry {
            seq,
            sender: identity,
            cert: cert.signed().clone(),
            accepted_at,
            envelope: request.body.clone(),
            targets,
            invite_code_hash,
        });
        // And judged again with the entry in.
        self.judge_lagging();
        let answer = json!({
            "entry_id": Self::entry_id(seq),
            "accepted_at": rfc3339(accepted_at),
            "directory_version": self.directory_version,
            "known_version": if sender.is_some() { self.known(&identity) } else { Value::Null },
        });
        self.appended
            .insert((identity, request.body.clone()), answer.clone());
        Ok((200, answer))
    }
}

/// `403 not_admitted`, which carries no `current` (Dispatch wire 7.6).
/// Whether `method` `route` (the path after `/v1/{id}/`) is a call of Dispatch wire 7.4.
fn is_route(method: &str, route: &str) -> bool {
    let segments: Vec<&str> = route.split('/').collect();
    matches!(
        (method, segments.as_slice()),
        ("PUT" | "GET", ["identity"])
            | (
                "POST",
                ["inbox"] | ["ops"] | ["connect"] | ["freeze"] | ["unfreeze"]
            )
            | (
                "POST",
                ["import"] | ["erase"] | ["recovery", "admission" | "upload"]
            )
            | (
                "POST",
                ["import", "activate"] | ["apps", _, "keys" | "leave" | "revoke"]
            )
            | (
                "GET",
                ["feed"] | ["allow"] | ["connect"] | ["records"] | ["directory"]
            )
            | (
                "GET",
                ["apps"] | ["export"] | ["claims", _] | ["records", _]
            )
            | ("GET", ["apps", _, "keys"] | ["export", "chunks", _])
            | (
                "PUT",
                ["peers"] | ["push"] | ["handover"] | ["import", "chunks", _]
            )
            | ("GET", ["handover"])
            | ("DELETE", ["connect", _])
    )
}

fn not_admitted() -> Answer {
    bad(ErrorCode::NotAdmitted, "not admitted", json!(null))
}

/// `403 permission_missing` to an app of another identity at a read only own apps make.
fn own_reads_only() -> Answer {
    bad(
        ErrorCode::PermissionMissing,
        "7.4: only the account's own apps make this read",
        json!(null),
    )
}

/// `409 identity_needed`, with `known_version`, the version of the sender's `identity.json`
/// the Dispatch holds, `null` for none or as to a stranger, as in `current` (Dispatch wire 7.1,
/// 7.6; `crates/pubky-dispatch/src/service/inbox.rs`, `identity_needed`).
fn identity_needed(version: Option<u64>) -> Answer {
    let (status, mut body) = bad(
        ErrorCode::IdentityNeeded,
        "identity needed",
        json!({ "version": version }),
    );
    body["known_version"] = json!(version);
    (status, body)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A request of `method` to `path` from another identity's app carrying `cert`.
    fn foreign(
        method: &str,
        path: &str,
        cert: &pubky_dispatch_core::records::AppCert,
    ) -> crate::transport::Request {
        crate::transport::Request {
            method: method.into(),
            origin: crate::testing::DISPATCH_ORIGIN.into(),
            path_and_query: path.into(),
            headers: vec![crate::transport::Header {
                name: header::CERT.into(),
                value: cert.signed().compact(),
            }],
            body: b"{}".to_vec(),
            timeout: crate::transport::TimeoutClass::Bulk,
        }
    }

    /// A scripted Dispatch, and the certificate of an app of another identity.
    fn dispatch_and_stranger() -> (std::sync::Arc<ScriptedDispatch>, AppCert) {
        let identity = pubky_dispatch_core::keys::IdentityKey::from_secret([1; 32]);
        let dispatch = ScriptedDispatch::new(
            &identity,
            [2; 32],
            std::sync::Arc::new(crate::clock::TestClock::new(1_000)),
        );
        let other = pubky_dispatch_core::keys::IdentityKey::from_secret([7; 32]);
        let keys = pubky_dispatch_core::keys::AppKeys::from_secrets([8; 32], [9; 32]);
        let cert = AppCert::issue(
            &other,
            pubky_dispatch_core::records::AppCertBody::new(
                other.public(),
                keys.signing_public(),
                keys.bundle_public(),
                vec!["notes".into()],
                &[],
                0,
                86_400_000,
            ),
        )
        .unwrap();
        (dispatch, cert)
    }

    #[test]
    fn test_scripted_other_identity_reads_only_own_apps_make_are_refused() {
        // `403 permission_missing` at the reads only own apps make, as at the service
        // (`crates/pubky-dispatch/src/service/rules.rs`, `other_app_refusal`); a batch keeps
        // `403 not_admitted` (Dispatch wire 6.4 step 1, 7.4.4, 7.6).
        let (dispatch, cert) = dispatch_and_stranger();
        let mut inner = dispatch.lock();
        let sender = Sender {
            identity: cert.identity(),
            app: Some(cert.app_id()),
            code: None,
        };
        let key = b64(&[3; 32]);
        let calls = [
            ("GET", "feed".to_owned(), "permission_missing"),
            ("GET", "feed?after=0".to_owned(), "permission_missing"),
            ("GET", format!("claims/{key}"), "permission_missing"),
            ("GET", "allow".to_owned(), "permission_missing"),
            (
                "GET",
                format!("records?collection={key}"),
                "permission_missing",
            ),
            ("GET", format!("records/{key}"), "permission_missing"),
            ("POST", "ops".to_owned(), "not_admitted"),
        ];
        for (method, rest, code) in calls {
            let request = foreign(method, &format!("/{rest}"), &cert);
            let (status, body) = inner.route_foreign(&request, &sender, &rest).unwrap();
            assert_eq!(
                (status, &body["code"]),
                (403, &json!(code)),
                "{method} {rest}"
            );
        }
    }

    #[test]
    fn test_scripted_other_identity_at_own_app_and_signer_calls_is_refused() {
        // `403 permission_missing` at every call only an own app or the signer makes, as
        // at the service (`crates/pubky-dispatch/src/service/rules.rs`, `other_app_refusal`).
        let (dispatch, cert) = dispatch_and_stranger();
        let mut inner = dispatch.lock();
        let sender = Sender {
            identity: cert.identity(),
            app: Some(cert.app_id()),
            code: None,
        };
        let app = zbase32_encode(&cert.app_id());
        let calls = [
            ("GET", format!("apps/{app}/keys")),
            ("POST", format!("apps/{app}/keys")),
            ("POST", format!("apps/{app}/leave")),
            ("POST", format!("apps/{app}/revoke")),
            ("GET", "apps".to_owned()),
            ("GET", "handover".to_owned()),
            ("PUT", "handover".to_owned()),
            ("PUT", "identity".to_owned()),
            ("POST", "recovery/admission".to_owned()),
            ("POST", "erase".to_owned()),
        ];
        for (method, rest) in calls {
            let request = foreign(method, &format!("/{rest}"), &cert);
            let (status, body) = inner.route_foreign(&request, &sender, &rest).unwrap();
            assert_eq!(
                (status, &body["code"]),
                (403, &json!("permission_missing")),
                "{method} {rest}"
            );
        }
    }

    #[test]
    fn test_scripted_append_query_is_read_before_admission() {
        // The query is decoded, and a parameter given twice refused, before any check of
        // the append, as at the service (Dispatch wire 7.1): a stranger gets `400`, not `403
        // not_admitted`.
        let (dispatch, cert) = dispatch_and_stranger();
        let mut inner = dispatch.lock();
        let sender = Sender {
            identity: cert.identity(),
            app: Some(cert.app_id()),
            code: None,
        };
        for rest in [
            "inbox?apps_version=0&apps_version=0",
            "inbox?apps_version=%zz",
        ] {
            let request = foreign("POST", &format!("/{rest}"), &cert);
            let (status, body) = inner.route_foreign(&request, &sender, rest).unwrap();
            assert_eq!(
                (status, &body["code"]),
                (400, &json!("bad_request")),
                "{rest}"
            );
        }
        let rest = "inbox?apps_version=%30";
        let request = foreign("POST", &format!("/{rest}"), &cert);
        let (_, body) = inner.route_foreign(&request, &sender, rest).unwrap();
        assert_eq!(body["code"], json!("not_admitted"), "decoded, then judged");
    }

    #[test]
    fn test_scripted_identity_needed_carries_known_version() {
        // `409 identity_needed` carries `known_version`, `null` for no copy held, beside
        // `current` (Dispatch wire 7.1, 7.6; `crates/pubky-dispatch/src/service/inbox.rs`).
        let (dispatch, cert) = dispatch_and_stranger();
        let mut inner = dispatch.lock();
        inner.open_admission = true;
        let sender = Sender {
            identity: cert.identity(),
            app: Some(cert.app_id()),
            code: None,
        };
        let rest = "inbox?apps_version=0";
        let request = foreign("POST", &format!("/{rest}"), &cert);
        let (status, body) = inner.route_foreign(&request, &sender, rest).unwrap();
        assert_eq!((status, &body["code"]), (409, &json!("identity_needed")));
        assert_eq!(body["current"], json!({ "version": null }));
        let members = body.as_object().unwrap();
        assert_eq!(members.get("known_version"), Some(&Value::Null));
    }

    #[test]
    fn test_scripted_foreign_app_at_an_own_call_is_permission_missing() {
        // An app of another identity at a call only own apps or the signer make gets
        // `403 permission_missing`, as at the service; at a batch, `403 not_admitted`
        // (Dispatch wire 6.4 step 1, 7.6).
        let identity = pubky_dispatch_core::keys::IdentityKey::from_secret([1; 32]);
        let dispatch = ScriptedDispatch::new(
            &identity,
            [2; 32],
            std::sync::Arc::new(crate::clock::TestClock::new(1_000)),
        );
        let mut inner = dispatch.lock();
        let other = pubky_dispatch_core::keys::IdentityKey::from_secret([7; 32]);
        let keys = pubky_dispatch_core::keys::AppKeys::from_secrets([8; 32], [9; 32]);
        let body = pubky_dispatch_core::records::AppCertBody::new(
            other.public(),
            keys.signing_public(),
            keys.bundle_public(),
            vec!["notes".into()],
            &[],
            0,
            86_400_000,
        );
        let cert = AppCert::issue(&other, body).unwrap();
        let sender = Sender {
            identity: other.public(),
            app: Some(cert.app_id()),
            code: None,
        };
        for (method, rest, code) in [
            ("POST", "recovery/upload", "permission_missing"),
            ("GET", "feed", "permission_missing"),
            ("GET", "records", "permission_missing"),
            ("POST", "ops", "not_admitted"),
            ("GET", "no/such/route", "not_found"),
        ] {
            let request = foreign(method, &format!("/{rest}"), &cert);
            let (status, body) = inner.route_foreign(&request, &sender, rest).unwrap();
            let expected = if code == "not_found" { 404 } else { 403 };
            assert_eq!(
                (status, &body["code"]),
                (expected, &json!(code)),
                "{method} {rest}"
            );
        }
    }

    #[test]
    fn test_scripted_staged_admission_holds_senders_back() {
        // While admission is staged after a provider loss, a sender the Dispatch can't
        // otherwise admit gets `503 staged` at `PUT /peers`, the inbox and the directory,
        // and `403 not_admitted` once it ends, `POST /connect` included, whatever the policy
        // (Dispatch spec 12.6 step 2; wire 7.4.3, 7.4.5, 7.4.7, 7.4.10).
        let identity = pubky_dispatch_core::keys::IdentityKey::from_secret([1; 32]);
        let dispatch = ScriptedDispatch::new(
            &identity,
            [2; 32],
            std::sync::Arc::new(crate::clock::TestClock::new(1_000)),
        );
        let mut inner = dispatch.lock();
        let other = pubky_dispatch_core::keys::IdentityKey::from_secret([7; 32]);
        let keys = pubky_dispatch_core::keys::AppKeys::from_secrets([8; 32], [9; 32]);
        let cert = AppCert::issue(
            &other,
            pubky_dispatch_core::records::AppCertBody::new(
                other.public(),
                keys.signing_public(),
                keys.bundle_public(),
                vec!["notes".into()],
                &[],
                0,
                86_400_000,
            ),
        )
        .unwrap();
        let sender = Sender {
            identity: other.public(),
            app: Some(cert.app_id()),
            code: None,
        };
        let calls = [
            ("PUT", "/peers", "peers"),
            ("POST", "/inbox?apps_version=0", "inbox?apps_version=0"),
            ("GET", "/directory", "directory"),
            ("POST", "/connect", "connect"),
        ];
        for (staged, code) in [(true, "staged"), (false, "not_admitted")] {
            inner.admission_staged = staged;
            for (method, path, rest) in calls {
                let request = foreign(method, path, &cert);
                let (_, body) = inner.route_foreign(&request, &sender, rest).unwrap();
                assert_eq!(
                    body["code"],
                    json!(code),
                    "{method} {path}, staged {staged}"
                );
            }
        }
    }

    #[test]
    fn test_scripted_connect_check_five_is_the_services() {
        // At the service (`crates/pubky-dispatch/src/service/connect.rs`, check 5 by the
        // certificate, Dispatch wire 7.2): a held copy that doesn't list the app, or lists it
        // with another certificate, is `409 identity_needed` naming the held version; a
        // closed renewal `403 not_current`; the scripted Dispatch answers alike.
        use pubky_dispatch_core::records::{
            IdentityBody, IdentityPolicy, Inbox, ListedApp, RenewedCert,
        };
        let (dispatch, cert) = dispatch_and_stranger();
        let mut inner = dispatch.lock();
        let own = pubky_dispatch_core::keys::IdentityKey::from_secret([1; 32]);
        let mut policy = IdentityPolicy::default();
        policy.connect_requests.enabled = true;
        let key = inner.service.verifying_key().to_bytes();
        let body = IdentityBody::first(
            own.public(),
            [0; 16],
            Inbox::new(crate::testing::DISPATCH_ORIGIN, key),
            policy,
        );
        inner.doc = Some(IdentityDoc::sign(&own, body).unwrap());
        let other = pubky_dispatch_core::keys::IdentityKey::from_secret([7; 32]);
        let copy = |edit: &dyn Fn(&mut IdentityBody)| {
            let mut body = IdentityBody::first(
                other.public(),
                [0; 16],
                Inbox::new(crate::testing::DISPATCH_ORIGIN, [5; 32]),
                IdentityPolicy::default(),
            );
            edit(&mut body);
            IdentityDoc::sign(&other, body).unwrap()
        };
        let another = ListedApp {
            app_id: cert.app_id(),
            cert: [9; 32],
        };
        let sender = Sender {
            identity: other.public(),
            app: Some(cert.app_id()),
            code: None,
        };
        let request = foreign("POST", "/connect", &cert);
        let cases = [
            (
                "not listed",
                copy(&|_| {}),
                (409, json!("identity_needed"), json!(1)),
            ),
            (
                "another certificate",
                copy(&|b| b.apps = vec![another]),
                (409, json!("identity_needed"), json!(1)),
            ),
            (
                "renewal closed",
                copy(&|b| {
                    b.apps = vec![another];
                    b.renewed = vec![RenewedCert {
                        app_id: cert.app_id(),
                        cert: cert.hash(),
                        until: Some(1),
                    }];
                }),
                (403, json!("not_current"), Value::Null),
            ),
            (
                "removed",
                copy(&|b| {
                    b.removed = vec![pubky_dispatch_core::records::RemovedApp {
                        app_id: cert.app_id(),
                        distrust_from: 1,
                    }];
                }),
                (409, json!("identity_needed"), Value::Null),
            ),
        ];
        let mut differences = Vec::new();
        for (what, doc, service) in cases {
            inner.peers.insert(other.public(), doc);
            let (status, body) = inner.route_foreign(&request, &sender, "connect").unwrap();
            let got = (
                status,
                body["code"].clone(),
                body.get("known_version").cloned().unwrap_or(Value::Null),
            );
            if got != service {
                differences.push(format!("{what}: scripted {got:?}, service {service:?}"));
            }
        }
        assert!(differences.is_empty(), "{}", differences.join("\n"));
    }

    #[test]
    fn test_scripted_peers_copy_lost_to_a_restore_is_behind() {
        // `PUT /peers` counts at the scripted Dispatch as at the service: a stranger's copy,
        // acknowledged at a serving account, moves the count and the mark; a restore that
        // loses it is behind, though the head is the mark's (Dispatch wire 7.3, "The state").
        use pubky_dispatch_core::records::{IdentityBody, IdentityPolicy, Inbox};
        let (dispatch, cert) = dispatch_and_stranger();
        let mut inner = dispatch.lock();
        let own = pubky_dispatch_core::keys::IdentityKey::from_secret([1; 32]);
        let mut policy = IdentityPolicy::default();
        policy.connect_requests.enabled = true;
        let key = inner.service.verifying_key().to_bytes();
        let body = IdentityBody::first(
            own.public(),
            [0; 16],
            Inbox::new(crate::testing::DISPATCH_ORIGIN, key),
            policy,
        );
        inner.doc = Some(IdentityDoc::sign(&own, body).unwrap());
        assert_eq!(inner.judge(), super::super::marks::Verdict::Healthy);
        let (seq, count) = (inner.seq, inner.state_version);
        let other = pubky_dispatch_core::keys::IdentityKey::from_secret([7; 32]);
        let copy = IdentityDoc::sign(
            &other,
            IdentityBody::first(
                other.public(),
                [0; 16],
                Inbox::new(crate::testing::DISPATCH_ORIGIN, [5; 32]),
                IdentityPolicy::default(),
            ),
        )
        .unwrap();
        let sender = Sender {
            identity: other.public(),
            app: Some(cert.app_id()),
            code: None,
        };
        let mut request = foreign("PUT", "/peers", &cert);
        request.body = serde_json::to_vec(copy.signed()).unwrap();
        let (status, _) = inner.route_foreign(&request, &sender, "peers").unwrap();
        assert_eq!(status, 200);
        inner.settle_mark();
        assert_eq!((inner.seq, inner.state_version), (seq, count + 1));
        // The same copy again changes nothing, and counts nothing.
        let (status, _) = inner.route_foreign(&request, &sender, "peers").unwrap();
        assert_eq!(status, 200);
        assert_eq!(inner.state_version, count + 1);
        drop(inner);
        assert_eq!(dispatch.mark_state_version(), Some(count + 1));
        dispatch.restore_to(seq);
        assert_eq!(dispatch.state_version(), count);
        assert!(matches!(
            dispatch.lock().judge(),
            super::super::marks::Verdict::Failing(notice)
                if notice.reason == pubky_dispatch_core::http::NoticeReason::Behind
        ));
    }

    #[test]
    fn test_scripted_upload_lists_answer_a_connect_request() {
        // The service writes an upload's list entries with `put_list_entry`, which removes
        // the sender's pending connect request (`crates/pubky-dispatch/src/store/ops.rs`).
        // The scripted merge removes both requests too.
        let (dispatch, _) = dispatch_and_stranger();
        let mut inner = dispatch.lock();
        inner.shared.connect.push(([4; 32], 1));
        inner.shared.connect.push(([6; 32], 1));
        let lists = pubky_dispatch_core::recovery::UploadLists {
            kept: Some(vec![[4; 32]]),
            deny: Some(vec![[6; 32]]),
        };
        let mut changes = pubky_dispatch_core::recovery::UploadChanges::default();
        inner
            .shared
            .merge_upload(
                &pubky_dispatch_core::recovery::CheckedUpload::default(),
                Some(&lists),
                100,
                pubky_dispatch_core::ops::Position {
                    generation: 1,
                    seq: 1,
                },
                1,
                &mut changes,
            )
            .expect("upload lists");
        assert!(
            inner.shared.connect.is_empty(),
            "{:?}",
            inner.shared.connect
        );
    }

    #[test]
    fn test_scripted_connect_reads_and_declines_need_their_permissions() {
        // As at the service: the signer, holding neither `lists.read` nor
        // `reply.add`, reads no connect requests and declines none, and neither the
        // signer nor an own app asks to connect.
        let (dispatch, _) = dispatch_and_stranger();
        let mut inner = dispatch.lock();
        inner.shared.connect.push(([4; 32], 1));
        let pubky = pubky_dispatch_core::enc::pubky_id(&[4; 32]);
        for (method, rest) in [
            ("GET", "connect".to_string()),
            ("DELETE", format!("connect/{pubky}")),
            ("POST", "connect".to_string()),
        ] {
            let request = crate::transport::Request {
                method: method.into(),
                origin: crate::testing::DISPATCH_ORIGIN.into(),
                path_and_query: format!("/{rest}"),
                headers: Vec::new(),
                body: Vec::new(),
                timeout: crate::transport::TimeoutClass::Bulk,
            };
            let (status, body) = inner.route_shared(&request, None, &rest).unwrap();
            assert_eq!(
                (status, body["code"].clone()),
                (403, json!("permission_missing")),
                "{method} {rest}"
            );
        }
        assert_eq!(inner.shared.connect.len(), 1, "nothing declined");
    }

    #[test]
    fn test_scripted_connect_cap_is_the_wires_at_most() {
        // A policy's `max_pending` above `max_connect_pending` is capped at it, as at the
        // service; one below it applies.
        use pubky_dispatch_core::records::{IdentityBody, IdentityPolicy, Inbox};
        let (dispatch, _) = dispatch_and_stranger();
        let mut inner = dispatch.lock();
        let own = pubky_dispatch_core::keys::IdentityKey::from_secret([1; 32]);
        let key = inner.service.verifying_key().to_bytes();
        for (asked, applies) in [(MAX_CONNECT_PENDING + 1, MAX_CONNECT_PENDING), (3, 3)] {
            let mut policy = IdentityPolicy::default();
            policy.connect_requests.enabled = true;
            policy.connect_requests.max_pending = asked;
            let body = IdentityBody::first(
                own.public(),
                [0; 16],
                Inbox::new(crate::testing::DISPATCH_ORIGIN, key),
                policy,
            );
            inner.doc = Some(IdentityDoc::sign(&own, body).unwrap());
            assert_eq!(inner.connect_cap(), applies);
        }
    }
}
