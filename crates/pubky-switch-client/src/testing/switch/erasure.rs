//! Observable pending, rejected and committed erasure outcomes (Switch wire 7.3).

use super::*;
use pubky_switch_core::http::{RequestHeaders, RequestTarget, parse_erase_body, verify_request};

/// The retained outcome of one authenticated erasure whose answer is unavailable.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ErasureOutcome {
    /// The account remains and no outcome is known.
    Unresolved,
    /// The account is absent but no outcome evidence remains.
    UnresolvedAbsent,
    /// Deletion committed; its external completed record is not yet published.
    Committed,
    /// Non-application is established; the pending attempt is not yet withdrawn.
    Rejected,
}

#[derive(Clone, Debug)]
pub(super) struct Attempt {
    created: u64,
    identity_hash: Option<[u8; 32]>,
    at: u64,
    outcome: ErasureOutcome,
}

impl ScriptedSwitch {
    /// Retain this outcome after the next erasure passes its normal binding checks.
    pub fn fail_next_erasure(&self, outcome: ErasureOutcome) {
        self.lock().next_erasure_outcome = Some(outcome);
    }
}

impl Inner {
    pub(super) fn erasure_fault(&mut self, created: u64) -> Option<Answer> {
        let selected_account = self.account_binding().ok()?.association()
            == pubky_switch_core::records::AccountAssociation::Account;
        let outcome = self.next_erasure_outcome.take()?;
        let attempt = Attempt {
            created,
            identity_hash: self
                .doc
                .as_ref()
                .filter(|_| selected_account)
                .map(IdentityDoc::hash),
            at: self.now().max(created),
            outcome,
        };
        if matches!(
            outcome,
            ErasureOutcome::Committed | ErasureOutcome::UnresolvedAbsent
        ) {
            self.drop_account();
        }
        self.marks.attempt = Some(attempt);
        Some(bad(
            ErrorCode::Unavailable,
            "the erasure outcome is unresolved",
            Value::Null,
        ))
    }

    /// Completed and rejected evidence may be reconciled by a read. An unknown attempt
    /// requires a new authenticated erasure; account presence is not outcome evidence.
    pub(super) fn pending_erasure(&mut self, request: &Request) -> Option<Response> {
        let attempt = self.marks.attempt.clone()?;
        if self.marks.unreadable {
            return None;
        }
        match attempt.outcome {
            ErasureOutcome::Committed => {
                self.marks.erasure_at_ms = Some(attempt.at);
                self.marks.slot = marks::MarkSlot::Missing;
                self.marks.attempt = None;
                return None;
            }
            ErasureOutcome::Rejected => {
                self.marks.attempt = None;
                return None;
            }
            ErasureOutcome::Unresolved | ErasureOutcome::UnresolvedAbsent => {}
        }
        let answer = if request.method == "POST" && request.path_and_query.ends_with("/erase") {
            self.retry_erasure(request, &attempt)
        } else {
            bad(
                ErrorCode::Unavailable,
                "the erasure outcome is unresolved",
                Value::Null,
            )
        };
        let at = if self.hosts() {
            self.stamped_ms
        } else {
            self.now()
        };
        Some(self.respond_signed(&self.service, request, answer.0, &answer.1, at, None))
    }

    fn retry_erasure(&mut self, request: &Request, attempt: &Attempt) -> Answer {
        if let Some(refused) = self.erasure_timestamp_refusal(request) {
            return refused;
        }
        if request.header(header::APP).is_some() {
            return bad(
                ErrorCode::PermissionMissing,
                "only the signer erases",
                Value::Null,
            );
        }
        let headers = RequestHeaders {
            timestamp: request
                .header(header::TIMESTAMP)
                .unwrap_or_default()
                .to_owned(),
            identity: request
                .header(header::IDENTITY)
                .unwrap_or_default()
                .to_owned(),
            app: None,
            cert: request.header(header::CERT).map(str::to_owned),
            invite_code: request.header(header::INVITE_CODE).map(str::to_owned),
            created: request.header(header::CREATED).map(str::to_owned),
        };
        let target = RequestTarget {
            method: &request.method,
            origin: &request.origin,
            path_and_query: &request.path_and_query,
            body: &request.body,
        };
        let verified = request
            .header(header::SIGNATURE)
            .and_then(|text| unb64_array::<64>(text).ok())
            .is_some_and(|signature| {
                headers.identity == pubky_id(&self.identity.public())
                    && verify_request(&self.identity.public(), &target, &headers, &signature)
                        .is_ok()
            });
        if !verified {
            return bad(
                ErrorCode::BadSignature,
                "the signer did not sign the erasure",
                Value::Null,
            );
        }
        if self.hosts() {
            self.marks.attempt = None;
            let answer = self.erase_answer(request);
            if answer.0 != 200 {
                self.marks.attempt = Some(attempt.clone());
            }
            return answer;
        }
        let named = match parse_erase_body(&request.body) {
            Ok(named) => named,
            Err(_) => {
                return bad(
                    ErrorCode::BadRequest,
                    "the erasure body is invalid",
                    Value::Null,
                );
            }
        };
        if named.created != Some(attempt.created) || named.identity_hash != attempt.identity_hash {
            return bad(
                ErrorCode::Conflict,
                "the erasure names another account or document",
                json!({"created": rfc3339(attempt.created), "identity": null}),
            );
        }
        self.marks.erasure_at_ms = Some(self.now().max(attempt.at));
        self.marks.slot = marks::MarkSlot::Missing;
        self.marks.attempt = None;
        (200, json!({"erased": true}))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scripted_unresolved_erasure_does_not_sweep_account_state() {
        let identity = IdentityKey::from_secret([1; 32]);
        let clock = Arc::new(TestClock::new(100_000));
        let switch = ScriptedSwitch::new(&identity, [2; 32], clock);
        {
            let mut inner = switch.lock();
            inner.shared.invites.insert(
                [3; 32],
                shared::Invite {
                    max_uses: 1,
                    uses: 0,
                    writer: [4; 16],
                    expires_at: 1,
                },
            );
            let created = inner.creation_time();
            inner.marks.attempt = Some(Attempt {
                created,
                identity_hash: None,
                at: 100_000,
                outcome: ErasureOutcome::Unresolved,
            });
        }
        let request = Request {
            method: "GET".into(),
            origin: SWITCH_ORIGIN.into(),
            path_and_query: format!("/v1/{}/identity", identity.id()),
            headers: Vec::new(),
            body: Vec::new(),
            timeout: crate::transport::TimeoutClass::Bulk,
        };
        let answer = switch.handle(&request).unwrap();
        assert_eq!(answer.status, 503);
        assert_eq!(switch.lock().shared.invites.len(), 1);
        switch.lock().marks.attempt.as_mut().unwrap().outcome = ErasureOutcome::Rejected;
        let answer = switch.handle(&request).unwrap();
        assert_eq!(answer.status, 200);
        assert!(switch.lock().shared.invites.is_empty());
    }
}
