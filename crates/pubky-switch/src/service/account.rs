//! Authenticated, read-only account discovery and creation bindings (Switch account
//! binding 1-3). Observations describe one confirmed store without changing its records.

use pubky_switch_core::{
    enc::{pubky_id, pubky_key},
    http::{self as wire_http, RequestTarget, Uncompared, header},
    records::{ACCOUNT_OBSERVATION_VALIDITY_MS, AccountObservationBody},
    time::{MAX_TIME_MS, rfc3339},
};

use super::{
    Answer, Service,
    marking::Judged,
    rules::{Caller, decode_claim},
    signed::{AnswerTime, Asked, sign_answer},
    store_error,
    verdict::{self, MarkInput, RequestClass, Route, Verdict},
};
use crate::http::{
    SwitchRequest, SwitchResponse,
    error::{ApiError, ErrorCode},
};

/// An authenticated intent names a different current creation (Switch account binding 1).
pub(super) fn creation_conflict(created: u64) -> ApiError {
    ApiError::new(ErrorCode::Conflict, "account binding: another creation")
        .with_current(serde_json::json!({ "created": rfc3339(created) }))
}

/// Carried authority no longer describes the current store/account tuple.
pub(super) fn binding_changed() -> ApiError {
    ApiError::new(ErrorCode::Conflict, "account binding: changed")
        .with_current(serde_json::json!({ "binding": "changed" }))
}

/// Check an existing-account request before request-dependent mutations. The caller holds
/// the identity lock and has established a coherent, resolved judgement.
pub(super) fn check_creation(request: &SwitchRequest, judged: &Judged) -> Result<(), ApiError> {
    let headers = request.signed_headers();
    let bound = headers
        .text(header::CREATED)
        .ok_or_else(|| ApiError::bad_request("account binding: Switch-Created is missing"))
        .and_then(|text| {
            wire_http::parse_created(text)
                .map_err(|_| ApiError::bad_request("account binding: invalid creation"))
        })?;
    let created = judged
        .created_at_ms()?
        .ok_or_else(|| ApiError::unavailable("account binding: creation is unknown"))?;
    if bound != created {
        return Err(creation_conflict(created));
    }
    Ok(())
}

impl Service {
    /// An authenticated signer checks its creation before a failing account's endpoint
    /// verdict. A request queued behind erasure reads the new state under the same lock
    /// (Switch account binding 1); nothing is stamped or swept here.
    pub(super) async fn signer_notice_under_lock(
        &self,
        identity: &str,
        request: &SwitchRequest,
        class: &RequestClass,
        asked: Asked<'_>,
        base_ms: u64,
    ) -> SwitchResponse {
        let result = async {
            let mut lock = self
                .store
                .lock_identity(identity)
                .await
                .map_err(|e| store_error(&e))?;
            let store_id = self
                .marks
                .identity()
                .await
                .map_err(|_| discovery_unavailable())?;
            let inputs = self.mark_inputs(identity).await;
            let found = crate::store::Store::lookup_with(lock.conn(), identity)
                .await
                .map_err(|e| store_error(&e))?;
            let account = found.as_ref().map(|found| self.found_input(found));
            let judged = self
                .judge_with(lock.conn(), identity, account, inputs)
                .await;
            if self
                .marks
                .identity()
                .await
                .map_err(|_| discovery_unavailable())?
                != store_id
                || judged.judgement.decision.erase_account_again
            {
                return Err(discovery_unavailable());
            }
            let routed = verdict::answer(&judged.judgement, class, self.current_key());
            let committed_ms = found.as_ref().map(|found| found.stamped_time_ms);
            if judged.created_at_ms()?.is_some()
                && !matches!(routed.route, Route::Unavailable)
                && !matches!(
                    judged.judgement.decision.verdict,
                    Verdict::NotHosted { delete_mark: true }
                )
                && let Err(error) = check_creation(request, &judged)
            {
                return Ok(self.keyed_error(
                    &routed.key,
                    asked,
                    AnswerTime::TimeBase(base_ms, Uncompared::CreationConflict),
                    &error,
                ));
            }
            self.verdict_answer(identity, &routed, asked, base_ms, committed_ms)
                .ok_or_else(discovery_unavailable)
        }
        .await;
        result.unwrap_or_else(|error| {
            self.service_error(
                asked,
                AnswerTime::TimeBase(base_ms, Uncompared::Unavailable),
                &error,
            )
        })
    }

    pub(super) async fn get_account(
        &self,
        request: &SwitchRequest,
        base_ms: u64,
        asked: Asked<'_>,
    ) -> SwitchResponse {
        let key = self.keys.current();
        let at = AnswerTime::TimeBase(base_ms, Uncompared::AccountDiscovery);
        let result = async {
            let identity = request
                .route
                .account
                .as_deref()
                .ok_or_else(|| ApiError::bad_request("account binding: identity is missing"))?;
            if let Some(error) = self.limited_before_authentication(identity, request, base_ms) {
                return Err(error);
            }
            let identity_key = self
                .authenticate_discovery(request, identity, base_ms)
                .inspect_err(|error| {
                    if super::is_failed_authentication(error.code) {
                        self.record_failure(request, identity.to_string());
                    }
                })?;
            let mut lock = self
                .store
                .lock_identity(identity)
                .await
                .map_err(|e| store_error(&e))?;
            // Read the identity first and last: a later successful low-level read cannot
            // turn a mixed-store observation into current absence (account binding 2).
            let store_id = self
                .marks
                .identity()
                .await
                .map_err(|_| discovery_unavailable())?;
            let inputs = self.mark_inputs(identity).await;
            let found = crate::store::Store::lookup_with(lock.conn(), identity)
                .await
                .map_err(|e| store_error(&e))?;
            let account = found.as_ref().map(|found| self.found_input(found));
            let judged = self
                .judge_with(lock.conn(), identity, account, inputs)
                .await;
            if matches!(judged.mark, MarkInput::StoreUnreadable)
                || (matches!(judged.mark, MarkInput::NotAMark) && judged.account.is_none())
                || judged.judgement.decision.erase_account_again
                || judged.erasure_at_ms.is_some_and(|erased| {
                    judged
                        .mark()
                        .is_some_and(|mark| mark.created_at_ms <= erased)
                })
                || matches!(
                    judged.judgement.decision.verdict,
                    Verdict::Unknown | Verdict::NotHosted { delete_mark: true }
                )
                || self
                    .marks
                    .identity()
                    .await
                    .map_err(|_| discovery_unavailable())?
                    != store_id
            {
                return Err(discovery_unavailable());
            }
            let binding = judged
                .account_binding()
                .map_err(|_| discovery_unavailable())?;
            // No account-stamped or caller-selected time can mint this authority.
            let observed_at = self
                .time
                .read()
                .trusted_ms
                .ok_or_else(discovery_unavailable)?;
            let expires_at = observed_at
                .checked_add(ACCOUNT_OBSERVATION_VALIDITY_MS)
                .filter(|at| *at <= MAX_TIME_MS)
                .ok_or_else(discovery_unavailable)?;
            let body = AccountObservationBody {
                identity: identity_key,
                origin: self.origin.clone(),
                service_key: super::PublicKeyBytes::public_key_bytes(&key),
                store_id,
                association: binding.association(),
                created: binding.created(),
                erased_at: judged.erasure_at_ms,
                observed_at,
                expires_at,
            }
            .to_json()
            .map_err(|_| discovery_unavailable())?;
            Ok(sign_answer(
                &key,
                asked,
                AnswerTime::TimeBase(observed_at, Uncompared::AccountDiscovery),
                Answer::ok(body),
            ))
        }
        .await;
        result.unwrap_or_else(|error| Self::signed_error(&key, asked, at, &error))
    }

    fn authenticate_discovery(
        &self,
        request: &SwitchRequest,
        identity: &str,
        base_ms: u64,
    ) -> Result<[u8; 32], ApiError> {
        let identity_key = pubky_key(identity)
            .map_err(|_| ApiError::bad_request("account binding: invalid identity"))?;
        if pubky_id(&identity_key) != identity
            || !request.body.is_empty()
            || request.path_and_query.contains('?')
        {
            return Err(ApiError::bad_request(
                "account binding: discovery has a canonical path and no query or body",
            ));
        }
        let headers = request.signed_headers();
        if [
            header::APP,
            header::CERT,
            header::INVITE_CODE,
            header::TRANSFER,
            header::CREATED,
        ]
        .into_iter()
        .any(|name| headers.text(name).is_some())
        {
            return Err(ApiError::bad_request(
                "account binding: discovery carries only identity, timestamp and signature",
            ));
        }
        let claimed = decode_claim(&identity_key, &headers, base_ms)?;
        if claimed.caller != Caller::Signer {
            return Err(ApiError::new(
                ErrorCode::PermissionMissing,
                "account binding: only the signer discovers",
            ));
        }
        wire_http::verify_request(
            &identity_key,
            &RequestTarget {
                method: &request.method,
                path_and_query: &request.path_and_query,
                body: &request.body,
                origin: &self.origin,
            },
            &claimed.headers,
            &claimed.signature,
        )
        .map_err(|_| {
            ApiError::new(
                ErrorCode::BadSignature,
                "7.1: the request signature doesn't verify",
            )
        })?;
        Ok(identity_key)
    }
}

fn discovery_unavailable() -> ApiError {
    ApiError::unavailable("account binding: current state or trusted time is unavailable")
}
