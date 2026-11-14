//! `POST /v1/enroll` (Switch wire 3.7, 7.4.1).

use pubky_switch_core::{
    Error as CoreError,
    enc::pubky_key,
    http::{self as wire_http, RequestTarget, header},
    records::{Enrollment, EnrollmentAnswer, IdentityDoc, Limits as AnnouncedLimits},
    sig::SignedDoc,
};

use super::{
    Answer, Service,
    rules::{Caller, decode_claim},
    signed::{Asked, sign_answer},
    store_error,
    verdict::{self, RequestClass, Route, Verdict},
};
use crate::{
    http::{
        SwitchRequest, SwitchResponse,
        error::{ApiError, ErrorCode},
    },
    limits::{Limits, fixed},
    marks::{MarkRead, MarkWrite},
    store::NewAccount,
};

/// The limits an enrollment answer announces (Switch wire 3.7).
pub(crate) fn announced_limits(limits: &Limits) -> AnnouncedLimits {
    AnnouncedLimits {
        app_limit: u64::from(limits.app_limit),
        max_envelope: fixed::MAX_ENVELOPE,
        max_sealed_value: fixed::MAX_SEALED_VALUE,
        quota_bytes: limits.quota_bytes,
        max_batch: fixed::MAX_BATCH,
        record_quota_bytes: limits.record_quota_bytes,
        max_import_bytes: limits.max_import_bytes,
    }
}

/// Read and check the enrollment a request carries: `{ "enrollment": signed<Enrollment> }`,
/// for `identity` at `origin` (Switch wire 3.7, 7.4.1).
pub fn read_enrollment(
    body: &[u8],
    identity: &[u8; 32],
    origin: &str,
) -> Result<Enrollment, ApiError> {
    let value: serde_json::Value = pubky_switch_core::json::parse_json(body)
        .map_err(|_| ApiError::bad_request("7.4.1: the body isn't strict JSON"))?;
    let signed: SignedDoc = value
        .get("enrollment")
        .cloned()
        .and_then(|enrollment| serde_json::from_value(enrollment).ok())
        .ok_or_else(|| ApiError::bad_request("7.4.1: the body carries no enrollment"))?;
    Enrollment::verify(&signed, identity, origin).map_err(|error| match error {
        CoreError::Signature(_) => ApiError::new(
            ErrorCode::BadSignature,
            "3.7: the identity didn't sign the enrollment",
        ),
        _ => ApiError::bad_request("3.7: the enrollment breaks a rule"),
    })
}

/// What an enrollment's answer names, and the service time it is answered at.
struct Enrolled {
    time_ms: u64,
    limits: AnnouncedLimits,
    /// The account's creation time (Switch wire 3.7).
    created: u64,
}

impl Service {
    /// `POST /v1/enroll`, from the signer (Switch wire 3.7, 7.4.1): the answer, and every
    /// error, signed with the service's current key, the one the answer names, without a
    /// head.
    pub(super) async fn enroll(
        &self,
        request: &SwitchRequest,
        base_ms: u64,
        signature: Asked<'_>,
    ) -> SwitchResponse {
        let current = self.keys.current();
        let refuse = |error: &ApiError| Self::signed_error(&current, signature, base_ms, error);
        let (enrollment, identity_text) = match self.check_enrollment(request, base_ms) {
            Ok(checked) => checked,
            Err(error) => return refuse(&error),
        };
        match self
            .answer_enrollment(&enrollment, &identity_text, base_ms)
            .await
        {
            Ok(Enrolled {
                time_ms,
                limits,
                created,
            }) => {
                // The one place the answer is built (Switch wire 3.7).
                let answer = EnrollmentAnswer::new(
                    &enrollment,
                    super::PublicKeyBytes::public_key_bytes(&current),
                    limits,
                    created,
                );
                match answer.to_json() {
                    Ok(body) => sign_answer(&current, signature, time_ms, Answer::ok(body)),
                    Err(_) => refuse(&ApiError::unavailable("7.6: a temporary failure")),
                }
            }
            // At the identity's service time, which no answer shows going back (Switch wire
            // 7.1 Timestamp, 7.3 step 3).
            Err((error, time_ms)) => Self::signed_error(&current, signature, time_ms, &error),
        }
    }

    /// The request's checks: the signer of its own identity, then the enrollment.
    fn check_enrollment(
        &self,
        request: &SwitchRequest,
        base_ms: u64,
    ) -> Result<(Enrollment, String), ApiError> {
        let identity_text = request
            .headers
            .get(header::IDENTITY)
            .and_then(|value| value.to_str().ok())
            .ok_or_else(|| ApiError::bad_request("7.1: Switch-Identity is missing"))?
            .to_string();
        let identity = pubky_key(&identity_text)
            .map_err(|_| ApiError::bad_request("7.1: Switch-Identity isn't a Pubky ID"))?;
        let claimed = decode_claim(&identity, &request.headers, base_ms)?;
        if claimed.caller != Caller::Signer {
            return Err(ApiError::new(
                ErrorCode::PermissionMissing,
                "7.4.1: only the signer enrolls",
            ));
        }
        let target = RequestTarget {
            method: &request.method,
            path_and_query: &request.path_and_query,
            body: &request.body,
            origin: &self.origin,
        };
        wire_http::verify_request(&identity, &target, &claimed.headers, &claimed.signature)
            .map_err(|_| {
                ApiError::new(
                    ErrorCode::BadSignature,
                    "7.1: the request signature doesn't verify",
                )
            })?;
        let enrollment = read_enrollment(&request.body, &identity, &self.origin)?;
        Ok((enrollment, identity_text))
    }

    /// What the enrollment's answer names, under the verdict of the identity's account and
    /// mark (Switch wire 3.7, 7.3 Tables 2 and 3): a new account's, or an existing one's. A
    /// refusal comes with the identity's service time it is answered at.
    async fn answer_enrollment(
        &self,
        enrollment: &Enrollment,
        identity_text: &str,
        base_ms: u64,
    ) -> Result<Enrolled, (ApiError, u64)> {
        let unavailable = || ApiError::unavailable("7.6: a temporary failure");
        // An account that the first row of Table 1 erases again goes first, so the enrollment
        // makes a new account and answers nothing from the old one; a leftover mark goes too.
        let (found, judged) = self
            .judge_at_step_two(identity_text)
            .await
            .map_err(|error| (error, base_ms))?;
        // The identity's service time (Switch wire 7.1 Timestamp, 7.3 step 3).
        let service_ms = found
            .as_ref()
            .map_or(base_ms, |found| base_ms.max(found.stamped_time_ms));
        let at = |error: ApiError| (error, service_ms);
        let enrollment_hash = enrollment
            .signed()
            .doc_hash()
            .map_err(|_| at(unavailable()))?;
        let routed = verdict::answer(&judged.judgement, &RequestClass::Enroll, self.current_key());
        match routed.route {
            Route::CreateAccount | Route::TakeOverMark if found.is_none() => {
                if let Some(created) = self
                    .create_account(enrollment, identity_text, enrollment_hash, base_ms)
                    .await
                    .map_err(at)?
                {
                    return Ok(created);
                }
                // Another enrollment made the account first: answered as at an account that
                // exists.
            }
            Route::Proceed { head: false } => {}
            // While the mark store can't be read no mark is created (Switch wire 7.4.1).
            Route::Unavailable => {
                return Err(at(ApiError::unavailable(
                    "7.4.1: the mark store can't be read",
                )));
            }
            _ => return Err(at(unavailable())),
        }
        self.enroll_at_account(enrollment, identity_text, enrollment_hash, base_ms)
            .await
            .map_err(at)
    }

    /// Create the identity's account (Switch wire 7.3, Table 3), all under the identity's
    /// lock, which every erasure and every other enrollment of the identity takes too: the
    /// identity judged again, and the creation time read, there; the mark first, (0, 0)
    /// durably with the current key and the creation time, then the account, at that same
    /// time. A (0, 0) mark without an account, left by a crash between the two or a restore,
    /// is taken, and so is a lost account's mark, whose head and retirements stay: the
    /// account is then staged and bounded. An erasure's leftover mark is deleted first.
    /// `None` when another enrollment made the account first.
    async fn create_account(
        &self,
        enrollment: &Enrollment,
        identity_text: &str,
        enrollment_hash: [u8; 32],
        base_ms: u64,
    ) -> Result<Option<Enrolled>, ApiError> {
        let unavailable = || ApiError::unavailable("7.6: a temporary failure");
        let mark_failure = |failure: crate::marks::MarkStoreError, what: &'static str| {
            tracing::error!(%failure, what);
            unavailable()
        };
        let mut lock = self
            .store
            .lock_identity(identity_text)
            .await
            .map_err(|e| store_error(&e))?;
        if lock.has_account().await.map_err(|e| store_error(&e))? {
            return Ok(None);
        }
        let inputs = self.mark_inputs(identity_text).await;
        let judged = self.judge_with(identity_text, None, inputs).await;
        let routed = verdict::answer(&judged.judgement, &RequestClass::Enroll, self.current_key());
        match routed.route {
            Route::CreateAccount | Route::TakeOverMark => {}
            Route::Unavailable => {
                return Err(ApiError::unavailable("7.4.1: the mark store can't be read"));
            }
            _ => return Err(unavailable()),
        }
        let key = self.current_key();
        // Created after every erasure's record of the identity, so it is never taken for one
        // a restored database brought back, and after the creation of any mark it takes over,
        // so an erasure that named the earlier time never reaches it (Switch wire 7.3, Table 1
        // and "The mark"). Read under the lock, so no record or mark changes before the
        // account commits.
        let created_at_ms = [
            judged.erasure_at_ms,
            judged.mark().map(|mark| mark.created_at_ms),
        ]
        .into_iter()
        .flatten()
        .fold(base_ms, |at, earlier| at.max(earlier.saturating_add(1)));
        let leftover = matches!(
            judged.judgement.verdict,
            Verdict::NotHosted { delete_mark: true }
        );
        if leftover && let Some(erased_at_ms) = judged.erasure_at_ms {
            // An erasure's leftover isn't taken: it is deleted first (Table 3).
            self.marks
                .delete_created_by(identity_text, erased_at_ms)
                .await
                .map_err(|failure| mark_failure(failure, "deleting an erasure's leftover mark"))?;
        }
        let marked = match judged.mark() {
            Some(held) if !leftover => self
                .marks
                .take(identity_text, *held, key, created_at_ms)
                .await
                .map_err(|failure| mark_failure(failure, "taking a mark over"))?,
            _ => self
                .marks
                .create_zero(identity_text, key, created_at_ms)
                .await
                .map_err(|failure| mark_failure(failure, "writing a new account's mark"))?,
        };
        if !matches!(marked, MarkWrite::Written(_)) {
            // Under the lock nothing else writes the mark: one changed meanwhile is a store
            // that changed under the service.
            return Err(unavailable());
        }
        let limits = announced_limits(&self.limits);
        let account = NewAccount {
            id: identity_text.to_string(),
            identity_key: enrollment.body().identity,
            generation: enrollment.identity_doc().map_or(1, IdentityDoc::generation),
            created_at_ms,
            limits,
            identity_doc: enrollment.identity_doc().map(|doc| doc.signed().clone()),
            revoked_apps: enrollment.revoked_apps().to_vec(),
            enrollment_hash,
        };
        let creation = lock
            .create(&account)
            .await
            .map_err(|e| store_error(&e))?
            .ok_or_else(unavailable)?;
        creation.commit().await.map_err(|e| store_error(&e))?;
        // Answered at the time it was created, which may be past `base_ms`.
        Ok(Some(Enrolled {
            time_ms: created_at_ms,
            limits,
            created: created_at_ms,
        }))
    }

    /// An enrollment at an account that exists (Switch wire 3.7, 7.3 Table 3), under the
    /// identity's lock and the account's: it changes nothing by itself, but at a serving
    /// account its `revoked_apps` are held for the next generation, and at a staged account
    /// that no document names yet the mark's key becomes the key the answer names, durably
    /// before the commit.
    async fn enroll_at_account(
        &self,
        enrollment: &Enrollment,
        identity_text: &str,
        enrollment_hash: [u8; 32],
        base_ms: u64,
    ) -> Result<Enrolled, ApiError> {
        let unavailable = || ApiError::unavailable("7.6: a temporary failure");
        let mut txn = self
            .store
            .begin(identity_text)
            .await
            .map_err(|e| store_error(&e))?
            .ok_or_else(unavailable)?;
        let time_ms = txn.stamp(base_ms);
        let limits = txn.announced_limits().await.map_err(|e| store_error(&e))?;
        // The account's creation time, read under the lock: the mark's, or the account's
        // own where the mark is lost (Switch wire 3.7).
        let created = match self.marks.read(identity_text).await {
            Ok(MarkRead::Mark(mark)) => mark.created_at_ms,
            Ok(MarkRead::Missing | MarkRead::NotAMark) => txn.head().created_at_ms,
            Err(failure) => {
                tracing::error!(%failure, "reading a mark");
                return Err(ApiError::unavailable("7.4.1: the mark store can't be read"));
            }
        };
        let held = txn
            .held_identity()
            .await
            .map_err(|e| store_error(&e))?
            .map(|held| IdentityDoc::verify(&held.doc, &enrollment.body().identity))
            .transpose()
            .map_err(|_| unavailable())?;
        let key = self.current_key();
        let serving = held.as_ref().is_some_and(|doc| {
            doc.inbox().url == self.origin
                && self.keys.signer_for(&doc.inbox().service_key).is_some()
        });
        if serving {
            txn.hold_revoked_apps(enrollment.revoked_apps())
                .await
                .map_err(|e| store_error(&e))?;
        }
        txn.keep_enrollment_answer(&enrollment_hash, time_ms, self.limits.max_enrollments)
            .await
            .map_err(|e| store_error(&e))?;
        if !serving && let Err(failure) = self.marks.set_key(identity_text, key, created).await {
            tracing::error!(%failure, "a staged account's mark taking the current key");
            return Err(unavailable());
        }
        txn.commit().await.map_err(|e| store_error(&e))?;
        Ok(Enrolled {
            time_ms,
            limits,
            created,
        })
    }
}
