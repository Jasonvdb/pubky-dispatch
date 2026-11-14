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
    marking::Judged,
    rules::{Caller, decode_claim},
    signed::{Asked, sign_answer},
    store_error,
    verdict::{self, RequestClass, Route},
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
            Err(error) => refuse(&error),
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
    /// mark (Switch wire 3.7, 7.3 Tables 2 and 3): a new account's, or an existing one's.
    async fn answer_enrollment(
        &self,
        enrollment: &Enrollment,
        identity_text: &str,
        base_ms: u64,
    ) -> Result<Enrolled, ApiError> {
        let unavailable = || ApiError::unavailable("7.6: a temporary failure");
        let enrollment_hash = enrollment.signed().doc_hash().map_err(|_| unavailable())?;
        // An account that the first row of Table 1 erases again goes first, so the enrollment
        // makes a new account and answers nothing from the old one; a leftover mark goes too.
        let (found, judged) = self.judge_at_step_two(identity_text).await?;
        let routed = verdict::answer(&judged.judgement, &RequestClass::Enroll, self.current_key());
        match routed.route {
            Route::CreateAccount | Route::TakeOverMark if found.is_none() => {
                if let Some(created) = self
                    .create_account(enrollment, identity_text, &judged, enrollment_hash, base_ms)
                    .await?
                {
                    return Ok(created);
                }
                // Another enrollment made the account first: answered as at an account that
                // exists.
            }
            Route::Proceed { head: false } => {}
            // While the mark store can't be read no mark is created (Switch wire 7.4.1).
            Route::Unavailable => {
                return Err(ApiError::unavailable("7.4.1: the mark store can't be read"));
            }
            _ => return Err(unavailable()),
        }
        self.enroll_at_account(enrollment, identity_text, &judged, enrollment_hash, base_ms)
            .await
    }

    /// Create the identity's account (Switch wire 7.3, Table 3): the mark first, (0, 0)
    /// durably with the current key and the creation time, then the account. A (0, 0) mark
    /// without an account, left by a crash between the two or a restore, is taken, and so is
    /// a lost account's mark, whose head and retirements stay: the account is then staged and
    /// bounded. `None` when another enrollment made the account first.
    async fn create_account(
        &self,
        enrollment: &Enrollment,
        identity_text: &str,
        judged: &Judged,
        enrollment_hash: [u8; 32],
        base_ms: u64,
    ) -> Result<Option<Enrolled>, ApiError> {
        let unavailable = || ApiError::unavailable("7.6: a temporary failure");
        if !self.lock_is_fresh() {
            return Err(unavailable());
        }
        let key = self.current_key();
        // Created after every erasure's record of the identity, so it is never taken for one
        // a restored database brought back, and after the creation of any mark it takes over,
        // so an erasure that named the earlier time never reaches it (Switch wire 7.3, Table 1
        // and "The mark").
        let created_at_ms = [
            judged.erasure_at_ms,
            judged.mark().map(|mark| mark.created_at_ms),
        ]
        .into_iter()
        .flatten()
        .fold(base_ms, |at, earlier| at.max(earlier.saturating_add(1)));
        let marked = self
            .marks
            .create_zero(identity_text, key, created_at_ms)
            .await
            .map_err(|failure| {
                tracing::error!(%failure, "writing a new account's mark");
                unavailable()
            })?;
        match marked {
            MarkWrite::Written(_) => {}
            // An erasure's leftover isn't taken: it is deleted first.
            MarkWrite::Unchanged(MarkRead::Mark(held))
                if judged
                    .erasure_at_ms
                    .is_some_and(|at| at >= held.created_at_ms) =>
            {
                return Err(unavailable());
            }
            MarkWrite::Unchanged(MarkRead::Mark(_)) => {
                match self.marks.take(identity_text, key, created_at_ms).await {
                    Ok(MarkWrite::Written(_)) => {}
                    Ok(MarkWrite::Unchanged(_)) => return Err(unavailable()),
                    Err(failure) => {
                        tracing::error!(%failure, "taking a mark over");
                        return Err(unavailable());
                    }
                }
            }
            MarkWrite::Unchanged(MarkRead::Missing | MarkRead::NotAMark) => {
                return Err(unavailable());
            }
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
        let Some(creation) = self
            .store
            .begin_create(&account)
            .await
            .map_err(|e| store_error(&e))?
        else {
            return Ok(None);
        };
        // The ledger is read after the insert: an erasure that committed before it recorded
        // its record first (Table 3).
        let ledger = self.keys.erasure(identity_text).await.map_err(|failure| {
            tracing::error!(%failure, "reading the erasure ledger");
            unavailable()
        })?;
        let created = creation.commit(ledger).await.map_err(|e| store_error(&e))?;
        // Raised past a record made meanwhile: the mark takes the account's creation time.
        if created != created_at_ms
            && !matches!(
                self.marks.take(identity_text, key, created).await,
                Ok(MarkWrite::Written(_))
            )
        {
            tracing::error!("a new account's mark didn't take its creation time");
        }
        // Answered at the time it was created, which may be past `base_ms`.
        Ok(Some(Enrolled {
            time_ms: created,
            limits,
            created,
        }))
    }

    /// An enrollment at an account that exists (Switch wire 3.7, 7.3 Table 3): it changes
    /// nothing by itself, but at a serving account its `revoked_apps` are held for the next
    /// generation, and at a staged account that no document names yet the mark's key
    /// becomes the key the answer names.
    async fn enroll_at_account(
        &self,
        enrollment: &Enrollment,
        identity_text: &str,
        judged: &Judged,
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
        // The account's creation time: the mark's, or the account's own where the mark is
        // lost (Switch wire 3.7).
        let created = judged
            .mark()
            .map_or(txn.head().created_at_ms, |mark| mark.created_at_ms);
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
        txn.commit().await.map_err(|e| store_error(&e))?;
        if !serving && let Err(failure) = self.marks.set_key(identity_text, key).await {
            tracing::error!(%failure, "a staged account's mark taking the current key");
            return Err(unavailable());
        }
        Ok(Enrolled {
            time_ms,
            limits,
            created,
        })
    }
}
