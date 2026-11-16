//! Read-only account observations and signed enrollment authority (Switch account binding
//! 1-3). The mark store's identity stays separate from the account it describes.

use pubky_switch_core::http::{self, RequestHeaders, RequestTarget};
use pubky_switch_core::records::{
    ACCOUNT_OBSERVATION_VALIDITY_MS, AccountAssociation, AccountBinding, AccountMarkInput,
    AccountObservationBody, Enrollment, EnrollmentIntent, ObservationValidity,
};
use pubky_switch_core::time::{MAX_TIME_MS, parse_rfc3339};

use super::{marks::MarkSlot, *};

pub(super) fn binding_changed() -> Answer {
    bad(
        ErrorCode::Conflict,
        "account binding: changed",
        json!({ "binding": "changed" }),
    )
}

pub(super) fn unavailable() -> Answer {
    bad(
        ErrorCode::Unavailable,
        "account binding: current state is unavailable",
        Value::Null,
    )
}

impl Inner {
    /// Authenticate independently of a hosted account, before any request-dependent
    /// mutation (Switch account binding 1-3).
    pub(super) fn authenticate_signer(&self, request: &Request) -> Result<(), Answer> {
        let headers = RequestHeaders {
            identity: request
                .header(header::IDENTITY)
                .unwrap_or_default()
                .to_owned(),
            timestamp: request
                .header(header::TIMESTAMP)
                .unwrap_or_default()
                .to_owned(),
            app: request.header(header::APP).map(str::to_owned),
            cert: request.header(header::CERT).map(str::to_owned),
            invite_code: request.header(header::INVITE_CODE).map(str::to_owned),
            created: request.header(header::CREATED).map(str::to_owned),
        };
        if headers.app.is_some() {
            return Err(bad(
                ErrorCode::PermissionMissing,
                "only the signer calls",
                Value::Null,
            ));
        }
        if headers.identity != self.identity.id() {
            return Err(bad(
                ErrorCode::BadSignature,
                "the request names another identity",
                Value::Null,
            ));
        }
        let timestamp = parse_rfc3339(&headers.timestamp).map_err(|_| {
            bad(
                ErrorCode::BadRequest,
                "invalid request timestamp",
                Value::Null,
            )
        })?;
        if headers.timestamp.len() != 20 || !headers.timestamp.ends_with('Z') {
            return Err(bad(
                ErrorCode::BadRequest,
                "invalid request timestamp",
                Value::Null,
            ));
        }
        if timestamp.abs_diff(self.now()) > pubky_switch_core::records::CLOCK_TOLERANCE_MS {
            return Err(bad(
                ErrorCode::StaleTimestamp,
                "request time is stale",
                json!({ "server_time": rfc3339(self.now()) }),
            ));
        }
        let signature = request
            .header(header::SIGNATURE)
            .and_then(|text| unb64_array::<64>(text).ok())
            .ok_or_else(|| bad(ErrorCode::BadSignature, "no signer signature", Value::Null))?;
        let target = RequestTarget {
            method: &request.method,
            origin: &self.origin,
            path_and_query: &request.path_and_query,
            body: &request.body,
        };
        http::verify_request(&self.identity.public(), &target, &headers, &signature).map_err(|_| {
            bad(
                ErrorCode::BadSignature,
                "the signer did not sign the request",
                Value::Null,
            )
        })
    }

    /// Refuse an ordinary creation binding before pending-erasure resolution, timestamps,
    /// sweeps or endpoint effects, under the same account lock (Switch account binding 1).
    pub(super) fn ordinary_binding_refusal(&self, request: &Request) -> Option<Response> {
        let path = request.path_and_query.split('?').next().unwrap_or_default();
        if http::is_public_read(&request.method, &request.path_and_query)
            || (request.method == "GET" && path.ends_with("/account"))
            || (request.method == "POST" && path == "/v1/enroll")
        {
            return None;
        }
        let (status, body) = self.check_ordinary_binding(request).err()?;
        let code = body
            .get("code")
            .and_then(Value::as_str)
            .and_then(ErrorCode::parse);
        let uncompared = http::uncompared(
            &request.method,
            &request.path_and_query,
            http::BodyField::read(&request.body),
            status,
            code,
            body.get("current"),
            false,
        );
        let at = if uncompared.is_none() && self.hosts() {
            self.stamped_ms
        } else {
            self.now()
        };
        Some(self.respond_at(&self.service, request, status, &body, at))
    }

    fn check_ordinary_binding(&self, request: &Request) -> Result<(), Answer> {
        let invalid = |message: &str| bad(ErrorCode::BadRequest, message, Value::Null);
        let path = request.path_and_query.split('?').next().unwrap_or_default();
        let suffix = path.splitn(4, '/').nth(3).unwrap_or_default();
        let transfer =
            request.method == "GET" && (suffix == "export" || suffix.starts_with("export/chunks/"));
        let text = request.header(header::CREATED);
        if request.header(header::APP).is_some() || transfer {
            return if text.is_some() {
                Err(invalid("this caller carries no creation header"))
            } else {
                Ok(())
            };
        }
        let created = text
            .ok_or_else(|| invalid("Switch-Created is missing"))
            .and_then(|text| {
                http::parse_created(text).map_err(|_| invalid("invalid account creation"))
            })?;
        if request.method == "POST" && suffix == "erase" {
            let named = http::parse_erase_body(&request.body)
                .map_err(|_| invalid("invalid erasure body"))?;
            if named.created != Some(created) {
                return Err(invalid("erasure body and header differ"));
            }
        }
        self.authenticate_signer(request).map_err(|answer| {
            // Authentication grants no mutation on failure, but Table 2 still decides
            // whether the account's notice takes precedence over that refusal.
            self.verdict_refusal(request, self.judge())
                .unwrap_or(answer)
        })?;
        // Outcome reconciliation retains its existing authority. Only a correctly bound,
        // authenticated retry can reach it; it must not infer absence from uncertainty.
        if matches!(
            self.judge(),
            marks::Verdict::Unknown | marks::Verdict::NotHosted { delete_mark: true }
        ) {
            return Ok(());
        }
        if let Some(current) = self.account_binding()?.created()
            && current != created
        {
            return Err(bad(
                ErrorCode::Conflict,
                "account binding: another creation",
                json!({ "created": rfc3339(current) }),
            ));
        }
        Ok(())
    }

    pub(super) fn account_observation(&self, request: &Request) -> Result<Answer, ScriptError> {
        if request.path_and_query != format!("/v1/{}/account", self.identity.id())
            || !request.body.is_empty()
            || [
                header::APP,
                header::CERT,
                header::INVITE_CODE,
                header::TRANSFER,
                header::CREATED,
            ]
            .iter()
            .any(|name| request.header(name).is_some())
        {
            return Ok(bad(
                ErrorCode::BadRequest,
                "account discovery has no query, body or extra headers",
                Value::Null,
            ));
        }
        if let Err(answer) = self.authenticate_signer(request) {
            return Ok(answer);
        }
        let store_id = match self.confirmed_store() {
            Ok(id) => id,
            Err(answer) => return Ok(answer),
        };
        let binding = match self.account_binding() {
            Ok(binding) => binding,
            Err(answer) => return Ok(answer),
        };
        let created = binding.created();
        let observed_at = self.now();
        let Some(expires_at) = observed_at
            .checked_add(ACCOUNT_OBSERVATION_VALIDITY_MS)
            .filter(|at| *at <= MAX_TIME_MS)
        else {
            return Ok(unavailable());
        };
        if created
            .into_iter()
            .chain(self.marks.erasure_at_ms)
            .any(|at| at > observed_at)
        {
            return Ok(unavailable());
        }
        let body = AccountObservationBody {
            identity: self.identity.public(),
            origin: self.origin.clone(),
            service_key: self.service.verifying_key().to_bytes(),
            store_id,
            association: binding.association(),
            created,
            erased_at: self.marks.erasure_at_ms,
            observed_at,
            expires_at,
        };
        Ok((200, serde_json::from_slice(&body.to_json()?)?))
    }

    /// Confirm current state without reconciling an erasure or sweeping a leftover mark.
    /// Discovery and enrollment cannot infer non-application from absence (Sections 2-3).
    pub(super) fn confirmed_store(&self) -> Result<[u8; 16], Answer> {
        let covered = self.marks.erasure_at_ms.is_some_and(|erased| {
            self.hosts() && self.created_at_ms <= erased
                || matches!(self.marks.slot, MarkSlot::At(mark) if mark.created_at_ms <= erased)
        });
        if self.marks.unreadable
            || self.marks.attempt.is_some()
            || covered
            || (!self.hosts() && self.marks.slot == MarkSlot::Corrupt)
        {
            return Err(unavailable());
        }
        self.marks.identity.ok_or_else(unavailable)
    }

    pub(super) fn account_binding(&self) -> Result<AccountBinding, Answer> {
        let mark = if self.marks.unreadable {
            AccountMarkInput::Unreadable
        } else {
            match self.marks.slot {
                MarkSlot::Missing => AccountMarkInput::Missing,
                MarkSlot::Corrupt => AccountMarkInput::Malformed,
                MarkSlot::At(mark) => AccountMarkInput::Created(mark.created_at_ms),
            }
        };
        AccountBinding::select(self.hosts().then_some(self.created_at_ms), mark)
            .map_err(|_| unavailable())
    }

    pub(super) fn authorize_enrollment(
        &self,
        enrollment: &Enrollment,
        store_id: [u8; 16],
    ) -> Result<(), Answer> {
        let binding = self.account_binding()?;
        match enrollment.body().intent {
            EnrollmentIntent::Existing { created } => {
                if let Some(current) = binding.created()
                    && created != current
                {
                    return Err(bad(
                        ErrorCode::Conflict,
                        "account binding: another creation",
                        json!({ "created": rfc3339(current) }),
                    ));
                }
                if binding.association() != AccountAssociation::Account {
                    return Err(self.notice().map_or_else(
                        || {
                            bad(
                                ErrorCode::NotFound,
                                "identity is not hosted",
                                json!({ "hosted": false }),
                            )
                        },
                        |notice| marks::notice_answer(&notice),
                    ));
                }
            }
            EnrollmentIntent::Create { .. } | EnrollmentIntent::Takeover { .. } => {
                let observation = enrollment.observation().ok_or_else(binding_changed)?;
                match observation.validity(self.now()) {
                    ObservationValidity::Future => return Err(unavailable()),
                    ObservationValidity::Expired => {
                        return Err(bad(
                            ErrorCode::Conflict,
                            "account binding: expired",
                            json!({ "binding": "expired" }),
                        ));
                    }
                    ObservationValidity::Current => {}
                }
                let body = observation.body();
                if body.store_id != store_id
                    || body.service_key != self.service.verifying_key().to_bytes()
                    || body.created != binding.created()
                    || body.association != binding.association()
                    || body.erased_at != self.marks.erasure_at_ms
                {
                    return Err(binding_changed());
                }
                if binding
                    .created()
                    .into_iter()
                    .chain(self.marks.erasure_at_ms)
                    .any(|at| at > self.now())
                {
                    return Err(unavailable());
                }
                let allowed = match enrollment.body().intent {
                    EnrollmentIntent::Create { .. } => {
                        !self.hosts() && self.marks.slot == MarkSlot::Missing
                    }
                    EnrollmentIntent::Takeover { created, .. } => {
                        binding.association() == AccountAssociation::Mark
                            && matches!(self.marks.slot, MarkSlot::At(mark) if mark.created_at_ms == created)
                    }
                    EnrollmentIntent::Existing { .. } => false,
                };
                if !allowed {
                    return Err(binding_changed());
                }
            }
        }
        Ok(())
    }
}
