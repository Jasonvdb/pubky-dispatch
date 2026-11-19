//! Enrollment and the first `identity.json` (Switch spec 12.1, Switch wire 3.7, 7.4.1,
//! 7.4.2, 7.4.15).

use std::sync::Arc;

use pubky_switch_client::client::SentRequest;
use pubky_switch_client::store::MemoryStore;
use pubky_switch_client::testing::TestIdentity;
use pubky_switch_client::transport::{Request, TimeoutClass};
use pubky_switch_core::enc::unb64_array;
use pubky_switch_core::http::{ResponseParts, header, verify_response};
use pubky_switch_core::records::{IDENTITY_PATH, IdentityDoc};
use pubky_switch_signer::Signer;
use serde_json::json;

use super::{ORIGIN, STEP_MS};
use crate::{FlowResult, World};

/// A new identity's signer enrolls at its switch, delivers the first `identity.json` and
/// publishes it; then the same install opens its records again and finds nothing owed.
///
/// Calls: `POST /v1/enroll`, `PUT /v1/{id}/identity`, `GET /v1/{id}/apps`, and the public
/// `GET /v1/{id}/identity`.
///
/// # Errors
///
/// When a step that should succeed against any switch fails.
pub async fn enrollment(world: &World) -> FlowResult {
    let alice = world.identity("alice")?;
    world.add_switch(ORIGIN, &[&alice]).await?;
    let store = Arc::new(MemoryStore::new());

    let env = world.signer_env(&alice, store.clone())?;
    let mut signer = Signer::create(env, world.keyring(&alice)?, ORIGIN).await?;
    world.outcome("created", &status(&signer)?);
    world.advance_ms(STEP_MS);
    signer.resume().await?;
    world.outcome("enrolled", &status(&signer)?);
    let delivered = signer
        .identity_doc()?
        .ok_or("the signer holds no identity.json")?;
    drop(signer);
    world.advance_ms(STEP_MS);
    let published = world.files().identity_doc(&alice.public());
    world.outcome(
        "published",
        &json!({
            "path": IDENTITY_PATH,
            "version": published.as_ref().map(IdentityDoc::version),
        }),
    );

    // Anyone reads the newest `identity.json` from the switch (Switch wire 7.4.15). Neither
    // the client nor the signer makes this call: a reader without keys does, so the flow
    // checks the answer as such a reader would. Its body is the document the signer
    // delivered, byte for byte, and it is signed with the account's service key. Byte for
    // byte is stricter than the wire asks of the answer's own object, whose members a
    // writer may order as it likes (Switch wire 1.1): deliberately so, while both switches
    // write it this way, so that a change of either shows here.
    let path = format!("/v1/{}/identity", alice.key().id());
    let sent = SentRequest::of(&Request {
        method: "GET".into(),
        origin: ORIGIN.into(),
        path_and_query: path.clone(),
        headers: Vec::new(),
        body: Vec::new(),
        timeout: TimeoutClass::default(),
    });
    let answer = world.request("GET", ORIGIN, &path).await?;
    let mut expected = b"{\"identity\":".to_vec();
    expected.extend_from_slice(&serde_json::to_vec(delivered.signed())?);
    expected.push(b'}');
    if answer.body != expected {
        return Err("the public read isn't the delivered identity.json, byte for byte".into());
    }
    let signature = answer
        .header(header::SERVICE_SIGNATURE)
        .and_then(|text| unb64_array::<64>(text).ok())
        .ok_or("the public read carries no service signature")?;
    let server_time = answer
        .header(header::SERVER_TIME)
        .ok_or("the public read carries no service time")?;
    verify_response(
        &delivered.inbox().service_key,
        &ResponseParts {
            status: answer.status,
            request: sent.received(true),
            server_time,
            head: answer.header(header::HEAD),
            body: &answer.body,
        },
        &signature,
    )?;
    world.advance_ms(STEP_MS);

    // The same install after a restart: nothing is owed, and nothing changes.
    let env = world.signer_env(&alice, store)?;
    let mut signer = Signer::open(env, world.keyring(&alice)?).await?;
    signer.resume().await?;
    world.outcome("reopened", &status(&signer)?);
    Ok(())
}

/// A signer of `identity`, enrolled at the switch at `origin` and serving, on a store of its
/// own.
pub(crate) async fn enroll(
    world: &World,
    identity: &TestIdentity,
    origin: &str,
) -> Result<Signer, Box<dyn std::error::Error>> {
    let env = world.signer_env(identity, Arc::new(MemoryStore::new()))?;
    let mut signer = Signer::create(env, world.keyring(identity)?, origin).await?;
    signer.resume().await?;
    world.outcome("enrolled", &status(&signer)?);
    world.advance_ms(STEP_MS);
    Ok(signer)
}

/// An alert, for the trace: as it prints, but for the one that names another install, whose
/// ID is made at random on each run and so is left out.
fn shown_alert(alert: &pubky_switch_signer::Alert) -> String {
    match alert {
        pubky_switch_signer::Alert::ManagedByOtherInstall { .. } => {
            "ManagedByOtherInstall".to_owned()
        }
        other => format!("{other:?}"),
    }
}

/// What a signer shows of itself, for the trace.
pub(crate) fn status(signer: &Signer) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    let doc = signer.identity_doc()?;
    let high_water = signer.high_water()?;
    Ok(json!({
        // The status's name: what it carries, such as another install's ID, differs from
        // run to run.
        "status": format!("{:?}", signer.status())
            .split(|c: char| !c.is_ascii_alphanumeric())
            .next(),
        "version": doc.as_ref().map(pubky_switch_core::records::IdentityDoc::version),
        "generation": doc.as_ref().map(pubky_switch_core::records::IdentityDoc::generation),
        "apps": doc.as_ref().map(|doc| doc.body().apps.len()),
        "high_water_version": high_water.map(|mark| mark.version),
        "high_water_generation": high_water.map(|mark| mark.generation),
        "alerts": signer.alerts().iter().map(shown_alert).collect::<Vec<_>>(),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Backend;
    use pubky_switch_client::client::{Credentials, SwitchClient};
    use pubky_switch_client::transport::Header;
    use pubky_switch_core::enc::{b64, zbase32_encode};
    use pubky_switch_core::keys::IdentityKey;

    #[tokio::test]
    async fn test_expired_first_enrollment_restart_scripted() {
        check_first_enrollment_restart(Backend::Scripted).await;
    }

    #[tokio::test]
    async fn test_expired_first_enrollment_restart_service() {
        check_first_enrollment_restart(Backend::Service).await;
    }

    async fn check_first_enrollment_restart(backend: Backend) {
        for applied in [false, true] {
            let result = Box::pin(crate::run_here(backend, async |world: &World| {
                Box::pin(first_enrollment_restart(world, applied)).await
            }))
            .await;
            assert!(
                matches!(result, Ok(Some(_))),
                "applied {applied}: {result:?}"
            );
        }
    }

    async fn first_enrollment_restart(world: &World, applied: bool) -> FlowResult {
        use pubky_switch_client::ClientError;
        use pubky_switch_core::http::ErrorCode;
        use pubky_switch_signer::{SignerError, SignerStatus, UserConfirmed};

        let alice = world.identity("alice")?;
        world.add_switch(ORIGIN, &[&alice]).await?;
        let env = world.signer_env(&alice, Arc::new(MemoryStore::new()))?;
        let mut signer = Signer::create(env.clone(), world.keyring(&alice)?, ORIGIN).await?;
        let install = signer.install_id();
        if applied {
            world.lose_answer("POST", "/v1/enroll");
        } else {
            world.unreachable("POST", "/v1/enroll");
        }
        assert!(signer.resume().await.is_err());
        assert_eq!(signer.status(), SignerStatus::Enrolling);
        drop(signer);
        world.advance_ms(301_000);
        let mut signer = Signer::open(env.clone(), world.keyring(&alice)?).await?;
        if !applied {
            assert!(
                matches!(signer.resume().await, Err(SignerError::Switch(ClientError::Switch {
                code: ErrorCode::Conflict, current, ..
            })) if current == json!({ "binding": "expired" }))
            );
            assert_eq!(world.enrollments_sent(), 1);
            // Let the exact retry reach the service, then interrupt the newly authorized
            // creation before its first send completes (Switch account binding 3).
            world.unreachable_after("POST", "/v1/enroll", 1);
        }
        let origin = signer
            .first_enrollment_origin()?
            .ok_or("the original service is missing after restart")?
            .to_owned();
        assert_eq!(origin, ORIGIN);
        let restarted = signer
            .restart_first_enrollment(&origin, UserConfirmed::shown_and_confirmed())
            .await;
        if applied {
            restarted?;
        } else {
            assert!(matches!(
                restarted,
                Err(SignerError::Switch(ClientError::Transport(_)))
            ));
            assert_eq!(world.enrollments_sent(), 2);
            drop(signer);
            signer = Signer::open(env, world.keyring(&alice)?).await?;
            signer.resume().await?;
        }
        let doc = signer
            .identity_doc()?
            .ok_or("the first document is missing")?;
        assert_eq!(signer.status(), SignerStatus::Signing);
        assert_eq!(signer.first_enrollment_origin()?, None);
        assert_eq!(
            (doc.version(), doc.generation(), doc.body().signer),
            (1, 1, install)
        );
        assert_eq!(doc.inbox().url, ORIGIN);
        assert_eq!(
            world
                .files()
                .identity_doc(&alice.public())
                .as_ref()
                .map(IdentityDoc::hash),
            Some(doc.hash())
        );
        assert_eq!(world.enrollments_sent(), if applied { 1 } else { 2 });
        assert_eq!(world.faults_left(), 0);
        Ok(())
    }

    #[tokio::test]
    async fn test_first_setup_with_an_existing_account_scripted() {
        check_existing_first_account(Backend::Scripted).await;
    }

    #[tokio::test]
    async fn test_first_setup_with_an_existing_account_service() {
        check_existing_first_account(Backend::Service).await;
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum FirstAccount {
        WithBackup,
        ServiceCopyOnly,
        MarkOnly,
        DamagedStateWithBackup,
        DamagedStateWithServiceCopy,
    }

    async fn check_existing_first_account(backend: Backend) {
        for account in [
            FirstAccount::WithBackup,
            FirstAccount::ServiceCopyOnly,
            FirstAccount::MarkOnly,
            FirstAccount::DamagedStateWithBackup,
            FirstAccount::DamagedStateWithServiceCopy,
        ] {
            let result = Box::pin(crate::run_here(backend, async |world: &World| {
                Box::pin(existing_first_account(world, account)).await
            }))
            .await;
            assert!(matches!(result, Ok(Some(_))), "{account:?}: {result:?}");
        }
        let result = Box::pin(crate::run_here(backend, signed_first_creation_changed)).await;
        assert!(
            matches!(result, Ok(Some(_))),
            "changed signed creation: {result:?}"
        );
    }

    fn damage_first_state(store: &MemoryStore, identity: &TestIdentity) -> FlowResult {
        use pubky_switch_client::store::{StateStore, WriteBatch};
        let namespace = pubky_switch_signer::state::signer_namespace(&identity.public());
        let mut batch = WriteBatch::new();
        batch.put(&namespace, b"state", vec![0])?;
        store.commit(batch)?;
        Ok(())
    }

    async fn signed_first_creation_changed(world: &World) -> FlowResult {
        use pubky_switch_client::ClientError;
        use pubky_switch_core::http::ErrorCode;
        use pubky_switch_signer::{Refusal, SignerError, SignerStatus, UserConfirmed};

        let alice = world.identity("alice")?;
        world.add_switch(ORIGIN, &[&alice]).await?;
        let store = Arc::new(MemoryStore::new());
        let env = world.signer_env(&alice, store.clone())?;
        let mut first = Signer::create(env.clone(), world.keyring(&alice)?, ORIGIN).await?;
        world.unreachable("POST", "/v1/enroll");
        assert!(matches!(
            first.resume().await,
            Err(SignerError::Switch(ClientError::Transport(_)))
        ));
        drop(first);
        let other = enroll(world, &alice, ORIGIN).await?;
        let original = other.identity_doc()?.ok_or("missing current document")?;
        let mut first = Signer::open(env.clone(), world.keyring(&alice)?).await?;
        assert!(
            matches!(first.resume().await, Err(SignerError::Switch(ClientError::Switch {
            code: ErrorCode::Conflict, current, ..
        })) if current == json!({ "binding": "changed" }))
        );
        assert_eq!(first.status(), SignerStatus::Enrolling);
        assert_eq!(
            first
                .restore(UserConfirmed::shown_and_confirmed())
                .await
                .unwrap_err(),
            Refusal::FlowInProgress.into()
        );
        drop(first);
        damage_first_state(&store, &alice)?;
        assert!(matches!(
            Signer::restore_over_unusable(
                env,
                world.keyring(&alice)?,
                pubky_switch_signer::RecordsDiscarded::shown_and_confirmed()
            )
            .await,
            Err(SignerError::Refused(Refusal::FlowInProgress))
        ));
        assert_eq!(
            world
                .files()
                .identity_doc(&alice.public())
                .as_ref()
                .map(IdentityDoc::hash),
            Some(original.hash())
        );
        Ok(())
    }

    async fn existing_first_account(world: &World, account: FirstAccount) -> FlowResult {
        use pubky_switch_client::ClientError;
        use pubky_switch_core::records::SIGNER_BACKUP_PATH;
        use pubky_switch_signer::{
            KeyRecoveryConfirmed, KeyRecoveryStop, Refusal, SignerError, SignerStatus,
            UserConfirmed,
        };

        let alice = world.identity("alice")?;
        world.add_switch(ORIGIN, &[&alice]).await?;
        let mut original = enroll(world, &alice, ORIGIN).await?;
        let previous = original.set_record_max_age(Some(3600)).await?;
        drop(original);
        if matches!(
            account,
            FirstAccount::ServiceCopyOnly
                | FirstAccount::MarkOnly
                | FirstAccount::DamagedStateWithServiceCopy
        ) {
            world.files().remove(alice.public(), SIGNER_BACKUP_PATH);
            world.files().remove(alice.public(), IDENTITY_PATH);
        }
        if account == FirstAccount::MarkOnly {
            world.lose_account(ORIGIN, &alice).await?;
        }

        let store = Arc::new(MemoryStore::new());
        let env = world.signer_env(&alice, store.clone())?;
        let mut signer = Signer::create(env.clone(), world.keyring(&alice)?, ORIGIN).await?;
        let install = signer.install_id();
        let original_enrollments = world.enrollments_sent();
        world.lose_answer("GET", "/account");
        assert!(matches!(
            signer.resume().await,
            Err(SignerError::Switch(ClientError::Transport(_)))
        ));
        assert_eq!(signer.status(), SignerStatus::Enrolling);
        drop(signer);
        let mut signer = Signer::open(env.clone(), world.keyring(&alice)?).await?;
        assert_eq!(
            signer.resume().await,
            Err(Refusal::FirstAccountPresent.into())
        );
        assert_eq!(signer.status(), SignerStatus::FirstAccountPresent);
        assert!(signer.identity_doc()?.is_none());
        assert_eq!(world.enrollments_sent(), original_enrollments);
        let requests = world.requests_sent();
        drop(signer);
        let mut signer = Signer::open(env.clone(), world.keyring(&alice)?).await?;
        assert_eq!(signer.first_enrollment_origin()?, Some(ORIGIN));
        assert_eq!(
            signer.resume().await,
            Err(Refusal::FirstAccountPresent.into())
        );
        assert_eq!(
            signer
                .restart_first_enrollment(ORIGIN, UserConfirmed::shown_and_confirmed())
                .await,
            Err(Refusal::FirstEnrollmentUnavailable.into())
        );
        assert_eq!(world.requests_sent(), requests);

        let confirm = |survey: &pubky_switch_signer::KeyRecoverySurvey| {
            assert!(survey.origin_supplied);
            assert_eq!(survey.origin, ORIGIN);
            assert_eq!(survey.version, previous.version());
            KeyRecoveryConfirmed::shown_and_confirmed(survey, &[])
        };
        let restored = match account {
            FirstAccount::DamagedStateWithBackup | FirstAccount::DamagedStateWithServiceCopy => {
                drop(signer);
                damage_first_state(&store, &alice)?;
                let mut discard = pubky_switch_signer::RecordsDiscarded::shown_and_confirmed();
                if account == FirstAccount::DamagedStateWithServiceCopy {
                    let survey = Box::pin(Signer::survey_key_recovery_new(
                        env.clone(),
                        world.keyring(&alice)?,
                    ))
                    .await?;
                    discard = discard.and_key_recovery(confirm(&survey));
                }
                signer = Box::pin(Signer::restore_over_unusable(
                    env,
                    world.keyring(&alice)?,
                    discard,
                ))
                .await?;
                signer.identity_doc()?.ok_or("missing restored document")?
            }
            FirstAccount::WithBackup => {
                Box::pin(signer.restore(UserConfirmed::shown_and_confirmed())).await?
            }
            FirstAccount::ServiceCopyOnly => {
                let survey = signer.survey_key_recovery().await?;
                Box::pin(signer.restore(confirm(&survey))).await?
            }
            FirstAccount::MarkOnly => {
                assert!(matches!(
                    signer.survey_key_recovery().await,
                    Err(SignerError::Refused(Refusal::KeyRecovery(
                        KeyRecoveryStop::NotServing
                    )))
                ));
                assert_eq!(signer.status(), SignerStatus::FirstAccountPresent);
                assert_eq!(world.enrollments_sent(), original_enrollments);
                return Ok(());
            }
        };
        assert_eq!(signer.status(), SignerStatus::Signing);
        assert_eq!(
            (restored.version(), restored.generation()),
            (previous.version() + 1, previous.generation())
        );
        assert_eq!(restored.body().signer, signer.install_id());
        if !matches!(
            account,
            FirstAccount::DamagedStateWithBackup | FirstAccount::DamagedStateWithServiceCopy
        ) {
            assert_eq!(signer.install_id(), install);
        }
        assert_eq!(restored.inbox(), previous.inbox());
        assert_eq!(restored.body().record_max_age, Some(3600));
        assert_eq!(
            world
                .files()
                .identity_doc(&alice.public())
                .as_ref()
                .map(IdentityDoc::hash),
            Some(restored.hash())
        );
        Ok(())
    }

    #[tokio::test]
    async fn test_public_identity_headers_scripted() {
        check_public_headers(Backend::Scripted, false).await;
    }

    #[tokio::test]
    async fn test_public_identity_headers_service() {
        check_public_headers(Backend::Service, false).await;
    }

    #[tokio::test]
    async fn test_public_identity_app_header_keeps_last_seen_scripted() {
        check_public_headers(Backend::Scripted, true).await;
    }

    #[tokio::test]
    async fn test_public_identity_app_header_keeps_last_seen_service() {
        check_public_headers(Backend::Service, true).await;
    }

    async fn check_public_headers(backend: Backend, seen_only: bool) {
        let result = Box::pin(crate::run_here(backend, async |world: &World| {
            Box::pin(public_headers(world, seen_only)).await
        }))
        .await;
        assert!(matches!(result, Ok(Some(_))), "{result:?}");
    }

    async fn public_headers(world: &World, seen_only: bool) -> FlowResult {
        let alice = world.identity("alice")?;
        world.add_switch(ORIGIN, &[&alice]).await?;
        let mut signer = enroll(world, &alice, ORIGIN).await?;
        let (app, _) =
            super::super::messaging::joined(world, &alice, &mut signer, "wallet").await?;
        let service_key = signer
            .identity_doc()?
            .ok_or("no identity")?
            .inbox()
            .service_key;
        let client = SwitchClient::new(
            ORIGIN,
            alice.public(),
            Credentials::Signer {
                identity: alice.public(),
                key: Arc::new(IdentityKey::from_secret(alice.key().secret_bytes())),
            },
            Some(service_key),
            world.transport(),
            world.clock().clone(),
        )?;
        let created = client
            .observe_account()
            .await?
            .body()
            .created
            .ok_or("the enrolled account has no creation")?;
        let client = client.with_account_created(created)?;
        let before = client
            .apps()
            .await?
            .apps
            .into_iter()
            .find(|status| status.app_id == app.app_id())
            .ok_or("registered app missing")?
            .last_seen;
        world.advance_ms(STEP_MS);
        let id = alice.key().id();
        let path = format!("/v1/{id}/identity");
        let bare = Request {
            method: "GET".into(),
            origin: ORIGIN.into(),
            path_and_query: path,
            headers: Vec::new(),
            body: Vec::new(),
            timeout: TimeoutClass::default(),
        };
        let checked = client.public_identity().await?;
        if checked.identity.identity() != alice.public() || checked.freeze.is_some() {
            return Err("the public read must return the enrolled identity".into());
        }
        let baseline = world.transport().send(bare.clone()).await?;
        if baseline.header("cache-control")
            != Some(pubky_switch_core::http::public_read_cache_control().as_str())
        {
            return Err("the public identity cache lifetime differs".into());
        }
        let cases = if seen_only {
            vec![vec![
                Header::new(header::IDENTITY, &id),
                Header::new(header::APP, &zbase32_encode(&app.app_id())),
            ]]
        } else {
            vec![
                vec![Header::new(header::IDENTITY, &id)],
                vec![Header::new(header::TIMESTAMP, "2000-01-01T00:00:00Z")],
                vec![
                    Header::new(header::IDENTITY, &id),
                    Header::new(header::APP, &zbase32_encode(&[99; 16])),
                ],
                vec![
                    Header::new(header::IDENTITY, &id),
                    Header::new(header::APP, &zbase32_encode(&app.app_id())),
                ],
                vec![
                    Header::new(header::APP, "bad"),
                    Header::new(header::APP, "bad"),
                ],
                vec![
                    Header::new(header::SIGNATURE, "bad"),
                    Header::new(header::CERT, ""),
                    Header::new(header::TIMESTAMP, "never"),
                ],
            ]
        };
        let mut responses = Vec::new();
        for headers in cases {
            let request = Request {
                headers,
                ..bare.clone()
            };
            assert_eq!(
                pubky_switch_core::http::received_request(
                    &SentRequest::of(&request).received(true)
                ),
                pubky_switch_core::http::received_request(&SentRequest::of(&bare).received(true))
            );
            responses.push(world.transport().send(request).await?);
        }
        let after = client
            .apps()
            .await?
            .apps
            .into_iter()
            .find(|status| status.app_id == app.app_id())
            .ok_or("registered app missing")?
            .last_seen;
        if seen_only {
            assert_eq!(after, before, "public headers do not mark an app seen");
            return Ok(());
        }
        let outcomes: Vec<_> = responses
            .iter()
            .map(|answer| {
                (
                    answer.status,
                    answer.body == baseline.body,
                    answer.header(header::HEAD).is_none(),
                )
            })
            .collect();
        assert_eq!(
            outcomes,
            vec![(baseline.status, true, true); responses.len()]
        );
        assert_eq!(baseline.status, 200);
        assert!(baseline.header(header::HEAD).is_none());
        for answer in responses {
            let signature = unb64_array::<64>(
                answer
                    .header(header::SERVICE_SIGNATURE)
                    .ok_or("no signature")?,
            )?;
            verify_response(
                &service_key,
                &ResponseParts {
                    status: answer.status,
                    request: SentRequest::of(&bare).received(true),
                    server_time: answer.header(header::SERVER_TIME).ok_or("no time")?,
                    head: answer.header(header::HEAD),
                    body: &answer.body,
                },
                &signature,
            )?;
            world.outcome(
                "public read",
                &json!({"status": answer.status, "signature": b64(&signature)}),
            );
        }
        Ok(())
    }
}
