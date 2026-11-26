//! An interrupted first creation stays at its original service (Dispatch account binding 3).

use super::*;
use crate::Backend;
use crate::flows::occurrence;
use pubky_dispatch_client::ClientError;
use pubky_dispatch_signer::{
    Alert, FirstEnrollmentStop, Refusal, SignerError, SignerStatus, UserConfirmed,
};

#[tokio::test]
async fn test_first_enrollment_answer_scripted() {
    check_first_answer(Backend::Scripted).await;
}

#[tokio::test]
async fn test_first_enrollment_answer_service() {
    check_first_answer(Backend::Service).await;
}

async fn check_first_answer(backend: Backend) {
    for applied in [true, false] {
        let result = Box::pin(crate::run_here(backend, async |world: &World| {
            Box::pin(first_answer(world, applied)).await
        }))
        .await;
        assert!(
            matches!(result, Ok(Some(_))),
            "applied {applied}: {result:?}"
        );
    }
}

async fn first_answer(world: &World, applied: bool) -> FlowResult {
    let alice = world.identity("alice")?;
    world.add_dispatch(ORIGIN, &[&alice]).await?;
    let env = world.signer_env(&alice, Arc::new(MemoryStore::new()))?;
    let mut signer = Signer::create(env.clone(), world.keyring(&alice)?, ORIGIN).await?;
    if applied {
        world.lose_answer("POST", "/v1/enroll");
    } else {
        world.unreachable("POST", "/v1/enroll");
    }
    assert!(matches!(
        Box::pin(signer.resume()).await,
        Err(SignerError::Dispatch(ClientError::Transport(_)))
    ));
    if applied {
        // An intermediary is reachable while the original service's receipt is unavailable.
        world.refuse("POST", "/v1/enroll", 400, "bad_request");
        assert!(matches!(
            Box::pin(signer.resume()).await,
            Err(SignerError::Dispatch(ClientError::BadServiceSignature {
                status: 400
            }))
        ));
    } else {
        world.advance_ms(301_000);
        assert!(
            matches!(Box::pin(signer.resume()).await, Err(SignerError::Dispatch(ClientError::Dispatch { current, .. })) if current == json!({"binding": "expired"}))
        );
    }
    drop(signer);
    let mut signer = Signer::open(env, world.keyring(&alice)?).await?;
    let alert = Alert::FirstEnrollmentHeld {
        reason: if applied {
            FirstEnrollmentStop::Unconfirmed
        } else {
            FirstEnrollmentStop::Expired
        },
    };
    assert_eq!(signer.status(), SignerStatus::FirstEnrollmentHeld);
    assert_eq!(signer.alerts(), std::slice::from_ref(&alert));
    let sent = world.requests_sent();
    assert_eq!(
        Box::pin(signer.run_due()).await.unwrap_err(),
        Refusal::FirstEnrollmentHeld.into()
    );
    assert_eq!(
        Box::pin(signer.resume()).await.unwrap_err(),
        Refusal::FirstEnrollmentHeld.into()
    );
    assert_eq!(
        world.requests_sent(),
        sent,
        "unattended setup resent the enrollment"
    );
    assert!(signer.identity_doc()?.is_none());
    if applied {
        signer.clear_alert(&occurrence(&signer, &alert)).await?;
        assert_eq!(world.requests_sent(), sent);
        Box::pin(signer.resume()).await?;
    } else {
        Box::pin(signer.restart_first_enrollment(ORIGIN, UserConfirmed::shown_and_confirmed()))
            .await?;
    }
    assert_eq!(signer.status(), SignerStatus::Signing);
    assert!(signer.alerts().is_empty());
    assert_eq!(world.enrollments_sent(), if applied { 1 } else { 2 });
    let doc = signer.identity_doc()?.ok_or("missing first document")?;
    assert_eq!(
        (doc.version(), doc.generation(), doc.body().signer),
        (1, 1, signer.install_id())
    );
    assert_eq!(
        world
            .files()
            .identity_doc(&alice.public())
            .map(|copy| copy.hash()),
        Some(doc.hash())
    );
    Ok(())
}
