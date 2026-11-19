//! An interrupted first creation stays at its original service (Switch account binding 3).

use super::*;
use crate::Backend;
use pubky_switch_client::ClientError;
use pubky_switch_signer::{SignerError, SignerStatus};

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
        assert!(matches!(result, Ok(Some(_))), "applied {applied}: {result:?}");
    }
}

async fn first_answer(world: &World, applied: bool) -> FlowResult {
    let alice = world.identity("alice")?;
    world.add_switch(ORIGIN, &[&alice]).await?;
    let env = world.signer_env(&alice, Arc::new(MemoryStore::new()))?;
    let mut signer = Signer::create(env.clone(), world.keyring(&alice)?, ORIGIN).await?;
    if applied {
        world.lose_answer("POST", "/v1/enroll");
    } else {
        world.unreachable("POST", "/v1/enroll");
    }
    assert!(matches!(Box::pin(signer.resume()).await, Err(SignerError::Switch(ClientError::Transport(_)))));
    if applied {
        // An intermediary is reachable while the original service's receipt is unavailable.
        world.refuse("POST", "/v1/enroll", 400, "bad_request");
        assert!(matches!(Box::pin(signer.resume()).await, Err(SignerError::Switch(ClientError::BadServiceSignature { status: 400 }))));
    } else {
        world.advance_ms(301_000);
        assert!(matches!(Box::pin(signer.resume()).await, Err(SignerError::Switch(ClientError::Switch { current, .. })) if current == json!({"binding": "expired"})));
    }
    drop(signer);
    let mut signer = Signer::open(env, world.keyring(&alice)?).await?;
    world.unreachable("POST", "/v1/enroll");
    assert!(Box::pin(signer.run_due()).await.is_err());
    assert_eq!(world.faults_left(), 1, "unattended setup resent the enrollment");
    assert!(signer.identity_doc()?.is_none());
    assert_ne!(signer.status(), SignerStatus::Signing);
    Ok(())
}
