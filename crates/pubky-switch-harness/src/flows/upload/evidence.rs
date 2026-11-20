//! Ordinary provider-loss recovery with one service acknowledgement (Switch wire 7.4.14).

use super::*;
use crate::{Backend, run};
use pubky_switch_client::app::AppEvent;
use pubky_switch_client::client::answers::{RecoveryUpload, UploadedOp};
use pubky_switch_client::error::{ClientError, TransportError};

#[tokio::test]
async fn test_wallet_record_uploads_with_one_acknowledgement_at_both_switches() {
    for backend in [Backend::Scripted, Backend::Service] {
        for proved_first in [true, false] {
            run(backend, async |world| {
                recovered_writes(world, proved_first).await
            })
            .await
            .expect("recover the wallet's and phone's writes");
        }
    }
}

async fn join_wallet(
    world: &World,
    alice: &TestIdentity,
    signer: &mut Signer,
    name: &str,
) -> Result<App, Box<dyn std::error::Error>> {
    let asking = Asking::new(world.app_keys(alice, name)?)?;
    let (app, _) = Box::pin(joined_as(
        world,
        alice,
        signer,
        asking,
        notes_protocol_with_records(),
    ))
    .await?;
    Ok(app)
}

async fn recovered_writes(world: &World, proved_first: bool) -> FlowResult {
    let alice = world.identity("alice")?;
    world.add_switch(ORIGIN, &[&alice]).await?;
    let mut signer = Box::pin(enroll(world, &alice, ORIGIN)).await?;
    let mut wallet = join_wallet(world, &alice, &mut signer, "wallet").await?;
    let mut phone = join_wallet(world, &alice, &mut signer, "phone").await?;
    // The reader has no shared write to upload when it follows the provider change.
    let mut reader = join_wallet(world, &alice, &mut signer, "reader").await?;
    let original = signer.identity_doc()?.ok_or("missing original identity")?;
    let target = RecordTarget::new(notes_collection(), b"shopping list");
    let first = Box::pin(wallet.put_record(&target, br#"{"items":["milk"]}"#, vec![])).await?;
    let evidence = wallet.shared_evidence().await?;
    let [held] = evidence.ops.as_slice() else {
        return Err("expected a single wallet write".into());
    };
    let proved = UploadedOp {
        op: held.op.clone(),
        cert: held.cert.clone(),
        proof: Some(held.proof.clone().ok_or("missing wallet acknowledgement")?),
    };

    // An intervening write leaves the final write's signed base beyond the wallet's
    // acknowledged version. The phone keeps its signed batch when its answer is lost.
    Box::pin(phone.read_record(&target)).await?;
    Box::pin(phone.put_record(&target, br#"{"items":["milk","eggs"]}"#, vec![])).await?;
    let old = client_of(
        world,
        &alice,
        "phone",
        &phone,
        ORIGIN,
        original.inbox().service_key,
    )?;
    let entry = Box::pin(phone.record_op(&target, Some(br#"{"items":["eggs"]}"#), vec![])).await?;
    let batch = old.sign_batch(original.generation(), vec![entry], None)?;
    world.lose_answer("POST", "/ops");
    assert!(matches!(
        old.submit(&batch).await,
        Err(ClientError::Transport(TransportError::Timeout))
    ));
    assert_eq!(
        world
            .last_fact("{alice/phone} POST /v1/{alice}/ops", "status")
            .as_deref(),
        Some("200")
    );
    let [pending] = batch.ops() else {
        return Err("expected a single phone write".into());
    };
    let unanswered = UploadedOp {
        op: pending.signed().clone(),
        cert: phone.cert().signed().clone(),
        proof: None,
    };

    Box::pin(lose_and_recover(world, &alice, &mut signer)).await?;
    let new = signer.identity_doc()?.ok_or("missing recovery identity")?;
    Box::pin(follow_recovery(
        world,
        &mut reader,
        "reader",
        original.generation(),
    ))
    .await?;
    let client = client_of(
        world,
        &alice,
        "reader",
        &reader,
        RECOVERY_ORIGIN,
        new.inbox().service_key,
    )?;
    let uploads = if proved_first {
        [&proved, &unanswered]
    } else {
        [&unanswered, &proved]
    };
    let body = |write: &UploadedOp| RecoveryUpload {
        lost_identity: Some(original.signed().clone()),
        records: vec![write.clone()],
        ..RecoveryUpload::default()
    };
    for (i, write) in uploads.into_iter().enumerate() {
        let result = client
            .recovery_upload(&body(write), false)
            .await?
            .result
            .ok_or("missing upload result")?;
        assert_eq!(result.records.contains(&first.key), i == 0 || !proved_first);
        assert_eq!(result.divergent.contains(&first.key), i == 1);
    }
    for write in uploads {
        let repeated = client
            .recovery_upload(&body(write), false)
            .await?
            .result
            .ok_or("missing repeated upload result")?;
        assert!(repeated.records.is_empty() && repeated.divergent.is_empty());
    }
    let installed = client.record(&first.key).await?.view;
    assert_eq!(installed.op, proved.op);
    assert_eq!(installed.version, first.version.version);
    assert!(installed.divergent);
    let shown = Box::pin(reader.read_record(&target))
        .await?
        .ok_or("missing recovered record")?;
    assert_eq!(shown.content, first.content);
    assert!(shown.divergent);
    assert!(
        reader.take_events().iter().any(
            |event| matches!(event, AppEvent::RecordDivergent { key, .. } if key == &first.key)
        )
    );
    let resolved =
        Box::pin(reader.put_record(&target, br#"{"items":["milk","eggs"]}"#, vec![])).await?;
    assert!(!resolved.divergent);
    let written_here = client.record(&first.key).await?.view;
    assert!(!written_here.divergent);
    let replay = client
        .recovery_upload(&body(&unanswered), false)
        .await?
        .result
        .ok_or("missing upload result after the local write")?;
    assert!(replay.records.is_empty());
    assert_eq!(replay.divergent, vec![first.key]);
    let kept = client.record(&first.key).await?.view;
    assert_eq!(kept.op, written_here.op);
    assert!(kept.divergent);
    Ok(())
}
