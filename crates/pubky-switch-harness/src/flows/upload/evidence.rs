//! Ordinary provider-loss recovery with one service acknowledgement (Switch wire 7.4.14).

use super::*;
use crate::{Backend, run_here};
use pubky_switch_client::app::Evidence;
use pubky_switch_client::client::answers::{RecoveryUpload, UploadedOp};
use pubky_switch_client::error::{ClientError, TransportError};

#[tokio::test]
async fn test_wallet_record_uploads_scripted() {
    wallet_uploads(Backend::Scripted).await;
}

#[tokio::test]
async fn test_wallet_record_uploads_service() {
    wallet_uploads(Backend::Service).await;
}

async fn wallet_uploads(backend: Backend) {
    for proved_first in [true, false] {
        let trace = Box::pin(run_here(backend, async |world: &World| {
            Box::pin(recovered_writes(world, proved_first)).await
        }))
        .await
        .expect("recover the wallet's and phone's writes");
        if backend == Backend::Scripted {
            assert!(trace.is_some());
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
    let original = signer.identity_doc()?.ok_or("missing original identity")?;
    let target = RecordTarget::new(notes_collection(), b"shopping list");
    // The phone keeps the signed create whose submission timed out. It has never read
    // the key, so it cannot contribute a receipt for this write or an intervening one.
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

    phone
        .keep_evidence(vec![Evidence::Op {
            op: unanswered.op.clone(),
            cert: unanswered.cert.clone(),
            proof: None,
        }])
        .await?;
    assert!(phone.shared_evidence().await?.ops.is_empty());
    Box::pin(wallet.read_record(&target))
        .await?
        .ok_or("missing the phone's write")?;
    let first = Box::pin(wallet.put_record(&target, br#"{"items":["milk"]}"#, vec![])).await?;
    let evidence = wallet.shared_evidence().await?;
    let [proved] = evidence.ops.as_slice() else {
        return Err("expected the wallet's acknowledged write".into());
    };
    assert!(proved.proof.is_some());

    Box::pin(lose_and_recover(world, &alice, &mut signer)).await?;
    let order = if proved_first {
        [("wallet", &mut wallet), ("phone", &mut phone)]
    } else {
        [("phone", &mut phone), ("wallet", &mut wallet)]
    };
    for (i, (name, app)) in order.into_iter().enumerate() {
        Box::pin(follow_recovery(world, app, name, original.generation())).await?;
        expect_records(
            world,
            name,
            usize::from(i == 0 || !proved_first),
            usize::from(i == 1),
        )?;
    }
    let new = signer.identity_doc()?.ok_or("missing recovery identity")?;
    let client = client_of(
        world,
        &alice,
        "wallet",
        &wallet,
        RECOVERY_ORIGIN,
        new.inbox().service_key,
    )?;
    let installed = client.record(&first.key).await?.view;
    assert_eq!(installed.op, proved.op);
    assert_eq!(installed.version, first.version.version);
    assert!(installed.divergent);
    let shown = Box::pin(wallet.read_record(&target))
        .await?
        .ok_or("missing recovered record")?;
    assert_eq!(shown.content, first.content);
    assert!(shown.divergent);

    let resolved =
        Box::pin(wallet.put_record(&target, br#"{"items":["milk","eggs"]}"#, vec![])).await?;
    assert!(!resolved.divergent);
    let written_here = client.record(&first.key).await?.view;
    assert!(!written_here.divergent);
    let phone_client = client_of(
        world,
        &alice,
        "phone",
        &phone,
        RECOVERY_ORIGIN,
        new.inbox().service_key,
    )?;
    let replay = phone_client
        .recovery_upload(
            &RecoveryUpload {
                lost_identity: Some(original.signed().clone()),
                records: vec![unanswered],
                ..RecoveryUpload::default()
            },
            false,
        )
        .await?
        .result
        .ok_or("missing repeated upload result")?;
    assert!(replay.records.is_empty());
    let kept = client.record(&first.key).await?.view;
    assert_eq!(kept.op, written_here.op);
    // This create's bound is below the acknowledged version that the local write built on.
    assert!(replay.divergent.is_empty() && !kept.divergent);
    Ok(())
}

#[tokio::test]
async fn test_retained_record_successor_scripted() {
    Box::pin(run_here(Backend::Scripted, arrival_orders))
        .await
        .expect("compare successive writes")
        .expect("scripted trace");
}

#[tokio::test]
async fn test_retained_record_successor_service() {
    Box::pin(run_here(Backend::Service, arrival_orders))
        .await
        .expect("compare successive writes");
}

async fn arrival_orders(world: &World) -> FlowResult {
    let alice = world.identity("alice")?;
    world.add_switch(ORIGIN, &[&alice]).await?;
    let mut signer = Box::pin(enroll(world, &alice, ORIGIN)).await?;
    let mut writer = join_wallet(world, &alice, &mut signer, "wallet").await?;
    let mut phone = join_wallet(world, &alice, &mut signer, "phone").await?;
    let original = signer.identity_doc()?.ok_or("missing original identity")?;
    let origin = client_of(
        world,
        &alice,
        "wallet",
        &writer,
        ORIGIN,
        original.inbox().service_key,
    )?;
    let orders = [
        [0, 1, 2],
        [1, 0, 2],
        [2, 0, 1],
        [2, 1, 0],
        [1, 2, 0],
        [0, 2, 1],
    ];
    let mut cases = Vec::new();
    for order in orders {
        let target = RecordTarget::new(notes_collection(), &order);
        let first = Box::pin(writer.put_record(&target, br#"{"items":["milk"]}"#, vec![])).await?;
        let parent = origin.record(&first.key).await?.view;
        let receipt = parent.proof.ok_or("missing original receipt")?;
        let parent = UploadedOp {
            op: parent.op,
            cert: parent.cert,
            proof: None,
        };
        let second = Box::pin(writer.put_record(&target, br#"{"items":["eggs"]}"#, vec![])).await?;
        let child = origin.record(&second.key).await?.view;
        let child = UploadedOp {
            op: child.op,
            cert: child.cert,
            proof: None,
        };
        let proved = UploadedOp {
            proof: Some(receipt),
            ..parent.clone()
        };
        cases.push((first.key, order, [parent, child, proved]));
    }
    Box::pin(lose_and_recover(world, &alice, &mut signer)).await?;
    Box::pin(follow_recovery(
        world,
        &mut phone,
        "phone",
        original.generation(),
    ))
    .await?;
    let new = signer.identity_doc()?.ok_or("missing recovery identity")?;
    let client = client_of(
        world,
        &alice,
        "phone",
        &phone,
        RECOVERY_ORIGIN,
        new.inbox().service_key,
    )?;
    for (key, order, writes) in cases {
        for i in order {
            let upload = RecoveryUpload {
                lost_identity: Some(original.signed().clone()),
                records: vec![writes[usize::from(i)].clone()],
                ..RecoveryUpload::default()
            };
            client.recovery_upload(&upload, false).await?;
        }
        let installed = client.record(&key).await?.view;
        assert_eq!(installed.op, writes[1].op, "order {order:?}");
        assert_eq!(installed.cert, writes[1].cert);
        assert!(!installed.divergent, "order {order:?}");
        let repeated = client
            .recovery_upload(
                &RecoveryUpload {
                    lost_identity: Some(original.signed().clone()),
                    records: writes.to_vec(),
                    ..RecoveryUpload::default()
                },
                false,
            )
            .await?
            .result
            .ok_or("missing repeated upload result")?;
        assert!(
            repeated.records.is_empty() && repeated.divergent.is_empty(),
            "order {order:?}"
        );
        assert_eq!(client.record(&key).await?.view.revision, installed.revision);
    }
    Ok(())
}
