//! Ordinary provider-loss recovery with one service acknowledgement (Switch wire 7.4.14).

use super::*;
use crate::{Backend, run_here};
use pubky_switch_client::app::Evidence;
use pubky_switch_client::client::answers::{RecoveryUpload, UploadChanges, UploadedOp};
use pubky_switch_client::error::{ClientError, TransportError};
use pubky_switch_core::sig::SignedDoc;

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
    let (full_key, full) = Box::pin(acknowledged_writes(&mut writer, &origin, b"full", 10)).await?;
    let (ordered_key, ordered) =
        Box::pin(acknowledged_writes(&mut writer, &origin, b"ordered", 3)).await?;
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
        let mut stored_parent = false;
        for i in order {
            // Once the operation has been uploaded, the receipt can arrive on its own.
            if i == 2 && stored_parent {
                send_evidence(
                    &client,
                    original.signed(),
                    vec![],
                    writes[2].proof.iter().cloned().collect(),
                )
                .await?;
            } else {
                send_evidence(
                    &client,
                    original.signed(),
                    vec![writes[usize::from(i)].clone()],
                    vec![],
                )
                .await?;
            }
            stored_parent |= i == 0;
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
    let doc = original.signed();
    let bound = |r: &UploadedOp| UploadedOp {
        proof: None,
        ..r.clone()
    };
    // The first operation is current; all eight slots are occupied, including the
    // successor in slot zero. Promoting it leaves room for the displaced operation.
    let occupied = full
        .iter()
        .enumerate()
        .filter(|(i, _)| *i != 1)
        .map(|(_, r)| bound(r))
        .collect();
    send_evidence(&client, doc, occupied, vec![]).await?;
    send_evidence(&client, doc, vec![full[1].clone()], vec![]).await?;
    let view = client.record(&full_key).await?.view;
    assert_eq!(view.op, full[2].op);
    assert!(view.divergent);
    let replay = send_evidence(&client, doc, vec![bound(&full[0])], vec![]).await?;
    assert!(replay.records.is_empty() && replay.divergent.is_empty());

    // A receipt received before its operation is counted and discarded. Re-sending it
    // after the older write has been retained resolves the nonadjacent versions.
    let receipts: Vec<_> = ordered[0].proof.iter().cloned().collect();
    let unmatched = send_evidence(&client, doc, vec![], receipts.clone()).await?;
    assert!(unmatched.records.is_empty() && unmatched.divergent.is_empty());
    send_evidence(
        &client,
        doc,
        vec![ordered[2].clone(), bound(&ordered[0])],
        vec![],
    )
    .await?;
    assert!(client.record(&ordered_key).await?.view.divergent);
    let resolved = send_evidence(&client, doc, vec![], receipts.clone()).await?;
    assert_eq!(resolved.records, [ordered_key]);
    assert!(resolved.divergent.is_empty());
    let view = client.record(&ordered_key).await?.view;
    assert_eq!(view.op, ordered[2].op);
    assert!(!view.divergent);
    let replay = send_evidence(&client, doc, vec![], receipts).await?;
    assert!(replay.records.is_empty() && replay.divergent.is_empty());
    assert_eq!(
        client.record(&ordered_key).await?.view.revision,
        view.revision
    );
    let still_dated = send_evidence(&client, doc, vec![ordered[0].clone()], vec![]).await?;
    assert!(still_dated.records.is_empty() && still_dated.divergent.is_empty());
    let repeated = send_evidence(&client, doc, vec![bound(&ordered[0])], vec![]).await?;
    assert!(repeated.records.is_empty() && repeated.divergent.is_empty());
    let held = client.record(&ordered_key).await?.view;
    assert!(!held.divergent);
    assert_eq!((held.op, held.revision), (view.op, view.revision));
    let again = send_evidence(&client, doc, vec![bound(&ordered[0])], vec![]).await?;
    assert!(again.records.is_empty() && again.divergent.is_empty());
    Ok(())
}

async fn acknowledged_writes(
    writer: &mut App,
    origin: &SwitchClient,
    name: &[u8],
    count: u8,
) -> Result<([u8; 32], Vec<UploadedOp>), Box<dyn std::error::Error>> {
    let target = RecordTarget::new(notes_collection(), name);
    let mut history = Vec::new();
    let mut key = None;
    for i in 0..count {
        let content = json!({"items":[i]}).to_string();
        let write = Box::pin(writer.put_record(&target, content.as_bytes(), vec![])).await?;
        let view = origin.record(&write.key).await?.view;
        history.push(UploadedOp {
            op: view.op,
            cert: view.cert,
            proof: Some(view.proof.ok_or("missing original receipt")?),
        });
        key = Some(write.key);
    }
    Ok((key.ok_or("empty write history")?, history))
}

async fn send_evidence(
    client: &SwitchClient,
    lost: &SignedDoc,
    records: Vec<UploadedOp>,
    proofs: Vec<SignedDoc>,
) -> Result<UploadChanges, Box<dyn std::error::Error>> {
    let upload = RecoveryUpload {
        lost_identity: Some(lost.clone()),
        records,
        proofs,
        ..RecoveryUpload::default()
    };
    Ok(client
        .recovery_upload(&upload, false)
        .await?
        .result
        .ok_or("missing upload result")?)
}

#[tokio::test]
async fn test_rule_reinstatement_scripted() {
    Box::pin(run_here(Backend::Scripted, reinstated_write))
        .await
        .expect("reinstate the parent")
        .expect("scripted trace");
}

#[tokio::test]
async fn test_rule_reinstatement_service() {
    Box::pin(run_here(Backend::Service, reinstated_write))
        .await
        .expect("reinstate the parent");
}

async fn reinstated_write(world: &World) -> FlowResult {
    use crate::parties::NOTES;
    use pubky_switch_client::app::{Collection, RecordRead};
    use pubky_switch_client::testing::{ProtocolSpec, TestProtocol};
    use pubky_switch_core::{ident::Policy, records::AppCert};

    let alice = world.identity("alice")?;
    world.add_switch(ORIGIN, &[&alice]).await?;
    let mut signer = Box::pin(enroll(world, &alice, ORIGIN)).await?;
    let collection = Collection::new(
        "example.items",
        Policy::new(NOTES, &[NOTES]).with_create_scope(NOTES),
    );
    let protocol = || {
        Arc::new(TestProtocol::new(ProtocolSpec {
            name: NOTES.into(),
            keyed_scopes: vec![NOTES.into()],
            collections: vec![collection.clone()],
            ..ProtocolSpec::default()
        }))
    };
    let (mut writer, _) = Box::pin(joined_as(
        world,
        &alice,
        &mut signer,
        Asking::new(world.app_keys(&alice, "wallet")?)?,
        protocol(),
    ))
    .await?;
    let (mut reader, _) = Box::pin(joined_as(
        world,
        &alice,
        &mut signer,
        Asking::new(world.app_keys(&alice, "phone")?)?,
        protocol(),
    ))
    .await?;
    let original = signer.identity_doc()?.ok_or("missing original identity")?;
    let origin = client_of(
        world,
        &alice,
        "wallet",
        &writer,
        ORIGIN,
        original.inbox().service_key,
    )?;
    let target = RecordTarget::new(collection, b"recovered");
    let first = Box::pin(writer.put_record(&target, b"1", vec![])).await?;
    let a = origin.record(&first.key).await?.view;
    Box::pin(writer.put_record(&target, b"2", vec![])).await?;
    let b = origin.record(&first.key).await?.view;
    world.advance_ms(STEP_MS);
    let mut grant = writer.cert().body().clone();
    grant.issued_at = world.now_ms();
    let later = AppCert::issue(alice.key(), grant)?;
    Box::pin(lose_and_recover(world, &alice, &mut signer)).await?;
    Box::pin(follow_recovery(
        world,
        &mut reader,
        "phone",
        original.generation(),
    ))
    .await?;
    let new = signer.identity_doc()?.ok_or("missing recovery identity")?;
    let client = client_of(
        world,
        &alice,
        "phone",
        &reader,
        RECOVERY_ORIGIN,
        new.inbox().service_key,
    )?;
    let doc = original.signed();
    let parent = UploadedOp {
        op: a.op.clone(),
        cert: a.cert,
        proof: a.proof,
    };
    let child = UploadedOp {
        op: b.op.clone(),
        cert: later.signed().clone(),
        proof: None,
    };
    send_evidence(&client, doc, vec![parent], vec![]).await?;
    assert_eq!(client.record(&first.key).await?.view.op, a.op);
    let first_read = Box::pin(reader.read_record_fresh(&target)).await?;
    assert!(
        matches!(&first_read, RecordRead::Fresh(r) if r.content.value() == Some(b"1")),
        "{first_read:?}"
    );
    send_evidence(&client, doc, vec![child.clone()], vec![]).await?;
    assert_eq!(client.record(&first.key).await?.view.op, b.op);
    let child_read = Box::pin(reader.read_record_fresh(&target)).await?;
    assert!(
        matches!(&child_read, RecordRead::Fresh(r) if r.content.value() == Some(b"2")),
        "{child_read:?}"
    );
    let review = send_evidence(
        &client,
        doc,
        vec![],
        vec![b.proof.ok_or("missing child receipt")?],
    )
    .await?;
    assert_eq!(review.unverified, 1);
    let restored = client.record(&first.key).await?.view;
    assert_eq!(restored.op, a.op);
    assert!(!restored.divergent);
    let reinstated = Box::pin(reader.read_record_fresh(&target)).await?;
    assert!(
        matches!(&reinstated, RecordRead::Fresh(r) if r.content.value() == Some(b"1")),
        "{reinstated:?}"
    );
    let retry = send_evidence(&client, doc, vec![child], vec![]).await?;
    assert_eq!(retry.unverified, 1);
    Ok(())
}
