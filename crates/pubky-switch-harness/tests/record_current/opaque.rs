//! Address, read-scope and wire privacy checks (Switch wire 1.5, 6.2, 7.4.9; Switch spec 15).

use super::*;
use pubky_switch_client::app::OpBatch;
use pubky_switch_client::client::answers::{FeedItem, FeedQuery};
use pubky_switch_core::enc::unb64;
use pubky_switch_core::export::{Chunk, ChunkAnswer, Part, RecordEntry, chunk_id};
use pubky_switch_harness::parties::NOTES_JOURNAL;

/// Check raw bytes and the contents of signed documents and encoded export chunks.
fn contains_name(bytes: &[u8]) -> bool {
    bytes
        .windows(COLLECTION.len())
        .any(|w| w == COLLECTION.as_bytes())
        || serde_json::from_slice::<Value>(bytes).is_ok_and(|value| nested_name(&value))
}

fn nested_name(value: &Value) -> bool {
    match value {
        Value::Object(fields) => fields
            .iter()
            .any(|(k, v)| k.contains(COLLECTION) || nested_name(v)),
        Value::Array(values) => values.iter().any(nested_name),
        Value::String(s) => {
            s.contains(COLLECTION)
                || s.split('.').any(|part| {
                    unb64(part).is_ok_and(|bytes| !bytes.is_empty() && contains_name(&bytes))
                })
        }
        _ => false,
    }
}

#[test]
fn test_wire_name_inside_encoded_operation_is_detected() {
    let plain = json!({"id_inputs": {"collection": COLLECTION}}).to_string();
    let nested = json!({"op": {"body": b64(plain.as_bytes())}}).to_string();
    assert!(!nested.contains(COLLECTION));
    assert!(contains_name(nested.as_bytes()));
    assert!(!contains_name(br#"{"collection":"opaque"}"#));
}

/// Inspect each exchange before the harness normalizes its signed documents and IDs.
pub(super) fn watch(world: &World) {
    world.distort(|request, response| {
        assert!(!contains_name(request.url().as_bytes()), "request URL");
        for header in request.headers.iter().chain(&response.headers) {
            assert!(
                !contains_name(header.name.as_bytes()) && !nested_name(&json!(header.value)),
                "header {}",
                header.name
            );
        }
        assert!(
            !contains_name(&request.body),
            "{} request",
            request.path_and_query
        );
        assert!(
            !contains_name(&response.body),
            "{} response",
            request.path_and_query
        );
    });
}

/// Encode the record from an actual response in the export wire format (Switch wire 10.3).
fn check_export(view: pubky_switch_client::client::answers::SharedRecordView) {
    let op = SignedOp::peek(&view.op).unwrap();
    let OpKind::RecordPut(put) = &op.body().kind else {
        panic!("record")
    };
    let chunk = Chunk {
        index: 0,
        first: 0,
        parts: vec![Part::Record(RecordEntry {
            key: view.key,
            collection: view.collection,
            read_scope: view.read_scope,
            write_scopes: view.write_scopes,
            generation: view.generation,
            version: view.version,
            op: Some(view.op),
            seq: view.seq,
            deleted: view.deleted,
            writer: view.writer,
            from_upload: false,
            upload_base: None,
            size: u64::try_from(put.value_sealed.ct.len()).unwrap(),
            cert: Some(view.cert),
            proof: view.proof,
        })],
    };
    let answer = ChunkAnswer {
        id: chunk_id(0),
        data: chunk.to_json().unwrap(),
    };
    assert!(!contains_name(&answer.to_json()));
    assert_eq!(Chunk::parse(&answer.data).unwrap(), chunk);
}

pub(super) async fn wire_names(world: &World) {
    let mut w = Box::pin(writer_with(world, notes_protocol_with_records())).await;
    watch(world);
    let start = world.trace().lines.len();
    let one = RecordTarget::new(notes_collection(), b"one");
    let two = RecordTarget::new(notes_collection(), b"two");
    let key = w.app.put_record(&one, b"{}", vec![]).await.unwrap().key;
    w.app.put_record(&one, br#"{"n":2}"#, vec![]).await.unwrap();
    let update = w.app.record_op(&one, Some(b"{}"), vec![]).await.unwrap();
    let create = w.app.record_op(&two, Some(b"{}"), vec![]).await.unwrap();
    w.app
        .submit_batch(OpBatch::new().entry(update).entry(create))
        .await
        .unwrap();
    w.app.delete_record(&two, vec![]).await.unwrap();

    let view = w.client.record(&key).await.unwrap().view;
    let page = w
        .client
        .records(&view.collection, None, None)
        .await
        .unwrap();
    assert_eq!(page.records.len(), 1);
    assert_eq!(page.records[0].op, view.op);
    let page = w
        .client
        .feed(FeedQuery {
            after: Some(pubky_switch_core::ops::Position {
                generation: view.generation,
                seq: view.seq - 1,
            }),
            ..FeedQuery::default()
        })
        .await
        .unwrap();
    assert!(
        page.items
            .iter()
            .any(|item| matches!(item, FeedItem::Chain(item) if item.item == view.op))
    );
    check_export(view);
    let client = SwitchClient::new(
        ORIGIN,
        w.who.public(),
        Credentials::Signer {
            identity: w.who.public(),
            key: Arc::new(pubky_switch_core::keys::IdentityKey::from_secret(
                w.who.key().secret_bytes(),
            )),
        },
        Some(w.service_key),
        world.transport(),
        world.clock().clone(),
    )
    .unwrap();
    let created = client
        .observe_account()
        .await
        .unwrap()
        .body()
        .created
        .unwrap();
    let client = client.with_account_created(created).unwrap();
    // Also inspect the actual manifest response, including a service refusal. A
    // service that supplies a manifest must serve the bytes named by each chunk.
    if let Ok(manifest) = client.export().await {
        for chunk in &manifest.body().chunks {
            let answer = client.export_chunk(&chunk.id).await.unwrap();
            assert!(!contains_name(&answer.data));
        }
    }
    let trace = world.trace();
    let calls: Vec<_> = trace
        .lines
        .iter()
        .skip(start)
        .filter_map(|line| line.call)
        .collect();
    assert!(calls.iter().filter(|call| **call == "ops").count() >= 4);
    for required in ["get_record", "list_records", "feed", "export"] {
        assert!(calls.contains(&required), "missing {required}: {calls:?}");
    }
}

pub(super) async fn held_policy(world: &World) {
    let w = Box::pin(writer(world)).await;
    let before = w.write(1, b"original", RecordVersion::NONE, b"{}").await;
    let update = w.put(b"original", version(&before), b"{}");
    let key = update.key;
    let held = pubky_switch_core::shared::RecordState::after(
        &update,
        version(&before).generation,
        version(&before).version,
    );
    let base = Some((&held, current(&before)));
    let accepts = |put: &RecordPut| {
        pubky_switch_core::shared::check_record_put(put, &[], base, w.epoch, true, None)
    };
    assert!(accepts(&update).is_ok());
    let mut other_collection = update.clone();
    other_collection.collection =
        collection_id(&w.who.public(), &w.who.key().naming_key(), "other");
    let mut other_policy = update;
    other_policy.policy = Policy::new(NOTES, &[NOTES, NOTES_JOURNAL]);
    for (id, put) in [(2, other_collection), (3, other_policy)] {
        // Exercise the held-state comparison independently of submission's address check.
        assert_eq!(accepts(&put).unwrap_err().code, ErrorCode::BadRequest);
        let ops = w.batch(id, vec![(vec![], OpKind::RecordPut(put))]);
        assert_eq!(
            w.post(&ops).await.unwrap_err().code(),
            Some(ErrorCode::BadRequest)
        );
        assert_eq!(body(&w.get(&key).await), before);
    }
    w.write(4, b"original", version(&before), b"{}").await;
}

pub(super) async fn read_scope(world: &World) {
    let w = Box::pin(writer(world)).await;
    let visible = w.put(b"item", RecordVersion::NONE, b"{}");
    // Same identity, name, natural key and writer. Only the read policy varies.
    let mut hidden = visible.clone();
    hidden.policy = Policy::new(NOTES_JOURNAL, &[NOTES]);
    hidden.key = record_key_from_blinded(
        &hidden.collection,
        &hidden.id_inputs.blinded_key,
        &hidden.policy.hash().unwrap(),
    );
    hidden.value_sealed = SealedValue::seal(
        &w.who.key().scope_key(w.epoch, NOTES_JOURNAL),
        &w.who.public(),
        w.epoch,
        NOTES_JOURNAL,
        &hidden.key,
        b"{}",
    )
    .unwrap();
    let ops = w.batch(
        1,
        vec![
            (vec![], OpKind::RecordPut(hidden.clone())),
            (vec![], OpKind::RecordPut(visible.clone())),
        ],
    );
    assert_eq!(w.proofs(&ops, &w.post(&ops).await.unwrap()).len(), 2);
    assert_eq!(
        w.client.record(&hidden.key).await.unwrap_err().code(),
        Some(ErrorCode::PermissionMissing)
    );
    let page = w
        .client
        .records(&visible.collection, None, None)
        .await
        .unwrap();
    assert_eq!(
        page.records.iter().map(|r| r.key).collect::<Vec<_>>(),
        [visible.key]
    );
}
