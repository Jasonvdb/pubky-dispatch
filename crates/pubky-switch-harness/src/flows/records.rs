//! Shared records (Switch spec 10.3, Switch wire 6.2 `record.put`, 7.4.9, 7.5): one app
//! writes a record, and the identity's other apps learn of it, each by what it may read.

use pubky_switch_client::app::{App, RecordTarget, SharedRecord};
use serde_json::{Value, json};

use super::enrollment::enroll;
use super::join::{app_status, events};
use super::messaging::joined_as;
use super::{ORIGIN, STEP_MS};
use crate::parties::{
    Asking, NOTES_LISTS, notes_collection, notes_protocol, notes_protocol_with_records,
};
use crate::{FlowResult, World};

/// The wallet and the phone hold the collection's read scope; the pad doesn't. The wallet
/// writes a record, changes it and deletes it. After each write the phone and the pad
/// follow their feeds, and the flow notes what the phone holds of the record; the phone
/// also reads the record from the switch. The wallet then writes a second record, and a
/// tablet joins and lists the collection.
///
/// Calls: `GET /v1/{id}/records` (an app with collections lists them when it joins: none
/// yet, then one), `POST /v1/{id}/ops` (`record.put`: create, update, delete), `GET
/// /v1/{id}/feed` with another app's `record.put`, by an app holding its read scope and by
/// one that doesn't, and `GET /v1/{id}/records/{key}` for a record with a value, a changed
/// value, and a deleted one.
///
/// # Errors
///
/// When a step that should succeed against any switch fails.
pub async fn records(world: &World) -> FlowResult {
    let alice = world.identity("alice")?;
    world.add_switch(ORIGIN, &[&alice]).await?;
    let mut signer = enroll(world, &alice, ORIGIN).await?;
    let with_records = |name: &str| -> Result<Asking, crate::HarnessError> {
        Asking::new(world.app_keys(&alice, name)?)
    };
    let (mut wallet, _) = joined_as(
        world,
        &alice,
        &mut signer,
        with_records("wallet")?,
        notes_protocol_with_records(),
    )
    .await?;
    let (mut phone, _) = joined_as(
        world,
        &alice,
        &mut signer,
        with_records("phone")?,
        notes_protocol_with_records(),
    )
    .await?;
    let asking = Asking::for_scope(world.app_keys(&alice, "pad")?, NOTES_LISTS)?;
    let (mut pad, _) = joined_as(world, &alice, &mut signer, asking, notes_protocol()).await?;
    for (app, name) in [(&mut wallet, "the wallet"), (&mut phone, "the phone")] {
        look(world, app, &format!("{name} before any record")).await?;
    }
    look(world, &mut pad, "the pad before any record").await?;

    let target = RecordTarget::new(notes_collection(), b"shopping list");
    let key = phone.record_key(&target)?;
    let writes: [(&str, Option<&str>); 3] = [
        ("wrote the record", Some(r#"{"items":["milk"]}"#)),
        ("changed the record", Some(r#"{"items":["milk","bread"]}"#)),
        ("deleted the record", None),
    ];
    for (step, value) in writes {
        let written = match value {
            Some(value) => {
                wallet
                    .put_record(&target, value.as_bytes(), Vec::new())
                    .await?
            }
            None => wallet.delete_record(&target, Vec::new()).await?,
        };
        world.outcome(
            &format!("the wallet {step}"),
            &json!({
                "record": shown(Some(&written)),
                "events": events(&wallet.take_events()),
            }),
        );
        world.advance_ms(STEP_MS);

        // The phone holds the read scope: it learns the write from its feed.
        look(
            world,
            &mut phone,
            &format!("the phone after the wallet {step}"),
        )
        .await?;
        let held = phone.shared_record(&key).await?;
        world.outcome(
            &format!("what the phone holds after the wallet {step}"),
            &shown(held.as_ref()),
        );
        // The pad doesn't: the write is an item it may not read.
        look(world, &mut pad, &format!("the pad after the wallet {step}")).await?;

        // And what the switch tells the phone when it asks.
        let read = phone.read_record(&target).await?;
        world.outcome(
            &format!("what the phone reads after the wallet {step}"),
            &json!({
                "record": shown(read.as_ref()),
                "events": events(&phone.take_events()),
            }),
        );
        world.advance_ms(STEP_MS);
    }

    // A second record, which stays.
    let kept_target = RecordTarget::new(notes_collection(), b"address book");
    let kept = wallet
        .put_record(&kept_target, br#"{"names":["bob"]}"#, Vec::new())
        .await?;
    world.outcome("the wallet wrote a second record", &shown(Some(&kept)));
    world.advance_ms(STEP_MS);

    // An app that joins now lists the collection: the record that stays, and what the
    // switch shows of the deleted one.
    let (mut tablet, _) = joined_as(
        world,
        &alice,
        &mut signer,
        with_records("tablet")?,
        notes_protocol_with_records(),
    )
    .await?;
    let deleted = tablet.shared_record(&key).await?;
    let kept = tablet
        .shared_record(&tablet.record_key(&kept_target)?)
        .await?;
    let listed = tablet.records_of(&notes_collection().name).await?;
    world.outcome(
        "what the tablet holds after it joined",
        &json!({
            "the deleted record": shown(deleted.as_ref()),
            "the record that stays": shown(kept.as_ref()),
            "listed": listed.len(),
            "app": app_status(&mut tablet),
        }),
    );
    Ok(())
}

/// What a shared record shows, for the trace.
pub(crate) fn shown(record: Option<&SharedRecord>) -> Value {
    match record {
        None => json!({ "held": false }),
        Some(record) => json!({
            "held": true,
            "collection": record.collection,
            "version": record.version.version,
            "generation": record.version.generation,
            "authenticated": record.authenticated,
            "doubtful": record.doubtful,
            "written_at_ms": record.written_at_ms,
            "content": format!("{:?}", record.content),
            "value": record.content.value().map(|value| String::from_utf8_lossy(value).into_owned()),
        }),
    }
}

/// `app` follows its feed and moves its cursor: the events it raises at this read, and
/// where it stands.
pub(crate) async fn look(world: &World, app: &mut App, name: &str) -> FlowResult {
    let report = app.receive(None).await?;
    app.flush_cursor().await?;
    world.outcome(
        name,
        &json!({
            "events": events(&report.events),
            "stopped": report.stopped,
            "app": app_status(app),
        }),
    );
    world.advance_ms(STEP_MS);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::flows::{admission::note, messaging::joined};
    use crate::{Backend, run_here};
    use pubky_switch_client::app::{AppEvent, Delivery, RecordJob};
    use pubky_switch_core::ops::SignedOp;

    async fn stopped_record_job(world: &World) -> FlowResult {
        let alice = world.identity("alice")?;
        let bob = world.identity("bob")?;
        world.add_switch(ORIGIN, &[&alice, &bob]).await?;
        let mut alice_signer = Box::pin(enroll(world, &alice, ORIGIN)).await?;
        let mut bob_signer = Box::pin(enroll(world, &bob, ORIGIN)).await?;
        let (mut wallet, _) = Box::pin(joined_as(
            world,
            &alice,
            &mut alice_signer,
            Asking::new(world.app_keys(&alice, "wallet")?)?,
            notes_protocol_with_records(),
        ))
        .await?;
        let (mut recipient, _) =
            Box::pin(joined(world, &bob, &mut bob_signer, "recipient")).await?;
        Box::pin(recipient.add_contact(&alice.public())).await?;

        let target = RecordTarget::new(notes_collection(), b"shopping list");
        Box::pin(wallet.put_record(&target, b"{}", vec![])).await?;
        let message = wallet
            .sign_message(note(bob.public(), "milk", None))?
            .with_record(RecordJob {
                target: target.clone(),
                tag: vec![],
            });
        let msg_id = wallet.queue_signed(message).await?;
        let deleted = Box::pin(wallet.delete_record(&target, vec![])).await?;
        let evidence = wallet.shared_evidence().await?;
        let [write] = evidence.ops.as_slice() else {
            return Err("expected the delete of the only shared record".into());
        };
        let hash = SignedOp::peek(&write.op)?.item_hash()?;

        Box::pin(wallet.flush_outbox()).await?;
        assert!(matches!(
            wallet.delivery(&msg_id).await?,
            Some(Delivery::Accepted { .. })
        ));
        let owner = crate::parties::NOTES;
        let duties = wallet.unacknowledged_events_for(owner).await?;
        let [event] = duties.as_slice() else {
            return Err("expected the record owner's stopped job".into());
        };
        assert!(matches!(
            event, AppEvent::RecordJobStopped { msg_id: stopped, key, generation, version, item_hash, batch_id: None, .. }
                if stopped == &msg_id && key == &deleted.key && *generation == deleted.version.generation
                    && *version == deleted.version.version && *item_hash == hash
        ));
        let id = event.id().ok_or("the stopped job has no event ID")?;
        wallet.ack_event_with(owner, id, &[]).await?;
        assert!(wallet.pending_duty_events().await?.is_empty());
        Ok(())
    }

    async fn observe_record_values(world: &World) -> FlowResult {
        let alice = world.identity("alice")?;
        world.add_switch(ORIGIN, &[&alice]).await?;
        let mut signer = Box::pin(enroll(world, &alice, ORIGIN)).await?;
        let spec = notes_protocol_with_records().spec().clone();
        let protocol = std::sync::Arc::new(
            pubky_switch_client::testing::TestProtocol::new(spec).observing_records(),
        );
        let (mut writer, _) = Box::pin(joined_as(
            world,
            &alice,
            &mut signer,
            Asking::new(world.app_keys(&alice, "wallet")?)?,
            protocol.clone(),
        ))
        .await?;
        let (mut reader, _) = Box::pin(joined_as(
            world,
            &alice,
            &mut signer,
            Asking::new(world.app_keys(&alice, "phone")?)?,
            protocol,
        ))
        .await?;
        let target = RecordTarget::new(notes_collection(), b"shopping list");
        let values = [
            br#"{"items":["milk"]}"#.as_slice(),
            br#"{"items":["eggs"]}"#,
        ];
        for value in values {
            let written = Box::pin(writer.put_record(&target, value, vec![])).await?;
            let evidence = writer.shared_evidence().await?;
            let [write] = evidence.ops.as_slice() else {
                return Err("expected the current record operation".into());
            };
            let hash = SignedOp::peek(&write.op)?.item_hash()?;
            assert_eq!(
                writer
                    .protocol_get(crate::parties::NOTES, &hash)
                    .await?
                    .as_deref(),
                Some(value)
            );
            Box::pin(reader.receive(None)).await?;
            assert_eq!(
                reader
                    .protocol_get(crate::parties::NOTES, &hash)
                    .await?
                    .as_deref(),
                Some(value)
            );
            Box::pin(reader.flush_cursor()).await?;
            assert!(reader.service_cursor().seq >= written.version.version);
        }
        Ok(())
    }

    #[tokio::test]
    async fn test_record_observations_for_both_apps_at_both_switches() {
        for backend in [Backend::Service, Backend::Scripted] {
            Box::pin(run_here(backend, observe_record_values))
                .await
                .unwrap();
        }
    }

    async fn observe_deleted_record(world: &World) -> FlowResult {
        let alice = world.identity("alice")?;
        world.add_switch(ORIGIN, &[&alice]).await?;
        let mut signer = Box::pin(enroll(world, &alice, ORIGIN)).await?;
        let asking = |name| Asking::new(world.app_keys(&alice, name)?);
        let (mut writer, _) = Box::pin(joined_as(
            world,
            &alice,
            &mut signer,
            asking("wallet")?,
            notes_protocol_with_records(),
        ))
        .await?;
        let spec = notes_protocol_with_records().spec().clone();
        let protocol = std::sync::Arc::new(
            pubky_switch_client::testing::TestProtocol::new(spec).observing_deletions(),
        );
        let (mut reader, _) = Box::pin(joined_as(
            world,
            &alice,
            &mut signer,
            asking("phone")?,
            protocol,
        ))
        .await?;
        let target = RecordTarget::new(notes_collection(), b"shopping list");
        let value = br#"{"items":["milk"]}"#;
        Box::pin(writer.put_record(&target, value, vec![])).await?;
        Box::pin(reader.receive(None)).await?;
        let delete = Box::pin(writer.delete_record(&target, vec![])).await?;
        let evidence = writer.shared_evidence().await?;
        let [write] = evidence.ops.as_slice() else {
            return Err("expected the deleted record".into());
        };
        let hash = SignedOp::peek(&write.op)?.item_hash()?;
        Box::pin(reader.receive(None)).await?;
        assert_eq!(
            reader
                .protocol_get(crate::parties::NOTES, &hash)
                .await?
                .as_deref(),
            Some(value.as_slice())
        );
        Box::pin(reader.flush_cursor()).await?;
        assert!(reader.service_cursor().seq >= delete.version.version);
        Ok(())
    }

    #[tokio::test]
    async fn test_record_deletion_observation_at_both_switches() {
        for backend in [Backend::Service, Backend::Scripted] {
            Box::pin(run_here(backend, observe_deleted_record))
                .await
                .unwrap();
        }
    }

    #[tokio::test]
    async fn test_record_job_stopped_names_the_signed_delete_at_both_switches() {
        for backend in [Backend::Service, Backend::Scripted] {
            Box::pin(run_here(backend, stopped_record_job))
                .await
                .unwrap();
        }
    }
}
