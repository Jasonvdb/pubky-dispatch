//! An app's own record as its protocol changes it, delivered with `app.put` and published
//! on the Homeserver (Dispatch spec 4.2, 12.1 step 2; Dispatch wire 3.2, 6.2).

use pubky_dispatch_client::DispatchClient;
use pubky_dispatch_client::app::{App, AppConfig, AppError, Publication};
use pubky_dispatch_core::records::{AppRecord, app_record_path};
use serde_json::{Map, Value, json};

use super::enrollment::{enroll, status};
use super::join::{app_status, events};
use super::messaging::{joined, joined_with};
use super::upload::client_of;
use super::{ORIGIN, STEP_MS};
use crate::parties::{Asking, notes_protocol};
use crate::{FlowResult, World};

/// The member's protocol name: the notes protocol's.
const NOTES: &str = "notes";

/// A day in milliseconds.
const DAY_MS: u64 = 24 * 3_600_000;

/// An app that publishes its record joins, publishing its first record; it sets its
/// protocol's member, which the Dispatch takes as a newer record; the answer to the next
/// change is lost, and the app sends the same batch again, which the Dispatch answers with
/// the original proofs; it renews the record, then removes the member. After each step the
/// Homeserver holds the record the Dispatch holds, byte for byte, but while the lost answer
/// leaves the newer record undelivered, and the signer's routine run reads the account's
/// apps with it.
///
/// Calls, beyond the join's: the app's `POST /v1/{id}/ops` (`app.put` of a newer record,
/// and the same batch again after a lost answer), the sibling app's `GET /v1/{id}/directory`
/// after the join and first update, and the signer's `GET /v1/{id}/apps`.
///
/// # Errors
///
/// When a step that should succeed against any Dispatch fails, or the Homeserver holds
/// another record than the app's after a step that published it, or a sibling app reads
/// different record bytes in the directory.
pub async fn own_record(world: &World) -> FlowResult {
    let alice = world.identity("alice")?;
    world.add_dispatch(ORIGIN, &[&alice]).await?;
    let mut signer = enroll(world, &alice, ORIGIN).await?;
    let (reader, _) = Box::pin(joined(world, &alice, &mut signer, "phone")).await?;
    let client = client_of(
        world,
        &alice,
        "phone",
        &reader,
        ORIGIN,
        reader.own_identity().inbox().service_key,
    )?;
    let config = AppConfig {
        publishes_record: true,
        ..AppConfig::default()
    };
    let asking = Asking::new(world.app_keys(&alice, "wallet")?)?;
    let (mut wallet, _) =
        joined_with(world, &alice, &mut signer, asking, notes_protocol(), config).await?;
    world.outcome("joined, published", &published(world, &wallet));
    on_the_homeserver(world, &wallet, true, "the join")?;
    check_directory_record(&client, &wallet, None).await?;
    let joined_record = wallet.record().clone();

    let expires = world.now_ms() + 30 * DAY_MS;
    let mut member = Map::new();
    member.insert("endpoints".into(), json!({ "sample": "payload" }));
    let set = wallet
        .set_protocol_member(NOTES, Some(member.clone()), Some(expires))
        .await?;
    if set != Publication::Published {
        return Err(format!("the member update returned {set:?}").into());
    }
    if wallet.record() == &joined_record {
        return Err("the member update retained the signed join record".into());
    }
    world.outcome("member set", &changed(world, &mut wallet, Ok(set)));
    on_the_homeserver(world, &wallet, true, "the member set")?;
    check_directory_record(&client, &wallet, Some(&member)).await?;
    world.advance_ms(STEP_MS);

    member.insert("more".into(), json!(1));
    world.lose_answer("POST", "/ops");
    let lost = wallet
        .set_protocol_member(NOTES, Some(member), Some(expires))
        .await;
    world.outcome(
        "member changed, its answer lost",
        &changed(world, &mut wallet, lost),
    );
    on_the_homeserver(world, &wallet, false, "the change whose answer was lost")?;
    world.advance_ms(STEP_MS);
    let again = wallet.publish_record().await;
    world.outcome("sent again", &changed(world, &mut wallet, again));
    on_the_homeserver(world, &wallet, true, "the change sent again")?;
    world.advance_ms(STEP_MS);

    let renewed = wallet
        .renew_record(NOTES, Some(world.now_ms() + 30 * DAY_MS))
        .await;
    world.outcome("renewed", &changed(world, &mut wallet, renewed));
    on_the_homeserver(world, &wallet, true, "the renewal")?;
    world.advance_ms(STEP_MS);
    let removed = wallet.set_protocol_member(NOTES, None, None).await;
    world.outcome("member removed", &changed(world, &mut wallet, removed));
    on_the_homeserver(world, &wallet, true, "the member removed")?;
    world.advance_ms(STEP_MS);

    let report = wallet.receive(None).await?;
    world.outcome(
        "received",
        &json!({ "events": events(&report.events), "app": app_status(&mut wallet) }),
    );
    signer.run_due().await?;
    world.outcome("signer ran what is due", &status(&signer)?);
    Ok(())
}

/// The directory reader verifies the signed record the wallet just published (Dispatch wire 3.2).
async fn check_directory_record(
    reader: &DispatchClient,
    writer: &App,
    expected_member: Option<&Map<String, Value>>,
) -> FlowResult {
    let listed = reader
        .directory(None)
        .await?
        .apps
        .into_iter()
        .find(|app| app.app_id == writer.app_id())
        .ok_or("the directory omitted the publishing app")?;
    if listed.record.signed() != writer.record() {
        return Err("the directory returned a different signed app record".into());
    }
    if listed.record.body().protocol(NOTES) != expected_member {
        return Err("the directory record holds a different notes member".into());
    }
    let body: Value = listed.record.signed().peek()?;
    if body.get("label").is_some() {
        return Err("the signed app record contains a display label".into());
    }
    Ok(())
}

/// What a change returned, with the record the app presents and what the Homeserver holds.
fn changed(world: &World, app: &mut App, result: Result<Publication, AppError>) -> Value {
    let ended = match result {
        Ok(Publication::Published) => json!("published"),
        Ok(Publication::NotPublishing) => json!("not publishing"),
        Ok(Publication::Owed { .. }) => json!("owed"),
        Ok(Publication::Superseded) => json!("superseded"),
        Ok(other) => json!(format!("{other:?}")),
        Err(error) => json!({ "error": error.code().map(|code| code.as_str().to_owned()) }),
    };
    json!({
        "ended": ended,
        "record": published(world, app),
        "events": events(&app.take_events()),
    })
}

/// Fail the flow unless whether the Homeserver holds the app's record, byte for byte, is
/// `expected` after `step`.
fn on_the_homeserver(world: &World, app: &App, expected: bool, step: &str) -> FlowResult {
    if holds_record(world, app) != expected {
        return Err(format!(
            "after {step}, the Homeserver {} the app's record",
            if expected { "doesn't hold" } else { "holds" }
        )
        .into());
    }
    Ok(())
}

/// Whether the Homeserver holds the app's record in the same bytes.
fn holds_record(world: &World, app: &App) -> bool {
    world
        .files()
        .file(app.identity(), &app_record_path(&app.app_id()))
        .as_deref()
        .is_some_and(|bytes| serde_json::to_vec(app.record()).is_ok_and(|mine| mine == bytes))
}

/// The app's record, and whether the Homeserver holds it in the same bytes.
fn published(world: &World, app: &App) -> Value {
    let same = holds_record(world, app);
    let record = AppRecord::verify(app.record(), &app.identity()).ok();
    json!({
        "updated_at": record.as_ref().map(AppRecord::updated_at),
        "expires_at": record.as_ref().and_then(AppRecord::expires_at),
        "member": record.as_ref().and_then(|r| r.body().protocol(NOTES).cloned()),
        "on_the_homeserver": same,
    })
}
