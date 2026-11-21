//! A provider loss and the recovery after it (Switch spec 12.6 steps 1 and 2, Switch wire
//! 3.3, 3.7, 7.4.1, 7.4.2, 7.4.14): the signer declares the service it is enrolled at lost,
//! enrolls at a service, delivers the next generation's first document there, and the
//! staged admission the recovery starts is ended, by the signer or by an app's upload.
//!
//! The recovery's own record, the `recovery` transition that starts the new chain, is in
//! no answer to the signer. Four flows show it, [`provider_loss`],
//! [`provider_loss_sender_admitted`], [`provider_loss_in_place`] and
//! [`provider_loss_in_place_sender`]: the wallet follows the
//! recovery there, registers at the service, reads the new chain from its first item, and
//! uploads what it holds. The other three compare neither the record nor the start of the
//! chain. What an upload merges is in [`super::upload`].

#[cfg(test)]
mod member;
#[cfg(test)]
pub(super) use member::{app_env, join_member};
#[cfg(test)]
mod tests;

use std::sync::Arc;

use pubky_switch::limits::Limits;
use pubky_switch_client::app::{App, DOC_CACHE_MS, OutgoingMessage};
use pubky_switch_client::store::MemoryStore;
use pubky_switch_client::testing::TestProtocol;
use pubky_switch_core::records::IdentityDoc;
use pubky_switch_signer::{Signer, SignerStatus, UserConfirmed};
use serde_json::{Value, json};

use super::enrollment::{enroll, status};
use super::join::{app_status, events};
use super::messaging::joined;
use super::upload::{CAROLS_FIRST_CALL, expect_lists};
use super::{ORIGIN, STEP_MS};
use crate::parties::NOTE_KIND;
use crate::{FlowResult, World};

/// Where the sender's identity is enrolled: a service that isn't lost.
pub(super) const SENDERS_ORIGIN: &str = "https://senders.example";

/// The service the identity recovers at.
pub(super) const RECOVERY_ORIGIN: &str = "https://recovery.example";

/// What a recovery's version shows, for the trace.
pub(super) fn recovered(
    doc: &IdentityDoc,
    signer: &Signer,
) -> Result<Value, Box<dyn std::error::Error>> {
    Ok(json!({
        "version": doc.version(),
        "generation": doc.generation(),
        "recovery_from": doc.body().recovery_from,
        "data_epoch": doc.data_epoch(),
        "apps": doc.body().apps.len(),
        "removed": doc.body().removed.len(),
        "inbox": doc.inbox().url,
        "signer": status(signer)?,
    }))
}

/// An error as `Debug` shows it, without the switch's `message`s: a message is for people,
/// not for programs (Switch wire 7.6), and the two switches word theirs apart, so the
/// trace keeps none, here as in an answer's body.
pub(super) fn shown_without_messages(error: &impl std::fmt::Debug) -> String {
    const MESSAGE: &str = "message: \"";
    let shown = format!("{error:?}");
    let mut kept = String::with_capacity(shown.len());
    let mut rest = shown.as_str();
    while let Some(at) = rest.find(MESSAGE) {
        kept.push_str(&rest[..at]);
        let text = &rest[at + MESSAGE.len()..];
        // The message ends at the first quote `Debug` didn't escape.
        let mut escaped = false;
        let end = text
            .char_indices()
            .find(|&(_, c)| {
                let ends = c == '"' && !escaped;
                escaped = c == '\\' && !escaped;
                ends
            })
            .map_or(text.len(), |(index, _)| index + 1);
        rest = text[end..].strip_prefix(", ").unwrap_or(&text[end..]);
    }
    kept.push_str(rest);
    kept
}

/// How a party's call ended, for the trace: the error's kinds and the status a switch
/// refused with, never its text.
pub(super) fn ended<T, E: std::fmt::Debug>(result: &Result<T, E>) -> Value {
    match result {
        Ok(_) => json!({ "ok": true }),
        Err(error) => {
            let shown = shown_without_messages(error);
            let kinds: Vec<&str> = shown
                .split(|c: char| !c.is_ascii_alphanumeric())
                .filter(|word| word.chars().next().is_some_and(|c| c.is_ascii_uppercase()))
                .take(4)
                .collect();
            let status = shown.split_once("status: ").and_then(|(_, rest)| {
                let digits: String = rest.chars().take_while(char::is_ascii_digit).collect();
                digits.parse::<u16>().ok()
            });
            json!({ "ok": false, "error": kinds.join(" "), "status": status })
        }
    }
}

/// Fail the flow unless the run's last request labelled `label` was answered `status` with
/// the error `code`: what the step must be at either switch, not only alike at both.
pub(super) fn expect_answer(world: &World, label: &str, status: u16, code: &str) -> FlowResult {
    let [was, with, _] = world
        .last_answer(label)
        .ok_or_else(|| format!("no request {label} was sent"))?;
    if was == status.to_string() && with == format!("text {code}") {
        Ok(())
    } else {
        Err(format!("{label} was answered {was} {with}, not {status} {code}").into())
    }
}

/// Fail the flow unless the signer's `POST /recovery/admission` was answered `200` and its
/// call ended well (Switch wire 7.4.14).
fn expect_admission_ended<T, E>(world: &World, ending: &Result<T, E>) -> FlowResult {
    let answered = world.last_fact("{alice} POST /v1/{alice}/recovery/admission", "status");
    if ending.is_ok() && answered.as_deref() == Some("200") {
        Ok(())
    } else {
        Err(format!(
            "the staged admission wasn't ended: the call {}, answered {answered:?}",
            if ending.is_ok() {
                "went well"
            } else {
                "failed"
            }
        )
        .into())
    }
}

/// The request an app's upload is, by the app's name.
pub(super) fn upload_of(app: &str) -> String {
    format!("{{alice/{app}}} POST /v1/{{alice}}/recovery/upload")
}

/// alice's app `name` follows the recovery (Switch spec 12.6 steps 1 to 3): it reads her
/// newest `identity.json` from the Homeserver, finds the new service in it, registers
/// there, reads the new chain's first item, and uploads what it holds: its evidence, then
/// its copy of the lists.
///
/// The app is the one that reads the new chain from its start, so its read is held to the
/// record a recovery begins with: the `recovery` transition at `seq` 1, naming the
/// generation `lost` (Switch wire 7.4.2). No answer to the signer shows that record; a
/// service transition is shown in full to every own app (Switch wire 7.4.4).
pub(super) async fn follow_recovery(
    world: &World,
    app: &mut App,
    name: &str,
    lost: u64,
) -> FlowResult {
    // As when the Homeserver's event stream names the document (Switch spec 4.3).
    let start = world.trace().lines.len();
    let refreshed = app.refresh_identity().await;
    let followed = app.follow_provider().await;
    world.outcome(
        &format!("the {name} followed the recovery"),
        &json!({
            "refreshed": ended(&refreshed),
            "ended": ended(&followed),
            "events": events(&app.take_events()),
            "app": app_status(app),
        }),
    );
    world.advance_ms(STEP_MS);
    if followed.is_err() {
        return Err(format!("the {name}'s follow ended {}", ended(&followed)).into());
    }
    let read = format!("{{alice/{name}}} GET /v1/{{alice}}/feed");
    let trace = world.trace();
    let opening = trace.lines[start..]
        .iter()
        .find(|line| line.label == read)
        .ok_or("the app didn't read the new chain")?;
    let fact = |fact: &str| opening.facts.get(&format!("body.items[0].{fact}")).cloned();
    let first = (
        fact("seq"),
        fact("item.body~.type"),
        fact("item.body~.recovery_from"),
    );
    let record = (
        Some("number 1".to_owned()),
        Some("text recovery".to_owned()),
        Some(format!("number {lost}")),
    );
    if first != record {
        return Err(format!("the new chain's first item is {first:?}, not {record:?}").into());
    }
    Ok(())
}

/// Fail the flow unless the last upload of alice's app `name` was taken, and its `lists`
/// added an entry exactly when `lists` says so (Switch wire 7.4.14, "Answer").
pub(super) fn expect_upload(world: &World, name: &str, lists: bool) -> FlowResult {
    let upload = upload_of(name);
    let status = world.last_fact(&upload, "status");
    let added = world.last_fact(&upload, "body.result.lists");
    if status.as_deref() == Some("200") && added == Some(format!("bool {lists}")) {
        Ok(())
    } else {
        Err(format!("the {name}'s upload was answered {status:?}, lists {added:?}").into())
    }
}

/// Fail the flow unless the signer's last read of the apps says admission is staged
/// exactly when `staged` says so (Switch wire 7.4.12 `recovery`).
pub(super) fn expect_staged(world: &World, staged: bool) -> FlowResult {
    let shown = world.last_fact(
        "{alice} GET /v1/{alice}/apps",
        "body.recovery.admission_staged",
    );
    if shown == Some(format!("bool {staged}")) {
        Ok(())
    } else {
        Err(format!("the apps read says admission_staged {shown:?}, not {staged}").into())
    }
}

/// bob's delivery of his `identity.json` to alice's switch, his first call when he writes
/// to her at a service that doesn't hold it.
pub(super) const BOBS_FIRST_CALL: &str = "{bob/shop} PUT /v1/{alice}/peers";

/// `shop` sends alice a note, or tries its queued ones again, and the flow notes how each
/// stands.
pub(super) async fn send(
    world: &World,
    name: &str,
    shop: &mut App,
    to: Option<[u8; 32]>,
) -> FlowResult {
    let outcome = match to {
        Some(to) => {
            let mut body = serde_json::Map::new();
            body.insert("text".into(), json!("hello"));
            let sent = shop.send(OutgoingMessage::new(to, NOTE_KIND, body)).await;
            json!({
                "delivery": sent.as_ref().ok().map(|(_, delivery)| {
                    format!("{delivery:?}").split(' ').next().map(str::to_owned)
                }),
                "ok": sent.is_ok(),
            })
        }
        None => {
            let flushed = shop.flush_outbox().await?;
            json!({
                "done": flushed.done.len(),
                "queued": flushed.queued.len(),
                "failed": flushed.failed.len(),
                "undelivered": flushed.undelivered.len(),
            })
        }
    };
    world.outcome(
        name,
        &json!({ "sent": outcome, "events": events(&shop.take_events()) }),
    );
    world.advance_ms(STEP_MS);
    Ok(())
}

/// A provider loss and a recovery at another service. alice's signer declares the loss: it
/// enrolls at the new service, delivers the next generation's first document, which lists
/// her wallet, and publishes it. The wallet manages the lists, so the recovery leaves
/// admission staged for its upload; here the signer ends it first, on the user's word. The
/// wallet then follows the recovery and uploads what it holds, which is no contact. bob's
/// shop writes to alice: the service judges him by its lists, which are empty.
///
/// Calls: `POST /v1/enroll` at the new service, `PUT /v1/{id}/identity` with a recovery's
/// first document, `GET /v1/{id}/apps` with `recovery`, `POST /v1/{id}/recovery/admission`,
/// an app's registration and its `POST /v1/{id}/recovery/upload` after the admission
/// ended, and a sender's `PUT /v1/{id}/peers` at an account recovered and not rebuilt.
///
/// # Errors
///
/// When a step that should succeed against any switch fails.
pub async fn provider_loss(world: &World) -> FlowResult {
    let alice = world.identity("alice")?;
    let bob = world.identity("bob")?;
    world.add_switch(ORIGIN, &[&alice]).await?;
    world.add_switch(SENDERS_ORIGIN, &[&bob]).await?;
    let mut alice_signer = enroll(world, &alice, ORIGIN).await?;
    let mut bob_signer = enroll(world, &bob, SENDERS_ORIGIN).await?;
    let (mut wallet, _) = joined(world, &alice, &mut alice_signer, "wallet").await?;
    let (mut shop, _) = joined(world, &bob, &mut bob_signer, "shop").await?;

    Box::pin(wallet.retain_loss_uploads()).await?;

    // The service is gone, and another stands ready.
    world.lose_switch(ORIGIN);
    world.add_switch(RECOVERY_ORIGIN, &[&alice]).await?;
    let doc = alice_signer
        .declare_provider_loss(RECOVERY_ORIGIN, UserConfirmed::shown_and_confirmed())
        .await?;
    world.outcome(
        "the signer declared the loss and recovered elsewhere",
        &recovered(&doc, &alice_signer)?,
    );
    world.advance_ms(STEP_MS);

    let ending = alice_signer.end_staged_admission().await;
    world.outcome(
        "the signer ended the staged admission",
        &json!({ "ended": ended(&ending), "signer": status(&alice_signer)? }),
    );
    expect_admission_ended(world, &ending)?;
    world.advance_ms(STEP_MS);

    // The wallet's lists upload comes after the end: it carries no contact, adds nothing,
    // and staged admission doesn't start again (Switch wire 7.4.14).
    follow_recovery(world, &mut wallet, "wallet", 1).await?;
    expect_upload(world, "wallet", false)?;
    let opening = Box::pin(wallet.recovery_roster())
        .await?
        .ok_or("the recovery roster is missing")?;
    if opening.hash() != doc.hash() {
        return Err("the wallet kept a different opening document".into());
    }

    let observations = Box::pin(wallet.loss_uploads(opening.generation())).await?;
    let [observation] = observations.as_slice() else {
        return Err("the recovery evidence step was not retained once".into());
    };
    let (inputs, local) = Box::pin(wallet.loss_upload_inputs(observation)).await?;
    if observation.app_id != wallet.app_id()
        || observation.opening_hash != Some(opening.hash())
        || !local.omitted.is_empty()
        || inputs.lists.is_some()
        || !matches!(
            observation.outcome,
            pubky_switch_client::app::LossUploadOutcome::Answered { .. }
                | pubky_switch_client::app::LossUploadOutcome::NoRequest
        )
    {
        return Err("the wallet's loss evidence step has no matching outcome".into());
    }

    send(
        world,
        "bob's shop wrote to alice once admission had ended",
        &mut shop,
        Some(alice.public()),
    )
    .await?;
    // Ended, bob is judged by the lists, which are empty at the new service.
    expect_answer(world, BOBS_FIRST_CALL, 403, "not_admitted")?;

    alice_signer.run_due().await?;
    world.outcome("alice's signer ran what is due", &status(&alice_signer)?);
    expect_staged(world, false)?;
    Ok(())
}

/// A sender held back while admission is staged, and admitted once alice's wallet has
/// brought her lists. bob is alice's contact, and his shop has written to her; carol is a
/// contact she blocked. Her service is lost and her signer recovers at another, which
/// holds no list: admission is staged, and bob's next note is answered `503 staged`, as a
/// stranger's would be, and so is carol's. The wallet follows the recovery; its upload
/// carries her contacts and her deny list and ends the staged admission (Switch spec 12.6
/// step 2). bob's shop tries again and is admitted, and the wallet reads his note at the
/// new service. carol's stall tries again and is refused: the deny list is in force from
/// the moment anyone is admitted.
///
/// Calls: a sender's calls at a staged account (`503 staged`); `POST
/// /v1/{id}/recovery/upload` with `lists.kept` from an app holding `lists.manage`;
/// `GET /v1/{id}/apps` with `admission_staged` false after it; a contact's `PUT
/// /v1/{id}/peers`, `GET /v1/{id}/directory` and `POST /v1/{id}/inbox` after the upload.
///
/// # Errors
///
/// When a step that should succeed against any switch fails.
pub async fn provider_loss_sender_admitted(world: &World) -> FlowResult {
    let alice = world.identity("alice")?;
    let bob = world.identity("bob")?;
    let carol = world.identity("carol")?;
    world.add_switch(ORIGIN, &[&alice]).await?;
    world.add_switch(SENDERS_ORIGIN, &[&bob, &carol]).await?;
    let mut alice_signer = enroll(world, &alice, ORIGIN).await?;
    let mut bob_signer = enroll(world, &bob, SENDERS_ORIGIN).await?;
    let mut carol_signer = enroll(world, &carol, SENDERS_ORIGIN).await?;
    let (mut wallet, wallet_protocol) = joined(world, &alice, &mut alice_signer, "wallet").await?;
    let (mut shop, _) = joined(world, &bob, &mut bob_signer, "shop").await?;
    let (mut stall, _) = joined(world, &carol, &mut carol_signer, "stall").await?;

    wallet.keep_peer(&bob.public()).await?;
    world.advance_ms(STEP_MS);
    wallet.keep_peer(&carol.public()).await?;
    world.advance_ms(STEP_MS);
    wallet.deny(&carol.public()).await?;
    world.outcome(
        "the wallet saved bob and carol as contacts and blocked carol",
        &app_status(&mut wallet),
    );
    world.advance_ms(STEP_MS);
    send(
        world,
        "bob's shop wrote to alice, as a contact",
        &mut shop,
        Some(alice.public()),
    )
    .await?;
    read_notes(
        world,
        "the wallet read bob's note",
        &mut wallet,
        &wallet_protocol,
        1,
    )
    .await?;

    world.lose_switch(ORIGIN);
    world.add_switch(RECOVERY_ORIGIN, &[&alice]).await?;
    let doc = alice_signer
        .declare_provider_loss(RECOVERY_ORIGIN, UserConfirmed::shown_and_confirmed())
        .await?;
    world.outcome(
        "the signer declared the loss and recovered elsewhere",
        &recovered(&doc, &alice_signer)?,
    );
    // bob's shop uses its copy of alice's `identity.json` for ten minutes (Switch spec 4.3):
    // until then it would write to the service that is gone.
    world.advance_ms(DOC_CACHE_MS);

    send(
        world,
        "bob's shop wrote to alice while admission was staged",
        &mut shop,
        Some(alice.public()),
    )
    .await?;
    // Staged, the service holds every sender back (Switch spec 12.6 step 2). bob wrote to
    // alice before, so his shop asks for her directory first (Switch wire 7.4.10).
    expect_answer(world, "{bob/shop} GET /v1/{alice}/directory", 503, "staged")?;
    // carol, blocked, is held back the same way: the staging tells her nothing.
    send(
        world,
        "carol's stall wrote to alice while admission was staged",
        &mut stall,
        Some(alice.public()),
    )
    .await?;
    expect_answer(world, CAROLS_FIRST_CALL, 503, "staged")?;

    follow_recovery(world, &mut wallet, "wallet", 1).await?;
    expect_upload(world, "wallet", true)?;
    alice_signer.run_due().await?;
    world.outcome(
        "alice's signer ran what is due, the admission ended by the upload",
        &status(&alice_signer)?,
    );
    expect_staged(world, false)?;

    send(
        world,
        "bob's shop tried again once the wallet had uploaded",
        &mut shop,
        None,
    )
    .await?;
    for call in ["PUT /v1/{alice}/peers", "POST /v1/{alice}/inbox"] {
        let answered = world.last_fact(&format!("{{bob/shop}} {call}"), "status");
        if answered.as_deref() != Some("200") {
            return Err(format!("bob's {call} was answered {answered:?}").into());
        }
    }
    // The same upload brought the deny list: carol, a contact too, is refused as soon as
    // anyone is admitted.
    send(
        world,
        "carol's stall tried again once the wallet had uploaded",
        &mut stall,
        None,
    )
    .await?;
    expect_answer(world, CAROLS_FIRST_CALL, 403, "not_admitted")?;
    expect_lists(
        world,
        "the lists at the new service",
        &mut wallet,
        &[&bob, &carol],
        &[&carol],
    )
    .await?;
    read_notes(
        world,
        "the wallet read bob's note at the new service",
        &mut wallet,
        &wallet_protocol,
        2,
    )
    .await?;
    Ok(())
}

/// A sender who writes during a recovery in place. bob is alice's contact and has written
/// to her. Her signer declares her service's generation lost at the same origin, so bob's
/// shop, which still holds her earlier `identity.json`, writes where it wrote before: the
/// account, started afresh, holds no list, admission is staged, and the inbox answers
/// `503 staged`. alice's wallet follows the recovery and its upload brings her contacts;
/// bob's shop reads her newest document, tries again and is admitted. The directory he
/// reads then shows higher versions than before the recovery: they are the account's and
/// went on counting.
///
/// Calls: `POST /v1/{id}/inbox` at a staged account (`503 staged`), from a sender who
/// holds the document of the generation lost; the same sender's calls after the upload.
///
/// # Errors
///
/// When a step that should succeed against any switch fails.
pub async fn provider_loss_in_place_sender(world: &World) -> FlowResult {
    let alice = world.identity("alice")?;
    let bob = world.identity("bob")?;
    world.add_switch(ORIGIN, &[&alice]).await?;
    world.add_switch(SENDERS_ORIGIN, &[&bob]).await?;
    let mut alice_signer = enroll(world, &alice, ORIGIN).await?;
    let mut bob_signer = enroll(world, &bob, SENDERS_ORIGIN).await?;
    let (mut wallet, wallet_protocol) = joined(world, &alice, &mut alice_signer, "wallet").await?;
    let (mut shop, _) = joined(world, &bob, &mut bob_signer, "shop").await?;
    wallet.keep_peer(&bob.public()).await?;
    world.outcome(
        "the wallet saved bob as a contact",
        &app_status(&mut wallet),
    );
    world.advance_ms(STEP_MS);
    send(
        world,
        "bob's shop wrote to alice, as a contact",
        &mut shop,
        Some(alice.public()),
    )
    .await?;
    read_notes(
        world,
        "the wallet read bob's note",
        &mut wallet,
        &wallet_protocol,
        1,
    )
    .await?;

    let before = directory_versions(world)?;

    let doc = alice_signer
        .declare_provider_loss(ORIGIN, UserConfirmed::shown_and_confirmed())
        .await?;
    world.outcome(
        "the signer declared the loss and recovered in place",
        &recovered(&doc, &alice_signer)?,
    );
    world.advance_ms(STEP_MS);

    send(
        world,
        "bob's shop wrote to alice while admission was staged",
        &mut shop,
        Some(alice.public()),
    )
    .await?;
    expect_answer(world, "{bob/shop} POST /v1/{alice}/inbox", 503, "staged")?;

    follow_recovery(world, &mut wallet, "wallet", 1).await?;
    expect_upload(world, "wallet", true)?;
    // The account answers under its new key, which bob's shop doesn't know while it uses
    // its copy of alice's `identity.json`, for ten minutes (Switch spec 4.3): it takes no
    // answer for the service's word until it has read the document again.
    world.advance_ms(DOC_CACHE_MS);
    send(
        world,
        "bob's shop tried again once the wallet had uploaded",
        &mut shop,
        None,
    )
    .await?;
    let answered = world.last_fact("{bob/shop} POST /v1/{alice}/inbox", "status");
    if answered.as_deref() != Some("200") {
        return Err(format!("bob's note was answered {answered:?}").into());
    }
    // The wallet stopped being reachable at recovery and became reachable again when
    // it registered its receive key (Switch wire 7.4.10).
    let after = directory_versions(world)?;
    if after.0 <= before.0 || after.1.checked_sub(before.1) != Some(2) {
        return Err(format!(
            "the directory's versions were {before:?} before the recovery and are {after:?}"
        )
        .into());
    }
    read_notes(
        world,
        "the wallet read bob's note after the recovery",
        &mut wallet,
        &wallet_protocol,
        2,
    )
    .await?;
    Ok(())
}

/// The `directory_version` and the `apps_version` bob's shop read last in alice's
/// directory.
fn directory_versions(world: &World) -> Result<(u64, u64), Box<dyn std::error::Error>> {
    let version = |name: &str| -> Result<u64, Box<dyn std::error::Error>> {
        let shown = world
            .last_fact(
                "{bob/shop} GET /v1/{alice}/directory",
                &format!("body.{name}"),
            )
            .ok_or_else(|| format!("no directory read shows {name}"))?;
        Ok(shown
            .strip_prefix("number ")
            .ok_or_else(|| format!("{name} reads {shown}"))?
            .parse()?)
    };
    Ok((version("directory_version")?, version("apps_version")?))
}

/// `app` follows its feed; the flow fails unless its protocol has taken `notes` messages
/// by then.
async fn read_notes(
    world: &World,
    name: &str,
    app: &mut App,
    protocol: &TestProtocol,
    notes: usize,
) -> FlowResult {
    let report = app.receive(None).await?;
    app.flush_cursor().await?;
    let received = protocol.received().len();
    world.outcome(
        name,
        &json!({
            "events": events(&report.events),
            "stopped": report.stopped,
            "messages": received,
            "app": app_status(app),
        }),
    );
    world.advance_ms(STEP_MS);
    if received == notes {
        Ok(())
    } else {
        Err(format!("{name}: the wallet holds {received} notes, not {notes}").into())
    }
}

/// A recovery in place: alice's service still serves, and her signer declares its
/// generation lost there. The enrollment is answered with the service's one key, and the
/// version naming it starts the account afresh. The first enrollment of the run is then
/// sent again as a retry still on its way: the service's key is still the one its answer
/// named, so it gets that answer again, `200` (Switch wire 3.7: "The same enrollment again
/// gets the same answer, byte for byte, while the service's key is the one that answer
/// named"). The wallet follows the
/// recovery at the same origin; it manages the lists, so its upload, which carries no
/// contact, ends the staged admission, and the signer, asked to end it, finds nothing to
/// end and sends no call. The signer then signs on at the service.
///
/// Calls: `POST /v1/enroll` at a serving account, `PUT /v1/{id}/identity` with a recovery's
/// first document, `POST /v1/enroll` with an enrollment answered before the generation
/// started, and `POST /v1/{id}/recovery/upload` with empty `lists.kept` from an
/// app holding `lists.manage`, which ends staged admission.
///
/// # Errors
///
/// When a step that should succeed against any switch fails.
pub async fn provider_loss_in_place(world: &World) -> FlowResult {
    let alice = world.identity("alice")?;
    world.add_switch(ORIGIN, &[&alice]).await?;
    let mut signer = enroll(world, &alice, ORIGIN).await?;
    let (mut wallet, _) = joined(world, &alice, &mut signer, "wallet").await?;

    let doc = signer
        .declare_provider_loss(ORIGIN, UserConfirmed::shown_and_confirmed())
        .await?;
    world.outcome(
        "the signer declared the loss and recovered in place",
        &recovered(&doc, &signer)?,
    );
    world.advance_ms(STEP_MS);

    // Sent now, before anything else takes time: the enrollment was signed at the run's
    // start, and a switch answers one whose timestamp is more than five minutes old `401
    // stale_timestamp`, whatever became of its key (Switch wire 7.1). The flow is four
    // steps of 61.25 seconds in here.
    let retried = world.enroll_again(0).await?;
    world.outcome(
        "the first enrollment, sent again",
        &json!({ "status": retried.status }),
    );
    // The service's key is still the one its answer named: the same answer again (Switch
    // wire 3.7).
    if retried.status != 200 {
        return Err(format!("the first enrollment again was answered {}", retried.status).into());
    }
    world.advance_ms(STEP_MS);
    follow_recovery(world, &mut wallet, "wallet", 1).await?;
    expect_upload(world, "wallet", false)?;

    let sent = world.requests_sent();
    let ending = signer.end_staged_admission().await;
    world.outcome(
        "the signer found the staged admission ended",
        &json!({ "ended": ended(&ending), "signer": status(&signer)? }),
    );
    expect_staged(world, false)?;
    let asked = world.last_fact("{alice} POST /v1/{alice}/recovery/admission", "status");
    if ending.is_err() || asked.is_some() || world.requests_sent() != sent + 1 {
        return Err(format!(
            "the signer's end of an admission already ended: {}, a call answered {asked:?}",
            ended(&ending)
        )
        .into());
    }
    world.advance_ms(STEP_MS);
    let next = signer.set_record_max_age(Some(60)).await?;
    world.outcome("the signer signed on", &recovered(&next, &signer)?);
    Ok(())
}

/// Where a recovery is refused: a service whose app limit is below the apps alice lists.
const SMALL_ORIGIN: &str = "https://small.example";

/// A recovery refused, then declared again elsewhere. alice lists two apps; the service
/// her signer first recovers at takes one. It refuses the recovery's first document for
/// good, and the signer shows the recovery as refused there, signing nothing else. The
/// user declares the loss again at another service, which takes it, at a higher version of
/// the same generation.
///
/// Calls: `POST /v1/enroll` at two services, and `PUT /v1/{id}/identity` with a first
/// document over the service's app limit, refused.
///
/// # Errors
///
/// When a step that should succeed against any switch fails.
pub async fn provider_loss_refused(world: &World) -> FlowResult {
    let alice = world.identity("alice")?;
    world.add_switch(ORIGIN, &[&alice]).await?;
    let mut signer = enroll(world, &alice, ORIGIN).await?;
    let (_wallet, _) = joined(world, &alice, &mut signer, "wallet").await?;
    let (_phone, _) = joined(world, &alice, &mut signer, "phone").await?;

    world.lose_switch(ORIGIN);
    let one_app = Limits {
        app_limit: 1,
        ..Limits::default()
    };
    world
        .add_switch_with(SMALL_ORIGIN, &[&alice], one_app)
        .await?;
    let refused = signer
        .declare_provider_loss(SMALL_ORIGIN, UserConfirmed::shown_and_confirmed())
        .await;
    world.outcome(
        "the service refused the recovery",
        &json!({ "ended": ended(&refused), "signer": status(&signer)? }),
    );
    let shown = signer.status();
    if !matches!(&shown, SignerStatus::RecoveryRefused { origin } if origin == SMALL_ORIGIN) {
        return Err(format!("the signer is {shown:?}, not refused at {SMALL_ORIGIN}").into());
    }
    world.advance_ms(STEP_MS);
    // Refused, the recovery waits to be declared again: a run sends nothing.
    let sent = world.requests_sent();
    let waiting = signer.resume().await;
    if world.requests_sent() != sent {
        return Err("the signer sent something while its recovery was refused".into());
    }
    world.outcome(
        "the signer's next run, the recovery refused",
        &json!({ "ended": ended(&waiting), "signer": status(&signer)? }),
    );
    world.advance_ms(STEP_MS);

    world.add_switch(RECOVERY_ORIGIN, &[&alice]).await?;
    let doc = signer
        .declare_provider_loss(RECOVERY_ORIGIN, UserConfirmed::shown_and_confirmed())
        .await?;
    world.outcome(
        "the signer declared the loss again, elsewhere",
        &recovered(&doc, &signer)?,
    );
    Ok(())
}

/// An enrollment that takes four sends, the first three refused in transit (Switch wire
/// 7.4.1 Errors). Each is answered in the service's place by something that holds none of
/// its keys: a `400`, a `503 unavailable` and a `200` no key signs. The signer hasn't
/// pinned the new service's key, so it can check none of them and takes none for the
/// service's word; an enrollment error changes nothing, and the signer sends the same
/// enrollment again. After the `400` it does so in the same run; the `503` and the answer
/// that doesn't verify end the run, and the next run sends the same bytes. The fourth send
/// reaches the service, and the recovery completes.
///
/// Calls: `POST /v1/enroll` four times, the first three never reaching the service.
///
/// # Errors
///
/// When a step that should succeed against any switch fails, the signer signs another
/// enrollment or sends it other than four times, or a fault met no request.
pub async fn provider_loss_refusals_in_transit(world: &World) -> FlowResult {
    let alice = world.identity("alice")?;
    world.add_switch(ORIGIN, &[&alice]).await?;
    let mut signer = enroll(world, &alice, ORIGIN).await?;
    let (_wallet, _) = joined(world, &alice, &mut signer, "wallet").await?;

    world.lose_switch(ORIGIN);
    world.add_switch(RECOVERY_ORIGIN, &[&alice]).await?;
    let (sent, enrollments) = (world.requests_sent(), world.enrollments_sent());
    world.refuse("POST", "/v1/enroll", 400, "bad_request");
    world.refuse("POST", "/v1/enroll", 503, "unavailable");
    let declared = signer
        .declare_provider_loss(RECOVERY_ORIGIN, UserConfirmed::shown_and_confirmed())
        .await;
    world.outcome(
        "the signer declared the loss, its enrollment refused twice",
        &json!({ "ended": ended(&declared), "signer": status(&signer)? }),
    );
    if declared.is_ok() {
        return Err("the declaration completed after a 503".into());
    }
    world.advance_ms(STEP_MS);

    world.refuse("POST", "/v1/enroll", 200, "ok");
    let unverified = signer.resume().await;
    world.outcome(
        "the signer's next run, its enrollment answered unsigned",
        &json!({ "ended": ended(&unverified), "signer": status(&signer)? }),
    );
    if unverified.is_ok() {
        return Err("the recovery completed on an answer no key signs".into());
    }
    world.advance_ms(STEP_MS);

    let resumed = signer.resume().await;
    let doc = signer
        .identity_doc()?
        .ok_or("the signer holds no identity document")?;
    world.outcome(
        "the signer recovered at its fourth send",
        &json!({ "ended": ended(&resumed), "recovered": recovered(&doc, &signer)? }),
    );
    resumed?;
    if doc.inbox().url != RECOVERY_ORIGIN {
        return Err(format!("the newest version names {}", doc.inbox().url).into());
    }
    // One enrollment, sent four times: an error changes nothing (Switch wire 7.4.1). The
    // recovery's other calls are the delivery and the reads after it.
    let new_enrollments = world.enrollments_sent() - enrollments;
    if new_enrollments != 1 {
        return Err(format!("{new_enrollments} different enrollments were sent, not 1").into());
    }
    let trace = world.trace();
    let sends = trace
        .lines
        .iter()
        .filter(|line| !line.label.starts_with("outcome "))
        .skip(sent)
        .filter(|line| line.label == "{alice} POST /v1/enroll")
        .count();
    if sends != 4 {
        return Err(format!("the enrollment took {sends} sends, not 4").into());
    }
    if world.faults_left() != 0 {
        return Err("a fault met no request".into());
    }
    Ok(())
}

/// A revocation asked for while a recovery is in progress (Switch spec 12.6 step 1, 12.2).
/// alice's service is lost. Her signer declares the loss, and the recovery's first
/// document doesn't reach the new service: the recovery is in progress. She revokes her
/// phone then. Nothing is sent, to the lost service or the new one: the revocation is kept
/// and shown pending. The signer's next run completes the recovery at the new service and
/// sends the revocation there; the version that removes the phone follows.
///
/// Calls: `POST /v1/{id}/apps/{app_id}/revoke` at the service an identity recovered at,
/// for an app the recovery's document lists, and the removing version after it.
///
/// # Errors
///
/// When a step that should succeed against any switch fails, a fault met no request, the
/// revocation sends a request while the recovery is in progress, or the phone isn't
/// revoked and removed at the new service.
pub async fn provider_loss_revocation_meanwhile(world: &World) -> FlowResult {
    let alice = world.identity("alice")?;
    world.add_switch(ORIGIN, &[&alice]).await?;
    let mut signer = enroll(world, &alice, ORIGIN).await?;
    let (mut wallet, _) = joined(world, &alice, &mut signer, "wallet").await?;
    let (phone, _) = joined(world, &alice, &mut signer, "phone").await?;

    world.lose_switch(ORIGIN);
    world.add_switch(RECOVERY_ORIGIN, &[&alice]).await?;
    world.unreachable("PUT", "/identity");
    let declared = signer
        .declare_provider_loss(RECOVERY_ORIGIN, UserConfirmed::shown_and_confirmed())
        .await;
    world.outcome(
        "the signer declared the loss, and its document didn't arrive",
        &json!({ "ended": ended(&declared), "signer": status(&signer)? }),
    );
    world.advance_ms(STEP_MS);

    let sent = world.requests_sent();
    let revoking = signer
        .revoke(phone.app_id(), None, UserConfirmed::shown_and_confirmed())
        .await;
    world.outcome(
        "the signer was asked to revoke the phone, the recovery in progress",
        &json!({ "ended": ended(&revoking), "signer": status(&signer)? }),
    );
    if revoking.is_ok() || world.requests_sent() != sent {
        return Err(format!(
            "a revocation during a recovery ended {} after {} requests",
            ended(&revoking),
            world.requests_sent() - sent
        )
        .into());
    }
    world.advance_ms(STEP_MS);

    // A run while the recovery still can't complete: its document doesn't arrive this
    // time either. The run sends that delivery and nothing else: the revocation waits for
    // the service that takes the recovery, and goes to no other.
    world.unreachable("PUT", "/identity");
    let revocations = revocations_sent(world);
    let meanwhile = signer.run_due().await;
    world.outcome(
        "the signer's run, the recovery still in progress",
        &json!({ "ended": ended(&meanwhile), "signer": status(&signer)? }),
    );
    if meanwhile.is_ok() || revocations_sent(world) != revocations || world.faults_left() != 0 {
        return Err(format!(
            "a run during the recovery ended {} and sent {} revocations",
            ended(&meanwhile),
            revocations_sent(world) - revocations
        )
        .into());
    }
    world.advance_ms(STEP_MS);

    let revoked_at = world.now_ms();
    let resumed = signer.resume().await;
    world.outcome(
        "the signer's next run completed the recovery and sent the revocation",
        &json!({ "ended": ended(&resumed), "signer": status(&signer)? }),
    );
    world.advance_ms(STEP_MS);
    let removed = signer.complete_removals().await?;
    let newest = signer.identity_doc()?;
    world.outcome(
        "the signer removed the phone at the new service",
        &json!({
            "all_removed": removed,
            "apps": newest.as_ref().map(|doc| doc.body().apps.len()),
            "removed": newest.as_ref().map(|doc| doc.body().removed.len()),
            "inbox": newest.as_ref().map(|doc| doc.inbox().url.clone()),
            "signer": status(&signer)?,
        }),
    );
    if world.faults_left() != 0 {
        return Err("a fault met no request".into());
    }
    let revocation = "{alice} POST /v1/{alice}/apps/{alice/phone}/revoke";
    let revoked = world.last_fact(revocation, "status");
    let listed = newest.as_ref().map(|doc| doc.body().apps.len());
    let gone = newest.as_ref().map(|doc| doc.body().removed.len());
    let at_new = newest
        .as_ref()
        .is_some_and(|doc| doc.inbox().url == RECOVERY_ORIGIN);
    // The removal counts from the time the new service took the revocation.
    let dated: Vec<u64> = newest
        .iter()
        .flat_map(|doc| doc.body().removed.iter())
        .map(|removed| removed.distrust_from)
        .collect();
    if revoked.as_deref() != Some("200") || listed != Some(1) || dated != [revoked_at] || !at_new {
        return Err(format!(
            "the revocation was answered {revoked:?}, and the newest version lists {listed:?} \
             apps and removes {gone:?}, dated {dated:?}, not {revoked_at}"
        )
        .into());
    }
    // A surviving app first goes online after the removal (Switch spec 12.6).
    Box::pin(follow_recovery(world, &mut wallet, "wallet", 1)).await?;
    let opening = Box::pin(wallet.recovery_roster())
        .await?
        .ok_or("the recovery roster is missing")?;
    if opening.listed_cert(&phone.app_id()).is_none()
        || !Box::pin(wallet.recovery_removal(&phone.app_id()))
            .await?
            .is_some_and(|doc| doc.lists_removed(&phone.app_id()))
    {
        return Err("the original roster or the subsequent removal is missing".into());
    }
    let removed_version = newest
        .as_ref()
        .ok_or("the removing document is missing")?
        .version();
    world.advance_ms(STEP_MS);
    let purged = Box::pin(signer.purge_removed(phone.app_id())).await?;
    Box::pin(wallet.refresh_identity()).await?;
    if purged.lists_removed(&phone.app_id())
        || wallet.own_identity().hash() != purged.hash()
        || !Box::pin(wallet.recovery_removal(&phone.app_id()))
            .await?
            .is_some_and(|doc| doc.version() == removed_version)
        || Box::pin(wallet.recovery_removal(&wallet.app_id()))
            .await?
            .is_some()
    {
        return Err("the purged phone's original removal did not survive".into());
    }
    Ok(())
}

/// How many revocations the run has sent so far, to any service, answered or not.
fn revocations_sent(world: &World) -> usize {
    let trace = world.trace();
    trace
        .lines
        .iter()
        .filter(|line| line.label.starts_with("{alice} POST ") && line.label.ends_with("/revoke"))
        .count()
}

/// A restore in the middle of a recovery. alice's service is lost with a revocation of her
/// wallet still pending, which it never took. Her signer declares the loss, and the
/// recovery's first document doesn't reach the new service. The install is gone then; a new
/// one is restored from the signer backup on the Homeserver. The restore itself completes
/// the recovery at the new service, signs the version naming the new install, and revokes
/// the wallet there. A run after it finds nothing owed. Completing the removals then
/// delivers the version that removes the wallet, and ends the staged admission.
///
/// Calls: `PUT /v1/{id}/identity` of a recovery by a restored install, `POST
/// /v1/{id}/apps/{app_id}/revoke`, the removal and `POST /v1/{id}/recovery/admission` at
/// the new service.
///
/// # Errors
///
/// When a step that should succeed against any switch fails, or a fault met no request.
pub async fn provider_loss_restored(world: &World) -> FlowResult {
    let alice = world.identity("alice")?;
    world.add_switch(ORIGIN, &[&alice]).await?;
    let mut signer = enroll(world, &alice, ORIGIN).await?;
    let (wallet, _) = joined(world, &alice, &mut signer, "wallet").await?;

    world.lose_switch(ORIGIN);
    let revoking = signer
        .revoke(wallet.app_id(), None, UserConfirmed::shown_and_confirmed())
        .await;
    world.outcome(
        "the signer asked to revoke the wallet, the service lost",
        &json!({ "ended": ended(&revoking), "signer": status(&signer)? }),
    );
    world.advance_ms(STEP_MS);

    world.add_switch(RECOVERY_ORIGIN, &[&alice]).await?;
    world.unreachable("PUT", "/identity");
    let declared = signer
        .declare_provider_loss(RECOVERY_ORIGIN, UserConfirmed::shown_and_confirmed())
        .await;
    world.outcome(
        "the signer declared the loss, and its document didn't arrive",
        &json!({ "ended": ended(&declared), "signer": status(&signer)? }),
    );
    world.advance_ms(STEP_MS);
    drop(signer);

    // A new install, from the backup on the Homeserver.
    let env = world.signer_env(&alice, Arc::new(MemoryStore::new()))?;
    let mut restored = Signer::restore_new(
        env,
        world.keyring(&alice)?,
        UserConfirmed::shown_and_confirmed(),
    )
    .await?;
    world.outcome(
        "a new install was restored: it completed the recovery and revoked the wallet",
        &status(&restored)?,
    );
    let revocation = "{alice} POST /v1/{alice}/apps/{alice/wallet}/revoke";
    let revoked = world.last_fact(revocation, "status");
    world.advance_ms(STEP_MS);
    let sent = world.requests_sent();
    let resumed = restored.resume().await;
    world.outcome(
        "the restored install's next run, nothing owed",
        &json!({
            "ended": ended(&resumed),
            "requests": world.requests_sent() - sent,
            "signer": status(&restored)?,
        }),
    );
    world.advance_ms(STEP_MS);
    let removed = restored.complete_removals().await?;
    let newest = restored.identity_doc()?;
    world.outcome(
        "the restored install removed the wallet and ended the staged admission",
        &json!({
            "all_removed": removed,
            "apps": newest.as_ref().map(|doc| doc.body().apps.len()),
            "removed": newest.as_ref().map(|doc| doc.body().removed.len()),
            "signer": status(&restored)?,
        }),
    );
    if world.faults_left() != 0 {
        return Err("a fault met no request".into());
    }
    // The wallet was revoked at the new service by the restore, the newest version removes
    // it, and the staged admission is ended.
    let listed = newest.as_ref().map(|doc| doc.body().apps.len());
    let gone = newest.as_ref().map(|doc| doc.body().removed.len());
    if revoked.as_deref() != Some("200") || listed != Some(0) || gone != Some(1) || !removed {
        return Err(format!(
            "the revocation was answered {revoked:?}, and the newest version lists {listed:?} \
             apps and removes {gone:?}"
        )
        .into());
    }
    let admission = world.last_fact("{alice} POST /v1/{alice}/recovery/admission", "status");
    if admission.as_deref() != Some("200") {
        return Err(format!("the end of the staged admission was answered {admission:?}").into());
    }
    Ok(())
}

/// A restore in the middle of a recovery in place (Switch spec 12.6 step 1, 12.8, Switch
/// wire 3.13). alice's service still serves, and her signer declares its generation lost
/// there. The enrollment is answered with the service's one key, and the recovery's first
/// document doesn't arrive. The install is gone then; a new one is restored from the signer
/// backup on the Homeserver, which holds that document. The restore delivers it, which
/// starts the account afresh, and then the version naming the new install. The wallet
/// follows the recovery, and the new install signs on.
///
/// Calls: `PUT /v1/{id}/identity` with a recovery's first document, sent by a restored
/// install, and the version naming that install after it.
///
/// # Errors
///
/// When a step that should succeed against any switch fails, a fault met no request, or
/// the restore ends otherwise than at the next generation with the new install signing.
pub async fn provider_loss_in_place_restored(world: &World) -> FlowResult {
    let alice = world.identity("alice")?;
    world.add_switch(ORIGIN, &[&alice]).await?;
    let mut signer = enroll(world, &alice, ORIGIN).await?;
    let (mut wallet, _) = joined(world, &alice, &mut signer, "wallet").await?;
    let before = signer
        .identity_doc()?
        .ok_or("the signer holds no document")?;

    world.unreachable("PUT", "/identity");
    let declared = signer
        .declare_provider_loss(ORIGIN, UserConfirmed::shown_and_confirmed())
        .await;
    world.outcome(
        "the signer declared the loss in place, and its document didn't arrive",
        &json!({ "ended": ended(&declared), "signer": status(&signer)? }),
    );
    if declared.is_ok() || world.faults_left() != 0 {
        return Err("the recovery's document wasn't cut off".into());
    }
    world.advance_ms(STEP_MS);
    drop(signer);

    // A new install, from the backup on the Homeserver.
    let env = world.signer_env(&alice, Arc::new(MemoryStore::new()))?;
    let mut restored = Signer::restore_new(
        env,
        world.keyring(&alice)?,
        UserConfirmed::shown_and_confirmed(),
    )
    .await?;
    let newest = restored
        .identity_doc()?
        .ok_or("the restored install holds no document")?;
    world.outcome(
        "a new install was restored: it completed the recovery in place",
        &json!({
            "generation": newest.generation(),
            "recovery_from": newest.body().recovery_from,
            "version_steps": newest.version() - before.version(),
            "names_the_new_install": newest.body().signer == restored.install_id(),
            "signer": status(&restored)?,
        }),
    );
    let published = world
        .files()
        .identity_doc(&alice.public())
        .map(|doc| doc.version());
    if newest.generation() != before.generation() + 1
        || newest.version() != before.version() + 2
        || newest.body().signer != restored.install_id()
        || restored.status() != SignerStatus::Signing
        || published != Some(newest.version())
    {
        return Err(format!(
            "the restore ended at generation {} and version {}, published {published:?}, \
             the install {:?}",
            newest.generation(),
            newest.version(),
            restored.status()
        )
        .into());
    }
    world.advance_ms(STEP_MS);

    // The wallet's upload, with no contact to bring, ends the staged admission.
    follow_recovery(world, &mut wallet, "wallet", 1).await?;
    expect_upload(world, "wallet", false)?;
    restored.run_due().await?;
    world.outcome("the restored install ran what is due", &status(&restored)?);
    expect_staged(world, false)?;
    world.advance_ms(STEP_MS);
    let next = restored.set_record_max_age(Some(60)).await?;
    world.outcome(
        "the restored install signed on",
        &recovered(&next, &restored)?,
    );
    Ok(())
}

/// A recovery refused at the origin the identity was enrolled at (Switch spec 12.6 step 1,
/// Switch wire 3.3, 7.4.1). alice lists two apps. Her provider loses what it held and
/// serves again at the same origin, empty, and now takes one app an account. Her signer
/// declares the loss there: the service knows no account for her, so the enrollment makes
/// a new one, answered with the service's one key, the one the signer had pinned for this
/// origin ("A service signs with one key for all its accounts", Switch wire 3.3 "Service
/// keys"; the world keeps the origin's key). The recovery's first document lists two apps
/// and is refused, under that key. The signer takes the refusal for the service's word: it
/// shows the recovery as refused there and sends nothing more. Declared again at another
/// service, the recovery completes.
///
/// Calls: `GET /v1/{id}/account` and `POST /v1/enroll` at an origin whose service lost
/// the account, and `PUT /v1/{id}/identity` refused there for the app limit
/// (`400 bad_request`), signed with the key the enrollment named.
///
/// # Errors
///
/// When a step that should succeed against any switch fails, the refusal isn't signed with
/// the service's one key, or the signer doesn't end as refused there, or sends something
/// after it.
pub async fn provider_loss_same_origin_refused(world: &World) -> FlowResult {
    let alice = world.identity("alice")?;
    world.add_switch(ORIGIN, &[&alice]).await?;
    let mut signer = enroll(world, &alice, ORIGIN).await?;
    let (_wallet, _) = joined(world, &alice, &mut signer, "wallet").await?;
    let (_phone, _) = joined(world, &alice, &mut signer, "phone").await?;

    // The same origin, served again with nothing of what it held.
    world.lose_switch(ORIGIN);
    let one_app = Limits {
        app_limit: 1,
        ..Limits::default()
    };
    world.add_switch_with(ORIGIN, &[&alice], one_app).await?;
    let before = world.trace().lines.len();
    let refused = signer
        .declare_provider_loss(ORIGIN, UserConfirmed::shown_and_confirmed())
        .await;
    world.outcome(
        "the service, empty at the same origin, refused the recovery",
        &json!({ "ended": ended(&refused), "signer": status(&signer)? }),
    );
    // The refusal is the service's own, signed with the key its enrollment answer named,
    // the service's one key, which the signer had pinned for this origin: it reads the
    // refusal under it at once, and sends nothing more.
    let delivery = "{alice} PUT /v1/{alice}/identity";
    expect_answer(world, delivery, 400, "bad_request")?;
    let sent: Vec<(String, String)> = world
        .trace()
        .lines
        .iter()
        .skip(before)
        .filter(|line| !line.label.starts_with("outcome "))
        .map(|line| {
            let status = line.facts.get("status").cloned().unwrap_or_default();
            (line.label.clone(), status)
        })
        .collect();
    let expected = [
        ("{alice} GET /v1/{alice}/account", "200"),
        ("{alice} POST /v1/enroll", "200"),
        (delivery, "400"),
    ];
    let as_expected = sent.len() == expected.len()
        && sent
            .iter()
            .zip(expected)
            .all(|((label, status), (wanted, answered))| label == wanted && status == answered);
    if !as_expected {
        return Err(format!(
            "the declaration sent {sent:?}; expected account observation, enrollment and one refused delivery"
        )
        .into());
    }
    // An answer the trace names no key for counts as none.
    let key_of = |label: &str| {
        world
            .last_answer(label)
            .map(|[_, _, key]| key)
            .filter(|key| !key.is_empty())
    };
    let enrolled_under = key_of("{alice} POST /v1/enroll");
    let refused_under = key_of(delivery);
    let shown = signer.status();
    if refused_under != enrolled_under
        || refused_under.is_none()
        || !matches!(&shown, SignerStatus::RecoveryRefused { origin } if origin == ORIGIN)
    {
        return Err(format!(
            "the refusal is signed with {refused_under:?}, the enrollment's answer with \
             {enrolled_under:?}, and the signer is {shown:?}"
        )
        .into());
    }
    world.advance_ms(STEP_MS);
    // Refused, the recovery waits to be declared again: a run sends nothing.
    let sent = world.requests_sent();
    let waiting = signer.resume().await;
    if world.requests_sent() != sent {
        return Err("the signer sent something while its recovery was refused".into());
    }
    world.outcome(
        "the signer's next run, the recovery refused",
        &json!({ "ended": ended(&waiting), "signer": status(&signer)? }),
    );
    world.advance_ms(STEP_MS);

    world.add_switch(RECOVERY_ORIGIN, &[&alice]).await?;
    let doc = signer
        .declare_provider_loss(RECOVERY_ORIGIN, UserConfirmed::shown_and_confirmed())
        .await?;
    world.outcome(
        "the signer declared the loss again, elsewhere",
        &recovered(&doc, &signer)?,
    );
    Ok(())
}
