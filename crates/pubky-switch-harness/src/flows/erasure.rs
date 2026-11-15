//! The account's erasure, when the user stops using the Switch (Switch spec 12.7, Switch
//! wire 7.4.16).

use pubky_switch_client::app::{App, AppEvent};
use pubky_switch_signer::{Signer, SignerStatus, UserConfirmed};
use serde_json::{Value, json};

use super::enrollment::{enroll, status};
use super::join::{app_status, events};
use super::messaging::joined;
use super::recovery::{expect_staged, expect_upload, follow_recovery};
use super::{ORIGIN, STEP_MS};
use crate::{FlowResult, World};

/// Where the signer stands in an erasure in doubt, for the trace: how its run ended, its
/// state, since when it holds the account as erased but unconfirmed, as far into the flow
/// as the world's clock was then, and whether its `identity.json` is on the Homeserver.
fn in_doubt<T, E: std::fmt::Debug>(
    world: &World,
    started_ms: u64,
    signer: &Signer,
    run: &Result<T, E>,
    identity: &[u8; 32],
) -> Result<Value, Box<dyn std::error::Error>> {
    let unconfirmed_since = match signer.status() {
        SignerStatus::ErasedUnconfirmed { since_ms } => Some(since_ms.saturating_sub(started_ms)),
        _ => None,
    };
    Ok(json!({
        "ended": ended(run),
        "signer": status(signer)?,
        "unconfirmed_since_ms_into_the_flow": unconfirmed_since,
        "published": world.files().identity_doc(identity).is_some(),
    }))
}

/// Fail the flow when the signer doesn't stand where the step says: the steps of the wait
/// are named for what the signer holds at each, on either switch.
fn standing(signer: &Signer, expected: &str, holds: bool) -> FlowResult {
    if holds {
        Ok(())
    } else {
        Err(format!("the signer is {:?}, not {expected}", signer.status()).into())
    }
}

/// How a call ended, for the trace: nothing of an error but its kinds.
fn ended<T, E: std::fmt::Debug>(result: &Result<T, E>) -> Value {
    match result {
        Ok(_) => json!({ "ok": true }),
        Err(error) => {
            let shown = super::recovery::shown_without_messages(error);
            let kinds: Vec<&str> = shown
                .split(|c: char| !c.is_ascii_alphanumeric())
                .filter(|word| word.chars().next().is_some_and(|c| c.is_ascii_uppercase()))
                .take(4)
                .collect();
            json!({ "ok": false, "error": kinds.join(" ") })
        }
    }
}

/// One read of an app whose account was erased, for the trace: how it ended, the events it
/// raised, where the app stands with its service, and whether the identity's
/// `identity.json` is on the Homeserver. Returns whether the read raised `AccountGone`.
async fn read_once_erased(
    world: &World,
    name: &str,
    app: &mut App,
    identity: &[u8; 32],
) -> Result<bool, Box<dyn std::error::Error>> {
    let read = app.receive(None).await;
    let (stopped, raised) = match &read {
        Ok(report) => (Some(report.stopped), report.events.clone()),
        Err(_) => (None, app.take_events()),
    };
    // Where the app stands with its service, asked apart from the read, with the events
    // the asking itself raised.
    let provider = app.follow_provider().await;
    let provider_events = app.take_events();
    world.outcome(
        name,
        &json!({
            "ended": ended(&read),
            "stopped": stopped,
            "events": events(&raised),
            "provider": match &provider {
                Ok(status) => ended_word(&format!("{status:?}")),
                Err(error) => ended_word(&format!("{error:?}")),
            },
            "provider_events": events(&provider_events),
            "app": app_status(app),
            "published": world.files().identity_doc(identity).is_some(),
        }),
    );
    Ok(raised
        .iter()
        .any(|event| matches!(event, AppEvent::AccountGone { .. })))
}

/// The first word of a `Debug` text: a status's or an error's name.
fn ended_word(shown: &str) -> String {
    shown
        .split(|c: char| !c.is_ascii_alphanumeric())
        .next()
        .unwrap_or_default()
        .to_owned()
}

/// Fail the flow when a read of the app's wait raised `AccountGone` or not, against what
/// the step says.
fn gone(raised: bool, expected: bool, step: &str) -> FlowResult {
    if raised == expected {
        Ok(())
    } else if expected {
        Err(format!("{step}: the app didn't take its account as gone").into())
    } else {
        Err(format!("{step}: the app took its account as gone already").into())
    }
}

/// What the world shows of the identity once its signer closed the account: the signer's
/// own state, whether its `identity.json` is still on the Homeserver, what anyone reading
/// the public `identity.json` from the switch gets, an app's next reads, and the signer's
/// next run.
///
/// The app's next read meets the service's `404` saying that it doesn't host the identity,
/// signed with the service key the app pinned and bound to its own request, and a missing
/// `identity.json`: "Both together are an erasure, at once" (Switch spec 12.7 step 5,
/// Switch wire 7.4.16 Afterwards), so that read raises `AccountGone`. The flow deletes
/// nothing itself: the file is missing because the signer's erasure took it off the
/// Homeserver. A read after that asks the switch nothing.
async fn afterwards(
    world: &World,
    name: &str,
    signer: &mut Signer,
    app: &mut App,
    public_path: &str,
    identity: &[u8; 32],
) -> FlowResult {
    world.outcome(
        &format!("{name}: the signer"),
        &json!({
            "signer": status(signer)?,
            "published": world.files().identity_doc(identity).is_some(),
        }),
    );
    let public = world.request("GET", ORIGIN, public_path).await?;
    world.outcome(
        &format!("{name}: the public read"),
        &json!({ "status": public.status }),
    );

    let step = format!("{name}: an app's next read, the account is gone");
    let raised = read_once_erased(world, &step, app, identity).await?;
    gone(raised, true, &step)?;
    world.advance_ms(STEP_MS);
    let step = format!("{name}: the app's read once the account is gone");
    read_once_erased(world, &step, app, identity).await?;

    world.advance_ms(STEP_MS);
    let again = signer.resume().await;
    world.outcome(
        &format!("{name}: the signer's next run"),
        &json!({ "ended": ended(&again), "signer": status(signer)? }),
    );
    Ok(())
}

/// The signer closes the identity's account: `identity.json` leaves the Homeserver, the
/// switch erases the account, and every later call is answered by the not-hosted `404`,
/// signed with the service key.
///
/// An app of the identity takes the account as gone at its next read (Switch spec 12.7
/// step 5).
///
/// Calls: `POST /v1/{id}/erase` (`200`), then the public `GET /v1/{id}/identity` and an
/// own app's `GET /v1/{id}/feed`, each answered `404` with the service key. The signer,
/// holding the account as erased, sends nothing at its next run, nor does the app once it
/// took the account as gone.
///
/// # Errors
///
/// When a step that should succeed against any switch fails.
pub async fn erasure(world: &World) -> FlowResult {
    let alice = world.identity("alice")?;
    world.add_switch(ORIGIN, &[&alice]).await?;
    let mut signer = enroll(world, &alice, ORIGIN).await?;
    let (mut wallet, _) = joined(world, &alice, &mut signer, "wallet").await?;
    let public_path = format!("/v1/{}/identity", alice.key().id());

    let closed = signer
        .close_account(UserConfirmed::shown_and_confirmed())
        .await;
    world.outcome("the account was closed", &ended(&closed));
    world.advance_ms(STEP_MS);
    afterwards(
        world,
        "after the erasure",
        &mut signer,
        &mut wallet,
        &public_path,
        &alice.public(),
    )
    .await
}

/// The erasure's answer is lost: the signer's call fails with the erasure in doubt. Its
/// next run meets the not-hosted `404` its pinned key signed, which "confirms the erasure at
/// once" (Switch wire 7.4.16 "The signer's `404`", Switch spec 12.7 step 5): the account is
/// erased, and the erasure is never sent again. An app of the identity then takes the
/// account as gone, as in [`erasure`].
///
/// Calls: `POST /v1/{id}/erase` with its answer lost; then the signer's read at its next
/// run, answered `404` with the service key; then the calls of [`erasure`] after its
/// `200`.
///
/// # Errors
///
/// When a step that should succeed against any switch fails.
pub async fn erasure_answer_lost(world: &World) -> FlowResult {
    let started_ms = world.now_ms();
    let alice = world.identity("alice")?;
    world.add_switch(ORIGIN, &[&alice]).await?;
    let mut signer = enroll(world, &alice, ORIGIN).await?;
    let (mut wallet, _) = joined(world, &alice, &mut signer, "wallet").await?;
    let public_path = format!("/v1/{}/identity", alice.key().id());

    world.lose_answer("POST", "/erase");
    let lost = signer
        .close_account(UserConfirmed::shown_and_confirmed())
        .await;
    world.outcome(
        "the erasure's answer was lost",
        &in_doubt(world, started_ms, &signer, &lost, &alice.public())?,
    );
    standing(
        &signer,
        "erasing",
        matches!(signer.status(), SignerStatus::Erasing),
    )?;
    world.advance_ms(STEP_MS);
    let first = signer.resume().await;
    world.outcome(
        "the signer's next run meets the signed 404: erased",
        &in_doubt(world, started_ms, &signer, &first, &alice.public())?,
    );
    standing(
        &signer,
        "erased",
        matches!(signer.status(), SignerStatus::Erased),
    )?;
    world.advance_ms(STEP_MS);
    afterwards(
        world,
        "after the erasure",
        &mut signer,
        &mut wallet,
        &public_path,
        &alice.public(),
    )
    .await?;
    if world.faults_left() != 0 {
        return Err("a fault met no request".into());
    }
    Ok(())
}

/// An erased account enrolled again at the same origin (Switch spec 12.7 step 4, Switch
/// wire 7.4.16, 7.4.1). alice's signer closes her account, and the service deletes
/// everything it held for her, her account's mark too. Her signer then declares the loss at
/// the same origin. The service knows no account for her, so the enrollment makes a new one
/// with a new (0, 0) mark, under the service's one key, the erased account's too. The
/// account starts as after a provider loss: its first document is the next generation's,
/// at a higher version, naming the erased one as lost. Her wallet follows the recovery
/// there, and the signer signs on.
///
/// Calls: `POST /v1/enroll` and `PUT /v1/{id}/identity` at an origin whose account was
/// erased, and what follows a recovery there.
///
/// # Errors
///
/// When a step that should succeed against any switch fails, the new account answers
/// under another key than the switch's one key, or doesn't start at the next generation.
pub async fn erasure_enrolled_again(world: &World) -> FlowResult {
    let alice = world.identity("alice")?;
    world.add_switch(ORIGIN, &[&alice]).await?;
    let mut signer = enroll(world, &alice, ORIGIN).await?;
    let (mut wallet, _) = joined(world, &alice, &mut signer, "wallet").await?;
    let before = signer
        .identity_doc()?
        .ok_or("the signer holds no document")?;
    let first_key = world.last_answer("{alice} GET /v1/{alice}/apps");

    let closed = signer
        .close_account(UserConfirmed::shown_and_confirmed())
        .await;
    world.outcome("the account was closed", &ended(&closed));
    if closed.is_err() || signer.status() != SignerStatus::Erased {
        return Err(format!(
            "the account wasn't erased: the signer is {:?}",
            signer.status()
        )
        .into());
    }
    world.advance_ms(STEP_MS);

    let doc = signer
        .declare_provider_loss(ORIGIN, UserConfirmed::shown_and_confirmed())
        .await?;
    world.outcome(
        "the signer enrolled again at the same origin",
        &json!({
            "generation": doc.generation(),
            "recovery_from": doc.body().recovery_from,
            "version_steps": doc.version() - before.version(),
            "signer": status(&signer)?,
        }),
    );
    // The switch's one key signs for the new account, as it did for the erased one
    // (Switch wire 7.1).
    // An answer the trace names no key for counts as none.
    let named =
        |answer: Option<[String; 3]>| answer.map(|[_, _, key]| key).filter(|key| !key.is_empty());
    let key_of = |label: &str| named(world.last_answer(label));
    let enrolled_under = key_of("{alice} POST /v1/enroll");
    let delivered_under = key_of("{alice} PUT /v1/{alice}/identity");
    let erased_key = named(first_key);
    if doc.generation() != before.generation() + 1
        || doc.body().recovery_from != Some(before.generation())
        || doc.version() <= before.version()
        || delivered_under.as_deref() != Some("service key number 1")
        || enrolled_under.is_none()
        || enrolled_under != erased_key
    {
        return Err(format!(
            "the new account starts at generation {} from {:?}, its enrollment answered \
             under {enrolled_under:?} and its document under {delivered_under:?}; the erased \
             account signed with {erased_key:?}",
            doc.generation(),
            doc.body().recovery_from
        )
        .into());
    }
    world.advance_ms(STEP_MS);

    // The wallet follows the recovery there; its upload, with no contact to bring, ends
    // the staged admission.
    follow_recovery(world, &mut wallet, "wallet", 1).await?;
    expect_upload(world, "wallet", false)?;
    signer.run_due().await?;
    world.outcome("the signer ran what is due", &status(&signer)?);
    expect_staged(world, false)?;
    world.advance_ms(STEP_MS);
    let next = signer.set_record_max_age(Some(60)).await?;
    world.outcome(
        "the signer signed on",
        &json!({ "version_steps": next.version() - doc.version(), "signer": status(&signer)? }),
    );
    Ok(())
}
