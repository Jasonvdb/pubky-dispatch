//! The recovery notice (Switch wire 7.3, Tables 1 to 3; 7.6; Switch spec 6.5): an account
//! whose state and mark disagree, or whose account is lost with its mark kept, answers
//! every call with a signed `503 recovery_required`, without a head, until the signer
//! starts a generation above both the held document's and the mark's with `recovery_from`.
//!
//! Each flow puts both switches in the same state with the world's controls, as an
//! operator's restore or loss leaves it, then has the signer, the app and a reader of the
//! public `identity.json` call, holds every answer to the notice Table 1 gives, and
//! recovers in place.

use pubky_switch_client::app::{App, AppError, ProviderStatus, Refusal};
use pubky_switch_core::http::header;
use pubky_switch_signer::{Signer, UserConfirmed};
use serde_json::json;

use super::enrollment::{enroll, status};
use super::join::app_status;
use super::messaging::joined;
use super::recovery::{ended, follow_recovery, recovered};
use super::{ORIGIN, STEP_MS};
use crate::{FlowResult, World};

/// The notice a flow expects: Switch wire 7.6's `current`.
#[derive(Clone, Copy, Debug)]
struct Notice {
    generation: u64,
    reason: &'static str,
    permanent: bool,
}

/// What each request alice's account answered from line `from` of the trace on, but an
/// enrollment, must be: `notice`, signed, with no `Switch-Head` (Switch wire 7.3, Table 2
/// and the paragraph below it). At least `calls` such requests must have been sent.
fn expect_notices(world: &World, from: usize, notice: Notice, calls: usize) -> FlowResult {
    let trace = world.trace();
    let mut answered = 0;
    for line in trace.lines.iter().skip(from) {
        if !line.label.contains("/v1/{alice}") || !line.facts.contains_key("status") {
            continue;
        }
        let fact = |name: &str| line.facts.get(name).map(String::as_str);
        let expected = [
            ("status", "503".to_owned()),
            ("body.code", "text recovery_required".to_owned()),
            (
                "body.current.generation",
                format!("number {}", notice.generation),
            ),
            ("body.current.reason", format!("text {}", notice.reason)),
            (
                "body.current.permanent",
                format!("bool {}", notice.permanent),
            ),
            (&format!("header {}", header::HEAD), "absent".to_owned()),
        ];
        for (name, value) in &expected {
            if fact(name) != Some(value.as_str()) {
                return Err(format!(
                    "{} was answered {name} {:?}, not {value}",
                    line.label,
                    fact(name)
                )
                .into());
            }
        }
        answered += 1;
    }
    if answered < calls {
        return Err(format!("{answered} calls met the notice, not {calls}").into());
    }
    Ok(())
}

/// The public read of alice's `identity.json` at the switch (Switch wire 7.4.15), as any
/// reader sends it, and its status.
async fn public_read(world: &World, step: &str) -> Result<u16, Box<dyn std::error::Error>> {
    let alice = world.identity("alice")?;
    let path = format!("/v1/{}/identity", alice.key().id());
    let answer = world.request("GET", ORIGIN, &path).await?;
    world.outcome(
        &format!("the public read, {step}"),
        &json!({ "status": answer.status }),
    );
    Ok(answer.status)
}

/// The wallet reads its feed and holds an attempted contact addition locally. The
/// signer reads the apps, and a reader reads `identity.json`. Each call's end goes into the
/// trace: the notice is a signed `503`, which no party can mistake for the switch's
/// answer to its call.
async fn every_caller_asks(
    world: &World,
    signer: &mut Signer,
    wallet: &mut App,
    step: &str,
) -> FlowResult {
    let bob = world.identity("bob")?;
    if wallet.recovery_required().is_some() {
        let followed = wallet.follow_provider().await?;
        if !matches!(followed, ProviderStatus::RecoveryRequired { .. }) {
            return Err("the explicit provider check lost the held notice".into());
        }
    }
    let read = wallet.receive(None).await;
    let calls = world.requests_sent();
    let added = wallet.add_contact(&bob.public()).await;
    if world.requests_sent() != calls {
        return Err("a held wallet sent an own write".into());
    }
    world.outcome(
        &format!("the wallet's calls, {step}"),
        &json!({
            "read": ended(&read),
            "added": ended(&added),
            "app": app_status(wallet),
        }),
    );
    let attempts = signer.open_attempts(wallet.app_id()).await;
    world.outcome(
        &format!("the signer's read of the apps, {step}"),
        &json!({ "ended": ended(&attempts), "signer": status(signer)? }),
    );
    public_read(world, step).await?;
    world.advance_ms(STEP_MS);
    if !read.as_ref().is_ok_and(|report| report.stopped)
        || !matches!(
            added,
            Err(AppError::Refused(Refusal::RecoveryRequired { .. }))
        )
        || attempts.is_ok()
    {
        return Err(format!("a call went through {step}").into());
    }
    Ok(())
}

/// The signer recovers in place (Switch spec 12.6 at the same service; Switch wire 7.3,
/// Table 2): its enrollment is answered as 3.7, and its start of the next generation,
/// with `recovery_from` the one that ends, is above both the held document's generation
/// and the mark's, so the account starts afresh and serves. The wallet follows it and the
/// public read is served again.
async fn recover_in_place(world: &World, signer: &mut Signer, wallet: &mut App) -> FlowResult {
    let doc = signer
        .declare_provider_loss(ORIGIN, UserConfirmed::shown_and_confirmed())
        .await?;
    world.outcome("the signer recovered in place", &recovered(&doc, signer)?);
    world.advance_ms(STEP_MS);
    served_again(world, signer, wallet).await
}

/// After the start, the account serves: the wallet follows the recovery, reading the new
/// chain from its `recovery` record, the signer reads the apps, and the public read is
/// `200`.
async fn served_again(world: &World, signer: &mut Signer, wallet: &mut App) -> FlowResult {
    follow_recovery(world, wallet, "wallet", 1).await?;
    let attempts = signer.open_attempts(wallet.app_id()).await;
    world.outcome(
        "the signer's read of the apps, recovered",
        &json!({ "ended": ended(&attempts), "signer": status(signer)? }),
    );
    if attempts.is_err() {
        return Err(format!("the signer's read ended {}", ended(&attempts)).into());
    }
    let read = public_read(world, "recovered").await?;
    if read != 200 {
        return Err(format!("the public read was answered {read} once recovered").into());
    }
    Ok(())
}

/// alice's signer enrolled at [`ORIGIN`], and her wallet joined there.
async fn serving(world: &World) -> Result<(Signer, App), Box<dyn std::error::Error>> {
    let alice = world.identity("alice")?;
    world.add_switch(ORIGIN, &[&alice]).await?;
    let mut signer = enroll(world, &alice, ORIGIN).await?;
    let (wallet, _) = joined(world, &alice, &mut signer, "wallet").await?;
    Ok((signer, wallet))
}

/// A restore leaves alice's account a write behind its mark (Switch wire 7.3, Table 1:
/// serving, state behind the mark, failing `behind`). Every call, the public read too,
/// gets the notice at the account's generation, not permanent, with no head; the signer's
/// recovery in place clears it.
///
/// Calls: every call of the wallet, the signer and a reader answered with the notice, and
/// `PUT /v1/{id}/identity` with the start a failing account takes.
///
/// # Errors
///
/// When a step that should succeed against any switch fails.
pub async fn notice_behind(world: &World) -> FlowResult {
    let alice = world.identity("alice")?;
    let (mut signer, mut wallet) = serving(world).await?;
    world.restore_behind_mark(ORIGIN, &alice).await?;
    let from = world.trace().lines.len();
    every_caller_asks(world, &mut signer, &mut wallet, "behind its mark").await?;
    // A delivery other than the start gets the notice too (Switch wire 7.3, Table 2).
    let delivered = signer.set_record_max_age(Some(60)).await;
    world.outcome(
        "the signer's next version, behind its mark",
        &json!({ "ended": ended(&delivered), "signer": status(&signer)? }),
    );
    world.advance_ms(STEP_MS);
    if delivered.is_ok() {
        return Err("the signer's next version went through behind the mark".into());
    }
    let notice = Notice {
        generation: 1,
        reason: "behind",
        permanent: false,
    };
    expect_notices(world, from, notice, 4)?;
    recover_in_place(world, &mut signer, &mut wallet).await
}

/// alice's mark is lost from a mark store that reads (Switch wire 7.3, Table 1: serving,
/// no mark, failing `mark_lost`). The notice names the account's generation (7.6); the
/// recovery in place, which writes the mark anew (Table 3), clears it.
///
/// Calls: as [`notice_behind`], at a lost mark.
///
/// # Errors
///
/// When a step that should succeed against any switch fails.
pub async fn notice_mark_lost(world: &World) -> FlowResult {
    let alice = world.identity("alice")?;
    let (mut signer, mut wallet) = serving(world).await?;
    world.lose_mark(ORIGIN, &alice).await?;
    let from = world.trace().lines.len();
    every_caller_asks(world, &mut signer, &mut wallet, "the mark lost").await?;
    let notice = Notice {
        generation: 1,
        reason: "mark_lost",
        permanent: false,
    };
    expect_notices(world, from, notice, 3)?;
    recover_in_place(world, &mut signer, &mut wallet).await
}

/// alice's mark records another chain hash at her state's pair (Switch wire 7.3, Table 1:
/// serving, failing `fork`); the recovery in place clears it.
///
/// Calls: as [`notice_behind`], at a fork.
///
/// # Errors
///
/// When a step that should succeed against any switch fails.
pub async fn notice_fork(world: &World) -> FlowResult {
    let alice = world.identity("alice")?;
    let (mut signer, mut wallet) = serving(world).await?;
    world.fork_mark(ORIGIN, &alice).await?;
    let from = world.trace().lines.len();
    every_caller_asks(world, &mut signer, &mut wallet, "a fork").await?;
    let notice = Notice {
        generation: 1,
        reason: "fork",
        permanent: false,
    };
    expect_notices(world, from, notice, 3)?;
    recover_in_place(world, &mut signer, &mut wallet).await
}

/// alice's account is lost, its mark kept (Switch wire 7.3, Table 1, row "None": lost).
/// Every call gets the notice, `behind` at the mark's generation. The signer's enrollment
/// creates a staged account that takes the mark over (Table 3), which is bounded: the
/// calls still get the notice. The start above both generations, its first try failed
/// on the way, then sent again, makes the account serve.
///
/// Calls: every call of the wallet, the signer and a reader answered with the notice at a
/// lost account and at a bounded one, `POST /v1/enroll` at a lost account, and `PUT
/// /v1/{id}/identity` with the start a bounded account takes.
///
/// # Errors
///
/// When a step that should succeed against any switch fails.
pub async fn notice_account_lost(world: &World) -> FlowResult {
    let alice = world.identity("alice")?;
    let (mut signer, mut wallet) = serving(world).await?;
    world.lose_account(ORIGIN, &alice).await?;
    let notice = Notice {
        generation: 1,
        reason: "behind",
        permanent: false,
    };
    let from = world.trace().lines.len();
    every_caller_asks(world, &mut signer, &mut wallet, "the account lost").await?;
    expect_notices(world, from, notice, 3)?;

    // The enrollment goes through; the start that follows never arrives.
    world.unreachable("PUT", "/identity");
    let declared = signer
        .declare_provider_loss(ORIGIN, UserConfirmed::shown_and_confirmed())
        .await;
    world.outcome(
        "the signer declared the loss in place, its start lost on the way",
        &json!({ "ended": ended(&declared), "signer": status(&signer)? }),
    );
    world.advance_ms(STEP_MS);
    let enrolled = world.last_fact("{alice} POST /v1/enroll", "status");
    if declared.is_ok() || enrolled.as_deref() != Some("200") {
        return Err(format!(
            "the declaration ended {}, its enrollment answered {enrolled:?}",
            ended(&declared)
        )
        .into());
    }
    let from = world.trace().lines.len();
    every_caller_asks(world, &mut signer, &mut wallet, "the mark taken over").await?;
    expect_notices(world, from, notice, 3)?;

    signer.resume().await?;
    world.outcome("the signer sent its start again", &status(&signer)?);
    world.advance_ms(STEP_MS);
    served_again(world, &mut signer, &mut wallet).await
}

/// The operator retires the generation of alice's account, a write behind its mark
/// (Switch spec 6.5; Switch wire 7.3, Table 1: failing, permanent): the notice says
/// `permanent: true` from then on. The signer's start of the next generation still clears
/// it: a retirement counts only while the state isn't of a later generation than the mark.
///
/// Calls: as [`notice_behind`], before and after the retirement.
///
/// # Errors
///
/// When a step that should succeed against any switch fails.
pub async fn notice_retired(world: &World) -> FlowResult {
    let alice = world.identity("alice")?;
    let (mut signer, mut wallet) = serving(world).await?;
    world.restore_behind_mark(ORIGIN, &alice).await?;
    let mut notice = Notice {
        generation: 1,
        reason: "behind",
        permanent: false,
    };
    let from = world.trace().lines.len();
    every_caller_asks(world, &mut signer, &mut wallet, "behind its mark").await?;
    expect_notices(world, from, notice, 3)?;

    world.retire(ORIGIN, &alice, 1).await?;
    notice.permanent = true;
    let from = world.trace().lines.len();
    every_caller_asks(world, &mut signer, &mut wallet, "retired").await?;
    expect_notices(world, from, notice, 3)?;
    recover_in_place(world, &mut signer, &mut wallet).await
}

#[cfg(test)]
mod two_wallets;

#[cfg(test)]
mod tests {
    use pubky_switch_client::ClientError;
    use pubky_switch_client::app::{AppEvent, ProviderHealth, ProviderStatus};
    use pubky_switch_core::http::{ErrorCode, NoticeReason};

    use super::super::recovery::{ended, shown_without_messages};
    use super::ORIGIN;
    use crate::{Backend, FlowResult, World};

    #[tokio::test]
    async fn test_wallet_clears_a_temporary_notice_in_the_same_generation() -> FlowResult {
        for backend in [Backend::Scripted, Backend::Service] {
            let trace = Box::pin(crate::run_here(backend, reattach_account)).await?;
            if backend == Backend::Scripted {
                assert!(trace.is_some());
            }
        }
        Ok(())
    }

    async fn reattach_account(world: &World) -> FlowResult {
        let alice = world.identity("alice")?;
        let (_signer, mut wallet) = Box::pin(super::serving(world)).await?;
        Box::pin(wallet.receive(None)).await?;
        let document = wallet.own_identity().hash();
        let generation = wallet.own_identity().generation();
        Box::pin(world.set_account_missing(ORIGIN, &alice, true)).await?;
        assert!(Box::pin(wallet.receive(None)).await?.stopped);
        let notice = wallet
            .recovery_required()
            .ok_or("missing temporary recovery notice")?;
        assert_eq!(notice.generation, generation);
        assert_eq!(notice.reason, Some(NoticeReason::Behind));
        assert!(!notice.permanent);
        Box::pin(world.set_account_missing(ORIGIN, &alice, false)).await?;
        assert_eq!(
            Box::pin(wallet.follow_provider()).await?,
            ProviderStatus::Current
        );
        assert_eq!(wallet.provider_health(), ProviderHealth::Ok);
        assert_eq!(wallet.recovery_required(), None);
        assert_eq!(wallet.own_identity().hash(), document);
        let duties = wallet.pending_duty_events().await?;
        assert!(duties.iter().any(|duty| {
            matches!(duty.event, AppEvent::RecoveryNoticeCleared { generation: cleared, .. } if cleared == generation)
        }));
        Ok(())
    }

    #[test]
    fn test_shown_without_messages_leaves_the_switch_message_out() {
        let refused = |message: &str| ClientError::Switch {
            status: 503,
            code: ErrorCode::RecoveryRequired,
            message: message.to_owned(),
            current: serde_json::json!({ "reason": "behind" }),
            known_version: None,
            retry_after: None,
        };
        let shown = shown_without_messages(&refused("Switch wire 7.3: \"quoted\" Words"));
        assert!(
            !shown.contains("message") && !shown.contains("Words"),
            "{shown}"
        );
        assert!(
            shown.contains("RecoveryRequired") && shown.contains("behind"),
            "{shown}"
        );
        let one: Result<(), _> = Err(refused("Switch wire 7.3"));
        let other: Result<(), _> = Err(refused("the account awaits a recovery"));
        assert_eq!(ended(&one), ended(&other));
    }
}
