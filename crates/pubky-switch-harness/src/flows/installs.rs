//! A signer's copies and its installs (Switch spec 4.3, 12.8, Switch wire 3.3 "Deliver,
//! then publish", 3.13): the published copy put right, another document at the published
//! version, an install put back to an older state, and a new install restored from the
//! signer backup.
//!
//! In most of these the switch does nothing out of the ordinary: it answers the signer's
//! reads of the apps and takes its deliveries, and what the flow is about is what the
//! signer does with them, run at both switches. That holds for the published copy put
//! right, another document at the version, records behind, a version never delivered, and
//! all of a new install taking over but the version naming another signer. Clearing the
//! alarm for another document delivers the signer's version again as a retry, which the
//! switch answers as the delivery it already took. Only [`signer_two_installs_race`] has
//! the switch refuse a delivery.

#[cfg(test)]
mod cancel_key_recovery;

use std::sync::Arc;

use pubky_switch_client::store::MemoryStore;
use pubky_switch_client::testing::TestIdentity;
use pubky_switch_client::{Credentials, SwitchClient};
use pubky_switch_core::keys::IdentityKey;
use pubky_switch_core::records::{
    AppRecord, AppRecordBody, IDENTITY_PATH, IdentityDoc, SIGNER_BACKUP_PATH, SignerBackup,
    app_record_path,
};
use pubky_switch_signer::{
    Alert, AppFate, CertChange, KeyRecoveryConfirmed, Refusal, Signer, SignerError, SignerStatus,
    UserConfirmed,
};
use serde_json::{Value, json};

use super::enrollment::{enroll, status};
use super::handover::expect_delivery_refused;
use super::messaging::joined;
use super::{ORIGIN, STEP_MS};
use crate::store::KeptCommits;
use crate::{FlowResult, World};

/// A day in milliseconds.
const DAY_MS: u64 = 24 * 3_600_000;

/// The version of `identity.json` on alice's Homeserver, when one reads there.
fn published(world: &World, alice: &TestIdentity) -> Option<u64> {
    world
        .files()
        .identity_doc(&alice.public())
        .map(|doc| doc.version())
}

/// How many versions the switch has taken from alice's signer so far.
fn deliveries(world: &World) -> usize {
    let trace = world.trace();
    trace
        .lines
        .iter()
        .filter(|line| line.label == "{alice} PUT /v1/{alice}/identity")
        .filter(|line| line.facts.get("status").map(String::as_str) == Some("200"))
        .count()
}

/// How a signer's call ended, for the trace: the error's kinds, never its text.
fn ended<T, E: std::fmt::Debug>(result: &Result<T, E>) -> Value {
    match result {
        Ok(_) => json!({ "ok": true }),
        Err(error) => {
            let shown = super::recovery::shown_without_messages(error);
            let kinds: Vec<&str> = shown
                .split(|c: char| !c.is_ascii_alphanumeric())
                .filter(|word| word.chars().next().is_some_and(|c| c.is_ascii_uppercase()))
                .take(3)
                .collect();
            json!({ "ok": false, "error": kinds.join(" ") })
        }
    }
}

/// The published copy put right (Switch wire 3.3 "Deliver, then publish"). The signer's
/// second version is at the switch and published. Then the Homeserver's copy goes back to
/// the first version, goes missing, and stops reading as a document: each time the
/// signer's next run reads the switch's copy, finds its own newest version there, and
/// publishes it again. It signs nothing for that.
///
/// Calls: the signer's routine `GET /v1/{id}/apps`, whose copy of `identity.json` it
/// publishes from.
///
/// # Errors
///
/// When a step that should succeed against any switch fails, a run leaves the Homeserver
/// without the newest version, or it delivers a version to the switch.
pub async fn publication_repaired(world: &World) -> FlowResult {
    let alice = world.identity("alice")?;
    world.add_switch(ORIGIN, &[&alice]).await?;
    let mut signer = enroll(world, &alice, ORIGIN).await?;
    let first = signer
        .identity_doc()?
        .ok_or("the signer holds no document")?;
    let second = signer.set_record_max_age(Some(86_400)).await?;
    world.outcome(
        "the signer delivered and published a second version",
        &status(&signer)?,
    );
    world.advance_ms(STEP_MS);

    let delivered = deliveries(world);
    for copy in ["an older version", "nothing", "no document"] {
        match copy {
            "an older version" => world.files().publish(&first)?,
            "nothing" => world.files().remove(alice.public(), IDENTITY_PATH),
            _ => world
                .files()
                .put(alice.public(), IDENTITY_PATH, b"not a document".to_vec()),
        }
        signer.run_due().await?;
        world.outcome(
            &format!("the signer's run, the Homeserver holding {copy}"),
            &json!({ "published": published(world, &alice), "signer": status(&signer)? }),
        );
        if published(world, &alice) != Some(second.version()) || deliveries(world) != delivered {
            return Err(format!(
                "with {copy} on the Homeserver, the run left version {:?} there and \\
                 delivered {} versions",
                published(world, &alice),
                deliveries(world) - delivered
            )
            .into());
        }
        world.advance_ms(STEP_MS);
    }
    Ok(())
}

/// Another document at the published version (Switch spec 4.3). The signer's second
/// version reaches the switch, and the Homeserver fails its publication. Then the
/// Homeserver shows another document at that version, signed with the identity key, as a
/// copy of the key in other hands could write. The signer raises the alarm: it publishes
/// nothing over it and signs nothing on top. Once the user clears the alert, the signer
/// delivers its version again, a retry the switch answers as the delivery it took, reads
/// the switch's copy, its own, publishes it over the other, and signs on.
///
/// Calls: `PUT /v1/{id}/identity` with the version the switch holds, sent again, `GET
/// /v1/{id}/apps` as the copy an alarm is cleared against, and the next version's delivery
/// after it. The switch's part is those ordinary answers: the alarm and its clearing are
/// the signer's.
///
/// # Errors
///
/// When a step that should succeed against any switch fails, the signer signs while the
/// alarm is held, or its own version isn't published once the alert is cleared.
pub async fn publication_other_document(world: &World) -> FlowResult {
    let alice = world.identity("alice")?;
    world.add_switch(ORIGIN, &[&alice]).await?;
    let mut signer = enroll(world, &alice, ORIGIN).await?;

    world.fail_homeserver_write(&alice, IDENTITY_PATH);
    let unpublished = signer.set_record_max_age(Some(86_400)).await;
    let second = signer
        .identity_doc()?
        .ok_or("the signer holds no document")?;
    world.outcome(
        "the signer delivered a second version, its publication failing",
        &json!({ "ended": ended(&unpublished), "signer": status(&signer)? }),
    );
    if unpublished.is_ok() || world.homeserver_faults_left() != 0 {
        return Err("the second version's publication didn't fail".into());
    }
    // Another body at the same version, under the identity's own signature.
    let mut body = second.body().clone();
    body.record_max_age = Some(7_200);
    let other = IdentityDoc::sign(alice.key(), body)?;
    world.files().publish(&other)?;
    world.advance_ms(STEP_MS);

    let alarmed = signer.resume().await;
    world.outcome(
        "the signer's run found another document at its version",
        &json!({ "ended": ended(&alarmed), "signer": status(&signer)? }),
    );
    let delivered = deliveries(world);
    let held = signer.set_record_max_age(Some(3_600)).await;
    world.outcome(
        "the signer was asked for a new version, the alarm held",
        &json!({ "ended": ended(&held), "signer": status(&signer)? }),
    );
    let theirs = world
        .files()
        .identity_doc(&alice.public())
        .map(|doc| doc.hash());
    if alarmed.is_ok()
        || held.is_ok()
        || deliveries(world) != delivered
        || theirs != Some(other.hash())
    {
        return Err("the signer signed or published while another document stood".into());
    }
    world.advance_ms(STEP_MS);

    let alert = signer
        .alerts()
        .iter()
        .find(|alert| matches!(alert, Alert::Equivocation { .. }))
        .cloned()
        .ok_or("the signer holds no alert for the other document")?;
    signer.clear_alert(&alert).await?;
    let ours = world
        .files()
        .identity_doc(&alice.public())
        .map(|doc| doc.hash());
    world.outcome(
        "the user cleared the alert",
        &json!({ "published_is_the_signers": ours == Some(second.hash()), "signer": status(&signer)? }),
    );
    if ours != Some(second.hash()) {
        return Err("the signer's own version isn't published over the other document".into());
    }
    world.advance_ms(STEP_MS);

    let third = signer.set_record_max_age(Some(3_600)).await?;
    world.outcome("the signer signed on", &status(&signer)?);
    if published(world, &alice) != Some(third.version()) {
        return Err("the third version isn't published".into());
    }
    Ok(())
}

/// A new install restored from the signer backup takes over (Switch spec 12.8, Switch wire
/// 3.13). alice's signer has approved her wallet. On another device a new install is
/// restored from the backup on her Homeserver: it delivers the next version, which names
/// it as the signer, and renews the wallet's certificate, which it holds from the backup.
/// The first install, asked for a new version, reads the switch's copy, finds another
/// install signing, and signs nothing.
///
/// Calls: `PUT /v1/{id}/identity` with a version that names another signer install, and
/// the first install's read of it.
///
/// # Errors
///
/// When a step that should succeed against any switch fails, the restored install doesn't
/// become the signer, or the first one still signs.
pub async fn signer_new_install(world: &World) -> FlowResult {
    let alice = world.identity("alice")?;
    world.add_switch(ORIGIN, &[&alice]).await?;
    let mut old = enroll(world, &alice, ORIGIN).await?;
    let (wallet, _) = joined(world, &alice, &mut old, "wallet").await?;
    let before = old.identity_doc()?.ok_or("the signer holds no document")?;

    let env = world.signer_env(&alice, Arc::new(MemoryStore::new()))?;
    let mut new = Signer::restore_new(
        env,
        world.keyring(&alice)?,
        UserConfirmed::shown_and_confirmed(),
    )
    .await?;
    let taken = new
        .identity_doc()?
        .ok_or("the new install holds no document")?;
    world.outcome(
        "a new install was restored from the backup",
        &json!({
            "version_steps": taken.version() - before.version(),
            "names_the_new_install": taken.body().signer == new.install_id(),
            "apps": taken.body().apps.len(),
            "signer": status(&new)?,
        }),
    );
    if taken.version() != before.version() + 1
        || taken.body().signer != new.install_id()
        || new.install_id() == old.install_id()
        || published(world, &alice) != Some(taken.version())
    {
        return Err("the restored install didn't take over with the next version".into());
    }
    world.advance_ms(DAY_MS);

    let change = CertChange {
        scopes: None,
        expires_at: Some(world.now_ms() + 400 * DAY_MS),
    };
    let renewing = new.renew(wallet.app_id(), change).await?;
    world.outcome(
        "the new install renewed the wallet's certificate",
        &json!({ "version": renewing.version(), "signer": status(&new)? }),
    );
    world.advance_ms(STEP_MS);

    let delivered = deliveries(world);
    let refused = old.set_record_max_age(Some(60)).await;
    world.outcome(
        "the first install was asked for a new version",
        &json!({ "ended": ended(&refused), "signer": status(&old)? }),
    );
    // Refused for that reason: the new install is the signer.
    let reason = old.status();
    if refused.is_ok()
        || deliveries(world) != delivered
        || reason
            != (SignerStatus::ManagedBy {
                install: new.install_id(),
            })
    {
        return Err(format!(
            "the first install still signs after the take-over, or stands as {reason:?}"
        )
        .into());
    }
    Ok(())
}

/// An install put back to an older state, and restored in place (Switch spec 12.8). alice's
/// signer delivers a second version. Then its device is put back to the state it had
/// before that version, as by a device backup restored: its records are behind its own
/// newest version, which the switch holds. Asked for a new version, it finds that out and
/// signs nothing. The user restores it in place from the signer backup on the Homeserver:
/// it takes the backup's records and delivers the next version as the same install, and
/// signs on.
///
/// Calls: the signer's read of a copy newer than its records, and `PUT /v1/{id}/identity`
/// with the version a restore in place delivers.
///
/// # Errors
///
/// When a step that should succeed against any switch fails, the install signs with its
/// records behind, or the restore doesn't bring it back to signing.
pub async fn signer_records_behind(world: &World) -> FlowResult {
    let alice = world.identity("alice")?;
    world.add_switch(ORIGIN, &[&alice]).await?;
    let store = Arc::new(KeptCommits::new());
    let env = world.signer_env(&alice, store.clone())?;
    let mut signer = Signer::create(env, world.keyring(&alice)?, ORIGIN).await?;
    signer.resume().await?;
    world.outcome("enrolled", &status(&signer)?);
    world.advance_ms(STEP_MS);
    let install = signer.install_id();
    let earlier = store.commits();

    let second = signer.set_record_max_age(Some(86_400)).await?;
    world.outcome("the signer delivered a second version", &status(&signer)?);
    world.advance_ms(STEP_MS);
    drop(signer);

    // The device as it was before the second version.
    let put_back = Arc::new(store.as_of(earlier)?);
    let env = world.signer_env(&alice, put_back)?;
    let mut signer = Signer::open(env, world.keyring(&alice)?).await?;
    let delivered = deliveries(world);
    let behind = signer.set_record_max_age(Some(60)).await;
    world.outcome(
        "the install, put back, was asked for a new version",
        &json!({ "ended": ended(&behind), "signer": status(&signer)? }),
    );
    // Refused for that reason: its records are behind its own second version.
    let reason = signer.status();
    if behind.is_ok()
        || deliveries(world) != delivered
        || reason
            != (SignerStatus::RecordsBehind {
                version: second.version(),
            })
    {
        return Err(format!("the install, put back, signed or stands as {reason:?}").into());
    }
    world.advance_ms(STEP_MS);

    let restored = signer.restore(UserConfirmed::shown_and_confirmed()).await?;
    world.outcome(
        "the install was restored in place from the backup",
        &json!({
            "version_steps": restored.version() - second.version(),
            "the_same_install": restored.body().signer == install,
            "signer": status(&signer)?,
        }),
    );
    if restored.version() != second.version() + 1
        || restored.body().signer != install
        || published(world, &alice) != Some(restored.version())
    {
        return Err("the restore in place didn't deliver the next version as this install".into());
    }
    world.advance_ms(STEP_MS);

    let next = signer.set_record_max_age(Some(60)).await?;
    world.outcome("the install signed on", &status(&signer)?);
    if published(world, &alice) != Some(next.version()) {
        return Err("the version after the restore isn't published".into());
    }
    Ok(())
}

/// A restore that finds a version the switch never took (Switch wire 3.13). alice's signer
/// signs a second version, writes its backup, and its delivery doesn't arrive. The install
/// is gone then. A new install restored from the backup delivers the backup's version
/// first, as signed, and then the next one, which names it as the signer.
///
/// Calls: `PUT /v1/{id}/identity` with a version signed by an install that is gone,
/// delivered by the one restored from its backup, and the version that follows.
///
/// # Errors
///
/// When a step that should succeed against any switch fails, a fault met no request, or
/// the restore doesn't deliver the two versions in order.
pub async fn signer_restore_undelivered(world: &World) -> FlowResult {
    let alice = world.identity("alice")?;
    world.add_switch(ORIGIN, &[&alice]).await?;
    let mut old = enroll(world, &alice, ORIGIN).await?;
    let (_wallet, _) = joined(world, &alice, &mut old, "wallet").await?;
    let before = old.identity_doc()?.ok_or("the signer holds no document")?;

    world.unreachable("PUT", "/identity");
    let undelivered = old.set_record_max_age(Some(86_400)).await;
    world.outcome(
        "the signer signed a version whose delivery didn't arrive",
        &json!({ "ended": ended(&undelivered), "signer": status(&old)? }),
    );
    if undelivered.is_ok() || world.faults_left() != 0 {
        return Err("the version's delivery wasn't cut off".into());
    }
    world.advance_ms(STEP_MS);
    drop(old);

    let delivered = deliveries(world);
    let env = world.signer_env(&alice, Arc::new(MemoryStore::new()))?;
    let new = Signer::restore_new(
        env,
        world.keyring(&alice)?,
        UserConfirmed::shown_and_confirmed(),
    )
    .await?;
    let taken = new
        .identity_doc()?
        .ok_or("the new install holds no document")?;
    world.outcome(
        "a new install was restored from the backup",
        &json!({
            "versions_delivered": deliveries(world) - delivered,
            "version_steps": taken.version() - before.version(),
            "names_the_new_install": taken.body().signer == new.install_id(),
            "signer": status(&new)?,
        }),
    );
    // The first of the two is the version the install that is gone signed, byte for byte:
    // its signature is the one the delivery that didn't arrive carried, and the second
    // carries another.
    let signatures: Vec<Option<String>> = {
        let trace = world.trace();
        let sent: Vec<_> = trace
            .lines
            .iter()
            .filter(|line| line.label == "{alice} PUT /v1/{alice}/identity")
            .collect();
        sent.iter()
            .rev()
            .take(3)
            .rev()
            .map(|line| line.facts.get("request body.identity.sig").cloned())
            .collect()
    };
    let as_signed = matches!(
        signatures.as_slice(),
        [Some(lost), Some(first), Some(second)] if lost == first && first != second
    );
    if !as_signed {
        return Err(format!(
            "the restore's deliveries carry the signatures {signatures:?}: the first isn't \
             the version as the lost install signed it"
        )
        .into());
    }
    if deliveries(world) - delivered != 2
        || taken.version() != before.version() + 2
        || taken.body().signer != new.install_id()
        || published(world, &alice) != Some(taken.version())
    {
        return Err(format!(
            "the restore delivered {} versions and ended {} past the last one taken",
            deliveries(world) - delivered,
            taken.version() - before.version()
        )
        .into());
    }
    Ok(())
}

/// A restore that finds a revocation only the switch holds (Switch spec 12.2, 12.8). alice's
/// signer revokes her phone: the switch takes the revocation, its answer is lost, and the
/// signer's next read doesn't arrive either. The install is gone then. A new install
/// restored from the backup takes over; its run reads the revocation at the switch and
/// removes the phone, distrusted from the time the switch revoked it.
///
/// Calls: `GET /v1/{id}/apps` showing a revocation the reading install didn't ask for,
/// and the removing version dated by it.
///
/// # Errors
///
/// When a step that should succeed against any switch fails, a fault met no request, or
/// the phone isn't removed from the time of its revocation.
pub async fn signer_restore_revocation(world: &World) -> FlowResult {
    let alice = world.identity("alice")?;
    world.add_switch(ORIGIN, &[&alice]).await?;
    let mut old = enroll(world, &alice, ORIGIN).await?;
    let (_wallet, _) = joined(world, &alice, &mut old, "wallet").await?;
    let (phone, _) = joined(world, &alice, &mut old, "phone").await?;
    world.advance_ms(DAY_MS);

    // The read before the revocation goes through; the revocation's answer is lost, and
    // the read after it doesn't arrive.
    world.lose_answer("POST", "/revoke");
    world.unreachable_after("GET", "/apps", 1);
    let revoked_at = world.now_ms();
    let revoking = old
        .revoke(phone.app_id(), None, UserConfirmed::shown_and_confirmed())
        .await;
    world.outcome(
        "the signer revoked the phone and heard nothing back",
        &json!({ "ended": ended(&revoking), "signer": status(&old)? }),
    );
    if revoking.is_ok() || world.faults_left() != 0 {
        return Err("the revocation's answer and the read after it weren't cut off".into());
    }
    world.advance_ms(DAY_MS);
    drop(old);

    let env = world.signer_env(&alice, Arc::new(MemoryStore::new()))?;
    let mut new = Signer::restore_new(
        env,
        world.keyring(&alice)?,
        UserConfirmed::shown_and_confirmed(),
    )
    .await?;
    world.outcome("a new install was restored from the backup", &status(&new)?);
    world.advance_ms(STEP_MS);
    new.run_due().await?;
    let newest = new
        .identity_doc()?
        .ok_or("the new install holds no document")?;
    let dated: Vec<u64> = newest
        .body()
        .removed
        .iter()
        .filter(|removed| removed.app_id == phone.app_id())
        .map(|removed| removed.distrust_from)
        .collect();
    world.outcome(
        "the new install's run removed the phone",
        &json!({
            "apps": newest.body().apps.len(),
            "removed": newest.body().removed.len(),
            "dated_at_the_revocation": dated == [revoked_at],
            "signer": status(&new)?,
        }),
    );
    if dated != [revoked_at] || newest.body().apps.len() != 1 {
        return Err(format!(
            "the phone's removal is dated {dated:?}, not {revoked_at}, with {} apps listed",
            newest.body().apps.len()
        )
        .into());
    }
    Ok(())
}

/// Two new installs restored at once (Switch wire 3.13, 7.4.2). alice's signer install is
/// gone. Two new installs are restored from its backup at the same moment, each on a
/// device of its own: each reads the same newest version and signs the next one, naming
/// itself. The first one's delivery is held back on its way; the second one's arrives and
/// is taken. The first then arrives: another body at the version the switch holds, and is
/// refused. The second install signs for the identity.
///
/// Calls: `PUT /v1/{id}/identity` with another body at the held version (`409 stale_identity`).
///
/// # Errors
///
/// When a step that should succeed against any switch fails, the delivery that arrives
/// second isn't refused, the install whose delivery arrived first isn't the signer, or
/// the other restore ends otherwise than as managed by that install.
pub async fn signer_two_installs_race(world: &World) -> FlowResult {
    let alice = world.identity("alice")?;
    world.add_switch(ORIGIN, &[&alice]).await?;
    let mut old = enroll(world, &alice, ORIGIN).await?;
    let (_wallet, _) = joined(world, &alice, &mut old, "wallet").await?;
    let before = old.identity_doc()?.ok_or("the signer holds no document")?;
    drop(old);

    let restore = |world: &World| -> Result<_, Box<dyn std::error::Error>> {
        let env = world.signer_env(&alice, Arc::new(MemoryStore::new()))?;
        Ok(Signer::restore_new(
            env,
            world.keyring(&alice)?,
            UserConfirmed::shown_and_confirmed(),
        ))
    };
    world.hold_back_next("PUT", "/identity");
    let held = restore(world)?;
    let through = restore(world)?;
    let second = async {
        // Once the first install's delivery is on its way and held.
        while world.held_back_now() == 0 {
            tokio::task::yield_now().await;
        }
        let restored = through.await;
        world.let_go();
        restored
    };
    let both = tokio::time::timeout(
        std::time::Duration::from_secs(15),
        futures_util::future::join(held, second),
    );
    let raced = both.await;
    world.let_go();
    let Ok((late, winner)) = raced else {
        return Err("the two restores didn't both end".into());
    };
    let winner = winner?;
    let taken = winner
        .identity_doc()?
        .ok_or("the winner holds no document")?;
    world.outcome(
        "one restore's delivery arrived first, the other's after it",
        &json!({
            "late": ended(&late.as_ref().map(|_| ())),
            "version_steps": taken.version() - before.version(),
            "names_the_winner": taken.body().signer == winner.install_id(),
            "winner": status(&winner)?,
        }),
    );
    expect_delivery_refused(world)?;
    if taken.version() != before.version() + 1
        || taken.body().signer != winner.install_id()
        || published(world, &alice) != Some(taken.version())
    {
        return Err("the install whose delivery arrived first isn't the signer".into());
    }
    // The restore that lost stands aside: the copy its refusal carries names the other
    // install, and it raises no alarm over it.
    let stands_aside = matches!(
        &late,
        Err(SignerError::NotNamed { install }) if *install == winner.install_id()
    );
    if !stands_aside {
        return Err(format!(
            "the restore whose delivery arrived second ended {}, not as managed by the other \
             install",
            ended(&late.as_ref().map(|_| ()))
        )
        .into());
    }
    Ok(())
}

/// The switch's view of alice's account a recovery with the key alone relies on: its copy of
/// `identity.json`, its creation, and each app's App ID, standing and removal times (Switch
/// wire 7.4.12, 7.4.18), read with a client of its own.
async fn account_view(
    world: &World,
    alice: &TestIdentity,
    service_key: [u8; 32],
) -> Result<Value, Box<dyn std::error::Error>> {
    let client = SwitchClient::new(
        ORIGIN,
        alice.public(),
        Credentials::Signer {
            identity: alice.public(),
            key: Arc::new(IdentityKey::from_secret(alice.key().secret_bytes())),
        },
        Some(service_key),
        world.transport(),
        world.clock().clone(),
    )?;
    let created = client
        .observe_account()
        .await?
        .body()
        .created
        .ok_or("the account has no creation")?;
    let answer = client.with_account_created(created)?.apps().await?;
    let copy = answer
        .identity
        .map(|signed| IdentityDoc::verify(&signed, &alice.public()))
        .transpose()?
        .map(|doc| doc.hash());
    let mut apps: Vec<Value> = answer
        .apps
        .iter()
        .map(|status| {
            json!([
                status.app_id,
                status.current,
                status.revoked_at,
                status.departed_at
            ])
        })
        .collect();
    apps.sort_by_key(Value::to_string);
    Ok(json!({ "created": created, "copy": copy, "apps": apps }))
}

/// A recovery with the identity key alone after a racing delivery won and its backup write
/// failed (Switch spec 12.8, Switch wire 3.13). alice's signer has approved her wallet. An
/// install restored on another device wins its delivery, its backup write fails, and that
/// device is lost: the backup on the Homeserver is the one it restored from, and a restore
/// from it is refused as stale. On a third device the user confirms a survey of a recovery
/// with the key alone: the install enrolls at the account with `existing`, and its delivery
/// doesn't arrive. The account is as before the enrollment: the same copy, creation and apps.
/// Run again, the install delivers the racer's content naming itself, built on the racer's
/// version, and signs on.
///
/// Calls: `GET /v1/{id}/account`, an `existing` `POST /v1/enroll` at a serving account, and
/// `PUT /v1/{id}/identity` built on another install's version, sent again.
///
/// # Errors
///
/// When a step that should succeed against any switch fails, the enrollment changes the
/// account, or the recovering install isn't the signer afterwards.
pub async fn signer_key_recovery_after_a_racer(world: &World) -> FlowResult {
    let alice = world.identity("alice")?;
    world.add_switch(ORIGIN, &[&alice]).await?;
    let mut old = enroll(world, &alice, ORIGIN).await?;
    let (_wallet, _) = joined(world, &alice, &mut old, "wallet").await?;
    let before = old.identity_doc()?.ok_or("the signer holds no document")?;
    drop(old);

    world.fail_homeserver_write(&alice, SIGNER_BACKUP_PATH);
    let env = world.signer_env(&alice, Arc::new(MemoryStore::new()))?;
    let racer = Signer::restore_new(
        env,
        world.keyring(&alice)?,
        UserConfirmed::shown_and_confirmed(),
    )
    .await?;
    world.outcome(
        "an install restored on another device won, its backup write failing",
        &json!({ "backup_not_written": racer.alerts().contains(&Alert::BackupNotWritten) }),
    );
    if world.homeserver_faults_left() != 0 || !racer.alerts().contains(&Alert::BackupNotWritten) {
        return Err("the racer's backup write didn't fail".into());
    }
    let racer_install = racer.install_id();
    drop(racer);
    world.advance_ms(STEP_MS);

    let env = world.signer_env(&alice, Arc::new(MemoryStore::new()))?;
    let stale = Signer::restore_new(
        env,
        world.keyring(&alice)?,
        UserConfirmed::shown_and_confirmed(),
    )
    .await;
    world.outcome(
        "a restore on a third device",
        &ended(&stale.as_ref().map(|_| ())),
    );
    if !matches!(stale, Err(SignerError::Refused(Refusal::StaleBackup))) {
        return Err("the restore from the stale backup wasn't refused as stale".into());
    }
    let store = Arc::new(MemoryStore::new());
    let survey = Signer::survey_key_recovery_new(
        world.signer_env(&alice, store.clone())?,
        world.keyring(&alice)?,
    )
    .await?;
    world.outcome(
        "the survey of a recovery with the key alone",
        &json!({
            "version_steps": survey.version - before.version(),
            "names_the_racer": survey.signer == racer_install,
            "apps_staying": survey.apps.iter().filter(|(_, fate)| *fate == AppFate::Stays).count(),
        }),
    );
    let service_key = before.inbox().service_key;
    let enrolled = account_view(world, &alice, service_key).await?;
    world.unreachable("PUT", "/identity");
    let cut = Signer::restore_new(
        world.signer_env(&alice, store.clone())?,
        world.keyring(&alice)?,
        KeyRecoveryConfirmed::shown_and_confirmed(&survey, &[]),
    )
    .await;
    let after = account_view(world, &alice, service_key).await?;
    world.outcome(
        "the recovery enrolled with existing, its delivery not arriving",
        &json!({ "ended": ended(&cut.as_ref().map(|_| ())), "account_unchanged": after == enrolled }),
    );
    if cut.is_ok() || world.faults_left() != 0 || after != enrolled {
        return Err(
            "the existing enrollment changed the account, or the delivery wasn't cut".into(),
        );
    }
    world.advance_ms(STEP_MS);

    let mut new = Signer::open(world.signer_env(&alice, store)?, world.keyring(&alice)?).await?;
    new.resume().await?;
    let taken = new
        .identity_doc()?
        .ok_or("the recovering install holds no document")?;
    world.outcome(
        "the recovery, run again, delivered its version",
        &json!({
            "version_steps": taken.version() - before.version(),
            "names_the_new_install": taken.body().signer == new.install_id(),
            "same_generation": taken.generation() == before.generation(),
            "signer": status(&new)?,
        }),
    );
    if taken.version() != before.version() + 2
        || taken.body().signer != new.install_id()
        || taken.body().apps != before.body().apps
        || published(world, &alice) != Some(taken.version())
    {
        return Err("the recovering install didn't deliver the racer's content as its own".into());
    }
    world.advance_ms(STEP_MS);
    let next = new.set_record_max_age(Some(60)).await?;
    world.outcome("the recovering install signed on", &status(&new)?);
    if published(world, &alice) != Some(next.version()) {
        return Err("the version after the recovery isn't published".into());
    }
    Ok(())
}

/// A recovery with the identity key alone with the backup gone (Switch spec 12.8, Switch
/// wire 3.13). alice's signer has approved her wallet and her phone; the wallet's record is on
/// her Homeserver and the phone's isn't, the signer backup is gone, and the device is lost. On a
/// new device the user confirms the survey: the wallet stays, its certificate found in its
/// record, and the phone, whose certificate isn't found, is revoked. The install delivers the
/// copy's content naming itself, then the version that removes the phone, and signs on.
///
/// Calls: `POST /v1/{id}/apps/{app_id}/revoke` for an app whose certificate wasn't found, and
/// the removing version.
///
/// # Errors
///
/// When a step that should succeed against any switch fails, or the phone isn't removed.
pub async fn signer_key_recovery_backup_gone(world: &World) -> FlowResult {
    let alice = world.identity("alice")?;
    world.add_switch(ORIGIN, &[&alice]).await?;
    let mut old = enroll(world, &alice, ORIGIN).await?;
    let (wallet, _) = joined(world, &alice, &mut old, "wallet").await?;
    let (phone, _) = joined(world, &alice, &mut old, "phone").await?;
    let before = old.identity_doc()?.ok_or("the signer holds no document")?;
    drop(old);
    // The wallet publishes its record, carrying its certificate, on alice's Homeserver
    // (Switch spec 4.2); the phone's isn't there.
    let backup: SignerBackup = serde_json::from_slice(
        &world
            .files()
            .file(alice.public(), SIGNER_BACKUP_PATH)
            .ok_or("no signer backup")?,
    )?;
    let cert = backup
        .open(alice.key())?
        .certs()
        .iter()
        .find(|cert| cert.app_id() == wallet.app_id())
        .ok_or("the backup holds no certificate of the wallet")?
        .clone();
    let record = AppRecord::sign(
        &world.app_keys(&alice, "wallet")?,
        AppRecordBody::new(&cert, Vec::new(), world.now_ms()),
    )?;
    world.files().put(
        alice.public(),
        &app_record_path(&wallet.app_id()),
        serde_json::to_vec(record.signed())?,
    );
    world
        .files()
        .remove(alice.public(), &app_record_path(&phone.app_id()));
    world.files().remove(alice.public(), SIGNER_BACKUP_PATH);
    world.advance_ms(STEP_MS);

    let env = world.signer_env(&alice, Arc::new(MemoryStore::new()))?;
    let refused = Signer::restore_new(
        env,
        world.keyring(&alice)?,
        UserConfirmed::shown_and_confirmed(),
    )
    .await;
    if !matches!(refused, Err(SignerError::Refused(Refusal::NoBackup))) {
        return Err("the restore with no backup wasn't refused".into());
    }
    let store = Arc::new(MemoryStore::new());
    let survey = Signer::survey_key_recovery_new(
        world.signer_env(&alice, store.clone())?,
        world.keyring(&alice)?,
    )
    .await?;
    let fate = |app: [u8; 16]| {
        survey
            .apps
            .iter()
            .find(|(id, _)| *id == app)
            .map(|(_, f)| *f)
    };
    world.outcome(
        "the survey of a recovery with the key alone",
        &json!({
            "wallet_stays": fate(wallet.app_id()) == Some(AppFate::Stays),
            "phone_not_found": fate(phone.app_id()) == Some(AppFate::CertificateNotFound),
        }),
    );
    if fate(wallet.app_id()) != Some(AppFate::Stays)
        || fate(phone.app_id()) != Some(AppFate::CertificateNotFound)
    {
        return Err("the survey shows other fates for the two apps".into());
    }
    let mut new = Signer::restore_new(
        world.signer_env(&alice, store)?,
        world.keyring(&alice)?,
        KeyRecoveryConfirmed::shown_and_confirmed(&survey, &[]),
    )
    .await?;
    let newest = new
        .identity_doc()?
        .ok_or("the recovering install holds no document")?;
    world.outcome(
        "the recovery delivered its version, then removed the phone",
        &json!({
            "version_steps": newest.version() - before.version(),
            "wallet_listed": newest.listed_cert(&wallet.app_id()).is_some(),
            "phone_removed": newest.body().removed.iter().any(|r| r.app_id == phone.app_id()),
            "signer": status(&new)?,
        }),
    );
    if newest.version() != before.version() + 2
        || newest.body().signer != new.install_id()
        || newest.listed_cert(&wallet.app_id()).is_none()
        || newest.listed_cert(&phone.app_id()).is_some()
        || published(world, &alice) != Some(newest.version())
    {
        return Err("the recovery didn't end with the wallet listed and the phone removed".into());
    }
    world.advance_ms(STEP_MS);
    let next = new.set_record_max_age(Some(60)).await?;
    world.outcome("the recovering install signed on", &status(&new)?);
    if published(world, &alice) != Some(next.version()) {
        return Err("the version after the recovery isn't published".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Backend;
    use pubky_switch_client::StoreError;
    use pubky_switch_client::store::{Fault, FaultStore, StateStore, WriteBatch};
    use pubky_switch_signer::state::signer_namespace;
    use pubky_switch_signer::{RecordsDiscarded, RecordsFault};

    #[tokio::test]
    async fn test_restore_damaged_account_binding_scripted() {
        let result = crate::run_here(Backend::Scripted, restore_damaged_binding).await;
        assert!(matches!(result, Ok(Some(_))), "{result:?}");
    }

    #[tokio::test]
    async fn test_restore_damaged_account_binding_service() {
        let result = crate::run_here(Backend::Service, restore_damaged_binding).await;
        assert!(matches!(result, Ok(Some(_))), "{result:?}");
    }

    async fn restore_damaged_binding(world: &World) -> FlowResult {
        let alice = world.identity("alice")?;
        world.add_switch(ORIGIN, &[&alice]).await?;
        let store = Arc::new(MemoryStore::new());
        let env = world.signer_env(&alice, store.clone())?;
        let mut signer =
            Box::pin(Signer::create(env.clone(), world.keyring(&alice)?, ORIGIN)).await?;
        Box::pin(signer.resume()).await?;
        let first = signer.identity_doc()?.ok_or("missing first version")?;
        drop(signer);

        // The signed document survives a damaged device snapshot, but its local account
        // binding is missing. Ordinary reopening must preserve the snapshot (Switch spec 12.8).
        let ns = signer_namespace(&alice.public());
        let old = store.get(&ns, b"state")?.ok_or("missing signer state")?;
        let mut state: Value = serde_json::from_slice(&old)?;
        let account = state
            .pointer_mut("/newest/account")
            .ok_or("missing original account")?;
        assert!(account.is_object());
        *account = Value::Null;
        let damaged = serde_json::to_vec(&state)?;
        let mut batch = WriteBatch::new();
        batch.put(&ns, b"state", damaged.clone())?;
        store.commit(batch)?;
        let opened = Signer::open(env.clone(), world.keyring(&alice)?).await;
        assert!(matches!(
            opened,
            Err(SignerError::Records(RecordsFault::Damaged(_)))
        ));
        assert_eq!(store.get(&ns, b"state")?, Some(damaged));

        // The user's confirmed replacement commits, but its result doesn't reach the host.
        let faulty = Arc::new(FaultStore::new(store.clone(), Fault::FailAfter(1)));
        let result = Box::pin(Signer::restore_over_unusable(
            world.signer_env(&alice, faulty)?,
            world.keyring(&alice)?,
            RecordsDiscarded::shown_and_confirmed(),
        ))
        .await;
        assert!(matches!(
            result,
            Err(SignerError::Store(StoreError::Unknown))
        ));
        let mut signer = Signer::open(env, world.keyring(&alice)?).await?;
        Box::pin(signer.resume()).await?;
        let doc = signer.identity_doc()?.ok_or("missing restored version")?;
        assert_eq!(signer.status(), SignerStatus::Signing);
        assert_eq!(
            (doc.version(), doc.generation()),
            (first.version() + 1, first.generation())
        );
        assert_eq!(doc.body().signer, signer.install_id());
        assert_eq!(
            world
                .files()
                .identity_doc(&alice.public())
                .map(|published| published.hash()),
            Some(doc.hash())
        );
        let next = Box::pin(signer.set_record_max_age(Some(60))).await?;
        assert_eq!(next.version(), doc.version() + 1);
        assert_eq!(published(world, &alice), Some(next.version()));
        drop(signer);

        // A later device snapshot retains a rollback alarm as well as the damaged binding.
        // The real service continues serving the signer's current document (Switch spec 4.3).
        let alarm = Alert::Rollback {
            source: pubky_switch_signer::Source::Switch,
            version: Some(doc.version()),
            generation: Some(doc.generation()),
            high_water_version: next.version(),
        };
        let original = store.get(&ns, b"state")?.ok_or("missing signer state")?;
        let mut held: Value = serde_json::from_slice(&original)?;
        held["alerts"]
            .as_array_mut()
            .ok_or("missing alerts")?
            .push(serde_json::to_value(&alarm)?);
        held["switch_unconfirmed"] = true.into();
        let mut damaged = held.clone();
        assert!(damaged["newest"]["account"].is_object());
        damaged["newest"]["account"] = Value::Null;
        let damaged = serde_json::to_vec(&damaged)?;
        let mut batch = WriteBatch::new();
        batch.put(&ns, b"state", damaged.clone())?;
        store.commit(batch)?;

        let env = world.signer_env(&alice, store.clone())?;
        let backup = world
            .files()
            .file(alice.public(), SIGNER_BACKUP_PATH)
            .ok_or("missing current backup")?;
        let before = deliveries(world);
        world.files().remove(alice.public(), SIGNER_BACKUP_PATH);
        let missing = Box::pin(Signer::restore_over_unusable(
            env.clone(),
            world.keyring(&alice)?,
            RecordsDiscarded::shown_and_confirmed(),
        ))
        .await;
        assert_eq!(store.get(&ns, b"state")?, Some(damaged));
        world
            .files()
            .put(alice.public(), SIGNER_BACKUP_PATH, backup);
        let start = world.trace().lines.len();
        let repaired = Box::pin(Signer::restore_over_unusable(
            env.clone(),
            world.keyring(&alice)?,
            RecordsDiscarded::shown_and_confirmed(),
        ))
        .await?;
        assert_eq!(missing.unwrap_err(), Refusal::NoBackup.into());
        assert_eq!(repaired.install_id(), next.body().signer);
        assert_eq!(repaired.status(), SignerStatus::Alarm);
        let stored = store.get(&ns, b"state")?.ok_or("missing repaired state")?;
        assert_eq!(serde_json::from_slice::<Value>(&stored)?, held);
        assert_eq!(deliveries(world), before);
        assert!(world.trace().lines[start..].iter().any(|line| {
            line.label == "{alice} GET /v1/{alice}/apps"
                && line.facts.get("status").map(String::as_str) == Some("200")
        }));
        drop(repaired);
        let mut signer = Box::pin(Signer::open(env, world.keyring(&alice)?)).await?;
        assert_eq!(
            Box::pin(signer.set_record_max_age(Some(61)))
                .await
                .unwrap_err(),
            SignerError::Alarm(alarm.clone())
        );
        Box::pin(signer.clear_alert(&alarm)).await?;
        let signed = Box::pin(signer.set_record_max_age(Some(61))).await?;
        assert_eq!(signed.version(), next.version() + 1);
        assert_eq!(signed.body().signer, next.body().signer);
        assert_eq!(published(world, &alice), Some(signed.version()));
        Ok(())
    }
}

#[cfg(test)]
mod pending_delivery;
