//! Each recipient reads the invitation redeemed by its delivery, without reading lists
//! (Switch spec 7, Switch wire 7.4.3 and 7.5).
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;

use pubky_switch_client::app::{
    App, AppConfig, AppError, AppEvent, Delivery, EntryReceipt, OutgoingMessage, Refusal,
    UndeliverableReason,
};
use pubky_switch_client::store::MemoryStore;
use pubky_switch_client::testing::{ProtocolSpec, TestIdentity, TestProtocol};
use pubky_switch_core::admission::{PeerEntry, ReplyOrigin};
use pubky_switch_core::scopes::Permission;
use pubky_switch_harness::parties::{Asking, NOTE_KIND, NOTES};
use pubky_switch_harness::{Backend, FlowResult, World, run_here};
use pubky_switch_signer::{Protocol, Protocols, ScopeDef, Signer, UserConfirmed};
use serde_json::json;

const ORIGIN: &str = "https://switch.example";
const MANAGE: &str = "notes_manage";
const PEERS: &str = "notes_peers";
const PRUNE: &str = "notes_prune";
const KEEP: &str = "notes_keep";
const HOUR_MS: u64 = 3_600_000;

struct Invitations;

impl Protocol for Invitations {
    fn name(&self) -> &str {
        NOTES
    }

    fn scopes(&self) -> Vec<ScopeDef> {
        vec![
            ScopeDef::keyed(NOTES),
            ScopeDef::unkeyed(MANAGE),
            ScopeDef::unkeyed(PRUNE),
            ScopeDef::unkeyed(PEERS),
            ScopeDef::unkeyed(KEEP),
        ]
    }

    fn check_scopes(&self, _: &[&str]) -> Result<(), String> {
        Ok(())
    }

    fn permissions(&self, scopes: &[&str]) -> Vec<Permission> {
        if scopes.contains(&KEEP) {
            vec![Permission::ListsRead, Permission::ListsManage]
        } else if scopes.contains(&PRUNE) {
            vec![
                Permission::ListsRead,
                Permission::ListsManage,
                Permission::ReplyAdd,
            ]
        } else if scopes.contains(&PEERS) {
            vec![Permission::ListsManage, Permission::ReplyAdd]
        } else if scopes.contains(&MANAGE) {
            vec![Permission::ListsRead, Permission::ReplyAdd]
        } else {
            Vec::new()
        }
    }
}

fn protocol() -> Arc<TestProtocol> {
    Arc::new(TestProtocol::keeping(ProtocolSpec {
        name: NOTES.into(),
        keyed_scopes: vec![NOTES.into()],
        accepts: vec![NOTE_KIND.into()],
        ..ProtocolSpec::default()
    }))
}

async fn enroll(world: &World, who: &TestIdentity) -> Signer {
    let mut env = world.signer_env(who, Arc::new(MemoryStore::new())).unwrap();
    env.protocols = Protocols::new(vec![Arc::new(Invitations)]).unwrap();
    let mut signer = Box::pin(Signer::create(env, world.keyring(who).unwrap(), ORIGIN))
        .await
        .unwrap();
    Box::pin(signer.resume()).await.unwrap();
    signer
}

async fn join(
    world: &World,
    who: &TestIdentity,
    signer: &mut Signer,
    name: &str,
    scopes: &[&str],
) -> (App, Arc<TestProtocol>) {
    let asking = Asking::for_scopes(world.app_keys(who, name).unwrap(), scopes).unwrap();
    let reviewed = signer
        .review(asking.request.signed(), &asking.auth)
        .unwrap();
    let approved = Box::pin(signer.approve(reviewed)).await.unwrap();
    signer.claim_delivered(&approved.request).await.unwrap();
    let protocol = protocol();
    let mut app = Box::pin(App::join(
        world.app_env(Arc::new(MemoryStore::new())),
        protocol.clone(),
        AppConfig::default(),
        asking.join_request(who.public(), &approved).unwrap(),
    ))
    .await
    .unwrap();
    Box::pin(app.receive(None)).await.unwrap();
    (app, protocol)
}

fn note(to: [u8; 32], text: &str, code: Option<&str>) -> OutgoingMessage {
    let mut note = OutgoingMessage::new(
        to,
        NOTE_KIND,
        json!({"text": text}).as_object().unwrap().clone(),
    );
    note.invite_code = code.map(str::to_owned);
    note
}

async fn receipts(app: &mut App, protocol: &TestProtocol) -> Vec<(String, EntryReceipt)> {
    let mut events = Vec::new();
    loop {
        let report = Box::pin(app.receive(None)).await.unwrap();
        events.extend(report.events.into_iter().filter_map(|event| match event {
            AppEvent::MessageReceived {
                msg_id, receipt, ..
            } => Some((msg_id, receipt)),
            _ => None,
        }));
        if !report.more {
            break;
        }
    }
    let observed: Vec<_> = protocol
        .received()
        .into_iter()
        .map(|message| (message.message.msg_id, message.receipt))
        .collect();
    assert_eq!(
        events, observed,
        "callback and success retain the same receipt"
    );
    for (id, receipt) in &events {
        assert_eq!(receipt.service_key, app.own_identity().inbox().service_key);
        assert_eq!(
            app.protocol_get(NOTES, id.as_bytes()).await.unwrap(),
            Some(NOTE_KIND.as_bytes().to_vec()),
            "the protocol effect committed with the observed delivery"
        );
    }
    events
}

async fn invitation_delivery(world: &World) -> FlowResult {
    let alice = world.identity("alice")?;
    let bob = world.identity("bob")?;
    world.add_switch(ORIGIN, &[&alice, &bob]).await?;
    let mut alice_signer = Box::pin(enroll(world, &alice)).await;
    let mut bob_signer = Box::pin(enroll(world, &bob)).await;
    let (mut creator, creator_protocol) = Box::pin(join(
        world,
        &alice,
        &mut alice_signer,
        "creator",
        &[NOTES, MANAGE],
    ))
    .await;
    let (mut sibling, sibling_protocol) =
        Box::pin(join(world, &alice, &mut alice_signer, "sibling", &[NOTES])).await;
    let (mut keeper, _) = Box::pin(join(
        world,
        &alice,
        &mut alice_signer,
        "keeper",
        &[NOTES, KEEP],
    ))
    .await;
    let (mut sender, _) = Box::pin(join(world, &bob, &mut bob_signer, "sender", &[NOTES])).await;
    assert_eq!(creator.identity(), sibling.identity());
    assert_ne!(creator.app_id(), sibling.app_id());
    assert_ne!(keeper.app_id(), creator.app_id());
    assert_ne!(keeper.app_id(), sibling.app_id());
    assert!(sibling.cert().permissions().is_empty());
    assert!(creator.cert().has_permission(Permission::ReplyAdd));
    assert!(!creator.cert().has_permission(Permission::ListsManage));
    assert!(keeper.cert().has_permission(Permission::ListsManage));
    assert!(!keeper.cert().has_permission(Permission::ReplyAdd));
    let before = world.trace().lines.len();
    assert!(matches!(
        creator.keep_peer(&bob.public()).await,
        Err(AppError::Refused(Refusal::Usage(_)))
    ));
    assert!(matches!(
        keeper
            .register_invite_code(world.now_ms() + HOUR_MS, 1)
            .await,
        Err(AppError::Refused(Refusal::Usage(_)))
    ));
    assert!(matches!(
        sibling.invite(&bob.public()).await,
        Err(AppError::Refused(Refusal::Usage(_)))
    ));
    assert_eq!(
        world.trace().lines.len(),
        before,
        "permission refusals send nothing"
    );
    Box::pin(creator.receive(None)).await?;
    let backup = creator.backup().await?;
    let first = creator
        .register_invite_code(world.now_ms() + HOUR_MS, 1)
        .await?;
    let second = creator
        .register_invite_code(world.now_ms() + HOUR_MS, 1)
        .await?;
    assert_ne!(first.code_hash, second.code_hash);
    drop(creator);

    let mut expected = Vec::new();
    for (text, invitation) in [
        ("first", Some(&first)),
        ("second", Some(&second)),
        ("ordinary", None),
    ] {
        let (id, delivery) = Box::pin(sender.send(note(
            alice.public(),
            text,
            invitation.map(|code| code.code.as_str()),
        )))
        .await?;
        assert!(
            matches!(delivery, Delivery::Accepted { .. }),
            "{delivery:?}"
        );
        expected.push((id, invitation.map(|code| code.code_hash)));
    }

    let mut restored = Box::pin(App::restore(
        world.app_env(Arc::new(MemoryStore::new())),
        creator_protocol.clone(),
        AppConfig::default(),
        &backup,
    ))
    .await?;
    assert!(restored.invite_codes().await?.is_empty());
    assert!(sibling.invite_codes().await?.is_empty());
    let mut observed = Vec::new();
    for (app, protocol) in [
        (&mut sibling, &sibling_protocol),
        (&mut restored, &creator_protocol),
    ] {
        let receipts = Box::pin(receipts(app, protocol)).await;
        let delivered: Vec<_> = receipts
            .iter()
            .map(|(id, receipt)| (id.clone(), receipt.invite_code_hash))
            .collect();
        assert_eq!(delivered, expected);
        observed.push(
            receipts
                .into_iter()
                .map(|(_, receipt)| receipt.entry_id)
                .collect::<Vec<_>>(),
        );
    }
    assert_eq!(
        observed[0], observed[1],
        "both apps read the same three entries"
    );
    let lists = restored.allow_list().await?;
    assert_eq!(lists.peers.len(), 1);
    assert_eq!(lists.peers[0].pubky, bob.public());
    assert!(!lists.peers[0].kept);
    assert_eq!(
        lists.peers[0].reply.expect("invitation reply grant").origin,
        ReplyOrigin::Invite(first.code_hash)
    );

    for invitation in [&first, &second] {
        let (_, delivery) =
            Box::pin(sender.send(note(alice.public(), "spent", Some(&invitation.code)))).await?;
        assert!(
            matches!(
                delivery,
                Delivery::Queued {
                    undeliverable_reason: Some(UndeliverableReason::NotAdmitted),
                    ..
                }
            ),
            "{delivery:?}"
        );
    }

    let original_reply = lists.peers[0].reply;
    keeper.keep_peer(&bob.public()).await?;
    let both = restored.allow_list().await?;
    assert!(both.peers[0].kept);
    assert_eq!(both.peers[0].reply, original_reply);
    keeper.remove_reply(&bob.public()).await?;
    let kept = restored.allow_list().await?;
    assert!(kept.peers[0].kept);
    assert_eq!(kept.peers[0].reply, None);
    let (_, delivery) = Box::pin(sender.send(note(alice.public(), "kept", None))).await?;
    assert!(matches!(delivery, Delivery::Accepted { .. }));
    assert_eq!(restored.allow_list().await?.peers[0].reply, None);

    restored.invite(&bob.public()).await?;
    let both = restored.allow_list().await?;
    assert!(both.peers[0].kept);
    assert_eq!(
        both.peers[0].reply.expect("app reply grant").origin,
        ReplyOrigin::App(restored.app_id())
    );
    keeper.remove_kept_peer(&bob.public()).await?;
    let reply = restored.allow_list().await?;
    assert!(!reply.peers[0].kept);
    assert_eq!(reply.peers[0].reply, both.peers[0].reply);
    let (_, delivery) = Box::pin(sender.send(note(alice.public(), "reply", None))).await?;
    assert!(matches!(delivery, Delivery::Accepted { .. }));

    keeper.remove_reply(&bob.public()).await?;
    assert!(restored.allow_list().await?.peers.is_empty());
    let (_, delivery) = Box::pin(sender.send(note(alice.public(), "no reason", None))).await?;
    assert!(matches!(
        delivery,
        Delivery::Queued {
            undeliverable_reason: Some(UndeliverableReason::NotAdmitted),
            ..
        }
    ));
    Ok(())
}

#[tokio::test]
async fn test_invitation_receipts_reach_sibling_and_restored_creator_on_both_backends() {
    for backend in [Backend::Scripted, Backend::Service] {
        let Some(trace) = run_here(backend, invitation_delivery).await.unwrap() else {
            continue;
        };
        for line in &trace.lines {
            assert!(
                !line
                    .label
                    .starts_with("{alice/sibling} GET /v1/{alice}/allow")
            );
            assert!(
                !line.facts.keys().any(|fact| fact.starts_with("violation")),
                "{trace}"
            );
        }
    }
}

async fn reply_grant_history(world: &World) -> FlowResult {
    use pubky_switch_client::app::OpBatch;
    use pubky_switch_core::admission::PeerReason;
    use pubky_switch_core::ops::OpKind;
    let alice = world.identity("alice")?;
    let bob = world.identity("bob")?;
    world.add_switch(ORIGIN, &[&alice, &bob]).await?;
    let mut owner = Box::pin(enroll(world, &alice)).await;
    let mut guest = Box::pin(enroll(world, &bob)).await;
    let (mut receiver, _) =
        Box::pin(join(world, &alice, &mut owner, "receiver", &[NOTES, PRUNE])).await;
    let (mut sender, _) = Box::pin(join(world, &bob, &mut guest, "sender", &[NOTES])).await;
    let invitation = receiver
        .register_invite_code(world.now_ms() + HOUR_MS, 1)
        .await?;
    world.advance_ms(1_000);
    let granted_at = world.now_ms();
    let (_, first) =
        Box::pin(sender.send(note(alice.public(), "invited", Some(&invitation.code)))).await?;
    assert!(matches!(first, Delivery::Accepted { .. }));
    let grants = receiver.allow_list().await?.peers;
    assert_eq!(grants.len(), 1, "{grants:?}");
    let original = grants[0];
    assert_eq!(original.pubky, bob.public());
    assert!(!original.kept);
    let reply = original.reply.expect("invitation reply grant");
    assert_eq!(reply.origin, ReplyOrigin::Invite(invitation.code_hash));
    assert_eq!(reply.at, granted_at);
    assert_eq!(reply.last_used, None);

    world.advance_ms(1_000);
    let (_, second) = Box::pin(sender.send(note(alice.public(), "ordinary", None))).await?;
    assert!(matches!(second, Delivery::Accepted { .. }));
    let mut used = original;
    used.reply
        .as_mut()
        .expect("invitation reply grant")
        .last_used = Some(world.now_ms());
    assert_eq!(receiver.allow_list().await?.peers, [used]);
    world.advance_ms(1_000);
    Box::pin(receiver.invite(&bob.public())).await?;
    assert_eq!(receiver.allow_list().await?.peers, [used]);

    let peer = bob.public();
    let reason = PeerReason::Reply;
    Box::pin(
        receiver.submit_batch(
            OpBatch::new()
                .op(OpKind::AllowDelete {
                    pubky: peer,
                    reason,
                })
                .op(OpKind::AllowPut {
                    pubky: peer,
                    reason,
                }),
        ),
    )
    .await?;
    let grants = receiver.allow_list().await?.peers;
    assert_eq!(grants.len(), 1, "{grants:?}");
    let new = &grants[0];
    assert_eq!(new.pubky, peer);
    assert!(!new.kept);
    let reply = new.reply.expect("app reply grant");
    assert_eq!(reply.origin, ReplyOrigin::App(receiver.app_id()));
    assert_eq!(reply.at, world.now_ms());
    assert_eq!(reply.last_used, None);
    Ok(())
}

#[tokio::test]
async fn test_reply_grant_history_scripted() {
    run_here(Backend::Scripted, reply_grant_history)
        .await
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn test_reply_grant_history_service() {
    run_here(Backend::Service, reply_grant_history)
        .await
        .unwrap();
}

async fn kept_peer_after_loss(world: &World) -> FlowResult {
    let alice = world.identity("alice")?;
    let kept_peer = world.identity("bob")?.public();
    let reply_only = world.identity("carol")?.public();
    world.add_switch(ORIGIN, &[&alice]).await?;
    let mut signer = Box::pin(enroll(world, &alice)).await;
    let (mut manager, protocol) =
        Box::pin(join(world, &alice, &mut signer, "manager", &[NOTES, PEERS])).await;
    let (mut reader, _) =
        Box::pin(join(world, &alice, &mut signer, "reader", &[NOTES, MANAGE])).await;
    assert!(!manager.cert().has_permission(Permission::ListsRead));
    assert!(!reader.cert().has_permission(Permission::ListsManage));
    Box::pin(manager.keep_peer(&kept_peer)).await?;
    Box::pin(manager.invite(&reply_only)).await?;
    assert!(manager.admits(&kept_peer).await? && manager.admits(&reply_only).await?);
    let original = reader.allow_list().await?;
    assert_eq!(original.peers.len(), 2);
    let kept = original
        .peers
        .iter()
        .find(|peer| peer.pubky == kept_peer)
        .expect("kept peer");
    assert!(kept.kept);
    assert_eq!(kept.reply, None);
    let invited = original
        .peers
        .iter()
        .find(|peer| peer.pubky == reply_only)
        .expect("reply peer");
    assert!(!invited.kept);
    assert_eq!(
        invited.reply.expect("app reply grant").origin,
        ReplyOrigin::App(manager.app_id())
    );

    let mut previous = ORIGIN;
    for (i, next) in ["https://second.example", "https://third.example"]
        .into_iter()
        .enumerate()
    {
        world.lose_switch(previous);
        world.add_switch(next, &[&alice]).await?;
        world.advance_ms(1_000);
        Box::pin(signer.declare_provider_loss(next, UserConfirmed::shown_and_confirmed())).await?;
        Box::pin(signer.end_staged_admission()).await?;
        if i == 0 {
            Box::pin(manager.refresh_identity()).await?;
            world.unreachable("POST", "/ops");
            assert!(Box::pin(manager.follow_provider()).await.is_err());
            let info = manager.recovery_info().await?.expect("declared loss");
            assert_eq!(info.step, pubky_switch_client::app::RecoveryStep::Register);
            assert!(
                !manager.admits(&kept_peer).await? && !manager.admits(&reply_only).await?,
                "the lost service cannot establish admission during interrupted registration"
            );
        }
        for app in [&mut manager, &mut reader] {
            Box::pin(app.refresh_identity()).await?;
            Box::pin(app.follow_provider()).await?;
        }
        let listed = reader.allow_list().await?;
        assert_eq!(
            listed.peers,
            [PeerEntry {
                pubky: kept_peer,
                kept: true,
                reply: None
            }],
            "the manager supplied its kept peer after loss {}",
            i + 1
        );
        assert!(
            !manager.admits(&kept_peer).await?,
            "the upload supplies no individual admission"
        );
        assert!(!manager.admits(&reply_only).await?);
        if i == 0 {
            let backup = manager.backup().await?;
            drop(manager);
            manager = Box::pin(App::restore(
                world.app_env(Arc::new(MemoryStore::new())),
                protocol.clone(),
                AppConfig::default(),
                &backup,
            ))
            .await?;
            assert!(!manager.admits(&kept_peer).await? && !manager.admits(&reply_only).await?);
            Box::pin(manager.receive(None)).await?;
        }
        previous = next;
    }
    Box::pin(manager.keep_peer(&kept_peer)).await?;
    assert!(manager.admits(&kept_peer).await?);
    Box::pin(manager.remove_kept_peer(&kept_peer)).await?;
    assert!(!manager.admits(&kept_peer).await?);
    assert!(
        reader
            .allow_list()
            .await?
            .peers
            .iter()
            .all(|peer| !peer.kept)
    );
    Ok(())
}

#[tokio::test]
async fn test_kept_peer_recovery_without_list_read_across_two_losses_scripted() {
    run_here(Backend::Scripted, kept_peer_after_loss)
        .await
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn test_kept_peer_recovery_without_list_read_across_two_losses_service() {
    run_here(Backend::Service, kept_peer_after_loss)
        .await
        .unwrap();
}
