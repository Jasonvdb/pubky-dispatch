//! Approving an app against the scripted switch (Switch spec 3.2, 12.1; Switch wire 3.9,
//! 3.10): the review's checks, the certificate and the version that lists it, and the
//! companion claim as the app reads it.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

#[path = "../examples/approve_app.rs"]
mod host_example;

use common::*;
use pubky_switch_client::testing::Fault as SwitchFault;
use pubky_switch_core::keys::AppKeys;
use pubky_switch_core::records::{AppRequest, Approval, ApprovalClaim, app_record_path};
use pubky_switch_core::scopes::Permission;
use pubky_switch_signer::{Protocols, Refusal, Signer, SignerError, UserConfirmed};

fn refusal(error: SignerError) -> Refusal {
    match error {
        SignerError::Refused(refusal) => refusal,
        other => panic!("not a refusal: {other:?}"),
    }
}

#[derive(Default)]
struct HostApprovals {
    record: std::cell::RefCell<Option<([u8; 32], host_example::SavedApproval)>>,
    interrupt_save: std::cell::Cell<bool>,
    interrupt_remove: std::cell::Cell<bool>,
}

impl host_example::ApprovalStore for HostApprovals {
    fn read(
        &self,
        hash: &[u8; 32],
    ) -> host_example::HostResult<Option<host_example::SavedApproval>> {
        Ok(self
            .record
            .borrow()
            .as_ref()
            .filter(|(key, _)| key == hash)
            .map(|(_, approval)| approval.clone()))
    }

    fn save(
        &self,
        hash: &[u8; 32],
        record: host_example::SavedApproval,
    ) -> host_example::HostResult<()> {
        let mut record = record;
        if let host_example::SavedApproval::Confirmed { consent, .. } = &mut record {
            *consent = serde_json::from_slice(&serde_json::to_vec(consent)?)?;
        }
        *self.record.borrow_mut() = Some((*hash, record));
        if self.interrupt_save.replace(false) {
            return Err("host stopped after saving the user's choice".into());
        }
        Ok(())
    }

    fn remove(&self, hash: &[u8; 32]) -> host_example::HostResult<()> {
        if self.interrupt_remove.replace(false) {
            return Err("host stopped before removing the record".into());
        }
        assert!(
            self.record
                .borrow()
                .as_ref()
                .is_some_and(|(key, _)| key == hash)
        );
        self.record.borrow_mut().take();
        Ok(())
    }
}

#[tokio::test]
async fn test_approval_host_example_respects_consent_and_finishes_on_reopen() {
    let world = World::new();
    let (mut signer, signer_store) = world.enrolled().await;
    let app = App::new(&["notes", "notes_tags"], None, [9; 32]);
    let hash = AppRequest::verify(&app.request).unwrap().hash();
    let record_cap = format!("{}:rw", app_record_path(&app.keys.app_id_bytes()));
    let host = HostApprovals {
        interrupt_remove: true.into(),
        ..Default::default()
    };
    let mut selected = signer.review(&app.request, &app.auth).unwrap();
    selected.decline(&[TAGS_PATH]).unwrap();
    let expected_consent = selected.consent();
    let delivered_claim = std::cell::RefCell::new(Vec::new());
    for confirmed in [false, true] {
        let claim_sent = std::cell::Cell::new(false);
        let grant_sent = std::cell::Cell::new(false);
        let result = Box::pin(host_example::approve_app(
            &mut signer,
            &host,
            &app.request,
            &app.auth,
            async |review| {
                assert_eq!(review.request_hash(), hash);
                assert_eq!(review.asked_caps, app.auth.caps);
                review.decline(&[TAGS_PATH])?;
                Ok(confirmed)
            },
            async |auth, bytes| {
                assert!(confirmed);
                assert!(matches!(&*host.record.borrow(), Some((key, host_example::SavedApproval::Confirmed { request, auth: saved, consent })) if key == &hash && request == &app.request && saved == auth && **consent == expected_consent));
                let claim = ApprovalClaim::from_plaintext(bytes)?;
                claim.verify(&world.key.public(), auth)?;
                delivered_claim.replace(bytes.to_vec());
                claim_sent.set(true);
                Ok(())
            },
            async |_, caps| {
                assert!(claim_sent.get());
                assert_eq!(caps, record_cap);
                grant_sent.set(true);
                Ok(())
            },
        )).await;
        if confirmed {
            assert_eq!(
                result.unwrap_err().to_string(),
                "host stopped before removing the record"
            );
        } else {
            assert_eq!(result.unwrap(), None);
            assert!(host.record.borrow().is_none());
        }
        assert_eq!(claim_sent.get(), confirmed);
        assert_eq!(grant_sent.get(), confirmed);
        assert!(signer.approved(&hash).unwrap().is_none());
        assert_eq!(signer.apps().unwrap().len(), usize::from(confirmed));
    }
    assert!(
        matches!(&*host.record.borrow(), Some((key, host_example::SavedApproval::GrantComplete)) if *key == hash)
    );
    let doc = signer.identity_doc().unwrap().unwrap();
    let app_id = app.keys.app_id_bytes();
    let cert = doc.listed_cert(&app_id).unwrap();
    let delivered = pubky_switch_signer::ApprovedRequest {
        request: hash,
        app_id,
        caps: record_cap,
        claim: delivered_claim.into_inner(),
    };
    assert_eq!(world.join(&app, &delivered).hash(), cert);
    drop(signer);

    let mut reopened = pubky_switch_signer::Signer::open(world.env(signer_store), world.keyring())
        .await
        .unwrap();
    assert!(reopened.approved(&hash).unwrap().is_none());
    Box::pin(host_example::resume_approval(
        &mut reopened,
        &host,
        &hash,
        async |_, _| panic!("sent the companion claim twice"),
        async |_, _| panic!("approved the grant twice"),
    ))
    .await
    .unwrap();
    let resumed = reopened.identity_doc().unwrap().unwrap();
    assert_eq!(resumed.listed_cert(&app_id), Some(cert));
    assert_eq!(resumed.signed(), doc.signed());
    assert!(host.record.borrow().is_none());
}

#[tokio::test]
async fn test_approval_host_rechecks_confirmed_terms_before_issuing_on_restart() {
    use std::sync::Arc;

    for changed in [false, true] {
        let world = World::new();
        let (initial, store) = world.enrolled().await;
        drop(initial);
        let protocols = |right| Protocols::new(vec![Arc::new(NotesGiving(vec![right]))]).unwrap();
        let mut signer = Signer::open(
            world.env_with(store.clone(), protocols(Permission::ListsRead)),
            world.keyring(),
        )
        .await
        .unwrap();
        let app = App::new(&["notes"], None, [9; 32]);
        let hash = AppRequest::verify(&app.request).unwrap().hash();
        let reviewed = signer.review(&app.request, &app.auth).unwrap();
        let original = signer.identity_doc().unwrap().unwrap();
        let host = HostApprovals {
            interrupt_save: true.into(),
            ..Default::default()
        };
        let interrupted = Box::pin(host_example::approve_app(
            &mut signer,
            &host,
            &app.request,
            &app.auth,
            async |review| {
                assert_eq!(review.permissions, [Permission::ListsRead]);
                Ok(true)
            },
            async |_, _| panic!("sent an uncommitted claim"),
            async |_, _| panic!("sent an uncommitted grant"),
        ))
        .await
        .unwrap_err();
        assert_eq!(
            interrupted.to_string(),
            "host stopped after saving the user's choice"
        );
        assert!(signer.approved(&hash).unwrap().is_none());
        drop(signer);
        let right = if changed {
            Permission::ReplyAdd
        } else {
            Permission::ListsRead
        };
        let mut signer = Signer::open(world.env_with(store, protocols(right)), world.keyring())
            .await
            .unwrap();
        if changed {
            let first = world.transport.requests().len();
            assert_eq!(
                Box::pin(signer.approve(reviewed)).await.unwrap_err(),
                Refusal::ApprovalChanged.into()
            );
            let failure = Box::pin(host_example::resume_approval(
                &mut signer,
                &host,
                &hash,
                async |_, _| panic!("delivered before fresh consent"),
                async |_, _| panic!("granted before fresh consent"),
            ))
            .await
            .unwrap_err();
            assert_eq!(
                failure.downcast_ref::<SignerError>(),
                Some(&Refusal::ApprovalChanged.into())
            );
            assert!(host.record.borrow().is_none());
            assert_eq!(
                signer.identity_doc().unwrap().unwrap().signed(),
                original.signed()
            );
            assert!(signer.approved(&hash).unwrap().is_none());
            assert!(
                world.transport.requests()[first..]
                    .iter()
                    .all(|r| r.method == "GET")
            );
        }
        let claim = std::cell::RefCell::new(Vec::new());
        let result = Box::pin(host_example::approve_app(
            &mut signer,
            &host,
            &app.request,
            &app.auth,
            async |review| {
                assert!(changed, "unchanged consent was requested again");
                assert_eq!(review.permissions, [right]);
                Ok(true)
            },
            async |_, bytes| {
                claim.replace(bytes.to_vec());
                Ok(())
            },
            async |_, caps| {
                assert_eq!(caps, app.auth.caps);
                Ok(())
            },
        ))
        .await
        .unwrap();
        assert_eq!(result, Some(hash));
        let delivered = pubky_switch_signer::ApprovedRequest {
            request: hash,
            app_id: app.keys.app_id_bytes(),
            caps: app.auth.caps.clone(),
            claim: claim.into_inner(),
        };
        assert_eq!(world.join(&app, &delivered).permissions(), [right]);
    }
}

#[tokio::test]
async fn test_approval_host_redelivers_the_issued_claim_after_a_permission_change() {
    use std::sync::Arc;

    let world = World::new();
    let (mut signer, store) = world.enrolled().await;
    let app = App::new(&["notes"], None, [9; 32]);
    let hash = AppRequest::verify(&app.request).unwrap().hash();
    let host = HostApprovals::default();
    Box::pin(host_example::approve_app(
        &mut signer,
        &host,
        &app.request,
        &app.auth,
        async |review| {
            assert_eq!(review.permissions, [Permission::ClaimsRead]);
            Ok(true)
        },
        async |_, _| Err("relay is unavailable".into()),
        async |_, _| panic!("grant preceded relay"),
    ))
    .await
    .unwrap_err();
    let issued = signer.approved(&hash).unwrap().unwrap();
    let document = signer.identity_doc().unwrap().unwrap();
    drop(signer);
    let protocols =
        Protocols::new(vec![Arc::new(NotesGiving(vec![Permission::ReplyAdd]))]).unwrap();
    let mut signer = Signer::open(world.env_with(store, protocols), world.keyring())
        .await
        .unwrap();
    Box::pin(host_example::resume_approval(
        &mut signer,
        &host,
        &hash,
        async |_, claim| {
            assert_eq!(claim, issued.claim);
            Ok(())
        },
        async |_, caps| {
            assert_eq!(caps, issued.caps);
            Ok(())
        },
    ))
    .await
    .unwrap();
    assert_eq!(
        signer.identity_doc().unwrap().unwrap().signed(),
        document.signed()
    );
    assert_eq!(
        world.join(&app, &issued).permissions(),
        [Permission::ClaimsRead]
    );
    assert!(signer.approved(&hash).unwrap().is_none());
    assert!(host.record.borrow().is_none());
}

/// The notes protocol with the tag scope's keys and its grant path's purpose chosen by the
/// test, so a reopened signer can show other terms for the same request.
struct NotesShown {
    tags_keyed: bool,
    purpose: &'static str,
}

impl pubky_switch_signer::Protocol for NotesShown {
    fn name(&self) -> &str {
        "notes"
    }
    fn scopes(&self) -> Vec<pubky_switch_signer::ScopeDef> {
        vec![
            pubky_switch_signer::ScopeDef::keyed("notes"),
            pubky_switch_signer::ScopeDef {
                name: "notes_tags".into(),
                has_keys: self.tags_keyed,
            },
        ]
    }
    fn check_scopes(&self, _: &[&str]) -> Result<(), String> {
        Ok(())
    }
    fn permissions(&self, scopes: &[&str]) -> Vec<Permission> {
        if scopes.contains(&"notes") {
            vec![Permission::ClaimsRead]
        } else {
            Vec::new()
        }
    }
    fn grant_paths(&self, _: &[u8; 16], scopes: &[&str]) -> Vec<pubky_switch_signer::GrantPath> {
        if scopes.contains(&"notes_tags") {
            vec![pubky_switch_signer::GrantPath {
                path: TAGS_PATH.into(),
                purpose: self.purpose.into(),
            }]
        } else {
            Vec::new()
        }
    }
}

#[tokio::test]
async fn test_approval_refuses_a_review_whose_keys_or_purposes_changed() {
    // Whether a scope has Shared Data Keys and what a grant path is for are shown to the user;
    // a protocol update that changes either between the review and `approve` signs nothing
    // (Switch spec 12.1 step 1).
    use std::sync::Arc;

    const PURPOSE: &str = "the public tag list";
    let shown = |tags_keyed, purpose| {
        Protocols::new(vec![Arc::new(NotesShown {
            tags_keyed,
            purpose,
        })])
        .unwrap()
    };
    for (before, after) in [
        (shown(false, PURPOSE), shown(true, PURPOSE)),
        (shown(false, PURPOSE), shown(false, "the tag list, shared")),
    ] {
        let world = World::new();
        let (initial, store) = world.enrolled().await;
        drop(initial);
        let signer = Signer::open(world.env_with(store.clone(), before), world.keyring())
            .await
            .unwrap();
        let app = App::new(&["notes", "notes_tags"], None, [9; 32]);
        let review = signer.review(&app.request, &app.auth).unwrap();
        let original = signer.identity_doc().unwrap().unwrap();
        drop(signer);
        let mut signer = Signer::open(world.env_with(store, after), world.keyring())
            .await
            .unwrap();
        let first = world.transport.requests().len();
        let hash = review.request_hash();
        assert_eq!(
            Box::pin(signer.approve(review)).await.unwrap_err(),
            Refusal::ApprovalChanged.into()
        );
        assert_eq!(
            signer.identity_doc().unwrap().unwrap().signed(),
            original.signed()
        );
        assert!(signer.approved(&hash).unwrap().is_none());
        assert!(
            world.transport.requests()[first..]
                .iter()
                .all(|r| r.method == "GET")
        );
    }
}

#[tokio::test]
async fn test_approval_consent_applies_only_to_its_identity_and_request() {
    // A saved consent names the identity and the request it was given for: applied to a
    // review of another request, or carrying another identity, it is refused.
    let world = World::new();
    let (signer, _) = world.enrolled().await;
    let first = App::new(&["notes"], None, [9; 32]);
    let second = App::new(&["notes"], None, [10; 32]);
    let consent = signer
        .review(&first.request, &first.auth)
        .unwrap()
        .consent();
    let other = signer.review(&second.request, &second.auth).unwrap();
    assert_eq!(
        consent.apply_to(other).unwrap_err(),
        Refusal::ApprovalChanged.into()
    );
    let mut value = serde_json::to_value(&consent).unwrap();
    value["identity"] = serde_json::to_value([7u8; 32]).unwrap();
    let elsewhere: pubky_switch_signer::ApprovalConsent = serde_json::from_value(value).unwrap();
    let review = signer.review(&first.request, &first.auth).unwrap();
    assert_eq!(
        elsewhere.apply_to(review.clone()).unwrap_err(),
        Refusal::ApprovalChanged.into()
    );
    assert!(consent.apply_to(review).is_ok());
}

#[tokio::test]
async fn test_approval_review_fields_edited_for_display_change_nothing() {
    // A host may sort or translate what it shows: the consent is the review's own copy, so the
    // saved choice still applies to a fresh review.
    let world = World::new();
    let (signer, _) = world.enrolled().await;
    let app = App::new(&["notes", "notes_tags"], None, [9; 32]);
    let mut review = signer.review(&app.request, &app.auth).unwrap();
    let before = review.consent();
    review.scopes.reverse();
    review.grant_paths[0].purpose = "la liste publique".into();
    review.renews = !review.renews;
    review.decline(&[TAGS_PATH]).unwrap();
    let consent = review.consent();
    assert_ne!(consent, before, "the decline is kept");
    let fresh = signer.review(&app.request, &app.auth).unwrap();
    assert_eq!(consent.apply_to(fresh).unwrap().declined(), [TAGS_PATH]);
}

#[tokio::test]
async fn test_approval_shows_and_grants_each_peer_permission_independently() {
    use std::sync::Arc;

    for permission in [
        Permission::ListsRead,
        Permission::ListsManage,
        Permission::ReplyAdd,
    ] {
        let world = World::new();
        let (original, store) = world.enrolled().await;
        drop(original);
        let protocols = Protocols::new(vec![Arc::new(NotesGiving(vec![permission]))]).unwrap();
        let mut signer = Signer::open(world.env_with(store, protocols), world.keyring())
            .await
            .unwrap();
        let app = App::new(&["notes"], None, [9; 32]);
        let review = signer.review(&app.request, &app.auth).unwrap();
        assert_eq!(review.permissions, [permission]);
        let approved = signer.approve(review).await.unwrap();
        let cert = world.join(&app, &approved);
        assert_eq!(cert.permissions(), [permission]);
        signer.claim_delivered(&approved.request).await.unwrap();
    }
}

#[tokio::test]
async fn test_approval_lists_the_app_and_the_app_reads_its_claim() {
    let world = World::new();
    let (mut signer, _) = world.enrolled().await;
    let app = App::new(&["notes", "notes_tags"], None, [9; 32]);
    let review = signer.review(&app.request, &app.auth).unwrap();
    assert_eq!(review.app_id, app.keys.app_id_bytes());
    // The permissions are the protocol's table for the scopes, in the fixed order.
    assert_eq!(
        review.permissions,
        [Permission::ClaimsRead, Permission::ListsRead]
    );
    assert_eq!(review.keyed, ["notes"]);
    assert_eq!(review.grant_paths.len(), 1);
    assert_eq!(review.grant_paths[0].path, TAGS_PATH);

    let approved = signer.approve(review).await.unwrap();
    assert_eq!(approved.app_id, app.keys.app_id_bytes());
    assert_eq!(approved.caps, app.auth.caps);
    // The version listing the certificate is delivered, published and backed up.
    let doc = signer.identity_doc().unwrap().unwrap();
    assert_eq!(doc.version(), 2);
    let cert_hash = doc.listed_cert(&app.keys.app_id_bytes()).unwrap();
    assert_eq!(world.switch.identity_doc().unwrap().signed(), doc.signed());
    assert_eq!(world.published().unwrap().signed(), doc.signed());
    let records = world.backup();
    assert_eq!(records.identity_doc().signed(), doc.signed());
    assert!(records.certs().iter().any(|c| c.hash() == cert_hash));

    // The app checks the claim and reads the approval, opening its key bundle (Switch wire
    // 3.10).
    let identity = world.key.public();
    let claim = ApprovalClaim::from_plaintext(&approved.claim).unwrap();
    let json = claim.verify(&identity, &app.auth).unwrap();
    let request = AppRequest::verify(&app.request).unwrap();
    let has_keys = |scope: &str| scope == "notes";
    let read = Approval::read(
        json,
        &request,
        &identity,
        &app.keys.bundle_secret(),
        &has_keys,
    )
    .unwrap();
    assert_eq!(read.cert.hash(), cert_hash);
    assert_eq!(read.cert.scopes(), ["notes", "notes_tags"]);
    assert_eq!(
        read.cert.permissions(),
        [Permission::ClaimsRead, Permission::ListsRead]
    );
    assert_eq!(read.identity.signed(), doc.signed());
    assert_eq!(read.naming_key, world.key.naming_key());
    assert_eq!(
        read.keys.get(1, "notes"),
        Some(world.key.scope_key(1, "notes"))
    );
    assert_eq!(read.keys.get(1, "notes_tags"), None);

    // The host reports it delivered: the claim is dropped.
    assert!(signer.approved(&approved.request).unwrap().is_some());
    signer.claim_delivered(&approved.request).await.unwrap();
    assert!(signer.approved(&approved.request).unwrap().is_none());
}

#[tokio::test]
async fn test_approval_of_a_listed_app_with_its_keys_renews_its_certificate() {
    // The app asks again with the keys it is listed with, now for fewer scopes: approving it
    // renews its certificate with them (Switch wire 3.9 step 5, 3.8), and the approval that
    // answers it holds the renewed certificate and the renewing version.
    let world = World::new();
    let (mut signer, _) = world.enrolled().await;
    let app = App::new(&["notes", "notes_tags"], None, [9; 32]);
    world.approve(&mut signer, &app).await;
    let id = app.keys.app_id_bytes();
    let first = signer
        .identity_doc()
        .unwrap()
        .unwrap()
        .listed_cert(&id)
        .unwrap();
    let again = App::new(&["notes"], None, [10; 32]);
    let review = signer.review(&again.request, &again.auth).unwrap();
    assert!(review.renews);
    assert_eq!(review.app_id, id);
    let approved = signer.approve(review).await.unwrap();
    let newest = signer.identity_doc().unwrap().unwrap();
    let renewed = newest.listed_cert(&id).unwrap();
    assert_ne!(renewed, first);
    assert!(
        newest
            .body()
            .renewed
            .iter()
            .any(|r| r.app_id == id && r.cert == first)
    );
    // Stored at the switch with its full bundle, as every renewal is.
    assert_eq!(world.switch.app(&id).renewed.unwrap().hash(), renewed);

    let identity = world.key.public();
    let claim = ApprovalClaim::from_plaintext(&approved.claim).unwrap();
    let json = claim.verify(&identity, &again.auth).unwrap();
    let request = AppRequest::verify(&again.request).unwrap();
    let read = Approval::read(
        json,
        &request,
        &identity,
        &app.keys.bundle_secret(),
        &|scope: &str| scope == "notes",
    )
    .unwrap();
    assert_eq!(read.cert.hash(), renewed);
    assert_eq!(read.cert.scopes(), ["notes"]);
    assert!(read.identity.listed_cert(&id) == Some(renewed));
    assert_eq!(
        read.keys.get(1, "notes"),
        Some(world.key.scope_key(1, "notes"))
    );
    world.assert_no_version_sent_twice();
}

#[tokio::test]
async fn test_approval_renewing_a_listed_app_holds_its_claim_until_published() {
    // The renewing version couldn't be published: the claim was committed with it, and is
    // released only once a later run has published it, as for every approval.
    let world = World::new();
    let (mut signer, _) = world.enrolled().await;
    let app = App::new(&["notes"], None, [9; 32]);
    world.approve(&mut signer, &app).await;
    let again = App::new(&["notes"], None, [10; 32]);
    let review = signer.review(&again.request, &again.auth).unwrap();
    let request = review.request_hash();
    *world.homeserver.failing_puts.lock().unwrap() = true;
    let error = signer.approve(review).await.unwrap_err();
    assert!(matches!(error, SignerError::Homeserver(_)), "{error:?}");
    assert!(signer.approved(&request).unwrap().is_none());
    *world.homeserver.failing_puts.lock().unwrap() = false;
    signer.resume().await.unwrap();
    let approved = signer.approved(&request).unwrap().unwrap();
    let claim = ApprovalClaim::from_plaintext(&approved.claim).unwrap();
    claim.verify(&world.key.public(), &again.auth).unwrap();
    world.assert_no_version_sent_twice();
}

#[tokio::test]
async fn test_approval_of_a_listed_app_with_other_keys_is_refused() {
    // The same signing key, so the same App ID, with another bundle key: a listed App ID is
    // never given other keys (Switch wire 3.9 step 5).
    let world = World::new();
    let (mut signer, _) = world.enrolled().await;
    let app = App::new(&["notes"], None, [9; 32]);
    world.approve(&mut signer, &app).await;
    let other = App::with_keys(
        AppKeys::from_secrets([3; 32], [44; 32]),
        &["notes"],
        None,
        [10; 32],
    );
    assert_eq!(other.keys.app_id_bytes(), app.keys.app_id_bytes());
    let error = signer.review(&other.request, &other.auth).unwrap_err();
    assert!(matches!(refusal(error), Refusal::AppRequest(ref why) if why.contains("step 5")),);
}

#[tokio::test]
async fn test_approval_of_a_listed_app_that_never_joined_isnt_renewed() {
    // The app was approved but never delivered its record, so the switch can't take a
    // renewed certificate for it (Switch wire 6.2): the approval is refused, and nothing is
    // signed.
    let world = World::new();
    let (mut signer, _) = world.enrolled().await;
    let app = App::new(&["notes"], None, [9; 32]);
    let review = signer.review(&app.request, &app.auth).unwrap();
    signer.approve(review).await.unwrap();
    let again = App::new(&["notes"], None, [10; 32]);
    let review = signer.review(&again.request, &again.auth).unwrap();
    assert!(review.renews);
    let sent = world.sent_docs().len();
    assert_eq!(
        refusal(signer.approve(review).await.unwrap_err()),
        Refusal::NotJoined
    );
    assert_eq!(world.sent_docs().len(), sent);
}

#[tokio::test]
async fn test_review_refuses_a_scope_no_protocol_owns() {
    let world = World::new();
    let (signer, _) = world.enrolled().await;
    let app = App::new(&["notes", "photos"], None, [9; 32]);
    let error = signer.review(&app.request, &app.auth).unwrap_err();
    assert_eq!(
        refusal(error),
        Refusal::UnknownScopes {
            scopes: vec!["photos".into()]
        }
    );
}

#[tokio::test]
async fn test_review_refuses_capabilities_that_arent_the_apps_own() {
    let world = World::new();
    let (signer, _) = world.enrolled().await;
    let record = format!(
        "{}:rw",
        app_record_path(&AppKeys::from_secrets([3; 32], [4; 32]).app_id_bytes())
    );
    for caps in [
        // A path the app's protocols don't add for its scopes.
        format!("{record},{TAGS_PATH}:rw"),
        // No record path.
        format!("{TAGS_PATH}:rw"),
    ] {
        let app = App::new(&["notes"], Some(caps.clone()), [9; 32]);
        let error = signer.review(&app.request, &app.auth).unwrap_err();
        assert!(
            matches!(refusal(error), Refusal::AppRequest(ref why) if why.contains("step 3")),
            "{caps}"
        );
    }
}

#[tokio::test]
async fn test_review_refuses_a_request_bound_to_another_auth_request() {
    let world = World::new();
    let (signer, _) = world.enrolled().await;
    let app = App::new(&["notes"], None, [9; 32]);
    let mut other = app.auth.clone();
    other.secret = [10; 32];
    let error = signer.review(&app.request, &other).unwrap_err();
    assert!(matches!(refusal(error), Refusal::AppRequest(ref why) if why.contains("step 2")),);
}

#[tokio::test]
async fn test_review_needs_a_first_version() {
    let world = World::new();
    let signer = pubky_switch_signer::Signer::create(
        world.env(std::sync::Arc::new(
            pubky_switch_client::store::MemoryStore::new(),
        )),
        world.keyring(),
        pubky_switch_client::testing::SWITCH_ORIGIN,
    )
    .await
    .unwrap();
    let app = App::new(&["notes"], None, [9; 32]);
    let error = signer.review(&app.request, &app.auth).unwrap_err();
    assert_eq!(refusal(error), Refusal::NotSetUp);
}

#[tokio::test]
async fn test_approval_claim_waits_for_its_delivery() {
    let world = World::new();
    let (mut signer, _) = world.enrolled().await;
    let app = App::new(&["notes"], None, [9; 32]);
    let review = signer.review(&app.request, &app.auth).unwrap();
    let request = review.request_hash();
    *world.homeserver.failing_puts.lock().unwrap() = true;
    let error = signer.approve(review).await.unwrap_err();
    assert!(matches!(error, SignerError::Homeserver(_)), "{error:?}");
    // Not delivered, so not released.
    assert!(signer.approved(&request).unwrap().is_none());
    assert_eq!(world.switch.identity_doc().unwrap().version(), 1);
    *world.homeserver.failing_puts.lock().unwrap() = false;
    signer.resume().await.unwrap();
    let approved = signer.approved(&request).unwrap().unwrap();
    let claim = ApprovalClaim::from_plaintext(&approved.claim).unwrap();
    claim.verify(&world.key.public(), &app.auth).unwrap();
    world.assert_no_version_sent_twice();
}

#[tokio::test]
async fn test_approval_claim_of_a_refused_delivery_is_never_released() {
    let world = World::new();
    let (mut signer, _) = world.enrolled().await;
    let first = signer.identity_doc().unwrap().unwrap();
    signer.set_record_max_age(Some(86_400)).await.unwrap();
    world.switch.deliver_identity(&first).unwrap();
    let app = App::new(&["notes"], None, [9; 32]);
    let review = signer.review(&app.request, &app.auth).unwrap();
    let request = review.request_hash();
    let error = signer.approve(review).await.unwrap_err();
    assert!(matches!(error, SignerError::Alarm(_)), "{error:?}");
    assert!(signer.approved(&request).unwrap().is_none());
}

#[tokio::test]
async fn test_review_refuses_a_grant_that_covers_identity_json() {
    // Only the covers check refuses this: the reason names it (Switch wire 3.9 step 3).
    let world = World::new();
    let (signer, _) = world.enrolled().await;
    let record = format!(
        "{}:rw",
        app_record_path(&AppKeys::from_secrets([3; 32], [4; 32]).app_id_bytes())
    );
    for covering in [
        "/pub/pubky-switch/",
        "/pub/",
        "/priv/pubky-switch/",
        "/priv/",
        "/priv/pubky-switch/v1/signer-backup.json",
    ] {
        let app = App::new(&["notes"], Some(format!("{record},{covering}:rw")), [9; 32]);
        let error = signer.review(&app.request, &app.auth).unwrap_err();
        assert!(
            matches!(refusal(error), Refusal::AppRequest(ref why) if why.contains("covers")),
            "{covering}"
        );
    }
}

#[tokio::test]
async fn test_review_refuses_an_app_id_the_newest_version_lists_as_removed() {
    // Wire 3.9 step 4. The revocations PR writes the signer's own tombstones; here the
    // newest version, adopted from the switch, another install's, lists the app in `removed`.
    let world = World::new();
    let (mut signer, _) = world.enrolled().await;
    let app = App::new(&["notes"], None, [9; 32]);
    let newest = signer.identity_doc().unwrap().unwrap();
    let mut body = newest.body().clone();
    body.version += 1;
    body.signer = [7; 16];
    body.removed.push(pubky_switch_core::records::RemovedApp {
        app_id: app.keys.app_id_bytes(),
        distrust_from: START_MS,
    });
    let removing = pubky_switch_core::records::IdentityDoc::sign(&world.key, body).unwrap();
    world.switch.deliver_identity(&removing).unwrap();
    let error = signer.set_record_max_age(Some(86_400)).await.unwrap_err();
    assert_eq!(error, SignerError::NotNamed { install: [7; 16] });
    let error = signer.review(&app.request, &app.auth).unwrap_err();
    assert!(matches!(refusal(error), Refusal::AppRequest(ref why) if why.contains("step 4")),);
}

#[tokio::test]
async fn test_review_refuses_an_app_past_the_app_limit() {
    // Wire 3.9 step 6, at the limit the switch announced at enrollment.
    let world = World::new();
    world
        .switch
        .set_enroll_limits(pubky_switch_core::records::Limits {
            app_limit: 1,
            ..Default::default()
        });
    let (mut signer, _) = world.enrolled().await;
    let first = App::new(&["notes"], None, [9; 32]);
    let review = signer.review(&first.request, &first.auth).unwrap();
    signer.approve(review).await.unwrap();
    let second = App::with_keys(
        AppKeys::from_secrets([5; 32], [6; 32]),
        &["notes"],
        None,
        [10; 32],
    );
    let error = signer.review(&second.request, &second.auth).unwrap_err();
    assert!(matches!(refusal(error), Refusal::AppRequest(ref why) if why.contains("step 6")),);
}

#[tokio::test]
async fn test_approval_claim_waits_for_the_publish_and_for_alarms() {
    let world = World::new();
    let (mut signer, _) = world.enrolled().await;
    let first = signer.identity_doc().unwrap().unwrap();
    let app = App::new(&["notes"], None, [9; 32]);
    let review = signer.review(&app.request, &app.auth).unwrap();
    let request = review.request_hash();
    // Delivered, but the publish fails: no claim yet (Switch wire 3.9).
    *world.homeserver.failing_path.lock().unwrap() =
        Some(pubky_switch_core::records::IDENTITY_PATH.into());
    let error = signer.approve(review).await.unwrap_err();
    assert!(matches!(error, SignerError::Homeserver(_)), "{error:?}");
    assert_eq!(world.switch.identity_doc().unwrap().version(), 2);
    assert!(signer.approved(&request).unwrap().is_none());
    *world.homeserver.failing_path.lock().unwrap() = None;
    signer.resume().await.unwrap();
    assert!(signer.approved(&request).unwrap().is_some());
    // The switch rolls back: the alarm holds the claim back until the user clears it.
    world.switch.deliver_identity(&first).unwrap();
    let error = signer.set_record_max_age(Some(86_400)).await.unwrap_err();
    let SignerError::Alarm(alert) = error else {
        panic!("{error:?}")
    };
    assert!(signer.approved(&request).unwrap().is_none());
    // Clearing it delivers the newest version again; the switch, back at version 1, takes it,
    // and only then is the claim released.
    signer.clear_alert(&alert).await.unwrap();
    let at_switch = world.switch.identity_doc().unwrap();
    assert_eq!(at_switch.version(), 2);
    assert!(at_switch.listed_cert(&app.keys.app_id_bytes()).is_some());
    assert!(signer.approved(&request).unwrap().is_some());
    world.assert_no_version_sent_twice();
}

#[tokio::test]
async fn test_approval_clearing_an_alarm_the_switch_still_shows_keeps_the_claim_held() {
    let world = World::new();
    let (mut signer, _) = world.enrolled().await;
    let first = signer.identity_doc().unwrap().unwrap();
    let app = App::new(&["notes"], None, [9; 32]);
    let review = signer.review(&app.request, &app.auth).unwrap();
    let approved = signer.approve(review).await.unwrap();
    // The switch holds another version 2: equivocation.
    let mut body = first.body().clone();
    body.version = 2;
    body.record_max_age = Some(60);
    let forked = pubky_switch_core::records::IdentityDoc::sign(&world.key, body).unwrap();
    world.switch.deliver_identity(&forked).unwrap();
    let error = signer.set_record_max_age(Some(86_400)).await.unwrap_err();
    let SignerError::Alarm(alert) = error else {
        panic!("{error:?}")
    };
    // Clearing it delivers version 2 again, which the switch refuses: the alarm comes back.
    let error = signer.clear_alert(&alert).await.unwrap_err();
    assert_eq!(error, SignerError::Alarm(alert));
    assert!(signer.approved(&approved.request).unwrap().is_none());
}

#[tokio::test]
async fn test_approval_after_an_old_alarm_waits_for_the_alert_to_be_cleared() {
    // The switch went back and is put back as it was: nothing is signed while the alert is
    // held. Once the user clears it, the re-delivery confirms the switch, and the approval and
    // its claim go through.
    let world = World::new();
    let (mut signer, _) = world.enrolled().await;
    let first = signer.identity_doc().unwrap().unwrap();
    signer.set_record_max_age(Some(86_400)).await.unwrap();
    world.switch.deliver_identity(&first).unwrap();
    let SignerError::Alarm(alert) = signer.set_record_max_age(Some(3_600)).await.unwrap_err()
    else {
        panic!("no alarm")
    };
    let second = signer.identity_doc().unwrap().unwrap();
    world.switch.deliver_identity(&second).unwrap();
    let app = App::new(&["notes"], None, [9; 32]);
    let review = signer.review(&app.request, &app.auth).unwrap();
    let sent = world.sent_docs().len();
    assert_eq!(
        signer.approve(review.clone()).await.unwrap_err(),
        SignerError::Alarm(alert.clone())
    );
    assert_eq!(world.sent_docs().len(), sent);
    signer.clear_alert(&alert).await.unwrap();
    let approved = signer.approve(review).await.unwrap();
    assert_eq!(signer.approved(&approved.request).unwrap(), Some(approved));
}

#[tokio::test]
async fn test_approval_withholds_claim_before_revocation_reaches_the_switch() {
    let world = World::new();
    let (mut signer, _) = world.enrolled().await;
    let app = App::new(&["notes"], None, [9; 32]);
    let terms = signer.review(&app.request, &app.auth).unwrap();
    let issued = signer.approve(terms.clone()).await.unwrap();
    let listing = world.published().unwrap();

    world.switch.fail_next(SwitchFault::Unreachable {
        path: "/revoke".into(),
        after: 0,
    });
    let error = signer
        .revoke(issued.app_id, None, UserConfirmed::shown_and_confirmed())
        .await
        .unwrap_err();
    assert!(matches!(error, SignerError::Switch(_)), "{error:?}");
    assert!(!world.switch.app(&issued.app_id).departed);
    assert_eq!(world.published().unwrap().signed(), listing.signed());
    assert!(signer.approved(&issued.request).unwrap().is_none());
    assert!(matches!(
        refusal(signer.approve(terms).await.unwrap_err()),
        Refusal::AppRequest(_)
    ));
}

#[tokio::test]
async fn test_approval_withholds_renewal_claim_after_removal_delivery_fails() {
    let world = World::new();
    let (mut signer, store) = world.enrolled().await;
    let app = App::new(&["notes"], None, [9; 32]);
    world.approve(&mut signer, &app).await;
    let renewal = App::with_keys(app.keys, &["notes"], None, [10; 32]);
    let terms = signer.review(&renewal.request, &renewal.auth).unwrap();
    let issued = signer.approve(terms).await.unwrap();
    let listing = world.published().unwrap();

    world.switch.fail_next(SwitchFault::Unreachable {
        path: "/identity".into(),
        after: 0,
    });
    let error = signer
        .revoke(issued.app_id, None, UserConfirmed::shown_and_confirmed())
        .await
        .unwrap_err();
    assert!(matches!(error, SignerError::Switch(_)), "{error:?}");
    assert!(world.switch.app(&issued.app_id).departed);
    assert_eq!(world.published().unwrap().signed(), listing.signed());
    drop(signer);

    let reopened = Signer::open(world.env(store), world.keyring())
        .await
        .unwrap();
    assert!(reopened.approved(&issued.request).unwrap().is_none());
}

#[tokio::test]
async fn test_approval_claim_is_held_while_another_install_signs() {
    let world = World::new();
    let (mut signer, _) = world.enrolled().await;
    let app = App::new(&["notes"], None, [9; 32]);
    let review = signer.review(&app.request, &app.auth).unwrap();
    let approved = signer.approve(review).await.unwrap();
    let newest = signer.identity_doc().unwrap().unwrap();
    world
        .switch
        .deliver_identity(&world.other_install_version(&newest, [7; 16]))
        .unwrap();
    signer.set_record_max_age(Some(86_400)).await.unwrap_err();
    assert!(signer.approved(&approved.request).unwrap().is_none());
}

#[tokio::test]
async fn test_approval_claim_is_held_while_the_records_are_behind() {
    let world = World::new();
    let (mut signer, _) = world.enrolled().await;
    let app = App::new(&["notes"], None, [9; 32]);
    let review = signer.review(&app.request, &app.auth).unwrap();
    let approved = signer.approve(review).await.unwrap();
    assert!(signer.approved(&approved.request).unwrap().is_some());
    // The switch then shows a newer version of this install's own.
    let newest = signer.identity_doc().unwrap().unwrap();
    world
        .switch
        .deliver_identity(&world.other_install_version(&newest, signer.install_id()))
        .unwrap();
    let error = signer.set_record_max_age(Some(86_400)).await.unwrap_err();
    assert!(
        matches!(error, SignerError::Refused(Refusal::RecordsBehind { .. })),
        "{error:?}"
    );
    assert!(signer.approved(&approved.request).unwrap().is_none());
}

#[tokio::test]
async fn test_approval_a_refused_delivery_leaves_no_certificate() {
    use pubky_switch_core::http::ErrorCode;
    let world = World::new();
    let (mut signer, _) = world.enrolled().await;
    let app = App::new(&["notes"], None, [9; 32]);
    world.switch.fail_next(SwitchFault::Error {
        path: "/identity".into(),
        code: ErrorCode::BadRequest,
        current: serde_json::Value::Null,
    });
    let review = signer.review(&app.request, &app.auth).unwrap();
    signer.approve(review).await.unwrap_err();
    assert!(signer.certificates().unwrap().is_empty());
    // Approving the same request again holds one certificate for the App ID.
    let review = signer.review(&app.request, &app.auth).unwrap();
    signer.approve(review).await.unwrap();
    let id = app.keys.app_id_bytes();
    let held = signer.certificates().unwrap();
    assert_eq!(held.iter().filter(|c| c.app_id() == id).count(), 1);
}

#[tokio::test]
async fn test_approval_a_reopened_signer_releases_the_same_claim_bytes() {
    // The bytes `approve` returned are the bytes a reopened signer gives: signed once, never
    // again (the approval seals its bundle with fresh randomness, so a second signing would
    // differ).
    let world = World::new();
    let (mut signer, store) = world.enrolled().await;
    let app = App::new(&["notes"], None, [9; 32]);
    let review = signer.review(&app.request, &app.auth).unwrap();
    let request = review.request_hash();
    let before = signer.approve(review).await.unwrap();
    drop(signer);
    let mut reopened = pubky_switch_signer::Signer::open(world.env(store), world.keyring())
        .await
        .unwrap();
    reopened.resume().await.unwrap();
    let first = reopened.approved(&request).unwrap().unwrap();
    assert_eq!(first.claim, before.claim);
    ApprovalClaim::from_plaintext(&first.claim)
        .unwrap()
        .verify(&world.key.public(), &app.auth)
        .unwrap();
}

#[tokio::test]
async fn test_approval_clock_check_isnt_widened_by_a_slow_backup_read() {
    // The device clock is 5.5 minutes behind the switch, the tolerance 5. The copy check
    // reads `GET /apps`, then the signer backup, which takes 60 s here. The clock check
    // compares the switch's time with the device clock when that answer came, not after the
    // backup read: refused (Switch spec 10.1).
    use pubky_switch_client::clock::TestClock;
    use pubky_switch_core::records::SIGNER_BACKUP_PATH;
    use std::sync::Arc;
    let world = World::new();
    let (signer, store) = world.enrolled().await;
    drop(signer);
    let device = Arc::new(TestClock::new(START_MS - 330_000));
    let mut env = world.env(store);
    env.clock = device.clone();
    let mut signer = pubky_switch_signer::Signer::open(env, world.keyring())
        .await
        .unwrap();
    let switch_clock = Arc::clone(&world.clock);
    let device_clock = Arc::clone(&device);
    *world.homeserver.after_get.lock().unwrap() = Some((
        SIGNER_BACKUP_PATH.to_owned(),
        1,
        Box::new(move || {
            switch_clock.advance_ms(60_000);
            device_clock.advance_ms(60_000);
        }),
    ));
    let app = App::new(&["notes"], None, [9; 32]);
    let review = signer.review(&app.request, &app.auth).unwrap();
    let error = signer.approve(review).await.unwrap_err();
    assert!(
        matches!(error, SignerError::Refused(Refusal::ClockOff { .. })),
        "{error:?}"
    );
}
