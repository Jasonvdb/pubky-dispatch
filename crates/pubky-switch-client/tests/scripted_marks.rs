//! The scripted switch's mark and verdict (Switch wire 7.3, "Accounts and marks", Tables 1
//! to 3), through the real client: each test control puts the account and its mark out of
//! step, and the switch answers as Table 2 gives. And the one service key: an answer for
//! another account, path or method, which that key signs validly, is never taken by the
//! client for the request it sent (Switch wire 7.1).

// The helpers set up fixed test state, where a failure is a test failure.
#![allow(clippy::unwrap_used, clippy::panic)]

use std::sync::{Arc, Mutex};

use pubky_switch_client::clock::{Clock, TestClock};
use pubky_switch_client::testing::{
    ProtocolSpec, START_MS, SWITCH_ORIGIN, ScriptedSwitch, Seeds, TestHomeserver, TestIdentity,
    TestSigner,
};
use pubky_switch_client::transport::{BoxFuture, Request, Response, Transport};
use pubky_switch_client::{ClientError, Credentials, SwitchClient, TransportError};
use pubky_switch_core::chain::ZERO_HASH;
use pubky_switch_core::http::{ErrorCode, IdentityDelivery, NoticeReason, RecoveryNotice};
use pubky_switch_core::records::{Enrollment, EnrollmentBody, IdentityDoc, IdentityPolicy};
use serde_json::{Value, json};

/// Alice's signer, her account serving at its first `identity.json`.
fn alice() -> TestSigner {
    let signer = TestSigner::new(
        TestIdentity::new(&Seeds::default(), "alice"),
        Arc::new(TestClock::new(START_MS)),
        Arc::new(TestHomeserver::new()),
        ProtocolSpec::default(),
    );
    signer.next_doc(|_| {}).unwrap();
    signer
}

/// The signer's client of its account, the switch's key pinned, through `transport`, with
/// its own clock at `now_ms`.
fn client_at(signer: &TestSigner, transport: Arc<dyn Transport>, now_ms: u64) -> SwitchClient {
    let key = signer.identity().key();
    SwitchClient::new(
        SWITCH_ORIGIN,
        key.public(),
        Credentials::Signer {
            identity: key.public(),
            key: Arc::new(pubky_switch_core::keys::IdentityKey::from_secret(
                key.secret_bytes(),
            )),
        },
        Some(signer.switch().service_key()),
        transport,
        Arc::new(TestClock::new(now_ms)) as Arc<dyn Clock>,
    )
    .unwrap()
}

fn client(signer: &TestSigner) -> SwitchClient {
    client_at(signer, signer.switch().transport(), signer.clock().now_ms())
}

/// The notice an error carries, verified by the client.
fn notice(error: &ClientError) -> RecoveryNotice {
    match error {
        ClientError::Switch {
            status: 503,
            code: ErrorCode::RecoveryRequired,
            current,
            ..
        } => RecoveryNotice::from_current(current).unwrap(),
        other => panic!("no notice: {other:?}"),
    }
}

fn code(error: &ClientError) -> (u16, ErrorCode, Value) {
    match error {
        ClientError::Switch {
            status,
            code,
            current,
            ..
        } => (*status, *code, current.clone()),
        other => panic!("not a switch error: {other:?}"),
    }
}

fn behind(generation: u64, permanent: bool) -> RecoveryNotice {
    RecoveryNotice {
        generation,
        reason: NoticeReason::Behind,
        permanent,
    }
}

/// The signer's next `identity.json`, changed by `change`, not delivered.
fn next(
    signer: &TestSigner,
    change: impl FnOnce(&mut pubky_switch_core::records::IdentityBody),
) -> IdentityDoc {
    signer.sign_next(change).unwrap()
}

fn delivery(doc: &IdentityDoc, prev: Option<[u8; 32]>) -> IdentityDelivery {
    IdentityDelivery {
        identity: doc.signed().clone(),
        prev,
    }
}

/// The start of generation `generation`, `recovery_from` the one before, naming the switch.
fn start(signer: &TestSigner, generation: u64) -> IdentityDoc {
    next(signer, |body| {
        body.generation = generation;
        body.recovery_from = Some(generation - 1);
    })
}

fn enrollment(signer: &TestSigner, nonce: u8) -> Enrollment {
    let key = signer.identity().key();
    Enrollment::sign(
        key,
        EnrollmentBody {
            identity: key.public(),
            origin: SWITCH_ORIGIN.to_owned(),
            nonce: [nonce; 16],
            policy: IdentityPolicy::default(),
            identity_doc: None,
            revoked_apps: None,
        },
    )
    .unwrap()
}

#[tokio::test]
async fn test_marks_mark_follows_the_heads_given_out() {
    let alice = alice();
    let switch = alice.switch();
    let answer = client(&alice).apps().await.unwrap();
    let (generation, seq, chain_hash) = switch.mark().unwrap();
    assert_eq!((generation, seq), (1, switch.tip_seq()));
    assert_ne!(seq, 0);
    let _ = answer;
    alice.next_doc(|_| {}).unwrap();
    client(&alice).apps().await.unwrap();
    let (_, later, later_hash) = switch.mark().unwrap();
    assert_eq!(later, switch.tip_seq());
    assert!(later > seq && later_hash != chain_hash);
}

#[tokio::test]
async fn test_marks_restore_behind_the_mark_gets_the_notice() {
    let alice = alice();
    let switch = alice.switch();
    alice.next_doc(|_| {}).unwrap();
    let client = client(&alice);
    client.apps().await.unwrap();
    let marked = switch.mark().unwrap();
    switch.restore_to(1);
    // Every call gets it, the public read included, signed with the one key the client
    // pinned, with no head; the mark doesn't move.
    let error = client.apps().await.unwrap_err();
    assert_eq!(notice(&error), behind(1, false));
    let error = client.public_identity().await.unwrap_err();
    assert_eq!(notice(&error), behind(1, false));
    assert_eq!(switch.mark(), Some(marked));
}

#[tokio::test]
async fn test_marks_notice_replaces_a_stale_timestamp() {
    // The notice goes also to a request the switch would refuse before authentication
    // (Switch wire 7.3, below Table 2).
    let alice = alice();
    alice.next_doc(|_| {}).unwrap();
    client(&alice).apps().await.unwrap();
    alice.switch().restore_to(1);
    let late = client_at(
        &alice,
        alice.switch().transport(),
        START_MS + pubky_switch_core::records::CLOCK_TOLERANCE_MS + 60_000,
    );
    let error = late.apps().await.unwrap_err();
    assert_eq!(notice(&error), behind(1, false));
}

#[tokio::test]
async fn test_marks_fork_gets_the_notice() {
    let alice = alice();
    let client = client(&alice);
    client.apps().await.unwrap();
    alice.switch().fork_mark();
    let error = client.apps().await.unwrap_err();
    assert_eq!(notice(&error).reason, NoticeReason::Fork);
}

#[tokio::test]
async fn test_marks_lost_or_corrupt_mark_gets_the_notice() {
    for corrupt in [false, true] {
        let alice = alice();
        let client = client(&alice);
        client.apps().await.unwrap();
        if corrupt {
            alice.switch().corrupt_mark();
        } else {
            alice.switch().lose_mark();
        }
        let error = client.apps().await.unwrap_err();
        assert_eq!(
            notice(&error),
            RecoveryNotice {
                generation: 1,
                reason: NoticeReason::MarkLost,
                permanent: false,
            }
        );
        assert_eq!(alice.switch().mark(), None, "nothing writes it back");
    }
}

#[tokio::test]
async fn test_marks_unreadable_store_is_unavailable_and_moves_nothing() {
    let alice = alice();
    let switch = alice.switch();
    let client = client(&alice);
    client.apps().await.unwrap();
    let marked = switch.mark();
    switch.set_mark_store_unreadable(true);
    alice.next_doc(|_| {}).unwrap();
    let error = client.apps().await.unwrap_err();
    assert_eq!(code(&error).0, 503);
    assert_eq!(code(&error).1, ErrorCode::Unavailable);
    let error = client.enroll(&enrollment(&alice, 1)).await.unwrap_err();
    assert_eq!(code(&error).1, ErrorCode::Unavailable);
    assert_eq!(
        switch.mark(),
        marked,
        "no mark moved while the store can't be read"
    );
    switch.set_mark_store_unreadable(false);
    client.apps().await.unwrap();
    assert_ne!(switch.mark(), marked, "the mark moves again");
}

#[tokio::test]
async fn test_marks_retired_generation_is_permanent() {
    let alice = alice();
    let switch = alice.switch();
    alice.next_doc(|_| {}).unwrap();
    let client = client(&alice);
    client.apps().await.unwrap();
    switch.restore_to(1);
    assert!(!notice(&client.apps().await.unwrap_err()).permanent);
    switch.retire(1);
    assert_eq!(notice(&client.apps().await.unwrap_err()), behind(1, true));
}

#[tokio::test]
async fn test_marks_failing_account_takes_only_a_start_above_both() {
    let alice = alice();
    let switch = alice.switch();
    alice.next_doc(|_| {}).unwrap();
    let client = client(&alice);
    client.apps().await.unwrap();
    switch.restore_to(1);
    let held = switch.identity_doc().unwrap().hash();
    // A next version at the same generation, and a start without `recovery_from`: the
    // notice.
    let same = next(&alice, |_| {});
    let error = client
        .put_identity(&delivery(&same, Some(held)))
        .await
        .unwrap_err();
    assert_eq!(notice(&error), behind(1, false));
    let without = next(&alice, |body| body.generation = 2);
    let error = client
        .put_identity(&delivery(&without, Some(held)))
        .await
        .unwrap_err();
    assert_eq!(notice(&error), behind(1, false));
    // The start above both, with `recovery_from`: the account starts afresh at it, and the
    // mark moves to its first head.
    let recovery = start(&alice, 2);
    let answer = client
        .put_identity(&delivery(&recovery, Some(held)))
        .await
        .unwrap();
    assert_eq!(answer.head.generation, 2);
    assert_eq!(switch.generation(), 2);
    assert_eq!(switch.mark().map(|(g, _, _)| g), Some(2));
    client.apps().await.unwrap();
}

#[tokio::test]
async fn test_marks_lost_mark_takes_a_start_above_the_held_document() {
    // With the mark lost the switch can't tell which generation it last served: a start
    // above the held document's goes through, and writes the mark anew (Switch wire 7.3,
    // Table 3).
    let alice = alice();
    let switch = alice.switch();
    let client = client(&alice);
    switch.lose_mark();
    let held = switch.identity_doc().unwrap().hash();
    let recovery = start(&alice, 2);
    client
        .put_identity(&delivery(&recovery, Some(held)))
        .await
        .unwrap();
    let (generation, seq, _) = switch.mark().unwrap();
    assert_eq!((generation, seq), (2, switch.tip_seq()));
    client.apps().await.unwrap();
}

#[tokio::test]
async fn test_marks_lost_account_is_taken_over_by_an_enrollment() {
    let alice = alice();
    let switch = alice.switch();
    let client = client(&alice);
    client.apps().await.unwrap();
    let marked = switch.mark().unwrap();
    switch.lose_account();
    // No account, and a mark that records a head: the notice, at the mark's generation.
    assert_eq!(notice(&client.apps().await.unwrap_err()), behind(1, false));
    let held = alice.switch().identity_doc();
    assert!(held.is_none(), "nothing of the account is left");
    // The enrollment makes a staged account that takes the mark over, bounded by it.
    let answer = client.enroll(&enrollment(&alice, 7)).await.unwrap();
    assert_eq!(answer.service_key, switch.service_key(), "the one key");
    assert_eq!(switch.mark(), Some(marked));
    assert_eq!(notice(&client.apps().await.unwrap_err()), behind(1, false));
    // A first document at generation 1 doesn't start above the mark: the notice. The
    // start above it goes through.
    let first = next(&alice, |body| {
        body.generation = 1;
        body.recovery_from = None;
    });
    let error = client
        .put_identity(&delivery(&first, None))
        .await
        .unwrap_err();
    assert_eq!(notice(&error), behind(1, false));
    let recovery = start(&alice, 2);
    client
        .put_identity(&delivery(&recovery, None))
        .await
        .unwrap();
    assert_eq!(switch.mark().map(|(g, _, _)| g), Some(2));
    client.apps().await.unwrap();
}

#[tokio::test]
async fn test_marks_erasure_goes_through_at_a_failing_account() {
    let alice = alice();
    let switch = alice.switch();
    alice.next_doc(|_| {}).unwrap();
    let client = client(&alice);
    client.apps().await.unwrap();
    switch.restore_to(1);
    // Another document: `409 conflict`, carrying the copy the account holds.
    let error = client.erase(Some([9; 32])).await.unwrap_err();
    let (status, refusal, current) = code(&error);
    assert_eq!((status, refusal), (409, ErrorCode::Conflict));
    let held = switch.identity_doc().unwrap();
    assert_eq!(current, json!({ "identity": held.signed() }));
    client.erase(Some(held.hash())).await.unwrap();
    assert!(switch.erased());
    assert_eq!(switch.mark(), None);
    // Afterwards the identity isn't hosted: the `404`, signed with the one key.
    let error = client.apps().await.unwrap_err();
    assert_eq!(
        code(&error),
        (404, ErrorCode::NotFound, json!({ "hosted": false }))
    );
}

#[tokio::test]
async fn test_marks_erasure_names_the_held_document() {
    let alice = alice();
    let client = client(&alice);
    let held = alice.switch().identity_doc().unwrap();
    // Without a hash at an account that holds a document, and with another one: `409`,
    // with no copy at an account that doesn't answer the notice.
    for named in [None, Some([9; 32])] {
        let error = client.erase(named).await.unwrap_err();
        assert_eq!(code(&error), (409, ErrorCode::Conflict, Value::Null));
    }
    assert!(!alice.switch().erased());
    client.erase(Some(held.hash())).await.unwrap();
    assert!(alice.switch().erased());
}

#[tokio::test]
async fn test_marks_erasure_signed_before_the_account_existed_is_stale() {
    // An erasure whose timestamp is earlier than the creation time in the account's mark
    // is `401 stale_timestamp`, even within 5 minutes of the switch's time (Switch wire
    // 7.4.16); the client sends it once more at the time the refusal gives, and that one
    // goes through.
    struct Statuses {
        switch: Arc<ScriptedSwitch>,
        seen: Mutex<Vec<u16>>,
    }
    impl Transport for Statuses {
        fn send(&self, request: Request) -> BoxFuture<'_, Result<Response, TransportError>> {
            Box::pin(async move {
                let answer = self.switch.handle(&request)?;
                self.seen.lock().unwrap().push(answer.status);
                Ok(answer)
            })
        }
    }
    let alice = alice();
    let held = alice.switch().identity_doc().unwrap();
    let statuses = Arc::new(Statuses {
        switch: Arc::clone(alice.switch()),
        seen: Mutex::new(Vec::new()),
    });
    let early = client_at(
        &alice,
        Arc::clone(&statuses) as Arc<dyn Transport>,
        START_MS - 60_000,
    );
    early.erase(Some(held.hash())).await.unwrap();
    assert_eq!(*statuses.seen.lock().unwrap(), [401, 200]);
    assert!(alice.switch().erased());
}

#[tokio::test]
async fn test_marks_erasure_at_a_lost_identity_writes_the_record() {
    let alice = alice();
    let switch = alice.switch();
    let client = client(&alice);
    client.apps().await.unwrap();
    switch.lose_account();
    // Whatever hash it names: no document is held to compare.
    client.erase(Some([9; 32])).await.unwrap();
    assert!(switch.erasure_record().is_some());
    assert_eq!(switch.mark(), None);
    let error = client.apps().await.unwrap_err();
    assert_eq!(code(&error).2, json!({ "hosted": false }));
}

#[tokio::test]
async fn test_marks_enrollment_after_an_erasure_makes_a_new_account() {
    let alice = alice();
    let switch = alice.switch();
    let client = client(&alice);
    client
        .erase(Some(switch.identity_doc().unwrap().hash()))
        .await
        .unwrap();
    let answer = client.enroll(&enrollment(&alice, 3)).await.unwrap();
    assert_eq!(answer.service_key, switch.service_key(), "the one key");
    assert_eq!(switch.mark(), Some((0, 0, ZERO_HASH)));
    // Staged: everything but the delivery that makes it serve is `503 staged`.
    let error = client.apps().await.unwrap_err();
    assert_eq!(code(&error).1, ErrorCode::Staged);
}

/// A transport that changes each request before the switch at `target` answers it, so
/// the answer is the switch's, validly signed with its one key, for another request than
/// the one the client sent.
struct Rewrite {
    target: Arc<dyn Transport>,
    edit: Box<dyn Fn(&mut Request) + Send + Sync>,
}

impl Rewrite {
    fn new(
        target: Arc<dyn Transport>,
        edit: impl Fn(&mut Request) + Send + Sync + 'static,
    ) -> Arc<Self> {
        Arc::new(Self {
            target,
            edit: Box::new(edit),
        })
    }
}

impl Transport for Rewrite {
    fn send(&self, mut request: Request) -> BoxFuture<'_, Result<Response, TransportError>> {
        (self.edit)(&mut request);
        self.target.send(request)
    }
}

fn refused(result: Result<impl std::fmt::Debug, ClientError>) {
    match result {
        Err(ClientError::BadServiceSignature { .. }) => {}
        other => panic!("taken: {other:?}"),
    }
}

#[tokio::test]
async fn test_one_key_answer_for_another_path_is_refused() {
    let alice = alice();
    let transport = Rewrite::new(alice.switch().transport(), |request| {
        request.path_and_query = request.path_and_query.replace("/apps", "/handover");
    });
    refused(client_at(&alice, transport, START_MS).apps().await);
}

#[tokio::test]
async fn test_one_key_answer_for_another_method_is_refused() {
    let alice = alice();
    let transport = Rewrite::new(alice.switch().transport(), |request| {
        if request.method == "PUT" {
            request.method = "GET".into();
        }
    });
    let doc = next(&alice, |_| {});
    let prev = alice.switch().identity_doc().unwrap().hash();
    refused(
        client_at(&alice, transport, START_MS)
            .put_identity(&delivery(&doc, Some(prev)))
            .await,
    );
}

#[tokio::test]
async fn test_one_key_answer_about_another_account_is_refused() {
    // Bob's account at the same switch, under the same one key, answers the notice; alice's
    // request answered with bob's notice is refused, though the key signs it.
    let alice = alice();
    let bob = TestIdentity::new(&Seeds::default(), "bob");
    let bobs = ScriptedSwitch::new(
        bob.key(),
        alice.identity().service_secret(),
        Arc::clone(alice.clock()),
    );
    assert_eq!(bobs.service_key(), alice.switch().service_key());
    bobs.lose_mark();
    let (alice_id, bob_id) = (alice.identity().key().id(), bob.key().id());
    let transport = Rewrite::new(bobs.transport(), move |request| {
        request.path_and_query = request.path_and_query.replace(&alice_id, &bob_id);
    });
    refused(client_at(&alice, transport, START_MS).apps().await);
}

#[tokio::test]
async fn test_one_key_earlier_answer_replayed_is_refused() {
    // The answer to an earlier request for the same call, of the generation before a
    // recovery in place: the request signature binds it to its own request.
    let alice = alice();
    let kept: Arc<Mutex<Option<Response>>> = Arc::new(Mutex::new(None));
    struct Replay {
        switch: Arc<ScriptedSwitch>,
        kept: Arc<Mutex<Option<Response>>>,
    }
    impl Transport for Replay {
        fn send(&self, request: Request) -> BoxFuture<'_, Result<Response, TransportError>> {
            Box::pin(async move {
                if let Some(old) = self.kept.lock().unwrap().clone() {
                    return Ok(old);
                }
                let answer = self.switch.handle(&request)?;
                *self.kept.lock().unwrap() = Some(answer.clone());
                Ok(answer)
            })
        }
    }
    let signer = client(&alice);
    let client = SwitchClient::new(
        SWITCH_ORIGIN,
        signer.account(),
        signer.credentials().clone(),
        signer.pinned_key(),
        Arc::new(Replay {
            switch: Arc::clone(alice.switch()),
            kept: Arc::clone(&kept),
        }),
        Arc::clone(alice.clock()) as Arc<dyn Clock>,
    )
    .unwrap();
    client.apps().await.unwrap();
    // A second later, so the next request is signed anew.
    alice.clock().advance_ms(1_000);
    let held = alice.switch().identity_doc().unwrap().hash();
    let recovery = start(&alice, 2);
    alice
        .switch()
        .transport()
        .send(Request {
            method: "PUT".into(),
            origin: SWITCH_ORIGIN.into(),
            path_and_query: format!("/v1/{}/identity", alice.identity().key().id()),
            headers: Vec::new(),
            body: delivery(&recovery, Some(held)).to_json(),
        })
        .await
        .unwrap();
    assert_eq!(alice.switch().generation(), 2);
    assert!(kept.lock().unwrap().is_some());
    refused(client.apps().await);
}
