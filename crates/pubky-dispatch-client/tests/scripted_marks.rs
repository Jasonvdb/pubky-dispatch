//! The scripted Dispatch's mark and verdict (Dispatch wire 7.3, "Accounts and marks", Tables 1
//! to 3), through the real client: each test control puts the account and its mark out of
//! step, and the Dispatch answers as Table 2 gives. And the one service key: an answer for
//! another account, path or method, which that key signs validly, is never taken by the
//! client for the request it sent (Dispatch wire 7.1).

// The helpers set up fixed test state, where a failure is a test failure.
#![allow(clippy::unwrap_used, clippy::panic)]

use std::sync::{Arc, Mutex};

use pubky_dispatch_client::clock::{Clock, TestClock};
use pubky_dispatch_client::testing::{
    AppSpec, DISPATCH_ORIGIN, ProtocolSpec, START_MS, ScriptedDispatch, Seeds, TestHomeserver,
    TestIdentity, TestSigner, issue_cert,
};
use pubky_dispatch_client::transport::{BoxFuture, Request, Response, Transport};
use pubky_dispatch_client::{ClientError, Credentials, DispatchClient, TransportError};
use pubky_dispatch_core::chain::ZERO_HASH;
use pubky_dispatch_core::http::{ErrorCode, IdentityDelivery, NoticeReason, RecoveryNotice};
use pubky_dispatch_core::records::{
    Enrollment, EnrollmentBody, EnrollmentIntent, IdentityDoc, IdentityPolicy,
};
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

/// The signer's client of its account, the Dispatch's key pinned, through `transport`, with
/// its own clock at `now_ms`.
fn unbound_client_at(
    signer: &TestSigner,
    transport: Arc<dyn Transport>,
    now_ms: u64,
) -> DispatchClient {
    let key = signer.identity().key();
    DispatchClient::new(
        DISPATCH_ORIGIN,
        key.public(),
        Credentials::Signer {
            identity: key.public(),
            key: Arc::new(pubky_dispatch_core::keys::IdentityKey::from_secret(
                key.secret_bytes(),
            )),
        },
        Some(signer.dispatch().service_key()),
        transport,
        Arc::new(TestClock::new(now_ms)) as Arc<dyn Clock>,
    )
    .unwrap()
}

fn client_at(signer: &TestSigner, transport: Arc<dyn Transport>, now_ms: u64) -> DispatchClient {
    unbound_client_at(signer, transport, now_ms)
        .with_account_created(signer.dispatch().created())
        .unwrap()
}

fn bound_client(signer: &TestSigner, created: u64) -> DispatchClient {
    unbound_client_at(
        signer,
        signer.dispatch().transport(),
        signer.clock().now_ms(),
    )
    .with_account_created(created)
    .unwrap()
}

fn client(signer: &TestSigner) -> DispatchClient {
    client_at(
        signer,
        signer.dispatch().transport(),
        signer.clock().now_ms(),
    )
}

/// The notice an error carries, verified by the client.
fn notice(error: &ClientError) -> RecoveryNotice {
    match error {
        ClientError::Dispatch {
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
        ClientError::Dispatch {
            status,
            code,
            current,
            ..
        } => (*status, *code, current.clone()),
        other => panic!("not a Dispatch error: {other:?}"),
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
    change: impl FnOnce(&mut pubky_dispatch_core::records::IdentityBody),
) -> IdentityDoc {
    signer.sign_next(change).unwrap()
}

fn delivery(doc: &IdentityDoc, prev: Option<[u8; 32]>) -> IdentityDelivery {
    IdentityDelivery {
        identity: doc.signed().clone(),
        prev,
    }
}

/// The start of generation `generation`, `recovery_from` the one before, naming the Dispatch.
fn start(signer: &TestSigner, generation: u64) -> IdentityDoc {
    next(signer, |body| {
        body.generation = generation;
        body.recovery_from = Some(generation - 1);
    })
}

fn enrollment(signer: &TestSigner, nonce: u8, intent: EnrollmentIntent) -> Enrollment {
    let key = signer.identity().key();
    Enrollment::sign(
        key,
        EnrollmentBody {
            identity: key.public(),
            origin: DISPATCH_ORIGIN.to_owned(),
            nonce: [nonce; 16],
            intent,
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
    let dispatch = alice.dispatch();
    let answer = client(&alice).apps().await.unwrap();
    let (generation, seq, chain_hash) = dispatch.mark().unwrap();
    assert_eq!((generation, seq), (1, dispatch.tip_seq()));
    assert_ne!(seq, 0);
    let _ = answer;
    alice.next_doc(|_| {}).unwrap();
    client(&alice).apps().await.unwrap();
    let (_, later, later_hash) = dispatch.mark().unwrap();
    assert_eq!(later, dispatch.tip_seq());
    assert!(later > seq && later_hash != chain_hash);
}

#[tokio::test]
async fn test_marks_restore_behind_the_mark_gets_the_notice() {
    let alice = alice();
    let dispatch = alice.dispatch();
    alice.next_doc(|_| {}).unwrap();
    let client = client(&alice);
    client.apps().await.unwrap();
    let marked = dispatch.mark().unwrap();
    dispatch.restore_to(1);
    // Every call gets it, the public read included, signed with the one key the client
    // pinned, with no head; the mark doesn't move.
    let error = client.apps().await.unwrap_err();
    assert_eq!(notice(&error), behind(1, false));
    let error = client.public_identity().await.unwrap_err();
    assert_eq!(notice(&error), behind(1, false));
    assert_eq!(dispatch.mark(), Some(marked));
}

#[tokio::test]
async fn test_marks_restore_dropping_a_counted_write_gets_the_notice() {
    let alice = alice();
    let dispatch = alice.dispatch();
    let client = client(&alice);
    client.apps().await.unwrap();
    let marked = dispatch.mark().unwrap();
    // bob's shop appends: a `seq` past the head, with no chain item, which counts and which
    // the mark covers once it is acknowledged (Dispatch wire 7.3, "Moving it").
    let bob = TestIdentity::new(&Seeds::default(), "bob");
    let keys = bob.app_keys("shop");
    let cert = issue_cert(bob.key(), &keys, &AppSpec::new(&["tasks"]), START_MS).unwrap();
    let before = dispatch.seq();
    let count = dispatch.state_version();
    assert_eq!(dispatch.mark_state_version(), Some(count));
    let seq = dispatch.send_envelope(bob.public(), &cert, vec![1; 32], &[]);
    assert_eq!(seq, before + 1);
    assert_eq!(dispatch.mark(), Some(marked), "the head stays");
    assert_eq!(dispatch.mark_state_version(), Some(count + 1));
    client.apps().await.unwrap();
    // A restore of the state to before the append, its head as it was: behind, though the
    // head is the mark's, as the service's one rule judges it (Dispatch wire 7.3, Table 1).
    dispatch.restore_to(before);
    assert_eq!(dispatch.state_version(), count);
    let error = client.apps().await.unwrap_err();
    assert_eq!(notice(&error), behind(1, false));
    assert_eq!(
        dispatch.mark_state_version(),
        Some(count + 1),
        "the mark stays"
    );
}

#[tokio::test]
async fn test_marks_notice_replaces_a_stale_timestamp() {
    // The notice goes also to a request the Dispatch would refuse before authentication
    // (Dispatch wire 7.3, below Table 2).
    let alice = alice();
    alice.next_doc(|_| {}).unwrap();
    client(&alice).apps().await.unwrap();
    alice.dispatch().restore_to(1);
    let late = client_at(
        &alice,
        alice.dispatch().transport(),
        START_MS + pubky_dispatch_core::records::CLOCK_TOLERANCE_MS + 60_000,
    );
    let error = late.apps().await.unwrap_err();
    assert_eq!(notice(&error), behind(1, false));
}

#[tokio::test]
async fn test_marks_fork_gets_the_notice() {
    let alice = alice();
    let client = client(&alice);
    client.apps().await.unwrap();
    alice.dispatch().fork_mark();
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
            alice.dispatch().corrupt_mark();
        } else {
            alice.dispatch().lose_mark();
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
        assert_eq!(alice.dispatch().mark(), None, "nothing writes it back");
    }
}

#[tokio::test]
async fn test_marks_unreadable_store_is_unavailable_and_moves_nothing() {
    let alice = alice();
    let dispatch = alice.dispatch();
    let client = client(&alice);
    client.apps().await.unwrap();
    let marked = dispatch.mark();
    dispatch.set_mark_store_unreadable(true);
    alice.next_doc(|_| {}).unwrap();
    let error = client.apps().await.unwrap_err();
    assert_eq!(code(&error).0, 503);
    assert_eq!(code(&error).1, ErrorCode::Unavailable);
    let error = client
        .enroll(&enrollment(
            &alice,
            1,
            EnrollmentIntent::Existing {
                created: dispatch.created(),
            },
        ))
        .await
        .unwrap_err();
    assert_eq!(code(&error).1, ErrorCode::Unavailable);
    assert_eq!(
        dispatch.mark(),
        marked,
        "no mark moved while the store can't be read"
    );
    dispatch.set_mark_store_unreadable(false);
    client.apps().await.unwrap();
    assert_ne!(dispatch.mark(), marked, "the mark moves again");
}

#[tokio::test]
async fn test_marks_retired_generation_is_permanent() {
    let alice = alice();
    let dispatch = alice.dispatch();
    alice.next_doc(|_| {}).unwrap();
    let client = client(&alice);
    client.apps().await.unwrap();
    dispatch.restore_to(1);
    assert!(!notice(&client.apps().await.unwrap_err()).permanent);
    dispatch.retire(1);
    assert_eq!(notice(&client.apps().await.unwrap_err()), behind(1, true));
}

#[tokio::test]
async fn test_marks_failing_account_takes_only_a_start_above_both() {
    let alice = alice();
    let dispatch = alice.dispatch();
    alice.next_doc(|_| {}).unwrap();
    let client = client(&alice);
    client.apps().await.unwrap();
    dispatch.restore_to(1);
    let held = dispatch.identity_doc().unwrap().hash();
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
    assert_eq!(dispatch.generation(), 2);
    assert_eq!(dispatch.mark().map(|(g, _, _)| g), Some(2));
    client.apps().await.unwrap();
}

#[tokio::test]
async fn test_marks_lost_mark_takes_a_start_above_the_held_document() {
    // With the mark lost the Dispatch can't tell which generation it last served: a start
    // above the held document's goes through, and writes the mark anew (Dispatch wire 7.3,
    // Table 3).
    let alice = alice();
    let dispatch = alice.dispatch();
    let client = client(&alice);
    dispatch.lose_mark();
    let held = dispatch.identity_doc().unwrap().hash();
    let recovery = start(&alice, 2);
    client
        .put_identity(&delivery(&recovery, Some(held)))
        .await
        .unwrap();
    let (generation, seq, _) = dispatch.mark().unwrap();
    assert_eq!((generation, seq), (2, dispatch.tip_seq()));
    client.apps().await.unwrap();
}

#[tokio::test]
async fn test_marks_lost_account_is_taken_over_by_an_enrollment() {
    let alice = alice();
    let dispatch = alice.dispatch();
    let client = client(&alice);
    client.apps().await.unwrap();
    let marked = dispatch.mark().unwrap();
    assert!(dispatch.mark_state_version() > Some(0));
    dispatch.lose_account();
    // No account, and a mark that records a head: the notice, at the mark's generation.
    assert_eq!(notice(&client.apps().await.unwrap_err()), behind(1, false));
    let held = alice.dispatch().identity_doc();
    assert!(held.is_none(), "nothing of the account is left");
    // The enrollment makes a staged account that takes the mark over, bounded by it.
    alice.clock().advance_ms(1);
    let observation = client.observe_account().await.unwrap();
    let answer = client
        .enroll(&enrollment(
            &alice,
            7,
            EnrollmentIntent::Takeover {
                created: dispatch.created(),
                observation: observation.carried().clone(),
            },
        ))
        .await
        .unwrap();
    let client = bound_client(&alice, answer.created);
    assert_eq!(answer.service_key, dispatch.service_key(), "the one key");
    assert_eq!(dispatch.mark(), Some(marked));
    assert_eq!(
        dispatch.mark_state_version(),
        Some(0),
        "the new account's count"
    );
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
    assert_eq!(dispatch.mark().map(|(g, _, _)| g), Some(2));
    client.apps().await.unwrap();
}

/// The `current` of a `409` to an erasure: the creation time it was checked against, and
/// `identity` where the answer carries it (Dispatch wire 7.4.16).
fn checked(created: u64, identity: Option<Value>) -> Value {
    let mut current = json!({ "created": pubky_dispatch_core::time::rfc3339(created) });
    if let Some(identity) = identity {
        current["identity"] = identity;
    }
    current
}

#[tokio::test]
async fn test_marks_erasure_goes_through_at_a_failing_account() {
    let alice = alice();
    let dispatch = alice.dispatch();
    alice.next_doc(|_| {}).unwrap();
    let client = client(&alice);
    client.apps().await.unwrap();
    dispatch.restore_to(1);
    let created = dispatch.created();
    let held = dispatch.identity_doc().unwrap();
    // A different document carries the held copy; a creation conflict carries only the
    // current creation (Dispatch wire 7.4.16; Dispatch account binding 1).
    for (named_created, named) in [(created, [9; 32]), (created + 1, held.hash())] {
        let error = bound_client(&alice, named_created)
            .erase(Some(named_created), Some(named))
            .await
            .unwrap_err();
        assert_eq!(
            code(&error),
            (
                409,
                ErrorCode::Conflict,
                checked(
                    created,
                    (named_created == created).then(|| json!(held.signed()))
                )
            )
        );
    }
    client
        .erase(Some(created), Some(held.hash()))
        .await
        .unwrap();
    assert!(dispatch.erased());
    assert_eq!(dispatch.mark(), None);
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
    let created = alice.dispatch().created();
    let held = alice.dispatch().identity_doc().unwrap();
    // Without a hash at an account that holds a document, and with another one: `409`,
    // carrying only the creation time at an account that doesn't answer the notice.
    for named in [None, Some([9; 32])] {
        let error = client.erase(Some(created), named).await.unwrap_err();
        assert_eq!(
            code(&error),
            (409, ErrorCode::Conflict, checked(created, None))
        );
    }
    assert!(!alice.dispatch().erased());
    client
        .erase(Some(created), Some(held.hash()))
        .await
        .unwrap();
    assert!(alice.dispatch().erased());
}

#[tokio::test]
async fn test_marks_discovery_supplies_creation_for_authorized_erasure() {
    let alice = alice();
    let held = alice.dispatch().identity_doc().unwrap();
    let bootstrap = unbound_client_at(&alice, alice.dispatch().transport(), alice.clock().now_ms());
    let observation = bootstrap.observe_account().await.unwrap();
    let learned = observation.body().created.unwrap();
    assert_eq!(learned, alice.dispatch().created());
    assert!(!alice.dispatch().erased());
    let client = bootstrap.with_account_created(learned).unwrap();
    client
        .erase(Some(learned), Some(held.hash()))
        .await
        .unwrap();
    assert!(alice.dispatch().erased());
}

#[tokio::test]
async fn test_marks_erasure_replayed_at_a_later_account_is_conflict() {
    // An erasure followed by a distinct authorized enrollment at a later trusted time:
    // the new creation is after the erasure record and the erased creation, so
    // an erasure naming the first account's time, the first request again, is `409
    // conflict` carrying the new account's, and the new account and its mark stay; one
    // naming the new time erases it. Before the enrollment the same request is the
    // not-hosted `404` (Dispatch wire 7.3, The mark; 7.4.16).
    let alice = alice();
    let dispatch = alice.dispatch();
    let client = client(&alice);
    let first = dispatch.created();
    let held = dispatch.identity_doc().unwrap();
    client.erase(Some(first), Some(held.hash())).await.unwrap();
    assert_eq!(
        dispatch.erasure_record(),
        Some(alice.clock().now_ms().max(first))
    );
    let error = client.erase(Some(first), None).await.unwrap_err();
    assert_eq!(
        code(&error),
        (404, ErrorCode::NotFound, json!({ "hosted": false }))
    );
    alice.clock().advance_ms(1);
    let observation = client.observe_account().await.unwrap();
    let new_client = unbound_client_at(&alice, dispatch.transport(), alice.clock().now_ms());
    let answer = new_client
        .enroll(&enrollment(
            &alice,
            3,
            EnrollmentIntent::Create {
                observation: observation.carried().clone(),
            },
        ))
        .await
        .unwrap();
    let client = bound_client(&alice, answer.created);
    let later = dispatch.created();
    assert_eq!(answer.created, later);
    assert_eq!(
        later,
        dispatch.erasure_record().unwrap() + 1,
        "the trusted clock is one millisecond past erasure"
    );
    let error = bound_client(&alice, first)
        .erase(Some(first), None)
        .await
        .unwrap_err();
    assert_eq!(
        code(&error),
        (409, ErrorCode::Conflict, checked(later, None))
    );
    assert_eq!(dispatch.mark(), Some((0, 0, ZERO_HASH)));
    assert!(!dispatch.erased());
    client.erase(Some(later), None).await.unwrap();
    assert!(dispatch.erased());
}

#[tokio::test]
async fn test_marks_enrollment_taking_a_mark_over_is_created_later() {
    // An explicitly authorized takeover uses trusted time after the marked creation;
    // successive accounts never share a creation (Dispatch account binding 3).
    let alice = alice();
    let dispatch = alice.dispatch();
    let client = client(&alice);
    let mut earlier = dispatch.created();
    for nonce in [3, 4] {
        dispatch.lose_account();
        alice.clock().advance_ms(1);
        let observation = client.observe_account().await.unwrap();
        let answer = bound_client(&alice, earlier)
            .enroll(&enrollment(
                &alice,
                nonce,
                EnrollmentIntent::Takeover {
                    created: earlier,
                    observation: observation.carried().clone(),
                },
            ))
            .await
            .unwrap();
        assert_eq!(answer.created, earlier + 1);
        assert_eq!(dispatch.created(), answer.created);
        earlier = answer.created;
    }
}

#[tokio::test]
async fn test_marks_erasure_at_a_lost_identity_writes_the_record() {
    let alice = alice();
    let dispatch = alice.dispatch();
    let client = client(&alice);
    client.apps().await.unwrap();
    let created = dispatch.created();
    dispatch.lose_account();
    // Another creation time: `409 conflict`, carrying the mark's and `identity` `null`,
    // nothing written (Dispatch wire 7.4.16).
    let error = bound_client(&alice, created + 1)
        .erase(Some(created + 1), None)
        .await
        .unwrap_err();
    assert_eq!(
        code(&error),
        (409, ErrorCode::Conflict, checked(created, None))
    );
    assert_eq!(dispatch.erasure_record(), None);
    assert!(dispatch.mark().is_some());
    // The mark's creation time, whatever hash it names: no document is held to compare.
    client.erase(Some(created), Some([9; 32])).await.unwrap();
    assert!(dispatch.erasure_record().is_some());
    assert_eq!(dispatch.mark(), None);
    let error = client.apps().await.unwrap_err();
    assert_eq!(code(&error).2, json!({ "hosted": false }));
}

#[tokio::test]
async fn test_marks_enrollment_after_an_erasure_makes_a_new_account() {
    let alice = alice();
    let dispatch = alice.dispatch();
    let client = client(&alice);
    client
        .erase(
            Some(dispatch.created()),
            Some(dispatch.identity_doc().unwrap().hash()),
        )
        .await
        .unwrap();
    alice.clock().advance_ms(1);
    let observation = client.observe_account().await.unwrap();
    let new_client = unbound_client_at(&alice, dispatch.transport(), alice.clock().now_ms());
    let answer = new_client
        .enroll(&enrollment(
            &alice,
            3,
            EnrollmentIntent::Create {
                observation: observation.carried().clone(),
            },
        ))
        .await
        .unwrap();
    let client = bound_client(&alice, answer.created);
    assert_eq!(answer.service_key, dispatch.service_key(), "the one key");
    assert_eq!(dispatch.mark(), Some((0, 0, ZERO_HASH)));
    // Staged: everything but the delivery that makes it serve is `503 staged`.
    let error = client.apps().await.unwrap_err();
    assert_eq!(code(&error).1, ErrorCode::Staged);
}

#[tokio::test]
async fn test_marks_staged_import_refuses_erasure_while_abort_is_allowed() {
    for change in [
        ScriptedDispatch::lose_mark,
        ScriptedDispatch::corrupt_mark,
        ScriptedDispatch::fork_mark,
        |dispatch: &ScriptedDispatch| dispatch.retire(1),
    ] {
        let alice = alice();
        let staged = alice.dispatch().import_into([45; 32]);
        let client = client_at(&alice, staged.transport(), alice.clock().now_ms());
        client.pin(staged.service_key());
        let created = staged.created();
        let held = staged.identity_doc().unwrap();
        for failed in [false, true] {
            if failed {
                change(&staged);
            }
            let mark = staged.mark();
            let refused = client
                .erase(Some(created), Some(held.hash()))
                .await
                .unwrap_err();
            assert_eq!(code(&refused).1, ErrorCode::Conflict);
            assert_eq!(code(&refused).2, checked(created, None));
            assert!(!staged.erased());
            assert_eq!(staged.identity_doc().unwrap().hash(), held.hash());
            assert_eq!(staged.mark(), mark);
            assert_eq!(staged.erasure_record(), None);
            staged.set_mark_store_unreadable(true);
            let unavailable = client
                .erase(Some(created), Some(held.hash()))
                .await
                .unwrap_err();
            assert_eq!(code(&unavailable).1, ErrorCode::Unavailable);
            assert!(!staged.erased());
            assert_eq!(staged.mark(), mark);
            assert_eq!(staged.erasure_record(), None);
            staged.set_mark_store_unreadable(false);
        }
    }
}

/// A transport that changes each request before the Dispatch at `target` answers it, so
/// the answer is the Dispatch's, validly signed with its one key, for another request than
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
    let transport = Rewrite::new(alice.dispatch().transport(), |request| {
        request.path_and_query = request.path_and_query.replace("/apps", "/handover");
    });
    refused(client_at(&alice, transport, START_MS).apps().await);
}

#[tokio::test]
async fn test_one_key_answer_for_another_method_is_refused() {
    let alice = alice();
    let transport = Rewrite::new(alice.dispatch().transport(), |request| {
        if request.method == "PUT" {
            request.method = "GET".into();
        }
    });
    let doc = next(&alice, |_| {});
    let prev = alice.dispatch().identity_doc().unwrap().hash();
    refused(
        client_at(&alice, transport, START_MS)
            .put_identity(&delivery(&doc, Some(prev)))
            .await,
    );
}

#[tokio::test]
async fn test_one_key_answer_about_another_account_is_refused() {
    // Bob's account at the same Dispatch, under the same one key, answers the notice; alice's
    // request answered with bob's notice is refused, though the key signs it.
    let alice = alice();
    let bob = TestIdentity::new(&Seeds::default(), "bob");
    let bobs = ScriptedDispatch::new(
        bob.key(),
        alice.identity().service_secret(),
        Arc::clone(alice.clock()),
    );
    assert_eq!(bobs.service_key(), alice.dispatch().service_key());
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
        dispatch: Arc<ScriptedDispatch>,
        kept: Arc<Mutex<Option<Response>>>,
    }
    impl Transport for Replay {
        fn send(&self, request: Request) -> BoxFuture<'_, Result<Response, TransportError>> {
            Box::pin(async move {
                if let Some(old) = self.kept.lock().unwrap().clone() {
                    return Ok(old);
                }
                let answer = self.dispatch.handle(&request)?;
                *self.kept.lock().unwrap() = Some(answer.clone());
                Ok(answer)
            })
        }
    }
    let signer = client(&alice);
    let client = DispatchClient::new(
        DISPATCH_ORIGIN,
        signer.account(),
        signer.credentials().clone(),
        signer.pinned_key(),
        Arc::new(Replay {
            dispatch: Arc::clone(alice.dispatch()),
            kept: Arc::clone(&kept),
        }),
        Arc::clone(alice.clock()) as Arc<dyn Clock>,
    )
    .unwrap()
    .with_account_created(alice.dispatch().created())
    .unwrap();
    client.apps().await.unwrap();
    // A second later, so the next request is signed anew.
    alice.clock().advance_ms(1_000);
    let held = alice.dispatch().identity_doc().unwrap().hash();
    let recovery = start(&alice, 2);
    signer
        .put_identity(&delivery(&recovery, Some(held)))
        .await
        .unwrap();
    assert_eq!(alice.dispatch().generation(), 2);
    assert!(kept.lock().unwrap().is_some());
    refused(client.apps().await);
}

#[tokio::test]
async fn test_scripted_erasure_pending_retry_checks_signature_creation_and_document() {
    use pubky_dispatch_client::testing::ErasureOutcome;
    for outcome in [ErasureOutcome::Unresolved, ErasureOutcome::UnresolvedAbsent] {
        let signer = alice();
        let dispatch = signer.dispatch();
        let client = client(&signer);
        let created = dispatch.created();
        let hash = dispatch.identity_doc().unwrap().hash();
        dispatch.fail_next_erasure(outcome);
        assert_eq!(
            code(&client.erase(Some(created), Some(hash)).await.unwrap_err()).1,
            ErrorCode::Unavailable
        );
        for (created, hash) in [(created + 1, hash), (created, [9; 32])] {
            assert_eq!(
                code(
                    &bound_client(&signer, created)
                        .erase(Some(created), Some(hash))
                        .await
                        .unwrap_err()
                )
                .1,
                ErrorCode::Conflict
            );
        }
        let bad = Request {
            method: "POST".into(),
            origin: DISPATCH_ORIGIN.into(),
            path_and_query: format!("/v1/{}/erase", signer.identity().key().id()),
            headers: vec![
                pubky_dispatch_client::transport::Header::new(
                    pubky_dispatch_core::http::header::IDENTITY,
                    &signer.identity().key().id(),
                ),
                pubky_dispatch_client::transport::Header::new(
                    pubky_dispatch_core::http::header::TIMESTAMP,
                    &pubky_dispatch_core::time::rfc3339_seconds(signer.clock().now_ms()),
                ),
                pubky_dispatch_client::transport::Header::new(
                    pubky_dispatch_core::http::header::CREATED,
                    &pubky_dispatch_core::time::rfc3339(created),
                ),
                pubky_dispatch_client::transport::Header::new(
                    pubky_dispatch_core::http::header::SIGNATURE,
                    &pubky_dispatch_core::enc::b64(&[0; 64]),
                ),
            ],
            body: pubky_dispatch_core::http::erase_body(Some(created), Some(&hash)),
            timeout: pubky_dispatch_client::transport::TimeoutClass::Bulk,
        };
        let answer = dispatch.handle(&bad).unwrap();
        // The unresolved outcome has Table 2 precedence over failed authentication.
        assert_eq!(answer.status, 503);
        assert_eq!(
            serde_json::from_slice::<Value>(&answer.body).unwrap()["code"],
            "unavailable"
        );
        assert_eq!(
            code(&client.apps().await.unwrap_err()).1,
            ErrorCode::Unavailable
        );
        client.erase(Some(created), Some(hash)).await.unwrap();
        assert!(client.apps().await.unwrap_err().is_not_hosted());
    }
}
