//! Peer reasons in operations, transition proofs, signed list answers and export parts
//! (Switch wire 6.2, 6.5, 7.4.6, 10.3).

use ed25519_dalek::SigningKey;
use pubky_switch_core::admission::{PeerEntry, ReplyGrant, ReplyOrigin};
use pubky_switch_core::chain::{
    ChainTip, ItemType, ProofBody, ProofState, ServiceTransition, SignedHead, Stub,
    TransitionProof, item_hash,
};
use pubky_switch_core::enc;
use pubky_switch_core::export::Part;
use pubky_switch_core::http;
use pubky_switch_core::ops::{OpKind, SignedOp};
use pubky_switch_core::sig::SignedDoc;
use pubky_switch_core::time::parse_rfc3339;
use serde_json::Value;

use crate::common::*;

#[test]
fn test_peer_admission_chain_and_proofs() {
    let file = load("chain.json");
    let case = &file["peer_admission"];
    let keys = keys();
    let wallet = keys.app("wallet");
    let alice = wallet.identity;
    let app_id = enc::app_id_decode(&wallet.app_id).unwrap();
    let writer = SigningKey::from_bytes(&wallet.signing_secret);
    let public = keys.service_key(&enc::pubky_id(&alice));
    let service = SigningKey::from_bytes(&keys.secret(&public).unwrap());
    let mut head = arr(&file, "signed_heads")
        .iter()
        .map(|h| SignedHead::from_value(&h["head"]).unwrap())
        .find(|h| h.seq == 9)
        .unwrap();
    head.verify(&public, &alice).unwrap();

    let items = arr(case, "items");
    let seqs = [10, 11, 12, 14, 17, 18, 19, 20];
    assert_eq!(items.len(), seqs.len());
    for (row, seq) in items.iter().zip(seqs) {
        let stub = Stub::from_value(&row["stub"]).unwrap();
        let env = stub.open().unwrap();
        assert_eq!(env.seq, seq);
        assert_eq!(env.prev_chain_hash, head.chain_hash);
        assert_eq!(Stub::of(&env), stub);
        let doc: SignedDoc = serde_json::from_value(row["item"].clone()).unwrap();
        assert_eq!(
            item_hash(env.item_type, &doc.doc_bytes().unwrap()),
            env.item_hash
        );
        if env.item_type == ItemType::Service {
            let transition = ServiceTransition::verify(&doc, &public, &alice).unwrap();
            assert_eq!(transition.sign(&service, &alice).unwrap(), doc);
            let ServiceTransition::ReplyAdd {
                pubky,
                code_hash,
                at,
            } = transition
            else {
                panic!("an invitation grants reply");
            };
            assert_eq!(pubky, keys.identity("bob"));
            assert_eq!(code_hash, first_invite());
            assert_eq!(at, env.server_time);
        } else {
            let op = SignedOp::verify(&doc, &wallet.signing_public, &alice, Some(&app_id)).unwrap();
            assert_eq!(
                SignedOp::sign(&writer, op.body().clone()).unwrap().signed(),
                &doc
            );
            let (object, state) = match &op.body().kind {
                OpKind::InviteCodePut(put) => (
                    enc::b64(&put.code_hash),
                    ProofState::InviteCodePut {
                        max_uses: put.max_uses,
                    },
                ),
                OpKind::AllowPut { pubky, reason } => (
                    enc::pubky_id(pubky),
                    ProofState::Allow {
                        reason: *reason,
                        present: true,
                    },
                ),
                OpKind::AllowDelete { pubky, reason } => (
                    enc::pubky_id(pubky),
                    ProofState::Allow {
                        reason: *reason,
                        present: false,
                    },
                ),
                _ => panic!("an invitation or peer reason"),
            };
            let actual: SignedDoc = serde_json::from_value(row["proof"].clone()).unwrap();
            let proof = TransitionProof::sign(
                &service,
                &alice,
                ProofBody::new(stub.clone(), object, &state),
            )
            .unwrap();
            assert_eq!(proof.signed(), &actual);
        }
        head = SignedHead::sign(
            &service,
            &alice,
            &ChainTip {
                generation: env.generation,
                seq,
                chain_hash: stub.chain_hash,
            },
        );
    }
    assert_eq!(head, SignedHead::from_value(&case["head"]).unwrap());
}

fn first_invite() -> [u8; 32] {
    b64n(st(&load("identifiers.json")["invite_code"], "code_hash"))
}

#[test]
fn test_peer_admission_list_and_export() {
    let keys = keys();
    let wallet = keys.app("wallet");
    let public = keys.service_key(&enc::pubky_id(&wallet.identity));
    let file = load("http.json");
    let answer = arr(&file, "responses")
        .iter()
        .find(|r| r["name"] == "own app: peer admission after the wallet changes kept peers")
        .unwrap();
    let request = crate::http::answered(&keys, &file, answer);
    http::verify_response(
        &public,
        &crate::http::parts_of(answer, &request),
        &b64n::<64>(st(answer, "signature")),
    )
    .unwrap();
    let head = SignedHead::from_header(st(&answer["headers"], http::header::HEAD)).unwrap();
    assert_eq!(
        head.to_value(),
        load("chain.json")["peer_admission"]["head"]
    );

    let export = load("export.json");
    let parts = &export["peer_admission"];
    let raw = st(parts, "entry");
    let part = Part::read(&serde_json::from_str(raw).unwrap()).unwrap();
    assert_eq!(part.to_json().unwrap(), raw.as_bytes());
    let Part::Entry(pending) = part else {
        panic!("a pending inbox entry");
    };
    assert_eq!(pending.seq, 15);
    assert_eq!(pending.sender, keys.identity("bob"));
    assert_eq!(
        pending.invite_code_hash,
        Some(enc::hash(&seed("invitations/second-code")[..16]))
    );

    let body: Value = serde_json::from_str(st(answer, "body")).unwrap();
    let rows = arr(&body, "peers");
    let exported = strings(&parts["admission"]);
    assert_eq!((rows.len(), exported.len()), (3, 3));
    assert!(
        rows.windows(2)
            .all(|p| st(&p[0], "pubky") < st(&p[1], "pubky"))
    );
    let mut origins = (0, 0, 0);
    for (row, raw) in rows.iter().zip(exported) {
        let peer = PeerEntry::from_value(row).unwrap();
        let part = Part::read(&serde_json::from_str(&raw).unwrap()).unwrap();
        assert_eq!(part, Part::Admission(peer));
        assert_eq!(part.to_json().unwrap(), raw.as_bytes());
        match peer.reply {
            Some(ReplyGrant {
                origin: ReplyOrigin::Invite(hash),
                at,
                last_used,
            }) => {
                assert!(peer.kept);
                assert_eq!(peer.pubky, pending.sender);
                assert_eq!(hash, first_invite());
                assert_ne!(Some(hash), pending.invite_code_hash);
                assert!(at < pending.accepted_at_ms);
                assert_eq!(
                    last_used,
                    Some(parse_rfc3339("2026-01-01T00:05:00.150Z").unwrap())
                );
                origins.0 += 1;
            }
            Some(ReplyGrant {
                origin: ReplyOrigin::App(app),
                last_used,
                ..
            }) => {
                assert!(!peer.kept);
                assert_eq!(app, enc::app_id_decode(&wallet.app_id).unwrap());
                assert_eq!(last_used, None);
                origins.1 += 1;
            }
            None => {
                assert!(peer.kept);
                origins.2 += 1;
            }
        }
    }
    assert_eq!(origins, (1, 1, 1));
}
