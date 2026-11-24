//! `export.json`: a complete export of alice's account (Switch wire 10.2, 10.3), its
//! manifest signed with the fixed service key, which activates under Switch wire 10.5 at a
//! next service enrolled with her version 3 at the freeze's time, and the record and claim
//! parts a faulty old service could send instead, each refused at the activation.
//!
//! The chunk is read part by part and every part written again, byte for byte; the parts are
//! packed again into the chunk, the manifest rebuilt over it and signed again with the fixed
//! key. What the export shares with `chain.json`, `documents.json` and `http.json` is
//! compared with those files.

use std::collections::{BTreeMap, HashMap, HashSet};

use super::chain::{Chain, Item, first_claim};
use ed25519_dalek::SigningKey;
use pubky_switch_core::admission::{PeerEntry, PeerReason, ReplyGrant, ReplyOrigin};
use pubky_switch_core::chain::{ChainTip, ProofBody, SignedHead, TransitionProof};
use pubky_switch_core::chain::{ItemType, ProofState, ServiceTransition};
use pubky_switch_core::claims::Outcome;
use pubky_switch_core::claims::{Claim, ClaimType};
use pubky_switch_core::enc::{app_id_decode, b64 as b64e, hash};
use pubky_switch_core::export::{
    Activation, Chunk, ChunkAnswer, DEFAULT_CHUNK_TARGET, ExportCaller, ExportRead, Import,
    MAX_IMPORT_BYTES, Manifest, ManifestBody, Part, UploadedHead, UploadedProof, Uploads, activate,
    pack,
};
use pubky_switch_core::export::{
    AppPart, AttemptState, BatchPart, ChainPart, ClaimEntryPart, ClaimPart, ClaimState, EntryPart,
    EntryResult, MetaPart, RecordEntry,
};
use pubky_switch_core::http::ErrorCode;
use pubky_switch_core::labels;
use pubky_switch_core::ops::Refusal;
use pubky_switch_core::ops::{BatchRef, OpKind, ops_hash};
use pubky_switch_core::records::ExportTransferBody;
use pubky_switch_core::records::{
    AppRecord, CLOCK_TOLERANCE_MS, ExportTransfer, Freeze, IdentityDoc,
};
use pubky_switch_core::sig::SignedDoc;
use pubky_switch_core::{enc, envelope, message};
use serde_json::{Value, json};

use crate::common::*;

/// What the activation of the vector's export compares with.
struct Fixture {
    alice: [u8; 32],
    o_key: [u8; 32],
    o_secret: SigningKey,
    manifest: Manifest,
    chunk: Vec<u8>,
    parts: Vec<Part>,
    freeze: Freeze,
    enrolled: IdentityDoc,
}

impl Fixture {
    fn load() -> Self {
        let keys = keys();
        let v = load("export.json");
        let alice = keys.identity("alice");
        let o_key = keys.service_key(&enc::pubky_id(&alice));
        assert_eq!(st(&v, "service_key"), b64e(&o_key));
        let signed: SignedDoc = serde_json::from_value(v["manifest"]["signed"].clone()).unwrap();
        let manifest = Manifest::verify(&signed, &o_key, &alice).unwrap();
        let chunk = st(&v["chunks"][0], "json").as_bytes().to_vec();
        let parts = manifest.read_parts(&[&chunk]).unwrap();
        Self {
            alice,
            o_key,
            o_secret: SigningKey::from_bytes(&keys.secret(&o_key).unwrap()),
            manifest,
            chunk,
            parts,
            freeze: Freeze::verify(&document("alice freeze"), &alice).unwrap(),
            enrolled: IdentityDoc::verify(&document("alice identity.json"), &alice).unwrap(),
        }
    }

    fn run(
        &self,
        manifest: &Manifest,
        parts: &[Part],
        uploads: &Uploads,
        now: u64,
    ) -> Result<Import, Refusal> {
        activate(
            &Activation {
                manifest,
                freeze: &self.freeze,
                enrolled: &self.enrolled,
                now: Some(now),
                uploads,
                revoked_apps: &[],
            },
            parts,
        )
    }

    /// The activation of `parts` under the vector's manifest, its part count changed to
    /// theirs and signed again with the fixed key.
    fn run_parts(&self, parts: &[Part]) -> Result<Import, Refusal> {
        let manifest = self.resign(|b| b.parts = parts.len() as u64);
        self.run(&manifest, parts, &Uploads::default(), self.now())
    }

    fn now(&self) -> u64 {
        self.manifest.body().last_time
    }

    /// The vector's manifest, changed and signed again with the fixed key.
    fn resign(&self, change: impl FnOnce(&mut ManifestBody)) -> Manifest {
        let mut body = self.manifest.body().clone();
        change(&mut body);
        Manifest::sign(&self.o_secret, body).unwrap()
    }

    fn index(&self, kind: &str) -> usize {
        self.parts.iter().position(|p| p.kind() == kind).unwrap()
    }
}

fn refused(result: Result<Import, Refusal>, code: ErrorCode, rule: &str) {
    let error = result.expect_err(rule);
    assert_eq!(error.code, code, "{rule}: {error}");
    assert!(error.reason.contains(rule), "{rule}: {error}");
}

#[test]
pub(super) fn test_vectors_export() {
    let keys = keys();
    let docs = super::documents::issue_documents();
    let chain = super::chain::chain_cases(&keys, &docs);
    export_cases(&keys, &docs, &chain);
    let f = Fixture::load();
    check_manifest(&f);
    check_parts_byte_for_byte(&f);
    let import = check_activation(&f, &chain);
    check_record_rejections(&f);
    check_claim_rejections(&f);
    check_activation_rules(&f, &chain);
    check_uploads(&f);
    check_chain_cross(&f, &import, &chain);
    check_documents_cross(&f);
    check_http_cross(&f);
}

/// The manifest (Switch wire 10.2): a signed document under the fixed service key, its
/// signature reproduced, bound to documents.json's freeze, its chunk list well formed.
fn check_manifest(f: &Fixture) {
    let keys = keys();
    let m = &load("export.json")["manifest"];
    assert_eq!(st(m, "label"), labels::sig::EXPORT_MANIFEST);
    let signed = f.manifest.signed();
    assert_eq!(signed.body_bytes().unwrap(), st(m, "body").as_bytes());
    assert_eq!(signed.compact(), st(m, "compact"));
    assert_eq!(
        hex::encode(signed.doc_bytes().unwrap()),
        st(m, "doc_bytes_hex")
    );
    assert_eq!(
        b64e(&f.manifest.hash()),
        st(m, "doc_hash"),
        "the manifest hash"
    );
    assert!(reproduce(
        &keys,
        &f.o_key,
        labels::sig::EXPORT_MANIFEST,
        &[&f.alice, st(m, "body").as_bytes()],
        &signed.sig_bytes().unwrap(),
    ));
    assert_eq!(
        f.o_key,
        keys.service_key(&pubky_switch_core::enc::pubky_id(&f.alice))
    );
    // Only the old service's key verifies it, for alice only.
    let bob = keys.identity("bob");
    assert!(matches!(
        Manifest::verify(
            signed,
            &keys.service_key(&pubky_switch_core::enc::pubky_id(&bob)),
            &f.alice
        ),
        Err(pubky_switch_core::Error::Signature(_))
    ));
    assert!(Manifest::verify(signed, &f.o_key, &bob).is_err());
    // Bound to the move, its chunk list well formed (Switch wire 10.4 steps 5 and 6).
    f.manifest
        .check_binding(&f.alice, &f.freeze, &f.enrolled)
        .unwrap();
    f.manifest.check_chunks(MAX_IMPORT_BYTES).unwrap();
    let body = f.manifest.body();
    assert_eq!(body.chunks.len(), 1);
    assert_eq!(body.chunks[0].id, "00000");
    assert!(
        body.checkpoint.is_none(),
        "the chain parts start at 32 zero bytes"
    );
    let more = f.resign(|b| b.bytes += 1);
    assert_eq!(
        more.check_chunks(MAX_IMPORT_BYTES).unwrap_err().status(),
        400
    );
    assert_eq!(more.check_chunks(0).unwrap_err().status(), 400);
    assert_eq!(f.manifest.check_chunks(1000).unwrap_err().status(), 413);
    let skipped = f.resign(|b| b.next_generation = 3);
    assert_eq!(
        skipped
            .check_binding(&f.alice, &f.freeze, &f.enrolled)
            .unwrap_err()
            .status(),
        400
    );
    // The chunk: its length and hash are the manifest's (Switch wire 10.4).
    let c = &load("export.json")["chunks"][0];
    assert_eq!(f.chunk.len() as u64, int(c, "len"));
    assert_eq!(b64e(&hash(&f.chunk)), st(c, "hash"));
    f.manifest.check_chunk("00000", &f.chunk).unwrap();
    let mut tampered = f.chunk.clone();
    tampered[20] ^= 1;
    let error = f.manifest.check_chunk("00000", &tampered).unwrap_err();
    assert_eq!(error.status(), 409);
    assert_eq!(error.current.unwrap()["chunk"]["id"], "00000");
    assert_eq!(
        f.manifest.check_chunk("00001", b"{}").unwrap_err().status(),
        404
    );
    assert_eq!(f.manifest.missing(|id| id == "00000"), Vec::<String>::new());
    assert_eq!(f.manifest.missing(|_| false), ["00000"]);
}

/// Every part written again, byte for byte; the parts packed again into the chunk; and the
/// manifest rebuilt over it and signed again with the fixed key (Switch wire 10.2, 10.3).
fn check_parts_byte_for_byte(f: &Fixture) {
    let value: Value = serde_json::from_slice(&f.chunk).unwrap();
    let raw = arr(&value, "parts");
    assert_eq!(raw.len(), f.parts.len());
    assert_eq!(f.parts.len(), 19);
    let mut written = Vec::new();
    for (part, raw) in f.parts.iter().zip(raw) {
        assert_eq!(part.kind(), st(raw, "part"));
        let bytes = part.to_json().unwrap();
        assert_eq!(
            serde_json::from_slice::<Value>(&bytes).unwrap(),
            *raw,
            "{}",
            part.kind()
        );
        assert_eq!(Part::read(raw).unwrap(), *part, "{}", part.kind());
        written.push(bytes);
    }
    // The claim entry's `cert` is always written: `null` here, since the wallet's app part
    // carries the certificate; a part without it doesn't read (Switch wire 10.3).
    let ci = f.index("claim_entry");
    assert!(matches!(&f.parts[ci], Part::ClaimEntry(e) if e.cert.is_none()));
    assert!(raw[ci]["cert"].is_null());
    let mut without = raw[ci].clone();
    without.as_object_mut().unwrap().remove("cert");
    assert_eq!(Part::read(&without).unwrap_err().status(), 400);
    let chunk = Chunk::parse(&f.chunk).unwrap();
    assert_eq!((chunk.index, chunk.first), (0, 0));
    assert_eq!(
        chunk.to_json().unwrap(),
        f.chunk,
        "the chunk, byte for byte"
    );
    let packed = pack(&f.parts, DEFAULT_CHUNK_TARGET).unwrap();
    assert_eq!(packed.len(), 1);
    assert_eq!(packed[0].1, f.chunk);
    assert_eq!(packed[0].0, f.manifest.body().chunks[0]);
    let m = f.manifest.body();
    let body = ManifestBody::new(
        m.identity,
        m.freeze_hash,
        m.generation,
        m.last_time,
        m.head,
        m.checkpoint,
        packed.into_iter().map(|(r, _)| r).collect(),
    )
    .unwrap();
    assert_eq!(&body, m);
    let signed = Manifest::sign(&f.o_secret, body).unwrap();
    assert_eq!(
        signed.signed(),
        f.manifest.signed(),
        "the manifest, signed again"
    );
    // Packed to a smaller chunk size, the same parts make more chunks, in order.
    let small = pack(&f.parts, 4096).unwrap();
    assert!(small.len() > 1);
    let mut next = 0;
    for (i, (r, bytes)) in small.iter().enumerate() {
        assert_eq!(r.id, format!("{i:05}"));
        assert_eq!(r.first, next);
        assert_eq!(r.len, bytes.len() as u64);
        next = r.last + 1;
        let c = Chunk::parse(bytes).unwrap();
        assert_eq!(c.index, i as u64);
    }
    assert_eq!(next, 19);
}

/// The full activation, at a next service enrolled with alice's version 3 whose trusted time
/// is the freeze's (vectors README, "Export").
fn check_activation(f: &Fixture, chain: &Chain) -> Import {
    let keys = keys();
    let import = f
        .run(&f.manifest, &f.parts, &Uploads::default(), f.now())
        .unwrap();
    let wallet = app_id_decode(&keys.app("wallet").app_id).unwrap();
    let phone = app_id_decode(&keys.app("phone").app_id).unwrap();
    assert_eq!(import.seq, chain.items.last().unwrap().seq + 1);
    assert_eq!(import.chain.len(), chain.items.len() + 1);
    assert_eq!(import.identity.version(), f.enrolled.version());
    assert_eq!(import.manifest_hash, f.manifest.hash());
    assert_eq!(import.reachable, [wallet], "the wallet alone is reachable");
    assert_eq!(import.app_added_at, [(wallet, 1)]);
    // Seq 9's revoke makes the phone revoked here, whatever its part says.
    let p = import.apps.iter().find(|a| a.part.app_id == phone).unwrap();
    assert!(p.revoked && p.is_tombstone());
    assert_eq!(import.records.len(), 1);
    assert_eq!(
        import.records[0].state.version.version,
        chain.by_source("record.put update").seq
    );
    assert_eq!(import.claims.len(), 1);
    let claim = &import.claims[0].claim;
    assert_eq!((claim.step, claim.creator), (1, Some(wallet)));
    assert_eq!(claim.last_entry, Some(1_767_225_603_000));
    // The entry was checked against the certificate the wallet's app part carries.
    let entries = &import.claims[0].entries;
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].cert, None);
    // The kept proofs, the record's and the claim entry's, all name generation 1.
    assert_eq!(import.proof_generations, [1]);
    assert_eq!(import.batches.len(), 3);
    assert_eq!(
        import.freeze_at,
        f.now(),
        "last_time is the freeze transition's time"
    );
    assert!(f.now() > f.freeze.body().issued_at);
    // The enrollment's revoked apps stay tombstones.
    let revoked = [wallet];
    let held = activate(
        &Activation {
            manifest: &f.manifest,
            freeze: &f.freeze,
            enrolled: &f.enrolled,
            now: Some(f.now()),
            uploads: &Uploads::default(),
            revoked_apps: &revoked,
        },
        &f.parts,
    )
    .unwrap();
    let w = held.apps.iter().find(|a| a.part.app_id == wallet).unwrap();
    assert!(w.revoked && w.is_tombstone());
    assert!(held.reachable.is_empty() && held.app_added_at.is_empty());
    // Without trusted time the activation waits.
    let waits = activate(
        &Activation {
            manifest: &f.manifest,
            freeze: &f.freeze,
            enrolled: &f.enrolled,
            now: None,
            uploads: &Uploads::default(),
            revoked_apps: &[],
        },
        &f.parts,
    );
    refused(waits, ErrorCode::Unavailable, "no trusted time");
    import
}

/// Wire 10.5 step 3, shared records: "Every part but one taken from a recovery upload
/// carries `proof`, and an upload's carries none (`409 conflict` otherwise)." For a carried
/// proof: "The proof names that write: its stub's `item_hash` is the operation's at the
/// part's `seq`, and its stub's generation is the one the operation names, the record's,
/// since a service applies only operations of its own generation (6.4 step 6); its
/// `object` is `key` and its state shows the part's `generation` and `version`; and it
/// verifies with that generation's service key: O's for g, else the one the imported
/// `identity.json` lists for it in `service_keys` (3.3) (`409 conflict` for either)."
/// Wire 10.5 on claims: "If the certificate belongs to another app or the operation's
/// signature fails to verify with it, return `401 bad_signature`." The creator must
/// match "the owner of its first attempt ... (`409 conflict`)", and the resulting state
/// "must match the state in its proof ... (`409 conflict`)". For the last entry time:
/// "Any mismatch gives `409 conflict`." N "rejects a live claim marked `rebuilt` if the
/// imported `identity.json` has `recovery_from` set to `null` (`409 conflict`)".
fn check_refusal(f: &Fixture, parts: &[Part], case: &Value, rule: &str) -> Refusal {
    let error = f.run_parts(parts).expect_err(rule);
    assert_eq!(u64::from(error.status()), int(case, "status"), "{rule}");
    assert_eq!(error.code.as_str(), st(case, "code"), "{rule}");
    assert!(error.reason.contains(rule), "{rule}: {error}");
    error
}

/// The first write's sequence named by the substituted-proof case.
fn first_write_seq(name: &str) -> Option<u64> {
    let seq = name.strip_prefix("the proof of another write, the record's first (seq ")?;
    Some(seq.strip_suffix(')').unwrap().parse().unwrap())
}

/// `record_rejections`: the record part as a faulty old service could send it, each refused
/// at the activation for its rule (Switch wire 10.5).
fn check_record_rejections(f: &Fixture) {
    let v = load("export.json");
    let ri = f.index("record");
    let cases = arr(&v, "record_rejections");
    assert_eq!(cases.len(), 3);
    for case in cases {
        let name = st(case, "name");
        let rule = match name {
            "no proof" => "no proof of its current write",
            "a proof whose signature doesn't verify with O's key" => {
                "doesn't verify with generation 1's service key"
            }
            other if first_write_seq(other).is_some() => "isn't the proof of its current write",
            other => panic!("unknown record rejection {other}"),
        };
        let mut parts = f.parts.clone();
        parts[ri] = Part::read(&json!({ "part": "record", "record": case["record"] })).unwrap();
        check_refusal(f, &parts, case, rule);
    }
}

/// `claim_rejections`: the claim part as a faulty old service could send it, each refused at
/// activation for its rule and its status (Switch wire 6.8, 10.5). Where a case
/// carries `entry_proof`, it stands for the claim's entry's proof; where it carries
/// `claim_entry`, that part follows the claim's own entry.
fn check_claim_rejections(f: &Fixture) {
    let v = load("export.json");
    let ci = f.index("claim");
    let cases = arr(&v, "claim_rejections");
    assert_eq!(cases.len(), 6);
    for case in cases {
        let name = st(case, "name");
        let rule = match name {
            "a creator other than the owner of its first attempt" => "its creator",
            "a last_entry_ms before its last entry's time" => "its last_entry_ms",
            "the open attempt shown failed, with its entry's proof signed again to match" => {
                "an entry's proof doesn't show the state its entry leads to"
            }
            "a failed entry O signed itself, freeing the wallet's open attempt" => {
                "an entry's operation isn't its writer's"
            }
            ANOTHER_WRITER => "its certificate is another app's",
            REBUILT => "the identity.json declares no provider loss",
            other => panic!("unknown claim rejection {other}"),
        };
        let mut parts = f.parts.clone();
        parts[ci] = Part::read(&json!({
            "part": "claim", "claim_key": case["claim_key"], "claim": case["claim"]
        }))
        .unwrap();
        if let Some(proof) = case.get("entry_proof") {
            let Part::ClaimEntry(entry) = &mut parts[ci + 1] else {
                panic!("{name}: the claim's entry");
            };
            entry.proof = serde_json::from_value(proof.clone()).unwrap();
            // Signed again by the old service: the proof alone verifies.
            TransitionProof::verify(&entry.proof, &f.o_key, &f.alice).unwrap();
        }
        if let Some(raw) = case.get("claim_entry") {
            let part = Part::read(raw).unwrap();
            assert_eq!(part.kind(), "claim_entry", "{name}");
            parts.insert(ci + 2, part);
        }
        check_refusal(f, &parts, case, rule);
    }
}

const ANOTHER_WRITER: &str = "a failed entry the executor signed under its own certificate, naming the wallet as its writer, freeing the wallet's open attempt";
const REBUILT: &str = "the claim marked rebuilt from uploads on an account without a provider loss, its open attempt failed and the claim freed";

/// More of the activation's checks on the vector's export, each refused for its rule.
fn check_activation_rules(f: &Fixture, chain: &Chain) {
    let chain_index = |seq| {
        f.parts
            .iter()
            .position(|p| matches!(p, Part::Chain(c) if c.seq == seq))
            .unwrap()
    };
    let identity = chain_index(chain.by_source("alice identity.json").seq);
    let registration = chain.by_source("app.put");
    // The parts in order: two chain parts swapped are refused by the order (400), before
    // the link (409); meta not first is 400.
    let mut swapped = f.parts.clone();
    swapped.swap(identity, chain_index(registration.seq));
    refused(f.run_parts(&swapped), ErrorCode::BadRequest, "out of order");
    let mut swapped = f.parts.clone();
    swapped.swap(f.index("meta"), f.index("chain"));
    refused(
        f.run_parts(&swapped),
        ErrorCode::BadRequest,
        "only the first, is meta",
    );
    // A document that isn't its stub's.
    let mut parts = f.parts.clone();
    if let Part::Chain(c) = &mut parts[identity] {
        c.doc = Some(registration.item.clone());
    }
    refused(
        f.run_parts(&parts),
        ErrorCode::Conflict,
        "the chain part at seq",
    );
    // Every batch a kept stub names has its part.
    let without: Vec<Part> = f
        .parts
        .iter()
        .filter(|p| p.kind() != "batch")
        .cloned()
        .collect();
    refused(
        f.run_parts(&without),
        ErrorCode::Conflict,
        "without its batch part",
    );
    // The freeze transition's document dropped.
    let mut parts = f.parts.clone();
    if let Part::Chain(c) = &mut parts[chain_index(f.manifest.body().head.seq)] {
        c.doc = None;
    }
    refused(
        f.run_parts(&parts),
        ErrorCode::Conflict,
        "isn't the freeze transition",
    );
    // A manifest naming another freeze.
    let other = f.resign(|b| b.freeze_hash = [7; 32]);
    refused(
        f.run(&other, &f.parts, &Uploads::default(), f.now()),
        ErrorCode::Conflict,
        "names another freeze",
    );
    // `last_time` 1 ms before the transition's `at`.
    let early = f.resign(|b| b.last_time -= 1);
    refused(
        f.run(&early, &f.parts, &Uploads::default(), f.now()),
        ErrorCode::Conflict,
        "last_time is before",
    );
    // Up to the clock tolerance ahead of this service's time imports; 1 ms more doesn't.
    f.run(
        &f.manifest,
        &f.parts,
        &Uploads::default(),
        f.now() - CLOCK_TOLERANCE_MS,
    )
    .unwrap();
    refused(
        f.run(
            &f.manifest,
            &f.parts,
            &Uploads::default(),
            f.now() - CLOCK_TOLERANCE_MS - 1,
        ),
        ErrorCode::Conflict,
        "ahead of this service's time",
    );
    // The meta part's identity.json: a version behind the enrolled one, or not the newest
    // identity item of the chain parts.
    let mut parts = f.parts.clone();
    if let Part::Meta(meta) = &mut parts[0] {
        meta.identity = document("alice identity.json, first delivery (version 1)");
    }
    refused(
        f.run_parts(&parts),
        ErrorCode::Conflict,
        "goes back on the enrolled one",
    );
    let alice = f.alice;
    let v6 = IdentityDoc::verify(
        &document("alice identity.json, record age limit (version 6)"),
        &alice,
    )
    .unwrap();
    let later = activate(
        &Activation {
            manifest: &f.manifest,
            freeze: &f.freeze,
            enrolled: &v6,
            now: Some(f.now()),
            uploads: &Uploads::default(),
            revoked_apps: &[],
        },
        &f.parts,
    );
    assert!(later.is_err(), "an export behind the enrolled version");
    // The meta part's seq and generation are the head's.
    let head_seq = f.manifest.body().head.seq;
    for seq in [head_seq - 1, head_seq + 1] {
        let mut parts = f.parts.clone();
        if let Part::Meta(meta) = &mut parts[0] {
            meta.seq = seq;
        }
        refused(
            f.run_parts(&parts),
            ErrorCode::Conflict,
            "generation or seq isn't the head's",
        );
    }
    // A broken head signature is 401.
    let mut head = f.manifest.body().head;
    head.sig = [0; 64];
    let forged = f.resign(|b| b.head = head);
    refused(
        f.run(&forged, &f.parts, &Uploads::default(), f.now()),
        ErrorCode::BadSignature,
        "the head",
    );
    // The wallet's receive key at another seq, or none while the chain holds one.
    let wi = f
        .parts
        .iter()
        .position(|p| matches!(p, Part::App(a) if a.record.is_some()))
        .unwrap();
    let mut parts = f.parts.clone();
    if let Part::App(a) = &mut parts[wi] {
        a.receive_keys[0].1 += 1;
    }
    refused(
        f.run_parts(&parts),
        ErrorCode::Conflict,
        "isn't that chain item",
    );
    let mut parts = f.parts.clone();
    if let Part::App(a) = &mut parts[wi] {
        a.receive_keys.clear();
    }
    refused(
        f.run_parts(&parts),
        ErrorCode::Conflict,
        "isn't the chain's newest",
    );
    // Without the wallet's part, a listed app has none.
    let mut parts = f.parts.clone();
    parts.remove(wi);
    refused(f.run_parts(&parts), ErrorCode::Conflict, "no app part");
    // A record member that isn't its operation's.
    let ri = f.index("record");
    let mut parts = f.parts.clone();
    if let Part::Record(r) = &mut parts[ri] {
        r.size += 1;
    }
    refused(
        f.run_parts(&parts),
        ErrorCode::Conflict,
        "a member isn't its operation's",
    );
    // The record's op carried as well: the same bytes import.
    let mut parts = f.parts.clone();
    if let Part::Record(r) = &mut parts[ri] {
        r.op = Some(chain.at(r.seq).item.clone());
    }
    f.run_parts(&parts).unwrap();
    // The claim entry's certificate carried in its part: the same certificate imports.
    let wallet_cert = f
        .parts
        .iter()
        .find_map(|p| match p {
            Part::App(a) => a.record.as_ref(),
            _ => None,
        })
        .map(|d| {
            AppRecord::verify(d, &f.alice)
                .unwrap()
                .cert()
                .signed()
                .clone()
        })
        .unwrap();
    let ei = f.index("claim_entry");
    let mut parts = f.parts.clone();
    if let Part::ClaimEntry(e) = &mut parts[ei] {
        e.cert = Some(wallet_cert);
    }
    f.run_parts(&parts).unwrap();
    // A live claim without its entry.
    let ci = f.index("claim");
    let mut parts = f.parts.clone();
    parts.remove(ci + 1);
    refused(
        f.run_parts(&parts),
        ErrorCode::Conflict,
        "a live claim without entries",
    );
}

/// The uploaded heads and evidence (Switch wire 7.4.14, 10.5).
fn check_uploads(f: &Fixture) {
    let keys = keys();
    let chain = load("chain.json");
    let wallet = app_id_decode(&keys.app("wallet").app_id).unwrap();
    let head = |h: &Value| SignedHead::from_value(h).unwrap();
    let mut heads: Vec<UploadedHead> = arr(&chain, "signed_heads")
        .iter()
        .map(|h| UploadedHead {
            app_id: wallet,
            head: head(&h["head"]),
        })
        .collect();
    heads.push(UploadedHead {
        app_id: wallet,
        head: f.manifest.body().head,
    });
    let uploads = Uploads {
        heads,
        proofs: Vec::new(),
    };
    f.run(&f.manifest, &f.parts, &uploads, f.now()).unwrap();
    let forked = arr(&chain, "rejections")
        .iter()
        .find(|r| st(r, "name") == "forked head")
        .unwrap();
    let uploads = Uploads {
        heads: vec![UploadedHead {
            app_id: wallet,
            head: head(&forked["head"]),
        }],
        proofs: Vec::new(),
    };
    refused(
        f.run(&f.manifest, &f.parts, &uploads, f.now()),
        ErrorCode::Conflict,
        "isn't on the imported chain",
    );
    // chain.json's record proofs, (1, 6) and (1, 8), and the claim attempt's hold.
    let proofs: Vec<UploadedProof> = arr(&chain, "transition_proofs")
        .iter()
        .filter(|p| {
            let name = st(p, "name");
            name.starts_with("record.put") || name.starts_with("claim attempt")
        })
        .map(|p| UploadedProof {
            app_id: wallet,
            proof: TransitionProof::verify(
                &serde_json::from_value(p["signed"].clone()).unwrap(),
                &f.o_key,
                &f.alice,
            )
            .unwrap(),
        })
        .collect();
    assert_eq!(proofs.len(), 3);
    let uploads = Uploads {
        heads: Vec::new(),
        proofs: proofs.clone(),
    };
    f.run(&f.manifest, &f.parts, &uploads, f.now()).unwrap();
    // Without the claim, the attempt's evidence fails; without the record, the record's.
    let no_claim: Vec<Part> = f
        .parts
        .iter()
        .filter(|p| !matches!(p.kind(), "claim" | "claim_entry"))
        .cloned()
        .collect();
    let manifest = f.resign(|b| b.parts = no_claim.len() as u64);
    refused(
        f.run(&manifest, &no_claim, &uploads, f.now()),
        ErrorCode::Conflict,
        "a claim with an attempt",
    );
}

/// What the export shares with `chain.json`: its chain parts are that chain's items, seq 6's
/// superseded `record.put` a stub only, then the freeze transition, which extends chain.json's
/// head at 9; the record's proof and the claim entry's are chain.json's.
fn check_chain_cross(f: &Fixture, import: &Import, chain: &Chain) {
    let parts = &import.chain;
    assert_eq!(parts.len(), chain.items.len() + 1);
    let superseded = chain.superseded_writes();
    assert_eq!(
        superseded,
        HashSet::from([chain.by_source("record.put create").seq])
    );
    for (part, item) in parts.iter().zip(&chain.items) {
        assert_eq!(part.seq, item.seq);
        assert_eq!(part.stub, item.stub);
        assert_eq!(part.item_type, item.item_type);
        assert_eq!(
            part.doc.as_ref(),
            (!superseded.contains(&item.seq)).then_some(&item.item)
        );
    }
    let last = chain.items.last().unwrap();
    let file = load("chain.json");
    let head = arr(&file, "signed_heads")
        .iter()
        .map(|h| SignedHead::from_value(&h["head"]).unwrap())
        .find(|h| h.seq == last.seq)
        .expect("head at the end of the chain");
    let freeze = parts.last().unwrap();
    assert_eq!(freeze.seq, last.seq + 1);
    // The freeze transition's signature, reproduced from the fixed service key.
    let doc = freeze.doc.as_ref().unwrap();
    assert!(reproduce(
        &keys(),
        &f.o_key,
        labels::sig::SERVICE_OP,
        &[&f.alice, &doc.body_bytes().unwrap()],
        &doc.sig_bytes().unwrap(),
    ));
    assert_eq!(freeze.stub.open().unwrap().prev_chain_hash, head.chain_hash);
    let proof = |source| chain.proofs[&chain.by_source(source).seq].signed();
    assert_eq!(
        import.records[0].part.proof.as_ref(),
        Some(proof("record.put update"))
    );
    assert_eq!(&import.claims[0].entries[0].proof, proof("claim attempt"));
    assert_eq!(
        import.identity.signed(),
        &chain.by_source("alice identity.json").item
    );
}

/// What the export shares with `documents.json`: the freeze it belongs to, and the export
/// transfer that names its manifest.
fn check_documents_cross(f: &Fixture) {
    let transfer = ExportTransfer::verify(
        &document("alice export transfer, for export.json's manifest"),
        &f.alice,
    )
    .unwrap();
    assert_eq!(transfer.body().manifest_hash, f.manifest.hash());
    assert_eq!(transfer.body().freeze_hash, f.freeze.hash());
    assert_eq!(f.manifest.body().freeze_hash, f.freeze.hash());
    assert_eq!(&transfer.body().to, f.freeze.next());
    assert_eq!(&transfer.body().from, f.enrolled.inbox());
}

/// What the export shares with `http.json`: the next service's chunk fetch under the export
/// transfer, which the old service's checks admit, and its answer, the chunk.
fn check_http_cross(f: &Fixture) {
    let http = load("http.json");
    let request = arr(&http, "requests")
        .iter()
        .find(|r| st(r, "name").contains("export chunk fetch"))
        .unwrap();
    let id = st(request, "path").rsplit('/').next().unwrap();
    assert_eq!(
        st(request, "path"),
        format!(
            "/v1/{}/export/chunks/{id}",
            pubky_switch_core::enc::pubky_id(&f.alice)
        )
    );
    let transfer = ExportTransfer::verify(
        &SignedDoc::from_compact(st(&request["headers"], "switch-transfer")).unwrap(),
        &f.alice,
    )
    .unwrap();
    let read = ExportRead {
        caller: ExportCaller::NextService(&transfer),
        frozen_with: Some(&f.freeze),
        has_identity: true,
        origin: st(request, "origin"),
        service_key: &f.o_key,
    };
    let chunk = read.check_chunk(&f.manifest, id).unwrap();
    assert_eq!(chunk.id, "00000");
    assert_eq!(
        read.check_manifest().unwrap_err().status(),
        403,
        "the manifest is the signer's"
    );
    let response = arr(&http, "responses")
        .iter()
        .find(|r| st(r, "name").contains("the export chunk"))
        .unwrap();
    assert_eq!(b64n::<32>(st(response, "public_key")), f.o_key);
    let answer = ChunkAnswer {
        id: id.to_owned(),
        data: f.chunk.clone(),
    };
    assert_eq!(answer.to_json(), st(response, "body").as_bytes());
    assert_eq!(
        ChunkAnswer::parse(st(response, "body").as_bytes()).unwrap(),
        answer
    );
    f.manifest.check_fetched(id, &answer.data).unwrap();
}

/// Carry the claim store's state in an export part.
fn claim_part(key: [u8; 32], claim: &Claim) -> Part {
    Part::Claim(ClaimPart {
        claim_key: key,
        claim: ClaimState {
            step: claim.step,
            attempts: claim
                .attempts
                .iter()
                .map(|a| AttemptState {
                    attempt_id: a.attempt_id,
                    owner: a.owner,
                    outcome: a.outcome,
                    opened_at_ms: a.opened_at,
                    orphan_after_s: a.orphan_after,
                    possibly_duplicate: a.possibly_duplicate,
                    duplicate: a.duplicate,
                    deadline_ms: claim.pin.deadline(),
                    from_upload: a.from_upload,
                    resolved_by: a.resolved_by,
                })
                .collect(),
            current: claim.current_attempt().map(|a| a.attempt_id),
            settled: claim.settled,
            divergent: claim.divergent,
            pinned_deadline: claim.pin,
            rebuilt: claim.rebuilt,
            creator: claim.creator,
            last_entry_ms: claim.last_entry,
        },
    })
}

fn part_text(p: &Part) -> String {
    String::from_utf8(p.to_json().unwrap()).unwrap()
}

fn part_value(p: &Part) -> Value {
    serde_json::from_slice(&p.to_json().unwrap()).unwrap()
}

/// The account after the freeze was appended to the generation's last stub.
fn frozen(keys: &Keys, docs: &HashMap<String, SignedDoc>, chain: &Chain, input: &Value) -> Fixture {
    let wallet = keys.app("wallet");
    let alice = wallet.identity;
    let wallet_id = app_id_decode(&wallet.app_id).unwrap();
    let service = service_signer(keys, &alice);
    let current = IdentityDoc::verify(&docs["alice identity.json"], &alice).unwrap();
    let freeze = Freeze::verify(&docs["alice freeze"], &alice).unwrap();
    let last = chain.items.last().unwrap();
    let at = time_of(input, "freeze_at");
    let t = ServiceTransition::Freeze {
        freeze_hash: freeze.hash(),
        next_generation: freeze.body().next_generation,
        inbox: freeze.next().clone(),
        at,
    };
    let row = Item::append(
        &last.tip(),
        last.seq + 1,
        at,
        ItemType::Service,
        t.sign(&service, &alice).unwrap(),
    );
    let tip = row.tip();
    let head = SignedHead::sign(&service, &alice, &tip);
    let mut parts = vec![Part::Meta(MetaPart {
        identity: current.signed().clone(),
        generation: tip.generation,
        seq: tip.seq,
        directory_version: int(input, "directory_version"),
        apps_version: int(input, "apps_version"),
        app_added_at: vec![(wallet_id, int(input, "wallet_added_at"))],
    })];
    // Wire 10.3 carries a null doc for the writes dropped under 7.5.
    let superseded = chain.superseded_writes();
    parts.extend(chain.items.iter().chain([&row]).map(|r| {
        Part::Chain(ChainPart {
            seq: r.seq,
            stub: r.stub.clone(),
            item_type: r.item_type,
            doc: (!superseded.contains(&r.seq)).then(|| r.item.clone()),
        })
    }));
    let mut apps = current.body().apps.clone();
    apps.sort_by_key(|a| enc::zbase32_encode(&a.app_id));
    let ServiceTransition::Revoke {
        app_id: revoked,
        at: revoked_at,
    } = ServiceTransition::from_value(&chain.by_source("revoke").item.peek().unwrap()).unwrap()
    else {
        panic!("expected revocation")
    };
    let registration = chain.by_source("app.put");
    for app in apps {
        let registered = app.app_id == wallet_id;
        parts.push(Part::App(AppPart {
            app_id: app.app_id,
            record: registered.then(|| docs["wallet app record"].clone()),
            record_seq: registered.then_some(registration.seq),
            record_at_ms: registered.then_some(registration.envelope.server_time),
            receive_keys: if registered {
                vec![(
                    docs["wallet receive key record"].clone(),
                    chain.by_source("receive_key.put").seq,
                )]
            } else {
                vec![]
            },
            cursor: if registered {
                int(input, "wallet_cursor")
            } else {
                0
            },
            last_seen_ms: registered.then_some(last.envelope.server_time),
            revoked_at_ms: (app.app_id == revoked).then_some(revoked_at),
            departed_at_ms: None,
            departure_epoch: None,
            rotated: false,
            renewed_cert: None,
            lagging: false,
            keys_through: Some(int(input, "keys_through")),
            full_bundle_requested_ms: None,
        }));
    }
    let attempt = chain.by_source("claim attempt");
    let (claim_key, claim) = first_claim(attempt);
    parts.push(claim_part(claim_key, &claim));
    parts.push(Part::ClaimEntry(ClaimEntryPart {
        claim_key,
        step: claim.step - 1,
        seq: attempt.seq,
        op: attempt.item.clone(),
        proof: chain.proofs[&attempt.seq].signed().clone(),
        cert: None,
    }));
    let update = chain.by_source("record.put update");
    let op = update.op();
    let OpKind::RecordPut(put) = &op.body().kind else {
        panic!("expected record write")
    };
    parts.push(Part::Record(RecordEntry {
        key: put.key,
        collection: put.collection,
        read_scope: put.policy.read_scope.clone(),
        write_scopes: put.policy.write_scopes.clone(),
        generation: update.envelope.generation,
        version: update.seq,
        seq: update.seq,
        op: None,
        deleted: put.value_sealed.looks_like_delete(),
        writer: op.body().app_id.unwrap(),
        from_upload: false,
        upload_base: None,
        size: put.value_sealed.ct.len() as u64,
        cert: None,
        proof: Some(chain.proofs[&update.seq].signed().clone()),
    }));
    let mut batches = BTreeMap::new();
    for r in &chain.items {
        if let Some(b) = r.envelope.batch {
            let (_, ops) = batches
                .entry(b64e(&b.id))
                .or_insert_with(|| (r.envelope.server_time, Vec::new()));
            ops.push(r.op());
        }
    }
    parts.extend(batches.into_values().map(|(at_ms, ops)| {
        Part::Batch(BatchPart {
            id: ops[0].body().batch.id,
            at_ms,
            ops_hash: ops_hash(&ops).unwrap(),
        })
    }));
    let [(chunk_ref, chunk)] = pack(&parts, DEFAULT_CHUNK_TARGET)
        .unwrap()
        .try_into()
        .unwrap();
    let body = ManifestBody::new(
        alice,
        freeze.hash(),
        tip.generation,
        at,
        head,
        None,
        vec![chunk_ref],
    )
    .unwrap();
    Fixture {
        alice,
        o_key: service.verifying_key().to_bytes(),
        manifest: Manifest::sign(&service, body).unwrap(),
        o_secret: service,
        chunk,
        parts,
        freeze,
        enrolled: current,
    }
}

/// Rebuild each rejected record, then check the actual refusal and its published wording.
fn record_faults(f: &Fixture, keys: &Keys, chain: &Chain, file: &Value) {
    let ri = f.index("record");
    for (i, c) in arr(file, "record_rejections").iter().enumerate() {
        let mut parts = f.parts.clone();
        let Part::Record(r) = &mut parts[ri] else {
            panic!("expected record")
        };
        let key = b64e(&r.key);
        let name = st(c, "name");
        let (proof, rule, text) = match (name, first_write_seq(name)) {
            ("no proof", None) => (
                None,
                "no proof of its current write",
                "proof is missing: a current write's proof is kept and exported",
            ),
            ("a proof whose signature doesn't verify with O's key", None) => (
                Some(
                    TransitionProof::sign(
                        &service_signer(keys, &keys.identity(st(c, "signing_account"))),
                        &f.alice,
                        chain.proofs[&r.seq].body().clone(),
                    )
                    .unwrap()
                    .signed()
                    .clone(),
                ),
                "doesn't verify with generation 1's service key",
                "proof isn't signed with its generation's service key",
            ),
            (_, Some(seq)) => {
                assert_eq!(seq, chain.by_source("record.put create").seq, "{name}");
                (
                    Some(chain.proofs[&seq].signed().clone()),
                    "isn't the proof of its current write",
                    "proof isn't its current write's",
                )
            }
            (other, None) => panic!("unknown record fault {other}"),
        };
        let carried = json!(proof);
        r.proof = proof;
        let mut value = part_value(&parts[ri]);
        value["record"]["proof"] = carried;
        let path = format!("/record_rejections/{i}");
        let record: Vec<_> = value["record"]
            .as_object()
            .unwrap()
            .iter()
            .map(|(key, value)| (key.as_str(), value.clone()))
            .collect();
        generated_members("export.json", &format!("{path}/record"), &record);
        generated_members(
            "export.json",
            &path,
            &[("error", json!(format!("record {key}'s {text}")))],
        );
        check_refusal(f, &parts, c, rule);
    }
}

/// Sign a failed entry under a different writer and bind its proof to the frozen head.
fn forged_entry(
    f: &Fixture,
    attempt: &Item,
    claim: &Claim,
    key: [u8; 32],
    batch: [u8; 16],
    signer: &SigningKey,
    cert: Option<SignedDoc>,
) -> Part {
    let mut body = attempt.op().body().clone();
    let OpKind::Claim(fields) = &mut body.kind else {
        panic!("expected attempt")
    };
    fields.kind = ClaimType::Failed;
    fields.expected_step = claim.step - 1;
    fields.orphan_after = None;
    fields.deadline = None;
    body.conditions.clear();
    body.batch = BatchRef {
        id: batch,
        count: 1,
    };
    let doc = SignedDoc::sign_bytes(
        signer,
        labels::sig::OP,
        &[&f.alice],
        body.to_json().unwrap(),
    );
    let h = f.manifest.body().head;
    let tip = ChainTip {
        generation: h.generation,
        seq: h.seq,
        chain_hash: h.chain_hash,
    };
    let row = Item::append(&tip, h.seq + 1, f.now(), ItemType::Op, doc);
    let state = ProofState::Claim(claim.view(&key, f.now(), &|_| true).to_value());
    let proof = TransitionProof::sign(
        &f.o_secret,
        &f.alice,
        ProofBody::new(row.stub, b64e(&key), &state),
    )
    .unwrap();
    Part::ClaimEntry(ClaimEntryPart {
        claim_key: key,
        step: claim.step - 1,
        seq: row.seq,
        op: row.item,
        proof: proof.signed().clone(),
        cert,
    })
}

/// Change the named field or writer of a valid claim and check the pinned refusal.
fn claim_faults(
    f: &Fixture,
    keys: &Keys,
    docs: &HashMap<String, SignedDoc>,
    chain: &Chain,
    file: &Value,
) {
    let ci = f.index("claim");
    let attempt = chain.by_source("claim attempt");
    let (key, base) = first_claim(attempt);
    let cases = arr(file, "claim_rejections");
    for (i, c) in cases.iter().enumerate() {
        let name = st(c, "name");
        let path = format!("/claim_rejections/{i}");
        let mut claim = base.clone();
        let mut parts = f.parts.clone();
        let mut extra = Vec::new();
        let reason = match name {
            "a creator other than the owner of its first attempt" => {
                claim.creator =
                    Some(app_id_decode(&keys.app(st(c, "creator_app")).app_id).unwrap());
                "its creator isn't the owner of its first attempt"
            }
            "a last_entry_ms before its last entry's time" => {
                claim.last_entry = Some(claim.last_entry.unwrap() - int(c, "earlier_ms"));
                "its last_entry_ms isn't its last entry's time"
            }
            "the open attempt shown failed, with its entry's proof signed again to match" => {
                claim.attempts[0].outcome = Outcome::Failed;
                claim.current = None;
                let state = ProofState::Claim(
                    claim
                        .view(&key, attempt.envelope.server_time, &|_| true)
                        .to_value(),
                );
                let proof = TransitionProof::sign(
                    &f.o_secret,
                    &f.alice,
                    ProofBody::new(attempt.stub.clone(), b64e(&key), &state),
                )
                .unwrap();
                let Part::ClaimEntry(e) = &mut parts[ci + 1] else {
                    panic!("expected claim entry")
                };
                e.proof = proof.signed().clone();
                extra.push(("entry_proof", json!(e.proof)));
                "an entry's proof doesn't show the state its entry leads to"
            }
            "a failed entry O signed itself, freeing the wallet's open attempt"
            | ANOTHER_WRITER
            | REBUILT => {
                claim.attempts[0].outcome = Outcome::Failed;
                claim.attempts[0].resolved_by = claim.creator;
                claim.current = None;
                if name == REBUILT {
                    claim.rebuilt = true;
                    "rebuilt from uploads, but the identity.json declares no provider loss"
                } else {
                    claim.step += 1;
                    claim.last_entry = Some(f.now());
                    let executor = SigningKey::from_bytes(&keys.app("executor").signing_secret);
                    let (signer, cert) = if name == ANOTHER_WRITER {
                        (&executor, Some(docs["executor certificate"].clone()))
                    } else {
                        (&f.o_secret, None)
                    };
                    let forged = forged_entry(
                        f,
                        attempt,
                        &claim,
                        key,
                        seed16(c, "batch_seed_label"),
                        signer,
                        cert,
                    );
                    extra.push(("claim_entry", part_value(&forged)));
                    parts.insert(ci + 2, forged);
                    "an entry's operation isn't its writer's"
                }
            }
            other => panic!("unknown claim fault {other}"),
        };
        parts[ci] = claim_part(key, &claim);
        let wire = part_value(&parts[ci]);
        extra.extend([
            ("claim_key", json!(b64e(&key))),
            ("claim", wire["claim"].clone()),
        ]);
        generated_members("export.json", &path, &extra);
        let refused = check_refusal(f, &parts, c, reason);
        if matches!(name, ANOTHER_WRITER | REBUILT) {
            assert_eq!(st(c, "error"), quoted(&refused.reason));
        } else {
            let text = format!("claim {}: {reason}", b64e(&key));
            generated_members("export.json", &path, &[("error", json!(text))]);
        }
    }
}

/// Seal the pending assignment and carry it in both of the independent histories.
fn pending_entries(
    keys: &Keys,
    docs: &HashMap<String, SignedDoc>,
    chain: &Chain,
    file: &Value,
) -> (EntryPart, Vec<PeerEntry>) {
    let c = &file["pending_entry"];
    let shop = keys.app("shop");
    let wallet = keys.app("wallet");
    let signer =
        pubky_switch_core::keys::AppKeys::from_secrets(shop.signing_secret, shop.bundle_secret);
    let at = time_of(c, "accepted_at");
    let message = message::Message {
        from: message::Sender::of_app(shop.identity, &signer),
        to: wallet.identity,
        msg_id: uuid_from_seed(st(c, "msg_id_seed_label")),
        kind: st(c, "kind").into(),
        created_at_ms: at,
        body: c["body"].as_object().unwrap().clone(),
        refs: vec![],
    };
    let random = fixed_from_seeds(st(c, "seal_seed_label"));
    let env = envelope::seal_with(
        &wallet.identity,
        &[envelope::Recipient::new(wallet.receive_public)],
        &message.sign(&signer).unwrap().encode(),
        c["notify"].as_bool().unwrap(),
        &random.content_key,
        &random.nonce,
        &[random.ikm_e],
    )
    .unwrap();
    let second = chain
        .peers
        .iter()
        .find(|row| row.seq == int(c, "invite_seq"))
        .unwrap()
        .op();
    let OpKind::InviteCodePut(invite) = &second.body().kind else {
        panic!("expected second invite")
    };
    let mut entry = EntryPart {
        seq: int(c, "seq"),
        sender: shop.identity,
        cert: docs["shop certificate"].clone(),
        accepted_at_ms: at,
        invite_code_hash: Some(invite.code_hash),
        envelope: env,
        targets: vec![app_id_decode(&wallet.app_id).unwrap()],
        result: EntryResult {
            entry_id: seed16(c, "entry_seed_label"),
            accepted_at: at,
            directory_version: int(c, "directory_version"),
        },
        unreadable: false,
        missed: None,
    };
    generated_members(
        "export.json",
        "/pending_entry",
        &[("json", json!(part_text(&Part::Entry(entry.clone()))))],
    );
    let pending = entry.clone();
    let p = &file["peer_admission"];
    entry.seq = int(p, "entry_seq");
    entry.result.entry_id = seed16(p, "entry_seed_label");
    entry.result.directory_version = int(p, "directory_version");
    let mut peers = BTreeMap::new();
    for row in &chain.peers {
        let at = row.envelope.server_time;
        let (peer, reason, present, origin) = match row.item_type {
            ItemType::Service => {
                let ServiceTransition::ReplyAdd {
                    pubky, code_hash, ..
                } = ServiceTransition::from_value(&row.item.peek().unwrap()).unwrap()
                else {
                    panic!("expected reply grant")
                };
                (
                    pubky,
                    PeerReason::Reply,
                    true,
                    ReplyOrigin::Invite(code_hash),
                )
            }
            ItemType::Op => {
                let op = row.op();
                let (peer, reason, present) = match &op.body().kind {
                    OpKind::InviteCodePut(_) => continue,
                    OpKind::AllowPut { pubky, reason } => (*pubky, *reason, true),
                    OpKind::AllowDelete { pubky, reason } => (*pubky, *reason, false),
                    kind => panic!("unknown admission operation {}", kind.name()),
                };
                (
                    peer,
                    reason,
                    present,
                    ReplyOrigin::App(op.body().app_id.unwrap()),
                )
            }
            ItemType::Identity => panic!("unexpected admission identity at {}", row.seq),
        };
        let peer = peers.entry(enc::pubky_id(&peer)).or_insert(PeerEntry {
            pubky: peer,
            kept: false,
            reply: None,
        });
        match reason {
            PeerReason::Kept => peer.kept = present,
            PeerReason::Reply => {
                peer.reply = present.then_some(ReplyGrant {
                    origin,
                    at,
                    last_used: None,
                })
            }
        }
    }
    peers
        .get_mut(&enc::pubky_id(&shop.identity))
        .unwrap()
        .reply
        .as_mut()
        .unwrap()
        .last_used = Some(time_of(p, "last_used"));
    let peers: Vec<_> = peers.into_values().collect();
    let admission: Vec<_> = peers
        .iter()
        .cloned()
        .map(|p| part_text(&Part::Admission(p)))
        .collect();
    generated_members(
        "export.json",
        "/peer_admission",
        &[
            ("entry", json!(part_text(&Part::Entry(entry)))),
            ("admission", json!(admission)),
        ],
    );
    (pending, peers)
}

pub(super) struct ExportCases {
    pub transfer: ExportTransfer,
    pub chunk: ChunkAnswer,
    pub pending: EntryPart,
    pub peers: Vec<PeerEntry>,
}

/// Pack the rebuilt parts, sign their manifest, and issue the transfer for that manifest.
pub(super) fn export_cases(
    keys: &Keys,
    docs: &HashMap<String, SignedDoc>,
    chain: &Chain,
) -> ExportCases {
    let file = load("export.json");
    super::generation::check_annotations("export.json", &file);
    let key_file = load("keys.json");
    let service = arr(&key_file, "service_keys")
        .iter()
        .find(|s| service_owner(s) == "alice")
        .unwrap();
    let description = format!(
        "A complete export (wire 10.2, 10.3) of alice's account, signed with the fixed service key of \
         keys.json ({}) over lp(\"{}\", identity, body). It is the account frozen right after chain.json's \
         last item (operations.json continues the account past that item instead). It activates under wire \
         10.5 at a next service enrolled with alice's current identity.json (version 3) whose trusted time \
         is the freeze's. One chunk holds, in the order of wire 10.3: the meta part; the chain, the items of \
         chain.json (seqs 1 to 9) and then the freeze transition (seq 10, wire 6.5) for documents.json's \
         freeze, with the record.put of seq 6 as a stub only, since seq 8 supersedes it (wire 7.5); an app \
         part for each app the identity.json lists: the wallet with its record and receive key of seqs 3 and \
         4 and its cursor at 9, the phone revoked at seq 9, and the executor, the phone and the executor \
         having registered nowhere in this chain; the live claim of seq 7, its creator the wallet, then its \
         one entry as a claim_entry part with that entry's transition proof, which the claim is replayed \
         from, and cert null, since the wallet's app part carries the certificate the entry was checked \
         against; the shared record at (1, 8), its op and cert null since the chain part at seq 8 and the \
         wallet's app part carry them, and its proof the transition proof of that write (chain.json, seq 8), \
         which O keeps with the record; and a batch part for each of the three batches the stubs name, with \
         its operation hash and time and no proofs. The inbox entry at seq 5 (bob's assignment) isn't \
         exported: the wallet, its one target, moved its cursor past it, so O deleted it. The head is the \
         freeze transition, and last_time is its time, after the freeze's issued_at (wire 10.5). The meta \
         part's app_added_at maps each app reachable at the freeze (current, with a receive key) to the \
         apps_version at which it became reachable: the wallet alone, at 1, since the phone is revoked and \
         neither it nor the executor holds a receive key; apps_version is 4, as http.json's append names it. \
         The manifest names the freeze by its hash; its chunk entry gives the chunk's length and BLAKE3 \
         hash. record_rejections are the chunk's record part as a faulty O could send it instead, each \
         refused at the activation (409): without its proof, with a signature that doesn't verify with O's \
         key (another proof's), and with the proof of another write; the chunk with such a part also has \
         another hash, which a check of the part alone needn't recompute. claim_rejections are the chunk's \
         claim part as a faulty O could send it, each refused at the activation for its rule (409 unless \
         status says otherwise): with the phone as its creator; with a last_entry_ms 1 ms before its entry's \
         time; with the open attempt shown failed and the entry's proof (entry_proof) signed again by O to \
         show that state, which the replay of the entry refuses; and with the attempt failed by a further \
         claim_entry part (claim_entry, inserted after the claim's own entry) whose operation O signed with \
         its service key in place of the wallet's signing key, refused at that entry's first check (401).",
        st(service, "seed_label"),
        labels::sig::EXPORT_MANIFEST,
    );
    generated_members("export.json", "", &[("description", json!(description))]);
    let f = frozen(keys, docs, chain, &file["manifest"]);
    let m = f.manifest.signed();
    assert_eq!(st(&file["manifest"], "signer"), "service key");
    generated_members("export.json", "", &[("service_key", json!(b64e(&f.o_key)))]);
    generated_members(
        "export.json",
        "/manifest",
        &[
            ("label", json!(labels::sig::EXPORT_MANIFEST)),
            ("signed", json!(m)),
            (
                "body",
                json!(String::from_utf8(m.body_bytes().unwrap()).unwrap()),
            ),
            ("compact", json!(m.compact())),
            ("doc_hash", json!(b64e(&f.manifest.hash()))),
            ("doc_bytes_hex", json!(hex::encode(m.doc_bytes().unwrap()))),
        ],
    );
    let id = &f.manifest.body().chunks[0].id;
    generated_members(
        "export.json",
        "",
        &[(
            "chunks",
            json!([{
                "id": id,
                "json": std::str::from_utf8(&f.chunk).unwrap(),
                "len": f.chunk.len(),
                "hash": b64e(&hash(&f.chunk)),
            }]),
        )],
    );
    record_faults(&f, keys, chain, &file);
    claim_faults(&f, keys, docs, chain, &file);
    let (pending, peers) = pending_entries(keys, docs, chain, &file);
    let documents = load("documents.json");
    let (i, c) = arr(&documents, "documents")
        .iter()
        .enumerate()
        .find(|(_, c)| c["name"] == "alice export transfer, for export.json's manifest")
        .unwrap();
    let transfer = ExportTransfer::sign(
        &keys.identity_key(&super::documents::document_signer(keys, c)),
        ExportTransferBody {
            identity: f.alice,
            freeze_hash: f.freeze.hash(),
            manifest_hash: f.manifest.hash(),
            from: f.enrolled.inbox().clone(),
            to: f.freeze.next().clone(),
            issued_at: time_of(c, "issued_at"),
        },
    )
    .unwrap();
    super::documents::emit_document(i, labels::sig::EXPORT_TRANSFER, transfer.signed());
    ExportCases {
        pending,
        peers,
        transfer,
        chunk: ChunkAnswer {
            id: id.clone(),
            data: f.chunk,
        },
    }
}
