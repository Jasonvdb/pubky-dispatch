//! `signatures.json`: one signature per Switch label, and the signatures a verifier refuses
//! or must take (Switch wire 2.1, 2.3).

use curve25519_dalek::Scalar;
use curve25519_dalek::constants::EIGHT_TORSION;
use curve25519_dalek::edwards::{CompressedEdwardsY, EdwardsPoint};
use ed25519_dalek::SigningKey;
use pubky_switch_core::enc::{self, app_id_decode, split_lp};
use pubky_switch_core::{Error, http, labels, sig};
use serde_json::{Value, json};
use sha2::{Digest, Sha512};

use crate::common::*;

/// Every signature label of Switch wire 2.3.
const LABELS: [&str; 23] = [
    labels::sig::APP_CERT,
    labels::sig::APP_RECORD,
    labels::sig::RECEIVE_KEY,
    labels::sig::IDENTITY,
    labels::sig::KEY_BUNDLE,
    labels::sig::FREEZE,
    labels::sig::UNFREEZE,
    labels::sig::DISCARDED,
    labels::sig::EXPORT_MANIFEST,
    labels::sig::ENROLL,
    labels::sig::MSG,
    labels::sig::HTTP,
    labels::sig::HTTP_RESPONSE,
    labels::sig::OP,
    labels::sig::SERVICE_OP,
    labels::sig::PROOF,
    labels::sig::HEAD,
    labels::sig::PUSH,
    labels::sig::APP_REQUEST,
    labels::sig::EXPORT_TRANSFER,
    labels::sig::TRANSFER_REQUEST,
    labels::sig::SIGNER_HANDOVER,
    labels::sig::SIGNER_BACKUP,
];

/// The verifier step and the reason the vectors publish for it.
fn refusal(error: &Error) -> (u8, &'static str) {
    let Error::Signature(why) = error else {
        panic!("not a signature error: {error}");
    };
    if why.contains("S isn't below the group order") {
        (1, "non-canonical S")
    } else if why.contains("not canonical") || why.contains("is invalid") {
        if why.contains("public key") {
            (2, "non-canonical or invalid public key")
        } else {
            (2, "non-canonical or invalid R")
        }
    } else if why.contains("small order") {
        if why.contains("public key") {
            (3, "small-order public key")
        } else {
            (3, "small-order R")
        }
    } else if why.contains("the equation doesn't hold") {
        (4, "the equation doesn't hold")
    } else {
        panic!("no step named in {why}")
    }
}

/// Split signed bytes `lp(label, fields...)` back into the label and the fields.
fn label_and_fields(signed: &[u8]) -> (String, Vec<Vec<u8>>) {
    let mut parts = split_lp(signed).expect("lp() bytes");
    let label = String::from_utf8(parts.remove(0)).expect("a UTF-8 label");
    (label, parts)
}

/// Whether ed25519-dalek's non-strict `verify` takes the signature.
fn lenient_accepts(public: &[u8; 32], signed: &[u8], signature: &[u8; 64]) -> bool {
    use ed25519_dalek::Verifier as _;
    ed25519_dalek::VerifyingKey::from_bytes(public).is_ok_and(|key| {
        key.verify(signed, &ed25519_dalek::Signature::from_bytes(signature))
            .is_ok()
    })
}

/// A label's position is fixed by the published wire order, even if its spelling changes.
fn case_path(label: &str) -> String {
    let index = LABELS
        .iter()
        .position(|l| *l == label)
        .expect("wire signature label");
    format!("/signatures/{index}")
}

/// Emit the bytes and signature produced by a source document, envelope or HTTP exchange.
pub(super) fn generated_case(label: &str, names: &[&str], fields: &[&[u8]], signature: &[u8; 64]) {
    assert_eq!(names.len(), fields.len());
    let fields_json: Value = names
        .iter()
        .zip(fields)
        .map(|(name, f)| json!({"name": name, "hex": hex::encode(f)}))
        .collect();
    generated_members(
        "signatures.json",
        &case_path(label),
        &[
            ("label", json!(label)),
            ("fields", fields_json),
            (
                "signed_bytes_hex",
                json!(hex::encode(sig::signed_bytes(label, fields))),
            ),
            ("signature", json!(enc::b64(signature))),
        ],
    );
}

/// Add the group order to S without reducing the result, preserving R.
fn noncanonical_s(mut signature: [u8; 64]) -> [u8; 64] {
    // -1 in the scalar field encodes L - 1. Start the addition with a carry of one.
    let mut carry = 1u16;
    for (s, limb) in signature[32..].iter_mut().zip((-Scalar::ONE).to_bytes()) {
        let sum = u16::from(*s) + u16::from(limb) + carry;
        *s = sum.to_le_bytes()[0];
        carry = sum >> 8;
    }
    assert_eq!(carry, 0);
    signature
}

/// The wire label, named fields in signing order, and signature held by a carrier.
type Carrier = (&'static str, Vec<(String, Vec<u8>)>, [u8; 64]);

/// Read a carrier with a fixed number of named fields.
fn carried<const N: usize>(
    label: &'static str,
    fields: [(&str, Vec<u8>); N],
    signature: &str,
) -> Carrier {
    (
        label,
        fields
            .into_iter()
            .map(|(n, bytes)| (n.to_owned(), bytes))
            .collect(),
        b64n(signature),
    )
}

/// A named case in a carrying file.
fn named<'a>(file: &'a Value, group: &str, name: &str) -> &'a Value {
    arr(file, group)
        .iter()
        .find(|c| c["name"] == name)
        .unwrap_or_else(|| panic!("missing {group} case {name}"))
}

/// The handover and backup cover the number and exact bytes of their envelopes.
fn signer_record(label: &'static str, case: &Value, record: &Value) -> Carrier {
    let plaintext: Value =
        serde_json::from_str(st(case, "plaintext_json")).expect("signer records");
    let envelopes = arr(record, "envelopes");
    let count = u32::try_from(envelopes.len()).expect("envelope count");
    let mut fields = vec![(
        "identity".to_owned(),
        pubky(st(&plaintext, "identity")).to_vec(),
    )];
    if label == labels::sig::SIGNER_HANDOVER {
        fields.push((
            "app_id".into(),
            app_id_decode(st(case, "app_id"))
                .expect("recipient app")
                .to_vec(),
        ));
    }
    fields.push(("u32_be(n)".into(), count.to_be_bytes().to_vec()));
    for (i, envelope) in envelopes.iter().enumerate() {
        fields.push((
            format!("envelope {} bytes", i + 1),
            b64(envelope.as_str().expect("envelope")),
        ));
    }
    (label, fields, b64n(st(record, "sig")))
}

/// Read the exact signed bytes from the carriers in wire order.
fn carriers(keys: &Keys) -> [Carrier; 23] {
    use labels::sig::*;
    let documents = load("documents.json");
    let envelopes = load("envelopes.json");
    let export = load("export.json");
    let chain = load("chain.json");
    let http = load("http.json");
    let sealed = load("sealed.json");
    let alice = keys.identity("alice");
    let doc = |label, name| {
        let entry = named(&documents, "documents", name);
        let signed = &entry["signed"];
        let body = b64(st(signed, "body"));
        assert_eq!(body, st(entry, "body").as_bytes(), "{name}");
        carried(label, [("body", body)], st(signed, "sig"))
    };
    let item = |label, seq: u64| {
        let item = &arr(&chain, "items")
            .iter()
            .find(|i| i["seq"] == seq)
            .expect("signed chain item")["item"];
        carried(
            label,
            [
                ("identity", alice.to_vec()),
                ("body", b64(st(item, "body"))),
            ],
            st(item, "sig"),
        )
    };
    let exchange = |label, group, name| {
        let case = named(&http, group, name);
        let fields = arr(case, "fields")
            .iter()
            .map(|f| (st(f, "name").to_owned(), hx(st(f, "hex"))))
            .collect();
        (label, fields, b64n(st(case, "signature")))
    };
    let bundle = &envelopes["key_bundle"];
    let app = keys.app(st(bundle, "app"));
    let unfreeze = &documents["unfreeze"];
    let discarded = &documents["discarded"]["answer"];
    let manifest = &export["manifest"]["signed"];
    let assignment = named(&sealed, "cases", "task_items record of an assignment");
    let record: Value =
        serde_json::from_str(st(assignment, "plaintext")).expect("assignment record");
    let message = &record["messages"][0]["plaintext"];
    let json = b64(st(message, "json"));
    let body: Value = serde_json::from_slice(&json).expect("message JSON");
    let proof = &named(&chain, "transition_proofs", "claim attempt (seq 7)")["signed"];
    let head = &chain["signed_heads"][0]["head"];
    let push = &http["webhook"];
    let handover = &envelopes["signer_handover"];
    let backup = &envelopes["signer_backup"];
    [
        doc(APP_CERT, "wallet certificate"),
        doc(APP_RECORD, "wallet app record"),
        doc(RECEIVE_KEY, "wallet receive key record"),
        doc(IDENTITY, "alice identity.json"),
        carried(
            KEY_BUNDLE,
            [
                ("identity", app.identity.to_vec()),
                (
                    "app ID",
                    app_id_decode(&app.app_id).expect("bundle app").to_vec(),
                ),
                ("envelope bytes", b64(st(&bundle["bundle"], "envelope"))),
            ],
            st(&bundle["bundle"], "sig"),
        ),
        doc(FREEZE, "alice freeze"),
        carried(
            UNFREEZE,
            [
                ("identity", alice.to_vec()),
                ("freeze hash", b64(st(unfreeze, "freeze_hash"))),
            ],
            st(unfreeze, "sig"),
        ),
        carried(
            DISCARDED,
            [
                ("identity", alice.to_vec()),
                ("freeze hash", b64(st(discarded, "discarded"))),
            ],
            st(discarded, "sig"),
        ),
        carried(
            EXPORT_MANIFEST,
            [
                ("identity", alice.to_vec()),
                ("body", b64(st(manifest, "body"))),
            ],
            st(manifest, "sig"),
        ),
        doc(ENROLL, "alice enrollment"),
        carried(
            MSG,
            [
                ("recipient identity", pubky(st(&body, "to")).to_vec()),
                ("message JSON bytes", json),
            ],
            st(message, "signature"),
        ),
        exchange(HTTP, "requests", "own app: long-poll feed read"),
        exchange(
            HTTP_RESPONSE,
            "responses",
            "own app: feed page, with the head header",
        ),
        item(OP, 7),
        item(SERVICE_OP, 9),
        carried(
            PROOF,
            [
                ("identity", alice.to_vec()),
                ("body", b64(st(proof, "body"))),
            ],
            st(proof, "sig"),
        ),
        carried(
            HEAD,
            [
                ("identity", alice.to_vec()),
                (
                    "u64(chain version)",
                    int(head, "chain_version").to_be_bytes().to_vec(),
                ),
                (
                    "u64(generation)",
                    int(head, "generation").to_be_bytes().to_vec(),
                ),
                ("u64(seq)", int(head, "seq").to_be_bytes().to_vec()),
                ("chain hash", b64(st(head, "chain_hash"))),
            ],
            st(head, "sig"),
        ),
        carried(
            PUSH,
            [
                ("relay origin", st(push, "relay_origin").as_bytes().to_vec()),
                ("body", st(push, "body").as_bytes().to_vec()),
            ],
            st(&push["headers"], http::header::SIGNATURE),
        ),
        doc(APP_REQUEST, "wallet app request"),
        doc(
            EXPORT_TRANSFER,
            "alice export transfer, for export.json's manifest",
        ),
        exchange(
            TRANSFER_REQUEST,
            "requests",
            "next service: export chunk fetch under the export transfer",
        ),
        signer_record(SIGNER_HANDOVER, handover, &handover["handover"]),
        signer_record(SIGNER_BACKUP, backup, &backup["backup"]),
    ]
}

/// Select the fixed key of the signer named in a signature case.
fn signer(keys: &Keys, case: &Value) -> SigningKey {
    let alice = keys.identity("alice");
    let public = match st(case, "signer") {
        "identity key" => alice,
        "app" => keys.app("wallet").signing_public,
        "sender app" => keys.app("shop").signing_public,
        "service key" => keys.service_key(&enc::pubky_id(&alice)),
        "next service key" | "the next service's key" => keys.next_service_key,
        other => panic!("unknown signer {other}"),
    };
    SigningKey::from_bytes(&keys.secret(&public).expect("fixed signing key"))
}

/// Verify the signature on the carrier before emitting it under its wire label.
fn ordinary(keys: &Keys, case: &Value, (label, fields, carried): &Carrier) {
    let (names, mut bytes): (Vec<_>, Vec<_>) = fields
        .iter()
        .map(|(name, bytes)| (name.as_str(), bytes.as_slice()))
        .unzip();
    let key = signer(keys, case);
    let public = key.verifying_key().to_bytes();
    let signature = sig::sign(&key, label, &bytes);
    assert_eq!(&signature, carried, "{label}: carrier signature");
    sig::verify(&public, label, &bytes, &signature).unwrap_or_else(|e| panic!("{label}: {e}"));
    generated_case(label, &names, &bytes, &signature);
    generated_members(
        "signatures.json",
        &case_path(label),
        &[("public_key", json!(enc::b64(&public)))],
    );

    let other = if *label == labels::sig::APP_CERT {
        labels::sig::APP_RECORD
    } else {
        labels::sig::APP_CERT
    };
    assert!(sig::verify(&public, other, &bytes, &signature).is_err());
    let mut longer = bytes[0].to_vec();
    longer.push(0);
    bytes[0] = &longer;
    assert!(sig::verify(&public, label, &bytes, &signature).is_err());
}

/// The message field and signature of a single verifier example.
struct Example {
    label: &'static str,
    message: Vec<u8>,
    public: [u8; 32],
    signature: [u8; 64],
}

impl Example {
    /// Frame the message and emit the bytes a verifier receives.
    fn members(&self) -> Vec<(&'static str, Value)> {
        let signed = sig::signed_bytes(self.label, &[&self.message]);
        assert_eq!(
            label_and_fields(&signed),
            (self.label.into(), vec![self.message.clone()])
        );
        vec![
            ("label", json!(self.label)),
            ("signed_bytes_hex", json!(hex::encode(signed))),
            ("public_key", json!(enc::b64(&self.public))),
            ("signature", json!(enc::b64(&self.signature))),
        ]
    }

    /// Check the strict verifier's step and both verifiers' pinned outcomes.
    fn check_verdicts(&self, case: &Value, step: Option<u8>) {
        let name = st(case, "name");
        let fields = [self.message.as_slice()];
        let result = sig::verify(&self.public, self.label, &fields, &self.signature);
        let reason = if let Some(step) = step {
            let error = result.expect_err("a refused signature");
            let (actual, reason) = refusal(&error);
            assert_eq!(actual, step, "{name}: {error}");
            Some(reason)
        } else {
            result.expect("the mixed-order key is taken");
            None
        };
        assert_eq!(Some(&json!(reason)), case.get("reason"), "{name}: reason");
        assert_eq!(
            lenient_accepts(
                &self.public,
                &sig::signed_bytes(self.label, &fields),
                &self.signature,
            ),
            case["lenient_accepts"]
                .as_bool()
                .expect("pinned lenient verdict"),
            "{name}: lenient_accepts"
        );
    }
}

/// The certificate faults reuse the exact body and signature of the wallet certificate.
fn certificate_rejection(case: &Value, path: &str, cert: &Carrier, alice: [u8; 32]) {
    use labels::sig::{APP_CERT, APP_RECORD};
    let (_, fields, signature) = cert;
    let (label, public, signature, step) = match st(case, "name") {
        "non-canonical S" => {
            let changed = noncanonical_s(*signature);
            assert_eq!(changed[..32], signature[..32]);
            assert_ne!(changed[32..], signature[32..]);
            (APP_CERT, alice, changed, 1)
        }
        "small-order public key" => {
            let identity = EIGHT_TORSION[0].compress().to_bytes();
            let mut signature = [0; 64];
            signature[..32].copy_from_slice(&identity);
            (APP_CERT, identity, signature, 3)
        }
        "another label" => (APP_RECORD, alice, *signature, 4),
        name => panic!("unknown certificate rejection {name}"),
    };
    let example = Example {
        label,
        message: fields[0].1.clone(),
        public,
        signature,
    };
    example.check_verdicts(case, Some(step));
    generated_members("signatures.json", path, &example.members());
}

/// Encode a small Edwards y-coordinate as y + p, using the order-two point's y = p - 1.
fn noncanonical_y(y: u8) -> [u8; 32] {
    let mut bytes = EIGHT_TORSION[4].compress().to_bytes();
    bytes[0] += 1 + y;
    let point = CompressedEdwardsY(bytes)
        .decompress()
        .expect("point at y + p");
    let mut canonical = [0; 32];
    canonical[0] = y;
    assert_eq!(point.compress().to_bytes(), canonical);
    bytes
}

/// Find the first framed message whose reduced Ed25519 challenge has the chosen residue.
fn edge_challenge(
    short: &str,
    public: &[u8; 32],
    commitment: &[u8; 32],
    residue: Option<u8>,
) -> (u64, Vec<u8>, Scalar) {
    for counter in 0..=u64::MAX {
        // Name-free text, so a later change of the protocol's names leaves it as it is.
        let message = format!("edge case: {short} {counter}").into_bytes();
        let signed = sig::signed_bytes(labels::sig::APP_RECORD, &[&message]);
        let hash = Sha512::new()
            .chain_update(commitment)
            .chain_update(public)
            .chain_update(signed)
            .finalize();
        let k = Scalar::from_bytes_mod_order_wide(&hash.into());
        if residue.is_none_or(|n| k.to_bytes()[0] % 8 == n) {
            return (counter, message, k);
        }
    }
    unreachable!("no message with the chosen challenge")
}

/// Build the curve points, challenge and response from the case's seed labels and torsion index.
fn curve_case(case: &Value, path: &str) {
    let name = st(case, "name");
    let a = Scalar::from_bytes_mod_order(seed(st(case, "seed_a")));
    let (nonce, commitment) = match name {
        "small-order R" => (Scalar::ZERO, EIGHT_TORSION[4].compress().to_bytes()),
        "non-canonical R" => (Scalar::ZERO, noncanonical_y(1)),
        _ => {
            let r = Scalar::from_bytes_mod_order(seed(st(case, "seed_r")));
            (r, EdwardsPoint::mul_base(&r).compress().to_bytes())
        }
    };
    let torsion = || {
        let index = int(case, "torsion_index");
        assert!(index < 8 && index % 2 == 1, "T must have order eight");
        EIGHT_TORSION[usize::try_from(index).expect("torsion index")]
    };
    let mixed = || {
        (EdwardsPoint::mul_base(&a) + torsion())
            .compress()
            .to_bytes()
    };
    let (public, short, residue, step) = match name {
        "mixed-order public key" => (mixed(), "mixed-order key", Some(0), None),
        "cofactored equation only" => (mixed(), "cofactored only", Some(1), Some(4)),
        "small-order R" => (mixed(), "small-order R", Some(4), Some(3)),
        "non-canonical R" => (mixed(), "non-canonical R", Some(0), Some(2)),
        "non-canonical public key" => {
            let public = noncanonical_y(3);
            let decoded = CompressedEdwardsY(public)
                .decompress()
                .expect("point at y = 3");
            assert!(!decoded.is_small_order());
            (public, "non-canonical public key", None, Some(2))
        }
        "small-order public key of order 8" => (
            torsion().compress().to_bytes(),
            "small-order public key",
            None,
            Some(3),
        ),
        _ => panic!("unknown curve example {name}"),
    };
    let (counter, message, k) = edge_challenge(short, &public, &commitment, residue);
    let s = nonce + k * a;
    if let Some(residue) = residue {
        let lhs = EdwardsPoint::mul_base(&s);
        let rhs = CompressedEdwardsY(commitment).decompress().expect("R")
            + k * CompressedEdwardsY(public).decompress().expect("public key");
        assert_eq!(lhs.mul_by_cofactor(), rhs.mul_by_cofactor(), "{name}");
        assert_eq!(lhs == rhs, residue != 1, "{name}");
    }
    let mut signature = [0; 64];
    signature[..32].copy_from_slice(&commitment);
    signature[32..].copy_from_slice(&s.to_bytes());
    let example = Example {
        label: labels::sig::APP_RECORD,
        message,
        public,
        signature,
    };
    let mut members = example.members();
    members.extend([
        ("counter", json!(counter)),
        (
            "fields",
            json!([{"name": "body", "hex": hex::encode(&example.message)}]),
        ),
    ]);
    example.check_verdicts(case, step);
    generated_members("signatures.json", path, &members);
}

/// Reproduce each wire signature and exercise the accepted and refused examples.
#[test]
pub(super) fn test_vectors_signatures() {
    let keys = keys();
    let file = load("signatures.json");
    let carriers = carriers(&keys);
    let cases = arr(&file, "signatures");
    assert_eq!(cases.len(), LABELS.len());
    for ((case, carrier), label) in cases.iter().zip(&carriers).zip(LABELS) {
        assert_eq!(carrier.0, label);
        ordinary(&keys, case, carrier);
    }
    let cert = &carriers[0];
    assert_eq!(cert.0, labels::sig::APP_CERT);
    for (i, case) in arr(&file, "rejections").iter().enumerate() {
        let path = format!("/rejections/{i}");
        match st(case, "name") {
            "non-canonical S" | "small-order public key" | "another label" => {
                certificate_rejection(case, &path, cert, keys.identity("alice"));
            }
            _ => curve_case(case, &path),
        }
    }
    let [accepted] = arr(&file, "accepted").as_slice() else {
        panic!("one accepted case")
    };
    assert_eq!(st(accepted, "name"), "mixed-order public key");
    curve_case(accepted, "/accepted/0");
}

/// The published signatures verify over the exact fields held by their carriers.
#[test]
fn test_vectors_signatures_match_their_carriers() {
    let file = load("signatures.json");
    let cases = arr(&file, "signatures");
    let carriers = carriers(&keys());
    assert_eq!(cases.len(), carriers.len());
    for (case, (label, fields, signature)) in cases.iter().zip(carriers) {
        assert_eq!(st(case, "label"), label);
        assert_eq!(b64n::<64>(st(case, "signature")), signature, "{label}");
        let refs: Vec<_> = fields.iter().map(|(_, f)| f.as_slice()).collect();
        sig::verify(&b64n(st(case, "public_key")), label, &refs, &signature)
            .unwrap_or_else(|e| panic!("{label}: carrier signature: {e}"));
    }
}
