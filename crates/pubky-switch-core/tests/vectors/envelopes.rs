//! `envelopes.json`: envelopes to one and three recipients in every bucket, with every input
//! and intermediate value, the bucket boundaries, envelopes to refuse, and the envelopes of
//! key bundles, the signer hand-over and the signer backup, with the parts and hand-overs to
//! refuse (Switch wire 3.5, 3.8, 3.12, 3.13, 4, 5.1).

use pubky_switch_core::enc;
use pubky_switch_core::enc::{app_id_decode, kid, zbase32_encode};
use pubky_switch_core::envelope::{self, Recipient};
use pubky_switch_core::keys::{AppKeys as SigningApp, IdentityKey, ReceiveKey};
use pubky_switch_core::labels;
use pubky_switch_core::message::{Message, MessagePlaintext, VerifiedSender, message_hash};
use pubky_switch_core::ops::KeyBundlePut;
use pubky_switch_core::records::{
    self, BundlePart, IdentityDoc, KeyBundle, KeyBundleContents, PartReader, RestoreStart,
    SignerBackup, SignerHandover, SignerRecords, SkipReason, StoredPart,
};
use pubky_switch_core::{Error, ident};
use serde_json::{Value, json};

use crate::common::*;
use crate::documents::IssuedDocuments;

/// A case's envelope, by name.
fn case<'a>(v: &'a Value, name: &str) -> &'a Value {
    arr(v, "cases")
        .iter()
        .find(|c| st(c, "name") == name)
        .unwrap_or_else(|| panic!("no case {name}"))
}

/// The step of Switch wire 4.3 an opening error names.
fn refusing_step(error: &pubky_switch_core::Error) -> u8 {
    let text = error.to_string();
    (1..=6)
        .find(|step| text.contains(&format!("Switch wire 4.3 step {step}:")))
        .unwrap_or_else(|| panic!("no step named in {text}"))
}

/// The app of `keys.json` whose App ID bytes these are.
fn app_of<'a>(keys: &'a Keys, app_id: &[u8; 16]) -> &'a AppKeys {
    keys.app_by_id(&zbase32_encode(app_id))
}

/// The computed members of an envelope case.
fn emit(path: &str, members: &[(&str, Value)]) {
    generated_members("envelopes.json", path, members);
}

/// The chosen message body and time, addressed from the shop to Alice.
fn message(keys: &Keys, c: &Value, body: Value, refs: Vec<[u8; 32]>) -> Message {
    let shop = keys.app("shop");
    Message {
        from: pubky_switch_core::message::Sender::of_app(
            shop.identity,
            &SigningApp::from_secrets(shop.signing_secret, shop.bundle_secret),
        ),
        to: keys.identity("alice"),
        msg_id: uuid_from_seed(st(c, "msg_id_seed_label")),
        kind: st(c, "kind").into(),
        created_at_ms: pubky_switch_core::time::parse_rfc3339(st(c, "created_at")).unwrap(),
        refs,
        body: body.as_object().unwrap().clone(),
    }
}

/// The recurring assignment referenced by the cancellation and the dated record key.
pub(super) fn recurring_assignment_hash(keys: &Keys) -> [u8; 32] {
    let file = load("envelopes.json");
    let messages = &file["messages"];
    let recurring = &messages["assignment"];
    message_hash(
        &message(keys, recurring, recurring["body"].clone(), vec![])
            .to_json()
            .unwrap(),
    )
}

/// Describe the message kinds and the seeds, names and paths used in the sealed records.
fn descriptions(file: &Value) {
    let messages = &file["messages"];
    let text = format!(
        "Binary envelopes (wire 4) with fixed randomness: content key, body nonce, and per recipient the HPKE \
         ephemeral keying material ikmE (RFC 9180 DeriveKeyPair, so skE follows). Each envelope opens for every \
         listed recipient with its receive secret to the given plaintext (wire 4.5) followed by zeros. Two \
         messages, both from bob's shop to alice: a {} in the 1 KiB bucket, and a {} padded with msg_ids ({}) in \
         the larger ones. Suite {}: HPKE base mode DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, ChaCha20-Poly1305 \
         wrapping the content key; XChaCha20-Poly1305 body with the whole header as AAD.",
        st(&messages["cancellation"], "kind"),
        st(&messages["resend"], "kind"),
        st(&messages["resend"], "item_seed_prefix"),
        envelope::SUITE,
    );
    emit("", &[("description", json!(text))]);
    let text = format!(
        "Wire 3.12: alice's signer hands her identity to the signer in her phone app. Its JSON is split in two at \
         its middle byte, and each part goes in its own envelope to the bundle key the phone's certificate names \
         (documents.json), notify off, HPKE info naming alice and that key's kid, plaintext u32_be(len) | part | \
         zeros; alice's identity key signs lp(\"{}\", identity, the phone's App ID, u32_be(2), envelope 1 bytes, \
         envelope 2 bytes) (signatures.json). The parts, concatenated in order, are plaintext_json: alice's \
         identity key, her identity.json version 3 (documents.json), the App ID she revoked, the certificates that \
         document references (its listed apps'), the switch's limits and the key bundle part stored for the \
         executor (bundle_parts: the key_bundle above, data epoch 2, made for the executor's certificate). It opens \
         only with the phone's bundle secret. The signer stores it at the switch for the phone (http.json).",
        labels::sig::SIGNER_HANDOVER,
    );
    emit("/signer_handover", &[("note", json!(text))]);
    let (directory, _) = records::SIGNER_BACKUP_PATH[1..]
        .split_once('/')
        .expect("backup path");
    let text = format!(
        "Wire 3.13: alice's signer backup, as her signer writes it on her Homeserver at path, under /{directory}, \
         which the Homeserver serves only to her sessions whose capabilities cover it. Its JSON, plaintext_json, is \
         a backup's plaintext: signer_handover's records with kind {}, without identity_secret, and with prev, the \
         document hash of her version 1, which version 3 builds on. It is in one part, in an envelope to her backup \
         key (keys.json backup_public, derived from her identity secret), sealed with the seed {}, notify off, HPKE \
         info naming alice and that key's kid, plaintext u32_be(len) | JSON | zeros; alice's identity key signs \
         lp(\"{}\", identity, u32_be(1), envelope bytes) (signatures.json). It opens only with her backup secret, \
         which only the identity key derives.",
        records::BACKUP_KIND,
        st(&file["signer_backup"], "seal_seed_label"),
        labels::sig::SIGNER_BACKUP,
    );
    emit("/signer_backup", &[("note", json!(text))]);
    let labels: Vec<_> = arr(&file["key_bundle_rejections"], "cases")
        .iter()
        .map(|c| st(c, "seal_seed_label"))
        .collect();
    let indexed = labels
        .first()
        .and_then(|label| label.strip_suffix("/0"))
        .filter(|prefix| {
            labels
                .iter()
                .enumerate()
                .all(|(i, label)| *label == format!("{prefix}/{i}"))
        });
    let [cek, nonce, ikm_e] = SEAL_SEED_SUFFIXES;
    let seeds = match indexed {
        Some(prefix) => {
            format!("{prefix}/<n>/{cek}, /{nonce}, /{ikm_e}, <n> the case's index in cases, from 0")
        }
        None => labels
            .iter()
            .map(|label| seal_seed_labels(label).join(", "))
            .collect::<Vec<_>>()
            .join("; "),
    };
    let text = format!(
        "Wire 3.5 Reading: key bundle parts the executor skips although each verifies and opens with its bundle \
         secret (key_bundle.bundle_secret_hex): each is key_bundle's part at data epoch 2 changed once, sealed with \
         fixed randomness (seeds {seeds}) and signed by alice's identity key. A part's keys are exactly one for \
         each keyed scope of the certificate its cert names and each data epoch of its range, and cert names a \
         certificate the reader takes parts for. The executor holds documents.json's executor certificate. reason \
         is the prototype's wording.",
    );
    emit("/key_bundle_rejections", &[("description", json!(text))]);
}

/// Seal each message, retain its envelope for the refusal cases, and open every wrap.
#[test]
pub(super) fn test_vectors_envelopes() {
    envelope_cases();
}

/// The signed hand-over delivered and fetched over HTTP.
pub(super) fn envelope_cases() -> (SignerHandover, KeyBundlePut) {
    let file = load("envelopes.json");
    super::generation::check_annotations("envelopes.json", &file);
    let keys = keys();
    let shop = keys.app("shop");
    let signer = SigningApp::from_secrets(shop.signing_secret, shop.bundle_secret);
    let messages = &file["messages"];
    let reference = recurring_assignment_hash(&keys);
    let cancel = &messages["cancellation"];
    let small = message(&keys, cancel, cancel["body"].clone(), vec![reference])
        .sign(&signer)
        .unwrap()
        .encode();
    let resend = &messages["resend"];
    let mut envelopes = std::collections::HashMap::new();
    for (i, c) in arr(&file, "cases").iter().enumerate() {
        let plaintext = if let Some(count) = c.get("resend_count") {
            let prefix = st(resend, "item_seed_prefix");
            let ids: Vec<_> = (0..count.as_u64().unwrap())
                .map(|n| uuid_from_seed(&format!("{prefix}/{n}")))
                .collect();
            message(&keys, resend, json!({"msg_ids":ids}), vec![])
                .sign(&signer)
                .unwrap()
                .encode()
        } else {
            small.clone()
        };
        let bytes = envelope_case(&keys, c, i, &plaintext);
        assert!(envelopes.insert(st(c, "name"), bytes).is_none());
    }
    check_rejections(&keys, &file, &envelopes, &small);
    for b in arr(&file, "bucket_fit") {
        let bucket = envelope::bucket_for(
            int(b, "recipients") as usize,
            int(b, "plaintext_len") as usize,
        );
        assert_eq!(json!(bucket), b["bucket"], "bucket fit {b}");
    }
    let docs = IssuedDocuments::from_fixture(&keys);
    let (stored, put) = bundle_cases(&keys, &file, &docs);
    let handover = signer_handover_case(&keys, &file, &docs, &stored);
    signer_backup_case(&keys, &file, &docs, &stored);
    descriptions(&file);
    (handover, put)
}

/// The marker, header, body AAD and wrapped keys come from the sealed bytes in wire order.
fn envelope_case(keys: &Keys, c: &Value, index: usize, plaintext: &[u8]) -> Vec<u8> {
    let name = st(c, "name");
    let path = format!("/cases/{index}");
    let identity = keys.identity("alice");
    let content_key = seed(st(c, "cek_seed_label"));
    let nonce = seed(st(c, "nonce_seed_label"))[..24].try_into().unwrap();
    let notify = c["notify"].as_bool().unwrap();
    let wraps = arr(c, "recipients");
    let recipients: Vec<_> = wraps
        .iter()
        .map(|r| Recipient::new(keys.app(st(r, "app")).receive_public))
        .collect();
    let ikm: Vec<_> = wraps
        .iter()
        .map(|r| seed(st(r, "ikm_e_seed_label")))
        .collect();
    let bytes = envelope::seal_with(
        &identity,
        &recipients,
        plaintext,
        notify,
        &content_key,
        &nonce,
        &ikm,
    )
    .unwrap();
    let header = envelope::check_at_inbox(&bytes).unwrap();
    assert_eq!(header.notify, notify);
    assert_eq!(header.nonce, nonce);
    assert_eq!(
        header.key_commitment,
        envelope::key_commitment(&content_key)
    );
    assert_eq!(header.wraps.len(), wraps.len());
    assert_eq!(
        name,
        format!("{} recipient(s), {} KiB", wraps.len(), bytes.len() / 1024)
    );
    assert_eq!(
        envelope::bucket_for(wraps.len(), plaintext.len()),
        Some(bytes.len())
    );
    emit(
        &path,
        &[
            ("recipient_identity_hex", json!(hex::encode(identity))),
            ("cek_hex", json!(hex::encode(content_key))),
            ("nonce_hex", json!(hex::encode(nonce))),
            (
                "key_commitment_hex",
                json!(hex::encode(header.key_commitment)),
            ),
            ("plaintext_hex", json!(hex::encode(plaintext))),
            ("plaintext_len", json!(plaintext.len())),
            ("envelope", json!(enc::b64(&bytes))),
            ("envelope_len", json!(bytes.len())),
            ("header_hex", json!(hex::encode(&bytes[..header.len()]))),
            (
                "hpke_aad_hex",
                json!(hex::encode(&bytes[..envelope::FIXED_HEADER_LEN])),
            ),
        ],
    );
    for (j, r) in wraps.iter().enumerate() {
        let app = keys.app(st(r, "app"));
        let wrap = &header.wraps[j];
        let (sk_e, enc) = envelope::ephemeral_key(&ikm[j]);
        assert_eq!(wrap.kid, app.receive_kid);
        assert_eq!(wrap.enc, enc);
        emit(
            &format!("{path}/recipients/{j}"),
            &[
                ("receive_secret_hex", json!(hex::encode(app.receive_secret))),
                ("receive_public", json!(enc::b64(&app.receive_public))),
                ("kid", json!(enc::b64(&wrap.kid))),
                (
                    "hpke_info_hex",
                    json!(hex::encode(envelope::hpke_info(&identity, &wrap.kid))),
                ),
                ("ikm_e_hex", json!(hex::encode(ikm[j]))),
                ("sk_e_hex", json!(hex::encode(sk_e))),
                ("enc_hex", json!(hex::encode(enc))),
                ("wrapped_cek_hex", json!(hex::encode(wrap.wrapped_key))),
            ],
        );
        assert_eq!(
            envelope::content_key_of(&bytes, &identity, &app.receive_secret).unwrap(),
            content_key
        );
        check_message(
            keys,
            name,
            &bytes,
            &identity,
            &app.receive_secret,
            plaintext,
        );
    }
    bytes
}

/// The seeded bytes HPKE requests for one ephemeral key pair.
struct EphemeralSeed<'a>(&'a [u8]);

impl hpke::rand_core::TryRng for EphemeralSeed<'_> {
    type Error = std::convert::Infallible;
    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
        std::io::Read::read_exact(&mut self.0, dst).unwrap();
        Ok(())
    }
    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        let mut bytes = [0; 4];
        self.try_fill_bytes(&mut bytes)?;
        Ok(u32::from_le_bytes(bytes))
    }
    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        let mut bytes = [0; 8];
        self.try_fill_bytes(&mut bytes)?;
        Ok(u64::from_le_bytes(bytes))
    }
}
impl hpke::rand_core::TryCryptoRng for EphemeralSeed<'_> {}

/// The second recipient unwraps a different CEK under the first key's commitment.
fn mismatched_commitment(keys: &Keys, c: &Value, plaintext: &[u8]) -> Vec<u8> {
    use chacha20poly1305::{
        XChaCha20Poly1305,
        aead::{Aead, KeyInit, Payload},
    };
    use hpke::{
        Deserializable, Kem, OpModeS, Serializable, aead::ChaCha20Poly1305, kdf::HkdfSha256,
        kem::X25519HkdfSha256,
    };
    let cek = seed(st(c, "cek_seed_label"));
    let other = seed(st(c, "other_cek_seed_label"));
    let nonce: [u8; 24] = seed(st(c, "nonce_seed_label"))[..24].try_into().unwrap();
    let identity = keys.identity("alice");
    let mut header = envelope::MAGIC.to_vec();
    header.extend([envelope::VERSION, envelope::SUITE, 0, 2]);
    header.extend(envelope::key_commitment(&cek));
    let aad = header.clone();
    for (i, (app, key)) in [(keys.app("wallet"), cek), (keys.app("phone"), other)]
        .iter()
        .enumerate()
    {
        let public = <X25519HkdfSha256 as Kem>::PublicKey::from_bytes(&app.receive_public).unwrap();
        let ikm = seed(c["ikm_e_seed_labels"][i].as_str().unwrap());
        let mut rng = EphemeralSeed(&ikm);
        let (enc, wrapped) =
            hpke::single_shot_seal_with_rng::<ChaCha20Poly1305, HkdfSha256, X25519HkdfSha256>(
                &OpModeS::Base,
                &public,
                &envelope::hpke_info(&identity, &app.receive_kid),
                key,
                &aad,
                &mut rng,
            )
            .unwrap();
        assert!(rng.0.is_empty());
        header.extend(app.receive_kid);
        header.extend_from_slice(&enc.to_bytes());
        header.extend(wrapped);
    }
    let mut padded = plaintext.to_vec();
    padded.resize(
        envelope::bucket_for(2, plaintext.len()).unwrap()
            - header.len()
            - envelope::NONCE_LEN
            - envelope::TAG_LEN,
        0,
    );
    let ct = XChaCha20Poly1305::new((&cek).into())
        .encrypt(
            (&nonce).into(),
            Payload {
                msg: &padded,
                aad: &header,
            },
        )
        .unwrap();
    header.extend(nonce);
    header.extend(ct);
    header
}

/// Open each changed envelope and compare the result with the published refusal.
fn check_rejections(
    keys: &Keys,
    file: &Value,
    envelopes: &std::collections::HashMap<&str, Vec<u8>>,
    plaintext: &[u8],
) {
    let alice = keys.identity("alice");
    for (i, c) in arr(file, "rejections").iter().enumerate() {
        let path = format!("/rejections/{i}");
        if let Some(change) = c.get("change") {
            let source = st(c, "case");
            let mut bytes = envelopes[source].clone();
            let flip = match change.as_str().unwrap() {
                "flip the notify bit (byte 6)" => true,
                "open with bob's identity in the HPKE info" => false,
                other => panic!("unknown envelope change {other}"),
            };
            let id = if flip {
                bytes[envelope::MAGIC.len() + 2] ^= envelope::FLAG_NOTIFY;
                emit(&path, &[("envelope", json!(enc::b64(&bytes)))]);
                alice
            } else {
                keys.identity("bob")
            };
            envelope::check_at_inbox(&bytes).unwrap();
            for r in arr(case(file, source), "recipients") {
                let error = envelope::open(&bytes, &id, &keys.app(st(r, "app")).receive_secret)
                    .unwrap_err();
                assert_eq!(refusing_step(&error), 3);
                assert_eq!(
                    st(c, "result"),
                    if flip {
                        "rejected (HPKE AAD and body AAD)"
                    } else {
                        "rejected"
                    }
                );
            }
        } else {
            assert_eq!(st(c, "name"), "forged key commitment");
            let bytes = mismatched_commitment(keys, c, plaintext);
            emit(
                &path,
                &[
                    ("envelope", json!(enc::b64(&bytes))),
                    ("recipient_identity_hex", json!(hex::encode(alice))),
                ],
            );
            let mut opened = Vec::new();
            let mut rejected = Vec::new();
            for name in ["wallet", "phone"] {
                let app = keys.app(name);
                match MessagePlaintext::open(&bytes, &alice, &app.receive_secret) {
                    Ok(message) => {
                        assert_eq!(message.encode(), plaintext);
                        opened.push(name);
                    }
                    Err(error) => {
                        assert!(
                            matches!(&error, Error::Crypto(reason) if reason ==
                            "Switch wire 4.3 step 4: the content key doesn't match the key commitment"),
                            "{error}"
                        );
                        rejected.push(name);
                    }
                }
            }
            assert_eq!(json!(opened), c["opens_for"]);
            let [expected] = arr(c, "rejected_by").as_slice() else {
                panic!("one refusal")
            };
            let app = keys.app(st(expected, "app"));
            assert_eq!(rejected, [app.name.as_str()]);
            assert_eq!(st(expected, "reason"), "key commitment mismatch");
            emit(
                &format!("{path}/rejected_by/0"),
                &[("receive_secret_hex", json!(hex::encode(app.receive_secret)))],
            );
        }
    }
}

/// The CEK, nonce, ephemeral seed and HPKE secret of a single-recipient envelope.
fn emit_randomness(path: &str, r: &envelope::FixedRandomness) {
    let (sk_e, _) = envelope::ephemeral_key(&r.ikm_e);
    emit(
        path,
        &[
            ("cek_hex", json!(hex::encode(r.content_key))),
            ("nonce_hex", json!(hex::encode(r.nonce))),
            ("ikm_e_hex", json!(hex::encode(r.ikm_e))),
            ("sk_e_hex", json!(hex::encode(sk_e))),
        ],
    );
}

/// Sign and seal the exact contents, including the single change of a refused part.
fn seal_bundle(
    keys: &Keys,
    app: &AppKeys,
    c: &Value,
    path: &str,
    contents: &KeyBundleContents,
) -> KeyBundle {
    let json = contents.to_json().unwrap();
    let r = fixed_from_seeds(st(c, "seal_seed_label"));
    let bundle = KeyBundle::seal_json_with(
        &keys.identity_key(&app.identity),
        &app_id_decode(&app.app_id).unwrap(),
        &app.bundle_public,
        &json,
        &r,
    )
    .unwrap();
    emit(
        path,
        &[
            ("bundle", json!(bundle)),
            ("plaintext_json", json!(std::str::from_utf8(&json).unwrap())),
        ],
    );
    if path == "/key_bundle" {
        emit(
            path,
            &[
                (
                    "framed_hex",
                    json!(hex::encode(envelope::frame(&json).unwrap())),
                ),
                ("envelope_len", json!(bundle.envelope().len())),
            ],
        );
    }
    if c.get("app").is_some() {
        emit_randomness(path, &r);
        emit(
            path,
            &[
                ("bundle_kid", json!(enc::b64(&kid(&app.bundle_public)))),
                ("bundle_secret_hex", json!(hex::encode(app.bundle_secret))),
            ],
        );
    }
    bundle
}

/// The incremental part, its four faults, and the renewed wallet's full part.
fn bundle_cases(keys: &Keys, file: &Value, docs: &IssuedDocuments) -> (StoredPart, KeyBundlePut) {
    let c = &file["key_bundle"];
    let app = keys.app(st(c, "app"));
    let cert = &docs.certs[&app.name];
    let first = int(c, "first_epoch");
    let last = int(c, "last_epoch");
    let scopes = keyed_scopes(file);
    let has_keys = |s: &str| scopes.contains(s);
    let contents = KeyBundleContents::derive(
        &keys.identity_key(&app.identity),
        cert,
        first,
        last,
        &has_keys,
    )
    .unwrap();
    let bundle = seal_bundle(keys, app, c, "/key_bundle", &contents);
    let put = KeyBundlePut {
        target_app_id: cert.app_id(),
        bundle,
        first_epoch: first,
        last_epoch: last,
    };
    let stored = StoredPart {
        app_id: cert.app_id(),
        first_epoch: first,
        last_epoch: last,
        cert: cert.hash(),
    };
    let certs = [cert];
    let reader = PartReader {
        identity: app.identity,
        app_id: cert.app_id(),
        bundle_secret: &app.bundle_secret,
        certs: &certs,
        newest_epoch: docs.identities["alice identity.json"].data_epoch(),
        has_keys: &has_keys,
    };
    for (i, r) in arr(&file["key_bundle_rejections"], "cases")
        .iter()
        .enumerate()
    {
        let mut bad = contents.clone();
        match st(r, "name") {
            "extra scope" => {
                let scope = st(r, "scope");
                bad.keys.keys.push(pubky_switch_core::keys::ScopeKey {
                    data_epoch: last,
                    scope: scope.into(),
                    key: keys.identity_key(&app.identity).scope_key(last, scope),
                });
            }
            "duplicate pair" => {
                let mut duplicate = bad.keys.keys[0].clone();
                duplicate.key = seed(st(r, "key_seed_label"));
                bad.keys.keys.insert(1, duplicate);
            }
            "missing pair" => bad.keys.keys.retain(|k| k.scope != st(r, "scope")),
            "unknown certificate" => bad.cert = docs.certs["wallet"].hash(),
            other => panic!("unknown bundle rejection {other}"),
        }
        let path = format!("/key_bundle_rejections/cases/{i}");
        let bundle = seal_bundle(keys, app, r, &path, &bad);
        bundle.verify(&app.identity, &cert.app_id()).unwrap();
        let opened =
            envelope::open_framed(bundle.envelope(), &app.identity, &app.bundle_secret).unwrap();
        assert_eq!(opened.as_slice(), bad.to_json().unwrap().as_slice());
        let part = part(&bundle, first, last);
        let why = reader.open_part(&part).unwrap_err();
        let reading = reader.read(&[part], None).unwrap();
        assert!(reading.taken.is_empty() && reading.keys.keys.is_empty());
        let reason = match why {
            SkipReason::UnknownCert => "the part names a certificate the app doesn't hold".into(),
            SkipReason::WrongKeys(why) if why.contains("doesn't hold") => format!(
                "a key for {}, a scope the certificate doesn't hold",
                st(r, "scope")
            ),
            SkipReason::WrongKeys(why) if why.contains("two keys") => format!(
                "two keys for {} at data epoch {last}",
                contents.keys.keys[0].scope
            ),
            SkipReason::WrongKeys(why) if why.contains("lacks") => {
                "the part lacks a key of its certificate's scopes and range".into()
            }
            why => panic!("unexpected bundle refusal {why:?}"),
        };
        assert_eq!(st(r, "reason"), reason, "{}", st(r, "change"));
        emit(
            &path,
            &[("first_epoch", json!(first)), ("last_epoch", json!(last))],
        );
    }
    let c = &file["reduction_key_bundle"];
    let app = keys.app(st(c, "app"));
    let cert = &docs.certs[&format!("{} certificate, renewed", app.name)];
    let removed: Vec<_> = records::keyed_scopes(&docs.certs[&app.name], &has_keys)
        .into_iter()
        .filter(|scope| !cert.holds_scope(scope))
        .collect();
    assert_eq!(removed, [st(c, "removed_scope")]);
    seal_bundle(
        keys,
        app,
        c,
        "/reduction_key_bundle",
        &KeyBundleContents::derive(
            &keys.identity_key(&app.identity),
            cert,
            int(c, "first_epoch"),
            int(c, "last_epoch"),
            &has_keys,
        )
        .unwrap(),
    );
    (stored, put)
}

/// Verify the published key bundles, hand-over and backup through the reader APIs.
#[test]
fn test_vectors_envelopes_readers() {
    let keys = keys();
    let file = load("envelopes.json");
    check_bucket_fit(&file);
    let keyed = keyed_scopes(&file);
    let has_keys = |scope: &str| keyed.contains(scope);
    let docs = IssuedDocuments::from_fixture(&keys);
    check_key_bundle(&keys, &docs, &file["key_bundle"], &has_keys);
    check_reduction_bundle(&keys, &docs, &file["reduction_key_bundle"], &has_keys);
    check_signer_handover(
        &keys,
        &docs,
        &file["signer_handover"],
        &file["signer_handover_rejections"],
    );
    check_signer_backup(&keys, &docs, &file["signer_backup"]);
}

/// The opened message passes the checks of Switch wire 5.1 that need no records, and is
/// rebuilt byte for byte: its JSON, its signature and its plaintext.
fn check_message(
    keys: &Keys,
    name: &str,
    bytes: &[u8],
    identity: &[u8; 32],
    secret: &[u8; 32],
    plaintext: &[u8],
) {
    let opened = MessagePlaintext::open(bytes, identity, secret).unwrap();
    assert_eq!(opened.encode(), plaintext, "{name}: plaintext");
    let sender = app_of(keys, &opened.sender_app_id());
    let verified = VerifiedSender {
        identity: sender.identity,
        app_id: app_id_decode(&sender.app_id).unwrap(),
        signing_key: sender.signing_public,
    };
    let message = opened
        .check(identity, &sender.identity, &verified, &[])
        .unwrap_or_else(|e| panic!("{name}: {e}"));
    assert!(!message.is_from_own_app());
    assert!(message.to_json().unwrap() == opened.json(), "{name}: JSON");
    // Addressed to the identity it is sealed to, and no other.
    let bob = keys.identity("bob");
    assert!(
        opened
            .check(&bob, &sender.identity, &verified, &[])
            .is_err()
    );
}

/// `bucket_fit`: the smallest bucket for a plaintext length and a recipient count, or none;
/// each sealed with fresh randomness to that length, or refused.
fn check_bucket_fit(v: &Value) {
    let identity = [0x42; 32];
    for b in arr(v, "bucket_fit") {
        let count = int(b, "recipients") as usize;
        let len = int(b, "plaintext_len") as usize;
        let keys: Vec<ReceiveKey> = (0..count)
            .map(|i| ReceiveKey::from_secret(0, *blake3::hash(&i.to_be_bytes()).as_bytes()))
            .collect();
        let recipients: Vec<Recipient> = keys.iter().map(|k| Recipient::new(k.public)).collect();
        let plaintext = vec![0x5a; len];
        match b["bucket"].as_u64() {
            Some(bucket) => {
                let sealed = envelope::seal(&identity, &recipients, &plaintext, false).unwrap();
                assert_eq!(sealed.len() as u64, bucket, "bucket fit {b}");
                let last = keys.last().expect("a recipient");
                let opened = envelope::open(&sealed, &identity, &last.secret()).unwrap();
                assert_eq!(&opened[..len], plaintext.as_slice());
            }
            None => assert!(envelope::seal(&identity, &recipients, &plaintext, false).is_err()),
        }
    }
}

fn bundle_of(value: &Value) -> KeyBundle {
    serde_json::from_value(value.clone()).unwrap()
}

/// A part with its range in the clear, as `key_bundle.put` names it.
fn part(bundle: &KeyBundle, first_epoch: u64, last_epoch: u64) -> BundlePart {
    BundlePart {
        bundle: bundle.clone(),
        first_epoch,
        last_epoch,
    }
}

/// The app's bundle key in the vector: its kid and secret are `keys.json`'s.
fn check_bundle_key(app: &AppKeys, kid_text: &str, secret_hex: &str) {
    assert_eq!(kid(&app.bundle_public), b64n::<8>(kid_text), "{}", app.name);
    assert_eq!(hx32(secret_hex), app.bundle_secret, "{}", app.name);
}

/// `key_bundle` (Switch wire 3.5): the executor's incremental part at data epoch 2, verified,
/// opened, read, and rebuilt byte for byte from the fixed keys and randomness.
fn check_key_bundle(
    keys: &Keys,
    docs: &IssuedDocuments,
    kb: &Value,
    has_keys: &dyn Fn(&str) -> bool,
) {
    let app = keys.app(st(kb, "app"));
    let alice = app.identity;
    let app_id = app_id_decode(&app.app_id).unwrap();
    check_bundle_key(app, st(kb, "bundle_kid"), st(kb, "bundle_secret_hex"));
    let bundle = bundle_of(&kb["bundle"]);
    assert_eq!(bundle.envelope().len() as u64, int(kb, "envelope_len"));
    bundle.verify(&alice, &app_id).unwrap();
    assert!(reproduce(
        keys,
        &alice,
        labels::sig::KEY_BUNDLE,
        &[&alice, &app_id, bundle.envelope()],
        &bundle.sig()
    ));
    let json = st(kb, "plaintext_json").as_bytes();
    assert_eq!(
        envelope::content_key_of(bundle.envelope(), &alice, &app.bundle_secret).unwrap(),
        fixed_from_seeds(st(kb, "seal_seed_label")).content_key
    );

    // Opened, it is the plaintext; written again, the same bytes.
    let contents = bundle.open(&alice, &app_id, &app.bundle_secret).unwrap();
    assert!(
        *contents.to_json().unwrap() == *json,
        "the plaintext written again"
    );
    assert_eq!(contents.naming_key, keys.naming(&alice));
    // Made for the executor's certificate, whose keyed scopes it holds over epoch 2: derived
    // again from the identity key, the same plaintext.
    let cert = &docs.certs["executor"];
    assert_eq!(
        contents.cert,
        cert.hash(),
        "names the executor's certificate"
    );
    let key = keys.identity_key(&alice);
    let derived = KeyBundleContents::derive(&key, cert, 2, 2, has_keys).unwrap();
    assert!(*derived.to_json().unwrap() == *json, "derived again");
    records::check_bundle_keys(&contents, cert, has_keys).unwrap();
    let root = keys.root(&alice);
    for k in &contents.keys.keys {
        assert_eq!(k.key, ident::key_of_scope(&root, k.data_epoch, &k.scope));
    }
    // Read as the executor reads its parts, with alice's version 3 (data epoch 2).
    let newest = &docs.identities["alice identity.json"];
    let certs = [cert];
    let reader = PartReader {
        identity: alice,
        app_id,
        bundle_secret: &app.bundle_secret,
        newest_epoch: newest.data_epoch(),
        certs: &certs,
        has_keys,
    };
    let reading = reader.read(&[part(&bundle, 2, 2)], None).unwrap();
    assert_eq!(reading.taken, [(2, 2)]);
    assert!(reading.skipped.is_empty());
    // Relabelled in the clear, it is skipped.
    let relabelled = reader.read(&[part(&bundle, 1, 2)], None).unwrap();
    assert_eq!(relabelled.skipped[0].reason, SkipReason::Relabelled);
    // Not for another app, nor another bundle secret.
    let phone = keys.app("phone");
    let phone_id = app_id_decode(&phone.app_id).unwrap();
    assert!(bundle.open(&alice, &phone_id, &app.bundle_secret).is_err());
    assert!(bundle.open(&alice, &app_id, &phone.bundle_secret).is_err());
}

/// `reduction_key_bundle` (Switch wire 3.5, 3.8 "Reductions"): the wallet's full bundle made
/// for its renewed certificate, epochs 1 to 3, without the removed scope's keys.
fn check_reduction_bundle(
    keys: &Keys,
    docs: &IssuedDocuments,
    r: &Value,
    has_keys: &dyn Fn(&str) -> bool,
) {
    let app = keys.app(st(r, "app"));
    let alice = app.identity;
    let app_id = app_id_decode(&app.app_id).unwrap();
    check_bundle_key(app, st(r, "bundle_kid"), st(r, "bundle_secret_hex"));
    let key = keys.identity_key(&alice);
    let original = &docs.certs["wallet"];
    let renewed = &docs.certs["wallet certificate, renewed"];
    let removed = st(r, "removed_scope");
    assert!(records::is_reduction(original, renewed));
    assert!(records::reduction_rotates(original, renewed, has_keys));
    assert!(original.holds_scope(removed) && !renewed.holds_scope(removed));
    let renewing = &docs.identities["alice identity.json, wallet renewal in progress"];
    let (last, data_epoch) = records::renewal_epochs(true, 2).unwrap();
    assert_eq!((last, data_epoch), (3, renewing.data_epoch()));
    let (first_epoch, last_epoch) = (int(r, "first_epoch"), int(r, "last_epoch"));
    assert_eq!((first_epoch, last_epoch), (1, last));

    let bundle = bundle_of(&r["bundle"]);
    assert!(reproduce(
        keys,
        &alice,
        labels::sig::KEY_BUNDLE,
        &[&alice, &app_id, bundle.envelope()],
        &bundle.sig()
    ));
    let json = st(r, "plaintext_json").as_bytes();
    let contents = bundle.open(&alice, &app_id, &app.bundle_secret).unwrap();
    assert_eq!(
        contents.cert,
        renewed.hash(),
        "made for the renewed certificate"
    );
    assert!(contents.keys.keys.iter().all(|k| k.scope != removed));
    let derived =
        KeyBundleContents::derive(&key, renewed, first_epoch, last_epoch, has_keys).unwrap();
    assert!(*derived.to_json().unwrap() == *json, "derived again");
    // The signer's own split makes the same one part.
    let parts = records::seal_bundle_parts(&key, renewed, 1, last, has_keys).unwrap();
    assert_eq!(parts.len(), 1);
    assert_eq!(
        parts[0]
            .bundle
            .open(&alice, &app_id, &app.bundle_secret)
            .unwrap(),
        contents
    );

    // The wallet takes it once its newest identity.json lists the renewal, which it holds.
    let held = std::slice::from_ref(renewed);
    let p = part(&bundle, first_epoch, last_epoch);
    let read_with = |newest: &IdentityDoc| {
        let certs = records::reader_certs(original, held, newest);
        let reader = PartReader {
            identity: alice,
            app_id,
            bundle_secret: &app.bundle_secret,
            newest_epoch: newest.data_epoch(),
            certs: &certs,
            has_keys,
        };
        reader.read(std::slice::from_ref(&p), None).unwrap()
    };
    let reading = read_with(renewing);
    assert_eq!(reading.taken, [(1, 3)]);
    assert!(
        records::missing_keys(&reading.keys, renewed, has_keys, 3).is_empty(),
        "every key of the renewed certificate, epochs 1 to 3"
    );
    // Under version 3, which doesn't list the renewal, it is skipped like a stale part.
    let before = read_with(&docs.identities["alice identity.json"]);
    assert_eq!(before.skipped[0].reason, SkipReason::UnknownCert);
}

/// Assemble the signer's records from the issued documents, stored part and account limits.
fn alice_records(
    keys: &Keys,
    docs: &IssuedDocuments,
    stored: &StoredPart,
    account_created: &str,
    prev: Option<[u8; 32]>,
) -> SignerRecords {
    let alice = keys.identity("alice");
    let current = &docs.identities["alice identity.json"];
    let issued: Vec<_> = current
        .body()
        .apps
        .iter()
        .map(|app| {
            docs.certs
                .values()
                .find(|cert| cert.hash() == app.cert)
                .unwrap()
                .clone()
        })
        .collect();
    SignerRecords::new(
        keys.identity_key(&alice),
        current.clone(),
        pubky_switch_core::time::parse_rfc3339(account_created).unwrap(),
        &[keys.removed_app],
        &issued,
        super::http::enrollment_limits(),
        std::slice::from_ref(stored),
        prev,
    )
    .unwrap()
}

/// Seal the two halves of the hand-over and sign their order and count.
fn signer_handover_case(
    keys: &Keys,
    file: &Value,
    docs: &IssuedDocuments,
    stored: &StoredPart,
) -> SignerHandover {
    let case = &file["signer_handover"];
    let app = keys.app(st(case, "app"));
    let key = keys.identity_key(&app.identity);
    let app_id = app_id_decode(&app.app_id).unwrap();
    let records = alice_records(keys, docs, stored, st(file, "account_created"), None);
    let json = records.to_json().unwrap();
    let (first, second) = json.split_at(json.len() / 2);
    let parts = [first, second];
    let randomness: Vec<_> = arr(case, "parts")
        .iter()
        .map(|p| fixed_from_seeds(st(p, "seal_seed_label")))
        .collect();
    let cert = &docs.certs[&app.name];
    let handover =
        SignerHandover::seal_parts_with(&key, &app_id, &cert.bundle_key(), &parts, &randomness)
            .unwrap();
    emit(
        "/signer_handover",
        &[
            ("app_id", json!(app.app_id)),
            ("bundle_kid", json!(enc::b64(&kid(&app.bundle_public)))),
            ("bundle_secret_hex", json!(hex::encode(app.bundle_secret))),
            ("handover", json!(handover)),
            ("plaintext_json", json!(std::str::from_utf8(&json).unwrap())),
        ],
    );
    let envelopes = handover.envelopes();
    for (i, p) in parts.iter().enumerate() {
        let path = format!("/signer_handover/parts/{i}");
        emit_randomness(&path, &randomness[i]);
        emit(
            &path,
            &[
                ("part", json!(std::str::from_utf8(p).unwrap())),
                ("envelope_len", json!(envelopes[i].len())),
            ],
        );
    }
    for (i, c) in arr(&file["signer_handover_rejections"], "cases")
        .iter()
        .enumerate()
    {
        let bad = match st(c, "name") {
            "the parts swapped" => SignerHandover::from_parts(
                vec![envelopes[1].clone(), envelopes[0].clone()],
                handover.sig(),
            ),
            "the second part missing" => {
                SignerHandover::from_parts(vec![envelopes[0].clone()], handover.sig())
            }
            "a signature over u32_be(3) beside the two parts" => {
                let signature = pubky_switch_core::sig::sign(
                    &ed25519_dalek::SigningKey::from_bytes(&keys.identity_secrets[&app.identity]),
                    labels::sig::SIGNER_HANDOVER,
                    &[
                        &app.identity,
                        &app_id,
                        &3u32.to_be_bytes(),
                        &envelopes[0],
                        &envelopes[1],
                    ],
                );
                SignerHandover::from_parts(envelopes.to_vec(), signature)
            }
            name => panic!("unknown hand-over rejection {name}"),
        };
        let error = bad
            .open(&app.identity, &app_id, &app.bundle_secret)
            .unwrap_err();
        assert!(matches!(error, Error::Signature(_)) && error.to_string().contains("check 1"));
        assert_eq!(
            st(c, "reason"),
            "the hand-over isn't signed by the identity for this app, these parts and this order"
        );
        emit(
            &format!("/signer_handover_rejections/cases/{i}"),
            &[("handover", json!(bad))],
        );
    }
    handover
}

/// Back up the same records with their previous identity hash, using the backup key.
fn signer_backup_case(keys: &Keys, file: &Value, docs: &IssuedDocuments, stored: &StoredPart) {
    let alice = keys.identity("alice");
    let key = keys.identity_key(&alice);
    let v1 = &docs.identities["alice identity.json, first delivery (version 1)"];
    let records = alice_records(
        keys,
        docs,
        stored,
        st(file, "account_created"),
        Some(v1.hash()),
    );
    let json = records.to_backup_json().unwrap();
    let random = fixed_from_seeds(st(&file["signer_backup"], "seal_seed_label"));
    let backup = SignerBackup::seal_parts_with(&key, &[&json], &[random]).unwrap();
    emit_randomness("/signer_backup", &random);
    emit(
        "/signer_backup",
        &[
            ("backup", json!(backup)),
            ("backup_kid", json!(enc::b64(&kid(&key.backup_public())))),
            ("backup_secret_hex", json!(hex::encode(key.backup_secret()))),
            ("envelope_len", json!(backup.envelopes()[0].len())),
            ("path", json!(records::SIGNER_BACKUP_PATH)),
            ("plaintext_json", json!(std::str::from_utf8(&json).unwrap())),
        ],
    );
}

/// `signer_handover` and `signer_handover_rejections` (Switch wire 3.12): alice's hand-over
/// to her phone in two parts, opened, checked and rebuilt byte for byte; its take-over and
/// abort; and the hand-overs refused at check 1.
fn check_signer_handover(keys: &Keys, docs: &IssuedDocuments, h: &Value, rejections: &Value) {
    let app = keys.app(st(h, "app"));
    let alice = app.identity;
    let app_id = app_id_decode(&app.app_id).unwrap();
    check_bundle_key(app, st(h, "bundle_kid"), st(h, "bundle_secret_hex"));
    let handover: SignerHandover = serde_json::from_value(h["handover"].clone()).unwrap();
    assert_eq!(serde_json::to_value(&handover).unwrap(), h["handover"]);
    let json = st(h, "plaintext_json").as_bytes();

    // Its two parts: the JSON split at its middle byte, each in a 4 KiB envelope.
    let parts = arr(h, "parts");
    assert_eq!(parts.len(), handover.envelopes().len());
    assert_eq!(parts.len(), 2);
    let (first, second) = json.split_at(json.len() / 2);
    assert_eq!(st(&parts[0], "part").as_bytes(), first);
    assert_eq!(st(&parts[1], "part").as_bytes(), second);
    for (p, env) in parts.iter().zip(handover.envelopes()) {
        assert_eq!(env.len() as u64, int(p, "envelope_len"));
        assert_eq!(
            envelope::content_key_of(env, &alice, &app.bundle_secret).unwrap(),
            fixed_from_seeds(st(p, "seal_seed_label")).content_key
        );
    }
    let count = 2u32.to_be_bytes();
    assert!(reproduce(
        keys,
        &alice,
        labels::sig::SIGNER_HANDOVER,
        &[
            &alice,
            &app_id,
            &count,
            &handover.envelopes()[0],
            &handover.envelopes()[1]
        ],
        &handover.sig()
    ));

    // The phone opens it: checks 1 and 2.
    let records = handover.open(&alice, &app_id, &app.bundle_secret).unwrap();
    assert!(
        *records.to_json().unwrap() == *json,
        "the records written again"
    );
    assert_eq!(
        records.identity_doc().signed(),
        docs.identities["alice identity.json"].signed()
    );
    assert_eq!(records.key().public(), alice);
    assert_eq!(*records.limits(), super::http::enrollment_limits());
    assert_eq!(records.revoked_apps(), [keys.removed_app]);
    let executor = keys.app("executor");
    let executor_cert = &docs.certs["executor"];
    assert_eq!(
        records.bundle_parts(),
        [StoredPart {
            app_id: app_id_decode(&executor.app_id).unwrap(),
            first_epoch: 2,
            last_epoch: 2,
            cert: executor_cert.hash(),
        }],
        "the executor's part of key_bundle"
    );
    assert!(records.prev().is_none());
    // The switch stores it for the phone, its envelopes for the phone's bundle key alone.
    let phone_cert = &docs.certs["phone"];
    handover
        .check_stored(&alice, &app_id, &phone_cert.bundle_key())
        .unwrap();
    let wallet_id = app_id_decode(&keys.app("wallet").app_id).unwrap();
    assert!(
        handover
            .open(&alice, &wallet_id, &keys.app("wallet").bundle_secret)
            .is_err()
    );

    let key = keys.identity_key(&alice);
    // The signer's own split fits one envelope.
    let own = SignerHandover::seal(&key, phone_cert, &records).unwrap();
    assert_eq!(own.envelopes().len(), 1);
    assert!(
        *own.open(&alice, &app_id, &app.bundle_secret)
            .unwrap()
            .to_json()
            .unwrap()
            == *json
    );

    // Check 3, the take-over and the abort (documents.json's version 5).
    let v3 = records.identity_doc().clone();
    records::check_handover_copies(&records, &[&v3]).unwrap();
    let (abort, prev) = records::abort_body(&v3).unwrap();
    assert_eq!(prev, v3.hash());
    let abort = IdentityDoc::sign(&key, abort).unwrap();
    assert_eq!(
        abort.signed(),
        docs.identities["alice identity.json, hand-over abort (version 5)"].signed(),
        "the abort rebuilt"
    );
    assert!(
        records::check_handover_copies(&records, &[&abort]).is_err(),
        "an abort that won"
    );
    let (take_over, prev) = records::take_over_body(&records, [0x55; 16]).unwrap();
    assert_eq!(
        (take_over.version, take_over.signer, prev),
        (4, [0x55; 16], v3.hash())
    );
    assert!(!records::succeeded(
        &v3,
        &[abort.hash()],
        abort.version(),
        &abort.hash()
    ));
    let take_over = IdentityDoc::sign(&key, take_over).unwrap();
    assert!(records::succeeded(
        &v3,
        &[abort.hash()],
        4,
        &take_over.hash()
    ));

    // The rejections, each refused at check 1 by its signature.
    let cases = arr(rejections, "cases");
    assert!(!cases.is_empty());
    for case in cases {
        let name = st(case, "name");
        let bad: SignerHandover = serde_json::from_value(case["handover"].clone()).unwrap();
        let error = bad.open(&alice, &app_id, &app.bundle_secret).unwrap_err();
        assert!(matches!(error, Error::Signature(_)), "{name}: {error}");
        assert!(error.to_string().contains("check 1"), "{name}: {error}");
        if bad.sig() != handover.sig() {
            // A signature whose count isn't the parts': rebuilt from the identity key.
            let n = u32::try_from(bad.envelopes().len() + 1)
                .unwrap()
                .to_be_bytes();
            let mut fields: Vec<&[u8]> = vec![&alice, &app_id, &n];
            fields.extend(bad.envelopes().iter().map(Vec::as_slice));
            assert!(
                reproduce(
                    keys,
                    &alice,
                    labels::sig::SIGNER_HANDOVER,
                    &fields,
                    &bad.sig()
                ),
                "{name}"
            );
        }
    }
}

/// `signer_backup` (Switch wire 3.13): alice's backup in one part, opened with her key,
/// rebuilt byte for byte, and checked for a restore.
fn check_signer_backup(keys: &Keys, docs: &IssuedDocuments, b: &Value) {
    let alice = keys.identity("alice");
    let key = keys.identity_key(&alice);
    assert_eq!(kid(&key.backup_public()), b64n::<8>(st(b, "backup_kid")));
    assert_eq!(key.backup_secret(), hx32(st(b, "backup_secret_hex")));
    assert_eq!(st(b, "path"), records::SIGNER_BACKUP_PATH);
    let backup: SignerBackup = serde_json::from_value(b["backup"].clone()).unwrap();
    assert_eq!(backup.envelopes().len(), 1);
    let env = &backup.envelopes()[0];
    assert_eq!(env.len() as u64, int(b, "envelope_len"));
    let count = 1u32.to_be_bytes();
    assert!(reproduce(
        keys,
        &alice,
        labels::sig::SIGNER_BACKUP,
        &[&alice, &count, env],
        &backup.sig()
    ));

    let json = st(b, "plaintext_json").as_bytes();
    let records = backup.open(&key).unwrap();
    assert!(
        *records.to_backup_json().unwrap() == *json,
        "the records written again"
    );
    // A backup's plaintext holds no secret, and names its own kind.
    let plaintext: Value = serde_json::from_slice(json).unwrap();
    assert!(plaintext.get("identity_secret").is_none());
    assert_eq!(st(&plaintext, "kind"), records::BACKUP_KIND);
    let v1 = &docs.identities["alice identity.json, first delivery (version 1)"];
    assert_eq!(records.prev(), Some(v1.hash()), "prev names version 1");
    // Only the identity key opens it.
    assert!(backup.open(&IdentityKey::from_secret([7; 32])).is_err());
    let phone = keys.app("phone");
    assert!(envelope::open(env, &alice, &phone.bundle_secret).is_err());

    // The restore's check 3.
    let v3 = records.identity_doc().clone();
    assert_eq!(
        records::check_restore_copies(&records, Some(&v3), Some(&v3)).unwrap(),
        RestoreStart::AtBackup
    );
    assert_eq!(
        records::check_restore_copies(&records, Some(v1), None).unwrap(),
        RestoreStart::DeliverBackupFirst
    );
    let abort = &docs.identities["alice identity.json, hand-over abort (version 5)"];
    assert!(records::check_restore_copies(&records, Some(abort), None).is_err());
    assert!(records::check_restore_copies(&records, Some(&v3), Some(abort)).is_err());
    assert!(records::check_restore_copies(&records, None, None).is_err());
}
