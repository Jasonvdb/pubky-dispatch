//! Verification and explicit regeneration of the core's vector cases.

use std::borrow::Cow;
use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;

use pubky_switch_core::spec_vectors_dir;
use serde_json::Value;

thread_local! {
    // A file as a test changed it in memory, read in place of the published one.
    static CHANGED: RefCell<Option<(String, Value)>> = const { RefCell::new(None) };
    static PLACES: RefCell<Option<BTreeSet<(String, String)>>> = const { RefCell::new(None) };
    // Only the generator sees pending changes. Other tests read the published files.
    static STAGED: RefCell<Option<BTreeMap<String, Value>>> = const { RefCell::new(None) };
}

/// A parsed vector file, including any cases already generated on this thread.
pub fn load(name: &str) -> Value {
    if let Some(value) = CHANGED.with_borrow(|changed| {
        changed
            .as_ref()
            .filter(|(file, _)| file == name)
            .map(|(_, value)| value.clone())
    }) {
        return value;
    }
    if let Some(value) = STAGED.with_borrow(|files| files.as_ref()?.get(name).cloned()) {
        return value;
    }
    let path = spec_vectors_dir().join(name);
    let bytes = fs::read(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    serde_json::from_slice(&bytes).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

/// Where a case that `pubky-switch-core` generated lies in its vector file (README "How the
/// files were generated"), as a JSON pointer.
#[derive(Clone, Copy, Debug)]
pub enum Place<'a> {
    /// A generated object member.
    Member(&'a str),
    /// A case of an array, found by its `name`.
    Case(&'a str),
    /// An array element the core rewrote, at its index, for an array whose cases have no
    /// `name`.
    Element(&'a str),
}

/// Compare generated cases with the fixture, or stage them during regeneration.
pub fn generated(name: &str, cases: &[(Place<'_>, Value)]) {
    let mut file = load(name);
    let staging = STAGED.with_borrow(Option::is_some);
    for (place, value) in cases {
        let pointer = match *place {
            Place::Member(p) | Place::Element(p) => Cow::Borrowed(p),
            Place::Case(p) => {
                let list = file
                    .pointer_mut(p)
                    .and_then(Value::as_array_mut)
                    .unwrap_or_else(|| panic!("{name}: no array at {p}"));
                let index = list
                    .iter()
                    .position(|case| case["name"] == value["name"])
                    .unwrap_or(list.len());
                if staging && index == list.len() {
                    list.push(Value::Null);
                }
                Cow::Owned(format!("{p}/{index}"))
            }
        };
        PLACES.with_borrow_mut(|places| {
            if let Some(places) = places {
                places.insert((name.to_owned(), pointer.to_string()));
            }
        });
        if !staging {
            assert_eq!(
                file.pointer(&pointer),
                Some(value),
                "{name}: {pointer} isn't what the core generates; see spec/vectors/README.md to regenerate"
            );
        } else if let Some(held) = file.pointer_mut(&pointer) {
            *held = value.clone();
        } else if matches!(place, Place::Member(_)) {
            let mut member = &mut file;
            for token in pointer.strip_prefix('/').expect("a member path").split('/') {
                member = if member.is_array() {
                    &mut member[token.parse::<usize>().expect("array index")]
                } else {
                    &mut member[token.replace("~1", "/").replace("~0", "~")]
                };
            }
            *member = value.clone();
        } else {
            panic!("{name}: no element at {pointer}");
        }
    }
    if staging {
        STAGED.with_borrow_mut(|files| {
            files
                .as_mut()
                .expect("staged files")
                .insert(name.to_owned(), file)
        });
    }
}

/// Emit only the computed members of an object, preserving its independent inputs.
pub fn generated_members(name: &str, base: &str, members: &[(&str, Value)]) {
    let paths: Vec<_> = members
        .iter()
        .map(|(key, _)| format!("{base}/{key}"))
        .collect();
    let cases: Vec<_> = paths
        .iter()
        .zip(members)
        .map(|(path, (_, v))| (Place::Member(path), v.clone()))
        .collect();
    generated(name, &cases);
}

/// Supply the seed labels when upgrading fixtures that only stored their derived bytes.
/// Ordinary tests and subsequent regenerations use the labels in the file.
fn fixtures_with_seed_labels() -> BTreeMap<String, Value> {
    use serde_json::json;

    let add = |case: &mut Value, member: &str, label: Value| {
        case.as_object_mut()
            .expect("vector case")
            .entry(member)
            .or_insert(label);
    };
    let mut keys = load("keys.json");
    add(
        &mut keys["removed_app"],
        "signing_seed_label",
        json!("alice/old-phone/signing"),
    );
    let mut encoding = load("encoding.json");
    add(
        &mut encoding["derive"][4],
        "seed_labels",
        json!(["envelope/cek"]),
    );
    for (i, label) in [(4, "b64/16"), (5, "b64/32")] {
        add(
            &mut encoding["base64url"]["valid"][i],
            "seed_label",
            json!(label),
        );
    }
    let mut sealed = load("sealed.json");
    for case in sealed["cases"].as_array_mut().unwrap() {
        let name = super::common::st(case, "name");
        let nonce_label = format!("sealed/{name}/nonce");
        let msg_label = match name {
            "task_items record of an assignment" => Some("msg/assignment"),
            "task_lists record" => Some("msg/list"),
            _ => None,
        };
        add(case, "nonce_seed_label", json!(nonce_label));
        if let Some(label) = msg_label {
            add(case, "msg_id_seed_label", json!(label));
        }
    }
    BTreeMap::from([
        ("keys.json".into(), keys),
        ("encoding.json".into(), encoding),
        ("sealed.json".into(), sealed),
    ])
}

/// Regenerate the core-owned cases. This is the only writer for the published fixtures.
#[test]
#[ignore = "set PUBKY_SWITCH_WRITE_VECTORS=1 to publish regenerated fixtures"]
fn regenerate_vectors() {
    let publish = std::env::var("PUBKY_SWITCH_WRITE_VECTORS").as_deref() == Ok("1");
    let dir = spec_vectors_dir();
    // Every writer for this checkout shares this lock, even across Cargo target dirs.
    let target = dir.join("../../target");
    fs::create_dir_all(&target).unwrap();
    let lock = fs::File::options()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(target.join("vector-regeneration.lock"))
        .unwrap();
    lock.try_lock()
        .unwrap_or_else(|e| panic!("could not lock the vector fixtures for regeneration: {e}"));
    STAGED.set(Some(fixtures_with_seed_labels()));

    super::keys::test_vectors_keys();
    super::encoding::test_vectors_encoding();
    super::sealed::test_vectors_sealed();

    let keys = super::common::keys();
    // The chain and document verifiers consume the rebuilt proofs, manifest and transfer.
    let (replacements, chunk) = super::record_current::record_cases(&keys);
    super::identifiers::test_vectors_identifiers();
    super::documents::test_vectors_documents();
    super::envelopes::test_vectors_envelopes();
    super::operations::test_vectors_operations();
    super::chain::test_vectors_chain();
    // Rebuild the HTTP requests and feed cursors before signing their record/export answers.
    super::http::http_cases(&keys);
    super::record_current::http_cases(&keys, &replacements, &chunk);
    super::export::test_vectors_export();
    super::signatures::test_vectors_signatures();

    for (name, file) in STAGED.take().unwrap() {
        let path = dir.join(&name);
        let mut bytes = serde_json::to_vec_pretty(&file).unwrap();
        bytes.push(b'\n');
        if fs::read(&path).unwrap() == bytes {
            continue;
        }
        assert!(
            publish,
            "{name} changed; see spec/vectors/README.md to regenerate"
        );
        // The writer holds the lock through rename. Readers always see complete JSON.
        let temp = dir.join(".regenerating-vector.tmp");
        fs::write(&temp, bytes).unwrap();
        fs::rename(temp, path).unwrap();
    }
}

/// Match an exact JSON pointer, allowing '*' only where the document has an array index.
fn input_matches(root: &Value, pointer: &str, pattern: &str) -> bool {
    let mut value = root;
    let mut tokens = pointer.split('/').skip(1);
    for part in pattern.split('/').skip(1) {
        let Some(token) = tokens.next() else {
            return false;
        };
        if (part == "*" && !value.is_array()) || (part != "*" && part != token) {
            return false;
        }
        value = value.pointer(&format!("/{token}")).expect("visited member");
    }
    tokens.next().is_none()
}

/// Check the leaves below a pointer, including empty arrays and objects.
fn check_leaves(
    name: &str,
    root: &Value,
    value: &Value,
    pointer: &str,
    generated: &BTreeSet<String>,
    inputs: &[&str],
) {
    if generated.contains(pointer) {
        return;
    }
    match value {
        Value::Object(members) if !members.is_empty() => {
            for (member, child) in members {
                let token = member.replace('~', "~0").replace('/', "~1");
                check_leaves(
                    name,
                    root,
                    child,
                    &format!("{pointer}/{token}"),
                    generated,
                    inputs,
                );
            }
        }
        Value::Array(elements) if !elements.is_empty() => {
            for (index, child) in elements.iter().enumerate() {
                check_leaves(
                    name,
                    root,
                    child,
                    &format!("{pointer}/{index}"),
                    generated,
                    inputs,
                );
            }
        }
        _ => assert!(
            inputs.iter().any(|p| input_matches(root, pointer, p)),
            "{name}: {pointer} is neither a declared input nor generated"
        ),
    }
}

/// Every published leaf must be a declared fixture input or belong to a computed output.
#[test]
fn test_vectors_every_member_is_an_input_or_generated() {
    // Coverage currently includes only keys, encoding, sealed and signatures.
    type Fixture = (&'static str, fn(), &'static [&'static str]);
    let fixtures: &[Fixture] = &[
        (
            "keys.json",
            super::keys::test_vectors_keys,
            &[
                "/description",
                "/identities/*/name",
                "/identities/*/seed_label",
                "/apps/*/name",
                "/apps/*/signing_seed_label",
                "/apps/*/bundle_seed_label",
                "/apps/*/permissions/*",
                "/apps/*/scopes/*",
                "/apps/*/receive_key/n",
                "/apps/*/receive_key/seed_label",
                "/scope_keys/*/identity",
                "/scope_keys/*/data_epoch",
                "/scope_keys/*/scope",
                "/sub_scope_keys/description",
                "/sub_scope_keys/keys/*/identity",
                "/sub_scope_keys/keys/*/data_epoch",
                "/sub_scope_keys/keys/*/parent",
                "/sub_scope_keys/keys/*/sub",
                "/service_keys/*/seed_label",
                "/next_service_key/seed_label",
                "/next_service_key/description",
                "/next_service_key/origin",
                "/removed_app/name",
                "/removed_app/signing_seed_label",
            ],
        ),
        (
            "encoding.json",
            super::encoding::test_vectors_encoding,
            &[
                "/description",
                "/base64url/valid/0/hex",
                "/base64url/valid/0/base64url",
                "/base64url/valid/1/hex",
                "/base64url/valid/1/base64url",
                "/base64url/valid/2/hex",
                "/base64url/valid/2/base64url",
                "/base64url/valid/3/hex",
                "/base64url/valid/3/base64url",
                "/base64url/valid/4/seed_label",
                "/base64url/valid/5/seed_label",
                "/base64url/invalid/*/base64url",
                "/base64url/invalid/*/why",
                "/lp/0/parts_hex",
                "/lp/1/parts_hex/*",
                "/lp/2/parts_hex/*",
                "/lp/3/parts_hex/*",
                "/lp/4/parts_hex/*",
                "/lp/0/output_hex",
                "/lp/1/output_hex",
                "/lp/2/output_hex",
                "/lp/3/output_hex",
                "/lp/4/output_hex",
                "/derive/0/parts_hex",
                "/derive/1/parts_hex/*",
                "/derive/2/parts_hex/*",
                "/derive/4/seed_labels/*",
                "/zbase32/invalid/*/why",
                "/u64_be/*/value",
                "/u64_be/*/hex",
                "/u64_be/6/note",
                "/json/0/json",
                "/json/1/json",
                "/json/2/json",
                "/json/3/json",
                "/json/4/json",
                "/json/5/json",
                "/json/6/json",
                "/json/7/json",
                "/json/8/json",
                "/json/9/json",
                "/json/10/json",
                "/json/11/json",
                "/json/12/json",
                "/json/13/json_hex",
                "/json/*/valid",
                "/json/13/why",
                "/json/10/read_as",
                "/json/11/read_as",
                "/json/12/read_as",
                "/rfc3339/parse/*/text",
                "/rfc3339/parse/*/unix_ms",
                "/rfc3339/format/*/unix_ms",
                "/rfc3339/format/*/text",
                "/rfc3339/invalid/*/text",
                "/rfc3339/lenient_reader_only/*/text",
                "/rfc3339/lenient_reader_only/*/unix_ms",
            ],
        ),
        (
            "sealed.json",
            super::sealed::test_vectors_sealed,
            &[
                "/description",
                "/cases/*/name",
                "/cases/*/scope",
                "/cases/*/data_epoch",
                "/cases/*/nonce_seed_label",
                "/cases/0/msg_id_seed_label",
                "/cases/1/msg_id_seed_label",
            ],
        ),
        (
            "signatures.json",
            super::signatures::test_vectors_signatures,
            &[
                "/description",
                "/signatures/*/signer",
                "/rejections/*/name",
                "/rejections/*/why",
                "/rejections/*/reason",
                "/rejections/*/lenient_accepts",
                "/rejections/3/seed_a",
                "/rejections/3/seed_r",
                "/rejections/3/torsion_index",
                "/rejections/4/seed_a",
                "/rejections/4/seed_r",
                "/rejections/4/torsion_index",
                "/rejections/5/seed_a",
                "/rejections/5/seed_r",
                "/rejections/5/torsion_index",
                "/rejections/6/seed_a",
                "/rejections/6/seed_r",
                "/rejections/6/torsion_index",
                "/rejections/7/seed_a",
                "/rejections/7/seed_r",
                "/rejections/7/torsion_index",
                "/accepted/0/name",
                "/accepted/0/why",
                "/accepted/0/reason",
                "/accepted/0/lenient_accepts",
                "/accepted/0/seed_a",
                "/accepted/0/seed_r",
                "/accepted/0/torsion_index",
            ],
        ),
    ];
    for &(name, verify, inputs) in fixtures {
        PLACES.set(Some(BTreeSet::new()));
        verify();
        let generated = PLACES
            .take()
            .expect("recorded places")
            .into_iter()
            .filter_map(|(file, pointer)| (file == name).then_some(pointer))
            .collect();
        let file = load(name);
        check_leaves(name, &file, &file, "", &generated, inputs);
    }
}

/// A seed label stored as an input decides its values: with one changed in memory, its
/// file's verifier no longer reproduces the published file, so no label is kept for show.
#[test]
fn test_vectors_seed_labels_decide_their_values() {
    type Fixture = (&'static str, fn(), &'static str);
    let fixtures: [Fixture; 5] = [
        (
            "keys.json",
            super::keys::test_vectors_keys,
            "/removed_app/signing_seed_label",
        ),
        (
            "encoding.json",
            super::encoding::test_vectors_encoding,
            "/derive/4/seed_labels/0",
        ),
        (
            "sealed.json",
            super::sealed::test_vectors_sealed,
            "/cases/0/nonce_seed_label",
        ),
        (
            "sealed.json",
            super::sealed::test_vectors_sealed,
            "/cases/0/msg_id_seed_label",
        ),
        (
            "signatures.json",
            super::signatures::test_vectors_signatures,
            "/accepted/0/seed_a",
        ),
    ];
    for (name, verify, label_at) in fixtures {
        let mut file = load(name);
        let label = file
            .pointer_mut(label_at)
            .unwrap_or_else(|| panic!("{name}: no label at {label_at}"));
        *label = Value::String(format!("{}/changed", label.as_str().expect("a label")));
        CHANGED.set(Some((name.to_owned(), file)));
        let outcome = std::panic::catch_unwind(verify);
        CHANGED.set(None);
        // Refused by the comparison with the published file, not by any other check.
        let why = outcome
            .err()
            .and_then(|payload| payload.downcast::<String>().ok())
            .unwrap_or_else(|| panic!("{name}: {label_at} doesn't decide any value"));
        assert!(
            why.contains("isn't what the core generates"),
            "{name}: {label_at}: {why}"
        );
    }
}
