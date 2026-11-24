//! Verification and explicit regeneration of the core's vector cases.

use std::borrow::Cow;
use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;

use pubky_switch_core::spec_vectors_dir;
use serde_json::Value;

thread_local! {
    static PLACES: RefCell<Option<BTreeSet<(String, String)>>> = const { RefCell::new(None) };
    // Only the generator sees pending changes. Other tests read the published files.
    static STAGED: RefCell<Option<BTreeMap<String, Value>>> = const { RefCell::new(None) };
}

/// A parsed vector file, including any cases already generated on this thread.
pub fn load(name: &str) -> Value {
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
    STAGED.set(Some(BTreeMap::new()));

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
                "/removed_app/app_id",
            ],
        ),
        (
            "encoding.json",
            super::encoding::test_vectors_encoding,
            &[
                "/description",
                "/base64url/valid/*/hex",
                "/base64url/valid/*/base64url",
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
                "/derive/4/parts_hex/*",
                "/zbase32/invalid/*/why",
                "/u64_be/*/value",
                "/u64_be/*/hex",
                "/u64_be/*/note",
                "/json/*/json",
                "/json/*/json_hex",
                "/json/*/valid",
                "/json/*/why",
                "/json/*/read_as",
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
                "/cases/*/nonce_hex",
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
                "/accepted/*/name",
                "/accepted/*/why",
                "/accepted/*/seed_a",
                "/accepted/*/torsion_index",
                "/accepted/*/seed_r",
                "/accepted/*/counter",
                "/rejections/*/seed_a",
                "/rejections/*/torsion_index",
                "/rejections/*/seed_r",
                "/rejections/*/counter",
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
