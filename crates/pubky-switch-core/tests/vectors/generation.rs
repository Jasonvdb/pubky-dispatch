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
    super::documents::test_vectors_documents();
    super::sealed::test_vectors_sealed();
    super::envelopes::test_vectors_envelopes();

    let keys = super::common::keys();
    // The chain and document verifiers consume the rebuilt proofs, manifest and transfer.
    let (replacements, chunk) = super::record_current::record_cases(&keys);
    super::identifiers::test_vectors_identifiers();
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

/// Visit the leaves outside generated subtrees, including empty arrays and objects.
fn visit_leaves(
    value: &Value,
    pointer: &str,
    generated: &BTreeSet<String>,
    visit: &mut impl FnMut(&str, &Value),
) {
    if generated.contains(pointer) {
        return;
    }
    match value {
        Value::Object(members) if !members.is_empty() => {
            for (member, child) in members {
                let token = member.replace('~', "~0").replace('/', "~1");
                visit_leaves(child, &format!("{pointer}/{token}"), generated, visit);
            }
        }
        Value::Array(elements) if !elements.is_empty() => {
            for (index, child) in elements.iter().enumerate() {
                visit_leaves(child, &format!("{pointer}/{index}"), generated, visit);
            }
        }
        _ => visit(pointer, value),
    }
}

type Fixture = (&'static str, fn(), &'static [&'static str]);

fn fixtures() -> &'static [Fixture] {
    &[
        (
            "keys.json",
            super::keys::test_vectors_keys,
            &[
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
                "/rejections/4/torsion_index",
                "/rejections/5/seed_a",
                "/rejections/5/torsion_index",
                "/rejections/6/seed_a",
                "/rejections/6/seed_r",
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
        (
            "documents.json",
            || {
                super::documents::test_vectors_documents();
                // The export transfer belongs to the export manifest's producer.
                super::record_current::record_cases(&super::common::keys());
            },
            &[
                "/documents/*/name",
                "/documents/*/signer",
                "/documents/0/expires_at",
                "/documents/0/issued_at",
                "/documents/1/expires_at",
                "/documents/1/issued_at",
                "/documents/2/expires_at",
                "/documents/2/issued_at",
                "/documents/3/expires_at",
                "/documents/3/issued_at",
                "/documents/4/accepts/*",
                "/documents/4/expires_at",
                "/documents/4/protocols/tasks/features/board_kinds/*",
                "/documents/4/protocols/tasks/public_boards",
                "/documents/4/updated_at",
                "/documents/5/accepts/*",
                "/documents/5/expires_at",
                "/documents/5/protocols/tasks/features/board_kinds/*",
                "/documents/5/protocols/tasks/public_boards",
                "/documents/5/updated_at",
                "/documents/6/accepts/*",
                "/documents/6/expires_at",
                "/documents/6/protocols/tasks/features/board_kinds/*",
                "/documents/6/protocols/tasks/public_boards",
                "/documents/6/updated_at",
                "/documents/7/accepts/*",
                "/documents/7/expires_at",
                "/documents/7/protocols/tasks/features/board_kinds/*",
                "/documents/7/protocols/tasks/public_boards/home",
                "/documents/7/updated_at",
                "/documents/12/data_epoch",
                "/documents/12/distrust_from",
                "/documents/12/listed_apps/*",
                "/documents/12/origin",
                "/documents/12/policy/admission",
                "/documents/12/policy/connect_requests/enabled",
                "/documents/12/policy/connect_requests/max_pending",
                "/documents/12/policy/connect_requests/push",
                "/documents/12/signer_seed_label",
                "/documents/12/version",
                "/documents/13/data_epoch",
                "/documents/13/listed_apps/*",
                "/documents/13/origin",
                "/documents/13/policy/admission",
                "/documents/13/policy/connect_requests/enabled",
                "/documents/13/policy/connect_requests/max_pending",
                "/documents/13/policy/connect_requests/push",
                "/documents/13/signer_seed_label",
                "/documents/13/version",
                "/documents/14/nonce_seed_label",
                "/documents/14/observed_at",
                "/documents/14/store_id_seed_label",
                "/documents/15/expires_at",
                "/documents/15/issued_at",
                "/documents/15/permissions/*",
                "/documents/15/scopes/*",
                "/documents/16/data_epoch",
                "/documents/16/until",
                "/documents/16/version",
                "/documents/17/data_epoch",
                "/documents/17/until",
                "/documents/17/version",
                "/documents/18/issued_at",
                "/documents/18/next_generation",
                "/documents/18/nonce_seed_label",
                "/documents/19/data_epoch",
                "/documents/19/version",
                "/documents/20/record_max_age",
                "/documents/20/version",
                "/documents/22/nonce_seed_label",
                "/documents/22/observed_at",
                "/documents/22/store_id_seed_label",
                "/documents/23/expires_at",
                "/documents/23/issued_at",
                "/documents/24/accepts/*",
                "/documents/24/expires_at",
                "/documents/24/protocols/tasks/features/board_kinds/*",
                "/documents/24/protocols/tasks/public_boards",
                "/documents/24/updated_at",
                "/documents/26/generation",
                "/documents/26/version",
                "/documents/27/expires_at",
                "/documents/27/issued_at",
                "/documents/28/accepts/*",
                "/documents/28/expires_at",
                "/documents/28/protocols/tasks/features/board_kinds/*",
                "/documents/28/protocols/tasks/public_boards",
                "/documents/28/updated_at",
                "/documents/29/version",
                "/auth_request/client_id",
                "/auth_request/client_seed_label",
                "/auth_request/secret_seed_label",
                "/approval/keyed_scopes/*",
                "/approval/seal_seed_label",
                "/approval/rejections/*/step",
                "/approval/rejections/*/error",
                "/approval/rejections/*/last_epoch",
                "/approval/rejections/*/seal_seed_label",
                "/identity_rejections/cases/*/name",
                "/identity_rejections/cases/*/error",
                "/app_record_conflict/conflict",
                "/app_record_conflict/kept",
                "/app_record_conflict/updated_at",
                "/app_record_conflict/records/*/board_kind",
                "/permission_rejections/cases/*/name",
                "/permission_rejections/cases/*/reason",
                "/permission_rejections/cases/2/extra_permission",
                "/scope_rule/accepted/*/extra_scopes/*",
                "/scope_rule/refused/*/reason",
                "/scope_rule/refused/*/extra_scopes/*",
                "/app_record_protocols/accepted/0/protocol",
                "/app_record_protocols/accepted/0/member/items/0",
                "/app_record_protocols/accepted/0/member/items/1/deep",
                "/app_record_protocols/accepted/0/member/level",
                "/app_record_protocols/accepted/1/protocol",
                "/app_record_protocols/accepted/1/member",
                "/app_record_protocols/refused/*/reason",
                "/app_record_protocols/refused/0/protocol",
                "/app_record_protocols/refused/0/member",
                "/app_record_protocols/refused/1/protocol",
                "/app_record_protocols/refused/1/member",
                "/app_record_protocols/refused/2/protocol",
                "/app_record_protocols/refused/2/member",
                "/app_record_protocols/refused/3/protocol",
                "/app_record_protocols/refused/3/member",
                "/app_record_protocols/refused/4/protocol",
                "/app_record_protocols/refused/4/member",
                "/app_record_protocols/refused/5/protocol",
                "/app_record_protocols/refused/5/member",
                "/app_record_protocols/refused/6/protocol",
                "/app_record_protocols/refused/6/member",
                "/app_record_protocols/refused/7/name",
                "/app_record_protocols/refused/7/protocols",
            ],
        ),
        (
            "envelopes.json",
            super::envelopes::test_vectors_envelopes,
            &[
                "/keyed_scopes/*",
                "/messages/assignment/body/board",
                "/messages/assignment/body/every",
                "/messages/assignment/body/starts_at",
                "/messages/assignment/body/task",
                "/messages/assignment/created_at",
                "/messages/assignment/kind",
                "/messages/assignment/msg_id_seed_label",
                "/messages/cancellation/body/reason",
                "/messages/cancellation/created_at",
                "/messages/cancellation/kind",
                "/messages/cancellation/msg_id_seed_label",
                "/messages/resend/created_at",
                "/messages/resend/item_seed_prefix",
                "/messages/resend/kind",
                "/messages/resend/msg_id_seed_label",
                "/cases/*/name",
                "/cases/*/notify",
                "/cases/*/cek_seed_label",
                "/cases/*/nonce_seed_label",
                "/cases/*/recipients/*/app",
                "/cases/*/recipients/*/ikm_e_seed_label",
                "/cases/2/resend_count",
                "/cases/3/resend_count",
                "/cases/4/resend_count",
                "/cases/5/resend_count",
                "/cases/6/resend_count",
                "/cases/7/resend_count",
                "/bucket_fit/*/bucket",
                "/bucket_fit/*/plaintext_len",
                "/bucket_fit/*/recipients",
                "/rejections/0/case",
                "/rejections/0/change",
                "/rejections/0/result",
                "/rejections/1/case",
                "/rejections/1/change",
                "/rejections/1/result",
                "/rejections/2/name",
                "/rejections/2/opens_for/*",
                "/rejections/2/rejected_by/0/app",
                "/rejections/2/rejected_by/0/reason",
                "/rejections/2/cek_seed_label",
                "/rejections/2/nonce_seed_label",
                "/rejections/2/other_cek_seed_label",
                "/rejections/2/ikm_e_seed_labels/0",
                "/rejections/2/ikm_e_seed_labels/1",
                "/key_bundle/app",
                "/key_bundle/first_epoch",
                "/key_bundle/last_epoch",
                "/key_bundle/seal_seed_label",
                "/reduction_key_bundle/app",
                "/reduction_key_bundle/first_epoch",
                "/reduction_key_bundle/last_epoch",
                "/reduction_key_bundle/seal_seed_label",
                "/reduction_key_bundle/removed_scope",
                "/key_bundle_rejections/cases/*/name",
                "/key_bundle_rejections/cases/*/reason",
                "/key_bundle_rejections/cases/*/seal_seed_label",
                "/key_bundle_rejections/cases/0/scope",
                "/key_bundle_rejections/cases/1/key_seed_label",
                "/key_bundle_rejections/cases/2/scope",
                "/signer_handover/app",
                "/signer_handover/parts/*/seal_seed_label",
                "/signer_backup/seal_seed_label",
                "/signer_handover_rejections/cases/*/name",
                "/signer_handover_rejections/cases/*/reason",
            ],
        ),
    ]
}

/// Authored explanations and captions that do not choose wire values or expected outcomes.
fn annotations(file: &str) -> &'static [&'static str] {
    match file {
        "documents.json" => &[
            "/app_record_conflict/description",
            "/app_record_protocols/description",
            "/auth_request/description",
            "/identity_rejections/description",
            "/permission_rejections/description",
            "/scope_rule/description",
            "/approval/rejections/*/name",
            "/approval/rejections/*/rule",
            "/identity_rejections/cases/*/rule",
            "/scope_rule/accepted/*/name",
            "/scope_rule/refused/*/name",
            "/app_record_protocols/accepted/*/name",
            "/app_record_protocols/refused/*/name",
        ],
        "envelopes.json" => &[
            "/key_bundle/note",
            "/reduction_key_bundle/note",
            "/rejections/2/note",
            "/signer_handover_rejections/description",
            "/key_bundle_rejections/cases/*/change",
        ],
        _ => &[],
    }
}

/// Require the authored text on each case, including each element of a captioned array.
pub(super) fn check_annotations(name: &str, file: &Value) {
    for &pattern in annotations(name) {
        let (parent, member) = pattern.rsplit_once('/').unwrap();
        let check = |entry: &Value| {
            assert!(
                entry[member].as_str().is_some_and(|s| !s.trim().is_empty()),
                "{name}: missing text at {pattern}"
            );
        };
        if let Some(array) = parent.strip_suffix("/*") {
            for entry in file.pointer(array).and_then(Value::as_array).expect(array) {
                check(entry);
            }
        } else {
            check(file.pointer(parent).expect(parent));
        }
    }
}

/// Every published leaf is covered and every declared pattern covers a leaf.
#[test]
fn test_vectors_every_member_is_an_input_or_generated() {
    for &(name, verify, inputs) in fixtures() {
        PLACES.set(Some(BTreeSet::new()));
        verify();
        let generated = PLACES
            .take()
            .expect("recorded places")
            .into_iter()
            .filter_map(|(file, pointer)| (file == name).then_some(pointer))
            .collect();
        let file = load(name);
        let prose = annotations(name);
        let mut unmatched: BTreeSet<_> = inputs.iter().chain(prose).copied().collect();
        visit_leaves(&file, "", &generated, &mut |pointer, _| {
            let mut covered = false;
            for &pattern in inputs.iter().chain(prose) {
                if input_matches(&file, pointer, pattern) {
                    covered = true;
                    unmatched.remove(pattern);
                }
            }
            assert!(
                covered,
                "{name}: {pointer} is outside the declared inputs, annotations and generated values"
            );
        });
        assert!(
            unmatched.is_empty(),
            "{name}: patterns matched no leaf: {unmatched:?}"
        );
    }
}

/// Rebuild the two files even when none of the keys or carriers they can derive is available.
#[test]
fn test_vectors_documents_and_envelopes_derive_their_carriers() {
    PLACES.set(Some(BTreeSet::new()));
    super::keys::test_vectors_keys();
    super::documents::test_vectors_documents();
    super::envelopes::test_vectors_envelopes();
    let mut files = BTreeMap::new();
    for (name, path) in PLACES.take().unwrap() {
        let file = files.entry(name.clone()).or_insert_with(|| load(&name));
        *file.pointer_mut(&path).expect("published output") = Value::Null;
    }
    STAGED.set(Some(files));
    // The envelopes can issue their own documents while the published signatures are absent.
    super::envelopes::test_vectors_envelopes();
    super::documents::test_vectors_documents();
    let rebuilt = STAGED.take().unwrap();
    for name in ["documents.json", "envelopes.json"] {
        assert!(
            rebuilt[name] == load(name),
            "{name} differs after regeneration"
        );
    }
}

/// Seed labels are scalar members or entries of a seed_labels array.
fn is_seed_label(pointer: &str) -> bool {
    let Some((parent, name)) = pointer.rsplit_once('/') else {
        return false;
    };
    name.ends_with("seed_label")
        || matches!(name, "seed_a" | "seed_r" | "item_seed_prefix")
        || parent
            .rsplit('/')
            .next()
            .is_some_and(|member| member.ends_with("seed_labels"))
}

/// Each seed label in the file decides at least one generated value.
#[test]
fn test_vectors_seed_labels_decide_their_values() {
    for &(name, verify, _) in fixtures() {
        verify();
        let file = load(name);
        visit_leaves(&file, "", &BTreeSet::new(), &mut |pointer, value| {
            let Some(label) = value.as_str().filter(|_| is_seed_label(pointer)) else {
                return;
            };
            let mut changed = file.clone();
            *changed.pointer_mut(pointer).expect("visited label") =
                Value::String(format!("{label}/changed"));
            CHANGED.set(Some((name.to_owned(), changed)));
            let outcome = std::panic::catch_unwind(verify);
            CHANGED.set(None);
            let payload = outcome
                .err()
                .unwrap_or_else(|| panic!("{name}: {pointer} doesn't decide any value"));
            let why = payload
                .downcast_ref::<String>()
                .map(String::as_str)
                .or_else(|| payload.downcast_ref::<&str>().copied());
            assert!(
                why.is_some_and(|s| s
                    .split_once(" isn't what the core generates")
                    .is_some_and(|(location, _)| !location.ends_with("/description")
                        && !location.ends_with("/note"))),
                "{name}: {pointer}: {why:?}"
            );
        });
    }
}
