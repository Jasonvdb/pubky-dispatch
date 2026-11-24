//! Verification and explicit regeneration of the core's vector cases.

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::fs;

use pubky_dispatch_core::spec_vectors_dir;
use serde_json::Value;

thread_local! {
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

/// Where a case that `pubky-dispatch-core` generated lies in its vector file (README "How the
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
    if STAGED.with_borrow(Option::is_some) {
        for (place, value) in cases {
            match place {
                Place::Member(pointer) => {
                    let mut member = &mut file;
                    for key in pointer.strip_prefix('/').expect("a member path").split('/') {
                        member = &mut member[key];
                    }
                    *member = value.clone();
                }
                Place::Element(pointer) => {
                    *file
                        .pointer_mut(pointer)
                        .unwrap_or_else(|| panic!("{name}: no element at {pointer}")) =
                        value.clone();
                }
                Place::Case(pointer) => {
                    let list = file
                        .pointer_mut(pointer)
                        .and_then(Value::as_array_mut)
                        .unwrap_or_else(|| panic!("{name}: no array at {pointer}"));
                    match list.iter_mut().find(|c| c["name"] == value["name"]) {
                        Some(held) => *held = value.clone(),
                        None => list.push(value.clone()),
                    }
                }
            }
        }
        STAGED.with_borrow_mut(|files| files.as_mut().unwrap().insert(name.to_owned(), file));
        return;
    }
    for (place, value) in cases {
        let held = match place {
            Place::Member(pointer) | Place::Element(pointer) => file.pointer(pointer),
            Place::Case(pointer) => file
                .pointer(pointer)
                .and_then(Value::as_array)
                .and_then(|list| list.iter().find(|c| c["name"] == value["name"])),
        };
        assert_eq!(
            held,
            Some(value),
            "{name}: {place:?} isn't what the core generates; see spec/vectors/README.md to regenerate"
        );
    }
}

/// Regenerate the core-owned cases. This is the only writer for the published fixtures.
#[test]
#[ignore = "set PUBKY_DISPATCH_WRITE_VECTORS=1 to publish regenerated fixtures"]
fn regenerate_vectors() {
    let publish = std::env::var("PUBKY_DISPATCH_WRITE_VECTORS").as_deref() == Ok("1");
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
