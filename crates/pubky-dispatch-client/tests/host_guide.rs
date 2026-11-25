//! Check the app host guide against the client crate's public enum declarations.

#![allow(clippy::unwrap_used, clippy::expect_used)]

#[path = "../../../tests/support/guide_enums.rs"]
mod guide_enums;

use guide_enums::{public_enums, rust_files};
use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

const GUIDE: &str = include_str!("../../../docs/app-host-guide.md");

fn declared_variants(root: &Path) -> BTreeSet<String> {
    let mut cases = BTreeSet::new();
    for path in rust_files(root) {
        let source = fs::read_to_string(&path).unwrap();
        for (name, variants) in public_enums(&source) {
            // The store and the scripted service both export an enum named Fault.
            let name = if name == "Fault" {
                let relative = path.strip_prefix(root).unwrap();
                let module = relative.components().next().unwrap();
                format!("{}::{name}", module.as_os_str().to_str().unwrap())
            } else {
                name
            };
            for variant in variants {
                assert!(
                    cases.insert(format!("{name}::{variant}")),
                    "ambiguous {name}::{variant}"
                );
            }
        }
    }
    cases
}

#[test]
fn test_app_host_guide_covers_public_variants() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let declared = declared_variants(&root);
    assert!(!declared.is_empty(), "no public variants discovered");

    let mut documented = BTreeSet::new();
    for line in GUIDE.lines() {
        if let Some(row) = line.strip_prefix("| `") {
            let (case, entry) = row.split_once("` | ").expect("a case and its explanation");
            assert!(
                !entry.trim_end_matches('|').trim().is_empty(),
                "empty entry for {case}"
            );
            assert!(
                documented.insert(case.to_owned()),
                "duplicate entry for {case}"
            );
        }
    }
    let missing: Vec<_> = declared.difference(&documented).collect();
    let stale: Vec<_> = documented.difference(&declared).collect();
    assert!(
        missing.is_empty() && stale.is_empty(),
        "missing {missing:?}, unknown {stale:?}"
    );
}
