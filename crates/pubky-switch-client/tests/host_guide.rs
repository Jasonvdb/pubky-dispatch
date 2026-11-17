//! Check the app host guide against the client crate's public enum declarations.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

const GUIDE: &str = include_str!("../../../docs/app-host-guide.md");

/// Tokenize the parts of Rust needed for enum declarations. Comments and literal contents
/// are opaque, including braces and commas in an attribute or a discriminant.
fn tokens(mut source: &str) -> Vec<&str> {
    let mut result = Vec::new();
    while !source.is_empty() {
        source = source.trim_start();
        if source.is_empty() {
            break;
        }
        if source.starts_with("//") {
            source = source.split_once('\n').map_or("", |(_, rest)| rest);
            continue;
        }
        if let Some(mut rest) = source.strip_prefix("/*") {
            let mut depth = 1;
            while depth > 0 {
                let pos = rest.find(['/', '*']).expect("unterminated block comment");
                rest = &rest[pos..];
                if let Some(after) = rest.strip_prefix("/*") {
                    depth += 1;
                    rest = after;
                } else if let Some(after) = rest.strip_prefix("*/") {
                    depth -= 1;
                    rest = after;
                } else {
                    rest = &rest[1..];
                }
            }
            source = rest;
            continue;
        }
        if let Some(rest) = source
            .strip_prefix("br")
            .or_else(|| source.strip_prefix("cr"))
            .or_else(|| source.strip_prefix('r'))
        {
            let hashes = rest.len() - rest.trim_start_matches('#').len();
            if let Some(body) = rest[hashes..].strip_prefix('"') {
                let close = format!("\"{}", &rest[..hashes]);
                source = body.split_once(&close).expect("unterminated raw string").1;
                continue;
            }
        }
        let first = source.chars().next().unwrap();
        let rest = &source[first.len_utf8()..];
        // A lifetime has no closing quote. Plain character literals contain one character.
        if first == '"' || (first == '\'' && rest.starts_with('\\')) {
            let mut chars = rest.chars();
            while let Some(c) = chars.next() {
                if c == '\\' {
                    chars.next();
                } else if c == first {
                    break;
                }
            }
            source = chars.as_str();
        } else if first == '\''
            && let Some(after) = rest
                .chars()
                .next()
                .and_then(|c| rest[c.len_utf8()..].strip_prefix('\''))
        {
            source = after;
        } else {
            let len = if first.is_alphanumeric() || first == '_' {
                source
                    .find(|c: char| !c.is_alphanumeric() && c != '_')
                    .unwrap_or(source.len())
            } else {
                first.len_utf8()
            };
            result.push(&source[..len]);
            source = &source[len..];
        }
    }
    result
}

/// Read the first identifier of each variant. Nested fields, attributes and expressions
/// may contain commas of their own.
fn variants<'a>(body: impl Iterator<Item = &'a str>) -> Vec<&'a str> {
    let mut names = Vec::new();
    let mut depth = 0usize;
    let mut at_name = true;
    for token in body {
        match token {
            "}" if depth == 0 => return names,
            "(" | "[" | "{" => depth += 1,
            ")" | "]" | "}" => depth -= 1,
            "," if depth == 0 => at_name = true,
            "#" => {}
            name if depth == 0 && at_name => {
                assert!(
                    name.starts_with(|c: char| c.is_alphabetic() || c == '_'),
                    "invalid variant {name}"
                );
                names.push(name);
                at_name = false;
            }
            _ => {}
        }
    }
    unreachable!("unterminated enum")
}

fn read_sources(root: &Path, dir: &Path, cases: &mut BTreeSet<String>) {
    for entry in fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            read_sources(root, &path, cases);
        } else if path.extension().is_some_and(|extension| extension == "rs") {
            let source = fs::read_to_string(&path).unwrap();
            let words = tokens(&source);
            for (i, head) in words.windows(3).enumerate() {
                let ["pub", "enum", name] = head else {
                    continue;
                };
                // The store and the scripted service both export an enum named Fault.
                let name = if *name == "Fault" {
                    let relative = path.strip_prefix(root).unwrap();
                    let module = relative.components().next().unwrap();
                    format!("{}::{name}", module.as_os_str().to_str().unwrap())
                } else {
                    (*name).to_owned()
                };
                let body = words[i + 3..]
                    .iter()
                    .copied()
                    .skip_while(|t| *t != "{")
                    .skip(1);
                for variant in variants(body) {
                    assert!(
                        cases.insert(format!("{name}::{variant}")),
                        "ambiguous {name}::{variant}"
                    );
                }
            }
        }
    }
}

#[test]
fn test_app_host_guide_covers_public_variants() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut declared = BTreeSet::new();
    read_sources(&root, &root, &mut declared);
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
