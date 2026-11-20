//! Rust declarations used by the two host guide tests.

use std::fs;
use std::path::{Path, PathBuf};

/// Find Rust source files below a crate's source directory.
pub(super) fn rust_files(dir: &Path) -> Vec<PathBuf> {
    let mut files = Vec::new();
    for entry in fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            files.extend(rust_files(&path));
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            files.push(path);
        }
    }
    files
}

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

/// Read the literal public enum declarations in a source file, including item-macro inputs.
/// Only names written at the declaration enter the inventory.
pub(super) fn public_enums(source: &str) -> Vec<(String, Vec<String>)> {
    let words = tokens(source);
    let mut enums = Vec::new();
    for (i, head) in words.windows(3).enumerate() {
        let ["pub", "enum", name] = head else {
            continue;
        };
        if !name.starts_with(|c: char| c.is_alphabetic() || c == '_') {
            continue;
        }
        let body = words[i + 3..]
            .iter()
            .copied()
            .skip_while(|t| *t != "{")
            .skip(1);
        let names = variants(body).into_iter().map(str::to_owned).collect();
        enums.push(((*name).to_owned(), names));
    }
    enums
}
