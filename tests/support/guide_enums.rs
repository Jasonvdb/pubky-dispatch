//! Rust declarations used by the two host guide tests.

use std::fs;
use std::path::{Path, PathBuf};
use syn::visit::Visit;

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

/// Read unrestricted public enum declarations and their variant names in source order.
pub(super) fn public_enums(source: &str) -> Vec<(String, Vec<String>)> {
    #[derive(Default)]
    struct Enums(Vec<(String, Vec<String>)>);

    impl<'ast> Visit<'ast> for Enums {
        fn visit_item_enum(&mut self, item: &'ast syn::ItemEnum) {
            if matches!(item.vis, syn::Visibility::Public(_)) {
                let variants = item.variants.iter().map(|v| v.ident.to_string()).collect();
                self.0.push((item.ident.to_string(), variants));
            }
            syn::visit::visit_item_enum(self, item);
        }
    }

    let file = syn::parse_file(source).expect("valid Rust source");
    let mut enums = Enums::default();
    enums.visit_file(&file);
    enums.0
}
