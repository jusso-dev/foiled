//! Runs the lint against the real repository tree and fixtures.

use std::path::{Path, PathBuf};

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

#[test]
fn repository_tree_is_clean() {
    let report = foiled_lint::run(&repo_root(), foiled_lint::BINDINGS).unwrap();
    assert!(
        report.findings.is_empty(),
        "lint findings in the repository: {:#?}",
        report.findings
    );
    assert!(
        report.files_checked >= 3,
        "catalogue entries were not checked"
    );
}

#[test]
fn invalid_catalogue_fixtures_are_rejected_by_the_schema() {
    let root = repo_root();
    let schema = foiled_lint::load(&root.join("catalogue/schema/entry.schema.json")).unwrap();
    let validator = jsonschema::validator_for(&schema).unwrap();
    let dir = root.join("catalogue/testdata/invalid");
    let mut seen = 0;
    for entry in std::fs::read_dir(&dir).unwrap() {
        let path = entry.unwrap().path();
        let instance = foiled_lint::load(&path).unwrap();
        assert!(
            !validator.is_valid(&instance),
            "{} should be rejected",
            path.display()
        );
        seen += 1;
    }
    assert!(seen >= 3);
}
