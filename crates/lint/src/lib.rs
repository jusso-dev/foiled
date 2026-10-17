//! Repository lint for Foiled data files.
//!
//! Two checks run over the repository root:
//!
//! 1. Every `*.schema.json` file is valid JSON and a valid JSON Schema.
//! 2. Every data file in a directory listed in [`BINDINGS`] validates against
//!    the schema bound to that directory. JSON and YAML are both accepted.
//!
//! A binding whose schema file does not exist yet is skipped, so the lint can
//! land before the schemas it will police.

use std::fmt;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde_json::Value;
use walkdir::WalkDir;

/// Directory to schema bindings, relative to the repository root.
pub const BINDINGS: &[Binding] = &[Binding {
    data_dir: "catalogue/entries",
    schema: "catalogue/schema/entry.schema.json",
}];

/// Directories never scanned for schema files.
const SKIP_DIRS: &[&str] = &[".git", "target", "node_modules", "dist", "build"];

#[derive(Debug, Clone, Copy)]
pub struct Binding {
    pub data_dir: &'static str,
    pub schema: &'static str,
}

/// One problem found by the lint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    pub path: PathBuf,
    pub message: String,
}

impl fmt::Display for Finding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.path.display(), self.message)
    }
}

/// Summary of a lint run.
#[derive(Debug, Default)]
pub struct Report {
    pub schemas_checked: usize,
    pub files_checked: usize,
    pub findings: Vec<Finding>,
}

/// Parse a JSON or YAML file into a JSON value.
pub fn load(path: &Path) -> Result<Value> {
    let text =
        std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    match path.extension().and_then(|e| e.to_str()) {
        Some("yaml" | "yml") => serde_yaml_ng::from_str(&text).context("parsing YAML"),
        _ => serde_json::from_str(&text).context("parsing JSON"),
    }
}

fn is_data_file(path: &Path) -> bool {
    matches!(
        path.extension().and_then(|e| e.to_str()),
        Some("json" | "yaml" | "yml")
    )
}

fn skipped(entry: &walkdir::DirEntry) -> bool {
    entry.file_type().is_dir()
        && entry
            .file_name()
            .to_str()
            .is_some_and(|n| SKIP_DIRS.contains(&n))
}

/// Run every check against `root` using `bindings`.
pub fn run(root: &Path, bindings: &[Binding]) -> Result<Report> {
    let mut report = Report::default();

    for entry in WalkDir::new(root).into_iter().filter_entry(|e| !skipped(e)) {
        let entry = entry?;
        let path = entry.path();
        if !entry.file_type().is_file()
            || !path
                .file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.ends_with(".schema.json"))
        {
            continue;
        }
        report.schemas_checked += 1;
        let rel = path.strip_prefix(root).unwrap_or(path).to_path_buf();
        match load(path) {
            Err(e) => report.findings.push(Finding {
                path: rel,
                message: format!("{e:#}"),
            }),
            Ok(schema) => {
                if let Err(e) = jsonschema::meta::validate(&schema) {
                    report.findings.push(Finding {
                        path: rel,
                        message: format!("not a valid JSON Schema: {e}"),
                    });
                }
            }
        }
    }

    for binding in bindings {
        let schema_path = root.join(binding.schema);
        let data_dir = root.join(binding.data_dir);
        if !data_dir.exists() {
            continue;
        }
        if !schema_path.exists() {
            report.findings.push(Finding {
                path: PathBuf::from(binding.data_dir),
                message: format!("data files exist but schema {} is missing", binding.schema),
            });
            continue;
        }
        let schema = load(&schema_path)?;
        let validator = match jsonschema::validator_for(&schema) {
            Ok(v) => v,
            Err(e) => {
                report.findings.push(Finding {
                    path: PathBuf::from(binding.schema),
                    message: format!(
                        "cannot build validator, {} not checked: {e}",
                        binding.data_dir
                    ),
                });
                continue;
            }
        };
        for entry in WalkDir::new(&data_dir).sort_by_file_name() {
            let entry = entry?;
            let path = entry.path();
            if !entry.file_type().is_file() || !is_data_file(path) {
                continue;
            }
            report.files_checked += 1;
            let rel = path.strip_prefix(root).unwrap_or(path).to_path_buf();
            match load(path) {
                Err(e) => report.findings.push(Finding {
                    path: rel,
                    message: format!("{e:#}"),
                }),
                Ok(instance) => {
                    for err in validator.iter_errors(&instance) {
                        report.findings.push(Finding {
                            path: rel.clone(),
                            message: format!("{} at '{}'", err, err.instance_path()),
                        });
                    }
                }
            }
        }
    }

    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    const ENTRY_SCHEMA: &str = r#"{
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "type": "object",
        "required": ["id"],
        "properties": { "id": { "type": "string" } }
    }"#;

    fn binding() -> [Binding; 1] {
        [Binding {
            data_dir: "entries",
            schema: "schema/entry.schema.json",
        }]
    }

    fn write(root: &Path, rel: &str, body: &str) {
        let p = root.join(rel);
        fs::create_dir_all(p.parent().unwrap()).unwrap();
        fs::write(p, body).unwrap();
    }

    #[test]
    fn valid_json_and_yaml_entries_pass() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "schema/entry.schema.json", ENTRY_SCHEMA);
        write(dir.path(), "entries/a.json", r#"{"id":"demo/1.0"}"#);
        write(dir.path(), "entries/nested/b.yaml", "id: demo/2.0\n");
        let report = run(dir.path(), &binding()).unwrap();
        assert!(report.findings.is_empty(), "{:?}", report.findings);
        assert_eq!(report.schemas_checked, 1);
        assert_eq!(report.files_checked, 2);
    }

    #[test]
    fn entry_breaking_schema_is_reported() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "schema/entry.schema.json", ENTRY_SCHEMA);
        write(dir.path(), "entries/bad.json", r#"{"id": 7}"#);
        write(dir.path(), "entries/missing.yaml", "product: demo\n");
        let report = run(dir.path(), &binding()).unwrap();
        assert_eq!(report.findings.len(), 2, "{:?}", report.findings);
        assert!(
            report
                .findings
                .iter()
                .any(|f| f.path.ends_with("bad.json") && f.message.contains("/id"))
        );
        assert!(
            report
                .findings
                .iter()
                .any(|f| f.path.ends_with("missing.yaml") && f.message.contains("id"))
        );
    }

    #[test]
    fn invalid_schema_and_unparseable_file_are_reported() {
        let dir = tempfile::tempdir().unwrap();
        write(
            dir.path(),
            "schemas/broken.schema.json",
            r#"{"type": "not-a-type"}"#,
        );
        write(dir.path(), "schemas/garbage.schema.json", "{ nope");
        let report = run(dir.path(), &binding()).unwrap();
        assert_eq!(report.schemas_checked, 2);
        assert_eq!(report.findings.len(), 2, "{:?}", report.findings);
    }

    #[test]
    fn binding_with_neither_schema_nor_data_is_skipped() {
        let dir = tempfile::tempdir().unwrap();
        let report = run(dir.path(), &binding()).unwrap();
        assert!(report.findings.is_empty());
        assert_eq!(report.files_checked, 0);
    }

    #[test]
    fn data_without_schema_fails() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "entries/a.json", r#"{"anything": true}"#);
        let report = run(dir.path(), &binding()).unwrap();
        assert_eq!(report.findings.len(), 1, "{:?}", report.findings);
        assert!(report.findings[0].message.contains("is missing"));
    }

    #[test]
    fn unresolvable_schema_ref_fails_instead_of_skipping() {
        let dir = tempfile::tempdir().unwrap();
        write(
            dir.path(),
            "schema/entry.schema.json",
            r#"{"$ref": "https://example.invalid/other.schema.json"}"#,
        );
        write(dir.path(), "entries/a.json", r#"{"id":"x"}"#);
        let report = run(dir.path(), &binding()).unwrap();
        assert!(
            report
                .findings
                .iter()
                .any(|f| f.message.contains("cannot build validator")),
            "{:?}",
            report.findings
        );
    }

    #[test]
    fn ignores_build_directories() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "node_modules/x/bad.schema.json", "{ nope");
        write(dir.path(), "target/y.schema.json", "{ nope");
        let report = run(dir.path(), &binding()).unwrap();
        assert_eq!(report.schemas_checked, 0);
    }
}
