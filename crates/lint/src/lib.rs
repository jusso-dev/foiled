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
use foiled_core::catalogue::{Artefact, CatalogueEntry, EntryStatus};
use serde_json::Value;
use walkdir::WalkDir;

const CATALOGUE_ENTRIES: &str = "catalogue/entries";

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

    check_catalogue(root, &mut report)?;
    Ok(report)
}

/// Catalogue checks the schema cannot express: id matches path, artefact
/// shape matches the decoy kind, and verified emulation entries point at a
/// profile or module manifest that exists in the tree.
fn check_catalogue(root: &Path, report: &mut Report) -> Result<()> {
    let entries_dir = root.join(CATALOGUE_ENTRIES);
    if !entries_dir.exists() {
        return Ok(());
    }
    for entry in WalkDir::new(&entries_dir).sort_by_file_name() {
        let entry = entry?;
        let path = entry.path();
        if !entry.file_type().is_file() || !is_data_file(path) {
            continue;
        }
        let rel = path.strip_prefix(root).unwrap_or(path).to_path_buf();
        let Ok(value) = load(path) else {
            continue; // reported by the schema pass
        };
        let Ok(parsed) = serde_json::from_value::<CatalogueEntry>(value) else {
            continue; // the schema pass reports the shape error
        };
        let within = path
            .strip_prefix(&entries_dir)
            .unwrap_or(path)
            .to_string_lossy()
            .replace('\\', "/");
        for problem in parsed.problems_at(&within) {
            report.findings.push(Finding {
                path: rel.clone(),
                message: problem.to_string(),
            });
        }
        if parsed.status == EntryStatus::Verified {
            let required = match &parsed.artefact {
                Some(Artefact::Emulator(a)) => Some(format!(
                    "emulators/{}/profiles/{}.yaml",
                    a.emulator_id, a.emulator_profile
                )),
                Some(Artefact::Module(a)) => Some(format!("modules/{}/manifest.yaml", a.module_id)),
                _ => None,
            };
            if let Some(required) = required
                && !root.join(&required).exists()
            {
                report.findings.push(Finding {
                    path: rel.clone(),
                    message: format!("verified entry needs {required}"),
                });
            }
        }
    }
    Ok(())
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

    const MINIMAL_ENTRY_SCHEMA: &str = r#"{"type": "object"}"#;

    fn catalogue_entry(id: &str, status: &str, artefact: &str) -> String {
        format!(
            r#"{{"id":"{id}","product":"p","vendor":"v","version":"1","decoy_kind":"emulation",
            "artefact":{artefact},"cves":[],"listen_ports":[{{"port":1,"protocol":"tcp","service":"x"}}],
            "sources":["https://example.com"],"status":"{status}","risk_notes":"r"}}"#
        )
    }

    #[test]
    fn catalogue_id_must_match_path() {
        let dir = tempfile::tempdir().unwrap();
        write(
            dir.path(),
            "catalogue/schema/entry.schema.json",
            MINIMAL_ENTRY_SCHEMA,
        );
        write(
            dir.path(),
            "catalogue/entries/emulator/redis/7.0.json",
            &catalogue_entry(
                "emulator/redis/6.0",
                "draft",
                r#"{"emulator_id":"redis","emulator_profile":"redis-7.0"}"#,
            ),
        );
        let report = run(dir.path(), BINDINGS).unwrap();
        assert_eq!(report.findings.len(), 1, "{:?}", report.findings);
        assert!(report.findings[0].message.contains("emulator/redis/7.0"));
    }

    #[test]
    fn verified_emulation_needs_existing_profile() {
        let dir = tempfile::tempdir().unwrap();
        write(
            dir.path(),
            "catalogue/schema/entry.schema.json",
            MINIMAL_ENTRY_SCHEMA,
        );
        let body = catalogue_entry(
            "emulator/redis/7.0",
            "verified",
            r#"{"emulator_id":"redis","emulator_profile":"redis-7.0"}"#,
        );
        write(
            dir.path(),
            "catalogue/entries/emulator/redis/7.0.json",
            &body,
        );
        let report = run(dir.path(), BINDINGS).unwrap();
        assert_eq!(report.findings.len(), 1, "{:?}", report.findings);
        assert!(
            report.findings[0]
                .message
                .contains("emulators/redis/profiles/redis-7.0.yaml")
        );

        write(
            dir.path(),
            "emulators/redis/profiles/redis-7.0.yaml",
            "id: redis-7.0\n",
        );
        let report = run(dir.path(), BINDINGS).unwrap();
        assert!(report.findings.is_empty(), "{:?}", report.findings);
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
