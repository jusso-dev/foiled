//! Repository lint for Foiled data files.
//!
//! Checks run over the repository root:
//!
//! 1. Every `*.schema.json` file is valid JSON and a valid JSON Schema.
//! 2. Every data file in a directory listed in [`BINDINGS`] validates against
//!    the schema bound to that directory. A binding may also name a single
//!    file. JSON and YAML are both accepted.
//! 3. Catalogue entries pass the checks a schema cannot express, including
//!    a `hooks/<id>.yaml` manifest for every declared instrumentation hook.
//! 4. `configs/contribute-back.yaml`, if present, parses as a
//!    [`SharePolicy`] and has no policy problems (#37).
//!
//! A binding whose schema file does not exist yet is skipped, so the lint can
//! land before the schemas it will police.

use std::fmt;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use foiled_core::catalogue::{Artefact, CatalogueEntry, EntryStatus};
use foiled_core::share::SharePolicy;
use serde_json::Value;
use walkdir::WalkDir;

const CATALOGUE_ENTRIES: &str = "catalogue/entries";
const HOOKS_DIR: &str = "hooks";
const CONTRIBUTE_BACK: &str = "configs/contribute-back.yaml";

/// Data to schema bindings, relative to the repository root.
pub const BINDINGS: &[Binding] = &[
    Binding {
        data_dir: "catalogue/entries",
        schema: "catalogue/schema/entry.schema.json",
    },
    Binding {
        data_dir: "catalogue/matchers",
        schema: "catalogue/schema/matcher.schema.json",
    },
    Binding {
        data_dir: "catalogue/sequences",
        schema: "catalogue/schema/sequence.schema.json",
    },
    Binding {
        data_dir: "catalogue/advisories",
        schema: "catalogue/schema/advisory.schema.json",
    },
    Binding {
        data_dir: "testdata/watchlist",
        schema: "schemas/watchlist-entry.schema.json",
    },
    Binding {
        data_dir: "configs/confidence.yaml",
        schema: "schemas/confidence-config.schema.json",
    },
    Binding {
        data_dir: "testdata/confidence-links",
        schema: "schemas/confidence-link.schema.json",
    },
    Binding {
        data_dir: "configs/retention.yaml",
        schema: "schemas/retention-config.schema.json",
    },
    Binding {
        data_dir: "configs/enrichment.yaml",
        schema: "schemas/enrichment-config.schema.json",
    },
    Binding {
        data_dir: "configs/llm.yaml",
        schema: "schemas/llm-config.schema.json",
    },
    Binding {
        data_dir: "testdata/llm-eval/expected",
        schema: "schemas/llm-correlation-result.schema.json",
    },
    Binding {
        data_dir: "testdata/enrichment/facts",
        schema: "schemas/fact.schema.json",
    },
    Binding {
        data_dir: "testdata/capture",
        schema: "schemas/capture-event.schema.json",
    },
    Binding {
        data_dir: "testdata/attack",
        schema: "schemas/capture-event.schema.json",
    },
    Binding {
        data_dir: "rules/attack",
        schema: "schemas/attack-rule.schema.json",
    },
    Binding {
        data_dir: "testdata/technique-links",
        schema: "schemas/technique-link.schema.json",
    },
    Binding {
        data_dir: "testdata/quarantine",
        schema: "schemas/quarantine-meta.schema.json",
    },
    Binding {
        data_dir: "testdata/attempts/expected",
        schema: "schemas/attempt.schema.json",
    },
    Binding {
        data_dir: "testdata/attempts/timeline",
        schema: "schemas/attempt-timeline.schema.json",
    },
    Binding {
        data_dir: "testdata/iocs/expected",
        schema: "schemas/ioc.schema.json",
    },
    Binding {
        data_dir: "testdata/campaigns/expected",
        schema: "schemas/campaign.schema.json",
    },
    Binding {
        data_dir: "testdata/campaigns/actions",
        schema: "schemas/campaign-action.schema.json",
    },
    Binding {
        data_dir: "testdata/exports/stix",
        schema: "schemas/stix-bundle.schema.json",
    },
    Binding {
        data_dir: "testdata/exports/misp",
        schema: "schemas/misp-event.schema.json",
    },
    Binding {
        data_dir: "catalogue/actors",
        schema: "schemas/actor-report.schema.json",
    },
    Binding {
        data_dir: "testdata/actors/reports",
        schema: "schemas/actor-report.schema.json",
    },
    Binding {
        data_dir: "testdata/actors/expected",
        schema: "schemas/actor-link.schema.json",
    },
    Binding {
        data_dir: "testdata/agent/jobs",
        schema: "schemas/agent/job.schema.json",
    },
    Binding {
        data_dir: "testdata/agent/results",
        schema: "schemas/agent/job-result.schema.json",
    },
    Binding {
        data_dir: "testdata/agent/heartbeats",
        schema: "schemas/agent/heartbeat.schema.json",
    },
    Binding {
        data_dir: "testdata/agent/registry",
        schema: "schemas/agent/agent-record.schema.json",
    },
    Binding {
        data_dir: "testdata/agent/enrol/requests",
        schema: "schemas/agent/enrol-request.schema.json",
    },
    Binding {
        data_dir: "testdata/agent/enrol/responses",
        schema: "schemas/agent/enrol-response.schema.json",
    },
    Binding {
        data_dir: "testdata/releases",
        schema: "schemas/release-manifest.schema.json",
    },
    Binding {
        data_dir: "hooks",
        schema: "schemas/hook-manifest.schema.json",
    },
    Binding {
        data_dir: "emulators",
        schema: "schemas/emulator-profile.schema.json",
    },
    Binding {
        data_dir: "modules",
        schema: "schemas/module-manifest.schema.json",
    },
    Binding {
        data_dir: "configs/alerting.yaml",
        schema: "schemas/alerting-config.schema.json",
    },
    Binding {
        data_dir: "testdata/alerts",
        schema: "schemas/alert.schema.json",
    },
    Binding {
        data_dir: "configs/mcp.yaml",
        schema: "schemas/mcp-config.schema.json",
    },
    Binding {
        data_dir: "testdata/mcp/results",
        schema: "schemas/mcp-tool-result.schema.json",
    },
    Binding {
        data_dir: "testdata/radar/points",
        schema: "schemas/radar-point.schema.json",
    },
    Binding {
        data_dir: "testdata/radar/expected",
        schema: "schemas/radar-feed.schema.json",
    },
    Binding {
        data_dir: "testdata/review/expected",
        schema: "schemas/review-item.schema.json",
    },
    Binding {
        data_dir: "testdata/write-ups/examples",
        schema: "schemas/write-up.schema.json",
    },
    Binding {
        data_dir: "testdata/public/pages",
        schema: "schemas/public-exploit-page.schema.json",
    },
    Binding {
        data_dir: "testdata/public/lists",
        schema: "schemas/public-exploit-list.schema.json",
    },
];

/// Directories never scanned for schema files.
const SKIP_DIRS: &[&str] = &[".git", "target", "node_modules", "dist", "build"];

#[derive(Debug, Clone, Copy)]
pub struct Binding {
    /// A directory, walked recursively, or a single data file.
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
    check_contribute_back(root, &mut report);
    Ok(report)
}

/// The contribute-back policy must parse into the type the API Worker and
/// agents load, and must pass its own rules (#37).
fn check_contribute_back(root: &Path, report: &mut Report) {
    let path = root.join(CONTRIBUTE_BACK);
    if !path.exists() {
        return;
    }
    report.files_checked += 1;
    let rel = PathBuf::from(CONTRIBUTE_BACK);
    let parsed = load(&path).and_then(|v| {
        serde_json::from_value::<SharePolicy>(v).context("not a contribute-back policy")
    });
    match parsed {
        Err(e) => report.findings.push(Finding {
            path: rel,
            message: format!("{e:#}"),
        }),
        Ok(policy) => {
            for problem in policy.problems() {
                report.findings.push(Finding {
                    path: rel.clone(),
                    message: problem,
                });
            }
        }
    }
}

/// Catalogue checks the schema cannot express: id matches path, artefact
/// shape matches the decoy kind, verified emulation entries point at a
/// profile or module manifest that exists in the tree, and every declared
/// instrumentation hook has a manifest under `hooks/` (#32).
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
        for m in &parsed.matchers {
            if !root.join(format!("catalogue/matchers/{m}.yaml")).exists() {
                report.findings.push(Finding {
                    path: rel.clone(),
                    message: format!("matcher {m} not found in catalogue/matchers/"),
                });
            }
        }
        for hook in &parsed.instrumentation_hooks {
            let required = format!("{HOOKS_DIR}/{hook}.yaml");
            if !root.join(&required).exists() {
                report.findings.push(Finding {
                    path: rel.clone(),
                    message: format!("instrumentation hook {hook} needs {required}"),
                });
            }
        }
        if parsed.status == EntryStatus::Verified {
            let required = match &parsed.artefact {
                Some(Artefact::Emulator(a)) => Some(format!(
                    "emulators/{}/profiles/{}.yaml",
                    a.emulator_id, a.emulator_profile
                )),
                Some(Artefact::Module(a)) => Some(format!("modules/{}/manifest.yaml", a.module_id)),
                Some(Artefact::Sandbox(a)) => a
                    .recipe_id
                    .as_ref()
                    .map(|r| format!("build/recipes/{r}/Containerfile")),
                None => None,
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
        // This checks file existence only; the stub profile is not meant to
        // pass the profile schema, which this temp tree does not carry.
        let bindings: Vec<Binding> = BINDINGS
            .iter()
            .filter(|b| b.data_dir != "emulators")
            .copied()
            .collect();
        let report = run(dir.path(), &bindings).unwrap();
        assert!(report.findings.is_empty(), "{:?}", report.findings);
    }

    #[test]
    fn declared_hooks_need_a_manifest() {
        let dir = tempfile::tempdir().unwrap();
        write(
            dir.path(),
            "catalogue/schema/entry.schema.json",
            MINIMAL_ENTRY_SCHEMA,
        );
        write(
            dir.path(),
            "schemas/hook-manifest.schema.json",
            MINIMAL_ENTRY_SCHEMA,
        );
        let body = catalogue_entry(
            "emulator/redis/7.0",
            "draft",
            r#"{"emulator_id":"redis","emulator_profile":"redis-7.0"}"#,
        )
        .replace(
            r#""status""#,
            r#""instrumentation_hooks":["redis.config-set-dir"],"status""#,
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
                .contains("hooks/redis.config-set-dir.yaml")
        );

        write(
            dir.path(),
            "hooks/redis.config-set-dir.yaml",
            "id: redis.config-set-dir\n",
        );
        let report = run(dir.path(), BINDINGS).unwrap();
        assert!(report.findings.is_empty(), "{:?}", report.findings);
    }

    #[test]
    fn binding_can_name_a_single_file() {
        let dir = tempfile::tempdir().unwrap();
        let single = [Binding {
            data_dir: "configs/one.yaml",
            schema: "schema/entry.schema.json",
        }];
        write(dir.path(), "schema/entry.schema.json", ENTRY_SCHEMA);
        write(dir.path(), "configs/one.yaml", "id: ok\n");
        // A sibling that would fail the schema is not bound, so not checked.
        write(dir.path(), "configs/other.yaml", "id: 7\n");
        let report = run(dir.path(), &single).unwrap();
        assert!(report.findings.is_empty(), "{:?}", report.findings);
        assert_eq!(report.files_checked, 1);

        write(dir.path(), "configs/one.yaml", "product: demo\n");
        let report = run(dir.path(), &single).unwrap();
        assert_eq!(report.findings.len(), 1, "{:?}", report.findings);
        assert!(report.findings[0].path.ends_with("configs/one.yaml"));
    }

    #[test]
    fn shipped_contribute_back_policy_matches_code_defaults() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let value = load(&root.join(CONTRIBUTE_BACK)).unwrap();
        let policy: SharePolicy = serde_json::from_value(value).unwrap();
        assert_eq!(policy, SharePolicy::default());
        assert!(policy.problems().is_empty(), "{:?}", policy.problems());
    }

    #[test]
    fn contribute_back_policy_problems_are_reported() {
        let dir = tempfile::tempdir().unwrap();
        let shipped = fs::read_to_string(
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../..")
                .join(CONTRIBUTE_BACK),
        )
        .unwrap();
        write(
            dir.path(),
            CONTRIBUTE_BACK,
            &shipped.replace("edge_sensors_default: off", "edge_sensors_default: on"),
        );
        let report = run(dir.path(), &binding()).unwrap();
        assert_eq!(report.findings.len(), 1, "{:?}", report.findings);
        assert!(report.findings[0].message.contains("edge_sensors_default"));

        write(
            dir.path(),
            CONTRIBUTE_BACK,
            &shipped.replace("delay_days: 7", "delay_days: 7\n  include_enrichment: true"),
        );
        let report = run(dir.path(), &binding()).unwrap();
        assert_eq!(report.findings.len(), 1, "{:?}", report.findings);
        assert!(
            report.findings[0]
                .message
                .contains("not a contribute-back policy")
        );
    }

    #[test]
    fn verified_sandbox_recipe_must_exist() {
        let dir = tempfile::tempdir().unwrap();
        write(
            dir.path(),
            "catalogue/schema/entry.schema.json",
            MINIMAL_ENTRY_SCHEMA,
        );
        let body = r#"{"id":"foiled/demo/1","product":"p","vendor":"v","version":"1","decoy_kind":"sandbox",
            "artefact":{"recipe_id":"demo"},"cves":[],"listen_ports":[{"port":1,"protocol":"tcp","service":"x"}],
            "sources":["https://example.com"],"status":"verified","risk_notes":"r"}"#;
        write(dir.path(), "catalogue/entries/foiled/demo/1.json", body);
        let report = run(dir.path(), BINDINGS).unwrap();
        assert_eq!(report.findings.len(), 1, "{:?}", report.findings);
        assert!(
            report.findings[0]
                .message
                .contains("build/recipes/demo/Containerfile")
        );
        write(
            dir.path(),
            "build/recipes/demo/Containerfile",
            "FROM scratch\n",
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
