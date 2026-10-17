//! Catalogue entries (#5): decoys an operator can launch.
//!
//! The JSON Schema at `catalogue/schema/entry.schema.json` is the contract for
//! the files under `catalogue/entries/`. These types mirror it so the API and
//! host agent can work with parsed entries, and add checks a schema cannot
//! express on its own.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DecoyKind {
    /// A pinned build of real software in a sandbox (#3, #6).
    Sandbox,
    /// A Foiled emulator profile or a reused open source decoy module (#30).
    Emulation,
}

impl DecoyKind {
    pub fn as_str(self) -> &'static str {
        match self {
            DecoyKind::Sandbox => "sandbox",
            DecoyKind::Emulation => "emulation",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EntryStatus {
    Draft,
    Verified,
    Deprecated,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Runtime {
    Firecracker,
    Docker,
}

/// What actually runs for an entry. Variant order matters for untagged
/// deserialisation: the emulator and module shapes are tried before the
/// sandbox shape, and every shape rejects unknown fields.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Artefact {
    Emulator(EmulatorArtefact),
    Module(ModuleArtefact),
    Sandbox(SandboxArtefact),
}

/// A custom Foiled emulator profile (#30).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EmulatorArtefact {
    pub emulator_id: String,
    pub emulator_profile: String,
}

/// A reused open source decoy module, always run as its own container (#30, #38).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModuleArtefact {
    pub module_id: String,
    pub module_profile: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub image: Option<String>,
    /// Upstream SPDX licence id.
    pub licence: String,
}

/// A digest-pinned image, a build recipe (#6), or both.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SandboxArtefact {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub image: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recipe_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runtime: Option<Runtime>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthRequirement {
    Unauth,
    Auth,
    Either,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CveRef {
    pub cve_id: String,
    pub severity: String,
    pub sources: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth_requirement: Option<AuthRequirement>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Protocol {
    Tcp,
    Udp,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ListenPort {
    pub port: u16,
    pub protocol: Protocol,
    pub service: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DefaultCredential {
    pub username: String,
    pub password: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CanarySlot {
    pub path: String,
    pub kind: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CatalogueEntry {
    pub id: String,
    pub product: String,
    pub vendor: String,
    pub version: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version_constraint: Option<String>,
    pub decoy_kind: DecoyKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub artefact: Option<Artefact>,
    pub cves: Vec<CveRef>,
    pub listen_ports: Vec<ListenPort>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub default_credentials: Vec<DefaultCredential>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub fingerprint_hints: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub banner_hints: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub expected_techniques: Vec<String>,
    /// Tier 1 signature ids under `catalogue/matchers/` (#12).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub matchers: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub instrumentation_hooks: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub canary_slots: Vec<CanarySlot>,
    pub sources: Vec<String>,
    pub status: EntryStatus,
    pub risk_notes: String,
}

/// A problem the schema cannot catch on its own.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EntryProblem {
    /// The artefact shape does not belong to the entry's decoy kind.
    ArtefactKindMismatch { kind: DecoyKind },
    /// A verified entry has no artefact.
    VerifiedWithoutArtefact,
    /// A sandbox artefact has neither an image digest nor a recipe.
    SandboxArtefactEmpty,
    /// The same port and protocol is listed twice.
    DuplicatePort { port: u16 },
    /// The entry id does not match the file path it was loaded from.
    IdPathMismatch { expected: String },
}

impl std::fmt::Display for EntryProblem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EntryProblem::ArtefactKindMismatch { kind } => {
                write!(
                    f,
                    "artefact shape does not match decoy_kind {}",
                    kind.as_str()
                )
            }
            EntryProblem::VerifiedWithoutArtefact => {
                write!(f, "verified entries need an artefact")
            }
            EntryProblem::SandboxArtefactEmpty => {
                write!(f, "sandbox artefact needs an image digest or a recipe_id")
            }
            EntryProblem::DuplicatePort { port } => write!(f, "port {port} listed twice"),
            EntryProblem::IdPathMismatch { expected } => {
                write!(f, "id does not match file path, expected '{expected}'")
            }
        }
    }
}

impl CatalogueEntry {
    /// Checks beyond the JSON Schema. Returns every problem found.
    pub fn problems(&self) -> Vec<EntryProblem> {
        let mut out = Vec::new();
        match (&self.artefact, self.decoy_kind) {
            (None, _) if self.status == EntryStatus::Verified => {
                out.push(EntryProblem::VerifiedWithoutArtefact)
            }
            (None, _) => {}
            (Some(Artefact::Sandbox(a)), DecoyKind::Sandbox) => {
                if a.image.is_none() && a.recipe_id.is_none() {
                    out.push(EntryProblem::SandboxArtefactEmpty);
                }
            }
            (Some(Artefact::Emulator(_) | Artefact::Module(_)), DecoyKind::Emulation) => {}
            (Some(_), kind) => out.push(EntryProblem::ArtefactKindMismatch { kind }),
        }
        let mut seen = Vec::new();
        for p in &self.listen_ports {
            let key = (p.port, p.protocol);
            if seen.contains(&key) {
                out.push(EntryProblem::DuplicatePort { port: p.port });
            }
            seen.push(key);
        }
        out
    }

    /// The id implied by a path relative to `catalogue/entries/`, for example
    /// `foiled/demo-app/1.0.0.yaml` gives `foiled/demo-app/1.0.0`.
    pub fn id_for_path(relative: &str) -> String {
        let trimmed = relative.trim_start_matches("./").replace('\\', "/");
        for ext in [".yaml", ".yml", ".json"] {
            if let Some(stem) = trimmed.strip_suffix(ext) {
                return stem.to_string();
            }
        }
        trimmed
    }

    /// Like [`CatalogueEntry::problems`], plus the id and path check.
    pub fn problems_at(&self, relative_path: &str) -> Vec<EntryProblem> {
        let mut out = self.problems();
        let expected = Self::id_for_path(relative_path);
        if expected != self.id {
            out.push(EntryProblem::IdPathMismatch { expected });
        }
        out
    }

    /// True when an operator or agent may launch this entry without an
    /// explicit draft override (#24).
    pub fn launchable_by_default(&self) -> bool {
        self.status == EntryStatus::Verified && self.problems().is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn base(kind: &str, status: &str, artefact: Option<serde_json::Value>) -> serde_json::Value {
        let mut v = json!({
            "id": "foiled/demo-app/1.0.0",
            "product": "Demo",
            "vendor": "Foiled",
            "version": "1.0.0",
            "decoy_kind": kind,
            "cves": [{"cve_id": "FOILED-DEMO-0001", "severity": "critical", "sources": ["synthetic"]}],
            "listen_ports": [{"port": 8080, "protocol": "tcp", "service": "http"}],
            "sources": ["https://example.com/advisory"],
            "status": status,
            "risk_notes": "test"
        });
        if let Some(a) = artefact {
            v["artefact"] = a;
        }
        v
    }

    fn parse(v: serde_json::Value) -> CatalogueEntry {
        serde_json::from_value(v).expect("entry parses")
    }

    #[test]
    fn sandbox_recipe_entry_is_launchable() {
        let e = parse(base(
            "sandbox",
            "verified",
            Some(json!({"recipe_id": "foiled-demo-app", "runtime": "firecracker"})),
        ));
        assert!(matches!(e.artefact, Some(Artefact::Sandbox(_))));
        assert!(e.problems().is_empty());
        assert!(e.launchable_by_default());
    }

    #[test]
    fn emulator_and_module_shapes_parse_as_their_variants() {
        let e = parse(base(
            "emulation",
            "draft",
            Some(json!({"emulator_id": "redis", "emulator_profile": "redis-7.0"})),
        ));
        assert!(matches!(e.artefact, Some(Artefact::Emulator(_))));
        assert!(!e.launchable_by_default(), "drafts need an override");

        let m = parse(base(
            "emulation",
            "verified",
            Some(
                json!({"module_id": "cowrie", "module_profile": "debian", "licence": "BSD-3-Clause"}),
            ),
        ));
        assert!(matches!(m.artefact, Some(Artefact::Module(_))));
        assert!(m.problems().is_empty());
    }

    #[test]
    fn sandbox_entry_with_only_emulator_id_is_rejected() {
        // Parses as an emulator shape, then the kind check rejects it.
        let e = parse(base(
            "sandbox",
            "draft",
            Some(json!({"emulator_id": "redis", "emulator_profile": "x"})),
        ));
        assert_eq!(
            e.problems(),
            vec![EntryProblem::ArtefactKindMismatch {
                kind: DecoyKind::Sandbox
            }]
        );
        // With no profile at all it matches no variant.
        let bad = base("sandbox", "draft", Some(json!({"emulator_id": "redis"})));
        assert!(serde_json::from_value::<CatalogueEntry>(bad).is_err());
    }

    #[test]
    fn verified_without_artefact_and_empty_sandbox_are_problems() {
        let e = parse(base("emulation", "verified", None));
        assert_eq!(e.problems(), vec![EntryProblem::VerifiedWithoutArtefact]);
        let draft = parse(base("emulation", "draft", None));
        assert!(draft.problems().is_empty());
        let empty = parse(base("sandbox", "draft", Some(json!({}))));
        assert_eq!(empty.problems(), vec![EntryProblem::SandboxArtefactEmpty]);
    }

    #[test]
    fn duplicate_ports_are_reported_per_protocol() {
        let mut v = base("sandbox", "draft", None);
        v["listen_ports"] = json!([
            {"port": 53, "protocol": "udp", "service": "dns"},
            {"port": 53, "protocol": "tcp", "service": "dns"},
            {"port": 53, "protocol": "udp", "service": "dns"}
        ]);
        assert_eq!(
            parse(v).problems(),
            vec![EntryProblem::DuplicatePort { port: 53 }]
        );
    }

    #[test]
    fn id_must_match_path() {
        let e = parse(base("sandbox", "draft", None));
        assert!(e.problems_at("foiled/demo-app/1.0.0.yaml").is_empty());
        assert_eq!(
            e.problems_at("foiled/demo-app/1.0.1.yaml"),
            vec![EntryProblem::IdPathMismatch {
                expected: "foiled/demo-app/1.0.1".into()
            }]
        );
        assert_eq!(CatalogueEntry::id_for_path("a/b.json"), "a/b");
    }

    #[test]
    fn unknown_fields_are_rejected() {
        let mut v = base("sandbox", "draft", None);
        v["surprise"] = json!(true);
        assert!(serde_json::from_value::<CatalogueEntry>(v).is_err());
    }

    #[test]
    fn round_trips_through_json() {
        let e = parse(base(
            "sandbox",
            "verified",
            Some(json!({"recipe_id": "foiled-demo-app"})),
        ));
        let back: CatalogueEntry =
            serde_json::from_value(serde_json::to_value(&e).unwrap()).unwrap();
        assert_eq!(e, back);
    }
}
