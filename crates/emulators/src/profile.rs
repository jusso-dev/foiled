//! Emulator profiles: `emulators/<emulator_id>/profiles/<id>.yaml`.
//!
//! The schema is `schemas/emulator-profile.schema.json`; these types mirror
//! it and reject unknown fields. [`Profile::problems`] covers what the
//! schema cannot express. Canary values (#17) are never in a profile: the
//! profile holds `{{canary.<name>}}` placeholders and the supervisor renders
//! per-decoy values in with [`Profile::render`] before `start`.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use foiled_core::capture::{HookStage, Severity};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::http_portal::HttpSettings;
use crate::jitter::Jitter;
use crate::redis::RedisSettings;

pub const SCHEMA_VERSION: u32 = 1;

/// Profiles shipped in the repository, compiled into the emulator host so
/// the binary and its default profiles are pinned by one digest.
const BUILTIN: &[(&str, &str)] = &[
    (
        "redis-7.0",
        include_str!("../../../emulators/redis/profiles/redis-7.0.yaml"),
    ),
    (
        "portal-generic",
        include_str!("../../../emulators/ssl-vpn/profiles/portal-generic.yaml"),
    ),
];

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Profile {
    pub schema_version: u32,
    /// Profile id; the file stem.
    pub id: String,
    /// The directory under `emulators/`; what catalogue entries call
    /// `emulator_id`.
    pub emulator_id: String,
    /// Which plug-in serves this profile (`redis`, `http_portal`).
    pub plugin: String,
    pub description: String,
    /// Catalogue entries that point at this profile.
    pub catalogue_ids: Vec<String>,
    pub listen: Vec<ListenPort>,
    #[serde(default)]
    pub tls: TlsMode,
    #[serde(default)]
    pub jitter: Jitter,
    #[serde(default)]
    pub claimed_cves: Vec<ClaimedCve>,
    #[serde(default)]
    pub hooks: Vec<HookPoint>,
    #[serde(default)]
    pub canaries: Vec<CanarySlot>,
    #[serde(default)]
    pub fingerprint_checks: Vec<FingerprintCheck>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub redis: Option<RedisSettings>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub http: Option<HttpSettings>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ListenPort {
    pub port: u16,
    pub protocol: Protocol,
    pub service: String,
    #[serde(default)]
    pub tls: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Protocol {
    Tcp,
}

/// How TLS is provided for the profile's TLS ports.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TlsMode {
    /// Plain TCP only.
    #[default]
    None,
    /// A TLS frontend on the host terminates with a certificate the operator
    /// supplies for a name they control (FR-04). The emulator sees plain TCP.
    OperatorCert,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClaimKind {
    /// Shows the shape of a claim. Must use a placeholder id
    /// (`CVE-2099-*` or `FOILED-DEMO-*`), never a real CVE.
    Illustrative,
    /// Backed by a documented matcher (#12) and a tested harness.
    Matched,
}

/// A catalogue CVE the profile says it answers for.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClaimedCve {
    pub cve_id: String,
    pub claim: ClaimKind,
    /// Hook point that fires when the claimed path is reached.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hook: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub matcher: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub harness: Option<String>,
    pub notes: String,
}

/// A vulnerable-path checkpoint (#32): when it matches, the emulator emits a
/// `hook` envelope as well as the `application` one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HookPoint {
    pub id: String,
    pub stage: HookStage,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cve_id: Option<String>,
    pub severity: Severity,
    pub on: HookTrigger,
    pub description: String,
}

/// What a hook matches. Redis profiles use `command` (and optionally `arg`,
/// matched against any argument after the command words); HTTP profiles use
/// `path` (and optionally `method`). `command`, `arg` and `method` may list
/// alternatives separated by `|` and match case-insensitively.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HookTrigger {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub command: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub arg: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub method: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CanaryKind {
    ApiKey,
    DatabaseUrl,
    CloudAccessKey,
    SshPrivateKey,
    AdminPassword,
}

/// A slot the supervisor fills with a per-decoy canary value (#17).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CanarySlot {
    pub name: String,
    pub kind: CanaryKind,
    pub description: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CheckResult {
    Pass,
    AcceptedTell,
    NotApplicable,
}

/// A fingerprint checklist item (`docs/fingerprint-resistance.md`) applied
/// to this profile. Tests in this crate assert the `pass` ones.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FingerprintCheck {
    pub item: String,
    pub result: CheckResult,
    pub note: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProfileError {
    Io(String),
    Parse(String),
    Invalid(Vec<String>),
    Canary(String),
}

impl std::fmt::Display for ProfileError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProfileError::Io(e) => write!(f, "reading profile: {e}"),
            ProfileError::Parse(e) => write!(f, "parsing profile: {e}"),
            ProfileError::Invalid(p) => write!(f, "invalid profile: {}", p.join("; ")),
            ProfileError::Canary(e) => write!(f, "canary: {e}"),
        }
    }
}

impl std::error::Error for ProfileError {}

const PLACEHOLDER_OPEN: &str = "{{canary.";
const PLACEHOLDER_CLOSE: &str = "}}";

fn is_slug(s: &str) -> bool {
    let mut chars = s.chars();
    chars
        .next()
        .is_some_and(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
        && chars
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '-' | '_' | '.'))
}

fn is_placeholder_cve(id: &str) -> bool {
    id.starts_with("CVE-2099-") || id.starts_with("FOILED-DEMO-")
}

/// Every canary placeholder name in `s`.
fn placeholders_in(s: &str, out: &mut BTreeSet<String>) {
    let mut rest = s;
    while let Some(start) = rest.find(PLACEHOLDER_OPEN) {
        let after = &rest[start + PLACEHOLDER_OPEN.len()..];
        match after.find(PLACEHOLDER_CLOSE) {
            Some(end) => {
                out.insert(after[..end].to_string());
                rest = &after[end + PLACEHOLDER_CLOSE.len()..];
            }
            None => {
                out.insert(after.to_string());
                break;
            }
        }
    }
}

fn walk_strings(v: &Value, f: &mut impl FnMut(&str)) {
    match v {
        Value::String(s) => f(s),
        Value::Array(a) => a.iter().for_each(|x| walk_strings(x, f)),
        Value::Object(o) => o.values().for_each(|x| walk_strings(x, f)),
        _ => {}
    }
}

fn map_strings(v: &mut Value, f: &mut impl FnMut(&str) -> String) {
    match v {
        Value::String(s) => *s = f(s),
        Value::Array(a) => a.iter_mut().for_each(|x| map_strings(x, f)),
        Value::Object(o) => o.values_mut().for_each(|x| map_strings(x, f)),
        _ => {}
    }
}

impl Profile {
    pub fn from_yaml(text: &str) -> Result<Self, ProfileError> {
        serde_yaml_ng::from_str(text).map_err(|e| ProfileError::Parse(e.to_string()))
    }

    pub fn load(path: &Path) -> Result<Self, ProfileError> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| ProfileError::Io(format!("{}: {e}", path.display())))?;
        Self::from_yaml(&text)
    }

    /// A profile shipped in the repository, by id.
    pub fn builtin(id: &str) -> Option<Self> {
        BUILTIN
            .iter()
            .find(|(i, _)| *i == id)
            .and_then(|(_, text)| Self::from_yaml(text).ok())
    }

    /// Ids of the shipped profiles served by `plugin`.
    pub fn builtin_ids(plugin: &str) -> Vec<&'static str> {
        BUILTIN
            .iter()
            .filter(|(_, text)| Self::from_yaml(text).is_ok_and(|p| p.plugin == plugin))
            .map(|(id, _)| *id)
            .collect()
    }

    pub fn hook(&self, id: &str) -> Option<&HookPoint> {
        self.hooks.iter().find(|h| h.id == id)
    }

    /// Canary placeholder names used anywhere in the profile.
    pub fn placeholders(&self) -> BTreeSet<String> {
        let mut out = BTreeSet::new();
        if let Ok(v) = serde_json::to_value(self) {
            walk_strings(&v, &mut |s| placeholders_in(s, &mut out));
        }
        out
    }

    /// True once every canary placeholder has a value.
    pub fn is_rendered(&self) -> bool {
        self.placeholders().is_empty()
    }

    /// Fill every `{{canary.<name>}}` with its per-decoy value. Every
    /// declared slot needs a value and every placeholder must be declared.
    pub fn render(&self, values: &BTreeMap<String, String>) -> Result<Self, ProfileError> {
        let declared: BTreeSet<&str> = self.canaries.iter().map(|c| c.name.as_str()).collect();
        for name in &declared {
            match values.get(*name) {
                None => return Err(ProfileError::Canary(format!("no value for slot '{name}'"))),
                Some(v) if v.contains(PLACEHOLDER_OPEN) || v.is_empty() => {
                    return Err(ProfileError::Canary(format!("bad value for slot '{name}'")));
                }
                Some(_) => {}
            }
        }
        for name in self.placeholders() {
            if !declared.contains(name.as_str()) {
                return Err(ProfileError::Canary(format!(
                    "placeholder '{name}' has no canary slot"
                )));
            }
        }
        let mut v = serde_json::to_value(self).map_err(|e| ProfileError::Parse(e.to_string()))?;
        map_strings(&mut v, &mut |s| {
            let mut out = s.to_string();
            for (name, value) in values {
                if declared.contains(name.as_str()) {
                    out = out.replace(
                        &format!("{PLACEHOLDER_OPEN}{name}{PLACEHOLDER_CLOSE}"),
                        value,
                    );
                }
            }
            out
        });
        serde_json::from_value(v).map_err(|e| ProfileError::Parse(e.to_string()))
    }

    /// Checks the schema cannot express. Empty means valid.
    pub fn problems(&self) -> Vec<String> {
        let mut out = Vec::new();
        if self.schema_version != SCHEMA_VERSION {
            out.push(format!("schema_version must be {SCHEMA_VERSION}"));
        }
        for (name, v) in [("id", &self.id), ("emulator_id", &self.emulator_id)] {
            if !is_slug(v) {
                out.push(format!("{name} '{v}' is not a lower-case slug"));
            }
        }
        if self.catalogue_ids.is_empty() {
            out.push("catalogue_ids must name at least one catalogue entry".into());
        }

        match (self.plugin.as_str(), &self.redis, &self.http) {
            (crate::redis::PLUGIN, Some(r), None) => out.extend(r.problems()),
            (crate::http_portal::PLUGIN, None, Some(h)) => out.extend(h.problems(&self.hooks)),
            (crate::redis::PLUGIN, _, _) => {
                out.push("plugin redis needs a redis section and no http section".into())
            }
            (crate::http_portal::PLUGIN, _, _) => {
                out.push("plugin http_portal needs an http section and no redis section".into())
            }
            (other, _, _) => out.push(format!("unknown plugin '{other}'")),
        }

        if self.listen.is_empty() {
            out.push("listen must have at least one port".into());
        }
        let mut ports = BTreeSet::new();
        for l in &self.listen {
            if l.port == 0 {
                out.push("listen port 0 is not allowed".into());
            }
            if !ports.insert(l.port) {
                out.push(format!("listen port {} appears twice", l.port));
            }
        }
        let any_tls = self.listen.iter().any(|l| l.tls);
        if any_tls && self.tls == TlsMode::None {
            out.push("a listen port has tls: true but tls is none".into());
        }
        if !any_tls && self.tls != TlsMode::None {
            out.push("tls is set but no listen port has tls: true".into());
        }
        out.extend(self.jitter.problems());

        let mut hook_ids = BTreeSet::new();
        for h in &self.hooks {
            if !is_slug(&h.id) {
                out.push(format!("hook id '{}' is not a slug", h.id));
            }
            if !hook_ids.insert(h.id.as_str()) {
                out.push(format!("hook id '{}' appears twice", h.id));
            }
            let t = &h.on;
            let shape_ok = match self.plugin.as_str() {
                crate::redis::PLUGIN => {
                    t.command.is_some() && t.method.is_none() && t.path.is_none()
                }
                crate::http_portal::PLUGIN => {
                    t.path.is_some() && t.command.is_none() && t.arg.is_none()
                }
                _ => true,
            };
            if !shape_ok {
                out.push(format!(
                    "hook '{}' trigger does not fit plug-in {}",
                    h.id, self.plugin
                ));
            }
            if let Some(cve) = &h.cve_id
                && !self.claimed_cves.iter().any(|c| &c.cve_id == cve)
            {
                out.push(format!("hook '{}' names unclaimed {cve}", h.id));
            }
        }

        for c in &self.claimed_cves {
            match c.claim {
                ClaimKind::Illustrative if !is_placeholder_cve(&c.cve_id) => out.push(format!(
                    "{} is claimed as illustrative but is not a placeholder id (CVE-2099-*, FOILED-DEMO-*)",
                    c.cve_id
                )),
                ClaimKind::Matched if c.matcher.is_none() || c.harness.is_none() => out.push(
                    format!("{} is claimed as matched without a matcher and harness", c.cve_id),
                ),
                _ => {}
            }
            if let Some(h) = &c.hook
                && !hook_ids.contains(h.as_str())
            {
                out.push(format!("{} names unknown hook '{h}'", c.cve_id));
            }
        }

        let mut slots = BTreeSet::new();
        for c in &self.canaries {
            if !c
                .name
                .chars()
                .all(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit() || ch == '_')
                || c.name.is_empty()
            {
                out.push(format!("canary name '{}' must be [a-z0-9_]+", c.name));
            }
            if !slots.insert(c.name.as_str()) {
                out.push(format!("canary '{}' appears twice", c.name));
            }
        }
        for p in self.placeholders() {
            if !slots.contains(p.as_str()) {
                out.push(format!(
                    "placeholder '{{{{canary.{p}}}}}' has no canary slot"
                ));
            }
        }
        for c in &self.fingerprint_checks {
            let ok = c.item.len() == 5
                && c.item.starts_with("FR-")
                && c.item[3..].chars().all(|ch| ch.is_ascii_digit());
            if !ok {
                out.push(format!("fingerprint item '{}' is not FR-NN", c.item));
            }
        }
        out
    }

    /// Fail unless the profile is valid and fully rendered.
    pub fn check_ready(&self) -> Result<(), ProfileError> {
        let mut p = self.problems();
        if !self.is_rendered() {
            p.push("canary placeholders are not rendered".into());
        }
        if p.is_empty() {
            Ok(())
        } else {
            Err(ProfileError::Invalid(p))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn canaries(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn shipped_profiles_parse_and_are_valid() {
        for (id, _) in BUILTIN {
            let p = Profile::builtin(id).unwrap_or_else(|| panic!("{id} parses"));
            assert_eq!(&p.id, id);
            assert!(p.problems().is_empty(), "{id}: {:?}", p.problems());
            assert!(!p.is_rendered(), "{id} should carry canary placeholders");
        }
        assert_eq!(Profile::builtin_ids("redis"), vec!["redis-7.0"]);
        assert_eq!(Profile::builtin_ids("http_portal"), vec!["portal-generic"]);
    }

    #[test]
    fn render_fills_declared_slots_only() {
        let p = Profile::builtin("redis-7.0").unwrap();
        let names: Vec<String> = p.canaries.iter().map(|c| c.name.clone()).collect();
        assert!(matches!(
            p.render(&BTreeMap::new()),
            Err(ProfileError::Canary(_))
        ));
        let values: BTreeMap<String, String> = names
            .iter()
            .map(|n| (n.clone(), format!("canary-{n}-value")))
            .collect();
        let r = p.render(&values).unwrap();
        assert!(r.is_rendered());
        assert!(r.check_ready().is_ok());
        assert!(serde_json::to_string(&r).unwrap().contains("canary-"));
    }

    #[test]
    fn undeclared_placeholder_is_a_problem() {
        let mut p = Profile::builtin("redis-7.0").unwrap();
        p.description = "{{canary.nope}}".into();
        assert!(p.problems().iter().any(|x| x.contains("nope")));
        assert!(p.render(&canaries(&[("nope", "x")])).is_err());
    }

    #[test]
    fn real_looking_cve_cannot_be_illustrative() {
        let mut p = Profile::builtin("redis-7.0").unwrap();
        p.claimed_cves[0].cve_id = "CVE-2022-0543".into();
        assert!(
            p.problems()
                .iter()
                .any(|x| x.contains("not a placeholder id"))
        );
        p.claimed_cves[0].claim = ClaimKind::Matched;
        assert!(
            p.problems()
                .iter()
                .any(|x| x.contains("matcher and harness"))
        );
    }

    #[test]
    fn wrong_section_and_bad_jitter_are_problems() {
        let mut p = Profile::builtin("redis-7.0").unwrap();
        p.plugin = "http_portal".into();
        assert!(p.problems().iter().any(|x| x.contains("http section")));
        let mut p = Profile::builtin("redis-7.0").unwrap();
        p.jitter = Jitter {
            min_ms: 10,
            max_ms: 1,
        };
        assert!(!p.problems().is_empty());
    }

    #[test]
    fn unknown_fields_are_rejected() {
        let text = include_str!("../../../emulators/redis/profiles/redis-7.0.yaml");
        let bad = format!("{text}\nexecute_lua: true\n");
        assert!(Profile::from_yaml(&bad).is_err());
    }
}
