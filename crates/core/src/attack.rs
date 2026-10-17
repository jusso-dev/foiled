//! MITRE ATT&CK technique mapping (#26).
//!
//! Rules under `rules/attack/*.yaml` map capture envelopes
//! ([`CaptureEvent`]) to official ATT&CK technique ids from the pinned
//! version in `data/attack/VERSION`. Callers parse the YAML into a
//! `serde_json::Value` and then into [`AttackRule`]; this module never reads
//! files. The contract is `schemas/attack-rule.schema.json` and the doc is
//! `docs/attack-mapping.md`.
//!
//! Rule matches are evidence, not verdicts. Each [`TechniqueLink`] carries
//! the signals that produced it and goes to the confidence layer (#27) for a
//! score. LLM suggestions never come through here (#28).

use std::borrow::Cow;
use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::capture::{CaptureEvent, Channel, HookStage, Severity};

/// Highest rule weight.
pub const MAX_WEIGHT: u8 = 100;

/// One mapping rule. Mirrors `schemas/attack-rule.schema.json`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AttackRule {
    pub id: String,
    /// Official ATT&CK id, technique (`T1059`) or sub-technique (`T1059.004`).
    pub technique: String,
    /// Signal strength 0-100 handed to #27.
    pub weight: u8,
    pub evidence_summary: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// If not empty, the event channel must be one of these.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub channels: Vec<Channel>,
    /// Every condition must hold.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub all: Vec<Condition>,
    /// At least one condition must hold, when not empty.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub any: Vec<Condition>,
}

/// A test on one envelope field. Exactly one operator must be set.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Condition {
    pub field: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub equals: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub contains: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prefix: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub contains_any: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prefix_any: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exists: Option<bool>,
    /// Compare ASCII case-insensitively.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub ignore_case: bool,
}

enum Op<'a> {
    Equals(&'a str),
    Contains(&'a str),
    Prefix(&'a str),
    ContainsAny(&'a [String]),
    PrefixAny(&'a [String]),
    Exists(bool),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HookField {
    HookId,
    CatalogueId,
    CveId,
    Stage,
    CmdLines,
    FileWrites,
    ImplantRefs,
    Notes,
}

enum Field<'a> {
    Channel,
    DecoyKind,
    CatalogueId,
    Severity,
    Hook(HookField),
    Data(Vec<&'a str>),
}

fn parse_field(s: &str) -> Option<Field<'_>> {
    Some(match s {
        "channel" => Field::Channel,
        "decoy_kind" => Field::DecoyKind,
        "catalogue_id" => Field::CatalogueId,
        "severity" => Field::Severity,
        "hook.hook_id" => Field::Hook(HookField::HookId),
        "hook.catalogue_id" => Field::Hook(HookField::CatalogueId),
        "hook.cve_id" => Field::Hook(HookField::CveId),
        "hook.stage" => Field::Hook(HookField::Stage),
        "hook.cmd_lines" => Field::Hook(HookField::CmdLines),
        "hook.file_writes" => Field::Hook(HookField::FileWrites),
        "hook.implant_refs" => Field::Hook(HookField::ImplantRefs),
        "hook.notes" => Field::Hook(HookField::Notes),
        _ => {
            let path = s.strip_prefix("data.")?;
            let parts: Vec<&str> = path.split('.').collect();
            if parts.iter().any(|p| p.is_empty()) {
                return None;
            }
            Field::Data(parts)
        }
    })
}

fn severity_str(s: Severity) -> &'static str {
    match s {
        Severity::Info => "info",
        Severity::Low => "low",
        Severity::Medium => "medium",
        Severity::High => "high",
        Severity::Critical => "critical",
    }
}

fn stage_str(s: HookStage) -> &'static str {
    match s {
        HookStage::Trigger => "trigger",
        HookStage::PostExploit => "post_exploit",
        HookStage::Cleanup => "cleanup",
    }
}

fn scalar(v: &Value) -> Option<Cow<'_, str>> {
    match v {
        Value::String(s) => Some(Cow::Borrowed(s)),
        Value::Number(n) => Some(Cow::Owned(n.to_string())),
        Value::Bool(b) => Some(Cow::Owned(b.to_string())),
        _ => None,
    }
}

/// The string values of `field` on `event`. `None` when the field is absent
/// or null. Lists yield one value per scalar element.
fn resolve<'e>(field: &Field<'_>, event: &'e CaptureEvent) -> Option<Vec<Cow<'e, str>>> {
    let one = |s: &'e str| Some(vec![Cow::Borrowed(s)]);
    let list = |v: &'e [String]| Some(v.iter().map(|s| Cow::Borrowed(s.as_str())).collect());
    match field {
        Field::Channel => one(event.channel.as_str()),
        Field::DecoyKind => one(event.decoy_kind.as_str()),
        Field::CatalogueId => one(&event.catalogue_id),
        Field::Severity => one(severity_str(event.severity)),
        Field::Hook(f) => {
            let h = event.hook.as_ref()?;
            match f {
                HookField::HookId => one(&h.hook_id),
                HookField::CatalogueId => one(&h.catalogue_id),
                HookField::CveId => one(h.cve_id.as_deref()?),
                HookField::Stage => one(stage_str(h.stage)),
                HookField::CmdLines => list(&h.cmd_lines),
                HookField::FileWrites => list(&h.file_writes),
                HookField::ImplantRefs => list(&h.implant_refs),
                HookField::Notes => one(h.notes.as_deref()?),
            }
        }
        Field::Data(path) => {
            let (first, rest) = path.split_first()?;
            let mut v = event.data.get(*first)?;
            for key in rest {
                v = v.as_object()?.get(*key)?;
            }
            match v {
                Value::Null => None,
                Value::Array(items) => Some(items.iter().filter_map(scalar).collect()),
                Value::Object(_) => Some(Vec::new()),
                other => Some(scalar(other).into_iter().collect()),
            }
        }
    }
}

fn fold(s: &str, ignore_case: bool) -> Cow<'_, str> {
    if ignore_case {
        Cow::Owned(s.to_ascii_lowercase())
    } else {
        Cow::Borrowed(s)
    }
}

impl Condition {
    fn op(&self) -> Result<Op<'_>, &'static str> {
        let mut ops = Vec::new();
        if let Some(v) = &self.equals {
            ops.push(Op::Equals(v));
        }
        if let Some(v) = &self.contains {
            ops.push(Op::Contains(v));
        }
        if let Some(v) = &self.prefix {
            ops.push(Op::Prefix(v));
        }
        if let Some(v) = &self.contains_any {
            ops.push(Op::ContainsAny(v));
        }
        if let Some(v) = &self.prefix_any {
            ops.push(Op::PrefixAny(v));
        }
        if let Some(v) = self.exists {
            ops.push(Op::Exists(v));
        }
        if ops.len() != 1 {
            return Err("needs exactly one operator");
        }
        let op = ops.pop().expect("one operator");
        // An empty needle would match every value.
        let empty_needle = match &op {
            Op::Contains(n) | Op::Prefix(n) => n.is_empty(),
            Op::ContainsAny(ns) | Op::PrefixAny(ns) => {
                ns.is_empty() || ns.iter().any(|n| n.is_empty())
            }
            Op::Equals(_) | Op::Exists(_) => false,
        };
        if empty_needle {
            return Err("needles must not be empty");
        }
        Ok(op)
    }

    fn check(&self) -> Result<(), &'static str> {
        if parse_field(&self.field).is_none() {
            return Err("unknown field");
        }
        self.op().map(|_| ())
    }

    /// Whether the condition holds for `event`. A malformed condition never
    /// holds, so an unvalidated rule fails closed.
    pub fn matches(&self, event: &CaptureEvent) -> bool {
        let (Some(field), Ok(op)) = (parse_field(&self.field), self.op()) else {
            return false;
        };
        let values = resolve(&field, event);
        if let Op::Exists(want) = op {
            return values.is_some() == want;
        }
        let Some(values) = values else {
            return false;
        };
        let ic = self.ignore_case;
        values.iter().any(|v| {
            let v = fold(v, ic);
            match &op {
                Op::Equals(n) => v == fold(n, ic),
                Op::Contains(n) => v.contains(fold(n, ic).as_ref()),
                Op::Prefix(n) => v.starts_with(fold(n, ic).as_ref()),
                Op::ContainsAny(ns) => ns.iter().any(|n| v.contains(fold(n, ic).as_ref())),
                Op::PrefixAny(ns) => ns.iter().any(|n| v.starts_with(fold(n, ic).as_ref())),
                Op::Exists(_) => unreachable!("handled above"),
            }
        })
    }
}

impl AttackRule {
    /// Whether the rule fires on `event`. A rule with no conditions never
    /// fires.
    pub fn matches(&self, event: &CaptureEvent) -> bool {
        if self.all.is_empty() && self.any.is_empty() {
            return false;
        }
        if !self.channels.is_empty() && !self.channels.contains(&event.channel) {
            return false;
        }
        self.all.iter().all(|c| c.matches(event))
            && (self.any.is_empty() || self.any.iter().any(|c| c.matches(event)))
    }
}

/// True for an official technique (`T1059`) or sub-technique (`T1059.004`) id.
pub fn is_technique_id(s: &str) -> bool {
    let b = s.as_bytes();
    let digits = |r: &[u8]| r.iter().all(u8::is_ascii_digit);
    match b.len() {
        5 => b[0] == b'T' && digits(&b[1..5]),
        9 => b[0] == b'T' && digits(&b[1..5]) && b[5] == b'.' && digits(&b[6..9]),
        _ => false,
    }
}

/// Split an official id into `(technique_id, subtechnique_id)`.
pub fn split_technique(id: &str) -> Option<(String, Option<String>)> {
    if !is_technique_id(id) {
        return None;
    }
    Some(match id.split_once('.') {
        Some((parent, _)) => (parent.to_string(), Some(id.to_string())),
        None => (id.to_string(), None),
    })
}

/// MITRE's page for `id` in the pinned major version, for UI chips (#14).
pub fn technique_url(attack_version: &str, id: &str) -> String {
    let major = attack_version.split('.').next().unwrap_or(attack_version);
    format!(
        "https://attack.mitre.org/versions/v{major}/techniques/{}/",
        id.replace('.', "/")
    )
}

/// One rule firing on one event.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MatchedSignal {
    pub rule_id: String,
    pub event_id: String,
    pub weight: u8,
    pub summary: String,
}

/// Every signal for one technique or sub-technique across a set of events.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TechniqueLink {
    pub technique_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subtechnique_id: Option<String>,
    pub matched_signals: Vec<MatchedSignal>,
    pub max_weight: u8,
}

impl TechniqueLink {
    /// The most specific official id: the sub-technique when there is one.
    pub fn official_id(&self) -> &str {
        self.subtechnique_id
            .as_deref()
            .unwrap_or(&self.technique_id)
    }

    /// The stored link object (`schemas/technique-link.schema.json`).
    pub fn for_attempt(self, attempt_id: &str, attack_version: &str) -> AttemptTechniqueLink {
        AttemptTechniqueLink {
            attempt_id: attempt_id.to_string(),
            attack_version: attack_version.to_string(),
            technique_id: self.technique_id,
            subtechnique_id: self.subtechnique_id,
            matched_signals: self.matched_signals,
            max_weight: self.max_weight,
            confidence_ref: None,
        }
    }
}

/// An attempt (#25) to technique link as stored and exported. Mirrors
/// `schemas/technique-link.schema.json`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AttemptTechniqueLink {
    pub attempt_id: String,
    pub attack_version: String,
    pub technique_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subtechnique_id: Option<String>,
    pub matched_signals: Vec<MatchedSignal>,
    pub max_weight: u8,
    /// Set once #27 has scored the link.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub confidence_ref: Option<String>,
}

/// Run `rules` over `events` (normally one attempt's events) and return one
/// link per technique or sub-technique that any rule matched.
///
/// Output is deterministic: links are ordered by technique then
/// sub-technique id, signals by event time, event id and rule id, and a
/// rule that matches the same event twice (a duplicated envelope) counts
/// once. Rules with a malformed technique id or condition are ignored; run
/// [`validate`] when loading rules so that never happens silently.
pub fn evaluate(rules: &[AttackRule], events: &[CaptureEvent]) -> Vec<TechniqueLink> {
    type Key = (String, Option<String>);
    type SignalKey = (i64, String, String);
    let mut found: BTreeMap<Key, BTreeMap<SignalKey, MatchedSignal>> = BTreeMap::new();
    for rule in rules {
        let Some(key) = split_technique(&rule.technique) else {
            continue;
        };
        for event in events.iter().filter(|e| rule.matches(e)) {
            found.entry(key.clone()).or_default().insert(
                (event.ts, event.event_id.clone(), rule.id.clone()),
                MatchedSignal {
                    rule_id: rule.id.clone(),
                    event_id: event.event_id.clone(),
                    weight: rule.weight.min(MAX_WEIGHT),
                    summary: rule.evidence_summary.clone(),
                },
            );
        }
    }
    found
        .into_iter()
        .map(|((technique_id, subtechnique_id), signals)| {
            let mut matched_signals: Vec<MatchedSignal> = Vec::new();
            for s in signals.into_values() {
                // The same event id with a different ts is still the same event.
                if !matched_signals
                    .iter()
                    .any(|m| m.event_id == s.event_id && m.rule_id == s.rule_id)
                {
                    matched_signals.push(s);
                }
            }
            let max_weight = matched_signals.iter().map(|s| s.weight).max().unwrap_or(0);
            TechniqueLink {
                technique_id,
                subtechnique_id,
                matched_signals,
                max_weight,
            }
        })
        .collect()
}

/// A rule that cannot be loaded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuleProblem {
    BadRuleId(String),
    DuplicateRuleId(String),
    BadTechniqueId {
        rule: String,
        technique: String,
    },
    UnknownTechnique {
        rule: String,
        technique: String,
    },
    WeightOutOfRange {
        rule: String,
        weight: u8,
    },
    EmptySummary(String),
    NoConditions(String),
    BadCondition {
        rule: String,
        field: String,
        reason: &'static str,
    },
}

impl std::fmt::Display for RuleProblem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RuleProblem::BadRuleId(id) => {
                write!(f, "rule id '{id}' must match ^[a-z0-9][a-z0-9.-]*$")
            }
            RuleProblem::DuplicateRuleId(id) => write!(f, "rule id '{id}' is used more than once"),
            RuleProblem::BadTechniqueId { rule, technique } => {
                write!(f, "{rule}: '{technique}' is not an ATT&CK technique id")
            }
            RuleProblem::UnknownTechnique { rule, technique } => write!(
                f,
                "{rule}: {technique} is not in the pinned ATT&CK sidecar (data/attack/techniques.json)"
            ),
            RuleProblem::WeightOutOfRange { rule, weight } => {
                write!(f, "{rule}: weight {weight} is above {MAX_WEIGHT}")
            }
            RuleProblem::EmptySummary(rule) => write!(f, "{rule}: evidence_summary is empty"),
            RuleProblem::NoConditions(rule) => {
                write!(f, "{rule}: needs at least one condition in all or any")
            }
            RuleProblem::BadCondition {
                rule,
                field,
                reason,
            } => {
                write!(f, "{rule}: condition on '{field}': {reason}")
            }
        }
    }
}

fn is_rule_id(s: &str) -> bool {
    let mut chars = s.chars();
    s.len() <= 64
        && chars
            .next()
            .is_some_and(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
        && chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '.' | '-'))
}

/// Check `rules` against each other and against `known`, the official ids in
/// the pinned sidecar. A sub-technique's parent must be known too, so the UI
/// can always name both.
pub fn validate(rules: &[AttackRule], known: &BTreeSet<String>) -> Vec<RuleProblem> {
    let mut out = Vec::new();
    let mut seen = BTreeSet::new();
    for rule in rules {
        let id = &rule.id;
        if !is_rule_id(id) {
            out.push(RuleProblem::BadRuleId(id.clone()));
        }
        if !seen.insert(id.as_str()) {
            out.push(RuleProblem::DuplicateRuleId(id.clone()));
        }
        match split_technique(&rule.technique) {
            None => out.push(RuleProblem::BadTechniqueId {
                rule: id.clone(),
                technique: rule.technique.clone(),
            }),
            Some((parent, sub)) => {
                for t in sub.iter().chain(std::iter::once(&parent)) {
                    if !known.contains(t) {
                        out.push(RuleProblem::UnknownTechnique {
                            rule: id.clone(),
                            technique: t.clone(),
                        });
                    }
                }
            }
        }
        if rule.weight > MAX_WEIGHT {
            out.push(RuleProblem::WeightOutOfRange {
                rule: id.clone(),
                weight: rule.weight,
            });
        }
        if rule.evidence_summary.trim().is_empty() {
            out.push(RuleProblem::EmptySummary(id.clone()));
        }
        if rule.all.is_empty() && rule.any.is_empty() {
            out.push(RuleProblem::NoConditions(id.clone()));
        }
        for c in rule.all.iter().chain(&rule.any) {
            if let Err(reason) = c.check() {
                out.push(RuleProblem::BadCondition {
                    rule: id.clone(),
                    field: c.field.clone(),
                    reason,
                });
            }
        }
    }
    out
}

/// One technique in the curated sidecar `data/attack/techniques.json`.
/// `id`, `name`, `tactics` and `stix_id` are copied unchanged from the pinned
/// bundle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TechniqueInfo {
    pub id: String,
    pub name: String,
    pub tactics: Vec<String>,
    pub url: String,
    pub stix_id: String,
}

/// The curated subset of the pinned ATT&CK version that Foiled ships, with
/// MITRE's notice kept alongside it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AttackSidecar {
    pub attack_version: String,
    pub domain: String,
    pub source: String,
    pub notice: String,
    pub licence: String,
    pub licence_url: String,
    pub sidecar_note: String,
    pub techniques: Vec<TechniqueInfo>,
}

impl AttackSidecar {
    pub fn known_ids(&self) -> BTreeSet<String> {
        self.techniques.iter().map(|t| t.id.clone()).collect()
    }

    pub fn get(&self, id: &str) -> Option<&TechniqueInfo> {
        self.techniques.iter().find(|t| t.id == id)
    }

    /// Checks the sidecar must pass before it ships.
    pub fn problems(&self) -> Vec<String> {
        let mut out = Vec::new();
        if !self.notice.contains("The MITRE Corporation") {
            out.push("notice must carry MITRE's copyright designation".to_string());
        }
        if self.licence.trim().is_empty()
            || !self.licence_url.starts_with("https://attack.mitre.org/")
        {
            out.push("licence and licence_url must reproduce MITRE's terms of use".to_string());
        }
        let ids = self.known_ids();
        if ids.len() != self.techniques.len() {
            out.push("technique ids must be unique".to_string());
        }
        for t in &self.techniques {
            let Some((parent, sub)) = split_technique(&t.id) else {
                out.push(format!("'{}' is not an ATT&CK technique id", t.id));
                continue;
            };
            if sub.is_some() && !ids.contains(&parent) {
                out.push(format!("{}: parent {parent} is missing", t.id));
            }
            if t.name.trim().is_empty() || t.tactics.is_empty() {
                out.push(format!("{}: name and tactics are required", t.id));
            }
            if t.url != technique_url(&self.attack_version, &t.id) {
                out.push(format!(
                    "{}: url must point at the pinned version's page",
                    t.id
                ));
            }
            if !t.stix_id.starts_with("attack-pattern--") {
                out.push(format!("{}: stix_id must be an attack-pattern id", t.id));
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn event(text: &str) -> CaptureEvent {
        serde_json::from_str(text).unwrap()
    }

    fn demo_attempt() -> Vec<CaptureEvent> {
        [
            include_str!("../../../testdata/attack/demo-01-upload.json"),
            include_str!("../../../testdata/attack/demo-02-hook-trigger.json"),
            include_str!("../../../testdata/attack/demo-03-hook-post-exploit.json"),
            include_str!("../../../testdata/attack/demo-04-egress-download.json"),
        ]
        .into_iter()
        .map(event)
        .collect()
    }

    fn rule(v: serde_json::Value) -> AttackRule {
        serde_json::from_value(v).unwrap()
    }

    fn shell_rule() -> AttackRule {
        rule(json!({
            "id": "t1059-004-hook-shell",
            "technique": "T1059.004",
            "weight": 80,
            "evidence_summary": "Unix shell command ran after the vulnerable path fired",
            "channels": ["hook"],
            "all": [
                {"field": "hook.stage", "equals": "post_exploit"},
                {"field": "hook.cmd_lines", "contains_any": ["sh -c", "| sh", "bash -c"]}
            ]
        }))
    }

    fn known() -> BTreeSet<String> {
        [
            "T1059",
            "T1059.004",
            "T1105",
            "T1190",
            "T1053",
            "T1053.003",
            "T1110",
            "T1110.001",
        ]
        .into_iter()
        .map(String::from)
        .collect()
    }

    fn ids(links: &[TechniqueLink]) -> Vec<&str> {
        links.iter().map(TechniqueLink::official_id).collect()
    }

    #[test]
    fn post_exploit_shell_exec_links_t1059_004() {
        let links = evaluate(&[shell_rule()], &demo_attempt());
        assert_eq!(links.len(), 1);
        let link = &links[0];
        assert_eq!(link.technique_id, "T1059");
        assert_eq!(link.subtechnique_id.as_deref(), Some("T1059.004"));
        assert_eq!(link.max_weight, 80);
        assert_eq!(
            link.matched_signals,
            vec![MatchedSignal {
                rule_id: "t1059-004-hook-shell".into(),
                event_id: "atk-demo-03".into(),
                weight: 80,
                summary: "Unix shell command ran after the vulnerable path fired".into(),
            }]
        );
    }

    #[test]
    fn trigger_stage_hook_is_not_a_shell_exec() {
        let trigger = event(include_str!(
            "../../../testdata/attack/demo-02-hook-trigger.json"
        ));
        assert!(!shell_rule().matches(&trigger));
    }

    #[test]
    fn three_demo_fixtures_map_to_techniques() {
        let rules = [
            rule(
                json!({"id": "a", "technique": "T1190", "weight": 85, "evidence_summary": "s",
                        "channels": ["hook"], "all": [{"field": "hook.stage", "equals": "trigger"}]}),
            ),
            rule(
                json!({"id": "b", "technique": "T1053.003", "weight": 70, "evidence_summary": "s",
                        "all": [{"field": "data.command", "equals": "config", "ignore_case": true},
                                {"field": "data.args", "prefix_any": ["/var/spool/cron"]}]}),
            ),
            rule(
                json!({"id": "c", "technique": "T1110.001", "weight": 30, "evidence_summary": "s",
                        "all": [{"field": "data.eventid", "equals": "cowrie.login.failed"}]}),
            ),
        ];
        assert!(validate(&rules, &known()).is_empty());
        for (text, want) in [
            (
                include_str!("../../../testdata/attack/demo-02-hook-trigger.json"),
                "T1190",
            ),
            (
                include_str!("../../../testdata/attack/redis-01-config-dir.json"),
                "T1053.003",
            ),
            (
                include_str!("../../../testdata/attack/ssh-01-login-failed.json"),
                "T1110.001",
            ),
        ] {
            assert_eq!(ids(&evaluate(&rules, &[event(text)])), vec![want]);
        }
        // CONFIG SET dbfilename is not a cron write.
        let other = event(include_str!(
            "../../../testdata/attack/redis-03-config-dbfilename.json"
        ));
        assert!(evaluate(&rules, &[other]).is_empty());
    }

    #[test]
    fn links_are_deduplicated_and_ordered() {
        let rules = [
            shell_rule(),
            rule(
                json!({"id": "t1105-egress", "technique": "T1105", "weight": 60, "evidence_summary": "egress",
                        "channels": ["egress"], "all": [{"field": "data.method", "equals": "GET"}]}),
            ),
            rule(
                json!({"id": "t1105-hook", "technique": "T1105", "weight": 55, "evidence_summary": "hook",
                        "all": [{"field": "hook.cmd_lines", "contains": "curl "}]}),
            ),
            rule(
                json!({"id": "t1190", "technique": "T1190", "weight": 85, "evidence_summary": "trigger",
                        "all": [{"field": "hook.stage", "equals": "trigger"}]}),
            ),
        ];
        let events = demo_attempt();
        let links = evaluate(&rules, &events);
        assert_eq!(ids(&links), vec!["T1059.004", "T1105", "T1190"]);
        let t1105 = &links[1];
        assert_eq!(t1105.max_weight, 60);
        let order: Vec<(&str, &str)> = t1105
            .matched_signals
            .iter()
            .map(|s| (s.event_id.as_str(), s.rule_id.as_str()))
            .collect();
        assert_eq!(
            order,
            vec![
                ("atk-demo-03", "t1105-hook"),
                ("atk-demo-04", "t1105-egress")
            ]
        );

        // Input order and duplicated envelopes do not change the result.
        let mut shuffled: Vec<_> = events.iter().rev().cloned().collect();
        shuffled.extend(events.iter().cloned());
        let mut rules_rev = rules.to_vec();
        rules_rev.reverse();
        assert_eq!(evaluate(&rules_rev, &shuffled), links);
    }

    #[test]
    fn operators_cover_data_lists_numbers_and_case() {
        let upload = event(include_str!("../../../testdata/attack/demo-01-upload.json"));
        let redis = event(include_str!(
            "../../../testdata/attack/redis-02-set-cron-miner.json"
        ));
        let cond = |v: serde_json::Value| -> Condition { serde_json::from_value(v).unwrap() };
        assert!(cond(json!({"field": "data.status", "equals": "201"})).matches(&upload));
        assert!(cond(json!({"field": "data.path", "prefix": "/api/upload"})).matches(&upload));
        assert!(!cond(json!({"field": "data.path", "prefix": "/upload"})).matches(&upload));
        assert!(cond(json!({"field": "data.matcher_id", "exists": true})).matches(&upload));
        assert!(cond(json!({"field": "data.nope", "exists": false})).matches(&upload));
        assert!(!cond(json!({"field": "data.nope", "contains": "x"})).matches(&upload));
        assert!(!cond(json!({"field": "data.path.deeper", "exists": true})).matches(&upload));
        assert!(cond(json!({"field": "channel", "equals": "application"})).matches(&upload));
        assert!(cond(json!({"field": "decoy_kind", "equals": "sandbox"})).matches(&upload));
        assert!(!cond(json!({"field": "hook.stage", "exists": true})).matches(&upload));
        // XMRig in the fixture, xmrig in the needle.
        assert!(!cond(json!({"field": "data.args", "contains_any": ["xmrig"]})).matches(&redis));
        assert!(
            cond(json!({"field": "data.args", "contains_any": ["xmrig"], "ignore_case": true}))
                .matches(&redis)
        );
    }

    #[test]
    fn malformed_rules_fail_closed() {
        let events = demo_attempt();
        let bad = [
            rule(
                json!({"id": "two-ops", "technique": "T1190", "weight": 1, "evidence_summary": "s",
                        "all": [{"field": "hook.stage", "equals": "trigger", "prefix": "t"}]}),
            ),
            rule(
                json!({"id": "empty-needle", "technique": "T1190", "weight": 1, "evidence_summary": "s",
                        "all": [{"field": "data.path", "contains_any": [""]}]}),
            ),
            rule(
                json!({"id": "bad-field", "technique": "T1190", "weight": 1, "evidence_summary": "s",
                        "all": [{"field": "payload", "exists": false}]}),
            ),
            rule(
                json!({"id": "no-conditions", "technique": "T1190", "weight": 1, "evidence_summary": "s"}),
            ),
            rule(
                json!({"id": "bad-technique", "technique": "T1190.1", "weight": 1, "evidence_summary": "s",
                        "all": [{"field": "channel", "equals": "hook"}]}),
            ),
        ];
        assert!(evaluate(&bad, &events).is_empty());
    }

    #[test]
    fn validate_reports_every_problem() {
        let rules = [
            rule(
                json!({"id": "Bad Id", "technique": "T9999", "weight": 101, "evidence_summary": " ",
                        "all": [{"field": "data.", "equals": "x"}]}),
            ),
            rule(
                json!({"id": "dup", "technique": "T1059.999", "weight": 5, "evidence_summary": "s",
                        "any": [{"field": "data.x"}]}),
            ),
            rule(json!({"id": "dup", "technique": "T1059", "weight": 5, "evidence_summary": "s"})),
            rule(
                json!({"id": "fine", "technique": "nope", "weight": 5, "evidence_summary": "s",
                        "all": [{"field": "data.x", "prefix_any": []}]}),
            ),
        ];
        let p = validate(&rules, &known());
        let has = |want: &RuleProblem| assert!(p.contains(want), "missing {want:?} in {p:?}");
        has(&RuleProblem::BadRuleId("Bad Id".into()));
        has(&RuleProblem::UnknownTechnique {
            rule: "Bad Id".into(),
            technique: "T9999".into(),
        });
        has(&RuleProblem::WeightOutOfRange {
            rule: "Bad Id".into(),
            weight: 101,
        });
        has(&RuleProblem::EmptySummary("Bad Id".into()));
        has(&RuleProblem::BadCondition {
            rule: "Bad Id".into(),
            field: "data.".into(),
            reason: "unknown field",
        });
        has(&RuleProblem::UnknownTechnique {
            rule: "dup".into(),
            technique: "T1059.999".into(),
        });
        has(&RuleProblem::BadCondition {
            rule: "dup".into(),
            field: "data.x".into(),
            reason: "needs exactly one operator",
        });
        has(&RuleProblem::DuplicateRuleId("dup".into()));
        has(&RuleProblem::NoConditions("dup".into()));
        has(&RuleProblem::BadTechniqueId {
            rule: "fine".into(),
            technique: "nope".into(),
        });
        has(&RuleProblem::BadCondition {
            rule: "fine".into(),
            field: "data.x".into(),
            reason: "needles must not be empty",
        });
        assert_eq!(p.len(), 11, "{p:?}");
        assert!(validate(&[shell_rule()], &known()).is_empty());
        // A sub-technique needs its parent in the sidecar too.
        let only_sub: BTreeSet<String> = ["T1059.004".to_string()].into();
        assert_eq!(
            validate(&[shell_rule()], &only_sub),
            vec![RuleProblem::UnknownTechnique {
                rule: "t1059-004-hook-shell".into(),
                technique: "T1059".into()
            }]
        );
    }

    #[test]
    fn technique_ids_and_urls() {
        for ok in ["T1059", "T1059.004", "T0001"] {
            assert!(is_technique_id(ok), "{ok}");
        }
        for bad in [
            "t1059",
            "T159",
            "T1059.04",
            "T1059.0041",
            "T1059-004",
            "TA0002",
            "",
        ] {
            assert!(!is_technique_id(bad), "{bad}");
        }
        assert_eq!(split_technique("T1110"), Some(("T1110".into(), None)));
        assert_eq!(
            technique_url("20.0", "T1059.004"),
            "https://attack.mitre.org/versions/v20/techniques/T1059/004/"
        );
    }

    #[test]
    fn attempt_link_serialises_to_the_stored_shape() {
        let link = evaluate(&[shell_rule()], &demo_attempt()).remove(0);
        let stored = serde_json::to_value(link.for_attempt("atm-demo-1", "20.0")).unwrap();
        assert_eq!(stored["attempt_id"], "atm-demo-1");
        assert_eq!(stored["technique_id"], "T1059");
        assert_eq!(stored["subtechnique_id"], "T1059.004");
        assert!(stored.get("confidence_ref").is_none());
    }

    #[test]
    fn sidecar_problems_catch_drift() {
        let mut s = AttackSidecar {
            attack_version: "20.0".into(),
            domain: "enterprise-attack".into(),
            source: "https://github.com/mitre/cti".into(),
            notice: "\u{a9} 2026 The MITRE Corporation.".into(),
            licence: "terms".into(),
            licence_url: "https://attack.mitre.org/resources/legal-and-branding/terms-of-use/"
                .into(),
            sidecar_note: "subset".into(),
            techniques: vec![TechniqueInfo {
                id: "T1059".into(),
                name: "Command and Scripting Interpreter".into(),
                tactics: vec!["execution".into()],
                url: technique_url("20.0", "T1059"),
                stix_id: "attack-pattern--7385dfaf-6886-4229-9ecd-6fd678040830".into(),
            }],
        };
        assert!(s.problems().is_empty(), "{:?}", s.problems());
        s.techniques.push(TechniqueInfo {
            id: "T1105.001".into(),
            name: "x".into(),
            tactics: vec!["command-and-control".into()],
            url: "https://attack.mitre.org/techniques/T1105/001".into(),
            stix_id: "attack-pattern--x".into(),
        });
        s.notice = "copyright".into();
        assert_eq!(s.problems().len(), 3, "{:?}", s.problems());
    }
}
