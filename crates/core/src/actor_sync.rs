//! The actor reference catalogue sourced from ThreatSieve (#29): a staged
//! sync of actors, intrusion sets, campaigns and reports over the service
//! binding, mapped into the curated report format ([`ActorReport`]) and
//! kept as a versioned snapshot.
//!
//! Pure and deterministic, with no I/O: [`SyncState`] says which request
//! comes next ([`SyncState::next_request`]) and takes each answer
//! ([`SyncState::apply`]). The API's cron runs a bounded number of calls per
//! invocation, saves the state between runs, and on completion writes the
//! [`Snapshot`] ([`snapshot`]). [`LayeredSource`] serves the catalogue: the
//! bundled ATT&CK groups and curated reports always, plus the snapshot's
//! entries while it is fresh.
//!
//! Every imported entry passes the same checks as a curated one
//! ([`ActorReport::problems`]): attribution wording, the two-publisher rule
//! for named groups, technique ids from the pinned sidecar, valid
//! indicators. Entries with one publisher are never named groups and count
//! at [`crate::actor::SINGLE_PUBLISHER_WEIGHT_PCT`]. Entries with a source
//! that does not allow redistribution or commercial use are `restricted`:
//! matched and shown, never exported (the same rule as enrichment, #11).
//! See `docs/actor-attribution.md#threatsieve`.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::actor::{
    ActorReport, AttackGroups, CatalogueSource, Geo, Imported, Indicator, IndicatorType, Label,
    LabelKind, MAX_REPORT_INDICATORS, MAX_REPORT_TECHNIQUES, MAX_SOURCES, ReportTargeting, Source,
    SourceKind, https_host, normalise, wording_problems,
};
use crate::enrich_pipeline::{HttpMethod, ProviderRequest};

/// Snapshot and sync state format. A change starts a fresh sync.
pub const FORMAT: u32 = 1;
/// Base URL; the host is ignored by a service binding.
pub const BASE_URL: &str = "https://threatsieve/v1";
/// Page size for list calls (ThreatSieve allows 1 to 100).
pub const PAGE_LIMIT: u32 = 100;
/// The hub name recorded on imported entries.
pub const HUB: &str = "threatsieve";
/// Most aliases kept per entry.
const MAX_ALIASES: usize = 16;
/// Most report URLs read from one entity's external references.
const MAX_REFS: usize = 8;
/// Most dropped-entry notes kept in a snapshot.
const MAX_DROPPED_NOTES: usize = 100;
const DAY_MS: i64 = 86_400_000;

// ---------------------------------------------------------------------------
// Config (`configs/actor-catalogue.yaml`)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CatalogueConfig {
    pub version: u32,
    pub threatsieve: ThreatSieveSync,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ThreatSieveSync {
    pub enabled: bool,
    /// Service binding name in `wrangler.jsonc` (the one enrichment uses).
    pub binding: String,
    /// Worker secret holding the API key (scope `intel:read`).
    pub api_key_env: String,
    /// R2 key prefix in the evidence bucket for the state and snapshots.
    pub blob_prefix: String,
    /// Calls to ThreatSieve per cron run.
    pub calls_per_run: u32,
    /// Start a new sync once the snapshot is this old.
    pub refresh_after_hours: u32,
    /// Stop serving a snapshot this old: the catalogue falls back to the
    /// bundled ATT&CK groups and curated reports.
    pub stale_after_hours: u32,
    /// Give up on a sync still running after this long and start again.
    pub max_sync_hours: u32,
    pub max_actors: usize,
    pub max_campaigns: usize,
    pub max_reports: usize,
    /// Serve entries with a source that does not allow redistribution or
    /// commercial use (matched and shown, never exported). Off by default,
    /// like `show_restricted_to_requester` in enrichment: turn on only once
    /// counsel has confirmed those terms allow showing them to tenants.
    pub include_restricted: bool,
}

impl CatalogueConfig {
    pub fn problems(&self) -> Vec<String> {
        let mut out = Vec::new();
        let t = &self.threatsieve;
        if self.version != 1 {
            out.push("version must be 1".into());
        }
        let env_ok = |s: &str| {
            !s.is_empty()
                && s.bytes()
                    .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_')
        };
        if !env_ok(&t.binding) || !env_ok(&t.api_key_env) {
            out.push("binding and api_key_env are upper-case names".into());
        }
        if !(t.blob_prefix.ends_with('/') && !t.blob_prefix.starts_with('/'))
            || t.blob_prefix.contains("..")
        {
            out.push("blob_prefix must be a relative key prefix ending in /".into());
        }
        if !(1..=200).contains(&t.calls_per_run) {
            out.push("calls_per_run must be 1 to 200".into());
        }
        if t.refresh_after_hours == 0 || t.stale_after_hours <= t.refresh_after_hours {
            out.push("stale_after_hours must be greater than refresh_after_hours".into());
        }
        if t.max_sync_hours == 0 {
            out.push("max_sync_hours must be positive".into());
        }
        for (n, v) in [
            ("max_actors", t.max_actors),
            ("max_campaigns", t.max_campaigns),
            ("max_reports", t.max_reports),
        ] {
            if !(1..=5000).contains(&v) {
                out.push(format!("{n} must be 1 to 5000"));
            }
        }
        out
    }
}

// ---------------------------------------------------------------------------
// ThreatSieve responses (camelCase entities, snake_case envelopes)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TsProvenance {
    #[serde(default)]
    pub source_id: String,
    #[serde(default)]
    pub source_name: String,
    #[serde(default)]
    pub source_url: Option<String>,
    #[serde(default)]
    pub retrieved_at: Option<String>,
    #[serde(default)]
    pub published_at: Option<String>,
    #[serde(default)]
    pub license: Option<String>,
    #[serde(default)]
    pub redistributable: bool,
    /// Source assertions only: a copy of another source's record.
    #[serde(default)]
    pub mirrored: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TsEntity {
    pub id: String,
    #[serde(rename = "type")]
    pub kind: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub aliases: Vec<String>,
    #[serde(default)]
    pub external_id: Option<String>,
    #[serde(default)]
    pub data: Value,
    #[serde(default)]
    pub provenance: TsProvenance,
}

#[derive(Debug, Clone, Default, Deserialize)]
struct TsList {
    #[serde(default)]
    data: Vec<TsEntity>,
    #[serde(default)]
    next_cursor: Option<String>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
struct TsRelated {
    #[serde(default)]
    relationship_type: String,
    #[serde(default)]
    assertion_type: String,
    #[serde(default)]
    entity: Option<TsEntity>,
}

#[derive(Debug, Clone, Deserialize)]
struct TsDetail {
    entity: TsEntity,
    #[serde(default)]
    source_assertions: Vec<TsProvenance>,
    #[serde(default)]
    relationships: Vec<TsRelated>,
}

// ---------------------------------------------------------------------------
// Sync state
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Phase {
    Actors,
    Campaigns,
    Reports,
    Details,
    Done,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EntityKind {
    Actor,
    Campaign,
}

/// One publisher's record of an entity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceDigest {
    pub source_id: String,
    pub name: String,
    pub url: Option<String>,
    /// `YYYY-MM-DD`.
    pub published: Option<String>,
    pub retrieved: Option<String>,
    pub licence: Option<String>,
    pub redistributable: bool,
    pub mirrored: bool,
}

/// What Foiled keeps of one actor or campaign.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EntityDigest {
    pub entity_id: String,
    pub kind: EntityKind,
    pub name: String,
    pub aliases: Vec<String>,
    pub external_id: Option<String>,
    pub sources: Vec<SourceDigest>,
    /// https URLs from the entity's external references.
    pub refs: Vec<String>,
    pub techniques: BTreeSet<String>,
    /// `(type, value)` of observables related to the entity.
    pub indicators: BTreeSet<(IndicatorType, String)>,
    pub cves: BTreeSet<String>,
}

/// A report entity and the entities it names.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReportDigest {
    pub title: String,
    pub source: SourceDigest,
    pub object_refs: BTreeSet<String>,
}

/// Why a run stopped early.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SyncError {
    /// Rate limited or unavailable: keep the state, try next run.
    Later { retry_after_secs: Option<u32> },
    /// Refused or unreadable: start a new sync next run.
    Fatal(String),
}

/// A sync in progress, saved between cron runs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SyncState {
    pub format: u32,
    pub started_at: i64,
    pub phase: Phase,
    pub cursor: Option<String>,
    /// Entities to fetch in detail, in list order.
    pub queue: Vec<(String, EntityKind)>,
    pub next_detail: usize,
    pub details: Vec<EntityDigest>,
    pub reports: Vec<ReportDigest>,
    pub calls: u32,
    /// Detail fetches that answered 404 (removed since the listing).
    pub missing: u32,
    #[serde(default)]
    pub last_error: Option<String>,
}

fn encode(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

fn date_part(s: &Option<String>) -> Option<String> {
    s.as_deref()
        .and_then(|d| d.get(..10))
        .filter(|d| crate::actor::date_ms(d).is_some())
        .map(str::to_string)
}

fn digest_source(p: &TsProvenance) -> SourceDigest {
    SourceDigest {
        source_id: p.source_id.clone(),
        name: p.source_name.clone(),
        url: p.source_url.clone().filter(|u| https_host(u).is_some()),
        published: date_part(&p.published_at),
        retrieved: date_part(&p.retrieved_at),
        licence: p.license.clone().filter(|l| !l.trim().is_empty()),
        redistributable: p.redistributable,
        mirrored: p.mirrored,
    }
}

/// https URLs in `data.stix.external_references`, and the MITRE id there.
fn stix_refs(data: &Value) -> (Vec<String>, Option<String>) {
    let mut urls = Vec::new();
    let mut mitre = None;
    for r in data
        .pointer("/stix/external_references")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        if r.get("source_name").and_then(Value::as_str) == Some("mitre-attack") {
            mitre = r
                .get("external_id")
                .and_then(Value::as_str)
                .map(str::to_string);
        }
        if let Some(u) = r.get("url").and_then(Value::as_str)
            && https_host(u).is_some()
            && urls.len() < MAX_REFS
            && !urls.iter().any(|x| x == u)
        {
            urls.push(u.to_string());
        }
    }
    (urls, mitre)
}

fn observable_indicator(e: &TsEntity) -> Option<(IndicatorType, String)> {
    let kind = match e.data.get("observableType").and_then(Value::as_str)? {
        "ipv4" | "ipv6" => IndicatorType::Ip,
        "domain" => IndicatorType::Domain,
        "url" => IndicatorType::Url,
        "sha256" => IndicatorType::Sha256,
        _ => return None,
    };
    normalise(kind, &e.name).map(|v| (kind, v))
}

fn is_attack_id(s: &str, prefix: char) -> bool {
    s.len() == 5 && s.starts_with(prefix) && s[1..].bytes().all(|b| b.is_ascii_digit())
}

impl SyncState {
    pub fn new(now: i64) -> Self {
        SyncState {
            format: FORMAT,
            started_at: now,
            phase: Phase::Actors,
            cursor: None,
            queue: Vec::new(),
            next_detail: 0,
            details: Vec::new(),
            reports: Vec::new(),
            calls: 0,
            missing: 0,
            last_error: None,
        }
    }

    pub fn is_done(&self) -> bool {
        self.phase == Phase::Done
    }

    /// The next call, or `None` when the sync is done.
    pub fn next_request(&self, api_key: &str) -> Option<ProviderRequest> {
        let page = |path: &str| {
            let mut url = format!("{BASE_URL}/{path}limit={PAGE_LIMIT}");
            if let Some(c) = &self.cursor {
                url.push_str(&format!("&cursor={}", encode(c)));
            }
            url
        };
        let url = match self.phase {
            Phase::Actors => page("actors?"),
            Phase::Campaigns => page("campaigns?"),
            Phase::Reports => page("entities?type=report&"),
            Phase::Details => {
                let (id, _) = self.queue.get(self.next_detail)?;
                format!("{BASE_URL}/entities/{}", encode(id))
            }
            Phase::Done => return None,
        };
        Some(ProviderRequest {
            method: HttpMethod::Get,
            url,
            headers: vec![
                ("authorization".into(), format!("Bearer {api_key}")),
                ("accept".into(), "application/json".into()),
            ],
            body: None,
        })
    }

    fn after_list(&mut self, next: Option<String>, full: bool) {
        self.cursor = next.filter(|_| !full);
        if self.cursor.is_none() {
            self.phase = match self.phase {
                Phase::Actors => Phase::Campaigns,
                Phase::Campaigns => Phase::Reports,
                Phase::Reports | Phase::Details => {
                    if self.queue.is_empty() {
                        Phase::Done
                    } else {
                        Phase::Details
                    }
                }
                Phase::Done => Phase::Done,
            };
        }
    }

    /// Take the answer to [`SyncState::next_request`].
    pub fn apply(
        &mut self,
        cfg: &ThreatSieveSync,
        status: u16,
        body: &str,
        retry_after_secs: Option<u32>,
    ) -> Result<(), SyncError> {
        self.calls += 1;
        match status {
            200 => {}
            404 if self.phase == Phase::Details => {
                self.missing += 1;
                self.next_detail += 1;
                if self.next_detail >= self.queue.len() {
                    self.phase = Phase::Done;
                }
                return Ok(());
            }
            429 | 500..=599 => return Err(SyncError::Later { retry_after_secs }),
            s => return Err(SyncError::Fatal(format!("ThreatSieve answered {s}"))),
        }
        let bad = |e: serde_json::Error| SyncError::Fatal(format!("unreadable answer: {e}"));
        match self.phase {
            Phase::Actors | Phase::Campaigns => {
                let list: TsList = serde_json::from_str(body).map_err(bad)?;
                let (kind, cap) = if self.phase == Phase::Actors {
                    (EntityKind::Actor, cfg.max_actors)
                } else {
                    (EntityKind::Campaign, cfg.max_campaigns)
                };
                let wanted: &[&str] = if kind == EntityKind::Actor {
                    &["threat-actor", "intrusion-set"]
                } else {
                    &["campaign"]
                };
                let mut have = self.queue.iter().filter(|(_, k)| *k == kind).count();
                for e in list.data {
                    if have >= cap {
                        break;
                    }
                    if wanted.contains(&e.kind.as_str())
                        && !self.queue.iter().any(|(id, _)| *id == e.id)
                    {
                        self.queue.push((e.id, kind));
                        have += 1;
                    }
                }
                self.after_list(list.next_cursor, have >= cap);
            }
            Phase::Reports => {
                let list: TsList = serde_json::from_str(body).map_err(bad)?;
                for e in list.data {
                    if self.reports.len() >= cfg.max_reports {
                        break;
                    }
                    if e.kind != "report" {
                        continue;
                    }
                    let (refs, _) = stix_refs(&e.data);
                    let mut source = digest_source(&e.provenance);
                    if source.url.is_none() {
                        source.url = refs.first().cloned();
                    }
                    if source.published.is_none() {
                        source.published = e
                            .data
                            .pointer("/stix/published")
                            .and_then(Value::as_str)
                            .and_then(|d| date_part(&Some(d.to_string())));
                    }
                    let object_refs = e
                        .data
                        .pointer("/stix/object_refs")
                        .and_then(Value::as_array)
                        .into_iter()
                        .flatten()
                        .filter_map(Value::as_str)
                        .map(str::to_string)
                        .collect();
                    self.reports.push(ReportDigest {
                        title: e.name,
                        source,
                        object_refs,
                    });
                }
                let full = self.reports.len() >= cfg.max_reports;
                self.after_list(list.next_cursor, full);
            }
            Phase::Details => {
                let d: TsDetail = serde_json::from_str(body).map_err(bad)?;
                let kind = self
                    .queue
                    .get(self.next_detail)
                    .map(|(_, k)| *k)
                    .unwrap_or(EntityKind::Actor);
                self.details.push(digest_detail(d, kind));
                self.next_detail += 1;
                if self.next_detail >= self.queue.len() {
                    self.phase = Phase::Done;
                }
            }
            Phase::Done => {}
        }
        Ok(())
    }
}

fn digest_detail(d: TsDetail, kind: EntityKind) -> EntityDigest {
    let e = d.entity;
    let (refs, mitre_ref) = stix_refs(&e.data);
    let mut sources: Vec<SourceDigest> = d.source_assertions.iter().map(digest_source).collect();
    if sources.is_empty() {
        sources.push(digest_source(&e.provenance));
    }
    let mut techniques = BTreeSet::new();
    let mut indicators = BTreeSet::new();
    let mut cves = BTreeSet::new();
    for r in d.relationships {
        // Model inferences are never evidence of anything here.
        if r.assertion_type == "model_inferred" {
            continue;
        }
        let Some(other) = r.entity else {
            continue;
        };
        match other.kind.as_str() {
            "attack-technique" if r.relationship_type.eq_ignore_ascii_case("uses") => {
                if let Some(t) = other
                    .external_id
                    .filter(|t| crate::attack::is_technique_id(t))
                {
                    techniques.insert(t);
                }
            }
            "observable" => {
                if let Some(i) = observable_indicator(&other) {
                    indicators.insert(i);
                }
            }
            "vulnerability" => {
                if let Some(c) = other
                    .external_id
                    .map(|c| c.to_ascii_uppercase())
                    .filter(|c| c.starts_with("CVE-"))
                {
                    cves.insert(c);
                }
            }
            _ => {}
        }
    }
    EntityDigest {
        entity_id: e.id,
        kind,
        name: e.name,
        aliases: e.aliases,
        external_id: e.external_id.or(mitre_ref),
        sources,
        refs,
        techniques,
        indicators,
        cves,
    }
}

// ---------------------------------------------------------------------------
// Mapping and the snapshot
// ---------------------------------------------------------------------------

/// Whether a ThreatSieve source allows commercial use, from its licence
/// records (ThreatSieve migration 0034). Entity answers carry only
/// `redistributable`; anything not listed counts as unknown, which is not
/// allowed.
pub fn commercial_use(source_id: &str) -> Option<bool> {
    match source_id {
        "mitre" | "cisa-kev" | "misp" | "iptoasn" | "epss" | "nvd" => Some(true),
        "threatfox" | "urlhaus" | "feodo" | "greynoise" | "crowdsec" | "virustotal" => Some(false),
        _ => None,
    }
}

fn source_kind(source_id: &str) -> SourceKind {
    match source_id {
        "mitre" => SourceKind::AttackGroup,
        "cisa-kev" => SourceKind::GovernmentAdvisory,
        "misp" | "misp-feed" => SourceKind::MispGalaxy,
        _ => SourceKind::VendorReport,
    }
}

fn to_source(
    s: &SourceDigest,
    title: &str,
    fallback_url: Option<&str>,
    day: &str,
) -> Option<Source> {
    let url = s.url.clone().or(fallback_url.map(str::to_string))?;
    let retrieved = s.retrieved.clone().unwrap_or_else(|| day.to_string());
    let published = s.published.clone().unwrap_or_else(|| retrieved.clone());
    // A publication date after retrieval is a feed error; trust retrieval.
    let published = if published > retrieved {
        retrieved.clone()
    } else {
        published
    };
    let name = if s.name.trim().is_empty() {
        s.source_id.clone()
    } else {
        s.name.trim().to_string()
    };
    Some(Source {
        kind: source_kind(&s.source_id),
        publisher: name,
        title: title.chars().take(200).collect(),
        url,
        published,
        retrieved: Some(retrieved),
        sha256: None,
        licence: s.licence.clone().unwrap_or_else(|| {
            format!(
                "Unknown (ThreatSieve source {}); treated as not redistributable",
                s.source_id
            )
        }),
        licence_url: None,
    })
}

fn restricted(s: &SourceDigest) -> bool {
    !s.redistributable || commercial_use(&s.source_id) != Some(true)
}

/// Map one entity, with the reports that name it, into the curated format.
/// `Err` says why it was left out.
pub fn map_entity(
    d: &EntityDigest,
    reports: &[&ReportDigest],
    known: &BTreeSet<String>,
    day: &str,
) -> Result<ActorReport, String> {
    let name: String = d.name.trim().chars().take(80).collect();
    if name.is_empty() {
        return Err("no name".into());
    }
    if let Some(p) = wording_problems(&name, false).first() {
        return Err(format!("name: {p}"));
    }
    let mitre = d.sources.iter().any(|s| s.source_id == "mitre");
    let attack_id = d.external_id.clone().filter(|x| {
        mitre
            && match d.kind {
                EntityKind::Actor => is_attack_id(x, 'G'),
                EntityKind::Campaign => is_attack_id(x, 'C'),
            }
    });
    let title = match (&attack_id, d.kind) {
        (Some(a), _) => format!("ATT&CK {a} ({name})"),
        (None, EntityKind::Campaign) => format!("Campaign {name}"),
        (None, EntityKind::Actor) => name.clone(),
    };
    // Mirrors are copies of another source's record: never a publisher.
    let own: Vec<&SourceDigest> = d.sources.iter().filter(|s| !s.mirrored).collect();
    let mut sources: Vec<Source> = Vec::new();
    let mut restricted_any = false;
    for s in &own {
        restricted_any |= restricted(s);
        if let Some(src) = to_source(s, &title, d.refs.first().map(String::as_str), day) {
            sources.push(src);
        }
    }
    for r in reports {
        restricted_any |= restricted(&r.source);
        if let Some(src) = to_source(&r.source, &r.title, None, day) {
            sources.push(src);
        }
    }
    sources.dedup_by(|a, b| a.url == b.url && a.publisher == b.publisher);
    sources.truncate(MAX_SOURCES);
    if sources.is_empty() {
        return Err("no source with an https URL".into());
    }
    let publishers = sources
        .iter()
        .map(|s| s.publisher.trim().to_lowercase())
        .collect::<BTreeSet<_>>()
        .len() as u32;
    let kind = if attack_id.is_none() && d.kind == EntityKind::Actor && publishers >= 2 {
        LabelKind::NamedGroup
    } else {
        LabelKind::Cluster
    };
    let techniques: Vec<String> = d
        .techniques
        .iter()
        .filter(|t| known.contains(*t))
        .take(MAX_REPORT_TECHNIQUES)
        .cloned()
        .collect();
    let indicators: Vec<Indicator> = d
        .indicators
        .iter()
        .take(MAX_REPORT_INDICATORS)
        .map(|(k, v)| Indicator {
            kind: *k,
            value: v.clone(),
            source: 0,
        })
        .collect();
    let aliases: Vec<String> = d
        .aliases
        .iter()
        .map(|a| a.trim().chars().take(80).collect::<String>())
        .filter(|a| !a.is_empty() && *a != name && wording_problems(a, false).is_empty())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .take(MAX_ALIASES)
        .collect();
    let h = Sha256::digest(d.entity_id.as_bytes());
    let report = ActorReport {
        id: format!("ts-{}", hex::encode(&h[..6])),
        example: false,
        label: Label { kind, text: name },
        aliases,
        sources,
        techniques,
        indicators,
        targeting: ReportTargeting {
            cves: d.cves.iter().cloned().collect(),
            catalogue_ids: vec![],
        },
        geo: Geo::default(),
        notes: format!("Imported from ThreatSieve entity {}.", d.entity_id)
            .chars()
            .take(1000)
            .collect(),
        imported: Some(Imported {
            from: HUB.into(),
            entity_id: d.entity_id.clone(),
            attack_id,
            restricted: restricted_any,
            publishers,
        }),
    };
    let problems = report.problems(known);
    if problems.is_empty() {
        Ok(report)
    } else {
        Err(problems.join("; "))
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnapshotCounts {
    pub actors: u32,
    pub campaigns: u32,
    pub reports: u32,
    pub imported: u32,
    pub restricted: u32,
    pub dropped: u32,
    pub missing: u32,
}

/// A finished import, as stored. Mirrors what [`LayeredSource`] serves.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Snapshot {
    pub format: u32,
    pub source: String,
    /// Unix ms the sync finished.
    pub synced_at: i64,
    pub started_at: i64,
    /// The pinned ATT&CK version technique ids were checked against.
    pub attack_version: String,
    pub counts: SnapshotCounts,
    /// Imported entries, sorted by id.
    pub reports: Vec<ActorReport>,
    /// Why entries were left out (at most 100).
    pub dropped: Vec<String>,
}

/// Where the current snapshot is, with its digest (the pin).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnapshotPointer {
    pub format: u32,
    pub key: String,
    pub synced_at: i64,
    /// SHA-256 of the snapshot body; a reader refuses a body that differs.
    pub sha256: String,
    pub imported: u32,
}

/// Build the snapshot from a finished sync.
pub fn snapshot(state: &SyncState, sidecar: &crate::attack::AttackSidecar, now: i64) -> Snapshot {
    let known = sidecar.known_ids();
    let day = crate::timeline::iso(now)[..10].to_string();
    let mut counts = SnapshotCounts {
        reports: state.reports.len() as u32,
        missing: state.missing,
        ..Default::default()
    };
    let mut reports = Vec::new();
    let mut dropped = Vec::new();
    for d in &state.details {
        match d.kind {
            EntityKind::Actor => counts.actors += 1,
            EntityKind::Campaign => counts.campaigns += 1,
        }
        let naming: Vec<&ReportDigest> = state
            .reports
            .iter()
            .filter(|r| r.object_refs.contains(&d.entity_id))
            .collect();
        match map_entity(d, &naming, &known, &day) {
            Ok(r) => {
                if r.imported.as_ref().is_some_and(|i| i.restricted) {
                    counts.restricted += 1;
                }
                reports.push(r);
            }
            Err(why) => {
                counts.dropped += 1;
                if dropped.len() < MAX_DROPPED_NOTES {
                    dropped.push(format!("{}: {why}", d.entity_id));
                }
            }
        }
    }
    reports.sort_by(|a, b| a.id.cmp(&b.id));
    reports.dedup_by(|a, b| a.id == b.id);
    counts.imported = reports.len() as u32;
    Snapshot {
        format: FORMAT,
        source: HUB.into(),
        synced_at: now,
        started_at: state.started_at,
        attack_version: sidecar.attack_version.clone(),
        counts,
        reports,
        dropped,
    }
}

/// Lowercase hex SHA-256 of a snapshot body.
pub fn body_sha256(body: &str) -> String {
    hex::encode(Sha256::digest(body.as_bytes()))
}

impl Snapshot {
    pub fn is_fresh(&self, cfg: &ThreatSieveSync, now: i64) -> bool {
        self.format == FORMAT
            && now - self.synced_at <= i64::from(cfg.stale_after_hours) * 3_600_000
            && self.synced_at <= now + DAY_MS
    }
}

/// The catalogue the API serves: the bundled ATT&CK groups and curated
/// reports always, plus a fresh snapshot's imports. A stale or missing
/// snapshot falls back to the bundled data alone.
pub struct LayeredSource<'a> {
    pub groups: Option<AttackGroups>,
    pub curated: Vec<ActorReport>,
    pub snapshot: Option<&'a Snapshot>,
    pub config: &'a ThreatSieveSync,
    pub now: i64,
}

impl CatalogueSource for LayeredSource<'_> {
    fn attack_groups(&self) -> Option<AttackGroups> {
        self.groups.clone()
    }

    fn reports(&self) -> Vec<ActorReport> {
        let mut out = self.curated.clone();
        if let Some(s) = self.snapshot.filter(|s| s.is_fresh(self.config, self.now)) {
            out.extend(
                s.reports
                    .iter()
                    .filter(|r| {
                        r.imported
                            .as_ref()
                            .is_some_and(|i| self.config.include_restricted || !i.restricted)
                    })
                    .cloned(),
            );
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn requests_are_paged_and_ids_encoded() {
        let mut s = SyncState::new(0);
        let r = s.next_request("k").unwrap();
        assert_eq!(r.url, "https://threatsieve/v1/actors?limit=100");
        assert_eq!(r.headers[0].1, "Bearer k");
        s.cursor = Some("intrusion-set--a b".into());
        assert!(
            s.next_request("k")
                .unwrap()
                .url
                .ends_with("&cursor=intrusion-set--a%20b")
        );
        s.phase = Phase::Details;
        s.queue = vec![("obs/x?y".into(), EntityKind::Actor)];
        assert_eq!(
            s.next_request("k").unwrap().url,
            "https://threatsieve/v1/entities/obs%2Fx%3Fy"
        );
        s.phase = Phase::Done;
        assert!(s.next_request("k").is_none());
    }

    #[test]
    fn commercial_use_follows_the_licence_records() {
        assert_eq!(commercial_use("mitre"), Some(true));
        assert_eq!(commercial_use("greynoise"), Some(false));
        assert_eq!(commercial_use("taxii-foiled"), None);
    }
}
