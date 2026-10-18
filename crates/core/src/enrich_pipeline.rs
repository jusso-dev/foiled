//! The `foiled-enrich` pipeline (#11): queue messages, the enrichment
//! config, the per-message plan, and the ThreatSieve lookup.
//!
//! External intel comes from one hub, ThreatSieve (the operator's own threat
//! intel platform), called over a Cloudflare service binding with `POST
//! /v1/lookup`. ThreatSieve gathers the per-source data (GreyNoise, KEV,
//! EPSS and the rest) and says, per answer, which sources it came from and
//! whether each may be redistributed or used commercially. Foiled turns
//! that into Facts and keeps anything restricted out of exports and away
//! from other tenants. The operator's own `local_asn` table stays a
//! separate, first-party provider.
//!
//! Everything here is pure and builds for `wasm32-unknown-unknown`. The API
//! Worker does the I/O (`foiled_api::enrich_consumer`). See
//! `docs/enrichment.md`; the lookup contract is ThreatSieve's.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::capture::{CaptureEvent, Severity};
use crate::enrichment::{
    CacheEntry, Fact, LOCAL_ASN, Observable, ObservableKind, ParseError, THREATSIEVE,
    THREATSIEVE_RESTRICTED, clip, observables_for_event,
};

/// Version of [`EnrichMessage`].
pub const MESSAGE_VERSION: u32 = 1;
/// Most messages one ingest batch sends. Anything beyond is left for the
/// next time the observable is seen.
pub const MAX_MESSAGES_PER_BATCH: usize = 500;
/// Most observables in one ThreatSieve lookup (the contract's limit).
pub const MAX_LOOKUP_BATCH: usize = 500;
/// Longest ThreatSieve answer read, in bytes.
pub const MAX_RESPONSE_BYTES: usize = 4 * 1024 * 1024;
/// Longest wait for ThreatSieve, in milliseconds.
pub const FETCH_TIMEOUT_MS: u32 = 10_000;
/// Longest backoff after repeated failures for one observable.
pub const MAX_BACKOFF_SECS: u64 = 24 * 3600;
/// Longest `Retry-After` honoured, in seconds.
pub const MAX_RETRY_AFTER_SECS: u32 = 3600;
/// `Retry-After` used when a 429 carries none Foiled can read.
pub const DEFAULT_RETRY_AFTER_SECS: u32 = 60;
/// Share of a day budget `normal` messages may use; the rest is kept for
/// `high` ones.
pub const NORMAL_DAY_SHARE_PERCENT: u32 = 80;
/// URL of the lookup. The host is ignored by a service binding; the path
/// is ThreatSieve's.
pub const LOOKUP_URL: &str = "https://threatsieve/v1/lookup";
/// Longest an answer may be cached while ThreatSieve is still fetching one
/// of its sources (`pending_sources`). ThreatSieve caps `ttl_seconds` the
/// same way; Foiled enforces it too.
pub const PENDING_MAX_TTL_SECS: u64 = 300;
/// Most sources listed in `threatsieve.sources`.
pub const MAX_SOURCES: usize = 16;
/// Most relationships kept per answer, and their highest confidence.
/// Relationships are context for an analyst, never attribution.
pub const MAX_RELATIONSHIPS: usize = 16;
pub const RELATIONSHIP_MAX_CONFIDENCE: u8 = 20;
/// Confidence of a `model_inferred` relationship.
pub const MODEL_INFERRED_CONFIDENCE: u8 = 5;
/// Confidence given to CVE catalogue Facts (KEV, EPSS, CVSS, OSV).
pub const CVE_CONFIDENCE: u8 = 90;
/// Confidence given to network Facts (ASN, prefix, country).
pub const NETWORK_CONFIDENCE: u8 = 85;

// ---------------------------------------------------------------------------
// Config (`configs/enrichment.yaml`, schema enrichment-config.schema.json)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnrichConfig {
    pub version: u32,
    pub queue: String,
    pub cache: CacheSettings,
    pub show_to_tenants: bool,
    pub providers: Providers,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CacheSettings {
    pub store: String,
    pub negative_ttl_secs: u64,
    pub error_backoff_secs: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Providers {
    pub local_asn: LocalProvider,
    pub threatsieve: ThreatSieveProvider,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LocalProvider {
    pub enabled: bool,
    pub observables: Vec<ObservableKind>,
    pub dataset_key: String,
    pub ttl_secs: u64,
}

/// Sections ThreatSieve can answer with.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LookupSection {
    Reputation,
    Network,
    Cve,
    Relationships,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ThreatSieveProvider {
    pub enabled: bool,
    pub observables: Vec<ObservableKind>,
    /// Service binding name in `wrangler.jsonc`.
    pub binding: String,
    /// Worker secret holding the ThreatSieve API key (scope `intel:read`).
    pub api_key_env: String,
    pub include: Vec<LookupSection>,
    /// Longest Foiled keeps an answer. Never longer than ThreatSieve's own
    /// `ttl_seconds` for it.
    pub ttl_secs: u64,
    /// Observables per lookup, at most [`MAX_LOOKUP_BATCH`].
    pub batch_size: usize,
    /// Lookups (not observables) per minute and per day.
    pub rate_limit: RateLimit,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RateLimit {
    pub per_minute: u32,
    pub per_day: u32,
}

fn env_name_ok(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 64
        && s.as_bytes()[0].is_ascii_uppercase()
        && s.bytes()
            .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_')
}

impl EnrichConfig {
    /// Checks the schema cannot express.
    pub fn problems(&self) -> Vec<String> {
        let mut out = Vec::new();
        if self.version != 1 {
            out.push("version must be 1".into());
        }
        if self.cache.store != "d1" {
            out.push("cache.store must be d1".into());
        }
        let t = &self.providers.threatsieve;
        if !(1..=MAX_LOOKUP_BATCH).contains(&t.batch_size) {
            out.push(format!(
                "threatsieve.batch_size must be 1 to {MAX_LOOKUP_BATCH}"
            ));
        }
        if !env_name_ok(&t.binding) || !env_name_ok(&t.api_key_env) {
            out.push("threatsieve binding and api_key_env must be upper-case names".into());
        }
        if t.include.is_empty() {
            out.push("threatsieve.include must not be empty".into());
        }
        if t.rate_limit.per_minute == 0 || t.rate_limit.per_day == 0 {
            out.push("threatsieve rate limits must be at least 1".into());
        }
        out
    }
}

// ---------------------------------------------------------------------------
// Messages
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Priority {
    Normal,
    High,
}

/// One message on `foiled-enrich`: one observable seen by one tenant.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnrichMessage {
    pub v: u32,
    pub observable: Observable,
    pub tenant_id: String,
    #[serde(default)]
    pub event_id: Option<String>,
    #[serde(default)]
    pub attempt_id: Option<String>,
    pub first_seen: i64,
    pub priority: Priority,
}

impl EnrichMessage {
    /// Why the consumer must drop this message. Empty when it is fine.
    pub fn problems(&self) -> Vec<String> {
        let mut out = Vec::new();
        if self.v != MESSAGE_VERSION {
            out.push(format!("unknown message version {}", self.v));
        }
        if self.tenant_id.is_empty() || self.tenant_id.len() > 128 || self.tenant_id.contains('@') {
            out.push("tenant_id must be 1 to 128 characters without '@'".into());
        }
        // Never ask about the operator's own network.
        if !self.observable.is_external_lookup_eligible() {
            out.push("observable is not eligible for an external lookup".into());
        }
        out
    }
}

/// Messages for a stamped ingest batch: the observables of each event
/// (`enrichment::observables_for_event`), of its IOCs
/// (`ioc::event_observables`) and the CVE id of a hook hit, one per tenant
/// and observable, earliest sighting first, `high` when any event that named
/// it was `high` or `critical`. Events without a tenant are skipped. At most
/// [`MAX_MESSAGES_PER_BATCH`], high priority first.
pub fn messages_for_events(events: &[CaptureEvent]) -> Vec<EnrichMessage> {
    let mut by: BTreeMap<(String, Observable), EnrichMessage> = BTreeMap::new();
    for e in events {
        let Some(tenant) = e.tenant_id.as_deref().filter(|t| !t.is_empty()) else {
            continue;
        };
        let priority = if e.severity >= Severity::High {
            Priority::High
        } else {
            Priority::Normal
        };
        let mut observables = observables_for_event(e);
        observables.extend(crate::ioc::event_observables(e));
        // Demo ids (FOILED-DEMO-0001) are not CVE ids and are skipped.
        observables.extend(
            e.hook
                .as_ref()
                .and_then(|h| h.cve_id.as_deref())
                .and_then(|c| Observable::cve(c).ok()),
        );
        for o in observables {
            if !o.is_external_lookup_eligible() {
                continue;
            }
            let m = by
                .entry((tenant.to_string(), o.clone()))
                .or_insert_with(|| EnrichMessage {
                    v: MESSAGE_VERSION,
                    observable: o,
                    tenant_id: tenant.to_string(),
                    event_id: Some(e.event_id.clone()),
                    attempt_id: e.attempt_id.clone(),
                    first_seen: e.ts,
                    priority,
                });
            if e.ts < m.first_seen {
                m.first_seen = e.ts;
                m.event_id = Some(e.event_id.clone());
            }
            m.priority = m.priority.max(priority);
        }
    }
    let mut out: Vec<EnrichMessage> = by.into_values().collect();
    out.sort_by(|a, b| {
        (b.priority, a.first_seen, &a.observable).cmp(&(a.priority, b.first_seen, &b.observable))
    });
    out.truncate(MAX_MESSAGES_PER_BATCH);
    out
}

// ---------------------------------------------------------------------------
// Plan
// ---------------------------------------------------------------------------

/// A failed provider call for one observable, kept for backoff.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProviderFailureRecord {
    pub provider: String,
    pub observable: Observable,
    pub failures: u32,
    pub last_failed_at: i64,
    /// From the provider's `Retry-After`, when it sent one.
    #[serde(default)]
    pub retry_at: Option<i64>,
}

/// When a provider may be asked again after `failures` failures in a row:
/// `error_backoff_secs` doubled for each repeat, at most
/// [`MAX_BACKOFF_SECS`], and never before a `Retry-After` time.
pub fn backoff_until(f: &ProviderFailureRecord, error_backoff_secs: u64) -> i64 {
    let doublings = f.failures.saturating_sub(1).min(20);
    let secs = error_backoff_secs
        .saturating_mul(1u64 << doublings)
        .min(MAX_BACKOFF_SECS);
    let backoff = f
        .last_failed_at
        .saturating_add(i64::try_from(secs).unwrap_or(i64::MAX).saturating_mul(1000));
    backoff.max(f.retry_at.unwrap_or(i64::MIN))
}

/// What to do with one provider for one message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Step {
    /// A fresh cache row exists that this tenant may read.
    Cached,
    /// Asked too recently after a failure; skip until the backoff ends.
    BackingOff { until: i64 },
    /// Look up in the operator's ASN table.
    Local,
    /// Ask ThreatSieve (batched with the other messages, after budget).
    Lookup,
}

/// The providers to run for a message: `local_asn` and `threatsieve` when
/// enabled for the observable's kind. `fresh` is the fresh cache rows this
/// tenant may read; `failures` the recorded failures.
pub fn plan(
    config: &EnrichConfig,
    observable: &Observable,
    fresh: &[CacheEntry],
    failures: &[ProviderFailureRecord],
    now_ms: i64,
) -> Vec<(&'static str, Step)> {
    let step = |id: &'static str, cached_as: &[&str], run: Step| {
        if fresh.iter().any(|e| {
            cached_as.contains(&e.provider.as_str())
                && &e.observable == observable
                && e.is_fresh(now_ms)
        }) {
            return Step::Cached;
        }
        if let Some(f) = failures
            .iter()
            .find(|f| f.provider == id && &f.observable == observable)
        {
            let until = backoff_until(f, config.cache.error_backoff_secs);
            if now_ms < until {
                return Step::BackingOff { until };
            }
        }
        run
    };
    let mut out = Vec::new();
    let l = &config.providers.local_asn;
    if l.enabled && l.observables.contains(&observable.kind) {
        out.push((LOCAL_ASN, step(LOCAL_ASN, &[LOCAL_ASN], Step::Local)));
    }
    let t = &config.providers.threatsieve;
    if t.enabled && t.observables.contains(&observable.kind) {
        out.push((
            THREATSIEVE,
            step(
                THREATSIEVE,
                &[THREATSIEVE, THREATSIEVE_RESTRICTED],
                Step::Lookup,
            ),
        ));
    }
    out
}

/// The day budget a lookup of `priority` may use: all of it for `high`,
/// [`NORMAL_DAY_SHARE_PERCENT`] for `normal` (at least one).
pub fn day_limit_for(per_day: u32, priority: Priority) -> u32 {
    match priority {
        Priority::High => per_day,
        Priority::Normal => (per_day.saturating_mul(NORMAL_DAY_SHARE_PERCENT) / 100).max(1),
    }
}

// ---------------------------------------------------------------------------
// ThreatSieve lookup
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpMethod {
    Get,
    Post,
}

/// One outbound call, built without any I/O. Headers carry a key, so a
/// `ProviderRequest` is never logged.
#[derive(Clone, PartialEq, Eq)]
pub struct ProviderRequest {
    pub method: HttpMethod,
    pub url: String,
    pub headers: Vec<(String, String)>,
    pub body: Option<String>,
}

impl std::fmt::Debug for ProviderRequest {
    /// Shows the method and URL only: headers may hold a key.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProviderRequest")
            .field("method", &self.method)
            .field("url", &self.url)
            .finish_non_exhaustive()
    }
}

/// ThreatSieve's observable type for a Foiled observable.
pub fn lookup_type(o: &Observable) -> &'static str {
    match o.kind {
        ObservableKind::Ip if o.value.contains(':') => "ipv6",
        ObservableKind::Ip => "ipv4",
        ObservableKind::Domain => "domain",
        ObservableKind::Url => "url",
        ObservableKind::Sha256 => "sha256",
        ObservableKind::Cve => "cve",
    }
}

/// `POST /v1/lookup` for up to [`MAX_LOOKUP_BATCH`] observables, the key as
/// a bearer token. Duplicates are sent once.
pub fn lookup_request(
    observables: &[Observable],
    include: &[LookupSection],
    api_key: &str,
) -> ProviderRequest {
    let mut seen: Vec<&Observable> = Vec::new();
    for o in observables {
        if seen.len() == MAX_LOOKUP_BATCH {
            break;
        }
        if !seen.contains(&o) {
            seen.push(o);
        }
    }
    let body = serde_json::json!({
        "observables": seen
            .iter()
            .map(|o| serde_json::json!({ "type": lookup_type(o), "value": o.value }))
            .collect::<Vec<_>>(),
        "include": include,
    });
    ProviderRequest {
        method: HttpMethod::Post,
        url: LOOKUP_URL.to_string(),
        headers: vec![
            ("authorization".into(), format!("Bearer {api_key}")),
            ("content-type".into(), "application/json".into()),
            ("accept".into(), "application/json".into()),
        ],
        body: Some(body.to_string()),
    }
}

#[derive(Debug, Clone, Default, Deserialize)]
struct LookupResponse {
    #[serde(default)]
    results: Vec<LookupResult>,
}

#[derive(Debug, Clone, Default, Deserialize)]
struct LookupResult {
    #[serde(rename = "type")]
    kind: String,
    value: String,
    /// The spelling Foiled sent (`value` is ThreatSieve's normalised one).
    #[serde(default)]
    input: Option<String>,
    #[serde(default)]
    found: bool,
    #[serde(default)]
    pending_sources: Option<Vec<String>>,
    #[serde(default)]
    error: Option<ResultError>,
    #[serde(default)]
    entity_id: Option<String>,
    #[serde(default)]
    ttl_seconds: Option<u64>,
    #[serde(default)]
    reputation: Option<Reputation>,
    #[serde(default)]
    network: Option<Network>,
    #[serde(default)]
    cve: Option<CveInfo>,
    #[serde(default)]
    relationships: Option<Vec<Relationship>>,
    #[serde(default)]
    sources: Option<Vec<SourceTerms>>,
}

#[derive(Debug, Clone, Default, Deserialize)]
struct ResultError {
    #[serde(default)]
    code: Option<String>,
}

/// ThreatSieve's error shape, `{ "error": { "code", "message" } }`.
#[derive(Debug, Clone, Default, Deserialize)]
struct ErrorBody {
    #[serde(default)]
    error: Option<ResultError>,
}

#[derive(Debug, Clone, Default, Deserialize)]
struct Reputation {
    #[serde(default)]
    classification: Option<String>,
    #[serde(default)]
    score: Option<f64>,
    #[serde(default)]
    confidence: Option<f64>,
    #[serde(default)]
    scanner: Option<Scanner>,
    #[serde(default)]
    tags: Option<Vec<String>>,
}

#[derive(Debug, Clone, Default, Deserialize)]
struct Scanner {
    #[serde(default)]
    is_scanner: Option<bool>,
    #[serde(default)]
    benign_service: Option<bool>,
    #[serde(default)]
    name: Option<String>,
}

#[derive(Debug, Clone, Default, Deserialize)]
struct Network {
    #[serde(default)]
    asn: Option<u64>,
    #[serde(default)]
    as_org: Option<String>,
    #[serde(default)]
    prefix: Option<String>,
    #[serde(default)]
    country: Option<String>,
}

#[derive(Debug, Clone, Default, Deserialize)]
struct CveInfo {
    #[serde(default)]
    status: Option<String>,
    #[serde(default)]
    cvss: Option<Cvss>,
    #[serde(default)]
    cwe: Option<Vec<String>>,
    #[serde(default)]
    kev: Option<Kev>,
    #[serde(default)]
    epss: Option<Epss>,
    #[serde(default)]
    osv_ids: Option<Vec<String>>,
}

#[derive(Debug, Clone, Default, Deserialize)]
struct Cvss {
    #[serde(default)]
    version: Option<String>,
    #[serde(default)]
    base_score: Option<f64>,
    #[serde(default)]
    vector: Option<String>,
}

#[derive(Debug, Clone, Default, Deserialize)]
struct Kev {
    #[serde(default)]
    listed: Option<bool>,
    #[serde(default)]
    date_added: Option<String>,
    #[serde(default)]
    ransomware: Option<String>,
}

#[derive(Debug, Clone, Default, Deserialize)]
struct Epss {
    #[serde(default)]
    score: Option<f64>,
    #[serde(default)]
    percentile: Option<f64>,
}

#[derive(Debug, Clone, Default, Deserialize)]
struct Relationship {
    #[serde(default)]
    id: Option<String>,
    #[serde(rename = "type", default)]
    kind: Option<String>,
    #[serde(default)]
    direction: Option<String>,
    #[serde(default)]
    source_id: Option<String>,
    #[serde(default)]
    assertion: Option<String>,
    #[serde(default)]
    confidence: Option<f64>,
    #[serde(default)]
    target: Option<RelTarget>,
}

#[derive(Debug, Clone, Default, Deserialize)]
struct RelTarget {
    #[serde(rename = "type", default)]
    kind: Option<String>,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    external_ids: Option<BTreeMap<String, Value>>,
}

#[derive(Debug, Clone, Default, Deserialize)]
struct SourceTerms {
    #[serde(default)]
    source_id: Option<String>,
    #[serde(default)]
    license: Option<String>,
    #[serde(default)]
    retrieved_at: Option<String>,
    #[serde(default)]
    redistributable: Option<bool>,
    #[serde(default)]
    commercial_use: Option<bool>,
}

/// One ThreatSieve answer, ready for the cache.
#[derive(Debug, Clone, PartialEq)]
pub struct Mapped {
    pub observable: Observable,
    /// True when any contributing source may not be redistributed or used
    /// commercially, or its terms are unknown. Restricted answers are
    /// written under [`THREATSIEVE_RESTRICTED`], per tenant.
    pub restricted: bool,
    pub found: bool,
    /// ThreatSieve is still fetching a source; the row lives at most
    /// [`PENDING_MAX_TTL_SECS`] so the next sighting asks again.
    pub pending: bool,
    /// ThreatSieve could not use this value (`INVALID_OBSERVABLE`). Nothing
    /// is cached; the consumer records a failure and backs off.
    pub error: Option<String>,
    pub facts: Vec<Fact>,
    /// How long the row may be cached: the shorter of Foiled's TTL and
    /// ThreatSieve's `ttl_seconds` (the negative TTL when there are no
    /// Facts).
    pub ttl_secs: u64,
}

impl Mapped {
    pub fn provider(&self) -> &'static str {
        if self.restricted {
            THREATSIEVE_RESTRICTED
        } else {
            THREATSIEVE
        }
    }
}

/// Why a lookup gave no answers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LookupError {
    /// 429: ask again after this many seconds.
    RateLimited {
        retry_after_secs: u32,
    },
    /// 413: too many observables (Foiled never sends more than 500).
    TooLarge,
    /// 401, 403, 5xx, a redirect or any other non-200 answer.
    Unavailable(String),
    Parse(ParseError),
}

impl std::fmt::Display for LookupError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::RateLimited { retry_after_secs } => {
                write!(f, "rate limited; retry after {retry_after_secs} s")
            }
            Self::TooLarge => write!(f, "too many observables in one lookup"),
            Self::Unavailable(m) => write!(f, "unavailable: {m}"),
            Self::Parse(e) => write!(f, "{e}"),
        }
    }
}

/// `Retry-After` in seconds (a delta; an HTTP date is not parsed and gives
/// the default), capped at [`MAX_RETRY_AFTER_SECS`].
pub fn retry_after_secs(header: Option<&str>) -> u32 {
    header
        .and_then(|h| h.trim().parse::<u32>().ok())
        .unwrap_or(DEFAULT_RETRY_AFTER_SECS)
        .clamp(1, MAX_RETRY_AFTER_SECS)
}

fn fact(
    provider: &str,
    key: &str,
    value: Value,
    confidence: u8,
    now_ms: i64,
    ttl: u64,
    raw_ref: Option<String>,
) -> Fact {
    Fact {
        provider: provider.to_string(),
        key: key.to_string(),
        value,
        confidence: confidence.min(100),
        observed_at: now_ms,
        ttl_secs: ttl,
        raw_ref,
    }
}

fn observable_of(kind: &str, value: &str) -> Option<Observable> {
    let k = match kind {
        "ipv4" | "ipv6" => ObservableKind::Ip,
        "domain" => ObservableKind::Domain,
        "url" => ObservableKind::Url,
        "sha256" => ObservableKind::Sha256,
        "cve" => ObservableKind::Cve,
        _ => return None,
    };
    Observable::new(k, value).ok()
}

fn conf(v: Option<f64>, default: u8) -> u8 {
    v.filter(|c| c.is_finite())
        .map(|c| c.clamp(0.0, 100.0).round() as u8)
        .unwrap_or(default)
}

fn texts(items: &[String], max: usize) -> Value {
    let mut out: Vec<String> = items
        .iter()
        .map(|s| clip(s))
        .filter(|s| !s.is_empty())
        .collect();
    out.sort();
    out.dedup();
    out.truncate(max);
    Value::from(out)
}

/// Map one answer to Facts. Every Fact is keyed under a topic (`asn.`,
/// `geo.`, `cve.`) or `threatsieve.`, carries the answer's provider id, and
/// is clipped like any provider text.
fn map_result(r: &LookupResult, now_ms: i64, config: &EnrichConfig) -> Option<Mapped> {
    // Map back by the spelling Foiled sent; both normalise the same way.
    let observable = r
        .input
        .as_deref()
        .and_then(|i| observable_of(&r.kind, i))
        .or_else(|| observable_of(&r.kind, &r.value))?;
    if let Some(e) = &r.error {
        let code = e.code.as_deref().map(clip).unwrap_or_default();
        return Some(Mapped {
            observable,
            restricted: false,
            found: false,
            pending: false,
            error: Some(if code.is_empty() {
                "rejected by ThreatSieve".into()
            } else {
                code
            }),
            facts: Vec::new(),
            ttl_secs: 0,
        });
    }
    let sources = r.sources.as_deref().unwrap_or(&[]);
    // Any source that forbids (or does not state) redistribution or
    // commercial use makes the whole answer restricted: Facts are not split
    // by source, so the strictest terms win. No sources at all means the
    // provenance is unknown, which is restricted too.
    let restricted = sources.is_empty()
        || sources
            .iter()
            .any(|s| s.redistributable != Some(true) || s.commercial_use != Some(true));
    let provider = if restricted {
        THREATSIEVE_RESTRICTED
    } else {
        THREATSIEVE
    };
    let pending = r.pending_sources.as_ref().is_some_and(|p| !p.is_empty());
    let t = &config.providers.threatsieve;
    let ttl_for = |has_facts: bool| {
        let ours = if has_facts {
            t.ttl_secs
        } else {
            config.cache.negative_ttl_secs
        };
        let mut ttl = r.ttl_seconds.map_or(ours, |s| s.min(ours));
        if pending {
            ttl = ttl.min(PENDING_MAX_TTL_SECS);
        }
        ttl
    };
    // The Fact TTL; the row TTL is settled once the Facts are known.
    let ttl = ttl_for(true);
    let raw_ref = r
        .entity_id
        .as_deref()
        .map(clip)
        .filter(|id| !id.is_empty() && id.len() <= 200)
        .map(|id| format!("threatsieve:{id}"));
    let f = |key: &str, v: Value, c: u8| fact(provider, key, v, c, now_ms, ttl, raw_ref.clone());
    let mut facts = Vec::new();
    // Network context comes for any routed address, found or not.
    if let Some(n) = &r.network {
        if let Some(asn) = n.asn.and_then(|a| u32::try_from(a).ok()) {
            facts.push(f("asn.number", Value::from(asn), NETWORK_CONFIDENCE));
        }
        if let Some(org) = n.as_org.as_deref().map(clip).filter(|o| !o.is_empty()) {
            facts.push(f("asn.org", Value::from(org), NETWORK_CONFIDENCE));
        }
        // The registry country of the range, not where the host is.
        if let Some(c) = n
            .country
            .as_deref()
            .filter(|c| c.len() == 2 && c.bytes().all(|b| b.is_ascii_alphabetic()))
        {
            facts.push(f(
                "geo.country",
                Value::from(c.to_ascii_uppercase()),
                NETWORK_CONFIDENCE,
            ));
        }
        if let Some(p) = n.prefix.as_deref().map(clip).filter(|p| !p.is_empty()) {
            facts.push(f("threatsieve.prefix", Value::from(p), NETWORK_CONFIDENCE));
        }
    }
    if r.found {
        if let Some(rep) = &r.reputation {
            let c = conf(rep.confidence, 50);
            if let Some(cl) = rep
                .classification
                .as_deref()
                .map(clip)
                .filter(|s| !s.is_empty())
            {
                facts.push(f("threatsieve.classification", Value::from(cl), c));
            }
            if let Some(score) = rep.score.filter(|s| s.is_finite()) {
                facts.push(f(
                    "threatsieve.score",
                    Value::from(score.clamp(0.0, 100.0).round() as u64),
                    c,
                ));
            }
            if let Some(s) = &rep.scanner {
                if let Some(b) = s.is_scanner {
                    facts.push(f("threatsieve.scanner", Value::Bool(b), c));
                }
                if let Some(b) = s.benign_service {
                    facts.push(f("threatsieve.benign_service", Value::Bool(b), c));
                }
                if let Some(name) = s.name.as_deref().map(clip).filter(|s| !s.is_empty()) {
                    facts.push(f("threatsieve.scanner_name", Value::from(name), c));
                }
            }
            if let Some(tags) = rep.tags.as_deref().filter(|t| !t.is_empty()) {
                facts.push(f("threatsieve.tags", texts(tags, 64), c));
            }
        }
        if let Some(cve) = &r.cve {
            if let Some(s) = cve.status.as_deref().map(clip).filter(|s| !s.is_empty()) {
                facts.push(f("cve.status", Value::from(s), CVE_CONFIDENCE));
            }
            if let Some(k) = &cve.kev {
                if let Some(b) = k.listed {
                    facts.push(f("cve.kev_listed", Value::Bool(b), CVE_CONFIDENCE));
                }
                if let Some(d) = k.date_added.as_deref().map(clip).filter(|s| !s.is_empty()) {
                    facts.push(f("cve.kev_date_added", Value::from(d), CVE_CONFIDENCE));
                }
                if let Some(rw) = k.ransomware.as_deref().map(clip).filter(|s| !s.is_empty()) {
                    facts.push(f("cve.kev_ransomware", Value::from(rw), CVE_CONFIDENCE));
                }
            }
            if let Some(e) = &cve.epss {
                if let Some(s) = e.score.filter(|s| (0.0..=1.0).contains(s)) {
                    facts.push(f("cve.epss_score", Value::from(s), CVE_CONFIDENCE));
                }
                if let Some(p) = e.percentile.filter(|s| (0.0..=1.0).contains(s)) {
                    facts.push(f("cve.epss_percentile", Value::from(p), CVE_CONFIDENCE));
                }
            }
            if let Some(c) = &cve.cvss {
                if let Some(s) = c.base_score.filter(|s| (0.0..=10.0).contains(s)) {
                    facts.push(f("cve.cvss_base_score", Value::from(s), CVE_CONFIDENCE));
                }
                if let Some(v) = c.version.as_deref().map(clip).filter(|s| !s.is_empty()) {
                    facts.push(f("cve.cvss_version", Value::from(v), CVE_CONFIDENCE));
                }
                if let Some(v) = c.vector.as_deref().map(clip).filter(|s| !s.is_empty()) {
                    facts.push(f("cve.cvss_vector", Value::from(v), CVE_CONFIDENCE));
                }
            }
            if let Some(cwe) = cve.cwe.as_deref().filter(|c| !c.is_empty()) {
                facts.push(f("cve.cwe", texts(cwe, 32), CVE_CONFIDENCE));
            }
            if let Some(osv) = cve.osv_ids.as_deref().filter(|c| !c.is_empty()) {
                facts.push(f("cve.osv_ids", texts(osv, 64), CVE_CONFIDENCE));
            }
        }
        // Relationships are context for an analyst: low confidence, never
        // an attribution, and `model_inferred` lowest of all.
        let rels: Vec<(u8, Value)> = r
            .relationships
            .as_deref()
            .unwrap_or(&[])
            .iter()
            .take(MAX_RELATIONSHIPS)
            .map(|rel| {
                let assertion = rel.assertion.as_deref().map(clip).unwrap_or_default();
                let c = if assertion == "model_inferred" {
                    MODEL_INFERRED_CONFIDENCE
                } else {
                    conf(rel.confidence, RELATIONSHIP_MAX_CONFIDENCE)
                        .min(RELATIONSHIP_MAX_CONFIDENCE)
                };
                let target = rel.target.clone().unwrap_or_default();
                let mitre = target
                    .external_ids
                    .as_ref()
                    .and_then(|x| x.get("mitre"))
                    .and_then(Value::as_str)
                    .map(clip);
                (
                    c,
                    serde_json::json!({
                        "id": rel.id.as_deref().map(clip),
                        "type": rel.kind.as_deref().map(clip),
                        "direction": rel.direction.as_deref().map(clip),
                        "assertion": assertion,
                        "source_id": rel.source_id.as_deref().map(clip),
                        "target_type": target.kind.as_deref().map(clip),
                        "name": target.name.as_deref().map(clip),
                        "mitre": mitre,
                    }),
                )
            })
            .collect();
        if !rels.is_empty() {
            let c = rels
                .iter()
                .map(|(c, _)| *c)
                .min()
                .unwrap_or(MODEL_INFERRED_CONFIDENCE);
            facts.push(f(
                "threatsieve.related",
                Value::Array(rels.into_iter().map(|(_, v)| v).collect()),
                c,
            ));
        }
    }
    if pending {
        let p = r.pending_sources.as_deref().unwrap_or(&[]);
        facts.push(f("threatsieve.pending_sources", texts(p, MAX_SOURCES), 100));
    }
    // Provenance: each source's own terms, as ThreatSieve recorded them.
    if !facts.is_empty() && !sources.is_empty() {
        let list: Vec<Value> = sources
            .iter()
            .take(MAX_SOURCES)
            .map(|s| {
                serde_json::json!({
                    "source_id": s.source_id.as_deref().map(clip),
                    "license": s.license.as_deref().map(clip),
                    "redistributable": s.redistributable,
                    "commercial_use": s.commercial_use,
                    "retrieved_at": s.retrieved_at.as_deref().map(clip),
                })
            })
            .collect();
        facts.push(f("threatsieve.sources", Value::Array(list), 100));
    }
    // An answer with no Facts is a "not found" row: nothing to restrict,
    // so it is shared, and it lives for the negative TTL at most.
    let has_facts = !facts.is_empty();
    Some(Mapped {
        observable,
        restricted: restricted && has_facts,
        found: r.found,
        pending,
        error: None,
        facts,
        ttl_secs: ttl_for(has_facts),
    })
}

/// Turn a lookup's HTTP answer into cache-ready answers. Answers for types
/// Foiled does not ask about (`md5`, `asn`) are skipped.
pub fn lookup_outcome(
    status: u16,
    retry_after: Option<&str>,
    body: &str,
    now_ms: i64,
    config: &EnrichConfig,
) -> Result<Vec<Mapped>, LookupError> {
    match status {
        200 => {}
        429 => {
            return Err(LookupError::RateLimited {
                retry_after_secs: retry_after_secs(retry_after),
            });
        }
        413 => return Err(LookupError::TooLarge),
        _ => {
            // ThreatSieve's error code, when the body has one.
            let code = serde_json::from_str::<ErrorBody>(body)
                .ok()
                .and_then(|b| b.error)
                .and_then(|e| e.code)
                .map(|c| clip(&c))
                .filter(|c| {
                    !c.is_empty() && c.bytes().all(|b| b.is_ascii_uppercase() || b == b'_')
                });
            let what = match status {
                401 | 403 => "key refused",
                _ => "answered",
            };
            return Err(LookupError::Unavailable(match code {
                Some(c) => format!("{what} {status} {c}"),
                None => format!("{what} {status}"),
            }));
        }
    }
    if body.len() > MAX_RESPONSE_BYTES {
        return Err(LookupError::Parse(ParseError::Provider(
            "response too large".into(),
        )));
    }
    let parsed: LookupResponse =
        serde_json::from_str(body).map_err(|_| LookupError::Parse(ParseError::NotJson))?;
    Ok(parsed
        .results
        .iter()
        .filter_map(|r| map_result(r, now_ms, config))
        .collect())
}

/// Facts that may be written to the cache for `provider`: those with no
/// [`Fact::problems`]. Returns the kept Facts and how many were dropped.
pub fn valid_facts(provider: &str, facts: Vec<Fact>) -> (Vec<Fact>, usize) {
    let before = facts.len();
    let kept: Vec<Fact> = facts
        .into_iter()
        .filter(|f| f.problems(provider).is_empty())
        .collect();
    let dropped = before - kept.len();
    (kept, dropped)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const NOW: i64 = 1_792_285_400_000;
    const CONFIG: &str = include_str!("../../../configs/enrichment.yaml");
    const LOOKUP: &str = include_str!("../../../testdata/enrichment/threatsieve/lookup.json");

    fn config() -> EnrichConfig {
        serde_yaml_ng::from_str(CONFIG).unwrap()
    }

    fn ev(id: &str, ts: i64, severity: &str, src: &str, tenant: Option<&str>) -> CaptureEvent {
        let mut v = json!({
            "event_id": id, "ts": ts, "decoy_id": "d1", "catalogue_id": "foiled/demo-app/1.0.0",
            "decoy_kind": "sandbox", "channel": "application", "severity": severity,
            "src": {"ip": src}, "data": {"method": "GET", "path": "/x"}
        });
        if let Some(t) = tenant {
            v["tenant_id"] = json!(t);
        }
        serde_json::from_value(v).unwrap()
    }

    #[test]
    fn shipped_config_parses_with_no_problems() {
        let c = config();
        assert!(c.problems().is_empty(), "{:?}", c.problems());
        assert!(c.providers.local_asn.enabled);
        assert!(!c.providers.threatsieve.enabled, "ships off until bound");
        assert_eq!(c.providers.threatsieve.binding, "THREATSIEVE");
        assert!(c.providers.threatsieve.batch_size <= MAX_LOOKUP_BATCH);
        let mut bad = c.clone();
        bad.providers.threatsieve.batch_size = 501;
        assert!(!bad.problems().is_empty());
    }

    #[test]
    fn messages_dedupe_per_tenant_and_include_cves() {
        let mut egress: CaptureEvent = serde_json::from_value(json!({
            "event_id": "e4", "ts": NOW + 30, "decoy_id": "d1", "catalogue_id": "c/1",
            "decoy_kind": "sandbox", "channel": "egress", "severity": "info", "tenant_id": "t1",
            "src": {"ip": "10.85.1.2"}, "dst": {"ip": "192.0.2.80", "port": 80},
            "data": {"host": "stage2.example.invalid", "method": "GET", "path": "/x.sh"}
        }))
        .unwrap();
        egress.attempt_id = Some("att_1".into());
        let hook = |id: &str, cve: &str| -> CaptureEvent {
            serde_json::from_value(json!({
                "event_id": id, "ts": NOW + 40, "decoy_id": "d1", "catalogue_id": "c/1",
                "decoy_kind": "sandbox", "channel": "hook", "severity": "high", "tenant_id": "t1",
                "src": {"ip": "203.0.113.7"},
                "hook": {"hook_id": "h", "catalogue_id": "c/1", "cve_id": cve, "stage": "trigger",
                         "sequence_no": 1, "t_offset_ms": 0}
            }))
            .unwrap()
        };
        let events = vec![
            ev("e2", NOW + 10, "info", "203.0.113.7", Some("t1")),
            ev("e1", NOW, "info", "203.0.113.7", Some("t1")),
            ev("e3", NOW + 20, "critical", "203.0.113.7", Some("t1")),
            ev("e5", NOW, "info", "203.0.113.7", Some("t2")),
            ev("e6", NOW, "info", "203.0.113.7", None),
            ev("e7", NOW, "info", "10.0.0.1", Some("t1")),
            egress,
            hook("e8", "CVE-2099-0001"),
            hook("e9", "FOILED-DEMO-0001"),
        ];
        let msgs = messages_for_events(&events);
        let t1_src = msgs
            .iter()
            .find(|m| m.tenant_id == "t1" && m.observable.value == "203.0.113.7")
            .unwrap();
        assert_eq!(
            (t1_src.first_seen, t1_src.event_id.as_deref()),
            (NOW, Some("e1"))
        );
        assert_eq!(t1_src.priority, Priority::High);
        assert!(msgs.iter().any(|m| m.tenant_id == "t2"));
        assert!(!msgs.iter().any(|m| m.observable.value.starts_with("10.")));
        let kinds: Vec<(&str, &str)> = msgs
            .iter()
            .filter(|m| m.tenant_id == "t1")
            .map(|m| (m.observable.kind.as_str(), m.observable.value.as_str()))
            .collect();
        for want in [
            ("ip", "192.0.2.80"),
            ("domain", "stage2.example.invalid"),
            ("url", "http://stage2.example.invalid/x.sh"),
            ("cve", "CVE-2099-0001"),
        ] {
            assert!(kinds.contains(&want), "{want:?}");
        }
        assert!(!kinds.iter().any(|(_, v)| v.contains("DEMO")));
        assert_eq!(msgs[0].priority, Priority::High, "high first");
        for m in &msgs {
            assert!(m.problems().is_empty());
            let back: EnrichMessage =
                serde_json::from_str(&serde_json::to_string(m).unwrap()).unwrap();
            assert_eq!(&back, m);
        }
    }

    #[test]
    fn plan_skips_fresh_rows_and_backs_off_after_failures() {
        let mut c = config();
        c.providers.threatsieve.enabled = true;
        let o = Observable::ip("203.0.113.7").unwrap();
        let row = |provider: &str| CacheEntry {
            provider: provider.into(),
            observable: o.clone(),
            fetched_at: NOW - 1000,
            ttl_secs: 86_400,
            facts: vec![],
            tenant_id: None,
        };
        assert_eq!(
            plan(&c, &o, &[], &[], NOW),
            vec![(LOCAL_ASN, Step::Local), (THREATSIEVE, Step::Lookup)]
        );
        // A restricted row this tenant may read counts as cached.
        assert_eq!(
            plan(&c, &o, &[row(THREATSIEVE_RESTRICTED)], &[], NOW)[1],
            (THREATSIEVE, Step::Cached)
        );
        let failure = ProviderFailureRecord {
            provider: THREATSIEVE.into(),
            observable: o.clone(),
            failures: 3,
            last_failed_at: NOW - 1000,
            retry_at: None,
        };
        assert_eq!(
            plan(&c, &o, &[], std::slice::from_ref(&failure), NOW)[1],
            (
                THREATSIEVE,
                Step::BackingOff {
                    until: NOW - 1000 + 1_200_000
                }
            )
        );
        assert_eq!(
            plan(&c, &o, &[], std::slice::from_ref(&failure), NOW + 1_300_000)[1].1,
            Step::Lookup
        );
        // Retry-After wins when it is later.
        let ra = ProviderFailureRecord {
            retry_at: Some(NOW + 5_000_000),
            ..failure
        };
        assert_eq!(backoff_until(&ra, 300), NOW + 5_000_000);
        // CVEs only go to ThreatSieve.
        let cve = Observable::cve("cve-2099-0001").unwrap();
        assert_eq!(cve.value, "CVE-2099-0001");
        assert_eq!(
            plan(&c, &cve, &[], &[], NOW),
            vec![(THREATSIEVE, Step::Lookup)]
        );
    }

    #[test]
    fn budgets_by_priority() {
        assert_eq!(day_limit_for(7, Priority::High), 7);
        assert_eq!(day_limit_for(7, Priority::Normal), 5);
        assert_eq!(day_limit_for(1, Priority::Normal), 1);
    }

    #[test]
    fn lookup_request_batches_and_keeps_the_key_in_a_header() {
        let mut obs: Vec<Observable> = (0..600)
            .map(|i| Observable::ip(&format!("198.51.{}.{}", i / 250, i % 250)).unwrap())
            .collect();
        obs.insert(1, obs[0].clone());
        obs.push(Observable::ip("2001:db8::1").unwrap());
        let r = lookup_request(&obs, &[LookupSection::Network], "ts-test-key");
        assert_eq!(r.method, HttpMethod::Post);
        assert!(!r.url.contains("ts-test-key"));
        assert!(!format!("{r:?}").contains("ts-test-key"));
        assert!(
            r.headers
                .contains(&("authorization".into(), "Bearer ts-test-key".into()))
        );
        let body: Value = serde_json::from_str(r.body.as_deref().unwrap()).unwrap();
        let sent = body["observables"].as_array().unwrap();
        assert_eq!(sent.len(), MAX_LOOKUP_BATCH, "capped, duplicates once");
        assert_eq!(sent[0], json!({"type": "ipv4", "value": "198.51.0.0"}));
        assert_eq!(body["include"], json!(["network"]));
        let one = lookup_request(&[Observable::ip("2001:db8::1").unwrap()], &[], "k");
        assert!(one.body.unwrap().contains("\"ipv6\""));
    }

    #[test]
    fn lookup_answers_map_to_facts_with_provenance() {
        let mut c = config();
        c.providers.threatsieve.ttl_secs = 10_800;
        let mapped = lookup_outcome(200, None, LOOKUP, NOW, &c).unwrap();
        let by = |v: &str| mapped.iter().find(|m| m.observable.value == v).unwrap();
        let ip = by("203.0.113.7");
        assert!(ip.restricted, "GreyNoise is not redistributable");
        assert_eq!(ip.provider(), THREATSIEVE_RESTRICTED);
        assert_eq!(ip.ttl_secs, 10_800, "ours is shorter than ThreatSieve's");
        let key =
            |m: &Mapped, k: &str| m.facts.iter().find(|f| f.key == k).map(|f| f.value.clone());
        assert_eq!(key(ip, "asn.number"), Some(json!(64500)));
        assert_eq!(key(ip, "geo.country"), Some(json!("AU")));
        assert_eq!(
            key(ip, "threatsieve.classification"),
            Some(json!("malicious"))
        );
        assert_eq!(key(ip, "threatsieve.scanner"), Some(json!(true)));
        assert!(
            ip.facts
                .iter()
                .all(|f| f.provider == THREATSIEVE_RESTRICTED)
        );
        let related = ip
            .facts
            .iter()
            .find(|f| f.key == "threatsieve.related")
            .unwrap();
        assert!(related.confidence <= RELATIONSHIP_MAX_CONFIDENCE);
        assert_eq!(related.value[0]["mitre"], json!("G9999"));
        assert_eq!(related.value[0]["target_type"], json!("threat-actor"));
        assert_eq!(related.value[0]["id"], json!("relationship--demo-1"));
        assert_eq!(related.value[1]["direction"], json!("incoming"));
        assert_eq!(related.value[1]["source_id"], json!("analyst"));
        assert_eq!(related.confidence, MODEL_INFERRED_CONFIDENCE);
        // Each source's own terms travel with the answer.
        let sources = key(ip, "threatsieve.sources").unwrap();
        assert_eq!(sources[0]["source_id"], json!("greynoise"));
        assert_eq!(sources[0]["commercial_use"], json!(false));
        assert_eq!(
            sources[0]["retrieved_at"],
            json!("2026-10-17T03:00:00.000Z")
        );
        assert!(
            ip.facts
                .iter()
                .all(|f| f.raw_ref.as_deref() == Some("threatsieve:obs_demo_ip"))
        );
        // A redistributable, commercial-use answer is shareable.
        let cve = by("CVE-2099-0001");
        assert!(!cve.restricted);
        assert_eq!(cve.provider(), THREATSIEVE);
        assert_eq!(cve.ttl_secs, 3600, "ThreatSieve's ttl_seconds is shorter");
        assert_eq!(key(cve, "cve.kev_listed"), Some(json!(true)));
        assert_eq!(key(cve, "cve.epss_score"), Some(json!(0.97)));
        assert_eq!(key(cve, "cve.cvss_base_score"), Some(json!(9.8)));
        assert_eq!(key(cve, "cve.osv_ids"), Some(json!(["GHSA-demo-0001"])));
        assert_eq!(key(cve, "cve.status"), Some(json!("Analyzed")));
        // Mapped back by the spelling Foiled sent.
        assert_eq!(cve.observable, Observable::cve("CVE-2099-0001").unwrap());
        // Unknown terms (null) are restricted; not found is a negative row.
        let unknown = by("stage2.example.invalid");
        assert!(unknown.restricted);
        let miss = by("198.51.100.23");
        assert!(!miss.found && miss.facts.is_empty());
        assert!(!miss.restricted, "an empty row has nothing to restrict");
        assert_eq!(miss.ttl_secs, c.cache.negative_ttl_secs.min(600));
        // Network context alone: not found, but the ASN is kept, shared.
        let routed = by("198.51.100.40");
        assert!(!routed.found && !routed.restricted);
        assert_eq!(key(routed, "asn.number"), Some(json!(64501)));
        assert!(
            routed.facts.iter().all(|f| f.raw_ref.is_none()),
            "no entity"
        );
        // A pending source caps the row at five minutes.
        let pending = by("203.0.113.8");
        assert!(pending.pending);
        assert!(pending.ttl_secs <= PENDING_MAX_TTL_SECS);
        assert!(
            pending
                .facts
                .iter()
                .all(|f| f.ttl_secs <= PENDING_MAX_TTL_SECS)
        );
        assert_eq!(
            key(pending, "threatsieve.pending_sources"),
            Some(json!(["crowdsec", "greynoise"]))
        );
        // A rejected value carries its error and no Facts.
        let bad = by("rejected.example.invalid");
        assert_eq!(bad.error.as_deref(), Some("INVALID_OBSERVABLE"));
        assert!(bad.facts.is_empty());
        // md5 answers are not Foiled observables.
        assert!(!mapped.iter().any(|m| m.observable.value.len() == 32));
        for m in &mapped {
            let (kept, dropped) = valid_facts(m.provider(), m.facts.clone());
            assert_eq!(
                (kept.len(), dropped),
                (m.facts.len(), 0),
                "{:?}",
                m.observable
            );
        }
    }

    #[test]
    fn lookup_status_codes() {
        let c = config();
        assert_eq!(
            lookup_outcome(429, Some("120"), "", NOW, &c),
            Err(LookupError::RateLimited {
                retry_after_secs: 120
            })
        );
        assert_eq!(
            lookup_outcome(429, Some("Wed, 21 Oct 2099 07:28:00 GMT"), "", NOW, &c),
            Err(LookupError::RateLimited {
                retry_after_secs: DEFAULT_RETRY_AFTER_SECS
            })
        );
        assert_eq!(retry_after_secs(Some("999999")), MAX_RETRY_AFTER_SECS);
        assert_eq!(
            lookup_outcome(413, None, "", NOW, &c),
            Err(LookupError::TooLarge)
        );
        assert_eq!(
            lookup_outcome(
                401,
                None,
                r#"{"error":{"code":"UNAUTHORIZED","message":"no","request_id":"r1"}}"#,
                NOW,
                &c
            ),
            Err(LookupError::Unavailable(
                "key refused 401 UNAUTHORIZED".into()
            ))
        );
        assert_eq!(
            lookup_outcome(400, None, r#"{"error":{"code":"<b>x</b>"}}"#, NOW, &c),
            Err(LookupError::Unavailable("answered 400".into())),
            "odd codes are not echoed"
        );
        assert!(matches!(
            lookup_outcome(503, None, "", NOW, &c),
            Err(LookupError::Unavailable(_))
        ));
        assert!(matches!(
            lookup_outcome(302, None, "", NOW, &c),
            Err(LookupError::Unavailable(_))
        ));
        assert!(matches!(
            lookup_outcome(200, None, "nope", NOW, &c),
            Err(LookupError::Parse(_))
        ));
        assert_eq!(lookup_outcome(200, None, "{}", NOW, &c), Ok(vec![]));
    }
}
