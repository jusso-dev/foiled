//! Enrichment (#11): observables, Facts, provider response parsers, the local
//! IP-to-ASN table, cache freshness, noise inputs and export redaction.
//!
//! Everything here is pure. The `foiled-enrich` Queue consumer in the API
//! Worker does the HTTP fetches, the per-provider rate limit and the D1 cache;
//! this module only validates observables and turns response bodies into
//! [`Fact`]s, so it has no network, clock or file access and builds for
//! `wasm32-unknown-unknown`. Time is always passed in as Unix milliseconds.
//!
//! Third-party Facts are enrichment only. They are never resold or
//! republished, and [`redact_for_export`] removes them from anything that
//! leaves the operator's console (`docs/compliance/licence-register.md`).
//!
//! Design and pipeline: `docs/enrichment.md`. Fact contract:
//! `schemas/fact.schema.json`. Provider config: `configs/enrichment.yaml`.

use std::collections::BTreeMap;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::capture::{CaptureEvent, Channel, PayloadRef};

/// Provider id for the local IP-to-ASN table.
pub const LOCAL_ASN: &str = "local_asn";
/// Provider id for GreyNoise Community.
pub const GREYNOISE: &str = "greynoise";
/// Provider id for CrowdSec CTI.
pub const CROWDSEC: &str = "crowdsec";
/// Provider id for DShield (SANS ISC).
pub const DSHIELD: &str = "dshield";
/// Provider id for ThreatSieve, the operator's intel hub, for Facts whose
/// every contributing source allows redistribution and commercial use.
pub const THREATSIEVE: &str = "threatsieve";
/// Provider id for ThreatSieve Facts with any source that does not allow
/// redistribution or commercial use, or whose terms are unknown. Never
/// exported, and kept per tenant (`docs/enrichment.md`).
pub const THREATSIEVE_RESTRICTED: &str = "threatsieve_restricted";

/// Providers whose data is never exported, published or resold. Facts from
/// these are shown only inside the entitled operator's console.
///
/// `local_asn` is listed because its dataset may be MaxMind GeoLite2, which the
/// licence register keeps out of exports until a row there says otherwise.
pub const NEVER_REDISTRIBUTE: &[&str] = &[
    GREYNOISE,
    CROWDSEC,
    DSHIELD,
    "shadowserver",
    "huntio",
    "abuseipdb",
    LOCAL_ASN,
    THREATSIEVE_RESTRICTED,
];

/// Confidence given to GreyNoise facts. GreyNoise Community does not report a
/// certainty, so this is a fixed provider default (`docs/enrichment.md`).
pub const GREYNOISE_CONFIDENCE: u8 = 80;
/// Confidence given to DShield facts, which are sensor counts with no
/// certainty field.
pub const DSHIELD_CONFIDENCE: u8 = 70;
/// Confidence given to local ASN and country facts.
pub const LOCAL_ASN_CONFIDENCE: u8 = 90;
/// CrowdSec confidence when the response carries no `confidence` field.
pub const CROWDSEC_DEFAULT_CONFIDENCE: u8 = 50;

/// Longest provider string kept in a Fact. Provider output is untrusted text.
pub const MAX_TEXT: usize = 256;
/// Most items kept from any provider list.
pub const MAX_ITEMS: usize = 64;
/// Longest URL observable accepted.
pub const MAX_URL: usize = 2048;

// ---------------------------------------------------------------------------
// Observables
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObservableKind {
    Ip,
    Domain,
    Sha256,
    Url,
    /// A CVE id (`CVE-2099-0001`), for CVE context from ThreatSieve.
    Cve,
}

impl ObservableKind {
    pub fn as_str(self) -> &'static str {
        match self {
            ObservableKind::Ip => "ip",
            ObservableKind::Domain => "domain",
            ObservableKind::Sha256 => "sha256",
            ObservableKind::Url => "url",
            ObservableKind::Cve => "cve",
        }
    }
}

/// Something Facts hang off: an IP, a domain, a file hash or a URL. Values are
/// normalised on construction so the same thing always has the same cache key.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub struct Observable {
    pub kind: ObservableKind,
    pub value: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ObservableError {
    BadIp(String),
    BadDomain(String),
    BadSha256(String),
    BadUrl(String),
    BadCve(String),
}

impl fmt::Display for ObservableError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BadIp(v) => write!(f, "'{v}' is not an IP address"),
            Self::BadDomain(v) => write!(f, "'{v}' is not a domain name"),
            Self::BadSha256(v) => write!(f, "'{v}' is not a lower or upper case SHA-256 hex"),
            Self::BadUrl(v) => write!(f, "'{v}' is not an http, https or ftp URL"),
            Self::BadCve(v) => write!(f, "'{v}' is not a CVE id"),
        }
    }
}

impl std::error::Error for ObservableError {}

impl Observable {
    /// Validates and normalises `value`. IPs are canonicalised (IPv4-mapped
    /// IPv6 becomes IPv4), domains and hashes are lower-cased and a trailing
    /// dot on a domain is dropped.
    pub fn new(kind: ObservableKind, value: &str) -> Result<Self, ObservableError> {
        let value = value.trim();
        let value = match kind {
            ObservableKind::Ip => value
                .parse::<IpAddr>()
                .map(|ip| ip.to_canonical().to_string())
                .map_err(|_| ObservableError::BadIp(value.to_owned()))?,
            ObservableKind::Domain => {
                let d = value
                    .strip_suffix('.')
                    .unwrap_or(value)
                    .to_ascii_lowercase();
                if !valid_domain(&d) {
                    return Err(ObservableError::BadDomain(value.to_owned()));
                }
                d
            }
            ObservableKind::Sha256 => {
                let h = value.to_ascii_lowercase();
                if h.len() != 64 || !h.bytes().all(|b| b.is_ascii_hexdigit()) {
                    return Err(ObservableError::BadSha256(value.to_owned()));
                }
                h
            }
            ObservableKind::Url => {
                if !valid_url(value) {
                    return Err(ObservableError::BadUrl(value.to_owned()));
                }
                value.to_owned()
            }
            ObservableKind::Cve => {
                let c = value.to_ascii_uppercase();
                if !is_cve_id(&c) {
                    return Err(ObservableError::BadCve(value.to_owned()));
                }
                c
            }
        };
        Ok(Self { kind, value })
    }

    pub fn ip(value: &str) -> Result<Self, ObservableError> {
        Self::new(ObservableKind::Ip, value)
    }

    pub fn sha256(value: &str) -> Result<Self, ObservableError> {
        Self::new(ObservableKind::Sha256, value)
    }

    pub fn domain(value: &str) -> Result<Self, ObservableError> {
        Self::new(ObservableKind::Domain, value)
    }

    pub fn cve(value: &str) -> Result<Self, ObservableError> {
        Self::new(ObservableKind::Cve, value)
    }

    /// Cache key for this observable and provider: `provider:kind:value`.
    pub fn cache_key(&self, provider: &str) -> String {
        format!("{provider}:{}:{}", self.kind.as_str(), self.value)
    }

    /// False for IPs that must never be sent to a third party: private,
    /// loopback, link-local, carrier-grade NAT, unique local, multicast and
    /// unspecified addresses. Those are the operator's own network, not the
    /// attacker's. Other kinds are always eligible. Documentation ranges
    /// (RFC 5737, RFC 3849) are eligible so fixtures exercise the full path;
    /// real traffic never comes from them.
    pub fn is_external_lookup_eligible(&self) -> bool {
        if self.kind != ObservableKind::Ip {
            return true;
        }
        match self.value.parse::<IpAddr>() {
            Ok(IpAddr::V4(v4)) => {
                let o = v4.octets();
                let cgnat = o[0] == 100 && (o[1] & 0xc0) == 64;
                !(v4.is_private()
                    || v4.is_loopback()
                    || v4.is_link_local()
                    || v4.is_unspecified()
                    || v4.is_multicast()
                    || v4.is_broadcast()
                    || cgnat)
            }
            Ok(IpAddr::V6(v6)) => {
                let first = v6.segments()[0];
                let unique_local = (first & 0xfe00) == 0xfc00;
                let link_local = (first & 0xffc0) == 0xfe80;
                !(v6.is_loopback()
                    || v6.is_unspecified()
                    || v6.is_multicast()
                    || unique_local
                    || link_local)
            }
            Err(_) => false,
        }
    }
}

impl<'de> Deserialize<'de> for Observable {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Raw {
            kind: ObservableKind,
            value: String,
        }
        let raw = Raw::deserialize(d)?;
        Observable::new(raw.kind, &raw.value).map_err(serde::de::Error::custom)
    }
}

fn valid_domain(d: &str) -> bool {
    !d.is_empty()
        && d.len() <= 253
        && d.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        })
}

fn valid_url(u: &str) -> bool {
    if u.len() > MAX_URL || u.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return false;
    }
    let Some((scheme, rest)) = u.split_once("://") else {
        return false;
    };
    if !matches!(
        scheme.to_ascii_lowercase().as_str(),
        "http" | "https" | "ftp"
    ) {
        return false;
    }
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    let host = authority.rsplit('@').next().unwrap_or("");
    !host.is_empty()
}

/// Observables worth enriching in one capture event. The ingest consumer
/// sends one `foiled-enrich` message per distinct observable in a batch.
///
/// - The attacker's address: `src.ip`, or `dst.ip` for `egress` events (the
///   decoy is the source there and the destination is the attacker's choice).
/// - Hashes: the sha256 in `payload_ref` and `data.body_sha256`.
/// - Domains: `data.host` on `egress` and `data.query` on `dns` events.
///
/// Invalid values and IPs that fail [`Observable::is_external_lookup_eligible`]
/// are skipped. The result is sorted and has no duplicates.
pub fn observables_for_event(event: &CaptureEvent) -> Vec<Observable> {
    let mut out = Vec::new();
    let peer = match event.channel {
        Channel::Egress => event.dst.as_ref().map(|d| d.ip.as_str()),
        _ => Some(event.src.ip.as_str()),
    };
    out.extend(
        peer.and_then(|ip| Observable::ip(ip).ok())
            .filter(Observable::is_external_lookup_eligible),
    );
    if let Some(p) = event.payload_ref.as_deref().and_then(PayloadRef::parse) {
        out.extend(Observable::sha256(&p.sha256).ok());
    }
    let text = |k: &str| event.data.get(k).and_then(Value::as_str);
    out.extend(text("body_sha256").and_then(|h| Observable::sha256(h).ok()));
    let domain_field = match event.channel {
        Channel::Egress => text("host"),
        Channel::Dns => text("query"),
        _ => None,
    };
    out.extend(domain_field.and_then(|d| Observable::domain(d).ok()));
    out.sort();
    out.dedup();
    out
}

// ---------------------------------------------------------------------------
// Facts
// ---------------------------------------------------------------------------

/// One piece of context a provider asserts about an observable. Mirrors
/// `schemas/fact.schema.json`.
///
/// `confidence` is the provider's own certainty, 0 to 100. It is an input to
/// the confidence layer (#27), never a final link score.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Fact {
    pub provider: String,
    /// Dotted key, prefixed with the provider or topic, such as
    /// `greynoise.noise` or `asn.number`.
    pub key: String,
    pub value: Value,
    pub confidence: u8,
    /// Unix milliseconds when the provider was asked.
    pub observed_at: i64,
    /// How long the Fact may be used before it must be fetched again.
    pub ttl_secs: u64,
    /// Where the raw response is kept, if anywhere (a cache row id or an
    /// `r2://` reference). Never the response itself.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub raw_ref: Option<String>,
}

/// Longest serialised Fact value accepted into the cache.
pub const MAX_FACT_VALUE_BYTES: usize = 8 * 1024;

impl Fact {
    /// Why this Fact may not be written to the cache: the checks of
    /// `schemas/fact.schema.json` plus a size cap on the value and a match
    /// between the Fact's provider and the provider that produced it. Empty
    /// when it is fine.
    pub fn problems(&self, expected_provider: &str) -> Vec<String> {
        let mut out = Vec::new();
        let provider_ok = !self.provider.is_empty()
            && self.provider.len() <= 32
            && self.provider.as_bytes()[0].is_ascii_lowercase()
            && self
                .provider
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_');
        if !provider_ok {
            out.push(format!("bad provider id '{}'", clip(&self.provider)));
        }
        if self.provider != expected_provider {
            out.push(format!(
                "Fact names provider '{}' but came from '{expected_provider}'",
                clip(&self.provider)
            ));
        }
        let key_ok = self.key.len() <= 96
            && self.key.split('.').count() >= 2
            && self.key.split('.').all(|part| {
                !part.is_empty()
                    && part
                        .bytes()
                        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
            });
        if !key_ok {
            out.push(format!("bad key '{}'", clip(&self.key)));
        }
        if self.confidence > 100 {
            out.push("confidence above 100".into());
        }
        if serde_json::to_vec(&self.value).map_or(usize::MAX, |v| v.len()) > MAX_FACT_VALUE_BYTES {
            out.push(format!("value over {MAX_FACT_VALUE_BYTES} bytes"));
        }
        if self.raw_ref.as_ref().is_some_and(|r| r.len() > 512) {
            out.push("raw_ref over 512 characters".into());
        }
        out
    }

    /// True while `now_ms` is before `observed_at + ttl_secs`.
    pub fn is_fresh(&self, now_ms: i64) -> bool {
        now_ms < expiry(self.observed_at, self.ttl_secs)
    }
}

/// When and for how long a set of parsed Facts is valid.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Stamp {
    pub observed_at: i64,
    pub ttl_secs: u64,
    pub raw_ref: Option<String>,
}

impl Stamp {
    pub fn new(observed_at: i64, ttl_secs: u64) -> Self {
        Self {
            observed_at,
            ttl_secs,
            raw_ref: None,
        }
    }

    fn fact(&self, provider: &str, key: &str, value: Value, confidence: u8) -> Fact {
        Fact {
            provider: provider.to_owned(),
            key: key.to_owned(),
            value,
            confidence: confidence.min(100),
            observed_at: self.observed_at,
            ttl_secs: self.ttl_secs,
            raw_ref: self.raw_ref.clone(),
        }
    }
}

fn expiry(observed_at: i64, ttl_secs: u64) -> i64 {
    let ttl_ms = i64::try_from(ttl_secs)
        .unwrap_or(i64::MAX)
        .saturating_mul(1000);
    observed_at.saturating_add(ttl_ms)
}

// ---------------------------------------------------------------------------
// Provider interface
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EnrichError {
    /// The provider does not handle this observable kind.
    Unsupported,
    /// The provider could not be reached or returned a server error.
    Unavailable(String),
    /// The provider's rate limit or daily quota is used up.
    RateLimited,
    /// The response could not be parsed.
    Parse(ParseError),
}

impl fmt::Display for EnrichError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unsupported => write!(f, "observable kind not supported"),
            Self::Unavailable(m) => write!(f, "provider unavailable: {m}"),
            Self::RateLimited => write!(f, "provider rate limit reached"),
            Self::Parse(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for EnrichError {}

impl From<ParseError> for EnrichError {
    fn from(e: ParseError) -> Self {
        Self::Parse(e)
    }
}

/// A source of Facts. This is the synchronous, pure half of the interface:
/// local providers (the ASN table, test fakes) implement it directly. Network
/// providers in the Worker fetch the body and call the matching `parse_*`
/// function, then return the same `Result<Vec<Fact>, EnrichError>`.
///
/// `Ok(vec![])` means the provider knows nothing about the observable, which
/// is cached like any other answer. `Err` is never cached as a Fact.
pub trait Provider {
    fn id(&self) -> &str;
    fn supports(&self, kind: ObservableKind) -> bool;
    fn enrich(&self, observable: &Observable, now_ms: i64) -> Result<Vec<Fact>, EnrichError>;
}

/// Facts for one observable, from every provider that answered.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObservedFacts {
    pub observable: Observable,
    pub facts: Vec<Fact>,
}

/// A provider call that failed. Failures are reported, retried by the
/// consumer and never remove the capture event or other providers' Facts.
#[derive(Debug, Clone, PartialEq)]
pub struct ProviderFailure {
    pub provider: String,
    pub observable: Observable,
    pub error: EnrichError,
}

/// Outcome of [`enrich_all`].
#[derive(Debug, Clone, Default, PartialEq)]
pub struct EnrichmentRun {
    /// Facts by observable. Observables with no Facts are left out.
    pub facts: BTreeMap<Observable, Vec<Fact>>,
    pub failures: Vec<ProviderFailure>,
}

impl EnrichmentRun {
    /// Facts attached to `observable`, or an empty slice.
    pub fn facts_for(&self, observable: &Observable) -> &[Fact] {
        self.facts.get(observable).map(Vec::as_slice).unwrap_or(&[])
    }
}

/// Runs every provider over every observable it supports. One provider failing
/// does not stop the others; its failure is recorded and the run continues.
pub fn enrich_all(
    providers: &[&dyn Provider],
    observables: &[Observable],
    now_ms: i64,
) -> EnrichmentRun {
    let mut run = EnrichmentRun::default();
    for observable in observables {
        for provider in providers {
            if !provider.supports(observable.kind) {
                continue;
            }
            match provider.enrich(observable, now_ms) {
                Ok(facts) if facts.is_empty() => {}
                Ok(facts) => run
                    .facts
                    .entry(observable.clone())
                    .or_default()
                    .extend(facts),
                Err(error) => run.failures.push(ProviderFailure {
                    provider: provider.id().to_owned(),
                    observable: observable.clone(),
                    error,
                }),
            }
        }
    }
    run
}

// ---------------------------------------------------------------------------
// Cache
// ---------------------------------------------------------------------------

/// One row of the enrichment cache in D1, keyed by observable and provider.
/// An entry with no Facts is a cached "provider knows nothing", so the
/// consumer does not ask again until it expires.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CacheEntry {
    pub provider: String,
    pub observable: Observable,
    /// Unix milliseconds when the provider answered.
    pub fetched_at: i64,
    pub ttl_secs: u64,
    pub facts: Vec<Fact>,
    /// Set when the row may only be read by the tenant whose lookup wrote
    /// it (ThreatSieve answers with a source that may not be shared).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant_id: Option<String>,
}

impl CacheEntry {
    /// The D1 primary key: `provider:kind:value`, plus `@tenant` for a row
    /// kept for one tenant.
    pub fn key(&self) -> String {
        let base = self.observable.cache_key(&self.provider);
        match &self.tenant_id {
            Some(t) => format!("{base}@{t}"),
            None => base,
        }
    }

    /// True while `now_ms` is before `fetched_at + ttl_secs`. A fetch time in
    /// the future (clock skew) still counts as fresh until it expires.
    pub fn is_fresh(&self, now_ms: i64) -> bool {
        now_ms < expiry(self.fetched_at, self.ttl_secs)
    }
}

// ---------------------------------------------------------------------------
// Response parsers
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseError {
    /// The body was not JSON.
    NotJson,
    /// The body was JSON but not an object.
    NotObject,
    /// The provider returned an error message instead of data.
    Provider(String),
    /// A required field was absent.
    Missing(&'static str),
    /// A field had the wrong type.
    WrongType(&'static str),
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotJson => write!(f, "response is not JSON"),
            Self::NotObject => write!(f, "response is not a JSON object"),
            Self::Provider(m) => write!(f, "provider error: {m}"),
            Self::Missing(k) => write!(f, "response has no '{k}'"),
            Self::WrongType(k) => write!(f, "response field '{k}' has the wrong type"),
        }
    }
}

impl std::error::Error for ParseError {}

type Object = serde_json::Map<String, Value>;

fn parse_object(body: &str) -> Result<Object, ParseError> {
    match serde_json::from_str::<Value>(body) {
        Ok(Value::Object(o)) => Ok(o),
        Ok(_) => Err(ParseError::NotObject),
        Err(_) => Err(ParseError::NotJson),
    }
}

/// Untrusted provider text: control characters removed, length capped.
pub(crate) fn clip(s: &str) -> String {
    s.chars()
        .filter(|c| !c.is_control())
        .take(MAX_TEXT)
        .collect()
}

fn text_field(o: &Object, key: &'static str) -> Option<String> {
    o.get(key)
        .and_then(Value::as_str)
        .map(clip)
        .filter(|s| !s.is_empty())
}

fn provider_message(o: &Object) -> String {
    ["message", "error", "detail"]
        .iter()
        .find_map(|k| o.get(*k).and_then(Value::as_str))
        .map(clip)
        .unwrap_or_else(|| "unknown error".to_owned())
}

/// Parses a GreyNoise Community response (`GET /v3/community/{ip}`).
///
/// `noise` and `riot` are required booleans; `classification`, `name` and
/// `last_seen` are added when present. A "not observed" answer (both flags
/// false) still yields the two flag Facts, because "not noise" is useful to
/// the noise score (#25). A body with no flags is a provider error, such as a
/// rate limit message.
pub fn parse_greynoise_community(body: &str, stamp: &Stamp) -> Result<Vec<Fact>, ParseError> {
    let o = parse_object(body)?;
    if !o.contains_key("noise") && !o.contains_key("riot") {
        return Err(ParseError::Provider(provider_message(&o)));
    }
    let flag = |k: &'static str| match o.get(k) {
        Some(Value::Bool(b)) => Ok(*b),
        Some(_) => Err(ParseError::WrongType(k)),
        None => Err(ParseError::Missing(k)),
    };
    let noise = flag("noise")?;
    let riot = flag("riot")?;
    let fact = |key: &str, v: Value| stamp.fact(GREYNOISE, key, v, GREYNOISE_CONFIDENCE);
    let mut facts = vec![
        fact("greynoise.noise", Value::Bool(noise)),
        fact("greynoise.riot", Value::Bool(riot)),
    ];
    for (field, key) in [
        ("classification", "greynoise.classification"),
        ("name", "greynoise.name"),
        ("last_seen", "greynoise.last_seen"),
    ] {
        if let Some(v) = text_field(&o, field) {
            facts.push(fact(key, Value::String(v)));
        }
    }
    Ok(facts)
}

fn crowdsec_confidence(o: &Object) -> u8 {
    match o.get("confidence").and_then(Value::as_str) {
        Some("high") => 90,
        Some("medium") => 60,
        Some("low") => 30,
        _ => CROWDSEC_DEFAULT_CONFIDENCE,
    }
}

/// `name` of each object in a list (CrowdSec `behaviors`, `attack_details`,
/// `mitre_techniques`), clipped, de-duplicated and capped at [`MAX_ITEMS`].
fn names(o: &Object, key: &'static str, keep: impl Fn(&str) -> bool) -> Vec<Value> {
    let mut out: Vec<String> = o
        .get(key)
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|item| match item {
            Value::String(s) => Some(s.as_str()),
            Value::Object(m) => m.get("name").and_then(Value::as_str),
            _ => None,
        })
        .filter(|s| keep(s))
        .map(clip)
        .collect();
    out.sort();
    out.dedup();
    out.truncate(MAX_ITEMS);
    out.into_iter().map(Value::String).collect()
}

fn is_technique_id(s: &str) -> bool {
    let b = s.as_bytes();
    let base = b.len() >= 5 && b[0] == b'T' && b[1..5].iter().all(u8::is_ascii_digit);
    match b.len() {
        5 => base,
        9 => base && b[5] == b'.' && b[6..9].iter().all(u8::is_ascii_digit),
        _ => false,
    }
}

fn is_cve_id(s: &str) -> bool {
    let Some(rest) = s.strip_prefix("CVE-") else {
        return false;
    };
    let Some((year, num)) = rest.split_once('-') else {
        return false;
    };
    year.len() == 4
        && year.bytes().all(|b| b.is_ascii_digit())
        && (4..=7).contains(&num.len())
        && num.bytes().all(|b| b.is_ascii_digit())
}

/// Parses a CrowdSec CTI smoke response (`GET /v2/smoke/{ip}`).
///
/// Produces `crowdsec.reputation`, `crowdsec.behaviors`,
/// `crowdsec.attack_details`, `crowdsec.mitre_techniques` and
/// `crowdsec.cves`, each only when present and non-empty. Technique and CVE
/// ids that do not look like ids are dropped. Confidence comes from the
/// response's own `confidence` (`high` 90, `medium` 60, `low` 30).
pub fn parse_crowdsec_smoke(body: &str, stamp: &Stamp) -> Result<Vec<Fact>, ParseError> {
    let o = parse_object(body)?;
    let has_data = ["ip", "reputation", "behaviors", "scores"]
        .iter()
        .any(|k| o.contains_key(*k));
    if !has_data {
        return Err(ParseError::Provider(provider_message(&o)));
    }
    let confidence = crowdsec_confidence(&o);
    let fact = |key: &str, v: Value| stamp.fact(CROWDSEC, key, v, confidence);
    let mut facts = Vec::new();
    if let Some(r) = text_field(&o, "reputation") {
        facts.push(fact("crowdsec.reputation", Value::String(r)));
    }
    let lists = [
        ("crowdsec.behaviors", names(&o, "behaviors", |_| true)),
        (
            "crowdsec.attack_details",
            names(&o, "attack_details", |_| true),
        ),
        (
            "crowdsec.mitre_techniques",
            names(&o, "mitre_techniques", is_technique_id),
        ),
        ("crowdsec.cves", names(&o, "cves", is_cve_id)),
    ];
    for (key, items) in lists {
        if !items.is_empty() {
            facts.push(fact(key, Value::Array(items)));
        }
    }
    Ok(facts)
}

/// A DShield count may be a number, a numeric string or null.
fn dshield_count(o: &Object, key: &'static str) -> Result<Option<u64>, ParseError> {
    match o.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Number(n)) => n.as_u64().map(Some).ok_or(ParseError::WrongType(key)),
        Some(Value::String(s)) if s.trim().is_empty() => Ok(None),
        Some(Value::String(s)) => s
            .trim()
            .parse::<u64>()
            .map(Some)
            .map_err(|_| ParseError::WrongType(key)),
        Some(_) => Err(ParseError::WrongType(key)),
    }
}

/// Parses a DShield IP response (`GET /api/ip/{ip}?json`).
///
/// Produces `dshield.count` (reports), `dshield.attacks` (targets),
/// `dshield.mindate` and `dshield.maxdate`, each only when not null. An IP
/// DShield has never seen returns nulls and yields no Facts.
pub fn parse_dshield_ip(body: &str, stamp: &Stamp) -> Result<Vec<Fact>, ParseError> {
    let o = parse_object(body)?;
    let ip = match o.get("ip") {
        Some(Value::Object(ip)) => ip,
        Some(_) => return Err(ParseError::WrongType("ip")),
        None => return Err(ParseError::Provider(provider_message(&o))),
    };
    let fact = |key: &str, v: Value| stamp.fact(DSHIELD, key, v, DSHIELD_CONFIDENCE);
    let mut facts = Vec::new();
    for (field, key) in [("count", "dshield.count"), ("attacks", "dshield.attacks")] {
        if let Some(n) = dshield_count(ip, field)? {
            facts.push(fact(key, Value::from(n)));
        }
    }
    for (field, key) in [
        ("mindate", "dshield.mindate"),
        ("maxdate", "dshield.maxdate"),
    ] {
        if let Some(d) = text_field(ip, field) {
            facts.push(fact(key, Value::String(d)));
        }
    }
    Ok(facts)
}

// ---------------------------------------------------------------------------
// Local IP-range-to-ASN table
// ---------------------------------------------------------------------------

/// One row of the ASN table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AsnRecord {
    pub asn: u32,
    pub org: String,
    /// ISO 3166-1 alpha-2, upper case, when the dataset has one.
    pub country: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AsnTableError {
    /// 1-based line number in the CSV.
    pub line: usize,
    pub reason: String,
}

impl fmt::Display for AsnTableError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "line {}: {}", self.line, self.reason)
    }
}

impl std::error::Error for AsnTableError {}

#[derive(Debug, Clone, Default)]
struct Ranges<T> {
    /// `(start, end, index into records)`, sorted by start, non-overlapping.
    rows: Vec<(T, T, usize)>,
}

impl<T: Ord + Copy> Ranges<T> {
    fn sort_and_check(&mut self) -> Result<(), usize> {
        self.rows.sort_by_key(|r| r.0);
        for pair in self.rows.windows(2) {
            if pair[1].0 <= pair[0].1 {
                return Err(pair[1].2);
            }
        }
        Ok(())
    }

    fn find(&self, ip: T) -> Option<usize> {
        // Index of the first row whose start is greater than ip; the row
        // before it is the only candidate.
        let i = self.rows.partition_point(|r| r.0 <= ip);
        let (_, end, idx) = *self.rows.get(i.checked_sub(1)?)?;
        (ip <= end).then_some(idx)
    }
}

/// An in-memory IP-range-to-ASN table, loaded from an operator-downloaded
/// dataset converted to `start_ip,end_ip,asn,org,country` CSV. The dataset is
/// never committed to the repository.
#[derive(Debug, Clone, Default)]
pub struct AsnTable {
    v4: Ranges<u32>,
    v6: Ranges<u128>,
    records: Vec<AsnRecord>,
    /// TTL given to Facts this table produces.
    pub ttl_secs: u64,
}

impl AsnTable {
    /// Default Fact TTL: seven days, matching the enrichment cache default in
    /// `configs/retention.yaml`.
    pub const DEFAULT_TTL_SECS: u64 = 7 * 24 * 3600;

    /// Parses `start_ip,end_ip,asn,org,country` lines. Blank lines, `#`
    /// comments and a `start_ip,...` header are skipped. `org` may contain
    /// commas and may be wrapped in double quotes. `asn` may carry an `AS`
    /// prefix. `country` may be empty. Ranges must not overlap.
    pub fn from_csv(text: &str) -> Result<Self, AsnTableError> {
        let mut table = AsnTable {
            ttl_secs: Self::DEFAULT_TTL_SECS,
            ..Self::default()
        };
        let mut lines_of = Vec::new();
        for (n, raw) in text.lines().enumerate() {
            let line_no = n + 1;
            let line = raw.trim();
            if line.is_empty() || line.starts_with('#') || line.starts_with("start_ip,") {
                continue;
            }
            let err = |reason: &str| AsnTableError {
                line: line_no,
                reason: reason.to_owned(),
            };
            let mut head = line.splitn(4, ',');
            let (Some(start), Some(end), Some(asn), Some(rest)) =
                (head.next(), head.next(), head.next(), head.next())
            else {
                return Err(err("expected start_ip,end_ip,asn,org,country"));
            };
            let Some((org, country)) = rest.rsplit_once(',') else {
                return Err(err("expected start_ip,end_ip,asn,org,country"));
            };
            let start: IpAddr = start.trim().parse().map_err(|_| err("bad start_ip"))?;
            let end: IpAddr = end.trim().parse().map_err(|_| err("bad end_ip"))?;
            let asn = asn.trim();
            let asn: u32 = asn
                .strip_prefix("AS")
                .unwrap_or(asn)
                .parse()
                .map_err(|_| err("bad asn"))?;
            let org = org.trim();
            let org = org
                .strip_prefix('"')
                .and_then(|o| o.strip_suffix('"'))
                .unwrap_or(org);
            let country = country.trim();
            let country = match country {
                "" | "None" | "ZZ" => None,
                c if c.len() == 2 && c.bytes().all(|b| b.is_ascii_alphabetic()) => {
                    Some(c.to_ascii_uppercase())
                }
                _ => return Err(err("country must be two letters or empty")),
            };
            let idx = table.records.len();
            table.records.push(AsnRecord {
                asn,
                org: clip(org),
                country,
            });
            lines_of.push(line_no);
            match (start.to_canonical(), end.to_canonical()) {
                (IpAddr::V4(s), IpAddr::V4(e)) if s <= e => {
                    table.v4.rows.push((s.to_bits(), e.to_bits(), idx));
                }
                (IpAddr::V6(s), IpAddr::V6(e)) if s <= e => {
                    table.v6.rows.push((s.to_bits(), e.to_bits(), idx));
                }
                (IpAddr::V4(_), IpAddr::V4(_)) | (IpAddr::V6(_), IpAddr::V6(_)) => {
                    return Err(err("start_ip is after end_ip"));
                }
                _ => return Err(err("start_ip and end_ip are different address families")),
            }
        }
        let overlap = |idx: usize| AsnTableError {
            line: lines_of[idx],
            reason: "range overlaps an earlier range".to_owned(),
        };
        table.v4.sort_and_check().map_err(overlap)?;
        table.v6.sort_and_check().map_err(overlap)?;
        Ok(table)
    }

    /// Number of ranges loaded.
    pub fn len(&self) -> usize {
        self.records.len()
    }

    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    /// Binary search for the range holding `ip`. IPv4-mapped IPv6 addresses
    /// are looked up as IPv4.
    pub fn lookup(&self, ip: IpAddr) -> Option<&AsnRecord> {
        let idx = match ip.to_canonical() {
            IpAddr::V4(v4) => self.v4.find(Ipv4Addr::to_bits(v4)),
            IpAddr::V6(v6) => self.v6.find(Ipv6Addr::to_bits(v6)),
        }?;
        self.records.get(idx)
    }
}

impl Provider for AsnTable {
    fn id(&self) -> &str {
        LOCAL_ASN
    }

    fn supports(&self, kind: ObservableKind) -> bool {
        kind == ObservableKind::Ip
    }

    /// `asn.number`, `asn.org` and, when known, `geo.country`. An IP outside
    /// every range yields no Facts.
    fn enrich(&self, observable: &Observable, now_ms: i64) -> Result<Vec<Fact>, EnrichError> {
        if observable.kind != ObservableKind::Ip {
            return Err(EnrichError::Unsupported);
        }
        let ip: IpAddr = observable
            .value
            .parse()
            .map_err(|_| EnrichError::Unsupported)?;
        let Some(rec) = self.lookup(ip) else {
            return Ok(Vec::new());
        };
        let stamp = Stamp::new(now_ms, self.ttl_secs);
        let fact = |key: &str, v: Value| stamp.fact(LOCAL_ASN, key, v, LOCAL_ASN_CONFIDENCE);
        let mut facts = vec![
            fact("asn.number", Value::from(rec.asn)),
            fact("asn.org", Value::String(rec.org.clone())),
        ];
        if let Some(c) = &rec.country {
            facts.push(fact("geo.country", Value::String(c.clone())));
        }
        Ok(facts)
    }
}

// ---------------------------------------------------------------------------
// Reading the cache
// ---------------------------------------------------------------------------

/// Providers whose Facts every tenant may see: `local_asn` is the operator's
/// own table (still never redistributed), `yara` runs Foiled's own rules,
/// and `threatsieve` is only written for answers whose every source allows
/// redistribution and commercial use (anything else is
/// `threatsieve_restricted`, kept per tenant). This is an allowlist: every
/// other provider, including one added to the config later, is treated as
/// third party.
pub const FIRST_PARTY: &[&str] = &[LOCAL_ASN, "yara", THREATSIEVE];

/// Known third-party provider names, used to catch their data relabelled
/// under another provider's name (`greynoise.noise` as a key).
pub const KNOWN_THIRD_PARTY: &[&str] = &[
    GREYNOISE,
    CROWDSEC,
    DSHIELD,
    "shadowserver",
    "huntio",
    "abuseipdb",
];

/// True unless `provider` is on [`FIRST_PARTY`]. Ignores ASCII case.
pub fn is_third_party(provider: &str) -> bool {
    !FIRST_PARTY.iter().any(|p| p.eq_ignore_ascii_case(provider))
}

/// True if a Fact key's namespace names a known third-party provider.
fn third_party_namespace(key: &str) -> bool {
    let ns = key.split('.').next().unwrap_or("");
    KNOWN_THIRD_PARTY.iter().any(|p| p.eq_ignore_ascii_case(ns))
}

impl CacheEntry {
    /// A cache row as stored in D1 (`enrich_cache`). `None` for a row that
    /// does not parse (unknown kind, invalid value, bad Facts JSON, negative
    /// numbers), which is skipped rather than trusted.
    pub fn from_row(
        provider: &str,
        kind: &str,
        value: &str,
        fetched_at: i64,
        ttl_secs: i64,
        facts_json: &str,
        tenant_id: Option<&str>,
    ) -> Option<Self> {
        let kind: ObservableKind = serde_json::from_value(Value::String(kind.to_owned())).ok()?;
        let observable = Observable::new(kind, value).ok()?;
        let facts: Vec<Fact> = serde_json::from_str(facts_json).ok()?;
        Some(CacheEntry {
            provider: provider.to_owned(),
            observable,
            fetched_at,
            ttl_secs: u64::try_from(ttl_secs).ok()?,
            facts,
            tenant_id: tenant_id.map(str::to_owned),
        })
    }
}

/// Who is reading cached Facts and when.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReadPolicy<'a> {
    pub now_ms: i64,
    /// The reading tenant. Rows kept for one tenant are read only by it.
    pub tenant_id: Option<&'a str>,
    /// `show_to_tenants` in `configs/enrichment.yaml`. When false (the
    /// shipped default) third-party Facts are left out of anything a tenant
    /// user can read.
    pub show_third_party: bool,
}

/// The Facts that may be used from cache rows, grouped by observable:
///
/// - the row is fresh at `now` (`fetched_at + ttl_secs`), and younger than
///   the retention cap for its provider (`enrichment_cache` TTLs, #16), so
///   a row the purge job has not reached yet is not used either;
/// - each Fact is fresh at `now` (`observed_at + ttl_secs`);
/// - each Fact belongs to the row's provider, so a row cannot carry
///   another provider's data under its name;
/// - third-party providers (anything not on [`FIRST_PARTY`]), and Facts
///   keyed under a known third-party namespace (`greynoise.noise`), only
///   when `show_third_party` is set.
///
/// Observables are in order, with no duplicates; Facts keep row order.
pub fn usable_facts(
    entries: &[CacheEntry],
    policy: ReadPolicy<'_>,
    retention: &crate::retention::RetentionConfig,
) -> Vec<ObservedFacts> {
    let mut by: BTreeMap<Observable, Vec<Fact>> = BTreeMap::new();
    for e in entries {
        if !e.is_fresh(policy.now_ms) {
            continue;
        }
        let cap_days = retention.ttl_days_for(
            crate::retention::DataClass::EnrichmentCache,
            Some(&e.provider),
        );
        let cap_ms = i64::from(cap_days).saturating_mul(86_400_000);
        if policy.now_ms.saturating_sub(e.fetched_at) >= cap_ms {
            continue;
        }
        // A row kept for one tenant is that tenant's own lookup: shown to it
        // whatever `show_to_tenants` says, and to nobody else.
        let own = match &e.tenant_id {
            Some(t) if policy.tenant_id == Some(t.as_str()) => true,
            Some(_) => continue,
            None => false,
        };
        if !own && !policy.show_third_party && is_third_party(&e.provider) {
            continue;
        }
        let facts = e.facts.iter().filter(|f| {
            f.provider.eq_ignore_ascii_case(&e.provider)
                && f.is_fresh(policy.now_ms)
                && (own || policy.show_third_party || !third_party_namespace(&f.key))
        });
        by.entry(e.observable.clone())
            .or_default()
            .extend(facts.cloned());
    }
    by.into_iter()
        .filter(|(_, facts)| !facts.is_empty())
        .map(|(observable, facts)| ObservedFacts { observable, facts })
        .collect()
}

// ---------------------------------------------------------------------------
// Consumers
// ---------------------------------------------------------------------------

/// The enrichment inputs to the noise score on attempts (#25) and the
/// `noise_score` evidence in the confidence layer (#27). `None` means the
/// provider was not asked, is off, or did not answer.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct NoiseFacts {
    pub greynoise_noise: Option<bool>,
    pub greynoise_riot: Option<bool>,
    pub crowdsec_reputation: Option<String>,
}

/// Picks the newest value for each noise input from `facts`. Ties on
/// `observed_at` keep the later Fact in the slice.
pub fn noise_inputs(facts: &[Fact]) -> NoiseFacts {
    let newest = |provider: &str, key: &str| {
        facts
            .iter()
            .filter(|f| f.provider == provider && f.key == key)
            .max_by_key(|f| f.observed_at)
            .map(|f| &f.value)
    };
    NoiseFacts {
        greynoise_noise: newest(GREYNOISE, "greynoise.noise").and_then(Value::as_bool),
        greynoise_riot: newest(GREYNOISE, "greynoise.riot").and_then(Value::as_bool),
        crowdsec_reputation: newest(CROWDSEC, "crowdsec.reputation")
            .and_then(Value::as_str)
            .map(str::to_owned),
    }
}

/// True if `provider` is on [`NEVER_REDISTRIBUTE`]. Ignores ASCII case.
pub fn is_never_redistribute(provider: &str) -> bool {
    NEVER_REDISTRIBUTE
        .iter()
        .any(|p| p.eq_ignore_ascii_case(provider))
}

/// Facts that may leave the operator's console in an export (#13), a public
/// page (#35) or a contribute-back channel (#37). Drops every Fact whose
/// provider is on [`NEVER_REDISTRIBUTE`], and, as a second guard, every Fact
/// whose key is namespaced under one of those providers (`greynoise.noise`
/// relabelled under another provider is still GreyNoise data).
pub fn redact_for_export(facts: &[Fact]) -> Vec<Fact> {
    facts
        .iter()
        .filter(|f| {
            let ns = f.key.split('.').next().unwrap_or("");
            !is_never_redistribute(&f.provider) && !is_never_redistribute(ns)
        })
        .cloned()
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    const NOW: i64 = 1_792_285_400_000;
    const DAY: u64 = 86_400;

    const GN_NOISE: &str =
        include_str!("../../../testdata/enrichment/providers/greynoise-community-noise.json");
    const GN_RIOT: &str =
        include_str!("../../../testdata/enrichment/providers/greynoise-community-riot.json");
    const GN_UNSEEN: &str =
        include_str!("../../../testdata/enrichment/providers/greynoise-community-not-found.json");
    const CS_SMOKE: &str =
        include_str!("../../../testdata/enrichment/providers/crowdsec-smoke.json");
    const CS_UNSEEN: &str =
        include_str!("../../../testdata/enrichment/providers/crowdsec-not-found.json");
    const DS_IP: &str = include_str!("../../../testdata/enrichment/providers/dshield-ip.json");
    const DS_UNSEEN: &str =
        include_str!("../../../testdata/enrichment/providers/dshield-unknown.json");
    const ASN_CSV: &str = include_str!("../../../testdata/enrichment/asn.csv");
    const FACT_FIXTURES: [&str; 3] = [
        include_str!("../../../testdata/enrichment/facts/greynoise-noise.json"),
        include_str!("../../../testdata/enrichment/facts/local-asn-number.json"),
        include_str!("../../../testdata/enrichment/facts/yara-match.json"),
    ];
    const CAPTURE: [&str; 4] = [
        include_str!("../../../testdata/capture/http-upload.json"),
        include_str!("../../../testdata/capture/hook-trigger.json"),
        include_str!("../../../testdata/capture/egress-blocked.json"),
        include_str!("../../../testdata/capture/emulator-redis.json"),
    ];

    fn stamp() -> Stamp {
        Stamp::new(NOW, DAY)
    }

    fn get<'a>(facts: &'a [Fact], key: &str) -> Option<&'a Value> {
        facts.iter().find(|f| f.key == key).map(|f| &f.value)
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    // --- observables -------------------------------------------------------

    #[test]
    fn observables_normalise() {
        assert_eq!(
            Observable::ip("::ffff:203.0.113.7").unwrap().value,
            "203.0.113.7"
        );
        assert_eq!(
            Observable::ip("2001:DB8:0:0::1").unwrap().value,
            "2001:db8::1"
        );
        assert_eq!(
            Observable::domain("Stage2.Example.INVALID.").unwrap().value,
            "stage2.example.invalid"
        );
        let h = "9F86D081884C7D659A2FEAA0C55AD015A3BF4F1B2B0B822CD15D6C15B0F00A08";
        assert_eq!(Observable::sha256(h).unwrap().value, h.to_ascii_lowercase());
        assert!(Observable::new(ObservableKind::Url, "https://example.invalid/x.sh").is_ok());
    }

    #[test]
    fn observables_reject_bad_values() {
        assert!(Observable::ip("203.0.113.999").is_err());
        assert!(Observable::ip("").is_err());
        assert!(Observable::domain("-bad.example").is_err());
        assert!(Observable::domain("a..example").is_err());
        assert!(Observable::domain("has space.example").is_err());
        assert!(Observable::domain(&"a".repeat(64)).is_err());
        assert!(Observable::sha256("abc").is_err());
        assert!(Observable::sha256(&"g".repeat(64)).is_err());
        for bad in [
            "example.invalid/x",
            "javascript://alert(1)",
            "http://",
            "http://exa mple.invalid/",
            "file:///etc/passwd",
        ] {
            assert!(Observable::new(ObservableKind::Url, bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn observable_deserialise_validates() {
        let ok: Observable =
            serde_json::from_str(r#"{"kind":"ip","value":"::ffff:192.0.2.1"}"#).unwrap();
        assert_eq!(ok.value, "192.0.2.1");
        assert!(serde_json::from_str::<Observable>(r#"{"kind":"ip","value":"nope"}"#).is_err());
        assert!(
            serde_json::from_str::<Observable>(r#"{"kind":"ip","value":"192.0.2.1","x":1}"#)
                .is_err()
        );
    }

    #[test]
    fn private_addresses_are_not_sent_out() {
        for private in [
            "10.85.1.2",
            "192.168.1.1",
            "172.16.0.1",
            "127.0.0.1",
            "169.254.1.1",
            "100.64.0.1",
            "0.0.0.0",
            "224.0.0.1",
            "::1",
            "fd00::1",
            "fe80::1",
        ] {
            assert!(
                !Observable::ip(private)
                    .unwrap()
                    .is_external_lookup_eligible(),
                "{private}"
            );
        }
        for public in ["203.0.113.7", "198.51.100.23", "2001:db8::1"] {
            assert!(
                Observable::ip(public)
                    .unwrap()
                    .is_external_lookup_eligible()
            );
        }
        assert!(
            Observable::domain("example.invalid")
                .unwrap()
                .is_external_lookup_eligible()
        );
    }

    #[test]
    fn cache_key_is_provider_kind_value() {
        let o = Observable::ip("203.0.113.7").unwrap();
        assert_eq!(o.cache_key("greynoise"), "greynoise:ip:203.0.113.7");
    }

    #[test]
    fn observables_from_capture_fixtures() {
        let events: Vec<CaptureEvent> = CAPTURE
            .iter()
            .map(|t| serde_json::from_str(t).unwrap())
            .collect();
        let sha = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08";
        // HTTP upload: attacker IP plus the payload hash (in payload_ref and
        // body_sha256, de-duplicated).
        assert_eq!(
            observables_for_event(&events[0]),
            vec![
                Observable::ip("203.0.113.7").unwrap(),
                Observable::sha256(sha).unwrap()
            ]
        );
        // Egress: the decoy's private source is skipped; the destination and
        // the requested host are the attacker's infrastructure.
        assert_eq!(
            observables_for_event(&events[2]),
            vec![
                Observable::ip("192.0.2.80").unwrap(),
                Observable::domain("stage2.example.invalid").unwrap()
            ]
        );
        assert_eq!(
            observables_for_event(&events[3]),
            vec![Observable::ip("198.51.100.23").unwrap()]
        );
    }

    // --- facts and cache ----------------------------------------------------

    #[test]
    fn fact_fixtures_match_the_type() {
        for text in FACT_FIXTURES {
            let f: Fact = serde_json::from_str(text).unwrap();
            assert!(f.confidence <= 100);
            let back = serde_json::to_value(&f).unwrap();
            assert_eq!(back, serde_json::from_str::<Value>(text).unwrap());
        }
    }

    #[test]
    fn cache_entry_freshness() {
        let entry = CacheEntry {
            provider: GREYNOISE.to_owned(),
            observable: Observable::ip("203.0.113.7").unwrap(),
            fetched_at: NOW,
            ttl_secs: 60,
            facts: Vec::new(),
            tenant_id: None,
        };
        assert_eq!(entry.key(), "greynoise:ip:203.0.113.7");
        assert!(entry.is_fresh(NOW));
        assert!(entry.is_fresh(NOW + 59_999));
        assert!(!entry.is_fresh(NOW + 60_000));
        let forever = CacheEntry {
            ttl_secs: u64::MAX,
            ..entry.clone()
        };
        assert!(forever.is_fresh(i64::MAX - 1));
        let zero = CacheEntry {
            ttl_secs: 0,
            ..entry
        };
        assert!(!zero.is_fresh(NOW));
    }

    #[test]
    fn fact_freshness_uses_its_own_ttl() {
        let facts = parse_greynoise_community(GN_NOISE, &Stamp::new(NOW, 10)).unwrap();
        assert!(facts[0].is_fresh(NOW + 9_000));
        assert!(!facts[0].is_fresh(NOW + 10_000));
    }

    // --- GreyNoise -----------------------------------------------------------

    #[test]
    fn greynoise_noise() {
        let facts = parse_greynoise_community(GN_NOISE, &stamp()).unwrap();
        assert_eq!(get(&facts, "greynoise.noise"), Some(&Value::Bool(true)));
        assert_eq!(get(&facts, "greynoise.riot"), Some(&Value::Bool(false)));
        assert_eq!(
            get(&facts, "greynoise.classification"),
            Some(&Value::from("malicious"))
        );
        assert_eq!(
            get(&facts, "greynoise.last_seen"),
            Some(&Value::from("2026-10-15"))
        );
        assert!(facts.iter().all(|f| f.provider == GREYNOISE
            && f.confidence == GREYNOISE_CONFIDENCE
            && f.observed_at == NOW
            && f.ttl_secs == DAY));
    }

    #[test]
    fn greynoise_riot() {
        let facts = parse_greynoise_community(GN_RIOT, &stamp()).unwrap();
        assert_eq!(get(&facts, "greynoise.riot"), Some(&Value::Bool(true)));
        assert_eq!(
            get(&facts, "greynoise.name"),
            Some(&Value::from("Example Public Resolver"))
        );
    }

    #[test]
    fn greynoise_not_observed_still_reports_flags() {
        let facts = parse_greynoise_community(GN_UNSEEN, &stamp()).unwrap();
        assert_eq!(facts.len(), 2);
        assert_eq!(get(&facts, "greynoise.noise"), Some(&Value::Bool(false)));
        assert_eq!(get(&facts, "greynoise.riot"), Some(&Value::Bool(false)));
    }

    #[test]
    fn greynoise_errors() {
        assert_eq!(
            parse_greynoise_community(r#"{"message":"Rate limit exceeded"}"#, &stamp()),
            Err(ParseError::Provider("Rate limit exceeded".to_owned()))
        );
        assert_eq!(
            parse_greynoise_community(r#"{"noise":"yes","riot":false}"#, &stamp()),
            Err(ParseError::WrongType("noise"))
        );
        assert_eq!(
            parse_greynoise_community(r#"{"noise":true}"#, &stamp()),
            Err(ParseError::Missing("riot"))
        );
        assert_eq!(
            parse_greynoise_community("<html>", &stamp()),
            Err(ParseError::NotJson)
        );
        assert_eq!(
            parse_greynoise_community("[]", &stamp()),
            Err(ParseError::NotObject)
        );
    }

    #[test]
    fn provider_text_is_clipped_and_stripped() {
        let long = "x".repeat(MAX_TEXT * 2);
        let body = format!(
            r#"{{"noise":true,"riot":false,"name":"{long}","classification":"bad\u0007\u001b[31m"}}"#
        );
        let facts = parse_greynoise_community(&body, &stamp()).unwrap();
        let name = get(&facts, "greynoise.name").unwrap().as_str().unwrap();
        assert_eq!(name.chars().count(), MAX_TEXT);
        assert_eq!(
            get(&facts, "greynoise.classification"),
            Some(&Value::from("bad[31m"))
        );
    }

    // --- CrowdSec -------------------------------------------------------------

    #[test]
    fn crowdsec_smoke() {
        let facts = parse_crowdsec_smoke(CS_SMOKE, &stamp()).unwrap();
        assert_eq!(
            get(&facts, "crowdsec.reputation"),
            Some(&Value::from("malicious"))
        );
        assert_eq!(
            get(&facts, "crowdsec.behaviors"),
            Some(&serde_json::json!(["http:exploit", "http:scan"]))
        );
        assert_eq!(
            get(&facts, "crowdsec.attack_details"),
            Some(&serde_json::json!([
                "crowdsecurity/http-path-traversal-probing",
                "crowdsecurity/http-probing"
            ]))
        );
        // "not-a-technique" is dropped; the sub-technique is kept.
        assert_eq!(
            get(&facts, "crowdsec.mitre_techniques"),
            Some(&serde_json::json!(["T1190", "T1595.002"]))
        );
        // "CVE-bogus" is dropped.
        assert_eq!(
            get(&facts, "crowdsec.cves"),
            Some(&serde_json::json!(["CVE-2099-0001"]))
        );
        assert!(
            facts
                .iter()
                .all(|f| f.provider == CROWDSEC && f.confidence == 90)
        );
    }

    #[test]
    fn crowdsec_not_found_is_a_provider_error() {
        assert_eq!(
            parse_crowdsec_smoke(CS_UNSEEN, &stamp()),
            Err(ParseError::Provider(
                "IP address information not found".to_owned()
            ))
        );
    }

    #[test]
    fn crowdsec_sparse_and_confidence_levels() {
        let facts = parse_crowdsec_smoke(
            r#"{"ip":"198.51.100.23","reputation":"unknown","behaviors":[],"cves":[]}"#,
            &stamp(),
        )
        .unwrap();
        assert_eq!(facts.len(), 1);
        assert_eq!(facts[0].confidence, CROWDSEC_DEFAULT_CONFIDENCE);
        let low = parse_crowdsec_smoke(
            r#"{"ip":"198.51.100.23","reputation":"suspicious","confidence":"low"}"#,
            &stamp(),
        )
        .unwrap();
        assert_eq!(low[0].confidence, 30);
    }

    #[test]
    fn crowdsec_lists_are_capped() {
        let many: Vec<String> = (0..200)
            .map(|i| format!("\"CVE-2099-{:04}\"", i + 1000))
            .collect();
        let body = format!(r#"{{"ip":"203.0.113.7","cves":[{}]}}"#, many.join(","));
        let facts = parse_crowdsec_smoke(&body, &stamp()).unwrap();
        assert_eq!(
            get(&facts, "crowdsec.cves")
                .unwrap()
                .as_array()
                .unwrap()
                .len(),
            MAX_ITEMS
        );
    }

    // --- DShield ---------------------------------------------------------------

    #[test]
    fn dshield_ip() {
        let facts = parse_dshield_ip(DS_IP, &stamp()).unwrap();
        assert_eq!(get(&facts, "dshield.count"), Some(&Value::from(42u64)));
        assert_eq!(get(&facts, "dshield.attacks"), Some(&Value::from(7u64)));
        assert_eq!(
            get(&facts, "dshield.mindate"),
            Some(&Value::from("2026-09-30"))
        );
        assert_eq!(
            get(&facts, "dshield.maxdate"),
            Some(&Value::from("2026-10-15"))
        );
        assert!(facts.iter().all(|f| f.confidence == DSHIELD_CONFIDENCE));
    }

    #[test]
    fn dshield_unknown_ip_has_no_facts() {
        assert_eq!(parse_dshield_ip(DS_UNSEEN, &stamp()).unwrap(), Vec::new());
    }

    #[test]
    fn dshield_numeric_strings_and_errors() {
        let facts = parse_dshield_ip(
            r#"{"ip":{"number":"203.0.113.7","count":"12","attacks":""}}"#,
            &stamp(),
        )
        .unwrap();
        assert_eq!(get(&facts, "dshield.count"), Some(&Value::from(12u64)));
        assert_eq!(get(&facts, "dshield.attacks"), None);
        assert_eq!(
            parse_dshield_ip(r#"{"ip":{"count":"lots"}}"#, &stamp()),
            Err(ParseError::WrongType("count"))
        );
        assert_eq!(
            parse_dshield_ip(r#"{"error":"bad IP address"}"#, &stamp()),
            Err(ParseError::Provider("bad IP address".to_owned()))
        );
    }

    // --- ASN table -------------------------------------------------------------

    #[test]
    fn asn_table_lookup_v4_and_v6() {
        let t = AsnTable::from_csv(ASN_CSV).unwrap();
        assert_eq!(t.len(), 5);
        let r = t.lookup(ip("192.0.2.200")).unwrap();
        assert_eq!(r.asn, 64496);
        assert_eq!(r.org, "Example Docs Net, Pty Ltd");
        assert_eq!(r.country.as_deref(), Some("AU"));
        // Range edges are inclusive.
        assert_eq!(t.lookup(ip("198.51.100.0")).unwrap().asn, 64497);
        assert_eq!(t.lookup(ip("198.51.100.255")).unwrap().asn, 64497);
        // IPv4-mapped IPv6 is looked up as IPv4.
        assert_eq!(t.lookup(ip("::ffff:203.0.113.7")).unwrap().asn, 64498);
        // Gap between ranges and outside every range.
        assert!(t.lookup(ip("203.0.113.200")).is_none());
        assert!(t.lookup(ip("8.8.8.8")).is_none());
        assert!(t.lookup(ip("0.0.0.0")).is_none());
        assert_eq!(t.lookup(ip("2001:db8::1")).unwrap().asn, 64499);
        let v6 = t.lookup(ip("2001:db8:1:ffff::1")).unwrap();
        assert_eq!((v6.asn, v6.country.as_deref()), (64500, None));
        assert!(t.lookup(ip("2001:db8:2::1")).is_none());
    }

    #[test]
    fn asn_table_rejects_bad_rows() {
        let cases = [
            ("192.0.2.0,192.0.2.255,64496,Org\n", 1, "expected"),
            ("192.0.2.9,192.0.2.1,64496,Org,AU\n", 1, "after end_ip"),
            ("192.0.2.0,2001:db8::,64496,Org,AU\n", 1, "families"),
            ("192.0.2.0,192.0.2.9,ASX,Org,AU\n", 1, "bad asn"),
            ("nope,192.0.2.9,1,Org,AU\n", 1, "bad start_ip"),
            ("192.0.2.0,192.0.2.9,1,Org,Australia\n", 1, "two letters"),
            (
                "# c\n192.0.2.0,192.0.2.9,1,A,AU\n192.0.2.5,192.0.2.20,2,B,AU\n",
                3,
                "overlaps",
            ),
        ];
        for (csv, line, reason) in cases {
            let e = AsnTable::from_csv(csv).unwrap_err();
            assert_eq!(e.line, line, "{csv}");
            assert!(e.reason.contains(reason), "{csv}: {e}");
        }
    }

    #[test]
    fn asn_table_empty_and_as_prefix() {
        let t = AsnTable::from_csv("# nothing yet\n\n").unwrap();
        assert!(t.is_empty());
        assert!(t.lookup(ip("192.0.2.1")).is_none());
        let t = AsnTable::from_csv("192.0.2.0,192.0.2.255,AS64496,Org,au\n").unwrap();
        let r = t.lookup(ip("192.0.2.1")).unwrap();
        assert_eq!((r.asn, r.country.as_deref()), (64496, Some("AU")));
    }

    #[test]
    fn asn_table_binary_search_over_many_ranges() {
        let mut csv = String::new();
        for i in 0u32..1000 {
            let start = Ipv4Addr::from_bits(0xC000_0000 + i * 16);
            let end = Ipv4Addr::from_bits(0xC000_0000 + i * 16 + 7);
            csv.push_str(&format!("{start},{end},{},Org {i},AU\n", 1000 + i));
        }
        let t = AsnTable::from_csv(&csv).unwrap();
        for i in [0u32, 1, 499, 998, 999] {
            let inside = IpAddr::V4(Ipv4Addr::from_bits(0xC000_0000 + i * 16 + 3));
            let gap = IpAddr::V4(Ipv4Addr::from_bits(0xC000_0000 + i * 16 + 9));
            assert_eq!(t.lookup(inside).unwrap().asn, 1000 + i);
            assert!(t.lookup(gap).is_none());
        }
    }

    #[test]
    fn asn_table_as_provider() {
        let t = AsnTable::from_csv(ASN_CSV).unwrap();
        let o = Observable::ip("203.0.113.7").unwrap();
        let facts = t.enrich(&o, NOW).unwrap();
        assert_eq!(get(&facts, "asn.number"), Some(&Value::from(64498u32)));
        assert_eq!(
            get(&facts, "asn.org"),
            Some(&Value::from("Example Hosting"))
        );
        assert_eq!(get(&facts, "geo.country"), Some(&Value::from("US")));
        assert!(
            facts
                .iter()
                .all(|f| f.provider == LOCAL_ASN && f.ttl_secs == AsnTable::DEFAULT_TTL_SECS)
        );
        assert!(
            t.enrich(&Observable::ip("8.8.8.8").unwrap(), NOW)
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            t.enrich(&Observable::domain("example.invalid").unwrap(), NOW),
            Err(EnrichError::Unsupported)
        );
    }

    // --- consumers -------------------------------------------------------------

    #[test]
    fn noise_inputs_from_facts() {
        assert_eq!(noise_inputs(&[]), NoiseFacts::default());
        let mut facts = parse_greynoise_community(GN_NOISE, &Stamp::new(NOW - 1000, DAY)).unwrap();
        facts.extend(parse_crowdsec_smoke(CS_SMOKE, &stamp()).unwrap());
        // A newer GreyNoise answer wins over the older one.
        facts.extend(parse_greynoise_community(GN_RIOT, &stamp()).unwrap());
        assert_eq!(
            noise_inputs(&facts),
            NoiseFacts {
                greynoise_noise: Some(false),
                greynoise_riot: Some(true),
                crowdsec_reputation: Some("malicious".to_owned()),
            }
        );
    }

    #[test]
    fn noise_inputs_ignore_other_providers() {
        let mut f = parse_greynoise_community(GN_NOISE, &stamp()).unwrap();
        for fact in &mut f {
            fact.provider = "fake".to_owned();
        }
        assert_eq!(noise_inputs(&f), NoiseFacts::default());
    }

    #[test]
    fn export_drops_every_third_party_fact() {
        let mut facts = Vec::new();
        facts.extend(parse_greynoise_community(GN_NOISE, &stamp()).unwrap());
        facts.extend(parse_crowdsec_smoke(CS_SMOKE, &stamp()).unwrap());
        facts.extend(parse_dshield_ip(DS_IP, &stamp()).unwrap());
        let asn = AsnTable::from_csv(ASN_CSV).unwrap();
        facts.extend(
            asn.enrich(&Observable::ip("203.0.113.7").unwrap(), NOW)
                .unwrap(),
        );
        for p in ["shadowserver", "huntio", "abuseipdb", "AbuseIPDB"] {
            facts.push(stamp().fact(p, &format!("{}.x", p.to_ascii_lowercase()), Value::Null, 50));
        }
        // Relabelled third-party data is still caught by its key.
        facts.push(stamp().fact("foiled", "greynoise.noise", Value::Bool(true), 50));
        let yara: Fact = serde_json::from_str(FACT_FIXTURES[2]).unwrap();
        facts.push(yara.clone());

        let out = redact_for_export(&facts);
        assert_eq!(out, vec![yara]);
        for p in NEVER_REDISTRIBUTE {
            assert!(is_never_redistribute(p));
        }
        assert!(!is_never_redistribute("yara"));
    }

    // --- provider interface and attachment to an attempt ------------------------

    /// A provider that answers for any IP with one fixed Fact.
    struct FakeProvider;

    impl Provider for FakeProvider {
        fn id(&self) -> &str {
            "fake"
        }
        fn supports(&self, kind: ObservableKind) -> bool {
            kind == ObservableKind::Ip
        }
        fn enrich(&self, o: &Observable, now_ms: i64) -> Result<Vec<Fact>, EnrichError> {
            Ok(vec![Stamp::new(now_ms, 3600).fact(
                "fake",
                "fake.seen",
                Value::String(o.value.clone()),
                75,
            )])
        }
    }

    /// A provider that is always down.
    struct DownProvider;

    impl Provider for DownProvider {
        fn id(&self) -> &str {
            "down"
        }
        fn supports(&self, _: ObservableKind) -> bool {
            true
        }
        fn enrich(&self, _: &Observable, _: i64) -> Result<Vec<Fact>, EnrichError> {
            Err(EnrichError::Unavailable("connection reset".to_owned()))
        }
    }

    /// Stand-in for the attempt entity from #25: events grouped by decoy and
    /// attacker, plus the observables they carry. Facts join by observable,
    /// never by a field on the Fact, so the real attempt type can replace this.
    #[derive(Debug)]
    struct AttemptFixture {
        attempt_id: String,
        event_ids: Vec<String>,
        observables: BTreeSet<Observable>,
    }

    impl AttemptFixture {
        fn facts<'a>(&self, run: &'a EnrichmentRun) -> Vec<(&Observable, &'a Fact)> {
            self.observables
                .iter()
                .flat_map(|o| run.facts_for(o).iter().map(move |f| (o, f)))
                .collect()
        }
    }

    fn attempts_from_capture() -> Vec<AttemptFixture> {
        let mut by_key: BTreeMap<(String, String), AttemptFixture> = BTreeMap::new();
        for text in CAPTURE {
            let e: CaptureEvent = serde_json::from_str(text).unwrap();
            if e.channel == Channel::Egress {
                continue; // egress belongs to the attempt that caused it (#25)
            }
            let n = by_key.len();
            let a = by_key
                .entry((e.decoy_id.clone(), e.src.ip.clone()))
                .or_insert_with(|| AttemptFixture {
                    attempt_id: format!("att-{:04}", n + 1),
                    event_ids: Vec::new(),
                    observables: BTreeSet::new(),
                });
            a.event_ids.push(e.event_id.clone());
            a.observables.extend(observables_for_event(&e));
        }
        by_key.into_values().collect()
    }

    #[test]
    fn fake_provider_facts_attach_to_attempt_fixture() {
        let attempts = attempts_from_capture();
        let demo = attempts
            .iter()
            .find(|a| a.event_ids.contains(&"evt-0001".to_owned()))
            .unwrap();
        assert_eq!(demo.event_ids, ["evt-0001", "evt-0002"]);

        let observables: Vec<Observable> = attempts
            .iter()
            .flat_map(|a| a.observables.iter().cloned())
            .collect();
        let asn = AsnTable::from_csv(ASN_CSV).unwrap();
        let providers: [&dyn Provider; 3] = [&FakeProvider, &DownProvider, &asn];
        let run = enrich_all(&providers, &observables, NOW);

        let attached = demo.facts(&run);
        let attacker = Observable::ip("203.0.113.7").unwrap();
        assert!(attached.iter().any(|(o, f)| **o == attacker
            && f.provider == "fake"
            && f.value == "203.0.113.7"
            && f.observed_at == NOW));
        assert!(
            attached
                .iter()
                .any(|(o, f)| **o == attacker && f.key == "asn.number")
        );
        // The hash observable has no Fact (fake and ASN only do IPs), but the
        // attempt still lists it, ready for YARA results later.
        assert!(
            demo.observables
                .iter()
                .any(|o| o.kind == ObservableKind::Sha256)
        );

        // The down provider failed for every observable and the run went on.
        assert_eq!(run.failures.len(), observables.len());
        assert!(run.failures.iter().all(|f| f.provider == "down"));

        // Nothing was dropped from the attempts by the failure.
        let redis = attempts
            .iter()
            .find(|a| a.event_ids == ["evt-0003"])
            .unwrap();
        assert!(!redis.attempt_id.is_empty());
        assert_eq!(redis.facts(&run).len(), 1 + 3);
    }

    #[test]
    fn all_failing_providers_leave_events_intact() {
        let attempts = attempts_from_capture();
        let observables: Vec<Observable> = attempts
            .iter()
            .flat_map(|a| a.observables.iter().cloned())
            .collect();
        let run = enrich_all(&[&DownProvider], &observables, NOW);
        assert!(run.facts.is_empty());
        assert_eq!(run.failures.len(), observables.len());
        let ids: Vec<&String> = attempts.iter().flat_map(|a| &a.event_ids).collect();
        assert_eq!(ids.len(), 3);
    }

    fn row(provider: &str, ip: &str, fetched_at: i64, ttl: u64, facts: Vec<Fact>) -> CacheEntry {
        CacheEntry {
            provider: provider.into(),
            observable: Observable::ip(ip).unwrap(),
            fetched_at,
            ttl_secs: ttl,
            facts,
            tenant_id: None,
        }
    }

    fn fact_at(provider: &str, key: &str, v: Value, at: i64, ttl: u64) -> Fact {
        Fact {
            provider: provider.into(),
            key: key.into(),
            value: v,
            confidence: 90,
            observed_at: at,
            ttl_secs: ttl,
            raw_ref: None,
        }
    }

    #[test]
    fn cache_rows_parse_and_bad_rows_are_skipped() {
        let facts = serde_json::to_string(&vec![fact_at(
            LOCAL_ASN,
            "asn.number",
            Value::from(64498),
            NOW,
            DAY,
        )])
        .unwrap();
        let e = CacheEntry::from_row(
            LOCAL_ASN,
            "ip",
            "::ffff:203.0.113.7",
            NOW,
            86_400,
            &facts,
            None,
        )
        .unwrap();
        assert_eq!(e.observable.value, "203.0.113.7");
        assert_eq!(e.facts.len(), 1);
        assert!(
            CacheEntry::from_row(LOCAL_ASN, "ipv9", "203.0.113.7", NOW, 1, "[]", None).is_none()
        );
        assert!(CacheEntry::from_row(LOCAL_ASN, "ip", "nope", NOW, 1, "[]", None).is_none());
        assert!(
            CacheEntry::from_row(LOCAL_ASN, "ip", "203.0.113.7", NOW, -1, "[]", None).is_none()
        );
        assert!(CacheEntry::from_row(LOCAL_ASN, "ip", "203.0.113.7", NOW, 1, "{", None).is_none());
    }

    #[test]
    fn usable_facts_honour_ttls_retention_provider_and_visibility() {
        let ret = crate::retention::RetentionConfig::default();
        let now = NOW + 1000;
        let policy = ReadPolicy {
            now_ms: now,
            tenant_id: None,
            show_third_party: false,
        };
        let entries = vec![
            // Fresh row, one fresh and one expired Fact, one Fact that
            // claims another provider.
            row(
                LOCAL_ASN,
                "203.0.113.7",
                NOW,
                DAY,
                vec![
                    fact_at(LOCAL_ASN, "asn.number", Value::from(64498), NOW, DAY),
                    fact_at(
                        LOCAL_ASN,
                        "asn.org",
                        Value::from("old"),
                        NOW - 2 * 86_400_000,
                        DAY,
                    ),
                    fact_at(GREYNOISE, "greynoise.noise", Value::Bool(true), NOW, DAY),
                ],
            ),
            // Expired row.
            row(
                LOCAL_ASN,
                "198.51.100.23",
                NOW - 2 * 86_400_000,
                DAY,
                vec![fact_at(
                    LOCAL_ASN,
                    "asn.number",
                    Value::from(64497),
                    NOW - 2 * 86_400_000,
                    10 * DAY,
                )],
            ),
            // Row TTL longer than the retention cap (7 days by default).
            row(
                LOCAL_ASN,
                "192.0.2.1",
                NOW - 8 * 86_400_000,
                30 * DAY,
                vec![fact_at(
                    LOCAL_ASN,
                    "asn.number",
                    Value::from(64496),
                    NOW - 8 * 86_400_000,
                    30 * DAY,
                )],
            ),
            // Third-party row, and a relabelled third-party key.
            row(
                GREYNOISE,
                "203.0.113.7",
                NOW,
                DAY,
                vec![fact_at(
                    GREYNOISE,
                    "greynoise.noise",
                    Value::Bool(true),
                    NOW,
                    DAY,
                )],
            ),
            row(
                "team_asn",
                "203.0.113.7",
                NOW,
                DAY,
                vec![
                    fact_at("team_asn", "greynoise.noise", Value::Bool(true), NOW, DAY),
                    fact_at("team_asn", "geo.country", Value::from("US"), NOW, DAY),
                ],
            ),
            // First party, with a relabelled third-party key.
            row(
                "yara",
                "203.0.113.7",
                NOW,
                DAY,
                vec![
                    fact_at("yara", "greynoise.noise", Value::Bool(true), NOW, DAY),
                    fact_at("yara", "yara.rule", Value::from("demo_rule"), NOW, DAY),
                ],
            ),
        ];
        // A provider nobody listed is third party by default.
        assert!(is_third_party("team_asn") && is_third_party("brand_new_provider"));
        assert!(!is_third_party("LOCAL_ASN") && !is_third_party("yara"));
        let got = usable_facts(&entries, policy, &ret);
        assert_eq!(got.len(), 1);
        let keys: Vec<(&str, &str)> = got[0]
            .facts
            .iter()
            .map(|f| (f.provider.as_str(), f.key.as_str()))
            .collect();
        assert_eq!(keys, vec![(LOCAL_ASN, "asn.number"), ("yara", "yara.rule")]);

        let shown = usable_facts(
            &entries,
            ReadPolicy {
                now_ms: now,
                tenant_id: None,
                show_third_party: true,
            },
            &ret,
        );
        assert_eq!(shown[0].facts.len(), 6);
        assert!(shown[0].facts.iter().any(|f| f.provider == GREYNOISE));
    }

    #[test]
    fn fact_problems_catch_bad_and_relabelled_facts() {
        let ok = fact_at(LOCAL_ASN, "asn.number", Value::from(64498), NOW, DAY);
        assert!(ok.problems(LOCAL_ASN).is_empty());
        assert!(!ok.problems(GREYNOISE).is_empty(), "provider mismatch");
        let mut bad = ok.clone();
        bad.key = "Bad Key".into();
        assert!(!bad.problems(LOCAL_ASN).is_empty());
        let mut bad = ok.clone();
        bad.key = "nodot".into();
        assert!(!bad.problems(LOCAL_ASN).is_empty());
        let mut bad = ok.clone();
        bad.confidence = 101;
        assert!(!bad.problems(LOCAL_ASN).is_empty());
        let mut bad = ok.clone();
        bad.value = Value::String("x".repeat(MAX_FACT_VALUE_BYTES));
        assert!(!bad.problems(LOCAL_ASN).is_empty());
        let mut bad = ok;
        bad.provider = "Local-ASN".into();
        assert!(!bad.problems("Local-ASN").is_empty());
    }
}
