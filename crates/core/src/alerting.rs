//! Alerting (#15): event types, severities, dedupe, rate limits, routing
//! and webhook signing.
//!
//! Pure logic only. Time is always a parameter (Unix milliseconds), there is
//! no I/O, and nothing here reads secrets. The delivery worker (a Queue
//! consumer in the control plane) owns the network calls and the secret
//! values; this module decides what to send where. See `docs/alerting.md`
//! and `configs/alerting.yaml`.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::attempt::{Attempt, AttemptState, HookHit};
use crate::capture::HookStage;
/// Alert severities share the capture envelope scale:
/// `info < low < medium < high < critical`.
pub use crate::capture::Severity;

const HOUR_SECS: u32 = 3600;
const DAY_SECS: u32 = 24 * HOUR_SECS;

/// Smallest dedupe window the config accepts, in seconds.
pub const MIN_DEDUPE_WINDOW_SECS: u32 = 60;
/// Default bound on remembered dedupe keys.
pub const DEFAULT_DEDUPE_MAX_KEYS: usize = 10_000;
/// Per-type cap applied when the config does not set one.
pub const DEFAULT_TYPE_LIMIT: RateLimit = RateLimit {
    burst: 5,
    per_hour: 20,
};

/// Every alert type the control plane can raise. Names are snake_case and
/// part of the payload contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AlertType {
    /// A vulnerable-path hook fired at the trigger stage (#32).
    VulnPathHookFired,
    /// The confidence layer promoted a CVE assessment tier (#12, #33).
    CveAssessed,
    /// A predisclosure watchlist spike (#12, #35).
    PredisclosureSpike,
    /// A campaign cluster was created or changed (#34).
    CampaignUpdated,
    /// An edge sensor stopped reporting (#31).
    EdgeSensorOffline,
    /// A new analyst review queue item (#35).
    ReviewQueueItem,
    /// A decoy reached post-exploitation or was marked compromised (#8).
    DecoyCompromised,
    /// A planted canary value was used (#17).
    CanaryUsed,
    /// YARA matched a quarantined file (#11).
    YaraMatch,
    /// Honeyscore self-check at or above threshold (#18).
    HoneyscoreHigh,
    /// Capture volume on a host passed the pressure mark (ADR 0005).
    CaptureDiskPressure,
    /// A rotation entered `failed` or a freeze was not confirmed (#8).
    RotationFailed,
    /// A sandbox host stopped heartbeating (#41).
    HostOffline,
    /// The rotation storm guard engaged (#8).
    RotationStorm,
    /// A decoy kept a burnt IP because the pool was empty (#8, #18).
    DecoyBurnt,
    /// A rotation succeeded. Log sink only by default (#8).
    DecoyRotated,
}

/// Which facts make two alerts "the same" for dedupe.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DedupeBasis {
    /// Source IP + CVE id, per window.
    SrcCve,
    /// Campaign id, per window.
    Campaign,
    /// Decoy id + alert type, per window.
    DecoyType,
    /// The alert's `subject` (host, sensor, public IP, CVE or queue item id).
    Subject,
}

impl AlertType {
    pub const ALL: [AlertType; 16] = [
        AlertType::VulnPathHookFired,
        AlertType::CveAssessed,
        AlertType::PredisclosureSpike,
        AlertType::CampaignUpdated,
        AlertType::EdgeSensorOffline,
        AlertType::ReviewQueueItem,
        AlertType::DecoyCompromised,
        AlertType::CanaryUsed,
        AlertType::YaraMatch,
        AlertType::HoneyscoreHigh,
        AlertType::CaptureDiskPressure,
        AlertType::RotationFailed,
        AlertType::HostOffline,
        AlertType::RotationStorm,
        AlertType::DecoyBurnt,
        AlertType::DecoyRotated,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            AlertType::VulnPathHookFired => "vuln_path_hook_fired",
            AlertType::CveAssessed => "cve_assessed",
            AlertType::PredisclosureSpike => "predisclosure_spike",
            AlertType::CampaignUpdated => "campaign_updated",
            AlertType::EdgeSensorOffline => "edge_sensor_offline",
            AlertType::ReviewQueueItem => "review_queue_item",
            AlertType::DecoyCompromised => "decoy_compromised",
            AlertType::CanaryUsed => "canary_used",
            AlertType::YaraMatch => "yara_match",
            AlertType::HoneyscoreHigh => "honeyscore_high",
            AlertType::CaptureDiskPressure => "capture_disk_pressure",
            AlertType::RotationFailed => "rotation_failed",
            AlertType::HostOffline => "host_offline",
            AlertType::RotationStorm => "rotation_storm",
            AlertType::DecoyBurnt => "decoy_burnt",
            AlertType::DecoyRotated => "decoy_rotated",
        }
    }

    /// Default severity, before any `severity_overrides` in the config.
    pub fn default_severity(self) -> Severity {
        use AlertType::*;
        match self {
            CanaryUsed | RotationFailed => Severity::Critical,
            VulnPathHookFired | PredisclosureSpike | EdgeSensorOffline | DecoyCompromised
            | YaraMatch | CaptureDiskPressure | HostOffline | RotationStorm => Severity::High,
            CveAssessed | CampaignUpdated | HoneyscoreHigh | DecoyBurnt => Severity::Medium,
            ReviewQueueItem => Severity::Low,
            DecoyRotated => Severity::Info,
        }
    }

    pub fn dedupe_basis(self) -> DedupeBasis {
        use AlertType::*;
        match self {
            VulnPathHookFired => DedupeBasis::SrcCve,
            CampaignUpdated => DedupeBasis::Campaign,
            DecoyCompromised | CanaryUsed | YaraMatch | RotationFailed | RotationStorm
            | DecoyBurnt | DecoyRotated => DedupeBasis::DecoyType,
            CveAssessed | PredisclosureSpike | EdgeSensorOffline | ReviewQueueItem
            | HoneyscoreHigh | CaptureDiskPressure | HostOffline => DedupeBasis::Subject,
        }
    }

    /// Default dedupe window in seconds, before `dedupe.windows` overrides.
    pub fn default_window_secs(self) -> u32 {
        use AlertType::*;
        match self {
            CveAssessed | CampaignUpdated | HoneyscoreHigh | DecoyBurnt | ReviewQueueItem => {
                DAY_SECS
            }
            _ => HOUR_SECS,
        }
    }
}

impl fmt::Display for AlertType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LinkKind {
    Attempt,
    QueueItem,
    Decoy,
    Campaign,
    Host,
    Sensor,
    Docs,
}

/// A console link. `href` is a path relative to `console_base_url`; the
/// delivery worker makes it absolute when rendering.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Link {
    pub kind: LinkKind,
    pub href: String,
}

/// The alert payload (`schemas/alert.schema.json`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Alert {
    pub alert_id: String,
    /// Unix milliseconds of the event that raised the alert.
    pub ts: i64,
    pub severity: Severity,
    #[serde(rename = "type")]
    pub alert_type: AlertType,
    pub decoy_id: Option<String>,
    pub attempt_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub campaign_id: Option<String>,
    pub summary: String,
    pub links: Vec<Link>,
    /// Attacker source IP, when the alert is about one source.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub src_ip: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cve_id: Option<String>,
    /// Host id, sensor id, public IP, CVE id or queue item id for alerts
    /// that are not about one decoy.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AlertError {
    EmptyField(&'static str),
    /// Critical alerts must link to a console attempt or review queue item.
    CriticalWithoutLink,
}

impl fmt::Display for AlertError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AlertError::EmptyField(name) => write!(f, "alert field `{name}` is empty"),
            AlertError::CriticalWithoutLink => {
                f.write_str("critical alerts must link to an attempt or a review queue item")
            }
        }
    }
}

impl std::error::Error for AlertError {}

impl Alert {
    /// Deterministic id from the alert type and the facts that identify it,
    /// so a retried producer raises the same `alert_id`.
    pub fn make_id(alert_type: AlertType, parts: &[&str]) -> String {
        let mut h = Sha256::new();
        h.update(alert_type.as_str().as_bytes());
        for p in parts {
            h.update(b"\n");
            h.update(p.as_bytes());
        }
        format!("alr_{}", hex::encode(&h.finalize()[..12]))
    }

    pub fn has_primary_link(&self) -> bool {
        self.links
            .iter()
            .any(|l| matches!(l.kind, LinkKind::Attempt | LinkKind::QueueItem))
    }

    pub fn validate(&self) -> Result<(), AlertError> {
        if self.alert_id.is_empty() {
            return Err(AlertError::EmptyField("alert_id"));
        }
        if self.summary.trim().is_empty() {
            return Err(AlertError::EmptyField("summary"));
        }
        if self.severity == Severity::Critical && !self.has_primary_link() {
            return Err(AlertError::CriticalWithoutLink);
        }
        Ok(())
    }

    /// The dedupe key for this alert under `window_secs`. The time bucket is
    /// taken from the alert's own `ts`, so a late or retried alert lands in
    /// the same bucket as the original. Missing facts fall back to the
    /// alert id, which only dedupes exact repeats.
    pub fn dedupe_key(&self, window_secs: u32) -> (String, i64) {
        let window_ms = i64::from(window_secs.max(1)) * 1000;
        let bucket = self.ts.div_euclid(window_ms);
        let fallback = self.alert_id.as_str();
        let facts = match self.alert_type.dedupe_basis() {
            DedupeBasis::SrcCve => format!(
                "{}|{}",
                self.src_ip.as_deref().unwrap_or(fallback),
                self.cve_id.as_deref().unwrap_or("-")
            ),
            DedupeBasis::Campaign => self.campaign_id.as_deref().unwrap_or(fallback).to_owned(),
            DedupeBasis::DecoyType => self.decoy_id.as_deref().unwrap_or(fallback).to_owned(),
            DedupeBasis::Subject => self.subject.as_deref().unwrap_or(fallback).to_owned(),
        };
        (format!("{}|{facts}|{bucket}", self.alert_type), bucket)
    }
}

/// Alerts raised by one attempt (#25). One page per attempt at most:
///
/// - probe only: nothing;
/// - exploit with a hook hit: one `vuln_path_hook_fired` (high);
/// - post-exploitation: one `decoy_compromised` (high). A hook hit on the
///   same attempt is still reported as `vuln_path_hook_fired`, demoted to
///   medium because the page has gone out, so it lands in the review queue
///   as a CVE assess-as candidate (#35) instead of paging twice.
///
/// Exploit state reached only through matchers raises nothing here; the
/// confidence layer raises `cve_assessed` for those (#12).
pub fn alerts_from_attempt(attempt: &Attempt) -> Vec<Alert> {
    let mut out = Vec::new();
    let links = vec![
        Link {
            kind: LinkKind::Attempt,
            href: format!("/attempts/{}", attempt.attempt_id),
        },
        Link {
            kind: LinkKind::Decoy,
            href: format!("/decoys/{}", attempt.decoy_id),
        },
    ];
    let base = |alert_type: AlertType, severity: Severity, ts: i64, summary: String| Alert {
        alert_id: Alert::make_id(alert_type, &[&attempt.tenant_id, &attempt.attempt_id]),
        ts,
        severity,
        alert_type,
        decoy_id: Some(attempt.decoy_id.clone()),
        attempt_id: Some(attempt.attempt_id.clone()),
        campaign_id: attempt.campaign_id.clone(),
        summary,
        links: links.clone(),
        src_ip: Some(attempt.src.clone()),
        cve_id: None,
        subject: None,
    };

    let compromised = attempt.state == AttemptState::PostExploitation;
    if compromised {
        let change = attempt
            .state_history
            .iter()
            .find(|c| c.state == AttemptState::PostExploitation);
        let (ts, signal) = change.map_or((attempt.last_seen, String::from("unknown")), |c| {
            (c.at, format!("{:?}", c.signal))
        });
        let summary = format!(
            "Decoy {} reached post-exploitation from {} (signal: {}, catalogue {})",
            attempt.decoy_id, attempt.src, signal, attempt.catalogue_id
        );
        out.push(base(
            AlertType::DecoyCompromised,
            AlertType::DecoyCompromised.default_severity(),
            ts,
            summary,
        ));
    }

    let triggers: Vec<&HookHit> = attempt
        .hook_hits
        .iter()
        .filter(|h| h.stage == HookStage::Trigger)
        .collect();
    if let Some(first) = triggers.first() {
        let cves: BTreeSet<&str> = triggers
            .iter()
            .filter_map(|h| h.cve_id.as_deref())
            .collect();
        let cve_text = if cves.is_empty() {
            String::from("no CVE linked")
        } else {
            cves.into_iter().collect::<Vec<_>>().join(", ")
        };
        let severity = if compromised {
            Severity::Medium
        } else {
            AlertType::VulnPathHookFired.default_severity()
        };
        let mut alert = base(
            AlertType::VulnPathHookFired,
            severity,
            first.ts,
            format!(
                "Hook {} fired on decoy {} from {} ({cve_text})",
                first.hook_id, attempt.decoy_id, attempt.src
            ),
        );
        alert.cve_id = first.cve_id.clone();
        out.push(alert);
    }
    out
}

/// Hex HMAC-SHA256 of `body` under `secret`, sent as `X-Foiled-Signature`.
pub fn sign_webhook(secret: &[u8], body: &[u8]) -> String {
    let mut mac = Hmac::<Sha256>::new_from_slice(secret).expect("HMAC takes any key length");
    mac.update(body);
    hex::encode(mac.finalize().into_bytes())
}

// ---------------------------------------------------------------------------
// Dedupe and rate limits

/// Remembers dedupe keys until they expire. Memory is bounded: when full,
/// expired keys go first, then the key closest to expiry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Deduper {
    max_keys: usize,
    expiry_by_key: BTreeMap<String, i64>,
    by_expiry: BTreeSet<(i64, String)>,
}

impl Deduper {
    pub fn new(max_keys: usize) -> Self {
        Self {
            max_keys: max_keys.max(1),
            expiry_by_key: BTreeMap::new(),
            by_expiry: BTreeSet::new(),
        }
    }

    pub fn len(&self) -> usize {
        self.expiry_by_key.len()
    }

    pub fn is_empty(&self) -> bool {
        self.expiry_by_key.is_empty()
    }

    fn remove(&mut self, key: &str) {
        if let Some(exp) = self.expiry_by_key.remove(key) {
            self.by_expiry.remove(&(exp, key.to_owned()));
        }
    }

    fn purge_expired(&mut self, now: i64) {
        while let Some((exp, key)) = self.by_expiry.first().cloned() {
            if exp > now {
                break;
            }
            self.by_expiry.pop_first();
            self.expiry_by_key.remove(&key);
        }
    }

    /// Returns `true` the first time `key` is seen before it expires, and
    /// records it until `expires_at`. Returns `false` for a duplicate.
    pub fn check(&mut self, key: &str, expires_at: i64, now: i64) -> bool {
        self.purge_expired(now);
        if self.expiry_by_key.contains_key(key) {
            return false;
        }
        if expires_at <= now {
            return true;
        }
        while self.expiry_by_key.len() >= self.max_keys {
            match self.by_expiry.pop_first() {
                Some((_, evict)) => {
                    self.expiry_by_key.remove(&evict);
                }
                None => break,
            }
        }
        self.remove(key);
        self.expiry_by_key.insert(key.to_owned(), expires_at);
        self.by_expiry.insert((expires_at, key.to_owned()));
        true
    }
}

/// A token bucket limit: `burst` tokens, refilled at `per_hour`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RateLimit {
    pub burst: u32,
    pub per_hour: u32,
}

/// Integer token bucket. Starts full. Time only moves forward: a `now`
/// earlier than the last refill adds nothing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TokenBucket {
    capacity: u32,
    tokens: u32,
    /// Milliseconds per token; 0 means no refill.
    refill_every_ms: i64,
    last_refill: i64,
}

impl TokenBucket {
    pub fn new(limit: RateLimit, now: i64) -> Self {
        let refill_every_ms = if limit.per_hour == 0 {
            0
        } else {
            (3_600_000 / i64::from(limit.per_hour)).max(1)
        };
        Self {
            capacity: limit.burst,
            tokens: limit.burst,
            refill_every_ms,
            last_refill: now,
        }
    }

    pub fn tokens(&self) -> u32 {
        self.tokens
    }

    fn refill(&mut self, now: i64) {
        if self.refill_every_ms == 0 || now <= self.last_refill {
            return;
        }
        let earned = (now - self.last_refill) / self.refill_every_ms;
        if earned == 0 {
            return;
        }
        let tokens = u64::from(self.tokens).saturating_add(earned as u64);
        self.tokens = tokens.min(u64::from(self.capacity)) as u32;
        if self.tokens == self.capacity {
            self.last_refill = now;
        } else {
            self.last_refill += earned * self.refill_every_ms;
        }
    }

    /// Takes one token if one is available at `now`.
    pub fn try_take(&mut self, now: i64) -> bool {
        self.refill(now);
        if self.tokens == 0 {
            return false;
        }
        self.tokens -= 1;
        true
    }
}

// ---------------------------------------------------------------------------
// Config (`configs/alerting.yaml`)

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RouteKind {
    /// Generic JSON webhook, signed with `X-Foiled-Signature`.
    Webhook,
    /// Slack-compatible incoming webhook (`{"text": ...}`).
    SlackWebhook,
    /// Email through an operator SMTP relay. Documented, not delivered yet.
    Email,
    /// Structured log line on the control plane.
    Log,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouteConfig {
    pub id: String,
    pub kind: RouteKind,
    #[serde(default = "default_true")]
    pub enabled: bool,
    pub min_severity: Severity,
    /// Only these types, when set. Empty means every type.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub types: Vec<AlertType>,
    /// Name of the Worker secret holding the webhook URL. Name only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url_env: Option<String>,
    /// Name of the Worker secret holding the HMAC key. Name only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signing_secret_env: Option<String>,
    /// Name of the Worker secret holding the SMTP relay URL and credentials.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub smtp_relay_env: Option<String>,
    /// Name of the variable holding the recipient list.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub to_env: Option<String>,
    /// Per-route token bucket. None means unlimited (log sink).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rate_limit: Option<RateLimit>,
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DedupeConfig {
    #[serde(default = "default_max_keys")]
    pub max_keys: usize,
    /// Window in seconds per type; types not listed use their default.
    #[serde(default)]
    pub windows: BTreeMap<AlertType, u32>,
}

fn default_max_keys() -> usize {
    DEFAULT_DEDUPE_MAX_KEYS
}

impl Default for DedupeConfig {
    fn default() -> Self {
        Self {
            max_keys: DEFAULT_DEDUPE_MAX_KEYS,
            windows: BTreeMap::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AlertingConfig {
    pub version: u32,
    /// Console origin used to make link paths absolute.
    pub console_base_url: String,
    /// Send medium alerts to the review queue (#35) instead of routes.
    #[serde(default)]
    pub review_queue_for_medium: bool,
    pub routes: Vec<RouteConfig>,
    #[serde(default)]
    pub severity_overrides: BTreeMap<AlertType, Severity>,
    #[serde(default)]
    pub dedupe: DedupeConfig,
    /// Per-type caps; types not listed use [`DEFAULT_TYPE_LIMIT`].
    #[serde(default)]
    pub type_limits: BTreeMap<AlertType, RateLimit>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfigError {
    Version(u32),
    ConsoleUrl,
    RouteId(String),
    DuplicateRoute(String),
    MissingField { route: String, field: &'static str },
    EnvName { route: String, value: String },
    EmailNotImplemented(String),
    ZeroBurst(String),
    Window(AlertType),
    MaxKeys,
    NoLogSink,
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ConfigError::Version(v) => write!(f, "unsupported alerting config version {v}"),
            ConfigError::ConsoleUrl => f.write_str(
                "console_base_url must be an https:// origin with no credentials or query",
            ),
            ConfigError::RouteId(id) => write!(f, "route id `{id}` must match [a-z0-9][a-z0-9_-]*"),
            ConfigError::DuplicateRoute(id) => write!(f, "route id `{id}` is used twice"),
            ConfigError::MissingField { route, field } => {
                write!(f, "route `{route}` needs `{field}`")
            }
            ConfigError::EnvName { route, value } => write!(
                f,
                "route `{route}`: `{value}` is not an environment variable name; put the secret in a Worker secret and name it here"
            ),
            ConfigError::EmailNotImplemented(id) => write!(
                f,
                "route `{id}`: email delivery is not implemented yet (#15), keep it disabled"
            ),
            ConfigError::ZeroBurst(at) => write!(f, "{at}: rate limit burst must be at least 1"),
            ConfigError::Window(t) => write!(
                f,
                "dedupe window for `{t}` must be at least {MIN_DEDUPE_WINDOW_SECS} seconds"
            ),
            ConfigError::MaxKeys => f.write_str("dedupe.max_keys must be at least 1"),
            ConfigError::NoLogSink => f.write_str("at least one enabled `log` route is required"),
        }
    }
}

impl std::error::Error for ConfigError {}

/// Upper case letters, digits and `_`, not starting with a digit. A pasted
/// URL or token fails this rule.
pub fn is_env_name(name: &str) -> bool {
    !name.is_empty()
        && name.starts_with(|c: char| c.is_ascii_uppercase() || c == '_')
        && name
            .chars()
            .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_')
}

fn is_route_id(id: &str) -> bool {
    id.starts_with(|c: char| c.is_ascii_lowercase() || c.is_ascii_digit())
        && id
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' || c == '-')
}

impl AlertingConfig {
    pub fn severity_for(&self, t: AlertType) -> Severity {
        self.severity_overrides
            .get(&t)
            .copied()
            .unwrap_or_else(|| t.default_severity())
    }

    pub fn window_secs_for(&self, t: AlertType) -> u32 {
        self.dedupe
            .windows
            .get(&t)
            .copied()
            .unwrap_or_else(|| t.default_window_secs())
    }

    pub fn type_limit_for(&self, t: AlertType) -> RateLimit {
        self.type_limits
            .get(&t)
            .copied()
            .unwrap_or(DEFAULT_TYPE_LIMIT)
    }

    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.version != 1 {
            return Err(ConfigError::Version(self.version));
        }
        let url = &self.console_base_url;
        let rest = url.strip_prefix("https://").unwrap_or("");
        if rest.is_empty() || rest.contains(['@', '?', '#', ' ']) {
            return Err(ConfigError::ConsoleUrl);
        }
        let mut seen = BTreeSet::new();
        for r in &self.routes {
            if !is_route_id(&r.id) {
                return Err(ConfigError::RouteId(r.id.clone()));
            }
            if !seen.insert(r.id.as_str()) {
                return Err(ConfigError::DuplicateRoute(r.id.clone()));
            }
            let required: &[(&'static str, &Option<String>)] = match r.kind {
                RouteKind::Webhook => &[
                    ("url_env", &r.url_env),
                    ("signing_secret_env", &r.signing_secret_env),
                ],
                RouteKind::SlackWebhook => &[("url_env", &r.url_env)],
                RouteKind::Email => &[("smtp_relay_env", &r.smtp_relay_env), ("to_env", &r.to_env)],
                RouteKind::Log => &[],
            };
            for (field, value) in required {
                if value.is_none() {
                    return Err(ConfigError::MissingField {
                        route: r.id.clone(),
                        field,
                    });
                }
            }
            for value in [
                &r.url_env,
                &r.signing_secret_env,
                &r.smtp_relay_env,
                &r.to_env,
            ]
            .into_iter()
            .flatten()
            {
                if !is_env_name(value) {
                    return Err(ConfigError::EnvName {
                        route: r.id.clone(),
                        value: value.clone(),
                    });
                }
            }
            if r.kind == RouteKind::Email && r.enabled {
                return Err(ConfigError::EmailNotImplemented(r.id.clone()));
            }
            if r.rate_limit.is_some_and(|l| l.burst == 0) {
                return Err(ConfigError::ZeroBurst(format!("route `{}`", r.id)));
            }
        }
        if !self
            .routes
            .iter()
            .any(|r| r.enabled && r.kind == RouteKind::Log)
        {
            return Err(ConfigError::NoLogSink);
        }
        if self.dedupe.max_keys == 0 {
            return Err(ConfigError::MaxKeys);
        }
        for (t, w) in &self.dedupe.windows {
            if *w < MIN_DEDUPE_WINDOW_SECS {
                return Err(ConfigError::Window(*t));
            }
        }
        for (t, l) in &self.type_limits {
            if l.burst == 0 {
                return Err(ConfigError::ZeroBurst(format!("type `{t}`")));
            }
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Router

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SuppressReason {
    /// Same dedupe key already seen in the window.
    Duplicate,
    /// The per-type cap is empty.
    TypeRateLimited,
    /// Every matching route's bucket is empty.
    RouteRateLimited,
    /// No enabled route accepts this type and severity.
    NoRoute,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Decision {
    /// Deliver to these route ids.
    Send(Vec<String>),
    /// Do not deliver. The decision is still logged.
    Suppressed { reason: SuppressReason },
    /// Create or update a review queue item (#35) instead of paging.
    ToReviewQueue,
}

/// Holds dedupe and rate limit state for one tenant. The control plane keeps
/// one per tenant in a Durable Object so every delivery worker shares it,
/// and persists it (serde) so an eviction does not reset dedupe or buckets.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Router {
    config: AlertingConfig,
    deduper: Deduper,
    route_buckets: BTreeMap<String, TokenBucket>,
    type_buckets: BTreeMap<AlertType, TokenBucket>,
}

impl Router {
    pub fn new(config: AlertingConfig, now: i64) -> Result<Self, ConfigError> {
        config.validate()?;
        let route_buckets = config
            .routes
            .iter()
            .filter_map(|r| {
                r.rate_limit
                    .map(|l| (r.id.clone(), TokenBucket::new(l, now)))
            })
            .collect();
        let type_buckets = AlertType::ALL
            .iter()
            .map(|t| (*t, TokenBucket::new(config.type_limit_for(*t), now)))
            .collect();
        Ok(Self {
            deduper: Deduper::new(config.dedupe.max_keys),
            config,
            route_buckets,
            type_buckets,
        })
    }

    pub fn config(&self) -> &AlertingConfig {
        &self.config
    }

    /// Decide what happens to `alert` at `now`. A configured severity
    /// override for the type replaces the producer's severity first, so the
    /// caller sends the effective severity. Order: dedupe, review queue
    /// fallback for medium, per-type cap, then per-route buckets. Critical
    /// alerts are deduped but never rate limited.
    pub fn route(&mut self, alert: &mut Alert, now: i64) -> Decision {
        if let Some(s) = self.config.severity_overrides.get(&alert.alert_type) {
            alert.severity = *s;
        }
        let severity = alert.severity;
        let critical = severity == Severity::Critical;

        let window = self.config.window_secs_for(alert.alert_type);
        let (key, bucket) = alert.dedupe_key(window);
        let window_ms = i64::from(window) * 1000;
        // Keep the key for one extra window to absorb late and retried alerts.
        let expires_at = ((bucket + 1) * window_ms).max(now) + window_ms;
        if !self.deduper.check(&key, expires_at, now) {
            return Decision::Suppressed {
                reason: SuppressReason::Duplicate,
            };
        }

        if severity == Severity::Medium
            && self.config.review_queue_for_medium
            && alert.alert_type != AlertType::ReviewQueueItem
        {
            return Decision::ToReviewQueue;
        }

        let matching: Vec<&RouteConfig> = self
            .config
            .routes
            .iter()
            .filter(|r| {
                r.enabled
                    && severity >= r.min_severity
                    && (r.types.is_empty() || r.types.contains(&alert.alert_type))
            })
            .collect();
        if matching.is_empty() {
            return Decision::Suppressed {
                reason: SuppressReason::NoRoute,
            };
        }

        if !critical {
            let bucket = self
                .type_buckets
                .get_mut(&alert.alert_type)
                .expect("a bucket per type");
            if !bucket.try_take(now) {
                return Decision::Suppressed {
                    reason: SuppressReason::TypeRateLimited,
                };
            }
        }

        let mut send = Vec::new();
        for r in matching {
            let allowed = critical
                || match self.route_buckets.get_mut(&r.id) {
                    Some(b) => b.try_take(now),
                    None => true,
                };
            if allowed {
                send.push(r.id.clone());
            }
        }
        if send.is_empty() {
            Decision::Suppressed {
                reason: SuppressReason::RouteRateLimited,
            }
        } else {
            Decision::Send(send)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::attempt::{self, DEFAULT_IDLE_GAP_MS, ExtraSignals};
    use crate::capture::CaptureEvent;
    use serde_json::json;

    const T0: i64 = 1_792_285_323_000;
    const HOUR_MS: i64 = 3_600_000;

    fn ev(id: &str, ts: i64, decoy: &str, src: &str, channel: &str) -> serde_json::Value {
        json!({
            "event_id": id, "ts": ts, "decoy_id": decoy, "catalogue_id": "foiled/demo-app/1.0.0",
            "decoy_kind": "sandbox", "channel": channel, "severity": "info",
            "src": {"ip": src}, "tenant_id": "t1",
            "source": {"kind": "host", "id": "host-1"}, "data": {}
        })
    }

    fn hook(id: &str, ts: i64, decoy: &str, src: &str, stage: &str) -> serde_json::Value {
        let mut v = ev(id, ts, decoy, src, "hook");
        v["hook"] = json!({"hook_id": "demo-app.upload-path-traversal", "catalogue_id": "foiled/demo-app/1.0.0",
            "cve_id": "FOILED-DEMO-0001", "stage": stage, "sequence_no": 1, "t_offset_ms": 0});
        v
    }

    fn attempts(vs: Vec<serde_json::Value>) -> Vec<Attempt> {
        let events: Vec<CaptureEvent> = vs
            .into_iter()
            .map(|v| serde_json::from_value(v).unwrap())
            .collect();
        attempt::build(&events, DEFAULT_IDLE_GAP_MS, &ExtraSignals::new())
    }

    fn route(kind: RouteKind, id: &str, min: Severity, limit: Option<RateLimit>) -> RouteConfig {
        RouteConfig {
            id: id.into(),
            kind,
            enabled: true,
            min_severity: min,
            types: vec![],
            url_env: None,
            signing_secret_env: None,
            smtp_relay_env: None,
            to_env: None,
            rate_limit: limit,
        }
    }

    fn config() -> AlertingConfig {
        let mut webhook = route(
            RouteKind::Webhook,
            "ops-webhook",
            Severity::High,
            Some(RateLimit {
                burst: 10,
                per_hour: 30,
            }),
        );
        webhook.url_env = Some("FOILED_ALERT_WEBHOOK_URL".into());
        webhook.signing_secret_env = Some("FOILED_ALERT_WEBHOOK_SECRET".into());
        AlertingConfig {
            version: 1,
            console_base_url: "https://foiled.example.com".into(),
            review_queue_for_medium: true,
            routes: vec![route(RouteKind::Log, "log", Severity::Info, None), webhook],
            severity_overrides: BTreeMap::new(),
            dedupe: DedupeConfig::default(),
            type_limits: BTreeMap::new(),
        }
    }

    fn alert(t: AlertType, ts: i64) -> Alert {
        Alert {
            alert_id: Alert::make_id(t, &[&ts.to_string()]),
            ts,
            severity: t.default_severity(),
            alert_type: t,
            decoy_id: Some("dcy-demo-1".into()),
            attempt_id: Some("att_demo".into()),
            campaign_id: None,
            summary: "example".into(),
            links: vec![Link {
                kind: LinkKind::Attempt,
                href: "/attempts/att_demo".into(),
            }],
            src_ip: Some("203.0.113.7".into()),
            cve_id: Some("CVE-2099-0001".into()),
            subject: Some("host-demo-1".into()),
        }
    }

    #[test]
    fn hmac_rfc4231_case_2() {
        assert_eq!(
            sign_webhook(b"Jefe", b"what do ya want for nothing?"),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
    }

    #[test]
    fn issue_types_have_documented_severities() {
        use AlertType::*;
        assert_eq!(CanaryUsed.default_severity(), Severity::Critical);
        assert_eq!(RotationFailed.default_severity(), Severity::Critical);
        assert_eq!(VulnPathHookFired.default_severity(), Severity::High);
        assert_eq!(DecoyCompromised.default_severity(), Severity::High);
        assert_eq!(HoneyscoreHigh.default_severity(), Severity::Medium);
        assert_eq!(DecoyRotated.default_severity(), Severity::Info);
        for t in AlertType::ALL {
            let s = serde_json::to_value(t).unwrap();
            assert_eq!(s, json!(t.as_str()));
        }
    }

    #[test]
    fn probe_only_attempt_raises_nothing() {
        let a = attempts(vec![ev("e1", T0, "d1", "198.51.100.9", "application")]);
        assert!(alerts_from_attempt(&a[0]).is_empty());
    }

    #[test]
    fn hook_trigger_without_post_exploit_is_one_high_alert() {
        let a = attempts(vec![
            ev("e1", T0, "d1", "203.0.113.7", "application"),
            hook("e2", T0 + 1000, "d1", "203.0.113.7", "trigger"),
        ]);
        let alerts = alerts_from_attempt(&a[0]);
        assert_eq!(alerts.len(), 1);
        let al = &alerts[0];
        assert_eq!(al.alert_type, AlertType::VulnPathHookFired);
        assert_eq!(al.severity, Severity::High);
        assert_eq!(al.cve_id.as_deref(), Some("FOILED-DEMO-0001"));
        assert_eq!(al.ts, T0 + 1000);
        assert!(al.has_primary_link());
        al.validate().unwrap();
        // Deterministic ids: the same attempt raises the same alert ids.
        assert_eq!(alerts, alerts_from_attempt(&a[0]));
    }

    #[test]
    fn tabletop_100_scanner_probes_give_bounded_alerts() {
        // 100 scanner hits from 20 sources across 5 decoys in ten minutes.
        let events: Vec<_> = (0..100)
            .map(|i| {
                ev(
                    &format!("e{i}"),
                    T0 + i * 6000,
                    &format!("d{}", i % 5),
                    &format!("198.51.100.{}", i % 20),
                    "application",
                )
            })
            .collect();
        let atts = attempts(events);
        assert!(atts.len() > 1);
        let mut router = Router::new(config(), T0).unwrap();
        let mut sent = 0;
        for a in &atts {
            for mut al in alerts_from_attempt(a) {
                if matches!(router.route(&mut al, T0), Decision::Send(_)) {
                    sent += 1;
                }
            }
        }
        // N = 0: probes never page.
        assert_eq!(sent, 0);
    }

    #[test]
    fn tabletop_100_mass_exploit_hits_are_bounded() {
        // Worst case: every one of 100 scanner hits fires the hook, from 100
        // different sources, within one hour.
        let events: Vec<_> = (0..100)
            .map(|i| {
                hook(
                    &format!("e{i}"),
                    T0 + i * 1000,
                    &format!("d{}", i % 5),
                    &format!("198.51.100.{i}"),
                    "trigger",
                )
            })
            .collect();
        let atts = attempts(events);
        assert_eq!(atts.len(), 100);
        let mut router = Router::new(config(), T0).unwrap();
        let mut sent = 0;
        let mut suppressed = 0;
        for a in &atts {
            for mut al in alerts_from_attempt(a) {
                match router.route(&mut al, a.last_seen) {
                    Decision::Send(_) => sent += 1,
                    Decision::Suppressed { .. } => suppressed += 1,
                    Decision::ToReviewQueue => panic!("high alerts do not go to the queue"),
                }
            }
        }
        // 100 s is too short for a refill (one token per 180 s), so the
        // per-type burst is the bound.
        let n = DEFAULT_TYPE_LIMIT.burst as usize;
        assert_eq!(sent, n, "bound {n}");
        assert_eq!(sent + suppressed, 100);

        // One source sending the same CVE to 100 decoys over 31 minutes,
        // inside one clock hour (T0 is 123 s past the hour): one alert.
        let events: Vec<_> = (0..100)
            .map(|i| {
                hook(
                    &format!("r{i}"),
                    T0 + i * 31 * 60 * 1000 / 100,
                    &format!("d{i}"),
                    "203.0.113.50",
                    "trigger",
                )
            })
            .collect();
        let mut router = Router::new(config(), T0).unwrap();
        let mut sent = 0;
        for a in &attempts(events) {
            for mut al in alerts_from_attempt(a) {
                if matches!(router.route(&mut al, a.last_seen), Decision::Send(_)) {
                    sent += 1;
                }
            }
        }
        assert_eq!(T0 % HOUR_MS, 123_000);
        assert_eq!(sent, 1);
    }

    #[test]
    fn tabletop_single_exploit_chain_is_one_high_alert_and_a_queue_item() {
        let mut egress = ev("e4", T0 + 3000, "d1", "10.85.1.2", "egress");
        egress["dst"] = json!({"ip": "192.0.2.80", "port": 80});
        let a = attempts(vec![
            ev("e1", T0, "d1", "203.0.113.7", "application"),
            hook("e2", T0 + 1000, "d1", "203.0.113.7", "trigger"),
            hook("e3", T0 + 2000, "d1", "203.0.113.7", "post_exploit"),
            egress,
        ]);
        assert_eq!(a.len(), 1);
        let alerts = alerts_from_attempt(&a[0]);
        let mut router = Router::new(config(), T0).unwrap();
        let mut sends = Vec::new();
        let mut queued = Vec::new();
        for mut al in alerts {
            match router.route(&mut al, T0 + 5000) {
                Decision::Send(r) => sends.push((al, r)),
                Decision::ToReviewQueue => queued.push(al),
                Decision::Suppressed { reason } => panic!("suppressed: {reason:?}"),
            }
        }
        assert_eq!(sends.len(), 1, "exactly one page");
        let (high, routes) = &sends[0];
        assert_eq!(high.alert_type, AlertType::DecoyCompromised);
        assert_eq!(high.severity, Severity::High);
        assert_eq!(routes, &vec!["log".to_string(), "ops-webhook".to_string()]);
        assert_eq!(queued.len(), 1);
        assert_eq!(queued[0].alert_type, AlertType::VulnPathHookFired);
        assert_eq!(queued[0].severity, Severity::Medium);
        // Every alert in the chain links to the console attempt.
        let path = format!("/attempts/{}", a[0].attempt_id);
        assert!(high.links.iter().any(|l| l.href == path));
        assert!(queued[0].links.iter().any(|l| l.href == path));
    }

    #[test]
    fn critical_alerts_need_a_primary_link() {
        let mut al = alert(AlertType::RotationFailed, T0);
        al.validate().unwrap();
        al.links = vec![Link {
            kind: LinkKind::Decoy,
            href: "/decoys/dcy-demo-1".into(),
        }];
        assert_eq!(al.validate(), Err(AlertError::CriticalWithoutLink));
        al.links.push(Link {
            kind: LinkKind::QueueItem,
            href: "/review-queue/rq_demo".into(),
        });
        al.validate().unwrap();
    }

    #[test]
    fn critical_alerts_are_deduped_but_not_rate_limited() {
        let mut cfg = config();
        cfg.routes[1].rate_limit = Some(RateLimit {
            burst: 1,
            per_hour: 0,
        });
        let mut router = Router::new(cfg, T0).unwrap();
        for i in 0..20 {
            let mut al = alert(AlertType::CanaryUsed, T0);
            al.decoy_id = Some(format!("dcy-{i}"));
            assert_eq!(
                router.route(&mut al, T0),
                Decision::Send(vec!["log".into(), "ops-webhook".into()])
            );
        }
        let mut again = alert(AlertType::CanaryUsed, T0);
        again.decoy_id = Some("dcy-0".into());
        assert_eq!(
            router.route(&mut again, T0 + 1),
            Decision::Suppressed {
                reason: SuppressReason::Duplicate
            }
        );
    }

    #[test]
    fn router_state_survives_a_persist_and_restore() {
        let mut router = Router::new(config(), T0).unwrap();
        let mut al = alert(AlertType::YaraMatch, T0);
        assert!(matches!(router.route(&mut al, T0), Decision::Send(_)));
        let saved = serde_json::to_string(&router).unwrap();
        let mut restored: Router = serde_json::from_str(&saved).unwrap();
        assert_eq!(
            restored.route(&mut al, T0 + 1),
            Decision::Suppressed {
                reason: SuppressReason::Duplicate
            }
        );
    }

    #[test]
    fn dedupe_keys_follow_the_documented_facts() {
        let a = alert(AlertType::VulnPathHookFired, T0);
        let (k, _) = a.dedupe_key(3600);
        assert!(k.starts_with("vuln_path_hook_fired|203.0.113.7|CVE-2099-0001|"));
        let mut c = alert(AlertType::CampaignUpdated, T0);
        c.campaign_id = Some("cmp_demo".into());
        let (k, day) = c.dedupe_key(86_400);
        assert_eq!(k, format!("campaign_updated|cmp_demo|{day}"));
        let d = alert(AlertType::YaraMatch, T0);
        assert!(d.dedupe_key(3600).0.starts_with("yara_match|dcy-demo-1|"));
        let h = alert(AlertType::HostOffline, T0);
        assert!(
            h.dedupe_key(3600)
                .0
                .starts_with("host_offline|host-demo-1|")
        );
    }

    #[test]
    fn campaign_updates_dedupe_per_day_and_medium_goes_to_queue() {
        let mut router = Router::new(config(), T0).unwrap();
        let mut first = alert(AlertType::CampaignUpdated, T0);
        first.campaign_id = Some("cmp_demo".into());
        assert_eq!(router.route(&mut first, T0), Decision::ToReviewQueue);
        let mut later = first.clone();
        later.ts = T0 + HOUR_MS;
        assert_eq!(
            router.route(&mut later, T0 + HOUR_MS),
            Decision::Suppressed {
                reason: SuppressReason::Duplicate
            }
        );
        // Without the fallback, medium goes to routes with min_severity <= medium.
        let mut cfg = config();
        cfg.review_queue_for_medium = false;
        let mut router = Router::new(cfg, T0).unwrap();
        let mut m = first.clone();
        assert_eq!(router.route(&mut m, T0), Decision::Send(vec!["log".into()]));
    }

    #[test]
    fn severity_overrides_apply_before_routing() {
        let mut cfg = config();
        cfg.severity_overrides
            .insert(AlertType::CaptureDiskPressure, Severity::Critical);
        cfg.severity_overrides
            .insert(AlertType::DecoyRotated, Severity::Low);
        let mut router = Router::new(cfg, T0).unwrap();
        let mut al = alert(AlertType::CaptureDiskPressure, T0);
        assert!(matches!(router.route(&mut al, T0), Decision::Send(r) if r.len() == 2));
        assert_eq!(al.severity, Severity::Critical);
        let mut info = alert(AlertType::DecoyRotated, T0);
        assert_eq!(
            router.route(&mut info, T0),
            Decision::Send(vec!["log".into()])
        );
        assert_eq!(info.severity, Severity::Low);
    }

    #[test]
    fn no_matching_route_is_suppressed() {
        let mut cfg = config();
        cfg.routes[0].min_severity = Severity::High;
        let mut router = Router::new(cfg, T0).unwrap();
        let mut al = alert(AlertType::ReviewQueueItem, T0);
        assert_eq!(
            router.route(&mut al, T0),
            Decision::Suppressed {
                reason: SuppressReason::NoRoute
            }
        );
    }

    #[test]
    fn route_buckets_limit_each_route_separately() {
        let mut cfg = config();
        cfg.routes[1].rate_limit = Some(RateLimit {
            burst: 2,
            per_hour: 0,
        });
        cfg.type_limits.insert(
            AlertType::YaraMatch,
            RateLimit {
                burst: 100,
                per_hour: 0,
            },
        );
        let mut router = Router::new(cfg, T0).unwrap();
        let mut results = Vec::new();
        for i in 0..4 {
            let mut al = alert(AlertType::YaraMatch, T0);
            al.decoy_id = Some(format!("dcy-{i}"));
            results.push(router.route(&mut al, T0));
        }
        let two = Decision::Send(vec!["log".into(), "ops-webhook".into()]);
        let one = Decision::Send(vec!["log".into()]);
        assert_eq!(results, vec![two.clone(), two, one.clone(), one]);
    }

    #[test]
    fn token_bucket_refills_with_time_only_forward() {
        let mut b = TokenBucket::new(
            RateLimit {
                burst: 2,
                per_hour: 60,
            },
            T0,
        );
        assert!(b.try_take(T0));
        assert!(b.try_take(T0));
        assert!(!b.try_take(T0));
        assert!(!b.try_take(T0 - HOUR_MS), "time going back adds nothing");
        assert!(!b.try_take(T0 + 59_999));
        assert!(b.try_take(T0 + 60_000));
        assert!(!b.try_take(T0 + 60_000));
        // A long gap refills to capacity, not beyond.
        assert!(b.try_take(T0 + 10 * HOUR_MS));
        assert!(b.try_take(T0 + 10 * HOUR_MS));
        assert!(!b.try_take(T0 + 10 * HOUR_MS));
        let mut never = TokenBucket::new(
            RateLimit {
                burst: 1,
                per_hour: 0,
            },
            T0,
        );
        assert!(never.try_take(T0));
        assert!(!never.try_take(T0 + 100 * HOUR_MS));
    }

    #[test]
    fn deduper_expires_and_stays_bounded() {
        let mut d = Deduper::new(3);
        assert!(d.check("a", T0 + 10, T0));
        assert!(!d.check("a", T0 + 10, T0 + 5));
        assert!(d.check("a", T0 + 20, T0 + 10), "expired keys are new again");
        assert!(d.check("b", T0 + 30, T0 + 10));
        assert!(d.check("c", T0 + 40, T0 + 10));
        assert!(d.check("d", T0 + 50, T0 + 10));
        assert_eq!(d.len(), 3, "bounded");
        // `a` was closest to expiry and was evicted.
        assert!(d.check("a", T0 + 20, T0 + 11));
        assert!(!d.check("d", T0 + 50, T0 + 11));
        for i in 0..1000 {
            d.check(&format!("k{i}"), T0 + 1000 + i, T0 + 12);
        }
        assert_eq!(d.len(), 3);
        assert!(
            d.check("late", T0, T0 + 12),
            "already expired is not stored"
        );
        assert!(d.check("late", T0, T0 + 12));
    }

    #[test]
    fn config_validation_rejects_secrets_and_bad_routes() {
        config().validate().unwrap();
        let mut c = config();
        c.routes[1].url_env = Some("https://hooks.example.com/T000/B000/XXXX".into());
        assert!(matches!(c.validate(), Err(ConfigError::EnvName { .. })));
        let mut c = config();
        c.routes[1].signing_secret_env = None;
        assert!(matches!(
            c.validate(),
            Err(ConfigError::MissingField { .. })
        ));
        let mut c = config();
        c.routes.remove(0);
        assert_eq!(c.validate(), Err(ConfigError::NoLogSink));
        let mut c = config();
        let mut email = route(RouteKind::Email, "email", Severity::High, None);
        email.smtp_relay_env = Some("FOILED_SMTP_RELAY".into());
        email.to_env = Some("FOILED_ALERT_EMAIL_TO".into());
        c.routes.push(email);
        assert!(matches!(
            c.validate(),
            Err(ConfigError::EmailNotImplemented(_))
        ));
        c.routes[2].enabled = false;
        c.validate().unwrap();
        let mut c = config();
        c.console_base_url = "https://user:pw@foiled.example.com".into();
        assert_eq!(c.validate(), Err(ConfigError::ConsoleUrl));
        let mut c = config();
        c.dedupe.windows.insert(AlertType::YaraMatch, 10);
        assert_eq!(c.validate(), Err(ConfigError::Window(AlertType::YaraMatch)));
        let mut c = config();
        c.routes.push(c.routes[0].clone());
        assert!(matches!(c.validate(), Err(ConfigError::DuplicateRoute(_))));
    }

    #[test]
    fn alert_json_shape() {
        let al = alert(AlertType::VulnPathHookFired, T0);
        let v = serde_json::to_value(&al).unwrap();
        assert_eq!(v["type"], "vuln_path_hook_fired");
        assert_eq!(v["severity"], "high");
        assert!(v.get("campaign_id").is_none());
        let back: Alert = serde_json::from_value(v).unwrap();
        assert_eq!(back, al);
    }
}
