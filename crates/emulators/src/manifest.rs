//! Module manifests: `modules/<module_id>/manifest.yaml` (#30).
//!
//! A decoy module is a reused open source honeypot (Cowrie, OpenCanary and
//! others) that runs as its own container. Foiled never imports, links or
//! vendors module code; it starts the pinned image and reads the JSON the
//! module writes (ADR 0002). The manifest records the protocol, personas,
//! ports, upstream licence, image digest and the mapping from the module's
//! event schema to capture envelopes. The schema is
//! `schemas/module-manifest.schema.json`.

use std::collections::BTreeSet;
use std::path::Path;

use foiled_core::capture::{CaptureEvent, Channel, Endpoint, Severity};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};

use crate::sink::{Event, EventSink};
use crate::util::{clip, days_from_civil, sha256_hex};

pub const SCHEMA_VERSION: u32 = 1;
const PLACEHOLDER_DIGEST: &str =
    "sha256:0000000000000000000000000000000000000000000000000000000000000000";
/// Longest string copied from a module event into an envelope.
const FIELD_CLIP: usize = 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModuleManifest {
    pub schema_version: u32,
    pub module_id: String,
    pub name: String,
    pub upstream: String,
    pub version: String,
    /// Upstream SPDX licence id.
    pub licence: String,
    /// Always `separate_container`: module code never enters Foiled source.
    pub distribution: Distribution,
    /// Whether images we distribute must offer corresponding source.
    /// Required for GPL modules.
    pub source_offer: bool,
    /// Upstream licence files kept in any image we build.
    pub licence_files: Vec<String>,
    pub image: ImageRef,
    pub isolation: Isolation,
    pub protocols: Vec<String>,
    pub catalogue_ids: Vec<String>,
    pub personas: Vec<Persona>,
    pub ports: Vec<ModulePort>,
    pub health: HealthCheck,
    pub log: LogSource,
    pub event_mapping: EventMapping,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Distribution {
    SeparateContainer,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Isolation {
    Runc,
    Runsc,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImageRef {
    pub reference: String,
    pub digest: String,
    /// False while `digest` is a placeholder. A catalogue entry using this
    /// module cannot be verified until it is true.
    pub pinned: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HostnameSource {
    /// From the host's per-decoy identity store (FR-01), never a default.
    IdentityStore,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Persona {
    pub id: String,
    pub description: String,
    pub hostname: HostnameSource,
    /// Exact banners the persona sends; must be in the catalogue entry's
    /// `banner_hints` (FR-05).
    pub banners: Vec<String>,
    /// Published ports this persona opens; a subset of `ports`.
    pub ports: Vec<u16>,
    /// Upstream configuration overrides, `section.key: value`.
    #[serde(default)]
    pub settings: std::collections::BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModulePort {
    pub port: u16,
    pub container_port: u16,
    pub protocol: crate::profile::Protocol,
    pub service: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HealthKind {
    Tcp,
    Banner,
    Http,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HealthCheck {
    pub kind: HealthKind,
    pub container_port: u16,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expect: Option<String>,
    pub interval_s: u32,
    /// Consecutive failures before the decoy is rotated (`health_failed`).
    pub failures: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LogFormat {
    Jsonl,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LogSource {
    /// Relative to the per-generation log directory.
    pub path: String,
    pub format: LogFormat,
    pub max_line_bytes: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EventMapping {
    pub id: String,
    pub fields: CommonFields,
    pub events: Vec<EventRule>,
    pub unmapped: Unmapped,
}

/// Where the common envelope inputs live in a module event.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CommonFields {
    pub event: String,
    pub timestamp: String,
    pub src_ip: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub src_port: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Unmapped {
    /// Count and drop events the mapping does not list.
    DropAndCount,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EventRule {
    /// The module's own event name, for example `cowrie.login.failed`.
    pub event: String,
    pub channel: Channel,
    pub severity: Severity,
    #[serde(default)]
    pub data: Vec<FieldCopy>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Transform {
    #[default]
    Copy,
    /// Keep only the SHA-256 of the value (passwords, bodies; #16).
    Sha256,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FieldCopy {
    pub from: String,
    pub to: String,
    #[serde(default)]
    pub transform: Transform,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MapError {
    TooLong(usize),
    NotJson,
    Missing(&'static str),
    BadTimestamp(String),
    BadIp(String),
}

impl std::fmt::Display for MapError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MapError::TooLong(n) => write!(f, "line is {n} bytes"),
            MapError::NotJson => write!(f, "line is not a JSON object"),
            MapError::Missing(field) => write!(f, "missing {field}"),
            MapError::BadTimestamp(t) => write!(f, "bad timestamp '{t}'"),
            MapError::BadIp(ip) => write!(f, "bad source ip '{ip}'"),
        }
    }
}

impl std::error::Error for MapError {}

/// RFC 3339 timestamp (`2026-10-18T03:04:05.123456Z` or with an offset) to
/// Unix milliseconds.
pub fn parse_rfc3339(s: &str) -> Option<i64> {
    let b = s.as_bytes();
    if b.len() < 20 || b[4] != b'-' || b[7] != b'-' || !matches!(b[10], b'T' | b't' | b' ') {
        return None;
    }
    if b[13] != b':' || b[16] != b':' {
        return None;
    }
    let num = |r: std::ops::Range<usize>| -> Option<i64> {
        let part = s.get(r)?;
        part.bytes()
            .all(|c| c.is_ascii_digit())
            .then(|| part.parse().ok())
            .flatten()
    };
    let (y, mo, d) = (num(0..4)?, num(5..7)?, num(8..10)?);
    let (h, mi, sec) = (num(11..13)?, num(14..16)?, num(17..19)?);
    if !(1..=12).contains(&mo) || !(1..=31).contains(&d) || h > 23 || mi > 59 || sec > 60 {
        return None;
    }
    let mut i = 19;
    let mut millis = 0i64;
    if b.get(i) == Some(&b'.') {
        i += 1;
        let start = i;
        while b.get(i).is_some_and(u8::is_ascii_digit) {
            i += 1;
        }
        if i == start {
            return None;
        }
        let frac = &s[start..i.min(start + 3)];
        millis = frac.parse::<i64>().ok()? * 10i64.pow(3 - frac.len() as u32);
    }
    let offset_s = match b.get(i) {
        Some(b'Z' | b'z') if i + 1 == b.len() => 0,
        Some(sign @ (b'+' | b'-')) if b.len() == i + 6 && b[i + 3] == b':' => {
            let oh = num(i + 1..i + 3)?;
            let om = num(i + 4..i + 6)?;
            let v = oh * 3600 + om * 60;
            if *sign == b'+' { v } else { -v }
        }
        _ => return None,
    };
    let days = days_from_civil(y, mo as u32, d as u32);
    let secs = days * 86_400 + h * 3600 + mi * 60 + sec - offset_s;
    Some(secs * 1000 + millis)
}

impl ModuleManifest {
    pub fn from_yaml(text: &str) -> Result<Self, String> {
        serde_yaml_ng::from_str(text).map_err(|e| e.to_string())
    }

    pub fn load(path: &Path) -> Result<Self, String> {
        let text = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
        Self::from_yaml(&text)
    }

    /// True once the image digest is real. Verified catalogue entries need it.
    pub fn is_pinned(&self) -> bool {
        self.image.pinned && self.image.digest != PLACEHOLDER_DIGEST
    }

    pub fn is_gpl(&self) -> bool {
        self.licence.contains("GPL")
    }

    pub fn problems(&self) -> Vec<String> {
        let mut out = Vec::new();
        if self.schema_version != SCHEMA_VERSION {
            out.push(format!("schema_version must be {SCHEMA_VERSION}"));
        }
        if self.is_gpl() && !self.source_offer {
            out.push(format!(
                "{} is {}: images must offer corresponding source (source_offer: true)",
                self.module_id, self.licence
            ));
        }
        if self.licence_files.is_empty() {
            out.push("licence_files must list the upstream licence text".into());
        }
        let digest_ok = self.image.digest.strip_prefix("sha256:").is_some_and(|h| {
            h.len() == 64
                && h.bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        });
        if !digest_ok {
            out.push(format!(
                "image digest '{}' is not sha256:<64 hex>",
                self.image.digest
            ));
        }
        if self.image.pinned && self.image.digest == PLACEHOLDER_DIGEST {
            out.push("image is marked pinned but the digest is the placeholder".into());
        }
        if self.image.reference.contains('@') {
            out.push("image.reference must not carry a digest; use image.digest".into());
        }
        let mut published = BTreeSet::new();
        let mut inside = BTreeSet::new();
        for p in &self.ports {
            if !published.insert(p.port) {
                out.push(format!("published port {} appears twice", p.port));
            }
            inside.insert(p.container_port);
        }
        if !inside.contains(&self.health.container_port) {
            out.push(format!(
                "health check port {} is not a container port",
                self.health.container_port
            ));
        }
        if self.health.interval_s == 0 || self.health.failures == 0 {
            out.push("health interval_s and failures must be at least 1".into());
        }
        if self.personas.is_empty() {
            out.push("at least one persona is required".into());
        }
        for persona in &self.personas {
            for port in &persona.ports {
                if !published.contains(port) {
                    out.push(format!("persona {} opens unknown port {port}", persona.id));
                }
            }
            if persona.banners.is_empty() {
                out.push(format!("persona {} has no banners", persona.id));
            }
        }
        if self.log.path.starts_with('/') || self.log.path.split('/').any(|s| s == "..") {
            out.push("log.path must be relative and stay inside the log directory".into());
        }
        if self.log.max_line_bytes == 0 || self.log.max_line_bytes > 1024 * 1024 {
            out.push("log.max_line_bytes must be 1..=1048576".into());
        }
        let mut seen = BTreeSet::new();
        for rule in &self.event_mapping.events {
            if !seen.insert(rule.event.as_str()) {
                out.push(format!("event {} is mapped twice", rule.event));
            }
            if rule.channel == Channel::Hook {
                out.push(format!(
                    "event {} cannot map to the hook channel",
                    rule.event
                ));
            }
        }
        out
    }

    /// Map one line of the module's JSON log to an envelope. `Ok(None)` for
    /// events the mapping does not list (counted and dropped by the agent).
    /// The line is untrusted: it is size-capped, every copied string is
    /// clipped, and nothing in it is used as a path or executed.
    pub fn map_line(&self, line: &str, sink: &EventSink) -> Result<Option<CaptureEvent>, MapError> {
        if line.len() > self.log.max_line_bytes {
            return Err(MapError::TooLong(line.len()));
        }
        let v: Value = serde_json::from_str(line).map_err(|_| MapError::NotJson)?;
        let obj = v.as_object().ok_or(MapError::NotJson)?;
        let f = &self.event_mapping.fields;
        let event = obj
            .get(&f.event)
            .and_then(Value::as_str)
            .ok_or(MapError::Missing("event"))?;
        let Some(rule) = self.event_mapping.events.iter().find(|r| r.event == event) else {
            return Ok(None);
        };
        let ts_text = obj
            .get(&f.timestamp)
            .and_then(Value::as_str)
            .ok_or(MapError::Missing("timestamp"))?;
        let ts = parse_rfc3339(ts_text)
            .ok_or_else(|| MapError::BadTimestamp(clip(ts_text.as_bytes(), 64)))?;
        let ip = obj
            .get(&f.src_ip)
            .and_then(Value::as_str)
            .ok_or(MapError::Missing("src_ip"))?;
        let ip: std::net::IpAddr = ip
            .parse()
            .map_err(|_| MapError::BadIp(clip(ip.as_bytes(), 64)))?;
        let port = f
            .src_port
            .as_ref()
            .and_then(|k| obj.get(k))
            .and_then(Value::as_u64)
            .and_then(|p| u16::try_from(p).ok());

        let mut data = Map::new();
        data.insert("module".into(), json!(self.module_id));
        data.insert("module_event".into(), json!(clip(event.as_bytes(), 128)));
        if let Some(s) = f
            .session
            .as_ref()
            .and_then(|k| obj.get(k))
            .and_then(Value::as_str)
        {
            data.insert("session".into(), json!(clip(s.as_bytes(), 64)));
        }
        for copy in &rule.data {
            let Some(value) = obj.get(&copy.from) else {
                continue;
            };
            let mapped = match (copy.transform, value) {
                (Transform::Sha256, Value::String(s)) => json!(sha256_hex(s.as_bytes())),
                (Transform::Sha256, other) => json!(sha256_hex(other.to_string().as_bytes())),
                (Transform::Copy, Value::String(s)) => json!(clip(s.as_bytes(), FIELD_CLIP)),
                (Transform::Copy, Value::Number(_) | Value::Bool(_)) => value.clone(),
                (Transform::Copy, other) => json!(clip(other.to_string().as_bytes(), FIELD_CLIP)),
            };
            data.insert(copy.to.clone(), mapped);
        }
        let ev = Event {
            channel: rule.channel,
            severity: rule.severity,
            src: Endpoint {
                ip: ip.to_canonical().to_string(),
                port,
            },
            // The agent knows the decoy's own address and sets it.
            dst: None,
            data,
            hook: None,
        };
        Ok(Some(sink.build(ev, ts)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc3339_parses_like_cowrie_writes_it() {
        assert_eq!(parse_rfc3339("1970-01-01T00:00:00Z"), Some(0));
        assert_eq!(
            parse_rfc3339("2026-10-18T01:02:03.123456Z"),
            Some(1_792_285_323_123)
        );
        assert_eq!(
            parse_rfc3339("2026-10-18T11:02:03.5+10:00"),
            Some(1_792_285_323_500)
        );
        for bad in [
            "",
            "2026-10-18",
            "2026-13-01T00:00:00Z",
            "2026-10-18T00:00:00",
            "x026-10-18T00:00:00Z",
            "2026-10-18T00:00:00.Z",
        ] {
            assert_eq!(parse_rfc3339(bad), None, "{bad}");
        }
    }
}
