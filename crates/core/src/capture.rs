//! Capture envelopes (#9) and vulnerable-path hook events (#32).
//!
//! Hosts and sensors send small events as envelopes. Anything large (pcaps,
//! file diffs, quarantined payloads, request slices over the inline cap)
//! goes straight to R2 and the envelope carries a [`PayloadRef`]. The
//! contract is `schemas/capture-event.schema.json`; these types mirror it.
//!
//! Envelopes are untrusted input: the ingest API validates them, replaces
//! any `source` or `tenant_id` the sender claimed with its certificate
//! identity, and never derives confidence from fields in the event (#27).

use serde::{Deserialize, Serialize};

use crate::catalogue::DecoyKind;

/// Largest serialised envelope accepted at ingest. Queue messages cap at
/// 128 KB; keeping events small leaves room for batching.
pub const MAX_EVENT_BYTES: usize = 16 * 1024;
/// Largest batch accepted by one ingest request.
pub const MAX_BATCH: usize = 100;
/// How far in the future (clock skew) an event timestamp may be.
pub const MAX_FUTURE_SKEW_MS: i64 = 5 * 60 * 1000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Channel {
    /// Flows and packet metadata from the host-side tap or bridge.
    Network,
    /// Application logs: HTTP access lines, protocol opcodes, emulator events.
    Application,
    /// File-system diffs on rotate, or virtual FS writes from emulators.
    Filesystem,
    /// Process exec tracing (eBPF, auditd); not available for pure emulators.
    Process,
    /// A payload moved to quarantine.
    Quarantine,
    /// A vulnerable-path instrumentation hook fired (#32).
    Hook,
    /// DNS queries seen by the internal resolver (#4).
    Dns,
    /// Requests seen by the egress proxy (#4).
    Egress,
}

impl Channel {
    pub fn as_str(self) -> &'static str {
        match self {
            Channel::Network => "network",
            Channel::Application => "application",
            Channel::Filesystem => "filesystem",
            Channel::Process => "process",
            Channel::Quarantine => "quarantine",
            Channel::Hook => "hook",
            Channel::Dns => "dns",
            Channel::Egress => "egress",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Endpoint {
    pub ip: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceKind {
    Host,
    Sensor,
}

/// Who sent the event. Always set by the ingest API from the client
/// certificate, never trusted from the body.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Source {
    pub kind: SourceKind,
    pub id: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HookStage {
    Trigger,
    PostExploit,
    Cleanup,
}

/// Fields a vulnerable-path hook adds to an envelope (#32).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HookEvent {
    pub hook_id: String,
    pub catalogue_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cve_id: Option<String>,
    pub stage: HookStage,
    /// The exact request slice that reached the vulnerable code, by reference.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_slice_ref: Option<String>,
    pub sequence_no: u32,
    pub t_offset_ms: u64,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub cmd_lines: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub file_writes: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub implant_refs: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
}

/// One capture envelope.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CaptureEvent {
    pub event_id: String,
    /// Unix milliseconds when the event happened on the host.
    pub ts: i64,
    pub decoy_id: String,
    pub catalogue_id: String,
    pub decoy_kind: DecoyKind,
    /// Guest generation; bumps on every rebuild (`docs/rotation.md`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub generation: Option<u32>,
    pub channel: Channel,
    pub severity: Severity,
    pub src: Endpoint,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dst: Option<Endpoint>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payload_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attempt_id: Option<String>,
    /// Set by ingest from the certificate identity.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<Source>,
    /// Set by ingest from the certificate identity.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hook: Option<HookEvent>,
    /// Channel-specific detail (for example method, path, status, user agent).
    /// Bodies over the inline cap go to R2 and are referenced instead.
    #[serde(default)]
    pub data: serde_json::Map<String, serde_json::Value>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EventProblem {
    TooLarge { bytes: usize },
    EmptyField(&'static str),
    BadTimestamp,
    BadIp(String),
    HookChannelMismatch,
    BadPayloadRef(String),
}

impl std::fmt::Display for EventProblem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EventProblem::TooLarge { bytes } => {
                write!(f, "event is {bytes} bytes, limit is {MAX_EVENT_BYTES}")
            }
            EventProblem::EmptyField(name) => write!(f, "{name} must not be empty"),
            EventProblem::BadTimestamp => write!(f, "ts is not a plausible time"),
            EventProblem::BadIp(ip) => write!(f, "'{ip}' is not an IP address"),
            EventProblem::HookChannelMismatch => {
                write!(
                    f,
                    "hook fields are only allowed on the hook channel, and required there"
                )
            }
            EventProblem::BadPayloadRef(r) => write!(f, "invalid payload_ref '{r}'"),
        }
    }
}

fn is_ip(s: &str) -> bool {
    s.parse::<std::net::IpAddr>().is_ok()
}

impl CaptureEvent {
    /// Checks the schema cannot express. `now_ms` bounds the timestamp.
    pub fn problems(&self, now_ms: i64) -> Vec<EventProblem> {
        let mut out = Vec::new();
        let bytes = serde_json::to_vec(self)
            .map(|v| v.len())
            .unwrap_or(usize::MAX);
        if bytes > MAX_EVENT_BYTES {
            out.push(EventProblem::TooLarge { bytes });
        }
        for (name, v) in [
            ("event_id", &self.event_id),
            ("decoy_id", &self.decoy_id),
            ("catalogue_id", &self.catalogue_id),
        ] {
            if v.trim().is_empty() {
                out.push(EventProblem::EmptyField(name));
            }
        }
        // 2020-01-01 is a floor no real capture predates.
        if self.ts < 1_577_836_800_000 || self.ts > now_ms + MAX_FUTURE_SKEW_MS {
            out.push(EventProblem::BadTimestamp);
        }
        for ep in std::iter::once(&self.src).chain(self.dst.iter()) {
            if !is_ip(&ep.ip) {
                out.push(EventProblem::BadIp(ep.ip.clone()));
            }
        }
        if (self.channel == Channel::Hook) != self.hook.is_some() {
            out.push(EventProblem::HookChannelMismatch);
        }
        let refs = self.payload_ref.iter().chain(
            self.hook
                .iter()
                .filter_map(|h| h.request_slice_ref.as_ref()),
        );
        for r in refs {
            if PayloadRef::parse(r).is_none() {
                out.push(EventProblem::BadPayloadRef(r.clone()));
            }
        }
        out
    }

    /// Replace whatever the sender claimed about itself with its verified
    /// identity.
    pub fn stamp(&mut self, source: Source, tenant_id: &str) {
        self.source = Some(source);
        self.tenant_id = Some(tenant_id.to_string());
    }
}

/// `r2://<bucket>/<tenant>/<decoy-id>/<attempt-id>/<channel>/<sha256>`.
/// `attempt-id` is `_` when the object is not tied to an attempt yet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PayloadRef {
    pub bucket: String,
    pub tenant_id: String,
    pub decoy_id: String,
    pub attempt_id: Option<String>,
    pub channel: Channel,
    pub sha256: String,
}

fn safe_segment(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 128
        && s != "."
        && s != ".."
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
}

fn is_sha256_hex(s: &str) -> bool {
    s.len() == 64
        && s.chars()
            .all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c))
}

impl PayloadRef {
    pub fn parse(s: &str) -> Option<Self> {
        let rest = s.strip_prefix("r2://")?;
        let parts: Vec<&str> = rest.split('/').collect();
        let [bucket, tenant, decoy, attempt, channel, sha] = parts.as_slice() else {
            return None;
        };
        if ![bucket, tenant, decoy, attempt]
            .iter()
            .all(|p| safe_segment(p))
            || !is_sha256_hex(sha)
        {
            return None;
        }
        let channel: Channel =
            serde_json::from_value(serde_json::Value::String(channel.to_string())).ok()?;
        Some(PayloadRef {
            bucket: bucket.to_string(),
            tenant_id: tenant.to_string(),
            decoy_id: decoy.to_string(),
            attempt_id: (*attempt != "_").then(|| attempt.to_string()),
            channel,
            sha256: sha.to_string(),
        })
    }

    /// The object key inside the bucket.
    pub fn key(&self) -> String {
        format!(
            "{}/{}/{}/{}/{}",
            self.tenant_id,
            self.decoy_id,
            self.attempt_id.as_deref().unwrap_or("_"),
            self.channel.as_str(),
            self.sha256
        )
    }

    /// Build a reference after checking every segment, so a caller cannot
    /// smuggle `..` or `/` into an object key.
    pub fn new(
        bucket: &str,
        tenant_id: &str,
        decoy_id: &str,
        attempt_id: Option<&str>,
        channel: Channel,
        sha256: &str,
    ) -> Option<Self> {
        let r = format!(
            "r2://{bucket}/{tenant_id}/{decoy_id}/{}/{}/{sha256}",
            attempt_id.unwrap_or("_"),
            channel.as_str()
        );
        Self::parse(&r)
    }
}

impl std::fmt::Display for PayloadRef {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "r2://{}/{}", self.bucket, self.key())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const NOW: i64 = 1_800_000_000_000;
    const SHA: &str = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08";

    fn http_event() -> serde_json::Value {
        json!({
            "event_id": "e1",
            "ts": NOW - 1000,
            "decoy_id": "d1",
            "catalogue_id": "foiled/demo-app/1.0.0",
            "decoy_kind": "sandbox",
            "channel": "application",
            "severity": "info",
            "src": {"ip": "203.0.113.7", "port": 51234},
            "dst": {"ip": "10.85.1.2", "port": 8080},
            "data": {"method": "POST", "path": "/api/upload?path=../../tmp/x", "status": 201,
                     "user_agent": "curl/8.0"}
        })
    }

    fn parse(v: serde_json::Value) -> CaptureEvent {
        serde_json::from_value(v).unwrap()
    }

    #[test]
    fn valid_http_event_has_no_problems() {
        assert!(parse(http_event()).problems(NOW).is_empty());
    }

    #[test]
    fn hook_fields_belong_on_the_hook_channel() {
        let mut v = http_event();
        v["channel"] = json!("hook");
        assert_eq!(
            parse(v.clone()).problems(NOW),
            vec![EventProblem::HookChannelMismatch]
        );
        v["hook"] = json!({
            "hook_id": "demo-app.upload-path-traversal",
            "catalogue_id": "foiled/demo-app/1.0.0",
            "cve_id": "FOILED-DEMO-0001",
            "stage": "trigger",
            "request_slice_ref": format!("r2://foiled-evidence/t1/d1/_/hook/{SHA}"),
            "sequence_no": 1,
            "t_offset_ms": 12,
            "file_writes": ["/tmp/x"]
        });
        assert!(parse(v.clone()).problems(NOW).is_empty());
        v["channel"] = json!("application");
        assert_eq!(
            parse(v).problems(NOW),
            vec![EventProblem::HookChannelMismatch]
        );
    }

    #[test]
    fn rejects_bad_ips_timestamps_and_refs() {
        let mut v = http_event();
        v["src"]["ip"] = json!("not-an-ip");
        v["ts"] = json!(NOW + MAX_FUTURE_SKEW_MS + 1);
        v["payload_ref"] = json!("r2://b/t/../x/network/abc");
        let p = parse(v).problems(NOW);
        assert!(p.contains(&EventProblem::BadIp("not-an-ip".into())));
        assert!(p.contains(&EventProblem::BadTimestamp));
        assert!(
            p.iter()
                .any(|x| matches!(x, EventProblem::BadPayloadRef(_)))
        );
    }

    #[test]
    fn oversized_events_are_rejected() {
        let mut v = http_event();
        v["data"]["blob"] = json!("x".repeat(MAX_EVENT_BYTES));
        assert!(matches!(
            parse(v).problems(NOW).as_slice(),
            [EventProblem::TooLarge { .. }]
        ));
    }

    #[test]
    fn unknown_fields_are_rejected() {
        let mut v = http_event();
        v["confidence"] = json!(100);
        assert!(serde_json::from_value::<CaptureEvent>(v).is_err());
    }

    #[test]
    fn stamping_overrides_claimed_identity() {
        let mut v = http_event();
        v["tenant_id"] = json!("someone-else");
        v["source"] = json!({"kind": "host", "id": "forged"});
        let mut e = parse(v);
        e.stamp(
            Source {
                kind: SourceKind::Host,
                id: "host-1".into(),
            },
            "t1",
        );
        assert_eq!(e.tenant_id.as_deref(), Some("t1"));
        assert_eq!(e.source.unwrap().id, "host-1");
    }

    #[test]
    fn payload_refs_round_trip_and_refuse_traversal() {
        let r = format!("r2://foiled-evidence/t1/d1/a1/network/{SHA}");
        let p = PayloadRef::parse(&r).unwrap();
        assert_eq!(p.attempt_id.as_deref(), Some("a1"));
        assert_eq!(p.key(), format!("t1/d1/a1/network/{SHA}"));
        assert_eq!(p.to_string(), r);
        let none = PayloadRef::new(
            "foiled-evidence",
            "t1",
            "d1",
            None,
            Channel::Quarantine,
            SHA,
        )
        .unwrap();
        assert_eq!(none.key(), format!("t1/d1/_/quarantine/{SHA}"));
        for bad in [
            format!("r2://b/t1/../a/network/{SHA}"),
            format!("r2://b/t1/d1/a1/nope/{SHA}"),
            "r2://b/t1/d1/a1/network/ABC".to_string(),
            format!("s3://b/t1/d1/a1/network/{SHA}"),
            format!("r2://b/t1/d1/a1/network/{SHA}/extra"),
            format!("r2://b/t 1/d1/a1/network/{SHA}"),
        ] {
            assert!(PayloadRef::parse(&bad).is_none(), "{bad}");
        }
        assert!(PayloadRef::new("b", "t1", "../d", None, Channel::Network, SHA).is_none());
    }
}
