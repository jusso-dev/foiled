//! Contribute-back sharing policy (#37).
//!
//! `configs/contribute-back.yaml` is parsed into [`SharePolicy`]. The design
//! and the reasons behind each rule are in `docs/contribute-back.md`.
//!
//! Three decisions live here so the API Worker, the host agent and the edge
//! sensor agent all make them the same way:
//!
//! - [`may_share`]: may this sensor's data go to this channel at all?
//! - [`public_ioc_release`]: may this IOC be published yet?
//! - [`strip_non_shareable`]: remove fields that must never leave, whatever
//!   the channel. This is a backstop: outbound records are built from an
//!   allow-list of fields first.

use serde::de::Error as _;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::{Map, Value};

/// Milliseconds in a day.
pub const DAY_MS: u64 = 86_400_000;

/// The only policy file version this code understands.
pub const POLICY_VERSION: u32 = 1;

/// Enrichment providers whose fields are never shared or published. A key is
/// removed if it equals the name or starts with the name followed by `.` or
/// `_` (for example `greynoise.classification` or `dshield_count`).
pub const ENRICHMENT_PROVIDERS: &[&str] =
    &["greynoise", "crowdsec", "dshield", "shadowserver", "huntio"];

/// Other keys that are never shared. A key is removed if it equals the name or
/// starts with the name followed by `.` (for example `canary.token_id`).
pub const NEVER_SHARED_KEYS: &[&str] = &["tenant_id", "payload_body", "canary"];

/// Where a sensor runs and who owns it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SensorKind {
    /// A sensor Foiled operators run for research (#7).
    Research,
    /// A sensor on someone else's host, usually a customer (#31).
    Edge,
}

/// A contribute-back channel.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Channel {
    /// Cowrie's `dshield` output plugin.
    Dshield,
    /// CrowdSec Security Engine signals from unmodified Hub scenarios.
    Crowdsec,
    /// SentryPeer peer-to-peer sharing, only where the SIP module runs.
    Sentrypeer,
    /// Delayed public IOCs on exploit pages and datasets (#35).
    PublicIocs,
}

/// `on` or `off`. Also accepts a YAML boolean, because YAML 1.1 parsers read a
/// bare `off` as `false`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Toggle {
    On,
    Off,
}

impl Toggle {
    pub fn is_on(self) -> bool {
        self == Toggle::On
    }
}

impl Serialize for Toggle {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(if self.is_on() { "on" } else { "off" })
    }
}

impl<'de> Deserialize<'de> for Toggle {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Raw {
            Bool(bool),
            Text(String),
        }
        match Raw::deserialize(d)? {
            Raw::Bool(true) => Ok(Toggle::On),
            Raw::Bool(false) => Ok(Toggle::Off),
            Raw::Text(t) if t == "on" => Ok(Toggle::On),
            Raw::Text(t) if t == "off" => Ok(Toggle::Off),
            Raw::Text(t) => Err(D::Error::custom(format!("expected on or off, got {t:?}"))),
        }
    }
}

/// Confidence band from the confidence layer (#27).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Band {
    Low,
    Medium,
    High,
}

impl Band {
    /// Parse a band name. Unknown names return `None`, which callers treat as
    /// "not shareable".
    pub fn parse(s: &str) -> Option<Band> {
        match s {
            "low" => Some(Band::Low),
            "medium" => Some(Band::Medium),
            "high" => Some(Band::High),
            _ => None,
        }
    }
}

/// Traffic Light Protocol 2.0 label for released IOCs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Tlp {
    /// Public: exploit pages and open datasets.
    Clear,
    /// Community only: the account-gated dataset, not public pages.
    Green,
    Amber,
    #[serde(rename = "amber+strict")]
    AmberStrict,
    Red,
}

impl Tlp {
    /// Whether IOCs under this label may leave through the public IOC channel
    /// at all. Amber and red never do.
    pub fn allows_release(self) -> bool {
        matches!(self, Tlp::Clear | Tlp::Green)
    }
}

/// Settings shared by the community channels.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChannelPolicy {
    pub enabled: bool,
    /// Sensor kinds the channel may run on. Each sensor must also be opted in.
    pub sensor_kinds: Vec<SensorKind>,
}

/// DShield channel settings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DshieldPolicy {
    pub enabled: bool,
    pub sensor_kinds: Vec<SensorKind>,
    /// Name of the environment variable holding the contact email. Never the
    /// email itself and never a credential.
    pub contact_email_env: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Channels {
    pub dshield: DshieldPolicy,
    pub crowdsec: ChannelPolicy,
    pub sentrypeer: ChannelPolicy,
}

/// Delayed public IOC settings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublicIocsPolicy {
    pub enabled: bool,
    pub sensor_kinds: Vec<SensorKind>,
    /// Days after `first_seen` before an IOC may be released.
    pub delay_days: u32,
    /// Lowest confidence band that may be released.
    pub min_confidence: Band,
    /// Label carried by released IOCs.
    pub tlp: Tlp,
}

/// The whole of `configs/contribute-back.yaml`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SharePolicy {
    pub version: u32,
    /// Opt-in state for a research sensor with no explicit choice recorded.
    pub research_sensors_default: Toggle,
    /// Opt-in state for an edge sensor with no explicit choice recorded. Only
    /// `off` passes [`SharePolicy::problems`].
    pub edge_sensors_default: Toggle,
    pub channels: Channels,
    pub public_iocs: PublicIocsPolicy,
}

impl Default for SharePolicy {
    /// The defaults shipped in `configs/contribute-back.yaml`.
    fn default() -> Self {
        SharePolicy {
            version: POLICY_VERSION,
            research_sensors_default: Toggle::On,
            edge_sensors_default: Toggle::Off,
            channels: Channels {
                dshield: DshieldPolicy {
                    enabled: true,
                    sensor_kinds: vec![SensorKind::Research, SensorKind::Edge],
                    contact_email_env: "FOILED_DSHIELD_CONTACT_EMAIL".to_string(),
                },
                crowdsec: ChannelPolicy {
                    enabled: true,
                    sensor_kinds: vec![SensorKind::Research, SensorKind::Edge],
                },
                sentrypeer: ChannelPolicy {
                    enabled: false,
                    sensor_kinds: vec![SensorKind::Research],
                },
            },
            public_iocs: PublicIocsPolicy {
                enabled: true,
                sensor_kinds: vec![SensorKind::Research],
                delay_days: 7,
                min_confidence: Band::High,
                tlp: Tlp::Clear,
            },
        }
    }
}

impl SharePolicy {
    /// Opt-in state for a sensor that has no explicit choice recorded.
    pub fn default_opt_in(&self, kind: SensorKind) -> bool {
        match kind {
            SensorKind::Research => self.research_sensors_default.is_on(),
            SensorKind::Edge => self.edge_sensors_default.is_on(),
        }
    }

    fn channel(&self, channel: Channel) -> (bool, &[SensorKind]) {
        match channel {
            Channel::Dshield => (
                self.channels.dshield.enabled,
                &self.channels.dshield.sensor_kinds,
            ),
            Channel::Crowdsec => (
                self.channels.crowdsec.enabled,
                &self.channels.crowdsec.sensor_kinds,
            ),
            Channel::Sentrypeer => (
                self.channels.sentrypeer.enabled,
                &self.channels.sentrypeer.sensor_kinds,
            ),
            Channel::PublicIocs => (self.public_iocs.enabled, &self.public_iocs.sensor_kinds),
        }
    }

    /// Rules the type cannot express. An empty list means the policy may be
    /// loaded.
    pub fn problems(&self) -> Vec<String> {
        let mut out = Vec::new();
        if self.version != POLICY_VERSION {
            out.push(format!(
                "version must be {POLICY_VERSION}, got {}",
                self.version
            ));
        }
        if self.edge_sensors_default.is_on() {
            out.push(
                "edge_sensors_default must be off: customer sensor data is shared only after an explicit opt-in"
                    .to_string(),
            );
        }
        if !is_env_var_name(&self.channels.dshield.contact_email_env) {
            out.push(format!(
                "channels.dshield.contact_email_env must be an environment variable name (A-Z, 0-9, _), got {:?}",
                self.channels.dshield.contact_email_env
            ));
        }
        out
    }
}

fn is_env_var_name(s: &str) -> bool {
    let mut chars = s.chars();
    chars
        .next()
        .is_some_and(|c| c.is_ascii_uppercase() || c == '_')
        && chars.all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_')
}

/// Whether data from a sensor may go to a channel.
///
/// `sensor_opted_in` is the sensor's recorded choice, or
/// [`SharePolicy::default_opt_in`] when it has none. All of these must hold:
/// the channel is enabled, it may run on this sensor kind, and the sensor is
/// opted in.
pub fn may_share(
    policy: &SharePolicy,
    sensor_kind: SensorKind,
    sensor_opted_in: bool,
    channel: Channel,
) -> bool {
    let (enabled, kinds) = policy.channel(channel);
    enabled && sensor_opted_in && kinds.contains(&sensor_kind)
}

/// Public release decision for one IOC.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "decision", rename_all = "snake_case")]
pub enum Release {
    /// Eligible, but the delay has not passed. Check again at `until_ms`.
    Hold { until_ms: u64 },
    /// May be published now under the policy's TLP label.
    Release,
    /// May not be published on current facts: channel off, TLP blocks public
    /// release, not analyst-confirmed, or confidence below the minimum.
    Never,
}

/// Decide whether an IOC may be published.
///
/// `first_seen_ms` is the earliest sighting on a sensor for which
/// [`may_share`] allows [`Channel::PublicIocs`]. `band` is the confidence band
/// name from #27; unknown names are treated as below the minimum.
/// Unconfirmed IOCs are never released, whatever their age or band.
pub fn public_ioc_release(
    policy: &SharePolicy,
    first_seen_ms: u64,
    confirmed: bool,
    band: &str,
    now_ms: u64,
) -> Release {
    let p = &policy.public_iocs;
    if !p.enabled || !p.tlp.allows_release() || !confirmed {
        return Release::Never;
    }
    match Band::parse(band) {
        Some(b) if b >= p.min_confidence => {}
        _ => return Release::Never,
    }
    let until_ms = first_seen_ms.saturating_add(u64::from(p.delay_days).saturating_mul(DAY_MS));
    if now_ms < until_ms {
        Release::Hold { until_ms }
    } else {
        Release::Release
    }
}

fn matches_entry(key: &str, entry: &str, separators: &[char]) -> bool {
    match key.strip_prefix(entry) {
        Some("") => true,
        Some(rest) => rest.starts_with(separators),
        None => false,
    }
}

fn is_non_shareable(key: &str) -> bool {
    let key = key.to_ascii_lowercase();
    ENRICHMENT_PROVIDERS
        .iter()
        .any(|p| matches_entry(&key, p, &['.', '_']))
        || NEVER_SHARED_KEYS
            .iter()
            .any(|k| matches_entry(&key, k, &['.']))
}

fn strip_value(value: &mut Value) -> usize {
    match value {
        Value::Object(map) => strip_non_shareable(map),
        Value::Array(items) => items.iter_mut().map(strip_value).sum(),
        _ => 0,
    }
}

/// Remove every key that must never be shared, at any depth, and return how
/// many keys were removed (for the audit log).
///
/// Removed: enrichment provider fields (see [`ENRICHMENT_PROVIDERS`]) and the
/// keys in [`NEVER_SHARED_KEYS`]. Matching ignores ASCII case.
pub fn strip_non_shareable(fields: &mut Map<String, Value>) -> usize {
    let before = fields.len();
    fields.retain(|k, _| !is_non_shareable(k));
    let mut removed = before - fields.len();
    for v in fields.values_mut() {
        removed += strip_value(v);
    }
    removed
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const T0: u64 = 1_760_000_000_000;

    fn policy() -> SharePolicy {
        SharePolicy::default()
    }

    const ALL: [Channel; 4] = [
        Channel::Dshield,
        Channel::Crowdsec,
        Channel::Sentrypeer,
        Channel::PublicIocs,
    ];

    #[test]
    fn tabletop_edge_sensor_opted_out_sends_nothing() {
        let p = policy();
        let opted_in = p.default_opt_in(SensorKind::Edge);
        assert!(!opted_in, "edge sensors default to off");
        for ch in ALL {
            assert!(!may_share(&p, SensorKind::Edge, opted_in, ch), "{ch:?}");
        }
    }

    #[test]
    fn tabletop_research_sensor_with_cowrie_plugin_sends_to_dshield() {
        let p = policy();
        let opted_in = p.default_opt_in(SensorKind::Research);
        assert!(opted_in, "research sensors default to on");
        assert!(may_share(
            &p,
            SensorKind::Research,
            opted_in,
            Channel::Dshield
        ));
        assert!(may_share(
            &p,
            SensorKind::Research,
            opted_in,
            Channel::Crowdsec
        ));
        assert!(may_share(
            &p,
            SensorKind::Research,
            opted_in,
            Channel::PublicIocs
        ));
    }

    #[test]
    fn research_sensor_that_opts_out_sends_nothing() {
        let p = policy();
        for ch in ALL {
            assert!(!may_share(&p, SensorKind::Research, false, ch), "{ch:?}");
        }
    }

    #[test]
    fn edge_sensor_that_opts_in_shares_community_channels_but_not_public_iocs() {
        let p = policy();
        assert!(may_share(&p, SensorKind::Edge, true, Channel::Dshield));
        assert!(may_share(&p, SensorKind::Edge, true, Channel::Crowdsec));
        assert!(!may_share(&p, SensorKind::Edge, true, Channel::PublicIocs));
        assert!(!may_share(&p, SensorKind::Edge, true, Channel::Sentrypeer));
    }

    #[test]
    fn disabled_channel_shares_nothing() {
        let p = policy();
        assert!(!p.channels.sentrypeer.enabled);
        assert!(!may_share(
            &p,
            SensorKind::Research,
            true,
            Channel::Sentrypeer
        ));

        let mut p = policy();
        p.channels.dshield.enabled = false;
        assert!(!may_share(&p, SensorKind::Research, true, Channel::Dshield));
    }

    #[test]
    fn delay_boundary() {
        let p = policy();
        let until = T0 + 7 * DAY_MS;
        assert_eq!(
            public_ioc_release(&p, T0, true, "high", T0),
            Release::Hold { until_ms: until }
        );
        assert_eq!(
            public_ioc_release(&p, T0, true, "high", until - 1),
            Release::Hold { until_ms: until }
        );
        assert_eq!(
            public_ioc_release(&p, T0, true, "high", until),
            Release::Release
        );
        assert_eq!(
            public_ioc_release(&p, T0, true, "high", until + 1),
            Release::Release
        );
    }

    #[test]
    fn delay_follows_policy() {
        let mut p = policy();
        p.public_iocs.delay_days = 30;
        assert_eq!(
            public_ioc_release(&p, T0, true, "high", T0 + 7 * DAY_MS),
            Release::Hold {
                until_ms: T0 + 30 * DAY_MS
            }
        );
        p.public_iocs.delay_days = 0;
        assert_eq!(
            public_ioc_release(&p, T0, true, "high", T0),
            Release::Release
        );
    }

    #[test]
    fn delay_saturates_instead_of_wrapping() {
        let p = policy();
        assert_eq!(
            public_ioc_release(&p, u64::MAX - 1, true, "high", u64::MAX - 1),
            Release::Hold { until_ms: u64::MAX }
        );
    }

    #[test]
    fn unconfirmed_is_never_public() {
        let p = policy();
        for now in [T0, T0 + 7 * DAY_MS, T0 + 3650 * DAY_MS] {
            assert_eq!(
                public_ioc_release(&p, T0, false, "high", now),
                Release::Never
            );
        }
    }

    #[test]
    fn band_below_minimum_or_unknown_is_never_public() {
        let p = policy();
        let later = T0 + 30 * DAY_MS;
        assert_eq!(
            public_ioc_release(&p, T0, true, "medium", later),
            Release::Never
        );
        assert_eq!(
            public_ioc_release(&p, T0, true, "low", later),
            Release::Never
        );
        assert_eq!(
            public_ioc_release(&p, T0, true, "HIGH", later),
            Release::Never
        );
        assert_eq!(public_ioc_release(&p, T0, true, "", later), Release::Never);

        let mut p = policy();
        p.public_iocs.min_confidence = Band::Medium;
        assert_eq!(
            public_ioc_release(&p, T0, true, "medium", later),
            Release::Release
        );
    }

    #[test]
    fn tlp_and_channel_switch_gate_release() {
        let later = T0 + 30 * DAY_MS;
        let mut p = policy();
        p.public_iocs.tlp = Tlp::Green;
        assert_eq!(
            public_ioc_release(&p, T0, true, "high", later),
            Release::Release
        );
        for tlp in [Tlp::Amber, Tlp::AmberStrict, Tlp::Red] {
            p.public_iocs.tlp = tlp;
            assert_eq!(
                public_ioc_release(&p, T0, true, "high", later),
                Release::Never,
                "{tlp:?}"
            );
        }
        let mut p = policy();
        p.public_iocs.enabled = false;
        assert_eq!(
            public_ioc_release(&p, T0, true, "high", later),
            Release::Never
        );
    }

    #[test]
    fn strip_removes_enrichment_and_private_fields_at_any_depth() {
        let mut v = json!({
            "src_ip": "203.0.113.7",
            "first_seen": "2099-01-01T00:00:00Z",
            "payload_sha256": "00",
            "greynoise.classification": "malicious",
            "GreyNoise.riot": false,
            "crowdsec.reputation": "known",
            "dshield": {"count": 3},
            "dshield_attacks": 9,
            "shadowserver.asn": 64500,
            "huntio.c2": true,
            "tenant_id": "t-1",
            "payload_body": "GET / HTTP/1.1",
            "canary": "AKIAFOILEDDEMO",
            "canary.token_id": "c-1",
            "context": {
                "tenant_id": "t-2",
                "observables": [
                    {"type": "ip", "value": "198.51.100.9", "greynoise.noise": true},
                    {"type": "url", "value": "http://192.0.2.1/x", "payload_body": "x"}
                ]
            }
        });
        let map = v.as_object_mut().unwrap();
        let removed = strip_non_shareable(map);
        assert_eq!(removed, 14);
        assert_eq!(
            v,
            json!({
                "src_ip": "203.0.113.7",
                "first_seen": "2099-01-01T00:00:00Z",
                "payload_sha256": "00",
                "context": {
                    "observables": [
                        {"type": "ip", "value": "198.51.100.9"},
                        {"type": "url", "value": "http://192.0.2.1/x"}
                    ]
                }
            })
        );
    }

    #[test]
    fn strip_keeps_lookalike_keys() {
        let mut v = json!({
            "canary_seen": true,
            "tenant_identity_note": "kept: not tenant_id",
            "dshieldish": 1,
            "crowdsecurity_scenario": "kept: not crowdsec_"
        });
        let removed = strip_non_shareable(v.as_object_mut().unwrap());
        assert_eq!(removed, 0);
        assert_eq!(v.as_object().unwrap().len(), 4);
    }

    #[test]
    fn default_policy_has_no_problems_and_round_trips() {
        let p = policy();
        assert!(p.problems().is_empty(), "{:?}", p.problems());
        let text = serde_json::to_string(&p).unwrap();
        let back: SharePolicy = serde_json::from_str(&text).unwrap();
        assert_eq!(back, p);
    }

    #[test]
    fn problems_catch_edge_default_on_and_bad_env_name() {
        let mut p = policy();
        p.edge_sensors_default = Toggle::On;
        p.channels.dshield.contact_email_env = "ops@example.com".to_string();
        p.version = 2;
        let problems = p.problems();
        assert_eq!(problems.len(), 3, "{problems:?}");
        assert!(problems.iter().any(|m| m.contains("edge_sensors_default")));
        assert!(problems.iter().any(|m| m.contains("contact_email_env")));
        assert!(problems.iter().any(|m| m.contains("version")));
    }

    #[test]
    fn toggle_accepts_on_off_and_booleans() {
        let on: Toggle = serde_json::from_value(json!("on")).unwrap();
        let off: Toggle = serde_json::from_value(json!("off")).unwrap();
        let f: Toggle = serde_json::from_value(json!(false)).unwrap();
        assert_eq!((on, off, f), (Toggle::On, Toggle::Off, Toggle::Off));
        assert!(serde_json::from_value::<Toggle>(json!("maybe")).is_err());
        assert_eq!(serde_json::to_value(Toggle::Off).unwrap(), json!("off"));
    }

    #[test]
    fn unknown_fields_are_rejected() {
        let mut v = serde_json::to_value(policy()).unwrap();
        v["public_iocs"]["include_enrichment"] = json!(true);
        assert!(serde_json::from_value::<SharePolicy>(v).is_err());
    }

    #[test]
    fn release_serialises_with_a_decision_tag() {
        assert_eq!(
            serde_json::to_value(Release::Hold { until_ms: 5 }).unwrap(),
            json!({"decision": "hold", "until_ms": 5})
        );
        assert_eq!(
            serde_json::to_value(Release::Never).unwrap(),
            json!({"decision": "never"})
        );
    }
}
