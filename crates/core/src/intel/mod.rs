//! Intel outputs (#13): STIX 2.1 bundles, MISP events and IOC CSV and
//! JSON, built from attempts (#25), their scored links (#27) and the IOCs
//! extracted from them (#34).
//!
//! Everything here is pure and deterministic: the same input and options
//! always give byte-identical output, with ids derived from content
//! (UUIDv5 over a Foiled namespace, and the STIX namespace for cyber
//! observables). Nothing reads a clock.
//!
//! The pipeline is [`select`] then a serialiser ([`stix`], [`misp`],
//! [`table`]). [`select`] is the single gate every format goes through:
//! attempt filters, the confidence gate (`publish_min` via each link's
//! `publishable`, plus an optional `min_confidence`), analyst suppressions,
//! the actor opt-in, the payload opt-in, and export redaction of enrichment
//! context (`ioc::redact_for_export`). The serialisers never see anything
//! that did not pass it.
//!
//! Campaigns (#33) and actors (#29) arrive as [`ConfidenceLink`]s of kind
//! `attempt_campaign` and `attempt_actor` on [`AttemptRecord::links`]. The
//! serialisers already map them (STIX `campaign` and `intrusion-set`, MISP
//! `campaign-id` and `threat-actor`); producers only need to add the links.
//!
//! See `docs/intel-outputs.md`.

use std::collections::{BTreeMap, BTreeSet};

use serde::Serialize;
use serde_json::Value;

use crate::attack::{AttackSidecar, TechniqueInfo};
use crate::attempt::{Attempt, AttemptState};
use crate::catalogue::DecoyKind;
use crate::confidence::{Band, ConfidenceLink, Feedback, LinkKind};
use crate::ioc::{Ioc, IocRole, IocType, export_refs};
use crate::share::Tlp;
use crate::timeline::printable;

pub mod misp;
pub mod stix;
pub mod table;
pub mod uuid5;

/// Namespace for every Foiled-minted UUIDv5: `uuid5(NAMESPACE_URL,
/// "https://github.com/jusso-dev/foiled")`. A test keeps it equal.
pub const FOILED_NAMESPACE: &str = "8f76a3ac-a14d-537e-9444-887bfe367e46";

/// The STIX 2.1 namespace for deterministic cyber observable ids (STIX 2.1
/// section 2.9).
pub const STIX_SCO_NAMESPACE: &str = "00abedb4-aa42-466c-9c01-fed23315a9b7";

/// `created` for reference objects that do not change with the evidence
/// (the Foiled identity, vulnerabilities, markings Foiled defines):
/// 2026-01-01T00:00:00Z.
pub const REFERENCE_EPOCH_MS: i64 = 1_767_225_600_000;

/// One attempt with its scored links and IOC notes.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct AttemptRecord {
    pub attempt: Attempt,
    /// Scored links (#27), with analyst overrides applied: CVE and technique
    /// links today. Campaign (#33) and actor (#29) links use the same type.
    /// `attempt_ioc` links are ignored here: IOCs carry their own score.
    pub links: Vec<ConfidenceLink>,
    pub file_ioc_limited: bool,
    pub notes: Vec<String>,
}

/// Everything an export is built from, for one tenant and window.
#[derive(Debug, Clone, Default)]
pub struct ExportInput {
    pub attempts: Vec<AttemptRecord>,
    /// IOCs extracted from those attempts, with enrichment context. Export
    /// redaction is applied by [`select`].
    pub iocs: Vec<Ioc>,
    /// The pinned ATT&CK sidecar, for technique names and STIX ids.
    pub attack: Option<AttackSidecar>,
}

/// Filters and opt-ins. The defaults are the safe ones.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExportOptions {
    /// 0 to 100. Links and IOCs scoring below this are dropped. This only
    /// ever narrows: it never lets anything below `publish_min` through.
    pub min_confidence: Option<u8>,
    pub catalogue_id: Option<String>,
    pub state: Option<AttemptState>,
    pub campaign_id: Option<String>,
    pub decoy_kind: Option<DecoyKind>,
    /// Include links and IOCs that are not publishable (below
    /// `publish_min`, or carried only by LLM, pre-disclosure or catalogue
    /// evidence). Only an authorised analyst may set this; the result is
    /// marked TLP:AMBER+STRICT or stricter and is never public.
    pub include_unreviewed: bool,
    /// Include actor links (#29). Off by default.
    pub include_actors: bool,
    /// Include request strings stored from bodies and request slices
    /// (`request_substring` with role `payload`). Off by default (#16).
    pub include_payloads: bool,
    pub tlp: Tlp,
}

impl Default for ExportOptions {
    fn default() -> Self {
        ExportOptions {
            min_confidence: None,
            catalogue_id: None,
            state: None,
            campaign_id: None,
            decoy_kind: None,
            include_unreviewed: false,
            include_actors: false,
            include_payloads: false,
            tlp: Tlp::Amber,
        }
    }
}

impl ExportOptions {
    /// The label the export carries: the requested one, raised to
    /// TLP:AMBER+STRICT when unreviewed material is included.
    pub fn effective_tlp(&self) -> Tlp {
        if self.include_unreviewed && self.tlp.strictness() < Tlp::AmberStrict.strictness() {
            Tlp::AmberStrict
        } else {
            self.tlp
        }
    }
}

/// What the gate removed, so an export can say so.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct Dropped {
    /// Attempts removed by the attempt filters.
    pub attempts_filtered: usize,
    /// Attempts with nothing left to export after the gate.
    pub attempts_empty: usize,
    pub iocs_below_gate: usize,
    pub links_below_gate: usize,
    /// Links or IOCs an analyst marked false positive. Never exported.
    pub suppressed: usize,
    /// Actor links left out because `include_actors` was off.
    pub actor_links: usize,
    /// Payload request strings left out because `include_payloads` was off.
    pub payload_iocs: usize,
    /// Attempts whose campaign id was removed because the campaign link
    /// did not pass the gate.
    pub campaign_ids: usize,
}

/// The gated view every serialiser reads.
#[derive(Debug, Clone, PartialEq)]
pub struct Selection {
    /// Sorted by first seen, then id. Links are gated.
    pub attempts: Vec<AttemptRecord>,
    /// Gated and redacted for export. Sorted by first seen, type, value.
    pub iocs: Vec<Ioc>,
    pub tlp: Tlp,
    /// True when `include_unreviewed` was set.
    pub unreviewed: bool,
    /// Sidecar entries for the technique links that passed.
    pub techniques: BTreeMap<String, TechniqueInfo>,
    pub attack_version: Option<String>,
    /// MITRE's notice and licence, carried by any export with techniques.
    pub attack_notice: Option<String>,
    pub dropped: Dropped,
}

impl Selection {
    /// The exported IOCs seen in one attempt.
    pub fn iocs_for<'a>(&'a self, attempt_id: &'a str) -> impl Iterator<Item = &'a Ioc> + 'a {
        self.iocs
            .iter()
            .filter(move |i| i.attempt_ids.iter().any(|a| a == attempt_id))
    }

    pub fn is_empty(&self) -> bool {
        self.attempts.is_empty() && self.iocs.is_empty()
    }
}

/// True when an analyst marked the link false positive.
pub fn suppressed(link: &ConfidenceLink) -> bool {
    link.r#override
        .as_ref()
        .is_some_and(|o| o.feedback == Feedback::FalsePositive)
}

/// True when an analyst marked the link true positive.
pub fn confirmed(link: &ConfidenceLink) -> bool {
    link.r#override
        .as_ref()
        .is_some_and(|o| o.feedback == Feedback::TruePositive)
}

fn passes(score: u8, publishable: bool, opts: &ExportOptions) -> bool {
    score >= opts.min_confidence.unwrap_or(0) && (publishable || opts.include_unreviewed)
}

pub fn attempt_matches(a: &Attempt, opts: &ExportOptions) -> bool {
    opts.catalogue_id
        .as_deref()
        .is_none_or(|c| a.catalogue_id == c)
        && opts.state.is_none_or(|s| a.state == s)
        && opts
            .campaign_id
            .as_deref()
            .is_none_or(|c| a.campaign_id.as_deref() == Some(c))
        && opts.decoy_kind.is_none_or(|k| a.decoy_kind == k)
}

fn payload_string(i: &Ioc) -> bool {
    i.ioc_type == IocType::RequestSubstring && i.roles.contains(&IocRole::Payload)
}

/// Apply the filters and the confidence gate. See the module docs.
pub fn select(input: ExportInput, opts: &ExportOptions) -> Selection {
    let mut dropped = Dropped::default();
    let mut attempts: Vec<AttemptRecord> = Vec::new();
    for mut rec in input.attempts {
        if !attempt_matches(&rec.attempt, opts) {
            dropped.attempts_filtered += 1;
            continue;
        }
        rec.links.retain(|l| {
            if l.kind == LinkKind::AttemptIoc {
                return false;
            }
            if suppressed(l) {
                dropped.suppressed += 1;
                return false;
            }
            if l.kind == LinkKind::AttemptActor && !opts.include_actors {
                dropped.actor_links += 1;
                return false;
            }
            let ok = passes(l.score, l.publishable, opts);
            if !ok {
                dropped.links_below_gate += 1;
            }
            ok
        });
        rec.links
            .sort_by(|a, b| (a.kind, &a.target).cmp(&(b.kind, &b.target)));
        attempts.push(rec);
    }
    // Campaign membership is a claim too (#33): only campaigns whose link
    // passed the gate may be named anywhere in the export.
    let published_campaigns: BTreeSet<String> = attempts
        .iter()
        .flat_map(|r| &r.links)
        .filter(|l| l.kind == LinkKind::AttemptCampaign)
        .map(|l| l.target.clone())
        .collect();
    for rec in &mut attempts {
        if rec
            .attempt
            .campaign_id
            .as_ref()
            .is_some_and(|c| !published_campaigns.contains(c))
        {
            rec.attempt.campaign_id = None;
            dropped.campaign_ids += 1;
        }
    }
    let kept: BTreeSet<&str> = attempts
        .iter()
        .map(|r| r.attempt.attempt_id.as_str())
        .collect();

    let mut iocs: Vec<Ioc> = Vec::new();
    for i in input.iocs {
        if !i.attempt_ids.iter().any(|a| kept.contains(a.as_str())) {
            continue;
        }
        if payload_string(&i) && !opts.include_payloads {
            dropped.payload_iocs += 1;
            continue;
        }
        // An IOC false-positive decision would arrive through the review
        // queue (#35); a suppressed score is 0 and never publishable.
        if !passes(i.confidence.score, i.confidence.publishable, opts) {
            dropped.iocs_below_gate += 1;
            continue;
        }
        let mut i = i;
        i.campaign_ids.retain(|c| published_campaigns.contains(c));
        iocs.push(i);
    }
    // `redact_for_export`, in place.
    for i in &mut iocs {
        i.enrichment = export_refs(&i.enrichment);
    }
    iocs.sort_by(|a, b| {
        (a.first_seen, a.ioc_type, &a.value).cmp(&(b.first_seen, b.ioc_type, &b.value))
    });

    let with_iocs: BTreeSet<&str> = iocs
        .iter()
        .flat_map(|i| i.attempt_ids.iter().map(String::as_str))
        .collect();
    let mut out_attempts = Vec::new();
    for rec in attempts {
        if rec.links.is_empty() && !with_iocs.contains(rec.attempt.attempt_id.as_str()) {
            dropped.attempts_empty += 1;
        } else {
            out_attempts.push(rec);
        }
    }
    out_attempts.sort_by(|a, b| {
        (a.attempt.first_seen, &a.attempt.attempt_id)
            .cmp(&(b.attempt.first_seen, &b.attempt.attempt_id))
    });

    let mut techniques = BTreeMap::new();
    if let Some(sidecar) = &input.attack {
        for l in out_attempts
            .iter()
            .flat_map(|r| &r.links)
            .filter(|l| l.kind == LinkKind::AttemptTechnique)
        {
            if let Some(t) = sidecar.get(&l.target) {
                techniques.insert(t.id.clone(), t.clone());
            }
        }
    }
    // Links to ATT&CK groups (#29) name MITRE content too.
    let attack_groups = out_attempts
        .iter()
        .flat_map(|r| &r.links)
        .any(crate::actor::is_attack_group_link);
    let (attack_version, attack_notice) = match &input.attack {
        Some(s) if !techniques.is_empty() || attack_groups => (
            Some(s.attack_version.clone()),
            Some(format!("{} {}", s.notice, s.licence)),
        ),
        _ => (None, None),
    };
    Selection {
        attempts: out_attempts,
        iocs,
        tlp: opts.effective_tlp(),
        unreviewed: opts.include_unreviewed,
        techniques,
        attack_version,
        attack_notice,
        dropped,
    }
}

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

/// `YYYY-MM-DDTHH:MM:SS.mmmZ` for Unix ms, the STIX 2.1 timestamp form.
pub fn timestamp(unix_ms: i64) -> String {
    let base = crate::timeline::iso(unix_ms);
    format!(
        "{}.{:03}Z",
        base.trim_end_matches('Z'),
        unix_ms.rem_euclid(1000)
    )
}

/// JSON with object keys sorted at every level (RFC 8785 for the strings
/// and integers Foiled emits), so content-derived ids do not depend on
/// serde_json features.
pub fn canonical(v: &Value) -> String {
    let mut out = String::new();
    write_canonical(v, &mut out);
    out
}

fn write_canonical(v: &Value, out: &mut String) {
    match v {
        Value::Object(m) => {
            let sorted: BTreeMap<&String, &Value> = m.iter().collect();
            out.push('{');
            for (n, (k, v)) in sorted.into_iter().enumerate() {
                if n > 0 {
                    out.push(',');
                }
                out.push_str(&Value::String(k.clone()).to_string());
                out.push(':');
                write_canonical(v, out);
            }
            out.push('}');
        }
        Value::Array(a) => {
            out.push('[');
            for (n, v) in a.iter().enumerate() {
                if n > 0 {
                    out.push(',');
                }
                write_canonical(v, out);
            }
            out.push(']');
        }
        other => out.push_str(&other.to_string()),
    }
}

pub fn band_name(b: Band) -> &'static str {
    match b {
        Band::Low => "low",
        Band::Medium => "medium",
        Band::High => "high",
    }
}

/// Link targets come from capture events; escape them like any other
/// attacker-reachable text before they go into prose.
fn target_text(link: &ConfidenceLink) -> String {
    printable(&link.target)
}

/// The sentence an export uses for a link, with the #12 and #29 wording
/// rules: "we assess as" until an analyst confirms a CVE or technique,
/// "possible association" for an actor unless the link is high and
/// analyst-confirmed. Never "confirmed" without an analyst.
pub fn link_sentence(link: &ConfidenceLink, technique: Option<&TechniqueInfo>) -> String {
    let t = target_text(link);
    let tail = format!(
        " Confidence {} of 100 ({}).",
        link.score,
        band_name(link.band)
    );
    let body = match link.kind {
        LinkKind::AttemptCve if confirmed(link) => {
            format!("An analyst confirmed this as an attempt against {t}.")
        }
        LinkKind::AttemptCve => format!("We assess as an attempt against {t}."),
        LinkKind::AttemptTechnique => {
            let named = match technique {
                Some(info) => format!("ATT&CK {t} ({})", info.name),
                None => format!("ATT&CK {t}"),
            };
            if confirmed(link) {
                format!("An analyst confirmed this attempt as {named}.")
            } else {
                format!("We assess as {named}.")
            }
        }
        LinkKind::AttemptActor if confirmed(link) && link.band == Band::High => {
            format!("Confirmed association with {t}, reviewed by an analyst.")
        }
        LinkKind::AttemptActor => {
            format!("Possible association with {t}. This is not an attribution.")
        }
        LinkKind::AttemptCampaign if confirmed(link) => {
            format!("An analyst confirmed this attempt as part of campaign {t}.")
        }
        LinkKind::AttemptCampaign => format!("Possible part of campaign {t}."),
        LinkKind::AttemptIoc => format!("We assess as indicator {t}."),
    };
    format!("{body}{tail}")
}

/// The wording an export carries for a link, from the same rules as
/// [`link_sentence`].
pub fn link_wording(link: &ConfidenceLink) -> &'static str {
    match link.kind {
        LinkKind::AttemptActor if confirmed(link) && link.band == Band::High => {
            "confirmed association"
        }
        LinkKind::AttemptActor => "possible association",
        LinkKind::AttemptCampaign if confirmed(link) => "confirmed",
        LinkKind::AttemptCampaign => "possible",
        _ if confirmed(link) => "confirmed",
        _ => "we assess as",
    }
}

/// The sentence for an IOC.
pub fn ioc_sentence(i: &Ioc) -> String {
    let attempts = i.attempt_ids.len();
    let lead = if i.confidence.wording == "confirmed" {
        "An analyst confirmed this as malicious activity"
    } else {
        "We assess as malicious activity"
    };
    let mut s = format!(
        "{lead}: {} seen at Foiled decoys, which have no legitimate users, in {attempts} attempt{} ({} sighting{}). Confidence {} of 100 ({}).",
        i.ioc_type.as_str(),
        if attempts == 1 { "" } else { "s" },
        i.sightings,
        if i.sightings == 1 { "" } else { "s" },
        i.confidence.score,
        band_name(i.confidence.band),
    );
    if i.file_ioc_limited {
        s.push_str(" Seen in an attempt where the implant may be memory-resident: no file hash is available for it.");
    }
    if i.redacted {
        s.push_str(" Secrets or personal information were removed from the value, so it is not byte-exact.");
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::confidence::{ConfidenceConfig, Evidence, EvidenceSource, Override, score};

    fn link(
        kind: LinkKind,
        target: &str,
        src: EvidenceSource,
        fb: Option<Feedback>,
    ) -> ConfidenceLink {
        score(
            &ConfidenceConfig::default(),
            kind,
            "att_1",
            target,
            vec![Evidence {
                signal_id: "s".into(),
                source: src,
                weight: 100,
                summary: "s".into(),
                reference: None,
            }],
            fb.map(|feedback| Override {
                feedback,
                analyst_id: "a".into(),
                at: 0,
                note: String::new(),
            }),
        )
        .unwrap()
    }

    #[test]
    fn namespace_is_derived_from_the_repository_url() {
        assert_eq!(
            // NAMESPACE_URL from RFC 9562.
            uuid5::uuid_v5(
                "6ba7b811-9dad-11d1-80b4-00c04fd430c8",
                "https://github.com/jusso-dev/foiled"
            ),
            FOILED_NAMESPACE
        );
    }

    #[test]
    fn timestamps_have_milliseconds() {
        assert_eq!(timestamp(1_792_285_323_004), "2026-10-18T01:02:03.004Z");
        assert_eq!(timestamp(REFERENCE_EPOCH_MS), "2026-01-01T00:00:00.000Z");
    }

    #[test]
    fn canonical_sorts_keys() {
        let v = serde_json::json!({"b": 1, "a": {"d": "x\"y", "c": [2, 1]}});
        assert_eq!(canonical(&v), r#"{"a":{"c":[2,1],"d":"x\"y"},"b":1}"#);
    }

    #[test]
    fn wording_is_cautious_until_an_analyst_confirms() {
        let cve = link(
            LinkKind::AttemptCve,
            "CVE-2099-0001",
            EvidenceSource::VulnPathHook,
            None,
        );
        assert!(
            link_sentence(&cve, None).starts_with("We assess as an attempt against CVE-2099-0001.")
        );
        assert_eq!(link_wording(&cve), "we assess as");
        let ok = link(
            LinkKind::AttemptCve,
            "CVE-2099-0001",
            EvidenceSource::VulnPathHook,
            Some(Feedback::TruePositive),
        );
        assert!(link_sentence(&ok, None).starts_with("An analyst confirmed"));

        // Actors: possible association, even when strong, unless confirmed.
        let actor = link(
            LinkKind::AttemptActor,
            "Example Group",
            EvidenceSource::VulnPathHook,
            None,
        );
        let s = link_sentence(&actor, None);
        assert!(
            s.starts_with("Possible association with Example Group."),
            "{s}"
        );
        assert!(!s.contains("onfirmed"));
        assert_eq!(link_wording(&actor), "possible association");
        let sure = link(
            LinkKind::AttemptActor,
            "Example Group",
            EvidenceSource::Llm,
            Some(Feedback::TruePositive),
        );
        assert_eq!(sure.band, Band::High);
        assert_eq!(link_wording(&sure), "confirmed association");
        let unsure = link(
            LinkKind::AttemptActor,
            "Example Group",
            EvidenceSource::Llm,
            Some(Feedback::Unsure),
        );
        assert_eq!(link_wording(&unsure), "possible association");
    }

    #[test]
    fn hostile_targets_are_escaped_in_prose() {
        let l = link(
            LinkKind::AttemptCve,
            "CVE-2099-0001\u{202E}x",
            EvidenceSource::VulnPathHook,
            None,
        );
        assert!(link_sentence(&l, None).contains("\\u{202e}"));
    }

    #[test]
    fn unreviewed_exports_are_at_least_amber_strict() {
        let mut o = ExportOptions {
            tlp: Tlp::Clear,
            include_unreviewed: true,
            ..Default::default()
        };
        assert_eq!(o.effective_tlp(), Tlp::AmberStrict);
        o.tlp = Tlp::Red;
        assert_eq!(o.effective_tlp(), Tlp::Red);
        o.include_unreviewed = false;
        o.tlp = Tlp::Green;
        assert_eq!(o.effective_tlp(), Tlp::Green);
    }
}
