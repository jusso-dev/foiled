//! Campaigns (#33): attempts (#25) clustered across decoys and sensors by
//! shared infrastructure, TTPs, targeting and payloads, kept as one
//! first-class object per cluster.
//!
//! Deterministic and explainable: the same attempts, IOCs (#34), signals
//! and analyst actions always give the same campaigns, ids and evidence, in
//! any input order. Every member lists the features that joined it, and
//! every campaign is scored with the confidence layer (#27), worded
//! "possible" until an analyst confirms it.
//!
//! Cost is bounded. Each attempt yields at most
//! [`MAX_FEATURES_PER_ATTEMPT`] join keys; attempts are blocked on those
//! keys in an inverted index and joined with union-find, so the work is
//! linear in (attempt, key) pairs and never pairwise over attempts.
//!
//! Tenant-scoped: attempts from any other tenant are ignored. There is no
//! fleet (cross-tenant) scope yet; see `docs/campaigns.md`. Actor
//! possible-association (#29) attaches to `suggested_actor_links`, which
//! clustering never fills.
//!
//! Contract: `schemas/campaign.schema.json` and
//! `schemas/campaign-action.schema.json`.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::alerting::{Alert, AlertType, Link, LinkKind as AlertLinkKind, Severity};
use crate::attack::AttackRule;
use crate::attempt::{Attempt, AttemptState, NoiseBand};
use crate::capture::CaptureEvent;
use crate::confidence::{
    Band, ConfidenceConfig, ConfidenceLink, Evidence, EvidenceSource, Feedback, LinkKind, Override,
    score,
};
use crate::cvemap::Rules;
use crate::ioc::{Extraction, Ioc, IocRole, IocType, defang};
use crate::timeline::printable;

const HOUR_MS: i64 = 3_600_000;
const DAY_MS: i64 = 24 * HOUR_MS;

/// Attempts sharing a key join only when the later one starts within this
/// long of the earlier one ending.
pub const DEFAULT_JOIN_GAP_MS: i64 = 7 * DAY_MS;
/// A campaign with no new attempt for this long is `closed`.
pub const DEFAULT_CLOSED_AFTER_MS: i64 = 7 * DAY_MS;
/// Most join keys taken from one attempt, strongest first.
pub const MAX_FEATURES_PER_ATTEMPT: usize = 64;
/// Most joins listed per member. Every join still counts for clustering.
pub const MAX_JOINS_PER_MEMBER: usize = 8;
/// Most values listed per feature in `feature_summary`.
pub const MAX_SUMMARY_VALUES: usize = 16;
/// Most IOC ids listed in `shared_ioc_ids`.
pub const MAX_SHARED_IOCS: usize = 64;
/// Most clustering evidence items scored per campaign.
pub const MAX_CONFIDENCE_ITEMS: usize = 16;
/// Most request shapes (path and user agent pairs) taken from one attempt.
pub const MAX_REQUEST_SHAPES: usize = 4;
/// Most analyst actions replayed per tenant (the newest are kept).
pub const MAX_ACTIONS: usize = 2000;
/// Longest analyst title, in characters.
pub const MAX_TITLE_CHARS: usize = 120;
/// Longest analyst note, in characters.
pub const MAX_NOTE_CHARS: usize = 1000;
/// Most attempt ids one split action may name.
pub const MAX_ACTION_ATTEMPTS: usize = 500;
/// Most campaigns one merge action may fold in.
pub const MAX_ACTION_CAMPAIGNS: usize = 20;
/// Version of the campaign id derivation.
pub const ID_VERSION: u32 = 1;

const ID_DOMAIN: &str = "foiled-campaign/v1";
/// Characters of a feature value shown in a generated title.
const TITLE_VALUE_CHARS: usize = 40;
/// SHA-256 of nothing: every empty body has it, so it joins nothing.
const EMPTY_SHA256: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

// ---------------------------------------------------------------------------
// Features
// ---------------------------------------------------------------------------

/// A join key kind. Declaration order is strength order (strong first).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Feature {
    /// Same SHA-256 of what was sent to the decoy (`payload_sha256` IOC).
    PayloadSha256,
    /// Same SHA-256 of a file the attacker left (`file_sha256` IOC).
    FileSha256,
    /// Same second-stage or callback URL.
    Stage2Url,
    /// Same callback or second-stage host name (domain or DNS query IOC).
    CallbackDomain,
    /// Same callback or second-stage address.
    CallbackIp,
    /// Same behaviour fingerprint (`bf1:`), exploit or later only.
    BehaviourFingerprint,
    /// Same command line.
    Cmdline,
    /// Same exact request string, exploit or later only.
    RequestSubstring,
    /// Same source address, both attempts at exploit or later.
    SrcIp,
    /// Same source ASN and the same CVE, exploit or later.
    AsnCve,
    /// Same source ASN and the same ATT&CK technique set, exploit or later.
    AsnTechniques,
    /// Same request path and user agent, exploit or later.
    RequestShape,
}

/// How much a feature says on its own.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Strength {
    /// An artefact that is hard to share by chance: a hash, a stage-2 URL,
    /// callback infrastructure.
    Strong,
    /// Overlapping behaviour that a public exploit can also explain.
    Medium,
    /// Two weak facts at once. Never bridges two clusters that strong or
    /// medium features already formed.
    Weak,
}

impl Strength {
    /// Evidence weight for the confidence layer (#27).
    pub fn weight(self) -> u8 {
        match self {
            Strength::Strong => 100,
            Strength::Medium => 70,
            Strength::Weak => 40,
        }
    }
}

/// The issue's four feature families.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Family {
    Infrastructure,
    Ttp,
    Targeting,
    Payload,
}

impl Feature {
    pub const ALL: [Feature; 12] = [
        Feature::PayloadSha256,
        Feature::FileSha256,
        Feature::Stage2Url,
        Feature::CallbackDomain,
        Feature::CallbackIp,
        Feature::BehaviourFingerprint,
        Feature::Cmdline,
        Feature::RequestSubstring,
        Feature::SrcIp,
        Feature::AsnCve,
        Feature::AsnTechniques,
        Feature::RequestShape,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Feature::PayloadSha256 => "payload_sha256",
            Feature::FileSha256 => "file_sha256",
            Feature::Stage2Url => "stage2_url",
            Feature::CallbackDomain => "callback_domain",
            Feature::CallbackIp => "callback_ip",
            Feature::BehaviourFingerprint => "behaviour_fingerprint",
            Feature::Cmdline => "cmdline",
            Feature::RequestSubstring => "request_substring",
            Feature::SrcIp => "src_ip",
            Feature::AsnCve => "asn_cve",
            Feature::AsnTechniques => "asn_techniques",
            Feature::RequestShape => "request_shape",
        }
    }

    pub fn strength(self) -> Strength {
        match self {
            Feature::PayloadSha256
            | Feature::FileSha256
            | Feature::Stage2Url
            | Feature::CallbackDomain
            | Feature::CallbackIp => Strength::Strong,
            Feature::BehaviourFingerprint | Feature::Cmdline | Feature::RequestSubstring => {
                Strength::Medium
            }
            Feature::SrcIp | Feature::AsnCve | Feature::AsnTechniques | Feature::RequestShape => {
                Strength::Weak
            }
        }
    }

    pub fn families(self) -> &'static [Family] {
        match self {
            Feature::PayloadSha256
            | Feature::FileSha256
            | Feature::RequestSubstring
            | Feature::RequestShape => &[Family::Payload],
            Feature::Stage2Url | Feature::CallbackDomain | Feature::CallbackIp | Feature::SrcIp => {
                &[Family::Infrastructure]
            }
            Feature::BehaviourFingerprint | Feature::Cmdline => &[Family::Ttp],
            Feature::AsnCve => &[Family::Infrastructure, Family::Targeting],
            Feature::AsnTechniques => &[Family::Infrastructure, Family::Ttp],
        }
    }

    /// Words for summaries and titles.
    pub fn label(self) -> &'static str {
        match self {
            Feature::PayloadSha256 => "payload hash",
            Feature::FileSha256 => "file hash",
            Feature::Stage2Url => "stage-2 URL",
            Feature::CallbackDomain => "callback domain",
            Feature::CallbackIp => "callback address",
            Feature::BehaviourFingerprint => "behaviour fingerprint",
            Feature::Cmdline => "command line",
            Feature::RequestSubstring => "request string",
            Feature::SrcIp => "source address",
            Feature::AsnCve => "ASN and CVE",
            Feature::AsnTechniques => "ASN and technique set",
            Feature::RequestShape => "request shape",
        }
    }
}

/// What the clustering knows about one attempt beyond the attempt itself,
/// computed from its events by [`attempt_signals`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AttemptSignals {
    /// CVE ids from CVE mapping tiers 1, 2 and 5 (#12). Hook hit CVEs are
    /// read from the attempt.
    pub cves: BTreeSet<String>,
    /// ATT&CK technique ids from the bundled rules (#26).
    pub techniques: BTreeSet<String>,
}

/// CVE and technique sets per attempt id, from the same rule packs the
/// confidence links use. Linear in events times rules.
pub fn attempt_signals(
    attempts: &[Attempt],
    events: &[CaptureEvent],
    attack_rules: &[AttackRule],
    cve_rules: &Rules,
) -> BTreeMap<String, AttemptSignals> {
    let by_id: BTreeMap<&str, &CaptureEvent> =
        events.iter().map(|e| (e.event_id.as_str(), e)).collect();
    let mut out = BTreeMap::new();
    for a in attempts {
        let mine: Vec<CaptureEvent> = a
            .event_ids
            .iter()
            .filter_map(|id| by_id.get(id.as_str()).map(|e| (*e).clone()))
            .collect();
        let tiers = crate::cvemap::evaluate(cve_rules, &mine, &[]);
        // ATT&CK rules see which signatures matched as `data.matcher_id`,
        // as in the confidence links.
        let annotated: Vec<CaptureEvent> = mine
            .into_iter()
            .map(|mut e| {
                if let Some(ids) = tiers.matcher_hits.get(&e.event_id) {
                    e.data
                        .insert("matcher_id".into(), serde_json::Value::from(ids[0].clone()));
                }
                e
            })
            .collect();
        let techniques = crate::attack::evaluate(attack_rules, &annotated)
            .iter()
            .map(|l| l.official_id().to_string())
            .collect();
        out.insert(
            a.attempt_id.clone(),
            AttemptSignals {
                cves: tiers.evidence.into_keys().collect(),
                techniques,
            },
        );
    }
    out
}

// ---------------------------------------------------------------------------
// The campaign object
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CampaignStatus {
    /// Low confidence or fewer than three attempts.
    Emerging,
    Active,
    /// No new attempt for [`Params::closed_after_ms`], or closed by an analyst.
    Closed,
}

impl CampaignStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            CampaignStatus::Emerging => "emerging",
            CampaignStatus::Active => "active",
            CampaignStatus::Closed => "closed",
        }
    }
}

/// Who may see the campaign. Only `tenant` exists: a fleet scope for shared
/// research sensors needs an explicit research operator first.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TenantScope {
    Tenant,
}

/// One feature that joined a member to another member.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Join {
    /// `campaign:<feature>:<hash>`, the confidence evidence id.
    pub signal_id: String,
    pub feature: Feature,
    pub families: Vec<Family>,
    pub strength: Strength,
    pub weight: u8,
    /// Defanged and escaped for people. Never parse this.
    pub display: String,
    /// The member this one shares the feature with (its neighbour in time).
    pub with_attempt_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ioc_id: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActionKind {
    /// Set the campaign title.
    Label,
    /// Set or clear a status override.
    Status,
    /// Fold other campaigns into this one.
    Merge,
    /// Move attempts out into a campaign of their own.
    Split,
    /// Confirm (`true_positive`), reject or comment on the campaign (#27).
    Feedback,
}

impl ActionKind {
    pub fn as_str(self) -> &'static str {
        match self {
            ActionKind::Label => "label",
            ActionKind::Status => "status",
            ActionKind::Merge => "merge",
            ActionKind::Split => "split",
            ActionKind::Feedback => "feedback",
        }
    }
}

/// Set on a member that is in the campaign because of an analyst action.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AddedBy {
    pub action_id: String,
    pub kind: ActionKind,
    pub analyst_id: String,
    pub at: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Member {
    pub attempt_id: String,
    pub decoy_id: String,
    pub catalogue_id: String,
    pub sensor_id: Option<String>,
    pub src: String,
    pub first_seen: i64,
    pub last_seen: i64,
    pub state: AttemptState,
    pub noise_score: Option<u8>,
    /// Up to [`MAX_JOINS_PER_MEMBER`] features shared with other members,
    /// strongest first.
    pub joined_by: Vec<Join>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub added_by: Option<AddedBy>,
}

/// The attempt the campaign id is derived from, and what joined it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Seed {
    pub attempt_id: String,
    pub features: Vec<Feature>,
}

/// Distinct values of one feature, display-safe.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Counted {
    pub count: u32,
    /// Up to [`MAX_SUMMARY_VALUES`], sorted. Defanged and escaped.
    pub values: Vec<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InfrastructureSummary {
    /// Every member's source address.
    pub src_ips: Counted,
    /// Every member source's ASN, where enrichment knows it (#11).
    pub asns: Vec<u32>,
    pub stage2_urls: Counted,
    pub callback_domains: Counted,
    pub callback_ips: Counted,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TtpSummary {
    /// ATT&CK technique ids seen on any member (#26).
    pub techniques: Vec<String>,
    pub behaviour_fingerprints: Counted,
    pub cmdlines: Counted,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PayloadSummary {
    pub payload_sha256: Counted,
    pub file_sha256: Counted,
    pub request_substrings: Counted,
    pub request_shapes: Counted,
}

/// Mass versus selective targeting (`docs/campaigns.md#targeting-pattern`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TargetingPattern {
    Mass,
    Mixed,
    Selective,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NoiseBands {
    pub targeted: u32,
    pub mixed: u32,
    pub mass: u32,
    pub unknown: u32,
}

/// When the campaign hit a CVE relative to its advisory (#12).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdvisoryTiming {
    pub cve_id: String,
    pub published_at: i64,
    /// First member attempt with this CVE.
    pub first_seen: i64,
    /// Whole hours from publication to `first_seen`; negative before it.
    pub offset_hours: i64,
    pub before_disclosure: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Targeting {
    pub pattern: TargetingPattern,
    pub attempts: u32,
    pub sources: u32,
    pub decoys_touched: u32,
    pub sensors_touched: u32,
    pub products_touched: u32,
    /// Decoys with attacker-facing traffic in the window that run a product
    /// the campaign touched.
    pub visible_decoys: u32,
    /// `decoys_touched` as a percentage of `visible_decoys`.
    pub coverage_pct: u8,
    pub noise_bands: NoiseBands,
    pub catalogue_ids: Vec<String>,
    pub cves: Vec<String>,
    pub advisory_timing: Vec<AdvisoryTiming>,
    /// Every reason for `pattern`, in words.
    pub evidence: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FeatureSummary {
    pub infrastructure: InfrastructureSummary,
    pub ttp: TtpSummary,
    pub targeting: Targeting,
    pub payload: PayloadSummary,
}

/// The #27 score for the campaign, condensed from a `ConfidenceLink` of
/// kind `attempt_campaign` (attempt: the seed, target: the campaign).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CampaignConfidence {
    pub score: u8,
    pub band: Band,
    pub wording: String,
    pub publishable: bool,
    pub evidence: Vec<Evidence>,
    pub caps_applied: Vec<String>,
}

/// Attachment point for actor possible-association (#29). Clustering never
/// fills this; #29 does, through #27, with "possible association" wording
/// unless an analyst confirms a high link.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActorSuggestion {
    pub label: String,
    pub wording: String,
    pub confidence_ref: String,
    pub report_urls: Vec<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AnalystState {
    /// Escaped analyst title, when one was set.
    pub title: Option<String>,
    /// Status override, when one was set.
    pub status: Option<CampaignStatus>,
    /// The latest feedback on the campaign (#27).
    pub feedback: Option<Override>,
    /// Campaign ids folded into this one by merges.
    pub merged_from: Vec<String>,
    /// The campaign this one was split out of.
    pub split_from: Option<String>,
    /// Actions applied, oldest first.
    pub action_ids: Vec<String>,
}

/// One campaign. Mirrors `schemas/campaign.schema.json`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Campaign {
    /// `cmp_` plus 24 hex characters (see [`campaign_id`]).
    pub campaign_id: String,
    pub tenant_id: String,
    pub tenant_scope: TenantScope,
    /// Escaped. An analyst title when set, otherwise generated.
    pub title: String,
    pub status: CampaignStatus,
    pub first_seen: i64,
    pub last_seen: i64,
    pub seed: Seed,
    /// Every member, oldest first.
    pub attempt_ids: Vec<String>,
    pub decoy_ids: Vec<String>,
    pub sensor_ids: Vec<String>,
    pub catalogue_ids: Vec<String>,
    pub members: Vec<Member>,
    pub feature_summary: FeatureSummary,
    /// IOC ids seen in at least two members (#34).
    pub shared_ioc_ids: Vec<String>,
    /// Where the full #27 explanation lives.
    pub confidence_ref: String,
    pub confidence: CampaignConfidence,
    /// Reserved for #29. Always empty from clustering.
    pub suggested_actor_links: Vec<ActorSuggestion>,
    pub analyst: AnalystState,
    pub notes: Vec<String>,
}

/// A campaign named by an analyst action, with the attempt that anchors it
/// (its seed when the action was taken). Actions follow the anchor, so they
/// still apply when a wider window gives the campaign a different id.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CampaignRef {
    pub campaign_id: String,
    pub anchor_attempt_id: String,
}

/// One audited analyst action. Mirrors `schemas/campaign-action.schema.json`.
/// Actions are stored, never edited, and replayed in `(at, action_id)` order
/// over the computed clustering.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CampaignAction {
    pub action_id: String,
    pub kind: ActionKind,
    pub campaign_id: String,
    pub anchor_attempt_id: String,
    /// `label`: the new title.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    /// `status`: the override; absent clears it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<CampaignStatus>,
    /// `merge`: campaigns to fold in.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub merge: Vec<CampaignRef>,
    /// `split`: attempts to move out.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub attempt_ids: Vec<String>,
    /// `feedback`: the decision.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub feedback: Option<Feedback>,
    pub note: String,
    pub analyst_id: String,
    pub at: i64,
}

impl CampaignAction {
    /// Problems with the action's own fields. The API also checks that the
    /// campaigns and attempts it names exist.
    pub fn problems(&self) -> Vec<String> {
        let mut out = Vec::new();
        if self.note.chars().count() > MAX_NOTE_CHARS {
            out.push(format!("note must be at most {MAX_NOTE_CHARS} characters"));
        }
        let want = |ok: bool, what: &str, out: &mut Vec<String>| {
            if !ok {
                out.push(format!("{} needs {what}", self.kind.as_str()));
            }
        };
        let only = |present: bool, field: &str, kind: ActionKind, out: &mut Vec<String>| {
            if present && self.kind != kind {
                out.push(format!("{field} is only for {}", kind.as_str()));
            }
        };
        only(self.title.is_some(), "title", ActionKind::Label, &mut out);
        only(
            self.status.is_some(),
            "status",
            ActionKind::Status,
            &mut out,
        );
        only(
            !self.merge.is_empty(),
            "campaign_ids",
            ActionKind::Merge,
            &mut out,
        );
        only(
            !self.attempt_ids.is_empty(),
            "attempt_ids",
            ActionKind::Split,
            &mut out,
        );
        only(
            self.feedback.is_some(),
            "feedback",
            ActionKind::Feedback,
            &mut out,
        );
        match self.kind {
            ActionKind::Label => {
                let t = self.title.as_deref().unwrap_or("").trim();
                want(!t.is_empty(), "a title", &mut out);
                if t.chars().count() > MAX_TITLE_CHARS {
                    out.push(format!(
                        "title must be at most {MAX_TITLE_CHARS} characters"
                    ));
                }
            }
            ActionKind::Status => {}
            ActionKind::Merge => {
                want(!self.merge.is_empty(), "campaign_ids", &mut out);
                if self.merge.len() > MAX_ACTION_CAMPAIGNS {
                    out.push(format!(
                        "merge takes at most {MAX_ACTION_CAMPAIGNS} campaigns"
                    ));
                }
            }
            ActionKind::Split => {
                want(!self.attempt_ids.is_empty(), "attempt_ids", &mut out);
                if self.attempt_ids.len() > MAX_ACTION_ATTEMPTS {
                    out.push(format!(
                        "split takes at most {MAX_ACTION_ATTEMPTS} attempts"
                    ));
                }
            }
            ActionKind::Feedback => want(self.feedback.is_some(), "feedback", &mut out),
        }
        out
    }
}

/// Everything clustering reads. Attempts and IOCs must come from the same
/// window build.
pub struct Input<'a> {
    pub tenant_id: &'a str,
    pub attempts: &'a [Attempt],
    pub iocs: &'a Extraction,
    /// By attempt id, from [`attempt_signals`].
    pub signals: &'a BTreeMap<String, AttemptSignals>,
    /// Source address to ASN number, from enrichment Facts (#11).
    pub asns: &'a BTreeMap<String, u32>,
    /// CVE id to advisory publication time in Unix ms (#12).
    pub advisories: &'a BTreeMap<String, i64>,
    pub actions: &'a [CampaignAction],
    /// Unix ms, for `closed`.
    pub now: i64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Params {
    pub join_gap_ms: i64,
    pub closed_after_ms: i64,
}

impl Default for Params {
    fn default() -> Self {
        Params {
            join_gap_ms: DEFAULT_JOIN_GAP_MS,
            closed_after_ms: DEFAULT_CLOSED_AFTER_MS,
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Clustering {
    /// Sorted by first seen, then id.
    pub campaigns: Vec<Campaign>,
    /// Skipped analyst actions, refused bridges and dissolved campaigns.
    pub notes: Vec<String>,
}

impl Clustering {
    pub fn get(&self, campaign_id: &str) -> Option<&Campaign> {
        self.campaigns.iter().find(|c| c.campaign_id == campaign_id)
    }

    /// Campaign id per member attempt id.
    pub fn membership(&self) -> BTreeMap<&str, &str> {
        self.campaigns
            .iter()
            .flat_map(|c| {
                c.attempt_ids
                    .iter()
                    .map(move |a| (a.as_str(), c.campaign_id.as_str()))
            })
            .collect()
    }
}

/// `cmp_` plus 24 hex characters of SHA-256 over the tenant and the seed
/// attempt (the earliest member). The seed's features are recorded in
/// `seed`, not hashed: hashing them would change the id every time the
/// campaign grew through a different feature.
pub fn campaign_id(tenant_id: &str, seed_attempt_id: &str) -> String {
    hash_id(&format!("{ID_DOMAIN}\n{tenant_id}\n{seed_attempt_id}"))
}

/// Id for the attempts a split action moves out.
pub fn split_campaign_id(tenant_id: &str, action_id: &str) -> String {
    hash_id(&format!("{ID_DOMAIN}\nsplit\n{tenant_id}\n{action_id}"))
}

fn hash_id(s: &str) -> String {
    let h = Sha256::digest(s.as_bytes());
    format!("cmp_{}", hex::encode(&h[..12]))
}

/// True for ids of the `cmp_` form.
pub fn valid_campaign_id(id: &str) -> bool {
    id.strip_prefix("cmp_").is_some_and(|h| {
        h.len() == 24
            && h.bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    })
}

// ---------------------------------------------------------------------------
// Clustering
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct Key {
    feature: Feature,
    value: String,
}

impl Key {
    fn signal_id(&self) -> String {
        let h = Sha256::digest(format!("{}\n{}", self.feature.as_str(), self.value).as_bytes());
        format!(
            "campaign:{}:{}",
            self.feature.as_str(),
            hex::encode(&h[..6])
        )
    }
}

#[derive(Debug, Clone)]
struct KeyInfo {
    display: String,
    ioc_id: Option<String>,
}

fn ip_display(ip: &str) -> String {
    defang(
        if ip.contains(':') {
            IocType::Ipv6
        } else {
            IocType::Ip
        },
        ip,
    )
}

fn has_role(i: &Ioc, roles: &[IocRole]) -> bool {
    i.roles.iter().any(|r| roles.contains(r))
}

/// Join keys for one attempt, strongest first, at most
/// [`MAX_FEATURES_PER_ATTEMPT`]. Returns whether any were dropped.
fn keys_for(
    a: &Attempt,
    iocs: &BTreeMap<&str, &Ioc>,
    refs: &[String],
    signals: Option<&AttemptSignals>,
    asn: Option<u32>,
    info: &mut BTreeMap<Key, KeyInfo>,
) -> (Vec<Key>, bool) {
    let exploit = a.state >= AttemptState::Exploit;
    let mut out: BTreeMap<Key, KeyInfo> = BTreeMap::new();
    let mut add = |feature: Feature, value: String, display: String, ioc_id: Option<String>| {
        out.entry(Key { feature, value })
            .or_insert(KeyInfo { display, ioc_id });
    };
    let callback = [IocRole::Callback, IocRole::Stage2];
    let mut paths: Vec<&Ioc> = Vec::new();
    let mut uas: Vec<&Ioc> = Vec::new();
    for r in refs {
        let Some(i) = iocs.get(r.as_str()) else {
            continue;
        };
        let id = Some(i.ioc_id.clone());
        let lower = i.value.to_ascii_lowercase();
        match i.ioc_type {
            IocType::PayloadSha256 if lower != EMPTY_SHA256 => {
                add(Feature::PayloadSha256, lower, i.display.clone(), id);
            }
            IocType::FileSha256 if lower != EMPTY_SHA256 => {
                add(Feature::FileSha256, lower, i.display.clone(), id);
            }
            IocType::Url if has_role(i, &callback) => {
                add(Feature::Stage2Url, i.value.clone(), i.display.clone(), id);
            }
            IocType::Domain | IocType::DnsQuery if has_role(i, &callback) => {
                let name = lower.trim_end_matches('.').to_string();
                let display = defang(IocType::Domain, &name);
                add(Feature::CallbackDomain, name, display, id);
            }
            IocType::Ip | IocType::Ipv6 if has_role(i, &callback) => {
                add(Feature::CallbackIp, lower, i.display.clone(), id);
            }
            IocType::BehaviourFingerprint => {
                add(Feature::BehaviourFingerprint, lower, i.display.clone(), id);
            }
            IocType::Cmdline => add(Feature::Cmdline, i.value.clone(), i.display.clone(), id),
            IocType::RequestSubstring if exploit => {
                add(
                    Feature::RequestSubstring,
                    i.value.clone(),
                    i.display.clone(),
                    id,
                );
            }
            IocType::HttpPath if exploit => paths.push(i),
            IocType::HttpUa if exploit => uas.push(i),
            _ => {}
        }
    }
    let mut shapes = 0;
    'shapes: for p in &paths {
        for u in &uas {
            if shapes == MAX_REQUEST_SHAPES {
                break 'shapes;
            }
            shapes += 1;
            add(
                Feature::RequestShape,
                format!("{}\n{}", p.value, u.value),
                format!("{} with {}", p.display, u.display),
                None,
            );
        }
    }
    if exploit {
        add(
            Feature::SrcIp,
            a.src.to_ascii_lowercase(),
            ip_display(&a.src),
            None,
        );
        if let Some(asn) = asn {
            let mut cves: BTreeSet<String> = a
                .hook_hits
                .iter()
                .filter_map(|h| h.cve_id.as_deref())
                .map(str::to_ascii_uppercase)
                .collect();
            if let Some(s) = signals {
                cves.extend(s.cves.iter().map(|c| c.to_ascii_uppercase()));
            }
            for c in cves {
                add(
                    Feature::AsnCve,
                    format!("AS{asn}\n{c}"),
                    format!("AS{asn} and {}", printable(&c)),
                    None,
                );
            }
            if let Some(s) = signals.filter(|s| !s.techniques.is_empty()) {
                let set: Vec<&str> = s.techniques.iter().map(String::as_str).collect();
                let joined = set.join(",");
                add(
                    Feature::AsnTechniques,
                    format!("AS{asn}\n{joined}"),
                    format!("AS{asn} and {}", printable(&joined)),
                    None,
                );
            }
        }
    }
    let dropped = out.len() > MAX_FEATURES_PER_ATTEMPT;
    let keys: Vec<Key> = out
        .into_iter()
        .take(MAX_FEATURES_PER_ATTEMPT)
        .map(|(k, v)| {
            info.entry(k.clone()).or_insert(v);
            k
        })
        .collect();
    (keys, dropped)
}

struct Dsu {
    parent: Vec<usize>,
    size: Vec<usize>,
    /// Holds a cluster formed by strong or medium features.
    established: Vec<bool>,
}

impl Dsu {
    fn new(n: usize) -> Self {
        Dsu {
            parent: (0..n).collect(),
            size: vec![1; n],
            established: vec![false; n],
        }
    }

    fn find(&mut self, mut x: usize) -> usize {
        while self.parent[x] != x {
            self.parent[x] = self.parent[self.parent[x]];
            x = self.parent[x];
        }
        x
    }

    fn union(&mut self, a: usize, b: usize) {
        let (a, b) = (self.find(a), self.find(b));
        if a == b {
            return;
        }
        // Larger tree is the root; ties go to the lower index.
        let (root, child) = if (self.size[a], b) >= (self.size[b], a) {
            (a, b)
        } else {
            (b, a)
        };
        self.parent[child] = root;
        self.size[root] += self.size[child];
        self.established[root] |= self.established[child];
    }
}

/// A cluster while analyst actions are replayed.
struct Group {
    seed: usize,
    members: BTreeSet<usize>,
    added_by: BTreeMap<usize, AddedBy>,
    analyst: AnalystState,
}

/// Cluster a tenant's attempts into campaigns and apply analyst actions.
pub fn cluster(input: &Input<'_>, params: Params, cfg: &ConfidenceConfig) -> Clustering {
    let mut attempts: Vec<&Attempt> = input
        .attempts
        .iter()
        .filter(|a| a.tenant_id == input.tenant_id)
        .collect();
    attempts.sort_by(|a, b| (a.first_seen, &a.attempt_id).cmp(&(b.first_seen, &b.attempt_id)));
    attempts.dedup_by(|a, b| a.attempt_id == b.attempt_id);
    let n = attempts.len();
    let idx_of: BTreeMap<&str, usize> = attempts
        .iter()
        .enumerate()
        .map(|(i, a)| (a.attempt_id.as_str(), i))
        .collect();
    let ioc_index: BTreeMap<&str, &Ioc> = input
        .iocs
        .iocs
        .iter()
        .map(|i| (i.ioc_id.as_str(), i))
        .collect();
    let refs: BTreeMap<&str, &[String]> = input
        .iocs
        .attempts
        .iter()
        .map(|x| (x.attempt_id.as_str(), x.ioc_refs.as_slice()))
        .collect();

    // Blocking: one posting list per key, in time order.
    let mut info: BTreeMap<Key, KeyInfo> = BTreeMap::new();
    let mut index: BTreeMap<Key, Vec<usize>> = BTreeMap::new();
    let mut keys_of: Vec<Vec<Key>> = Vec::with_capacity(n);
    let mut truncated: BTreeSet<usize> = BTreeSet::new();
    for (i, a) in attempts.iter().enumerate() {
        let (keys, dropped) = keys_for(
            a,
            &ioc_index,
            refs.get(a.attempt_id.as_str()).copied().unwrap_or(&[]),
            input.signals.get(&a.attempt_id),
            input.asns.get(&a.src).copied(),
            &mut info,
        );
        if dropped {
            truncated.insert(i);
        }
        for k in &keys {
            index.entry(k.clone()).or_default().push(i);
        }
        keys_of.push(keys);
    }

    // Union-find: strong and medium keys first, then weak keys, which may
    // attach stragglers but never bridge two established clusters.
    let mut dsu = Dsu::new(n);
    let mut edges: Vec<Vec<(Key, usize)>> = vec![Vec::new(); n];
    let mut refused = 0usize;
    for weak_pass in [false, true] {
        if weak_pass {
            for i in 0..n {
                let r = dsu.find(i);
                if dsu.size[r] >= 2 {
                    dsu.established[r] = true;
                }
            }
        }
        for (key, posting) in &index {
            if (key.feature.strength() == Strength::Weak) != weak_pass {
                continue;
            }
            for w in posting.windows(2) {
                let (p, c) = (w[0], w[1]);
                if attempts[c].first_seen - attempts[p].last_seen > params.join_gap_ms {
                    continue;
                }
                let (rp, rc) = (dsu.find(p), dsu.find(c));
                if rp != rc {
                    if weak_pass && dsu.established[rp] && dsu.established[rc] {
                        refused += 1;
                        continue;
                    }
                    dsu.union(rp, rc);
                }
                edges[p].push((key.clone(), c));
                edges[c].push((key.clone(), p));
            }
        }
    }

    let mut by_root: BTreeMap<usize, BTreeSet<usize>> = BTreeMap::new();
    for i in 0..n {
        let r = dsu.find(i);
        by_root.entry(r).or_default().insert(i);
    }
    let mut groups: BTreeMap<String, Group> = BTreeMap::new();
    let mut member_of: Vec<Option<String>> = vec![None; n];
    for members in by_root.into_values().filter(|m| m.len() >= 2) {
        let seed = *members.iter().next().expect("non-empty");
        let id = campaign_id(input.tenant_id, &attempts[seed].attempt_id);
        for &m in &members {
            member_of[m] = Some(id.clone());
        }
        groups.insert(
            id,
            Group {
                seed,
                members,
                added_by: BTreeMap::new(),
                analyst: AnalystState::default(),
            },
        );
    }

    let mut notes = Vec::new();
    if refused > 0 {
        notes.push(format!(
            "{refused} weak feature join(s) were not used because they would have bridged two \
             campaigns already formed by strong or medium features."
        ));
    }
    apply_actions(
        input,
        &idx_of,
        &edges,
        &mut groups,
        &mut member_of,
        &mut notes,
    );

    // Visible decoys per product, for the targeting pattern.
    let mut decoys_by_product: BTreeMap<&str, BTreeSet<&str>> = BTreeMap::new();
    for a in &attempts {
        decoys_by_product
            .entry(a.catalogue_id.as_str())
            .or_default()
            .insert(a.decoy_id.as_str());
    }
    let ctx = BuildCtx {
        input,
        params,
        cfg,
        attempts: &attempts,
        keys_of: &keys_of,
        edges: &edges,
        info: &info,
        refs: &refs,
        decoys_by_product: &decoys_by_product,
        truncated: &truncated,
    };
    let mut campaigns: Vec<Campaign> = Vec::new();
    for (id, g) in groups {
        if g.members.len() < 2 {
            notes.push(format!(
                "Campaign {id} has fewer than two attempts after analyst actions and is not shown."
            ));
            continue;
        }
        campaigns.push(build_campaign(&ctx, id, g));
    }
    campaigns.sort_by(|a, b| (a.first_seen, &a.campaign_id).cmp(&(b.first_seen, &b.campaign_id)));
    Clustering { campaigns, notes }
}

fn apply_actions(
    input: &Input<'_>,
    idx_of: &BTreeMap<&str, usize>,
    edges: &[Vec<(Key, usize)>],
    groups: &mut BTreeMap<String, Group>,
    member_of: &mut [Option<String>],
    notes: &mut Vec<String>,
) {
    let mut actions: Vec<&CampaignAction> = input.actions.iter().collect();
    actions.sort_by(|a, b| (a.at, &a.action_id).cmp(&(b.at, &b.action_id)));
    let skip = actions.len().saturating_sub(MAX_ACTIONS);
    if skip > 0 {
        notes.push(format!(
            "{skip} older analyst action(s) were not replayed: at most {MAX_ACTIONS} are."
        ));
    }
    let group_of = |member_of: &[Option<String>], attempt_id: &str| {
        idx_of.get(attempt_id).and_then(|&i| member_of[i].clone())
    };
    for a in actions.into_iter().skip(skip) {
        let Some(gid) = group_of(member_of, &a.anchor_attempt_id) else {
            notes.push(format!(
                "Analyst action {} was not applied: campaign {} has no clustered attempts in \
                 this window.",
                printable(&a.action_id),
                printable(&a.campaign_id)
            ));
            continue;
        };
        let by = AddedBy {
            action_id: a.action_id.clone(),
            kind: a.kind,
            analyst_id: a.analyst_id.clone(),
            at: a.at,
        };
        match a.kind {
            ActionKind::Label => {
                let g = groups.get_mut(&gid).expect("group exists");
                if let Some(t) = a.title.as_deref().map(str::trim).filter(|t| !t.is_empty()) {
                    let t: String = t.chars().take(MAX_TITLE_CHARS).collect();
                    g.analyst.title = Some(printable(&t));
                }
            }
            ActionKind::Status => {
                groups.get_mut(&gid).expect("group exists").analyst.status = a.status;
            }
            ActionKind::Feedback => {
                if let Some(f) = a.feedback {
                    groups.get_mut(&gid).expect("group exists").analyst.feedback = Some(Override {
                        feedback: f,
                        analyst_id: a.analyst_id.clone(),
                        at: a.at,
                        note: a.note.clone(),
                    });
                }
            }
            ActionKind::Merge => {
                for r in a.merge.iter().take(MAX_ACTION_CAMPAIGNS) {
                    let Some(other) = group_of(member_of, &r.anchor_attempt_id) else {
                        notes.push(format!(
                            "Analyst action {} could not merge campaign {}: it has no clustered \
                             attempts in this window.",
                            printable(&a.action_id),
                            printable(&r.campaign_id)
                        ));
                        continue;
                    };
                    if other == gid {
                        continue;
                    }
                    let o = groups.remove(&other).expect("group exists");
                    let g = groups.get_mut(&gid).expect("group exists");
                    for &m in &o.members {
                        member_of[m] = Some(gid.clone());
                        g.members.insert(m);
                        g.added_by.insert(m, by.clone());
                    }
                    g.analyst.merged_from.push(other);
                    g.analyst.merged_from.extend(o.analyst.merged_from);
                }
            }
            ActionKind::Split => {
                let g = groups.get(&gid).expect("group exists");
                let moving: BTreeSet<usize> = a
                    .attempt_ids
                    .iter()
                    .take(MAX_ACTION_ATTEMPTS)
                    .filter_map(|id| idx_of.get(id.as_str()).copied())
                    .filter(|i| g.members.contains(i))
                    .collect();
                if moving.is_empty() || moving.len() == g.members.len() {
                    notes.push(format!(
                        "Analyst action {} was not applied: a split must leave attempts on both \
                         sides.",
                        printable(&a.action_id)
                    ));
                } else {
                    split(input, a, &gid, &moving, &by, edges, groups, member_of);
                }
            }
        }
        if let Some(g) = groups.get_mut(&gid) {
            g.analyst.action_ids.push(a.action_id.clone());
        }
    }
}

/// Split `moving` out of group `gid`. The side holding the seed keeps the
/// campaign id; the other side gets [`split_campaign_id`].
#[allow(clippy::too_many_arguments)]
fn split(
    input: &Input<'_>,
    a: &CampaignAction,
    gid: &str,
    moving: &BTreeSet<usize>,
    by: &AddedBy,
    edges: &[Vec<(Key, usize)>],
    groups: &mut BTreeMap<String, Group>,
    member_of: &mut [Option<String>],
) {
    let g = groups.get_mut(gid).expect("group exists");
    let rest: BTreeSet<usize> = g.members.difference(moving).copied().collect();
    let (keep, out) = if moving.contains(&g.seed) {
        (moving.clone(), rest)
    } else {
        (rest, moving.clone())
    };
    let new_id = split_campaign_id(input.tenant_id, &a.action_id);
    let mut new_added = BTreeMap::new();
    for &m in &out {
        g.added_by.remove(&m);
        member_of[m] = Some(new_id.clone());
    }
    g.members = keep;
    for &m in moving {
        if g.members.contains(&m) {
            g.added_by.insert(m, by.clone());
        } else {
            new_added.insert(m, by.clone());
        }
    }
    // Members left with no join inside their side stay by the analyst's
    // decision, so say so.
    let orphaned =
        |members: &BTreeSet<usize>, m: usize| !edges[m].iter().any(|(_, o)| members.contains(o));
    let keep_orphans: Vec<usize> = g
        .members
        .iter()
        .copied()
        .filter(|&m| orphaned(&g.members, m))
        .collect();
    for m in keep_orphans {
        g.added_by.entry(m).or_insert_with(|| by.clone());
    }
    for &m in &out {
        if orphaned(&out, m) {
            new_added.entry(m).or_insert_with(|| by.clone());
        }
    }
    let seed = *out.iter().next().expect("non-empty");
    groups.insert(
        new_id,
        Group {
            seed,
            members: out,
            added_by: new_added,
            analyst: AnalystState {
                split_from: Some(gid.to_string()),
                action_ids: vec![a.action_id.clone()],
                ..AnalystState::default()
            },
        },
    );
}

struct BuildCtx<'a, 'b> {
    input: &'a Input<'b>,
    params: Params,
    cfg: &'a ConfidenceConfig,
    attempts: &'a [&'a Attempt],
    keys_of: &'a [Vec<Key>],
    edges: &'a [Vec<(Key, usize)>],
    info: &'a BTreeMap<Key, KeyInfo>,
    refs: &'a BTreeMap<&'a str, &'a [String]>,
    decoys_by_product: &'a BTreeMap<&'a str, BTreeSet<&'a str>>,
    truncated: &'a BTreeSet<usize>,
}

fn counted(values: impl IntoIterator<Item = String>) -> Counted {
    let all: BTreeSet<String> = values.into_iter().collect();
    Counted {
        count: u32::try_from(all.len()).unwrap_or(u32::MAX),
        values: all.into_iter().take(MAX_SUMMARY_VALUES).collect(),
    }
}

fn u32_len(n: usize) -> u32 {
    u32::try_from(n).unwrap_or(u32::MAX)
}

fn build_campaign(ctx: &BuildCtx<'_, '_>, campaign_id: String, g: Group) -> Campaign {
    let atts = ctx.attempts;
    let members_idx: Vec<usize> = g.members.iter().copied().collect();

    // Joins per member, inside the campaign only, strongest first.
    let mut members = Vec::with_capacity(members_idx.len());
    for &m in &members_idx {
        let mut seen: BTreeSet<&Key> = BTreeSet::new();
        let mut joins: Vec<(&Key, usize)> = Vec::new();
        for (k, o) in &ctx.edges[m] {
            if g.members.contains(o) && seen.insert(k) {
                joins.push((k, *o));
            }
        }
        joins.sort_by(|x, y| x.0.cmp(y.0));
        let a = atts[m];
        members.push(Member {
            attempt_id: a.attempt_id.clone(),
            decoy_id: a.decoy_id.clone(),
            catalogue_id: a.catalogue_id.clone(),
            sensor_id: a.sensor_id.clone(),
            src: a.src.clone(),
            first_seen: a.first_seen,
            last_seen: a.last_seen,
            state: a.state,
            noise_score: a.noise.as_ref().map(|n| n.score),
            joined_by: joins
                .into_iter()
                .take(MAX_JOINS_PER_MEMBER)
                .map(|(k, o)| join(ctx, k, atts[o]))
                .collect(),
            added_by: g.added_by.get(&m).cloned(),
        });
    }

    // Keys shared inside the campaign, with how many members share each.
    let mut shared: BTreeMap<&Key, usize> = BTreeMap::new();
    for &m in &members_idx {
        let mut mine: BTreeSet<&Key> = BTreeSet::new();
        for (k, o) in &ctx.edges[m] {
            if g.members.contains(o) {
                mine.insert(k);
            }
        }
        for k in mine {
            *shared.entry(k).or_default() += 1;
        }
    }
    // Values of every key held by two or more members, for the summary.
    let mut held: BTreeMap<&Key, usize> = BTreeMap::new();
    for &m in &members_idx {
        for k in &ctx.keys_of[m] {
            *held.entry(k).or_default() += 1;
        }
    }
    let shared_values = |f: Feature| {
        counted(
            held.iter()
                .filter(|(k, n)| k.feature == f && **n >= 2)
                .filter_map(|(k, _)| ctx.info.get(*k).map(|i| i.display.clone())),
        )
    };

    let mut cves: BTreeSet<String> = BTreeSet::new();
    let mut cve_first: BTreeMap<String, i64> = BTreeMap::new();
    let mut techniques: BTreeSet<String> = BTreeSet::new();
    for &m in &members_idx {
        let a = atts[m];
        let mut mine: BTreeSet<String> = a
            .hook_hits
            .iter()
            .filter_map(|h| h.cve_id.as_deref())
            .map(str::to_ascii_uppercase)
            .collect();
        if let Some(s) = ctx.input.signals.get(&a.attempt_id) {
            mine.extend(s.cves.iter().map(|c| c.to_ascii_uppercase()));
            techniques.extend(s.techniques.iter().map(|t| printable(t)));
        }
        for c in mine {
            let e = cve_first.entry(c.clone()).or_insert(a.first_seen);
            *e = (*e).min(a.first_seen);
            cves.insert(c);
        }
    }

    let infrastructure = InfrastructureSummary {
        src_ips: counted(members_idx.iter().map(|&m| ip_display(&atts[m].src))),
        asns: members_idx
            .iter()
            .filter_map(|&m| ctx.input.asns.get(&atts[m].src).copied())
            .collect::<BTreeSet<u32>>()
            .into_iter()
            .collect(),
        stage2_urls: shared_values(Feature::Stage2Url),
        callback_domains: shared_values(Feature::CallbackDomain),
        callback_ips: shared_values(Feature::CallbackIp),
    };
    let ttp = TtpSummary {
        techniques: techniques.into_iter().collect(),
        behaviour_fingerprints: shared_values(Feature::BehaviourFingerprint),
        cmdlines: shared_values(Feature::Cmdline),
    };
    let payload = PayloadSummary {
        payload_sha256: shared_values(Feature::PayloadSha256),
        file_sha256: shared_values(Feature::FileSha256),
        request_substrings: shared_values(Feature::RequestSubstring),
        request_shapes: shared_values(Feature::RequestShape),
    };
    let targeting = targeting(ctx, &members_idx, &cves, &cve_first);

    // Confidence: one clustering item per shared key, strongest and most
    // shared first, plus the lowest member noise score.
    let mut ranked: Vec<(&Key, usize)> = shared.into_iter().collect();
    ranked.sort_by(|a, b| {
        (a.0.feature.strength(), std::cmp::Reverse(a.1), a.0).cmp(&(
            b.0.feature.strength(),
            std::cmp::Reverse(b.1),
            b.0,
        ))
    });
    let mut evidence: Vec<Evidence> = ranked
        .iter()
        .take(MAX_CONFIDENCE_ITEMS)
        .map(|(k, count)| {
            let i = ctx.info.get(*k);
            Evidence {
                signal_id: k.signal_id(),
                source: EvidenceSource::CampaignCluster,
                weight: k.feature.strength().weight(),
                summary: format!(
                    "{count} attempts share {} {}",
                    k.feature.label(),
                    i.map_or("", |i| i.display.as_str())
                ),
                reference: i.and_then(|i| i.ioc_id.clone()),
            }
        })
        .collect();
    let analyst_added = g.added_by.len();
    if analyst_added > 0 {
        evidence.push(Evidence {
            signal_id: format!("campaign:analyst:{campaign_id}"),
            source: EvidenceSource::Analyst,
            weight: 0,
            summary: format!("{analyst_added} attempts are members by analyst merge or split"),
            reference: None,
        });
    }
    if let Some(low) = members_idx
        .iter()
        .filter_map(|&m| atts[m].noise.as_ref().map(|n| n.score))
        .min()
    {
        evidence.push(Evidence {
            signal_id: format!("campaign:noise:{campaign_id}"),
            source: EvidenceSource::NoiseScore,
            weight: low,
            summary: format!("lowest member source noise score {low}"),
            reference: None,
        });
    }
    let link = score(
        ctx.cfg,
        LinkKind::AttemptCampaign,
        &atts[g.seed].attempt_id,
        &campaign_id,
        evidence,
        g.analyst.feedback.clone(),
    );
    let confidence = match link {
        Some(l) => CampaignConfidence {
            score: l.score,
            band: l.band,
            wording: l.wording,
            publishable: l.publishable,
            evidence: l.evidence,
            caps_applied: l.caps_applied,
        },
        // Unreachable in practice: every campaign has a join or an action.
        None => CampaignConfidence {
            score: 0,
            band: Band::Low,
            wording: "possible".into(),
            publishable: false,
            evidence: vec![],
            caps_applied: vec![],
        },
    };

    let first_seen = members_idx
        .iter()
        .map(|&m| atts[m].first_seen)
        .min()
        .unwrap_or(0);
    let last_seen = members_idx
        .iter()
        .map(|&m| atts[m].last_seen)
        .max()
        .unwrap_or(0);
    let status = match g.analyst.status {
        Some(s) => s,
        None if ctx.input.now - last_seen > ctx.params.closed_after_ms => CampaignStatus::Closed,
        None if confidence.band == Band::Low || members_idx.len() < 3 => CampaignStatus::Emerging,
        None => CampaignStatus::Active,
    };
    let title = g.analyst.title.clone().unwrap_or_else(|| {
        let decoys = targeting.decoys_touched;
        match ranked.first() {
            Some((k, _)) => {
                let display = ctx.info.get(*k).map_or("", |i| i.display.as_str());
                let short: String = display.chars().take(TITLE_VALUE_CHARS).collect();
                let more = if display.chars().count() > TITLE_VALUE_CHARS {
                    "..."
                } else {
                    ""
                };
                let label = k.feature.label();
                let mut c = label.chars();
                let label = c
                    .next()
                    .map(|f| f.to_uppercase().chain(c).collect::<String>())
                    .unwrap_or_default();
                format!("{label} {short}{more} on {decoys} decoys")
            }
            None => format!("{} attempts grouped by an analyst", members_idx.len()),
        }
    });

    let seed_features: Vec<Feature> = ctx.edges[g.seed]
        .iter()
        .filter(|(_, o)| g.members.contains(o))
        .map(|(k, _)| k.feature)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();

    let mut ioc_counts: BTreeMap<&str, usize> = BTreeMap::new();
    for &m in &members_idx {
        let mine: BTreeSet<&str> = ctx
            .refs
            .get(atts[m].attempt_id.as_str())
            .map(|r| r.iter().map(String::as_str).collect())
            .unwrap_or_default();
        for id in mine {
            *ioc_counts.entry(id).or_default() += 1;
        }
    }
    let shared_ioc_ids: Vec<String> = ioc_counts
        .into_iter()
        .filter(|(_, n)| *n >= 2)
        .take(MAX_SHARED_IOCS)
        .map(|(id, _)| id.to_string())
        .collect();

    let mut notes = Vec::new();
    let cut = members_idx
        .iter()
        .filter(|m| ctx.truncated.contains(m))
        .count();
    if cut > 0 {
        notes.push(format!(
            "{cut} member attempt(s) had more than {MAX_FEATURES_PER_ATTEMPT} features; the \
             weakest were not used."
        ));
    }

    let set = |f: &dyn Fn(&Attempt) -> Option<String>| -> Vec<String> {
        members_idx
            .iter()
            .filter_map(|&m| f(atts[m]))
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect()
    };
    Campaign {
        confidence_ref: format!("/v0/campaigns/{campaign_id}/evidence"),
        tenant_id: ctx.input.tenant_id.to_string(),
        tenant_scope: TenantScope::Tenant,
        title,
        status,
        first_seen,
        last_seen,
        seed: Seed {
            attempt_id: atts[g.seed].attempt_id.clone(),
            features: seed_features,
        },
        attempt_ids: members_idx
            .iter()
            .map(|&m| atts[m].attempt_id.clone())
            .collect(),
        decoy_ids: set(&|a| Some(a.decoy_id.clone())),
        sensor_ids: set(&|a| a.sensor_id.clone()),
        catalogue_ids: set(&|a| Some(a.catalogue_id.clone())),
        members,
        feature_summary: FeatureSummary {
            infrastructure,
            ttp,
            targeting,
            payload,
        },
        shared_ioc_ids,
        confidence,
        suggested_actor_links: vec![],
        analyst: g.analyst,
        notes,
        campaign_id,
    }
}

fn join(ctx: &BuildCtx<'_, '_>, k: &Key, with: &Attempt) -> Join {
    let i = ctx.info.get(k);
    Join {
        signal_id: k.signal_id(),
        feature: k.feature,
        families: k.feature.families().to_vec(),
        strength: k.feature.strength(),
        weight: k.feature.strength().weight(),
        display: i.map(|i| i.display.clone()).unwrap_or_default(),
        with_attempt_id: with.attempt_id.clone(),
        ioc_id: i.and_then(|i| i.ioc_id.clone()),
    }
}

fn targeting(
    ctx: &BuildCtx<'_, '_>,
    members: &[usize],
    cves: &BTreeSet<String>,
    cve_first: &BTreeMap<String, i64>,
) -> Targeting {
    let atts = ctx.attempts;
    let decoys: BTreeSet<&str> = members.iter().map(|&m| atts[m].decoy_id.as_str()).collect();
    let products: BTreeSet<&str> = members
        .iter()
        .map(|&m| atts[m].catalogue_id.as_str())
        .collect();
    let sensors: BTreeSet<&str> = members
        .iter()
        .filter_map(|&m| atts[m].sensor_id.as_deref())
        .collect();
    let sources: BTreeSet<&str> = members.iter().map(|&m| atts[m].src.as_str()).collect();
    let visible: BTreeSet<&str> = products
        .iter()
        .filter_map(|p| ctx.decoys_by_product.get(p))
        .flatten()
        .copied()
        .collect();
    let visible_n = visible.len().max(decoys.len()).max(1);
    let coverage = u8::try_from(decoys.len() * 100 / visible_n).unwrap_or(100);
    let mut bands = NoiseBands::default();
    for &m in members {
        match atts[m].noise.as_ref().map(|n| n.band) {
            Some(NoiseBand::Targeted) => bands.targeted += 1,
            Some(NoiseBand::Mixed) => bands.mixed += 1,
            Some(NoiseBand::Mass) => bands.mass += 1,
            None => bands.unknown += 1,
        }
    }
    let mut evidence = vec![format!(
        "touched {} of {} visible decoy(s) running the same products ({coverage}%)",
        decoys.len(),
        visible_n
    )];
    let mass_majority = bands.mass as usize * 2 > members.len();
    if bands.mass > 0 {
        evidence.push(format!(
            "{} of {} member attempt(s) come from sources that score as mass scanning",
            bands.mass,
            members.len()
        ));
    }
    let pattern = if (coverage >= 60 && decoys.len() >= 3) || mass_majority {
        TargetingPattern::Mass
    } else if visible_n >= 3 && coverage <= 34 && bands.mass == 0 {
        evidence.push("left most visible decoys of the same products alone".into());
        TargetingPattern::Selective
    } else {
        TargetingPattern::Mixed
    };
    let mut advisory_timing = Vec::new();
    for c in cves {
        let (Some(&published_at), Some(&first_seen)) =
            (ctx.input.advisories.get(c), cve_first.get(c))
        else {
            continue;
        };
        let offset_hours = (first_seen - published_at).div_euclid(HOUR_MS);
        let before = first_seen < published_at;
        evidence.push(if before {
            format!(
                "first attempt on {} came {} hour(s) before its advisory",
                printable(c),
                -offset_hours
            )
        } else {
            format!(
                "first attempt on {} came {offset_hours} hour(s) after its advisory",
                printable(c)
            )
        });
        advisory_timing.push(AdvisoryTiming {
            cve_id: printable(c),
            published_at,
            first_seen,
            offset_hours,
            before_disclosure: before,
        });
    }
    Targeting {
        pattern,
        attempts: u32_len(members.len()),
        sources: u32_len(sources.len()),
        decoys_touched: u32_len(decoys.len()),
        sensors_touched: u32_len(sensors.len()),
        products_touched: u32_len(products.len()),
        visible_decoys: u32_len(visible_n),
        coverage_pct: coverage,
        noise_bands: bands,
        catalogue_ids: products.iter().map(|p| p.to_string()).collect(),
        cves: cves.iter().map(|c| printable(c)).collect(),
        advisory_timing,
        evidence,
    }
}

// ---------------------------------------------------------------------------
// Read model glue, confidence links and alerts
// ---------------------------------------------------------------------------

/// Fill `campaign_id` on attempts and `campaign_ids` on IOCs from a
/// clustering over the same window.
pub fn attach(attempts: &mut [Attempt], iocs: &mut Extraction, clustering: &Clustering) {
    let by_attempt = clustering.membership();
    for a in attempts.iter_mut() {
        a.campaign_id = by_attempt.get(a.attempt_id.as_str()).map(|c| c.to_string());
    }
    for i in iocs.iocs.iter_mut() {
        let ids: BTreeSet<String> = i
            .attempt_ids
            .iter()
            .filter_map(|a| by_attempt.get(a.as_str()).map(|c| c.to_string()))
            .collect();
        i.campaign_ids = ids.into_iter().collect();
    }
}

/// The full #27 link for the campaign as a whole (attempt: the seed).
pub fn campaign_link(cfg: &ConfidenceConfig, c: &Campaign) -> Option<ConfidenceLink> {
    score(
        cfg,
        LinkKind::AttemptCampaign,
        &c.seed.attempt_id,
        &c.campaign_id,
        c.confidence.evidence.clone(),
        c.analyst.feedback.clone(),
    )
}

/// One `attempt_campaign` link per member: the features that joined it,
/// its own noise score, and an analyst confirmation when an action put it
/// there.
pub fn member_links(cfg: &ConfidenceConfig, c: &Campaign) -> Vec<ConfidenceLink> {
    c.members
        .iter()
        .filter_map(|m| {
            let mut evidence: Vec<Evidence> = m
                .joined_by
                .iter()
                .map(|j| Evidence {
                    signal_id: j.signal_id.clone(),
                    source: EvidenceSource::CampaignCluster,
                    weight: j.weight,
                    summary: format!(
                        "shares {} {} with {}",
                        j.feature.label(),
                        j.display,
                        j.with_attempt_id
                    ),
                    reference: Some(j.with_attempt_id.clone()),
                })
                .collect();
            let analyst = m.added_by.as_ref().map(|b| {
                evidence.push(Evidence {
                    signal_id: format!("campaign:analyst:{}", b.action_id),
                    source: EvidenceSource::Analyst,
                    weight: 0,
                    summary: format!("added by analyst {} action", b.kind.as_str()),
                    reference: Some(b.action_id.clone()),
                });
                Override {
                    feedback: Feedback::TruePositive,
                    analyst_id: b.analyst_id.clone(),
                    at: b.at,
                    note: format!("{} action {}", b.kind.as_str(), b.action_id),
                }
            });
            if let Some(n) = m.noise_score {
                evidence.push(Evidence {
                    signal_id: format!("noise:{}", m.src),
                    source: EvidenceSource::NoiseScore,
                    weight: n,
                    summary: format!("source noise score {n}"),
                    reference: None,
                });
            }
            score(
                cfg,
                LinkKind::AttemptCampaign,
                &m.attempt_id,
                &c.campaign_id,
                evidence,
                analyst,
            )
        })
        .collect()
}

/// `campaign_updated` alerts (#15) for campaigns that are new or grew since
/// `previous` (campaign id to member count, as the producer last saw it).
/// Closed campaigns raise nothing. Emerging campaigns raise `low` so they
/// land in the review queue rather than paging.
pub fn alerts(previous: &BTreeMap<String, usize>, current: &[Campaign]) -> Vec<Alert> {
    let mut out = Vec::new();
    for c in current {
        if c.status == CampaignStatus::Closed {
            continue;
        }
        let n = c.attempt_ids.len();
        let t = &c.feature_summary.targeting;
        let what = match previous.get(&c.campaign_id) {
            None => format!("New {} campaign {}", c.status.as_str(), c.campaign_id),
            Some(&before) if n > before => {
                format!("Campaign {} grew from {before}", c.campaign_id)
            }
            Some(_) => continue,
        };
        let severity = if c.status == CampaignStatus::Emerging {
            Severity::Low
        } else {
            AlertType::CampaignUpdated.default_severity()
        };
        out.push(Alert {
            alert_id: Alert::make_id(
                AlertType::CampaignUpdated,
                &[&c.tenant_id, &c.campaign_id, &n.to_string()],
            ),
            ts: c.last_seen,
            severity,
            alert_type: AlertType::CampaignUpdated,
            decoy_id: None,
            attempt_id: None,
            campaign_id: Some(c.campaign_id.clone()),
            summary: format!(
                "{what} to {n} attempts from {} sources across {} decoys ({} campaign, \
                 confidence {}): {}",
                t.sources, t.decoys_touched, c.confidence.wording, c.confidence.score, c.title
            ),
            links: vec![Link {
                kind: AlertLinkKind::Campaign,
                href: format!("/campaigns/{}", c.campaign_id),
            }],
            src_ip: None,
            cve_id: None,
            subject: None,
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::attempt::{DEFAULT_IDLE_GAP_MS, ExtraSignals, build};
    use crate::ioc::{ExtractOptions, extract};
    use serde_json::{Value, json};

    const T0: i64 = 1_792_285_323_000;
    const HASH: &str = "2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae";

    fn app(id: &str, ts: i64, decoy: &str, src: &str, data: Value) -> Value {
        json!({
            "event_id": id, "ts": ts, "decoy_id": decoy, "catalogue_id": "foiled/demo-app/1.0.0",
            "decoy_kind": "sandbox", "channel": "application", "severity": "info",
            "src": {"ip": src}, "tenant_id": "t1",
            "source": {"kind": "sensor", "id": format!("sensor-{decoy}")}, "data": data
        })
    }

    fn hook(id: &str, ts: i64, decoy: &str, src: &str) -> Value {
        let mut v = app(id, ts, decoy, src, json!({}));
        v["channel"] = json!("hook");
        v["hook"] = json!({"hook_id": "demo-app.upload-path-traversal",
            "catalogue_id": "foiled/demo-app/1.0.0", "cve_id": "FOILED-DEMO-0001",
            "stage": "trigger", "sequence_no": 1, "t_offset_ms": 0});
        v
    }

    fn post(id: &str, ts: i64, decoy: &str, src: &str, hash: &str) -> Value {
        post_to(id, ts, decoy, src, hash, "/api/upload")
    }

    fn post_to(id: &str, ts: i64, decoy: &str, src: &str, hash: &str, path: &str) -> Value {
        app(
            id,
            ts,
            decoy,
            src,
            json!({"method": "POST", "path": path, "body_sha256": hash}),
        )
    }

    struct Run {
        attempts: Vec<Attempt>,
        x: Extraction,
        signals: BTreeMap<String, AttemptSignals>,
        asns: BTreeMap<String, u32>,
    }

    fn prepare(vs: Vec<Value>) -> Run {
        let events: Vec<CaptureEvent> = vs
            .into_iter()
            .map(|v| serde_json::from_value(v).unwrap())
            .collect();
        let attempts = build(&events, DEFAULT_IDLE_GAP_MS, &ExtraSignals::new());
        let x = extract(
            &attempts,
            &events,
            &ConfidenceConfig::default(),
            ExtractOptions::default(),
        );
        Run {
            attempts,
            x,
            signals: BTreeMap::new(),
            asns: BTreeMap::new(),
        }
    }

    fn run(r: &Run, actions: &[CampaignAction]) -> Clustering {
        cluster(
            &Input {
                tenant_id: "t1",
                attempts: &r.attempts,
                iocs: &r.x,
                signals: &r.signals,
                asns: &r.asns,
                advisories: &BTreeMap::new(),
                actions,
                now: T0 + HOUR_MS,
            },
            Params::default(),
            &ConfidenceConfig::default(),
        )
    }

    fn wave() -> Vec<Value> {
        vec![
            post("a1", T0, "d1", "203.0.113.1", HASH),
            post("a2", T0 + 1000, "d2", "203.0.113.2", HASH),
            post("a3", T0 + 2000, "d3", "203.0.113.3", HASH),
            post("a4", T0 + 3000, "d4", "203.0.113.4", &"ab".repeat(32)),
        ]
    }

    #[test]
    fn same_payload_hash_on_three_sensors_is_one_campaign() {
        let r = prepare(wave());
        let c = run(&r, &[]);
        assert_eq!(c.campaigns.len(), 1);
        let k = &c.campaigns[0];
        assert_eq!(k.attempt_ids.len(), 3);
        assert_eq!(k.sensor_ids.len(), 3);
        assert_eq!(k.status, CampaignStatus::Active);
        assert_eq!(k.confidence.band, Band::Medium);
        assert_eq!(k.confidence.wording, "possible");
        assert!(
            !k.confidence.publishable,
            "clustering alone never publishes"
        );
        assert!(valid_campaign_id(&k.campaign_id));
        assert_eq!(k.campaign_id, campaign_id("t1", &k.seed.attempt_id));
        assert_eq!(k.seed.features, vec![Feature::PayloadSha256]);
        assert!(
            k.members.iter().all(
                |m| !m.joined_by.is_empty() && m.joined_by[0].feature == Feature::PayloadSha256
            )
        );
        assert_eq!(k.feature_summary.payload.payload_sha256.count, 1);
        assert!(k.suggested_actor_links.is_empty());
        assert!(k.title.starts_with("Payload hash"));
    }

    #[test]
    fn deterministic_in_any_input_order() {
        let r = prepare(wave());
        let mut rev = wave();
        rev.reverse();
        let r2 = prepare(rev);
        assert_eq!(run(&r, &[]), run(&r2, &[]));
    }

    #[test]
    fn probes_sharing_only_an_asn_form_no_campaign() {
        let mut r = prepare(vec![
            app(
                "p1",
                T0,
                "d1",
                "203.0.113.10",
                json!({"method": "GET", "path": "/"}),
            ),
            app(
                "p2",
                T0 + 10,
                "d2",
                "203.0.113.11",
                json!({"method": "GET", "path": "/"}),
            ),
        ]);
        r.asns.insert("203.0.113.10".into(), 64498);
        r.asns.insert("203.0.113.11".into(), 64498);
        assert!(run(&r, &[]).campaigns.is_empty());
    }

    #[test]
    fn asn_and_cve_alone_is_low_and_emerging() {
        let mut r = prepare(vec![
            hook("h1", T0, "d1", "203.0.113.10"),
            hook("h2", T0 + 10, "d2", "203.0.113.11"),
        ]);
        r.asns.insert("203.0.113.10".into(), 64498);
        r.asns.insert("203.0.113.11".into(), 64498);
        let c = run(&r, &[]);
        assert_eq!(c.campaigns.len(), 1);
        let k = &c.campaigns[0];
        assert_eq!(k.confidence.band, Band::Low);
        assert_eq!(k.status, CampaignStatus::Emerging);
        assert_eq!(k.seed.features, vec![Feature::AsnCve]);
        assert_eq!(k.feature_summary.targeting.cves, vec!["FOILED-DEMO-0001"]);
    }

    #[test]
    fn join_gap_splits_and_closed_after_idle() {
        let r = prepare(vec![
            post("a1", T0, "d1", "203.0.113.1", HASH),
            post("a2", T0 + 8 * DAY_MS, "d2", "203.0.113.2", HASH),
        ]);
        assert!(run(&r, &[]).campaigns.is_empty(), "more than the gap apart");
        let r = prepare(wave());
        let c = cluster(
            &Input {
                tenant_id: "t1",
                attempts: &r.attempts,
                iocs: &r.x,
                signals: &r.signals,
                asns: &r.asns,
                advisories: &BTreeMap::new(),
                actions: &[],
                now: T0 + 30 * DAY_MS,
            },
            Params::default(),
            &ConfidenceConfig::default(),
        );
        assert_eq!(c.campaigns[0].status, CampaignStatus::Closed);
    }

    #[test]
    fn other_tenants_are_ignored() {
        let mut r = prepare(wave());
        for a in &mut r.attempts {
            a.tenant_id = "t2".into();
        }
        assert!(run(&r, &[]).campaigns.is_empty());
    }

    #[test]
    fn weak_keys_do_not_bridge_two_established_campaigns() {
        let other = "cd".repeat(32);
        let mut r = prepare(vec![
            post("a1", T0, "d1", "203.0.113.1", HASH),
            post("a2", T0 + 10, "d2", "203.0.113.2", HASH),
            // A different path, so the two chains have different behaviour
            // fingerprints and only the ASN and CVE are shared.
            post_to("b1", T0 + 20, "d3", "198.51.100.1", &other, "/api/import"),
            post_to("b2", T0 + 30, "d4", "198.51.100.2", &other, "/api/import"),
            hook("a1h", T0 + 1, "d1", "203.0.113.1"),
            hook("b1h", T0 + 21, "d3", "198.51.100.1"),
        ]);
        r.asns.insert("203.0.113.1".into(), 64498);
        r.asns.insert("198.51.100.1".into(), 64498);
        let c = run(&r, &[]);
        assert_eq!(c.campaigns.len(), 2);
        assert!(c.notes.iter().any(|n| n.contains("bridged")));
    }

    fn action(id: &str, kind: ActionKind, c: &Campaign) -> CampaignAction {
        CampaignAction {
            action_id: id.into(),
            kind,
            campaign_id: c.campaign_id.clone(),
            anchor_attempt_id: c.seed.attempt_id.clone(),
            title: None,
            status: None,
            merge: vec![],
            attempt_ids: vec![],
            feedback: None,
            note: "reviewed".into(),
            analyst_id: "analyst".into(),
            at: T0 + 100,
        }
    }

    #[test]
    fn analyst_label_feedback_merge_and_split_replay() {
        let other = "cd".repeat(32);
        let mut events = wave();
        events.push(post("b1", T0 + 20, "d5", "198.51.100.1", &other));
        events.push(post("b2", T0 + 30, "d6", "198.51.100.2", &other));
        let r = prepare(events);
        let base = run(&r, &[]);
        assert_eq!(base.campaigns.len(), 2);
        let (a, b) = (&base.campaigns[0], &base.campaigns[1]);

        let mut label = action("act1", ActionKind::Label, a);
        label.title = Some("Upload <wave>".into());
        let mut fb = action("act2", ActionKind::Feedback, a);
        fb.feedback = Some(Feedback::TruePositive);
        let mut merge = action("act3", ActionKind::Merge, a);
        merge.merge = vec![CampaignRef {
            campaign_id: b.campaign_id.clone(),
            anchor_attempt_id: b.seed.attempt_id.clone(),
        }];
        merge.at += 1;
        let c = run(&r, &[merge.clone(), label.clone(), fb.clone()]);
        assert_eq!(c.campaigns.len(), 1);
        let m = &c.campaigns[0];
        assert_eq!(m.campaign_id, a.campaign_id);
        assert_eq!(m.attempt_ids.len(), 5);
        assert_eq!(m.analyst.merged_from, vec![b.campaign_id.clone()]);
        assert_eq!(m.title, printable("Upload <wave>"));
        assert_eq!(
            (m.confidence.score, m.confidence.wording.as_str()),
            (100, "confirmed")
        );
        assert_eq!(m.analyst.action_ids, vec!["act1", "act2", "act3"]);
        let added: Vec<_> = m.members.iter().filter(|x| x.added_by.is_some()).collect();
        assert_eq!(added.len(), 2);
        let links = member_links(&ConfidenceConfig::default(), m);
        assert_eq!(links.len(), 5);
        assert!(links.iter().filter(|l| l.wording == "confirmed").count() == 2);

        // Split the merged-in pair back out: the seed side keeps the id.
        let mut split = action("act4", ActionKind::Split, m);
        split.attempt_ids = b.attempt_ids.clone();
        split.at += 10;
        let c = run(&r, &[merge, label, fb, split]);
        assert_eq!(c.campaigns.len(), 2);
        let kept = c.get(&a.campaign_id).unwrap();
        assert_eq!(kept.attempt_ids.len(), 3);
        let out = c.get(&split_campaign_id("t1", "act4")).expect("split side");
        assert_eq!(out.attempt_ids, b.attempt_ids);
        assert_eq!(
            out.analyst.split_from.as_deref(),
            Some(a.campaign_id.as_str())
        );
    }

    #[test]
    fn actions_for_missing_campaigns_are_noted_not_applied() {
        let r = prepare(wave());
        let base = run(&r, &[]);
        let mut a = action("act1", ActionKind::Status, &base.campaigns[0]);
        a.anchor_attempt_id = "att_missing".into();
        a.status = Some(CampaignStatus::Closed);
        let c = run(&r, &[a]);
        assert_eq!(c.campaigns[0].status, CampaignStatus::Active);
        assert!(c.notes.iter().any(|n| n.contains("not applied")));
    }

    #[test]
    fn action_problems_are_reported() {
        let r = prepare(wave());
        let base = run(&r, &[]);
        let mut a = action("x", ActionKind::Label, &base.campaigns[0]);
        assert!(!a.problems().is_empty());
        a.title = Some("t".repeat(MAX_TITLE_CHARS + 1));
        assert!(!a.problems().is_empty());
        a.title = Some("Wave".into());
        assert!(a.problems().is_empty());
        let mut s = action("y", ActionKind::Split, &base.campaigns[0]);
        assert!(!s.problems().is_empty());
        s.attempt_ids = vec![base.campaigns[0].attempt_ids[0].clone()];
        assert!(s.problems().is_empty());
        s.feedback = Some(Feedback::Unsure);
        assert_eq!(s.problems(), vec!["feedback is only for feedback"]);
    }

    #[test]
    fn attach_fills_attempts_and_iocs() {
        let mut r = prepare(wave());
        let c = run(&r, &[]);
        let id = c.campaigns[0].campaign_id.clone();
        attach(&mut r.attempts, &mut r.x, &c);
        assert_eq!(
            r.attempts
                .iter()
                .filter(|a| a.campaign_id.as_deref() == Some(id.as_str()))
                .count(),
            3
        );
        let hash = r.x.iocs.iter().find(|i| i.value == HASH).unwrap();
        assert_eq!(hash.campaign_ids, vec![id]);
    }

    #[test]
    fn alerts_for_new_and_grown_campaigns_only() {
        let r = prepare(wave());
        let c = run(&r, &[]);
        let k = &c.campaigns[0];
        let new = alerts(&BTreeMap::new(), &c.campaigns);
        assert_eq!(new.len(), 1);
        assert_eq!(new[0].alert_type, AlertType::CampaignUpdated);
        assert_eq!(new[0].severity, Severity::Medium);
        assert!(new[0].validate().is_ok());
        assert!(new[0].summary.starts_with("New active campaign"));
        let same = BTreeMap::from([(k.campaign_id.clone(), 3)]);
        assert!(alerts(&same, &c.campaigns).is_empty());
        let grew = alerts(&BTreeMap::from([(k.campaign_id.clone(), 2)]), &c.campaigns);
        assert!(grew[0].summary.contains("grew from 2 to 3"));
        // The id is over tenant, campaign and size, so a retried producer
        // raises the same alert for the same growth.
        assert_eq!(grew[0].alert_id, new[0].alert_id);
    }

    #[test]
    fn work_is_linear_in_shared_keys() {
        // 2,000 attempts sharing one hash cluster without pairwise work, and
        // the per-member evidence stays bounded.
        let events: Vec<Value> = (0..2000)
            .map(|i| {
                post(
                    &format!("e{i}"),
                    T0 + i,
                    &format!("d{}", i % 50),
                    &format!("198.51.100.{}", i % 250),
                    HASH,
                )
            })
            .collect();
        let r = prepare(events);
        let c = run(&r, &[]);
        assert_eq!(c.campaigns.len(), 1);
        assert!(
            c.campaigns[0]
                .members
                .iter()
                .all(|m| m.joined_by.len() <= MAX_JOINS_PER_MEMBER)
        );
        assert_eq!(
            c.campaigns[0].feature_summary.targeting.pattern,
            TargetingPattern::Mass
        );
    }
}
