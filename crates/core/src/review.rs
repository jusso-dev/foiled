//! The analyst review queue (#35).
//!
//! One queue over everything that needs a person before it is trusted or
//! published: pending CVE and technique links (#12, #26, #27), pre-disclosure
//! candidates (#12), IOC publication candidates (#34, #37), campaign labels
//! (#33), actor possible-associations (#29) and write-ups in review.
//!
//! Items are derived on read from the same window model as attempts, so
//! there is no second copy of the evidence. What is stored is the analyst
//! state per item ([`ReviewState`]): claim, assignment, snooze and the
//! decision, with a version for compare-and-set. Every action is audited by
//! the API. Item ids are stable: the same subject always has the same id.
//! See `docs/review-queue.md`.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::confidence::Band;

pub const MAX_NOTE_CHARS: usize = 1_000;
/// Longest snooze, in milliseconds (30 days).
pub const MAX_SNOOZE_MS: i64 = 30 * 86_400_000;
pub const MAX_PRINCIPAL_CHARS: usize = 128;
/// How long a decision in progress holds an item before another attempt
/// may take over.
pub const DECISION_LEASE_MS: i64 = 60_000;
const HOUR_MS: i64 = 3_600_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReviewKind {
    /// An `attempt_cve` link with no analyst decision yet.
    CveLink,
    /// A CVE link carried by a pre-disclosure back-match (#12).
    PredisclosureCandidate,
    TechniqueLink,
    /// An IOC eligible for the public IOC list once an analyst confirms it.
    IocPublication,
    /// A campaign with no analyst feedback yet: confirm it and its label.
    CampaignLabel,
    /// Two campaigns clustering refused to join because one source's
    /// attempts were the only bridge (#33 `possible_links`): merge or not.
    CampaignMerge,
    /// A CVE or technique link an analyst marked `unsure`, for example
    /// after a false-positive report: a second analyst decides.
    FalsePositiveFeedback,
    /// An actor possible-association (#29), from the actor engine's links.
    ActorAssociation,
    /// A write-up waiting for its second reviewer.
    WriteUp,
}

impl ReviewKind {
    pub const ALL: [ReviewKind; 9] = [
        ReviewKind::CveLink,
        ReviewKind::PredisclosureCandidate,
        ReviewKind::TechniqueLink,
        ReviewKind::IocPublication,
        ReviewKind::CampaignLabel,
        ReviewKind::CampaignMerge,
        ReviewKind::FalsePositiveFeedback,
        ReviewKind::ActorAssociation,
        ReviewKind::WriteUp,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            ReviewKind::CveLink => "cve_link",
            ReviewKind::PredisclosureCandidate => "predisclosure_candidate",
            ReviewKind::TechniqueLink => "technique_link",
            ReviewKind::IocPublication => "ioc_publication",
            ReviewKind::CampaignLabel => "campaign_label",
            ReviewKind::CampaignMerge => "campaign_merge",
            ReviewKind::FalsePositiveFeedback => "false_positive_feedback",
            ReviewKind::ActorAssociation => "actor_association",
            ReviewKind::WriteUp => "write_up",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|k| k.as_str() == s)
    }

    /// Hours from `created_at` until the item is overdue.
    pub fn sla_hours(self) -> i64 {
        match self {
            ReviewKind::PredisclosureCandidate => 4,
            ReviewKind::CveLink | ReviewKind::FalsePositiveFeedback => 24,
            ReviewKind::WriteUp | ReviewKind::IocPublication => 48,
            ReviewKind::TechniqueLink
            | ReviewKind::CampaignLabel
            | ReviewKind::CampaignMerge
            | ReviewKind::ActorAssociation => 72,
        }
    }

    /// Base priority before confidence and age.
    fn base_priority(self) -> u32 {
        match self {
            ReviewKind::PredisclosureCandidate => 400,
            ReviewKind::WriteUp => 350,
            ReviewKind::CveLink | ReviewKind::FalsePositiveFeedback => 300,
            ReviewKind::ActorAssociation => 250,
            ReviewKind::IocPublication | ReviewKind::CampaignLabel | ReviewKind::CampaignMerge => {
                200
            }
            ReviewKind::TechniqueLink => 150,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReviewStatus {
    Open,
    Claimed,
    Snoozed,
    Approved,
    Rejected,
    /// A decision was being applied and did not finish, or its rollback
    /// failed. Shown first in the queue; after [`DECISION_LEASE_MS`] it can
    /// be decided again (effects are idempotent, so a retry cannot
    /// duplicate them).
    NeedsAttention,
}

impl ReviewStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            ReviewStatus::Open => "open",
            ReviewStatus::Claimed => "claimed",
            ReviewStatus::Snoozed => "snoozed",
            ReviewStatus::Approved => "approved",
            ReviewStatus::Rejected => "rejected",
            ReviewStatus::NeedsAttention => "needs_attention",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        use ReviewStatus::*;
        [Open, Claimed, Snoozed, Approved, Rejected, NeedsAttention]
            .into_iter()
            .find(|x| x.as_str() == s)
    }

    pub fn decided(self) -> bool {
        matches!(self, ReviewStatus::Approved | ReviewStatus::Rejected)
    }
}

/// The stored analyst state of one item. Absent means open.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewState {
    pub item_id: String,
    pub kind: ReviewKind,
    pub status: ReviewStatus,
    pub assignee: Option<String>,
    pub claimed_at: Option<i64>,
    pub snoozed_until: Option<i64>,
    pub decided_by: Option<String>,
    pub decided_at: Option<i64>,
    pub note: String,
    /// Starts at 1 and goes up by one per action; writes compare and set.
    pub version: u32,
    pub updated_at: i64,
    /// `needs_attention`: the decision that was being applied.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pending: Option<ActionKind>,
}

impl ReviewState {
    pub fn new(item_id: &str, kind: ReviewKind) -> Self {
        ReviewState {
            item_id: item_id.to_string(),
            kind,
            status: ReviewStatus::Open,
            assignee: None,
            claimed_at: None,
            snoozed_until: None,
            decided_by: None,
            decided_at: None,
            note: String::new(),
            version: 0,
            updated_at: 0,
            pending: None,
        }
    }

    /// The marker written before a decision's effect is applied: the item
    /// is held as `needs_attention` until the decision is recorded or
    /// rolled back.
    pub fn deciding(&self, action: ActionKind, actor: &str, now: i64) -> ReviewState {
        let mut m = self.clone();
        m.status = ReviewStatus::NeedsAttention;
        m.pending = Some(action);
        m.assignee = Some(actor.to_string());
        m.version = self.version + 1;
        m.updated_at = now;
        m
    }

    /// The status a reader sees: a snooze that has run out is open again.
    pub fn effective_status(&self, now: i64) -> ReviewStatus {
        match self.status {
            ReviewStatus::Snoozed if self.snoozed_until.is_none_or(|u| u <= now) => {
                if self.assignee.is_some() {
                    ReviewStatus::Claimed
                } else {
                    ReviewStatus::Open
                }
            }
            s => s,
        }
    }
}

/// What an analyst can do to an item.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActionKind {
    /// Take the item yourself.
    Claim,
    /// Give the item to someone (a token id).
    Assign,
    /// Give a claimed item back to the queue.
    Release,
    Approve,
    Reject,
    /// Hide the item until a time.
    Snooze,
    /// Start a draft write-up from the item. Does not decide it.
    Promote,
}

impl ActionKind {
    pub fn as_str(self) -> &'static str {
        match self {
            ActionKind::Claim => "claim",
            ActionKind::Assign => "assign",
            ActionKind::Release => "release",
            ActionKind::Approve => "approve",
            ActionKind::Reject => "reject",
            ActionKind::Snooze => "snooze",
            ActionKind::Promote => "promote",
        }
    }
}

/// Why an action was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ActionError {
    /// The request itself is wrong (400).
    Invalid(String),
    /// The item's state does not allow it (409).
    Conflict(String),
}

fn valid_principal(id: &str) -> bool {
    !id.is_empty()
        && id.chars().count() <= MAX_PRINCIPAL_CHARS
        && id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.' | ':'))
}

/// Apply one action to an item's state and return the new state. Pure: the
/// API stores the result with compare-and-set on `version` and audits it.
/// `Promote` leaves the state as it is apart from the version.
pub fn apply(
    current: &ReviewState,
    action: ActionKind,
    actor: &str,
    assignee: Option<&str>,
    snooze_until: Option<i64>,
    note: &str,
    now: i64,
) -> Result<ReviewState, ActionError> {
    use ActionError::{Conflict, Invalid};
    if note.chars().count() > MAX_NOTE_CHARS {
        return Err(Invalid(format!(
            "note must be at most {MAX_NOTE_CHARS} characters"
        )));
    }
    let mut status = current.effective_status(now);
    if status == ReviewStatus::NeedsAttention {
        if now - current.updated_at < DECISION_LEASE_MS {
            return Err(Conflict(
                "a decision on this item is being applied; try again shortly".into(),
            ));
        }
        // A stalled or failed decision: anyone may take the item over.
        status = ReviewStatus::Open;
    }
    if status.decided() {
        return Err(Conflict(format!(
            "item is already {}; decisions are final",
            status.as_str()
        )));
    }
    let held_by_other = current
        .assignee
        .as_deref()
        .is_some_and(|a| a != actor && status != ReviewStatus::Open);
    let mut next = current.clone();
    next.version = current.version + 1;
    next.updated_at = now;
    next.status = status;
    next.pending = None;
    if current.status == ReviewStatus::NeedsAttention {
        next.assignee = None;
    }
    match action {
        ActionKind::Claim => {
            if held_by_other {
                return Err(Conflict("item is claimed by someone else".into()));
            }
            next.status = ReviewStatus::Claimed;
            next.assignee = Some(actor.to_string());
            next.claimed_at = Some(now);
            next.snoozed_until = None;
        }
        ActionKind::Assign => {
            let to = assignee.ok_or_else(|| Invalid("assign needs an assignee".into()))?;
            if !valid_principal(to) {
                return Err(Invalid(
                    "assignee must be a token id (letters, digits, _ - . :)".into(),
                ));
            }
            next.status = ReviewStatus::Claimed;
            next.assignee = Some(to.to_string());
            next.claimed_at = Some(now);
            next.snoozed_until = None;
        }
        ActionKind::Release => {
            if current.assignee.as_deref() != Some(actor) {
                return Err(Conflict("only the assignee can release an item".into()));
            }
            next.status = ReviewStatus::Open;
            next.assignee = None;
            next.claimed_at = None;
        }
        ActionKind::Approve | ActionKind::Reject => {
            if held_by_other {
                return Err(Conflict(
                    "item is claimed by someone else; ask them or reassign it".into(),
                ));
            }
            if action == ActionKind::Reject && note.trim().is_empty() {
                return Err(Invalid("reject needs a note".into()));
            }
            next.status = if action == ActionKind::Approve {
                ReviewStatus::Approved
            } else {
                ReviewStatus::Rejected
            };
            next.assignee = Some(actor.to_string());
            next.decided_by = Some(actor.to_string());
            next.decided_at = Some(now);
            next.snoozed_until = None;
        }
        ActionKind::Snooze => {
            if held_by_other {
                return Err(Conflict("item is claimed by someone else".into()));
            }
            let until = snooze_until.ok_or_else(|| Invalid("snooze needs until".into()))?;
            if until <= now || until - now > MAX_SNOOZE_MS {
                return Err(Invalid(
                    "until must be in the future and at most 30 days away".into(),
                ));
            }
            next.status = ReviewStatus::Snoozed;
            next.snoozed_until = Some(until);
        }
        ActionKind::Promote => {
            next.status = current.status;
        }
    }
    if !note.is_empty() {
        next.note = note.to_string();
    }
    Ok(next)
}

/// A stable id for something a decision writes (a campaign action, say),
/// from the item, the decision and which part of the effect it is. A retried
/// decision writes the same ids, so it cannot duplicate its effect.
pub fn effect_id(item_id: &str, action: ActionKind, part: &str) -> String {
    let h =
        Sha256::digest(format!("review-effect\n{item_id}\n{}\n{part}", action.as_str()).as_bytes());
    hex::encode(&h[..16])
}

/// `rq_` plus 24 hex characters over the tenant, kind and subject.
pub fn item_id(tenant_id: &str, kind: ReviewKind, subject: &[&str]) -> String {
    let mut h = Sha256::new();
    h.update(b"review\n");
    h.update(tenant_id.as_bytes());
    h.update(b"\n");
    h.update(kind.as_str().as_bytes());
    for s in subject {
        h.update(b"\n");
        h.update(s.as_bytes());
    }
    format!("rq_{}", hex::encode(&h.finalize()[..12]))
}

pub fn valid_item_id(id: &str) -> bool {
    id.strip_prefix("rq_").is_some_and(|h| {
        h.len() == 24
            && h.bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    })
}

/// What an item points at. Only the fields for its kind are set.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Subject {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attempt_id: Option<String>,
    /// CVE id, technique id or actor id.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ioc_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub campaign_id: Option<String>,
    /// `campaign_merge`: the campaign to fold into `campaign_id`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub other_campaign_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub writeup_id: Option<String>,
    /// `actor_association`: set when a confirmed link needs another look
    /// because attempts joined it since (#29): each such change is a new
    /// item.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revision: Option<String>,
    /// When the write-up was submitted for review: each submission is a
    /// new item.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub submitted_at: Option<i64>,
}

/// A derived item before its stored state is merged in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Candidate {
    pub kind: ReviewKind,
    pub subject: Subject,
    /// Escaped one-line summary.
    pub title: String,
    pub score: u8,
    pub band: Band,
    pub wording: String,
    /// When the evidence was first seen, or the write-up was submitted.
    pub created_at: i64,
    /// A decision recorded outside the queue (an override from
    /// `/v0/attempts/{id}/links`, campaign feedback), as status, by, at.
    pub decided_elsewhere: Option<(ReviewStatus, String, i64)>,
}

/// One queue item. Mirrors `schemas/review-item.schema.json`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewItem {
    pub item_id: String,
    pub tenant_id: String,
    pub kind: ReviewKind,
    pub subject: Subject,
    pub title: String,
    pub score: u8,
    pub band: Band,
    pub wording: String,
    pub status: ReviewStatus,
    pub assignee: Option<String>,
    pub claimed_at: Option<i64>,
    pub snoozed_until: Option<i64>,
    pub decided_by: Option<String>,
    pub decided_at: Option<i64>,
    pub note: String,
    pub created_at: i64,
    pub age_ms: i64,
    pub sla_hours: i64,
    pub sla_due_at: i64,
    pub sla_breached: bool,
    /// Higher first. See [`priority`].
    pub priority: u32,
    pub version: u32,
}

/// Queue order: kind, then confidence, then how close the item is to its
/// SLA (overdue items jump ahead). Snoozed and decided items sink to 0.
pub fn priority(
    kind: ReviewKind,
    score: u8,
    status: ReviewStatus,
    created_at: i64,
    now: i64,
) -> u32 {
    if matches!(status, ReviewStatus::Snoozed) || status.decided() {
        return 0;
    }
    if status == ReviewStatus::NeedsAttention {
        return 2_000;
    }
    let sla_ms = kind.sla_hours() * HOUR_MS;
    let age = (now - created_at).max(0);
    let urgency = if age >= sla_ms {
        200
    } else {
        (age * 100 / sla_ms.max(1)) as u32
    };
    kind.base_priority() + u32::from(score.min(100)) + urgency
}

/// Merge a candidate with its stored state (if any) into an item.
pub fn item(tenant_id: &str, c: Candidate, state: Option<&ReviewState>, now: i64) -> ReviewItem {
    let parts = subject_key(&c.subject);
    let refs: Vec<&str> = parts.iter().map(String::as_str).collect();
    let item_id = item_id(tenant_id, c.kind, &refs);
    let mut st = state
        .cloned()
        .unwrap_or_else(|| ReviewState::new(&item_id, c.kind));
    if state.is_none()
        && let Some((status, by, at)) = &c.decided_elsewhere
    {
        st.status = *status;
        st.decided_by = Some(by.clone());
        st.decided_at = Some(*at);
    }
    let status = st.effective_status(now);
    let sla_hours = c.kind.sla_hours();
    let sla_due_at = c.created_at + sla_hours * HOUR_MS;
    ReviewItem {
        item_id,
        tenant_id: tenant_id.to_string(),
        kind: c.kind,
        subject: c.subject,
        title: c.title,
        score: c.score,
        band: c.band,
        wording: c.wording,
        status,
        assignee: st.assignee,
        claimed_at: st.claimed_at,
        snoozed_until: if status == ReviewStatus::Snoozed {
            st.snoozed_until
        } else {
            None
        },
        decided_by: st.decided_by,
        decided_at: st.decided_at,
        note: st.note,
        created_at: c.created_at,
        age_ms: (now - c.created_at).max(0),
        sla_hours,
        sla_due_at,
        sla_breached: !status.decided() && now >= sla_due_at,
        priority: priority(c.kind, c.score, status, c.created_at, now),
        version: st.version,
    }
}

/// The parts of a subject that identify it, in a fixed order. A write-up
/// item includes the submission time, so a resubmitted write-up is a new
/// item.
pub fn subject_key(s: &Subject) -> Vec<String> {
    let mut out: Vec<String> = [
        &s.attempt_id,
        &s.target,
        &s.ioc_id,
        &s.campaign_id,
        &s.other_campaign_id,
        &s.writeup_id,
        &s.revision,
    ]
    .into_iter()
    .flatten()
    .cloned()
    .collect();
    if let Some(v) = s.submitted_at {
        out.push(format!("submitted:{v}"));
    }
    out
}

/// Sort items: priority descending, then oldest first, then id.
pub fn sort(items: &mut [ReviewItem]) {
    items.sort_by(|a, b| {
        (b.priority, a.created_at, &a.item_id).cmp(&(a.priority, b.created_at, &b.item_id))
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: i64 = 1_800_000_000_000;

    fn open() -> ReviewState {
        ReviewState::new("rq_x", ReviewKind::CveLink)
    }

    #[test]
    fn claim_approve_and_decisions_are_final() {
        let s = apply(&open(), ActionKind::Claim, "alice", None, None, "", NOW).unwrap();
        assert_eq!(
            (s.status, s.assignee.as_deref(), s.version),
            (ReviewStatus::Claimed, Some("alice"), 1)
        );
        let err = apply(&s, ActionKind::Approve, "bob", None, None, "", NOW).unwrap_err();
        assert!(matches!(err, ActionError::Conflict(_)));
        let s = apply(
            &s,
            ActionKind::Approve,
            "alice",
            None,
            None,
            "seen in pcap",
            NOW,
        )
        .unwrap();
        assert_eq!(s.status, ReviewStatus::Approved);
        assert_eq!(s.decided_by.as_deref(), Some("alice"));
        assert!(matches!(
            apply(&s, ActionKind::Reject, "alice", None, None, "x", NOW),
            Err(ActionError::Conflict(_))
        ));
    }

    #[test]
    fn reject_needs_a_note_and_assign_checks_the_assignee() {
        assert!(matches!(
            apply(&open(), ActionKind::Reject, "a", None, None, " ", NOW),
            Err(ActionError::Invalid(_))
        ));
        assert!(matches!(
            apply(
                &open(),
                ActionKind::Assign,
                "a",
                Some("bob smith"),
                None,
                "",
                NOW
            ),
            Err(ActionError::Invalid(_))
        ));
        let s = apply(
            &open(),
            ActionKind::Assign,
            "a",
            Some("tok_bob"),
            None,
            "",
            NOW,
        )
        .unwrap();
        assert_eq!(s.assignee.as_deref(), Some("tok_bob"));
        // Only the assignee releases.
        assert!(apply(&s, ActionKind::Release, "a", None, None, "", NOW).is_err());
        let r = apply(&s, ActionKind::Release, "tok_bob", None, None, "", NOW).unwrap();
        assert_eq!((r.status, r.assignee), (ReviewStatus::Open, None));
    }

    #[test]
    fn a_stalled_decision_can_be_retried_after_the_lease() {
        let marker = open().deciding(ActionKind::Approve, "alice", NOW);
        assert_eq!(marker.status, ReviewStatus::NeedsAttention);
        assert_eq!(
            priority(ReviewKind::CveLink, 10, marker.status, NOW, NOW),
            2_000
        );
        assert!(matches!(
            apply(&marker, ActionKind::Approve, "bob", None, None, "", NOW + 1),
            Err(ActionError::Conflict(_))
        ));
        let s = apply(
            &marker,
            ActionKind::Approve,
            "bob",
            None,
            None,
            "",
            NOW + DECISION_LEASE_MS,
        )
        .unwrap();
        assert_eq!(s.status, ReviewStatus::Approved);
        assert_eq!(s.pending, None);
        assert_eq!(
            effect_id("rq_x", ActionKind::Approve, "label"),
            effect_id("rq_x", ActionKind::Approve, "label")
        );
        assert_ne!(
            effect_id("rq_x", ActionKind::Approve, "label"),
            effect_id("rq_x", ActionKind::Reject, "label")
        );
    }

    #[test]
    fn snooze_runs_out() {
        assert!(
            apply(
                &open(),
                ActionKind::Snooze,
                "a",
                None,
                Some(NOW - 1),
                "",
                NOW
            )
            .is_err()
        );
        assert!(
            apply(
                &open(),
                ActionKind::Snooze,
                "a",
                None,
                Some(NOW + MAX_SNOOZE_MS + 1),
                "",
                NOW
            )
            .is_err()
        );
        let s = apply(
            &open(),
            ActionKind::Snooze,
            "a",
            None,
            Some(NOW + 1_000),
            "",
            NOW,
        )
        .unwrap();
        assert_eq!(s.effective_status(NOW), ReviewStatus::Snoozed);
        assert_eq!(s.effective_status(NOW + 1_000), ReviewStatus::Open);
        assert_eq!(
            priority(ReviewKind::CveLink, 90, ReviewStatus::Snoozed, NOW, NOW),
            0
        );
    }

    #[test]
    fn priority_orders_by_kind_score_and_sla() {
        let fresh = priority(ReviewKind::CveLink, 50, ReviewStatus::Open, NOW, NOW);
        let half = priority(
            ReviewKind::CveLink,
            50,
            ReviewStatus::Open,
            NOW - 12 * HOUR_MS,
            NOW,
        );
        let late = priority(
            ReviewKind::CveLink,
            50,
            ReviewStatus::Open,
            NOW - 25 * HOUR_MS,
            NOW,
        );
        assert!(fresh < half && half < late);
        assert_eq!(late, 300 + 50 + 200);
        let pre = priority(
            ReviewKind::PredisclosureCandidate,
            30,
            ReviewStatus::Open,
            NOW,
            NOW,
        );
        assert!(pre > fresh);
    }

    #[test]
    fn ids_are_stable_and_tenant_scoped() {
        let a = item_id("t1", ReviewKind::CveLink, &["att_1", "CVE-2099-0001"]);
        assert_eq!(
            a,
            item_id("t1", ReviewKind::CveLink, &["att_1", "CVE-2099-0001"])
        );
        assert_ne!(
            a,
            item_id("t2", ReviewKind::CveLink, &["att_1", "CVE-2099-0001"])
        );
        assert!(valid_item_id(&a));
        assert!(!valid_item_id("rq_../../etc"));
    }

    #[test]
    fn decisions_made_elsewhere_show_as_decided() {
        let c = Candidate {
            kind: ReviewKind::CveLink,
            subject: Subject {
                attempt_id: Some("att_1".into()),
                target: Some("CVE-2099-0001".into()),
                ..Default::default()
            },
            title: "x".into(),
            score: 60,
            band: Band::Medium,
            wording: "we assess as".into(),
            created_at: NOW - 30 * HOUR_MS,
            decided_elsewhere: Some((ReviewStatus::Approved, "alice".into(), NOW - 1)),
        };
        let i = item("t1", c, None, NOW);
        assert_eq!(i.status, ReviewStatus::Approved);
        assert!(!i.sla_breached);
        assert_eq!(i.priority, 0);
    }
}
