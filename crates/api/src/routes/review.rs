//! The analyst review queue (#35): `GET /v0/review-queue`,
//! `GET /v0/review-queue/{item_id}` and
//! `POST /v0/review-queue/{item_id}/actions`.
//!
//! Items are derived on request from the same window model as attempts
//! (pending CVE and technique links, pre-disclosure candidates, IOC
//! publication candidates, campaign labels, actor possible-associations)
//! plus write-ups in review, and merged with the stored analyst state
//! (`foiled_core::review`). Every route is scoped to the caller's tenant.
//! Approve and reject also record the decision where it belongs (a link
//! override, a campaign feedback action, a write-up transition), and every
//! action is audited as `review.<action>`.

use std::collections::{BTreeMap, BTreeSet, HashMap};

use sha2::Digest;

use axum::extract::{Path, Query, State};
use axum::routing::{get, post};
use axum::{Json, Router};
use foiled_core::attempt::Attempt;
use foiled_core::audit::Outcome;
use foiled_core::auth::{Principal, Role, Scope};
use foiled_core::campaign::{ActionKind as CampaignActionKind, CampaignAction, MAX_ANCHORS};
use foiled_core::confidence::{
    ConfidenceConfig, ConfidenceLink, EvidenceSource, Feedback, LinkKind, Override,
};
use foiled_core::review::{
    self, ActionError, ActionKind, Candidate, ReviewItem, ReviewKind, ReviewState, ReviewStatus,
    Subject,
};
use foiled_core::share::{self, Channel, SensorKind};
use foiled_core::timeline::printable;
use foiled_core::writeup::{Checklist, WriteUp, WriteUpStatus};
use serde::{Deserialize, Serialize};

use crate::AppState;
use crate::auth::Auth;
use crate::error::{ApiError, JsonBody};
use crate::routes::attempts::{
    Campaigns, Iocs, WindowModel, canonical_window, window_bounds, window_model,
};
use crate::routes::{HOUR_MS, audit_record, check_rate, page_limit};
use crate::store::LinkOverride;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/v0/review-queue", get(list))
        .route("/v0/review-queue/{item_id}", get(get_one))
        .route("/v0/review-queue/{item_id}/actions", post(act))
}

/// Which statuses a list shows. `pending` (the default) is open, claimed
/// and snoozed.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StatusFilter {
    #[default]
    Pending,
    Open,
    Claimed,
    Snoozed,
    Approved,
    Rejected,
    NeedsAttention,
    All,
}

impl StatusFilter {
    fn matches(self, s: ReviewStatus) -> bool {
        match self {
            StatusFilter::Pending => !s.decided(),
            StatusFilter::Open => s == ReviewStatus::Open,
            StatusFilter::Claimed => s == ReviewStatus::Claimed,
            StatusFilter::Snoozed => s == ReviewStatus::Snoozed,
            StatusFilter::Approved => s == ReviewStatus::Approved,
            StatusFilter::Rejected => s == ReviewStatus::Rejected,
            StatusFilter::NeedsAttention => s == ReviewStatus::NeedsAttention,
            StatusFilter::All => true,
        }
    }
}

#[derive(Debug, Deserialize, Default)]
pub struct QueueQuery {
    pub since: Option<i64>,
    pub until: Option<i64>,
    pub kind: Option<ReviewKind>,
    #[serde(default)]
    pub status: StatusFilter,
    /// A token id, or `me`.
    pub assignee: Option<String>,
    pub sla_breached: Option<bool>,
    pub limit: Option<usize>,
}

#[derive(Debug, Deserialize, Default)]
pub struct WindowQuery {
    pub since: Option<i64>,
    pub until: Option<i64>,
}

#[derive(Debug, Serialize)]
pub struct QueueList {
    pub items: Vec<ReviewItem>,
    /// Items matching the filters before `limit`.
    pub total: usize,
    pub truncated: bool,
    pub notes: Vec<String>,
}

/// Scored links per attempt with analyst overrides applied, read in one
/// store call. Shared with the radar rollup.
pub(crate) async fn links_by_attempt(
    state: &AppState,
    tenant_id: &str,
    m: &WindowModel,
) -> Result<(BTreeMap<String, Vec<ConfidenceLink>>, Vec<LinkOverride>), ApiError> {
    let overrides = if m.attempts.is_empty() {
        Vec::new()
    } else {
        state
            .store
            .link_overrides_many(
                tenant_id,
                m.attempts.iter().map(|a| a.attempt_id.clone()).collect(),
            )
            .await?
    };
    let mut by_attempt: HashMap<&str, BTreeMap<(LinkKind, String), Override>> = HashMap::new();
    for o in &overrides {
        by_attempt
            .entry(o.attempt_id.as_str())
            .or_default()
            .insert((o.kind, o.target.clone()), o.decision.clone());
    }
    let events: HashMap<&str, &foiled_core::capture::CaptureEvent> =
        m.events.iter().map(|e| (e.event_id.as_str(), e)).collect();
    let cfg = ConfidenceConfig::default();
    let empty = BTreeMap::new();
    let mut out = BTreeMap::new();
    for a in &m.attempts {
        let mine: Vec<_> = a
            .event_ids
            .iter()
            .filter_map(|id| events.get(id.as_str()).map(|e| (*e).clone()))
            .collect();
        let links = crate::links::links_for_attempt(
            &cfg,
            state.catalogue.get(&a.catalogue_id),
            a,
            &mine,
            by_attempt.get(a.attempt_id.as_str()).unwrap_or(&empty),
        );
        out.insert(a.attempt_id.clone(), links);
    }
    Ok((out, overrides))
}

/// Kind and opt-in per sensor seen in these attempts (#31, #37), keyed by
/// `radar::sensor_ref`.
///
/// Research means a decoy in a tenant the operator designated as research
/// (`RESEARCH_TENANTS`), under the policy's research default. Everything
/// else is treated as edge: an edge sensor uses its recorded choice, and a
/// tenant's own decoy uses its sandbox host's recorded choice. Missing
/// choices use the edge default (off). One store read per distinct sensor
/// or decoy.
pub(crate) async fn sensor_share(
    state: &AppState,
    tenant_id: &str,
    attempts: &[Attempt],
) -> Result<foiled_core::radar::SensorShare, ApiError> {
    let research = state.research_tenants.iter().any(|t| t == tenant_id);
    let edge_default = state.share.default_opt_in(SensorKind::Edge);
    let mut out = BTreeMap::new();
    let mut hosts: BTreeMap<String, bool> = BTreeMap::new();
    for a in attempts {
        let key = foiled_core::radar::sensor_ref(a);
        if out.contains_key(&key) {
            continue;
        }
        let value = match (&a.sensor_id, research) {
            (None, true) => (
                SensorKind::Research,
                state.share.default_opt_in(SensorKind::Research),
            ),
            (Some(id), _) => {
                let opted = state
                    .store
                    .get_agent(tenant_id, Role::Sensor, id)
                    .await?
                    .and_then(|r| r.share_opt_in)
                    .unwrap_or(edge_default);
                (SensorKind::Edge, opted)
            }
            (None, false) => {
                let host = state
                    .store
                    .get_decoy(tenant_id, &a.decoy_id)
                    .await?
                    .and_then(|d| d.host_id);
                let opted = match host {
                    Some(h) => match hosts.get(&h) {
                        Some(o) => *o,
                        None => {
                            let o = state
                                .store
                                .get_agent(tenant_id, Role::Host, &h)
                                .await?
                                .and_then(|r| r.share_opt_in)
                                .unwrap_or(edge_default);
                            hosts.insert(h, o);
                            o
                        }
                    },
                    None => edge_default,
                };
                (SensorKind::Edge, opted)
            }
        };
        out.insert(key, value);
    }
    Ok(out)
}

/// Attempts whose sensor may feed `channel`, per [`sensor_share`].
pub(crate) fn shareable_attempts(
    policy: &share::SharePolicy,
    sensors: &foiled_core::radar::SensorShare,
    attempts: &[Attempt],
    channel: Channel,
) -> BTreeSet<String> {
    attempts
        .iter()
        .filter(|a| {
            let (kind, opted) = sensors
                .get(&foiled_core::radar::sensor_ref(a))
                .copied()
                .unwrap_or((SensorKind::Edge, policy.default_opt_in(SensorKind::Edge)));
            share::may_share(policy, kind, opted, channel)
        })
        .map(|a| a.attempt_id.clone())
        .collect()
}

fn to_share_band(b: foiled_core::confidence::Band) -> share::Band {
    use foiled_core::confidence::Band;
    match b {
        Band::Low => share::Band::Low,
        Band::Medium => share::Band::Medium,
        Band::High => share::Band::High,
    }
}

fn decided_by(o: &Override) -> Option<(ReviewStatus, String, i64)> {
    match o.feedback {
        Feedback::TruePositive => Some((ReviewStatus::Approved, o.analyst_id.clone(), o.at)),
        Feedback::FalsePositive => Some((ReviewStatus::Rejected, o.analyst_id.clone(), o.at)),
        Feedback::Unsure => None,
    }
}

fn sentence_case(s: &str) -> String {
    let mut c = s.chars();
    match c.next() {
        Some(f) => f.to_uppercase().chain(c).collect(),
        None => String::new(),
    }
}

/// Everything the queue derives for one window, plus the window itself so
/// actions can use it without a second build.
pub(crate) struct Derived {
    pub candidates: Vec<Candidate>,
    pub model: WindowModel,
    /// The window the items came from, for effects that build it again.
    pub since: Option<i64>,
    pub until: Option<i64>,
    pub truncated: bool,
    pub notes: Vec<String>,
}

/// Derive every candidate item for a tenant's window.
pub(crate) async fn derive(
    state: &AppState,
    tenant_id: &str,
    since: Option<i64>,
    until: Option<i64>,
) -> Result<Derived, ApiError> {
    let (from, to) = window_bounds(state, since, until);
    let mut m = window_model(
        state,
        tenant_id,
        from,
        to,
        Iocs::Attach,
        Campaigns::Full {
            record: canonical_window(since, until),
        },
    )
    .await?;
    let cfg = ConfidenceConfig::default();
    let (links, _) = links_by_attempt(state, tenant_id, &m).await?;
    let attempts: HashMap<&str, &Attempt> = m
        .attempts
        .iter()
        .map(|a| (a.attempt_id.as_str(), a))
        .collect();
    let mut out = Vec::new();

    // CVE and technique links, and pre-disclosure candidates.
    for (attempt_id, list) in &links {
        let Some(a) = attempts.get(attempt_id.as_str()) else {
            continue;
        };
        for l in list {
            let kind = match l.kind {
                LinkKind::AttemptCve
                    if l.evidence
                        .iter()
                        .any(|e| e.source == EvidenceSource::PredisclosureBackmatch) =>
                {
                    ReviewKind::PredisclosureCandidate
                }
                LinkKind::AttemptCve => ReviewKind::CveLink,
                LinkKind::AttemptTechnique => ReviewKind::TechniqueLink,
                _ => continue,
            };
            if !l.radar_queue && l.r#override.is_none() {
                continue;
            }
            // An analyst marked it unsure: a second analyst decides.
            let kind = if l
                .r#override
                .as_ref()
                .is_some_and(|o| o.feedback == Feedback::Unsure)
            {
                ReviewKind::FalsePositiveFeedback
            } else {
                kind
            };
            let what = if kind == ReviewKind::TechniqueLink {
                "technique"
            } else {
                "an attempt against"
            };
            out.push(Candidate {
                kind,
                subject: Subject {
                    attempt_id: Some(attempt_id.clone()),
                    target: Some(l.target.clone()),
                    ..Default::default()
                },
                title: printable(&format!(
                    "{} {what} {} on {} from {}",
                    sentence_case(&l.wording),
                    l.target,
                    a.catalogue_id,
                    a.src
                )),
                score: l.score,
                band: l.band,
                wording: l.wording.clone(),
                created_at: a.first_seen,
                decided_elsewhere: l.r#override.as_ref().and_then(decided_by),
            });
        }
    }

    // IOC publication candidates: from sensors that may feed public IOCs,
    // at or above the release band (#37). The release itself still waits
    // for the delay.
    let sensors = sensor_share(state, tenant_id, &m.attempts).await?;
    let shareable = shareable_attempts(&state.share, &sensors, &m.attempts, Channel::PublicIocs);
    for ioc in &m.iocs.iocs {
        if to_share_band(ioc.confidence.band) < state.share.public_iocs.min_confidence
            || !ioc.attempt_ids.iter().any(|a| shareable.contains(a))
        {
            continue;
        }
        out.push(Candidate {
            kind: ReviewKind::IocPublication,
            subject: Subject {
                ioc_id: Some(ioc.ioc_id.clone()),
                ..Default::default()
            },
            title: printable(&format!(
                "Release {} indicator {} after the public delay",
                serde_json::to_value(ioc.ioc_type)
                    .ok()
                    .and_then(|v| v.as_str().map(str::to_string))
                    .unwrap_or_default(),
                ioc.display
            )),
            score: ioc.confidence.score,
            band: ioc.confidence.band,
            wording: ioc.confidence.wording.clone(),
            created_at: ioc.first_seen,
            decided_elsewhere: None,
        });
    }

    // Campaign labels.
    for c in &m.campaigns.campaigns {
        if c.confidence.score < cfg.thresholds.radar_queue_min && c.analyst.feedback.is_none() {
            continue;
        }
        out.push(Candidate {
            kind: ReviewKind::CampaignLabel,
            subject: Subject {
                campaign_id: Some(c.campaign_id.clone()),
                ..Default::default()
            },
            title: format!("Possible campaign: {}", c.title),
            score: c.confidence.score,
            band: c.confidence.band,
            wording: c.confidence.wording.clone(),
            created_at: c.first_seen,
            decided_elsewhere: c.analyst.feedback.as_ref().and_then(decided_by),
        });
    }

    // Merge proposals: bridges clustering refused (#33).
    let mut proposed = BTreeSet::new();
    for c in &m.campaigns.campaigns {
        for link in &c.possible_links {
            for other in &link.other_campaign_ids {
                let Some(o) = m.campaigns.get(other) else {
                    continue;
                };
                // One item per pair, kept on the older campaign.
                let (keep, fold) =
                    if (c.first_seen, &c.campaign_id) <= (o.first_seen, &o.campaign_id) {
                        (c, o)
                    } else {
                        (o, c)
                    };
                if !proposed.insert((keep.campaign_id.clone(), fold.campaign_id.clone())) {
                    continue;
                }
                let decided = keep
                    .analyst
                    .merged_from
                    .contains(&fold.campaign_id)
                    .then(|| (ReviewStatus::Approved, String::new(), keep.last_seen));
                out.push(Candidate {
                    kind: ReviewKind::CampaignMerge,
                    subject: Subject {
                        campaign_id: Some(keep.campaign_id.clone()),
                        other_campaign_id: Some(fold.campaign_id.clone()),
                        ..Default::default()
                    },
                    title: format!(
                        "Possible merge: {} into {}, bridged by one source {}",
                        fold.campaign_id, keep.campaign_id, link.src
                    ),
                    score: keep.confidence.score.min(fold.confidence.score),
                    band: keep.confidence.band.min(fold.confidence.band),
                    wording: "possible".into(),
                    created_at: keep.first_seen.max(fold.first_seen),
                    decided_elsewhere: decided,
                });
            }
        }
    }

    // Actor possible-associations (#29): links matched on this window by
    // the actor engine, campaigns and lone attempts, as /v0/actor-links
    // does. A link that needs attention (`review_queue`: pending at or above
    // the queue threshold, or confirmed with attempts added since) is an
    // open item; other decided links show as decided.
    if let Some(inputs) = m.inputs.take() {
        let mut campaigns = std::mem::take(&mut m.campaigns.campaigns);
        let matched = crate::routes::actors::match_window(
            state,
            tenant_id,
            &mut campaigns,
            crate::routes::actors::Window {
                lone_attempts: true,
                ..crate::routes::actors::Window::campaigns_of(&m, &inputs)
            },
        )
        .await;
        m.campaigns.campaigns = campaigns;
        m.inputs = Some(inputs);
        let (actor_links, _, _) = matched?;
        for l in actor_links {
            use foiled_core::actor::{LinkStatus, SubjectKind};
            // A confirmed link that needs another look is a new item: its
            // key includes the attempts added since the confirmation.
            let revision = (!l.new_since_confirmation.is_empty()).then(|| {
                let h = sha2::Sha256::digest(l.new_since_confirmation.join("\n").as_bytes());
                hex::encode(&h[..8])
            });
            let decided = match l.status {
                _ if l.review_queue => None,
                LinkStatus::Pending => continue,
                LinkStatus::Confirmed | LinkStatus::Rejected => {
                    let status = if l.status == LinkStatus::Confirmed {
                        ReviewStatus::Approved
                    } else {
                        ReviewStatus::Rejected
                    };
                    let o = l.confidence.r#override.as_ref();
                    Some((
                        status,
                        o.map(|o| o.analyst_id.clone()).unwrap_or_default(),
                        o.map_or(0, |o| o.at),
                    ))
                }
            };
            let first_seen = match l.subject_kind {
                SubjectKind::Campaign => m.campaigns.get(&l.subject_id).map(|c| c.first_seen),
                SubjectKind::Attempt => attempts.get(l.subject_id.as_str()).map(|a| a.first_seen),
            }
            .unwrap_or(0);
            out.push(Candidate {
                kind: ReviewKind::ActorAssociation,
                subject: Subject {
                    attempt_id: (l.subject_kind == SubjectKind::Attempt)
                        .then(|| l.subject_id.clone()),
                    campaign_id: (l.subject_kind == SubjectKind::Campaign)
                        .then(|| l.subject_id.clone()),
                    target: Some(l.actor_id.clone()),
                    revision,
                    ..Default::default()
                },
                title: printable(&l.statement),
                score: l.score,
                band: l.band,
                wording: l.wording.clone(),
                created_at: first_seen,
                decided_elsewhere: decided,
            });
        }
    }

    // Write-ups: in review (open), and the outcome of recent submissions.
    for w in state
        .store
        .list_writeups(tenant_id, None, crate::routes::writeups::MAX_LIST)
        .await?
    {
        let Some(submitted) = w.submitted_at else {
            continue;
        };
        let decided = match w.status {
            WriteUpStatus::Review => None,
            WriteUpStatus::Approved | WriteUpStatus::Published | WriteUpStatus::Withdrawn => {
                Some((
                    ReviewStatus::Approved,
                    w.reviewer_id.clone().unwrap_or_default(),
                    w.approved_at.unwrap_or(w.updated_at),
                ))
            }
            WriteUpStatus::Draft => Some((
                ReviewStatus::Rejected,
                w.reviewer_id.clone().unwrap_or_default(),
                w.updated_at,
            )),
        };
        out.push(Candidate {
            kind: ReviewKind::WriteUp,
            subject: Subject {
                writeup_id: Some(w.writeup_id.clone()),
                submitted_at: Some(submitted),
                ..Default::default()
            },
            title: printable(&format!("Write-up for review: {}", w.title)),
            score: 0,
            band: foiled_core::confidence::Band::Low,
            wording: "review".into(),
            created_at: submitted,
            decided_elsewhere: decided,
        });
    }

    let mut notes = m.campaigns.notes.clone();
    if m.truncated {
        notes.push(
            "The window held more events than the cap, so some items may be missing. Narrow \
             since and until."
                .into(),
        );
    }
    Ok(Derived {
        since,
        until,
        candidates: out,
        truncated: m.truncated,
        notes,
        model: m,
    })
}

/// Merge candidates with stored state into items.
async fn items(
    state: &AppState,
    tenant_id: &str,
    candidates: Vec<Candidate>,
) -> Result<Vec<ReviewItem>, ApiError> {
    let now = (state.clock)();
    let ids: Vec<String> = candidates
        .iter()
        .map(|c| {
            let parts = review::subject_key(&c.subject);
            let refs: Vec<&str> = parts.iter().map(String::as_str).collect();
            review::item_id(tenant_id, c.kind, &refs)
        })
        .collect();
    let states: HashMap<String, ReviewState> = if ids.is_empty() {
        HashMap::new()
    } else {
        state
            .store
            .review_states(tenant_id, ids.clone())
            .await?
            .into_iter()
            .map(|s| (s.item_id.clone(), s))
            .collect()
    };
    Ok(candidates
        .into_iter()
        .zip(ids)
        .map(|(c, id)| review::item(tenant_id, c, states.get(&id), now))
        .collect())
}

async fn list(
    State(state): State<AppState>,
    auth: Auth,
    Query(q): Query<QueueQuery>,
) -> Result<Json<QueueList>, ApiError> {
    let who = auth.require(Scope::ReviewRead)?;
    let d = derive(&state, &who.tenant_id, q.since, q.until).await?;
    let assignee = q
        .assignee
        .as_deref()
        .map(|a| if a == "me" { who.id.as_str() } else { a });
    let mut all: Vec<ReviewItem> = items(&state, &who.tenant_id, d.candidates)
        .await?
        .into_iter()
        .filter(|i| q.kind.is_none_or(|k| i.kind == k))
        .filter(|i| q.status.matches(i.status))
        .filter(|i| assignee.is_none_or(|a| i.assignee.as_deref() == Some(a)))
        .filter(|i| q.sla_breached.is_none_or(|b| i.sla_breached == b))
        .collect();
    review::sort(&mut all);
    let total = all.len();
    all.truncate(page_limit(q.limit));
    Ok(Json(QueueList {
        items: all,
        total,
        truncated: d.truncated,
        notes: d.notes,
    }))
}

async fn find(
    state: &AppState,
    tenant_id: &str,
    item_id: &str,
    q: &WindowQuery,
) -> Result<(ReviewItem, Candidate, Derived), ApiError> {
    if !review::valid_item_id(item_id) {
        return Err(ApiError::not_found("review item"));
    }
    let mut d = derive(state, tenant_id, q.since, q.until).await?;
    let pos = d
        .candidates
        .iter()
        .position(|c| {
            let parts = review::subject_key(&c.subject);
            let refs: Vec<&str> = parts.iter().map(String::as_str).collect();
            review::item_id(tenant_id, c.kind, &refs) == item_id
        })
        .ok_or_else(|| ApiError::not_found("review item"))?;
    let c = d.candidates.swap_remove(pos);
    let item = items(state, tenant_id, vec![c.clone()])
        .await?
        .pop()
        .ok_or_else(|| ApiError::not_found("review item"))?;
    Ok((item, c, d))
}

async fn get_one(
    State(state): State<AppState>,
    auth: Auth,
    Path(item_id): Path<String>,
    Query(q): Query<WindowQuery>,
) -> Result<Json<ReviewItem>, ApiError> {
    let who = auth.require(Scope::ReviewRead)?;
    let (item, _, _) = find(&state, &who.tenant_id, &item_id, &q).await?;
    Ok(Json(item))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActionBody {
    pub action: ActionKind,
    /// `assign`: the token id to give the item to.
    pub assignee: Option<String>,
    /// `snooze`: Unix ms, at most 30 days away.
    pub until: Option<i64>,
    #[serde(default)]
    pub note: String,
    /// The item version you acted on; 409 if it changed since.
    pub expected_version: Option<u32>,
    /// `approve` on a `campaign_label` item: the campaign title to record.
    pub label: Option<String>,
    /// `approve` on a `write_up` item: the second reviewer's checklist.
    pub checklist: Option<Checklist>,
}

#[derive(Debug, Serialize)]
pub struct ActionResult {
    pub item: ReviewItem,
    /// What the decision changed besides the queue, for example
    /// `link.override true_positive`.
    pub effect: Option<String>,
    /// `promote`: the draft write-up created from the item.
    pub writeup_id: Option<String>,
}

fn action_error(e: ActionError) -> ApiError {
    match e {
        ActionError::Invalid(m) => ApiError::bad_request(m),
        ActionError::Conflict(m) => ApiError::conflict(m),
    }
}

/// Claim, assign, release, approve, reject, snooze or promote one item.
async fn act(
    State(state): State<AppState>,
    auth: Auth,
    Path(item_id): Path<String>,
    Query(q): Query<WindowQuery>,
    JsonBody(body): JsonBody<ActionBody>,
) -> Result<Json<ActionResult>, ApiError> {
    let who = auth.require(Scope::ReviewWrite)?.clone();
    if body.note.chars().count() > review::MAX_NOTE_CHARS {
        return Err(ApiError::bad_request(format!(
            "note must be at most {} characters",
            review::MAX_NOTE_CHARS
        )));
    }
    check_rate(
        &state,
        &who,
        "review.action",
        state.limits.review_actions_per_hour,
        HOUR_MS,
    )
    .await?;
    let now = (state.clock)();
    let (item, candidate, derived) = find(&state, &who.tenant_id, &item_id, &q).await?;
    if body.expected_version.is_some_and(|v| v != item.version) {
        return Err(ApiError::conflict(
            "the item changed since you read it; read it again",
        ));
    }

    if body.action == ActionKind::Promote {
        let writeup_id = promote(&state, &who, &item, &candidate, &derived).await?;
        let mut rec = audit_record(
            &state,
            &who,
            "review.promote",
            Some(&item_id),
            Outcome::Accepted,
        );
        rec.detail = serde_json::json!({
            "kind": item.kind,
            "subject": item.subject,
            "writeup_id": writeup_id,
        });
        state.store.append_audit(rec).await?;
        return Ok(Json(ActionResult {
            item,
            effect: Some("writeup.create".into()),
            writeup_id: Some(writeup_id),
        }));
    }

    // The current state: stored, or as the candidate says (a decision made
    // elsewhere, such as an override on /v0/attempts/{id}/links, is final).
    let stored = state
        .store
        .review_states(&who.tenant_id, vec![item_id.clone()])
        .await?
        .pop();
    let mut current = stored
        .clone()
        .unwrap_or_else(|| ReviewState::new(&item_id, item.kind));
    if stored.is_none()
        && let Some((status, by, at)) = &candidate.decided_elsewhere
    {
        current.status = *status;
        current.decided_by = Some(by.clone());
        current.decided_at = Some(*at);
    }
    let next = review::apply(
        &current,
        body.action,
        &who.id,
        body.assignee.as_deref(),
        body.until,
        &body.note,
        now,
    )
    .map_err(action_error)?;

    let effect = if matches!(body.action, ActionKind::Approve | ActionKind::Reject) {
        Some(
            decide_safely(
                &state, &who, &item, &candidate, &derived, &body, &current, next,
            )
            .await?,
        )
    } else {
        if !state
            .store
            .put_review_state(&who.tenant_id, next, current.version)
            .await?
        {
            return Err(ApiError::conflict(
                "the item changed while you acted on it; read it again",
            ));
        }
        None
    };
    let mut rec = audit_record(
        &state,
        &who,
        &format!("review.{}", body.action.as_str()),
        Some(&item_id),
        Outcome::Accepted,
    );
    rec.reason_text = (!body.note.is_empty()).then(|| body.note.clone());
    rec.detail = serde_json::json!({
        "kind": item.kind,
        "subject": item.subject,
        "assignee": body.assignee,
        "until": body.until,
        "effect": effect,
    });
    state.store.append_audit(rec).await?;
    // Read the item again. Some decisions remove the subject they were
    // about (a merge joins the campaigns, a decided "unsure" link becomes an
    // ordinary decided link), so fall back to the stored state over the
    // subject as it was.
    let item = match find(&state, &who.tenant_id, &item_id, &q).await {
        Ok((item, _, _)) => item,
        Err(e) if e.status == http::StatusCode::NOT_FOUND => {
            let stored = state
                .store
                .review_states(&who.tenant_id, vec![item_id.clone()])
                .await?
                .pop();
            review::item(&who.tenant_id, candidate, stored.as_ref(), (state.clock)())
        }
        Err(e) => return Err(e),
    };
    Ok(Json(ActionResult {
        item,
        effect,
        writeup_id: None,
    }))
}

/// Apply a decision without letting a race or a failure leave it half
/// done:
///
/// 1. Claim the item with compare-and-set as `needs_attention`, holding the
///    pending decision, so of two analysts acting at once only one goes on.
/// 2. Apply the effect where it belongs. Effects are idempotent (stable ids
///    keyed by item and decision, upserts), so a retry cannot duplicate
///    them.
/// 3. Record the decision (compare-and-set from the marker).
///
/// If the effect fails, the item is put back as it was. If that rollback
/// fails too, it is audited as `review.rollback_failed` and the item stays
/// `needs_attention`, first in the queue, until someone decides it again.
#[allow(clippy::too_many_arguments)]
async fn decide_safely(
    state: &AppState,
    who: &Principal,
    item: &ReviewItem,
    candidate: &Candidate,
    derived: &Derived,
    body: &ActionBody,
    current: &ReviewState,
    decided: ReviewState,
) -> Result<String, ApiError> {
    let now = (state.clock)();
    let marker = current.deciding(body.action, &who.id, now);
    if !state
        .store
        .put_review_state(&who.tenant_id, marker.clone(), current.version)
        .await?
    {
        return Err(ApiError::conflict(
            "the item changed while you acted on it; read it again",
        ));
    }
    match decide(state, who, item, candidate, derived, body).await {
        Ok(effect) => {
            let mut done = decided;
            done.version = marker.version + 1;
            done.updated_at = now;
            let recorded = state
                .store
                .put_review_state(&who.tenant_id, done, marker.version)
                .await;
            if !matches!(recorded, Ok(true)) {
                // The effect is in place; only the queue state lags. The
                // item stays needs_attention and a retry is idempotent.
                audit_failure(state, who, &item.item_id, "review.record_failed", &effect).await;
                return Err(ApiError::conflict(
                    "the decision took effect but the queue could not record it; the item needs attention",
                ));
            }
            Ok(effect)
        }
        Err(e) => {
            let mut back = current.clone();
            back.version = marker.version + 1;
            back.updated_at = now;
            let reverted = state
                .store
                .put_review_state(&who.tenant_id, back, marker.version)
                .await;
            if !matches!(reverted, Ok(true)) {
                audit_failure(
                    state,
                    who,
                    &item.item_id,
                    "review.rollback_failed",
                    &e.message,
                )
                .await;
            }
            Err(e)
        }
    }
}

/// Audit a failure in the decision path. Best effort: the caller is
/// already returning an error.
async fn audit_failure(
    state: &AppState,
    who: &Principal,
    item_id: &str,
    action: &str,
    detail: &str,
) {
    let mut rec = audit_record(state, who, action, Some(item_id), Outcome::Failed);
    rec.detail = serde_json::json!({ "detail": detail });
    let _ = state.store.append_audit(rec).await;
}

/// Append a campaign action written by a review decision. Its id is stable
/// for the item and decision, so when a retry finds it already stored (the
/// store refuses duplicate ids) the append counts as done.
async fn append_once(
    state: &AppState,
    tenant_id: &str,
    action: CampaignAction,
) -> Result<(), ApiError> {
    let id = action.action_id.clone();
    match state.store.append_campaign_action(tenant_id, action).await {
        Ok(()) => Ok(()),
        Err(e) => {
            let stored = state
                .store
                .campaign_actions(tenant_id, foiled_core::campaign::MAX_FEEDBACK_ACTIONS)
                .await?
                .iter()
                .any(|a| a.action_id == id);
            if stored { Ok(()) } else { Err(e.into()) }
        }
    }
}

/// Record an approve or reject where the decision belongs. Returns a short
/// description of the effect for the audit log.
async fn decide(
    state: &AppState,
    who: &Principal,
    item: &ReviewItem,
    c: &Candidate,
    d: &Derived,
    body: &ActionBody,
) -> Result<String, ApiError> {
    let approve = body.action == ActionKind::Approve;
    let feedback = if approve {
        Feedback::TruePositive
    } else {
        Feedback::FalsePositive
    };
    let now = (state.clock)();
    let decision = Override {
        feedback,
        analyst_id: who.id.clone(),
        at: now,
        note: body.note.clone(),
    };
    let feedback_name = if approve {
        "true_positive"
    } else {
        "false_positive"
    };
    let override_link = |attempt_id: String, kind: LinkKind, target: String| LinkOverride {
        attempt_id,
        kind,
        target,
        decision: decision.clone(),
    };
    match c.kind {
        ReviewKind::CveLink
        | ReviewKind::PredisclosureCandidate
        | ReviewKind::TechniqueLink
        | ReviewKind::FalsePositiveFeedback => {
            let technique = c
                .subject
                .target
                .as_deref()
                .and_then(foiled_core::writeup::normalise_technique)
                .is_some();
            let kind = if c.kind == ReviewKind::TechniqueLink || technique {
                LinkKind::AttemptTechnique
            } else {
                LinkKind::AttemptCve
            };
            let attempt_id = c.subject.attempt_id.clone().unwrap_or_default();
            let target = c.subject.target.clone().unwrap_or_default();
            state
                .store
                .put_link_override(
                    &who.tenant_id,
                    override_link(attempt_id.clone(), kind, target.clone()),
                )
                .await?;
            // The attempt's own audit trail shows the override too.
            let mut rec = audit_record(
                state,
                who,
                "link.override",
                Some(&attempt_id),
                Outcome::Accepted,
            );
            rec.detail = serde_json::json!({
                "kind": kind,
                "target": target,
                "feedback": feedback,
                "note": body.note,
                "review_item_id": item.item_id,
            });
            state.store.append_audit(rec).await?;
            Ok(format!("link.override {feedback_name}"))
        }
        ReviewKind::ActorAssociation => {
            // Recorded by the actor engine (#29) as an actor link decision.
            let subject_id = c
                .subject
                .attempt_id
                .clone()
                .or_else(|| c.subject.campaign_id.clone())
                .unwrap_or_default();
            let actor_id = c.subject.target.clone().unwrap_or_default();
            let link_id = foiled_core::actor::link_id(&who.tenant_id, &subject_id, &actor_id);
            let decision = if approve {
                foiled_core::actor::Decision::Confirm
            } else {
                foiled_core::actor::Decision::Reject
            };
            crate::routes::actors::record_decision(
                state,
                who,
                &link_id,
                decision,
                body.note.clone(),
                d.since,
                d.until,
            )
            .await?;
            Ok(format!("actor_link.{}", decision.as_str()))
        }
        ReviewKind::CampaignLabel => {
            let cid = c.subject.campaign_id.clone().unwrap_or_default();
            let camp = d
                .model
                .campaigns
                .get(&cid)
                .ok_or_else(|| ApiError::not_found("campaign"))?;
            let anchors: Vec<String> = camp
                .attempt_ids
                .iter()
                .rev()
                .take(MAX_ANCHORS)
                .cloned()
                .collect();
            let mut actions = Vec::new();
            if approve && let Some(title) = body.label.as_deref().map(str::trim) {
                actions.push((CampaignActionKind::Label, Some(title.to_string()), None));
            }
            actions.push((CampaignActionKind::Feedback, None, Some(feedback)));
            let mut done = Vec::new();
            for (kind, title, fb) in actions {
                let action = CampaignAction {
                    action_id: review::effect_id(&item.item_id, body.action, kind.as_str()),
                    kind,
                    campaign_id: cid.clone(),
                    anchor_attempt_ids: anchors.clone(),
                    title,
                    status: None,
                    merge: vec![],
                    attempt_ids: vec![],
                    feedback: fb,
                    note: body.note.clone(),
                    analyst_id: who.id.clone(),
                    at: now,
                };
                let problems = action.problems();
                if !problems.is_empty() {
                    return Err(ApiError::bad_request(problems.join("; ")));
                }
                append_once(state, &who.tenant_id, action.clone()).await?;
                let mut rec = audit_record(
                    state,
                    who,
                    &format!("campaign.{}", action.kind.as_str()),
                    Some(&cid),
                    Outcome::Accepted,
                );
                rec.detail = serde_json::to_value(&action).unwrap_or(serde_json::Value::Null);
                state.store.append_audit(rec).await?;
                done.push(format!("campaign.{}", action.kind.as_str()));
            }
            Ok(done.join(", "))
        }
        ReviewKind::CampaignMerge => {
            if !approve {
                return Ok("merge declined".into());
            }
            let keep = c.subject.campaign_id.clone().unwrap_or_default();
            let fold = c.subject.other_campaign_id.clone().unwrap_or_default();
            let anchors = |id: &str| -> Result<Vec<String>, ApiError> {
                Ok(d.model
                    .campaigns
                    .get(id)
                    .ok_or_else(|| ApiError::not_found("campaign"))?
                    .attempt_ids
                    .iter()
                    .rev()
                    .take(MAX_ANCHORS)
                    .cloned()
                    .collect())
            };
            let action = CampaignAction {
                action_id: review::effect_id(&item.item_id, body.action, "merge"),
                kind: CampaignActionKind::Merge,
                campaign_id: keep.clone(),
                anchor_attempt_ids: anchors(&keep)?,
                title: None,
                status: None,
                merge: vec![foiled_core::campaign::CampaignRef {
                    campaign_id: fold.clone(),
                    anchor_attempt_ids: anchors(&fold)?,
                }],
                attempt_ids: vec![],
                feedback: None,
                note: body.note.clone(),
                analyst_id: who.id.clone(),
                at: now,
            };
            let problems = action.problems();
            if !problems.is_empty() {
                return Err(ApiError::bad_request(problems.join("; ")));
            }
            append_once(state, &who.tenant_id, action.clone()).await?;
            let mut rec =
                audit_record(state, who, "campaign.merge", Some(&keep), Outcome::Accepted);
            rec.detail = serde_json::to_value(&action).unwrap_or(serde_json::Value::Null);
            state.store.append_audit(rec).await?;
            Ok("campaign.merge".into())
        }
        ReviewKind::IocPublication => Ok(if approve {
            "ioc cleared for release after the delay".into()
        } else {
            "ioc kept private".into()
        }),
        ReviewKind::WriteUp => {
            let wid = c.subject.writeup_id.clone().unwrap_or_default();
            let to = if approve {
                WriteUpStatus::Approved
            } else {
                WriteUpStatus::Draft
            };
            // A retry after the transition already happened is a no-op.
            let already = state
                .store
                .get_writeup(&who.tenant_id, &wid)
                .await?
                .is_some_and(|w| w.status == to && w.submitted_at == c.subject.submitted_at);
            if already {
                return Ok(format!("writeup.{}", to.as_str()));
            }
            crate::routes::writeups::transition(
                state,
                who,
                &wid,
                crate::routes::writeups::TransitionBody {
                    to,
                    expected_version: None,
                    note: body.note.clone(),
                    checklist: body.checklist,
                },
            )
            .await?;
            Ok(format!("writeup.{}", to.as_str()))
        }
    }
}

/// Start a draft write-up from an item. Placeholders in the template fail
/// lint on purpose, so the author has to replace them before review.
async fn promote(
    state: &AppState,
    who: &Principal,
    item: &ReviewItem,
    c: &Candidate,
    d: &Derived,
) -> Result<String, ApiError> {
    let (cves, techniques, campaigns, attempts): (
        Vec<String>,
        Vec<String>,
        Vec<String>,
        Vec<String>,
    ) = match c.kind {
        ReviewKind::CveLink | ReviewKind::PredisclosureCandidate => (
            c.subject.target.iter().cloned().collect(),
            vec![],
            vec![],
            c.subject.attempt_id.iter().cloned().collect(),
        ),
        ReviewKind::TechniqueLink => (
            vec![],
            c.subject.target.iter().cloned().collect(),
            vec![],
            c.subject.attempt_id.iter().cloned().collect(),
        ),
        ReviewKind::CampaignLabel => {
            let cid = c.subject.campaign_id.clone().unwrap_or_default();
            let camp = d.model.campaigns.get(&cid);
            (
                camp.map(|x| x.feature_summary.targeting.cves.clone())
                    .unwrap_or_default(),
                vec![],
                vec![cid],
                camp.map(|x| {
                    x.attempt_ids
                        .iter()
                        .take(foiled_core::writeup::MAX_REFS)
                        .cloned()
                        .collect()
                })
                .unwrap_or_default(),
            )
        }
        _ => {
            return Err(ApiError::bad_request(
                "only CVE, technique, pre-disclosure and campaign items can be promoted",
            ));
        }
    };
    let cves: Vec<String> = cves
        .iter()
        .filter_map(|c| foiled_core::writeup::normalise_cve(c))
        .take(foiled_core::writeup::MAX_REFS)
        .collect();
    let techniques: Vec<String> = techniques
        .iter()
        .filter_map(|t| foiled_core::writeup::normalise_technique(t))
        .collect();
    let subject = cves
        .first()
        .or(techniques.first())
        .cloned()
        .unwrap_or_else(|| "activity".into());
    let now = (state.clock)();
    let seed = (state.ids)();
    let writeup_id = foiled_core::writeup::writeup_id(&seed);
    let slug = format!(
        "{}-{}",
        subject.to_ascii_lowercase().replace('.', "-"),
        &writeup_id[3..9]
    );
    let w = WriteUp {
        writeup_id: writeup_id.clone(),
        tenant_id: who.tenant_id.clone(),
        slug,
        title: format!("Activity we assess as targeting {subject}"),
        summary: String::new(),
        body_md: format!(
            "## Summary\n\nWe assess as attempts against {subject}. TODO: describe the behaviour \
             sequence.\n\n## Timeline\n\nTODO: first seen on Foiled sensors, advisory date.\n\n\
             ## Sources\n\nTODO: link the advisory.\n"
        ),
        status: WriteUpStatus::Draft,
        tlp: foiled_core::share::Tlp::Clear,
        embargo_until: None,
        cve_ids: cves,
        technique_ids: techniques,
        campaign_ids: campaigns,
        ioc_ids: vec![],
        attempt_ids: attempts,
        first_seen: Some(item.created_at),
        redacted_payload: None,
        source_item_id: Some(item.item_id.clone()),
        author_id: who.id.clone(),
        reviewer_id: None,
        checklist: None,
        version: 1,
        created_at: now,
        updated_at: now,
        submitted_at: None,
        approved_at: None,
        published_at: None,
        withdrawn_at: None,
    };
    state.store.insert_writeup(w, &who.id).await?;
    let mut rec = audit_record(
        state,
        who,
        "writeup.create",
        Some(&writeup_id),
        Outcome::Accepted,
    );
    rec.detail = serde_json::json!({ "source_item_id": item.item_id });
    state.store.append_audit(rec).await?;
    Ok(writeup_id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pending_hides_decided_items() {
        assert!(StatusFilter::Pending.matches(ReviewStatus::Snoozed));
        assert!(!StatusFilter::Pending.matches(ReviewStatus::Approved));
        assert!(StatusFilter::All.matches(ReviewStatus::Rejected));
    }

    #[test]
    fn sentence_case_capitalises_wording() {
        assert_eq!(sentence_case("we assess as"), "We assess as");
        assert_eq!(sentence_case(""), "");
    }
}
