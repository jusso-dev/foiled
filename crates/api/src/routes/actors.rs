//! Actor possible-association (#29): the public-source reference catalogue
//! (`GET /v0/actors`, `GET /v0/actors/{actor_id}`), the tenant's actor
//! links (`GET /v0/actor-links`, `GET /v0/actor-links/{link_id}`) and
//! audited analyst decisions (`POST /v0/actor-links/{link_id}/decision`).
//!
//! Links are a read model like campaigns: matched on request with
//! `foiled_core::actor` over the campaigns and lone attempts in a bounded
//! window, scored through #27 and capped so nothing reaches `high` or
//! publishes without an analyst. Only the decisions are stored. Every route
//! is scoped to the caller's tenant.
//!
//! The review queue (#35) lists pending links with
//! `GET /v0/actor-links?status=pending&review_queue=true` (or
//! [`actor_model`]) and records decisions through [`record_decision`].

use std::collections::{BTreeMap, BTreeSet};

use axum::extract::{Path, Query, State};
use axum::routing::{get, post};
use axum::{Json, Router};
use foiled_core::actor::{
    self, ActorDecision, ActorLink, ActorProfile, Decision, LabelKind, LinkStatus, Subject,
    SubjectInput, SubjectKind, valid_actor_id, valid_link_id,
};
use foiled_core::attempt::Attempt;
use foiled_core::auth::{Principal, Scope};
use foiled_core::campaign::Campaign;
use foiled_core::capture::CaptureEvent;
use foiled_core::confidence::{ConfidenceConfig, Override};
use foiled_core::ioc::Extraction;
use serde::{Deserialize, Serialize};

use crate::AppState;
use crate::auth::Auth;
use crate::error::ApiError;
use crate::routes::attempts::{
    Campaigns, ClusterInputs, Iocs, WindowModel, canonical_window, window_bounds, window_model,
};
use crate::routes::page_limit;

pub const MAX_NOTE_CHARS: usize = 1000;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/v0/actors", get(list_actors))
        .route("/v0/actors/{actor_id}", get(get_actor))
        .route("/v0/actor-links", get(list_links))
        .route("/v0/actor-links/{link_id}", get(get_link))
        .route("/v0/actor-links/{link_id}/decision", post(decide))
}

// ---------------------------------------------------------------------------
// The catalogue
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceFilter {
    Attack,
    Report,
}

#[derive(Debug, Deserialize, Default)]
pub struct ActorQuery {
    /// Case-insensitive text in the label or an alias.
    pub q: Option<String>,
    pub label_kind: Option<LabelKind>,
    pub source: Option<SourceFilter>,
    /// Profiles using this ATT&CK technique id.
    pub technique: Option<String>,
    pub limit: Option<usize>,
    /// Return profiles after this actor id.
    pub cursor: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct ActorList {
    pub items: Vec<ActorProfile>,
    pub next_cursor: Option<String>,
    /// Profiles in the rarity population (every active ATT&CK group plus
    /// every curated report).
    pub population: u32,
    pub attack_version: Option<String>,
    /// MITRE's copyright designation and licence, which travel with ATT&CK
    /// group names.
    pub attack_notice: Option<String>,
}

async fn list_actors(
    State(state): State<AppState>,
    auth: Auth,
    Query(q): Query<ActorQuery>,
) -> Result<Json<ActorList>, ApiError> {
    auth.require(Scope::CampaignsRead)?;
    if q.q.as_ref().is_some_and(|t| t.chars().count() > 100) {
        return Err(ApiError::bad_request("q must be at most 100 characters"));
    }
    let needle = q.q.as_deref().map(str::to_lowercase);
    let limit = page_limit(q.limit);
    let cat = &state.actors;
    let mut items: Vec<ActorProfile> = cat
        .profiles
        .iter()
        .filter(|p| q.cursor.as_deref().is_none_or(|c| p.actor_id.as_str() > c))
        .filter(|p| q.label_kind.is_none_or(|k| p.label_kind == k))
        .filter(|p| match q.source {
            None => true,
            Some(SourceFilter::Attack) => p.actor_id.starts_with("attack:"),
            Some(SourceFilter::Report) => p.actor_id.starts_with("report:"),
        })
        .filter(|p| {
            q.technique
                .as_deref()
                .is_none_or(|t| p.techniques.iter().any(|x| x.eq_ignore_ascii_case(t)))
        })
        .filter(|p| {
            needle.as_deref().is_none_or(|n| {
                p.label.to_lowercase().contains(n)
                    || p.aliases.iter().any(|a| a.to_lowercase().contains(n))
            })
        })
        .take(limit + 1)
        .cloned()
        .collect();
    let next_cursor = if items.len() > limit {
        items.truncate(limit);
        items.last().map(|p| p.actor_id.clone())
    } else {
        None
    };
    Ok(Json(ActorList {
        items,
        next_cursor,
        population: cat.population,
        attack_version: cat.attack_version.clone(),
        attack_notice: cat.attack_notice.clone(),
    }))
}

async fn get_actor(
    State(state): State<AppState>,
    auth: Auth,
    Path(actor_id): Path<String>,
) -> Result<Json<ActorProfile>, ApiError> {
    auth.require(Scope::CampaignsRead)?;
    if !valid_actor_id(&actor_id) {
        return Err(ApiError::not_found("actor"));
    }
    state
        .actors
        .get(&actor_id)
        .cloned()
        .map(Json)
        .ok_or_else(|| ApiError::not_found("actor"))
}

// ---------------------------------------------------------------------------
// Links over a window
// ---------------------------------------------------------------------------

/// Actor links for one tenant and window, with what is needed to score a
/// subject again after a decision.
pub(crate) struct ActorModel {
    /// Per subject, decided links plus the strongest pending ones.
    pub links: Vec<ActorLink>,
    pub truncated: bool,
    subjects: Vec<Subject>,
    decisions: BTreeMap<(String, String), ActorDecision>,
}

/// What [`match_window`] reads from a window model.
#[derive(Clone, Copy)]
pub(crate) struct Window<'a> {
    pub attempts: &'a [Attempt],
    /// Also match attempts in no listed campaign.
    pub lone_attempts: bool,
    pub events: &'a [CaptureEvent],
    pub iocs: &'a Extraction,
    pub inputs: &'a ClusterInputs,
}

impl<'a> Window<'a> {
    /// Campaigns only, from a full window model.
    pub(crate) fn campaigns_of(m: &'a WindowModel, inputs: &'a ClusterInputs) -> Self {
        Window {
            attempts: &m.attempts,
            lone_attempts: false,
            events: &m.events,
            iocs: &m.iocs,
            inputs,
        }
    }
}

/// Match campaigns (and, with `lone_attempts`, the attempts in none of
/// them) against the catalogue and fill `suggested_actor_links` on
/// `campaigns`. Store reads (source countries for the explanation, and
/// analyst decisions) happen only for subjects that matched a profile, so
/// a window with no candidate costs no extra read.
pub(crate) async fn match_window(
    state: &AppState,
    tenant_id: &str,
    campaigns: &mut [Campaign],
    w: Window<'_>,
) -> Result<
    (
        Vec<ActorLink>,
        Vec<Subject>,
        BTreeMap<(String, String), ActorDecision>,
    ),
    ApiError,
> {
    let cfg = ConfidenceConfig::default();
    let all = actor::subjects(&SubjectInput {
        tenant_id,
        campaigns,
        attempts: w.attempts,
        lone_attempts: w.lone_attempts,
        signals: &w.inputs.signals,
        iocs: w.iocs,
        asns: &w.inputs.asns,
        countries: &BTreeMap::new(),
        events: w.events,
    });
    let first = actor::suggest(&state.actors, &cfg, &all, &BTreeMap::new());
    let linked: BTreeSet<&str> = first.iter().map(|l| l.subject_id.as_str()).collect();
    let mut subjects: Vec<Subject> = all
        .into_iter()
        .filter(|s| linked.contains(s.id.as_str()))
        .collect();
    if subjects.is_empty() {
        actor::attach_suggestions(campaigns, &[]);
        return Ok((Vec::new(), Vec::new(), BTreeMap::new()));
    }
    let countries = source_countries(
        state,
        subjects
            .iter()
            .flat_map(|s| s.sources.iter().map(String::as_str)),
    )
    .await;
    for s in subjects.iter_mut() {
        s.set_countries(&countries);
    }
    let decisions: BTreeMap<(String, String), ActorDecision> = state
        .store
        .actor_decisions(tenant_id, subjects.iter().map(|s| s.id.clone()).collect())
        .await?
        .into_iter()
        .map(|d| ((d.subject_id.clone(), d.actor_id.clone()), d))
        .collect();
    let links = actor::suggest(&state.actors, &cfg, &subjects, &decisions);
    actor::attach_suggestions(campaigns, &links);
    Ok((links, subjects, decisions))
}

/// Source address to the newest cached `geo.country` Fact (#11), for the
/// `not_counted` explanation only. Geography is never evidence, so if the
/// cache cannot be read the link is built without it.
async fn source_countries<'a>(
    state: &AppState,
    addresses: impl Iterator<Item = &'a str>,
) -> BTreeMap<String, String> {
    use foiled_core::enrichment::Observable;
    let mut by_observable: BTreeMap<Observable, BTreeSet<&str>> = BTreeMap::new();
    for a in addresses {
        if let Ok(o) = Observable::ip(a) {
            by_observable.entry(o).or_default().insert(a);
        }
    }
    let cached =
        crate::enrichment::cached_facts(state, by_observable.keys().cloned().collect()).await;
    let mut out = BTreeMap::new();
    for (o, facts) in &cached.facts {
        let newest = facts
            .iter()
            .filter(|f| f.key == "geo.country")
            .filter_map(|f| {
                f.value
                    .as_str()
                    .filter(|c| c.len() == 2 && c.bytes().all(|b| b.is_ascii_uppercase()))
                    .map(|c| (f.observed_at, c.to_string()))
            })
            .max();
        if let Some((_, c)) = newest {
            for a in by_observable.get(o).into_iter().flatten() {
                out.insert((*a).to_string(), c.clone());
            }
        }
    }
    out
}

/// Fill `suggested_actor_links` on one campaign of a full window model
/// (campaign detail, #33). Lone attempts are not matched.
pub(crate) async fn attach_to_campaign(
    state: &AppState,
    tenant_id: &str,
    m: &WindowModel,
    campaign: &mut Campaign,
) -> Result<(), ApiError> {
    let Some(inputs) = m.inputs.as_ref() else {
        return Ok(());
    };
    match_window(
        state,
        tenant_id,
        std::slice::from_mut(campaign),
        Window::campaigns_of(m, inputs),
    )
    .await?;
    Ok(())
}

/// Fill `suggested_actor_links` on every campaign of a full window model
/// (the campaign list with `include=actors`). Lone attempts are not
/// matched.
pub(crate) async fn attach_to_model(
    state: &AppState,
    tenant_id: &str,
    m: &mut WindowModel,
) -> Result<(), ApiError> {
    let Some(inputs) = m.inputs.take() else {
        return Ok(());
    };
    let mut campaigns = std::mem::take(&mut m.campaigns.campaigns);
    let r = match_window(
        state,
        tenant_id,
        &mut campaigns,
        Window::campaigns_of(m, &inputs),
    )
    .await;
    m.campaigns.campaigns = campaigns;
    m.inputs = Some(inputs);
    r?;
    Ok(())
}

/// Every actor link in a window, for this API and the review queue (#35).
/// Campaign ids are recorded in the registry only for the canonical
/// window, as for the campaign routes.
pub(crate) async fn actor_model(
    state: &AppState,
    tenant_id: &str,
    since: Option<i64>,
    until: Option<i64>,
) -> Result<ActorModel, ApiError> {
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
    let inputs = m.inputs.take().expect("full model has inputs");
    let mut campaigns = std::mem::take(&mut m.campaigns.campaigns);
    let (links, subjects, decisions) = match_window(
        state,
        tenant_id,
        &mut campaigns,
        Window {
            lone_attempts: true,
            ..Window::campaigns_of(&m, &inputs)
        },
    )
    .await?;
    Ok(ActorModel {
        links,
        truncated: m.truncated,
        subjects,
        decisions,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StatusFilter {
    Pending,
    Confirmed,
    Rejected,
}

#[derive(Debug, Deserialize, Default)]
pub struct LinkQuery {
    pub since: Option<i64>,
    pub until: Option<i64>,
    pub status: Option<StatusFilter>,
    pub subject_kind: Option<SubjectKind>,
    /// A campaign or attempt id.
    pub subject_id: Option<String>,
    pub actor_id: Option<String>,
    /// Only links the review queue should show (#35): pending and at or
    /// above `radar_queue_min`.
    pub review_queue: Option<bool>,
    /// 0 to 100.
    pub min_confidence: Option<u8>,
    pub limit: Option<usize>,
}

#[derive(Debug, Serialize)]
pub struct LinkList {
    pub items: Vec<ActorLink>,
    /// True when the window held more events than the cap; narrow it.
    pub truncated: bool,
}

fn status_matches(s: LinkStatus, f: StatusFilter) -> bool {
    matches!(
        (s, f),
        (LinkStatus::Pending, StatusFilter::Pending)
            | (LinkStatus::Confirmed, StatusFilter::Confirmed)
            | (LinkStatus::Rejected, StatusFilter::Rejected)
    )
}

async fn list_links(
    State(state): State<AppState>,
    auth: Auth,
    Query(q): Query<LinkQuery>,
) -> Result<Json<LinkList>, ApiError> {
    let who = auth.require(Scope::CampaignsRead)?;
    if q.min_confidence.is_some_and(|m| m > 100) {
        return Err(ApiError::bad_request(
            "min_confidence must be between 0 and 100",
        ));
    }
    let m = actor_model(&state, &who.tenant_id, q.since, q.until).await?;
    let mut items: Vec<ActorLink> = m
        .links
        .into_iter()
        .filter(|l| q.status.is_none_or(|s| status_matches(l.status, s)))
        .filter(|l| q.subject_kind.is_none_or(|k| l.subject_kind == k))
        .filter(|l| q.subject_id.as_deref().is_none_or(|s| l.subject_id == s))
        .filter(|l| q.actor_id.as_deref().is_none_or(|a| l.actor_id == a))
        .filter(|l| q.review_queue.is_none_or(|r| l.review_queue == r))
        .filter(|l| q.min_confidence.is_none_or(|n| l.score >= n))
        .collect();
    // Strongest first.
    items.sort_by(|a, b| (b.score, &a.link_id).cmp(&(a.score, &b.link_id)));
    items.truncate(page_limit(q.limit));
    Ok(Json(LinkList {
        items,
        truncated: m.truncated,
    }))
}

#[derive(Debug, Deserialize, Default)]
pub struct WindowQuery {
    pub since: Option<i64>,
    pub until: Option<i64>,
}

async fn get_link(
    State(state): State<AppState>,
    auth: Auth,
    Path(link_id): Path<String>,
    Query(q): Query<WindowQuery>,
) -> Result<Json<ActorLink>, ApiError> {
    let who = auth.require(Scope::CampaignsRead)?;
    if !valid_link_id(&link_id) {
        return Err(ApiError::not_found("actor link"));
    }
    let m = actor_model(&state, &who.tenant_id, q.since, q.until).await?;
    m.links
        .into_iter()
        .find(|l| l.link_id == link_id)
        .map(Json)
        .ok_or_else(|| ApiError::not_found("actor link"))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DecisionBody {
    pub decision: Decision,
    /// Why. Required to confirm.
    pub note: String,
}

/// Record an analyst decision on an actor link in the window (audited as
/// `actor_link.<decision>`) and return the link as it scores now. Shared
/// with the review queue (#35). The caller checks `review:write`.
pub(crate) async fn record_decision(
    state: &AppState,
    who: &Principal,
    link_id: &str,
    decision: Decision,
    note: String,
    since: Option<i64>,
    until: Option<i64>,
) -> Result<ActorLink, ApiError> {
    if !valid_link_id(link_id) {
        return Err(ApiError::not_found("actor link"));
    }
    if note.chars().count() > MAX_NOTE_CHARS {
        return Err(ApiError::bad_request(format!(
            "note must be at most {MAX_NOTE_CHARS} characters"
        )));
    }
    // The note travels with the link in the audit log and the console; it
    // must not make the attribution claim the link itself never makes.
    let problems = actor::wording_problems(&note, true);
    if !problems.is_empty() {
        return Err(ApiError::bad_request(format!(
            "note: {}",
            problems.join("; ")
        )));
    }
    if decision == Decision::Confirm && note.trim().is_empty() {
        return Err(ApiError::bad_request(
            "a confirmation needs a note saying why",
        ));
    }
    crate::routes::check_rate(
        state,
        who,
        "actor_link.decision",
        state.limits.actor_decisions_per_hour,
        crate::routes::HOUR_MS,
    )
    .await?;
    let mut m = actor_model(state, &who.tenant_id, since, until).await?;
    let before = m
        .links
        .iter()
        .find(|l| l.link_id == link_id)
        .cloned()
        .ok_or_else(|| ApiError::not_found("actor link"))?;
    let o = Override {
        feedback: decision.feedback(),
        analyst_id: who.id.clone(),
        at: (state.clock)(),
        note: note.clone(),
    };
    state
        .store
        .put_actor_decision(
            &who.tenant_id,
            ActorDecision {
                subject_id: before.subject_id.clone(),
                actor_id: before.actor_id.clone(),
                decision: o.clone(),
                // What the analyst saw: a confirmation covers these attempts
                // only, never ones that join the campaign later.
                attempt_ids: before.attempt_ids.clone(),
            },
        )
        .await?;
    let mut rec = crate::routes::audit_record(
        state,
        who,
        &format!("actor_link.{}", decision.as_str()),
        Some(link_id),
        foiled_core::audit::Outcome::Accepted,
    );
    rec.detail = serde_json::json!({
        "subject_kind": before.subject_kind,
        "subject_id": before.subject_id,
        "actor_id": before.actor_id,
        "label": before.label,
        "status_before": before.status,
        "score_before": before.score,
        "band_before": before.band,
        "decision": decision,
        "note": note,
        "attempt_ids": before.attempt_ids,
    });
    state.store.append_audit(rec).await?;
    m.decisions.insert(
        (before.subject_id.clone(), before.actor_id.clone()),
        ActorDecision {
            subject_id: before.subject_id.clone(),
            actor_id: before.actor_id.clone(),
            decision: o,
            attempt_ids: before.attempt_ids.clone(),
        },
    );
    let subject: Vec<Subject> = m
        .subjects
        .into_iter()
        .filter(|s| s.id == before.subject_id)
        .collect();
    actor::suggest(
        &state.actors,
        &ConfidenceConfig::default(),
        &subject,
        &m.decisions,
    )
    .into_iter()
    .find(|l| l.link_id == link_id)
    .ok_or_else(|| ApiError::not_found("actor link"))
}

async fn decide(
    State(state): State<AppState>,
    auth: Auth,
    Path(link_id): Path<String>,
    Query(q): Query<WindowQuery>,
    crate::error::JsonBody(body): crate::error::JsonBody<DecisionBody>,
) -> Result<Json<ActorLink>, ApiError> {
    let who = auth.require(Scope::ReviewWrite)?.clone();
    record_decision(
        &state,
        &who,
        &link_id,
        body.decision,
        body.note,
        q.since,
        q.until,
    )
    .await
    .map(Json)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_filter_maps_each_status() {
        assert!(status_matches(LinkStatus::Pending, StatusFilter::Pending));
        assert!(!status_matches(
            LinkStatus::Confirmed,
            StatusFilter::Pending
        ));
        assert!(status_matches(LinkStatus::Rejected, StatusFilter::Rejected));
    }
}
