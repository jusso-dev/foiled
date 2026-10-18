//! Campaign endpoints (#33): `GET /v0/campaigns`, `GET /v0/campaigns/{id}`,
//! its member attempts, its confidence evidence, and analyst actions
//! (`GET` and `POST /v0/campaigns/{id}/actions`).
//!
//! Campaigns are a read model like attempts and IOCs: clustered on request
//! from the attempts in a bounded window with `foiled_core::campaign`, so
//! the same evidence and actions always give the same campaigns and ids.
//! Every route is scoped to the caller's tenant. Analyst actions are stored
//! append-only, replayed over the clustering, and written to the audit log.

use axum::extract::{Path, Query, State};
use axum::routing::get;
use axum::{Json, Router};
use foiled_core::attempt::Attempt;
use foiled_core::auth::Scope;
use foiled_core::campaign::{
    ActionKind, Campaign, CampaignAction, CampaignRef, CampaignStatus, MAX_ACTION_ATTEMPTS,
    MAX_ACTION_CAMPAIGNS, MAX_ACTIONS, campaign_link, member_links, split_campaign_id,
    valid_campaign_id,
};
use foiled_core::confidence::{ConfidenceConfig, ConfidenceLink, Feedback};
use serde::{Deserialize, Serialize};

use crate::AppState;
use crate::auth::Auth;
use crate::error::ApiError;
use crate::routes::attempts::{Iocs, WindowModel, window_bounds, window_model};
use crate::routes::page_limit;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/v0/campaigns", get(list))
        .route("/v0/campaigns/{campaign_id}", get(get_one))
        .route("/v0/campaigns/{campaign_id}/attempts", get(attempts))
        .route("/v0/campaigns/{campaign_id}/evidence", get(evidence))
        .route(
            "/v0/campaigns/{campaign_id}/actions",
            get(list_actions).post(act),
        )
}

#[derive(Debug, Deserialize, Default)]
pub struct CampaignQuery {
    pub since: Option<i64>,
    pub until: Option<i64>,
    pub status: Option<CampaignStatus>,
    /// Campaigns holding this attempt.
    pub attempt_id: Option<String>,
    pub sensor_id: Option<String>,
    pub decoy_id: Option<String>,
    /// Case-insensitive CVE id among the campaign's CVEs.
    pub cve: Option<String>,
    /// Campaigns sharing this IOC between members (#34).
    pub ioc_id: Option<String>,
    /// 0 to 100, against the campaign's confidence score (#27).
    pub min_confidence: Option<u8>,
    pub limit: Option<usize>,
}

#[derive(Debug, Deserialize, Default)]
pub struct WindowQuery {
    pub since: Option<i64>,
    pub until: Option<i64>,
    pub limit: Option<usize>,
}

#[derive(Debug, Serialize)]
pub struct CampaignList {
    pub items: Vec<Campaign>,
    /// True when the window held more events than the cap; narrow it.
    pub truncated: bool,
    /// Analyst actions that did not apply in this window, and similar.
    pub notes: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct CampaignAttempts {
    pub campaign_id: String,
    pub items: Vec<Attempt>,
    pub truncated: bool,
}

#[derive(Debug, Serialize)]
pub struct CampaignEvidence {
    pub campaign_id: String,
    /// The campaign as a whole (attempt: the seed).
    pub confidence: ConfidenceLink,
    /// One `attempt_campaign` link per member, in member order.
    pub members: Vec<ConfidenceLink>,
    pub truncated: bool,
}

#[derive(Debug, Serialize)]
pub struct ActionList {
    pub campaign_id: String,
    pub items: Vec<CampaignAction>,
}

#[derive(Debug, Serialize)]
pub struct ActionResult {
    pub action: CampaignAction,
    /// The campaign as it is now, or null when the action dissolved it.
    pub campaign: Option<Campaign>,
}

async fn model(
    state: &AppState,
    tenant_id: &str,
    since: Option<i64>,
    until: Option<i64>,
) -> Result<WindowModel, ApiError> {
    let (since, until) = window_bounds(state, since, until);
    window_model(state, tenant_id, since, until, Iocs::Attach).await
}

fn find(m: WindowModel, campaign_id: &str) -> Result<(Campaign, WindowModel), ApiError> {
    let c = m
        .campaigns
        .get(campaign_id)
        .cloned()
        .ok_or_else(|| ApiError::not_found("campaign"))?;
    Ok((c, m))
}

async fn list(
    State(state): State<AppState>,
    auth: Auth,
    Query(q): Query<CampaignQuery>,
) -> Result<Json<CampaignList>, ApiError> {
    let who = auth.require(Scope::CampaignsRead)?;
    if q.min_confidence.is_some_and(|m| m > 100) {
        return Err(ApiError::bad_request(
            "min_confidence must be between 0 and 100",
        ));
    }
    let m = model(&state, &who.tenant_id, q.since, q.until).await?;
    let mut items: Vec<Campaign> = m
        .campaigns
        .campaigns
        .into_iter()
        .filter(|c| q.status.is_none_or(|s| c.status == s))
        .filter(|c| {
            q.attempt_id
                .as_deref()
                .is_none_or(|a| c.attempt_ids.iter().any(|x| x == a))
        })
        .filter(|c| {
            q.sensor_id
                .as_deref()
                .is_none_or(|s| c.sensor_ids.iter().any(|x| x == s))
        })
        .filter(|c| {
            q.decoy_id
                .as_deref()
                .is_none_or(|d| c.decoy_ids.iter().any(|x| x == d))
        })
        .filter(|c| {
            q.cve.as_deref().is_none_or(|v| {
                c.feature_summary
                    .targeting
                    .cves
                    .iter()
                    .any(|x| x.eq_ignore_ascii_case(v))
            })
        })
        .filter(|c| {
            q.ioc_id
                .as_deref()
                .is_none_or(|i| c.shared_ioc_ids.iter().any(|x| x == i))
        })
        .filter(|c| q.min_confidence.is_none_or(|n| c.confidence.score >= n))
        .collect();
    // Newest activity first.
    items.sort_by(|a, b| (b.last_seen, &b.campaign_id).cmp(&(a.last_seen, &a.campaign_id)));
    items.truncate(page_limit(q.limit));
    Ok(Json(CampaignList {
        items,
        truncated: m.truncated,
        notes: m.campaigns.notes,
    }))
}

async fn get_one(
    State(state): State<AppState>,
    auth: Auth,
    Path(campaign_id): Path<String>,
    Query(q): Query<WindowQuery>,
) -> Result<Json<Campaign>, ApiError> {
    let who = auth.require(Scope::CampaignsRead)?;
    if !valid_campaign_id(&campaign_id) {
        return Err(ApiError::not_found("campaign"));
    }
    let m = model(&state, &who.tenant_id, q.since, q.until).await?;
    Ok(Json(find(m, &campaign_id)?.0))
}

/// Member attempts, newest activity first, with `campaign_id` filled.
async fn attempts(
    State(state): State<AppState>,
    auth: Auth,
    Path(campaign_id): Path<String>,
    Query(q): Query<WindowQuery>,
) -> Result<Json<CampaignAttempts>, ApiError> {
    let who = auth.require(Scope::CampaignsRead)?.clone();
    auth.require(Scope::AttemptsRead)?;
    if !valid_campaign_id(&campaign_id) {
        return Err(ApiError::not_found("campaign"));
    }
    let m = model(&state, &who.tenant_id, q.since, q.until).await?;
    let (_, m) = find(m, &campaign_id)?;
    let mut items: Vec<Attempt> = m
        .attempts
        .into_iter()
        .filter(|a| a.campaign_id.as_deref() == Some(campaign_id.as_str()))
        .collect();
    items.sort_by(|a, b| (b.last_seen, &b.attempt_id).cmp(&(a.last_seen, &a.attempt_id)));
    items.truncate(page_limit(q.limit));
    Ok(Json(CampaignAttempts {
        campaign_id,
        items,
        truncated: m.truncated,
    }))
}

/// The full #27 explanation: the campaign link and one link per member.
async fn evidence(
    State(state): State<AppState>,
    auth: Auth,
    Path(campaign_id): Path<String>,
    Query(q): Query<WindowQuery>,
) -> Result<Json<CampaignEvidence>, ApiError> {
    let who = auth.require(Scope::CampaignsRead)?;
    if !valid_campaign_id(&campaign_id) {
        return Err(ApiError::not_found("campaign"));
    }
    let m = model(&state, &who.tenant_id, q.since, q.until).await?;
    let truncated = m.truncated;
    let (c, _) = find(m, &campaign_id)?;
    let cfg = ConfidenceConfig::default();
    let confidence = campaign_link(&cfg, &c).ok_or_else(|| ApiError::not_found("campaign"))?;
    Ok(Json(CampaignEvidence {
        members: member_links(&cfg, &c),
        confidence,
        campaign_id,
        truncated,
    }))
}

/// Stored actions that name this campaign: as the target, as a merged-in
/// campaign, or as the campaign a split created. Read from storage only, so
/// actions on a campaign outside the current window are still listed.
async fn list_actions(
    State(state): State<AppState>,
    auth: Auth,
    Path(campaign_id): Path<String>,
) -> Result<Json<ActionList>, ApiError> {
    let who = auth.require(Scope::CampaignsRead)?;
    if !valid_campaign_id(&campaign_id) {
        return Err(ApiError::not_found("campaign"));
    }
    let items = state
        .store
        .campaign_actions(&who.tenant_id, MAX_ACTIONS)
        .await?
        .into_iter()
        .filter(|a| {
            a.campaign_id == campaign_id
                || a.merge.iter().any(|r| r.campaign_id == campaign_id)
                || (a.kind == ActionKind::Split
                    && split_campaign_id(&who.tenant_id, &a.action_id) == campaign_id)
        })
        .collect();
    Ok(Json(ActionList { campaign_id, items }))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActionBody {
    pub action: ActionKind,
    /// `label`.
    pub title: Option<String>,
    /// `status`: `emerging`, `active` or `closed`; null clears the override.
    pub status: Option<CampaignStatus>,
    /// `merge`: campaigns in the same window to fold into this one.
    pub campaign_ids: Option<Vec<String>>,
    /// `split`: member attempts to move into a campaign of their own.
    pub attempt_ids: Option<Vec<String>>,
    /// `feedback`.
    pub feedback: Option<Feedback>,
    pub note: String,
}

/// Record an analyst action (audited as `campaign.<action>`), then return
/// the campaign as it is now.
async fn act(
    State(state): State<AppState>,
    auth: Auth,
    Path(campaign_id): Path<String>,
    Query(q): Query<WindowQuery>,
    crate::error::JsonBody(body): crate::error::JsonBody<ActionBody>,
) -> Result<Json<ActionResult>, ApiError> {
    let who = auth.require(Scope::CampaignsWrite)?.clone();
    if !valid_campaign_id(&campaign_id) {
        return Err(ApiError::not_found("campaign"));
    }
    // Cheap size checks before the window is built.
    if body
        .campaign_ids
        .as_ref()
        .is_some_and(|v| v.len() > MAX_ACTION_CAMPAIGNS)
    {
        return Err(ApiError::bad_request(format!(
            "campaign_ids takes at most {MAX_ACTION_CAMPAIGNS} campaigns"
        )));
    }
    if body
        .attempt_ids
        .as_ref()
        .is_some_and(|v| v.len() > MAX_ACTION_ATTEMPTS)
    {
        return Err(ApiError::bad_request(format!(
            "attempt_ids takes at most {MAX_ACTION_ATTEMPTS} attempts"
        )));
    }
    let m = model(&state, &who.tenant_id, q.since, q.until).await?;
    let (c, m) = find(m, &campaign_id)?;

    let mut merge = Vec::new();
    for id in body.campaign_ids.iter().flatten() {
        if *id == campaign_id {
            return Err(ApiError::bad_request("a campaign cannot merge with itself"));
        }
        let other = m.campaigns.get(id).ok_or_else(|| {
            ApiError::bad_request("campaign_ids must name campaigns in the same window")
        })?;
        merge.push(CampaignRef {
            campaign_id: other.campaign_id.clone(),
            anchor_attempt_id: other.seed.attempt_id.clone(),
        });
    }
    let attempt_ids = body.attempt_ids.clone().unwrap_or_default();
    if attempt_ids.iter().any(|a| !c.attempt_ids.contains(a)) {
        return Err(ApiError::bad_request(
            "attempt_ids must name attempts in this campaign",
        ));
    }
    if body.action == ActionKind::Split && attempt_ids.len() >= c.attempt_ids.len() {
        return Err(ApiError::bad_request(
            "a split must leave at least one attempt in the campaign",
        ));
    }
    let action = CampaignAction {
        action_id: (state.ids)(),
        kind: body.action,
        campaign_id: campaign_id.clone(),
        anchor_attempt_id: c.seed.attempt_id.clone(),
        title: body.title.map(|t| t.trim().to_string()),
        status: body.status,
        merge,
        attempt_ids,
        feedback: body.feedback,
        note: body.note,
        analyst_id: who.id.clone(),
        at: (state.clock)(),
    };
    let problems = action.problems();
    if !problems.is_empty() {
        return Err(ApiError::bad_request(problems.join("; ")));
    }
    state
        .store
        .append_campaign_action(&who.tenant_id, action.clone())
        .await?;
    let mut rec = crate::routes::audit_record(
        &state,
        &who,
        &format!("campaign.{}", action.kind.as_str()),
        Some(&campaign_id),
        foiled_core::audit::Outcome::Accepted,
    );
    rec.detail = serde_json::to_value(&action).unwrap_or(serde_json::Value::Null);
    state.store.append_audit(rec).await?;

    let m = model(&state, &who.tenant_id, q.since, q.until).await?;
    let campaign = m.campaigns.get(&campaign_id).cloned();
    Ok(Json(ActionResult { action, campaign }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn campaign_ids_are_checked_before_lookup() {
        assert!(valid_campaign_id("cmp_0123456789abcdef01234567"));
        assert!(!valid_campaign_id("cmp_0123456789ABCDEF01234567"));
        assert!(!valid_campaign_id("cmp_../../etc"));
        assert!(!valid_campaign_id("att_0123456789abcdef01234567"));
    }
}
