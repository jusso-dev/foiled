//! `GET /v0/attempts` and `GET /v0/attempts/{id}` (#25).
//!
//! Attempts are a read model: built on request from the capture events in a
//! time window with the deterministic grouping in `foiled_core::attempt`,
//! so the same evidence always gives the same attempts and ids. Windows are
//! bounded (default 7 days, at most 20,000 events) to stay inside Workers
//! CPU limits; a materialised table can replace this without changing the
//! contract.

use axum::extract::{Path, Query, State};
use axum::routing::get;
use axum::{Json, Router};
use foiled_core::attempt::{Attempt, AttemptState, DEFAULT_IDLE_GAP_MS, ExtraSignals, build};
use foiled_core::auth::Scope;
use foiled_core::catalogue::DecoyKind;
use serde::{Deserialize, Serialize};

use crate::AppState;
use crate::auth::Auth;
use crate::error::ApiError;
use crate::routes::page_limit;

pub const MAX_WINDOW_EVENTS: usize = 20_000;
const DAY_MS: i64 = 24 * 3600 * 1000;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/v0/attempts", get(list))
        .route("/v0/attempts/{attempt_id}", get(get_one))
}

#[derive(Debug, Deserialize, Default)]
pub struct AttemptQuery {
    pub since: Option<i64>,
    pub until: Option<i64>,
    pub decoy_id: Option<String>,
    pub decoy_kind: Option<DecoyKind>,
    pub sensor_id: Option<String>,
    pub src: Option<String>,
    pub state: Option<AttemptState>,
    pub cve: Option<String>,
    pub campaign_id: Option<String>,
    pub limit: Option<usize>,
}

#[derive(Debug, Serialize)]
pub struct AttemptList {
    pub items: Vec<Attempt>,
    /// True when the window held more events than the cap; narrow it.
    pub truncated: bool,
}

/// Build attempts for a tenant over a window.
pub(crate) async fn attempts_in_window(
    state: &AppState,
    tenant_id: &str,
    since: i64,
    until: i64,
) -> Result<(Vec<Attempt>, bool), ApiError> {
    if until <= since || until - since > 31 * DAY_MS {
        return Err(ApiError::bad_request(
            "window must be positive and at most 31 days",
        ));
    }
    let events = state
        .store
        .events_between(tenant_id, since, until, MAX_WINDOW_EVENTS + 1)
        .await?;
    let truncated = events.len() > MAX_WINDOW_EVENTS;
    let events = &events[..events.len().min(MAX_WINDOW_EVENTS)];
    Ok((
        build(events, DEFAULT_IDLE_GAP_MS, &ExtraSignals::new()),
        truncated,
    ))
}

fn window(state: &AppState, q: &AttemptQuery) -> (i64, i64) {
    let until = q.until.unwrap_or_else(|| (state.clock)() + 1);
    let since = q.since.unwrap_or(until - 7 * DAY_MS);
    (since, until)
}

async fn list(
    State(state): State<AppState>,
    auth: Auth,
    Query(q): Query<AttemptQuery>,
) -> Result<Json<AttemptList>, ApiError> {
    let who = auth.require(Scope::AttemptsRead)?;
    let (since, until) = window(&state, &q);
    let (attempts, truncated) = attempts_in_window(&state, &who.tenant_id, since, until).await?;
    let mut items: Vec<Attempt> = attempts
        .into_iter()
        .filter(|a| q.decoy_id.as_deref().is_none_or(|d| a.decoy_id == d))
        .filter(|a| q.decoy_kind.is_none_or(|k| a.decoy_kind == k))
        .filter(|a| {
            q.sensor_id
                .as_deref()
                .is_none_or(|s| a.sensor_id.as_deref() == Some(s))
        })
        .filter(|a| q.src.as_deref().is_none_or(|s| a.src == s))
        .filter(|a| q.state.is_none_or(|s| a.state == s))
        .filter(|a| {
            q.campaign_id
                .as_deref()
                .is_none_or(|c| a.campaign_id.as_deref() == Some(c))
        })
        .filter(|a| {
            q.cve.as_deref().is_none_or(|c| {
                a.hook_hits.iter().any(|h| {
                    h.cve_id
                        .as_deref()
                        .is_some_and(|x| x.eq_ignore_ascii_case(c))
                })
            })
        })
        .collect();
    // Newest activity first.
    items.sort_by(|a, b| (b.last_seen, &b.attempt_id).cmp(&(a.last_seen, &a.attempt_id)));
    items.truncate(page_limit(q.limit));
    Ok(Json(AttemptList { items, truncated }))
}

async fn get_one(
    State(state): State<AppState>,
    auth: Auth,
    Path(attempt_id): Path<String>,
    Query(q): Query<AttemptQuery>,
) -> Result<Json<Attempt>, ApiError> {
    let who = auth.require(Scope::AttemptsRead)?;
    let (since, until) = window(&state, &q);
    let (attempts, _) = attempts_in_window(&state, &who.tenant_id, since, until).await?;
    attempts
        .into_iter()
        .find(|a| a.attempt_id == attempt_id)
        .map(Json)
        .ok_or_else(|| ApiError::not_found("attempt"))
}
