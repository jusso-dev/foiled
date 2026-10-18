//! IOC read endpoints (#34): `GET /v0/iocs`, `GET /v0/iocs/{ioc_id}` and
//! `GET /v0/attempts/{attempt_id}/iocs`.
//!
//! IOCs are a read model like attempts: extracted on request from the
//! attempts in a bounded window with `foiled_core::ioc`, so the same
//! evidence always gives the same ids, and anything the retention purge
//! removed (#16) never comes back. Address IOCs get ASN context from cached
//! enrichment Facts (#11) when the store has them. Every route is scoped to
//! the caller's tenant and read-only, so nothing here is audited.

use std::collections::BTreeMap;

use axum::extract::{Path, Query, State};
use axum::routing::get;
use axum::{Json, Router};
use foiled_core::auth::Scope;
use foiled_core::enrichment::{Fact, Observable};
use foiled_core::ioc::{
    Ioc, IocRole, IocType, MAX_VALUE_CHARS, address_observables, apply_enrichment, refang,
};
use serde::{Deserialize, Serialize};

use crate::AppState;
use crate::auth::Auth;
use crate::error::ApiError;
use crate::routes::attempts::{Campaigns, Iocs, window_bounds, window_model};
use crate::routes::page_limit;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/v0/iocs", get(search))
        .route("/v0/iocs/{ioc_id}", get(get_one))
        .route("/v0/attempts/{attempt_id}/iocs", get(for_attempt))
}

#[derive(Debug, Deserialize, Default)]
pub struct IocQuery {
    pub since: Option<i64>,
    pub until: Option<i64>,
    #[serde(rename = "type")]
    pub ioc_type: Option<IocType>,
    /// Exact value. Defanged input (`203[.]0[.]113[.]7`, `hxxp://`) is
    /// accepted.
    pub value: Option<String>,
    pub role: Option<IocRole>,
    pub attempt_id: Option<String>,
    pub campaign_id: Option<String>,
    pub file_ioc_limited: Option<bool>,
    pub limit: Option<usize>,
}

#[derive(Debug, Deserialize, Default)]
pub struct WindowQuery {
    pub since: Option<i64>,
    pub until: Option<i64>,
}

#[derive(Debug, Serialize)]
pub struct IocList {
    pub items: Vec<Ioc>,
    /// True when the window held more events than the cap; narrow it.
    pub truncated: bool,
}

#[derive(Debug, Serialize)]
pub struct AttemptIocList {
    pub attempt_id: String,
    pub file_ioc_limited: bool,
    pub notes: Vec<String>,
    pub items: Vec<Ioc>,
    pub truncated: bool,
}

/// Add ASN context to the IOCs about to be returned.
pub(crate) async fn enrich(
    state: &AppState,
    tenant_id: &str,
    iocs: &mut [Ioc],
) -> Result<(), ApiError> {
    let observables = address_observables(iocs);
    if observables.is_empty() {
        return Ok(());
    }
    // The store may answer once per provider for the same observable.
    let mut facts: BTreeMap<Observable, Vec<Fact>> = BTreeMap::new();
    for o in state.store.enrichment_facts(tenant_id, observables).await? {
        facts.entry(o.observable).or_default().extend(o.facts);
    }
    apply_enrichment(iocs, &facts);
    Ok(())
}

fn value_matches(ioc: &Ioc, wanted: &str) -> bool {
    ioc.value == wanted
        || (ioc.ioc_type.case_insensitive() && ioc.value.eq_ignore_ascii_case(wanted))
}

async fn search(
    State(state): State<AppState>,
    auth: Auth,
    Query(q): Query<IocQuery>,
) -> Result<Json<IocList>, ApiError> {
    let who = auth.require(Scope::IocsRead)?;
    if q.value
        .as_deref()
        .is_some_and(|v| v.chars().nth(MAX_VALUE_CHARS).is_some())
    {
        return Err(ApiError::bad_request(format!(
            "value must be at most {MAX_VALUE_CHARS} characters"
        )));
    }
    let wanted = q.value.as_deref().map(refang);
    let (since, until) = window_bounds(&state, q.since, q.until);
    // Clustering only when filtering by campaign; otherwise `campaign_ids`
    // come from the registry.
    let campaigns = if q.campaign_id.is_some() {
        Campaigns::Full {
            record: crate::routes::attempts::canonical_window(q.since, q.until),
        }
    } else {
        Campaigns::Registry
    };
    let m = window_model(
        &state,
        &who.tenant_id,
        since,
        until,
        Iocs::Attach,
        campaigns,
    )
    .await?;
    let mut items: Vec<Ioc> = m
        .iocs
        .iocs
        .into_iter()
        .filter(|i| q.ioc_type.is_none_or(|t| i.ioc_type == t))
        .filter(|i| wanted.as_deref().is_none_or(|v| value_matches(i, v)))
        .filter(|i| q.role.is_none_or(|r| i.roles.contains(&r)))
        .filter(|i| {
            q.attempt_id
                .as_deref()
                .is_none_or(|a| i.attempt_ids.iter().any(|x| x == a))
        })
        .filter(|i| {
            q.campaign_id
                .as_deref()
                .is_none_or(|c| i.campaign_ids.iter().any(|x| x == c))
        })
        .filter(|i| q.file_ioc_limited.is_none_or(|f| i.file_ioc_limited == f))
        .collect();
    // Newest activity first.
    items.sort_by(|a, b| (b.last_seen, &b.ioc_id).cmp(&(a.last_seen, &a.ioc_id)));
    items.truncate(page_limit(q.limit));
    enrich(&state, &who.tenant_id, &mut items).await?;
    Ok(Json(IocList {
        items,
        truncated: m.truncated,
    }))
}

fn valid_ioc_id(id: &str) -> bool {
    id.strip_prefix("ioc_").is_some_and(|h| {
        h.len() == 24
            && h.bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    })
}

async fn get_one(
    State(state): State<AppState>,
    auth: Auth,
    Path(ioc_id): Path<String>,
    Query(q): Query<WindowQuery>,
) -> Result<Json<Ioc>, ApiError> {
    let who = auth.require(Scope::IocsRead)?;
    if !valid_ioc_id(&ioc_id) {
        return Err(ApiError::not_found("ioc"));
    }
    let (since, until) = window_bounds(&state, q.since, q.until);
    let m = window_model(
        &state,
        &who.tenant_id,
        since,
        until,
        Iocs::Attach,
        Campaigns::Registry,
    )
    .await?;
    let mut found: Vec<Ioc> = m
        .iocs
        .iocs
        .into_iter()
        .filter(|i| i.ioc_id == ioc_id)
        .collect();
    enrich(&state, &who.tenant_id, &mut found).await?;
    found
        .pop()
        .map(Json)
        .ok_or_else(|| ApiError::not_found("ioc"))
}

async fn for_attempt(
    State(state): State<AppState>,
    auth: Auth,
    Path(attempt_id): Path<String>,
    Query(q): Query<WindowQuery>,
) -> Result<Json<AttemptIocList>, ApiError> {
    let who = auth.require(Scope::IocsRead)?;
    let (since, until) = window_bounds(&state, q.since, q.until);
    let m = window_model(
        &state,
        &who.tenant_id,
        since,
        until,
        Iocs::Attach,
        Campaigns::Registry,
    )
    .await?;
    let summary = m
        .iocs
        .for_attempt(&attempt_id)
        .cloned()
        .ok_or_else(|| ApiError::not_found("attempt"))?;
    let mut by_id: BTreeMap<String, Ioc> = m
        .iocs
        .iocs
        .into_iter()
        .map(|i| (i.ioc_id.clone(), i))
        .collect();
    let mut items: Vec<Ioc> = summary
        .ioc_refs
        .iter()
        .filter_map(|id| by_id.remove(id))
        .collect();
    enrich(&state, &who.tenant_id, &mut items).await?;
    Ok(Json(AttemptIocList {
        attempt_id: summary.attempt_id,
        file_ioc_limited: summary.file_ioc_limited,
        notes: summary.notes,
        items,
        truncated: m.truncated,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ioc_ids_are_checked_before_lookup() {
        assert!(valid_ioc_id("ioc_0123456789abcdef01234567"));
        assert!(!valid_ioc_id("ioc_0123456789ABCDEF01234567"));
        assert!(!valid_ioc_id("ioc_../../etc"));
        assert!(!valid_ioc_id("att_0123456789abcdef01234567"));
    }
}
