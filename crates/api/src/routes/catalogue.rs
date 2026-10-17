//! `GET /v0/catalogue/entries` and `GET /v0/catalogue/entries/{id}`.
//! Read-only: the catalogue changes through reviewed pull requests (#5).

use axum::extract::{Path, Query, State};
use axum::routing::get;
use axum::{Json, Router};
use foiled_core::auth::Scope;
use foiled_core::catalogue::{CatalogueEntry, DecoyKind, EntryStatus};
use serde::{Deserialize, Serialize};

use crate::AppState;
use crate::auth::Auth;
use crate::error::ApiError;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/entries", get(list))
        .route("/entries/{*id}", get(get_one))
}

#[derive(Debug, Deserialize)]
pub struct ListQuery {
    pub decoy_kind: Option<DecoyKind>,
    pub status: Option<EntryStatus>,
    pub cve: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct EntryList {
    pub items: Vec<CatalogueEntry>,
}

async fn list(
    State(state): State<AppState>,
    auth: Auth,
    Query(q): Query<ListQuery>,
) -> Result<Json<EntryList>, ApiError> {
    auth.require(Scope::CatalogueRead)?;
    let items = state
        .catalogue
        .entries()
        .iter()
        .filter(|e| q.decoy_kind.is_none_or(|k| e.decoy_kind == k))
        .filter(|e| q.status.is_none_or(|s| e.status == s))
        .filter(|e| {
            q.cve
                .as_deref()
                .is_none_or(|c| e.cves.iter().any(|x| x.cve_id.eq_ignore_ascii_case(c)))
        })
        .cloned()
        .collect();
    Ok(Json(EntryList { items }))
}

async fn get_one(
    State(state): State<AppState>,
    auth: Auth,
    Path(id): Path<String>,
) -> Result<Json<CatalogueEntry>, ApiError> {
    auth.require(Scope::CatalogueRead)?;
    state
        .catalogue
        .get(&id)
        .cloned()
        .map(Json)
        .ok_or_else(|| ApiError::not_found("catalogue entry"))
}
