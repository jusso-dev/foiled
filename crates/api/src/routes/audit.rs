//! `GET /v0/audit`: the tenant's audit log, newest first.

use axum::extract::{Query, State};
use axum::routing::get;
use axum::{Json, Router};
use foiled_core::audit::AuditRecord;
use foiled_core::auth::Scope;
use serde::{Deserialize, Serialize};

use crate::AppState;
use crate::auth::Auth;
use crate::error::ApiError;
use crate::store::AuditQuery;

pub fn router() -> Router<AppState> {
    Router::new().route("/", get(list))
}

#[derive(Debug, Deserialize)]
pub struct ListQuery {
    pub action: Option<String>,
    pub target: Option<String>,
    /// Opaque cursor from a previous page's `next_cursor`.
    pub cursor: Option<String>,
    pub limit: Option<usize>,
}

#[derive(Debug, Serialize)]
pub struct AuditList {
    pub items: Vec<AuditRecord>,
    /// Pass as `cursor` to fetch the next page.
    pub next_cursor: Option<String>,
}

async fn list(
    State(state): State<AppState>,
    auth: Auth,
    Query(q): Query<ListQuery>,
) -> Result<Json<AuditList>, ApiError> {
    let who = auth.require(Scope::AuditRead)?;
    let limit = super::page_limit(q.limit);
    let before = q
        .cursor
        .as_deref()
        .map(|c| parse_cursor(c).ok_or_else(|| ApiError::bad_request("invalid cursor")))
        .transpose()?;
    let items = state
        .store
        .list_audit(
            &who.tenant_id,
            AuditQuery {
                action: q.action,
                target: q.target,
                limit,
                before,
            },
        )
        .await?;
    let next_cursor = (items.len() == limit)
        .then(|| items.last().map(|a| format!("{}_{}", a.ts, a.id)))
        .flatten();
    Ok(Json(AuditList { items, next_cursor }))
}

/// Cursor format: `<ts>_<id>`.
pub(crate) fn parse_cursor(c: &str) -> Option<(i64, String)> {
    let (ts, id) = c.split_once('_')?;
    (!id.is_empty()).then(|| ts.parse().ok().map(|t| (t, id.to_string())))?
}
