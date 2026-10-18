//! Public, unauthenticated reads (#35): `GET /v0/public/exploited` and
//! `GET /v0/public/exploited/{slug}`. The radar is trusted-side only.
//!
//! These routes never take credentials and never read tenant-scoped data.
//! They make exactly two reads: [`Store::public_page`] and
//! [`Store::public_pages`] (allow-listed snapshots written at publish time,
//! at most [`MAX_PAGES`] rows), plus a per-client rate limit. IOCs on a page
//! appear only after their release time. Every response carries explicit,
//! short cache headers so a withdrawn page leaves caches quickly (it is also
//! purged on withdrawal); errors never leak internals.
//!
//! [`Store::public_page`]: crate::store::Store::public_page
//! [`Store::public_pages`]: crate::store::Store::public_pages

use axum::extract::{Path, State};
use axum::http::{HeaderMap, HeaderValue, header};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use foiled_core::writeup::{PublicPageSummary, valid_slug};
use serde::Serialize;

use crate::AppState;
use crate::auth::Meta;
use crate::error::ApiError;

/// Browsers and shared caches may keep a public response this long
/// (seconds). Short, so a withdrawn page that could not be purged is gone
/// within a minute.
pub const PUBLIC_MAX_AGE: u32 = 60;
/// Most pages the list returns.
pub const MAX_PAGES: usize = 100;
/// Public reads per client per minute.
pub const PUBLIC_READS_PER_MINUTE: u32 = 120;
/// The client address the public site Worker forwards.
pub const CLIENT_IP_HEADER: &str = "x-foiled-client-ip";

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/v0/public/exploited", get(list))
        .route("/v0/public/exploited/{slug}", get(page))
}

/// Add the public headers to any response: a short cache for success and
/// 404, none for anything else.
fn public(res: Result<Response, ApiError>) -> Response {
    let mut res = match res {
        Ok(r) => r,
        Err(e) => e.into_response(),
    };
    let status = res.status();
    let cache = if status.is_success() {
        format!("public, max-age={PUBLIC_MAX_AGE}, s-maxage={PUBLIC_MAX_AGE}")
    } else if status == http::StatusCode::NOT_FOUND {
        format!("public, max-age={PUBLIC_MAX_AGE}")
    } else {
        "no-store".to_string()
    };
    let h = res.headers_mut();
    if let Ok(v) = HeaderValue::from_str(&cache) {
        h.insert(header::CACHE_CONTROL, v);
    }
    h.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    h.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    h.insert(header::VARY, HeaderValue::from_static("Accept-Encoding"));
    res
}

#[derive(Debug, Serialize)]
pub struct PageList {
    pub items: Vec<PublicPageSummary>,
}

/// Count one public read for the client: the address the public site
/// Worker forwards, else the connecting address, else one shared bucket.
async fn limit(state: &AppState, headers: &HeaderMap, meta: &Meta) -> Result<(), ApiError> {
    let ip = headers
        .get(CLIENT_IP_HEADER)
        .and_then(|v| v.to_str().ok())
        .filter(|v| !v.is_empty() && v.len() <= 64 && v.parse::<std::net::IpAddr>().is_ok())
        .map(str::to_string)
        .or_else(|| meta.0.ip.clone())
        .unwrap_or_else(|| "unknown".into());
    let minute = 60_000;
    let window = (state.clock)() / minute * minute;
    if state
        .store
        .rate_limit(
            &format!("public.read:{ip}"),
            window,
            PUBLIC_READS_PER_MINUTE,
        )
        .await?
    {
        Ok(())
    } else {
        Err(ApiError::rate_limited())
    }
}

async fn list(State(state): State<AppState>, headers: HeaderMap, meta: Meta) -> Response {
    let res = async {
        limit(&state, &headers, &meta).await?;
        let now = (state.clock)();
        let items = state.store.public_pages(now, MAX_PAGES).await?;
        Ok(Json(PageList { items }).into_response())
    }
    .await;
    public(res)
}

async fn page(
    State(state): State<AppState>,
    Path(slug): Path<String>,
    headers: HeaderMap,
    meta: Meta,
) -> Response {
    let res = async {
        limit(&state, &headers, &meta).await?;
        if !valid_slug(&slug) {
            return Err(ApiError::not_found("page"));
        }
        let now = (state.clock)();
        let page = state
            .store
            .public_page(&slug, now)
            .await?
            .ok_or_else(|| ApiError::not_found("page"))?;
        Ok(Json(page.as_of(now)).into_response())
    }
    .await;
    public(res)
}
