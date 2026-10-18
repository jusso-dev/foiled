//! The radar (#35): `GET /v0/radar` for operators and
//! `POST /v0/radar/rollups` to roll up one closed day for the caller's
//! tenant.
//!
//! A rollup builds the tenant's attempts, links (with analyst overrides)
//! and campaigns for one UTC day, turns them into rollup points
//! (`foiled_core::radar::observe`), replaces that tenant-day in Postgres and
//! writes the points to Analytics Engine through [`crate::sinks::RadarSink`].
//! Reads aggregate rollups with the share policy's thresholds
//! (`foiled_core::radar::aggregate`): `audience=tenant` (the default) is the
//! caller's own data; `audience=fleet` is every tenant's opted-in data
//! behind the k-anonymity thresholds, and never names a tenant. The radar
//! is trusted-side only: there is no public route.

use std::collections::BTreeMap;

use axum::extract::{Query, State};
use axum::routing::{get, post};
use axum::{Json, Router};
use foiled_core::audit::Outcome;
use foiled_core::auth::Scope;
use foiled_core::confidence::ConfidenceConfig;
use foiled_core::radar::{
    self, Audience, DAY_MS, Dimension, Filter, ObserveInput, RadarFeed, analytics_points, day_floor,
};
use serde::{Deserialize, Serialize};

use crate::AppState;
use crate::auth::Auth;
use crate::error::{ApiError, JsonBody};
use crate::routes::attempts::{Campaigns, Iocs, window_model};
use crate::routes::{HOUR_MS, audit_record, check_rate};
use crate::store::MAX_RADAR_POINTS;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/v0/radar", get(feed))
        .route("/v0/radar/rollups", post(rollup))
}

#[derive(Debug, Deserialize, Default)]
pub struct RadarQuery {
    pub audience: Option<Audience>,
    pub dimension: Option<Dimension>,
    pub key: Option<String>,
    pub product: Option<String>,
    pub since: Option<i64>,
    pub until: Option<i64>,
    pub limit: Option<usize>,
}

/// Display names for products from the bundled catalogue.
pub(crate) fn product_labels(state: &AppState) -> BTreeMap<(Dimension, String), String> {
    state
        .catalogue
        .entries()
        .iter()
        .map(|e| {
            (
                (Dimension::Product, radar::product_key(&e.id)),
                format!("{} {}", e.vendor, e.product),
            )
        })
        .collect()
}

/// Read rollups and aggregate them. The tenant audience reads the caller's
/// tenant only; the fleet audience reads every tenant.
pub(crate) async fn build_feed(
    state: &AppState,
    audience: Audience,
    tenant: Option<&str>,
    q: &RadarQuery,
) -> Result<RadarFeed, ApiError> {
    for s in [&q.key, &q.product].into_iter().flatten() {
        if s.is_empty() || s.len() > 200 {
            return Err(ApiError::bad_request(
                "key and product must be 1 to 200 characters",
            ));
        }
    }
    let now = (state.clock)();
    let until = q.until.unwrap_or(now);
    let since = q.since.unwrap_or(until - 30 * DAY_MS);
    let read_tenant = match audience {
        Audience::Tenant => tenant,
        Audience::Fleet => None,
    };
    let points = state
        .store
        .radar_points(
            read_tenant,
            day_floor(since),
            day_floor(until) + DAY_MS,
            MAX_RADAR_POINTS + 1,
        )
        .await?;
    let capped = points.len() > MAX_RADAR_POINTS;
    let points = &points[..points.len().min(MAX_RADAR_POINTS)];
    let mut feed = radar::aggregate(
        points,
        audience,
        tenant,
        &state.share.radar,
        since,
        until,
        now,
        &Filter {
            dimension: q.dimension,
            key: q.key.clone(),
            product: q.product.clone(),
            limit: q.limit.unwrap_or(20),
        },
        &product_labels(state),
    )
    .map_err(|e| ApiError::bad_request(e.0))?;
    if capped {
        feed.notes.push(
            "The window held more rollup rows than one read takes; counts may be low. Narrow \
             since and until."
                .into(),
        );
    }
    Ok(feed)
}

async fn feed(
    State(state): State<AppState>,
    auth: Auth,
    Query(q): Query<RadarQuery>,
) -> Result<Json<RadarFeed>, ApiError> {
    let who = auth.require(Scope::ReviewRead)?;
    let audience = q.audience.unwrap_or(Audience::Tenant);
    Ok(Json(
        build_feed(&state, audience, Some(&who.tenant_id), &q).await?,
    ))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RollupBody {
    /// Any time on the UTC day to roll up. The day must have closed and be
    /// within the last 31 days.
    pub day: i64,
}

#[derive(Debug, Serialize)]
pub struct RollupResult {
    pub day: i64,
    pub points: usize,
    /// True when the Analytics Engine write failed; Postgres has the rows.
    pub analytics_failed: bool,
    pub truncated: bool,
}

/// Roll up one closed day for the caller's tenant (audited as
/// `radar.rollup`). Idempotent: the tenant-day is replaced.
async fn rollup(
    State(state): State<AppState>,
    auth: Auth,
    JsonBody(body): JsonBody<RollupBody>,
) -> Result<Json<RollupResult>, ApiError> {
    let who = auth.require(Scope::ReviewWrite)?.clone();
    check_rate(
        &state,
        &who,
        "review.action",
        state.limits.review_actions_per_hour,
        HOUR_MS,
    )
    .await?;
    let now = (state.clock)();
    let day = day_floor(body.day);
    if day + DAY_MS > now || day < day_floor(now) - 31 * DAY_MS {
        return Err(ApiError::bad_request(
            "day must have closed and be within the last 31 days",
        ));
    }
    // One day either side, so attempts that cross midnight stay whole.
    let m = window_model(
        &state,
        &who.tenant_id,
        day - DAY_MS,
        day + 2 * DAY_MS,
        Iocs::Attach,
        Campaigns::Full { record: false },
    )
    .await?;
    let (links, _) = crate::routes::review::links_by_attempt(&state, &who.tenant_id, &m).await?;
    let sensors = crate::routes::review::sensor_share(&state, &who.tenant_id, &m.attempts).await?;
    let points = radar::observe(&ObserveInput {
        tenant_id: &who.tenant_id,
        day,
        attempts: &m.attempts,
        links: &links,
        campaigns: &m.campaigns.campaigns,
        sensors: &sensors,
        policy: &state.share,
        confidence: &ConfidenceConfig::default(),
    });
    let n = points.len();
    // Analytics Engine gets only rows whose sensor may feed the radar.
    let analytics = analytics_points(&points, &state.share);
    state
        .store
        .put_radar_points(&who.tenant_id, day, points)
        .await?;
    let analytics_failed = state.radar_sink.write(&analytics).is_err();
    let mut rec = audit_record(&state, &who, "radar.rollup", None, Outcome::Accepted);
    rec.detail =
        serde_json::json!({ "day": day, "points": n, "analytics_failed": analytics_failed });
    state.store.append_audit(rec).await?;
    Ok(Json(RollupResult {
        day,
        points: n,
        analytics_failed,
        truncated: m.truncated,
    }))
}
