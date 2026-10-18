//! Foiled control plane API.
//!
//! One Axum [`Router`] served from a Cloudflare Worker through workers-rs
//! (`http` and `axum` features). There is no Tokio runtime on Workers, so the
//! router is driven by [`tower_service::Service::call`] from the fetch event
//! rather than `axum::serve` (ADR 0009). The router itself has no Worker
//! dependency: handlers reach storage through [`store::Store`], so the whole
//! API is tested on the host with [`memory::MemoryStore`].
//!
//! The contract is `api/openapi.yaml`. Paths marked `x-foiled-status: planned`
//! there are not served yet.

use std::sync::Arc;

use axum::{Json, Router, routing::get};
use serde::Serialize;

pub mod actor_sync;
pub mod auth;
pub mod catalogue;
pub mod d1_sql;
pub mod enrich_consumer;
pub mod enrichment;
pub mod error;
pub mod issuer;
pub mod links;
pub mod mcp;
pub mod memory;
pub mod routes;
pub mod sinks;
pub mod store;
#[cfg(target_arch = "wasm32")]
mod worker_glue;

use catalogue::Catalogue;
use store::Store;

/// Tunable safety limits. Defaults are deliberately tight (#21, #24).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Limits {
    /// Decoy creates per principal per hour.
    pub creates_per_hour: u32,
    /// Destructive actions (stop, rotate, reset, destroy) per principal per hour.
    pub destructive_per_hour: u32,
    /// Decoys per tenant that are not destroyed.
    pub max_live_decoys: u32,
    pub default_lifetime_secs: i64,
    pub max_lifetime_secs: i64,
    /// How long a host agent may take to lease a job before it expires.
    pub job_ttl_secs: i64,
    /// How long a lease holds before another lease may take the job.
    pub job_lease_secs: i64,
    /// Sensor and host registrations (each mints an enrolment token) per
    /// principal per hour (#31).
    pub enrolments_per_hour: u32,
    /// `POST /v0/enrol` attempts per source IP per hour.
    pub enrol_attempts_per_hour: u32,
    /// Certificate renewals per identity per day.
    pub renewals_per_day: u32,
    /// Ingest batches per host or sensor identity per minute.
    pub ingest_batches_per_minute: u32,
    /// Lifetime of issued client certificates.
    pub cert_validity_days: u32,
    /// Campaign analyst actions per principal per hour (#33).
    pub campaign_actions_per_hour: u32,
    /// Most capture events read for one attempts, IOC or export window.
    /// Larger windows are cut at this many events, oldest first (#25).
    pub max_window_events: usize,
    /// Most D1 statements one request may spend reading the enrichment
    /// cache (#11). Each covers up to 98 observables. The default leaves
    /// room inside the D1 Free plan's 50 queries per Worker invocation.
    pub enrichment_lookup_statements: usize,
    /// Actor link decisions per principal per hour (#29).
    pub actor_decisions_per_hour: u32,
    /// Review queue actions, write-up writes and radar rollups per
    /// principal per hour (#35).
    pub review_actions_per_hour: u32,
}

impl Default for Limits {
    fn default() -> Self {
        Limits {
            creates_per_hour: 10,
            destructive_per_hour: 30,
            max_live_decoys: 5,
            default_lifetime_secs: 24 * 3600,
            max_lifetime_secs: 7 * 24 * 3600,
            job_ttl_secs: 3600,
            job_lease_secs: 300,
            enrolments_per_hour: 10,
            enrol_attempts_per_hour: 30,
            renewals_per_day: 4,
            ingest_batches_per_minute: 120,
            cert_validity_days: foiled_core::enrolment::DEFAULT_CERT_VALIDITY_DAYS,
            campaign_actions_per_hour: 60,
            max_window_events: routes::attempts::MAX_WINDOW_EVENTS,
            enrichment_lookup_statements: 20,
            actor_decisions_per_hour: 60,
            review_actions_per_hour: 240,
        }
    }
}

pub type Clock = Arc<dyn Fn() -> i64 + Send + Sync>;
pub type IdSource = Arc<dyn Fn() -> String + Send + Sync>;

/// Shared state for every handler.
#[derive(Clone)]
pub struct AppState {
    pub store: Arc<dyn Store>,
    pub catalogue: Arc<Catalogue>,
    /// Unix time in milliseconds.
    pub clock: Clock,
    pub ids: IdSource,
    pub limits: Limits,
    /// R2 upload signing; `None` when evidence uploads are not configured.
    pub uploads: Option<routes::ingest::UploadConfig>,
    /// Signs host agent jobs; `None` disables leasing.
    pub job_signer: Option<Arc<foiled_core::agent::JobSigner>>,
    /// MCP endpoint settings (`configs/mcp.yaml`, #24).
    pub mcp: Arc<foiled_core::mcp::McpConfig>,
    /// Signs enrolment CSRs; `None` disables enrolment and renewal (#31).
    pub cert_issuer: Option<Arc<dyn issuer::CertIssuer>>,
    /// The actor reference catalogue (#29).
    pub actors: Arc<foiled_core::actor::ActorCatalogue>,
    /// Contribute-back policy (`configs/contribute-back.yaml`, #37): opt-in
    /// defaults, the public IOC delay and the radar thresholds (#35).
    pub share: Arc<foiled_core::share::SharePolicy>,
    /// Analytics Engine writes for radar rollups (#35).
    pub radar_sink: Arc<dyn sinks::RadarSink>,
    /// Tenants whose operators may publish public pages (#35). Empty
    /// means nobody can publish.
    pub publisher_tenants: Arc<Vec<String>>,
    /// Tenants the operator runs as research (#35, #37). Only their sandbox
    /// decoys count as research sensors; every other tenant's decoys are
    /// treated like edge sensors (opt-in and every radar threshold).
    pub research_tenants: Arc<Vec<String>>,
    /// Purges public page URLs from caches on publish and withdraw (#35).
    pub cache_purger: Arc<dyn sinks::CachePurger>,
}

impl AppState {
    pub fn new(store: Arc<dyn Store>, clock: Clock) -> Self {
        AppState {
            store,
            catalogue: Arc::new(Catalogue::bundled()),
            clock,
            ids: Arc::new(|| uuid::Uuid::new_v4().simple().to_string()),
            limits: Limits::default(),
            uploads: None,
            job_signer: None,
            mcp: Arc::new(mcp::bundled_config()),
            cert_issuer: None,
            actors: links::bundled_actor_catalogue(),
            share: Arc::new(foiled_core::share::SharePolicy::default()),
            radar_sink: Arc::new(sinks::NoRadarSink),
            publisher_tenants: Arc::new(Vec::new()),
            research_tenants: Arc::new(Vec::new()),
            cache_purger: Arc::new(sinks::NoCachePurger),
        }
    }
}

/// Body returned by `GET /healthz`.
#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct Health {
    pub status: &'static str,
    pub service: &'static str,
    pub version: &'static str,
}

async fn healthz() -> Json<Health> {
    Json(Health {
        status: "ok",
        service: "foiled-api",
        version: env!("CARGO_PKG_VERSION"),
    })
}

/// Every REST route, without the MCP endpoint or a fallback.
fn rest_routes() -> Router<AppState> {
    let decoys = routes::decoys::router();
    Router::new()
        .route("/healthz", get(healthz))
        .nest("/v0/catalogue", routes::catalogue::router())
        .nest("/v0/decoys", decoys.clone())
        // Alias kept for agents and docs that say "sandbox" (#24).
        .nest("/v0/sandboxes", decoys)
        .nest("/v0/audit", routes::audit::router())
        .merge(routes::ingest::router())
        .merge(routes::hosts::router())
        .merge(routes::agents::router())
        .merge(routes::exports::router())
        .merge(routes::attempts::router())
        .merge(routes::iocs::router())
        .merge(routes::campaigns::router())
        .merge(routes::actors::router())
        .merge(routes::radar::router())
        .merge(routes::review::router())
        .merge(routes::writeups::router())
        .merge(routes::public::router())
        .merge(routes::taxii::router())
}

/// The REST API alone. MCP tool calls are replayed against this router, so
/// the MCP endpoint is a pure client of the API and can never reach itself.
pub fn rest_router(state: AppState) -> Router {
    rest_routes()
        .fallback(|| async { error::ApiError::not_found("route") })
        .with_state(state)
}

/// Build the API router.
pub fn router(state: AppState) -> Router {
    rest_routes()
        .merge(mcp::router())
        .fallback(|| async { error::ApiError::not_found("route") })
        .with_state(state)
}
