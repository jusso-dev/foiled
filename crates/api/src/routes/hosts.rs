//! Agent channel for sandbox hosts (#41, ADR 0008) and edge sensors (#31,
//! ADR 0007). mTLS identities only.
//!
//! - `POST /v0/{hosts|sensors}/{id}/jobs:lease`: signed jobs for this agent.
//! - `POST /v0/{hosts|sensors}/{id}/jobs/{job_id}:ack`: the result of a job.
//! - `POST /v0/{hosts|sensors}/{id}/heartbeat`: health, and for enrolled
//!   agents where the request came from.
//!
//! A certificate can only act as itself: the path's id must be the
//! certificate's identity, the role must match the path family, and it only
//! sees jobs placed on it. Edge sensors never take unplaced jobs.

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::routing::post;
use axum::{Json, Router};
use foiled_core::agent::{Heartbeat, JobBody, JobKind, JobOutcome, JobResult, SignedJob};
use foiled_core::audit::Outcome;
use foiled_core::auth::{Principal, Role, Scope};
use foiled_core::decoy::{DecoyState, Reason, ReasonCode};
use foiled_core::enrolment::{SeenFrom, network_changed};
use serde::{Deserialize, Serialize};

use crate::AppState;
use crate::auth::{Auth, ClientMeta, Meta};
use crate::error::{ApiError, JsonBody};
use crate::routes::audit_record;
use crate::store::JobRecord;

/// One family of agents on the channel.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Family {
    pub role: Role,
    pub lease: Scope,
    pub report: Scope,
    /// Research hosts pick up unplaced work; edge sensors only run what was
    /// placed on them.
    pub take_unplaced: bool,
    pub noun: &'static str,
    pub wrong_self: &'static str,
}

pub(crate) const HOSTS: Family = Family {
    role: Role::Host,
    lease: Scope::HostLease,
    report: Scope::HostReport,
    take_unplaced: true,
    noun: "host",
    wrong_self: "wrong_host",
};

pub(crate) const SENSORS: Family = Family {
    role: Role::Sensor,
    lease: Scope::SensorLease,
    report: Scope::SensorReport,
    take_unplaced: false,
    noun: "sensor",
    wrong_self: "wrong_sensor",
};

pub fn router() -> Router<AppState> {
    let mut r = Router::new();
    for (prefix, param, f) in [
        ("hosts", "host_id", HOSTS),
        ("sensors", "sensor_id", SENSORS),
    ] {
        r = r
            .route(
                &format!("/v0/{prefix}/{{{param}}}/jobs:lease"),
                post(move |s, a, m, p, q| lease(f, s, a, m, p, q)),
            )
            .route(
                &format!("/v0/{prefix}/{{{param}}}/jobs/{{job_action}}"),
                post(move |s, a, m, p, b| ack(f, s, a, m, p, b)),
            )
            .route(
                &format!("/v0/{prefix}/{{{param}}}/heartbeat"),
                post(move |s, a, m, p, b| heartbeat(f, s, a, m, p, b)),
            );
    }
    r
}

/// The caller holds `scope` (so its role is the family's) and the path
/// names the caller itself.
pub(crate) fn as_self<'a>(
    auth: &'a Auth,
    f: Family,
    scope: Scope,
    id: &str,
) -> Result<&'a Principal, ApiError> {
    let who = auth.require(scope)?;
    if who.role != f.role || who.id != id {
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            f.wrong_self,
            format!("a {} may only act as itself", f.noun),
        ));
    }
    Ok(who)
}

#[derive(Debug, Deserialize)]
pub struct LeaseQuery {
    pub max: Option<usize>,
}

#[derive(Debug, Serialize)]
pub struct Leased {
    pub jobs: Vec<SignedJob>,
    pub lease_expires_at: i64,
}

fn reason_of(job: &JobRecord) -> Option<Reason> {
    let code: ReasonCode =
        serde_json::from_value(serde_json::Value::String(job.reason_code.clone()?)).ok()?;
    Some(Reason {
        code,
        text: job.reason_text.clone().unwrap_or_default(),
    })
}

async fn lease(
    f: Family,
    State(state): State<AppState>,
    auth: Auth,
    Meta(meta): Meta,
    Path(host_id): Path<String>,
    Query(q): Query<LeaseQuery>,
) -> Result<Json<Leased>, ApiError> {
    let who = as_self(&auth, f, f.lease, &host_id)?.clone();
    note_seen(&state, &who, &meta, false).await?;
    let signer = state.job_signer.clone().ok_or_else(|| {
        ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "signing_disabled",
            "job signing is not configured",
        )
    })?;
    let now = (state.clock)();
    let lease_ms = state.limits.job_lease_secs * 1000;
    let jobs = state
        .store
        .lease_jobs(
            &who.tenant_id,
            &who.id,
            now,
            lease_ms,
            q.max.unwrap_or(10).clamp(1, 50),
            f.take_unplaced,
        )
        .await?;
    let mut signed = Vec::with_capacity(jobs.len());
    for job in jobs {
        let Some(kind) = JobKind::parse(&job.kind) else {
            continue; // unknown kinds never leave the control plane
        };
        let body = JobBody {
            job_id: job.id.clone(),
            host_id: who.id.clone(),
            tenant_id: who.tenant_id.clone(),
            decoy_id: job.decoy_id.clone(),
            kind,
            reason: reason_of(&job),
            decoy: job
                .params
                .clone()
                .and_then(|p| serde_json::from_value(p).ok()),
            idempotency_key: job.idempotency_key.clone(),
            issued_at: now,
            expires_at: job.expires_at,
        };
        signed.push(signer.sign(&body));
    }
    Ok(Json(Leased {
        jobs: signed,
        lease_expires_at: now + lease_ms,
    }))
}

async fn ack(
    f: Family,
    State(state): State<AppState>,
    auth: Auth,
    Meta(meta): Meta,
    Path((host_id, job_action)): Path<(String, String)>,
    JsonBody(result): JsonBody<JobResult>,
) -> Result<StatusCode, ApiError> {
    let who = as_self(&auth, f, f.report, &host_id)?.clone();
    note_seen(&state, &who, &meta, false).await?;
    let job_id = job_action
        .strip_suffix(":ack")
        .ok_or_else(|| ApiError::not_found("action"))?;
    if result.job_id != job_id {
        return Err(ApiError::bad_request(
            "job_id in the body does not match the path",
        ));
    }
    let status = match result.outcome {
        JobOutcome::Succeeded => "succeeded",
        JobOutcome::Failed => "failed",
        JobOutcome::Rejected => "rejected",
    };
    let job = state
        .store
        .finish_job(&who.tenant_id, &who.id, job_id, status)
        .await?
        .ok_or_else(|| ApiError::conflict("job is not leased by this host"))?;
    let now = (state.clock)();

    let mut applied = None;
    if let (JobOutcome::Succeeded | JobOutcome::Failed, Some(target)) =
        (result.outcome, result.decoy_state)
    {
        let decoy = state
            .store
            .get_decoy(&who.tenant_id, &job.decoy_id)
            .await?
            .ok_or_else(|| ApiError::not_found("decoy"))?;
        // A successful rotate or reset is a rebuild: the decoy must pass
        // through `rotating` so the generation bumps, even when it ends where
        // it started.
        let rebuild = result.outcome == JobOutcome::Succeeded
            && matches!(
                JobKind::parse(&job.kind),
                Some(JobKind::DecoyRotate | JobKind::DecoyReset)
            );
        let path = if rebuild && decoy.state != DecoyState::Rotating {
            decoy
                .state
                .path_to(DecoyState::Rotating)
                .zip(DecoyState::Rotating.path_to(target))
                .map(|(mut a, b)| {
                    a.extend(b);
                    a
                })
        } else {
            decoy.state.path_to(target)
        }
        .ok_or_else(|| {
            ApiError::conflict(format!(
                "decoy cannot move from {} to {}",
                decoy.state.as_str(),
                target.as_str()
            ))
        })?;
        let mut cur = decoy.state;
        for next in path {
            let rebuild = cur == DecoyState::Rotating && next == DecoyState::Starting;
            if !state
                .store
                .set_decoy_state(&who.tenant_id, &decoy.id, cur, next, rebuild, now)
                .await?
            {
                return Err(ApiError::conflict("decoy state changed concurrently"));
            }
            cur = next;
        }
        applied = Some(cur);
    }

    let outcome = match result.outcome {
        JobOutcome::Succeeded => Outcome::Accepted,
        JobOutcome::Failed => Outcome::Failed,
        JobOutcome::Rejected => Outcome::Denied,
    };
    let mut rec = audit_record(&state, &who, "job.ack", Some(&job.decoy_id), outcome);
    rec.job_id = Some(job.id.clone());
    rec.reason_code = job.reason_code.clone();
    rec.detail = serde_json::json!({
        "kind": job.kind,
        "outcome": status,
        "decoy_state": applied.map(DecoyState::as_str),
        "detail": result.detail,
    });
    state.store.append_audit(rec).await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn heartbeat(
    f: Family,
    State(state): State<AppState>,
    auth: Auth,
    Meta(meta): Meta,
    Path(host_id): Path<String>,
    JsonBody(hb): JsonBody<Heartbeat>,
) -> Result<StatusCode, ApiError> {
    let who = as_self(&auth, f, f.report, &host_id)?.clone();
    if hb.host_id != who.id {
        return Err(ApiError::bad_request("host_id in the body does not match"));
    }
    let now = (state.clock)();
    let skew = hb.host_time - now;
    let value = serde_json::to_value(&hb).map_err(|e| ApiError::bad_request(e.to_string()))?;
    state
        .store
        .record_heartbeat(&who.tenant_id, &who.id, value, skew, now)
        .await?;
    note_seen(&state, &who, &meta, true).await?;
    Ok(StatusCode::NO_CONTENT)
}

/// How stale `last_seen_at` may get before a request without a network
/// change refreshes it. Keeps the common path to one registry read.
const SEEN_REFRESH_MS: i64 = 5 * 60 * 1000;

/// Remember where an enrolled host or sensor calls from, and flag a move to
/// another network: a copied certificate in use elsewhere looks like this.
/// Called from every authenticated agent route (lease, ack, heartbeat,
/// ingest, uploads, renewal). Writes only when the network changed, when
/// `always` (heartbeats), or when the last sighting is stale.
pub(crate) async fn note_seen(
    state: &AppState,
    who: &Principal,
    meta: &ClientMeta,
    always: bool,
) -> Result<(), ApiError> {
    if !matches!(who.role, Role::Host | Role::Sensor) {
        return Ok(());
    }
    let Some(agent) = state
        .store
        .get_agent(&who.tenant_id, who.role, &who.id)
        .await?
    else {
        return Ok(());
    };
    let now = (state.clock)();
    let prev = SeenFrom {
        ip: agent.last_ip.clone(),
        asn: agent.last_asn,
    };
    // Without request metadata (tests, local mock) keep what we knew.
    let seen = SeenFrom {
        ip: meta.ip.clone().or(prev.ip.clone()),
        asn: meta.asn.or(prev.asn),
    };
    let changed = network_changed(&prev, &seen);
    let stale = agent
        .last_seen_at
        .is_none_or(|t| now - t >= SEEN_REFRESH_MS);
    if !(changed || always || stale || seen != prev) {
        return Ok(());
    }
    state
        .store
        .record_agent_seen(&who.tenant_id, &who.id, seen.clone(), changed, now)
        .await?;
    if changed {
        let action = format!("{}.network_changed", who.role.as_str());
        let mut rec = audit_record(state, who, &action, Some(&who.id), Outcome::Accepted);
        rec.detail = serde_json::json!({"from": prev, "to": seen});
        state.store.append_audit(rec).await?;
    }
    Ok(())
}
