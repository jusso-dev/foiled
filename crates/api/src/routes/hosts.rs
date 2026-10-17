//! Sandbox host agent channel (#41, ADR 0008). mTLS identities only.
//!
//! - `POST /v0/hosts/{host_id}/jobs:lease`: signed jobs for this host.
//! - `POST /v0/hosts/{host_id}/jobs/{job_id}:ack`: the result of a job.
//! - `POST /v0/hosts/{host_id}/heartbeat`: host health.
//!
//! A host certificate can only act as itself: the path's host id must be the
//! certificate's identity, and it only sees jobs placed on it.

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::routing::post;
use axum::{Json, Router};
use foiled_core::agent::{Heartbeat, JobBody, JobKind, JobOutcome, JobResult, SignedJob};
use foiled_core::audit::Outcome;
use foiled_core::auth::{Principal, Scope};
use foiled_core::decoy::{DecoyState, Reason, ReasonCode};
use serde::{Deserialize, Serialize};

use crate::AppState;
use crate::auth::Auth;
use crate::error::{ApiError, JsonBody};
use crate::routes::audit_record;
use crate::store::JobRecord;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/v0/hosts/{host_id}/jobs:lease", post(lease))
        .route("/v0/hosts/{host_id}/jobs/{job_action}", post(ack))
        .route("/v0/hosts/{host_id}/heartbeat", post(heartbeat))
}

fn as_self<'a>(auth: &'a Auth, scope: Scope, host_id: &str) -> Result<&'a Principal, ApiError> {
    let who = auth.require(scope)?;
    if who.id != host_id {
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "wrong_host",
            "a host may only act as itself",
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
    State(state): State<AppState>,
    auth: Auth,
    Path(host_id): Path<String>,
    Query(q): Query<LeaseQuery>,
) -> Result<Json<Leased>, ApiError> {
    let who = as_self(&auth, Scope::HostLease, &host_id)?.clone();
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
    State(state): State<AppState>,
    auth: Auth,
    Path((host_id, job_action)): Path<(String, String)>,
    JsonBody(result): JsonBody<JobResult>,
) -> Result<StatusCode, ApiError> {
    let who = as_self(&auth, Scope::HostReport, &host_id)?.clone();
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
    State(state): State<AppState>,
    auth: Auth,
    Path(host_id): Path<String>,
    JsonBody(hb): JsonBody<Heartbeat>,
) -> Result<StatusCode, ApiError> {
    let who = as_self(&auth, Scope::HostReport, &host_id)?.clone();
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
    Ok(StatusCode::NO_CONTENT)
}
