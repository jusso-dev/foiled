//! `/v0/decoys` (alias `/v0/sandboxes`).
//!
//! The API never touches a sandbox host directly. Creating, stopping,
//! rotating, resetting or destroying a decoy writes a job that the host agent
//! leases over mTLS (#41). Only host reports move a decoy out of `pending`
//! (`docs/rotation.md`). Every write is audited and destructive actions need
//! a reason.

use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::routing::{get, post};
use axum::{Json, Router};
use foiled_core::audit::Outcome;
use foiled_core::auth::{Principal, Scope};
use foiled_core::catalogue::{Artefact, EntryStatus, Runtime};
use foiled_core::decoy::{Decoy, DecoyState, Reason};
use serde::{Deserialize, Serialize};

use crate::AppState;
use crate::auth::Auth;
use crate::error::{ApiError, JsonBody};
use crate::routes::{audit_record, page_limit};
use crate::store::{DecoyQuery, JobRecord};

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/", post(create).get(list))
        // `{id}` or `{id}:<action>`, for example `/v0/decoys/abc:rotate`.
        .route("/{id_action}", get(get_one).post(action))
}

const IDEMPOTENCY_HEADER: &str = "idempotency-key";

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateDecoy {
    pub catalogue_id: String,
    pub label: Option<String>,
    pub lifetime_seconds: Option<i64>,
    /// Launch a `draft` entry. Needs the `decoys:elevate` scope.
    #[serde(default)]
    pub allow_draft: bool,
}

#[derive(Debug, Serialize)]
pub struct DecoyList {
    pub items: Vec<Decoy>,
    pub next_cursor: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct JobAccepted {
    pub decoy: Decoy,
    pub job_id: String,
    pub job_kind: String,
}

#[derive(Debug, Deserialize)]
pub struct ListQuery {
    pub state: Option<DecoyState>,
    pub catalogue_id: Option<String>,
    pub limit: Option<usize>,
    pub cursor: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActionBody {
    pub reason: Reason,
}

fn idempotency_key(headers: &HeaderMap) -> Result<Option<String>, ApiError> {
    match headers.get(IDEMPOTENCY_HEADER) {
        None => Ok(None),
        Some(v) => {
            let s = v
                .to_str()
                .map_err(|_| ApiError::bad_request("Idempotency-Key must be ASCII"))?;
            if s.is_empty() || s.len() > 128 {
                return Err(ApiError::bad_request(
                    "Idempotency-Key must be 1 to 128 characters",
                ));
            }
            Ok(Some(s.to_string()))
        }
    }
}

async fn check_rate(
    state: &AppState,
    who: &Principal,
    bucket: &str,
    limit: u32,
) -> Result<(), ApiError> {
    let hour_ms = 3_600_000;
    let window = (state.clock)() / hour_ms * hour_ms;
    let key = format!("{bucket}:{}:{}", who.tenant_id, who.id);
    if state.store.rate_limit(&key, window, limit).await? {
        Ok(())
    } else {
        Err(ApiError::rate_limited())
    }
}

async fn create(
    State(state): State<AppState>,
    auth: Auth,
    headers: HeaderMap,
    JsonBody(body): JsonBody<CreateDecoy>,
) -> Result<(StatusCode, Json<JobAccepted>), ApiError> {
    let who = auth.require(Scope::DecoysWrite)?.clone();
    let idem = idempotency_key(&headers)?;

    if let Some(key) = &idem
        && let Some(job) = state
            .store
            .job_by_idempotency_key(&who.tenant_id, key)
            .await?
    {
        let decoy = state
            .store
            .get_decoy(&who.tenant_id, &job.decoy_id)
            .await?
            .ok_or_else(|| ApiError::conflict("idempotency key belongs to another request"))?;
        if job.kind != "decoy.create" || decoy.catalogue_id != body.catalogue_id {
            return Err(ApiError::conflict(
                "idempotency key belongs to another request",
            ));
        }
        return Ok((
            StatusCode::OK,
            Json(JobAccepted {
                decoy,
                job_id: job.id,
                job_kind: job.kind,
            }),
        ));
    }

    let deny = |code: &'static str, msg: &str| ApiError::unprocessable(code, msg);
    let entry = state
        .catalogue
        .get(&body.catalogue_id)
        .ok_or_else(|| deny("unknown_catalogue_entry", "no catalogue entry with that id"))?;
    match entry.status {
        EntryStatus::Deprecated => {
            return Err(deny(
                "entry_deprecated",
                "deprecated entries cannot be launched",
            ));
        }
        EntryStatus::Draft if !(body.allow_draft && who.has(Scope::DecoysElevate)) => {
            return Err(deny(
                "entry_draft",
                "draft entries need allow_draft and the decoys:elevate scope",
            ));
        }
        _ => {}
    }
    if !entry.problems().is_empty() {
        return Err(deny("entry_invalid", "catalogue entry failed its checks"));
    }
    if let Some(Artefact::Sandbox(a)) = &entry.artefact
        && a.runtime == Some(Runtime::Docker)
    {
        // The Docker fallback is for labs only and never internet-facing (#3).
        return Err(deny(
            "runtime_not_allowed",
            "docker runtime entries cannot be launched through the API",
        ));
    }
    let lifetime = body
        .lifetime_seconds
        .unwrap_or(state.limits.default_lifetime_secs);
    if lifetime <= 0 || lifetime > state.limits.max_lifetime_secs {
        return Err(ApiError::bad_request(format!(
            "lifetime_seconds must be between 1 and {}",
            state.limits.max_lifetime_secs
        )));
    }
    if let Some(label) = &body.label
        && (label.chars().count() > 100 || label.chars().any(char::is_control))
    {
        return Err(ApiError::bad_request(
            "label must be at most 100 printable characters",
        ));
    }

    check_rate(&state, &who, "decoy.create", state.limits.creates_per_hour).await?;
    if state.store.count_live_decoys(&who.tenant_id).await? >= state.limits.max_live_decoys {
        return Err(deny(
            "decoy_cap_reached",
            "too many live decoys for this tenant",
        ));
    }

    let now = (state.clock)();
    let decoy = Decoy {
        id: (state.ids)(),
        tenant_id: who.tenant_id.clone(),
        catalogue_id: entry.id.clone(),
        decoy_kind: entry.decoy_kind,
        label: body.label,
        state: DecoyState::Pending,
        host_id: None,
        generation: 1,
        created_at: now,
        updated_at: now,
        expires_at: now + lifetime * 1000,
        created_by: who.id.clone(),
    };
    let job = JobRecord {
        id: (state.ids)(),
        tenant_id: who.tenant_id.clone(),
        decoy_id: decoy.id.clone(),
        host_id: None,
        kind: "decoy.create".into(),
        reason_code: None,
        reason_text: None,
        idempotency_key: idem.clone().unwrap_or_else(|| (state.ids)()),
        created_at: now,
        expires_at: now + state.limits.job_ttl_secs * 1000,
        status: "queued".into(),
    };
    state.store.create_decoy(decoy.clone(), job.clone()).await?;

    let mut rec = audit_record(
        &state,
        &who,
        "decoy.create",
        Some(&decoy.id),
        Outcome::Accepted,
    );
    rec.job_id = Some(job.id.clone());
    rec.idempotency_key = idem;
    rec.detail =
        serde_json::json!({"catalogue_id": decoy.catalogue_id, "lifetime_seconds": lifetime});
    state.store.append_audit(rec).await?;

    Ok((
        StatusCode::CREATED,
        Json(JobAccepted {
            decoy,
            job_id: job.id,
            job_kind: job.kind,
        }),
    ))
}

async fn list(
    State(state): State<AppState>,
    auth: Auth,
    Query(q): Query<ListQuery>,
) -> Result<Json<DecoyList>, ApiError> {
    let who = auth.require(Scope::DecoysRead)?;
    let limit = page_limit(q.limit);
    let items = state
        .store
        .list_decoys(
            &who.tenant_id,
            DecoyQuery {
                state: q.state,
                catalogue_id: q.catalogue_id,
                limit,
                cursor: q.cursor,
            },
        )
        .await?;
    let next_cursor = (items.len() == limit)
        .then(|| items.last().map(|d| d.id.clone()))
        .flatten();
    Ok(Json(DecoyList { items, next_cursor }))
}

async fn get_one(
    State(state): State<AppState>,
    auth: Auth,
    Path(id): Path<String>,
) -> Result<Json<Decoy>, ApiError> {
    let who = auth.require(Scope::DecoysRead)?;
    if id.contains(':') {
        return Err(ApiError::new(
            StatusCode::METHOD_NOT_ALLOWED,
            "method_not_allowed",
            "actions use POST",
        ));
    }
    state
        .store
        .get_decoy(&who.tenant_id, &id)
        .await?
        .map(Json)
        .ok_or_else(|| ApiError::not_found("decoy"))
}

/// What each action asks the host agent to do, and the state it aims for.
fn action_target(action: &str) -> Option<(&'static str, DecoyState)> {
    match action {
        "stop" => Some(("decoy.stop", DecoyState::Stopped)),
        "rotate" => Some(("decoy.rotate", DecoyState::Rotating)),
        "reset" => Some(("decoy.reset", DecoyState::Rotating)),
        "mark-compromised" => Some(("decoy.mark_compromised", DecoyState::Quarantined)),
        "destroy" => Some(("decoy.destroy", DecoyState::Destroyed)),
        _ => None,
    }
}

async fn action(
    State(state): State<AppState>,
    auth: Auth,
    Path(id_action): Path<String>,
    headers: HeaderMap,
    JsonBody(body): JsonBody<ActionBody>,
) -> Result<(StatusCode, Json<JobAccepted>), ApiError> {
    let who = auth.require(Scope::DecoysWrite)?.clone();
    let (id, action) = id_action
        .split_once(':')
        .ok_or_else(|| ApiError::not_found("action"))?;
    let (job_kind, target) = action_target(action).ok_or_else(|| ApiError::not_found("action"))?;
    body.reason.validate().map_err(ApiError::bad_request)?;
    let idem = idempotency_key(&headers)?;

    if let Some(key) = &idem
        && let Some(job) = state
            .store
            .job_by_idempotency_key(&who.tenant_id, key)
            .await?
    {
        if job.decoy_id != id || job.kind != job_kind {
            return Err(ApiError::conflict(
                "idempotency key belongs to another request",
            ));
        }
        let decoy = state
            .store
            .get_decoy(&who.tenant_id, id)
            .await?
            .ok_or_else(|| ApiError::not_found("decoy"))?;
        return Ok((
            StatusCode::OK,
            Json(JobAccepted {
                decoy,
                job_id: job.id,
                job_kind: job.kind,
            }),
        ));
    }

    let decoy = state
        .store
        .get_decoy(&who.tenant_id, id)
        .await?
        .ok_or_else(|| ApiError::not_found("decoy"))?;
    if !decoy.state.can_transition_to(target) {
        let mut rec = audit_record(&state, &who, job_kind, Some(id), Outcome::Denied);
        rec.reason_code = Some(reason_code_str(&body.reason));
        rec.reason_text = Some(body.reason.text.clone());
        rec.detail = serde_json::json!({"from_state": decoy.state.as_str()});
        state.store.append_audit(rec).await?;
        return Err(ApiError::conflict(format!(
            "cannot {action} a decoy in state {}",
            decoy.state.as_str()
        )));
    }
    check_rate(
        &state,
        &who,
        "decoy.destructive",
        state.limits.destructive_per_hour,
    )
    .await?;

    let now = (state.clock)();
    let job = JobRecord {
        id: (state.ids)(),
        tenant_id: who.tenant_id.clone(),
        decoy_id: decoy.id.clone(),
        host_id: decoy.host_id.clone(),
        kind: job_kind.into(),
        reason_code: Some(reason_code_str(&body.reason)),
        reason_text: Some(body.reason.text.clone()),
        idempotency_key: idem.clone().unwrap_or_else(|| (state.ids)()),
        created_at: now,
        expires_at: now + state.limits.job_ttl_secs * 1000,
        status: "queued".into(),
    };
    state.store.insert_job(job.clone()).await?;

    let mut rec = audit_record(&state, &who, job_kind, Some(id), Outcome::Accepted);
    rec.reason_code = job.reason_code.clone();
    rec.reason_text = job.reason_text.clone();
    rec.job_id = Some(job.id.clone());
    rec.idempotency_key = idem;
    state.store.append_audit(rec).await?;

    Ok((
        StatusCode::ACCEPTED,
        Json(JobAccepted {
            decoy,
            job_id: job.id,
            job_kind: job.kind,
        }),
    ))
}

fn reason_code_str(r: &Reason) -> String {
    serde_json::to_value(r.code)
        .ok()
        .and_then(|v| v.as_str().map(str::to_string))
        .unwrap_or_default()
}
