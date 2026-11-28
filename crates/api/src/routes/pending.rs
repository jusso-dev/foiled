//! Human approval of destructive MCP tool calls (#95).
//!
//! `reset_sandbox` and `destroy_sandbox` from an agent (`mcp` role) token
//! do not run: they record a pending action (`crate::mcp::tools`). A human
//! operator approves or rejects it here, from the console's review queue
//! page. Approval is a compare-and-set from `pending`, so an action runs at
//! most once however many approvals race, and never after it expires. The
//! approved action is then sent to the decoy action route with the
//! approver's own token, so the API's scopes, state checks, limits and
//! `decoy.<action>` audit record apply exactly as for any operator action.
//!
//! Also `PUT /v0/tokens/{token_id}/auto-approve`: an admin marks an agent
//! token as trusted automation, whose destructive calls run at once.
//!
//! See `docs/mcp/foiled-mcp.md`.

use axum::body::{Body, Bytes};
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, Method, StatusCode, header};
use axum::routing::{get, post, put};
use axum::{Json, Router};
use foiled_core::audit::Outcome;
use foiled_core::auth::{Principal, Role, Scope};
use foiled_core::pending_action::{PendingAction, PendingStatus, check_note};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tower_service::Service;

use crate::AppState;
use crate::auth::Auth;
use crate::error::{ApiError, JsonBody};
use crate::routes::{audit_record, page_limit};
use crate::store::PendingQuery;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/v0/pending-actions", get(list))
        .route("/v0/pending-actions/{id}", get(get_one))
        .route("/v0/pending-actions/{id}/approve", post(approve))
        .route("/v0/pending-actions/{id}/reject", post(reject))
        .route("/v0/tokens/{token_id}/auto-approve", put(set_auto_approve))
}

/// Audit actions written here.
pub const AUDIT_APPROVE: &str = "pending_action.approve";
/// Written after the approval wins and before the action is sent. If it
/// cannot be written the action does not run, so every run has a durable
/// record of both the approving human and the requesting agent.
pub const AUDIT_RUN: &str = "pending_action.run";
pub const AUDIT_REJECT: &str = "pending_action.reject";
pub const AUDIT_AUTO_APPROVE: &str = "token.auto_approve";

#[derive(Debug, Deserialize)]
pub struct ListQuery {
    pub status: Option<PendingStatus>,
    pub limit: Option<usize>,
    pub cursor: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct PendingList {
    pub items: Vec<PendingAction>,
    pub next_cursor: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DecisionBody {
    /// Why. Optional to approve, required to reject. Audited.
    pub note: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AutoApproveBody {
    pub enabled: bool,
    /// Why. Required. Audited.
    pub note: String,
}

#[derive(Debug, Serialize)]
pub struct AutoApproveResult {
    pub token_id: String,
    pub auto_approve: bool,
}

async fn list(
    State(state): State<AppState>,
    auth: Auth,
    Query(q): Query<ListQuery>,
) -> Result<Json<PendingList>, ApiError> {
    let who = auth.require(Scope::DecoysRead)?;
    let limit = page_limit(q.limit);
    let now = (state.clock)();
    let items: Vec<PendingAction> = state
        .store
        .list_pending_actions(
            &who.tenant_id,
            PendingQuery {
                status: q.status,
                now,
                limit,
                cursor: q.cursor,
            },
        )
        .await?
        .into_iter()
        .map(|p| p.view_at(now))
        .collect();
    let next_cursor = (items.len() == limit)
        .then(|| items.last().map(|p| p.id.clone()))
        .flatten();
    Ok(Json(PendingList { items, next_cursor }))
}

async fn get_one(
    State(state): State<AppState>,
    auth: Auth,
    Path(id): Path<String>,
) -> Result<Json<PendingAction>, ApiError> {
    let who = auth.require(Scope::DecoysRead)?;
    let now = (state.clock)();
    state
        .store
        .get_pending_action(&who.tenant_id, &id)
        .await?
        .map(|p| Json(p.view_at(now)))
        .ok_or_else(|| ApiError::not_found("pending action"))
}

/// Only a human operator with `decoys:write` decides. An agent token can
/// never approve or reject, its own actions or anyone else's.
fn decider(auth: &Auth) -> Result<Principal, ApiError> {
    let who = auth.require(Scope::DecoysWrite)?.clone();
    if who.role != Role::Human {
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "forbidden",
            "only a human operator token can decide a pending action",
        ));
    }
    Ok(who)
}

/// The decision body is optional: an empty body is no note.
fn decision_body(bytes: &Bytes) -> Result<DecisionBody, ApiError> {
    if bytes.iter().all(u8::is_ascii_whitespace) {
        return Ok(DecisionBody::default());
    }
    serde_json::from_slice(bytes)
        .map_err(|e| ApiError::new(StatusCode::BAD_REQUEST, "invalid_body", e.to_string()))
}

/// The decision audit record: the approving or rejecting human is the
/// actor; the requesting agent token is in `detail`.
fn decision_record(
    state: &AppState,
    who: &Principal,
    action: &str,
    p: &PendingAction,
    outcome: Outcome,
    extra: Value,
) -> foiled_core::audit::AuditRecord {
    let mut rec = audit_record(state, who, action, Some(&p.sandbox_id), outcome);
    rec.reason_code = serde_json::to_value(p.reason.code)
        .ok()
        .and_then(|v| v.as_str().map(str::to_string));
    rec.reason_text = Some(p.reason.text.clone());
    rec.job_id = p.job_id.clone();
    let mut detail = json!({
        "pending_action_id": p.id,
        "action": p.action.as_str(),
        "tool": p.tool(),
        "sandbox_id": p.sandbox_id,
        "requested_by": p.requested_by,
        "requested_kind": p.requested_kind,
        "requested_at": p.created_at,
        "decided_by": who.id,
        "decided_kind": who.role,
    });
    if let (Some(d), Some(e)) = (detail.as_object_mut(), extra.as_object()) {
        for (k, v) in e {
            d.insert(k.clone(), v.clone());
        }
    }
    rec.detail = detail;
    rec
}

/// Refuse a decision on an action that is no longer pending, and audit
/// the refusal.
async fn not_pending(
    state: &AppState,
    who: &Principal,
    audit_action: &str,
    p: &PendingAction,
    now: i64,
) -> Result<ApiError, ApiError> {
    let status = p.status_at(now);
    let rec = decision_record(
        state,
        who,
        audit_action,
        p,
        Outcome::Denied,
        json!({"status": status, "error_code": "not_pending"}),
    );
    state.store.append_audit(rec).await?;
    Ok(ApiError::conflict(format!(
        "pending action is {}, not pending",
        status.as_str()
    )))
}

async fn approve(
    State(state): State<AppState>,
    auth: Auth,
    Path(id): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<PendingAction>, ApiError> {
    let who = decider(&auth)?;
    let body = decision_body(&body)?;
    let note = check_note(body.note.as_deref(), false).map_err(ApiError::bad_request)?;
    let now = (state.clock)();
    let p = state
        .store
        .get_pending_action(&who.tenant_id, &id)
        .await?
        .ok_or_else(|| ApiError::not_found("pending action"))?;
    if p.status_at(now) != PendingStatus::Pending {
        return Err(not_pending(&state, &who, AUDIT_APPROVE, &p, now).await?);
    }
    // The compare-and-set is the gate: of any number of approvals, at most
    // one gets the row back, and only before it expires. Expiry is judged
    // at the decision, not when the request arrived: the clock is read
    // again after the last await before the statement, so the only
    // tolerance left is that one statement's latency.
    let now = (state.clock)();
    let Some(p) = state
        .store
        .decide_pending_action(
            &who.tenant_id,
            &id,
            PendingStatus::Approved,
            &who.id,
            note.clone(),
            now,
        )
        .await?
    else {
        let latest = state
            .store
            .get_pending_action(&who.tenant_id, &id)
            .await?
            .unwrap_or(p);
        return Err(not_pending(&state, &who, AUDIT_APPROVE, &latest, now).await?);
    };

    // The audit store is not D1, so the decision and its audit record
    // cannot share a transaction. Write the record first: if it fails the
    // action does not run, and the approved row ends `failed` (it never
    // runs again; the agent may ask anew).
    let run = decision_record(
        &state,
        &who,
        AUDIT_RUN,
        &p,
        Outcome::Accepted,
        json!({"status": p.status, "note": note}),
    );
    if let Err(e) = state.store.append_audit(run).await {
        let _ = state
            .store
            .finish_pending_action(
                &who.tenant_id,
                &id,
                PendingStatus::Failed,
                None,
                Some("audit_unavailable".into()),
            )
            .await;
        return Err(e.into());
    }

    // Run it as the approver, through the same route an operator uses. The
    // pending action id is the idempotency key, so even a repeated send
    // could only ever queue one job.
    let ran = run_action(&state, &headers, &p).await;
    let (status, job_id, error) = match ran {
        Ok(r) => (
            PendingStatus::Executed,
            r["job_id"].as_str().map(str::to_string),
            None,
        ),
        // The route may have queued the job and then failed (its own audit
        // write, say). A queued job will run, so record it as executed.
        Err(e) => match queued_job(&state, &p).await {
            Some(job) => (PendingStatus::Executed, Some(job), Some(e)),
            None => (PendingStatus::Failed, None, Some(e)),
        },
    };
    let executed = status == PendingStatus::Executed;
    let error_code = error
        .as_ref()
        .filter(|_| !executed)
        .map(|e| e.code.to_string());
    // The action already ran (or failed). A bookkeeping or audit failure
    // must not hide that from the approver: the row stays `approved`,
    // which never runs again, and the API wrote its own decoy record.
    let _ = state
        .store
        .finish_pending_action(
            &who.tenant_id,
            &id,
            status,
            job_id.clone(),
            error_code.clone(),
        )
        .await;
    let mut done = p.clone();
    done.status = status;
    done.job_id = job_id;
    done.error_code = error_code.clone();
    let outcome = match &error {
        _ if executed => Outcome::Accepted,
        None => Outcome::Accepted,
        Some(e) if e.status.is_server_error() => Outcome::Failed,
        Some(_) => Outcome::Denied,
    };
    let rec = decision_record(
        &state,
        &who,
        AUDIT_APPROVE,
        &done,
        outcome,
        json!({
            "status": status,
            "note": note,
            "error_code": error_code,
            "http_status": error.as_ref().map(|e| e.status.as_u16()),
            // Set when the job was queued but the route then failed.
            "error_after_queue": error.as_ref().filter(|_| executed).map(|e| e.code.clone()),
        }),
    );
    // The `pending_action.run` record already holds both identities; this
    // one adds the outcome, which the pending action and the API's
    // `decoy.<action>` record also hold.
    let _ = state.store.append_audit(rec).await;
    Ok(Json(done))
}

/// The job the decoy route queued for this pending action, if any. The
/// pending action id is its idempotency key.
async fn queued_job(state: &AppState, p: &PendingAction) -> Option<String> {
    let kind = format!("decoy.{}", p.action.as_str());
    state
        .store
        .job_by_idempotency_key(&p.tenant_id, &p.id)
        .await
        .ok()
        .flatten()
        .filter(|j| j.decoy_id == p.sandbox_id && j.kind == kind)
        .map(|j| j.id)
}

/// An error from the decoy action route, as the approver sees it.
#[derive(Debug, Clone)]
struct ActionError {
    status: StatusCode,
    code: String,
}

async fn run_action(
    state: &AppState,
    headers: &HeaderMap,
    p: &PendingAction,
) -> Result<Value, ActionError> {
    let internal = |code: &str| ActionError {
        status: StatusCode::INTERNAL_SERVER_ERROR,
        code: code.into(),
    };
    let bearer = headers
        .get(header::AUTHORIZATION)
        .cloned()
        .ok_or_else(|| internal("unauthorised"))?;
    let req = http::Request::builder()
        .method(Method::POST)
        .uri(format!(
            "/v0/sandboxes/{}:{}",
            p.sandbox_id,
            p.action.as_str()
        ))
        .header(header::AUTHORIZATION, bearer)
        .header(header::CONTENT_TYPE, "application/json")
        .header("idempotency-key", &p.id)
        .body(Body::from(json!({"reason": p.reason}).to_string()))
        .map_err(|_| internal("bad_request"))?;
    let mut api = crate::rest_router(state.clone());
    let res = api.call(req).await.unwrap_or_else(|e| match e {});
    let status = res.status();
    let bytes = axum::body::to_bytes(res.into_body(), 1024 * 1024)
        .await
        .map_err(|_| internal("response_too_large"))?;
    let value: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    if status.is_success() {
        Ok(value)
    } else {
        Err(ActionError {
            status,
            code: value["error"]["code"]
                .as_str()
                .unwrap_or("error")
                .chars()
                .take(64)
                .collect(),
        })
    }
}

async fn reject(
    State(state): State<AppState>,
    auth: Auth,
    Path(id): Path<String>,
    body: Bytes,
) -> Result<Json<PendingAction>, ApiError> {
    let who = decider(&auth)?;
    let body = decision_body(&body)?;
    let note = check_note(body.note.as_deref(), true).map_err(ApiError::bad_request)?;
    let now = (state.clock)();
    let p = state
        .store
        .get_pending_action(&who.tenant_id, &id)
        .await?
        .ok_or_else(|| ApiError::not_found("pending action"))?;
    if p.status_at(now) != PendingStatus::Pending {
        return Err(not_pending(&state, &who, AUDIT_REJECT, &p, now).await?);
    }
    let now = (state.clock)();
    let Some(done) = state
        .store
        .decide_pending_action(
            &who.tenant_id,
            &id,
            PendingStatus::Rejected,
            &who.id,
            note.clone(),
            now,
        )
        .await?
    else {
        let latest = state
            .store
            .get_pending_action(&who.tenant_id, &id)
            .await?
            .unwrap_or(p);
        return Err(not_pending(&state, &who, AUDIT_REJECT, &latest, now).await?);
    };
    let rec = decision_record(
        &state,
        &who,
        AUDIT_REJECT,
        &done,
        Outcome::Accepted,
        json!({"status": done.status, "note": note}),
    );
    state.store.append_audit(rec).await?;
    Ok(Json(done))
}

/// Mark an agent token as trusted automation, or take it back. Admin
/// operators only; the token must be an `mcp` token in the same tenant.
async fn set_auto_approve(
    State(state): State<AppState>,
    auth: Auth,
    Path(token_id): Path<String>,
    JsonBody(body): JsonBody<AutoApproveBody>,
) -> Result<Json<AutoApproveResult>, ApiError> {
    let who = auth.require(Scope::Admin)?.clone();
    if who.role != Role::Human {
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "forbidden",
            "only a human admin token can change auto-approve",
        ));
    }
    let note = check_note(Some(&body.note), true).map_err(ApiError::bad_request)?;
    let target = state
        .store
        .token(&token_id)
        .await?
        .filter(|t| t.tenant_id == who.tenant_id)
        .ok_or_else(|| ApiError::not_found("token"))?;
    if target.role != Role::Mcp {
        return Err(ApiError::unprocessable(
            "not_an_agent_token",
            "auto-approve applies to mcp tokens only; operator tokens never wait for approval",
        ));
    }
    // The flag is in D1 and the audit log is not, so they cannot commit
    // together. Audit first: if that fails the flag is untouched, so the
    // approval bypass is never on without a record. If the flag write then
    // fails, a second record says the change did not apply.
    let record = |outcome: Outcome| {
        let mut rec = audit_record(&state, &who, AUDIT_AUTO_APPROVE, Some(&token_id), outcome);
        rec.reason_text = note.clone();
        rec.detail = json!({
            "token_id": token_id,
            "auto_approve": body.enabled,
            "was": target.auto_approve,
        });
        rec
    };
    state.store.append_audit(record(Outcome::Accepted)).await?;
    let set = state
        .store
        .set_token_auto_approve(&who.tenant_id, &token_id, body.enabled)
        .await;
    if !matches!(set, Ok(true)) {
        let mut undone = record(Outcome::Failed);
        undone.detail["applied"] = json!(false);
        let _ = state.store.append_audit(undone).await;
        return Err(match set {
            Ok(_) => ApiError::not_found("token"),
            Err(e) => e.into(),
        });
    }
    Ok(Json(AutoApproveResult {
        token_id,
        auto_approve: body.enabled,
    }))
}
