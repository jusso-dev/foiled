//! Route handlers grouped by resource.

pub mod actors;
pub mod agents;
pub mod attempts;
pub mod audit;
pub mod campaigns;
pub mod catalogue;
pub mod decoys;
pub mod exports;
pub mod hosts;
pub mod ingest;
pub mod iocs;
pub mod public;
pub mod radar;
pub mod review;
pub mod writeups;
pub mod taxii;

use foiled_core::audit::{AuditRecord, Outcome};
use foiled_core::auth::Principal;

use crate::AppState;

/// Common fields for an audit record written by a handler.
pub(crate) fn audit_record(
    state: &AppState,
    who: &Principal,
    action: &str,
    target: Option<&str>,
    outcome: Outcome,
) -> AuditRecord {
    AuditRecord {
        id: (state.ids)(),
        ts: (state.clock)(),
        tenant_id: who.tenant_id.clone(),
        actor_id: who.id.clone(),
        actor_kind: who.role,
        action: action.to_string(),
        target: target.map(str::to_string),
        reason_code: None,
        reason_text: None,
        job_id: None,
        idempotency_key: None,
        outcome,
        detail: serde_json::Value::Null,
    }
}

/// Count one hit against a fixed-window rate limit for this principal.
/// `window_ms` is the window length, for example an hour.
pub(crate) async fn check_rate(
    state: &AppState,
    who: &Principal,
    bucket: &str,
    limit: u32,
    window_ms: i64,
) -> Result<(), crate::error::ApiError> {
    let window = (state.clock)() / window_ms * window_ms;
    let key = format!("{bucket}:{}:{}", who.tenant_id, who.id);
    if state.store.rate_limit(&key, window, limit).await? {
        Ok(())
    } else {
        Err(crate::error::ApiError::rate_limited())
    }
}

pub(crate) const HOUR_MS: i64 = 3_600_000;

/// Clamp a `limit` query parameter.
pub(crate) fn page_limit(requested: Option<usize>) -> usize {
    requested.unwrap_or(50).clamp(1, 200)
}
