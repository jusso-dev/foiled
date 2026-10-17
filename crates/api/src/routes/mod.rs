//! Route handlers grouped by resource.

pub mod audit;
pub mod catalogue;
pub mod decoys;

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

/// Clamp a `limit` query parameter.
pub(crate) fn page_limit(requested: Option<usize>) -> usize {
    requested.unwrap_or(50).clamp(1, 200)
}
