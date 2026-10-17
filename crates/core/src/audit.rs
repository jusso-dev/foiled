//! Audit records (#21). Every write to the control plane leaves one.

use serde::{Deserialize, Serialize};

use crate::auth::Role;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    Accepted,
    Denied,
    Failed,
}

impl Outcome {
    pub fn as_str(self) -> &'static str {
        match self {
            Outcome::Accepted => "accepted",
            Outcome::Denied => "denied",
            Outcome::Failed => "failed",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        [Outcome::Accepted, Outcome::Denied, Outcome::Failed]
            .into_iter()
            .find(|o| o.as_str() == s)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditRecord {
    pub id: String,
    pub ts: i64,
    pub tenant_id: String,
    pub actor_id: String,
    pub actor_kind: Role,
    /// Dotted action name, for example `decoy.create` or `decoy.rotate`.
    pub action: String,
    /// What the action was applied to, for example a decoy id.
    pub target: Option<String>,
    pub reason_code: Option<String>,
    pub reason_text: Option<String>,
    pub job_id: Option<String>,
    pub idempotency_key: Option<String>,
    pub outcome: Outcome,
    /// Extra structured detail. Secrets are never written here.
    pub detail: serde_json::Value,
}
