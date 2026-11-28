//! Pending actions (#95): destructive MCP tool calls held until a human
//! approves them in the console.
//!
//! `reset_sandbox` and `destroy_sandbox` need `confirm: true` and a reason,
//! but both are set by the same agent that reads attacker text, so a prompt
//! injection can supply them. An agent's destructive call therefore only
//! records a pending action. A human operator approves or rejects it in the
//! console (the review queue page); approval runs it once, rejection or
//! expiry means it never runs. A token an admin marked `auto_approve` skips
//! the wait, for trusted automation. Mirrored by
//! `schemas/pending-action.schema.json`. See `docs/mcp/foiled-mcp.md`.

use serde::{Deserialize, Serialize};

use crate::auth::Role;
use crate::decoy::{DecoyState, Reason};

/// How long a pending action waits for a human before it expires.
pub const PENDING_ACTION_TTL_MS: i64 = 15 * 60 * 1000;

/// Unexpired pending actions one token may have open at once. Another
/// destructive call is refused until a human clears the queue.
pub const MAX_OPEN_PER_TOKEN: u32 = 10;

/// Longest decision note, in characters.
pub const MAX_NOTE_CHARS: usize = 1000;

/// Every pending action id starts with this.
pub const ID_PREFIX: &str = "pa_";

/// What the agent asked for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PendingKind {
    Reset,
    Destroy,
}

impl PendingKind {
    pub fn as_str(self) -> &'static str {
        match self {
            PendingKind::Reset => "reset",
            PendingKind::Destroy => "destroy",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        [PendingKind::Reset, PendingKind::Destroy]
            .into_iter()
            .find(|k| k.as_str() == s)
    }

    /// The MCP tool that asks for it.
    pub fn tool(self) -> &'static str {
        match self {
            PendingKind::Reset => "reset_sandbox",
            PendingKind::Destroy => "destroy_sandbox",
        }
    }

    /// The decoy state the API moves to, to check the action is possible.
    pub fn target_state(self) -> DecoyState {
        match self {
            PendingKind::Reset => DecoyState::Rotating,
            PendingKind::Destroy => DecoyState::Destroyed,
        }
    }
}

/// Where a pending action is. `Expired` is never stored: it is a `Pending`
/// row read after `expires_at`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PendingStatus {
    /// Waiting for a human.
    Pending,
    /// A human approved it and the action is running. A row left here
    /// (the Worker stopped mid-run) is never run again.
    Approved,
    /// Approved and the API accepted the action (`job_id` is set).
    Executed,
    /// Approved but the API refused or failed it (`error_code` is set).
    Failed,
    /// A human rejected it. It never runs.
    Rejected,
    /// Nobody decided in time. It never runs.
    Expired,
}

impl PendingStatus {
    pub const ALL: &'static [PendingStatus] = &[
        PendingStatus::Pending,
        PendingStatus::Approved,
        PendingStatus::Executed,
        PendingStatus::Failed,
        PendingStatus::Rejected,
        PendingStatus::Expired,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            PendingStatus::Pending => "pending",
            PendingStatus::Approved => "approved",
            PendingStatus::Executed => "executed",
            PendingStatus::Failed => "failed",
            PendingStatus::Rejected => "rejected",
            PendingStatus::Expired => "expired",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        Self::ALL.iter().copied().find(|v| v.as_str() == s)
    }

    /// True for the values a row can hold.
    pub fn stored(self) -> bool {
        self != PendingStatus::Expired
    }
}

/// One destructive action waiting for, or past, a human decision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PendingAction {
    pub id: String,
    pub tenant_id: String,
    pub action: PendingKind,
    pub sandbox_id: String,
    /// The agent's reason. Agent-written text: treat it as data.
    pub reason: Reason,
    /// The agent's idempotency key: a retry with it returns this action.
    /// The approved action is sent to the API with the action id as its
    /// idempotency key.
    pub idempotency_key: Option<String>,
    /// Token id that asked.
    pub requested_by: String,
    pub requested_kind: Role,
    pub created_at: i64,
    pub expires_at: i64,
    pub status: PendingStatus,
    /// Token id of the human who approved or rejected it.
    pub decided_by: Option<String>,
    pub decided_at: Option<i64>,
    pub note: Option<String>,
    /// The host job the approved action queued.
    pub job_id: Option<String>,
    /// The API error code when the approved action failed.
    pub error_code: Option<String>,
}

impl PendingAction {
    /// The status as seen at `now`: a pending row past its expiry is
    /// `Expired`.
    pub fn status_at(&self, now: i64) -> PendingStatus {
        if self.status == PendingStatus::Pending && now >= self.expires_at {
            PendingStatus::Expired
        } else {
            self.status
        }
    }

    /// This record as returned by the API at `now`.
    pub fn view_at(mut self, now: i64) -> Self {
        self.status = self.status_at(now);
        self
    }

    /// The MCP tool that asked for it.
    pub fn tool(&self) -> &'static str {
        self.action.tool()
    }
}

/// Check a decision note: at most [`MAX_NOTE_CHARS`] characters, and not
/// blank when `required`.
pub fn check_note(note: Option<&str>, required: bool) -> Result<Option<String>, &'static str> {
    let note = note.map(str::trim).filter(|n| !n.is_empty());
    match note {
        None if required => Err("note must not be empty"),
        Some(n) if n.chars().count() > MAX_NOTE_CHARS => Err("note is longer than 1000 characters"),
        other => Ok(other.map(str::to_string)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decoy::ReasonCode;

    fn action(status: PendingStatus) -> PendingAction {
        PendingAction {
            id: "pa_1".into(),
            tenant_id: "t1".into(),
            action: PendingKind::Destroy,
            sandbox_id: "dcy1".into(),
            reason: Reason {
                code: ReasonCode::OperatorManual,
                text: "done".into(),
            },
            idempotency_key: None,
            requested_by: "agent".into(),
            requested_kind: Role::Mcp,
            created_at: 1_000,
            expires_at: 1_000 + PENDING_ACTION_TTL_MS,
            status,
            decided_by: None,
            decided_at: None,
            note: None,
            job_id: None,
            error_code: None,
        }
    }

    #[test]
    fn pending_rows_expire_at_their_deadline() {
        let a = action(PendingStatus::Pending);
        assert_eq!(a.status_at(a.expires_at - 1), PendingStatus::Pending);
        assert_eq!(a.status_at(a.expires_at), PendingStatus::Expired);
        // Decided rows keep their status after the deadline.
        for s in [
            PendingStatus::Approved,
            PendingStatus::Executed,
            PendingStatus::Failed,
            PendingStatus::Rejected,
        ] {
            assert_eq!(action(s).status_at(i64::MAX), s);
        }
        assert_eq!(
            a.clone().view_at(a.expires_at).status,
            PendingStatus::Expired
        );
    }

    #[test]
    fn strings_round_trip() {
        for s in PendingStatus::ALL {
            assert_eq!(PendingStatus::parse(s.as_str()), Some(*s));
            let json = serde_json::to_value(s).unwrap();
            assert_eq!(json, s.as_str());
        }
        assert!(!PendingStatus::Expired.stored());
        for k in [PendingKind::Reset, PendingKind::Destroy] {
            assert_eq!(PendingKind::parse(k.as_str()), Some(k));
        }
        assert_eq!(PendingKind::Destroy.tool(), "destroy_sandbox");
        assert_eq!(PendingKind::Reset.target_state(), DecoyState::Rotating);
    }

    #[test]
    fn notes_are_checked() {
        assert_eq!(check_note(None, false), Ok(None));
        assert_eq!(check_note(Some("  "), false), Ok(None));
        assert!(check_note(Some("  "), true).is_err());
        assert_eq!(check_note(Some(" ok "), true), Ok(Some("ok".into())));
        assert!(check_note(Some(&"x".repeat(1001)), false).is_err());
    }

    #[test]
    fn ttl_is_fifteen_minutes() {
        assert_eq!(PENDING_ACTION_TTL_MS, 900_000);
    }
}
