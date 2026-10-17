//! Decoy lifecycle (#8, #21, #41).
//!
//! The control plane only writes `pending` on create. Every other state
//! change comes from a host report, and any route back to service passes
//! through `rotating`, which rebuilds from the catalogue digest. See
//! `docs/rotation.md`.

use serde::{Deserialize, Serialize};

use crate::catalogue::DecoyKind;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DecoyState {
    Pending,
    Starting,
    Healthy,
    Rotating,
    Stopped,
    Quarantined,
    Failed,
    Destroyed,
}

impl DecoyState {
    pub const ALL: [DecoyState; 8] = [
        DecoyState::Pending,
        DecoyState::Starting,
        DecoyState::Healthy,
        DecoyState::Rotating,
        DecoyState::Stopped,
        DecoyState::Quarantined,
        DecoyState::Failed,
        DecoyState::Destroyed,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            DecoyState::Pending => "pending",
            DecoyState::Starting => "starting",
            DecoyState::Healthy => "healthy",
            DecoyState::Rotating => "rotating",
            DecoyState::Stopped => "stopped",
            DecoyState::Quarantined => "quarantined",
            DecoyState::Failed => "failed",
            DecoyState::Destroyed => "destroyed",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|v| v.as_str() == s)
    }

    /// Allowed transitions. A guest that was stopped, quarantined or failed
    /// never goes straight back to `starting`: it must be rebuilt through
    /// `rotating`.
    pub fn can_transition_to(self, next: DecoyState) -> bool {
        use DecoyState::*;
        if self == next {
            return false;
        }
        match self {
            Pending => matches!(next, Starting | Failed | Destroyed),
            Starting => matches!(next, Healthy | Failed | Stopped | Destroyed),
            Healthy => matches!(next, Rotating | Stopped | Quarantined | Failed | Destroyed),
            Rotating => matches!(next, Starting | Stopped | Failed | Destroyed),
            Stopped => matches!(next, Rotating | Quarantined | Destroyed),
            Quarantined => matches!(next, Rotating | Destroyed),
            Failed => matches!(next, Rotating | Destroyed),
            Destroyed => false,
        }
    }

    /// Shortest sequence of allowed moves from `self` to `target`, not
    /// including `self`. `None` when the target cannot be reached. Hosts
    /// report the state a job ended in; the control plane walks this path so
    /// every intermediate move is still checked.
    pub fn path_to(self, target: DecoyState) -> Option<Vec<DecoyState>> {
        if self == target {
            return Some(Vec::new());
        }
        let mut prev: [Option<DecoyState>; 8] = [None; 8];
        let idx = |s: DecoyState| Self::ALL.iter().position(|x| *x == s).unwrap_or(0);
        let mut queue = std::collections::VecDeque::from([self]);
        let mut seen = [false; 8];
        seen[idx(self)] = true;
        while let Some(cur) = queue.pop_front() {
            for next in Self::ALL {
                if !seen[idx(next)] && cur.can_transition_to(next) {
                    seen[idx(next)] = true;
                    prev[idx(next)] = Some(cur);
                    if next == target {
                        let mut path = vec![next];
                        let mut at = next;
                        while let Some(p) = prev[idx(at)] {
                            if p == self {
                                break;
                            }
                            path.push(p);
                            at = p;
                        }
                        path.reverse();
                        return Some(path);
                    }
                    queue.push_back(next);
                }
            }
        }
        None
    }

    /// The decoy accepts attacker traffic only in this state.
    pub fn is_published(self) -> bool {
        self == DecoyState::Healthy
    }

    pub fn is_terminal(self) -> bool {
        self == DecoyState::Destroyed
    }
}

/// Why a decoy is being rotated, reset, stopped or destroyed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReasonCode {
    MaxLifetime,
    Idle,
    ReverseShell,
    EgressBlocked,
    YaraMatch,
    CanaryUsed,
    HoneyscoreHigh,
    HealthFailed,
    OperatorManual,
}

impl ReasonCode {
    /// True for signals that the guest may be compromised. These rotations
    /// take a best-effort forensic snapshot before destroy.
    pub fn indicates_compromise(self) -> bool {
        matches!(
            self,
            ReasonCode::ReverseShell
                | ReasonCode::EgressBlocked
                | ReasonCode::YaraMatch
                | ReasonCode::CanaryUsed
        )
    }
}

/// A required, human-readable reason for a destructive action (#21).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Reason {
    pub code: ReasonCode,
    pub text: String,
}

impl Reason {
    pub const MAX_TEXT: usize = 500;

    /// Reasons must say something. Whitespace-only text is rejected.
    pub fn validate(&self) -> Result<(), &'static str> {
        let t = self.text.trim();
        if t.is_empty() {
            return Err("reason.text must not be empty");
        }
        if t.chars().count() > Self::MAX_TEXT {
            return Err("reason.text is longer than 500 characters");
        }
        Ok(())
    }
}

/// A decoy as stored in D1 and returned by `/v0/decoys`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Decoy {
    pub id: String,
    pub tenant_id: String,
    pub catalogue_id: String,
    pub decoy_kind: DecoyKind,
    pub label: Option<String>,
    pub state: DecoyState,
    pub host_id: Option<String>,
    /// Catalogue generation counter: bumps on every rebuild.
    pub generation: u32,
    pub created_at: i64,
    pub updated_at: i64,
    /// Unix ms after which the decoy is rotated for `max_lifetime`.
    pub expires_at: i64,
    pub created_by: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use DecoyState::*;

    #[test]
    fn states_round_trip_through_strings() {
        for s in DecoyState::ALL {
            assert_eq!(DecoyState::parse(s.as_str()), Some(s));
        }
        assert_eq!(DecoyState::parse("running"), None);
    }

    #[test]
    fn compromised_states_only_return_through_rotating() {
        for from in [Stopped, Quarantined, Failed] {
            assert!(!from.can_transition_to(Starting), "{from:?} -> starting");
            assert!(!from.can_transition_to(Healthy), "{from:?} -> healthy");
            assert!(from.can_transition_to(Rotating));
        }
        assert!(Rotating.can_transition_to(Starting));
    }

    #[test]
    fn destroyed_is_terminal_and_reachable_from_everywhere_else() {
        for s in DecoyState::ALL {
            assert!(!Destroyed.can_transition_to(s));
            if s != Destroyed {
                assert!(s.can_transition_to(Destroyed), "{s:?}");
            }
        }
        assert!(Destroyed.is_terminal());
    }

    #[test]
    fn happy_path_create_publish_rotate() {
        let path = [Pending, Starting, Healthy, Rotating, Starting, Healthy];
        for w in path.windows(2) {
            assert!(w[0].can_transition_to(w[1]), "{:?} -> {:?}", w[0], w[1]);
        }
        assert!(Healthy.is_published());
        assert!(!Rotating.is_published());
        assert!(!Pending.can_transition_to(Healthy));
        assert!(!Healthy.can_transition_to(Healthy));
    }

    #[test]
    fn paths_walk_through_allowed_moves_only() {
        assert_eq!(Pending.path_to(Healthy), Some(vec![Starting, Healthy]));
        assert_eq!(Rotating.path_to(Healthy), Some(vec![Starting, Healthy]));
        assert_eq!(Healthy.path_to(Healthy), Some(vec![]));
        // A quarantined guest only comes back through a rebuild.
        assert_eq!(
            Quarantined.path_to(Healthy),
            Some(vec![Rotating, Starting, Healthy])
        );
        assert_eq!(Destroyed.path_to(Healthy), None);
        for from in DecoyState::ALL {
            for to in DecoyState::ALL {
                if let Some(path) = from.path_to(to) {
                    let mut cur = from;
                    for s in path {
                        assert!(cur.can_transition_to(s), "{cur:?} -> {s:?}");
                        cur = s;
                    }
                    assert_eq!(cur, to);
                }
            }
        }
    }

    #[test]
    fn reason_text_is_required() {
        let r = |text: &str| Reason {
            code: ReasonCode::OperatorManual,
            text: text.into(),
        };
        assert!(r("rotating after demo").validate().is_ok());
        assert!(r("   ").validate().is_err());
        assert!(r(&"x".repeat(501)).validate().is_err());
    }

    #[test]
    fn compromise_codes() {
        assert!(ReasonCode::ReverseShell.indicates_compromise());
        assert!(!ReasonCode::MaxLifetime.indicates_compromise());
        let json = serde_json::to_string(&ReasonCode::HoneyscoreHigh).unwrap();
        assert_eq!(json, "\"honeyscore_high\"");
    }
}
