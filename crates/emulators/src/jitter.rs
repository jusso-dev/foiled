//! Response timing jitter (#18, FR-17 in `docs/fingerprint-resistance.md`).
//!
//! Scripted emulators answer in the same few microseconds every time, which
//! is a tell. Each reply waits a random delay in `min_ms..=max_ms` first.
//! Profiles default to a small range; tests set it to zero.

use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::util::Rng;

/// Highest `max_ms` a profile may set. More than this breaks clients.
pub const MAX_JITTER_MS: u32 = 2_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Jitter {
    pub min_ms: u32,
    pub max_ms: u32,
}

impl Default for Jitter {
    /// A few milliseconds: enough spread to look like a real server, never
    /// enough to break a client.
    fn default() -> Self {
        Jitter {
            min_ms: 2,
            max_ms: 15,
        }
    }
}

impl Jitter {
    pub const NONE: Jitter = Jitter {
        min_ms: 0,
        max_ms: 0,
    };

    pub fn is_none(&self) -> bool {
        self.max_ms == 0
    }

    pub fn problems(&self) -> Vec<String> {
        let mut out = Vec::new();
        if self.min_ms > self.max_ms {
            out.push(format!(
                "jitter min_ms {} is above max_ms {}",
                self.min_ms, self.max_ms
            ));
        }
        if self.max_ms > MAX_JITTER_MS {
            out.push(format!(
                "jitter max_ms {} is above the {MAX_JITTER_MS} ms cap",
                self.max_ms
            ));
        }
        out
    }

    pub fn pick(&self, rng: &mut Rng) -> Duration {
        let hi = self.max_ms.min(MAX_JITTER_MS);
        let lo = self.min_ms.min(hi);
        Duration::from_millis(rng.range(u64::from(lo), u64::from(hi)))
    }

    /// Sleep for a picked delay. Returns at once when the range is zero.
    pub async fn wait(&self, rng: &mut Rng) {
        let d = self.pick(rng);
        if !d.is_zero() {
            tokio::time::sleep(d).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn picks_stay_in_range_and_none_is_zero() {
        let mut rng = Rng::seeded(42);
        let j = Jitter::default();
        let picks: Vec<u128> = (0..500).map(|_| j.pick(&mut rng).as_millis()).collect();
        assert!(picks.iter().all(|&ms| (2..=15).contains(&ms)));
        // Natural spread, not one constant value.
        assert!(picks.iter().min() != picks.iter().max());
        assert!(Jitter::NONE.pick(&mut rng).is_zero());
        assert!(Jitter::NONE.is_none());
    }

    #[test]
    fn bad_ranges_are_reported() {
        assert_eq!(
            Jitter {
                min_ms: 5,
                max_ms: 1
            }
            .problems()
            .len(),
            1
        );
        assert_eq!(
            Jitter {
                min_ms: 0,
                max_ms: 60_000
            }
            .problems()
            .len(),
            1
        );
        assert!(Jitter::default().problems().is_empty());
    }
}
