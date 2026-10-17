//! Every job passes this gate before the runtime sees it.
//!
//! Refused: anything not signed by a trusted key, jobs for another host,
//! expired jobs, jobs issued implausibly far in the future, replays of an
//! idempotency key already run, destructive jobs without a reason, and
//! create or rebuild jobs whose artefact is not on the local allow-list.

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;

use foiled_core::agent::{JobBody, JobKind, SignedJob, TrustedKeys, VerifyError};

/// How far ahead of the host clock a job's `issued_at` may be.
pub const MAX_ISSUE_SKEW_MS: i64 = 5 * 60 * 1000;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Rejection {
    Signature(VerifyError),
    WrongHost { expected: String, got: String },
    Expired,
    FromTheFuture,
    Replay,
    MissingReason,
    MissingArtefact,
    NotAllowListed(String),
}

impl std::fmt::Display for Rejection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Rejection::Signature(e) => write!(f, "signature: {e}"),
            Rejection::WrongHost { expected, got } => {
                write!(f, "job is for host {got}, this is {expected}")
            }
            Rejection::Expired => write!(f, "job has expired"),
            Rejection::FromTheFuture => write!(f, "job issued too far in the future"),
            Rejection::Replay => write!(f, "idempotency key already used"),
            Rejection::MissingReason => write!(f, "destructive job without a reason"),
            Rejection::MissingArtefact => write!(f, "no pinned artefact in the job"),
            Rejection::NotAllowListed(a) => {
                write!(f, "artefact {a} is not on the local allow-list")
            }
        }
    }
}

/// Idempotency keys already run, kept until their job would have expired.
/// Persisted so a restart cannot be used to replay a job.
pub struct ReplayStore {
    path: Option<PathBuf>,
    seen: HashMap<String, i64>,
}

impl ReplayStore {
    pub fn in_memory() -> Self {
        ReplayStore {
            path: None,
            seen: HashMap::new(),
        }
    }

    pub fn open(path: PathBuf) -> std::io::Result<Self> {
        let seen = match std::fs::read_to_string(&path) {
            Ok(text) => serde_json::from_str(&text).unwrap_or_default(),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => HashMap::new(),
            Err(e) => return Err(e),
        };
        Ok(ReplayStore {
            path: Some(path),
            seen,
        })
    }

    fn contains(&self, key: &str) -> bool {
        self.seen.contains_key(key)
    }

    fn insert(&mut self, key: &str, expires_at: i64, now: i64) -> std::io::Result<()> {
        self.seen.retain(|_, exp| *exp > now);
        self.seen.insert(key.to_string(), expires_at);
        if let Some(path) = &self.path {
            let tmp = path.with_extension("tmp");
            std::fs::write(&tmp, serde_json::to_vec(&self.seen)?)?;
            std::fs::rename(tmp, path)?;
        }
        Ok(())
    }
}

pub struct JobGate {
    pub host_id: String,
    pub keys: TrustedKeys,
    pub allowlist: HashSet<String>,
    pub replays: ReplayStore,
}

impl JobGate {
    /// Check a signed job. On success the idempotency key is recorded, so the
    /// same job cannot be admitted twice.
    pub fn admit(&mut self, job: &SignedJob, now: i64) -> Result<JobBody, Rejection> {
        let body = self.keys.verify(job).map_err(Rejection::Signature)?;
        if body.host_id != self.host_id {
            return Err(Rejection::WrongHost {
                expected: self.host_id.clone(),
                got: body.host_id,
            });
        }
        if body.expires_at <= now {
            return Err(Rejection::Expired);
        }
        if body.issued_at > now + MAX_ISSUE_SKEW_MS {
            return Err(Rejection::FromTheFuture);
        }
        if self.replays.contains(&body.idempotency_key) {
            return Err(Rejection::Replay);
        }
        if body.kind.needs_reason() && body.reason.is_none() {
            return Err(Rejection::MissingReason);
        }
        if matches!(
            body.kind,
            JobKind::DecoyCreate | JobKind::DecoyRotate | JobKind::DecoyReset
        ) {
            let artefact = body
                .decoy
                .as_ref()
                .and_then(|d| d.artefact.clone())
                .ok_or(Rejection::MissingArtefact)?;
            if !self.allowlist.contains(&artefact) {
                return Err(Rejection::NotAllowListed(artefact));
            }
        }
        // A failed write here would let a restart replay the job; refuse rather.
        self.replays
            .insert(&body.idempotency_key, body.expires_at, now)
            .map_err(|_| Rejection::Replay)?;
        Ok(body)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use foiled_core::agent::{DecoyParams, JobSigner};
    use foiled_core::catalogue::DecoyKind;
    use foiled_core::decoy::{Reason, ReasonCode};

    const SEED: &str = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
    const NOW: i64 = 1_800_000_000_000;

    fn signer() -> JobSigner {
        JobSigner::from_seed_hex("k1", SEED).unwrap()
    }

    fn gate() -> JobGate {
        let mut keys = TrustedKeys::default();
        keys.add_hex("k1", &signer().public_key_hex()).unwrap();
        JobGate {
            host_id: "host-1".into(),
            keys,
            allowlist: HashSet::from(["emulator:redis/redis-7.0".to_string()]),
            replays: ReplayStore::in_memory(),
        }
    }

    fn create(key: &str, artefact: Option<&str>) -> JobBody {
        JobBody {
            job_id: format!("job-{key}"),
            host_id: "host-1".into(),
            tenant_id: "t1".into(),
            decoy_id: "d1".into(),
            kind: JobKind::DecoyCreate,
            reason: None,
            decoy: Some(DecoyParams {
                catalogue_id: "emulator/redis/7.0".into(),
                decoy_kind: DecoyKind::Emulation,
                generation: 1,
                artefact: artefact.map(str::to_string),
                image: None,
                listen_ports: vec![],
                hard_deadline: NOW + 86_400_000,
            }),
            idempotency_key: key.into(),
            issued_at: NOW,
            expires_at: NOW + 60_000,
        }
    }

    #[test]
    fn admits_a_good_job_once() {
        let mut g = gate();
        let job = signer().sign(&create("k1", Some("emulator:redis/redis-7.0")));
        assert!(g.admit(&job, NOW).is_ok());
        assert_eq!(g.admit(&job, NOW + 1), Err(Rejection::Replay));
    }

    #[test]
    fn forged_jobs_are_rejected() {
        let mut g = gate();
        let forger = JobSigner::from_seed_hex("k1", &"07".repeat(32)).unwrap();
        let job = forger.sign(&create("k1", Some("emulator:redis/redis-7.0")));
        assert!(matches!(g.admit(&job, NOW), Err(Rejection::Signature(_))));
        // Editing a signed body (for example swapping the artefact) breaks it.
        let mut job = signer().sign(&create("k2", Some("emulator:redis/redis-7.0")));
        job.body = job.body.replace("redis-7.0\"", "redis-6.0\"");
        assert!(matches!(g.admit(&job, NOW), Err(Rejection::Signature(_))));
    }

    #[test]
    fn expired_and_future_jobs_are_rejected() {
        let mut g = gate();
        let job = signer().sign(&create("k1", Some("emulator:redis/redis-7.0")));
        assert_eq!(g.admit(&job, NOW + 60_000), Err(Rejection::Expired));
        let mut future = create("k2", Some("emulator:redis/redis-7.0"));
        future.issued_at = NOW + MAX_ISSUE_SKEW_MS + 1;
        future.expires_at = future.issued_at + 60_000;
        assert_eq!(
            g.admit(&signer().sign(&future), NOW),
            Err(Rejection::FromTheFuture)
        );
    }

    #[test]
    fn jobs_for_other_hosts_are_rejected() {
        let mut g = gate();
        let mut other = create("k1", Some("emulator:redis/redis-7.0"));
        other.host_id = "host-2".into();
        assert!(matches!(
            g.admit(&signer().sign(&other), NOW),
            Err(Rejection::WrongHost { .. })
        ));
    }

    #[test]
    fn artefacts_must_be_pinned_and_allow_listed() {
        let mut g = gate();
        assert_eq!(
            g.admit(&signer().sign(&create("k1", None)), NOW),
            Err(Rejection::MissingArtefact)
        );
        let unlisted = format!("sha256:{}", "b".repeat(64));
        assert_eq!(
            g.admit(&signer().sign(&create("k2", Some(&unlisted))), NOW),
            Err(Rejection::NotAllowListed(unlisted))
        );
    }

    #[test]
    fn destructive_jobs_need_a_reason() {
        let mut g = gate();
        let mut destroy = create("k1", None);
        destroy.kind = JobKind::DecoyDestroy;
        destroy.decoy = None;
        assert_eq!(
            g.admit(&signer().sign(&destroy), NOW),
            Err(Rejection::MissingReason)
        );
        destroy.idempotency_key = "k2".into();
        destroy.reason = Some(Reason {
            code: ReasonCode::OperatorManual,
            text: "done".into(),
        });
        assert!(g.admit(&signer().sign(&destroy), NOW).is_ok());
    }

    #[test]
    fn replay_protection_survives_a_restart() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("replays.json");
        let job = signer().sign(&create("k1", Some("emulator:redis/redis-7.0")));
        {
            let mut g = gate();
            g.replays = ReplayStore::open(path.clone()).unwrap();
            assert!(g.admit(&job, NOW).is_ok());
        }
        let mut g = gate();
        g.replays = ReplayStore::open(path).unwrap();
        assert_eq!(g.admit(&job, NOW + 10), Err(Rejection::Replay));
    }
}
