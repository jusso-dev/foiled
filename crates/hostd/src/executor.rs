//! Map one admitted job onto runtime calls (`docs/rotation.md`).
//!
//! Rebuilds always destroy the guest and create a fresh one from the pinned
//! artefact; a compromised guest is never restarted from its disk. If a
//! containment step fails the decoy is left stopped and unpublished, and the
//! result says so.

use foiled_core::agent::{JobBody, JobKind, JobOutcome, JobResult};
use foiled_core::decoy::DecoyState;

use crate::runtime::{DecoySpec, Runtime, RuntimeError, SnapshotKind};

fn ok(job: &JobBody, state: Option<DecoyState>) -> JobResult {
    JobResult {
        job_id: job.job_id.clone(),
        outcome: JobOutcome::Succeeded,
        decoy_state: state,
        detail: None,
    }
}

fn failed(job: &JobBody, state: Option<DecoyState>, e: RuntimeError) -> JobResult {
    JobResult {
        job_id: job.job_id.clone(),
        outcome: JobOutcome::Failed,
        decoy_state: state,
        detail: Some(e.0),
    }
}

/// Stop, flush capture, take a forensic snapshot when the reason suggests
/// compromise (best effort), destroy. Returns an error only for steps that
/// matter for containment.
fn tear_down(rt: &dyn Runtime, job: &JobBody) -> Result<(), RuntimeError> {
    let id = job.decoy_id.as_str();
    rt.stop(id)?;
    // Evidence steps are best effort: losing them must not block containment.
    let _ = rt.capture_flush(id);
    if job
        .reason
        .as_ref()
        .is_some_and(|r| r.code.indicates_compromise())
    {
        let _ = rt.snapshot(id, SnapshotKind::Forensic);
    }
    rt.destroy(id)
}

fn build(rt: &dyn Runtime, job: &JobBody) -> Result<(), RuntimeError> {
    let params = job
        .decoy
        .clone()
        .ok_or_else(|| RuntimeError("job has no run parameters".into()))?;
    rt.create(&DecoySpec {
        decoy_id: job.decoy_id.clone(),
        params,
    })?;
    rt.start(&job.decoy_id)
}

pub fn execute(rt: &dyn Runtime, job: &JobBody) -> JobResult {
    let id = job.decoy_id.as_str();
    match job.kind {
        JobKind::DecoyCreate => match build(rt, job) {
            Ok(()) => ok(job, Some(DecoyState::Healthy)),
            Err(e) => {
                let _ = rt.stop(id);
                failed(job, Some(DecoyState::Failed), e)
            }
        },
        JobKind::DecoyStart => match rt.start(id) {
            Ok(()) => ok(job, Some(DecoyState::Healthy)),
            Err(e) => failed(job, Some(DecoyState::Failed), e),
        },
        JobKind::DecoyStop => match rt.stop(id) {
            Ok(()) => ok(job, Some(DecoyState::Stopped)),
            Err(e) => failed(job, None, e),
        },
        JobKind::DecoyRotate | JobKind::DecoyReset => {
            if let Err(e) = tear_down(rt, job) {
                return failed(job, Some(DecoyState::Stopped), e);
            }
            match build(rt, job) {
                Ok(()) => ok(job, Some(DecoyState::Healthy)),
                Err(e) => {
                    let _ = rt.stop(id);
                    failed(job, Some(DecoyState::Failed), e)
                }
            }
        }
        JobKind::DecoyMarkCompromised => {
            if let Err(e) = rt.stop(id) {
                return failed(job, None, e);
            }
            let _ = rt.capture_flush(id);
            let _ = rt.snapshot(id, SnapshotKind::Forensic);
            ok(job, Some(DecoyState::Quarantined))
        }
        JobKind::DecoyDestroy => match tear_down(rt, job) {
            Ok(()) => ok(job, Some(DecoyState::Destroyed)),
            Err(e) => failed(job, Some(DecoyState::Stopped), e),
        },
        JobKind::DecoySnapshot => match rt.snapshot(id, SnapshotKind::Forensic) {
            Ok(_) => ok(job, None),
            Err(e) => failed(job, None, e),
        },
        JobKind::CaptureFlush => match rt.capture_flush(id) {
            Ok(()) => ok(job, None),
            Err(e) => failed(job, None, e),
        },
        JobKind::HostDrain => {
            let mut last = None;
            for d in rt.running() {
                if let Err(e) = rt.stop(&d) {
                    last = Some(e);
                }
            }
            match last {
                None => ok(job, None),
                Some(e) => failed(job, None, e),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::{Call, FakeRuntime};
    use foiled_core::agent::DecoyParams;
    use foiled_core::catalogue::DecoyKind;
    use foiled_core::decoy::{Reason, ReasonCode};

    fn job(kind: JobKind, code: Option<ReasonCode>) -> JobBody {
        JobBody {
            job_id: "j1".into(),
            host_id: "host-1".into(),
            tenant_id: "t1".into(),
            decoy_id: "d1".into(),
            kind,
            reason: code.map(|code| Reason {
                code,
                text: "test".into(),
            }),
            decoy: Some(DecoyParams {
                catalogue_id: "foiled/demo-app/1.0.0".into(),
                decoy_kind: DecoyKind::Sandbox,
                generation: 2,
                artefact: Some(format!("sha256:{}", "a".repeat(64))),
                image: None,
                listen_ports: vec![],
                hard_deadline: 0,
            }),
            idempotency_key: "k".into(),
            issued_at: 0,
            expires_at: 1,
        }
    }

    #[test]
    fn create_builds_and_starts() {
        let rt = FakeRuntime::default();
        let r = execute(&rt, &job(JobKind::DecoyCreate, None));
        assert_eq!(r.decoy_state, Some(DecoyState::Healthy));
        assert!(matches!(rt.calls()[0], Call::Create { generation: 2, .. }));
        assert_eq!(rt.calls()[1], Call::Start("d1".into()));
        assert_eq!(rt.running(), vec!["d1".to_string()]);
    }

    #[test]
    fn rotation_after_compromise_snapshots_then_rebuilds_from_the_artefact() {
        let rt = FakeRuntime::default();
        let r = execute(
            &rt,
            &job(JobKind::DecoyRotate, Some(ReasonCode::EgressBlocked)),
        );
        assert_eq!(r.outcome, JobOutcome::Succeeded);
        let calls = rt.calls();
        assert_eq!(calls[0], Call::Stop("d1".into()), "freeze first");
        assert_eq!(calls[1], Call::CaptureFlush("d1".into()));
        assert_eq!(calls[2], Call::Snapshot("d1".into()));
        assert_eq!(
            calls[3],
            Call::Destroy("d1".into()),
            "never reboot the old guest"
        );
        assert!(matches!(calls[4], Call::Create { .. }));
        assert_eq!(calls[5], Call::Start("d1".into()));
    }

    #[test]
    fn routine_rotation_skips_the_forensic_snapshot() {
        let rt = FakeRuntime::default();
        execute(
            &rt,
            &job(JobKind::DecoyRotate, Some(ReasonCode::MaxLifetime)),
        );
        assert!(!rt.calls().iter().any(|c| matches!(c, Call::Snapshot(_))));
    }

    #[test]
    fn failed_destroy_leaves_the_decoy_stopped_and_never_rebuilt() {
        let rt = FakeRuntime::failing_when(|c| matches!(c, Call::Destroy(_)));
        let r = execute(
            &rt,
            &job(JobKind::DecoyRotate, Some(ReasonCode::OperatorManual)),
        );
        assert_eq!(r.outcome, JobOutcome::Failed);
        assert_eq!(r.decoy_state, Some(DecoyState::Stopped));
        assert!(
            !rt.calls()
                .iter()
                .any(|c| matches!(c, Call::Create { .. } | Call::Start(_)))
        );
    }

    #[test]
    fn evidence_failures_do_not_block_containment() {
        let rt =
            FakeRuntime::failing_when(|c| matches!(c, Call::CaptureFlush(_) | Call::Snapshot(_)));
        let r = execute(
            &rt,
            &job(JobKind::DecoyDestroy, Some(ReasonCode::YaraMatch)),
        );
        assert_eq!(r.decoy_state, Some(DecoyState::Destroyed));
    }

    #[test]
    fn mark_compromised_quarantines_without_destroying() {
        let rt = FakeRuntime::default();
        let r = execute(
            &rt,
            &job(
                JobKind::DecoyMarkCompromised,
                Some(ReasonCode::ReverseShell),
            ),
        );
        assert_eq!(r.decoy_state, Some(DecoyState::Quarantined));
        assert!(!rt.calls().iter().any(|c| matches!(c, Call::Destroy(_))));
    }

    #[test]
    fn failed_create_reports_failed() {
        let rt = FakeRuntime::failing_when(|c| matches!(c, Call::Start(_)));
        let r = execute(&rt, &job(JobKind::DecoyCreate, None));
        assert_eq!(r.outcome, JobOutcome::Failed);
        assert_eq!(r.decoy_state, Some(DecoyState::Failed));
    }
}
