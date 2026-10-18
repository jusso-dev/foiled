//! One agent: lease, check, execute, report; flush buffered evidence; send
//! heartbeats. Each step is a method so tests can drive it deterministically.

use std::sync::Arc;

use foiled_core::agent::{Heartbeat, JobOutcome, JobResult};
use foiled_core::capture::{CaptureEvent, MAX_BATCH};

use crate::buffer::OfflineBuffer;
use crate::client::{ClientError, ControlPlane};
use crate::executor;
use crate::gate::JobGate;
use crate::runtime::Runtime;

pub struct Agent {
    pub host_id: String,
    pub gate: JobGate,
    pub runtime: Arc<dyn Runtime>,
    pub cp: ControlPlane,
    pub buffer: OfflineBuffer,
    pub publicly_exposed: bool,
    pub kvm_present: bool,
    pub state_dir: std::path::PathBuf,
    /// Run parameters of decoys this agent built, for log capture.
    pub decoys: std::collections::HashMap<String, foiled_core::agent::DecoyParams>,
}

#[derive(Debug, Default, PartialEq, Eq)]
pub struct TickReport {
    pub executed: usize,
    pub rejected: usize,
}

impl Agent {
    /// Lease jobs and run each one that passes the gate. Rejections are
    /// reported back so the control plane can audit them.
    pub async fn run_jobs(&mut self, now: i64) -> Result<TickReport, ClientError> {
        let mut report = TickReport::default();
        for signed in self.cp.lease().await? {
            let result = match self.gate.admit(&signed, now) {
                Ok(job) => {
                    report.executed += 1;
                    let rt = self.runtime.clone();
                    let (decoy_id, params) = (job.decoy_id.clone(), job.decoy.clone());
                    let result =
                        tokio::task::spawn_blocking(move || executor::execute(rt.as_ref(), &job))
                            .await
                            .map_err(|e| ClientError::Unavailable(e.to_string()))?;
                    match (result.decoy_state, params) {
                        (Some(foiled_core::decoy::DecoyState::Healthy), Some(p)) => {
                            self.decoys.insert(decoy_id, p);
                        }
                        (Some(foiled_core::decoy::DecoyState::Destroyed), _) => {
                            self.decoys.remove(&decoy_id);
                        }
                        _ => {}
                    }
                    result
                }
                Err(rejection) => {
                    report.rejected += 1;
                    // Only report jobs we can name; a forged body has no trusted id.
                    let Ok(body) = serde_json::from_str::<serde_json::Value>(&signed.body) else {
                        continue;
                    };
                    let Some(job_id) = body["job_id"].as_str() else {
                        continue;
                    };
                    JobResult {
                        job_id: job_id.to_string(),
                        outcome: JobOutcome::Rejected,
                        decoy_state: None,
                        detail: Some(rejection.to_string()),
                    }
                }
            };
            match self.cp.ack(&result).await {
                // A refused ack (for example a forged job id) is not retried.
                Ok(()) | Err(ClientError::Refused(..)) => {}
                Err(e) => return Err(e),
            }
        }
        Ok(report)
    }

    /// Queue a capture envelope locally. Sending happens in [`Agent::flush`].
    pub fn capture(&mut self, event: &CaptureEvent) -> std::io::Result<()> {
        self.buffer.push(event)
    }

    /// Send buffered events oldest first until the buffer is empty or the
    /// control plane is unreachable. Returns how many were accepted.
    ///
    /// - Unreachable, 5xx or 429 (back-pressure): stop, keep everything,
    ///   try again next tick.
    /// - 401, or a 403 about the caller (certificate revoked, retired or
    ///   unknown, scope missing): stop and keep everything. The data is
    ///   fine; the identity is not.
    /// - Any other refusal, including a 403 `not_assigned` for a decoy that
    ///   is no longer this agent's: the batch holds an event ingest will
    ///   never take. Resend one at a time and drop only the refused events,
    ///   logged and counted in `dropped_events`, so one stale event cannot
    ///   stall the buffer.
    ///
    /// Delivery is at least once. Ingest is idempotent on `event_id`, so a
    /// resend after a crash or a split batch creates no duplicates.
    pub async fn flush(&mut self) -> Result<usize, ClientError> {
        let unavailable = |e: std::io::Error| ClientError::Unavailable(e.to_string());
        let mut sent = 0;
        loop {
            let batch = self.buffer.peek(MAX_BATCH).map_err(unavailable)?;
            if batch.is_empty() {
                return Ok(sent);
            }
            let mut refused = 0;
            match self.cp.send_events(&batch).await {
                Ok(()) => {}
                Err(e) if e.is_identity_problem() => return Err(e),
                Err(ClientError::Refused(..)) => {
                    for (i, event) in batch.iter().enumerate() {
                        match self.cp.send_events(std::slice::from_ref(event)).await {
                            Ok(()) => {}
                            Err(e) if e.is_identity_problem() => {
                                self.buffer.commit(i).map_err(unavailable)?;
                                return Err(e);
                            }
                            Err(e @ ClientError::Refused(..)) => {
                                eprintln!(
                                    "foiled-hostd: dropping event {} refused by ingest: {}",
                                    event.event_id,
                                    e.code().unwrap_or_else(|| e.to_string())
                                );
                                self.buffer.note_dropped(1);
                                refused += 1;
                            }
                            Err(e) => {
                                self.buffer.commit(i).map_err(unavailable)?;
                                return Err(e);
                            }
                        }
                    }
                }
                Err(e) => return Err(e),
            }
            self.buffer.commit(batch.len()).map_err(unavailable)?;
            sent += batch.len() - refused;
        }
    }

    pub fn heartbeat_body(&self, now: i64) -> Heartbeat {
        Heartbeat {
            host_id: self.host_id.clone(),
            agent_version: env!("CARGO_PKG_VERSION").to_string(),
            kvm_present: self.kvm_present,
            publicly_exposed: self.publicly_exposed,
            free_disk_bytes: fs4::available_space(&self.state_dir).unwrap_or(0),
            running_decoys: self.runtime.running(),
            host_time: now,
            buffered_events: self.buffer.len().unwrap_or(0),
            dropped_events: self.buffer.dropped(),
        }
    }

    pub async fn heartbeat(&self, now: i64) -> Result<(), ClientError> {
        self.cp.heartbeat(&self.heartbeat_body(now)).await
    }
}
