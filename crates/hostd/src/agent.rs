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
    /// control plane is unreachable. Returns how many were delivered.
    pub async fn flush(&mut self) -> Result<usize, ClientError> {
        let mut sent = 0;
        loop {
            let batch = self
                .buffer
                .peek(MAX_BATCH)
                .map_err(|e| ClientError::Unavailable(e.to_string()))?;
            if batch.is_empty() {
                return Ok(sent);
            }
            match self.cp.send_events(&batch).await {
                Ok(()) => {}
                // The control plane will never accept this batch. Drop it so
                // the buffer does not wedge; the drop shows in heartbeats.
                Err(ClientError::Refused(..)) => {}
                Err(e) => return Err(e),
            }
            self.buffer
                .commit(batch.len())
                .map_err(|e| ClientError::Unavailable(e.to_string()))?;
            sent += batch.len();
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
