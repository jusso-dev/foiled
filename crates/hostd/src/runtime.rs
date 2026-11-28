//! The decoy runtime interface (ADR 0002). Only the host agent calls it,
//! never anything on the network. Firecracker, module containers and
//! emulator supervision implement it on real hosts; [`FakeRuntime`] records
//! calls for tests and dry runs (`sandbox_runtime = "fake"`).
//!
//! Today only the Docker lab runtime and the fake are built in. Firecracker
//! is tracked in #3; [`from_config`] refuses it instead of substituting
//! another runtime (#91).

use std::sync::{Arc, Mutex};

use foiled_core::agent::{DecoyParams, FailureCode, SandboxRuntime};

use crate::config::{ConfigError, HostConfig};
use crate::docker::DockerRuntime;

/// Build the runtime `cfg` names. Never substitutes one runtime for another:
/// a runtime that is not built in is an error, and the agent exits.
pub fn from_config(cfg: &HostConfig) -> Result<(SandboxRuntime, Arc<dyn Runtime>), ConfigError> {
    let kind = cfg.runtime()?;
    let runtime: Arc<dyn Runtime> = match kind {
        SandboxRuntime::Docker => Arc::new(DockerRuntime::new(cfg.docker.clone())),
        SandboxRuntime::Fake => Arc::new(FakeRuntime::default()),
        SandboxRuntime::Firecracker => return Err(ConfigError::RuntimeNotBuiltIn(kind)),
    };
    Ok((kind, runtime))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecoySpec {
    pub decoy_id: String,
    pub params: DecoyParams,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecMeta {
    pub listen_addrs: Vec<String>,
    pub pid_or_cid: String,
    pub artefact: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SnapshotKind {
    /// Read-only evidence of a possibly compromised guest; never booted.
    Forensic,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeError {
    pub message: String,
    /// Reported to the control plane as the job result's `failure_code`.
    pub code: Option<FailureCode>,
}

impl RuntimeError {
    pub fn new(message: impl Into<String>) -> Self {
        RuntimeError {
            message: message.into(),
            code: None,
        }
    }

    /// The decoy network's egress block could not be confirmed (#93).
    pub fn egress(message: impl Into<String>) -> Self {
        RuntimeError {
            message: format!("egress unverified: {}", message.into()),
            code: Some(FailureCode::EgressUnverified),
        }
    }
}

impl std::fmt::Display for RuntimeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

pub type RtResult<T> = Result<T, RuntimeError>;

/// Blocking interface; the agent runs it on a blocking thread.
pub trait Runtime: Send + Sync {
    /// Read-only checks that a later `create` would also run (for Docker,
    /// the egress preflight). Rotate and reset call it before tearing down
    /// the running decoy, so a check that is bound to fail never leaves the
    /// decoy absent. `create` must still check for itself.
    fn preflight(&self) -> RtResult<()> {
        Ok(())
    }
    fn create(&self, spec: &DecoySpec) -> RtResult<ExecMeta>;
    fn start(&self, decoy_id: &str) -> RtResult<()>;
    /// Freeze networking and stop the guest. Never asks the guest to shut down.
    fn stop(&self, decoy_id: &str) -> RtResult<()>;
    fn destroy(&self, decoy_id: &str) -> RtResult<()>;
    fn snapshot(&self, decoy_id: &str, kind: SnapshotKind) -> RtResult<String>;
    /// Push buffered capture for this decoy to the host buffer.
    fn capture_flush(&self, decoy_id: &str) -> RtResult<()>;
    fn running(&self) -> Vec<String>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Call {
    Create {
        decoy_id: String,
        artefact: String,
        generation: u32,
    },
    Start(String),
    Stop(String),
    Destroy(String),
    Snapshot(String),
    CaptureFlush(String),
}

/// Predicate selecting calls a [`FakeRuntime`] should fail.
pub type FailWhen = fn(&Call) -> bool;

/// Records every call. Can be told to fail a given call.
#[derive(Default)]
pub struct FakeRuntime {
    pub calls: Mutex<Vec<Call>>,
    running: Mutex<Vec<String>>,
    fail_on: Mutex<Option<FailWhen>>,
}

impl FakeRuntime {
    pub fn failing_when(f: FailWhen) -> Self {
        let r = FakeRuntime::default();
        *r.fail_on.lock().unwrap() = Some(f);
        r
    }

    pub fn calls(&self) -> Vec<Call> {
        self.calls.lock().unwrap().clone()
    }

    fn record(&self, c: Call) -> RtResult<()> {
        let fail = self.fail_on.lock().unwrap().is_some_and(|f| f(&c));
        self.calls.lock().unwrap().push(c);
        if fail {
            Err(RuntimeError::new("injected failure"))
        } else {
            Ok(())
        }
    }
}

impl Runtime for FakeRuntime {
    fn create(&self, spec: &DecoySpec) -> RtResult<ExecMeta> {
        let artefact = spec.params.artefact.clone().unwrap_or_default();
        self.record(Call::Create {
            decoy_id: spec.decoy_id.clone(),
            artefact: artefact.clone(),
            generation: spec.params.generation,
        })?;
        Ok(ExecMeta {
            listen_addrs: spec
                .params
                .listen_ports
                .iter()
                .map(|p| format!("10.85.1.2:{}", p.port))
                .collect(),
            pid_or_cid: format!("fake-{}", spec.decoy_id),
            artefact,
        })
    }

    fn start(&self, decoy_id: &str) -> RtResult<()> {
        self.record(Call::Start(decoy_id.into()))?;
        self.running.lock().unwrap().push(decoy_id.into());
        Ok(())
    }

    fn stop(&self, decoy_id: &str) -> RtResult<()> {
        self.record(Call::Stop(decoy_id.into()))?;
        self.running.lock().unwrap().retain(|d| d != decoy_id);
        Ok(())
    }

    fn destroy(&self, decoy_id: &str) -> RtResult<()> {
        self.record(Call::Destroy(decoy_id.into()))
    }

    fn snapshot(&self, decoy_id: &str, _kind: SnapshotKind) -> RtResult<String> {
        self.record(Call::Snapshot(decoy_id.into()))?;
        Ok(format!("snap-{decoy_id}"))
    }

    fn capture_flush(&self, decoy_id: &str) -> RtResult<()> {
        self.record(Call::CaptureFlush(decoy_id.into()))
    }

    fn running(&self) -> Vec<String> {
        self.running.lock().unwrap().clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const LAB: &str = r#"
host_id = "lab-1"
api_base = "http://127.0.0.1:8787"
publicly_exposed = false
allowlist = []
state_dir = "/tmp/foiled-test"

[[trusted_keys]]
id = "k1"
public_key = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
"#;

    fn build(runtime: &str) -> Result<SandboxRuntime, ConfigError> {
        let cfg = HostConfig::parse(&format!("sandbox_runtime = \"{runtime}\"\n{LAB}"))?;
        from_config(&cfg).map(|(kind, _)| kind)
    }

    #[test]
    fn startup_builds_only_the_runtime_that_was_named() {
        assert_eq!(build("docker"), Ok(SandboxRuntime::Docker));
        assert_eq!(build("fake"), Ok(SandboxRuntime::Fake));
        assert_eq!(
            build("firecracker"),
            Err(ConfigError::RuntimeNotBuiltIn(SandboxRuntime::Firecracker))
        );
        // No runtime named: the Firecracker default, which is refused rather
        // than quietly replaced by the recording runtime.
        let cfg = HostConfig::parse(LAB).unwrap();
        assert!(matches!(
            from_config(&cfg),
            Err(ConfigError::RuntimeNotBuiltIn(SandboxRuntime::Firecracker))
        ));
    }
}
