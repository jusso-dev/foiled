//! Docker lab runtime (ADR 0002). For local labs and the MVP walkthrough
//! only: the config refuses it on a publicly exposed host, and it binds
//! published ports to a lab address (loopback by default).
//!
//! Every decoy runs with a read-only root, all capabilities dropped,
//! `no-new-privileges`, PID, memory and CPU limits, tmpfs for the paths the
//! image needs to write, on a dedicated bridge network whose new outbound
//! connections the operator drops in `DOCKER-USER` (see
//! `docs/mvp-walkthrough.md`). Images are run by digest only.

use std::process::Command;
use std::sync::Mutex;

use serde::Deserialize;

use crate::runtime::{DecoySpec, ExecMeta, RtResult, Runtime, RuntimeError, SnapshotKind};

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DockerConfig {
    /// Bridge network created by the operator (for example `foiled-lab`).
    #[serde(default = "default_network")]
    pub network: String,
    /// Address published ports bind to. Loopback unless the lab says otherwise.
    #[serde(default = "default_bind")]
    pub bind: String,
    /// Paths inside decoys that get a small tmpfs, since the root is read-only.
    #[serde(default = "default_writable")]
    pub writable: Vec<String>,
    #[serde(default = "default_memory")]
    pub memory: String,
    #[serde(default = "default_pids")]
    pub pids_limit: u32,
}

fn default_network() -> String {
    "foiled-lab".into()
}
fn default_bind() -> String {
    "127.0.0.1".into()
}
fn default_writable() -> Vec<String> {
    vec!["/tmp".into()]
}
fn default_memory() -> String {
    "256m".into()
}
fn default_pids() -> u32 {
    256
}

impl Default for DockerConfig {
    fn default() -> Self {
        DockerConfig {
            network: default_network(),
            bind: default_bind(),
            writable: default_writable(),
            memory: default_memory(),
            pids_limit: default_pids(),
        }
    }
}

pub fn container_name(decoy_id: &str) -> String {
    format!("foiled-{decoy_id}")
}

/// Arguments for `docker run`. Pure, so the hardening is unit tested.
pub fn run_args(cfg: &DockerConfig, spec: &DecoySpec) -> Result<Vec<String>, RuntimeError> {
    let image = spec
        .params
        .image
        .clone()
        .ok_or_else(|| RuntimeError("sandbox job has no image reference".into()))?;
    let digest = image
        .split_once('@')
        .map(|(_, d)| d.to_string())
        .ok_or_else(|| RuntimeError("image is not pinned by digest".into()))?;
    if spec.params.artefact.as_deref() != Some(digest.as_str()) {
        return Err(RuntimeError(
            "image digest does not match the allow-listed artefact".into(),
        ));
    }
    let id = &spec.decoy_id;
    let mut a: Vec<String> = [
        "run",
        "--detach",
        "--name",
        &container_name(id),
        "--read-only",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges",
        "--pids-limit",
        &cfg.pids_limit.to_string(),
        "--memory",
        &cfg.memory,
        "--cpus",
        "1",
        "--network",
        &cfg.network,
        "--restart",
        "no",
        "--label",
        &format!("foiled.decoy={id}"),
        "--label",
        &format!("foiled.generation={}", spec.params.generation),
        "--label",
        &format!("foiled.catalogue={}", spec.params.catalogue_id),
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();
    for path in &cfg.writable {
        a.push("--tmpfs".into());
        // Sticky world-writable like /tmp: images run as a non-root user.
        a.push(format!("{path}:rw,noexec,nosuid,size=64m,mode=1777"));
    }
    for p in &spec.params.listen_ports {
        let proto = match p.protocol {
            foiled_core::catalogue::Protocol::Tcp => "tcp",
            foiled_core::catalogue::Protocol::Udp => "udp",
        };
        a.push("--publish".into());
        a.push(format!("{}:{}:{}/{proto}", cfg.bind, p.port, p.port));
    }
    a.push(image);
    Ok(a)
}

pub struct DockerRuntime {
    pub cfg: DockerConfig,
    running: Mutex<Vec<String>>,
}

impl DockerRuntime {
    pub fn new(cfg: DockerConfig) -> Self {
        DockerRuntime {
            cfg,
            running: Mutex::new(Vec::new()),
        }
    }

    fn docker(&self, args: &[String]) -> RtResult<String> {
        let out = Command::new("docker")
            .args(args)
            .output()
            .map_err(|e| RuntimeError(format!("docker: {e}")))?;
        if out.status.success() {
            Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
        } else {
            Err(RuntimeError(format!(
                "docker {}: {}",
                args.first().map(String::as_str).unwrap_or(""),
                String::from_utf8_lossy(&out.stderr).trim()
            )))
        }
    }
}

impl Runtime for DockerRuntime {
    fn create(&self, spec: &DecoySpec) -> RtResult<ExecMeta> {
        let args = run_args(&self.cfg, spec)?;
        let cid = self.docker(&args)?;
        // `docker run --detach` both creates and starts; start() is a no-op.
        self.running.lock().unwrap().push(spec.decoy_id.clone());
        Ok(ExecMeta {
            listen_addrs: spec
                .params
                .listen_ports
                .iter()
                .map(|p| format!("{}:{}", self.cfg.bind, p.port))
                .collect(),
            pid_or_cid: cid,
            artefact: spec.params.artefact.clone().unwrap_or_default(),
        })
    }

    fn start(&self, decoy_id: &str) -> RtResult<()> {
        // `docker run --detach` already started it. Report healthy only if
        // the container is still running a few seconds later, so a decoy
        // that crashes on start is reported as failed.
        for _ in 0..3 {
            std::thread::sleep(std::time::Duration::from_secs(1));
            let state = self.docker(&[
                "inspect".into(),
                "--format".into(),
                "{{.State.Running}}".into(),
                container_name(decoy_id),
            ])?;
            if state != "true" {
                return Err(RuntimeError("container exited during start".into()));
            }
        }
        Ok(())
    }

    fn stop(&self, decoy_id: &str) -> RtResult<()> {
        // Disconnect first so the guest loses the network before anything else.
        let _ = self.docker(&[
            "network".into(),
            "disconnect".into(),
            "--force".into(),
            self.cfg.network.clone(),
            container_name(decoy_id),
        ]);
        self.docker(&["kill".into(), container_name(decoy_id)])
            .or_else(|e| {
                if e.0.contains("is not running") || e.0.contains("No such container") {
                    Ok(String::new())
                } else {
                    Err(e)
                }
            })?;
        self.running.lock().unwrap().retain(|d| d != decoy_id);
        Ok(())
    }

    fn destroy(&self, decoy_id: &str) -> RtResult<()> {
        self.docker(&["rm".into(), "--force".into(), container_name(decoy_id)])
            .map(|_| ())
    }

    fn snapshot(&self, decoy_id: &str, _kind: SnapshotKind) -> RtResult<String> {
        // `docker diff` lists changed paths; full export is left to the
        // forensics tooling, never booted.
        self.docker(&["diff".into(), container_name(decoy_id)])
    }

    fn capture_flush(&self, _decoy_id: &str) -> RtResult<()> {
        // Log capture streams continuously (see `logcapture`); nothing buffered here.
        Ok(())
    }

    fn running(&self) -> Vec<String> {
        self.running.lock().unwrap().clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use foiled_core::agent::DecoyParams;
    use foiled_core::catalogue::{DecoyKind, ListenPort, Protocol};

    fn spec(image: Option<&str>, artefact: Option<&str>) -> DecoySpec {
        DecoySpec {
            decoy_id: "d1".into(),
            params: DecoyParams {
                catalogue_id: "foiled/demo-app/1.0.0".into(),
                decoy_kind: DecoyKind::Sandbox,
                generation: 3,
                artefact: artefact.map(str::to_string),
                image: image.map(str::to_string),
                listen_ports: vec![ListenPort {
                    port: 8080,
                    protocol: Protocol::Tcp,
                    service: "http".into(),
                    tls: None,
                }],
                hard_deadline: 0,
            },
        }
    }

    fn digest() -> String {
        format!("sha256:{}", "a".repeat(64))
    }

    #[test]
    fn runs_hardened_and_by_digest() {
        let image = format!("localhost:5000/foiled-demo-app@{}", digest());
        let cfg = DockerConfig {
            writable: vec!["/tmp".into(), "/srv/demo-app".into()],
            ..DockerConfig::default()
        };
        let a = run_args(&cfg, &spec(Some(&image), Some(&digest()))).unwrap();
        let joined = a.join(" ");
        for flag in [
            "--read-only",
            "--cap-drop ALL",
            "--security-opt no-new-privileges",
            "--pids-limit 256",
            "--memory 256m",
            "--network foiled-lab",
            "--restart no",
            "--publish 127.0.0.1:8080:8080/tcp",
            "--tmpfs /srv/demo-app:rw,noexec,nosuid,size=64m,mode=1777",
            "--label foiled.generation=3",
        ] {
            assert!(joined.contains(flag), "missing {flag}: {joined}");
        }
        assert!(!joined.contains("--privileged"));
        assert!(!joined.contains("--network host"));
        assert_eq!(a.last().unwrap(), &image, "image comes last, by digest");
    }

    #[test]
    fn refuses_unpinned_or_mismatched_images() {
        let cfg = DockerConfig::default();
        assert!(run_args(&cfg, &spec(None, Some(&digest()))).is_err());
        assert!(run_args(&cfg, &spec(Some("foiled-demo-app:latest"), Some(&digest()))).is_err());
        let other = format!("r/x@sha256:{}", "b".repeat(64));
        assert!(run_args(&cfg, &spec(Some(&other), Some(&digest()))).is_err());
    }
}
