//! ```text
//! foiled-hostd [run] <hostd.toml>                         run the agent
//! foiled-hostd enrol <hostd.toml> <token-file>            redeem an enrolment token (#31)
//! foiled-hostd verify-update <hostd.toml> <manifest.json> <artefact>
//!                                                         verify and stage a signed build
//! ```

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use foiled_core::agent::TrustedKeys;
use foiled_core::capture::CaptureEvent;
use foiled_hostd::agent::Agent;
use foiled_hostd::buffer::OfflineBuffer;
use foiled_hostd::client::ControlPlane;
use foiled_hostd::config::{HostConfig, SandboxRuntime};
use foiled_hostd::docker::{DockerRuntime, container_name};
use foiled_hostd::enrol::IdentityFiles;
use foiled_hostd::gate::{JobGate, ReplayStore};
use foiled_hostd::logcapture::line_to_event;
use foiled_hostd::runtime::{FakeRuntime, Runtime};
use foiled_hostd::update;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::sync::mpsc;

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

fn fail(msg: impl std::fmt::Display) -> ! {
    eprintln!("foiled-hostd: {msg}");
    std::process::exit(1)
}

/// Follow a Docker decoy's stdout and turn its JSON log lines into envelopes.
fn follow_docker_logs(
    decoy_id: String,
    params: foiled_core::agent::DecoyParams,
    tx: mpsc::UnboundedSender<CaptureEvent>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let child = tokio::process::Command::new("docker")
            .args(["logs", "--follow", &container_name(&decoy_id)])
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null())
            .kill_on_drop(true)
            .spawn();
        let Ok(mut child) = child else { return };
        let Some(out) = child.stdout.take() else {
            return;
        };
        let mut lines = BufReader::new(out).lines();
        while let Ok(Some(line)) = lines.next_line().await {
            if let Some(e) = line_to_event(&decoy_id, &params, &line)
                && tx.send(e).is_err()
            {
                break;
            }
        }
    })
}

fn load_config(path: &str) -> HostConfig {
    let text = std::fs::read_to_string(path).unwrap_or_else(|e| fail(format!("{path}: {e}")));
    HostConfig::parse(&text).unwrap_or_else(|e| fail(e))
}

fn identity_files(cfg: &HostConfig) -> Option<IdentityFiles> {
    match (&cfg.client_cert, &cfg.client_key) {
        (Some(cert), Some(key)) => Some(IdentityFiles::new(
            cert.clone(),
            key.clone(),
            &cfg.state_dir,
        )),
        _ => None,
    }
}

fn control_plane(cfg: &HostConfig) -> ControlPlane {
    let identity = identity_files(cfg).map(|files| {
        let mut pem = std::fs::read(&files.cert).unwrap_or_else(|e| fail(e));
        pem.extend(std::fs::read(&files.key).unwrap_or_else(|e| fail(e)));
        reqwest::Identity::from_pem(&pem).unwrap_or_else(|e| fail(e))
    });
    // `None` only for a loopback lab mock (validated in config).
    ControlPlane::new(&cfg.api_base, &cfg.host_id, identity)
        .unwrap_or_else(|e| fail(e))
        .with_role(cfg.role)
}

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let arg = |i: usize| -> &str {
        args.get(i)
            .map(String::as_str)
            .unwrap_or_else(|| fail("missing argument; see the usage in the docs"))
    };
    match args.first().map(String::as_str) {
        Some("enrol") => {
            let cfg = load_config(arg(1));
            let files = identity_files(&cfg)
                .unwrap_or_else(|| fail("client_cert and client_key must be set to enrol"));
            std::fs::create_dir_all(&cfg.state_dir).unwrap_or_else(|e| fail(e));
            let meta = foiled_hostd::enrol::enrol(
                &cfg.api_base,
                std::path::Path::new(arg(2)),
                &files,
                &cfg.host_id,
                cfg.role,
            )
            .await
            .unwrap_or_else(|e| fail(e));
            println!(
                "enrolled {} {} in tenant {}; certificate {} expires at {}",
                meta.role.as_str(),
                meta.agent_id,
                meta.tenant_id,
                meta.cert_sha256,
                meta.expires_at
            );
        }
        Some("verify-update") => {
            let cfg = load_config(arg(1));
            let mut keys = TrustedKeys::default();
            for k in &cfg.release_keys {
                keys.add_hex(&k.id, &k.public_key)
                    .unwrap_or_else(|e| fail(e));
            }
            let manifest = std::fs::read_to_string(arg(2)).unwrap_or_else(|e| fail(e));
            let target = update::current_target()
                .unwrap_or_else(|| fail(update::UpdateError::UnknownTarget));
            let staged = update::stage_update(
                &keys,
                &manifest,
                std::path::Path::new(arg(3)),
                &target,
                env!("CARGO_PKG_VERSION"),
                &cfg.state_dir,
            )
            .unwrap_or_else(|e| fail(e));
            println!("verified and staged {}", staged.display());
        }
        Some("run") => run(load_config(arg(1))).await,
        Some(path) => run(load_config(path)).await,
        None => run(load_config("/etc/foiled/hostd.toml")).await,
    }
}

async fn run(cfg: HostConfig) {
    let mut keys = TrustedKeys::default();
    for k in &cfg.trusted_keys {
        keys.add_hex(&k.id, &k.public_key)
            .unwrap_or_else(|e| fail(e));
    }
    std::fs::create_dir_all(&cfg.state_dir).unwrap_or_else(|e| fail(e));
    let files = identity_files(&cfg);
    if let Some(files) = &files {
        foiled_hostd::enrol::recover(files).unwrap_or_else(|e| fail(e));
    }
    let cp = control_plane(&cfg);
    let gate = JobGate {
        host_id: cfg.host_id.clone(),
        keys,
        allowlist: cfg.allowlist.iter().cloned().collect::<HashSet<_>>(),
        replays: ReplayStore::open(cfg.state_dir.join("replays.json")).unwrap_or_else(|e| fail(e)),
    };
    let buffer = OfflineBuffer::open(cfg.state_dir.join("buffer"), cfg.buffer_cap())
        .unwrap_or_else(|e| fail(e));
    let docker = cfg.sandbox_runtime == SandboxRuntime::Docker;
    let runtime: Arc<dyn Runtime> = if docker {
        Arc::new(DockerRuntime::new(cfg.docker.clone()))
    } else {
        // The Firecracker and module drivers land with the runtime work (#3).
        eprintln!(
            "foiled-hostd: Firecracker driver not available yet, using the recording runtime"
        );
        Arc::new(FakeRuntime::default())
    };
    let mut agent = Agent {
        host_id: cfg.host_id.clone(),
        gate,
        runtime,
        cp,
        buffer,
        publicly_exposed: cfg.publicly_exposed,
        kvm_present: std::path::Path::new("/dev/kvm").exists(),
        state_dir: cfg.state_dir.clone(),
        decoys: HashMap::new(),
    };

    let (tx, mut rx) = mpsc::unbounded_channel();
    let mut followers: HashMap<String, tokio::task::JoinHandle<()>> = HashMap::new();
    let mut poll = tokio::time::interval(Duration::from_secs(cfg.poll_secs));
    let mut beat = tokio::time::interval(Duration::from_secs(cfg.heartbeat_secs));
    let mut renewal = tokio::time::interval(Duration::from_secs(3600));
    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => break,
            Some(event) = rx.recv() => {
                if let Err(e) = agent.capture(&event) { eprintln!("foiled-hostd: buffer: {e}"); }
            }
            _ = poll.tick() => {
                if let Err(e) = agent.run_jobs(now_ms()).await { eprintln!("foiled-hostd: {e}"); }
                if docker {
                    // Drop followers for decoys that are gone, and for streams that
                    // ended (a rotation replaces the container).
                    followers.retain(|id, h| {
                        let keep = agent.decoys.contains_key(id) && !h.is_finished();
                        if !keep {
                            h.abort();
                        }
                        keep
                    });
                    for (id, params) in &agent.decoys {
                        followers.entry(id.clone()).or_insert_with(|| {
                            follow_docker_logs(id.clone(), params.clone(), tx.clone())
                        });
                    }
                }
                if let Err(e) = agent.flush().await { eprintln!("foiled-hostd: {e}"); }
            }
            _ = beat.tick() => {
                if let Err(e) = agent.heartbeat(now_ms()).await { eprintln!("foiled-hostd: {e}"); }
            }
            _ = renewal.tick() => {
                // Renew at two thirds of the certificate's life, then reconnect
                // with the new identity. The old one works for 24 hours more.
                if let Some(files) = &files {
                    match foiled_hostd::enrol::renew_if_due(&agent.cp, files, now_ms()).await {
                        Ok(Some(meta)) => {
                            eprintln!("foiled-hostd: renewed certificate {}", meta.cert_sha256);
                            agent.cp = control_plane(&cfg);
                        }
                        Ok(None) => {}
                        Err(e) => eprintln!("foiled-hostd: {e}"),
                    }
                }
            }
        }
    }
}
