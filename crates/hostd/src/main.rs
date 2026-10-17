//! `foiled-hostd <path to hostd.toml>`

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
use foiled_hostd::gate::{JobGate, ReplayStore};
use foiled_hostd::logcapture::line_to_event;
use foiled_hostd::runtime::{FakeRuntime, Runtime};
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

#[tokio::main]
async fn main() {
    let path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "/etc/foiled/hostd.toml".into());
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| fail(format!("{path}: {e}")));
    let cfg = HostConfig::parse(&text).unwrap_or_else(|e| fail(e));

    let mut keys = TrustedKeys::default();
    for k in &cfg.trusted_keys {
        keys.add_hex(&k.id, &k.public_key)
            .unwrap_or_else(|e| fail(e));
    }
    let identity = match (&cfg.client_cert, &cfg.client_key) {
        (Some(cert), Some(key)) => {
            let mut pem = std::fs::read(cert).unwrap_or_else(|e| fail(e));
            pem.extend(std::fs::read(key).unwrap_or_else(|e| fail(e)));
            Some(reqwest::Identity::from_pem(&pem).unwrap_or_else(|e| fail(e)))
        }
        // Only reachable for a loopback lab mock (validated in config).
        _ => None,
    };
    let cp = ControlPlane::new(&cfg.api_base, &cfg.host_id, identity).unwrap_or_else(|e| fail(e));
    run(cfg, keys, cp).await;
}

async fn run(cfg: HostConfig, keys: TrustedKeys, cp: ControlPlane) {
    std::fs::create_dir_all(&cfg.state_dir).unwrap_or_else(|e| fail(e));
    let gate = JobGate {
        host_id: cfg.host_id.clone(),
        keys,
        allowlist: cfg.allowlist.iter().cloned().collect::<HashSet<_>>(),
        replays: ReplayStore::open(cfg.state_dir.join("replays.json")).unwrap_or_else(|e| fail(e)),
    };
    let buffer = OfflineBuffer::open(cfg.state_dir.join("buffer"), cfg.buffer_max_bytes)
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
        }
    }
}
