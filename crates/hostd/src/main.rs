//! `foiled-hostd <path to hostd.toml>`

use std::collections::HashSet;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use foiled_core::agent::TrustedKeys;
use foiled_hostd::agent::Agent;
use foiled_hostd::buffer::OfflineBuffer;
use foiled_hostd::client::ControlPlane;
use foiled_hostd::config::HostConfig;
use foiled_hostd::gate::{JobGate, ReplayStore};
use foiled_hostd::runtime::FakeRuntime;

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
    let mut pem = std::fs::read(&cfg.client_cert).unwrap_or_else(|e| fail(e));
    pem.extend(std::fs::read(&cfg.client_key).unwrap_or_else(|e| fail(e)));
    let identity = reqwest::Identity::from_pem(&pem).unwrap_or_else(|e| fail(e));
    let cp =
        ControlPlane::new(&cfg.api_base, &cfg.host_id, Some(identity)).unwrap_or_else(|e| fail(e));

    std::fs::create_dir_all(&cfg.state_dir).unwrap_or_else(|e| fail(e));
    let gate = JobGate {
        host_id: cfg.host_id.clone(),
        keys,
        allowlist: cfg.allowlist.iter().cloned().collect::<HashSet<_>>(),
        replays: ReplayStore::open(cfg.state_dir.join("replays.json")).unwrap_or_else(|e| fail(e)),
    };
    let buffer = OfflineBuffer::open(cfg.state_dir.join("buffer"), cfg.buffer_max_bytes)
        .unwrap_or_else(|e| fail(e));
    // The Firecracker and module runtimes land with the runtime work (#3);
    // until then the agent runs the recording runtime so the control loop,
    // gate and evidence path can be exercised end to end.
    eprintln!("foiled-hostd: no production runtime configured yet, using the recording runtime");
    let mut agent = Agent {
        host_id: cfg.host_id.clone(),
        gate,
        runtime: Arc::new(FakeRuntime::default()),
        cp,
        buffer,
        publicly_exposed: cfg.publicly_exposed,
        kvm_present: std::path::Path::new("/dev/kvm").exists(),
        state_dir: cfg.state_dir.clone(),
    };

    let mut poll = tokio::time::interval(Duration::from_secs(cfg.poll_secs));
    let mut beat = tokio::time::interval(Duration::from_secs(cfg.heartbeat_secs));
    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => break,
            _ = poll.tick() => {
                if let Err(e) = agent.run_jobs(now_ms()).await { eprintln!("foiled-hostd: {e}"); }
                if let Err(e) = agent.flush().await { eprintln!("foiled-hostd: {e}"); }
            }
            _ = beat.tick() => {
                if let Err(e) = agent.heartbeat(now_ms()).await { eprintln!("foiled-hostd: {e}"); }
            }
        }
    }
}
