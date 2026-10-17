//! End to end: the real API router served over HTTP on loopback, and the
//! real agent leasing, verifying, executing and acknowledging jobs. The
//! server stands in for Cloudflare's mTLS check by attaching the host's
//! client certificate identity to every request that has no bearer token.

use std::collections::HashSet;
use std::sync::Arc;

use axum::extract::Request;
use axum::middleware::{self, Next};
use foiled_api::auth::{ClientCert, sha256_hex};
use foiled_api::memory::MemoryStore;
use foiled_api::store::{IdentityRecord, TokenRecord};
use foiled_api::{AppState, router};
use foiled_core::agent::{JobSigner, TrustedKeys};
use foiled_core::auth::{Role, Scope};
use foiled_core::capture::CaptureEvent;
use foiled_core::decoy::DecoyState;
use foiled_hostd::agent::Agent;
use foiled_hostd::buffer::OfflineBuffer;
use foiled_hostd::client::ControlPlane;
use foiled_hostd::gate::{JobGate, ReplayStore};
use foiled_hostd::runtime::{Call, FakeRuntime};

const NOW: i64 = 1_800_000_000_000;
const SECRET: &str = "0123456789abcdef0123456789abcdef";
const SEED: &str = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";

async fn mtls_stand_in(mut req: Request, next: Next) -> axum::response::Response {
    if !req.headers().contains_key("authorization") {
        req.extensions_mut().insert(ClientCert {
            verified: true,
            sha256: "01".repeat(32),
        });
    }
    next.run(req).await
}

async fn serve(state: AppState) -> (String, tokio::task::JoinHandle<()>) {
    let app = router(state).layer(middleware::from_fn(mtls_stand_in));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    (format!("http://{addr}"), handle)
}

fn control_plane_state() -> (Arc<MemoryStore>, AppState) {
    let store = Arc::new(MemoryStore::new());
    store.add_token(TokenRecord {
        id: "admin1".into(),
        tenant_id: "t1".into(),
        role: Role::Human,
        scopes: vec![Scope::Admin],
        secret_sha256: sha256_hex(SECRET),
        expires_at: None,
        revoked: false,
    });
    store.add_identity(IdentityRecord {
        id: "host-1".into(),
        tenant_id: "t1".into(),
        role: Role::Host,
        scopes: vec![Scope::HostLease, Scope::HostReport, Scope::HostIngest],
        cert_sha256: "01".repeat(32),
        revoked: false,
    });
    let mut state = AppState::new(store.clone(), Arc::new(|| NOW));
    state.job_signer = Some(Arc::new(JobSigner::from_seed_hex("k1", SEED).unwrap()));
    (store, state)
}

fn agent(base: &str, dir: &std::path::Path, allow: &[&str]) -> (Agent, Arc<FakeRuntime>) {
    let mut keys = TrustedKeys::default();
    keys.add_hex(
        "k1",
        &JobSigner::from_seed_hex("k1", SEED)
            .unwrap()
            .public_key_hex(),
    )
    .unwrap();
    let runtime = Arc::new(FakeRuntime::default());
    let agent = Agent {
        host_id: "host-1".into(),
        gate: JobGate {
            host_id: "host-1".into(),
            keys,
            allowlist: allow.iter().map(|s| s.to_string()).collect::<HashSet<_>>(),
            replays: ReplayStore::open(dir.join("replays.json")).unwrap(),
        },
        runtime: runtime.clone(),
        cp: ControlPlane::new(base, "host-1", None).unwrap(),
        buffer: OfflineBuffer::open(dir.join("buffer"), 1 << 30).unwrap(),
        publicly_exposed: true,
        kvm_present: false,
        state_dir: dir.to_path_buf(),
        decoys: Default::default(),
    };
    (agent, runtime)
}

async fn operator_create(base: &str, catalogue_id: &str) -> String {
    let res = reqwest::Client::new()
        .post(format!("{base}/v0/decoys"))
        .bearer_auth(format!("fo_admin1.{SECRET}"))
        .json(&serde_json::json!({"catalogue_id": catalogue_id, "allow_draft": true}))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 201);
    let body: serde_json::Value = res.json().await.unwrap();
    body["decoy"]["id"].as_str().unwrap().to_string()
}

#[tokio::test]
async fn operator_launch_reaches_a_healthy_decoy_through_the_agent() {
    let (store, state) = control_plane_state();
    let (base, _server) = serve(state).await;
    let dir = tempfile::tempdir().unwrap();
    let (mut agent, runtime) = agent(&base, dir.path(), &["emulator:redis/redis-7.0"]);

    let decoy = operator_create(&base, "emulator/redis/7.0").await;
    let report = agent.run_jobs(NOW).await.unwrap();
    assert_eq!(report.executed, 1);
    assert!(
        matches!(&runtime.calls()[0], Call::Create { artefact, .. } if artefact == "emulator:redis/redis-7.0")
    );
    let d = store.decoy(&decoy).unwrap();
    assert_eq!(d.state, DecoyState::Healthy);
    assert_eq!(d.host_id.as_deref(), Some("host-1"));

    agent.heartbeat(NOW + 250).await.unwrap();
    let (hb, skew) = store.heartbeat("t1", "host-1").unwrap();
    assert_eq!(skew, 250);
    assert_eq!(hb["running_decoys"][0], decoy);
}

#[tokio::test]
async fn unlisted_artefacts_are_refused_and_reported() {
    let (store, state) = control_plane_state();
    let (base, _server) = serve(state).await;
    let dir = tempfile::tempdir().unwrap();
    let (mut agent, runtime) = agent(&base, dir.path(), &[]);

    let decoy = operator_create(&base, "emulator/redis/7.0").await;
    let report = agent.run_jobs(NOW).await.unwrap();
    assert_eq!(report.rejected, 1);
    assert!(runtime.calls().is_empty(), "nothing ran");
    assert_eq!(store.decoy(&decoy).unwrap().state, DecoyState::Pending);
    let rec = store
        .audit()
        .into_iter()
        .find(|a| a.action == "job.ack")
        .unwrap();
    assert_eq!(rec.outcome, foiled_core::audit::Outcome::Denied);
    assert!(
        rec.detail["detail"]
            .as_str()
            .unwrap()
            .contains("allow-list")
    );
}

fn event(decoy: &str, i: u32) -> CaptureEvent {
    serde_json::from_value(serde_json::json!({
        "event_id": format!("evt-{i}"),
        "ts": NOW - 1000,
        "decoy_id": decoy,
        "catalogue_id": "emulator/redis/7.0",
        "decoy_kind": "emulation",
        "channel": "application",
        "severity": "info",
        "src": {"ip": "198.51.100.23"},
        "data": {"command": "INFO"}
    }))
    .unwrap()
}

#[tokio::test]
async fn evidence_buffers_through_an_outage_and_drains_once() {
    let (store, state) = control_plane_state();
    let (base, server) = serve(state.clone()).await;
    let dir = tempfile::tempdir().unwrap();
    let (mut agent, _rt) = agent(&base, dir.path(), &["emulator:redis/redis-7.0"]);
    let decoy = operator_create(&base, "emulator/redis/7.0").await;
    agent.run_jobs(NOW).await.unwrap();

    // Control plane goes away; events keep landing in the local buffer.
    server.abort();
    let _ = server.await;
    for i in 0..150 {
        agent.capture(&event(&decoy, i)).unwrap();
    }
    assert!(agent.flush().await.is_err());
    assert_eq!(agent.buffer.len().unwrap(), 150);

    // It comes back on a new port; the agent drains in batches of 100.
    let (base2, _server2) = serve(state).await;
    agent.cp = ControlPlane::new(&base2, "host-1", None).unwrap();
    assert_eq!(agent.flush().await.unwrap(), 150);
    assert!(agent.buffer.is_empty().unwrap());
    let queued = store.queued_events();
    assert_eq!(queued.len(), 150);
    let ids: HashSet<_> = queued.iter().map(|e| e.event_id.clone()).collect();
    assert_eq!(ids.len(), 150, "no duplicates past the idempotency key");
    assert!(
        queued
            .iter()
            .all(|e| e.source.as_ref().unwrap().id == "host-1")
    );
}
