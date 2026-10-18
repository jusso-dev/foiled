//! Edge sensor end to end (#31): register, enrol with a key generated on
//! the sensor, place an emulation on it, lease and run it, buffer evidence
//! through an outage, replay it exactly once into the store, renew the
//! certificate, and revoke.
//!
//! The real API router is served over HTTP on loopback. A middleware stands
//! in for Cloudflare's WAF rule and the Worker's `tlsClientAuth` copy: it
//! attaches the fingerprint of the certificate the sensor last installed,
//! read from the sensor's own certificate file. No TLS, no network beyond
//! loopback and no real CA are involved (`FakeIssuer`).

use std::collections::HashSet;
use std::sync::{Arc, Mutex};

use axum::extract::Request;
use axum::middleware::{self, Next};
use foiled_api::auth::{ClientCert, sha256_hex};
use foiled_api::issuer::FakeIssuer;
use foiled_api::memory::MemoryStore;
use foiled_api::store::{Store, TokenRecord};
use foiled_api::{AppState, router};
use foiled_core::agent::{JobSigner, TrustedKeys};
use foiled_core::auth::{Role, Scope};
use foiled_core::capture::{CaptureEvent, SourceKind};
use foiled_core::decoy::DecoyState;
use foiled_core::enrolment::cert_fingerprint;
use foiled_hostd::agent::Agent;
use foiled_hostd::buffer::OfflineBuffer;
use foiled_hostd::client::{ClientError, ControlPlane};
use foiled_hostd::enrol::{self, IdentityFiles};
use foiled_hostd::gate::{JobGate, ReplayStore};
use foiled_hostd::runtime::FakeRuntime;

const NOW: i64 = 1_800_000_000_000;
const SECRET: &str = "0123456789abcdef0123456789abcdef";
const SEED: &str = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";

type Presented = Arc<Mutex<Option<String>>>;

async fn serve(state: AppState, presented: Presented) -> (String, tokio::task::JoinHandle<()>) {
    let app = router(state).layer(middleware::from_fn(move |mut req: Request, next: Next| {
        let presented = presented.clone();
        async move {
            let fp = presented.lock().unwrap().clone();
            if let Some(fp) = fp
                && !req.headers().contains_key("authorization")
            {
                req.extensions_mut().insert(ClientCert {
                    verified: true,
                    sha256: fp,
                });
            }
            next.run(req).await
        }
    }));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    (format!("http://{addr}"), handle)
}

fn state() -> (Arc<MemoryStore>, Arc<FakeIssuer>, AppState) {
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
    let issuer = Arc::new(FakeIssuer::new());
    let mut state = AppState::new(store.clone(), Arc::new(|| NOW));
    state.job_signer = Some(Arc::new(JobSigner::from_seed_hex("k1", SEED).unwrap()));
    state.cert_issuer = Some(issuer.clone());
    (store, issuer, state)
}

async fn operator(base: &str, path: &str, body: serde_json::Value) -> serde_json::Value {
    let res = reqwest::Client::new()
        .post(format!("{base}{path}"))
        .bearer_auth(format!("fo_admin1.{SECRET}"))
        .json(&body)
        .send()
        .await
        .unwrap();
    assert!(res.status().is_success(), "{path}: {}", res.status());
    res.json().await.unwrap()
}

fn event(decoy: &str, id: &str) -> CaptureEvent {
    serde_json::from_value(serde_json::json!({
        "event_id": id,
        "ts": NOW - 1000,
        "decoy_id": decoy,
        "catalogue_id": "emulator/redis/7.0",
        "decoy_kind": "emulation",
        "channel": "application",
        "severity": "info",
        "src": {"ip": "203.0.113.9"},
        "data": {"command": "CONFIG SET dir /var/spool/cron"}
    }))
    .unwrap()
}

fn present(presented: &Presented, files: &IdentityFiles) {
    let pem = std::fs::read_to_string(&files.cert).unwrap();
    *presented.lock().unwrap() = cert_fingerprint(&pem);
}

#[tokio::test]
async fn enrol_place_buffer_replay_renew_and_revoke() {
    let (store, issuer, state) = state();
    let presented: Presented = Arc::default();
    let (base, server) = serve(state.clone(), presented.clone()).await;
    let dir = tempfile::tempdir().unwrap();

    // 1. Register. The operator hands the token to the sensor out of band.
    let reg = operator(
        &base,
        "/v0/sensors",
        serde_json::json!({"label": "Branch office"}),
    )
    .await;
    let sensor_id = reg["agent"]["id"].as_str().unwrap().to_string();
    let token_file = dir.path().join("enrolment-token");
    std::fs::write(&token_file, reg["enrolment"]["token"].as_str().unwrap()).unwrap();

    // 2. Enrol: key generated here, CSR sent, token file gone afterwards.
    let files = IdentityFiles::new(
        dir.path().join("sensor.crt"),
        dir.path().join("sensor.key"),
        dir.path(),
    );
    let meta = enrol::enrol(&base, &token_file, &files, &sensor_id, Role::Sensor)
        .await
        .unwrap();
    assert_eq!((meta.tenant_id.as_str(), meta.role), ("t1", Role::Sensor));
    assert!(!token_file.exists(), "the token never stays on disk");
    assert!(
        std::fs::read_to_string(&files.key)
            .unwrap()
            .contains("PRIVATE KEY")
    );
    present(&presented, &files);
    assert_eq!(
        presented.lock().unwrap().as_deref(),
        Some(meta.cert_sha256.as_str())
    );

    // 3. Place an emulation on this sensor; the sensor leases and runs it.
    let placed = operator(
        &base,
        "/v0/decoys",
        serde_json::json!({"catalogue_id": "emulator/redis/7.0", "allow_draft": true, "sensor_id": sensor_id}),
    )
    .await;
    let decoy = placed["decoy"]["id"].as_str().unwrap().to_string();
    let mut keys = TrustedKeys::default();
    keys.add_hex(
        "k1",
        &JobSigner::from_seed_hex("k1", SEED)
            .unwrap()
            .public_key_hex(),
    )
    .unwrap();
    let mut agent = Agent {
        host_id: sensor_id.clone(),
        gate: JobGate {
            host_id: sensor_id.clone(),
            keys,
            allowlist: HashSet::from(["emulator:redis/redis-7.0".to_string()]),
            replays: ReplayStore::open(dir.path().join("replays.json")).unwrap(),
        },
        runtime: Arc::new(FakeRuntime::default()),
        cp: ControlPlane::new(&base, &sensor_id, None)
            .unwrap()
            .with_role(Role::Sensor),
        buffer: OfflineBuffer::open(dir.path().join("buffer"), 256 * 1024 * 1024).unwrap(),
        publicly_exposed: true,
        kvm_present: false,
        state_dir: dir.path().to_path_buf(),
        decoys: Default::default(),
    };
    assert_eq!(agent.run_jobs(NOW).await.unwrap().executed, 1);
    assert_eq!(store.decoy(&decoy).unwrap().state, DecoyState::Healthy);
    agent.heartbeat(NOW).await.unwrap();

    // 4. Network down: N events go to the on-disk buffer, nothing is lost.
    server.abort();
    let _ = server.await;
    const N: usize = 250;
    for i in 0..N {
        agent.capture(&event(&decoy, &format!("evt-{i}"))).unwrap();
        if i == 120 {
            // One event this sensor may not send (not its decoy).
            agent
                .capture(&event("someone-elses-decoy", "evt-bad"))
                .unwrap();
        }
    }
    assert!(matches!(
        agent.flush().await,
        Err(ClientError::Unavailable(_))
    ));
    assert_eq!(agent.buffer.len().unwrap(), N as u64 + 1);

    // 5. Network back: drain in batches. The bad event is dropped on its
    // own and counted; every good event arrives once, stamped as the sensor.
    let (base2, _server2) = serve(state.clone(), presented.clone()).await;
    agent.cp = ControlPlane::new(&base2, &sensor_id, None)
        .unwrap()
        .with_role(Role::Sensor);
    assert_eq!(agent.flush().await.unwrap(), N);
    assert!(agent.buffer.is_empty().unwrap());
    assert_eq!(agent.buffer.dropped(), 1);
    let queued = store.queued_events();
    let ids: HashSet<_> = queued.iter().map(|e| e.event_id.clone()).collect();
    assert_eq!(ids.len(), N);
    assert!(!ids.contains("evt-bad"));
    assert!(queued.iter().all(|e| {
        let s = e.source.as_ref().unwrap();
        s.kind == SourceKind::Sensor && s.id == sensor_id && e.tenant_id.as_deref() == Some("t1")
    }));

    // 6. A crash between send and local commit means a resend. Delivery is
    // at least once on the wire; the store keeps one copy per event_id.
    for i in 0..10 {
        agent.capture(&event(&decoy, &format!("evt-{i}"))).unwrap();
    }
    assert_eq!(agent.flush().await.unwrap(), 10);
    let stored = store
        .events_between("t1", 0, i64::MAX, 10_000)
        .await
        .unwrap();
    assert_eq!(stored.len(), N, "exactly once in the store");

    // 7. Renewal at two thirds of the certificate's life.
    let life = meta.expires_at - meta.issued_at;
    let renewed = enrol::renew_if_due(&agent.cp, &files, meta.issued_at + life / 2)
        .await
        .unwrap();
    assert!(renewed.is_none(), "not due yet");
    let renewed = enrol::renew_if_due(&agent.cp, &files, meta.issued_at + life * 2 / 3)
        .await
        .unwrap()
        .expect("due");
    assert_ne!(renewed.cert_sha256, meta.cert_sha256);
    present(&presented, &files);
    agent.heartbeat(NOW).await.unwrap();

    // 8. Revoke. Both certificates are revoked at the CA; the sensor's
    // buffered evidence is kept, not dropped, while it is locked out.
    operator(
        &base2,
        &format!("/v0/sensors/{sensor_id}:revoke"),
        serde_json::json!({"reason": {"code": "operator_manual", "text": "Decommissioned."}}),
    )
    .await;
    assert_eq!(issuer.revoked(), vec!["fake-1", "fake-2"]);
    agent.capture(&event(&decoy, "evt-after-revoke")).unwrap();
    let err = agent.flush().await.unwrap_err();
    assert!(err.is_identity_problem(), "{err}");
    assert_eq!(agent.buffer.len().unwrap(), 1);
    assert!(agent.run_jobs(NOW).await.is_err());
}
