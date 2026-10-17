//! Host agent channel: leasing signed jobs, acknowledging results, heartbeats.

use std::sync::Arc;

use axum::body::Body;
use foiled_api::auth::{ClientCert, sha256_hex};
use foiled_api::memory::MemoryStore;
use foiled_api::store::{IdentityRecord, TokenRecord};
use foiled_api::{AppState, router};
use foiled_core::agent::{JobKind, JobSigner, SignedJob, TrustedKeys};
use foiled_core::auth::{Role, Scope};
use foiled_core::decoy::DecoyState;
use http::{Request, StatusCode};
use http_body_util::BodyExt;
use serde_json::{Value, json};
use tower::ServiceExt;

const NOW: i64 = 1_800_000_000_000;
const SECRET: &str = "0123456789abcdef0123456789abcdef";
const SEED: &str = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";

struct H {
    store: Arc<MemoryStore>,
    state: AppState,
}

fn cert(n: u8) -> String {
    format!("{n:02x}").repeat(32)
}

fn harness(signing: bool) -> H {
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
    for (n, id) in [(1u8, "host-1"), (2, "host-2")] {
        store.add_identity(IdentityRecord {
            id: id.into(),
            tenant_id: "t1".into(),
            role: Role::Host,
            scopes: vec![Scope::HostLease, Scope::HostReport],
            cert_sha256: cert(n),
            revoked: false,
        });
    }
    let mut state = AppState::new(store.clone(), Arc::new(|| NOW));
    if signing {
        state.job_signer = Some(Arc::new(JobSigner::from_seed_hex("k1", SEED).unwrap()));
    }
    H { store, state }
}

async fn send(h: &H, req: Request<Body>) -> (StatusCode, Value) {
    let res = router(h.state.clone()).oneshot(req).await.unwrap();
    let status = res.status();
    let bytes = res.into_body().collect().await.unwrap().to_bytes();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

async fn operator(h: &H, path: &str, body: Value) -> (StatusCode, Value) {
    let req = Request::post(path)
        .header("authorization", format!("Bearer fo_admin1.{SECRET}"))
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .unwrap();
    send(h, req).await
}

async fn host(h: &H, n: u8, path: &str, body: Value) -> (StatusCode, Value) {
    let mut req = Request::post(path)
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .unwrap();
    req.extensions_mut().insert(ClientCert {
        verified: true,
        sha256: cert(n),
    });
    send(h, req).await
}

fn keys() -> TrustedKeys {
    let mut k = TrustedKeys::default();
    let signer = JobSigner::from_seed_hex("k1", SEED).unwrap();
    k.add_hex("k1", &signer.public_key_hex()).unwrap();
    k
}

async fn create_redis(h: &H) -> String {
    let (s, b) = operator(
        h,
        "/v0/decoys",
        json!({"catalogue_id": "emulator/redis/7.0", "allow_draft": true}),
    )
    .await;
    assert_eq!(s, StatusCode::CREATED, "{b}");
    b["decoy"]["id"].as_str().unwrap().to_string()
}

async fn lease(h: &H, n: u8, host_id: &str) -> Vec<SignedJob> {
    let (s, b) = host(h, n, &format!("/v0/hosts/{host_id}/jobs:lease"), json!({})).await;
    assert_eq!(s, StatusCode::OK, "{b}");
    serde_json::from_value(b["jobs"].clone()).unwrap()
}

#[tokio::test]
async fn leasing_needs_a_signing_key() {
    let h = harness(false);
    let (s, b) = host(&h, 1, "/v0/hosts/host-1/jobs:lease", json!({})).await;
    assert_eq!(s, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(b["error"]["code"], "signing_disabled");
}

#[tokio::test]
async fn hosts_lease_signed_jobs_once_and_only_as_themselves() {
    let h = harness(true);
    let decoy = create_redis(&h).await;

    let (s, b) = host(&h, 2, "/v0/hosts/host-1/jobs:lease", json!({})).await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    assert_eq!(b["error"]["code"], "wrong_host");

    let jobs = lease(&h, 1, "host-1").await;
    assert_eq!(jobs.len(), 1);
    let body = keys().verify(&jobs[0]).expect("signature verifies");
    assert_eq!(body.kind, JobKind::DecoyCreate);
    assert_eq!(body.host_id, "host-1");
    assert_eq!(body.decoy_id, decoy);
    let params = body.decoy.expect("create jobs carry run parameters");
    assert_eq!(params.artefact.as_deref(), Some("emulator:redis/redis-7.0"));
    assert_eq!(params.generation, 1);
    assert_eq!(
        h.store.decoy(&decoy).unwrap().host_id.as_deref(),
        Some("host-1")
    );

    assert!(
        lease(&h, 1, "host-1").await.is_empty(),
        "leased job is held"
    );
    assert!(lease(&h, 2, "host-2").await.is_empty(), "placed on host-1");
}

#[tokio::test]
async fn acks_move_the_decoy_through_allowed_states_and_are_audited() {
    let h = harness(true);
    let decoy = create_redis(&h).await;
    let job = keys().verify(&lease(&h, 1, "host-1").await[0]).unwrap();
    let ack = format!("/v0/hosts/host-1/jobs/{}:ack", job.job_id);

    let (s, _) = host(
        &h,
        2,
        &format!("/v0/hosts/host-2/jobs/{}:ack", job.job_id),
        json!({"job_id": job.job_id, "outcome": "succeeded", "decoy_state": "healthy"}),
    )
    .await;
    assert_eq!(s, StatusCode::CONFLICT, "only the leasing host can ack");

    let ok = json!({"job_id": job.job_id, "outcome": "succeeded", "decoy_state": "healthy"});
    let (s, b) = host(&h, 1, &ack, ok.clone()).await;
    assert_eq!(s, StatusCode::NO_CONTENT, "{b}");
    assert_eq!(h.store.decoy(&decoy).unwrap().state, DecoyState::Healthy);
    let rec = h
        .store
        .audit()
        .into_iter()
        .find(|a| a.action == "job.ack")
        .unwrap();
    assert_eq!(rec.actor_id, "host-1");
    assert_eq!(rec.detail["decoy_state"], "healthy");

    let (s, _) = host(&h, 1, &ack, ok).await;
    assert_eq!(s, StatusCode::CONFLICT, "acks are not replayable");
}

#[tokio::test]
async fn a_rotation_rebuilds_and_bumps_the_generation() {
    let h = harness(true);
    let decoy = create_redis(&h).await;
    let create = keys().verify(&lease(&h, 1, "host-1").await[0]).unwrap();
    host(
        &h,
        1,
        &format!("/v0/hosts/host-1/jobs/{}:ack", create.job_id),
        json!({"job_id": create.job_id, "outcome": "succeeded", "decoy_state": "healthy"}),
    )
    .await;

    let reason = json!({"reason": {"code": "max_lifetime", "text": "scheduled"}});
    let (s, _) = operator(&h, &format!("/v0/decoys/{decoy}:rotate"), reason).await;
    assert_eq!(s, StatusCode::ACCEPTED);
    let rotate = keys().verify(&lease(&h, 1, "host-1").await[0]).unwrap();
    assert_eq!(rotate.kind, JobKind::DecoyRotate);
    assert_eq!(rotate.reason.unwrap().text, "scheduled");
    let (s, _) = host(
        &h,
        1,
        &format!("/v0/hosts/host-1/jobs/{}:ack", rotate.job_id),
        json!({"job_id": rotate.job_id, "outcome": "succeeded", "decoy_state": "healthy"}),
    )
    .await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    let d = h.store.decoy(&decoy).unwrap();
    assert_eq!(d.state, DecoyState::Healthy);
    assert_eq!(d.generation, 2);
}

#[tokio::test]
async fn impossible_reported_states_are_refused() {
    let h = harness(true);
    let decoy = create_redis(&h).await;
    let job = keys().verify(&lease(&h, 1, "host-1").await[0]).unwrap();
    // Straight from pending to quarantined is fine (pending -> ... ) only if reachable;
    // destroyed decoys can never come back.
    h.store.set_state(&decoy, DecoyState::Destroyed);
    let (s, b) = host(
        &h,
        1,
        &format!("/v0/hosts/host-1/jobs/{}:ack", job.job_id),
        json!({"job_id": job.job_id, "outcome": "succeeded", "decoy_state": "healthy"}),
    )
    .await;
    assert_eq!(s, StatusCode::CONFLICT, "{b}");
    assert_eq!(h.store.decoy(&decoy).unwrap().state, DecoyState::Destroyed);
}

#[tokio::test]
async fn rejected_jobs_are_audited_as_denied() {
    let h = harness(true);
    create_redis(&h).await;
    let job = keys().verify(&lease(&h, 1, "host-1").await[0]).unwrap();
    let (s, _) = host(&h, 1, &format!("/v0/hosts/host-1/jobs/{}:ack", job.job_id),
        json!({"job_id": job.job_id, "outcome": "rejected", "detail": "artefact not on allow-list"})).await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    let rec = h
        .store
        .audit()
        .into_iter()
        .find(|a| a.action == "job.ack")
        .unwrap();
    assert_eq!(rec.outcome, foiled_core::audit::Outcome::Denied);
}

#[tokio::test]
async fn heartbeats_record_clock_skew_for_the_calling_host_only() {
    let h = harness(true);
    let hb = |id: &str| {
        json!({
            "host_id": id, "agent_version": "0.1.0", "kvm_present": true, "publicly_exposed": true,
            "free_disk_bytes": 1_000_000u64, "running_decoys": [], "host_time": NOW + 1500,
            "buffered_events": 0, "dropped_events": 0
        })
    };
    let (s, _) = host(&h, 1, "/v0/hosts/host-1/heartbeat", hb("host-1")).await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    let (_, skew) = h.store.heartbeat("t1", "host-1").unwrap();
    assert_eq!(skew, 1500);
    let (s, _) = host(&h, 1, "/v0/hosts/host-1/heartbeat", hb("host-2")).await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    let (s, _) = host(&h, 1, "/v0/hosts/host-2/heartbeat", hb("host-2")).await;
    assert_eq!(s, StatusCode::FORBIDDEN);
}
