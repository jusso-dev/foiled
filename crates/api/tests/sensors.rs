//! Edge sensor enrolment, mTLS identity, rotation, revocation and tenancy
//! (#31). These are the API tests sketched in `docs/deploy/edge-sensor.md`:
//! a sensor certificate can only ever act as that sensor, in its tenant.

use std::sync::Arc;
use std::sync::atomic::{AtomicI64, Ordering};

use axum::body::Body;
use foiled_api::auth::{ClientCert, ClientMeta, sha256_hex};
use foiled_api::issuer::FakeIssuer;
use foiled_api::memory::MemoryStore;
use foiled_api::store::TokenRecord;
use foiled_api::{AppState, router};
use foiled_core::agent::{JobSigner, SignedJob, TrustedKeys};
use foiled_core::auth::{Role, Scope};
use foiled_core::capture::SourceKind;
use foiled_core::enrolment::RENEWAL_GRACE_MS;
use http::{Request, StatusCode};
use http_body_util::BodyExt;
use serde_json::{Value, json};
use tower::ServiceExt;

const NOW: i64 = 1_800_000_000_000;
const SECRET: &str = "0123456789abcdef0123456789abcdef";
const SEED: &str = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";

struct H {
    store: Arc<MemoryStore>,
    issuer: Arc<FakeIssuer>,
    state: AppState,
    clock: Arc<AtomicI64>,
}

fn csr() -> String {
    let v: Value = serde_json::from_str(include_str!(
        "../../../testdata/agent/enrol/requests/sensor.json"
    ))
    .unwrap();
    v["csr_pem"].as_str().unwrap().to_string()
}

fn harness_with(issuer: bool) -> H {
    let store = Arc::new(MemoryStore::new());
    for (id, tenant, scopes) in [
        ("admin1", "t1", vec![Scope::Admin]),
        ("admin2", "t2", vec![Scope::Admin]),
        ("reader1", "t1", vec![Scope::SensorsRead]),
    ] {
        store.add_token(TokenRecord {
            id: id.into(),
            tenant_id: tenant.into(),
            role: Role::Human,
            scopes,
            secret_sha256: sha256_hex(SECRET),
            expires_at: None,
            revoked: false,
        });
    }
    let clock = Arc::new(AtomicI64::new(NOW));
    let c = clock.clone();
    let mut state = AppState::new(store.clone(), Arc::new(move || c.load(Ordering::SeqCst)));
    state.job_signer = Some(Arc::new(JobSigner::from_seed_hex("k1", SEED).unwrap()));
    let fake = Arc::new(FakeIssuer::new());
    if issuer {
        state.cert_issuer = Some(fake.clone());
    }
    H {
        store,
        issuer: fake,
        state,
        clock,
    }
}

fn harness() -> H {
    harness_with(true)
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

async fn operator(h: &H, who: &str, method: &str, path: &str, body: Value) -> (StatusCode, Value) {
    let req = Request::builder()
        .method(method)
        .uri(path)
        .header("authorization", format!("Bearer fo_{who}.{SECRET}"))
        .header("content-type", "application/json")
        .body(Body::from(if body.is_null() {
            String::new()
        } else {
            body.to_string()
        }))
        .unwrap();
    send(h, req).await
}

/// A request as the Worker would pass it on after the WAF rule: the
/// verified certificate fingerprint and where it came from.
async fn as_cert(
    h: &H,
    fp: &str,
    ip: &str,
    asn: u32,
    path: &str,
    body: Value,
) -> (StatusCode, Value) {
    let mut req = Request::post(path)
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .unwrap();
    req.extensions_mut().insert(ClientCert {
        verified: true,
        sha256: fp.to_string(),
    });
    req.extensions_mut().insert(ClientMeta {
        ip: Some(ip.into()),
        asn: Some(asn),
    });
    send(h, req).await
}

async fn cert(h: &H, fp: &str, path: &str, body: Value) -> (StatusCode, Value) {
    as_cert(h, fp, "198.51.100.20", 64500, path, body).await
}

async fn enrol_raw(h: &H, token: &str, csr_pem: &str) -> (StatusCode, Value) {
    let mut req = Request::post("/v0/enrol")
        .header("content-type", "application/json")
        .body(Body::from(
            json!({"token": token, "csr_pem": csr_pem}).to_string(),
        ))
        .unwrap();
    req.extensions_mut().insert(ClientMeta {
        ip: Some("198.51.100.20".into()),
        asn: Some(64500),
    });
    send(h, req).await
}

/// Register a sensor as `admin`; returns (sensor id, token).
async fn register(h: &H, admin: &str, body: Value) -> (String, String) {
    let (s, b) = operator(h, admin, "POST", "/v0/sensors", body).await;
    assert_eq!(s, StatusCode::CREATED, "{b}");
    (
        b["agent"]["id"].as_str().unwrap().to_string(),
        b["enrolment"]["token"].as_str().unwrap().to_string(),
    )
}

/// Register and enrol; returns (sensor id, certificate fingerprint).
async fn enrolled(h: &H, admin: &str, body: Value) -> (String, String) {
    let (id, token) = register(h, admin, body).await;
    let (s, b) = enrol_raw(h, &token, &csr()).await;
    assert_eq!(s, StatusCode::CREATED, "{b}");
    (id, b["cert_sha256"].as_str().unwrap().to_string())
}

async fn place_redis(h: &H, admin: &str, sensor_id: &str) -> (StatusCode, Value) {
    operator(
        h,
        admin,
        "POST",
        "/v0/decoys",
        json!({"catalogue_id": "emulator/redis/7.0", "allow_draft": true, "sensor_id": sensor_id}),
    )
    .await
}

fn event(decoy: &str, id: &str) -> Value {
    json!({
        "event_id": id,
        "ts": NOW - 1000,
        "decoy_id": decoy,
        "catalogue_id": "emulator/redis/7.0",
        "decoy_kind": "emulation",
        "channel": "application",
        "severity": "info",
        "src": {"ip": "203.0.113.7", "port": 40000},
        "data": {"command": "CONFIG SET dir /tmp"}
    })
}

fn actions(h: &H, action: &str) -> Vec<foiled_core::audit::AuditRecord> {
    h.store
        .audit()
        .into_iter()
        .filter(|a| a.action == action)
        .collect()
}

#[tokio::test]
async fn registration_returns_a_one_time_token_and_never_audits_it() {
    let h = harness();
    let (s, b) = operator(
        &h,
        "admin1",
        "POST",
        "/v0/sensors",
        json!({"label": "Branch office", "share_opt_in": false}),
    )
    .await;
    assert_eq!(s, StatusCode::CREATED, "{b}");
    assert_eq!(b["agent"]["status"], "pending");
    assert_eq!(b["agent"]["role"], "sensor");
    assert_eq!(b["agent"]["sandbox_allowed"], false, "edge default");
    assert_eq!(b["agent"]["share_opt_in"], false);
    let token = b["enrolment"]["token"].as_str().unwrap();
    assert!(token.starts_with("foe_"));
    assert_eq!(b["enrolment"]["expires_at"], NOW + 3_600_000);
    let audit = serde_json::to_string(&h.store.audit()).unwrap();
    assert!(audit.contains("sensor.create"));
    assert!(
        !audit.contains(token.split('.').nth(1).unwrap()),
        "secret never audited"
    );

    let (s, list) = operator(&h, "reader1", "GET", "/v0/sensors", Value::Null).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(list["items"].as_array().unwrap().len(), 1);
    let (s, _) = operator(&h, "reader1", "POST", "/v0/sensors", json!({})).await;
    assert_eq!(s, StatusCode::FORBIDDEN, "sensors:write needed");
    let (s, _) = operator(
        &h,
        "admin1",
        "POST",
        "/v0/sensors",
        json!({"enrolment_ttl_seconds": 10}),
    )
    .await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn enrolment_binds_the_certificate_to_the_tokens_identity_only() {
    let h = harness();
    let (id, token) = register(&h, "admin1", json!({})).await;
    let (s, b) = enrol_raw(&h, &token, &csr()).await;
    assert_eq!(s, StatusCode::CREATED, "{b}");
    assert_eq!(b["agent_id"], id.as_str());
    assert_eq!(b["tenant_id"], "t1");
    assert_eq!(b["role"], "sensor");
    assert_eq!(
        b["scopes"],
        json!([
            "sensor:lease",
            "sensor:report",
            "sensor:ingest",
            "sensor:upload"
        ])
    );
    let fp = b["cert_sha256"].as_str().unwrap();
    assert_eq!(
        foiled_core::enrolment::cert_fingerprint(b["certificate_pem"].as_str().unwrap()).as_deref(),
        Some(fp)
    );
    let (_, agent) = operator(
        &h,
        "admin1",
        "GET",
        &format!("/v0/sensors/{id}"),
        Value::Null,
    )
    .await;
    assert_eq!(agent["status"], "active");
    assert_eq!(agent["cert_sha256"], fp);

    // Tabletop step 5: the token is single use, and reuse is audited.
    let (s, _) = enrol_raw(&h, &token, &csr()).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    let denied = actions(&h, "sensor.enrol");
    assert!(
        denied
            .iter()
            .any(|a| a.outcome == foiled_core::audit::Outcome::Denied)
    );
    // A guessed secret for a real token id is refused and audited too.
    let forged = format!("{}.{}", token.split('.').next().unwrap(), "x".repeat(64));
    let (s, _) = enrol_raw(&h, &forged, &csr()).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn enrolment_refuses_bad_csrs_without_burning_the_token() {
    let h = harness();
    let (_, token) = register(&h, "admin1", json!({})).await;
    let with_key = format!(
        "{}-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n",
        csr()
    );
    let (s, b) = enrol_raw(&h, &token, &with_key).await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    assert!(
        b["error"]["message"]
            .as_str()
            .unwrap()
            .contains("private key")
    );
    let (s, _) = enrol_raw(&h, &token, &csr()).await;
    assert_eq!(
        s,
        StatusCode::CREATED,
        "token still usable after a refused CSR"
    );
}

#[tokio::test]
async fn expired_tokens_and_missing_issuer_are_refused() {
    let h = harness();
    let (_, token) = register(&h, "admin1", json!({"enrolment_ttl_seconds": 300})).await;
    h.clock.store(NOW + 300_000, Ordering::SeqCst);
    let (s, _) = enrol_raw(&h, &token, &csr()).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);

    let h = harness_with(false);
    let (_, token) = register(&h, "admin1", json!({})).await;
    let (s, b) = enrol_raw(&h, &token, &csr()).await;
    assert_eq!(s, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(b["error"]["code"], "enrolment_disabled");
}

#[tokio::test]
async fn a_sensor_certificate_cannot_reach_operator_routes() {
    // Tabletop steps 2 to 4: a stolen sensor certificate is not an operator.
    let h = harness();
    let (id, fp) = enrolled(&h, "admin1", json!({})).await;
    for (path, body) in [
        ("/v0/sensors", json!({})),
        ("/v0/hosts", json!({})),
        ("/v0/decoys", json!({"catalogue_id": "emulator/redis/7.0"})),
        (
            &format!("/v0/sensors/{id}:reenrol") as &str,
            json!({"reason": {"code": "operator_manual", "text": "x"}}),
        ),
    ] {
        let (s, _) = cert(&h, &fp, path, body).await;
        assert_eq!(s, StatusCode::FORBIDDEN, "{path}");
    }
    let mut req = Request::get("/v0/audit").body(Body::empty()).unwrap();
    req.extensions_mut().insert(ClientCert {
        verified: true,
        sha256: fp.clone(),
    });
    let (s, _) = send(&h, req).await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    // Not even the host channel: a sensor is not a host.
    let (s, _) = cert(&h, &fp, &format!("/v0/hosts/{id}/jobs:lease"), json!({})).await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    // An unverified certificate with a known fingerprint is nobody.
    let mut req = Request::post(format!("/v0/sensors/{id}/jobs:lease"))
        .body(Body::from("{}"))
        .unwrap();
    req.extensions_mut().insert(ClientCert {
        verified: false,
        sha256: fp,
    });
    assert_eq!(send(&h, req).await.0, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn sensors_lease_only_their_own_placed_jobs() {
    let h = harness();
    let (a, fa) = enrolled(&h, "admin1", json!({})).await;
    let (b, fb) = enrolled(&h, "admin1", json!({})).await;
    // An unplaced job is for research hosts; sensors never take it.
    let (s, _) = operator(
        &h,
        "admin1",
        "POST",
        "/v0/decoys",
        json!({"catalogue_id": "emulator/redis/7.0", "allow_draft": true}),
    )
    .await;
    assert_eq!(s, StatusCode::CREATED);
    let (s, placed) = place_redis(&h, "admin1", &a).await;
    assert_eq!(s, StatusCode::CREATED, "{placed}");
    assert_eq!(placed["decoy"]["host_id"], a.as_str());

    let (s, body) = cert(&h, &fa, &format!("/v0/sensors/{a}/jobs:lease"), json!({})).await;
    assert_eq!(s, StatusCode::OK, "{body}");
    let jobs: Vec<SignedJob> = serde_json::from_value(body["jobs"].clone()).unwrap();
    assert_eq!(jobs.len(), 1);
    let mut keys = TrustedKeys::default();
    keys.add_hex(
        "k1",
        &JobSigner::from_seed_hex("k1", SEED)
            .unwrap()
            .public_key_hex(),
    )
    .unwrap();
    let job = keys.verify(&jobs[0]).unwrap();
    assert_eq!(job.host_id, a, "signed for this sensor");
    assert_eq!(job.decoy_id, placed["decoy"]["id"].as_str().unwrap());

    let (_, body) = cert(&h, &fb, &format!("/v0/sensors/{b}/jobs:lease"), json!({})).await;
    assert_eq!(body["jobs"], json!([]), "sensor b sees nothing");
    let (s, body) = cert(&h, &fb, &format!("/v0/sensors/{a}/jobs:lease"), json!({})).await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    assert_eq!(body["error"]["code"], "wrong_sensor");
}

#[tokio::test]
async fn placement_is_tenant_scoped_and_emulation_first() {
    let h = harness();
    let (a, _) = enrolled(&h, "admin1", json!({})).await;
    let (s, b) = place_redis(&h, "admin2", &a).await;
    assert_eq!(
        s,
        StatusCode::UNPROCESSABLE_ENTITY,
        "another tenant's sensor"
    );
    assert_eq!(b["error"]["code"], "sensor_unavailable");
    let (s, b) = operator(
        &h,
        "admin1",
        "POST",
        "/v0/decoys",
        json!({"catalogue_id": "foiled/demo-app/1.0.0", "sensor_id": a}),
    )
    .await;
    assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(b["error"]["code"], "sandbox_not_allowed");
    let (heavy, _) = enrolled(&h, "admin1", json!({"sandbox_allowed": true})).await;
    let (s, b) = operator(
        &h,
        "admin1",
        "POST",
        "/v0/decoys",
        json!({"catalogue_id": "foiled/demo-app/1.0.0", "sensor_id": heavy}),
    )
    .await;
    assert_eq!(s, StatusCode::CREATED, "{b}");
    // Other tenants cannot see or act on the sensor at all.
    let (s, _) = operator(
        &h,
        "admin2",
        "GET",
        &format!("/v0/sensors/{a}"),
        Value::Null,
    )
    .await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    let (s, _) = operator(
        &h,
        "admin2",
        "POST",
        &format!("/v0/sensors/{a}:revoke"),
        json!({"reason": {"code": "operator_manual", "text": "not mine"}}),
    )
    .await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    let (_, list) = operator(&h, "admin2", "GET", "/v0/sensors", Value::Null).await;
    assert_eq!(list["items"], json!([]));
}

#[tokio::test]
async fn ingest_is_stamped_with_the_sensor_and_limited_to_its_decoys() {
    let h = harness();
    let (a, fa) = enrolled(&h, "admin1", json!({})).await;
    let (b, fb) = enrolled(&h, "admin1", json!({})).await;
    let (other, fo) = enrolled(&h, "admin2", json!({})).await;
    let (_, d) = place_redis(&h, "admin1", &a).await;
    let decoy = d["decoy"]["id"].as_str().unwrap().to_string();
    let (_, d2) = place_redis(&h, "admin2", &other).await;
    let other_decoy = d2["decoy"]["id"].as_str().unwrap().to_string();

    // Claimed identity and tenant are replaced (tabletop step 6).
    let mut e = event(&decoy, "e1");
    e["tenant_id"] = json!("t2");
    e["source"] = json!({"kind": "host", "id": "host-1"});
    let (s, body) = cert(&h, &fa, "/v0/ingest/events", json!({"events": [e]})).await;
    assert_eq!(s, StatusCode::ACCEPTED, "{body}");
    let q = h.store.queued_events();
    assert_eq!(q[0].tenant_id.as_deref(), Some("t1"));
    let src = q[0].source.as_ref().unwrap();
    assert_eq!(
        (src.kind, src.id.as_str()),
        (SourceKind::Sensor, a.as_str())
    );

    // Another sensor in the same tenant cannot write for this decoy.
    let (s, body) = cert(
        &h,
        &fb,
        "/v0/ingest/events",
        json!({"events": [event(&decoy, "e2")]}),
    )
    .await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    assert_eq!(body["error"]["code"], "not_assigned");
    // A sensor in another tenant cannot even see it.
    let (s, _) = cert(
        &h,
        &fo,
        "/v0/ingest/events",
        json!({"events": [event(&decoy, "e3")]}),
    )
    .await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    // And this sensor cannot write into the other tenant's decoy.
    let (s, _) = cert(
        &h,
        &fa,
        "/v0/ingest/events",
        json!({"events": [event(&other_decoy, "e4")]}),
    )
    .await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    assert_eq!(h.store.queued_events().len(), 1);
    let _ = b;
}

#[tokio::test]
async fn ingest_is_rate_limited_per_identity() {
    let mut h = harness();
    h.state.limits.ingest_batches_per_minute = 2;
    let (a, fa) = enrolled(&h, "admin1", json!({})).await;
    let (_, d) = place_redis(&h, "admin1", &a).await;
    let decoy = d["decoy"]["id"].as_str().unwrap().to_string();
    for i in 0..2 {
        let (s, _) = cert(
            &h,
            &fa,
            "/v0/ingest/events",
            json!({"events": [event(&decoy, &format!("e{i}"))]}),
        )
        .await;
        assert_eq!(s, StatusCode::ACCEPTED);
    }
    let (s, _) = cert(
        &h,
        &fa,
        "/v0/ingest/events",
        json!({"events": [event(&decoy, "e9")]}),
    )
    .await;
    assert_eq!(s, StatusCode::TOO_MANY_REQUESTS);
    h.clock.fetch_add(60_000, Ordering::SeqCst);
    let (s, _) = cert(
        &h,
        &fa,
        "/v0/ingest/events",
        json!({"events": [event(&decoy, "e10")]}),
    )
    .await;
    assert_eq!(s, StatusCode::ACCEPTED, "next window");
}

#[tokio::test]
async fn revocation_is_immediate_final_and_reaches_the_ca() {
    let h = harness();
    let (a, fa) = enrolled(&h, "admin1", json!({})).await;
    let (s, _) = cert(&h, &fa, &format!("/v0/sensors/{a}/jobs:lease"), json!({})).await;
    assert_eq!(s, StatusCode::OK);
    let reason =
        json!({"reason": {"code": "operator_manual", "text": "Sensor host reported stolen."}});
    let (s, b) = operator(
        &h,
        "admin1",
        "POST",
        &format!("/v0/sensors/{a}:revoke"),
        reason.clone(),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{b}");
    assert_eq!(b["agent"]["status"], "revoked");
    assert_eq!(b["agent"]["revoke_reason"]["code"], "operator_manual");
    assert_eq!(b["ca_revoked"], 1);
    assert_eq!(h.issuer.revoked(), vec!["fake-1"]);
    let rec = &actions(&h, "sensor.revoke")[0];
    assert_eq!(rec.reason_code.as_deref(), Some("operator_manual"));

    // Tabletop step 10: the Worker refuses the certificate from now on.
    for path in [
        format!("/v0/sensors/{a}/jobs:lease"),
        format!("/v0/sensors/{a}/heartbeat"),
        "/v0/ingest/events".to_string(),
    ] {
        let (s, _) = cert(&h, &fa, &path, json!({})).await;
        assert_eq!(s, StatusCode::UNAUTHORIZED, "{path}");
    }
    let (s, _) = operator(
        &h,
        "admin1",
        "POST",
        &format!("/v0/sensors/{a}:revoke"),
        reason.clone(),
    )
    .await;
    assert_eq!(s, StatusCode::CONFLICT, "final");
    let (s, _) = operator(
        &h,
        "admin1",
        "POST",
        &format!("/v0/sensors/{a}:reenrol"),
        reason,
    )
    .await;
    assert_eq!(
        s,
        StatusCode::CONFLICT,
        "a revoked sensor is never re-enrolled"
    );
}

#[tokio::test]
async fn revoking_a_pending_sensor_kills_its_token() {
    let h = harness();
    let (a, token) = register(&h, "admin1", json!({})).await;
    let reason =
        json!({"reason": {"code": "operator_manual", "text": "Token pasted into a ticket."}});
    let (s, _) = operator(
        &h,
        "admin1",
        "POST",
        &format!("/v0/sensors/{a}:revoke"),
        reason,
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    let (s, _) = enrol_raw(&h, &token, &csr()).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn renewal_overlaps_for_the_grace_period_only() {
    let h = harness();
    let (a, old) = enrolled(&h, "admin1", json!({})).await;
    let (s, b) = cert(
        &h,
        &old,
        &format!("/v0/sensors/{a}/certificate:renew"),
        json!({"csr_pem": csr()}),
    )
    .await;
    assert_eq!(s, StatusCode::CREATED, "{b}");
    let new = b["cert_sha256"].as_str().unwrap().to_string();
    assert_ne!(new, old);
    let lease = format!("/v0/sensors/{a}/jobs:lease");
    assert_eq!(cert(&h, &new, &lease, json!({})).await.0, StatusCode::OK);
    assert_eq!(
        cert(&h, &old, &lease, json!({})).await.0,
        StatusCode::OK,
        "grace"
    );
    h.clock.fetch_add(RENEWAL_GRACE_MS, Ordering::SeqCst);
    assert_eq!(
        cert(&h, &old, &lease, json!({})).await.0,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(cert(&h, &new, &lease, json!({})).await.0, StatusCode::OK);
    // Only as itself.
    let (b2, fb) = enrolled(&h, "admin1", json!({})).await;
    let (s, _) = cert(
        &h,
        &fb,
        &format!("/v0/sensors/{a}/certificate:renew"),
        json!({"csr_pem": csr()}),
    )
    .await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    let _ = b2;
    assert_eq!(actions(&h, "sensor.renew").len(), 1);
}

#[tokio::test]
async fn renewals_are_rate_limited() {
    let mut h = harness();
    h.state.limits.renewals_per_day = 1;
    let (a, fp) = enrolled(&h, "admin1", json!({})).await;
    let path = format!("/v0/sensors/{a}/certificate:renew");
    assert_eq!(
        cert(&h, &fp, &path, json!({"csr_pem": csr()})).await.0,
        StatusCode::CREATED
    );
    assert_eq!(
        cert(&h, &fp, &path, json!({"csr_pem": csr()})).await.0,
        StatusCode::TOO_MANY_REQUESTS
    );
}

#[tokio::test]
async fn reenrolment_replaces_the_token_and_retires_old_certificates_at_once() {
    let h = harness();
    let (a, old) = enrolled(&h, "admin1", json!({})).await;
    let reason = json!({"reason": {"code": "operator_manual", "text": "Disk replaced, key lost."}});
    let (s, b) = operator(
        &h,
        "admin1",
        "POST",
        &format!("/v0/sensors/{a}:reenrol"),
        reason.clone(),
    )
    .await;
    assert_eq!(s, StatusCode::CREATED, "{b}");
    let first = b["enrolment"]["token"].as_str().unwrap().to_string();
    let (_, b) = operator(
        &h,
        "admin1",
        "POST",
        &format!("/v0/sensors/{a}:reenrol"),
        reason,
    )
    .await;
    let second = b["enrolment"]["token"].as_str().unwrap().to_string();
    assert_eq!(
        enrol_raw(&h, &first, &csr()).await.0,
        StatusCode::UNAUTHORIZED,
        "superseded"
    );
    let (s, b) = enrol_raw(&h, &second, &csr()).await;
    assert_eq!(s, StatusCode::CREATED);
    assert_eq!(b["agent_id"], a.as_str(), "same sensor id");
    let lease = format!("/v0/sensors/{a}/jobs:lease");
    assert_eq!(
        cert(&h, &old, &lease, json!({})).await.0,
        StatusCode::UNAUTHORIZED
    );
    let new = b["cert_sha256"].as_str().unwrap();
    assert_eq!(cert(&h, new, &lease, json!({})).await.0, StatusCode::OK);
}

#[tokio::test]
async fn a_network_jump_is_flagged_and_audited() {
    // Tabletop step 1: a copied certificate used from elsewhere.
    let h = harness();
    let (a, fp) = enrolled(&h, "admin1", json!({})).await;
    let hb = |now: i64| {
        json!({
            "host_id": a, "agent_version": "0.1.0", "kvm_present": false,
            "publicly_exposed": true, "free_disk_bytes": 1, "running_decoys": [],
            "host_time": now, "buffered_events": 0, "dropped_events": 0
        })
    };
    let path = format!("/v0/sensors/{a}/heartbeat");
    assert_eq!(
        cert(&h, &fp, &path, hb(NOW)).await.0,
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        as_cert(&h, &fp, "198.51.100.77", 64500, &path, hb(NOW))
            .await
            .0,
        StatusCode::NO_CONTENT
    );
    assert!(actions(&h, "sensor.network_changed").is_empty(), "same ASN");
    assert_eq!(
        as_cert(&h, &fp, "203.0.113.50", 64511, &path, hb(NOW))
            .await
            .0,
        StatusCode::NO_CONTENT
    );
    let jumps = actions(&h, "sensor.network_changed");
    assert_eq!(jumps.len(), 1);
    assert_eq!(jumps[0].detail["to"]["asn"], 64511);
    let (_, agent) = operator(
        &h,
        "admin1",
        "GET",
        &format!("/v0/sensors/{a}"),
        Value::Null,
    )
    .await;
    assert_eq!(agent["network_changed_at"], NOW);
    assert_eq!(agent["last_ip"], "203.0.113.50");
}

#[tokio::test]
async fn hosts_enrol_through_the_same_flow_with_the_host_role() {
    let h = harness();
    let (s, b) = operator(
        &h,
        "admin1",
        "POST",
        "/v0/hosts",
        json!({"label": "Research VPS"}),
    )
    .await;
    assert_eq!(s, StatusCode::CREATED, "{b}");
    assert_eq!(b["agent"]["sandbox_allowed"], true);
    let id = b["agent"]["id"].as_str().unwrap().to_string();
    let (s, r) = enrol_raw(&h, b["enrolment"]["token"].as_str().unwrap(), &csr()).await;
    assert_eq!(s, StatusCode::CREATED);
    assert_eq!(
        r["scopes"],
        json!(["host:lease", "host:report", "host:ingest", "host:upload"])
    );
    let fp = r["cert_sha256"].as_str().unwrap();
    assert_eq!(
        cert(&h, fp, &format!("/v0/hosts/{id}/jobs:lease"), json!({}))
            .await
            .0,
        StatusCode::OK
    );
    assert_eq!(
        cert(&h, fp, &format!("/v0/sensors/{id}/jobs:lease"), json!({}))
            .await
            .0,
        StatusCode::FORBIDDEN,
        "a host is not a sensor"
    );
    let (_, sensors) = operator(&h, "admin1", "GET", "/v0/sensors", Value::Null).await;
    assert_eq!(sensors["items"], json!([]), "registries are separate");
}
