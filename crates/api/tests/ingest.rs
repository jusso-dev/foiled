//! Evidence ingest and upload URL contract tests.

use std::sync::Arc;

use axum::body::Body;
use foiled_api::auth::{ClientCert, sha256_hex};
use foiled_api::memory::MemoryStore;
use foiled_api::routes::ingest::UploadConfig;
use foiled_api::store::{IdentityRecord, TokenRecord};
use foiled_api::{AppState, router};
use foiled_core::auth::{Role, Scope};
use foiled_core::capture::SourceKind;
use foiled_core::sigv4::Credentials;
use http::{Request, StatusCode};
use http_body_util::BodyExt;
use serde_json::{Value, json};
use tower::ServiceExt;

const NOW: i64 = 1_800_000_000_000;
const SECRET: &str = "0123456789abcdef0123456789abcdef";
const SHA: &str = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08";

struct H {
    store: Arc<MemoryStore>,
    state: AppState,
    decoy: String,
}

fn cert(n: u8) -> String {
    format!("{n:02x}").repeat(32)
}

async fn harness() -> H {
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
    for (n, id, tenant, role, scopes) in [
        (
            1,
            "host-1",
            "t1",
            Role::Host,
            vec![Scope::HostIngest, Scope::HostUpload],
        ),
        (
            2,
            "host-2",
            "t1",
            Role::Host,
            vec![Scope::HostIngest, Scope::HostUpload],
        ),
        (
            3,
            "host-x",
            "t2",
            Role::Host,
            vec![Scope::HostIngest, Scope::HostUpload],
        ),
        (4, "host-ro", "t1", Role::Host, vec![Scope::HostLease]),
    ] {
        store.add_identity(IdentityRecord {
            id: id.into(),
            tenant_id: tenant.into(),
            role,
            scopes,
            cert_sha256: cert(n),
            revoked: false,
        });
    }
    let mut state = AppState::new(store.clone(), Arc::new(|| NOW));
    // Create a decoy through the API, then assign it to host-1.
    let req = Request::post("/v0/decoys")
        .header("authorization", format!("Bearer fo_admin1.{SECRET}"))
        .header("content-type", "application/json")
        .body(Body::from(
            json!({"catalogue_id": "foiled/demo-app/1.0.0"}).to_string(),
        ))
        .unwrap();
    let res = router(state.clone()).oneshot(req).await.unwrap();
    let body: Value =
        serde_json::from_slice(&res.into_body().collect().await.unwrap().to_bytes()).unwrap();
    let decoy = body["decoy"]["id"].as_str().unwrap().to_string();
    store.set_host(&decoy, "host-1");
    state.uploads = None;
    H {
        store,
        state,
        decoy,
    }
}

async fn call_as(h: &H, n: u8, path: &str, body: Value) -> (StatusCode, Value) {
    let mut req = Request::post(path)
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .unwrap();
    req.extensions_mut().insert(ClientCert {
        verified: true,
        sha256: cert(n),
    });
    let res = router(h.state.clone()).oneshot(req).await.unwrap();
    let status = res.status();
    let bytes = res.into_body().collect().await.unwrap().to_bytes();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

fn event(decoy: &str, i: u32) -> Value {
    json!({
        "event_id": format!("evt-{i}"),
        "ts": NOW - 1000,
        "decoy_id": decoy,
        "catalogue_id": "foiled/demo-app/1.0.0",
        "decoy_kind": "sandbox",
        "channel": "application",
        "severity": "info",
        "src": {"ip": "203.0.113.7", "port": 40000},
        "data": {"method": "GET", "path": "/", "status": 200},
        "tenant_id": "forged-tenant",
        "source": {"kind": "sensor", "id": "forged"}
    })
}

#[tokio::test]
async fn host_events_are_stamped_and_queued() {
    let h = harness().await;
    let batch = json!({"events": [event(&h.decoy, 1), event(&h.decoy, 2)]});
    let (s, b) = call_as(&h, 1, "/v0/ingest/events", batch).await;
    assert_eq!(s, StatusCode::ACCEPTED, "{b}");
    assert_eq!(b["accepted"], 2);
    let q = h.store.queued_events();
    assert_eq!(q.len(), 2);
    for e in q {
        assert_eq!(e.tenant_id.as_deref(), Some("t1"));
        let src = e.source.unwrap();
        assert_eq!(src.kind, SourceKind::Host);
        assert_eq!(src.id, "host-1");
    }
}

#[tokio::test]
async fn hosts_can_only_send_for_their_own_decoys() {
    let h = harness().await;
    let batch = json!({"events": [event(&h.decoy, 1)]});
    let (s, b) = call_as(&h, 2, "/v0/ingest/events", batch.clone()).await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    assert_eq!(b["error"]["code"], "not_assigned");
    let (s, _) = call_as(&h, 3, "/v0/ingest/events", batch.clone()).await;
    assert_eq!(s, StatusCode::NOT_FOUND, "other tenant sees nothing");
    let (s, _) = call_as(&h, 4, "/v0/ingest/events", batch).await;
    assert_eq!(
        s,
        StatusCode::FORBIDDEN,
        "lease-only identity cannot ingest"
    );
    assert!(h.store.queued_events().is_empty());
}

#[tokio::test]
async fn operators_cannot_ingest_even_with_admin() {
    let h = harness().await;
    let req = Request::post("/v0/ingest/events")
        .header("authorization", format!("Bearer fo_admin1.{SECRET}"))
        .header("content-type", "application/json")
        .body(Body::from(
            json!({"events": [event(&h.decoy, 1)]}).to_string(),
        ))
        .unwrap();
    let res = router(h.state.clone()).oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn invalid_events_reject_the_whole_batch() {
    let h = harness().await;
    let mut bad = event(&h.decoy, 2);
    bad["src"]["ip"] = json!("999.1.1.1");
    let (s, b) = call_as(
        &h,
        1,
        "/v0/ingest/events",
        json!({"events": [event(&h.decoy, 1), bad]}),
    )
    .await;
    assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY);
    assert!(
        b["error"]["message"]
            .as_str()
            .unwrap()
            .contains("events[1]")
    );

    let mut foreign = event(&h.decoy, 3);
    foreign["payload_ref"] = json!(format!(
        "r2://foiled-evidence/t2/{}/_/network/{SHA}",
        h.decoy
    ));
    let (s, b) = call_as(&h, 1, "/v0/ingest/events", json!({"events": [foreign]})).await;
    assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY);
    assert!(
        b["error"]["message"]
            .as_str()
            .unwrap()
            .contains("outside this decoy")
    );

    let (s, _) = call_as(&h, 1, "/v0/ingest/events", json!({"events": []})).await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    let many: Vec<Value> = (0..101).map(|i| event(&h.decoy, i)).collect();
    let (s, _) = call_as(&h, 1, "/v0/ingest/events", json!({"events": many})).await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    assert!(h.store.queued_events().is_empty());
}

fn with_uploads(mut h: H) -> H {
    h.state.uploads = Some(UploadConfig {
        host: "acct.r2.cloudflarestorage.com".into(),
        bucket: "foiled-evidence".into(),
        credentials: Credentials {
            access_key_id: "AKIDEXAMPLE".into(),
            secret_access_key: "not-a-real-secret".into(),
        },
        expires_secs: 300,
    });
    h
}

#[tokio::test]
async fn upload_urls_are_scoped_to_one_object() {
    let h = harness().await;
    let req = json!({"decoy_id": h.decoy, "channel": "network", "sha256": SHA, "size": 1024});
    let (s, b) = call_as(&h, 1, "/v0/uploads", req.clone()).await;
    assert_eq!(s, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(b["error"]["code"], "uploads_disabled");

    let h = with_uploads(h);
    let (s, b) = call_as(&h, 1, "/v0/uploads", req.clone()).await;
    assert_eq!(s, StatusCode::CREATED, "{b}");
    let key = format!("t1/{}/_/network/{SHA}", h.decoy);
    assert_eq!(b["payload_ref"], format!("r2://foiled-evidence/{key}"));
    let url = b["url"].as_str().unwrap();
    assert!(url.starts_with(&format!(
        "https://acct.r2.cloudflarestorage.com/foiled-evidence/{key}?"
    )));
    assert!(url.contains("X-Amz-Expires=300"));
    assert!(url.contains("X-Amz-SignedHeaders=host%3Bx-amz-checksum-sha256"));
    assert!(url.contains("X-Amz-Signature="));
    assert_eq!(b["headers"][0][0], "x-amz-checksum-sha256");
    assert_eq!(
        b["headers"][0][1],
        "n4bQgYhMfWWaL+qgxVrQFaO/TxsrC4Is0V1sFbDwCgg="
    );
    assert_eq!(b["expires_at"], NOW + 300_000);

    let (s, _) = call_as(&h, 2, "/v0/uploads", req.clone()).await;
    assert_eq!(s, StatusCode::FORBIDDEN, "not this host's decoy");
    let mut bad = req.clone();
    bad["sha256"] = json!("../../etc");
    assert_eq!(
        call_as(&h, 1, "/v0/uploads", bad).await.0,
        StatusCode::BAD_REQUEST
    );
    let mut big = req;
    big["size"] = json!(6u64 * 1024 * 1024 * 1024);
    assert_eq!(
        call_as(&h, 1, "/v0/uploads", big).await.0,
        StatusCode::BAD_REQUEST
    );
}
