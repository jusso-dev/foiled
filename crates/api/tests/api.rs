//! Contract tests for the API router over the in-memory store.

use std::sync::Arc;
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};

use axum::body::Body;
use foiled_api::auth::{ClientCert, sha256_hex};
use foiled_api::memory::MemoryStore;
use foiled_api::store::{IdentityRecord, TokenRecord};
use foiled_api::{AppState, router};
use foiled_core::auth::{Role, Scope};
use foiled_core::decoy::DecoyState;
use http::{Request, StatusCode};
use http_body_util::BodyExt;
use serde_json::{Value, json};
use tower::ServiceExt;

const SECRET: &str = "0123456789abcdef0123456789abcdef";
const NOW: i64 = 1_800_000_000_000;

struct Harness {
    store: Arc<MemoryStore>,
    state: AppState,
    clock: Arc<AtomicI64>,
}

fn token(id: &str, tenant: &str, role: Role, scopes: &[Scope]) -> TokenRecord {
    TokenRecord {
        id: id.into(),
        tenant_id: tenant.into(),
        role,
        scopes: scopes.to_vec(),
        secret_sha256: sha256_hex(SECRET),
        expires_at: None,
        revoked: false,
    }
}

fn harness() -> Harness {
    let store = Arc::new(MemoryStore::new());
    store.add_token(token("admin1", "t1", Role::Human, &[Scope::Admin]));
    store.add_token(token(
        "reader1",
        "t1",
        Role::Human,
        &[Scope::CatalogueRead, Scope::DecoysRead],
    ));
    store.add_token(token(
        "elevated1",
        "t1",
        Role::Human,
        &[Scope::DecoysWrite, Scope::DecoysRead, Scope::DecoysElevate],
    ));
    store.add_token(token("other1", "t2", Role::Human, &[Scope::Admin]));
    store.add_token(TokenRecord {
        revoked: true,
        ..token("revoked1", "t1", Role::Human, &[Scope::Admin])
    });
    store.add_token(TokenRecord {
        expires_at: Some(NOW - 1),
        ..token("expired1", "t1", Role::Human, &[Scope::Admin])
    });
    store.add_identity(IdentityRecord {
        id: "host-1".into(),
        tenant_id: "t1".into(),
        role: Role::Host,
        scopes: vec![Scope::HostLease, Scope::Admin, Scope::DecoysWrite],
        cert_sha256: "aa".repeat(32),
        revoked: false,
        valid_until: None,
        expires_at: None,
    });
    let clock = Arc::new(AtomicI64::new(NOW));
    let counter = Arc::new(AtomicU64::new(0));
    let mut state = AppState::new(store.clone(), {
        let c = clock.clone();
        Arc::new(move || c.load(Ordering::SeqCst))
    });
    state.ids = Arc::new(move || format!("id{:04}", counter.fetch_add(1, Ordering::SeqCst)));
    Harness {
        store,
        state,
        clock,
    }
}

fn bearer(id: &str) -> String {
    format!("Bearer fo_{id}.{SECRET}")
}

async fn call(h: &Harness, req: Request<Body>) -> (StatusCode, Value) {
    let res = router(h.state.clone()).oneshot(req).await.unwrap();
    let status = res.status();
    let bytes = res.into_body().collect().await.unwrap().to_bytes();
    let body = if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes)
            .unwrap_or_else(|_| Value::String(String::from_utf8_lossy(&bytes).into()))
    };
    (status, body)
}

fn get(path: &str, tok: &str) -> Request<Body> {
    Request::get(path)
        .header("authorization", bearer(tok))
        .body(Body::empty())
        .unwrap()
}

fn post(path: &str, tok: &str, body: Value) -> Request<Body> {
    Request::post(path)
        .header("authorization", bearer(tok))
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .unwrap()
}

fn create_demo() -> Value {
    json!({"catalogue_id": "foiled/demo-app/1.0.0", "label": "demo"})
}

#[tokio::test]
async fn healthz_needs_no_auth() {
    let h = harness();
    let (s, b) = call(&h, Request::get("/healthz").body(Body::empty()).unwrap()).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(b["status"], "ok");
}

#[tokio::test]
async fn missing_bad_revoked_and_expired_credentials_are_401() {
    let h = harness();
    let (s, b) = call(&h, Request::get("/v0/decoys").body(Body::empty()).unwrap()).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    assert_eq!(b["error"]["code"], "unauthorised");
    let wrong = Request::get("/v0/decoys")
        .header(
            "authorization",
            format!("Bearer fo_admin1.{}", "f".repeat(32)),
        )
        .body(Body::empty())
        .unwrap();
    assert_eq!(call(&h, wrong).await.0, StatusCode::UNAUTHORIZED);
    assert_eq!(
        call(&h, get("/v0/decoys", "revoked1")).await.0,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        call(&h, get("/v0/decoys", "expired1")).await.0,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        call(&h, get("/v0/decoys", "nobody")).await.0,
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn scopes_are_enforced() {
    let h = harness();
    let (s, b) = call(&h, post("/v0/decoys", "reader1", create_demo())).await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    assert_eq!(b["error"]["message"], "requires scope decoys:write");
    assert_eq!(
        call(&h, get("/v0/audit", "reader1")).await.0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        call(&h, get("/v0/decoys", "reader1")).await.0,
        StatusCode::OK
    );
}

#[tokio::test]
async fn catalogue_is_served_with_filters_and_slash_ids() {
    let h = harness();
    let (s, b) = call(&h, get("/v0/catalogue/entries", "reader1")).await;
    assert_eq!(s, StatusCode::OK);
    assert!(b["items"].as_array().unwrap().len() >= 3);
    let (_, b) = call(
        &h,
        get("/v0/catalogue/entries?decoy_kind=sandbox", "reader1"),
    )
    .await;
    assert!(
        b["items"]
            .as_array()
            .unwrap()
            .iter()
            .all(|e| e["decoy_kind"] == "sandbox")
    );
    let (_, b) = call(
        &h,
        get("/v0/catalogue/entries?cve=foiled-demo-0001", "reader1"),
    )
    .await;
    assert_eq!(b["items"][0]["id"], "foiled/demo-app/1.0.0");
    let (s, b) = call(
        &h,
        get("/v0/catalogue/entries/emulator/redis/7.0", "reader1"),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(b["decoy_kind"], "emulation");
    let (s, _) = call(&h, get("/v0/catalogue/entries/nope/1", "reader1")).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn create_decoy_writes_pending_decoy_job_and_audit() {
    let h = harness();
    let (s, b) = call(&h, post("/v0/decoys", "admin1", create_demo())).await;
    assert_eq!(s, StatusCode::CREATED, "{b}");
    assert_eq!(b["decoy"]["state"], "pending");
    assert_eq!(b["decoy"]["decoy_kind"], "sandbox");
    assert_eq!(b["decoy"]["expires_at"], NOW + 24 * 3600 * 1000);
    assert_eq!(b["job_kind"], "decoy.create");
    let jobs = h.store.jobs();
    assert_eq!(jobs.len(), 1);
    assert_eq!(jobs[0].status, "queued");
    let audit = h.store.audit();
    assert_eq!(audit.len(), 1);
    assert_eq!(audit[0].action, "decoy.create");
    assert_eq!(audit[0].actor_id, "admin1");
    assert_eq!(audit[0].job_id.as_deref(), Some(jobs[0].id.as_str()));

    let id = b["decoy"]["id"].as_str().unwrap();
    let (s, got) = call(&h, get(&format!("/v0/decoys/{id}"), "reader1")).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(got["catalogue_id"], "foiled/demo-app/1.0.0");
    // The sandboxes alias serves the same resource.
    let (s, _) = call(&h, get(&format!("/v0/sandboxes/{id}"), "reader1")).await;
    assert_eq!(s, StatusCode::OK);
}

#[tokio::test]
async fn drafts_need_allow_draft_and_elevate_scope() {
    let h = harness();
    let draft = json!({"catalogue_id": "emulator/redis/7.0"});
    let (s, b) = call(&h, post("/v0/decoys", "admin1", draft.clone())).await;
    assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(b["error"]["code"], "entry_draft");
    let with_flag = json!({"catalogue_id": "emulator/redis/7.0", "allow_draft": true});
    // admin implies decoys:elevate.
    assert_eq!(
        call(&h, post("/v0/decoys", "admin1", with_flag.clone()))
            .await
            .0,
        StatusCode::CREATED
    );
    assert_eq!(
        call(&h, post("/v0/decoys", "elevated1", with_flag)).await.0,
        StatusCode::CREATED
    );
}

#[tokio::test]
async fn create_validates_entry_lifetime_and_label() {
    let h = harness();
    let (s, b) = call(
        &h,
        post("/v0/decoys", "admin1", json!({"catalogue_id": "x/y/1"})),
    )
    .await;
    assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(b["error"]["code"], "unknown_catalogue_entry");
    let too_long =
        json!({"catalogue_id": "foiled/demo-app/1.0.0", "lifetime_seconds": 8 * 24 * 3600});
    assert_eq!(
        call(&h, post("/v0/decoys", "admin1", too_long)).await.0,
        StatusCode::BAD_REQUEST
    );
    let zero = json!({"catalogue_id": "foiled/demo-app/1.0.0", "lifetime_seconds": 0});
    assert_eq!(
        call(&h, post("/v0/decoys", "admin1", zero)).await.0,
        StatusCode::BAD_REQUEST
    );
    let label = json!({"catalogue_id": "foiled/demo-app/1.0.0", "label": "a\u{0007}b"});
    assert_eq!(
        call(&h, post("/v0/decoys", "admin1", label)).await.0,
        StatusCode::BAD_REQUEST
    );
    assert!(h.store.jobs().is_empty());
}

#[tokio::test]
async fn idempotency_key_returns_the_original_decoy() {
    let h = harness();
    let req = || {
        Request::post("/v0/decoys")
            .header("authorization", bearer("admin1"))
            .header("content-type", "application/json")
            .header("idempotency-key", "retry-1")
            .body(Body::from(create_demo().to_string()))
            .unwrap()
    };
    let (s1, b1) = call(&h, req()).await;
    let (s2, b2) = call(&h, req()).await;
    assert_eq!(s1, StatusCode::CREATED);
    assert_eq!(s2, StatusCode::OK);
    assert_eq!(b1["decoy"]["id"], b2["decoy"]["id"]);
    assert_eq!(h.store.jobs().len(), 1);
    // Same key, different request body: refused.
    let other = Request::post("/v0/decoys")
        .header("authorization", bearer("admin1"))
        .header("content-type", "application/json")
        .header("idempotency-key", "retry-1")
        .body(Body::from(
            json!({"catalogue_id": "emulator/redis/7.0", "allow_draft": true}).to_string(),
        ))
        .unwrap();
    assert_eq!(call(&h, other).await.0, StatusCode::CONFLICT);
}

#[tokio::test]
async fn create_rate_limit_and_live_cap() {
    let mut h = harness();
    h.state.limits.creates_per_hour = 2;
    h.state.limits.max_live_decoys = 100;
    for _ in 0..2 {
        assert_eq!(
            call(&h, post("/v0/decoys", "admin1", create_demo()))
                .await
                .0,
            StatusCode::CREATED
        );
    }
    let (s, b) = call(&h, post("/v0/decoys", "admin1", create_demo())).await;
    assert_eq!(s, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(b["error"]["code"], "rate_limited");
    // Next hour window resets the counter.
    h.clock.fetch_add(3_600_000, Ordering::SeqCst);
    assert_eq!(
        call(&h, post("/v0/decoys", "admin1", create_demo()))
            .await
            .0,
        StatusCode::CREATED
    );

    let mut h = harness();
    h.state.limits.max_live_decoys = 1;
    assert_eq!(
        call(&h, post("/v0/decoys", "admin1", create_demo()))
            .await
            .0,
        StatusCode::CREATED
    );
    let (s, b) = call(&h, post("/v0/decoys", "admin1", create_demo())).await;
    assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(b["error"]["code"], "decoy_cap_reached");
}

#[tokio::test]
async fn tenants_cannot_see_each_others_decoys() {
    let h = harness();
    let (_, b) = call(&h, post("/v0/decoys", "admin1", create_demo())).await;
    let id = b["decoy"]["id"].as_str().unwrap();
    let (s, _) = call(&h, get(&format!("/v0/decoys/{id}"), "other1")).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    let (_, list) = call(&h, get("/v0/decoys", "other1")).await;
    assert!(list["items"].as_array().unwrap().is_empty());
    let reason = json!({"reason": {"code": "operator_manual", "text": "cleanup"}});
    let (s, _) = call(
        &h,
        post(&format!("/v0/decoys/{id}:destroy"), "other1", reason),
    )
    .await;
    assert_eq!(s, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn actions_need_a_reason_and_a_legal_transition() {
    let h = harness();
    let (_, b) = call(&h, post("/v0/decoys", "admin1", create_demo())).await;
    let id = b["decoy"]["id"].as_str().unwrap().to_string();
    let rotate = format!("/v0/decoys/{id}:rotate");

    let blank = json!({"reason": {"code": "operator_manual", "text": "  "}});
    let (s, b) = call(&h, post(&rotate, "admin1", blank)).await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "{b}");

    // A pending decoy cannot rotate yet; the refusal is audited.
    let reason = json!({"reason": {"code": "operator_manual", "text": "fresh image"}});
    let (s, _) = call(&h, post(&rotate, "admin1", reason.clone())).await;
    assert_eq!(s, StatusCode::CONFLICT);
    let denied = h
        .store
        .audit()
        .into_iter()
        .find(|a| a.action == "decoy.rotate")
        .unwrap();
    assert_eq!(denied.outcome, foiled_core::audit::Outcome::Denied);

    h.store.set_state(&id, DecoyState::Healthy);
    let (s, b) = call(&h, post(&rotate, "admin1", reason.clone())).await;
    assert_eq!(s, StatusCode::ACCEPTED, "{b}");
    assert_eq!(b["job_kind"], "decoy.rotate");
    let job = h
        .store
        .jobs()
        .into_iter()
        .find(|j| j.kind == "decoy.rotate")
        .unwrap();
    assert_eq!(job.reason_code.as_deref(), Some("operator_manual"));
    assert_eq!(job.reason_text.as_deref(), Some("fresh image"));

    let (s, _) = call(
        &h,
        post(
            &format!("/v0/decoys/{id}:explode"),
            "admin1",
            reason.clone(),
        ),
    )
    .await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    let (s, _) = call(
        &h,
        post(&format!("/v0/decoys/{id}:destroy"), "admin1", reason),
    )
    .await;
    assert_eq!(s, StatusCode::ACCEPTED);
}

#[tokio::test]
async fn host_certificates_cannot_use_operator_routes() {
    let h = harness();
    let with_cert = |verified: bool, method: &str, path: &str, body: Value| {
        let mut req = Request::builder()
            .method(method)
            .uri(path)
            .header("content-type", "application/json")
            .body(Body::from(body.to_string()))
            .unwrap();
        req.extensions_mut().insert(ClientCert {
            verified,
            sha256: "aa".repeat(32),
        });
        req
    };
    // The identity row lists admin and decoys:write, but the host role drops them.
    let (s, _) = call(&h, with_cert(true, "POST", "/v0/decoys", create_demo())).await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    let (s, _) = call(&h, with_cert(true, "GET", "/v0/audit", Value::Null)).await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    let (s, _) = call(&h, with_cert(false, "GET", "/v0/decoys", Value::Null)).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn audit_lists_newest_first_with_a_cursor() {
    let h = harness();
    for _ in 0..3 {
        call(&h, post("/v0/decoys", "admin1", create_demo())).await;
        h.clock.fetch_add(10, Ordering::SeqCst);
    }
    let (s, page1) = call(&h, get("/v0/audit?limit=2", "admin1")).await;
    assert_eq!(s, StatusCode::OK);
    let items = page1["items"].as_array().unwrap();
    assert_eq!(items.len(), 2);
    assert!(items[0]["ts"].as_i64() > items[1]["ts"].as_i64());
    let cursor = page1["next_cursor"].as_str().unwrap();
    let (_, page2) = call(
        &h,
        get(&format!("/v0/audit?limit=2&cursor={cursor}"), "admin1"),
    )
    .await;
    assert_eq!(page2["items"].as_array().unwrap().len(), 1);
    assert!(page2["next_cursor"].is_null());
    let (s, _) = call(&h, get("/v0/audit?cursor=garbage", "admin1")).await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn unknown_routes_are_json_404() {
    let h = harness();
    let (s, b) = call(&h, get("/v0/nothing", "admin1")).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    assert_eq!(b["error"]["code"], "not_found");
}

#[tokio::test]
async fn malformed_bodies_use_the_error_format() {
    let h = harness();
    let (s, b) = call(&h, post("/v0/decoys", "admin1", json!({"catalogue_id": 7}))).await;
    assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(b["error"]["code"], "invalid_body");
    let (s, b) = call(
        &h,
        post(
            "/v0/decoys",
            "admin1",
            json!({"catalogue_id": "x", "surprise": 1}),
        ),
    )
    .await;
    assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(b["error"]["code"], "invalid_body");
}
