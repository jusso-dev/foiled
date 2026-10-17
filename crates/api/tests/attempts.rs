//! `/v0/attempts` over the demo fleet fixture (#25).

use std::sync::Arc;

use axum::body::Body;
use foiled_api::auth::sha256_hex;
use foiled_api::memory::MemoryStore;
use foiled_api::store::{Store, TokenRecord};
use foiled_api::{AppState, router};
use foiled_core::auth::{Role, Scope};
use foiled_core::capture::CaptureEvent;
use http::{Request, StatusCode};
use http_body_util::BodyExt;
use serde_json::Value;
use tower::ServiceExt;

const SECRET: &str = "0123456789abcdef0123456789abcdef";
const T0: i64 = 1_792_285_323_000;

async fn harness() -> AppState {
    let store = Arc::new(MemoryStore::new());
    for (id, tenant, scopes) in [
        ("analyst", "t1", vec![Scope::AttemptsRead]),
        ("other", "t2", vec![Scope::AttemptsRead]),
        ("nobody", "t1", vec![Scope::DecoysRead]),
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
    let raw: Value = serde_json::from_str(
        &std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../testdata/attempts/demo-fleet.input.json"
        ))
        .unwrap(),
    )
    .unwrap();
    let events: Vec<CaptureEvent> = serde_json::from_value(raw["events"].clone()).unwrap();
    store.enqueue_events(events).await.unwrap();
    AppState::new(store, Arc::new(|| T0 + 3_600_000))
}

async fn get(state: &AppState, tok: &str, path: &str) -> (StatusCode, Value) {
    let req = Request::get(path)
        .header("authorization", format!("Bearer fo_{tok}.{SECRET}"))
        .body(Body::empty())
        .unwrap();
    let res = router(state.clone()).oneshot(req).await.unwrap();
    let status = res.status();
    let bytes = res.into_body().collect().await.unwrap().to_bytes();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

#[tokio::test]
async fn lists_attempts_newest_first_with_filters() {
    let s = harness().await;
    let (st, b) = get(&s, "analyst", "/v0/attempts").await;
    assert_eq!(st, StatusCode::OK, "{b}");
    let items = b["items"].as_array().unwrap();
    assert_eq!(items.len(), 4);
    assert_eq!(b["truncated"], false);
    assert_eq!(items[0]["src"], "192.0.2.44", "newest activity first");

    let (_, b) = get(&s, "analyst", "/v0/attempts?state=post-exploitation").await;
    let items = b["items"].as_array().unwrap();
    assert_eq!(items.len(), 1);
    assert_eq!(items[0]["src"], "203.0.113.7");
    assert_eq!(items[0]["noise"]["band"], "targeted");

    let (_, b) = get(&s, "analyst", "/v0/attempts?cve=foiled-demo-0001").await;
    assert_eq!(b["items"].as_array().unwrap().len(), 1);
    let (_, b) = get(&s, "analyst", "/v0/attempts?src=198.51.100.23").await;
    assert_eq!(b["items"].as_array().unwrap().len(), 2);
    let (_, b) = get(&s, "analyst", "/v0/attempts?decoy_kind=emulation").await;
    assert_eq!(b["items"].as_array().unwrap().len(), 2);
    let (_, b) = get(&s, "analyst", "/v0/attempts?limit=1").await;
    assert_eq!(b["items"].as_array().unwrap().len(), 1);
}

#[tokio::test]
async fn gets_one_attempt_by_its_stable_id() {
    let s = harness().await;
    let (_, b) = get(&s, "analyst", "/v0/attempts?state=post-exploitation").await;
    let id = b["items"][0]["attempt_id"].as_str().unwrap().to_string();
    let (st, a) = get(&s, "analyst", &format!("/v0/attempts/{id}")).await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(a["event_ids"].as_array().unwrap().len(), 5);
    assert_eq!(a["hook_hits"][0]["cve_id"], "FOILED-DEMO-0001");
    let (st, _) = get(&s, "analyst", "/v0/attempts/att_000000000000000000000000").await;
    assert_eq!(st, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn tenants_scopes_and_windows_are_enforced() {
    let s = harness().await;
    let (_, b) = get(&s, "other", "/v0/attempts").await;
    assert!(b["items"].as_array().unwrap().is_empty());
    let (st, _) = get(&s, "nobody", "/v0/attempts").await;
    assert_eq!(st, StatusCode::FORBIDDEN);
    let (st, _) = get(&s, "analyst", "/v0/attempts?since=0").await;
    assert_eq!(st, StatusCode::BAD_REQUEST, "windows are capped at 31 days");
    let (_, b) = get(
        &s,
        "analyst",
        &format!("/v0/attempts?since={}&until={}", T0 + 100_000, T0 + 200_000),
    )
    .await;
    assert_eq!(
        b["items"].as_array().unwrap().len(),
        1,
        "only the Redis config probe"
    );
}
