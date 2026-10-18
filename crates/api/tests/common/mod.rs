//! Shared harness for the #35 tests: tokens, the fleet-wave fixture and a
//! request helper that returns status, headers and JSON.

#![allow(dead_code)]

use std::sync::Arc;

use axum::body::Body;
use foiled_api::auth::sha256_hex;
use foiled_api::memory::{MemoryCachePurger, MemoryRadarSink, MemoryStore};
use foiled_api::store::{Store, TokenRecord};
use foiled_api::{AppState, router};
use foiled_core::auth::{Role, Scope};
use foiled_core::capture::CaptureEvent;
use http::{HeaderMap, Request, StatusCode};
use http_body_util::BodyExt;
use serde_json::Value;
use tower::ServiceExt;

pub const SECRET: &str = "0123456789abcdef0123456789abcdef";
pub const DAY: i64 = 86_400_000;
/// UTC midnight of the fleet-wave fixture's day.
pub const FIXTURE_DAY: i64 = 1_792_281_600_000;

pub struct Harness {
    pub state: AppState,
    pub store: Arc<MemoryStore>,
    pub sink: Arc<MemoryRadarSink>,
    pub purger: Arc<MemoryCachePurger>,
}

/// Tokens: `analyst` and `reviewer` (review read and write, attempts and
/// campaigns read), `publisher` (also review:publish and attempts:write), `reader`
/// (review:read only), `nobody` (no review scopes) in tenant `t1`, and
/// `other` (everything) in tenant `t2`. `t1` may publish and is the
/// operator's research tenant, so its decoys count as research sensors.
pub async fn harness(now: i64) -> Harness {
    let store = Arc::new(MemoryStore::new());
    let rw = vec![
        Scope::ReviewRead,
        Scope::ReviewWrite,
        Scope::AttemptsRead,
        Scope::CampaignsRead,
    ];
    let mut publish = rw.clone();
    publish.extend([Scope::ReviewPublish, Scope::AttemptsWrite]);
    for (id, tenant, scopes) in [
        ("analyst", "t1", rw.clone()),
        ("reviewer", "t1", rw.clone()),
        ("publisher", "t1", publish.clone()),
        ("reader", "t1", vec![Scope::ReviewRead]),
        ("nobody", "t1", vec![Scope::AttemptsRead]),
        ("other", "t2", publish),
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
            "/../../testdata/campaigns/fleet-wave.input.json"
        ))
        .unwrap(),
    )
    .unwrap();
    let events: Vec<CaptureEvent> = serde_json::from_value(raw["events"].clone()).unwrap();
    store.enqueue_events(events).await.unwrap();
    let sink = Arc::new(MemoryRadarSink::default());
    let mut state = AppState::new(store.clone(), Arc::new(move || now));
    let ids = std::sync::Mutex::new(0u32);
    state.ids = Arc::new(move || {
        let mut g = ids.lock().unwrap();
        *g += 1;
        format!("id-{:04}", *g)
    });
    state.radar_sink = sink.clone();
    state.publisher_tenants = Arc::new(vec!["t1".into()]);
    state.research_tenants = Arc::new(vec!["t1".into()]);
    let purger = Arc::new(MemoryCachePurger::default());
    state.cache_purger = purger.clone();
    Harness {
        state,
        store,
        sink,
        purger,
    }
}

/// Send a request. `tok` empty means no credentials.
pub async fn send(
    state: &AppState,
    tok: &str,
    method: &str,
    path: &str,
    body: Value,
) -> (StatusCode, HeaderMap, Value) {
    let mut req = Request::builder()
        .method(method)
        .uri(path)
        .header("content-type", "application/json");
    if !tok.is_empty() {
        req = req.header("authorization", format!("Bearer fo_{tok}.{SECRET}"));
    }
    let req = req
        .body(if body.is_null() {
            Body::empty()
        } else {
            Body::from(body.to_string())
        })
        .unwrap();
    let res = router(state.clone()).oneshot(req).await.unwrap();
    let status = res.status();
    let headers = res.headers().clone();
    let bytes = res.into_body().collect().await.unwrap().to_bytes();
    (
        status,
        headers,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

pub async fn get(state: &AppState, tok: &str, path: &str) -> (StatusCode, Value) {
    let (s, _, b) = send(state, tok, "GET", path, Value::Null).await;
    (s, b)
}

pub async fn post(state: &AppState, tok: &str, path: &str, body: Value) -> (StatusCode, Value) {
    let (s, _, b) = send(state, tok, "POST", path, body).await;
    (s, b)
}

pub fn items(b: &Value) -> &Vec<Value> {
    b["items"].as_array().unwrap()
}

/// The shipped ATT&CK groups plus the fictional reports in
/// `testdata/actors/reports` (#29), as `crates/api/tests/actors.rs` uses.
pub fn actor_catalogue() -> foiled_core::actor::ActorCatalogue {
    let root = |rel: &str| format!("{}/../../{rel}", env!("CARGO_MANIFEST_DIR"));
    let read = |rel: &str| -> Value {
        serde_json::from_str(&std::fs::read_to_string(root(rel)).unwrap()).unwrap()
    };
    let groups: foiled_core::actor::AttackGroups =
        serde_json::from_value(read("data/attack/groups.json")).unwrap();
    let techniques = serde_json::from_value(read("data/attack/techniques.json")).unwrap();
    let mut paths: Vec<_> = std::fs::read_dir(root("testdata/actors/reports"))
        .unwrap()
        .map(|e| e.unwrap().path())
        .collect();
    paths.sort();
    let reports = paths
        .iter()
        .map(|p| serde_yaml_ng::from_str(&std::fs::read_to_string(p).unwrap()).unwrap())
        .collect();
    let c = foiled_core::actor::ActorCatalogue::build(Some(&groups), &techniques, reports);
    assert!(c.problems.is_empty(), "{:?}", c.problems);
    c
}
