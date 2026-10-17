//! Keeps `api/openapi.yaml` and the router in step: every operation marked
//! `x-foiled-status: implemented` must be routed, and every `planned` one
//! must not be (so the spec never over-promises and never lags).

use std::sync::Arc;

use axum::body::Body;
use foiled_api::auth::sha256_hex;
use foiled_api::memory::MemoryStore;
use foiled_api::store::TokenRecord;
use foiled_api::{AppState, router};
use foiled_core::auth::{Role, Scope};
use http::Request;
use http_body_util::BodyExt;
use serde_json::Value;
use tower::ServiceExt;

const SECRET: &str = "0123456789abcdef0123456789abcdef";
const METHODS: &[&str] = &["get", "post", "put", "patch", "delete"];

fn spec() -> Value {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../api/openapi.yaml");
    serde_yaml_ng::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

fn resolve<'a>(spec: &'a Value, item: &'a Value) -> &'a Value {
    match item.get("$ref").and_then(Value::as_str) {
        Some(r) => {
            let ptr = r.trim_start_matches('#');
            spec.pointer(ptr)
                .unwrap_or_else(|| panic!("dangling $ref {r}"))
        }
        None => item,
    }
}

fn concrete(path: &str) -> String {
    path.replace("{entry_id}", "foiled/demo-app/1.0.0")
        .replace("{sha256}", &"a".repeat(64))
        .split('/')
        .map(|seg| {
            if let (Some(start), Some(end)) = (seg.find('{'), seg.find('}')) {
                format!("{}x{}", &seg[..start], &seg[end + 1..])
            } else {
                seg.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join("/")
}

/// True when the router has no route at all for this method and path.
async fn unrouted(state: &AppState, method: &str, path: &str) -> bool {
    let req = Request::builder()
        .method(method.to_uppercase().as_str())
        .uri(path)
        .header("authorization", format!("Bearer fo_admin1.{SECRET}"))
        .header("content-type", "application/json")
        .body(Body::from("{}"))
        .unwrap();
    let res = router(state.clone()).oneshot(req).await.unwrap();
    let status = res.status();
    let body = res.into_body().collect().await.unwrap().to_bytes();
    let v: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
    status == 405 || (status == 404 && v["error"]["message"] == "route not found")
}

#[tokio::test]
async fn implemented_operations_are_routed_and_planned_ones_are_not() {
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
    let state = AppState::new(store, Arc::new(|| 1_800_000_000_000));
    let spec = spec();
    let mut implemented = 0;
    let mut planned = 0;
    for (path, item) in spec["paths"].as_object().unwrap() {
        let item = resolve(&spec, item);
        for method in METHODS {
            let Some(op) = item.get(*method) else {
                continue;
            };
            let status = op["x-foiled-status"]
                .as_str()
                .unwrap_or_else(|| panic!("{method} {path} has no x-foiled-status"));
            assert!(
                op.get("x-foiled-store").is_some(),
                "{method} {path} has no x-foiled-store"
            );
            let url = concrete(path);
            let missing = unrouted(&state, method, &url).await;
            match status {
                "implemented" => {
                    implemented += 1;
                    assert!(
                        !missing,
                        "{method} {path} is implemented in the spec but not routed"
                    );
                }
                "planned" => {
                    planned += 1;
                    assert!(
                        op.get("x-foiled-issue").is_some(),
                        "{method} {path} needs x-foiled-issue"
                    );
                    assert!(
                        missing,
                        "{method} {path} is routed but the spec says planned"
                    );
                }
                other => panic!("{method} {path}: unknown status {other}"),
            }
        }
    }
    assert!(implemented >= 11, "implemented operations: {implemented}");
    assert!(planned >= 20, "planned operations: {planned}");
}
