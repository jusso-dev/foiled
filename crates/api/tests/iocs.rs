//! `/v0/iocs` and `/v0/attempts/{id}/iocs` over the memory-only fixture
//! (#34): tenant scoping, filters, ASN context and `ioc_refs` on attempts.

use std::sync::Arc;

use axum::body::Body;
use foiled_api::auth::sha256_hex;
use foiled_api::memory::MemoryStore;
use foiled_api::store::{Store, TokenRecord};
use foiled_api::{AppState, router};
use foiled_core::auth::{Role, Scope};
use foiled_core::capture::CaptureEvent;
use foiled_core::enrichment::{Fact, Observable, ObservedFacts};
use http::{Request, StatusCode};
use http_body_util::BodyExt;
use serde_json::{Value, json};
use tower::ServiceExt;

const SECRET: &str = "0123456789abcdef0123456789abcdef";
const T0: i64 = 1_792_285_323_000;

async fn harness() -> AppState {
    let store = Arc::new(MemoryStore::new());
    for (id, tenant, scopes) in [
        ("analyst", "t1", vec![Scope::IocsRead, Scope::AttemptsRead]),
        ("other", "t2", vec![Scope::IocsRead]),
        ("nobody", "t1", vec![Scope::AttemptsRead]),
        (
            "lead",
            "t1",
            vec![
                Scope::AttemptsRead,
                Scope::AttemptsWrite,
                Scope::ExportsRead,
            ],
        ),
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
            "/../../testdata/iocs/memory-only.input.json"
        ))
        .unwrap(),
    )
    .unwrap();
    let events: Vec<CaptureEvent> = serde_json::from_value(raw["events"].clone()).unwrap();
    store.enqueue_events(events).await.unwrap();
    let fact = |key: &str, value: Value| Fact {
        provider: "local_asn".into(),
        key: key.into(),
        value,
        confidence: 90,
        observed_at: T0,
        ttl_secs: 604_800,
        raw_ref: None,
    };
    store.add_facts(
        "t1",
        ObservedFacts {
            observable: Observable::ip("203.0.113.50").unwrap(),
            facts: vec![
                fact("asn.number", json!(64498)),
                fact("asn.org", json!("Example Hosting")),
                fact("greynoise.noise", json!(true)),
            ],
        },
    );
    // A provider not on the never-redistribute list, for the export guard.
    store.add_facts(
        "t1",
        ObservedFacts {
            observable: Observable::ip("203.0.113.50").unwrap(),
            facts: vec![Fact {
                provider: "team_asn".into(),
                ..fact("geo.country", json!("US"))
            }],
        },
    );
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

fn items(b: &Value) -> &Vec<Value> {
    b["items"].as_array().unwrap()
}

#[tokio::test]
async fn search_lists_tenant_iocs_with_asn_context_and_no_file_hash() {
    let s = harness().await;
    let (st, b) = get(&s, "analyst", "/v0/iocs").await;
    assert_eq!(st, StatusCode::OK, "{b}");
    assert_eq!(b["truncated"], false);
    let all = items(&b);
    assert_eq!(all.len(), 14);
    assert!(all.iter().all(|i| i["type"] != "file_sha256"));
    assert!(all.iter().all(|i| i["file_ioc_limited"] == true));
    let last: Vec<i64> = all
        .iter()
        .map(|i| i["last_seen"].as_i64().unwrap())
        .collect();
    assert!(last.windows(2).all(|w| w[0] >= w[1]), "newest first");

    let src = all.iter().find(|i| i["value"] == "203.0.113.50").unwrap();
    let keys: Vec<&str> = src["enrichment"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["key"].as_str().unwrap())
        .collect();
    assert_eq!(
        keys,
        vec!["asn.number", "asn.org", "geo.country"],
        "only ASN and geo facts"
    );
    assert_eq!(src["enrichment"][0]["shareable"], false);
    assert_eq!(src["enrichment"][2]["shareable"], true);
    assert_eq!(src["display"], "203[.]0[.]113[.]50");

    // Another tenant sees nothing; a token without iocs:read is refused.
    let (st, b) = get(&s, "other", "/v0/iocs").await;
    assert_eq!(st, StatusCode::OK);
    assert!(items(&b).is_empty());
    let (st, _) = get(&s, "nobody", "/v0/iocs").await;
    assert_eq!(st, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn search_filters_by_type_value_role_and_attempt() {
    let s = harness().await;
    let (_, b) = get(
        &s,
        "analyst",
        "/v0/iocs?type=url&value=hxxp://stage2%5B.%5Dexample%5B.%5Dinvalid/m.sh",
    )
    .await;
    assert_eq!(items(&b).len(), 1, "{b}");
    assert_eq!(items(&b)[0]["value"], "http://stage2.example.invalid/m.sh");

    let (_, b) = get(&s, "analyst", "/v0/iocs?value=STAGE2.example.invalid").await;
    let types: Vec<&str> = items(&b)
        .iter()
        .map(|i| i["type"].as_str().unwrap())
        .collect();
    assert_eq!(types.len(), 2);
    assert!(types.contains(&"domain") && types.contains(&"dns_query"));

    let (_, b) = get(&s, "analyst", "/v0/iocs?role=callback&type=dns_query").await;
    assert_eq!(items(&b).len(), 2);

    let (_, b) = get(&s, "analyst", "/v0/iocs?type=behaviour_fingerprint").await;
    let bf = &items(&b)[0];
    assert!(bf["value"].as_str().unwrap().starts_with("bf2:"));
    let attempt = bf["attempt_ids"][0].as_str().unwrap().to_string();

    let (_, b) = get(
        &s,
        "analyst",
        &format!("/v0/iocs?attempt_id={attempt}&limit=3"),
    )
    .await;
    assert_eq!(items(&b).len(), 3);
    let (_, b) = get(
        &s,
        "analyst",
        "/v0/iocs?attempt_id=att_000000000000000000000000",
    )
    .await;
    assert!(items(&b).is_empty());
    let (_, b) = get(&s, "analyst", "/v0/iocs?file_ioc_limited=false").await;
    assert!(items(&b).is_empty());

    let (st, _) = get(&s, "analyst", "/v0/iocs?type=md5").await;
    assert_eq!(st, StatusCode::BAD_REQUEST);
    let long = "a".repeat(2049);
    let (st, _) = get(&s, "analyst", &format!("/v0/iocs?value={long}")).await;
    assert_eq!(st, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn get_one_is_tenant_scoped() {
    let s = harness().await;
    let (_, b) = get(&s, "analyst", "/v0/iocs?type=http_ua").await;
    let id = items(&b)[0]["ioc_id"].as_str().unwrap().to_string();
    assert_eq!(
        items(&b)[0]["value"],
        "demo-loader/0.1 (REDACTED@example.invalid)"
    );

    let (st, one) = get(&s, "analyst", &format!("/v0/iocs/{id}")).await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(one["ioc_id"], id.as_str());
    assert_eq!(one["redacted"], true);
    let (st, _) = get(&s, "other", &format!("/v0/iocs/{id}")).await;
    assert_eq!(st, StatusCode::NOT_FOUND);
    let (st, _) = get(&s, "analyst", "/v0/iocs/ioc_000000000000000000000000").await;
    assert_eq!(st, StatusCode::NOT_FOUND);
    let (st, _) = get(&s, "analyst", "/v0/iocs/not-an-id").await;
    assert_eq!(st, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn attempts_carry_ioc_refs_and_the_attempt_view_explains_the_gap() {
    let s = harness().await;
    let (_, b) = get(&s, "analyst", "/v0/attempts").await;
    let attempt = &items(&b)[0];
    let id = attempt["attempt_id"].as_str().unwrap();
    let refs: Vec<&str> = attempt["ioc_refs"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r.as_str().unwrap())
        .collect();
    assert_eq!(refs.len(), 14);

    let (_, t) = get(&s, "analyst", &format!("/v0/attempts/{id}/timeline")).await;
    assert_eq!(t["ioc_refs"], attempt["ioc_refs"]);

    let (st, v) = get(&s, "analyst", &format!("/v0/attempts/{id}/iocs")).await;
    assert_eq!(st, StatusCode::OK, "{v}");
    assert_eq!(v["file_ioc_limited"], true);
    assert!(
        v["notes"][0]
            .as_str()
            .unwrap()
            .contains("no file hash is reported")
    );
    let got: Vec<&str> = items(&v)
        .iter()
        .map(|i| i["ioc_id"].as_str().unwrap())
        .collect();
    assert_eq!(got, refs, "same order as ioc_refs");

    let (st, _) = get(&s, "other", &format!("/v0/attempts/{id}/iocs")).await;
    assert_eq!(st, StatusCode::NOT_FOUND);
    let (st, _) = get(&s, "nobody", &format!("/v0/attempts/{id}/iocs")).await;
    assert_eq!(st, StatusCode::FORBIDDEN);
}

async fn send(
    state: &AppState,
    tok: &str,
    req: http::request::Builder,
    body: Body,
) -> (StatusCode, String) {
    let req = req
        .header("authorization", format!("Bearer fo_{tok}.{SECRET}"))
        .header("content-type", "application/json")
        .body(body)
        .unwrap();
    let res = router(state.clone()).oneshot(req).await.unwrap();
    let status = res.status();
    let bytes = res.into_body().collect().await.unwrap().to_bytes();
    (status, String::from_utf8(bytes.to_vec()).unwrap())
}

#[tokio::test]
async fn csv_export_keeps_never_redistribute_asn_data_out() {
    let s = harness().await;
    let (st, csv) = send(
        &s,
        "lead",
        Request::get("/v0/exports/iocs.csv"),
        Body::empty(),
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    assert!(csv.lines().next().unwrap().ends_with(",asn,as_org,country"));
    let row = csv
        .lines()
        .find(|l| l.starts_with("ipv4,203.0.113.50,"))
        .unwrap();
    // local_asn (ASN 64498, Example Hosting) is never exported; the
    // shareable team_asn country is.
    assert!(row.ends_with(",,,US"), "{row}");
    assert!(!csv.contains("64498") && !csv.contains("Example Hosting"));
}

#[tokio::test]
async fn ioc_links_cannot_be_overridden_per_attempt() {
    let s = harness().await;
    let (_, b) = get(&s, "analyst", "/v0/attempts").await;
    let id = items(&b)[0]["attempt_id"].as_str().unwrap().to_string();
    let body = json!({"kind": "attempt_ioc", "target": "ioc_000000000000000000000000",
        "feedback": "false_positive", "note": "test"});
    let (st, text) = send(
        &s,
        "lead",
        Request::post(format!("/v0/attempts/{id}/links")),
        Body::from(body.to_string()),
    )
    .await;
    assert_eq!(st, StatusCode::BAD_REQUEST, "{text}");
    assert!(text.contains("attempt_ioc"));
}
