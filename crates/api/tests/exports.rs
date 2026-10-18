//! Export routes (#13): scopes, tenant isolation, the confidence gate, the
//! analyst-only unreviewed path, the legacy CSV, and continuing a cut
//! export with its cursor.

use std::sync::Arc;

use axum::body::Body;
use foiled_api::auth::sha256_hex;
use foiled_api::memory::MemoryStore;
use foiled_api::store::{Store, TokenRecord};
use foiled_api::{AppState, router};
use foiled_core::auth::{Role, Scope};
use foiled_core::capture::CaptureEvent;
use foiled_core::intel::{misp, stix};
use http::{HeaderMap, Request, StatusCode};
use http_body_util::BodyExt;
use serde_json::Value;
use tower::ServiceExt;

const SECRET: &str = "0123456789abcdef0123456789abcdef";
const T0: i64 = 1_792_285_323_000;

async fn harness() -> (AppState, Arc<MemoryStore>) {
    let store = Arc::new(MemoryStore::new());
    for (id, tenant, role, scopes) in [
        ("lead", "t1", Role::Human, vec![Scope::ExportsRead]),
        (
            "analyst",
            "t1",
            Role::Human,
            vec![Scope::ExportsRead, Scope::ReviewWrite],
        ),
        ("other", "t2", Role::Human, vec![Scope::ExportsRead]),
        ("reader", "t1", Role::Human, vec![Scope::IocsRead]),
        ("agent", "t1", Role::Mcp, vec![Scope::ExportsRead]),
    ] {
        store.add_token(TokenRecord {
            id: id.into(),
            tenant_id: tenant.into(),
            role,
            scopes,
            secret_sha256: sha256_hex(SECRET),
            expires_at: None,
            revoked: false,
        });
    }
    for rel in [
        "iocs/memory-only.input.json",
        "exports/synthetic.input.json",
    ] {
        let raw: Value = serde_json::from_str(
            &std::fs::read_to_string(format!(
                "{}/../../testdata/{rel}",
                env!("CARGO_MANIFEST_DIR")
            ))
            .unwrap(),
        )
        .unwrap();
        let events: Vec<CaptureEvent> = serde_json::from_value(raw["events"].clone()).unwrap();
        store.enqueue_events(events).await.unwrap();
    }
    let state = AppState::new(store.clone(), Arc::new(|| T0 + 3_600_000));
    (state, store)
}

async fn call(
    state: &AppState,
    tok: Option<&str>,
    path: &str,
    accept: Option<&str>,
) -> (StatusCode, HeaderMap, String) {
    let mut req = Request::get(path);
    if let Some(t) = tok {
        req = req.header("authorization", format!("Bearer fo_{t}.{SECRET}"));
    }
    if let Some(a) = accept {
        req = req.header("accept", a);
    }
    let res = router(state.clone())
        .oneshot(req.body(Body::empty()).unwrap())
        .await
        .unwrap();
    let status = res.status();
    let headers = res.headers().clone();
    let bytes = res.into_body().collect().await.unwrap().to_bytes();
    (status, headers, String::from_utf8(bytes.to_vec()).unwrap())
}

fn json(s: &str) -> Value {
    serde_json::from_str(s).unwrap()
}

fn objects_of<'a>(b: &'a Value, ty: &str) -> Vec<&'a Value> {
    b["objects"]
        .as_array()
        .map(|a| a.iter().filter(|o| o["type"] == ty).collect())
        .unwrap_or_default()
}

#[tokio::test]
async fn stix_export_is_scoped_gated_and_valid() {
    let (s, _) = harness().await;
    let (st, h, body) = call(&s, Some("lead"), "/v0/exports/stix", None).await;
    assert_eq!(st, StatusCode::OK, "{body}");
    assert_eq!(h["content-type"], stix::MEDIA_TYPE);
    assert_eq!(h["x-foiled-truncated"], "false");
    let b = json(&body);
    let problems = stix::problems(&b);
    assert!(problems.is_empty(), "{problems:#?}");
    // Both exploit attempts, no probe-only source, no file hash.
    assert_eq!(objects_of(&b, "observed-data").len(), 2);
    assert!(!body.contains("198.51.100.9\""));
    assert!(objects_of(&b, "file").is_empty());
    // Rule-only technique links stay below publish_min without an analyst.
    assert!(objects_of(&b, "attack-pattern").is_empty());
    assert_eq!(objects_of(&b, "vulnerability").len(), 1);
    // Never-redistribute or tenant data never leaves.
    assert!(!body.contains("tenant_id") && !body.contains("\"t1\""));

    // The same request gives the same bytes.
    let (_, _, again) = call(&s, Some("lead"), "/v0/exports/stix", None).await;
    assert_eq!(again, body);

    // Other tenants see an export with nothing of t1 in it.
    let (st, _, other) = call(&s, Some("other"), "/v0/exports/stix", None).await;
    assert_eq!(st, StatusCode::OK);
    assert!(objects_of(&json(&other), "indicator").is_empty());
    // No exports:read, or an MCP token (which can never hold it): refused.
    let (st, _, _) = call(&s, Some("reader"), "/v0/exports/stix", None).await;
    assert_eq!(st, StatusCode::FORBIDDEN);
    let (st, _, _) = call(&s, Some("agent"), "/v0/exports/stix", None).await;
    assert_eq!(st, StatusCode::FORBIDDEN);
    let (st, _, _) = call(&s, None, "/v0/exports/stix", None).await;
    assert_eq!(st, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn filters_and_bad_input() {
    let (s, _) = harness().await;
    let (st, _, _) = call(
        &s,
        Some("lead"),
        "/v0/exports/stix?min_confidence=101",
        None,
    )
    .await;
    assert_eq!(st, StatusCode::BAD_REQUEST);
    let (st, _, _) = call(&s, Some("lead"), "/v0/exports/stix?tlp=white", None).await;
    assert_eq!(st, StatusCode::BAD_REQUEST);
    let long = "a".repeat(300);
    let (st, _, _) = call(
        &s,
        Some("lead"),
        &format!("/v0/exports/stix?catalogue_id={long}"),
        None,
    )
    .await;
    assert_eq!(st, StatusCode::BAD_REQUEST);

    // decoy_kind and catalogue filters select attempts.
    let (_, _, body) = call(
        &s,
        Some("lead"),
        "/v0/exports/stix?decoy_kind=emulation",
        None,
    )
    .await;
    assert!(objects_of(&json(&body), "observed-data").is_empty());
    let (_, _, body) = call(
        &s,
        Some("lead"),
        "/v0/exports/stix?catalogue_id=foiled/demo-app/1.0.0&state=post-exploitation",
        None,
    )
    .await;
    assert_eq!(objects_of(&json(&body), "observed-data").len(), 2);

    // TLP label, with `+` arriving as a space.
    let (_, _, body) = call(&s, Some("lead"), "/v0/exports/stix?tlp=amber+strict", None).await;
    assert!(body.contains("TLP:AMBER+STRICT"));
}

#[tokio::test]
async fn unreviewed_exports_need_review_write_and_are_audited() {
    let (s, store) = harness().await;
    let (st, _, _) = call(
        &s,
        Some("lead"),
        "/v0/exports/stix?include_unreviewed=true",
        None,
    )
    .await;
    assert_eq!(st, StatusCode::FORBIDDEN);
    assert!(store.audit().is_empty());

    let (st, _, body) = call(
        &s,
        Some("analyst"),
        "/v0/exports/stix?include_unreviewed=true&tlp=clear",
        None,
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    // Lifted to AMBER+STRICT, and the rule-only technique links appear
    // with "we assess as".
    assert!(body.contains("TLP:AMBER+STRICT") && !body.contains("TLP:CLEAR"));
    assert!(body.contains("We assess as ATT&CK T1190"));
    let audit = store.audit();
    assert_eq!(audit.len(), 1);
    assert_eq!(audit[0].action, "export.unreviewed");
    assert_eq!(audit[0].actor_id, "analyst");
}

#[tokio::test]
async fn misp_and_ioc_json_exports() {
    let (s, _) = harness().await;
    let (st, _, body) = call(&s, Some("lead"), "/v0/exports/misp", None).await;
    assert_eq!(st, StatusCode::OK);
    let e = json(&body);
    assert!(misp::problems(&e).is_empty(), "{:?}", misp::problems(&e));
    assert_eq!(e["Event"]["published"], false);
    assert!(!body.contains("\"sha256\""), "no file was captured");

    let (st, h, body) = call(&s, Some("lead"), "/v0/exports/iocs.json", None).await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(h["content-type"], "application/json");
    let j = json(&body);
    assert_eq!(j["tlp"], "amber");
    assert_eq!(j["truncated"], false);
    let items: Vec<foiled_core::ioc::Ioc> = serde_json::from_value(j["items"].clone()).unwrap();
    assert!(!items.is_empty());
    assert!(items.iter().all(|i| i.confidence.publishable));
    assert!(
        j["attempts"]
            .as_array()
            .unwrap()
            .iter()
            .any(|a| a["file_ioc_limited"] == true)
    );
}

#[tokio::test]
async fn legacy_csv_is_unchanged_and_ioc_columns_are_opt_in() {
    let (s, _) = harness().await;
    let (st, _, csv) = call(&s, Some("lead"), "/v0/exports/iocs.csv", None).await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(
        csv.lines().next().unwrap(),
        "indicator_type,indicator,first_seen,last_seen,event_count,decoy_ids,catalogue_ids,hook_cves,asn,as_org,country"
    );
    let (st, _, csv) = call(&s, Some("lead"), "/v0/exports/iocs.csv?fields=ioc", None).await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(
        csv.lines().next().unwrap(),
        foiled_core::intel::table::CSV_COLUMNS.join(",")
    );
    assert!(csv.contains("203[.]0[.]113[.]50"));
    let (st, _, _) = call(&s, Some("lead"), "/v0/exports/iocs.csv?fields=all", None).await;
    assert_eq!(st, StatusCode::BAD_REQUEST);
}

/// More events in one millisecond than an export reads: the cursor is
/// `(ts, event_id)`, so each part moves on and the parts cover every event
/// exactly once.
#[tokio::test]
async fn cut_exports_continue_by_cursor_even_within_one_millisecond() {
    let (mut s, store) = harness().await;
    s.limits.max_window_events = 3;
    let burst: Vec<CaptureEvent> = (0..10)
        .map(|n| {
            serde_json::from_value(serde_json::json!({
                "event_id": format!("burst-{n:02}"), "ts": T0 + 600_000,
                "decoy_id": "dcy-burst", "catalogue_id": "foiled/demo-app/1.0.0",
                "decoy_kind": "sandbox", "channel": "application", "severity": "info",
                "src": {"ip": "198.51.100.44"}, "tenant_id": "t9",
                "data": {"method": "GET", "path": format!("/b/{n}")}
            }))
            .unwrap()
        })
        .collect();
    store.enqueue_events(burst).await.unwrap();
    store.add_token(TokenRecord {
        id: "burst".into(),
        tenant_id: "t9".into(),
        role: Role::Human,
        scopes: vec![Scope::ExportsRead],
        secret_sha256: sha256_hex(SECRET),
        expires_at: None,
        revoked: false,
    });
    let base = format!(
        "/v0/exports/iocs.json?since={}&until={}",
        T0,
        T0 + 3_600_000
    );
    let mut url = base.clone();
    let mut cursors = Vec::new();
    for part in 0.. {
        assert!(part < 10, "the export did not finish: {cursors:?}");
        let (st, h, body) = call(&s, Some("burst"), &url, None).await;
        assert_eq!(st, StatusCode::OK, "{body}");
        let j = json(&body);
        match h.get("x-foiled-next-cursor") {
            None => {
                assert_eq!(j["truncated"], false);
                break;
            }
            Some(c) => {
                let c = c.to_str().unwrap().to_string();
                assert_eq!(j["next_cursor"], c.as_str());
                assert!(!cursors.contains(&c), "cursor repeated: {c}");
                cursors.push(c.clone());
                url = format!("{base}&cursor={c}");
            }
        }
    }
    // 10 events, 3 per part: cut after events 3, 6 and 9.
    assert_eq!(cursors.len(), 3);
    let (st, _, _) = call(&s, Some("burst"), &format!("{base}&cursor=12.zz"), None).await;
    assert_eq!(st, StatusCode::BAD_REQUEST);
}

/// Real campaigns (#33): clustering puts attempts in a campaign, and the
/// export carries it as a STIX `campaign` with scored relationships and a
/// MISP `campaign-id`, worded "possible" until an analyst confirms.
#[tokio::test]
async fn campaigns_from_clustering_reach_the_exports() {
    let store = Arc::new(MemoryStore::new());
    store.add_token(TokenRecord {
        id: "analyst".into(),
        tenant_id: "t1".into(),
        role: Role::Human,
        scopes: vec![Scope::ExportsRead, Scope::ReviewWrite],
        secret_sha256: sha256_hex(SECRET),
        expires_at: None,
        revoked: false,
    });
    let raw: Value = serde_json::from_str(
        &std::fs::read_to_string(format!(
            "{}/../../testdata/campaigns/fleet-wave.input.json",
            env!("CARGO_MANIFEST_DIR")
        ))
        .unwrap(),
    )
    .unwrap();
    let events: Vec<CaptureEvent> = serde_json::from_value(raw["events"].clone()).unwrap();
    store.enqueue_events(events).await.unwrap();
    let now = raw["now"].as_i64().unwrap();
    let s = AppState::new(store, Arc::new(move || now));

    let (st, _, body) = call(
        &s,
        Some("analyst"),
        "/v0/exports/stix?include_unreviewed=true",
        None,
    )
    .await;
    assert_eq!(st, StatusCode::OK, "{body}");
    let b = json(&body);
    assert!(stix::problems(&b).is_empty(), "{:?}", stix::problems(&b));
    let campaigns = objects_of(&b, "campaign");
    assert!(!campaigns.is_empty(), "clustering should give a campaign");
    let cid = campaigns[0]["name"].as_str().unwrap().to_string();
    assert!(cid.starts_with("cmp_"));
    let rel = objects_of(&b, "relationship")
        .into_iter()
        .find(|r| r["target_ref"] == campaigns[0]["id"])
        .expect("relationship to the campaign");
    assert!(rel["confidence"].is_u64());
    assert!(
        rel["description"]
            .as_str()
            .unwrap()
            .starts_with(&format!("Possible part of campaign {cid}."))
    );

    // The campaign filter selects its attempts; MISP carries the id.
    let (_, _, body) = call(
        &s,
        Some("analyst"),
        &format!("/v0/exports/misp?include_unreviewed=true&campaign_id={cid}"),
        None,
    )
    .await;
    let e = json(&body);
    assert!(misp::problems(&e).is_empty());
    assert!(
        e["Event"]["Attribute"]
            .as_array()
            .unwrap()
            .iter()
            .any(|a| a["type"] == "campaign-id" && a["value"] == cid.as_str())
    );
}
