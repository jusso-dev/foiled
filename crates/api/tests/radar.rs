//! `/v0/radar` and `/v0/radar/rollups` (#35): daily rollups from the
//! fleet-wave fixture, the Analytics Engine fake, audiences and tenant
//! isolation.

mod common;

use common::*;
use foiled_api::store::Store;
use foiled_core::confidence::Band;
use foiled_core::radar::{Dimension, RadarPoint, source_key};
use foiled_core::share::SensorKind;
use http::StatusCode;
use serde_json::json;

/// The day after the fixture, 01:00 UTC: the fixture day has closed.
const NEXT_DAY: i64 = FIXTURE_DAY + DAY + 3_600_000;

fn point(tenant: &str, src: &str, kind: SensorKind, shared: bool) -> RadarPoint {
    RadarPoint {
        day: FIXTURE_DAY,
        tenant_id: tenant.into(),
        sensor: format!("{tenant}-sensor"),
        sensor_kind: kind,
        shared,
        dimension: Dimension::Cve,
        key: "CVE-2099-0002".into(),
        product: "foiled/demo-app".into(),
        source: source_key(src),
        attempts: 2,
        score: 80,
        band: Band::High,
        publishable: true,
        predisclosure: false,
    }
}

#[tokio::test]
async fn rollup_writes_postgres_rows_and_analytics_points() {
    let h = harness(NEXT_DAY).await;
    let (st, b) = post(
        &h.state,
        "analyst",
        "/v0/radar/rollups",
        json!({"day": NEXT_DAY}),
    )
    .await;
    assert_eq!(st, StatusCode::BAD_REQUEST, "today has not closed: {b}");
    let (st, b) = post(
        &h.state,
        "reader",
        "/v0/radar/rollups",
        json!({"day": FIXTURE_DAY}),
    )
    .await;
    assert_eq!(st, StatusCode::FORBIDDEN, "{b}");
    let (st, b) = post(
        &h.state,
        "analyst",
        "/v0/radar/rollups",
        json!({"day": FIXTURE_DAY + 5}),
    )
    .await;
    assert_eq!(st, StatusCode::OK, "{b}");
    assert_eq!(b["day"], FIXTURE_DAY);
    let n = b["points"].as_u64().unwrap() as usize;
    assert!(n > 0, "{b}");
    let stored = h
        .store
        .radar_points(Some("t1"), FIXTURE_DAY, FIXTURE_DAY + DAY, 1000)
        .await
        .unwrap();
    assert_eq!(stored.len(), n);
    assert!(stored.iter().any(|p| p.dimension == Dimension::Cve));
    assert!(stored.iter().any(|p| p.dimension == Dimension::Product));
    // Analytics Engine got the same points, without the source hash.
    // Analytics Engine got only the rows from sensors that may feed the
    // radar (the research decoys; the edge sensors never opted in), without
    // the tenant or the source hash.
    let ae = h.sink.points();
    let shared: Vec<_> = stored.iter().filter(|p| p.shared).collect();
    assert!(!shared.is_empty() && shared.len() < n, "{stored:?}");
    assert_eq!(ae.len(), shared.len());
    for (p, a) in shared.iter().zip(&ae) {
        assert_eq!(a.index, format!("{}:{}", p.dimension.as_str(), p.key));
        assert!(!a.blobs.contains(&p.source));
        assert!(!a.blobs.iter().any(|b| b == "t1"));
    }
    // Idempotent: a second rollup replaces the day.
    post(
        &h.state,
        "analyst",
        "/v0/radar/rollups",
        json!({"day": FIXTURE_DAY}),
    )
    .await;
    let again = h
        .store
        .radar_points(Some("t1"), FIXTURE_DAY, FIXTURE_DAY + DAY, 1000)
        .await
        .unwrap();
    assert_eq!(again.len(), n);
    assert!(h.store.audit().iter().any(|a| a.action == "radar.rollup"));

    // The tenant sees its own counts with the cautious wording.
    let (st, feed) = get(
        &h.state,
        "reader",
        &format!("/v0/radar?since={FIXTURE_DAY}&until={NEXT_DAY}"),
    )
    .await;
    assert_eq!(st, StatusCode::OK, "{feed}");
    assert_eq!(feed["audience"], "tenant");
    let cve = feed["series"]
        .as_array()
        .unwrap()
        .iter()
        .find(|s| s["dimension"] == "cve")
        .unwrap_or_else(|| panic!("{feed}"));
    assert_eq!(cve["wording"], "we assess as");
    let product = feed["series"]
        .as_array()
        .unwrap()
        .iter()
        .find(|s| s["dimension"] == "product")
        .unwrap();
    assert_ne!(
        product["label"], product["key"],
        "products get a display name"
    );
}

#[tokio::test]
async fn audiences_keep_tenants_apart() {
    let h = harness(NEXT_DAY + 10 * DAY).await;
    // t2 has a lot of activity on an edge sensor it never opted in.
    let t2: Vec<_> = (0..10)
        .map(|i| point("t2", &format!("198.51.100.{i}"), SensorKind::Edge, false))
        .collect();
    h.store
        .put_radar_points("t2", FIXTURE_DAY, t2)
        .await
        .unwrap();
    let q = format!("since={FIXTURE_DAY}&until={}", FIXTURE_DAY + DAY);
    // t1's own radar never shows t2's rows.
    let (_, own) = get(&h.state, "reader", &format!("/v0/radar?{q}")).await;
    assert!(own["series"].as_array().unwrap().is_empty(), "{own}");
    // The fleet radar skips sensors that did not opt in.
    let (_, fleet) = get(&h.state, "reader", &format!("/v0/radar?audience=fleet&{q}")).await;
    assert!(fleet["series"].as_array().unwrap().is_empty(), "{fleet}");
    assert!(!fleet.to_string().contains("t2"));
    // Opted in, but only one tenant shares edge data for the key: still
    // held back (min_edge_tenants).
    let shared: Vec<_> = (0..10)
        .map(|i| point("t2", &format!("198.51.100.{i}"), SensorKind::Edge, true))
        .collect();
    h.store
        .put_radar_points("t2", FIXTURE_DAY, shared)
        .await
        .unwrap();
    let (_, fleet) = get(&h.state, "reader", &format!("/v0/radar?audience=fleet&{q}")).await;
    assert!(fleet["series"].as_array().unwrap().is_empty(), "{fleet}");
    // The public audience is not served here.
    let (st, _) = get(
        &h.state,
        "reader",
        &format!("/v0/radar?audience=public&{q}"),
    )
    .await;
    assert_eq!(st, StatusCode::BAD_REQUEST);
    let (st, _) = get(&h.state, "nobody", "/v0/radar").await;
    assert_eq!(st, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn tenant_decoys_are_not_research_and_need_an_opt_in() {
    let mut h = harness(NEXT_DAY).await;
    // t1 is not a research tenant here: its decoys count as edge sensors
    // with the default opt-in (off).
    h.state.research_tenants = std::sync::Arc::new(vec![]);
    let (st, b) = post(
        &h.state,
        "analyst",
        "/v0/radar/rollups",
        json!({"day": FIXTURE_DAY}),
    )
    .await;
    assert_eq!(st, StatusCode::OK, "{b}");
    let stored = h
        .store
        .radar_points(Some("t1"), FIXTURE_DAY, FIXTURE_DAY + DAY, 1000)
        .await
        .unwrap();
    assert!(!stored.is_empty());
    assert!(
        stored
            .iter()
            .all(|p| p.sensor_kind == SensorKind::Edge && !p.shared)
    );
    // Nothing goes to Analytics Engine, and the fleet radar shows nothing.
    assert!(h.sink.points().is_empty());
    let q = format!("since={FIXTURE_DAY}&until={NEXT_DAY}");
    let (_, fleet) = get(&h.state, "reader", &format!("/v0/radar?audience=fleet&{q}")).await;
    assert!(fleet["series"].as_array().unwrap().is_empty(), "{fleet}");
    // The tenant still sees its own data.
    let (_, own) = get(&h.state, "reader", &format!("/v0/radar?{q}")).await;
    assert!(!own["series"].as_array().unwrap().is_empty());
}
