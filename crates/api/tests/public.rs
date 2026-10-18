//! Public routes (#35) must never return private, tenant or unpublished
//! data. These tests try: drafts, items in review, approved but
//! unpublished, embargoed, withdrawn and TLP:GREEN write-ups, forged
//! credentials, held-back IOCs, a public radar (there is none) and a scan
//! of every public response for tenant, principal, sensor and attempt
//! identifiers. Public reads are rate limited per client.

mod common;

use std::sync::Arc;

use common::*;
use foiled_core::share::Tlp;
use foiled_core::writeup::{WriteUp, WriteUpStatus, writeup_id};
use http::StatusCode;
use serde_json::{Value, json};

const NOW: i64 = 1_792_306_923_000;

const CHECKLIST: &str = r#"{"tenant_data_removed": true, "wording_checked": true, "no_exploit_code": true, "payloads_redacted": true, "sources_linked": true, "delay_rules_checked": true}"#;

/// Strings that must never appear in a public response.
const PRIVATE: &[&str] = &[
    "\"t1\"",
    "\"t2\"",
    "tenant_id",
    "t1 ",
    "analyst",
    "reviewer",
    "publisher",
    "att_",
    "rq_",
    "wu_",
    "sensor-",
    "dcy-",
    "host-1",
    "author",
    "Bearer",
    "attempt_ids",
    "suppressed_buckets",
];

fn assert_public_safe(v: &Value) {
    let text = v.to_string();
    for p in PRIVATE {
        assert!(
            !text.contains(p),
            "{p} leaked into a public response: {text}"
        );
    }
}

fn writeup(slug: &str, status: WriteUpStatus) -> WriteUp {
    WriteUp {
        writeup_id: writeup_id(slug),
        tenant_id: "t1".into(),
        slug: slug.into(),
        title: format!("Secret draft {slug}"),
        summary: "tenant t1 internal".into(),
        body_md: "att_0123456789abcdef01234567".into(),
        status,
        tlp: Tlp::Clear,
        embargo_until: None,
        cve_ids: vec![],
        technique_ids: vec![],
        campaign_ids: vec![],
        ioc_ids: vec![],
        attempt_ids: vec!["att_0123456789abcdef01234567".into()],
        first_seen: None,
        redacted_payload: None,
        source_item_id: None,
        author_id: "analyst".into(),
        reviewer_id: None,
        checklist: None,
        version: 1,
        created_at: 1,
        updated_at: 1,
        submitted_at: None,
        approved_at: None,
        published_at: None,
        withdrawn_at: None,
    }
}

async fn public(h: &Harness, path: &str) -> (StatusCode, http::HeaderMap, Value) {
    send(&h.state, "", "GET", path, Value::Null).await
}

#[tokio::test]
async fn unpublished_write_ups_are_never_public() {
    let h = harness(NOW).await;
    for (slug, status) in [
        ("draft-one", WriteUpStatus::Draft),
        ("in-review", WriteUpStatus::Review),
        ("approved-only", WriteUpStatus::Approved),
        ("was-withdrawn", WriteUpStatus::Withdrawn),
    ] {
        h.store.force_writeup(writeup(slug, status));
        for tok in ["", "publisher", "other"] {
            let (st, headers, b) = send(
                &h.state,
                tok,
                "GET",
                &format!("/v0/public/exploited/{slug}"),
                Value::Null,
            )
            .await;
            assert_eq!(st, StatusCode::NOT_FOUND, "{slug} as {tok:?}: {b}");
            assert_eq!(headers["cache-control"], "public, max-age=60");
            assert_public_safe(&b);
        }
    }
    let (st, headers, list) = public(&h, "/v0/public/exploited").await;
    assert_eq!(st, StatusCode::OK);
    assert!(items(&list).is_empty(), "{list}");
    assert_eq!(headers["cache-control"], "public, max-age=60, s-maxage=60");
    assert_eq!(headers["x-content-type-options"], "nosniff");
    // Path tricks are 404 before any read.
    for slug in ["..%2f..%2fv0%2faudit", "Draft-One", "a--b", "%00"] {
        let (st, _, _) = public(&h, &format!("/v0/public/exploited/{slug}")).await;
        assert_eq!(st, StatusCode::NOT_FOUND, "{slug}");
    }
}

#[tokio::test]
async fn embargoed_pages_wait_and_the_list_follows() {
    let h = harness(NOW).await;
    let mut page = foiled_core::writeup::public_page(
        &writeup("embargoed", WriteUpStatus::Published),
        &Default::default(),
        NOW,
    );
    page.title = "Embargoed page".into();
    page.summary = "Not yet".into();
    page.body = vec![];
    page.visible_from = NOW + DAY;
    h.store.force_public_page("t1", "wu_x", page);
    let (st, _, _) = public(&h, "/v0/public/exploited/embargoed").await;
    assert_eq!(st, StatusCode::NOT_FOUND);
    let (_, _, list) = public(&h, "/v0/public/exploited").await;
    assert!(items(&list).is_empty());
    let mut later = h.state.clone();
    later.clock = Arc::new(|| NOW + 2 * DAY);
    let (st, _, b) = send(
        &later,
        "",
        "GET",
        "/v0/public/exploited/embargoed",
        Value::Null,
    )
    .await;
    assert_eq!(st, StatusCode::OK, "{b}");
}

#[tokio::test]
async fn published_page_holds_iocs_until_released_and_leaks_nothing() {
    let h = harness(NOW).await;
    // Approve every IOC publication candidate in the queue.
    let (_, q) = get(
        &h.state,
        "analyst",
        "/v0/review-queue?kind=ioc_publication&limit=200",
    )
    .await;
    let candidates = items(&q).clone();
    assert!(
        !candidates.is_empty(),
        "the fixture has research-sensor IOCs: {q}"
    );
    let mut ioc_ids = Vec::new();
    for c in &candidates {
        let id = c["item_id"].as_str().unwrap();
        let (st, b) = post(
            &h.state,
            "analyst",
            &format!("/v0/review-queue/{id}/actions"),
            json!({"action": "approve"}),
        )
        .await;
        assert_eq!(st, StatusCode::OK, "{b}");
        ioc_ids.push(c["subject"]["ioc_id"].clone());
    }
    ioc_ids.truncate(50);
    let (st, w) = post(
        &h.state,
        "analyst",
        "/v0/write-ups",
        json!({
            "slug": "fleet-wave",
            "title": "A wave of upload attempts",
            "summary": "We assess as attempts against FOILED-DEMO-0001.",
            "body_md": "We assess as attempts against FOILED-DEMO-0001. [advisory](https://advisories.example.invalid/x)\n\n<script>alert(1)</script>",
            "cve_ids": ["FOILED-DEMO-0001"],
            "ioc_ids": ioc_ids,
        }),
    )
    .await;
    assert_eq!(st, StatusCode::OK, "{w}");
    let id = w["writeup_id"].as_str().unwrap();
    // Raw HTML fails lint, so fix it before review.
    let (st, _, w) = send(
        &h.state,
        "analyst",
        "PATCH",
        &format!("/v0/write-ups/{id}"),
        json!({"body_md": "We assess as attempts against FOILED-DEMO-0001. [advisory](https://advisories.example.invalid/x)", "expected_version": 1}),
    )
    .await;
    assert_eq!(st, StatusCode::OK, "{w}");
    let checklist: Value = serde_json::from_str(CHECKLIST).unwrap();
    for (tok, body) in [
        ("analyst", json!({"to": "review"})),
        (
            "reviewer",
            json!({"to": "approved", "checklist": checklist}),
        ),
        ("publisher", json!({"to": "published"})),
    ] {
        let (st, b) = post(
            &h.state,
            tok,
            &format!("/v0/write-ups/{id}/transitions"),
            body,
        )
        .await;
        assert_eq!(st, StatusCode::OK, "{tok}: {b}");
    }

    // At publish time every IOC is still inside the 7-day delay.
    let (st, headers, page) = public(&h, "/v0/public/exploited/fleet-wave").await;
    assert_eq!(st, StatusCode::OK, "{page}");
    assert_eq!(page["iocs"], json!([]), "held IOCs are not shown");
    assert_public_safe(&page);
    assert_eq!(headers["cache-control"], "public, max-age=60, s-maxage=60");
    assert_eq!(headers["referrer-policy"], "no-referrer");

    // Eight days later they are released, defanged.
    let mut later = h.state.clone();
    later.clock = Arc::new(|| NOW + 8 * DAY);
    let (st, _, page) = send(
        &later,
        "",
        "GET",
        "/v0/public/exploited/fleet-wave",
        Value::Null,
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    let released = page["iocs"].as_array().unwrap();
    assert!(!released.is_empty(), "{page}");
    for i in released {
        assert_eq!(i["tlp"], "clear");
        assert!(i["release_at"].as_i64().unwrap() <= NOW + 8 * DAY);
        assert_eq!(
            i.as_object().unwrap().len(),
            5,
            "allow-listed fields only: {i}"
        );
    }
    assert_public_safe(&page);
    // Only IOCs from research sensors: the edge sensors never opted in.
    for edge in [
        "203.0.113.21",
        "203[.]0[.]113[.]21",
        "203.0.113.22",
        "203[.]0[.]113[.]22",
    ] {
        assert!(!page.to_string().contains(edge), "{edge}");
    }

    // A credentialed caller gets exactly the same public body.
    let (_, _, with_token) = send(
        &later,
        "other",
        "GET",
        "/v0/public/exploited/fleet-wave",
        Value::Null,
    )
    .await;
    assert_eq!(with_token, page);
    let (_, _, list) = send(&later, "", "GET", "/v0/public/exploited", Value::Null).await;
    assert_eq!(items(&list).len(), 1);
    assert_public_safe(&list);
}

#[tokio::test]
async fn public_reads_are_rate_limited_per_client_and_the_radar_is_not_public() {
    let h = harness(NOW).await;
    let read = |ip: &'static str| {
        let state = h.state.clone();
        async move {
            let req = http::Request::builder()
                .uri("/v0/public/exploited")
                .header("x-foiled-client-ip", ip)
                .body(axum::body::Body::empty())
                .unwrap();
            let res = tower::ServiceExt::oneshot(foiled_api::router(state), req)
                .await
                .unwrap();
            (
                res.status(),
                res.headers()
                    .get("cache-control")
                    .map(|v| v.to_str().unwrap().to_string()),
            )
        }
    };
    for _ in 0..foiled_api::routes::public::PUBLIC_READS_PER_MINUTE {
        assert_eq!(read("198.51.100.7").await.0, StatusCode::OK);
    }
    let (st, cache) = read("198.51.100.7").await;
    assert_eq!(st, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(cache.as_deref(), Some("no-store"));
    // Another client is unaffected.
    assert_eq!(read("198.51.100.8").await.0, StatusCode::OK);
    // The radar is trusted-side only.
    let (st, _, _) = public(&h, "/v0/public/radar").await;
    assert_eq!(st, StatusCode::NOT_FOUND);
}
