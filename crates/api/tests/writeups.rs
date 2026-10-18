//! `/v0/write-ups` (#35): draft, edit, lint, second reviewer, checklist,
//! publish rules (scope, publisher tenant, TLP, slug), embargo, withdraw,
//! versions and audit, with tenant isolation.

mod common;

use common::*;
use http::StatusCode;
use serde_json::{Value, json};

const NOW: i64 = 1_792_306_923_000;

fn clean_body() -> Value {
    json!({
        "slug": "demo-app-upload-path-traversal",
        "title": "Upload path traversal attempts against Demo App",
        "summary": "We assess as attempts against FOILED-DEMO-0001 from several sources.",
        "body_md": "## What we saw\n\nWe assess as attempts against FOILED-DEMO-0001: uploads that climb out of the upload directory.\n\nSource: [advisory](https://advisories.example.invalid/FOILED-DEMO-0001).\n",
        "cve_ids": ["foiled-demo-0001"],
        "technique_ids": ["T1190"],
        "redacted_payload": "POST /api/upload?path=../../tmp/.w HTTP/1.1\nAuthorization: Bearer abcdefghijklmnop0123456789",
    })
}

const CHECKLIST: &str = r#"{"tenant_data_removed": true, "wording_checked": true, "no_exploit_code": true, "payloads_redacted": true, "sources_linked": true, "delay_rules_checked": true}"#;

async fn create(h: &Harness, body: Value) -> Value {
    let (st, w) = post(&h.state, "analyst", "/v0/write-ups", body).await;
    assert_eq!(st, StatusCode::OK, "{w}");
    w
}

async fn to(h: &Harness, tok: &str, id: &str, body: Value) -> (StatusCode, Value) {
    post(
        &h.state,
        tok,
        &format!("/v0/write-ups/{id}/transitions"),
        body,
    )
    .await
}

/// Create, submit and approve (by `reviewer`).
async fn approved(h: &Harness, body: Value) -> String {
    let w = create(h, body).await;
    let id = w["writeup_id"].as_str().unwrap().to_string();
    assert_eq!(w["lint"], json!([]), "{w}");
    let (st, b) = to(h, "analyst", &id, json!({"to": "review"})).await;
    assert_eq!(st, StatusCode::OK, "{b}");
    let checklist: Value = serde_json::from_str(CHECKLIST).unwrap();
    let (st, b) = to(
        h,
        "reviewer",
        &id,
        json!({"to": "approved", "checklist": checklist}),
    )
    .await;
    assert_eq!(st, StatusCode::OK, "{b}");
    id
}

#[tokio::test]
async fn full_workflow_to_a_public_page() {
    let h = harness(NOW).await;
    let w = create(&h, clean_body()).await;
    let id = w["writeup_id"].as_str().unwrap().to_string();
    assert_eq!(w["status"], "draft");
    assert_eq!(w["cve_ids"], json!(["FOILED-DEMO-0001"]));
    assert!(
        !w["redacted_payload"]
            .as_str()
            .unwrap()
            .contains("abcdefghijklmnop0123456789"),
        "secrets are redacted on save: {w}"
    );

    // Edits need the version and only happen in draft.
    let (st, _, b) = send(
        &h.state,
        "analyst",
        "PATCH",
        &format!("/v0/write-ups/{id}"),
        json!({"title": "Upload path traversal attempts against Demo App 1.0"}),
    )
    .await;
    assert_eq!(st, StatusCode::BAD_REQUEST, "{b}");
    let (st, _, b) = send(
        &h.state,
        "analyst",
        "PATCH",
        &format!("/v0/write-ups/{id}"),
        json!({"title": "Upload path traversal attempts against Demo App 1.0", "expected_version": 1}),
    )
    .await;
    assert_eq!(st, StatusCode::OK, "{b}");
    assert_eq!(b["version"], 2);

    let (st, b) = to(&h, "analyst", &id, json!({"to": "published"})).await;
    assert_eq!(st, StatusCode::FORBIDDEN, "needs review:publish: {b}");
    let (st, b) = to(&h, "analyst", &id, json!({"to": "review"})).await;
    assert_eq!(st, StatusCode::OK, "{b}");
    let (st, _, _) = send(
        &h.state,
        "analyst",
        "PATCH",
        &format!("/v0/write-ups/{id}"),
        json!({"title": "x", "expected_version": 3}),
    )
    .await;
    assert_eq!(st, StatusCode::CONFLICT, "no edits in review");

    // It is in the review queue.
    let (_, q) = get(&h.state, "reviewer", "/v0/review-queue?kind=write_up").await;
    assert_eq!(items(&q).len(), 1);

    // The author cannot approve; the checklist must be complete.
    let checklist: Value = serde_json::from_str(CHECKLIST).unwrap();
    let (st, b) = to(
        &h,
        "analyst",
        &id,
        json!({"to": "approved", "checklist": checklist}),
    )
    .await;
    assert_eq!(st, StatusCode::UNPROCESSABLE_ENTITY, "{b}");
    assert_eq!(b["error"]["code"], "second_reviewer");
    let mut partial = checklist.clone();
    partial["sources_linked"] = json!(false);
    let (st, b) = to(
        &h,
        "reviewer",
        &id,
        json!({"to": "approved", "checklist": partial}),
    )
    .await;
    assert_eq!(st, StatusCode::UNPROCESSABLE_ENTITY, "{b}");
    // Approve through the queue instead of the transition route.
    let item = items(&q)[0]["item_id"].as_str().unwrap().to_string();
    let (st, b) = post(
        &h.state,
        "reviewer",
        &format!("/v0/review-queue/{item}/actions"),
        json!({"action": "approve", "checklist": checklist}),
    )
    .await;
    assert_eq!(st, StatusCode::OK, "{b}");
    assert_eq!(b["effect"], "writeup.approved");

    // Publish: scope and publisher tenant.
    let (st, b) = to(&h, "reviewer", &id, json!({"to": "published"})).await;
    assert_eq!(st, StatusCode::FORBIDDEN, "{b}");
    let (st, b) = to(&h, "publisher", &id, json!({"to": "published"})).await;
    assert_eq!(st, StatusCode::OK, "{b}");
    assert_eq!(b["status"], "published");

    let (st, page) = get(
        &h.state,
        "",
        "/v0/public/exploited/demo-app-upload-path-traversal",
    )
    .await;
    assert_eq!(st, StatusCode::OK, "{page}");
    assert_eq!(page["cves"][0]["wording"], "we assess as");
    assert_eq!(
        page["canonical_path"],
        "/exploited/demo-app-upload-path-traversal"
    );
    let text = page.to_string();
    for private in [
        "t1",
        "analyst",
        "reviewer",
        "publisher",
        "att_",
        "tenant_id",
    ] {
        assert!(
            !text.contains(&format!("\"{private}")),
            "{private} leaked: {text}"
        );
    }

    // Versions and audit.
    let (_, v) = get(&h.state, "reader", &format!("/v0/write-ups/{id}/versions")).await;
    let actions: Vec<&str> = items(&v)
        .iter()
        .map(|x| x["action"].as_str().unwrap())
        .collect();
    assert_eq!(
        actions,
        vec![
            "create",
            "edit",
            "transition.review",
            "transition.approved",
            "transition.published"
        ]
    );
    let audit: Vec<String> = h.store.audit().iter().map(|a| a.action.clone()).collect();
    for want in [
        "writeup.create",
        "writeup.edit",
        "writeup.review",
        "writeup.approved",
        "review.approve",
        "writeup.published",
    ] {
        assert!(audit.iter().any(|a| a == want), "{want}: {audit:?}");
    }

    // Withdraw takes the page down and purges its URLs from caches.
    let (st, b) = to(&h, "publisher", &id, json!({"to": "withdrawn"})).await;
    assert_eq!(st, StatusCode::OK, "{b}");
    let purges = h.purger.purges();
    assert_eq!(purges.len(), 2, "publish and withdraw both purge");
    assert!(purges[1].contains(&"/exploited/demo-app-upload-path-traversal".to_string()));
    let (st, _) = get(
        &h.state,
        "",
        "/v0/public/exploited/demo-app-upload-path-traversal",
    )
    .await;
    assert_eq!(st, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn embargo_tlp_and_slug_rules() {
    let h = harness(NOW).await;
    let mut body = clean_body();
    body["embargo_until"] = json!(NOW + 2 * DAY);
    let id = approved(&h, body).await;
    let (st, b) = to(&h, "publisher", &id, json!({"to": "published"})).await;
    assert_eq!(st, StatusCode::OK, "{b}");
    // Published but embargoed: not public yet.
    let (st, _) = get(
        &h.state,
        "",
        "/v0/public/exploited/demo-app-upload-path-traversal",
    )
    .await;
    assert_eq!(st, StatusCode::NOT_FOUND);
    let (_, list) = get(&h.state, "", "/v0/public/exploited").await;
    assert!(items(&list).is_empty());
    let mut later = h.state.clone();
    later.clock = std::sync::Arc::new(|| NOW + 3 * DAY);
    let (st, _) = get(
        &later,
        "",
        "/v0/public/exploited/demo-app-upload-path-traversal",
    )
    .await;
    assert_eq!(st, StatusCode::OK);

    // A second write-up cannot take the same slug.
    let id2 = approved(&h, clean_body()).await;
    let (st, b) = to(&h, "publisher", &id2, json!({"to": "published"})).await;
    assert_eq!(st, StatusCode::CONFLICT, "{b}");

    // TLP:GREEN never goes public.
    let mut green = clean_body();
    green["slug"] = json!("green-note");
    green["tlp"] = json!("green");
    let w = create(&h, green).await;
    let gid = w["writeup_id"].as_str().unwrap();
    assert!(
        w["lint"]
            .as_array()
            .unwrap()
            .iter()
            .all(|f| f["severity"] == "warning")
    );
    to(&h, "analyst", gid, json!({"to": "review"})).await;
    let checklist: Value = serde_json::from_str(CHECKLIST).unwrap();
    to(
        &h,
        "reviewer",
        gid,
        json!({"to": "approved", "checklist": checklist}),
    )
    .await;
    let (st, b) = to(&h, "publisher", gid, json!({"to": "published"})).await;
    assert_eq!(st, StatusCode::UNPROCESSABLE_ENTITY, "{b}");
    assert_eq!(b["error"]["code"], "tlp");
}

#[tokio::test]
async fn lint_blocks_tenant_data_and_unconfirmed_claims() {
    let h = harness(NOW).await;
    let mut body = clean_body();
    body["body_md"] = json!(
        "Attempts against FOILED-DEMO-0001 were confirmed at tenant t1 from 10.20.30.40. [src](https://a.example.invalid/)"
    );
    let w = create(&h, body).await;
    let rules: Vec<&str> = w["lint"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f["rule"].as_str().unwrap())
        .collect();
    for want in [
        "assessed-wording",
        "confirmed-without-analyst",
        "tenant-data",
        "ip-address",
    ] {
        assert!(rules.contains(&want), "{want}: {rules:?}");
    }
    let id = w["writeup_id"].as_str().unwrap();
    let (st, b) = to(&h, "analyst", id, json!({"to": "review"})).await;
    assert_eq!(st, StatusCode::UNPROCESSABLE_ENTITY, "{b}");
}

#[tokio::test]
async fn write_ups_are_tenant_scoped_and_publishing_needs_a_publisher_tenant() {
    let h = harness(NOW).await;
    let id = approved(&h, clean_body()).await;
    for path in [
        format!("/v0/write-ups/{id}"),
        format!("/v0/write-ups/{id}/versions"),
    ] {
        let (st, _) = get(&h.state, "other", &path).await;
        assert_eq!(st, StatusCode::NOT_FOUND, "{path}");
    }
    let (_, list) = get(&h.state, "other", "/v0/write-ups").await;
    assert!(items(&list).is_empty());
    let (st, _) = to(&h, "other", &id, json!({"to": "published"})).await;
    assert_eq!(st, StatusCode::FORBIDDEN, "t2 is not a publisher tenant");
    // Not found for the right tenant once publishing is allowed for t2.
    let mut st2 = h.state.clone();
    st2.publisher_tenants = std::sync::Arc::new(vec!["t1".into(), "t2".into()]);
    let (st, _) = to(
        &Harness {
            state: st2,
            store: h.store.clone(),
            sink: h.sink.clone(),
            purger: h.purger.clone(),
        },
        "other",
        &id,
        json!({"to": "published"}),
    )
    .await;
    assert_eq!(st, StatusCode::NOT_FOUND);
    let (st, _) = get(&h.state, "analyst", "/v0/write-ups/wu_..%2f..").await;
    assert_eq!(st, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn a_reviewer_who_edited_cannot_approve_alone() {
    let h = harness(NOW).await;
    let w = create(&h, clean_body()).await;
    let id = w["writeup_id"].as_str().unwrap().to_string();
    let (st, _) = to(&h, "analyst", &id, json!({"to": "review"})).await;
    assert_eq!(st, StatusCode::OK);
    // The reviewer sends it back, edits it, resubmits and tries to approve.
    let (st, b) = to(
        &h,
        "reviewer",
        &id,
        json!({"to": "draft", "note": "tighten the summary"}),
    )
    .await;
    assert_eq!(st, StatusCode::OK, "{b}");
    let (st, _, b) = send(
        &h.state,
        "reviewer",
        "PATCH",
        &format!("/v0/write-ups/{id}"),
        json!({"summary": "We assess as attempts against FOILED-DEMO-0001.", "expected_version": 3}),
    )
    .await;
    assert_eq!(st, StatusCode::OK, "{b}");
    let (st, _) = to(&h, "reviewer", &id, json!({"to": "review"})).await;
    assert_eq!(st, StatusCode::OK);
    let checklist: Value = serde_json::from_str(CHECKLIST).unwrap();
    let (st, b) = to(
        &h,
        "reviewer",
        &id,
        json!({"to": "approved", "checklist": checklist}),
    )
    .await;
    assert_eq!(st, StatusCode::UNPROCESSABLE_ENTITY, "{b}");
    assert_eq!(b["error"]["code"], "second_reviewer");
    // Nor through the queue.
    let (_, q) = get(&h.state, "reviewer", "/v0/review-queue?kind=write_up").await;
    let item = items(&q)[0]["item_id"].as_str().unwrap().to_string();
    let (st, b) = post(
        &h.state,
        "reviewer",
        &format!("/v0/review-queue/{item}/actions"),
        json!({"action": "approve", "checklist": checklist}),
    )
    .await;
    assert_eq!(st, StatusCode::UNPROCESSABLE_ENTITY, "{b}");
    // The failed effect leaves the item open to decide again.
    let (_, q) = get(&h.state, "reviewer", "/v0/review-queue?kind=write_up").await;
    assert_eq!(items(&q)[0]["status"], "open");
    // The author also edited, so only a third person can approve.
    let (st, _) = to(
        &h,
        "analyst",
        &id,
        json!({"to": "approved", "checklist": checklist}),
    )
    .await;
    assert_eq!(st, StatusCode::UNPROCESSABLE_ENTITY);
    let (st, b) = to(
        &h,
        "publisher",
        &id,
        json!({"to": "approved", "checklist": checklist}),
    )
    .await;
    assert_eq!(st, StatusCode::OK, "{b}");
}

#[tokio::test]
async fn a_publish_that_loses_a_race_leaves_the_winner_alone() {
    let h = harness(NOW).await;
    let id = approved(&h, clean_body()).await;
    let (_, w) = get(&h.state, "publisher", &format!("/v0/write-ups/{id}")).await;
    let v = w["version"].as_i64().unwrap();
    let (st, b) = to(
        &h,
        "publisher",
        &id,
        json!({"to": "published", "expected_version": v}),
    )
    .await;
    assert_eq!(st, StatusCode::OK, "{b}");
    let (_, page) = get(
        &h.state,
        "",
        "/v0/public/exploited/demo-app-upload-path-traversal",
    )
    .await;
    // A second publish that read the same version loses and changes nothing.
    let (st, _) = to(
        &h,
        "publisher",
        &id,
        json!({"to": "published", "expected_version": v}),
    )
    .await;
    assert_eq!(st, StatusCode::CONFLICT);
    let (st, again) = get(
        &h.state,
        "",
        "/v0/public/exploited/demo-app-upload-path-traversal",
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(again, page);
    // A different write-up with the same slug loses too, and is put back
    // to approved without touching the winner's page.
    let id2 = approved(&h, clean_body()).await;
    let (st, _) = to(&h, "publisher", &id2, json!({"to": "published"})).await;
    assert_eq!(st, StatusCode::CONFLICT);
    let (_, w2) = get(&h.state, "publisher", &format!("/v0/write-ups/{id2}")).await;
    assert_eq!(w2["status"], "approved");
    let (_, after) = get(
        &h.state,
        "",
        "/v0/public/exploited/demo-app-upload-path-traversal",
    )
    .await;
    assert_eq!(after, page);
}

#[tokio::test]
async fn a_failed_withdrawal_leaves_it_published_and_can_be_retried() {
    let h = harness(NOW).await;
    let id = approved(&h, clean_body()).await;
    let (st, _) = to(&h, "publisher", &id, json!({"to": "published"})).await;
    assert_eq!(st, StatusCode::OK);
    h.store.fail_page_removal(true);
    let (st, b) = to(&h, "publisher", &id, json!({"to": "withdrawn"})).await;
    assert_eq!(st, StatusCode::SERVICE_UNAVAILABLE, "{b}");
    let (_, w) = get(&h.state, "publisher", &format!("/v0/write-ups/{id}")).await;
    assert_eq!(
        w["status"], "published",
        "still published, so it can be retried"
    );
    h.store.fail_page_removal(false);
    let (st, b) = to(&h, "publisher", &id, json!({"to": "withdrawn"})).await;
    assert_eq!(st, StatusCode::OK, "{b}");
    let (st, _) = get(
        &h.state,
        "",
        "/v0/public/exploited/demo-app-upload-path-traversal",
    )
    .await;
    assert_eq!(st, StatusCode::NOT_FOUND);
    // Withdrawing again retries the removal and purge, and changes nothing.
    let purges = h.purger.purges().len();
    let (st, b) = to(&h, "publisher", &id, json!({"to": "withdrawn"})).await;
    assert_eq!(st, StatusCode::OK, "{b}");
    assert_eq!(b["version"], w["version"].as_i64().unwrap() + 1);
    assert_eq!(h.purger.purges().len(), purges + 1);
}

#[tokio::test]
async fn a_slug_clash_whose_revert_fails_is_reported() {
    let h = harness(NOW).await;
    let first = approved(&h, clean_body()).await;
    let (st, _) = to(&h, "publisher", &first, json!({"to": "published"})).await;
    assert_eq!(st, StatusCode::OK);
    let (_, before) = get(
        &h.state,
        "",
        "/v0/public/exploited/demo-app-upload-path-traversal",
    )
    .await;
    let second = approved(&h, clean_body()).await;
    h.store.fail_writeup_update_for("revert.publish");
    let (st, b) = to(&h, "publisher", &second, json!({"to": "published"})).await;
    assert_eq!(st, StatusCode::CONFLICT, "{b}");
    assert_eq!(b["error"]["code"], "publish_incomplete");
    assert!(
        h.store
            .audit()
            .iter()
            .any(|a| a.action == "writeup.publish_revert_failed"
                && a.outcome == foiled_core::audit::Outcome::Failed)
    );
    // The first write-up's page is untouched.
    let (st, page) = get(
        &h.state,
        "",
        "/v0/public/exploited/demo-app-upload-path-traversal",
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(page, before);
}
