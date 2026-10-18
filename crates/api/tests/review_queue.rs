//! `/v0/review-queue` (#35) over the fleet-wave fixture: derived items,
//! tenant scoping, claim and decide with audit, decisions recorded where
//! they belong, snooze, compare-and-set and promotion to a write-up.

mod common;

use common::*;
use http::StatusCode;
use serde_json::{Value, json};

const NOW: i64 = 1_792_306_923_000;

async fn queue(h: &Harness, tok: &str, query: &str) -> Vec<Value> {
    let (st, b) = get(&h.state, tok, &format!("/v0/review-queue{query}")).await;
    assert_eq!(st, StatusCode::OK, "{b}");
    items(&b).clone()
}

fn of_kind<'a>(items: &'a [Value], kind: &str) -> Vec<&'a Value> {
    items.iter().filter(|i| i["kind"] == kind).collect()
}

#[tokio::test]
async fn queue_is_derived_sorted_and_tenant_scoped() {
    let h = harness(NOW).await;
    let all = queue(&h, "analyst", "").await;
    assert!(!of_kind(&all, "cve_link").is_empty(), "{all:#?}");
    assert!(!of_kind(&all, "campaign_label").is_empty(), "{all:#?}");
    for i in &all {
        assert_eq!(i["tenant_id"], "t1");
        assert_eq!(i["status"], "open");
        assert!(i["item_id"].as_str().unwrap().starts_with("rq_"));
        assert!(i["sla_due_at"].as_i64().unwrap() > i["created_at"].as_i64().unwrap());
    }
    let prio: Vec<i64> = all
        .iter()
        .map(|i| i["priority"].as_i64().unwrap())
        .collect();
    let mut sorted = prio.clone();
    sorted.sort_by(|a, b| b.cmp(a));
    assert_eq!(prio, sorted, "highest priority first");
    // CVE link titles keep the cautious wording.
    for i in of_kind(&all, "cve_link") {
        assert!(
            i["title"].as_str().unwrap().starts_with("We assess as"),
            "{i}"
        );
    }
    // Filters.
    let cves = queue(&h, "analyst", "?kind=cve_link").await;
    assert!(cves.iter().all(|i| i["kind"] == "cve_link"));
    // Another tenant sees none of it, and cannot read t1's items by id.
    assert!(queue(&h, "other", "").await.is_empty());
    let id = all[0]["item_id"].as_str().unwrap();
    let (st, _) = get(&h.state, "other", &format!("/v0/review-queue/{id}")).await;
    assert_eq!(st, StatusCode::NOT_FOUND);
    let (st, _) = get(&h.state, "nobody", "/v0/review-queue").await;
    assert_eq!(st, StatusCode::FORBIDDEN);
    let (st, _) = get(&h.state, "analyst", "/v0/review-queue/rq_..%2f..").await;
    assert_eq!(st, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn claim_approve_records_the_override_and_audits() {
    let h = harness(NOW).await;
    let all = queue(&h, "analyst", "?kind=cve_link").await;
    let item = all[0].clone();
    let id = item["item_id"].as_str().unwrap().to_string();
    let path = format!("/v0/review-queue/{id}/actions");
    let attempt = item["subject"]["attempt_id"].as_str().unwrap().to_string();
    let target = item["subject"]["target"].as_str().unwrap().to_string();

    let (st, b) = post(&h.state, "reader", &path, json!({"action": "claim"})).await;
    assert_eq!(st, StatusCode::FORBIDDEN, "{b}");
    let (st, b) = post(&h.state, "analyst", &path, json!({"action": "claim"})).await;
    assert_eq!(st, StatusCode::OK, "{b}");
    assert_eq!(b["item"]["status"], "claimed");
    assert_eq!(b["item"]["assignee"], "analyst");
    // Someone else cannot decide a claimed item.
    let (st, b) = post(&h.state, "reviewer", &path, json!({"action": "approve"})).await;
    assert_eq!(st, StatusCode::CONFLICT, "{b}");
    // Stale versions are refused.
    let (st, _) = post(
        &h.state,
        "analyst",
        &path,
        json!({"action": "approve", "expected_version": 0}),
    )
    .await;
    assert_eq!(st, StatusCode::CONFLICT);
    let (st, b) = post(
        &h.state,
        "analyst",
        &path,
        json!({"action": "approve", "note": "hook fired on the vulnerable path", "expected_version": 1}),
    )
    .await;
    assert_eq!(st, StatusCode::OK, "{b}");
    assert_eq!(b["item"]["status"], "approved");
    assert_eq!(b["item"]["decided_by"], "analyst");
    assert_eq!(b["effect"], "link.override true_positive");
    // Final: no second decision.
    let (st, _) = post(
        &h.state,
        "analyst",
        &path,
        json!({"action": "reject", "note": "x"}),
    )
    .await;
    assert_eq!(st, StatusCode::CONFLICT);
    // The link now reads confirmed on the attempt.
    let (st, links) = get(
        &h.state,
        "analyst",
        &format!("/v0/attempts/{attempt}/links"),
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    let link = items(&links)
        .iter()
        .find(|l| l["kind"] == "attempt_cve" && l["target"] == target.as_str())
        .unwrap();
    assert_eq!(link["wording"], "confirmed");
    // Pending lists drop it; approved lists show it.
    assert!(
        !queue(&h, "analyst", "")
            .await
            .iter()
            .any(|i| i["item_id"] == id.as_str())
    );
    assert!(
        queue(&h, "analyst", "?status=approved")
            .await
            .iter()
            .any(|i| i["item_id"] == id.as_str())
    );
    let audit: Vec<String> = h.store.audit().iter().map(|a| a.action.clone()).collect();
    for want in ["review.claim", "link.override", "review.approve"] {
        assert!(audit.iter().any(|a| a == want), "{want}: {audit:?}");
    }
}

#[tokio::test]
async fn decisions_made_on_the_attempt_show_as_decided() {
    let h = harness(NOW).await;
    let item = queue(&h, "analyst", "?kind=cve_link").await[0].clone();
    let attempt = item["subject"]["attempt_id"].as_str().unwrap();
    let (st, b) = post(
        &h.state,
        "publisher",
        &format!("/v0/attempts/{attempt}/links"),
        json!({"kind": "attempt_cve", "target": item["subject"]["target"], "feedback": "true_positive", "note": "seen in pcap"}),
    )
    .await;
    assert_eq!(st, StatusCode::OK, "{b}");
    let id = item["item_id"].as_str().unwrap();
    let approved = queue(&h, "analyst", "?status=approved").await;
    let got = approved.iter().find(|i| i["item_id"] == id).unwrap();
    assert_eq!(got["decided_by"], "publisher");
    let (st, _) = post(
        &h.state,
        "analyst",
        &format!("/v0/review-queue/{id}/actions"),
        json!({"action": "reject", "note": "x"}),
    )
    .await;
    assert_eq!(st, StatusCode::CONFLICT, "already decided on the attempt");
}

#[tokio::test]
async fn reject_needs_a_note_and_records_a_false_positive() {
    let h = harness(NOW).await;
    let item = queue(&h, "analyst", "?kind=cve_link").await[0].clone();
    let attempt = item["subject"]["attempt_id"].as_str().unwrap();
    let (st, b) = post(
        &h.state,
        "analyst",
        &format!("/v0/attempts/{attempt}/links"),
        json!({"kind": "attempt_cve", "target": item["subject"]["target"], "feedback": "false_positive", "note": "scanner"}),
    )
    .await;
    assert_eq!(
        st,
        StatusCode::FORBIDDEN,
        "analyst lacks attempts:write: {b}"
    );
    let id = item["item_id"].as_str().unwrap();
    let (st, b) = post(
        &h.state,
        "analyst",
        &format!("/v0/review-queue/{id}/actions"),
        json!({"action": "reject", "note": ""}),
    )
    .await;
    assert_eq!(st, StatusCode::BAD_REQUEST, "reject needs a note: {b}");
    let (st, b) = post(
        &h.state,
        "analyst",
        &format!("/v0/review-queue/{id}/actions"),
        json!({"action": "reject", "note": "mass scanner, not targeted"}),
    )
    .await;
    assert_eq!(st, StatusCode::OK, "{b}");
    assert_eq!(b["effect"], "link.override false_positive");
    let rejected = queue(&h, "analyst", "?status=rejected").await;
    assert!(rejected.iter().any(|i| i["item_id"] == id));
}

#[tokio::test]
async fn snooze_assign_and_release() {
    let h = harness(NOW).await;
    let item = queue(&h, "analyst", "").await[0].clone();
    let id = item["item_id"].as_str().unwrap();
    let path = format!("/v0/review-queue/{id}/actions");
    let (st, _) = post(
        &h.state,
        "analyst",
        &path,
        json!({"action": "snooze", "until": NOW + 40 * DAY}),
    )
    .await;
    assert_eq!(st, StatusCode::BAD_REQUEST, "at most 30 days");
    let (st, b) = post(
        &h.state,
        "analyst",
        &path,
        json!({"action": "snooze", "until": NOW + DAY, "note": "waiting on advisory"}),
    )
    .await;
    assert_eq!(st, StatusCode::OK, "{b}");
    assert_eq!(b["item"]["status"], "snoozed");
    assert_eq!(b["item"]["priority"], 0);
    let (st, b) = post(
        &h.state,
        "analyst",
        &path,
        json!({"action": "assign", "assignee": "reviewer"}),
    )
    .await;
    assert_eq!(st, StatusCode::OK, "{b}");
    let mine = queue(&h, "reviewer", "?assignee=me").await;
    assert_eq!(mine.len(), 1);
    let (st, _) = post(&h.state, "analyst", &path, json!({"action": "release"})).await;
    assert_eq!(st, StatusCode::CONFLICT, "only the assignee releases");
    let (st, b) = post(&h.state, "reviewer", &path, json!({"action": "release"})).await;
    assert_eq!(st, StatusCode::OK, "{b}");
    assert_eq!(b["item"]["status"], "open");
    let (st, _) = post(
        &h.state,
        "analyst",
        &path,
        json!({"action": "assign", "assignee": "<script>"}),
    )
    .await;
    assert_eq!(st, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn campaign_label_approval_records_campaign_actions() {
    let h = harness(NOW).await;
    let item = queue(&h, "analyst", "?kind=campaign_label").await[0].clone();
    let id = item["item_id"].as_str().unwrap();
    let (st, b) = post(
        &h.state,
        "analyst",
        &format!("/v0/review-queue/{id}/actions"),
        json!({"action": "approve", "label": "Upload path wave", "note": "same payload hash"}),
    )
    .await;
    assert_eq!(st, StatusCode::OK, "{b}");
    assert_eq!(b["effect"], "campaign.label, campaign.feedback");
    let cid = item["subject"]["campaign_id"].as_str().unwrap();
    let (st, c) = get(&h.state, "analyst", &format!("/v0/campaigns/{cid}")).await;
    assert_eq!(st, StatusCode::OK, "{c}");
    assert_eq!(c["title"], "Upload path wave");
    assert_eq!(c["confidence"]["wording"], "confirmed");
}

#[tokio::test]
async fn promote_starts_a_draft_that_lint_holds_back() {
    let h = harness(NOW).await;
    let item = queue(&h, "analyst", "?kind=cve_link").await[0].clone();
    let id = item["item_id"].as_str().unwrap();
    let (st, b) = post(
        &h.state,
        "analyst",
        &format!("/v0/review-queue/{id}/actions"),
        json!({"action": "promote"}),
    )
    .await;
    assert_eq!(st, StatusCode::OK, "{b}");
    let wid = b["writeup_id"].as_str().unwrap();
    let (st, w) = get(&h.state, "analyst", &format!("/v0/write-ups/{wid}")).await;
    assert_eq!(st, StatusCode::OK, "{w}");
    assert_eq!(w["status"], "draft");
    assert_eq!(w["source_item_id"], id);
    assert_eq!(w["cve_ids"][0], item["subject"]["target"]);
    let rules: Vec<&str> = w["lint"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f["rule"].as_str().unwrap())
        .collect();
    assert!(rules.contains(&"placeholder"), "{rules:?}");
    let (st, b) = post(
        &h.state,
        "analyst",
        &format!("/v0/write-ups/{wid}/transitions"),
        json!({"to": "review"}),
    )
    .await;
    assert_eq!(st, StatusCode::UNPROCESSABLE_ENTITY, "{b}");
    assert_eq!(b["error"]["code"], "lint_failed");
}

/// Golden: the fleet-wave queue, one file per item in queue order, in
/// `testdata/review/expected/` (validated against
/// `schemas/review-item.schema.json` by the repository lint). Regenerate
/// with FOILED_BLESS=1 and review the diff.
#[tokio::test]
async fn fleet_wave_queue_matches_golden() {
    let h = harness(NOW).await;
    let all = queue(&h, "analyst", "?limit=200").await;
    let dir = std::path::Path::new(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../testdata/review/expected"
    ));
    if std::env::var("FOILED_BLESS").is_ok() {
        for e in std::fs::read_dir(dir).unwrap() {
            std::fs::remove_file(e.unwrap().path()).unwrap();
        }
        for (i, item) in all.iter().enumerate() {
            std::fs::write(
                dir.join(format!("fleet-wave-{i:02}.json")),
                serde_json::to_string_pretty(item).unwrap() + "\n",
            )
            .unwrap();
        }
    }
    let mut files: Vec<_> = std::fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().path())
        .collect();
    files.sort();
    let want: Vec<Value> = files
        .iter()
        .map(|p| serde_json::from_str(&std::fs::read_to_string(p).unwrap()).unwrap())
        .collect();
    assert_eq!(all, want, "rerun with FOILED_BLESS=1 and review the diff");
}

/// Two established campaigns that one source's attempts bridge: clustering
/// refuses the join and the queue proposes the merge (#33 possible links).
fn bridged_fleet() -> Vec<foiled_core::capture::CaptureEvent> {
    const T0: i64 = 1_792_285_323_000;
    let a = "ab".repeat(32);
    let b = "cd".repeat(32);
    let ev = |id: &str, ts: i64, decoy: &str, src: &str, hash: &str| {
        serde_json::from_value(json!({
            "event_id": id, "ts": ts, "decoy_id": decoy, "catalogue_id": "foiled/demo-app/1.0.0",
            "decoy_kind": "sandbox", "channel": "application", "severity": "info",
            "src": {"ip": src}, "tenant_id": "t2",
            "source": {"kind": "sensor", "id": format!("sensor-{decoy}")},
            "data": {"method": "POST", "path": "/api/upload", "body_sha256": hash}
        }))
        .unwrap()
    };
    vec![
        ev("a1", T0, "d1", "203.0.113.1", &a),
        ev("a2", T0 + 10, "d2", "203.0.113.2", &a),
        ev("a3", T0 + 20, "d3", "203.0.113.3", &a),
        ev("b1", T0 + 30, "d4", "198.51.100.1", &b),
        ev("b2", T0 + 40, "d5", "198.51.100.2", &b),
        ev("b3", T0 + 50, "d6", "198.51.100.3", &b),
        ev("f1", T0 + 60, "dz", "192.0.2.66", &a),
        ev("f2", T0 + 61, "dz", "192.0.2.66", &b),
    ]
}

#[tokio::test]
async fn bridged_campaigns_become_a_merge_proposal() {
    use foiled_api::store::Store;
    let h = harness(NOW).await;
    h.store.enqueue_events(bridged_fleet()).await.unwrap();
    let merges = queue(&h, "other", "?kind=campaign_merge").await;
    assert_eq!(merges.len(), 1, "one item per pair: {merges:#?}");
    let m = &merges[0];
    assert!(m["title"].as_str().unwrap().contains("192[.]0[.]2[.]66"));
    let keep = m["subject"]["campaign_id"].as_str().unwrap().to_string();
    let fold = m["subject"]["other_campaign_id"]
        .as_str()
        .unwrap()
        .to_string();
    let id = m["item_id"].as_str().unwrap();
    let (st, b) = post(
        &h.state,
        "other",
        &format!("/v0/review-queue/{id}/actions"),
        json!({"action": "approve", "note": "same operator, two payloads"}),
    )
    .await;
    assert_eq!(st, StatusCode::OK, "{b}");
    assert_eq!(b["effect"], "campaign.merge");
    let (st, c) = get(&h.state, "other", &format!("/v0/campaigns/{keep}")).await;
    assert_eq!(st, StatusCode::OK, "{c}");
    assert!(
        c["analyst"]["merged_from"]
            .as_array()
            .unwrap()
            .iter()
            .any(|x| x == fold.as_str()),
        "{c}"
    );
    // t1 never sees t2's proposal.
    assert!(
        queue(&h, "analyst", "?kind=campaign_merge")
            .await
            .is_empty()
    );
}

#[tokio::test]
async fn unsure_feedback_becomes_a_second_opinion_item() {
    let h = harness(NOW).await;
    let item = queue(&h, "analyst", "?kind=cve_link").await[0].clone();
    let attempt = item["subject"]["attempt_id"].as_str().unwrap();
    let (st, b) = post(
        &h.state,
        "publisher",
        &format!("/v0/attempts/{attempt}/links"),
        json!({"kind": "attempt_cve", "target": item["subject"]["target"], "feedback": "unsure", "note": "customer reports a scanner"}),
    )
    .await;
    assert_eq!(st, StatusCode::OK, "{b}");
    let fp = queue(&h, "analyst", "?kind=false_positive_feedback").await;
    assert_eq!(fp.len(), 1, "{fp:#?}");
    assert_eq!(fp[0]["status"], "open");
    let id = fp[0]["item_id"].as_str().unwrap();
    let (st, b) = post(
        &h.state,
        "analyst",
        &format!("/v0/review-queue/{id}/actions"),
        json!({"action": "reject", "note": "scanner traffic, not targeted"}),
    )
    .await;
    assert_eq!(st, StatusCode::OK, "{b}");
    assert_eq!(b["effect"], "link.override false_positive");
}

#[tokio::test]
async fn actor_links_from_the_actor_engine_are_reviewed_in_the_queue() {
    let mut h = harness(NOW).await;
    h.state.actors = std::sync::Arc::new(actor_catalogue());
    let actors = queue(&h, "analyst", "?kind=actor_association").await;
    assert_eq!(actors.len(), 1, "{actors:#?}");
    let a = &actors[0];
    assert_eq!(a["wording"], "possible association");
    let title = a["title"].as_str().unwrap().to_lowercase();
    assert!(title.contains("possible association"), "{a}");
    let id = a["item_id"].as_str().unwrap();
    let path = format!("/v0/review-queue/{id}/actions");
    // A confirmation needs a note; the failed effect leaves the item open.
    let (st, b) = post(&h.state, "analyst", &path, json!({"action": "approve"})).await;
    assert_eq!(st, StatusCode::BAD_REQUEST, "{b}");
    assert_eq!(
        queue(&h, "analyst", "?kind=actor_association").await[0]["status"],
        "open"
    );
    let (st, b) = post(
        &h.state,
        "analyst",
        &path,
        json!({"action": "approve", "note": "techniques and infrastructure match the public report"}),
    )
    .await;
    assert_eq!(st, StatusCode::OK, "{b}");
    assert_eq!(b["effect"], "actor_link.confirm");
    // Recorded by the actor engine: the link now reads confirmed.
    let (_, links) = get(&h.state, "analyst", "/v0/actor-links?status=confirmed").await;
    assert_eq!(items(&links).len(), 1, "{links}");
    let decided = queue(&h, "analyst", "?kind=actor_association&status=approved").await;
    assert_eq!(decided.len(), 1);
}

#[tokio::test]
async fn retried_decisions_never_duplicate_their_effects() {
    use foiled_api::store::Store;
    let h = harness(NOW).await;
    let item = queue(&h, "analyst", "?kind=campaign_label").await[0].clone();
    let id = item["item_id"].as_str().unwrap().to_string();
    let path = format!("/v0/review-queue/{id}/actions");
    let body = json!({"action": "approve", "label": "Upload path wave", "note": "same payload"});
    let (st, b) = post(&h.state, "analyst", &path, body.clone()).await;
    assert_eq!(st, StatusCode::OK, "{b}");
    let actions = h.store.campaign_action_count("t1");
    // As if recording the decision had failed after the effect: the item
    // is stuck as needs_attention.
    let mut stuck = h.store.review_states("t1", vec![id.clone()]).await.unwrap()[0].clone();
    let v = stuck.version;
    stuck.status = foiled_core::review::ReviewStatus::NeedsAttention;
    stuck.pending = Some(foiled_core::review::ActionKind::Approve);
    stuck.version = v + 1;
    stuck.updated_at = NOW;
    assert!(h.store.put_review_state("t1", stuck, v).await.unwrap());
    let shown = queue(&h, "analyst", "?status=needs_attention").await;
    assert_eq!(shown.len(), 1);
    assert!(
        shown[0]["priority"].as_i64().unwrap() >= 2_000,
        "first in the queue"
    );
    // Within the lease nobody can act on it.
    let (st, _) = post(&h.state, "analyst", &path, body.clone()).await;
    assert_eq!(st, StatusCode::CONFLICT);
    // After it, a retry records the decision without new campaign actions.
    let mut later = h.state.clone();
    later.clock = std::sync::Arc::new(|| NOW + 120_000);
    let (st, b) = post(&later, "analyst", &path, body).await;
    assert_eq!(st, StatusCode::OK, "{b}");
    assert_eq!(b["item"]["status"], "approved");
    assert_eq!(h.store.campaign_action_count("t1"), actions);
}

#[tokio::test]
async fn a_failed_rollback_is_audited_and_needs_attention() {
    let h = harness(NOW).await;
    // A write-up approval without the checklist fails its effect.
    let (st, w) = post(
        &h.state,
        "analyst",
        "/v0/write-ups",
        json!({
            "slug": "rollback-case",
            "title": "Upload attempts against Demo App",
            "summary": "We assess as attempts against FOILED-DEMO-0001.",
            "body_md": "We assess as attempts against FOILED-DEMO-0001. [advisory](https://advisories.example.invalid/x)",
            "cve_ids": ["FOILED-DEMO-0001"],
        }),
    )
    .await;
    assert_eq!(st, StatusCode::OK, "{w}");
    let wid = w["writeup_id"].as_str().unwrap();
    let (st, _) = post(
        &h.state,
        "analyst",
        &format!("/v0/write-ups/{wid}/transitions"),
        json!({"to": "review"}),
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    let item = queue(&h, "reviewer", "?kind=write_up").await[0].clone();
    let path = format!(
        "/v0/review-queue/{}/actions",
        item["item_id"].as_str().unwrap()
    );
    h.store.fail_review_rollback(true);
    let (st, b) = post(&h.state, "reviewer", &path, json!({"action": "approve"})).await;
    assert_eq!(st, StatusCode::UNPROCESSABLE_ENTITY, "{b}");
    assert!(
        h.store
            .audit()
            .iter()
            .any(|a| a.action == "review.rollback_failed"
                && a.outcome == foiled_core::audit::Outcome::Failed)
    );
    let stuck = queue(&h, "reviewer", "?kind=write_up&status=needs_attention").await;
    assert_eq!(stuck.len(), 1);
}
