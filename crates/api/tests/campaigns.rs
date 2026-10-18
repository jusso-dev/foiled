//! `/v0/campaigns` over the fleet-wave fixture (#33): tenant scoping,
//! filters, member attempts, evidence, `campaign_id` on attempts and IOCs,
//! and audited analyst actions.

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

async fn harness() -> (AppState, Arc<MemoryStore>) {
    let store = Arc::new(MemoryStore::new());
    for (id, tenant, scopes) in [
        (
            "analyst",
            "t1",
            vec![Scope::CampaignsRead, Scope::AttemptsRead, Scope::IocsRead],
        ),
        (
            "lead",
            "t1",
            vec![
                Scope::CampaignsRead,
                Scope::CampaignsWrite,
                Scope::AttemptsRead,
            ],
        ),
        ("camponly", "t1", vec![Scope::CampaignsRead]),
        ("nobody", "t1", vec![Scope::AttemptsRead]),
        (
            "other",
            "t2",
            vec![Scope::CampaignsRead, Scope::CampaignsWrite],
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
            "/../../testdata/campaigns/fleet-wave.input.json"
        ))
        .unwrap(),
    )
    .unwrap();
    let events: Vec<CaptureEvent> = serde_json::from_value(raw["events"].clone()).unwrap();
    store.enqueue_events(events).await.unwrap();
    let now = raw["now"].as_i64().unwrap();
    for (ip, asn) in raw["asns"].as_object().unwrap() {
        store.add_facts(
            "t1",
            ObservedFacts {
                observable: Observable::ip(ip).unwrap(),
                facts: vec![Fact {
                    provider: "local_asn".into(),
                    key: "asn.number".into(),
                    value: asn.clone(),
                    confidence: 90,
                    observed_at: now,
                    ttl_secs: 604_800,
                    raw_ref: None,
                }],
            },
        );
    }
    let mut state = AppState::new(store.clone(), Arc::new(move || now));
    let ids = std::sync::Mutex::new(0u32);
    state.ids = Arc::new(move || {
        let mut g = ids.lock().unwrap();
        *g += 1;
        format!("id-{:04}", *g)
    });
    (state, store)
}

async fn send(
    state: &AppState,
    tok: &str,
    method: &str,
    path: &str,
    body: Value,
) -> (StatusCode, Value) {
    let req = Request::builder()
        .method(method)
        .uri(path)
        .header("authorization", format!("Bearer fo_{tok}.{SECRET}"))
        .header("content-type", "application/json")
        .body(if body.is_null() {
            Body::empty()
        } else {
            Body::from(body.to_string())
        })
        .unwrap();
    let res = router(state.clone()).oneshot(req).await.unwrap();
    let status = res.status();
    let bytes = res.into_body().collect().await.unwrap().to_bytes();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

async fn get(state: &AppState, tok: &str, path: &str) -> (StatusCode, Value) {
    send(state, tok, "GET", path, Value::Null).await
}

fn items(b: &Value) -> &Vec<Value> {
    b["items"].as_array().unwrap()
}

/// The payload-hash wave (three sensors) and the stage-2 pair.
async fn ids(s: &AppState) -> (String, String) {
    let (st, b) = get(s, "analyst", "/v0/campaigns").await;
    assert_eq!(st, StatusCode::OK, "{b}");
    let all = items(&b);
    assert_eq!(all.len(), 2, "{b}");
    let wave = all
        .iter()
        .find(|c| c["attempt_ids"].as_array().unwrap().len() == 3)
        .unwrap();
    let pair = all
        .iter()
        .find(|c| c["attempt_ids"].as_array().unwrap().len() == 2)
        .unwrap();
    (
        wave["campaign_id"].as_str().unwrap().to_string(),
        pair["campaign_id"].as_str().unwrap().to_string(),
    )
}

#[tokio::test]
async fn list_is_tenant_scoped_filtered_and_newest_first() {
    let (s, _) = harness().await;
    let (st, b) = get(&s, "analyst", "/v0/campaigns").await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(b["truncated"], false);
    let all = items(&b);
    assert_eq!(all.len(), 2);
    assert!(all[0]["last_seen"].as_i64() >= all[1]["last_seen"].as_i64());
    assert!(all.iter().all(|c| c["tenant_scope"] == "tenant"));
    assert!(all.iter().all(|c| c["suggested_actor_links"] == json!([])));
    let (wave, pair) = ids(&s).await;

    let (_, b) = get(&s, "analyst", "/v0/campaigns?status=active").await;
    assert_eq!(items(&b).len(), 1);
    assert_eq!(items(&b)[0]["campaign_id"], wave.as_str());
    let (_, b) = get(&s, "analyst", "/v0/campaigns?sensor_id=sensor-sgp-1").await;
    assert_eq!(items(&b)[0]["campaign_id"], wave.as_str());
    let (_, b) = get(&s, "analyst", "/v0/campaigns?cve=foiled-demo-0001").await;
    assert_eq!(items(&b).len(), 2);
    let (_, b) = get(&s, "analyst", "/v0/campaigns?min_confidence=50").await;
    assert_eq!(items(&b).len(), 1);
    assert_eq!(items(&b)[0]["campaign_id"], pair.as_str());
    let (st, _) = get(&s, "analyst", "/v0/campaigns?min_confidence=101").await;
    assert_eq!(st, StatusCode::BAD_REQUEST);

    let (st, b) = get(&s, "other", "/v0/campaigns").await;
    assert_eq!(st, StatusCode::OK);
    assert!(items(&b).is_empty(), "another tenant sees nothing");
    let (st, _) = get(&s, "other", &format!("/v0/campaigns/{wave}")).await;
    assert_eq!(st, StatusCode::NOT_FOUND);
    let (st, _) = get(&s, "nobody", "/v0/campaigns").await;
    assert_eq!(st, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn one_campaign_its_attempts_and_evidence() {
    let (s, _) = harness().await;
    let (wave, _) = ids(&s).await;
    let (st, c) = get(&s, "analyst", &format!("/v0/campaigns/{wave}")).await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(c["confidence"]["wording"], "possible");
    assert_eq!(
        c["confidence_ref"],
        format!("/v0/campaigns/{wave}/evidence")
    );
    for m in c["members"].as_array().unwrap() {
        assert_eq!(m["joined_by"][0]["feature"], "payload_sha256");
    }
    let (st, _) = get(&s, "analyst", "/v0/campaigns/cmp_000000000000000000000000").await;
    assert_eq!(st, StatusCode::NOT_FOUND);
    let (st, _) = get(&s, "analyst", "/v0/campaigns/not-an-id").await;
    assert_eq!(st, StatusCode::NOT_FOUND);

    let (st, a) = get(&s, "analyst", &format!("/v0/campaigns/{wave}/attempts")).await;
    assert_eq!(st, StatusCode::OK, "{a}");
    assert_eq!(items(&a).len(), 3);
    assert!(items(&a).iter().all(|x| x["campaign_id"] == wave.as_str()));
    let (st, _) = get(&s, "camponly", &format!("/v0/campaigns/{wave}/attempts")).await;
    assert_eq!(
        st,
        StatusCode::FORBIDDEN,
        "member attempts need attempts:read"
    );

    let (st, e) = get(&s, "analyst", &format!("/v0/campaigns/{wave}/evidence")).await;
    assert_eq!(st, StatusCode::OK, "{e}");
    assert_eq!(e["confidence"]["kind"], "attempt_campaign");
    assert_eq!(e["confidence"]["target"], wave.as_str());
    assert_eq!(e["confidence"]["score"], c["confidence"]["score"]);
    assert_eq!(e["members"].as_array().unwrap().len(), 3);
    assert!(
        e["members"]
            .as_array()
            .unwrap()
            .iter()
            .all(|l| l["evidence"][0]["source"] == "campaign_cluster")
    );
}

#[tokio::test]
async fn attempts_and_iocs_carry_campaign_ids() {
    let (s, _) = harness().await;
    let (wave, pair) = ids(&s).await;
    let (_, b) = get(&s, "analyst", "/v0/attempts").await;
    let all = items(&b);
    assert_eq!(all.len(), 6);
    assert_eq!(
        all.iter().filter(|a| a["campaign_id"].is_string()).count(),
        5,
        "the bystander probe has none"
    );
    let (_, b) = get(&s, "analyst", &format!("/v0/attempts?campaign_id={pair}")).await;
    assert_eq!(items(&b).len(), 2);
    let (_, b) = get(
        &s,
        "analyst",
        &format!("/v0/iocs?campaign_id={wave}&type=payload_sha256"),
    )
    .await;
    assert_eq!(items(&b).len(), 1);
    assert_eq!(items(&b)[0]["campaign_ids"], json!([wave]));
}

#[tokio::test]
async fn analyst_actions_are_validated_audited_and_replayed() {
    let (s, store) = harness().await;
    let (wave, pair) = ids(&s).await;
    let path = format!("/v0/campaigns/{wave}/actions");

    // Scope, tenant and validation.
    let label = json!({"action": "label", "title": "Upload wave", "note": "reviewed"});
    let (st, _) = send(&s, "analyst", "POST", &path, label.clone()).await;
    assert_eq!(st, StatusCode::FORBIDDEN);
    let (st, _) = send(&s, "other", "POST", &path, label.clone()).await;
    assert_eq!(st, StatusCode::NOT_FOUND);
    for bad in [
        json!({"action": "label", "note": ""}),
        json!({"action": "label", "title": "t".repeat(121), "note": ""}),
        json!({"action": "label", "title": "x", "feedback": "unsure", "note": ""}),
        json!({"action": "split", "attempt_ids": ["att_000000000000000000000000"], "note": ""}),
        json!({"action": "merge", "campaign_ids": ["cmp_000000000000000000000000"], "note": ""}),
        json!({"action": "merge", "campaign_ids": [wave], "note": ""}),
        json!({"action": "feedback", "note": ""}),
        json!({"action": "label", "title": "x", "note": "n".repeat(1001)}),
    ] {
        let (st, b) = send(&s, "lead", "POST", &path, bad.clone()).await;
        assert_eq!(st, StatusCode::BAD_REQUEST, "{bad} -> {b}");
    }
    let (st, _) = send(
        &s,
        "lead",
        "POST",
        &path,
        json!({"action": "rename", "note": ""}),
    )
    .await;
    assert_eq!(st, StatusCode::UNPROCESSABLE_ENTITY);
    assert!(store.audit().is_empty(), "rejected actions write nothing");

    // Label, confirm and close: each is audited and shows on the campaign.
    let (st, r) = send(&s, "lead", "POST", &path, label).await;
    assert_eq!(st, StatusCode::OK, "{r}");
    assert_eq!(r["campaign"]["title"], "Upload wave");
    let (_, r) = send(
        &s,
        "lead",
        "POST",
        &path,
        json!({"action": "feedback", "feedback": "true_positive", "note": "same loader"}),
    )
    .await;
    assert_eq!(r["campaign"]["confidence"]["wording"], "confirmed");
    assert_eq!(r["campaign"]["confidence"]["score"], 100);
    let (_, r) = send(
        &s,
        "lead",
        "POST",
        &path,
        json!({"action": "status", "status": "closed", "note": "wave over"}),
    )
    .await;
    assert_eq!(r["campaign"]["status"], "closed");
    let audit = store.audit();
    let actions: Vec<&str> = audit.iter().map(|a| a.action.as_str()).collect();
    assert_eq!(
        actions,
        vec!["campaign.label", "campaign.feedback", "campaign.status"]
    );
    assert!(
        audit
            .iter()
            .all(|a| a.target.as_deref() == Some(wave.as_str()))
    );
    assert_eq!(audit[0].detail["title"], "Upload wave");

    // Merge the stage-2 pair in, then split it back out.
    let (st, r) = send(
        &s,
        "lead",
        "POST",
        &path,
        json!({"action": "merge", "campaign_ids": [pair], "note": "same wave"}),
    )
    .await;
    assert_eq!(st, StatusCode::OK, "{r}");
    assert_eq!(r["campaign"]["attempt_ids"].as_array().unwrap().len(), 5);
    assert_eq!(r["campaign"]["analyst"]["merged_from"], json!([pair]));
    let (_, b) = get(&s, "analyst", "/v0/campaigns").await;
    assert_eq!(items(&b).len(), 1);
    let (st, _) = get(&s, "analyst", &format!("/v0/campaigns/{pair}")).await;
    assert_eq!(st, StatusCode::NOT_FOUND, "merged away");

    let moved: Vec<Value> = r["campaign"]["members"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|m| m["added_by"]["kind"] == "merge")
        .map(|m| m["attempt_id"].clone())
        .collect();
    assert_eq!(moved.len(), 2);
    let (st, r) = send(
        &s,
        "lead",
        "POST",
        &path,
        json!({"action": "split", "attempt_ids": moved, "note": "different operator"}),
    )
    .await;
    assert_eq!(st, StatusCode::OK, "{r}");
    assert_eq!(r["campaign"]["attempt_ids"].as_array().unwrap().len(), 3);
    let (_, b) = get(&s, "analyst", "/v0/campaigns").await;
    assert_eq!(items(&b).len(), 2);
    let split = items(&b)
        .iter()
        .find(|c| c["analyst"]["split_from"] == wave.as_str())
        .unwrap();
    let split_id = split["campaign_id"].as_str().unwrap();

    // Actions are listed by campaign, newest last, and stay tenant-scoped.
    let (st, l) = get(&s, "analyst", &path).await;
    assert_eq!(st, StatusCode::OK);
    let kinds: Vec<&str> = items(&l)
        .iter()
        .map(|a| a["kind"].as_str().unwrap())
        .collect();
    assert_eq!(kinds, vec!["label", "feedback", "status", "merge", "split"]);
    let (_, l) = get(&s, "analyst", &format!("/v0/campaigns/{pair}/actions")).await;
    assert_eq!(items(&l).len(), 1, "the merge names the pair");
    let (_, l) = get(&s, "analyst", &format!("/v0/campaigns/{split_id}/actions")).await;
    assert_eq!(items(&l)[0]["kind"], "split");
    let (_, l) = get(&s, "other", &path).await;
    assert!(items(&l).is_empty());
}
