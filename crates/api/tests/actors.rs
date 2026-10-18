//! `/v0/actors` and `/v0/actor-links` over the fleet-wave fixture (#29):
//! the catalogue, tenant scoping, the medium possible association and the
//! geography-only non-link, `suggested_actor_links` on campaigns, and
//! audited confirm, reject and reopen decisions.

use std::sync::Arc;

use axum::body::Body;
use foiled_api::auth::sha256_hex;
use foiled_api::memory::MemoryStore;
use foiled_api::store::{Store, TokenRecord};
use foiled_api::{AppState, router};
use foiled_core::actor::{ActorCatalogue, ActorReport, AttackGroups};
use foiled_core::auth::{Role, Scope};
use foiled_core::capture::CaptureEvent;
use foiled_core::enrichment::{CacheEntry, Fact, Observable};
use http::{Request, StatusCode};
use http_body_util::BodyExt;
use serde_json::{Value, json};
use tower::ServiceExt;

const SECRET: &str = "0123456789abcdef0123456789abcdef";

fn root(rel: &str) -> String {
    format!("{}/../../{rel}", env!("CARGO_MANIFEST_DIR"))
}

fn read_json(rel: &str) -> Value {
    serde_json::from_str(&std::fs::read_to_string(root(rel)).unwrap()).unwrap()
}

/// The shipped catalogue plus the fictional reports in testdata.
fn catalogue() -> ActorCatalogue {
    let groups: AttackGroups =
        serde_json::from_value(read_json("data/attack/groups.json")).unwrap();
    let techniques = serde_json::from_value(read_json("data/attack/techniques.json")).unwrap();
    let mut reports: Vec<ActorReport> = Vec::new();
    let mut paths: Vec<_> = std::fs::read_dir(root("testdata/actors/reports"))
        .unwrap()
        .map(|e| e.unwrap().path())
        .collect();
    paths.sort();
    for p in paths {
        let text = std::fs::read_to_string(&p).unwrap();
        reports.push(serde_yaml_ng::from_str(&text).unwrap());
    }
    let c = ActorCatalogue::build(Some(&groups), &techniques, reports);
    assert!(c.problems.is_empty(), "{:?}", c.problems);
    c
}

fn fact(key: &str, value: Value, now: i64) -> Fact {
    Fact {
        provider: "local_asn".into(),
        key: key.into(),
        value,
        confidence: 90,
        observed_at: now,
        ttl_secs: 604_800,
        raw_ref: None,
    }
}

async fn harness() -> (AppState, Arc<MemoryStore>) {
    let store = Arc::new(MemoryStore::new());
    for (id, tenant, scopes) in [
        ("analyst", "t1", vec![Scope::CampaignsRead]),
        (
            "reviewer",
            "t1",
            vec![Scope::CampaignsRead, Scope::ReviewWrite],
        ),
        (
            "lead",
            "t1",
            vec![Scope::CampaignsRead, Scope::CampaignsWrite],
        ),
        ("nobody", "t1", vec![Scope::AttemptsRead]),
        (
            "other",
            "t2",
            vec![Scope::CampaignsRead, Scope::ReviewWrite],
        ),
        ("exporter", "t1", vec![Scope::ExportsRead]),
        (
            "exportreviewer",
            "t1",
            vec![Scope::ExportsRead, Scope::ReviewWrite],
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
    let raw = read_json("testdata/campaigns/fleet-wave.input.json");
    let geo = read_json("testdata/actors/fleet-wave.input.json");
    let events: Vec<CaptureEvent> = serde_json::from_value(raw["events"].clone()).unwrap();
    store.enqueue_events(events).await.unwrap();
    let now = raw["now"].as_i64().unwrap();
    for (ip, country) in geo["countries"].as_object().unwrap() {
        let mut facts = vec![fact("geo.country", country.clone(), now)];
        if let Some(asn) = raw["asns"].get(ip) {
            facts.push(fact("asn.number", asn.clone(), now));
        }
        store.add_cache_entry(CacheEntry {
            provider: "local_asn".into(),
            observable: Observable::ip(ip).unwrap(),
            fetched_at: now,
            ttl_secs: 604_800,
            facts,
        });
    }
    let mut state = AppState::new(store.clone(), Arc::new(move || now));
    state.actors = Arc::new(catalogue());
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

#[tokio::test]
async fn catalogue_lists_attack_groups_with_mitre_notice() {
    let (s, _) = harness().await;
    let (st, b) = get(&s, "analyst", "/v0/actors?source=attack&limit=5").await;
    assert_eq!(st, StatusCode::OK, "{b}");
    assert_eq!(items(&b).len(), 5);
    assert!(
        b["attack_notice"]
            .as_str()
            .unwrap()
            .contains("The MITRE Corporation")
    );
    assert_eq!(b["attack_version"], "20.0");
    let next = b["next_cursor"].as_str().unwrap();
    let (_, b2) = get(
        &s,
        "analyst",
        &format!("/v0/actors?source=attack&limit=5&cursor={next}"),
    )
    .await;
    assert!(items(&b2)[0]["actor_id"].as_str().unwrap() > next);

    let (st, b) = get(&s, "analyst", "/v0/actors/report:example-cluster-01").await;
    assert_eq!(st, StatusCode::OK, "{b}");
    assert_eq!(b["label_kind"], "cluster");
    assert_eq!(
        b["sources"][0]["licence"],
        "Fictional example for tests and docs; no third-party content"
    );
    let (st, _) = get(&s, "analyst", "/v0/actors/report:..%2Fx").await;
    assert_eq!(st, StatusCode::NOT_FOUND);
    let (st, _) = get(&s, "nobody", "/v0/actors").await;
    assert_eq!(st, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn fleet_wave_gets_one_medium_link_and_geo_only_gets_none() {
    let (s, _) = harness().await;
    let (st, b) = get(&s, "analyst", "/v0/actor-links").await;
    assert_eq!(st, StatusCode::OK, "{b}");
    let links = items(&b);
    assert_eq!(links.len(), 1, "{b}");
    let l = &links[0];
    assert_eq!(l["actor_id"], "report:example-cluster-01");
    assert_eq!(l["subject_kind"], "campaign");
    assert_eq!(l["band"], "medium");
    assert_eq!(l["wording"], "possible association");
    assert_eq!(l["status"], "pending");
    assert_eq!(l["publishable"], false);
    assert_eq!(l["review_queue"], true);
    assert_eq!(
        l["sources"][0]["url"],
        "https://reports.example.com/2026/example-cluster-01"
    );
    // Same match as the golden file.
    let golden = read_json("testdata/actors/expected/fleet-wave-00.json");
    assert_eq!(*l, golden);

    // A plain campaign list does not run the matcher.
    let (_, c) = get(&s, "analyst", "/v0/campaigns").await;
    assert!(
        items(&c)
            .iter()
            .all(|c| c["suggested_actor_links"].as_array().unwrap().is_empty())
    );
    let (st, _) = get(&s, "analyst", "/v0/campaigns?include=everything").await;
    assert_eq!(st, StatusCode::BAD_REQUEST);
    // Campaign detail does, for that campaign.
    let (st, one) = get(
        &s,
        "analyst",
        &format!("/v0/campaigns/{}", l["subject_id"].as_str().unwrap()),
    )
    .await;
    assert_eq!(st, StatusCode::OK, "{one}");
    assert_eq!(one["suggested_actor_links"][0]["link_id"], l["link_id"]);

    // With include=actors the campaign carries the suggestion; the geo-only
    // wave does not.
    let (_, c) = get(&s, "analyst", "/v0/campaigns?include=actors").await;
    for camp in items(&c) {
        let sugg = camp["suggested_actor_links"].as_array().unwrap();
        if camp["campaign_id"] == l["subject_id"] {
            assert_eq!(sugg.len(), 1);
            assert_eq!(sugg[0]["link_id"], l["link_id"]);
            assert_eq!(
                sugg[0]["confidence_ref"],
                format!("/v0/actor-links/{}", l["link_id"].as_str().unwrap())
            );
        } else {
            assert!(sugg.is_empty(), "{camp}");
        }
    }

    // Filters and the one-link route.
    let (_, q) = get(
        &s,
        "analyst",
        "/v0/actor-links?status=pending&review_queue=true",
    )
    .await;
    assert_eq!(items(&q).len(), 1);
    let (_, q) = get(&s, "analyst", "/v0/actor-links?status=confirmed").await;
    assert!(items(&q).is_empty());
    let (_, q) = get(&s, "analyst", "/v0/actor-links?min_confidence=70").await;
    assert!(items(&q).is_empty());
    let id = l["link_id"].as_str().unwrap();
    let (st, one) = get(&s, "analyst", &format!("/v0/actor-links/{id}")).await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(one, *l);

    // Tenant isolation: another tenant sees nothing and cannot read it.
    let (_, o) = get(&s, "other", "/v0/actor-links").await;
    assert!(items(&o).is_empty());
    let (st, _) = get(&s, "other", &format!("/v0/actor-links/{id}")).await;
    assert_eq!(st, StatusCode::NOT_FOUND);
    let (st, _) = get(&s, "analyst", "/v0/actor-links/acl_nothex").await;
    assert_eq!(st, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn decisions_are_audited_scoped_and_change_the_link() {
    let (s, store) = harness().await;
    let (_, b) = get(&s, "analyst", "/v0/actor-links").await;
    let id = items(&b)[0]["link_id"].as_str().unwrap().to_string();
    let path = format!("/v0/actor-links/{id}/decision");

    // Only review:write may decide; another tenant cannot find the link.
    let (st, _) = send(
        &s,
        "lead",
        "POST",
        &path,
        json!({"decision": "confirm", "note": "x"}),
    )
    .await;
    assert_eq!(st, StatusCode::FORBIDDEN);
    let (st, _) = send(
        &s,
        "other",
        "POST",
        &path,
        json!({"decision": "confirm", "note": "x"}),
    )
    .await;
    assert_eq!(st, StatusCode::NOT_FOUND);
    // A confirmation needs a reason; unknown fields are refused.
    let (st, _) = send(
        &s,
        "reviewer",
        "POST",
        &path,
        json!({"decision": "confirm", "note": " "}),
    )
    .await;
    assert_eq!(st, StatusCode::BAD_REQUEST);
    // A note may not make the claim the link never makes.
    let (st, nb) = send(
        &s,
        "reviewer",
        "POST",
        &path,
        json!({"decision": "confirm", "note": "This wave was carried out by EXAMPLE."}),
    )
    .await;
    assert_eq!(st, StatusCode::BAD_REQUEST, "{nb}");
    let (st, _) = send(
        &s,
        "reviewer",
        "POST",
        &path,
        json!({"decision": "confirm", "note": "x", "score": 100}),
    )
    .await;
    assert_eq!(st, StatusCode::UNPROCESSABLE_ENTITY);

    let (st, l) = send(
        &s,
        "reviewer",
        "POST",
        &path,
        json!({"decision": "confirm", "note": "Callback host matches the advisory."}),
    )
    .await;
    assert_eq!(st, StatusCode::OK, "{l}");
    assert_eq!(l["status"], "confirmed");
    assert_eq!(l["band"], "high");
    assert_eq!(l["wording"], "confirmed association");
    assert_eq!(l["publishable"], true);
    assert!(
        l["statement"]
            .as_str()
            .unwrap()
            .starts_with("Confirmed association")
    );
    let audit = store.audit();
    let rec = audit
        .iter()
        .find(|r| r.action == "actor_link.confirm")
        .unwrap();
    assert_eq!(rec.target.as_deref(), Some(id.as_str()));
    assert_eq!(rec.actor_id, "reviewer");
    assert_eq!(rec.detail["score_before"], items(&b)[0]["score"]);

    // Persisted: later reads see it, and the campaign suggestion says so.
    let (_, c) = get(&s, "analyst", "/v0/campaigns?include=actors").await;
    let sugg: Vec<&Value> = items(&c)
        .iter()
        .flat_map(|c| c["suggested_actor_links"].as_array().unwrap())
        .collect();
    assert_eq!(sugg.len(), 1);
    assert_eq!(sugg[0]["status"], "confirmed");

    let (_, l) = send(
        &s,
        "reviewer",
        "POST",
        &path,
        json!({"decision": "reject", "note": ""}),
    )
    .await;
    assert_eq!(
        (l["status"].as_str(), l["score"].as_u64()),
        (Some("rejected"), Some(0))
    );
    let (_, c) = get(&s, "analyst", "/v0/campaigns?include=actors").await;
    assert!(
        items(&c)
            .iter()
            .all(|c| c["suggested_actor_links"].as_array().unwrap().is_empty()),
        "rejected links are not suggested"
    );
    let (_, l) = send(
        &s,
        "reviewer",
        "POST",
        &path,
        json!({"decision": "reopen", "note": ""}),
    )
    .await;
    assert_eq!(l["status"], "pending");
    assert_eq!(l["band"], "medium");
    let actions: Vec<String> = store
        .audit()
        .iter()
        .filter(|r| r.action.starts_with("actor_link."))
        .map(|r| r.action.clone())
        .collect();
    assert_eq!(
        actions,
        [
            "actor_link.confirm",
            "actor_link.reject",
            "actor_link.reopen"
        ]
    );
}

fn objects<'a>(b: &'a Value, ty: &str) -> Vec<&'a Value> {
    b["objects"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|o| o["type"] == ty)
        .collect()
}

fn misp_actors(e: &Value) -> usize {
    e["Event"]["Attribute"]
        .as_array()
        .map(|a| a.iter().filter(|x| x["type"] == "threat-actor").count())
        .unwrap_or(0)
}

#[tokio::test]
async fn only_confirmed_actor_links_reach_exports() {
    let (s, _) = harness().await;
    let (_, b) = get(&s, "analyst", "/v0/actor-links").await;
    let link = items(&b)[0].clone();
    let id = link["link_id"].as_str().unwrap().to_string();

    // Pending: nothing, even with the opt-in and unreviewed material.
    for (tok, q) in [
        ("exporter", "include_actors=true"),
        (
            "exportreviewer",
            "include_actors=true&include_unreviewed=true",
        ),
    ] {
        let (st, bundle) = get(&s, tok, &format!("/v0/exports/stix?{q}")).await;
        assert_eq!(st, StatusCode::OK, "{bundle}");
        assert!(objects(&bundle, "intrusion-set").is_empty(), "{q}");
        let (_, event) = get(&s, tok, &format!("/v0/exports/misp?{q}")).await;
        assert_eq!(misp_actors(&event), 0, "{q}");
    }

    let (st, _) = send(
        &s,
        "reviewer",
        "POST",
        &format!("/v0/actor-links/{id}/decision"),
        json!({"decision": "confirm", "note": "Callback host matches the advisory."}),
    )
    .await;
    assert_eq!(st, StatusCode::OK);

    // Confirmed, but no opt-in: still nothing.
    let (_, bundle) = get(&s, "exporter", "/v0/exports/stix").await;
    assert!(objects(&bundle, "intrusion-set").is_empty());

    // Confirmed and opted in: one intrusion-set, one relationship per member.
    let (_, bundle) = get(&s, "exporter", "/v0/exports/stix?include_actors=true").await;
    let sets = objects(&bundle, "intrusion-set");
    assert_eq!(sets.len(), 1, "{bundle}");
    let set = sets[0];
    assert_eq!(set["name"], link["label"]);
    assert_eq!(set["x_foiled_actor_id"], "report:example-cluster-01");
    assert_eq!(
        set["external_references"][0]["url"],
        "https://advisories.example.org/ex-2026-001"
    );
    let set_id = set["id"].as_str().unwrap();
    let rels: Vec<&Value> = objects(&bundle, "relationship")
        .into_iter()
        .filter(|r| r["target_ref"] == set_id)
        .collect();
    assert_eq!(rels.len(), 2);
    for r in rels {
        assert_eq!(r["x_foiled_wording"], "confirmed association");
        assert!(
            r["description"]
                .as_str()
                .unwrap()
                .starts_with("Confirmed association with")
        );
        assert_eq!(r["confidence"], 100);
    }
    let problems = foiled_core::intel::stix::problems(&bundle);
    assert!(problems.is_empty(), "{problems:#?}");
    let (_, event) = get(&s, "exporter", "/v0/exports/misp?include_actors=true").await;
    assert!(misp_actors(&event) >= 1, "{event}");

    // Rejected: gone again.
    let (st, _) = send(
        &s,
        "reviewer",
        "POST",
        &format!("/v0/actor-links/{id}/decision"),
        json!({"decision": "reject", "note": ""}),
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    let (_, bundle) = get(
        &s,
        "exportreviewer",
        "/v0/exports/stix?include_actors=true&include_unreviewed=true",
    )
    .await;
    assert!(objects(&bundle, "intrusion-set").is_empty());
}
