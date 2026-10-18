//! TAXII 2.1 over the materialised STIX object log (#13): discovery and
//! errors, the audited admin materialiser, immutability of stored versions,
//! paging with no skips or duplicates while the log grows, referential
//! completeness for polling clients, versions, and retention.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::sync::atomic::{AtomicI64, Ordering};

use axum::body::Body;
use foiled_api::auth::sha256_hex;
use foiled_api::memory::MemoryStore;
use foiled_api::routes::taxii::{
    Budget, DEFAULT_BUDGET, LEASE_MS, QUIET_REBUILDS_PER_RUN, collection_id, materialise,
    materialise_all, materialise_tick, materialise_with,
};
use foiled_api::store::{DayRecord, LinkOverride, NewVersion};
use foiled_api::store::{Store, TokenRecord};
use foiled_api::{AppState, router};
use foiled_core::auth::{Role, Scope};
use foiled_core::capture::CaptureEvent;
use foiled_core::confidence::{Feedback, LinkKind, Override};
use foiled_core::enrichment::{CacheEntry, Fact, Observable};
use foiled_core::intel::log::{PUBLISHED, content_hash};
use foiled_core::intel::stix;
use http::{HeaderMap, Request, StatusCode};
use http_body_util::BodyExt;
use serde_json::Value;
use tower::ServiceExt;

const SECRET: &str = "0123456789abcdef0123456789abcdef";
const T0: i64 = 1_792_285_323_000;
const HOUR: i64 = 3_600_000;
const DAY: i64 = 24 * HOUR;
const TAXII: &str = "application/taxii+json;version=2.1";

fn events(rel: &str, shift: i64) -> Vec<CaptureEvent> {
    let raw: Value = serde_json::from_str(
        &std::fs::read_to_string(format!(
            "{}/../../testdata/{rel}",
            env!("CARGO_MANIFEST_DIR")
        ))
        .unwrap(),
    )
    .unwrap();
    let mut events: Vec<CaptureEvent> = serde_json::from_value(raw["events"].clone()).unwrap();
    for e in &mut events {
        e.ts += shift;
        e.event_id = format!("{}-{shift}", e.event_id);
    }
    events
}

struct H {
    state: AppState,
    store: Arc<MemoryStore>,
    now: Arc<AtomicI64>,
}

async fn harness() -> H {
    harness_with(events("iocs/memory-only.input.json", 0)).await
}

async fn harness_with(initial: Vec<CaptureEvent>) -> H {
    let store = Arc::new(MemoryStore::new());
    for (id, tenant, scopes) in [
        ("lead", "t1", vec![Scope::ExportsRead]),
        ("admin", "t1", vec![Scope::Admin]),
        ("other", "t2", vec![Scope::ExportsRead]),
        ("reader", "t1", vec![Scope::IocsRead]),
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
    store.enqueue_events(initial).await.unwrap();
    let now = Arc::new(AtomicI64::new(T0 + HOUR));
    let clock = now.clone();
    let state = AppState::new(
        store.clone(),
        Arc::new(move || clock.load(Ordering::SeqCst)),
    );
    H { state, store, now }
}

async fn call(
    state: &AppState,
    method: &str,
    tok: Option<&str>,
    path: &str,
    accept: Option<&str>,
) -> (StatusCode, HeaderMap, String) {
    let mut req = Request::builder().method(method).uri(path);
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

fn base() -> String {
    format!("/taxii2/foiled/collections/{}/", collection_id())
}

/// Every page of a query, following `next`. Returns the objects and the
/// newest `X-TAXII-Date-Added-Last`.
async fn poll(state: &AppState, query: &str, limit: usize) -> (Vec<Value>, Option<String>) {
    let mut out = Vec::new();
    let mut last: Option<String> = None;
    let mut next: Option<String> = None;
    for _ in 0..500 {
        let mut url = format!("{}objects/?limit={limit}{query}", base());
        if let Some(n) = &next {
            url.push_str(&format!("&next={n}"));
        }
        let (st, h, body) = call(state, "GET", Some("lead"), &url, Some(TAXII)).await;
        assert_eq!(st, StatusCode::OK, "{body}");
        assert_eq!(h["content-type"], TAXII);
        if let Some(v) = h.get("x-taxii-date-added-last") {
            let v = v.to_str().unwrap().to_string();
            if last.as_ref().is_none_or(|l| v > *l) {
                last = Some(v);
            }
        }
        let p = json(&body);
        out.extend(p["objects"].as_array().cloned().unwrap_or_default());
        if p["more"] != true {
            assert!(p.get("next").is_none());
            return (out, last);
        }
        next = Some(p["next"].as_str().unwrap().to_string());
    }
    panic!("paging did not finish");
}

fn key(o: &Value) -> (String, String) {
    let v = o["modified"]
        .as_str()
        .or_else(|| o["created"].as_str())
        .unwrap_or("observable")
        .to_string();
    (o["id"].as_str().unwrap().to_string(), v)
}

fn dangling(store: &BTreeMap<String, Value>) -> Vec<String> {
    let mut out = Vec::new();
    for (id, o) in store {
        for r in stix::refs_of(o) {
            if !store.contains_key(&r) {
                out.push(format!("{id} -> {r}"));
            }
        }
    }
    out
}

fn merge(store: &mut BTreeMap<String, Value>, objs: Vec<Value>) {
    for o in objs {
        store.insert(o["id"].as_str().unwrap().to_string(), o);
    }
}

#[tokio::test]
async fn discovery_root_collections_and_errors() {
    let h = harness().await;
    let s = &h.state;
    let (st, hd, body) = call(s, "GET", Some("lead"), "/taxii2/", Some(TAXII)).await;
    assert_eq!(st, StatusCode::OK, "{body}");
    assert_eq!(hd["content-type"], TAXII);
    assert_eq!(json(&body)["api_roots"][0], "/taxii2/foiled/");
    let (_, _, body) = call(s, "GET", Some("lead"), "/taxii2/foiled/", None).await;
    assert_eq!(json(&body)["versions"][0], TAXII);
    let (_, _, body) = call(s, "GET", Some("lead"), "/taxii2/foiled/collections/", None).await;
    let c = json(&body);
    assert_eq!(c["collections"][0]["id"], collection_id());
    assert_eq!(c["collections"][0]["can_write"], false);

    let (st, hd, body) = call(
        s,
        "GET",
        Some("lead"),
        "/taxii2/foiled/collections/00000000-0000-4000-8000-000000000000/",
        None,
    )
    .await;
    assert_eq!(st, StatusCode::NOT_FOUND);
    assert_eq!(hd["content-type"], TAXII);
    assert_eq!(json(&body)["http_status"], "404");
    let (st, _, _) = call(s, "GET", Some("lead"), "/taxii2/", Some("text/html")).await;
    assert_eq!(st, StatusCode::NOT_ACCEPTABLE);
    let (st, hd, _) = call(s, "GET", None, "/taxii2/", Some(TAXII)).await;
    assert_eq!(st, StatusCode::UNAUTHORIZED);
    assert_eq!(hd["content-type"], TAXII);
    let (st, _, _) = call(s, "GET", Some("reader"), "/taxii2/", Some(TAXII)).await;
    assert_eq!(st, StatusCode::FORBIDDEN);
    for q in [
        "limit=0",
        "added_after=yesterday",
        "next=zz",
        "match[version]=soon",
    ] {
        let (st, _, _) = call(
            s,
            "GET",
            Some("lead"),
            &format!("{}objects/?{q}", base()),
            None,
        )
        .await;
        assert_eq!(st, StatusCode::BAD_REQUEST, "{q}");
    }
}

#[tokio::test]
async fn taxii_serves_only_what_the_audited_materialiser_wrote() {
    let h = harness().await;
    let s = &h.state;
    // Nothing is rebuilt on a request: an empty log serves nothing.
    let (objs, _) = poll(s, "", 10).await;
    assert!(objs.is_empty());

    let (st, _, _) = call(s, "POST", Some("lead"), "/v0/taxii/materialise", None).await;
    assert_eq!(st, StatusCode::FORBIDDEN);
    let (st, _, body) = call(s, "POST", Some("admin"), "/v0/taxii/materialise", None).await;
    assert_eq!(st, StatusCode::OK, "{body}");
    let r = json(&body);
    assert!(r["versions_written"].as_u64().unwrap() > 10, "{r}");
    // The day itself, and the day before (its margin reads this day's
    // first hours but owns none of its attempts).
    assert!(r["days_written"].as_u64().unwrap() >= 1, "{r}");
    let audit = h.store.audit();
    assert_eq!(audit.last().unwrap().action, "taxii.materialise");

    let (objs, _) = poll(s, "", 7).await;
    assert!(!objs.is_empty());
    let mut client = BTreeMap::new();
    merge(&mut client, objs.clone());
    assert!(dangling(&client).is_empty(), "{:?}", dangling(&client));
    // The published view only: no probe-only source, no unreviewed links.
    let text = serde_json::to_string(&objs).unwrap();
    assert!(text.contains("TLP:AMBER") && !text.contains("TLP:AMBER+STRICT"));
    assert!(objs.iter().all(|o| o["x_foiled_publishable"] != false));

    // Other tenants see nothing; a second run with no new events writes
    // nothing and skips the day.
    let (st, _, body) = call(
        s,
        "GET",
        Some("other"),
        &format!("{}objects/", base()),
        None,
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    assert!(json(&body).get("objects").is_none());
    let again = materialise(s, "t1").await.unwrap();
    assert_eq!(again.versions_written, 0);
    assert_eq!(again.days_written, 0);
    assert!(again.days_skipped >= 1);
    assert_eq!(materialise_all(s).await.unwrap(), 1);
}

#[tokio::test]
async fn versions_are_immutable_and_created_never_moves() {
    let h = harness().await;
    let s = &h.state;
    materialise(s, "t1").await.unwrap();
    let (first, _) = poll(s, "&match[version]=all", 50).await;
    let before: BTreeMap<(String, String), Value> =
        first.iter().map(|o| (key(o), o.clone())).collect();

    // New evidence the same day: the day is rebuilt from scratch.
    h.store
        .enqueue_events(events("exports/synthetic.input.json", 2 * HOUR))
        .await
        .unwrap();
    h.now.store(T0 + 3 * HOUR, Ordering::SeqCst);
    let r = materialise(s, "t1").await.unwrap();
    assert!(r.versions_written > 0);
    assert!(r.unchanged > 0, "unchanged objects are not rewritten");

    let (all, _) = poll(s, "&match[version]=all", 50).await;
    let mut created: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let mut seen: BTreeSet<(String, String)> = BTreeSet::new();
    for o in &all {
        let k = key(o);
        assert!(seen.insert(k.clone()), "one row per (id, version): {k:?}");
        // The same id and version always has the same content.
        if let Some(old) = before.get(&k) {
            assert_eq!(old, o, "{k:?} changed");
        }
        if let Some(c) = o["created"].as_str() {
            created
                .entry(k.0.clone())
                .or_default()
                .insert(c.to_string());
        }
    }
    assert!(
        before.keys().all(|k| seen.contains(k)),
        "versions are never removed"
    );
    for (id, c) in created {
        assert_eq!(c.len(), 1, "{id} has more than one created: {c:?}");
    }

    // Versions endpoint and filters.
    let vuln = all.iter().find(|o| o["type"] == "vulnerability").unwrap();
    let vid = vuln["id"].as_str().unwrap();
    let (st, _, body) = call(
        s,
        "GET",
        Some("lead"),
        &format!("{}objects/{vid}/versions/", base()),
        Some(TAXII),
    )
    .await;
    assert_eq!(st, StatusCode::OK, "{body}");
    let versions = json(&body)["versions"].as_array().unwrap().clone();
    assert!(!versions.is_empty());
    let (_, _, body) = call(
        s,
        "GET",
        Some("lead"),
        &format!("{}objects/{vid}/?match[version]=first", base()),
        None,
    )
    .await;
    assert_eq!(json(&body)["objects"][0]["modified"], versions[0]);
    let (st, _, _) = call(
        s,
        "GET",
        Some("lead"),
        &format!(
            "{}objects/indicator--00000000-0000-4000-8000-000000000000/",
            base()
        ),
        None,
    )
    .await;
    assert_eq!(st, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn paging_never_skips_or_repeats_while_the_log_grows() {
    let h = harness().await;
    let s = &h.state;
    materialise(s, "t1").await.unwrap();

    // Page through every version, three at a time; after the first page,
    // new evidence is materialised.
    let mut collected: Vec<Value> = Vec::new();
    let mut next: Option<String> = None;
    let mut grown = false;
    for _ in 0..500 {
        let mut url = format!("{}objects/?limit=3&match[version]=all", base());
        if let Some(n) = &next {
            url.push_str(&format!("&next={n}"));
        }
        let (_, _, body) = call(s, "GET", Some("lead"), &url, None).await;
        let p = json(&body);
        collected.extend(p["objects"].as_array().cloned().unwrap_or_default());
        if !grown {
            h.store
                .enqueue_events(events("exports/synthetic.input.json", 2 * HOUR))
                .await
                .unwrap();
            h.now.store(T0 + 3 * HOUR, Ordering::SeqCst);
            assert!(materialise(s, "t1").await.unwrap().versions_written > 0);
            grown = true;
        }
        if p["more"] != true {
            break;
        }
        next = Some(p["next"].as_str().unwrap().to_string());
    }
    let (fresh, _) = poll(s, "&match[version]=all", 1000).await;
    let keys: Vec<(String, String)> = collected.iter().map(key).collect();
    let unique: BTreeSet<&(String, String)> = keys.iter().collect();
    assert_eq!(unique.len(), keys.len(), "no row twice");
    let fresh_keys: BTreeSet<(String, String)> = fresh.iter().map(key).collect();
    assert_eq!(
        unique.into_iter().cloned().collect::<BTreeSet<_>>(),
        fresh_keys,
        "no row skipped"
    );
}

#[tokio::test]
async fn polling_clients_keep_every_reference() {
    let h = harness().await;
    let s = &h.state;
    materialise(s, "t1").await.unwrap();
    let mut client = BTreeMap::new();
    let (first, mark) = poll(s, "", 4).await;
    merge(&mut client, first);
    assert!(dangling(&client).is_empty());

    h.store
        .enqueue_events(events("exports/synthetic.input.json", 2 * HOUR))
        .await
        .unwrap();
    h.store
        .enqueue_events(events("iocs/file-drop.input.json", DAY))
        .await
        .unwrap();
    h.now.store(T0 + DAY + HOUR, Ordering::SeqCst);
    let r = materialise(s, "t1").await.unwrap();
    assert!(r.days_written >= 2);

    let (second, _) = poll(s, &format!("&added_after={}", mark.unwrap()), 4).await;
    assert!(!second.is_empty());
    merge(&mut client, second);
    assert!(dangling(&client).is_empty(), "{:?}", dangling(&client));
    let patterns: Vec<&str> = client
        .values()
        .filter_map(|o| o["pattern"].as_str())
        .collect();
    assert!(patterns.contains(&"[domain-name:value = 'q4x9.cb.example.invalid']"));

    // Manifest agrees with the objects.
    let (_, _, body) = call(
        s,
        "GET",
        Some("lead"),
        &format!("{}manifest/?limit=1000", base()),
        None,
    )
    .await;
    let m = json(&body);
    let ids: BTreeSet<&str> = m["objects"]
        .as_array()
        .unwrap()
        .iter()
        .map(|o| o["id"].as_str().unwrap())
        .collect();
    assert_eq!(ids.len(), client.len());
}

#[tokio::test]
async fn retention_removes_objects_whose_evidence_expired() {
    let h = harness().await;
    let s = &h.state;
    materialise(s, "t1").await.unwrap();
    assert!(!poll(s, "", 100).await.0.is_empty());
    // Past the 90-day attempt TTL, with the events purged too.
    h.now.store(T0 + 91 * DAY, Ordering::SeqCst);
    let r = materialise(s, "t1").await.unwrap();
    assert!(r.purged > 0);
    assert!(poll(s, "", 100).await.0.is_empty());
}

// ---------------------------------------------------------------------------
// Withdrawal, revocation and attempts that cross midnight
// ---------------------------------------------------------------------------

async fn override_link(h: &H, kind: LinkKind, target: &str, feedback: Feedback, at: i64) {
    // The synthetic attempt (source 203.0.113.60).
    let (status, _, body) = call(
        &h.state,
        "GET",
        Some("lead"),
        "/taxii2/foiled/collections/",
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let events = h.store.queued_events();
    let attempts = foiled_core::attempt::build(
        &events,
        foiled_core::attempt::DEFAULT_IDLE_GAP_MS,
        &foiled_api::links::matcher_signals(&events),
    );
    let a = attempts
        .iter()
        .find(|a| a.src == "203.0.113.60")
        .expect("synthetic attempt");
    h.store
        .put_link_override(
            "t1",
            LinkOverride {
                attempt_id: a.attempt_id.clone(),
                kind,
                target: target.into(),
                decision: Override {
                    feedback,
                    analyst_id: "analyst-1".into(),
                    at,
                    note: "test".into(),
                },
            },
        )
        .await
        .unwrap();
}

fn relationship_to_vulnerability(objs: &[Value]) -> Vec<&Value> {
    objs.iter()
        .filter(|o| {
            o["type"] == "relationship"
                && o["target_ref"]
                    .as_str()
                    .is_some_and(|t| t.starts_with("vulnerability--"))
                && o["description"]
                    .as_str()
                    .is_some_and(|d| d.contains("FOILED-DEMO-0001"))
        })
        .collect()
}

/// An analyst marks a published link false positive: subscribers polling
/// with added_after get a revoked last version. Undoing it publishes the
/// link again under a new id, because a revoked object stays revoked.
#[tokio::test]
async fn suppressed_links_are_revoked_for_subscribers() {
    let h = harness().await;
    h.store
        .enqueue_events(events("exports/synthetic.input.json", 2 * HOUR))
        .await
        .unwrap();
    h.now.store(T0 + 3 * HOUR, Ordering::SeqCst);
    let s = &h.state;
    materialise(s, "t1").await.unwrap();
    let (first, mark) = poll(s, "", 50).await;
    let synth_obs = first
        .iter()
        .find(|o| {
            o["type"] == "observed-data"
                && o["x_foiled_summary"]
                    .as_str()
                    .unwrap()
                    .contains("203.0.113.60")
        })
        .expect("synthetic attempt observed")["id"]
        .as_str()
        .unwrap()
        .to_string();
    let rel = first
        .iter()
        .find(|o| {
            o["type"] == "relationship"
                && o["source_ref"] == synth_obs.as_str()
                && o["target_ref"]
                    .as_str()
                    .unwrap()
                    .starts_with("vulnerability--")
        })
        .expect("published CVE link")
        .clone();
    let rid = rel["id"].as_str().unwrap().to_string();

    override_link(
        &h,
        LinkKind::AttemptCve,
        "FOILED-DEMO-0001",
        Feedback::FalsePositive,
        T0 + 3 * HOUR,
    )
    .await;
    h.now.store(T0 + 4 * HOUR, Ordering::SeqCst);
    let r = materialise(s, "t1").await.unwrap();
    assert!(r.revoked >= 1, "{r:?}");

    let (second, mark2) = poll(s, &format!("&added_after={}", mark.unwrap()), 50).await;
    let revoked = second
        .iter()
        .find(|o| o["id"] == rid.as_str())
        .expect("subscribers see the withdrawn link");
    assert_eq!(revoked["revoked"], true);
    assert!(revoked["modified"].as_str() > rel["modified"].as_str());
    assert_eq!(revoked["created"], rel["created"]);

    // Undo: the link is published again under a new id.
    override_link(
        &h,
        LinkKind::AttemptCve,
        "FOILED-DEMO-0001",
        Feedback::TruePositive,
        T0 + 4 * HOUR,
    )
    .await;
    h.now.store(T0 + 5 * HOUR, Ordering::SeqCst);
    let r = materialise(s, "t1").await.unwrap();
    assert!(r.reissued >= 1, "{r:?}");
    let (third, _) = poll(s, &format!("&added_after={}", mark2.unwrap()), 50).await;
    let back = third
        .iter()
        .find(|o| {
            o["type"] == "relationship"
                && o["source_ref"] == synth_obs.as_str()
                && o["target_ref"]
                    .as_str()
                    .unwrap()
                    .starts_with("vulnerability--")
        })
        .expect("the link is back");
    assert_ne!(back["id"], rid.as_str());
    assert!(back.get("revoked").is_none());
    assert!(
        back["description"]
            .as_str()
            .unwrap()
            .starts_with("An analyst confirmed")
    );
    // The old id stays revoked.
    let (_, _, body) = call(
        s,
        "GET",
        Some("lead"),
        &format!("{}objects/{rid}/", base()),
        None,
    )
    .await;
    assert_eq!(json(&body)["objects"][0]["revoked"], true);
    check_log_golden("taxii-log", s).await;
}

/// The latest version of every object in the log as one bundle, kept as
/// `testdata/exports/stix/<name>.json` so CI runs stix2-validator over
/// what TAXII serves (revoked and reissued versions included). To
/// regenerate after an intended change, run with FOILED_BLESS=1.
async fn check_log_golden(name: &str, state: &AppState) {
    let (rows, _) = poll(state, "", 1000).await;
    let mut latest = BTreeMap::new();
    merge(&mut latest, rows);
    if let Ok(dir) = std::env::var("FOILED_TAXII_DUMP") {
        let (all, _) = poll(state, "&match[version]=all", 1000).await;
        std::fs::write(
            format!("{dir}/{name}-all.json"),
            serde_json::to_string_pretty(&all).unwrap(),
        )
        .unwrap();
    }
    let got = serde_json::json!({
        "type": "bundle",
        "id": format!("bundle--{}", foiled_core::intel::uuid5::uuid_v5(
            foiled_core::intel::FOILED_NAMESPACE,
            &format!("golden|{name}"),
        )),
        "objects": latest.into_values().collect::<Vec<_>>(),
    });
    let problems = stix::problems(&got);
    assert!(problems.is_empty(), "{problems:#?}");
    let path = format!(
        "{}/../../testdata/exports/stix/{name}.json",
        env!("CARGO_MANIFEST_DIR")
    );
    if std::env::var("FOILED_BLESS").is_ok() {
        std::fs::write(&path, serde_json::to_string_pretty(&got).unwrap() + "\n").unwrap();
    }
    let want: Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
    assert_eq!(got, want, "{path}");
}

/// Content an object had before comes back as the newest version, so
/// "latest" is the current state.
#[tokio::test]
async fn earlier_content_becomes_the_latest_version_again() {
    let h = harness().await;
    let s = &h.state;
    materialise(s, "t1").await.unwrap();
    let (all, _) = poll(s, "&match[version]=all", 100).await;
    let rel = relationship_to_vulnerability(&all)[0].clone();
    let rid = rel["id"].as_str().unwrap().to_string();

    // The memory-only attempt's CVE link: confirmed, then back to unsure.
    let events = h.store.queued_events();
    let attempts = foiled_core::attempt::build(
        &events,
        foiled_core::attempt::DEFAULT_IDLE_GAP_MS,
        &foiled_api::links::matcher_signals(&events),
    );
    let aid = attempts[0].attempt_id.clone();
    for (n, feedback) in [Feedback::TruePositive, Feedback::Unsure]
        .into_iter()
        .enumerate()
    {
        h.store
            .put_link_override(
                "t1",
                LinkOverride {
                    attempt_id: aid.clone(),
                    kind: LinkKind::AttemptCve,
                    target: "FOILED-DEMO-0001".into(),
                    decision: Override {
                        feedback,
                        analyst_id: "analyst-1".into(),
                        at: T0 + (n as i64 + 2) * HOUR,
                        note: "test".into(),
                    },
                },
            )
            .await
            .unwrap();
        h.now.store(T0 + (n as i64 + 2) * HOUR, Ordering::SeqCst);
        materialise(s, "t1").await.unwrap();
    }
    let (_, _, body) = call(
        s,
        "GET",
        Some("lead"),
        &format!("{}objects/{rid}/versions/", base()),
        None,
    )
    .await;
    let versions = json(&body)["versions"].as_array().unwrap().clone();
    assert_eq!(versions.len(), 3, "{versions:?}");
    let (_, _, body) = call(
        s,
        "GET",
        Some("lead"),
        &format!("{}objects/{rid}/", base()),
        None,
    )
    .await;
    let latest = json(&body)["objects"][0].clone();
    let strip = |v: &Value| {
        let mut v = v.clone();
        v.as_object_mut().unwrap().remove("modified");
        v
    };
    assert_eq!(
        strip(&latest),
        strip(&rel),
        "latest is the first content again"
    );
    assert_eq!(latest["modified"], versions[2]);

    // match[version] lists mean any of their values (TAXII 2.1 3.4.2):
    // first,last is two of the three versions, not all of them.
    let (_, _, body) = call(
        s,
        "GET",
        Some("lead"),
        &format!("{}objects/{rid}/?match[version]=first,last", base()),
        None,
    )
    .await;
    let got: Vec<Value> = json(&body)["objects"]
        .as_array()
        .unwrap()
        .iter()
        .map(|o| o["modified"].clone())
        .collect();
    assert_eq!(got.len(), 2, "{body}");
    assert!(got.contains(&versions[0]) && got.contains(&versions[2]));
    let (_, _, body) = call(
        s,
        "GET",
        Some("lead"),
        &format!(
            "{}objects/{rid}/?match[version]=first,{}",
            base(),
            versions[1].as_str().unwrap()
        ),
        None,
    )
    .await;
    assert_eq!(json(&body)["objects"].as_array().unwrap().len(), 2);
    let (_, _, body) = call(
        s,
        "GET",
        Some("lead"),
        &format!("{}objects/{rid}/?match[version]=all", base()),
        None,
    )
    .await;
    assert_eq!(json(&body)["objects"].as_array().unwrap().len(), 3);
}

/// An attempt that starts before midnight and continues after it is built
/// whole by the day it started in, under one id, whichever run sees it.
#[tokio::test]
async fn attempts_crossing_midnight_keep_one_id() {
    let h = harness().await;
    let s = &h.state;
    let midnight = T0.div_euclid(DAY) * DAY + DAY;
    let mut evs = events("exports/synthetic.input.json", 0);
    evs.retain(|e| e.src.ip != "198.51.100.9");
    for (n, e) in evs.iter_mut().enumerate() {
        e.event_id = format!("night-{n}");
        // The probe five minutes before midnight, the rest just after.
        e.ts = if n == 0 {
            midnight - 5 * 60_000
        } else {
            midnight + 60_000 + n as i64
        };
    }
    let (before, after): (Vec<_>, Vec<_>) = evs.into_iter().partition(|e| e.ts < midnight);
    // A run just before midnight sees only the probe.
    h.store.enqueue_events(before.clone()).await.unwrap();
    h.now.store(midnight - 60_000, Ordering::SeqCst);
    materialise(s, "t1").await.unwrap();
    // Runs after midnight see the rest.
    h.store.enqueue_events(after.clone()).await.unwrap();
    for t in [midnight + HOUR, midnight + 8 * HOUR] {
        h.now.store(t, Ordering::SeqCst);
        materialise(s, "t1").await.unwrap();
    }
    let mut all_events = before;
    all_events.extend(after);
    let whole = foiled_core::attempt::build(
        &all_events,
        foiled_core::attempt::DEFAULT_IDLE_GAP_MS,
        &foiled_api::links::matcher_signals(&all_events),
    );
    assert_eq!(whole.len(), 1);
    let (rows, _) = poll(s, "&match[version]=all", 1000).await;
    let night: BTreeSet<&str> = rows
        .iter()
        .filter(|o| matches!(o["type"].as_str(), Some("observed-data") | Some("grouping")))
        .filter(|o| {
            o["x_foiled_summary"]
                .as_str()
                .unwrap_or("")
                .contains("203.0.113.60")
        })
        .map(|o| o["x_foiled_attempt_id"].as_str().unwrap())
        .collect();
    assert_eq!(night, BTreeSet::from([whole[0].attempt_id.as_str()]));
}

// ---------------------------------------------------------------------------
// Objects shared across days, budgets and resumption, one run at a time
// ---------------------------------------------------------------------------

/// The synthetic attempt on day `n` (01:00 UTC), with its own event ids.
fn day_events(n: i64) -> Vec<CaptureEvent> {
    events("exports/synthetic.input.json", n * DAY)
}

fn day_start(n: i64) -> i64 {
    T0.div_euclid(DAY) * DAY + n * DAY
}

/// Every stored version, by id, oldest first.
async fn history(state: &AppState) -> BTreeMap<String, Vec<Value>> {
    let (rows, _) = poll(state, "&match[version]=all", 1000).await;
    let mut out: BTreeMap<String, Vec<Value>> = BTreeMap::new();
    for o in rows {
        out.entry(o["id"].as_str().unwrap().to_string())
            .or_default()
            .push(o);
    }
    for v in out.values_mut() {
        v.sort_by(|a, b| key(a).1.cmp(&key(b).1));
    }
    out
}

/// The latest version of every object, without `created` and `modified`
/// (which record when a version was first written, not what it says).
fn latest_content(h: &BTreeMap<String, Vec<Value>>) -> BTreeMap<String, String> {
    h.iter()
        .map(|(id, v)| (id.clone(), content_hash(v.last().unwrap())))
        .collect()
}

/// No object ever goes back to content it had before: versions only move
/// forward, they never flip between views.
fn assert_no_flips(h: &BTreeMap<String, Vec<Value>>) {
    for (id, versions) in h {
        let hashes: Vec<String> = versions.iter().map(content_hash).collect();
        let unique: BTreeSet<&String> = hashes.iter().collect();
        assert_eq!(unique.len(), hashes.len(), "{id} flips: {versions:#?}");
    }
}

fn find<'a>(h: &'a BTreeMap<String, Vec<Value>>, ty: &str, pattern: &str) -> &'a Vec<Value> {
    h.values()
        .find(|v| {
            v[0]["type"] == ty
                && v[0]["pattern"]
                    .as_str()
                    .or_else(|| v[0]["sighting_of_ref"].as_str())
                    .is_some_and(|p| p.contains(pattern))
        })
        .unwrap_or_else(|| panic!("no {ty} for {pattern}"))
}

const CALLBACK: &str = "q4x9.cb.example.invalid";

/// Three days that share indicators, built in every order in one run: the
/// log is identical, every object has one version, and the shared
/// indicator and sighting aggregate all three days.
#[tokio::test]
async fn shared_objects_do_not_depend_on_the_order_days_are_built() {
    let mut logs = Vec::new();
    for order in [[0, 1, 2], [2, 1, 0], [1, 2, 0], [0, 2, 1]] {
        let mut evs = Vec::new();
        for n in 0..3 {
            evs.extend(day_events(n));
        }
        let h = harness_with(evs).await;
        h.now.store(day_start(2) + 6 * HOUR, Ordering::SeqCst);
        // Days are built least recently served first: seed the order.
        let fence = seed_lease(&h).await;
        for (rank, n) in order.iter().enumerate() {
            h.store
                .put_stix_day(
                    "t1",
                    PUBLISHED,
                    day_start(*n),
                    DayRecord {
                        served_ms: rank as i64,
                        ..Default::default()
                    },
                    fence,
                )
                .await
                .unwrap();
        }
        h.store.stix_release("t1", PUBLISHED, "seed").await.unwrap();
        let r = materialise(&h.state, "t1").await.unwrap();
        assert!(!r.incomplete, "{r:?}");
        // The three days, and the day before (its margin reads day 0's
        // first hours but owns none of its attempts).
        assert_eq!(r.days_written, 4, "{r:?}");
        let log = history(&h.state).await;
        for (id, v) in &log {
            assert_eq!(v.len(), 1, "{id}: no intermediate versions");
        }
        logs.push(log);
    }
    for other in &logs[1..] {
        assert_eq!(&logs[0], other, "the same log whatever the order");
    }
    let log = &logs[0];
    let ind = &find(log, "indicator", CALLBACK)[0];
    let sid = ind["id"].as_str().unwrap();
    let sighting = &find(log, "sighting", sid)[0];
    // Day 0 alone: the shared objects start there and count a third.
    let (one_day, valid_from) = {
        let h = harness_with(day_events(0)).await;
        materialise(&h.state, "t1").await.unwrap();
        let l = history(&h.state).await;
        let i = &find(&l, "indicator", CALLBACK)[0];
        let id = i["id"].as_str().unwrap().to_string();
        (
            find(&l, "sighting", &id)[0]["count"].as_u64().unwrap(),
            i["valid_from"].clone(),
        )
    };
    assert_eq!(ind["valid_from"], valid_from);
    assert_eq!(sighting["count"].as_u64().unwrap(), 3 * one_day);
    assert_eq!(
        sighting["observed_data_refs"].as_array().unwrap().len(),
        3,
        "one observed-data per day's attempt"
    );
    let mut client = BTreeMap::new();
    merge(&mut client, log.values().map(|v| v[0].clone()).collect());
    assert!(dangling(&client).is_empty(), "{:?}", dangling(&client));
}

/// Days arriving one run at a time, in opposite orders, then the newest
/// day rebuilt again and again: the latest content is the same either way
/// and no object ever flips back to an earlier version.
#[tokio::test]
async fn days_arriving_in_any_order_converge_without_flipping() {
    let mut finals = Vec::new();
    for order in [[0, 1, 2], [2, 1, 0]] {
        let h = harness_with(vec![]).await;
        h.now.store(day_start(2) + 6 * HOUR, Ordering::SeqCst);
        for n in order {
            h.store.enqueue_events(day_events(n)).await.unwrap();
            let r = materialise(&h.state, "t1").await.unwrap();
            assert!(r.days_written >= 1, "{r:?}");
        }
        // More of the same activity today, twice: the shared objects grow,
        // they do not swap between per-day views.
        for k in 1..=2 {
            h.store
                .enqueue_events(events("exports/synthetic.input.json", 2 * DAY + k * HOUR))
                .await
                .unwrap();
            h.now.store(day_start(2) + (6 + k) * HOUR, Ordering::SeqCst);
            materialise(&h.state, "t1").await.unwrap();
        }
        let log = history(&h.state).await;
        assert_no_flips(&log);
        let ind = find(&log, "indicator", CALLBACK);
        let sid = ind[0]["id"].as_str().unwrap().to_string();
        let counts: Vec<u64> = find(&log, "sighting", &sid)
            .iter()
            .map(|s| s["count"].as_u64().unwrap())
            .collect();
        assert!(counts.windows(2).all(|w| w[0] < w[1]), "{counts:?}");
        let confidence: Vec<u64> = ind
            .iter()
            .map(|i| i["confidence"].as_u64().unwrap())
            .collect();
        assert!(
            confidence.windows(2).all(|w| w[0] <= w[1]),
            "{confidence:?}"
        );
        finals.push(latest_content(&log));
    }
    assert_eq!(finals[0], finals[1]);
}

/// A day with more parts than one run may build is continued from where
/// the run stopped, newer days still get built meanwhile, and the result
/// is what one unbounded run writes.
#[tokio::test]
async fn a_day_over_budget_is_continued_and_does_not_block_newer_days() {
    // Day 0: the synthetic attempt five times (30 events); 4 per part.
    let busy = || {
        let mut evs = Vec::new();
        for k in 0..5 {
            evs.extend(events("exports/synthetic.input.json", k * 10 * 60_000));
        }
        evs
    };
    let small = Budget {
        parts: 2,
        parts_per_day: 2,
        chunks: DEFAULT_BUDGET.chunks,
    };

    let mut h = harness_with(busy()).await;
    h.state.limits.max_window_events = 4;
    h.now.store(day_start(2) + 6 * HOUR, Ordering::SeqCst);
    let first = materialise_with(&h.state, "t1", small).await.unwrap();
    assert!(first.incomplete);
    assert_eq!(first.parts, 2);
    assert_eq!(first.days_written, 0, "the busy day is not done yet");
    let days = h.store.stix_days("t1", PUBLISHED).await.unwrap();
    let p = days[&day_start(0)].progress.clone().unwrap();
    assert_eq!(p.parts, 2, "progress is stored");
    assert!(p.cursor.is_some());

    // A newer day gets events; it is built in the next run, ahead of the
    // busy day that already had its turn.
    h.store.enqueue_events(day_events(2)).await.unwrap();
    let second = materialise_with(&h.state, "t1", small).await.unwrap();
    assert_eq!(second.days_written, 1, "{second:?}");
    let days = h.store.stix_days("t1", PUBLISHED).await.unwrap();
    assert!(
        days[&day_start(2)].progress.is_none(),
        "the new day is done"
    );
    assert!(days[&day_start(0)].progress.is_some());

    let mut parts = first.parts + second.parts;
    for _ in 0..20 {
        let r = materialise_with(&h.state, "t1", small).await.unwrap();
        parts += r.parts;
        if !r.incomplete {
            break;
        }
    }
    let days = h.store.stix_days("t1", PUBLISHED).await.unwrap();
    assert!(days.values().all(|d| d.progress.is_none()), "{days:?}");

    // One unbounded run over the same events and part size.
    let mut evs = busy();
    evs.extend(day_events(2));
    let mut once = harness_with(evs).await;
    once.state.limits.max_window_events = 4;
    once.now.store(day_start(2) + 6 * HOUR, Ordering::SeqCst);
    let unbounded = Budget {
        parts: 100,
        parts_per_day: 100,
        chunks: 100,
    };
    let r = materialise_with(&once.state, "t1", unbounded)
        .await
        .unwrap();
    assert!(!r.incomplete);
    assert_eq!(parts, r.parts, "resumed parts are not rebuilt");
    let resumed = history(&h.state).await;
    assert_eq!(
        latest_content(&resumed),
        latest_content(&history(&once.state).await)
    );
    let mut client = BTreeMap::new();
    merge(
        &mut client,
        resumed
            .values()
            .map(|v| v.last().unwrap().clone())
            .collect(),
    );
    assert!(dangling(&client).is_empty(), "{:?}", dangling(&client));
}

/// One run per tenant at a time: a second run (cron or admin) is refused
/// while the lease is held, and a crashed run's lease lapses.
#[tokio::test]
async fn a_second_run_for_the_tenant_is_refused_until_the_lease_lapses() {
    let h = harness().await;
    let s = &h.state;
    let now = T0 + HOUR;
    assert!(
        h.store
            .stix_lease("t1", PUBLISHED, "crashed-run", now, LEASE_MS)
            .await
            .unwrap()
            .is_some()
    );
    let e = materialise(s, "t1").await.unwrap_err();
    assert_eq!(e.status, StatusCode::CONFLICT);
    let (st, _, body) = call(s, "POST", Some("admin"), "/v0/taxii/materialise", None).await;
    assert_eq!(st, StatusCode::CONFLICT, "{body}");
    assert_eq!(h.store.audit().last().unwrap().outcome.as_str(), "denied");
    // The cron skips the tenant rather than failing.
    assert_eq!(materialise_all(s).await.unwrap(), 1);
    assert!(poll(s, "", 10).await.0.is_empty(), "nothing was written");

    h.now.store(now + LEASE_MS + 1, Ordering::SeqCst);
    let r = materialise(s, "t1").await.unwrap();
    assert!(r.versions_written > 0);
    // The run gave its lease back; the next holder's generation is
    // higher than any before it.
    let next = h
        .store
        .stix_lease("t1", PUBLISHED, "next", now + LEASE_MS + 2, LEASE_MS)
        .await
        .unwrap();
    assert_eq!(next, Some(3));
}

/// Take the lease as a test writer; returns its generation.
async fn seed_lease(h: &H) -> i64 {
    h.store
        .stix_lease(
            "t1",
            PUBLISHED,
            "seed",
            h.now.load(Ordering::SeqCst),
            LEASE_MS,
        )
        .await
        .unwrap()
        .expect("lease")
}

/// A run that stalls past its lease while another run takes the tenant
/// over cannot write again: every write is fenced by the lease generation,
/// and the run stops.
#[tokio::test]
async fn a_stalled_run_cannot_write_after_a_takeover() {
    let h = harness_with(day_events(0)).await;
    // Another run takes the tenant after the stalled run's third write.
    h.store.take_over_stix_lease_after("t1", PUBLISHED, 3);
    let e = materialise(&h.state, "t1").await.unwrap_err();
    assert_eq!(e.status, StatusCode::CONFLICT);
    assert!(e.message.contains("lease"), "{e:?}");
    let days = h.store.stix_days("t1", PUBLISHED).await.unwrap();
    // Writes after the takeover were refused: no day was finished.
    assert!(days.values().all(|d| d.signature.is_empty()), "{days:?}");
    // The stalled run's generation is refused for every kind of write.
    let stale = 1;
    assert!(
        h.store
            .put_stix_day("t1", PUBLISHED, 0, DayRecord::default(), stale)
            .await
            .is_err()
    );
    assert!(
        h.store
            .stix_append("t1", PUBLISHED, vec![], vec![], T0, stale)
            .await
            .is_err()
    );
}

/// An IOC whose own day passes the gate but whose merged view across days
/// does not (here: other days fill its first 16 attempts with ones that
/// add nothing, which pushes the day's hook out): nothing published names
/// it, by value or by id, and no reference is left without a target.
#[tokio::test]
async fn below_gate_iocs_are_never_named_or_referenced() {
    use foiled_core::intel::merge::IocContribution;
    use foiled_core::ioc::{IocType, ioc_id};
    let ip = "203.0.113.60";
    let id = ioc_id(IocType::Ip, ip);
    let h = harness_with(day_events(0)).await;
    let s = &h.state;
    // The day alone publishes it: the plain export has it.
    let (st, _, body) = call(
        s,
        "GET",
        Some("lead"),
        &format!(
            "/v0/exports/stix?since={}&until={}",
            day_start(0),
            day_start(1)
        ),
        None,
    )
    .await;
    assert_eq!(st, StatusCode::OK, "{body}");
    assert!(body.contains(ip), "the day's gate passes it");

    // An old day's contribution with 16 attempts that sort first and add
    // nothing.
    let weak = IocContribution {
        ioc_id: id.clone(),
        ioc_type: IocType::Ip,
        value: ip.into(),
        display: String::new(),
        roles: BTreeSet::new(),
        redacted: false,
        file_ioc_limited: false,
        first_seen: day_start(-10),
        last_seen: day_start(-10),
        sightings: 16,
        attempts: 16,
        campaign_ids: BTreeSet::new(),
        decoy_ids: BTreeSet::new(),
        catalogue_ids: BTreeSet::new(),
        extracted_from: BTreeSet::new(),
        fingerprint: None,
        evidence: (0..16)
            .map(|n| (format!("att_000000000000000000{n:04}"), Default::default()))
            .collect(),
        observed: BTreeSet::new(),
    };
    let fence = seed_lease(&h).await;
    let old = day_start(-10);
    h.store
        .stix_stage_part(
            "t1",
            PUBLISHED,
            old,
            0,
            vec![],
            vec![(id.clone(), serde_json::to_string(&weak).unwrap())],
            DayRecord::default(),
            fence,
        )
        .await
        .unwrap();
    h.store
        .stix_promote_day(
            "t1",
            PUBLISHED,
            old,
            DayRecord {
                signature: "old".into(),
                ..Default::default()
            },
            fence,
        )
        .await
        .unwrap();
    h.store.stix_release("t1", PUBLISHED, "seed").await.unwrap();

    let r = materialise(s, "t1").await.unwrap();
    assert!(!r.incomplete, "{r:?}");
    let log = history(s).await;
    assert!(!log.is_empty());
    let text = serde_json::to_string(&log).unwrap();
    let sco = stix::observable_for(IocType::Ip, ip).unwrap()["id"]
        .as_str()
        .unwrap()
        .to_string();
    let ind = stix::foiled_id("indicator", &id);
    for needle in [ip, sco.as_str(), ind.as_str()] {
        assert!(!text.contains(needle), "{needle} is below the gate");
    }
    // The attempt itself is still published.
    assert!(
        log.values()
            .any(|v| matches!(v[0]["type"].as_str(), Some("observed-data" | "grouping")))
    );
    let mut client = BTreeMap::new();
    merge(&mut client, log.values().flatten().cloned().collect());
    assert!(dangling(&client).is_empty(), "{:?}", dangling(&client));
}

/// Two writers that planned from the same head cannot both write: the
/// second append of an existing (id, version) fails and writes nothing.
#[tokio::test]
async fn version_conflicts_fail_loudly() {
    let h = harness().await;
    let v = |content: &str, id: &str| NewVersion {
        id: id.into(),
        object_type: "indicator".into(),
        version: "2026-10-18T01:00:00.000Z".into(),
        created: Some("2026-10-18T01:00:00.000Z".into()),
        content: format!("{{\"c\":\"{content}\"}}"),
        content_sha256: content.into(),
        refs: vec![],
    };
    let a = "indicator--2ed6657d-e927-568b-95e1-2665a8aea6a2";
    let b = "indicator--3ed6657d-e927-568b-95e1-2665a8aea6a2";
    let fence = seed_lease(&h).await;
    assert_eq!(
        h.store
            .stix_append("t1", PUBLISHED, vec![v("one", a)], vec![], T0, fence)
            .await
            .unwrap(),
        1
    );
    // The same content as the head is skipped, not a conflict.
    assert_eq!(
        h.store
            .stix_append("t1", PUBLISHED, vec![v("one", a)], vec![], T0, fence)
            .await
            .unwrap(),
        0
    );
    let err = h
        .store
        .stix_append(
            "t1",
            PUBLISHED,
            vec![v("new", b), v("two", a)],
            vec![],
            T0,
            fence,
        )
        .await
        .unwrap_err();
    assert!(err.0.contains("conflict"), "{err:?}");
    assert!(
        poll(&h.state, &format!("&match[id]={b}"), 10)
            .await
            .0
            .is_empty(),
        "all or nothing"
    );
}

/// Late enrichment and campaign or rule changes rebuild the days they
/// touch, not only new events and analyst decisions.
#[tokio::test]
async fn late_enrichment_rebuilds_days() {
    let h = harness_with(day_events(0)).await;
    let s = &h.state;
    materialise(s, "t1").await.unwrap();
    let again = materialise(s, "t1").await.unwrap();
    assert_eq!(again.days_written, 0);
    h.store.add_cache_entry(CacheEntry {
        provider: "team_asn".into(),
        observable: Observable::ip("203.0.113.60").unwrap(),
        fetched_at: T0 + HOUR,
        ttl_secs: 604_800,
        facts: vec![Fact {
            provider: "team_asn".into(),
            key: "asn.number".into(),
            value: serde_json::json!(64498),
            confidence: 90,
            observed_at: T0 + HOUR,
            ttl_secs: 604_800,
            raw_ref: None,
        }],
        tenant_id: None,
    });
    h.now.store(T0 + 2 * HOUR, Ordering::SeqCst);
    let r = materialise(s, "t1").await.unwrap();
    assert!(r.days_written >= 1, "{r:?}");
}

/// A change that touches the inputs of every day but none of their events
/// rebuilds at most `QUIET_REBUILDS_PER_RUN` days per run, the rest in
/// later runs, and a cache refresh that only moves the fetch time
/// rebuilds nothing.
#[tokio::test]
async fn quiet_rebuilds_are_spread_and_refreshes_rebuild_nothing() {
    let mut evs = Vec::new();
    for n in 0..4 {
        evs.extend(day_events(n));
    }
    let h = harness_with(evs).await;
    let s = &h.state;
    let mut now = day_start(3) + 6 * HOUR;
    h.now.store(now, Ordering::SeqCst);
    while materialise(s, "t1").await.unwrap().incomplete {}
    let entry = |at: i64| CacheEntry {
        provider: "team_asn".into(),
        observable: Observable::ip("203.0.113.60").unwrap(),
        fetched_at: at,
        ttl_secs: 604_800,
        facts: vec![Fact {
            provider: "team_asn".into(),
            key: "asn.number".into(),
            value: serde_json::json!(64498),
            confidence: 90,
            observed_at: at,
            ttl_secs: 604_800,
            raw_ref: None,
        }],
        tenant_id: None,
    };
    // New enrichment for the address every day shares.
    now += HOUR;
    h.store.add_cache_entry(entry(now));
    h.now.store(now + 1, Ordering::SeqCst);
    let mut rebuilt = Vec::new();
    loop {
        let r = materialise(s, "t1").await.unwrap();
        // One part per day here, so parts count the days rebuilt.
        assert!(r.parts <= QUIET_REBUILDS_PER_RUN, "{r:?}");
        rebuilt.push(r.parts);
        if !r.incomplete {
            break;
        }
    }
    assert_eq!(rebuilt.iter().sum::<usize>(), 4, "{rebuilt:?}");
    assert!(rebuilt.len() >= 2, "{rebuilt:?}");
    // The same facts fetched again later: nothing to rebuild.
    now += HOUR;
    h.store.add_cache_entry(entry(now));
    h.now.store(now + 1, Ordering::SeqCst);
    let r = materialise(s, "t1").await.unwrap();
    assert_eq!(
        (r.days_written, r.parts, r.incomplete),
        (0, 0, false),
        "{r:?}"
    );
}

/// Each scheduled tick serves a bounded number of tenants and the next
/// tick starts after the last one served.
#[tokio::test]
async fn scheduled_ticks_rotate_through_tenants() {
    let mut evs = Vec::new();
    for t in ["t1", "t3", "t4"] {
        for mut e in day_events(0) {
            e.tenant_id = Some(t.into());
            e.event_id = format!("{t}-{}", e.event_id);
            evs.push(e);
        }
    }
    let h = harness_with(evs).await;
    let s = &h.state;
    let served = |h: &H| {
        let store = h.store.clone();
        async move {
            let mut out = Vec::new();
            for t in ["t1", "t3", "t4"] {
                if !store.stix_days(t, PUBLISHED).await.unwrap().is_empty() {
                    out.push(t);
                }
            }
            out
        }
    };
    assert_eq!(materialise_tick(s, 2, 1000).await.unwrap(), 2);
    assert_eq!(served(&h).await, ["t1", "t3"]);
    assert_eq!(
        h.store
            .stix_cron_cursor(PUBLISHED)
            .await
            .unwrap()
            .as_deref(),
        Some("t3")
    );
    assert_eq!(materialise_tick(s, 2, 1000).await.unwrap(), 2);
    assert_eq!(served(&h).await, ["t1", "t3", "t4"]);
    assert_eq!(
        h.store
            .stix_cron_cursor(PUBLISHED)
            .await
            .unwrap()
            .as_deref(),
        Some("t1"),
        "wrapped round"
    );
    // A work budget of one unit stops after the first tenant with work.
    let fresh = harness_with(
        h.store
            .queued_events()
            .into_iter()
            .filter(|e| e.tenant_id.as_deref() != Some("t1"))
            .collect(),
    )
    .await;
    assert_eq!(materialise_tick(&fresh.state, 3, 1).await.unwrap(), 1);
}
