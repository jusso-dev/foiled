//! The actor catalogue from ThreatSieve (#29) against a fake ThreatSieve
//! (`testdata/actors/threatsieve/responses.json`), no network: a staged
//! sync across cron runs, the versioned snapshot and its pin, freshness
//! and fallback to the bundled catalogue, mapping rules (wording,
//! publishers, restricted sources, model inferences), and restricted links
//! never exported.

use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};

use foiled_api::actor_sync::{
    BlobFuture, Blobs, MemoryBlobs, SyncDeps, SyncOutcome, bundled_config, current_snapshot,
    load_catalogue, refresh_catalogue, run_sync,
};
use foiled_api::enrich_consumer::{HttpFuture, HttpReply, ProviderHttp, ProviderRequest};
use foiled_core::actor::{
    ActorDecision, IndicatorType, LabelKind, LinkStatus, Subject, SubjectIndicator, SubjectKind,
    export_links, suggest,
};
use foiled_core::actor_sync::CatalogueConfig;
use foiled_core::confidence::{ConfidenceConfig, Feedback, Override};
use foiled_core::enrich_pipeline::HttpMethod;
use foiled_core::ioc::IocType;
use serde_json::Value;

const HOUR: i64 = 3_600_000;

fn fixture() -> Value {
    serde_json::from_str(
        &std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../testdata/actors/threatsieve/responses.json"
        ))
        .unwrap(),
    )
    .unwrap()
}

struct FakeThreatSieve {
    responses: Value,
    seen: RefCell<Vec<String>>,
    /// Answer every call with this status instead.
    force: RefCell<Option<u16>>,
}

impl FakeThreatSieve {
    fn new() -> Self {
        FakeThreatSieve {
            responses: fixture()["responses"].clone(),
            seen: RefCell::new(Vec::new()),
            force: RefCell::new(None),
        }
    }
}

impl ProviderHttp for FakeThreatSieve {
    fn send(&self, req: ProviderRequest) -> HttpFuture<'_> {
        assert_eq!(req.method, HttpMethod::Get);
        assert!(
            req.headers
                .iter()
                .any(|(k, v)| k == "authorization" && v == "Bearer ts-key"),
            "the key goes as a bearer token"
        );
        let path = req
            .url
            .strip_prefix("https://threatsieve")
            .unwrap()
            .to_string();
        self.seen.borrow_mut().push(path.clone());
        let reply = match *self.force.borrow() {
            Some(status) => HttpReply {
                status,
                body: "{}".into(),
                retry_after: Some("120".into()),
            },
            None => {
                let r = &self.responses[path.as_str()];
                assert!(!r.is_null(), "unexpected call {path}");
                HttpReply {
                    status: r["status"].as_u64().unwrap() as u16,
                    body: r["body"].to_string(),
                    retry_after: None,
                }
            }
        };
        Box::pin(std::future::ready(Ok(reply)))
    }
}

fn config(calls_per_run: u32) -> CatalogueConfig {
    let mut c = bundled_config().expect("bundled config loads").clone();
    c.threatsieve.enabled = true;
    c.threatsieve.calls_per_run = calls_per_run;
    c.threatsieve.include_restricted = true;
    c
}

fn now() -> i64 {
    fixture()["now"].as_i64().unwrap()
}

async fn sync(
    blobs: &dyn Blobs,
    http: Option<&FakeThreatSieve>,
    cfg: &CatalogueConfig,
    at: i64,
) -> SyncOutcome {
    let secret = |n: &str| (n == "THREATSIEVE_API_KEY").then(|| "ts-key".to_string());
    run_sync(&SyncDeps {
        blobs,
        http: http.map(|h| h as &dyn ProviderHttp),
        secret: &secret,
        config: cfg,
        now_ms: at,
    })
    .await
}

/// Run until the sync completes, returning every outcome.
async fn sync_to_end(
    blobs: &MemoryBlobs,
    http: &FakeThreatSieve,
    cfg: &CatalogueConfig,
) -> Vec<SyncOutcome> {
    let mut out = Vec::new();
    for _ in 0..20 {
        let o = sync(blobs, Some(http), cfg, now()).await;
        let done = matches!(o, SyncOutcome::Completed { .. });
        out.push(o);
        if done {
            break;
        }
    }
    out
}

#[tokio::test]
async fn nothing_happens_until_the_operator_opts_in() {
    let blobs = MemoryBlobs::default();
    let shipped = bundled_config().unwrap();
    assert!(!shipped.threatsieve.enabled, "opt-in, like enrichment");
    assert_eq!(
        sync(&blobs, None, shipped, now()).await,
        SyncOutcome::Disabled
    );
    let cfg = config(4);
    assert!(matches!(
        sync(&blobs, None, &cfg, now()).await,
        SyncOutcome::NotConfigured(_)
    ));
    let http = FakeThreatSieve::new();
    let no_key = |_: &str| None;
    let o = run_sync(&SyncDeps {
        blobs: &blobs,
        http: Some(&http),
        secret: &no_key,
        config: &cfg,
        now_ms: now(),
    })
    .await;
    assert!(matches!(o, SyncOutcome::NotConfigured(_)));
    assert!(http.seen.borrow().is_empty());
    // With nothing synced the API serves the bundled catalogue.
    let (sha, cat) = load_catalogue(&blobs, &cfg, now()).await;
    assert!(sha.is_none());
    assert!(cat.profiles.iter().all(|p| p.imported_from.is_none()));
}

#[tokio::test]
async fn a_staged_sync_imports_a_pinned_snapshot_with_the_rules_applied() {
    let blobs = MemoryBlobs::default();
    let http = FakeThreatSieve::new();
    let cfg = config(4);
    let outcomes = sync_to_end(&blobs, &http, &cfg).await;
    assert_eq!(
        outcomes[..2],
        [
            SyncOutcome::Progress { calls: 4 },
            SyncOutcome::Progress { calls: 4 }
        ],
        "four calls per run, state kept between runs"
    );
    let SyncOutcome::Completed { imported, key } = outcomes.last().unwrap().clone() else {
        panic!("{outcomes:?}");
    };
    assert_eq!(http.seen.borrow().len(), 10);
    assert!(key.starts_with("actors/threatsieve/snapshots/"));
    // The next run waits for refresh_after_hours.
    assert_eq!(
        sync(&blobs, Some(&http), &cfg, now() + HOUR).await,
        SyncOutcome::UpToDate
    );
    assert_eq!(http.seen.borrow().len(), 10);

    let (sha, snap) = current_snapshot(&blobs, &cfg, now())
        .await
        .expect("fresh and pinned");
    assert_eq!(snap.counts.imported, imported);
    assert_eq!(snap.counts.missing, 1, "removed since listing");
    assert!(
        snap.dropped
            .iter()
            .any(|d| d.starts_with("threat-actor_bad")),
        "{:?}",
        snap.dropped
    );
    let (served, cat) = load_catalogue(&blobs, &cfg, now()).await;
    assert_eq!(served.as_deref(), Some(sha.as_str()));

    // ATT&CK G0106 is in the pinned sidecar: the sidecar wins.
    assert!(cat.get("attack:G0106").unwrap().imported_from.is_none());
    // G9001 is new: imported, one publisher, half weight, sidecar ids only.
    let g = cat.get("attack:G9001").unwrap();
    assert_eq!(g.imported_from.as_deref(), Some("threatsieve"));
    assert_eq!(g.weight_pct, 50);
    assert_eq!(g.label, "ATT&CK G9001 (EXAMPLE New Group)");
    assert!(g.techniques.contains(&"T1059.004".to_string()));
    assert!(!g.techniques.contains(&"T9999".to_string()));
    assert!(
        !g.restricted,
        "MITRE allows redistribution and commercial use"
    );
    assert!(
        cat.get("attack:C9001").is_some(),
        "campaigns import as clusters"
    );

    // The TAXII cluster: three publishers (the mirror does not count), a
    // named group, restricted, no model-inferred indicator.
    let c = cat
        .profiles
        .iter()
        .find(|p| p.label.starts_with("EXAMPLE-TS-CLUSTER-7"))
        .unwrap();
    assert_eq!(c.label_kind, LabelKind::NamedGroup);
    assert_eq!(c.weight_pct, 100);
    assert!(c.restricted);
    let ind: BTreeSet<&str> = c.indicators.iter().map(|i| i.value.as_str()).collect();
    assert_eq!(
        ind,
        BTreeSet::from(["stage2.example.invalid", "192.0.2.80"])
    );
    assert_eq!(c.targeting.cves, ["CVE-2099-0001"]);
    assert!(
        c.sources
            .iter()
            .any(|s| s.url == "https://reports.example.com/ts/7")
    );
    assert!(
        c.sources
            .iter()
            .all(|s| s.publisher != "MISP galaxy mirror")
    );
    assert!(
        !c.aliases.iter().any(|a| a.contains("responsible")),
        "{:?}",
        c.aliases
    );
    for p in cat.profiles.iter().filter(|p| p.imported_from.is_some()) {
        assert!(foiled_core::actor::wording_problems(&p.label, false).is_empty());
    }
    assert!(cat.problems.is_empty(), "{:?}", cat.problems);

    // By default restricted entries stay out of the served catalogue.
    let mut strict = cfg.clone();
    strict.threatsieve.include_restricted = false;
    let (_, cat) = load_catalogue(&blobs, &strict, now()).await;
    assert!(cat.profiles.iter().all(|p| !p.restricted));
    assert!(cat.get("attack:G9001").is_some());
}

#[tokio::test]
async fn stale_or_tampered_snapshots_fall_back_to_the_bundled_catalogue() {
    let blobs = MemoryBlobs::default();
    let http = FakeThreatSieve::new();
    let cfg = config(50);
    sync_to_end(&blobs, &http, &cfg).await;
    let week = i64::from(cfg.threatsieve.stale_after_hours) * HOUR;
    let (sha, cat) = load_catalogue(&blobs, &cfg, now() + week + HOUR).await;
    assert!(sha.is_none(), "stale");
    assert!(cat.get("attack:G9001").is_none());
    // A body that no longer matches the pointer's digest is refused.
    let key = blobs
        .keys()
        .into_iter()
        .find(|k| k.contains("/snapshots/"))
        .unwrap();
    let body = blobs.get(&key).await.unwrap().unwrap();
    blobs
        .put(&key, body.replace("EXAMPLE New Group", "EXAMPLE Tampered"))
        .await
        .unwrap();
    assert!(current_snapshot(&blobs, &cfg, now()).await.is_none());
    assert!(load_catalogue(&blobs, &cfg, now()).await.0.is_none());
}

#[tokio::test]
async fn rate_limits_and_refusals_keep_progress() {
    let blobs = MemoryBlobs::default();
    let http = FakeThreatSieve::new();
    let cfg = config(4);
    assert_eq!(
        sync(&blobs, Some(&http), &cfg, now()).await,
        SyncOutcome::Progress { calls: 4 }
    );
    *http.force.borrow_mut() = Some(429);
    assert_eq!(
        sync(&blobs, Some(&http), &cfg, now()).await,
        SyncOutcome::Waiting {
            calls: 1,
            retry_after_secs: Some(120)
        }
    );
    // The saved state resumes where it stopped.
    *http.force.borrow_mut() = None;
    let before = http.seen.borrow().len();
    sync(&blobs, Some(&http), &cfg, now()).await;
    assert_eq!(
        http.seen.borrow()[before],
        http.seen.borrow()[before - 1],
        "the refused call again"
    );
    // A refused key stalls the sync; it does not throw progress away.
    *http.force.borrow_mut() = Some(401);
    assert!(matches!(
        sync(&blobs, Some(&http), &cfg, now()).await,
        SyncOutcome::Stalled { calls: 1, .. }
    ));
    *http.force.borrow_mut() = None;
    let start = http.seen.borrow().len();
    sync(&blobs, Some(&http), &cfg, now()).await;
    assert_eq!(
        http.seen.borrow()[start],
        http.seen.borrow()[start - 1],
        "the refused call again, not a new sync"
    );
}

#[tokio::test]
async fn a_sync_making_progress_is_never_restarted() {
    let blobs = MemoryBlobs::default();
    let http = FakeThreatSieve::new();
    let cfg = config(1);
    let cap = i64::from(cfg.threatsieve.max_sync_hours) * HOUR;
    // One call a day: far past max_sync_hours in total, progress every run.
    let mut at = now();
    let mut last = SyncOutcome::Disabled;
    for _ in 0..20 {
        last = sync(&blobs, Some(&http), &cfg, at).await;
        if matches!(last, SyncOutcome::Completed { .. }) {
            break;
        }
        at += cap / 2;
    }
    assert!(matches!(last, SyncOutcome::Completed { .. }), "{last:?}");
    assert_eq!(http.seen.borrow().len(), 10, "no call made twice");
}

#[tokio::test]
async fn a_sync_with_no_progress_past_the_cap_starts_over() {
    let blobs = MemoryBlobs::default();
    let http = FakeThreatSieve::new();
    let cfg = config(4);
    let cap = i64::from(cfg.threatsieve.max_sync_hours) * HOUR;
    sync(&blobs, Some(&http), &cfg, now()).await;
    *http.force.borrow_mut() = Some(429);
    sync(&blobs, Some(&http), &cfg, now() + HOUR).await;
    *http.force.borrow_mut() = None;
    let start = http.seen.borrow().len();
    sync(&blobs, Some(&http), &cfg, now() + cap + 2 * HOUR).await;
    assert_eq!(
        http.seen.borrow()[start],
        "/v1/actors?limit=100",
        "a new sync"
    );
}

/// [`MemoryBlobs`] that can fail writes to one key and records reads.
#[derive(Default)]
struct FlakyBlobs {
    inner: MemoryBlobs,
    fail_put: RefCell<Option<String>>,
    reads: RefCell<Vec<String>>,
}

impl Blobs for FlakyBlobs {
    fn get(&self, key: &str) -> BlobFuture<'_, Option<String>> {
        self.reads.borrow_mut().push(key.to_string());
        self.inner.get(key)
    }

    fn put(&self, key: &str, body: String) -> BlobFuture<'_, ()> {
        if self
            .fail_put
            .borrow()
            .as_deref()
            .is_some_and(|k| key.ends_with(k))
        {
            return Box::pin(std::future::ready(Err("R2 unavailable".into())));
        }
        self.inner.put(key, body)
    }
}

#[tokio::test]
async fn a_failed_pointer_write_is_retried_without_resyncing() {
    let blobs = FlakyBlobs::default();
    let http = FakeThreatSieve::new();
    let cfg = config(50);
    *blobs.fail_put.borrow_mut() = Some("current.json".into());
    assert!(matches!(
        sync(&blobs, Some(&http), &cfg, now()).await,
        SyncOutcome::Waiting { .. }
    ));
    assert_eq!(http.seen.borrow().len(), 10);
    assert!(current_snapshot(&blobs, &cfg, now()).await.is_none());
    *blobs.fail_put.borrow_mut() = None;
    let o = sync(&blobs, Some(&http), &cfg, now() + HOUR).await;
    assert!(matches!(o, SyncOutcome::Completed { .. }), "{o:?}");
    assert_eq!(
        http.seen.borrow().len(),
        10,
        "published from the saved state"
    );
    let (_, snap) = current_snapshot(&blobs, &cfg, now() + HOUR).await.unwrap();
    assert_eq!(snap.synced_at, now(), "synced when the last call answered");
    assert_eq!(
        sync(&blobs, Some(&http), &cfg, now() + 2 * HOUR).await,
        SyncOutcome::UpToDate
    );
}

#[tokio::test]
async fn an_unchanged_pointer_skips_the_snapshot_body() {
    let blobs = FlakyBlobs::default();
    let http = FakeThreatSieve::new();
    let cfg = config(50);
    sync(&blobs, Some(&http), &cfg, now()).await;
    blobs.reads.borrow_mut().clear();
    let first = refresh_catalogue(&blobs, &cfg, now(), None).await;
    assert!(first.sha256.is_some());
    assert!(
        blobs
            .reads
            .borrow()
            .iter()
            .any(|k| k.contains("/snapshots/"))
    );
    blobs.reads.borrow_mut().clear();
    let again = refresh_catalogue(&blobs, &cfg, now() + HOUR, Some(&first)).await;
    assert_eq!(again.sha256, first.sha256);
    assert!(std::sync::Arc::ptr_eq(&again.catalogue, &first.catalogue));
    assert_eq!(
        *blobs.reads.borrow(),
        ["actors/threatsieve/current.json"],
        "the pointer only"
    );
    // Once stale, the same pointer no longer serves the imports.
    let week = i64::from(cfg.threatsieve.stale_after_hours) * HOUR;
    let stale = refresh_catalogue(&blobs, &cfg, now() + week + HOUR, Some(&first)).await;
    assert!(stale.sha256.is_none());
    assert!(stale.catalogue.get("attack:G9001").is_none());
}

#[tokio::test]
async fn restricted_profiles_link_but_never_export() {
    let blobs = MemoryBlobs::default();
    let http = FakeThreatSieve::new();
    let cfg = config(50);
    sync_to_end(&blobs, &http, &cfg).await;
    let (_, cat) = load_catalogue(&blobs, &cfg, now()).await;
    let s = Subject {
        kind: SubjectKind::Campaign,
        id: "cmp_000000000000000000000001".into(),
        tenant_id: "t1".into(),
        seed_attempt_id: "att_1".into(),
        attempt_ids: vec!["att_1".into()],
        first_seen: now(),
        techniques: BTreeSet::new(),
        indicators: vec![SubjectIndicator {
            kind: IndicatorType::Domain,
            value: "stage2.example.invalid".into(),
            ioc_id: "ioc_1".into(),
            ioc_type: IocType::Domain,
            observed: true,
        }],
        asns: BTreeSet::new(),
        cves: BTreeSet::new(),
        catalogue_ids: BTreeSet::new(),
        sources: BTreeSet::new(),
        countries: BTreeSet::new(),
    };
    let pending = suggest(
        &cat,
        &ConfidenceConfig::default(),
        std::slice::from_ref(&s),
        &BTreeMap::new(),
    );
    let l = pending
        .iter()
        .find(|l| l.label.starts_with("EXAMPLE-TS-CLUSTER-7"))
        .expect("a restricted profile still matches");
    assert!(l.restricted);
    assert!(l.not_counted.iter().any(|n| n.contains("never exported")));
    let d = BTreeMap::from([(
        (s.id.clone(), l.actor_id.clone()),
        ActorDecision {
            subject_id: s.id.clone(),
            actor_id: l.actor_id.clone(),
            decision: Override {
                feedback: Feedback::TruePositive,
                analyst_id: "lead".into(),
                at: 1,
                note: "Reviewed against the feed.".into(),
            },
            attempt_ids: vec!["att_1".into()],
        },
    )]);
    let confirmed = suggest(&cat, &ConfidenceConfig::default(), &[s], &d);
    let c = confirmed.iter().find(|x| x.actor_id == l.actor_id).unwrap();
    assert_eq!(c.status, LinkStatus::Confirmed);
    assert!(
        export_links(&confirmed)
            .values()
            .flatten()
            .all(|x| x.target != c.label)
    );
}
