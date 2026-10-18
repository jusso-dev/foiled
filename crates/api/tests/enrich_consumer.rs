//! The `foiled-enrich` consumer (#11) over the in-memory store, with a fake
//! ThreatSieve. No test makes a network call: the fake answers `POST
//! /v1/lookup` from `testdata/enrichment/threatsieve/lookup.json` (only the
//! observables it was asked about, as ThreatSieve does) and records every
//! request.

use std::cell::RefCell;

use foiled_api::enrich_consumer::{
    Deps, HttpFuture, HttpReply, MessageReport, Outcome, ProviderHttp, ProviderRequest,
    ProviderResult, process_batch,
};
use foiled_api::memory::MemoryStore;
use foiled_api::store::Store;
use foiled_core::enrich_pipeline::{EnrichConfig, EnrichMessage, HttpMethod, LOOKUP_URL, Priority};
use foiled_core::enrichment::{
    AsnTable, LOCAL_ASN, Observable, THREATSIEVE, THREATSIEVE_RESTRICTED,
};
use serde_json::Value;

const NOW: i64 = 1_792_285_400_000;
const FIX: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../testdata/enrichment");
const KEY: &str = "fake-intel-read-key";

/// How the fake answers.
#[derive(Clone)]
enum Mode {
    /// 200 with the fixture's results for the asked observables.
    Answer,
    /// This status, an optional `Retry-After` and an error body.
    Status(u16, Option<&'static str>),
    /// The binding call itself fails.
    Refuse,
}

/// A fake ThreatSieve behind the service binding.
struct FakeThreatSieve {
    mode: RefCell<Mode>,
    seen: RefCell<Vec<ProviderRequest>>,
}

impl FakeThreatSieve {
    fn new() -> Self {
        FakeThreatSieve {
            mode: RefCell::new(Mode::Answer),
            seen: RefCell::new(Vec::new()),
        }
    }

    fn set(&self, mode: Mode) {
        *self.mode.borrow_mut() = mode;
    }

    fn calls(&self) -> usize {
        self.seen.borrow().len()
    }

    /// The `value`s of each request, in order.
    fn asked(&self) -> Vec<Vec<String>> {
        self.seen
            .borrow()
            .iter()
            .map(|r| {
                let body: Value = serde_json::from_str(r.body.as_deref().unwrap()).unwrap();
                body["observables"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|o| o["value"].as_str().unwrap().to_string())
                    .collect()
            })
            .collect()
    }
}

fn fixture() -> Value {
    serde_json::from_str(
        &std::fs::read_to_string(format!("{FIX}/threatsieve/lookup.json")).unwrap(),
    )
    .unwrap()
}

impl ProviderHttp for FakeThreatSieve {
    fn send(&self, req: ProviderRequest) -> HttpFuture<'_> {
        assert_eq!(req.method, HttpMethod::Post);
        assert_eq!(req.url, LOOKUP_URL);
        let auth = req
            .headers
            .iter()
            .find(|(k, _)| k == "authorization")
            .map(|(_, v)| v.clone());
        let body: Value = serde_json::from_str(req.body.as_deref().unwrap()).unwrap();
        self.seen.borrow_mut().push(req);
        let mode = self.mode.borrow().clone();
        Box::pin(async move {
            if auth.as_deref() != Some(&format!("Bearer {KEY}")) {
                return Ok(HttpReply {
                    status: 401,
                    body: r#"{"error":"unauthorised"}"#.into(),
                    retry_after: None,
                });
            }
            match mode {
                Mode::Refuse => Err("connection refused".to_string()),
                Mode::Status(status, retry_after) => Ok(HttpReply {
                    status,
                    body: r#"{"error":"try later"}"#.into(),
                    retry_after: retry_after.map(str::to_string),
                }),
                Mode::Answer => {
                    let asked: Vec<String> = body["observables"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .map(|o| o["value"].as_str().unwrap().to_ascii_lowercase())
                        .collect();
                    let mut answer = fixture();
                    let results: Vec<Value> = answer["results"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .filter(|r| {
                            asked.contains(&r["value"].as_str().unwrap().to_ascii_lowercase())
                        })
                        .cloned()
                        .collect();
                    answer["results"] = Value::Array(results);
                    Ok(HttpReply {
                        status: 200,
                        body: answer.to_string(),
                        retry_after: None,
                    })
                }
            }
        })
    }
}

fn config() -> EnrichConfig {
    let mut c: EnrichConfig = serde_yaml_ng::from_str(
        &std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../configs/enrichment.yaml"
        ))
        .unwrap(),
    )
    .unwrap();
    c.providers.threatsieve.enabled = true;
    c
}

fn secrets(name: &str) -> Option<String> {
    (name == "THREATSIEVE_API_KEY").then(|| KEY.to_string())
}

fn msg(o: Observable, tenant: &str, priority: Priority) -> EnrichMessage {
    EnrichMessage {
        v: 1,
        observable: o,
        tenant_id: tenant.into(),
        event_id: Some("e1".into()),
        attempt_id: None,
        first_seen: NOW,
        priority,
    }
}

fn ip(v: &str, tenant: &str) -> EnrichMessage {
    msg(Observable::ip(v).unwrap(), tenant, Priority::High)
}

fn asn() -> AsnTable {
    AsnTable::from_csv(&std::fs::read_to_string(format!("{FIX}/asn.csv")).unwrap()).unwrap()
}

fn result<'a>(report: &'a MessageReport, id: &str) -> &'a ProviderResult {
    &report
        .1
        .iter()
        .find(|(p, _)| p == id)
        .unwrap_or_else(|| panic!("no {id} in {report:?}"))
        .1
}

#[tokio::test]
async fn one_lookup_per_batch_with_shared_and_per_tenant_rows() {
    let store = MemoryStore::new();
    let ts = FakeThreatSieve::new();
    let (c, table) = (config(), asn());
    let d = Deps {
        store: &store,
        threatsieve: Some(&ts),
        secret: &secrets,
        asn: Some(&table),
        config: &c,
        now_ms: NOW,
    };
    let batch = vec![
        ip("203.0.113.7", "t1"),
        ip("203.0.113.7", "t2"),
        msg(
            Observable::cve("CVE-2099-0001").unwrap(),
            "t1",
            Priority::Normal,
        ),
        ip("198.51.100.23", "t1"),
        msg(
            Observable::domain("Stage2.Example.INVALID").unwrap(),
            "t2",
            Priority::Normal,
        ),
        ip("203.0.113.8", "t1"),
        msg(
            Observable::domain("rejected.example.invalid").unwrap(),
            "t1",
            Priority::Normal,
        ),
    ];
    let reports = process_batch(&batch, &d).await;
    for r in &reports {
        assert_eq!(r.0, Outcome::Ack, "{r:?}");
    }
    assert_eq!(ts.calls(), 1, "one lookup for the whole batch");
    assert_eq!(ts.asked()[0].len(), 6, "duplicates are asked once");

    // GreyNoise terms forbid redistribution: kept for each tenant that asked.
    assert!(matches!(
        result(&reports[0], THREATSIEVE),
        ProviderResult::Written {
            restricted: true,
            dropped: 0,
            ..
        }
    ));
    let rows = store.cache_entries();
    let restricted: Vec<_> = rows
        .iter()
        .filter(|e| e.provider == THREATSIEVE_RESTRICTED && e.observable.value == "203.0.113.7")
        .collect();
    assert_eq!(restricted.len(), 2);
    let mut tenants: Vec<_> = restricted
        .iter()
        .map(|e| e.tenant_id.clone().unwrap())
        .collect();
    tenants.sort();
    assert_eq!(tenants, ["t1", "t2"]);
    assert!(
        restricted[0]
            .facts
            .iter()
            .any(|f| f.key == "asn.number" && f.value == 64500)
    );

    // Every source redistributable: one shared row, cached no longer than
    // ThreatSieve's ttl_seconds.
    let cve = rows
        .iter()
        .find(|e| e.observable.kind.as_str() == "cve")
        .unwrap();
    assert_eq!(cve.provider, THREATSIEVE);
    assert_eq!(cve.tenant_id, None);
    assert_eq!(cve.ttl_secs, 3600);
    assert!(cve.facts.iter().any(|f| f.key == "cve.kev_listed"));

    // Unknown terms (commercial_use: null) are restricted too.
    let domain = rows
        .iter()
        .find(|e| e.observable.kind.as_str() == "domain")
        .unwrap();
    assert_eq!(domain.provider, THREATSIEVE_RESTRICTED);
    assert_eq!(domain.tenant_id.as_deref(), Some("t2"));

    // Not found: an empty shared row, for no longer than ttl_seconds.
    let miss = rows
        .iter()
        .find(|e| e.observable.value == "198.51.100.23" && e.provider == THREATSIEVE)
        .unwrap();
    assert!(miss.facts.is_empty());
    assert!(miss.ttl_secs <= 600);

    // A source still pending: cached for five minutes at most.
    let pending = rows
        .iter()
        .find(|e| e.observable.value == "203.0.113.8" && e.provider == THREATSIEVE)
        .unwrap();
    assert!(pending.ttl_secs <= 300);
    assert!(!pending.is_fresh(NOW + 301_000));

    // A value ThreatSieve rejects is not cached and backs off.
    assert!(
        matches!(result(&reports[6], THREATSIEVE), ProviderResult::Failed(e) if e.contains("INVALID_OBSERVABLE"))
    );
    assert!(
        !rows
            .iter()
            .any(|e| e.observable.value == "rejected.example.invalid")
    );
    let rejected = Observable::domain("rejected.example.invalid").unwrap();
    assert_eq!(store.enrich_failures(rejected).await.unwrap().len(), 1);

    // local_asn still answers from the operator's table.
    assert!(matches!(
        result(&reports[0], LOCAL_ASN),
        ProviderResult::Written { .. }
    ));
    for row in &rows {
        assert!(row.facts.iter().all(|f| f.provider == row.provider));
        assert!(row.is_fresh(NOW));
    }

    // The same tenants again: everything cached (or backing off), and
    // ThreatSieve not asked.
    let again = process_batch(&batch[..6], &d).await;
    for r in &again {
        assert!(
            r.1.iter().all(|(_, p)| *p == ProviderResult::Cached),
            "{r:?}"
        );
    }
    assert_eq!(ts.calls(), 1);

    // Another tenant cannot read t1's restricted row, so it asks for itself.
    let other = process_batch(&[ip("203.0.113.7", "t3")], &d).await;
    assert!(matches!(
        result(&other[0], THREATSIEVE),
        ProviderResult::Written {
            restricted: true,
            ..
        }
    ));
    assert_eq!(ts.calls(), 2);
    let t3 = store
        .enrichment_cache(
            vec![Observable::ip("203.0.113.7").unwrap()],
            NOW,
            1,
            Some("t3".into()),
        )
        .await
        .unwrap();
    assert!(t3.iter().all(|e| e.tenant_id.as_deref() != Some("t1")));
}

#[tokio::test]
async fn lookups_are_chunked_by_batch_size_and_budgets_are_never_overspent() {
    let store = MemoryStore::new();
    let ts = FakeThreatSieve::new();
    let mut c = config();
    c.providers.threatsieve.batch_size = 2;
    c.providers.threatsieve.rate_limit.per_minute = 2;
    let d = Deps {
        store: &store,
        threatsieve: Some(&ts),
        secret: &secrets,
        asn: None,
        config: &c,
        now_ms: NOW,
    };
    let batch: Vec<_> = (1..=5)
        .map(|n| ip(&format!("198.51.100.{n}"), "t1"))
        .collect();
    let reports = process_batch(&batch, &d).await;
    assert_eq!(ts.calls(), 2, "two chunks of two; the third has no budget");
    assert!(ts.asked().iter().all(|a| a.len() == 2));
    assert_eq!(
        *result(&reports[4], THREATSIEVE),
        ProviderResult::MinuteBudgetSpent
    );
    assert_eq!(reports[4].0, Outcome::Retry { delay_secs: 60 });
    assert_eq!(reports[0].0, Outcome::Ack);

    // Day budget: normal priority may use 80 percent, high all of it.
    let mut c = config();
    c.providers.threatsieve.rate_limit.per_day = 5;
    let store = MemoryStore::new();
    let ts = FakeThreatSieve::new();
    let mut normal = 0;
    for minute in 0..6 {
        let d = Deps {
            store: &store,
            threatsieve: Some(&ts),
            secret: &secrets,
            asn: None,
            config: &c,
            now_ms: NOW + minute * 60_000,
        };
        let o = Observable::ip(&format!("203.0.113.{}", minute + 10)).unwrap();
        let r = process_batch(&[msg(o, "t1", Priority::Normal)], &d).await;
        match result(&r[0], THREATSIEVE) {
            ProviderResult::Written { .. } => normal += 1,
            ProviderResult::DayBudgetSpent => assert_eq!(r[0].0, Outcome::Ack),
            other => panic!("{other:?}"),
        }
    }
    assert_eq!(normal, 4);
    let d = Deps {
        store: &store,
        threatsieve: Some(&ts),
        secret: &secrets,
        asn: None,
        config: &c,
        now_ms: NOW + 10 * 60_000,
    };
    let r = process_batch(&[ip("203.0.113.40", "t1")], &d).await;
    assert!(matches!(
        result(&r[0], THREATSIEVE),
        ProviderResult::Written { .. }
    ));
    let r = process_batch(&[ip("203.0.113.41", "t1")], &d).await;
    assert_eq!(*result(&r[0], THREATSIEVE), ProviderResult::DayBudgetSpent);
    assert_eq!(ts.calls(), 5);
}

#[tokio::test]
async fn rate_limits_honour_retry_after_and_failures_back_off() {
    let store = MemoryStore::new();
    let ts = FakeThreatSieve::new();
    ts.set(Mode::Status(429, Some("120")));
    let c = config();
    let at = |now_ms| Deps {
        store: &store,
        threatsieve: Some(&ts),
        secret: &secrets,
        asn: None,
        config: &c,
        now_ms,
    };
    let batch = [ip("203.0.113.7", "t1"), ip("198.51.100.23", "t1")];
    let r = process_batch(&batch, &at(NOW)).await;
    assert!(
        matches!(result(&r[0], THREATSIEVE), ProviderResult::Failed(e) if e.contains("rate limited"))
    );
    assert_eq!(r[0].0, Outcome::Retry { delay_secs: 120 });
    assert_eq!(r[1].0, Outcome::Retry { delay_secs: 120 });
    let failures = store
        .enrich_failures(Observable::ip("203.0.113.7").unwrap())
        .await
        .unwrap();
    assert_eq!(failures[0].retry_at, Some(NOW + 120_000));

    // Not asked again before Retry-After, even after the error backoff.
    ts.set(Mode::Answer);
    let r = process_batch(&batch, &at(NOW + 60_000)).await;
    assert_eq!(*result(&r[0], THREATSIEVE), ProviderResult::BackingOff);
    assert_eq!(ts.calls(), 1);

    // Afterwards it answers, and the failure is forgotten.
    let r = process_batch(&batch, &at(NOW + 600_000)).await;
    assert!(matches!(
        result(&r[0], THREATSIEVE),
        ProviderResult::Written { .. }
    ));
    assert!(
        store
            .enrich_failures(Observable::ip("203.0.113.7").unwrap())
            .await
            .unwrap()
            .is_empty()
    );

    // Other errors are recorded and acknowledged: the next sighting retries
    // after the backoff.
    ts.set(Mode::Status(503, None));
    let r = process_batch(&[ip("203.0.113.9", "t1")], &at(NOW + 600_000)).await;
    assert_eq!(r[0].0, Outcome::Ack);
    assert!(matches!(result(&r[0], THREATSIEVE), ProviderResult::Failed(e) if e.contains("503")));
    ts.set(Mode::Refuse);
    let r = process_batch(&[ip("203.0.113.10", "t1")], &at(NOW + 600_000)).await;
    assert!(
        matches!(result(&r[0], THREATSIEVE), ProviderResult::Failed(e) if e.contains("refused"))
    );
}

#[tokio::test]
async fn a_missing_binding_or_key_degrades_to_local_asn_without_spending_budget() {
    let store = MemoryStore::new();
    let ts = FakeThreatSieve::new();
    let mut c = config();
    c.providers.threatsieve.rate_limit.per_minute = 1;
    let table = asn();
    let no_key = |_: &str| None;
    let d = Deps {
        store: &store,
        threatsieve: Some(&ts),
        secret: &no_key,
        asn: Some(&table),
        config: &c,
        now_ms: NOW,
    };
    let r = process_batch(&[ip("203.0.113.7", "t1")], &d).await;
    assert_eq!(r[0].0, Outcome::Ack);
    assert!(
        matches!(result(&r[0], THREATSIEVE), ProviderResult::NotConfigured(e) if e.contains("THREATSIEVE_API_KEY"))
    );
    assert!(matches!(
        result(&r[0], LOCAL_ASN),
        ProviderResult::Written { .. }
    ));
    let unbound = Deps {
        threatsieve: None,
        secret: &secrets,
        ..d
    };
    let r = process_batch(&[ip("203.0.113.7", "t1")], &unbound).await;
    assert!(
        matches!(result(&r[0], THREATSIEVE), ProviderResult::NotConfigured(e) if e.contains("THREATSIEVE"))
    );
    assert_eq!(ts.calls(), 0);
    assert!(
        store
            .cache_entries()
            .iter()
            .all(|e| e.provider == LOCAL_ASN)
    );

    // The minute budget of one is still whole.
    let ok = Deps {
        secret: &secrets,
        ..d
    };
    let r = process_batch(&[ip("203.0.113.7", "t1")], &ok).await;
    assert!(matches!(
        result(&r[0], THREATSIEVE),
        ProviderResult::Written { .. }
    ));
}

#[tokio::test]
async fn bad_messages_are_dropped_and_store_failures_retry() {
    let store = MemoryStore::new();
    let ts = FakeThreatSieve::new();
    let c = config();
    let d = Deps {
        store: &store,
        threatsieve: Some(&ts),
        secret: &secrets,
        asn: None,
        config: &c,
        now_ms: NOW,
    };
    let mut wrong = ip("203.0.113.7", "t1");
    wrong.v = 2;
    let r = process_batch(
        &[
            ip("10.0.0.1", "t1"),
            wrong,
            ip("203.0.113.7", "tenant@other"),
        ],
        &d,
    )
    .await;
    assert!(r.iter().all(|(o, _)| *o == Outcome::Drop), "{r:?}");
    assert_eq!(ts.calls(), 0, "private addresses never leave");

    store.fail_enrichment_reads();
    let r = process_batch(&[ip("203.0.113.7", "t1")], &d).await;
    assert_eq!(r[0].0, Outcome::Retry { delay_secs: 30 });
    assert_eq!(ts.calls(), 0);
}
