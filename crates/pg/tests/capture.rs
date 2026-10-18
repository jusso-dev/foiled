//! Capture event storage against a real Postgres (CI service container).

use foiled_core::capture::{CaptureEvent, Source, SourceKind};
use foiled_pg::{InsertError, events_between, events_for_decoy, insert_events, ip_iocs, migrate};
use tokio_postgres::{Client, NoTls};

async fn connect() -> Client {
    let url = std::env::var("FOILED_TEST_PG_URL")
        .expect("FOILED_TEST_PG_URL must point at a disposable Postgres database");
    let (client, conn) = tokio_postgres::connect(&url, NoTls).await.expect("connect");
    tokio::spawn(conn);
    migrate(&client).await.expect("migrate");
    client
}

fn fixture(name: &str) -> CaptureEvent {
    let path = format!(
        "{}/../../testdata/capture/{name}",
        env!("CARGO_MANIFEST_DIR")
    );
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

fn stamped(mut e: CaptureEvent, tenant: &str) -> CaptureEvent {
    e.stamp(
        Source {
            kind: SourceKind::Host,
            id: "host-1".into(),
        },
        tenant,
    );
    e
}

#[tokio::test]
#[ignore = "needs FOILED_TEST_PG_URL; CI runs it with --include-ignored"]
async fn events_insert_once_and_read_back_in_order() {
    let c = connect().await;
    let tenant = format!("cap-{}", std::process::id());
    let hook = stamped(fixture("hook-trigger.json"), &tenant);
    let http = stamped(fixture("http-upload.json"), &tenant);
    let n = insert_events(&c, &[hook.clone(), http.clone()], 1)
        .await
        .unwrap();
    assert_eq!(n, 2);
    // At-least-once redelivery is a no-op.
    let n = insert_events(&c, std::slice::from_ref(&http), 2)
        .await
        .unwrap();
    assert_eq!(n, 0);
    let got = events_for_decoy(&c, &tenant, &http.decoy_id, 10)
        .await
        .unwrap();
    assert_eq!(got, vec![http, hook], "time order, full envelopes");
}

#[tokio::test]
#[ignore = "needs FOILED_TEST_PG_URL; CI runs it with --include-ignored"]
async fn one_source_cannot_pre_claim_another_sources_event_id() {
    let c = connect().await;
    let tenant = format!("cap-src-{}", std::process::id());
    let http = fixture("http-upload.json");
    let from = |kind, id: &str| {
        let mut e = http.clone();
        e.stamp(
            Source {
                kind,
                id: id.into(),
            },
            &tenant,
        );
        e
    };
    // A rogue sensor sends first with the same event_id.
    let n = insert_events(&c, &[from(SourceKind::Sensor, "sensor-rogue")], 1)
        .await
        .unwrap();
    assert_eq!(n, 1);
    let n = insert_events(&c, &[from(SourceKind::Host, "host-1")], 2)
        .await
        .unwrap();
    assert_eq!(n, 1, "the real event is still stored");
    let n = insert_events(&c, &[from(SourceKind::Host, "host-1")], 3)
        .await
        .unwrap();
    assert_eq!(n, 0, "a replay from the same source is still a no-op");
}

#[tokio::test]
#[ignore = "needs FOILED_TEST_PG_URL; CI runs it with --include-ignored"]
async fn unstamped_events_are_refused_and_rows_are_append_only() {
    let c = connect().await;
    let raw = fixture("emulator-redis.json");
    assert!(matches!(
        insert_events(&c, std::slice::from_ref(&raw), 1).await,
        Err(InsertError::Unstamped(_))
    ));
    let tenant = format!("cap-upd-{}", std::process::id());
    insert_events(&c, &[stamped(raw.clone(), &tenant)], 1)
        .await
        .unwrap();
    let err = c
        .execute(
            "UPDATE capture_events SET severity = 'info' WHERE tenant_id = $1",
            &[&tenant],
        )
        .await
        .unwrap_err();
    assert!(format!("{err:?}").contains("append-only"));
}

#[tokio::test]
#[ignore = "needs FOILED_TEST_PG_URL; CI runs it with --include-ignored"]
async fn ip_iocs_aggregate_per_source_and_respect_since() {
    let c = connect().await;
    let tenant = format!("ioc-{}", std::process::id());
    let events = [
        stamped(fixture("http-upload.json"), &tenant),
        stamped(fixture("hook-trigger.json"), &tenant),
        stamped(fixture("emulator-redis.json"), &tenant),
    ];
    insert_events(&c, &events, 1).await.unwrap();
    let rows = ip_iocs(&c, &tenant, 0).await.unwrap();
    assert_eq!(rows.len(), 2);
    let attacker = rows.iter().find(|r| r.ip == "203.0.113.7").unwrap();
    assert_eq!(attacker.events, 2);
    assert_eq!(attacker.hook_cves, vec!["FOILED-DEMO-0001".to_string()]);
    assert_eq!(attacker.decoy_ids, vec!["dcy-demo-1".to_string()]);
    let later = ip_iocs(&c, &tenant, events[2].ts).await.unwrap();
    assert_eq!(later.len(), 1);
    assert_eq!(later[0].ip, "198.51.100.23");
    assert!(ip_iocs(&c, "nobody", 0).await.unwrap().is_empty());
}

#[tokio::test]
#[ignore = "needs FOILED_TEST_PG_URL; CI runs it with --include-ignored"]
async fn events_between_is_half_open_and_tenant_scoped() {
    let c = connect().await;
    let tenant = format!("win-{}", std::process::id());
    let http = stamped(fixture("http-upload.json"), &tenant);
    let hook = stamped(fixture("hook-trigger.json"), &tenant);
    insert_events(&c, &[http.clone(), hook.clone()], 1)
        .await
        .unwrap();
    let all = events_between(&c, &tenant, 0, i64::MAX, 10).await.unwrap();
    assert_eq!(all, vec![http.clone(), hook.clone()]);
    let first = events_between(&c, &tenant, 0, hook.ts, 10).await.unwrap();
    assert_eq!(first, vec![http]);
    assert!(
        events_between(&c, "other", 0, i64::MAX, 10)
            .await
            .unwrap()
            .is_empty()
    );
}
