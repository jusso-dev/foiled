//! The materialised STIX object log behind TAXII (#13) and the
//! materialiser's state against a real Postgres (CI service container).

use foiled_pg::{
    DayRow, VersionMatch, VersionRow, event_signature, migrate, put_stix_cron_cursor, put_stix_day,
    stix_append, stix_contributions, stix_cron_cursor, stix_day_attempts, stix_day_inputs,
    stix_days, stix_history, stix_lease, stix_pending, stix_pending_move, stix_promote_day,
    stix_published, stix_purge, stix_query, stix_release, stix_set_published, stix_stage_part,
};
use tokio_postgres::{Client, NoTls};

async fn connect() -> Client {
    let url = std::env::var("FOILED_TEST_PG_URL")
        .expect("FOILED_TEST_PG_URL must point at a disposable Postgres database");
    let (client, conn) = tokio_postgres::connect(&url, NoTls).await.expect("connect");
    tokio::spawn(conn);
    migrate(&client).await.expect("migrate");
    client
}

/// Take the tenant's lease as a test writer; returns its generation.
async fn lease(c: &Client, tenant: &str) -> i64 {
    stix_lease(c, tenant, "published", "test", 60_000)
        .await
        .unwrap()
        .expect("lease")
}

fn row(id: &str, version: &str, content: &str) -> VersionRow {
    VersionRow {
        id: format!("indicator--{id}"),
        version: version.into(),
        created: Some("2026-10-18T01:00:00.000Z".into()),
        object_type: "indicator".into(),
        content: format!("{{\"c\":\"{content}\"}}"),
        content_sha256: format!("sha-{content}"),
        refs: vec![],
    }
}

fn all() -> VersionMatch {
    VersionMatch {
        all: true,
        ..Default::default()
    }
}

const A: &str = "2ed6657d-e927-568b-95e1-2665a8aea6a2";
const B: &str = "3ed6657d-e927-568b-95e1-2665a8aea6a2";

#[tokio::test]
#[ignore = "needs FOILED_TEST_PG_URL; CI runs it with --include-ignored"]
async fn log_appends_are_immutable_ordered_and_paged() {
    let c = connect().await;
    let tenant = format!("stix-{}", std::process::id());
    let coll = "published";
    let g = lease(&c, &tenant).await;

    let first = vec![
        row(A, "2026-10-18T01:00:00.000Z", "a1"),
        row(B, "2026-10-18T01:00:00.000Z", "b1"),
    ];
    let ev = vec![
        (format!("indicator--{A}"), 100),
        (format!("indicator--{B}"), 100),
    ];
    assert_eq!(
        stix_append(&c, &tenant, coll, &first, &ev, 1_000, g)
            .await
            .unwrap(),
        2
    );
    // The same content again writes nothing.
    assert_eq!(
        stix_append(&c, &tenant, coll, &first, &[], 1_000, g)
            .await
            .unwrap(),
        0
    );
    // The same (id, version) with other content is a conflict: the append
    // fails and writes nothing, not even its other rows.
    let clash = vec![
        row(B, "2026-10-18T05:00:00.000Z", "b-new"),
        row(A, "2026-10-18T01:00:00.000Z", "a-other"),
    ];
    let err = stix_append(&c, &tenant, coll, &clash, &[], 1_000, g)
        .await
        .unwrap_err();
    assert_eq!(
        err.code(),
        Some(&tokio_postgres::error::SqlState::UNIQUE_VIOLATION),
        "{err}"
    );
    // A new version, appended with an earlier clock: date_added still moves on.
    let second = vec![row(A, "2026-10-18T02:00:00.000Z", "a2")];
    assert_eq!(
        stix_append(&c, &tenant, coll, &second, &[], 500, g)
            .await
            .unwrap(),
        1
    );

    let hist = stix_history(&c, &tenant, coll, &[format!("indicator--{A}")])
        .await
        .unwrap();
    assert_eq!(hist.len(), 1);
    assert_eq!(hist[0].2, "2026-10-18T02:00:00.000Z");
    assert_eq!(hist[0].3, "sha-a2", "head hash");
    assert!(!hist[0].4, "not revoked");

    let q = |m: VersionMatch| {
        let c = &c;
        let tenant = tenant.clone();
        async move {
            stix_query(c, &tenant, coll, None, None, None, None, &m, 10)
                .await
                .unwrap()
        }
    };
    let every = q(all()).await;
    assert_eq!(every.len(), 3, "the conflicting append left nothing");
    assert_eq!(every[0].date_added, 1_000);
    assert_eq!(every[2].date_added, 1_001, "after every row before it");
    let last = q(VersionMatch {
        last: true,
        ..Default::default()
    })
    .await;
    assert_eq!(last.len(), 2);
    assert!(last.iter().any(|r| r.content.contains("a2")));
    let firsts = q(VersionMatch {
        first: true,
        ..Default::default()
    })
    .await;
    assert!(firsts.iter().any(|r| r.content.contains("a1")));
    let exact = q(VersionMatch {
        exact: vec!["2026-10-18T02:00:00.000Z".to_string()],
        ..Default::default()
    })
    .await;
    assert_eq!(exact.len(), 1);
    // Any of first or an exact version.
    let any = q(VersionMatch {
        first: true,
        exact: vec!["2026-10-18T02:00:00.000Z".to_string()],
        ..Default::default()
    })
    .await;
    assert_eq!(any.len(), 3);

    // Paging by cursor covers every row once.
    let p1 = stix_query(&c, &tenant, coll, None, None, None, None, &all(), 2)
        .await
        .unwrap();
    let l = &p1[1];
    let p2 = stix_query(
        &c,
        &tenant,
        coll,
        None,
        Some((l.date_added, &l.id, &l.version)),
        None,
        None,
        &all(),
        2,
    )
    .await
    .unwrap();
    assert_eq!(p1.len() + p2.len(), 3);
    let after = stix_query(&c, &tenant, coll, Some(1_000), None, None, None, &all(), 10)
        .await
        .unwrap();
    assert_eq!(after.len(), 1);
    let types = vec!["malware".to_string()];
    assert!(
        stix_query(
            &c,
            &tenant,
            coll,
            None,
            None,
            None,
            Some(&types),
            &all(),
            10
        )
        .await
        .unwrap()
        .is_empty()
    );

    // Versions are append-only in the database too.
    assert!(
        c.execute(
            "UPDATE stix_object_versions SET content = 'x' WHERE tenant_id = $1",
            &[&tenant]
        )
        .await
        .is_err()
    );

    // Retention removes whole objects by their newest evidence.
    let ev = vec![(format!("indicator--{B}"), 5_000)];
    stix_append(&c, &tenant, coll, &[], &ev, 2_000, g)
        .await
        .unwrap();
    assert_eq!(stix_purge(&c, &tenant, coll, 1_000, g).await.unwrap(), 2);
    let left = stix_query(&c, &tenant, coll, None, None, None, None, &all(), 10)
        .await
        .unwrap();
    assert_eq!(left.len(), 1);
    assert_eq!(left[0].id, format!("indicator--{B}"));
    assert_eq!(event_signature(&c, &tenant, 0, 1).await.unwrap(), "0:0");
}

/// Retention keeps an expired object while one that stays refers to it.
#[tokio::test]
#[ignore = "needs FOILED_TEST_PG_URL; CI runs it with --include-ignored"]
async fn retention_keeps_what_a_kept_object_refers_to() {
    let c = connect().await;
    let tenant = format!("stix-refs-{}", std::process::id());
    let coll = "published";
    let g = lease(&c, &tenant).await;
    let target = row(A, "2026-10-18T01:00:00.000Z", "t");
    let referrer = VersionRow {
        refs: vec![format!("indicator--{A}")],
        ..row(B, "2026-10-18T01:00:00.000Z", "r")
    };
    let ev = vec![
        (format!("indicator--{A}"), 100),
        (format!("indicator--{B}"), 9_000),
    ];
    stix_append(&c, &tenant, coll, &[target, referrer], &ev, 1, g)
        .await
        .unwrap();
    assert_eq!(stix_purge(&c, &tenant, coll, 1_000, g).await.unwrap(), 0);
    assert_eq!(stix_purge(&c, &tenant, coll, 10_000, g).await.unwrap(), 2);
}

#[tokio::test]
#[ignore = "needs FOILED_TEST_PG_URL; CI runs it with --include-ignored"]
async fn earlier_content_returns_as_a_new_head_and_revocation_shows() {
    let c = connect().await;
    let tenant = format!("stix-head-{}", std::process::id());
    let coll = "published";
    let g = lease(&c, &tenant).await;
    let id = format!("indicator--{A}");
    let v = |version: &str, content: &str| VersionRow {
        id: id.clone(),
        version: version.into(),
        created: Some("2026-10-18T01:00:00.000Z".into()),
        object_type: "indicator".into(),
        content: content.into(),
        content_sha256: format!("sha-{content}"),
        refs: vec![],
    };
    for (version, content) in [
        ("2026-10-18T01:00:00.000Z", "{\"x\":1}"),
        ("2026-10-18T02:00:00.000Z", "{\"x\":2}"),
        // Back to the first content: a new head, not skipped.
        ("2026-10-18T03:00:00.000Z", "{\"x\":1}"),
    ] {
        let n = stix_append(&c, &tenant, coll, &[v(version, content)], &[], 1, g)
            .await
            .unwrap();
        assert_eq!(n, 1, "{version}");
    }
    // Same as the head: skipped.
    let same = v("2026-10-18T04:00:00.000Z", "{\"x\":1}");
    assert_eq!(
        stix_append(&c, &tenant, coll, &[same], &[], 1, g)
            .await
            .unwrap(),
        0
    );
    let rev = v("2026-10-18T05:00:00.000Z", "{\"revoked\":true,\"x\":1}");
    assert_eq!(
        stix_append(&c, &tenant, coll, &[rev], &[], 1, g)
            .await
            .unwrap(),
        1
    );
    let hist = stix_history(&c, &tenant, coll, std::slice::from_ref(&id))
        .await
        .unwrap();
    assert_eq!(hist[0].2, "2026-10-18T05:00:00.000Z");
    assert!(hist[0].4, "head is revoked");
    let every = stix_query(&c, &tenant, coll, None, None, None, None, &all(), 10)
        .await
        .unwrap();
    assert_eq!(every.len(), 4);
    let first_last = stix_query(
        &c,
        &tenant,
        coll,
        None,
        None,
        None,
        None,
        &VersionMatch {
            first: true,
            last: true,
            ..Default::default()
        },
        10,
    )
    .await
    .unwrap();
    let versions: Vec<&str> = first_last.iter().map(|r| r.version.as_str()).collect();
    assert_eq!(
        versions,
        ["2026-10-18T01:00:00.000Z", "2026-10-18T05:00:00.000Z"],
        "first,last is any of the two, not every version"
    );
}

/// Staging, resuming a part, promoting attempts and contributions, gate
/// decisions, the publishing queues and per-day inputs.
#[tokio::test]
#[ignore = "needs FOILED_TEST_PG_URL; CI runs it with --include-ignored"]
async fn materialiser_state_stages_promotes_and_publishes_days() {
    let c = connect().await;
    let tenant = format!("stix-state-{}", std::process::id());
    let coll = "published";
    let g = lease(&c, &tenant).await;
    let day = 86_400_000;
    let building: DayRow = (day, String::new(), vec![], Some("{\"p\":1}".into()), 5);
    let attempts = vec![
        ("att_b".to_string(), "{\"v\":1}".to_string()),
        ("att_a".to_string(), "{\"v\":1}".to_string()),
    ];
    let contribs = vec![("ioc_a".to_string(), "{\"n\":1}".to_string())];
    stix_stage_part(&c, &tenant, coll, 0, &attempts, &contribs, &building, g)
        .await
        .unwrap();
    // Part 0 redone after a crash replaces itself.
    let again = vec![("att_b".to_string(), "{\"v\":2}".to_string())];
    let redo = vec![(
        "ioc_b".to_string(),
        "{\"ioc_type\":\"ip\",\"value\":\"203.0.113.9\"}".to_string(),
    )];
    stix_stage_part(&c, &tenant, coll, 0, &again, &redo, &building, g)
        .await
        .unwrap();
    assert_eq!(
        stix_days(&c, &tenant, coll).await.unwrap(),
        vec![building.clone()]
    );
    // Nothing is live before the promotion.
    let ids = vec!["ioc_a".to_string(), "ioc_b".to_string()];
    assert!(
        stix_contributions(&c, &tenant, coll, &ids)
            .await
            .unwrap()
            .is_empty()
    );
    assert!(
        stix_day_attempts(&c, &tenant, coll, day, None, 10)
            .await
            .unwrap()
            .is_empty()
    );
    let publishing: DayRow = (day, String::new(), vec![], Some("{\"p\":2}".into()), 5);
    stix_promote_day(&c, &tenant, coll, &publishing, g)
        .await
        .unwrap();
    assert_eq!(
        stix_contributions(&c, &tenant, coll, &ids)
            .await
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        stix_day_attempts(&c, &tenant, coll, day, None, 10)
            .await
            .unwrap(),
        vec![("att_b".to_string(), "{\"v\":2}".to_string())]
    );
    assert_eq!(
        stix_pending(&c, &tenant, coll, "merge", 10).await.unwrap(),
        vec!["ioc_b".to_string()]
    );
    stix_pending_move(
        &c,
        &tenant,
        coll,
        &["ioc_b".into()],
        "merge",
        Some("sighting"),
        g,
    )
    .await
    .unwrap();
    assert_eq!(
        stix_pending(&c, &tenant, coll, "sighting", 10)
            .await
            .unwrap(),
        vec!["ioc_b".to_string()]
    );

    // Gate decisions.
    let pass = vec![(
        "ioc_b".to_string(),
        "ip".to_string(),
        "203.0.113.9".to_string(),
    )];
    stix_set_published(&c, &tenant, coll, &pass, &[], g)
        .await
        .unwrap();
    assert_eq!(stix_published(&c, &tenant, coll, &ids).await.unwrap(), pass);
    stix_set_published(&c, &tenant, coll, &[], &["ioc_b".into()], g)
        .await
        .unwrap();
    assert!(
        stix_published(&c, &tenant, coll, &ids)
            .await
            .unwrap()
            .is_empty()
    );

    // Per-day inputs: the day's addresses, and a digest that moves with an
    // analyst decision on one of its attempts.
    let (before, addresses) = stix_day_inputs(&c, &tenant, coll, day).await.unwrap();
    assert_eq!(addresses, vec!["203.0.113.9".to_string()]);
    c.execute(
        "INSERT INTO link_overrides (tenant_id, attempt_id, kind, target, feedback, analyst_id, at)
         VALUES ($1, 'att_b', 'attempt_cve', 'CVE-2099-0001', 'false_positive', 'a', 7)",
        &[&tenant],
    )
    .await
    .unwrap();
    let (after, _) = stix_day_inputs(&c, &tenant, coll, day).await.unwrap();
    assert_ne!(before, after);
    let (other, _) = stix_day_inputs(&c, &tenant, coll, day + 86_400_000)
        .await
        .unwrap();
    assert_ne!(other, after, "another day's inputs do not move");

    let done: DayRow = (day, "4:9".into(), vec!["x--1".into()], None, 5);
    put_stix_day(&c, &tenant, coll, &done, g).await.unwrap();
    assert_eq!(stix_days(&c, &tenant, coll).await.unwrap(), vec![done]);
    // Retention drops the day's state with the day.
    stix_purge(&c, &tenant, coll, day + 1, g).await.unwrap();
    assert!(stix_days(&c, &tenant, coll).await.unwrap().is_empty());
    assert!(
        stix_day_attempts(&c, &tenant, coll, day, None, 10)
            .await
            .unwrap()
            .is_empty()
    );

    put_stix_cron_cursor(&c, &tenant, "t-b").await.unwrap();
    put_stix_cron_cursor(&c, &tenant, "t-c").await.unwrap();
    assert_eq!(
        stix_cron_cursor(&c, &tenant).await.unwrap().as_deref(),
        Some("t-c")
    );
}

/// Concurrent runs for one tenant: exactly one gets the lease. A holder
/// that stalls past its lease (judged by the database clock) loses it to
/// the next run, and every write it then attempts is refused.
#[tokio::test]
#[ignore = "needs FOILED_TEST_PG_URL; CI runs it with --include-ignored"]
async fn one_materialiser_run_per_tenant_and_stalled_holders_are_fenced() {
    let tenant = format!("stix-lease-{}", std::process::id());
    let coll = "published";
    let mut tasks = Vec::new();
    for n in 0..8 {
        let tenant = tenant.clone();
        tasks.push(tokio::spawn(async move {
            let c = connect().await;
            stix_lease(&c, &tenant, coll, &format!("run-{n}"), 60_000)
                .await
                .unwrap()
        }));
    }
    let mut won = 0;
    for t in tasks {
        won += usize::from(t.await.unwrap().is_some());
    }
    assert_eq!(won, 1, "exactly one concurrent run holds the tenant");

    let c = connect().await;
    let other = format!("{tenant}-2");
    let a = stix_lease(&c, &other, coll, "a", 50)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        stix_lease(&c, &other, coll, "a", 50).await.unwrap(),
        Some(a),
        "a renewal keeps the generation"
    );
    assert_eq!(stix_lease(&c, &other, coll, "b", 50).await.unwrap(), None);
    let day: DayRow = (1, "a".into(), vec![], None, 0);
    put_stix_day(&c, &other, coll, &day, a).await.unwrap();
    // `a` stalls past its lease; `b` takes over with a higher generation.
    tokio::time::sleep(std::time::Duration::from_millis(120)).await;
    let b = stix_lease(&c, &other, coll, "b", 60_000)
        .await
        .unwrap()
        .unwrap();
    assert!(b > a);
    assert_eq!(
        stix_lease(&c, &other, coll, "a", 60_000).await.unwrap(),
        None
    );
    let err = put_stix_day(&c, &other, coll, &(1, "stale".into(), vec![], None, 0), a)
        .await
        .unwrap_err();
    assert!(
        err.to_string().contains("stix lease lost")
            || format!("{err:?}").contains("stix lease lost"),
        "{err:?}"
    );
    assert!(stix_append(&c, &other, coll, &[], &[], 1, a).await.is_err());
    assert!(stix_purge(&c, &other, coll, 0, a).await.is_err());
    put_stix_day(&c, &other, coll, &(1, "b".into(), vec![], None, 0), b)
        .await
        .unwrap();
    assert_eq!(stix_days(&c, &other, coll).await.unwrap()[0].1, "b");
    // Releasing keeps the generation: the next holder's is higher still.
    stix_release(&c, &other, coll, "b").await.unwrap();
    let next = stix_lease(&c, &other, coll, "a", 60_000)
        .await
        .unwrap()
        .unwrap();
    assert!(next > b);
}
