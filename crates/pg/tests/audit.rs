//! Runs against a real Postgres. CI starts one as a service container and
//! sets `FOILED_TEST_PG_URL`; run locally with
//! `FOILED_TEST_PG_URL=postgres://... cargo test -p foiled-pg -- --include-ignored`.

use foiled_core::audit::{AuditRecord, Outcome};
use foiled_core::auth::Role;
use foiled_pg::{AuditFilter, append_audit, list_audit, migrate};
use tokio_postgres::{Client, NoTls};

async fn connect() -> Client {
    let url = std::env::var("FOILED_TEST_PG_URL")
        .expect("FOILED_TEST_PG_URL must point at a disposable Postgres database");
    let (client, conn) = tokio_postgres::connect(&url, NoTls).await.expect("connect");
    tokio::spawn(conn);
    migrate(&client).await.expect("migrate");
    client
}

fn record(id: &str, tenant: &str, ts: i64, action: &str, target: &str) -> AuditRecord {
    AuditRecord {
        id: id.into(),
        ts,
        tenant_id: tenant.into(),
        actor_id: "tok1".into(),
        actor_kind: Role::Human,
        action: action.into(),
        target: Some(target.into()),
        reason_code: Some("operator_manual".into()),
        reason_text: Some("test".into()),
        job_id: None,
        idempotency_key: None,
        outcome: Outcome::Accepted,
        detail: serde_json::json!({"n": ts}),
    }
}

#[tokio::test]
#[ignore = "needs FOILED_TEST_PG_URL; CI runs it with --include-ignored"]
async fn concurrent_migrations_do_not_race() {
    let url = std::env::var("FOILED_TEST_PG_URL").expect("FOILED_TEST_PG_URL");
    let mut handles = Vec::new();
    for _ in 0..4 {
        let url = url.clone();
        handles.push(tokio::spawn(async move {
            let (client, conn) = tokio_postgres::connect(&url, NoTls).await.expect("connect");
            tokio::spawn(conn);
            migrate(&client).await.expect("concurrent migrate")
        }));
    }
    for h in handles {
        h.await.unwrap();
    }
}

#[tokio::test]
#[ignore = "needs FOILED_TEST_PG_URL; CI runs it with --include-ignored"]
async fn migrations_are_idempotent() {
    let c = connect().await;
    assert!(migrate(&c).await.unwrap().is_empty());
}

#[tokio::test]
#[ignore = "needs FOILED_TEST_PG_URL; CI runs it with --include-ignored"]
async fn audit_round_trip_filters_and_keyset_pages() {
    let c = connect().await;
    let tenant = format!("t-{}", std::process::id());
    let other = format!("{tenant}-other");
    for (i, ts) in [100, 200, 200, 300].iter().enumerate() {
        let action = if i == 3 {
            "decoy.destroy"
        } else {
            "decoy.create"
        };
        append_audit(
            &c,
            &record(&format!("{tenant}-{i}"), &tenant, *ts, action, "d1"),
        )
        .await
        .unwrap();
    }
    append_audit(
        &c,
        &record(&format!("{other}-x"), &other, 400, "decoy.create", "d1"),
    )
    .await
    .unwrap();

    let all = list_audit(
        &c,
        &tenant,
        &AuditFilter {
            limit: 10,
            ..Default::default()
        },
    )
    .await
    .unwrap();
    assert_eq!(all.len(), 4, "tenant isolation");
    assert_eq!(all[0].ts, 300);
    assert_eq!(all[0].detail, serde_json::json!({"n": 300}));

    // Two rows share ts=200; keyset paging must not drop either.
    let page1 = list_audit(
        &c,
        &tenant,
        &AuditFilter {
            limit: 2,
            ..Default::default()
        },
    )
    .await
    .unwrap();
    let last = page1.last().unwrap();
    let page2 = list_audit(
        &c,
        &tenant,
        &AuditFilter {
            limit: 10,
            before: Some((last.ts, last.id.clone())),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    let mut ids: Vec<String> = page1
        .iter()
        .chain(page2.iter())
        .map(|r| r.id.clone())
        .collect();
    ids.sort();
    ids.dedup();
    assert_eq!(ids.len(), 4);

    let destroys = list_audit(
        &c,
        &tenant,
        &AuditFilter {
            action: Some("decoy.destroy".into()),
            limit: 10,
            ..Default::default()
        },
    )
    .await
    .unwrap();
    assert_eq!(destroys.len(), 1);
}

#[tokio::test]
#[ignore = "needs FOILED_TEST_PG_URL; CI runs it with --include-ignored"]
async fn audit_rows_cannot_be_updated() {
    let c = connect().await;
    let id = format!("upd-{}", std::process::id());
    append_audit(&c, &record(&id, "t-upd", 1, "decoy.create", "d1"))
        .await
        .unwrap();
    let err = c
        .execute("UPDATE audit_log SET action = 'x' WHERE id = $1", &[&id])
        .await
        .unwrap_err();
    assert!(err.to_string().contains("append-only") || format!("{err:?}").contains("append-only"));
}
