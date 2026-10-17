//! Link override storage against a real Postgres (CI service container).

use foiled_pg::{LinkOverrideRow, link_overrides, migrate, put_link_override};
use tokio_postgres::NoTls;

#[tokio::test]
#[ignore = "needs FOILED_TEST_PG_URL; CI runs it with --include-ignored"]
async fn latest_decision_per_link_wins_and_is_tenant_scoped() {
    let url = std::env::var("FOILED_TEST_PG_URL").expect("FOILED_TEST_PG_URL");
    let (c, conn) = tokio_postgres::connect(&url, NoTls).await.unwrap();
    tokio::spawn(conn);
    migrate(&c).await.unwrap();
    let tenant = format!("ovr-{}", std::process::id());
    let mut row = LinkOverrideRow {
        attempt_id: "att_1".into(),
        kind: "attempt_cve".into(),
        target: "FOILED-DEMO-0001".into(),
        feedback: "unsure".into(),
        analyst_id: "a1".into(),
        at: 1,
        note: "first look".into(),
    };
    put_link_override(&c, &tenant, &row).await.unwrap();
    row.feedback = "true_positive".into();
    row.at = 2;
    put_link_override(&c, &tenant, &row).await.unwrap();
    let got = link_overrides(&c, &tenant, "att_1").await.unwrap();
    assert_eq!(got, vec![row.clone()]);
    assert!(
        link_overrides(&c, "other", "att_1")
            .await
            .unwrap()
            .is_empty()
    );
    row.feedback = "maybe".into();
    assert!(
        put_link_override(&c, &tenant, &row).await.is_err(),
        "feedback is constrained"
    );
}
