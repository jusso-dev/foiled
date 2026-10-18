//! Actor link decision storage (#29) against a real Postgres (CI service
//! container).

use foiled_pg::{ActorDecisionRow, actor_decisions, migrate, put_actor_decision};
use tokio_postgres::NoTls;

#[tokio::test]
#[ignore = "needs FOILED_TEST_PG_URL; CI runs it with --include-ignored"]
async fn latest_decision_per_link_wins_and_is_tenant_scoped() {
    let url = std::env::var("FOILED_TEST_PG_URL").expect("FOILED_TEST_PG_URL");
    let (c, conn) = tokio_postgres::connect(&url, NoTls).await.unwrap();
    tokio::spawn(conn);
    migrate(&c).await.unwrap();
    let tenant = format!("act-{}", std::process::id());
    let mut row = ActorDecisionRow {
        subject_id: "cmp_0123456789abcdef01234567".into(),
        actor_id: "report:example-cluster-01".into(),
        feedback: "true_positive".into(),
        analyst_id: "a1".into(),
        at: 1,
        note: "same callback host".into(),
    };
    put_actor_decision(&c, &tenant, &row).await.unwrap();
    row.feedback = "false_positive".into();
    row.at = 2;
    put_actor_decision(&c, &tenant, &row).await.unwrap();
    let ids = vec![row.subject_id.clone(), "att_other".to_string()];
    let got = actor_decisions(&c, &tenant, &ids).await.unwrap();
    assert_eq!(got, vec![row.clone()]);
    assert!(actor_decisions(&c, "other", &ids).await.unwrap().is_empty());
    row.feedback = "maybe".into();
    assert!(
        put_actor_decision(&c, &tenant, &row).await.is_err(),
        "feedback is constrained"
    );
    row.feedback = "unsure".into();
    row.actor_id = "../etc".into();
    assert!(
        put_actor_decision(&c, &tenant, &row).await.is_err(),
        "actor ids are constrained"
    );
}
