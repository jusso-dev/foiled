//! Campaign action storage against a real Postgres (CI service container).

use foiled_core::campaign::{ActionKind, CampaignAction};
use foiled_pg::{append_campaign_action, campaign_actions, migrate};
use tokio_postgres::NoTls;

fn action(id: &str, at: i64) -> CampaignAction {
    CampaignAction {
        action_id: id.into(),
        kind: ActionKind::Label,
        campaign_id: "cmp_0123456789abcdef01234567".into(),
        anchor_attempt_id: "att_0123456789abcdef01234567".into(),
        title: Some("Upload wave".into()),
        status: None,
        merge: vec![],
        attempt_ids: vec![],
        feedback: None,
        note: "reviewed".into(),
        analyst_id: "a1".into(),
        at,
    }
}

#[tokio::test]
#[ignore = "needs FOILED_TEST_PG_URL; CI runs it with --include-ignored"]
async fn actions_append_read_back_oldest_first_and_are_tenant_scoped() {
    let url = std::env::var("FOILED_TEST_PG_URL").expect("FOILED_TEST_PG_URL");
    let (c, conn) = tokio_postgres::connect(&url, NoTls).await.unwrap();
    tokio::spawn(conn);
    migrate(&c).await.unwrap();
    let tenant = format!("cmp-{}", std::process::id());
    for (id, at) in [("act-2", 2), ("act-1", 1), ("act-3", 3)] {
        append_campaign_action(&c, &tenant, &action(id, at))
            .await
            .unwrap();
    }
    let got = campaign_actions(&c, &tenant, 2).await.unwrap();
    assert_eq!(got, vec![action("act-2", 2), action("act-3", 3)]);
    assert!(campaign_actions(&c, "other", 10).await.unwrap().is_empty());
    assert!(
        append_campaign_action(&c, &tenant, &action("act-1", 9))
            .await
            .is_err(),
        "action ids are unique per tenant"
    );
    assert!(
        c.execute(
            "UPDATE campaign_actions SET at = 0 WHERE tenant_id = $1",
            &[&tenant]
        )
        .await
        .is_err(),
        "rows are append-only"
    );
}
