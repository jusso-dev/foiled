//! Campaign action and registry storage against a real Postgres (CI
//! service container).

use foiled_core::campaign::{
    ActionKind, CampaignAction, MemberRecord, RegistryUpdate, StoredCampaign,
};
use foiled_core::confidence::Feedback;
use foiled_pg::{
    append_campaign_action, campaign_actions, campaign_memberships, campaign_records, migrate,
    update_campaign_registry,
};
use tokio_postgres::{Client, NoTls};

async fn connect() -> Client {
    let url = std::env::var("FOILED_TEST_PG_URL").expect("FOILED_TEST_PG_URL");
    let (c, conn) = tokio_postgres::connect(&url, NoTls).await.unwrap();
    tokio::spawn(conn);
    migrate(&c).await.unwrap();
    c
}

fn action(id: &str, kind: ActionKind, at: i64) -> CampaignAction {
    CampaignAction {
        action_id: id.into(),
        kind,
        campaign_id: "cmp_0123456789abcdef01234567".into(),
        anchor_attempt_ids: vec!["att_0123456789abcdef01234567".into()],
        title: (kind == ActionKind::Label).then(|| "Upload wave".into()),
        status: None,
        merge: vec![],
        attempt_ids: vec![],
        feedback: (kind == ActionKind::Feedback).then_some(Feedback::Unsure),
        note: "reviewed".into(),
        analyst_id: "a1".into(),
        at,
    }
}

#[tokio::test]
#[ignore = "needs FOILED_TEST_PG_URL; CI runs it with --include-ignored"]
async fn structural_actions_always_load_and_feedback_is_capped() {
    let c = connect().await;
    let tenant = format!("cmp-{}", std::process::id());
    let rows = [
        action("act-1", ActionKind::Label, 1),
        action("act-2", ActionKind::Feedback, 2),
        action("act-3", ActionKind::Feedback, 3),
        action("act-4", ActionKind::Feedback, 4),
    ];
    for a in &rows {
        append_campaign_action(&c, &tenant, a).await.unwrap();
    }
    let got = campaign_actions(&c, &tenant, 2).await.unwrap();
    assert_eq!(got, vec![rows[0].clone(), rows[2].clone(), rows[3].clone()]);
    assert!(campaign_actions(&c, "other", 10).await.unwrap().is_empty());
    assert!(
        append_campaign_action(&c, &tenant, &rows[0]).await.is_err(),
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

#[tokio::test]
#[ignore = "needs FOILED_TEST_PG_URL; CI runs it with --include-ignored"]
async fn registry_keeps_created_at_widens_times_and_counts_members() {
    let c = connect().await;
    let tenant = format!("reg-{}", std::process::id());
    let rec = |first, last, created| StoredCampaign {
        campaign_id: "cmp_0123456789abcdef01234567".into(),
        created_at: created,
        first_seen: first,
        last_seen: last,
        merged_into: None,
        attempts: 0,
    };
    let member = |a: &str| MemberRecord {
        attempt_id: a.into(),
        campaign_id: "cmp_0123456789abcdef01234567".into(),
        attempt_first_seen: 10,
    };
    let up = RegistryUpdate {
        campaigns: vec![rec(10, 20, 100)],
        members: vec![member("att_a"), member("att_b")],
    };
    update_campaign_registry(&c, &tenant, &up, 100)
        .await
        .unwrap();
    let up = RegistryUpdate {
        campaigns: vec![rec(15, 40, 999)],
        members: vec![member("att_c")],
    };
    update_campaign_registry(&c, &tenant, &up, 200)
        .await
        .unwrap();
    let got = campaign_records(&c, &tenant, &["cmp_0123456789abcdef01234567".into()])
        .await
        .unwrap();
    assert_eq!(
        got,
        vec![StoredCampaign {
            attempts: 3,
            ..rec(10, 40, 100)
        }]
    );
    let m = campaign_memberships(&c, &tenant, &["att_a".into(), "att_x".into()])
        .await
        .unwrap();
    assert_eq!(m.len(), 1);
    assert!(
        campaign_memberships(&c, "other", &["att_a".into()])
            .await
            .unwrap()
            .is_empty()
    );
}
