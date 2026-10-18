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
    // A stale writer cannot clear merged_into, point it at itself, make the
    // campaign younger, or move a member to a newer campaign.
    let newer = StoredCampaign {
        campaign_id: "cmp_bbbbbbbbbbbbbbbbbbbbbbbb".into(),
        merged_into: Some("cmp_0123456789abcdef01234567".into()),
        ..rec(10, 20, 500)
    };
    update_campaign_registry(
        &c,
        &tenant,
        &RegistryUpdate {
            campaigns: vec![newer.clone()],
            members: vec![],
        },
        300,
    )
    .await
    .unwrap();
    let stale = RegistryUpdate {
        campaigns: vec![
            StoredCampaign {
                merged_into: None,
                ..newer.clone()
            },
            rec(10, 20, 999),
        ],
        members: vec![MemberRecord {
            campaign_id: newer.campaign_id.clone(),
            ..member("att_a")
        }],
    };
    update_campaign_registry(&c, &tenant, &stale, 400)
        .await
        .unwrap();
    let got = campaign_records(&c, &tenant, std::slice::from_ref(&newer.campaign_id))
        .await
        .unwrap();
    assert_eq!(got[0].merged_into, newer.merged_into);
    let old = campaign_records(&c, &tenant, &["cmp_0123456789abcdef01234567".into()])
        .await
        .unwrap();
    assert_eq!(old[0].created_at, 100);
    let selfish = RegistryUpdate {
        campaigns: vec![StoredCampaign {
            merged_into: Some("cmp_0123456789abcdef01234567".into()),
            ..rec(10, 20, 100)
        }],
        members: vec![],
    };
    update_campaign_registry(&c, &tenant, &selfish, 500)
        .await
        .unwrap();
    let old = campaign_records(&c, &tenant, &["cmp_0123456789abcdef01234567".into()])
        .await
        .unwrap();
    assert_eq!(old[0].merged_into, None, "never merged into itself");

    let m = campaign_memberships(&c, &tenant, &["att_a".into(), "att_x".into()])
        .await
        .unwrap();
    assert_eq!(
        m,
        vec![(
            "att_a".to_string(),
            "cmp_0123456789abcdef01234567".to_string()
        )],
        "members only move to older campaigns"
    );
    assert!(
        campaign_memberships(&c, "other", &["att_a".into()])
            .await
            .unwrap()
            .is_empty()
    );
}

#[tokio::test]
#[ignore = "needs FOILED_TEST_PG_URL; CI runs it with --include-ignored"]
async fn a_first_read_writes_thousands_of_rows_in_two_statements() {
    let c = connect().await;
    let tenant = format!("bulk-{}", std::process::id());
    let campaigns: Vec<StoredCampaign> = (0..300)
        .map(|i| StoredCampaign {
            campaign_id: format!("cmp_{i:024x}"),
            created_at: 1,
            first_seen: 10,
            last_seen: 20,
            merged_into: None,
            attempts: 0,
        })
        .collect();
    let members: Vec<MemberRecord> = (0..6000)
        .map(|i| MemberRecord {
            attempt_id: format!("att_{i:024x}"),
            campaign_id: format!("cmp_{:024x}", i % 300),
            attempt_first_seen: 10,
        })
        .collect();
    let up = RegistryUpdate { campaigns, members };
    update_campaign_registry(&c, &tenant, &up, 1).await.unwrap();
    // Replaying the same update is a no-op.
    update_campaign_registry(&c, &tenant, &up, 2).await.unwrap();
    let got = campaign_records(&c, &tenant, &["cmp_000000000000000000000007".into()])
        .await
        .unwrap();
    assert_eq!(got[0].attempts, 20);
}
