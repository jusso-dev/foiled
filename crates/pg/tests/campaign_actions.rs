//! Campaign action and registry storage against a real Postgres (CI
//! service container).

use foiled_core::campaign::{
    ActionKind, BridgeRecord, CampaignAction, Feature, MemberRecord, RegistryUpdate, StoredCampaign,
};
use foiled_core::confidence::Feedback;
use foiled_pg::{
    append_campaign_action, campaign_actions, campaign_bridges, campaign_memberships,
    campaign_records, migrate, update_campaign_registry,
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
        bridges: vec![],
    };
    update_campaign_registry(&c, &tenant, &up, 100)
        .await
        .unwrap();
    let up = RegistryUpdate {
        campaigns: vec![rec(15, 40, 999)],
        members: vec![member("att_c")],
        bridges: vec![],
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
            bridges: vec![],
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
        bridges: vec![],
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
        bridges: vec![],
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
async fn a_first_read_writes_thousands_of_rows_in_batched_statements() {
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
    let up = RegistryUpdate {
        campaigns,
        members,
        bridges: vec![],
    };
    update_campaign_registry(&c, &tenant, &up, 1).await.unwrap();
    // Replaying the same update is a no-op.
    update_campaign_registry(&c, &tenant, &up, 2).await.unwrap();
    let got = campaign_records(&c, &tenant, &["cmp_000000000000000000000007".into()])
        .await
        .unwrap();
    assert_eq!(got[0].attempts, 20);
}

#[tokio::test]
#[ignore = "needs FOILED_TEST_PG_URL; CI runs it with --include-ignored"]
async fn racing_writers_never_leave_a_merge_cycle() {
    let url = std::env::var("FOILED_TEST_PG_URL").expect("FOILED_TEST_PG_URL");
    let c0 = connect().await;
    let rec = |id: &str, created: i64, merged: Option<&str>| StoredCampaign {
        campaign_id: id.into(),
        created_at: created,
        first_seen: 10,
        last_seen: 20,
        merged_into: merged.map(str::to_string),
        attempts: 0,
    };
    // Two first writers that disagree on which campaign is older, each
    // folding the other into the one it thinks is older.
    let w1 = RegistryUpdate {
        campaigns: vec![rec("cmp_x", 5, None), rec("cmp_y", 6, Some("cmp_x"))],
        ..Default::default()
    };
    let w2 = RegistryUpdate {
        campaigns: vec![rec("cmp_y", 3, None), rec("cmp_x", 4, Some("cmp_y"))],
        ..Default::default()
    };
    let base = format!("race-{}", std::process::id());
    for round in 0..20 {
        let tenant = format!("{base}-{round}");
        let mut handles = Vec::new();
        for up in [w1.clone(), w2.clone()] {
            let (url, tenant) = (url.clone(), tenant.clone());
            handles.push(tokio::spawn(async move {
                let (c, conn) = tokio_postgres::connect(&url, NoTls).await.unwrap();
                tokio::spawn(conn);
                // The per-tenant advisory lock serialises writers, so
                // neither is aborted (no deadlock, no trigger error).
                update_campaign_registry(&c, &tenant, &up, 1).await.unwrap();
            }));
        }
        for h in handles {
            h.await.unwrap();
        }
        let got = campaign_records(&c0, &tenant, &["cmp_x".into(), "cmp_y".into()])
            .await
            .unwrap();
        assert_eq!(got.len(), 2);
        let (x, y) = (&got[0], &got[1]);
        assert!(
            x.merged_into.is_none() || y.merged_into.is_none(),
            "round {round}: cycle {x:?} {y:?}"
        );
        for (from, to) in [(x, y), (y, x)] {
            if from.merged_into.as_deref() == Some(to.campaign_id.as_str()) {
                assert!(
                    (to.created_at, &to.campaign_id) < (from.created_at, &from.campaign_id),
                    "merges only point strictly older"
                );
            }
        }
    }
}

#[tokio::test]
#[ignore = "needs FOILED_TEST_PG_URL; CI runs it with --include-ignored"]
async fn triggers_hold_the_order_and_bridges_follow_applied_merges() {
    let c = connect().await;
    let tenant = format!("trg-{}", std::process::id());
    let rec = |id: &str, created: i64| StoredCampaign {
        campaign_id: id.into(),
        created_at: created,
        first_seen: 10,
        last_seen: 20,
        merged_into: None,
        attempts: 0,
    };
    let bridge = |into: &str, from: &str| BridgeRecord {
        campaign_id: into.into(),
        merged_campaign_id: Some(from.into()),
        attempt_id: "att_f".into(),
        with_attempt_id: "att_b".into(),
        signal_id: "campaign:payload_sha256:0123456789ab".into(),
        feature: Feature::PayloadSha256,
        attempt_side: 3,
        with_side: 3,
        small_halves: false,
        recorded_at: 7,
    };
    let up = RegistryUpdate {
        campaigns: vec![
            rec("cmp_old", 1),
            StoredCampaign {
                merged_into: Some("cmp_old".into()),
                ..rec("cmp_new", 2)
            },
            // Pointing at a newer campaign is dropped, and so is its bridge.
            StoredCampaign {
                merged_into: Some("cmp_new".into()),
                ..rec("cmp_older", 0)
            },
        ],
        members: vec![],
        bridges: vec![bridge("cmp_old", "cmp_new"), bridge("cmp_new", "cmp_older")],
    };
    update_campaign_registry(&c, &tenant, &up, 1).await.unwrap();
    assert_eq!(
        campaign_bridges(&c, &tenant, "cmp_old").await.unwrap(),
        vec![bridge("cmp_old", "cmp_new")]
    );
    assert!(
        campaign_bridges(&c, &tenant, "cmp_new")
            .await
            .unwrap()
            .is_empty()
    );
    let older = campaign_records(&c, &tenant, &["cmp_older".into()])
        .await
        .unwrap();
    assert_eq!(older[0].merged_into, None);
    for bad in [
        "UPDATE campaigns SET created_at = 99 WHERE tenant_id = $1 AND campaign_id = 'cmp_old'",
        "UPDATE campaigns SET merged_into = NULL WHERE tenant_id = $1 AND campaign_id = 'cmp_new'",
        "UPDATE campaigns SET merged_into = 'cmp_new' WHERE tenant_id = $1 AND campaign_id = 'cmp_older'",
    ] {
        assert!(c.execute(bad, &[&tenant]).await.is_err(), "{bad}");
    }
}

#[tokio::test]
#[ignore = "needs FOILED_TEST_PG_URL; CI runs it with --include-ignored"]
async fn first_merges_record_provenance_once_both_attempts_are_members() {
    let c = connect().await;
    let tenant = format!("prov-{}", std::process::id());
    let bridge = |a: &str, w: &str| BridgeRecord {
        campaign_id: "cmp_c".into(),
        merged_campaign_id: None,
        attempt_id: a.into(),
        with_attempt_id: w.into(),
        signal_id: "campaign:payload_sha256:0123456789ab".into(),
        feature: Feature::PayloadSha256,
        attempt_side: 2,
        with_side: 2,
        small_halves: true,
        recorded_at: 7,
    };
    let member = |a: &str| MemberRecord {
        attempt_id: a.into(),
        campaign_id: "cmp_c".into(),
        attempt_first_seen: 10,
    };
    let up = RegistryUpdate {
        campaigns: vec![StoredCampaign {
            campaign_id: "cmp_c".into(),
            created_at: 1,
            first_seen: 10,
            last_seen: 20,
            merged_into: None,
            attempts: 0,
        }],
        members: vec![member("att_f"), member("att_b")],
        // The second names an attempt that is not a member: not written.
        bridges: vec![bridge("att_f", "att_b"), bridge("att_f", "att_x")],
    };
    update_campaign_registry(&c, &tenant, &up, 1).await.unwrap();
    update_campaign_registry(&c, &tenant, &up, 2).await.unwrap();
    assert_eq!(
        campaign_bridges(&c, &tenant, "cmp_c").await.unwrap(),
        vec![bridge("att_f", "att_b")]
    );
}
