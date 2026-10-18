//! Review queue state, write-ups, public pages and radar rollups (#35)
//! against a real Postgres (CI service container).

use foiled_core::confidence::Band;
use foiled_core::radar::{Dimension, RadarPoint};
use foiled_core::review::{ReviewKind, ReviewState, ReviewStatus};
use foiled_core::share::{SensorKind, Tlp};
use foiled_core::writeup::{PageFacts, WriteUp, WriteUpStatus, writeup_id};
use foiled_pg::*;
use tokio_postgres::{Client, NoTls};

async fn connect() -> Client {
    let url = std::env::var("FOILED_TEST_PG_URL").expect("FOILED_TEST_PG_URL");
    let (c, conn) = tokio_postgres::connect(&url, NoTls).await.unwrap();
    tokio::spawn(conn);
    migrate(&c).await.unwrap();
    c
}

fn tenant(name: &str) -> String {
    format!("{name}-{}", std::process::id())
}

fn writeup(t: &str, seed: &str, slug: &str) -> WriteUp {
    WriteUp {
        writeup_id: writeup_id(&format!("{t}{seed}")),
        tenant_id: t.into(),
        slug: slug.into(),
        title: "Title".into(),
        summary: "We assess as FOILED-DEMO-0001.".into(),
        body_md: "Body".into(),
        status: WriteUpStatus::Draft,
        tlp: Tlp::Clear,
        embargo_until: None,
        cve_ids: vec![],
        technique_ids: vec![],
        campaign_ids: vec![],
        ioc_ids: vec![],
        attempt_ids: vec![],
        first_seen: None,
        redacted_payload: None,
        source_item_id: None,
        author_id: "a1".into(),
        reviewer_id: None,
        checklist: None,
        version: 1,
        created_at: 1,
        updated_at: 1,
        submitted_at: None,
        approved_at: None,
        published_at: None,
        withdrawn_at: None,
    }
}

#[tokio::test]
#[ignore = "needs FOILED_TEST_PG_URL; CI runs it with --include-ignored"]
async fn review_state_compare_and_set() {
    let c = connect().await;
    let t = tenant("rq");
    let item = "rq_0123456789abcdef01234567";
    let mut s = ReviewState::new(item, ReviewKind::CveLink);
    s.version = 1;
    s.status = ReviewStatus::Claimed;
    assert!(put_review_state(&c, &t, &s, 0).await.unwrap());
    assert!(
        !put_review_state(&c, &t, &s, 0).await.unwrap(),
        "row exists"
    );
    let mut next = s.clone();
    next.version = 2;
    next.status = ReviewStatus::Approved;
    assert!(!put_review_state(&c, &t, &next, 5).await.unwrap(), "stale");
    assert!(put_review_state(&c, &t, &next, 1).await.unwrap());
    let got = review_states(&c, &t, &[item.to_string()]).await.unwrap();
    assert_eq!(got, vec![next]);
    assert!(
        review_states(&c, "other", &[item.to_string()])
            .await
            .unwrap()
            .is_empty()
    );
}

#[tokio::test]
#[ignore = "needs FOILED_TEST_PG_URL; CI runs it with --include-ignored"]
async fn writeups_are_versioned_and_pages_are_slug_guarded() {
    let c = connect().await;
    let t = tenant("wu");
    let slug = format!("page-{}", std::process::id());
    let mut w = writeup(&t, "a", &slug);
    insert_writeup(&c, &w, "a1").await.unwrap();
    assert_eq!(
        get_writeup(&c, &t, &w.writeup_id).await.unwrap(),
        Some(w.clone())
    );
    assert!(
        get_writeup(&c, "other", &w.writeup_id)
            .await
            .unwrap()
            .is_none()
    );
    let old = w.version;
    w.version = 2;
    w.status = WriteUpStatus::Review;
    w.updated_at = 2;
    assert!(
        update_writeup(&c, &w, old, "transition.review", "a1")
            .await
            .unwrap()
    );
    assert!(
        !update_writeup(&c, &w, old, "edit", "a1").await.unwrap(),
        "stale"
    );
    let v = writeup_versions(&c, &t, &w.writeup_id).await.unwrap();
    assert_eq!(
        v.iter().map(|x| x.action.as_str()).collect::<Vec<_>>(),
        vec!["create", "transition.review"]
    );
    assert_eq!(
        list_writeups(&c, &t, Some("review"), 10)
            .await
            .unwrap()
            .len(),
        1
    );
    // Versions are append-only.
    assert!(
        c.execute(
            "UPDATE writeup_versions SET action = 'x' WHERE tenant_id = $1",
            &[&t]
        )
        .await
        .is_err()
    );

    let page = foiled_core::writeup::public_page(&w, &PageFacts::default(), 100);
    assert!(put_public_page(&c, &t, &w.writeup_id, &page).await.unwrap());
    let other = writeup(&t, "b", &slug);
    assert!(
        !put_public_page(&c, &t, &other.writeup_id, &page)
            .await
            .unwrap(),
        "slug taken"
    );
    // An older snapshot never replaces a newer one.
    let mut stale = page.clone();
    stale.version = 1;
    stale.title = "stale".into();
    assert!(
        put_public_page(&c, &t, &w.writeup_id, &stale)
            .await
            .unwrap()
    );
    assert_eq!(
        public_page(&c, &slug, 100).await.unwrap(),
        Some(page.clone())
    );
    assert_eq!(
        public_page(&c, &slug, 50).await.unwrap(),
        None,
        "not yet visible"
    );
    assert_eq!(
        public_page(&c, &slug, 100).await.unwrap(),
        Some(page.clone())
    );
    assert!(
        public_pages(&c, 100, 500)
            .await
            .unwrap()
            .iter()
            .any(|p| p.slug == slug)
    );
    remove_public_page(&c, &t, &w.writeup_id).await.unwrap();
    assert_eq!(public_page(&c, &slug, 100).await.unwrap(), None);
}

#[tokio::test]
#[ignore = "needs FOILED_TEST_PG_URL; CI runs it with --include-ignored"]
async fn radar_rollups_replace_a_tenant_day() {
    let c = connect().await;
    let t = tenant("radar");
    let day = 1_792_281_600_000;
    let p = |src: &str| RadarPoint {
        day,
        tenant_id: t.clone(),
        sensor: "decoy:d1".into(),
        sensor_kind: SensorKind::Research,
        shared: true,
        dimension: Dimension::Cve,
        key: "CVE-2099-0001".into(),
        product: "foiled/demo-app".into(),
        source: src.into(),
        attempts: 1,
        score: 80,
        band: Band::High,
        publishable: true,
        predisclosure: false,
    };
    put_radar_points(&c, &t, day, &[p("0000000000000001"), p("0000000000000002")])
        .await
        .unwrap();
    put_radar_points(&c, &t, day, &[p("0000000000000003")])
        .await
        .unwrap();
    let got = radar_points(&c, Some(&t), day, day + 86_400_000, 100)
        .await
        .unwrap();
    assert_eq!(got, vec![p("0000000000000003")]);
    assert!(
        radar_points(&c, Some("other"), day, day + 86_400_000, 100)
            .await
            .unwrap()
            .is_empty()
    );
}
