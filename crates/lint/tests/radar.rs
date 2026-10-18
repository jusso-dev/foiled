//! Golden test for radar aggregation (#35): `testdata/radar/scenario.input.json`
//! (rollup points from research decoys and edge sensors in several
//! tenants) is aggregated for the fleet and for two tenants. The feeds must match
//! `testdata/radar/expected/`, which the repository lint also validates
//! against `schemas/radar-feed.schema.json`.
//!
//! To regenerate after an intended change, run with FOILED_BLESS=1 and
//! review the diff.

use std::collections::BTreeMap;
use std::path::Path;

use foiled_core::radar::{Audience, Filter, RadarFeed, RadarPoint, aggregate};
use foiled_core::share::RadarPolicy;

fn root() -> &'static Path {
    Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/../../testdata/radar"))
}

fn scenario() -> (Vec<RadarPoint>, i64, i64) {
    let raw: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(root().join("scenario.input.json")).unwrap())
            .unwrap();
    (
        serde_json::from_value(raw["points"].clone()).unwrap(),
        raw["since"].as_i64().unwrap(),
        raw["until"].as_i64().unwrap(),
    )
}

fn feed(audience: Audience, tenant: Option<&str>, now: i64) -> RadarFeed {
    let (points, since, until) = scenario();
    let labels = BTreeMap::from([(
        (
            foiled_core::radar::Dimension::Product,
            "foiled/demo-app".to_string(),
        ),
        "Foiled Demo App".to_string(),
    )]);
    aggregate(
        &points,
        audience,
        tenant,
        &RadarPolicy::default(),
        since,
        until - 1,
        now,
        &Filter {
            limit: 20,
            ..Default::default()
        },
        &labels,
    )
    .unwrap()
}

fn golden(name: &str, f: &RadarFeed) {
    let path = root().join("expected").join(format!("{name}.json"));
    let got = serde_json::to_string_pretty(f).unwrap() + "\n";
    if std::env::var("FOILED_BLESS").is_ok() {
        std::fs::write(&path, &got).unwrap();
    }
    let want = std::fs::read_to_string(&path).unwrap();
    assert_eq!(
        got, want,
        "{name} differs; rerun with FOILED_BLESS=1 and review"
    );
}

fn keys(f: &RadarFeed) -> Vec<&str> {
    f.series.iter().map(|s| s.key.as_str()).collect()
}

#[test]
fn audiences_match_their_goldens() {
    let (_, _, until) = scenario();
    let fleet = feed(Audience::Fleet, None, until + 3_600_000);
    let research = feed(Audience::Tenant, Some("t-research"), until + 3_600_000);
    let tenant = feed(Audience::Tenant, Some("t-edge-d"), until + 3_600_000);
    golden("fleet", &fleet);
    golden("tenant-research", &research);
    golden("tenant-edge-d", &tenant);

    // Fleet: opted-in sensors over every threshold, nothing else.
    for hidden in [
        "CVE-2099-0007",
        "CVE-2099-0008",
        "CVE-2099-0010",
        "CVE-2099-0011",
    ] {
        assert!(!keys(&fleet).contains(&hidden), "{hidden}");
    }
    assert!(
        keys(&fleet).contains(&"T1190"),
        "three edge tenants opted in"
    );
    // The medium, unpublishable link counts but is never a headline.
    assert!(keys(&fleet).contains(&"CVE-2099-0009"));
    assert!(!fleet.cards.iter().any(|c| c.key == "CVE-2099-0009"));
    assert!(fleet.cards.iter().any(|c| c.key == "FOILED-DEMO-0001"));
    assert!(fleet.cards.iter().any(|c| c.key == "CVE-2099-0001"));
    // A tenant sees its own sensor even though it never opted in.
    assert_eq!(keys(&tenant), vec!["CVE-2099-0008"]);
    // And its own small buckets.
    assert!(keys(&research).contains(&"CVE-2099-0011"));
    // Nothing identifying in any feed.
    for f in [&fleet, &research, &tenant] {
        let text = serde_json::to_string(f).unwrap();
        for private in [
            "t-research",
            "t-edge",
            "dcy-",
            "sen-",
            "192.0.2.",
            "198.51.100.",
        ] {
            assert!(!text.contains(private), "{private}");
        }
    }
}

/// `configs/contribute-back.yaml` and `SharePolicy::default()` (what the API
/// Worker uses) must agree, radar section included.
#[test]
fn shipped_share_policy_matches_the_code_default() {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../configs/contribute-back.yaml"
    );
    let v = foiled_lint::load(Path::new(path)).unwrap();
    let parsed: foiled_core::share::SharePolicy = serde_json::from_value(v).unwrap();
    assert_eq!(parsed, foiled_core::share::SharePolicy::default());
}
