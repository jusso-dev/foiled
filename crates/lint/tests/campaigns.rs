//! Golden test for campaign clustering (#33): each
//! `testdata/campaigns/*.input.json` is grouped into attempts (#25) with the
//! tier 1 signatures as state signals (as the API does), its IOCs extracted
//! (#34), its CVE and technique signals computed from the shipped rule
//! packs (#12, #26), and clustered with the fixture's ASN table (#11). The
//! campaigns must match `testdata/campaigns/expected/`, one file per
//! campaign, which the repository lint also validates against
//! `schemas/campaign.schema.json`.
//!
//! To regenerate after an intended change, run with FOILED_BLESS=1 and
//! review the diff.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use foiled_core::attack::AttackRule;
use foiled_core::attempt::{Attempt, DEFAULT_IDLE_GAP_MS, ExtraSignals, StateSignal, build};
use foiled_core::campaign::{
    ActionKind, Campaign, CampaignAction, CampaignStatus, Clustering, Feature, Input, Params,
    Registry, TargetingPattern, attach, attempt_signals, cluster,
};
use foiled_core::capture::CaptureEvent;
use foiled_core::confidence::{Band, ConfidenceConfig};
use foiled_core::cvemap::Rules;
use foiled_core::ioc::{ExtractOptions, Extraction, extract};
use serde::de::DeserializeOwned;

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn load_dir<T: DeserializeOwned>(rel: &str) -> Vec<T> {
    let mut out = Vec::new();
    for e in walkdir::WalkDir::new(root().join(rel)).sort_by_file_name() {
        let e = e.unwrap();
        let ext = e.path().extension().and_then(|x| x.to_str());
        if e.file_type().is_file() && matches!(ext, Some("yaml" | "yml" | "json")) {
            let v = foiled_lint::load(e.path()).unwrap();
            out.push(
                serde_json::from_value(v)
                    .unwrap_or_else(|err| panic!("{}: {err}", e.path().display())),
            );
        }
    }
    out
}

struct Fixture {
    attempts: Vec<Attempt>,
    iocs: Extraction,
    clustering: Clustering,
}

fn run(name: &str, actions: &[CampaignAction]) -> Fixture {
    let raw: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(root().join(format!("testdata/campaigns/{name}.input.json")))
            .unwrap(),
    )
    .unwrap();
    let now = raw["now"].as_i64().unwrap();
    let events: Vec<CaptureEvent> = serde_json::from_value(raw["events"].clone()).unwrap();
    for e in &events {
        assert!(e.problems(now).is_empty(), "{}", e.event_id);
    }
    let asns: BTreeMap<String, u32> = serde_json::from_value(raw["asns"].clone()).unwrap();
    let rules = Rules {
        matchers: load_dir("catalogue/matchers"),
        sequences: load_dir("catalogue/sequences"),
        advisories: load_dir("catalogue/advisories"),
    };
    let attack: Vec<AttackRule> = load_dir("rules/attack");
    // Tier 1 signature hits move attempts to exploit, as in the API.
    let mut extra = ExtraSignals::new();
    for m in &rules.matchers {
        for e in events.iter().filter(|e| m.matches(e)) {
            extra.insert(e.event_id.clone(), vec![StateSignal::Matcher]);
        }
    }
    let mut attempts = build(&events, DEFAULT_IDLE_GAP_MS, &extra);
    let cfg = ConfidenceConfig::default();
    let mut iocs = extract(&attempts, &events, &cfg, ExtractOptions::default());
    foiled_core::ioc::attach_refs(&mut attempts, &iocs);
    let signals = attempt_signals(&attempts, &events, &attack, &rules);
    let advisories: BTreeMap<String, i64> = rules
        .advisories
        .iter()
        .map(|a| (a.cve_id.clone(), a.published_at))
        .collect();
    let clustering = cluster(
        &Input {
            tenant_id: "t1",
            attempts: &attempts,
            iocs: &iocs,
            signals: &signals,
            asns: &asns,
            advisories: &advisories,
            actions,
            registry: &Registry::default(),
            now,
        },
        Params::default(),
        &cfg,
    );
    attach(&mut attempts, &mut iocs, &clustering);
    Fixture {
        attempts,
        iocs,
        clustering,
    }
}

fn check_golden(name: &str, campaigns: &[Campaign]) {
    let dir = root().join("testdata/campaigns/expected");
    let prefix = format!("{name}-");
    let ours = |p: &Path| {
        p.file_name()
            .unwrap()
            .to_string_lossy()
            .starts_with(&prefix)
    };
    if std::env::var("FOILED_BLESS").is_ok() {
        for entry in std::fs::read_dir(&dir).unwrap() {
            let p = entry.unwrap().path();
            if ours(&p) {
                std::fs::remove_file(p).unwrap();
            }
        }
        for (i, c) in campaigns.iter().enumerate() {
            let path = dir.join(format!("{name}-{i:02}.json"));
            std::fs::write(path, serde_json::to_string_pretty(c).unwrap() + "\n").unwrap();
        }
    }
    let mut files: Vec<_> = std::fs::read_dir(&dir)
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| ours(p))
        .collect();
    files.sort();
    let expected: Vec<Campaign> = files
        .iter()
        .map(|p| serde_json::from_str(&std::fs::read_to_string(p).unwrap()).unwrap())
        .collect();
    assert_eq!(campaigns, expected.as_slice(), "{name}");
}

#[test]
fn fleet_wave_matches_golden() {
    let f = run("fleet-wave", &[]);
    check_golden("fleet-wave", &f.clustering.campaigns);
    let c = &f.clustering.campaigns;
    assert_eq!(
        c.len(),
        2,
        "two campaigns, the bystander probe joins nothing"
    );

    // #33 validation: three attempts, same payload hash, different sensors.
    let wave = &c[0];
    assert_eq!(wave.attempt_ids.len(), 3);
    assert_eq!(wave.sensor_ids.len(), 3);
    assert_eq!(wave.seed.features[0], Feature::PayloadSha256);
    assert!(
        wave.members
            .iter()
            .all(|m| m.joined_by[0].feature == Feature::PayloadSha256)
    );
    assert_eq!(wave.status, CampaignStatus::Active);
    assert_eq!(wave.confidence.band, Band::Medium);
    assert_eq!(wave.confidence.wording, "possible");
    assert!(!wave.confidence.publishable);
    let timing = &wave.feature_summary.targeting.advisory_timing;
    assert_eq!(timing.len(), 1);
    assert!(timing[0].before_disclosure, "the advisory came later");

    // The stage-2 pair joins on strong infrastructure and medium TTPs.
    let chain = &c[1];
    assert_eq!(chain.attempt_ids.len(), 2);
    assert_eq!(chain.status, CampaignStatus::Emerging, "only two attempts");
    let features: Vec<Feature> = chain.members[0]
        .joined_by
        .iter()
        .map(|j| j.feature)
        .collect();
    for f in [
        Feature::Stage2Url,
        Feature::CallbackDomain,
        Feature::CallbackIp,
        Feature::BehaviourFingerprint,
        Feature::AsnCve,
    ] {
        assert!(features.contains(&f), "missing {f:?} in {features:?}");
    }
    assert_eq!(chain.feature_summary.infrastructure.asns, vec![64500]);
    assert_eq!(
        chain.feature_summary.infrastructure.stage2_urls.values,
        vec!["hxxp://stage2[.]example[.]invalid/m.sh"]
    );
    assert!(
        chain
            .feature_summary
            .ttp
            .techniques
            .contains(&"T1190".to_string())
    );
    assert_ne!(
        chain.feature_summary.targeting.pattern,
        TargetingPattern::Mass
    );

    // The read model: attempts and IOCs carry the campaign ids.
    let clustered = f
        .attempts
        .iter()
        .filter(|a| a.campaign_id.is_some())
        .count();
    assert_eq!(clustered, 5);
    let url = f
        .iocs
        .iocs
        .iter()
        .find(|i| i.value == "http://stage2.example.invalid/m.sh")
        .unwrap();
    assert_eq!(url.campaign_ids, vec![chain.campaign_id.clone()]);

    // Same evidence, same campaigns and ids.
    assert_eq!(run("fleet-wave", &[]).clustering, f.clustering);
}

#[test]
fn shared_asn_and_generic_probe_form_no_campaign() {
    // #33 validation: only a shared ASN and a generic probe.
    let f = run("shared-asn-probe", &[]);
    check_golden("shared-asn-probe", &f.clustering.campaigns);
    assert!(f.clustering.campaigns.is_empty());
    assert!(f.attempts.iter().all(|a| a.campaign_id.is_none()));
}

#[test]
fn recorded_analyst_actions_replay_over_the_fleet_wave() {
    let actions: Vec<CampaignAction> = load_dir("testdata/campaigns/actions");
    assert!(!actions.is_empty());
    for a in &actions {
        assert!(
            a.problems().is_empty(),
            "{}: {:?}",
            a.action_id,
            a.problems()
        );
    }
    let base = run("fleet-wave", &[]);
    let f = run("fleet-wave", &actions);
    assert!(f.clustering.notes.is_empty(), "{:?}", f.clustering.notes);
    let merge = actions
        .iter()
        .find(|a| a.kind == ActionKind::Merge)
        .unwrap();
    assert_eq!(f.clustering.campaigns.len(), 1, "the two campaigns merged");
    let c = &f.clustering.campaigns[0];
    assert_eq!(c.campaign_id, merge.campaign_id);
    assert_eq!(c.attempt_ids.len(), 5);
    assert_eq!(
        c.analyst.merged_from,
        vec![merge.merge[0].campaign_id.clone()]
    );
    let label = actions
        .iter()
        .find(|a| a.kind == ActionKind::Label)
        .unwrap();
    assert_eq!(Some(c.title.as_str()), label.title.as_deref());
    assert_eq!(
        c.analyst.action_ids,
        actions
            .iter()
            .map(|a| a.action_id.clone())
            .collect::<Vec<_>>()
    );
    // Base campaign ids are the ones the actions name.
    for a in &actions {
        assert!(base.clustering.get(&a.campaign_id).is_some());
    }
}

fn validator(schema: &str) -> jsonschema::Validator {
    let schema = foiled_lint::load(&root().join(schema)).unwrap();
    jsonschema::validator_for(&schema).unwrap()
}

#[test]
fn schemas_refuse_attribution_wording_fleet_scope_and_unexplained_members() {
    let v = validator("schemas/campaign.schema.json");
    let good: serde_json::Value =
        serde_json::to_value(&run("fleet-wave", &[]).clustering.campaigns[0]).unwrap();
    assert!(v.is_valid(&good));
    let bad = |f: &dyn Fn(&mut serde_json::Value)| {
        let mut c = good.clone();
        f(&mut c);
        assert!(!v.is_valid(&c), "{c}");
    };
    // A bridge record, as clustering writes it, validates.
    let mut bridged = good.clone();
    bridged["bridges"] =
        serde_json::json!([serde_json::to_value(foiled_core::campaign::BridgeRecord {
            campaign_id: good["campaign_id"].as_str().unwrap().into(),
            merged_campaign_id: None,
            attempt_id: good["attempt_ids"][0].as_str().unwrap().into(),
            with_attempt_id: good["attempt_ids"][1].as_str().unwrap().into(),
            signal_id: "campaign:payload_sha256:0123456789ab".into(),
            feature: Feature::PayloadSha256,
            attempt_side: 2,
            with_side: 2,
            small_halves: true,
            recorded_at: 1,
        })
        .unwrap()]);
    assert!(v.is_valid(&bridged), "{bridged}");
    bad(&|c| c["confidence"]["wording"] = "confirmed association".into());
    bad(&|c| c["tenant_scope"] = "fleet".into());
    bad(&|c| c["members"][0]["joined_by"] = serde_json::json!([]));
    bad(&|c| c["attempt_ids"] = serde_json::json!([c["attempt_ids"][0].clone()]));
    bad(&|c| {
        c["suggested_actor_links"] = serde_json::json!([{"label": "x", "wording": "attributed to",
            "confidence_ref": "x", "report_urls": []}])
    });

    let v = validator("schemas/campaign-action.schema.json");
    let actions: Vec<serde_json::Value> = load_dir("testdata/campaigns/actions");
    let mut label = actions.into_iter().find(|a| a["kind"] == "label").unwrap();
    assert!(v.is_valid(&label));
    label["feedback"] = "unsure".into();
    assert!(!v.is_valid(&label), "fields belong to their action");
}
