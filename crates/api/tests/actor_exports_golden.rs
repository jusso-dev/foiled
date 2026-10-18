//! Golden test for actor links in intel exports (#29, #13). The fleet-wave
//! fixture is built as the API builds it, matched against the shipped
//! ATT&CK groups and the fictional reports in `testdata/actors/reports/`,
//! and exported with `include_actors`. Pending links never export, even
//! with `include_unreviewed`; confirmed links become an `intrusion-set` and
//! a `related-to` relationship per member with cautious wording, and an
//! `intrusion-set` derived from an ATT&CK group carries MITRE's notice.
//! Outputs must match `testdata/exports/{stix,misp}/fleet-wave-actors.json`.
//!
//! To regenerate after an intended change, run with FOILED_BLESS=1 and
//! review the diff.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use foiled_api::catalogue::Catalogue;
use foiled_api::links::{attack_rules, attack_sidecar, cve_rules, matcher_signals};
use foiled_api::routes::exports::{OverrideIndex, export_input};
use foiled_core::actor::{
    ActorCatalogue, ActorLink, ActorReport, AttackGroups, LinkStatus, SubjectInput, export_links,
    subjects, suggest,
};
use foiled_core::attempt::{DEFAULT_IDLE_GAP_MS, build};
use foiled_core::campaign::{Input, Params, Registry, attach, attempt_signals, cluster};
use foiled_core::capture::CaptureEvent;
use foiled_core::confidence::{ConfidenceConfig, Feedback, Override};
use foiled_core::intel::{ExportOptions, Selection, misp, select, stix};
use foiled_core::ioc::{ExtractOptions, extract};
use serde_json::Value;

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../testdata")
}

fn read(rel: &str) -> Value {
    serde_json::from_str(&std::fs::read_to_string(root().join(rel)).unwrap()).unwrap()
}

fn catalogue() -> ActorCatalogue {
    let groups: AttackGroups = serde_json::from_str(
        &std::fs::read_to_string(root().join("../data/attack/groups.json")).unwrap(),
    )
    .unwrap();
    let mut paths: Vec<_> = std::fs::read_dir(root().join("actors/reports"))
        .unwrap()
        .map(|e| e.unwrap().path())
        .collect();
    paths.sort();
    let reports: Vec<ActorReport> = paths
        .iter()
        .map(|p| serde_yaml_ng::from_str(&std::fs::read_to_string(p).unwrap()).unwrap())
        .collect();
    let c = ActorCatalogue::build(Some(&groups), attack_sidecar(), reports);
    assert!(c.problems.is_empty(), "{:?}", c.problems);
    c
}

/// The export selection for the fleet-wave fixture. `confirm` names the
/// actor ids an analyst confirmed on the stage-2 campaign. The campaign is
/// also given two rare techniques so an ATT&CK group links to it.
fn selection(confirm: &[&str], opts: &ExportOptions) -> (Selection, Vec<ActorLink>) {
    let raw = read("campaigns/fleet-wave.input.json");
    let now = raw["now"].as_i64().unwrap();
    let events: Vec<CaptureEvent> = serde_json::from_value(raw["events"].clone()).unwrap();
    let asns: BTreeMap<String, u32> = serde_json::from_value(raw["asns"].clone()).unwrap();
    let mut attempts = build(&events, DEFAULT_IDLE_GAP_MS, &matcher_signals(&events));
    let cfg = ConfidenceConfig::default();
    let mut x = extract(&attempts, &events, &cfg, ExtractOptions::default());
    foiled_core::ioc::attach_refs(&mut attempts, &x);
    let signals = attempt_signals(&attempts, &events, attack_rules(), cve_rules());
    let mut clustering = cluster(
        &Input {
            tenant_id: "t1",
            attempts: &attempts,
            iocs: &x,
            signals: &signals,
            asns: &asns,
            advisories: &BTreeMap::new(),
            actions: &[],
            registry: &Registry::default(),
            now,
        },
        Params::default(),
        &cfg,
    );
    attach(&mut attempts, &mut x, &clustering);
    let chain = clustering
        .campaigns
        .iter_mut()
        .find(|c| c.attempt_ids.len() == 2)
        .unwrap();
    for t in ["T1496.001", "T1053.003"] {
        chain.feature_summary.ttp.techniques.push(t.into());
    }
    let chain_id = chain.campaign_id.clone();
    let subj = subjects(&SubjectInput {
        tenant_id: "t1",
        campaigns: &clustering.campaigns,
        attempts: &attempts,
        signals: &signals,
        iocs: &x,
        asns: &asns,
        countries: &BTreeMap::new(),
    });
    let decisions = confirm
        .iter()
        .map(|a| {
            (
                (chain_id.clone(), a.to_string()),
                Override {
                    feedback: Feedback::TruePositive,
                    analyst_id: "lead".into(),
                    at: now,
                    note: "Reviewed against the cited sources.".into(),
                },
            )
        })
        .collect();
    let links = suggest(&catalogue(), &cfg, &subj, &decisions);
    let input = export_input(
        &Catalogue::bundled(),
        attempts,
        &events,
        &x,
        x.iocs.clone(),
        &OverrideIndex::new(),
        &clustering.campaigns,
        &export_links(&links),
    );
    (select(input, opts), links)
}

fn opts(unreviewed: bool) -> ExportOptions {
    ExportOptions {
        include_actors: true,
        include_unreviewed: unreviewed,
        ..ExportOptions::default()
    }
}

fn of_type<'a>(b: &'a Value, ty: &str) -> Vec<&'a Value> {
    b["objects"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|o| o["type"] == ty)
        .collect()
}

fn check_json(dir: &str, name: &str, got: &Value) {
    let path = root()
        .join("exports")
        .join(dir)
        .join(format!("{name}.json"));
    if std::env::var("FOILED_BLESS").is_ok() {
        std::fs::write(&path, serde_json::to_string_pretty(got).unwrap() + "\n").unwrap();
    }
    let want: Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
    assert_eq!(got, &want, "{}", path.display());
}

#[test]
fn pending_actor_links_never_export() {
    for unreviewed in [false, true] {
        let (sel, links) = selection(&[], &opts(unreviewed));
        assert!(links.len() >= 2, "a report link and an ATT&CK link");
        assert!(links.iter().all(|l| l.status == LinkStatus::Pending));
        let bundle = stix::bundle(&sel);
        assert!(of_type(&bundle, "intrusion-set").is_empty());
        let event = misp::event(&sel, "actors|pending");
        assert!(
            !serde_json::to_string(&event)
                .unwrap()
                .contains("threat-actor")
        );
    }
}

#[test]
fn confirmed_actor_links_export_with_cautious_wording_and_mitre_notice() {
    let (_, pending) = selection(&[], &opts(false));
    let attack = pending
        .iter()
        .find(|l| l.actor_id.starts_with("attack:"))
        .expect("an ATT&CK group links on the rare techniques");
    let attack_id = attack.actor_id.clone();
    let (sel, links) = selection(&["report:example-cluster-01", &attack_id], &opts(false));
    let bundle = stix::bundle(&sel);
    let problems = stix::problems(&bundle);
    assert!(problems.is_empty(), "{problems:#?}");
    let event = misp::event(&sel, "golden|fleet-wave-actors");
    let problems = misp::problems(&event);
    assert!(problems.is_empty(), "{problems:#?}");
    check_json("stix", "fleet-wave-actors", &bundle);
    check_json("misp", "fleet-wave-actors", &event);

    let sets = of_type(&bundle, "intrusion-set");
    assert_eq!(sets.len(), 2, "{bundle}");
    let notice = of_type(&bundle, "marking-definition")
        .into_iter()
        .find(|m| m["name"].as_str().unwrap_or("").contains("MITRE ATT&CK"))
        .expect("MITRE notice marking")["id"]
        .clone();
    for set in &sets {
        let from_attack = set["x_foiled_actor_id"] == Value::from(attack_id.clone());
        let marked = set["object_marking_refs"]
            .as_array()
            .unwrap()
            .contains(&notice);
        assert_eq!(marked, from_attack, "{set}");
        if from_attack {
            assert_eq!(set["external_references"][0]["source_name"], "mitre-attack");
            assert!(
                set["external_references"][0]["url"]
                    .as_str()
                    .unwrap()
                    .starts_with("https://attack.mitre.org/versions/v20/groups/")
            );
        }
    }
    for r in of_type(&bundle, "relationship").into_iter().filter(|r| {
        r["target_ref"]
            .as_str()
            .unwrap()
            .starts_with("intrusion-set--")
    }) {
        assert_eq!(r["x_foiled_wording"], "confirmed association");
        let d = r["description"].as_str().unwrap();
        assert!(d.starts_with("Confirmed association with"), "{d}");
        assert!(
            foiled_core::actor::wording_problems(d, true).is_empty(),
            "{d}"
        );
    }
    assert!(
        event.to_string().contains("ATT&CK v20.0"),
        "MISP carries the notice"
    );
    // Links not confirmed stay out even when others are.
    let exported: usize = sets.len();
    let confirmed = links
        .iter()
        .filter(|l| l.status == LinkStatus::Confirmed)
        .count();
    assert_eq!(exported, confirmed);
}
