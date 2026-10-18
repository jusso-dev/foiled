//! Golden test for actor possible-association (#29) over the fleet-wave
//! campaigns (#33): `testdata/campaigns/fleet-wave.input.json` is built
//! into attempts, IOCs and campaigns as the campaign golden test does, then
//! matched against the shipped ATT&CK groups sidecar and the fictional
//! reports in `testdata/actors/reports/`, with the source countries in
//! `testdata/actors/fleet-wave.input.json`. The links must match
//! `testdata/actors/expected/`, one file per link, which the repository
//! lint also validates against `schemas/actor-link.schema.json`.
//!
//! Also checks the shipped catalogue: every curated report in
//! `catalogue/actors/` is real (not an example) and passes the report
//! rules; every report under `testdata/actors/reports/` is an example.
//!
//! To regenerate after an intended change, run with FOILED_BLESS=1 and
//! review the diff.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use foiled_core::actor::{
    ActorCatalogue, ActorDecision, ActorLink, ActorReport, AttackGroups, LinkStatus, SubjectInput,
    SubjectKind, attach_suggestions, export_links, subjects, suggest, wording_problems,
};
use foiled_core::attack::{AttackRule, AttackSidecar};
use foiled_core::attempt::{DEFAULT_IDLE_GAP_MS, ExtraSignals, StateSignal, build};
use foiled_core::campaign::{Input, Params, Registry, attach, attempt_signals, cluster};
use foiled_core::capture::CaptureEvent;
use foiled_core::confidence::{Band, ConfidenceConfig, Feedback, Override};
use foiled_core::cvemap::Rules;
use foiled_core::ioc::{ExtractOptions, extract};
use serde::de::DeserializeOwned;

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn load_dir<T: DeserializeOwned>(rel: &str) -> Vec<T> {
    let mut out = Vec::new();
    let dir = root().join(rel);
    if !dir.exists() {
        return out;
    }
    for e in walkdir::WalkDir::new(dir).sort_by_file_name() {
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

fn load<T: DeserializeOwned>(rel: &str) -> T {
    serde_json::from_value(foiled_lint::load(&root().join(rel)).unwrap()).unwrap()
}

fn sidecar() -> AttackSidecar {
    load("data/attack/techniques.json")
}

fn catalogue() -> ActorCatalogue {
    let groups: AttackGroups = load("data/attack/groups.json");
    let mut reports: Vec<ActorReport> = load_dir("catalogue/actors");
    reports.extend(load_dir::<ActorReport>("testdata/actors/reports"));
    let c = ActorCatalogue::build(Some(&groups), &sidecar(), reports);
    assert!(c.problems.is_empty(), "{:?}", c.problems);
    c
}

struct Fixture {
    links: Vec<ActorLink>,
    campaigns: Vec<foiled_core::campaign::Campaign>,
    subjects: Vec<foiled_core::actor::Subject>,
    attempts: Vec<foiled_core::attempt::Attempt>,
}

type Decisions = BTreeMap<(String, String), ActorDecision>;

fn run(decisions: &Decisions) -> Fixture {
    run_input(
        "testdata/campaigns/fleet-wave.input.json",
        "testdata/actors/fleet-wave.input.json",
        decisions,
    )
}

/// Build attempts, IOCs, campaigns and actor links from `events_rel`
/// (`events`, `now`, optional `asns`) with source countries from `geo_rel`.
fn run_input(events_rel: &str, geo_rel: &str, decisions: &Decisions) -> Fixture {
    let raw: serde_json::Value = load(events_rel);
    let geo: serde_json::Value = load(geo_rel);
    let now = raw["now"].as_i64().unwrap();
    let events: Vec<CaptureEvent> = serde_json::from_value(raw["events"].clone()).unwrap();
    for e in &events {
        assert!(e.problems(now).is_empty(), "{}", e.event_id);
    }
    let asns: BTreeMap<String, u32> =
        serde_json::from_value(raw.get("asns").cloned().unwrap_or_default()).unwrap_or_default();
    let countries: BTreeMap<String, String> =
        serde_json::from_value(geo["countries"].clone()).unwrap();
    let rules = Rules {
        matchers: load_dir("catalogue/matchers"),
        sequences: load_dir("catalogue/sequences"),
        advisories: load_dir("catalogue/advisories"),
    };
    let attack: Vec<AttackRule> = load_dir("rules/attack");
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
    let mut clustering = cluster(
        &Input {
            tenant_id: "t1",
            attempts: &attempts,
            iocs: &iocs,
            signals: &signals,
            asns: &asns,
            advisories: &advisories,
            actions: &[],
            registry: &Registry::default(),
            now,
        },
        Params::default(),
        &cfg,
    );
    attach(&mut attempts, &mut iocs, &clustering);
    let subj = subjects(&SubjectInput {
        tenant_id: "t1",
        campaigns: &clustering.campaigns,
        attempts: &attempts,
        lone_attempts: true,
        signals: &signals,
        iocs: &iocs,
        asns: &asns,
        countries: &countries,
        events: &events,
    });
    let links = suggest(&catalogue(), &cfg, &subj, decisions);
    attach_suggestions(&mut clustering.campaigns, &links);
    Fixture {
        links,
        campaigns: clustering.campaigns,
        subjects: subj,
        attempts,
    }
}

fn confirm(l: &ActorLink, attempts: &[String]) -> Decisions {
    BTreeMap::from([(
        (l.subject_id.clone(), l.actor_id.clone()),
        ActorDecision {
            subject_id: l.subject_id.clone(),
            actor_id: l.actor_id.clone(),
            decision: Override {
                feedback: Feedback::TruePositive,
                analyst_id: "lead".into(),
                at: 1,
                note: "Callback address and loader match the advisory.".into(),
            },
            attempt_ids: attempts.to_vec(),
        },
    )])
}

fn check_golden(name: &str, links: &[ActorLink]) {
    let dir = root().join("testdata/actors/expected");
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
        for (i, l) in links.iter().enumerate() {
            let path = dir.join(format!("{name}-{i:02}.json"));
            std::fs::write(path, serde_json::to_string_pretty(l).unwrap() + "\n").unwrap();
        }
    }
    let mut files: Vec<_> = std::fs::read_dir(&dir)
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| ours(p))
        .collect();
    files.sort();
    let expected: Vec<ActorLink> = files
        .iter()
        .map(|p| serde_json::from_str(&std::fs::read_to_string(p).unwrap()).unwrap())
        .collect();
    assert_eq!(links, expected.as_slice(), "{name}");
}

#[test]
fn fleet_wave_gets_one_medium_possible_association_and_geo_only_gets_none() {
    let f = run(&BTreeMap::new());
    check_golden("fleet-wave", &f.links);
    assert_eq!(
        f.subjects
            .iter()
            .filter(|s| s.kind == SubjectKind::Campaign)
            .count(),
        2
    );
    assert_eq!(
        f.subjects
            .iter()
            .filter(|s| s.kind == SubjectKind::Attempt)
            .count(),
        1,
        "the bystander probe"
    );

    // #29 validation: the stage-2 campaign shares techniques, a callback
    // domain and IP, targeting and an ASN with EXAMPLE-CLUSTER-01.
    assert_eq!(f.links.len(), 1, "{:#?}", f.links);
    let l = &f.links[0];
    let chain = f
        .campaigns
        .iter()
        .find(|c| c.attempt_ids.len() == 2)
        .unwrap();
    assert_eq!(l.subject_id, chain.campaign_id);
    assert_eq!(l.actor_id, "report:example-cluster-01");
    assert_eq!(l.band, Band::Medium);
    assert_eq!(l.status, LinkStatus::Pending);
    assert_eq!(l.wording, "possible association");
    assert!(!l.publishable, "never published without an analyst");
    assert!(l.review_queue);
    assert!(
        l.statement
            .starts_with("Possible association with EXAMPLE-CLUSTER-01")
    );
    assert!(l.statement.ends_with("This is not an attribution."));
    assert!(wording_problems(&l.statement, false).is_empty());
    let urls: Vec<&str> = l.sources.iter().map(|s| s.url.as_str()).collect();
    assert_eq!(
        urls,
        [
            "https://reports.example.com/2026/example-cluster-01",
            "https://advisories.example.org/ex-2026-001"
        ]
    );
    assert!(
        l.matched.indicators.iter().any(|i| i.source_url == urls[1]),
        "each indicator cites the report that lists it"
    );
    assert!(l.not_counted.iter().any(|n| n.contains("geography")));

    // Geography (and a shared ASN) alone: no link for the payload-hash wave,
    // the bystander or EXAMPLE-nexus.
    assert!(f.links.iter().all(|l| l.subject_id == chain.campaign_id));
    assert!(
        f.links
            .iter()
            .all(|l| l.actor_id != "report:example-nexus-02")
    );

    // The campaign carries the suggestion; the other carries none.
    assert_eq!(chain.suggested_actor_links.len(), 1);
    let s = &chain.suggested_actor_links[0];
    assert_eq!(s.wording, "possible association");
    assert_eq!(s.confidence_ref, format!("/v0/actor-links/{}", l.link_id));
    assert_eq!(s.report_urls.len(), 2);
    for c in f
        .campaigns
        .iter()
        .filter(|c| c.campaign_id != chain.campaign_id)
    {
        assert!(c.suggested_actor_links.is_empty());
    }

    // Pending links never reach exports (#13).
    assert!(export_links(&f.links).is_empty());

    // Same evidence, same links.
    assert_eq!(run(&BTreeMap::new()).links, f.links);
}

#[test]
fn analyst_confirmation_is_the_only_way_to_high_and_exports() {
    let base = run(&BTreeMap::new());
    let l = &base.links[0];
    let f = run(&confirm(l, &l.attempt_ids));
    let c = &f.links[0];
    assert_eq!(c.status, LinkStatus::Confirmed);
    assert_eq!(
        (c.band, c.wording.as_str()),
        (Band::High, "confirmed association")
    );
    assert!(c.publishable && !c.review_queue);
    let ex = export_links(&f.links);
    assert_eq!(ex.len(), 2, "one attempt_actor link per member");
    for (attempt, links) in &ex {
        assert!(c.attempt_ids.contains(attempt));
        assert_eq!(links[0].wording, "confirmed association");
        assert_eq!(links[0].target, c.label);
    }

    // Confirmed while the campaign had one member: the second one joined
    // later, is not covered, never exports as confirmed and goes back to
    // review.
    let f = run(&confirm(l, &l.attempt_ids[..1]));
    let c = &f.links[0];
    assert_eq!(c.status, LinkStatus::Confirmed);
    assert_eq!(c.confirmed_attempt_ids, l.attempt_ids[..1]);
    assert_eq!(c.new_since_confirmation, l.attempt_ids[1..]);
    assert!(c.review_queue);
    let ex = export_links(&f.links);
    assert_eq!(ex.keys().collect::<Vec<_>>(), [&l.attempt_ids[0]]);
}

#[test]
fn a_callback_the_attacker_named_counts_as_sent_not_observed() {
    // JNDI-style: the request names stage2.example.invalid, the decoy then
    // looks it up and connects. EXAMPLE-CLUSTER-01 lists that domain.
    let f = run_input(
        "testdata/actors/jndi-callback.input.json",
        "testdata/actors/jndi-callback.input.json",
        &BTreeMap::new(),
    );
    let attempt_of = |event: &str| {
        f.attempts
            .iter()
            .find(|a| a.event_ids.iter().any(|e| e == event))
            .unwrap()
            .attempt_id
            .clone()
    };
    let (named, unprompted) = (attempt_of("jndi-1"), attempt_of("jndi-4"));
    assert_ne!(named, unprompted);
    let l = f
        .links
        .iter()
        .find(|l| l.actor_id == "report:example-cluster-01" && l.subject_id == named)
        .expect("a weak link to review");
    assert_eq!(l.band, Band::Low, "{}", l.score);
    assert!(!l.matched.indicators.is_empty());
    assert!(
        l.matched.indicators.iter().all(|i| !i.observed),
        "{:#?}",
        l.matched
    );
    assert!(
        l.confidence
            .evidence
            .iter()
            .all(|e| e.source != foiled_core::confidence::EvidenceSource::ActorIndicatorOverlap)
    );
    assert!(l.not_counted.iter().any(|n| n.contains("false flag")));
    assert!(
        l.matched.indicators.len() >= 2,
        "the domain and the address reached"
    );
    // The other attempt reached the same host and address without naming
    // them: observed for it, whatever the first attempt sent.
    let other = f.subjects.iter().find(|s| s.id == unprompted).unwrap();
    let callbacks: Vec<_> = other
        .indicators
        .iter()
        .filter(|i| i.value == "stage2.example.invalid" || i.value == "192.0.2.80")
        .collect();
    assert_eq!(
        callbacks.len(),
        3,
        "domain, DNS query and address: {:#?}",
        other.indicators
    );
    assert!(callbacks.iter().all(|i| i.observed));
    let mine = f.subjects.iter().find(|s| s.id == named).unwrap();
    assert!(
        mine.indicators
            .iter()
            .filter(|i| i.value == "stage2.example.invalid" || i.value == "192.0.2.80")
            .all(|i| !i.observed)
    );
    // In the fleet wave the stage-2 host came from a download command in
    // the post-exploit hook, so the domain and the address the decoy
    // reached for it are sent too; the source address the attack came from
    // is observed and carries the link to medium.
    let fleet = run(&BTreeMap::new());
    let ind = &fleet.links[0].matched.indicators;
    let observed = |d: &str| ind.iter().find(|i| i.display == d).unwrap().observed;
    assert!(!observed("stage2[.]example[.]invalid"));
    assert!(!observed("192[.]0[.]2[.]80"));
    assert!(observed("192[.]0[.]2[.]10"));
}

#[test]
fn shipped_catalogue_holds_real_entries_and_testdata_holds_examples() {
    let real: Vec<ActorReport> = load_dir("catalogue/actors");
    assert!(real.iter().all(|r| !r.example), "examples stay in testdata");
    let examples: Vec<ActorReport> = load_dir("testdata/actors/reports");
    assert!(!examples.is_empty());
    assert!(examples.iter().all(|r| r.example));
    let known = sidecar().known_ids();
    for r in real.iter().chain(examples.iter()) {
        assert!(
            r.problems(&known).is_empty(),
            "{}: {:?}",
            r.id,
            r.problems(&known)
        );
    }
}

#[test]
fn link_schema_refuses_unconfirmed_strong_wording() {
    let schema = foiled_lint::load(&root().join("schemas/actor-link.schema.json")).unwrap();
    let v = jsonschema::validator_for(&schema).unwrap();
    let good = serde_json::to_value(&run(&BTreeMap::new()).links[0]).unwrap();
    assert!(v.is_valid(&good));
    let bad = |f: &dyn Fn(&mut serde_json::Value)| {
        let mut l = good.clone();
        f(&mut l);
        assert!(!v.is_valid(&l), "{l}");
    };
    bad(&|l| l["wording"] = "confirmed association".into());
    bad(&|l| l["band"] = "high".into());
    bad(&|l| l["publishable"] = true.into());
    bad(&|l| l["statement"] = "EXAMPLE-CLUSTER-01 is behind this campaign.".into());
    bad(&|l| l["statement"] = "Confirmed: EXAMPLE-CLUSTER-01.".into());
}
