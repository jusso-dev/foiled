//! CVE mapping tier files (#12) parse into the Rust types, point at things
//! that exist, and give the confidence the docs promise on the demo fleet.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use foiled_core::capture::CaptureEvent;
use foiled_core::catalogue::CatalogueEntry;
use foiled_core::confidence::{Band, ConfidenceConfig, Evidence, EvidenceSource, LinkKind, score};
use foiled_core::cvemap::{
    Advisory, Matcher, Rules, Sequence, WatchlistEntry, backmatch, evaluate,
};
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

fn rules() -> Rules {
    Rules {
        matchers: load_dir("catalogue/matchers"),
        sequences: load_dir("catalogue/sequences"),
        advisories: load_dir("catalogue/advisories"),
    }
}

#[test]
fn tier_files_reference_existing_matchers_entries_and_cves() {
    let entries: Vec<CatalogueEntry> = load_dir("catalogue/entries");
    let r = rules();
    assert!(!r.matchers.is_empty() && !r.sequences.is_empty() && !r.advisories.is_empty());
    let matcher_ids: BTreeSet<&str> = r.matchers.iter().map(|m| m.id.as_str()).collect();
    let cves_of = |cat: &str| -> BTreeSet<String> {
        entries
            .iter()
            .find(|e| e.id == cat)
            .unwrap_or_else(|| panic!("catalogue entry {cat} not found"))
            .cves
            .iter()
            .map(|c| c.cve_id.clone())
            .collect()
    };
    let check = |what: &str, cats: &[String], cves: &[String]| {
        for cat in cats {
            let known = cves_of(cat);
            for cve in cves {
                assert!(known.contains(cve), "{what}: {cve} not listed on {cat}");
            }
        }
    };
    for m in &r.matchers {
        check(&m.id, &m.catalogue_ids, &m.cve_ids);
    }
    for s in &r.sequences {
        check(&s.id, &s.catalogue_ids, &s.cve_ids);
        for step in &s.steps {
            if let Some(m) = &step.matcher {
                assert!(
                    matcher_ids.contains(m.as_str()),
                    "{}: unknown matcher {m}",
                    s.id
                );
            }
        }
    }
    for a in &r.advisories {
        check(&a.cve_id, &a.catalogue_ids, std::slice::from_ref(&a.cve_id));
    }
}

fn demo_events() -> Vec<CaptureEvent> {
    let v = foiled_lint::load(&root().join("testdata/attempts/demo-fleet.input.json")).unwrap();
    serde_json::from_value(v["events"].clone()).unwrap()
}

fn link(evidence: Vec<Evidence>) -> foiled_core::confidence::ConfidenceLink {
    score(
        &ConfidenceConfig::default(),
        LinkKind::AttemptCve,
        "att_example",
        "FOILED-DEMO-0001",
        evidence,
        None,
    )
    .unwrap()
}

/// Hook evidence the way the API builds it from an attempt's hook hits.
fn hook_evidence(events: &[CaptureEvent]) -> Vec<Evidence> {
    events
        .iter()
        .filter(|e| e.hook.is_some())
        .map(|e| Evidence {
            signal_id: format!("hook:{}", e.event_id),
            source: EvidenceSource::VulnPathHook,
            weight: 100,
            summary: "hook".into(),
            reference: Some(e.event_id.clone()),
        })
        .collect()
}

#[test]
fn demo_chain_is_high_and_a_sprayed_upload_alone_is_not() {
    let r = rules();
    let all = demo_events();
    let attacker: Vec<CaptureEvent> = all
        .iter()
        .filter(|e| e.src.ip == "203.0.113.7")
        .cloned()
        .collect();

    // Full chain: page load, traversal upload, hook.
    let t = evaluate(&r, &attacker, &[]);
    let mut evidence = t.evidence["FOILED-DEMO-0001"].clone();
    let sources: BTreeSet<_> = evidence.iter().map(|e| e.source).collect();
    assert!(sources.contains(&EvidenceSource::Rule));
    assert!(sources.contains(&EvidenceSource::Sequence));
    assert_eq!(
        t.matcher_hits["x2"],
        vec!["foiled-demo-0001-upload-traversal".to_string()]
    );
    evidence.extend(hook_evidence(&attacker));
    assert_eq!(link(evidence).band, Band::High);

    // A scanner that only sprays the upload request: signature only.
    let sprayed: Vec<CaptureEvent> = attacker
        .iter()
        .filter(|e| e.event_id == "x2")
        .cloned()
        .collect();
    let t = evaluate(&r, &sprayed, &[]);
    let evidence = t.evidence["FOILED-DEMO-0001"].clone();
    assert!(evidence.iter().all(|e| e.source == EvidenceSource::Rule));
    let l = link(evidence);
    assert!(l.band <= Band::Medium, "signature only scored {}", l.score);
    assert!(!l.publishable);

    // The Redis probe and the plain page loads match nothing.
    let quiet: Vec<CaptureEvent> = all
        .iter()
        .filter(|e| e.src.ip != "203.0.113.7")
        .cloned()
        .collect();
    assert!(evaluate(&r, &quiet, &[]).evidence.is_empty());
}

#[test]
fn watchlist_example_back_matches_the_demo_advisory_with_lead_time() {
    let entries: Vec<WatchlistEntry> = load_dir("testdata/watchlist");
    let advisories: Vec<Advisory> = load_dir("catalogue/advisories");
    let b = backmatch(&entries[0], &advisories[0]).expect("back-match");
    assert_eq!(b.cve_id, "FOILED-DEMO-0001");
    assert!(b.first_seen < b.advisory_published_at);
    assert!(b.lead_time_ms > 0);
}

#[test]
fn sequences_and_matchers_round_trip() {
    for m in load_dir::<Matcher>("catalogue/matchers") {
        let back: Matcher = serde_json::from_value(serde_json::to_value(&m).unwrap()).unwrap();
        assert_eq!(back, m);
    }
    for s in load_dir::<Sequence>("catalogue/sequences") {
        let back: Sequence = serde_json::from_value(serde_json::to_value(&s).unwrap()).unwrap();
        assert_eq!(back, s);
    }
}
