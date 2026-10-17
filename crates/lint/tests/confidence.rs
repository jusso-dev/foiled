//! The shipped confidence config equals the code defaults, and the worked
//! examples from docs/confidence.md produce links that validate against the
//! schema (written to testdata/confidence-links/ with FOILED_BLESS=1).

use std::path::Path;

use foiled_core::confidence::{
    ConfidenceConfig, ConfidenceLink, Evidence, EvidenceSource, LinkKind, score,
};

fn root() -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

#[test]
fn shipped_config_matches_defaults_and_is_consistent() {
    let v = foiled_lint::load(&root().join("configs/confidence.yaml")).unwrap();
    let cfg: ConfidenceConfig = serde_json::from_value(v).unwrap();
    assert_eq!(cfg, ConfidenceConfig::default());
    assert!(cfg.problems().is_empty(), "{:?}", cfg.problems());
}

fn ev(id: &str, source: EvidenceSource, weight: u8, summary: &str) -> Evidence {
    Evidence {
        signal_id: id.into(),
        source,
        weight,
        summary: summary.into(),
        reference: None,
    }
}

fn examples() -> Vec<(&'static str, ConfidenceLink)> {
    let cfg = ConfidenceConfig::default();
    use EvidenceSource::*;
    vec![
        (
            "hook-and-sequence-high",
            score(
                &cfg,
                LinkKind::AttemptCve,
                "att_000000000000000000000001",
                "FOILED-DEMO-0001",
                vec![
                    ev(
                        "hook:demo-app.upload-path-traversal",
                        VulnPathHook,
                        100,
                        "vulnerable path ran",
                    ),
                    ev(
                        "seq:demo-upload-chain",
                        Sequence,
                        90,
                        "probe, upload, write in order",
                    ),
                    ev(
                        "catalogue:foiled/demo-app/1.0.0",
                        CataloguePrior,
                        100,
                        "decoy stood up for this CVE",
                    ),
                ],
                None,
            )
            .unwrap(),
        ),
        (
            "signature-only-medium",
            score(
                &cfg,
                LinkKind::AttemptCve,
                "att_000000000000000000000002",
                "FOILED-DEMO-0001",
                vec![
                    ev(
                        "matcher:foiled-demo-0001-upload-traversal",
                        Rule,
                        100,
                        "request shape matched",
                    ),
                    ev(
                        "catalogue:foiled/demo-app/1.0.0",
                        CataloguePrior,
                        100,
                        "decoy stood up for this CVE",
                    ),
                ],
                None,
            )
            .unwrap(),
        ),
        (
            "llm-only-capped",
            score(
                &cfg,
                LinkKind::AttemptCve,
                "att_000000000000000000000003",
                "CVE-2099-0001",
                vec![ev("llm:proposal-1", Llm, 100, "model proposed this CVE")],
                None,
            )
            .unwrap(),
        ),
    ]
}

#[test]
fn worked_examples_match_the_documented_outcomes() {
    let ex = examples();
    let get = |n: &str| &ex.iter().find(|(k, _)| *k == n).unwrap().1;
    assert_eq!(
        get("hook-and-sequence-high").band,
        foiled_core::confidence::Band::High
    );
    assert!(get("hook-and-sequence-high").publishable);
    assert_eq!(
        get("signature-only-medium").band,
        foiled_core::confidence::Band::Medium
    );
    assert!(!get("llm-only-capped").publishable);
    let dir = root().join("testdata/confidence-links");
    for (name, link) in &ex {
        let path = dir.join(format!("{name}.json"));
        if std::env::var("FOILED_BLESS").is_ok() {
            std::fs::write(&path, serde_json::to_string_pretty(link).unwrap() + "\n").unwrap();
        }
        let stored: ConfidenceLink =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(&stored, link, "{name}");
    }
}
