//! ATT&CK mapping data checks (#26): every rule under `rules/attack/` loads
//! into the core rule type and names a technique in the pinned sidecar
//! `data/attack/techniques.json`, catalogue priors use known ids, and the
//! shipped rules map the demo attempt fixtures in `testdata/attack/` to the
//! expected techniques.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use foiled_core::attack::{
    AttackRule, AttackSidecar, AttemptTechniqueLink, TechniqueLink, evaluate, validate,
};
use foiled_core::capture::CaptureEvent;
use serde_json::Value;

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn files(rel: &str, ext: &str) -> Vec<PathBuf> {
    let mut out: Vec<_> = std::fs::read_dir(root().join(rel))
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().and_then(|e| e.to_str()) == Some(ext))
        .collect();
    out.sort();
    out
}

fn sidecar() -> AttackSidecar {
    let value = foiled_lint::load(&root().join("data/attack/techniques.json")).unwrap();
    serde_json::from_value(value).unwrap()
}

fn rules() -> Vec<AttackRule> {
    files("rules/attack", "yaml")
        .into_iter()
        .map(|p| {
            let value = foiled_lint::load(&p).unwrap();
            let rule: AttackRule =
                serde_json::from_value(value).unwrap_or_else(|e| panic!("{}: {e}", p.display()));
            let stem = p.file_stem().unwrap().to_str().unwrap();
            assert_eq!(
                rule.id,
                stem,
                "{}: id must equal the file name",
                p.display()
            );
            rule
        })
        .collect()
}

fn read_trimmed(rel: &str) -> String {
    std::fs::read_to_string(root().join(rel))
        .unwrap()
        .trim()
        .to_string()
}

#[test]
fn sidecar_matches_pinned_version_and_keeps_mitre_notice() {
    let s = sidecar();
    assert!(s.problems().is_empty(), "{:?}", s.problems());
    assert_eq!(s.attack_version, read_trimmed("data/attack/VERSION"));
    assert_eq!(s.domain, "enterprise-attack");
    let sha = read_trimmed("data/attack/SHA256");
    assert!(
        sha.len() == 64
            && sha
                .chars()
                .all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c)),
        "data/attack/SHA256 must hold one lowercase SHA-256"
    );
}

#[test]
fn every_rule_loads_and_names_a_known_technique() {
    let rules = rules();
    assert!(rules.len() >= 5, "expected at least five rules");
    let problems = validate(&rules, &sidecar().known_ids());
    let text: Vec<String> = problems.iter().map(ToString::to_string).collect();
    assert!(problems.is_empty(), "{text:#?}");
}

#[test]
fn catalogue_priors_use_known_techniques() {
    let known = sidecar().known_ids();
    let mut stack = vec![root().join("catalogue/entries")];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                stack.push(path);
                continue;
            }
            let value = foiled_lint::load(&path).unwrap();
            let priors = value
                .get("expected_techniques")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default();
            for t in priors {
                let t = t.as_str().unwrap();
                assert!(
                    known.contains(t),
                    "{}: {t} is not in data/attack/techniques.json",
                    path.display()
                );
            }
        }
    }
}

fn attempts() -> BTreeMap<String, Vec<CaptureEvent>> {
    let mut out: BTreeMap<String, Vec<CaptureEvent>> = BTreeMap::new();
    for p in files("testdata/attack", "json") {
        let value = foiled_lint::load(&p).unwrap();
        let e: CaptureEvent =
            serde_json::from_value(value).unwrap_or_else(|err| panic!("{}: {err}", p.display()));
        assert!(
            e.problems(1_800_000_000_000).is_empty(),
            "{}: {:?}",
            p.display(),
            e.problems(1_800_000_000_000)
        );
        let attempt = e.attempt_id.clone().expect("fixtures carry attempt_id");
        out.entry(attempt).or_default().push(e);
    }
    out
}

fn ids(links: &[TechniqueLink]) -> Vec<&str> {
    links.iter().map(TechniqueLink::official_id).collect()
}

#[test]
fn shipped_rules_map_demo_attempts_to_expected_techniques() {
    let rules = rules();
    let attempts = attempts();
    let expected: [(&str, &[&str]); 3] = [
        (
            "atm-demo-1",
            &[
                "T1059.004",
                "T1071.001",
                "T1082",
                "T1083",
                "T1105",
                "T1190",
                "T1505.003",
            ],
        ),
        ("atm-redis-1", &["T1053.003", "T1496.001"]),
        ("atm-ssh-1", &["T1046", "T1059.004", "T1082", "T1110.001"]),
    ];
    assert_eq!(attempts.len(), expected.len());
    for (attempt, want) in expected {
        let links = evaluate(&rules, &attempts[attempt]);
        assert_eq!(ids(&links), want, "{attempt}");
    }

    let ssh = evaluate(&rules, &attempts["atm-ssh-1"]);
    let guessing = ssh.iter().find(|l| l.official_id() == "T1110.001").unwrap();
    assert_eq!(
        guessing.matched_signals.len(),
        2,
        "one signal per failed login"
    );

    let demo = evaluate(&rules, &attempts["atm-demo-1"]);
    let t1190 = demo.iter().find(|l| l.official_id() == "T1190").unwrap();
    assert_eq!(t1190.max_weight, 85, "hook trigger outweighs the signature");
}

#[test]
fn post_exploit_shell_exec_yields_t1059_004_link() {
    let rules = rules();
    let demo = evaluate(&rules, &attempts()["atm-demo-1"]);
    let shell = demo
        .into_iter()
        .find(|l| l.subtechnique_id.as_deref() == Some("T1059.004"))
        .expect("T1059.004 link");
    assert_eq!(shell.technique_id, "T1059");
    let stored = shell.for_attempt("atm-demo-1", &read_trimmed("data/attack/VERSION"));
    let golden: AttemptTechniqueLink = serde_json::from_value(
        foiled_lint::load(&root().join("testdata/technique-links/demo-unix-shell.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(stored, golden);
}

#[test]
fn every_produced_link_validates_against_the_link_schema() {
    let schema = foiled_lint::load(&root().join("schemas/technique-link.schema.json")).unwrap();
    let validator = jsonschema::validator_for(&schema).unwrap();
    let version = read_trimmed("data/attack/VERSION");
    let rules = rules();
    let mut count = 0;
    for (attempt, events) in attempts() {
        for link in evaluate(&rules, &events) {
            let stored = serde_json::to_value(link.for_attempt(&attempt, &version)).unwrap();
            let errors: Vec<String> = validator
                .iter_errors(&stored)
                .map(|e| e.to_string())
                .collect();
            assert!(errors.is_empty(), "{stored}: {errors:?}");
            count += 1;
        }
    }
    assert!(count >= 3);
}
