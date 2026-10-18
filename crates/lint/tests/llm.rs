//! LLM correlation checks (#28): the shipped config parses into the core
//! type, keeps gateway caching and logging off and caps evidence weight; the
//! result schema rejects confidence and ungrounded links; and every eval
//! case, run offline through the fake provider, produces output that is
//! valid against `schemas/llm-correlation-result.schema.json`.

use std::collections::BTreeSet;
use std::future::Future;
use std::path::{Path, PathBuf};
use std::task::{Context, Poll, Waker};

use foiled_core::attack::AttackSidecar;
use foiled_core::llm::{
    Budget, CorrelationInput, CostLimits, EvalCase, LLM_MAX_WEIGHT, LlmConfig, SamplingRules,
    correlate,
};
use serde_json::{Value, json};

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn load(rel: &str) -> Value {
    foiled_lint::load(&root().join(rel)).unwrap()
}

fn validator(rel: &str) -> jsonschema::Validator {
    jsonschema::validator_for(&load(rel)).unwrap()
}

fn block_on<F: Future>(f: F) -> F::Output {
    let mut f = std::pin::pin!(f);
    let mut cx = Context::from_waker(Waker::noop());
    match f.as_mut().poll(&mut cx) {
        Poll::Ready(v) => v,
        Poll::Pending => panic!("offline providers never wait"),
    }
}

fn files(rel: &str) -> Vec<PathBuf> {
    let mut out: Vec<PathBuf> = std::fs::read_dir(root().join(rel))
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().is_some_and(|e| e == "json"))
        .collect();
    out.sort();
    out
}

#[test]
fn shipped_config_is_valid_off_and_safe() {
    let value = load("configs/llm.yaml");
    assert!(validator("schemas/llm-config.schema.json").is_valid(&value));
    let cfg: LlmConfig = serde_json::from_value(value).unwrap();
    assert_eq!(cfg.problems(), Vec::<String>::new());
    assert!(!cfg.enabled, "the LLM worker must ship off");
    assert!(!cfg.gateway.cache_responses);
    assert!(!cfg.gateway.collect_logs);
    assert_eq!(cfg.budgets, CostLimits::default());
    assert_eq!(cfg.sampling, SamplingRules::default());
    assert!(cfg.evidence.max_weight <= LLM_MAX_WEIGHT);
    let commercial: Vec<_> = cfg.providers.iter().filter(|p| !p.open_model).collect();
    assert!(
        commercial.iter().all(|p| !p.enabled),
        "commercial providers are opt in"
    );
}

#[test]
fn config_schema_rejects_unsafe_settings() {
    let v = validator("schemas/llm-config.schema.json");
    let good = load("configs/llm.yaml");

    let mut cached = good.clone();
    cached["gateway"]["cache_responses"] = json!(true);
    assert!(!v.is_valid(&cached));

    let mut logged = good.clone();
    logged["gateway"]["collect_logs"] = json!(true);
    assert!(!v.is_valid(&logged));

    let mut pasted = good.clone();
    pasted["providers"][1]["api_key_env"] = json!("sk-ant-example-not-a-real-key");
    assert!(!v.is_valid(&pasted));

    let mut heavy = good.clone();
    heavy["evidence"]["max_weight"] = json!(41);
    assert!(!v.is_valid(&heavy));
}

#[test]
fn result_schema_rejects_confidence_and_ungrounded_links() {
    let v = validator("schemas/llm-correlation-result.schema.json");
    let good = load("testdata/llm-eval/expected/demo-upload-traversal.json");
    assert!(v.is_valid(&good));

    let mut confident = good.clone();
    confident["confidence"] = json!(100);
    assert!(!v.is_valid(&confident));

    let mut ungrounded = good.clone();
    ungrounded["citations"] = json!([]);
    assert!(!v.is_valid(&ungrounded));

    let mut empty = ungrounded.clone();
    empty["cve_ids"] = json!([]);
    empty["technique_ids"] = json!([]);
    assert!(v.is_valid(&empty));

    let mut long = good.clone();
    long["rationale"] = json!("x".repeat(601));
    assert!(!v.is_valid(&long));
}

#[test]
fn offline_eval_cases_produce_schema_valid_output() {
    let v = validator("schemas/llm-correlation-result.schema.json");
    let sidecar: AttackSidecar =
        serde_json::from_value(load("data/attack/techniques.json")).unwrap();
    let techniques = sidecar.known_ids();
    let cases = files("testdata/llm-eval/cases");
    assert!(cases.len() >= 2);
    for path in cases {
        let case: EvalCase = serde_json::from_value(foiled_lint::load(&path).unwrap()).unwrap();
        let cves: BTreeSet<String> = case.known_cves.iter().cloned().collect();
        let input = CorrelationInput {
            attempt: &case.attempt,
            chunks: &case.retrieved,
            known_cves: &cves,
            known_techniques: &techniques,
        };
        let fake = case.fake_provider();
        let out = block_on(correlate(
            &[&fake],
            &mut Budget::default(),
            &CostLimits::default(),
            &SamplingRules::default(),
            &input,
            1_792_285_400_000,
        ))
        .unwrap_or_else(|e| panic!("{}: {e}", case.case_id));
        let produced = serde_json::to_value(&out.proposal).unwrap();
        assert!(v.is_valid(&produced), "{}: {produced}", case.case_id);
        let expected = load(&format!("testdata/llm-eval/expected/{}.json", case.case_id));
        assert_eq!(produced, expected, "{}", case.case_id);
    }
}
