//! The capture fixtures validate against the JSON Schema (via BINDINGS in the
//! repository test) and also parse into the Rust envelope with no problems,
//! so the schema and `foiled_core::capture` cannot drift apart.

use std::path::Path;

use foiled_core::capture::{CaptureEvent, Channel, EventProblem};

fn fixtures() -> Vec<(String, serde_json::Value)> {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../testdata/capture");
    let mut out: Vec<_> = std::fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().path())
        .map(|p| (p.display().to_string(), foiled_lint::load(&p).unwrap()))
        .collect();
    out.sort_by(|a, b| a.0.cmp(&b.0));
    out
}

#[test]
fn every_fixture_parses_and_passes_core_checks() {
    let now = 1_800_000_000_000;
    let all = fixtures();
    assert!(all.len() >= 4);
    let mut channels = Vec::new();
    for (name, value) in all {
        let e: CaptureEvent =
            serde_json::from_value(value).unwrap_or_else(|err| panic!("{name}: {err}"));
        assert!(e.problems(now).is_empty(), "{name}: {:?}", e.problems(now));
        channels.push(e.channel);
    }
    assert!(channels.contains(&Channel::Hook));
    assert!(channels.contains(&Channel::Application));
}

#[test]
fn schema_and_core_both_reject_hook_fields_off_the_hook_channel() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let schema = foiled_lint::load(&root.join("schemas/capture-event.schema.json")).unwrap();
    let validator = jsonschema::validator_for(&schema).unwrap();
    let (_, mut hook) = fixtures()
        .into_iter()
        .find(|(n, _)| n.ends_with("hook-trigger.json"))
        .unwrap();
    assert!(validator.is_valid(&hook));
    hook["channel"] = serde_json::json!("application");
    assert!(!validator.is_valid(&hook));
    let e: CaptureEvent = serde_json::from_value(hook).unwrap();
    assert!(
        e.problems(1_800_000_000_000)
            .contains(&EventProblem::HookChannelMismatch)
    );
}
