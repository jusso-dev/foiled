//! Agent protocol fixtures validate against `schemas/agent/` (repository
//! lint) and parse into the Rust protocol types, so the two stay in step.

use std::path::Path;

use foiled_core::agent::{Heartbeat, JobBody, JobResult, JobSigner, TrustedKeys};

fn load_dir(rel: &str) -> Vec<serde_json::Value> {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join(rel);
    let mut files: Vec<_> = std::fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().path())
        .collect();
    files.sort();
    files
        .iter()
        .map(|p| foiled_lint::load(p).unwrap())
        .collect()
}

#[test]
fn fixtures_parse_into_protocol_types() {
    let jobs = load_dir("testdata/agent/jobs");
    assert!(jobs.len() >= 3);
    for j in jobs {
        let body: JobBody = serde_json::from_value(j).unwrap();
        // A body that parses must survive signing and verification unchanged.
        let signer = JobSigner::from_seed_hex("k1", &"42".repeat(32)).unwrap();
        let mut keys = TrustedKeys::default();
        keys.add_hex("k1", &signer.public_key_hex()).unwrap();
        assert_eq!(keys.verify(&signer.sign(&body)).unwrap(), body);
    }
    for r in load_dir("testdata/agent/results") {
        serde_json::from_value::<JobResult>(r).unwrap();
    }
    for h in load_dir("testdata/agent/heartbeats") {
        serde_json::from_value::<Heartbeat>(h).unwrap();
    }
}

#[test]
fn schema_requires_a_reason_on_destructive_jobs() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let schema = foiled_lint::load(&root.join("schemas/agent/job.schema.json")).unwrap();
    let v = jsonschema::validator_for(&schema).unwrap();
    let mut destroy = load_dir("testdata/agent/jobs")
        .into_iter()
        .find(|j| j["kind"] == "decoy.destroy")
        .unwrap();
    assert!(v.is_valid(&destroy));
    destroy.as_object_mut().unwrap().remove("reason");
    assert!(!v.is_valid(&destroy));
}
