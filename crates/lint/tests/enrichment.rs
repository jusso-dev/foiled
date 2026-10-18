//! The shipped enrichment config has the operator's ASN table and the
//! ThreatSieve hub, ships ThreatSieve off, names the key by variable only,
//! and keeps restricted ThreatSieve answers out of exports. The Fact
//! fixtures pass both the schema and the Rust type.

use std::path::{Path, PathBuf};

use foiled_core::enrichment::{
    Fact, LOCAL_ASN, NEVER_REDISTRIBUTE, THREATSIEVE, THREATSIEVE_RESTRICTED,
};
use serde_json::{Value, json};

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn config() -> Value {
    foiled_lint::load(&root().join("configs/enrichment.yaml")).unwrap()
}

fn validator(schema: &str) -> jsonschema::Validator {
    let schema = foiled_lint::load(&root().join(schema)).unwrap();
    jsonschema::validator_for(&schema).unwrap()
}

#[test]
fn shipped_providers_and_redistribution() {
    let cfg = config();
    let providers = cfg["providers"].as_object().unwrap();
    let ids: Vec<&str> = providers.keys().map(String::as_str).collect();
    assert_eq!(ids, vec![LOCAL_ASN, THREATSIEVE]);
    assert_eq!(
        cfg["providers"][THREATSIEVE]["enabled"],
        json!(false),
        "off until bound"
    );
    assert!(NEVER_REDISTRIBUTE.contains(&LOCAL_ASN));
    assert!(NEVER_REDISTRIBUTE.contains(&THREATSIEVE_RESTRICTED));
    // Only provenance-checked answers are written as `threatsieve`.
    assert!(!NEVER_REDISTRIBUTE.contains(&THREATSIEVE));
    assert_eq!(cfg["show_to_tenants"], json!(false));
}

#[test]
fn schema_rejects_pasted_keys_unknown_providers_and_big_batches() {
    let v = validator("schemas/enrichment-config.schema.json");
    let good = config();
    assert!(v.is_valid(&good));

    let mut pasted = good.clone();
    pasted["providers"]["threatsieve"]["api_key_env"] = json!("ts_live_3xAmPl3k3y");
    assert!(!v.is_valid(&pasted));

    let mut extra = good.clone();
    extra["providers"]["greynoise"] = good["providers"]["threatsieve"].clone();
    assert!(!v.is_valid(&extra));

    let mut big = good.clone();
    big["providers"]["threatsieve"]["batch_size"] = json!(501);
    assert!(!v.is_valid(&big));

    let mut no_key = good;
    no_key["providers"]["threatsieve"]
        .as_object_mut()
        .unwrap()
        .remove("api_key_env");
    assert!(!v.is_valid(&no_key));
}

#[test]
fn fact_fixtures_match_schema_and_type() {
    let v = validator("schemas/fact.schema.json");
    let dir = root().join("testdata/enrichment/facts");
    let mut n = 0;
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        let value = foiled_lint::load(&path).unwrap();
        assert!(v.is_valid(&value), "{}", path.display());
        let _: Fact =
            serde_json::from_value(value).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
        n += 1;
    }
    assert!(n >= 3);

    let bad = json!({
        "provider": "greynoise", "key": "greynoise.noise", "value": true,
        "confidence": 101, "observed_at": 0, "ttl_secs": 60
    });
    assert!(!v.is_valid(&bad));
}
