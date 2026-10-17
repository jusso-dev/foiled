//! The shipped enrichment config keeps every third-party provider off, names
//! keys by variable only, and lists only providers that `foiled_core` keeps
//! out of exports. The Fact fixtures pass both the schema and the Rust type.

use std::path::{Path, PathBuf};

use foiled_core::enrichment::{Fact, LOCAL_ASN, NEVER_REDISTRIBUTE};
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
fn third_party_providers_are_off_by_default() {
    let cfg = config();
    let providers = cfg["providers"].as_object().unwrap();
    assert_eq!(providers.len(), 7);
    for (id, p) in providers {
        assert!(
            NEVER_REDISTRIBUTE.contains(&id.as_str()),
            "{id} is not in NEVER_REDISTRIBUTE"
        );
        if id != LOCAL_ASN {
            assert_eq!(p["enabled"], json!(false), "{id} must ship disabled");
        }
    }
    assert_eq!(cfg["show_to_tenants"], json!(false));
}

#[test]
fn schema_rejects_pasted_keys_and_unknown_providers() {
    let v = validator("schemas/enrichment-config.schema.json");
    let good = config();
    assert!(v.is_valid(&good));

    let mut pasted = good.clone();
    pasted["providers"]["greynoise"]["api_key_env"] = json!("gn_live_3xAmPl3k3y");
    assert!(!v.is_valid(&pasted));

    let mut extra = good.clone();
    extra["providers"]["newfeed"] = good["providers"]["abuseipdb"].clone();
    assert!(!v.is_valid(&extra));

    let mut no_ua = good.clone();
    no_ua["providers"]["dshield"]
        .as_object_mut()
        .unwrap()
        .remove("user_agent_env");
    assert!(!v.is_valid(&no_ua));

    let mut keyless = good.clone();
    keyless["providers"]["crowdsec"]
        .as_object_mut()
        .unwrap()
        .remove("api_key_env");
    assert!(!v.is_valid(&keyless));

    let mut plain_http = good;
    plain_http["providers"]["abuseipdb"]["endpoint"] = json!("http://api.example.invalid/");
    assert!(!v.is_valid(&plain_http));
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
