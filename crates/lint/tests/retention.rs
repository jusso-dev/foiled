//! Checks `configs/retention.yaml` against the Rust types in foiled-core.

use std::path::{Path, PathBuf};

use foiled_core::retention::{DataClass, RetentionConfig, TtlDays};

fn config_path() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../configs/retention.yaml")
}

#[test]
fn shipped_config_parses_and_matches_documented_defaults() {
    let value = foiled_lint::load(&config_path()).unwrap();
    let config: RetentionConfig = serde_json::from_value(value).unwrap();
    assert_eq!(config, RetentionConfig::default());
}

#[test]
fn commented_metadata_only_example_parses() {
    let text = std::fs::read_to_string(config_path()).unwrap();
    // The example is the commented `# ttl_days:` block after the
    // "Metadata-only mode" heading, ending at the first bare `#` line.
    let start = text.find("# Metadata-only mode").expect("example heading");
    let block: String = text[start..]
        .lines()
        .skip_while(|l| l.trim() != "# ttl_days:")
        .take_while(|l| l.trim() != "#")
        .map(|l| format!("{}\n", l.strip_prefix("# ").unwrap_or(l)))
        .collect();
    let value: serde_json::Value = serde_yaml_ng::from_str(&block).unwrap();
    let ttl: TtlDays = serde_json::from_value(value["ttl_days"].clone()).unwrap();

    let config = RetentionConfig {
        ttl_days: ttl,
        ..RetentionConfig::default()
    };
    for class in [
        DataClass::Pcap,
        DataClass::FsDiff,
        DataClass::QuarantineFile,
        DataClass::ForensicSnapshot,
        DataClass::ExportBundle,
    ] {
        assert_eq!(config.ttl_days_for(class, None), 0, "{class:?}");
    }
    assert!(config.ttl_days_for(DataClass::Attempt, None) > 0);
    assert!(config.ttl_days_for(DataClass::QuarantineMeta, None) > 0);

    // The example config is also valid against the schema.
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let schema = foiled_lint::load(&root.join("schemas/retention-config.schema.json")).unwrap();
    let validator = jsonschema::validator_for(&schema).unwrap();
    let instance = serde_json::to_value(&config).unwrap();
    assert!(validator.is_valid(&instance));
}

#[test]
fn schema_rejects_bad_configs() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let schema = foiled_lint::load(&root.join("schemas/retention-config.schema.json")).unwrap();
    let validator = jsonschema::validator_for(&schema).unwrap();
    let good = serde_json::to_value(RetentionConfig::default()).unwrap();
    assert!(validator.is_valid(&good));

    let mut negative = good.clone();
    negative["ttl_days"]["pcap"] = (-1).into();
    let mut short_audit = good.clone();
    short_audit["ttl_days"]["audit"] = 7.into();
    let mut unknown = good.clone();
    unknown["ttl_days"]["pcaps"] = 14.into();
    let mut missing = good.clone();
    missing.as_object_mut().unwrap().remove("store_payloads");
    for bad in [negative, short_audit, unknown, missing] {
        assert!(!validator.is_valid(&bad), "{bad}");
    }
}
