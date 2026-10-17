//! Checks that `configs/honeyscore.yaml` parses into the core config type and
//! ships disabled (#18).

use std::path::Path;

use foiled_core::honeyscore::{Cadence, HoneyscoreConfig};

#[test]
fn shipped_honeyscore_config_is_valid_and_disabled() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../configs/honeyscore.yaml");
    let value = foiled_lint::load(&path).unwrap();
    let cfg: HoneyscoreConfig = serde_json::from_value(value).unwrap();
    cfg.validate().unwrap();
    assert!(!cfg.enabled, "the Honeyscore check must be off by default");
    assert_eq!(cfg.cadence, Cadence::Daily);
    assert_eq!(cfg.threshold, 0.5);
    assert_eq!(cfg.api_key_env, "SHODAN_API_KEY");
}
