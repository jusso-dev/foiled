//! Checks `configs/mcp.yaml`, `schemas/mcp-config.schema.json` and the tool
//! descriptors in `testdata/mcp/tools-list.json` (#24). The descriptors are
//! a golden file written by `crates/api/tests/mcp.rs`.

use std::path::{Path, PathBuf};

use foiled_core::mcp::McpConfig;
use serde_json::{Value, json};

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn load(rel: &str) -> Value {
    foiled_lint::load(&root().join(rel)).unwrap()
}

#[test]
fn shipped_config_parses_and_matches_documented_defaults() {
    let config: McpConfig = serde_json::from_value(load("configs/mcp.yaml")).unwrap();
    assert_eq!(config, McpConfig::default());
    assert!(config.problems().is_empty());
}

#[test]
fn schema_rejects_loose_configs() {
    let schema = load("schemas/mcp-config.schema.json");
    let validator = jsonschema::validator_for(&schema).unwrap();
    let good = serde_json::to_value(McpConfig::default()).unwrap();
    assert!(validator.is_valid(&good));

    let mut long_life = good.clone();
    long_life["limits"]["max_lifetime_seconds"] = (8 * 24 * 3600).into();
    let mut zero = good.clone();
    zero["limits"]["creates_per_hour"] = 0.into();
    let mut plain_http = good.clone();
    plain_http["allowed_origins"] = json!(["http://console.example.invalid"]);
    let mut unknown = good.clone();
    unknown["limits"]["burst"] = 10.into();
    for bad in [long_life, zero, plain_http, unknown] {
        assert!(!validator.is_valid(&bad), "{bad}");
    }
}

fn tool<'a>(list: &'a Value, name: &str) -> &'a Value {
    list["tools"]
        .as_array()
        .unwrap()
        .iter()
        .find(|t| t["name"] == name)
        .unwrap_or_else(|| panic!("no tool {name}"))
}

#[test]
fn tool_schemas_compile_and_hold_the_safety_rules() {
    let list = load("testdata/mcp/tools-list.json");
    for t in list["tools"].as_array().unwrap() {
        jsonschema::validator_for(&t["inputSchema"])
            .unwrap_or_else(|e| panic!("{}: {e}", t["name"]));
        jsonschema::validator_for(&t["outputSchema"])
            .unwrap_or_else(|e| panic!("{}: {e}", t["name"]));
        assert_eq!(
            t["outputSchema"],
            load("schemas/mcp-tool-result.schema.json")
        );
    }

    let destroy =
        jsonschema::validator_for(&tool(&list, "destroy_sandbox")["inputSchema"]).unwrap();
    assert!(destroy.is_valid(&json!({"sandbox_id": "dcy1", "reason": "done", "confirm": true})));
    for bad in [
        json!({"sandbox_id": "dcy1", "reason": "done"}),
        json!({"sandbox_id": "dcy1", "reason": "done", "confirm": false}),
        json!({"sandbox_id": "dcy1", "reason": "", "confirm": true}),
        json!({"sandbox_id": "dcy1:destroy", "reason": "done", "confirm": true}),
    ] {
        assert!(!destroy.is_valid(&bad), "{bad}");
    }

    let create = jsonschema::validator_for(&tool(&list, "create_sandbox")["inputSchema"]).unwrap();
    assert!(create.is_valid(&json!({"catalogue_entry_id": "foiled/demo-app/1.0.0"})));
    assert!(!create.is_valid(&json!({
        "catalogue_entry_id": "foiled/demo-app/1.0.0",
        "lifetime_seconds": McpConfig::default().limits.max_lifetime_seconds + 1,
    })));

    let events = jsonschema::validator_for(&tool(&list, "get_events")["inputSchema"]).unwrap();
    assert!(events.is_valid(&json!({"sandbox_id": "dcy1"})));
    assert!(!events.is_valid(&json!({})));
    assert!(!events.is_valid(&json!({"sandbox_id": "a", "attempt_id": "b"})));
}
