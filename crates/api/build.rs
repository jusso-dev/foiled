//! Bundle reviewed repository data into the Worker as JSON:
//! - `catalogue/entries/**` (#5) as `catalogue.json`, sorted by id;
//! - `rules/attack/*.yaml` (#26) as `attack_rules.json`, sorted by id;
//! - `catalogue/{matchers,sequences,advisories}` (#12) as `matchers.json`,
//!   `sequences.json` and `advisories.json`;
//! - `configs/mcp.yaml` (#24) as `mcp_config.json`;
//! - `configs/retention.yaml` (#16) as `retention_config.json`;
//! - `configs/enrichment.yaml` (#11) as `enrichment_config.json`;
//! - `catalogue/actors/*.yaml` (#29) as `actor_reports.json`, sorted by id.
//!
//! Each deploy serves exactly what was merged. `foiled-lint` validates the
//! files in CI; this script only converts YAML to JSON.

use std::path::Path;

fn bundle(rel: &str, out_name: &str) {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join(rel);
    println!("cargo:rerun-if-changed={}", dir.display());
    let mut items: Vec<serde_json::Value> = Vec::new();
    if dir.exists() {
        for entry in walkdir::WalkDir::new(&dir).sort_by_file_name() {
            let entry = entry.expect("walk");
            let path = entry.path();
            println!("cargo:rerun-if-changed={}", path.display());
            let ext = path.extension().and_then(|e| e.to_str());
            if !entry.file_type().is_file() || !matches!(ext, Some("yaml" | "yml" | "json")) {
                continue;
            }
            let text = std::fs::read_to_string(path).expect("read");
            let value: serde_json::Value = if ext == Some("json") {
                serde_json::from_str(&text).expect("parse JSON")
            } else {
                serde_yaml_ng::from_str(&text).expect("parse YAML")
            };
            items.push(value);
        }
    }
    items.sort_by(|a, b| a["id"].as_str().cmp(&b["id"].as_str()));
    let out = Path::new(&std::env::var("OUT_DIR").unwrap()).join(out_name);
    std::fs::write(out, serde_json::to_vec(&items).unwrap()).unwrap();
}

/// Convert one YAML file to JSON.
fn bundle_file(rel: &str, out_name: &str) {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join(rel);
    println!("cargo:rerun-if-changed={}", path.display());
    let text = std::fs::read_to_string(&path).expect("read");
    let value: serde_json::Value = serde_yaml_ng::from_str(&text).expect("parse YAML");
    let out = Path::new(&std::env::var("OUT_DIR").unwrap()).join(out_name);
    std::fs::write(out, serde_json::to_vec(&value).unwrap()).unwrap();
}

fn main() {
    bundle("catalogue/entries", "catalogue.json");
    bundle("rules/attack", "attack_rules.json");
    bundle("catalogue/matchers", "matchers.json");
    bundle("catalogue/sequences", "sequences.json");
    bundle("catalogue/advisories", "advisories.json");
    bundle_file("configs/mcp.yaml", "mcp_config.json");
    bundle_file("configs/retention.yaml", "retention_config.json");
    bundle_file("configs/enrichment.yaml", "enrichment_config.json");
    bundle("catalogue/actors", "actor_reports.json");
}
