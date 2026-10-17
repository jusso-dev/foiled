//! Bundle `catalogue/entries/**` into the Worker as one JSON array.
//!
//! The catalogue is reviewed data in git, so each deploy serves exactly the
//! entries that were merged. `foiled-lint` validates the files in CI; this
//! script only converts YAML to JSON and sorts by id.

use std::path::Path;

fn main() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../catalogue/entries");
    println!("cargo:rerun-if-changed={}", dir.display());
    let mut entries: Vec<serde_json::Value> = Vec::new();
    if dir.exists() {
        for entry in walkdir::WalkDir::new(&dir).sort_by_file_name() {
            let entry = entry.expect("walk catalogue");
            let path = entry.path();
            println!("cargo:rerun-if-changed={}", path.display());
            let ext = path.extension().and_then(|e| e.to_str());
            if !entry.file_type().is_file() || !matches!(ext, Some("yaml" | "yml" | "json")) {
                continue;
            }
            let text = std::fs::read_to_string(path).expect("read entry");
            let value: serde_json::Value = if ext == Some("json") {
                serde_json::from_str(&text).expect("parse JSON entry")
            } else {
                serde_yaml_ng::from_str(&text).expect("parse YAML entry")
            };
            entries.push(value);
        }
    }
    entries.sort_by(|a, b| a["id"].as_str().cmp(&b["id"].as_str()));
    let out = Path::new(&std::env::var("OUT_DIR").unwrap()).join("catalogue.json");
    std::fs::write(out, serde_json::to_vec(&entries).unwrap()).unwrap();
}
