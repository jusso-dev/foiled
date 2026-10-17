//! Instrumentation hooks (#32): shipped manifests parse into the Rust type and
//! match their catalogue entries, and the demo exploit sequence in
//! `testdata/capture/demo-exploit-*.json` (hook trigger, then a file write,
//! then quarantine) yields ordered hook hits plus a quarantine reference.

use std::path::{Path, PathBuf};

use foiled_core::capture::{CaptureEvent, Channel, HookStage, PayloadRef};
use foiled_core::catalogue::CatalogueEntry;
use foiled_core::hooks::{HookKind, HookManifest, hook_hits};

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn demo_exploit_events() -> Vec<CaptureEvent> {
    let dir = root().join("testdata/capture");
    let mut paths: Vec<_> = std::fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with("demo-exploit-"))
        })
        .collect();
    paths.sort();
    paths
        .iter()
        .map(|p| serde_json::from_value(foiled_lint::load(p).unwrap()).unwrap())
        .collect()
}

#[test]
fn demo_exploit_yields_hook_hits_and_quarantine_ref() {
    let mut events = demo_exploit_events();
    assert_eq!(events.len(), 3);
    // Arrival order must not matter.
    events.reverse();

    let hits = hook_hits(&events);
    let got: Vec<_> = hits
        .iter()
        .map(|h| (h.hook_id.as_str(), h.stage, h.event_id.as_str()))
        .collect();
    assert_eq!(
        got,
        vec![
            (
                "demo-app.upload-path-traversal",
                HookStage::Trigger,
                "evt-demo-0011"
            ),
            (
                "demo-app.upload-path-traversal",
                HookStage::PostExploit,
                "evt-demo-0012"
            ),
        ]
    );
    assert!(
        hits.iter()
            .all(|h| h.cve_id.as_deref() == Some("FOILED-DEMO-0001"))
    );

    // The file write is recorded on the post-exploit hook.
    let post = events
        .iter()
        .find(|e| e.event_id == "evt-demo-0012")
        .and_then(|e| e.hook.as_ref())
        .unwrap();
    assert_eq!(post.file_writes, vec!["/tmp/x.sh".to_string()]);

    // The quarantine envelope, sent by the host at flush, carries a
    // payload_ref in the same attempt and names the written path and hook, so
    // attempt assembly (#25) can join it to the post-exploit hit.
    let quarantine = events
        .iter()
        .find(|e| e.channel == Channel::Quarantine)
        .unwrap();
    let qref = quarantine.payload_ref.as_deref().unwrap();
    let parsed = PayloadRef::parse(qref).unwrap();
    assert_eq!(parsed.channel, Channel::Quarantine);
    assert_eq!(parsed.attempt_id.as_deref(), Some("att-demo-1"));
    assert_eq!(
        quarantine.data["sha256"].as_str(),
        Some(parsed.sha256.as_str())
    );
    let guest_path = quarantine.data["guest_path"].as_str().unwrap();
    assert!(post.file_writes.iter().any(|p| p == guest_path));
    assert_eq!(
        quarantine.data["hook_id"].as_str(),
        Some("demo-app.upload-path-traversal")
    );
    assert_eq!(quarantine.data["executed"], serde_json::json!(false));
    assert!(
        events
            .iter()
            .all(|e| e.attempt_id.as_deref() == Some("att-demo-1"))
    );
}

#[test]
fn shipped_hook_manifests_parse_and_match_the_catalogue() {
    let dir = root().join("hooks");
    let mut seen = 0;
    for entry in std::fs::read_dir(&dir).unwrap() {
        let path = entry.unwrap().path();
        let m: HookManifest = serde_json::from_value(foiled_lint::load(&path).unwrap())
            .unwrap_or_else(|e| panic!("{}: {e}", path.display()));
        let stem = path.file_stem().unwrap().to_str().unwrap();
        assert_eq!(m.id, stem, "{}", path.display());
        assert!(m.redaction.inline_cap_bytes <= foiled_core::hooks::INLINE_SLICE_CAP);
        for cat in &m.catalogue_ids {
            let entry_path = root().join(format!("catalogue/entries/{cat}.yaml"));
            let entry: CatalogueEntry =
                serde_json::from_value(foiled_lint::load(&entry_path).unwrap()).unwrap();
            assert!(
                entry.instrumentation_hooks.contains(&m.id),
                "{cat} does not declare {}",
                m.id
            );
        }
        seen += 1;
    }
    assert!(seen >= 1);

    let demo: HookManifest = serde_json::from_value(
        foiled_lint::load(&dir.join("demo-app.upload-path-traversal.yaml")).unwrap(),
    )
    .unwrap();
    assert_eq!(demo.kind, HookKind::InProcess);
    assert_eq!(demo.cve_id.as_deref(), Some("FOILED-DEMO-0001"));
    assert_eq!(
        demo.stages,
        vec![HookStage::Trigger, HookStage::PostExploit]
    );
}
