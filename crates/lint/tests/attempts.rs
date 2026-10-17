//! Golden test for attempt grouping (#25): `testdata/attempts/*.input.json`
//! holds capture envelopes; `testdata/attempts/expected/` holds the attempts
//! they must produce, one file per attempt. Expected files are also
//! validated against `schemas/attempt.schema.json` by the repository lint.
//!
//! To regenerate after an intended change, run with FOILED_BLESS=1 and
//! review the diff.

use std::path::Path;

use foiled_core::attempt::{Attempt, DEFAULT_IDLE_GAP_MS, ExtraSignals, build};
use foiled_core::capture::CaptureEvent;

#[test]
fn demo_fleet_groups_into_the_expected_attempts() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../testdata/attempts");
    let raw: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(root.join("demo-fleet.input.json")).unwrap())
            .unwrap();
    let events: Vec<CaptureEvent> = serde_json::from_value(raw["events"].clone()).unwrap();
    for e in &events {
        assert!(e.problems(1_800_000_000_000).is_empty(), "{}", e.event_id);
    }
    let got = build(&events, DEFAULT_IDLE_GAP_MS, &ExtraSignals::new());
    let dir = root.join("expected");
    if std::env::var("FOILED_BLESS").is_ok() {
        for (i, a) in got.iter().enumerate() {
            let path = dir.join(format!("demo-fleet-{i}.json"));
            std::fs::write(path, serde_json::to_string_pretty(a).unwrap() + "\n").unwrap();
        }
    }
    let mut files: Vec<_> = std::fs::read_dir(&dir)
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| {
            p.file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with("demo-fleet-")
        })
        .collect();
    files.sort();
    let expected: Vec<Attempt> = files
        .iter()
        .map(|p| serde_json::from_str(&std::fs::read_to_string(p).unwrap()).unwrap())
        .collect();
    assert_eq!(got, expected);
}
