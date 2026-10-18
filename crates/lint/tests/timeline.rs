//! Golden test for the attempt timeline (#10): the demo fleet in
//! `testdata/attempts/demo-fleet.input.json` is grouped into attempts (#25)
//! and each attempt's timeline must match `testdata/attempts/timeline/`,
//! as JSON and as the plain-text rendering. The JSON files are also
//! validated against `schemas/attempt-timeline.schema.json` by the lint.
//!
//! To regenerate after an intended change, run with FOILED_BLESS=1 and
//! review the diff.

use std::path::Path;

use foiled_core::attempt::{DEFAULT_IDLE_GAP_MS, ExtraSignals, build};
use foiled_core::capture::CaptureEvent;
use foiled_core::timeline::{Timeline, build_timeline, render_text};

#[test]
fn demo_fleet_timelines_match_the_golden_files() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../testdata/attempts");
    let raw: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(root.join("demo-fleet.input.json")).unwrap())
            .unwrap();
    let events: Vec<CaptureEvent> = serde_json::from_value(raw["events"].clone()).unwrap();
    let attempts = build(&events, DEFAULT_IDLE_GAP_MS, &ExtraSignals::new());
    let dir = root.join("timeline");
    let bless = std::env::var("FOILED_BLESS").is_ok();
    if bless {
        std::fs::create_dir_all(&dir).unwrap();
    }
    for (i, a) in attempts.iter().enumerate() {
        let got = build_timeline(a, &events);
        let json_path = dir.join(format!("demo-fleet-{i}.json"));
        let text_path = dir.join(format!("demo-fleet-{i}.txt"));
        if bless {
            std::fs::write(
                &json_path,
                serde_json::to_string_pretty(&got).unwrap() + "\n",
            )
            .unwrap();
            std::fs::write(&text_path, render_text(&got)).unwrap();
        }
        let expected: Timeline =
            serde_json::from_str(&std::fs::read_to_string(&json_path).unwrap()).unwrap();
        assert_eq!(got, expected, "{}", json_path.display());
        assert_eq!(
            render_text(&got),
            std::fs::read_to_string(&text_path).unwrap(),
            "{}",
            text_path.display()
        );
    }
    let files = std::fs::read_dir(&dir).unwrap().count();
    assert_eq!(files, attempts.len() * 2, "no stale golden files");
}
