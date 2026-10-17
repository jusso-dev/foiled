//! Helpers shared by the integration tests.
#![allow(dead_code)]

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use foiled_core::capture::CaptureEvent;
use foiled_emulators::{Emulator, EventSink, Jitter, Profile, SinkContext};
use tokio::net::TcpListener;
use tokio::sync::mpsc;

pub fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

pub fn now_ms() -> i64 {
    foiled_emulators::sink::now_ms()
}

/// A shipped profile with canaries rendered as `cnry-<name>` and no jitter.
pub fn rendered(id: &str) -> Profile {
    let p = Profile::builtin(id).expect("shipped profile");
    let values: BTreeMap<String, String> = p
        .canaries
        .iter()
        .map(|c| (c.name.clone(), format!("cnry-{}", c.name)))
        .collect();
    let mut p = p.render(&values).expect("renders");
    p.jitter = Jitter::NONE;
    p
}

pub fn sink(catalogue_id: &str) -> (EventSink, mpsc::Receiver<CaptureEvent>) {
    EventSink::new(
        SinkContext::new("dcy-test-1", catalogue_id).with_id_prefix("evt"),
        1024,
    )
}

/// Start `emu` with `profile` on a loopback port.
pub async fn start(
    emu: &mut dyn Emulator,
    profile: &Profile,
) -> (SocketAddr, mpsc::Receiver<CaptureEvent>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (sink, rx) = sink(&profile.catalogue_ids[0]);
    emu.start(profile, listener, sink).unwrap();
    (addr, rx)
}

/// Receive events until `n` arrive or a second passes with none.
pub async fn collect(rx: &mut mpsc::Receiver<CaptureEvent>, n: usize) -> Vec<CaptureEvent> {
    let mut out = Vec::new();
    while out.len() < n {
        match tokio::time::timeout(Duration::from_secs(2), rx.recv()).await {
            Ok(Some(ev)) => out.push(ev),
            _ => break,
        }
    }
    out
}

/// Every envelope must pass the capture-layer checks.
pub fn assert_valid(events: &[CaptureEvent]) {
    for ev in events {
        let problems = ev.problems(now_ms());
        assert!(problems.is_empty(), "{}: {problems:?}", ev.event_id);
        // And round-trip through JSON with unknown fields rejected.
        let back: CaptureEvent = serde_json::from_str(&serde_json::to_string(ev).unwrap()).unwrap();
        assert_eq!(&back, ev);
    }
}

/// Words that must never reach an attacker (FR-01).
pub const TELLS: &[&str] = &[
    "honeypot", "honey", "foiled", "decoy", "sandbox", "emulat", "trap", "cowrie", "canary",
];

pub fn assert_no_tells(text: &str, what: &str) {
    let lower = text.to_ascii_lowercase();
    for t in TELLS {
        assert!(!lower.contains(t), "{what} contains '{t}'");
    }
}
