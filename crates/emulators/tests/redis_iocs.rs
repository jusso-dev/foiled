//! The IOC fixture `testdata/iocs/redis-emulator.input.json` is the Redis
//! emulator's real output for a credential-heavy session, with only the
//! volatile parts (ids, times, ports, session) pinned. If the emulator's
//! event shape changes, this test fails until the fixture is regenerated
//! with FOILED_BLESS=1, so IOC extraction (#34) is always tested against
//! what the emulator really emits.

mod common;

use foiled_core::attempt::{DEFAULT_IDLE_GAP_MS, ExtraSignals, build};
use foiled_core::capture::{CaptureEvent, Endpoint, Source, SourceKind};
use foiled_core::confidence::ConfidenceConfig;
use foiled_core::ioc::{ExtractOptions, IocType, extract};
use foiled_emulators::Emulator;
use foiled_emulators::redis::RedisEmulator;
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

const T0: i64 = 1_792_285_500_000;
const PASSWORD: &str = "hunter2";

fn resp(parts: &[&str]) -> Vec<u8> {
    let mut out = format!("*{}\r\n", parts.len()).into_bytes();
    for p in parts {
        out.extend(format!("${}\r\n{p}\r\n", p.len()).into_bytes());
    }
    out
}

/// Pin what changes from run to run; keep everything the emulator chose.
fn pin(events: Vec<CaptureEvent>) -> Vec<CaptureEvent> {
    events
        .into_iter()
        .enumerate()
        .map(|(i, mut e)| {
            e.event_id = format!("rds-{:02}", i + 1);
            e.ts = T0 + 1000 * i as i64;
            e.decoy_id = "dcy-redis-1".into();
            e.src = Endpoint {
                ip: "198.51.100.23".into(),
                port: Some(40001),
            };
            e.dst = Some(Endpoint {
                ip: "10.85.1.10".into(),
                port: Some(6379),
            });
            e.tenant_id = Some("t1".into());
            e.source = Some(Source {
                kind: SourceKind::Host,
                id: "host-1".into(),
            });
            if e.data.contains_key("session") {
                e.data.insert("session".into(), json!("s1"));
            }
            if let Some(h) = e.hook.as_mut() {
                h.t_offset_ms = 1000 * i as u64;
            }
            e
        })
        .collect()
}

#[tokio::test]
async fn redis_fixture_is_real_emulator_output_and_extracts_without_secrets() {
    let mut emu = RedisEmulator::new();
    let (addr, mut rx) = common::start(&mut emu, &common::rendered("redis-7.0")).await;
    let mut s = TcpStream::connect(addr).await.unwrap();
    let mut req = Vec::new();
    for c in [
        &["AUTH", "default", PASSWORD][..],
        &["HELLO", "3", "AUTH", "default", PASSWORD],
        &["CONFIG", "SET", "dir", "/var/spool/cron"],
        &["CONFIG", "SET", "dbfilename", "root"],
        &["MODULE", "LOAD", "/tmp/exp.so"],
        &[
            "MIGRATE",
            "192.0.2.10",
            "6379",
            "k",
            "0",
            "5000",
            "AUTH2",
            "default",
            PASSWORD,
        ],
        &["CONFIG", "SET", "requirepass", PASSWORD],
    ] {
        req.extend(resp(c));
    }
    req.extend_from_slice(b"QUIT\r\n");
    s.write_all(&req).await.unwrap();
    let mut sink = Vec::new();
    let _ = tokio::time::timeout(std::time::Duration::from_secs(5), s.read_to_end(&mut sink)).await;
    let events = pin(common::collect(&mut rx, 64).await);
    emu.stop().await;
    assert!(events.len() >= 8, "{} events", events.len());

    // The emulator masks credentials before it logs them (#16): the
    // password appears nowhere in the events, only its hash and length.
    let text = serde_json::to_string(&events).unwrap();
    assert!(!text.contains(PASSWORD), "{text}");
    assert_eq!(
        events
            .iter()
            .filter(|e| e.data.contains_key("redacted_args"))
            .count(),
        4,
        "AUTH, HELLO, MIGRATE and CONFIG SET requirepass"
    );

    let path = common::repo_root().join("testdata/iocs/redis-emulator.input.json");
    let got = json!({
        "description": "Real Redis emulator output (crates/emulators/tests/redis_iocs.rs) for a session that authenticates, sends HELLO AUTH and MIGRATE AUTH2 with a password, rewrites the persistence config, loads a module and sets requirepass. The emulator masks the password in args, error and config_set and keeps only its hash in redacted_args. Ids, times, addresses, ports and the session are pinned; everything else is as emitted.",
        "events": events,
    });
    if std::env::var("FOILED_BLESS").is_ok() {
        std::fs::write(&path, serde_json::to_string_pretty(&got).unwrap() + "\n").unwrap();
    }
    let expected: Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
    assert_eq!(
        got,
        expected,
        "{} differs from the emulator's output; run with FOILED_BLESS=1",
        path.display()
    );

    // Extraction over the real shape: secrets never reach an IOC, and the
    // fingerprint uses the subcommand the emulator logs apart.
    let attempts = build(&events, DEFAULT_IDLE_GAP_MS, &ExtraSignals::new());
    let x = extract(
        &attempts,
        &events,
        &ConfidenceConfig::default(),
        ExtractOptions::default(),
    );
    let all = serde_json::to_string(&x.iocs).unwrap();
    assert!(!all.contains(PASSWORD), "{all}");
    let subs: Vec<&str> = x
        .iocs
        .iter()
        .filter(|i| i.ioc_type == IocType::RequestSubstring)
        .map(|i| i.value.as_str())
        .collect();
    for want in [
        "HELLO 3 AUTH REDACTED REDACTED",
        "CONFIG SET requirepass REDACTED",
        "CONFIG SET dir /var/spool/cron",
        "MIGRATE 192.0.2.10 6379 k 0 5000 AUTH2 REDACTED REDACTED",
    ] {
        assert!(subs.contains(&want), "{want} not in {subs:?}");
    }
    let steps = x
        .iocs
        .iter()
        .find_map(|i| i.fingerprint.clone())
        .expect("hooks fired, so the attempt has a fingerprint")
        .steps;
    assert!(steps.contains(&"cmd CONFIG SET".to_string()), "{steps:?}");
    assert!(steps.contains(&"cmd MODULE LOAD".to_string()), "{steps:?}");
    assert!(
        steps.iter().all(|s| !s.contains("REQUIREPASS")),
        "{steps:?}"
    );
}
