//! Plug-in contract (#30 validation): a plug-in starts on a listener it is
//! given, emits application envelopes through the sink, and stops cleanly:
//! the listener closes, every session ends and the sink is released.

mod common;

use std::time::Duration;

use foiled_core::capture::{Channel, Severity};
use foiled_emulators::{
    BoxFuture, Emulator, EmulatorError, Event, EventSink, Health, Profile, http_portal, redis,
};
use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;
use tokio::task::JoinHandle;

/// The smallest possible plug-in: answers one HTTP request per connection
/// and emits one application event for it.
#[derive(Default)]
struct FakePlugin {
    stop_tx: Option<oneshot::Sender<()>>,
    task: Option<JoinHandle<()>>,
    stopped: bool,
}

impl Emulator for FakePlugin {
    fn name(&self) -> &'static str {
        "fake"
    }

    fn profiles(&self) -> Vec<&'static str> {
        vec!["fake-1"]
    }

    fn start(
        &mut self,
        profile: &Profile,
        listener: TcpListener,
        sink: EventSink,
    ) -> Result<(), EmulatorError> {
        if profile.plugin != "fake" {
            return Err(EmulatorError::WrongPlugin {
                expected: "fake",
                got: profile.plugin.clone(),
            });
        }
        if self.task.is_some() || self.stopped {
            return Err(EmulatorError::AlreadyStarted);
        }
        let (tx, mut rx) = oneshot::channel();
        self.stop_tx = Some(tx);
        self.task = Some(tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = &mut rx => break,
                    accepted = listener.accept() => {
                        let Ok((mut s, peer)) = accepted else { continue };
                        let local = s.local_addr().unwrap();
                        let mut buf = [0u8; 1024];
                        let n = s.read(&mut buf).await.unwrap_or(0);
                        let line = String::from_utf8_lossy(&buf[..n]);
                        let path = line.split(' ').nth(1).unwrap_or("/").to_string();
                        let _ = s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok").await;
                        let data = json!({"protocol": "http", "method": "GET", "path": path, "status": 200});
                        sink.emit(Event::application(peer, local, Severity::Info, data.as_object().unwrap().clone()));
                    }
                }
            }
        }));
        Ok(())
    }

    fn stop(&mut self) -> BoxFuture<'_, ()> {
        Box::pin(async move {
            if let Some(tx) = self.stop_tx.take() {
                let _ = tx.send(());
            }
            if let Some(t) = self.task.take() {
                let _ = t.await;
                self.stopped = true;
            }
        })
    }

    fn health(&self) -> Health {
        match &self.task {
            Some(_) => Health::Serving { sessions: 0 },
            None if self.stopped => Health::Stopped,
            None => Health::NotStarted,
        }
    }
}

fn fake_profile() -> Profile {
    let mut p = common::rendered("portal-generic");
    p.plugin = "fake".into();
    p
}

/// Drive any plug-in through the contract. `probe` is a request that gets
/// a reply starting with `expect`.
async fn contract(emu: &mut dyn Emulator, profile: &Profile, probe: &[u8], expect: &[u8]) {
    assert_eq!(emu.health(), Health::NotStarted);
    let (addr, mut rx) = common::start(emu, profile).await;
    assert!(matches!(emu.health(), Health::Serving { .. }));

    let mut s = TcpStream::connect(addr).await.unwrap();
    s.write_all(probe).await.unwrap();
    let mut got = vec![0u8; expect.len()];
    tokio::time::timeout(Duration::from_secs(5), s.read_exact(&mut got))
        .await
        .expect("reply in time")
        .unwrap();
    assert_eq!(got, expect, "{}", String::from_utf8_lossy(&got));

    let events = common::collect(&mut rx, 1).await;
    assert_eq!(events.len(), 1, "one application event");
    let ev = &events[0];
    assert_eq!(ev.channel, Channel::Application);
    assert_eq!(ev.src.ip, "127.0.0.1");
    assert_eq!(ev.src.port, Some(s.local_addr().unwrap().port()));
    assert_eq!(ev.dst.as_ref().and_then(|d| d.port), Some(addr.port()));
    assert_eq!(ev.catalogue_id, profile.catalogue_ids[0]);
    common::assert_valid(&events);
    drop(s);

    tokio::time::timeout(Duration::from_secs(5), emu.stop())
        .await
        .expect("stops in time");
    assert_eq!(emu.health(), Health::Stopped);
    assert!(
        TcpStream::connect(addr).await.is_err(),
        "listener closed on stop"
    );
    // Every session has ended, so every sink clone is gone.
    assert!(
        tokio::time::timeout(Duration::from_secs(2), rx.recv())
            .await
            .expect("sink released")
            .is_none()
    );
    // Stopping twice is fine; restarting in place is not (ADR 0002).
    emu.stop().await;
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let (sink, _rx) = common::sink("x/y");
    assert!(matches!(
        emu.start(profile, listener, sink),
        Err(EmulatorError::AlreadyStarted)
    ));
}

#[tokio::test]
async fn fake_plugin_starts_emits_one_event_and_stops_cleanly() {
    let mut fake = FakePlugin::default();
    assert_eq!(fake.name(), "fake");
    contract(
        &mut fake,
        &fake_profile(),
        b"GET /contract HTTP/1.1\r\nHost: x\r\n\r\n",
        b"HTTP/1.1 200 OK\r\n",
    )
    .await;
}

#[tokio::test]
async fn redis_plugin_meets_the_contract() {
    let mut emu = redis::RedisEmulator::new();
    assert_eq!(emu.profiles(), vec!["redis-7.0"]);
    contract(
        &mut emu,
        &common::rendered("redis-7.0"),
        b"*1\r\n$4\r\nPING\r\n",
        b"+PONG\r\n",
    )
    .await;
}

#[tokio::test]
async fn http_portal_plugin_meets_the_contract() {
    let mut emu = http_portal::HttpPortalEmulator::new();
    assert_eq!(emu.profiles(), vec!["portal-generic"]);
    contract(
        &mut emu,
        &common::rendered("portal-generic"),
        b"GET /robots.txt HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nServer: nginx\r\n",
    )
    .await;
}

#[tokio::test]
async fn plugins_refuse_wrong_unrendered_or_invalid_profiles() {
    let bind = || async { TcpListener::bind("127.0.0.1:0").await.unwrap() };
    let (sink, _rx) = common::sink("emulator/redis/7.0");

    let mut emu = foiled_emulators::plugin("redis").unwrap();
    let portal = common::rendered("portal-generic");
    assert!(matches!(
        emu.start(&portal, bind().await, sink.clone()),
        Err(EmulatorError::WrongPlugin { .. })
    ));
    // Canary placeholders left in: refused.
    let raw = Profile::builtin("redis-7.0").unwrap();
    assert!(matches!(
        emu.start(&raw, bind().await, sink.clone()),
        Err(EmulatorError::Profile(_))
    ));
    let mut bad = common::rendered("redis-7.0");
    bad.redis.as_mut().unwrap().commands.push("EVAL".into());
    assert!(matches!(
        emu.start(&bad, bind().await, sink.clone()),
        Err(EmulatorError::Profile(_))
    ));
    assert_eq!(emu.health(), Health::NotStarted);
    assert!(foiled_emulators::plugin("nope").is_none());
}
