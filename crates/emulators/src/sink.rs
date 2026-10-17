//! The `EventSink`: emulator observations in, capture envelopes out (#9).
//!
//! An emulator calls [`EventSink::emit`] for every command, request or hook.
//! The sink fills in the decoy context, a timestamp and an event id, enforces
//! the 16 KB envelope cap, and queues the envelope without blocking. When
//! the queue is full the event is dropped and counted: a flood must never
//! stall the protocol loop. [`write_jsonl`] drains the queue into the JSON
//! lines file the host agent tails (ADR 0002), which stamps the fields a
//! decoy may not set and ships the envelopes.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use foiled_core::capture::{CaptureEvent, Channel, Endpoint, HookEvent, MAX_EVENT_BYTES, Severity};
use foiled_core::catalogue::DecoyKind;
use serde_json::{Map, Value};
use tokio::io::{AsyncWrite, AsyncWriteExt};
use tokio::sync::mpsc;

use crate::util::Rng;

/// Who the events are about. The host agent overwrites these with what it
/// knows; the emulator fills them so envelopes are valid on their own.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SinkContext {
    pub decoy_id: String,
    pub catalogue_id: String,
    pub generation: Option<u32>,
    /// Event ids are `<id_prefix>-<sequence>`. Random per start by default,
    /// so ids stay unique across restarts; tests pin it.
    pub id_prefix: String,
}

impl SinkContext {
    pub fn new(decoy_id: &str, catalogue_id: &str) -> Self {
        SinkContext {
            decoy_id: decoy_id.to_string(),
            catalogue_id: catalogue_id.to_string(),
            generation: None,
            id_prefix: Rng::from_entropy().hex(16),
        }
    }

    pub fn with_id_prefix(mut self, prefix: &str) -> Self {
        self.id_prefix = prefix.to_string();
        self
    }

    pub fn with_generation(mut self, generation: u32) -> Self {
        self.generation = Some(generation);
        self
    }
}

/// One observation, before the sink adds context.
#[derive(Debug, Clone, PartialEq)]
pub struct Event {
    pub channel: Channel,
    pub severity: Severity,
    pub src: Endpoint,
    pub dst: Option<Endpoint>,
    pub data: Map<String, Value>,
    pub hook: Option<HookEvent>,
}

impl Event {
    /// An `application` event for one command or request on a connection.
    pub fn application(
        peer: SocketAddr,
        local: SocketAddr,
        severity: Severity,
        data: Map<String, Value>,
    ) -> Self {
        Event {
            channel: Channel::Application,
            severity,
            src: endpoint(peer),
            dst: Some(endpoint(local)),
            data,
            hook: None,
        }
    }

    /// A `hook` event (#32) for a profile hook point that fired.
    pub fn hook(
        peer: SocketAddr,
        local: SocketAddr,
        severity: Severity,
        hook: HookEvent,
        data: Map<String, Value>,
    ) -> Self {
        Event {
            channel: Channel::Hook,
            severity,
            src: endpoint(peer),
            dst: Some(endpoint(local)),
            data,
            hook: Some(hook),
        }
    }
}

/// The peer address as an envelope endpoint. IPv4-mapped IPv6 addresses
/// are shown as plain IPv4.
pub fn endpoint(addr: SocketAddr) -> Endpoint {
    Endpoint {
        ip: addr.ip().to_canonical().to_string(),
        port: Some(addr.port()),
    }
}

pub fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

struct Inner {
    ctx: SinkContext,
    tx: mpsc::Sender<CaptureEvent>,
    seq: AtomicU64,
    dropped: AtomicU64,
}

/// Cheap to clone; every session holds one.
#[derive(Clone)]
pub struct EventSink {
    inner: Arc<Inner>,
}

impl std::fmt::Debug for EventSink {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EventSink")
            .field("ctx", &self.inner.ctx)
            .field("dropped", &self.dropped())
            .finish()
    }
}

impl EventSink {
    /// A sink with a bounded queue of `capacity` envelopes.
    pub fn new(ctx: SinkContext, capacity: usize) -> (Self, mpsc::Receiver<CaptureEvent>) {
        let (tx, rx) = mpsc::channel(capacity.max(1));
        let sink = EventSink {
            inner: Arc::new(Inner {
                ctx,
                tx,
                seq: AtomicU64::new(0),
                dropped: AtomicU64::new(0),
            }),
        };
        (sink, rx)
    }

    pub fn context(&self) -> &SinkContext {
        &self.inner.ctx
    }

    /// Build the envelope for `ev` at `ts_ms` without queueing it.
    pub fn build(&self, ev: Event, ts_ms: i64) -> CaptureEvent {
        let ctx = &self.inner.ctx;
        let seq = self.inner.seq.fetch_add(1, Ordering::Relaxed) + 1;
        let mut out = CaptureEvent {
            event_id: format!("{}-{seq:08x}", ctx.id_prefix),
            ts: ts_ms,
            decoy_id: ctx.decoy_id.clone(),
            catalogue_id: ctx.catalogue_id.clone(),
            decoy_kind: DecoyKind::Emulation,
            generation: ctx.generation,
            channel: ev.channel,
            severity: ev.severity,
            src: ev.src,
            dst: ev.dst,
            payload_ref: None,
            attempt_id: None,
            source: None,
            tenant_id: None,
            hook: ev.hook,
            data: ev.data,
        };
        fit(&mut out);
        out
    }

    /// Queue an envelope for `ev`. Returns its event id, or `None` when the
    /// queue was full or closed and the event was dropped.
    pub fn emit(&self, ev: Event) -> Option<String> {
        let env = self.build(ev, now_ms());
        let id = env.event_id.clone();
        match self.inner.tx.try_send(env) {
            Ok(()) => Some(id),
            Err(_) => {
                self.inner.dropped.fetch_add(1, Ordering::Relaxed);
                None
            }
        }
    }

    /// Events dropped because the queue was full or closed.
    pub fn dropped(&self) -> u64 {
        self.inner.dropped.load(Ordering::Relaxed)
    }
}

/// Keep an envelope under [`MAX_EVENT_BYTES`]. Emulators clip their own
/// fields; this is the backstop. Large `data` values are dropped and the
/// envelope is marked `truncated`.
fn fit(ev: &mut CaptureEvent) {
    let size = |e: &CaptureEvent| serde_json::to_vec(e).map(|v| v.len()).unwrap_or(usize::MAX);
    if size(ev) <= MAX_EVENT_BYTES {
        return;
    }
    ev.data.retain(|_, v| {
        serde_json::to_vec(v)
            .map(|b| b.len() <= 256)
            .unwrap_or(false)
    });
    ev.data.insert("truncated".into(), Value::Bool(true));
    if size(ev) > MAX_EVENT_BYTES {
        ev.data = Map::new();
        ev.data.insert("truncated".into(), Value::Bool(true));
    }
    let too_big = size(ev) > MAX_EVENT_BYTES;
    if let Some(h) = ev.hook.as_mut()
        && too_big
    {
        h.cmd_lines.clear();
        h.file_writes.clear();
        h.implant_refs.clear();
        h.notes = None;
    }
}

/// Write queued envelopes as JSON lines until every sender is gone.
/// Returns the number of lines written.
pub async fn write_jsonl<W: AsyncWrite + Unpin>(
    mut rx: mpsc::Receiver<CaptureEvent>,
    mut out: W,
) -> std::io::Result<u64> {
    let mut n = 0;
    while let Some(ev) = rx.recv().await {
        let mut line = serde_json::to_vec(&ev).map_err(std::io::Error::other)?;
        line.push(b'\n');
        out.write_all(&line).await?;
        n += 1;
    }
    out.flush().await?;
    Ok(n)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn addr(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    fn data(v: Value) -> Map<String, Value> {
        v.as_object().unwrap().clone()
    }

    fn sink(capacity: usize) -> (EventSink, mpsc::Receiver<CaptureEvent>) {
        EventSink::new(
            SinkContext::new("dcy-redis-1", "emulator/redis/7.0").with_id_prefix("t"),
            capacity,
        )
    }

    #[test]
    fn builds_valid_envelopes_with_sequential_ids() {
        let (s, _rx) = sink(4);
        let ev = Event::application(
            addr("[::ffff:198.51.100.23]:40001"),
            addr("10.85.1.10:6379"),
            Severity::Medium,
            data(json!({"protocol": "redis", "command": "PING"})),
        );
        let a = s.build(ev.clone(), now_ms());
        let b = s.build(ev, now_ms());
        assert_eq!(a.event_id, "t-00000001");
        assert_eq!(b.event_id, "t-00000002");
        assert_eq!(a.src.ip, "198.51.100.23");
        assert_eq!(a.decoy_kind, DecoyKind::Emulation);
        assert!(
            a.problems(now_ms()).is_empty(),
            "{:?}",
            a.problems(now_ms())
        );
    }

    #[test]
    fn oversized_data_is_cut_to_fit() {
        let (s, _rx) = sink(4);
        let ev = Event::application(
            addr("203.0.113.7:1234"),
            addr("10.85.1.2:80"),
            Severity::Info,
            data(json!({"method": "GET", "blob": "x".repeat(MAX_EVENT_BYTES * 2)})),
        );
        let env = s.build(ev, now_ms());
        assert!(env.problems(now_ms()).is_empty());
        assert_eq!(env.data["truncated"], json!(true));
        assert_eq!(env.data["method"], json!("GET"));
        assert!(!env.data.contains_key("blob"));
    }

    #[tokio::test]
    async fn full_queue_drops_and_counts_instead_of_blocking() {
        let (s, mut rx) = sink(1);
        let ev = Event::application(
            addr("203.0.113.7:1234"),
            addr("10.85.1.2:80"),
            Severity::Info,
            Map::new(),
        );
        assert!(s.emit(ev.clone()).is_some());
        assert!(s.emit(ev).is_none());
        assert_eq!(s.dropped(), 1);
        assert!(rx.recv().await.is_some());
    }

    #[tokio::test]
    async fn jsonl_writer_emits_one_line_per_envelope() {
        let (s, rx) = sink(8);
        for _ in 0..3 {
            s.emit(Event::application(
                addr("203.0.113.7:1234"),
                addr("10.85.1.2:80"),
                Severity::Info,
                data(json!({"protocol": "http"})),
            ));
        }
        drop(s);
        let mut out = Vec::new();
        assert_eq!(write_jsonl(rx, &mut out).await.unwrap(), 3);
        let text = String::from_utf8(out).unwrap();
        for line in text.lines() {
            let ev: CaptureEvent = serde_json::from_str(line).unwrap();
            assert!(ev.problems(now_ms()).is_empty());
        }
        assert_eq!(text.lines().count(), 3);
    }
}
