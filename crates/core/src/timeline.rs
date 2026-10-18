//! Attempt timeline (#10): the ordered, read-only view of what one attempt
//! did, built from the attempt (#25) and its capture events. Grouping lives
//! in `attempt`; this module only orders, summarises and renders.
//!
//! Summaries are built from known envelope fields and escaped, so attacker
//! text can never inject control characters or line breaks into the text
//! rendering. See `docs/attempt-timeline.md`.

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::attempt::{Attempt, AttemptState, StateSignal};
use crate::capture::{CaptureEvent, Channel, Severity};
use crate::sigv4::amz_date;

/// Longest summary kept, in characters, before `…` is appended.
pub const MAX_SUMMARY_CHARS: usize = 160;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StateMark {
    pub state: AttemptState,
    pub signal: StateSignal,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TimelineEntry {
    /// 1-based position in the timeline.
    pub seq: u32,
    pub ts: i64,
    /// Milliseconds since the attempt's first event.
    pub t_offset_ms: i64,
    pub channel: Channel,
    pub severity: Severity,
    /// One escaped line describing the event.
    pub summary: String,
    /// Set when the attempt entered a new state at this event.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state_change: Option<StateMark>,
    /// The full capture envelope, unchanged.
    pub event: CaptureEvent,
}

/// Where and how to cut a pcap slice for this attempt (MVP capture layout,
/// `docs/attempt-timeline.md`). Foiled never replays traffic.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PcapExtract {
    /// BPF filter for `tcpdump -r ... -w ...`.
    pub filter: String,
    /// Window to cut, Unix ms, padded by `PCAP_PAD_MS` on both sides.
    pub from_ms: i64,
    pub to_ms: i64,
    /// Ring files on the host, relative to the capture volume.
    pub source_glob: String,
    /// Where the slice is written, relative to the capture volume.
    pub output_path: String,
}

pub const PCAP_PAD_MS: i64 = 5_000;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Timeline {
    pub attempt_id: String,
    pub decoy_id: String,
    pub catalogue_id: String,
    pub src: String,
    pub first_seen: i64,
    pub last_seen: i64,
    pub state: AttemptState,
    pub entries: Vec<TimelineEntry>,
    pub payload_refs: Vec<String>,
    pub ioc_refs: Vec<String>,
    pub pcap: PcapExtract,
    /// Caveats for the reader, such as encrypted traffic without keys.
    pub notes: Vec<String>,
    /// Event ids the attempt lists but that were not supplied (for example
    /// purged by retention, #16).
    pub missing_event_ids: Vec<String>,
}

/// Escape control, bidi and line-break characters and cap the length.
pub fn printable(s: &str) -> String {
    let mut out = String::new();
    for (n, c) in s.chars().enumerate() {
        if n >= MAX_SUMMARY_CHARS {
            out.push('…');
            break;
        }
        let bidi = matches!(c, '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}' | '\u{200E}' | '\u{200F}');
        if c.is_control() || bidi {
            out.push_str(&c.escape_unicode().to_string());
        } else {
            out.push(c);
        }
    }
    out
}

fn text(v: Option<&Value>) -> Option<String> {
    match v? {
        Value::String(s) => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        Value::Bool(b) => Some(b.to_string()),
        Value::Array(a) => Some(
            a.iter()
                .filter_map(|x| text(Some(x)))
                .collect::<Vec<_>>()
                .join(" "),
        ),
        _ => None,
    }
}

fn endpoint(e: &Option<crate::capture::Endpoint>) -> String {
    match e {
        Some(d) => match d.port {
            Some(p) => format!("{}:{p}", d.ip),
            None => d.ip.clone(),
        },
        None => "?".into(),
    }
}

/// One line for an event, from known fields only.
pub fn summarise(e: &CaptureEvent) -> String {
    let d = |k: &str| text(e.data.get(k));
    let s = match e.channel {
        Channel::Application => match (d("method"), d("path"), d("command")) {
            (Some(m), Some(p), _) => match d("status") {
                Some(st) => format!("{m} {p} -> {st}"),
                None => format!("{m} {p}"),
            },
            (_, _, Some(c)) => match d("args") {
                Some(a) => format!("{c} {a}"),
                None => c,
            },
            _ => format!("application event ({} fields)", e.data.len()),
        },
        Channel::Hook => match &e.hook {
            Some(h) => {
                let stage = serde_json::to_value(h.stage)
                    .ok()
                    .and_then(|v| v.as_str().map(str::to_string))
                    .unwrap_or_default();
                match &h.cve_id {
                    Some(cve) => format!("hook {} fired at {stage} ({cve})", h.hook_id),
                    None => format!("hook {} fired at {stage}", h.hook_id),
                }
            }
            None => "hook event without hook block".into(),
        },
        Channel::Egress => format!(
            "egress to {} ({})",
            endpoint(&e.dst),
            d("verdict").unwrap_or_else(|| "no verdict".into())
        ),
        Channel::Dns => format!(
            "dns query {}",
            d("qname")
                .or_else(|| d("query"))
                .unwrap_or_else(|| "?".into())
        ),
        Channel::Filesystem => format!(
            "file {} {}",
            d("op").unwrap_or_else(|| "change".into()),
            d("path").unwrap_or_else(|| "?".into())
        ),
        Channel::Process => format!(
            "exec {}",
            d("cmdline")
                .or_else(|| d("argv"))
                .unwrap_or_else(|| "?".into())
        ),
        Channel::Quarantine => format!(
            "quarantined {}",
            d("sha256")
                .or_else(|| d("path"))
                .unwrap_or_else(|| "payload".into())
        ),
        Channel::Network => format!(
            "{} {} -> {}",
            d("proto").unwrap_or_else(|| "flow".into()),
            endpoint(&Some(e.src.clone())),
            endpoint(&e.dst)
        ),
    };
    printable(&s)
}

fn looks_encrypted(e: &CaptureEvent) -> bool {
    e.data.get("tls").and_then(Value::as_bool) == Some(true)
        || e.dst.as_ref().and_then(|d| d.port) == Some(443)
}

/// Build the timeline for one attempt. `events` may contain other events;
/// only the attempt's are used. Order is time, then event id.
pub fn build_timeline(attempt: &Attempt, events: &[CaptureEvent]) -> Timeline {
    let mut mine: Vec<&CaptureEvent> = events
        .iter()
        .filter(|e| attempt.event_ids.contains(&e.event_id))
        .collect();
    mine.sort_by(|a, b| (a.ts, &a.event_id).cmp(&(b.ts, &b.event_id)));
    mine.dedup_by(|a, b| a.event_id == b.event_id);

    let entries: Vec<TimelineEntry> = mine
        .iter()
        .enumerate()
        .map(|(i, e)| TimelineEntry {
            seq: i as u32 + 1,
            ts: e.ts,
            t_offset_ms: e.ts - attempt.first_seen,
            channel: e.channel,
            severity: e.severity,
            summary: summarise(e),
            state_change: attempt
                .state_history
                .iter()
                .find(|c| c.event_id == e.event_id)
                .map(|c| StateMark {
                    state: c.state,
                    signal: c.signal,
                }),
            event: (*e).clone(),
        })
        .collect();

    let missing_event_ids: Vec<String> = attempt
        .event_ids
        .iter()
        .filter(|id| !mine.iter().any(|e| &e.event_id == *id))
        .cloned()
        .collect();

    let mut notes = Vec::new();
    if mine.iter().any(|e| looks_encrypted(e)) {
        notes.push(
            "Some traffic was TLS. Without session keys the pcap shows handshakes and sizes, not \
             HTTP bodies; request details come only from what the decoy itself logged."
                .to_string(),
        );
    }
    if !missing_event_ids.is_empty() {
        notes.push(format!(
            "{} event(s) of this attempt are no longer stored (retention, #16).",
            missing_event_ids.len()
        ));
    }

    Timeline {
        attempt_id: attempt.attempt_id.clone(),
        decoy_id: attempt.decoy_id.clone(),
        catalogue_id: attempt.catalogue_id.clone(),
        src: attempt.src.clone(),
        first_seen: attempt.first_seen,
        last_seen: attempt.last_seen,
        state: attempt.state,
        entries,
        payload_refs: attempt.payload_refs.clone(),
        ioc_refs: attempt.ioc_refs.clone(),
        pcap: PcapExtract {
            filter: format!("host {}", attempt.src),
            from_ms: attempt.first_seen - PCAP_PAD_MS,
            to_ms: attempt.last_seen + PCAP_PAD_MS,
            source_glob: format!("pcap/{}/ring*.pcap*", attempt.decoy_id),
            output_path: format!("attempts/{}/attempt.pcap", attempt.attempt_id),
        },
        notes,
        missing_event_ids,
    }
}

/// `YYYY-MM-DDTHH:MM:SSZ` for Unix ms.
pub fn iso(unix_ms: i64) -> String {
    let a = amz_date(unix_ms);
    format!(
        "{}-{}-{}T{}:{}:{}Z",
        &a[0..4],
        &a[4..6],
        &a[6..8],
        &a[9..11],
        &a[11..13],
        &a[13..15]
    )
}

fn label<T: Serialize>(v: &T) -> String {
    serde_json::to_value(v)
        .ok()
        .and_then(|v| v.as_str().map(str::to_string))
        .unwrap_or_default()
}

/// Plain-text rendering for terminals and tickets.
pub fn render_text(t: &Timeline) -> String {
    let mut out = format!(
        "attempt {}  {} -> {} ({})\nstate {}  first seen {}  last seen {}  {} event(s)\n",
        t.attempt_id,
        printable(&t.src),
        t.decoy_id,
        t.catalogue_id,
        label(&t.state),
        iso(t.first_seen),
        iso(t.last_seen),
        t.entries.len()
    );
    for e in &t.entries {
        out.push_str(&format!(
            "{:>4}  +{:>4}.{:03}s  {:<11} {:<8} {}\n",
            e.seq,
            e.t_offset_ms / 1000,
            e.t_offset_ms % 1000,
            label(&e.channel),
            label(&e.severity),
            e.summary
        ));
        if let Some(m) = &e.state_change {
            out.push_str(&format!(
                "                   state -> {} ({})\n",
                label(&m.state),
                label(&m.signal)
            ));
        }
    }
    for r in &t.payload_refs {
        out.push_str(&format!("payload {r}\n"));
    }
    for r in &t.ioc_refs {
        out.push_str(&format!("ioc {r}\n"));
    }
    out.push_str(&format!(
        "pcap filter '{}' from {} to {}\n",
        t.pcap.filter,
        iso(t.pcap.from_ms),
        iso(t.pcap.to_ms)
    ));
    for n in &t.notes {
        out.push_str(&format!("note: {n}\n"));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::attempt::{DEFAULT_IDLE_GAP_MS, ExtraSignals, build};
    use serde_json::json;

    fn ev(id: &str, ts: i64, channel: &str, data: Value) -> CaptureEvent {
        serde_json::from_value(json!({
            "event_id": id, "ts": ts, "decoy_id": "d1", "catalogue_id": "foiled/demo-app/1.0.0",
            "decoy_kind": "sandbox", "channel": channel, "severity": "info", "tenant_id": "t1",
            "src": {"ip": "203.0.113.7"}, "dst": {"ip": "10.85.1.2", "port": 443}, "data": data
        }))
        .unwrap()
    }

    #[test]
    fn attacker_text_cannot_break_lines_or_flip_direction() {
        let e = ev(
            "a",
            1_000,
            "application",
            json!({"method": "GET", "path": "/x\r\nFAKE 200\u{202E}gpj.exe"}),
        );
        let s = summarise(&e);
        assert!(!s.contains('\n') && !s.contains('\r') && !s.contains('\u{202E}'));
        assert!(s.contains("\\u{d}\\u{a}") && s.contains("\\u{202e}"), "{s}");
        let long = ev(
            "b",
            1_000,
            "application",
            json!({"method": "GET", "path": "/".repeat(500)}),
        );
        assert_eq!(summarise(&long).chars().count(), MAX_SUMMARY_CHARS + 1);
    }

    #[test]
    fn orders_by_time_marks_state_changes_and_reports_gaps() {
        let events = vec![
            ev(
                "b",
                2_000,
                "application",
                json!({"method": "POST", "path": "/api/upload"}),
            ),
            ev(
                "a",
                1_000,
                "application",
                json!({"method": "GET", "path": "/"}),
            ),
        ];
        let extra = ExtraSignals::from([("b".to_string(), vec![StateSignal::Matcher])]);
        let mut attempt = build(&events, DEFAULT_IDLE_GAP_MS, &extra).remove(0);
        attempt.event_ids.push("purged".into());
        let t = build_timeline(&attempt, &events);
        assert_eq!(
            t.entries
                .iter()
                .map(|e| e.event.event_id.as_str())
                .collect::<Vec<_>>(),
            ["a", "b"]
        );
        assert_eq!(t.entries[1].t_offset_ms, 1_000);
        assert_eq!(
            t.entries[1].state_change.as_ref().unwrap().state,
            AttemptState::Exploit
        );
        assert_eq!(t.missing_event_ids, ["purged"]);
        assert_eq!(t.notes.len(), 2, "TLS and retention notes: {:?}", t.notes);
        assert_eq!(t.pcap.filter, "host 203.0.113.7");
        assert_eq!(t.pcap.from_ms, 1_000 - PCAP_PAD_MS);
        let text = render_text(&t);
        assert!(text.contains("state -> exploit (matcher)"), "{text}");
        assert!(text.starts_with(&format!("attempt {}", t.attempt_id)));
    }

    #[test]
    fn iso_formats_utc() {
        assert_eq!(iso(0), "1970-01-01T00:00:00Z");
        assert_eq!(iso(1_792_285_383_000), "2026-10-18T01:03:03Z");
    }
}
