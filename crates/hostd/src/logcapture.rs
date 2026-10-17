//! Application-channel capture from a decoy's JSON log stream (ADR 0005).
//!
//! The demo app (`build/recipes/foiled-demo-app`) writes one JSON object per
//! request and one per hook firing. This turns those lines into capture
//! envelopes. Log lines come from the guest, so they are untrusted: only
//! known fields are copied, sizes are capped, and anything that does not
//! parse is skipped.

use foiled_core::agent::DecoyParams;
use foiled_core::capture::{
    CaptureEvent, Channel, Endpoint, HookEvent, HookStage, MAX_EVENT_BYTES, Severity,
};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

/// `YYYY-MM-DDTHH:MM:SS[.fff]Z` to Unix milliseconds.
pub fn parse_utc_ms(s: &str) -> Option<i64> {
    let s = s.strip_suffix('Z')?;
    let (date, time) = s.split_once('T')?;
    let mut d = date.split('-');
    let (y, m, day): (i64, i64, i64) = (
        d.next()?.parse().ok()?,
        d.next()?.parse().ok()?,
        d.next()?.parse().ok()?,
    );
    let (hms, frac) = time.split_once('.').unwrap_or((time, "0"));
    let mut t = hms.split(':');
    let (hh, mm, ss): (i64, i64, i64) = (
        t.next()?.parse().ok()?,
        t.next()?.parse().ok()?,
        t.next()?.parse().ok()?,
    );
    if !(1..=12).contains(&m) || !(1..=31).contains(&day) || hh > 23 || mm > 59 || ss > 60 {
        return None;
    }
    let ms: i64 = format!("{frac:0<3}")[..3].parse().ok()?;
    // Days from civil (Howard Hinnant).
    let y2 = if m <= 2 { y - 1 } else { y };
    let era = y2.div_euclid(400);
    let yoe = y2 - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    Some(((days * 86_400 + hh * 3600 + mm * 60 + ss) * 1000) + ms)
}

fn event_id(decoy_id: &str, generation: u32, line: &str) -> String {
    let h = Sha256::digest(format!("{decoy_id}\n{generation}\n{line}").as_bytes());
    hex::encode(&h[..16])
}

fn short(v: &Value, max: usize) -> Value {
    match v.as_str() {
        Some(s) if s.len() > max => Value::String(format!("{}...[truncated]", &s[..floor(s, max)])),
        _ => v.clone(),
    }
}

fn floor(s: &str, mut i: usize) -> usize {
    while !s.is_char_boundary(i) {
        i -= 1;
    }
    i
}

/// One envelope for one log line, or `None` for lines that are not
/// attacker activity (start-up records, garbage).
pub fn line_to_event(decoy_id: &str, params: &DecoyParams, line: &str) -> Option<CaptureEvent> {
    if line.len() > MAX_EVENT_BYTES {
        return None;
    }
    let rec: Map<String, Value> = serde_json::from_str(line).ok()?;
    let ts = parse_utc_ms(rec.get("ts")?.as_str()?)?;
    let src_ip = rec.get("src")?.as_str()?.to_string();
    if src_ip.parse::<std::net::IpAddr>().is_err() {
        return None;
    }
    let port = params.listen_ports.first().map(|p| p.port);
    let base = |channel, severity, data, hook| CaptureEvent {
        event_id: event_id(decoy_id, params.generation, line),
        ts,
        decoy_id: decoy_id.to_string(),
        catalogue_id: params.catalogue_id.clone(),
        decoy_kind: params.decoy_kind,
        generation: Some(params.generation),
        channel,
        severity,
        src: Endpoint {
            ip: src_ip.clone(),
            port: None,
        },
        dst: port.map(|p| Endpoint {
            ip: "0.0.0.0".into(),
            port: Some(p),
        }),
        payload_ref: None,
        attempt_id: None,
        source: None,
        tenant_id: None,
        hook,
        data,
    };

    if rec.get("kind").and_then(Value::as_str) == Some("hook") {
        let stage = match rec.get("stage").and_then(Value::as_str)? {
            "trigger" => HookStage::Trigger,
            "post_exploit" => HookStage::PostExploit,
            "cleanup" => HookStage::Cleanup,
            _ => return None,
        };
        let file_writes: Vec<String> = match rec.get("file_writes").and_then(Value::as_array) {
            Some(list) => list
                .iter()
                .filter_map(Value::as_str)
                .take(32)
                .map(|s| s.chars().take(512).collect())
                .collect(),
            None => rec
                .get("resolved_path")
                .and_then(Value::as_str)
                .map(|s| s.chars().take(512).collect::<String>())
                .into_iter()
                .collect(),
        };
        let hook = HookEvent {
            hook_id: rec.get("hook_id")?.as_str()?.to_string(),
            catalogue_id: params.catalogue_id.clone(),
            cve_id: rec
                .get("cve_id")
                .and_then(Value::as_str)
                .map(str::to_string),
            stage,
            request_slice_ref: None,
            sequence_no: rec
                .get("sequence_no")
                .and_then(Value::as_u64)
                .map(|n| n.min(u64::from(u32::MAX)) as u32)
                .unwrap_or(1),
            t_offset_ms: rec.get("t_offset_ms").and_then(Value::as_u64).unwrap_or(0),
            cmd_lines: vec![],
            file_writes,
            implant_refs: vec![],
            notes: rec.get("notes").and_then(Value::as_str).map(str::to_string),
        };
        let mut data = Map::new();
        if let Some(p) = rec.get("request_path") {
            data.insert("path".into(), short(p, 1024));
        }
        return Some(base(Channel::Hook, Severity::High, data, Some(hook)));
    }

    // Access record.
    rec.get("method")?;
    let mut data = Map::new();
    for key in ["method", "path", "status", "bytes", "user_agent"] {
        if let Some(v) = rec.get(key) {
            data.insert(key.into(), short(v, 1024));
        }
    }
    let severity = match (
        rec.get("method").and_then(Value::as_str),
        rec.get("path").and_then(Value::as_str),
    ) {
        (Some("POST"), Some(p)) if p.starts_with("/api/upload") => Severity::Medium,
        _ => Severity::Info,
    };
    Some(base(Channel::Application, severity, data, None))
}

#[cfg(test)]
mod tests {
    use super::*;
    use foiled_core::catalogue::{DecoyKind, ListenPort, Protocol};

    fn params() -> DecoyParams {
        DecoyParams {
            catalogue_id: "foiled/demo-app/1.0.0".into(),
            decoy_kind: DecoyKind::Sandbox,
            generation: 1,
            artefact: None,
            image: None,
            listen_ports: vec![ListenPort {
                port: 8080,
                protocol: Protocol::Tcp,
                service: "http".into(),
                tls: None,
            }],
            hard_deadline: 0,
        }
    }

    #[test]
    fn parses_utc_timestamps() {
        assert_eq!(
            parse_utc_ms("2026-10-18T01:02:03.456Z"),
            Some(1_792_285_323_456)
        );
        assert_eq!(parse_utc_ms("2000-02-29T00:00:00Z"), Some(951_782_400_000));
        assert_eq!(parse_utc_ms("2026-13-01T00:00:00Z"), None);
        assert_eq!(parse_utc_ms("2026-10-18 01:02:03"), None);
    }

    #[test]
    fn access_lines_become_application_events() {
        let line = r#"{"bytes":42,"method":"POST","path":"/api/upload?path=../../tmp/x","src":"203.0.113.7","status":201,"ts":"2026-10-18T01:02:03.456Z","user_agent":"curl/8.0"}"#;
        let e = line_to_event("d1", &params(), line).unwrap();
        assert_eq!(e.channel, Channel::Application);
        assert_eq!(e.severity, Severity::Medium);
        assert_eq!(e.src.ip, "203.0.113.7");
        assert_eq!(e.data["status"], 201);
        assert!(
            e.problems(1_800_000_000_000).is_empty(),
            "{:?}",
            e.problems(1_800_000_000_000)
        );
        // Same line, same id: replays dedupe at ingest.
        assert_eq!(
            e.event_id,
            line_to_event("d1", &params(), line).unwrap().event_id
        );
    }

    #[test]
    fn hook_lines_become_hook_events() {
        let line = r#"{"catalogue_id":"foiled/demo-app/1.0.0","cve_id":"FOILED-DEMO-0001","hook_id":"demo-app.upload-path-traversal","kind":"hook","notes":"resolved path escaped the upload root","request_path":"/api/upload?path=../../tmp/x","resolved_path":"/tmp/x","src":"203.0.113.7","stage":"trigger","ts":"2026-10-18T01:02:03.468Z","upload_root":"/srv/demo-app/uploads"}"#;
        let e = line_to_event("d1", &params(), line).unwrap();
        assert_eq!(e.channel, Channel::Hook);
        let h = e.hook.as_ref().unwrap();
        assert_eq!(h.cve_id.as_deref(), Some("FOILED-DEMO-0001"));
        assert_eq!(h.file_writes, vec!["/tmp/x".to_string()]);
        assert!(e.problems(1_800_000_000_000).is_empty());
    }

    #[test]
    fn post_exploit_lines_keep_their_sequence_and_writes() {
        let line = r#"{"catalogue_id":"foiled/demo-app/1.0.0","cve_id":"FOILED-DEMO-0001","file_writes":["/tmp/x.sh"],"hook_id":"demo-app.upload-path-traversal","kind":"hook","sequence_no":2,"src":"203.0.113.7","stage":"post_exploit","t_offset_ms":15,"ts":"2026-10-18T01:02:03.470Z"}"#;
        let e = line_to_event("d1", &params(), line).unwrap();
        let h = e.hook.unwrap();
        assert_eq!(h.stage, HookStage::PostExploit);
        assert_eq!((h.sequence_no, h.t_offset_ms), (2, 15));
        assert_eq!(h.file_writes, vec!["/tmp/x.sh".to_string()]);
    }

    #[test]
    fn junk_and_startup_lines_are_skipped() {
        let start = r#"{"event":"start","host":"0.0.0.0","port":8080,"ts":"2026-10-18T01:00:00.000Z","version":"1.0.0"}"#;
        assert!(line_to_event("d1", &params(), start).is_none());
        assert!(line_to_event("d1", &params(), "not json").is_none());
        let bad_ip =
            r#"{"method":"GET","path":"/","src":"-","status":200,"ts":"2026-10-18T01:00:00.000Z"}"#;
        assert!(line_to_event("d1", &params(), bad_ip).is_none());
    }
}
