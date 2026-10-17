//! Vulnerable-path instrumentation hooks (#32).
//!
//! A hook manifest (`hooks/<id>.yaml`, schema
//! `schemas/hook-manifest.schema.json`) declares what one hook watches, which
//! stages it emits and how its request slice is redacted. Hook hits arrive as
//! capture envelopes on the `hook` channel ([`crate::capture::HookEvent`]).
//!
//! This module holds the pure parts: the manifest type, the request slice
//! redaction decision the host agent makes before building an envelope, and
//! [`hook_hits`], which turns an attempt's events into the ordered `hook_hits`
//! list used by attempts (#25), CVE tier 3 (#12) and confidence (#27).
//! See `docs/instrumentation.md`.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::capture::{CaptureEvent, Channel, HookStage};

/// Largest request slice kept inline in an envelope's `data`. Anything larger
/// goes to R2 and is referenced by `hook.request_slice_ref`.
pub const INLINE_SLICE_CAP: usize = 4 * 1024;

/// How a hook is wired into the decoy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HookKind {
    /// A callback compiled or baked into a sandboxed app (the demo app).
    InProcess,
    /// A checkpoint inside a Foiled emulator (#30).
    EmulatorCheckpoint,
    /// A host-side eBPF uprobe, where the runtime makes it stable (v0.2+).
    EbpfUprobe,
}

/// Where the hook writes its lines for the host agent to read.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HookTransport {
    /// JSON lines on the guest's serial or stdout log channel.
    LogChannel,
    /// JSON lines on a dedicated vsock port.
    Vsock,
    /// The emulator's own JSON event stream.
    EmulatorEvents,
}

/// What happens to the request slice that reached the vulnerable code.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SlicePolicy {
    /// Hash only unless the operator set `store_payloads: true` (#16).
    FollowStorePayloads,
    /// Always hash only, whatever `store_payloads` says.
    HashOnly,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Redaction {
    pub request_slice: SlicePolicy,
    /// Inline cap for this hook, at most [`INLINE_SLICE_CAP`].
    pub inline_cap_bytes: usize,
    /// Longest string field (paths, notes) the hook writes before truncating.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_field_chars: Option<usize>,
}

/// One hook manifest. Mirrors `schemas/hook-manifest.schema.json`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HookManifest {
    pub id: String,
    pub catalogue_ids: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cve_id: Option<String>,
    pub kind: HookKind,
    pub transport: HookTransport,
    pub stages: Vec<HookStage>,
    /// Plain description of the vulnerable condition that fires the hook.
    pub trigger: String,
    /// Envelope `hook` fields this hook fills in.
    pub fields: Vec<String>,
    pub redaction: Redaction,
    pub owner: String,
    /// Repository path of the trusted hook code.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
}

/// What to put in an envelope for a request slice.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RequestSlice {
    /// Small, UTF-8 and allowed: goes in `data.request_slice`.
    Inline(String),
    /// Payloads are not stored: only the hash and length are kept.
    Hashed { sha256: String, len: usize },
    /// Stored, but too large or not text: upload to R2 and set
    /// `hook.request_slice_ref`.
    NeedsUpload { sha256: String, len: usize },
}

/// Decide how a request slice is recorded. With `store_payloads` off (the
/// default, #16) only a hash leaves the host. With it on, slices up to
/// `inline_cap` bytes of valid UTF-8 stay inline and everything else is
/// uploaded whole and referenced.
pub fn redact_request_slice(bytes: &[u8], inline_cap: usize, store_payloads: bool) -> RequestSlice {
    let sha256 = || hex::encode(Sha256::digest(bytes));
    let len = bytes.len();
    if !store_payloads {
        return RequestSlice::Hashed {
            sha256: sha256(),
            len,
        };
    }
    if len <= inline_cap
        && let Ok(text) = std::str::from_utf8(bytes)
    {
        return RequestSlice::Inline(text.to_string());
    }
    RequestSlice::NeedsUpload {
        sha256: sha256(),
        len,
    }
}

/// One hook hit on an attempt (#25 `hook_hits[]`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HookHit {
    pub hook_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cve_id: Option<String>,
    pub stage: HookStage,
    pub event_id: String,
    pub ts: i64,
}

/// Hook hits in `events`, ordered by `ts` then `sequence_no` (then
/// `event_id`, so the order is total). Events off the hook channel are
/// ignored.
pub fn hook_hits(events: &[CaptureEvent]) -> Vec<HookHit> {
    let mut hits: Vec<(u32, HookHit)> = events
        .iter()
        .filter(|e| e.channel == Channel::Hook)
        .filter_map(|e| {
            let h = e.hook.as_ref()?;
            Some((
                h.sequence_no,
                HookHit {
                    hook_id: h.hook_id.clone(),
                    cve_id: h.cve_id.clone(),
                    stage: h.stage,
                    event_id: e.event_id.clone(),
                    ts: e.ts,
                },
            ))
        })
        .collect();
    hits.sort_by(|(sa, a), (sb, b)| (a.ts, sa, &a.event_id).cmp(&(b.ts, sb, &b.event_id)));
    hits.into_iter().map(|(_, h)| h).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn hash_only_when_payloads_are_not_stored() {
        let r = redact_request_slice(b"test", INLINE_SLICE_CAP, false);
        assert_eq!(
            r,
            RequestSlice::Hashed {
                sha256: "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08".into(),
                len: 4
            }
        );
    }

    #[test]
    fn small_text_is_inline_when_allowed() {
        assert_eq!(
            redact_request_slice(b"path=../../tmp/x.sh", INLINE_SLICE_CAP, true),
            RequestSlice::Inline("path=../../tmp/x.sh".into())
        );
        let exact = vec![b'a'; INLINE_SLICE_CAP];
        assert!(matches!(
            redact_request_slice(&exact, INLINE_SLICE_CAP, true),
            RequestSlice::Inline(s) if s.len() == INLINE_SLICE_CAP
        ));
    }

    #[test]
    fn large_or_binary_slices_need_upload() {
        let big = vec![b'a'; INLINE_SLICE_CAP + 1];
        assert!(matches!(
            redact_request_slice(&big, INLINE_SLICE_CAP, true),
            RequestSlice::NeedsUpload { len, ref sha256 } if len == INLINE_SLICE_CAP + 1 && sha256.len() == 64
        ));
        assert!(matches!(
            redact_request_slice(&[0xff, 0xfe], INLINE_SLICE_CAP, true),
            RequestSlice::NeedsUpload { len: 2, .. }
        ));
        // A big slice is still hash-only when payloads are not stored.
        assert!(matches!(
            redact_request_slice(&big, INLINE_SLICE_CAP, false),
            RequestSlice::Hashed { .. }
        ));
    }

    fn event(id: &str, ts: i64, hook: Option<(u32, &str)>) -> CaptureEvent {
        let mut v = json!({
            "event_id": id,
            "ts": ts,
            "decoy_id": "dcy-demo-1",
            "catalogue_id": "foiled/demo-app/1.0.0",
            "decoy_kind": "sandbox",
            "channel": "application",
            "severity": "info",
            "src": {"ip": "203.0.113.7"}
        });
        if let Some((seq, stage)) = hook {
            v["channel"] = json!("hook");
            v["hook"] = json!({
                "hook_id": "demo-app.upload-path-traversal",
                "catalogue_id": "foiled/demo-app/1.0.0",
                "cve_id": "FOILED-DEMO-0001",
                "stage": stage,
                "sequence_no": seq,
                "t_offset_ms": 0
            });
        }
        serde_json::from_value(v).unwrap()
    }

    #[test]
    fn hook_hits_are_ordered_by_time_then_sequence() {
        let events = vec![
            event("e4", 2000, Some((3, "cleanup"))),
            event("e1", 1000, None),
            event("e3", 1500, Some((2, "post_exploit"))),
            event("e2", 1500, Some((1, "trigger"))),
        ];
        let hits = hook_hits(&events);
        let order: Vec<_> = hits
            .iter()
            .map(|h| (h.event_id.as_str(), h.stage))
            .collect();
        assert_eq!(
            order,
            vec![
                ("e2", HookStage::Trigger),
                ("e3", HookStage::PostExploit),
                ("e4", HookStage::Cleanup)
            ]
        );
        assert_eq!(hits[0].cve_id.as_deref(), Some("FOILED-DEMO-0001"));
        assert_eq!(hits[0].ts, 1500);
        assert!(hook_hits(&[event("e1", 1, None)]).is_empty());
    }

    #[test]
    fn manifest_round_trips_and_rejects_unknown_fields() {
        let v = json!({
            "id": "demo-app.upload-path-traversal",
            "catalogue_ids": ["foiled/demo-app/1.0.0"],
            "cve_id": "FOILED-DEMO-0001",
            "kind": "in_process",
            "transport": "log_channel",
            "stages": ["trigger", "post_exploit"],
            "trigger": "upload path resolves outside the upload root",
            "fields": ["hook_id", "stage"],
            "redaction": {"request_slice": "follow_store_payloads", "inline_cap_bytes": 4096},
            "owner": "foiled maintainers"
        });
        let m: HookManifest = serde_json::from_value(v.clone()).unwrap();
        assert_eq!(m.kind, HookKind::InProcess);
        assert_eq!(serde_json::to_value(&m).unwrap(), v);
        let mut bad = v;
        bad["phone_home"] = json!("https://example.invalid");
        assert!(serde_json::from_value::<HookManifest>(bad).is_err());
    }
}
