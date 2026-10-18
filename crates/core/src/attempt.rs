//! Exploit attempts (#25): capture envelopes grouped into one object per
//! source and decoy, with a monotonic state and a noise score.
//!
//! Grouping is deterministic: the same events always produce the same
//! attempts with the same ids, so attempts can be recomputed from the
//! evidence at any time. Raw events are never changed or deleted here.
//! See `docs/attempts.md`.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::capture::{CaptureEvent, Channel, HookStage};
use crate::catalogue::DecoyKind;
use crate::enrichment::NoiseFacts;

/// A new attempt starts when the same source has been quiet on the same
/// decoy for longer than this.
pub const DEFAULT_IDLE_GAP_MS: i64 = 30 * 60 * 1000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AttemptState {
    Probe,
    Exploit,
    PostExploitation,
}

impl AttemptState {
    pub fn as_str(self) -> &'static str {
        match self {
            AttemptState::Probe => "probe",
            AttemptState::Exploit => "exploit",
            AttemptState::PostExploitation => "post-exploitation",
        }
    }
}

/// Why an attempt moved to a state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StateSignal {
    FirstContact,
    /// A tier 1 signature or tier 2 sequence matched (#12).
    Matcher,
    /// A vulnerable-path hook fired at the trigger stage (#32).
    HookTrigger,
    /// A hook reported post-exploitation activity.
    HookPostExploit,
    /// The decoy tried to reach out (egress proxy or DNS).
    Egress,
    /// A file was written in the guest or quarantined.
    FileWrite,
    /// A process ran in the guest.
    ProcessExec,
    /// YARA matched a dropped file (#11).
    Yara,
    /// A planted canary was used (#17).
    Canary,
}

impl StateSignal {
    pub fn implies(self) -> AttemptState {
        match self {
            StateSignal::FirstContact => AttemptState::Probe,
            StateSignal::Matcher | StateSignal::HookTrigger => AttemptState::Exploit,
            StateSignal::HookPostExploit
            | StateSignal::Egress
            | StateSignal::FileWrite
            | StateSignal::ProcessExec
            | StateSignal::Yara
            | StateSignal::Canary => AttemptState::PostExploitation,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StateChange {
    pub state: AttemptState,
    pub at: i64,
    pub signal: StateSignal,
    pub event_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HookHit {
    pub hook_id: String,
    pub cve_id: Option<String>,
    pub stage: HookStage,
    pub event_id: String,
    pub ts: i64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NoiseBand {
    Targeted,
    Mixed,
    Mass,
}

/// Targeted versus mass activity for the attempt's source (#25, #27).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NoiseScore {
    /// 0 (looks targeted) to 100 (looks like mass scanning).
    pub score: u8,
    pub band: NoiseBand,
    /// Events from this source across the visible fleet in the window.
    pub hits: u64,
    /// Distinct decoy kinds and catalogue products this source touched.
    pub decoy_types_touched: u32,
    pub decoys_touched: u32,
    /// `tenant` today; `fleet` once shared research sensors report (#31, #35).
    pub fleet_scope: String,
    pub evidence: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Attempt {
    pub attempt_id: String,
    pub tenant_id: String,
    pub decoy_id: String,
    pub catalogue_id: String,
    pub decoy_kind: DecoyKind,
    pub sensor_id: Option<String>,
    pub src: String,
    pub first_seen: i64,
    pub last_seen: i64,
    pub state: AttemptState,
    pub state_history: Vec<StateChange>,
    pub event_ids: Vec<String>,
    pub payload_refs: Vec<String>,
    pub ioc_refs: Vec<String>,
    pub hook_hits: Vec<HookHit>,
    pub campaign_id: Option<String>,
    pub labels: BTreeMap<String, String>,
    pub noise: Option<NoiseScore>,
}

/// Channels whose `src` is the attacker. Egress, DNS, process and file
/// events are emitted from inside the decoy, so their `src` is the guest;
/// they join the attempt active on that decoy at the time.
fn attacker_facing(c: Channel) -> bool {
    matches!(c, Channel::Network | Channel::Application | Channel::Hook)
}

fn signal_of(e: &CaptureEvent) -> Option<StateSignal> {
    match e.channel {
        Channel::Hook => match e.hook.as_ref().map(|h| h.stage) {
            Some(HookStage::Trigger) => Some(StateSignal::HookTrigger),
            Some(HookStage::PostExploit | HookStage::Cleanup) => Some(StateSignal::HookPostExploit),
            None => None,
        },
        Channel::Egress | Channel::Dns => Some(StateSignal::Egress),
        Channel::Filesystem | Channel::Quarantine => Some(StateSignal::FileWrite),
        Channel::Process => Some(StateSignal::ProcessExec),
        Channel::Network | Channel::Application => None,
    }
}

fn attempt_id(tenant: &str, decoy: &str, src: &str, first_event: &str) -> String {
    let h = Sha256::digest(format!("{tenant}\n{decoy}\n{src}\n{first_event}").as_bytes());
    format!("att_{}", hex::encode(&h[..12]))
}

/// Extra signals computed elsewhere (matchers, YARA, canaries), by event id.
pub type ExtraSignals = BTreeMap<String, Vec<StateSignal>>;

/// Group events into attempts. Events must belong to one tenant. Output is
/// sorted by `first_seen`, then id. Guest-side events that fall outside
/// every attempt window are returned in the second vector.
pub fn group(
    events: &[CaptureEvent],
    idle_gap_ms: i64,
    extra: &ExtraSignals,
) -> (Vec<Attempt>, Vec<String>) {
    let mut sorted: Vec<&CaptureEvent> = events.iter().collect();
    sorted.sort_by(|a, b| (a.ts, &a.event_id).cmp(&(b.ts, &b.event_id)));

    let mut attempts: Vec<Attempt> = Vec::new();
    // (decoy, src) -> index of the open attempt
    let mut open: BTreeMap<(String, String), usize> = BTreeMap::new();
    let mut orphans = Vec::new();

    for e in sorted {
        let tenant = e.tenant_id.clone().unwrap_or_default();
        let idx = if attacker_facing(e.channel) {
            let key = (e.decoy_id.clone(), e.src.ip.clone());
            match open.get(&key) {
                Some(&i) if e.ts - attempts[i].last_seen <= idle_gap_ms => i,
                _ => {
                    attempts.push(Attempt {
                        attempt_id: attempt_id(&tenant, &e.decoy_id, &e.src.ip, &e.event_id),
                        tenant_id: tenant,
                        decoy_id: e.decoy_id.clone(),
                        catalogue_id: e.catalogue_id.clone(),
                        decoy_kind: e.decoy_kind,
                        sensor_id: e
                            .source
                            .as_ref()
                            .filter(|s| s.kind == crate::capture::SourceKind::Sensor)
                            .map(|s| s.id.clone()),
                        src: e.src.ip.clone(),
                        first_seen: e.ts,
                        last_seen: e.ts,
                        state: AttemptState::Probe,
                        state_history: vec![StateChange {
                            state: AttemptState::Probe,
                            at: e.ts,
                            signal: StateSignal::FirstContact,
                            event_id: e.event_id.clone(),
                        }],
                        event_ids: vec![],
                        payload_refs: vec![],
                        ioc_refs: vec![],
                        hook_hits: vec![],
                        campaign_id: None,
                        labels: BTreeMap::new(),
                        noise: None,
                    });
                    let i = attempts.len() - 1;
                    open.insert(key, i);
                    i
                }
            }
        } else {
            // Most recently active attempt on this decoy, within the gap.
            let candidate = attempts
                .iter()
                .enumerate()
                .filter(|(_, a)| a.decoy_id == e.decoy_id && e.ts - a.last_seen <= idle_gap_ms)
                .max_by_key(|(_, a)| a.last_seen)
                .map(|(i, _)| i);
            match candidate {
                Some(i) => i,
                None => {
                    orphans.push(e.event_id.clone());
                    continue;
                }
            }
        };

        let a = &mut attempts[idx];
        a.last_seen = a.last_seen.max(e.ts);
        a.event_ids.push(e.event_id.clone());
        for r in e
            .payload_ref
            .iter()
            .chain(e.hook.iter().filter_map(|h| h.request_slice_ref.as_ref()))
        {
            if !a.payload_refs.contains(r) {
                a.payload_refs.push(r.clone());
            }
        }
        if let Some(h) = &e.hook {
            a.hook_hits.push(HookHit {
                hook_id: h.hook_id.clone(),
                cve_id: h.cve_id.clone(),
                stage: h.stage,
                event_id: e.event_id.clone(),
                ts: e.ts,
            });
        }
        let signals = signal_of(e)
            .into_iter()
            .chain(extra.get(&e.event_id).into_iter().flatten().copied());
        for s in signals {
            let next = s.implies();
            if next > a.state {
                a.state = next;
                a.state_history.push(StateChange {
                    state: next,
                    at: e.ts,
                    signal: s,
                    event_id: e.event_id.clone(),
                });
            }
        }
    }
    attempts.sort_by(|a, b| (a.first_seen, &a.attempt_id).cmp(&(b.first_seen, &b.attempt_id)));
    (attempts, orphans)
}

/// Score how much a source looks like mass scanning, from what the visible
/// fleet saw of it (`events`, any decoys of the tenant in the window) and,
/// optionally, ThreatSieve's scanner classification for the source (#11,
/// from [`crate::enrichment::noise_inputs`]). `NoiseFacts::default()` means no
/// enrichment, which is neutral.
pub fn noise_score(src: &str, events: &[CaptureEvent], hints: &NoiseFacts) -> NoiseScore {
    let mine: Vec<&CaptureEvent> = events
        .iter()
        .filter(|e| attacker_facing(e.channel) && e.src.ip == src)
        .collect();
    let hits = mine.len() as u64;
    let decoys: BTreeSet<&str> = mine.iter().map(|e| e.decoy_id.as_str()).collect();
    let products: BTreeSet<&str> = mine.iter().map(|e| e.catalogue_id.as_str()).collect();
    let mut evidence = Vec::new();

    // Breadth across products is the strongest sign of mass scanning.
    let mut score: i32 = match products.len() {
        0 | 1 => 10,
        2 | 3 => 40,
        _ => 70,
    };
    evidence.push(format!("touched {} catalogue product(s)", products.len()));
    if decoys.len() >= 5 {
        score += 10;
        evidence.push(format!("touched {} decoys", decoys.len()));
    }
    if hits >= 1000 {
        score += 10;
        evidence.push(format!("{hits} events in the window"));
    }
    // A restricted input is the tenant's own lookup: it may move the score
    // the tenant sees, and the evidence says it must not leave the console.
    let from = if hints.restricted {
        "ThreatSieve (restricted source, console only)"
    } else {
        "ThreatSieve"
    };
    if hints.scanner == Some(true) {
        score += 20;
        evidence.push(format!(
            "{from} classifies the source as an internet scanner"
        ));
    }
    if hints.benign_service == Some(true) {
        score = score.max(90);
        evidence.push(format!("{from} marks the source as a known benign service"));
    }
    if let Some(c) = hints.classification.as_deref().filter(|c| *c != "unknown") {
        evidence.push(format!("{from} classification: {c}"));
    }
    if !hints.tags.is_empty() {
        evidence.push(format!("{from} tags: {}", hints.tags.join(", ")));
    }
    let score = score.clamp(0, 100) as u8;
    let band = match score {
        0..=29 => NoiseBand::Targeted,
        30..=59 => NoiseBand::Mixed,
        _ => NoiseBand::Mass,
    };
    NoiseScore {
        score,
        band,
        hits,
        decoy_types_touched: products.len() as u32,
        decoys_touched: decoys.len() as u32,
        fleet_scope: "tenant".into(),
        evidence,
    }
}

/// Group and score in one step, the way the API builds its read model.
pub fn build(events: &[CaptureEvent], idle_gap_ms: i64, extra: &ExtraSignals) -> Vec<Attempt> {
    let (mut attempts, _) = group(events, idle_gap_ms, extra);
    for a in &mut attempts {
        a.noise = Some(noise_score(&a.src, events, &NoiseFacts::default()));
    }
    attempts
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const T0: i64 = 1_792_285_323_000;

    fn ev(
        id: &str,
        ts: i64,
        decoy: &str,
        catalogue: &str,
        src: &str,
        channel: &str,
    ) -> serde_json::Value {
        json!({
            "event_id": id, "ts": ts, "decoy_id": decoy, "catalogue_id": catalogue,
            "decoy_kind": "sandbox", "channel": channel, "severity": "info",
            "src": {"ip": src}, "tenant_id": "t1",
            "source": {"kind": "host", "id": "host-1"}, "data": {}
        })
    }

    fn hook(id: &str, ts: i64, src: &str, stage: &str) -> serde_json::Value {
        let mut v = ev(id, ts, "d1", "foiled/demo-app/1.0.0", src, "hook");
        v["hook"] = json!({"hook_id": "demo-app.upload-path-traversal", "catalogue_id": "foiled/demo-app/1.0.0",
            "cve_id": "FOILED-DEMO-0001", "stage": stage, "sequence_no": 1, "t_offset_ms": 0});
        v
    }

    fn parse(vs: Vec<serde_json::Value>) -> Vec<CaptureEvent> {
        vs.into_iter()
            .map(|v| serde_json::from_value(v).unwrap())
            .collect()
    }

    #[test]
    fn probe_only_attempt() {
        let events = parse(vec![
            ev(
                "e1",
                T0,
                "d1",
                "foiled/demo-app/1.0.0",
                "198.51.100.9",
                "application",
            ),
            ev(
                "e2",
                T0 + 1000,
                "d1",
                "foiled/demo-app/1.0.0",
                "198.51.100.9",
                "application",
            ),
        ]);
        let (a, orphans) = group(&events, DEFAULT_IDLE_GAP_MS, &ExtraSignals::new());
        assert!(orphans.is_empty());
        assert_eq!(a.len(), 1);
        assert_eq!(a[0].state, AttemptState::Probe);
        assert_eq!(a[0].event_ids, vec!["e1", "e2"]);
    }

    #[test]
    fn full_chain_with_hook_hit_and_guest_side_events() {
        let mut egress = ev(
            "e4",
            T0 + 3000,
            "d1",
            "foiled/demo-app/1.0.0",
            "10.85.1.2",
            "egress",
        );
        egress["dst"] = json!({"ip": "192.0.2.80", "port": 80});
        let events = parse(vec![
            ev(
                "e1",
                T0,
                "d1",
                "foiled/demo-app/1.0.0",
                "203.0.113.7",
                "application",
            ),
            hook("e2", T0 + 1000, "203.0.113.7", "trigger"),
            hook("e3", T0 + 2000, "203.0.113.7", "post_exploit"),
            egress,
        ]);
        let (a, _) = group(&events, DEFAULT_IDLE_GAP_MS, &ExtraSignals::new());
        assert_eq!(a.len(), 1, "guest egress joins the active attempt");
        let a = &a[0];
        assert_eq!(a.state, AttemptState::PostExploitation);
        let path: Vec<_> = a
            .state_history
            .iter()
            .map(|s| (s.state, s.signal))
            .collect();
        assert_eq!(
            path,
            vec![
                (AttemptState::Probe, StateSignal::FirstContact),
                (AttemptState::Exploit, StateSignal::HookTrigger),
                (AttemptState::PostExploitation, StateSignal::HookPostExploit),
            ]
        );
        assert_eq!(a.hook_hits.len(), 2);
        assert_eq!(a.hook_hits[0].cve_id.as_deref(), Some("FOILED-DEMO-0001"));
        assert_eq!(a.event_ids.len(), 4);
    }

    #[test]
    fn idle_gap_splits_and_sources_and_decoys_stay_separate() {
        let events = parse(vec![
            ev("e1", T0, "d1", "c/1", "203.0.113.7", "application"),
            ev(
                "e2",
                T0 + DEFAULT_IDLE_GAP_MS + 1,
                "d1",
                "c/1",
                "203.0.113.7",
                "application",
            ),
            ev("e3", T0, "d2", "c/2", "203.0.113.7", "application"),
            ev("e4", T0, "d1", "c/1", "198.51.100.1", "application"),
        ]);
        let (a, _) = group(&events, DEFAULT_IDLE_GAP_MS, &ExtraSignals::new());
        assert_eq!(a.len(), 4);
    }

    #[test]
    fn ids_are_deterministic_and_state_never_goes_back() {
        let events = parse(vec![
            hook("e1", T0, "203.0.113.7", "trigger"),
            ev(
                "e2",
                T0 + 1,
                "d1",
                "foiled/demo-app/1.0.0",
                "203.0.113.7",
                "application",
            ),
        ]);
        let (a1, _) = group(&events, DEFAULT_IDLE_GAP_MS, &ExtraSignals::new());
        let mut reversed = events.clone();
        reversed.reverse();
        let (a2, _) = group(&reversed, DEFAULT_IDLE_GAP_MS, &ExtraSignals::new());
        assert_eq!(a1, a2, "input order does not matter");
        assert_eq!(a1[0].state, AttemptState::Exploit);
        assert!(a1[0].attempt_id.starts_with("att_"));
    }

    #[test]
    fn extra_signals_from_matchers_promote_state() {
        let events = parse(vec![ev(
            "e1",
            T0,
            "d1",
            "c/1",
            "203.0.113.7",
            "application",
        )]);
        let extra = ExtraSignals::from([("e1".to_string(), vec![StateSignal::Matcher])]);
        let (a, _) = group(&events, DEFAULT_IDLE_GAP_MS, &extra);
        assert_eq!(a[0].state, AttemptState::Exploit);
        assert_eq!(a[0].state_history[1].signal, StateSignal::Matcher);
    }

    #[test]
    fn orphan_guest_events_are_reported_not_dropped_silently() {
        let events = parse(vec![ev("e1", T0, "d1", "c/1", "10.85.1.2", "egress")]);
        let (a, orphans) = group(&events, DEFAULT_IDLE_GAP_MS, &ExtraSignals::new());
        assert!(a.is_empty());
        assert_eq!(orphans, vec!["e1"]);
    }

    #[test]
    fn noise_bands_follow_breadth() {
        let one = parse(vec![ev(
            "e1",
            T0,
            "d1",
            "c/1",
            "203.0.113.7",
            "application",
        )]);
        let n = noise_score("203.0.113.7", &one, &NoiseFacts::default());
        assert_eq!(n.band, NoiseBand::Targeted);
        let wide: Vec<_> = parse(
            (0..5)
                .map(|i| {
                    ev(
                        &format!("e{i}"),
                        T0,
                        &format!("d{i}"),
                        &format!("c/{i}"),
                        "198.51.100.5",
                        "application",
                    )
                })
                .collect(),
        );
        let n = noise_score("198.51.100.5", &wide, &NoiseFacts::default());
        assert_eq!(n.band, NoiseBand::Mass);
        assert_eq!(n.decoy_types_touched, 5);
        let benign = noise_score(
            "203.0.113.7",
            &one,
            &NoiseFacts {
                benign_service: Some(true),
                ..NoiseFacts::default()
            },
        );
        assert_eq!(benign.score, 90);
        assert_eq!(benign.band, NoiseBand::Mass);
        assert!(
            benign
                .evidence
                .iter()
                .any(|e| e == "ThreatSieve marks the source as a known benign service")
        );
    }

    #[test]
    fn threatsieve_scanner_facts_move_the_noise_score() {
        let one = parse(vec![ev(
            "e1",
            T0,
            "d1",
            "c/1",
            "203.0.113.7",
            "application",
        )]);
        // Unknown (no scanner Fact) and "not a scanner" are both neutral.
        let base = noise_score("203.0.113.7", &one, &NoiseFacts::default()).score;
        let not_scanner = NoiseFacts {
            scanner: Some(false),
            benign_service: Some(false),
            classification: Some("unknown".into()),
            ..NoiseFacts::default()
        };
        let n = noise_score("203.0.113.7", &one, &not_scanner);
        assert_eq!((base, n.score), (10, 10));
        assert_eq!(n.evidence.len(), 1);

        let scanner = NoiseFacts {
            scanner: Some(true),
            classification: Some("malicious".into()),
            tags: vec!["bruteforce".into()],
            ..NoiseFacts::default()
        };
        let n = noise_score("203.0.113.7", &one, &scanner);
        assert_eq!(n.score, 30);
        assert_eq!(n.band, NoiseBand::Mixed);
        assert_eq!(
            n.evidence[1..],
            [
                "ThreatSieve classifies the source as an internet scanner",
                "ThreatSieve classification: malicious",
                "ThreatSieve tags: bruteforce",
            ]
        );

        // The tenant's own restricted answer still counts, and is labelled.
        let restricted = noise_score(
            "203.0.113.7",
            &one,
            &NoiseFacts {
                restricted: true,
                ..scanner
            },
        );
        assert_eq!(restricted.score, 30);
        assert!(
            restricted.evidence[1..]
                .iter()
                .all(|e| e.starts_with("ThreatSieve (restricted source, console only)"))
        );
    }
}
