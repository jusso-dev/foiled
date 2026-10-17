//! CVE mapping tiers (#12): turn capture evidence into confidence evidence
//! (#27) for attempt to CVE links. See `docs/exploit-attribution.md`.
//!
//! 1. Signatures (`catalogue/matchers/`) -> `rule`
//! 2. Ordered sequences (`catalogue/sequences/`) -> `sequence`
//! 3. Vulnerable-path hooks (#32) -> `vuln_path_hook` (built from hook hits)
//! 4. Pre-disclosure watchlist back-matches -> `predisclosure_backmatch`
//! 5. Vendor advisory fields (`catalogue/advisories/`) -> `vendor_desc`
//!
//! Matching is plain string comparison over known envelope fields, never
//! regex and never anything that executes attacker input.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::capture::{CaptureEvent, Channel};
use crate::catalogue::AuthRequirement;
use crate::confidence::{Evidence, EvidenceSource};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Op {
    Equals,
    Prefix,
    Contains,
    ContainsAny,
    Regex,
}

/// One test on one envelope field, `data.<name>` or `hook.<name>`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Condition {
    pub field: String,
    pub op: Op,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<Value>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub values: Vec<String>,
    #[serde(default)]
    pub case_insensitive: bool,
}

fn field<'a>(e: &'a CaptureEvent, path: &str, hook_json: &'a Option<Value>) -> Option<&'a Value> {
    let (root, name) = path.split_once('.')?;
    match root {
        "data" => e.data.get(name),
        "hook" => hook_json.as_ref()?.get(name),
        _ => None,
    }
}

impl Condition {
    fn holds(&self, e: &CaptureEvent, hook_json: &Option<Value>) -> bool {
        let Some(actual) = field(e, &self.field, hook_json) else {
            return false;
        };
        let norm = |s: &str| {
            if self.case_insensitive {
                s.to_lowercase()
            } else {
                s.to_string()
            }
        };
        let text = match actual {
            Value::String(s) => norm(s),
            Value::Number(n) => n.to_string(),
            Value::Bool(b) => b.to_string(),
            _ => return false,
        };
        let want = || match &self.value {
            Some(Value::String(s)) => Some(norm(s)),
            Some(Value::Number(n)) => Some(n.to_string()),
            _ => None,
        };
        match self.op {
            Op::Equals => want().is_some_and(|w| text == w),
            Op::Prefix => want().is_some_and(|w| !w.is_empty() && text.starts_with(&w)),
            Op::Contains => want().is_some_and(|w| !w.is_empty() && text.contains(&w)),
            Op::ContainsAny => self
                .values
                .iter()
                .any(|v| !v.is_empty() && text.contains(&norm(v))),
            // Regex conditions are accepted by the schema for future use but
            // never match here: no regex engine runs over attacker input.
            Op::Regex => false,
        }
    }
}

/// Tier 1: a curated request signature.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Matcher {
    pub id: String,
    pub tier: String,
    pub cve_ids: Vec<String>,
    pub catalogue_ids: Vec<String>,
    pub channel: Channel,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth_requirement: Option<AuthRequirement>,
    pub all: Vec<Condition>,
    pub description: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub references: Vec<String>,
}

impl Matcher {
    pub fn matches(&self, e: &CaptureEvent) -> bool {
        if e.channel != self.channel || !self.catalogue_ids.contains(&e.catalogue_id) {
            return false;
        }
        let hook_json = e.hook.as_ref().and_then(|h| serde_json::to_value(h).ok());
        !self.all.is_empty() && self.all.iter().all(|c| c.holds(e, &hook_json))
    }
}

/// One step of a tier 2 sequence: a matcher id, or inline conditions.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Step {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub matcher: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub channel: Option<Channel>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub all: Vec<Condition>,
    pub description: String,
}

/// Tier 2: steps that must appear in order within one attempt.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Sequence {
    pub id: String,
    pub cve_ids: Vec<String>,
    pub catalogue_ids: Vec<String>,
    pub max_span_ms: i64,
    pub steps: Vec<Step>,
    pub description: String,
}

impl Sequence {
    /// Event ids for the earliest ordered match, or `None`.
    pub fn find(&self, events: &[&CaptureEvent], matchers: &[Matcher]) -> Option<Vec<String>> {
        if self.steps.is_empty() {
            return None;
        }
        let step_holds = |s: &Step, e: &CaptureEvent| -> bool {
            if !self.catalogue_ids.contains(&e.catalogue_id) {
                return false;
            }
            if let Some(c) = s.channel
                && e.channel != c
            {
                return false;
            }
            if let Some(m) = &s.matcher {
                return matchers.iter().any(|x| &x.id == m && x.matches(e));
            }
            let hook_json = e.hook.as_ref().and_then(|h| serde_json::to_value(h).ok());
            !s.all.is_empty() && s.all.iter().all(|c| c.holds(e, &hook_json))
        };
        // Try each event that satisfies step 1 as a start; greedy forward.
        for (i, start) in events.iter().enumerate() {
            if !step_holds(&self.steps[0], start) {
                continue;
            }
            let mut ids = vec![start.event_id.clone()];
            let mut step = 1;
            for e in &events[i + 1..] {
                if step == self.steps.len() || e.ts - start.ts > self.max_span_ms {
                    break;
                }
                if step_holds(&self.steps[step], e) {
                    ids.push(e.event_id.clone());
                    step += 1;
                }
            }
            if step == self.steps.len() {
                return Some(ids);
            }
        }
        None
    }
}

/// Tier 5: structured fields from a public advisory.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Advisory {
    pub cve_id: String,
    pub catalogue_ids: Vec<String>,
    /// Path prefix the advisory names.
    pub endpoint: String,
    pub auth_requirement: AuthRequirement,
    pub published_at: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub post_exploit_notes: Option<String>,
    pub references: Vec<String>,
}

/// Whether the attempt hit the endpoint authenticated, unauthenticated or
/// both. Decoys that know set `data.authenticated` on application events.
fn observed_auth(events: &[&CaptureEvent], endpoint: &str) -> Option<AuthRequirement> {
    let mut seen_auth = false;
    let mut seen_unauth = false;
    for e in events {
        let on_endpoint = e
            .data
            .get("path")
            .and_then(Value::as_str)
            .is_some_and(|p| p.starts_with(endpoint));
        if !on_endpoint {
            continue;
        }
        match e.data.get("authenticated").and_then(Value::as_bool) {
            Some(true) => seen_auth = true,
            Some(false) => seen_unauth = true,
            None => {}
        }
    }
    match (seen_auth, seen_unauth) {
        (true, true) => Some(AuthRequirement::Either),
        (true, false) => Some(AuthRequirement::Auth),
        (false, true) => Some(AuthRequirement::Unauth),
        (false, false) => None,
    }
}

/// Tier 4 (pre-disclosure): consistent, non-generic traffic against a
/// product with no CVE yet. Fields per `docs/exploit-attribution.md`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WatchlistEntry {
    pub id: String,
    pub catalogue_id: String,
    pub pattern: Vec<Condition>,
    pub first_seen: i64,
    pub last_seen: i64,
    pub hits: u64,
    pub distinct_sources: u64,
    pub notes: String,
}

/// What a back-match found: we saw it before the advisory was published.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Backmatch {
    pub watchlist_id: String,
    pub cve_id: String,
    pub first_seen: i64,
    pub advisory_published_at: i64,
    /// Positive when Foiled saw the traffic first.
    pub lead_time_ms: i64,
}

/// Match a watchlist entry to a newly published advisory: same product and
/// the advisory endpoint appears in the watched pattern.
pub fn backmatch(entry: &WatchlistEntry, advisory: &Advisory) -> Option<Backmatch> {
    if !advisory.catalogue_ids.contains(&entry.catalogue_id) {
        return None;
    }
    let mentions = entry.pattern.iter().any(|c| {
        c.field == "data.path"
            && match (&c.op, &c.value) {
                (Op::Prefix | Op::Equals | Op::Contains, Some(Value::String(v))) => {
                    v.starts_with(&advisory.endpoint) || advisory.endpoint.starts_with(v.as_str())
                }
                _ => false,
            }
    });
    mentions.then(|| Backmatch {
        watchlist_id: entry.id.clone(),
        cve_id: advisory.cve_id.clone(),
        first_seen: entry.first_seen,
        advisory_published_at: advisory.published_at,
        lead_time_ms: advisory.published_at - entry.first_seen,
    })
}

/// Rule packs bundled with the control plane.
#[derive(Debug, Clone, Default)]
pub struct Rules {
    pub matchers: Vec<Matcher>,
    pub sequences: Vec<Sequence>,
    pub advisories: Vec<Advisory>,
}

/// Evidence per CVE from tiers 1, 2, 4 and 5 for one attempt's events, and
/// the ids of events a signature matched (so the attempt can move to
/// `exploit`, and ATT&CK rules can see `data.matcher_id`).
pub struct TierResult {
    pub evidence: BTreeMap<String, Vec<Evidence>>,
    pub matcher_hits: BTreeMap<String, Vec<String>>,
}

pub fn evaluate(rules: &Rules, events: &[CaptureEvent], backmatches: &[Backmatch]) -> TierResult {
    let mut sorted: Vec<&CaptureEvent> = events.iter().collect();
    sorted.sort_by(|a, b| (a.ts, &a.event_id).cmp(&(b.ts, &b.event_id)));
    let mut evidence: BTreeMap<String, Vec<Evidence>> = BTreeMap::new();
    let mut matcher_hits: BTreeMap<String, Vec<String>> = BTreeMap::new();

    for m in &rules.matchers {
        for e in sorted.iter().filter(|e| m.matches(e)) {
            matcher_hits
                .entry(e.event_id.clone())
                .or_default()
                .push(m.id.clone());
            for cve in &m.cve_ids {
                evidence.entry(cve.clone()).or_default().push(Evidence {
                    signal_id: format!("matcher:{}:{}", m.id, e.event_id),
                    source: EvidenceSource::Rule,
                    weight: 100,
                    summary: format!("signature {} matched", m.id),
                    reference: Some(e.event_id.clone()),
                });
            }
        }
    }
    for s in &rules.sequences {
        if let Some(ids) = s.find(&sorted, &rules.matchers) {
            for cve in &s.cve_ids {
                evidence.entry(cve.clone()).or_default().push(Evidence {
                    signal_id: format!("sequence:{}", s.id),
                    source: EvidenceSource::Sequence,
                    weight: 100,
                    summary: format!("sequence {} matched in order ({} steps)", s.id, ids.len()),
                    reference: ids.last().cloned(),
                });
            }
        }
    }
    for a in &rules.advisories {
        let on_product: Vec<&CaptureEvent> = sorted
            .iter()
            .copied()
            .filter(|e| a.catalogue_ids.contains(&e.catalogue_id))
            .collect();
        let Some(observed) = observed_auth(&on_product, &a.endpoint) else {
            continue;
        };
        let consistent = matches!(
            (a.auth_requirement, observed),
            (AuthRequirement::Either, _)
                | (AuthRequirement::Unauth, AuthRequirement::Unauth)
                | (AuthRequirement::Auth, AuthRequirement::Auth)
                | (AuthRequirement::Unauth, AuthRequirement::Either)
                | (AuthRequirement::Auth, AuthRequirement::Either)
        );
        if consistent {
            evidence
                .entry(a.cve_id.clone())
                .or_default()
                .push(Evidence {
                    signal_id: format!("advisory:{}", a.cve_id),
                    source: EvidenceSource::VendorDesc,
                    weight: 100,
                    summary: format!(
                        "advisory endpoint {} hit with auth {:?}, matching the advisory ({:?})",
                        a.endpoint, observed, a.auth_requirement
                    )
                    .to_lowercase(),
                    reference: a.references.first().cloned(),
                });
        }
    }
    for b in backmatches {
        evidence
            .entry(b.cve_id.clone())
            .or_default()
            .push(Evidence {
                signal_id: format!("predisclosure:{}", b.watchlist_id),
                source: EvidenceSource::PredisclosureBackmatch,
                weight: 100,
                summary: format!(
                    "watched pattern first seen {} ms before the advisory",
                    b.lead_time_ms
                ),
                reference: None,
            });
    }
    TierResult {
        evidence,
        matcher_hits,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::confidence::{Band, ConfidenceConfig, LinkKind, score};
    use serde_json::json;

    const T0: i64 = 1_792_285_323_000;

    fn ev(id: &str, ts: i64, channel: &str, data: Value) -> CaptureEvent {
        serde_json::from_value(json!({
            "event_id": id, "ts": ts, "decoy_id": "d1", "catalogue_id": "foiled/demo-app/1.0.0",
            "decoy_kind": "sandbox", "channel": channel, "severity": "info",
            "src": {"ip": "203.0.113.7"}, "data": data
        }))
        .unwrap()
    }

    fn hook_ev(id: &str, ts: i64) -> CaptureEvent {
        let mut e = ev(id, ts, "hook", json!({}));
        e.hook = Some(crate::capture::HookEvent {
            hook_id: "demo-app.upload-path-traversal".into(),
            catalogue_id: "foiled/demo-app/1.0.0".into(),
            cve_id: Some("FOILED-DEMO-0001".into()),
            stage: crate::capture::HookStage::Trigger,
            request_slice_ref: None,
            sequence_no: 1,
            t_offset_ms: 0,
            cmd_lines: vec![],
            file_writes: vec![],
            implant_refs: vec![],
            notes: None,
        });
        e
    }

    fn matcher() -> Matcher {
        serde_json::from_value(json!({
            "id": "foiled-demo-0001-upload-traversal", "tier": "signature",
            "cve_ids": ["FOILED-DEMO-0001"], "catalogue_ids": ["foiled/demo-app/1.0.0"],
            "channel": "application", "auth_requirement": "unauth",
            "all": [
                {"field": "data.method", "op": "equals", "value": "POST"},
                {"field": "data.path", "op": "prefix", "value": "/api/upload"},
                {"field": "data.path", "op": "contains_any", "case_insensitive": true,
                 "values": ["../", "..%2f", "%2e%2e/"]}
            ],
            "description": "demo"
        }))
        .unwrap()
    }

    fn sequence() -> Sequence {
        serde_json::from_value(json!({
            "id": "foiled-demo-0001-upload-chain", "cve_ids": ["FOILED-DEMO-0001"],
            "catalogue_ids": ["foiled/demo-app/1.0.0"], "max_span_ms": 600000,
            "steps": [
                {"channel": "application", "all": [{"field": "data.method", "op": "equals", "value": "GET"}], "description": "look around"},
                {"matcher": "foiled-demo-0001-upload-traversal", "description": "traversal upload"},
                {"channel": "hook", "all": [{"field": "hook.hook_id", "op": "equals", "value": "demo-app.upload-path-traversal"}], "description": "vulnerable path ran"}
            ],
            "description": "demo chain"
        }))
        .unwrap()
    }

    fn upload(id: &str, ts: i64, path: &str) -> CaptureEvent {
        ev(
            id,
            ts,
            "application",
            json!({"method": "POST", "path": path, "authenticated": false}),
        )
    }

    #[test]
    fn signature_matches_traversal_but_not_normal_uploads() {
        let m = matcher();
        assert!(m.matches(&upload("a", T0, "/api/upload?path=../../tmp/x")));
        assert!(
            m.matches(&upload("b", T0, "/api/upload?path=%2E%2E/x")),
            "case-insensitive"
        );
        assert!(!m.matches(&upload("c", T0, "/api/upload?path=report.pdf")));
        let mut other = upload("d", T0, "/api/upload?path=../x");
        other.catalogue_id = "emulator/redis/7.0".into();
        assert!(!m.matches(&other), "other products never match");
    }

    #[test]
    fn sequence_needs_order_and_span() {
        let rules = Rules {
            matchers: vec![matcher()],
            sequences: vec![sequence()],
            advisories: vec![],
        };
        let events = vec![
            ev(
                "g",
                T0,
                "application",
                json!({"method": "GET", "path": "/"}),
            ),
            upload("u", T0 + 1000, "/api/upload?path=../../tmp/x"),
            hook_ev("h", T0 + 1010),
        ];
        let r = evaluate(&rules, &events, &[]);
        let ev_ = &r.evidence["FOILED-DEMO-0001"];
        assert!(ev_.iter().any(|e| e.source == EvidenceSource::Sequence));
        assert_eq!(
            r.matcher_hits["u"],
            vec!["foiled-demo-0001-upload-traversal".to_string()]
        );

        // Out of order: hook before the upload does not complete the sequence.
        let wrong = vec![
            ev(
                "g",
                T0,
                "application",
                json!({"method": "GET", "path": "/"}),
            ),
            hook_ev("h", T0 + 500),
            upload("u", T0 + 1000, "/api/upload?path=../../tmp/x"),
        ];
        let r = evaluate(&rules, &wrong, &[]);
        assert!(
            !r.evidence["FOILED-DEMO-0001"]
                .iter()
                .any(|e| e.source == EvidenceSource::Sequence)
        );
        // Too slow: steps further apart than max_span_ms.
        let slow = vec![
            ev(
                "g",
                T0,
                "application",
                json!({"method": "GET", "path": "/"}),
            ),
            upload("u", T0 + 700_000, "/api/upload?path=../x"),
            hook_ev("h", T0 + 700_010),
        ];
        let r = evaluate(&rules, &slow, &[]);
        assert!(
            !r.evidence["FOILED-DEMO-0001"]
                .iter()
                .any(|e| e.source == EvidenceSource::Sequence)
        );
    }

    #[test]
    fn signature_only_stays_medium_and_full_chain_reaches_high() {
        let rules = Rules {
            matchers: vec![matcher()],
            sequences: vec![sequence()],
            advisories: vec![],
        };
        let cfg = ConfidenceConfig::default();
        let probe = vec![upload("u", T0, "/api/upload?path=../x")];
        let r = evaluate(&rules, &probe, &[]);
        let l = score(
            &cfg,
            LinkKind::AttemptCve,
            "a",
            "FOILED-DEMO-0001",
            r.evidence["FOILED-DEMO-0001"].clone(),
            None,
        )
        .unwrap();
        assert!(l.band <= Band::Medium, "signature alone: {}", l.score);

        let chain = vec![
            ev(
                "g",
                T0,
                "application",
                json!({"method": "GET", "path": "/"}),
            ),
            upload("u", T0 + 1000, "/api/upload?path=../../tmp/x"),
            hook_ev("h", T0 + 1010),
        ];
        let r = evaluate(&rules, &chain, &[]);
        let mut evidence = r.evidence["FOILED-DEMO-0001"].clone();
        evidence.push(Evidence {
            signal_id: "hook:h".into(),
            source: EvidenceSource::VulnPathHook,
            weight: 100,
            summary: "hook".into(),
            reference: None,
        });
        let l = score(
            &cfg,
            LinkKind::AttemptCve,
            "a",
            "FOILED-DEMO-0001",
            evidence,
            None,
        )
        .unwrap();
        assert_eq!(
            l.band,
            Band::High,
            "signature + sequence + hook: {}",
            l.score
        );
    }

    #[test]
    fn auth_requirement_disambiguates_variants() {
        // Illustrative: two made-up CVEs on the same endpoint, one needing a
        // session and one not. These are not claims about real CVEs.
        let adv = |cve: &str, auth: &str| -> Advisory {
            serde_json::from_value(json!({
                "cve_id": cve, "catalogue_ids": ["foiled/demo-app/1.0.0"], "endpoint": "/api/upload",
                "auth_requirement": auth, "published_at": T0 + 86_400_000, "references": ["https://example.invalid/advisory"]
            }))
            .unwrap()
        };
        let rules = Rules {
            matchers: vec![],
            sequences: vec![],
            advisories: vec![adv("CVE-2099-0101", "unauth"), adv("CVE-2099-0102", "auth")],
        };
        let unauth = vec![upload("u", T0, "/api/upload?path=x")];
        let r = evaluate(&rules, &unauth, &[]);
        assert!(r.evidence.contains_key("CVE-2099-0101"));
        assert!(!r.evidence.contains_key("CVE-2099-0102"));
        let mut authed = upload("v", T0, "/api/upload?path=x");
        authed.data.insert("authenticated".into(), json!(true));
        let r = evaluate(&rules, &[authed], &[]);
        assert!(r.evidence.contains_key("CVE-2099-0102"));
        assert!(!r.evidence.contains_key("CVE-2099-0101"));
    }

    #[test]
    fn watchlist_backmatch_records_lead_time_and_alone_does_not_publish() {
        let entry: WatchlistEntry = serde_json::from_value(json!({
            "id": "wl-demo-upload", "catalogue_id": "foiled/demo-app/1.0.0",
            "pattern": [{"field": "data.path", "op": "prefix", "value": "/api/upload"}],
            "first_seen": T0, "last_seen": T0 + 3_600_000, "hits": 42, "distinct_sources": 3,
            "notes": "consistent non-generic uploads"
        }))
        .unwrap();
        let advisory: Advisory = serde_json::from_value(json!({
            "cve_id": "CVE-2099-0101", "catalogue_ids": ["foiled/demo-app/1.0.0"], "endpoint": "/api/upload",
            "auth_requirement": "unauth", "published_at": T0 + 6 * 86_400_000, "references": ["https://example.invalid/a"]
        }))
        .unwrap();
        let b = backmatch(&entry, &advisory).unwrap();
        assert!(b.first_seen < b.advisory_published_at);
        assert_eq!(b.lead_time_ms, 6 * 86_400_000);
        let r = evaluate(&Rules::default(), &[], &[b]);
        let l = score(
            &ConfidenceConfig::default(),
            LinkKind::AttemptCve,
            "a",
            "CVE-2099-0101",
            r.evidence["CVE-2099-0101"].clone(),
            None,
        )
        .unwrap();
        assert!(!l.publishable);
        let mut other = advisory.clone();
        other.catalogue_ids = vec!["emulator/redis/7.0".into()];
        assert!(backmatch(&entry, &other).is_none());
    }

    #[test]
    fn regex_conditions_never_match() {
        let c = Condition {
            field: "data.path".into(),
            op: Op::Regex,
            value: Some(json!(".*")),
            values: vec![],
            case_insensitive: false,
        };
        assert!(!c.holds(&upload("u", T0, "/x"), &None));
    }
}
