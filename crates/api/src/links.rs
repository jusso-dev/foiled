//! Confidence links for one attempt (#27): gather evidence from what the
//! control plane already knows and score it with `foiled_core::confidence`.
//!
//! Evidence today: vulnerable-path hook hits (#32), CVE mapping tiers 1, 2
//! and 5 (#12, `foiled_core::cvemap`), the catalogue entry's CVEs and
//! expected techniques as priors (#5), the attempt's noise score (#25) and
//! ATT&CK rule matches (#26). Pre-disclosure back-matches (#12 tier 4),
//! enrichment (#11) and LLM proposals (#28) plug into the same evidence list.

use std::collections::BTreeMap;
use std::sync::OnceLock;

use foiled_core::attack::{AttackRule, evaluate};
use foiled_core::attempt::{Attempt, AttemptState, ExtraSignals, StateSignal};
use foiled_core::capture::CaptureEvent;
use foiled_core::catalogue::CatalogueEntry;
use foiled_core::confidence::{
    ConfidenceConfig, ConfidenceLink, Evidence, EvidenceSource, LinkKind, Override, score,
};
use foiled_core::cvemap::Rules;

static RULES: &str = include_str!(concat!(env!("OUT_DIR"), "/attack_rules.json"));
static MATCHERS: &str = include_str!(concat!(env!("OUT_DIR"), "/matchers.json"));
static SEQUENCES: &str = include_str!(concat!(env!("OUT_DIR"), "/sequences.json"));
static ADVISORIES: &str = include_str!(concat!(env!("OUT_DIR"), "/advisories.json"));

/// The ATT&CK rules bundled at build time. Validated by `foiled-lint` in CI,
/// so a parse failure is a build bug.
pub fn attack_rules() -> &'static [AttackRule] {
    static PARSED: OnceLock<Vec<AttackRule>> = OnceLock::new();
    PARSED.get_or_init(|| serde_json::from_str(RULES).expect("bundled ATT&CK rules parse"))
}

/// The CVE mapping rule packs bundled at build time, validated by
/// `foiled-lint` in CI.
pub fn cve_rules() -> &'static Rules {
    static PARSED: OnceLock<Rules> = OnceLock::new();
    PARSED.get_or_init(|| Rules {
        matchers: serde_json::from_str(MATCHERS).expect("bundled matchers parse"),
        sequences: serde_json::from_str(SEQUENCES).expect("bundled sequences parse"),
        advisories: serde_json::from_str(ADVISORIES).expect("bundled advisories parse"),
    })
}

/// Event ids a tier 1 signature matched, as attempt state signals: a
/// signature hit moves an attempt to `exploit` (#25).
pub fn matcher_signals(events: &[CaptureEvent]) -> ExtraSignals {
    let mut out = ExtraSignals::new();
    for m in &cve_rules().matchers {
        for e in events.iter().filter(|e| m.matches(e)) {
            out.insert(e.event_id.clone(), vec![StateSignal::Matcher]);
        }
    }
    out
}

fn ev(
    signal_id: String,
    source: EvidenceSource,
    weight: u8,
    summary: String,
    reference: Option<String>,
) -> Evidence {
    Evidence {
        signal_id,
        source,
        weight,
        summary,
        reference,
    }
}

/// Every link for one attempt, CVEs first then techniques, each sorted by
/// target. `overrides` are analyst decisions keyed by kind and target.
pub fn links_for_attempt(
    cfg: &ConfidenceConfig,
    entry: Option<&CatalogueEntry>,
    attempt: &Attempt,
    events: &[CaptureEvent],
    overrides: &BTreeMap<(LinkKind, String), Override>,
) -> Vec<ConfidenceLink> {
    let noise = attempt.noise.as_ref().map(|n| {
        ev(
            format!("noise:{}", attempt.src),
            EvidenceSource::NoiseScore,
            n.score,
            format!("source noise score {} ({:?})", n.score, n.band).to_lowercase(),
            None,
        )
    });

    // CVEs.
    let mut cves: BTreeMap<String, Vec<Evidence>> = BTreeMap::new();
    for h in &attempt.hook_hits {
        if let Some(cve) = &h.cve_id {
            cves.entry(cve.clone()).or_default().push(ev(
                format!("hook:{}:{}", h.hook_id, h.event_id),
                EvidenceSource::VulnPathHook,
                100,
                format!("vulnerable-path hook {} fired at {:?}", h.hook_id, h.stage).to_lowercase(),
                Some(h.event_id.clone()),
            ));
        }
    }
    let tiers = foiled_core::cvemap::evaluate(cve_rules(), events, &[]);
    for (cve, list) in tiers.evidence {
        cves.entry(cve).or_default().extend(list);
    }
    if let Some(entry) = entry {
        // The decoy was stood up for these CVEs. A prior on its own never
        // publishes; it is only attached once the attempt got past probing
        // or another signal exists for the CVE.
        for c in &entry.cves {
            if attempt.state > AttemptState::Probe || cves.contains_key(&c.cve_id) {
                cves.entry(c.cve_id.clone()).or_default().push(ev(
                    format!("catalogue:{}", entry.id),
                    EvidenceSource::CataloguePrior,
                    100,
                    format!("decoy {} is catalogued for {}", entry.id, c.cve_id),
                    None,
                ));
            }
        }
    }

    // Techniques.
    let mut techniques: BTreeMap<String, Vec<Evidence>> = BTreeMap::new();
    // ATT&CK rules see which signatures matched as `data.matcher_id` (#26).
    let annotated: Vec<CaptureEvent> = events
        .iter()
        .cloned()
        .map(|mut e| {
            if let Some(ids) = tiers.matcher_hits.get(&e.event_id) {
                e.data
                    .insert("matcher_id".into(), serde_json::Value::from(ids[0].clone()));
            }
            e
        })
        .collect();
    for link in evaluate(attack_rules(), &annotated) {
        let id = link.official_id().to_string();
        for s in &link.matched_signals {
            techniques.entry(id.clone()).or_default().push(ev(
                format!("attack:{}:{}", s.rule_id, s.event_id),
                EvidenceSource::Rule,
                s.weight,
                s.summary.clone(),
                Some(s.event_id.clone()),
            ));
        }
    }
    if let Some(entry) = entry {
        for t in &entry.expected_techniques {
            if let Some(list) = techniques.get_mut(t) {
                list.push(ev(
                    format!("catalogue:{}", entry.id),
                    EvidenceSource::CataloguePrior,
                    100,
                    format!("catalogue expects {t} for this decoy"),
                    None,
                ));
            }
        }
    }

    let mut out = Vec::new();
    for (kind, groups) in [
        (LinkKind::AttemptCve, cves),
        (LinkKind::AttemptTechnique, techniques),
    ] {
        for (target, mut evidence) in groups {
            if let Some(n) = &noise {
                evidence.push(n.clone());
            }
            let o = overrides.get(&(kind, target.clone())).cloned();
            if let Some(link) = score(cfg, kind, &attempt.attempt_id, &target, evidence, o) {
                out.push(link);
            }
        }
    }
    out
}
