//! The confidence layer (#27): one scoring model for every link Foiled
//! asserts (attempt to CVE, technique, actor or campaign).
//!
//! Deterministic: the same evidence and config always give the same score.
//! Every contribution and every cap is listed in the explanation, so LLM or
//! pre-disclosure involvement can never be hidden. See `docs/confidence.md`.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LinkKind {
    AttemptCve,
    AttemptTechnique,
    AttemptActor,
    AttemptCampaign,
}

/// Where a piece of evidence came from. Producers: #12 (rule, sequence,
/// vuln_path_hook, vendor_desc, predisclosure_backmatch, catalogue_prior),
/// #11 (enrichment), #25 (noise_score), #28 (llm), #33 (campaign_cluster),
/// #26 (rule, for techniques), analysts (analyst).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceSource {
    Rule,
    Sequence,
    VulnPathHook,
    CataloguePrior,
    VendorDesc,
    PredisclosureBackmatch,
    Enrichment,
    Llm,
    Analyst,
    CampaignCluster,
    NoiseScore,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Evidence {
    pub signal_id: String,
    pub source: EvidenceSource,
    /// How strong this signal is on its own, 0 to 100. For `noise_score`
    /// this is the noise score (100 is pure mass scanning).
    pub weight: u8,
    pub summary: String,
    #[serde(default, rename = "ref", skip_serializing_if = "Option::is_none")]
    pub reference: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Band {
    Low,
    Medium,
    High,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Feedback {
    TruePositive,
    FalsePositive,
    Unsure,
}

/// An audited analyst decision on one link.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Override {
    pub feedback: Feedback,
    pub analyst_id: String,
    pub at: i64,
    pub note: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Thresholds {
    pub medium: u8,
    pub high: u8,
    pub publish_min: u8,
    pub ui_highlight_min: u8,
    pub auto_state_promote_min: u8,
    pub radar_queue_min: u8,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceWeight {
    /// Points a full-strength signal from this source adds.
    pub points: u8,
    /// Most this source can add however many signals it has.
    pub cap: u8,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConfidenceConfig {
    pub version: u32,
    pub thresholds: Thresholds,
    pub weights: BTreeMap<EvidenceSource, SourceWeight>,
    /// Most the noise score can take off a link.
    pub noise_max_penalty: u8,
}

impl Default for ConfidenceConfig {
    /// Mirrors `configs/confidence.yaml`; a test keeps them equal.
    fn default() -> Self {
        use EvidenceSource::*;
        let w = |points, cap| SourceWeight { points, cap };
        ConfidenceConfig {
            version: 1,
            thresholds: Thresholds {
                medium: 40,
                high: 70,
                publish_min: 60,
                ui_highlight_min: 50,
                auto_state_promote_min: 70,
                radar_queue_min: 40,
            },
            weights: BTreeMap::from([
                (VulnPathHook, w(60, 60)),
                (Sequence, w(40, 45)),
                (Rule, w(30, 40)),
                (VendorDesc, w(15, 15)),
                (CataloguePrior, w(10, 10)),
                (PredisclosureBackmatch, w(25, 25)),
                (Enrichment, w(10, 15)),
                (Llm, w(20, 20)),
                (CampaignCluster, w(15, 20)),
                (Analyst, w(0, 0)),
                (NoiseScore, w(0, 0)),
            ]),
            noise_max_penalty: 20,
        }
    }
}

impl ConfidenceConfig {
    pub fn problems(&self) -> Vec<String> {
        let mut out = Vec::new();
        let t = &self.thresholds;
        if !(t.medium < t.high && t.high <= 100) {
            out.push("thresholds must satisfy medium < high <= 100".into());
        }
        if let Some(llm) = self.weights.get(&EvidenceSource::Llm)
            && llm.cap >= t.high
        {
            out.push("llm cap must stay below the high threshold".into());
        }
        if let Some(p) = self.weights.get(&EvidenceSource::PredisclosureBackmatch)
            && p.cap >= t.publish_min
        {
            out.push("predisclosure_backmatch cap must stay below publish_min".into());
        }
        for (s, w) in &self.weights {
            if w.cap > 100 || w.points > 100 {
                out.push(format!("{s:?} points and cap must be at most 100"));
            }
        }
        out
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Contribution {
    pub source: EvidenceSource,
    /// Signed points this source added to the score.
    pub points: i32,
    pub signal_ids: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfidenceLink {
    pub kind: LinkKind,
    pub attempt_id: String,
    /// CVE id, technique id, actor label or campaign id.
    pub target: String,
    pub score: u8,
    pub band: Band,
    /// The phrase UI and exports must use for this link.
    pub wording: String,
    pub evidence: Vec<Evidence>,
    pub contributions: Vec<Contribution>,
    /// Plain-language notes about every cap that changed the score.
    pub caps_applied: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub r#override: Option<Override>,
    pub publishable: bool,
    pub ui_highlight: bool,
    pub auto_state_promote: bool,
    pub radar_queue: bool,
}

fn wording(kind: LinkKind, band: Band, confirmed: bool) -> &'static str {
    match (kind, confirmed) {
        (LinkKind::AttemptCve | LinkKind::AttemptTechnique, true) => "confirmed",
        (LinkKind::AttemptCve | LinkKind::AttemptTechnique, false) => "we assess as",
        // Actors keep the cautious phrase unless high and analyst-confirmed (#29).
        (LinkKind::AttemptActor, true) if band == Band::High => "confirmed association",
        (LinkKind::AttemptActor, _) => "possible association",
        (LinkKind::AttemptCampaign, true) => "confirmed",
        (LinkKind::AttemptCampaign, false) => "possible",
    }
}

/// Score one link. `evidence` must not be empty.
pub fn score(
    cfg: &ConfidenceConfig,
    kind: LinkKind,
    attempt_id: &str,
    target: &str,
    evidence: Vec<Evidence>,
    analyst: Option<Override>,
) -> Option<ConfidenceLink> {
    if evidence.is_empty() {
        return None;
    }
    let mut by_source: BTreeMap<EvidenceSource, Vec<&Evidence>> = BTreeMap::new();
    for e in &evidence {
        by_source.entry(e.source).or_default().push(e);
    }
    let mut contributions = Vec::new();
    let mut caps = Vec::new();
    let mut total: i32 = 0;
    for (source, items) in &by_source {
        if matches!(source, EvidenceSource::NoiseScore | EvidenceSource::Analyst) {
            continue;
        }
        let Some(w) = cfg.weights.get(source) else {
            continue;
        };
        // Strongest signal counts fully; each further one adds a quarter of
        // its share, so repeats help a little but cannot run away.
        let mut strengths: Vec<u8> = items.iter().map(|e| e.weight.min(100)).collect();
        strengths.sort_unstable_by(|a, b| b.cmp(a));
        let raw: f64 = strengths
            .iter()
            .enumerate()
            .map(|(i, s)| {
                let share = f64::from(w.points) * f64::from(*s) / 100.0;
                if i == 0 { share } else { share / 4.0 }
            })
            .sum();
        let mut pts = raw.round() as i32;
        if pts > i32::from(w.cap) {
            caps.push(format!("{source:?} capped at {} points", w.cap));
            pts = i32::from(w.cap);
        }
        total += pts;
        contributions.push(Contribution {
            source: *source,
            points: pts,
            signal_ids: items.iter().map(|e| e.signal_id.clone()).collect(),
        });
    }

    // Noise lowers confidence in a targeted reading, but never below what a
    // vulnerable-path hook or a signature established on its own.
    if let Some(noise) = by_source.get(&EvidenceSource::NoiseScore) {
        let n = noise.iter().map(|e| e.weight).max().unwrap_or(0);
        let penalty = (f64::from(cfg.noise_max_penalty) * f64::from(n) / 100.0).round() as i32;
        let floor = contributions
            .iter()
            .filter(|c| {
                matches!(
                    c.source,
                    EvidenceSource::VulnPathHook | EvidenceSource::Rule
                )
            })
            .map(|c| c.points)
            .max()
            .unwrap_or(0);
        let after = (total - penalty).max(floor.min(total));
        if penalty > 0 {
            contributions.push(Contribution {
                source: EvidenceSource::NoiseScore,
                points: after - total,
                signal_ids: noise.iter().map(|e| e.signal_id.clone()).collect(),
            });
            if after != total - penalty {
                caps.push("noise penalty limited so it cannot cancel a hook or signature".into());
            }
        }
        total = after;
    }

    let only = |allowed: &[EvidenceSource]| {
        by_source
            .keys()
            .all(|s| allowed.contains(s) || *s == EvidenceSource::NoiseScore)
    };
    let t = cfg.thresholds;
    // LLM proposals alone can never reach high (#28).
    if only(&[EvidenceSource::Llm, EvidenceSource::CataloguePrior])
        && by_source.contains_key(&EvidenceSource::Llm)
        && total >= i32::from(t.high)
    {
        total = i32::from(t.high) - 1;
        caps.push("LLM-only evidence capped below high".into());
    }
    // Pre-disclosure back-matches alone stay below publish until reviewed.
    let predisclosure_only = only(&[
        EvidenceSource::PredisclosureBackmatch,
        EvidenceSource::CataloguePrior,
    ]) && by_source.contains_key(&EvidenceSource::PredisclosureBackmatch);
    let llm_only = only(&[EvidenceSource::Llm, EvidenceSource::CataloguePrior])
        && by_source.contains_key(&EvidenceSource::Llm);
    if predisclosure_only && total >= i32::from(t.publish_min) {
        total = i32::from(t.publish_min) - 1;
        caps.push("pre-disclosure evidence alone capped below publish".into());
    }
    let catalogue_only = only(&[EvidenceSource::CataloguePrior]);

    let mut score = total.clamp(0, 100) as u8;
    let mut confirmed = false;
    let mut suppressed = false;
    if let Some(o) = &analyst {
        match o.feedback {
            Feedback::TruePositive => {
                score = 100;
                confirmed = true;
            }
            Feedback::FalsePositive => {
                score = 0;
                suppressed = true;
            }
            Feedback::Unsure => {}
        }
    }
    let band = if score >= t.high {
        Band::High
    } else if score >= t.medium {
        Band::Medium
    } else {
        Band::Low
    };
    let reviewed = matches!(
        analyst.as_ref().map(|o| o.feedback),
        Some(Feedback::TruePositive)
    );
    // Never auto-publish below publish_min, and never publish LLM-only,
    // pre-disclosure-only or catalogue-only links without an analyst.
    let publishable = !suppressed
        && score >= t.publish_min
        && (reviewed || !(llm_only || predisclosure_only || catalogue_only));
    Some(ConfidenceLink {
        kind,
        attempt_id: attempt_id.to_string(),
        target: target.to_string(),
        score,
        band,
        wording: wording(kind, band, confirmed).to_string(),
        evidence,
        contributions,
        caps_applied: caps,
        r#override: analyst,
        publishable,
        ui_highlight: !suppressed && score >= t.ui_highlight_min,
        auto_state_promote: !suppressed && score >= t.auto_state_promote_min && !llm_only,
        radar_queue: !suppressed && score >= t.radar_queue_min,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use EvidenceSource::*;

    fn ev(id: &str, source: EvidenceSource, weight: u8) -> Evidence {
        Evidence {
            signal_id: id.into(),
            source,
            weight,
            summary: format!("{source:?}"),
            reference: None,
        }
    }

    fn cve(evidence: Vec<Evidence>, o: Option<Override>) -> ConfidenceLink {
        score(
            &ConfidenceConfig::default(),
            LinkKind::AttemptCve,
            "att_1",
            "FOILED-DEMO-0001",
            evidence,
            o,
        )
        .unwrap()
    }

    #[test]
    fn default_config_is_consistent() {
        assert!(ConfidenceConfig::default().problems().is_empty());
    }

    #[test]
    fn hook_plus_sequence_is_high_and_publishable() {
        let l = cve(
            vec![ev("h", VulnPathHook, 100), ev("s", Sequence, 90)],
            None,
        );
        assert_eq!(l.band, Band::High);
        assert!(l.publishable);
        assert_eq!(
            l.wording, "we assess as",
            "unconfirmed until an analyst says so"
        );
    }

    #[test]
    fn signature_only_is_medium() {
        let l = cve(vec![ev("m", Rule, 100), ev("c", CataloguePrior, 100)], None);
        assert_eq!(l.score, 40);
        assert_eq!(l.band, Band::Medium);
        assert!(!l.publishable);
    }

    #[test]
    fn predisclosure_alone_does_not_publish() {
        let l = cve(
            vec![
                ev("p", PredisclosureBackmatch, 100),
                ev("c", CataloguePrior, 100),
            ],
            None,
        );
        assert!(l.score < 60);
        assert!(!l.publishable);
    }

    #[test]
    fn llm_only_is_capped_and_never_publishes() {
        let mut cfg = ConfidenceConfig::default();
        // Even a misconfigured, generous LLM weight cannot reach high alone.
        cfg.weights.insert(
            Llm,
            SourceWeight {
                points: 100,
                cap: 100,
            },
        );
        let l = score(
            &cfg,
            LinkKind::AttemptCve,
            "a",
            "CVE-2099-0001",
            vec![ev("l", Llm, 100)],
            None,
        )
        .unwrap();
        assert_eq!(l.score, 69);
        assert!(l.caps_applied.iter().any(|c| c.contains("LLM-only")));
        assert!(!l.publishable);
        assert!(!l.auto_state_promote);
        let def = cve(vec![ev("l", Llm, 100)], None);
        assert_eq!(def.score, 20, "default LLM maximum contribution is 20");
    }

    #[test]
    fn analyst_confirm_flips_wording_and_false_positive_suppresses() {
        let tp = Override {
            feedback: Feedback::TruePositive,
            analyst_id: "analyst".into(),
            at: 1,
            note: "seen in pcap".into(),
        };
        let l = cve(vec![ev("m", Rule, 100)], Some(tp.clone()));
        assert_eq!((l.score, l.wording.as_str()), (100, "confirmed"));
        assert!(l.publishable);
        let fp = Override {
            feedback: Feedback::FalsePositive,
            ..tp
        };
        let l = cve(vec![ev("h", VulnPathHook, 100)], Some(fp));
        assert_eq!(l.score, 0);
        assert!(!l.publishable && !l.ui_highlight && !l.radar_queue);
    }

    #[test]
    fn noise_lowers_but_cannot_cancel_a_hook() {
        let quiet = cve(
            vec![ev("h", VulnPathHook, 100), ev("s", Sequence, 50)],
            None,
        );
        let noisy = cve(
            vec![
                ev("h", VulnPathHook, 100),
                ev("s", Sequence, 50),
                ev("n", NoiseScore, 100),
            ],
            None,
        );
        assert!(noisy.score < quiet.score);
        assert!(noisy.score >= 60, "hook contribution is the floor");
        let floor_hit = cve(
            vec![ev("h", VulnPathHook, 100), ev("n", NoiseScore, 100)],
            None,
        );
        assert_eq!(floor_hit.score, 60);
        assert!(floor_hit.caps_applied.iter().any(|c| c.contains("noise")));
    }

    #[test]
    fn actor_links_keep_cautious_wording() {
        let tp = Override {
            feedback: Feedback::TruePositive,
            analyst_id: "a".into(),
            at: 1,
            note: String::new(),
        };
        let cfg = ConfidenceConfig::default();
        let l = score(
            &cfg,
            LinkKind::AttemptActor,
            "a",
            "cluster-x",
            vec![ev("r", Rule, 100)],
            None,
        )
        .unwrap();
        assert_eq!(l.wording, "possible association");
        let l = score(
            &cfg,
            LinkKind::AttemptActor,
            "a",
            "cluster-x",
            vec![ev("r", Rule, 100)],
            Some(tp),
        )
        .unwrap();
        assert_eq!(l.wording, "confirmed association");
    }

    #[test]
    fn deterministic_and_repeats_have_diminishing_returns() {
        let one = cve(vec![ev("m1", Rule, 100)], None);
        let three = cve(
            vec![
                ev("m1", Rule, 100),
                ev("m2", Rule, 100),
                ev("m3", Rule, 100),
            ],
            None,
        );
        assert!(
            three.score > one.score && three.score <= 40,
            "{}",
            three.score
        );
        assert_eq!(
            three,
            cve(
                vec![
                    ev("m1", Rule, 100),
                    ev("m2", Rule, 100),
                    ev("m3", Rule, 100)
                ],
                None
            )
        );
        assert!(
            score(
                &ConfidenceConfig::default(),
                LinkKind::AttemptCve,
                "a",
                "x",
                vec![],
                None
            )
            .is_none()
        );
    }
}
