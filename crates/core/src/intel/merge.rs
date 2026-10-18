//! Indicators merged across UTC days for the TAXII object log (#13).
//!
//! The materialiser builds each UTC day on its own, but an indicator, its
//! sighting, its observable and (for a file) its malware instance can be
//! seen on several days. Built from one day's window they would differ by
//! day (first seen, sighting count, confidence), and whichever day ran last
//! would decide the stored version. Instead each day records an
//! [`IocContribution`] per IOC, and the published objects are built from
//! the merge of every day's contribution. [`IocContribution::merge`] is
//! associative and commutative, so the result depends only on the set of
//! contributions, never on the order days were built in.
//!
//! The merged indicator is scored with [`ioc_confidence`] over the union of
//! the days' evidence, with the same limits extraction applies to one
//! window (the first [`MAX_CONFIDENCE_ITEMS`] decoys and attempts by id), so
//! a week seen in one window and the same week merged from seven days score
//! the same. See `docs/intel-outputs.md#taxii-21`.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use super::payload_string;
use super::stix::{self, StixObject, foiled_id};
use crate::confidence::ConfidenceConfig;
use crate::ioc::{
    AttemptEvidence, FingerprintDetail, Ioc, IocOrigin, IocRole, IocType, MAX_CONFIDENCE_ITEMS,
    ioc_confidence,
};
use crate::share::Tlp;

/// Most `observed-data` references a merged sighting keeps (the smallest
/// ids), so merging stays bounded for an address seen in every attempt.
pub const MAX_OBSERVED_REFS: usize = 100;

/// One day's share of an IOC: what its published objects are built from.
/// Counts cover only the attempts the day owns (those whose first event is
/// in it), so adding the days' counts counts each attempt once.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IocContribution {
    pub ioc_id: String,
    pub ioc_type: IocType,
    pub value: String,
    pub display: String,
    pub roles: BTreeSet<IocRole>,
    pub redacted: bool,
    pub file_ioc_limited: bool,
    pub first_seen: i64,
    pub last_seen: i64,
    /// Events (attempts, for fingerprints) the value was seen in.
    pub sightings: u64,
    pub attempts: u64,
    pub campaign_ids: BTreeSet<String>,
    pub decoy_ids: BTreeSet<String>,
    pub catalogue_ids: BTreeSet<String>,
    pub extracted_from: BTreeSet<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fingerprint: Option<FingerprintDetail>,
    /// The first [`MAX_CONFIDENCE_ITEMS`] attempts by id and what each adds
    /// to confidence (the default when nothing).
    pub evidence: BTreeMap<String, AttemptEvidence>,
    /// The `observed-data` ids the IOC's attempts would have, smallest
    /// [`MAX_OBSERVED_REFS`]. A sighting names only those that are
    /// published.
    pub observed: BTreeSet<String>,
}

fn keep_first<T: Ord>(set: &mut BTreeSet<T>, n: usize) {
    while set.len() > n {
        set.pop_last();
    }
}

fn merge_evidence(a: &mut AttemptEvidence, b: AttemptEvidence) {
    a.hook = match (a.hook.take(), b.hook) {
        (Some(x), Some(y)) => Some(x.min(y)),
        (x, y) => x.or(y),
    };
    a.signature |= b.signature;
    a.noise = match (a.noise, b.noise) {
        (Some(x), Some(y)) => Some(x.min(y)),
        (x, y) => x.or(y),
    };
}

impl IocContribution {
    /// The contribution of `i` (an IOC extracted from one day's attempts
    /// only). `evidence` holds what each of those attempts adds to
    /// confidence; campaign ids not in `published_campaigns` are dropped,
    /// as `select` drops them.
    pub fn of(
        i: &Ioc,
        evidence: &BTreeMap<String, AttemptEvidence>,
        published_campaigns: &BTreeSet<String>,
    ) -> IocContribution {
        let attempts: BTreeSet<&String> = i.attempt_ids.iter().collect();
        let observed = attempts
            .iter()
            .take(MAX_OBSERVED_REFS)
            .map(|a| foiled_id("observed-data", a))
            .collect();
        IocContribution {
            ioc_id: i.ioc_id.clone(),
            ioc_type: i.ioc_type,
            value: i.value.clone(),
            display: i.display.clone(),
            roles: i.roles.iter().copied().collect(),
            redacted: i.redacted,
            file_ioc_limited: i.file_ioc_limited,
            first_seen: i.first_seen,
            last_seen: i.last_seen,
            sightings: u64::from(i.sightings),
            attempts: attempts.len() as u64,
            campaign_ids: i
                .campaign_ids
                .iter()
                .filter(|c| published_campaigns.contains(*c))
                .cloned()
                .collect(),
            decoy_ids: i.decoy_ids.iter().cloned().collect(),
            catalogue_ids: i.catalogue_ids.iter().cloned().collect(),
            extracted_from: i.extracted_from.iter().cloned().collect(),
            fingerprint: i.fingerprint.clone(),
            evidence: attempts
                .iter()
                .take(MAX_CONFIDENCE_ITEMS)
                .map(|a| ((*a).clone(), evidence.get(*a).cloned().unwrap_or_default()))
                .collect(),
            observed,
        }
    }

    /// Fold `other` (the same IOC) into this one. Associative and
    /// commutative: any order of merging gives the same result.
    pub fn merge(&mut self, other: IocContribution) {
        debug_assert_eq!(self.ioc_id, other.ioc_id);
        self.roles.extend(other.roles);
        self.redacted |= other.redacted;
        self.file_ioc_limited |= other.file_ioc_limited;
        self.first_seen = self.first_seen.min(other.first_seen);
        self.last_seen = self.last_seen.max(other.last_seen);
        self.sightings = self.sightings.saturating_add(other.sightings);
        self.attempts = self.attempts.saturating_add(other.attempts);
        self.campaign_ids.extend(other.campaign_ids);
        self.decoy_ids.extend(other.decoy_ids);
        self.catalogue_ids.extend(other.catalogue_ids);
        self.extracted_from.extend(other.extracted_from);
        self.fingerprint = match (self.fingerprint.take(), other.fingerprint) {
            (Some(a), Some(b)) => Some(if (a.version, &a.steps) <= (b.version, &b.steps) {
                a
            } else {
                b
            }),
            (a, b) => a.or(b),
        };
        for (aid, e) in other.evidence {
            match self.evidence.get_mut(&aid) {
                Some(mine) => merge_evidence(mine, e),
                None => {
                    self.evidence.insert(aid, e);
                }
            }
        }
        while self.evidence.len() > MAX_CONFIDENCE_ITEMS {
            self.evidence.pop_last();
        }
        self.observed.extend(other.observed);
        keep_first(&mut self.observed, MAX_OBSERVED_REFS);
    }

    /// The merged IOC, scored over all its evidence. `attempt_ids`,
    /// `event_ids` and `enrichment` are empty: the attempt count is
    /// [`IocContribution::attempts`] and enrichment is added by the caller.
    pub fn to_ioc(&self, cfg: &ConfidenceConfig) -> Ioc {
        let first_attempt = self.evidence.keys().next().cloned().unwrap_or_default();
        let confidence = ioc_confidence(
            cfg,
            &self.ioc_id,
            &first_attempt,
            self.decoy_ids.iter(),
            self.evidence.iter().map(|(a, e)| (a, Some(e))),
        );
        Ioc {
            ioc_id: self.ioc_id.clone(),
            ioc_type: self.ioc_type,
            value: self.value.clone(),
            display: self.display.clone(),
            roles: self.roles.iter().copied().collect(),
            origin: IocOrigin::Observed,
            redacted: self.redacted,
            file_ioc_limited: self.file_ioc_limited,
            first_seen: self.first_seen,
            last_seen: self.last_seen,
            sightings: u32::try_from(self.sightings).unwrap_or(u32::MAX),
            attempt_ids: vec![],
            campaign_ids: self.campaign_ids.iter().cloned().collect(),
            decoy_ids: self.decoy_ids.iter().cloned().collect(),
            catalogue_ids: self.catalogue_ids.iter().cloned().collect(),
            event_ids: vec![],
            extracted_from: self.extracted_from.iter().cloned().collect(),
            enrichment: vec![],
            fingerprint: self.fingerprint.clone(),
            confidence,
        }
    }

    /// Whether the merged IOC `ioc` (from [`IocContribution::to_ioc`])
    /// passes the default gate: publishable and not a payload string.
    pub fn published(ioc: &Ioc) -> bool {
        ioc.confidence.publishable && !payload_string(ioc)
    }

    /// The published objects for the merged IOC `ioc` (enrichment added):
    /// everything but the sighting, then the sighting, which names only the
    /// `observed-data` in `served`. Empty when the IOC does not pass the
    /// gate.
    pub fn objects(
        &self,
        ioc: &Ioc,
        served: &BTreeSet<String>,
        tlp: Tlp,
    ) -> (Vec<StixObject>, Option<StixObject>) {
        if !Self::published(ioc) {
            return (vec![], None);
        }
        let built = stix::ioc_objects(ioc, self.attempts as usize, tlp);
        let sighting = built.indicator.as_ref().map(|ind| {
            let v = stix::sighting(ioc, ind, self.observed.intersection(served), tlp);
            StixObject::new(&v, ioc.last_seen)
        });
        let mut objects: Vec<StixObject> = built
            .objects
            .iter()
            .map(|(v, t)| StixObject::new(v, *t))
            .collect();
        objects.sort_by(|a, b| {
            (stix::rank(a.object_type()), a.id()).cmp(&(stix::rank(b.object_type()), b.id()))
        });
        (objects, sighting)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ioc::IocConfidence;

    fn contribution(day: i64, attempts: &[(&str, AttemptEvidence)]) -> IocContribution {
        IocContribution {
            ioc_id: "ioc_0123456789abcdef01234567".into(),
            ioc_type: IocType::Ip,
            value: "203.0.113.7".into(),
            display: "203[.]0[.]113[.]7".into(),
            roles: BTreeSet::from([IocRole::Source]),
            redacted: false,
            file_ioc_limited: false,
            first_seen: day,
            last_seen: day + 10,
            sightings: 2,
            attempts: attempts.len() as u64,
            campaign_ids: BTreeSet::new(),
            decoy_ids: BTreeSet::from([format!("dcy_{day}")]),
            catalogue_ids: BTreeSet::new(),
            extracted_from: BTreeSet::new(),
            fingerprint: None,
            evidence: attempts
                .iter()
                .map(|(a, e)| (a.to_string(), e.clone()))
                .collect(),
            observed: attempts
                .iter()
                .map(|(a, _)| foiled_id("observed-data", a))
                .collect(),
        }
    }

    fn hook() -> AttemptEvidence {
        AttemptEvidence {
            hook: Some(("h1".into(), "ev1".into())),
            signature: false,
            noise: Some(40),
        }
    }

    fn quiet(noise: u8) -> AttemptEvidence {
        AttemptEvidence {
            noise: Some(noise),
            ..Default::default()
        }
    }

    fn merged(order: &[&IocContribution]) -> IocContribution {
        let mut it = order.iter();
        let mut m = (*it.next().unwrap()).clone();
        for c in it {
            m.merge((*c).clone());
        }
        m
    }

    #[test]
    fn merging_ignores_order_and_grouping() {
        let a = contribution(100, &[("att_a", hook())]);
        let b = contribution(200, &[("att_b", quiet(90)), ("att_c", quiet(10))]);
        let c = contribution(300, &[("att_d", quiet(50))]);
        let abc = merged(&[&a, &b, &c]);
        assert_eq!(abc, merged(&[&c, &b, &a]));
        assert_eq!(abc, merged(&[&b, &a, &c]));
        let mut bc = b.clone();
        bc.merge(c.clone());
        let mut a_bc = a.clone();
        a_bc.merge(bc);
        assert_eq!(abc, a_bc);
        assert_eq!(abc.first_seen, 100);
        assert_eq!(abc.last_seen, 310);
        assert_eq!(abc.sightings, 6);
        assert_eq!(abc.attempts, 4);
        assert_eq!(abc.decoy_ids.len(), 3);
        let cfg = ConfidenceConfig::default();
        assert_eq!(abc.to_ioc(&cfg), merged(&[&c, &a, &b]).to_ioc(&cfg));
    }

    #[test]
    fn confidence_is_scored_over_every_days_evidence() {
        let cfg = ConfidenceConfig::default();
        let a = contribution(100, &[("att_a", hook())]);
        let b = contribution(200, &[("att_b", quiet(90))]);
        let one = a.to_ioc(&cfg).confidence;
        let both = merged(&[&a, &b]).to_ioc(&cfg).confidence;
        // The same as scoring both attempts and decoys in one window.
        let direct: IocConfidence = ioc_confidence(
            &cfg,
            &a.ioc_id,
            "att_a",
            [String::from("dcy_100"), String::from("dcy_200")].iter(),
            [
                (&String::from("att_a"), Some(&hook())),
                (&String::from("att_b"), Some(&quiet(90))),
            ]
            .into_iter(),
        );
        assert_eq!(both, direct);
        assert!(one.score > 0);
    }

    #[test]
    fn limits_hold_after_merging() {
        let many: Vec<(String, AttemptEvidence)> = (0..40)
            .map(|n| (format!("att_{n:03}"), quiet(n as u8)))
            .collect();
        let refs: Vec<(&str, AttemptEvidence)> =
            many.iter().map(|(a, e)| (a.as_str(), e.clone())).collect();
        let mut evens = contribution(1, &[]);
        let mut odds = contribution(2, &[]);
        for (n, (a, e)) in refs.iter().enumerate() {
            let target = if n % 2 == 0 { &mut evens } else { &mut odds };
            target.evidence.insert(a.to_string(), e.clone());
            target.observed.insert(foiled_id("observed-data", a));
        }
        // Each day keeps its own first 16, as `of` does.
        for c in [&mut evens, &mut odds] {
            while c.evidence.len() > MAX_CONFIDENCE_ITEMS {
                c.evidence.pop_last();
            }
        }
        let m = merged(&[&odds, &evens]);
        let want: Vec<String> = (0..16).map(|n| format!("att_{n:03}")).collect();
        assert_eq!(m.evidence.keys().cloned().collect::<Vec<_>>(), want);
        assert!(m.observed.len() <= MAX_OBSERVED_REFS);
    }

    #[test]
    fn unpublishable_iocs_build_nothing() {
        let cfg = ConfidenceConfig::default();
        // Decoy prior and a noisy source only: never publishable alone.
        let c = contribution(100, &[("att_a", quiet(90))]);
        let ioc = c.to_ioc(&cfg);
        assert!(!ioc.confidence.publishable);
        assert!(c.objects(&ioc, &BTreeSet::new(), Tlp::Amber).0.is_empty());
        let h = contribution(100, &[("att_a", hook())]);
        let ioc = h.to_ioc(&cfg);
        assert!(ioc.confidence.publishable, "{:?}", ioc.confidence);
        let (objs, sighting) = h.objects(&ioc, &h.observed, Tlp::Amber);
        assert!(objs.iter().any(|o| o.object_type() == "indicator"));
        let s = sighting.unwrap().value();
        assert_eq!(s["count"], 2);
        // A sighting names only published observed-data.
        let none = h
            .objects(&ioc, &BTreeSet::new(), Tlp::Amber)
            .1
            .unwrap()
            .value();
        assert!(none.get("observed_data_refs").is_none());
        assert_eq!(s["observed_data_refs"].as_array().unwrap().len(), 1);
        let ind = objs
            .iter()
            .find(|o| o.object_type() == "indicator")
            .unwrap();
        let d = ind.value()["description"].as_str().unwrap().to_string();
        assert!(d.contains("in 1 attempt (2 sightings)"), "{d}");
    }
}
