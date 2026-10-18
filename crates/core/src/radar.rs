//! The radar (#35): aggregated, privacy-safe, confidence-gated counts and
//! trends per CVE, technique, campaign and product over time.
//!
//! Two steps, both pure:
//!
//! 1. [`observe`] turns one tenant's attempts for one closed UTC day into
//!    [`RadarPoint`]s: one per key, sensor and (hashed) source, with the
//!    best confidence seen. The API stores these as daily rollups in
//!    Postgres and writes them to Analytics Engine ([`analytics_point`]).
//! 2. [`aggregate`] reads rollups for a window and applies the share policy
//!    (`configs/contribute-back.yaml`, `radar`): which sensors may count,
//!    the confidence gate, minimum distinct sources, sensors and edge
//!    tenants per bucket (k-anonymity), checked again on every filtered
//!    slice so totals cannot be differenced. Only counts leave: never a
//!    tenant, sensor, source or attempt.
//!
//! Headline cards are built from publishable counts only, so a low
//! confidence or LLM-only link never becomes a headline. See
//! `docs/radar.md`.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::attempt::{Attempt, AttemptState};
use crate::campaign::Campaign;
use crate::confidence::{Band, ConfidenceConfig, ConfidenceLink, EvidenceSource, LinkKind};
use crate::share::{self, RadarPolicy, SensorKind};

pub const DAY_MS: i64 = 86_400_000;
/// Longest window [`aggregate`] accepts, in days (Analytics Engine keeps
/// about three months; longer trends come from the Postgres rollups).
pub const MAX_WINDOW_DAYS: i64 = 92;
pub const MAX_SERIES_PER_DIMENSION: usize = 100;
/// Analytics Engine index limit, in bytes.
const AE_INDEX_BYTES: usize = 96;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Dimension {
    Cve,
    Technique,
    Campaign,
    Product,
}

impl Dimension {
    pub const ALL: [Dimension; 4] = [
        Dimension::Cve,
        Dimension::Technique,
        Dimension::Campaign,
        Dimension::Product,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Dimension::Cve => "cve",
            Dimension::Technique => "technique",
            Dimension::Campaign => "campaign",
            Dimension::Product => "product",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|d| d.as_str() == s)
    }

    /// The phrase counts in this dimension carry (`docs/ui/voice.md`).
    pub fn wording(self) -> &'static str {
        match self {
            Dimension::Cve | Dimension::Technique => "we assess as",
            Dimension::Campaign => "possible",
            Dimension::Product => "observed",
        }
    }
}

/// One daily rollup row: attempts from one source at one sensor for one
/// key. Mirrors `schemas/radar-point.schema.json`. Stored per tenant;
/// never returned by any endpoint.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RadarPoint {
    /// UTC midnight, Unix ms.
    pub day: i64,
    pub tenant_id: String,
    /// Edge sensor id, or `decoy:<id>` for a research decoy.
    pub sensor: String,
    pub sensor_kind: SensorKind,
    /// The sensor's opt-in for the radar channel (#37).
    pub shared: bool,
    pub dimension: Dimension,
    /// CVE id, technique id, campaign id or `vendor/product`.
    pub key: String,
    /// The attempt's `vendor/product`, for the product filter.
    pub product: String,
    /// Hash of the source address ([`source_key`]).
    pub source: String,
    pub attempts: u32,
    pub score: u8,
    pub band: Band,
    /// The link passed the publish gate (#27): never LLM-only,
    /// pre-disclosure-only or catalogue-only without an analyst.
    pub publishable: bool,
    /// Pre-disclosure back-match evidence (#12) was part of the link.
    pub predisclosure: bool,
}

/// A one-way hash of a source address, used only to count distinct
/// sources. Not anonymous on its own (the IPv4 space is small), so it is
/// never output; see `docs/radar.md#privacy`.
pub fn source_key(src: &str) -> String {
    let h = Sha256::digest(format!("radar-source\n{src}").as_bytes());
    hex::encode(&h[..8])
}

/// UTC midnight at or before `ts`.
pub fn day_floor(ts: i64) -> i64 {
    ts.div_euclid(DAY_MS) * DAY_MS
}

/// `vendor/product` from a catalogue id like `vendor/product/1.0.0`.
pub fn product_key(catalogue_id: &str) -> String {
    let mut parts = catalogue_id.splitn(3, '/');
    match (parts.next(), parts.next()) {
        (Some(v), Some(p)) => format!("{v}/{p}"),
        _ => catalogue_id.to_string(),
    }
}

/// Where a sensor sits and whether it opted in, keyed by [`sensor_ref`].
/// Sensors missing from the map are edge sensors with the policy default
/// (off).
pub type SensorShare = BTreeMap<String, (SensorKind, bool)>;

/// The sensor an attempt came through: the edge sensor id, or
/// `decoy:<id>` for a decoy on a sandbox host.
pub fn sensor_ref(a: &Attempt) -> String {
    match &a.sensor_id {
        Some(id) => id.clone(),
        None => format!("decoy:{}", a.decoy_id),
    }
}

/// What [`observe`] reads for one tenant and one day.
pub struct ObserveInput<'a> {
    pub tenant_id: &'a str,
    /// Attempts whose `first_seen` falls in `[day, day + 1 day)` count.
    pub day: i64,
    pub attempts: &'a [Attempt],
    /// Scored links per attempt id (#27), with analyst overrides applied.
    pub links: &'a BTreeMap<String, Vec<ConfidenceLink>>,
    pub campaigns: &'a [Campaign],
    /// Kind and opt-in per [`sensor_ref`]; missing sensors are edge
    /// sensors with the default (off).
    pub sensors: &'a SensorShare,
    pub policy: &'a share::SharePolicy,
    pub confidence: &'a ConfidenceConfig,
}

fn band_of(cfg: &ConfidenceConfig, score: u8) -> Band {
    if score >= cfg.thresholds.high {
        Band::High
    } else if score >= cfg.thresholds.medium {
        Band::Medium
    } else {
        Band::Low
    }
}

/// Daily rollup points for one tenant. Links below the radar threshold
/// (`radar_queue_min`) and analyst-rejected links are left out entirely.
/// Output is sorted and merged, so the same input gives the same points.
pub fn observe(input: &ObserveInput) -> Vec<RadarPoint> {
    let day = day_floor(input.day);
    let campaigns: BTreeMap<&str, &Campaign> = input
        .campaigns
        .iter()
        .map(|c| (c.campaign_id.as_str(), c))
        .collect();
    type Key = (Dimension, String, String, String);
    let mut merged: BTreeMap<Key, RadarPoint> = BTreeMap::new();
    for a in input.attempts {
        if day_floor(a.first_seen) != day {
            continue;
        }
        // Only sensors the operator designated as research count as
        // research; anything else, including a tenant's own decoys, is
        // treated like an edge sensor: opt-in and every threshold.
        let sensor = sensor_ref(a);
        let (kind, shared) = input.sensors.get(&sensor).copied().unwrap_or((
            SensorKind::Edge,
            input.policy.default_opt_in(SensorKind::Edge),
        ));
        let product = product_key(&a.catalogue_id);
        let source = source_key(&a.src);
        let mut add = |dimension: Dimension,
                       key: String,
                       score: u8,
                       band: Band,
                       publishable: bool,
                       predisclosure: bool| {
            let p = merged
                .entry((dimension, key.clone(), sensor.clone(), source.clone()))
                .or_insert_with(|| RadarPoint {
                    day,
                    tenant_id: input.tenant_id.to_string(),
                    sensor: sensor.clone(),
                    sensor_kind: kind,
                    shared,
                    dimension,
                    key,
                    product: product.clone(),
                    source: source.clone(),
                    attempts: 0,
                    score: 0,
                    band: Band::Low,
                    publishable: false,
                    predisclosure: false,
                });
            p.attempts += 1;
            if score > p.score {
                p.score = score;
                p.band = band;
            }
            p.publishable |= publishable;
            p.predisclosure |= predisclosure;
        };
        let mut best = 0u8;
        for l in input.links.get(&a.attempt_id).into_iter().flatten() {
            let dimension = match l.kind {
                LinkKind::AttemptCve => Dimension::Cve,
                LinkKind::AttemptTechnique => Dimension::Technique,
                _ => continue,
            };
            if !l.radar_queue {
                continue;
            }
            best = best.max(l.score);
            let pre = l
                .evidence
                .iter()
                .any(|e| e.source == EvidenceSource::PredisclosureBackmatch);
            add(
                dimension,
                l.target.to_ascii_uppercase(),
                l.score,
                l.band,
                l.publishable,
                pre,
            );
        }
        if let Some(c) = a.campaign_id.as_deref().and_then(|id| campaigns.get(id))
            && c.confidence.score >= input.confidence.thresholds.radar_queue_min
        {
            add(
                Dimension::Campaign,
                c.campaign_id.clone(),
                c.confidence.score,
                c.confidence.band,
                c.confidence.publishable,
                false,
            );
        }
        // Products count attempts that got past probing: the gate is the
        // attempt state (#25), and the band is the best link's.
        if a.state >= AttemptState::Exploit {
            add(
                Dimension::Product,
                product.clone(),
                best,
                band_of(input.confidence, best),
                true,
                false,
            );
        }
    }
    merged.into_values().collect()
}

/// Who a feed is for. Decides which points may count and which limits
/// apply.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Audience {
    /// Operators of any tenant: the whole fleet, opted-in sensors only,
    /// every threshold, closed days only.
    Fleet,
    /// One tenant's own data: no cross-tenant thresholds, but the same
    /// confidence floor.
    Tenant,
}

#[derive(Debug, Clone, Default)]
pub struct Filter {
    pub dimension: Option<Dimension>,
    pub key: Option<String>,
    /// `vendor/product`.
    pub product: Option<String>,
    /// Most series per dimension.
    pub limit: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RadarDay {
    pub day: i64,
    pub attempts: u64,
    /// Attempts on publishable links only. Zero when the publishable or
    /// the other part of the day would fall below the thresholds on its
    /// own, so the split cannot single anyone out.
    pub publishable_attempts: u64,
    pub sources: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Direction {
    Up,
    Down,
    Flat,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Trend {
    pub direction: Direction,
    /// Second half of the window against the first, in percent.
    pub pct: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RadarSeries {
    pub dimension: Dimension,
    pub key: String,
    /// Display name where one is known (products), else the key.
    pub label: String,
    pub wording: String,
    pub total_attempts: u64,
    /// Distinct sources over the window, counted on shown days only.
    pub total_sources: u32,
    pub best_band: Band,
    pub first_day: i64,
    pub last_day: i64,
    /// One entry per day in the window, oldest first. Days below the
    /// thresholds are zero.
    pub days: Vec<RadarDay>,
    pub trend: Trend,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CardKind {
    /// A CVE we assess as targeted at high confidence, first shown in the
    /// last two days of the window.
    NewCveAssessment,
    /// A jump in attempts on a CVE link carried by pre-disclosure evidence.
    PredisclosureSpike,
    /// A campaign first shown in the last two days of the window.
    CampaignEmergence,
    /// A jump in attempts on any key.
    Spike,
}

/// A headline. Built from publishable counts only.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RadarCard {
    pub card_id: String,
    pub kind: CardKind,
    pub dimension: Dimension,
    pub key: String,
    pub day: i64,
    pub attempts: u64,
    pub sources: u32,
    pub headline: String,
}

/// The limits that applied, so a reader can see why counts are missing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppliedPolicy {
    pub min_sources: u32,
    pub min_sensors: u32,
    pub min_edge_tenants: u32,
    pub min_confidence: share::Band,
}

/// A radar feed. Mirrors `schemas/radar-feed.schema.json`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RadarFeed {
    pub audience: Audience,
    pub generated_at: i64,
    /// First day shown (UTC midnight).
    pub since: i64,
    /// Day after the last day shown: only closed days are shown.
    pub until: i64,
    pub policy: AppliedPolicy,
    pub series: Vec<RadarSeries>,
    pub cards: Vec<RadarCard>,
    /// Buckets (or filtered slices of buckets) held back by the thresholds.
    pub suppressed_buckets: u64,
    pub notes: Vec<String>,
}

fn to_share_band(b: Band) -> share::Band {
    match b {
        Band::Low => share::Band::Low,
        Band::Medium => share::Band::Medium,
        Band::High => share::Band::High,
    }
}

/// Why [`aggregate`] refused a window.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WindowError(pub String);

#[derive(Default)]
struct Bucket {
    attempts: u64,
    publishable_attempts: u64,
    sources: BTreeSet<String>,
    publishable_sources: BTreeSet<String>,
    best: Option<Band>,
    best_publishable: Option<Band>,
    predisclosure: bool,
}

/// Whether a set of rows may be shown on its own: enough distinct sources
/// and sensors, and enough tenants behind any edge rows in it.
fn passes(points: &[&RadarPoint], a: &AppliedPolicy) -> bool {
    if points.is_empty() {
        return false;
    }
    let sources: BTreeSet<&str> = points.iter().map(|p| p.source.as_str()).collect();
    let sensors: BTreeSet<(&str, &str)> = points
        .iter()
        .map(|p| (p.tenant_id.as_str(), p.sensor.as_str()))
        .collect();
    let edge: BTreeSet<&str> = points
        .iter()
        .filter(|p| p.sensor_kind == SensorKind::Edge)
        .map(|p| p.tenant_id.as_str())
        .collect();
    sources.len() >= a.min_sources as usize
        && sensors.len() >= a.min_sensors as usize
        && (edge.is_empty() || edge.len() >= a.min_edge_tenants as usize)
}

impl Bucket {
    /// Counts for rows that passed. The publishable part is counted only
    /// when `split_ok` (every (product, publishable) cell of the bucket
    /// passes); otherwise it is zero and makes no headline.
    fn from_points(points: &[&RadarPoint], split_ok: bool) -> Self {
        let mut b = Bucket::default();
        for p in points {
            b.attempts += u64::from(p.attempts);
            b.sources.insert(p.source.clone());
            b.best = b.best.max(Some(p.band));
            if split_ok && p.publishable {
                b.publishable_attempts += u64::from(p.attempts);
                b.publishable_sources.insert(p.source.clone());
                b.best_publishable = b.best_publishable.max(Some(p.band));
                b.predisclosure |= p.predisclosure;
            }
        }
        b
    }
}

/// Aggregate rollup points into a feed.
///
/// `tenant_id` is the caller's tenant for [`Audience::Tenant`] (points from
/// any other tenant are ignored, whatever the store returned) and ignored
/// otherwise. `since` and `until` are rounded to whole UTC days.
#[allow(clippy::too_many_arguments)]
pub fn aggregate(
    points: &[RadarPoint],
    audience: Audience,
    tenant_id: Option<&str>,
    policy: &RadarPolicy,
    since: i64,
    until: i64,
    now: i64,
    filter: &Filter,
    labels: &BTreeMap<(Dimension, String), String>,
) -> Result<RadarFeed, WindowError> {
    let since = day_floor(since);
    let requested_until = day_floor(until + DAY_MS - 1);
    if requested_until <= since || (requested_until - since) / DAY_MS > MAX_WINDOW_DAYS {
        return Err(WindowError(format!(
            "window must be positive and at most {MAX_WINDOW_DAYS} days"
        )));
    }
    // Only closed days.
    let until = requested_until.min(day_floor(now)).max(since);
    let tenant_view = audience == Audience::Tenant;
    let applied = AppliedPolicy {
        min_sources: if tenant_view { 1 } else { policy.min_sources },
        min_sensors: if tenant_view { 1 } else { policy.min_sensors },
        min_edge_tenants: if tenant_view {
            1
        } else {
            policy.min_edge_tenants
        },
        min_confidence: policy.min_confidence,
    };
    let mut notes = Vec::new();
    if !policy.enabled && !tenant_view {
        notes.push("The radar is switched off in the share policy.".into());
    }

    // Every filter except the product one picks whole buckets. The product
    // filter cuts a slice out of each bucket, so it is applied after the
    // thresholds, below.
    type BKey = (Dimension, String, i64);
    let counted = |p: &&RadarPoint| -> bool {
        if p.day < since || p.day >= until {
            return false;
        }
        if to_share_band(p.band) < policy.min_confidence {
            return false;
        }
        if filter.dimension.is_some_and(|d| d != p.dimension) {
            return false;
        }
        if filter
            .key
            .as_deref()
            .is_some_and(|k| !k.eq_ignore_ascii_case(&p.key))
        {
            return false;
        }
        match audience {
            Audience::Tenant => tenant_id.is_some_and(|t| t == p.tenant_id),
            Audience::Fleet => {
                policy.enabled && p.shared && policy.sensor_kinds.contains(&p.sensor_kind)
            }
        }
    };
    let mut grouped: BTreeMap<BKey, Vec<&RadarPoint>> = BTreeMap::new();
    for p in points.iter().filter(counted) {
        grouped
            .entry((p.dimension, p.key.clone(), p.day))
            .or_default()
            .push(p);
    }
    let mut suppressed = 0u64;
    let mut shown: BTreeMap<(Dimension, String), BTreeMap<i64, Bucket>> = BTreeMap::new();
    for ((d, key, day), all) in grouped {
        // Edge rows count only when enough tenants share the bucket.
        let edge_tenants: BTreeSet<&str> = all
            .iter()
            .filter(|p| p.sensor_kind == SensorKind::Edge)
            .map(|p| p.tenant_id.as_str())
            .collect();
        let kept: Vec<&RadarPoint> = all
            .into_iter()
            .filter(|p| {
                p.sensor_kind != SensorKind::Edge
                    || edge_tenants.len() >= applied.min_edge_tenants as usize
            })
            .collect();
        if !passes(&kept, &applied) {
            suppressed += 1;
            continue;
        }
        // Every number the feed can show for this bucket is a sum of cells
        // (product, publishable). If each cell that can be shown passes on
        // its own, any difference of shown numbers is a sum of passing
        // cells and passes too. So product slices are shown only when every
        // product slice passes, and the publishable split only when every
        // (product, publishable) cell passes.
        let mut by_product: BTreeMap<String, Vec<&RadarPoint>> = BTreeMap::new();
        let mut cells: BTreeMap<(String, bool), Vec<&RadarPoint>> = BTreeMap::new();
        for p in &kept {
            let product = p.product.to_ascii_lowercase();
            by_product.entry(product.clone()).or_default().push(p);
            cells.entry((product, p.publishable)).or_default().push(p);
        }
        let slices_ok = by_product.values().all(|c| passes(c, &applied));
        let split_ok = cells.values().all(|c| passes(c, &applied));
        let visible = match filter.product.as_deref() {
            None => kept,
            Some(product) => {
                let Some(slice) = by_product.remove(&product.to_ascii_lowercase()) else {
                    continue;
                };
                if !slices_ok {
                    suppressed += 1;
                    continue;
                }
                slice
            }
        };
        shown
            .entry((d, key))
            .or_default()
            .insert(day, Bucket::from_points(&visible, split_ok));
    }

    let days: Vec<i64> = (0..(until - since) / DAY_MS)
        .map(|i| since + i * DAY_MS)
        .collect();
    let mid = since + (until - since) / DAY_MS / 2 * DAY_MS;
    let mut series = Vec::new();
    let mut cards = Vec::new();
    for ((dimension, key), by_day) in shown {
        let mut sources = BTreeSet::new();
        let mut best = Band::Low;
        let (mut first_half, mut second_half) = (0u64, 0u64);
        for (day, b) in &by_day {
            sources.extend(b.sources.iter().cloned());
            best = best.max(b.best.unwrap_or(Band::Low));
            if *day < mid {
                first_half += b.attempts;
            } else {
                second_half += b.attempts;
            }
        }
        let total: u64 = by_day.values().map(|b| b.attempts).sum();
        let pct = if first_half == 0 {
            if second_half > 0 { 100 } else { 0 }
        } else {
            (second_half as i64 - first_half as i64) * 100 / first_half as i64
        };
        let direction = if pct >= 10 {
            Direction::Up
        } else if pct <= -10 {
            Direction::Down
        } else {
            Direction::Flat
        };
        let label = labels
            .get(&(dimension, key.clone()))
            .cloned()
            .unwrap_or_else(|| key.clone());
        cards.extend(cards_for(dimension, &key, &label, &by_day, until));
        series.push(RadarSeries {
            dimension,
            key: key.clone(),
            label,
            wording: dimension.wording().to_string(),
            total_attempts: total,
            total_sources: sources.len() as u32,
            best_band: best,
            first_day: *by_day.keys().next().unwrap_or(&since),
            last_day: *by_day.keys().next_back().unwrap_or(&since),
            days: days
                .iter()
                .map(|d| match by_day.get(d) {
                    Some(b) => RadarDay {
                        day: *d,
                        attempts: b.attempts,
                        publishable_attempts: b.publishable_attempts,
                        sources: b.sources.len() as u32,
                    },
                    None => RadarDay {
                        day: *d,
                        attempts: 0,
                        publishable_attempts: 0,
                        sources: 0,
                    },
                })
                .collect(),
            trend: Trend { direction, pct },
        });
    }
    // Biggest first within each dimension, then cap each dimension.
    series.sort_by(|a, b| {
        (a.dimension, b.total_attempts, &a.key).cmp(&(b.dimension, a.total_attempts, &b.key))
    });
    let limit = filter.limit.clamp(1, MAX_SERIES_PER_DIMENSION);
    let mut per: BTreeMap<Dimension, usize> = BTreeMap::new();
    series.retain(|s| {
        let n = per.entry(s.dimension).or_default();
        *n += 1;
        *n <= limit
    });
    cards.sort_by(|a, b| (b.day, a.kind as u8, &a.key).cmp(&(a.day, b.kind as u8, &b.key)));
    if until < requested_until {
        notes.push("Only closed days are shown; today is rolled up after midnight UTC.".into());
    }
    Ok(RadarFeed {
        audience,
        generated_at: now,
        since,
        until,
        policy: applied,
        series,
        cards,
        suppressed_buckets: suppressed,
        notes,
    })
}

fn card_id(kind: CardKind, dimension: Dimension, key: &str, day: i64) -> String {
    let h = Sha256::digest(format!("{kind:?}\n{dimension:?}\n{key}\n{day}").as_bytes());
    format!("rc_{}", hex::encode(&h[..12]))
}

/// Headline cards for one series, from publishable counts only.
fn cards_for(
    dimension: Dimension,
    key: &str,
    label: &str,
    by_day: &BTreeMap<i64, Bucket>,
    until: i64,
) -> Vec<RadarCard> {
    let mut out = Vec::new();
    let publishable: Vec<(i64, &Bucket)> = by_day
        .iter()
        .filter(|(_, b)| b.publishable_attempts > 0)
        .map(|(d, b)| (*d, b))
        .collect();
    let Some(&(first_day, first)) = publishable.first() else {
        return out;
    };
    let &(last_day, last) = publishable.last().unwrap_or(&(first_day, first));
    let recent = first_day >= until - 2 * DAY_MS;
    let mut card = |kind: CardKind, day: i64, b: &Bucket, headline: String| {
        out.push(RadarCard {
            card_id: card_id(kind, dimension, key, day),
            kind,
            dimension,
            key: key.to_string(),
            day,
            attempts: b.publishable_attempts,
            sources: b.publishable_sources.len() as u32,
            headline,
        });
    };
    let sources = |b: &Bucket| b.publishable_sources.len();
    if dimension == Dimension::Cve && recent && first.best_publishable == Some(Band::High) {
        card(
            CardKind::NewCveAssessment,
            first_day,
            first,
            format!(
                "New: attempts we assess as targeting {key} from {} sources",
                sources(first)
            ),
        );
    }
    if dimension == Dimension::Campaign && recent {
        card(
            CardKind::CampaignEmergence,
            first_day,
            first,
            format!(
                "Possible new campaign {key}: {} attempts from {} sources",
                first.publishable_attempts,
                sources(first)
            ),
        );
    }
    // A spike: the last shown day has at least three times the average of
    // the earlier shown days, and at least ten attempts.
    if publishable.len() >= 3 {
        let earlier = &publishable[..publishable.len() - 1];
        let avg = earlier
            .iter()
            .map(|(_, b)| b.publishable_attempts)
            .sum::<u64>()
            / earlier.len() as u64;
        if last.publishable_attempts >= 10 && last.publishable_attempts >= avg.max(1) * 3 {
            let subject = match dimension {
                Dimension::Cve | Dimension::Technique => {
                    format!("Attempts we assess as targeting {label}")
                }
                Dimension::Campaign => format!("Attempts in possible campaign {label}"),
                Dimension::Product => format!("Attempts against {label}"),
            };
            let kind = if dimension == Dimension::Cve && last.predisclosure {
                CardKind::PredisclosureSpike
            } else {
                CardKind::Spike
            };
            card(
                kind,
                last_day,
                last,
                format!(
                    "{subject} rose to {}, up from an average of {avg}",
                    last.publishable_attempts
                ),
            );
        }
    }
    out
}

/// One Analytics Engine data point (#35, ADR 0009): an index for sampling,
/// blobs for grouping and doubles for sums. Written only for rows whose
/// sensor may feed the radar ([`analytics_points`]); never the tenant,
/// sensor or source. The dataset is private to the account.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct AnalyticsPoint {
    pub index: String,
    pub blobs: Vec<String>,
    pub doubles: Vec<f64>,
}

/// Map a rollup point to Analytics Engine. The index is the dimension and
/// key (public identifiers such as CVE ids), not the tenant.
pub fn analytics_point(p: &RadarPoint) -> AnalyticsPoint {
    let mut index = format!("{}:{}", p.dimension.as_str(), p.key);
    while index.len() > AE_INDEX_BYTES {
        index.pop();
    }
    AnalyticsPoint {
        index,
        blobs: vec![
            p.dimension.as_str().to_string(),
            p.key.clone(),
            p.product.clone(),
            match p.sensor_kind {
                SensorKind::Research => "research".into(),
                SensorKind::Edge => "edge".into(),
            },
            format!("{:?}", p.band).to_lowercase(),
        ],
        doubles: vec![
            f64::from(p.attempts),
            f64::from(p.score),
            if p.publishable { 1.0 } else { 0.0 },
            if p.predisclosure { 1.0 } else { 0.0 },
            p.day as f64,
        ],
    }
}

/// Analytics Engine points for the rows whose sensor may feed the radar
/// under the share policy (opted in, allowed kind). Others stay in the
/// tenant's own Postgres rollup only.
pub fn analytics_points(points: &[RadarPoint], policy: &share::SharePolicy) -> Vec<AnalyticsPoint> {
    points
        .iter()
        .filter(|p| share::may_share(policy, p.sensor_kind, p.shared, share::Channel::Radar))
        .map(analytics_point)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const DAY0: i64 = 1_798_761_600_000; // a UTC midnight

    fn pt(tenant: &str, sensor: &str, kind: SensorKind, shared: bool, src: &str) -> RadarPoint {
        RadarPoint {
            day: DAY0,
            tenant_id: tenant.into(),
            sensor: sensor.into(),
            sensor_kind: kind,
            shared,
            dimension: Dimension::Cve,
            key: "CVE-2099-0001".into(),
            product: "foiled/demo-app".into(),
            source: source_key(src),
            attempts: 1,
            score: 80,
            band: Band::High,
            publishable: true,
            predisclosure: false,
        }
    }

    fn run(points: &[RadarPoint], audience: Audience, now: i64) -> RadarFeed {
        aggregate(
            points,
            audience,
            Some("t1"),
            &RadarPolicy::default(),
            DAY0 - 6 * DAY_MS,
            DAY0 + DAY_MS,
            now,
            &Filter {
                limit: 20,
                ..Default::default()
            },
            &BTreeMap::new(),
        )
        .unwrap()
    }

    fn research(srcs: &[&str]) -> Vec<RadarPoint> {
        srcs.iter()
            .map(|s| pt("t1", "decoy:d1", SensorKind::Research, true, s))
            .collect()
    }

    #[test]
    fn buckets_below_min_sources_are_suppressed() {
        let now = DAY0 + 30 * DAY_MS;
        let two = run(
            &research(&["198.51.100.1", "198.51.100.2"]),
            Audience::Fleet,
            now,
        );
        assert!(two.series.is_empty());
        assert_eq!(two.suppressed_buckets, 1);
        let three = run(
            &research(&["198.51.100.1", "198.51.100.2", "198.51.100.3"]),
            Audience::Fleet,
            now,
        );
        assert_eq!(three.series.len(), 1);
        assert_eq!(three.series[0].total_attempts, 3);
        assert_eq!(three.series[0].wording, "we assess as");
        // A tenant sees its own small numbers.
        let own = run(&research(&["198.51.100.1"]), Audience::Tenant, now);
        assert_eq!(own.series.len(), 1);
    }

    #[test]
    fn edge_data_needs_opt_in_and_enough_tenants() {
        let now = DAY0 + 30 * DAY_MS;
        let not_shared: Vec<_> = ["a", "b", "c"]
            .iter()
            .map(|s| pt("t2", "sen1", SensorKind::Edge, false, s))
            .collect();
        assert!(run(&not_shared, Audience::Fleet, now).series.is_empty());
        // Opted in, but one tenant only: dropped, never shown.
        let one_tenant: Vec<_> = ["a", "b", "c"]
            .iter()
            .map(|s| pt("t2", "sen1", SensorKind::Edge, true, s))
            .collect();
        assert!(run(&one_tenant, Audience::Fleet, now).series.is_empty());
        let three_tenants: Vec<_> = [("t2", "a"), ("t3", "b"), ("t4", "c")]
            .iter()
            .map(|(t, s)| pt(t, "sen", SensorKind::Edge, true, s))
            .collect();
        assert_eq!(run(&three_tenants, Audience::Fleet, now).series.len(), 1);
    }

    #[test]
    fn unpublishable_links_never_make_headlines() {
        let pts = research(&["a", "b", "c"]);
        // LLM-only and other unpublishable links: on the fleet radar for
        // operators (if medium or above), never a headline.
        let llm: Vec<_> = pts
            .iter()
            .cloned()
            .map(|mut p| {
                p.publishable = false;
                p.score = 45;
                p.band = Band::Medium;
                p
            })
            .collect();
        let fleet = run(&llm, Audience::Fleet, DAY0 + 2 * DAY_MS);
        assert_eq!(fleet.series.len(), 1);
        assert!(fleet.cards.is_empty());
        assert_eq!(
            fleet.series[0]
                .days
                .iter()
                .map(|d| d.publishable_attempts)
                .sum::<u64>(),
            0
        );
        let low: Vec<_> = llm
            .into_iter()
            .map(|mut p| {
                p.band = Band::Low;
                p
            })
            .collect();
        assert!(
            run(&low, Audience::Fleet, DAY0 + 30 * DAY_MS)
                .series
                .is_empty()
        );
    }

    fn by_product(points: &[RadarPoint], product: Option<&str>) -> RadarFeed {
        aggregate(
            points,
            Audience::Fleet,
            None,
            &RadarPolicy::default(),
            DAY0 - 6 * DAY_MS,
            DAY0 + DAY_MS,
            DAY0 + 2 * DAY_MS,
            &Filter {
                product: product.map(str::to_string),
                limit: 20,
                ..Default::default()
            },
            &BTreeMap::new(),
        )
        .unwrap()
    }

    fn day_attempts(f: &RadarFeed) -> Option<u64> {
        f.series
            .first()
            .map(|s| s.days.iter().map(|d| d.attempts).sum())
    }

    #[test]
    fn product_slices_cannot_difference_out_one_tenant() {
        // Three opted-in edge tenants on one CVE, so the bucket passes.
        // Tenants a and b saw it on product A, tenant c alone on product B.
        let mut pts = Vec::new();
        for (t, src, product) in [
            ("ta", "198.51.100.1", "acme/a"),
            ("ta", "198.51.100.2", "acme/a"),
            ("tb", "198.51.100.3", "acme/a"),
            ("tb", "198.51.100.4", "acme/a"),
            ("tc", "198.51.100.5", "acme/b"),
        ] {
            let mut p = pt(t, &format!("sen-{t}"), SensorKind::Edge, true, src);
            p.product = product.into();
            pts.push(p);
        }
        // The whole bucket is shown.
        assert_eq!(day_attempts(&by_product(&pts, None)), Some(5));
        // Product B is tenant c alone: suppressed.
        assert_eq!(day_attempts(&by_product(&pts, Some("acme/b"))), None);
        // Product A would leave tenant c alone as the difference: also
        // suppressed, so total minus A minus B reveals nothing.
        let a = by_product(&pts, Some("acme/a"));
        assert_eq!(day_attempts(&a), None);
        assert_eq!(a.suppressed_buckets, 1);
        // With a third tenant behind product B too, both halves pass
        // except on sources, so add sources until each half passes alone.
        for (t, src) in [("td", "198.51.100.6"), ("te", "198.51.100.7")] {
            let mut p = pt(t, &format!("sen-{t}"), SensorKind::Edge, true, src);
            p.product = "acme/b".into();
            pts.push(p);
        }
        let mut more = pt("tc", "sen-tc", SensorKind::Edge, true, "198.51.100.8");
        more.product = "acme/a".into();
        pts.push(more);
        // A: ta, tb, tc (3 tenants, 5 sources). Rest (B): tc, td, te.
        assert_eq!(day_attempts(&by_product(&pts, Some("acme/a"))), Some(5));
        assert_eq!(day_attempts(&by_product(&pts, Some("acme/b"))), Some(3));
    }

    #[test]
    fn three_way_product_split_cannot_isolate_a_small_slice() {
        // Products A and B have three tenants each; C is tenant t7 alone.
        // Total minus A minus B would be t7's count, so no product slice is
        // shown while any slice fails, though the whole bucket still is.
        let mut pts = Vec::new();
        let mut n = 0;
        for (product, tenants) in [
            ("acme/a", vec!["t1", "t2", "t3"]),
            ("acme/b", vec!["t4", "t5", "t6"]),
            ("acme/c", vec!["t7"]),
        ] {
            for t in tenants {
                n += 1;
                let mut p = pt(
                    t,
                    &format!("sen-{t}"),
                    SensorKind::Edge,
                    true,
                    &format!("198.51.100.{n}"),
                );
                p.product = product.into();
                pts.push(p);
            }
        }
        assert_eq!(day_attempts(&by_product(&pts, None)), Some(7));
        for product in ["acme/a", "acme/b", "acme/c"] {
            assert_eq!(
                day_attempts(&by_product(&pts, Some(product))),
                None,
                "{product}"
            );
        }
        // Once C has enough tenants too, every slice is shown.
        for (t, src) in [("t8", "198.51.100.20"), ("t9", "198.51.100.21")] {
            let mut p = pt(t, &format!("sen-{t}"), SensorKind::Edge, true, src);
            p.product = "acme/c".into();
            pts.push(p);
        }
        assert_eq!(day_attempts(&by_product(&pts, Some("acme/a"))), Some(3));
        assert_eq!(day_attempts(&by_product(&pts, Some("acme/c"))), Some(3));
    }

    #[test]
    fn publishable_split_is_withheld_when_one_side_is_small() {
        let mut pts = research(&["a", "b", "c"]);
        let mut odd = pt("t1", "decoy:d1", SensorKind::Research, true, "d");
        odd.publishable = false;
        odd.band = Band::Medium;
        pts.push(odd);
        let f = run(&pts, Audience::Fleet, DAY0 + 2 * DAY_MS);
        let day = f.series[0].days.iter().find(|d| d.attempts > 0).unwrap();
        assert_eq!(day.attempts, 4);
        assert_eq!(
            day.publishable_attempts, 0,
            "the split would expose one source"
        );
    }

    #[test]
    fn tenant_audience_never_mixes_tenants() {
        let mut pts = research(&["a"]);
        pts.push(pt("t9", "decoy:d9", SensorKind::Research, true, "z"));
        let own = run(&pts, Audience::Tenant, DAY0 + 2 * DAY_MS);
        assert_eq!(own.series[0].total_attempts, 1);
    }

    #[test]
    fn new_high_cve_makes_a_card_and_spikes_are_found() {
        let now = DAY0 + 2 * DAY_MS;
        let feed = run(&research(&["a", "b", "c"]), Audience::Fleet, now);
        assert_eq!(feed.cards.len(), 1);
        assert_eq!(feed.cards[0].kind, CardKind::NewCveAssessment);
        assert!(feed.cards[0].headline.contains("we assess as"));
        let mut pts = Vec::new();
        for d in 0..4 {
            let n = if d == 3 { 12 } else { 1 };
            for s in ["a", "b", "c"] {
                let mut p = pt("t1", "decoy:d1", SensorKind::Research, true, s);
                p.day = DAY0 - (3 - d) * DAY_MS;
                p.attempts = n;
                p.dimension = Dimension::Technique;
                p.key = "T1190".into();
                pts.push(p);
            }
        }
        let feed = run(&pts, Audience::Fleet, now);
        assert!(
            feed.cards.iter().any(|c| c.kind == CardKind::Spike),
            "{:?}",
            feed.cards
        );
        assert_eq!(feed.series[0].trend.direction, Direction::Up);
        assert_eq!(feed.series[0].days.len(), 7);
    }

    #[test]
    fn analytics_points_only_for_shared_sensors() {
        let policy = share::SharePolicy::default();
        let shared = pt("t1", "sen1", SensorKind::Edge, true, "a");
        let private = pt("t2", "sen2", SensorKind::Edge, false, "b");
        let out = analytics_points(&[shared, private], &policy);
        assert_eq!(out.len(), 1);
    }

    #[test]
    fn analytics_points_carry_no_source() {
        let p = pt("t1", "decoy:d1", SensorKind::Research, true, "203.0.113.5");
        let a = analytics_point(&p);
        assert_eq!(a.index, "cve:CVE-2099-0001");
        assert!(!a.blobs.iter().any(|b| b == "t1"));
        assert!(!a.blobs.iter().any(|b| b == &p.source));
        assert_eq!(a.doubles[0], 1.0);
    }

    #[test]
    fn windows_are_bounded() {
        let err = aggregate(
            &[],
            Audience::Fleet,
            None,
            &RadarPolicy::default(),
            DAY0,
            DAY0 + 200 * DAY_MS,
            DAY0,
            &Filter::default(),
            &BTreeMap::new(),
        );
        assert!(err.is_err());
        assert_eq!(product_key("foiled/demo-app/1.0.0"), "foiled/demo-app");
    }
}
