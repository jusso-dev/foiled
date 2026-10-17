//! Retention policy and purge planner (#16).
//!
//! `configs/retention.yaml` is validated by `schemas/retention-config.schema.json`
//! and parses into [`RetentionConfig`]. The purge job (a Workers cron trigger,
//! wired up with the data layer) lists candidate items from Postgres, R2 and
//! D1, asks [`plan_purge`] which ones have expired, deletes them (unless the
//! run is a dry run) and writes [`PurgePlan::summary`] to the audit log.
//!
//! The planner is pure: it takes the current time as a parameter and never
//! reads a clock, so it builds for `wasm32-unknown-unknown` and is easy to test
//! with a skewed clock. See `docs/privacy-and-retention.md`.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

/// Milliseconds in one day.
pub const MS_PER_DAY: i64 = 86_400_000;

/// The audit log always outlives at least this many days, whatever the config
/// says, so a purge can never delete its own record straight away.
pub const MIN_AUDIT_TTL_DAYS: u32 = 30;

/// Operator retention policy. Mirrors `schemas/retention-config.schema.json`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RetentionConfig {
    /// Config format version. Always 1 for now.
    pub version: u32,
    /// Keep full request bodies and payload bytes. Off by default: only hashes
    /// are stored.
    pub store_payloads: bool,
    pub purge: PurgeSettings,
    pub ttl_days: TtlDays,
    pub enrichment_cache: EnrichmentCacheTtl,
    /// Decoy ids whose data the purge job must not delete (legal hold).
    pub legal_holds: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PurgeSettings {
    /// When false the purge job plans nothing and deletes nothing.
    pub enabled: bool,
    /// When true the purge job reports what it would delete and deletes
    /// nothing.
    pub dry_run: bool,
}

/// Time to live in whole days for each data class. Zero means "delete at the
/// next purge run".
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TtlDays {
    pub pcap: u32,
    pub access_log: u32,
    pub fs_diff: u32,
    pub quarantine_file: u32,
    pub quarantine_meta: u32,
    pub attempt: u32,
    pub forensic_snapshot: u32,
    pub export_bundle: u32,
    /// Floored at [`MIN_AUDIT_TTL_DAYS`] by the planner.
    pub audit: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnrichmentCacheTtl {
    /// TTL for providers without their own entry.
    pub default_ttl_days: u32,
    /// Per-provider TTL in days, keyed by provider id (for example
    /// `greynoise`).
    #[serde(default)]
    pub providers: BTreeMap<String, u32>,
}

impl Default for RetentionConfig {
    /// The defaults documented in `docs/privacy-and-retention.md` and shipped
    /// in `configs/retention.yaml`.
    fn default() -> Self {
        RetentionConfig {
            version: 1,
            store_payloads: false,
            purge: PurgeSettings {
                enabled: true,
                dry_run: true,
            },
            ttl_days: TtlDays {
                pcap: 14,
                access_log: 30,
                fs_diff: 30,
                quarantine_file: 30,
                quarantine_meta: 90,
                attempt: 90,
                forensic_snapshot: 7,
                export_bundle: 1,
                audit: 365,
            },
            enrichment_cache: EnrichmentCacheTtl {
                default_ttl_days: 7,
                providers: BTreeMap::new(),
            },
            legal_holds: Vec::new(),
        }
    }
}

impl RetentionConfig {
    /// Effective TTL in days for one item of `class`. `provider` only matters
    /// for [`DataClass::EnrichmentCache`].
    pub fn ttl_days_for(&self, class: DataClass, provider: Option<&str>) -> u32 {
        let t = &self.ttl_days;
        match class {
            DataClass::Pcap => t.pcap,
            DataClass::AccessLog => t.access_log,
            DataClass::FsDiff => t.fs_diff,
            DataClass::QuarantineFile => t.quarantine_file,
            DataClass::QuarantineMeta => t.quarantine_meta,
            DataClass::Attempt => t.attempt,
            DataClass::ForensicSnapshot => t.forensic_snapshot,
            DataClass::ExportBundle => t.export_bundle,
            DataClass::Audit => t.audit.max(MIN_AUDIT_TTL_DAYS),
            DataClass::EnrichmentCache => provider
                .and_then(|p| self.enrichment_cache.providers.get(p).copied())
                .unwrap_or(self.enrichment_cache.default_ttl_days),
        }
    }
}

/// Kinds of stored data, each with its own TTL.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DataClass {
    /// Packet captures in R2 (#9 network channel).
    Pcap,
    /// Application and protocol access logs (#9 application channel).
    AccessLog,
    /// Filesystem diffs taken on rotate (#8, #9).
    FsDiff,
    /// Quarantined payload bytes in R2.
    QuarantineFile,
    /// Quarantine metadata rows (hash, size, type, YARA hits), no bytes.
    QuarantineMeta,
    /// Cached enrichment lookups (#11).
    EnrichmentCache,
    /// Attempt and session index rows and their capture events (#25).
    Attempt,
    /// Forensic snapshots of a rotated guest (#8).
    ForensicSnapshot,
    /// Generated export bundles (#13).
    ExportBundle,
    /// Audit log rows.
    Audit,
}

impl DataClass {
    pub const ALL: [DataClass; 10] = [
        DataClass::Pcap,
        DataClass::AccessLog,
        DataClass::FsDiff,
        DataClass::QuarantineFile,
        DataClass::QuarantineMeta,
        DataClass::EnrichmentCache,
        DataClass::Attempt,
        DataClass::ForensicSnapshot,
        DataClass::ExportBundle,
        DataClass::Audit,
    ];
}

/// One stored thing the purge job might delete.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Item {
    pub class: DataClass,
    /// Store key: an R2 object key or prefix, or a row id.
    pub key: String,
    /// Creation time in milliseconds since the Unix epoch, as recorded by the
    /// trusted side on receipt.
    pub created_at_ms: i64,
    /// Decoy the item belongs to, used for legal holds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decoy_id: Option<String>,
    /// Enrichment provider id, only for [`DataClass::EnrichmentCache`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider: Option<String>,
}

/// What a purge run will delete.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PurgePlan {
    /// Copied from the config. When true the caller deletes nothing.
    pub dry_run: bool,
    /// Keys to delete.
    pub delete: Vec<String>,
    /// Expired items kept because their decoy is on legal hold.
    pub kept_for_hold: usize,
    /// Items whose `created_at_ms` is after `now_ms` (clock skew). Never
    /// deleted on this run.
    pub future_dated: usize,
    /// Number of keys to delete, per class.
    pub counts_by_class: BTreeMap<DataClass, usize>,
}

/// Counts-only record of a purge run for the audit log. Holds no keys and no
/// content.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PurgeSummary {
    pub dry_run: bool,
    pub planned: usize,
    pub kept_for_hold: usize,
    pub future_dated: usize,
    pub counts_by_class: BTreeMap<DataClass, usize>,
}

impl PurgePlan {
    pub fn summary(&self) -> PurgeSummary {
        PurgeSummary {
            dry_run: self.dry_run,
            planned: self.delete.len(),
            kept_for_hold: self.kept_for_hold,
            future_dated: self.future_dated,
            counts_by_class: self.counts_by_class.clone(),
        }
    }
}

/// Decide which of `items` have outlived their TTL at `now_ms`.
///
/// - Purge disabled: nothing is planned.
/// - An item is expired when `now_ms - created_at_ms >= ttl`. TTL 0 therefore
///   means "delete at the next run".
/// - An item created after `now_ms` (clock skew between hosts and the control
///   plane) is not expired, is never deleted on this run and is counted in
///   `future_dated`.
/// - Expired items of a decoy on legal hold are kept and counted in
///   `kept_for_hold`.
pub fn plan_purge(config: &RetentionConfig, now_ms: i64, items: &[Item]) -> PurgePlan {
    let mut plan = PurgePlan {
        dry_run: config.purge.dry_run,
        ..PurgePlan::default()
    };
    if !config.purge.enabled {
        return plan;
    }
    let holds: BTreeSet<&str> = config.legal_holds.iter().map(String::as_str).collect();

    for item in items {
        if item.created_at_ms > now_ms {
            plan.future_dated += 1;
            continue;
        }
        let age_ms = now_ms.saturating_sub(item.created_at_ms);
        let ttl_ms = i64::from(config.ttl_days_for(item.class, item.provider.as_deref()))
            .saturating_mul(MS_PER_DAY);
        if age_ms < ttl_ms {
            continue;
        }
        if item.decoy_id.as_deref().is_some_and(|d| holds.contains(d)) {
            plan.kept_for_hold += 1;
            continue;
        }
        plan.delete.push(item.key.clone());
        *plan.counts_by_class.entry(item.class).or_default() += 1;
    }
    plan
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: i64 = 1_800_000_000_000;
    const HOUR: i64 = 3_600_000;

    fn days(n: i64) -> i64 {
        n * MS_PER_DAY
    }

    fn item(class: DataClass, key: &str, age_ms: i64) -> Item {
        Item {
            class,
            key: key.to_string(),
            created_at_ms: NOW - age_ms,
            decoy_id: Some("decoy-a".to_string()),
            provider: None,
        }
    }

    fn live() -> RetentionConfig {
        let mut c = RetentionConfig::default();
        c.purge.dry_run = false;
        c
    }

    /// Raw evidence gone at the next run; metadata kept.
    fn metadata_only() -> RetentionConfig {
        let mut c = live();
        c.ttl_days.pcap = 0;
        c.ttl_days.fs_diff = 0;
        c.ttl_days.quarantine_file = 0;
        c.ttl_days.forensic_snapshot = 0;
        c.ttl_days.export_bundle = 0;
        c.ttl_days.access_log = 1;
        c
    }

    #[test]
    fn defaults_match_the_documented_policy() {
        let c = RetentionConfig::default();
        assert!(!c.store_payloads);
        assert!(c.purge.enabled);
        assert!(c.purge.dry_run);
        assert!(c.legal_holds.is_empty());
        let expect = [
            (DataClass::Pcap, 14),
            (DataClass::AccessLog, 30),
            (DataClass::FsDiff, 30),
            (DataClass::QuarantineFile, 30),
            (DataClass::QuarantineMeta, 90),
            (DataClass::EnrichmentCache, 7),
            (DataClass::Attempt, 90),
            (DataClass::ForensicSnapshot, 7),
            (DataClass::ExportBundle, 1),
            (DataClass::Audit, 365),
        ];
        assert_eq!(expect.len(), DataClass::ALL.len());
        for (class, ttl) in expect {
            assert_eq!(c.ttl_days_for(class, None), ttl, "{class:?}");
        }
    }

    #[test]
    fn expires_at_ttl_and_not_before() {
        let items = [
            item(DataClass::Pcap, "young", days(14) - 1),
            item(DataClass::Pcap, "exact", days(14)),
            item(DataClass::Pcap, "old", days(40)),
        ];
        let plan = plan_purge(&live(), NOW, &items);
        assert_eq!(plan.delete, ["exact", "old"]);
        assert_eq!(plan.counts_by_class[&DataClass::Pcap], 2);
    }

    #[test]
    fn each_class_uses_its_own_ttl() {
        let age = days(20);
        let items: Vec<Item> = DataClass::ALL
            .iter()
            .map(|&c| item(c, &format!("{c:?}"), age))
            .collect();
        let plan = plan_purge(&live(), NOW, &items);
        // 20 days is past pcap (14), enrichment (7), forensic (7) and export (1).
        assert_eq!(
            plan.delete,
            [
                "Pcap",
                "EnrichmentCache",
                "ForensicSnapshot",
                "ExportBundle"
            ]
        );
        assert_eq!(plan.counts_by_class.values().sum::<usize>(), 4);
    }

    #[test]
    fn ttl_zero_deletes_at_next_run() {
        let mut c = live();
        c.ttl_days.pcap = 0;
        let items = [
            item(DataClass::Pcap, "just-now", 0),
            item(DataClass::Pcap, "a-second-ago", 1_000),
        ];
        let plan = plan_purge(&c, NOW, &items);
        assert_eq!(plan.delete, ["just-now", "a-second-ago"]);
    }

    #[test]
    fn future_dated_items_are_not_expired() {
        // A host clock one hour ahead stamps items in the control plane's future.
        let mut c = live();
        c.ttl_days.pcap = 0;
        let items = [
            item(DataClass::Pcap, "skewed-1ms", -1),
            item(DataClass::Pcap, "skewed-1h", -HOUR),
            item(DataClass::Attempt, "skewed-years", -days(3650)),
            item(DataClass::Pcap, "now", 0),
        ];
        let plan = plan_purge(&c, NOW, &items);
        assert_eq!(plan.delete, ["now"]);
        assert_eq!(plan.future_dated, 3);

        // Once the control plane clock passes the stamp plus the TTL, it goes.
        let later = plan_purge(&c, NOW + HOUR, &items);
        assert_eq!(later.delete, ["skewed-1ms", "skewed-1h", "now"]);
        assert_eq!(later.future_dated, 1);
    }

    #[test]
    fn clock_skew_does_not_shorten_retention() {
        // An item stamped 1 h in the future is kept for its full TTL counted
        // from that stamp, never deleted early.
        let skewed = item(DataClass::Pcap, "k", -HOUR);
        let just_short = NOW + HOUR + days(14) - 1;
        assert!(
            plan_purge(&live(), just_short, std::slice::from_ref(&skewed))
                .delete
                .is_empty()
        );
        let at_ttl = NOW + HOUR + days(14);
        assert_eq!(plan_purge(&live(), at_ttl, &[skewed]).delete, ["k"]);
    }

    #[test]
    fn legal_hold_keeps_only_that_decoy() {
        let mut c = live();
        c.legal_holds = vec!["decoy-held".to_string()];
        let mut held = item(DataClass::Pcap, "held", days(100));
        held.decoy_id = Some("decoy-held".to_string());
        let mut held_young = item(DataClass::Pcap, "held-young", 0);
        held_young.decoy_id = Some("decoy-held".to_string());
        let other = item(DataClass::Pcap, "other", days(100));
        let mut no_decoy = item(DataClass::EnrichmentCache, "enrich", days(100));
        no_decoy.decoy_id = None;

        let plan = plan_purge(&c, NOW, &[held, held_young, other, no_decoy]);
        assert_eq!(plan.delete, ["other", "enrich"]);
        assert_eq!(plan.kept_for_hold, 1, "only expired held items count");
    }

    #[test]
    fn disabled_purge_plans_nothing() {
        let mut c = metadata_only();
        c.purge.enabled = false;
        let items = [item(DataClass::Pcap, "old", days(1000))];
        let plan = plan_purge(&c, NOW, &items);
        assert!(plan.delete.is_empty());
        assert!(plan.counts_by_class.is_empty());
    }

    #[test]
    fn dry_run_flag_is_carried_into_the_plan() {
        let items = [item(DataClass::Pcap, "old", days(30))];
        let dry = plan_purge(&RetentionConfig::default(), NOW, &items);
        assert!(dry.dry_run);
        // A dry run still reports what it would delete.
        assert_eq!(dry.delete, ["old"]);
        assert!(!plan_purge(&live(), NOW, &items).dry_run);
    }

    #[test]
    fn metadata_only_mode_drops_raw_evidence_and_keeps_metadata() {
        let age = HOUR;
        let items = [
            item(DataClass::Pcap, "pcap", age),
            item(DataClass::FsDiff, "diff", age),
            item(DataClass::QuarantineFile, "bytes", age),
            item(DataClass::ForensicSnapshot, "snap", age),
            item(DataClass::ExportBundle, "bundle", age),
            item(DataClass::AccessLog, "log", age),
            item(DataClass::QuarantineMeta, "meta", age),
            item(DataClass::Attempt, "attempt", age),
            item(DataClass::Audit, "audit", age),
        ];
        let plan = plan_purge(&metadata_only(), NOW, &items);
        assert_eq!(plan.delete, ["pcap", "diff", "bytes", "snap", "bundle"]);

        let next_day = plan_purge(&metadata_only(), NOW + days(1), &items);
        assert!(next_day.delete.contains(&"log".to_string()));
        assert!(!next_day.delete.contains(&"attempt".to_string()));
        assert!(!next_day.delete.contains(&"meta".to_string()));
    }

    #[test]
    fn enrichment_cache_uses_provider_ttl() {
        let mut c = live();
        c.enrichment_cache.providers.insert("fast".to_string(), 1);
        c.enrichment_cache.providers.insert("slow".to_string(), 30);
        let mk = |key: &str, provider: Option<&str>| Item {
            provider: provider.map(str::to_string),
            ..item(DataClass::EnrichmentCache, key, days(2))
        };
        let items = [
            mk("fast", Some("fast")),
            mk("slow", Some("slow")),
            mk("unknown", Some("unlisted")),
            mk("none", None),
        ];
        let plan = plan_purge(&c, NOW, &items);
        assert_eq!(plan.delete, ["fast"]);
        let later = plan_purge(&c, NOW + days(5), &items);
        assert_eq!(later.delete, ["fast", "unknown", "none"]);
    }

    #[test]
    fn audit_log_has_a_floor() {
        let mut c = live();
        c.ttl_days.audit = 0;
        assert_eq!(c.ttl_days_for(DataClass::Audit, None), MIN_AUDIT_TTL_DAYS);
        let items = [
            item(DataClass::Audit, "recent", days(29)),
            item(DataClass::Audit, "old", days(30)),
        ];
        assert_eq!(plan_purge(&c, NOW, &items).delete, ["old"]);
    }

    #[test]
    fn extreme_timestamps_do_not_overflow() {
        let mut c = live();
        c.ttl_days.attempt = u32::MAX;
        let mut ancient = item(DataClass::Attempt, "ancient", 0);
        ancient.created_at_ms = i64::MIN;
        let mut pcap = item(DataClass::Pcap, "pcap", 0);
        pcap.created_at_ms = i64::MIN;
        let plan = plan_purge(&c, i64::MAX, &[ancient, pcap]);
        assert_eq!(plan.delete, ["ancient", "pcap"]);
    }

    #[test]
    fn summary_holds_counts_not_keys() {
        let secret_key = "tenant/decoy-a/att-1/network/0123abcd";
        let items = [
            item(DataClass::Pcap, secret_key, days(30)),
            item(DataClass::AccessLog, "log-1", days(31)),
        ];
        let summary = plan_purge(&RetentionConfig::default(), NOW, &items).summary();
        assert_eq!(summary.planned, 2);
        let json = serde_json::to_string(&summary).unwrap();
        assert!(!json.contains(secret_key), "{json}");
        assert!(!json.contains("log-1"), "{json}");
        assert!(json.contains(r#""pcap":1"#), "{json}");
        assert!(json.contains(r#""access_log":1"#), "{json}");
    }

    #[test]
    fn config_round_trips_and_rejects_unknown_fields() {
        let c = RetentionConfig::default();
        let json = serde_json::to_value(&c).unwrap();
        let back: RetentionConfig = serde_json::from_value(json.clone()).unwrap();
        assert_eq!(back, c);

        let mut extra = json;
        extra["ttl_days"]["pcaps"] = 3.into();
        assert!(serde_json::from_value::<RetentionConfig>(extra).is_err());
    }
}
