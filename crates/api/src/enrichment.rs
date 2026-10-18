//! Reading the enrichment cache (#11) for API responses.
//!
//! Every route that shows enrichment context (IOC ASN refs, the CSV export's
//! ASN columns) reads it through [`cached_facts`], so the rules live in one
//! place: `foiled_core::enrichment::usable_facts` with the provider TTLs,
//! the retention cap from `configs/retention.yaml` (#16) and
//! `show_to_tenants` from `configs/enrichment.yaml`, both bundled at build
//! time. Exports then apply the never-redistribute rule on top
//! (`foiled_core::ioc::export_refs`).
//!
//! Enrichment is context, never a reason to fail a request: if the cache
//! cannot be read, the response goes out without it and says so.

use std::collections::BTreeMap;
use std::sync::OnceLock;

use axum::http::{HeaderMap, HeaderName, HeaderValue};
use foiled_core::enrichment::{Fact, Observable, ReadPolicy, usable_facts};
use foiled_core::retention::RetentionConfig;

use crate::AppState;

static RETENTION: &str = include_str!(concat!(env!("OUT_DIR"), "/retention_config.json"));
static ENRICHMENT: &str = include_str!(concat!(env!("OUT_DIR"), "/enrichment_config.json"));

/// Response header set when enrichment context could not be read.
pub const UNAVAILABLE_HEADER: &str = "x-foiled-enrichment";

/// `configs/retention.yaml` as bundled at build time. `foiled-lint`
/// validates it in CI; if a bad file still gets through, the built-in
/// defaults (the same values the file ships with) are used.
pub fn bundled_retention() -> &'static RetentionConfig {
    static PARSED: OnceLock<RetentionConfig> = OnceLock::new();
    PARSED.get_or_init(|| serde_json::from_str(RETENTION).unwrap_or_default())
}

/// `configs/enrichment.yaml` as bundled at build time, or `None` when it
/// does not parse or has problems. `None` switches the `foiled-enrich`
/// consumer off rather than running it with unknown limits.
pub fn bundled_enrich_config() -> Option<&'static foiled_core::enrich_pipeline::EnrichConfig> {
    static PARSED: OnceLock<Option<foiled_core::enrich_pipeline::EnrichConfig>> = OnceLock::new();
    PARSED
        .get_or_init(|| {
            serde_json::from_str::<foiled_core::enrich_pipeline::EnrichConfig>(ENRICHMENT)
                .ok()
                .filter(|c| c.problems().is_empty())
        })
        .as_ref()
}

/// `show_to_tenants` from the bundled `configs/enrichment.yaml`. Anything
/// but an explicit `true` keeps third-party Facts hidden.
pub fn show_third_party_to_tenants() -> bool {
    static PARSED: OnceLock<bool> = OnceLock::new();
    *PARSED.get_or_init(|| {
        serde_json::from_str::<serde_json::Value>(ENRICHMENT)
            .ok()
            .and_then(|v| {
                v.get("show_to_tenants")
                    .and_then(serde_json::Value::as_bool)
            })
            .unwrap_or(false)
    })
}

/// Usable cached Facts by observable, and whether the cache could be read.
#[derive(Debug, Default)]
pub struct CachedFacts {
    pub facts: BTreeMap<Observable, Vec<Fact>>,
    /// True when the store failed. `facts` is then empty.
    pub unavailable: bool,
}

impl CachedFacts {
    /// `x-foiled-enrichment: unavailable` when the cache could not be read.
    pub fn headers(&self) -> HeaderMap {
        let mut h = HeaderMap::new();
        if self.unavailable {
            h.insert(
                HeaderName::from_static(UNAVAILABLE_HEADER),
                HeaderValue::from_static("unavailable"),
            );
        }
        h
    }
}

/// Usable cached Facts for `observables` (newest first: when the statement
/// budget in `Limits::enrichment_lookup_statements` runs out, the oldest
/// are left without context). One store call. A store failure is logged by
/// the store and turned into `unavailable`, never into an error.
pub async fn cached_facts(
    state: &AppState,
    tenant_id: &str,
    observables: Vec<Observable>,
) -> CachedFacts {
    if observables.is_empty() {
        return CachedFacts::default();
    }
    let now_ms = (state.clock)();
    let rows = match state
        .store
        .enrichment_cache(
            observables,
            now_ms,
            state.limits.enrichment_lookup_statements,
            Some(tenant_id.to_string()),
        )
        .await
    {
        Ok(rows) => rows,
        Err(_) => {
            return CachedFacts {
                facts: BTreeMap::new(),
                unavailable: true,
            };
        }
    };
    let policy = ReadPolicy {
        now_ms,
        tenant_id: Some(tenant_id),
        show_third_party: show_third_party_to_tenants(),
    };
    CachedFacts {
        facts: usable_facts(&rows, policy, bundled_retention())
            .into_iter()
            .map(|o| (o.observable, o.facts))
            .collect(),
        unavailable: false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bundled_configs_parse() {
        assert_eq!(
            serde_json::from_str::<RetentionConfig>(RETENTION).unwrap(),
            *bundled_retention()
        );
        assert!(!show_third_party_to_tenants(), "shipped value");
        let c = bundled_enrich_config().expect("shipped config parses");
        assert_eq!(c.queue, "foiled-enrich");
    }
}
