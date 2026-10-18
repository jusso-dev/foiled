//! Where radar rollups go besides Postgres (#35).
//!
//! On Workers the sink is the `RADAR` Analytics Engine dataset (ADR 0001,
//! ADR 0009): one data point per rollup row, for high-volume counting and
//! ad hoc SQL by operators. The dataset is private to the account; no public
//! route reads it. Tests use [`crate::memory::MemoryRadarSink`].

use foiled_core::radar::AnalyticsPoint;

/// Writes radar data points. Synchronous: Analytics Engine's
/// `writeDataPoint` does not wait for the write.
pub trait RadarSink: Send + Sync {
    fn write(&self, points: &[AnalyticsPoint]) -> Result<(), String>;
}

/// Drops every point. The default when no dataset is bound.
#[derive(Debug, Default)]
pub struct NoRadarSink;

impl RadarSink for NoRadarSink {
    fn write(&self, _points: &[AnalyticsPoint]) -> Result<(), String> {
        Ok(())
    }
}

/// A boxed `Send` future, as the store uses.
pub type PurgeFuture<'a> =
    std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), String>> + Send + 'a>>;

/// Purges public page URLs from Cloudflare's cache when a page is
/// published, republished or withdrawn (#35). Paths are site-relative
/// (`/exploited/<slug>`); the Worker implementation turns them into URLs on
/// the public origin and calls the zone purge API. Tests use
/// [`crate::memory::MemoryCachePurger`].
pub trait CachePurger: Send + Sync {
    fn purge(&self, paths: Vec<String>) -> PurgeFuture<'_>;
}

/// Purges nothing. The default when no purge token is configured; pages
/// then leave caches when their max-age runs out.
#[derive(Debug, Default)]
pub struct NoCachePurger;

impl CachePurger for NoCachePurger {
    fn purge(&self, _paths: Vec<String>) -> PurgeFuture<'_> {
        Box::pin(std::future::ready(Ok(())))
    }
}

/// The public paths that show a page: the page, its data request, the list
/// and the sitemap.
pub fn page_paths(slug: &str) -> Vec<String> {
    vec![
        format!("/exploited/{slug}"),
        format!("/exploited/{slug}.data"),
        "/exploited".into(),
        "/exploited.data".into(),
        "/sitemap.xml".into(),
    ]
}
