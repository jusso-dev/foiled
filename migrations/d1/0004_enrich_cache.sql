-- Enrichment cache (#11, docs/enrichment.md). One row per provider and
-- observable, shared by every tenant of a deployment; who may read which
-- Facts is decided in code (foiled_core::enrichment::usable_facts). The
-- foiled-enrich consumer writes rows; the API reads them for ASN context on
-- IOCs and exports. The retention purge (#16) deletes rows past their
-- per-provider enrichment_cache TTL.
CREATE TABLE IF NOT EXISTS enrich_cache (
    cache_key  TEXT PRIMARY KEY,      -- provider:kind:value (Observable::cache_key)
    provider   TEXT NOT NULL,
    kind       TEXT NOT NULL CHECK (kind IN ('ip', 'domain', 'sha256', 'url')),
    value      TEXT NOT NULL,         -- normalised observable value
    fetched_at INTEGER NOT NULL,      -- unix ms
    ttl_secs   INTEGER NOT NULL CHECK (ttl_secs >= 0),
    facts      TEXT NOT NULL          -- JSON array of Facts, [] for "knows nothing"
);
CREATE INDEX IF NOT EXISTS enrich_cache_observable ON enrich_cache (kind, value);
CREATE INDEX IF NOT EXISTS enrich_cache_age ON enrich_cache (provider, fetched_at);
