-- Enrichment consumer state (#11, docs/enrichment.md).

-- enrich_cache gains tenant_id (rows only the looking-up tenant may read,
-- for ThreatSieve answers with a source that may not be shared) and the
-- `cve` kind. SQLite cannot change a CHECK in place, so the table is
-- rebuilt; existing rows are kept as shared rows.
CREATE TABLE enrich_cache_v2 (
    cache_key  TEXT PRIMARY KEY,      -- provider:kind:value, plus @tenant for a tenant row
    provider   TEXT NOT NULL,
    kind       TEXT NOT NULL CHECK (kind IN ('ip', 'domain', 'sha256', 'url', 'cve')),
    value      TEXT NOT NULL,         -- normalised observable value
    fetched_at INTEGER NOT NULL,      -- unix ms
    ttl_secs   INTEGER NOT NULL CHECK (ttl_secs >= 0),
    facts      TEXT NOT NULL,         -- JSON array of Facts, [] for "knows nothing"
    tenant_id  TEXT                   -- NULL: any tenant may read the row
);
INSERT INTO enrich_cache_v2 (cache_key, provider, kind, value, fetched_at, ttl_secs, facts)
    SELECT cache_key, provider, kind, value, fetched_at, ttl_secs, facts FROM enrich_cache;
DROP TABLE enrich_cache;
ALTER TABLE enrich_cache_v2 RENAME TO enrich_cache;
CREATE INDEX IF NOT EXISTS enrich_cache_observable ON enrich_cache (kind, value);
CREATE INDEX IF NOT EXISTS enrich_cache_age ON enrich_cache (provider, fetched_at);

-- One counter per provider and window. Taken with a conditional upsert so
-- two consumer invocations can never overspend a provider's quota.
CREATE TABLE IF NOT EXISTS enrich_budget (
    provider     TEXT NOT NULL,
    window       TEXT NOT NULL CHECK (window IN ('minute', 'day')),
    window_start INTEGER NOT NULL,        -- unix ms, truncated to the window
    used         INTEGER NOT NULL CHECK (used >= 0),
    PRIMARY KEY (provider, window, window_start)
);

-- Failed lookups per observable, for exponential backoff and Retry-After.
-- Cleared when the provider answers. Never holds a response body or a key.
CREATE TABLE IF NOT EXISTS enrich_failures (
    cache_key      TEXT PRIMARY KEY,      -- provider:kind:value
    provider       TEXT NOT NULL,
    kind           TEXT NOT NULL,
    value          TEXT NOT NULL,
    failures       INTEGER NOT NULL CHECK (failures >= 1),
    last_failed_at INTEGER NOT NULL,      -- unix ms
    retry_at       INTEGER,               -- unix ms, from Retry-After
    last_error     TEXT NOT NULL          -- short, clipped
);
CREATE INDEX IF NOT EXISTS enrich_failures_observable ON enrich_failures (kind, value);
