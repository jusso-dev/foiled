-- Review queue, research write-ups, public pages and radar rollups (#35).
-- See docs/review-queue.md, docs/research-writeups.md and docs/radar.md.

-- Analyst state per review queue item. Items themselves are derived on
-- read; only the claim, assignment, snooze and decision are stored. Writes
-- compare and set on version. Every action is also in the audit log.
CREATE TABLE IF NOT EXISTS review_states (
    tenant_id  text NOT NULL,
    item_id    text NOT NULL CHECK (item_id ~ '^rq_[a-f0-9]{24}$'),
    kind       text NOT NULL CHECK (kind IN ('cve_link', 'predisclosure_candidate', 'technique_link',
                                             'ioc_publication', 'campaign_label', 'actor_association', 'write_up')),
    status     text NOT NULL CHECK (status IN ('open', 'claimed', 'snoozed', 'approved', 'rejected')),
    version    integer NOT NULL CHECK (version > 0),
    updated_at bigint NOT NULL,
    body       jsonb NOT NULL,
    PRIMARY KEY (tenant_id, item_id)
);

-- Write-ups: the current version per write-up.
CREATE TABLE IF NOT EXISTS writeups (
    tenant_id  text NOT NULL,
    writeup_id text NOT NULL CHECK (writeup_id ~ '^wu_[a-f0-9]{24}$'),
    status     text NOT NULL CHECK (status IN ('draft', 'review', 'approved', 'published', 'withdrawn')),
    version    integer NOT NULL CHECK (version > 0),
    updated_at bigint NOT NULL,
    body       jsonb NOT NULL,
    PRIMARY KEY (tenant_id, writeup_id)
);

CREATE INDEX IF NOT EXISTS writeups_tenant_updated
    ON writeups (tenant_id, updated_at DESC, writeup_id DESC);

-- Every version of every write-up, append-only.
CREATE TABLE IF NOT EXISTS writeup_versions (
    tenant_id  text NOT NULL,
    writeup_id text NOT NULL,
    version    integer NOT NULL,
    action     text NOT NULL,
    actor_id   text NOT NULL,
    at         bigint NOT NULL,
    body       jsonb NOT NULL,
    PRIMARY KEY (tenant_id, writeup_id, version)
);

CREATE OR REPLACE FUNCTION writeup_versions_append_only() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'writeup_versions is append-only';
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS writeup_versions_no_update ON writeup_versions;
CREATE TRIGGER writeup_versions_no_update
    BEFORE UPDATE ON writeup_versions
    FOR EACH ROW EXECUTE FUNCTION writeup_versions_append_only();

-- Public exploit pages: allow-listed snapshots written at publish time.
-- The public routes read `page` only, never tenant_id or writeup_id.
CREATE TABLE IF NOT EXISTS public_pages (
    slug         text PRIMARY KEY CHECK (slug ~ '^[a-z0-9]+(-[a-z0-9]+)*$'),
    tenant_id    text NOT NULL,
    writeup_id   text NOT NULL,
    -- Write-up version of the snapshot; older ones never replace newer.
    version      integer NOT NULL,
    visible_from bigint NOT NULL,
    page         jsonb NOT NULL,
    UNIQUE (tenant_id, writeup_id)
);

CREATE INDEX IF NOT EXISTS public_pages_visible
    ON public_pages (visible_from DESC, slug DESC);

-- Radar daily rollups, one row per key, sensor and hashed source per
-- tenant-day. Replaced whole per tenant-day. Never read by key, sensor or
-- source from outside the aggregation.
CREATE TABLE IF NOT EXISTS radar_rollups (
    tenant_id text NOT NULL,
    day       bigint NOT NULL CHECK (day % 86400000 = 0),
    dimension text NOT NULL CHECK (dimension IN ('cve', 'technique', 'campaign', 'product')),
    key       text NOT NULL,
    sensor    text NOT NULL,
    source    text NOT NULL,
    body      jsonb NOT NULL,
    PRIMARY KEY (tenant_id, day, dimension, key, sensor, source)
);

CREATE INDEX IF NOT EXISTS radar_rollups_day ON radar_rollups (day);
