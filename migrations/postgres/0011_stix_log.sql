-- Materialised STIX object log behind TAXII (#13). TAXII serves these rows
-- and never rebuilds objects on a request.
--
-- stix_object_versions holds one row per object version and is append-only:
-- a version's content never changes, so an (id, version) pair always names
-- the same JSON (STIX 2.1 section 3.6). The materialiser writes a version
-- only when the content differs from the object's current head, keeps
-- `created` from the first version, revokes (a last version with
-- `revoked: true`) what no day supports any more, and gives each append one
-- date_added later than every row before it, so paging on
-- (date_added, id, version) never skips or repeats a row. Rows are removed
-- only by the retention purge (#16), a whole object at a time, when the
-- newest evidence behind it is older than the attempt TTL.
--
-- Ids and versions compare byte-wise (COLLATE "C") so cursors order the
-- same in every database locale.
CREATE TABLE IF NOT EXISTS stix_object_versions (
    tenant_id      text   NOT NULL,
    collection_id  text   NOT NULL,
    id             text   COLLATE "C" NOT NULL,
    version        text   COLLATE "C" NOT NULL,
    created        text,
    object_type    text   NOT NULL,
    date_added     bigint NOT NULL,
    content        text   NOT NULL,
    content_sha256 text   NOT NULL,
    PRIMARY KEY (tenant_id, collection_id, id, version)
);

CREATE INDEX IF NOT EXISTS stix_object_versions_paging
    ON stix_object_versions (tenant_id, collection_id, date_added, id, version);

CREATE OR REPLACE FUNCTION stix_object_versions_no_update() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'stix_object_versions is append-only';
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS stix_object_versions_no_update ON stix_object_versions;
CREATE TRIGGER stix_object_versions_no_update BEFORE UPDATE ON stix_object_versions
    FOR EACH ROW EXECUTE FUNCTION stix_object_versions_no_update();

-- One row per object: the first version's `created`, the newest version
-- and its content hash (for match[version]=last and "same as the head"),
-- the newest evidence time and every id any version refers to (for
-- retention).
CREATE TABLE IF NOT EXISTS stix_object_heads (
    tenant_id       text   NOT NULL,
    collection_id   text   NOT NULL,
    id              text   COLLATE "C" NOT NULL,
    created         text,
    latest_version  text   COLLATE "C" NOT NULL,
    latest_sha256   text   NOT NULL,
    max_evidence_ms bigint NOT NULL DEFAULT 0,
    refs            text[] NOT NULL DEFAULT '{}',
    PRIMARY KEY (tenant_id, collection_id, id)
);

CREATE INDEX IF NOT EXISTS stix_object_heads_evidence
    ON stix_object_heads (tenant_id, collection_id, max_evidence_ms);

-- The scheduled run's tenant list (every tenant with a log) without a
-- scan of every head.
CREATE INDEX IF NOT EXISTS stix_object_heads_collection
    ON stix_object_heads (collection_id, tenant_id);

CREATE INDEX IF NOT EXISTS stix_object_heads_refs
    ON stix_object_heads USING gin (refs);

-- The materialiser's record of each UTC day: the signature of the inputs
-- its published objects were built from (its events; the analyst
-- decisions, campaign memberships and actions and enrichment touching its
-- attempts; rule and config versions), so a run skips unchanged days; the
-- ids of the day's own objects, so a later publish can revoke what it no
-- longer supports; a build or publish in progress (JSON: target signature,
-- event cursor, parts staged, ids published, phase), continued by the next
-- run; and when the day last got build time, for round-robin.
CREATE TABLE IF NOT EXISTS stix_materialised_days (
    tenant_id     text   NOT NULL,
    collection_id text   NOT NULL,
    day_ms        bigint NOT NULL,
    signature     text   NOT NULL,
    object_ids    text[] NOT NULL DEFAULT '{}',
    progress      text,
    served_ms     bigint NOT NULL DEFAULT 0,
    PRIMARY KEY (tenant_id, collection_id, day_ms)
);

-- A day's attempts as scored, before the gate (JSON `AttemptRecord`):
-- staged by a build, live once the build is complete. The day's own
-- objects (observed-data, groupings, notes, link targets and their
-- relationships) are built from the live rows when the day is published,
-- against the merged gate decision, so they only name published IOCs.
CREATE TABLE IF NOT EXISTS stix_day_attempts (
    tenant_id     text    NOT NULL,
    collection_id text    NOT NULL,
    live          boolean NOT NULL,
    day_ms        bigint  NOT NULL,
    attempt_id    text    COLLATE "C" NOT NULL,
    body          text    NOT NULL,
    PRIMARY KEY (tenant_id, collection_id, live, day_ms, attempt_id)
);

-- Each day's share of each IOC (JSON `IocContribution`), one row per build
-- part. Indicators, sightings, observables and malware are built from the
-- merge of every live row for the IOC, so they do not depend on which day
-- ran last. Staged rows become live when the day's last part is staged.
CREATE TABLE IF NOT EXISTS stix_ioc_contributions (
    tenant_id     text    NOT NULL,
    collection_id text    NOT NULL,
    live          boolean NOT NULL,
    day_ms        bigint  NOT NULL,
    part          integer NOT NULL,
    ioc_id        text    COLLATE "C" NOT NULL,
    body          text    NOT NULL,
    PRIMARY KEY (tenant_id, collection_id, live, day_ms, part, ioc_id)
);

CREATE INDEX IF NOT EXISTS stix_ioc_contributions_ioc
    ON stix_ioc_contributions (tenant_id, collection_id, ioc_id) WHERE live;

-- IOCs whose merged view passes the gate, with the type and value the
-- days' objects need to name their observable and indicator. Below-gate
-- IOCs are never listed, so nothing below the gate can be referenced.
CREATE TABLE IF NOT EXISTS stix_ioc_published (
    tenant_id     text NOT NULL,
    collection_id text NOT NULL,
    ioc_id        text COLLATE "C" NOT NULL,
    ioc_type      text NOT NULL,
    value         text NOT NULL,
    PRIMARY KEY (tenant_id, collection_id, ioc_id)
);

-- IOCs whose contributions changed and whose merged objects (step
-- `merge`), then sightings (step `sighting`), are still to be published.
CREATE TABLE IF NOT EXISTS stix_pending_iocs (
    tenant_id     text NOT NULL,
    collection_id text NOT NULL,
    step          text NOT NULL CHECK (step IN ('merge', 'sighting')),
    ioc_id        text COLLATE "C" NOT NULL,
    PRIMARY KEY (tenant_id, collection_id, step, ioc_id)
);

-- One materialiser run per tenant at a time. A lease, not a session lock,
-- so a Worker that dies mid-run cannot hold it past `expires_at` (judged by
-- the database clock). `generation` is the fencing token: a takeover
-- increments it, it never goes back, and every materialiser write checks it
-- with stix_fence in its own transaction, so a run that stalled past its
-- lease cannot overwrite its successor's work.
CREATE TABLE IF NOT EXISTS stix_materialiser_leases (
    tenant_id     text   NOT NULL,
    collection_id text   NOT NULL,
    holder        text   NOT NULL,
    expires_at    bigint NOT NULL,
    generation    bigint NOT NULL DEFAULT 1,
    PRIMARY KEY (tenant_id, collection_id)
);

-- Lock the lease row against takeover until the calling transaction ends,
-- and fail unless its generation is the caller's.
CREATE OR REPLACE FUNCTION stix_fence(t text, c text, g bigint) RETURNS void AS $$
DECLARE
    current bigint;
BEGIN
    SELECT generation INTO current FROM stix_materialiser_leases
    WHERE tenant_id = t AND collection_id = c FOR SHARE;
    IF current IS DISTINCT FROM g THEN
        RAISE EXCEPTION 'stix lease lost: generation %, current %', g, current;
    END IF;
END;
$$ LANGUAGE plpgsql;

-- The last tenant the scheduled materialiser served, so each tick starts
-- after it.
CREATE TABLE IF NOT EXISTS stix_cron_cursor (
    collection_id text PRIMARY KEY,
    tenant_id     text NOT NULL
);
