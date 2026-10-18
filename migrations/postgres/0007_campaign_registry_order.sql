-- Campaign registry ordering and bridge provenance (#33).
--
-- created_at is set on insert and never changed, and merged_into is
-- write-once and may only point at a strictly older campaign by
-- (created_at, campaign_id). That order is total and immutable, so no chain
-- of merges can loop, whatever order concurrent writers commit in. The API
-- writes merges with a join that already checks this; the triggers below
-- are the backstop for any other writer.

-- Clear merges written before this rule that do not point strictly older.
UPDATE campaigns c SET merged_into = NULL
WHERE c.merged_into IS NOT NULL
  AND NOT EXISTS (
    SELECT 1 FROM campaigns t
    WHERE t.tenant_id = c.tenant_id
      AND t.campaign_id = c.merged_into
      AND (t.created_at, t.campaign_id) < (c.created_at, c.campaign_id));

CREATE OR REPLACE FUNCTION campaigns_registry_order() RETURNS trigger AS $$
BEGIN
    IF TG_OP = 'UPDATE' THEN
        IF NEW.created_at <> OLD.created_at THEN
            RAISE EXCEPTION 'campaigns.created_at is set on insert only';
        END IF;
        IF OLD.merged_into IS NOT NULL AND NEW.merged_into IS DISTINCT FROM OLD.merged_into THEN
            RAISE EXCEPTION 'campaigns.merged_into is write-once';
        END IF;
    END IF;
    IF NEW.merged_into IS NOT NULL
       AND (TG_OP = 'INSERT' OR OLD.merged_into IS NULL)
       AND NOT EXISTS (
         SELECT 1 FROM campaigns t
         WHERE t.tenant_id = NEW.tenant_id
           AND t.campaign_id = NEW.merged_into
           AND (t.created_at, t.campaign_id) < (NEW.created_at, NEW.campaign_id)) THEN
        RAISE EXCEPTION 'campaigns.merged_into must name a strictly older campaign';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS campaigns_registry_order ON campaigns;
CREATE TRIGGER campaigns_registry_order BEFORE INSERT OR UPDATE ON campaigns
    FOR EACH ROW EXECUTE FUNCTION campaigns_registry_order();

-- Provenance for every merge the registry makes permanent: which attempts
-- and feature joined two groups into one campaign. merged_campaign_id is the
-- recorded campaign folded in, or NULL when two groups merged before either
-- was recorded. small_halves flags merges made while a side was below the
-- forged-bridge guard size. Rows are only written for merges that were
-- applied, and are never edited.
CREATE TABLE IF NOT EXISTS campaign_bridges (
    tenant_id          text NOT NULL,
    campaign_id        text NOT NULL,
    merged_campaign_id text,
    attempt_id         text NOT NULL,
    with_attempt_id    text NOT NULL,
    signal_id          text NOT NULL,
    feature            text NOT NULL,
    attempt_side       integer NOT NULL,
    with_side          integer NOT NULL,
    small_halves       boolean NOT NULL,
    recorded_at        bigint NOT NULL,
    PRIMARY KEY (tenant_id, campaign_id, attempt_id, with_attempt_id, signal_id)
);
