-- Analyst actions on campaigns (#33): label, status, merge, split and
-- feedback. Append-only: actions are replayed in (at, action_id) order over
-- the computed clustering, so a row is never edited. Updates are refused by
-- trigger; rows only leave with the tenant. Every row is also written to the
-- audit log by the API.
CREATE TABLE IF NOT EXISTS campaign_actions (
    tenant_id   text NOT NULL,
    action_id   text NOT NULL,
    campaign_id text NOT NULL,
    kind        text NOT NULL CHECK (kind IN ('label', 'status', 'merge', 'split', 'feedback')),
    analyst_id  text NOT NULL,
    at          bigint NOT NULL,
    body        jsonb NOT NULL,
    PRIMARY KEY (tenant_id, action_id)
);

CREATE INDEX IF NOT EXISTS campaign_actions_tenant_at
    ON campaign_actions (tenant_id, at DESC, action_id DESC);

CREATE OR REPLACE FUNCTION campaign_actions_append_only() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'campaign_actions is append-only';
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS campaign_actions_no_update ON campaign_actions;
CREATE TRIGGER campaign_actions_no_update
    BEFORE UPDATE ON campaign_actions
    FOR EACH ROW EXECUTE FUNCTION campaign_actions_append_only();
