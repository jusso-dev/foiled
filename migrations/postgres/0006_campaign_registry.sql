-- Campaign registry (#33): which campaign each attempt was last recorded
-- in, and when each campaign id was first recorded. Clustering reuses the
-- oldest recorded id of a cluster's members, so ids, labels, merges and
-- splits hold as the read window moves. Rows hold attempt ids and times, no
-- addresses; they follow the attempt TTL (#16).
CREATE TABLE IF NOT EXISTS campaigns (
    tenant_id   text NOT NULL,
    campaign_id text NOT NULL,
    created_at  bigint NOT NULL,
    first_seen  bigint NOT NULL,
    last_seen   bigint NOT NULL,
    merged_into text,
    updated_at  bigint NOT NULL,
    PRIMARY KEY (tenant_id, campaign_id)
);

CREATE TABLE IF NOT EXISTS campaign_members (
    tenant_id          text NOT NULL,
    attempt_id         text NOT NULL,
    campaign_id        text NOT NULL,
    attempt_first_seen bigint NOT NULL,
    recorded_at        bigint NOT NULL,
    PRIMARY KEY (tenant_id, attempt_id)
);

CREATE INDEX IF NOT EXISTS campaign_members_campaign
    ON campaign_members (tenant_id, campaign_id);
CREATE INDEX IF NOT EXISTS campaign_members_first_seen
    ON campaign_members (tenant_id, attempt_first_seen);

-- Feedback is the only action kind the replay caps; this index serves the
-- "every structural action plus the newest feedback" read.
CREATE INDEX IF NOT EXISTS campaign_actions_tenant_kind_at
    ON campaign_actions (tenant_id, kind, at DESC, action_id DESC);
