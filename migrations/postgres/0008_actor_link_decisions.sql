-- Analyst decisions on actor possible-associations (#29). One row per
-- subject (campaign or attempt id) and actor id; the latest decision wins.
-- Every change is also written to the audit log by the API as
-- actor_link.confirm, actor_link.reject or actor_link.reopen. Rows hold ids,
-- an analyst id and the analyst's note, no addresses.
CREATE TABLE IF NOT EXISTS actor_link_decisions (
    tenant_id  text NOT NULL,
    subject_id text NOT NULL,
    actor_id   text NOT NULL CHECK (actor_id ~ '^(attack|report):[A-Za-z0-9-]{1,64}$'),
    feedback   text NOT NULL CHECK (feedback IN ('true_positive', 'false_positive', 'unsure')),
    analyst_id text NOT NULL,
    at         bigint NOT NULL,
    note       text NOT NULL DEFAULT '',
    PRIMARY KEY (tenant_id, subject_id, actor_id)
);
