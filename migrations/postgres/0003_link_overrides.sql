-- Analyst decisions on confidence links (#27). The latest decision per link
-- wins; every change is also written to the audit log by the API.
CREATE TABLE IF NOT EXISTS link_overrides (
    tenant_id  text NOT NULL,
    attempt_id text NOT NULL,
    kind       text NOT NULL CHECK (kind IN ('attempt_cve', 'attempt_technique', 'attempt_actor', 'attempt_campaign')),
    target     text NOT NULL,
    feedback   text NOT NULL CHECK (feedback IN ('true_positive', 'false_positive', 'unsure')),
    analyst_id text NOT NULL,
    at         bigint NOT NULL,
    note       text NOT NULL DEFAULT '',
    PRIMARY KEY (tenant_id, attempt_id, kind, target)
);
