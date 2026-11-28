-- Out-of-band human approval for destructive MCP tools (#95,
-- docs/mcp/foiled-mcp.md).

-- Destructive actions a token asks for run without a human when this is 1.
-- For trusted automation only. Off for every existing token; only an admin
-- operator can turn it on (PUT /v0/tokens/{token_id}/auto-approve).
ALTER TABLE api_tokens ADD COLUMN auto_approve INTEGER NOT NULL DEFAULT 0
    CHECK (auto_approve IN (0, 1));

-- reset_sandbox and destroy_sandbox calls from agents, held until a human
-- approves or rejects them in the console. A pending row past expires_at is
-- expired and never runs. Status moves once, by compare-and-set:
-- pending -> approved -> executed or failed, or pending -> rejected.
CREATE TABLE IF NOT EXISTS pending_actions (
    id              TEXT PRIMARY KEY,
    tenant_id       TEXT NOT NULL,
    action          TEXT NOT NULL CHECK (action IN ('reset', 'destroy')),
    sandbox_id      TEXT NOT NULL,
    reason_code     TEXT NOT NULL,
    reason_text     TEXT NOT NULL,
    idempotency_key TEXT,
    requested_by    TEXT NOT NULL,          -- token id of the agent
    requested_kind  TEXT NOT NULL CHECK (requested_kind IN ('human', 'mcp')),
    created_at      INTEGER NOT NULL,       -- unix ms
    expires_at      INTEGER NOT NULL,       -- unix ms
    status          TEXT NOT NULL CHECK (status IN ('pending', 'approved', 'executed',
                                                    'failed', 'rejected')),
    decided_by      TEXT,                   -- token id of the human
    decided_at      INTEGER,
    note            TEXT,
    job_id          TEXT,
    error_code      TEXT,
    UNIQUE (tenant_id, requested_by, idempotency_key)
);
CREATE INDEX IF NOT EXISTS pending_actions_tenant_created
    ON pending_actions (tenant_id, created_at DESC, id DESC);
CREATE INDEX IF NOT EXISTS pending_actions_requester_open
    ON pending_actions (tenant_id, requested_by, status, expires_at);
