-- Audit log (#21). Append-only: rows are inserted by the API Worker and only
-- deleted by the retention purge (#16). Updates are refused by trigger.
CREATE TABLE IF NOT EXISTS audit_log (
    id              text PRIMARY KEY,
    ts              bigint NOT NULL,
    tenant_id       text NOT NULL,
    actor_id        text NOT NULL,
    actor_kind      text NOT NULL CHECK (actor_kind IN ('human', 'mcp', 'host', 'sensor')),
    action          text NOT NULL,
    target          text,
    reason_code     text,
    reason_text     text,
    job_id          text,
    idempotency_key text,
    outcome         text NOT NULL CHECK (outcome IN ('accepted', 'denied', 'failed')),
    detail          jsonb NOT NULL DEFAULT 'null'::jsonb
);

CREATE INDEX IF NOT EXISTS audit_log_tenant_ts ON audit_log (tenant_id, ts DESC, id DESC);
CREATE INDEX IF NOT EXISTS audit_log_tenant_target ON audit_log (tenant_id, target);

CREATE OR REPLACE FUNCTION audit_log_no_update() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'audit_log is append-only';
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS audit_log_no_update ON audit_log;
CREATE TRIGGER audit_log_no_update BEFORE UPDATE ON audit_log
    FOR EACH ROW EXECUTE FUNCTION audit_log_no_update();
