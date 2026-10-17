-- Capture envelopes written by the ingest Queue consumer (#9).
-- Delivery is at least once, so inserts are idempotent on event_id.
-- Rows are evidence: never updated; deleted only by the retention purge (#16).
CREATE TABLE IF NOT EXISTS capture_events (
    event_id     text NOT NULL,
    tenant_id    text NOT NULL,
    decoy_id     text NOT NULL,
    catalogue_id text NOT NULL,
    decoy_kind   text NOT NULL CHECK (decoy_kind IN ('sandbox', 'emulation')),
    ts           bigint NOT NULL,
    channel      text NOT NULL,
    severity     text NOT NULL,
    src_ip       inet NOT NULL,
    attempt_id   text,
    payload_ref  text,
    source_kind  text NOT NULL CHECK (source_kind IN ('host', 'sensor')),
    source_id    text NOT NULL,
    body         jsonb NOT NULL,
    received_at  bigint NOT NULL,
    PRIMARY KEY (tenant_id, event_id)
);

CREATE INDEX IF NOT EXISTS capture_events_decoy_ts ON capture_events (tenant_id, decoy_id, ts);
CREATE INDEX IF NOT EXISTS capture_events_src_ts ON capture_events (tenant_id, src_ip, ts);
CREATE INDEX IF NOT EXISTS capture_events_attempt ON capture_events (tenant_id, attempt_id) WHERE attempt_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS capture_events_received ON capture_events (received_at);

CREATE OR REPLACE FUNCTION capture_events_no_update() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'capture_events is append-only';
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS capture_events_no_update ON capture_events;
CREATE TRIGGER capture_events_no_update BEFORE UPDATE ON capture_events
    FOR EACH ROW EXECUTE FUNCTION capture_events_no_update();
