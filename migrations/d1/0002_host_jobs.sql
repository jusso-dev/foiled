-- Host agent job leasing and heartbeats (#41).
ALTER TABLE jobs ADD COLUMN params TEXT;          -- JSON DecoyParams for create and rebuild jobs
ALTER TABLE jobs ADD COLUMN leased_until INTEGER; -- unix ms; NULL unless status = 'leased'

CREATE TABLE IF NOT EXISTS host_heartbeats (
    tenant_id     TEXT NOT NULL,
    host_id       TEXT NOT NULL,
    heartbeat     TEXT NOT NULL,     -- JSON foiled_core::agent::Heartbeat
    clock_skew_ms INTEGER NOT NULL,  -- host clock minus control plane clock
    received_at   INTEGER NOT NULL,
    PRIMARY KEY (tenant_id, host_id)
);
