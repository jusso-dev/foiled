-- D1 schema for control-plane config (#21, ADR 0009).
-- Attempts, IOCs, campaigns, review queue and audit live in Postgres.

CREATE TABLE IF NOT EXISTS api_tokens (
    id            TEXT PRIMARY KEY,
    tenant_id     TEXT NOT NULL,
    role          TEXT NOT NULL CHECK (role IN ('human', 'mcp')),
    scopes        TEXT NOT NULL,           -- space separated scope names
    secret_sha256 TEXT NOT NULL,           -- hex SHA-256 of the secret part only
    label         TEXT,
    created_at    INTEGER NOT NULL,
    expires_at    INTEGER,
    revoked       INTEGER NOT NULL DEFAULT 0
);

-- Sandbox hosts (#41) and edge sensors (#31), identified by client certificate.
CREATE TABLE IF NOT EXISTS identities (
    id          TEXT PRIMARY KEY,
    tenant_id   TEXT NOT NULL,
    role        TEXT NOT NULL CHECK (role IN ('host', 'sensor')),
    scopes      TEXT NOT NULL,
    cert_sha256 TEXT NOT NULL UNIQUE,
    created_at  INTEGER NOT NULL,
    revoked     INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS decoys (
    id           TEXT PRIMARY KEY,
    tenant_id    TEXT NOT NULL,
    catalogue_id TEXT NOT NULL,
    decoy_kind   TEXT NOT NULL CHECK (decoy_kind IN ('sandbox', 'emulation')),
    label        TEXT,
    state        TEXT NOT NULL CHECK (state IN ('pending', 'starting', 'healthy', 'rotating',
                                                 'stopped', 'quarantined', 'failed', 'destroyed')),
    host_id      TEXT,
    generation   INTEGER NOT NULL DEFAULT 1,
    created_at   INTEGER NOT NULL,
    updated_at   INTEGER NOT NULL,
    expires_at   INTEGER NOT NULL,
    created_by   TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS decoys_tenant_created ON decoys (tenant_id, created_at DESC, id DESC);

CREATE TABLE IF NOT EXISTS jobs (
    id              TEXT PRIMARY KEY,
    tenant_id       TEXT NOT NULL,
    decoy_id        TEXT NOT NULL REFERENCES decoys (id),
    host_id         TEXT,
    kind            TEXT NOT NULL,
    reason_code     TEXT,
    reason_text     TEXT,
    idempotency_key TEXT NOT NULL,
    created_at      INTEGER NOT NULL,
    expires_at      INTEGER NOT NULL,
    status          TEXT NOT NULL,
    UNIQUE (tenant_id, idempotency_key)
);
CREATE INDEX IF NOT EXISTS jobs_host_status ON jobs (host_id, status, created_at);

CREATE TABLE IF NOT EXISTS rate_limits (
    key          TEXT NOT NULL,
    window_start INTEGER NOT NULL,
    count        INTEGER NOT NULL,
    PRIMARY KEY (key, window_start)
);
