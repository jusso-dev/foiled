-- Enrolment, certificate rotation and the sensor and host registry (#31, ADR 0007).

-- One row per client certificate rather than per identity, so a renewal can
-- overlap the old and new certificates for a short grace period.
CREATE TABLE identities_v2 (
    cert_sha256 TEXT PRIMARY KEY,         -- lowercase hex SHA-256 of the DER certificate
    id          TEXT NOT NULL,            -- host or sensor id
    tenant_id   TEXT NOT NULL,
    role        TEXT NOT NULL CHECK (role IN ('host', 'sensor')),
    scopes      TEXT NOT NULL,
    created_at  INTEGER NOT NULL,
    revoked     INTEGER NOT NULL DEFAULT 0,
    valid_until INTEGER,                  -- unix ms; set when the certificate is retired
    issuer_ref  TEXT,                     -- the CA's certificate id, used to revoke it there
    expires_at  INTEGER                   -- certificate notAfter, unix ms
);
INSERT INTO identities_v2 (cert_sha256, id, tenant_id, role, scopes, created_at, revoked)
    SELECT cert_sha256, id, tenant_id, role, scopes, created_at, revoked FROM identities;
DROP TABLE identities;
ALTER TABLE identities_v2 RENAME TO identities;
CREATE INDEX IF NOT EXISTS identities_by_id ON identities (tenant_id, id);

-- `sensor:heartbeat` was folded into `sensor:report`. Strip the old name so
-- no stored row carries a scope the code no longer knows.
UPDATE identities SET scopes = TRIM(REPLACE(scopes, 'sensor:heartbeat', ''))
    WHERE scopes LIKE '%sensor:heartbeat%';
UPDATE api_tokens SET scopes = TRIM(REPLACE(scopes, 'sensor:heartbeat', ''))
    WHERE scopes LIKE '%sensor:heartbeat%';

-- Registered sensors and hosts. Identity comes from the certificate; this
-- table holds lifecycle and what the console shows.
CREATE TABLE IF NOT EXISTS agents (
    id                 TEXT PRIMARY KEY,
    tenant_id          TEXT NOT NULL,
    role               TEXT NOT NULL CHECK (role IN ('host', 'sensor')),
    label              TEXT,
    status             TEXT NOT NULL CHECK (status IN ('pending', 'active', 'revoked')),
    sandbox_allowed    INTEGER NOT NULL DEFAULT 0,
    share_opt_in       INTEGER,           -- NULL means the contribute-back default (#37)
    created_at         INTEGER NOT NULL,
    created_by         TEXT NOT NULL,
    enrolled_at        INTEGER,
    cert_sha256        TEXT,
    cert_expires_at    INTEGER,
    last_seen_at       INTEGER,
    last_ip            TEXT,
    last_asn           INTEGER,
    network_changed_at INTEGER,
    revoked_at         INTEGER,
    revoke_reason_code TEXT,
    revoke_reason_text TEXT
);
CREATE INDEX IF NOT EXISTS agents_tenant_role_created ON agents (tenant_id, role, created_at DESC, id DESC);

-- One-time enrolment tokens. Only the SHA-256 of the secret is stored.
CREATE TABLE IF NOT EXISTS enrolment_tokens (
    id            TEXT PRIMARY KEY,
    tenant_id     TEXT NOT NULL,
    agent_id      TEXT NOT NULL REFERENCES agents (id),
    role          TEXT NOT NULL CHECK (role IN ('host', 'sensor')),
    secret_sha256 TEXT NOT NULL,
    created_at    INTEGER NOT NULL,
    expires_at    INTEGER NOT NULL,
    created_by    TEXT NOT NULL,
    used_at       INTEGER
);
CREATE INDEX IF NOT EXISTS enrolment_tokens_agent ON enrolment_tokens (tenant_id, agent_id);

-- Identities created before this migration (hand-registered hosts) get a
-- registry row, so they can be listed, revoked and renewed through the API.
-- Their certificates have no CA reference: revoke those at the CA by hand.
INSERT OR IGNORE INTO agents (id, tenant_id, role, status, sandbox_allowed, created_at,
                              created_by, enrolled_at, cert_sha256)
    SELECT id, tenant_id, role,
           CASE WHEN MAX(revoked) = 1 THEN 'revoked' ELSE 'active' END,
           CASE WHEN role = 'host' THEN 1 ELSE 0 END,
           MIN(created_at), 'migration-0003', MIN(created_at), MAX(cert_sha256)
    FROM identities GROUP BY tenant_id, id, role;
