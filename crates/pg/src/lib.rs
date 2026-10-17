//! Postgres schema and queries for Foiled's intel store (ADR 0009).
//!
//! The same code runs natively (tests against a real Postgres in CI) and on
//! Workers, where the API Worker opens a `tokio_postgres::Client` over a
//! Hyperdrive socket. Nothing here spawns tasks or touches the network
//! itself: callers hand in a connected client.

use foiled_core::audit::{AuditRecord, Outcome};
use foiled_core::auth::Role;
use tokio_postgres::{Client, Error, Row};

/// Ordered migrations under `migrations/postgres/`.
pub const MIGRATIONS: &[(&str, &str)] = &[(
    "0001_audit",
    include_str!("../../../migrations/postgres/0001_audit.sql"),
)];

/// Arbitrary constant key for the migration advisory lock.
const MIGRATION_LOCK_KEY: i64 = 0x666f_696c_6564; // "foiled"

/// Apply any migration not yet recorded in `schema_migrations`. Intended for
/// tests and operator tooling, never called per request from the Worker.
///
/// Safe to call from several connections at once: a session advisory lock
/// serialises runners, and each migration commits with its bookkeeping row.
pub async fn migrate(client: &Client) -> Result<Vec<&'static str>, Error> {
    client
        .execute("SELECT pg_advisory_lock($1)", &[&MIGRATION_LOCK_KEY])
        .await?;
    let result = migrate_locked(client).await;
    let unlock = client
        .execute("SELECT pg_advisory_unlock($1)", &[&MIGRATION_LOCK_KEY])
        .await;
    let applied = result?;
    unlock?;
    Ok(applied)
}

async fn migrate_locked(client: &Client) -> Result<Vec<&'static str>, Error> {
    client
        .batch_execute(
            "CREATE TABLE IF NOT EXISTS schema_migrations (
                version text PRIMARY KEY,
                applied_at timestamptz NOT NULL DEFAULT now()
            )",
        )
        .await?;
    let mut applied = Vec::new();
    for (version, sql) in MIGRATIONS {
        let done = client
            .query_opt(
                "SELECT 1 FROM schema_migrations WHERE version = $1",
                &[version],
            )
            .await?
            .is_some();
        if done {
            continue;
        }
        client.batch_execute("BEGIN").await?;
        let step = async {
            client.batch_execute(sql).await?;
            client
                .execute(
                    "INSERT INTO schema_migrations (version) VALUES ($1)",
                    &[version],
                )
                .await
        }
        .await;
        match step {
            Ok(_) => client.batch_execute("COMMIT").await?,
            Err(e) => {
                client.batch_execute("ROLLBACK").await?;
                return Err(e);
            }
        }
        applied.push(*version);
    }
    Ok(applied)
}

pub async fn append_audit(client: &Client, r: &AuditRecord) -> Result<(), Error> {
    client
        .execute(
            "INSERT INTO audit_log (id, ts, tenant_id, actor_id, actor_kind, action, target,
                reason_code, reason_text, job_id, idempotency_key, outcome, detail)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)",
            &[
                &r.id,
                &r.ts,
                &r.tenant_id,
                &r.actor_id,
                &r.actor_kind.as_str(),
                &r.action,
                &r.target,
                &r.reason_code,
                &r.reason_text,
                &r.job_id,
                &r.idempotency_key,
                &r.outcome.as_str(),
                &r.detail,
            ],
        )
        .await?;
    Ok(())
}

/// Filters for [`list_audit`]. `before` is a `(ts, id)` keyset cursor.
#[derive(Debug, Clone, Default)]
pub struct AuditFilter {
    pub action: Option<String>,
    pub target: Option<String>,
    pub before: Option<(i64, String)>,
    pub limit: i64,
}

/// Newest first, keyset paginated on `(ts, id)`.
pub async fn list_audit(
    client: &Client,
    tenant_id: &str,
    f: &AuditFilter,
) -> Result<Vec<AuditRecord>, Error> {
    let (before_ts, before_id) = match &f.before {
        Some((ts, id)) => (Some(*ts), Some(id.as_str())),
        None => (None, None),
    };
    let rows = client
        .query(
            "SELECT id, ts, tenant_id, actor_id, actor_kind, action, target, reason_code,
                    reason_text, job_id, idempotency_key, outcome, detail
             FROM audit_log
             WHERE tenant_id = $1
               AND ($2::text IS NULL OR action = $2)
               AND ($3::text IS NULL OR target = $3)
               AND ($4::bigint IS NULL OR (ts, id) < ($4, $5::text))
             ORDER BY ts DESC, id DESC
             LIMIT $6",
            &[
                &tenant_id, &f.action, &f.target, &before_ts, &before_id, &f.limit,
            ],
        )
        .await?;
    Ok(rows.iter().filter_map(audit_from_row).collect())
}

fn audit_from_row(row: &Row) -> Option<AuditRecord> {
    Some(AuditRecord {
        id: row.get("id"),
        ts: row.get("ts"),
        tenant_id: row.get("tenant_id"),
        actor_id: row.get("actor_id"),
        actor_kind: Role::parse(row.get("actor_kind"))?,
        action: row.get("action"),
        target: row.get("target"),
        reason_code: row.get("reason_code"),
        reason_text: row.get("reason_text"),
        job_id: row.get("job_id"),
        idempotency_key: row.get("idempotency_key"),
        outcome: Outcome::parse(row.get("outcome"))?,
        detail: row.get("detail"),
    })
}
