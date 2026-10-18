//! Postgres schema and queries for Foiled's intel store (ADR 0009).
//!
//! The same code runs natively (tests against a real Postgres in CI) and on
//! Workers, where the API Worker opens a `tokio_postgres::Client` over a
//! Hyperdrive socket. Nothing here spawns tasks or touches the network
//! itself: callers hand in a connected client.

use foiled_core::audit::{AuditRecord, Outcome};
use foiled_core::auth::Role;
use foiled_core::capture::CaptureEvent;
use tokio_postgres::{Client, Error, Row};

/// Ordered migrations under `migrations/postgres/`.
pub const MIGRATIONS: &[(&str, &str)] = &[
    (
        "0001_audit",
        include_str!("../../../migrations/postgres/0001_audit.sql"),
    ),
    (
        "0002_capture_events",
        include_str!("../../../migrations/postgres/0002_capture_events.sql"),
    ),
    (
        "0003_link_overrides",
        include_str!("../../../migrations/postgres/0003_link_overrides.sql"),
    ),
    (
        "0004_capture_events_source_key",
        include_str!("../../../migrations/postgres/0004_capture_events_source_key.sql"),
    ),
    (
        "0005_campaign_actions",
        include_str!("../../../migrations/postgres/0005_campaign_actions.sql"),
    ),
    (
        "0006_campaign_registry",
        include_str!("../../../migrations/postgres/0006_campaign_registry.sql"),
    ),
    (
        "0007_campaign_registry_order",
        include_str!("../../../migrations/postgres/0007_campaign_registry_order.sql"),
    ),
];

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

/// Insert stamped envelopes. Returns how many were new; replays of an
/// `event_id` already stored for the same sending identity are ignored (Queue
/// delivery is at least once).
/// Events without a stamped source or tenant are refused: they never came
/// through the ingest API.
pub async fn insert_events(
    client: &Client,
    events: &[CaptureEvent],
    received_at: i64,
) -> Result<u64, InsertError> {
    let stmt = client
        .prepare(
            "INSERT INTO capture_events (event_id, tenant_id, decoy_id, catalogue_id, decoy_kind, ts,
                channel, severity, src_ip, attempt_id, payload_ref, source_kind, source_id, body,
                received_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9::text::inet, $10, $11, $12, $13, $14, $15)
             ON CONFLICT (tenant_id, source_kind, source_id, event_id) DO NOTHING",
        )
        .await?;
    let mut inserted = 0;
    for e in events {
        let (Some(tenant), Some(source)) = (&e.tenant_id, &e.source) else {
            return Err(InsertError::Unstamped(e.event_id.clone()));
        };
        let body = serde_json::to_value(e).map_err(|err| InsertError::Encode(err.to_string()))?;
        let kind = serde_json::to_value(source.kind)
            .ok()
            .and_then(|v| v.as_str().map(str::to_string))
            .unwrap_or_default();
        inserted += client
            .execute(
                &stmt,
                &[
                    &e.event_id,
                    tenant,
                    &e.decoy_id,
                    &e.catalogue_id,
                    &e.decoy_kind.as_str(),
                    &e.ts,
                    &e.channel.as_str(),
                    &serde_json::to_value(e.severity)
                        .ok()
                        .and_then(|v| v.as_str().map(str::to_string))
                        .unwrap_or_default(),
                    &e.src.ip,
                    &e.attempt_id,
                    &e.payload_ref,
                    &kind,
                    &source.id,
                    &body,
                    &received_at,
                ],
            )
            .await?;
    }
    Ok(inserted)
}

/// Events for one decoy in time order, for timelines (#10) and tests.
pub async fn events_for_decoy(
    client: &Client,
    tenant_id: &str,
    decoy_id: &str,
    limit: i64,
) -> Result<Vec<CaptureEvent>, Error> {
    let rows = client
        .query(
            "SELECT body FROM capture_events WHERE tenant_id = $1 AND decoy_id = $2
             ORDER BY ts, event_id LIMIT $3",
            &[&tenant_id, &decoy_id, &limit],
        )
        .await?;
    Ok(rows
        .iter()
        .filter_map(|r| serde_json::from_value(r.get("body")).ok())
        .collect())
}

#[derive(Debug)]
pub enum InsertError {
    Db(Error),
    Unstamped(String),
    Encode(String),
}

impl From<Error> for InsertError {
    fn from(e: Error) -> Self {
        InsertError::Db(e)
    }
}

impl std::fmt::Display for InsertError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            InsertError::Db(e) => write!(f, "{e}"),
            InsertError::Unstamped(id) => write!(f, "event {id} has no ingest identity"),
            InsertError::Encode(e) => write!(f, "encode: {e}"),
        }
    }
}

/// Per source IP aggregates for the IOC export, oldest first.
pub struct IpIoc {
    pub ip: String,
    pub first_seen: i64,
    pub last_seen: i64,
    pub events: i64,
    pub decoy_ids: Vec<String>,
    pub catalogue_ids: Vec<String>,
    pub hook_cves: Vec<String>,
}

pub async fn ip_iocs(client: &Client, tenant_id: &str, since: i64) -> Result<Vec<IpIoc>, Error> {
    let rows = client
        .query(
            "SELECT host(src_ip) AS ip, min(ts) AS first_seen, max(ts) AS last_seen,
                    count(*) AS events,
                    array_agg(DISTINCT decoy_id ORDER BY decoy_id) AS decoy_ids,
                    array_agg(DISTINCT catalogue_id ORDER BY catalogue_id) AS catalogue_ids,
                    array_remove(array_agg(DISTINCT body->'hook'->>'cve_id'), NULL) AS hook_cves
             FROM capture_events
             WHERE tenant_id = $1 AND ts >= $2
             GROUP BY src_ip
             ORDER BY min(ts), host(src_ip)",
            &[&tenant_id, &since],
        )
        .await?;
    Ok(rows
        .iter()
        .map(|r| {
            let mut hook_cves: Vec<String> = r.get("hook_cves");
            hook_cves.sort();
            IpIoc {
                ip: r.get("ip"),
                first_seen: r.get("first_seen"),
                last_seen: r.get("last_seen"),
                events: r.get("events"),
                decoy_ids: r.get("decoy_ids"),
                catalogue_ids: r.get("catalogue_ids"),
                hook_cves,
            }
        })
        .collect())
}

/// Stamped events for a tenant in `[since, until)`, oldest first.
pub async fn events_between(
    client: &Client,
    tenant_id: &str,
    since: i64,
    until: i64,
    limit: i64,
) -> Result<Vec<CaptureEvent>, Error> {
    let rows = client
        .query(
            "SELECT body FROM capture_events WHERE tenant_id = $1 AND ts >= $2 AND ts < $3
             ORDER BY ts, event_id LIMIT $4",
            &[&tenant_id, &since, &until, &limit],
        )
        .await?;
    Ok(rows
        .iter()
        .filter_map(|r| serde_json::from_value(r.get("body")).ok())
        .collect())
}

/// One stored analyst decision (`link_overrides`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinkOverrideRow {
    pub attempt_id: String,
    pub kind: String,
    pub target: String,
    pub feedback: String,
    pub analyst_id: String,
    pub at: i64,
    pub note: String,
}

pub async fn put_link_override(
    client: &Client,
    tenant_id: &str,
    r: &LinkOverrideRow,
) -> Result<(), Error> {
    client
        .execute(
            "INSERT INTO link_overrides (tenant_id, attempt_id, kind, target, feedback, analyst_id, at, note)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
             ON CONFLICT (tenant_id, attempt_id, kind, target)
             DO UPDATE SET feedback = $5, analyst_id = $6, at = $7, note = $8",
            &[&tenant_id, &r.attempt_id, &r.kind, &r.target, &r.feedback, &r.analyst_id, &r.at, &r.note],
        )
        .await?;
    Ok(())
}

pub async fn link_overrides(
    client: &Client,
    tenant_id: &str,
    attempt_id: &str,
) -> Result<Vec<LinkOverrideRow>, Error> {
    let rows = client
        .query(
            "SELECT attempt_id, kind, target, feedback, analyst_id, at, note FROM link_overrides
             WHERE tenant_id = $1 AND attempt_id = $2 ORDER BY kind, target",
            &[&tenant_id, &attempt_id],
        )
        .await?;
    Ok(rows
        .iter()
        .map(|r| LinkOverrideRow {
            attempt_id: r.get("attempt_id"),
            kind: r.get("kind"),
            target: r.get("target"),
            feedback: r.get("feedback"),
            analyst_id: r.get("analyst_id"),
            at: r.get("at"),
            note: r.get("note"),
        })
        .collect())
}

/// Append one analyst campaign action (#33). `body` is the whole
/// `CampaignAction` as JSON; the other columns are copied out of it for
/// filtering and the CHECK constraint.
pub async fn append_campaign_action(
    client: &Client,
    tenant_id: &str,
    action: &foiled_core::campaign::CampaignAction,
) -> Result<(), Error> {
    let body = serde_json::to_value(action).unwrap_or(serde_json::Value::Null);
    client
        .execute(
            "INSERT INTO campaign_actions (tenant_id, action_id, campaign_id, kind, analyst_id, at, body)
             VALUES ($1, $2, $3, $4, $5, $6, $7)",
            &[
                &tenant_id,
                &action.action_id,
                &action.campaign_id,
                &action.kind.as_str(),
                &action.analyst_id,
                &action.at,
                &body,
            ],
        )
        .await?;
    Ok(())
}

/// Every structural campaign action (label, status, merge, split) for a
/// tenant and the newest `feedback_limit` feedback actions, oldest first.
/// Rows whose body no longer parses are skipped rather than failing the
/// read.
pub async fn campaign_actions(
    client: &Client,
    tenant_id: &str,
    feedback_limit: i64,
) -> Result<Vec<foiled_core::campaign::CampaignAction>, Error> {
    let rows = client
        .query(
            "SELECT body, at, action_id FROM campaign_actions
             WHERE tenant_id = $1 AND kind <> 'feedback'
             UNION ALL
             (SELECT body, at, action_id FROM campaign_actions
              WHERE tenant_id = $1 AND kind = 'feedback'
              ORDER BY at DESC, action_id DESC LIMIT $2)
             ORDER BY at, action_id",
            &[&tenant_id, &feedback_limit],
        )
        .await?;
    Ok(rows
        .iter()
        .filter_map(|r| serde_json::from_value(r.get::<_, serde_json::Value>("body")).ok())
        .collect())
}

/// Recorded campaign per attempt (#33), for the attempts given.
pub async fn campaign_memberships(
    client: &Client,
    tenant_id: &str,
    attempt_ids: &[String],
) -> Result<Vec<(String, String)>, Error> {
    let rows = client
        .query(
            "SELECT attempt_id, campaign_id FROM campaign_members
             WHERE tenant_id = $1 AND attempt_id = ANY($2)",
            &[&tenant_id, &attempt_ids],
        )
        .await?;
    Ok(rows
        .iter()
        .map(|r| (r.get("attempt_id"), r.get("campaign_id")))
        .collect())
}

/// Registry records for these campaign ids, with their recorded member
/// counts.
pub async fn campaign_records(
    client: &Client,
    tenant_id: &str,
    campaign_ids: &[String],
) -> Result<Vec<foiled_core::campaign::StoredCampaign>, Error> {
    let rows = client
        .query(
            "SELECT c.campaign_id, c.created_at, c.first_seen, c.last_seen, c.merged_into,
                    (SELECT count(*) FROM campaign_members m
                     WHERE m.tenant_id = c.tenant_id AND m.campaign_id = c.campaign_id) AS attempts
             FROM campaigns c WHERE c.tenant_id = $1 AND c.campaign_id = ANY($2)
             ORDER BY c.campaign_id",
            &[&tenant_id, &campaign_ids],
        )
        .await?;
    Ok(rows
        .iter()
        .map(|r| foiled_core::campaign::StoredCampaign {
            campaign_id: r.get("campaign_id"),
            created_at: r.get("created_at"),
            first_seen: r.get("first_seen"),
            last_seen: r.get("last_seen"),
            merged_into: r.get("merged_into"),
            attempts: u32::try_from(r.get::<_, i64>("attempts")).unwrap_or(u32::MAX),
        })
        .collect())
}

/// Apply a registry update in one transaction, as batched multi-row
/// statements. Writes converge whatever order concurrent or stale readers
/// commit in:
///
/// - `created_at` is set on insert and never changed; first and last seen
///   only widen.
/// - Registry writes for one tenant are serialised by a transaction-scoped
///   advisory lock taken first, so two writers never interleave their row
///   locks (and cannot deadlock on each other).
/// - `merged_into` is write-once and only set to a campaign that is
///   strictly older by `(created_at, campaign_id)`. That order is total and
///   immutable, so merges can never form a cycle. A trigger (migration
///   0007) refuses anything else.
/// - A membership only moves to an older campaign.
/// - Bridge provenance is written only for merges that were applied: the
///   folded campaign now points here, or both attempts are recorded here.
pub async fn update_campaign_registry(
    client: &Client,
    tenant_id: &str,
    update: &foiled_core::campaign::RegistryUpdate,
    now: i64,
) -> Result<(), Error> {
    if update.is_empty() {
        return Ok(());
    }
    // Rows are written in key order too, for predictable lock order with
    // writers outside this function.
    let mut update = update.clone();
    update
        .campaigns
        .sort_by(|a, b| a.campaign_id.cmp(&b.campaign_id));
    update
        .campaigns
        .dedup_by(|a, b| a.campaign_id == b.campaign_id);
    update
        .members
        .sort_by(|a, b| a.attempt_id.cmp(&b.attempt_id));
    update.members.dedup_by(|a, b| a.attempt_id == b.attempt_id);
    let update = &update;
    let ids: Vec<&str> = update
        .campaigns
        .iter()
        .map(|c| c.campaign_id.as_str())
        .collect();
    let created: Vec<i64> = update.campaigns.iter().map(|c| c.created_at).collect();
    let first: Vec<i64> = update.campaigns.iter().map(|c| c.first_seen).collect();
    let last: Vec<i64> = update.campaigns.iter().map(|c| c.last_seen).collect();
    let merges: Vec<(&str, &str)> = update
        .campaigns
        .iter()
        .filter_map(|c| {
            c.merged_into
                .as_deref()
                .filter(|m| *m != c.campaign_id)
                .map(|m| (c.campaign_id.as_str(), m))
        })
        .collect();
    let merge_from: Vec<&str> = merges.iter().map(|m| m.0).collect();
    let merge_into: Vec<&str> = merges.iter().map(|m| m.1).collect();
    let attempts: Vec<&str> = update
        .members
        .iter()
        .map(|m| m.attempt_id.as_str())
        .collect();
    let member_of: Vec<&str> = update
        .members
        .iter()
        .map(|m| m.campaign_id.as_str())
        .collect();
    let seen: Vec<i64> = update
        .members
        .iter()
        .map(|m| m.attempt_first_seen)
        .collect();
    let b = &update.bridges;
    let b_into: Vec<&str> = b.iter().map(|x| x.campaign_id.as_str()).collect();
    let b_from: Vec<Option<&str>> = b.iter().map(|x| x.merged_campaign_id.as_deref()).collect();
    let b_attempt: Vec<&str> = b.iter().map(|x| x.attempt_id.as_str()).collect();
    let b_with: Vec<&str> = b.iter().map(|x| x.with_attempt_id.as_str()).collect();
    let b_signal: Vec<&str> = b.iter().map(|x| x.signal_id.as_str()).collect();
    let b_feature: Vec<&str> = b.iter().map(|x| x.feature.as_str()).collect();
    let b_sides: Vec<i32> = b
        .iter()
        .map(|x| i32::try_from(x.attempt_side).unwrap_or(i32::MAX))
        .collect();
    let b_with_sides: Vec<i32> = b
        .iter()
        .map(|x| i32::try_from(x.with_side).unwrap_or(i32::MAX))
        .collect();
    let b_small: Vec<bool> = b.iter().map(|x| x.small_halves).collect();
    let b_at: Vec<i64> = b.iter().map(|x| x.recorded_at).collect();
    client.batch_execute("BEGIN").await?;
    let step = async {
        client
            .execute(
                "SELECT pg_advisory_xact_lock(hashtext('campaign_registry:' || $1::text))",
                &[&tenant_id],
            )
            .await?;
        if !ids.is_empty() {
            client
                .execute(
                    "INSERT INTO campaigns (tenant_id, campaign_id, created_at, first_seen, last_seen, merged_into, updated_at)
                     SELECT $1, t.c, t.cr, t.f, t.l, NULL, $6
                     FROM UNNEST($2::text[], $3::bigint[], $4::bigint[], $5::bigint[]) AS t(c, cr, f, l)
                     ON CONFLICT (tenant_id, campaign_id) DO UPDATE SET
                       first_seen = LEAST(campaigns.first_seen, EXCLUDED.first_seen),
                       last_seen = GREATEST(campaigns.last_seen, EXCLUDED.last_seen),
                       updated_at = EXCLUDED.updated_at",
                    &[&tenant_id, &ids, &created, &first, &last, &now],
                )
                .await?;
        }
        if !merges.is_empty() {
            client
                .execute(
                    "UPDATE campaigns c SET merged_into = t.m, updated_at = $4
                     FROM UNNEST($2::text[], $3::text[]) AS t(c, m), campaigns tgt
                     WHERE c.tenant_id = $1 AND c.campaign_id = t.c AND c.merged_into IS NULL
                       AND tgt.tenant_id = $1 AND tgt.campaign_id = t.m
                       AND (tgt.created_at, tgt.campaign_id) < (c.created_at, c.campaign_id)",
                    &[&tenant_id, &merge_from, &merge_into, &now],
                )
                .await?;
        }
        if !attempts.is_empty() {
            client
                .execute(
                    "INSERT INTO campaign_members (tenant_id, attempt_id, campaign_id, attempt_first_seen, recorded_at)
                     SELECT $1, t.a, t.c, t.f, $5
                     FROM UNNEST($2::text[], $3::text[], $4::bigint[]) AS t(a, c, f)
                     ON CONFLICT (tenant_id, attempt_id) DO UPDATE SET
                       campaign_id = EXCLUDED.campaign_id,
                       recorded_at = EXCLUDED.recorded_at
                     WHERE NOT EXISTS (
                         SELECT 1 FROM campaigns o
                         WHERE o.tenant_id = campaign_members.tenant_id
                           AND o.campaign_id = campaign_members.campaign_id)
                       OR EXISTS (
                         SELECT 1 FROM campaigns n, campaigns o
                         WHERE n.tenant_id = campaign_members.tenant_id
                           AND n.campaign_id = EXCLUDED.campaign_id
                           AND o.tenant_id = campaign_members.tenant_id
                           AND o.campaign_id = campaign_members.campaign_id
                           AND (n.created_at, n.campaign_id) < (o.created_at, o.campaign_id))",
                    &[&tenant_id, &attempts, &member_of, &seen, &now],
                )
                .await?;
        }
        if !b.is_empty() {
            client
                .execute(
                    "INSERT INTO campaign_bridges (tenant_id, campaign_id, merged_campaign_id, attempt_id, with_attempt_id, signal_id, feature, attempt_side, with_side, small_halves, recorded_at)
                     SELECT $1, t.i, t.f, t.a, t.w, t.s, t.k, t.sa, t.sw, t.sm, t.r
                     FROM UNNEST($2::text[], $3::text[], $4::text[], $5::text[], $6::text[], $7::text[],
                                 $8::int[], $9::int[], $10::bool[], $11::bigint[])
                       AS t(i, f, a, w, s, k, sa, sw, sm, r)
                     WHERE EXISTS (
                         SELECT 1 FROM campaigns c
                         WHERE c.tenant_id = $1 AND c.campaign_id = t.f AND c.merged_into = t.i)
                       OR (
                         EXISTS (SELECT 1 FROM campaign_members m
                                 WHERE m.tenant_id = $1 AND m.attempt_id = t.a AND m.campaign_id = t.i)
                         AND EXISTS (SELECT 1 FROM campaign_members m
                                 WHERE m.tenant_id = $1 AND m.attempt_id = t.w AND m.campaign_id = t.i))
                     ON CONFLICT DO NOTHING",
                    &[
                        &tenant_id, &b_into, &b_from, &b_attempt, &b_with, &b_signal, &b_feature,
                        &b_sides, &b_with_sides, &b_small, &b_at,
                    ],
                )
                .await?;
        }
        Ok::<(), Error>(())
    }
    .await;
    match step {
        Ok(()) => client.batch_execute("COMMIT").await,
        Err(e) => {
            client.batch_execute("ROLLBACK").await?;
            Err(e)
        }
    }
}

/// Bridge provenance for merges into this campaign, oldest first.
pub async fn campaign_bridges(
    client: &Client,
    tenant_id: &str,
    campaign_id: &str,
) -> Result<Vec<foiled_core::campaign::BridgeRecord>, Error> {
    let rows = client
        .query(
            "SELECT campaign_id, merged_campaign_id, attempt_id, with_attempt_id, signal_id, feature,
                    attempt_side, with_side, small_halves, recorded_at
             FROM campaign_bridges WHERE tenant_id = $1 AND campaign_id = $2
             ORDER BY recorded_at, attempt_id, with_attempt_id, signal_id",
            &[&tenant_id, &campaign_id],
        )
        .await?;
    Ok(rows
        .iter()
        .filter_map(|r| {
            Some(foiled_core::campaign::BridgeRecord {
                campaign_id: r.get("campaign_id"),
                merged_campaign_id: r.get("merged_campaign_id"),
                attempt_id: r.get("attempt_id"),
                with_attempt_id: r.get("with_attempt_id"),
                signal_id: r.get("signal_id"),
                feature: serde_json::from_value(serde_json::Value::String(r.get("feature")))
                    .ok()?,
                attempt_side: u32::try_from(r.get::<_, i32>("attempt_side")).unwrap_or(0),
                with_side: u32::try_from(r.get::<_, i32>("with_side")).unwrap_or(0),
                small_halves: r.get("small_halves"),
                recorded_at: r.get("recorded_at"),
            })
        })
        .collect())
}
