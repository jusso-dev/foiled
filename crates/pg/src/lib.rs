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
    (
        "0008_actor_link_decisions",
        include_str!("../../../migrations/postgres/0008_actor_link_decisions.sql"),
    ),
    (
        "0009_actor_decision_attempts",
        include_str!("../../../migrations/postgres/0009_actor_decision_attempts.sql"),
    ),
    (
        "0010_review_writeups_radar",
        include_str!("../../../migrations/postgres/0010_review_writeups_radar.sql"),
    ),
    (
        "0011_stix_log",
        include_str!("../../../migrations/postgres/0011_stix_log.sql"),
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

/// Events strictly after `(after_ts, after_id)` in `(ts, event_id)` order,
/// for continuing an export past a cut (#13).
pub async fn events_after(
    client: &Client,
    tenant_id: &str,
    after_ts: i64,
    after_id: &str,
    until: i64,
    limit: i64,
) -> Result<Vec<CaptureEvent>, Error> {
    let rows = client
        .query(
            "SELECT body FROM capture_events WHERE tenant_id = $1 AND (ts, event_id) > ($2, $3)
             AND ts < $4 ORDER BY ts, event_id LIMIT $5",
            &[&tenant_id, &after_ts, &after_id, &until, &limit],
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
    Ok(rows.iter().map(override_row).collect())
}

/// Overrides for several attempts in one query, for exports (#13).
pub async fn link_overrides_many(
    client: &Client,
    tenant_id: &str,
    attempt_ids: &[String],
) -> Result<Vec<LinkOverrideRow>, Error> {
    let rows = client
        .query(
            "SELECT attempt_id, kind, target, feedback, analyst_id, at, note FROM link_overrides
             WHERE tenant_id = $1 AND attempt_id = ANY($2) ORDER BY attempt_id, kind, target",
            &[&tenant_id, &attempt_ids],
        )
        .await?;
    Ok(rows.iter().map(override_row).collect())
}

fn override_row(r: &Row) -> LinkOverrideRow {
    LinkOverrideRow {
        attempt_id: r.get("attempt_id"),
        kind: r.get("kind"),
        target: r.get("target"),
        feedback: r.get("feedback"),
        analyst_id: r.get("analyst_id"),
        at: r.get("at"),
        note: r.get("note"),
    }
}

/// One stored analyst decision on an actor link (`actor_link_decisions`,
/// #29).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActorDecisionRow {
    pub subject_id: String,
    pub actor_id: String,
    pub feedback: String,
    pub analyst_id: String,
    pub at: i64,
    pub note: String,
    /// The attempts the decision covered when it was made.
    pub attempt_ids: Vec<String>,
}

pub async fn put_actor_decision(
    client: &Client,
    tenant_id: &str,
    r: &ActorDecisionRow,
) -> Result<(), Error> {
    client
        .execute(
            "INSERT INTO actor_link_decisions (tenant_id, subject_id, actor_id, feedback, analyst_id, at, note, attempt_ids)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
             ON CONFLICT (tenant_id, subject_id, actor_id)
             DO UPDATE SET feedback = $4, analyst_id = $5, at = $6, note = $7, attempt_ids = $8",
            &[&tenant_id, &r.subject_id, &r.actor_id, &r.feedback, &r.analyst_id, &r.at, &r.note, &r.attempt_ids],
        )
        .await?;
    Ok(())
}

/// Decisions for these subjects (campaign or attempt ids).
pub async fn actor_decisions(
    client: &Client,
    tenant_id: &str,
    subject_ids: &[String],
) -> Result<Vec<ActorDecisionRow>, Error> {
    let rows = client
        .query(
            "SELECT subject_id, actor_id, feedback, analyst_id, at, note, attempt_ids FROM actor_link_decisions
             WHERE tenant_id = $1 AND subject_id = ANY($2) ORDER BY subject_id, actor_id",
            &[&tenant_id, &subject_ids],
        )
        .await?;
    Ok(rows
        .iter()
        .map(|r| ActorDecisionRow {
            subject_id: r.get("subject_id"),
            actor_id: r.get("actor_id"),
            feedback: r.get("feedback"),
            analyst_id: r.get("analyst_id"),
            at: r.get("at"),
            note: r.get("note"),
            attempt_ids: r.get("attempt_ids"),
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

fn json<T: serde::Serialize>(v: &T) -> serde_json::Value {
    serde_json::to_value(v).unwrap_or(serde_json::Value::Null)
}

fn bodies<T: serde::de::DeserializeOwned>(rows: &[Row], column: &str) -> Vec<T> {
    // Rows whose body no longer parses are skipped rather than failing the
    // read.
    rows.iter()
        .filter_map(|r| serde_json::from_value(r.get::<_, serde_json::Value>(column)).ok())
        .collect()
}

/// Stored review queue state for these items (#35).
pub async fn review_states(
    client: &Client,
    tenant_id: &str,
    item_ids: &[String],
) -> Result<Vec<foiled_core::review::ReviewState>, Error> {
    let rows = client
        .query(
            "SELECT body FROM review_states WHERE tenant_id = $1 AND item_id = ANY($2)",
            &[&tenant_id, &item_ids],
        )
        .await?;
    Ok(bodies(&rows, "body"))
}

/// Write a review item's state if the stored version is `expected` (0: no
/// row yet). Returns false, writing nothing, when it is not.
pub async fn put_review_state(
    client: &Client,
    tenant_id: &str,
    state: &foiled_core::review::ReviewState,
    expected: u32,
) -> Result<bool, Error> {
    let version = i32::try_from(state.version).unwrap_or(i32::MAX);
    let expected = i32::try_from(expected).unwrap_or(i32::MAX);
    let n = if expected == 0 {
        client
            .execute(
                "INSERT INTO review_states (tenant_id, item_id, kind, status, version, updated_at, body)
                 VALUES ($1, $2, $3, $4, $5, $6, $7) ON CONFLICT (tenant_id, item_id) DO NOTHING",
                &[
                    &tenant_id,
                    &state.item_id,
                    &state.kind.as_str(),
                    &state.status.as_str(),
                    &version,
                    &state.updated_at,
                    &json(state),
                ],
            )
            .await?
    } else {
        client
            .execute(
                "UPDATE review_states SET status = $3, version = $4, updated_at = $5, body = $6
                 WHERE tenant_id = $1 AND item_id = $2 AND version = $7",
                &[
                    &tenant_id,
                    &state.item_id,
                    &state.status.as_str(),
                    &version,
                    &state.updated_at,
                    &json(state),
                    &expected,
                ],
            )
            .await?
    };
    Ok(n == 1)
}

async fn insert_version(
    client: &Client,
    w: &foiled_core::writeup::WriteUp,
    action: &str,
    actor_id: &str,
) -> Result<(), Error> {
    let version = i32::try_from(w.version).unwrap_or(i32::MAX);
    client
        .execute(
            "INSERT INTO writeup_versions (tenant_id, writeup_id, version, action, actor_id, at, body)
             VALUES ($1, $2, $3, $4, $5, $6, $7)",
            &[
                &w.tenant_id,
                &w.writeup_id,
                &version,
                &action,
                &actor_id,
                &w.updated_at,
                &json(w),
            ],
        )
        .await?;
    Ok(())
}

async fn in_transaction<T>(
    client: &Client,
    step: impl std::future::Future<Output = Result<Option<T>, Error>>,
) -> Result<Option<T>, Error> {
    client.batch_execute("BEGIN").await?;
    match step.await {
        Ok(Some(v)) => {
            client.batch_execute("COMMIT").await?;
            Ok(Some(v))
        }
        Ok(None) => {
            client.batch_execute("ROLLBACK").await?;
            Ok(None)
        }
        Err(e) => {
            client.batch_execute("ROLLBACK").await?;
            Err(e)
        }
    }
}

/// Insert a write-up and its first version row together (#35).
pub async fn insert_writeup(
    client: &Client,
    w: &foiled_core::writeup::WriteUp,
    actor_id: &str,
) -> Result<(), Error> {
    let version = i32::try_from(w.version).unwrap_or(i32::MAX);
    in_transaction(client, async {
        client
            .execute(
                "INSERT INTO writeups (tenant_id, writeup_id, status, version, updated_at, body)
                 VALUES ($1, $2, $3, $4, $5, $6)",
                &[
                    &w.tenant_id,
                    &w.writeup_id,
                    &w.status.as_str(),
                    &version,
                    &w.updated_at,
                    &json(w),
                ],
            )
            .await?;
        insert_version(client, w, "create", actor_id).await?;
        Ok(Some(()))
    })
    .await
    .map(|_| ())
}

pub async fn get_writeup(
    client: &Client,
    tenant_id: &str,
    writeup_id: &str,
) -> Result<Option<foiled_core::writeup::WriteUp>, Error> {
    let rows = client
        .query(
            "SELECT body FROM writeups WHERE tenant_id = $1 AND writeup_id = $2",
            &[&tenant_id, &writeup_id],
        )
        .await?;
    Ok(bodies(&rows, "body").into_iter().next())
}

/// Newest change first, optionally one status only.
pub async fn list_writeups(
    client: &Client,
    tenant_id: &str,
    status: Option<&str>,
    limit: i64,
) -> Result<Vec<foiled_core::writeup::WriteUp>, Error> {
    let rows = client
        .query(
            "SELECT body FROM writeups WHERE tenant_id = $1 AND ($2::text IS NULL OR status = $2)
             ORDER BY updated_at DESC, writeup_id DESC LIMIT $3",
            &[&tenant_id, &status, &limit],
        )
        .await?;
    Ok(bodies(&rows, "body"))
}

/// Replace a write-up if its stored version is `expected`, and append the
/// version row, in one transaction. False, writing nothing, otherwise.
pub async fn update_writeup(
    client: &Client,
    w: &foiled_core::writeup::WriteUp,
    expected: u32,
    action: &str,
    actor_id: &str,
) -> Result<bool, Error> {
    let version = i32::try_from(w.version).unwrap_or(i32::MAX);
    let expected = i32::try_from(expected).unwrap_or(i32::MAX);
    in_transaction(client, async {
        let n = client
            .execute(
                "UPDATE writeups SET status = $3, version = $4, updated_at = $5, body = $6
                 WHERE tenant_id = $1 AND writeup_id = $2 AND version = $7",
                &[
                    &w.tenant_id,
                    &w.writeup_id,
                    &w.status.as_str(),
                    &version,
                    &w.updated_at,
                    &json(w),
                    &expected,
                ],
            )
            .await?;
        if n != 1 {
            return Ok(None);
        }
        insert_version(client, w, action, actor_id).await?;
        Ok(Some(()))
    })
    .await
    .map(|r| r.is_some())
}

/// One stored write-up version.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WriteUpVersionRow {
    pub writeup: foiled_core::writeup::WriteUp,
    pub action: String,
    pub actor_id: String,
    pub at: i64,
}

pub async fn writeup_versions(
    client: &Client,
    tenant_id: &str,
    writeup_id: &str,
) -> Result<Vec<WriteUpVersionRow>, Error> {
    let rows = client
        .query(
            "SELECT action, actor_id, at, body FROM writeup_versions
             WHERE tenant_id = $1 AND writeup_id = $2 ORDER BY version",
            &[&tenant_id, &writeup_id],
        )
        .await?;
    Ok(rows
        .iter()
        .filter_map(|r| {
            Some(WriteUpVersionRow {
                writeup: serde_json::from_value(r.get::<_, serde_json::Value>("body")).ok()?,
                action: r.get("action"),
                actor_id: r.get("actor_id"),
                at: r.get("at"),
            })
        })
        .collect())
}

/// Store a write-up's public page, replacing its earlier one. False when
/// another write-up holds the slug.
pub async fn put_public_page(
    client: &Client,
    tenant_id: &str,
    writeup_id: &str,
    page: &foiled_core::writeup::PublicPage,
) -> Result<bool, Error> {
    in_transaction(client, async {
        let version = i32::try_from(page.version).unwrap_or(i32::MAX);
        // An older snapshot never replaces a newer one for the same write-up.
        let newer = client
            .query_opt(
                "SELECT 1 FROM public_pages WHERE tenant_id = $1 AND writeup_id = $2 AND version > $3",
                &[&tenant_id, &writeup_id, &version],
            )
            .await?;
        if newer.is_some() {
            return Ok(Some(()));
        }
        client
            .execute(
                "DELETE FROM public_pages WHERE tenant_id = $1 AND writeup_id = $2 AND slug <> $3",
                &[&tenant_id, &writeup_id, &page.slug],
            )
            .await?;
        let n = client
            .execute(
                "INSERT INTO public_pages (slug, tenant_id, writeup_id, version, visible_from, page)
                 VALUES ($1, $2, $3, $4, $5, $6)
                 ON CONFLICT (slug) DO UPDATE SET version = EXCLUDED.version,
                   visible_from = EXCLUDED.visible_from, page = EXCLUDED.page
                 WHERE public_pages.tenant_id = EXCLUDED.tenant_id
                   AND public_pages.writeup_id = EXCLUDED.writeup_id
                   AND public_pages.version <= EXCLUDED.version",
                &[&page.slug, &tenant_id, &writeup_id, &version, &page.visible_from, &json(page)],
            )
            .await?;
        Ok(if n == 1 { Some(()) } else { None })
    })
    .await
    .map(|r| r.is_some())
}

pub async fn remove_public_page(
    client: &Client,
    tenant_id: &str,
    writeup_id: &str,
) -> Result<(), Error> {
    client
        .execute(
            "DELETE FROM public_pages WHERE tenant_id = $1 AND writeup_id = $2",
            &[&tenant_id, &writeup_id],
        )
        .await?;
    Ok(())
}

/// The page for a slug if visible at `now`. Reads `page` only.
pub async fn public_page(
    client: &Client,
    slug: &str,
    now: i64,
) -> Result<Option<foiled_core::writeup::PublicPage>, Error> {
    let rows = client
        .query(
            "SELECT page FROM public_pages WHERE slug = $1 AND visible_from <= $2",
            &[&slug, &now],
        )
        .await?;
    Ok(bodies(&rows, "page").into_iter().next())
}

/// Pages visible at `now`, newest first. Reads `page` only.
pub async fn public_pages(
    client: &Client,
    now: i64,
    limit: i64,
) -> Result<Vec<foiled_core::writeup::PublicPage>, Error> {
    let rows = client
        .query(
            "SELECT page FROM public_pages WHERE visible_from <= $1
             ORDER BY visible_from DESC, slug DESC LIMIT $2",
            &[&now, &limit],
        )
        .await?;
    Ok(bodies(&rows, "page"))
}

/// Replace one tenant's radar rollup for one day, in one transaction.
pub async fn put_radar_points(
    client: &Client,
    tenant_id: &str,
    day: i64,
    points: &[foiled_core::radar::RadarPoint],
) -> Result<(), Error> {
    let rows: Vec<&foiled_core::radar::RadarPoint> = points
        .iter()
        .filter(|p| p.tenant_id == tenant_id && p.day == day)
        .collect();
    let body = json(&rows);
    in_transaction(client, async {
        client
            .execute(
                "DELETE FROM radar_rollups WHERE tenant_id = $1 AND day = $2",
                &[&tenant_id, &day],
            )
            .await?;
        if !rows.is_empty() {
            client
                .execute(
                    "INSERT INTO radar_rollups (tenant_id, day, dimension, key, sensor, source, body)
                     SELECT $1, $2, e->>'dimension', e->>'key', e->>'sensor', e->>'source', e
                     FROM jsonb_array_elements($3::jsonb) AS e",
                    &[&tenant_id, &day, &body],
                )
                .await?;
        }
        Ok(Some(()))
    })
    .await
    .map(|_| ())
}

/// Rollup rows with `since <= day < until`, for one tenant or all.
pub async fn radar_points(
    client: &Client,
    tenant_id: Option<&str>,
    since: i64,
    until: i64,
    limit: i64,
) -> Result<Vec<foiled_core::radar::RadarPoint>, Error> {
    let rows = client
        .query(
            "SELECT body FROM radar_rollups
             WHERE ($1::text IS NULL OR tenant_id = $1) AND day >= $2 AND day < $3
             LIMIT $4",
            &[&tenant_id, &since, &until, &limit],
        )
        .await?;
    Ok(bodies(&rows, "body"))
}

// ---------------------------------------------------------------------------
// Materialised STIX object log behind TAXII (#13)
// ---------------------------------------------------------------------------

/// The head of one object: `(id, created, latest_version, latest_sha256,
/// revoked)`.
pub type HistoryRow = (String, Option<String>, String, String, bool);

/// A version to append.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VersionRow {
    pub id: String,
    pub version: String,
    pub created: Option<String>,
    pub object_type: String,
    pub content: String,
    pub content_sha256: String,
    /// Every id the version refers to.
    pub refs: Vec<String>,
}

/// A stored version as served: `(id, object_type, version, date_added,
/// content)`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredRow {
    pub id: String,
    pub object_type: String,
    pub version: String,
    pub date_added: i64,
    pub content: String,
}

/// `match[version]`: a row matches when it is any of these.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct VersionMatch {
    pub first: bool,
    pub last: bool,
    pub all: bool,
    pub exact: Vec<String>,
}

/// One materialised day: `(day_ms, signature, object_ids, progress JSON,
/// served_ms)`.
pub type DayRow = (i64, String, Vec<String>, Option<String>, i64);

/// One of a day's attempts: `(attempt_id, AttemptRecord JSON)`.
pub type AttemptRow = (String, String);

/// An IOC the merge published: `(ioc_id, type, value)`.
pub type PublishedRow = (String, String, String);

/// Inside a transaction: lock the tenant's lease row and fail (SQLSTATE
/// `P0001`, "stix lease lost") unless its generation is `fence`. The share
/// lock holds off a takeover until the transaction ends, so a write either
/// commits under the generation it checked or not at all.
async fn fence(
    client: &Client,
    tenant_id: &str,
    collection: &str,
    fence: i64,
) -> Result<(), Error> {
    client
        .execute(
            "SELECT stix_fence($1, $2, $3)",
            &[&tenant_id, &collection, &fence],
        )
        .await?;
    Ok(())
}

async fn in_tx<T>(
    client: &Client,
    body: impl std::future::Future<Output = Result<T, Error>>,
) -> Result<T, Error> {
    client.batch_execute("BEGIN").await?;
    match body.await {
        Ok(v) => {
            client.batch_execute("COMMIT").await?;
            Ok(v)
        }
        Err(e) => {
            let _ = client.batch_execute("ROLLBACK").await;
            Err(e)
        }
    }
}

pub async fn stix_history(
    client: &Client,
    tenant_id: &str,
    collection: &str,
    ids: &[String],
) -> Result<Vec<HistoryRow>, Error> {
    let rows = client
        .query(
            "SELECT h.id::text AS id, h.created, h.latest_version::text AS latest,
                    h.latest_sha256,
                    coalesce((v.content::jsonb ->> 'revoked') = 'true', false) AS revoked
             FROM stix_object_heads h
             JOIN stix_object_versions v
               ON v.tenant_id = h.tenant_id AND v.collection_id = h.collection_id
              AND v.id = h.id AND v.version = h.latest_version
             WHERE h.tenant_id = $1 AND h.collection_id = $2 AND h.id = ANY($3)",
            &[&tenant_id, &collection, &ids],
        )
        .await?;
    Ok(rows
        .iter()
        .map(|r| {
            (
                r.get("id"),
                r.get("created"),
                r.get("latest"),
                r.get("latest_sha256"),
                r.get("revoked"),
            )
        })
        .collect())
}

/// Append versions in one transaction under one `date_added`, later than
/// every row already in the collection and no earlier than `now`. Rows
/// whose content equals the object's current head are skipped. A row whose
/// `(id, version)` exists is a conflict: the insert fails with a unique
/// violation and nothing is written, so two writers that planned from the
/// same head never lose a version silently. `evidence` raises each
/// object's newest evidence time; each head keeps the union of its
/// versions' references. A transaction-level advisory lock per tenant and
/// collection serialises appends, so commit order is `date_added` order.
/// Fenced by the lease generation. Returns the rows written.
pub async fn stix_append(
    client: &Client,
    tenant_id: &str,
    collection: &str,
    rows: &[VersionRow],
    evidence: &[(String, i64)],
    now: i64,
    fence_gen: i64,
) -> Result<u64, Error> {
    in_tx(client, async {
        fence(client, tenant_id, collection, fence_gen).await?;
        stix_append_in_tx(client, tenant_id, collection, rows, evidence, now).await
    })
    .await
}

async fn stix_append_in_tx(
    client: &Client,
    tenant_id: &str,
    collection: &str,
    rows: &[VersionRow],
    evidence: &[(String, i64)],
    now: i64,
) -> Result<u64, Error> {
    let lock_key = format!("stix|{tenant_id}|{collection}");
    client
        .execute(
            "SELECT pg_advisory_xact_lock(hashtextextended($1, 13))",
            &[&lock_key],
        )
        .await?;
    let newest: Option<i64> = client
        .query_one(
            "SELECT max(date_added) AS newest FROM stix_object_versions
             WHERE tenant_id = $1 AND collection_id = $2",
            &[&tenant_id, &collection],
        )
        .await?
        .get("newest");
    let date_added = newest.map_or(now, |n| now.max(n + 1));
    let ids: Vec<&str> = rows.iter().map(|r| r.id.as_str()).collect();
    let versions: Vec<&str> = rows.iter().map(|r| r.version.as_str()).collect();
    let created: Vec<Option<&str>> = rows.iter().map(|r| r.created.as_deref()).collect();
    let types: Vec<&str> = rows.iter().map(|r| r.object_type.as_str()).collect();
    let contents: Vec<&str> = rows.iter().map(|r| r.content.as_str()).collect();
    let hashes: Vec<&str> = rows.iter().map(|r| r.content_sha256.as_str()).collect();
    let refs: Vec<String> = rows
        .iter()
        .map(|r| serde_json::to_string(&r.refs).unwrap_or_else(|_| "[]".into()))
        .collect();
    let inserted: i64 = client
        .query_one(
            "WITH ins AS (
                 INSERT INTO stix_object_versions
                     (tenant_id, collection_id, id, version, created, object_type, date_added,
                      content, content_sha256)
                 SELECT $1, $2, u.id, u.version, u.created, u.object_type, $3, u.content, u.sha
                 FROM unnest($4::text[], $5::text[], $6::text[], $7::text[], $8::text[], $9::text[])
                     AS u(id, version, created, object_type, content, sha)
                 WHERE NOT EXISTS (
                     SELECT 1 FROM stix_object_heads h
                     WHERE h.tenant_id = $1 AND h.collection_id = $2 AND h.id = u.id
                       AND h.latest_sha256 = u.sha)
                 RETURNING id, version, created, content_sha256
             ), refs AS (
                 SELECT u.id, ARRAY(SELECT jsonb_array_elements_text(u.refs::jsonb)) AS refs
                 FROM unnest($4::text[], $10::text[]) AS u(id, refs)
             ), heads AS (
                 INSERT INTO stix_object_heads
                     (tenant_id, collection_id, id, created, latest_version, latest_sha256, refs)
                 SELECT $1, $2, ins.id, ins.created, ins.version, ins.content_sha256,
                        coalesce(refs.refs, '{}')
                 FROM ins LEFT JOIN refs ON refs.id = ins.id
                 ON CONFLICT (tenant_id, collection_id, id) DO UPDATE
                     SET latest_sha256 = CASE
                             WHEN EXCLUDED.latest_version > stix_object_heads.latest_version
                             THEN EXCLUDED.latest_sha256
                             ELSE stix_object_heads.latest_sha256 END,
                         latest_version = greatest(stix_object_heads.latest_version,
                                                   EXCLUDED.latest_version),
                         refs = ARRAY(SELECT DISTINCT x FROM unnest(
                             stix_object_heads.refs || EXCLUDED.refs) AS x ORDER BY x)
                 RETURNING 1
             )
             SELECT count(*) AS n FROM ins",
            &[
                &tenant_id,
                &collection,
                &date_added,
                &ids,
                &versions,
                &created,
                &types,
                &contents,
                &hashes,
                &refs,
            ],
        )
        .await?
        .get("n");
    let ev_ids: Vec<&str> = evidence.iter().map(|(id, _)| id.as_str()).collect();
    let ev_ms: Vec<i64> = evidence.iter().map(|(_, ms)| *ms).collect();
    client
        .execute(
            "UPDATE stix_object_heads h SET max_evidence_ms = greatest(h.max_evidence_ms, u.ev)
             FROM (SELECT id, max(ev) AS ev FROM unnest($3::text[], $4::bigint[]) AS x(id, ev)
                   GROUP BY id) AS u
             WHERE h.tenant_id = $1 AND h.collection_id = $2 AND h.id = u.id",
            &[&tenant_id, &collection, &ev_ids, &ev_ms],
        )
        .await?;
    Ok(inserted as u64)
}

/// The TAXII query: rows after `added_after` and after the cursor, filtered
/// by id, type and version (any of first, last, all or exact versions),
/// ordered by `(date_added, id, version)`.
#[allow(clippy::too_many_arguments)]
pub async fn stix_query(
    client: &Client,
    tenant_id: &str,
    collection: &str,
    added_after: Option<i64>,
    after: Option<(i64, &str, &str)>,
    ids: Option<&[String]>,
    types: Option<&[String]>,
    versions: &VersionMatch,
    limit: i64,
) -> Result<Vec<StoredRow>, Error> {
    let (after_ms, after_id, after_version) = match after {
        Some((ms, id, v)) => (Some(ms), id, v),
        None => (None, "", ""),
    };
    let rows = client
        .query(
            "SELECT v.id::text AS id, v.object_type, v.version::text AS version, v.date_added,
                    v.content
             FROM stix_object_versions v
             JOIN stix_object_heads h
               ON h.tenant_id = v.tenant_id AND h.collection_id = v.collection_id AND h.id = v.id
             WHERE v.tenant_id = $1 AND v.collection_id = $2
               AND ($3::bigint IS NULL OR v.date_added > $3)
               AND ($4::bigint IS NULL OR (v.date_added, v.id, v.version) > ($4, $5::text COLLATE \"C\", $6::text COLLATE \"C\"))
               AND ($7::text[] IS NULL OR v.id = ANY($7))
               AND ($8::text[] IS NULL OR v.object_type = ANY($8))
               AND ($9
                    OR ($10 AND v.version = h.latest_version)
                    OR ($11 AND v.version = (
                         SELECT min(f.version) FROM stix_object_versions f
                         WHERE f.tenant_id = v.tenant_id AND f.collection_id = v.collection_id
                           AND f.id = v.id))
                    OR v.version = ANY($12))
             ORDER BY v.date_added, v.id, v.version
             LIMIT $13",
            &[
                &tenant_id,
                &collection,
                &added_after,
                &after_ms,
                &after_id,
                &after_version,
                &ids,
                &types,
                &versions.all,
                &versions.last,
                &versions.first,
                &versions.exact,
                &limit,
            ],
        )
        .await?;
    Ok(rows
        .iter()
        .map(|r| StoredRow {
            id: r.get("id"),
            object_type: r.get("object_type"),
            version: r.get("version"),
            date_added: r.get("date_added"),
            content: r.get("content"),
        })
        .collect())
}

/// Remove every version of objects whose newest evidence is older than
/// `evidence_before`, unless an object that stays refers to them, and the
/// materialiser's state for days before it. Returns the version rows
/// removed.
pub async fn stix_purge(
    client: &Client,
    tenant_id: &str,
    collection: &str,
    evidence_before: i64,
    fence_gen: i64,
) -> Result<u64, Error> {
    in_tx(client, async {
        fence(client, tenant_id, collection, fence_gen).await?;
        stix_purge_in_tx(client, tenant_id, collection, evidence_before).await
    })
    .await
}

async fn stix_purge_in_tx(
    client: &Client,
    tenant_id: &str,
    collection: &str,
    evidence_before: i64,
) -> Result<u64, Error> {
    let n: i64 = client
        .query_one(
            "WITH stale AS (
                 DELETE FROM stix_object_heads h
                 WHERE h.tenant_id = $1 AND h.collection_id = $2 AND h.max_evidence_ms < $3
                   AND NOT EXISTS (
                       SELECT 1 FROM stix_object_heads k
                       WHERE k.tenant_id = $1 AND k.collection_id = $2
                         AND k.max_evidence_ms >= $3 AND k.refs @> ARRAY[h.id::text])
                 RETURNING id
             ), gone AS (
                 DELETE FROM stix_object_versions v USING stale
                 WHERE v.tenant_id = $1 AND v.collection_id = $2 AND v.id = stale.id
                 RETURNING 1
             ), old_days AS (
                 DELETE FROM stix_materialised_days
                 WHERE tenant_id = $1 AND collection_id = $2 AND day_ms < $3
                 RETURNING 1
             ), old_attempts AS (
                 DELETE FROM stix_day_attempts
                 WHERE tenant_id = $1 AND collection_id = $2 AND day_ms < $3
                 RETURNING 1
             ), old_contributions AS (
                 DELETE FROM stix_ioc_contributions
                 WHERE tenant_id = $1 AND collection_id = $2 AND day_ms < $3
                 RETURNING ioc_id
             ), requeued AS (
                 INSERT INTO stix_pending_iocs (tenant_id, collection_id, step, ioc_id)
                 SELECT DISTINCT $1, $2, 'merge', ioc_id FROM old_contributions
                 ON CONFLICT DO NOTHING
                 RETURNING 1
             )
             SELECT count(*) AS n FROM gone",
            &[&tenant_id, &collection, &evidence_before],
        )
        .await?
        .get("n");
    Ok(n as u64)
}

pub async fn stix_days(
    client: &Client,
    tenant_id: &str,
    collection: &str,
) -> Result<Vec<DayRow>, Error> {
    let rows = client
        .query(
            "SELECT day_ms, signature, object_ids, progress, served_ms FROM stix_materialised_days
             WHERE tenant_id = $1 AND collection_id = $2",
            &[&tenant_id, &collection],
        )
        .await?;
    Ok(rows
        .iter()
        .map(|r| {
            (
                r.get("day_ms"),
                r.get("signature"),
                r.get("object_ids"),
                r.get("progress"),
                r.get("served_ms"),
            )
        })
        .collect())
}

/// Save a day record. Fenced.
pub async fn put_stix_day(
    client: &Client,
    tenant_id: &str,
    collection: &str,
    day: &DayRow,
    fence_gen: i64,
) -> Result<(), Error> {
    in_tx(client, async {
        fence(client, tenant_id, collection, fence_gen).await?;
        write_day(client, tenant_id, collection, day).await
    })
    .await
}

async fn write_day(
    client: &Client,
    tenant_id: &str,
    collection: &str,
    day: &DayRow,
) -> Result<(), Error> {
    let (day_ms, signature, ids, progress, served) = day;
    client
        .execute(
            "INSERT INTO stix_materialised_days
                 (tenant_id, collection_id, day_ms, signature, object_ids, progress, served_ms)
             VALUES ($1, $2, $3, $4, $5, $6, $7)
             ON CONFLICT (tenant_id, collection_id, day_ms)
             DO UPDATE SET signature = EXCLUDED.signature, object_ids = EXCLUDED.object_ids,
                           progress = EXCLUDED.progress, served_ms = EXCLUDED.served_ms",
            &[
                &tenant_id,
                &collection,
                day_ms,
                signature,
                ids,
                progress,
                served,
            ],
        )
        .await?;
    Ok(())
}

/// Stage one build part in one transaction: drop staged contributions of
/// this part and later ones (and, for part 0, the day's staged attempts),
/// upsert the part's attempts, insert its contributions (`(ioc_id, JSON)`)
/// and save the day. Fenced.
#[allow(clippy::too_many_arguments)]
pub async fn stix_stage_part(
    client: &Client,
    tenant_id: &str,
    collection: &str,
    part: i32,
    attempts: &[AttemptRow],
    contributions: &[(String, String)],
    day: &DayRow,
    fence_gen: i64,
) -> Result<(), Error> {
    let day_ms = day.0;
    in_tx(client, async {
        fence(client, tenant_id, collection, fence_gen).await?;
        client
            .execute(
                "DELETE FROM stix_ioc_contributions
                 WHERE tenant_id = $1 AND collection_id = $2 AND NOT live AND day_ms = $3
                   AND part >= $4",
                &[&tenant_id, &collection, &day_ms, &part],
            )
            .await?;
        if part == 0 {
            client
                .execute(
                    "DELETE FROM stix_day_attempts
                     WHERE tenant_id = $1 AND collection_id = $2 AND NOT live AND day_ms = $3",
                    &[&tenant_id, &collection, &day_ms],
                )
                .await?;
        }
        let ids: Vec<&str> = attempts.iter().map(|a| a.0.as_str()).collect();
        let bodies: Vec<&str> = attempts.iter().map(|a| a.1.as_str()).collect();
        client
            .execute(
                "INSERT INTO stix_day_attempts
                     (tenant_id, collection_id, live, day_ms, attempt_id, body)
                 SELECT $1, $2, false, $3, u.id, u.body
                 FROM unnest($4::text[], $5::text[]) AS u(id, body)
                 ON CONFLICT (tenant_id, collection_id, live, day_ms, attempt_id) DO UPDATE
                     SET body = EXCLUDED.body",
                &[&tenant_id, &collection, &day_ms, &ids, &bodies],
            )
            .await?;
        let iocs: Vec<&str> = contributions.iter().map(|c| c.0.as_str()).collect();
        let bodies: Vec<&str> = contributions.iter().map(|c| c.1.as_str()).collect();
        client
            .execute(
                "INSERT INTO stix_ioc_contributions
                     (tenant_id, collection_id, live, day_ms, part, ioc_id, body)
                 SELECT $1, $2, false, $3, $4, u.ioc, u.body
                 FROM unnest($5::text[], $6::text[]) AS u(ioc, body)",
                &[&tenant_id, &collection, &day_ms, &part, &iocs, &bodies],
            )
            .await?;
        write_day(client, tenant_id, collection, day).await
    })
    .await
}

/// Make a day's staged attempts and contributions live in one
/// transaction: queue every IOC with an old or new contribution for
/// merging, replace the live rows, save the day. Fenced.
pub async fn stix_promote_day(
    client: &Client,
    tenant_id: &str,
    collection: &str,
    day: &DayRow,
    fence_gen: i64,
) -> Result<(), Error> {
    let day_ms = day.0;
    in_tx(client, async {
        fence(client, tenant_id, collection, fence_gen).await?;
        client
            .execute(
                "INSERT INTO stix_pending_iocs (tenant_id, collection_id, step, ioc_id)
                 SELECT DISTINCT $1, $2, 'merge', ioc_id FROM stix_ioc_contributions
                 WHERE tenant_id = $1 AND collection_id = $2 AND day_ms = $3
                 ON CONFLICT DO NOTHING",
                &[&tenant_id, &collection, &day_ms],
            )
            .await?;
        for table in ["stix_ioc_contributions", "stix_day_attempts"] {
            client
                .execute(
                    &format!(
                        "DELETE FROM {table}
                         WHERE tenant_id = $1 AND collection_id = $2 AND live AND day_ms = $3"
                    ),
                    &[&tenant_id, &collection, &day_ms],
                )
                .await?;
            client
                .execute(
                    &format!(
                        "UPDATE {table} SET live = true
                         WHERE tenant_id = $1 AND collection_id = $2 AND NOT live AND day_ms = $3"
                    ),
                    &[&tenant_id, &collection, &day_ms],
                )
                .await?;
        }
        write_day(client, tenant_id, collection, day).await
    })
    .await
}

/// A day's live attempts with id after `after`, in id order.
pub async fn stix_day_attempts(
    client: &Client,
    tenant_id: &str,
    collection: &str,
    day_ms: i64,
    after: Option<&str>,
    limit: i64,
) -> Result<Vec<AttemptRow>, Error> {
    let rows = client
        .query(
            "SELECT attempt_id::text AS attempt_id, body FROM stix_day_attempts
             WHERE tenant_id = $1 AND collection_id = $2 AND live AND day_ms = $3
               AND ($4::text IS NULL OR attempt_id > $4::text COLLATE \"C\")
             ORDER BY attempt_id LIMIT $5",
            &[&tenant_id, &collection, &day_ms, &after, &limit],
        )
        .await?;
    Ok(rows
        .iter()
        .map(|r| (r.get("attempt_id"), r.get("body")))
        .collect())
}

/// Which of these IOCs the last merge published.
pub async fn stix_published(
    client: &Client,
    tenant_id: &str,
    collection: &str,
    ioc_ids: &[String],
) -> Result<Vec<PublishedRow>, Error> {
    let rows = client
        .query(
            "SELECT ioc_id::text AS ioc_id, ioc_type, value FROM stix_ioc_published
             WHERE tenant_id = $1 AND collection_id = $2 AND ioc_id = ANY($3)",
            &[&tenant_id, &collection, &ioc_ids],
        )
        .await?;
    Ok(rows
        .iter()
        .map(|r| (r.get("ioc_id"), r.get("ioc_type"), r.get("value")))
        .collect())
}

/// Record merge gate decisions in one transaction. Fenced.
pub async fn stix_set_published(
    client: &Client,
    tenant_id: &str,
    collection: &str,
    add: &[PublishedRow],
    remove: &[String],
    fence_gen: i64,
) -> Result<(), Error> {
    in_tx(client, async {
        fence(client, tenant_id, collection, fence_gen).await?;
        client
            .execute(
                "DELETE FROM stix_ioc_published
                 WHERE tenant_id = $1 AND collection_id = $2 AND ioc_id = ANY($3)",
                &[&tenant_id, &collection, &remove],
            )
            .await?;
        let ids: Vec<&str> = add.iter().map(|a| a.0.as_str()).collect();
        let types: Vec<&str> = add.iter().map(|a| a.1.as_str()).collect();
        let values: Vec<&str> = add.iter().map(|a| a.2.as_str()).collect();
        client
            .execute(
                "INSERT INTO stix_ioc_published (tenant_id, collection_id, ioc_id, ioc_type, value)
                 SELECT $1, $2, u.id, u.ty, u.value
                 FROM unnest($3::text[], $4::text[], $5::text[]) AS u(id, ty, value)
                 ON CONFLICT (tenant_id, collection_id, ioc_id) DO NOTHING",
                &[&tenant_id, &collection, &ids, &types, &values],
            )
            .await?;
        Ok(())
    })
    .await
}

/// Every live contribution to these IOCs: `(ioc_id, day_ms, JSON)`.
pub async fn stix_contributions(
    client: &Client,
    tenant_id: &str,
    collection: &str,
    ioc_ids: &[String],
) -> Result<Vec<(String, i64, String)>, Error> {
    let rows = client
        .query(
            "SELECT ioc_id::text AS ioc_id, day_ms, body FROM stix_ioc_contributions
             WHERE tenant_id = $1 AND collection_id = $2 AND live AND ioc_id = ANY($3)
             ORDER BY ioc_id, day_ms, part",
            &[&tenant_id, &collection, &ioc_ids],
        )
        .await?;
    Ok(rows
        .iter()
        .map(|r| (r.get("ioc_id"), r.get("day_ms"), r.get("body")))
        .collect())
}

/// The first `limit` IOC ids queued for `step`, in id order.
pub async fn stix_pending(
    client: &Client,
    tenant_id: &str,
    collection: &str,
    step: &str,
    limit: i64,
) -> Result<Vec<String>, Error> {
    let rows = client
        .query(
            "SELECT ioc_id::text AS ioc_id FROM stix_pending_iocs
             WHERE tenant_id = $1 AND collection_id = $2 AND step = $3
             ORDER BY ioc_id LIMIT $4",
            &[&tenant_id, &collection, &step, &limit],
        )
        .await?;
    Ok(rows.iter().map(|r| r.get("ioc_id")).collect())
}

/// Take IOC ids off queue `from` and, when `to` is set, put them on it.
/// Fenced.
pub async fn stix_pending_move(
    client: &Client,
    tenant_id: &str,
    collection: &str,
    ids: &[String],
    from: &str,
    to: Option<&str>,
    fence_gen: i64,
) -> Result<(), Error> {
    in_tx(client, async {
        fence(client, tenant_id, collection, fence_gen).await?;
        client
            .execute(
                "DELETE FROM stix_pending_iocs
                 WHERE tenant_id = $1 AND collection_id = $2 AND step = $3 AND ioc_id = ANY($4)",
                &[&tenant_id, &collection, &from, &ids],
            )
            .await?;
        if let Some(to) = to {
            client
                .execute(
                    "INSERT INTO stix_pending_iocs (tenant_id, collection_id, step, ioc_id)
                     SELECT $1, $2, $3, u FROM unnest($4::text[]) AS u
                     ON CONFLICT DO NOTHING",
                    &[&tenant_id, &collection, &to, &ids],
                )
                .await?;
        }
        Ok(())
    })
    .await
}

/// Take or renew the materialiser lease for `ttl_ms`, judged by the
/// database clock. Returns the lease generation when `holder` holds it
/// afterwards: it was free, expired or `holder`'s. A takeover increments
/// the generation; a renewal keeps it.
pub async fn stix_lease(
    client: &Client,
    tenant_id: &str,
    collection: &str,
    holder: &str,
    ttl_ms: i64,
) -> Result<Option<i64>, Error> {
    let row = client
        .query_opt(
            "WITH now AS (SELECT (extract(epoch FROM clock_timestamp()) * 1000)::bigint AS ms)
             INSERT INTO stix_materialiser_leases
                 (tenant_id, collection_id, holder, expires_at, generation)
             SELECT $1, $2, $3, now.ms + $4, 1 FROM now
             ON CONFLICT (tenant_id, collection_id) DO UPDATE
                 SET holder = EXCLUDED.holder,
                     expires_at = EXCLUDED.expires_at,
                     generation = CASE
                         WHEN stix_materialiser_leases.holder = EXCLUDED.holder
                         THEN stix_materialiser_leases.generation
                         ELSE stix_materialiser_leases.generation + 1 END
                 WHERE stix_materialiser_leases.holder = EXCLUDED.holder
                    OR stix_materialiser_leases.expires_at
                       < (extract(epoch FROM clock_timestamp()) * 1000)::bigint
             RETURNING generation",
            &[&tenant_id, &collection, &holder, &ttl_ms],
        )
        .await?;
    Ok(row.map(|r| r.get("generation")))
}

/// Give the lease up, if `holder` holds it: it expires now and keeps its
/// generation, so the next holder's is higher.
pub async fn stix_release(
    client: &Client,
    tenant_id: &str,
    collection: &str,
    holder: &str,
) -> Result<(), Error> {
    client
        .execute(
            "UPDATE stix_materialiser_leases SET holder = '', expires_at = 0
             WHERE tenant_id = $1 AND collection_id = $2 AND holder = $3",
            &[&tenant_id, &collection, &holder],
        )
        .await?;
    Ok(())
}

pub async fn stix_cron_cursor(client: &Client, collection: &str) -> Result<Option<String>, Error> {
    let row = client
        .query_opt(
            "SELECT tenant_id FROM stix_cron_cursor WHERE collection_id = $1",
            &[&collection],
        )
        .await?;
    Ok(row.map(|r| r.get("tenant_id")))
}

pub async fn put_stix_cron_cursor(
    client: &Client,
    collection: &str,
    tenant_id: &str,
) -> Result<(), Error> {
    client
        .execute(
            "INSERT INTO stix_cron_cursor (collection_id, tenant_id) VALUES ($1, $2)
             ON CONFLICT (collection_id) DO UPDATE SET tenant_id = EXCLUDED.tenant_id",
            &[&collection, &tenant_id],
        )
        .await?;
    Ok(())
}

/// One day's inputs other than its events: a digest of the analyst link
/// decisions on its live attempts, their campaign memberships, those
/// campaigns' records and the actions on them; and the day's addresses
/// (from its live contributions), for the caller to look up in the
/// enrichment cache.
pub async fn stix_day_inputs(
    client: &Client,
    tenant_id: &str,
    collection: &str,
    day_ms: i64,
) -> Result<(String, Vec<String>), Error> {
    let r = client
        .query_one(
            "WITH a AS (
                 SELECT attempt_id::text AS attempt_id FROM stix_day_attempts
                 WHERE tenant_id = $1 AND collection_id = $2 AND live AND day_ms = $3
             ), m AS (
                 SELECT cm.campaign_id, cm.recorded_at FROM campaign_members cm
                 JOIN a ON a.attempt_id = cm.attempt_id WHERE cm.tenant_id = $1
             )
             SELECT concat_ws('|',
                 (SELECT count(*) || ':' || coalesce(max(o.at), 0) FROM link_overrides o
                  JOIN a ON a.attempt_id = o.attempt_id WHERE o.tenant_id = $1),
                 (SELECT count(*) || ':' || coalesce(max(recorded_at), 0) FROM m),
                 (SELECT count(*) || ':' || coalesce(max(c.updated_at), 0) FROM campaigns c
                  WHERE c.tenant_id = $1 AND c.campaign_id IN (SELECT campaign_id FROM m)),
                 (SELECT count(*) || ':' || coalesce(max(x.at), 0) FROM campaign_actions x
                  WHERE x.tenant_id = $1 AND x.campaign_id IN (SELECT campaign_id FROM m))
             ) AS sig",
            &[&tenant_id, &collection, &day_ms],
        )
        .await?;
    let rows = client
        .query(
            "SELECT DISTINCT body::jsonb ->> 'value' AS value FROM stix_ioc_contributions
             WHERE tenant_id = $1 AND collection_id = $2 AND live AND day_ms = $3
               AND body::jsonb ->> 'ioc_type' IN ('ip', 'ipv6')",
            &[&tenant_id, &collection, &day_ms],
        )
        .await?;
    Ok((
        r.get("sig"),
        rows.iter().filter_map(|r| r.get("value")).collect(),
    ))
}

/// Count and newest arrival of a tenant's events in `[since, until)`, as
/// `"<count>:<max received_at>"`.
pub async fn event_signature(
    client: &Client,
    tenant_id: &str,
    since: i64,
    until: i64,
) -> Result<String, Error> {
    let r = client
        .query_one(
            "SELECT count(*)::text || ':' || coalesce(max(received_at), 0)::text AS sig
             FROM capture_events WHERE tenant_id = $1 AND ts >= $2 AND ts < $3",
            &[&tenant_id, &since, &until],
        )
        .await?;
    Ok(r.get("sig"))
}

/// Tenants with object heads, day records or queued IOCs in the collection.
pub async fn stix_tenants(client: &Client, collection: &str) -> Result<Vec<String>, Error> {
    let rows = client
        .query(
            "SELECT tenant_id FROM stix_object_heads WHERE collection_id = $1
             UNION SELECT tenant_id FROM stix_materialised_days WHERE collection_id = $1
             UNION SELECT tenant_id FROM stix_pending_iocs WHERE collection_id = $1
             ORDER BY tenant_id",
            &[&collection],
        )
        .await?;
    Ok(rows.iter().map(|r| r.get("tenant_id")).collect())
}

/// Tenants with an event received at or after `since`, in id order.
pub async fn tenants_with_events(client: &Client, since: i64) -> Result<Vec<String>, Error> {
    let rows = client
        .query(
            "SELECT DISTINCT tenant_id FROM capture_events WHERE received_at >= $1
             ORDER BY tenant_id",
            &[&since],
        )
        .await?;
    Ok(rows.iter().map(|r| r.get("tenant_id")).collect())
}
