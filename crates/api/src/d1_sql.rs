//! SQL for the D1 store. Kept apart from the Worker binding code so the
//! statements are tested against SQLite on the host (D1 is SQLite).
//! Parameters are positional (`?1`, `?2`, ...).

/// Every D1 migration, in order. Wrangler applies them in production.
pub const MIGRATIONS: &[&str] = &[
    include_str!("../../../migrations/d1/0001_init.sql"),
    include_str!("../../../migrations/d1/0002_host_jobs.sql"),
    include_str!("../../../migrations/d1/0003_enrolment.sql"),
    include_str!("../../../migrations/d1/0004_enrich_cache.sql"),
    include_str!("../../../migrations/d1/0005_enrich_consumer.sql"),
];

pub const TOKEN_BY_ID: &str = "SELECT id, tenant_id, role, scopes, secret_sha256, expires_at, revoked \
     FROM api_tokens WHERE id = ?1";

pub const IDENTITY_BY_CERT: &str = "SELECT id, tenant_id, role, scopes, cert_sha256, revoked, valid_until, \
     expires_at FROM identities WHERE cert_sha256 = ?1";

pub const INSERT_DECOY: &str = "INSERT INTO decoys (id, tenant_id, catalogue_id, decoy_kind, label, state, host_id, \
     generation, created_at, updated_at, expires_at, created_by) \
     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)";

const DECOY_COLUMNS: &str = "id, tenant_id, catalogue_id, decoy_kind, label, state, host_id, generation, \
     created_at, updated_at, expires_at, created_by";

pub fn decoy_by_id() -> String {
    format!("SELECT {DECOY_COLUMNS} FROM decoys WHERE tenant_id = ?1 AND id = ?2")
}

/// `?1` tenant, `?2` state or NULL, `?3` catalogue id or NULL,
/// `?4`/`?5` keyset cursor (created_at, id) or NULL, `?6` limit.
pub fn list_decoys() -> String {
    format!(
        "SELECT {DECOY_COLUMNS} FROM decoys \
         WHERE tenant_id = ?1 \
           AND (?2 IS NULL OR state = ?2) \
           AND (?3 IS NULL OR catalogue_id = ?3) \
           AND (?4 IS NULL OR created_at < ?4 OR (created_at = ?4 AND id < ?5)) \
           AND (?7 IS NULL OR created_by = ?7) \
           AND (?8 = 0 OR state != 'destroyed') \
         ORDER BY created_at DESC, id DESC LIMIT ?6"
    )
}

/// Resolve a list cursor (a decoy id) to its keyset position.
pub const CURSOR_POSITION: &str =
    "SELECT created_at, id FROM decoys WHERE tenant_id = ?1 AND id = ?2";

pub const COUNT_LIVE_DECOYS: &str =
    "SELECT COUNT(*) AS n FROM decoys WHERE tenant_id = ?1 AND state != 'destroyed'";

pub const INSERT_JOB: &str = "INSERT INTO jobs (id, tenant_id, decoy_id, host_id, kind, reason_code, reason_text, \
     idempotency_key, created_at, expires_at, status, params, leased_until) \
     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)";

pub const JOB_COLUMNS: &str = "id, tenant_id, decoy_id, host_id, kind, reason_code, reason_text, \
     idempotency_key, created_at, expires_at, status, params, leased_until";

pub fn job_by_idempotency_key() -> String {
    format!("SELECT {JOB_COLUMNS} FROM jobs WHERE tenant_id = ?1 AND idempotency_key = ?2")
}

/// Lease jobs for a host in one statement, so two hosts cannot take the same
/// unplaced job. `?1` tenant, `?2` host, `?3` now, `?4` lease ms, `?5` limit,
/// `?6` 1 to take unplaced jobs (research hosts) or 0 (edge sensors).
pub fn lease_jobs() -> String {
    format!(
        "UPDATE jobs SET host_id = ?2, status = 'leased', leased_until = ?3 + ?4 \
         WHERE id IN (SELECT id FROM jobs WHERE tenant_id = ?1 \
             AND ((host_id IS NULL AND ?6 = 1) OR host_id = ?2) \
             AND (status = 'queued' OR (status = 'leased' AND leased_until <= ?3)) \
             AND expires_at > ?3 \
             ORDER BY created_at, id LIMIT ?5) \
         RETURNING {JOB_COLUMNS}"
    )
}

/// After a lease, place unplaced decoys on the host that took their jobs.
pub const PLACE_DECOYS: &str = "UPDATE decoys SET host_id = ?2 \
     WHERE tenant_id = ?1 AND host_id IS NULL AND id IN \
     (SELECT decoy_id FROM jobs WHERE tenant_id = ?1 AND host_id = ?2 AND status = 'leased')";

/// `?1` tenant, `?2` host, `?3` job id, `?4` final status.
pub fn finish_job() -> String {
    format!(
        "UPDATE jobs SET status = ?4, leased_until = NULL \
         WHERE tenant_id = ?1 AND host_id = ?2 AND id = ?3 AND status = 'leased' \
         RETURNING {JOB_COLUMNS}"
    )
}

/// Compare-and-set. `?3` expected state, `?4` new state, `?5` generation
/// increment (0 or 1), `?6` now.
pub const SET_DECOY_STATE: &str = "UPDATE decoys SET state = ?4, generation = generation + ?5, updated_at = ?6 \
     WHERE tenant_id = ?1 AND id = ?2 AND state = ?3 RETURNING id";

pub const UPSERT_HEARTBEAT: &str = "INSERT INTO host_heartbeats (tenant_id, host_id, heartbeat, clock_skew_ms, received_at) \
     VALUES (?1, ?2, ?3, ?4, ?5) \
     ON CONFLICT (tenant_id, host_id) DO UPDATE SET heartbeat = ?3, clock_skew_ms = ?4, received_at = ?5";

/// The count for one window, without adding a hit.
pub const RATE_COUNT: &str = "SELECT count FROM rate_limits WHERE key = ?1 AND window_start = ?2";

/// Increment and return the count for one window in one statement.
pub const RATE_LIMIT_HIT: &str = "INSERT INTO rate_limits (key, window_start, count) VALUES (?1, ?2, 1) \
     ON CONFLICT (key, window_start) DO UPDATE SET count = count + 1 \
     RETURNING count";

// Enrolment and the sensor and host registry (#31).

pub const AGENT_COLUMNS: &str = "id, tenant_id, role, label, status, sandbox_allowed, share_opt_in, \
     created_at, created_by, enrolled_at, cert_sha256, cert_expires_at, last_seen_at, last_ip, \
     last_asn, network_changed_at, revoked_at, revoke_reason_code, revoke_reason_text";

pub const INSERT_AGENT: &str = "INSERT INTO agents (id, tenant_id, role, label, status, sandbox_allowed, share_opt_in, \
     created_at, created_by, enrolled_at, cert_sha256, cert_expires_at, last_seen_at, last_ip, \
     last_asn, network_changed_at, revoked_at, revoke_reason_code, revoke_reason_text) \
     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19)";

/// `?1` tenant, `?2` role, `?3` id.
pub fn agent_by_id() -> String {
    format!("SELECT {AGENT_COLUMNS} FROM agents WHERE tenant_id = ?1 AND role = ?2 AND id = ?3")
}

/// Resolve a list cursor (an agent id) to its keyset position.
pub const AGENT_CURSOR: &str =
    "SELECT created_at, id FROM agents WHERE tenant_id = ?1 AND role = ?2 AND id = ?3";

/// `?1` tenant, `?2` role, `?3`/`?4` keyset cursor or NULL, `?5` limit.
pub fn list_agents() -> String {
    format!(
        "SELECT {AGENT_COLUMNS} FROM agents WHERE tenant_id = ?1 AND role = ?2 \
           AND (?3 IS NULL OR created_at < ?3 OR (created_at = ?3 AND id < ?4)) \
         ORDER BY created_at DESC, id DESC LIMIT ?5"
    )
}

pub const INSERT_ENROLMENT_TOKEN: &str = "INSERT INTO enrolment_tokens (id, tenant_id, agent_id, role, secret_sha256, \
     created_at, expires_at, created_by, used_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)";

/// Close every unused token for an agent. `?1` tenant, `?2` agent, `?3` now.
pub const CLOSE_UNUSED_TOKENS: &str = "UPDATE enrolment_tokens SET used_at = ?3 \
     WHERE tenant_id = ?1 AND agent_id = ?2 AND used_at IS NULL";

pub const ENROLMENT_TOKEN_BY_ID: &str = "SELECT id, tenant_id, agent_id, role, secret_sha256, created_at, \
     expires_at, created_by, used_at FROM enrolment_tokens WHERE id = ?1";

/// Single use, enforced in one statement. `?1` id, `?2` now.
pub const CONSUME_ENROLMENT_TOKEN: &str = "UPDATE enrolment_tokens SET used_at = ?2 \
     WHERE id = ?1 AND used_at IS NULL AND expires_at > ?2 RETURNING id";

/// Shorten the life of an identity's live certificates to `?3`.
/// `?1` tenant, `?2` identity id.
pub const RETIRE_CERTS: &str = "UPDATE identities SET valid_until = ?3 \
     WHERE tenant_id = ?1 AND id = ?2 AND revoked = 0 AND (valid_until IS NULL OR valid_until > ?3)";

/// Insert a certificate only while its agent is not revoked, so a revoke
/// racing an enrolment can never leave a live certificate behind.
/// `?1` fingerprint, `?2` id, `?3` tenant, `?4` role, `?5` scopes,
/// `?6` now, `?7` issuer ref, `?8` expires at.
pub const INSERT_AGENT_IDENTITY: &str = "INSERT INTO identities (cert_sha256, id, tenant_id, role, scopes, created_at, \
     issuer_ref, expires_at) SELECT ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8 \
     WHERE EXISTS (SELECT 1 FROM agents WHERE tenant_id = ?3 AND role = ?4 AND id = ?2 AND status != 'revoked')";

/// `?1` tenant, `?2` role, `?3` id, `?4` now, `?5` fingerprint, `?6` expires at.
pub const ACTIVATE_AGENT: &str = "UPDATE agents SET status = 'active', enrolled_at = COALESCE(enrolled_at, ?4), \
     cert_sha256 = ?5, cert_expires_at = ?6 \
     WHERE tenant_id = ?1 AND role = ?2 AND id = ?3 AND status != 'revoked' RETURNING id";

/// `?1` tenant, `?2` role, `?3` id, `?4` now, `?5` reason code, `?6` reason text.
pub const REVOKE_AGENT: &str = "UPDATE agents SET status = 'revoked', revoked_at = COALESCE(revoked_at, ?4), \
     revoke_reason_code = ?5, revoke_reason_text = ?6 \
     WHERE tenant_id = ?1 AND role = ?2 AND id = ?3 RETURNING id";

/// `?1` tenant, `?2` identity id.
pub const REVOKE_IDENTITIES: &str =
    "UPDATE identities SET revoked = 1 WHERE tenant_id = ?1 AND id = ?2";

/// Every certificate of an identity with its CA reference (NULL for
/// certificates issued outside `/v0/enrol`). `?1` tenant, `?2` identity id.
pub const AGENT_CERTS: &str = "SELECT cert_sha256, issuer_ref FROM identities \
     WHERE tenant_id = ?1 AND id = ?2 ORDER BY created_at, cert_sha256";

/// Reopen a token after the CA failed to issue. Only the claim made at
/// `?2` is undone, and never for a revoked agent. `?1` id.
pub const RELEASE_ENROLMENT_TOKEN: &str = "UPDATE enrolment_tokens SET used_at = NULL \
     WHERE id = ?1 AND used_at = ?2 AND EXISTS (SELECT 1 FROM agents \
     WHERE agents.id = enrolment_tokens.agent_id AND agents.tenant_id = enrolment_tokens.tenant_id \
     AND agents.status != 'revoked')";

/// `?1` tenant, `?2` id, `?3` now, `?4` ip, `?5` asn, `?6` 1 if the network jumped.
pub const RECORD_AGENT_SEEN: &str = "UPDATE agents SET last_seen_at = ?3, last_ip = ?4, last_asn = ?5, \
     network_changed_at = CASE WHEN ?6 = 1 THEN ?3 ELSE network_changed_at END \
     WHERE tenant_id = ?1 AND id = ?2";

// Enrichment cache reads (#11).

/// D1 binds at most 100 parameters per statement.
pub const D1_MAX_BOUND_PARAMS: usize = 100;

/// Observable values per lookup statement: the bound limit less the kind,
/// the clock and the tenant.
pub const ENRICH_LOOKUP_CHUNK: usize = D1_MAX_BOUND_PARAMS - 3;

/// Cache rows for some values of one kind that are still fresh and that
/// the tenant may read (shared rows, and its own). `?1` kind, `?2` now
/// (unix ms), `?3` tenant or NULL, `?4`.. the values. Uses
/// `enrich_cache_observable`.
pub fn enrich_cache_lookup(values: usize) -> String {
    let list: Vec<String> = (0..values).map(|i| format!("?{}", i + 4)).collect();
    format!(
        "SELECT provider, kind, value, fetched_at, ttl_secs, facts, tenant_id FROM enrich_cache \
         WHERE kind = ?1 AND value IN ({}) AND fetched_at + ttl_secs * 1000 > ?2 \
         AND (tenant_id IS NULL OR tenant_id = ?3)",
        list.join(", ")
    )
}

/// How to look up a set of observables in at most `max_statements`
/// statements: duplicates removed first, then the first
/// `max_statements * ENRICH_LOOKUP_CHUNK` kept (callers pass the newest
/// first), then one `(kind, values)` per statement, grouped by kind, at most
/// [`ENRICH_LOOKUP_CHUNK`] values each. Send them in one D1 batch.
pub fn enrich_lookup_plan(
    observables: &[foiled_core::enrichment::Observable],
    max_statements: usize,
) -> Vec<(&'static str, Vec<String>)> {
    use std::collections::{BTreeMap, BTreeSet};
    let mut seen: BTreeSet<&foiled_core::enrichment::Observable> = BTreeSet::new();
    let mut kept: Vec<&foiled_core::enrichment::Observable> = Vec::new();
    let budget = max_statements.saturating_mul(ENRICH_LOOKUP_CHUNK);
    for o in observables {
        if kept.len() == budget {
            break;
        }
        if seen.insert(o) {
            kept.push(o);
        }
    }
    let mut by_kind: BTreeMap<&'static str, Vec<String>> = BTreeMap::new();
    for o in kept {
        by_kind
            .entry(o.kind.as_str())
            .or_default()
            .push(o.value.clone());
    }
    let mut plan = Vec::new();
    for (kind, values) in by_kind {
        for chunk in values.chunks(ENRICH_LOOKUP_CHUNK) {
            plan.push((kind, chunk.to_vec()));
        }
    }
    // Grouping by kind can split the budget unevenly; never exceed it.
    plan.truncate(max_statements);
    plan
}

// Enrichment consumer writes (#11).

/// Write a cache row, replacing the provider's earlier answer for the same
/// observable (and tenant, for a tenant row). `?1` key, `?2` provider, `?3`
/// kind, `?4` value, `?5` fetched_at, `?6` ttl_secs, `?7` Facts JSON, `?8`
/// tenant or NULL.
pub const ENRICH_CACHE_UPSERT: &str = "INSERT INTO enrich_cache (cache_key, provider, kind, value, fetched_at, ttl_secs, facts, tenant_id) \
     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8) \
     ON CONFLICT (cache_key) DO UPDATE SET fetched_at = ?5, ttl_secs = ?6, facts = ?7";

/// Take one unit of a provider's budget for one window, only while under
/// the limit. Returns the new count, or no row when the budget is spent.
/// `?1` provider, `?2` window (`minute` or `day`), `?3` window start, `?4`
/// limit (at least 1).
pub const ENRICH_BUDGET_TAKE: &str = "INSERT INTO enrich_budget (provider, window, window_start, used) VALUES (?1, ?2, ?3, 1) \
     ON CONFLICT (provider, window, window_start) DO UPDATE SET used = used + 1 WHERE used < ?4 \
     RETURNING used";

/// Give back a unit taken from one window (the minute unit, when the day
/// budget turned out to be spent).
pub const ENRICH_BUDGET_REFUND: &str = "UPDATE enrich_budget SET used = used - 1 \
     WHERE provider = ?1 AND window = ?2 AND window_start = ?3 AND used > 0";

/// Drop a provider's counters older than `?2` (unix ms).
pub const ENRICH_BUDGET_PRUNE: &str =
    "DELETE FROM enrich_budget WHERE provider = ?1 AND window_start < ?2";

/// Failures recorded for one observable. `?1` kind, `?2` value.
pub const ENRICH_FAILURES_FOR: &str = "SELECT provider, kind, value, failures, last_failed_at, retry_at FROM enrich_failures \
     WHERE kind = ?1 AND value = ?2";

/// Count a failure. `?1` key, `?2` provider, `?3` kind, `?4` value, `?5`
/// now, `?6` error text, `?7` Retry-After time or NULL.
pub const ENRICH_FAILURE_RECORD: &str = "INSERT INTO enrich_failures (cache_key, provider, kind, value, failures, last_failed_at, last_error, retry_at) \
     VALUES (?1, ?2, ?3, ?4, 1, ?5, ?6, ?7) \
     ON CONFLICT (cache_key) DO UPDATE SET failures = failures + 1, last_failed_at = ?5, last_error = ?6, retry_at = ?7";

/// Forget failures once the provider answers. `?1` key.
pub const ENRICH_FAILURE_CLEAR: &str = "DELETE FROM enrich_failures WHERE cache_key = ?1";

/// Start of the minute and the UTC day holding `now_ms`.
pub fn budget_windows(now_ms: i64) -> (i64, i64) {
    (
        now_ms - now_ms.rem_euclid(60_000),
        now_ms - now_ms.rem_euclid(86_400_000),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::{Connection, OptionalExtension, params};

    fn db() -> Connection {
        let c = Connection::open_in_memory().unwrap();
        for m in MIGRATIONS {
            c.execute_batch(m).unwrap();
        }
        c
    }

    fn insert_decoy(c: &Connection, id: &str, tenant: &str, created: i64, state: &str) {
        c.execute(
            INSERT_DECOY,
            params![
                id,
                tenant,
                "foiled/demo-app/1.0.0",
                "sandbox",
                None::<String>,
                state,
                None::<String>,
                1,
                created,
                created,
                created + 1000,
                "tok1"
            ],
        )
        .unwrap();
    }

    #[test]
    fn first_migration_applies_twice() {
        let c = db();
        c.execute_batch(MIGRATIONS[0]).unwrap();
    }

    #[test]
    fn decoy_queries_filter_and_page_by_keyset() {
        let c = db();
        insert_decoy(&c, "a", "t1", 100, "pending");
        insert_decoy(&c, "b", "t1", 200, "healthy");
        insert_decoy(&c, "c", "t1", 200, "destroyed");
        insert_decoy(&c, "z", "t2", 300, "pending");

        let ids = |sql: &str, p: &[&dyn rusqlite::ToSql]| -> Vec<String> {
            let mut st = c.prepare(sql).unwrap();
            st.query_map(p, |r| r.get::<_, String>(0))
                .unwrap()
                .map(Result::unwrap)
                .collect()
        };
        let none: Option<String> = None;
        let none_i: Option<i64> = None;
        let all = ids(
            &list_decoys(),
            &[&"t1", &none, &none, &none_i, &none, &10, &none, &0],
        );
        assert_eq!(all, vec!["c", "b", "a"]);
        let healthy = ids(
            &list_decoys(),
            &[
                &"t1",
                &Some("healthy"),
                &none,
                &none_i,
                &none,
                &10,
                &none,
                &0,
            ],
        );
        assert_eq!(healthy, vec!["b"]);
        // Cursor after "c" (ts 200) must still return "b" (same ts) then "a".
        let (ts, id): (i64, String) = c
            .query_row(CURSOR_POSITION, params!["t1", "c"], |r| {
                Ok((r.get(0)?, r.get(1)?))
            })
            .unwrap();
        let next = ids(
            &list_decoys(),
            &[&"t1", &none, &none, &Some(ts), &Some(id), &10, &none, &0],
        );
        assert_eq!(next, vec!["b", "a"]);
        let live = ids(
            &list_decoys(),
            &[&"t1", &none, &none, &none_i, &none, &10, &Some("tok1"), &1],
        );
        assert_eq!(live, vec!["b", "a"]);
        let nobody = ids(
            &list_decoys(),
            &[&"t1", &none, &none, &none_i, &none, &10, &Some("other"), &1],
        );
        assert!(nobody.is_empty());
        let got: Option<String> = c
            .query_row(&decoy_by_id(), params!["t2", "a"], |r| r.get(0))
            .optional()
            .unwrap();
        assert_eq!(got, None, "tenant isolation");
        let n: i64 = c
            .query_row(COUNT_LIVE_DECOYS, params!["t1"], |r| r.get(0))
            .unwrap();
        assert_eq!(n, 2);
    }

    #[test]
    fn rate_limit_counts_per_window() {
        let c = db();
        let hit = |w: i64| -> i64 {
            c.query_row(RATE_LIMIT_HIT, params!["k", w], |r| r.get(0))
                .unwrap()
        };
        let count = |w: i64| -> Option<i64> {
            c.query_row(RATE_COUNT, params!["k", w], |r| r.get(0))
                .optional()
                .unwrap()
        };
        assert_eq!(count(0), None);
        assert_eq!(hit(0), 1);
        assert_eq!(hit(0), 2);
        assert_eq!(count(0), Some(2));
        assert_eq!(hit(3600), 1);
    }

    #[test]
    fn jobs_are_unique_per_idempotency_key() {
        let c = db();
        insert_decoy(&c, "a", "t1", 1, "pending");
        let ins = |id: &str| {
            c.execute(
                INSERT_JOB,
                params![
                    id,
                    "t1",
                    "a",
                    None::<String>,
                    "decoy.create",
                    None::<String>,
                    None::<String>,
                    "k1",
                    1,
                    2,
                    "queued",
                    None::<String>,
                    None::<i64>
                ],
            )
        };
        ins("j1").unwrap();
        assert!(ins("j2").is_err());
        let kind: String = c
            .query_row(&job_by_idempotency_key(), params!["t1", "k1"], |r| r.get(4))
            .unwrap();
        assert_eq!(kind, "decoy.create");
    }

    #[test]
    fn identity_and_token_lookups() {
        let c = db();
        c.execute(
            "INSERT INTO identities (id, tenant_id, role, scopes, cert_sha256, created_at) \
             VALUES ('h1', 't1', 'host', 'host:lease', 'ab', 1)",
            [],
        )
        .unwrap();
        let role: String = c
            .query_row(IDENTITY_BY_CERT, params!["ab"], |r| r.get(2))
            .unwrap();
        assert_eq!(role, "host");
        assert!(
            c.execute(
                "INSERT INTO identities (id, tenant_id, role, scopes, cert_sha256, created_at) \
                 VALUES ('h2', 't1', 'admin', '', 'cd', 1)",
                [],
            )
            .is_err(),
            "only host and sensor roles"
        );
        c.execute(
            "INSERT INTO api_tokens (id, tenant_id, role, scopes, secret_sha256, created_at) \
             VALUES ('t', 't1', 'human', 'admin', 'ff', 1)",
            [],
        )
        .unwrap();
        let scopes: String = c
            .query_row(TOKEN_BY_ID, params!["t"], |r| r.get(3))
            .unwrap();
        assert_eq!(scopes, "admin");
    }

    fn job(c: &Connection, id: &str, decoy: &str, host: Option<&str>, created: i64, expires: i64) {
        c.execute(
            INSERT_JOB,
            params![
                id,
                "t1",
                decoy,
                host,
                "decoy.create",
                None::<String>,
                None::<String>,
                format!("k-{id}"),
                created,
                expires,
                "queued",
                "{}",
                None::<i64>
            ],
        )
        .unwrap();
    }

    fn lease(c: &Connection, host: &str, now: i64, limit: i64) -> Vec<String> {
        let mut st = c.prepare(&lease_jobs()).unwrap();
        let mut ids: Vec<String> = st
            .query_map(params!["t1", host, now, 1000, limit, 1], |r| r.get(0))
            .unwrap()
            .map(Result::unwrap)
            .collect();
        ids.sort();
        c.execute(PLACE_DECOYS, params!["t1", host]).unwrap();
        ids
    }

    #[test]
    fn leasing_places_jobs_once_and_respects_expiry_and_lapses() {
        let c = db();
        insert_decoy(&c, "d1", "t1", 1, "pending");
        insert_decoy(&c, "d2", "t1", 2, "pending");
        insert_decoy(&c, "d3", "t1", 3, "pending");
        job(&c, "j1", "d1", None, 1, 10_000);
        job(&c, "j2", "d2", Some("host-b"), 2, 10_000);
        job(&c, "j3", "d3", None, 3, 50);
        assert_eq!(
            lease(&c, "host-a", 100, 10),
            vec!["j1"],
            "j2 is host-b's, j3 expired"
        );
        let placed: String = c
            .query_row("SELECT host_id FROM decoys WHERE id = 'd1'", [], |r| {
                r.get(0)
            })
            .unwrap();
        assert_eq!(placed, "host-a");
        assert!(lease(&c, "host-b", 200, 10).contains(&"j2".to_string()));
        assert!(
            !lease(&c, "host-b", 300, 10).contains(&"j1".to_string()),
            "held by host-a"
        );
        // After the lease lapses only host-a (now its owner) can take it again.
        assert_eq!(lease(&c, "host-a", 1_200, 10), vec!["j1"]);
    }

    #[test]
    fn finishing_needs_the_leasing_host() {
        let c = db();
        insert_decoy(&c, "d1", "t1", 1, "pending");
        job(&c, "j1", "d1", None, 1, 10_000);
        lease(&c, "host-a", 100, 10);
        let other: Option<String> = c
            .query_row(
                &finish_job(),
                params!["t1", "host-b", "j1", "succeeded"],
                |r| r.get(0),
            )
            .optional()
            .unwrap();
        assert_eq!(other, None);
        let mine: Option<String> = c
            .query_row(
                &finish_job(),
                params!["t1", "host-a", "j1", "succeeded"],
                |r| r.get(10),
            )
            .optional()
            .unwrap();
        assert_eq!(mine.as_deref(), Some("succeeded"));
        let again: Option<String> = c
            .query_row(
                &finish_job(),
                params!["t1", "host-a", "j1", "failed"],
                |r| r.get(0),
            )
            .optional()
            .unwrap();
        assert_eq!(again, None, "a finished job cannot be finished twice");
    }

    #[test]
    fn decoy_state_is_compare_and_set() {
        let c = db();
        insert_decoy(&c, "d1", "t1", 1, "rotating");
        let set = |from: &str, to: &str, bump: i64| -> bool {
            c.query_row(
                SET_DECOY_STATE,
                params!["t1", "d1", from, to, bump, 5],
                |r| r.get::<_, String>(0),
            )
            .optional()
            .unwrap()
            .is_some()
        };
        assert!(!set("healthy", "stopped", 0));
        assert!(set("rotating", "starting", 1));
        let generation: i64 = c
            .query_row("SELECT generation FROM decoys WHERE id = 'd1'", [], |r| {
                r.get(0)
            })
            .unwrap();
        assert_eq!(generation, 2);
    }

    #[test]
    fn heartbeats_upsert() {
        let c = db();
        c.execute(UPSERT_HEARTBEAT, params!["t1", "h1", "{}", -5, 1])
            .unwrap();
        c.execute(UPSERT_HEARTBEAT, params!["t1", "h1", "{\"x\":1}", 7, 2])
            .unwrap();
        let (hb, skew): (String, i64) = c
            .query_row(
                "SELECT heartbeat, clock_skew_ms FROM host_heartbeats",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!((hb.as_str(), skew), ("{\"x\":1}", 7));
    }

    #[test]
    fn identities_migration_keeps_existing_rows_and_registers_them() {
        let c = Connection::open_in_memory().unwrap();
        c.execute_batch(MIGRATIONS[0]).unwrap();
        c.execute_batch(MIGRATIONS[1]).unwrap();
        for (id, role, scopes, fp, revoked) in [
            ("h1", "host", "host:lease", "ab", 1),
            ("h2", "host", "host:lease host:report host:ingest", "cd", 0),
            ("s9", "sensor", "sensor:ingest sensor:heartbeat", "ef", 0),
        ] {
            c.execute(
                "INSERT INTO identities (id, tenant_id, role, scopes, cert_sha256, created_at, revoked) \
                 VALUES (?1, 't1', ?2, ?3, ?4, 1, ?5)",
                params![id, role, scopes, fp, revoked],
            )
            .unwrap();
        }
        for m in &MIGRATIONS[2..] {
            c.execute_batch(m).unwrap();
        }
        let (id, revoked, valid): (String, i64, Option<i64>) = c
            .query_row(IDENTITY_BY_CERT, params!["ab"], |r| {
                Ok((r.get(0)?, r.get(5)?, r.get(6)?))
            })
            .unwrap();
        assert_eq!((id.as_str(), revoked, valid), ("h1", 1, None));
        let scopes: String = c
            .query_row(IDENTITY_BY_CERT, params!["ef"], |r| r.get(3))
            .unwrap();
        assert_eq!(scopes, "sensor:ingest", "retired scope name stripped");
        assert!(foiled_core::auth::parse_scopes(&scopes).is_ok());

        // Pre-existing identities are in the registry with the right status.
        let status = |role: &str, id: &str| -> String {
            c.query_row(&agent_by_id(), params!["t1", role, id], |r| r.get(4))
                .unwrap()
        };
        assert_eq!(status("host", "h1"), "revoked");
        assert_eq!(status("host", "h2"), "active");
        assert_eq!(status("sensor", "s9"), "active");

        // A migrated host can be revoked through the registry statements.
        let hit: Option<String> = c
            .query_row(
                REVOKE_AGENT,
                params!["t1", "host", "h2", 50, "operator_manual", "old host"],
                |r| r.get(0),
            )
            .optional()
            .unwrap();
        assert_eq!(hit.as_deref(), Some("h2"));
        c.execute(REVOKE_IDENTITIES, params!["t1", "h2"]).unwrap();
        let (revoked, issuer): (i64, Option<String>) = c
            .query_row(AGENT_CERTS_REVOKED, params!["cd"], |r| {
                Ok((r.get(0)?, r.get(1)?))
            })
            .unwrap();
        assert_eq!(
            (revoked, issuer),
            (1, None),
            "no CA reference: revoke by hand"
        );
        assert_eq!(status("host", "h2"), "revoked");
    }

    const AGENT_CERTS_REVOKED: &str =
        "SELECT revoked, issuer_ref FROM identities WHERE cert_sha256 = ?1";

    fn insert_agent(c: &Connection, id: &str, tenant: &str, role: &str, created: i64) {
        c.execute(
            INSERT_AGENT,
            params![
                id,
                tenant,
                role,
                None::<String>,
                "pending",
                0,
                None::<i64>,
                created,
                "tok1",
                None::<i64>,
                None::<String>,
                None::<i64>,
                None::<i64>,
                None::<String>,
                None::<i64>,
                None::<i64>,
                None::<i64>,
                None::<String>,
                None::<String>
            ],
        )
        .unwrap();
    }

    fn insert_token(c: &Connection, id: &str, agent: &str, expires: i64) {
        c.execute(
            INSERT_ENROLMENT_TOKEN,
            params![
                id,
                "t1",
                agent,
                "sensor",
                "ff",
                1,
                expires,
                "tok1",
                None::<i64>
            ],
        )
        .unwrap();
    }

    fn consume(c: &Connection, id: &str, now: i64) -> bool {
        c.query_row(CONSUME_ENROLMENT_TOKEN, params![id, now], |r| {
            r.get::<_, String>(0)
        })
        .optional()
        .unwrap()
        .is_some()
    }

    #[test]
    fn enrolment_tokens_are_single_use_and_expire() {
        let c = db();
        insert_agent(&c, "s1", "t1", "sensor", 1);
        insert_token(&c, "e1", "s1", 1_000);
        insert_token(&c, "e2", "s1", 1_000);
        assert!(!consume(&c, "e1", 1_000), "expired at 1000");
        assert!(consume(&c, "e2", 999));
        assert!(!consume(&c, "e2", 999), "second redemption fails");
        insert_token(&c, "e3", "s1", 5_000);
        c.execute(CLOSE_UNUSED_TOKENS, params!["t1", "s1", 10])
            .unwrap();
        assert!(!consume(&c, "e3", 20), "closed by a re-enrolment or revoke");
        let used: Option<i64> = c
            .query_row(ENROLMENT_TOKEN_BY_ID, params!["e2"], |r| r.get(8))
            .unwrap();
        assert_eq!(used, Some(999));
    }

    fn bind(c: &Connection, fp: &str, agent: &str, now: i64, retire: i64) -> bool {
        c.execute(RETIRE_CERTS, params!["t1", agent, retire])
            .unwrap();
        c.execute(
            INSERT_AGENT_IDENTITY,
            params![
                fp,
                agent,
                "t1",
                "sensor",
                "sensor:ingest",
                now,
                format!("ref-{fp}"),
                now + 100
            ],
        )
        .unwrap();
        c.query_row(
            ACTIVATE_AGENT,
            params!["t1", "sensor", agent, now, fp, now + 100],
            |r| r.get::<_, String>(0),
        )
        .optional()
        .unwrap()
        .is_some()
    }

    #[test]
    fn certificates_bind_rotate_and_revoke() {
        let c = db();
        insert_agent(&c, "s1", "t1", "sensor", 1);
        assert!(bind(&c, "aa", "s1", 10, 10));
        assert!(bind(&c, "bb", "s1", 20, 50), "renewal with grace");
        let valid = |fp: &str| -> Option<i64> {
            c.query_row(IDENTITY_BY_CERT, params![fp], |r| r.get(6))
                .unwrap()
        };
        assert_eq!(
            valid("aa"),
            Some(50),
            "old certificate retires after the grace"
        );
        assert_eq!(valid("bb"), None);
        let (status, fp): (String, String) = c
            .query_row(&agent_by_id(), params!["t1", "sensor", "s1"], |r| {
                Ok((r.get(4)?, r.get(10)?))
            })
            .unwrap();
        assert_eq!((status.as_str(), fp.as_str()), ("active", "bb"));
        assert!(
            c.query_row(&agent_by_id(), params!["t1", "host", "s1"], |r| r
                .get::<_, String>(0))
                .optional()
                .unwrap()
                .is_none(),
            "role is part of the key"
        );

        let revoked: Option<String> = c
            .query_row(
                REVOKE_AGENT,
                params!["t1", "sensor", "s1", 60, "operator_manual", "stolen"],
                |r| r.get(0),
            )
            .optional()
            .unwrap();
        assert!(revoked.is_some());
        c.execute(REVOKE_IDENTITIES, params!["t1", "s1"]).unwrap();
        let n: i64 = c
            .query_row(
                "SELECT COUNT(*) FROM identities WHERE id = 's1' AND revoked = 0",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(n, 0);
        let mut st = c.prepare(AGENT_CERTS).unwrap();
        let refs: Vec<Option<String>> = st
            .query_map(params!["t1", "s1"], |r| r.get(1))
            .unwrap()
            .map(Result::unwrap)
            .collect();
        assert_eq!(
            refs,
            vec![Some("ref-aa".to_string()), Some("ref-bb".to_string())]
        );
        assert!(
            !bind(&c, "cc", "s1", 70, 70),
            "a revoked agent binds nothing"
        );
        assert!(
            c.query_row(IDENTITY_BY_CERT, params!["cc"], |r| r.get::<_, String>(0))
                .optional()
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn agents_list_per_tenant_and_role_and_record_sightings() {
        let c = db();
        insert_agent(&c, "a", "t1", "sensor", 100);
        insert_agent(&c, "b", "t1", "sensor", 200);
        insert_agent(&c, "h", "t1", "host", 300);
        insert_agent(&c, "z", "t2", "sensor", 400);
        let ids = |p: &[&dyn rusqlite::ToSql]| -> Vec<String> {
            let mut st = c.prepare(&list_agents()).unwrap();
            st.query_map(p, |r| r.get::<_, String>(0))
                .unwrap()
                .map(Result::unwrap)
                .collect()
        };
        let none_i: Option<i64> = None;
        let none: Option<String> = None;
        assert_eq!(
            ids(&[&"t1", &"sensor", &none_i, &none, &10]),
            vec!["b", "a"]
        );
        assert_eq!(
            ids(&[&"t1", &"sensor", &Some(200), &Some("b"), &10]),
            vec!["a"]
        );
        c.execute(
            RECORD_AGENT_SEEN,
            params!["t1", "a", 7, "192.0.2.1", 64500, 1],
        )
        .unwrap();
        c.execute(
            RECORD_AGENT_SEEN,
            params!["t1", "a", 9, "192.0.2.2", 64500, 0],
        )
        .unwrap();
        let (seen, changed): (i64, Option<i64>) = c
            .query_row(&agent_by_id(), params!["t1", "sensor", "a"], |r| {
                Ok((r.get(12)?, r.get(15)?))
            })
            .unwrap();
        assert_eq!((seen, changed), (9, Some(7)));
    }

    #[test]
    fn sensors_never_lease_unplaced_jobs() {
        let c = db();
        insert_decoy(&c, "d1", "t1", 1, "pending");
        insert_decoy(&c, "d2", "t1", 2, "pending");
        job(&c, "j1", "d1", None, 1, 10_000);
        job(&c, "j2", "d2", Some("sensor-1"), 2, 10_000);
        let mut st = c.prepare(&lease_jobs()).unwrap();
        let ids: Vec<String> = st
            .query_map(params!["t1", "sensor-1", 100, 1000, 10, 0], |r| r.get(0))
            .unwrap()
            .map(Result::unwrap)
            .collect();
        assert_eq!(ids, vec!["j2"]);
    }

    #[test]
    fn concurrent_redemptions_of_one_token_have_one_winner() {
        // Two connections to one database file racing on the same token.
        let path = std::env::temp_dir().join(format!(
            "foiled-d1-token-race-{}-{:?}.sqlite",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_file(&path);
        {
            let c = Connection::open(&path).unwrap();
            for m in MIGRATIONS {
                c.execute_batch(m).unwrap();
            }
            insert_agent(&c, "s1", "t1", "sensor", 1);
            insert_token(&c, "e1", "s1", 10_000);
        }
        for round in 0..20 {
            let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
            let wins: Vec<bool> = (0..2)
                .map(|_| {
                    let (b, p) = (barrier.clone(), path.clone());
                    std::thread::spawn(move || {
                        let c = Connection::open(p).unwrap();
                        c.busy_timeout(std::time::Duration::from_secs(5)).unwrap();
                        b.wait();
                        consume(&c, "e1", 100 + round)
                    })
                })
                .collect::<Vec<_>>()
                .into_iter()
                .map(|h| h.join().unwrap())
                .collect();
            assert_eq!(wins.iter().filter(|w| **w).count(), 1, "round {round}");
            // Reopen for the next round, as a CA failure would.
            let c = Connection::open(&path).unwrap();
            c.execute(RELEASE_ENROLMENT_TOKEN, params!["e1", 100 + round])
                .unwrap();
        }
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn released_tokens_reopen_only_for_the_same_claim_and_live_agents() {
        let c = db();
        insert_agent(&c, "s1", "t1", "sensor", 1);
        insert_token(&c, "e1", "s1", 10_000);
        assert!(consume(&c, "e1", 5));
        c.execute(RELEASE_ENROLMENT_TOKEN, params!["e1", 6])
            .unwrap();
        assert!(
            !consume(&c, "e1", 7),
            "another claim's release does nothing"
        );
        c.execute(RELEASE_ENROLMENT_TOKEN, params!["e1", 5])
            .unwrap();
        assert!(consume(&c, "e1", 8), "released after a CA failure");
        c.query_row(
            REVOKE_AGENT,
            params!["t1", "sensor", "s1", 9, "operator_manual", "x"],
            |r| r.get::<_, String>(0),
        )
        .unwrap();
        c.execute(RELEASE_ENROLMENT_TOKEN, params!["e1", 8])
            .unwrap();
        assert!(!consume(&c, "e1", 10), "never reopened for a revoked agent");
    }

    fn insert_cache(
        c: &Connection,
        provider: &str,
        kind: &str,
        value: &str,
        fetched: i64,
        ttl: i64,
    ) {
        c.execute(
            "INSERT INTO enrich_cache (cache_key, provider, kind, value, fetched_at, ttl_secs, facts) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, '[]')",
            params![format!("{provider}:{kind}:{value}"), provider, kind, value, fetched, ttl],
        )
        .unwrap();
    }

    fn lookup(c: &Connection, kind: &str, now: i64, values: &[String]) -> Vec<(String, String)> {
        lookup_as(c, kind, now, None, values)
    }

    fn lookup_as(
        c: &Connection,
        kind: &str,
        now: i64,
        tenant: Option<&str>,
        values: &[String],
    ) -> Vec<(String, String)> {
        let mut args: Vec<rusqlite::types::Value> = vec![
            kind.to_string().into(),
            now.into(),
            tenant
                .map(|t| rusqlite::types::Value::from(t.to_string()))
                .unwrap_or(rusqlite::types::Value::Null),
        ];
        args.extend(
            values
                .iter()
                .map(|v| rusqlite::types::Value::from(v.clone())),
        );
        let mut st = c.prepare(&enrich_cache_lookup(values.len())).unwrap();
        st.query_map(rusqlite::params_from_iter(args), |r| {
            Ok((r.get(0)?, r.get(2)?))
        })
        .unwrap()
        .map(Result::unwrap)
        .collect()
    }

    #[test]
    fn enrichment_cache_lookup_is_batched_fresh_and_bound() {
        use foiled_core::enrichment::Observable;
        let c = db();
        let now = 1_800_000_000_000;
        insert_cache(&c, "local_asn", "ip", "203.0.113.7", now - 1000, 604_800);
        insert_cache(&c, "greynoise", "ip", "203.0.113.7", now - 1000, 86_400);
        // Expired: fetched two days ago with a one day TTL.
        insert_cache(
            &c,
            "greynoise",
            "ip",
            "198.51.100.23",
            now - 2 * 86_400_000,
            86_400,
        );
        insert_cache(&c, "local_asn", "domain", "stage2.example.invalid", now, 60);
        // A value that looks like SQL is only ever a bound parameter.
        let hostile = "x') OR 1=1 --".to_string();

        let got = lookup(
            &c,
            "ip",
            now,
            &[
                "203.0.113.7".into(),
                "198.51.100.23".into(),
                hostile.clone(),
            ],
        );
        let mut got: Vec<String> = got.into_iter().map(|(p, _)| p).collect();
        got.sort();
        assert_eq!(got, vec!["greynoise", "local_asn"]);
        assert!(lookup(&c, "domain", now, &[hostile]).is_empty());

        // A tenant row is read by its tenant only; CVE rows are allowed.
        c.execute(
            ENRICH_CACHE_UPSERT,
            params![
                "threatsieve_restricted:ip:203.0.113.7@t1",
                "threatsieve_restricted",
                "ip",
                "203.0.113.7",
                now,
                3600,
                "[]",
                "t1"
            ],
        )
        .unwrap();
        c.execute(
            ENRICH_CACHE_UPSERT,
            params![
                "threatsieve:cve:CVE-2099-0001",
                "threatsieve",
                "cve",
                "CVE-2099-0001",
                now,
                3600,
                "[]",
                None::<String>
            ],
        )
        .unwrap();
        let providers = |tenant| {
            let mut p: Vec<String> = lookup_as(&c, "ip", now, tenant, &["203.0.113.7".into()])
                .into_iter()
                .map(|(p, _)| p)
                .collect();
            p.sort();
            p
        };
        assert!(providers(Some("t1")).contains(&"threatsieve_restricted".to_string()));
        assert!(!providers(Some("t2")).contains(&"threatsieve_restricted".to_string()));
        assert!(!providers(None).contains(&"threatsieve_restricted".to_string()));
        assert_eq!(lookup(&c, "cve", now, &["CVE-2099-0001".into()]).len(), 1);

        // 250 addresses and a domain: three IP statements and one domain
        // statement, every one under D1's bound parameter limit.
        let mut obs: Vec<Observable> = (0..250)
            .map(|i| Observable::ip(&format!("198.51.{}.{}", i / 250, i % 250)).unwrap())
            .collect();
        obs.push(Observable::ip("203.0.113.7").unwrap());
        obs.push(Observable::ip("203.0.113.7").unwrap());
        obs.push(Observable::domain("stage2.example.invalid").unwrap());
        let plan = enrich_lookup_plan(&obs, 20);
        assert_eq!(plan.iter().filter(|(k, _)| *k == "ip").count(), 3);
        assert_eq!(plan.iter().filter(|(k, _)| *k == "domain").count(), 1);
        assert_eq!(plan.iter().map(|(_, v)| v.len()).sum::<usize>(), 252);
        let mut hits = Vec::new();
        for (kind, values) in &plan {
            assert!(values.len() + 3 <= D1_MAX_BOUND_PARAMS);
            hits.extend(lookup(&c, kind, now, values));
        }
        assert_eq!(hits.len(), 3, "{hits:?}");

        // The statement budget bounds the work for a huge window. Duplicates
        // go first, so they never use up the budget, and the earliest
        // observables (callers pass the newest first) are the ones kept.
        let ip = |i: usize| {
            Observable::ip(&format!("10.{}.{}.{}", i / 65536, (i / 256) % 256, i % 256)).unwrap()
        };
        let mut many: Vec<Observable> = vec![ip(0); 500];
        many.extend((0..5_000).map(ip));
        let plan = enrich_lookup_plan(&many, 3);
        assert_eq!(plan.len(), 3);
        let kept: Vec<&String> = plan.iter().flat_map(|(_, v)| v).collect();
        assert_eq!(kept.len(), 3 * ENRICH_LOOKUP_CHUNK);
        assert_eq!(kept[0], "10.0.0.0");
        assert_eq!(kept[1], "10.0.0.1", "the duplicate did not take a slot");
        assert!(
            !kept.iter().any(|v| *v == "10.0.19.135"),
            "older ones are cut"
        );
        // The default budget stays inside the D1 Free plan.
        assert!(enrich_lookup_plan(&many, 20).len() <= 20);
    }

    #[test]
    fn enrichment_budget_cache_and_failure_statements() {
        let c = db();
        let now = 1_800_000_000_123;
        let (minute, day) = budget_windows(now);
        assert_eq!(minute % 60_000, 0);
        assert_eq!(day % 86_400_000, 0);
        let take = |window: &str, start: i64, limit: i64| -> Option<i64> {
            c.query_row(
                ENRICH_BUDGET_TAKE,
                params!["greynoise", window, start, limit],
                |r| r.get(0),
            )
            .optional()
            .unwrap()
        };
        // Two a minute: the third take is refused and changes nothing.
        assert_eq!(take("minute", minute, 2), Some(1));
        assert_eq!(take("minute", minute, 2), Some(2));
        assert_eq!(take("minute", minute, 2), None);
        // A new minute starts again.
        assert_eq!(take("minute", minute + 60_000, 2), Some(1));
        c.execute(ENRICH_BUDGET_REFUND, params!["greynoise", "minute", minute])
            .unwrap();
        assert_eq!(take("minute", minute, 2), Some(2));
        c.execute(ENRICH_BUDGET_PRUNE, params!["greynoise", minute + 1])
            .unwrap();
        let left: i64 = c
            .query_row("SELECT COUNT(*) FROM enrich_budget", [], |r| r.get(0))
            .unwrap();
        assert_eq!(left, 1);
        assert_eq!(take("day", day, 7), Some(1));

        // Cache upsert replaces the provider's earlier answer.
        for (fetched, facts) in [(now, "[]"), (now + 5, "[{\"x\":1}]")] {
            c.execute(
                ENRICH_CACHE_UPSERT,
                params![
                    "greynoise:ip:203.0.113.7",
                    "greynoise",
                    "ip",
                    "203.0.113.7",
                    fetched,
                    86_400,
                    facts,
                    None::<String>
                ],
            )
            .unwrap();
        }
        let (fetched, facts): (i64, String) = c
            .query_row("SELECT fetched_at, facts FROM enrich_cache", [], |r| {
                Ok((r.get(0)?, r.get(1)?))
            })
            .unwrap();
        assert_eq!((fetched, facts.as_str()), (now + 5, "[{\"x\":1}]"));

        // Failures count up and clear.
        for t in [now, now + 1] {
            c.execute(
                ENRICH_FAILURE_RECORD,
                params![
                    "crowdsec:ip:203.0.113.7",
                    "crowdsec",
                    "ip",
                    "203.0.113.7",
                    t,
                    "503",
                    t + 60_000
                ],
            )
            .unwrap();
        }
        let (n, at, retry): (i64, i64, i64) = c
            .query_row(ENRICH_FAILURES_FOR, params!["ip", "203.0.113.7"], |r| {
                Ok((r.get(3)?, r.get(4)?, r.get(5)?))
            })
            .unwrap();
        assert_eq!((n, at, retry), (2, now + 1, now + 60_001));
        c.execute(ENRICH_FAILURE_CLEAR, params!["crowdsec:ip:203.0.113.7"])
            .unwrap();
        assert!(
            c.query_row(ENRICH_FAILURES_FOR, params!["ip", "203.0.113.7"], |r| r
                .get::<_, i64>(3))
                .optional()
                .unwrap()
                .is_none()
        );
    }
}
