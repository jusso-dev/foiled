//! SQL for the D1 store. Kept apart from the Worker binding code so the
//! statements are tested against SQLite on the host (D1 is SQLite).
//! Parameters are positional (`?1`, `?2`, ...).

/// Every D1 migration, in order. Wrangler applies them in production.
pub const MIGRATIONS: &[&str] = &[
    include_str!("../../../migrations/d1/0001_init.sql"),
    include_str!("../../../migrations/d1/0002_host_jobs.sql"),
];

pub const TOKEN_BY_ID: &str = "SELECT id, tenant_id, role, scopes, secret_sha256, expires_at, revoked \
     FROM api_tokens WHERE id = ?1";

pub const IDENTITY_BY_CERT: &str = "SELECT id, tenant_id, role, scopes, cert_sha256, revoked \
     FROM identities WHERE cert_sha256 = ?1";

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
/// unplaced job. `?1` tenant, `?2` host, `?3` now, `?4` lease ms, `?5` limit.
pub fn lease_jobs() -> String {
    format!(
        "UPDATE jobs SET host_id = ?2, status = 'leased', leased_until = ?3 + ?4 \
         WHERE id IN (SELECT id FROM jobs WHERE tenant_id = ?1 \
             AND (host_id IS NULL OR host_id = ?2) \
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
            .query_map(params!["t1", host, now, 1000, limit], |r| r.get(0))
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
}
