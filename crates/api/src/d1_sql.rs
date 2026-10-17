//! SQL for the D1 store. Kept apart from the Worker binding code so the
//! statements are tested against SQLite on the host (D1 is SQLite).
//! Parameters are positional (`?1`, `?2`, ...).

pub const SCHEMA: &str = include_str!("../../../migrations/d1/0001_init.sql");

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
         ORDER BY created_at DESC, id DESC LIMIT ?6"
    )
}

/// Resolve a list cursor (a decoy id) to its keyset position.
pub const CURSOR_POSITION: &str =
    "SELECT created_at, id FROM decoys WHERE tenant_id = ?1 AND id = ?2";

pub const COUNT_LIVE_DECOYS: &str =
    "SELECT COUNT(*) AS n FROM decoys WHERE tenant_id = ?1 AND state != 'destroyed'";

pub const INSERT_JOB: &str = "INSERT INTO jobs (id, tenant_id, decoy_id, host_id, kind, reason_code, reason_text, \
     idempotency_key, created_at, expires_at, status) \
     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)";

pub const JOB_BY_IDEMPOTENCY_KEY: &str = "SELECT id, tenant_id, decoy_id, host_id, kind, reason_code, reason_text, \
     idempotency_key, created_at, expires_at, status \
     FROM jobs WHERE tenant_id = ?1 AND idempotency_key = ?2";

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
        c.execute_batch(SCHEMA).unwrap();
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
    fn schema_applies_twice() {
        let c = db();
        c.execute_batch(SCHEMA).unwrap();
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
        let all = ids(&list_decoys(), &[&"t1", &none, &none, &none_i, &none, &10]);
        assert_eq!(all, vec!["c", "b", "a"]);
        let healthy = ids(
            &list_decoys(),
            &[&"t1", &Some("healthy"), &none, &none_i, &none, &10],
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
            &[&"t1", &none, &none, &Some(ts), &Some(id), &10],
        );
        assert_eq!(next, vec!["b", "a"]);
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
        assert_eq!(hit(0), 1);
        assert_eq!(hit(0), 2);
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
                    "queued"
                ],
            )
        };
        ins("j1").unwrap();
        assert!(ins("j2").is_err());
        let kind: String = c
            .query_row(JOB_BY_IDEMPOTENCY_KEY, params!["t1", "k1"], |r| r.get(4))
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
}
