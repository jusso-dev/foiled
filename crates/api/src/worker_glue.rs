//! Cloudflare Worker entry point and the D1 + Postgres store.
//!
//! Only compiled for `wasm32`. Everything that can be tested on the host
//! lives elsewhere: routing in `routes`, SQL in `d1_sql` and `foiled-pg`.

use std::str::FromStr;
use std::sync::Arc;

use foiled_core::audit::AuditRecord;
use foiled_core::auth::{Role, parse_scopes};
use foiled_core::catalogue::DecoyKind;
use foiled_core::decoy::{Decoy, DecoyState};
use serde::Deserialize;
use tower_service::Service;
use worker::send::SendFuture;
use worker::wasm_bindgen::JsValue;
use worker::{Cf, Context, D1Database, Env, HttpRequest, Hyperdrive, event};

use crate::auth::ClientCert;
use crate::d1_sql as sql;
use crate::store::{
    AuditQuery, DecoyQuery, IdentityRecord, JobRecord, Store, StoreError, StoreFuture, TokenRecord,
};
use crate::{AppState, router};

#[event(fetch)]
async fn fetch(
    mut req: HttpRequest,
    env: Env,
    _ctx: Context,
) -> worker::Result<axum::http::Response<axum::body::Body>> {
    if let Some(cert) = client_cert(&req) {
        req.extensions_mut().insert(cert);
    }
    let store = CfStore {
        db: env.d1("DB")?,
        hyperdrive: env.hyperdrive("HYPERDRIVE")?,
    };
    let state = AppState::new(
        Arc::new(store),
        Arc::new(|| worker::Date::now().as_millis() as i64),
    );
    Ok(router(state).call(req).await?)
}

/// Copy `cf.tlsClientAuth` into a plain extension the router can read.
fn client_cert(req: &HttpRequest) -> Option<ClientCert> {
    let auth = req.extensions().get::<Cf>()?.tls_client_auth()?;
    if auth.cert_presented() != "1" {
        return None;
    }
    Some(ClientCert {
        verified: auth.cert_verified() == "SUCCESS",
        sha256: auth.cert_fingerprint_sha256().to_ascii_lowercase(),
    })
}

struct CfStore {
    db: D1Database,
    hyperdrive: Hyperdrive,
}

fn err(e: impl std::fmt::Display) -> StoreError {
    worker::console_error!("store: {e}");
    StoreError(e.to_string())
}

fn s(v: &str) -> JsValue {
    JsValue::from_str(v)
}

fn opt(v: Option<&str>) -> JsValue {
    v.map(JsValue::from_str).unwrap_or(JsValue::NULL)
}

fn n(v: i64) -> JsValue {
    JsValue::from_f64(v as f64)
}

fn wrap<'a, T: 'a>(
    fut: impl std::future::Future<Output = Result<T, StoreError>> + 'a,
) -> StoreFuture<'a, T> {
    Box::pin(SendFuture::new(fut))
}

#[derive(Deserialize)]
struct TokenRow {
    id: String,
    tenant_id: String,
    role: String,
    scopes: String,
    secret_sha256: String,
    expires_at: Option<f64>,
    revoked: f64,
}

#[derive(Deserialize)]
struct IdentityRow {
    id: String,
    tenant_id: String,
    role: String,
    scopes: String,
    cert_sha256: String,
    revoked: f64,
}

#[derive(Deserialize)]
struct DecoyRow {
    id: String,
    tenant_id: String,
    catalogue_id: String,
    decoy_kind: String,
    label: Option<String>,
    state: String,
    host_id: Option<String>,
    generation: f64,
    created_at: f64,
    updated_at: f64,
    expires_at: f64,
    created_by: String,
}

impl DecoyRow {
    fn into_decoy(self) -> Result<Decoy, StoreError> {
        let decoy_kind = match self.decoy_kind.as_str() {
            "sandbox" => DecoyKind::Sandbox,
            "emulation" => DecoyKind::Emulation,
            other => return Err(StoreError(format!("bad decoy_kind {other}"))),
        };
        Ok(Decoy {
            id: self.id,
            tenant_id: self.tenant_id,
            catalogue_id: self.catalogue_id,
            decoy_kind,
            label: self.label,
            state: DecoyState::parse(&self.state)
                .ok_or_else(|| StoreError(format!("bad state {}", self.state)))?,
            host_id: self.host_id,
            generation: self.generation as u32,
            created_at: self.created_at as i64,
            updated_at: self.updated_at as i64,
            expires_at: self.expires_at as i64,
            created_by: self.created_by,
        })
    }
}

#[derive(Deserialize)]
struct JobRow {
    id: String,
    tenant_id: String,
    decoy_id: String,
    host_id: Option<String>,
    kind: String,
    reason_code: Option<String>,
    reason_text: Option<String>,
    idempotency_key: String,
    created_at: f64,
    expires_at: f64,
    status: String,
}

#[derive(Deserialize)]
struct CountRow {
    #[serde(alias = "n")]
    count: f64,
}

#[derive(Deserialize)]
struct CursorRow {
    created_at: f64,
    id: String,
}

fn role(s: &str) -> Result<Role, StoreError> {
    Role::parse(s).ok_or_else(|| StoreError(format!("bad role {s}")))
}

fn job_args(j: &JobRecord) -> Vec<JsValue> {
    vec![
        s(&j.id),
        s(&j.tenant_id),
        s(&j.decoy_id),
        opt(j.host_id.as_deref()),
        s(&j.kind),
        opt(j.reason_code.as_deref()),
        opt(j.reason_text.as_deref()),
        s(&j.idempotency_key),
        n(j.created_at),
        n(j.expires_at),
        s(&j.status),
    ]
}

impl CfStore {
    async fn pg(&self) -> Result<tokio_postgres::Client, StoreError> {
        let config =
            tokio_postgres::Config::from_str(&self.hyperdrive.connection_string()).map_err(err)?;
        let socket = self.hyperdrive.connect().map_err(err)?;
        let (client, connection) = config
            .connect_raw(socket, worker::postgres_tls::PassthroughTls)
            .await
            .map_err(err)?;
        worker::wasm_bindgen_futures::spawn_local(async move {
            if let Err(e) = connection.await {
                worker::console_error!("postgres connection: {e}");
            }
        });
        Ok(client)
    }
}

impl Store for CfStore {
    fn token(&self, id: &str) -> StoreFuture<'_, Option<TokenRecord>> {
        let id = id.to_string();
        wrap(async move {
            let row: Option<TokenRow> = self
                .db
                .prepare(sql::TOKEN_BY_ID)
                .bind(&[s(&id)])
                .map_err(err)?
                .first(None)
                .await
                .map_err(err)?;
            row.map(|r| {
                Ok(TokenRecord {
                    id: r.id,
                    tenant_id: r.tenant_id,
                    role: role(&r.role)?,
                    scopes: parse_scopes(&r.scopes).map_err(StoreError)?,
                    secret_sha256: r.secret_sha256,
                    expires_at: r.expires_at.map(|v| v as i64),
                    revoked: r.revoked != 0.0,
                })
            })
            .transpose()
        })
    }

    fn identity_by_cert(&self, cert_sha256: &str) -> StoreFuture<'_, Option<IdentityRecord>> {
        let fp = cert_sha256.to_string();
        wrap(async move {
            let row: Option<IdentityRow> = self
                .db
                .prepare(sql::IDENTITY_BY_CERT)
                .bind(&[s(&fp)])
                .map_err(err)?
                .first(None)
                .await
                .map_err(err)?;
            row.map(|r| {
                Ok(IdentityRecord {
                    id: r.id,
                    tenant_id: r.tenant_id,
                    role: role(&r.role)?,
                    scopes: parse_scopes(&r.scopes).map_err(StoreError)?,
                    cert_sha256: r.cert_sha256,
                    revoked: r.revoked != 0.0,
                })
            })
            .transpose()
        })
    }

    fn create_decoy(&self, d: Decoy, job: JobRecord) -> StoreFuture<'_, ()> {
        wrap(async move {
            let insert_decoy = self
                .db
                .prepare(sql::INSERT_DECOY)
                .bind(&[
                    s(&d.id),
                    s(&d.tenant_id),
                    s(&d.catalogue_id),
                    s(d.decoy_kind.as_str()),
                    opt(d.label.as_deref()),
                    s(d.state.as_str()),
                    opt(d.host_id.as_deref()),
                    n(d.generation.into()),
                    n(d.created_at),
                    n(d.updated_at),
                    n(d.expires_at),
                    s(&d.created_by),
                ])
                .map_err(err)?;
            let insert_job = self
                .db
                .prepare(sql::INSERT_JOB)
                .bind(&job_args(&job))
                .map_err(err)?;
            // A D1 batch runs as one transaction.
            self.db
                .batch(vec![insert_decoy, insert_job])
                .await
                .map_err(err)?;
            Ok(())
        })
    }

    fn get_decoy(&self, tenant_id: &str, id: &str) -> StoreFuture<'_, Option<Decoy>> {
        let (t, i) = (tenant_id.to_string(), id.to_string());
        wrap(async move {
            let row: Option<DecoyRow> = self
                .db
                .prepare(sql::decoy_by_id())
                .bind(&[s(&t), s(&i)])
                .map_err(err)?
                .first(None)
                .await
                .map_err(err)?;
            row.map(DecoyRow::into_decoy).transpose()
        })
    }

    fn list_decoys(&self, tenant_id: &str, q: DecoyQuery) -> StoreFuture<'_, Vec<Decoy>> {
        let t = tenant_id.to_string();
        wrap(async move {
            let cursor: Option<CursorRow> = match &q.cursor {
                None => None,
                Some(c) => self
                    .db
                    .prepare(sql::CURSOR_POSITION)
                    .bind(&[s(&t), s(c)])
                    .map_err(err)?
                    .first(None)
                    .await
                    .map_err(err)?,
            };
            let rows = self
                .db
                .prepare(sql::list_decoys())
                .bind(&[
                    s(&t),
                    opt(q.state.map(DecoyState::as_str)),
                    opt(q.catalogue_id.as_deref()),
                    cursor
                        .as_ref()
                        .map(|c| n(c.created_at as i64))
                        .unwrap_or(JsValue::NULL),
                    opt(cursor.as_ref().map(|c| c.id.as_str())),
                    n(q.limit as i64),
                ])
                .map_err(err)?
                .all()
                .await
                .map_err(err)?
                .results::<DecoyRow>()
                .map_err(err)?;
            rows.into_iter().map(DecoyRow::into_decoy).collect()
        })
    }

    fn count_live_decoys(&self, tenant_id: &str) -> StoreFuture<'_, u32> {
        let t = tenant_id.to_string();
        wrap(async move {
            let row: Option<CountRow> = self
                .db
                .prepare(sql::COUNT_LIVE_DECOYS)
                .bind(&[s(&t)])
                .map_err(err)?
                .first(None)
                .await
                .map_err(err)?;
            Ok(row.map(|r| r.count as u32).unwrap_or(0))
        })
    }

    fn insert_job(&self, job: JobRecord) -> StoreFuture<'_, ()> {
        wrap(async move {
            self.db
                .prepare(sql::INSERT_JOB)
                .bind(&job_args(&job))
                .map_err(err)?
                .run()
                .await
                .map_err(err)?;
            Ok(())
        })
    }

    fn job_by_idempotency_key(
        &self,
        tenant_id: &str,
        key: &str,
    ) -> StoreFuture<'_, Option<JobRecord>> {
        let (t, k) = (tenant_id.to_string(), key.to_string());
        wrap(async move {
            let row: Option<JobRow> = self
                .db
                .prepare(sql::JOB_BY_IDEMPOTENCY_KEY)
                .bind(&[s(&t), s(&k)])
                .map_err(err)?
                .first(None)
                .await
                .map_err(err)?;
            Ok(row.map(|r| JobRecord {
                id: r.id,
                tenant_id: r.tenant_id,
                decoy_id: r.decoy_id,
                host_id: r.host_id,
                kind: r.kind,
                reason_code: r.reason_code,
                reason_text: r.reason_text,
                idempotency_key: r.idempotency_key,
                created_at: r.created_at as i64,
                expires_at: r.expires_at as i64,
                status: r.status,
            }))
        })
    }

    fn rate_limit(&self, key: &str, window_start: i64, limit: u32) -> StoreFuture<'_, bool> {
        let k = key.to_string();
        wrap(async move {
            let row: Option<CountRow> = self
                .db
                .prepare(sql::RATE_LIMIT_HIT)
                .bind(&[s(&k), n(window_start)])
                .map_err(err)?
                .first(None)
                .await
                .map_err(err)?;
            Ok(row.is_some_and(|r| r.count as u32 <= limit))
        })
    }

    fn append_audit(&self, record: AuditRecord) -> StoreFuture<'_, ()> {
        wrap(async move {
            let client = self.pg().await?;
            foiled_pg::append_audit(&client, &record).await.map_err(err)
        })
    }

    fn list_audit(&self, tenant_id: &str, q: AuditQuery) -> StoreFuture<'_, Vec<AuditRecord>> {
        let t = tenant_id.to_string();
        wrap(async move {
            let client = self.pg().await?;
            let filter = foiled_pg::AuditFilter {
                action: q.action,
                target: q.target,
                before: q.before,
                limit: q.limit as i64,
            };
            foiled_pg::list_audit(&client, &t, &filter)
                .await
                .map_err(err)
        })
    }
}
