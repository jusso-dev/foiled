//! Cloudflare Worker entry point and the D1 + Postgres store.
//!
//! Only compiled for `wasm32`. Everything that can be tested on the host
//! lives elsewhere: routing in `routes`, SQL in `d1_sql` and `foiled-pg`.

use std::str::FromStr;
use std::sync::Arc;

use foiled_core::agent::JobSigner;
use foiled_core::audit::AuditRecord;
use foiled_core::auth::{Role, parse_scopes};
use foiled_core::capture::CaptureEvent;
use foiled_core::catalogue::DecoyKind;
use foiled_core::decoy::{Decoy, DecoyState};
use foiled_core::sigv4::Credentials;
use serde::Deserialize;
use tower_service::Service;
use worker::send::SendFuture;
use worker::wasm_bindgen::JsValue;
use worker::{
    AnalyticsEngineDataPointBuilder, Cf, Context, D1Database, Env, HttpRequest, Hyperdrive,
    MessageBatch, Queue, event,
};

use crate::auth::ClientCert;
use crate::d1_sql as sql;
use crate::routes::ingest::UploadConfig;
use crate::store::{
    AuditQuery, DecoyQuery, IdentityRecord, IpIocRow, JobRecord, LinkOverride, Store, StoreError,
    StoreFuture, TokenRecord,
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
        ingest: env.queue("INGEST").ok(),
    };
    let mut state = AppState::new(Arc::new(store), Arc::new(now_ms));
    state.uploads = upload_config(&env);
    state.job_signer = job_signer(&env).map(Arc::new);
    Ok(router(state).call(req).await?)
}

fn now_ms() -> i64 {
    worker::Date::now().as_millis() as i64
}

/// Job signing key: a 32-byte Ed25519 seed (hex) as the Worker secret
/// `JOB_SIGNING_KEY`, named by the var `JOB_SIGNING_KEY_ID`.
fn job_signer(env: &Env) -> Option<JobSigner> {
    let seed = env.secret("JOB_SIGNING_KEY").ok()?.to_string();
    let id = env.var("JOB_SIGNING_KEY_ID").ok()?.to_string();
    JobSigner::from_seed_hex(&id, &seed)
}

/// Upload signing needs an R2 S3 API token (Worker secrets) and the
/// endpoint host and bucket (vars). Missing any of them disables uploads.
fn upload_config(env: &Env) -> Option<UploadConfig> {
    let secret = |n: &str| env.secret(n).ok().map(|s| s.to_string());
    let var = |n: &str| env.var(n).ok().map(|s| s.to_string());
    Some(UploadConfig {
        host: var("R2_S3_HOST")?,
        bucket: var("EVIDENCE_BUCKET")?,
        credentials: Credentials {
            access_key_id: secret("R2_ACCESS_KEY_ID")?,
            secret_access_key: secret("R2_SECRET_ACCESS_KEY")?,
        },
        expires_secs: 300,
    })
}

/// Ingest Queue consumer: write envelopes to Postgres, count them in
/// Analytics Engine for the radar (#35). Delivery is at least once; the
/// insert is idempotent on event_id, so a retry after a partial failure is
/// safe.
#[event(queue)]
async fn consume(batch: MessageBatch<CaptureEvent>, env: Env, _ctx: Context) -> worker::Result<()> {
    let events: Vec<CaptureEvent> = batch
        .messages()?
        .into_iter()
        .map(|m| m.into_body())
        .collect();
    let store = CfStore {
        db: env.d1("DB")?,
        hyperdrive: env.hyperdrive("HYPERDRIVE")?,
        ingest: None,
    };
    let client = match store.pg().await {
        Ok(c) => c,
        Err(e) => {
            worker::console_error!("ingest consumer: {e}");
            batch.retry_all();
            return Ok(());
        }
    };
    match foiled_pg::insert_events(&client, &events, now_ms()).await {
        Ok(_) => {
            if let Ok(radar) = env.analytics_engine("RADAR") {
                for e in &events {
                    let point = AnalyticsEngineDataPointBuilder::new()
                        .indexes([e.catalogue_id.as_str()])
                        .add_blob(e.channel.as_str())
                        .add_blob(e.decoy_kind.as_str())
                        .add_blob(e.tenant_id.as_deref().unwrap_or(""))
                        .add_double(1.0)
                        .build();
                    if let Err(err) = radar.write_data_point(&point) {
                        worker::console_error!("radar counter: {err}");
                    }
                }
            }
            batch.ack_all();
        }
        Err(foiled_pg::InsertError::Unstamped(id)) => {
            // Never came through the ingest API. Drop rather than retry forever.
            worker::console_error!("ingest consumer: dropping unstamped event {id}");
            batch.ack_all();
        }
        Err(e) => {
            worker::console_error!("ingest consumer: {e}");
            batch.retry_all();
        }
    }
    Ok(())
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
    ingest: Option<Queue>,
}

/// Queues accept batches of up to 100 messages and 256 KB.
const QUEUE_BATCH_BYTES: usize = 200 * 1024;

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
    params: Option<String>,
    leased_until: Option<f64>,
}

#[derive(Deserialize)]
struct IdRow {
    #[allow(dead_code)]
    id: String,
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
        opt(j.params.as_ref().map(|p| p.to_string()).as_deref()),
        j.leased_until.map(n).unwrap_or(JsValue::NULL),
    ]
}

impl JobRow {
    fn into_record(self) -> JobRecord {
        JobRecord {
            id: self.id,
            tenant_id: self.tenant_id,
            decoy_id: self.decoy_id,
            host_id: self.host_id,
            kind: self.kind,
            reason_code: self.reason_code,
            reason_text: self.reason_text,
            idempotency_key: self.idempotency_key,
            created_at: self.created_at as i64,
            expires_at: self.expires_at as i64,
            status: self.status,
            params: self.params.and_then(|p| serde_json::from_str(&p).ok()),
            leased_until: self.leased_until.map(|v| v as i64),
        }
    }
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
                .prepare(sql::job_by_idempotency_key())
                .bind(&[s(&t), s(&k)])
                .map_err(err)?
                .first(None)
                .await
                .map_err(err)?;
            Ok(row.map(JobRow::into_record))
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

    fn enqueue_events(&self, events: Vec<CaptureEvent>) -> StoreFuture<'_, ()> {
        wrap(async move {
            let queue = self
                .ingest
                .as_ref()
                .ok_or_else(|| StoreError("INGEST queue binding missing".into()))?;
            let mut chunk: Vec<CaptureEvent> = Vec::new();
            let mut bytes = 0;
            for e in events {
                let size = serde_json::to_vec(&e).map(|v| v.len()).unwrap_or(0);
                if !chunk.is_empty() && (bytes + size > QUEUE_BATCH_BYTES || chunk.len() == 100) {
                    queue
                        .send_batch(std::mem::take(&mut chunk))
                        .await
                        .map_err(err)?;
                    bytes = 0;
                }
                bytes += size;
                chunk.push(e);
            }
            if !chunk.is_empty() {
                queue.send_batch(chunk).await.map_err(err)?;
            }
            Ok(())
        })
    }

    fn lease_jobs(
        &self,
        tenant_id: &str,
        host_id: &str,
        now: i64,
        lease_ms: i64,
        limit: usize,
    ) -> StoreFuture<'_, Vec<JobRecord>> {
        let (t, h) = (tenant_id.to_string(), host_id.to_string());
        wrap(async move {
            let mut rows = self
                .db
                .prepare(sql::lease_jobs())
                .bind(&[s(&t), s(&h), n(now), n(lease_ms), n(limit as i64)])
                .map_err(err)?
                .all()
                .await
                .map_err(err)?
                .results::<JobRow>()
                .map_err(err)?;
            self.db
                .prepare(sql::PLACE_DECOYS)
                .bind(&[s(&t), s(&h)])
                .map_err(err)?
                .run()
                .await
                .map_err(err)?;
            rows.sort_by(|a, b| {
                a.created_at
                    .total_cmp(&b.created_at)
                    .then_with(|| a.id.cmp(&b.id))
            });
            Ok(rows.into_iter().map(JobRow::into_record).collect())
        })
    }

    fn finish_job(
        &self,
        tenant_id: &str,
        host_id: &str,
        job_id: &str,
        status: &str,
    ) -> StoreFuture<'_, Option<JobRecord>> {
        let args = [s(tenant_id), s(host_id), s(job_id), s(status)];
        wrap(async move {
            let row: Option<JobRow> = self
                .db
                .prepare(sql::finish_job())
                .bind(&args)
                .map_err(err)?
                .first(None)
                .await
                .map_err(err)?;
            Ok(row.map(JobRow::into_record))
        })
    }

    fn set_decoy_state(
        &self,
        tenant_id: &str,
        decoy_id: &str,
        from: DecoyState,
        to: DecoyState,
        bump_generation: bool,
        now: i64,
    ) -> StoreFuture<'_, bool> {
        let args = [
            s(tenant_id),
            s(decoy_id),
            s(from.as_str()),
            s(to.as_str()),
            n(i64::from(bump_generation)),
            n(now),
        ];
        wrap(async move {
            let row: Option<IdRow> = self
                .db
                .prepare(sql::SET_DECOY_STATE)
                .bind(&args)
                .map_err(err)?
                .first(None)
                .await
                .map_err(err)?;
            Ok(row.is_some())
        })
    }

    fn record_heartbeat(
        &self,
        tenant_id: &str,
        host_id: &str,
        heartbeat: serde_json::Value,
        clock_skew_ms: i64,
        now: i64,
    ) -> StoreFuture<'_, ()> {
        let args = [
            s(tenant_id),
            s(host_id),
            s(&heartbeat.to_string()),
            n(clock_skew_ms),
            n(now),
        ];
        wrap(async move {
            self.db
                .prepare(sql::UPSERT_HEARTBEAT)
                .bind(&args)
                .map_err(err)?
                .run()
                .await
                .map_err(err)?;
            Ok(())
        })
    }

    fn ip_iocs(&self, tenant_id: &str, since: i64) -> StoreFuture<'_, Vec<IpIocRow>> {
        let t = tenant_id.to_string();
        wrap(async move {
            let client = self.pg().await?;
            let rows = foiled_pg::ip_iocs(&client, &t, since).await.map_err(err)?;
            Ok(rows
                .into_iter()
                .map(|r| IpIocRow {
                    ip: r.ip,
                    first_seen: r.first_seen,
                    last_seen: r.last_seen,
                    events: r.events,
                    decoy_ids: r.decoy_ids,
                    catalogue_ids: r.catalogue_ids,
                    hook_cves: r.hook_cves,
                })
                .collect())
        })
    }

    fn events_between(
        &self,
        tenant_id: &str,
        since: i64,
        until: i64,
        limit: usize,
    ) -> StoreFuture<'_, Vec<CaptureEvent>> {
        let t = tenant_id.to_string();
        wrap(async move {
            let client = self.pg().await?;
            foiled_pg::events_between(&client, &t, since, until, limit as i64)
                .await
                .map_err(err)
        })
    }

    fn link_overrides(
        &self,
        tenant_id: &str,
        attempt_id: &str,
    ) -> StoreFuture<'_, Vec<LinkOverride>> {
        let (t, a) = (tenant_id.to_string(), attempt_id.to_string());
        wrap(async move {
            let client = self.pg().await?;
            let rows = foiled_pg::link_overrides(&client, &t, &a)
                .await
                .map_err(err)?;
            Ok(rows
                .into_iter()
                .filter_map(|r| {
                    let kind = serde_json::from_value(serde_json::Value::String(r.kind)).ok()?;
                    let feedback =
                        serde_json::from_value(serde_json::Value::String(r.feedback)).ok()?;
                    Some(LinkOverride {
                        attempt_id: r.attempt_id,
                        kind,
                        target: r.target,
                        decision: foiled_core::confidence::Override {
                            feedback,
                            analyst_id: r.analyst_id,
                            at: r.at,
                            note: r.note,
                        },
                    })
                })
                .collect())
        })
    }

    fn put_link_override(&self, tenant_id: &str, o: LinkOverride) -> StoreFuture<'_, ()> {
        let t = tenant_id.to_string();
        wrap(async move {
            let name = |v: serde_json::Value| v.as_str().map(str::to_string).unwrap_or_default();
            let row = foiled_pg::LinkOverrideRow {
                attempt_id: o.attempt_id,
                kind: name(serde_json::to_value(o.kind).map_err(err)?),
                target: o.target,
                feedback: name(serde_json::to_value(o.decision.feedback).map_err(err)?),
                analyst_id: o.decision.analyst_id,
                at: o.decision.at,
                note: o.decision.note,
            };
            let client = self.pg().await?;
            foiled_pg::put_link_override(&client, &t, &row)
                .await
                .map_err(err)
        })
    }
}
