//! Cloudflare Worker entry point and the D1 + Postgres store.
//!
//! Only compiled for `wasm32`. Everything that can be tested on the host
//! lives elsewhere: routing in `routes`, SQL in `d1_sql` and `foiled-pg`.

use std::str::FromStr;
use std::sync::Arc;

use foiled_core::agent::JobSigner;
use foiled_core::audit::AuditRecord;
use foiled_core::auth::{Role, agent_scopes, parse_scopes};
use foiled_core::capture::CaptureEvent;
use foiled_core::catalogue::DecoyKind;
use foiled_core::decoy::{Decoy, DecoyState, Reason};
use foiled_core::enrich_pipeline::{EnrichMessage, ProviderFailureRecord};
use foiled_core::enrichment::{AsnTable, CacheEntry, Observable};
use foiled_core::enrolment::{AgentRecord, AgentStatus, SeenFrom};
use foiled_core::sigv4::Credentials;
use serde::Deserialize;
use tower_service::Service;
use worker::MessageExt;
use worker::send::SendFuture;
use worker::wasm_bindgen::JsValue;
use worker::{
    AnalyticsEngineDataPointBuilder, Cf, Context, D1Database, Env, HttpRequest, Hyperdrive,
    MessageBatch, Queue, event,
};

use crate::auth::{ClientCert, ClientMeta};
use crate::d1_sql as sql;
use crate::issuer::{CertIssuer, IssuedCert, IssuerError, IssuerFuture};
use crate::routes::ingest::UploadConfig;
use crate::store::{
    AgentCerts, AgentQuery, AuditQuery, BudgetOutcome, DecoyQuery, EnrolmentTokenRecord,
    IdentityRecord, IpIocRow, JobRecord, LinkOverride, NewCert, Store, StoreError, StoreFuture,
    TokenRecord,
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
    let meta = client_meta(&req);
    req.extensions_mut().insert(meta);
    let store = CfStore {
        db: env.d1("DB")?,
        hyperdrive: env.hyperdrive("HYPERDRIVE")?,
        ingest: env.queue("INGEST").ok(),
    };
    let mut state = AppState::new(Arc::new(store), Arc::new(now_ms));
    state.uploads = upload_config(&env);
    state.job_signer = job_signer(&env).map(Arc::new);
    state.cert_issuer = cloudflare_issuer(&env).map(|i| Arc::new(i) as Arc<dyn CertIssuer>);
    if let Ok(radar) = env.analytics_engine("RADAR") {
        state.radar_sink = Arc::new(AnalyticsSink(radar));
    }
    state.publisher_tenants = Arc::new(tenant_list(&env, "PUBLISHER_TENANTS"));
    state.research_tenants = Arc::new(tenant_list(&env, "RESEARCH_TENANTS"));
    if let Some(p) = zone_purger(&env) {
        state.cache_purger = Arc::new(p);
    }
    Ok(router(state).call(req).await?)
}

/// A comma separated tenant list var: `PUBLISHER_TENANTS` (may publish
/// public pages) or `RESEARCH_TENANTS` (decoys count as research sensors),
/// #35. Unset means none.
fn tenant_list(env: &Env, name: &str) -> Vec<String> {
    env.var(name)
        .map(|v| {
            v.to_string()
                .split(',')
                .map(str::trim)
                .filter(|t| !t.is_empty())
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

/// Purges public page URLs with the zone purge API (#35). Needs the var
/// `PUBLIC_SITE_ORIGIN` (`https://...`), the var `PUBLIC_ZONE_ID` and the
/// secret `CF_CACHE_PURGE_API_TOKEN` (Zone, Cache Purge only).
struct ZonePurger {
    origin: String,
    zone_id: String,
    api_token: String,
}

fn zone_purger(env: &Env) -> Option<ZonePurger> {
    let origin = env.var("PUBLIC_SITE_ORIGIN").ok()?.to_string();
    if !origin.starts_with("https://") {
        return None;
    }
    Some(ZonePurger {
        origin: origin.trim_end_matches('/').to_string(),
        zone_id: env.var("PUBLIC_ZONE_ID").ok()?.to_string(),
        api_token: env.secret("CF_CACHE_PURGE_API_TOKEN").ok()?.to_string(),
    })
}

impl crate::sinks::CachePurger for ZonePurger {
    fn purge(&self, paths: Vec<String>) -> crate::sinks::PurgeFuture<'_> {
        Box::pin(SendFuture::new(async move {
            let files: Vec<String> = paths
                .iter()
                .map(|p| format!("{}{p}", self.origin))
                .collect();
            let body = serde_json::json!({ "files": files }).to_string();
            let we = |e: worker::Error| e.to_string();
            let headers = worker::Headers::new();
            headers
                .set("authorization", &format!("Bearer {}", self.api_token))
                .map_err(we)?;
            headers
                .set("content-type", "application/json")
                .map_err(we)?;
            let mut init = worker::RequestInit::new();
            init.with_method(worker::Method::Post)
                .with_headers(headers)
                .with_body(Some(JsValue::from_str(&body)));
            let url = format!(
                "https://api.cloudflare.com/client/v4/zones/{}/purge_cache",
                self.zone_id
            );
            let req = worker::Request::new_with_init(&url, &init).map_err(we)?;
            let res = worker::Fetch::Request(req).send().await.map_err(we)?;
            let status = res.status_code();
            if (200..300).contains(&status) {
                Ok(())
            } else {
                Err(format!("cache purge failed ({status})"))
            }
        }))
    }
}

/// Radar rollups to the `RADAR` Analytics Engine dataset (#35).
struct AnalyticsSink(worker::AnalyticsEngineDataset);

impl crate::sinks::RadarSink for AnalyticsSink {
    fn write(&self, points: &[foiled_core::radar::AnalyticsPoint]) -> Result<(), String> {
        for p in points {
            let mut b = AnalyticsEngineDataPointBuilder::new().indexes([p.index.as_str()]);
            for blob in &p.blobs {
                b = b.add_blob(blob.as_str());
            }
            for d in &p.doubles {
                b = b.add_double(*d);
            }
            self.0
                .write_data_point(&b.build())
                .map_err(|e| e.to_string())?;
        }
        Ok(())
    }
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

/// Hourly cron (`triggers` in `wrangler.jsonc`): purge the enrichment
/// tables (#16), a bounded batch per run (`enrichment::purge`).
#[event(scheduled)]
async fn purge(_event: worker::ScheduledEvent, env: Env, _ctx: worker::ScheduleContext) {
    let store = match (env.d1("DB"), env.hyperdrive("HYPERDRIVE")) {
        (Ok(db), Ok(hyperdrive)) => CfStore {
            db,
            hyperdrive,
            ingest: None,
        },
        _ => {
            worker::console_error!("purge: D1 or Hyperdrive binding missing");
            return;
        }
    };
    match crate::enrichment::purge(&store, now_ms()).await {
        Ok(c) => worker::console_log!(
            "purge: enrichment expired {}, past retention {}, failures {}",
            c.expired,
            c.past_retention,
            c.failures
        ),
        Err(_) => worker::console_error!("purge: enrichment purge failed; next run retries"),
    }
}

/// Queue consumer for both queues this Worker reads. workers-rs allows one
/// queue handler per Worker, so the batch's queue name decides: the
/// `foiled-enrich` queue (named in `configs/enrichment.yaml`) goes to the
/// enrichment consumer, everything else is capture ingest.
#[event(queue)]
async fn consume(
    batch: MessageBatch<serde_json::Value>,
    env: Env,
    _ctx: Context,
) -> worker::Result<()> {
    let enrich_queue = crate::enrichment::bundled_enrich_config().map(|c| c.queue.as_str());
    if Some(batch.queue().as_str()) == enrich_queue {
        enrich_batch(batch, env).await
    } else {
        ingest_batch(batch, env).await
    }
}

/// Ingest: write envelopes to Postgres, count them in Analytics Engine for
/// the radar (#35), then send their observables to `foiled-enrich` (#11),
/// best effort. Delivery is at least once; the insert is idempotent on
/// event_id, so a retry after a partial failure is safe.
async fn ingest_batch(batch: MessageBatch<serde_json::Value>, env: Env) -> worker::Result<()> {
    let mut events: Vec<CaptureEvent> = Vec::new();
    for m in batch.messages()? {
        match serde_json::from_value::<CaptureEvent>(m.into_body()) {
            Ok(e) => events.push(e),
            // Only the ingest API sends here, so this is a bug; drop it
            // rather than retry forever.
            Err(e) => worker::console_error!("ingest consumer: dropping undecodable message: {e}"),
        }
    }
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
            send_for_enrichment(&env, &events).await;
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

/// Queue messages are at most 128 KB and a batch at most 100 messages.
const ENRICH_SEND_CHUNK: usize = 100;

/// Send the batch's observables (event and IOC observables, attempt
/// sources included) to `foiled-enrich`. Best effort: the events are
/// already stored, so a failed send is logged and the batch still acked.
async fn send_for_enrichment(env: &Env, events: &[CaptureEvent]) {
    if crate::enrichment::bundled_enrich_config().is_none() {
        return;
    }
    let Ok(queue) = env.queue("ENRICH") else {
        return;
    };
    let messages = foiled_core::enrich_pipeline::messages_for_events(events);
    for chunk in messages.chunks(ENRICH_SEND_CHUNK) {
        if let Err(e) = queue.send_batch(chunk.to_vec()).await {
            worker::console_error!("enrich producer: {e}");
            return;
        }
    }
}

/// The `foiled-enrich` consumer (#11): the whole batch at once, so the
/// ThreatSieve lookups are batched (`enrich_consumer::process_batch`), then
/// each message acked or retried on its own.
async fn enrich_batch(batch: MessageBatch<serde_json::Value>, env: Env) -> worker::Result<()> {
    let Some(config) = crate::enrichment::bundled_enrich_config() else {
        worker::console_error!("enrich consumer: configs/enrichment.yaml did not load; acking");
        batch.ack_all();
        return Ok(());
    };
    let store = CfStore {
        db: env.d1("DB")?,
        hyperdrive: env.hyperdrive("HYPERDRIVE")?,
        ingest: None,
    };
    let asn = if config.providers.local_asn.enabled {
        asn_table(&env, &config.providers.local_asn.dataset_key).await
    } else {
        None
    };
    let secret = |name: &str| -> Option<String> { env.secret(name).ok().map(|s| s.to_string()) };
    // No binding: ThreatSieve is reported as not configured, never guessed.
    let threatsieve = if config.providers.threatsieve.enabled {
        env.service(&config.providers.threatsieve.binding)
            .ok()
            .map(|fetcher| ThreatSieveHttp { fetcher })
    } else {
        None
    };
    let messages = batch.messages()?;
    let mut decoded = Vec::with_capacity(messages.len());
    let mut kept = Vec::with_capacity(messages.len());
    for m in messages {
        match serde_json::from_value::<EnrichMessage>(m.body().clone()) {
            Ok(msg) => {
                decoded.push(msg);
                kept.push(m);
            }
            Err(e) => {
                worker::console_error!("enrich consumer: dropping undecodable message: {e}");
                m.ack();
            }
        }
    }
    let deps = crate::enrich_consumer::Deps {
        store: &store,
        threatsieve: threatsieve
            .as_ref()
            .map(|t| t as &dyn crate::enrich_consumer::ProviderHttp),
        secret: &secret,
        asn: asn.as_deref(),
        config,
        now_ms: now_ms(),
    };
    let reports = crate::enrich_consumer::process_batch(&decoded, &deps).await;
    let mut warned = std::collections::BTreeSet::new();
    for (m, (outcome, report)) in kept.iter().zip(reports) {
        for (provider, result) in &report {
            if let crate::enrich_consumer::ProviderResult::Failed(e)
            | crate::enrich_consumer::ProviderResult::NotConfigured(e) = result
            {
                // One line per distinct problem, not one per message.
                if warned.insert((provider.clone(), e.clone())) {
                    worker::console_warn!("enrich {provider}: {e}");
                }
            }
        }
        match outcome {
            crate::enrich_consumer::Outcome::Ack => m.ack(),
            crate::enrich_consumer::Outcome::Drop => {
                worker::console_warn!("enrich consumer: dropped an invalid message");
                m.ack();
            }
            crate::enrich_consumer::Outcome::Retry { delay_secs } => m.retry_with_options(
                &worker::QueueRetryOptionsBuilder::new()
                    .with_delay_seconds(delay_secs)
                    .build(),
            ),
        }
    }
    Ok(())
}

thread_local! {
    /// The operator's ASN table and the R2 ETag it was loaded from, kept
    /// for the life of the isolate.
    static ASN_TABLE: std::cell::RefCell<Option<(String, std::rc::Rc<AsnTable>)>> =
        const { std::cell::RefCell::new(None) };
}

/// The ASN table from the private evidence bucket at `key`, reloaded when
/// the object's ETag changes. `None` when no dataset is uploaded or it does
/// not parse (logged), so `local_asn` is skipped rather than guessed.
async fn asn_table(env: &Env, key: &str) -> Option<std::rc::Rc<AsnTable>> {
    let bucket = env.bucket("EVIDENCE").ok()?;
    let head = match bucket.head(key).await {
        Ok(Some(h)) => h,
        Ok(None) => return None,
        Err(e) => {
            worker::console_error!("asn table: {e}");
            return None;
        }
    };
    let etag = head.etag();
    if let Some(t) = ASN_TABLE.with(|c| {
        c.borrow()
            .as_ref()
            .filter(|(e, _)| *e == etag)
            .map(|(_, t)| t.clone())
    }) {
        return Some(t);
    }
    let text = bucket
        .get(key)
        .execute()
        .await
        .ok()??
        .body()?
        .text()
        .await
        .ok()?;
    match AsnTable::from_csv(&text) {
        Ok(t) => {
            let t = std::rc::Rc::new(t);
            ASN_TABLE.with(|c| *c.borrow_mut() = Some((etag, t.clone())));
            Some(t)
        }
        Err(e) => {
            worker::console_error!("asn table: {e}");
            None
        }
    }
}

/// ThreatSieve over its service binding: the request never leaves
/// Cloudflare. `redirect: manual` (a redirect is an error), a timeout that
/// aborts the subrequest through an `AbortSignal` on the request, and the
/// body capped while it is read.
struct ThreatSieveHttp {
    fetcher: worker::Fetcher,
}

/// Read a response body, failing as soon as it passes `cap` bytes.
async fn read_capped(res: &mut worker::Response, cap: usize) -> Result<Vec<u8>, String> {
    use futures_util::StreamExt;
    if let Some(len) = res
        .headers()
        .get("content-length")
        .ok()
        .flatten()
        .and_then(|l| l.trim().parse::<usize>().ok())
        && len > cap
    {
        return Err("response too large".into());
    }
    let mut stream = res.stream().map_err(|e| format!("read failed: {e}"))?;
    let mut body = Vec::new();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|e| format!("read failed: {e}"))?;
        if body.len() + chunk.len() > cap {
            return Err("response too large".into());
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

impl crate::enrich_consumer::ProviderHttp for ThreatSieveHttp {
    fn send(
        &self,
        req: crate::enrich_consumer::ProviderRequest,
    ) -> crate::enrich_consumer::HttpFuture<'_> {
        use crate::enrich_consumer::SendError;
        Box::pin(async move {
            let fail = |e: String| SendError::Failed(e);
            let headers = worker::Headers::new();
            for (k, v) in &req.headers {
                headers.set(k, v).map_err(|e| fail(e.to_string()))?;
            }
            let mut init = worker::RequestInit::new();
            init.with_method(match req.method {
                foiled_core::enrich_pipeline::HttpMethod::Get => worker::Method::Get,
                foiled_core::enrich_pipeline::HttpMethod::Post => worker::Method::Post,
            })
            .with_headers(headers)
            .with_redirect(worker::RequestRedirect::Manual)
            .with_body(req.body.as_deref().map(JsValue::from_str));
            let request =
                worker::Request::new_with_init(&req.url, &init).map_err(|e| fail(e.to_string()))?;
            // workers-rs has no signal on RequestInit, so the signal is
            // added by re-wrapping the request in a web_sys one.
            let controller = worker::AbortController::default();
            let signal = controller.signal();
            let with_signal = worker::web_sys::RequestInit::new();
            with_signal.set_signal(Some(&signal));
            let request =
                worker::web_sys::Request::new_with_request_and_init(request.inner(), &with_signal)
                    .map(worker::Request::from)
                    .map_err(|e| fail(format!("{e:?}")))?;
            let cap = foiled_core::enrich_pipeline::MAX_RESPONSE_BYTES;
            let mut call = Box::pin(async {
                let res = self
                    .fetcher
                    .fetch_request(request)
                    .await
                    .map_err(|e| format!("fetch failed: {e}"))?;
                let mut res =
                    worker::Response::try_from(res).map_err(|e| format!("bad answer: {e}"))?;
                let status = res.status_code();
                let retry_after = res.headers().get("retry-after").ok().flatten();
                let bytes = read_capped(&mut res, cap).await?;
                Ok::<_, String>((status, retry_after, bytes))
            });
            let mut timer = Box::pin(worker::Delay::from(std::time::Duration::from_millis(
                u64::from(foiled_core::enrich_pipeline::FETCH_TIMEOUT_MS),
            )));
            let raced = std::future::poll_fn(|cx| {
                use std::future::Future;
                if let std::task::Poll::Ready(r) = call.as_mut().poll(cx) {
                    return std::task::Poll::Ready(Some(r));
                }
                if timer.as_mut().poll(cx).is_ready() {
                    return std::task::Poll::Ready(None);
                }
                std::task::Poll::Pending
            })
            .await;
            let Some(result) = raced else {
                // Cancel the subrequest rather than leave it running.
                drop(call);
                controller.abort();
                return Err(SendError::TimedOut);
            };
            let (status, retry_after, bytes) = result.map_err(fail)?;
            Ok(crate::enrich_consumer::HttpReply {
                status,
                body: String::from_utf8_lossy(&bytes).into_owned(),
                retry_after,
            })
        })
    }
}

/// Where the request came from. `CF-Connecting-IP` is set by Cloudflare's
/// edge and cannot be supplied by the client on a proxied hostname.
fn client_meta(req: &HttpRequest) -> ClientMeta {
    ClientMeta {
        ip: req
            .headers()
            .get("cf-connecting-ip")
            .and_then(|v| v.to_str().ok())
            .filter(|v| v.parse::<std::net::IpAddr>().is_ok())
            .map(str::to_string),
        asn: req.extensions().get::<Cf>().and_then(|cf| cf.asn()),
    }
}

/// Client certificate issuance through the Cloudflare-managed CA (#31).
/// Needs the Worker secret `CF_CLIENT_CERT_API_TOKEN` (a token with only
/// "SSL and Certificates: Edit" on the ingest zone) and the var
/// `CF_ZONE_ID`. Missing either disables enrolment and renewal.
struct CloudflareIssuer {
    zone_id: String,
    api_token: String,
}

fn cloudflare_issuer(env: &Env) -> Option<CloudflareIssuer> {
    Some(CloudflareIssuer {
        zone_id: env.var("CF_ZONE_ID").ok()?.to_string(),
        api_token: env.secret("CF_CLIENT_CERT_API_TOKEN").ok()?.to_string(),
    })
}

#[derive(Deserialize)]
struct CfEnvelope<T> {
    success: bool,
    result: Option<T>,
}

#[derive(Deserialize)]
struct CfClientCert {
    id: String,
    certificate: String,
}

impl CloudflareIssuer {
    async fn call(
        &self,
        method: worker::Method,
        path: &str,
        body: Option<String>,
    ) -> Result<worker::Response, IssuerError> {
        let ie = |e: worker::Error| IssuerError(e.to_string());
        let headers = worker::Headers::new();
        headers
            .set("authorization", &format!("Bearer {}", self.api_token))
            .map_err(ie)?;
        headers
            .set("content-type", "application/json")
            .map_err(ie)?;
        let mut init = worker::RequestInit::new();
        init.with_method(method)
            .with_headers(headers)
            .with_body(body.map(|b| JsValue::from_str(&b)));
        let url = format!(
            "https://api.cloudflare.com/client/v4/zones/{}/client_certificates{path}",
            self.zone_id
        );
        let req = worker::Request::new_with_init(&url, &init).map_err(ie)?;
        worker::Fetch::Request(req).send().await.map_err(ie)
    }
}

impl CertIssuer for CloudflareIssuer {
    fn issue(&self, csr_pem: &str, validity_days: u32) -> IssuerFuture<'_, IssuedCert> {
        let body = serde_json::json!({"csr": csr_pem, "validity_days": validity_days}).to_string();
        Box::pin(SendFuture::new(async move {
            let mut res = self.call(worker::Method::Post, "", Some(body)).await?;
            let status = res.status_code();
            let env: CfEnvelope<CfClientCert> =
                res.json().await.map_err(|e| IssuerError(e.to_string()))?;
            match env.result {
                Some(c) if env.success && (200..300).contains(&status) => Ok(IssuedCert {
                    certificate_pem: c.certificate,
                    issuer_ref: Some(c.id),
                }),
                // The response body can echo the CSR; log the status only.
                _ => Err(IssuerError(format!(
                    "client certificate create failed ({status})"
                ))),
            }
        }))
    }

    fn revoke(&self, issuer_ref: &str) -> IssuerFuture<'_, ()> {
        // DELETE revokes a Cloudflare-managed client certificate; it stays
        // listed as revoked and the WAF rule's `cert_revoked` check fires.
        let path = format!("/{issuer_ref}");
        Box::pin(SendFuture::new(async move {
            let res = self.call(worker::Method::Delete, &path, None).await?;
            let status = res.status_code();
            if (200..300).contains(&status) {
                Ok(())
            } else {
                Err(IssuerError(format!(
                    "client certificate revoke failed ({status})"
                )))
            }
        }))
    }
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

/// One `enrich_failures` row.
#[derive(Deserialize)]
struct FailureRow {
    provider: String,
    kind: String,
    value: String,
    failures: f64,
    last_failed_at: f64,
    retry_at: Option<f64>,
}

/// One `RETURNING used` row from a budget take.
#[derive(Deserialize)]
struct UsedRow {
    #[allow(dead_code)]
    used: f64,
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

/// One `enrich_cache` row. D1 returns integers as JavaScript numbers.
#[derive(Deserialize)]
struct EnrichRow {
    provider: String,
    kind: String,
    value: String,
    fetched_at: f64,
    ttl_secs: f64,
    facts: String,
    tenant_id: Option<String>,
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
    valid_until: Option<f64>,
    expires_at: Option<f64>,
}

#[derive(Deserialize)]
struct AgentRow {
    id: String,
    tenant_id: String,
    role: String,
    label: Option<String>,
    status: String,
    sandbox_allowed: f64,
    share_opt_in: Option<f64>,
    created_at: f64,
    created_by: String,
    enrolled_at: Option<f64>,
    cert_sha256: Option<String>,
    cert_expires_at: Option<f64>,
    last_seen_at: Option<f64>,
    last_ip: Option<String>,
    last_asn: Option<f64>,
    network_changed_at: Option<f64>,
    revoked_at: Option<f64>,
    revoke_reason_code: Option<String>,
    revoke_reason_text: Option<String>,
}

impl AgentRow {
    fn into_record(self) -> Result<AgentRecord, StoreError> {
        let ms = |v: Option<f64>| v.map(|x| x as i64);
        let revoke_reason = match (self.revoke_reason_code, self.revoke_reason_text) {
            (Some(code), Some(text)) => Some(Reason {
                code: serde_json::from_value(serde_json::Value::String(code)).map_err(err)?,
                text,
            }),
            _ => None,
        };
        Ok(AgentRecord {
            id: self.id,
            tenant_id: self.tenant_id,
            role: role(&self.role)?,
            label: self.label,
            status: AgentStatus::parse(&self.status)
                .ok_or_else(|| StoreError(format!("bad agent status {}", self.status)))?,
            sandbox_allowed: self.sandbox_allowed != 0.0,
            share_opt_in: self.share_opt_in.map(|v| v != 0.0),
            created_at: self.created_at as i64,
            created_by: self.created_by,
            enrolled_at: ms(self.enrolled_at),
            cert_sha256: self.cert_sha256,
            cert_expires_at: ms(self.cert_expires_at),
            last_seen_at: ms(self.last_seen_at),
            last_ip: self.last_ip,
            last_asn: self.last_asn.map(|v| v as u32),
            network_changed_at: ms(self.network_changed_at),
            revoked_at: ms(self.revoked_at),
            revoke_reason,
        })
    }
}

#[derive(Deserialize)]
struct TokenRowE {
    id: String,
    tenant_id: String,
    agent_id: String,
    role: String,
    secret_sha256: String,
    created_at: f64,
    expires_at: f64,
    created_by: String,
    used_at: Option<f64>,
}

#[derive(Deserialize)]
struct AgentCertRow {
    cert_sha256: String,
    issuer_ref: Option<String>,
}

#[derive(Deserialize)]
struct AgentCursorRow {
    created_at: f64,
    id: String,
}

fn opt_n(v: Option<i64>) -> JsValue {
    v.map(n).unwrap_or(JsValue::NULL)
}

fn token_args(t: &EnrolmentTokenRecord) -> Vec<JsValue> {
    vec![
        s(&t.id),
        s(&t.tenant_id),
        s(&t.agent_id),
        s(t.role.as_str()),
        s(&t.secret_sha256),
        n(t.created_at),
        n(t.expires_at),
        s(&t.created_by),
        opt_n(t.used_at),
    ]
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

/// Scopes from a stored row. A name the code no longer knows (for example
/// one retired by a migration) makes the credential unusable: the caller
/// gets a clean 401, the operator a log line, and nobody a 5xx.
fn stored_scopes(kind: &str, id: &str, raw: &str) -> Option<Vec<foiled_core::auth::Scope>> {
    match parse_scopes(raw) {
        Ok(v) => Some(v),
        Err(e) => {
            worker::console_error!("{kind} {id} refused: {e}");
            None
        }
    }
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
            let Some(r) = row else { return Ok(None) };
            let Some(scopes) = stored_scopes("token", &r.id, &r.scopes) else {
                return Ok(None);
            };
            Ok(Some(TokenRecord {
                id: r.id,
                tenant_id: r.tenant_id,
                role: role(&r.role)?,
                scopes,
                secret_sha256: r.secret_sha256,
                expires_at: r.expires_at.map(|v| v as i64),
                revoked: r.revoked != 0.0,
            }))
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
            let Some(r) = row else { return Ok(None) };
            let Some(scopes) = stored_scopes("identity", &r.id, &r.scopes) else {
                return Ok(None);
            };
            Ok(Some(IdentityRecord {
                id: r.id,
                tenant_id: r.tenant_id,
                role: role(&r.role)?,
                scopes,
                cert_sha256: r.cert_sha256,
                revoked: r.revoked != 0.0,
                valid_until: r.valid_until.map(|v| v as i64),
                expires_at: r.expires_at.map(|v| v as i64),
            }))
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
                    opt(q.created_by.as_deref()),
                    n(i64::from(q.live)),
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

    fn rate_count(&self, key: &str, window_start: i64) -> StoreFuture<'_, u32> {
        let k = key.to_string();
        wrap(async move {
            let row: Option<CountRow> = self
                .db
                .prepare(sql::RATE_COUNT)
                .bind(&[s(&k), n(window_start)])
                .map_err(err)?
                .first(None)
                .await
                .map_err(err)?;
            Ok(row.map(|r| r.count as u32).unwrap_or(0))
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
        take_unplaced: bool,
    ) -> StoreFuture<'_, Vec<JobRecord>> {
        let (t, h) = (tenant_id.to_string(), host_id.to_string());
        wrap(async move {
            let mut rows = self
                .db
                .prepare(sql::lease_jobs())
                .bind(&[
                    s(&t),
                    s(&h),
                    n(now),
                    n(lease_ms),
                    n(limit as i64),
                    n(i64::from(take_unplaced)),
                ])
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

    fn enrichment_cache(
        &self,
        observables: Vec<Observable>,
        now_ms: i64,
        max_statements: usize,
        tenant_id: Option<String>,
    ) -> StoreFuture<'_, Vec<CacheEntry>> {
        wrap(async move {
            // One D1 batch: one statement per kind and chunk of values, each
            // under the bound parameter limit, within the statement budget
            // (d1_sql::enrich_lookup_plan).
            let plan = sql::enrich_lookup_plan(&observables, max_statements);
            if plan.is_empty() {
                return Ok(Vec::new());
            }
            let mut statements = Vec::with_capacity(plan.len());
            for (kind, values) in &plan {
                let mut args = Vec::with_capacity(values.len() + 3);
                args.push(s(kind));
                args.push(n(now_ms));
                // A NULL tenant matches only shared rows.
                args.push(opt(tenant_id.as_deref()));
                args.extend(values.iter().map(|v| s(v)));
                statements.push(
                    self.db
                        .prepare(sql::enrich_cache_lookup(values.len()))
                        .bind(&args)
                        .map_err(err)?,
                );
            }
            let mut out = Vec::new();
            for result in self.db.batch(statements).await.map_err(err)? {
                for row in result.results::<EnrichRow>().map_err(err)? {
                    // A row that does not parse is skipped, never trusted.
                    match CacheEntry::from_row(
                        &row.provider,
                        &row.kind,
                        &row.value,
                        row.fetched_at as i64,
                        row.ttl_secs as i64,
                        &row.facts,
                        row.tenant_id.as_deref(),
                    ) {
                        Some(e) => out.push(e),
                        None => worker::console_warn!(
                            "store: skipped unreadable enrich_cache row for {}",
                            row.provider
                        ),
                    }
                }
            }
            Ok(out)
        })
    }

    fn upsert_enrich_cache(&self, entry: CacheEntry) -> StoreFuture<'_, ()> {
        wrap(async move {
            let facts = serde_json::to_string(&entry.facts).map_err(err)?;
            self.db
                .prepare(sql::ENRICH_CACHE_UPSERT)
                .bind(&[
                    s(&entry.key()),
                    s(&entry.provider),
                    s(entry.observable.kind.as_str()),
                    s(&entry.observable.value),
                    n(entry.fetched_at),
                    n(i64::try_from(entry.ttl_secs).unwrap_or(i64::MAX)),
                    s(&facts),
                    opt(entry.tenant_id.as_deref()),
                ])
                .map_err(err)?
                .run()
                .await
                .map_err(err)?;
            Ok(())
        })
    }

    fn take_enrich_budget(
        &self,
        provider: &str,
        now_ms: i64,
        per_minute: u32,
        per_day: u32,
    ) -> StoreFuture<'_, BudgetOutcome> {
        let p = provider.to_string();
        wrap(async move {
            let (minute, day) = sql::budget_windows(now_ms);
            let take = |window: &'static str, start: i64, limit: u32| {
                self.db.prepare(sql::ENRICH_BUDGET_TAKE).bind(&[
                    s(&p),
                    s(window),
                    n(start),
                    n(i64::from(limit.max(1))),
                ])
            };
            let got: Option<UsedRow> = take("minute", minute, per_minute)
                .map_err(err)?
                .first(None)
                .await
                .map_err(err)?;
            if got.is_none() {
                return Ok(BudgetOutcome::MinuteSpent);
            }
            let got: Option<UsedRow> = take("day", day, per_day)
                .map_err(err)?
                .first(None)
                .await
                .map_err(err)?;
            if got.is_none() {
                self.db
                    .prepare(sql::ENRICH_BUDGET_REFUND)
                    .bind(&[s(&p), s("minute"), n(minute)])
                    .map_err(err)?
                    .run()
                    .await
                    .map_err(err)?;
                return Ok(BudgetOutcome::DaySpent);
            }
            // Counters older than yesterday are no use to anyone.
            self.db
                .prepare(sql::ENRICH_BUDGET_PRUNE)
                .bind(&[s(&p), n(day - 86_400_000)])
                .map_err(err)?
                .run()
                .await
                .map_err(err)?;
            Ok(BudgetOutcome::Taken)
        })
    }

    fn enrich_failures(
        &self,
        observable: Observable,
    ) -> StoreFuture<'_, Vec<ProviderFailureRecord>> {
        wrap(async move {
            let rows = self
                .db
                .prepare(sql::ENRICH_FAILURES_FOR)
                .bind(&[s(observable.kind.as_str()), s(&observable.value)])
                .map_err(err)?
                .all()
                .await
                .map_err(err)?
                .results::<FailureRow>()
                .map_err(err)?;
            Ok(rows
                .into_iter()
                .filter(|r| r.kind == observable.kind.as_str() && r.value == observable.value)
                .map(|r| ProviderFailureRecord {
                    provider: r.provider,
                    observable: observable.clone(),
                    failures: r.failures.max(1.0) as u32,
                    last_failed_at: r.last_failed_at as i64,
                    retry_at: r.retry_at.map(|v| v as i64),
                })
                .collect())
        })
    }

    fn record_enrich_failure(
        &self,
        provider: &str,
        observable: Observable,
        now_ms: i64,
        error: String,
        retry_at: Option<i64>,
    ) -> StoreFuture<'_, ()> {
        let p = provider.to_string();
        wrap(async move {
            self.db
                .prepare(sql::ENRICH_FAILURE_RECORD)
                .bind(&[
                    s(&observable.cache_key(&p)),
                    s(&p),
                    s(observable.kind.as_str()),
                    s(&observable.value),
                    n(now_ms),
                    s(&error),
                    opt_n(retry_at),
                ])
                .map_err(err)?
                .run()
                .await
                .map_err(err)?;
            Ok(())
        })
    }

    fn clear_enrich_failure(&self, provider: &str, observable: Observable) -> StoreFuture<'_, ()> {
        let key = observable.cache_key(provider);
        wrap(async move {
            self.db
                .prepare(sql::ENRICH_FAILURE_CLEAR)
                .bind(&[s(&key)])
                .map_err(err)?
                .run()
                .await
                .map_err(err)?;
            Ok(())
        })
    }

    fn purge_enrichment(
        &self,
        plan: foiled_core::enrich_pipeline::EnrichPurgePlan,
    ) -> StoreFuture<'_, foiled_core::enrich_pipeline::EnrichPurgeCounts> {
        wrap(async move {
            // Rows deleted by one statement, from D1's result metadata.
            let run = |stmt: &str, args: Vec<JsValue>| {
                let stmt = stmt.to_string();
                async move {
                    let result = self
                        .db
                        .prepare(&stmt)
                        .bind(&args)
                        .map_err(err)?
                        .run()
                        .await
                        .map_err(err)?;
                    Ok::<u64, StoreError>(
                        result
                            .meta()
                            .ok()
                            .flatten()
                            .and_then(|m| m.changes)
                            .unwrap_or(0) as u64,
                    )
                }
            };
            let batch = n(i64::from(plan.batch));
            let mut counts = foiled_core::enrich_pipeline::EnrichPurgeCounts {
                expired: run(
                    sql::ENRICH_PURGE_EXPIRED,
                    vec![n(plan.now_ms), batch.clone()],
                )
                .await?,
                ..Default::default()
            };
            if let Some(r) = &plan.retention {
                for (provider, before) in &r.providers {
                    counts.past_retention += run(
                        sql::ENRICH_PURGE_PROVIDER,
                        vec![s(provider), n(*before), batch.clone()],
                    )
                    .await?;
                }
                let mut args = vec![n(r.default_before), batch.clone()];
                args.extend(r.providers.iter().map(|(p, _)| s(p)));
                counts.past_retention +=
                    run(&sql::enrich_purge_default(r.providers.len()), args).await?;
            }
            counts.failures = run(
                sql::ENRICH_PURGE_FAILURES,
                vec![n(plan.failures_before), n(plan.now_ms), batch],
            )
            .await?;
            Ok(counts)
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

    fn events_after(
        &self,
        tenant_id: &str,
        after: (i64, String),
        until: i64,
        limit: usize,
    ) -> StoreFuture<'_, Vec<CaptureEvent>> {
        let t = tenant_id.to_string();
        wrap(async move {
            let client = self.pg().await?;
            foiled_pg::events_after(&client, &t, after.0, &after.1, until, limit as i64)
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
            Ok(rows.into_iter().filter_map(override_from_row).collect())
        })
    }

    fn link_overrides_many(
        &self,
        tenant_id: &str,
        attempt_ids: Vec<String>,
    ) -> StoreFuture<'_, Vec<LinkOverride>> {
        let t = tenant_id.to_string();
        wrap(async move {
            if attempt_ids.is_empty() {
                return Ok(Vec::new());
            }
            let client = self.pg().await?;
            let rows = foiled_pg::link_overrides_many(&client, &t, &attempt_ids)
                .await
                .map_err(err)?;
            Ok(rows.into_iter().filter_map(override_from_row).collect())
        })
    }

    fn campaign_actions(
        &self,
        tenant_id: &str,
        feedback_limit: usize,
    ) -> StoreFuture<'_, Vec<foiled_core::campaign::CampaignAction>> {
        let t = tenant_id.to_string();
        wrap(async move {
            let client = self.pg().await?;
            foiled_pg::campaign_actions(&client, &t, feedback_limit as i64)
                .await
                .map_err(err)
        })
    }

    fn campaign_memberships(
        &self,
        tenant_id: &str,
        attempt_ids: Vec<String>,
    ) -> StoreFuture<'_, Vec<(String, String)>> {
        let t = tenant_id.to_string();
        wrap(async move {
            let client = self.pg().await?;
            foiled_pg::campaign_memberships(&client, &t, &attempt_ids)
                .await
                .map_err(err)
        })
    }

    fn campaign_records(
        &self,
        tenant_id: &str,
        campaign_ids: Vec<String>,
    ) -> StoreFuture<'_, Vec<foiled_core::campaign::StoredCampaign>> {
        let t = tenant_id.to_string();
        wrap(async move {
            let client = self.pg().await?;
            foiled_pg::campaign_records(&client, &t, &campaign_ids)
                .await
                .map_err(err)
        })
    }

    fn campaign_bridges(
        &self,
        tenant_id: &str,
        campaign_id: &str,
    ) -> StoreFuture<'_, Vec<foiled_core::campaign::BridgeRecord>> {
        let (t, c) = (tenant_id.to_string(), campaign_id.to_string());
        wrap(async move {
            let client = self.pg().await?;
            foiled_pg::campaign_bridges(&client, &t, &c)
                .await
                .map_err(err)
        })
    }

    fn update_campaign_registry(
        &self,
        tenant_id: &str,
        update: foiled_core::campaign::RegistryUpdate,
        now: i64,
    ) -> StoreFuture<'_, ()> {
        let t = tenant_id.to_string();
        wrap(async move {
            let client = self.pg().await?;
            foiled_pg::update_campaign_registry(&client, &t, &update, now)
                .await
                .map_err(err)
        })
    }

    fn append_campaign_action(
        &self,
        tenant_id: &str,
        action: foiled_core::campaign::CampaignAction,
    ) -> StoreFuture<'_, ()> {
        let t = tenant_id.to_string();
        wrap(async move {
            let client = self.pg().await?;
            foiled_pg::append_campaign_action(&client, &t, &action)
                .await
                .map_err(err)
        })
    }

    fn actor_decisions(
        &self,
        tenant_id: &str,
        subject_ids: Vec<String>,
    ) -> StoreFuture<'_, Vec<foiled_core::actor::ActorDecision>> {
        let t = tenant_id.to_string();
        wrap(async move {
            if subject_ids.is_empty() {
                return Ok(Vec::new());
            }
            let client = self.pg().await?;
            let rows = foiled_pg::actor_decisions(&client, &t, &subject_ids)
                .await
                .map_err(err)?;
            Ok(rows
                .into_iter()
                .filter_map(|r| {
                    let feedback =
                        serde_json::from_value(serde_json::Value::String(r.feedback)).ok()?;
                    Some(foiled_core::actor::ActorDecision {
                        subject_id: r.subject_id,
                        actor_id: r.actor_id,
                        decision: foiled_core::confidence::Override {
                            feedback,
                            analyst_id: r.analyst_id,
                            at: r.at,
                            note: r.note,
                        },
                        attempt_ids: r.attempt_ids,
                    })
                })
                .collect())
        })
    }

    fn put_actor_decision(
        &self,
        tenant_id: &str,
        d: foiled_core::actor::ActorDecision,
    ) -> StoreFuture<'_, ()> {
        let t = tenant_id.to_string();
        wrap(async move {
            let feedback = serde_json::to_value(d.decision.feedback)
                .map_err(err)?
                .as_str()
                .map(str::to_string)
                .unwrap_or_default();
            let row = foiled_pg::ActorDecisionRow {
                subject_id: d.subject_id,
                actor_id: d.actor_id,
                feedback,
                analyst_id: d.decision.analyst_id,
                at: d.decision.at,
                note: d.decision.note,
                attempt_ids: d.attempt_ids,
            };
            let client = self.pg().await?;
            foiled_pg::put_actor_decision(&client, &t, &row)
                .await
                .map_err(err)
        })
    }

    fn review_states(
        &self,
        tenant_id: &str,
        item_ids: Vec<String>,
    ) -> StoreFuture<'_, Vec<foiled_core::review::ReviewState>> {
        let t = tenant_id.to_string();
        wrap(async move {
            let client = self.pg().await?;
            foiled_pg::review_states(&client, &t, &item_ids)
                .await
                .map_err(err)
        })
    }

    fn put_review_state(
        &self,
        tenant_id: &str,
        state: foiled_core::review::ReviewState,
        expected: u32,
    ) -> StoreFuture<'_, bool> {
        let t = tenant_id.to_string();
        wrap(async move {
            let client = self.pg().await?;
            foiled_pg::put_review_state(&client, &t, &state, expected)
                .await
                .map_err(err)
        })
    }

    fn insert_writeup(
        &self,
        w: foiled_core::writeup::WriteUp,
        actor_id: &str,
    ) -> StoreFuture<'_, ()> {
        let actor = actor_id.to_string();
        wrap(async move {
            let client = self.pg().await?;
            foiled_pg::insert_writeup(&client, &w, &actor)
                .await
                .map_err(err)
        })
    }

    fn get_writeup(
        &self,
        tenant_id: &str,
        writeup_id: &str,
    ) -> StoreFuture<'_, Option<foiled_core::writeup::WriteUp>> {
        let (t, id) = (tenant_id.to_string(), writeup_id.to_string());
        wrap(async move {
            let client = self.pg().await?;
            foiled_pg::get_writeup(&client, &t, &id).await.map_err(err)
        })
    }

    fn list_writeups(
        &self,
        tenant_id: &str,
        status: Option<foiled_core::writeup::WriteUpStatus>,
        limit: usize,
    ) -> StoreFuture<'_, Vec<foiled_core::writeup::WriteUp>> {
        let t = tenant_id.to_string();
        wrap(async move {
            let client = self.pg().await?;
            foiled_pg::list_writeups(&client, &t, status.map(|s| s.as_str()), limit as i64)
                .await
                .map_err(err)
        })
    }

    fn update_writeup(
        &self,
        w: foiled_core::writeup::WriteUp,
        expected: u32,
        action: &str,
        actor_id: &str,
    ) -> StoreFuture<'_, bool> {
        let (action, actor) = (action.to_string(), actor_id.to_string());
        wrap(async move {
            let client = self.pg().await?;
            foiled_pg::update_writeup(&client, &w, expected, &action, &actor)
                .await
                .map_err(err)
        })
    }

    fn writeup_versions(
        &self,
        tenant_id: &str,
        writeup_id: &str,
    ) -> StoreFuture<'_, Vec<crate::store::WriteUpVersion>> {
        let (t, id) = (tenant_id.to_string(), writeup_id.to_string());
        wrap(async move {
            let client = self.pg().await?;
            let rows = foiled_pg::writeup_versions(&client, &t, &id)
                .await
                .map_err(err)?;
            Ok(rows
                .into_iter()
                .map(|r| crate::store::WriteUpVersion {
                    writeup: r.writeup,
                    action: r.action,
                    actor_id: r.actor_id,
                    at: r.at,
                })
                .collect())
        })
    }

    fn put_public_page(
        &self,
        tenant_id: &str,
        writeup_id: &str,
        page: foiled_core::writeup::PublicPage,
    ) -> StoreFuture<'_, bool> {
        let (t, id) = (tenant_id.to_string(), writeup_id.to_string());
        wrap(async move {
            let client = self.pg().await?;
            foiled_pg::put_public_page(&client, &t, &id, &page)
                .await
                .map_err(err)
        })
    }

    fn remove_public_page(&self, tenant_id: &str, writeup_id: &str) -> StoreFuture<'_, ()> {
        let (t, id) = (tenant_id.to_string(), writeup_id.to_string());
        wrap(async move {
            let client = self.pg().await?;
            foiled_pg::remove_public_page(&client, &t, &id)
                .await
                .map_err(err)
        })
    }

    fn public_page(
        &self,
        slug: &str,
        now: i64,
    ) -> StoreFuture<'_, Option<foiled_core::writeup::PublicPage>> {
        let slug = slug.to_string();
        wrap(async move {
            let client = self.pg().await?;
            foiled_pg::public_page(&client, &slug, now)
                .await
                .map_err(err)
        })
    }

    fn public_pages(
        &self,
        now: i64,
        limit: usize,
    ) -> StoreFuture<'_, Vec<foiled_core::writeup::PublicPageSummary>> {
        wrap(async move {
            let client = self.pg().await?;
            let pages = foiled_pg::public_pages(&client, now, limit as i64)
                .await
                .map_err(err)?;
            Ok(pages.iter().map(|p| p.summary_row()).collect())
        })
    }

    fn put_radar_points(
        &self,
        tenant_id: &str,
        day: i64,
        points: Vec<foiled_core::radar::RadarPoint>,
    ) -> StoreFuture<'_, ()> {
        let t = tenant_id.to_string();
        wrap(async move {
            let client = self.pg().await?;
            foiled_pg::put_radar_points(&client, &t, day, &points)
                .await
                .map_err(err)
        })
    }

    fn radar_points(
        &self,
        tenant_id: Option<&str>,
        since: i64,
        until: i64,
        limit: usize,
    ) -> StoreFuture<'_, Vec<foiled_core::radar::RadarPoint>> {
        let t = tenant_id.map(str::to_string);
        wrap(async move {
            let client = self.pg().await?;
            foiled_pg::radar_points(&client, t.as_deref(), since, until, limit as i64)
                .await
                .map_err(err)
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

    fn create_agent(&self, a: AgentRecord, token: EnrolmentTokenRecord) -> StoreFuture<'_, ()> {
        wrap(async move {
            let insert_agent = self
                .db
                .prepare(sql::INSERT_AGENT)
                .bind(&[
                    s(&a.id),
                    s(&a.tenant_id),
                    s(a.role.as_str()),
                    opt(a.label.as_deref()),
                    s(a.status.as_str()),
                    n(i64::from(a.sandbox_allowed)),
                    opt_n(a.share_opt_in.map(i64::from)),
                    n(a.created_at),
                    s(&a.created_by),
                    opt_n(a.enrolled_at),
                    opt(a.cert_sha256.as_deref()),
                    opt_n(a.cert_expires_at),
                    opt_n(a.last_seen_at),
                    opt(a.last_ip.as_deref()),
                    opt_n(a.last_asn.map(i64::from)),
                    opt_n(a.network_changed_at),
                    opt_n(a.revoked_at),
                    JsValue::NULL,
                    JsValue::NULL,
                ])
                .map_err(err)?;
            let insert_token = self
                .db
                .prepare(sql::INSERT_ENROLMENT_TOKEN)
                .bind(&token_args(&token))
                .map_err(err)?;
            self.db
                .batch(vec![insert_agent, insert_token])
                .await
                .map_err(err)?;
            Ok(())
        })
    }

    fn get_agent(
        &self,
        tenant_id: &str,
        role: Role,
        id: &str,
    ) -> StoreFuture<'_, Option<AgentRecord>> {
        let args = [s(tenant_id), s(role.as_str()), s(id)];
        wrap(async move {
            let row: Option<AgentRow> = self
                .db
                .prepare(sql::agent_by_id())
                .bind(&args)
                .map_err(err)?
                .first(None)
                .await
                .map_err(err)?;
            row.map(AgentRow::into_record).transpose()
        })
    }

    fn list_agents(
        &self,
        tenant_id: &str,
        role: Role,
        q: AgentQuery,
    ) -> StoreFuture<'_, Vec<AgentRecord>> {
        let (t, r) = (tenant_id.to_string(), role.as_str());
        wrap(async move {
            let cursor: Option<AgentCursorRow> = match &q.cursor {
                None => None,
                Some(c) => self
                    .db
                    .prepare(sql::AGENT_CURSOR)
                    .bind(&[s(&t), s(r), s(c)])
                    .map_err(err)?
                    .first(None)
                    .await
                    .map_err(err)?,
            };
            let rows = self
                .db
                .prepare(sql::list_agents())
                .bind(&[
                    s(&t),
                    s(r),
                    opt_n(cursor.as_ref().map(|c| c.created_at as i64)),
                    opt(cursor.as_ref().map(|c| c.id.as_str())),
                    n(q.limit as i64),
                ])
                .map_err(err)?
                .all()
                .await
                .map_err(err)?
                .results::<AgentRow>()
                .map_err(err)?;
            rows.into_iter().map(AgentRow::into_record).collect()
        })
    }

    fn replace_enrolment_token(
        &self,
        token: EnrolmentTokenRecord,
        now: i64,
    ) -> StoreFuture<'_, ()> {
        wrap(async move {
            let close = self
                .db
                .prepare(sql::CLOSE_UNUSED_TOKENS)
                .bind(&[s(&token.tenant_id), s(&token.agent_id), n(now)])
                .map_err(err)?;
            let insert = self
                .db
                .prepare(sql::INSERT_ENROLMENT_TOKEN)
                .bind(&token_args(&token))
                .map_err(err)?;
            self.db.batch(vec![close, insert]).await.map_err(err)?;
            Ok(())
        })
    }

    fn enrolment_token(&self, id: &str) -> StoreFuture<'_, Option<EnrolmentTokenRecord>> {
        let id = id.to_string();
        wrap(async move {
            let row: Option<TokenRowE> = self
                .db
                .prepare(sql::ENROLMENT_TOKEN_BY_ID)
                .bind(&[s(&id)])
                .map_err(err)?
                .first(None)
                .await
                .map_err(err)?;
            row.map(|r| {
                Ok(EnrolmentTokenRecord {
                    id: r.id,
                    tenant_id: r.tenant_id,
                    agent_id: r.agent_id,
                    role: role(&r.role)?,
                    secret_sha256: r.secret_sha256,
                    created_at: r.created_at as i64,
                    expires_at: r.expires_at as i64,
                    created_by: r.created_by,
                    used_at: r.used_at.map(|v| v as i64),
                })
            })
            .transpose()
        })
    }

    fn consume_enrolment_token(&self, id: &str, now: i64) -> StoreFuture<'_, bool> {
        let args = [s(id), n(now)];
        wrap(async move {
            let row: Option<IdRow> = self
                .db
                .prepare(sql::CONSUME_ENROLMENT_TOKEN)
                .bind(&args)
                .map_err(err)?
                .first(None)
                .await
                .map_err(err)?;
            Ok(row.is_some())
        })
    }

    fn release_enrolment_token(&self, id: &str, claimed_at: i64) -> StoreFuture<'_, ()> {
        let args = [s(id), n(claimed_at)];
        wrap(async move {
            self.db
                .prepare(sql::RELEASE_ENROLMENT_TOKEN)
                .bind(&args)
                .map_err(err)?
                .run()
                .await
                .map_err(err)?;
            Ok(())
        })
    }

    fn bind_certificate(
        &self,
        tenant_id: &str,
        role: Role,
        agent_id: &str,
        cert: NewCert,
        retire_at: i64,
        now: i64,
    ) -> StoreFuture<'_, bool> {
        let (t, a) = (tenant_id.to_string(), agent_id.to_string());
        let scopes = agent_scopes(role)
            .iter()
            .map(|x| x.as_str())
            .collect::<Vec<_>>()
            .join(" ");
        wrap(async move {
            let retire = self
                .db
                .prepare(sql::RETIRE_CERTS)
                .bind(&[s(&t), s(&a), n(retire_at)])
                .map_err(err)?;
            let insert = self
                .db
                .prepare(sql::INSERT_AGENT_IDENTITY)
                .bind(&[
                    s(&cert.cert_sha256),
                    s(&a),
                    s(&t),
                    s(role.as_str()),
                    s(&scopes),
                    n(now),
                    opt(cert.issuer_ref.as_deref()),
                    n(cert.expires_at),
                ])
                .map_err(err)?;
            let activate = self
                .db
                .prepare(sql::ACTIVATE_AGENT)
                .bind(&[
                    s(&t),
                    s(role.as_str()),
                    s(&a),
                    n(now),
                    s(&cert.cert_sha256),
                    n(cert.expires_at),
                ])
                .map_err(err)?;
            // One D1 batch is one transaction.
            let results = self
                .db
                .batch(vec![retire, insert, activate])
                .await
                .map_err(err)?;
            let activated = results
                .get(2)
                .map(|r| r.results::<IdRow>().map(|v| !v.is_empty()))
                .transpose()
                .map_err(err)?
                .unwrap_or(false);
            Ok(activated)
        })
    }

    fn revoke_agent(
        &self,
        tenant_id: &str,
        role: Role,
        agent_id: &str,
        reason: Reason,
        now: i64,
    ) -> StoreFuture<'_, Option<AgentCerts>> {
        let (t, a) = (tenant_id.to_string(), agent_id.to_string());
        wrap(async move {
            let code = serde_json::to_value(reason.code)
                .ok()
                .and_then(|v| v.as_str().map(str::to_string))
                .unwrap_or_default();
            let revoke = self
                .db
                .prepare(sql::REVOKE_AGENT)
                .bind(&[
                    s(&t),
                    s(role.as_str()),
                    s(&a),
                    n(now),
                    s(&code),
                    s(&reason.text),
                ])
                .map_err(err)?;
            let identities = self
                .db
                .prepare(sql::REVOKE_IDENTITIES)
                .bind(&[s(&t), s(&a)])
                .map_err(err)?;
            let tokens = self
                .db
                .prepare(sql::CLOSE_UNUSED_TOKENS)
                .bind(&[s(&t), s(&a), n(now)])
                .map_err(err)?;
            let refs = self
                .db
                .prepare(sql::AGENT_CERTS)
                .bind(&[s(&t), s(&a)])
                .map_err(err)?;
            let results = self
                .db
                .batch(vec![revoke, identities, tokens, refs])
                .await
                .map_err(err)?;
            let found = results
                .first()
                .map(|r| r.results::<IdRow>().map(|v| !v.is_empty()))
                .transpose()
                .map_err(err)?
                .unwrap_or(false);
            if !found {
                return Ok(None);
            }
            let certs = results
                .get(3)
                .map(|r| r.results::<AgentCertRow>())
                .transpose()
                .map_err(err)?
                .unwrap_or_default();
            Ok(Some(
                certs
                    .into_iter()
                    .map(|r| (r.cert_sha256, r.issuer_ref))
                    .collect(),
            ))
        })
    }

    fn record_agent_seen(
        &self,
        tenant_id: &str,
        agent_id: &str,
        seen: SeenFrom,
        network_changed: bool,
        now: i64,
    ) -> StoreFuture<'_, ()> {
        let args = [
            s(tenant_id),
            s(agent_id),
            n(now),
            opt(seen.ip.as_deref()),
            opt_n(seen.asn.map(i64::from)),
            n(i64::from(network_changed)),
        ];
        wrap(async move {
            self.db
                .prepare(sql::RECORD_AGENT_SEEN)
                .bind(&args)
                .map_err(err)?
                .run()
                .await
                .map_err(err)?;
            Ok(())
        })
    }
}

fn override_from_row(r: foiled_pg::LinkOverrideRow) -> Option<LinkOverride> {
    let kind = serde_json::from_value(serde_json::Value::String(r.kind)).ok()?;
    let feedback = serde_json::from_value(serde_json::Value::String(r.feedback)).ok()?;
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
}
