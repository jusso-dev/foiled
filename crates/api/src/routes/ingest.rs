//! Evidence ingest for sandbox hosts (#41) and edge sensors (#31), on the
//! mTLS ingest hostname only (ADR 0005).
//!
//! - `POST /v0/ingest/events`: a batch of capture envelopes. Validated,
//!   stamped with the certificate identity and put on the ingest Queue.
//! - `POST /v0/uploads`: a short-lived presigned PUT for exactly one R2
//!   object. Large evidence never passes through a Worker request body.
//!
//! A host or sensor may only send evidence for decoys assigned to it.

use std::collections::BTreeSet;

use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::post;
use axum::{Json, Router};
use foiled_core::auth::{Principal, Role, Scope};
use foiled_core::capture::{CaptureEvent, Channel, MAX_BATCH, PayloadRef, Source, SourceKind};
use foiled_core::sigv4::{self, Credentials, PresignRequest};
use serde::{Deserialize, Serialize};

use crate::AppState;
use crate::auth::Auth;
use crate::error::{ApiError, JsonBody};
use crate::routes::check_rate;

/// Largest object a single presigned PUT may carry. Bigger artefacts need
/// multipart upload, which is not offered yet.
pub const MAX_UPLOAD_BYTES: u64 = 5 * 1024 * 1024 * 1024;

/// Where and how upload URLs are minted. Secrets come from Worker secrets.
#[derive(Clone)]
pub struct UploadConfig {
    /// S3-compatible endpoint host, for example `<account>.r2.cloudflarestorage.com`.
    pub host: String,
    pub bucket: String,
    pub credentials: Credentials,
    pub expires_secs: u32,
}

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/v0/ingest/events", post(ingest_events))
        .route("/v0/uploads", post(mint_upload))
}

fn require_any(auth: &Auth, scopes: [Scope; 2]) -> Result<&Principal, ApiError> {
    auth.require(scopes[0]).or_else(|_| auth.require(scopes[1]))
}

fn source_of(p: &Principal) -> Result<Source, ApiError> {
    let kind = match p.role {
        Role::Host => SourceKind::Host,
        Role::Sensor => SourceKind::Sensor,
        _ => return Err(ApiError::forbidden("host:ingest or sensor:ingest")),
    };
    Ok(Source {
        kind,
        id: p.id.clone(),
    })
}

/// The decoy must exist in the caller's tenant and be assigned to the caller.
async fn check_owner(state: &AppState, who: &Principal, decoy_id: &str) -> Result<(), ApiError> {
    let decoy = state
        .store
        .get_decoy(&who.tenant_id, decoy_id)
        .await?
        .ok_or_else(|| ApiError::not_found("decoy"))?;
    if decoy.host_id.as_deref() != Some(who.id.as_str()) {
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "not_assigned",
            "decoy is not assigned to this identity",
        ));
    }
    Ok(())
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EventBatch {
    pub events: Vec<CaptureEvent>,
}

#[derive(Debug, Serialize)]
pub struct Accepted {
    pub accepted: usize,
}

async fn ingest_events(
    State(state): State<AppState>,
    auth: Auth,
    JsonBody(batch): JsonBody<EventBatch>,
) -> Result<(StatusCode, Json<Accepted>), ApiError> {
    let who = require_any(&auth, [Scope::HostIngest, Scope::SensorIngest])?.clone();
    let source = source_of(&who)?;
    // Per-identity flood control: a stolen certificate cannot exhaust the
    // ingest Queue for everyone else (#31 tabletop, step 8).
    check_rate(
        &state,
        &who,
        "ingest.batch",
        state.limits.ingest_batches_per_minute,
        60_000,
    )
    .await?;
    if batch.events.is_empty() || batch.events.len() > MAX_BATCH {
        return Err(ApiError::bad_request(format!(
            "a batch holds 1 to {MAX_BATCH} events"
        )));
    }
    let now = (state.clock)();
    let mut problems = Vec::new();
    for (i, e) in batch.events.iter().enumerate() {
        for p in e.problems(now) {
            problems.push(format!("events[{i}]: {p}"));
        }
        let refs = e
            .payload_ref
            .iter()
            .chain(e.hook.iter().filter_map(|h| h.request_slice_ref.as_ref()));
        for r in refs {
            // Evidence must live under the sender's own tenant and decoy.
            if let Some(pr) = PayloadRef::parse(r)
                && (pr.tenant_id != who.tenant_id || pr.decoy_id != e.decoy_id)
            {
                problems.push(format!("events[{i}]: payload_ref outside this decoy"));
            }
        }
    }
    if !problems.is_empty() {
        problems.truncate(20);
        return Err(ApiError::unprocessable(
            "invalid_events",
            problems.join("; "),
        ));
    }
    let decoys: BTreeSet<&str> = batch.events.iter().map(|e| e.decoy_id.as_str()).collect();
    for d in decoys {
        check_owner(&state, &who, d).await?;
    }
    let mut events = batch.events;
    for e in &mut events {
        e.stamp(source.clone(), &who.tenant_id);
    }
    let accepted = events.len();
    state.store.enqueue_events(events).await?;
    Ok((StatusCode::ACCEPTED, Json(Accepted { accepted })))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UploadRequest {
    pub decoy_id: String,
    pub attempt_id: Option<String>,
    pub channel: Channel,
    /// Lowercase hex SHA-256 of the object. It is part of the key and is
    /// checked by R2 through the signed `x-amz-checksum-sha256` header.
    pub sha256: String,
    pub size: u64,
}

#[derive(Debug, Serialize)]
pub struct UploadGrant {
    pub method: &'static str,
    pub url: String,
    /// Headers the uploader must send exactly as given.
    pub headers: Vec<(String, String)>,
    pub payload_ref: String,
    pub expires_at: i64,
}

fn base64(bytes: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for c in bytes.chunks(3) {
        let n = (u32::from(c[0]) << 16)
            | (u32::from(*c.get(1).unwrap_or(&0)) << 8)
            | u32::from(*c.get(2).unwrap_or(&0));
        out.push(T[(n >> 18) as usize & 63] as char);
        out.push(T[(n >> 12) as usize & 63] as char);
        out.push(if c.len() > 1 {
            T[(n >> 6) as usize & 63] as char
        } else {
            '='
        });
        out.push(if c.len() > 2 {
            T[n as usize & 63] as char
        } else {
            '='
        });
    }
    out
}

async fn mint_upload(
    State(state): State<AppState>,
    auth: Auth,
    JsonBody(req): JsonBody<UploadRequest>,
) -> Result<(StatusCode, Json<UploadGrant>), ApiError> {
    let who = require_any(&auth, [Scope::HostUpload, Scope::SensorUpload])?.clone();
    let cfg = state.uploads.clone().ok_or_else(|| {
        ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "uploads_disabled",
            "evidence uploads are not configured",
        )
    })?;
    if req.size == 0 || req.size > MAX_UPLOAD_BYTES {
        return Err(ApiError::bad_request(
            "size must be between 1 byte and 5 GiB",
        ));
    }
    let pr = PayloadRef::new(
        &cfg.bucket,
        &who.tenant_id,
        &req.decoy_id,
        req.attempt_id.as_deref(),
        req.channel,
        &req.sha256,
    )
    .ok_or_else(|| ApiError::bad_request("invalid decoy_id, attempt_id or sha256"))?;
    check_owner(&state, &who, &req.decoy_id).await?;

    let digest = hex::decode(&req.sha256).map_err(|_| ApiError::bad_request("invalid sha256"))?;
    let checksum = base64(&digest);
    let now = (state.clock)();
    let amz_date = sigv4::amz_date(now);
    let path = format!("/{}/{}", cfg.bucket, pr.key());
    let headers = [("x-amz-checksum-sha256", checksum.as_str())];
    let url = sigv4::presign(
        &PresignRequest {
            method: "PUT",
            host: &cfg.host,
            path: &path,
            region: "auto",
            service: "s3",
            amz_date: &amz_date,
            expires_secs: cfg.expires_secs,
            extra_headers: &headers,
        },
        &cfg.credentials,
    );
    Ok((
        StatusCode::CREATED,
        Json(UploadGrant {
            method: "PUT",
            url,
            headers: vec![("x-amz-checksum-sha256".into(), checksum)],
            payload_ref: pr.to_string(),
            expires_at: now + i64::from(cfg.expires_secs) * 1000,
        }),
    ))
}

#[cfg(test)]
mod tests {
    use super::base64;

    #[test]
    fn base64_matches_rfc4648_vectors() {
        for (input, want) in [
            ("", ""),
            ("f", "Zg=="),
            ("fo", "Zm8="),
            ("foo", "Zm9v"),
            ("foob", "Zm9vYg=="),
            ("fooba", "Zm9vYmE="),
            ("foobar", "Zm9vYmFy"),
        ] {
            assert_eq!(base64(input.as_bytes()), want);
        }
    }
}
