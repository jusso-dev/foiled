//! Storage behind the API.
//!
//! Handlers talk to [`Store`] only. On Workers the implementation is D1 for
//! config (tokens, identities, decoys, jobs, rate limits) and Postgres via
//! Hyperdrive for the audit log (ADR 0009). Tests and the local mock server
//! use [`crate::memory::MemoryStore`].
//!
//! Every method returns a boxed `Send` future so Axum handlers stay `Send`.
//! On Workers the binding futures are `!Send`; the Worker implementation
//! wraps them in `worker::send::SendFuture`, which is sound because a Worker
//! isolate is single threaded.

use std::future::Future;
use std::pin::Pin;

use foiled_core::audit::AuditRecord;
use foiled_core::auth::{Role, Scope};
use foiled_core::capture::CaptureEvent;
use foiled_core::decoy::{Decoy, DecoyState};
use serde::{Deserialize, Serialize};

pub type StoreFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T, StoreError>> + Send + 'a>>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoreError(pub String);

impl std::fmt::Display for StoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "store error: {}", self.0)
    }
}

/// A bearer token row. Only the SHA-256 of the secret part is stored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TokenRecord {
    pub id: String,
    pub tenant_id: String,
    pub role: Role,
    pub scopes: Vec<Scope>,
    /// Lowercase hex SHA-256 of the token secret.
    pub secret_sha256: String,
    pub expires_at: Option<i64>,
    pub revoked: bool,
}

/// A sandbox host or edge sensor known by its client certificate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdentityRecord {
    pub id: String,
    pub tenant_id: String,
    pub role: Role,
    pub scopes: Vec<Scope>,
    /// Lowercase hex SHA-256 fingerprint of the client certificate.
    pub cert_sha256: String,
    pub revoked: bool,
}

/// Work for a sandbox host agent (#41). Created by the API, leased and
/// acknowledged by the host.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JobRecord {
    pub id: String,
    pub tenant_id: String,
    pub decoy_id: String,
    pub host_id: Option<String>,
    /// For example `decoy.create`, `decoy.rotate`, `decoy.destroy`.
    pub kind: String,
    pub reason_code: Option<String>,
    pub reason_text: Option<String>,
    pub idempotency_key: String,
    pub created_at: i64,
    pub expires_at: i64,
    pub status: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DecoyQuery {
    pub state: Option<DecoyState>,
    pub catalogue_id: Option<String>,
    pub limit: usize,
    /// Return decoys created strictly before this id in list order.
    pub cursor: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AuditQuery {
    pub action: Option<String>,
    pub target: Option<String>,
    pub limit: usize,
    /// Keyset cursor: return records strictly older than this `(ts, id)`.
    pub before: Option<(i64, String)>,
}

pub trait Store: Send + Sync {
    fn token(&self, id: &str) -> StoreFuture<'_, Option<TokenRecord>>;

    fn identity_by_cert(&self, cert_sha256: &str) -> StoreFuture<'_, Option<IdentityRecord>>;

    /// Insert a decoy and its create job together.
    fn create_decoy(&self, decoy: Decoy, job: JobRecord) -> StoreFuture<'_, ()>;

    fn get_decoy(&self, tenant_id: &str, id: &str) -> StoreFuture<'_, Option<Decoy>>;

    /// Newest first.
    fn list_decoys(&self, tenant_id: &str, q: DecoyQuery) -> StoreFuture<'_, Vec<Decoy>>;

    /// Decoys that are not destroyed, for the concurrency cap.
    fn count_live_decoys(&self, tenant_id: &str) -> StoreFuture<'_, u32>;

    fn insert_job(&self, job: JobRecord) -> StoreFuture<'_, ()>;

    /// Find an earlier job by idempotency key, so retries do not duplicate work.
    fn job_by_idempotency_key(
        &self,
        tenant_id: &str,
        key: &str,
    ) -> StoreFuture<'_, Option<JobRecord>>;

    /// Count a hit in a fixed window and say whether it is within `limit`.
    fn rate_limit(&self, key: &str, window_start: i64, limit: u32) -> StoreFuture<'_, bool>;

    fn append_audit(&self, record: AuditRecord) -> StoreFuture<'_, ()>;

    /// Newest first, for one tenant.
    fn list_audit(&self, tenant_id: &str, q: AuditQuery) -> StoreFuture<'_, Vec<AuditRecord>>;

    /// Put validated, identity-stamped capture envelopes on the ingest Queue
    /// (#9). The Queue consumer writes them to Postgres.
    fn enqueue_events(&self, events: Vec<CaptureEvent>) -> StoreFuture<'_, ()>;
}
