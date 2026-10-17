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
    /// `queued`, `leased`, `succeeded`, `failed` or `rejected`.
    pub status: String,
    /// Run parameters for create and rebuild jobs (`foiled_core::agent::DecoyParams`).
    pub params: Option<serde_json::Value>,
    /// While leased, the time after which another lease may take the job.
    pub leased_until: Option<i64>,
}

/// An analyst decision on one link of one attempt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LinkOverride {
    pub attempt_id: String,
    pub kind: foiled_core::confidence::LinkKind,
    pub target: String,
    pub decision: foiled_core::confidence::Override,
}

/// One source IP seen at a tenant's decoys, for the IOC export (#22, #34).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IpIocRow {
    pub ip: String,
    pub first_seen: i64,
    pub last_seen: i64,
    pub events: i64,
    pub decoy_ids: Vec<String>,
    pub catalogue_ids: Vec<String>,
    /// CVE or FOILED-DEMO ids from hook events this source triggered.
    pub hook_cves: Vec<String>,
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

    /// Lease up to `limit` jobs for a host: queued jobs already for this host
    /// or not yet placed, plus leases that have lapsed. Unplaced jobs (and
    /// their decoys) are assigned to the host. Expired jobs are never leased.
    fn lease_jobs(
        &self,
        tenant_id: &str,
        host_id: &str,
        now: i64,
        lease_ms: i64,
        limit: usize,
    ) -> StoreFuture<'_, Vec<JobRecord>>;

    /// Close a job leased by `host_id`. Returns the job, or `None` when it is
    /// not leased by that host.
    fn finish_job(
        &self,
        tenant_id: &str,
        host_id: &str,
        job_id: &str,
        status: &str,
    ) -> StoreFuture<'_, Option<JobRecord>>;

    /// Compare-and-set a decoy's state. Returns false if it was not `from`.
    fn set_decoy_state(
        &self,
        tenant_id: &str,
        decoy_id: &str,
        from: DecoyState,
        to: DecoyState,
        bump_generation: bool,
        now: i64,
    ) -> StoreFuture<'_, bool>;

    /// Stamped capture events for a tenant with `since <= ts < until`,
    /// oldest first, at most `limit`. Attempts are built from these (#25).
    fn events_between(
        &self,
        tenant_id: &str,
        since: i64,
        until: i64,
        limit: usize,
    ) -> StoreFuture<'_, Vec<CaptureEvent>>;

    /// Analyst decisions on an attempt's links (#27).
    fn link_overrides(
        &self,
        tenant_id: &str,
        attempt_id: &str,
    ) -> StoreFuture<'_, Vec<LinkOverride>>;

    /// Record an analyst decision, replacing any earlier one for the link.
    fn put_link_override(&self, tenant_id: &str, o: LinkOverride) -> StoreFuture<'_, ()>;

    /// Source IPs seen since `since` (Unix ms), oldest first.
    fn ip_iocs(&self, tenant_id: &str, since: i64) -> StoreFuture<'_, Vec<IpIocRow>>;

    fn record_heartbeat(
        &self,
        tenant_id: &str,
        host_id: &str,
        heartbeat: serde_json::Value,
        clock_skew_ms: i64,
        now: i64,
    ) -> StoreFuture<'_, ()>;
}
