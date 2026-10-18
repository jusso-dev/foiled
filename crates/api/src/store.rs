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
use foiled_core::decoy::{Decoy, DecoyState, Reason};
use foiled_core::enrich_pipeline::{EnrichPurgeCounts, EnrichPurgePlan, ProviderFailureRecord};
use foiled_core::enrichment::{CacheEntry, Observable};
use foiled_core::enrolment::{AgentRecord, SeenFrom};
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

/// A sandbox host or edge sensor known by its client certificate. One row
/// per certificate: during a renewal an identity briefly has two.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdentityRecord {
    pub id: String,
    pub tenant_id: String,
    pub role: Role,
    pub scopes: Vec<Scope>,
    /// Lowercase hex SHA-256 fingerprint of the client certificate.
    pub cert_sha256: String,
    pub revoked: bool,
    /// After a renewal or re-enrolment, the old certificate stops working
    /// at this time (Unix ms). `None` while it is the current one.
    pub valid_until: Option<i64>,
    /// The certificate's own expiry (Unix ms), when known. Checked as well
    /// as Cloudflare's `certVerified`.
    pub expires_at: Option<i64>,
}

/// A one-time enrolment token (#31). Only the SHA-256 of the secret is
/// stored; the token itself is shown to the operator once.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnrolmentTokenRecord {
    pub id: String,
    pub tenant_id: String,
    pub agent_id: String,
    pub role: Role,
    pub secret_sha256: String,
    pub created_at: i64,
    pub expires_at: i64,
    pub created_by: String,
    pub used_at: Option<i64>,
}

/// A certificate the CA just issued, to bind to an agent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewCert {
    pub cert_sha256: String,
    /// The CA's id for the certificate, used to revoke it there.
    pub issuer_ref: Option<String>,
    pub issued_at: i64,
    pub expires_at: i64,
}

/// An identity's certificates: fingerprint and CA reference, if any.
pub type AgentCerts = Vec<(String, Option<String>)>;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AgentQuery {
    pub limit: usize,
    /// Return agents created strictly before this id in list order.
    pub cursor: Option<String>,
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

/// One stored version of a write-up (#35): the whole record after a
/// change, what changed it and who. Versions are never edited.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WriteUpVersion {
    pub writeup: foiled_core::writeup::WriteUp,
    /// `create`, `edit` or `transition.<status>`.
    pub action: String,
    pub actor_id: String,
    pub at: i64,
}

/// Most radar rollup rows one read returns.
pub const MAX_RADAR_POINTS: usize = 200_000;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DecoyQuery {
    pub state: Option<DecoyState>,
    pub catalogue_id: Option<String>,
    /// Only decoys created by this principal (token id).
    pub created_by: Option<String>,
    /// Only decoys that are not destroyed.
    pub live: bool,
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

/// Most events the default [`Store::events_after`] reads from one
/// millisecond.
pub const MAX_EVENTS_PER_MS: usize = 10_000;

/// Result of taking rate-limit budget for one provider call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BudgetOutcome {
    Taken,
    MinuteSpent,
    DaySpent,
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

    /// The count for one window, without adding a hit. Zero when unseen.
    fn rate_count(&self, key: &str, window_start: i64) -> StoreFuture<'_, u32>;

    fn append_audit(&self, record: AuditRecord) -> StoreFuture<'_, ()>;

    /// Newest first, for one tenant.
    fn list_audit(&self, tenant_id: &str, q: AuditQuery) -> StoreFuture<'_, Vec<AuditRecord>>;

    /// Put validated, identity-stamped capture envelopes on the ingest Queue
    /// (#9). The Queue consumer writes them to Postgres.
    fn enqueue_events(&self, events: Vec<CaptureEvent>) -> StoreFuture<'_, ()>;

    /// Lease up to `limit` jobs for a host: queued jobs already for this host
    /// or (when `take_unplaced`) not yet placed, plus leases that have
    /// lapsed. Unplaced jobs (and their decoys) are assigned to the host.
    /// Expired jobs are never leased. Edge sensors never take unplaced work.
    fn lease_jobs(
        &self,
        tenant_id: &str,
        host_id: &str,
        now: i64,
        lease_ms: i64,
        limit: usize,
        take_unplaced: bool,
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

    /// Events strictly after `after` in `(ts, event_id)` order, with
    /// `ts < until`, oldest first, at most `limit`. Lets a reader continue
    /// past a cut even when more than `limit` events share one millisecond
    /// (#13). The default reads the cursor's millisecond (at most
    /// [`MAX_EVENTS_PER_MS`] events, and refuses rather than answer wrongly
    /// beyond that), then the rest; stores that can compare
    /// `(ts, event_id)` directly override it.
    fn events_after(
        &self,
        tenant_id: &str,
        after: (i64, String),
        until: i64,
        limit: usize,
    ) -> StoreFuture<'_, Vec<CaptureEvent>> {
        let tenant_id = tenant_id.to_string();
        Box::pin(async move {
            let (ts, id) = after;
            let same_ms = self
                .events_between(&tenant_id, ts, (ts + 1).min(until), MAX_EVENTS_PER_MS + 1)
                .await?;
            if same_ms.len() > MAX_EVENTS_PER_MS {
                return Err(StoreError(format!(
                    "more than {MAX_EVENTS_PER_MS} events in one millisecond; this store cannot continue a cursor there"
                )));
            }
            let mut out: Vec<CaptureEvent> = same_ms
                .into_iter()
                .filter(|e| e.event_id > id)
                .take(limit)
                .collect();
            if out.len() < limit && ts + 1 < until {
                out.extend(
                    self.events_between(&tenant_id, ts + 1, until, limit - out.len())
                        .await?,
                );
            }
            Ok(out)
        })
    }

    /// Analyst decisions on an attempt's links (#27).
    fn link_overrides(
        &self,
        tenant_id: &str,
        attempt_id: &str,
    ) -> StoreFuture<'_, Vec<LinkOverride>>;

    /// Analyst decisions for several attempts at once, for exports (#13).
    /// The default asks once per attempt; stores that can answer in one
    /// query override it.
    fn link_overrides_many(
        &self,
        tenant_id: &str,
        attempt_ids: Vec<String>,
    ) -> StoreFuture<'_, Vec<LinkOverride>> {
        let tenant_id = tenant_id.to_string();
        Box::pin(async move {
            let mut out = Vec::new();
            for a in attempt_ids {
                out.extend(self.link_overrides(&tenant_id, &a).await?);
            }
            Ok(out)
        })
    }

    /// Record an analyst decision, replacing any earlier one for the link.
    fn put_link_override(&self, tenant_id: &str, o: LinkOverride) -> StoreFuture<'_, ()>;

    /// Analyst actions on campaigns (#33), oldest first: every structural
    /// action (label, status, merge, split) and the newest `feedback_limit`
    /// feedback actions.
    fn campaign_actions(
        &self,
        tenant_id: &str,
        feedback_limit: usize,
    ) -> StoreFuture<'_, Vec<foiled_core::campaign::CampaignAction>>;

    /// Recorded campaign per attempt, for these attempts (#33 registry).
    fn campaign_memberships(
        &self,
        tenant_id: &str,
        attempt_ids: Vec<String>,
    ) -> StoreFuture<'_, Vec<(String, String)>>;

    /// Registry records for these campaign ids, with member counts.
    fn campaign_records(
        &self,
        tenant_id: &str,
        campaign_ids: Vec<String>,
    ) -> StoreFuture<'_, Vec<foiled_core::campaign::StoredCampaign>>;

    /// Bridge provenance for merges into this campaign (#33).
    fn campaign_bridges(
        &self,
        tenant_id: &str,
        campaign_id: &str,
    ) -> StoreFuture<'_, Vec<foiled_core::campaign::BridgeRecord>>;

    /// Apply a registry update so concurrent writers converge: `created_at`
    /// is insert-only, first and last seen only widen, `merged_into` is
    /// write-once and only to a strictly older campaign, memberships only
    /// move to older campaigns.
    fn update_campaign_registry(
        &self,
        tenant_id: &str,
        update: foiled_core::campaign::RegistryUpdate,
        now: i64,
    ) -> StoreFuture<'_, ()>;

    /// Append an analyst campaign action. Actions are never edited.
    fn append_campaign_action(
        &self,
        tenant_id: &str,
        action: foiled_core::campaign::CampaignAction,
    ) -> StoreFuture<'_, ()>;

    /// The latest analyst decision on each actor link (#29) of these
    /// subjects (campaign or attempt ids).
    fn actor_decisions(
        &self,
        tenant_id: &str,
        subject_ids: Vec<String>,
    ) -> StoreFuture<'_, Vec<foiled_core::actor::ActorDecision>>;

    /// Record an analyst decision on an actor link, replacing any earlier
    /// one for the same subject and actor.
    fn put_actor_decision(
        &self,
        tenant_id: &str,
        d: foiled_core::actor::ActorDecision,
    ) -> StoreFuture<'_, ()>;

    /// Source IPs seen since `since` (Unix ms), oldest first.
    fn ip_iocs(&self, tenant_id: &str, since: i64) -> StoreFuture<'_, Vec<IpIocRow>>;

    /// Enrichment cache rows (#11) for these observables that are still
    /// fresh at `now_ms`, from every provider. The cache is shared by all
    /// tenants of a deployment (the operator owns the provider keys); what a
    /// caller may read from it is decided by
    /// [`crate::enrichment::cached_facts`], never by the store. The Worker
    /// store reads D1 `enrich_cache` in one batch of at most
    /// `max_statements` chunked statements (`d1_sql::enrich_lookup_plan`);
    /// pass the newest observables first, since the oldest are dropped when
    /// the budget runs out. Rows kept for one tenant are returned only for
    /// that `tenant_id`.
    fn enrichment_cache(
        &self,
        observables: Vec<Observable>,
        now_ms: i64,
        max_statements: usize,
        tenant_id: Option<String>,
    ) -> StoreFuture<'_, Vec<CacheEntry>>;

    /// Write an enrichment cache row (the `foiled-enrich` consumer, #11),
    /// replacing the provider's earlier answer for the observable.
    fn upsert_enrich_cache(&self, entry: CacheEntry) -> StoreFuture<'_, ()>;

    /// Take one unit of a provider's minute and day budget at `now_ms`, or
    /// none if either is spent (a minute unit taken before a spent day is
    /// given back).
    fn take_enrich_budget(
        &self,
        provider: &str,
        now_ms: i64,
        per_minute: u32,
        per_day: u32,
    ) -> StoreFuture<'_, BudgetOutcome>;

    /// Recorded provider failures for one observable, for backoff.
    fn enrich_failures(
        &self,
        observable: Observable,
    ) -> StoreFuture<'_, Vec<ProviderFailureRecord>>;

    /// Count a failed provider call. `error` is a short description, never
    /// a response body or a key; `retry_at` comes from a `Retry-After`.
    fn record_enrich_failure(
        &self,
        provider: &str,
        observable: Observable,
        now_ms: i64,
        error: String,
        retry_at: Option<i64>,
    ) -> StoreFuture<'_, ()>;

    /// Forget a provider's failures for an observable after it answers.
    fn clear_enrich_failure(&self, provider: &str, observable: Observable) -> StoreFuture<'_, ()>;

    /// Purge the enrichment tables (#16): cache rows past their own TTL,
    /// rows past their provider's retention cap when `plan.retention` is
    /// set, and failure rows that no longer affect any backoff. Each
    /// statement deletes at most `plan.batch` rows.
    fn purge_enrichment(&self, plan: EnrichPurgePlan) -> StoreFuture<'_, EnrichPurgeCounts>;
    // Review queue, write-ups, public pages and radar rollups (#35).

    /// Stored analyst state for these review items.
    fn review_states(
        &self,
        tenant_id: &str,
        item_ids: Vec<String>,
    ) -> StoreFuture<'_, Vec<foiled_core::review::ReviewState>>;

    /// Write an item's state if the stored version is `expected` (0 when
    /// there is no row yet). False, writing nothing, when it is not.
    fn put_review_state(
        &self,
        tenant_id: &str,
        state: foiled_core::review::ReviewState,
        expected: u32,
    ) -> StoreFuture<'_, bool>;

    /// Insert a new write-up and its first version row.
    fn insert_writeup(
        &self,
        writeup: foiled_core::writeup::WriteUp,
        actor_id: &str,
    ) -> StoreFuture<'_, ()>;

    fn get_writeup(
        &self,
        tenant_id: &str,
        writeup_id: &str,
    ) -> StoreFuture<'_, Option<foiled_core::writeup::WriteUp>>;

    /// Newest change first, optionally one status only.
    fn list_writeups(
        &self,
        tenant_id: &str,
        status: Option<foiled_core::writeup::WriteUpStatus>,
        limit: usize,
    ) -> StoreFuture<'_, Vec<foiled_core::writeup::WriteUp>>;

    /// Replace a write-up if its stored version is `expected`, and append
    /// the new version row, together. False, writing nothing, otherwise.
    fn update_writeup(
        &self,
        writeup: foiled_core::writeup::WriteUp,
        expected: u32,
        action: &str,
        actor_id: &str,
    ) -> StoreFuture<'_, bool>;

    /// Every version, oldest first.
    fn writeup_versions(
        &self,
        tenant_id: &str,
        writeup_id: &str,
    ) -> StoreFuture<'_, Vec<WriteUpVersion>>;

    /// Store the public snapshot of a write-up, replacing an earlier one
    /// for the same write-up. False when another write-up holds the slug.
    fn put_public_page(
        &self,
        tenant_id: &str,
        writeup_id: &str,
        page: foiled_core::writeup::PublicPage,
    ) -> StoreFuture<'_, bool>;

    fn remove_public_page(&self, tenant_id: &str, writeup_id: &str) -> StoreFuture<'_, ()>;

    /// The page for a slug if it is visible at `now`. Not tenant scoped:
    /// public pages hold no tenant data, and this is the only read the
    /// public routes make besides [`Store::public_pages`] and
    /// [`Store::radar_points`].
    fn public_page(
        &self,
        slug: &str,
        now: i64,
    ) -> StoreFuture<'_, Option<foiled_core::writeup::PublicPage>>;

    /// Pages visible at `now`, newest first.
    fn public_pages(
        &self,
        now: i64,
        limit: usize,
    ) -> StoreFuture<'_, Vec<foiled_core::writeup::PublicPageSummary>>;

    /// Replace one tenant's rollup for one day.
    fn put_radar_points(
        &self,
        tenant_id: &str,
        day: i64,
        points: Vec<foiled_core::radar::RadarPoint>,
    ) -> StoreFuture<'_, ()>;

    /// Rollup rows with `since <= day < until`, for one tenant or (None)
    /// every tenant, at most `limit`.
    fn radar_points(
        &self,
        tenant_id: Option<&str>,
        since: i64,
        until: i64,
        limit: usize,
    ) -> StoreFuture<'_, Vec<foiled_core::radar::RadarPoint>>;

    fn record_heartbeat(
        &self,
        tenant_id: &str,
        host_id: &str,
        heartbeat: serde_json::Value,
        clock_skew_ms: i64,
        now: i64,
    ) -> StoreFuture<'_, ()>;

    // Enrolment and the sensor and host registry (#31).

    /// Register an agent and its first enrolment token together.
    fn create_agent(&self, agent: AgentRecord, token: EnrolmentTokenRecord) -> StoreFuture<'_, ()>;

    fn get_agent(
        &self,
        tenant_id: &str,
        role: Role,
        id: &str,
    ) -> StoreFuture<'_, Option<AgentRecord>>;

    /// Newest first.
    fn list_agents(
        &self,
        tenant_id: &str,
        role: Role,
        q: AgentQuery,
    ) -> StoreFuture<'_, Vec<AgentRecord>>;

    /// Store a new enrolment token for an agent, invalidating any unused one.
    fn replace_enrolment_token(&self, token: EnrolmentTokenRecord, now: i64)
    -> StoreFuture<'_, ()>;

    fn enrolment_token(&self, id: &str) -> StoreFuture<'_, Option<EnrolmentTokenRecord>>;

    /// Mark a token used if it is unused and unexpired. True only for the
    /// one call that consumed it, so a token can never be redeemed twice.
    fn consume_enrolment_token(&self, id: &str, now: i64) -> StoreFuture<'_, bool>;

    /// Undo [`Store::consume_enrolment_token`] after the CA failed to
    /// issue, so the token can be retried. Only reopens a token still
    /// marked used at `claimed_at` whose agent is not revoked.
    fn release_enrolment_token(&self, id: &str, claimed_at: i64) -> StoreFuture<'_, ()>;

    /// Bind a certificate to a pending or active agent and mark it active.
    /// The agent's other live certificates stop working at `retire_at`.
    /// Returns false, binding nothing, if the agent is missing or revoked.
    fn bind_certificate(
        &self,
        tenant_id: &str,
        role: Role,
        agent_id: &str,
        cert: NewCert,
        retire_at: i64,
        now: i64,
    ) -> StoreFuture<'_, bool>;

    /// Revoke an agent, every certificate it holds and any unused token.
    /// Returns each certificate's fingerprint and CA reference (`None` for
    /// certificates issued outside `/v0/enrol`), or `None` if there is no
    /// such agent.
    fn revoke_agent(
        &self,
        tenant_id: &str,
        role: Role,
        agent_id: &str,
        reason: Reason,
        now: i64,
    ) -> StoreFuture<'_, Option<AgentCerts>>;

    /// Record where an agent was last seen from.
    fn record_agent_seen(
        &self,
        tenant_id: &str,
        agent_id: &str,
        seen: SeenFrom,
        network_changed: bool,
        now: i64,
    ) -> StoreFuture<'_, ()>;
}
