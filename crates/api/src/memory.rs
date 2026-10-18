//! In-memory [`Store`] for tests and the local mock server.

use std::collections::HashMap;
use std::sync::Mutex;

use foiled_core::audit::AuditRecord;
use foiled_core::auth::{Role, agent_scopes};
use foiled_core::capture::CaptureEvent;
use foiled_core::decoy::{Decoy, DecoyState, Reason};
use foiled_core::enrich_pipeline::{EnrichPurgeCounts, EnrichPurgePlan, ProviderFailureRecord};
use foiled_core::enrichment::{CacheEntry, Observable};
use foiled_core::enrolment::{AgentRecord, AgentStatus, SeenFrom};

use foiled_core::radar::{AnalyticsPoint, RadarPoint};
use foiled_core::review::ReviewState;
use foiled_core::writeup::{PublicPage, PublicPageSummary, WriteUp, WriteUpStatus};
use std::collections::BTreeMap;

use crate::sinks::RadarSink;
use crate::store::{
    AgentCerts, AgentQuery, AuditQuery, BudgetOutcome, DayAttempt, DayRecord, DecoyQuery,
    EnrolmentTokenRecord, Evidence, History, IdentityRecord, IpIocRow, JobRecord, LinkOverride,
    LogQuery, NewCert, NewVersion, PendingStep, PublishedIoc, StixVersion, Store, StoreError,
    StoreFuture, TokenRecord, WriteUpVersion,
};

#[derive(Default)]
struct Inner {
    tokens: HashMap<String, TokenRecord>,
    identities: Vec<IdentityRecord>,
    decoys: Vec<Decoy>,
    jobs: Vec<JobRecord>,
    rate: HashMap<(String, i64), u32>,
    audit: Vec<AuditRecord>,
    events: Vec<CaptureEvent>,
    heartbeats: HashMap<(String, String), (serde_json::Value, i64)>,
    overrides: Vec<(String, LinkOverride)>,
    campaign_actions: Vec<(String, foiled_core::campaign::CampaignAction)>,
    campaign_registry: HashMap<String, foiled_core::campaign::Registry>,
    actor_decisions: Vec<(String, foiled_core::actor::ActorDecision)>,
    /// Audit appends with this action fail, to test storage outages.
    fail_audit_action: Option<String>,
    /// Write-up updates with this action lose their version check (tests).
    fail_writeup_action: Option<String>,
    /// Public page removals fail (tests).
    fail_page_removal: bool,
    /// Review state writes that roll a decision back fail (tests).
    fail_review_rollback: bool,
    cache: Vec<CacheEntry>,
    fail_enrichment: bool,
    budget: HashMap<(String, &'static str, i64), u32>,
    failures: Vec<ProviderFailureRecord>,
    /// The STIX object log (#13): rows per (tenant, collection), heads with
    /// first `created` and newest evidence, and the materialiser's state.
    stix: HashMap<(String, String), StixLog>,
    /// The scheduled materialiser's tenant cursor, per collection.
    stix_cron: HashMap<String, String>,
    agents: Vec<AgentRecord>,
    enrolment_tokens: Vec<EnrolmentTokenRecord>,
    /// CA reference for each bound certificate, by fingerprint.
    issuer_refs: HashMap<String, String>,
    review_states: HashMap<(String, String), ReviewState>,
    writeups: Vec<WriteUp>,
    writeup_versions: Vec<(String, WriteUpVersion)>,
    /// Tenant, write-up id and page.
    public_pages: Vec<(String, String, PublicPage)>,
    radar: Vec<RadarPoint>,
}

#[derive(Default)]
struct StixLog {
    rows: Vec<StixVersion>,
    /// Content hash per (id, version).
    hash_of: HashMap<(String, String), String>,
    created: HashMap<String, Option<String>>,
    evidence: HashMap<String, i64>,
    /// Every id any version of an object refers to.
    refs: HashMap<String, std::collections::BTreeSet<String>>,
    days: BTreeMap<i64, DayRecord>,
    /// Attempts by (live, day, attempt id).
    attempts: BTreeMap<(bool, i64, String), String>,
    /// Contributions by (live, day, part, ioc id).
    contributions: BTreeMap<(bool, i64, u32, String), String>,
    /// IOCs the last merge published: id to (type, value).
    published: BTreeMap<String, (String, String)>,
    pending: std::collections::BTreeSet<(&'static str, String)>,
    /// `(holder, expires_at)`; `None` when released.
    lease: Option<(String, i64)>,
    /// The lease generation: incremented on every takeover, never reset.
    generation: i64,
    /// Test hook: after this many more fenced writes another run takes
    /// the lease.
    takeover_after: Option<usize>,
}

impl StixLog {
    /// Refuse a write from a run whose lease generation is not current.
    fn fence(&mut self, fence: i64) -> Result<(), StoreError> {
        if let Some(n) = self.takeover_after.as_mut() {
            if *n == 0 {
                self.takeover_after = None;
                self.generation += 1;
                self.lease = Some(("intruder".into(), i64::MAX));
            } else {
                *n -= 1;
            }
        }
        if self.lease.is_some() && self.generation == fence {
            Ok(())
        } else {
            Err(StoreError(format!(
                "stix lease lost: generation {fence}, current {}",
                self.generation
            )))
        }
    }

    fn head(&self, id: &str) -> Option<&StixVersion> {
        self.rows
            .iter()
            .filter(|r| r.id == id)
            .max_by(|a, b| a.version.cmp(&b.version))
    }
}

#[derive(Default)]
pub struct MemoryStore {
    inner: Mutex<Inner>,
}

impl MemoryStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_token(&self, token: TokenRecord) {
        self.lock().tokens.insert(token.id.clone(), token);
    }

    pub fn add_identity(&self, identity: IdentityRecord) {
        self.lock().identities.push(identity);
    }

    /// Certificate identities, for tests.
    pub fn identities(&self) -> Vec<IdentityRecord> {
        self.lock().identities.clone()
    }

    pub fn jobs(&self) -> Vec<JobRecord> {
        self.lock().jobs.clone()
    }

    /// Make every later write-up update recorded as `action` lose its
    /// version check, as a concurrent writer would (tests only).
    pub fn fail_writeup_update_for(&self, action: &str) {
        self.lock().fail_writeup_action = Some(action.to_string());
    }

    /// Make review state rollbacks (a `needs_attention` item written back
    /// to an undecided state) fail (tests only).
    pub fn fail_review_rollback(&self, fail: bool) {
        self.lock().fail_review_rollback = fail;
    }

    /// Campaign actions stored for a tenant (tests).
    pub fn campaign_action_count(&self, tenant_id: &str) -> usize {
        self.lock()
            .campaign_actions
            .iter()
            .filter(|(t, _)| t == tenant_id)
            .count()
    }

    /// Make public page removals fail, or work again (tests only).
    pub fn fail_page_removal(&self, fail: bool) {
        self.lock().fail_page_removal = fail;
    }

    /// Make every later audit append with `action` fail (tests only).
    pub fn fail_audit_for(&self, action: &str) {
        self.lock().fail_audit_action = Some(action.to_string());
    }

    pub fn audit(&self) -> Vec<AuditRecord> {
        self.lock().audit.clone()
    }

    /// Events put on the ingest queue, in order.
    pub fn queued_events(&self) -> Vec<CaptureEvent> {
        self.lock().events.clone()
    }

    /// Last heartbeat and clock skew recorded for a host.
    pub fn heartbeat(&self, tenant_id: &str, host_id: &str) -> Option<(serde_json::Value, i64)> {
        self.lock()
            .heartbeats
            .get(&(tenant_id.to_string(), host_id.to_string()))
            .cloned()
    }

    pub fn decoy(&self, id: &str) -> Option<Decoy> {
        self.lock().decoys.iter().find(|d| d.id == id).cloned()
    }

    /// Test helper: assign a decoy to a host, as the scheduler would.
    pub fn set_host(&self, id: &str, host_id: &str) {
        if let Some(d) = self.lock().decoys.iter_mut().find(|d| d.id == id) {
            d.host_id = Some(host_id.to_string());
        }
    }

    /// Test helper: force a decoy into a state, as a host report would.
    pub fn set_state(&self, id: &str, state: DecoyState) {
        if let Some(d) = self.lock().decoys.iter_mut().find(|d| d.id == id) {
            d.state = state;
        }
    }

    /// Make enrichment cache reads fail, to test graceful degradation.
    pub fn fail_enrichment_reads(&self) {
        self.lock().fail_enrichment = true;
    }

    /// Every enrichment cache row, for tests.
    pub fn cache_entries(&self) -> Vec<CacheEntry> {
        self.lock().cache.clone()
    }

    /// An enrichment cache row, as the `foiled-enrich` consumer would leave
    /// it in D1 (#11). Replaces the row for the same provider and
    /// observable.
    /// Let `writes` more fenced materialiser writes through for this
    /// tenant, then hand its lease to another run (a stalled run's lease
    /// taken over), so the stalled run's later writes are refused.
    pub fn take_over_stix_lease_after(&self, tenant_id: &str, collection: &str, writes: usize) {
        self.lock()
            .stix
            .entry((tenant_id.to_string(), collection.to_string()))
            .or_default()
            .takeover_after = Some(writes);
    }

    pub fn add_cache_entry(&self, entry: CacheEntry) {
        let mut g = self.lock();
        g.cache.retain(|e| e.key() != entry.key());
        g.cache.push(entry);
    }

    /// Stored actor link decisions, every tenant (tests).
    pub fn actor_decisions_for_tests(&self) -> Vec<foiled_core::actor::ActorDecision> {
        self.lock()
            .actor_decisions
            .iter()
            .map(|(_, d)| d.clone())
            .collect()
    }

    /// The campaign registry recorded for a tenant (tests).
    pub fn campaign_registry(&self, tenant_id: &str) -> foiled_core::campaign::Registry {
        self.lock()
            .campaign_registry
            .get(tenant_id)
            .cloned()
            .unwrap_or_default()
    }

    /// Put a stored write-up straight into place (tests: to set up states
    /// the API would refuse, such as a draft holding a public page).
    pub fn force_writeup(&self, w: WriteUp) {
        let mut g = self.lock();
        g.writeups.retain(|x| x.writeup_id != w.writeup_id);
        g.writeups.push(w);
    }

    /// Store a public page directly (tests).
    pub fn force_public_page(&self, tenant_id: &str, writeup_id: &str, page: PublicPage) {
        self.lock()
            .public_pages
            .push((tenant_id.into(), writeup_id.into(), page));
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        // A poisoned lock only happens after a panic in a test; keep going.
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }
}

fn ready<'a, T: Send + 'a>(v: Result<T, StoreError>) -> StoreFuture<'a, T> {
    Box::pin(std::future::ready(v))
}

impl Store for MemoryStore {
    fn events_after(
        &self,
        tenant_id: &str,
        after: (i64, String),
        until: i64,
        limit: usize,
    ) -> StoreFuture<'_, Vec<CaptureEvent>> {
        let mut out: Vec<CaptureEvent> = self
            .lock()
            .events
            .iter()
            .filter(|e| e.tenant_id.as_deref() == Some(tenant_id) && e.ts < until)
            .filter(|e| (e.ts, &e.event_id) > (after.0, &after.1))
            .cloned()
            .collect();
        let source = |e: &CaptureEvent| e.source.as_ref().map(|s| (s.kind, s.id.clone()));
        let mut seen = std::collections::HashSet::new();
        out.retain(|e| seen.insert((source(e), e.event_id.clone())));
        out.sort_by(|a, b| (a.ts, &a.event_id).cmp(&(b.ts, &b.event_id)));
        out.truncate(limit);
        ready(Ok(out))
    }

    fn event_signature(&self, tenant_id: &str, since: i64, until: i64) -> StoreFuture<'_, String> {
        let g = self.lock();
        let (mut n, mut last) = (0usize, 0usize);
        for (i, e) in g.events.iter().enumerate() {
            if e.tenant_id.as_deref() == Some(tenant_id) && e.ts >= since && e.ts < until {
                n += 1;
                last = i + 1;
            }
        }
        ready(Ok(format!("{n}:{last}")))
    }

    fn tenants_with_events(&self, since: i64) -> StoreFuture<'_, Vec<String>> {
        let set: std::collections::BTreeSet<String> = self
            .lock()
            .events
            .iter()
            .filter(|e| e.ts >= since)
            .filter_map(|e| e.tenant_id.clone())
            .collect();
        ready(Ok(set.into_iter().collect()))
    }

    fn stix_history(
        &self,
        tenant_id: &str,
        collection: &str,
        ids: Vec<String>,
    ) -> StoreFuture<'_, BTreeMap<String, History>> {
        let g = self.lock();
        let mut out = BTreeMap::new();
        if let Some(log) = g.stix.get(&(tenant_id.to_string(), collection.to_string())) {
            for id in ids {
                let Some(head) = log.head(&id) else {
                    continue;
                };
                let revoked = serde_json::from_str::<serde_json::Value>(&head.content)
                    .is_ok_and(|v| v["revoked"] == true);
                out.insert(
                    id.clone(),
                    History {
                        created: log.created.get(&id).cloned().flatten(),
                        latest: head.version.clone(),
                        latest_hash: log
                            .hash_of
                            .get(&(id.clone(), head.version.clone()))
                            .cloned()
                            .unwrap_or_default(),
                        revoked,
                    },
                );
            }
        }
        ready(Ok(out))
    }

    fn stix_append(
        &self,
        tenant_id: &str,
        collection: &str,
        versions: Vec<NewVersion>,
        evidence: Vec<Evidence>,
        now: i64,
        fence: i64,
    ) -> StoreFuture<'_, u64> {
        let mut g = self.lock();
        let log = g
            .stix
            .entry((tenant_id.to_string(), collection.to_string()))
            .or_default();
        if let Err(e) = log.fence(fence) {
            return ready(Err(e));
        }
        let newest = log
            .rows
            .iter()
            .map(|r| r.date_added)
            .max()
            .unwrap_or(i64::MIN);
        let date_added = now.max(newest.saturating_add(1));
        // All or nothing, as the Postgres transaction.
        let mut fresh = Vec::new();
        for v in versions {
            let same_as_head = log.head(&v.id).is_some_and(|h| {
                log.hash_of.get(&(v.id.clone(), h.version.clone())) == Some(&v.content_sha256)
            });
            if same_as_head {
                continue;
            }
            if log.hash_of.contains_key(&(v.id.clone(), v.version.clone()))
                || fresh
                    .iter()
                    .any(|f: &NewVersion| f.id == v.id && f.version == v.version)
            {
                return ready(Err(StoreError(format!(
                    "version conflict: {} {} exists",
                    v.id, v.version
                ))));
            }
            fresh.push(v);
        }
        let inserted = fresh.len() as u64;
        for v in fresh {
            log.hash_of
                .insert((v.id.clone(), v.version.clone()), v.content_sha256);
            log.created.entry(v.id.clone()).or_insert(v.created);
            log.refs.entry(v.id.clone()).or_default().extend(v.refs);
            log.rows.push(StixVersion {
                id: v.id,
                object_type: v.object_type,
                version: v.version,
                date_added,
                content: v.content,
            });
        }
        for e in evidence {
            if log.created.contains_key(&e.id) {
                let t = log.evidence.entry(e.id).or_insert(e.evidence_ms);
                *t = (*t).max(e.evidence_ms);
            }
        }
        ready(Ok(inserted))
    }

    fn stix_query(
        &self,
        tenant_id: &str,
        collection: &str,
        q: LogQuery,
    ) -> StoreFuture<'_, Vec<StixVersion>> {
        let g = self.lock();
        let rows = g
            .stix
            .get(&(tenant_id.to_string(), collection.to_string()))
            .map(|log| foiled_core::intel::log::query_rows(&log.rows, &q))
            .unwrap_or_default();
        ready(Ok(rows))
    }

    fn stix_purge(
        &self,
        tenant_id: &str,
        collection: &str,
        evidence_before: i64,
        fence: i64,
    ) -> StoreFuture<'_, u64> {
        let mut g = self.lock();
        let log = g
            .stix
            .entry((tenant_id.to_string(), collection.to_string()))
            .or_default();
        if let Err(e) = log.fence(fence) {
            return ready(Err(e));
        }
        let mut stale: std::collections::HashSet<String> = log
            .created
            .keys()
            .filter(|id| log.evidence.get(*id).copied().unwrap_or(0) < evidence_before)
            .cloned()
            .collect();
        // Keep what an object that stays refers to.
        let kept: std::collections::HashSet<&String> = log
            .refs
            .iter()
            .filter(|(id, _)| !stale.contains(*id))
            .flat_map(|(_, r)| r)
            .collect();
        stale.retain(|id| !kept.contains(id));
        let before = log.rows.len();
        log.rows.retain(|r| !stale.contains(&r.id));
        let removed = (before - log.rows.len()) as u64;
        log.hash_of.retain(|(id, _), _| !stale.contains(id));
        for id in &stale {
            log.created.remove(id);
            log.evidence.remove(id);
            log.refs.remove(id);
        }
        log.days.retain(|d, _| *d >= evidence_before);
        log.attempts.retain(|(_, d, _), _| *d >= evidence_before);
        let mut requeue = Vec::new();
        log.contributions.retain(|(_, d, _, ioc), _| {
            let keep = *d >= evidence_before;
            if !keep {
                requeue.push(ioc.clone());
            }
            keep
        });
        for ioc in requeue {
            log.pending.insert((PendingStep::Merge.as_str(), ioc));
        }
        ready(Ok(removed))
    }

    fn stix_days(
        &self,
        tenant_id: &str,
        collection: &str,
    ) -> StoreFuture<'_, BTreeMap<i64, DayRecord>> {
        let days = self
            .lock()
            .stix
            .get(&(tenant_id.to_string(), collection.to_string()))
            .map(|l| l.days.clone())
            .unwrap_or_default();
        ready(Ok(days))
    }

    fn put_stix_day(
        &self,
        tenant_id: &str,
        collection: &str,
        day_ms: i64,
        record: DayRecord,
        fence: i64,
    ) -> StoreFuture<'_, ()> {
        let mut g = self.lock();
        let log = g
            .stix
            .entry((tenant_id.to_string(), collection.to_string()))
            .or_default();
        if let Err(e) = log.fence(fence) {
            return ready(Err(e));
        }
        log.days.insert(day_ms, record);
        ready(Ok(()))
    }

    fn stix_stage_part(
        &self,
        tenant_id: &str,
        collection: &str,
        day_ms: i64,
        part: u32,
        attempts: Vec<DayAttempt>,
        contributions: Vec<(String, String)>,
        record: DayRecord,
        fence: i64,
    ) -> StoreFuture<'_, ()> {
        let mut g = self.lock();
        let log = g
            .stix
            .entry((tenant_id.to_string(), collection.to_string()))
            .or_default();
        if let Err(e) = log.fence(fence) {
            return ready(Err(e));
        }
        if part == 0 {
            log.attempts.retain(|(live, d, _), _| *live || *d != day_ms);
        }
        log.contributions
            .retain(|(live, d, p, _), _| *live || *d != day_ms || *p < part);
        for a in attempts {
            log.attempts.insert((false, day_ms, a.attempt_id), a.body);
        }
        for (ioc, body) in contributions {
            log.contributions.insert((false, day_ms, part, ioc), body);
        }
        log.days.insert(day_ms, record);
        ready(Ok(()))
    }

    fn stix_promote_day(
        &self,
        tenant_id: &str,
        collection: &str,
        day_ms: i64,
        record: DayRecord,
        fence: i64,
    ) -> StoreFuture<'_, ()> {
        let mut g = self.lock();
        let log = g
            .stix
            .entry((tenant_id.to_string(), collection.to_string()))
            .or_default();
        if let Err(e) = log.fence(fence) {
            return ready(Err(e));
        }
        let mut moved = BTreeMap::new();
        log.contributions.retain(|(live, d, p, ioc), body| {
            if *d != day_ms {
                return true;
            }
            log.pending
                .insert((PendingStep::Merge.as_str(), ioc.clone()));
            if !*live {
                moved.insert((true, *d, *p, ioc.clone()), body.clone());
            }
            false
        });
        log.contributions.extend(moved);
        let mut moved = BTreeMap::new();
        log.attempts.retain(|(live, d, a), body| {
            if *d != day_ms {
                return true;
            }
            if !*live {
                moved.insert((true, *d, a.clone()), body.clone());
            }
            false
        });
        log.attempts.extend(moved);
        log.days.insert(day_ms, record);
        ready(Ok(()))
    }

    fn stix_day_attempts(
        &self,
        tenant_id: &str,
        collection: &str,
        day_ms: i64,
        after: Option<String>,
        limit: usize,
    ) -> StoreFuture<'_, Vec<DayAttempt>> {
        let g = self.lock();
        let out = g
            .stix
            .get(&(tenant_id.to_string(), collection.to_string()))
            .map(|l| {
                l.attempts
                    .iter()
                    .filter(|((live, d, a), _)| {
                        *live && *d == day_ms && after.as_ref().is_none_or(|x| a > x)
                    })
                    .take(limit)
                    .map(|((_, _, a), body)| DayAttempt {
                        attempt_id: a.clone(),
                        body: body.clone(),
                    })
                    .collect()
            })
            .unwrap_or_default();
        ready(Ok(out))
    }

    fn stix_contributions(
        &self,
        tenant_id: &str,
        collection: &str,
        ioc_ids: Vec<String>,
    ) -> StoreFuture<'_, Vec<(String, i64, String)>> {
        let g = self.lock();
        let wanted: std::collections::HashSet<String> = ioc_ids.into_iter().collect();
        let out = g
            .stix
            .get(&(tenant_id.to_string(), collection.to_string()))
            .map(|l| {
                l.contributions
                    .iter()
                    .filter(|((live, _, _, ioc), _)| *live && wanted.contains(ioc))
                    .map(|((_, d, _, ioc), body)| (ioc.clone(), *d, body.clone()))
                    .collect()
            })
            .unwrap_or_default();
        ready(Ok(out))
    }

    fn stix_published(
        &self,
        tenant_id: &str,
        collection: &str,
        ioc_ids: Vec<String>,
    ) -> StoreFuture<'_, Vec<PublishedIoc>> {
        let g = self.lock();
        let out = g
            .stix
            .get(&(tenant_id.to_string(), collection.to_string()))
            .map(|l| {
                ioc_ids
                    .into_iter()
                    .filter_map(|id| {
                        l.published
                            .get(&id)
                            .map(|(t, v)| (id.clone(), t.clone(), v.clone()))
                    })
                    .collect()
            })
            .unwrap_or_default();
        ready(Ok(out))
    }

    fn stix_set_published(
        &self,
        tenant_id: &str,
        collection: &str,
        add: Vec<PublishedIoc>,
        remove: Vec<String>,
        fence: i64,
    ) -> StoreFuture<'_, ()> {
        let mut g = self.lock();
        let log = g
            .stix
            .entry((tenant_id.to_string(), collection.to_string()))
            .or_default();
        if let Err(e) = log.fence(fence) {
            return ready(Err(e));
        }
        for id in remove {
            log.published.remove(&id);
        }
        for (id, t, v) in add {
            log.published.insert(id, (t, v));
        }
        ready(Ok(()))
    }

    fn stix_pending(
        &self,
        tenant_id: &str,
        collection: &str,
        step: PendingStep,
        limit: usize,
    ) -> StoreFuture<'_, Vec<String>> {
        let g = self.lock();
        let out = g
            .stix
            .get(&(tenant_id.to_string(), collection.to_string()))
            .map(|l| {
                l.pending
                    .iter()
                    .filter(|(s, _)| *s == step.as_str())
                    .take(limit)
                    .map(|(_, id)| id.clone())
                    .collect()
            })
            .unwrap_or_default();
        ready(Ok(out))
    }

    fn stix_pending_move(
        &self,
        tenant_id: &str,
        collection: &str,
        ids: Vec<String>,
        from: PendingStep,
        to: Option<PendingStep>,
        fence: i64,
    ) -> StoreFuture<'_, ()> {
        let mut g = self.lock();
        let log = g
            .stix
            .entry((tenant_id.to_string(), collection.to_string()))
            .or_default();
        if let Err(e) = log.fence(fence) {
            return ready(Err(e));
        }
        for id in ids {
            log.pending.remove(&(from.as_str(), id.clone()));
            if let Some(t) = to {
                log.pending.insert((t.as_str(), id));
            }
        }
        ready(Ok(()))
    }

    fn stix_lease(
        &self,
        tenant_id: &str,
        collection: &str,
        holder: &str,
        now: i64,
        ttl_ms: i64,
    ) -> StoreFuture<'_, Option<i64>> {
        let mut g = self.lock();
        let log = g
            .stix
            .entry((tenant_id.to_string(), collection.to_string()))
            .or_default();
        let out = match &log.lease {
            Some((h, _)) if h == holder => {
                log.lease = Some((holder.to_string(), now + ttl_ms));
                Some(log.generation)
            }
            Some((_, exp)) if *exp >= now => None,
            _ => {
                log.generation += 1;
                log.lease = Some((holder.to_string(), now + ttl_ms));
                Some(log.generation)
            }
        };
        ready(Ok(out))
    }

    fn stix_release(&self, tenant_id: &str, collection: &str, holder: &str) -> StoreFuture<'_, ()> {
        let mut g = self.lock();
        if let Some(log) = g
            .stix
            .get_mut(&(tenant_id.to_string(), collection.to_string()))
            && log.lease.as_ref().is_some_and(|(h, _)| h == holder)
        {
            log.lease = None;
        }
        ready(Ok(()))
    }

    fn stix_tenants(&self, collection: &str) -> StoreFuture<'_, Vec<String>> {
        let tenants: Vec<String> = self
            .lock()
            .stix
            .iter()
            .filter(|((_, c), log)| {
                c == collection
                    && !(log.created.is_empty() && log.days.is_empty() && log.pending.is_empty())
            })
            .map(|((t, _), _)| t.clone())
            .collect();
        ready(Ok(tenants))
    }

    fn stix_cron_cursor(&self, collection: &str) -> StoreFuture<'_, Option<String>> {
        ready(Ok(self.lock().stix_cron.get(collection).cloned()))
    }

    fn put_stix_cron_cursor(&self, collection: &str, tenant_id: &str) -> StoreFuture<'_, ()> {
        self.lock()
            .stix_cron
            .insert(collection.to_string(), tenant_id.to_string());
        ready(Ok(()))
    }

    fn stix_day_inputs(
        &self,
        tenant_id: &str,
        collection: &str,
        day_ms: i64,
        now: i64,
    ) -> StoreFuture<'_, String> {
        use sha2::{Digest, Sha256};
        let g = self.lock();
        let Some(log) = g.stix.get(&(tenant_id.to_string(), collection.to_string())) else {
            return ready(Ok(String::new()));
        };
        let attempts: std::collections::BTreeSet<&String> = log
            .attempts
            .keys()
            .filter(|(live, d, _)| *live && *d == day_ms)
            .map(|(_, _, a)| a)
            .collect();
        let mut h = Sha256::new();
        for (t, o) in &g.overrides {
            if t == tenant_id && attempts.contains(&o.attempt_id) {
                h.update(format!(
                    "o|{}|{:?}|{}|{:?}\n",
                    o.attempt_id, o.kind, o.target, o.decision
                ));
            }
        }
        let mut campaigns = std::collections::BTreeSet::new();
        if let Some(r) = g.campaign_registry.get(tenant_id) {
            for a in &attempts {
                if let Some(c) = r.members.get(*a) {
                    h.update(format!("m|{a}|{c}\n"));
                    campaigns.insert(c.clone());
                }
            }
            for c in &campaigns {
                if let Some(rec) = r.campaigns.get(c) {
                    h.update(format!("c|{rec:?}\n"));
                }
            }
        }
        for (t, a) in &g.campaign_actions {
            if t == tenant_id && campaigns.contains(&a.campaign_id) {
                h.update(format!("a|{a:?}\n"));
            }
        }
        // Enrichment for the day's addresses.
        let addresses: std::collections::BTreeSet<String> = log
            .contributions
            .iter()
            .filter(|((live, d, _, _), _)| *live && *d == day_ms)
            .filter_map(|(_, body)| {
                let v: serde_json::Value = serde_json::from_str(body).ok()?;
                matches!(v["ioc_type"].as_str(), Some("ip" | "ipv6"))
                    .then(|| v["value"].as_str().map(str::to_string))
                    .flatten()
            })
            .collect();
        for e in &g.cache {
            if e.tenant_id.as_deref().is_none_or(|t| t == tenant_id)
                && matches!(e.observable.kind.as_str(), "ip")
                && addresses.contains(&e.observable.value)
                && e.is_fresh(now)
            {
                h.update(format!("e|{}\n", crate::routes::taxii::cache_row_input(e)));
            }
        }
        ready(Ok(hex::encode(h.finalize())))
    }

    fn token(&self, id: &str) -> StoreFuture<'_, Option<TokenRecord>> {
        ready(Ok(self.lock().tokens.get(id).cloned()))
    }

    fn identity_by_cert(&self, cert_sha256: &str) -> StoreFuture<'_, Option<IdentityRecord>> {
        let found = self
            .lock()
            .identities
            .iter()
            .find(|i| i.cert_sha256 == cert_sha256)
            .cloned();
        ready(Ok(found))
    }

    fn create_decoy(&self, decoy: Decoy, job: JobRecord) -> StoreFuture<'_, ()> {
        let mut g = self.lock();
        if g.decoys.iter().any(|d| d.id == decoy.id) {
            return ready(Err(StoreError(format!("decoy {} exists", decoy.id))));
        }
        g.decoys.push(decoy);
        g.jobs.push(job);
        ready(Ok(()))
    }

    fn get_decoy(&self, tenant_id: &str, id: &str) -> StoreFuture<'_, Option<Decoy>> {
        let found = self
            .lock()
            .decoys
            .iter()
            .find(|d| d.tenant_id == tenant_id && d.id == id)
            .cloned();
        ready(Ok(found))
    }

    fn list_decoys(&self, tenant_id: &str, q: DecoyQuery) -> StoreFuture<'_, Vec<Decoy>> {
        let g = self.lock();
        let mut all: Vec<Decoy> = g
            .decoys
            .iter()
            .filter(|d| d.tenant_id == tenant_id)
            .filter(|d| q.state.is_none_or(|s| d.state == s))
            .filter(|d| {
                q.catalogue_id
                    .as_deref()
                    .is_none_or(|c| d.catalogue_id == c)
            })
            .filter(|d| q.created_by.as_deref().is_none_or(|c| d.created_by == c))
            .filter(|d| !q.live || d.state != DecoyState::Destroyed)
            .cloned()
            .collect();
        all.sort_by(|a, b| (b.created_at, &b.id).cmp(&(a.created_at, &a.id)));
        if let Some(cursor) = &q.cursor
            && let Some(pos) = all.iter().position(|d| &d.id == cursor)
        {
            all.drain(..=pos);
        }
        all.truncate(q.limit);
        ready(Ok(all))
    }

    fn count_live_decoys(&self, tenant_id: &str) -> StoreFuture<'_, u32> {
        let n = self
            .lock()
            .decoys
            .iter()
            .filter(|d| d.tenant_id == tenant_id && d.state != DecoyState::Destroyed)
            .count();
        ready(Ok(n as u32))
    }

    fn insert_job(&self, job: JobRecord) -> StoreFuture<'_, ()> {
        self.lock().jobs.push(job);
        ready(Ok(()))
    }

    fn job_by_idempotency_key(
        &self,
        tenant_id: &str,
        key: &str,
    ) -> StoreFuture<'_, Option<JobRecord>> {
        let found = self
            .lock()
            .jobs
            .iter()
            .find(|j| j.tenant_id == tenant_id && j.idempotency_key == key)
            .cloned();
        ready(Ok(found))
    }

    fn rate_limit(&self, key: &str, window_start: i64, limit: u32) -> StoreFuture<'_, bool> {
        let mut g = self.lock();
        let count = g.rate.entry((key.to_string(), window_start)).or_insert(0);
        *count += 1;
        ready(Ok(*count <= limit))
    }

    fn rate_count(&self, key: &str, window_start: i64) -> StoreFuture<'_, u32> {
        let n = self
            .lock()
            .rate
            .get(&(key.to_string(), window_start))
            .copied()
            .unwrap_or(0);
        ready(Ok(n))
    }

    fn append_audit(&self, record: AuditRecord) -> StoreFuture<'_, ()> {
        let mut g = self.lock();
        if g.fail_audit_action.as_deref() == Some(record.action.as_str()) {
            return ready(Err(StoreError("audit unavailable".into())));
        }
        g.audit.push(record);
        drop(g);
        ready(Ok(()))
    }

    fn list_audit(&self, tenant_id: &str, q: AuditQuery) -> StoreFuture<'_, Vec<AuditRecord>> {
        let g = self.lock();
        let mut out: Vec<AuditRecord> = g
            .audit
            .iter()
            .filter(|a| a.tenant_id == tenant_id)
            .filter(|a| q.action.as_deref().is_none_or(|x| a.action == x))
            .filter(|a| {
                q.target
                    .as_deref()
                    .is_none_or(|x| a.target.as_deref() == Some(x))
            })
            .filter(|a| {
                q.before
                    .as_ref()
                    .is_none_or(|(ts, id)| (a.ts, &a.id) < (*ts, id))
            })
            .cloned()
            .collect();
        out.sort_by(|a, b| b.ts.cmp(&a.ts).then_with(|| b.id.cmp(&a.id)));
        out.truncate(q.limit);
        ready(Ok(out))
    }

    fn enqueue_events(&self, events: Vec<CaptureEvent>) -> StoreFuture<'_, ()> {
        self.lock().events.extend(events);
        ready(Ok(()))
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
        let mut g = self.lock();
        let mut leased = Vec::new();
        let mut placed = Vec::new();
        let mut order: Vec<usize> = (0..g.jobs.len()).collect();
        order.sort_by_key(|&i| (g.jobs[i].created_at, g.jobs[i].id.clone()));
        for i in order {
            if leased.len() >= limit {
                break;
            }
            let j = &mut g.jobs[i];
            let mine = match j.host_id.as_deref() {
                Some(h) => h == host_id,
                None => take_unplaced,
            };
            let available = j.status == "queued"
                || (j.status == "leased" && j.leased_until.is_some_and(|t| t <= now));
            if j.tenant_id != tenant_id || !mine || !available || j.expires_at <= now {
                continue;
            }
            if j.host_id.is_none() {
                placed.push(j.decoy_id.clone());
            }
            j.host_id = Some(host_id.to_string());
            j.status = "leased".into();
            j.leased_until = Some(now + lease_ms);
            leased.push(j.clone());
        }
        for d in g.decoys.iter_mut() {
            if d.tenant_id == tenant_id && d.host_id.is_none() && placed.contains(&d.id) {
                d.host_id = Some(host_id.to_string());
            }
        }
        ready(Ok(leased))
    }

    fn finish_job(
        &self,
        tenant_id: &str,
        host_id: &str,
        job_id: &str,
        status: &str,
    ) -> StoreFuture<'_, Option<JobRecord>> {
        let mut g = self.lock();
        let found = g.jobs.iter_mut().find(|j| {
            j.tenant_id == tenant_id
                && j.id == job_id
                && j.host_id.as_deref() == Some(host_id)
                && j.status == "leased"
        });
        let out = found.map(|j| {
            j.status = status.to_string();
            j.leased_until = None;
            j.clone()
        });
        ready(Ok(out))
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
        let mut g = self.lock();
        let d = g
            .decoys
            .iter_mut()
            .find(|d| d.tenant_id == tenant_id && d.id == decoy_id && d.state == from);
        let ok = match d {
            Some(d) => {
                d.state = to;
                d.updated_at = now;
                if bump_generation {
                    d.generation += 1;
                }
                true
            }
            None => false,
        };
        ready(Ok(ok))
    }

    fn record_heartbeat(
        &self,
        tenant_id: &str,
        host_id: &str,
        heartbeat: serde_json::Value,
        clock_skew_ms: i64,
        _now: i64,
    ) -> StoreFuture<'_, ()> {
        self.lock().heartbeats.insert(
            (tenant_id.to_string(), host_id.to_string()),
            (heartbeat, clock_skew_ms),
        );
        ready(Ok(()))
    }

    fn ip_iocs(&self, tenant_id: &str, since: i64) -> StoreFuture<'_, Vec<IpIocRow>> {
        use std::collections::BTreeMap;
        let g = self.lock();
        let mut rows: BTreeMap<String, IpIocRow> = BTreeMap::new();
        for e in g
            .events
            .iter()
            .filter(|e| e.tenant_id.as_deref() == Some(tenant_id) && e.ts >= since)
        {
            let r = rows.entry(e.src.ip.clone()).or_insert_with(|| IpIocRow {
                ip: e.src.ip.clone(),
                first_seen: e.ts,
                last_seen: e.ts,
                events: 0,
                decoy_ids: vec![],
                catalogue_ids: vec![],
                hook_cves: vec![],
            });
            r.first_seen = r.first_seen.min(e.ts);
            r.last_seen = r.last_seen.max(e.ts);
            r.events += 1;
            for (list, v) in [
                (&mut r.decoy_ids, Some(&e.decoy_id)),
                (&mut r.catalogue_ids, Some(&e.catalogue_id)),
                (
                    &mut r.hook_cves,
                    e.hook.as_ref().and_then(|h| h.cve_id.as_ref()),
                ),
            ] {
                if let Some(v) = v
                    && !list.contains(v)
                {
                    list.push(v.clone());
                    list.sort();
                }
            }
        }
        let mut out: Vec<IpIocRow> = rows.into_values().collect();
        out.sort_by(|a, b| (a.first_seen, &a.ip).cmp(&(b.first_seen, &b.ip)));
        ready(Ok(out))
    }

    fn enrichment_cache(
        &self,
        observables: Vec<Observable>,
        now_ms: i64,
        max_statements: usize,
        tenant_id: Option<String>,
    ) -> StoreFuture<'_, Vec<CacheEntry>> {
        // The same plan and rows as the D1 store: the observables the
        // statement budget covers, matching rows that are still fresh.
        let plan = crate::d1_sql::enrich_lookup_plan(&observables, max_statements);
        let wanted = |e: &CacheEntry| {
            plan.iter().any(|(kind, values)| {
                *kind == e.observable.kind.as_str() && values.contains(&e.observable.value)
            })
        };
        if self.lock().fail_enrichment {
            return ready(Err(StoreError("enrichment cache unavailable".into())));
        }
        let out = self
            .lock()
            .cache
            .iter()
            .filter(|e| wanted(e) && e.is_fresh(now_ms))
            .filter(|e| e.tenant_id.is_none() || e.tenant_id == tenant_id)
            .cloned()
            .collect();
        ready(Ok(out))
    }

    fn upsert_enrich_cache(&self, entry: CacheEntry) -> StoreFuture<'_, ()> {
        if self.lock().fail_enrichment {
            return ready(Err(StoreError("enrichment cache unavailable".into())));
        }
        self.add_cache_entry(entry);
        ready(Ok(()))
    }

    fn take_enrich_budget(
        &self,
        provider: &str,
        now_ms: i64,
        per_minute: u32,
        per_day: u32,
    ) -> StoreFuture<'_, BudgetOutcome> {
        let (minute, day) = crate::d1_sql::budget_windows(now_ms);
        let mut g = self.lock();
        let m = g
            .budget
            .entry((provider.to_string(), "minute", minute))
            .or_default();
        if *m >= per_minute {
            return ready(Ok(BudgetOutcome::MinuteSpent));
        }
        *m += 1;
        let d = g
            .budget
            .entry((provider.to_string(), "day", day))
            .or_default();
        if *d >= per_day {
            // Give the minute unit back, as the D1 store does.
            if let Some(m) = g.budget.get_mut(&(provider.to_string(), "minute", minute)) {
                *m -= 1;
            }
            return ready(Ok(BudgetOutcome::DaySpent));
        }
        *d += 1;
        ready(Ok(BudgetOutcome::Taken))
    }

    fn enrich_failures(
        &self,
        observable: Observable,
    ) -> StoreFuture<'_, Vec<ProviderFailureRecord>> {
        let out = self
            .lock()
            .failures
            .iter()
            .filter(|f| f.observable == observable)
            .cloned()
            .collect();
        ready(Ok(out))
    }

    fn record_enrich_failure(
        &self,
        provider: &str,
        observable: Observable,
        now_ms: i64,
        _error: String,
        retry_at: Option<i64>,
    ) -> StoreFuture<'_, ()> {
        let mut g = self.lock();
        match g
            .failures
            .iter_mut()
            .find(|f| f.provider == provider && f.observable == observable)
        {
            Some(f) => {
                f.failures += 1;
                f.last_failed_at = now_ms;
                f.retry_at = retry_at;
            }
            None => g.failures.push(ProviderFailureRecord {
                provider: provider.to_string(),
                observable,
                failures: 1,
                last_failed_at: now_ms,
                retry_at,
            }),
        }
        ready(Ok(()))
    }

    fn clear_enrich_failure(&self, provider: &str, observable: Observable) -> StoreFuture<'_, ()> {
        self.lock()
            .failures
            .retain(|f| !(f.provider == provider && f.observable == observable));
        ready(Ok(()))
    }

    fn purge_enrichment(&self, plan: EnrichPurgePlan) -> StoreFuture<'_, EnrichPurgeCounts> {
        let mut g = self.lock();
        let batch = plan.batch as usize;
        // Remove at most `batch` items matching `doomed`, like the SQL.
        fn take<T>(items: &mut Vec<T>, batch: usize, doomed: impl Fn(&T) -> bool) -> u64 {
            let mut n = 0;
            items.retain(|i| {
                if n < batch && doomed(i) {
                    n += 1;
                    false
                } else {
                    true
                }
            });
            n as u64
        }
        let mut counts = EnrichPurgeCounts {
            expired: take(&mut g.cache, batch, |e| !e.is_fresh(plan.now_ms)),
            ..EnrichPurgeCounts::default()
        };
        if let Some(r) = &plan.retention {
            for (provider, before) in &r.providers {
                counts.past_retention += take(&mut g.cache, batch, |e| {
                    &e.provider == provider && e.fetched_at <= *before
                });
            }
            counts.past_retention += take(&mut g.cache, batch, |e| {
                !r.providers.iter().any(|(p, _)| p == &e.provider)
                    && e.fetched_at <= r.default_before
            });
        }
        counts.failures = take(&mut g.failures, batch, |f| {
            f.last_failed_at <= plan.failures_before
                && f.retry_at.is_none_or(|at| at <= plan.now_ms)
        });
        ready(Ok(counts))
    }

    fn events_between(
        &self,
        tenant_id: &str,
        since: i64,
        until: i64,
        limit: usize,
    ) -> StoreFuture<'_, Vec<CaptureEvent>> {
        let mut out: Vec<CaptureEvent> = self
            .lock()
            .events
            .iter()
            .filter(|e| e.tenant_id.as_deref() == Some(tenant_id) && e.ts >= since && e.ts < until)
            .cloned()
            .collect();
        // One row per (tenant, sending identity, event_id), as in Postgres:
        // one sensor cannot pre-claim another sensor's event ids.
        let source = |e: &CaptureEvent| e.source.as_ref().map(|s| (s.kind, s.id.clone()));
        let mut seen = std::collections::HashSet::new();
        out.retain(|e| seen.insert((source(e), e.event_id.clone())));
        out.sort_by(|a, b| (a.ts, &a.event_id).cmp(&(b.ts, &b.event_id)));
        out.truncate(limit);
        ready(Ok(out))
    }

    fn link_overrides(
        &self,
        tenant_id: &str,
        attempt_id: &str,
    ) -> StoreFuture<'_, Vec<LinkOverride>> {
        let out = self
            .lock()
            .overrides
            .iter()
            .filter(|(t, o)| t == tenant_id && o.attempt_id == attempt_id)
            .map(|(_, o)| o.clone())
            .collect();
        ready(Ok(out))
    }

    fn campaign_actions(
        &self,
        tenant_id: &str,
        feedback_limit: usize,
    ) -> StoreFuture<'_, Vec<foiled_core::campaign::CampaignAction>> {
        let mut out: Vec<_> = self
            .lock()
            .campaign_actions
            .iter()
            .filter(|(t, _)| t == tenant_id)
            .map(|(_, a)| a.clone())
            .collect();
        out.sort_by(|a, b| (a.at, &a.action_id).cmp(&(b.at, &b.action_id)));
        let feedback = out.iter().filter(|a| !a.is_structural()).count();
        let mut shed = feedback.saturating_sub(feedback_limit);
        out.retain(|a| {
            if !a.is_structural() && shed > 0 {
                shed -= 1;
                return false;
            }
            true
        });
        ready(Ok(out))
    }

    fn campaign_memberships(
        &self,
        tenant_id: &str,
        attempt_ids: Vec<String>,
    ) -> StoreFuture<'_, Vec<(String, String)>> {
        let g = self.lock();
        let out = g
            .campaign_registry
            .get(tenant_id)
            .map(|r| {
                attempt_ids
                    .into_iter()
                    .filter_map(|a| r.members.get(&a).map(|c| (a.clone(), c.clone())))
                    .collect()
            })
            .unwrap_or_default();
        ready(Ok(out))
    }

    fn campaign_records(
        &self,
        tenant_id: &str,
        campaign_ids: Vec<String>,
    ) -> StoreFuture<'_, Vec<foiled_core::campaign::StoredCampaign>> {
        let g = self.lock();
        let out = g
            .campaign_registry
            .get(tenant_id)
            .map(|r| {
                campaign_ids
                    .iter()
                    .filter_map(|c| r.campaigns.get(c).cloned())
                    .collect()
            })
            .unwrap_or_default();
        ready(Ok(out))
    }

    fn campaign_bridges(
        &self,
        tenant_id: &str,
        campaign_id: &str,
    ) -> StoreFuture<'_, Vec<foiled_core::campaign::BridgeRecord>> {
        let out = self
            .lock()
            .campaign_registry
            .get(tenant_id)
            .map(|r| {
                r.bridges
                    .iter()
                    .filter(|b| b.campaign_id == campaign_id)
                    .cloned()
                    .collect()
            })
            .unwrap_or_default();
        ready(Ok(out))
    }

    fn update_campaign_registry(
        &self,
        tenant_id: &str,
        update: foiled_core::campaign::RegistryUpdate,
        _now: i64,
    ) -> StoreFuture<'_, ()> {
        self.lock()
            .campaign_registry
            .entry(tenant_id.to_string())
            .or_default()
            .apply(&update);
        ready(Ok(()))
    }

    fn append_campaign_action(
        &self,
        tenant_id: &str,
        action: foiled_core::campaign::CampaignAction,
    ) -> StoreFuture<'_, ()> {
        let mut g = self.lock();
        if g.campaign_actions
            .iter()
            .any(|(t, a)| t == tenant_id && a.action_id == action.action_id)
        {
            return ready(Err(StoreError("duplicate campaign action".into())));
        }
        g.campaign_actions.push((tenant_id.to_string(), action));
        ready(Ok(()))
    }

    fn link_overrides_many(
        &self,
        tenant_id: &str,
        attempt_ids: Vec<String>,
    ) -> StoreFuture<'_, Vec<LinkOverride>> {
        let wanted: std::collections::HashSet<String> = attempt_ids.into_iter().collect();
        let out = self
            .lock()
            .overrides
            .iter()
            .filter(|(t, o)| t == tenant_id && wanted.contains(&o.attempt_id))
            .map(|(_, o)| o.clone())
            .collect();
        ready(Ok(out))
    }

    fn review_states(
        &self,
        tenant_id: &str,
        item_ids: Vec<String>,
    ) -> StoreFuture<'_, Vec<ReviewState>> {
        let g = self.lock();
        let out = item_ids
            .into_iter()
            .filter_map(|i| g.review_states.get(&(tenant_id.to_string(), i)).cloned())
            .collect();
        ready(Ok(out))
    }

    fn put_review_state(
        &self,
        tenant_id: &str,
        state: ReviewState,
        expected: u32,
    ) -> StoreFuture<'_, bool> {
        let mut g = self.lock();
        let key = (tenant_id.to_string(), state.item_id.clone());
        if g.fail_review_rollback
            && !state.status.decided()
            && g.review_states
                .get(&key)
                .is_some_and(|s| s.status == foiled_core::review::ReviewStatus::NeedsAttention)
        {
            return ready(Err(StoreError("review state unavailable".into())));
        }
        let current = g.review_states.get(&key).map_or(0, |s| s.version);
        if current != expected {
            return ready(Ok(false));
        }
        g.review_states.insert(key, state);
        ready(Ok(true))
    }

    fn insert_writeup(&self, w: WriteUp, actor_id: &str) -> StoreFuture<'_, ()> {
        let mut g = self.lock();
        if g.writeups.iter().any(|x| x.writeup_id == w.writeup_id) {
            return ready(Err(StoreError("duplicate write-up".into())));
        }
        g.writeup_versions.push((
            w.tenant_id.clone(),
            WriteUpVersion {
                writeup: w.clone(),
                action: "create".into(),
                actor_id: actor_id.into(),
                at: w.updated_at,
            },
        ));
        g.writeups.push(w);
        ready(Ok(()))
    }

    fn get_writeup(&self, tenant_id: &str, writeup_id: &str) -> StoreFuture<'_, Option<WriteUp>> {
        let found = self
            .lock()
            .writeups
            .iter()
            .find(|w| w.tenant_id == tenant_id && w.writeup_id == writeup_id)
            .cloned();
        ready(Ok(found))
    }

    fn list_writeups(
        &self,
        tenant_id: &str,
        status: Option<WriteUpStatus>,
        limit: usize,
    ) -> StoreFuture<'_, Vec<WriteUp>> {
        let mut out: Vec<WriteUp> = self
            .lock()
            .writeups
            .iter()
            .filter(|w| w.tenant_id == tenant_id && status.is_none_or(|s| w.status == s))
            .cloned()
            .collect();
        out.sort_by(|a, b| (b.updated_at, &b.writeup_id).cmp(&(a.updated_at, &a.writeup_id)));
        out.truncate(limit);
        ready(Ok(out))
    }

    fn update_writeup(
        &self,
        w: WriteUp,
        expected: u32,
        action: &str,
        actor_id: &str,
    ) -> StoreFuture<'_, bool> {
        let mut g = self.lock();
        if g.fail_writeup_action.as_deref() == Some(action) {
            return ready(Ok(false));
        }
        let Some(pos) = g
            .writeups
            .iter()
            .position(|x| x.tenant_id == w.tenant_id && x.writeup_id == w.writeup_id)
        else {
            return ready(Ok(false));
        };
        if g.writeups[pos].version != expected {
            return ready(Ok(false));
        }
        g.writeup_versions.push((
            w.tenant_id.clone(),
            WriteUpVersion {
                writeup: w.clone(),
                action: action.into(),
                actor_id: actor_id.into(),
                at: w.updated_at,
            },
        ));
        g.writeups[pos] = w;
        ready(Ok(true))
    }

    fn writeup_versions(
        &self,
        tenant_id: &str,
        writeup_id: &str,
    ) -> StoreFuture<'_, Vec<WriteUpVersion>> {
        let out = self
            .lock()
            .writeup_versions
            .iter()
            .filter(|(t, v)| t == tenant_id && v.writeup.writeup_id == writeup_id)
            .map(|(_, v)| v.clone())
            .collect();
        ready(Ok(out))
    }

    fn put_public_page(
        &self,
        tenant_id: &str,
        writeup_id: &str,
        page: PublicPage,
    ) -> StoreFuture<'_, bool> {
        let mut g = self.lock();
        if g.public_pages
            .iter()
            .any(|(_, w, p)| p.slug == page.slug && w != writeup_id)
        {
            return ready(Ok(false));
        }
        // Written by version: an older snapshot never replaces a newer one.
        if g.public_pages
            .iter()
            .any(|(t, w, p)| t == tenant_id && w == writeup_id && p.version > page.version)
        {
            return ready(Ok(true));
        }
        g.public_pages
            .retain(|(t, w, _)| !(t == tenant_id && w == writeup_id));
        g.public_pages
            .push((tenant_id.into(), writeup_id.into(), page));
        ready(Ok(true))
    }

    fn remove_public_page(&self, tenant_id: &str, writeup_id: &str) -> StoreFuture<'_, ()> {
        if self.lock().fail_page_removal {
            return ready(Err(StoreError("page store unavailable".into())));
        }
        self.lock()
            .public_pages
            .retain(|(t, w, _)| !(t == tenant_id && w == writeup_id));
        ready(Ok(()))
    }

    fn public_page(&self, slug: &str, now: i64) -> StoreFuture<'_, Option<PublicPage>> {
        let found = self
            .lock()
            .public_pages
            .iter()
            .find(|(_, _, p)| p.slug == slug && p.visible_from <= now)
            .map(|(_, _, p)| p.clone());
        ready(Ok(found))
    }

    fn public_pages(&self, now: i64, limit: usize) -> StoreFuture<'_, Vec<PublicPageSummary>> {
        let mut out: Vec<PublicPageSummary> = self
            .lock()
            .public_pages
            .iter()
            .filter(|(_, _, p)| p.visible_from <= now)
            .map(|(_, _, p)| p.summary_row())
            .collect();
        out.sort_by(|a, b| (b.visible_from, &b.slug).cmp(&(a.visible_from, &a.slug)));
        out.truncate(limit);
        ready(Ok(out))
    }

    fn put_radar_points(
        &self,
        tenant_id: &str,
        day: i64,
        points: Vec<RadarPoint>,
    ) -> StoreFuture<'_, ()> {
        let mut g = self.lock();
        g.radar
            .retain(|p| !(p.tenant_id == tenant_id && p.day == day));
        g.radar.extend(
            points
                .into_iter()
                .filter(|p| p.tenant_id == tenant_id && p.day == day),
        );
        ready(Ok(()))
    }

    fn radar_points(
        &self,
        tenant_id: Option<&str>,
        since: i64,
        until: i64,
        limit: usize,
    ) -> StoreFuture<'_, Vec<RadarPoint>> {
        let mut out: Vec<RadarPoint> = self
            .lock()
            .radar
            .iter()
            .filter(|p| tenant_id.is_none_or(|t| p.tenant_id == t))
            .filter(|p| p.day >= since && p.day < until)
            .cloned()
            .collect();
        out.truncate(limit);
        ready(Ok(out))
    }

    fn put_link_override(&self, tenant_id: &str, o: LinkOverride) -> StoreFuture<'_, ()> {
        let mut g = self.lock();
        g.overrides.retain(|(t, x)| {
            !(t == tenant_id
                && x.attempt_id == o.attempt_id
                && x.kind == o.kind
                && x.target == o.target)
        });
        g.overrides.push((tenant_id.to_string(), o));
        ready(Ok(()))
    }

    fn actor_decisions(
        &self,
        tenant_id: &str,
        subject_ids: Vec<String>,
    ) -> StoreFuture<'_, Vec<foiled_core::actor::ActorDecision>> {
        let wanted: std::collections::HashSet<String> = subject_ids.into_iter().collect();
        let out = self
            .lock()
            .actor_decisions
            .iter()
            .filter(|(t, d)| t == tenant_id && wanted.contains(&d.subject_id))
            .map(|(_, d)| d.clone())
            .collect();
        ready(Ok(out))
    }

    fn put_actor_decision(
        &self,
        tenant_id: &str,
        d: foiled_core::actor::ActorDecision,
    ) -> StoreFuture<'_, ()> {
        let mut g = self.lock();
        g.actor_decisions.retain(|(t, x)| {
            !(t == tenant_id && x.subject_id == d.subject_id && x.actor_id == d.actor_id)
        });
        g.actor_decisions.push((tenant_id.to_string(), d));
        ready(Ok(()))
    }

    fn create_agent(&self, agent: AgentRecord, token: EnrolmentTokenRecord) -> StoreFuture<'_, ()> {
        let mut g = self.lock();
        if g.agents.iter().any(|a| a.id == agent.id) {
            return ready(Err(StoreError(format!("agent {} exists", agent.id))));
        }
        g.agents.push(agent);
        g.enrolment_tokens.push(token);
        ready(Ok(()))
    }

    fn get_agent(
        &self,
        tenant_id: &str,
        role: Role,
        id: &str,
    ) -> StoreFuture<'_, Option<AgentRecord>> {
        let found = self
            .lock()
            .agents
            .iter()
            .find(|a| a.tenant_id == tenant_id && a.role == role && a.id == id)
            .cloned();
        ready(Ok(found))
    }

    fn list_agents(
        &self,
        tenant_id: &str,
        role: Role,
        q: AgentQuery,
    ) -> StoreFuture<'_, Vec<AgentRecord>> {
        let mut all: Vec<AgentRecord> = self
            .lock()
            .agents
            .iter()
            .filter(|a| a.tenant_id == tenant_id && a.role == role)
            .cloned()
            .collect();
        all.sort_by(|a, b| (b.created_at, &b.id).cmp(&(a.created_at, &a.id)));
        if let Some(cursor) = &q.cursor
            && let Some(pos) = all.iter().position(|a| &a.id == cursor)
        {
            all.drain(..=pos);
        }
        all.truncate(q.limit);
        ready(Ok(all))
    }

    fn replace_enrolment_token(
        &self,
        token: EnrolmentTokenRecord,
        now: i64,
    ) -> StoreFuture<'_, ()> {
        let mut g = self.lock();
        for t in g.enrolment_tokens.iter_mut() {
            if t.tenant_id == token.tenant_id && t.agent_id == token.agent_id && t.used_at.is_none()
            {
                t.used_at = Some(now);
            }
        }
        g.enrolment_tokens.push(token);
        ready(Ok(()))
    }

    fn enrolment_token(&self, id: &str) -> StoreFuture<'_, Option<EnrolmentTokenRecord>> {
        let found = self
            .lock()
            .enrolment_tokens
            .iter()
            .find(|t| t.id == id)
            .cloned();
        ready(Ok(found))
    }

    fn consume_enrolment_token(&self, id: &str, now: i64) -> StoreFuture<'_, bool> {
        let mut g = self.lock();
        let ok = match g
            .enrolment_tokens
            .iter_mut()
            .find(|t| t.id == id && t.used_at.is_none() && t.expires_at > now)
        {
            Some(t) => {
                t.used_at = Some(now);
                true
            }
            None => false,
        };
        ready(Ok(ok))
    }

    fn release_enrolment_token(&self, id: &str, claimed_at: i64) -> StoreFuture<'_, ()> {
        let mut guard = self.lock();
        let g = &mut *guard;
        if let Some(t) = g
            .enrolment_tokens
            .iter_mut()
            .find(|t| t.id == id && t.used_at == Some(claimed_at))
        {
            let live = g.agents.iter().any(|a| {
                a.tenant_id == t.tenant_id && a.id == t.agent_id && a.status != AgentStatus::Revoked
            });
            if live {
                t.used_at = None;
            }
        }
        ready(Ok(()))
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
        let mut guard = self.lock();
        let g = &mut *guard;
        let Some(agent) = g.agents.iter_mut().find(|a| {
            a.tenant_id == tenant_id
                && a.role == role
                && a.id == agent_id
                && a.status != AgentStatus::Revoked
        }) else {
            return ready(Ok(false));
        };
        agent.status = AgentStatus::Active;
        agent.enrolled_at.get_or_insert(now);
        agent.cert_sha256 = Some(cert.cert_sha256.clone());
        agent.cert_expires_at = Some(cert.expires_at);
        for i in g.identities.iter_mut() {
            if i.tenant_id == tenant_id && i.id == agent_id && !i.revoked {
                i.valid_until = Some(i.valid_until.map_or(retire_at, |v| v.min(retire_at)));
            }
        }
        if let Some(r) = &cert.issuer_ref {
            g.issuer_refs.insert(cert.cert_sha256.clone(), r.clone());
        }
        g.identities.push(IdentityRecord {
            id: agent_id.to_string(),
            tenant_id: tenant_id.to_string(),
            role,
            scopes: agent_scopes(role),
            cert_sha256: cert.cert_sha256,
            revoked: false,
            valid_until: None,
            expires_at: Some(cert.expires_at),
        });
        ready(Ok(true))
    }

    fn revoke_agent(
        &self,
        tenant_id: &str,
        role: Role,
        agent_id: &str,
        reason: Reason,
        now: i64,
    ) -> StoreFuture<'_, Option<AgentCerts>> {
        let mut guard = self.lock();
        let g = &mut *guard;
        let Some(agent) = g
            .agents
            .iter_mut()
            .find(|a| a.tenant_id == tenant_id && a.role == role && a.id == agent_id)
        else {
            return ready(Ok(None));
        };
        agent.status = AgentStatus::Revoked;
        agent.revoked_at.get_or_insert(now);
        agent.revoke_reason = Some(reason);
        let mut fps = Vec::new();
        for i in g.identities.iter_mut() {
            if i.tenant_id == tenant_id && i.id == agent_id {
                i.revoked = true;
                fps.push(i.cert_sha256.clone());
            }
        }
        for t in g.enrolment_tokens.iter_mut() {
            if t.tenant_id == tenant_id && t.agent_id == agent_id && t.used_at.is_none() {
                t.used_at = Some(now);
            }
        }
        let refs = fps
            .into_iter()
            .map(|fp| {
                let r = g.issuer_refs.get(&fp).cloned();
                (fp, r)
            })
            .collect();
        ready(Ok(Some(refs)))
    }

    fn record_agent_seen(
        &self,
        tenant_id: &str,
        agent_id: &str,
        seen: SeenFrom,
        network_changed: bool,
        now: i64,
    ) -> StoreFuture<'_, ()> {
        if let Some(a) = self
            .lock()
            .agents
            .iter_mut()
            .find(|a| a.tenant_id == tenant_id && a.id == agent_id)
        {
            a.last_seen_at = Some(now);
            a.last_ip = seen.ip;
            a.last_asn = seen.asn;
            if network_changed {
                a.network_changed_at = Some(now);
            }
        }
        ready(Ok(()))
    }
}

/// Radar sink that keeps every point, for tests (#35). The Worker writes to
/// Analytics Engine instead.
#[derive(Default)]
pub struct MemoryRadarSink {
    points: Mutex<Vec<AnalyticsPoint>>,
}

impl MemoryRadarSink {
    pub fn points(&self) -> Vec<AnalyticsPoint> {
        self.points
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }
}

impl RadarSink for MemoryRadarSink {
    fn write(&self, points: &[AnalyticsPoint]) -> Result<(), String> {
        self.points
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .extend_from_slice(points);
        Ok(())
    }
}

/// Cache purger that records every purge, for tests (#35).
#[derive(Default)]
pub struct MemoryCachePurger {
    paths: Mutex<Vec<Vec<String>>>,
}

impl MemoryCachePurger {
    /// Every purge call, in order.
    pub fn purges(&self) -> Vec<Vec<String>> {
        self.paths.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }
}

impl crate::sinks::CachePurger for MemoryCachePurger {
    fn purge(&self, paths: Vec<String>) -> crate::sinks::PurgeFuture<'_> {
        self.paths
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(paths);
        Box::pin(std::future::ready(Ok(())))
    }
}
