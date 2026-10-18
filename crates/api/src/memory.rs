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

use crate::store::{
    AgentCerts, AgentQuery, AuditQuery, BudgetOutcome, DecoyQuery, EnrolmentTokenRecord,
    IdentityRecord, IpIocRow, JobRecord, LinkOverride, NewCert, Store, StoreError, StoreFuture,
    TokenRecord,
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
    cache: Vec<CacheEntry>,
    fail_enrichment: bool,
    budget: HashMap<(String, &'static str, i64), u32>,
    failures: Vec<ProviderFailureRecord>,
    agents: Vec<AgentRecord>,
    enrolment_tokens: Vec<EnrolmentTokenRecord>,
    /// CA reference for each bound certificate, by fingerprint.
    issuer_refs: HashMap<String, String>,
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
    pub fn add_cache_entry(&self, entry: CacheEntry) {
        let mut g = self.lock();
        g.cache.retain(|e| e.key() != entry.key());
        g.cache.push(entry);
    }

    /// The campaign registry recorded for a tenant (tests).
    pub fn campaign_registry(&self, tenant_id: &str) -> foiled_core::campaign::Registry {
        self.lock()
            .campaign_registry
            .get(tenant_id)
            .cloned()
            .unwrap_or_default()
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
