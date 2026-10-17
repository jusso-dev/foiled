//! In-memory [`Store`] for tests and the local mock server.

use std::collections::HashMap;
use std::sync::Mutex;

use foiled_core::audit::AuditRecord;
use foiled_core::capture::CaptureEvent;
use foiled_core::decoy::{Decoy, DecoyState};

use crate::store::{
    AuditQuery, DecoyQuery, IdentityRecord, IpIocRow, JobRecord, LinkOverride, Store, StoreError,
    StoreFuture, TokenRecord,
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

    pub fn jobs(&self) -> Vec<JobRecord> {
        self.lock().jobs.clone()
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

    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        // A poisoned lock only happens after a panic in a test; keep going.
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }
}

fn ready<'a, T: Send + 'a>(v: Result<T, StoreError>) -> StoreFuture<'a, T> {
    Box::pin(std::future::ready(v))
}

impl Store for MemoryStore {
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

    fn append_audit(&self, record: AuditRecord) -> StoreFuture<'_, ()> {
        self.lock().audit.push(record);
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
            let mine = j.host_id.as_deref().is_none_or(|h| h == host_id);
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
        out.sort_by(|a, b| (a.ts, &a.event_id).cmp(&(b.ts, &b.event_id)));
        out.dedup_by(|a, b| a.event_id == b.event_id);
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
}
