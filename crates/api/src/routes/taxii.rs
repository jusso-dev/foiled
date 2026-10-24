//! Read-only TAXII 2.1 server (#13), served from the materialised STIX
//! object log.
//!
//! A TAXII request reads stored object versions and never rebuilds
//! anything. The log is written by [`materialise`]: a scheduled Worker
//! handler runs it for tenants with recent events, and an admin can run it
//! for their own tenant with `POST /v0/taxii/materialise` (audited). Only
//! one run per tenant at a time: a run holds a lease in the store.
//!
//! A run builds the published view (the default `/v0/exports/stix`
//! options: publishable only, TLP:AMBER, no actors, no payload strings)
//! per UTC day, in 4,000-event parts, and stages it: the day's own objects
//! (its attempts' objects and link targets) and one contribution per IOC
//! (`foiled_core::intel::merge`). Indicators, sightings, observables and
//! malware are then published from the merge of every day's contribution,
//! so they never depend on which day ran last. Progress is stored after
//! every part and every publishing chunk, so a run that runs out of budget
//! is continued by the next. `foiled_core::intel::log::plan` decides which
//! versions are new.
//!
//! One API root, `/taxii2/foiled/`, with one collection. Its id is the same
//! for every tenant; what it holds is scoped by the bearer token
//! (`exports:read`). Paging follows TAXII 2.1: rows sort by `date_added`,
//! then id and version; `added_after` is exclusive; `limit` caps a page and
//! `next` is an opaque cursor. Because every append gets a `date_added`
//! after every row before it, paging never skips or repeats a row, and
//! a version's content never changes. See `docs/intel-outputs.md#taxii-21`.

use std::collections::{BTreeMap, BTreeSet, HashSet};

use axum::extract::rejection::QueryRejection;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, HeaderName, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use foiled_core::audit::Outcome;
use foiled_core::auth::{Principal, Role, Scope};
use foiled_core::confidence::{Band, ConfidenceConfig, LinkKind};
use foiled_core::enrichment::CacheEntry;
use foiled_core::intel::log::{
    Evidence, History, LogCursor, LogQuery, PUBLISHED, StixVersion, VersionFilter, parse_timestamp,
    plan, reissue_id, revocable, revocation, rewrite_ids,
};
use foiled_core::intel::merge::IocContribution;
use foiled_core::intel::stix::{self, StixObject};
use foiled_core::intel::{
    AttemptRecord, ExportInput, ExportOptions, FOILED_NAMESPACE, REFERENCE_EPOCH_MS, select,
    timestamp, uuid5::uuid_v5,
};
use foiled_core::ioc::{Ioc, IocConfidence, IocOrigin, IocType};
use foiled_core::retention::RetentionConfig;
use foiled_core::share::Tlp;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::AppState;
use crate::auth::Auth;
use crate::error::ApiError;
use crate::routes::exports::{ExportQuery, selection};
use crate::store::{DayAttempt, DayPhase, DayProgress, DayRecord, PendingStep};

pub const TAXII_MEDIA_TYPE: &str = "application/taxii+json;version=2.1";
pub const API_ROOT: &str = "/taxii2/foiled/";
/// Default and largest page size.
pub const DEFAULT_LIMIT: usize = 100;
pub const MAX_LIMIT: usize = 1000;
const DAY_MS: i64 = 24 * 3600 * 1000;
/// The materialiser builds the UTC days of the last week. Older days keep
/// what they last published until retention removes it.
pub const WINDOW_DAYS: i64 = 7;
/// IOCs or staged objects in one publishing chunk (one append).
pub const CHUNK: usize = 500;
/// How long a run's lease lasts without renewal. A run renews it before
/// every part and chunk; a Worker that dies mid-run frees the tenant when
/// it lapses.
pub const LEASE_MS: i64 = 10 * 60 * 1000;
/// Bump to rebuild every day when the materialiser's output changes.
const MATERIALISER_VERSION: &str = "2";

/// Work one run may do for one tenant. A run that stops early leaves the
/// rest to the next run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Budget {
    /// 4,000-event parts built.
    pub parts: usize,
    /// Most parts one day gets in one run, so a busy day cannot hold the
    /// others back.
    pub parts_per_day: usize,
    /// Publishing chunks appended.
    pub chunks: usize,
}

pub const DEFAULT_BUDGET: Budget = Budget {
    parts: 12,
    parts_per_day: 4,
    chunks: 24,
};

/// Most tenants one scheduled tick serves, and most work units (parts and
/// chunks) it spends before stopping; the next tick starts after the last
/// tenant served. Sized for the Workers default of 30 s CPU per
/// invocation (`docs/intel-outputs.md#taxii-21`).
pub const TENANTS_PER_TICK: usize = 8;
pub const WORK_PER_TICK: usize = 48;

/// The one collection's id: `uuid5(FOILED_NAMESPACE, "taxii-collection|published")`.
pub fn collection_id() -> String {
    uuid_v5(FOILED_NAMESPACE, "taxii-collection|published")
}

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/taxii2/", get(discovery))
        .route(API_ROOT, get(api_root))
        .route("/taxii2/foiled/collections/", get(collections))
        .route(
            "/taxii2/foiled/collections/{collection_id}/",
            get(collection),
        )
        .route(
            "/taxii2/foiled/collections/{collection_id}/objects/",
            get(objects),
        )
        .route(
            "/taxii2/foiled/collections/{collection_id}/objects/{object_id}/",
            get(object),
        )
        .route(
            "/taxii2/foiled/collections/{collection_id}/objects/{object_id}/versions/",
            get(versions),
        )
        .route(
            "/taxii2/foiled/collections/{collection_id}/manifest/",
            get(manifest),
        )
        .route("/v0/taxii/materialise", post(materialise_now))
}

// ---------------------------------------------------------------------------
// Materialiser
// ---------------------------------------------------------------------------

/// What one materialiser run did for one tenant.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct Report {
    /// Days whose build finished and whose objects were published.
    pub days_written: usize,
    /// Days whose inputs had not changed since they were published.
    pub days_skipped: usize,
    /// 4,000-event parts built.
    pub parts: usize,
    /// Publishing chunks appended.
    pub chunks: usize,
    /// New object versions appended (including revocations).
    pub versions_written: u64,
    /// Objects whose content equals their current head.
    pub unchanged: usize,
    /// Objects revoked because nothing supports them any more.
    pub revoked: usize,
    /// Objects that came back after a revocation, issued under a new id.
    pub reissued: usize,
    /// Version rows removed by retention.
    pub purged: u64,
    /// True when the budget ran out with work left; the next run
    /// continues from the stored progress.
    pub incomplete: bool,
}

/// How far before and after its day a day's window reads, so an attempt
/// that crosses midnight is built whole by the day it started in.
pub const DAY_MARGIN_MS: i64 = 6 * 3600 * 1000;
/// Most revocations of one object before the materialiser stops reissuing.
const MAX_REISSUES: u32 = 8;
/// The published view's label.
const TLP: Tlp = Tlp::Amber;

/// Map ids the log holds as revoked to the id their next issue uses:
/// `reissue_id(id, n)` for the first `n` whose head is not revoked.
async fn reissue_map(
    state: &AppState,
    tenant_id: &str,
    history: &BTreeMap<String, History>,
) -> Result<BTreeMap<String, String>, ApiError> {
    let mut map = BTreeMap::new();
    let mut pending: Vec<String> = history
        .iter()
        .filter(|(id, h)| h.revoked && revocable(id.split_once("--").map_or("", |(t, _)| t)))
        .map(|(id, _)| id.clone())
        .collect();
    for generation in 1..=MAX_REISSUES {
        if pending.is_empty() {
            break;
        }
        let candidates: Vec<String> = pending
            .iter()
            .map(|id| reissue_id(id, generation))
            .collect();
        let found = state
            .store
            .stix_history(tenant_id, PUBLISHED, candidates.clone())
            .await?;
        let mut next = Vec::new();
        for (id, rid) in pending.into_iter().zip(candidates) {
            if found.get(&rid).is_some_and(|h| h.revoked) {
                next.push(id);
            } else {
                map.insert(id, rid);
            }
        }
        pending = next;
    }
    Ok(map)
}

/// The signature input every day shares: a hash of the bundled rules,
/// ATT&CK sidecar and catalogue, the confidence config and the
/// materialiser version. When only this changes (a deploy), days are
/// rebuilt at most [`QUIET_REBUILDS_PER_RUN`] per run.
fn config_digest(state: &AppState) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(MATERIALISER_VERSION.as_bytes());
    h.update(crate::links::rules_digest().as_bytes());
    h.update(serde_json::to_vec(state.catalogue.entries()).unwrap_or_default());
    h.update(serde_json::to_vec(&ConfidenceConfig::default()).unwrap_or_default());
    hex::encode(h.finalize())
}

/// Days a run rebuilds without new events in their window: only their
/// other inputs (analyst decisions, campaigns, enrichment) or the config
/// digest moved. An active campaign or a deploy can touch every day at
/// once; those rebuilds are spread over runs, least recently served first.
pub const QUIET_REBUILDS_PER_RUN: usize = 2;

/// What a day's signature takes from one enrichment cache row: its key
/// and the facts objects can carry, not when it was fetched, so a refresh
/// that changes nothing rebuilds nothing. An expired row drops out of the
/// lookup, so expiry still counts.
pub fn cache_row_input(e: &CacheEntry) -> String {
    let mut facts: Vec<String> = e
        .facts
        .iter()
        .map(|f| format!("{}|{}|{}", f.provider, f.key, f.value))
        .collect();
    facts.sort();
    format!("{}|{}", e.key(), facts.join(";"))
}
/// Attempts in one publishing chunk of a day's own objects.
pub const ATTEMPT_CHUNK: usize = 200;

fn store_err(e: impl std::fmt::Display) -> ApiError {
    ApiError::from(crate::store::StoreError(e.to_string()))
}

/// The part of a merged IOC the day's own objects read (its observable and
/// indicator ids, and whether it is the attempt's source address), for an
/// IOC whose merged view passed the gate. Its other fields are never
/// serialised: the IOC's own objects come from the merge.
fn published_stub(id: &str, ty: &str, value: &str, attempts: Vec<String>) -> Option<Ioc> {
    let ioc_type = IocType::parse(ty)?;
    Some(Ioc {
        ioc_id: id.to_string(),
        ioc_type,
        value: value.to_string(),
        display: String::new(),
        roles: vec![],
        origin: IocOrigin::Observed,
        redacted: false,
        file_ioc_limited: false,
        first_seen: 0,
        last_seen: 0,
        sightings: 0,
        attempt_ids: attempts,
        campaign_ids: vec![],
        decoy_ids: vec![],
        catalogue_ids: vec![],
        event_ids: vec![],
        extracted_from: vec![],
        enrichment: vec![],
        fingerprint: None,
        confidence: IocConfidence {
            score: 100,
            band: Band::High,
            wording: String::new(),
            publishable: true,
            evidence: vec![],
            caps_applied: vec![],
        },
    })
}

/// Run the materialiser for one tenant with the default budget. Fails with
/// 409 when another run holds the tenant's lease.
pub async fn materialise(state: &AppState, tenant_id: &str) -> Result<Report, ApiError> {
    materialise_with(state, tenant_id, DEFAULT_BUDGET).await
}

/// [`materialise`] with an explicit budget.
pub async fn materialise_with(
    state: &AppState,
    tenant_id: &str,
    budget: Budget,
) -> Result<Report, ApiError> {
    let holder = (state.ids)();
    let now = (state.clock)();
    let Some(fence) = state
        .store
        .stix_lease(tenant_id, PUBLISHED, &holder, now, LEASE_MS)
        .await?
    else {
        return Err(ApiError::conflict(
            "a materialiser run is already in progress for this tenant",
        ));
    };
    let mut run = Run {
        state,
        tenant_id,
        holder: &holder,
        fence,
        now,
        budget,
        r: Report::default(),
    };
    let result = match run.go().await {
        // A fenced write refused: another run took the tenant over.
        Err(_) if run.renew().await.is_err() => Err(ApiError::conflict(
            "the materialiser lease was lost to another run",
        )),
        other => other,
    };
    // A failed release leaves the lease to lapse.
    let _ = state
        .store
        .stix_release(tenant_id, PUBLISHED, &holder)
        .await;
    result.map(|()| run.r)
}

struct Run<'a> {
    state: &'a AppState,
    tenant_id: &'a str,
    holder: &'a str,
    /// The lease generation every write is fenced with.
    fence: i64,
    now: i64,
    budget: Budget,
    r: Report,
}

impl Run<'_> {
    /// Renew the lease before more work; stop if another run took it.
    async fn renew(&self) -> Result<(), ApiError> {
        let held = self
            .state
            .store
            .stix_lease(
                self.tenant_id,
                PUBLISHED,
                self.holder,
                (self.state.clock)(),
                LEASE_MS,
            )
            .await?;
        if held == Some(self.fence) {
            Ok(())
        } else {
            Err(ApiError::conflict("the materialiser lease was lost"))
        }
    }

    async fn put_day(&self, day: i64, rec: DayRecord) -> Result<(), ApiError> {
        Ok(self
            .state
            .store
            .put_stix_day(self.tenant_id, PUBLISHED, day, rec, self.fence)
            .await?)
    }

    async fn go(&mut self) -> Result<(), ApiError> {
        let mut days = self
            .state
            .store
            .stix_days(self.tenant_id, PUBLISHED)
            .await?;
        self.build(&mut days).await?;
        self.publish(&mut days).await?;
        // Retention (#16): the log is a copy of evidence and takes the
        // attempt TTL, judged by the newest evidence behind each object.
        let ttl = i64::from(RetentionConfig::default().ttl_days.attempt) * DAY_MS;
        self.r.purged = self
            .state
            .store
            .stix_purge(self.tenant_id, PUBLISHED, self.now - ttl, self.fence)
            .await?;
        Ok(())
    }

    // ----- Building -----

    /// Stage parts for the days of the window that changed, continuing
    /// builds earlier runs left unfinished. Days are served least recently
    /// served first (newest first among equals), each at most
    /// `parts_per_day` parts, so one busy day cannot starve the others.
    async fn build(&mut self, days: &mut BTreeMap<i64, DayRecord>) -> Result<(), ApiError> {
        let today = self.now.div_euclid(DAY_MS) * DAY_MS;
        let config = config_digest(self.state);
        // Days whose events did not change, rebuilt at most
        // QUIET_REBUILDS_PER_RUN per run.
        let mut quiet: Vec<(i64, DayRecord)> = Vec::new();
        let mut todo: Vec<(i64, DayRecord)> = Vec::new();
        // The window's days, and any build still in progress (one that has
        // since left the window is finished, not abandoned).
        let mut candidates: BTreeSet<i64> = (0..WINDOW_DAYS).map(|b| today - b * DAY_MS).collect();
        candidates.extend(days.iter().filter_map(|(d, r)| {
            r.progress
                .as_ref()
                .is_some_and(|p| p.phase == DayPhase::Building)
                .then_some(*d)
        }));
        for day in candidates {
            let mut rec = days.get(&day).cloned().unwrap_or_default();
            match &rec.progress {
                Some(p) if p.phase == DayPhase::Building => {}
                // Built and waiting to be published: rebuilt after that.
                Some(_) => continue,
                None => {
                    let (since, until) = self.window(day);
                    let events = self
                        .state
                        .store
                        .event_signature(self.tenant_id, since, until)
                        .await?;
                    let inputs = self
                        .state
                        .store
                        .stix_day_inputs(self.tenant_id, PUBLISHED, day, self.now)
                        .await?;
                    let signature = format!("{events}#{inputs}#{config}");
                    if rec.signature == signature {
                        self.r.days_skipped += 1;
                        continue;
                    }
                    if events.starts_with("0:") && !days.contains_key(&day) {
                        continue;
                    }
                    let is_quiet = rec.signature.starts_with(&format!("{events}#"));
                    rec.progress = Some(DayProgress {
                        signature,
                        ..Default::default()
                    });
                    if is_quiet {
                        quiet.push((day, rec));
                        continue;
                    }
                }
            }
            todo.push((day, rec));
        }
        quiet.sort_by_key(|(day, rec)| (rec.served_ms, -day));
        if quiet.len() > QUIET_REBUILDS_PER_RUN {
            self.r.incomplete = true;
        }
        todo.extend(quiet.into_iter().take(QUIET_REBUILDS_PER_RUN));
        todo.sort_by_key(|(day, rec)| (rec.served_ms, -day));
        for (day, rec) in todo {
            let left = self.budget.parts.saturating_sub(self.r.parts);
            if left == 0 {
                self.r.incomplete = true;
                break;
            }
            let rec = self
                .build_day(day, rec, left.min(self.budget.parts_per_day))
                .await?;
            if rec
                .progress
                .as_ref()
                .is_some_and(|p| p.phase == DayPhase::Building)
            {
                self.r.incomplete = true;
            }
            days.insert(day, rec);
        }
        Ok(())
    }

    fn window(&self, day: i64) -> (i64, i64) {
        (
            day - DAY_MARGIN_MS,
            (day + DAY_MS + DAY_MARGIN_MS).min(self.now + 1),
        )
    }

    /// Stage up to `allowance` parts of one day: its attempts as scored and
    /// one contribution per IOC. When the last part is staged, both go
    /// live and the day's IOCs are queued for publishing.
    async fn build_day(
        &mut self,
        day: i64,
        mut rec: DayRecord,
        allowance: usize,
    ) -> Result<DayRecord, ApiError> {
        let state = self.state;
        // The published view only. No scopes: unreviewed material is
        // refused for it, so nothing below publish_min reaches the log.
        let who = Principal::new(
            "system:taxii-materialiser",
            Role::Human,
            self.tenant_id,
            Vec::<Scope>::new(),
        );
        let (since, until) = self.window(day);
        rec.served_ms = self.now;
        for _ in 0..allowance {
            self.renew().await?;
            let mut p = rec.progress.clone().unwrap_or_default();
            let q = ExportQuery {
                since: Some(since),
                until: Some(until),
                cursor: p.cursor.clone(),
                owned: Some((day, day + DAY_MS)),
                ..Default::default()
            };
            let built = selection(state, &who, &q, "taxii").await?;
            self.r.parts += 1;
            // Only campaigns whose link passed the gate may be named.
            let published: BTreeSet<String> = built
                .sel
                .attempts
                .iter()
                .flat_map(|a| &a.links)
                .filter(|l| l.kind == LinkKind::AttemptCampaign)
                .map(|l| l.target.clone())
                .collect();
            let mut contributions = Vec::new();
            let mut attempts = Vec::new();
            if let Some(owned) = &built.owned {
                for i in &owned.iocs {
                    let c = IocContribution::of(i, &owned.evidence, &published);
                    let body = serde_json::to_string(&c).map_err(store_err)?;
                    contributions.push((c.ioc_id, body));
                }
                for r in &owned.records {
                    attempts.push(DayAttempt {
                        attempt_id: r.attempt.attempt_id.clone(),
                        body: serde_json::to_string(r).map_err(store_err)?,
                    });
                }
            }
            let part = p.parts;
            let next = built.cut.filter(|_| built.truncated).map(|c| c.encode());
            let last = next.is_none();
            p.parts += 1;
            p.cursor = next.or(p.cursor);
            // The last part is staged with the progress from before it, so
            // a crash before the promotion redoes this part.
            if !last {
                rec.progress = Some(p.clone());
            }
            state
                .store
                .stix_stage_part(
                    self.tenant_id,
                    PUBLISHED,
                    day,
                    part,
                    attempts,
                    contributions,
                    rec.clone(),
                    self.fence,
                )
                .await?;
            if last {
                p.phase = DayPhase::Publishing { after: None };
                p.ids.clear();
                rec.progress = Some(p);
                state
                    .store
                    .stix_promote_day(self.tenant_id, PUBLISHED, day, rec.clone(), self.fence)
                    .await?;
                return Ok(rec);
            }
        }
        Ok(rec)
    }

    // ----- Publishing -----

    fn chunks_left(&mut self) -> bool {
        if self.r.chunks < self.budget.chunks {
            true
        } else {
            self.r.incomplete = true;
            false
        }
    }

    /// Publish in an order that keeps every reference resolvable: first
    /// the merged objects of every queued IOC (observables, indicators,
    /// malware) and its gate decision, then every day due for publishing,
    /// whose objects are built from its attempts against those decisions
    /// (so they only name published IOCs), then the queued IOCs' sightings
    /// (which name only published `observed-data`).
    async fn publish(&mut self, days: &mut BTreeMap<i64, DayRecord>) -> Result<(), ApiError> {
        let (state, tenant) = (self.state, self.tenant_id);
        loop {
            let ids = state
                .store
                .stix_pending(tenant, PUBLISHED, PendingStep::Merge, CHUNK)
                .await?;
            if ids.is_empty() {
                break;
            }
            if !self.chunks_left() {
                return Ok(());
            }
            self.renew().await?;
            self.publish_iocs(&ids, false, days).await?;
            state
                .store
                .stix_pending_move(
                    tenant,
                    PUBLISHED,
                    ids,
                    PendingStep::Merge,
                    Some(PendingStep::Sighting),
                    self.fence,
                )
                .await?;
            self.r.chunks += 1;
        }
        let publishing: Vec<i64> = days
            .iter()
            .filter(|(_, r)| {
                r.progress
                    .as_ref()
                    .is_some_and(|p| matches!(p.phase, DayPhase::Publishing { .. }))
            })
            .map(|(d, _)| *d)
            .collect();
        for day in publishing {
            loop {
                if !self.chunks_left() {
                    return Ok(());
                }
                self.renew().await?;
                if !self.publish_day_chunk(day, days).await? {
                    break;
                }
            }
        }
        loop {
            let ids = state
                .store
                .stix_pending(tenant, PUBLISHED, PendingStep::Sighting, CHUNK)
                .await?;
            if ids.is_empty() {
                return Ok(());
            }
            if !self.chunks_left() {
                return Ok(());
            }
            self.renew().await?;
            self.publish_iocs(&ids, true, days).await?;
            state
                .store
                .stix_pending_move(
                    tenant,
                    PUBLISHED,
                    ids,
                    PendingStep::Sighting,
                    None,
                    self.fence,
                )
                .await?;
            self.r.chunks += 1;
        }
    }

    /// Merge every live contribution of these IOCs and append their
    /// objects (`sightings` false) or their sightings (true). IOCs with no
    /// contribution left, or that no longer pass the gate, are revoked;
    /// the gate decision is recorded, and days whose attempts name an IOC
    /// whose decision changed are published again.
    async fn publish_iocs(
        &mut self,
        ids: &[String],
        sightings: bool,
        days: &mut BTreeMap<i64, DayRecord>,
    ) -> Result<(), ApiError> {
        let (state, tenant) = (self.state, self.tenant_id);
        let rows = state
            .store
            .stix_contributions(tenant, PUBLISHED, ids.to_vec())
            .await?;
        let mut merged: BTreeMap<String, IocContribution> = BTreeMap::new();
        let mut days_of: BTreeMap<String, BTreeSet<i64>> = BTreeMap::new();
        for (ioc, day, body) in rows {
            let c: IocContribution = serde_json::from_str(&body)
                .map_err(|e| store_err(format!("contribution of day {day} to {ioc}: {e}")))?;
            days_of.entry(ioc.clone()).or_default().insert(day);
            match merged.get_mut(&ioc) {
                Some(m) => m.merge(c),
                None => {
                    merged.insert(ioc, c);
                }
            }
        }
        let cfg = ConfidenceConfig::default();
        let mut iocs: Vec<Ioc> = merged.values().map(|c| c.to_ioc(&cfg)).collect();
        // Without the cache, objects would lose their ASN context now and
        // regain it next run: stop instead, and retry then.
        if crate::routes::iocs::enrich(state, tenant, &mut iocs)
            .await
            .unavailable
        {
            return Err(store_err("enrichment cache unavailable"));
        }
        let mut by_id: BTreeMap<String, Ioc> = BTreeMap::new();
        for mut i in iocs {
            i.enrichment = foiled_core::ioc::export_refs(&i.enrichment);
            by_id.insert(i.ioc_id.clone(), i);
        }
        // A sighting names only `observed-data` that is published, and
        // only an IOC whose recorded gate decision passed: the merge may
        // have run before a purge changed its contributions, and then its
        // indicator is not what a fresh gate would say.
        let mut served: BTreeSet<String> = BTreeSet::new();
        let mut recorded: BTreeSet<String> = BTreeSet::new();
        if sightings {
            recorded = state
                .store
                .stix_published(tenant, PUBLISHED, ids.to_vec())
                .await?
                .into_iter()
                .map(|(id, _, _)| id)
                .collect();
            let observed: BTreeSet<String> = merged
                .values()
                .flat_map(|c| c.observed.iter().cloned())
                .collect();
            served = state
                .store
                .stix_history(tenant, PUBLISHED, observed.into_iter().collect())
                .await?
                .into_iter()
                .filter(|(_, h)| !h.revoked)
                .map(|(id, _)| id)
                .collect();
        }
        let mut objects: Vec<StixObject> = Vec::new();
        if !sightings {
            objects.push(StixObject::new(&stix::identity(), REFERENCE_EPOCH_MS));
            objects.push(StixObject::new(&stix::tlp_marking(TLP), REFERENCE_EPOCH_MS));
        }
        let mut withdrawn = Vec::new();
        let mut passes: Vec<crate::store::PublishedIoc> = Vec::new();
        let mut fails: Vec<String> = Vec::new();
        for id in ids {
            if sightings && !recorded.contains(id) {
                continue;
            }
            let built = match (merged.get(id), by_id.get(id)) {
                (Some(c), Some(i)) => c.objects(i, &served, TLP),
                _ => (vec![], None),
            };
            match built {
                (objs, _) if objs.is_empty() => {
                    withdrawn.extend(stix::ioc_revocable_ids(id));
                    fails.push(id.clone());
                }
                (objs, sighting) => {
                    if let Some(i) = by_id.get(id) {
                        passes.push((id.clone(), i.ioc_type.as_str().to_string(), i.value.clone()));
                    }
                    if sightings {
                        objects.extend(sighting);
                    } else {
                        objects.extend(objs);
                    }
                }
            }
        }
        self.append(objects).await?;
        if sightings {
            return Ok(());
        }
        self.revoke(withdrawn).await?;
        // Record the gate decisions; days naming an IOC whose decision
        // changed are published again, so their objects follow it.
        let before: BTreeSet<String> = state
            .store
            .stix_published(tenant, PUBLISHED, ids.to_vec())
            .await?
            .into_iter()
            .map(|(id, _, _)| id)
            .collect();
        let changed: Vec<&String> = passes
            .iter()
            .map(|(id, _, _)| id)
            .filter(|id| !before.contains(*id))
            .chain(fails.iter().filter(|id| before.contains(*id)))
            .collect();
        let mut again: BTreeSet<i64> = BTreeSet::new();
        for id in changed {
            again.extend(days_of.get(id).into_iter().flatten());
        }
        state
            .store
            .stix_set_published(tenant, PUBLISHED, passes, fails, self.fence)
            .await?;
        for day in again {
            let Some(mut rec) = days.get(&day).cloned() else {
                continue;
            };
            let p = match rec.progress.take() {
                // Its build publishes it when done.
                Some(p) if p.phase == DayPhase::Building => {
                    rec.progress = Some(p);
                    continue;
                }
                Some(p) => DayProgress {
                    phase: DayPhase::Publishing { after: None },
                    ids: vec![],
                    ..p
                },
                None => DayProgress {
                    signature: rec.signature.clone(),
                    phase: DayPhase::Publishing { after: None },
                    ..Default::default()
                },
            };
            rec.progress = Some(p);
            self.put_day(day, rec.clone()).await?;
            days.insert(day, rec);
        }
        Ok(())
    }

    /// Publish the next chunk of a day's own objects, built from its live
    /// attempts against the recorded gate decisions. When none are left,
    /// revoke what the day supported before and does not now, and finish
    /// the day. Returns false when the day is finished.
    async fn publish_day_chunk(
        &mut self,
        day: i64,
        days: &mut BTreeMap<i64, DayRecord>,
    ) -> Result<bool, ApiError> {
        let (state, tenant) = (self.state, self.tenant_id);
        let mut rec = days.get(&day).cloned().unwrap_or_default();
        let Some(mut p) = rec.progress.clone() else {
            return Ok(false);
        };
        let DayPhase::Publishing { after } = &p.phase else {
            return Ok(false);
        };
        let rows = state
            .store
            .stix_day_attempts(tenant, PUBLISHED, day, after.clone(), ATTEMPT_CHUNK)
            .await?;
        if let Some(last) = rows.last() {
            let next = last.attempt_id.clone();
            let mut records: Vec<AttemptRecord> = Vec::with_capacity(rows.len());
            for r in &rows {
                records.push(serde_json::from_str(&r.body).map_err(|e| {
                    store_err(format!("attempt {} of day {day}: {e}", r.attempt_id))
                })?);
            }
            let ioc_ids: BTreeSet<String> = records
                .iter()
                .flat_map(|r| r.attempt.ioc_refs.iter().cloned())
                .collect();
            let iocs: Vec<Ioc> = state
                .store
                .stix_published(tenant, PUBLISHED, ioc_ids.into_iter().collect())
                .await?
                .into_iter()
                .filter_map(|(id, ty, value)| {
                    let seen: Vec<String> = records
                        .iter()
                        .filter(|r| r.attempt.ioc_refs.contains(&id))
                        .map(|r| r.attempt.attempt_id.clone())
                        .collect();
                    published_stub(&id, &ty, &value, seen)
                })
                .collect();
            let sel = select(
                ExportInput {
                    attempts: records,
                    iocs,
                    attack: Some(crate::links::attack_sidecar().clone()),
                },
                &ExportOptions::default(),
            );
            // The IOCs' own objects come from the merge.
            let mut from_iocs: HashSet<String> = HashSet::new();
            for i in &sel.iocs {
                from_iocs.extend(
                    stix::ioc_objects(i, 0, TLP)
                        .objects
                        .iter()
                        .filter_map(|(v, _)| v["id"].as_str().map(str::to_string)),
                );
                from_iocs.extend(stix::ioc_revocable_ids(&i.ioc_id));
            }
            let objects: Vec<StixObject> = stix::objects(&sel)
                .into_iter()
                .filter(|o| !from_iocs.contains(o.id()))
                .collect();
            p.ids.extend(objects.iter().map(|o| o.id().to_string()));
            p.ids.sort();
            p.ids.dedup();
            self.append(objects).await?;
            self.r.chunks += 1;
            p.phase = DayPhase::Publishing { after: Some(next) };
            rec.progress = Some(p);
            self.put_day(day, rec.clone()).await?;
            days.insert(day, rec);
            return Ok(true);
        }
        // What the day supported before and does not now is withdrawn,
        // unless another day still supports it.
        let produced: HashSet<&String> = p.ids.iter().collect();
        let others: HashSet<&String> = days
            .iter()
            .filter(|(d, _)| **d != day)
            .flat_map(|(_, r)| r.ids.iter().chain(r.progress.iter().flat_map(|p| &p.ids)))
            .collect();
        let withdrawn: Vec<String> = rec
            .ids
            .iter()
            .filter(|id| !produced.contains(id) && !others.contains(id))
            .cloned()
            .collect();
        self.revoke(withdrawn).await?;
        let done = DayRecord {
            signature: p.signature,
            ids: p.ids,
            progress: None,
            served_ms: rec.served_ms,
        };
        self.put_day(day, done.clone()).await?;
        days.insert(day, done);
        self.r.days_written += 1;
        Ok(false)
    }

    /// Plan and append objects: reissue revoked ids that came back (and
    /// rewrite references to them), write what differs from each head, and
    /// raise each referenced object's evidence time to its referrer's.
    async fn append(&mut self, objects: Vec<StixObject>) -> Result<(), ApiError> {
        if objects.is_empty() {
            return Ok(());
        }
        let (state, tenant) = (self.state, self.tenant_id);
        let own: BTreeSet<String> = objects.iter().map(|o| o.id().to_string()).collect();
        let mut wanted = own.clone();
        wanted.extend(objects.iter().flat_map(|o| o.refs.iter().cloned()));
        let mut history = state
            .store
            .stix_history(tenant, PUBLISHED, wanted.into_iter().collect())
            .await?;
        // Revoked objects that came back get a new id (STIX forbids
        // un-revoking); references follow.
        let map = reissue_map(state, tenant, &history).await?;
        let mut objects = objects;
        if !map.is_empty() {
            self.r.reissued += map.keys().filter(|k| own.contains(*k)).count();
            objects = rewrite_ids(objects, &map);
            let fresh = state
                .store
                .stix_history(tenant, PUBLISHED, map.values().cloned().collect())
                .await?;
            history.retain(|id, _| !map.contains_key(id));
            history.extend(fresh);
        }
        let mut p = plan(&objects, &history, self.now);
        for o in &objects {
            p.evidence.extend(o.refs.iter().map(|r| Evidence {
                id: r.clone(),
                evidence_ms: o.added,
            }));
        }
        drop(objects);
        self.r.unchanged += p.unchanged;
        self.r.versions_written += state
            .store
            .stix_append(tenant, PUBLISHED, p.new, p.evidence, self.now, self.fence)
            .await?;
        Ok(())
    }

    /// Revoke these ids (as built), or the ids they were reissued under.
    async fn revoke(&mut self, ids: Vec<String>) -> Result<(), ApiError> {
        if ids.is_empty() {
            return Ok(());
        }
        let history = self
            .state
            .store
            .stix_history(self.tenant_id, PUBLISHED, ids.clone())
            .await?;
        let map = reissue_map(self.state, self.tenant_id, &history).await?;
        let current: Vec<String> = ids
            .into_iter()
            .map(|id| map.get(&id).cloned().unwrap_or(id))
            .collect();
        self.r.revoked += revoke(
            self.state,
            self.tenant_id,
            current,
            self.now,
            self.fence,
            &mut self.r.versions_written,
        )
        .await?;
        Ok(())
    }
}

/// Append a revoked last version for each id that can be revoked and is
/// not already. Returns how many were revoked.
async fn revoke(
    state: &AppState,
    tenant_id: &str,
    ids: Vec<String>,
    now: i64,
    fence: i64,
    written: &mut u64,
) -> Result<usize, ApiError> {
    if ids.is_empty() {
        return Ok(0);
    }
    let history = state
        .store
        .stix_history(tenant_id, PUBLISHED, ids.clone())
        .await?;
    let ids: Vec<String> = ids
        .into_iter()
        .filter(|i| history.contains_key(i))
        .collect();
    if ids.is_empty() {
        return Ok(0);
    }
    let limit = ids.len() + 1;
    let heads = state
        .store
        .stix_query(
            tenant_id,
            PUBLISHED,
            LogQuery {
                ids: Some(ids),
                versions: VersionFilter::last(),
                limit,
                ..Default::default()
            },
        )
        .await?;
    let versions: Vec<_> = heads
        .iter()
        .filter_map(|h| history.get(&h.id).and_then(|hist| revocation(h, hist, now)))
        .collect();
    let n = versions.len();
    if n > 0 {
        *written += state
            .store
            .stix_append(tenant_id, PUBLISHED, versions, vec![], now, fence)
            .await?;
    }
    Ok(n)
}

/// The scheduled run: [`materialise_tick`] with [`TENANTS_PER_TICK`] and
/// [`WORK_PER_TICK`].
pub async fn materialise_all(state: &AppState) -> Result<usize, ApiError> {
    materialise_tick(state, TENANTS_PER_TICK, WORK_PER_TICK).await
}

/// Serve tenants with events in the window or anything in the log, in id
/// order, starting after the tenant the last tick ended on, until
/// `max_tenants` tenants or `max_work` parts and chunks. Each tenant gets
/// [`DEFAULT_BUDGET`] and what is left is continued by a later tick. A tenant another run holds
/// is skipped. Keeps going past a failing tenant and returns the first
/// error; otherwise the number of tenants served.
pub async fn materialise_tick(
    state: &AppState,
    max_tenants: usize,
    max_work: usize,
) -> Result<usize, ApiError> {
    let now = (state.clock)();
    // Tenants with recent events, and every tenant with a log, so one
    // whose events stopped is still purged as its evidence expires.
    let mut tenants = state
        .store
        .tenants_with_events(now - WINDOW_DAYS * DAY_MS)
        .await?;
    tenants.extend(state.store.stix_tenants(PUBLISHED).await?);
    tenants.sort();
    tenants.dedup();
    let cursor = state.store.stix_cron_cursor(PUBLISHED).await?;
    let start = cursor
        .as_ref()
        .map_or(0, |c| tenants.iter().position(|t| t > c).unwrap_or(0));
    let order = tenants[start..].iter().chain(&tenants[..start]);
    let (mut served, mut work) = (0, 0);
    let mut first_err = None;
    for t in order.take(max_tenants) {
        if work >= max_work {
            break;
        }
        match materialise(state, t).await {
            Ok(r) => work += r.parts + r.chunks,
            Err(e) if e.status == StatusCode::CONFLICT => {}
            Err(e) => {
                first_err.get_or_insert(e);
            }
        }
        state.store.put_stix_cron_cursor(PUBLISHED, t).await?;
        served += 1;
    }
    first_err.map_or(Ok(served), Err)
}

/// `POST /v0/taxii/materialise`: run the materialiser for the caller's
/// tenant now. Admin only, audited. 409 while another run holds the
/// tenant.
async fn materialise_now(
    State(state): State<AppState>,
    auth: Auth,
) -> Result<Json<Report>, ApiError> {
    let who = auth.require(Scope::Admin)?.clone();
    let report = materialise(&state, &who.tenant_id).await;
    let outcome = match &report {
        Ok(_) => Outcome::Accepted,
        Err(e) if e.status == StatusCode::CONFLICT => Outcome::Denied,
        Err(_) => Outcome::Failed,
    };
    let mut rec =
        crate::routes::audit_record(&state, &who, "taxii.materialise", Some(PUBLISHED), outcome);
    if let Ok(r) = &report {
        rec.detail = serde_json::to_value(r).unwrap_or(Value::Null);
    }
    state.store.append_audit(rec).await?;
    Ok(Json(report?))
}

// ---------------------------------------------------------------------------
// TAXII responses
// ---------------------------------------------------------------------------

/// A TAXII error message (section 3.6.1).
#[derive(Debug)]
pub struct TaxiiError {
    pub status: StatusCode,
    pub title: String,
}

impl TaxiiError {
    fn new(status: StatusCode, title: impl Into<String>) -> Self {
        TaxiiError {
            status,
            title: title.into(),
        }
    }
}

impl From<ApiError> for TaxiiError {
    fn from(e: ApiError) -> Self {
        TaxiiError::new(e.status, e.message)
    }
}

impl IntoResponse for TaxiiError {
    fn into_response(self) -> Response {
        let body = json!({
            "title": self.title,
            "http_status": self.status.as_u16().to_string(),
        });
        (
            self.status,
            [(header::CONTENT_TYPE, TAXII_MEDIA_TYPE)],
            body.to_string(),
        )
            .into_response()
    }
}

type TaxiiResult = Result<Response, TaxiiError>;

/// Whether the `Accept` header allows a TAXII 2.1 response. A missing
/// header is accepted, as is any range that covers
/// `application/taxii+json` without asking for another version.
pub fn acceptable(headers: &HeaderMap) -> bool {
    let Some(v) = headers.get(header::ACCEPT) else {
        return true;
    };
    let Ok(v) = v.to_str() else {
        return false;
    };
    v.split(',').any(|range| {
        let mut parts = range.split(';').map(|p| p.trim().to_ascii_lowercase());
        let media = parts.next().unwrap_or_default();
        let version_ok = parts.all(|p| match p.split_once('=') {
            Some((k, val)) if k.trim() == "version" => val.trim() == "2.1",
            _ => true,
        });
        matches!(
            media.as_str(),
            "*/*" | "application/*" | "application/taxii+json"
        ) && version_ok
    })
}

fn guard(auth: Result<Auth, ApiError>, headers: &HeaderMap) -> Result<Auth, TaxiiError> {
    let auth = auth?;
    auth.require(Scope::ExportsRead)?;
    if !acceptable(headers) {
        return Err(TaxiiError::new(
            StatusCode::NOT_ACCEPTABLE,
            "The server responds with application/taxii+json;version=2.1 only",
        ));
    }
    Ok(auth)
}

/// The query, parsed after [`guard`] so an unauthenticated caller gets 401
/// and a bad value gets a TAXII error body, not axum's plain text.
fn query(q: Result<Query<ObjectsQuery>, QueryRejection>) -> Result<ObjectsQuery, TaxiiError> {
    q.map(|Query(q)| q).map_err(|e| {
        TaxiiError::new(
            StatusCode::BAD_REQUEST,
            format!("Invalid query: {}", e.body_text()),
        )
    })
}

fn taxii_text(body: String) -> Response {
    (
        [
            (header::CONTENT_TYPE, TAXII_MEDIA_TYPE),
            (header::X_CONTENT_TYPE_OPTIONS, "nosniff"),
        ],
        body,
    )
        .into_response()
}

fn taxii(body: Value) -> Response {
    taxii_text(body.to_string())
}

/// `https://<host>` when the Host header is a plain host name, so the
/// discovery document can list absolute URLs; empty otherwise.
fn origin(headers: &HeaderMap) -> String {
    let host = headers
        .get(header::HOST)
        .and_then(|h| h.to_str().ok())
        .unwrap_or_default();
    let ok = !host.is_empty()
        && host.len() <= 253
        && host
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b':'));
    if ok {
        format!("https://{host}")
    } else {
        String::new()
    }
}

async fn discovery(auth: Result<Auth, ApiError>, headers: HeaderMap) -> TaxiiResult {
    guard(auth, &headers)?;
    let root = format!("{}{API_ROOT}", origin(&headers));
    Ok(taxii(json!({
        "title": "Foiled TAXII server",
        "description": "Read-only intel from Foiled decoys: publishable links and indicators only. See docs/intel-outputs.md.",
        "default": root,
        "api_roots": [root],
    })))
}

async fn api_root(auth: Result<Auth, ApiError>, headers: HeaderMap) -> TaxiiResult {
    guard(auth, &headers)?;
    Ok(taxii(json!({
        "title": "Foiled",
        "description": "Foiled decoy intel for the caller's tenant.",
        "versions": [TAXII_MEDIA_TYPE],
        "max_content_length": 0,
    })))
}

fn collection_resource() -> Value {
    json!({
        "id": collection_id(),
        "title": "Foiled published intel",
        "description": "Indicators, observed attempts, CVE and ATT&CK links that passed the Foiled confidence gate (publish_min, #27). TLP:AMBER. Versions are immutable.",
        "can_read": true,
        "can_write": false,
        "media_types": [stix::MEDIA_TYPE],
    })
}

async fn collections(auth: Result<Auth, ApiError>, headers: HeaderMap) -> TaxiiResult {
    guard(auth, &headers)?;
    Ok(taxii(json!({"collections": [collection_resource()]})))
}

fn check_collection(id: &str) -> Result<(), TaxiiError> {
    if id == collection_id() {
        Ok(())
    } else {
        Err(TaxiiError::new(
            StatusCode::NOT_FOUND,
            "Collection not found",
        ))
    }
}

async fn collection(
    auth: Result<Auth, ApiError>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> TaxiiResult {
    guard(auth, &headers)?;
    check_collection(&id)?;
    Ok(taxii(collection_resource()))
}

/// The filter and paging parameters of the objects, manifest and versions
/// endpoints.
#[derive(Debug, Deserialize, Default)]
pub struct ObjectsQuery {
    pub added_after: Option<String>,
    pub limit: Option<usize>,
    pub next: Option<String>,
    #[serde(rename = "match[id]")]
    pub match_id: Option<String>,
    #[serde(rename = "match[type]")]
    pub match_type: Option<String>,
    #[serde(rename = "match[version]")]
    pub match_version: Option<String>,
    #[serde(rename = "match[spec_version]")]
    pub match_spec_version: Option<String>,
}

fn list(param: &Option<String>) -> Option<Vec<String>> {
    param.as_ref().map(|s| {
        s.split(',')
            .map(|p| p.trim().to_string())
            .filter(|p| !p.is_empty())
            .take(100)
            .collect()
    })
}

/// One page of rows.
struct Page {
    rows: Vec<StixVersion>,
    more: bool,
    next: Option<String>,
}

fn bad(title: &str) -> TaxiiError {
    TaxiiError::new(StatusCode::BAD_REQUEST, title)
}

/// Read one page of the log. `id` pins the object (single-object and
/// versions endpoints); `default_versions` is the filter when
/// `match[version]` is absent.
async fn page(
    state: &AppState,
    auth: &Auth,
    q: &ObjectsQuery,
    id: Option<&str>,
    default_versions: VersionFilter,
) -> Result<Page, TaxiiError> {
    let limit = q.limit.unwrap_or(DEFAULT_LIMIT);
    if limit == 0 {
        return Err(bad("limit must be positive"));
    }
    let limit = limit.min(MAX_LIMIT);
    let added_after = match &q.added_after {
        None => None,
        Some(s) => {
            Some(parse_timestamp(s).ok_or_else(|| bad("added_after must be a STIX timestamp"))?)
        }
    };
    let after = match &q.next {
        None => None,
        Some(s) => Some(LogCursor::decode(s).ok_or_else(|| bad("next is not valid"))?),
    };
    let versions = match &q.match_version {
        None => default_versions,
        Some(s) => VersionFilter::parse(s).ok_or_else(|| bad("match[version] is not valid"))?,
    };
    if q.match_spec_version
        .as_deref()
        .is_some_and(|v| !v.split(',').any(|p| p.trim() == "2.1"))
    {
        return Ok(Page {
            rows: vec![],
            more: false,
            next: None,
        });
    }
    let ids = match id {
        Some(i) => Some(vec![i.to_string()]),
        None => list(&q.match_id),
    };
    let query = LogQuery {
        added_after,
        after,
        ids,
        types: list(&q.match_type),
        versions,
        limit: limit + 1,
    };
    let mut rows = state
        .store
        .stix_query(&auth.0.tenant_id, PUBLISHED, query)
        .await
        .map_err(ApiError::from)?;
    let more = rows.len() > limit;
    rows.truncate(limit);
    let next = if more {
        rows.last().map(|r| LogCursor::of(r).encode())
    } else {
        None
    };
    Ok(Page { rows, more, next })
}

fn page_headers(rows: &[StixVersion]) -> Vec<(HeaderName, HeaderValue)> {
    let mut h = Vec::new();
    if let (Some(first), Some(last)) = (
        rows.iter().map(|r| r.date_added).min(),
        rows.iter().map(|r| r.date_added).max(),
    ) {
        for (name, ms) in [
            ("x-taxii-date-added-first", first),
            ("x-taxii-date-added-last", last),
        ] {
            if let Ok(v) = HeaderValue::from_str(&timestamp(ms)) {
                h.push((HeaderName::from_static(name), v));
            }
        }
    }
    h
}

/// A TAXII envelope (or version list) over items already serialised as
/// JSON text, joined without parsing them again.
fn envelope<'a>(
    p: &Page,
    key: &str,
    items: impl Iterator<Item = std::borrow::Cow<'a, str>>,
) -> String {
    let mut out = format!("{{\"more\":{}", p.more);
    if let Some(n) = &p.next {
        out.push_str(",\"next\":");
        out.push_str(&Value::String(n.clone()).to_string());
    }
    let mut first = true;
    for item in items {
        if first {
            out.push_str(&format!(",\"{key}\":["));
        } else {
            out.push(',');
        }
        out.push_str(&item);
        first = false;
    }
    if !first {
        out.push(']');
    }
    out.push('}');
    out
}

fn with_headers(mut res: Response, extra: Vec<(HeaderName, HeaderValue)>) -> Response {
    for (k, v) in extra {
        res.headers_mut().insert(k, v);
    }
    res
}

fn object_page(p: Page) -> Response {
    let extra = page_headers(&p.rows);
    let body = envelope(
        &p,
        "objects",
        p.rows.iter().map(|r| r.content.as_str().into()),
    );
    with_headers(taxii_text(body), extra)
}

async fn objects(
    State(state): State<AppState>,
    auth: Result<Auth, ApiError>,
    headers: HeaderMap,
    Path(id): Path<String>,
    q: Result<Query<ObjectsQuery>, QueryRejection>,
) -> TaxiiResult {
    let auth = guard(auth, &headers)?;
    let q = query(q)?;
    check_collection(&id)?;
    let p = page(&state, &auth, &q, None, VersionFilter::last()).await?;
    Ok(object_page(p))
}

async fn object(
    State(state): State<AppState>,
    auth: Result<Auth, ApiError>,
    headers: HeaderMap,
    Path((id, object_id)): Path<(String, String)>,
    q: Result<Query<ObjectsQuery>, QueryRejection>,
) -> TaxiiResult {
    let auth = guard(auth, &headers)?;
    let q = query(q)?;
    check_collection(&id)?;
    let p = page(&state, &auth, &q, Some(&object_id), VersionFilter::last()).await?;
    if p.rows.is_empty() && q.next.is_none() {
        return Err(TaxiiError::new(StatusCode::NOT_FOUND, "Object not found"));
    }
    Ok(object_page(p))
}

async fn versions(
    State(state): State<AppState>,
    auth: Result<Auth, ApiError>,
    headers: HeaderMap,
    Path((id, object_id)): Path<(String, String)>,
    q: Result<Query<ObjectsQuery>, QueryRejection>,
) -> TaxiiResult {
    let auth = guard(auth, &headers)?;
    let mut q = query(q)?;
    check_collection(&id)?;
    // Every version, oldest first; match[version] does not apply here.
    q.match_version = None;
    let p = page(&state, &auth, &q, Some(&object_id), VersionFilter::all()).await?;
    if p.rows.is_empty() && q.next.is_none() {
        return Err(TaxiiError::new(StatusCode::NOT_FOUND, "Object not found"));
    }
    let extra = page_headers(&p.rows);
    let body = envelope(
        &p,
        "versions",
        p.rows
            .iter()
            .map(|r| Value::String(r.version.clone()).to_string().into()),
    );
    Ok(with_headers(taxii_text(body), extra))
}

async fn manifest(
    State(state): State<AppState>,
    auth: Result<Auth, ApiError>,
    headers: HeaderMap,
    Path(id): Path<String>,
    q: Result<Query<ObjectsQuery>, QueryRejection>,
) -> TaxiiResult {
    let auth = guard(auth, &headers)?;
    let q = query(q)?;
    check_collection(&id)?;
    let p = page(&state, &auth, &q, None, VersionFilter::last()).await?;
    let extra = page_headers(&p.rows);
    let body = envelope(
        &p,
        "objects",
        p.rows.iter().map(|r| {
            json!({
                "id": r.id,
                "date_added": timestamp(r.date_added),
                "version": r.version,
                "media_type": stix::MEDIA_TYPE,
            })
            .to_string()
            .into()
        }),
    );
    Ok(with_headers(taxii_text(body), extra))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accept_header_negotiation() {
        let mut h = HeaderMap::new();
        assert!(acceptable(&h));
        for (v, ok) in [
            ("application/taxii+json;version=2.1", true),
            ("application/taxii+json", true),
            ("application/json, */*", true),
            ("application/taxii+json; version=2.0", false),
            ("text/html", false),
        ] {
            h.insert(header::ACCEPT, HeaderValue::from_static(v));
            assert_eq!(acceptable(&h), ok, "{v}");
        }
    }
}
