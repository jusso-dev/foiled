//! The actor catalogue from ThreatSieve (#29): the hourly cron's sync run
//! and the catalogue the API serves.
//!
//! A run reads the saved [`SyncState`], makes at most `calls_per_run`
//! calls over the ThreatSieve client from enrichment (#11, the
//! `THREATSIEVE` service binding, opt-in), saves the state, and on
//! completion writes a versioned snapshot plus a pointer holding its
//! SHA-256. Readers refuse a snapshot whose digest differs from the
//! pointer (a torn or corrupt write; it is not a defence against someone
//! who can write the bucket), and serve imports only while the snapshot is
//! fresh; otherwise the catalogue is the bundled ATT&CK groups and curated
//! reports.
//!
//! Storage sits behind [`Blobs`] (R2 on Workers, [`MemoryBlobs`] in tests)
//! and HTTP behind [`ProviderHttp`], so the whole flow runs on the host
//! against a fake ThreatSieve. Design: `docs/actor-attribution.md`.

use std::collections::BTreeMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex, OnceLock};

use foiled_core::actor::ActorCatalogue;
use foiled_core::actor_sync::{
    CatalogueConfig, LayeredSource, Snapshot, SnapshotPointer, SyncError, SyncState, body_sha256,
    snapshot,
};
use foiled_core::enrich_pipeline::retry_after_secs;

use crate::enrich_consumer::ProviderHttp;

const HOUR_MS: i64 = 3_600_000;

static CONFIG: &str = include_str!(concat!(env!("OUT_DIR"), "/actor_catalogue_config.json"));

/// `configs/actor-catalogue.yaml`, validated by `foiled-lint` in CI. `None`
/// if it does not load, which leaves the bundled catalogue in place.
pub fn bundled_config() -> Option<&'static CatalogueConfig> {
    static PARSED: OnceLock<Option<CatalogueConfig>> = OnceLock::new();
    PARSED
        .get_or_init(|| {
            serde_json::from_str::<CatalogueConfig>(CONFIG)
                .ok()
                .filter(|c| c.problems().is_empty())
        })
        .as_ref()
}

pub type BlobFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T, String>> + 'a>>;

/// Small JSON documents by key.
pub trait Blobs {
    fn get(&self, key: &str) -> BlobFuture<'_, Option<String>>;
    fn put(&self, key: &str, body: String) -> BlobFuture<'_, ()>;
}

/// In-memory [`Blobs`] for tests and the local mock server.
#[derive(Default)]
pub struct MemoryBlobs(Mutex<BTreeMap<String, String>>);

impl MemoryBlobs {
    pub fn keys(&self) -> Vec<String> {
        self.0.lock().unwrap().keys().cloned().collect()
    }
}

impl Blobs for MemoryBlobs {
    fn get(&self, key: &str) -> BlobFuture<'_, Option<String>> {
        let v = self.0.lock().unwrap().get(key).cloned();
        Box::pin(std::future::ready(Ok(v)))
    }

    fn put(&self, key: &str, body: String) -> BlobFuture<'_, ()> {
        self.0.lock().unwrap().insert(key.to_string(), body);
        Box::pin(std::future::ready(Ok(())))
    }
}

pub struct SyncDeps<'a> {
    pub blobs: &'a dyn Blobs,
    /// The ThreatSieve binding, when the operator configured one.
    pub http: Option<&'a dyn ProviderHttp>,
    /// Reads a Worker secret by name.
    pub secret: &'a dyn Fn(&str) -> Option<String>,
    pub config: &'a CatalogueConfig,
    pub now_ms: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SyncOutcome {
    Disabled,
    /// Enabled, but the binding or the key is missing.
    NotConfigured(&'static str),
    /// The snapshot is younger than `refresh_after_hours`.
    UpToDate,
    /// Calls made; the sync goes on next run.
    Progress {
        calls: u32,
    },
    /// ThreatSieve asked to wait, or R2 failed; the sync goes on next run.
    Waiting {
        calls: u32,
        retry_after_secs: Option<u32>,
    },
    /// ThreatSieve refused or answered nonsense; the same call is made
    /// again next run, and the sync starts over only after
    /// `max_sync_hours` without progress.
    Stalled {
        calls: u32,
        why: String,
    },
    /// The sync finished without a single entity: nothing is published and
    /// the next sync starts after `refresh_after_hours`.
    Restarted(String),
    /// A new snapshot is current.
    Completed {
        imported: u32,
        key: String,
    },
}

fn key(cfg: &CatalogueConfig, name: &str) -> String {
    format!("{}{name}", cfg.threatsieve.blob_prefix)
}

async fn read_json<T: serde::de::DeserializeOwned>(blobs: &dyn Blobs, k: &str) -> Option<T> {
    let body = blobs.get(k).await.ok()??;
    serde_json::from_str(&body).ok()
}

async fn pointer(blobs: &dyn Blobs, cfg: &CatalogueConfig) -> Option<SnapshotPointer> {
    read_json(blobs, &key(cfg, "current.json")).await
}

async fn save_state(d: &SyncDeps<'_>, state: &SyncState) -> Result<(), String> {
    let body = serde_json::to_string(state).map_err(|e| e.to_string())?;
    d.blobs.put(&key(d.config, "state.json"), body).await
}

/// One cron run of the sync. Never panics and never fails the cron: what
/// happened is in the outcome, to log.
///
/// Progress is never thrown away: a sync resumes where it stopped until it
/// has made no progress for `max_sync_hours`, and a finished sync whose
/// snapshot or pointer write failed is published again from the saved
/// state, without calling ThreatSieve.
pub async fn run_sync(d: &SyncDeps<'_>) -> SyncOutcome {
    let t = &d.config.threatsieve;
    if !t.enabled {
        return SyncOutcome::Disabled;
    }
    let Some(http) = d.http else {
        return SyncOutcome::NotConfigured("no THREATSIEVE service binding");
    };
    let Some(api_key) = (d.secret)(&t.api_key_env).filter(|k| !k.is_empty()) else {
        return SyncOutcome::NotConfigured("no ThreatSieve API key secret");
    };
    let saved: Option<SyncState> = read_json::<SyncState>(d.blobs, &key(d.config, "state.json"))
        .await
        .filter(|s| s.format == foiled_core::actor_sync::FORMAT);
    let max_idle = i64::from(t.max_sync_hours) * HOUR_MS;
    let mut state = match saved {
        // Finished but not written: write it again while it is still worth
        // serving (a state without `finished_at` predates this format).
        Some(s)
            if s.is_done()
                && !s.published
                && s.finished_at.is_some_and(|at| {
                    d.now_ms - at <= i64::from(t.stale_after_hours) * HOUR_MS
                }) =>
        {
            s
        }
        Some(s) if !s.is_done() && d.now_ms - s.last_progress() <= max_idle => s,
        saved => {
            let last_sync = match saved.as_ref().filter(|s| s.is_done()) {
                Some(s) => s.finished_at,
                None => pointer(d.blobs, d.config).await.map(|p| p.synced_at),
            };
            if last_sync
                .is_some_and(|at| d.now_ms - at < i64::from(t.refresh_after_hours) * HOUR_MS)
            {
                return SyncOutcome::UpToDate;
            }
            let mut fresh = SyncState::new(d.now_ms);
            if saved.is_some_and(|s| !s.is_done()) {
                fresh.last_error = Some(format!(
                    "the previous sync made no progress for {} hours",
                    t.max_sync_hours
                ));
            }
            fresh
        }
    };
    let mut calls = 0;
    while calls < t.calls_per_run {
        let Some(req) = state.next_request(&api_key) else {
            break;
        };
        calls += 1;
        let reply = match http.send(req).await {
            Ok(r) => r,
            Err(_) => {
                let _ = save_state(d, &state).await;
                return SyncOutcome::Waiting {
                    calls,
                    retry_after_secs: None,
                };
            }
        };
        let wait = reply
            .retry_after
            .as_deref()
            .map(|h| retry_after_secs(Some(h)));
        match state.apply(t, reply.status, &reply.body, wait) {
            Ok(()) => state.progress_at = d.now_ms,
            Err(SyncError::Later { retry_after_secs }) => {
                let _ = save_state(d, &state).await;
                return SyncOutcome::Waiting {
                    calls,
                    retry_after_secs,
                };
            }
            Err(SyncError::Refused(why)) => {
                state.last_error = Some(why.clone());
                let _ = save_state(d, &state).await;
                return SyncOutcome::Stalled { calls, why };
            }
        }
    }
    if !state.is_done() {
        let _ = save_state(d, &state).await;
        return SyncOutcome::Progress { calls };
    }
    if state.details.is_empty() {
        // Nothing listed, or every detail failed: never replace a good
        // snapshot with an empty one. Recorded as a finished sync, so the
        // next attempt waits for refresh_after_hours instead of running a
        // full sync every hour.
        let why = "the sync found no entity to import".to_string();
        let mut done = SyncState::new(d.now_ms);
        done.phase = foiled_core::actor_sync::Phase::Done;
        done.finished_at = Some(d.now_ms);
        done.published = true;
        done.last_error = Some(why.clone());
        let _ = save_state(d, &done).await;
        return SyncOutcome::Restarted(why);
    }
    let synced_at = *state.finished_at.get_or_insert(d.now_ms);
    let snap = snapshot(&state, crate::links::attack_sidecar(), synced_at);
    let Ok(body) = serde_json::to_string(&snap) else {
        let _ = save_state(d, &state).await;
        return SyncOutcome::Stalled {
            calls,
            why: "snapshot did not serialise".into(),
        };
    };
    let snap_key = key(d.config, &format!("snapshots/{}.json", snap.synced_at));
    let p = SnapshotPointer {
        format: snap.format,
        key: snap_key.clone(),
        synced_at: snap.synced_at,
        sha256: body_sha256(&body),
        imported: snap.counts.imported,
    };
    // Snapshot first, pointer last: a reader never sees a pointer to a
    // snapshot that is not there. If either write fails the finished state
    // is kept and the next run writes both again.
    let pointer_body = serde_json::to_string(&p).unwrap_or_default();
    let written = d.blobs.put(&snap_key, body).await.is_ok()
        && d.blobs
            .put(&key(d.config, "current.json"), pointer_body)
            .await
            .is_ok();
    if !written {
        let _ = save_state(d, &state).await;
        return SyncOutcome::Waiting {
            calls,
            retry_after_secs: None,
        };
    }
    // Published: the entities are in the snapshot now.
    state.published = true;
    state.queue.clear();
    state.details.clear();
    state.reports.clear();
    let _ = save_state(d, &state).await;
    SyncOutcome::Completed {
        imported: p.imported,
        key: snap_key,
    }
}

/// The current snapshot, if its body matches the pointer's digest and it
/// is fresh. With its digest, for callers that cache by it.
pub async fn current_snapshot(
    blobs: &dyn Blobs,
    cfg: &CatalogueConfig,
    now: i64,
) -> Option<(String, Snapshot)> {
    let p = pointer(blobs, cfg).await?;
    snapshot_at(blobs, cfg, &p, now).await
}

async fn snapshot_at(
    blobs: &dyn Blobs,
    cfg: &CatalogueConfig,
    p: &SnapshotPointer,
    now: i64,
) -> Option<(String, Snapshot)> {
    if !p.key.starts_with(&cfg.threatsieve.blob_prefix) || !p.is_fresh(&cfg.threatsieve, now) {
        return None;
    }
    let body = blobs.get(&p.key).await.ok()??;
    if body_sha256(&body) != p.sha256 {
        return None;
    }
    let snap: Snapshot = serde_json::from_str(&body).ok()?;
    snap.is_fresh(&cfg.threatsieve, now)
        .then(|| (p.sha256.clone(), snap))
}

/// The catalogue to serve: the bundled ATT&CK groups and curated reports,
/// plus a fresh snapshot's imports.
pub fn catalogue(snapshot: Option<&Snapshot>, cfg: &CatalogueConfig, now: i64) -> ActorCatalogue {
    use foiled_core::actor::CatalogueSource;
    let bundled = crate::links::BundledActors;
    let source = LayeredSource {
        groups: bundled.attack_groups(),
        curated: bundled.reports(),
        snapshot,
        config: &cfg.threatsieve,
        now,
    };
    ActorCatalogue::from_source(&source, crate::links::attack_sidecar())
}

/// A served catalogue, the snapshot digest it was built from (`None` for
/// the bundled catalogue alone) and when the pointer was last read.
#[derive(Clone)]
pub struct CachedCatalogue {
    pub checked_at: i64,
    pub sha256: Option<String>,
    pub catalogue: Arc<ActorCatalogue>,
}

/// [`catalogue`] from what `blobs` holds now. With `prev`, only the small
/// pointer is read when its digest is unchanged and the snapshot still
/// fresh; the snapshot body is read and parsed only when it changed.
pub async fn refresh_catalogue(
    blobs: &dyn Blobs,
    cfg: &CatalogueConfig,
    now: i64,
    prev: Option<&CachedCatalogue>,
) -> CachedCatalogue {
    let bundled = || CachedCatalogue {
        checked_at: now,
        sha256: None,
        catalogue: crate::links::bundled_actor_catalogue(),
    };
    if !cfg.threatsieve.enabled {
        return bundled();
    }
    let Some(p) = pointer(blobs, cfg).await else {
        return bundled();
    };
    if let Some(prev) = prev
        && prev.sha256.as_deref() == Some(p.sha256.as_str())
        && p.is_fresh(&cfg.threatsieve, now)
    {
        return CachedCatalogue {
            checked_at: now,
            ..prev.clone()
        };
    }
    match snapshot_at(blobs, cfg, &p, now).await {
        Some((sha, snap)) => CachedCatalogue {
            checked_at: now,
            sha256: Some(sha),
            catalogue: Arc::new(catalogue(Some(&snap), cfg, now)),
        },
        None => bundled(),
    }
}

/// [`refresh_catalogue`] with nothing cached.
pub async fn load_catalogue(
    blobs: &dyn Blobs,
    cfg: &CatalogueConfig,
    now: i64,
) -> (Option<String>, Arc<ActorCatalogue>) {
    let c = refresh_catalogue(blobs, cfg, now, None).await;
    (c.sha256, c.catalogue)
}
