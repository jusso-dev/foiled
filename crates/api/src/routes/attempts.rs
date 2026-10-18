//! `GET /v0/attempts` and `GET /v0/attempts/{id}` (#25), and the attempt
//! timeline `GET /v0/attempts/{id}/timeline` (#10). `ioc_refs` on every
//! attempt is filled from IOC extraction over the same window (#34).
//!
//! Attempts are a read model: built on request from the capture events in a
//! time window with the deterministic grouping in `foiled_core::attempt`,
//! so the same evidence always gives the same attempts and ids.
//! `campaign_id` is filled from campaign clustering over the same window
//! (#33, `foiled_core::campaign`). Windows are
//! bounded (default 7 days, at most 20,000 events) to stay inside Workers
//! CPU limits; a materialised table can replace this without changing the
//! contract.

use axum::extract::{Path, Query, State};
use axum::http::header;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use foiled_core::attempt::{Attempt, AttemptState, DEFAULT_IDLE_GAP_MS, build};
use foiled_core::auth::Scope;
use foiled_core::catalogue::DecoyKind;
use serde::{Deserialize, Serialize};

use crate::AppState;
use crate::auth::Auth;
use crate::error::ApiError;
use crate::routes::page_limit;

pub const MAX_WINDOW_EVENTS: usize = 20_000;
const DAY_MS: i64 = 24 * 3600 * 1000;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/v0/attempts", get(list))
        .route("/v0/attempts/{attempt_id}", get(get_one))
        .route("/v0/attempts/{attempt_id}/timeline", get(timeline))
        .route(
            "/v0/attempts/{attempt_id}/links",
            get(links).post(override_link),
        )
}

#[derive(Debug, Deserialize, Default)]
pub struct AttemptQuery {
    pub since: Option<i64>,
    pub until: Option<i64>,
    pub decoy_id: Option<String>,
    pub decoy_kind: Option<DecoyKind>,
    pub sensor_id: Option<String>,
    pub src: Option<String>,
    pub state: Option<AttemptState>,
    pub cve: Option<String>,
    pub campaign_id: Option<String>,
    /// ATT&CK technique id, for example `T1190`. Matches attempts with a
    /// technique link to it (#26, #27).
    pub technique: Option<String>,
    /// 0 to 100. Matches attempts with a CVE or technique link (or, with
    /// `technique`, that technique's link) scoring at least this much.
    pub min_confidence: Option<u8>,
    pub limit: Option<usize>,
}

#[derive(Debug, Serialize)]
pub struct AttemptList {
    pub items: Vec<Attempt>,
    /// True when the window held more events than the cap; narrow it.
    pub truncated: bool,
}

/// Build attempts for a tenant over a window, with `campaign_id` read from
/// the campaign registry (no clustering).
pub(crate) async fn attempts_in_window(
    state: &AppState,
    tenant_id: &str,
    since: i64,
    until: i64,
) -> Result<(Vec<Attempt>, bool), ApiError> {
    let m = window_model(
        state,
        tenant_id,
        since,
        until,
        Iocs::Attach,
        Campaigns::Registry,
    )
    .await?;
    Ok((m.attempts, m.truncated))
}

/// Attempts plus events, without IOC extraction or campaign clustering
/// (`ioc_refs` stay empty, `campaign_id` stays null), for routes that never
/// return attempts (links and overrides).
pub(crate) async fn attempts_and_events_without_iocs(
    state: &AppState,
    tenant_id: &str,
    since: i64,
    until: i64,
) -> Result<(Vec<Attempt>, Vec<foiled_core::capture::CaptureEvent>), ApiError> {
    let m = window_model(state, tenant_id, since, until, Iocs::Skip, Campaigns::Skip).await?;
    Ok((m.attempts, m.events))
}

/// Whether to extract IOCs (#34) while building a window.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Iocs {
    /// Extract and fill `ioc_refs` on the attempts.
    Attach,
    /// Skip extraction; `ioc_refs` stay empty and `iocs` is empty.
    Skip,
}

/// How a window gets its campaigns (#33).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Campaigns {
    /// Cluster (needs `Iocs::Attach`), replay analyst actions, update the
    /// registry, and fill `campaign_id` and `campaign_ids`.
    Full,
    /// Fill `campaign_id` and `campaign_ids` from the registry only: one
    /// store read, no clustering and no actions. Ids are as of the last
    /// full read, which every list and campaign read makes.
    Registry,
    /// Nothing: `campaign_id` stays null.
    Skip,
}

/// Everything built from one window of a tenant's capture events.
pub(crate) struct WindowModel {
    /// With `ioc_refs` filled from `iocs`.
    pub attempts: Vec<Attempt>,
    pub events: Vec<foiled_core::capture::CaptureEvent>,
    /// IOCs extracted from the attempts (#34), without enrichment.
    pub iocs: foiled_core::ioc::Extraction,
    /// Campaigns clustered from the attempts (#33), with `Campaigns::Full`.
    pub campaigns: foiled_core::campaign::Clustering,
    /// What the clustering read, with `Campaigns::Full`, so a caller can
    /// cluster again (for example after recording an action).
    pub inputs: Option<ClusterInputs>,
    pub truncated: bool,
}

/// Build attempts, their IOCs and their campaigns for a tenant over a window.
pub(crate) async fn window_model(
    state: &AppState,
    tenant_id: &str,
    since: i64,
    until: i64,
    iocs: Iocs,
    campaigns: Campaigns,
) -> Result<WindowModel, ApiError> {
    if until <= since || until - since > 31 * DAY_MS {
        return Err(ApiError::bad_request(
            "window must be positive and at most 31 days",
        ));
    }
    let events = state
        .store
        .events_between(tenant_id, since, until, MAX_WINDOW_EVENTS + 1)
        .await?;
    let truncated = events.len() > MAX_WINDOW_EVENTS;
    let mut events = events;
    events.truncate(MAX_WINDOW_EVENTS);
    let signals = crate::links::matcher_signals(&events);
    let mut attempts = build(&events, DEFAULT_IDLE_GAP_MS, &signals);
    // Payload storage is off by default (#16), so inline bodies never
    // become IOC values here; their hashes do.
    let mut x = match iocs {
        Iocs::Attach => {
            let x = foiled_core::ioc::extract(
                &attempts,
                &events,
                &foiled_core::confidence::ConfidenceConfig::default(),
                foiled_core::ioc::ExtractOptions::default(),
            );
            foiled_core::ioc::attach_refs(&mut attempts, &x);
            x
        }
        Iocs::Skip => foiled_core::ioc::Extraction::default(),
    };
    let (clustering, inputs) = match campaigns {
        Campaigns::Full => {
            let inputs = cluster_inputs(state, tenant_id, &attempts, &events).await?;
            let c = run_clustering(state, tenant_id, &inputs, &attempts, &x, true).await;
            foiled_core::campaign::attach(&mut attempts, &mut x, &c);
            (c, Some(inputs))
        }
        Campaigns::Registry => {
            let registry = load_registry(state, tenant_id, &attempts).await?;
            let carried = registry
                .members
                .iter()
                .map(|(a, c)| (a.clone(), registry.resolve(c).to_string()))
                .collect();
            let from_registry = foiled_core::campaign::Clustering {
                carried,
                ..Default::default()
            };
            foiled_core::campaign::attach(&mut attempts, &mut x, &from_registry);
            (Default::default(), None)
        }
        Campaigns::Skip => (Default::default(), None),
    };
    Ok(WindowModel {
        attempts,
        events,
        iocs: x,
        campaigns: clustering,
        inputs,
        truncated,
    })
}

/// What campaign clustering reads besides the attempts and IOCs.
pub(crate) struct ClusterInputs {
    pub signals: std::collections::BTreeMap<String, foiled_core::campaign::AttemptSignals>,
    pub asns: std::collections::BTreeMap<String, u32>,
    pub advisories: std::collections::BTreeMap<String, i64>,
    pub actions: Vec<foiled_core::campaign::CampaignAction>,
    pub registry: foiled_core::campaign::Registry,
}

/// Gather clustering inputs (#33): CVE and technique signals from the
/// bundled rule packs (#12, #26), ASN numbers from cached enrichment Facts
/// (#11), advisory dates, the tenant's analyst actions (every structural
/// one, the newest feedback) and the registry for these attempts.
pub(crate) async fn cluster_inputs(
    state: &AppState,
    tenant_id: &str,
    attempts: &[Attempt],
    events: &[foiled_core::capture::CaptureEvent],
) -> Result<ClusterInputs, ApiError> {
    use foiled_core::campaign;
    let signals = campaign::attempt_signals(
        attempts,
        events,
        crate::links::attack_rules(),
        crate::links::cve_rules(),
    );
    let asns = source_asns(state, tenant_id, attempts).await?;
    let advisories = crate::links::cve_rules()
        .advisories
        .iter()
        .map(|a| (a.cve_id.to_ascii_uppercase(), a.published_at))
        .collect();
    let actions = state
        .store
        .campaign_actions(tenant_id, campaign::MAX_FEEDBACK_ACTIONS)
        .await?;
    let registry = load_registry(state, tenant_id, attempts).await?;
    Ok(ClusterInputs {
        signals,
        asns,
        advisories,
        actions,
        registry,
    })
}

/// Cluster and, when `record` is set, write what changed to the registry.
/// A failed registry write does not fail the read; it is noted, and the
/// next read writes again.
pub(crate) async fn run_clustering(
    state: &AppState,
    tenant_id: &str,
    inputs: &ClusterInputs,
    attempts: &[Attempt],
    iocs: &foiled_core::ioc::Extraction,
    record: bool,
) -> foiled_core::campaign::Clustering {
    use foiled_core::campaign;
    let now = (state.clock)();
    let mut c = campaign::cluster(
        &campaign::Input {
            tenant_id,
            attempts,
            iocs,
            signals: &inputs.signals,
            asns: &inputs.asns,
            advisories: &inputs.advisories,
            actions: &inputs.actions,
            registry: &inputs.registry,
            now,
        },
        campaign::Params::default(),
        &foiled_core::confidence::ConfidenceConfig::default(),
    );
    if record && !c.registry_update.is_empty() {
        let update = std::mem::take(&mut c.registry_update);
        if state
            .store
            .update_campaign_registry(tenant_id, update, now)
            .await
            .is_err()
        {
            c.notes.push(
                "The campaign registry could not be updated; new campaign ids are recorded on \
                 the next read."
                    .into(),
            );
        }
    }
    c
}

/// The registry entries for these attempts, with the records of their
/// campaigns and of any campaign those were merged into.
pub(crate) async fn load_registry(
    state: &AppState,
    tenant_id: &str,
    attempts: &[Attempt],
) -> Result<foiled_core::campaign::Registry, ApiError> {
    use foiled_core::campaign::{MAX_MERGE_HOPS, Registry};
    let mut registry = Registry::default();
    if attempts.is_empty() {
        return Ok(registry);
    }
    let ids = attempts.iter().map(|a| a.attempt_id.clone()).collect();
    registry.members = state
        .store
        .campaign_memberships(tenant_id, ids)
        .await?
        .into_iter()
        .collect();
    let mut wanted: Vec<String> = registry
        .members
        .values()
        .cloned()
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .collect();
    for _ in 0..MAX_MERGE_HOPS {
        if wanted.is_empty() {
            break;
        }
        for c in state.store.campaign_records(tenant_id, wanted).await? {
            registry.campaigns.insert(c.campaign_id.clone(), c);
        }
        wanted = registry.missing_targets();
    }
    Ok(registry)
}

/// Source address to ASN number, from the newest cached `asn.number` Fact
/// for each address. Addresses with no Fact are left out.
async fn source_asns(
    state: &AppState,
    tenant_id: &str,
    attempts: &[Attempt],
) -> Result<std::collections::BTreeMap<String, u32>, ApiError> {
    use foiled_core::enrichment::Observable;
    use std::collections::BTreeMap;
    let mut by_observable: BTreeMap<Observable, Vec<&str>> = BTreeMap::new();
    for a in attempts {
        if let Ok(o) = Observable::ip(&a.src) {
            by_observable.entry(o).or_default().push(a.src.as_str());
        }
    }
    if by_observable.is_empty() {
        return Ok(BTreeMap::new());
    }
    let observed = state
        .store
        .enrichment_facts(tenant_id, by_observable.keys().cloned().collect())
        .await?;
    let mut newest: BTreeMap<Observable, (i64, u32)> = BTreeMap::new();
    for o in observed {
        for f in o.facts.iter().filter(|f| f.key == "asn.number") {
            let Some(n) = f.value.as_u64().and_then(|n| u32::try_from(n).ok()) else {
                continue;
            };
            let e = newest
                .entry(o.observable.clone())
                .or_insert((f.observed_at, n));
            if (f.observed_at, n) > *e {
                *e = (f.observed_at, n);
            }
        }
    }
    let mut out = BTreeMap::new();
    for (o, (_, n)) in newest {
        for src in by_observable.get(&o).into_iter().flatten() {
            out.insert((*src).to_string(), n);
        }
    }
    Ok(out)
}

/// `since` and `until` with defaults: the 7 days up to now.
pub(crate) fn window_bounds(
    state: &AppState,
    since: Option<i64>,
    until: Option<i64>,
) -> (i64, i64) {
    let until = until.unwrap_or_else(|| (state.clock)() + 1);
    let since = since.unwrap_or(until - 7 * DAY_MS);
    (since, until)
}

fn window(state: &AppState, q: &AttemptQuery) -> (i64, i64) {
    window_bounds(state, q.since, q.until)
}

async fn list(
    State(state): State<AppState>,
    auth: Auth,
    Query(q): Query<AttemptQuery>,
) -> Result<Json<AttemptList>, ApiError> {
    let who = auth.require(Scope::AttemptsRead)?;
    if q.min_confidence.is_some_and(|m| m > 100) {
        return Err(ApiError::bad_request(
            "min_confidence must be between 0 and 100",
        ));
    }
    let (since, until) = window(&state, &q);
    let m = window_model(
        &state,
        &who.tenant_id,
        since,
        until,
        Iocs::Attach,
        Campaigns::Full,
    )
    .await?;
    let (attempts, events, truncated) = (m.attempts, m.events, m.truncated);
    let mut items: Vec<Attempt> = attempts
        .into_iter()
        .filter(|a| q.decoy_id.as_deref().is_none_or(|d| a.decoy_id == d))
        .filter(|a| q.decoy_kind.is_none_or(|k| a.decoy_kind == k))
        .filter(|a| {
            q.sensor_id
                .as_deref()
                .is_none_or(|s| a.sensor_id.as_deref() == Some(s))
        })
        .filter(|a| q.src.as_deref().is_none_or(|s| a.src == s))
        .filter(|a| q.state.is_none_or(|s| a.state == s))
        .filter(|a| {
            q.campaign_id
                .as_deref()
                .is_none_or(|c| a.campaign_id.as_deref() == Some(c))
        })
        .filter(|a| {
            q.cve.as_deref().is_none_or(|c| {
                a.hook_hits.iter().any(|h| {
                    h.cve_id
                        .as_deref()
                        .is_some_and(|x| x.eq_ignore_ascii_case(c))
                })
            })
        })
        .collect();
    if q.technique.is_some() || q.min_confidence.is_some() {
        let by_id: std::collections::HashMap<&str, &foiled_core::capture::CaptureEvent> =
            events.iter().map(|e| (e.event_id.as_str(), e)).collect();
        items.retain(|a| link_filter_matches(&state, a, &by_id, &q));
    }
    // Newest activity first.
    items.sort_by(|a, b| (b.last_seen, &b.attempt_id).cmp(&(a.last_seen, &a.attempt_id)));
    items.truncate(page_limit(q.limit));
    Ok(Json(AttemptList { items, truncated }))
}

/// The `technique` and `min_confidence` filters. Scores here are the
/// computed ones, before analyst overrides, so a list query never costs a
/// store read per attempt; `/links` shows the overridden score.
fn link_filter_matches(
    state: &AppState,
    attempt: &Attempt,
    by_id: &std::collections::HashMap<&str, &foiled_core::capture::CaptureEvent>,
    q: &AttemptQuery,
) -> bool {
    use foiled_core::confidence::LinkKind;
    let mine: Vec<_> = attempt
        .event_ids
        .iter()
        .filter_map(|id| by_id.get(id.as_str()).map(|e| (*e).clone()))
        .collect();
    let links = crate::links::links_for_attempt(
        &foiled_core::confidence::ConfidenceConfig::default(),
        state.catalogue.get(&attempt.catalogue_id),
        attempt,
        &mine,
        &std::collections::BTreeMap::new(),
    );
    let min = q.min_confidence.unwrap_or(0);
    links.iter().any(|l| {
        l.score >= min
            && match q.technique.as_deref() {
                Some(t) => l.kind == LinkKind::AttemptTechnique && l.target.eq_ignore_ascii_case(t),
                None => matches!(l.kind, LinkKind::AttemptCve | LinkKind::AttemptTechnique),
            }
    })
}

async fn get_one(
    State(state): State<AppState>,
    auth: Auth,
    Path(attempt_id): Path<String>,
    Query(q): Query<AttemptQuery>,
) -> Result<Json<Attempt>, ApiError> {
    let who = auth.require(Scope::AttemptsRead)?;
    let (since, until) = window(&state, &q);
    let (attempts, _) = attempts_in_window(&state, &who.tenant_id, since, until).await?;
    attempts
        .into_iter()
        .find(|a| a.attempt_id == attempt_id)
        .map(Json)
        .ok_or_else(|| ApiError::not_found("attempt"))
}

#[derive(Debug, Deserialize, Default, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum TimelineFormat {
    #[default]
    Json,
    Text,
}

#[derive(Debug, Deserialize, Default)]
pub struct FormatQuery {
    #[serde(default)]
    pub format: TimelineFormat,
}

/// The attempt's events in order, with state changes and a pcap extract
/// recipe (`docs/attempt-timeline.md`). `format=text` gives the escaped
/// plain-text rendering.
async fn timeline(
    State(state): State<AppState>,
    auth: Auth,
    Path(attempt_id): Path<String>,
    Query(q): Query<AttemptQuery>,
    Query(f): Query<FormatQuery>,
) -> Result<Response, ApiError> {
    let who = auth.require(Scope::AttemptsRead)?;
    let (since, until) = window(&state, &q);
    // The timeline shows IOC refs but not the campaign, so no clustering.
    let m = window_model(
        &state,
        &who.tenant_id,
        since,
        until,
        Iocs::Attach,
        Campaigns::Skip,
    )
    .await?;
    let (attempts, events, truncated) = (m.attempts, m.events, m.truncated);
    let attempt = attempts
        .iter()
        .find(|a| a.attempt_id == attempt_id)
        .ok_or_else(|| ApiError::not_found("attempt"))?;
    let mut t = foiled_core::timeline::build_timeline(attempt, &events);
    if truncated {
        t.notes.push(format!(
            "The window held more than {MAX_WINDOW_EVENTS} events, so this attempt may be cut \
             short. Narrow since and until."
        ));
    }
    Ok(match f.format {
        TimelineFormat::Json => Json(t).into_response(),
        TimelineFormat::Text => (
            [
                (header::CONTENT_TYPE, "text/plain; charset=utf-8"),
                (header::X_CONTENT_TYPE_OPTIONS, "nosniff"),
            ],
            foiled_core::timeline::render_text(&t),
        )
            .into_response(),
    })
}

#[derive(Debug, Serialize)]
pub struct LinkList {
    pub items: Vec<foiled_core::confidence::ConfidenceLink>,
}

async fn attempt_links(
    state: &AppState,
    tenant_id: &str,
    attempt_id: &str,
    q: &AttemptQuery,
) -> Result<Vec<foiled_core::confidence::ConfidenceLink>, ApiError> {
    let (since, until) = window(state, q);
    let (attempts, events) =
        attempts_and_events_without_iocs(state, tenant_id, since, until).await?;
    let attempt = attempts
        .into_iter()
        .find(|a| a.attempt_id == attempt_id)
        .ok_or_else(|| ApiError::not_found("attempt"))?;
    let mine: Vec<_> = events
        .into_iter()
        .filter(|e| attempt.event_ids.contains(&e.event_id))
        .collect();
    let overrides = state
        .store
        .link_overrides(tenant_id, attempt_id)
        .await?
        .into_iter()
        .map(|o| ((o.kind, o.target), o.decision))
        .collect();
    Ok(crate::links::links_for_attempt(
        &foiled_core::confidence::ConfidenceConfig::default(),
        state.catalogue.get(&attempt.catalogue_id),
        &attempt,
        &mine,
        &overrides,
    ))
}

async fn links(
    State(state): State<AppState>,
    auth: Auth,
    Path(attempt_id): Path<String>,
    Query(q): Query<AttemptQuery>,
) -> Result<Json<LinkList>, ApiError> {
    let who = auth.require(Scope::AttemptsRead)?;
    let items = attempt_links(&state, &who.tenant_id, &attempt_id, &q).await?;
    Ok(Json(LinkList { items }))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OverrideBody {
    pub kind: foiled_core::confidence::LinkKind,
    pub target: String,
    pub feedback: foiled_core::confidence::Feedback,
    pub note: String,
}

/// Record an analyst decision on one link (audited), then return the link
/// as it scores now.
async fn override_link(
    State(state): State<AppState>,
    auth: Auth,
    Path(attempt_id): Path<String>,
    Query(q): Query<AttemptQuery>,
    crate::error::JsonBody(body): crate::error::JsonBody<OverrideBody>,
) -> Result<Json<foiled_core::confidence::ConfidenceLink>, ApiError> {
    let who = auth.require(Scope::AttemptsWrite)?.clone();
    // IOC confidence is one score per indicator across every attempt it was
    // seen in, so a per-attempt override has nothing to attach to. The
    // OpenAPI enum and the link_overrides CHECK leave attempt_ioc out for
    // the same reason (docs/iocs.md#confidence).
    if body.kind == foiled_core::confidence::LinkKind::AttemptIoc {
        return Err(ApiError::bad_request(
            "attempt_ioc links are scored per indicator and cannot be overridden per attempt",
        ));
    }
    if body.note.chars().count() > 1000 {
        return Err(ApiError::bad_request(
            "note must be at most 1000 characters",
        ));
    }
    let current = attempt_links(&state, &who.tenant_id, &attempt_id, &q).await?;
    if !current
        .iter()
        .any(|l| l.kind == body.kind && l.target == body.target)
    {
        return Err(ApiError::not_found("link"));
    }
    let decision = foiled_core::confidence::Override {
        feedback: body.feedback,
        analyst_id: who.id.clone(),
        at: (state.clock)(),
        note: body.note.clone(),
    };
    state
        .store
        .put_link_override(
            &who.tenant_id,
            crate::store::LinkOverride {
                attempt_id: attempt_id.clone(),
                kind: body.kind,
                target: body.target.clone(),
                decision,
            },
        )
        .await?;
    let mut rec = crate::routes::audit_record(
        &state,
        &who,
        "link.override",
        Some(&attempt_id),
        foiled_core::audit::Outcome::Accepted,
    );
    rec.detail = serde_json::json!({
        "kind": body.kind,
        "target": body.target,
        "feedback": body.feedback,
        "note": body.note,
    });
    state.store.append_audit(rec).await?;
    let updated = attempt_links(&state, &who.tenant_id, &attempt_id, &q).await?;
    updated
        .into_iter()
        .find(|l| l.kind == body.kind && l.target == body.target)
        .map(Json)
        .ok_or_else(|| ApiError::not_found("link"))
}
