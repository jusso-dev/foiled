//! Intel exports (#13, #22): STIX 2.1, MISP and IOC CSV and JSON
//! downloads, all built by `foiled_core::intel` from the same read model as
//! `/v0/attempts` and `/v0/iocs`.
//!
//! Every export is tenant-scoped (`exports:read`) and confidence-gated:
//! only publishable links and IOCs (at or above `publish_min`, not carried
//! only by LLM, pre-disclosure or catalogue evidence, #27) leave by
//! default. `include_unreviewed=true` lifts the gate for an analyst who
//! also holds `review:write`; that export is audited and marked
//! TLP:AMBER+STRICT or stricter. Enrichment context passes through
//! `ioc::export_refs`, so never-redistribute providers stay out. Exports
//! read live rows only, so anything the retention purge removed (#16)
//! never comes back, and nothing is stored: each download is built on
//! request.
//!
//! `GET /v0/exports/iocs.csv` keeps its #22 shape (one row per source IP)
//! unless `fields=ioc` asks for the #34 column list.

use std::collections::{BTreeMap, HashMap};

use axum::Router;
use axum::extract::{Query, State};
use axum::http::{HeaderName, HeaderValue, header};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use foiled_core::attempt::{Attempt, AttemptState};
use foiled_core::audit::Outcome;
use foiled_core::auth::{Principal, Scope};
use foiled_core::capture::CaptureEvent;
use foiled_core::catalogue::DecoyKind;
use foiled_core::confidence::{ConfidenceConfig, LinkKind, Override};
use foiled_core::enrichment::Observable;
use foiled_core::intel::{
    AttemptRecord, ExportInput, ExportOptions, Selection, attempt_matches, misp, select, stix,
    table,
};
use foiled_core::ioc::{EnrichmentRef, Extraction, Ioc, context_refs, export_refs};
use foiled_core::share::Tlp;
use foiled_core::timeline::iso;
use serde::Deserialize;

use crate::AppState;
use crate::auth::Auth;
use crate::catalogue::Catalogue;
use crate::error::ApiError;
use crate::routes::attempts::{Campaigns, EventCursor, Iocs, window_bounds, window_model_capped};
use crate::store::{IpIocRow, LinkOverride};

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/v0/exports/iocs.csv", get(iocs_csv))
        .route("/v0/exports/iocs.json", get(iocs_json))
        .route("/v0/exports/stix", get(stix_bundle))
        .route("/v0/exports/misp", get(misp_event))
}

/// Header saying the window held more events than the cap.
pub const TRUNCATED_HEADER: &str = "x-foiled-truncated";
/// Header carrying the `cursor` to continue from after a cut window.
pub const NEXT_CURSOR_HEADER: &str = "x-foiled-next-cursor";
/// Most events one export or TAXII page reads, below the attempts cap: at
/// this size the worst case (every event a distinct indicator) stays well
/// inside the Workers 128 MB isolate limit (`tests/export_bounds.rs`).
/// Larger windows are cut and say where to continue.
pub const EXPORT_WINDOW_EVENTS: usize = 4_000;

#[derive(Debug, Deserialize, Default)]
pub struct CsvQuery {
    /// Unix ms; default is the last 30 days (`fields=source` only).
    pub since: Option<i64>,
    /// `source` (default, the #22 columns) or `ioc` (the #34 columns).
    pub fields: Option<String>,
}

/// Filters and opt-ins shared by every export and by TAXII.
#[derive(Debug, Deserialize, Default, Clone)]
pub struct ExportQuery {
    pub since: Option<i64>,
    pub until: Option<i64>,
    pub min_confidence: Option<u8>,
    pub catalogue_id: Option<String>,
    pub state: Option<AttemptState>,
    pub campaign_id: Option<String>,
    pub decoy_kind: Option<DecoyKind>,
    #[serde(default)]
    pub include_unreviewed: bool,
    #[serde(default)]
    pub include_actors: bool,
    #[serde(default)]
    pub include_payloads: bool,
    /// `clear`, `green`, `amber` (default), `amber+strict` or `red`.
    pub tlp: Option<String>,
    /// From `x-foiled-next-cursor`: continue a cut export after this event.
    pub cursor: Option<String>,
}

/// Parse a TLP label. `+` arrives as a space in a query string, and
/// `amber_strict` is accepted too.
pub fn parse_tlp(s: &str) -> Option<Tlp> {
    Tlp::parse(&s.trim().to_ascii_lowercase().replace([' ', '_'], "+"))
}

const MAX_FILTER_CHARS: usize = 256;

impl ExportQuery {
    /// Validate and turn into core options.
    pub fn options(&self) -> Result<ExportOptions, ApiError> {
        if self.min_confidence.is_some_and(|m| m > 100) {
            return Err(ApiError::bad_request(
                "min_confidence must be between 0 and 100",
            ));
        }
        for f in [&self.catalogue_id, &self.campaign_id]
            .into_iter()
            .flatten()
        {
            if f.chars().nth(MAX_FILTER_CHARS).is_some() {
                return Err(ApiError::bad_request(format!(
                    "filters must be at most {MAX_FILTER_CHARS} characters"
                )));
            }
        }
        let tlp = match &self.tlp {
            None => Tlp::Amber,
            Some(t) => parse_tlp(t).ok_or_else(|| {
                ApiError::bad_request("tlp must be clear, green, amber, amber+strict or red")
            })?,
        };
        Ok(ExportOptions {
            min_confidence: self.min_confidence,
            catalogue_id: self.catalogue_id.clone(),
            state: self.state,
            campaign_id: self.campaign_id.clone(),
            decoy_kind: self.decoy_kind,
            include_unreviewed: self.include_unreviewed,
            include_actors: self.include_actors,
            include_payloads: self.include_payloads,
            tlp,
        })
    }
}

/// Analyst decisions keyed by attempt, then link.
pub type OverrideIndex = BTreeMap<String, BTreeMap<(LinkKind, String), Override>>;

pub fn index_overrides(list: Vec<LinkOverride>) -> OverrideIndex {
    let mut out = OverrideIndex::new();
    for o in list {
        out.entry(o.attempt_id)
            .or_default()
            .insert((o.kind, o.target), o.decision);
    }
    out
}

/// Links that come from clustering and matching rather than from one
/// attempt's own events.
#[derive(Debug, Clone, Copy, Default)]
pub struct WindowLinks<'a> {
    /// Campaigns over the same window (#33); each member gets its own link.
    pub campaigns: &'a [foiled_core::campaign::Campaign],
    /// Actor links per attempt (#29), from `actor::export_links`, so only
    /// confirmed ones.
    pub actors: Option<&'a BTreeMap<String, Vec<foiled_core::confidence::ConfidenceLink>>>,
}

/// The export input for attempts built from `events`: links scored with
/// the bundled rules and catalogue (with overrides applied) and IOC notes
/// from `extraction`. Pure, so golden tests build exactly what the routes
/// serve.
pub fn export_input(
    catalogue: &Catalogue,
    attempts: Vec<Attempt>,
    events: &[CaptureEvent],
    extraction: &Extraction,
    iocs: Vec<Ioc>,
    overrides: &OverrideIndex,
    window: WindowLinks<'_>,
) -> ExportInput {
    let (campaigns, actor_links) = (window.campaigns, window.actors);
    let cfg_links = ConfidenceConfig::default();
    // Each member's own link (#33): its joins, carried-over state and noise,
    // so a weak or carried-over member is never exported with the
    // campaign's strongest score or an analyst's confirmation of the
    // campaign as a whole.
    let member_links: HashMap<(String, String), foiled_core::confidence::ConfidenceLink> =
        campaigns
            .iter()
            .flat_map(|c| foiled_core::campaign::member_links(&cfg_links, c))
            .map(|l| ((l.attempt_id.clone(), l.target.clone()), l))
            .collect();
    let by_id: HashMap<&str, &CaptureEvent> =
        events.iter().map(|e| (e.event_id.as_str(), e)).collect();
    let cfg = ConfidenceConfig::default();
    let empty = BTreeMap::new();
    let records = attempts
        .into_iter()
        .map(|attempt| {
            let mine: Vec<CaptureEvent> = attempt
                .event_ids
                .iter()
                .filter_map(|id| by_id.get(id.as_str()).map(|e| (*e).clone()))
                .collect();
            let links = crate::links::links_for_attempt(
                &cfg,
                catalogue.get(&attempt.catalogue_id),
                &attempt,
                &mine,
                overrides.get(&attempt.attempt_id).unwrap_or(&empty),
            );
            let mut links = links;
            if let Some(c) = &attempt.campaign_id
                && let Some(l) = member_links.get(&(attempt.attempt_id.clone(), c.clone()))
            {
                links.push(l.clone());
            }
            // Actor possible-associations (#29), already reduced by
            // `actor::export_links` to confirmed (the only publishable) ones.
            if let Some(list) = actor_links.and_then(|m| m.get(&attempt.attempt_id)) {
                links.extend(list.iter().cloned());
            }
            let summary = extraction.for_attempt(&attempt.attempt_id);
            AttemptRecord {
                file_ioc_limited: summary.is_some_and(|s| s.file_ioc_limited),
                notes: summary.map(|s| s.notes.clone()).unwrap_or_default(),
                links,
                attempt,
            }
        })
        .collect();
    ExportInput {
        attempts: records,
        iocs,
        attack: Some(crate::links::attack_sidecar().clone()),
    }
}

/// A gated selection and what the window looked like.
pub struct Built {
    pub sel: Selection,
    pub truncated: bool,
    /// When truncated, where the next part starts (see `WindowModel`).
    pub cut: Option<EventCursor>,
    /// Names this export for MISP event ids: a digest of the tenant, the
    /// options and the window, so the tenant id itself never appears.
    pub scope: String,
}

/// Build the gated selection for a tenant. `format` names the output for
/// the audit record an unreviewed export writes.
pub(crate) async fn selection(
    state: &AppState,
    who: &Principal,
    q: &ExportQuery,
    format: &str,
) -> Result<Built, ApiError> {
    let cap = state.limits.max_window_events.min(EXPORT_WINDOW_EVENTS);
    selection_capped(state, who, q, format, cap).await
}

/// [`selection`] reading at most `cap` events.
pub(crate) async fn selection_capped(
    state: &AppState,
    who: &Principal,
    q: &ExportQuery,
    format: &str,
    cap: usize,
) -> Result<Built, ApiError> {
    let opts = q.options()?;
    if opts.include_unreviewed {
        // Unreviewed material is for analysts only, and never public.
        if !who.has(Scope::ReviewWrite) {
            return Err(ApiError::forbidden(Scope::ReviewWrite.as_str()));
        }
        let mut rec = crate::routes::audit_record(
            state,
            who,
            "export.unreviewed",
            Some(format),
            Outcome::Accepted,
        );
        rec.detail = serde_json::json!({
            "format": format,
            "since": q.since,
            "until": q.until,
            "min_confidence": q.min_confidence,
            "tlp": opts.effective_tlp().as_str(),
        });
        state.store.append_audit(rec).await?;
    }
    let after = match &q.cursor {
        None => None,
        Some(c) => Some(
            EventCursor::decode(c).ok_or_else(|| ApiError::bad_request("cursor is not valid"))?,
        ),
    };
    let (since, until) = window_bounds(state, q.since, q.until);
    // A cursor continues a cut export: the window starts at its event.
    let since = after.as_ref().map_or(since, |c| c.ts);
    let mut m = window_model_capped(
        state,
        &who.tenant_id,
        since,
        until,
        after.as_ref(),
        Iocs::Attach,
        // Cluster (#33) without writing the registry, so campaign links
        // carry their #27 score and wording; ids follow the registry.
        Campaigns::Full { record: false },
        cap,
    )
    .await?;
    // Actor links (#29) only when the export opts in. Pending and rejected
    // links never leave, even with `include_unreviewed`: `export_links`
    // keeps confirmed links only.
    let actor_links = match m.inputs.as_ref() {
        Some(inputs) if opts.include_actors => {
            let (links, _, _) = crate::routes::actors::match_window(
                state,
                &who.tenant_id,
                &mut m.campaigns.campaigns,
                &m.attempts,
                &m.iocs,
                inputs,
            )
            .await?;
            foiled_core::actor::export_links(&links)
        }
        _ => BTreeMap::new(),
    };
    let attempts: Vec<Attempt> = m
        .attempts
        .into_iter()
        .filter(|a| attempt_matches(a, &opts))
        .collect();
    let ids: Vec<String> = attempts.iter().map(|a| a.attempt_id.clone()).collect();
    let kept: std::collections::HashSet<&str> = ids.iter().map(String::as_str).collect();
    let overrides = if ids.is_empty() {
        OverrideIndex::new()
    } else {
        index_overrides(
            state
                .store
                .link_overrides_many(&who.tenant_id, ids.clone())
                .await?,
        )
    };
    // Moved, not copied: a full window can hold tens of thousands of IOCs.
    let mut iocs: Vec<Ioc> = std::mem::take(&mut m.iocs.iocs)
        .into_iter()
        .filter(|i| i.attempt_ids.iter().any(|a| kept.contains(a.as_str())))
        .collect();
    // Enrichment is context: if the cache cannot be read the export goes
    // out without ASN refs rather than failing.
    let _ = crate::routes::iocs::enrich(state, &who.tenant_id, &mut iocs).await;
    let input = export_input(
        &state.catalogue,
        attempts,
        &m.events,
        &m.iocs,
        iocs,
        &overrides,
        WindowLinks {
            campaigns: &m.campaigns.campaigns,
            actors: Some(&actor_links),
        },
    );
    let scope = {
        use sha2::{Digest, Sha256};
        let key = format!(
            "{}|{since}|{until}|{:?}|{:?}|{:?}|{:?}|{:?}|{:?}|{}|{}|{}|{}",
            who.tenant_id,
            q.cursor,
            opts.min_confidence,
            opts.catalogue_id,
            opts.state,
            opts.campaign_id,
            opts.decoy_kind,
            opts.include_unreviewed,
            opts.include_actors,
            opts.include_payloads,
            opts.tlp.as_str(),
        );
        hex::encode(Sha256::digest(key.as_bytes()))
    };
    Ok(Built {
        sel: select(input, &opts),
        truncated: m.truncated,
        cut: m.cut,
        scope,
    })
}

fn download(
    content_type: &str,
    filename: &str,
    truncated: bool,
    next: Option<&EventCursor>,
    body: String,
) -> Response {
    let mut res = (
        [
            (header::CONTENT_TYPE, content_type.to_string()),
            (
                header::CONTENT_DISPOSITION,
                format!("attachment; filename=\"{filename}\""),
            ),
            (header::X_CONTENT_TYPE_OPTIONS, "nosniff".to_string()),
            (
                HeaderName::from_static(TRUNCATED_HEADER),
                truncated.to_string(),
            ),
        ],
        body,
    )
        .into_response();
    // Where to continue: the last event read, in `(ts, event_id)` order.
    // Passing it back as `cursor` reads strictly after it, so nothing is
    // skipped or repeated even when many events share a millisecond.
    if let Some(c) = next.filter(|_| truncated)
        && let Ok(v) = HeaderValue::from_str(&c.encode())
    {
        res.headers_mut()
            .insert(HeaderName::from_static(NEXT_CURSOR_HEADER), v);
    }
    res
}

async fn stix_bundle(
    State(state): State<AppState>,
    auth: Auth,
    Query(q): Query<ExportQuery>,
) -> Result<Response, ApiError> {
    let who = auth.require(Scope::ExportsRead)?;
    let Built {
        sel,
        truncated,
        cut,
        ..
    } = selection(&state, who, &q, "stix").await?;
    let objects = stix::objects(&sel);
    drop(sel);
    let body = stix::bundle_text(&objects);
    drop(objects);
    Ok(download(
        stix::MEDIA_TYPE,
        "foiled-stix.json",
        truncated,
        cut.as_ref(),
        body,
    ))
}

async fn misp_event(
    State(state): State<AppState>,
    auth: Auth,
    Query(q): Query<ExportQuery>,
) -> Result<Response, ApiError> {
    let who = auth.require(Scope::ExportsRead)?;
    let Built {
        sel,
        truncated,
        cut,
        scope,
    } = selection(&state, who, &q, "misp").await?;
    let body = misp::event(&sel, &scope).to_string();
    Ok(download(
        "application/json",
        "foiled-misp.json",
        truncated,
        cut.as_ref(),
        body,
    ))
}

async fn iocs_json(
    State(state): State<AppState>,
    auth: Auth,
    Query(q): Query<ExportQuery>,
) -> Result<Response, ApiError> {
    let who = auth.require(Scope::ExportsRead)?;
    let Built {
        sel,
        truncated,
        cut,
        ..
    } = selection(&state, who, &q, "iocs.json").await?;
    let mut v = table::json(&sel);
    v["truncated"] = serde_json::Value::Bool(truncated);
    if truncated && let Some(c) = &cut {
        v["next_cursor"] = serde_json::json!(c.encode());
    }
    let body = serde_json::to_string_pretty(&v).unwrap_or_default();
    Ok(download(
        "application/json",
        "foiled-iocs.json",
        truncated,
        cut.as_ref(),
        body,
    ))
}

/// Shareable ASN context for an address, already through
/// `ioc::export_refs`.
pub type ExportContext = BTreeMap<String, Vec<EnrichmentRef>>;

fn ref_text(refs: &[EnrichmentRef], key: &str) -> String {
    refs.iter()
        .find(|r| r.key == key)
        .map(|r| match &r.value {
            serde_json::Value::String(s) => s.clone(),
            v => v.to_string(),
        })
        .unwrap_or_default()
}

/// The #22 source-address CSV.
pub fn render_csv(rows: &[IpIocRow], context: &ExportContext) -> String {
    let mut out = String::from(
        "indicator_type,indicator,first_seen,last_seen,event_count,decoy_ids,catalogue_ids,hook_cves,asn,as_org,country\n",
    );
    for r in rows {
        let refs = context.get(&r.ip).map(Vec::as_slice).unwrap_or(&[]);
        let ty = if r.ip.contains(':') { "ipv6" } else { "ipv4" };
        let fields = [
            ty.to_string(),
            r.ip.clone(),
            iso(r.first_seen),
            iso(r.last_seen),
            r.events.to_string(),
            r.decoy_ids.join(";"),
            r.catalogue_ids.join(";"),
            r.hook_cves.join(";"),
            ref_text(refs, "asn.number"),
            ref_text(refs, "asn.org"),
            ref_text(refs, "geo.country"),
        ];
        let line: Vec<String> = fields.iter().map(|f| table::cell(f)).collect();
        out.push_str(&line.join(","));
        out.push('\n');
    }
    out
}

async fn iocs_csv(
    State(state): State<AppState>,
    auth: Auth,
    Query(c): Query<CsvQuery>,
    Query(q): Query<ExportQuery>,
) -> Result<Response, ApiError> {
    let who = auth.require(Scope::ExportsRead)?;
    match c.fields.as_deref() {
        None | Some("source") => {}
        Some("ioc") => {
            let Built {
                sel,
                truncated,
                cut,
                ..
            } = selection(&state, who, &q, "iocs.csv").await?;
            return Ok(download(
                "text/csv; charset=utf-8",
                "iocs.csv",
                truncated,
                cut.as_ref(),
                table::csv(&sel),
            ));
        }
        Some(_) => return Err(ApiError::bad_request("fields must be source or ioc")),
    }
    let since = c
        .since
        .unwrap_or_else(|| (state.clock)() - 30 * 24 * 3600 * 1000);
    let rows = state.store.ip_iocs(&who.tenant_id, since).await?;
    // Newest first, so a tight lookup budget leaves the oldest without
    // context.
    let mut by_recency: Vec<&IpIocRow> = rows.iter().collect();
    by_recency.sort_by_key(|a| std::cmp::Reverse(a.last_seen));
    let observables: Vec<Observable> = by_recency
        .iter()
        .filter_map(|r| Observable::ip(&r.ip).ok())
        .collect();
    let cached = crate::enrichment::cached_facts(&state, &who.tenant_id, observables).await;
    let headers = cached.headers();
    let context: ExportContext = cached
        .facts
        .into_iter()
        .map(|(o, f)| (o.value, export_refs(&context_refs(&f))))
        .filter(|(_, refs)| !refs.is_empty())
        .collect();
    // A cache failure leaves the ASN columns empty and says so in a header;
    // the export itself still succeeds.
    Ok((
        headers,
        [
            (header::CONTENT_TYPE, "text/csv; charset=utf-8"),
            (
                header::CONTENT_DISPOSITION,
                "attachment; filename=\"iocs.csv\"",
            ),
        ],
        render_csv(&rows, &context),
    )
        .into_response())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tlp_labels_survive_query_strings() {
        assert_eq!(parse_tlp("amber strict"), Some(Tlp::AmberStrict));
        assert_eq!(parse_tlp("AMBER+STRICT"), Some(Tlp::AmberStrict));
        assert_eq!(parse_tlp("amber_strict"), Some(Tlp::AmberStrict));
        assert_eq!(parse_tlp("clear"), Some(Tlp::Clear));
        assert_eq!(parse_tlp("white"), None);
    }

    #[test]
    fn renders_iso_times_and_lists() {
        let context = ExportContext::from([(
            "203.0.113.7".to_string(),
            vec![EnrichmentRef {
                provider: "team_asn".into(),
                key: "asn.number".into(),
                value: serde_json::json!(64498),
                observed_at: 0,
                shareable: true,
            }],
        )]);
        let csv = render_csv(
            &[IpIocRow {
                ip: "203.0.113.7".into(),
                first_seen: 1_792_285_323_000,
                last_seen: 1_792_285_383_000,
                events: 3,
                decoy_ids: vec!["d1".into(), "d2".into()],
                catalogue_ids: vec!["foiled/demo-app/1.0.0".into()],
                hook_cves: vec!["FOILED-DEMO-0001".into()],
            }],
            &context,
        );
        let line = csv.lines().nth(1).unwrap();
        assert_eq!(
            line,
            "ipv4,203.0.113.7,2026-10-18T01:02:03Z,2026-10-18T01:03:03Z,3,d1;d2,foiled/demo-app/1.0.0,FOILED-DEMO-0001,64498,,"
        );
    }
}
