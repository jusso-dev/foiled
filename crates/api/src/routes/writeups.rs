//! Research write-ups (#35): `GET` and `POST /v0/write-ups`,
//! `GET` and `PATCH /v0/write-ups/{id}`, `POST /v0/write-ups/{id}/transitions`
//! and `GET /v0/write-ups/{id}/versions`.
//!
//! A write-up moves draft -> review -> approved -> published (and can be
//! withdrawn). Edits happen only in draft. Submit, approve and publish run
//! the wording and privacy lint (`foiled_core::writeup::lint`); approve
//! needs a second reviewer (not the author) and the full checklist;
//! publish needs `review:publish`, a publisher tenant and TLP:CLEAR, and
//! stores an allow-listed public snapshot that the public routes serve.
//! Every change is a stored version and an audit record. Tenant scoped.

use std::collections::BTreeSet;

use axum::extract::{Path, Query, State};
use axum::routing::{get, post};
use axum::{Json, Router};
use foiled_core::audit::Outcome;
use foiled_core::auth::{Principal, Scope};
use foiled_core::confidence::{Feedback, LinkKind};
use foiled_core::review::{self, ReviewKind, ReviewStatus};
use foiled_core::share::{self, Channel, Release, Tlp};
use foiled_core::writeup::{
    self, Checklist, Finding, LintContext, PageFacts, PublicIoc, WriteUp, WriteUpStatus,
};
use serde::{Deserialize, Serialize};

use crate::AppState;
use crate::auth::Auth;
use crate::error::{ApiError, JsonBody};
use crate::routes::attempts::{Campaigns, Iocs, window_model};
use crate::routes::{HOUR_MS, audit_record, check_rate, page_limit};
use crate::store::WriteUpVersion;

/// Most write-ups one list reads.
pub const MAX_LIST: usize = 200;
const DAY_MS: i64 = 86_400_000;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/v0/write-ups", get(list).post(create))
        .route("/v0/write-ups/{writeup_id}", get(get_one).patch(edit))
        .route(
            "/v0/write-ups/{writeup_id}/transitions",
            post(transition_route),
        )
        .route("/v0/write-ups/{writeup_id}/versions", get(versions))
}

/// A write-up with its current lint findings.
#[derive(Debug, Serialize)]
pub struct WriteUpView {
    #[serde(flatten)]
    pub writeup: WriteUp,
    pub lint: Vec<Finding>,
}

#[derive(Debug, Serialize)]
pub struct WriteUpList {
    pub items: Vec<WriteUp>,
}

#[derive(Debug, Serialize)]
pub struct VersionList {
    pub writeup_id: String,
    pub items: Vec<WriteUpVersion>,
}

#[derive(Debug, Deserialize, Default)]
pub struct ListQuery {
    pub status: Option<WriteUpStatus>,
    pub limit: Option<usize>,
}

/// Fields a draft can set. Absent fields are left as they are on edit.
#[derive(Debug, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct Fields {
    pub slug: Option<String>,
    pub title: Option<String>,
    pub summary: Option<String>,
    pub body_md: Option<String>,
    pub tlp: Option<Tlp>,
    /// Unix ms; null clears it.
    #[serde(default, deserialize_with = "nullable")]
    pub embargo_until: Option<Option<i64>>,
    pub cve_ids: Option<Vec<String>>,
    pub technique_ids: Option<Vec<String>>,
    pub campaign_ids: Option<Vec<String>>,
    pub ioc_ids: Option<Vec<String>>,
    pub attempt_ids: Option<Vec<String>>,
    #[serde(default, deserialize_with = "nullable")]
    pub first_seen: Option<Option<i64>>,
    /// Redacted again on save; null clears it.
    #[serde(default, deserialize_with = "nullable")]
    pub redacted_payload: Option<Option<String>>,
    /// Edits only: the version you edited.
    pub expected_version: Option<u32>,
}

/// Tell "absent" (None) from "null" (Some(None)).
fn nullable<'de, D, T>(d: D) -> Result<Option<Option<T>>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::<T>::deserialize(d).map(Some)
}

fn ids(
    field: &str,
    v: Vec<String>,
    norm: impl Fn(&str) -> Option<String>,
) -> Result<Vec<String>, ApiError> {
    if v.len() > writeup::MAX_REFS {
        return Err(ApiError::bad_request(format!(
            "{field} takes at most {} ids",
            writeup::MAX_REFS
        )));
    }
    let mut out = Vec::new();
    for s in v {
        let n = norm(&s).ok_or_else(|| ApiError::bad_request(format!("{field}: invalid id")))?;
        if !out.contains(&n) {
            out.push(n);
        }
    }
    Ok(out)
}

fn hex_id(prefix: &'static str) -> impl Fn(&str) -> Option<String> {
    move |s: &str| {
        s.strip_prefix(prefix)
            .is_some_and(|h| {
                h.len() == 24
                    && h.bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            })
            .then(|| s.to_string())
    }
}

fn attempt_id(s: &str) -> Option<String> {
    (!s.is_empty()
        && s.len() <= 64
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-'))
    .then(|| s.to_string())
}

/// Apply and check fields. Size and format only; wording is lint's job.
fn apply(w: &mut WriteUp, f: Fields) -> Result<(), ApiError> {
    if let Some(slug) = f.slug {
        if !writeup::valid_slug(&slug) {
            return Err(ApiError::bad_request(
                "slug must be lowercase letters and digits in hyphen-separated words, at most 80 characters",
            ));
        }
        w.slug = slug;
    }
    let text = |field: &str, v: String, max: usize| -> Result<String, ApiError> {
        if v.chars().count() > max {
            return Err(ApiError::bad_request(format!(
                "{field} must be at most {max} characters"
            )));
        }
        Ok(v)
    };
    if let Some(t) = f.title {
        w.title = text("title", t, writeup::MAX_TITLE_CHARS)?;
    }
    if let Some(s) = f.summary {
        w.summary = text("summary", s, writeup::MAX_SUMMARY_CHARS)?;
    }
    if let Some(b) = f.body_md {
        if b.len() > foiled_core::markdown::MAX_BODY_BYTES {
            return Err(ApiError::bad_request(format!(
                "body_md must be at most {} bytes",
                foiled_core::markdown::MAX_BODY_BYTES
            )));
        }
        w.body_md = b;
    }
    if let Some(t) = f.tlp {
        w.tlp = t;
    }
    if let Some(e) = f.embargo_until {
        w.embargo_until = e;
    }
    if let Some(v) = f.cve_ids {
        w.cve_ids = ids("cve_ids", v, writeup::normalise_cve)?;
    }
    if let Some(v) = f.technique_ids {
        w.technique_ids = ids("technique_ids", v, writeup::normalise_technique)?;
    }
    if let Some(v) = f.campaign_ids {
        w.campaign_ids = ids("campaign_ids", v, hex_id("cmp_"))?;
    }
    if let Some(v) = f.ioc_ids {
        w.ioc_ids = ids("ioc_ids", v, hex_id("ioc_"))?;
    }
    if let Some(v) = f.attempt_ids {
        w.attempt_ids = ids("attempt_ids", v, attempt_id)?;
    }
    if let Some(s) = f.first_seen {
        w.first_seen = s;
    }
    if let Some(p) = f.redacted_payload {
        w.redacted_payload = match p {
            Some(p) => {
                let (clean, _) = foiled_core::redact::redact(&p);
                Some(text("redacted_payload", clean, writeup::MAX_PAYLOAD_CHARS)?)
            }
            None => None,
        };
    }
    Ok(())
}

/// Lint context: the owner's tenant id, and CVE and technique ids an
/// analyst confirmed on the write-up's attempts.
async fn lint_context(state: &AppState, w: &WriteUp) -> Result<(LintContext, PageFacts), ApiError> {
    let overrides = if w.attempt_ids.is_empty() {
        Vec::new()
    } else {
        state
            .store
            .link_overrides_many(&w.tenant_id, w.attempt_ids.clone())
            .await?
    };
    let mut facts = PageFacts::default();
    for o in overrides {
        if o.decision.feedback == Feedback::TruePositive
            && matches!(o.kind, LinkKind::AttemptCve | LinkKind::AttemptTechnique)
        {
            let id = o.target.to_ascii_uppercase();
            let at = facts.confirmed_at.entry(id).or_insert(o.decision.at);
            *at = (*at).min(o.decision.at);
        }
    }
    let ctx = LintContext {
        tenant_ids: vec![w.tenant_id.clone()],
        confirmed: facts.confirmed_at.keys().cloned().collect::<BTreeSet<_>>(),
    };
    Ok((ctx, facts))
}

async fn view(state: &AppState, w: WriteUp) -> Result<WriteUpView, ApiError> {
    let (ctx, _) = lint_context(state, &w).await?;
    let lint = writeup::lint(&w, &ctx);
    Ok(WriteUpView { writeup: w, lint })
}

async fn load(state: &AppState, tenant_id: &str, id: &str) -> Result<WriteUp, ApiError> {
    if !writeup::valid_writeup_id(id) {
        return Err(ApiError::not_found("write-up"));
    }
    state
        .store
        .get_writeup(tenant_id, id)
        .await?
        .ok_or_else(|| ApiError::not_found("write-up"))
}

async fn list(
    State(state): State<AppState>,
    auth: Auth,
    Query(q): Query<ListQuery>,
) -> Result<Json<WriteUpList>, ApiError> {
    let who = auth.require(Scope::ReviewRead)?;
    let items = state
        .store
        .list_writeups(&who.tenant_id, q.status, page_limit(q.limit))
        .await?;
    Ok(Json(WriteUpList { items }))
}

async fn get_one(
    State(state): State<AppState>,
    auth: Auth,
    Path(id): Path<String>,
) -> Result<Json<WriteUpView>, ApiError> {
    let who = auth.require(Scope::ReviewRead)?;
    let w = load(&state, &who.tenant_id, &id).await?;
    Ok(Json(view(&state, w).await?))
}

async fn versions(
    State(state): State<AppState>,
    auth: Auth,
    Path(id): Path<String>,
) -> Result<Json<VersionList>, ApiError> {
    let who = auth.require(Scope::ReviewRead)?;
    load(&state, &who.tenant_id, &id).await?;
    let items = state.store.writeup_versions(&who.tenant_id, &id).await?;
    Ok(Json(VersionList {
        writeup_id: id,
        items,
    }))
}

async fn create(
    State(state): State<AppState>,
    auth: Auth,
    JsonBody(f): JsonBody<Fields>,
) -> Result<Json<WriteUpView>, ApiError> {
    let who = auth.require(Scope::ReviewWrite)?.clone();
    check_rate(
        &state,
        &who,
        "review.action",
        state.limits.review_actions_per_hour,
        HOUR_MS,
    )
    .await?;
    if f.expected_version.is_some() {
        return Err(ApiError::bad_request("expected_version is for edits only"));
    }
    let now = (state.clock)();
    let id = writeup::writeup_id(&(state.ids)());
    let mut w = WriteUp {
        writeup_id: id.clone(),
        tenant_id: who.tenant_id.clone(),
        slug: String::new(),
        title: String::new(),
        summary: String::new(),
        body_md: String::new(),
        status: WriteUpStatus::Draft,
        tlp: Tlp::Clear,
        embargo_until: None,
        cve_ids: vec![],
        technique_ids: vec![],
        campaign_ids: vec![],
        ioc_ids: vec![],
        attempt_ids: vec![],
        first_seen: None,
        redacted_payload: None,
        source_item_id: None,
        author_id: who.id.clone(),
        reviewer_id: None,
        checklist: None,
        version: 1,
        created_at: now,
        updated_at: now,
        submitted_at: None,
        approved_at: None,
        published_at: None,
        withdrawn_at: None,
    };
    if f.slug.is_none() {
        return Err(ApiError::bad_request("slug is required"));
    }
    apply(&mut w, f)?;
    state.store.insert_writeup(w.clone(), &who.id).await?;
    let mut rec = audit_record(&state, &who, "writeup.create", Some(&id), Outcome::Accepted);
    rec.detail = serde_json::json!({ "slug": w.slug, "version": 1 });
    state.store.append_audit(rec).await?;
    Ok(Json(view(&state, w).await?))
}

async fn edit(
    State(state): State<AppState>,
    auth: Auth,
    Path(id): Path<String>,
    JsonBody(f): JsonBody<Fields>,
) -> Result<Json<WriteUpView>, ApiError> {
    let who = auth.require(Scope::ReviewWrite)?.clone();
    check_rate(
        &state,
        &who,
        "review.action",
        state.limits.review_actions_per_hour,
        HOUR_MS,
    )
    .await?;
    let mut w = load(&state, &who.tenant_id, &id).await?;
    let expected = f
        .expected_version
        .ok_or_else(|| ApiError::bad_request("expected_version is required"))?;
    if expected != w.version {
        return Err(ApiError::conflict(
            "the write-up changed since you read it; read it again",
        ));
    }
    if w.status != WriteUpStatus::Draft {
        return Err(ApiError::conflict(format!(
            "only drafts can be edited; this write-up is {}",
            w.status.as_str()
        )));
    }
    apply(&mut w, f)?;
    w.version = expected + 1;
    w.updated_at = (state.clock)();
    if !state
        .store
        .update_writeup(w.clone(), expected, "edit", &who.id)
        .await?
    {
        return Err(ApiError::conflict(
            "the write-up changed while you edited it; read it again",
        ));
    }
    let mut rec = audit_record(&state, &who, "writeup.edit", Some(&id), Outcome::Accepted);
    rec.detail = serde_json::json!({ "version": w.version });
    state.store.append_audit(rec).await?;
    Ok(Json(view(&state, w).await?))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TransitionBody {
    pub to: WriteUpStatus,
    /// The version you acted on; 409 if it changed.
    pub expected_version: Option<u32>,
    #[serde(default)]
    pub note: String,
    /// `approved`: the second reviewer's checklist, every item true.
    pub checklist: Option<Checklist>,
}

async fn transition_route(
    State(state): State<AppState>,
    auth: Auth,
    Path(id): Path<String>,
    JsonBody(body): JsonBody<TransitionBody>,
) -> Result<Json<WriteUpView>, ApiError> {
    let who = auth.require(Scope::ReviewWrite)?.clone();
    check_rate(
        &state,
        &who,
        "review.action",
        state.limits.review_actions_per_hour,
        HOUR_MS,
    )
    .await?;
    let w = transition(&state, &who, &id, body).await?;
    Ok(Json(view(&state, w).await?))
}

fn lint_failed(findings: &[Finding]) -> ApiError {
    let rules: BTreeSet<&str> = findings
        .iter()
        .filter(|f| f.severity == writeup::Severity::Error)
        .map(|f| f.rule.as_str())
        .collect();
    ApiError::unprocessable(
        "lint_failed",
        format!(
            "lint errors: {}. GET the write-up for details",
            rules.into_iter().collect::<Vec<_>>().join(", ")
        ),
    )
}

/// Move a write-up to another status (audited as `writeup.<status>`).
/// Shared with the review queue, which approves and rejects write-ups.
pub(crate) async fn transition(
    state: &AppState,
    who: &Principal,
    id: &str,
    body: TransitionBody,
) -> Result<WriteUp, ApiError> {
    if body.note.chars().count() > writeup::MAX_NOTE_CHARS {
        return Err(ApiError::bad_request(format!(
            "note must be at most {} characters",
            writeup::MAX_NOTE_CHARS
        )));
    }
    // Permission first, so a caller without it learns nothing about state.
    let publishing = matches!(body.to, WriteUpStatus::Published | WriteUpStatus::Withdrawn);
    if publishing {
        if !who.has(Scope::ReviewPublish) {
            return Err(ApiError::forbidden(Scope::ReviewPublish.as_str()));
        }
        if !state.publisher_tenants.contains(&who.tenant_id) {
            return Err(ApiError::new(
                http::StatusCode::FORBIDDEN,
                "forbidden",
                "this tenant does not publish public pages",
            ));
        }
    }
    let mut w = load(state, &who.tenant_id, id).await?;
    if body.expected_version.is_some_and(|v| v != w.version) {
        return Err(ApiError::conflict(
            "the write-up changed since you read it; read it again",
        ));
    }
    let from = w.status;
    let to = body.to;
    // Withdrawing a withdrawn write-up retries the page removal and purge,
    // in case an earlier withdrawal could not finish them.
    if from == WriteUpStatus::Withdrawn && to == WriteUpStatus::Withdrawn {
        let purge_failed = take_down(state, &w).await?;
        let mut rec = audit_record(state, who, "writeup.withdrawn", Some(id), Outcome::Accepted);
        rec.detail = serde_json::json!({
            "retry": true,
            "slug": w.slug,
            "cache_purge_failed": purge_failed,
        });
        state.store.append_audit(rec).await?;
        return Ok(w);
    }
    if !writeup::transition_allowed(from, to) {
        return Err(ApiError::conflict(format!(
            "a write-up cannot move from {} to {}",
            from.as_str(),
            to.as_str()
        )));
    }
    let now = (state.clock)();
    let mut page = None;
    let (ctx, mut facts) = lint_context(state, &w).await?;
    let findings = writeup::lint(&w, &ctx);
    let expected = w.version;
    match (from, to) {
        (WriteUpStatus::Draft, WriteUpStatus::Review) => {
            if writeup::has_errors(&findings) {
                return Err(lint_failed(&findings));
            }
            w.submitted_at = Some(now);
            w.reviewer_id = None;
            w.checklist = None;
        }
        (WriteUpStatus::Review, WriteUpStatus::Draft) => {
            if body.note.trim().is_empty() {
                return Err(ApiError::bad_request("sending back to draft needs a note"));
            }
            w.reviewer_id = Some(who.id.clone());
        }
        (WriteUpStatus::Review, WriteUpStatus::Approved) => {
            let versions = state
                .store
                .writeup_versions(&w.tenant_id, &w.writeup_id)
                .await?;
            if contributors(&w, &versions).contains(who.id.as_str()) {
                return Err(ApiError::unprocessable(
                    "second_reviewer",
                    "a second reviewer must approve: not the author, and not anyone who \
                     edited or submitted it since it was last approved",
                ));
            }
            let checklist = body.checklist.unwrap_or_default();
            if !checklist.complete() {
                return Err(ApiError::unprocessable(
                    "checklist_incomplete",
                    "every checklist item must be true to approve",
                ));
            }
            if writeup::has_errors(&findings) {
                return Err(lint_failed(&findings));
            }
            w.reviewer_id = Some(who.id.clone());
            w.checklist = Some(checklist);
            w.approved_at = Some(now);
        }
        (WriteUpStatus::Approved, WriteUpStatus::Draft) => {
            // Reopened for edits: the next submission is a new review.
            w.reviewer_id = None;
            w.checklist = None;
            w.approved_at = None;
            w.submitted_at = None;
        }
        (WriteUpStatus::Approved, WriteUpStatus::Published) => {
            if w.tlp != Tlp::Clear {
                return Err(ApiError::unprocessable(
                    "tlp",
                    "only TLP:CLEAR write-ups are published on public pages",
                ));
            }
            if writeup::has_errors(&findings) {
                return Err(lint_failed(&findings));
            }
            facts.advisories = crate::links::cve_rules()
                .advisories
                .iter()
                .map(|a| (a.cve_id.to_ascii_uppercase(), a.published_at))
                .collect();
            facts.iocs = released_iocs(state, &w, now).await?;
            w.published_at = Some(now);
            w.version = expected + 1;
            let built = writeup::public_page(&w, &facts, now);
            if writeup::page_leaks(&built, &ctx.tenant_ids) {
                return Err(ApiError::unprocessable(
                    "tenant_data",
                    "the public page would contain tenant data; remove it and try again",
                ));
            }
            // Stored only after this request wins the version check below.
            page = Some(built);
        }
        (WriteUpStatus::Published, WriteUpStatus::Withdrawn) => {
            // The page comes down before the status changes: if removing it
            // fails, the write-up stays published and the withdrawal can be
            // retried.
            take_down(state, &w).await?;
            w.withdrawn_at = Some(now);
        }
        _ => unreachable!("checked by transition_allowed"),
    }
    w.status = to;
    w.version = expected + 1;
    w.updated_at = now;
    let action = format!("transition.{}", to.as_str());
    // The version check comes first: a request that loses a race changes
    // nothing, and never touches the winner's public page.
    if !state
        .store
        .update_writeup(w.clone(), expected, &action, &who.id)
        .await?
    {
        return Err(ApiError::conflict(
            "the write-up changed while you acted on it; read it again",
        ));
    }
    let mut purge_failed = false;
    if let Some(page) = page {
        // Pages are written by version, so a stale write never replaces a
        // newer one. A slug held by another write-up undoes the publish.
        if !state
            .store
            .put_public_page(&w.tenant_id, &w.writeup_id, page)
            .await?
        {
            let mut back = w.clone();
            back.status = WriteUpStatus::Approved;
            back.published_at = None;
            back.version = w.version + 1;
            back.updated_at = now;
            let reverted = state
                .store
                .update_writeup(back, w.version, "revert.publish", &who.id)
                .await;
            if !matches!(reverted, Ok(true)) {
                // Published with no page: say so, audit it, and leave the
                // operator to withdraw it.
                let mut rec = audit_record(
                    state,
                    who,
                    "writeup.publish_revert_failed",
                    Some(id),
                    Outcome::Failed,
                );
                rec.detail = serde_json::json!({ "slug": w.slug, "version": w.version });
                state.store.append_audit(rec).await?;
                return Err(ApiError::new(
                    http::StatusCode::CONFLICT,
                    "publish_incomplete",
                    "another published write-up already uses this slug, and this write-up could \
                     not be put back to approved; it has no public page: withdraw it",
                ));
            }
            return Err(ApiError::conflict(
                "another published write-up already uses this slug",
            ));
        }
    }
    if to == WriteUpStatus::Published {
        purge_failed = state
            .cache_purger
            .purge(crate::sinks::page_paths(&w.slug))
            .await
            .is_err();
    }
    let mut rec = audit_record(
        state,
        who,
        &format!("writeup.{}", to.as_str()),
        Some(id),
        Outcome::Accepted,
    );
    rec.reason_text = (!body.note.is_empty()).then(|| body.note.clone());
    rec.detail = serde_json::json!({
        "from": from.as_str(),
        "to": to.as_str(),
        "version": w.version,
        "slug": w.slug,
        "cache_purge_failed": purge_failed,
    });
    state.store.append_audit(rec).await?;
    Ok(w)
}

/// Remove a write-up's public page and purge its URLs. Returns whether the
/// purge failed (the page itself is gone either way, or this errors).
async fn take_down(state: &AppState, w: &WriteUp) -> Result<bool, ApiError> {
    state
        .store
        .remove_public_page(&w.tenant_id, &w.writeup_id)
        .await?;
    Ok(state
        .cache_purger
        .purge(crate::sinks::page_paths(&w.slug))
        .await
        .is_err())
}

/// Who may not be the second reviewer: the author, and anyone who
/// created, edited or submitted the write-up since it was last approved.
fn contributors<'a>(
    w: &'a WriteUp,
    versions: &'a [crate::store::WriteUpVersion],
) -> BTreeSet<&'a str> {
    let since = versions
        .iter()
        .rposition(|v| v.action == "transition.approved")
        .map_or(0, |i| i + 1);
    let mut out: BTreeSet<&str> = versions[since..]
        .iter()
        .filter(|v| matches!(v.action.as_str(), "create" | "edit" | "transition.review"))
        .map(|v| v.actor_id.as_str())
        .collect();
    out.insert(w.author_id.as_str());
    out
}

/// IOCs on a write-up that may go on its public page: each one approved
/// in the review queue, seen on a sensor that may feed public IOCs, and
/// released by the share policy (#37). Held ones carry their release time
/// and stay hidden until then. Read from the last 31 days.
async fn released_iocs(
    state: &AppState,
    w: &WriteUp,
    now: i64,
) -> Result<Vec<PublicIoc>, ApiError> {
    // TLP:GREEN IOCs go to the account-gated dataset only, never to
    // public pages (docs/contribute-back.md).
    if w.ioc_ids.is_empty() || state.share.public_iocs.tlp != Tlp::Clear {
        return Ok(Vec::new());
    }
    let item_ids: Vec<String> = w
        .ioc_ids
        .iter()
        .map(|i| review::item_id(&w.tenant_id, ReviewKind::IocPublication, &[i]))
        .collect();
    let approved: BTreeSet<String> = state
        .store
        .review_states(&w.tenant_id, item_ids)
        .await?
        .into_iter()
        .filter(|s| s.status == ReviewStatus::Approved)
        .map(|s| s.item_id)
        .collect();
    if approved.is_empty() {
        return Ok(Vec::new());
    }
    let m = window_model(
        state,
        &w.tenant_id,
        now - 31 * DAY_MS + 1,
        now + 1,
        Iocs::Attach,
        Campaigns::Skip,
    )
    .await?;
    let sensors = crate::routes::review::sensor_share(state, &w.tenant_id, &m.attempts).await?;
    let shareable = crate::routes::review::shareable_attempts(
        &state.share,
        &sensors,
        &m.attempts,
        Channel::PublicIocs,
    );
    let policy = &state.share;
    let mut out = Vec::new();
    for ioc in &m.iocs.iocs {
        if !w.ioc_ids.contains(&ioc.ioc_id) {
            continue;
        }
        let item = review::item_id(&w.tenant_id, ReviewKind::IocPublication, &[&ioc.ioc_id]);
        if !approved.contains(&item) {
            continue;
        }
        // first_seen on sensors that may share, not on any sensor.
        let Some(first) = m
            .attempts
            .iter()
            .filter(|a| {
                shareable.contains(&a.attempt_id) && ioc.attempt_ids.contains(&a.attempt_id)
            })
            .map(|a| a.first_seen)
            .min()
        else {
            continue;
        };
        let band = serde_json::to_value(ioc.confidence.band)
            .ok()
            .and_then(|v| v.as_str().map(str::to_string))
            .unwrap_or_default();
        let release_at = match share::public_ioc_release(
            policy,
            u64::try_from(first).unwrap_or(0),
            true,
            &band,
            u64::try_from(now).unwrap_or(0),
        ) {
            Release::Release => first + i64::from(policy.public_iocs.delay_days) * DAY_MS,
            Release::Hold { until_ms } => i64::try_from(until_ms).unwrap_or(i64::MAX),
            Release::Never => continue,
        };
        out.push(PublicIoc {
            ioc_type: serde_json::to_value(ioc.ioc_type)
                .ok()
                .and_then(|v| v.as_str().map(str::to_string))
                .unwrap_or_default(),
            display: ioc.display.clone(),
            first_seen_day: foiled_core::radar::day_floor(first),
            release_at,
            tlp: policy.public_iocs.tlp,
        });
    }
    Ok(out)
}
