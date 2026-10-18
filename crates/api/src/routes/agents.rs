//! Edge sensor and sandbox host registry and enrolment (#31, ADR 0007).
//!
//! Operators (bearer tokens, tenant scoped):
//! - `POST /v0/sensors`, `POST /v0/hosts`: register and get a one-time
//!   enrolment token, shown once.
//! - `GET /v0/sensors`, `GET /v0/sensors/{id}` (and the same for hosts).
//! - `POST /v0/sensors/{id}:revoke`: revoke every certificate the sensor
//!   holds, here and at the CA. Final.
//! - `POST /v0/sensors/{id}:reenrol`: a new enrolment token for a lost key.
//!   Redeeming it retires the old certificates at once.
//!
//! Agents:
//! - `POST /v0/enrol`: redeem a token with a CSR. No bearer token and no
//!   client certificate; the token is the credential, once.
//! - `POST /v0/sensors/{id}/certificate:renew` (and hosts): over mTLS, a
//!   new certificate for a new key. The old one keeps working for the grace
//!   period so a lost response is not fatal.
//!
//! The identity bound to a certificate (id, role, tenant, scopes) comes only
//! from the token record or the presenting certificate, never from the
//! request body or the CSR subject.

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::{Json, Router};
use foiled_core::audit::Outcome;
use foiled_core::auth::{Principal, Role, Scope, agent_scopes};
use foiled_core::decoy::Reason;
use foiled_core::enrolment::{
    AgentRecord, AgentStatus, DEFAULT_ENROLMENT_TTL_MS, ENROLMENT_TOKEN_PREFIX, EnrolRequest,
    EnrolResponse, MAX_ENROLMENT_TTL_MS, MIN_ENROLMENT_TTL_MS, RENEWAL_GRACE_MS, RenewRequest,
    cert_fingerprint, csr_problem, parse_enrolment_token,
};
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;

use crate::AppState;
use crate::auth::{Auth, Meta, sha256_hex};
use crate::error::{ApiError, JsonBody};
use crate::issuer::CertIssuer;
use crate::routes::hosts::{self, Family};
use crate::routes::{HOUR_MS, audit_record, check_rate, page_limit};
use crate::store::{AgentQuery, EnrolmentTokenRecord, NewCert};

/// Operator side of one family.
#[derive(Debug, Clone, Copy)]
struct Registry {
    channel: Family,
    read: Scope,
    write: Scope,
    /// Default for `sandbox_allowed`: research hosts run sandboxes, edge
    /// sensors run emulations unless the tenant admin says otherwise.
    sandbox_default: bool,
}

const SENSORS: Registry = Registry {
    channel: hosts::SENSORS,
    read: Scope::SensorsRead,
    write: Scope::SensorsWrite,
    sandbox_default: false,
};

const HOSTS: Registry = Registry {
    channel: hosts::HOSTS,
    read: Scope::HostsRead,
    write: Scope::HostsWrite,
    sandbox_default: true,
};

pub fn router() -> Router<AppState> {
    let mut r = Router::new().route("/v0/enrol", post(enrol));
    for (prefix, param, reg) in [
        ("sensors", "sensor_id", SENSORS),
        ("hosts", "host_id", HOSTS),
    ] {
        r = r
            .route(
                &format!("/v0/{prefix}"),
                post(move |s, a, b| create(reg, s, a, b)).get(move |s, a, q| list(reg, s, a, q)),
            )
            .route(
                &format!("/v0/{prefix}/{{{param}}}"),
                get(move |s, a, p| get_one(reg, s, a, p))
                    .post(move |s, a, p, b| action(reg, s, a, p, b)),
            )
            .route(
                &format!("/v0/{prefix}/{{{param}}}/certificate:renew"),
                post(move |s, a, m, p, b| renew(reg, s, a, m, p, b)),
            );
    }
    r
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateAgent {
    pub label: Option<String>,
    pub sandbox_allowed: Option<bool>,
    pub share_opt_in: Option<bool>,
    pub enrolment_ttl_seconds: Option<i64>,
}

#[derive(Debug, Serialize)]
pub struct Enrolment {
    /// `foe_<id>.<secret>`. Shown once; only its hash is stored.
    pub token: String,
    pub expires_at: i64,
}

#[derive(Debug, Serialize)]
pub struct AgentCreated {
    pub agent: AgentRecord,
    pub enrolment: Enrolment,
}

#[derive(Debug, Serialize)]
pub struct AgentList {
    pub items: Vec<AgentRecord>,
    pub next_cursor: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct ListQuery {
    pub limit: Option<usize>,
    pub cursor: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActionBody {
    pub reason: Reason,
    pub enrolment_ttl_seconds: Option<i64>,
}

#[derive(Debug, Serialize)]
pub struct Revoked {
    pub agent: AgentRecord,
    /// Certificates revoked at the CA as well, so the WAF rule blocks them.
    pub ca_revoked: usize,
    /// Certificates the CA could not revoke. The Worker still refuses
    /// them; the operator finishes the job in the dashboard.
    pub ca_failed: usize,
}

fn ttl_ms(seconds: Option<i64>) -> Result<i64, ApiError> {
    let ms = seconds.map_or(DEFAULT_ENROLMENT_TTL_MS, |s| s.saturating_mul(1000));
    if !(MIN_ENROLMENT_TTL_MS..=MAX_ENROLMENT_TTL_MS).contains(&ms) {
        return Err(ApiError::bad_request(
            "enrolment_ttl_seconds must be between 300 and 86400",
        ));
    }
    Ok(ms)
}

/// A token for `agent`. The secret comes straight from the OS random
/// source (two v4 UUIDs, 244 random bits), never from `state.ids`.
fn new_token(
    state: &AppState,
    who: &Principal,
    agent: &AgentRecord,
    ttl_ms: i64,
) -> (EnrolmentTokenRecord, Enrolment) {
    let now = (state.clock)();
    let id = uuid::Uuid::new_v4().simple().to_string();
    let secret = format!(
        "{}{}",
        uuid::Uuid::new_v4().simple(),
        uuid::Uuid::new_v4().simple()
    );
    let rec = EnrolmentTokenRecord {
        id: id.clone(),
        tenant_id: agent.tenant_id.clone(),
        agent_id: agent.id.clone(),
        role: agent.role,
        secret_sha256: sha256_hex(&secret),
        created_at: now,
        expires_at: now + ttl_ms,
        created_by: who.id.clone(),
        used_at: None,
    };
    let shown = Enrolment {
        token: format!("{ENROLMENT_TOKEN_PREFIX}{id}.{secret}"),
        expires_at: rec.expires_at,
    };
    (rec, shown)
}

async fn create(
    reg: Registry,
    State(state): State<AppState>,
    auth: Auth,
    JsonBody(body): JsonBody<CreateAgent>,
) -> Result<(StatusCode, Json<AgentCreated>), ApiError> {
    let who = auth.require(reg.write)?.clone();
    if let Some(label) = &body.label
        && (label.trim().is_empty()
            || label.chars().count() > 100
            || label.chars().any(char::is_control))
    {
        return Err(ApiError::bad_request(
            "label must be 1 to 100 printable characters",
        ));
    }
    let ttl = ttl_ms(body.enrolment_ttl_seconds)?;
    check_rate(
        &state,
        &who,
        "agent.register",
        state.limits.enrolments_per_hour,
        HOUR_MS,
    )
    .await?;

    let now = (state.clock)();
    let agent = AgentRecord {
        id: (state.ids)(),
        tenant_id: who.tenant_id.clone(),
        role: reg.channel.role,
        label: body.label,
        status: AgentStatus::Pending,
        sandbox_allowed: body.sandbox_allowed.unwrap_or(reg.sandbox_default),
        share_opt_in: body.share_opt_in,
        created_at: now,
        created_by: who.id.clone(),
        enrolled_at: None,
        cert_sha256: None,
        cert_expires_at: None,
        last_seen_at: None,
        last_ip: None,
        last_asn: None,
        network_changed_at: None,
        revoked_at: None,
        revoke_reason: None,
    };
    let (token, shown) = new_token(&state, &who, &agent, ttl);
    state.store.create_agent(agent.clone(), token).await?;

    let action = format!("{}.create", reg.channel.noun);
    let mut rec = audit_record(&state, &who, &action, Some(&agent.id), Outcome::Accepted);
    // The token itself is never written to the audit log.
    rec.detail = serde_json::json!({
        "label": agent.label,
        "sandbox_allowed": agent.sandbox_allowed,
        "share_opt_in": agent.share_opt_in,
        "enrolment_expires_at": shown.expires_at,
    });
    state.store.append_audit(rec).await?;
    Ok((
        StatusCode::CREATED,
        Json(AgentCreated {
            agent,
            enrolment: shown,
        }),
    ))
}

async fn list(
    reg: Registry,
    State(state): State<AppState>,
    auth: Auth,
    Query(q): Query<ListQuery>,
) -> Result<Json<AgentList>, ApiError> {
    let who = auth.require(reg.read)?;
    let limit = page_limit(q.limit);
    let items = state
        .store
        .list_agents(
            &who.tenant_id,
            reg.channel.role,
            AgentQuery {
                limit,
                cursor: q.cursor,
            },
        )
        .await?;
    let next_cursor = (items.len() == limit)
        .then(|| items.last().map(|a| a.id.clone()))
        .flatten();
    Ok(Json(AgentList { items, next_cursor }))
}

async fn get_one(
    reg: Registry,
    State(state): State<AppState>,
    auth: Auth,
    Path(id): Path<String>,
) -> Result<Json<AgentRecord>, ApiError> {
    let who = auth.require(reg.read)?;
    if id.contains(':') {
        return Err(ApiError::new(
            StatusCode::METHOD_NOT_ALLOWED,
            "method_not_allowed",
            "actions use POST",
        ));
    }
    state
        .store
        .get_agent(&who.tenant_id, reg.channel.role, &id)
        .await?
        .map(Json)
        .ok_or_else(|| ApiError::not_found(reg.channel.noun))
}

async fn action(
    reg: Registry,
    State(state): State<AppState>,
    auth: Auth,
    Path(id_action): Path<String>,
    JsonBody(body): JsonBody<ActionBody>,
) -> Result<axum::response::Response, ApiError> {
    use axum::response::IntoResponse;
    let who = auth.require(reg.write)?.clone();
    let (id, action) = id_action
        .split_once(':')
        .ok_or_else(|| ApiError::not_found("action"))?;
    if !matches!(action, "revoke" | "reenrol") {
        return Err(ApiError::not_found("action"));
    }
    body.reason.validate().map_err(ApiError::bad_request)?;
    let agent = state
        .store
        .get_agent(&who.tenant_id, reg.channel.role, id)
        .await?
        .ok_or_else(|| ApiError::not_found(reg.channel.noun))?;
    let audit_action = format!("{}.{action}", reg.channel.noun);
    let mut rec = audit_record(&state, &who, &audit_action, Some(id), Outcome::Accepted);
    rec.reason_code = serde_json::to_value(body.reason.code)
        .ok()
        .and_then(|v| v.as_str().map(str::to_string));
    rec.reason_text = Some(body.reason.text.clone());

    if agent.status == AgentStatus::Revoked {
        rec.outcome = Outcome::Denied;
        rec.detail = serde_json::json!({"status": "revoked"});
        state.store.append_audit(rec).await?;
        return Err(ApiError::conflict(format!(
            "{} is already revoked; register a new one",
            reg.channel.noun
        )));
    }

    if action == "reenrol" {
        let ttl = ttl_ms(body.enrolment_ttl_seconds)?;
        check_rate(
            &state,
            &who,
            "agent.register",
            state.limits.enrolments_per_hour,
            HOUR_MS,
        )
        .await?;
        let (token, shown) = new_token(&state, &who, &agent, ttl);
        state
            .store
            .replace_enrolment_token(token, (state.clock)())
            .await?;
        rec.detail = serde_json::json!({"enrolment_expires_at": shown.expires_at});
        state.store.append_audit(rec).await?;
        return Ok((
            StatusCode::CREATED,
            Json(AgentCreated {
                agent,
                enrolment: shown,
            }),
        )
            .into_response());
    }

    // Revoke here first: from this point the Worker refuses every one of
    // the agent's certificates, whatever happens at the CA.
    let now = (state.clock)();
    let certs = state
        .store
        .revoke_agent(&who.tenant_id, reg.channel.role, id, body.reason, now)
        .await?
        .ok_or_else(|| ApiError::not_found(reg.channel.noun))?;
    let (mut ca_revoked, mut ca_failed) = (0, 0);
    let mut errors = Vec::new();
    // Certificates issued outside `/v0/enrol` (hosts registered before
    // migration 0003) have no CA reference: list them for the dashboard.
    let mut manual = Vec::new();
    for (fp, r) in &certs {
        match (&state.cert_issuer, r) {
            (Some(issuer), Some(r)) => match issuer.revoke(r).await {
                Ok(()) => ca_revoked += 1,
                Err(e) => {
                    ca_failed += 1;
                    errors.push(e.to_string());
                    manual.push(fp.clone());
                }
            },
            _ => {
                ca_failed += 1;
                manual.push(fp.clone());
            }
        }
    }
    rec.detail = serde_json::json!({
        "certificates": certs.len(),
        "ca_revoked": ca_revoked,
        "ca_failed": ca_failed,
        "ca_errors": errors,
        "revoke_in_dashboard": manual,
    });
    state.store.append_audit(rec).await?;
    let agent = state
        .store
        .get_agent(&who.tenant_id, reg.channel.role, id)
        .await?
        .ok_or_else(|| ApiError::not_found(reg.channel.noun))?;
    Ok(Json(Revoked {
        agent,
        ca_revoked,
        ca_failed,
    })
    .into_response())
}

fn issuer(state: &AppState) -> Result<std::sync::Arc<dyn CertIssuer>, ApiError> {
    state.cert_issuer.clone().ok_or_else(|| {
        ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "enrolment_disabled",
            "certificate issuance is not configured",
        )
    })
}

/// Sign the CSR and bind the certificate. Shared by enrolment and renewal.
/// A token claimed by this request, released again if the CA fails.
struct Claim<'a> {
    token_id: &'a str,
    claimed_at: i64,
}

async fn issue_and_bind(
    state: &AppState,
    issuer: &dyn CertIssuer,
    who: &Principal,
    csr_pem: &str,
    retire_at: i64,
    claim: Option<Claim<'_>>,
) -> Result<EnrolResponse, ApiError> {
    let now = (state.clock)();
    let issued = match issuer.issue(csr_pem, state.limits.cert_validity_days).await {
        Ok(i) => i,
        Err(_) => {
            // Nothing was issued, so the token was not really used: reopen
            // it for a retry rather than make the admin re-enrol.
            if let Some(c) = claim {
                state
                    .store
                    .release_enrolment_token(c.token_id, c.claimed_at)
                    .await?;
            }
            return Err(ApiError::new(
                StatusCode::BAD_GATEWAY,
                "issuer_failed",
                "the certificate authority did not issue a certificate; retry later",
            ));
        }
    };
    // Fingerprint the DER ourselves: it is what `certFingerprintSHA256`
    // will be when the certificate is presented.
    let fp = cert_fingerprint(&issued.certificate_pem).ok_or_else(|| {
        ApiError::new(
            StatusCode::BAD_GATEWAY,
            "issuer_failed",
            "the certificate authority returned no certificate",
        )
    })?;
    let expires_at = now + i64::from(state.limits.cert_validity_days) * 86_400_000;
    let bound = state
        .store
        .bind_certificate(
            &who.tenant_id,
            who.role,
            &who.id,
            NewCert {
                cert_sha256: fp.clone(),
                issuer_ref: issued.issuer_ref.clone(),
                issued_at: now,
                expires_at,
            },
            retire_at,
            now,
        )
        .await?;
    if !bound {
        // Revoked while we were issuing: take the new certificate back too.
        if let Some(r) = &issued.issuer_ref {
            let _ = issuer.revoke(r).await;
        }
        return Err(ApiError::unauthorised());
    }
    Ok(EnrolResponse {
        agent_id: who.id.clone(),
        tenant_id: who.tenant_id.clone(),
        role: who.role,
        scopes: agent_scopes(who.role),
        certificate_pem: issued.certificate_pem,
        cert_sha256: fp,
        issued_at: now,
        expires_at,
    })
}

async fn enrol(
    State(state): State<AppState>,
    Meta(meta): Meta,
    JsonBody(req): JsonBody<EnrolRequest>,
) -> Result<(StatusCode, Json<EnrolResponse>), ApiError> {
    let issuer = issuer(&state)?;
    let now = (state.clock)();
    // Per source IP, before any lookup, so token guessing is slow.
    let window = now / HOUR_MS * HOUR_MS;
    let ip_key = format!("enrol:ip:{}", meta.ip.as_deref().unwrap_or("unknown"));
    if !state
        .store
        .rate_limit(&ip_key, window, state.limits.enrol_attempts_per_hour)
        .await?
    {
        return Err(ApiError::rate_limited());
    }
    let (token_id, secret) =
        parse_enrolment_token(&req.token).ok_or_else(ApiError::unauthorised)?;
    let rec = state
        .store
        .enrolment_token(token_id)
        .await?
        .ok_or_else(ApiError::unauthorised)?;
    let who = Principal::new(
        rec.agent_id.clone(),
        rec.role,
        rec.tenant_id.clone(),
        agent_scopes(rec.role),
    );
    let noun = if rec.role == Role::Sensor {
        "sensor"
    } else {
        "host"
    };
    let action = format!("{noun}.enrol");
    let matches: bool = sha256_hex(secret)
        .as_bytes()
        .ct_eq(rec.secret_sha256.as_bytes())
        .into();
    let refusal = if !matches {
        Some("token secret does not match")
    } else if rec.used_at.is_some() {
        Some("token already used")
    } else if rec.expires_at <= now {
        Some("token expired")
    } else {
        None
    };
    if let Some(why) = refusal {
        // A reused or guessed token is worth an audit entry (tabletop step 5).
        let mut a = audit_record(&state, &who, &action, Some(&rec.agent_id), Outcome::Denied);
        a.detail = serde_json::json!({"why": why, "ip": meta.ip, "asn": meta.asn});
        state.store.append_audit(a).await?;
        return Err(ApiError::unauthorised());
    }
    if let Some(p) = csr_problem(&req.csr_pem) {
        return Err(ApiError::bad_request(p.to_string()));
    }
    // Single use: only the request that flips `used_at` goes on.
    if !state.store.consume_enrolment_token(token_id, now).await? {
        return Err(ApiError::unauthorised());
    }
    // A re-enrolment means the old key is lost or suspect: retire old
    // certificates now rather than after a grace period.
    let res = issue_and_bind(
        &state,
        issuer.as_ref(),
        &who,
        &req.csr_pem,
        now,
        Some(Claim {
            token_id,
            claimed_at: now,
        }),
    )
    .await?;
    let mut a = audit_record(&state, &who, &action, Some(&who.id), Outcome::Accepted);
    a.detail = serde_json::json!({
        "cert_sha256": res.cert_sha256,
        "expires_at": res.expires_at,
        "ip": meta.ip,
        "asn": meta.asn,
    });
    state.store.append_audit(a).await?;
    Ok((StatusCode::CREATED, Json(res)))
}

async fn renew(
    reg: Registry,
    State(state): State<AppState>,
    auth: Auth,
    Meta(meta): Meta,
    Path(id): Path<String>,
    JsonBody(req): JsonBody<RenewRequest>,
) -> Result<(StatusCode, Json<EnrolResponse>), ApiError> {
    let f = reg.channel;
    let who = hosts::as_self(&auth, f, f.report, &id)?.clone();
    hosts::note_seen(&state, &who, &meta, false).await?;
    let issuer = issuer(&state)?;
    let agent = state
        .store
        .get_agent(&who.tenant_id, who.role, &who.id)
        .await?
        .ok_or_else(|| ApiError::conflict("this identity was not enrolled through /v0/enrol"))?;
    if agent.status != AgentStatus::Active {
        return Err(ApiError::unauthorised());
    }
    if let Some(p) = csr_problem(&req.csr_pem) {
        return Err(ApiError::bad_request(p.to_string()));
    }
    check_rate(
        &state,
        &who,
        "agent.renew",
        state.limits.renewals_per_day,
        24 * HOUR_MS,
    )
    .await?;
    let now = (state.clock)();
    let res = issue_and_bind(
        &state,
        issuer.as_ref(),
        &who,
        &req.csr_pem,
        now + RENEWAL_GRACE_MS,
        None,
    )
    .await?;
    let action = format!("{}.renew", f.noun);
    let mut a = audit_record(&state, &who, &action, Some(&who.id), Outcome::Accepted);
    a.detail = serde_json::json!({
        "cert_sha256": res.cert_sha256,
        "previous_cert_sha256": agent.cert_sha256,
        "expires_at": res.expires_at,
        "ip": meta.ip,
        "asn": meta.asn,
    });
    state.store.append_audit(a).await?;
    Ok((StatusCode::CREATED, Json(res)))
}
