//! Out-of-band human approval for destructive MCP tools (#95), through the
//! MCP endpoint and the REST router it replays against:
//!
//! - without approval an agent's reset or destroy does not run, and expires;
//! - approval by a human runs it exactly once, audited with both the
//!   requesting agent token and the approving human;
//! - rejection; double and racing approvals; approvals after expiry;
//! - agents can never approve, and cannot skip approval through REST;
//! - the per-token auto-approve flag, which only a human admin can set;
//! - REST for human tokens is unchanged.

use std::sync::Arc;
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};

use axum::body::Body;
use foiled_api::auth::sha256_hex;
use foiled_api::mcp::tools::AUDIT_ACTION;
use foiled_api::memory::MemoryStore;
use foiled_api::routes::pending::{AUDIT_APPROVE, AUDIT_AUTO_APPROVE, AUDIT_REJECT};
use foiled_api::store::{Store, TokenRecord};
use foiled_api::{AppState, router};
use foiled_core::auth::{MCP_SCOPES, Role, Scope};
use foiled_core::decoy::DecoyState;
use foiled_core::pending_action::{MAX_OPEN_PER_TOKEN, PENDING_ACTION_TTL_MS};
use http::{Request, StatusCode};
use http_body_util::BodyExt;
use serde_json::{Value, json};
use tower::ServiceExt;

const SECRET: &str = "0123456789abcdef0123456789abcdef";
const NOW: i64 = 1_792_288_923_000;
const LEGACY: &str = "2025-11-25";

fn token(id: &str, tenant: &str, role: Role, scopes: &[Scope]) -> TokenRecord {
    TokenRecord {
        id: id.into(),
        tenant_id: tenant.into(),
        role,
        scopes: scopes.to_vec(),
        secret_sha256: sha256_hex(SECRET),
        expires_at: None,
        revoked: false,
        auto_approve: false,
    }
}

struct H {
    state: AppState,
    store: Arc<MemoryStore>,
    clock: Arc<AtomicI64>,
}

fn harness() -> H {
    let store = Arc::new(MemoryStore::new());
    store.add_token(token("agent", "t1", Role::Mcp, MCP_SCOPES));
    store.add_token(token("agentro", "t1", Role::Mcp, &[Scope::DecoysRead]));
    store.add_token(token("agentt2", "t2", Role::Mcp, MCP_SCOPES));
    store.add_token(token("operator", "t1", Role::Human, &[Scope::Admin]));
    store.add_token(token(
        "analyst",
        "t1",
        Role::Human,
        &[Scope::DecoysRead, Scope::DecoysWrite],
    ));
    store.add_token(token("reader", "t1", Role::Human, &[Scope::DecoysRead]));
    store.add_token(token("opt2", "t2", Role::Human, &[Scope::Admin]));
    let counter = Arc::new(AtomicU64::new(0));
    let clock = Arc::new(AtomicI64::new(NOW));
    let mut state = AppState::new(store.clone(), {
        let c = clock.clone();
        Arc::new(move || c.load(Ordering::SeqCst))
    });
    state.ids = Arc::new(move || format!("id{:04}", counter.fetch_add(1, Ordering::SeqCst)));
    H {
        state,
        store,
        clock,
    }
}

async fn send(state: &AppState, req: Request<Body>) -> (StatusCode, Value) {
    let res = router(state.clone()).oneshot(req).await.unwrap();
    let status = res.status();
    let bytes = res.into_body().collect().await.unwrap().to_bytes();
    let body = if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes).unwrap()
    };
    (status, body)
}

async fn rest(
    state: &AppState,
    tok: &str,
    method: &str,
    path: &str,
    body: Value,
) -> (StatusCode, Value) {
    let mut b = Request::builder()
        .method(method)
        .uri(path)
        .header("authorization", format!("Bearer fo_{tok}.{SECRET}"));
    let body = if body.is_null() {
        Body::empty()
    } else {
        b = b.header("content-type", "application/json");
        Body::from(body.to_string())
    };
    send(state, b.body(body).unwrap()).await
}

/// Call a tool through `POST /v0/mcp`; returns the `tools/call` result.
async fn tool(state: &AppState, tok: &str, name: &str, args: Value) -> Value {
    let body = json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
        "params": {"name": name, "arguments": args}});
    let req = Request::post("/v0/mcp")
        .header("authorization", format!("Bearer fo_{tok}.{SECRET}"))
        .header("content-type", "application/json")
        .header("accept", "application/json, text/event-stream")
        .header("mcp-protocol-version", LEGACY)
        .body(Body::from(body.to_string()))
        .unwrap();
    let (st, v) = send(state, req).await;
    assert_eq!(st, StatusCode::OK, "{v}");
    v["result"].clone()
}

/// Golden pending action records in `testdata/pending-actions/`, which
/// `foiled-lint` validates against `schemas/pending-action.schema.json`.
/// Regenerate with FOILED_BLESS=1 and review the diff.
fn golden(name: &str, got: &Value) {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../testdata/pending-actions")
        .join(name);
    if std::env::var("FOILED_BLESS").is_ok() {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, serde_json::to_string_pretty(got).unwrap() + "\n").unwrap();
    }
    let want: Value = serde_json::from_str(
        &std::fs::read_to_string(&path).unwrap_or_else(|_| panic!("missing {}", path.display())),
    )
    .unwrap();
    assert_eq!(
        got,
        &want,
        "{} differs; run with FOILED_BLESS=1",
        path.display()
    );
}

fn data(r: &Value) -> &Value {
    assert_eq!(r["isError"], false, "{r}");
    &r["structuredContent"]["data"]
}

fn error_code(r: &Value) -> &str {
    assert_eq!(r["isError"], true, "{r}");
    r["structuredContent"]["error"]["code"].as_str().unwrap()
}

/// A sandbox created by the operator, moved to `healthy` as a host would.
async fn sandbox(h: &H) -> String {
    let (st, v) = rest(
        &h.state,
        "operator",
        "POST",
        "/v0/sandboxes",
        json!({"catalogue_id": "foiled/demo-app/1.0.0"}),
    )
    .await;
    assert_eq!(st, StatusCode::CREATED, "{v}");
    let id = v["decoy"]["id"].as_str().unwrap().to_string();
    h.store.set_state(&id, DecoyState::Healthy);
    id
}

fn destroy_args(id: &str) -> Value {
    json!({"sandbox_id": id, "reason": "agent says the test is over", "confirm": true})
}

/// Host jobs queued for a sandbox, by kind.
fn jobs(h: &H, decoy: &str, kind: &str) -> usize {
    h.store
        .jobs()
        .iter()
        .filter(|j| j.decoy_id == decoy && j.kind == kind)
        .count()
}

fn audit_of(h: &H, action: &str) -> Vec<foiled_core::audit::AuditRecord> {
    h.store
        .audit()
        .into_iter()
        .filter(|a| a.action == action)
        .collect()
}

/// Ask for a destroy as the agent; returns the pending action id.
async fn ask(h: &H, tok: &str, id: &str) -> String {
    let r = tool(&h.state, tok, "destroy_sandbox", destroy_args(id)).await;
    let d = data(&r);
    assert_eq!(d["status"], "pending", "{d}");
    let pa = d["pending_action_id"].as_str().unwrap().to_string();
    assert!(pa.starts_with("pa_"));
    pa
}

#[tokio::test]
async fn without_approval_nothing_runs_and_the_action_expires() {
    let h = harness();
    let id = sandbox(&h).await;
    let r = tool(&h.state, "agent", "destroy_sandbox", destroy_args(&id)).await;
    let d = data(&r);
    assert_eq!(d["status"], "pending");
    assert!(d["note"].as_str().unwrap().contains("must approve"));
    let p = &d["pending_action"];
    assert_eq!(p["action"], "destroy");
    assert_eq!(p["sandbox_id"], id.as_str());
    assert_eq!(p["requested_by"], "agent");
    assert_eq!(p["requested_kind"], "mcp");
    assert_eq!(p["expires_at"], NOW + PENDING_ACTION_TTL_MS);
    let pa = d["pending_action_id"].as_str().unwrap().to_string();

    // Nothing was queued for a host and the sandbox is untouched.
    assert_eq!(jobs(&h, &id, "decoy.destroy"), 0);
    assert_eq!(h.store.decoy(&id).unwrap().state, DecoyState::Healthy);
    let rec = audit_of(&h, AUDIT_ACTION);
    assert_eq!(rec[0].detail["status"], "pending_approval");
    assert_eq!(rec[0].detail["approval"], "pending");
    assert_eq!(rec[0].detail["pending_action_id"], pa.as_str());
    assert!(rec[0].job_id.is_none());

    // The console lists it as pending.
    let (st, v) = rest(
        &h.state,
        "operator",
        "GET",
        "/v0/pending-actions?status=pending",
        Value::Null,
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(v["items"][0]["id"], pa.as_str());

    // Calling again with the same confirm does not run it either.
    let again = ask(&h, "agent", &id).await;
    assert_ne!(again, pa);
    assert_eq!(jobs(&h, &id, "decoy.destroy"), 0);

    // After the TTL it is expired, cannot be approved and never runs.
    h.clock.store(NOW + PENDING_ACTION_TTL_MS, Ordering::SeqCst);
    let r = tool(
        &h.state,
        "agent",
        "get_pending_action",
        json!({"pending_action_id": pa}),
    )
    .await;
    assert_eq!(data(&r)["status"], "expired");
    let (_, v) = rest(
        &h.state,
        "operator",
        "GET",
        &format!("/v0/pending-actions/{pa}"),
        Value::Null,
    )
    .await;
    golden("expired.json", &v);
    let (st, v) = rest(
        &h.state,
        "operator",
        "GET",
        "/v0/pending-actions?status=expired",
        Value::Null,
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(v["items"].as_array().unwrap().len(), 2);
    let (st, v) = rest(
        &h.state,
        "operator",
        "POST",
        &format!("/v0/pending-actions/{pa}/approve"),
        Value::Null,
    )
    .await;
    assert_eq!(st, StatusCode::CONFLICT, "{v}");
    assert!(v["error"]["message"].as_str().unwrap().contains("expired"));
    assert_eq!(jobs(&h, &id, "decoy.destroy"), 0);
    assert_eq!(h.store.decoy(&id).unwrap().state, DecoyState::Healthy);
    // The refused approval is audited.
    let refused = audit_of(&h, AUDIT_APPROVE);
    assert_eq!(refused.len(), 1);
    assert_eq!(refused[0].outcome.as_str(), "denied");
    assert_eq!(refused[0].detail["error_code"], "not_pending");
}

#[tokio::test]
async fn approval_runs_once_and_is_audited_with_both_identities() {
    let h = harness();
    let id = sandbox(&h).await;
    let pa = ask(&h, "agent", &id).await;

    let (st, v) = rest(
        &h.state,
        "analyst",
        "POST",
        &format!("/v0/pending-actions/{pa}/approve"),
        json!({"note": "I asked for this"}),
    )
    .await;
    assert_eq!(st, StatusCode::OK, "{v}");
    assert_eq!(v["status"], "executed");
    golden("executed.json", &v);
    assert_eq!(v["decided_by"], "analyst");
    assert_eq!(v["requested_by"], "agent");
    let job = v["job_id"].as_str().unwrap().to_string();
    assert_eq!(jobs(&h, &id, "decoy.destroy"), 1);

    // Approving again, or rejecting now, does nothing more.
    for (tok, path) in [
        ("analyst", format!("/v0/pending-actions/{pa}/approve")),
        ("operator", format!("/v0/pending-actions/{pa}/approve")),
        ("operator", format!("/v0/pending-actions/{pa}/reject")),
    ] {
        let (st, v) = rest(&h.state, tok, "POST", &path, json!({"note": "again"})).await;
        assert_eq!(st, StatusCode::CONFLICT, "{v}");
    }
    assert_eq!(jobs(&h, &id, "decoy.destroy"), 1);

    // The approval record: the human is the actor, the agent is recorded.
    let approvals: Vec<_> = audit_of(&h, AUDIT_APPROVE)
        .into_iter()
        .filter(|a| a.outcome.as_str() == "accepted")
        .collect();
    assert_eq!(approvals.len(), 1);
    let a = &approvals[0];
    assert_eq!(a.actor_id, "analyst");
    assert_eq!(a.actor_kind, Role::Human);
    assert_eq!(a.target.as_deref(), Some(id.as_str()));
    assert_eq!(a.job_id.as_deref(), Some(job.as_str()));
    assert_eq!(
        a.reason_text.as_deref(),
        Some("agent says the test is over")
    );
    assert_eq!(a.detail["pending_action_id"], pa.as_str());
    assert_eq!(a.detail["requested_by"], "agent");
    assert_eq!(a.detail["requested_kind"], "mcp");
    assert_eq!(a.detail["decided_by"], "analyst");
    assert_eq!(a.detail["decided_kind"], "human");
    assert_eq!(a.detail["status"], "executed");
    assert_eq!(a.detail["note"], "I asked for this");
    // The API's own decoy record is the approver's, with the same job.
    let d = audit_of(&h, "decoy.destroy");
    assert_eq!(d.len(), 1);
    assert_eq!(d[0].actor_id, "analyst");
    assert_eq!(d[0].job_id.as_deref(), Some(job.as_str()));
    // The agent's request record carries the agent's identity.
    let req = audit_of(&h, AUDIT_ACTION);
    assert_eq!(req[0].actor_id, "agent");
    assert_eq!(req[0].detail["pending_action_id"], pa.as_str());

    // The agent sees the outcome.
    let r = tool(
        &h.state,
        "agent",
        "get_pending_action",
        json!({"pending_action_id": pa}),
    )
    .await;
    assert_eq!(data(&r)["status"], "executed");
    assert_eq!(data(&r)["job_id"], job.as_str());
    assert_eq!(r["structuredContent"]["trust"], "untrusted_capture");
}

/// Approvals sent together, as spawned tasks, by two humans. The store's
/// compare-and-set lets exactly one through (the SQL is tested for the same
/// in `d1_sql::tests::pending_actions_decide_once_and_expire`).
#[tokio::test]
async fn approvals_sent_together_run_the_action_once() {
    let h = harness();
    let id = sandbox(&h).await;
    let pa = ask(&h, "agent", &id).await;
    let path = format!("/v0/pending-actions/{pa}/approve");
    let tasks: Vec<_> = (0..8)
        .map(|i| {
            let state = h.state.clone();
            let path = path.clone();
            let tok = if i % 2 == 0 { "operator" } else { "analyst" };
            tokio::spawn(async move { rest(&state, tok, "POST", &path, Value::Null).await })
        })
        .collect();
    let mut results = Vec::new();
    for t in tasks {
        results.push(t.await.unwrap());
    }
    let ok = results.iter().filter(|(s, _)| *s == StatusCode::OK).count();
    let conflict = results
        .iter()
        .filter(|(s, _)| *s == StatusCode::CONFLICT)
        .count();
    assert_eq!((ok, conflict), (1, 7), "{results:?}");
    assert_eq!(jobs(&h, &id, "decoy.destroy"), 1);
}

#[tokio::test]
async fn rejection_never_runs_and_needs_a_note() {
    let h = harness();
    let id = sandbox(&h).await;
    let pa = ask(&h, "agent", &id).await;
    let path = format!("/v0/pending-actions/{pa}/reject");
    let (st, v) = rest(&h.state, "operator", "POST", &path, Value::Null).await;
    assert_eq!(st, StatusCode::BAD_REQUEST, "{v}");
    let (st, v) = rest(&h.state, "operator", "POST", &path, json!({"note": "  "})).await;
    assert_eq!(st, StatusCode::BAD_REQUEST, "{v}");
    let (st, v) = rest(
        &h.state,
        "operator",
        "POST",
        &path,
        json!({"note": "I did not ask for this"}),
    )
    .await;
    assert_eq!(st, StatusCode::OK, "{v}");
    assert_eq!(v["status"], "rejected");
    golden("rejected.json", &v);
    assert_eq!(v["decided_by"], "operator");
    // A later approval cannot revive it.
    let (st, _) = rest(
        &h.state,
        "operator",
        "POST",
        &format!("/v0/pending-actions/{pa}/approve"),
        Value::Null,
    )
    .await;
    assert_eq!(st, StatusCode::CONFLICT);
    assert_eq!(jobs(&h, &id, "decoy.destroy"), 0);
    assert_eq!(h.store.decoy(&id).unwrap().state, DecoyState::Healthy);

    let r = audit_of(&h, AUDIT_REJECT);
    let accepted: Vec<_> = r
        .iter()
        .filter(|a| a.outcome.as_str() == "accepted")
        .collect();
    assert_eq!(accepted.len(), 1);
    assert_eq!(accepted[0].actor_id, "operator");
    assert_eq!(accepted[0].detail["requested_by"], "agent");
    assert_eq!(accepted[0].detail["note"], "I did not ask for this");
    let t = tool(
        &h.state,
        "agent",
        "get_pending_action",
        json!({"pending_action_id": pa}),
    )
    .await;
    assert_eq!(data(&t)["status"], "rejected");
}

#[tokio::test]
async fn only_humans_with_decoys_write_decide_and_tenants_are_isolated() {
    let h = harness();
    let id = sandbox(&h).await;
    let pa = ask(&h, "agent", &id).await;
    let approve = format!("/v0/pending-actions/{pa}/approve");
    // An agent can never approve, its own action or another's.
    let (st, v) = rest(&h.state, "agent", "POST", &approve, Value::Null).await;
    assert_eq!(st, StatusCode::FORBIDDEN, "{v}");
    // A human without decoys:write cannot either.
    let (st, _) = rest(&h.state, "reader", "POST", &approve, Value::Null).await;
    assert_eq!(st, StatusCode::FORBIDDEN);
    // Another tenant's admin does not even see it.
    let (st, _) = rest(&h.state, "opt2", "POST", &approve, Value::Null).await;
    assert_eq!(st, StatusCode::NOT_FOUND);
    let (st, v) = rest(&h.state, "opt2", "GET", "/v0/pending-actions", Value::Null).await;
    assert_eq!(st, StatusCode::OK);
    assert!(v["items"].as_array().unwrap().is_empty());
    let r = tool(
        &h.state,
        "agentt2",
        "get_pending_action",
        json!({"pending_action_id": pa}),
    )
    .await;
    assert_eq!(error_code(&r), "not_found");
    // A read-only agent cannot ask at all.
    let r = tool(&h.state, "agentro", "destroy_sandbox", destroy_args(&id)).await;
    assert_eq!(error_code(&r), "forbidden");
    // Nor can an agent ask about another tenant's sandbox.
    let r = tool(&h.state, "agentt2", "destroy_sandbox", destroy_args(&id)).await;
    assert_eq!(error_code(&r), "not_found");
    assert_eq!(jobs(&h, &id, "decoy.destroy"), 0);
    // Still pending, so the right human can still decide.
    let (st, _) = rest(&h.state, "operator", "POST", &approve, Value::Null).await;
    assert_eq!(st, StatusCode::OK);
}

#[tokio::test]
async fn requests_are_checked_retried_by_key_and_capped() {
    let h = harness();
    let id = sandbox(&h).await;
    // A move the sandbox cannot make is refused up front.
    h.store.set_state(&id, DecoyState::Destroyed);
    let r = tool(&h.state, "agent", "destroy_sandbox", destroy_args(&id)).await;
    assert_eq!(error_code(&r), "conflict");
    h.store.set_state(&id, DecoyState::Healthy);

    // The same idempotency key returns the same pending action.
    let mut args = destroy_args(&id);
    args["idempotency_key"] = json!("k-1");
    let first = tool(&h.state, "agent", "destroy_sandbox", args.clone()).await;
    let second = tool(&h.state, "agent", "destroy_sandbox", args.clone()).await;
    assert_eq!(
        data(&first)["pending_action_id"],
        data(&second)["pending_action_id"]
    );
    // The key cannot be reused for another action.
    let r = tool(&h.state, "agent", "reset_sandbox", args.clone()).await;
    assert_eq!(error_code(&r), "conflict");

    // Open requests per token are capped.
    for _ in 1..MAX_OPEN_PER_TOKEN {
        ask(&h, "agent", &id).await;
    }
    let r = tool(&h.state, "agent", "destroy_sandbox", destroy_args(&id)).await;
    assert_eq!(error_code(&r), "approval_queue_full");
    // Expired requests stop counting.
    h.clock.store(NOW + PENDING_ACTION_TTL_MS, Ordering::SeqCst);
    ask(&h, "agent", &id).await;
}

#[tokio::test]
async fn agents_cannot_skip_approval_through_rest() {
    let h = harness();
    let id = sandbox(&h).await;
    for action in ["destroy", "reset"] {
        let (st, v) = rest(
            &h.state,
            "agent",
            "POST",
            &format!("/v0/sandboxes/{id}:{action}"),
            json!({"reason": {"code": "operator_manual", "text": "direct"}}),
        )
        .await;
        assert_eq!(st, StatusCode::FORBIDDEN, "{v}");
        assert_eq!(v["error"]["code"], "approval_required");
    }
    assert_eq!(jobs(&h, &id, "decoy.destroy"), 0);
    assert_eq!(jobs(&h, &id, "decoy.reset"), 0);
    // Non-destructive actions are unchanged for agents.
    let (st, v) = rest(
        &h.state,
        "agent",
        "POST",
        &format!("/v0/sandboxes/{id}:stop"),
        json!({"reason": {"code": "operator_manual", "text": "pause"}}),
    )
    .await;
    assert_eq!(st, StatusCode::ACCEPTED, "{v}");
}

#[tokio::test]
async fn auto_approve_tokens_run_at_once_and_only_admins_set_the_flag() {
    let h = harness();
    let id = sandbox(&h).await;
    let path = "/v0/tokens/agent/auto-approve";
    let on = json!({"enabled": true, "note": "CI cleanup job"});
    // Only a human admin of the same tenant can set it.
    for (tok, want) in [
        ("agent", StatusCode::FORBIDDEN),
        ("analyst", StatusCode::FORBIDDEN),
        ("opt2", StatusCode::NOT_FOUND),
    ] {
        let (st, v) = rest(&h.state, tok, "PUT", path, on.clone()).await;
        assert_eq!(st, want, "{tok}: {v}");
    }
    let (st, _) = rest(
        &h.state,
        "operator",
        "PUT",
        path,
        json!({"enabled": true, "note": ""}),
    )
    .await;
    assert_eq!(st, StatusCode::BAD_REQUEST, "a note is required");
    let (st, v) = rest(
        &h.state,
        "operator",
        "PUT",
        "/v0/tokens/analyst/auto-approve",
        on.clone(),
    )
    .await;
    assert_eq!(st, StatusCode::UNPROCESSABLE_ENTITY, "{v}");
    assert!(!h.store.token("agent").await.unwrap().unwrap().auto_approve);

    let (st, v) = rest(&h.state, "operator", "PUT", path, on.clone()).await;
    assert_eq!(st, StatusCode::OK, "{v}");
    assert_eq!(v["auto_approve"], true);
    let set = audit_of(&h, AUDIT_AUTO_APPROVE);
    assert_eq!(set.len(), 1);
    assert_eq!(set[0].actor_id, "operator");
    assert_eq!(set[0].target.as_deref(), Some("agent"));
    assert_eq!(set[0].detail["auto_approve"], true);
    assert_eq!(set[0].reason_text.as_deref(), Some("CI cleanup job"));

    // Now the agent's destroy runs at once, and the audit says how.
    let r = tool(&h.state, "agent", "destroy_sandbox", destroy_args(&id)).await;
    assert_eq!(data(&r)["job_kind"], "decoy.destroy");
    assert_eq!(jobs(&h, &id, "decoy.destroy"), 1);
    let rec = audit_of(&h, AUDIT_ACTION);
    assert_eq!(rec[0].detail["approval"], "auto_approve");
    assert_eq!(rec[0].detail["status"], "ok");
    assert!(rec[0].job_id.is_some());

    // Turned off again, it waits for a human.
    let id2 = sandbox(&h).await;
    let (st, _) = rest(
        &h.state,
        "operator",
        "PUT",
        path,
        json!({"enabled": false, "note": "job retired"}),
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    ask(&h, "agent", &id2).await;
    assert_eq!(jobs(&h, &id2, "decoy.destroy"), 0);
}

#[tokio::test]
async fn human_tokens_keep_their_rest_and_mcp_behaviour() {
    let h = harness();
    // REST: a human's reset and destroy run at once, as before.
    let id = sandbox(&h).await;
    let (st, v) = rest(
        &h.state,
        "analyst",
        "POST",
        &format!("/v0/sandboxes/{id}:reset"),
        json!({"reason": {"code": "operator_manual", "text": "rebuild"}}),
    )
    .await;
    assert_eq!(st, StatusCode::ACCEPTED, "{v}");
    assert_eq!(v["job_kind"], "decoy.reset");
    let id2 = sandbox(&h).await;
    let (st, v) = rest(
        &h.state,
        "operator",
        "POST",
        &format!("/v0/sandboxes/{id2}:destroy"),
        json!({"reason": {"code": "operator_manual", "text": "done"}}),
    )
    .await;
    assert_eq!(st, StatusCode::ACCEPTED, "{v}");
    assert_eq!(v["job_kind"], "decoy.destroy");
    // MCP with an operator token: confirm (or elicitation) as before, no
    // pending action.
    let id3 = sandbox(&h).await;
    let r = tool(&h.state, "operator", "destroy_sandbox", destroy_args(&id3)).await;
    assert_eq!(data(&r)["job_kind"], "decoy.destroy");
    let rec = audit_of(&h, AUDIT_ACTION);
    assert_eq!(rec[0].detail["approval"], "confirm_argument");
    let (_, v) = rest(
        &h.state,
        "operator",
        "GET",
        "/v0/pending-actions",
        Value::Null,
    )
    .await;
    assert!(v["items"].as_array().unwrap().is_empty());
}

#[tokio::test]
async fn approval_that_the_api_refuses_is_recorded_as_failed() {
    let h = harness();
    let id = sandbox(&h).await;
    let pa = ask(&h, "agent", &id).await;
    // The sandbox went away before the human approved.
    h.store.set_state(&id, DecoyState::Destroyed);
    let (st, v) = rest(
        &h.state,
        "operator",
        "POST",
        &format!("/v0/pending-actions/{pa}/approve"),
        Value::Null,
    )
    .await;
    assert_eq!(st, StatusCode::OK, "{v}");
    assert_eq!(v["status"], "failed");
    assert_eq!(v["error_code"], "conflict");
    assert_eq!(jobs(&h, &id, "decoy.destroy"), 0);
    let a = audit_of(&h, AUDIT_APPROVE);
    assert_eq!(a[0].outcome.as_str(), "denied");
    assert_eq!(a[0].detail["status"], "failed");
    // A failed action is not retried by approving again.
    let (st, _) = rest(
        &h.state,
        "operator",
        "POST",
        &format!("/v0/pending-actions/{pa}/approve"),
        Value::Null,
    )
    .await;
    assert_eq!(st, StatusCode::CONFLICT);
}
