//! Local mock of the control plane for console (#14) and MCP (#24) contract
//! tests and the MVP lab walkthrough (#22). Serves the real router over the
//! in-memory store on loopback only, with one admin token printed at start.
//!
//! ```sh
//! cargo run -p foiled-mock-api -- 127.0.0.1:8787
//! # also prints an mcp-role token for MCP clients (POST /v0/mcp)
//! # lab mode: also accept one sandbox host without mTLS, and sign its jobs
//! cargo run -p foiled-mock-api -- 127.0.0.1:8787 --lab-host lab-host-1
//! ```
//!
//! Lab mode stands in for Cloudflare's mTLS check: requests without a bearer
//! token are treated as coming from the lab host. That is only acceptable
//! because the mock refuses to listen on anything but loopback. Nothing here
//! is for production.

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::extract::Request;
use axum::middleware::{self, Next};
use foiled_api::auth::{ClientCert, sha256_hex};
use foiled_api::memory::MemoryStore;
use foiled_api::store::{IdentityRecord, TokenRecord};
use foiled_api::{AppState, router};
use foiled_core::agent::JobSigner;
use foiled_core::auth::{Role, Scope};

const LAB_CERT: &str = "1ab1ab1ab1ab1ab1ab1ab1ab1ab1ab1ab1ab1ab1ab1ab1ab1ab1ab1ab1ab1ab1";

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

fn random_hex(bytes: usize) -> String {
    (0..bytes.div_ceil(16))
        .map(|_| uuid::Uuid::new_v4().simple().to_string())
        .collect::<String>()[..bytes * 2]
        .to_string()
}

async fn lab_mtls(mut req: Request, next: Next) -> axum::response::Response {
    if !req.headers().contains_key("authorization") {
        req.extensions_mut().insert(ClientCert {
            verified: true,
            sha256: LAB_CERT.into(),
        });
    }
    next.run(req).await
}

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let addr = args
        .first()
        .filter(|a| !a.starts_with("--"))
        .cloned()
        .unwrap_or_else(|| "127.0.0.1:8787".to_string());
    let lab_host = args
        .iter()
        .position(|a| a == "--lab-host")
        .and_then(|i| args.get(i + 1))
        .cloned();
    let socket: std::net::SocketAddr = addr.parse().expect("listen address");
    assert!(
        socket.ip().is_loopback(),
        "the mock only listens on loopback"
    );

    let secret = uuid::Uuid::new_v4().simple().to_string();
    let store = Arc::new(MemoryStore::new());
    store.add_token(TokenRecord {
        id: "dev".into(),
        tenant_id: "local".into(),
        role: Role::Human,
        scopes: vec![Scope::Admin],
        secret_sha256: sha256_hex(&secret),
        expires_at: None,
        revoked: false,
    });
    // An agent token for MCP clients (#24): role mcp, least privilege.
    let mcp_secret = uuid::Uuid::new_v4().simple().to_string();
    store.add_token(TokenRecord {
        id: "devmcp".into(),
        tenant_id: "local".into(),
        role: Role::Mcp,
        scopes: vec![
            Scope::CatalogueRead,
            Scope::DecoysRead,
            Scope::DecoysWrite,
            Scope::AttemptsRead,
            Scope::AuditRead,
        ],
        secret_sha256: sha256_hex(&mcp_secret),
        expires_at: None,
        revoked: false,
    });
    let mut state = AppState::new(store.clone(), Arc::new(now_ms));
    let mut app = None;
    if let Some(host_id) = &lab_host {
        store.add_identity(IdentityRecord {
            id: host_id.clone(),
            tenant_id: "local".into(),
            role: Role::Host,
            scopes: vec![
                Scope::HostLease,
                Scope::HostReport,
                Scope::HostIngest,
                Scope::HostUpload,
            ],
            cert_sha256: LAB_CERT.into(),
            revoked: false,
        });
        let signer = JobSigner::from_seed_hex("lab", &random_hex(32)).expect("seed");
        let public = signer.public_key_hex();
        state.job_signer = Some(Arc::new(signer));
        app = Some(router(state.clone()).layer(middleware::from_fn(lab_mtls)));
        println!("lab host: {host_id} (requests without a bearer token act as this host)");
        println!(
            "hostd.toml trusted key:\n[[trusted_keys]]\nid = \"lab\"\npublic_key = \"{public}\""
        );
    }
    let app = app.unwrap_or_else(|| router(state));
    let listener = tokio::net::TcpListener::bind(socket).await.expect("bind");
    println!("foiled mock API on http://{socket}");
    println!("token: fo_dev.{secret}");
    println!("mcp token: fo_devmcp.{mcp_secret} (MCP endpoint http://{socket}/v0/mcp)");
    axum::serve(listener, app)
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await
        .expect("serve");
}
