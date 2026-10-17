//! Local mock of the control plane for the console (#14) and MCP (#24)
//! contract tests. Serves the real router over the in-memory store on
//! 127.0.0.1 only, with one admin token printed at start.
//!
//! ```sh
//! cargo run -p foiled-mock-api -- 127.0.0.1:8787
//! ```

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use foiled_api::auth::sha256_hex;
use foiled_api::memory::MemoryStore;
use foiled_api::store::TokenRecord;
use foiled_api::{AppState, router};
use foiled_core::auth::{Role, Scope};

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

#[tokio::main]
async fn main() {
    let addr = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "127.0.0.1:8787".to_string());
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
    let state = AppState::new(store, Arc::new(now_ms));
    let listener = tokio::net::TcpListener::bind(socket).await.expect("bind");
    println!("foiled mock API on http://{socket}");
    println!("token: fo_dev.{secret}");
    axum::serve(listener, router(state))
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await
        .expect("serve");
}
