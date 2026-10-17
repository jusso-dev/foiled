//! Shared Foiled types and pure logic.
//!
//! Everything here must build for `wasm32-unknown-unknown` because the API
//! Worker (`crates/api`) depends on it. No Tokio, threads, sockets or file
//! system access (ADR 0009).

pub mod catalogue;
