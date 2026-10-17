//! Shared Foiled types and pure logic.
//!
//! Everything here must build for `wasm32-unknown-unknown` because the API
//! Worker (`crates/api`) depends on it. No Tokio, threads, sockets or file
//! system access (ADR 0009).

pub mod agent;
pub mod attack;
pub mod attempt;
pub mod audit;
pub mod auth;
pub mod capture;
pub mod catalogue;
pub mod confidence;
pub mod cvemap;
pub mod decoy;
pub mod enrichment;
pub mod honeyscore;
pub mod hooks;
pub mod retention;
pub mod share;
pub mod sigv4;
