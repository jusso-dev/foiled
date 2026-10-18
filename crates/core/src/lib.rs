//! Shared Foiled types and pure logic.
//!
//! Everything here must build for `wasm32-unknown-unknown` because the API
//! Worker (`crates/api`) depends on it. No Tokio, threads, sockets or file
//! system access (ADR 0009).

pub mod agent;
pub mod alerting;
pub mod attack;
pub mod attempt;
pub mod audit;
pub mod auth;
pub mod canary;
pub mod capture;
pub mod catalogue;
pub mod confidence;
pub mod cvemap;
pub mod decoy;
pub mod enrichment;
pub mod enrolment;
pub mod honeyscore;
pub mod hooks;
pub mod ioc;
pub mod llm;
pub mod mcp;
pub mod redact;
pub mod release;
pub mod retention;
pub mod share;
pub mod sigv4;
pub mod timeline;
