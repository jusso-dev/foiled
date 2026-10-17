//! Foiled sandbox host agent (#41, ADR 0008).
//!
//! Runs on each sandbox host as an unprivileged user. It only ever dials out:
//! it leases signed jobs from the control plane over mTLS, checks each one
//! ([`gate::JobGate`]), maps it onto the decoy [`runtime::Runtime`]
//! ([`executor`]), and reports the result. Evidence goes up as capture
//! envelopes, buffered locally ([`buffer::OfflineBuffer`]) while the control
//! plane is unreachable. There is no inbound management port and no shell.

pub mod agent;
pub mod buffer;
pub mod client;
pub mod config;
pub mod executor;
pub mod gate;
pub mod runtime;
