//! Foiled emulation plug-ins (#30, `docs/adr/0006-emulation-plugins.md`).
//!
//! An emulator fakes enough of a product's banners, routes and opcodes to
//! draw and record exploit attempts. It never runs attacker input: there is
//! no shell, no Lua, no module loader and no outbound connection anywhere in
//! this crate. Every byte from a client is untrusted and size-capped.
//!
//! The pieces:
//!
//! - [`Emulator`], the plug-in trait the supervisor (ADR 0002) drives.
//! - [`Profile`], the per-product YAML under `emulators/<id>/profiles/`,
//!   validated by `schemas/emulator-profile.schema.json`.
//! - [`EventSink`], which turns what an emulator sees into capture envelopes
//!   ([`foiled_core::capture::CaptureEvent`], #9).
//! - Two emulators: [`redis::RedisEmulator`] and
//!   [`http_portal::HttpPortalEmulator`].
//! - [`manifest::ModuleManifest`], the manifest for reused open source
//!   honeypots that run as their own containers (Cowrie and others).

use std::future::Future;
use std::pin::Pin;

use tokio::net::TcpListener;

pub mod http_portal;
pub mod jitter;
pub mod manifest;
pub mod profile;
pub mod redis;
mod server;
pub mod sink;
mod util;

pub use jitter::Jitter;
pub use profile::{Profile, ProfileError};
pub use sink::{Event, EventSink, SinkContext};
pub use util::Rng;

/// A boxed future, so [`Emulator`] stays object safe.
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// What the supervisor sees when it asks a plug-in how it is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Health {
    /// `start` has not been called.
    NotStarted,
    /// Accepting connections; `sessions` are open right now.
    Serving { sessions: usize },
    /// `stop` finished; the listener is closed and every session has ended.
    Stopped,
    /// The serving task ended without `stop`. The supervisor rotates the
    /// decoy (`health_failed`), it never restarts it in place (ADR 0002).
    Failed(String),
}

#[derive(Debug)]
pub enum EmulatorError {
    /// The profile names another plug-in.
    WrongPlugin {
        expected: &'static str,
        got: String,
    },
    /// The profile is invalid, or still has canary placeholders.
    Profile(ProfileError),
    AlreadyStarted,
    /// `start` was called outside a Tokio runtime.
    NoRuntime,
}

impl std::fmt::Display for EmulatorError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EmulatorError::WrongPlugin { expected, got } => {
                write!(f, "profile is for plug-in '{got}', not '{expected}'")
            }
            EmulatorError::Profile(e) => write!(f, "{e}"),
            EmulatorError::AlreadyStarted => write!(f, "emulator is already started"),
            EmulatorError::NoRuntime => write!(f, "start must be called inside a Tokio runtime"),
        }
    }
}

impl std::error::Error for EmulatorError {}

impl From<ProfileError> for EmulatorError {
    fn from(e: ProfileError) -> Self {
        EmulatorError::Profile(e)
    }
}

/// The plug-in interface. One instance serves one decoy.
///
/// The supervisor binds the listener (so the plug-in never chooses ports),
/// renders canaries into the profile, then calls [`Emulator::start`]. Events
/// go to the [`EventSink`]; the host agent stamps the fields a decoy may not
/// set and ships them (ADR 0002, ADR 0005).
pub trait Emulator: Send {
    /// Stable plug-in name, matching `plugin` in profiles.
    fn name(&self) -> &'static str;

    /// Ids of the profiles shipped with this plug-in (from
    /// `emulators/<id>/profiles/`). Operators may load others from disk.
    fn profiles(&self) -> Vec<&'static str>;

    /// Start serving on `listener`. Returns once the serving task is spawned.
    /// Must be called inside a Tokio runtime. Refuses a profile for another
    /// plug-in, an invalid profile, or one with unrendered canaries.
    fn start(
        &mut self,
        profile: &Profile,
        listener: TcpListener,
        sink: EventSink,
    ) -> Result<(), EmulatorError>;

    /// Stop accepting, end every open session and wait for the serving task.
    /// Safe to call more than once.
    fn stop(&mut self) -> BoxFuture<'_, ()>;

    fn health(&self) -> Health;
}

/// The built-in plug-ins by name.
pub fn plugin(name: &str) -> Option<Box<dyn Emulator>> {
    match name {
        redis::PLUGIN => Some(Box::new(redis::RedisEmulator::new())),
        http_portal::PLUGIN => Some(Box::new(http_portal::HttpPortalEmulator::new())),
        _ => None,
    }
}
