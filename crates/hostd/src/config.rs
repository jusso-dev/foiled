//! `hostd.toml`. Paths and identities only; no control-plane database
//! credentials ever live on a host (#41) or an edge sensor (#31).
//!
//! The same binary runs as a research sandbox host (`role = "host"`, the
//! default) or an edge sensor (`role = "sensor"`).

use std::path::PathBuf;

pub use foiled_core::agent::SandboxRuntime;
use foiled_core::auth::Role;
use foiled_core::enrolment::{HOST_BUFFER_BYTES, SENSOR_BUFFER_BYTES};
use serde::Deserialize;

/// Runtimes this build of `foiled-hostd` can drive. Firecracker is the
/// internet-facing default (ADR 0002) but its driver is not written yet
/// (#3), so a host configured for it refuses to start rather than pretend.
pub const BUILT_IN_RUNTIMES: &[SandboxRuntime] = &[SandboxRuntime::Docker, SandboxRuntime::Fake];

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustedKey {
    pub id: String,
    /// Hex Ed25519 public key of the control plane's job signing key.
    pub public_key: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostConfig {
    /// `host` (research sandbox host, #41) or `sensor` (edge sensor, #31).
    #[serde(default = "default_role")]
    pub role: Role,
    /// The host or sensor id the operator got when registering it.
    pub host_id: String,
    /// Ingest hostname base URL, for example `https://ingest.example.invalid`.
    pub api_base: String,
    /// PEM client certificate and key for mTLS (#31 enrolment). Required
    /// for `https://` control planes; only a lab host talking to a loopback
    /// mock may omit them.
    pub client_cert: Option<PathBuf>,
    pub client_key: Option<PathBuf>,
    pub trusted_keys: Vec<TrustedKey>,
    /// Artefacts this host will run: `sha256:<hex>`, `emulator:<id>/<profile>`
    /// or `module:<id>/<profile>[@sha256:<hex>]`.
    pub allowlist: Vec<String>,
    #[serde(default = "default_true")]
    pub publicly_exposed: bool,
    /// `firecracker` (default, not built in yet), `docker` (labs only) or
    /// `fake` (dry run: nothing runs, labs only). See [`HostConfig::runtime`].
    #[serde(default = "default_runtime")]
    pub sandbox_runtime: SandboxRuntime,
    pub state_dir: PathBuf,
    /// Offline buffer cap. Defaults to 1 GiB for hosts, 256 MiB for sensors.
    pub buffer_max_bytes: Option<u64>,
    /// Ed25519 release keys (offline, not the job key) that signed builds
    /// must verify against before an update is staged (#31).
    #[serde(default)]
    pub release_keys: Vec<TrustedKey>,
    #[serde(default = "default_heartbeat")]
    pub heartbeat_secs: u64,
    #[serde(default = "default_poll")]
    pub poll_secs: u64,
    /// Settings for the Docker lab runtime.
    #[serde(default)]
    pub docker: crate::docker::DockerConfig,
}

fn default_true() -> bool {
    true
}
fn default_runtime() -> SandboxRuntime {
    SandboxRuntime::Firecracker
}
fn default_role() -> Role {
    Role::Host
}
fn default_heartbeat() -> u64 {
    30
}
fn default_poll() -> u64 {
    5
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfigError {
    Parse(String),
    DockerOnPublicHost,
    /// `sandbox_runtime = "fake"` runs nothing, so a public host on it
    /// would look healthy to the control plane while capturing nothing.
    FakeOnPublicHost,
    /// The configured runtime has no driver in this build.
    RuntimeNotBuiltIn(SandboxRuntime),
    NoTrustedKeys,
    InsecureApiBase,
    MissingClientCertificate,
    BadRole,
    /// A key is pinned both as a job key and as a release key. Each signs
    /// one kind of thing; sharing one would let either stand in for the other.
    SharedSigningKey,
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConfigError::Parse(e) => write!(f, "hostd.toml: {e}"),
            ConfigError::DockerOnPublicHost => write!(
                f,
                "sandbox_runtime = \"docker\" is refused on a publicly exposed host"
            ),
            ConfigError::FakeOnPublicHost => write!(
                f,
                "sandbox_runtime = \"fake\" is a dry run that runs nothing; it is refused on a publicly exposed host"
            ),
            ConfigError::RuntimeNotBuiltIn(r) => write!(
                f,
                "sandbox_runtime = \"{}\" is not built into this foiled-hostd (the Firecracker driver is tracked in #3); \
                 refusing to start rather than report decoys that do not run. \
                 On a lab host that is not publicly exposed, use \"docker\", or \"fake\" for a dry run",
                r.as_str()
            ),
            ConfigError::NoTrustedKeys => write!(f, "trusted_keys must list at least one key"),
            ConfigError::InsecureApiBase => write!(
                f,
                "api_base must be https://, except a loopback mock on a host that is not publicly exposed"
            ),
            ConfigError::MissingClientCertificate => {
                write!(f, "client_cert and client_key are required for https://")
            }
            ConfigError::BadRole => write!(f, "role must be \"host\" or \"sensor\""),
            ConfigError::SharedSigningKey => write!(
                f,
                "release_keys and trusted_keys must not share a public key"
            ),
        }
    }
}

impl HostConfig {
    pub fn parse(text: &str) -> Result<Self, ConfigError> {
        let c: HostConfig = toml::from_str(text).map_err(|e| ConfigError::Parse(e.to_string()))?;
        c.validate()?;
        Ok(c)
    }

    /// The offline buffer cap for this role.
    pub fn buffer_cap(&self) -> u64 {
        self.buffer_max_bytes.unwrap_or(match self.role {
            Role::Sensor => SENSOR_BUFFER_BYTES,
            _ => HOST_BUFFER_BYTES,
        })
    }

    /// The runtime the agent will drive, or why it cannot start. Checked
    /// by `foiled-hostd run` before anything else, so a host never falls
    /// back to a runtime nobody asked for. `parse` does not call it: enrolling
    /// and verifying updates do not need a runtime.
    pub fn runtime(&self) -> Result<SandboxRuntime, ConfigError> {
        if BUILT_IN_RUNTIMES.contains(&self.sandbox_runtime) {
            Ok(self.sandbox_runtime)
        } else {
            Err(ConfigError::RuntimeNotBuiltIn(self.sandbox_runtime))
        }
    }

    pub fn validate(&self) -> Result<(), ConfigError> {
        if !matches!(self.role, Role::Host | Role::Sensor) {
            return Err(ConfigError::BadRole);
        }
        if self.publicly_exposed {
            match self.sandbox_runtime {
                SandboxRuntime::Docker => return Err(ConfigError::DockerOnPublicHost),
                SandboxRuntime::Fake => return Err(ConfigError::FakeOnPublicHost),
                SandboxRuntime::Firecracker => {}
            }
        }
        if self.trusted_keys.is_empty() {
            return Err(ConfigError::NoTrustedKeys);
        }
        let norm = |k: &TrustedKey| k.public_key.trim().to_ascii_lowercase();
        if self
            .release_keys
            .iter()
            .any(|r| self.trusted_keys.iter().any(|t| norm(t) == norm(r)))
        {
            return Err(ConfigError::SharedSigningKey);
        }
        if self.api_base.starts_with("https://") {
            if self.client_cert.is_none() || self.client_key.is_none() {
                return Err(ConfigError::MissingClientCertificate);
            }
        } else {
            let loopback = ["http://127.0.0.1:", "http://[::1]:", "http://localhost:"]
                .iter()
                .any(|p| self.api_base.starts_with(p));
            if !loopback || self.publicly_exposed {
                return Err(ConfigError::InsecureApiBase);
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const BASE: &str = r#"
host_id = "host-1"
api_base = "https://ingest.example.invalid"
client_cert = "/etc/foiled/host.crt"
client_key = "/etc/foiled/host.key"
allowlist = ["emulator:redis/redis-7.0"]
state_dir = "/var/lib/foiled"

[[trusted_keys]]
id = "k1"
public_key = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
"#;

    #[test]
    fn shipped_example_parses() {
        let text = std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../deploy/hostd.example.toml"
        ))
        .unwrap();
        let c = HostConfig::parse(&text).unwrap();
        assert!(c.publicly_exposed);
        assert_eq!(c.sandbox_runtime, SandboxRuntime::Firecracker);
        // The example describes the production shape, which cannot run on
        // this build: the agent must refuse to start with it (#91).
        assert_eq!(
            c.runtime(),
            Err(ConfigError::RuntimeNotBuiltIn(SandboxRuntime::Firecracker))
        );
    }

    #[test]
    fn shipped_sensor_example_parses() {
        let text = std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../deploy/sensor.example.toml"
        ))
        .unwrap();
        let c = HostConfig::parse(&text).unwrap();
        assert_eq!(c.role, Role::Sensor);
        assert_eq!(c.buffer_cap(), 256 * 1024 * 1024);
        assert_eq!(c.release_keys.len(), 1);
        assert_eq!(
            c.runtime(),
            Err(ConfigError::RuntimeNotBuiltIn(SandboxRuntime::Firecracker))
        );
    }

    #[test]
    fn defaults_are_safe() {
        let c = HostConfig::parse(BASE).unwrap();
        assert!(c.publicly_exposed, "assume public unless told otherwise");
        assert_eq!(c.sandbox_runtime, SandboxRuntime::Firecracker);
        assert_eq!(c.heartbeat_secs, 30);
        // The default never silently becomes something else.
        assert_eq!(
            c.runtime(),
            Err(ConfigError::RuntimeNotBuiltIn(SandboxRuntime::Firecracker))
        );
    }

    #[test]
    fn firecracker_is_refused_until_its_driver_is_built_in() {
        for prefix in ["", "publicly_exposed = false\n"] {
            let c = HostConfig::parse(&format!(
                "{prefix}sandbox_runtime = \"firecracker\"\n{BASE}"
            ))
            .unwrap();
            let e = c.runtime().unwrap_err();
            assert_eq!(
                e,
                ConfigError::RuntimeNotBuiltIn(SandboxRuntime::Firecracker)
            );
            let msg = e.to_string();
            assert!(msg.contains("firecracker") && msg.contains("#3"), "{msg}");
        }
    }

    #[test]
    fn fake_is_only_used_when_named_and_never_on_public_hosts() {
        let public = format!("sandbox_runtime = \"fake\"\n{BASE}");
        assert_eq!(
            HostConfig::parse(&public),
            Err(ConfigError::FakeOnPublicHost)
        );
        let lab = format!("sandbox_runtime = \"fake\"\npublicly_exposed = false\n{BASE}");
        let c = HostConfig::parse(&lab).unwrap();
        assert_eq!(c.runtime(), Ok(SandboxRuntime::Fake));
        let docker = format!("sandbox_runtime = \"docker\"\npublicly_exposed = false\n{BASE}");
        assert_eq!(
            HostConfig::parse(&docker).unwrap().runtime(),
            Ok(SandboxRuntime::Docker)
        );
        let unknown = format!("sandbox_runtime = \"recording\"\npublicly_exposed = false\n{BASE}");
        assert!(matches!(
            HostConfig::parse(&unknown),
            Err(ConfigError::Parse(_))
        ));
    }

    #[test]
    fn sensors_get_a_smaller_buffer_and_only_agent_roles_parse() {
        let host = HostConfig::parse(BASE).unwrap();
        assert_eq!(host.role, Role::Host);
        assert_eq!(host.buffer_cap(), 1024 * 1024 * 1024);
        let sensor = HostConfig::parse(&format!("role = \"sensor\"\n{BASE}")).unwrap();
        assert_eq!(sensor.buffer_cap(), 256 * 1024 * 1024);
        let capped = HostConfig::parse(&format!(
            "role = \"sensor\"\nbuffer_max_bytes = 1024\n{BASE}"
        ))
        .unwrap();
        assert_eq!(capped.buffer_cap(), 1024);
        assert_eq!(
            HostConfig::parse(&format!("role = \"human\"\n{BASE}")),
            Err(ConfigError::BadRole)
        );
    }

    #[test]
    fn job_and_release_keys_must_differ() {
        let shared = format!(
            "{BASE}\n[[release_keys]]\nid = \"rel\"\npublic_key = \"D75A980182B10AB7D54BFED3C964073A0EE172F3DAA62325AF021A68F707511A\"\n"
        );
        assert_eq!(
            HostConfig::parse(&shared),
            Err(ConfigError::SharedSigningKey)
        );
        let distinct = format!(
            "{BASE}\n[[release_keys]]\nid = \"rel\"\npublic_key = \"{}\"\n",
            "3d".repeat(32)
        );
        assert!(HostConfig::parse(&distinct).is_ok());
    }

    #[test]
    fn docker_is_refused_on_public_hosts() {
        let docker = format!("sandbox_runtime = \"docker\"\n{BASE}");
        assert_eq!(
            HostConfig::parse(&docker),
            Err(ConfigError::DockerOnPublicHost)
        );
        let lab = format!("sandbox_runtime = \"docker\"\npublicly_exposed = false\n{BASE}");
        assert!(HostConfig::parse(&lab).is_ok());
    }

    #[test]
    fn plain_http_and_unknown_keys_are_refused() {
        let http = BASE.replace("https://", "http://");
        assert_eq!(HostConfig::parse(&http), Err(ConfigError::InsecureApiBase));
        let lab = BASE.replace("https://ingest.example.invalid", "http://127.0.0.1:8787");
        assert_eq!(
            HostConfig::parse(&lab),
            Err(ConfigError::InsecureApiBase),
            "public host"
        );
        let lab = format!("publicly_exposed = false\n{lab}");
        assert!(HostConfig::parse(&lab).is_ok(), "loopback lab mock");
        let no_cert = BASE.replace("client_cert = \"/etc/foiled/host.crt\"\n", "");
        assert_eq!(
            HostConfig::parse(&no_cert),
            Err(ConfigError::MissingClientCertificate)
        );
        let extra = format!("database_url = \"postgres://x\"\n{BASE}");
        assert!(matches!(
            HostConfig::parse(&extra),
            Err(ConfigError::Parse(_))
        ));
    }
}
