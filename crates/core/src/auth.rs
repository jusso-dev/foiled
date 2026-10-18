//! Identities and scopes for the control plane API (#21, #31, #41).
//!
//! Humans, MCP clients, sandbox hosts and edge sensors are separate roles.
//! A role can only ever hold scopes from its own family, so a stolen host
//! certificate or sensor certificate can never carry `decoys:write` or
//! `admin`, whatever the token table says.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    /// An operator using the console or CLI with a bearer token.
    Human,
    /// An MCP server or other agent client with a bearer token (#24).
    Mcp,
    /// A Foiled sandbox host agent, identified by its mTLS certificate (#41).
    Host,
    /// An edge sensor, identified by its mTLS certificate (#31).
    Sensor,
}

impl Role {
    pub fn as_str(self) -> &'static str {
        match self {
            Role::Human => "human",
            Role::Mcp => "mcp",
            Role::Host => "host",
            Role::Sensor => "sensor",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        [Role::Human, Role::Mcp, Role::Host, Role::Sensor]
            .into_iter()
            .find(|r| r.as_str() == s)
    }
}

macro_rules! scopes {
    ($($variant:ident => $name:literal),+ $(,)?) => {
        /// A permission on the API. The string form is what tokens store.
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
        pub enum Scope { $($variant),+ }

        impl Scope {
            pub const ALL: &'static [Scope] = &[$(Scope::$variant),+];

            pub fn as_str(self) -> &'static str {
                match self { $(Scope::$variant => $name),+ }
            }

            pub fn parse(s: &str) -> Option<Scope> {
                match s { $($name => Some(Scope::$variant),)+ _ => None }
            }
        }
    };
}

scopes! {
    CatalogueRead => "catalogue:read",
    DecoysRead => "decoys:read",
    DecoysWrite => "decoys:write",
    DecoysElevate => "decoys:elevate",
    AttemptsRead => "attempts:read",
    AttemptsWrite => "attempts:write",
    CampaignsRead => "campaigns:read",
    CampaignsWrite => "campaigns:write",
    IocsRead => "iocs:read",
    ReviewRead => "review:read",
    ReviewWrite => "review:write",
    SensorsRead => "sensors:read",
    SensorsWrite => "sensors:write",
    HostsRead => "hosts:read",
    HostsWrite => "hosts:write",
    QuarantineRead => "quarantine:read",
    QuarantineDownload => "quarantine:download",
    ExportsRead => "exports:read",
    AlertsRead => "alerts:read",
    AlertsWrite => "alerts:write",
    AuditRead => "audit:read",
    EventsRead => "events:read",
    Admin => "admin",
    HostLease => "host:lease",
    HostReport => "host:report",
    HostIngest => "host:ingest",
    HostUpload => "host:upload",
    SensorIngest => "sensor:ingest",
    SensorUpload => "sensor:upload",
    SensorHeartbeat => "sensor:heartbeat",
}

impl Serialize for Scope {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for Scope {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        Scope::parse(&s).ok_or_else(|| serde::de::Error::custom(format!("unknown scope '{s}'")))
    }
}

/// The only scopes an `mcp` token can hold (#24). Agents get least
/// privilege: no `admin`, no writes outside decoys, and no quarantine
/// download, so a misled agent cannot fetch malware or change intel.
pub const MCP_SCOPES: &[Scope] = &[
    Scope::CatalogueRead,
    Scope::DecoysRead,
    Scope::DecoysWrite,
    Scope::DecoysElevate,
    Scope::AttemptsRead,
    Scope::AuditRead,
    Scope::EventsRead,
];

impl Scope {
    /// Whether a principal with `role` may hold this scope at all.
    pub fn allowed_for(self, role: Role) -> bool {
        let name = self.as_str();
        match role {
            Role::Host => name.starts_with("host:"),
            Role::Sensor => name.starts_with("sensor:"),
            Role::Human => !name.starts_with("host:") && !name.starts_with("sensor:"),
            Role::Mcp => MCP_SCOPES.contains(&self),
        }
    }
}

/// The authenticated caller of one request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Principal {
    /// Token id, host id or sensor id.
    pub id: String,
    pub role: Role,
    pub tenant_id: String,
    pub scopes: Vec<Scope>,
}

impl Principal {
    /// Build a principal, dropping any scope the role may not hold.
    pub fn new(
        id: impl Into<String>,
        role: Role,
        tenant_id: impl Into<String>,
        scopes: impl IntoIterator<Item = Scope>,
    ) -> Self {
        let mut scopes: Vec<Scope> = scopes.into_iter().filter(|s| s.allowed_for(role)).collect();
        scopes.sort();
        scopes.dedup();
        Principal {
            id: id.into(),
            role,
            tenant_id: tenant_id.into(),
            scopes,
        }
    }

    /// `admin` implies every human scope, never host or sensor scopes.
    pub fn has(&self, scope: Scope) -> bool {
        self.scopes.contains(&scope)
            || (scope.allowed_for(Role::Human) && self.scopes.contains(&Scope::Admin))
    }
}

/// Parse a space or comma separated scope list. Unknown scopes are errors so
/// a typo in the token table fails loudly rather than silently granting less.
pub fn parse_scopes(s: &str) -> Result<Vec<Scope>, String> {
    s.split([' ', ','])
        .filter(|p| !p.is_empty())
        .map(|p| Scope::parse(p).ok_or_else(|| format!("unknown scope '{p}'")))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scope_strings_round_trip() {
        for s in Scope::ALL {
            assert_eq!(Scope::parse(s.as_str()), Some(*s));
            let json = serde_json::to_string(s).unwrap();
            assert_eq!(serde_json::from_str::<Scope>(&json).unwrap(), *s);
        }
        assert!(serde_json::from_str::<Scope>("\"root\"").is_err());
    }

    #[test]
    fn host_identity_cannot_hold_human_scopes() {
        let p = Principal::new(
            "host-1",
            Role::Host,
            "t1",
            [
                Scope::Admin,
                Scope::DecoysWrite,
                Scope::HostLease,
                Scope::SensorIngest,
            ],
        );
        assert_eq!(p.scopes, vec![Scope::HostLease]);
        assert!(!p.has(Scope::DecoysWrite));
        assert!(!p.has(Scope::AuditRead));
    }

    #[test]
    fn sensor_identity_only_holds_sensor_scopes() {
        let p = Principal::new("s1", Role::Sensor, "t1", Scope::ALL.iter().copied());
        assert!(p.scopes.iter().all(|s| s.as_str().starts_with("sensor:")));
        assert!(p.has(Scope::SensorIngest));
        assert!(!p.has(Scope::HostLease));
    }

    #[test]
    fn mcp_tokens_get_least_privilege() {
        let p = Principal::new("agent", Role::Mcp, "t1", Scope::ALL.iter().copied());
        assert_eq!(p.scopes, {
            let mut s = MCP_SCOPES.to_vec();
            s.sort();
            s
        });
        assert!(!p.has(Scope::Admin));
        assert!(!p.has(Scope::QuarantineDownload));
        assert!(!p.has(Scope::AttemptsWrite));
        assert!(!p.has(Scope::HostLease));
        // `admin` in the token table grants an agent nothing.
        let a = Principal::new("agent", Role::Mcp, "t1", [Scope::Admin]);
        assert!(a.scopes.is_empty());
        assert!(!a.has(Scope::DecoysRead));
    }

    #[test]
    fn admin_implies_human_scopes_only() {
        let p = Principal::new("tok", Role::Human, "t1", [Scope::Admin]);
        assert!(p.has(Scope::DecoysWrite));
        assert!(p.has(Scope::AuditRead));
        assert!(!p.has(Scope::HostLease));
        assert!(!p.has(Scope::SensorIngest));
    }

    #[test]
    fn parse_scope_lists() {
        assert_eq!(
            parse_scopes("decoys:read, attempts:read").unwrap(),
            vec![Scope::DecoysRead, Scope::AttemptsRead]
        );
        assert!(parse_scopes("decoys:read decoys:everything").is_err());
        assert_eq!(parse_scopes("").unwrap(), vec![]);
    }
}
