//! Canary credentials planted in decoy guests (#17).
//!
//! The design is in `docs/canaries.md`. This module holds the pure parts:
//!
//! - [`generate`] turns 32 caller-supplied random bytes plus the decoy id,
//!   generation and kind into a [`Canary`]. The caller supplies the
//!   randomness and the time, which keeps this module wasm-safe and
//!   deterministic under test.
//! - [`CanaryIndex`] holds only SHA-256 hashes, lengths and a short prefix of
//!   each value, and finds exact occurrences of canary values in raw bytes
//!   (an HTTP request seen by the egress proxy or the beacon listener).
//! - [`render_env_file`] writes the `.env` file the host agent plants.
//!
//! Every format is visibly fake and fails closed against real services:
//! `vt-canary-` and `vt_canary_` prefixes, a `VTCANARY` cloud access key id
//! that no cloud provider issues, and a database host under the reserved
//! `.invalid` top-level domain.

use std::collections::BTreeMap;
use std::fmt;

use ed25519_dalek::SigningKey;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

/// Prefix shared by Foiled-native API keys and admin passwords.
pub const PREFIX: &str = "vt-canary-";
/// Prefix of fake API keys.
pub const API_KEY_PREFIX: &str = "vt-canary-ak-";
/// Prefix of fake database user names.
pub const DB_USER_PREFIX: &str = "vt_canary_";
/// Host in fake database URLs. `.invalid` never resolves (RFC 2606).
pub const DB_HOST: &str = "db.internal.invalid";
/// Prefix of fake cloud access key ids. Real AWS key ids start with a
/// four-letter type code such as `AKIA` or `ASIA`; `VTCANARY` is not one.
pub const CLOUD_ACCESS_ID_PREFIX: &str = "VTCANARY";
/// Prefix of fake cloud secret keys.
pub const CLOUD_SECRET_PREFIX: &str = "vtcanary";
/// How many leading bytes of each value the index keeps in clear text.
pub const NEEDLE_PREFIX_LEN: usize = 8;

const DOMAIN: &[u8] = b"foiled-canary-v1";
const BASE62: &[u8] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
const BASE32: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
const BASE64: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const PEM_BEGIN: &str = "-----BEGIN OPENSSH PRIVATE KEY-----";
const PEM_END: &str = "-----END OPENSSH PRIVATE KEY-----";
const OPENSSH_MAGIC: &[u8] = b"openssh-key-v1\0";
const SSH_ED25519: &[u8] = b"ssh-ed25519";

/// The canary kinds a catalogue entry can declare in `canary_slots`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CanaryKind {
    ApiKey,
    DatabaseUrl,
    CloudAccessKey,
    SshPrivateKey,
    AdminPassword,
}

impl CanaryKind {
    pub const ALL: [CanaryKind; 5] = [
        CanaryKind::ApiKey,
        CanaryKind::DatabaseUrl,
        CanaryKind::CloudAccessKey,
        CanaryKind::SshPrivateKey,
        CanaryKind::AdminPassword,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            CanaryKind::ApiKey => "api_key",
            CanaryKind::DatabaseUrl => "database_url",
            CanaryKind::CloudAccessKey => "cloud_access_key",
            CanaryKind::SshPrivateKey => "ssh_private_key",
            CanaryKind::AdminPassword => "admin_password",
        }
    }

    /// Parse the `kind` string of a catalogue `canary_slots` item.
    pub fn parse(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|k| k.as_str() == s)
    }
}

/// One planted value. `value` is secret: it travels only in the signed
/// create job to the host and into the guest. The trusted store keeps the
/// [`CanaryIndex`] form instead.
///
/// Value layout by kind:
///
/// - `api_key`: `vt-canary-ak-<32 hex>`
/// - `database_url`: `postgres://vt_canary_<8 hex>:<24 hex>@db.internal.invalid:5432/app`
/// - `cloud_access_key`: `<access key id>:<secret>`, where the id is
///   `VTCANARY<12 base32>` and the secret is `vtcanary<32 base62>`
/// - `ssh_private_key`: an unencrypted OpenSSH Ed25519 private key PEM
/// - `admin_password`: `vt-canary-<20 base62>`
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Canary {
    pub id: String,
    pub decoy_id: String,
    pub generation: u32,
    pub kind: CanaryKind,
    pub value: String,
    /// Unix milliseconds, supplied by the caller.
    pub created_at: i64,
}

impl fmt::Debug for Canary {
    // Never print the value: Debug output ends up in logs.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Canary")
            .field("id", &self.id)
            .field("decoy_id", &self.decoy_id)
            .field("generation", &self.generation)
            .field("kind", &self.kind)
            .field("value", &"<redacted>")
            .field("created_at", &self.created_at)
            .finish()
    }
}

impl Canary {
    /// `(access key id, secret)` for a cloud access key canary.
    pub fn cloud_key_pair(&self) -> Option<(&str, &str)> {
        if self.kind != CanaryKind::CloudAccessKey {
            return None;
        }
        self.value.split_once(':')
    }

    /// The password part of a database URL canary.
    pub fn db_password(&self) -> Option<&str> {
        if self.kind != CanaryKind::DatabaseUrl {
            return None;
        }
        let rest = self.value.strip_prefix("postgres://")?;
        let (userinfo, _) = rest.split_once('@')?;
        userinfo.split_once(':').map(|(_, p)| p)
    }

    /// `ssh-ed25519 <base64> <comment>` for an SSH canary, the line to put in
    /// the `.pub` file next to the key and on SSH decoys that watch for it.
    pub fn ssh_public_key(&self) -> Option<String> {
        let blob = self.ssh_public_blob()?;
        Some(format!(
            "ssh-ed25519 {} {}",
            base64_encode(&blob),
            ssh_comment(&self.id)
        ))
    }

    fn ssh_public_blob(&self) -> Option<Vec<u8>> {
        if self.kind != CanaryKind::SshPrivateKey {
            return None;
        }
        let body: String = self
            .value
            .lines()
            .filter(|l| !l.starts_with("-----"))
            .collect();
        let raw = base64_decode(&body)?;
        let mut r = Reader::new(raw.strip_prefix(OPENSSH_MAGIC)?);
        r.string()?; // cipher
        r.string()?; // kdf
        r.string()?; // kdf options
        r.u32()?; // number of keys
        r.string().map(<[u8]>::to_vec)
    }

    /// The strings the index looks for. Each is long and high-entropy enough
    /// that an exact match is attributable to this canary alone.
    pub fn needles(&self) -> Vec<String> {
        match self.kind {
            CanaryKind::ApiKey | CanaryKind::AdminPassword => vec![self.value.clone()],
            // The password is inside the URL, so one needle covers both the
            // whole URL and the password used on its own.
            CanaryKind::DatabaseUrl => self.db_password().map(str::to_string).into_iter().collect(),
            CanaryKind::CloudAccessKey => self
                .cloud_key_pair()
                .map(|(id, secret)| vec![id.to_string(), secret.to_string()])
                .unwrap_or_default(),
            CanaryKind::SshPrivateKey => {
                let mut out = vec![self.value.trim_end().to_string()];
                if let Some(blob) = self.ssh_public_blob() {
                    out.push(base64_encode(&blob));
                }
                out
            }
        }
    }
}

/// Mint a canary. Deterministic in all inputs; the caller supplies 32 bytes
/// from a CSPRNG (the Worker's `crypto.getRandomValues`, the host's OS
/// RNG) and the creation time. Values are HMAC-SHA256 outputs keyed by the
/// random bytes over the kind, decoy id and generation, so the same bytes
/// used for another decoy or generation still give unrelated values.
pub fn generate(
    kind: CanaryKind,
    decoy_id: &str,
    generation: u32,
    rng_bytes: &[u8; 32],
    created_at: i64,
) -> Canary {
    let ctx = Ctx {
        key: rng_bytes,
        kind,
        decoy_id,
        generation,
    };
    let id = format!("cn_{}", hex::encode(&ctx.block("id", 0)[..8]));
    let value = match kind {
        CanaryKind::ApiKey => format!("{API_KEY_PREFIX}{}", hex::encode(ctx.bytes("api", 16))),
        CanaryKind::DatabaseUrl => format!(
            "postgres://{DB_USER_PREFIX}{}:{}@{DB_HOST}:5432/app",
            hex::encode(ctx.bytes("db-user", 4)),
            hex::encode(ctx.bytes("db-pass", 12)),
        ),
        CanaryKind::CloudAccessKey => format!(
            "{CLOUD_ACCESS_ID_PREFIX}{}:{CLOUD_SECRET_PREFIX}{}",
            ctx.alphabet("cloud-id", BASE32, 12),
            ctx.alphabet("cloud-secret", BASE62, 32),
        ),
        CanaryKind::SshPrivateKey => openssh_ed25519_pem(
            &ctx.block("ssh-seed", 0),
            u32::from_be_bytes(first4(&ctx.block("ssh-check", 0))),
            &ssh_comment(&id),
        ),
        CanaryKind::AdminPassword => format!("{PREFIX}{}", ctx.alphabet("admin", BASE62, 20)),
    };
    Canary {
        id,
        decoy_id: decoy_id.to_string(),
        generation,
        kind,
        value,
        created_at,
    }
}

/// The beacon URL for a canary: `<base>/c/<canary id>`.
pub fn beacon_url(base: &str, canary_id: &str) -> String {
    format!("{}/c/{canary_id}", base.trim_end_matches('/'))
}

/// Render a `.env` file for the canaries that belong in one. SSH keys are
/// skipped (they get their own file). When `beacon_base_url` is set, the
/// file also points `API_BASE_URL` and `AWS_ENDPOINT_URL` at the beacon
/// listener so that an attacker who tries the stolen key hits it.
pub fn render_env_file(canaries: &[Canary], beacon_base_url: Option<&str>) -> String {
    let mut out = String::from("APP_ENV=production\nLOG_LEVEL=info\n");
    let mut seen: BTreeMap<&str, usize> = BTreeMap::new();
    let mut push = |out: &mut String, name: &'static str, value: &str| {
        let n = seen.entry(name).or_insert(0);
        *n += 1;
        if *n == 1 {
            out.push_str(&format!("{name}={value}\n"));
        } else {
            out.push_str(&format!("{name}_{n}={value}\n"));
        }
    };
    for c in canaries {
        match c.kind {
            CanaryKind::ApiKey => {
                if let Some(base) = beacon_base_url {
                    push(&mut out, "API_BASE_URL", &beacon_url(base, &c.id));
                }
                push(&mut out, "API_KEY", &c.value);
            }
            CanaryKind::DatabaseUrl => push(&mut out, "DATABASE_URL", &c.value),
            CanaryKind::CloudAccessKey => {
                if let Some((id, secret)) = c.cloud_key_pair() {
                    push(&mut out, "AWS_ACCESS_KEY_ID", id);
                    push(&mut out, "AWS_SECRET_ACCESS_KEY", secret);
                    if let Some(base) = beacon_base_url {
                        push(&mut out, "AWS_ENDPOINT_URL", &beacon_url(base, &c.id));
                    }
                }
            }
            CanaryKind::AdminPassword => push(&mut out, "ADMIN_PASSWORD", &c.value),
            CanaryKind::SshPrivateKey => {}
        }
    }
    out
}

/// One indexed needle. Holds no secret beyond the first
/// [`NEEDLE_PREFIX_LEN`] bytes, which for most kinds are the fixed fake
/// prefix.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IndexEntry {
    pub canary_id: String,
    pub decoy_id: String,
    pub generation: u32,
    pub kind: CanaryKind,
    pub prefix: String,
    pub len: usize,
    /// Lower-case hex SHA-256 of the needle.
    pub sha256: String,
}

/// A canary value found in scanned bytes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CanaryHit {
    pub canary_id: String,
    pub decoy_id: String,
    pub generation: u32,
    pub kind: CanaryKind,
    /// Byte offset of the match in the haystack.
    pub offset: usize,
}

impl CanaryHit {
    /// The `data` object of the `egress` capture envelope that reports this
    /// hit. `detector` is `egress_proxy`, `beacon` or `canarytokens`. The
    /// value is never included.
    pub fn capture_data(&self, detector: &str) -> Map<String, Value> {
        let mut m = Map::new();
        m.insert("detector".into(), detector.into());
        m.insert("canary_id".into(), self.canary_id.clone().into());
        m.insert("canary_kind".into(), self.kind.as_str().into());
        m.insert("canary_generation".into(), self.generation.into());
        m
    }
}

/// Exact-match lookup of canary values by hash. Safe to ship to the egress
/// proxy and the beacon listener: it never holds a full value.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CanaryIndex {
    entries: Vec<IndexEntry>,
}

impl CanaryIndex {
    pub fn new() -> Self {
        Self::default()
    }

    /// Index every needle of `canary`. Inserting the same canary twice is a
    /// no-op.
    pub fn insert(&mut self, canary: &Canary) {
        for needle in canary.needles() {
            let entry = IndexEntry {
                canary_id: canary.id.clone(),
                decoy_id: canary.decoy_id.clone(),
                generation: canary.generation,
                kind: canary.kind,
                prefix: needle[..NEEDLE_PREFIX_LEN.min(needle.len())].to_string(),
                len: needle.len(),
                sha256: sha256_hex(needle.as_bytes()),
            };
            if !self.entries.contains(&entry) {
                self.entries.push(entry);
            }
        }
    }

    pub fn entries(&self) -> &[IndexEntry] {
        &self.entries
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// The entry for a canary id, as seen in a beacon URL path.
    pub fn by_id(&self, canary_id: &str) -> Option<&IndexEntry> {
        self.entries.iter().find(|e| e.canary_id == canary_id)
    }

    /// Find every exact occurrence of an indexed value in `haystack`. For
    /// each distinct (prefix, length) pair, every occurrence of the prefix is
    /// hashed over the needle length and compared. Hits are ordered by
    /// offset.
    pub fn scan(&self, haystack: &[u8]) -> Vec<CanaryHit> {
        let mut groups: BTreeMap<(&[u8], usize), Vec<&IndexEntry>> = BTreeMap::new();
        for e in &self.entries {
            groups
                .entry((e.prefix.as_bytes(), e.len))
                .or_default()
                .push(e);
        }
        let mut hits = Vec::new();
        for ((prefix, len), group) in groups {
            if prefix.is_empty() || len > haystack.len() {
                continue;
            }
            for offset in 0..=haystack.len() - len {
                if !haystack[offset..].starts_with(prefix) {
                    continue;
                }
                let digest = sha256_hex(&haystack[offset..offset + len]);
                for e in group.iter().filter(|e| e.sha256 == digest) {
                    hits.push(CanaryHit {
                        canary_id: e.canary_id.clone(),
                        decoy_id: e.decoy_id.clone(),
                        generation: e.generation,
                        kind: e.kind,
                        offset,
                    });
                }
            }
        }
        hits.sort_by(|a, b| (a.offset, &a.canary_id).cmp(&(b.offset, &b.canary_id)));
        hits
    }
}

struct Ctx<'a> {
    key: &'a [u8; 32],
    kind: CanaryKind,
    decoy_id: &'a str,
    generation: u32,
}

impl Ctx<'_> {
    /// HMAC-SHA256(key = random bytes, length-prefixed domain, kind, decoy
    /// id and label, then generation and counter).
    fn block(&self, label: &str, counter: u32) -> [u8; 32] {
        let mut mac = Hmac::<Sha256>::new_from_slice(self.key).expect("HMAC takes any key length");
        for part in [
            DOMAIN,
            self.kind.as_str().as_bytes(),
            self.decoy_id.as_bytes(),
            label.as_bytes(),
        ] {
            mac.update(&(part.len() as u32).to_be_bytes());
            mac.update(part);
        }
        mac.update(&self.generation.to_be_bytes());
        mac.update(&counter.to_be_bytes());
        mac.finalize().into_bytes().into()
    }

    fn stream(&self, label: &'static str) -> impl Iterator<Item = u8> + '_ {
        (0u32..).flat_map(move |i| self.block(label, i))
    }

    fn bytes(&self, label: &'static str, n: usize) -> Vec<u8> {
        self.stream(label).take(n).collect()
    }

    /// `n` characters from `alphabet` with no modulo bias (rejection
    /// sampling).
    fn alphabet(&self, label: &'static str, alphabet: &[u8], n: usize) -> String {
        let limit = 256 - 256 % alphabet.len();
        self.stream(label)
            .filter(|b| usize::from(*b) < limit)
            .take(n)
            .map(|b| char::from(alphabet[usize::from(b) % alphabet.len()]))
            .collect()
    }
}

fn first4(b: &[u8; 32]) -> [u8; 4] {
    [b[0], b[1], b[2], b[3]]
}

fn ssh_comment(canary_id: &str) -> String {
    format!("{PREFIX}{canary_id}")
}

fn sha256_hex(b: &[u8]) -> String {
    hex::encode(Sha256::digest(b))
}

fn put_string(out: &mut Vec<u8>, s: &[u8]) {
    out.extend_from_slice(&(s.len() as u32).to_be_bytes());
    out.extend_from_slice(s);
}

/// Unencrypted OpenSSH private key (PROTOCOL.key) for one Ed25519 key.
fn openssh_ed25519_pem(seed: &[u8; 32], checkint: u32, comment: &str) -> String {
    let pk = SigningKey::from_bytes(seed).verifying_key().to_bytes();

    let mut public = Vec::new();
    put_string(&mut public, SSH_ED25519);
    put_string(&mut public, &pk);

    let mut private = Vec::new();
    private.extend_from_slice(&checkint.to_be_bytes());
    private.extend_from_slice(&checkint.to_be_bytes());
    put_string(&mut private, SSH_ED25519);
    put_string(&mut private, &pk);
    let mut sk = seed.to_vec();
    sk.extend_from_slice(&pk);
    put_string(&mut private, &sk);
    put_string(&mut private, comment.as_bytes());
    let mut pad = 1u8;
    while private.len() % 8 != 0 {
        private.push(pad);
        pad += 1;
    }

    let mut body = OPENSSH_MAGIC.to_vec();
    put_string(&mut body, b"none");
    put_string(&mut body, b"none");
    put_string(&mut body, b"");
    body.extend_from_slice(&1u32.to_be_bytes());
    put_string(&mut body, &public);
    put_string(&mut body, &private);

    let b64 = base64_encode(&body);
    let mut out = String::from(PEM_BEGIN);
    out.push('\n');
    for chunk in b64.as_bytes().chunks(70) {
        out.push_str(std::str::from_utf8(chunk).expect("base64 is ASCII"));
        out.push('\n');
    }
    out.push_str(PEM_END);
    out.push('\n');
    out
}

fn base64_encode(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b = [
            chunk[0],
            chunk.get(1).copied().unwrap_or(0),
            chunk.get(2).copied().unwrap_or(0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        for i in 0..4 {
            if i <= chunk.len() {
                out.push(char::from(BASE64[((n >> (18 - 6 * i)) & 63) as usize]));
            } else {
                out.push('=');
            }
        }
    }
    out
}

fn base64_decode(s: &str) -> Option<Vec<u8>> {
    let s = s.trim_end_matches('=');
    let mut out = Vec::with_capacity(s.len() * 3 / 4);
    let mut acc = 0u32;
    let mut bits = 0;
    for c in s.bytes() {
        let v = BASE64.iter().position(|&x| x == c)? as u32;
        acc = (acc << 6) | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    Some(out)
}

struct Reader<'a> {
    buf: &'a [u8],
}

impl<'a> Reader<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf }
    }

    fn u32(&mut self) -> Option<u32> {
        let (head, rest) = self.buf.split_first_chunk::<4>()?;
        self.buf = rest;
        Some(u32::from_be_bytes(*head))
    }

    fn string(&mut self) -> Option<&'a [u8]> {
        let n = self.u32()? as usize;
        if n > self.buf.len() {
            return None;
        }
        let (s, rest) = self.buf.split_at(n);
        self.buf = rest;
        Some(s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capture::{CaptureEvent, Channel, Endpoint, Severity};
    use crate::catalogue::DecoyKind;
    use crate::decoy::ReasonCode;

    const T0: i64 = 1_792_285_000_000;

    fn bytes(n: u8) -> [u8; 32] {
        let mut b = [0u8; 32];
        for (i, x) in b.iter_mut().enumerate() {
            *x = n.wrapping_mul(31).wrapping_add(i as u8);
        }
        b
    }

    fn mint(kind: CanaryKind) -> Canary {
        generate(kind, "dcy-demo-1", 3, &bytes(1), T0)
    }

    fn all_for(decoy: &str, generation: u32) -> Vec<Canary> {
        CanaryKind::ALL
            .into_iter()
            .enumerate()
            .map(|(i, k)| generate(k, decoy, generation, &bytes(i as u8 + 10), T0))
            .collect()
    }

    fn is_hex(s: &str) -> bool {
        s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    }

    fn in_alphabet(s: &str, a: &[u8]) -> bool {
        s.bytes().all(|b| a.contains(&b))
    }

    #[test]
    fn kind_strings_match_the_catalogue_schema() {
        for k in CanaryKind::ALL {
            assert_eq!(CanaryKind::parse(k.as_str()), Some(k));
            assert_eq!(serde_json::to_value(k).unwrap(), k.as_str());
        }
        assert_eq!(CanaryKind::parse("email"), None);
    }

    #[test]
    fn canary_id_format() {
        let c = mint(CanaryKind::ApiKey);
        let hex = c.id.strip_prefix("cn_").unwrap();
        assert_eq!(hex.len(), 16);
        assert!(is_hex(hex));
        assert_eq!(c.decoy_id, "dcy-demo-1");
        assert_eq!(c.generation, 3);
        assert_eq!(c.created_at, T0);
    }

    #[test]
    fn api_key_format() {
        let v = mint(CanaryKind::ApiKey).value;
        let rest = v.strip_prefix("vt-canary-ak-").unwrap();
        assert_eq!(rest.len(), 32);
        assert!(is_hex(rest));
    }

    #[test]
    fn database_url_format() {
        let c = mint(CanaryKind::DatabaseUrl);
        let rest = c.value.strip_prefix("postgres://vt_canary_").unwrap();
        let (user, rest) = rest.split_once(':').unwrap();
        let (pass, rest) = rest.split_once('@').unwrap();
        assert_eq!(rest, "db.internal.invalid:5432/app");
        assert_eq!(user.len(), 8);
        assert!(is_hex(user));
        assert_eq!(pass.len(), 24);
        assert!(is_hex(pass));
        assert_eq!(c.db_password(), Some(pass));
    }

    #[test]
    fn cloud_access_key_format() {
        let c = mint(CanaryKind::CloudAccessKey);
        let (id, secret) = c.cloud_key_pair().unwrap();
        // Same length as a real AWS access key id, but a prefix AWS never
        // issues (theirs start AKIA, ASIA, AIDA, AROA and similar).
        assert_eq!(id.len(), 20);
        let tail = id.strip_prefix("VTCANARY").unwrap();
        assert!(in_alphabet(tail, BASE32));
        assert!(!id.starts_with('A'));
        assert_eq!(secret.len(), 40);
        let tail = secret.strip_prefix("vtcanary").unwrap();
        assert!(in_alphabet(tail, BASE62));
    }

    #[test]
    fn admin_password_format() {
        let v = mint(CanaryKind::AdminPassword).value;
        let rest = v.strip_prefix("vt-canary-").unwrap();
        assert_eq!(rest.len(), 20);
        assert!(in_alphabet(rest, BASE62));
    }

    /// Decode our own PEM and check the PROTOCOL.key structure field by
    /// field, and that the private seed really derives the public key.
    #[test]
    fn ssh_private_key_is_well_formed_openssh_ed25519() {
        let c = mint(CanaryKind::SshPrivateKey);
        let lines: Vec<&str> = c.value.lines().collect();
        assert_eq!(lines.first(), Some(&PEM_BEGIN));
        assert_eq!(lines.last(), Some(&PEM_END));
        assert!(c.value.ends_with('\n'));
        assert!(lines[1..lines.len() - 1].iter().all(|l| l.len() <= 70));

        let body: String = lines[1..lines.len() - 1].concat();
        let raw = base64_decode(&body).unwrap();
        assert_eq!(base64_encode(&raw), body);
        let mut r = Reader::new(raw.strip_prefix(OPENSSH_MAGIC).unwrap());
        assert_eq!(r.string(), Some(&b"none"[..]));
        assert_eq!(r.string(), Some(&b"none"[..]));
        assert_eq!(r.string(), Some(&b""[..]));
        assert_eq!(r.u32(), Some(1));
        let public = r.string().unwrap().to_vec();
        let private = r.string().unwrap();
        assert!(r.buf.is_empty());
        assert_eq!(private.len() % 8, 0);

        let mut p = Reader::new(&public);
        assert_eq!(p.string(), Some(SSH_ED25519));
        let pk = p.string().unwrap();
        assert_eq!(pk.len(), 32);

        let mut s = Reader::new(private);
        let check1 = s.u32().unwrap();
        assert_eq!(s.u32(), Some(check1));
        assert_eq!(s.string(), Some(SSH_ED25519));
        assert_eq!(s.string(), Some(pk));
        let sk = s.string().unwrap();
        assert_eq!(sk.len(), 64);
        assert_eq!(&sk[32..], pk);
        let seed: [u8; 32] = sk[..32].try_into().unwrap();
        assert_eq!(SigningKey::from_bytes(&seed).verifying_key().to_bytes(), pk);
        let comment = s.string().unwrap();
        assert_eq!(comment, format!("vt-canary-{}", c.id).as_bytes());
        for (i, b) in s.buf.iter().enumerate() {
            assert_eq!(usize::from(*b), i + 1, "padding");
        }

        let pub_line = c.ssh_public_key().unwrap();
        assert_eq!(
            pub_line,
            format!("ssh-ed25519 {} vt-canary-{}", base64_encode(&public), c.id)
        );
    }

    /// Known answer from OpenSSH itself: `ssh-keygen -y -f` on the key
    /// generated from these inputs printed this line (and `ssh-keygen -Y
    /// sign` signed with it), so OpenSSH accepts our PEM and agrees on the
    /// key it holds.
    #[test]
    fn ssh_private_key_matches_openssh_known_answer() {
        let c = generate(CanaryKind::SshPrivateKey, "dcy-demo-1", 3, &[7u8; 32], T0);
        assert_eq!(c.id, "cn_19fae2c3f3637aa6");
        assert_eq!(
            c.ssh_public_key().unwrap(),
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBmNqUrsWwKJTKtXQry2bBJ9avbitgHjU+zAvzp7kS8/ \
             vt-canary-cn_19fae2c3f3637aa6"
        );
    }

    #[test]
    fn base64_round_trip_and_padding() {
        for (input, want) in [
            (&b""[..], ""),
            (b"f", "Zg=="),
            (b"fo", "Zm8="),
            (b"foo", "Zm9v"),
            (b"foob", "Zm9vYg=="),
            (b"fooba", "Zm9vYmE="),
            (b"foobar", "Zm9vYmFy"),
        ] {
            assert_eq!(base64_encode(input), want);
            assert_eq!(base64_decode(want).unwrap(), input);
        }
        assert_eq!(base64_decode("Zm9v!"), None);
    }

    #[test]
    fn generation_is_deterministic() {
        for k in CanaryKind::ALL {
            let a = generate(k, "dcy-demo-1", 3, &bytes(5), T0);
            let b = generate(k, "dcy-demo-1", 3, &bytes(5), T0);
            assert_eq!(a, b);
            let other = generate(k, "dcy-demo-1", 3, &bytes(6), T0);
            assert_ne!(a.value, other.value);
            assert_ne!(a.id, other.id);
        }
    }

    #[test]
    fn same_bytes_give_distinct_values_per_generation_decoy_and_kind() {
        let rng = bytes(9);
        let mut values = Vec::new();
        let mut ids = Vec::new();
        for k in CanaryKind::ALL {
            for decoy in ["dcy-demo-1", "dcy-demo-2"] {
                for generation in [1, 2, 3] {
                    let c = generate(k, decoy, generation, &rng, T0);
                    values.push(c.value);
                    ids.push(c.id);
                }
            }
        }
        let n = values.len();
        values.sort();
        values.dedup();
        ids.sort();
        ids.dedup();
        assert_eq!(values.len(), n);
        assert_eq!(ids.len(), n);
    }

    #[test]
    fn debug_never_prints_the_value() {
        for c in all_for("dcy-demo-1", 3) {
            let dbg = format!("{c:?}");
            assert!(dbg.contains("<redacted>"));
            for needle in c.needles() {
                assert!(!dbg.contains(&needle), "{dbg}");
            }
        }
    }

    #[test]
    fn index_holds_no_full_value() {
        let canaries = all_for("dcy-demo-1", 3);
        let mut index = CanaryIndex::new();
        for c in &canaries {
            index.insert(c);
            index.insert(c);
        }
        // api 1, db 1, cloud 2, ssh 2, admin 1.
        assert_eq!(index.len(), 7);
        let json = serde_json::to_string(&index).unwrap();
        for c in &canaries {
            for needle in c.needles() {
                assert!(!json.contains(&needle));
            }
        }
        let back: CanaryIndex = serde_json::from_str(&json).unwrap();
        assert_eq!(back, index);
    }

    #[test]
    fn scan_finds_api_key_in_http_request() {
        let c = mint(CanaryKind::ApiKey);
        let mut index = CanaryIndex::new();
        index.insert(&c);
        let head = "GET /v1/users HTTP/1.1\r\nHost: api.example.net\r\nAuthorization: Bearer ";
        let req = format!("{head}{}\r\nUser-Agent: curl/8.5.0\r\n\r\n", c.value);
        let hits = index.scan(req.as_bytes());
        assert_eq!(
            hits,
            vec![CanaryHit {
                canary_id: c.id.clone(),
                decoy_id: "dcy-demo-1".into(),
                generation: 3,
                kind: CanaryKind::ApiKey,
                offset: head.len(),
            }]
        );
    }

    #[test]
    fn scan_finds_each_kind_in_a_request_body() {
        let canaries = all_for("dcy-demo-1", 3);
        let mut index = CanaryIndex::new();
        for c in &canaries {
            index.insert(c);
        }
        // An exfil POST carrying the whole .env plus the SSH key.
        let body = format!(
            "{}\n{}",
            render_env_file(&canaries, None),
            canaries[3].value
        );
        let req = format!("POST /upload HTTP/1.1\r\nHost: 192.0.2.80\r\n\r\n{body}");
        let hits = index.scan(req.as_bytes());
        for c in &canaries {
            assert!(
                hits.iter().any(|h| h.canary_id == c.id && h.kind == c.kind),
                "{:?} not found",
                c.kind
            );
        }
        let offsets: Vec<_> = hits.iter().map(|h| h.offset).collect();
        let mut sorted = offsets.clone();
        sorted.sort();
        assert_eq!(offsets, sorted);
    }

    #[test]
    fn scan_finds_cloud_key_in_sigv4_header_and_db_password_alone() {
        let cloud = mint(CanaryKind::CloudAccessKey);
        let db = mint(CanaryKind::DatabaseUrl);
        let mut index = CanaryIndex::new();
        index.insert(&cloud);
        index.insert(&db);
        let (id, _) = cloud.cloud_key_pair().unwrap();
        let req = format!(
            "POST / HTTP/1.1\r\nAuthorization: AWS4-HMAC-SHA256 Credential={id}/20261018/us-east-1/sts/aws4_request, SignedHeaders=host;x-amz-date, Signature=00\r\n\r\nAction=GetCallerIdentity"
        );
        let hits = index.scan(req.as_bytes());
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].kind, CanaryKind::CloudAccessKey);

        let psql = format!(
            "PGPASSWORD={} psql -h 198.51.100.7 -U admin",
            db.db_password().unwrap()
        );
        let hits = index.scan(psql.as_bytes());
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].canary_id, db.id);
        assert_eq!(hits[0].offset, "PGPASSWORD=".len());
    }

    #[test]
    fn scan_has_no_false_hits_on_similar_strings() {
        let canaries = all_for("dcy-demo-1", 3);
        let mut index = CanaryIndex::new();
        for c in &canaries {
            index.insert(c);
        }
        let api = &canaries[0].value;
        let mut flipped = api.clone().into_bytes();
        let last = flipped.len() - 1;
        flipped[last] = if flipped[last] == b'0' { b'1' } else { b'0' };
        let near_misses = [
            String::from_utf8(flipped).unwrap(),
            api[..api.len() - 1].to_string(),
            api.to_uppercase(),
            // Same kinds, other decoy or other generation.
            generate(CanaryKind::ApiKey, "dcy-demo-2", 3, &bytes(10), T0).value,
            generate(CanaryKind::ApiKey, "dcy-demo-1", 4, &bytes(10), T0).value,
            generate(CanaryKind::AdminPassword, "dcy-demo-1", 3, &bytes(99), T0).value,
            "vt-canary-ak-00000000000000000000000000000000".into(),
            "VTCANARYAAAAAAAAAAAA".into(),
            "postgres://vt_canary_00000000:000000000000000000000000@db.internal.invalid:5432/app"
                .into(),
            "vt-canary-".repeat(10),
        ];
        for s in near_misses {
            let hits = index.scan(format!("Authorization: Bearer {s}\r\n").as_bytes());
            assert!(hits.is_empty(), "{s}: {hits:?}");
        }
        assert!(index.scan(b"").is_empty());
        assert!(index.scan(b"vt-canar").is_empty());
    }

    #[test]
    fn render_env_file_lists_env_kinds_and_skips_ssh() {
        let canaries = all_for("dcy-demo-1", 3);
        let env = render_env_file(&canaries, Some("https://beacon.example.net/"));
        let (id, secret) = canaries[2].cloud_key_pair().unwrap();
        let want = [
            format!(
                "API_BASE_URL=https://beacon.example.net/c/{}",
                canaries[0].id
            ),
            format!("API_KEY={}", canaries[0].value),
            format!("DATABASE_URL={}", canaries[1].value),
            format!("AWS_ACCESS_KEY_ID={id}"),
            format!("AWS_SECRET_ACCESS_KEY={secret}"),
            format!(
                "AWS_ENDPOINT_URL=https://beacon.example.net/c/{}",
                canaries[2].id
            ),
            format!("ADMIN_PASSWORD={}", canaries[4].value),
        ];
        for line in &want {
            assert!(env.lines().any(|l| l == line), "missing {line}\n{env}");
        }
        assert!(!env.contains("OPENSSH"));
        assert!(env.ends_with('\n'));

        let plain = render_env_file(&canaries[..1], None);
        assert_eq!(
            plain,
            format!(
                "APP_ENV=production\nLOG_LEVEL=info\nAPI_KEY={}\n",
                canaries[0].value
            )
        );

        let two = [
            mint(CanaryKind::ApiKey),
            generate(CanaryKind::ApiKey, "dcy-demo-1", 3, &bytes(2), T0),
        ];
        let env = render_env_file(&two, None);
        assert!(env.contains(&format!("\nAPI_KEY={}\n", two[0].value)));
        assert!(env.contains(&format!("\nAPI_KEY_2={}\n", two[1].value)));
    }

    #[test]
    fn hit_capture_data_carries_ids_not_values() {
        let c = mint(CanaryKind::ApiKey);
        let hit = CanaryHit {
            canary_id: c.id.clone(),
            decoy_id: c.decoy_id.clone(),
            generation: 3,
            kind: c.kind,
            offset: 0,
        };
        let data = hit.capture_data("beacon");
        assert_eq!(data["detector"], "beacon");
        assert_eq!(data["canary_id"], c.id.as_str());
        assert_eq!(data["canary_kind"], "api_key");
        assert_eq!(data["canary_generation"], 3);
        assert!(!Value::Object(data).to_string().contains(&c.value));
    }

    /// Tabletop from docs/canaries.md: the attacker exfiltrates `.env` from
    /// the demo app, then uses the API key against the API base URL it names,
    /// which is the beacon listener. The listener sees the request, matches
    /// the canary and raises a critical `canary_used` event naming the decoy.
    #[test]
    fn tabletop_exfil_env_then_use_key_at_beacon() {
        // Control plane mints canaries for the demo app's slot at create.
        let decoy = "dcy-demo-1";
        let api = generate(CanaryKind::ApiKey, decoy, 3, &bytes(42), T0);
        let db = generate(CanaryKind::DatabaseUrl, decoy, 3, &bytes(43), T0);
        let mut index = CanaryIndex::new();
        index.insert(&api);
        index.insert(&db);

        // Host agent plants /srv/demo-app/.env in the guest.
        let env = render_env_file(&[api.clone(), db], Some("https://beacon.example.net"));

        // Attacker reads the file through the path traversal bug and takes
        // it home. Everything below uses only what was in the file.
        let get = |name: &str| {
            env.lines()
                .find_map(|l| l.strip_prefix(&format!("{name}=")))
                .unwrap()
                .to_string()
        };
        let base = get("API_BASE_URL");
        let key = get("API_KEY");
        let path = format!(
            "{}/v1/users",
            base.strip_prefix("https://beacon.example.net").unwrap()
        );
        let request = format!(
            "GET {path} HTTP/1.1\r\nHost: beacon.example.net\r\nAuthorization: Bearer {key}\r\nUser-Agent: python-requests/2.32\r\n\r\n"
        );

        // Beacon listener: path token id and request bytes both match.
        let token = path.strip_prefix("/c/").unwrap().split('/').next().unwrap();
        let by_path = index.by_id(token).unwrap();
        assert_eq!(by_path.decoy_id, decoy);
        let hits = index.scan(request.as_bytes());
        assert_eq!(hits.len(), 1);
        let hit = &hits[0];
        assert_eq!(hit.canary_id, api.id);
        assert_eq!(hit.decoy_id, decoy);
        assert_eq!(hit.kind, CanaryKind::ApiKey);

        // The listener reports an egress-channel envelope at critical.
        let mut data = hit.capture_data("beacon");
        data.insert("method".into(), "GET".into());
        data.insert("path".into(), path.clone().into());
        let event = CaptureEvent {
            event_id: "evt-canary-1".into(),
            ts: T0 + 3_600_000,
            decoy_id: hit.decoy_id.clone(),
            catalogue_id: "foiled/demo-app/1.0.0".into(),
            decoy_kind: DecoyKind::Sandbox,
            generation: Some(hit.generation),
            channel: Channel::Egress,
            severity: Severity::Critical,
            src: Endpoint {
                ip: "203.0.113.45".into(),
                port: Some(51522),
            },
            dst: None,
            payload_ref: None,
            attempt_id: None,
            source: None,
            tenant_id: None,
            hook: None,
            data,
        };
        assert!(event.problems(T0 + 7_200_000).is_empty());
        assert_eq!(event.decoy_id, "dcy-demo-1");
        assert!(!serde_json::to_string(&event).unwrap().contains(&key));
        // canary_used is a compromise signal: freeze, then rotate.
        assert!(ReasonCode::CanaryUsed.indicates_compromise());
    }
}
