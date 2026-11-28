//! Read-only check that a decoy network cannot open outbound connections
//! (#93). Pure parsing and evaluation only: the caller runs the commands
//! (`docker network inspect`, `iptables -S`, `ip6tables -S` or
//! `nft -j list ruleset`) and hands over their output. hostd never edits
//! firewall rules.
//!
//! Both firewall listings are reduced to one small rule model and walked
//! the way the kernel would for a new connection from the decoy subnet:
//! from the forward hook, in order, following jumps. The check passes only
//! if a deny rule that covers the whole subnet is reached before anything
//! that could let some of that traffic through (an `ACCEPT`, a `RETURN` out
//! of the top chain, an unknown target). It is deliberately conservative: a
//! rule it does not understand never counts as a deny, and always counts as
//! a possible accept.

use std::collections::BTreeMap;
use std::net::IpAddr;

use serde::Deserialize;

/// An IPv4 or IPv6 prefix. Addresses are stored left-aligned in a `u128`
/// so one mask works for both families.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cidr {
    v6: bool,
    addr: u128,
    len: u8,
}

fn mask(len: u8) -> u128 {
    if len == 0 {
        0
    } else {
        u128::MAX << (128 - u32::from(len))
    }
}

impl Cidr {
    /// `10.86.0.0/24`, `fd00::/64`, or a bare address (a host prefix).
    pub fn parse(s: &str) -> Option<Cidr> {
        let (ip, len) = match s.split_once('/') {
            Some((ip, len)) => (ip, Some(len.parse::<u8>().ok()?)),
            None => (s, None),
        };
        let (v6, addr, max) = match ip.parse::<IpAddr>().ok()? {
            IpAddr::V4(a) => (false, u128::from(u32::from(a)) << 96, 32),
            IpAddr::V6(a) => (true, u128::from(a), 128),
        };
        let len = len.unwrap_or(max);
        if len > max {
            return None;
        }
        Some(Cidr {
            v6,
            addr: addr & mask(len),
            len,
        })
    }

    pub fn is_v6(&self) -> bool {
        self.v6
    }

    /// True when every address in `other` is also in `self`.
    pub fn contains(&self, other: &Cidr) -> bool {
        self.v6 == other.v6 && self.len <= other.len && other.addr & mask(self.len) == self.addr
    }

    pub fn overlaps(&self, other: &Cidr) -> bool {
        self.contains(other) || other.contains(self)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// `DROP` or `REJECT`.
    Deny,
    Accept,
    Return,
    Jump(String),
    Goto(String),
    /// Logging, counters, marks: evaluation carries on.
    Continue,
    /// A terminating target this check does not model. Treated as a
    /// possible accept.
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AddrMatch {
    pub negated: bool,
    pub nets: Vec<Cidr>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IfaceMatch {
    pub negated: bool,
    pub names: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rule {
    /// The rule as listed, for messages.
    pub text: String,
    pub verdict: Verdict,
    pub src: Option<AddrMatch>,
    pub dst: Option<AddrMatch>,
    pub iif: Option<IfaceMatch>,
    pub oif: Option<IfaceMatch>,
    /// `Some(true)` when a conntrack state match includes NEW, `Some(false)`
    /// when it excludes it, `None` without a state match.
    pub ct_new: Option<bool>,
    /// Any other match (protocol, port, an unknown module or a named set). Narrows the rule in ways this check does not model.
    pub other: bool,
}

impl Rule {
    fn new(text: String) -> Self {
        Rule {
            text,
            verdict: Verdict::Continue,
            src: None,
            dst: None,
            iif: None,
            oif: None,
            ct_new: None,
            other: false,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Family {
    V4,
    V6,
    Both,
}

impl Family {
    fn carries(self, v6: bool) -> bool {
        match self {
            Family::V4 => !v6,
            Family::V6 => v6,
            Family::Both => true,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Chain {
    pub family: Family,
    /// A base chain whose default policy drops what falls off its end.
    pub policy_drop: bool,
    pub rules: Vec<Rule>,
}

/// Chains by name, plus the chains a forwarded packet starts in.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Ruleset {
    pub chains: BTreeMap<String, Chain>,
    pub entries: Vec<String>,
}

/// One decoy subnet and the bridge interface its traffic arrives on.
#[derive(Debug, Clone, Copy)]
pub struct Target<'a> {
    pub net: Cidr,
    pub bridge: &'a str,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Coverage {
    Covered,
    /// This rule can let new outbound connections through before any deny.
    Shadowed(String),
    /// Nothing denies them.
    Missing,
}

fn iface_matches(pattern: &str, name: &str) -> bool {
    match pattern
        .strip_suffix('+')
        .or_else(|| pattern.strip_suffix('*'))
    {
        Some(prefix) => name.starts_with(prefix),
        None => pattern == name,
    }
}

/// True when an interface selector names exactly the decoy bridge and no
/// other interface: no wildcard, and every listed name is the bridge.
fn only_bridge(m: &IfaceMatch, bridge: &str) -> bool {
    !m.names.is_empty()
        && m.names
            .iter()
            .all(|p| p == bridge && !p.ends_with(['+', '*']))
}

/// Could this rule match some new connection from the target subnet to an
/// address outside it?
fn may_match(r: &Rule, t: &Target) -> bool {
    if r.ct_new == Some(false) {
        return false;
    }
    if let Some(m) = &r.src {
        if m.negated {
            if m.nets.iter().any(|n| n.contains(&t.net)) {
                return false;
            }
        } else if !m.nets.iter().any(|n| n.overlaps(&t.net)) {
            return false;
        }
    }
    if let Some(m) = &r.iif {
        let hit = m.names.iter().any(|p| iface_matches(p, t.bridge));
        if hit == m.negated {
            return false;
        }
    }
    if let Some(m) = &r.oif
        && !m.negated
        && only_bridge(m, t.bridge)
    {
        // Leaving through the decoy bridge itself: not egress.
        return false;
    }
    if let Some(m) = &r.dst
        && !m.negated
        && m.nets.iter().all(|n| n.v6 != t.net.v6 || t.net.contains(n))
    {
        // Only destinations inside the decoy network: not egress.
        return false;
    }
    true
}

/// Does this rule's match take in every new connection from the subnet?
fn covers_all(r: &Rule, t: &Target) -> bool {
    if r.other || r.dst.is_some() || r.ct_new == Some(false) {
        return false;
    }
    let src_ok = match &r.src {
        None => true,
        Some(m) => !m.negated && m.nets.iter().any(|n| n.contains(&t.net)),
    };
    let iif_ok = match &r.iif {
        None => true,
        Some(m) => !m.negated && m.names.iter().any(|p| iface_matches(p, t.bridge)),
    };
    let oif_ok = match &r.oif {
        None => true,
        // `! -o <bridge>` is every connection that leaves the network. A
        // wildcard or a list would also exempt other interfaces.
        Some(m) => m.negated && only_bridge(m, t.bridge),
    };
    src_ok && iif_ok && oif_ok
}

enum Walk {
    Covered,
    Escaped(String),
    Returned(String),
    FellThrough,
}

const MAX_DEPTH: usize = 16;

fn walk(rs: &Ruleset, name: &str, t: &Target, depth: usize) -> Walk {
    let Some(chain) = rs.chains.get(name) else {
        return Walk::Escaped(format!("jump to unknown chain {name}"));
    };
    if depth > MAX_DEPTH {
        return Walk::Escaped(format!("chain {name} is nested too deeply to follow"));
    }
    // A RETURN (or a goto that comes back) taking only some of the traffic:
    // that part leaves this chain, the rest carries on here. Both must be
    // safe, so a later deny here proves nothing for the part that left.
    let mut partial: Option<String> = None;
    let leave = |text: &String, partial: Option<String>| -> Option<Walk> {
        Some(Walk::Returned(partial.unwrap_or_else(|| text.clone())))
    };
    for r in &chain.rules {
        if !may_match(r, t) {
            continue;
        }
        let full = covers_all(r, t);
        let out = match &r.verdict {
            Verdict::Continue => None,
            Verdict::Deny if full => Some(Walk::Covered),
            Verdict::Deny => None,
            Verdict::Accept | Verdict::Unknown => return Walk::Escaped(r.text.clone()),
            Verdict::Return if full => leave(&r.text, partial.take()),
            Verdict::Return => {
                partial.get_or_insert_with(|| r.text.clone());
                None
            }
            Verdict::Jump(to) | Verdict::Goto(to) => match walk(rs, to, t, depth + 1) {
                // Only the traffic the jump selects reached the deny.
                Walk::Covered if full => Some(Walk::Covered),
                Walk::Covered => None,
                Walk::Escaped(x) => return Walk::Escaped(x),
                // Falling off a goto target leaves this chain as well.
                Walk::Returned(_) | Walk::FellThrough if matches!(r.verdict, Verdict::Goto(_)) => {
                    if full {
                        leave(&r.text, partial.take())
                    } else {
                        partial.get_or_insert_with(|| r.text.clone());
                        None
                    }
                }
                Walk::Returned(_) | Walk::FellThrough => None,
            },
        };
        match (out, partial.take()) {
            (Some(Walk::Covered), Some(p)) => return Walk::Returned(p),
            (Some(w), _) => return w,
            (None, p) => partial = p,
        }
    }
    match partial {
        Some(p) => Walk::Returned(p),
        None => Walk::FellThrough,
    }
}

/// Is every new outbound connection from `t.net` denied?
pub fn evaluate(rs: &Ruleset, t: &Target) -> Coverage {
    let mut shadowed = None;
    let mut seen = false;
    for entry in &rs.entries {
        let Some(chain) = rs.chains.get(entry) else {
            continue;
        };
        if !chain.family.carries(t.net.v6) {
            continue;
        }
        seen = true;
        // A deny in any base chain is final, so one covering chain is enough.
        match walk(rs, entry, t, 0) {
            Walk::Covered => return Coverage::Covered,
            Walk::Returned(_) | Walk::FellThrough if chain.policy_drop => {
                return Coverage::Covered;
            }
            Walk::Escaped(x) | Walk::Returned(x) => {
                shadowed.get_or_insert(x);
            }
            Walk::FellThrough => {}
        }
    }
    match shadowed {
        Some(x) if seen => Coverage::Shadowed(x),
        _ => Coverage::Missing,
    }
}

/// Split one `iptables -S` line into words, honouring double quotes.
fn split_words(line: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut in_word = false;
    let mut quoted = false;
    let mut chars = line.chars();
    while let Some(c) = chars.next() {
        match c {
            '"' => {
                quoted = !quoted;
                in_word = true;
            }
            '\\' if quoted => {
                if let Some(n) = chars.next() {
                    cur.push(n);
                }
            }
            c if c.is_whitespace() && !quoted => {
                if in_word {
                    out.push(std::mem::take(&mut cur));
                    in_word = false;
                }
            }
            c => {
                cur.push(c);
                in_word = true;
            }
        }
    }
    if in_word {
        out.push(cur);
    }
    out
}

fn addr_match(value: &str, negated: bool) -> Option<AddrMatch> {
    let nets = value
        .split(',')
        .map(Cidr::parse)
        .collect::<Option<Vec<_>>>()?;
    Some(AddrMatch { negated, nets })
}

/// Conntrack states a new connection is either in or not. Anything else
/// (the virtual `DNAT` and `SNAT` states, a typo) is not modelled.
const PLAIN_STATES: &[&str] = &["new", "established", "related", "invalid", "untracked"];

/// `Some(includes NEW)` for a list of plain states, `None` otherwise.
fn ct_new(states: &[&str], negated: bool) -> Option<bool> {
    if states.is_empty()
        || !states
            .iter()
            .all(|s| PLAIN_STATES.contains(&s.to_ascii_lowercase().as_str()))
    {
        return None;
    }
    Some(states.iter().any(|s| s.eq_ignore_ascii_case("new")) != negated)
}

/// Targets that log, mark or trace and then carry on.
const NON_TERMINATING: &[&str] = &[
    "LOG", "NFLOG", "ULOG", "MARK", "CONNMARK", "TRACE", "AUDIT", "CT", "NOTRACK", "CLASSIFY",
    "DSCP", "TOS", "TCPMSS",
];

fn parse_iptables_rule(words: &[String], chains: &BTreeMap<String, Chain>, text: &str) -> Rule {
    let mut r = Rule::new(text.to_string());
    let mut neg = false;
    let mut i = 0;
    let value = |i: usize| words.get(i + 1).map(String::as_str).unwrap_or("");
    while i < words.len() {
        let w = words[i].as_str();
        if w == "!" {
            neg = true;
            i += 1;
            continue;
        }
        match w {
            "-s" | "--source" => {
                r.src = addr_match(value(i), neg);
                r.other |= r.src.is_none();
                i += 2;
            }
            "-d" | "--destination" => {
                r.dst = addr_match(value(i), neg);
                r.other |= r.dst.is_none();
                i += 2;
            }
            "-i" | "--in-interface" | "-o" | "--out-interface" => {
                let m = Some(IfaceMatch {
                    negated: neg,
                    names: vec![value(i).to_string()],
                });
                if w.starts_with("-i") || w == "--in-interface" {
                    r.iif = m;
                } else {
                    r.oif = m;
                }
                i += 2;
            }
            "-m" | "--match" => {
                if !matches!(value(i), "conntrack" | "state" | "comment") {
                    r.other = true;
                }
                i += 2;
            }
            "--ctstate" | "--state" => {
                let states: Vec<&str> = value(i).split(',').collect();
                // An unmodelled state narrows the rule in an unknown way.
                r.ct_new = ct_new(&states, neg);
                r.other |= r.ct_new.is_none();
                i += 2;
            }
            "--comment" => i += 2,
            "-j" | "--jump" | "-g" | "--goto" => {
                let to = value(i);
                r.verdict = match to {
                    "DROP" | "REJECT" => Verdict::Deny,
                    "ACCEPT" => Verdict::Accept,
                    "RETURN" => Verdict::Return,
                    _ if chains.contains_key(to) => {
                        if w.starts_with("-g") || w == "--goto" {
                            Verdict::Goto(to.to_string())
                        } else {
                            Verdict::Jump(to.to_string())
                        }
                    }
                    _ if NON_TERMINATING.contains(&to) => Verdict::Continue,
                    _ => Verdict::Unknown,
                };
                // What follows is target options (for example --reject-with).
                break;
            }
            _ => {
                // Protocol, ports, output interface, other modules' options.
                r.other = true;
                let takes_value = words
                    .get(i + 1)
                    .is_some_and(|n| !n.starts_with('-') && n != "!");
                i += if takes_value { 2 } else { 1 };
            }
        }
        neg = false;
    }
    r
}

/// Parse the whole filter table as printed by `iptables -S` or
/// `ip6tables -S`. Evaluation starts in `FORWARD`, so Docker's own chains
/// and any rule placed outside `DOCKER-USER` are taken into account.
pub fn parse_iptables(listing: &str, family: Family) -> Ruleset {
    let mut chains: BTreeMap<String, Chain> = BTreeMap::new();
    let lines: Vec<Vec<String>> = listing.lines().map(split_words).collect();
    let empty = |policy_drop| Chain {
        family,
        policy_drop,
        rules: Vec::new(),
    };
    for w in &lines {
        match (w.first().map(String::as_str), w.get(1)) {
            (Some("-P"), Some(name)) => {
                let drop = w.get(2).is_some_and(|p| p == "DROP");
                chains.entry(name.clone()).or_insert_with(|| empty(drop));
            }
            (Some("-N" | "-A"), Some(name)) => {
                chains.entry(name.clone()).or_insert_with(|| empty(false));
            }
            _ => {}
        }
    }
    for (line, w) in listing.lines().zip(&lines) {
        if let (Some("-A"), Some(name)) = (w.first().map(String::as_str), w.get(1)) {
            let rule = parse_iptables_rule(&w[2..], &chains, line.trim());
            if let Some(c) = chains.get_mut(name) {
                c.rules.push(rule);
            }
        }
    }
    Ruleset {
        chains,
        entries: vec!["FORWARD".into()],
    }
}

fn nft_addrs(v: &serde_json::Value, out: &mut Vec<Cidr>) -> bool {
    use serde_json::Value;
    match v {
        Value::String(s) => Cidr::parse(s).map(|c| out.push(c)).is_some(),
        Value::Object(o) if o.contains_key("prefix") => {
            let p = &o["prefix"];
            let len = p["len"].as_u64().and_then(|l| u8::try_from(l).ok());
            match (p["addr"].as_str(), len) {
                (Some(a), Some(l)) => Cidr::parse(&format!("{a}/{l}"))
                    .map(|c| out.push(c))
                    .is_some(),
                _ => false,
            }
        }
        Value::Object(o) if o.contains_key("set") => nft_addrs(&o["set"], out),
        Value::Array(a) => a.iter().all(|e| nft_addrs(e, out)),
        _ => false,
    }
}

fn nft_words(v: &serde_json::Value, out: &mut Vec<String>) -> bool {
    use serde_json::Value;
    match v {
        // `@name` is a named set whose members are not read here.
        Value::String(s) if s.starts_with('@') => false,
        Value::String(s) => {
            out.push(s.clone());
            true
        }
        Value::Object(o) if o.contains_key("set") => nft_words(&o["set"], out),
        Value::Array(a) => a.iter().all(|e| nft_words(e, out)),
        _ => false,
    }
}

/// Keep the first of several matches on one field. Each further match
/// narrows the rule again, so it can no longer be shown to cover the whole
/// subnet; the first one is still a sound test of whether it can match.
fn set_once<T>(slot: &mut Option<T>, v: T, other: &mut bool) {
    if slot.is_some() {
        *other = true;
    } else {
        *slot = Some(v);
    }
}

fn parse_nft_rule(exprs: &[serde_json::Value], text: String, table_key: &str) -> Rule {
    let mut r = Rule::new(text);
    // A copy of the packet already left, whatever the rule does next.
    let mut escapes = false;
    for e in exprs {
        let Some((kind, body)) = e.as_object().and_then(|o| o.iter().next()) else {
            r.other = true;
            continue;
        };
        match kind.as_str() {
            "match" => {
                // Only equality, membership and their negation are modelled.
                // A relational operator (`<`, `>=`, ...) selects a range, so
                // it can neither rule an accept out nor prove a deny.
                let negated = match body["op"].as_str() {
                    Some("==" | "in") => false,
                    Some("!=") => true,
                    _ => {
                        r.other = true;
                        continue;
                    }
                };
                let left = &body["left"];
                let right = &body["right"];
                let field = left["payload"]["field"].as_str();
                if left["payload"]["protocol"].is_string()
                    && matches!(field, Some("saddr" | "daddr"))
                {
                    let mut nets = Vec::new();
                    if nft_addrs(right, &mut nets) {
                        let m = AddrMatch { negated, nets };
                        if field == Some("saddr") {
                            set_once(&mut r.src, m, &mut r.other);
                        } else {
                            set_once(&mut r.dst, m, &mut r.other);
                        }
                    } else {
                        r.other = true;
                    }
                } else if let Some(key @ ("iifname" | "oifname")) = left["meta"]["key"].as_str() {
                    let mut names = Vec::new();
                    if nft_words(right, &mut names) {
                        let m = IfaceMatch { negated, names };
                        if key == "iifname" {
                            set_once(&mut r.iif, m, &mut r.other);
                        } else {
                            set_once(&mut r.oif, m, &mut r.other);
                        }
                    } else {
                        r.other = true;
                    }
                } else if left["ct"]["key"].as_str() == Some("state") {
                    let mut states = Vec::new();
                    if nft_words(right, &mut states) {
                        let states: Vec<&str> = states.iter().map(String::as_str).collect();
                        match ct_new(&states, negated) {
                            Some(v) => set_once(&mut r.ct_new, v, &mut r.other),
                            None => r.other = true,
                        }
                    } else {
                        r.other = true;
                    }
                } else {
                    r.other = true;
                }
            }
            "accept" => r.verdict = Verdict::Accept,
            "drop" | "reject" => r.verdict = Verdict::Deny,
            "return" => r.verdict = Verdict::Return,
            "jump" | "goto" => {
                let to = body["target"].as_str().unwrap_or_default();
                let key = format!("{table_key} {to}");
                r.verdict = if kind == "jump" {
                    Verdict::Jump(key)
                } else {
                    Verdict::Goto(key)
                };
            }
            "counter" | "log" => {}
            "xt" if body["type"].as_str() == Some("target") => r.verdict = Verdict::Unknown,
            // A verdict map can accept some traffic; its entries are not read.
            "queue" | "vmap" => r.verdict = Verdict::Unknown,
            // `dup` and `fwd` send the packet, or a copy of it, elsewhere.
            "dup" | "fwd" => escapes = true,
            _ => r.other = true,
        }
    }
    if escapes {
        r.verdict = Verdict::Unknown;
    }
    r
}

/// Parse `nft -j list ruleset`. Every filter chain on the forward hook in
/// the `ip`, `ip6` or `inet` family is an entry. Rules written by
/// `iptables-nft` show up as opaque `xt` expressions, so on a host where
/// Docker manages iptables, check with `iptables` instead.
pub fn parse_nft(json: &str) -> Result<Ruleset, String> {
    let v: serde_json::Value =
        serde_json::from_str(json).map_err(|e| format!("nft JSON output: {e}"))?;
    let items = v["nftables"]
        .as_array()
        .ok_or("nft JSON output has no nftables array")?;
    let mut rs = Ruleset::default();
    let table_key = |o: &serde_json::Value| {
        format!(
            "{} {}",
            o["family"].as_str().unwrap_or_default(),
            o["table"].as_str().unwrap_or_default()
        )
    };
    // The kernel does not evaluate the chains of a dormant table.
    let mut dormant = std::collections::BTreeSet::new();
    for item in items {
        let tb = &item["table"];
        let mut flags = Vec::new();
        if tb.is_object()
            && nft_words(&tb["flags"], &mut flags)
            && flags.iter().any(|f| f == "dormant")
        {
            dormant.insert(format!(
                "{} {}",
                tb["family"].as_str().unwrap_or_default(),
                tb["name"].as_str().unwrap_or_default()
            ));
        }
    }
    for item in items {
        let c = &item["chain"];
        if !c.is_object() || dormant.contains(&table_key(c)) {
            continue;
        }
        let family = match c["family"].as_str() {
            Some("ip") => Family::V4,
            Some("ip6") => Family::V6,
            Some("inet") => Family::Both,
            _ => continue,
        };
        let key = format!(
            "{} {}",
            table_key(c),
            c["name"].as_str().unwrap_or_default()
        );
        if c["hook"].as_str() == Some("forward") && c["type"].as_str() == Some("filter") {
            rs.entries.push(key.clone());
        }
        rs.chains.insert(
            key,
            Chain {
                family,
                policy_drop: c["policy"].as_str() == Some("drop"),
                rules: Vec::new(),
            },
        );
    }
    for item in items {
        let r = &item["rule"];
        if !r.is_object() {
            continue;
        }
        let tk = table_key(r);
        let key = format!("{tk} {}", r["chain"].as_str().unwrap_or_default());
        let text = format!("nft rule {key} handle {}", r["handle"]);
        let exprs = r["expr"].as_array().map(Vec::as_slice).unwrap_or_default();
        let rule = parse_nft_rule(exprs, text, &tk);
        if let Some(c) = rs.chains.get_mut(&key) {
            c.rules.push(rule);
        }
    }
    Ok(rs)
}

/// What hostd needs from `docker network inspect`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkInfo {
    /// Full network ID, so the launch attaches to the network that was checked.
    pub id: String,
    pub driver: String,
    /// Host-side bridge interface, for rules that match on `-i`.
    pub bridge: String,
    pub subnets: Vec<(String, Cidr)>,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct InspectNet {
    #[serde(default)]
    id: String,
    #[serde(default)]
    driver: String,
    #[serde(rename = "IPAM", default)]
    ipam: Option<InspectIpam>,
    #[serde(default)]
    options: Option<BTreeMap<String, String>>,
}

#[derive(Deserialize)]
struct InspectIpam {
    #[serde(rename = "Config", default)]
    config: Option<Vec<InspectPool>>,
}

#[derive(Deserialize)]
struct InspectPool {
    #[serde(rename = "Subnet", default)]
    subnet: String,
}

/// Parse `docker network inspect <name>` (a JSON array of one network).
pub fn parse_network_inspect(json: &str) -> Result<NetworkInfo, String> {
    let nets: Vec<InspectNet> =
        serde_json::from_str(json).map_err(|e| format!("docker network inspect output: {e}"))?;
    let [n] = <[InspectNet; 1]>::try_from(nets)
        .map_err(|v| format!("docker network inspect returned {} networks", v.len()))?;
    let bridge = n
        .options
        .as_ref()
        .and_then(|o| o.get("com.docker.network.bridge.name"))
        .cloned()
        .unwrap_or_else(|| format!("br-{}", n.id.get(..12).unwrap_or(&n.id)));
    let mut subnets = Vec::new();
    for p in n.ipam.and_then(|i| i.config).unwrap_or_default() {
        let c =
            Cidr::parse(&p.subnet).ok_or_else(|| format!("unreadable subnet {:?}", p.subnet))?;
        subnets.push((p.subnet, c));
    }
    Ok(NetworkInfo {
        id: n.id,
        driver: n.driver,
        bridge,
        subnets,
    })
}

/// The network must be a bridge with at least one subnet, and with exactly
/// the configured subnets when any are configured.
pub fn check_network(name: &str, info: &NetworkInfo, expected: &[String]) -> Result<(), String> {
    if info.driver != "bridge" {
        return Err(format!(
            "decoy network {name} uses the {} driver, not bridge",
            info.driver
        ));
    }
    if info.subnets.is_empty() {
        return Err(format!("decoy network {name} has no subnet"));
    }
    if !expected.is_empty() {
        let mut want = expected
            .iter()
            .map(|s| Cidr::parse(s).ok_or_else(|| format!("configured subnet {s:?} is not a CIDR")))
            .collect::<Result<Vec<_>, _>>()?;
        let mut have: Vec<Cidr> = info.subnets.iter().map(|(_, c)| *c).collect();
        let key = |c: &Cidr| (c.v6, c.addr, c.len);
        want.sort_by_key(key);
        have.sort_by_key(key);
        if want != have {
            let have: Vec<&str> = info.subnets.iter().map(|(s, _)| s.as_str()).collect();
            return Err(format!(
                "decoy network {name} has subnets {have:?}, expected {expected:?}"
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const BR: &str = "br-0123456789ab";

    fn t(net: &str) -> Target<'static> {
        Target {
            net: Cidr::parse(net).unwrap(),
            bridge: BR,
        }
    }

    fn v4(listing: &str) -> Ruleset {
        parse_iptables(listing, Family::V4)
    }

    /// Docker 28 filter table for one user network, without any operator rule.
    const DOCKER28: &str = r#"-P INPUT ACCEPT
-P FORWARD DROP
-P OUTPUT ACCEPT
-N DOCKER
-N DOCKER-BRIDGE
-N DOCKER-CT
-N DOCKER-FORWARD
-N DOCKER-ISOLATION-STAGE-1
-N DOCKER-ISOLATION-STAGE-2
-N DOCKER-USER
-A FORWARD -j DOCKER-USER
-A FORWARD -j DOCKER-FORWARD
-A DOCKER ! -i br-0123456789ab -o br-0123456789ab -j DROP
-A DOCKER-BRIDGE -o br-0123456789ab -j DOCKER
-A DOCKER-CT -o br-0123456789ab -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
-A DOCKER-FORWARD -j DOCKER-CT
-A DOCKER-FORWARD -j DOCKER-ISOLATION-STAGE-1
-A DOCKER-FORWARD -j DOCKER-BRIDGE
-A DOCKER-FORWARD -i br-0123456789ab -j ACCEPT
-A DOCKER-ISOLATION-STAGE-1 -i br-0123456789ab ! -o br-0123456789ab -j DOCKER-ISOLATION-STAGE-2
-A DOCKER-ISOLATION-STAGE-2 -o br-0123456789ab -j DROP
"#;

    /// Docker before 28: rules straight in FORWARD and a trailing RETURN.
    const DOCKER27: &str = r#"-P INPUT ACCEPT
-P FORWARD DROP
-P OUTPUT ACCEPT
-N DOCKER
-N DOCKER-ISOLATION-STAGE-1
-N DOCKER-ISOLATION-STAGE-2
-N DOCKER-USER
-A FORWARD -j DOCKER-USER
-A FORWARD -j DOCKER-ISOLATION-STAGE-1
-A FORWARD -o br-0123456789ab -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
-A FORWARD -o br-0123456789ab -j DOCKER
-A FORWARD -i br-0123456789ab ! -o br-0123456789ab -j ACCEPT
-A FORWARD -i br-0123456789ab -o br-0123456789ab -j ACCEPT
-A DOCKER-ISOLATION-STAGE-1 -i br-0123456789ab ! -o br-0123456789ab -j DOCKER-ISOLATION-STAGE-2
-A DOCKER-ISOLATION-STAGE-1 -j RETURN
-A DOCKER-ISOLATION-STAGE-2 -o br-0123456789ab -j DROP
-A DOCKER-ISOLATION-STAGE-2 -j RETURN
-A DOCKER-USER -j RETURN
"#;

    const LAB_RULE: &str = "-A DOCKER-USER -s 10.86.0.0/24 -m conntrack --ctstate NEW -j REJECT --reject-with icmp-port-unreachable";

    fn with(base: &str, extra: &[&str]) -> String {
        let mut s = base.to_string();
        for l in extra {
            s.push_str(l);
            s.push('\n');
        }
        s
    }

    /// `iptables -I` puts a rule first in its chain.
    fn inserted(base: &str, rule: &str) -> String {
        let chain = split_words(rule)[1].clone();
        let anchor = format!("-A {chain} ");
        match base.find(&anchor) {
            Some(i) => format!("{}{rule}\n{}", &base[..i], &base[i..]),
            None => with(base, &[rule]),
        }
    }

    #[test]
    fn cidr_containment() {
        let lab = Cidr::parse("10.86.0.0/24").unwrap();
        assert!(Cidr::parse("10.0.0.0/8").unwrap().contains(&lab));
        assert!(Cidr::parse("0.0.0.0/0").unwrap().contains(&lab));
        assert!(!Cidr::parse("10.86.0.0/25").unwrap().contains(&lab));
        assert!(Cidr::parse("10.86.0.0/25").unwrap().overlaps(&lab));
        assert!(!Cidr::parse("10.87.0.0/24").unwrap().overlaps(&lab));
        assert_eq!(Cidr::parse("10.86.0.7/24"), Some(lab), "host bits masked");
        assert!(lab.contains(&Cidr::parse("10.86.0.9").unwrap()));
        let v6 = Cidr::parse("fd00:86::/64").unwrap();
        assert!(v6.is_v6());
        assert!(Cidr::parse("::/0").unwrap().contains(&v6));
        assert!(
            !Cidr::parse("0.0.0.0/0").unwrap().overlaps(&v6),
            "families never mix"
        );
        assert!(Cidr::parse("10.0.0.0/33").is_none());
        assert!(Cidr::parse("not-an-ip").is_none());
    }

    #[test]
    fn iptables_rule_in_docker_user_covers_the_subnet() {
        for base in [DOCKER28, DOCKER27] {
            let rs = v4(&inserted(base, LAB_RULE));
            assert_eq!(evaluate(&rs, &t("10.86.0.0/24")), Coverage::Covered);
        }
    }

    #[test]
    fn missing_rule_is_reported_with_the_rule_that_lets_traffic_out() {
        let rs = v4(DOCKER28);
        assert_eq!(
            evaluate(&rs, &t("10.86.0.0/24")),
            Coverage::Shadowed("-A DOCKER-FORWARD -i br-0123456789ab -j ACCEPT".into())
        );
        let rs = v4(DOCKER27);
        assert_eq!(
            evaluate(&rs, &t("10.86.0.0/24")),
            Coverage::Shadowed(
                "-A FORWARD -i br-0123456789ab ! -o br-0123456789ab -j ACCEPT".into()
            )
        );
    }

    #[test]
    fn an_empty_permissive_table_is_missing() {
        let rs = v4("-P INPUT ACCEPT\n-P FORWARD ACCEPT\n-P OUTPUT ACCEPT\n");
        assert_eq!(evaluate(&rs, &t("10.86.0.0/24")), Coverage::Missing);
    }

    #[test]
    fn a_rule_for_another_or_a_narrower_subnet_does_not_count() {
        for rule in [
            "-A DOCKER-USER -s 10.87.0.0/24 -m conntrack --ctstate NEW -j REJECT",
            "-A DOCKER-USER -s 10.86.0.0/25 -m conntrack --ctstate NEW -j REJECT",
            "-A DOCKER-USER ! -s 10.86.0.0/24 -j DROP",
        ] {
            let rs = v4(&inserted(DOCKER28, rule));
            assert!(
                matches!(evaluate(&rs, &t("10.86.0.0/24")), Coverage::Shadowed(_)),
                "{rule}"
            );
        }
    }

    #[test]
    fn broader_drop_and_bridge_interface_rules_count() {
        for rule in [
            "-A DOCKER-USER -s 10.0.0.0/8 -j DROP",
            "-A DOCKER-USER -i br-0123456789ab -m conntrack --ctstate NEW -j REJECT",
            "-A DOCKER-USER -i br-+ -m state --state NEW,INVALID -j DROP",
            "-A DOCKER-USER -i br-0123456789ab ! -o br-0123456789ab -j DROP",
            r#"-A DOCKER-USER -s 10.86.0.0/24 -m comment --comment "foiled decoy \"egress\"" -m conntrack --ctstate NEW -j REJECT"#,
        ] {
            let rs = v4(&inserted(DOCKER28, rule));
            assert_eq!(
                evaluate(&rs, &t("10.86.0.0/24")),
                Coverage::Covered,
                "{rule}"
            );
        }
    }

    #[test]
    fn a_partial_deny_does_not_count() {
        // Only port 80, only to one destination, only out of one interface,
        // or only established traffic: other connections still get out.
        for rule in [
            "-A DOCKER-USER -s 10.86.0.0/24 -p tcp -m tcp --dport 80 -j REJECT",
            "-A DOCKER-USER -s 10.86.0.0/24 -d 203.0.113.0/24 -j DROP",
            "-A DOCKER-USER -s 10.86.0.0/24 -o eth0 -j DROP",
            "-A DOCKER-USER -s 10.86.0.0/24 -o br-0123456789ab -j DROP",
            "-A DOCKER-USER -s 10.86.0.0/24 -m conntrack --ctstate ESTABLISHED -j DROP",
            "-A DOCKER-USER -s 10.86.0.0/24 -m conntrack ! --ctstate NEW -j DROP",
        ] {
            let rs = v4(&inserted(DOCKER28, rule));
            assert!(
                matches!(evaluate(&rs, &t("10.86.0.0/24")), Coverage::Shadowed(_)),
                "{rule}"
            );
        }
    }

    #[test]
    fn accept_or_return_before_the_reject_shadows_it() {
        let accept_dns = "-A DOCKER-USER -s 10.86.0.0/24 -p udp -m udp --dport 53 -j ACCEPT";
        let listing = inserted(&inserted(DOCKER28, LAB_RULE), accept_dns);
        assert_eq!(
            evaluate(&v4(&listing), &t("10.86.0.0/24")),
            Coverage::Shadowed(accept_dns.into())
        );
        // `iptables -A` on Docker 27 lands after the trailing RETURN.
        let appended = with(DOCKER27, &[LAB_RULE]);
        assert!(matches!(
            evaluate(&v4(&appended), &t("10.86.0.0/24")),
            Coverage::Shadowed(_)
        ));
        let unknown = "-A DOCKER-USER -s 10.86.0.0/24 -j NFQUEUE --queue-num 1";
        let listing = inserted(&inserted(DOCKER28, LAB_RULE), unknown);
        assert_eq!(
            evaluate(&v4(&listing), &t("10.86.0.0/24")),
            Coverage::Shadowed(unknown.into())
        );
    }

    #[test]
    fn harmless_rules_before_the_reject_do_not_shadow_it() {
        for earlier in [
            // Replies to inbound connections.
            "-A DOCKER-USER -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT",
            // Traffic that stays inside the decoy network, or comes into it.
            "-A DOCKER-USER -s 10.86.0.0/24 -d 10.86.0.0/24 -j ACCEPT",
            "-A DOCKER-USER -i br-0123456789ab -o br-0123456789ab -j ACCEPT",
            "-A DOCKER-USER -o br-0123456789ab -p tcp -m tcp --dport 8080 -j ACCEPT",
            // Other networks and other bridges.
            "-A DOCKER-USER -s 172.17.0.0/16 -j ACCEPT",
            "-A DOCKER-USER -i docker0 -j ACCEPT",
            "-A DOCKER-USER ! -i br-0123456789ab -j RETURN",
            // Logging carries on.
            "-A DOCKER-USER -s 10.86.0.0/24 -j LOG --log-prefix \"foiled egress \"",
        ] {
            let listing = inserted(&inserted(DOCKER28, LAB_RULE), earlier);
            assert_eq!(
                evaluate(&v4(&listing), &t("10.86.0.0/24")),
                Coverage::Covered,
                "{earlier}"
            );
        }
    }

    #[test]
    fn jumps_into_operator_chains_are_followed() {
        let listing = inserted(
            &with(
                &DOCKER28.replace("-N DOCKER-USER\n", "-N DOCKER-USER\n-N FOILED\n"),
                &["-A FOILED -s 10.86.0.0/24 -m conntrack --ctstate NEW -j REJECT"],
            ),
            "-A DOCKER-USER -j FOILED",
        );
        assert_eq!(
            evaluate(&v4(&listing), &t("10.86.0.0/24")),
            Coverage::Covered
        );
        // A RETURN in the operator chain falls back to DOCKER-USER, then out.
        let listing = listing.replace("-A FOILED -s", "-A FOILED -j RETURN\n-A FOILED -s");
        assert!(matches!(
            evaluate(&v4(&listing), &t("10.86.0.0/24")),
            Coverage::Shadowed(_)
        ));
        // A jump that only selects some traffic does not cover the subnet.
        let narrow = inserted(
            &with(
                &DOCKER28.replace("-N DOCKER-USER\n", "-N DOCKER-USER\n-N FOILED\n"),
                &["-A FOILED -j REJECT"],
            ),
            "-A DOCKER-USER -p tcp -j FOILED",
        );
        assert!(matches!(
            evaluate(&v4(&narrow), &t("10.86.0.0/24")),
            Coverage::Shadowed(_)
        ));
    }

    #[test]
    fn a_drop_policy_with_nothing_accepting_covers() {
        let rs = v4(
            "-P FORWARD DROP\n-A FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT\n",
        );
        assert_eq!(evaluate(&rs, &t("10.86.0.0/24")), Coverage::Covered);
    }

    #[test]
    fn ip6tables_listing_is_checked_for_the_v6_subnet() {
        let rule = "-A DOCKER-USER -s fd00:86::/64 -m conntrack --ctstate NEW -j REJECT --reject-with icmp6-port-unreachable";
        let rs = parse_iptables(&inserted(DOCKER28, rule), Family::V6);
        assert_eq!(evaluate(&rs, &t("fd00:86::/64")), Coverage::Covered);
        let rs = parse_iptables(&inserted(DOCKER28, LAB_RULE), Family::V6);
        assert!(matches!(
            evaluate(&rs, &t("fd00:86::/64")),
            Coverage::Shadowed(_)
        ));
    }

    fn nft(chains: &str, rules: &str) -> String {
        format!(
            r#"{{"nftables": [{{"metainfo": {{"version": "1.0.9", "json_schema_version": 1}}}},
            {{"table": {{"family": "inet", "name": "foiled", "handle": 1}}}}, {chains}, {rules}]}}"#
        )
    }

    const NFT_FORWARD: &str = r#"{"chain": {"family": "inet", "table": "foiled", "name": "forward", "handle": 1, "type": "filter", "hook": "forward", "prio": -1, "policy": "accept"}}"#;

    const NFT_DENY: &str = r#"{"rule": {"family": "inet", "table": "foiled", "chain": "forward", "handle": 4, "expr": [
        {"match": {"op": "==", "left": {"payload": {"protocol": "ip", "field": "saddr"}}, "right": {"prefix": {"addr": "10.86.0.0", "len": 24}}}},
        {"match": {"op": "in", "left": {"ct": {"key": "state"}}, "right": "new"}},
        {"counter": {"packets": 0, "bytes": 0}},
        {"reject": null}]}}"#;

    #[test]
    fn nftables_deny_rule_covers_the_subnet() {
        let rs = parse_nft(&nft(NFT_FORWARD, NFT_DENY)).unwrap();
        assert_eq!(evaluate(&rs, &t("10.86.0.0/24")), Coverage::Covered);
        // An IPv4 rule says nothing about the IPv6 subnet.
        assert_eq!(evaluate(&rs, &t("fd00:86::/64")), Coverage::Missing);
    }

    #[test]
    fn nftables_without_a_deny_rule_is_missing() {
        let rs = parse_nft(&nft(NFT_FORWARD, r#"{"metainfo": {}}"#)).unwrap();
        assert_eq!(evaluate(&rs, &t("10.86.0.0/24")), Coverage::Missing);
        let other = NFT_DENY.replace("10.86.0.0", "10.87.0.0");
        let rs = parse_nft(&nft(NFT_FORWARD, &other)).unwrap();
        assert_eq!(evaluate(&rs, &t("10.86.0.0/24")), Coverage::Missing);
    }

    #[test]
    fn nftables_accept_before_the_deny_shadows_it() {
        let accept = r#"{"rule": {"family": "inet", "table": "foiled", "chain": "forward", "handle": 3, "expr": [
            {"match": {"op": "==", "left": {"meta": {"key": "iifname"}}, "right": "br-0123456789ab"}},
            {"match": {"op": "==", "left": {"payload": {"protocol": "tcp", "field": "dport"}}, "right": 443}},
            {"accept": null}]}}"#;
        let rs = parse_nft(&nft(NFT_FORWARD, &format!("{accept}, {NFT_DENY}"))).unwrap();
        assert_eq!(
            evaluate(&rs, &t("10.86.0.0/24")),
            Coverage::Shadowed("nft rule inet foiled forward handle 3".into())
        );
        let established = r#"{"rule": {"family": "inet", "table": "foiled", "chain": "forward", "handle": 2, "expr": [
            {"match": {"op": "in", "left": {"ct": {"key": "state"}}, "right": ["established", "related"]}},
            {"accept": null}]}}"#;
        let rs = parse_nft(&nft(NFT_FORWARD, &format!("{established}, {NFT_DENY}"))).unwrap();
        assert_eq!(evaluate(&rs, &t("10.86.0.0/24")), Coverage::Covered);
    }

    #[test]
    fn nftables_follows_jumps_sets_and_drop_policy() {
        let chains = format!(
            r#"{NFT_FORWARD}, {{"chain": {{"family": "inet", "table": "foiled", "name": "decoys", "handle": 2}}}}"#
        );
        let rules = r#"{"rule": {"family": "inet", "table": "foiled", "chain": "forward", "handle": 5, "expr": [
                {"jump": {"target": "decoys"}}]}},
            {"rule": {"family": "inet", "table": "foiled", "chain": "decoys", "handle": 6, "expr": [
                {"match": {"op": "==", "left": {"payload": {"protocol": "ip6", "field": "saddr"}},
                  "right": {"set": [{"prefix": {"addr": "fd00:86::", "len": 64}}, "fd00:99::1"]}}},
                {"drop": null}]}}"#;
        let rs = parse_nft(&nft(&chains, rules)).unwrap();
        assert_eq!(evaluate(&rs, &t("fd00:86::/64")), Coverage::Covered);

        let drop_policy = NFT_FORWARD.replace(r#""policy": "accept""#, r#""policy": "drop""#);
        let rs = parse_nft(&nft(&drop_policy, r#"{"metainfo": {}}"#)).unwrap();
        assert_eq!(evaluate(&rs, &t("10.86.0.0/24")), Coverage::Covered);

        // A named set cannot be resolved here, so it never counts as a deny.
        let named = NFT_DENY.replace(
            r#"{"prefix": {"addr": "10.86.0.0", "len": 24}}"#,
            r#""@decoys""#,
        );
        let rs = parse_nft(&nft(NFT_FORWARD, &named)).unwrap();
        assert_eq!(evaluate(&rs, &t("10.86.0.0/24")), Coverage::Missing);
    }

    #[test]
    fn nftables_ignores_chains_off_the_forward_hook() {
        let input = NFT_FORWARD.replace(r#""hook": "forward""#, r#""hook": "input""#);
        let rs = parse_nft(&nft(&input, NFT_DENY)).unwrap();
        assert_eq!(evaluate(&rs, &t("10.86.0.0/24")), Coverage::Missing);
        assert!(parse_nft("not json").is_err());
        assert!(parse_nft("{}").is_err());
    }

    #[test]
    fn output_interface_exemptions_must_name_only_the_bridge() {
        // A wildcard or negated selector that also takes in another
        // interface is not "only the decoy bridge".
        for rule in [
            "-A DOCKER-USER -s 10.86.0.0/24 ! -o br-+ -j DROP",
            "-A DOCKER-USER -s 10.86.0.0/24 ! -o br-0123456789a+ -j DROP",
        ] {
            let rs = v4(&inserted(DOCKER28, rule));
            assert!(
                matches!(evaluate(&rs, &t("10.86.0.0/24")), Coverage::Shadowed(_)),
                "{rule}"
            );
        }
        // An accept out of every `br-` interface can reach other bridges.
        let accept = "-A DOCKER-USER -i br-0123456789ab -o br-+ -j ACCEPT";
        let listing = inserted(&inserted(DOCKER28, LAB_RULE), accept);
        assert_eq!(
            evaluate(&v4(&listing), &t("10.86.0.0/24")),
            Coverage::Shadowed(accept.into())
        );
        // The exact name still counts both ways.
        let exact = "-A DOCKER-USER -s 10.86.0.0/24 ! -o br-0123456789ab -j DROP";
        assert_eq!(
            evaluate(&v4(&inserted(DOCKER28, exact)), &t("10.86.0.0/24")),
            Coverage::Covered
        );
        let into = "-A DOCKER-USER -o br-0123456789ab -j ACCEPT";
        let listing = inserted(&inserted(DOCKER28, LAB_RULE), into);
        assert_eq!(
            evaluate(&v4(&listing), &t("10.86.0.0/24")),
            Coverage::Covered
        );
        // nftables sets with a wildcard are treated the same way.
        let nft_rule = r#"{"rule": {"family": "inet", "table": "foiled", "chain": "forward", "handle": 4, "expr": [
            {"match": {"op": "==", "left": {"payload": {"protocol": "ip", "field": "saddr"}}, "right": {"prefix": {"addr": "10.86.0.0", "len": 24}}}},
            {"match": {"op": "!=", "left": {"meta": {"key": "oifname"}}, "right": {"set": ["br-0123456789ab", "eth*"]}}},
            {"drop": null}]}}"#;
        let rs = parse_nft(&nft(NFT_FORWARD, nft_rule)).unwrap();
        assert_eq!(evaluate(&rs, &t("10.86.0.0/24")), Coverage::Missing);
    }

    #[test]
    fn a_partial_return_does_not_prove_coverage_through_the_drop_policy() {
        // Docker 27 style: FORWARD drops by default and Docker accepts the
        // bridge's traffic after a narrow RETURN.
        let base = "-P FORWARD DROP\n-N DOCKER-USER\n-N SKIP\n-A FORWARD -j DOCKER-USER\n\
            -A FORWARD -i br-0123456789ab -j ACCEPT\n";
        for (extra, what) in [
            (
                "-A FORWARD -p tcp -j RETURN\n",
                "partial RETURN in the base chain",
            ),
            (
                "-A FORWARD -p tcp -g SKIP\n-A SKIP -j RETURN\n",
                "conditional GOTO that returns",
            ),
        ] {
            let listing = base.replace(
                "-A FORWARD -j DOCKER-USER\n",
                &format!("-A FORWARD -j DOCKER-USER\n{extra}"),
            );
            assert_eq!(
                evaluate(&v4(&listing), &t("10.86.0.0/24")),
                Coverage::Shadowed("-A FORWARD -i br-0123456789ab -j ACCEPT".into()),
                "{what}"
            );
        }
        // An unconditional RETURN sends everything to the drop policy.
        let listing = base.replace(
            "-A FORWARD -j DOCKER-USER\n",
            "-A FORWARD -j DOCKER-USER\n-A FORWARD -j RETURN\n",
        );
        assert_eq!(
            evaluate(&v4(&listing), &t("10.86.0.0/24")),
            Coverage::Covered
        );
        // A partial RETURN then a full deny: both parts end in a drop.
        let listing = base.replace(
            "-A FORWARD -j DOCKER-USER\n",
            "-A FORWARD -j DOCKER-USER\n-A FORWARD -p tcp -j RETURN\n-A FORWARD -s 10.86.0.0/24 -j DROP\n",
        );
        assert_eq!(
            evaluate(&v4(&listing), &t("10.86.0.0/24")),
            Coverage::Covered
        );
        // Without a drop policy the returned part is not denied by the
        // later rule, so the chain does not cover.
        let accept_policy = listing.replace("-P FORWARD DROP", "-P FORWARD ACCEPT");
        assert!(matches!(
            evaluate(&v4(&accept_policy), &t("10.86.0.0/24")),
            Coverage::Shadowed(r) if r == "-A FORWARD -p tcp -j RETURN"
        ));
    }

    #[test]
    fn virtual_or_unknown_conntrack_states_are_not_reduced_to_new() {
        // A DNAT match can still select new connections: an accept on it
        // must shadow the deny, and a deny on it must not count.
        for state in ["DNAT", "NEW,DNAT", "SNAT", "BOGUS"] {
            let accept = format!("-A DOCKER-USER -m conntrack --ctstate {state} -j ACCEPT");
            let listing = inserted(&inserted(DOCKER28, LAB_RULE), &accept);
            assert_eq!(
                evaluate(&v4(&listing), &t("10.86.0.0/24")),
                Coverage::Shadowed(accept.clone()),
                "{state}"
            );
            let deny =
                format!("-A DOCKER-USER -s 10.86.0.0/24 -m conntrack ! --ctstate {state} -j DROP");
            assert!(
                matches!(
                    evaluate(&v4(&inserted(DOCKER28, &deny)), &t("10.86.0.0/24")),
                    Coverage::Shadowed(_)
                ),
                "{deny}"
            );
        }
        // Plain states keep their exact meaning.
        assert_eq!(ct_new(&["NEW"], false), Some(true));
        assert_eq!(ct_new(&["RELATED", "ESTABLISHED"], false), Some(false));
        assert_eq!(ct_new(&["INVALID", "UNTRACKED"], true), Some(true));
        assert_eq!(ct_new(&["NEW", "DNAT"], false), None);
        // nftables: `ct state dnat` is not a plain state either.
        let accept = r#"{"rule": {"family": "inet", "table": "foiled", "chain": "forward", "handle": 3, "expr": [
            {"match": {"op": "in", "left": {"ct": {"key": "state"}}, "right": ["established", "dnat"]}},
            {"accept": null}]}}"#;
        let rs = parse_nft(&nft(NFT_FORWARD, &format!("{accept}, {NFT_DENY}"))).unwrap();
        assert!(matches!(
            evaluate(&rs, &t("10.86.0.0/24")),
            Coverage::Shadowed(_)
        ));
    }

    #[test]
    fn nftables_verdict_maps_are_a_possible_accept() {
        let vmap = r#"{"rule": {"family": "inet", "table": "foiled", "chain": "forward", "handle": 3, "expr": [
            {"vmap": {"key": {"meta": {"key": "iifname"}}, "data": {"set": [["br-0123456789ab", {"accept": null}]]}}}]}}"#;
        let rs = parse_nft(&nft(NFT_FORWARD, &format!("{vmap}, {NFT_DENY}"))).unwrap();
        assert_eq!(
            evaluate(&rs, &t("10.86.0.0/24")),
            Coverage::Shadowed("nft rule inet foiled forward handle 3".into())
        );
        // Counters before the deny still carry on.
        let counter = r#"{"rule": {"family": "inet", "table": "foiled", "chain": "forward", "handle": 3, "expr": [
            {"counter": {"packets": 0, "bytes": 0}}]}}"#;
        let rs = parse_nft(&nft(NFT_FORWARD, &format!("{counter}, {NFT_DENY}"))).unwrap();
        assert_eq!(evaluate(&rs, &t("10.86.0.0/24")), Coverage::Covered);
    }

    #[test]
    fn nftables_dormant_tables_are_ignored() {
        let doc = |flags: &str| {
            format!(
                r#"{{"nftables": [
                {{"table": {{"family": "inet", "name": "foiled", "handle": 1{flags}}}}},
                {{"table": {{"family": "inet", "name": "active", "handle": 2}}}},
                {NFT_FORWARD}, {NFT_DENY}]}}"#
            )
        };
        let rs = parse_nft(&doc(r#", "flags": "dormant""#)).unwrap();
        assert_eq!(evaluate(&rs, &t("10.86.0.0/24")), Coverage::Missing);
        let rs = parse_nft(&doc(r#", "flags": ["dormant"]"#)).unwrap();
        assert_eq!(evaluate(&rs, &t("10.86.0.0/24")), Coverage::Missing);
        // An active table with the same rule still covers.
        let rs = parse_nft(&doc("")).unwrap();
        assert_eq!(evaluate(&rs, &t("10.86.0.0/24")), Coverage::Covered);
        // Only the dormant table is skipped, not an active one beside it.
        let active = NFT_FORWARD.replace(r#""table": "foiled""#, r#""table": "active""#);
        let active_deny = NFT_DENY.replace(r#""table": "foiled""#, r#""table": "active""#);
        let both = format!(
            r#"{{"nftables": [
            {{"table": {{"family": "inet", "name": "foiled", "handle": 1, "flags": ["dormant"]}}}},
            {{"table": {{"family": "inet", "name": "active", "handle": 2}}}},
            {NFT_FORWARD}, {NFT_DENY}, {active}, {active_deny}]}}"#
        );
        let rs = parse_nft(&both).unwrap();
        assert_eq!(evaluate(&rs, &t("10.86.0.0/24")), Coverage::Covered);
    }

    fn nft_rule(handle: u32, exprs: &str) -> String {
        format!(
            r#"{{"rule": {{"family": "inet", "table": "foiled", "chain": "forward", "handle": {handle}, "expr": [{exprs}]}}}}"#
        )
    }

    const NFT_SADDR_24: &str = r#"{"match": {"op": "==", "left": {"payload": {"protocol": "ip", "field": "saddr"}}, "right": {"prefix": {"addr": "10.86.0.0", "len": 24}}}}"#;

    #[test]
    fn nftables_relational_operators_are_not_equality() {
        // `ip saddr < 10.87.0.0` takes in the whole decoy subnet: an accept
        // on it must shadow the deny, and a deny on it must not count.
        for op in ["<", "<=", ">", ">=", "&"] {
            let accept = nft_rule(
                3,
                &format!(
                    r#"{{"match": {{"op": "{op}", "left": {{"payload": {{"protocol": "ip", "field": "saddr"}}}}, "right": "10.87.0.0"}}}}, {{"accept": null}}"#
                ),
            );
            let rs = parse_nft(&nft(NFT_FORWARD, &format!("{accept}, {NFT_DENY}"))).unwrap();
            assert_eq!(
                evaluate(&rs, &t("10.86.0.0/24")),
                Coverage::Shadowed("nft rule inet foiled forward handle 3".into()),
                "{op}"
            );
            let deny = NFT_DENY.replace(r#""op": "==""#, &format!(r#""op": "{op}""#));
            let rs = parse_nft(&nft(NFT_FORWARD, &deny)).unwrap();
            assert_eq!(evaluate(&rs, &t("10.86.0.0/24")), Coverage::Missing, "{op}");
        }
        // Equality and membership still work, negated or not.
        let member = NFT_DENY.replace(r#""op": "==""#, r#""op": "in""#);
        let rs = parse_nft(&nft(NFT_FORWARD, &member)).unwrap();
        assert_eq!(evaluate(&rs, &t("10.86.0.0/24")), Coverage::Covered);
        let other_net = nft_rule(
            3,
            r#"{"match": {"op": "!=", "left": {"payload": {"protocol": "ip", "field": "saddr"}}, "right": {"prefix": {"addr": "10.86.0.0", "len": 24}}}}, {"accept": null}"#,
        );
        let rs = parse_nft(&nft(NFT_FORWARD, &format!("{other_net}, {NFT_DENY}"))).unwrap();
        assert_eq!(evaluate(&rs, &t("10.86.0.0/24")), Coverage::Covered);
    }

    #[test]
    fn nftables_rules_with_two_source_matches_are_partial() {
        // Narrow prefix first, covering prefix second: only 10.86.0.0/25 is
        // dropped, so the rule does not cover the subnet.
        let narrow = r#"{"match": {"op": "==", "left": {"payload": {"protocol": "ip", "field": "saddr"}}, "right": {"prefix": {"addr": "10.86.0.0", "len": 25}}}}"#;
        for (a, b) in [(narrow, NFT_SADDR_24), (NFT_SADDR_24, narrow)] {
            let deny = nft_rule(4, &format!(r#"{a}, {b}, {{"drop": null}}"#));
            let rs = parse_nft(&nft(NFT_FORWARD, &deny)).unwrap();
            assert_eq!(evaluate(&rs, &t("10.86.0.0/24")), Coverage::Missing);
        }
        // An accept with two source matches still counts as a possible
        // accept when the first one overlaps the subnet.
        let accept = nft_rule(
            3,
            &format!(r#"{narrow}, {NFT_SADDR_24}, {{"accept": null}}"#),
        );
        let rs = parse_nft(&nft(NFT_FORWARD, &format!("{accept}, {NFT_DENY}"))).unwrap();
        assert!(matches!(
            evaluate(&rs, &t("10.86.0.0/24")),
            Coverage::Shadowed(_)
        ));
        // One source match keeps its meaning.
        let rs = parse_nft(&nft(NFT_FORWARD, NFT_DENY)).unwrap();
        assert_eq!(evaluate(&rs, &t("10.86.0.0/24")), Coverage::Covered);
    }

    #[test]
    fn nftables_named_interface_sets_are_not_literal_names() {
        // `iifname @trusted accept`: the set may hold the decoy bridge.
        let accept = nft_rule(
            3,
            r#"{"match": {"op": "==", "left": {"meta": {"key": "iifname"}}, "right": "@trusted"}}, {"accept": null}"#,
        );
        let rs = parse_nft(&nft(NFT_FORWARD, &format!("{accept}, {NFT_DENY}"))).unwrap();
        assert_eq!(
            evaluate(&rs, &t("10.86.0.0/24")),
            Coverage::Shadowed("nft rule inet foiled forward handle 3".into())
        );
        // A deny on a named set never counts.
        let deny = nft_rule(
            4,
            r#"{"match": {"op": "==", "left": {"meta": {"key": "iifname"}}, "right": "@decoys"}}, {"drop": null}"#,
        );
        let rs = parse_nft(&nft(NFT_FORWARD, &deny)).unwrap();
        assert_eq!(evaluate(&rs, &t("10.86.0.0/24")), Coverage::Missing);
        // Literal names and inline sets keep working.
        let deny = nft_rule(
            4,
            r#"{"match": {"op": "==", "left": {"meta": {"key": "iifname"}}, "right": {"set": ["br-0123456789ab", "foil0"]}}}, {"drop": null}"#,
        );
        let rs = parse_nft(&nft(NFT_FORWARD, &deny)).unwrap();
        assert_eq!(evaluate(&rs, &t("10.86.0.0/24")), Coverage::Covered);
        let other = nft_rule(
            3,
            r#"{"match": {"op": "==", "left": {"meta": {"key": "iifname"}}, "right": "docker0"}}, {"accept": null}"#,
        );
        let rs = parse_nft(&nft(NFT_FORWARD, &format!("{other}, {NFT_DENY}"))).unwrap();
        assert_eq!(evaluate(&rs, &t("10.86.0.0/24")), Coverage::Covered);
    }

    #[test]
    fn nftables_dup_is_an_escape_even_before_a_drop() {
        let dup = r#"{"dup": {"addr": "192.0.2.9", "dev": "eth0"}}"#;
        // A rule of its own, then a covering drop: the copy already left.
        let alone = nft_rule(3, &format!("{NFT_SADDR_24}, {dup}"));
        let rs = parse_nft(&nft(NFT_FORWARD, &format!("{alone}, {NFT_DENY}"))).unwrap();
        assert_eq!(
            evaluate(&rs, &t("10.86.0.0/24")),
            Coverage::Shadowed("nft rule inet foiled forward handle 3".into())
        );
        // In the same rule as the drop, even under a drop policy.
        let both = nft_rule(4, &format!(r#"{NFT_SADDR_24}, {dup}, {{"drop": null}}"#));
        let drop_policy = NFT_FORWARD.replace(r#""policy": "accept""#, r#""policy": "drop""#);
        for chain in [NFT_FORWARD.to_string(), drop_policy] {
            let rs = parse_nft(&nft(&chain, &both)).unwrap();
            assert_eq!(
                evaluate(&rs, &t("10.86.0.0/24")),
                Coverage::Shadowed("nft rule inet foiled forward handle 4".into())
            );
        }
        // Counters and logging still carry on.
        let log = nft_rule(
            3,
            &format!(r#"{NFT_SADDR_24}, {{"counter": null}}, {{"log": {{"prefix": "x"}}}}"#),
        );
        let rs = parse_nft(&nft(NFT_FORWARD, &format!("{log}, {NFT_DENY}"))).unwrap();
        assert_eq!(evaluate(&rs, &t("10.86.0.0/24")), Coverage::Covered);
    }

    const INSPECT: &str = r#"[{"Name": "foiled-lab", "Id": "0123456789abcdef0123", "Driver": "bridge",
        "EnableIPv6": true, "IPAM": {"Driver": "default", "Options": {}, "Config": [
        {"Subnet": "10.86.0.0/24", "Gateway": "10.86.0.1"}, {"Subnet": "fd00:86::/64"}]},
        "Options": {}, "Labels": {}}]"#;

    #[test]
    fn network_inspect_gives_driver_bridge_and_subnets() {
        let info = parse_network_inspect(INSPECT).unwrap();
        assert_eq!(info.id, "0123456789abcdef0123");
        assert_eq!(info.driver, "bridge");
        assert_eq!(info.bridge, BR);
        assert_eq!(info.subnets.len(), 2);
        assert!(info.subnets[1].1.is_v6());
        let named = INSPECT.replace(
            r#""Options": {}, "Labels""#,
            r#""Options": {"com.docker.network.bridge.name": "foil0"}, "Labels""#,
        );
        assert_eq!(parse_network_inspect(&named).unwrap().bridge, "foil0");
        assert!(parse_network_inspect("[]").is_err());
        assert!(parse_network_inspect("garbage").is_err());
    }

    #[test]
    fn network_must_be_a_bridge_with_the_expected_subnets() {
        let info = parse_network_inspect(INSPECT).unwrap();
        assert!(check_network("foiled-lab", &info, &[]).is_ok());
        let both = ["fd00:86::/64".to_string(), "10.86.0.0/24".to_string()];
        assert!(
            check_network("foiled-lab", &info, &both).is_ok(),
            "order does not matter"
        );
        let err = check_network("foiled-lab", &info, &["10.86.0.0/24".into()]).unwrap_err();
        assert!(err.contains("expected"), "{err}");
        let err = check_network(
            "foiled-lab",
            &info,
            &["10.99.0.0/24".into(), "fd00:86::/64".into()],
        )
        .unwrap_err();
        assert!(err.contains("10.86.0.0/24"), "{err}");
        assert!(check_network("foiled-lab", &info, &["nonsense".into()]).is_err());
        let host = NetworkInfo {
            driver: "host".into(),
            ..info.clone()
        };
        assert!(
            check_network("foiled-lab", &host, &[])
                .unwrap_err()
                .contains("not bridge")
        );
        let bare = NetworkInfo {
            subnets: vec![],
            ..info
        };
        assert!(check_network("foiled-lab", &bare, &[]).is_err());
    }
}
