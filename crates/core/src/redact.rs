//! Redaction of secrets and personal information in attacker text (#34,
//! #16).
//!
//! IOC values (`foiled_core::ioc`) and the Redis emulator's capture events
//! (#30) use these rules, so a value hidden in one is hidden in the other.
//! Redaction keeps the shape of the text (`password=REDACTED`,
//! `mysql -pREDACTED`, `curl -u admin:REDACTED`), so the rest stays useful
//! as an indicator. When in doubt it hides more, never less.
//!
//! Everything here is linear in the input: look-backs are bounded, the
//! shell lexer is one pass and nested `sh -c` strings are followed at most
//! three levels deep. See `docs/iocs.md` for the rules in words.

/// What hidden text is replaced with.
pub const REDACTED: &str = "REDACTED";

/// A name containing one of these (ignoring case) names a secret:
/// `password`, `dbpwd`, `authkey`, `X-Amz-Signature`, `apiToken`,
/// `sessid`. `auth` is the one exception: it does not count in a name part
/// that is exactly `author` or `authors` (but does in `authority`).
const SECRET_KEY_PARTS: &[&str] = &[
    "secret",
    "token",
    "password",
    "passwd",
    "pwd",
    "api-key",
    "api_key",
    "apikey",
    "private_key",
    "private-key",
    "privatekey",
    "signature",
    "session",
    "sessid",
    "auth",
    "credential",
    "cookie",
    "jwt",
];

/// Names that are secrets as a whole name (`pass=`, `key=`).
const SECRET_KEY_WORDS: &[&str] = &["pass", "key", "sig", "sid"];

/// Name parts (split on `-`, `_` and camel case) that name a secret only
/// as a whole part: `db_pass`, `x-sig`, `X-Auth-Pin`, `AuthorKey`, but not
/// `passport`, `spinner` or `monkey`.
const SECRET_KEY_COMPONENTS: &[&str] = &["pass", "sig", "sid", "pin", "key"];

/// Configuration keywords whose name mentions a secret but whose value is
/// a switch (`PasswordAuthentication no` in `sshd_config`). Only these keep
/// a boolean value; `password=no` is still hidden.
const SETTING_KEYS: &[&str] = &[
    "passwordauthentication",
    "permitemptypasswords",
    "kbdinteractiveauthentication",
    "challengeresponseauthentication",
    "pubkeyauthentication",
    "hostbasedauthentication",
    "gssapiauthentication",
    "kerberosauthentication",
];

/// The switch values a [`SETTING_KEYS`] keyword may show.
const SETTING_VALUES: &[&str] = &["yes", "no", "true", "false", "on", "off"];

/// Longest parameter or header name considered.
const MAX_KEY_CHARS: usize = 48;

/// How deep `sh -c '...'` strings are followed.
const MAX_SHELL_DEPTH: u8 = 3;

/// What kind of text is being redacted. Only header values differ: in a
/// command line an unquoted header value ends where the shell ends a word
/// (whitespace, `;`, `|`, `&`), so the commands after it stay visible; in
/// other text it runs to the end of the line or the closing quote.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TextKind {
    Text,
    CommandLine,
}

/// Split a name into parts on `-`, `_` and lower-to-upper case changes,
/// lower-cased.
fn components(name: &str) -> Vec<String> {
    let mut comps: Vec<String> = Vec::new();
    let mut cur = String::new();
    let mut prev_lower = false;
    for c in name.chars() {
        if c == '-' || c == '_' {
            if !cur.is_empty() {
                comps.push(std::mem::take(&mut cur));
            }
            prev_lower = false;
            continue;
        }
        if c.is_ascii_uppercase() && prev_lower && !cur.is_empty() {
            comps.push(std::mem::take(&mut cur));
        }
        prev_lower = c.is_ascii_lowercase() || c.is_ascii_digit();
        cur.push(c.to_ascii_lowercase());
    }
    if !cur.is_empty() {
        comps.push(cur);
    }
    comps
}

/// Whole name parts where `auth` is not a secret.
const NOT_AUTH_PARTS: &[&str] = &["author", "authors"];

/// True when a parameter, field, header or flag name names a secret.
pub fn secret_key(name: &str) -> bool {
    let name = name.trim_start_matches('-');
    let lower = name.to_ascii_lowercase();
    if lower.is_empty() {
        return false;
    }
    let parts = components(name);
    SECRET_KEY_WORDS.contains(&lower.as_str())
        || SECRET_KEY_PARTS
            .iter()
            .any(|p| *p != "auth" && lower.contains(p))
        // `auth` counts inside any part except exactly `author` or
        // `authors`: `authorkey`, `authority` and `AuthorKey` are secrets,
        // `author_name` and `authorName` are not.
        || parts
            .iter()
            .any(|c| c.contains("auth") && !NOT_AUTH_PARTS.contains(&c.as_str()))
        || parts
            .iter()
            .any(|c| SECRET_KEY_COMPONENTS.contains(&c.as_str()))
}

/// Remove secrets and personal information from attacker text, keeping its
/// shape. Returns the new text and whether anything changed.
pub fn redact(s: &str) -> (String, bool) {
    redact_as(s, TextKind::Text)
}

/// [`redact`] for a given kind of text.
///
/// 1. URL credentials: `scheme://user:pw@host` and `scheme://TOKEN@host`
///    become `scheme://REDACTED@host`.
/// 2. Command lines ([`redact_shell`]): the word after secret flags, the
///    password half of `-u user:pw`, and program password flags.
/// 3. Values after secret-named keys ([`redact_pairs`]): query strings,
///    config lines, JSON and headers.
/// 4. Email local parts, plain or with `%40`.
pub fn redact_as(s: &str, kind: TextKind) -> (String, bool) {
    let out = redact_emails(&redact_pairs(&redact_shell(&redact_userinfo(s), 0), kind));
    let changed = out != s;
    (out, changed)
}

fn redact_userinfo(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(i) = rest.find("://") {
        let (head, tail) = rest.split_at(i + 3);
        out.push_str(head);
        let end = tail
            .find(|c: char| matches!(c, '/' | '?' | '#' | '\'' | '"') || c.is_whitespace())
            .unwrap_or(tail.len());
        let authority = &tail[..end];
        match authority.rfind('@') {
            Some(at) => {
                // The user name goes too: it can be a person's.
                out.push_str(REDACTED);
                out.push_str(&authority[at..]);
            }
            None => out.push_str(authority),
        }
        rest = &tail[end..];
    }
    out.push_str(rest);
    out
}

// ---------------------------------------------------------------------------
// Command lines
// ---------------------------------------------------------------------------

/// Flags whose next word is a secret, for any program. `bearer` catches
/// `Authorization: Bearer x` written as words.
const SECRET_FLAGS: &[&str] = &[
    "--api-key",
    "--apikey",
    "--pass",
    "--password",
    "--secret",
    "--token",
    "-pass",
    "-passin",
    "-passout",
    "bearer",
];

/// Password flags of particular programs: `(program, flag, attached,
/// separate)`. Attached is `-pPW`; separate is `-p PW`.
const PROGRAM_SECRET_FLAGS: &[(&str, &str, bool, bool)] = &[
    ("mysql", "-p", true, false),
    ("mysqldump", "-p", true, false),
    ("mysqladmin", "-p", true, false),
    ("mariadb", "-p", true, false),
    ("mariadb-dump", "-p", true, false),
    ("sshpass", "-p", true, true),
    ("redis-cli", "-a", true, true),
    ("mosquitto_pub", "-P", false, true),
    ("mosquitto_sub", "-P", false, true),
    ("zip", "-P", false, true),
    ("unzip", "-P", false, true),
    ("7z", "-p", true, false),
    ("7za", "-p", true, false),
];

/// Flags whose next word is `user:password` (`user%password` for
/// `smbclient -U`).
const USER_PASS_FLAGS: &[&str] = &["-u", "--user", "--proxy-user", "-U"];

/// Programs that run the next word as the program.
const WRAPPERS: &[&str] = &[
    "sudo", "doas", "env", "timeout", "nice", "ionice", "nohup", "stdbuf", "time", "xargs", "exec",
    "command", "setsid",
];

/// Words that open a group or a clause before the program: `{ mysql ...; }`,
/// `if mysql ...; then`.
const GROUP_WORDS: &[&str] = &[
    "{", "}", "!", "if", "then", "else", "elif", "do", "while", "until", "time",
];

/// Shells whose `-c` string is another command line.
const SHELLS: &[&str] = &["sh", "bash", "zsh", "dash", "ash", "ksh", "busybox"];

/// Wrapper options that take the next word as their value.
fn wrapper_option_takes_arg(wrapper: &str, opt: &str) -> bool {
    let takes: &[&str] = match wrapper {
        "sudo" | "doas" => &["-u", "-g", "-C", "-D", "-h", "-p", "-r", "-t", "-U", "-T"],
        "env" => &["-u", "-C", "-S"],
        "timeout" => &["-s", "-k"],
        "nice" => &["-n"],
        "ionice" => &["-c", "-n", "-p"],
        "stdbuf" => &["-i", "-o", "-e"],
        "time" => &["-o", "-f"],
        "xargs" => &["-I", "-n", "-P", "-d", "-L", "-s", "-a", "-E"],
        _ => &[],
    };
    takes.contains(&opt)
}

/// A word in a command line, by byte range.
#[derive(Debug, Clone, Copy)]
struct Word {
    start: usize,
    end: usize,
}

enum Tok {
    Word(Word),
    /// `;`, `&`, `&&`, `|`, `||` or a newline outside quotes.
    Sep,
}

/// Split a command line into words and command separators the way a POSIX
/// shell does: quotes and backslashes keep spaces and separators inside a
/// word. If a quote is never closed (`it's here; curl --token abc`), the
/// line is split again with every quote from that one on treated as an
/// ordinary character, so the rest is still checked word by word (fail
/// closed). Two passes at most.
fn lex(s: &str) -> Vec<Tok> {
    match lex_from(s, usize::MAX) {
        Ok(toks) => toks,
        Err(open_at) => lex_from(s, open_at).unwrap_or_default(),
    }
}

/// One lexing pass. Quotes at byte `literal_from` or later are ordinary
/// characters. `Err` gives the position of a quote left open.
fn lex_from(s: &str, literal_from: usize) -> Result<Vec<Tok>, usize> {
    let mut out = Vec::new();
    let mut start: Option<usize> = None;
    let mut quote: Option<(char, usize)> = None;
    let mut it = s.char_indices().peekable();
    let end_word = |out: &mut Vec<Tok>, start: &mut Option<usize>, i: usize| {
        if let Some(st) = start.take() {
            out.push(Tok::Word(Word { start: st, end: i }));
        }
    };
    while let Some((i, c)) = it.next() {
        if let Some((q, _)) = quote {
            if c == q {
                quote = None;
            } else if c == '\\' && q == '"' {
                it.next();
            }
            continue;
        }
        match c {
            '\'' | '"' if i < literal_from => {
                start.get_or_insert(i);
                quote = Some((c, i));
            }
            '\\' => {
                start.get_or_insert(i);
                it.next();
            }
            // Command separators, and the edges of `( ... )`, `$( ... )` and
            // backtick substitutions, whose insides are commands too.
            ';' | '|' | '&' | '\n' | '(' | ')' | '`' => {
                end_word(&mut out, &mut start, i);
                if (c == '&' || c == '|') && it.peek().map(|x| x.1) == Some(c) {
                    it.next();
                }
                out.push(Tok::Sep);
            }
            '$' if it.peek().map(|x| x.1) == Some('(') => {
                end_word(&mut out, &mut start, i);
            }
            c if c.is_whitespace() => end_word(&mut out, &mut start, i),
            _ => {
                start.get_or_insert(i);
            }
        }
    }
    if let Some((_, at)) = quote {
        return Err(at);
    }
    end_word(&mut out, &mut start, s.len());
    Ok(out)
}

/// A word without its shell quoting.
fn unquote(w: &str) -> String {
    let mut out = String::with_capacity(w.len());
    let mut quote: Option<char> = None;
    let mut it = w.chars();
    while let Some(c) = it.next() {
        match (quote, c) {
            (None, '\'' | '"') => quote = Some(c),
            (Some(q), c) if c == q => quote = None,
            (None, '\\') | (Some('"'), '\\') => {
                if let Some(n) = it.next() {
                    out.push(n);
                }
            }
            _ => out.push(c),
        }
    }
    out
}

/// The quote a word is wholly wrapped in, if any.
fn wrapping_quote(raw: &str) -> Option<char> {
    let q = raw.chars().next().filter(|c| matches!(c, '\'' | '"'))?;
    (raw.len() >= 2 && raw.ends_with(q)).then_some(q)
}

/// A whole word replaced by `REDACTED`, keeping a wrapping quote.
fn masked_word(raw: &str) -> String {
    match wrapping_quote(raw) {
        Some(q) => format!("{q}{REDACTED}{q}"),
        None => REDACTED.to_string(),
    }
}

/// `user:pw` (or `user%pw`) with the password masked, keeping a wrapping
/// quote. `None` when there is no password part.
fn masked_user_pass(raw: &str, value: &str, prefix: &str) -> Option<String> {
    let i = value.find(':').or_else(|| value.find('%'))?;
    let kept = format!("{prefix}{}{REDACTED}", &value[..=i]);
    Some(match wrapping_quote(raw) {
        Some(q) => format!("{q}{kept}{q}"),
        None => kept,
    })
}

fn is_assignment(w: &str) -> bool {
    let Some((name, _)) = w.split_once('=') else {
        return false;
    };
    name.chars()
        .next()
        .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
        && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// Program name of a word: its basename, lower case, without `$(`, a
/// backtick or `(` in front.
fn program_name(w: &str) -> String {
    let w = w.trim_start_matches(['$', '(', '`', '{']);
    w.rsplit('/').next().unwrap_or(w).to_ascii_lowercase()
}

/// Redact secrets carried by command-line words: the word after secret
/// flags, `user:pw` after `-u`/`--user` (and attached as `-uuser:pw` and
/// `--user=user:pw`), and program password flags (`mysql -pPW`,
/// `sshpass -p PW`). Each command between `;`, `&&`, `||`, `|` and
/// newlines finds its program after `VAR=value` assignments and wrappers
/// with their options (`sudo -u root`, `env X=1`, `timeout 5`, `nice -n
/// 5`), and `sh -c '...'` strings are redacted as command lines too. Quoted
/// words are masked whole.
fn redact_shell(s: &str, depth: u8) -> String {
    let mut edits: Vec<(usize, usize, String)> = Vec::new();
    let mut segment: Vec<Word> = Vec::new();
    for tok in lex(s).into_iter().chain(std::iter::once(Tok::Sep)) {
        match tok {
            Tok::Word(w) => segment.push(w),
            Tok::Sep => {
                shell_segment(s, &segment, depth, &mut edits);
                segment.clear();
            }
        }
    }
    if edits.is_empty() {
        return s.to_string();
    }
    edits.sort_by_key(|e| e.0);
    let mut out = String::with_capacity(s.len());
    let mut last = 0;
    for (start, end, with) in edits {
        if start < last {
            continue;
        }
        out.push_str(&s[last..start]);
        out.push_str(&with);
        last = end;
    }
    out.push_str(&s[last..]);
    out
}

fn shell_segment(s: &str, words: &[Word], depth: u8, edits: &mut Vec<(usize, usize, String)>) {
    let n = words.len();
    if n == 0 {
        return;
    }
    let raw = |k: usize| &s[words[k].start..words[k].end];
    let uq: Vec<String> = (0..n).map(|k| unquote(raw(k))).collect();

    // The program: past assignments and wrappers with their options.
    let mut k = 0;
    while k < n {
        if is_assignment(&uq[k]) || GROUP_WORDS.contains(&uq[k].as_str()) {
            k += 1;
            continue;
        }
        let base = program_name(&uq[k]);
        if !WRAPPERS.contains(&base.as_str()) {
            break;
        }
        k += 1;
        while k < n && uq[k].starts_with('-') && uq[k].len() > 1 {
            let takes = wrapper_option_takes_arg(&base, &uq[k]);
            k += 1;
            if takes {
                k += 1;
            }
        }
        if base == "timeout" && k < n {
            k += 1;
        }
    }
    let prog = if k < n {
        program_name(&uq[k])
    } else {
        String::new()
    };

    // `sh -c '...'`: the string is a command line of its own.
    if SHELLS.contains(&prog.as_str())
        && depth < MAX_SHELL_DEPTH
        && let Some(j) = (k + 1..n)
            .find(|&j| uq[j].starts_with('-') && !uq[j].starts_with("--") && uq[j].contains('c'))
        && j + 1 < n
    {
        let w = words[j + 1];
        let (a, b) = if wrapping_quote(raw(j + 1)).is_some() {
            (w.start + 1, w.end - 1)
        } else {
            (w.start, w.end)
        };
        let inner = &s[a..b];
        let red = redact_shell(inner, depth + 1);
        if red != inner {
            edits.push((a, b, red));
        }
    }

    let mut i = 0;
    while i < n {
        let u = &uq[i];
        let lw = u.to_ascii_lowercase();
        let has_next = i + 1 < n;
        let word = words[i];
        if SECRET_FLAGS.contains(&lw.as_str()) && has_next {
            let w = words[i + 1];
            edits.push((w.start, w.end, masked_word(raw(i + 1))));
            i += 2;
            continue;
        }
        if USER_PASS_FLAGS.contains(&u.as_str()) && has_next {
            if let Some(m) = masked_user_pass(raw(i + 1), &uq[i + 1], "") {
                let w = words[i + 1];
                edits.push((w.start, w.end, m));
            }
            i += 2;
            continue;
        }
        // Attached: `--user=admin:pw`, `-uadmin:pw`, `-Uadmin%pw`.
        let attached = ["--user=", "--proxy-user="]
            .iter()
            .find_map(|p| u.strip_prefix(p).map(|v| (*p, v)))
            .or_else(|| {
                ["-u", "-U"]
                    .iter()
                    .find(|p| u.len() > 2 && u.starts_with(*p) && !u.starts_with("--"))
                    .map(|p| (*p, &u[2..]))
            });
        if let Some((prefix, value)) = attached
            && let Some(m) = masked_user_pass("", value, prefix)
        {
            edits.push((word.start, word.end, m));
            i += 1;
            continue;
        }
        if i > k
            && let Some(&(_, flag, attached, separate)) = PROGRAM_SECRET_FLAGS
                .iter()
                .find(|(p, f, _, _)| *p == prog && u.starts_with(f) && !u.starts_with("--"))
        {
            if u == flag && separate && has_next {
                let w = words[i + 1];
                edits.push((w.start, w.end, masked_word(raw(i + 1))));
                i += 2;
                continue;
            }
            if attached && u.len() > flag.len() {
                edits.push((word.start, word.end, format!("{flag}{REDACTED}")));
            }
        }
        i += 1;
    }
}

// ---------------------------------------------------------------------------
// Key and value pairs
// ---------------------------------------------------------------------------

fn value_end(c: char) -> bool {
    matches!(c, '&' | ';' | '\'' | '"' | '#' | ',' | '}' | ']') || c.is_whitespace()
}

fn key_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '_' | '-')
}

/// Redact the value after a secret-named key ([`secret_key`]):
///
/// - `name=value` and `name = value` (query strings, config lines, flags);
/// - JSON and quoted keys, `"Password" : "x"`, with escapes honoured;
/// - headers, `name:value` with or without a space: the whole value up to
///   the end of the line or the closing quote, or in a command line up to
///   the end of the shell word.
///
/// Kept: switch values of a few configuration keywords
/// (`PasswordAuthentication=no`, [`SETTING_KEYS`]). There is no `host:port`
/// exception: only the label before the colon is read, so a dotted host
/// (`auth.example.invalid:8080`) never names a secret, and a secret-named
/// label (`auth-server:8080`, `session-id:12345`) fails closed.
fn redact_pairs(s: &str, kind: TextKind) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    let mut quote: Option<char> = None;
    while let Some(c) = chars.next() {
        out.push(c);
        match c {
            '\\' => {
                if let Some(n) = chars.next() {
                    out.push(n);
                }
                continue;
            }
            '\'' | '"' => {
                if quote == Some(c) {
                    quote = None;
                } else if quote.is_none() {
                    quote = Some(c);
                }
                continue;
            }
            '=' | ':' => {}
            _ => continue,
        }
        let before = &out[..out.len() - 1];
        let trimmed = before.trim_end_matches([' ', '\t']);
        let quoted_key = trimmed.ends_with('"') || trimmed.ends_with('\'');
        let name_end = trimmed.len() - usize::from(quoted_key);
        let key_len = trimmed[..name_end]
            .chars()
            .rev()
            .take(MAX_KEY_CHARS + 1)
            .take_while(|ch| key_char(*ch))
            .count();
        if key_len == 0 || key_len > MAX_KEY_CHARS {
            continue;
        }
        let key = trimmed[name_end - key_len..name_end].to_string();
        let starts_word = trimmed[..name_end - key_len]
            .chars()
            .next_back()
            .is_none_or(|p| {
                matches!(
                    p,
                    '?' | '&' | ';' | '\'' | '"' | '{' | ',' | '(' | '[' | '|'
                ) || p.is_whitespace()
            });
        if !starts_word || !secret_key(&key) {
            continue;
        }
        let header = c == ':' && !quoted_key;
        let mut spaces = String::new();
        while let Some(&n) = chars.peek() {
            if n != ' ' && n != '\t' {
                break;
            }
            spaces.push(n);
            chars.next();
        }
        let value_quote = match chars.peek() {
            Some(&q @ ('"' | '\'')) if quote != Some(q) => {
                chars.next();
                Some(q)
            }
            _ => None,
        };
        let mut value = String::new();
        while let Some(&n) = chars.peek() {
            let end = match value_quote {
                Some(q) => n == q,
                None if header => match (kind, quote) {
                    (_, Some(q)) => n == q || n == '\n' || n == '\r',
                    (TextKind::Text, None) => n == '\n' || n == '\r',
                    (TextKind::CommandLine, None) => {
                        n.is_whitespace() || matches!(n, ';' | '|' | '&' | '\'' | '"')
                    }
                },
                None => value_end(n) || quote == Some(n),
            };
            if end {
                break;
            }
            chars.next();
            value.push(n);
            if n == '\\'
                && let Some(e) = chars.next()
            {
                value.push(e);
            }
        }
        let trimmed_value = value.trim_end();
        let setting = SETTING_KEYS.contains(&key.to_ascii_lowercase().as_str())
            && SETTING_VALUES
                .iter()
                .any(|w| trimmed_value.eq_ignore_ascii_case(w));
        out.push_str(&spaces);
        if let Some(q) = value_quote {
            out.push(q);
        }
        if value.is_empty() || setting {
            out.push_str(&value);
        } else {
            out.push_str(REDACTED);
            out.push_str(&value[trimmed_value.len()..]);
        }
        if let Some(q) = value_quote
            && chars.peek() == Some(&q)
        {
            chars.next();
            out.push(q);
        }
    }
    out
}

/// Replace the local part of email addresses, written plainly or with the
/// `@` URL-encoded (`%40`).
fn redact_emails(s: &str) -> String {
    let local_char =
        |c: char| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '%' | '+' | '-');
    let mut out = String::with_capacity(s.len());
    for (i, c) in s.char_indices() {
        let sep = if c == '@' {
            1
        } else if c == '%'
            && s[i..]
                .get(..3)
                .is_some_and(|x| x.eq_ignore_ascii_case("%40"))
        {
            3
        } else {
            0
        };
        if sep > 0 {
            let domain: String = s[i + sep..]
                .chars()
                .take(254)
                .take_while(|d| d.is_ascii_alphanumeric() || matches!(d, '.' | '-'))
                .collect();
            let domain = domain.trim_end_matches('.');
            let tld_ok = domain.rsplit_once('.').is_some_and(|(_, tld)| {
                tld.len() >= 2 && tld.bytes().all(|b| b.is_ascii_alphabetic())
            });
            let local_len = out
                .chars()
                .rev()
                .take(65)
                .take_while(|ch| local_char(*ch))
                .count();
            if tld_ok && (1..=64).contains(&local_len) {
                let local = &out[out.len() - local_len..];
                if local != REDACTED {
                    out.truncate(out.len() - local_len);
                    out.push_str(REDACTED);
                }
            }
        }
        out.push(c);
    }
    out
}

// ---------------------------------------------------------------------------
// Protocol commands
// ---------------------------------------------------------------------------

/// Words after which the next argument is a credential, in any command
/// without a rule of its own (`AUTH2` hides the two after it).
const SECRET_ARG_KEYWORDS: &[&str] = &[
    "AUTH",
    "PASS",
    "PASSWORD",
    "REQUIREPASS",
    "MASTERAUTH",
    "SECRET",
    "TOKEN",
    "APIKEY",
];

fn secret_config_name(name: &str) -> bool {
    let name = name.to_ascii_lowercase();
    name == "requirepass" || name == "masterauth" || name.ends_with("pass") || secret_key(&name)
}

/// Positions of credential arguments in a protocol command. `tokens` is
/// the whole command: the command name at 0, then its subcommand and
/// arguments as the client sent them. A keyword hides the arguments it
/// takes, or as many as follow when the arity is short (fail closed).
///
/// - `AUTH`, `LOGIN` and `PASS`: every argument (user names too: they can
///   be a person's).
/// - `HELLO ... AUTH user PW`: user and password; `MIGRATE ... AUTH PW |
///   AUTH2 user PW`: the password, or user and password.
/// - `CONFIG SET name value ...`: values of `requirepass`, `masterauth`
///   and other secret-named parameters.
/// - `ACL SETUSER name rule...`: password rules (`>pw`, `<pw`, `#hash`,
///   `!hash`).
/// - Any other command (`SENTINEL SET m auth-pass PW`, unknown commands):
///   the argument after [`SECRET_ARG_KEYWORDS`] or any secret-named word,
///   and `name=value` arguments with a secret name.
pub fn secret_arg_positions<S: AsRef<str>>(tokens: &[S]) -> Vec<usize> {
    let n = tokens.len();
    let tok = |i: usize| tokens[i].as_ref();
    let up = |i: usize| tokens.get(i).map(|x| x.as_ref().to_ascii_uppercase());
    let mut hits: Vec<usize> = Vec::new();
    // The `count` arguments after position `at`, or as many as there are.
    let after = |hits: &mut Vec<usize>, at: usize, count: usize| {
        hits.extend(at + 1..(at + 1 + count).min(n));
    };
    match up(0).as_deref() {
        Some("AUTH" | "LOGIN" | "PASS") => hits.extend(1..n),
        Some("HELLO") => {
            if let Some(i) = (1..n).find(|&i| up(i).as_deref() == Some("AUTH")) {
                after(&mut hits, i, 2);
            }
        }
        Some("MIGRATE") => {
            for i in 1..n {
                match up(i).as_deref() {
                    Some("AUTH") => after(&mut hits, i, 1),
                    Some("AUTH2") => after(&mut hits, i, 2),
                    _ => {}
                }
            }
        }
        Some("CONFIG") if up(1).as_deref() == Some("SET") => {
            if n.is_multiple_of(2) {
                let mut i = 2;
                while i + 1 < n {
                    if secret_config_name(tok(i)) {
                        hits.push(i + 1);
                    }
                    i += 2;
                }
            } else if let Some(i) = (2..n).find(|&i| secret_config_name(tok(i))) {
                hits.extend(i + 1..n);
            }
        }
        // From the user name on: a rule is never a user name, and a bare
        // `ACL SETUSER >pw` has none.
        Some("ACL") if up(1).as_deref() == Some("SETUSER") => {
            for i in 2..n {
                let t = tok(i);
                if t.len() > 1 && t.starts_with(['>', '<', '#', '!']) {
                    hits.push(i);
                }
            }
        }
        _ => {
            for i in 1..n {
                let t = tok(i);
                let u = t.to_ascii_uppercase();
                if u == "AUTH2" {
                    after(&mut hits, i, 2);
                } else if SECRET_ARG_KEYWORDS.contains(&u.as_str()) || secret_config_name(t) {
                    if t.contains('=') {
                        if t.split_once('=').is_some_and(|(_, v)| !v.is_empty()) {
                            hits.push(i);
                        }
                    } else {
                        after(&mut hits, i, 1);
                    }
                }
            }
        }
    }
    hits.retain(|&i| i >= 1 && i < n);
    hits.sort_unstable();
    hits.dedup();
    hits
}

/// The masked form of one credential argument, keeping its shape:
/// `>REDACTED` for an ACL password rule, `name=REDACTED` for a secret
/// `name=value`, else `REDACTED`.
pub fn mask_secret_arg(token: &str) -> String {
    if let Some(first @ ('>' | '<' | '#' | '!')) = token.chars().next() {
        return format!("{first}{REDACTED}");
    }
    match token.split_once('=') {
        Some((name, _)) if secret_key(name) => format!("{name}={REDACTED}"),
        _ => REDACTED.to_string(),
    }
}
