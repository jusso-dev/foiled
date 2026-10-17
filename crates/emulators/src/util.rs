//! Small helpers shared by the emulators. No I/O.

use sha2::{Digest, Sha256};

/// Lossy UTF-8 of at most `max` bytes, cut on a character boundary.
pub(crate) fn clip(bytes: &[u8], max: usize) -> String {
    let s = String::from_utf8_lossy(&bytes[..bytes.len().min(max)]);
    let mut s = s.into_owned();
    if s.len() > max {
        let mut end = max;
        while !s.is_char_boundary(end) {
            end -= 1;
        }
        s.truncate(end);
    }
    s
}

pub(crate) fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

/// xorshift64*: small, fast, not cryptographic. Used for jitter and
/// per-start values such as a fake process id, never for secrets.
#[derive(Debug, Clone)]
pub struct Rng(u64);

impl Rng {
    pub fn seeded(seed: u64) -> Self {
        Rng(seed.max(1))
    }

    pub fn from_entropy() -> Self {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0);
        let local = 0u8;
        let addr = &local as *const u8 as u64;
        Rng::seeded(nanos ^ addr.rotate_left(32) ^ u64::from(std::process::id()) << 17)
    }

    pub fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    /// Uniform-ish value in `lo..=hi`.
    pub fn range(&mut self, lo: u64, hi: u64) -> u64 {
        if hi <= lo {
            return lo;
        }
        lo + self.next_u64() % (hi - lo + 1)
    }

    pub fn hex(&mut self, len: usize) -> String {
        let mut s = String::with_capacity(len + 16);
        while s.len() < len {
            s.push_str(&format!("{:016x}", self.next_u64()));
        }
        s.truncate(len);
        s
    }
}

/// Glob match with `*`, `?` and `\` escapes, as Redis uses for KEYS and
/// CONFIG GET. Iterative with one backtrack point, so hostile patterns
/// cannot blow up (O(pattern x text)).
pub(crate) fn glob_match(pattern: &[u8], text: &[u8]) -> bool {
    let (mut p, mut t) = (0usize, 0usize);
    let mut star: Option<(usize, usize)> = None;
    while t < text.len() {
        if p < pattern.len() {
            match pattern[p] {
                b'*' => {
                    star = Some((p, t));
                    p += 1;
                    continue;
                }
                b'?' => {
                    p += 1;
                    t += 1;
                    continue;
                }
                b'\\' if p + 1 < pattern.len() => {
                    if pattern[p + 1] == text[t] {
                        p += 2;
                        t += 1;
                        continue;
                    }
                }
                c if c == text[t] => {
                    p += 1;
                    t += 1;
                    continue;
                }
                _ => {}
            }
        }
        match star {
            Some((sp, st)) => {
                p = sp + 1;
                t = st + 1;
                star = Some((sp, st + 1));
            }
            None => return false,
        }
    }
    pattern[p.min(pattern.len())..].iter().all(|&c| c == b'*')
}

/// Days since 1970-01-01 to (year, month, day). Howard Hinnant's algorithm.
pub(crate) fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// (year, month, day) to days since 1970-01-01.
pub(crate) fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y.rem_euclid(400);
    let m = i64::from(m);
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + i64::from(d) - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// IMF-fixdate for the HTTP `Date` header, from Unix seconds.
pub(crate) fn http_date(unix_secs: i64) -> String {
    const DAYS: [&str; 7] = ["Thu", "Fri", "Sat", "Sun", "Mon", "Tue", "Wed"];
    const MONTHS: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    let days = unix_secs.div_euclid(86_400);
    let secs = unix_secs.rem_euclid(86_400);
    let (y, m, d) = civil_from_days(days);
    format!(
        "{}, {:02} {} {} {:02}:{:02}:{:02} GMT",
        DAYS[days.rem_euclid(7) as usize],
        d,
        MONTHS[(m - 1) as usize],
        y,
        secs / 3600,
        (secs % 3600) / 60,
        secs % 60
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clip_respects_char_boundaries() {
        assert_eq!(clip("héllo".as_bytes(), 2), "h");
        assert_eq!(clip(b"abc", 10), "abc");
        assert_eq!(clip(&[0xff, b'a'], 10), "\u{fffd}a");
    }

    #[test]
    fn glob_matches_like_redis() {
        assert!(glob_match(b"*", b"anything"));
        assert!(glob_match(b"user:*", b"user:42"));
        assert!(glob_match(b"h?llo", b"hello"));
        assert!(!glob_match(b"h?llo", b"hllo"));
        assert!(glob_match(b"*dir*", b"dir"));
        assert!(glob_match(b"a\\*", b"a*"));
        assert!(!glob_match(b"a\\*", b"ab"));
        assert!(!glob_match(b"abc", b"abcd"));
        assert!(glob_match(b"", b""));
        assert!(!glob_match(b"", b"x"));
    }

    #[test]
    fn hostile_glob_is_fast() {
        let pattern = b"*a*a*a*a*a*a*a*a*a*a*a*a*b".to_vec();
        let text = vec![b'a'; 4096];
        let start = std::time::Instant::now();
        assert!(!glob_match(&pattern, &text));
        assert!(start.elapsed() < std::time::Duration::from_secs(1));
    }

    #[test]
    fn dates_round_trip_and_format() {
        assert_eq!(http_date(0), "Thu, 01 Jan 1970 00:00:00 GMT");
        assert_eq!(http_date(1_792_285_323), "Sun, 18 Oct 2026 01:02:03 GMT");
        for days in [-1000, 0, 59, 10_957, 20_744, 30_000] {
            let (y, m, d) = civil_from_days(days);
            assert_eq!(days_from_civil(y, m, d), days);
        }
    }

    #[test]
    fn rng_range_stays_in_bounds() {
        let mut r = Rng::seeded(7);
        for _ in 0..1000 {
            let v = r.range(3, 9);
            assert!((3..=9).contains(&v));
        }
        assert_eq!(r.range(5, 5), 5);
        assert_eq!(r.hex(40).len(), 40);
    }
}
