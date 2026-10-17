//! AWS Signature Version 4 query-string presigning, used to mint
//! short-lived R2 upload URLs for one object (#9). R2's S3 API accepts SigV4
//! with region `auto`. Pure functions: the caller supplies the time.

use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

type HmacSha256 = Hmac<Sha256>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Credentials {
    pub access_key_id: String,
    pub secret_access_key: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PresignRequest<'a> {
    pub method: &'a str,
    /// Host header value, for example `<account>.r2.cloudflarestorage.com`.
    pub host: &'a str,
    /// Absolute path, already in canonical form (`/bucket/key`). Each segment
    /// is percent-encoded by [`presign`].
    pub path: &'a str,
    pub region: &'a str,
    pub service: &'a str,
    /// `YYYYMMDDTHHMMSSZ`.
    pub amz_date: &'a str,
    pub expires_secs: u32,
    /// Extra signed headers besides `host`, lowercase names.
    pub extra_headers: &'a [(&'a str, &'a str)],
}

/// RFC 3986 unreserved characters pass; everything else is `%XX`.
pub fn uri_encode(s: &str, encode_slash: bool) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            b'/' if !encode_slash => out.push('/'),
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

fn hmac(key: &[u8], data: &str) -> Vec<u8> {
    let mut m = HmacSha256::new_from_slice(key).expect("HMAC accepts any key length");
    m.update(data.as_bytes());
    m.finalize().into_bytes().to_vec()
}

/// Returns the full query string (without `?`) including `X-Amz-Signature`.
pub fn presign_query(req: &PresignRequest<'_>, creds: &Credentials) -> String {
    let date = &req.amz_date[..8];
    let scope = format!("{date}/{}/{}/aws4_request", req.region, req.service);

    let mut headers: Vec<(String, String)> = vec![("host".into(), req.host.to_string())];
    headers.extend(
        req.extra_headers
            .iter()
            .map(|(k, v)| (k.to_ascii_lowercase(), v.trim().to_string())),
    );
    headers.sort();
    let signed_headers = headers
        .iter()
        .map(|(k, _)| k.as_str())
        .collect::<Vec<_>>()
        .join(";");
    let canonical_headers: String = headers.iter().map(|(k, v)| format!("{k}:{v}\n")).collect();

    let mut query = [
        ("X-Amz-Algorithm", "AWS4-HMAC-SHA256".to_string()),
        (
            "X-Amz-Credential",
            format!("{}/{scope}", creds.access_key_id),
        ),
        ("X-Amz-Date", req.amz_date.to_string()),
        ("X-Amz-Expires", req.expires_secs.to_string()),
        ("X-Amz-SignedHeaders", signed_headers.clone()),
    ]
    .map(|(k, v)| (uri_encode(k, true), uri_encode(&v, true)));
    query.sort();
    let canonical_query = query
        .iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join("&");

    let canonical_request = format!(
        "{}\n{}\n{canonical_query}\n{canonical_headers}\n{signed_headers}\nUNSIGNED-PAYLOAD",
        req.method,
        uri_encode(req.path, false),
    );
    let string_to_sign = format!(
        "AWS4-HMAC-SHA256\n{}\n{scope}\n{}",
        req.amz_date,
        hex::encode(Sha256::digest(canonical_request.as_bytes()))
    );
    let k_date = hmac(format!("AWS4{}", creds.secret_access_key).as_bytes(), date);
    let k_region = hmac(&k_date, req.region);
    let k_service = hmac(&k_region, req.service);
    let k_signing = hmac(&k_service, "aws4_request");
    let signature = hex::encode(hmac(&k_signing, &string_to_sign));
    format!("{canonical_query}&X-Amz-Signature={signature}")
}

/// A complete `https://` presigned URL.
pub fn presign(req: &PresignRequest<'_>, creds: &Credentials) -> String {
    format!(
        "https://{}{}?{}",
        req.host,
        uri_encode(req.path, false),
        presign_query(req, creds)
    )
}

/// Format Unix milliseconds as `YYYYMMDDTHHMMSSZ` (UTC), without a date
/// library so it builds anywhere.
pub fn amz_date(unix_ms: i64) -> String {
    let secs = unix_ms.div_euclid(1000);
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    // Civil-from-days (Howard Hinnant), valid for the proleptic Gregorian calendar.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!(
        "{y:04}{m:02}{d:02}T{:02}{:02}{:02}Z",
        rem / 3600,
        (rem % 3600) / 60,
        rem % 60
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn aws_example_creds() -> Credentials {
        // The documented example credentials from the AWS SigV4 guide. Not real.
        Credentials {
            access_key_id: "AKIAIOSFODNN7EXAMPLE".into(),
            secret_access_key: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY".into(),
        }
    }

    #[test]
    fn matches_the_aws_documented_presigned_get_example() {
        // "Example: Presigned URL" in the S3 SigV4 query auth documentation.
        let req = PresignRequest {
            method: "GET",
            host: "examplebucket.s3.amazonaws.com",
            path: "/test.txt",
            region: "us-east-1",
            service: "s3",
            amz_date: "20130524T000000Z",
            expires_secs: 86_400,
            extra_headers: &[],
        };
        let q = presign_query(&req, &aws_example_creds());
        assert!(
            q.ends_with(
                "X-Amz-Signature=aeeed9bbccd4d02ee5c0109b86d86835f995330da4c265957d157751f604d404"
            ),
            "{q}"
        );
        assert!(q.contains(
            "X-Amz-Credential=AKIAIOSFODNN7EXAMPLE%2F20130524%2Fus-east-1%2Fs3%2Faws4_request"
        ));
    }

    #[test]
    fn signature_changes_with_method_path_and_expiry() {
        let base = PresignRequest {
            method: "PUT",
            host: "acct.r2.cloudflarestorage.com",
            path: "/foiled-evidence/t1/d1/_/network/abc",
            region: "auto",
            service: "s3",
            amz_date: "20261018T010203Z",
            expires_secs: 300,
            extra_headers: &[],
        };
        let c = aws_example_creds();
        let a = presign_query(&base, &c);
        assert_ne!(
            a,
            presign_query(
                &PresignRequest {
                    method: "GET",
                    ..base.clone()
                },
                &c
            )
        );
        assert_ne!(
            a,
            presign_query(
                &PresignRequest {
                    path: "/foiled-evidence/t1/d2/_/network/abc",
                    ..base.clone()
                },
                &c
            )
        );
        assert_ne!(
            a,
            presign_query(
                &PresignRequest {
                    expires_secs: 301,
                    ..base.clone()
                },
                &c
            )
        );
        let url = presign(&base, &c);
        assert!(url.starts_with("https://acct.r2.cloudflarestorage.com/foiled-evidence/t1/d1/_/network/abc?X-Amz-Algorithm=AWS4-HMAC-SHA256"));
    }

    #[test]
    fn encodes_like_aws() {
        assert_eq!(uri_encode("a b/c~", false), "a%20b/c~");
        assert_eq!(uri_encode("a/b", true), "a%2Fb");
    }

    #[test]
    fn formats_amz_dates() {
        assert_eq!(amz_date(1_369_353_600_000), "20130524T000000Z");
        assert_eq!(amz_date(1_792_285_323_000), "20261018T010203Z");
        assert_eq!(amz_date(951_782_400_000), "20000229T000000Z");
    }
}
