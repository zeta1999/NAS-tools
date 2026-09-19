//! AWS Signature Version 4 (SPECS §2.1).
//!
//! TCP to the gateway is loopback, not a security boundary: any local process
//! can connect. SigV4 against a locally generated key pair is what makes an
//! unauthenticated process a refusal rather than a reader.

use crate::hmac::{ct_eq, hex_decode, hex_encode, hmac_sha256, sha256};
use std::collections::BTreeMap;

pub const UNSIGNED: &str = "UNSIGNED-PAYLOAD";
pub const ALGORITHM: &str = "AWS4-HMAC-SHA256";

#[derive(Debug, Clone)]
pub struct Creds {
    pub access_key_id: String,
    pub secret_access_key: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthError {
    Missing,
    Malformed(&'static str),
    UnknownKey,
    BadSignature,
    PayloadHash,
}

impl std::fmt::Display for AuthError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Missing => write!(f, "no Authorization header"),
            Self::Malformed(s) => write!(f, "malformed Authorization: {s}"),
            Self::UnknownKey => write!(f, "unknown access key"),
            Self::BadSignature => write!(f, "signature does not match"),
            Self::PayloadHash => write!(f, "x-amz-content-sha256 does not match the body"),
        }
    }
}

#[derive(Debug, Clone)]
pub struct SignedRequest<'a> {
    pub method: &'a str,
    pub path: &'a str,
    pub query: &'a str,
    pub headers: &'a BTreeMap<String, String>,
    pub body: &'a [u8],
}

/// Headers are stored lower-cased. Multi-value is joined with a comma, AWS-style.
pub fn header<'a>(headers: &'a BTreeMap<String, String>, name: &str) -> Option<&'a str> {
    headers.get(&name.to_ascii_lowercase()).map(String::as_str)
}

pub fn sign(creds: &Creds, region: &str, req: &SignedRequest<'_>) -> String {
    let (canon, signed, _payload_hash) = canonical(req);
    let date = amz_date(req.headers).unwrap_or("19700101T000000Z");
    let short = &date[..8.min(date.len())];
    let scope = format!("{short}/{region}/s3/aws4_request");
    let sts = string_to_sign(date, &scope, &canon);
    let sig = hex_encode(&signing_sig(creds, short, region, &sts));
    format!(
        "{ALGORITHM} Credential={}/{scope}, SignedHeaders={signed}, Signature={sig}",
        creds.access_key_id
    )
}

fn signing_sig(creds: &Creds, short_date: &str, region: &str, string_to_sign: &str) -> [u8; 32] {
    let mut k = Vec::with_capacity(4 + creds.secret_access_key.len());
    k.extend_from_slice(b"AWS4");
    k.extend_from_slice(creds.secret_access_key.as_bytes());
    let k_date = hmac_sha256(&k, short_date.as_bytes());
    let k_region = hmac_sha256(&k_date, region.as_bytes());
    let k_service = hmac_sha256(&k_region, b"s3");
    let k_signing = hmac_sha256(&k_service, b"aws4_request");
    hmac_sha256(&k_signing, string_to_sign.as_bytes())
}

fn string_to_sign(date: &str, scope: &str, canonical: &str) -> String {
    format!(
        "{ALGORITHM}\n{date}\n{scope}\n{}",
        hex_encode(&sha256(canonical.as_bytes()))
    )
}

fn amz_date(headers: &BTreeMap<String, String>) -> Option<&str> {
    header(headers, "x-amz-date").or_else(|| header(headers, "date"))
}

fn payload_hash(req: &SignedRequest<'_>) -> Result<String, AuthError> {
    match header(req.headers, "x-amz-content-sha256") {
        Some(UNSIGNED) => Ok(UNSIGNED.to_string()),
        Some(hex) if hex.len() == 64 => {
            let want = hex_decode(hex).ok_or(AuthError::PayloadHash)?;
            if !ct_eq(&want, &sha256(req.body)) {
                return Err(AuthError::PayloadHash);
            }
            Ok(hex.to_ascii_lowercase())
        }
        Some(_) => Err(AuthError::PayloadHash),
        None => Ok(hex_encode(&sha256(req.body))),
    }
}

fn uri_encode(s: &str, encode_slash: bool) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char);
            }
            b'/' if !encode_slash => out.push('/'),
            _ => {
                out.push('%');
                out.push_str(&hex_encode(&[b]).to_ascii_uppercase());
            }
        }
    }
    out
}

fn canonical(req: &SignedRequest<'_>) -> (String, String, String) {
    let payload = match payload_hash(req) {
        Ok(p) => p,
        Err(_) => hex_encode(&sha256(req.body)),
    };
    let signed: Vec<String> = req
        .headers
        .keys()
        .filter(|k| {
            *k == "host"
                || *k == "x-amz-date"
                || *k == "x-amz-content-sha256"
                || *k == "content-type"
                || *k == "range"
        })
        .cloned()
        .collect();
    // When verifying we use the SignedHeaders list from the Authorization
    // header, not this guess. `canonical` is also used by `sign`, which
    // signs the usual S3 set.
    let signed_str = signed.join(";");
    let mut canon_headers = String::new();
    for k in &signed {
        let v = req.headers.get(k).map(|s| s.trim()).unwrap_or("");
        canon_headers.push_str(k);
        canon_headers.push(':');
        canon_headers.push_str(v);
        canon_headers.push('\n');
    }
    let path = uri_encode(req.path, false);
    let query = canonical_query(req.query);
    let canon = format!(
        "{}\n{}\n{}\n{}\n{}\n{}",
        req.method.to_ascii_uppercase(),
        if path.is_empty() { "/" } else { &path },
        query,
        canon_headers,
        signed_str,
        payload
    );
    (canon, signed_str, payload)
}

fn canonical_with_signed(req: &SignedRequest<'_>, signed: &[&str], payload: &str) -> String {
    let mut canon_headers = String::new();
    for k in signed {
        let v = header(req.headers, k).unwrap_or("").trim();
        canon_headers.push_str(&k.to_ascii_lowercase());
        canon_headers.push(':');
        canon_headers.push_str(v);
        canon_headers.push('\n');
    }
    let path = uri_encode(req.path, false);
    format!(
        "{}\n{}\n{}\n{}\n{}\n{}",
        req.method.to_ascii_uppercase(),
        if path.is_empty() { "/" } else { &path },
        canonical_query(req.query),
        canon_headers,
        signed.join(";"),
        payload
    )
}

/// AWS canonical query string: decode, encode, sort by name then value.
///
/// The client signs this form, not the order the URL happened to use, so a
/// verifier that echoed `req.query` would refuse a legal `aws s3 ls` the
/// moment the SDK put `prefix=` before `list-type=`.
fn canonical_query(query: &str) -> String {
    if query.is_empty() {
        return String::new();
    }
    let mut parts: Vec<(String, String)> = query
        .split('&')
        .filter(|p| !p.is_empty())
        .map(|p| match p.split_once('=') {
            Some((k, v)) => (
                uri_encode(&decode_component(k), true),
                uri_encode(&decode_component(v), true),
            ),
            None => (uri_encode(&decode_component(p), true), String::new()),
        })
        .collect();
    parts.sort();
    parts
        .into_iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join("&")
}

fn decode_component(s: &str) -> String {
    crate::http1::percent_decode(&s.replace('+', " "))
}

struct AuthParts<'a> {
    access_key: &'a str,
    short_date: &'a str,
    region: &'a str,
    signed: Vec<&'a str>,
    signature: &'a str,
}

fn parse_authorization(value: &str) -> Result<AuthParts<'_>, AuthError> {
    let rest = value
        .strip_prefix(ALGORITHM)
        .ok_or(AuthError::Malformed("algorithm"))?
        .trim();
    let mut access_key = None;
    let mut short_date = None;
    let mut region = None;
    let mut signed = None;
    let mut signature = None;
    for part in rest.split(',') {
        let part = part.trim();
        if let Some(c) = part.strip_prefix("Credential=") {
            // AKID/YYYYMMDD/region/s3/aws4_request
            let mut it = c.split('/');
            access_key = it.next();
            short_date = it.next();
            region = it.next();
            if it.next() != Some("s3") || it.next() != Some("aws4_request") || it.next().is_some() {
                return Err(AuthError::Malformed("credential scope"));
            }
        } else if let Some(s) = part.strip_prefix("SignedHeaders=") {
            signed = Some(s.split(';').collect::<Vec<_>>());
        } else if let Some(s) = part.strip_prefix("Signature=") {
            signature = Some(s);
        }
    }
    Ok(AuthParts {
        access_key: access_key.ok_or(AuthError::Malformed("credential"))?,
        short_date: short_date.ok_or(AuthError::Malformed("date"))?,
        region: region.ok_or(AuthError::Malformed("region"))?,
        signed: signed.ok_or(AuthError::Malformed("signed headers"))?,
        signature: signature.ok_or(AuthError::Malformed("signature"))?,
    })
}

pub fn verify(creds: &Creds, req: &SignedRequest<'_>) -> Result<(), AuthError> {
    let auth = header(req.headers, "authorization").ok_or(AuthError::Missing)?;
    let parts = parse_authorization(auth)?;
    if parts.access_key != creds.access_key_id {
        return Err(AuthError::UnknownKey);
    }
    let payload = payload_hash(req)?;
    let date = amz_date(req.headers).ok_or(AuthError::Malformed("x-amz-date"))?;
    if !date.starts_with(parts.short_date) {
        return Err(AuthError::Malformed("date mismatch"));
    }
    let scope = format!("{}/{}/s3/aws4_request", parts.short_date, parts.region);
    let canon = canonical_with_signed(req, &parts.signed, &payload);
    let sts = string_to_sign(date, &scope, &canon);
    let expect = signing_sig(creds, parts.short_date, parts.region, &sts);
    let got = hex_decode(parts.signature).ok_or(AuthError::Malformed("signature hex"))?;
    if !ct_eq(&expect, &got) {
        return Err(AuthError::BadSignature);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn creds() -> Creds {
        Creds {
            access_key_id: "AKIDEXAMPLE".into(),
            secret_access_key: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY".into(),
        }
    }

    fn headers(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_ascii_lowercase(), (*v).to_string()))
            .collect()
    }

    #[test]
    fn a_request_we_signed_verifies() {
        let c = creds();
        let mut h = headers(&[
            ("host", "127.0.0.1:9000"),
            ("x-amz-date", "20130524T000000Z"),
            ("x-amz-content-sha256", UNSIGNED),
        ]);
        let req = SignedRequest {
            method: "GET",
            path: "/",
            query: "",
            headers: &h,
            body: b"",
        };
        let auth = {
            // sign needs the headers without Authorization
            sign(&c, "us-east-1", &req)
        };
        h.insert("authorization".into(), auth);
        let req = SignedRequest {
            method: "GET",
            path: "/",
            query: "",
            headers: &h,
            body: b"",
        };
        assert_eq!(verify(&c, &req), Ok(()));
    }

    #[test]
    fn a_flipped_signature_bit_is_refused() {
        let c = creds();
        let mut h = headers(&[
            ("host", "127.0.0.1:9000"),
            ("x-amz-date", "20130524T000000Z"),
            ("x-amz-content-sha256", UNSIGNED),
        ]);
        let req = SignedRequest {
            method: "GET",
            path: "/",
            query: "",
            headers: &h,
            body: b"",
        };
        let mut auth = sign(&c, "us-east-1", &req);
        auth.pop();
        auth.push('0');
        h.insert("authorization".into(), auth);
        let req = SignedRequest {
            method: "GET",
            path: "/",
            query: "",
            headers: &h,
            body: b"",
        };
        assert_eq!(verify(&c, &req), Err(AuthError::BadSignature));
    }

    #[test]
    fn missing_authorization_is_missing_not_a_bad_signature() {
        let h = headers(&[("host", "127.0.0.1")]);
        let req = SignedRequest {
            method: "GET",
            path: "/",
            query: "",
            headers: &h,
            body: b"",
        };
        assert_eq!(verify(&creds(), &req), Err(AuthError::Missing));
    }

    #[test]
    fn a_wrong_payload_hash_is_refused_before_the_signature() {
        let h = headers(&[
            ("host", "127.0.0.1"),
            ("x-amz-date", "20130524T000000Z"),
            (
                "x-amz-content-sha256",
                "0000000000000000000000000000000000000000000000000000000000000000",
            ),
            (
                "authorization",
                "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20130524/us-east-1/s3/aws4_request, \
                 SignedHeaders=host, Signature=00",
            ),
        ]);
        let req = SignedRequest {
            method: "PUT",
            path: "/b/k",
            query: "",
            headers: &h,
            body: b"not empty",
        };
        assert_eq!(verify(&creds(), &req), Err(AuthError::PayloadHash));
    }

    #[test]
    fn query_order_does_not_break_the_signature() {
        let c = creds();
        let mut h = headers(&[
            ("host", "127.0.0.1:9000"),
            ("x-amz-date", "20130524T000000Z"),
            ("x-amz-content-sha256", UNSIGNED),
        ]);
        // Sign with prefix first; verify with list-type first. Same params.
        let signed_as = SignedRequest {
            method: "GET",
            path: "/photos",
            query: "prefix=a&list-type=2",
            headers: &h,
            body: b"",
        };
        let auth = sign(&c, "us-east-1", &signed_as);
        h.insert("authorization".into(), auth);
        let arrived_as = SignedRequest {
            method: "GET",
            path: "/photos",
            query: "list-type=2&prefix=a",
            headers: &h,
            body: b"",
        };
        assert_eq!(verify(&c, &arrived_as), Ok(()));
    }
}
