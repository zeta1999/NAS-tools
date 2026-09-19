//! Read-only WebDAV on the same gateway (SPECS §8).
//!
//! `OPTIONS` / `PROPFIND` / `HEAD` / `GET`. Writes are 405 — the mount is
//! read-only in v0. TCP uses Basic against the same `gateway.json` secret
//! as SigV4; a unix socket is already the credential.

use crate::hmac::{b64_decode, ct_eq};
use crate::http1::{write_empty, write_response, write_response_with, Request};
use crate::s3::{face_err, write_object_get, Buckets, FaceError, ObjectInfo, Route};
use crate::sigv4::Creds;
use std::collections::BTreeSet;
use std::io::Write;

pub fn is_dav_method(method: &str) -> bool {
    matches!(method, "OPTIONS" | "PROPFIND")
}

/// TCP: WebDAV verbs, or a Basic Authorization (Finder / rclone).
pub fn wants_dav(req: &Request) -> bool {
    let method = req.method.to_ascii_uppercase();
    if is_dav_method(&method) {
        return true;
    }
    req.headers
        .get("authorization")
        .is_some_and(|v| v.as_bytes().starts_with(b"Basic "))
}

pub fn check_basic(creds: &Creds, req: &Request) -> Result<(), BasicError> {
    let Some(h) = req.headers.get("authorization") else {
        return Err(BasicError::Missing);
    };
    let raw = h.strip_prefix("Basic ").ok_or(BasicError::Missing)?;
    let bytes = b64_decode(raw).ok_or(BasicError::Malformed)?;
    let s = String::from_utf8(bytes).map_err(|_| BasicError::Malformed)?;
    let (user, pass) = s.split_once(':').ok_or(BasicError::Malformed)?;
    if ct_eq(user.as_bytes(), creds.access_key_id.as_bytes())
        && ct_eq(pass.as_bytes(), creds.secret_access_key.as_bytes())
    {
        Ok(())
    } else {
        Err(BasicError::Mismatch)
    }
}

#[derive(Debug)]
pub enum BasicError {
    Missing,
    Malformed,
    Mismatch,
}

impl std::fmt::Display for BasicError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Missing => write!(f, "Basic authentication required"),
            Self::Malformed => write!(f, "malformed Authorization"),
            Self::Mismatch => write!(f, "Basic credentials do not match"),
        }
    }
}

pub fn write_unauthorized<W: Write>(w: W) -> Result<(), crate::http1::HttpError> {
    write_response_with(
        w,
        401,
        "Unauthorized",
        "text/plain",
        &[("WWW-Authenticate", "Basic realm=\"nas\"")],
        b"unauthorized",
    )?;
    Ok(())
}

pub fn dispatch<B: Buckets, W: Write>(
    buckets: &B,
    req: &Request,
    w: W,
) -> Result<(), crate::http1::HttpError> {
    let method = req.method.to_ascii_uppercase();
    match (method.as_str(), crate::s3::route(&req.path, &req.query)) {
        ("OPTIONS", _) => write_options(w),
        ("PROPFIND", route) => propfind(buckets, req, route, w),
        ("GET", Route::Object { bucket, key }) => write_object_get(
            buckets,
            bucket,
            key,
            req.headers.get("range").map(String::as_str),
            w,
        ),
        ("HEAD", Route::Object { bucket, key }) => match buckets.head(bucket, key) {
            Ok(n) => write_head(w, n),
            Err(e) => face_err(w, e),
        },
        ("HEAD", Route::ListObjects { bucket, .. }) => match buckets.list(bucket, "") {
            Ok(_) => {
                write_empty(w, 200, "OK")?;
                Ok(())
            }
            Err(e) => face_err(w, e),
        },
        ("HEAD", Route::ListBuckets) => {
            write_empty(w, 200, "OK")?;
            Ok(())
        }
        ("GET", Route::ListBuckets) | ("GET", Route::ListObjects { .. }) => {
            // A GET on a collection is not a download; Finder uses PROPFIND.
            write_response(
                w,
                405,
                "Method Not Allowed",
                "text/plain",
                b"use PROPFIND on a collection",
            )?;
            Ok(())
        }
        ("PUT", _)
        | ("DELETE", _)
        | ("MKCOL", _)
        | ("MOVE", _)
        | ("COPY", _)
        | ("PROPPATCH", _) => {
            write_response(
                w,
                405,
                "Method Not Allowed",
                "text/plain",
                b"this WebDAV face is read-only (SPECS 8)",
            )?;
            Ok(())
        }
        _ => {
            write_response(w, 405, "Method Not Allowed", "text/plain", b"not allowed")?;
            Ok(())
        }
    }
}

fn write_head<W: Write>(mut w: W, n: u64) -> Result<(), crate::http1::HttpError> {
    write!(
        w,
        "HTTP/1.1 200 OK\r\nContent-Length: {n}\r\nContent-Type: application/octet-stream\r\nDAV: 1\r\nConnection: close\r\n\r\n"
    )?;
    w.flush()?;
    Ok(())
}

fn write_options<W: Write>(w: W) -> Result<(), crate::http1::HttpError> {
    write_response_with(
        w,
        200,
        "OK",
        "text/plain",
        &[
            ("DAV", "1"),
            ("Allow", "OPTIONS, PROPFIND, GET, HEAD"),
            ("MS-Author-Via", "DAV"),
        ],
        b"",
    )?;
    Ok(())
}

fn propfind<B: Buckets, W: Write>(
    buckets: &B,
    req: &Request,
    route: Route<'_>,
    w: W,
) -> Result<(), crate::http1::HttpError> {
    let depth = req.headers.get("depth").map(String::as_str).unwrap_or("1");
    let include_children = depth != "0";
    let mut responses = Vec::new();
    match route {
        Route::ListBuckets => {
            responses.push(prop_collection("/", None));
            if include_children {
                let names = match buckets.list_buckets() {
                    Ok(n) => n,
                    Err(e) => return face_err(w, e),
                };
                for n in names {
                    responses.push(prop_collection(&format!("/{n}/"), None));
                }
            }
        }
        Route::ListObjects { bucket, prefix } => {
            if !prefix.is_empty() {
                return object_or_collection(buckets, bucket, &prefix, include_children, w);
            }
            match buckets.list(bucket, "") {
                Ok(_) => {}
                Err(e) => return face_err(w, e),
            }
            responses.push(prop_collection(&format!("/{bucket}/"), None));
            if include_children {
                if let Err(e) =
                    append_children(buckets, bucket, "", &format!("/{bucket}/"), &mut responses)
                {
                    return face_err(w, e);
                }
            }
        }
        Route::Object { bucket, key } => {
            return object_or_collection(buckets, bucket, key, include_children, w);
        }
    }
    write_multistatus(w, &responses)
}

fn object_or_collection<B: Buckets, W: Write>(
    buckets: &B,
    bucket: &str,
    key: &str,
    include_children: bool,
    w: W,
) -> Result<(), crate::http1::HttpError> {
    let items = match buckets.list(bucket, key) {
        Ok(i) => i,
        Err(e) => return face_err(w, e),
    };
    let exact = items.iter().find(|o| o.key == key && !o.tombstone).cloned();
    let child_prefix = if key.ends_with('/') {
        key.to_string()
    } else {
        format!("{key}/")
    };
    let has_children = items
        .iter()
        .any(|o| !o.tombstone && o.key.starts_with(&child_prefix));
    if exact.is_none() && !has_children {
        return face_err(w, FaceError::NotFound(key.into()));
    }
    let mut responses = Vec::new();
    if let Some(o) = exact {
        responses.push(prop_file(
            &format!("/{bucket}/{}", href_encode(&o.key)),
            o.size,
        ));
    } else {
        let href = format!("/{bucket}/{}", href_encode(key.trim_end_matches('/')));
        responses.push(prop_collection(&format!("{href}/"), None));
        if include_children {
            if let Err(e) = append_children(
                buckets,
                bucket,
                &child_prefix,
                &format!("{href}/"),
                &mut responses,
            ) {
                return face_err(w, e);
            }
        }
    }
    write_multistatus(w, &responses)
}

fn append_children<B: Buckets>(
    buckets: &B,
    bucket: &str,
    prefix: &str,
    href_base: &str,
    out: &mut Vec<String>,
) -> Result<(), FaceError> {
    let items = buckets.list(bucket, prefix)?;
    let mut dirs = BTreeSet::new();
    let mut files: Vec<&ObjectInfo> = Vec::new();
    for o in &items {
        if o.tombstone {
            continue;
        }
        let rest = match o.key.strip_prefix(prefix) {
            Some(r) if !r.is_empty() => r,
            _ => continue,
        };
        match rest.split_once('/') {
            Some((dir, _)) if !dir.is_empty() => {
                dirs.insert(dir.to_string());
            }
            _ => files.push(o),
        }
    }
    for d in dirs {
        out.push(prop_collection(
            &format!("{href_base}{}/", href_encode(&d)),
            None,
        ));
    }
    for o in files {
        let name = o.key.strip_prefix(prefix).unwrap_or(o.key.as_str());
        out.push(prop_file(
            &format!("{href_base}{}", href_encode(name)),
            o.size,
        ));
    }
    Ok(())
}

fn xml_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            _ => out.push(c),
        }
    }
    out
}

fn href_encode(s: &str) -> String {
    let mut out = String::new();
    for b in s.as_bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'/' | b'~' => {
                out.push(*b as char);
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

fn prop_collection(href: &str, size: Option<u64>) -> String {
    let len = size
        .map(|n| format!("<D:getcontentlength>{n}</D:getcontentlength>"))
        .unwrap_or_default();
    format!(
        "<D:response><D:href>{}</D:href><D:propstat><D:prop>\
         <D:resourcetype><D:collection/></D:resourcetype>{len}\
         </D:prop><D:status>HTTP/1.1 200 OK</D:status></D:propstat></D:response>",
        xml_escape(href)
    )
}

fn prop_file(href: &str, size: u64) -> String {
    format!(
        "<D:response><D:href>{}</D:href><D:propstat><D:prop>\
         <D:getcontentlength>{size}</D:getcontentlength>\
         <D:getcontenttype>application/octet-stream</D:getcontenttype>\
         <D:resourcetype/>\
         </D:prop><D:status>HTTP/1.1 200 OK</D:status></D:propstat></D:response>",
        xml_escape(href)
    )
}

fn write_multistatus<W: Write>(w: W, responses: &[String]) -> Result<(), crate::http1::HttpError> {
    let mut body =
        String::from("<?xml version=\"1.0\" encoding=\"utf-8\"?><D:multistatus xmlns:D=\"DAV:\">");
    for r in responses {
        body.push_str(r);
    }
    body.push_str("</D:multistatus>");
    write_response_with(
        w,
        207,
        "Multi-Status",
        "application/xml; charset=utf-8",
        &[("DAV", "1")],
        body.as_bytes(),
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wants_dav_on_verbs_and_basic() {
        let mut req = Request {
            method: "PROPFIND".into(),
            path: "/".into(),
            query: String::new(),
            headers: Default::default(),
            body: vec![],
        };
        assert!(wants_dav(&req));
        req.method = "GET".into();
        assert!(!wants_dav(&req));
        req.headers
            .insert("authorization".into(), "Basic abc".into());
        assert!(wants_dav(&req));
    }
}
