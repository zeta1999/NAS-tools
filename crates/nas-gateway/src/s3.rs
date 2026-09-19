//! Path-style S3 subset: ListBuckets, ListObjects, Get, Put, Head, Delete.

use crate::http1::{parse_byte_range, write_empty, write_response, write_response_with, Request};
use std::io::Write;

#[derive(Debug)]
pub enum FaceError {
    Refused(String),
    NotFound(String),
    Error(String),
}

impl std::fmt::Display for FaceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Refused(s) | Self::NotFound(s) | Self::Error(s) => write!(f, "{s}"),
        }
    }
}

#[derive(Debug, Clone)]
pub struct ObjectInfo {
    pub key: String,
    pub size: u64,
    pub tombstone: bool,
}

/// Result of a ranged GET. `end` is exclusive. `bytes_fetched` is what the
/// store actually opened, so a caller can check O(range) rather than O(file).
#[derive(Debug, Clone)]
pub struct RangeBody {
    pub data: Vec<u8>,
    pub total: u64,
    pub start: u64,
    pub end: u64,
    pub chunks_fetched: usize,
    pub bytes_fetched: u64,
}

pub trait Buckets {
    fn list_buckets(&self) -> Result<Vec<String>, FaceError>;
    fn list(&self, bucket: &str, prefix: &str) -> Result<Vec<ObjectInfo>, FaceError>;
    fn get(&self, bucket: &str, key: &str) -> Result<Vec<u8>, FaceError>;
    fn put(&self, bucket: &str, key: &str, body: &[u8]) -> Result<u64, FaceError>;
    fn delete(&self, bucket: &str, key: &str) -> Result<(), FaceError>;
    fn head(&self, bucket: &str, key: &str) -> Result<u64, FaceError>;

    /// Default path materialises the whole object then slices. A store that
    /// can skip chunks (the local bucket) overrides this.
    fn get_range(
        &self,
        bucket: &str,
        key: &str,
        start: u64,
        end: u64,
    ) -> Result<RangeBody, FaceError> {
        let body = self.get(bucket, key)?;
        let total = body.len() as u64;
        let start = start.min(total);
        let end = end.min(total).max(start);
        Ok(RangeBody {
            data: body[start as usize..end as usize].to_vec(),
            total,
            start,
            end,
            chunks_fetched: 1,
            bytes_fetched: total,
        })
    }
}

pub enum Route<'a> {
    ListBuckets,
    ListObjects { bucket: &'a str, prefix: String },
    Object { bucket: &'a str, key: &'a str },
}

pub fn route<'a>(path: &'a str, query: &'a str) -> Route<'a> {
    let p = path.trim_start_matches('/');
    if p.is_empty() {
        return Route::ListBuckets;
    }
    let prefix = query_param(query, "prefix")
        .map(crate::http1::percent_decode)
        .unwrap_or_default();
    match p.split_once('/') {
        None => Route::ListObjects { bucket: p, prefix },
        Some((bucket, "")) => Route::ListObjects { bucket, prefix },
        Some((bucket, key)) => Route::Object { bucket, key },
    }
}

fn query_param<'a>(query: &'a str, name: &str) -> Option<&'a str> {
    query.split('&').find_map(|p| {
        let (k, v) = p.split_once('=')?;
        (k == name).then_some(v)
    })
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

fn s3_error(code: &str, message: &str) -> Vec<u8> {
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
         <Error><Code>{}</Code><Message>{}</Message></Error>",
        xml_escape(code),
        xml_escape(message)
    )
    .into_bytes()
}

pub fn dispatch<B: Buckets, W: Write>(
    buckets: &B,
    req: &Request,
    mut w: W,
) -> Result<(), crate::http1::HttpError> {
    let method = req.method.to_ascii_uppercase();
    match (method.as_str(), route(&req.path, &req.query)) {
        ("GET", Route::ListBuckets) => {
            let names = match buckets.list_buckets() {
                Ok(n) => n,
                Err(e) => return face_err(w, e),
            };
            let mut body = String::from(
                "<?xml version=\"1.0\" encoding=\"UTF-8\"?><ListAllMyBucketsResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"><Buckets>",
            );
            for n in names {
                body.push_str("<Bucket><Name>");
                body.push_str(&xml_escape(&n));
                body.push_str("</Name></Bucket>");
            }
            body.push_str("</Buckets></ListAllMyBucketsResult>");
            write_response(w, 200, "OK", "application/xml", body.as_bytes())?;
        }
        ("HEAD", Route::ListBuckets) => write_empty(w, 200, "OK")?,
        ("HEAD", Route::ListObjects { bucket, .. }) => match buckets.list(bucket, "") {
            Ok(_) => write_empty(w, 200, "OK")?,
            Err(e) => face_err(w, e)?,
        },
        ("GET", Route::ListObjects { bucket, prefix }) => {
            let items = match buckets.list(bucket, &prefix) {
                Ok(i) => i,
                Err(e) => return face_err(w, e),
            };
            let live: Vec<_> = items.into_iter().filter(|o| !o.tombstone).collect();
            let mut body = format!(
                "<?xml version=\"1.0\" encoding=\"UTF-8\"?><ListBucketResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"><Name>{}</Name><Prefix>{}</Prefix><KeyCount>{}</KeyCount><MaxKeys>1000</MaxKeys><IsTruncated>false</IsTruncated>",
                xml_escape(bucket),
                xml_escape(&prefix),
                live.len()
            );
            for o in live {
                body.push_str("<Contents><Key>");
                body.push_str(&xml_escape(&o.key));
                body.push_str("</Key><Size>");
                body.push_str(&o.size.to_string());
                body.push_str("</Size></Contents>");
            }
            body.push_str("</ListBucketResult>");
            write_response(w, 200, "OK", "application/xml", body.as_bytes())?;
        }
        ("GET", Route::Object { bucket, key }) => {
            write_object_get(
                buckets,
                bucket,
                key,
                req.headers.get("range").map(String::as_str),
                w,
            )?;
        }
        ("HEAD", Route::Object { bucket, key }) => match buckets.head(bucket, key) {
            Ok(n) => {
                write!(
                    w,
                    "HTTP/1.1 200 OK\r\nContent-Length: {n}\r\nContent-Type: application/octet-stream\r\nConnection: close\r\n\r\n"
                )?;
                w.flush()?;
            }
            Err(e) => face_err(w, e)?,
        },
        ("PUT", Route::Object { bucket, key }) => match buckets.put(bucket, key, &req.body) {
            Ok(_) => write_empty(w, 200, "OK")?,
            Err(e) => face_err(w, e)?,
        },
        ("DELETE", Route::Object { bucket, key }) => match buckets.delete(bucket, key) {
            Ok(()) => write_empty(w, 204, "No Content")?,
            Err(e) => face_err(w, e)?,
        },
        _ => {
            write_response(
                w,
                405,
                "Method Not Allowed",
                "application/xml",
                &s3_error(
                    "MethodNotAllowed",
                    "this S3 face does not implement that verb",
                ),
            )?;
        }
    }
    Ok(())
}

/// GET an object, honouring a single `Range` header when present.
pub fn write_object_get<B: Buckets, W: Write>(
    buckets: &B,
    bucket: &str,
    key: &str,
    range: Option<&str>,
    w: W,
) -> Result<(), crate::http1::HttpError> {
    match range {
        None => match buckets.get(bucket, key) {
            Ok(body) => write_response(w, 200, "OK", "application/octet-stream", &body)?,
            Err(e) => face_err(w, e)?,
        },
        Some(rh) => match buckets.head(bucket, key) {
            Err(e) => face_err(w, e)?,
            Ok(total) => match parse_byte_range(rh, total) {
                Some((start, end)) => match buckets.get_range(bucket, key, start, end) {
                    Ok(rb) => {
                        let last = rb.end.saturating_sub(1);
                        let cr = format!("bytes {start}-{last}/{total}");
                        let chunks = rb.chunks_fetched.to_string();
                        let fetched = rb.bytes_fetched.to_string();
                        write_response_with(
                            w,
                            206,
                            "Partial Content",
                            "application/octet-stream",
                            &[
                                ("Content-Range", &cr),
                                ("X-Nas-Chunks-Fetched", &chunks),
                                ("X-Nas-Bytes-Fetched", &fetched),
                            ],
                            &rb.data,
                        )?;
                    }
                    Err(e) => face_err(w, e)?,
                },
                None => {
                    let cr = format!("bytes */{total}");
                    write_response_with(
                        w,
                        416,
                        "Range Not Satisfiable",
                        "text/plain",
                        &[("Content-Range", cr.as_str())],
                        b"",
                    )?;
                }
            },
        },
    }
    Ok(())
}

pub(crate) fn face_err<W: Write>(w: W, e: FaceError) -> Result<(), crate::http1::HttpError> {
    match e {
        FaceError::Refused(m) => write_response(
            w,
            403,
            "Forbidden",
            "application/xml",
            &s3_error("AccessDenied", &m),
        )?,
        FaceError::NotFound(m) => write_response(
            w,
            404,
            "Not Found",
            "application/xml",
            &s3_error("NoSuchKey", &m),
        )?,
        FaceError::Error(m) => write_response(
            w,
            500,
            "Internal Server Error",
            "application/xml",
            &s3_error("InternalError", &m),
        )?,
    }
    Ok(())
}

pub fn auth_error<W: Write>(
    w: W,
    status: u16,
    reason: &str,
    code: &str,
    message: &str,
) -> Result<(), crate::http1::HttpError> {
    write_response(
        w,
        status,
        reason,
        "application/xml",
        &s3_error(code, message),
    )?;
    Ok(())
}
