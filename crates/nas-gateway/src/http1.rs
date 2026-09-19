//! Minimal HTTP/1.1. No chunked bodies, no pipelining.
//!
//! A peer answering `Content-Length: 0xFFFFFFFF` must not make us reserve four
//! gigabytes. The length is checked against [`MAX_BODY`] before any allocation
//! of the body.

use std::collections::BTreeMap;
use std::io::{self, Read, Write};

pub const MAX_BODY: u64 = 64 * 1024 * 1024;
pub const MAX_HEADER: usize = 64 * 1024;

#[derive(Debug)]
pub struct Request {
    pub method: String,
    pub path: String,
    pub query: String,
    pub headers: BTreeMap<String, String>,
    pub body: Vec<u8>,
}

#[derive(Debug)]
pub enum HttpError {
    Io(io::Error),
    Truncated,
    TooLarge { which: &'static str, got: u64 },
    BadLine,
}

impl std::fmt::Display for HttpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "{e}"),
            Self::Truncated => write!(f, "truncated HTTP request"),
            Self::TooLarge { which, got } => write!(f, "{which} is {got} B, over the cap"),
            Self::BadLine => write!(f, "malformed HTTP request line"),
        }
    }
}
impl std::error::Error for HttpError {}
impl From<io::Error> for HttpError {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}

pub fn read_request<R: Read>(mut r: R) -> Result<Request, HttpError> {
    let mut buf = Vec::new();
    let mut tmp = [0u8; 1024];
    let header_end = loop {
        if buf.len() > MAX_HEADER {
            return Err(HttpError::TooLarge {
                which: "headers",
                got: buf.len() as u64,
            });
        }
        let n = r.read(&mut tmp)?;
        if n == 0 {
            return Err(HttpError::Truncated);
        }
        buf.extend_from_slice(&tmp[..n]);
        if let Some(i) = find_double_crlf(&buf) {
            break i;
        }
    };
    let (head, rest) = buf.split_at(header_end);
    let mut lines = head.split(|b| *b == b'\n');
    let request_line = lines.next().ok_or(HttpError::BadLine)?;
    let (method, target) = parse_request_line(request_line)?;
    let (path, query) = split_target(&target);
    let mut headers = BTreeMap::new();
    for line in lines {
        let line = trim_cr(line);
        if line.is_empty() {
            continue;
        }
        let s = std::str::from_utf8(line).map_err(|_| HttpError::BadLine)?;
        let (k, v) = s.split_once(':').ok_or(HttpError::BadLine)?;
        headers.insert(k.trim().to_ascii_lowercase(), v.trim().to_string());
    }
    let want = match headers.get("content-length") {
        Some(v) => v.parse::<u64>().map_err(|_| HttpError::BadLine)?,
        None => 0,
    };
    if want > MAX_BODY {
        return Err(HttpError::TooLarge {
            which: "body",
            got: want,
        });
    }
    let want = want as usize;
    let mut body = rest.to_vec();
    body.reserve(want.saturating_sub(body.len()));
    while body.len() < want {
        let n = r.read(&mut tmp)?;
        if n == 0 {
            return Err(HttpError::Truncated);
        }
        body.extend_from_slice(&tmp[..n]);
        if body.len() > want {
            body.truncate(want);
            break;
        }
    }
    if body.len() > want {
        body.truncate(want);
    }
    Ok(Request {
        method,
        path,
        query,
        headers,
        body,
    })
}

fn find_double_crlf(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n").map(|i| i + 4)
}

fn trim_cr(line: &[u8]) -> &[u8] {
    match line.strip_suffix(b"\r") {
        Some(s) => s,
        None => line,
    }
}

fn parse_request_line(line: &[u8]) -> Result<(String, String), HttpError> {
    let line = trim_cr(line);
    let s = std::str::from_utf8(line).map_err(|_| HttpError::BadLine)?;
    let mut it = s.split(' ');
    let method = it.next().ok_or(HttpError::BadLine)?;
    let target = it.next().ok_or(HttpError::BadLine)?;
    if method.is_empty() || target.is_empty() {
        return Err(HttpError::BadLine);
    }
    Ok((method.to_string(), target.to_string()))
}

fn split_target(target: &str) -> (String, String) {
    match target.split_once('?') {
        Some((p, q)) => (decode_path(p), q.to_string()),
        None => (decode_path(target), String::new()),
    }
}

/// Percent-decode a path or query component. Used for S3 keys and prefixes.
pub fn percent_decode(p: &str) -> String {
    decode_path(p)
}

fn decode_path(p: &str) -> String {
    let mut out = Vec::new();
    let b = p.as_bytes();
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 2 < b.len() {
            if let Ok(v) =
                u8::from_str_radix(std::str::from_utf8(&b[i + 1..i + 3]).unwrap_or(""), 16)
            {
                out.push(v);
                i += 3;
                continue;
            }
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

pub fn write_response<W: Write>(
    mut w: W,
    status: u16,
    reason: &str,
    content_type: &str,
    body: &[u8],
) -> io::Result<()> {
    write!(
        w,
        "HTTP/1.1 {status} {reason}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    )?;
    w.write_all(body)?;
    w.flush()
}

pub fn write_empty<W: Write>(w: W, status: u16, reason: &str) -> io::Result<()> {
    write_response(w, status, reason, "text/plain", b"")
}
