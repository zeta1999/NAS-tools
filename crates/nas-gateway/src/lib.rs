//! Localhost S3 gateway (SPECS §2.1, §7.1).
//!
//! Sync HTTP/1.1, no async runtime. TCP is loopback-only and SigV4-gated.
//! A unix socket is mode-`0600` gated and does not demand a signature — the
//! filesystem is the credential, which is what the git helper will use.
//!
//! The residual is stated rather than implied: a process running as the same
//! user can read the socket or `gateway.json` and is inside the boundary.

pub mod creds;
pub mod hmac;
pub mod http1;
pub mod s3;
pub mod sigv4;

use http1::{read_request, write_response, HttpError};
use s3::{auth_error, dispatch, Buckets};
use sigv4::{verify, Creds, SignedRequest};
use std::io::{self, Write};
use std::net::TcpListener;
use std::path::Path;

/// Refuse any bind that is not loopback. "Localhost-only" is not access
/// control, but binding `0.0.0.0` would make it not even that.
pub fn assert_loopback(addr: std::net::SocketAddr) -> Result<(), io::Error> {
    if addr.ip().is_loopback() {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("gateway must bind loopback, not {}", addr.ip()),
        ))
    }
}

pub fn serve_tcp<B: Buckets>(
    listener: &TcpListener,
    creds: &Creds,
    buckets: &B,
    once: bool,
) -> io::Result<()> {
    assert_loopback(listener.local_addr()?)?;
    loop {
        let (stream, _) = listener.accept()?;
        let _ = handle_stream(stream, Some(creds), buckets);
        if once {
            return Ok(());
        }
    }
}

pub fn handle_stream<B: Buckets, S>(
    mut stream: S,
    creds: Option<&Creds>,
    buckets: &B,
) -> Result<(), HttpError>
where
    S: std::io::Read + Write,
{
    let req = match read_request(&mut stream) {
        Ok(r) => r,
        Err(HttpError::TooLarge { .. }) => {
            write_response(
                &mut stream,
                413,
                "Payload Too Large",
                "text/plain",
                b"body too large",
            )?;
            return Ok(());
        }
        Err(e) => return Err(e),
    };
    if let Some(creds) = creds {
        let signed = SignedRequest {
            method: &req.method,
            path: &req.path,
            query: &req.query,
            headers: &req.headers,
            body: &req.body,
        };
        if let Err(e) = verify(creds, &signed) {
            let (status, reason, code) = match e {
                sigv4::AuthError::Missing => (403, "Forbidden", "AccessDenied"),
                sigv4::AuthError::UnknownKey | sigv4::AuthError::BadSignature => {
                    (403, "Forbidden", "SignatureDoesNotMatch")
                }
                sigv4::AuthError::PayloadHash => (400, "Bad Request", "XAmzContentSHA256Mismatch"),
                sigv4::AuthError::Malformed(_) => {
                    (400, "Bad Request", "AuthorizationHeaderMalformed")
                }
            };
            auth_error(&mut stream, status, reason, code, &e.to_string())?;
            return Ok(());
        }
    }
    dispatch(buckets, &req, &mut stream)
}

/// Unix domain socket (SPECS §2.1). Mode `0600` is the credential; there is
/// no SigV4 on this path. The git helper and anything else that can open the
/// socket is already the same user as `nasd`.
#[cfg(unix)]
pub fn bind_unix(path: &Path) -> io::Result<std::os::unix::net::UnixListener> {
    if path.exists() {
        std::fs::remove_file(path)?;
    }
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let listener = std::os::unix::net::UnixListener::bind(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(listener)
}

#[cfg(unix)]
pub fn serve_unix<B: Buckets>(
    listener: &std::os::unix::net::UnixListener,
    buckets: &B,
    once: bool,
) -> io::Result<()> {
    loop {
        let (stream, _) = listener.accept()?;
        let _ = handle_stream(stream, None, buckets);
        if once {
            return Ok(());
        }
    }
}

/// A one-connection in-memory store, for protocol tests.
#[cfg(test)]
pub mod mem {
    use super::s3::{Buckets, FaceError, ObjectInfo};
    use std::collections::BTreeMap;
    use std::sync::Mutex;

    #[derive(Default)]
    pub struct Memory {
        pub buckets: Mutex<BTreeMap<String, BTreeMap<String, Vec<u8>>>>,
    }

    impl Memory {
        pub fn with_bucket(name: &str) -> Self {
            let mut b = BTreeMap::new();
            b.insert(name.into(), BTreeMap::new());
            Self {
                buckets: Mutex::new(b),
            }
        }
    }

    impl Buckets for Memory {
        fn list_buckets(&self) -> Result<Vec<String>, FaceError> {
            Ok(self.buckets.lock().unwrap().keys().cloned().collect())
        }
        fn list(&self, bucket: &str, prefix: &str) -> Result<Vec<ObjectInfo>, FaceError> {
            let g = self.buckets.lock().unwrap();
            let b = g
                .get(bucket)
                .ok_or_else(|| FaceError::NotFound(bucket.into()))?;
            Ok(b.iter()
                .filter(|(k, _)| prefix.is_empty() || k.starts_with(prefix))
                .map(|(k, v)| ObjectInfo {
                    key: k.clone(),
                    size: v.len() as u64,
                    tombstone: false,
                })
                .collect())
        }
        fn get(&self, bucket: &str, key: &str) -> Result<Vec<u8>, FaceError> {
            self.buckets
                .lock()
                .unwrap()
                .get(bucket)
                .and_then(|b| b.get(key).cloned())
                .ok_or_else(|| FaceError::NotFound(key.into()))
        }
        fn put(&self, bucket: &str, key: &str, body: &[u8]) -> Result<u64, FaceError> {
            let mut g = self.buckets.lock().unwrap();
            let b = g
                .get_mut(bucket)
                .ok_or_else(|| FaceError::NotFound(bucket.into()))?;
            b.insert(key.into(), body.to_vec());
            Ok(body.len() as u64)
        }
        fn delete(&self, bucket: &str, key: &str) -> Result<(), FaceError> {
            self.buckets
                .lock()
                .unwrap()
                .get_mut(bucket)
                .and_then(|b| b.remove(key))
                .map(|_| ())
                .ok_or_else(|| FaceError::NotFound(key.into()))
        }
        fn head(&self, bucket: &str, key: &str) -> Result<u64, FaceError> {
            self.get(bucket, key).map(|b| b.len() as u64)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hmac::hex_encode;
    use crate::sigv4::{sign, UNSIGNED};
    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream};
    use std::thread;

    fn creds() -> Creds {
        creds::generate(&[9u8; 16], &[8u8; 32])
    }

    fn signed_get(creds: &Creds, host: &str, path: &str) -> Vec<u8> {
        let mut headers = std::collections::BTreeMap::new();
        headers.insert("host".into(), host.to_string());
        headers.insert("x-amz-date".into(), "20130524T000000Z".into());
        headers.insert("x-amz-content-sha256".into(), UNSIGNED.into());
        let req = SignedRequest {
            method: "GET",
            path,
            query: "",
            headers: &headers,
            body: b"",
        };
        let auth = sign(creds, "us-east-1", &req);
        format!(
            "GET {path} HTTP/1.1\r\nHost: {host}\r\nX-Amz-Date: 20130524T000000Z\r\nX-Amz-Content-Sha256: {UNSIGNED}\r\nAuthorization: {auth}\r\n\r\n"
        )
        .into_bytes()
    }

    fn exchange(addr: std::net::SocketAddr, req: &[u8]) -> String {
        let mut s = TcpStream::connect(addr).unwrap();
        s.write_all(req).unwrap();
        s.shutdown(std::net::Shutdown::Write).ok();
        let mut out = Vec::new();
        s.read_to_end(&mut out).unwrap();
        String::from_utf8_lossy(&out).into_owned()
    }

    #[test]
    fn loopback_is_required() {
        let addr: std::net::SocketAddr = "1.2.3.4:9".parse().unwrap();
        assert!(assert_loopback(addr).is_err());
        let addr: std::net::SocketAddr = "127.0.0.1:9".parse().unwrap();
        assert!(assert_loopback(addr).is_ok());
    }

    #[test]
    fn an_unsigned_request_is_403() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let c = creds();
        let store = mem::Memory::with_bucket("photos");
        let t = thread::spawn(move || {
            serve_tcp(&listener, &c, &store, true).unwrap();
        });
        let resp = exchange(addr, b"GET / HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n");
        assert!(
            resp.starts_with("HTTP/1.1 403"),
            "unauthenticated was not refused: {resp}"
        );
        assert!(resp.contains("AccessDenied"));
        t.join().unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn a_unix_socket_does_not_demand_sigv4() {
        let dir = std::env::temp_dir().join(format!("nas-gw-unix-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("nasd.sock");
        let listener = bind_unix(&path).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions();
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(mode.mode() & 0o777, 0o600, "socket must be 0600");
        let store = mem::Memory::with_bucket("photos");
        let t = thread::spawn(move || {
            serve_unix(&listener, &store, true).unwrap();
        });
        let mut s = std::os::unix::net::UnixStream::connect(&path).unwrap();
        s.write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .unwrap();
        s.shutdown(std::net::Shutdown::Write).ok();
        let mut out = Vec::new();
        s.read_to_end(&mut out).unwrap();
        let resp = String::from_utf8_lossy(&out);
        assert!(
            resp.starts_with("HTTP/1.1 200"),
            "unix socket is the credential: {resp}"
        );
        assert!(resp.contains("<Name>photos</Name>"), "{resp}");
        t.join().unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_signed_list_is_200_and_names_the_bucket() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let c = creds();
        let store = mem::Memory::with_bucket("photos");
        let host = format!("127.0.0.1:{}", addr.port());
        let req = signed_get(&c, &host, "/");
        let t = thread::spawn(move || {
            serve_tcp(&listener, &c, &store, true).unwrap();
        });
        let resp = exchange(addr, &req);
        assert!(resp.starts_with("HTTP/1.1 200"), "{resp}");
        assert!(resp.contains("<Name>photos</Name>"), "{resp}");
        t.join().unwrap();
    }

    #[test]
    fn put_then_get_round_trips() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let c = creds();
        let store = mem::Memory::with_bucket("photos");
        let host = format!("127.0.0.1:{}", addr.port());
        let body = b"hello-s3";
        let hash = hex_encode(&crate::hmac::sha256(body));
        let mut headers = std::collections::BTreeMap::new();
        headers.insert("host".into(), host.clone());
        headers.insert("x-amz-date".into(), "20130524T000000Z".into());
        headers.insert("x-amz-content-sha256".into(), hash.clone());
        let signed = SignedRequest {
            method: "PUT",
            path: "/photos/a.bin",
            query: "",
            headers: &headers,
            body,
        };
        let auth = sign(&c, "us-east-1", &signed);
        let put = format!(
            "PUT /photos/a.bin HTTP/1.1\r\nHost: {host}\r\nX-Amz-Date: 20130524T000000Z\r\nX-Amz-Content-Sha256: {hash}\r\nAuthorization: {auth}\r\nContent-Length: {}\r\n\r\n",
            body.len()
        );
        let mut put_bytes = put.into_bytes();
        put_bytes.extend_from_slice(body);
        let get = signed_get(&c, &host, "/photos/a.bin");
        let t = thread::spawn(move || {
            serve_tcp(&listener, &c, &store, false).unwrap();
        });
        let put_resp = exchange(addr, &put_bytes);
        assert!(put_resp.starts_with("HTTP/1.1 200"), "{put_resp}");
        let get_resp = exchange(addr, &get);
        assert!(get_resp.contains("hello-s3"), "{get_resp}");
        // The server thread is looping; drop by connecting nothing — just
        // abandon it. The process ends with the test.
        let _ = t;
    }

    #[test]
    fn a_4gb_content_length_is_refused_before_allocation() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let c = creds();
        let store = mem::Memory::with_bucket("photos");
        let t = thread::spawn(move || {
            serve_tcp(&listener, &c, &store, true).unwrap();
        });
        let resp = exchange(
            addr,
            b"PUT /photos/x HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: 4294967295\r\n\r\n",
        );
        assert!(
            resp.contains("413") || resp.contains("403"),
            "a 4 GiB claim must not be honoured: {resp}"
        );
        t.join().unwrap();
    }
}
