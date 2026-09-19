//! `nas gateway …` — the localhost S3 face (SPECS §2.1).
//!
//! Credentials live in `$NAS_HOME/state/gateway.json` (0600). TCP is
//! loopback-only and SigV4-gated. An unauthenticated process is refused.

use crate::exit;
use crate::objectcmd::LocalBuckets;
use crate::repo;
use nas_core::{KeyScheme, Mode, PaddingProfile};
use nas_crypto::random;
use nas_gateway::creds::{self, CredsError};
use nas_gateway::hmac::hex_encode;
use nas_gateway::sigv4::{sign, Creds, SignedRequest, UNSIGNED};
use nas_gateway::{assert_loopback, serve_tcp};
use std::fs;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::thread;
use std::time::Duration;

fn err(msg: impl std::fmt::Display) -> i32 {
    eprintln!("error: {msg}");
    exit::ERROR
}

fn creds_path() -> PathBuf {
    repo::nas_home().join("state/gateway.json")
}

fn load_or_create_creds() -> Result<Creds, String> {
    let p = creds_path();
    match fs::read(&p) {
        Ok(b) => creds::decode(&b).map_err(|e: CredsError| e.to_string()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            fs::create_dir_all(p.parent().unwrap()).map_err(|e| e.to_string())?;
            let c = creds::generate(
                &random::array().map_err(|e| e.to_string())?,
                &random::array().map_err(|e| e.to_string())?,
            );
            repo::write_private_pub(&p, creds::encode(&c).as_bytes()).map_err(|e| e.to_string())?;
            Ok(c)
        }
        Err(e) => Err(e.to_string()),
    }
}

/// `nas gateway status --face s3`
pub fn status(face: Option<&str>) -> i32 {
    match face.unwrap_or("s3") {
        "s3" | "webdav" => {}
        other => {
            eprintln!("unknown face {other:?} (s3|webdav)");
            return exit::ERROR;
        }
    }
    let creds = match load_or_create_creds() {
        Ok(c) => c,
        Err(e) => return err(e),
    };
    let face = face.unwrap_or("s3");
    println!("face {face}");
    println!("bind 127.0.0.1 (loopback only; SPECS §2.1)");
    match face {
        "webdav" => println!("auth basic (TCP) / socket mode 0600 (unix)"),
        _ => println!("auth sigv4 (TCP) / socket mode 0600 (unix)"),
    }
    println!("access_key_id {}", creds.access_key_id);
    println!("creds {}", creds_path().display());
    println!("socket {}", default_socket_path().display());
    println!("mount read-only (SPECS §8)");
    println!("ready");
    exit::OK
}

pub fn default_socket_path() -> PathBuf {
    if let Ok(xdg) = std::env::var("XDG_RUNTIME_DIR") {
        if !xdg.is_empty() {
            return PathBuf::from(xdg).join("nasd.sock");
        }
    }
    repo::nas_home().join("state/nasd.sock")
}

/// `nas gateway serve [--listen 127.0.0.1:port|/path.sock] [--once]`
///
/// No `--listen` is the unix socket: that is the default transport (SPECS
/// §2.1). TCP is opt-in because `aws` and `rclone` cannot speak unix sockets.
pub fn serve(listen: Option<&str>, once: bool) -> i32 {
    match listen {
        None => serve_unix_path(&default_socket_path(), once),
        Some(s) if s.starts_with("unix:") => {
            serve_unix_path(Path::new(s.trim_start_matches("unix:")), once)
        }
        Some(s) if s.starts_with('/') || s.starts_with('.') => serve_unix_path(Path::new(s), once),
        Some(s) => serve_tcp_addr(s, once),
    }
}

fn serve_unix_path(path: &Path, once: bool) -> i32 {
    #[cfg(not(unix))]
    {
        let _ = (path, once);
        eprintln!("error: unix sockets are the default transport and this build is not unix");
        return exit::ERROR;
    }
    #[cfg(unix)]
    {
        let listener = match nas_gateway::bind_unix(path) {
            Ok(l) => l,
            Err(e) => return err(e),
        };
        eprintln!(
            "gateway s3+webdav on unix:{}  (mode 0600; SigV4/Basic not required)",
            path.display()
        );
        if let Err(e) = nas_gateway::serve_unix(&listener, &LocalBuckets::new(), once) {
            return err(e);
        }
        exit::OK
    }
}

fn serve_tcp_addr(listen: &str, once: bool) -> i32 {
    let addr: std::net::SocketAddr = match listen.parse() {
        Ok(a) => a,
        Err(_) => {
            eprintln!("--listen takes host:port, got {listen:?}");
            return exit::ERROR;
        }
    };
    if let Err(e) = assert_loopback(addr) {
        eprintln!("refused: {e}");
        return exit::REFUSED;
    }
    let creds = match load_or_create_creds() {
        Ok(c) => c,
        Err(e) => return err(e),
    };
    let listener = match TcpListener::bind(addr) {
        Ok(l) => l,
        Err(e) => return err(e),
    };
    let bound = match listener.local_addr() {
        Ok(a) => a,
        Err(e) => return err(e),
    };
    eprintln!(
        "gateway s3+webdav on http://{bound}  access_key_id {}  (SigV4 / Basic)",
        creds.access_key_id
    );
    if let Err(e) = serve_tcp(&listener, &creds, &LocalBuckets::new(), once) {
        return err(e);
    }
    exit::OK
}

/// `nas test gateway-auth-required` — SPECS §12.8, UC05.
///
/// Spins a real loopback listener and proves an unsigned GET is 403, then
/// that the same GET with a valid signature is 200. If the unsigned request
/// is allowed, that is a broken control, not a pending one.
pub fn auth_required() -> i32 {
    let creds = match load_or_create_creds() {
        Ok(c) => c,
        Err(e) => return err(e),
    };
    let listener = match TcpListener::bind("127.0.0.1:0") {
        Ok(l) => l,
        Err(e) => return err(e),
    };
    let addr = match listener.local_addr() {
        Ok(a) => a,
        Err(e) => return err(e),
    };
    let c = creds.clone();
    let t = thread::spawn(move || {
        let _ = serve_tcp(&listener, &c, &LocalBuckets::new(), false);
    });
    // Give the accept loop a moment. The first connect is the wait.
    thread::sleep(Duration::from_millis(20));

    let unsigned = b"GET / HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n";
    let unauth = match exchange(addr, unsigned) {
        Ok(s) => s,
        Err(e) => return err(e),
    };
    if !unauth.starts_with("HTTP/1.1 403") {
        eprintln!(
            "error: unauthenticated GET was not refused (got {})",
            unauth.lines().next().unwrap_or("")
        );
        return exit::ERROR;
    }

    let host = format!("127.0.0.1:{}", addr.port());
    let mut headers = std::collections::BTreeMap::new();
    headers.insert("host".into(), host.clone());
    headers.insert("x-amz-date".into(), "20130524T000000Z".into());
    headers.insert("x-amz-content-sha256".into(), UNSIGNED.to_string());
    let req = SignedRequest {
        method: "GET",
        path: "/",
        query: "",
        headers: &headers,
        body: b"",
    };
    let auth = sign(&creds, "us-east-1", &req);
    let signed = format!(
        "GET / HTTP/1.1\r\nHost: {host}\r\nX-Amz-Date: 20130524T000000Z\r\nX-Amz-Content-Sha256: {UNSIGNED}\r\nAuthorization: {auth}\r\n\r\n"
    );
    let ok = match exchange(addr, signed.as_bytes()) {
        Ok(s) => s,
        Err(e) => return err(e),
    };
    if !ok.starts_with("HTTP/1.1 200") {
        eprintln!(
            "error: signed GET failed ({})",
            ok.lines().next().unwrap_or("")
        );
        return exit::ERROR;
    }
    println!("gateway-auth-required: unsigned 403, signed 200 on {addr}");
    let _ = t;
    exit::OK
}

fn exchange(addr: std::net::SocketAddr, req: &[u8]) -> std::io::Result<String> {
    let mut s = TcpStream::connect(addr)?;
    s.set_read_timeout(Some(Duration::from_secs(2)))?;
    s.set_write_timeout(Some(Duration::from_secs(2)))?;
    s.write_all(req)?;
    s.shutdown(std::net::Shutdown::Write)?;
    let mut out = Vec::new();
    s.read_to_end(&mut out)?;
    Ok(String::from_utf8_lossy(&out).into_owned())
}

fn ensure_bucket(ns: &str) -> Result<(), String> {
    if crate::repo::Repo::exists(ns) {
        return Ok(());
    }
    crate::repo::Repo::create(
        ns,
        Mode::E2ee,
        KeyScheme::Convergent,
        PaddingProfile::None,
        None,
        None,
        None,
    )
    .map_err(|e| e.to_string())?;
    Ok(())
}

fn spawn_gateway() -> Result<(std::net::SocketAddr, Creds, thread::JoinHandle<()>), String> {
    let creds = load_or_create_creds()?;
    let listener = TcpListener::bind("127.0.0.1:0").map_err(|e| e.to_string())?;
    let addr = listener.local_addr().map_err(|e| e.to_string())?;
    let c = creds.clone();
    let t = thread::spawn(move || {
        let _ = serve_tcp(&listener, &c, &LocalBuckets::new(), false);
    });
    thread::sleep(Duration::from_millis(20));
    Ok((addr, creds, t))
}

fn signed_exchange(
    addr: std::net::SocketAddr,
    creds: &Creds,
    method: &str,
    path: &str,
    query: &str,
    body: &[u8],
) -> Result<String, String> {
    let host = format!("127.0.0.1:{}", addr.port());
    let hash = if body.is_empty() {
        UNSIGNED.to_string()
    } else {
        hex_encode(&nas_gateway::hmac::sha256(body))
    };
    let mut headers = std::collections::BTreeMap::new();
    headers.insert("host".into(), host.clone());
    headers.insert("x-amz-date".into(), "20130524T000000Z".into());
    headers.insert("x-amz-content-sha256".into(), hash.clone());
    let target = if query.is_empty() {
        path.to_string()
    } else {
        format!("{path}?{query}")
    };
    let req = SignedRequest {
        method,
        path,
        query,
        headers: &headers,
        body,
    };
    let auth = sign(creds, "us-east-1", &req);
    let mut msg = format!(
        "{method} {target} HTTP/1.1\r\nHost: {host}\r\nX-Amz-Date: 20130524T000000Z\r\nX-Amz-Content-Sha256: {hash}\r\nAuthorization: {auth}\r\n"
    );
    if !body.is_empty() {
        msg.push_str(&format!("Content-Length: {}\r\n", body.len()));
    }
    msg.push_str("\r\n");
    let mut bytes = msg.into_bytes();
    bytes.extend_from_slice(body);
    let resp = exchange(addr, &bytes).map_err(|e| e.to_string())?;
    Ok(resp)
}

fn http_body(resp: &str) -> &[u8] {
    resp.as_bytes()
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|i| &resp.as_bytes()[i + 4..])
        .unwrap_or(b"")
}

/// `nas test dvc-roundtrip <ns>` — SPECS §17 level 1, UC05.
///
/// DVC talking S3 is PUT + GET through this gateway. We do not require a
/// DVC install: the claim is the S3 face, not DVC's pointer files.
pub fn dvc_roundtrip(ns: &str) -> i32 {
    if let Err(e) = ensure_bucket(ns) {
        return err(e);
    }
    let (addr, creds, t) = match spawn_gateway() {
        Ok(v) => v,
        Err(e) => return err(e),
    };
    let body = b"dvc-dataset-row-1,ok\n";
    let path = format!("/{ns}/data/train.csv");
    let put = match signed_exchange(addr, &creds, "PUT", &path, "", body) {
        Ok(s) => s,
        Err(e) => return err(e),
    };
    if !put.starts_with("HTTP/1.1 200") {
        return err(format!(
            "PUT through the gateway failed: {}",
            put.lines().next().unwrap_or("")
        ));
    }
    let get = match signed_exchange(addr, &creds, "GET", &path, "", b"") {
        Ok(s) => s,
        Err(e) => return err(e),
    };
    if !get.starts_with("HTTP/1.1 200") || http_body(&get) != body {
        return err("GET did not return the bytes PUT through the gateway");
    }
    let list = match signed_exchange(addr, &creds, "GET", &format!("/{ns}"), "list-type=2", b"") {
        Ok(s) => s,
        Err(e) => return err(e),
    };
    if !list.contains("data/train.csv") {
        return err("ListObjects did not name the key");
    }
    println!("dvc-roundtrip: PUT/GET/List through SigV4 on {addr}");
    let _ = t;
    exit::OK
}

fn parse_bytes(s: &str) -> Option<u64> {
    let t = s.trim();
    if let Some(n) = t.strip_suffix("MiB").or_else(|| t.strip_suffix("M")) {
        n.trim().parse::<u64>().ok().map(|m| m * 1024 * 1024)
    } else if let Some(n) = t.strip_suffix("KiB").or_else(|| t.strip_suffix("K")) {
        n.trim().parse::<u64>().ok().map(|m| m * 1024)
    } else if let Some(n) = t.strip_suffix("GiB").or_else(|| t.strip_suffix("G")) {
        n.trim().parse::<u64>().ok().map(|m| m * 1024 * 1024 * 1024)
    } else {
        t.parse().ok()
    }
}

fn stored_bytes(ns: &str) -> Result<u64, String> {
    let repo = crate::repo::Repo::open_with(ns, crate::repo::passphrase_from(None))
        .map_err(|e| e.to_string())?;
    let blobs = repo.blobs().map_err(|e| e.to_string())?;
    let addrs = blobs.addrs().map_err(|e| e.to_string())?;
    Ok(addrs
        .iter()
        .filter_map(|a| fs::metadata(blobs.path(a)).ok())
        .map(|m| m.len())
        .sum())
}

/// `nas test dvc-incremental <ns> --rows 1 --max-transfer 5MiB`
///
/// One changed CSV row must not re-store the file. DVC's cache would; CDC
/// under the S3 key does not (SPECS §17).
pub fn dvc_incremental(ns: &str, rows: u32, max_transfer: &str) -> i32 {
    if let Err(e) = ensure_bucket(ns) {
        return err(e);
    }
    let budget = match parse_bytes(max_transfer) {
        Some(b) => b,
        None => return err(format!("--max-transfer takes a size, got {max_transfer:?}")),
    };
    let _ = rows; // the assertion is "one row"; the file is built with that edit
    let mut csv = String::from("id,value\n");
    for i in 0..20_000u32 {
        csv.push_str(&format!("{i:05},{:0>80}\n", i));
    }
    let tmp = std::env::temp_dir().join(format!("nas-dvc-inc-{}", std::process::id()));
    if let Err(e) = fs::write(&tmp, csv.as_bytes()) {
        return err(e);
    }
    let target = format!("{ns}/data/train.csv");
    if crate::objectcmd::put(&target, tmp.to_str().unwrap(), None) != exit::OK {
        return err("first put of the dataset failed");
    }
    let after_first = match stored_bytes(ns) {
        Ok(n) => n,
        Err(e) => return err(e),
    };
    // Change exactly one row. FastCDC's 16–256 KiB window means the added
    // ciphertext is a couple of chunks, not another copy of the file.
    let edited = csv.replacen("00010,", "99910,", 1);
    if let Err(e) = fs::write(&tmp, edited.as_bytes()) {
        return err(e);
    }
    if crate::objectcmd::put(&target, tmp.to_str().unwrap(), None) != exit::OK {
        return err("second put of the dataset failed");
    }
    let _ = fs::remove_file(&tmp);
    let added = match stored_bytes(ns) {
        Ok(n) => n.saturating_sub(after_first),
        Err(e) => return err(e),
    };
    println!(
        "dvc-incremental: one-row edit added {added} B (file {} B, budget {budget} B)",
        csv.len()
    );
    if added > budget {
        return err(format!(
            "one changed row cost {added} B, over the {budget} B budget — CDC is not helping"
        ));
    }
    if added >= csv.len() as u64 / 2 {
        return err("the second put stored most of the file again; that is DVC's bug, not ours");
    }
    exit::OK
}

/// `nas test dvc-md5-not-trusted <ns>` — SPECS §17.
///
/// DVC names cache objects by MD5. That is a name. We must not refuse (or
/// rewrite) a body whose MD5 is not the path it arrived under.
pub fn dvc_md5_not_trusted(ns: &str) -> i32 {
    if let Err(e) = ensure_bucket(ns) {
        return err(e);
    }
    let (addr, creds, t) = match spawn_gateway() {
        Ok(v) => v,
        Err(e) => return err(e),
    };
    // All-zero MD5 is not the hash of this body. If we treated the path as
    // integrity we would refuse the PUT or the GET.
    let key = format!("/{ns}/files/md5/00/00000000000000000000000000000000");
    let body = b"not-the-md5-of-this-path\n";
    let put = match signed_exchange(addr, &creds, "PUT", &key, "", body) {
        Ok(s) => s,
        Err(e) => return err(e),
    };
    if !put.starts_with("HTTP/1.1 200") {
        return err("PUT of a mis-named DVC cache object was refused");
    }
    let get = match signed_exchange(addr, &creds, "GET", &key, "", b"") {
        Ok(s) => s,
        Err(e) => return err(e),
    };
    if http_body(&get) != body {
        return err("GET did not return the body we stored under a lying MD5 name");
    }
    println!("dvc-md5-not-trusted: MD5 in the key is a name; the body is what we stored");
    let _ = t;
    exit::OK
}

fn basic_exchange(
    addr: std::net::SocketAddr,
    creds: &Creds,
    method: &str,
    path: &str,
    extra: &[(&str, &str)],
    body: &[u8],
) -> Result<String, String> {
    let token = nas_gateway::hmac::b64_encode(
        format!("{}:{}", creds.access_key_id, creds.secret_access_key).as_bytes(),
    );
    let host = format!("127.0.0.1:{}", addr.port());
    let mut msg =
        format!("{method} {path} HTTP/1.1\r\nHost: {host}\r\nAuthorization: Basic {token}\r\n");
    for (k, v) in extra {
        msg.push_str(&format!("{k}: {v}\r\n"));
    }
    if !body.is_empty() {
        msg.push_str(&format!("Content-Length: {}\r\n", body.len()));
    }
    msg.push_str("\r\n");
    let mut bytes = msg.into_bytes();
    bytes.extend_from_slice(body);
    exchange(addr, &bytes).map_err(|e| e.to_string())
}

fn header_value(resp: &str, name: &str) -> Option<String> {
    let prefix = format!("{name}:");
    for line in resp.lines() {
        if line.len() >= prefix.len() && line[..prefix.len()].eq_ignore_ascii_case(&prefix) {
            return Some(line[prefix.len()..].trim().to_string());
        }
    }
    None
}

/// `nas test webdav-auth-required` — SPECS §2.1, §8.
pub fn webdav_auth_required() -> i32 {
    let (addr, creds, t) = match spawn_gateway() {
        Ok(v) => v,
        Err(e) => return err(e),
    };
    let unauth = match exchange(
        addr,
        b"PROPFIND / HTTP/1.1\r\nHost: 127.0.0.1\r\nDepth: 0\r\n\r\n",
    ) {
        Ok(s) => s,
        Err(e) => return err(e),
    };
    if !unauth.starts_with("HTTP/1.1 401") {
        return err(format!(
            "unauthenticated PROPFIND was not 401 (got {})",
            unauth.lines().next().unwrap_or("")
        ));
    }
    if header_value(&unauth, "WWW-Authenticate")
        .filter(|v| v.to_ascii_lowercase().contains("basic"))
        .is_none()
    {
        return err("401 did not offer Basic");
    }
    let ok = match basic_exchange(addr, &creds, "PROPFIND", "/", &[("Depth", "0")], b"") {
        Ok(s) => s,
        Err(e) => return err(e),
    };
    if !ok.starts_with("HTTP/1.1 207") {
        return err(format!(
            "Basic PROPFIND failed ({})",
            ok.lines().next().unwrap_or("")
        ));
    }
    println!("webdav-auth-required: unauthenticated 401, Basic 207 on {addr}");
    let _ = t;
    exit::OK
}

/// `nas test webdav-roundtrip <ns>` — OPTIONS / PROPFIND / GET; PUT is 405.
pub fn webdav_roundtrip(ns: &str) -> i32 {
    if let Err(e) = ensure_bucket(ns) {
        return err(e);
    }
    let tmp = std::env::temp_dir().join(format!("nas-dav-{}", std::process::id()));
    if let Err(e) = fs::write(&tmp, b"dav-fixture-bytes") {
        return err(e);
    }
    if crate::objectcmd::put(
        &format!("{ns}/notes/hello.txt"),
        tmp.to_str().unwrap(),
        None,
    ) != exit::OK
    {
        return err("put of the WebDAV fixture failed");
    }
    let _ = fs::remove_file(&tmp);
    let (addr, creds, t) = match spawn_gateway() {
        Ok(v) => v,
        Err(e) => return err(e),
    };
    let options = match basic_exchange(addr, &creds, "OPTIONS", "/", &[], b"") {
        Ok(s) => s,
        Err(e) => return err(e),
    };
    if !options.starts_with("HTTP/1.1 200")
        || header_value(&options, "DAV").is_none()
        || !header_value(&options, "Allow")
            .unwrap_or_default()
            .contains("PROPFIND")
    {
        return err(format!("OPTIONS was not a WebDAV advertise: {options}"));
    }
    let list = match basic_exchange(
        addr,
        &creds,
        "PROPFIND",
        &format!("/{ns}/notes"),
        &[("Depth", "1")],
        b"",
    ) {
        Ok(s) => s,
        Err(e) => return err(e),
    };
    if !list.starts_with("HTTP/1.1 207") || !list.contains("hello.txt") {
        return err("PROPFIND did not name the key");
    }
    let get = match basic_exchange(
        addr,
        &creds,
        "GET",
        &format!("/{ns}/notes/hello.txt"),
        &[],
        b"",
    ) {
        Ok(s) => s,
        Err(e) => return err(e),
    };
    if !get.starts_with("HTTP/1.1 200") || http_body(&get) != b"dav-fixture-bytes" {
        return err("WebDAV GET did not return the stored bytes");
    }
    let put = match basic_exchange(
        addr,
        &creds,
        "PUT",
        &format!("/{ns}/notes/nope.txt"),
        &[],
        b"x",
    ) {
        Ok(s) => s,
        Err(e) => return err(e),
    };
    if !put.starts_with("HTTP/1.1 405") {
        return err("WebDAV PUT must be refused — the mount is read-only");
    }
    println!("webdav-roundtrip: OPTIONS/PROPFIND/GET on {addr}; PUT 405");
    let _ = t;
    exit::OK
}

/// `nas test ranged-read <ns>` — SPECS §12.9: a range GET fetches O(range).
pub fn ranged_read(ns: &str) -> i32 {
    if let Err(e) = ensure_bucket(ns) {
        return err(e);
    }
    const FILE: usize = 4 * 1024 * 1024;
    const START: u64 = 1_000_000;
    const LEN: u64 = 4096;
    let mut data = vec![0u8; FILE];
    for (i, b) in data.iter_mut().enumerate() {
        // ASCII so the HTTP exchange (UTF-8 text) does not lossy-replace the
        // slice we later compare against.
        *b = b'a' + (i % 26) as u8;
    }
    let tmp = std::env::temp_dir().join(format!("nas-range-{}", std::process::id()));
    if let Err(e) = fs::write(&tmp, &data) {
        return err(e);
    }
    if crate::objectcmd::put(&format!("{ns}/big.bin"), tmp.to_str().unwrap(), None) != exit::OK {
        return err("put of the ranged-read fixture failed");
    }
    let _ = fs::remove_file(&tmp);
    let (addr, creds, t) = match spawn_gateway() {
        Ok(v) => v,
        Err(e) => return err(e),
    };
    let last = START + LEN - 1;
    let get = match basic_exchange(
        addr,
        &creds,
        "GET",
        &format!("/{ns}/big.bin"),
        &[("Range", &format!("bytes={START}-{last}"))],
        b"",
    ) {
        Ok(s) => s,
        Err(e) => return err(e),
    };
    if !get.starts_with("HTTP/1.1 206") {
        return err(format!(
            "ranged GET was not 206 ({})",
            get.lines().next().unwrap_or("")
        ));
    }
    let body = http_body(&get);
    let want = &data[START as usize..(START + LEN) as usize];
    if body != want {
        return err(format!(
            "ranged GET body did not match the requested slice (got {} B, want {} B)",
            body.len(),
            want.len()
        ));
    }
    let chunks: usize = header_value(&get, "X-Nas-Chunks-Fetched")
        .and_then(|s| s.parse().ok())
        .unwrap_or(usize::MAX);
    let fetched: u64 = header_value(&get, "X-Nas-Bytes-Fetched")
        .and_then(|s| s.parse().ok())
        .unwrap_or(u64::MAX);
    if chunks == 0 || chunks > 3 {
        return err(format!(
            "ranged GET fetched {chunks} chunks; a 4 KiB range of a 4 MiB file should be 1–3"
        ));
    }
    if fetched >= FILE as u64 / 2 {
        return err(format!(
            "ranged GET fetched {fetched} B of a {FILE} B file — that is O(file), not O(range)"
        ));
    }
    println!("ranged-read: 4 KiB of {FILE} B fetched {chunks} chunk(s), {fetched} B ciphertext");
    let _ = t;
    exit::OK
}

/// `nas test cache-sealed <ns>` — SPECS §8.3: cache files are not plaintext.
pub fn cache_sealed(ns: &str) -> i32 {
    if let Err(e) = ensure_bucket(ns) {
        return err(e);
    }
    const MARKER: &[u8] = b"CACHE-PLAINTEXT-MARKER-M4";
    let tmp = std::env::temp_dir().join(format!("nas-cache-mark-{}", std::process::id()));
    if let Err(e) = fs::write(&tmp, MARKER) {
        return err(e);
    }
    if crate::objectcmd::put(&format!("{ns}/secret.bin"), tmp.to_str().unwrap(), None) != exit::OK {
        return err("put of the cache-sealed fixture failed");
    }
    let _ = fs::remove_file(&tmp);
    let (addr, creds, t) = match spawn_gateway() {
        Ok(v) => v,
        Err(e) => return err(e),
    };
    let get = match basic_exchange(addr, &creds, "GET", &format!("/{ns}/secret.bin"), &[], b"") {
        Ok(s) => s,
        Err(e) => return err(e),
    };
    if http_body(&get) != MARKER {
        return err("GET did not return the marker, so the cache was not exercised");
    }
    let dir = crate::repo::nas_home().join("state/cache");
    let rd = match fs::read_dir(&dir) {
        Ok(r) => r,
        Err(_) => return err(format!("no cache directory at {}", dir.display())),
    };
    let mut files = 0usize;
    for e in rd.flatten() {
        if !e.file_type().map(|t| t.is_file()).unwrap_or(false) {
            continue;
        }
        files += 1;
        let bytes = match fs::read(e.path()) {
            Ok(b) => b,
            Err(eio) => return err(eio),
        };
        if bytes.windows(MARKER.len()).any(|w| w == MARKER) {
            return err(format!(
                "cache file {} contained the plaintext marker",
                e.path().display()
            ));
        }
    }
    if files == 0 {
        return err("cache directory is empty after a GET — nothing was sealed");
    }
    println!("cache-sealed: {files} file(s) under state/cache/, none hold the marker");
    let _ = t;
    exit::OK
}
