//! Download speed test: plain HTTP/1.1 GET over a TCP socket bound to one
//! interface, written by hand (no HTTP crate).
//!
//! * Supports `Content-Length`, `Transfer-Encoding: chunked` and bodies
//!   delimited by connection close.
//! * Follows up to [`MAX_REDIRECTS`] redirects (301/302/303/307/308) to
//!   `http://` URLs only.
//! * Time-based: the body is read for `duration` after its first byte, or until
//!   `max_bytes`, or until the whole-request `timeout`; reaching any of them after
//!   the body started is a normal result, not an error.
//! * Throughput (`mbps`) excludes the first `warmup` of the body (TCP slow start).
//!   When the transfer ends before the warm-up is over, `mbps` is the rate over the
//!   whole body and `warmup_excluded_s` is absent. `mbps_all` is always the whole-body rate.
//!   DNS, connect and server think time never count.
//!
//! The host name is resolved with `tokio::net::lookup_host`, which is not
//! bound to the interface (acceptable: only the download itself must be).

use crate::model::SpeedResult;
use crate::probe::tcp::bound_socket;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::{Instant, timeout_at};

pub const MAX_REDIRECTS: usize = 3;
const MAX_HEADER: usize = 16 * 1024;
const READ_BUF: usize = 64 * 1024;
const MAX_CHUNK_LINE: usize = 1024;

/// Limits of one speed test.
#[derive(Debug, Clone)]
pub struct Opts {
    pub max_bytes: u64,
    /// Whole request per URL (incl. redirects).
    pub timeout: Duration,
    /// Body measurement time after the first body byte.
    pub duration: Duration,
    /// Initial part of the body not counted in `mbps`.
    pub warmup: Duration,
}

/// Tries `urls` in order; returns the first result without error, else the
/// last failure. Each URL gets its own `opts.timeout` (whole request incl. redirects).
pub async fn download(iface: &str, urls: &[String], opts: &Opts) -> SpeedResult {
    let mut last = SpeedResult {
        iface: iface.to_string(),
        err: Some("no_urls".into()),
        ..Default::default()
    };
    for url in urls {
        let r = fetch(iface, url, opts).await;
        if r.err.is_none() {
            return r;
        }
        tracing::debug!(iface, url, err = ?r.err, "speed test url failed");
        last = r;
    }
    last
}

async fn fetch(iface: &str, url: &str, opts: &Opts) -> SpeedResult {
    let deadline = Instant::now() + opts.timeout;
    let mut res = SpeedResult {
        iface: iface.to_string(),
        url: url.to_string(),
        ..Default::default()
    };
    let mut current = url.to_string();
    for hop in 0..=MAX_REDIRECTS {
        match get_once(iface, &current, opts, deadline).await {
            Ok(Outcome::Body(b)) => {
                res.bytes = b.bytes;
                res.secs = b.secs;
                let all = (b.bytes > 0 && b.secs > 0.0).then(|| b.bytes as f64 * 8.0 / b.secs / 1e6);
                res.mbps_all = all;
                res.mbps = match b.warm {
                    Some((wb, ws)) if b.secs - ws > 0.1 && b.bytes > wb => {
                        res.warmup_excluded_s = Some(ws);
                        Some((b.bytes - wb) as f64 * 8.0 / (b.secs - ws) / 1e6)
                    }
                    _ => all,
                };
                res.err = b.err;
                return res;
            }
            Ok(Outcome::Redirect(next)) => {
                if hop == MAX_REDIRECTS {
                    break;
                }
                current = next;
            }
            Err(e) => {
                res.err = Some(e);
                return res;
            }
        }
    }
    res.err = Some("too_many_redirects".into());
    res
}

#[derive(Debug)]
struct BodyStats {
    bytes: u64,
    secs: f64,
    /// Bytes and seconds (since the first body byte) at the end of the warm-up.
    warm: Option<(u64, f64)>,
    err: Option<String>,
}

#[derive(Debug)]
enum Outcome {
    Body(BodyStats),
    Redirect(String),
}

async fn get_once(iface: &str, url: &str, opts: &Opts, deadline: Instant) -> Result<Outcome, String> {
    let max_bytes = opts.max_bytes;
    let u = parse_url(url)?;
    let addrs: Vec<SocketAddr> =
        match timeout_at(deadline, tokio::net::lookup_host((u.host.as_str(), u.port))).await {
            Ok(Ok(a)) => a.collect(),
            Ok(Err(_)) => return Err("dns_failed".into()),
            Err(_) => return Err("timeout".into()),
        };
    let addr = addrs
        .iter()
        .find(|a| a.is_ipv4())
        .or_else(|| addrs.first())
        .copied()
        .ok_or_else(|| "dns_failed".to_string())?;
    let sock =
        bound_socket(iface, &addr).map_err(|r| r.err.unwrap_or_else(|| "bind_failed".into()))?;
    let mut stream = match timeout_at(deadline, sock.connect(addr)).await {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => return Err(crate::probe::err_code(&e, "connect_failed").into()),
        Err(_) => return Err("timeout".into()),
    };
    let req = format!(
        "GET {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: linkwatch/{}\r\nAccept: */*\r\n\
         Accept-Encoding: identity\r\nConnection: close\r\n\r\n",
        u.path,
        u.host_header(),
        env!("CARGO_PKG_VERSION")
    );
    match timeout_at(deadline, stream.write_all(req.as_bytes())).await {
        Ok(Ok(())) => {}
        Ok(Err(e)) => return Err(crate::probe::err_code(&e, "send_failed").into()),
        Err(_) => return Err("timeout".into()),
    }

    let mut buf = vec![0u8; READ_BUF];
    let mut head_buf = Vec::with_capacity(4096);
    let head_end = loop {
        if let Some(i) = find_subslice(&head_buf, b"\r\n\r\n") {
            break i + 4;
        }
        if head_buf.len() > MAX_HEADER {
            return Err("header_too_large".into());
        }
        let n = read_some(&mut stream, &mut buf, deadline).await?;
        if n == 0 {
            return Err("no_response".into());
        }
        head_buf.extend_from_slice(&buf[..n]);
    };
    if head_end > MAX_HEADER {
        return Err("header_too_large".into());
    }
    let head = parse_head(&head_buf[..head_end])?;
    if matches!(head.status, 301 | 302 | 303 | 307 | 308) {
        let loc = head
            .header("location")
            .ok_or_else(|| "redirect_without_location".to_string())?;
        return Ok(Outcome::Redirect(resolve_location(&u, loc)?));
    }
    if !(200..300).contains(&head.status) {
        return Err(format!("http_{}", head.status));
    }
    let mut body = BodyCounter::new(body_kind(&head)?);
    let mut t0: Option<Instant> = None;
    let mut warm: Option<(u64, f64)> = None;
    let leftover = &head_buf[head_end..];
    if !leftover.is_empty() {
        t0 = Some(Instant::now());
        body.feed(leftover)?;
    }
    let mut err = None;
    let mut eof = false;
    while !body.done() && body.bytes < max_bytes {
        let end = t0.map_or(deadline, |t| (t + opts.duration).min(deadline));
        if let Some(t) = t0
            && warm.is_none()
            && t.elapsed() >= opts.warmup
        {
            warm = Some((body.bytes, t.elapsed().as_secs_f64()));
        }
        let n = match timeout_at(end, stream.read(&mut buf)).await {
            Err(_) => break, // deadline: normal end of the measurement
            Ok(Ok(n)) => n,
            Ok(Err(e)) => {
                err = Some(crate::probe::err_code(&e, "recv_failed").to_string());
                break;
            }
        };
        if n == 0 {
            eof = true;
            if !body.finish_on_eof() {
                err = Some("truncated_body".into());
            }
            break;
        }
        t0.get_or_insert_with(Instant::now);
        body.feed(&buf[..n])?;
    }
    let secs = t0.map(|t| t.elapsed().as_secs_f64()).unwrap_or(0.0);
    if body.bytes == 0 && err.is_none() {
        let complete = eof || body.done();
        err = Some(if complete { "empty_body" } else { "timeout" }.into());
    }
    Ok(Outcome::Body(BodyStats {
        bytes: body.bytes,
        secs,
        warm,
        err,
    }))
}

async fn read_some(
    stream: &mut TcpStream,
    buf: &mut [u8],
    deadline: Instant,
) -> Result<usize, String> {
    match timeout_at(deadline, stream.read(buf)).await {
        Ok(Ok(n)) => Ok(n),
        Ok(Err(e)) => Err(crate::probe::err_code(&e, "recv_failed").into()),
        Err(_) => Err("timeout".into()),
    }
}

fn find_subslice(h: &[u8], n: &[u8]) -> Option<usize> {
    h.windows(n.len()).position(|w| w == n)
}

#[derive(Debug, PartialEq)]
struct Url {
    host: String,
    port: u16,
    /// Path plus query, always starting with '/'.
    path: String,
}

impl Url {
    fn host_header(&self) -> String {
        let h = if self.host.contains(':') {
            format!("[{}]", self.host)
        } else {
            self.host.clone()
        };
        if self.port == 80 {
            h
        } else {
            format!("{h}:{}", self.port)
        }
    }
}

fn parse_url(s: &str) -> Result<Url, String> {
    let Some(rest) = s.strip_prefix("http://") else {
        return Err(if s.starts_with("https://") {
            "https_unsupported"
        } else {
            "bad_url"
        }
        .into());
    };
    let rest = rest.split('#').next().unwrap_or_default();
    let split = rest.find(['/', '?']).unwrap_or(rest.len());
    let (auth, path) = rest.split_at(split);
    let path = if path.is_empty() {
        "/".to_string()
    } else if path.starts_with('?') {
        format!("/{path}")
    } else {
        path.to_string()
    };
    if auth.is_empty() || auth.contains('@') || path.bytes().any(|b| b <= b' ' || b == 0x7f) {
        return Err("bad_url".into());
    }
    let (host, port) = if let Some(v6) = auth.strip_prefix('[') {
        let (h, after) = v6.split_once(']').ok_or_else(|| "bad_url".to_string())?;
        let port = match after.strip_prefix(':') {
            Some(p) => p.parse().map_err(|_| "bad_url".to_string())?,
            None if after.is_empty() => 80,
            None => return Err("bad_url".into()),
        };
        (h.to_string(), port)
    } else {
        match auth.rsplit_once(':') {
            Some((h, p)) => (h.to_string(), p.parse().map_err(|_| "bad_url".to_string())?),
            None => (auth.to_string(), 80),
        }
    };
    if host.is_empty() || port == 0 {
        return Err("bad_url".into());
    }
    Ok(Url { host, port, path })
}

fn resolve_location(base: &Url, loc: &str) -> Result<String, String> {
    let loc = loc.trim();
    if loc.starts_with("http://") {
        Ok(loc.to_string())
    } else if loc.starts_with("https://") {
        Err("redirect_to_https".into())
    } else if let Some(r) = loc.strip_prefix("//") {
        Ok(format!("http://{r}"))
    } else if loc.starts_with('/') {
        Ok(format!("http://{}{loc}", base.host_header()))
    } else if loc.contains("://") {
        Err("redirect_unsupported_scheme".into())
    } else {
        let path = base.path.split('?').next().unwrap_or("/");
        let dir = path.rsplit_once('/').map(|(d, _)| d).unwrap_or("");
        Ok(format!("http://{}{dir}/{loc}", base.host_header()))
    }
}

#[derive(Debug, PartialEq)]
struct Head {
    status: u16,
    /// Lower-cased names, trimmed values.
    headers: Vec<(String, String)>,
}

impl Head {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v.as_str())
    }
}

fn parse_head(raw: &[u8]) -> Result<Head, String> {
    let text = String::from_utf8_lossy(raw);
    let mut lines = text.split("\r\n");
    let status_line = lines.next().unwrap_or_default();
    let mut parts = status_line.splitn(3, ' ');
    let version = parts.next().unwrap_or_default();
    let code = parts.next().unwrap_or_default();
    if !version.starts_with("HTTP/1.") || code.len() != 3 {
        return Err("bad_status_line".into());
    }
    let status: u16 = code.parse().map_err(|_| "bad_status_line".to_string())?;
    let mut headers = Vec::new();
    for l in lines.filter(|l| !l.is_empty()) {
        let (n, v) = l.split_once(':').ok_or_else(|| "bad_header".to_string())?;
        headers.push((n.trim().to_ascii_lowercase(), v.trim().to_string()));
    }
    Ok(Head { status, headers })
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum BodyKind {
    Length(u64),
    Chunked,
    UntilClose,
}

fn body_kind(h: &Head) -> Result<BodyKind, String> {
    let te_chunked = h
        .headers
        .iter()
        .filter(|(n, _)| n == "transfer-encoding")
        .flat_map(|(_, v)| v.split(','))
        .last()
        .is_some_and(|c| c.trim().eq_ignore_ascii_case("chunked"));
    if te_chunked {
        return Ok(BodyKind::Chunked);
    }
    let mut len = None;
    for (_, v) in h.headers.iter().filter(|(n, _)| n == "content-length") {
        let l: u64 = v.parse().map_err(|_| "bad_content_length".to_string())?;
        if len.is_some_and(|x| x != l) {
            return Err("bad_content_length".into());
        }
        len = Some(l);
    }
    Ok(len.map(BodyKind::Length).unwrap_or(BodyKind::UntilClose))
}

#[derive(Debug, PartialEq)]
enum ChunkState {
    /// Reading the hex size line (accumulated bytes).
    Size(Vec<u8>),
    Data(u64),
    /// CRLF after chunk data; number of bytes still expected.
    DataEnd(u8),
    Done,
}

/// Counts payload bytes of a body as it streams in.
#[derive(Debug)]
struct BodyCounter {
    kind: BodyKind,
    chunk: ChunkState,
    bytes: u64,
}

impl BodyCounter {
    fn new(kind: BodyKind) -> Self {
        Self {
            kind,
            chunk: ChunkState::Size(Vec::new()),
            bytes: 0,
        }
    }

    fn done(&self) -> bool {
        match self.kind {
            BodyKind::Length(l) => self.bytes >= l,
            BodyKind::Chunked => self.chunk == ChunkState::Done,
            BodyKind::UntilClose => false,
        }
    }

    /// Called at EOF; true if the body is complete.
    fn finish_on_eof(&self) -> bool {
        self.kind == BodyKind::UntilClose || self.done()
    }

    fn feed(&mut self, data: &[u8]) -> Result<(), String> {
        match self.kind {
            BodyKind::Length(l) => {
                let take = (data.len() as u64).min(l.saturating_sub(self.bytes));
                self.bytes += take;
                Ok(())
            }
            BodyKind::UntilClose => {
                self.bytes += data.len() as u64;
                Ok(())
            }
            BodyKind::Chunked => self.feed_chunked(data),
        }
    }

    fn feed_chunked(&mut self, mut data: &[u8]) -> Result<(), String> {
        while !data.is_empty() {
            match &mut self.chunk {
                ChunkState::Done => return Ok(()),
                ChunkState::Size(line) => {
                    let nl = data.iter().position(|&b| b == b'\n');
                    let end = nl.map(|i| i + 1).unwrap_or(data.len());
                    line.extend_from_slice(&data[..end]);
                    data = &data[end..];
                    if line.len() > MAX_CHUNK_LINE {
                        return Err("bad_chunk".into());
                    }
                    if nl.is_some() {
                        let size = parse_chunk_size(line)?;
                        self.chunk = if size == 0 {
                            ChunkState::Done
                        } else {
                            ChunkState::Data(size)
                        };
                    }
                }
                ChunkState::Data(left) => {
                    let take = (data.len() as u64).min(*left);
                    *left -= take;
                    self.bytes += take;
                    data = &data[take as usize..];
                    if *left == 0 {
                        self.chunk = ChunkState::DataEnd(2);
                    }
                }
                ChunkState::DataEnd(left) => {
                    let expect: &[u8] = if *left == 2 { b"\r\n" } else { b"\n" };
                    if data[0] != expect[0] {
                        return Err("bad_chunk".into());
                    }
                    data = &data[1..];
                    *left -= 1;
                    if *left == 0 {
                        self.chunk = ChunkState::Size(Vec::new());
                    }
                }
            }
        }
        Ok(())
    }
}

/// "1a2b;ext=1\r\n" -> 0x1a2b.
fn parse_chunk_size(line: &[u8]) -> Result<u64, String> {
    let s = std::str::from_utf8(line).map_err(|_| "bad_chunk".to_string())?;
    let hex = s.split(';').next().unwrap_or_default().trim();
    if hex.is_empty() || hex.len() > 16 {
        return Err("bad_chunk".into());
    }
    u64::from_str_radix(hex, 16).map_err(|_| "bad_chunk".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    #[test]
    fn url_parsing() {
        assert_eq!(
            parse_url("http://example.com/50MB.zip").unwrap(),
            Url {
                host: "example.com".into(),
                port: 80,
                path: "/50MB.zip".into()
            }
        );
        assert_eq!(
            parse_url("http://1.2.3.4:8080?x=1#frag").unwrap(),
            Url {
                host: "1.2.3.4".into(),
                port: 8080,
                path: "/?x=1".into()
            }
        );
        let v6 = parse_url("http://[::1]:81/a").unwrap();
        assert_eq!(v6.host, "::1");
        assert_eq!(v6.host_header(), "[::1]:81");
        assert_eq!(parse_url("https://x/").unwrap_err(), "https_unsupported");
        for bad in [
            "ftp://x",
            "http://",
            "http://:80/",
            "http://h:x/",
            "http://u@h/",
            "http://h/a b",
            "http://h:0/",
        ] {
            assert!(parse_url(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn redirects_resolve() {
        let base = parse_url("http://h:81/dir/file?q").unwrap();
        assert_eq!(resolve_location(&base, "http://o/x").unwrap(), "http://o/x");
        assert_eq!(resolve_location(&base, "/abs").unwrap(), "http://h:81/abs");
        assert_eq!(
            resolve_location(&base, "rel").unwrap(),
            "http://h:81/dir/rel"
        );
        assert_eq!(resolve_location(&base, "//cdn/y").unwrap(), "http://cdn/y");
        assert_eq!(
            resolve_location(&base, "https://s/").unwrap_err(),
            "redirect_to_https"
        );
        assert!(resolve_location(&base, "ftp://s/").is_err());
    }

    #[test]
    fn head_parsing() {
        let h = parse_head(b"HTTP/1.1 200 OK\r\nContent-Length: 42\r\nX-A:  b \r\n\r\n").unwrap();
        assert_eq!(h.status, 200);
        assert_eq!(h.header("content-length"), Some("42"));
        assert_eq!(h.header("x-a"), Some("b"));
        assert_eq!(body_kind(&h).unwrap(), BodyKind::Length(42));
        let h = parse_head(b"HTTP/1.0 404\r\n\r\n").unwrap();
        assert_eq!(h.status, 404);
        assert_eq!(body_kind(&h).unwrap(), BodyKind::UntilClose);
        let h = parse_head(
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip, chunked\r\nContent-Length: 5\r\n\r\n",
        )
        .unwrap();
        assert_eq!(body_kind(&h).unwrap(), BodyKind::Chunked);
        let h = parse_head(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nContent-Length: 6\r\n\r\n")
            .unwrap();
        assert!(body_kind(&h).is_err());
        let h = parse_head(b"HTTP/1.1 200 OK\r\nContent-Length: -1\r\n\r\n").unwrap();
        assert!(body_kind(&h).is_err());
        assert!(parse_head(b"SSH-2.0-OpenSSH\r\n\r\n").is_err());
        assert!(parse_head(b"HTTP/1.1 20 OK\r\n\r\n").is_err());
        assert!(parse_head(b"HTTP/1.1 200 OK\r\nnocolon\r\n\r\n").is_err());
        assert!(parse_head(b"").is_err());
    }

    #[test]
    fn chunked_decoding_any_split() {
        let body = b"4;ext=1\r\nWiki\r\n5\r\npedia\r\nE\r\n in\r\n\r\nchunks.\r\n0\r\n\r\n";
        for split in 0..body.len() {
            let mut c = BodyCounter::new(BodyKind::Chunked);
            c.feed(&body[..split]).unwrap();
            c.feed(&body[split..]).unwrap();
            assert!(c.done(), "split {split}");
            assert_eq!(c.bytes, 23);
        }
        let mut byte_by_byte = BodyCounter::new(BodyKind::Chunked);
        for b in body {
            byte_by_byte.feed(&[*b]).unwrap();
        }
        assert_eq!(byte_by_byte.bytes, 23);
    }

    #[test]
    fn chunked_errors() {
        for bad in [
            &b"zz\r\n"[..],
            b"4\r\nWikiXX",
            b"ffffffffffffffffff\r\n",
            b";\r\n",
        ] {
            let mut c = BodyCounter::new(BodyKind::Chunked);
            assert!(c.feed(bad).is_err(), "{:?}", String::from_utf8_lossy(bad));
        }
        let mut c = BodyCounter::new(BodyKind::Chunked);
        assert!(c.feed(&[b'1'; 2000]).is_err(), "endless size line");
        let mut c = BodyCounter::new(BodyKind::Chunked);
        c.feed(b"5\r\nab").unwrap();
        assert!(!c.finish_on_eof());
    }

    #[test]
    fn length_body_caps() {
        let mut c = BodyCounter::new(BodyKind::Length(3));
        c.feed(b"abcdef").unwrap();
        assert_eq!(c.bytes, 3);
        assert!(c.done());
    }

    /// Serves canned responses on 127.0.0.1; path selects the response.
    async fn server() -> SocketAddr {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let Ok((mut s, _)) = l.accept().await else {
                    return;
                };
                tokio::spawn(async move {
                    let mut req = Vec::new();
                    let mut b = [0u8; 1024];
                    while find_subslice(&req, b"\r\n\r\n").is_none() {
                        match s.read(&mut b).await {
                            Ok(0) | Err(_) => return,
                            Ok(n) => req.extend_from_slice(&b[..n]),
                        }
                    }
                    let line = String::from_utf8_lossy(&req)
                        .lines()
                        .next()
                        .unwrap_or_default()
                        .to_string();
                    let path = line.split(' ').nth(1).unwrap_or("/").to_string();
                    let big = vec![b'x'; 200_000];
                    let resp: Vec<u8> = match path.as_str() {
                        "/len" => [b"HTTP/1.1 200 OK\r\nContent-Length: 200000\r\n\r\n".to_vec(), big].concat(),
                        "/chunked" => b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n2\r\nde\r\n0\r\n\r\n".to_vec(),
                        "/close" => [b"HTTP/1.0 200 OK\r\n\r\n".to_vec(), big].concat(),
                        "/short" => b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\nabc".to_vec(),
                        "/r1" => b"HTTP/1.1 302 Found\r\nLocation: /r2\r\nContent-Length: 0\r\n\r\n".to_vec(),
                        "/r2" => b"HTTP/1.1 301 Moved\r\nLocation: chunked\r\nContent-Length: 0\r\n\r\n".to_vec(),
                        "/loop" => b"HTTP/1.1 307 Again\r\nLocation: /loop\r\n\r\n".to_vec(),
                        "/https" => b"HTTP/1.1 301 Moved\r\nLocation: https://x/\r\n\r\n".to_vec(),
                        "/hang" => {
                            let _ = s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 999999\r\n\r\nab").await;
                            tokio::time::sleep(Duration::from_secs(5)).await;
                            return;
                        }
                        "/huge" => [b"HTTP/1.1 200 OK\r\n".to_vec(), vec![b'a'; 20_000]].concat(),
                        _ => b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n".to_vec(),
                    };
                    let _ = s.write_all(&resp).await;
                    let _ = s.shutdown().await;
                });
            }
        });
        addr
    }

    fn opts(max_bytes: u64, timeout_ms: u64) -> Opts {
        Opts {
            max_bytes,
            timeout: Duration::from_millis(timeout_ms),
            duration: Duration::from_millis(timeout_ms),
            warmup: Duration::from_millis(0),
        }
    }

    async fn get(addr: SocketAddr, path: &str, max: u64) -> SpeedResult {
        let url = format!("http://{addr}{path}");
        download("lo", &[url], &opts(max, 2000)).await
    }

    #[tokio::test]
    async fn loopback_downloads() {
        let a = server().await;
        let r = get(a, "/len", u64::MAX).await;
        assert_eq!((r.bytes, r.err.as_deref()), (200_000, None), "{r:?}");
        assert!(r.mbps.is_some_and(|m| m > 0.0), "{r:?}");
        let r = get(a, "/chunked", u64::MAX).await;
        assert_eq!((r.bytes, r.err.as_deref()), (5, None), "{r:?}");
        let r = get(a, "/close", u64::MAX).await;
        assert_eq!((r.bytes, r.err.as_deref()), (200_000, None), "{r:?}");
        let r = get(a, "/len", 1000).await;
        assert!(
            r.err.is_none() && r.bytes >= 1000 && r.bytes < 200_000,
            "{r:?}"
        );
        let r = get(a, "/short", u64::MAX).await;
        assert_eq!(
            (r.bytes, r.err.as_deref()),
            (3, Some("truncated_body")),
            "{r:?}"
        );
        let r = get(a, "/r1", u64::MAX).await;
        assert_eq!((r.bytes, r.err.as_deref()), (5, None), "{r:?}");
        let r = get(a, "/loop", u64::MAX).await;
        assert_eq!(r.err.as_deref(), Some("too_many_redirects"));
        let r = get(a, "/https", u64::MAX).await;
        assert_eq!(r.err.as_deref(), Some("redirect_to_https"));
        let r = get(a, "/missing", u64::MAX).await;
        assert_eq!(r.err.as_deref(), Some("http_404"));
        let r = get(a, "/huge", u64::MAX).await;
        assert_eq!(r.err.as_deref(), Some("header_too_large"));
    }

    #[tokio::test]
    async fn deadline_stops_measurement() {
        let a = server().await;
        let url = format!("http://{a}/hang");
        let t = std::time::Instant::now();
        let r = download("lo", std::slice::from_ref(&url), &opts(u64::MAX, 500)).await;
        assert!(t.elapsed() < Duration::from_secs(2));
        assert_eq!((r.bytes, r.err.as_deref()), (2, None), "{r:?}");
        // Time-based: the body measurement stops after `duration`, well before the timeout.
        let t = std::time::Instant::now();
        let o = Opts { duration: Duration::from_millis(300), ..opts(u64::MAX, 3000) };
        let r = download("lo", &[url], &o).await;
        assert!(t.elapsed() < Duration::from_millis(1500), "{:?}", t.elapsed());
        assert_eq!(r.err, None, "{r:?}");
    }

    #[tokio::test]
    async fn falls_back_to_next_url() {
        let a = server().await;
        let urls = vec![
            "https://nope/".to_string(),
            format!("http://{a}/missing"),
            format!("http://{a}/chunked"),
        ];
        let r = download("lo", &urls, &opts(u64::MAX, 2000)).await;
        assert_eq!((r.bytes, r.err.as_deref()), (5, None), "{r:?}");
        let r = download("lo", &[], &opts(1, 1000)).await;
        assert_eq!(r.err.as_deref(), Some("no_urls"));
    }

    #[tokio::test]
    #[ignore = "real download on wlo1 (max 8 s / 50 MB)"]
    async fn real_download() {
        let c = crate::config::Speed::default();
        let o = Opts { max_bytes: c.max_bytes, timeout: Duration::from_secs(c.timeout_s), duration: Duration::from_secs(c.duration_s), warmup: Duration::from_millis(c.warmup_ms) };
        let r = download("wlo1", &c.urls, &o).await;
        println!("speed: {r:?}");
        assert!(r.err.is_none(), "{r:?}");
    }
}
