//! Optional read-only router telemetry over UPnP IGDv1/IGDv2 (unauthenticated LAN status & counters).
//!
//! Zero external crates or subprocesses: uses a tiny bounded SSDP M-SEARCH + HTTP/1.1 + SOAP XML
//! client with explicit timeouts on every socket call and no `unsafe` code.

pub mod advice;
#[cfg(feature = "router-audit")]
pub mod audit;
#[cfg(feature = "cve")]
pub mod cve;
pub mod types;

pub use types::{CveLookupResponse, PortCheck, RouterAudit};

use crate::config::Router as RouterConfig;
use crate::model::RouterSample;
use anyhow::{Context, bail};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};

const HTTP_TIMEOUT: Duration = Duration::from_secs(3);
const MAX_HTTP_BYTES: usize = 128 * 1024;
const MAX_HEADER_BYTES: usize = 16 * 1024;
const UPNP_IGD_TYPES: [&str; 2] = [
    "urn:schemas-upnp-org:device:InternetGatewayDevice:1",
    "urn:schemas-upnp-org:device:InternetGatewayDevice:2",
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpUrl {
    pub host: String,
    pub port: u16,
    pub path: String,
}

impl HttpUrl {
    pub fn base_string(&self) -> String {
        format!("http://{}:{}", self.host, self.port)
    }

    pub fn with_path(&self, raw_path: &str) -> Self {
        let p = raw_path.trim();
        let path = if p.is_empty() {
            "/".to_string()
        } else if let Some(rest) = p.strip_prefix("http://") {
            match rest.find('/') {
                Some(i) => rest[i..].to_string(),
                None => "/".to_string(),
            }
        } else if p.starts_with('/') {
            p.to_string()
        } else {
            let base_dir = match self.path.rfind('/') {
                Some(i) => &self.path[..=i],
                None => "/",
            };
            format!("{base_dir}{p}")
        };
        Self {
            host: self.host.clone(),
            port: self.port,
            path,
        }
    }
}

/// Parses a plain `http://host[:port][/path]` URL.
pub fn parse_http_url(url: &str) -> anyhow::Result<HttpUrl> {
    let trimmed = url.trim();
    let rest = trimmed
        .strip_prefix("http://")
        .ok_or_else(|| anyhow::anyhow!("router URL must start with http:// : {trimmed}"))?;
    anyhow::ensure!(
        !rest.bytes().any(|b| b.is_ascii_control() || b == b' '),
        "invalid characters in URL: {trimmed}"
    );
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    anyhow::ensure!(
        !authority.is_empty() && !authority.contains('@'),
        "invalid authority in URL: {trimmed}"
    );
    let (host, port) = match authority.rsplit_once(':') {
        Some((h, p)) => {
            anyhow::ensure!(!h.is_empty(), "empty host in URL: {trimmed}");
            let port: u16 = p
                .parse()
                .with_context(|| format!("invalid port in URL: {trimmed}"))?;
            (h.to_string(), port)
        }
        None => (authority.to_string(), 80),
    };
    Ok(HttpUrl {
        host,
        port,
        path: if path.is_empty() { "/".into() } else { path.into() },
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IgdEndpoints {
    pub base: HttpUrl,
    pub model: Option<String>,
    pub manufacturer: Option<String>,
    pub model_number: Option<String>,
    pub presentation_url: Option<String>,
    pub wan_common: Option<(String, String)>,
    pub wan_conn: Option<(String, String)>,
}

#[derive(Debug, Clone, Default)]
#[cfg_attr(not(feature = "router-audit"), allow(dead_code, reason = "firmware_hint and admin_url feed the router-audit UPnP adapter"))]
pub(crate) struct UpnpMeta {
    pub vendor: Option<String>,
    pub model: Option<String>,
    pub firmware_hint: Option<String>,
    pub admin_url: Option<String>,
    pub uptime_s: Option<u64>,
    pub wan_status: Option<String>,
    pub wan_access: Option<String>,
    pub link_down_mbps: Option<f64>,
    pub link_up_mbps: Option<f64>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum CounterDelta {
    Rate(f64),
    Saturated,
    Reset,
}

#[derive(Debug, Clone)]
struct PrevCounters {
    base: String,
    at: Instant,
    rx_bytes: Option<u64>,
    tx_bytes: Option<u64>,
    rx_pkts: Option<u64>,
    tx_pkts: Option<u64>,
}

pub struct Poller {
    endpoints: Option<IgdEndpoints>,
    prev: Option<PrevCounters>,
    fail_streak: u32,
}

impl Default for Poller {
    fn default() -> Self {
        Self::new()
    }
}

impl Poller {
    pub fn new() -> Self {
        Self {
            endpoints: None,
            prev: None,
            fail_streak: 0,
        }
    }

    /// Discovers IGD endpoints if needed and polls read-only UPnP status & counters.
    pub async fn poll(&mut self, gateway: Ipv4Addr, cfg: &RouterConfig) -> anyhow::Result<RouterSample> {
        if self.endpoints.is_none() {
            let desc_url = match &cfg.upnp_url {
                Some(u) => parse_http_url(u)?,
                None => {
                    let found = discover_igd(gateway, Duration::from_millis(2400)).await?;
                    parse_http_url(&found)?
                }
            };
            let xml = http_get(&desc_url, HTTP_TIMEOUT).await?;
            let eps = parse_igd_xml(&xml, &desc_url);
            if eps.wan_common.is_none() && eps.wan_conn.is_none() {
                bail!("router IGD XML contained neither WANCommonInterfaceConfig nor WANIP/PPPConnection");
            }
            self.endpoints = Some(eps);
        }

        let Some(eps) = self.endpoints.clone() else {
            bail!("missing IGD endpoints");
        };

        let res = poll_endpoints(&eps).await;
        match res {
            Ok((mut sample, rx_b, tx_b, rx_p, tx_p)) => {
                self.fail_streak = 0;
                let now = Instant::now();
                let base_key = eps.base.base_string();
                if let Some(prev) = &self.prev
                    && prev.base == base_key
                {
                    let dt = now.duration_since(prev.at).as_secs_f64();
                    if (1.0..=300.0).contains(&dt) {
                        const MAX_BYTE_RATE: f64 = 10_000_000_000.0 / 8.0;
                        const MAX_PKT_RATE: f64 = 2_000_000.0;
                        if let (Some(p), Some(c)) = (prev.rx_bytes, rx_b) {
                            match counter_delta(p, c, dt, MAX_BYTE_RATE) {
                                CounterDelta::Rate(r) => sample.wan_rx_mbps = Some(r * 8.0 / 1e6),
                                CounterDelta::Saturated => sample.bytes_saturated = true,
                                CounterDelta::Reset => {}
                            }
                        }
                        if let (Some(p), Some(c)) = (prev.tx_bytes, tx_b) {
                            match counter_delta(p, c, dt, MAX_BYTE_RATE) {
                                CounterDelta::Rate(r) => sample.wan_tx_mbps = Some(r * 8.0 / 1e6),
                                CounterDelta::Saturated => sample.bytes_saturated = true,
                                CounterDelta::Reset => {}
                            }
                        }
                        if let (Some(p), Some(c)) = (prev.rx_pkts, rx_p)
                            && let CounterDelta::Rate(r) = counter_delta(p, c, dt, MAX_PKT_RATE)
                        {
                            sample.wan_rx_pps = Some(r);
                        }
                        if let (Some(p), Some(c)) = (prev.tx_pkts, tx_p)
                            && let CounterDelta::Rate(r) = counter_delta(p, c, dt, MAX_PKT_RATE)
                        {
                            sample.wan_tx_pps = Some(r);
                        }
                    }
                }
                self.prev = Some(PrevCounters {
                    base: base_key,
                    at: now,
                    rx_bytes: rx_b,
                    tx_bytes: tx_b,
                    rx_pkts: rx_p,
                    tx_pkts: tx_p,
                });
                Ok(sample)
            }
            Err(e) => {
                self.fail_streak += 1;
                if self.fail_streak >= 3 {
                    self.endpoints = None;
                    self.prev = None;
                }
                Err(e)
            }
        }
    }
}

async fn poll_endpoints(
    eps: &IgdEndpoints,
) -> anyhow::Result<(RouterSample, Option<u64>, Option<u64>, Option<u64>, Option<u64>)> {
    let mut sample = RouterSample {
        source: Some("upnp_igd".into()),
        model: eps.model.clone(),
        ..Default::default()
    };
    let mut any_ok = false;
    let mut rx_b = None;
    let mut tx_b = None;
    let mut rx_p = None;
    let mut tx_p = None;

    if let Some((svc, ctrl)) = &eps.wan_common {
        if let Ok(xml) = soap_call(&eps.base, ctrl, svc, "GetCommonLinkProperties").await {
            any_ok = true;
            sample.wan_access = xml_tag_text(&xml, "NewWANAccessType");
            sample.phy_status = xml_tag_text(&xml, "NewPhysicalLinkStatus");
            sample.link_down_mbps = xml_tag_text(&xml, "NewLayer1DownstreamMaxBitRate")
                .and_then(|s| s.parse::<u64>().ok())
                .filter(|&v| v > 0)
                .map(|v| v as f64 / 1e6);
            sample.link_up_mbps = xml_tag_text(&xml, "NewLayer1UpstreamMaxBitRate")
                .and_then(|s| s.parse::<u64>().ok())
                .filter(|&v| v > 0)
                .map(|v| v as f64 / 1e6);
        }
        if let Ok(xml) = soap_call(&eps.base, ctrl, svc, "GetTotalBytesReceived").await
            && let Some(v) = xml_tag_text(&xml, "NewTotalBytesReceived").and_then(|s| s.parse::<u64>().ok())
        {
            any_ok = true;
            rx_b = Some(v);
        }
        if let Ok(xml) = soap_call(&eps.base, ctrl, svc, "GetTotalBytesSent").await
            && let Some(v) = xml_tag_text(&xml, "NewTotalBytesSent").and_then(|s| s.parse::<u64>().ok())
        {
            any_ok = true;
            tx_b = Some(v);
        }
        if let Ok(xml) = soap_call(&eps.base, ctrl, svc, "GetTotalPacketsReceived").await
            && let Some(v) = xml_tag_text(&xml, "NewTotalPacketsReceived").and_then(|s| s.parse::<u64>().ok())
        {
            any_ok = true;
            rx_p = Some(v);
        }
        if let Ok(xml) = soap_call(&eps.base, ctrl, svc, "GetTotalPacketsSent").await
            && let Some(v) = xml_tag_text(&xml, "NewTotalPacketsSent").and_then(|s| s.parse::<u64>().ok())
        {
            any_ok = true;
            tx_p = Some(v);
        }
    }

    if let Some((svc, ctrl)) = &eps.wan_conn
        && let Ok(xml) = soap_call(&eps.base, ctrl, svc, "GetStatusInfo").await
    {
        any_ok = true;
        sample.wan_status = xml_tag_text(&xml, "NewConnectionStatus");
        sample.last_error = xml_tag_text(&xml, "NewLastConnectionError")
            .filter(|e| !e.eq_ignore_ascii_case("ERROR_NONE"));
        sample.uptime_s = xml_tag_text(&xml, "NewUptime").and_then(|s| s.parse::<u64>().ok());
    }

    anyhow::ensure!(any_ok, "no UPnP SOAP action succeeded on {}", eps.base.base_string());
    Ok((sample, rx_b, tx_b, rx_p, tx_p))
}

/// Computes per-second rate between two cumulative counters, handling 32-bit wraparound and
/// routers (observed on DOCSIS CPEs) whose signed/unsigned 32-bit byte counters clamp at MAX.
pub fn counter_delta(prev: u64, cur: u64, dt_s: f64, max_rate: f64) -> CounterDelta {
    if dt_s <= 0.0 || !dt_s.is_finite() {
        return CounterDelta::Reset;
    }
    if cur == prev && (cur == i32::MAX as u64 || cur == u32::MAX as u64) {
        return CounterDelta::Saturated;
    }
    let delta = if cur >= prev {
        cur - prev
    } else if prev <= u32::MAX as u64 && cur <= u32::MAX as u64 {
        (u32::MAX as u64 - prev) + cur + 1
    } else {
        return CounterDelta::Reset;
    };
    let rate = delta as f64 / dt_s;
    if rate.is_finite() && rate <= max_rate {
        CounterDelta::Rate(rate)
    } else {
        CounterDelta::Reset
    }
}

/// Discovers the gateway's UPnP IGD device description URL and optional SSDP `SERVER` header.
pub(crate) async fn discover_igd_meta(gateway: Ipv4Addr, timeout: Duration) -> anyhow::Result<(String, Option<String>)> {
    let sock = UdpSocket::bind(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0)))
        .await
        .context("bind UDP for SSDP")?;
    let half = (timeout / 2).max(Duration::from_millis(500));

    // Try direct unicast to the gateway first (no LAN multicast noise).
    for st in UPNP_IGD_TYPES {
        let msg = format!(
            "M-SEARCH * HTTP/1.1\r\nHOST: {gateway}:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 1\r\nST: {st}\r\n\r\n"
        );
        let _ = sock
            .send_to(msg.as_bytes(), SocketAddr::V4(SocketAddrV4::new(gateway, 1900)))
            .await;
    }
    if let Some(hit) = recv_ssdp_location(&sock, gateway, half).await {
        return Ok(hit);
    }

    // Fallback: standard SSDP multicast, filtering replies strictly to the router IP.
    let mcast = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(239, 255, 255, 250), 1900));
    for st in UPNP_IGD_TYPES {
        let msg = format!(
            "M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 1\r\nST: {st}\r\n\r\n"
        );
        let _ = sock.send_to(msg.as_bytes(), mcast).await;
    }
    recv_ssdp_location(&sock, gateway, half)
        .await
        .ok_or_else(|| anyhow::anyhow!("no UPnP IGD SSDP response from {gateway}"))
}

/// Discovers the gateway's UPnP IGD device description URL via SSDP M-SEARCH.
pub async fn discover_igd(gateway: Ipv4Addr, timeout: Duration) -> anyhow::Result<String> {
    discover_igd_meta(gateway, timeout).await.map(|(loc, _)| loc)
}

async fn recv_ssdp_location(sock: &UdpSocket, gateway: Ipv4Addr, wait: Duration) -> Option<(String, Option<String>)> {
    let deadline = tokio::time::Instant::now() + wait;
    let mut buf = [0u8; 4096];
    while tokio::time::Instant::now() < deadline {
        let rem = deadline.saturating_duration_since(tokio::time::Instant::now());
        match tokio::time::timeout(rem, sock.recv_from(&mut buf)).await {
            Ok(Ok((n, _from))) => {
                let text = String::from_utf8_lossy(&buf[..n]);
                if let Some(loc) = ssdp_location(&text, gateway) {
                    return Some((loc, ssdp_server(&text)));
                }
            }
            _ => break,
        }
    }
    None
}

fn ssdp_server(resp: &str) -> Option<String> {
    for line in resp.lines() {
        let Some((name, val)) = line.split_once(':') else {
            continue;
        };
        if name.trim().eq_ignore_ascii_case("SERVER") {
            let s = val.trim();
            if !s.is_empty() {
                return Some(s.to_string());
            }
        }
    }
    None
}

/// Probes UPnP IGD metadata once (vendor, model, SSDP Server hint, admin URL, link stats).
pub(crate) async fn probe_upnp_meta(gateway: Ipv4Addr, upnp_url: Option<&str>) -> anyhow::Result<UpnpMeta> {
    let (desc_url, server) = match upnp_url {
        Some(u) => (parse_http_url(u)?, None),
        None => {
            let (found, srv) = discover_igd_meta(gateway, Duration::from_millis(2000)).await?;
            (parse_http_url(&found)?, srv)
        }
    };
    let xml = http_get(&desc_url, HTTP_TIMEOUT).await?;
    let eps = parse_igd_xml(&xml, &desc_url);
    let mut meta = UpnpMeta {
        vendor: eps.manufacturer.clone(),
        model: eps.model.clone().or_else(|| eps.model_number.clone()),
        firmware_hint: server,
        admin_url: eps.presentation_url.clone(),
        ..Default::default()
    };
    if (eps.wan_common.is_some() || eps.wan_conn.is_some())
        && let Ok((s, _, _, _, _)) = poll_endpoints(&eps).await
    {
        meta.uptime_s = s.uptime_s;
        meta.wan_status = s.wan_status;
        meta.wan_access = s.wan_access;
        meta.link_down_mbps = s.link_down_mbps;
        meta.link_up_mbps = s.link_up_mbps;
    }
    Ok(meta)
}

/// Extracts a `LOCATION` HTTP URL from an SSDP reply only if its host equals `gateway`.
pub fn ssdp_location(resp: &str, gateway: Ipv4Addr) -> Option<String> {
    let gw_str = gateway.to_string();
    for line in resp.lines() {
        let Some((name, val)) = line.split_once(':') else {
            continue;
        };
        if name.trim().eq_ignore_ascii_case("LOCATION") {
            let loc = val.trim();
            if let Ok(u) = parse_http_url(loc)
                && u.host == gw_str
            {
                return Some(loc.to_string());
            }
        }
    }
    None
}

async fn http_get(url: &HttpUrl, timeout: Duration) -> anyhow::Result<String> {
    let req = format!(
        "GET {} HTTP/1.1\r\nHost: {}:{}\r\nConnection: close\r\nUser-Agent: linkwatch\r\n\r\n",
        url.path, url.host, url.port
    );
    http_exchange(url, req.as_bytes(), timeout).await
}

async fn soap_call(
    base: &HttpUrl,
    control_path: &str,
    service_type: &str,
    action: &str,
) -> anyhow::Result<String> {
    let target = base.with_path(control_path);
    let body = format!(
        "<?xml version=\"1.0\" encoding=\"utf-8\"?>\
<s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\">\
<s:Body><u:{action} xmlns:u=\"{service_type}\"/></s:Body></s:Envelope>"
    );
    let req = format!(
        "POST {} HTTP/1.1\r\nHost: {}:{}\r\nContent-Type: text/xml; charset=\"utf-8\"\r\nSOAPAction: \"{service_type}#{action}\"\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        target.path,
        target.host,
        target.port,
        body.len()
    );
    http_exchange(&target, req.as_bytes(), HTTP_TIMEOUT).await
}

async fn http_exchange(target: &HttpUrl, req: &[u8], timeout: Duration) -> anyhow::Result<String> {
    let (code, head, body) = http_exchange_raw(target, req, timeout).await?;
    let status_line = head.lines().next().unwrap_or_default();
    anyhow::ensure!((200..300).contains(&code), "HTTP {code}: {status_line}");
    Ok(body)
}

pub(crate) async fn http_exchange_raw(
    target: &HttpUrl,
    req: &[u8],
    timeout: Duration,
) -> anyhow::Result<(u16, String, String)> {
    tokio::time::timeout(timeout, async {
        let mut s = TcpStream::connect((target.host.as_str(), target.port))
            .await
            .with_context(|| format!("connect {}:{}", target.host, target.port))?;
        s.write_all(req).await.context("send HTTP request")?;
        let mut buf = Vec::with_capacity(4096);
        let mut chunk = [0u8; 4096];
        loop {
            let n = s.read(&mut chunk).await.context("read HTTP response")?;
            if n == 0 {
                break;
            }
            if buf.len() + n > MAX_HTTP_BYTES {
                // A cut-off XML/SOAP body would parse into wrong or missing values: refuse it.
                bail!("HTTP response from {}:{} larger than {} bytes", target.host, target.port, MAX_HTTP_BYTES);
            }
            buf.extend_from_slice(&chunk[..n]);
        }
        parse_http_raw(&buf)
    })
    .await
    .map_err(|_| anyhow::anyhow!("HTTP timeout to {}:{}", target.host, target.port))?
}

pub fn parse_http_raw(raw: &[u8]) -> anyhow::Result<(u16, String, String)> {
    let sep = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .filter(|&p| p <= MAX_HEADER_BYTES)
        .ok_or_else(|| anyhow::anyhow!("malformed HTTP response"))?;
    let head = String::from_utf8_lossy(&raw[..sep]).into_owned();
    let status_line = head.lines().next().unwrap_or_default();
    let code: u16 = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|c| c.parse().ok())
        .unwrap_or(0);
    let chunked = head.lines().any(|l| {
        l.split_once(':').is_some_and(|(k, v)| {
            k.trim().eq_ignore_ascii_case("transfer-encoding")
                && v.to_ascii_lowercase().contains("chunked")
        })
    });
    let body = &raw[sep + 4..];
    let decoded = if chunked {
        decode_chunked(body).ok_or_else(|| anyhow::anyhow!("invalid chunked HTTP body"))?
    } else {
        body.to_vec()
    };
    Ok((code, head, String::from_utf8_lossy(&decoded).into_owned()))
}

pub fn decode_chunked(mut src: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    while !src.is_empty() {
        let crlf = src.windows(2).position(|w| w == b"\r\n")?;
        let line = std::str::from_utf8(&src[..crlf]).ok()?.trim();
        let hex_len = line.split(';').next()?.trim();
        let size = usize::from_str_radix(hex_len, 16).ok()?;
        src = &src[crlf + 2..];
        if size == 0 {
            return Some(out);
        }
        if src.len() < size {
            return None;
        }
        out.extend_from_slice(&src[..size]);
        src = &src[size..];
        if src.starts_with(b"\r\n") {
            src = &src[2..];
        }
    }
    Some(out)
}

/// Extracts IGD model info and WANCommonInterfaceConfig / WAN*Connection control URLs.
pub fn parse_igd_xml(xml: &str, base: &HttpUrl) -> IgdEndpoints {
    let root_header = match find_ascii_ci(xml, "<deviceList>") {
        Some(pos) => &xml[..pos],
        None => xml,
    };
    let mfg = xml_tag_text(root_header, "manufacturer");
    let model_name = xml_tag_text(root_header, "modelName")
        .or_else(|| xml_tag_text(root_header, "friendlyName"));
    let model_number = xml_tag_text(root_header, "modelNumber");
    let presentation_url = xml_tag_text(root_header, "presentationURL");
    let model = match (&mfg, &model_name) {
        (Some(a), Some(b)) if !b.to_ascii_lowercase().contains(&a.to_ascii_lowercase()) => {
            Some(format!("{a} {b}"))
        }
        (_, Some(b)) => Some(b.clone()),
        (Some(a), None) => Some(a.clone()),
        (None, None) => None,
    };

    let mut wan_common = None;
    let mut wan_conn = None;
    for svc in xml_blocks(xml, "service") {
        let Some(stype) = xml_tag_text(svc, "serviceType") else {
            continue;
        };
        let Some(ctrl) = xml_tag_text(svc, "controlURL") else {
            continue;
        };
        if wan_common.is_none()
            && stype.contains(":service:WANCommonInterfaceConfig:")
        {
            wan_common = Some((stype, ctrl));
        } else if wan_conn.is_none()
            && (stype.contains(":service:WANIPConnection:")
                || stype.contains(":service:WANPPPConnection:"))
        {
            wan_conn = Some((stype, ctrl));
        }
    }

    IgdEndpoints {
        base: base.clone(),
        model,
        manufacturer: mfg,
        model_number,
        presentation_url,
        wan_common,
        wan_conn,
    }
}

fn find_ascii_ci(haystack: &str, needle: &str) -> Option<usize> {
    let h = haystack.as_bytes();
    let n = needle.as_bytes();
    if n.is_empty() || h.len() < n.len() {
        return None;
    }
    (0..=h.len() - n.len()).find(|&i| h[i..i + n.len()].eq_ignore_ascii_case(n))
}

fn xml_blocks<'a>(xml: &'a str, tag: &str) -> Vec<&'a str> {
    let open = format!("<{tag}");
    let close = format!("</{tag}>");
    let mut out = Vec::new();
    let mut pos = 0;
    while let Some(rel_start) = find_ascii_ci(&xml[pos..], &open) {
        let abs_start = pos + rel_start;
        let after_open = abs_start + open.len();
        let Some(next_ch) = xml[after_open..].chars().next() else {
            break;
        };
        if next_ch != '>' && !next_ch.is_ascii_whitespace() {
            pos = after_open;
            continue;
        }
        let Some(rel_gt) = xml[after_open..].find('>') else {
            break;
        };
        let content_start = after_open + rel_gt + 1;
        let Some(rel_end) = find_ascii_ci(&xml[content_start..], &close) else {
            break;
        };
        let content_end = content_start + rel_end;
        out.push(&xml[content_start..content_end]);
        pos = content_end + close.len();
    }
    out
}

/// Extracts inner trimmed text of the first `<tag>...</tag>` (case-insensitive, non-nested).
pub fn xml_tag_text(xml: &str, tag: &str) -> Option<String> {
    xml_blocks(xml, tag)
        .into_iter()
        .next()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn oversized_http_response_is_refused() {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = l.local_addr().unwrap().port();
        tokio::spawn(async move {
            let (mut c, _) = l.accept().await.unwrap();
            let mut req = [0u8; 1024];
            let _ = c.read(&mut req).await;
            let body = vec![b'x'; MAX_HTTP_BYTES + 10];
            let head = format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n", body.len());
            let _ = c.write_all(head.as_bytes()).await;
            let _ = c.write_all(&body).await;
        });
        let url = parse_http_url(&format!("http://127.0.0.1:{port}/desc.xml")).unwrap();
        let err = http_get(&url, Duration::from_secs(3)).await.unwrap_err();
        assert!(format!("{err:#}").contains("larger than"), "{err:#}");
    }

    #[test]
    fn parses_http_url_and_relative_control_paths() {
        let u = parse_http_url("http://192.168.0.1:49152/IGDdevicedesc.xml").unwrap();
        assert_eq!(u.host, "192.168.0.1");
        assert_eq!(u.port, 49152);
        assert_eq!(u.path, "/IGDdevicedesc.xml");
        assert_eq!(
            u.with_path("/upnp/control/WANCommonInterfaceConfig0").path,
            "/upnp/control/WANCommonInterfaceConfig0"
        );
        assert_eq!(u.with_path("ctl/WAN").path, "/ctl/WAN");
        assert!(parse_http_url("https://192.168.0.1/").is_err());
        assert!(parse_http_url("http://user:pw@192.168.0.1/").is_err());
    }

    #[test]
    fn ssdp_location_filters_to_gateway_ip() {
        let gw = Ipv4Addr::new(192, 168, 0, 1);
        let good = "HTTP/1.1 200 OK\r\nCACHE-CONTROL: max-age=1800\r\nlocation: http://192.168.0.1:49152/igd.xml\r\n\r\n";
        assert_eq!(
            ssdp_location(good, gw).as_deref(),
            Some("http://192.168.0.1:49152/igd.xml")
        );
        let stranger = "HTTP/1.1 200 OK\r\nLOCATION: http://192.168.0.99:8080/igd.xml\r\n\r\n";
        assert_eq!(ssdp_location(stranger, gw), None);
    }

    #[test]
    fn igd_xml_and_soap_parsing() {
        let xml = r#"<?xml version="1.0"?>
<root><device>
  <deviceType>urn:schemas-upnp-org:device:InternetGatewayDevice:1</deviceType>
  <manufacturer>ExampleVendor</manufacturer>
  <modelName>GW-1000</modelName>
  <deviceList><device>
    <deviceType>urn:schemas-upnp-org:device:WANDevice:1</deviceType>
    <modelName>IgnoredSubDevice</modelName>
    <serviceList><service>
      <serviceType>urn:schemas-upnp-org:service:WANCommonInterfaceConfig:1</serviceType>
      <controlURL>/upnp/control/WANCommon0</controlURL>
    </service></serviceList>
    <deviceList><device>
      <serviceList><service>
        <serviceType>urn:schemas-upnp-org:service:WANIPConnection:1</serviceType>
        <controlURL>/upnp/control/WANIPConn0</controlURL>
      </service></serviceList>
    </device></deviceList>
  </device></deviceList>
</device></root>"#;
        let base = parse_http_url("http://192.168.0.1:49152/igd.xml").unwrap();
        let eps = parse_igd_xml(xml, &base);
        assert_eq!(eps.model.as_deref(), Some("ExampleVendor GW-1000"));
        assert_eq!(
            eps.wan_common,
            Some((
                "urn:schemas-upnp-org:service:WANCommonInterfaceConfig:1".into(),
                "/upnp/control/WANCommon0".into()
            ))
        );
        assert_eq!(
            eps.wan_conn,
            Some((
                "urn:schemas-upnp-org:service:WANIPConnection:1".into(),
                "/upnp/control/WANIPConn0".into()
            ))
        );

        let soap = "<s:Body><u:GetStatusInfoResponse><NewConnectionStatus>Connected</NewConnectionStatus><NewLastConnectionError>ERROR_NONE</NewLastConnectionError><NewUptime>4200</NewUptime></u:GetStatusInfoResponse></s:Body>";
        assert_eq!(xml_tag_text(soap, "NewConnectionStatus").as_deref(), Some("Connected"));
        assert_eq!(xml_tag_text(soap, "NewUptime").as_deref(), Some("4200"));
    }

    #[test]
    fn http_chunked_and_counter_deltas() {
        let raw = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n";
        let (code, _, body) = parse_http_raw(raw).unwrap();
        assert_eq!(code, 200);
        assert_eq!(body, "hello world");

        assert_eq!(
            counter_delta(1_000, 16_000, 15.0, 1e9),
            CounterDelta::Rate(1000.0)
        );
        assert_eq!(
            counter_delta(i32::MAX as u64, i32::MAX as u64, 15.0, 1e9),
            CounterDelta::Saturated
        );
        assert_eq!(
            counter_delta(u32::MAX as u64, u32::MAX as u64, 15.0, 1e9),
            CounterDelta::Saturated
        );
        // 32-bit wraparound
        assert_eq!(
            counter_delta(u32::MAX as u64 - 99, 900, 10.0, 1e9),
            CounterDelta::Rate(100.0)
        );
        // Bogus jump above max_rate
        assert_eq!(
            counter_delta(0, 10_000_000_000_000, 1.0, 1e9),
            CounterDelta::Reset
        );
    }
}
