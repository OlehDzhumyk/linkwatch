//! Read-only router diagnostics over modular protocol adapters (`UPnP`, `SNMP`, `TR-064`,
//! `OpenWrt ubus`, `HTTP Banner`) plus gateway LAN port inspection.
//!
//! Credentials passed in [`RouterProbeRequest`] live strictly in memory for the duration of a single
//! probe and are never logged, written to disk, or returned in responses.

use super::types::{AdapterExtra, PortCheck, RouterAudit};
use super::{HttpUrl, http_exchange_raw, probe_upnp_meta, xml_tag_text};
use base64_encode::encode as base64_std;
use chrono::Utc;
use md5::{Digest, Md5};
use serde::Deserialize;
use snmp2::{AsyncSession, Oid, Value};
use std::collections::HashMap;
use std::fmt;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::time::Duration;
use tokio::net::TcpStream;

mod base64_encode {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    pub fn encode(input: &[u8]) -> String {
        let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
        for chunk in input.chunks(3) {
            let b0 = u32::from(chunk[0]);
            let b1 = chunk.get(1).copied().map(u32::from).unwrap_or(0);
            let b2 = chunk.get(2).copied().map(u32::from).unwrap_or(0);
            let n = (b0 << 16) | (b1 << 8) | b2;
            out.push(char::from(TABLE[((n >> 18) & 0x3f) as usize]));
            out.push(char::from(TABLE[((n >> 12) & 0x3f) as usize]));
            out.push(if chunk.len() > 1 { char::from(TABLE[((n >> 6) & 0x3f) as usize]) } else { '=' });
            out.push(if chunk.len() > 2 { char::from(TABLE[(n & 0x3f) as usize]) } else { '=' });
        }
        out
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RouterAdapterKind {
    #[default]
    Auto,
    Upnp,
    Snmp,
    Tr064,
    Openwrt,
    Mikrotik,
    Http,
}

#[derive(Clone, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct RouterProbeRequest {
    #[serde(default)]
    pub adapter: RouterAdapterKind,
    #[serde(default)]
    pub host: Option<String>,
    #[serde(default)]
    pub username: Option<String>,
    #[serde(default)]
    pub password: Option<String>,
    #[serde(default)]
    pub community: Option<String>,
}

impl fmt::Debug for RouterProbeRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RouterProbeRequest")
            .field("adapter", &self.adapter)
            .field("host", &self.host)
            .field("username", &self.username)
            .field("password", &self.password.as_ref().map(|_| "[redacted]"))
            .field("community", &self.community.as_ref().map(|_| "[redacted]"))
            .finish()
    }
}

/// Validates a user-supplied target host: only private, loopback, or link-local IPv4 is accepted
/// to prevent using the probe endpoint for SSRF outside the local network.
pub fn validate_local_host(raw: &str) -> anyhow::Result<Ipv4Addr> {
    let trimmed = raw.trim();
    let ip: Ipv4Addr = trimmed
        .parse()
        .map_err(|_| anyhow::anyhow!("target host must be a local IPv4 address (got {trimmed:?})"))?;
    anyhow::ensure!(
        ip.is_private() || ip.is_loopback() || ip.is_link_local(),
        "refusing non-local address {ip} (must be RFC1918 private, loopback, or link-local)"
    );
    Ok(ip)
}

#[derive(Default)]
struct AdapterOut {
    vendor: Option<String>,
    model: Option<String>,
    firmware: Option<String>,
    admin_url: Option<String>,
    uptime_s: Option<u64>,
    details: Vec<AdapterExtra>,
    warnings: Vec<String>,
}

const PORT_LIST: [(u16, &str); 8] = [
    (21, "FTP"),
    (22, "SSH"),
    (23, "Telnet"),
    (53, "DNS"),
    (80, "HTTP"),
    (443, "HTTPS"),
    (49000, "TR-064"),
    (8080, "HTTP-Alt"),
];

/// Fast concurrent TCP connect scan of common gateway management ports.
pub async fn probe_gateway_ports(gw: Ipv4Addr) -> Vec<PortCheck> {
    let futs = PORT_LIST.iter().map(|&(port, service)| async move {
        let addr = SocketAddr::V4(SocketAddrV4::new(gw, port));
        let open = tokio::time::timeout(Duration::from_millis(650), TcpStream::connect(addr))
            .await
            .is_ok_and(|r| r.is_ok());
        (port, service, open)
    });
    let raw = futures::future::join_all(futs).await;
    let https_open = raw.iter().any(|&(p, _, o)| p == 443 && o);
    raw.into_iter()
        .map(|(port, service, open)| {
            let risk = if !open {
                "none"
            } else if matches!(port, 21 | 23) {
                "high"
            } else if matches!(port, 80 | 8080) && !https_open {
                "warn"
            } else {
                "info"
            };
            PortCheck {
                port,
                service: service.to_string(),
                open,
                risk: risk.to_string(),
            }
        })
        .collect()
}

fn push_opt(details: &mut Vec<AdapterExtra>, label: &str, value: Option<String>) {
    if let Some(v) = value.filter(|s| !s.trim().is_empty()) {
        details.push(AdapterExtra { label: label.to_string(), value: v });
    }
}

async fn run_upnp_adapter(gw: Ipv4Addr, upnp_url: Option<&str>) -> AdapterOut {
    let mut out = AdapterOut::default();
    match probe_upnp_meta(gw, upnp_url).await {
        Ok(m) => {
            out.vendor = m.vendor;
            out.model = m.model;
            out.firmware = m.firmware_hint;
            out.admin_url = m.admin_url;
            out.uptime_s = m.uptime_s;
            push_opt(&mut out.details, "WAN status", m.wan_status);
            push_opt(&mut out.details, "WAN access", m.wan_access);
            if let (Some(d), Some(u)) = (m.link_down_mbps, m.link_up_mbps) {
                out.details.push(AdapterExtra {
                    label: "Link rate".into(),
                    value: format!("{d:.1}↓ / {u:.1}↑ Mbit/s"),
                });
            }
        }
        Err(e) => out.warnings.push(format!("UPnP: {e}")),
    }
    out
}

async fn snmp_get_val(sess: &mut AsyncSession, nums: &[u64]) -> anyhow::Result<Option<String>> {
    let oid = Oid::from(nums).map_err(|_| anyhow::anyhow!("invalid OID"))?;
    let mut resp = tokio::time::timeout(Duration::from_millis(1200), sess.get(&oid))
        .await
        .map_err(|_| anyhow::anyhow!("SNMP timeout"))?
        .map_err(|e| anyhow::anyhow!("SNMP error: {e:?}"))?;
    let Some((_, val)) = resp.varbinds.next() else {
        return Ok(None);
    };
    Ok(match val {
        Value::OctetString(b) => Some(String::from_utf8_lossy(b).trim().to_string()),
        Value::Integer(n) => Some(n.to_string()),
        Value::Counter32(n) | Value::Unsigned32(n) => Some(n.to_string()),
        Value::Counter64(n) => Some(n.to_string()),
        Value::Timeticks(t) => Some((t / 100).to_string()),
        _ => None,
    })
}

async fn run_snmp_adapter(gw: Ipv4Addr, community: Option<&str>) -> AdapterOut {
    let mut out = AdapterOut::default();
    let comm = community.filter(|s| !s.is_empty()).unwrap_or("public");
    let addr = SocketAddr::V4(SocketAddrV4::new(gw, 161));
    let mut sess = match AsyncSession::new_v2c(addr, comm.as_bytes(), 1).await {
        Ok(s) => s,
        Err(e) => {
            out.warnings.push(format!("SNMP connect: {e}"));
            return out;
        }
    };
    match snmp_get_val(&mut sess, &[1, 3, 6, 1, 2, 1, 1, 1, 0]).await {
        Ok(Some(descr)) => {
            out.firmware = Some(descr.chars().take(120).collect());
            push_opt(&mut out.details, "SNMP sysDescr", Some(descr));
        }
        Ok(None) => out.warnings.push("SNMP sysDescr empty".into()),
        Err(e) => {
            out.warnings.push(format!("SNMP unreachable: {e}"));
            return out;
        }
    }
    if let Ok(Some(up)) = snmp_get_val(&mut sess, &[1, 3, 6, 1, 2, 1, 1, 3, 0]).await {
        out.uptime_s = up.parse().ok();
    }
    if let Ok(Some(name)) = snmp_get_val(&mut sess, &[1, 3, 6, 1, 2, 1, 1, 5, 0]).await {
        if out.model.is_none() && !name.is_empty() {
            out.model = Some(name.clone());
        }
        push_opt(&mut out.details, "SNMP sysName", Some(name));
    }
    if let Ok(Some(ifs)) = snmp_get_val(&mut sess, &[1, 3, 6, 1, 2, 1, 2, 1, 0]).await {
        let if_count = ifs.parse::<u64>().unwrap_or(0).min(8);
        push_opt(&mut out.details, "Interfaces (IF-MIB)", Some(ifs));
        for idx in 1..=if_count {
            let descr = snmp_get_val(&mut sess, &[1, 3, 6, 1, 2, 1, 2, 2, 1, 2, idx])
                .await
                .ok()
                .flatten()
                .filter(|s| !s.is_empty())
                .unwrap_or_else(|| format!("if{idx}"));
            let in_err = snmp_get_val(&mut sess, &[1, 3, 6, 1, 2, 1, 2, 2, 1, 14, idx])
                .await
                .ok()
                .flatten()
                .and_then(|v| v.parse::<u64>().ok())
                .unwrap_or(0);
            let out_err = snmp_get_val(&mut sess, &[1, 3, 6, 1, 2, 1, 2, 2, 1, 20, idx])
                .await
                .ok()
                .flatten()
                .and_then(|v| v.parse::<u64>().ok())
                .unwrap_or(0);
            let out_disc = snmp_get_val(&mut sess, &[1, 3, 6, 1, 2, 1, 2, 2, 1, 19, idx])
                .await
                .ok()
                .flatten()
                .and_then(|v| v.parse::<u64>().ok())
                .unwrap_or(0);
            if in_err > 0 || out_err > 0 || out_disc > 0 {
                let summary = format!("in_err={in_err}, out_err={out_err}, out_discards={out_disc}");
                out.details.push(AdapterExtra { label: format!("SNMP {descr} errors"), value: summary.clone() });
                out.warnings.push(format!("SNMP interface {descr} errors/discards: {summary}"));
            }
        }
    }
    if let Ok(Some(snr)) = snmp_get_val(&mut sess, &[1, 3, 6, 1, 2, 1, 10, 127, 1, 1, 4, 1, 5, 3]).await
        && let Ok(tenth_db) = snr.parse::<f64>()
    {
        out.details.push(AdapterExtra {
            label: "DOCSIS DS SNR (ch3)".into(),
            value: format!("{:.1} dB", tenth_db / 10.0),
        });
    }
    if let Ok(Some(uncorr)) = snmp_get_val(&mut sess, &[1, 3, 6, 1, 2, 1, 10, 127, 1, 1, 4, 1, 4, 3]).await {
        push_opt(&mut out.details, "DOCSIS uncorr (ch3)", Some(uncorr));
    }
    out
}

pub fn parse_digest_challenge(header_val: &str) -> Option<HashMap<String, String>> {
    let rest = header_val
        .trim()
        .strip_prefix("Digest ")
        .or_else(|| header_val.trim().strip_prefix("digest "))?;
    let mut map = HashMap::new();
    for part in rest.split(',') {
        let Some((k, v)) = part.trim().split_once('=') else { continue };
        let val = v.trim().trim_matches('"').to_string();
        map.insert(k.trim().to_ascii_lowercase(), val);
    }
    (map.contains_key("realm") && map.contains_key("nonce")).then_some(map)
}

fn md5_hex(s: &str) -> String {
    Md5::digest(s.as_bytes())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

pub fn digest_auth_header(
    method: &str,
    uri: &str,
    user: &str,
    pass: &str,
    ch: &HashMap<String, String>,
    cnonce: &str,
) -> Option<String> {
    let realm = ch.get("realm")?;
    let nonce = ch.get("nonce")?;
    let ha1 = md5_hex(&format!("{user}:{realm}:{pass}"));
    let ha2 = md5_hex(&format!("{method}:{uri}"));
    let has_auth_qop = ch
        .get("qop")
        .is_some_and(|q| q.split(',').any(|p| p.trim().eq_ignore_ascii_case("auth")));
    let response = if has_auth_qop {
        md5_hex(&format!("{ha1}:{nonce}:00000001:{cnonce}:auth:{ha2}"))
    } else {
        md5_hex(&format!("{ha1}:{nonce}:{ha2}"))
    };
    let mut hdr = format!(
        "Digest username=\"{user}\", realm=\"{realm}\", nonce=\"{nonce}\", uri=\"{uri}\", response=\"{response}\""
    );
    if has_auth_qop {
        hdr.push_str(&format!(", qop=auth, nc=00000001, cnonce=\"{cnonce}\""));
    }
    if let Some(opaque) = ch.get("opaque") {
        hdr.push_str(&format!(", opaque=\"{opaque}\""));
    }
    Some(hdr)
}

async fn run_tr064_adapter(gw: Ipv4Addr, user: Option<&str>, pass: Option<&str>) -> AdapterOut {
    let mut out = AdapterOut::default();
    let target = HttpUrl { host: gw.to_string(), port: 49000, path: "/upnp/control/deviceinfo".into() };
    let st = "urn:dslforum-org:service:DeviceInfo:1";
    let body = format!(
        "<?xml version=\"1.0\" encoding=\"utf-8\"?>\
<s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\">\
<s:Body><u:GetInfo xmlns:u=\"{st}\"/></s:Body></s:Envelope>"
    );
    let build_req = |auth: Option<&str>| -> Vec<u8> {
        let mut h = format!(
            "POST {} HTTP/1.1\r\nHost: {}:{}\r\nContent-Type: text/xml; charset=\"utf-8\"\r\nSOAPAction: \"{st}#GetInfo\"\r\nContent-Length: {}\r\nConnection: close\r\n",
            target.path, target.host, target.port, body.len()
        );
        if let Some(a) = auth {
            h.push_str(&format!("Authorization: {a}\r\n"));
        }
        h.push_str("\r\n");
        let mut raw = h.into_bytes();
        raw.extend_from_slice(body.as_bytes());
        raw
    };

    let res = http_exchange_raw(&target, &build_req(None), Duration::from_secs(2)).await;
    let (code, head, xml) = match res {
        Ok(r) => r,
        Err(e) => {
            out.warnings.push(format!("TR-064: {e}"));
            return out;
        }
    };
    let final_xml = if code == 401 {
        let Some(p) = pass.filter(|s| !s.is_empty()) else {
            out.warnings.push("TR-064 requires authentication (supply router username/password)".into());
            return out;
        };
        let u = user.filter(|s| !s.is_empty()).unwrap_or("admin");
        let www = head.lines().find_map(|l| {
            let (k, v) = l.split_once(':')?;
            k.trim().eq_ignore_ascii_case("www-authenticate").then(|| v.trim())
        });
        let Some(ch) = www.and_then(parse_digest_challenge) else {
            out.warnings.push("TR-064 returned 401 without Digest challenge".into());
            return out;
        };
        let Some(hdr) = digest_auth_header("POST", &target.path, u, p, &ch, "linkwatch1") else {
            out.warnings.push("TR-064 Digest challenge missing required fields".into());
            return out;
        };
        match http_exchange_raw(&target, &build_req(Some(&hdr)), Duration::from_secs(2)).await {
            Ok((c, _, b)) if (200..300).contains(&c) => b,
            Ok((c, _, _)) => {
                out.warnings.push(format!("TR-064 auth HTTP {c}"));
                return out;
            }
            Err(e) => {
                out.warnings.push(format!("TR-064 auth failed: {e}"));
                return out;
            }
        }
    } else if (200..300).contains(&code) {
        xml
    } else {
        out.warnings.push(format!("TR-064 HTTP {code}"));
        return out;
    };

    out.vendor = xml_tag_text(&final_xml, "NewManufacturerName");
    out.model = xml_tag_text(&final_xml, "NewModelName");
    out.firmware = xml_tag_text(&final_xml, "NewSoftwareVersion");
    out.uptime_s = xml_tag_text(&final_xml, "NewUpTime").and_then(|s| s.parse().ok());
    push_opt(&mut out.details, "Hardware version", xml_tag_text(&final_xml, "NewHardwareVersion"));
    out
}

pub fn parse_openwrt_board(v: &serde_json::Value) -> (Option<String>, Option<String>, Option<String>) {
    let result = v.pointer("/result/1");
    let Some(obj) = result.and_then(|r| r.as_object()) else {
        return (None, None, None);
    };
    let model = obj.get("model").and_then(|m| m.as_str()).map(str::to_string);
    let fw = obj
        .get("release")
        .and_then(|r| r.get("description").or_else(|| r.get("version")))
        .and_then(|s| s.as_str())
        .map(str::to_string);
    let kernel = obj.get("kernel").and_then(|s| s.as_str()).map(str::to_string);
    (model, fw, kernel)
}

async fn ubus_call(target: &HttpUrl, payload: serde_json::Value) -> anyhow::Result<serde_json::Value> {
    let body = payload.to_string();
    let req = format!(
        "POST {} HTTP/1.1\r\nHost: {}:{}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        target.path, target.host, target.port, body.len()
    );
    let (code, _, resp_body) = http_exchange_raw(target, req.as_bytes(), Duration::from_secs(2)).await?;
    anyhow::ensure!((200..300).contains(&code), "HTTP {code}");
    serde_json::from_str(&resp_body).map_err(|e| anyhow::anyhow!("invalid ubus JSON: {e}"))
}

async fn run_openwrt_adapter(gw: Ipv4Addr, user: Option<&str>, pass: Option<&str>) -> AdapterOut {
    let mut out = AdapterOut::default();
    let target = HttpUrl { host: gw.to_string(), port: 80, path: "/ubus".into() };
    let u = user.filter(|s| !s.is_empty()).unwrap_or("root");
    let p = pass.unwrap_or("");
    let login = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "call",
        "params": ["00000000000000000000000000000000", "session", "login", { "username": u, "password": p }]
    });
    let resp = match ubus_call(&target, login).await {
        Ok(v) => v,
        Err(e) => {
            out.warnings.push(format!("OpenWrt ubus: {e}"));
            return out;
        }
    };
    let Some(sid) = resp.pointer("/result/1/ubus_rpc_session").and_then(|s| s.as_str()) else {
        out.warnings.push("OpenWrt ubus login failed or endpoint disabled".into());
        return out;
    };
    let board_req = serde_json::json!({
        "jsonrpc": "2.0", "id": 2, "method": "call",
        "params": [sid, "system", "board", {}]
    });
    if let Ok(board) = ubus_call(&target, board_req).await {
        let (model, fw, kernel) = parse_openwrt_board(&board);
        out.model = model;
        out.firmware = fw;
        push_opt(&mut out.details, "Kernel", kernel);
    }
    let info_req = serde_json::json!({
        "jsonrpc": "2.0", "id": 3, "method": "call",
        "params": [sid, "system", "info", {}]
    });
    if let Ok(info) = ubus_call(&target, info_req).await {
        out.uptime_s = info.pointer("/result/1/uptime").and_then(|v| v.as_u64());
    }
    out
}

pub fn parse_mikrotik_uptime(raw: &str) -> Option<u64> {
    let s = raw.trim();
    if s.is_empty() {
        return None;
    }
    let mut total = 0u64;
    let mut num = String::new();
    let mut matched = false;
    for ch in s.chars() {
        if ch.is_ascii_digit() {
            num.push(ch);
            continue;
        }
        let mult = match ch {
            'w' => 7 * 86_400,
            'd' => 86_400,
            'h' => 3_600,
            'm' => 60,
            's' => 1,
            _ => return None,
        };
        let n: u64 = num.parse().ok()?;
        num.clear();
        total = total.saturating_add(n.saturating_mul(mult));
        matched = true;
    }
    (matched && num.is_empty()).then_some(total)
}

fn parse_mikrotik_json(res: Option<&serde_json::Value>, rb: Option<&serde_json::Value>) -> AdapterOut {
    let mut out = AdapterOut::default();
    if res.is_none() && rb.is_none() {
        return out;
    }
    out.vendor = Some("MikroTik".into());
    if let Some(r) = res.and_then(|v| v.as_object()) {
        out.model = r.get("board-name").and_then(|v| v.as_str()).map(str::to_string);
        out.firmware = r.get("version").and_then(|v| v.as_str()).map(str::to_string);
        out.uptime_s = r.get("uptime").and_then(|v| v.as_str()).and_then(parse_mikrotik_uptime);
        push_opt(&mut out.details, "Architecture", r.get("architecture-name").and_then(|v| v.as_str()).map(str::to_string));
        if let Some(cpu) = r.get("cpu-load").and_then(|v| v.as_str().map(str::to_string).or_else(|| v.as_u64().map(|n| n.to_string()))) {
            out.details.push(AdapterExtra { label: "CPU load".into(), value: format!("{cpu}%") });
        }
        if let Some(free) = r.get("free-memory").and_then(|v| v.as_str().and_then(|s| s.parse::<u64>().ok()).or_else(|| v.as_u64())) {
            out.details.push(AdapterExtra { label: "Free memory".into(), value: format!("{} MiB", free / (1024 * 1024)) });
        }
    }
    if let Some(b) = rb.and_then(|v| v.as_object()) {
        if let Some(m) = b.get("model").or_else(|| b.get("board-name")).and_then(|v| v.as_str()) {
            out.model = Some(m.to_string());
        }
        push_opt(&mut out.details, "RouterBOARD fw", b.get("current-firmware").and_then(|v| v.as_str()).map(str::to_string));
        push_opt(&mut out.details, "Upgrade fw", b.get("upgrade-firmware").and_then(|v| v.as_str()).map(str::to_string));
    }
    out
}

async fn http_get_basic_json(gw: Ipv4Addr, path: &str, auth_hdr: Option<&str>) -> anyhow::Result<serde_json::Value> {
    let target = HttpUrl { host: gw.to_string(), port: 80, path: path.into() };
    let mut req = format!("GET {path} HTTP/1.1\r\nHost: {gw}\r\nAccept: application/json\r\nConnection: close\r\n");
    if let Some(b64) = auth_hdr {
        req.push_str(&format!("Authorization: Basic {b64}\r\n"));
    }
    req.push_str("\r\n");
    let (code, _, body) = http_exchange_raw(&target, req.as_bytes(), Duration::from_secs(2)).await?;
    anyhow::ensure!((200..300).contains(&code), "HTTP {code}");
    serde_json::from_str(&body).map_err(|e| anyhow::anyhow!("invalid JSON: {e}"))
}

async fn run_mikrotik_adapter(gw: Ipv4Addr, user: Option<&str>, pass: Option<&str>) -> AdapterOut {
    let u = user.filter(|s| !s.is_empty()).unwrap_or("admin");
    let auth = pass.filter(|s| !s.is_empty()).map(|p| base64_std(format!("{u}:{p}").as_bytes()));
    let res = match http_get_basic_json(gw, "/rest/system/resource", auth.as_deref()).await {
        Ok(v) => v,
        Err(e) => {
            let mut out = AdapterOut::default();
            out.warnings.push(format!("MikroTik REST: {e}"));
            return out;
        }
    };
    let rb = http_get_basic_json(gw, "/rest/system/routerboard", auth.as_deref()).await.ok();
    let mut out = parse_mikrotik_json(Some(&res), rb.as_ref());
    out.admin_url = Some(format!("http://{gw}/"));
    out
}

pub fn parse_html_title(html: &str) -> Option<String> {
    let lower = html.to_ascii_lowercase();
    let start = lower.find("<title>")? + 7;
    let rel_end = lower[start..].find("</title>")?;
    let title = html[start..start + rel_end].split_whitespace().collect::<Vec<_>>().join(" ");
    (!title.is_empty()).then_some(title)
}

async fn run_http_adapter(gw: Ipv4Addr, user: Option<&str>, pass: Option<&str>) -> AdapterOut {
    let mut out = AdapterOut::default();
    let target = HttpUrl { host: gw.to_string(), port: 80, path: "/".into() };
    let auth_hdr = match (user.filter(|s| !s.is_empty()), pass) {
        (Some(u), Some(p)) if !p.is_empty() => Some(base64_std(format!("{u}:{p}").as_bytes())),
        (None, Some(p)) if !p.is_empty() => Some(base64_std(format!("admin:{p}").as_bytes())),
        _ => None,
    };
    let mut req = format!("GET / HTTP/1.1\r\nHost: {gw}\r\nConnection: close\r\nUser-Agent: linkwatch\r\n");
    if let Some(b64) = auth_hdr {
        req.push_str(&format!("Authorization: Basic {b64}\r\n"));
    }
    req.push_str("\r\n");
    match http_exchange_raw(&target, req.as_bytes(), Duration::from_secs(2)).await {
        Ok((code, head, body)) => {
            out.admin_url = Some(format!("http://{gw}/"));
            let server = head.lines().find_map(|l| {
                let (k, v) = l.split_once(':')?;
                k.trim().eq_ignore_ascii_case("server").then(|| v.trim().to_string())
            });
            push_opt(&mut out.details, "HTTP Server", server.clone());
            out.firmware = server.filter(|s| s.chars().any(|c| c.is_ascii_digit()));
            if let Some(title) = parse_html_title(&body) {
                if !title.eq_ignore_ascii_case("login") && !title.eq_ignore_ascii_case("router") {
                    out.model = Some(title.clone());
                }
                push_opt(&mut out.details, "Admin page title", Some(title));
            }
            push_opt(&mut out.details, "HTTP status", Some(code.to_string()));
        }
        Err(e) => out.warnings.push(format!("HTTP {gw}:80: {e}")),
    }
    out
}

fn merge_out(audit: &mut RouterAudit, src: AdapterOut, keep_warnings: bool) {
    if audit.vendor.is_none() { audit.vendor = src.vendor; }
    if audit.model.is_none() { audit.model = src.model; }
    if audit.firmware.is_none() { audit.firmware = src.firmware; }
    if audit.admin_url.is_none() { audit.admin_url = src.admin_url; }
    if audit.uptime_s.is_none() { audit.uptime_s = src.uptime_s; }
    for d in src.details {
        if !audit.details.iter().any(|x| x.label == d.label && x.value == d.value) {
            audit.details.push(d);
        }
    }
    if keep_warnings {
        audit.warnings.extend(src.warnings);
    }
}

pub async fn run_probe(
    gw: Ipv4Addr,
    gw_mac: Option<String>,
    req: &RouterProbeRequest,
    upnp_url: Option<&str>,
) -> RouterAudit {
    let ports = probe_gateway_ports(gw).await;
    let mut audit = RouterAudit {
        probed_at: Utc::now(),
        gateway_ip: Some(gw.to_string()),
        gateway_mac: gw_mac,
        adapter_used: format!("{:?}", req.adapter).to_ascii_lowercase(),
        ports,
        ..Default::default()
    };

    let u = req.username.as_deref();
    let p = req.password.as_deref();
    let c = req.community.as_deref();

    match req.adapter {
        RouterAdapterKind::Auto => {
            let mut used = Vec::new();
            let upnp = run_upnp_adapter(gw, upnp_url).await;
            if upnp.model.is_some() || upnp.vendor.is_some() || !upnp.details.is_empty() {
                used.push("upnp");
            }
            merge_out(&mut audit, upnp, false);

            let http = run_http_adapter(gw, u, p).await;
            if http.admin_url.is_some() {
                used.push("http");
            }
            merge_out(&mut audit, http, false);

            if c.is_some_and(|s| !s.is_empty()) {
                let snmp = run_snmp_adapter(gw, c).await;
                if !snmp.details.is_empty() { used.push("snmp"); }
                merge_out(&mut audit, snmp, true);
            }
            if p.is_some_and(|s| !s.is_empty()) {
                let ow = run_openwrt_adapter(gw, u, p).await;
                if ow.model.is_some() || ow.firmware.is_some() { used.push("openwrt"); }
                merge_out(&mut audit, ow, false);

                let tr = run_tr064_adapter(gw, u, p).await;
                if tr.model.is_some() || tr.firmware.is_some() { used.push("tr064"); }
                merge_out(&mut audit, tr, false);

                if audit.firmware.is_none() {
                    let mk = run_mikrotik_adapter(gw, u, p).await;
                    if mk.model.is_some() || mk.firmware.is_some() { used.push("mikrotik"); }
                    merge_out(&mut audit, mk, false);
                }
            }
            audit.adapter_used = if used.is_empty() { "passive".into() } else { used.join("+") };
        }
        RouterAdapterKind::Upnp => merge_out(&mut audit, run_upnp_adapter(gw, upnp_url).await, true),
        RouterAdapterKind::Snmp => merge_out(&mut audit, run_snmp_adapter(gw, c).await, true),
        RouterAdapterKind::Tr064 => merge_out(&mut audit, run_tr064_adapter(gw, u, p).await, true),
        RouterAdapterKind::Openwrt => merge_out(&mut audit, run_openwrt_adapter(gw, u, p).await, true),
        RouterAdapterKind::Mikrotik => merge_out(&mut audit, run_mikrotik_adapter(gw, u, p).await, true),
        RouterAdapterKind::Http => merge_out(&mut audit, run_http_adapter(gw, u, p).await, true),
    }

    for pck in &audit.ports {
        if pck.risk == "high" {
            audit.warnings.push(format!(
                "Insecure port {} ({}) is open on {}",
                pck.port, pck.service, gw
            ));
        } else if pck.risk == "warn" {
            audit.warnings.push(format!(
                "Plain HTTP management on port {} without HTTPS on {}",
                pck.port, gw
            ));
        }
    }
    audit
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_validation_allows_local_and_blocks_public() {
        assert_eq!(validate_local_host("192.168.0.1").unwrap(), Ipv4Addr::new(192, 168, 0, 1));
        assert_eq!(validate_local_host("10.0.0.1").unwrap(), Ipv4Addr::new(10, 0, 0, 1));
        assert_eq!(validate_local_host("127.0.0.1").unwrap(), Ipv4Addr::LOCALHOST);
        assert!(validate_local_host("8.8.8.8").is_err());
        assert!(validate_local_host("1.1.1.1").is_err());
        assert!(validate_local_host("example.com").is_err());
    }

    #[test]
    fn debug_redacts_secrets() {
        let req = RouterProbeRequest {
            adapter: RouterAdapterKind::Auto,
            host: Some("192.168.0.1".into()),
            username: Some("admin".into()),
            password: Some("supersecret".into()),
            community: Some("privatecomm".into()),
        };
        let s = format!("{req:?}");
        assert!(!s.contains("supersecret") && !s.contains("privatecomm"));
        assert!(s.contains("[redacted]"));
    }

    #[test]
    fn digest_auth_matches_rfc2617_example() {
        let hdr = "Digest realm=\"testrealm@host.com\", qop=\"auth,auth-int\", nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\", opaque=\"5ccc069c403ebaf9f0171e9517f40e41\"";
        let ch = parse_digest_challenge(hdr).unwrap();
        let auth = digest_auth_header(
            "GET",
            "/dir/index.html",
            "Mufasa",
            "Circle Of Life",
            &ch,
            "0a4f113b",
        )
        .unwrap();
        assert!(auth.contains("response=\"6629fae49393a05397450978507c4ef1\""), "{auth}");
        assert!(auth.contains("opaque=\"5ccc069c403ebaf9f0171e9517f40e41\""), "{auth}");
    }

    #[test]
    fn parses_openwrt_and_html_title() {
        let board = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 2,
            "result": [0, { "model": "Example Router A1", "kernel": "6.6.10", "release": { "description": "OpenWrt 24.10.0 r28000" } }]
        });
        assert_eq!(
            parse_openwrt_board(&board),
            (Some("Example Router A1".into()), Some("OpenWrt 24.10.0 r28000".into()), Some("6.6.10".into()))
        );
        assert_eq!(parse_html_title("<html><head><TITLE> Router Admin \n Panel </title></head></html>").as_deref(), Some("Router Admin Panel"));
    }

    #[test]
    fn parses_mikrotik_uptime_and_json_and_adapter_kind() {
        assert_eq!(parse_mikrotik_uptime("3w2d4h15m10s"), Some(3 * 604_800 + 2 * 86_400 + 4 * 3_600 + 15 * 60 + 10));
        assert_eq!(parse_mikrotik_uptime("45s"), Some(45));
        assert_eq!(parse_mikrotik_uptime(""), None);
        assert_eq!(parse_mikrotik_uptime("bad"), None);

        let kind: RouterAdapterKind = serde_json::from_str("\"mikrotik\"").unwrap();
        assert_eq!(kind, RouterAdapterKind::Mikrotik);

        let res = serde_json::json!({
            "board-name": "hAP ax2",
            "version": "7.15.3 (stable)",
            "uptime": "1d2h3m",
            "architecture-name": "arm64",
            "cpu-load": "4",
            "free-memory": "536870912"
        });
        let rb = serde_json::json!({
            "model": "C52iG-5HaxD2HaxD",
            "current-firmware": "7.15.3",
            "upgrade-firmware": "7.16"
        });
        let out = parse_mikrotik_json(Some(&res), Some(&rb));
        assert_eq!(out.vendor.as_deref(), Some("MikroTik"));
        assert_eq!(out.model.as_deref(), Some("C52iG-5HaxD2HaxD"));
        assert_eq!(out.firmware.as_deref(), Some("7.15.3 (stable)"));
        assert_eq!(out.uptime_s, Some(86_400 + 7_200 + 180));
        assert!(out.details.iter().any(|d| d.label == "Free memory" && d.value == "512 MiB"));
    }
}
