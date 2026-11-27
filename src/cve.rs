//! Explicit on-demand CVE & CISA KEV vulnerability lookup over TLS (pure Rust `rustls-rustcrypto`),
//! with 24-hour disk caching. Nothing runs passively; external requests occur only on explicit user action.

use chrono::{DateTime, TimeDelta, Utc};
use flate2::read::GzDecoder;
use rustls::pki_types::ServerName;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::io::Read;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

const CACHE_TTL_HOURS: i64 = 24;
const HTTP_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_API_BYTES: usize = 2 * 1024 * 1024;
const MAX_KEV_BYTES: usize = 6 * 1024 * 1024;
const MAX_CVE_CACHE_ENTRIES: usize = 64;

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CveLookupRequest {
    #[serde(default)]
    pub vendor: Option<String>,
    pub model: String,
    #[serde(default)]
    pub firmware: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[cfg_attr(test, derive(ts_rs::TS), ts(export))]
pub struct CveItem {
    pub id: String,
    pub severity: String,
    pub cvss: Option<f64>,
    pub kev: bool,
    pub summary: String,
    pub published: Option<String>,
    pub url: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(test, derive(ts_rs::TS), ts(export))]
pub struct CveLookupResponse {
    pub queried_at: DateTime<Utc>,
    pub cached: bool,
    pub source: String,
    pub query: String,
    pub total: usize,
    pub kev_count: usize,
    pub items: Vec<CveItem>,
    pub note: Option<String>,
}

pub fn sanitize_token(raw: &str) -> String {
    // Any whitespace (tabs, newlines) separates words; other unexpected characters are dropped.
    // `+` is kept: it is part of real model names (e.g. "RB5009UG+S+IN") and is percent-encoded later.
    raw.trim()
        .chars()
        .filter_map(|c| {
            if c.is_whitespace() {
                Some(' ')
            } else if c.is_ascii_alphanumeric() || matches!(c, '-' | '.' | '_' | '/' | '+') {
                Some(c)
            } else {
                None
            }
        })
        .collect::<String>()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

fn infer_vendor(model_lower: &str) -> Option<&'static str> {
    if model_lower.contains("archer") || model_lower.contains("tl-wr") || model_lower.contains("deco") {
        return Some("tp-link");
    }
    if model_lower.contains("rt-ax") || model_lower.contains("rt-ac") || model_lower.contains("gt-ax") {
        return Some("asus");
    }
    if model_lower.contains("fritzbox") || model_lower.contains("fritz box") || model_lower.contains("fritz") {
        return Some("avm");
    }
    if model_lower.contains("unifi") || model_lower.contains("udm") || model_lower.contains("edgerouter") {
        return Some("ubiquiti");
    }
    if model_lower.contains("nighthawk") || model_lower.contains("r7000") || model_lower.contains("rax") {
        return Some("netgear");
    }
    if model_lower.contains("dir-") || model_lower.contains("dap-") {
        return Some("d-link");
    }
    if model_lower.contains("openwrt") {
        return Some("openwrt");
    }
    let has_mt_prefix = model_lower.split_whitespace().any(|w| {
        ["rb", "hap", "crs", "ccr", "hex"].iter().any(|p| {
            w == *p || (w.starts_with(p) && (w[p.len()..].starts_with(|c: char| c.is_ascii_digit() || c == '-')))
        })
    });
    if has_mt_prefix || model_lower.contains("routerboard") {
        return Some("mikrotik");
    }
    None
}

/// Normalizes device vendor + model for cleaner CVE/NVD lookups, stripping generic words and
/// duplicated vendor prefixes, and inferring well-known router vendors when omitted.
pub fn normalize_device_query(vendor: Option<&str>, model: &str) -> (Option<String>, String) {
    let raw_model = sanitize_token(model);
    let mut v = vendor
        .map(sanitize_token)
        .filter(|s| !s.is_empty());

    let mut clean = raw_model.clone();
    for phrase in ["internet gateway device", "wireless router", "wi-fi router", "wifi router"] {
        if let Some(pos) = clean.to_ascii_lowercase().find(phrase) {
            let before = clean[..pos].trim();
            let after = clean[pos + phrase.len()..].trim();
            clean = [before, after].into_iter().filter(|s| !s.is_empty()).collect::<Vec<_>>().join(" ");
        }
    }
    let words: Vec<&str> = clean
        .split_whitespace()
        .filter(|w| !matches!(w.to_ascii_lowercase().as_str(), "router" | "gateway"))
        .collect();
    if !words.is_empty() {
        clean = words.join(" ");
    }

    if v.is_none() {
        v = infer_vendor(&clean.to_ascii_lowercase()).map(str::to_string);
    }

    if let Some(ref ven) = v {
        let vl = ven.to_ascii_lowercase();
        let cl = clean.to_ascii_lowercase();
        if let Some(rest) = cl.strip_prefix(&vl) {
            let trimmed_rest = clean[vl.len()..].trim();
            if !trimmed_rest.is_empty() && (rest.starts_with(' ') || rest.starts_with('-')) {
                clean = trimmed_rest.trim_start_matches('-').trim().to_string();
            }
        }
    }

    let final_model = if clean.trim().is_empty() { raw_model } else { clean };
    (v, final_model)
}

fn parse_ver_parts(raw: &str) -> Option<Vec<u64>> {
    let s = raw.trim().trim_start_matches(['v', 'V']);
    let token = s.split(char::is_whitespace).next()?;
    let mut out = Vec::new();
    for part in token.split('.') {
        let digits: String = part.chars().take_while(|c| c.is_ascii_digit()).collect();
        if digits.is_empty() {
            if out.is_empty() {
                return None;
            }
            break;
        }
        out.push(digits.parse().ok()?);
    }
    (!out.is_empty()).then_some(out)
}

/// Compares dot-separated numeric version segments (`true` iff `a < b`).
pub fn version_lt(a: &str, b: &str) -> Option<bool> {
    let pa = parse_ver_parts(a)?;
    let pb = parse_ver_parts(b)?;
    let n = pa.len().max(pb.len());
    for i in 0..n {
        let va = pa.get(i).copied().unwrap_or(0);
        let vb = pb.get(i).copied().unwrap_or(0);
        if va != vb {
            return Some(va < vb);
        }
    }
    Some(false)
}

#[derive(Debug, Clone, Deserialize)]
struct BundleEntry {
    id: String,
    #[serde(default)]
    vendor: Option<String>,
    #[serde(default)]
    model: Option<String>,
    #[serde(default)]
    keywords: Vec<String>,
    #[serde(default)]
    affected_below: Option<String>,
    #[serde(default)]
    severity: Option<String>,
    #[serde(default)]
    cvss: Option<f64>,
    #[serde(default)]
    kev: bool,
    summary: String,
    #[serde(default)]
    published: Option<String>,
    #[serde(default)]
    url: Option<String>,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum BundleFile {
    List(Vec<BundleEntry>),
    Wrapped { items: Vec<BundleEntry> },
}

fn load_offline_bundle(
    data_dir: &Path,
    vendor: Option<&str>,
    model: &str,
    firmware: Option<&str>,
    kev_set: &HashSet<String>,
) -> Option<Vec<CveItem>> {
    let gz_path = data_dir.join("cve-bundle.json.gz");
    let raw_bytes = if gz_path.is_file() {
        let f = std::fs::File::open(&gz_path).ok()?;
        let mut dec = GzDecoder::new(f).take((MAX_KEV_BYTES + 1) as u64);
        let mut buf = Vec::new();
        dec.read_to_end(&mut buf).ok()?;
        if buf.len() > MAX_KEV_BYTES {
            return None;
        }
        buf
    } else {
        let json_path = data_dir.join("cve-bundle.json");
        let meta = std::fs::metadata(&json_path).ok()?;
        if meta.len() > MAX_KEV_BYTES as u64 {
            return None;
        }
        std::fs::read(&json_path).ok()?
    };

    let entries = match serde_json::from_slice::<BundleFile>(&raw_bytes).ok()? {
        BundleFile::List(v) => v,
        BundleFile::Wrapped { items } => items,
    };

    let m_low = model.to_ascii_lowercase();
    let v_low = vendor.map(str::to_ascii_lowercase);
    let mut out = Vec::new();
    for e in entries {
        if let (Some(req_v), Some(ent_v)) = (&v_low, &e.vendor)
            && !ent_v.trim().is_empty()
            && !ent_v.to_ascii_lowercase().contains(req_v)
            && !req_v.contains(&ent_v.to_ascii_lowercase())
        {
            continue;
        }
        let model_hit = e.model.as_deref().is_some_and(|em| {
            let eml = em.to_ascii_lowercase();
            !eml.is_empty() && (eml.contains(&m_low) || m_low.contains(&eml))
        });
        let kw_hit = e.keywords.iter().any(|k| {
            let kl = k.to_ascii_lowercase();
            !kl.is_empty() && (kl.contains(&m_low) || m_low.contains(&kl))
        });
        if !model_hit && !kw_hit {
            continue;
        }
        if let (Some(fw), Some(fixed)) = (firmware, e.affected_below.as_deref())
            && version_lt(fw, fixed) == Some(false)
        {
            continue;
        }
        let is_kev = e.kev || kev_set.contains(&e.id);
        let severity = cvss_severity(e.cvss, e.severity.as_deref());
        let url = e.url.unwrap_or_else(|| format!("https://nvd.nist.gov/vuln/detail/{}", e.id));
        out.push(CveItem { id: e.id, severity, cvss: e.cvss, kev: is_kev, summary: e.summary, published: e.published, url });
    }
    Some(out)
}

fn percent_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.as_bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~') {
            out.push(char::from(*b));
        } else if *b == b' ' {
            out.push_str("%20");
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

fn parse_https_url(url: &str) -> anyhow::Result<(&str, &str)> {
    let rest = url
        .trim()
        .strip_prefix("https://")
        .ok_or_else(|| anyhow::anyhow!("URL must start with https://"))?;
    let (host, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    anyhow::ensure!(!host.is_empty() && !host.contains(':') && !host.contains('@'), "invalid HTTPS host");
    Ok((host, path))
}

pub(crate) fn tls_connector() -> anyhow::Result<TlsConnector> {
    let provider = Arc::new(rustls_rustcrypto::provider());
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let cfg = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| anyhow::anyhow!("TLS config error: {e}"))?
        .with_root_certificates(roots)
        .with_no_client_auth();
    Ok(TlsConnector::from(Arc::new(cfg)))
}

pub fn decode_http_body(raw: &[u8], max_bytes: usize) -> anyhow::Result<(u16, Vec<u8>)> {
    let sep = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .filter(|&p| p <= 16 * 1024)
        .ok_or_else(|| anyhow::anyhow!("malformed HTTPS response header"))?;
    let head = String::from_utf8_lossy(&raw[..sep]);
    let code: u16 = head
        .lines()
        .next()
        .unwrap_or_default()
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    let mut chunked = false;
    let mut gzipped = false;
    for line in head.lines() {
        let Some((k, v)) = line.split_once(':') else { continue };
        if k.trim().eq_ignore_ascii_case("transfer-encoding") && v.to_ascii_lowercase().contains("chunked") {
            chunked = true;
        }
        if k.trim().eq_ignore_ascii_case("content-encoding") && v.to_ascii_lowercase().contains("gzip") {
            gzipped = true;
        }
    }
    let body = &raw[sep + 4..];
    let dechunked = if chunked {
        crate::router::decode_chunked(body).ok_or_else(|| anyhow::anyhow!("invalid chunked HTTPS body"))?
    } else {
        body.to_vec()
    };
    if gzipped {
        let mut dec = GzDecoder::new(&dechunked[..]).take((max_bytes + 1) as u64);
        let mut out = Vec::new();
        dec.read_to_end(&mut out)?;
        anyhow::ensure!(out.len() <= max_bytes, "compressed HTTPS body exceeded {max_bytes} bytes");
        Ok((code, out))
    } else {
        anyhow::ensure!(dechunked.len() <= max_bytes, "HTTPS body exceeded {max_bytes} bytes");
        Ok((code, dechunked))
    }
}

async fn https_get(
    url: &str,
    extra_headers: &[(&str, &str)],
    timeout: Duration,
    max_bytes: usize,
) -> anyhow::Result<(u16, Vec<u8>)> {
    let (host, path) = parse_https_url(url)?;
    let connector = tls_connector()?;
    let sni = ServerName::try_from(host.to_string())
        .map_err(|_| anyhow::anyhow!("invalid TLS server name: {host}"))?;
    tokio::time::timeout(timeout, async {
        let tcp = TcpStream::connect((host, 443)).await?;
        let mut tls = connector.connect(sni, tcp).await?;
        let mut req = format!(
            "GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: linkwatch\r\nAccept: application/json\r\nAccept-Encoding: gzip\r\nConnection: close\r\n"
        );
        for &(k, v) in extra_headers {
            req.push_str(&format!("{k}: {v}\r\n"));
        }
        req.push_str("\r\n");
        tls.write_all(req.as_bytes()).await?;
        let mut raw = Vec::with_capacity(8192);
        let mut buf = [0u8; 8192];
        loop {
            let n = tls.read(&mut buf).await?;
            if n == 0 {
                break;
            }
            if raw.len() + n > max_bytes + 32 * 1024 {
                anyhow::bail!("HTTPS response exceeded {max_bytes} bytes");
            }
            raw.extend_from_slice(&buf[..n]);
        }
        decode_http_body(&raw, max_bytes)
    })
    .await
    .map_err(|_| anyhow::anyhow!("HTTPS timeout querying {host}"))?
}

fn cvss_severity(score: Option<f64>, fallback: Option<&str>) -> String {
    if let Some(s) = score {
        if s >= 9.0 { return "critical".into(); }
        if s >= 7.0 { return "high".into(); }
        if s >= 4.0 { return "medium".into(); }
        return "low".into();
    }
    fallback
        .map(|s| s.to_ascii_lowercase())
        .filter(|s| matches!(s.as_str(), "critical" | "high" | "medium" | "low"))
        .unwrap_or_else(|| "unknown".into())
}

pub fn parse_nvd_response(json: &serde_json::Value, kev: &HashSet<String>) -> Vec<CveItem> {
    let Some(vulns) = json.get("vulnerabilities").and_then(|v| v.as_array()) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for entry in vulns {
        let Some(c) = entry.get("cve") else { continue };
        let Some(id) = c.get("id").and_then(|s| s.as_str()).map(str::to_string) else { continue };
        let summary = c
            .get("descriptions")
            .and_then(|d| d.as_array())
            .and_then(|arr| arr.iter().find(|x| x.get("lang").and_then(|l| l.as_str()) == Some("en")).or_else(|| arr.first()))
            .and_then(|d| d.get("value"))
            .and_then(|s| s.as_str())
            .unwrap_or("")
            .chars()
            .take(360)
            .collect();
        let metric = c.pointer("/metrics/cvssMetricV31/0/cvssData")
            .or_else(|| c.pointer("/metrics/cvssMetricV30/0/cvssData"))
            .or_else(|| c.pointer("/metrics/cvssMetricV2/0/cvssData"));
        let cvss = metric.and_then(|m| m.get("baseScore")).and_then(|v| v.as_f64());
        let base_sev = metric.and_then(|m| m.get("baseSeverity")).and_then(|v| v.as_str());
        let published = c.get("published").and_then(|s| s.as_str()).map(|s| s.chars().take(10).collect());
        let is_kev = kev.contains(&id);
        out.push(CveItem {
            url: format!("https://nvd.nist.gov/vuln/detail/{id}"),
            id,
            severity: cvss_severity(cvss, base_sev),
            cvss,
            kev: is_kev,
            summary,
            published,
        });
    }
    out
}

pub fn parse_circl_response(json: &serde_json::Value, kev: &HashSet<String>) -> Vec<CveItem> {
    let arr = json
        .as_array()
        .or_else(|| json.get("results").and_then(|v| v.as_array()))
        .or_else(|| json.get("cves").and_then(|v| v.as_array()));
    let Some(list) = arr else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for entry in list {
        // CIRCL /vulnerability-lookup returns CVE5 records or summary objects.
        let id = entry
            .pointer("/cveMetadata/cveId")
            .or_else(|| entry.get("id"))
            .or_else(|| entry.get("cve"))
            .and_then(|s| s.as_str())
            .map(str::to_string);
        let Some(id) = id.filter(|s| s.starts_with("CVE-")) else { continue };
        let summary = entry
            .pointer("/containers/cna/descriptions/0/value")
            .or_else(|| entry.get("summary"))
            .or_else(|| entry.get("description"))
            .and_then(|s| s.as_str())
            .unwrap_or("")
            .chars()
            .take(360)
            .collect();
        let cvss = entry
            .pointer("/containers/cna/metrics/0/cvssV3_1/baseScore")
            .or_else(|| entry.pointer("/containers/cna/metrics/0/cvssV3_0/baseScore"))
            .or_else(|| entry.get("cvss"))
            .and_then(|v| v.as_f64());
        let published = entry
            .pointer("/cveMetadata/datePublished")
            .or_else(|| entry.get("Published"))
            .and_then(|s| s.as_str())
            .map(|s| s.chars().take(10).collect());
        let is_kev = kev.contains(&id);
        out.push(CveItem {
            url: format!("https://nvd.nist.gov/vuln/detail/{id}"),
            id,
            severity: cvss_severity(cvss, None),
            cvss,
            kev: is_kev,
            summary,
            published,
        });
    }
    out
}

#[derive(Serialize, Deserialize, Default)]
struct KevCache {
    fetched_at: DateTime<Utc>,
    ids: Vec<String>,
}

async fn load_kev_set(data_dir: &Path) -> (HashSet<String>, Option<String>) {
    let path = data_dir.join("kev-cache.json");
    let now = Utc::now();
    if let Ok(raw) = std::fs::read(&path)
        && let Ok(c) = serde_json::from_slice::<KevCache>(&raw)
        && now - c.fetched_at < TimeDelta::hours(CACHE_TTL_HOURS)
    {
        return (c.ids.into_iter().collect(), None);
    }
    let url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";
    match https_get(url, &[], HTTP_TIMEOUT, MAX_KEV_BYTES).await {
        Ok((200, body)) => {
            if let Ok(v) = serde_json::from_slice::<serde_json::Value>(&body)
                && let Some(arr) = v.get("vulnerabilities").and_then(|x| x.as_array())
            {
                let ids: Vec<String> = arr
                    .iter()
                    .filter_map(|e| e.get("cveID").and_then(|s| s.as_str()).map(str::to_string))
                    .collect();
                let cache = KevCache { fetched_at: now, ids: ids.clone() };
                if let Ok(bytes) = serde_json::to_vec(&cache) {
                    let _ = std::fs::write(&path, bytes);
                }
                return (ids.into_iter().collect(), None);
            }
            (HashSet::new(), Some("CISA KEV JSON schema unrecognized".into()))
        }
        Ok((code, _)) => (HashSet::new(), Some(format!("CISA KEV HTTP {code}"))),
        Err(e) => (HashSet::new(), Some(format!("CISA KEV offline: {e}"))),
    }
}

pub async fn lookup_cves(
    data_dir: &Path,
    req: &CveLookupRequest,
    nvd_api_key: Option<&str>,
) -> anyhow::Result<CveLookupResponse> {
    let raw_model = sanitize_token(&req.model);
    anyhow::ensure!(!raw_model.is_empty() && raw_model.len() <= 120, "router model must be 1..=120 ASCII characters");
    let (vendor, model) = normalize_device_query(req.vendor.as_deref(), &raw_model);
    let fw = req.firmware.as_deref().map(sanitize_token).filter(|s| !s.is_empty());

    let query_terms = [vendor.as_deref(), Some(model.as_str()), fw.as_deref()]
        .into_iter()
        .flatten()
        .collect::<Vec<_>>()
        .join(" ");
    let cache_key = query_terms.to_ascii_lowercase();
    let cache_path = data_dir.join("cve-cache.json");
    let now = Utc::now();

    let mut cache: HashMap<String, CveLookupResponse> = std::fs::read(&cache_path)
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or_default();
    if let Some(hit) = cache.get(&cache_key)
        && now - hit.queried_at < TimeDelta::hours(CACHE_TTL_HOURS)
    {
        let mut c = hit.clone();
        c.cached = true;
        return Ok(c);
    }

    let (kev, kev_note) = load_kev_set(data_dir).await;
    let mut items = Vec::new();
    let mut source = String::new();
    let mut notes: Vec<String> = kev_note.into_iter().collect();

    if let Some(ref v) = vendor {
        let circl_url = format!(
            "https://vulnerability.circl.lu/api/vulnerability/search/{}/{}",
            percent_encode(&v.to_ascii_lowercase()),
            percent_encode(&model.to_ascii_lowercase())
        );
        if let Ok((200, body)) = https_get(&circl_url, &[], HTTP_TIMEOUT, MAX_API_BYTES).await
            && let Ok(json) = serde_json::from_slice::<serde_json::Value>(&body)
        {
            items = parse_circl_response(&json, &kev);
            if !items.is_empty() {
                source = "CIRCL Vulnerability-Lookup + CISA KEV".into();
            }
        }
    }

    if items.is_empty() {
        let kw = [vendor.as_deref(), Some(model.as_str())]
            .into_iter()
            .flatten()
            .collect::<Vec<_>>()
            .join(" ");
        let nvd_url = format!(
            "https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={}&resultsPerPage=25",
            percent_encode(&kw)
        );
        let hdrs: Vec<(&str, &str)> = nvd_api_key
            .filter(|k| !k.is_empty())
            .map(|k| vec![("apiKey", k)])
            .unwrap_or_default();
        match https_get(&nvd_url, &hdrs, HTTP_TIMEOUT, MAX_API_BYTES).await {
            Ok((200, body)) => {
                if let Ok(json) = serde_json::from_slice::<serde_json::Value>(&body) {
                    items = parse_nvd_response(&json, &kev);
                    source = "NIST NVD 2.0 + CISA KEV".into();
                }
            }
            Ok((code, _)) => notes.push(format!("NIST NVD HTTP {code} (retry later or configure nvd_api_key)")),
            Err(e) => notes.push(format!("NIST NVD unreachable: {e}")),
        }
    }

    if items.is_empty()
        && let Some(bundle_items) = load_offline_bundle(data_dir, vendor.as_deref(), &model, fw.as_deref(), &kev)
        && !bundle_items.is_empty()
    {
        items = bundle_items;
        source = "offline bundle (cve-bundle)".into();
    }

    items.sort_by(|a, b| {
        b.kev
            .cmp(&a.kev)
            .then_with(|| b.cvss.unwrap_or(-1.0).total_cmp(&a.cvss.unwrap_or(-1.0)))
            .then_with(|| b.published.cmp(&a.published))
    });
    let total = items.len();
    items.truncate(25);
    let kev_count = items.iter().filter(|i| i.kev).count();
    let resp = CveLookupResponse {
        queried_at: now,
        cached: false,
        source: if source.is_empty() { "offline / unavailable".into() } else { source },
        query: query_terms,
        total,
        kev_count,
        items,
        note: (!notes.is_empty()).then(|| notes.join("; ")),
    };

    if cache.len() >= MAX_CVE_CACHE_ENTRIES
        && let Some(oldest) = cache.iter().min_by_key(|(_, v)| v.queried_at).map(|(k, _)| k.clone())
    {
        cache.remove(&oldest);
    }
    if !resp.items.is_empty() || resp.note.is_none() {
        cache.insert(cache_key, resp.clone());
        if let Ok(bytes) = serde_json::to_vec(&cache) {
            let _ = std::fs::write(&cache_path, bytes);
        }
    }
    Ok(resp)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitizes_queries() {
        assert_eq!(sanitize_token("  ACME\tGW-1200\n;drop  "), "ACME GW-1200 drop");
        assert_eq!(percent_encode("a b/c"), "a%20b%2Fc");
    }

    #[test]
    fn parses_nvd_and_circl_with_kev_priority() {
        let mut kev = HashSet::new();
        kev.insert("CVE-2024-1111".to_string());
        let nvd = serde_json::json!({
            "vulnerabilities": [
                {
                    "cve": {
                        "id": "CVE-2024-2222",
                        "published": "2024-05-01T00:00:00.000",
                        "descriptions": [{ "lang": "en", "value": "Low bug" }],
                        "metrics": { "cvssMetricV31": [{ "cvssData": { "baseScore": 9.8, "baseSeverity": "CRITICAL" } }] }
                    }
                },
                {
                    "cve": {
                        "id": "CVE-2024-1111",
                        "published": "2024-01-01T00:00:00.000",
                        "descriptions": [{ "lang": "en", "value": "Actively exploited bug" }],
                        "metrics": { "cvssMetricV31": [{ "cvssData": { "baseScore": 7.5, "baseSeverity": "HIGH" } }] }
                    }
                }
            ]
        });
        let mut items = parse_nvd_response(&nvd, &kev);
        items.sort_by(|a, b| b.kev.cmp(&a.kev).then_with(|| b.cvss.unwrap_or(-1.0).total_cmp(&a.cvss.unwrap_or(-1.0))));
        assert_eq!(items[0].id, "CVE-2024-1111");
        assert!(items[0].kev);
        assert_eq!(items[0].severity, "high");
        assert_eq!(items[1].severity, "critical");

        let circl = serde_json::json!([{
            "cveMetadata": { "cveId": "CVE-2024-1111", "datePublished": "2024-02-02T12:00:00Z" },
            "containers": { "cna": {
                "descriptions": [{ "value": "Router RCE" }],
                "metrics": [{ "cvssV3_1": { "baseScore": 8.8 } }]
            }}
        }]);
        let citems = parse_circl_response(&circl, &kev);
        assert_eq!(citems.len(), 1);
        assert!(citems[0].kev);
        assert_eq!(citems[0].cvss, Some(8.8));
    }

    #[test]
    fn http_body_guards_against_oversized_response() {
        let mut raw = b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n".to_vec();
        raw.extend_from_slice(&[b'a'; 100]);
        assert!(decode_http_body(&raw, 50).is_err());
        assert_eq!(decode_http_body(&raw, 100).unwrap().0, 200);
    }

    #[test]
    fn normalizes_device_queries_and_compares_versions() {
        assert_eq!(
            normalize_device_query(None, "TP-Link Archer C7 Wireless Router"),
            (Some("tp-link".into()), "Archer C7".into())
        );
        assert_eq!(
            normalize_device_query(Some("MikroTik"), "MikroTik RB5009UG+S+IN"),
            (Some("MikroTik".into()), "RB5009UG+S+IN".into())
        );
        assert_eq!(version_lt("7.14.2", "7.15"), Some(true));
        assert_eq!(version_lt("7.15.3 (stable)", "7.15.3"), Some(false));
        assert_eq!(version_lt("7.16", "7.15.3"), Some(false));
        assert_eq!(version_lt("unknown", "1.0"), None);
    }

    #[test]
    fn offline_cve_bundle_filters_by_model_and_firmware() {
        let d = tempfile::tempdir().unwrap();
        let bundle = serde_json::json!([
            {
                "id": "CVE-2024-9001",
                "vendor": "MikroTik",
                "model": "hAP ax2",
                "affected_below": "7.15",
                "cvss": 8.2,
                "kev": true,
                "summary": "Fixed in 7.15"
            },
            {
                "id": "CVE-2024-9002",
                "vendor": "MikroTik",
                "keywords": ["hAP ax2", "RouterOS"],
                "affected_below": "7.17",
                "cvss": 6.1,
                "kev": false,
                "summary": "Fixed in 7.17"
            }
        ]);
        std::fs::write(d.path().join("cve-bundle.json"), serde_json::to_vec(&bundle).unwrap()).unwrap();
        let kev = HashSet::new();

        // Firmware 7.14 triggers both; 7.15.2 skips 9001 and keeps 9002.
        let r1 = load_offline_bundle(d.path(), Some("MikroTik"), "hAP ax2", Some("7.14"), &kev).unwrap();
        assert_eq!(r1.len(), 2);
        let r2 = load_offline_bundle(d.path(), Some("MikroTik"), "hAP ax2", Some("7.15.2"), &kev).unwrap();
        assert_eq!(r2.len(), 1);
        assert_eq!(r2[0].id, "CVE-2024-9002");

        // Also test gzipped bundle precedence.
        use flate2::write::GzEncoder;
        use std::io::Write;
        let mut enc = GzEncoder::new(Vec::new(), flate2::Compression::default());
        enc.write_all(&serde_json::to_vec(&bundle).unwrap()).unwrap();
        let gz = enc.finish().unwrap();
        std::fs::write(d.path().join("cve-bundle.json.gz"), gz).unwrap();
        let r3 = load_offline_bundle(d.path(), None, "hAP ax2", Some("7.14"), &kev).unwrap();
        assert_eq!(r3.len(), 2);
    }
}
