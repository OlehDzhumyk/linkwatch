//! Structured, redacted, localized support & escalation packs (`linkwatch support-report`
//! and `GET /api/support-report`).
//!
//! Pure synthesis module: consumes finished outputs from `analyze`, `compare`, `site`,
//! `router_audit`, and `cve` without duplicating fault-detection thresholds.
//! Never includes `[web] token`, router credentials, SNMP communities, filesystem paths,
//! or per-hour LAN client occupancy series.

pub mod i18n;
pub mod render;

#[cfg(test)]
mod tests;

use crate::analyze::{Episode, IfaceReport, Report, RouterLine, is_load_provoked};
use crate::compare::{CompareOpts, CompareReport, CorrelatedKind, NetworkMatch, SessionRow, SessionView, attach_site_rf, compare};
use crate::router::CveLookupResponse;
use crate::model::{IncidentOrigin, IfaceRole, Verdict};
use crate::router::RouterAudit;
use crate::site::{RfPathEstimate, Site};
use chrono::{DateTime, Local, Utc};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

pub use render::{render_html, render_markdown};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Default, clap::ValueEnum)]
#[cfg_attr(test, derive(ts_rs::TS), ts(export))]
#[serde(rename_all = "snake_case")]
pub enum SupportAudience {
    #[default]
    Isp,
    Landlord,
    Admin,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Default, clap::ValueEnum)]
#[cfg_attr(test, derive(ts_rs::TS), ts(export))]
#[serde(rename_all = "snake_case")]
pub enum SupportLang {
    #[default]
    En,
    Uk,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Default, clap::ValueEnum)]
#[cfg_attr(test, derive(ts_rs::TS), ts(export))]
#[serde(rename_all = "snake_case")]
pub enum RedactionLevel {
    None,
    #[default]
    Standard,
    Strict,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, clap::ValueEnum)]
pub enum SupportFormat {
    #[default]
    Text,
    Md,
    Html,
    Json,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[cfg_attr(test, derive(ts_rs::TS), ts(export))]
#[serde(rename_all = "snake_case")]
pub enum ReadinessLevel {
    High,
    Medium,
    Low,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[cfg_attr(test, derive(ts_rs::TS), ts(export))]
#[serde(rename_all = "snake_case")]
pub enum AskSeverity {
    Critical,
    High,
    Medium,
    Info,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[cfg_attr(test, derive(ts_rs::TS), ts(export))]
pub struct SupportAsk {
    pub code: String,
    pub severity: AskSeverity,
    pub target: SupportAudience,
    pub summary: String,
    pub rationale: String,
    pub evidence_timestamps: Vec<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[cfg_attr(test, derive(ts_rs::TS), ts(export))]
pub struct ReadinessAssessment {
    pub level: ReadinessLevel,
    pub warnings: Vec<String>,
    pub warning_codes: Vec<String>,
    pub do_not_file_isp_line_ticket: bool,
    pub suggested_audience: Option<SupportAudience>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[cfg_attr(test, derive(ts_rs::TS), ts(export))]
pub struct AlreadyRuledOut {
    pub wired_ethernet_tested: bool,
    pub ntp_clock_synced: bool,
    pub wifi_power_save_off: bool,
    pub router_zero_reboots: bool,
    pub observer_faults_excluded: bool,
    pub load_incidents_excluded: bool,
    pub host_continuous_uptime: bool,
    pub items: Vec<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
#[cfg_attr(test, derive(ts_rs::TS), ts(export))]
pub struct SupportIncidentRow {
    pub start_utc: String,
    pub start_local: String,
    pub duration_s: f64,
    pub iface: String,
    pub state: String,
    pub cause: String,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
#[cfg_attr(test, derive(ts_rs::TS), ts(export))]
pub struct SupportPointRow {
    pub label: String,
    pub iface: String,
    pub bands: Vec<String>,
    pub hours: f64,
    pub availability_pct: f64,
    pub outages_per_h: f64,
    pub micro_per_h: f64,
    pub gw_rtt_med: Option<f64>,
    pub net_rtt_med: Option<f64>,
    pub loaded_net_rtt_med: Option<f64>,
    pub signal_med: Option<f64>,
    pub retry_rate_per_min: Option<f64>,
    pub speed_med_mbps: Option<f64>,
    pub distance_m: Option<f64>,
    pub walls_crossed: Option<u32>,
    pub obstacle_loss_db: Option<f64>,
    pub status: String,
}

#[derive(Debug, Clone, Serialize)]
#[cfg_attr(test, derive(ts_rs::TS), ts(export))]
pub struct SupportPack {
    pub generated_at: DateTime<Utc>,
    pub audience: SupportAudience,
    pub lang: SupportLang,
    pub redaction: RedactionLevel,
    pub title: String,
    pub verdict_headline: String,
    pub methodology: Vec<String>,
    pub readiness: ReadinessAssessment,
    pub ruled_out: AlreadyRuledOut,
    pub asks: Vec<SupportAsk>,
    pub findings: Vec<String>,
    pub points: Vec<SupportPointRow>,
    pub incidents: Vec<SupportIncidentRow>,
    pub security_notes: Vec<String>,
    pub free_text_notes: Vec<String>,
    pub short_text: String,
}

#[derive(Debug, Clone)]
pub struct SupportOpts {
    pub audience: SupportAudience,
    pub lang: SupportLang,
    pub redaction: RedactionLevel,
    pub tolerance_s: f64,
}

impl Default for SupportOpts {
    fn default() -> Self {
        Self {
            audience: SupportAudience::Isp,
            lang: SupportLang::En,
            redaction: RedactionLevel::Standard,
            tolerance_s: 2.0,
        }
    }
}

pub struct SupportInput<'a> {
    pub sessions: &'a [SessionView],
    pub site: Option<&'a Site>,
    pub router_audit: Option<&'a RouterAudit>,
    pub cve: Option<&'a CveLookupResponse>,
    pub router_log: &'a [RouterLine],
}

#[derive(Clone)]
struct Redactor {
    level: RedactionLevel,
    secrets_and_ids: Vec<(String, String)>,
}

impl Redactor {
    fn new(level: RedactionLevel, sessions: &[SessionView]) -> Self {
        let mut pairs = Vec::new();
        if level == RedactionLevel::Strict {
            for s in sessions {
                if let Some(m) = &s.meta
                    && !m.host.trim().is_empty()
                {
                    pairs.push((m.host.trim().to_string(), "[host]".to_string()));
                }
            }
        }
        Self { level, secrets_and_ids: pairs }
    }

    fn text(&self, raw: &str) -> String {
        let mut out = strip_fs_paths_and_tokens(raw);
        if matches!(self.level, RedactionLevel::Standard | RedactionLevel::Strict) {
            out = mask_macs(&out);
        }
        if self.level == RedactionLevel::Strict {
            out = mask_ipv4s(&out);
            out = mask_ssid_mentions(&out);
            for (needle, repl) in &self.secrets_and_ids {
                if !needle.is_empty() {
                    out = replace_case_insensitive(&out, needle, repl);
                }
            }
        }
        out
    }

    fn point_label(&self, idx: usize, raw: &str) -> String {
        if self.level == RedactionLevel::Strict {
            let letter = ((b'A') + ((idx % 26) as u8)) as char;
            return format!("Point {letter}");
        }
        let cleaned = self.text(raw);
        if cleaned.trim().is_empty() { format!("Point {}", idx + 1) } else { cleaned }
    }
}

fn replace_case_insensitive(hay: &str, needle: &str, repl: &str) -> String {
    if needle.is_empty() {
        return hay.to_string();
    }
    let hay_l = hay.to_ascii_lowercase();
    let needle_l = needle.to_ascii_lowercase();
    let mut out = String::with_capacity(hay.len());
    let mut pos = 0usize;
    while let Some(rel) = hay_l[pos..].find(&needle_l) {
        let abs = pos + rel;
        // Preserve ASCII boundaries when matching short hostnames inside words.
        let left_ok = abs == 0 || !hay.as_bytes()[abs - 1].is_ascii_alphanumeric();
        let right = abs + needle.len();
        let right_ok = right >= hay.len() || !hay.as_bytes()[right].is_ascii_alphanumeric();
        if left_ok && right_ok {
            out.push_str(&hay[pos..abs]);
            out.push_str(repl);
            pos = right;
        } else {
            let next = hay[pos..].chars().next().map_or(1, char::len_utf8);
            out.push_str(&hay[pos..pos + next]);
            pos += next;
        }
    }
    out.push_str(&hay[pos..]);
    out
}

fn strip_fs_paths_and_tokens(raw: &str) -> String {
    let mut words = Vec::new();
    for tok in raw.split(' ') {
        let trimmed = tok.trim_matches(|c: char| matches!(c, ',' | ';' | ')' | '(' | '"' | '\''));
        if trimmed.starts_with("/home/")
            || trimmed.starts_with("/Users/")
            || trimmed.starts_with("/var/")
            || trimmed.starts_with("/etc/")
            || trimmed.starts_with("/tmp/")
            || trimmed.starts_with("C:\\")
        {
            words.push("[path]");
        } else if trimmed.starts_with("token=") || trimmed.starts_with("?token=") {
            words.push("[redacted-token]");
        } else {
            words.push(tok);
        }
    }
    words.join(" ")
}

fn mask_macs(raw: &str) -> String {
    let bytes = raw.as_bytes();
    let mut out = String::with_capacity(raw.len());
    let mut i = 0usize;
    while i < bytes.len() {
        if i + 17 <= bytes.len()
            && is_mac_slice(&bytes[i..i + 17])
            && (i == 0 || !bytes[i - 1].is_ascii_hexdigit())
            && (i + 17 == bytes.len() || !bytes[i + 17].is_ascii_hexdigit())
        {
            let sep = bytes[i + 2] as char;
            out.push_str("xx");
            out.push(sep);
            out.push_str("xx");
            out.push(sep);
            out.push_str("xx");
            out.push_str(&raw[i + 8..i + 17].to_ascii_lowercase());
            i += 17;
            continue;
        }
        let ch = raw[i..].chars().next().unwrap_or(' ');
        out.push(ch);
        i += ch.len_utf8();
    }
    out
}

fn is_mac_slice(b: &[u8]) -> bool {
    if b.len() != 17 {
        return false;
    }
    let sep = b[2];
    if sep != b':' && sep != b'-' {
        return false;
    }
    for idx in 0..6 {
        let base = idx * 3;
        if !b[base].is_ascii_hexdigit() || !b[base + 1].is_ascii_hexdigit() {
            return false;
        }
        if idx < 5 && b[base + 2] != sep {
            return false;
        }
    }
    true
}

fn mask_ipv4s(raw: &str) -> String {
    let b = raw.as_bytes();
    let mut out = String::with_capacity(raw.len());
    let mut i = 0usize;
    while i < b.len() {
        if b[i].is_ascii_digit()
            && (i == 0 || !(b[i - 1].is_ascii_alphanumeric() || b[i - 1] == b'.'))
            && let Some((end, octets, prefix)) = parse_ipv4_prefix(&raw[i..])
        {
            let next_ok = i + end >= b.len() || !(b[i + end].is_ascii_alphanumeric() || b[i + end] == b'.');
            if next_ok {
                let is_priv = octets[0] == 10
                    || (octets[0] == 172 && (16..=31).contains(&octets[1]))
                    || (octets[0] == 192 && octets[1] == 168)
                    || (octets[0] == 100 && (64..=127).contains(&octets[1]))
                    || (octets[0] == 169 && octets[1] == 254)
                    || octets[0] == 127;
                if is_priv {
                    if prefix.is_some() {
                        out.push_str("192.0.2.0");
                    } else if octets[3] == 1 || octets[3] == 254 {
                        out.push_str("192.0.2.1");
                    } else {
                        out.push_str("192.0.2.10");
                    }
                } else if prefix.is_some() {
                    out.push_str("198.51.100.0");
                } else {
                    out.push_str("198.51.100.1");
                }
                if let Some(p) = prefix {
                    out.push('/');
                    out.push_str(&p);
                }
                i += end;
                continue;
            }
        }
        let ch = raw[i..].chars().next().unwrap_or(' ');
        out.push(ch);
        i += ch.len_utf8();
    }
    out
}

fn parse_ipv4_prefix(s: &str) -> Option<(usize, [u8; 4], Option<String>)> {
    let mut end = 0usize;
    for (idx, ch) in s.char_indices() {
        if ch.is_ascii_digit() || ch == '.' {
            end = idx + 1;
        } else {
            break;
        }
    }
    let ip_part = &s[..end];
    let parts: Vec<&str> = ip_part.split('.').collect();
    if parts.len() != 4 {
        return None;
    }
    let mut octets = [0u8; 4];
    for (idx, p) in parts.iter().enumerate() {
        if p.is_empty() || p.len() > 3 {
            return None;
        }
        octets[idx] = p.parse::<u8>().ok()?;
    }
    if s[end..].starts_with('/') {
        let mut p_end = end + 1;
        for (idx, ch) in s[end + 1..].char_indices() {
            if ch.is_ascii_digit() {
                p_end = end + 1 + idx + 1;
            } else {
                break;
            }
        }
        if p_end > end + 1 {
            return Some((p_end, octets, Some(s[end + 1..p_end].to_string())));
        }
    }
    Some((end, octets, None))
}

fn mask_ssid_mentions(raw: &str) -> String {
    // Mask quoted/token SSID forms like `SSID "MyHome"` / `SSID 'MyHome'` while advancing cursor.
    let mut out = raw.to_string();
    for marker in ["SSID ", "ssid ", "SSID: ", "ssid: "] {
        let mut cursor = 0usize;
        while cursor < out.len() {
            let Some(rel) = out[cursor..].find(marker) else { break };
            let pos = cursor + rel;
            let after = pos + marker.len();
            let rest = &out[after..];
            let repl_end = if let Some(inner) = rest.strip_prefix('"') {
                inner.find('"').map(|k| after + k + 2)
            } else if let Some(inner) = rest.strip_prefix('\'') {
                inner.find('\'').map(|k| after + k + 2)
            } else {
                rest.find(|c: char| c.is_whitespace() || c == ',' || c == ')')
                    .map(|k| after + k)
                    .or(Some(out.len()))
            };
            if let Some(end) = repl_end {
                let repl = "[hidden-ssid]";
                out.replace_range(pos..end, repl);
                cursor = pos + repl.len();
            } else {
                cursor = after;
            }
        }
    }
    out
}

fn best_point_status(row: &SessionRow, lang: SupportLang) -> String {
    if row.availability_pct < 99.0 || row.outages_per_h >= 1.0 || row.signal_med.is_some_and(|s| s < -75.0) {
        i18n::status_poor(lang).into()
    } else if row.availability_pct < 99.8
        || row.outages_per_h >= 0.25
        || row.micro_per_h >= 1.0
        || row.signal_med.is_some_and(|s| s < -67.0)
        || row.retry_rate_per_min.is_some_and(|r| r >= 60.0)
        || row.loaded_net_rtt_med.is_some_and(|r| r >= 150.0)
    {
        i18n::status_degraded(lang).into()
    } else {
        i18n::status_good(lang).into()
    }
}

fn pick_primary_iface(r: &Report) -> Option<&IfaceReport> {
    r.ifaces
        .iter()
        .filter(|i| i.ticks > 0)
        .min_by(|a, b| a.availability_pct.total_cmp(&b.availability_pct))
        .or_else(|| r.ifaces.first())
}

fn is_lan_finding_code(code: &str) -> bool {
    matches!(code, "f_lan" | "f_lan_evening" | "c_lan")
}

fn has_evening_lan_surge(sessions: &[SessionView]) -> bool {
    sessions
        .iter()
        .any(|s| s.report.findings_msg.iter().any(|m| m.code == "f_lan_evening"))
}

fn has_rogue_dhcp(sessions: &[SessionView]) -> bool {
    sessions
        .iter()
        .any(|s| s.report.security_events.iter().any(|ev| ev.contains("rogue_gateway")))
}

/// Synthesizes a complete support & escalation pack from analyzed session data.
pub fn build_pack(input: &SupportInput<'_>, opts: &SupportOpts) -> SupportPack {
    let lang = opts.lang;
    let redactor = Redactor::new(opts.redaction, input.sessions);

    let mut cmp_opt: Option<CompareReport> = if input.sessions.len() >= 2 {
        let mut c = compare(input.sessions.to_vec(), &CompareOpts { tolerance_s: opts.tolerance_s.max(0.0) });
        if let Some(site) = input.site {
            attach_site_rf(&mut c, site);
        }
        Some(c)
    } else {
        None
    };

    // Build unified point rows (either from CompareReport or single SessionView).
    let mut points = Vec::new();
    let mut session_rows: Vec<(usize, String, SessionRow)> = Vec::new();
    if let Some(ref mut cmp) = cmp_opt {
        for (idx, row) in cmp.sessions.iter().enumerate() {
            let lbl = redactor.point_label(idx, &row.label);
            points.push(SupportPointRow {
                label: lbl.clone(),
                iface: row.iface.clone(),
                bands: row.bands.clone(),
                hours: row.hours,
                availability_pct: row.availability_pct,
                outages_per_h: row.outages_per_h,
                micro_per_h: row.micro_per_h,
                gw_rtt_med: row.gw_rtt_med,
                net_rtt_med: row.net_rtt_med,
                loaded_net_rtt_med: row.loaded_net_rtt_med,
                signal_med: row.signal_med,
                retry_rate_per_min: row.retry_rate_per_min,
                speed_med_mbps: row.speed_med_mbps,
                distance_m: row.rf.as_ref().map(|r| r.distance_m),
                walls_crossed: row.rf.as_ref().map(|r| r.walls_crossed),
                obstacle_loss_db: row.rf.as_ref().map(|r| r.obstacle_loss_db),
                status: best_point_status(row, lang),
            });
            session_rows.push((idx, lbl, row.clone()));
        }
    } else if let Some(s) = input.sessions.first() {
        let p = pick_primary_iface(&s.report);
        let rf: Option<RfPathEstimate> = input
            .site
            .and_then(|site| s.meta.as_ref().and_then(|m| m.point.as_deref()).and_then(|pid| site.estimate_rf(pid)));
        let hours = s.report.hours;
        let div_h = if hours > 1e-4 { hours } else { 1.0 };
        let bands: Vec<String> = s
            .report
            .ifaces
            .iter()
            .flat_map(|i| i.bands.iter().map(|b| b.band.clone()))
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        let row = SessionRow {
            id: s.id.clone(),
            label: s.label.clone(),
            host: s.meta.as_ref().map_or_else(|| "-".into(), |m| m.host.clone()),
            point: s.meta.as_ref().and_then(|m| m.point.clone()),
            from: s.report.from,
            to: s.report.to,
            hours,
            iface: p.map_or_else(|| "-".into(), |i| i.iface.clone()),
            bands: bands.clone(),
            availability_pct: p.map_or(0.0, |i| i.availability_pct),
            outages: p.map_or(0, |i| i.episodes),
            micro_drops: p.map_or(0, |i| i.micro_drops),
            stalls: p.map_or(0, |i| i.stalls),
            outages_per_h: p.map_or(0.0, |i| if hours > 1e-4 { f64::from(i.episodes) / div_h } else { 0.0 }),
            micro_per_h: p.map_or(0.0, |i| if hours > 1e-4 { f64::from(i.micro_drops) / div_h } else { 0.0 }),
            gw_rtt_med: p.and_then(|i| i.gw_rtt_med),
            net_rtt_med: p.and_then(|i| i.net_rtt_med),
            loaded_net_rtt_med: p.and_then(|i| i.loaded_net_rtt_med),
            signal_med: p.and_then(|i| i.signal_med),
            speed_med_mbps: p.and_then(|i| i.speed_med_mbps),
            retry_rate_per_min: p.and_then(|i| i.retry_rate_per_min),
            observer_incidents: s.report.observer_incidents,
            rf: rf.clone(),
        };
        let lbl = redactor.point_label(0, &row.label);
        points.push(SupportPointRow {
            label: lbl.clone(),
            iface: row.iface.clone(),
            bands,
            hours: row.hours,
            availability_pct: row.availability_pct,
            outages_per_h: row.outages_per_h,
            micro_per_h: row.micro_per_h,
            gw_rtt_med: row.gw_rtt_med,
            net_rtt_med: row.net_rtt_med,
            loaded_net_rtt_med: row.loaded_net_rtt_med,
            signal_med: row.signal_med,
            retry_rate_per_min: row.retry_rate_per_min,
            speed_med_mbps: row.speed_med_mbps,
            distance_m: rf.as_ref().map(|r| r.distance_m),
            walls_crossed: rf.as_ref().map(|r| r.walls_crossed),
            obstacle_loss_db: rf.as_ref().map(|r| r.obstacle_loss_db),
            status: best_point_status(&row, lang),
        });
        session_rows.push((0, lbl, row));
    }

    // Aggregate measurements across sessions.
    let mut wired_count = 0usize;
    let mut wired_healthy = 0usize;
    let mut wifi_count = 0usize;
    let mut dual_path = false;
    let mut all_ntp_synced = !input.sessions.is_empty();
    let mut any_power_save = false;
    let mut any_polluted = false;
    let mut any_gaps = false;
    let mut max_hours = 0.0f64;
    let mut min_tick_s = 1.0f64;
    let mut total_net_incidents = 0u32;
    let mut total_obs_incidents = 0u32;
    let mut total_load_incidents = 0u32;
    let mut line_incidents = 0u32;
    let mut router_incidents = 0u32;
    let mut inet_incidents = 0u32;
    let mut dns_incidents = 0u32;
    let mut wifi_incidents = 0u32;
    let mut router_resets = 0u32;
    let mut has_router_telemetry = false;
    let mut loaded_rtt_peak: Option<f64> = None;
    let mut idle_rtt_med: Option<f64> = None;
    let mut worst_signal: Option<f64> = None;
    let mut max_retry_rate: Option<f64> = None;
    let mut evening_speed_collapse = false;
    let mut evening_rtt_spike = false;

    let mut unprovoked_eps: Vec<(usize, &Episode)> = Vec::new();
    let mut load_eps_ts: Vec<String> = Vec::new();
    let mut free_text_notes: BTreeSet<String> = BTreeSet::new();

    for (idx, s) in input.sessions.iter().enumerate() {
        max_hours = max_hours.max(s.report.hours);
        if s.report.tick_s > 0.0 {
            min_tick_s = s.report.tick_s;
        }
        total_net_incidents += s.report.network_incidents;
        total_obs_incidents += s.report.observer_incidents;
        total_load_incidents += s.report.load_incidents;
        line_incidents += s.report.incidents.get("line_problem").copied().unwrap_or(0);
        router_incidents += s.report.incidents.get("router_problem").copied().unwrap_or(0);
        inet_incidents += s.report.incidents.get("internet_problem").copied().unwrap_or(0);
        dns_incidents += s.report.incidents.get("dns").copied().unwrap_or(0);
        wifi_incidents += s.report.incidents.get("wifi_problem").copied().unwrap_or(0);

        if s.clock_synced != Some(true) || s.report.observer_findings_msg.iter().any(|m| m.code == "o_ntp") {
            all_ntp_synced = false;
        }
        if s.report.observer_findings_msg.iter().any(|m| m.code == "o_power_save") {
            any_power_save = true;
        }
        // Power-save has its own warning; other host pollution (late ticks, throttling) too.
        if s.report.observer_trust.level == crate::analyze::TrustLevel::Polluted
            && s.report.observer_trust.reasons.iter().any(|m| m.code != "t_power_save")
        {
            any_polluted = true;
        }
        if !s.gaps.is_empty() || !s.report.monitor_gaps.is_empty() {
            any_gaps = true;
        }
        if let Some(rr) = &s.report.router
            && rr.samples > 0
        {
            has_router_telemetry = true;
            router_resets += rr.uptime_resets;
        }

        let mut s_has_wired = false;
        let mut s_has_wifi = false;
        for iface in &s.report.ifaces {
            if iface.ticks == 0 && !iface.had_link {
                continue;
            }
            match iface.role {
                Some(IfaceRole::Ethernet) => {
                    s_has_wired = true;
                    wired_count += 1;
                    if iface.availability_pct >= 99.5 {
                        wired_healthy += 1;
                    }
                    if let Some(v) = iface.net_rtt_med {
                        idle_rtt_med = Some(idle_rtt_med.map_or(v, |c| c.min(v)));
                    }
                    if let Some(v) = iface.loaded_net_rtt_med {
                        loaded_rtt_peak = Some(loaded_rtt_peak.map_or(v, |c| c.max(v)));
                    }
                }
                Some(IfaceRole::Wifi) => {
                    s_has_wifi = true;
                    wifi_count += 1;
                    if let Some(sig) = iface.signal_med {
                        worst_signal = Some(worst_signal.map_or(sig, |c| c.min(sig)));
                    }
                    if let Some(r) = iface.retry_rate_per_min {
                        max_retry_rate = Some(max_retry_rate.map_or(r, |c| c.max(r)));
                    }
                    if let Some(v) = iface.loaded_net_rtt_med {
                        loaded_rtt_peak = Some(loaded_rtt_peak.map_or(v, |c| c.max(v)));
                    }
                    if idle_rtt_med.is_none()
                        && let Some(v) = iface.net_rtt_med
                    {
                        idle_rtt_med = Some(v);
                    }
                }
                _ => {}
            }
        }
        if s_has_wired && s_has_wifi {
            dual_path = true;
        }
        for f in &s.report.findings_msg {
            if f.code == "f_evening_speed" {
                evening_speed_collapse = true;
            } else if f.code == "f_evening_rtt" {
                evening_rtt_spike = true;
            }
        }
        for ep in &s.report.episodes {
            if ep.origin == IncidentOrigin::Observer {
                continue;
            }
            if is_load_provoked(ep) {
                load_eps_ts.push(fmt_utc(ep.start));
            } else {
                unprovoked_eps.push((idx, ep));
            }
        }
        if let Some(note) = s.meta.as_ref().and_then(|m| m.note.as_deref()) {
            let trimmed = redactor.text(note.trim());
            if !trimmed.is_empty() {
                free_text_notes.insert(trimmed);
            }
        }
    }

    let network_mismatch = cmp_opt
        .as_ref()
        .is_some_and(|c| c.network_matches.iter().any(|m| m.match_kind == NetworkMatch::Different));

    let has_wired = wired_count > 0;
    let has_wifi = wifi_count > 0;
    let shared_or_line_corr = cmp_opt.as_ref().is_some_and(|c| {
        c.correlated
            .iter()
            .any(|ci| matches!(ci.kind, CorrelatedKind::SharedOutage))
    });
    let wifi_only_corr = cmp_opt.as_ref().is_some_and(|c| {
        c.correlated
            .iter()
            .any(|ci| matches!(ci.kind, CorrelatedKind::LocalOnly | CorrelatedKind::WifiOnlyOutage))
    });

    let no_upstream_outages = line_incidents == 0 && router_incidents == 0 && inet_incidents == 0 && dns_incidents == 0 && !shared_or_line_corr;
    let wifi_symptoms = wifi_incidents > 0
        || wifi_only_corr
        || worst_signal.is_some_and(|s| s < -70.0)
        || max_retry_rate.is_some_and(|r| r >= 60.0);
    let wifi_only_fault = !network_mismatch && has_wired && wired_healthy == wired_count && no_upstream_outages && wifi_symptoms;
    let load_only_fault = total_net_incidents == 0 && total_load_incidents > 0 && !shared_or_line_corr;
    let rogue_dhcp = has_rogue_dhcp(input.sessions);

    let has_concurrent_dual_observers = cmp_opt.as_ref().is_some_and(|c| c.overlap_hours >= 2.0 && all_ntp_synced);

    let mut warning_codes = Vec::new();
    let mut warnings = Vec::new();
    if input.sessions.is_empty() {
        warning_codes.push("warn_no_sessions".into());
        warnings.push(i18n::warn_no_sessions(lang).into());
    }
    if network_mismatch {
        warning_codes.push("warn_network_mismatch".into());
        warnings.push(i18n::warn_network_mismatch(lang).into());
    }
    if max_hours > 0.0 && max_hours < 2.0 {
        warning_codes.push("warn_short_run".into());
        warnings.push(i18n::warn_short_run(lang, max_hours));
    }
    if opts.audience == SupportAudience::Isp && !has_wired && has_wifi && !wifi_only_fault {
        warning_codes.push("warn_wifi_only_for_isp".into());
        warnings.push(i18n::warn_wifi_only_for_isp(lang).into());
    }
    if any_power_save {
        warning_codes.push("warn_power_save".into());
        warnings.push(i18n::warn_power_save(lang).into());
    }
    if any_polluted {
        warning_codes.push("warn_observer_polluted".into());
        warnings.push(i18n::warn_observer_polluted(lang).into());
    }
    if !all_ntp_synced && !input.sessions.is_empty() {
        warning_codes.push("warn_ntp_unsynced".into());
        warnings.push(i18n::warn_ntp_unsynced(lang).into());
    }
    if any_gaps {
        warning_codes.push("warn_monitor_gaps".into());
        warnings.push(i18n::warn_monitor_gaps(lang).into());
    }

    let mut do_not_file_isp_line_ticket = false;
    let mut suggested_audience = None;
    if opts.audience == SupportAudience::Isp {
        if wifi_only_fault {
            do_not_file_isp_line_ticket = true;
            suggested_audience = Some(SupportAudience::Landlord);
            warning_codes.push("warn_isp_line_healthy_wifi_only".into());
            warnings.push(i18n::warn_isp_line_healthy_wifi_only(lang).into());
        } else if load_only_fault {
            do_not_file_isp_line_ticket = true;
            suggested_audience = Some(SupportAudience::Admin);
            warning_codes.push("warn_load_provoked_only".into());
            warnings.push(i18n::warn_load_provoked_only(lang).into());
        } else if rogue_dhcp {
            do_not_file_isp_line_ticket = true;
            suggested_audience = Some(SupportAudience::Admin);
            warning_codes.push("warn_rogue_dhcp_local".into());
            warnings.push(i18n::warn_rogue_dhcp_local(lang).into());
        }
    }

    let is_low = input.sessions.is_empty()
        || network_mismatch
        || max_hours < 2.0
        || (opts.audience == SupportAudience::Isp && !has_wired)
        || any_power_save
        || any_polluted
        || !all_ntp_synced
        || any_gaps;
    let is_high = !is_low && max_hours >= 6.0 && (dual_path || has_concurrent_dual_observers);
    let readiness_level = if is_low {
        ReadinessLevel::Low
    } else if is_high {
        ReadinessLevel::High
    } else {
        ReadinessLevel::Medium
    };

    // Already Ruled Out (strictly observed facts).
    let audit_has_uptime = input.router_audit.and_then(|a| a.uptime_s).is_some_and(|u| u >= 3600);
    let wired_ethernet_tested = has_wired;
    let ntp_clock_synced = all_ntp_synced && !input.sessions.is_empty();
    let wifi_power_save_off = has_wifi && !any_power_save;
    let router_zero_reboots = router_resets == 0 && (has_router_telemetry || audit_has_uptime);
    let observer_faults_excluded = !input.sessions.is_empty();
    let load_incidents_excluded = !input.sessions.is_empty();
    let host_continuous_uptime = !input.sessions.is_empty() && !any_gaps;

    let mut ruled_items = Vec::new();
    if wired_ethernet_tested {
        ruled_items.push(i18n::ro_wired(lang).into());
    }
    if ntp_clock_synced {
        ruled_items.push(i18n::ro_ntp(lang).into());
    }
    if wifi_power_save_off {
        ruled_items.push(i18n::ro_power_save_off(lang).into());
    }
    if router_zero_reboots {
        ruled_items.push(i18n::ro_router_uptime(lang).into());
    }
    if host_continuous_uptime {
        ruled_items.push(i18n::ro_host_uptime(lang).into());
    }
    if observer_faults_excluded {
        ruled_items.push(i18n::ro_observer_excluded(lang, total_obs_incidents));
    }
    if load_incidents_excluded && total_load_incidents > 0 {
        ruled_items.push(i18n::ro_load_excluded(lang, total_load_incidents));
    }

    // Build UTC + local incident table rows (unprovoked non-observer only).
    unprovoked_eps.sort_by_key(|a| std::cmp::Reverse(a.1.start));
    let mut incidents = Vec::new();
    let mut docsis_matched_notes = Vec::new();
    let mut isp_timestamps = Vec::new();
    let mut dns_timestamps = Vec::new();
    let mut router_timestamps = Vec::new();

    for (_, ep) in unprovoked_eps.iter().take(50) {
        let utc_s = fmt_utc(ep.start);
        let loc_s = fmt_local(ep.start);
        let mut details: Vec<String> = ep
            .context_msg
            .iter()
            .filter(|m| !is_lan_finding_code(&m.code))
            .map(|m| redactor.text(&m.text))
            .collect();
        for rl in input.router_log {
            if rl.ts >= ep.start - chrono::Duration::seconds(120) && rl.ts <= ep.end + chrono::Duration::seconds(120) {
                let txt = format!("DOCSIS {}: {}", rl.priority, redactor.text(&rl.text));
                docsis_matched_notes.push(format!("{utc_s} ({txt})"));
                details.push(txt);
            }
        }
        match ep.cause {
            Some(Verdict::LineProblem | Verdict::InternetProblem) => isp_timestamps.push(format!("{utc_s} / {loc_s}")),
            Some(Verdict::RouterProblem) => router_timestamps.push(format!("{utc_s} / {loc_s}")),
            Some(Verdict::Dns) => dns_timestamps.push(format!("{utc_s} / {loc_s}")),
            _ => {}
        }
        incidents.push(SupportIncidentRow {
            start_utc: utc_s,
            start_local: loc_s,
            duration_s: ep.duration_s,
            iface: ep.iface.clone(),
            state: ep.state.as_str().into(),
            cause: ep.cause.map_or("unknown", Verdict::as_str).into(),
            detail: details.into_iter().take(3).collect::<Vec<_>>().join("; "),
        });
    }

    // Evidence-gated asks (S1-S7).
    let mut asks = Vec::new();
    if rogue_dhcp {
        asks.push(SupportAsk {
            code: "local_rogue_dhcp".into(),
            severity: AskSeverity::Critical,
            target: SupportAudience::Admin,
            summary: i18n::ask_rogue_dhcp_sum(lang).into(),
            rationale: i18n::ask_rogue_dhcp_rat(lang).into(),
            evidence_timestamps: Vec::new(),
        });
    }

    let line_or_shared = line_incidents > 0 || inet_incidents > 0 || (shared_or_line_corr && total_net_incidents > 0);
    if line_or_shared && !wifi_only_fault && !load_only_fault && !network_mismatch {
        asks.push(SupportAsk {
            code: "isp_check_access_line".into(),
            severity: AskSeverity::High,
            target: SupportAudience::Isp,
            summary: i18n::ask_isp_line_sum(lang).into(),
            rationale: i18n::ask_isp_line_rat(lang, line_incidents + inet_incidents, !docsis_matched_notes.is_empty()),
            evidence_timestamps: isp_timestamps.iter().take(5).cloned().collect(),
        });
    }

    if (router_incidents > 0 || router_resets > 0) && !network_mismatch {
        let target = if opts.audience == SupportAudience::Isp { SupportAudience::Isp } else { SupportAudience::Admin };
        asks.push(SupportAsk {
            code: "replace_or_inspect_router".into(),
            severity: AskSeverity::High,
            target,
            summary: i18n::ask_router_sum(lang).into(),
            rationale: i18n::ask_router_rat(lang, router_incidents, router_resets, host_continuous_uptime),
            evidence_timestamps: router_timestamps.iter().take(5).cloned().collect(),
        });
    }

    if dns_incidents > 0 && !network_mismatch {
        asks.push(SupportAsk {
            code: "dns_resolver_check".into(),
            severity: AskSeverity::Medium,
            target: if opts.audience == SupportAudience::Admin { SupportAudience::Admin } else { SupportAudience::Isp },
            summary: i18n::ask_dns_sum(lang).into(),
            rationale: i18n::ask_dns_rat(lang, dns_incidents),
            evidence_timestamps: dns_timestamps.iter().take(5).cloned().collect(),
        });
    }

    let bufferbloat = loaded_rtt_peak.is_some_and(|l| l >= 150.0 && idle_rtt_med.is_none_or(|id| l >= id * 3.0))
        || total_load_incidents > 0;
    if bufferbloat {
        let sev = if load_only_fault { AskSeverity::Medium } else { AskSeverity::Info };
        let target = if opts.audience == SupportAudience::Admin { SupportAudience::Admin } else { SupportAudience::Isp };
        asks.push(SupportAsk {
            code: "sqm_or_bridge_mode".into(),
            severity: sev,
            target,
            summary: i18n::ask_bufferbloat_sum(lang).into(),
            rationale: i18n::ask_bufferbloat_rat(lang, loaded_rtt_peak, idle_rtt_med, total_load_incidents),
            evidence_timestamps: load_eps_ts.iter().take(5).cloned().collect(),
        });
    }

    let lan_surge = has_evening_lan_surge(input.sessions);
    if (evening_speed_collapse || evening_rtt_spike) && !lan_surge && has_wired {
        asks.push(SupportAsk {
            code: "isp_evening_congestion".into(),
            severity: AskSeverity::Medium,
            target: SupportAudience::Isp,
            summary: i18n::ask_evening_congestion_sum(lang).into(),
            rationale: i18n::ask_evening_congestion_rat(lang).into(),
            evidence_timestamps: Vec::new(),
        });
    }

    if wifi_symptoms && (!no_upstream_outages || wifi_only_fault || opts.audience != SupportAudience::Isp) {
        if opts.audience == SupportAudience::Landlord || wifi_only_fault {
            let max_walls = points.iter().filter_map(|p| p.walls_crossed).max();
            let max_loss = points.iter().filter_map(|p| p.obstacle_loss_db).reduce(f64::max);
            asks.push(SupportAsk {
                code: "landlord_wired_hallway_ap".into(),
                severity: AskSeverity::High,
                target: SupportAudience::Landlord,
                summary: i18n::ask_landlord_poe_sum(lang).into(),
                rationale: i18n::ask_landlord_poe_rat(lang, max_walls, max_loss),
                evidence_timestamps: Vec::new(),
            });
            asks.push(SupportAsk {
                code: "landlord_avoid_wireless_repeaters".into(),
                severity: AskSeverity::Medium,
                target: SupportAudience::Landlord,
                summary: i18n::ask_landlord_no_repeater_sum(lang).into(),
                rationale: i18n::ask_landlord_no_repeater_rat(lang).into(),
                evidence_timestamps: Vec::new(),
            });
        } else if opts.audience == SupportAudience::Admin {
            asks.push(SupportAsk {
                code: "admin_wifi_channel_placement".into(),
                severity: AskSeverity::Medium,
                target: SupportAudience::Admin,
                summary: i18n::ask_admin_wifi_sum(lang).into(),
                rationale: i18n::ask_admin_wifi_rat(lang, worst_signal, max_retry_rate),
                evidence_timestamps: Vec::new(),
            });
        }
    }

    // Security & hardware audit findings (S7).
    let mut security_notes = Vec::new();
    let risky_ports: Vec<&crate::router::PortCheck> = input
        .router_audit
        .map(|a| a.ports.iter().filter(|p| p.open && matches!(p.risk.as_str(), "high" | "warn")).collect())
        .unwrap_or_default();
    let cve_kevs = input.cve.map_or(0, |c| c.kev_count);
    let cve_total = input.cve.map_or(0, |c| c.total);
    if !risky_ports.is_empty() || cve_total > 0 {
        let port_list: Vec<String> = risky_ports.iter().map(|p| format!("{}/{}", p.service, p.port)).collect();
        asks.push(SupportAsk {
            code: "admin_firmware_hardening".into(),
            severity: if cve_kevs > 0 || risky_ports.iter().any(|p| p.risk == "high") { AskSeverity::High } else { AskSeverity::Medium },
            target: SupportAudience::Admin,
            summary: i18n::ask_sec_hardening_sum(lang).into(),
            rationale: i18n::ask_sec_hardening_rat(lang, &port_list, cve_total, cve_kevs),
            evidence_timestamps: Vec::new(),
        });
        security_notes.push(redactor.text(&i18n::ask_sec_hardening_rat(lang, &port_list, cve_total, cve_kevs)));
    } else if opts.audience == SupportAudience::Admin && input.router_audit.is_none() {
        security_notes.push(i18n::sec_passive_scope_only(lang).into());
    }
    for s in input.sessions {
        for ev in &s.report.security_events {
            security_notes.push(redactor.text(ev));
        }
    }

    // Findings list (omit LAN occupancy series at all redaction tiers, check S5/S12).
    let mut findings = Vec::new();
    if let Some(cmp) = &cmp_opt {
        for msg in &cmp.findings_msg {
            if is_lan_finding_code(&msg.code) {
                continue;
            }
            findings.push(redactor.text(&msg.text));
        }
    } else if let Some(s) = input.sessions.first() {
        for msg in &s.report.findings_msg {
            if is_lan_finding_code(&msg.code) {
                continue;
            }
            findings.push(redactor.text(&msg.text));
        }
    }
    if (evening_speed_collapse || evening_rtt_spike) && lan_surge {
        findings.push(i18n::finding_household_evening_surge(lang).into());
    }
    for delta in before_after_deltas(&session_rows, lang) {
        findings.push(delta);
    }

    // Headline verdict tailored cleanly to evidence.
    let verdict_headline = if network_mismatch {
        i18n::headline_mismatch(lang).into()
    } else if rogue_dhcp {
        i18n::headline_rogue_dhcp(lang).into()
    } else if wifi_only_fault {
        i18n::headline_wifi_only(lang).into()
    } else if load_only_fault {
        i18n::headline_load_only(lang).into()
    } else if line_or_shared {
        i18n::headline_line_fault(lang, line_incidents + inet_incidents)
    } else if router_incidents > 0 || router_resets > 0 {
        i18n::headline_router_fault(lang).into()
    } else if dns_incidents > 0 {
        i18n::headline_dns_fault(lang).into()
    } else {
        i18n::headline_healthy(lang).into()
    };

    let methodology = i18n::methodology_lines(lang, min_tick_s, has_wired, has_wifi, all_ntp_synced);
    let title = i18n::report_title(lang, opts.audience).into();

    let mut pack = SupportPack {
        generated_at: Utc::now(),
        audience: opts.audience,
        lang,
        redaction: opts.redaction,
        title,
        verdict_headline,
        methodology,
        readiness: ReadinessAssessment {
            level: readiness_level,
            warnings,
            warning_codes,
            do_not_file_isp_line_ticket,
            suggested_audience,
        },
        ruled_out: AlreadyRuledOut {
            wired_ethernet_tested,
            ntp_clock_synced,
            wifi_power_save_off,
            router_zero_reboots,
            observer_faults_excluded,
            load_incidents_excluded,
            host_continuous_uptime,
            items: ruled_items,
        },
        asks,
        findings,
        points,
        incidents,
        security_notes,
        free_text_notes: free_text_notes.into_iter().collect(),
        short_text: String::new(),
    };
    pack.short_text = render::render_short_text(&pack);
    pack
}

/// Computes quantified Before/After deltas when >= 2 non-overlapping sessions share a point (S12).
fn before_after_deltas(rows: &[(usize, String, SessionRow)], lang: SupportLang) -> Vec<String> {
    let mut by_point: BTreeMap<&str, Vec<&(usize, String, SessionRow)>> = BTreeMap::new();
    for item in rows {
        if let Some(pid) = item.2.point.as_deref() {
            by_point.entry(pid).or_default().push(item);
        }
    }
    let mut out = Vec::new();
    for mut grp in by_point.into_values() {
        if grp.len() < 2 {
            continue;
        }
        grp.sort_by_key(|item| item.2.from);
        let first = &grp[0].2;
        let last = &grp[grp.len() - 1].2;
        if let (Some(ft), Some(lt)) = (first.to, last.from)
            && ft <= lt
        {
            out.push(i18n::before_after_summary(
                lang,
                &grp[0].1,
                first.availability_pct,
                last.availability_pct,
                first.outages,
                last.outages,
                first.signal_med,
                last.signal_med,
                first.retry_rate_per_min,
                last.retry_rate_per_min,
            ));
        }
    }
    out
}

fn fmt_utc(t: DateTime<Utc>) -> String {
    t.format("%Y-%m-%d %H:%M:%S UTC").to_string()
}

fn fmt_local(t: DateTime<Utc>) -> String {
    t.with_timezone(&Local).format("%H:%M:%S %:z").to_string()
}
