//! `linkwatch analyze`: compress a session into a short, explainable report.
//!
//! Deterministic rules only, every finding states its evidence:
//! - outage episodes per interface (bad ticks merged when gaps are short) and their cross-path cause,
//! - micro-drops (1–2 s) counted separately: these are what people feel as "it froze for a moment",
//! - hourly profile (local time): loss, RTT median/p95, episodes,
//! - anomalous minutes by robust z-score (median/MAD) on RTT, signal and channel busy,
//! - regularity of episodes (fixed period, same time of day),
//! - context around each episode: roam, channel change, link change, low signal, busy channel,
//!   speed test, router (DOCSIS) log lines when imported.
//!
//! Streaming over samples: memory is bounded by minutes and episodes, not by ticks.


pub mod attribution;
mod detect;
mod engine;
mod markdown;
#[cfg(test)]
mod tests;
#[cfg(test)]
mod attribution_tests;

pub use engine::Analyzer;
pub use markdown::to_markdown;
use crate::model::*;
use chrono::{DateTime, Duration, Local, TimeZone, Timelike, Utc};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone)]
pub struct Opts {
    /// Bad ticks closer than this are merged into one episode.
    pub merge_gap_s: i64,
    /// Episodes up to this length are micro-drops.
    pub micro_max_s: f64,
    /// Robust z-score threshold for anomalous minutes.
    pub z: f64,
    /// Context window around an episode.
    pub context_s: i64,
    /// Probe interval of the session (from meta.json). One bad tick lasts this long.
    pub tick_s: f64,
    /// A tick with router RTT above this (ms) is a stall ("freezes" without loss).
    pub stall_gw_ms: f64,
    /// A tick with internet RTT above this (ms) is a stall.
    pub stall_net_ms: f64,
    /// Interface traffic (rx+tx, bit/s) above this, outside our speed test, is the host's own
    /// load (updates, backups, downloads): stalls then are not counted as network faults (H4).
    pub self_traffic_bps: f64,
    /// Packets per second (rx+tx) above this are the host's own load too (H16).
    pub self_traffic_pps: f64,
}

impl Default for Opts {
    fn default() -> Self {
        Self { merge_gap_s: 5, micro_max_s: 2.5, z: 4.0, context_s: 60, tick_s: 1.0, stall_gw_ms: 200.0, stall_net_ms: 500.0, self_traffic_bps: 10e6, self_traffic_pps: 2000.0 }
    }
}

impl Opts {
    /// Options for a session, with the probe interval from its stored configuration.
    pub fn for_session(meta: Option<&SessionMeta>) -> Self {
        let probe_ms = meta
            .and_then(|m| m.config.pointer("/intervals/probe_ms"))
            .and_then(|v| v.as_u64())
            .filter(|v| *v > 0)
            .unwrap_or(1000);
        let tick_s = probe_ms as f64 / 1000.0;
        let d = Self::default();
        // A micro-drop is at most two ticks; merging needs at least two ticks of gap.
        Self { tick_s, micro_max_s: d.micro_max_s.max(2.0 * tick_s + 0.5), merge_gap_s: d.merge_gap_s.max((2.0 * tick_s).ceil() as i64), ..d }
    }
}

/// An outage is a path that has a link and an address but does not get through, or a Wi-Fi
/// path that lost association or address (that is the Wi-Fi failing).
/// A wired path without link or address (cable unplugged) is reported separately.
fn is_bad(s: PathState) -> bool {
    !matches!(s, PathState::Ok | PathState::Degraded | PathState::Unknown)
}

fn is_no_link(role: IfaceRole, s: PathState) -> bool {
    role != IfaceRole::Wifi && matches!(s, PathState::LinkDown | PathState::NoIp)
}

/// Markdown table cells must not contain `|` or line breaks.
fn cell(s: &str) -> String {
    s.replace('|', "\\|").replace(['\n', '\r'], " ")
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct Episode {
    pub iface: String,
    pub role: IfaceRole,
    pub start: DateTime<Utc>,
    pub end: DateTime<Utc>,
    pub duration_s: f64,
    pub ticks: u32,
    /// Most frequent bad state during the episode.
    pub state: PathState,
    /// Filled by cross-path analysis.
    pub cause: Option<Verdict>,
    #[serde(default)]
    pub origin: IncidentOrigin,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub band: Option<String>,
    #[serde(default)]
    pub speedtest_active: bool,
    pub context: Vec<String>,
    /// `context` as translatable messages (same order).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub context_msg: Vec<Msg>,
    /// The detective's graded attribution with its evidence (docs/INCIDENT-ATTRIBUTION.md).
    #[serde(default)]
    pub finding: attribution::Finding,
}

impl Episode {
    /// Adds one context line (English text and message).
    pub fn note(&mut self, m: Msg) {
        self.context.push(m.text.clone());
        self.context_msg.push(m);
    }
}

/// True when a non-observer episode occurred during the monitor's own speed test and was short
/// enough (<= 45 s) to represent self-induced saturation rather than an idle unprovoked outage.
pub fn is_load_provoked(ep: &Episode) -> bool {
    ep.origin != IncidentOrigin::Observer && ep.speedtest_active && ep.duration_s <= 45.0
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct BandStats {
    pub band: String,
    pub ticks: u64,
    pub bad_ticks: u64,
    pub availability_pct: f64,
    pub episodes: u32,
    pub micro_drops: u32,
    pub gw_rtt_med: Option<f64>,
    pub net_rtt_med: Option<f64>,
    pub signal_med: Option<f64>,
    pub channels: Vec<u32>,
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct HourRow {
    pub hour: u32,
    pub ticks: u64,
    pub loss_pct: f64,
    pub gw_rtt_med: Option<f64>,
    pub gw_rtt_p95: Option<f64>,
    pub net_rtt_med: Option<f64>,
    pub net_rtt_p95: Option<f64>,
    pub episodes: u32,
    pub micro_drops: u32,
}

#[derive(Debug, Clone, Serialize)]
pub struct Anomaly {
    pub iface: String,
    pub metric: String,
    pub start: DateTime<Utc>,
    pub end: DateTime<Utc>,
    pub peak: f64,
    pub baseline: f64,
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct IfaceReport {
    pub iface: String,
    pub role: Option<IfaceRole>,
    pub ticks: u64,
    /// Ticks without link or address (not counted as outages or in availability).
    pub no_link_ticks: u64,
    pub availability_pct: f64,
    pub episodes: u32,
    pub micro_drops: u32,
    pub down_s: f64,
    pub longest_s: f64,
    pub gw_rtt_med: Option<f64>,
    pub net_rtt_med: Option<f64>,
    pub signal_med: Option<f64>,
    pub busy_med: Option<f64>,
    pub speed_med_mbps: Option<f64>,
    pub speed_peak_med_mbps: Option<f64>,
    pub speed_tests: u32,
    pub roams: u32,
    /// Wi-Fi re-associations to the same AP between two polls.
    pub reconnects: u32,
    /// Ticks with very high RTT but no loss (merged into stall episodes).
    pub stalls: u32,
    /// RTT while a speed test was running (latency under load, bufferbloat).
    pub loaded_gw_rtt_med: Option<f64>,
    pub loaded_net_rtt_med: Option<f64>,
    /// Never had a link but had an address without gateway etc.
    pub had_link: bool,
    pub hours: Vec<HourRow>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub bands: Vec<BandStats>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retry_rate_per_min: Option<f64>,
    #[serde(default)]
    pub tx_failed_total: u64,
    #[serde(default)]
    pub beacon_loss_total: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rx_busy_med: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub peak_net_rtt_p95: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub offpeak_net_rtt_p95: Option<f64>,
    #[serde(default)]
    pub wifi_airtime_congestion_stalls: u32,
    /// Seconds with the host's own traffic above `Opts::self_traffic_bps` outside speed tests.
    #[serde(default)]
    pub self_traffic_s: f64,
    /// Stalls during the host's own traffic (not counted in `stalls`).
    #[serde(default)]
    pub self_traffic_stalls: u32,
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct RouterReport {
    pub samples: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub link_down_mbps: Option<f64>,
    pub uptime_resets: u32,
    pub wan_down_samples: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wan_rx_mbps_med: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wan_rx_mbps_p95: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wan_rx_pps_med: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wan_rx_pps_p95: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wan_tx_pps_med: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wan_tx_pps_p95: Option<f64>,
    #[serde(default)]
    pub bytes_saturated: bool,
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct LanReport {
    pub samples: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub arp_alive_med: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub arp_alive_max: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ping_alive_med: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unique_seen_max: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub peak_arp_alive_med: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub offpeak_arp_alive_med: Option<f64>,
}

/// A translatable sentence: a stable code, its named values (already formatted), and the
/// English text. The web UI translates `code` with `args`; files and the CLI use `text`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[cfg_attr(test, derive(ts_rs::TS), ts(export))]
pub struct Msg {
    pub code: String,
    pub args: BTreeMap<String, String>,
    pub text: String,
}

/// Builds a [`Msg`]: `msg!("code", "English {name} text", name = value, ...)`. Every value is
/// turned into a string once, so the English text and the UI translation show the same digits.
#[macro_export]
macro_rules! msg {
    ($code:literal, $fmt:literal $(, $k:ident = $v:expr)* $(,)?) => {{
        $(let $k: String = ($v).to_string();)*
        $crate::analyze::Msg {
            code: $code.to_string(),
            text: format!($fmt $(, $k = $k)*),
            args: [$((stringify!($k).to_string(), $k.clone())),*].into_iter().collect(),
        }
    }};
}

/// English texts of a list of messages (for the Markdown report and the CLI).
pub fn texts(m: &[Msg]) -> Vec<String> {
    m.iter().map(|x| x.text.clone()).collect()
}

/// How far the measuring host itself can be trusted for this session
/// (docs/HOST-ISOLATION-SCENARIOS.md section 3.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Default)]
#[cfg_attr(test, derive(ts_rs::TS), ts(export))]
#[serde(rename_all = "snake_case")]
pub enum TrustLevel {
    /// No host problem seen: every verdict is about the network.
    #[default]
    Clean,
    /// Short host effects; the incidents they touched are excluded, the rest is valid.
    Caution,
    /// The host distorted the measurement for a large part of the run.
    Polluted,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[cfg_attr(test, derive(ts_rs::TS), ts(export))]
pub struct ObserverTrust {
    pub level: TrustLevel,
    /// Why the level is not `clean` (most serious first).
    pub reasons: Vec<Msg>,
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct Report {
    pub from: Option<DateTime<Utc>>,
    pub to: Option<DateTime<Utc>>,
    pub hours: f64,
    pub ifaces: Vec<IfaceReport>,
    pub episodes: Vec<Episode>,
    pub causes: BTreeMap<String, u32>,
    pub anomalies: Vec<Anomaly>,
    pub patterns: Vec<String>,
    pub monitor_gaps: Vec<String>,
    pub router_log_matches: Vec<String>,
    pub findings: Vec<String>,
    /// `findings` and `patterns` as translatable messages (same order).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub findings_msg: Vec<Msg>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub patterns_msg: Vec<Msg>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub observer_findings_msg: Vec<Msg>,
    /// Network outages merged across interfaces (observer incidents excluded).
    pub incidents: BTreeMap<String, u32>,
    /// Probe interval of the session in seconds (time resolution of the report).
    pub tick_s: f64,
    pub micro_max_s: f64,
    #[serde(default)]
    pub observer_incidents: u32,
    #[serde(default)]
    pub network_incidents: u32,
    #[serde(default)]
    pub load_incidents: u32,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub security_events: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub observer_findings: Vec<String>,
    #[serde(default)]
    pub observer_trust: ObserverTrust,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub router: Option<RouterReport>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lan: Option<LanReport>,
}

/// One router log line (DOCSIS event log), already converted to UTC.
#[derive(Debug, Clone)]
pub struct RouterLine {
    pub ts: DateTime<Utc>,
    pub priority: String,
    pub text: String,
}

/// Parse a cable-modem DOCSIS event log (copied from the router web UI): lines containing
/// "MM/DD/YYYY HH:MM:SS", tab or space separated priority and text. Router time is local.
pub fn parse_router_log(text: &str) -> Vec<RouterLine> {
    let mut out = Vec::new();
    for line in text.lines() {
        let Some(pos) = find_date(line) else { continue };
        let dt_s = &line[pos..pos + 19];
        let Ok(naive) = chrono::NaiveDateTime::parse_from_str(dt_s, "%m/%d/%Y %H:%M:%S") else { continue };
        let Some(local) = Local.from_local_datetime(&naive).earliest() else { continue };
        let rest = line[pos + 19..].trim();
        let prio = ["Critical", "Error", "Warning", "Notice", "Information"]
            .iter()
            .find(|p| rest.contains(*p))
            .map(|s| s.to_string())
            .unwrap_or_default();
        // Text follows the priority word when present ("<type> <priority> <text>;CM-MAC=...").
        let after = rest.find(prio.as_str()).filter(|_| !prio.is_empty()).map_or(rest, |i| &rest[i + prio.len()..]);
        let text = after.split(';').next().unwrap_or(after).trim().to_string();
        out.push(RouterLine { ts: local.with_timezone(&Utc), priority: prio, text });
    }
    out
}

fn find_date(line: &str) -> Option<usize> {
    let b = line.as_bytes();
    if b.len() < 19 {
        return None;
    }
    (0..=b.len() - 19).find(|&i| {
        let s = &b[i..i + 19];
        s[2] == b'/' && s[5] == b'/' && s[10] == b' ' && s[13] == b':' && s[16] == b':'
            && [0, 1, 3, 4, 6, 7, 8, 9, 11, 12, 14, 15, 17, 18].iter().all(|&k| s[k].is_ascii_digit())
    })
}
