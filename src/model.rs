//! Shared record types. This is the on-disk contract (JSON Lines) and the
//! in-memory contract between modules. Change only with a SCHEMA_VERSION bump.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::net::Ipv4Addr;

pub const SCHEMA_VERSION: u32 = 1;

/// Wi-Fi frequency band label for a centre frequency in MHz.
pub fn wifi_band(freq_mhz: u32) -> &'static str {
    match freq_mhz {
        2400..=2500 => "2.4 GHz",
        4900..=5924 => "5 GHz",
        5925..=7200 => "6 GHz",
        _ => "other",
    }
}

/// Identifying network fingerprint used to match sessions recorded on the same network.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
#[cfg_attr(test, derive(ts_rs::TS), ts(export, optional_fields))]
pub struct NetworkFingerprint {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gateway_ip: Option<Ipv4Addr>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gateway_mac: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subnet: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    #[cfg_attr(test, ts(optional = nullable))]
    pub bssids: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub isp_hop: Option<Ipv4Addr>,
}

/// Whether an outage episode was caused by the network or by the measuring device itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[cfg_attr(test, derive(ts_rs::TS), ts(export))]
#[serde(rename_all = "snake_case")]
pub enum IncidentOrigin {
    Network,
    Observer,
    #[default]
    Unknown,
}

/// Health metrics of the measuring host itself (recorded on the `host` stream).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
#[cfg_attr(test, derive(ts_rs::TS), ts(export, optional_fields))]
pub struct HostSample {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cpu_pct: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub load1: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mem_used_pct: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mem_avail_mb: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub disk_free_bytes: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub temp_c: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rpi_throttled: Option<u32>,
    #[serde(default, skip_serializing_if = "is_false")]
    #[cfg_attr(test, ts(optional = nullable))]
    pub throttled: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub clock_synced: Option<bool>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    #[cfg_attr(test, ts(optional = nullable))]
    pub wifi_power_save: BTreeMap<String, bool>,
}

/// Read-only router telemetry collected via UPnP IGD (optional, disabled by default).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
#[cfg_attr(test, derive(ts_rs::TS), ts(export, optional_fields))]
pub struct RouterSample {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wan_access: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub phy_status: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wan_status: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uptime_s: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub link_down_mbps: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub link_up_mbps: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wan_rx_mbps: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wan_tx_mbps: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wan_rx_pps: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wan_tx_pps: Option<f64>,
    /// True when the router's cumulative byte counter is clamped at i32/u32 MAX.
    #[serde(default, skip_serializing_if = "is_false")]
    #[cfg_attr(test, ts(optional = nullable))]
    pub bytes_saturated: bool,
}

impl RouterSample {
    /// True when the router reports that the WAN is not up.
    ///
    /// UPnP IGD values (compared case-insensitively):
    /// - `ConnectionStatus` (WANIPConnection): Unconfigured, Connecting, Connected,
    ///   PendingDisconnect, Disconnecting, Disconnected. Only `Connected` is up.
    /// - `PhysicalLinkStatus` (WANCommonInterfaceConfig): Up, Down, Initializing, Unavailable.
    ///   Only `Up` is up.
    ///
    /// A missing value is not "down": routers that do not report it stay silent.
    pub fn wan_down(&self) -> bool {
        self.wan_status.as_deref().is_some_and(|s| !s.eq_ignore_ascii_case("Connected"))
            || self.phy_status.as_deref().is_some_and(|s| !s.eq_ignore_ascii_case("Up"))
    }
}

/// Active device count on the local subnet (counts only; no addresses or MACs).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[cfg_attr(test, derive(ts_rs::TS), ts(export, optional_fields))]
pub struct LanSample {
    pub iface: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prefix_len: Option<u8>,
    pub probed: u32,
    pub ping_alive: u32,
    pub arp_alive: u32,
    pub unique_seen: u32,
}

/// Role of a monitored interface. Free-form name lives in `IfaceId`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(test, derive(ts_rs::TS), ts(export))]
#[serde(rename_all = "snake_case")]
pub enum IfaceRole {
    Wifi,
    Ethernet,
    Other,
}

/// Result of one active probe (ICMP echo, TCP connect, DNS query).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
#[cfg_attr(test, derive(ts_rs::TS), ts(export, optional_fields))]
pub struct ProbeResult {
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rtt_ms: Option<f64>,
    /// Short machine-readable error code: "timeout", "unreachable",
    /// "no_route", "bind_failed", "late_reply", "send_failed", "refused", ...
    #[serde(skip_serializing_if = "Option::is_none")]
    pub err: Option<String>,
}

impl ProbeResult {
    pub fn ok(rtt_ms: f64) -> Self {
        Self { ok: true, rtt_ms: Some(rtt_ms), err: None }
    }
    pub fn fail(err: impl Into<String>) -> Self {
        Self { ok: false, rtt_ms: None, err: Some(err.into()) }
    }
}

/// Aggregate over several internet targets probed in the same second.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
#[cfg_attr(test, derive(ts_rs::TS), ts(export, optional_fields))]
pub struct MultiResult {
    pub ok: u8,
    pub of: u8,
    /// Median RTT of the successful probes.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rtt_ms: Option<f64>,
}

/// Layer-1/3 state of an interface, read from the kernel.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
#[cfg_attr(test, derive(ts_rs::TS), ts(export, optional_fields))]
pub struct LinkState {
    /// Interface exists in the kernel.
    pub present: bool,
    /// IFF_UP and operstate "up".
    pub up: bool,
    /// Carrier (cable plugged / Wi-Fi associated).
    pub carrier: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ipv4: Option<Ipv4Addr>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prefix_len: Option<u8>,
    /// Default gateway reachable through this interface, if any.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gateway: Option<Ipv4Addr>,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
}

/// Classified state of one interface path at one moment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(test, derive(ts_rs::TS), ts(export))]
#[serde(rename_all = "snake_case")]
pub enum PathState {
    /// Everything answers within thresholds.
    Ok,
    /// Answers, but loss or latency above thresholds.
    Degraded,
    /// Interface missing, down, or no carrier / not associated.
    LinkDown,
    /// Link up but no IPv4 address or no gateway.
    NoIp,
    /// Gateway (router) does not answer.
    LanDown,
    /// Router answers, ISP first hop does not.
    IspDown,
    /// ISP hop answers (or unknown), no internet target answers.
    WanDown,
    /// Internet answers, DNS does not.
    DnsDown,
    /// Not enough data yet (startup).
    Unknown,
}

impl PathState {
    /// Name as written in JSON (snake_case), without serialising.
    pub fn as_str(self) -> &'static str {
        match self {
            PathState::Ok => "ok",
            PathState::Degraded => "degraded",
            PathState::LinkDown => "link_down",
            PathState::NoIp => "no_ip",
            PathState::LanDown => "lan_down",
            PathState::IspDown => "isp_down",
            PathState::WanDown => "wan_down",
            PathState::DnsDown => "dns_down",
            PathState::Unknown => "unknown",
        }
    }
}

impl Verdict {
    /// Name as written in JSON (snake_case), without serialising.
    pub fn as_str(self) -> &'static str {
        match self {
            Verdict::AllOk => "all_ok",
            Verdict::WifiProblem => "wifi_problem",
            Verdict::WiredProblem => "wired_problem",
            Verdict::RouterProblem => "router_problem",
            Verdict::LineProblem => "line_problem",
            Verdict::InternetProblem => "internet_problem",
            Verdict::Dns => "dns",
            Verdict::SinglePath => "single_path",
            Verdict::Unknown => "unknown",
        }
    }
}

/// Cross-interface verdict for one moment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(test, derive(ts_rs::TS), ts(export))]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    AllOk,
    /// Problem only on the Wi-Fi path, wired path fine.
    WifiProblem,
    /// Problem only on a wired path.
    WiredProblem,
    /// All paths fail at the router.
    RouterProblem,
    /// All paths fail beyond the router (cable line / ISP).
    LineProblem,
    /// All paths fail beyond the ISP hop.
    InternetProblem,
    Dns,
    /// Only one path monitored, cannot compare.
    SinglePath,
    Unknown,
}

/// One line per interface per probe tick.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(test, derive(ts_rs::TS), ts(export, optional_fields))]
pub struct Sample {
    pub iface: String,
    pub role: IfaceRole,
    pub link: LinkState,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gw: Option<ProbeResult>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub isp: Option<ProbeResult>,
    pub net: MultiResult,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tcp: Option<MultiResult>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dns: Option<ProbeResult>,
    /// Bytes since previous sample (passive load indicator).
    pub rx_delta: u64,
    pub tx_delta: u64,
    pub state: PathState,
    /// A speed test was running on ANY interface during this tick.
    pub speedtest_active: bool,
    /// The tick started late or was skipped because the previous one overran.
    #[serde(default, skip_serializing_if = "is_false")]
    #[cfg_attr(test, ts(optional = nullable))]
    pub overrun: bool,
    /// The monitor's own Wi-Fi scan (off-channel) was running during this tick.
    #[serde(default, skip_serializing_if = "is_false")]
    #[cfg_attr(test, ts(optional = nullable))]
    pub scan_active: bool,
    /// Wall-clock time of the tick start (when the probes were sent). The envelope `ts` is the
    /// time the record was written, which is later by up to the probe timeout.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub t: Option<chrono::DateTime<chrono::Utc>>,
    /// Operating Wi-Fi frequency (MHz) during this tick, when known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub freq_mhz: Option<u32>,
    /// Packets (rx + tx) since the previous sample: many small packets load Wi-Fi airtime even
    /// at a low byte rate (torrent/DHT, sync clients).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pkt_delta: Option<u64>,
}

fn is_false(b: &bool) -> bool {
    !*b
}

/// Wi-Fi station statistics (nl80211 GET_STATION + GET_INTERFACE).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
#[cfg_attr(test, derive(ts_rs::TS), ts(export, optional_fields))]
pub struct WifiStation {
    pub iface: String,
    pub connected: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bssid: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ssid: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub freq_mhz: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub channel: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub width_mhz: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signal_dbm: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signal_avg_dbm: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tx_bitrate_mbps: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rx_bitrate_mbps: Option<f64>,
    /// Counters are cumulative as reported by the driver.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tx_retries: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tx_failed: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub beacon_loss: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub connected_s: Option<u32>,
    /// Whether Wi-Fi client power-save is currently enabled on the interface.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub power_save: Option<bool>,
}

/// Channel survey for one frequency (nl80211 GET_SURVEY). Times are cumulative ms.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
#[cfg_attr(test, derive(ts_rs::TS), ts(export, optional_fields))]
pub struct SurveyEntry {
    pub freq_mhz: u32,
    /// True for the channel the interface currently uses.
    pub in_use: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub noise_dbm: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub active_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub busy_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rx_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tx_ms: Option<u64>,
}

/// Derived utilisation over the interval between two surveys of the in-use channel.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
#[cfg_attr(test, derive(ts_rs::TS), ts(export, optional_fields))]
pub struct ChannelLoad {
    pub iface: String,
    pub freq_mhz: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub noise_dbm: Option<i32>,
    /// Percent of time the medium was busy (any source).
    pub busy_pct: f64,
    /// Percent of time receiving frames (all, not only ours).
    pub rx_pct: f64,
    /// Percent of time we transmitted.
    pub tx_pct: f64,
    pub interval_ms: u64,
}

/// One neighbouring network from a scan.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
#[cfg_attr(test, derive(ts_rs::TS), ts(export, optional_fields))]
pub struct ScanBss {
    pub bssid: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ssid: Option<String>,
    pub freq_mhz: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub channel: Option<u32>,
    /// Advertised channel width in MHz parsed from beacon/probe-response IEs (20/40/80/160).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub width_mhz: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signal_dbm: Option<f64>,
    /// Milliseconds since the BSS was last seen, as reported by the kernel.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub seen_ms_ago: Option<u32>,
    #[serde(default, skip_serializing_if = "is_false")]
    #[cfg_attr(test, ts(optional = nullable))]
    pub associated: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub security: Option<String>,
    #[serde(default, skip_serializing_if = "is_false")]
    #[cfg_attr(test, ts(optional = nullable))]
    pub wps: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pmf: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
#[cfg_attr(test, derive(ts_rs::TS), ts(export))]
pub struct ScanReport {
    pub iface: String,
    pub bss: Vec<ScanBss>,
    /// True when results come from a scan we triggered, false when only cached.
    pub fresh: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
#[cfg_attr(test, derive(ts_rs::TS), ts(export, optional_fields))]
pub struct SpeedResult {
    pub iface: String,
    pub url: String,
    pub bytes: u64,
    pub secs: f64,
    /// Throughput after the TCP warm-up (see `warmup_excluded_s`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mbps: Option<f64>,
    /// Throughput over the whole body, warm-up included.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mbps_all: Option<f64>,
    /// Seconds at the start of the body not counted in `mbps`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub warmup_excluded_s: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub err: Option<String>,
}

/// Kind of an observer (host) alert. The JSON strings are the same as in old session files.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(test, derive(ts_rs::TS), ts(export))]
#[serde(rename_all = "snake_case")]
pub enum HostAlertKind {
    HighCpu,
    LowMemory,
    DriverReset,
    WifiPowerSave,
    Undervoltage,
    ThermalThrottle,
    /// Any alert name this version does not know (for example from a newer version).
    #[serde(other)]
    Other,
}

impl HostAlertKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::HighCpu => "high_cpu",
            Self::LowMemory => "low_memory",
            Self::DriverReset => "driver_reset",
            Self::WifiPowerSave => "wifi_power_save",
            Self::Undervoltage => "undervoltage",
            Self::ThermalThrottle => "thermal_throttle",
            Self::Other => "other",
        }
    }
}

/// The interface of a host alert. Uses the typed `iface`. For old records without it,
/// this is the one place that reads the `"<iface>: ..."` prefix of `detail`.
pub fn host_alert_iface<'a>(iface: Option<&'a str>, detail: &'a str) -> Option<&'a str> {
    iface.or_else(|| {
        let end = detail.find([':', ' '])?;
        (end > 0).then(|| &detail[..end])
    })
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(test, derive(ts_rs::TS), ts(export, optional_fields))]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum EventKind {
    /// Monitor started. `gap_s` = time since last heartbeat of a previous run in the same data dir.
    Start { version: String, #[serde(skip_serializing_if = "Option::is_none")] gap_s: Option<f64>, boot_id: String, #[serde(skip_serializing_if = "Option::is_none")] prev_boot_id: Option<String> },
    Stop { reason: String },
    StateChange { iface: String, from: PathState, to: PathState, prev_duration_s: f64 },
    VerdictChange { from: Verdict, to: Verdict, prev_duration_s: f64 },
    LinkChange { iface: String, from: LinkState, to: LinkState },
    Roam { iface: String, #[serde(skip_serializing_if = "Option::is_none")] from_bssid: Option<String>, #[serde(skip_serializing_if = "Option::is_none")] to_bssid: Option<String> },
    ChannelChange { iface: String, #[serde(skip_serializing_if = "Option::is_none")] from_mhz: Option<u32>, #[serde(skip_serializing_if = "Option::is_none")] to_mhz: Option<u32> },
    ClockJump { wall_delta_s: f64, mono_delta_s: f64 },
    SuspendGap { secs: f64 },
    DroppedRecords { count: u64 },
    TaskRestart { task: String, error: String },
    DiskPressure { free_bytes: u64, mode: String },
    Note { text: String },
    /// Wi-Fi re-associated (connection time went back) without a BSSID change.
    Reconnect { iface: String, #[serde(skip_serializing_if = "Option::is_none")] bssid: Option<String> },
    /// Kernel nl80211 MLME disconnect/deauth/disassoc event with reason code.
    WifiDisconnect {
        iface: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        bssid: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        reason_code: Option<u16>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        reason: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        by_ap: Option<bool>,
        #[serde(default, skip_serializing_if = "is_false")]
        #[cfg_attr(test, ts(optional = nullable))]
        timed_out: bool,
    },
    /// Observer (measuring host) health alert (throttling, high CPU, low RAM, driver reset, power-save).
    HostAlert {
        alert: HostAlertKind,
        /// Free text for people. Do not parse it: use `iface`.
        detail: String,
        /// Interface the alert is about. Old session files have none: use `host_alert_iface`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        iface: Option<String>,
    },
    /// Passive security anomaly detected on the local network.
    Security {
        detector: String,
        severity: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        iface: Option<String>,
        detail: String,
    },
    /// Updated network fingerprint discovered during a session.
    NetworkInfo { fingerprint: NetworkFingerprint },
    /// An event kind written by a newer version. Readers keep the line instead of dropping it.
    #[serde(other)]
    Unknown,
}

/// Everything written to disk is a Record inside an Envelope.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(test, derive(ts_rs::TS), ts(export))]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Record {
    Sample(Sample),
    Event(EventKind),
    Wifi(WifiStation),
    Survey { iface: String, entries: Vec<SurveyEntry> },
    ChannelLoad(ChannelLoad),
    Scan(ScanReport),
    Speed(SpeedResult),
    Heartbeat { uptime_s: f64 },
    Host(HostSample),
    Router(RouterSample),
    Lan(LanSample),
    /// A record type written by a newer version (forward compatibility; never written).
    #[serde(other)]
    Unknown,
}

impl Record {
    /// Which file stream this record belongs to.
    pub fn stream(&self) -> Stream {
        match self {
            Record::Sample(_) => Stream::Samples,
            Record::Event(_) => Stream::Events,
            Record::Wifi(_) | Record::Survey { .. } | Record::ChannelLoad(_) | Record::Scan(_) => Stream::Wifi,
            Record::Speed(_) => Stream::Speed,
            Record::Host(_) | Record::Router(_) | Record::Lan(_) => Stream::Host,
            Record::Heartbeat { .. } | Record::Unknown => Stream::Events,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Stream {
    Samples,
    Events,
    Wifi,
    Speed,
    Host,
}

impl Stream {
    pub const ALL: [Stream; 5] = [Stream::Samples, Stream::Events, Stream::Wifi, Stream::Speed, Stream::Host];
    pub fn name(self) -> &'static str {
        match self {
            Stream::Samples => "samples",
            Stream::Events => "events",
            Stream::Wifi => "wifi",
            Stream::Speed => "speed",
            Stream::Host => "host",
        }
    }
}

/// On-disk line. `seq` is assigned by the writer and is gap-free per data dir
/// across restarts; a gap in seq means lost records.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(test, derive(ts_rs::TS), ts(export))]
pub struct Envelope {
    pub v: u32,
    pub run: String,
    pub seq: u64,
    /// UTC, RFC 3339 with milliseconds.
    pub ts: chrono::DateTime<chrono::Utc>,
    /// CLOCK_MONOTONIC nanoseconds at creation (for ordering/intervals within a boot).
    pub mono_ns: u64,
    #[serde(flatten)]
    pub rec: Record,
}

/// Session metadata written once to meta.json of a session directory.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SessionMeta {
    pub v: u32,
    pub session: String,
    pub started: chrono::DateTime<chrono::Utc>,
    pub host: String,
    pub version: String,
    /// Observation point id from the site file, e.g. "B1/F2/R3". Optional.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub point: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    /// Free-text note about the measurement (window open, furniture moved). Optional.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
    pub config: serde_json::Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tz_offset_s: Option<i32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub clock_synced: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network: Option<NetworkFingerprint>,
}

/// CLOCK_MONOTONIC in ns.
pub fn mono_ns() -> u64 {
    clock_ns(nix::time::ClockId::CLOCK_MONOTONIC)
}

/// CLOCK_BOOTTIME in ns (includes suspend) on Linux; MONOTONIC elsewhere.
pub fn boot_ns() -> u64 {
    #[cfg(target_os = "linux")]
    {
        clock_ns(nix::time::ClockId::CLOCK_BOOTTIME)
    }
    #[cfg(not(target_os = "linux"))]
    {
        clock_ns(nix::time::ClockId::CLOCK_MONOTONIC)
    }
}

fn clock_ns(clock: nix::time::ClockId) -> u64 {
    match nix::time::clock_gettime(clock) {
        Ok(ts) => (ts.tv_sec().max(0) as u64).saturating_mul(1_000_000_000).saturating_add(ts.tv_nsec().max(0) as u64),
        Err(_) => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn old_host_alert_json_still_parses() {
        let line = r#"{"kind":"host_alert","alert":"driver_reset","detail":"wlo1: kernel ifindex changed 2 -> 5"}"#;
        let ev: EventKind = serde_json::from_str(line).unwrap();
        let EventKind::HostAlert { alert, detail, iface } = ev else { panic!("wrong kind") };
        assert_eq!(alert, HostAlertKind::DriverReset);
        assert_eq!(iface, None);
        assert_eq!(host_alert_iface(iface.as_deref(), &detail), Some("wlo1"));
        let unknown: EventKind = serde_json::from_str(r#"{"kind":"host_alert","alert":"future_thing","detail":"x"}"#).unwrap();
        assert!(matches!(unknown, EventKind::HostAlert { alert: HostAlertKind::Other, .. }));
        let new = EventKind::HostAlert { alert: HostAlertKind::DriverReset, detail: "d".into(), iface: Some("wlo1".into()) };
        let json = serde_json::to_string(&new).unwrap();
        assert!(json.contains(r#""alert":"driver_reset""#) && json.contains(r#""iface":"wlo1""#));
        let no_iface = serde_json::to_string(&EventKind::HostAlert { alert: HostAlertKind::HighCpu, detail: "d".into(), iface: None }).unwrap();
        assert!(!no_iface.contains("iface"));
    }

    #[test]
    fn wan_down_matches_upnp_values_case_insensitively() {
        let mk = |wan: Option<&str>, phy: Option<&str>| RouterSample {
            wan_status: wan.map(Into::into),
            phy_status: phy.map(Into::into),
            ..Default::default()
        };
        assert!(!mk(None, None).wan_down());
        assert!(!mk(Some("Connected"), Some("Up")).wan_down());
        assert!(!mk(Some("connected"), Some("UP")).wan_down());
        assert!(mk(Some("Disconnected"), Some("Up")).wan_down());
        assert!(mk(Some("Connecting"), None).wan_down());
        assert!(mk(Some("Connected"), Some("Down")).wan_down());
        assert!(mk(None, Some("Initializing")).wan_down());
        assert!(mk(None, Some("Unavailable")).wan_down());
    }

    #[test]
    fn as_str_matches_serde_names() {
        use PathState::*;
        for p in [Ok, Degraded, LinkDown, NoIp, LanDown, IspDown, WanDown, DnsDown, PathState::Unknown] {
            assert_eq!(serde_json::to_value(p).unwrap(), p.as_str());
        }
        use Verdict::*;
        for v in [AllOk, WifiProblem, WiredProblem, RouterProblem, LineProblem, InternetProblem, Dns, SinglePath, Verdict::Unknown] {
            assert_eq!(serde_json::to_value(v).unwrap(), v.as_str());
        }
    }

    #[test]
    fn envelope_roundtrip_is_flat_and_tagged() {
        let e = Envelope {
            v: SCHEMA_VERSION,
            run: "r1".into(),
            seq: 7,
            ts: chrono::Utc::now(),
            mono_ns: 1,
            rec: Record::Event(EventKind::Note { text: "hi".into() }),
        };
        let s = serde_json::to_string(&e).unwrap();
        assert!(s.contains("\"type\":\"event\""));
        assert!(s.contains("\"kind\":\"note\""));
        let back: Envelope = serde_json::from_str(&s).unwrap();
        assert_eq!(back, e);
    }

    #[test]
    fn unknown_kinds_from_newer_versions_still_parse() {
        let s = r#"{"v":1,"run":"r","seq":1,"ts":"2026-01-01T00:00:00Z","mono_ns":0,"type":"event","kind":"from_the_future","x":1}"#;
        let e: Envelope = serde_json::from_str(s).unwrap();
        assert_eq!(e.rec, Record::Event(EventKind::Unknown));
        let s = r#"{"v":1,"run":"r","seq":2,"ts":"2026-01-01T00:00:00Z","mono_ns":0,"type":"future_metric","cpu":3}"#;
        let e: Envelope = serde_json::from_str(s).unwrap();
        assert_eq!(e.rec, Record::Unknown);
    }

    #[test]
    fn host_and_new_events_roundtrip() {
        let mut ps = BTreeMap::new();
        ps.insert("wlo1".into(), false);
        let h = HostSample {
            cpu_pct: Some(12.5),
            load1: Some(0.25),
            mem_used_pct: Some(40.0),
            mem_avail_mb: Some(2048),
            disk_free_bytes: Some(10_000_000),
            temp_c: Some(45.2),
            rpi_throttled: Some(0),
            throttled: false,
            clock_synced: Some(true),
            wifi_power_save: ps,
        };
        let rec = Record::Host(h.clone());
        assert_eq!(rec.stream(), Stream::Host);
        let env = Envelope {
            v: SCHEMA_VERSION,
            run: "r1".into(),
            seq: 1,
            ts: chrono::Utc::now(),
            mono_ns: 10,
            rec,
        };
        let s = serde_json::to_string(&env).unwrap();
        assert!(s.contains("\"type\":\"host\""));
        let back: Envelope = serde_json::from_str(&s).unwrap();
        assert_eq!(back, env);

        for ev in [
            EventKind::WifiDisconnect {
                iface: "wlo1".into(),
                bssid: Some("02:00:00:00:00:01".into()),
                reason_code: Some(4),
                reason: Some("inactivity".into()),
                by_ap: Some(true),
                timed_out: false,
            },
            EventKind::HostAlert { alert: HostAlertKind::Undervoltage, detail: "0x1".into(), iface: None },
            EventKind::Security {
                detector: "gateway_mac_change".into(),
                severity: "high".into(),
                iface: Some("wlo1".into()),
                detail: "mac changed".into(),
            },
            EventKind::NetworkInfo {
                fingerprint: NetworkFingerprint {
                    gateway_ip: Some(Ipv4Addr::new(192, 168, 0, 1)),
                    gateway_mac: Some("02:00:00:00:00:04".into()),
                    subnet: Some("192.168.0.0/24".into()),
                    bssids: vec!["02:00:00:00:00:05".into()],
                    isp_hop: Some(Ipv4Addr::new(198, 51, 100, 1)),
                },
            },
        ] {
            let e = Envelope {
                v: SCHEMA_VERSION,
                run: "r".into(),
                seq: 2,
                ts: chrono::Utc::now(),
                mono_ns: 0,
                rec: Record::Event(ev),
            };
            let json = serde_json::to_string(&e).unwrap();
            assert_eq!(serde_json::from_str::<Envelope>(&json).unwrap(), e);
        }
        assert_eq!(wifi_band(2437), "2.4 GHz");
        assert_eq!(wifi_band(5180), "5 GHz");
        assert_eq!(wifi_band(5955), "6 GHz");
        assert_eq!(wifi_band(900), "other");
    }

    #[test]
    fn router_sample_roundtrip_on_host_stream() {
        let r = RouterSample {
            source: Some("upnp_igd".into()),
            model: Some("Example GW".into()),
            wan_access: Some("Ethernet".into()),
            phy_status: Some("Up".into()),
            wan_status: Some("Connected".into()),
            last_error: None,
            uptime_s: Some(3600),
            link_down_mbps: Some(100.0),
            link_up_mbps: Some(100.0),
            wan_rx_mbps: None,
            wan_tx_mbps: None,
            wan_rx_pps: Some(120.5),
            wan_tx_pps: Some(40.2),
            bytes_saturated: true,
        };
        let rec = Record::Router(r);
        assert_eq!(rec.stream(), Stream::Host);
        let env = Envelope {
            v: SCHEMA_VERSION,
            run: "r1".into(),
            seq: 9,
            ts: chrono::Utc::now(),
            mono_ns: 10,
            rec,
        };
        let s = serde_json::to_string(&env).unwrap();
        assert!(s.contains("\"type\":\"router\""));
        assert_eq!(serde_json::from_str::<Envelope>(&s).unwrap(), env);
    }

    #[test]
    fn lan_sample_roundtrip_on_host_stream() {
        let l = LanSample {
            iface: "eth0".into(),
            prefix_len: Some(24),
            probed: 253,
            ping_alive: 5,
            arp_alive: 11,
            unique_seen: 14,
        };
        let rec = Record::Lan(l);
        assert_eq!(rec.stream(), Stream::Host);
        let env = Envelope {
            v: SCHEMA_VERSION,
            run: "r1".into(),
            seq: 10,
            ts: chrono::Utc::now(),
            mono_ns: 20,
            rec,
        };
        let s = serde_json::to_string(&env).unwrap();
        assert!(s.contains("\"type\":\"lan\""));
        assert_eq!(serde_json::from_str::<Envelope>(&s).unwrap(), env);
    }
}
