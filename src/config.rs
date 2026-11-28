//! Configuration (TOML). Every field has a default so an empty file works.

use crate::model::IfaceRole;
use serde::{Deserialize, Serialize};
use std::net::{Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    /// Measurement profile: "light" (5 s, for small boards), "standard" (1 s), "detailed" (0.5 s,
    /// Wi-Fi statistics every second). Values set explicitly in [intervals] override the profile.
    pub profile: Profile,
    /// Root for all sessions. Each `run` creates <data_dir>/<session>/.
    pub data_dir: PathBuf,
    pub interfaces: Vec<IfaceConfig>,
    pub targets: Targets,
    pub intervals: Intervals,
    pub classify: Classify,
    pub speed: Speed,
    pub web: Web,
    pub site: SiteRef,
    pub storage: Storage,
    pub router: Router,
    pub alerts: Alerts,
    pub advisor: Advisor,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum Profile {
    Light,
    #[default]
    Standard,
    Detailed,
}

impl Profile {
    pub fn intervals(self) -> Intervals {
        let d = Intervals::default();
        match self {
            Profile::Standard => d,
            Profile::Light => Intervals { probe_ms: 5000, probe_timeout_ms: 2000, dns_s: 30, tcp_s: 30, wifi_s: 30, survey_s: 30, scan_s: 1800, host_s: 30, ..d },
            Profile::Detailed => Intervals { probe_ms: 500, probe_timeout_ms: 450, dns_s: 5, tcp_s: 2, wifi_s: 1, survey_s: 2, scan_s: 600, host_s: 5, ..d },
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IfaceConfig {
    pub name: String,
    /// Detected from sysfs when omitted.
    #[serde(default)]
    pub role: Option<IfaceRole>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Targets {
    /// Router. None = take the default gateway of each interface.
    pub gateway: Option<Ipv4Addr>,
    /// First hop inside the ISP. "auto" discovery when None and `isp_hop_auto`.
    pub isp_hop: Option<Ipv4Addr>,
    pub isp_hop_auto: bool,
    /// ICMP targets on the internet. Internet is "down" only when ALL fail.
    pub internet: Vec<Ipv4Addr>,
    /// TCP connect targets (ICMP may be filtered or rate-limited).
    pub tcp: Vec<SocketAddr>,
    /// DNS servers to query. Empty = the system resolvers from /etc/resolv.conf
    /// (skipping 127.0.0.53 stub, which is resolved via resolvectl data when possible).
    pub dns_servers: Vec<Ipv4Addr>,
    pub dns_name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Intervals {
    pub probe_ms: u64,
    pub probe_timeout_ms: u64,
    pub dns_s: u64,
    /// TCP connect probes (every N seconds; they open real connections).
    pub tcp_s: u64,
    pub wifi_s: u64,
    pub survey_s: u64,
    /// Active scan of neighbouring networks. 0 = off. Needs CAP_NET_ADMIN to trigger;
    /// without it only cached results are read.
    pub scan_s: u64,
    pub heartbeat_s: u64,
    pub isp_rediscover_s: u64,
    /// Host health sampling interval in seconds (0 = off).
    pub host_s: u64,
    /// Active LAN device count interval in seconds (0 = off; minimum 60 when enabled).
    pub lan_s: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Classify {
    /// Time in seconds a new state must hold before a state change is recorded (default 3.0).
    /// Independent of the probe interval: the tick count is derived from it.
    /// Precedence: `debounce_s` if set, else the deprecated `debounce` (ticks), else 3.0 s.
    pub debounce_s: Option<f64>,
    /// Time in seconds of the loss/latency window for Degraded (default 30.0).
    /// Precedence: `window_s` if set, else the deprecated `window` (ticks), else 30.0 s.
    pub window_s: Option<f64>,
    /// DEPRECATED. Debounce in probe ticks. Used only when `debounce_s` is not set.
    pub debounce: Option<u32>,
    /// DEPRECATED. Window in probe ticks. Used only when `window_s` is not set.
    pub window: Option<u32>,
    /// Effective debounce in ticks. Computed by `resolve`; not a config key.
    #[serde(skip)]
    pub debounce_ticks: u32,
    /// Effective window in ticks. Computed by `resolve`; not a config key.
    #[serde(skip)]
    pub window_ticks: u32,
    pub degraded_loss_pct: f64,
    pub degraded_gw_rtt_ms: f64,
    pub degraded_net_rtt_ms: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Speed {
    pub enabled: bool,
    /// Plain http:// URLs of large files. Tried in order until one works.
    pub urls: Vec<String>,
    /// Upper bound of bytes per test.
    pub max_bytes: u64,
    /// Whole request limit (DNS, connect, headers, body).
    pub timeout_s: u64,
    /// Measure the body for this long, then stop (time-based test).
    pub duration_s: u64,
    /// The first part of the body is TCP warm-up (slow start) and is not counted.
    pub warmup_ms: u64,
    pub interval_min: u64,
    /// Peak window (local time, "HH:MM"), uses `peak_interval_min`. End may be before start (wraps midnight).
    pub peak_start: String,
    pub peak_end: String,
    pub peak_interval_min: u64,
    /// Delay of the first test after start.
    pub first_after_s: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Web {
    pub enabled: bool,
    pub listen: SocketAddr,
    /// Optional access token. When set, every request needs `?token=<token>` once (it is
    /// then kept in a cookie) or `Authorization: Bearer <token>`. Use it when listening on the LAN.
    pub token: Option<String>,
    /// Who may read the UI and the GET API when a token is set: `token` (default, only
    /// token holders) or `open` (anyone on the network may view; changes still need the token).
    pub view: ViewAccess,
}

/// Read access to the web UI when `[web] token` is set.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum ViewAccess {
    #[default]
    Token,
    Open,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default, deny_unknown_fields)]
pub struct SiteRef {
    /// Path to a site layout TOML (see site.rs). Optional.
    pub file: Option<PathBuf>,
    /// Observation point for this session, e.g. "B1/F2/R3".
    pub point: Option<String>,
    pub label: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Storage {
    /// Below this many free bytes: stop writing samples, keep events.
    pub min_free_bytes: u64,
    /// Below this: write nothing but log to stderr/journal.
    pub critical_free_bytes: u64,
    /// fsync interval for open files.
    pub fsync_s: u64,
    /// Bounded channel size between producers and the writer.
    pub queue: usize,
    /// Compress files of previous days.
    pub compress_old: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Router {
    /// Poll optional read-only router telemetry (disabled by default).
    pub enabled: bool,
    /// Use unauthenticated UPnP IGD SOAP queries against the default gateway.
    pub upnp: bool,
    /// Optional explicit IGD XML URL, e.g. "http://192.168.0.1:49152/IGDdevicedesc.xml".
    /// When omitted, SSDP discovery on the gateway is used.
    pub upnp_url: Option<String>,
    /// Polling interval in seconds.
    pub interval_s: u64,
    /// Optional NIST NVD API key for higher rate limits on manual CVE lookups.
    pub nvd_api_key: Option<String>,
}

impl Default for Router {
    fn default() -> Self {
        Self { enabled: false, upnp: true, upnp_url: None, interval_s: 15, nvd_api_key: None }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Alerts {
    /// Send webhook / ntfy alerts on sustained outages and security events.
    pub enabled: bool,
    /// HTTP/HTTPS endpoint URL (e.g. "https://ntfy.example.com/linkwatch").
    pub webhook_url: Option<String>,
    /// Optional Bearer token for Authorization header.
    pub bearer_token: Option<String>,
    /// Seconds an outage verdict must persist before firing an alert.
    pub min_outage_s: u64,
    /// Emit immediate alerts on passive security detector events.
    pub security_events: bool,
    /// Minimum seconds between repeated alerts with the same key.
    pub cooldown_s: u64,
}

/// Readiness advisor (docs/ADVISOR.md).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Advisor {
    /// Risk codes the user accepts. An accepted risk is never reported (`linkwatch check`, run events).
    /// Blocking items cannot be accepted. Codes: see `check::readiness::CODES`.
    pub accept: Vec<String>,
}

impl Default for Alerts {
    fn default() -> Self {
        Self {
            enabled: false,
            webhook_url: None,
            bearer_token: None,
            min_outage_s: 60,
            security_events: true,
            cooldown_s: 300,
        }
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            profile: Profile::Standard,
            data_dir: PathBuf::from("/var/lib/linkwatch"),
            interfaces: vec![],
            targets: Targets::default(),
            intervals: Intervals::default(),
            classify: Classify::default(),
            speed: Speed::default(),
            web: Web::default(),
            site: SiteRef::default(),
            storage: Storage::default(),
            router: Router::default(),
            alerts: Alerts::default(),
            advisor: Advisor::default(),
        }
    }
}

impl Default for Targets {
    fn default() -> Self {
        Self {
            gateway: None,
            isp_hop: None,
            isp_hop_auto: true,
            internet: vec![Ipv4Addr::new(1, 1, 1, 1), Ipv4Addr::new(8, 8, 8, 8), Ipv4Addr::new(9, 9, 9, 9)],
            tcp: vec![SocketAddr::from(([1, 1, 1, 1], 443)), SocketAddr::from(([8, 8, 8, 8], 443))],
            dns_servers: vec![],
            dns_name: "example.com".into(),
        }
    }
}

impl Default for Intervals {
    fn default() -> Self {
        Self { probe_ms: 1000, probe_timeout_ms: 900, dns_s: 10, tcp_s: 5, wifi_s: 10, survey_s: 10, scan_s: 900, heartbeat_s: 10, isp_rediscover_s: 600, host_s: 10, lan_s: 0 }
    }
}

impl Default for Classify {
    fn default() -> Self {
        Self {
            debounce_s: None,
            window_s: None,
            debounce: None,
            window: None,
            debounce_ticks: 3,
            window_ticks: 30,
            degraded_loss_pct: 2.0,
            degraded_gw_rtt_ms: 50.0,
            degraded_net_rtt_ms: 150.0,
        }
    }
}

impl Classify {
    pub const DEFAULT_DEBOUNCE_S: f64 = 3.0;
    pub const DEFAULT_WINDOW_S: f64 = 30.0;

    /// Effective debounce in seconds (see the precedence rule on the fields).
    pub fn debounce_secs(&self, probe_ms: u64) -> f64 {
        Self::secs(self.debounce_s, self.debounce, Self::DEFAULT_DEBOUNCE_S, probe_ms)
    }

    /// Effective window in seconds (see the precedence rule on the fields).
    pub fn window_secs(&self, probe_ms: u64) -> f64 {
        Self::secs(self.window_s, self.window, Self::DEFAULT_WINDOW_S, probe_ms)
    }

    fn secs(secs: Option<f64>, ticks: Option<u32>, default: f64, probe_ms: u64) -> f64 {
        match (secs, ticks) {
            (Some(s), _) => s,
            (None, Some(t)) => f64::from(t) * probe_ms as f64 / 1000.0,
            (None, None) => default,
        }
    }

    fn to_ticks(secs: f64, probe_ms: u64) -> u32 {
        let tick_s = (probe_ms.max(1)) as f64 / 1000.0;
        // `as` saturates; NaN becomes 0 and is raised to 1. validate() rejects such values.
        ((secs / tick_s).round() as u32).max(1)
    }

    /// Compute the tick counts the classifier uses: max(1, round(seconds / tick_s)).
    pub fn resolve(&mut self, probe_ms: u64) {
        self.debounce_ticks = Self::to_ticks(self.debounce_secs(probe_ms), probe_ms);
        self.window_ticks = Self::to_ticks(self.window_secs(probe_ms), probe_ms);
    }
}

impl Default for Speed {
    fn default() -> Self {
        Self {
            enabled: true,
            urls: vec![
                "http://ipv4.download.thinkbroadband.com/1GB.zip".into(),
                "http://proof.ovh.net/files/1Gb.dat".into(),
            ],
            // Stops the download at 50 MiB; slower links stop at `duration_s` first.
            max_bytes: 50 * 1024 * 1024,
            timeout_s: 30,
            duration_s: 8,
            warmup_ms: 1500,
            // 4 tests per day. At most 4 x 50 MiB = 200 MiB per day per interface.
            interval_min: 360,
            // The evening peak window is kept, but it is not faster by default.
            peak_start: "18:00".into(),
            peak_end: "00:00".into(),
            peak_interval_min: 360,
            first_after_s: 60,
        }
    }
}

impl Default for Web {
    fn default() -> Self {
        // Local only by default: the UI shows addresses, SSIDs and neighbour networks.
        Self { enabled: true, listen: SocketAddr::from(([127, 0, 0, 1], 8080)), token: None, view: ViewAccess::Token }
    }
}

impl Default for Storage {
    fn default() -> Self {
        Self { min_free_bytes: 200 * 1024 * 1024, critical_free_bytes: 20 * 1024 * 1024, fsync_s: 5, queue: 4096, compress_old: true }
    }
}

impl Config {
    pub fn load(path: Option<&Path>) -> anyhow::Result<Self> {
        let cfg: Config = match path {
            Some(p) => {
                let text = std::fs::read_to_string(p).map_err(|e| anyhow::anyhow!("cannot read config {}: {e}", p.display()))?;
                Self::from_toml(&text).map_err(|e| anyhow::anyhow!("invalid config {}: {e}", p.display()))?
            }
            None => Config::default(),
        };
        cfg.validate()?;
        Ok(cfg)
    }

    /// Parse TOML, applying the profile's intervals underneath explicit [intervals] values.
    pub fn from_toml(text: &str) -> anyhow::Result<Self> {
        let mut user: toml::Table = text.parse()?;
        let profile: Profile = match user.get("profile") {
            Some(v) => v.clone().try_into()?,
            None => Profile::Standard,
        };
        let mut merged = toml::Table::try_from(profile.intervals())?;
        if let Some(toml::Value::Table(t)) = user.remove("intervals") {
            for (k, v) in t {
                merged.insert(k, v);
            }
        }
        user.insert("intervals".into(), toml::Value::Table(merged));
        let mut cfg: Config = toml::Value::Table(user).try_into()?;
        if cfg.classify.debounce.is_some() || cfg.classify.window.is_some() {
            tracing::warn!("config: classify.debounce and classify.window (ticks) are deprecated; use debounce_s and window_s (seconds)");
        }
        cfg.classify.resolve(cfg.intervals.probe_ms);
        Ok(cfg)
    }

    pub fn validate(&self) -> anyhow::Result<()> {
        anyhow::ensure!(self.intervals.probe_ms >= 200, "intervals.probe_ms must be >= 200");
        anyhow::ensure!(
            self.intervals.probe_timeout_ms < self.intervals.probe_ms,
            "intervals.probe_timeout_ms must be < probe_ms"
        );
        anyhow::ensure!(self.classify.debounce.is_none_or(|v| v >= 1), "classify.debounce must be >= 1");
        anyhow::ensure!(self.classify.window.is_none_or(|v| v >= 1), "classify.window must be >= 1");
        anyhow::ensure!(!self.targets.internet.is_empty() || !self.targets.tcp.is_empty(), "need at least one internet target");
        let mut names = std::collections::HashSet::new();
        for i in &self.interfaces {
            anyhow::ensure!(!i.name.is_empty() && i.name.len() < 16, "invalid interface name {:?}", i.name);
            anyhow::ensure!(names.insert(&i.name), "interface {} listed twice", i.name);
        }
        for u in &self.speed.urls {
            anyhow::ensure!(u.starts_with("http://"), "speed url must be plain http:// : {u}");
        }
        parse_hhmm(&self.speed.peak_start)?;
        parse_hhmm(&self.speed.peak_end)?;
        let iv = &self.intervals;
        let c = &self.classify;
        let sp = &self.speed;
        let st = &self.storage;
        const DAY_S: u64 = 86_400;
        anyhow::ensure!(iv.probe_ms <= 60_000, "intervals.probe_ms must be <= 60000");
        for (name, v) in [("dns_s", iv.dns_s), ("tcp_s", iv.tcp_s), ("wifi_s", iv.wifi_s), ("survey_s", iv.survey_s), ("scan_s", iv.scan_s), ("heartbeat_s", iv.heartbeat_s), ("isp_rediscover_s", iv.isp_rediscover_s), ("host_s", iv.host_s), ("lan_s", iv.lan_s)] {
            anyhow::ensure!(v <= DAY_S, "intervals.{name} must be <= {DAY_S}");
        }
        anyhow::ensure!(iv.lan_s == 0 || iv.lan_s >= 60, "intervals.lan_s must be 0 (off) or >= 60");
        anyhow::ensure!((1..=60).contains(&iv.heartbeat_s), "intervals.heartbeat_s must be 1..=60 (the systemd watchdog is fed with it)");
        anyhow::ensure!(c.debounce.is_none_or(|v| v <= 1000), "classify.debounce must be <= 1000");
        anyhow::ensure!(c.window.is_none_or(|v| v <= 3600), "classify.window must be <= 3600");
        for (name, v, max) in [("debounce_s", c.debounce_s, 600.0), ("window_s", c.window_s, 3600.0)] {
            if let Some(v) = v {
                anyhow::ensure!(v.is_finite() && v > 0.0 && v <= max, "classify.{name} must be > 0 and <= {max}");
            }
        }
        // Tick-based values (old files) are bounded in seconds too: ticks x probe interval.
        anyhow::ensure!(c.debounce_secs(iv.probe_ms) <= 600.0, "classify.debounce is longer than 600 s at this probe interval");
        anyhow::ensure!(c.window_secs(iv.probe_ms) <= 3600.0, "classify.window is longer than 3600 s at this probe interval");
        for (name, v) in [("degraded_loss_pct", c.degraded_loss_pct), ("degraded_gw_rtt_ms", c.degraded_gw_rtt_ms), ("degraded_net_rtt_ms", c.degraded_net_rtt_ms)] {
            anyhow::ensure!(v.is_finite() && v > 0.0, "classify.{name} must be > 0");
        }
        anyhow::ensure!(sp.timeout_s >= 1 && sp.timeout_s <= 600, "speed.timeout_s must be 1..=600");
        anyhow::ensure!(sp.duration_s >= 1 && sp.duration_s <= sp.timeout_s, "speed.duration_s must be 1..=timeout_s");
        anyhow::ensure!(sp.warmup_ms < sp.duration_s * 1000, "speed.warmup_ms must be < duration_s");
        anyhow::ensure!(sp.max_bytes >= 1024 * 1024, "speed.max_bytes must be >= 1 MiB");
        anyhow::ensure!(sp.first_after_s <= 7 * DAY_S, "speed.first_after_s must be <= 7 days");
        anyhow::ensure!((1..=7 * 24 * 60).contains(&sp.interval_min) && (1..=7 * 24 * 60).contains(&sp.peak_interval_min), "speed interval_min and peak_interval_min must be 1..=10080");
        anyhow::ensure!(!sp.enabled || !sp.urls.is_empty(), "speed.urls is empty while speed.enabled = true");
        anyhow::ensure!(st.critical_free_bytes <= st.min_free_bytes, "storage.critical_free_bytes must be <= min_free_bytes");
        anyhow::ensure!((1..=1_000_000).contains(&st.queue), "storage.queue must be 1..=1000000");
        anyhow::ensure!((1..=3600).contains(&st.fsync_s), "storage.fsync_s must be 1..=3600");
        if let Some(t) = &self.web.token {
            anyhow::ensure!(t.len() >= 16 && t.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'), "web.token must be at least 16 characters of [A-Za-z0-9_-]");
        }
        anyhow::ensure!((5..=3600).contains(&self.router.interval_s), "router.interval_s must be 5..=3600");
        if let Some(u) = &self.router.upnp_url {
            crate::router::parse_http_url(u)?;
        }
        for code in &self.advisor.accept {
            anyhow::ensure!(
                crate::check::readiness::is_acceptable(code),
                "advisor.accept: {code:?} is not an acceptable risk code (acceptable: {})",
                crate::check::readiness::acceptable_codes().join(", ")
            );
        }
        anyhow::ensure!((5..=86_400).contains(&self.alerts.min_outage_s), "alerts.min_outage_s must be 5..=86400");
        anyhow::ensure!((10..=86_400).contains(&self.alerts.cooldown_s), "alerts.cooldown_s must be 10..=86400");
        if self.alerts.enabled {
            let url = self.alerts.webhook_url.as_deref().ok_or_else(|| {
                anyhow::anyhow!("alerts.webhook_url must be set when alerts.enabled = true")
            })?;
            crate::notify::parse_webhook_url(url)?;
        } else if let Some(url) = &self.alerts.webhook_url {
            crate::notify::parse_webhook_url(url)?;
        }
        Ok(())
    }
}

pub fn parse_hhmm(s: &str) -> anyhow::Result<(u32, u32)> {
    let (h, m) = s.split_once(':').ok_or_else(|| anyhow::anyhow!("time must be HH:MM: {s}"))?;
    let (h, m): (u32, u32) = (h.parse()?, m.parse()?);
    anyhow::ensure!(h < 24 && m < 60, "time out of range: {s}");
    Ok((h, m))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_config_is_valid() {
        let c: Config = toml::from_str("").unwrap();
        c.validate().unwrap();
    }

    #[test]
    fn profile_sets_intervals_and_explicit_values_win() {
        let c = Config::from_toml("profile = 'light'\n[intervals]\ndns_s = 7\n").unwrap();
        assert_eq!(c.intervals.probe_ms, 5000);
        assert_eq!(c.intervals.dns_s, 7);
        c.validate().unwrap();
        let d = Config::from_toml("profile = 'detailed'").unwrap();
        assert_eq!(d.intervals.probe_ms, 500);
        d.validate().unwrap();
        assert!(Config::from_toml("profile = 'turbo'").is_err());
    }

    fn ticks(t: &str) -> (u32, u32) {
        let c = Config::from_toml(t).unwrap();
        c.validate().unwrap();
        (c.classify.debounce_ticks, c.classify.window_ticks)
    }

    #[test]
    fn classify_seconds_are_profile_independent() {
        // Same wall-clock debounce and window on every profile: ticks = seconds / tick.
        assert_eq!(ticks("profile = 'light'"), (1, 6)); // 3 s / 5 s = 0.6 -> 1
        assert_eq!(ticks(""), (3, 30));
        assert_eq!(ticks("profile = 'detailed'"), (6, 60));
        for (p, tick_s) in [("light", 5.0), ("standard", 1.0), ("detailed", 0.5)] {
            let (d, w) = ticks(&format!("profile = '{p}'\n[classify]\ndebounce_s = 10.0\nwindow_s = 60.0"));
            assert!((f64::from(d) * tick_s - 10.0).abs() <= tick_s / 2.0, "{p}");
            assert!((f64::from(w) * tick_s - 60.0).abs() <= tick_s / 2.0, "{p}");
        }
    }

    #[test]
    fn classify_old_tick_fields_still_work_and_seconds_win() {
        // Old file: ticks kept as ticks, whatever the profile.
        assert_eq!(ticks("profile = 'light'\n[classify]\ndebounce = 4\nwindow = 20"), (4, 20));
        assert_eq!(ticks("profile = 'detailed'\n[classify]\ndebounce = 4\nwindow = 20"), (4, 20));
        // Seconds win over ticks, per field.
        assert_eq!(ticks("[classify]\ndebounce = 9\ndebounce_s = 2.0\nwindow = 20"), (2, 20));
        // Sub-tick values are raised to one tick.
        assert_eq!(ticks("[classify]\ndebounce_s = 0.1").0, 1);
    }

    #[test]
    fn classify_bad_seconds_rejected() {
        for t in ["debounce_s = 0.0", "debounce_s = -1.0", "window_s = 0.0", "debounce_s = 601.0", "window_s = 3601.0", "debounce = 0", "debounce = 1001"] {
            let c = Config::from_toml(&format!("[classify]\n{t}")).unwrap();
            assert!(c.validate().is_err(), "{t}");
        }
        // Old ticks that exceed the seconds bound at a slow probe interval.
        let c = Config::from_toml("profile = 'light'\n[classify]\nwindow = 3600").unwrap();
        assert!(c.validate().is_err());
    }

    #[test]
    fn out_of_range_values_rejected() {
        for t in [
            "[speed]\nfirst_after_s = 100000000000000000",
            "[speed]\ninterval_min = 0",
            "[classify]\ndegraded_loss_pct = -1.0",
            "[classify]\nwindow = 4000000000",
            "[storage]\ncritical_free_bytes = 999999999999\nmin_free_bytes = 1",
            "[storage]\nqueue = 0",
            "[intervals]\nheartbeat_s = 0",
            "[web]\ntoken = 'short'",
            "[router]\ninterval_s = 2",
            "[router]\nupnp_url = 'https://192.168.0.1/igd.xml'",
            "[intervals]\nlan_s = 10",
            "[intervals]\nlan_s = 86401",
            "[alerts]\nmin_outage_s = 1",
            "[alerts]\nenabled = true",
            "[alerts]\nwebhook_url = 'ftp://127.0.0.1/hook'",
        ] {
            let c = Config::from_toml(t).unwrap();
            assert!(c.validate().is_err(), "{t}");
        }
        for t in ["[intervals]\nlan_s = 0", "[intervals]\nlan_s = 600", "[alerts]\nenabled = true\nwebhook_url = 'https://ntfy.example.com/lw'"] {
            Config::from_toml(t).unwrap().validate().unwrap();
        }
    }

    #[test]
    fn shipped_configs_are_valid() {
        for t in [include_str!("../examples/linkwatch.toml"), include_str!("../packaging/linkwatch.toml")] {
            Config::from_toml(t).unwrap().validate().unwrap();
        }
    }

    #[test]
    fn speed_defaults_are_light() {
        let sp = Speed::default();
        assert_eq!(sp.max_bytes, 50 * 1024 * 1024);
        assert_eq!(sp.interval_min, 360);
        assert_eq!(sp.peak_interval_min, sp.interval_min);
        // 4 tests per day, 50 MiB each, per interface.
        assert!(24 * 60 / sp.interval_min * sp.max_bytes <= 200 * 1024 * 1024);
    }

    #[test]
    fn advisor_accept_parses_and_rejects_unknown_code() {
        let c = Config::from_toml("[advisor]\naccept = [\"no_wired_path\", \"vpn_active\"]").unwrap();
        c.validate().unwrap();
        assert_eq!(c.advisor.accept.len(), 2);
        for bad in ["[advisor]\naccept = [\"typo\"]", "[advisor]\naccept = [\"icmp_permission\"]"] {
            assert!(Config::from_toml(bad).unwrap().validate().is_err(), "{bad}");
        }
        assert!(toml::from_str::<Config>("[advisor]\nnope = 1").is_err());
    }

    #[test]
    fn unknown_field_rejected() {
        assert!(toml::from_str::<Config>("nope = 1").is_err());
    }

    #[test]
    fn interfaces_parse() {
        let c: Config = toml::from_str("[[interfaces]]\nname='wlo1'\nrole='wifi'\n[[interfaces]]\nname='enp1s0'\n").unwrap();
        assert_eq!(c.interfaces.len(), 2);
        assert_eq!(c.interfaces[0].role, Some(IfaceRole::Wifi));
    }
}
