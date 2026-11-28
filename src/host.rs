//! Measuring host health (`host` stream): CPU, memory, disk, temperature,
//! Raspberry Pi throttling/undervoltage, clock sync, Wi-Fi power-save and driver resets.
//!
//! Reads `/proc` and `/sys` directly and asks a local `chronyd` over its read-only UDP
//! command port; never spawns subprocesses and never panics.

use crate::link;
use crate::model::{EventKind, HostAlertKind, HostSample, IfaceRole};
use std::collections::{BTreeMap, HashMap};
use std::path::Path;

/// Stable pseudonymous host identifier (64-bit FNV-1a of `/etc/machine-id`).
/// Never writes or exposes the raw machine-id.
pub fn stable_host_id() -> Option<String> {
    let raw = std::fs::read_to_string("/etc/machine-id")
        .or_else(|_| std::fs::read_to_string("/var/lib/dbus/machine-id"))
        .ok()?;
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }
    Some(fnv1a_hex(trimmed.as_bytes()))
}

fn fnv1a_hex(bytes: &[u8]) -> String {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for &b in bytes {
        h ^= u64::from(b);
        h = h.wrapping_mul(0x0100_0000_01b3);
    }
    format!("{h:016x}")
}

/// Active NTP time-sync daemon detected via its runtime marker, if any.
/// Note: `/run/chrony` reflects a running `chronyd` instance rather than individual poll lock state.
pub fn clock_sync_source() -> Option<&'static str> {
    if Path::new("/run/systemd/timesync/synchronized").exists() {
        return Some("systemd-timesyncd");
    }
    if std::fs::metadata("/run/chrony").is_ok() {
        return Some("chrony");
    }
    if Path::new("/run/ntpd.pid").exists() || Path::new("/run/openntpd").exists() {
        return Some("ntpd");
    }
    None
}

/// Clock state as `chronyd` reports it (`chronyc tracking`).
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ChronyTracking {
    /// Leap status is not "unsynchronised", a reference is selected and the stratum is valid.
    pub synced: bool,
    pub stratum: u16,
    /// Current offset of the system clock from NTP time, seconds (positive: fast).
    pub offset_s: f64,
    /// Upper bound of the clock error: |offset| + root delay / 2 + root dispersion, seconds.
    pub max_error_s: f64,
}

const CHRONY_CMD_PORT: u16 = 323;
const CHRONY_REQ_TRACKING: u16 = 33;
const CHRONY_RPY_TRACKING: u16 = 5;
/// The request is padded to the reply length (chrony refuses shorter ones: no amplification).
const CHRONY_TRACKING_LEN: usize = 104;

/// Asks the local `chronyd` (127.0.0.1:323, unprivileged) for its tracking state.
/// `None` when chrony does not answer within 300 ms (not running, or `cmdport 0`).
pub fn chrony_tracking() -> Option<ChronyTracking> {
    let sock = std::net::UdpSocket::bind(("127.0.0.1", 0)).ok()?;
    sock.set_read_timeout(Some(std::time::Duration::from_millis(300))).ok()?;
    sock.connect(("127.0.0.1", CHRONY_CMD_PORT)).ok()?;
    let seq = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(1, |d| d.subsec_nanos() | 1);
    sock.send(&chrony_tracking_request(seq)).ok()?;
    let mut buf = [0u8; 512];
    let n = sock.recv(&mut buf).ok()?;
    parse_chrony_tracking(&buf[..n], seq)
}

fn chrony_tracking_request(seq: u32) -> [u8; CHRONY_TRACKING_LEN] {
    let mut r = [0u8; CHRONY_TRACKING_LEN];
    r[0] = 6; // protocol version
    r[1] = 1; // request
    r[4..6].copy_from_slice(&CHRONY_REQ_TRACKING.to_be_bytes());
    r[8..12].copy_from_slice(&seq.to_be_bytes());
    r
}

/// chrony's 32-bit float: 7-bit signed exponent, 25-bit signed coefficient.
fn chrony_float(x: u32) -> f64 {
    let mut exp = (x >> 25) as i32;
    if exp >= 1 << 6 {
        exp -= 1 << 7;
    }
    exp -= 25;
    let mut coef = (x & ((1 << 25) - 1)) as i64;
    if coef >= 1 << 24 {
        coef -= 1 << 25;
    }
    coef as f64 * 2f64.powi(exp)
}

fn parse_chrony_tracking(d: &[u8], seq: u32) -> Option<ChronyTracking> {
    let u16_at = |o: usize| d.get(o..o + 2).map(|b| u16::from_be_bytes([b[0], b[1]]));
    let u32_at = |o: usize| d.get(o..o + 4).map(|b| u32::from_be_bytes([b[0], b[1], b[2], b[3]]));
    if d.len() < CHRONY_TRACKING_LEN || d[1] != 2 || u16_at(4)? != CHRONY_REQ_TRACKING || u16_at(6)? != CHRONY_RPY_TRACKING {
        return None;
    }
    // status 0 = success; the sequence must be ours.
    if u16_at(8)? != 0 || u32_at(16)? != seq {
        return None;
    }
    let b = 28; // reply header
    let ref_id = u32_at(b)?;
    let stratum = u16_at(b + 24)?;
    let leap = u16_at(b + 26)?;
    // chrony sends the correction still to apply; the clock offset has the opposite sign.
    let offset_s = -chrony_float(u32_at(b + 40)?);
    let root_delay = chrony_float(u32_at(b + 64)?);
    let root_disp = chrony_float(u32_at(b + 68)?);
    Some(ChronyTracking {
        synced: leap != 3 && ref_id != 0 && stratum > 0 && stratum < 16,
        stratum,
        offset_s,
        max_error_s: offset_s.abs() + root_delay.abs() / 2.0 + root_disp.abs(),
    })
}

/// Whether the clock is NTP-synchronized. For chrony this asks the daemon (H10: a running
/// daemon that lost its servers is not a synchronized clock); a silent chrony counts as
/// synchronized, as before.
pub fn clock_synced() -> bool {
    match clock_sync_source() {
        Some("chrony") => chrony_tracking().is_none_or(|t| t.synced),
        Some(_) => true,
        None => false,
    }
}

/// Parses the aggregate `cpu ...` line from `/proc/stat` into `(busy_jiffies, total_jiffies)`.
pub fn parse_proc_stat(text: &str) -> Option<(u64, u64)> {
    let line = text.lines().find(|l| l.starts_with("cpu "))?;
    let cols: Vec<u64> = line
        .split_whitespace()
        .skip(1)
        .filter_map(|s| s.parse::<u64>().ok())
        .collect();
    if cols.len() < 4 {
        return None;
    }
    let total: u64 = cols.iter().copied().fold(0u64, u64::saturating_add);
    let idle = cols[3].saturating_add(*cols.get(4).unwrap_or(&0));
    Some((total.saturating_sub(idle), total))
}

/// Parses 1-minute load average from `/proc/loadavg`.
pub fn parse_loadavg(text: &str) -> Option<f64> {
    text.split_whitespace().next()?.parse::<f64>().ok().filter(|v| v.is_finite() && *v >= 0.0)
}

/// Parses `/proc/meminfo` into `(used_pct, avail_mb)`.
pub fn parse_meminfo(text: &str) -> Option<(f64, u64)> {
    let mut total_kb: Option<u64> = None;
    let mut avail_kb: Option<u64> = None;
    let mut free_kb: Option<u64> = None;
    for line in text.lines() {
        let Some((k, rest)) = line.split_once(':') else { continue };
        let val = rest.split_whitespace().next().and_then(|v| v.parse::<u64>().ok());
        match k {
            "MemTotal" => total_kb = val,
            "MemAvailable" => avail_kb = val,
            "MemFree" => free_kb = val,
            _ => {}
        }
    }
    let total = total_kb.filter(|&t| t > 0)?;
    let avail = avail_kb.or(free_kb)?;
    let used_pct = ((total.saturating_sub(avail)) as f64 / total as f64 * 100.0).clamp(0.0, 100.0);
    Some((used_pct, avail / 1024))
}

/// Parses Raspberry Pi `get_throttled` hex status (`0x...` or plain hex).
pub fn parse_rpi_throttled(text: &str) -> Option<u32> {
    let s = text.trim();
    let hex = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")).unwrap_or(s);
    if hex.is_empty() {
        return None;
    }
    u32::from_str_radix(hex, 16).ok()
}

fn known_thermal_hwmon(name: &str) -> bool {
    let n = name.trim();
    [
        "coretemp",
        "k10temp",
        "zenpower",
        "cpu_thermal",
        "soc_thermal",
        "acpitz",
        "x86_pkg_temp",
        "bcm2835",
        "rp1_adc",
        "mt7921",
        "iwlwifi",
        "ath",
        "rtw",
        "amdgpu",
    ]
    .iter()
    .any(|p| n.starts_with(p))
}

/// Maximum plausible CPU/SoC/Wi-Fi temperature (°C) across `/sys/class/thermal` and known `/sys/class/hwmon` sensors.
pub fn read_max_temp_c() -> Option<f64> {
    let mut max_c: Option<f64> = None;
    if let Ok(rd) = std::fs::read_dir("/sys/class/thermal") {
        for e in rd.flatten() {
            let name = e.file_name();
            if name.to_str().is_some_and(|n| n.starts_with("thermal_zone"))
                && let Some(c) = read_millideg(&e.path().join("temp"))
            {
                max_c = Some(max_c.map_or(c, |m| m.max(c)));
            }
        }
    }
    if let Ok(rd) = std::fs::read_dir("/sys/class/hwmon") {
        for e in rd.flatten() {
            let Ok(hw_name) = std::fs::read_to_string(e.path().join("name")) else { continue };
            if !known_thermal_hwmon(&hw_name) {
                continue;
            }
            let Ok(files) = std::fs::read_dir(e.path()) else { continue };
            for f in files.flatten() {
                if f.file_name()
                    .to_str()
                    .is_some_and(|n| n.starts_with("temp") && n.ends_with("_input"))
                    && let Some(c) = read_millideg(&f.path())
                {
                    max_c = Some(max_c.map_or(c, |m| m.max(c)));
                }
            }
        }
    }
    max_c
}

fn read_millideg(path: &Path) -> Option<f64> {
    let raw: i64 = std::fs::read_to_string(path).ok()?.trim().parse().ok()?;
    let c = raw as f64 / 1000.0;
    (-20.0..=150.0).contains(&c).then_some(c)
}

/// Reads Raspberry Pi firmware throttle bitmask or hwmon undervoltage alarm, if present.
pub fn read_rpi_throttled() -> Option<u32> {
    let mut val = std::fs::read_to_string("/sys/devices/platform/soc/soc:firmware/get_throttled")
        .ok()
        .and_then(|s| parse_rpi_throttled(&s));
    if let Ok(rd) = std::fs::read_dir("/sys/class/hwmon") {
        for e in rd.flatten() {
            let alarm = e.path().join("in0_lcrit_alarm");
            if std::fs::read_to_string(alarm).is_ok_and(|s| s.trim() == "1") {
                val = Some(val.unwrap_or(0) | 0x1);
            }
        }
    }
    val
}

/// What a `Latch` reports.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Edge {
    Started,
    Cleared,
}

/// Once-per-session announcer of one condition (docs/ADVISOR.md rule 4): it reports the first
/// start, then the first clear after that start, and nothing more. A condition that comes back
/// later in the same session stays silent: the first report already told the user.
#[derive(Debug, Default, Clone, Copy)]
pub(crate) struct Latch {
    started: bool,
    cleared: bool,
}

impl Latch {
    pub(crate) fn update(&mut self, on: bool) -> Option<Edge> {
        if on && !self.started {
            self.started = true;
            return Some(Edge::Started);
        }
        if !on && self.started && !self.cleared {
            self.cleared = true;
            return Some(Edge::Cleared);
        }
        None
    }
}

/// Text of the note that reports a cleared advisor condition. The notifier sender in
/// `run/observer.rs` recognises the prefix.
pub(crate) const ADVISOR_CLEARED_PREFIX: &str = "advisor: ";

/// Stateful host observer: computes CPU deltas and emits edge-triggered host alerts.
#[derive(Debug, Default)]
pub struct HostMonitor {
    prev_cpu: Option<(u64, u64)>,
    prev_ifindex: HashMap<String, u32>,
    high_cpu_streak: u32,
    was_throttled: bool,
    was_low_mem: bool,
    /// Wi-Fi power-save, per interface.
    ps_latch: HashMap<String, Latch>,
    clock_latch: Latch,
    /// Advisor risk codes the user accepted: their events are never emitted.
    accept: Vec<String>,
}

impl HostMonitor {
    #[cfg(test)]
    pub fn new() -> Self {
        Self::default()
    }

    /// A monitor that stays silent about the advisor conditions in `accept` (`[advisor] accept`).
    pub fn with_accept(accept: Vec<String>) -> Self {
        Self { accept, ..Self::default() }
    }

    fn accepted(&self, code: &str) -> bool {
        self.accept.iter().any(|a| a == code)
    }

    pub fn sample(
        &mut self,
        data_dir: &Path,
        ifaces: &[(String, IfaceRole)],
        wifi_power_save: BTreeMap<String, bool>,
    ) -> (HostSample, Vec<EventKind>) {
        let cpu_raw = std::fs::read_to_string("/proc/stat").ok().and_then(|s| parse_proc_stat(&s));
        let cpu_pct = match (self.prev_cpu, cpu_raw) {
            (Some((b0, t0)), Some((b1, t1))) if t1 > t0 => {
                Some(((b1.saturating_sub(b0)) as f64 / (t1 - t0) as f64 * 100.0).clamp(0.0, 100.0))
            }
            _ => None,
        };
        if let Some(c) = cpu_raw {
            self.prev_cpu = Some(c);
        }
        let load1 = std::fs::read_to_string("/proc/loadavg").ok().and_then(|s| parse_loadavg(&s));
        let mem = std::fs::read_to_string("/proc/meminfo").ok().and_then(|s| parse_meminfo(&s));
        let (mem_used_pct, mem_avail_mb) = match mem {
            Some((u, a)) => (Some(u), Some(a)),
            None => (None, None),
        };
        let disk_free_bytes = crate::store::free_bytes(data_dir);
        let temp_c = read_max_temp_c();
        let rpi_throttled = read_rpi_throttled();
        let clock_synced = Some(clock_synced());

        let mut ifindexes = Vec::with_capacity(ifaces.len());
        for (name, _) in ifaces {
            if let Some(idx) = link::ifindex_sysfs(name) {
                ifindexes.push((name.clone(), idx));
            }
        }

        self.evaluate(
            HostSample {
                cpu_pct,
                load1,
                mem_used_pct,
                mem_avail_mb,
                disk_free_bytes,
                temp_c,
                rpi_throttled,
                throttled: false,
                clock_synced,
                wifi_power_save,
            },
            &ifindexes,
        )
    }

    pub(crate) fn evaluate(
        &mut self,
        mut sample: HostSample,
        ifindexes: &[(String, u32)],
    ) -> (HostSample, Vec<EventKind>) {
        let mut events = Vec::new();
        let rpi_active = sample.rpi_throttled.is_some_and(|v| v & 0x0f != 0);
        let over_temp = sample.temp_c.is_some_and(|t| t >= 95.0);
        let throttled = rpi_active || over_temp;
        sample.throttled = throttled;

        if throttled && !self.was_throttled {
            let undervolt = sample.rpi_throttled.is_some_and(|v| v & 0x1 != 0);
            let alert = if undervolt { HostAlertKind::Undervoltage } else { HostAlertKind::ThermalThrottle };
            let detail = format!(
                "rpi_throttled={:?}, temp_c={:?}",
                sample.rpi_throttled.map(|v| format!("0x{v:x}")),
                sample.temp_c
            );
            events.push(EventKind::HostAlert { alert, detail, iface: None });
        }
        self.was_throttled = throttled;

        if sample.cpu_pct.is_some_and(|c| c >= 92.0) {
            self.high_cpu_streak += 1;
            if self.high_cpu_streak == 3 {
                events.push(EventKind::HostAlert {
                    alert: HostAlertKind::HighCpu,
                    iface: None,
                    detail: format!("CPU usage {:.1}%", sample.cpu_pct.unwrap_or(0.0)),
                });
            }
        } else {
            self.high_cpu_streak = 0;
        }

        let low_mem = sample.mem_used_pct.is_some_and(|m| m >= 95.0);
        if low_mem && !self.was_low_mem {
            events.push(EventKind::HostAlert {
                alert: HostAlertKind::LowMemory,
                iface: None,
                detail: format!(
                    "memory {:.1}% used ({:?} MB free)",
                    sample.mem_used_pct.unwrap_or(0.0),
                    sample.mem_avail_mb
                ),
            });
        }
        self.was_low_mem = low_mem;

        for (name, idx) in ifindexes {
            if let Some(&prev) = self.prev_ifindex.get(name)
                && prev != 0
                && *idx != prev
            {
                events.push(EventKind::HostAlert {
                    alert: HostAlertKind::DriverReset,
                    iface: Some(name.clone()),
                    detail: format!("{name}: kernel ifindex changed {prev} -> {idx}"),
                });
            }
            self.prev_ifindex.insert(name.clone(), *idx);
        }

        if !self.accepted("wifi_power_save") {
            for (iface, &on) in &sample.wifi_power_save {
                match self.ps_latch.entry(iface.clone()).or_default().update(on) {
                    Some(Edge::Started) => events.push(EventKind::HostAlert {
                        alert: HostAlertKind::WifiPowerSave,
                        iface: Some(iface.clone()),
                        detail: format!("{iface}: Wi-Fi power_save is ON (spoils: latency numbers; can double RTT and add jitter)"),
                    }),
                    Some(Edge::Cleared) => events.push(EventKind::Note {
                        text: format!("{ADVISOR_CLEARED_PREFIX}wifi_power_save cleared on {iface}: power_save is off again"),
                    }),
                    None => {}
                }
            }
        }
        // `None` = state unknown: no change.
        if let (Some(synced), false) = (sample.clock_synced, self.accepted("clock_unsynced")) {
            match self.clock_latch.update(!synced) {
                Some(Edge::Started) => events.push(EventKind::HostAlert {
                    alert: HostAlertKind::ClockUnsynced,
                    iface: None,
                    detail: "clock lost NTP synchronization (spoils: cross-device compare and router-log matching)".into(),
                }),
                Some(Edge::Cleared) => events.push(EventKind::Note {
                    text: format!("{ADVISOR_CLEARED_PREFIX}clock_unsynced cleared: NTP synchronized again"),
                }),
                None => {}
            }
        }

        (sample, events)
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn chrony_tracking_reply_parses() {
        // Header (28 bytes) + tracking data (76 bytes), as sent by chronyd 4.x.
        let mut d = vec![0u8; 104];
        d[0] = 6;
        d[1] = 2;
        d[4..6].copy_from_slice(&33u16.to_be_bytes());
        d[6..8].copy_from_slice(&5u16.to_be_bytes());
        d[16..20].copy_from_slice(&77u32.to_be_bytes());
        d[28..32].copy_from_slice(&0xB97D_BE7Bu32.to_be_bytes());
        d[52..54].copy_from_slice(&3u16.to_be_bytes()); // stratum
        // offset 0.5 s: coef 2^24-1 would overflow sign; use coef 1 << 23, exp -24 -> 0.5
        let f = |exp: i32, coef: u32| (((exp + 25) as u32 & 0x7f) << 25) | (coef & 0x1ff_ffff);
        d[68..72].copy_from_slice(&f(-24, 1 << 23).to_be_bytes());
        d[96..100].copy_from_slice(&f(-30, 1 << 23).to_be_bytes()); // root dispersion ~0.0078
        let t = super::parse_chrony_tracking(&d, 77).unwrap();
        assert!(t.synced);
        assert_eq!(t.stratum, 3);
        assert!((t.offset_s + 0.5).abs() < 1e-9, "{}", t.offset_s);
        assert!((t.max_error_s - (0.5 + 0.0078125)).abs() < 1e-6, "{}", t.max_error_s);
        assert!(super::parse_chrony_tracking(&d, 78).is_none(), "foreign sequence");
        d[54..56].copy_from_slice(&3u16.to_be_bytes()); // leap = unsynchronised
        assert!(!super::parse_chrony_tracking(&d, 77).unwrap().synced);
        assert_eq!(super::chrony_float(0), 0.0);
        let r = super::chrony_tracking_request(9);
        assert_eq!((r.len(), r[0], r[1], &r[4..6], &r[8..12]), (104, 6, 1, &[0u8, 33][..], &9u32.to_be_bytes()[..]));
    }

    use super::*;

    #[test]
    fn proc_parsers() {
        let stat = "cpu  100 0 50 800 50 0 0 0 0 0\ncpu0 50 0 25 400 25 0 0 0 0 0\n";
        assert_eq!(parse_proc_stat(stat), Some((150, 1000)));
        assert_eq!(parse_proc_stat("nope"), None);

        assert_eq!(parse_loadavg("0.42 0.35 0.28 1/200 1234\n"), Some(0.42));
        assert_eq!(parse_loadavg("bad"), None);

        let mem = "MemTotal:       16000000 kB\nMemFree:         2000000 kB\nMemAvailable:   12000000 kB\n";
        let (used, avail) = parse_meminfo(mem).unwrap();
        assert!((used - 25.0).abs() < 1e-6);
        assert_eq!(avail, 12000000 / 1024);
        assert_eq!(parse_meminfo(""), None);

        assert_eq!(parse_rpi_throttled("0x50005\n"), Some(0x50005));
        assert_eq!(parse_rpi_throttled("50000"), Some(0x50000));
        assert_eq!(parse_rpi_throttled(""), None);
    }

    #[test]
    fn host_id_hashes_without_exposing_raw() {
        let a = fnv1a_hex(b"0123456789abcdef0123456789abcdef");
        let b = fnv1a_hex(b"fedcba9876543210fedcba9876543210");
        assert_eq!(a.len(), 16);
        assert_ne!(a, b);
    }

    #[test]
    fn monitor_emits_alerts_on_transitions() {
        let mut m = HostMonitor::new();
        let mut ps = BTreeMap::new();
        ps.insert("wlo1".into(), true);

        let base = HostSample {
            cpu_pct: Some(95.0),
            mem_used_pct: Some(96.0),
            mem_avail_mb: Some(50),
            temp_c: Some(86.0),
            rpi_throttled: Some(0x1),
            wifi_power_save: ps.clone(),
            ..Default::default()
        };

        let (s1, ev1) = m.evaluate(base.clone(), &[("wlo1".into(), 3)]);
        assert!(s1.throttled);
        assert!(ev1.iter().any(|e| matches!(e, EventKind::HostAlert { alert: HostAlertKind::Undervoltage, .. })));
        assert!(ev1.iter().any(|e| matches!(e, EventKind::HostAlert { alert: HostAlertKind::LowMemory, .. })));
        assert!(ev1.iter().any(|e| matches!(e, EventKind::HostAlert { alert: HostAlertKind::WifiPowerSave, .. })));
        assert!(!ev1.iter().any(|e| matches!(e, EventKind::HostAlert { alert: HostAlertKind::HighCpu, .. })));

        // Second high-CPU sample: still below streak 3; undervoltage/low_mem/ps do not repeat.
        let (_, ev2) = m.evaluate(base.clone(), &[("wlo1".into(), 3)]);
        assert!(ev2.is_empty(), "{ev2:?}");

        // Third high-CPU sample + ifindex jump => high_cpu and driver_reset fire.
        let (_, ev3) = m.evaluate(base, &[("wlo1".into(), 7)]);
        assert!(ev3.iter().any(|e| matches!(e, EventKind::HostAlert { alert: HostAlertKind::HighCpu, .. })));
        assert!(ev3.iter().any(|e| matches!(e, EventKind::HostAlert { alert: HostAlertKind::DriverReset, .. })));
    }

    fn sample(ps: Option<bool>, synced: Option<bool>) -> HostSample {
        let mut s = HostSample { clock_synced: synced, ..Default::default() };
        if let Some(on) = ps {
            s.wifi_power_save.insert("wlo1".into(), on);
        }
        s
    }

    fn adv(evs: &[EventKind]) -> Vec<String> {
        evs.iter()
            .map(|e| match e {
                EventKind::HostAlert { alert, .. } => format!("start:{}", alert.as_str()),
                EventKind::Note { text } => format!("note:{}", text.split_whitespace().nth(1).unwrap_or("")),
                _ => "other".into(),
            })
            .collect()
    }

    #[test]
    fn latch_reports_start_and_clear_once() {
        let mut l = Latch::default();
        assert_eq!(l.update(false), None);
        assert_eq!(l.update(true), Some(Edge::Started));
        assert_eq!(l.update(true), None);
        assert_eq!(l.update(false), Some(Edge::Cleared));
        assert_eq!(l.update(true), None, "a return in the same session is silent");
        assert_eq!(l.update(false), None);
    }

    #[test]
    fn advisor_events_once_per_session() {
        let mut m = HostMonitor::new();
        let ix = [("wlo1".to_string(), 3u32)];
        assert!(adv(&m.evaluate(sample(Some(false), Some(true)), &ix).1).is_empty());
        assert_eq!(adv(&m.evaluate(sample(Some(true), Some(false)), &ix).1), ["start:wifi_power_save", "start:clock_unsynced"]);
        assert!(m.evaluate(sample(Some(true), Some(false)), &ix).1.is_empty());
        // Unknown clock state changes nothing.
        assert!(m.evaluate(sample(Some(true), None), &ix).1.is_empty());
        assert_eq!(adv(&m.evaluate(sample(Some(false), Some(true)), &ix).1), ["note:wifi_power_save", "note:clock_unsynced"]);
        // Conditions return: silent for the rest of the session.
        assert!(m.evaluate(sample(Some(true), Some(false)), &ix).1.is_empty());
        assert!(m.evaluate(sample(Some(false), Some(true)), &ix).1.is_empty());
    }

    #[test]
    fn accepted_advisor_conditions_are_silent() {
        let mut m = HostMonitor::with_accept(vec!["wifi_power_save".into(), "clock_unsynced".into()]);
        assert!(m.evaluate(sample(Some(true), Some(false)), &[]).1.is_empty());
        assert!(m.evaluate(sample(Some(false), Some(true)), &[]).1.is_empty());
    }
}
