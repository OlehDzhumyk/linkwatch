//! Measuring host health (`host` stream): CPU, memory, disk, temperature,
//! Raspberry Pi throttling/undervoltage, clock sync, Wi-Fi power-save and driver resets.
//!
//! Reads `/proc` and `/sys` directly; never spawns subprocesses and never panics.

use crate::link;
use crate::model::{EventKind, HostSample, IfaceRole};
use std::collections::{BTreeMap, HashMap, HashSet};
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

/// Stateful host observer: computes CPU deltas and emits edge-triggered host alerts.
#[derive(Debug, Default)]
pub struct HostMonitor {
    prev_cpu: Option<(u64, u64)>,
    prev_ifindex: HashMap<String, u32>,
    high_cpu_streak: u32,
    was_throttled: bool,
    was_low_mem: bool,
    ps_warned: HashSet<String>,
}

impl HostMonitor {
    pub fn new() -> Self {
        Self::default()
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
        let clock_synced = Some(clock_sync_source().is_some());

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
            let alert = if undervolt { "undervoltage" } else { "thermal_throttle" };
            let detail = format!(
                "rpi_throttled={:?}, temp_c={:?}",
                sample.rpi_throttled.map(|v| format!("0x{v:x}")),
                sample.temp_c
            );
            events.push(EventKind::HostAlert { alert: alert.into(), detail });
        }
        self.was_throttled = throttled;

        if sample.cpu_pct.is_some_and(|c| c >= 92.0) {
            self.high_cpu_streak += 1;
            if self.high_cpu_streak == 3 {
                events.push(EventKind::HostAlert {
                    alert: "high_cpu".into(),
                    detail: format!("CPU usage {:.1}%", sample.cpu_pct.unwrap_or(0.0)),
                });
            }
        } else {
            self.high_cpu_streak = 0;
        }

        let low_mem = sample.mem_used_pct.is_some_and(|m| m >= 95.0);
        if low_mem && !self.was_low_mem {
            events.push(EventKind::HostAlert {
                alert: "low_memory".into(),
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
                    alert: "driver_reset".into(),
                    detail: format!("{name}: kernel ifindex changed {prev} -> {idx}"),
                });
            }
            self.prev_ifindex.insert(name.clone(), *idx);
        }

        for (iface, &on) in &sample.wifi_power_save {
            if on {
                if self.ps_warned.insert(iface.clone()) {
                    events.push(EventKind::HostAlert {
                        alert: "wifi_power_save".into(),
                        detail: format!("{iface}: Wi-Fi power_save is ON (can double RTT and add jitter)"),
                    });
                }
            } else {
                self.ps_warned.remove(iface);
            }
        }

        (sample, events)
    }
}

#[cfg(test)]
mod tests {
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
        assert!(ev1.iter().any(|e| matches!(e, EventKind::HostAlert { alert, .. } if alert == "undervoltage")));
        assert!(ev1.iter().any(|e| matches!(e, EventKind::HostAlert { alert, .. } if alert == "low_memory")));
        assert!(ev1.iter().any(|e| matches!(e, EventKind::HostAlert { alert, .. } if alert == "wifi_power_save")));
        assert!(!ev1.iter().any(|e| matches!(e, EventKind::HostAlert { alert, .. } if alert == "high_cpu")));

        // Second high-CPU sample: still below streak 3; undervoltage/low_mem/ps do not repeat.
        let (_, ev2) = m.evaluate(base.clone(), &[("wlo1".into(), 3)]);
        assert!(ev2.is_empty(), "{ev2:?}");

        // Third high-CPU sample + ifindex jump => high_cpu and driver_reset fire.
        let (_, ev3) = m.evaluate(base, &[("wlo1".into(), 7)]);
        assert!(ev3.iter().any(|e| matches!(e, EventKind::HostAlert { alert, .. } if alert == "high_cpu")));
        assert!(ev3.iter().any(|e| matches!(e, EventKind::HostAlert { alert, .. } if alert == "driver_reset")));
    }
}
