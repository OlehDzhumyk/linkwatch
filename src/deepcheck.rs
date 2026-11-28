//! `linkwatch check --deep`: about 10 s of active self-tests on top of `check`
//! (docs/HOST-ISOLATION-SCENARIOS.md section 3.1).
//!
//! 1. Timer wake-up jitter of this host (H1): the scheduler must wake the probe loop on time.
//! 2. Loopback ICMP RTT (H1): the host's own network stack must answer in well under 2 ms.
//! 3. CPU / IO pressure (Linux PSI, H1, H11).
//! 4. Path proof per interface (H8, B11): echo replies to the gateway must arrive on the
//!    interface that sent the request, not on the other one.

use crate::check::{Item, Level, item};
use crate::model::IfaceRole;
use crate::{link, probe};
use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

/// Value at quantile `q` (0..=1) of `v` (sorted in place). `None` for an empty slice.
fn quantile(v: &mut [f64], q: f64) -> Option<f64> {
    if v.is_empty() {
        return None;
    }
    v.sort_by(f64::total_cmp);
    let i = ((v.len() - 1) as f64 * q.clamp(0.0, 1.0)).round() as usize;
    Some(v[i])
}

pub async fn deep(ifaces: &[(String, IfaceRole)], gateway: Option<Ipv4Addr>) -> Vec<Item> {
    let mut out = vec![timer_jitter().await, loopback_rtt().await];
    out.extend(pressure(std::path::Path::new("/proc/pressure")));
    for (name, _) in ifaces {
        out.extend(path_proof(name, gateway).await);
    }
    out
}

/// H1: 100 sleeps of 20 ms; how late does the host wake us?
async fn timer_jitter() -> Item {
    let mut late = Vec::with_capacity(100);
    for _ in 0..100 {
        let t = Instant::now();
        tokio::time::sleep(Duration::from_millis(20)).await;
        late.push((t.elapsed().as_secs_f64() * 1e3 - 20.0).max(0.0));
    }
    let max = late.iter().copied().fold(0.0, f64::max);
    let p99 = quantile(&mut late, 0.99).unwrap_or(0.0);
    let lvl = if p99 >= 20.0 { Level::Fail } else if p99 >= 5.0 { Level::Warn } else { Level::Ok };
    item(
        lvl,
        "timer jitter",
        format!("wake-up delay p99 {p99:.1} ms, max {max:.1} ms (100 x 20 ms)"),
        (lvl != Level::Ok).then_some("the host is busy or throttled; stop heavy jobs (updates, builds, backups) or use a less loaded device"),
    )
    .code("timer_jitter")
}

/// H1: ICMP echo to 127.0.0.1 at 10 Hz for 2 s.
async fn loopback_rtt() -> Item {
    let mut rtt = Vec::with_capacity(20);
    let mut lost = 0;
    for _ in 0..20 {
        let r = probe::icmp::ping("lo", Ipv4Addr::LOCALHOST, Duration::from_millis(500)).await;
        match r.rtt_ms.filter(|_| r.ok) {
            Some(v) => rtt.push(v),
            None => lost += 1,
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    if rtt.is_empty() {
        return item(Level::Warn, "loopback rtt", "no reply from 127.0.0.1", Some("check the icmp permission line above"));
    }
    let p99 = quantile(&mut rtt, 0.99).unwrap_or(0.0);
    let bad = lost > 0 || p99 >= 2.0;
    item(
        if bad { Level::Warn } else { Level::Ok },
        "loopback rtt",
        format!("p99 {p99:.2} ms, lost {lost}/20"),
        bad.then_some("the host's own network stack is slow; RTT spikes may come from this device, not the network"),
    )
}

/// `some avg10=<v>` of a PSI file.
fn psi_some_avg10(text: &str) -> Option<f64> {
    let line = text.lines().find(|l| l.starts_with("some "))?;
    line.split_whitespace().find_map(|w| w.strip_prefix("avg10=")?.parse().ok())
}

/// H1 / H11: share of the last 10 s in which tasks waited for CPU or disk.
fn pressure(dir: &std::path::Path) -> Option<Item> {
    let cpu = std::fs::read_to_string(dir.join("cpu")).ok().as_deref().and_then(psi_some_avg10);
    let io = std::fs::read_to_string(dir.join("io")).ok().as_deref().and_then(psi_some_avg10);
    if cpu.is_none() && io.is_none() {
        return None;
    }
    let worst = cpu.unwrap_or(0.0).max(io.unwrap_or(0.0));
    let lvl = if worst >= 25.0 { Level::Fail } else if worst >= 5.0 { Level::Warn } else { Level::Ok };
    let f = |v: Option<f64>| v.map_or("-".to_string(), |v| format!("{v:.1}%"));
    Some(item(
        lvl,
        "cpu/io pressure",
        format!("cpu {} io {} (PSI some avg10)", f(cpu), f(io)),
        (lvl != Level::Ok).then_some("tasks wait for CPU or disk; probe ticks will be late (overrun). Stop the busy job or use faster storage"),
    ).code("host_pressure"))
}

/// H8 / B11: 5 echoes to the gateway through `iface`; the interface's own receive counter
/// must grow by at least the number of replies.
async fn path_proof(iface: &str, gateway: Option<Ipv4Addr>) -> Option<Item> {
    let l = link::read(iface);
    if !(l.present && l.up && l.carrier && l.ipv4.is_some()) {
        return None;
    }
    let gw = gateway.or(l.gateway)?;
    let before = link::rx_packets(iface)?;
    let mut ok = 0u64;
    for _ in 0..5 {
        if probe::icmp::ping(iface, gw, Duration::from_millis(900)).await.ok {
            ok += 1;
        }
    }
    let delta = link::rx_packets(iface)?.saturating_sub(before);
    let name = format!("path proof {iface}");
    Some(if ok == 0 {
        item(Level::Fail, name, format!("0/5 replies from {gw}"), Some("the router does not answer on this path")).code("path_isolation")
    } else if delta < ok {
        item(
            Level::Fail,
            name,
            format!("{ok}/5 replies from {gw}, but only {delta} packet(s) received on {iface}"),
            Some("replies come back on the other interface (ARP flux / rp_filter); install deploy/90-linkwatch.conf and run `sysctl --system`"),
        )
        .code("path_isolation")
    } else {
        item(Level::Ok, name, format!("{ok}/5 replies from {gw}, {delta} packet(s) received on {iface}"), None)
    })
}

/// Idle baseline of one interface (`linkwatch calibrate`).
#[derive(Debug, Clone, serde::Serialize)]
pub struct IfaceBaseline {
    pub iface: String,
    pub role: IfaceRole,
    pub gateway: Option<Ipv4Addr>,
    pub sent: u32,
    pub lost: u32,
    pub gw_rtt_p50_ms: Option<f64>,
    pub gw_rtt_p95_ms: Option<f64>,
    pub gw_rtt_p99_ms: Option<f64>,
    /// rx_errors + tx_errors + rx_dropped during the baseline.
    pub nic_errors: u64,
}

/// Idle baseline of the host and its paths, written to `<data_dir>/calibration.json`.
#[derive(Debug, Clone, serde::Serialize)]
pub struct Calibration {
    pub at: chrono::DateTime<chrono::Utc>,
    pub seconds: u64,
    pub timer_p99_ms: f64,
    pub timer_max_ms: f64,
    pub ifaces: Vec<IfaceBaseline>,
}

fn nic_error_sum(iface: &str) -> u64 {
    ["rx_errors", "tx_errors", "rx_dropped"]
        .iter()
        .filter_map(|f| std::fs::read_to_string(format!("/sys/class/net/{iface}/statistics/{f}")).ok()?.trim().parse::<u64>().ok())
        .sum()
}

async fn baseline_iface(iface: String, role: IfaceRole, gateway: Option<Ipv4Addr>, dur: Duration) -> IfaceBaseline {
    let l = link::read(&iface);
    let gw = gateway.or(l.gateway).filter(|_| l.carrier && l.ipv4.is_some());
    let mut b = IfaceBaseline { iface: iface.clone(), role, gateway: gw, sent: 0, lost: 0, gw_rtt_p50_ms: None, gw_rtt_p95_ms: None, gw_rtt_p99_ms: None, nic_errors: 0 };
    let Some(gw) = gw else { return b };
    let err0 = nic_error_sum(&iface);
    let end = Instant::now() + dur;
    let mut rtt = Vec::new();
    let mut tick = tokio::time::interval(Duration::from_millis(200));
    while Instant::now() < end {
        tick.tick().await;
        let r = probe::icmp::ping(&iface, gw, Duration::from_millis(900)).await;
        b.sent += 1;
        match r.rtt_ms.filter(|_| r.ok) {
            Some(v) => rtt.push(v),
            None => b.lost += 1,
        }
    }
    b.nic_errors = nic_error_sum(&iface).saturating_sub(err0);
    b.gw_rtt_p50_ms = quantile(&mut rtt, 0.5);
    b.gw_rtt_p95_ms = quantile(&mut rtt, 0.95);
    b.gw_rtt_p99_ms = quantile(&mut rtt, 0.99);
    b
}

/// `linkwatch calibrate`: probes every gateway at 5 Hz for `seconds` while it measures the
/// host's timer jitter. Gives the idle noise floor of this device (section 3.2, single node).
pub async fn calibrate(ifaces: &[(String, IfaceRole)], gateway: Option<Ipv4Addr>, seconds: u64) -> Calibration {
    let dur = Duration::from_secs(seconds.max(5));
    let at = chrono::Utc::now();
    let paths = futures::future::join_all(ifaces.iter().map(|(n, r)| baseline_iface(n.clone(), *r, gateway, dur)));
    let timer = async {
        let end = Instant::now() + dur;
        let mut late = Vec::new();
        while Instant::now() < end {
            let t = Instant::now();
            tokio::time::sleep(Duration::from_millis(50)).await;
            late.push((t.elapsed().as_secs_f64() * 1e3 - 50.0).max(0.0));
        }
        let max = late.iter().copied().fold(0.0, f64::max);
        (quantile(&mut late, 0.99).unwrap_or(0.0), max)
    };
    let (ifaces, (timer_p99_ms, timer_max_ms)) = tokio::join!(paths, timer);
    Calibration { at, seconds: dur.as_secs(), timer_p99_ms, timer_max_ms, ifaces }
}

/// Check-style lines for a calibration result.
pub fn calibration_items(c: &Calibration) -> Vec<Item> {
    let mut out = Vec::new();
    let t = if c.timer_p99_ms >= 5.0 { Level::Warn } else { Level::Ok };
    out.push(item(t, "timer jitter", format!("p99 {:.1} ms, max {:.1} ms over {} s", c.timer_p99_ms, c.timer_max_ms, c.seconds), (t != Level::Ok).then_some("the host is busy; idle RTT below includes host delay")).code("timer_jitter"));
    for b in &c.ifaces {
        let name = format!("baseline {}", b.iface);
        let Some(gw) = b.gateway else {
            out.push(item(Level::Warn, name, "no carrier, address or gateway: not measured", None));
            continue;
        };
        let loss = b.lost as f64 * 100.0 / b.sent.max(1) as f64;
        // An idle wired path to the router should be about 1 ms; Wi-Fi a few ms.
        let limit = if b.role == IfaceRole::Wifi { 30.0 } else { 5.0 };
        let p99 = b.gw_rtt_p99_ms.unwrap_or(f64::INFINITY);
        let bad = loss > 1.0 || p99 > limit || b.nic_errors > 0;
        let f = |v: Option<f64>| v.map_or("-".into(), |v| format!("{v:.1}"));
        out.push(item(
            if bad { Level::Warn } else { Level::Ok },
            name,
            format!("{gw}: p50 {} p95 {} p99 {} ms, loss {loss:.1}% ({}/{}), nic errors {}", f(b.gw_rtt_p50_ms), f(b.gw_rtt_p95_ms), f(b.gw_rtt_p99_ms), b.lost, b.sent, b.nic_errors),
            bad.then_some("the idle path is already noisy: later RTT spikes below this level are normal for this device and place"),
        ));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quantile_and_psi_parse() {
        let mut v = vec![5.0, 1.0, 3.0, 2.0, 4.0];
        assert_eq!(quantile(&mut v, 0.5), Some(3.0));
        assert_eq!(quantile(&mut v, 1.0), Some(5.0));
        assert_eq!(quantile(&mut [], 0.5), None);
        let psi = "some avg10=12.50 avg60=3.00 avg300=1.00 total=123\nfull avg10=1.00 avg60=0.00 avg300=0.00 total=5\n";
        assert_eq!(psi_some_avg10(psi), Some(12.5));
        assert_eq!(psi_some_avg10("garbage"), None);
    }

    #[test]
    fn pressure_levels() {
        let d = std::env::temp_dir().join(format!("lw-psi-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&d).unwrap();
        std::fs::write(d.join("cpu"), "some avg10=0.50 avg60=0 avg300=0 total=0\n").unwrap();
        std::fs::write(d.join("io"), "some avg10=30.00 avg60=0 avg300=0 total=0\n").unwrap();
        assert_eq!(pressure(&d).unwrap().level, Level::Fail);
        std::fs::write(d.join("io"), "some avg10=1.00 avg60=0 avg300=0 total=0\n").unwrap();
        assert_eq!(pressure(&d).unwrap().level, Level::Ok);
        assert!(pressure(&d.join("missing")).is_none());
        let _ = std::fs::remove_dir_all(d);
    }
}
