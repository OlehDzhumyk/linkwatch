//! `linkwatch calibrate`: idle baseline of the host and its paths
//! (docs/HOST-ISOLATION-SCENARIOS.md section 3.1).

use super::deep::quantile;
use super::{Item, Level, item};
use crate::model::IfaceRole;
use crate::{link, probe};
use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

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
