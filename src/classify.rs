//! Turns raw per-tick observations into debounced path states and a cross-path verdict.
//! Pure logic: no IO, no clocks except the timestamps passed in. Fully unit-tested.

use crate::config::Classify as Cfg;
use crate::model::{IfaceRole, PathState, ProbeResult, Sample, Verdict};
use std::collections::VecDeque;

/// Instantaneous state from one sample, before windowing and debouncing.
/// `last_dns` is the most recent DNS result (DNS runs less often than ticks).
pub fn instant_state(s: &Sample, isp_known: bool, last_dns: Option<&ProbeResult>) -> PathState {
    let l = &s.link;
    if !l.present || !l.up || !l.carrier {
        return PathState::LinkDown;
    }
    if l.ipv4.is_none() || l.gateway.is_none() {
        return PathState::NoIp;
    }
    let net_ok = s.net.ok > 0 || s.tcp.as_ref().is_some_and(|t| t.ok > 0);
    let gw_ok = s.gw.as_ref().is_some_and(|g| g.ok);
    let isp_ok = s.isp.as_ref().map(|i| i.ok);
    if net_ok {
        // The path works end to end. A router that ignores ICMP is not an outage.
        if let Some(d) = last_dns
            && !d.ok {
                return PathState::DnsDown;
            }
        return PathState::Ok;
    }
    if !gw_ok {
        return PathState::LanDown;
    }
    match (isp_known, isp_ok) {
        (true, Some(false)) => PathState::IspDown,
        _ => PathState::WanDown,
    }
}

/// Per-tick observation kept in the sliding window for Degraded detection.
#[derive(Debug, Clone, Copy)]
struct Obs {
    counted: bool,
    gw_fail: bool,
    net_fail: bool,
    gw_rtt: Option<f64>,
    net_rtt: Option<f64>,
}

/// Debounced state machine for one interface.
#[derive(Debug)]
pub struct PathClassifier {
    cfg: Cfg,
    window: VecDeque<Obs>,
    current: PathState,
    since: chrono::DateTime<chrono::Utc>,
    candidate: Option<(PathState, u32)>,
}

/// A debounced transition.
#[derive(Debug, Clone, PartialEq)]
pub struct Transition {
    pub from: PathState,
    pub to: PathState,
    pub prev_duration_s: f64,
    pub at: chrono::DateTime<chrono::Utc>,
}

impl PathClassifier {
    pub fn new(cfg: Cfg, now: chrono::DateTime<chrono::Utc>) -> Self {
        Self { cfg, window: VecDeque::new(), current: PathState::Unknown, since: now, candidate: None }
    }

    pub fn state(&self) -> PathState {
        self.current
    }

    pub fn since(&self) -> chrono::DateTime<chrono::Utc> {
        self.since
    }

    /// Feed one sample. Returns the instantaneous (windowed, not debounced) state
    /// and a transition if the debounced state changed.
    pub fn feed(
        &mut self,
        s: &Sample,
        isp_known: bool,
        last_dns: Option<&ProbeResult>,
        now: chrono::DateTime<chrono::Utc>,
    ) -> (PathState, Option<Transition>) {
        let base = instant_state(s, isp_known, last_dns);
        // Speed-test ticks do not count for loss/latency: we saturate the link ourselves.
        let counted = base == PathState::Ok && !s.speedtest_active && !s.scan_active;
        self.window.push_back(Obs {
            counted,
            gw_fail: !s.gw.as_ref().is_some_and(|g| g.ok),
            net_fail: s.net.ok < s.net.of,
            gw_rtt: s.gw.as_ref().and_then(|g| g.rtt_ms),
            net_rtt: s.net.rtt_ms,
        });
        while self.window.len() > self.cfg.window as usize {
            self.window.pop_front();
        }
        let inst = if base == PathState::Ok && self.degraded() { PathState::Degraded } else { base };
        // While our own speed test or Wi-Fi scan runs, failures may be caused by us: record the
        // instantaneous state in the sample, but do not move the debounced state towards a failure.
        if (s.speedtest_active || s.scan_active) && is_bad(inst) && !is_bad(self.current) {
            return (inst, None);
        }
        (inst, self.debounce(inst, now))
    }

    fn degraded(&self) -> bool {
        let obs: Vec<&Obs> = self.window.iter().filter(|o| o.counted).collect();
        // Need a minimum of evidence before calling a path degraded.
        if obs.len() < (self.cfg.window as usize / 2).max(5) {
            return false;
        }
        let n = obs.len() as f64;
        // A router that never answers ICMP in the whole window ignores pings: not a loss.
        let gw_answers = obs.iter().any(|o| !o.gw_fail);
        let gw_loss = if gw_answers { obs.iter().filter(|o| o.gw_fail).count() as f64 / n * 100.0 } else { 0.0 };
        let net_loss = obs.iter().filter(|o| o.net_fail).count() as f64 / n * 100.0;
        // net_fail counts partial loss (one of three targets). Use half weight for it.
        if gw_loss > self.cfg.degraded_loss_pct || net_loss / 2.0 > self.cfg.degraded_loss_pct {
            return true;
        }
        let med = |v: Vec<f64>| median(v);
        let gw_med = med(obs.iter().filter_map(|o| o.gw_rtt).collect());
        let net_med = med(obs.iter().filter_map(|o| o.net_rtt).collect());
        gw_med.is_some_and(|m| m > self.cfg.degraded_gw_rtt_ms) || net_med.is_some_and(|m| m > self.cfg.degraded_net_rtt_ms)
    }

    fn debounce(&mut self, inst: PathState, now: chrono::DateTime<chrono::Utc>) -> Option<Transition> {
        if inst == self.current {
            self.candidate = None;
            return None;
        }
        let count = match self.candidate {
            Some((s, c)) if s == inst => c + 1,
            _ => 1,
        };
        // Leaving Unknown at startup needs no debounce.
        if count >= self.cfg.debounce || self.current == PathState::Unknown {
            let t = Transition {
                from: self.current,
                to: inst,
                prev_duration_s: (now - self.since).num_milliseconds() as f64 / 1000.0,
                at: now,
            };
            self.current = inst;
            self.since = now;
            self.candidate = None;
            Some(t)
        } else {
            self.candidate = Some((inst, count));
            None
        }
    }
}

pub fn median(mut v: Vec<f64>) -> Option<f64> {
    v.retain(|x| x.is_finite());
    if v.is_empty() {
        return None;
    }
    v.sort_by(|a, b| a.total_cmp(b));
    let m = v.len() / 2;
    Some(if v.len().is_multiple_of(2) { (v[m - 1] + v[m]) / 2.0 } else { v[m] })
}

fn is_bad(s: PathState) -> bool {
    !matches!(s, PathState::Ok | PathState::Degraded | PathState::Unknown)
}

/// Cross-path verdict from the debounced states of all monitored interfaces.
/// A wired path without link or address (cable not plugged) cannot be compared, so it is left
/// out of the cross-path verdict. A Wi-Fi path without link or address (disassociated, no DHCP)
/// is a Wi-Fi failure and counts as bad.
pub fn verdict(states: &[(IfaceRole, PathState)], isp_known: bool) -> Verdict {
    let no_link = |s: PathState| matches!(s, PathState::LinkDown | PathState::NoIp);
    // Every path lost link at the same time (more than one path): the router itself.
    if states.len() > 1 && states.iter().all(|(_, s)| no_link(*s)) {
        return Verdict::RouterProblem;
    }
    let known: Vec<_> = states
        .iter()
        .filter(|(r, s)| *s != PathState::Unknown && !(*r != IfaceRole::Wifi && no_link(*s)))
        .collect();
    if known.is_empty() {
        return Verdict::Unknown;
    }
    let bad: Vec<_> = known.iter().filter(|(_, s)| is_bad(*s)).collect();
    if bad.is_empty() {
        return Verdict::AllOk;
    }
    if known.len() == 1 {
        return Verdict::SinglePath;
    }
    if bad.len() < known.len() {
        let wifi_bad = bad.iter().any(|(r, _)| *r == IfaceRole::Wifi);
        let wired_bad = bad.iter().any(|(r, _)| *r != IfaceRole::Wifi);
        return match (wifi_bad, wired_bad) {
            (true, false) => Verdict::WifiProblem,
            (false, true) => Verdict::WiredProblem,
            _ => Verdict::Unknown,
        };
    }
    // Every path is bad: find where it breaks, using the deepest common failure.
    let all = |f: &dyn Fn(PathState) -> bool| bad.iter().all(|(_, s)| f(*s));
    if all(&|s| s == PathState::DnsDown) {
        return Verdict::Dns;
    }
    if all(&|s| matches!(s, PathState::LanDown | PathState::LinkDown | PathState::NoIp)) {
        // If even the cable cannot reach the router, the router (or its LAN side) is the problem.
        return Verdict::RouterProblem;
    }
    if bad.iter().any(|(_, s)| *s == PathState::IspDown) {
        return Verdict::LineProblem;
    }
    if all(&|s| s == PathState::WanDown) {
        return if isp_known { Verdict::InternetProblem } else { Verdict::LineProblem };
    }
    Verdict::LineProblem
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{LinkState, MultiResult};
    use std::net::Ipv4Addr;

    fn cfg() -> Cfg {
        Cfg { debounce: 3, window: 10, degraded_loss_pct: 2.0, degraded_gw_rtt_ms: 50.0, degraded_net_rtt_ms: 150.0 }
    }
    fn t0() -> chrono::DateTime<chrono::Utc> {
        chrono::DateTime::from_timestamp(1_800_000_000, 0).unwrap()
    }
    fn link_ok() -> LinkState {
        LinkState {
            present: true,
            up: true,
            carrier: true,
            ipv4: Some(Ipv4Addr::new(192, 168, 0, 5)),
            prefix_len: Some(24),
            gateway: Some(Ipv4Addr::new(192, 168, 0, 1)),
            rx_bytes: 0,
            tx_bytes: 0,
        }
    }
    fn sample(gw: bool, isp: bool, net: u8) -> Sample {
        Sample {
            iface: "wlo1".into(),
            role: IfaceRole::Wifi,
            link: link_ok(),
            gw: Some(if gw { ProbeResult::ok(3.0) } else { ProbeResult::fail("timeout") }),
            isp: Some(if isp { ProbeResult::ok(10.0) } else { ProbeResult::fail("timeout") }),
            net: MultiResult { ok: net, of: 3, rtt_ms: if net > 0 { Some(15.0) } else { None } },
            tcp: None,
            dns: None,
            rx_delta: 0,
            tx_delta: 0,
            state: PathState::Unknown,
            speedtest_active: false,
            scan_active: false,
            overrun: false,
            t: None,
            freq_mhz: None,
        }
    }

    #[test]
    fn instant_states() {
        assert_eq!(instant_state(&sample(true, true, 3), true, None), PathState::Ok);
        assert_eq!(instant_state(&sample(false, false, 0), true, None), PathState::LanDown);
        assert_eq!(instant_state(&sample(true, false, 0), true, None), PathState::IspDown);
        assert_eq!(instant_state(&sample(true, true, 0), true, None), PathState::WanDown);
        assert_eq!(instant_state(&sample(true, false, 0), false, None), PathState::WanDown);
        // Router ignores ICMP but internet works: not an outage.
        assert_eq!(instant_state(&sample(false, true, 2), true, None), PathState::Ok);
        let mut s = sample(true, true, 3);
        s.link.carrier = false;
        assert_eq!(instant_state(&s, true, None), PathState::LinkDown);
        let mut s = sample(true, true, 3);
        s.link.ipv4 = None;
        assert_eq!(instant_state(&s, true, None), PathState::NoIp);
        assert_eq!(instant_state(&sample(true, true, 3), true, Some(&ProbeResult::fail("timeout"))), PathState::DnsDown);
    }

    #[test]
    fn tcp_success_counts_as_internet() {
        let mut s = sample(true, true, 0);
        s.tcp = Some(MultiResult { ok: 1, of: 2, rtt_ms: Some(20.0) });
        assert_eq!(instant_state(&s, true, None), PathState::Ok);
    }

    #[test]
    fn debounce_requires_consecutive_ticks() {
        let mut c = PathClassifier::new(cfg(), t0());
        let sec = |n| t0() + chrono::Duration::seconds(n);
        // Leaves Unknown immediately.
        let (_, tr) = c.feed(&sample(true, true, 3), true, None, sec(0));
        assert_eq!(tr.unwrap().to, PathState::Ok);
        // Two bad ticks then good: no transition (blip).
        assert!(c.feed(&sample(false, false, 0), true, None, sec(1)).1.is_none());
        assert!(c.feed(&sample(false, false, 0), true, None, sec(2)).1.is_none());
        assert!(c.feed(&sample(true, true, 3), true, None, sec(3)).1.is_none());
        assert_eq!(c.state(), PathState::Ok);
        // Three bad ticks: transition recorded at the third.
        c.feed(&sample(false, false, 0), true, None, sec(4));
        c.feed(&sample(false, false, 0), true, None, sec(5));
        let tr = c.feed(&sample(false, false, 0), true, None, sec(6)).1.unwrap();
        assert_eq!((tr.from, tr.to), (PathState::Ok, PathState::LanDown));
        assert!((tr.prev_duration_s - 6.0).abs() < 1e-9);
    }

    #[test]
    fn mixed_failures_do_not_reset_wrongly() {
        let mut c = PathClassifier::new(cfg(), t0());
        let sec = |n| t0() + chrono::Duration::seconds(n);
        c.feed(&sample(true, true, 3), true, None, sec(0));
        // LanDown, WanDown, LanDown: never three equal in a row -> stays Ok.
        assert!(c.feed(&sample(false, false, 0), true, None, sec(1)).1.is_none());
        assert!(c.feed(&sample(true, true, 0), true, None, sec(2)).1.is_none());
        assert!(c.feed(&sample(false, false, 0), true, None, sec(3)).1.is_none());
        assert_eq!(c.state(), PathState::Ok);
    }

    #[test]
    fn degraded_by_loss_and_latency() {
        let mut c = PathClassifier::new(cfg(), t0());
        let sec = |n| t0() + chrono::Duration::seconds(n);
        // 10 % gateway loss with internet still answering => Degraded.
        for i in 0..10 {
            let mut s = sample(i % 10 != 0, true, 3);
            if i % 10 == 0 {
                s.gw = Some(ProbeResult::fail("timeout"));
            }
            c.feed(&s, true, None, sec(i));
        }
        assert_eq!(c.state(), PathState::Degraded);

        let mut c = PathClassifier::new(cfg(), t0());
        for i in 0..10 {
            let mut s = sample(true, true, 3);
            s.gw = Some(ProbeResult::ok(120.0));
            c.feed(&s, true, None, sec(i));
        }
        assert_eq!(c.state(), PathState::Degraded);
    }

    #[test]
    fn router_ignoring_icmp_is_not_degraded() {
        let mut c = PathClassifier::new(cfg(), t0());
        let sec = |n| t0() + chrono::Duration::seconds(n);
        for i in 0..10 {
            c.feed(&sample(false, true, 3), true, None, sec(i));
        }
        assert_eq!(c.state(), PathState::Ok);
    }

    #[test]
    fn speedtest_ticks_ignored_for_degraded() {
        let mut c = PathClassifier::new(cfg(), t0());
        let sec = |n| t0() + chrono::Duration::seconds(n);
        for i in 0..10 {
            let mut s = sample(true, true, 3);
            s.gw = Some(ProbeResult::ok(400.0));
            s.speedtest_active = true;
            c.feed(&s, true, None, sec(i));
        }
        assert_eq!(c.state(), PathState::Ok);
    }

    #[test]
    fn own_speed_test_or_scan_does_not_open_an_outage() {
        let mut c = PathClassifier::new(cfg(), t0());
        let sec = |n| t0() + chrono::Duration::seconds(n);
        c.feed(&sample(true, true, 3), true, None, sec(0));
        for i in 1..10 {
            let mut s = sample(false, false, 0);
            s.speedtest_active = i < 5;
            s.scan_active = i >= 5;
            assert!(c.feed(&s, true, None, sec(i)).1.is_none(), "tick {i}");
        }
        assert_eq!(c.state(), PathState::Ok);
        // The same failure without our own activity is an outage after the debounce.
        for i in 10..13 {
            c.feed(&sample(false, false, 0), true, None, sec(i));
        }
        assert_eq!(c.state(), PathState::LanDown);
        // An outage that is already open is not hidden by a later speed test.
        let mut s = sample(false, false, 0);
        s.speedtest_active = true;
        c.feed(&s, true, None, sec(13));
        assert_eq!(c.state(), PathState::LanDown);
    }

    #[test]
    fn verdicts() {
        use IfaceRole::*;
        use PathState::*;
        assert_eq!(verdict(&[(Wifi, Ok), (Ethernet, Ok)], true), Verdict::AllOk);
        assert_eq!(verdict(&[(Wifi, LanDown), (Ethernet, Ok)], true), Verdict::WifiProblem);
        assert_eq!(verdict(&[(Wifi, Ok), (Ethernet, LinkDown)], true), Verdict::AllOk);
        assert_eq!(verdict(&[(Wifi, LanDown), (Ethernet, NoIp)], true), Verdict::SinglePath);
        assert_eq!(verdict(&[(Wifi, Ok), (Ethernet, LanDown)], true), Verdict::WiredProblem);
        assert_eq!(verdict(&[(Wifi, LinkDown), (Ethernet, LinkDown)], true), Verdict::RouterProblem);
        // Wi-Fi disassociated while the cable works: a Wi-Fi problem, not all OK.
        assert_eq!(verdict(&[(Wifi, LinkDown), (Ethernet, Ok)], true), Verdict::WifiProblem);
        assert_eq!(verdict(&[(Wifi, NoIp), (Ethernet, Ok)], true), Verdict::WifiProblem);
        // Cable unplugged and Wi-Fi drops: one comparable path only.
        assert_eq!(verdict(&[(Wifi, LinkDown), (Ethernet, NoIp), (Ethernet, Ok)], true), Verdict::WifiProblem);
        assert_eq!(verdict(&[(Ethernet, LinkDown)], true), Verdict::Unknown);
        assert_eq!(verdict(&[(Wifi, IspDown), (Ethernet, IspDown)], true), Verdict::LineProblem);
        assert_eq!(verdict(&[(Wifi, LanDown), (Ethernet, IspDown)], true), Verdict::LineProblem);
        assert_eq!(verdict(&[(Wifi, WanDown), (Ethernet, WanDown)], true), Verdict::InternetProblem);
        assert_eq!(verdict(&[(Wifi, WanDown), (Ethernet, WanDown)], false), Verdict::LineProblem);
        assert_eq!(verdict(&[(Wifi, LanDown), (Ethernet, LanDown)], true), Verdict::RouterProblem);
        assert_eq!(verdict(&[(Wifi, LanDown), (Ethernet, LinkDown)], true), Verdict::SinglePath);
        assert_eq!(verdict(&[(Wifi, DnsDown), (Ethernet, DnsDown)], true), Verdict::Dns);
        assert_eq!(verdict(&[(Wifi, LanDown)], true), Verdict::SinglePath);
        assert_eq!(verdict(&[(Wifi, Unknown), (Ethernet, Unknown)], true), Verdict::Unknown);
        assert_eq!(verdict(&[(Wifi, Degraded), (Ethernet, Ok)], true), Verdict::AllOk);
    }

    #[test]
    fn median_works() {
        assert_eq!(median(vec![]), None);
        assert_eq!(median(vec![3.0, 1.0, 2.0]), Some(2.0));
        assert_eq!(median(vec![4.0, 1.0, 2.0, 3.0]), Some(2.5));
        assert_eq!(median(vec![f64::NAN, 1.0]), Some(1.0));
    }
}
