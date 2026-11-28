//! Stage `masking`: conditions that blind one element for the whole session
//! (docs/INCIDENT-ATTRIBUTION.md, section 10, rule 3), reported once and never per incident.
//!
//! Below its share a condition blinds nothing (rule 2). M7 (VPN) has no signal in the data.
//! The per-incident masking (M1, M3) is part of [`attribution::attribute`].

use super::super::engine::{HostAcc, IfAcc, local_hour};
use super::super::*;
use super::context::START_GAP_MIN_S;
use super::windows::EVENING_HOURS;
use attribution::{BlindCause as C, Element as E};

/// Wi-Fi power-save on for at least this share of the session blinds latency figures (M4).
pub(super) const POWER_SAVE_BLIND_PCT: f64 = 5.0;
/// The host's own heavy traffic in at least this share of the evening blinds ISP evening patterns (M13).
const EVENING_SELF_TRAFFIC_BLIND_PCT: f64 = 10.0;
/// Own speed tests more often than this in the evening blind ISP evening patterns (M6).
const EVENING_SPEEDTEST_EVERY_S: f64 = 7200.0;
/// M6 needs at least this many own speed tests in the evening hours.
/// Engineering estimate: one test is not a pattern.
const EVENING_SPEEDTESTS_MIN: usize = 2;

/// What the session blinds are computed from.
pub(in crate::analyze) struct BlindInput<'a> {
    pub host: &'a HostAcc,
    /// Time-sorted events.
    pub events: &'a [(DateTime<Utc>, EventKind)],
    pub ifs: &'a BTreeMap<String, IfAcc>,
    pub speedtests: &'a [(DateTime<Utc>, String)],
    pub tick_s: f64,
    /// Length of the session in hours.
    pub session_hours: f64,
    pub trust: TrustLevel,
}

/// The blinds of the whole session, in the order M4, M9, M10, M13, M6.
pub(in crate::analyze) fn session_blinds(inp: &BlindInput) -> Vec<SessionBlind> {
    let mut out = Vec::new();
    out.extend(power_save_blind(inp.host));
    out.extend(monitor_gap_blind(inp.events, inp.session_hours * 3600.0));
    out.extend(polluted_observer_blind(inp.trust));
    out.extend(evening_blinds(inp));
    out
}

/// M4: power-save inflates RTT, it does not make long loss.
fn power_save_blind(host: &HostAcc) -> Option<SessionBlind> {
    if host.power_save_known == 0 {
        return None;
    }
    let share = host.power_save_on as f64 * 100.0 / host.power_save_known as f64;
    (share >= POWER_SAVE_BLIND_PCT).then(|| SessionBlind {
        element: E::Latency,
        by: C::PowerSave,
        share_pct: share,
        msg: crate::msg!("sb_power_save", "Wi-Fi power-save was on for {pct}% of the session: stall counts, bufferbloat and RTT medians are not reliable. Outages are still judged.", pct = format!("{share:.0}")),
    })
}

/// M9: nothing was measured inside the gaps.
fn monitor_gap_blind(events: &[(DateTime<Utc>, EventKind)], session_s: f64) -> Option<SessionBlind> {
    let gap_s: f64 = events
        .iter()
        .map(|(_, ev)| match ev {
            EventKind::Start { gap_s: Some(g), .. } if *g > START_GAP_MIN_S => *g,
            EventKind::SuspendGap { secs } => *secs,
            _ => 0.0,
        })
        .sum();
    (gap_s > 0.0).then(|| SessionBlind {
        element: E::Timing,
        by: C::MonitorGap,
        share_pct: if session_s > 0.0 { (gap_s * 100.0 / session_s).min(100.0) } else { 0.0 },
        msg: crate::msg!("sb_monitor_gap", "The monitor did not measure for {secs} s in total: nothing can be concluded inside these gaps (see monitor gaps).", secs = format!("{gap_s:.0}")),
    })
}

/// M10: a polluted observer caps every network result at medium.
fn polluted_observer_blind(trust: TrustLevel) -> Option<SessionBlind> {
    (trust == TrustLevel::Polluted).then(|| SessionBlind {
        element: E::Network,
        by: C::ObserverPolluted,
        share_pct: 100.0,
        msg: crate::msg!("sb_observer_polluted", "Observer Trust is polluted: every network result is limited to medium confidence."),
    })
}

/// M13 / M6: the evening ISP pattern is confounded with the host's own load.
fn evening_blinds(inp: &BlindInput) -> Vec<SessionBlind> {
    let mut out = Vec::new();
    let evening_ticks = |a: &IfAcc| EVENING_HOURS.map(|h| a.hour_ticks[h]).sum::<u64>();
    let self_share = inp
        .ifs
        .values()
        .filter(|a| evening_ticks(a) > 0)
        .map(|a| a.evening_self_ticks as f64 * 100.0 / evening_ticks(a) as f64)
        .fold(0.0, f64::max);
    if self_share >= EVENING_SELF_TRAFFIC_BLIND_PCT {
        out.push(SessionBlind {
            element: E::Isp,
            by: C::SelfTraffic,
            share_pct: self_share,
            msg: crate::msg!("sb_self_traffic", "The host's own traffic filled {pct}% of the evening hours (18-24): evening RTT and speed patterns cannot be blamed on the provider.", pct = format!("{self_share:.0}")),
        });
    }
    let evening_s = inp.ifs.values().map(evening_ticks).max().unwrap_or(0) as f64 * inp.tick_s;
    let tests = inp.speedtests.iter().filter(|(t, _)| EVENING_HOURS.contains(&(local_hour(*t) as usize))).count();
    if tests >= EVENING_SPEEDTESTS_MIN && evening_s / (tests as f64) < EVENING_SPEEDTEST_EVERY_S {
        out.push(SessionBlind {
            element: E::Isp,
            by: C::OwnSpeedTests,
            share_pct: 0.0,
            msg: crate::msg!("sb_own_speed_tests", "The monitor ran {n} speed tests in the evening hours (more often than every 2 h): evening congestion patterns are confounded with its own load.", n = tests),
        });
    }
    out
}

/// M10: a polluted observer cannot back a firm network verdict. Observer findings keep theirs.
pub(in crate::analyze) fn cap_polluted(episodes: &mut [Episode], level: TrustLevel) {
    if level == TrustLevel::Polluted {
        for e in episodes.iter_mut().filter(|e| !e.finding.attribution.is_observer()) {
            e.finding.confidence = e.finding.confidence.min(attribution::Confidence::Medium);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::fixtures::{episode, t0};
    use super::*;

    fn input<'a>(host: &'a HostAcc, events: &'a [(DateTime<Utc>, EventKind)], ifs: &'a BTreeMap<String, IfAcc>, speedtests: &'a [(DateTime<Utc>, String)], trust: TrustLevel) -> BlindInput<'a> {
        BlindInput { host, events, ifs, speedtests, tick_s: 1.0, session_hours: 1.0, trust }
    }

    fn codes(b: &[SessionBlind]) -> Vec<&str> {
        b.iter().map(|b| b.msg.code.as_str()).collect()
    }

    #[test]
    fn power_save_blinds_latency_from_five_percent() {
        let mut host = HostAcc { power_save_known: 100, power_save_on: 4, ..Default::default() };
        assert!(power_save_blind(&host).is_none());
        host.power_save_on = 5;
        let b = power_save_blind(&host).expect("blind");
        assert_eq!((b.element, b.by), (E::Latency, C::PowerSave));
        assert!((b.share_pct - 5.0).abs() < 1e-9);
        assert!(power_save_blind(&HostAcc::default()).is_none(), "no readings, no blind");
    }

    #[test]
    fn monitor_gaps_sum_suspend_and_long_restart_gaps() {
        let start = |g| EventKind::Start { version: "x".into(), gap_s: Some(g), boot_id: "b".into(), prev_boot_id: None };
        let events = [(t0(), start(60.0)), (t0(), start(2.0)), (t0(), EventKind::SuspendGap { secs: 240.0 })];
        let b = monitor_gap_blind(&events, 3600.0).expect("blind");
        assert_eq!(b.by, C::MonitorGap);
        assert!((b.share_pct - 300.0 * 100.0 / 3600.0).abs() < 1e-9, "a 2 s restart gap is not counted");
        assert!(b.msg.text.contains("300 s"));
        assert!(monitor_gap_blind(&[], 3600.0).is_none());
        assert_eq!(monitor_gap_blind(&events, 0.0).expect("blind").share_pct, 0.0, "an empty session has no share");
        assert_eq!(monitor_gap_blind(&events, 10.0).expect("blind").share_pct, 100.0, "the share is capped");
    }

    #[test]
    fn only_a_polluted_observer_blinds_the_network_element() {
        assert!(polluted_observer_blind(TrustLevel::Caution).is_none());
        assert!(polluted_observer_blind(TrustLevel::Clean).is_none());
        let b = polluted_observer_blind(TrustLevel::Polluted).expect("blind");
        assert_eq!((b.element, b.by, b.share_pct), (E::Network, C::ObserverPolluted, 100.0));
    }

    #[test]
    fn session_blinds_come_in_a_fixed_order() {
        let host = HostAcc { power_save_known: 10, power_save_on: 10, ..Default::default() };
        let events = [(t0(), EventKind::SuspendGap { secs: 30.0 })];
        let ifs = BTreeMap::new();
        let b = session_blinds(&input(&host, &events, &ifs, &[], TrustLevel::Polluted));
        assert_eq!(codes(&b), ["sb_power_save", "sb_monitor_gap", "sb_observer_polluted"]);
    }

    #[test]
    fn evening_self_traffic_blinds_the_isp_from_ten_percent() {
        let mk = |own: u64| {
            let mut hour_ticks = [0; 24];
            hour_ticks[20] = 100;
            BTreeMap::from([("wlo1".to_string(), IfAcc { hour_ticks, evening_self_ticks: own, ..Default::default() })])
        };
        let host = HostAcc::default();
        assert!(codes(&evening_blinds(&input(&host, &[], &mk(9), &[], TrustLevel::Clean))).is_empty());
        let b = evening_blinds(&input(&host, &[], &mk(10), &[], TrustLevel::Clean));
        assert_eq!(codes(&b), ["sb_self_traffic"]);
        assert_eq!((b[0].element, b[0].by), (E::Isp, C::SelfTraffic));
    }

    #[test]
    fn frequent_own_speed_tests_in_the_evening_blind_the_isp() {
        let mut hour_ticks = [0; 24];
        hour_ticks[19] = 3600;
        let ifs = BTreeMap::from([("wlo1".to_string(), IfAcc { hour_ticks, ..Default::default() })]);
        // Find a UTC instant whose local hour is in the evening, whatever the zone of the machine.
        let evening = (0..24).map(|h| t0() + Duration::hours(h)).find(|t| EVENING_HOURS.contains(&(local_hour(*t) as usize))).expect("an evening hour exists");
        let tests = |n: usize| (0..n).map(|_| (evening, "wlo1".to_string())).collect::<Vec<_>>();
        let host = HostAcc::default();
        // 3600 evening ticks of 1 s = 1 h: two tests are one per 30 min (too often), one test never counts.
        assert_eq!(codes(&evening_blinds(&input(&host, &[], &ifs, &tests(2), TrustLevel::Clean))), ["sb_own_speed_tests"]);
        assert!(evening_blinds(&input(&host, &[], &ifs, &tests(1), TrustLevel::Clean)).is_empty());
    }

    #[test]
    fn polluted_observer_caps_network_confidence_but_not_observer_findings() {
        use attribution::{Attribution, Confidence};
        let mut net = episode("wlo1", IfaceRole::Wifi, 0, 5, PathState::LanDown);
        net.finding.confidence = Confidence::High;
        let mut obs = net.clone();
        obs.finding.attribution = Attribution::ObserverConfirmed;
        let mut eps = [net, obs];
        cap_polluted(&mut eps, TrustLevel::Caution);
        assert_eq!(eps[0].finding.confidence, Confidence::High, "only a polluted observer caps");
        cap_polluted(&mut eps, TrustLevel::Polluted);
        assert_eq!(eps[0].finding.confidence, Confidence::Medium);
        assert_eq!(eps[1].finding.confidence, Confidence::High);
    }
}
