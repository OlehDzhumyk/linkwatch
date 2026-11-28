//! Stage `facts` (with attribution): what do the host, the router and the events around an
//! episode say about its origin?
//!
//! [`incident_facts`] collects the facts for one episode. The pure rules live in
//! [`attribution::attribute`]; this stage then sets the episode `finding` and `origin`.

use super::super::engine::{HostAcc, IfAcc, med64};
use super::super::*;
use super::cross_path::PathContext;
use super::episodes::{EpFlags, Tracked};
use super::telemetry::RouterEvents;
use super::windows::*;

/// Everything outside the episode that the facts need.
pub(in crate::analyze) struct FactsInput<'a> {
    /// Time-sorted events.
    pub events: &'a [(DateTime<Utc>, EventKind)],
    pub host: &'a HostAcc,
    pub router_events: &'a RouterEvents,
    pub router_log: &'a [RouterLine],
    pub ifs: &'a BTreeMap<String, IfAcc>,
    pub tick_s: f64,
}

/// Set `speedtest_active`, `finding` and `origin` of every episode. `paths` has one entry per
/// episode (stage `cross_path`).
pub(in crate::analyze) fn attribute_all(episodes: &mut [Tracked], paths: &[PathContext], inp: &FactsInput) {
    for ((ep, flags), path) in episodes.iter_mut().zip(paths) {
        let facts = incident_facts(ep, flags, path, inp);
        let finding = attribution::attribute(&facts);
        ep.speedtest_active = flags.speedtest > 0;
        ep.origin = origin_of(ep.cause, &finding, &facts, inp.host.samples);
        ep.finding = finding;
    }
}

/// Who owns the episode: the observer (host), the network, or nobody can say yet.
fn origin_of(cause: Option<Verdict>, finding: &attribution::Finding, facts: &attribution::IncidentFacts, host_samples: u64) -> IncidentOrigin {
    if finding.attribution.is_observer() {
        IncidentOrigin::Observer
    } else if finding.attribution != attribution::Attribution::Network
        || !matches!(cause, None | Some(Verdict::SinglePath | Verdict::Unknown))
        || facts.ap_disconnect
        || facts.router_hit
        || host_samples > 0
    {
        IncidentOrigin::Network
    } else {
        IncidentOrigin::Unknown
    }
}

/// The facts for one episode (docs/INCIDENT-ATTRIBUTION.md).
pub(super) fn incident_facts(ep: &Episode, flags: &EpFlags, path: &PathContext, inp: &FactsInput) -> attribution::IncidentFacts {
    let events = inp.events;
    let host = inp.host;
    let (near_lo, near_hi) = (ep.start - Duration::seconds(HOST_NEAR_BEFORE_S), ep.end + Duration::seconds(HOST_NEAR_AFTER_S));
    let around = |before_s: i64, after_s: i64| in_window(events, ep.start - Duration::seconds(before_s), ep.end + Duration::seconds(after_s));
    let ev_near = |before_s: i64, after_s: i64, pred: &dyn Fn(&EventKind) -> bool| around(before_s, after_s).iter().any(|(_, ev)| pred(ev));
    let router_near = |times: &[DateTime<Utc>], window_s: i64| {
        !in_window_times(times, ep.start - Duration::seconds(window_s), ep.end + Duration::seconds(window_s)).is_empty()
    };
    let mut facts = attribution::IncidentFacts {
        role: ep.role,
        duration_s: ep.duration_s,
        ticks: ep.ticks,
        tick_s: inp.tick_s,
        scan_ticks: flags.scan,
        speedtest_ticks: flags.speedtest,
        self_traffic_ticks: flags.self_traffic,
        overrun_ticks: flags.overrun_ticks,
        suspend_near: ev_near(SUSPEND_WINDOW_S, SUSPEND_WINDOW_S, &|ev| matches!(ev, EventKind::SuspendGap { .. })),
        driver_reset_offset_s: in_window(events, near_lo, near_hi)
            .iter()
            .filter(|(_, ev)| matches!(ev, EventKind::HostAlert { alert: HostAlertKind::DriverReset, detail, iface } if host_alert_iface(iface.as_deref(), detail) == Some(ep.iface.as_str())))
            .map(|(t, _)| (*t - ep.start).num_milliseconds() as f64 / 1000.0)
            .reduce(f64::min),
        throttled_near: {
            let (lo, hi) = (host.throttled_at.partition_point(|t| *t < near_lo), host.throttled_at.partition_point(|t| *t <= near_hi));
            lo < hi
        },
        low_memory_near: in_window(events, near_lo, near_hi).iter().any(|(_, ev)| matches!(ev, EventKind::HostAlert { alert: HostAlertKind::LowMemory, .. })),
        power_save_on: host.power_save_ifaces.contains(&ep.iface),
        other_failed: path.others.clone(),
        comparable_paths: path.comparable,
        router_hit: inp.router_log.iter().any(|r| {
            r.ts >= ep.start - Duration::seconds(ROUTER_LOG_WINDOW_S) && r.ts <= ep.end + Duration::seconds(ROUTER_LOG_WINDOW_S)
        }),
        ap_disconnect: ev_near(AP_DISCONNECT_WINDOW_S, AP_DISCONNECT_WINDOW_S, &|ev| {
            matches!(ev, EventKind::WifiDisconnect { iface, by_ap, timed_out, .. } if *iface == ep.iface && (*by_ap == Some(true) || *timed_out))
        }),
        clock_jump_near: ev_near(CLOCK_JUMP_WINDOW_S, CLOCK_JUMP_WINDOW_S, &|ev| matches!(ev, EventKind::ClockJump { .. })),
        router_reboot_near: router_near(&inp.router_events.reboots, ROUTER_REBOOT_WINDOW_S),
        router_wan_down_near: router_near(&inp.router_events.wan_down, ROUTER_WAN_DOWN_WINDOW_S),
        channel_switch_near: ev_near(CHANNEL_CHANGE_BEFORE_S, CHANNEL_CHANGE_AFTER_S, &|ev| matches!(ev, EventKind::ChannelChange { iface, .. } if *iface == ep.iface)),
        roam_near: ev_near(ROAM_BEFORE_S, ROAM_AFTER_S, &|ev| matches!(ev, EventKind::Roam { iface, .. } if *iface == ep.iface)),
        carrier_loss_near: ev_near(CARRIER_LOSS_WINDOW_S, CARRIER_LOSS_WINDOW_S, &|ev| matches!(ev, EventKind::LinkChange { iface, from, to } if *iface == ep.iface && from.carrier && !to.carrier)),
        no_ip: ep.state == PathState::NoIp,
        signal_dbm: None,
        busy_pct: None,
        clock_unsynced: host.clock_unsynced,
    };
    if let Some(a) = inp.ifs.get(&ep.iface) {
        let (w0, w1) = (ep.start - Duration::seconds(SIGNAL_WINDOW_S), ep.end + Duration::seconds(SIGNAL_WINDOW_S));
        facts.signal_dbm = med64(&mut in_window(&a.signal, w0, w1).iter().map(|(_, s)| f64::from(*s)).collect::<Vec<_>>());
        facts.busy_pct = med64(&mut in_window(&a.busy, w0, w1).iter().map(|(_, b)| *b).collect::<Vec<_>>());
    }
    facts
}

#[cfg(test)]
mod tests {
    use super::super::fixtures::{episode, t0, tracked};
    use super::*;

    fn at(s: i64) -> DateTime<Utc> {
        t0() + Duration::seconds(s)
    }

    fn no_path() -> PathContext {
        PathContext { cause: Verdict::SinglePath, others: vec![], comparable: 0 }
    }

    /// Facts of an 8 s Wi-Fi outage at t0+100 with the given events and host.
    fn facts_of(events: Vec<(DateTime<Utc>, EventKind)>, host: HostAcc, router_events: RouterEvents, router_log: Vec<RouterLine>) -> attribution::IncidentFacts {
        let ep = episode("wlo1", IfaceRole::Wifi, 100, 8, PathState::LanDown);
        let ifs = BTreeMap::new();
        let inp = FactsInput { events: &events, host: &host, router_events: &router_events, router_log: &router_log, ifs: &ifs, tick_s: 1.0 };
        incident_facts(&ep, &EpFlags { scan: 2, ..Default::default() }, &no_path(), &inp)
    }

    #[test]
    fn quiet_session_has_no_near_facts() {
        let f = facts_of(vec![], HostAcc::default(), RouterEvents::default(), vec![]);
        assert!(!f.suspend_near && !f.roam_near && !f.ap_disconnect && !f.router_hit && !f.throttled_near);
        assert_eq!((f.scan_ticks, f.ticks, f.comparable_paths), (2, 8, 0));
        assert_eq!(f.driver_reset_offset_s, None);
        assert_eq!((f.signal_dbm, f.busy_pct), (None, None));
    }

    #[test]
    fn events_count_only_inside_their_window() {
        let roam = |s: i64| (at(s), EventKind::Roam { iface: "wlo1".into(), from_bssid: None, to_bssid: None });
        // 10 s before the start is the edge of the roam window; 11 s is outside.
        assert!(facts_of(vec![roam(90)], HostAcc::default(), RouterEvents::default(), vec![]).roam_near);
        assert!(!facts_of(vec![roam(89)], HostAcc::default(), RouterEvents::default(), vec![]).roam_near);
        // 5 s after the end is the edge of the tolerance after the loss.
        assert!(facts_of(vec![roam(113)], HostAcc::default(), RouterEvents::default(), vec![]).roam_near);
        assert!(!facts_of(vec![roam(114)], HostAcc::default(), RouterEvents::default(), vec![]).roam_near);
        // A roam of another interface does not count.
        let other = vec![(at(100), EventKind::Roam { iface: "wlan1".into(), from_bssid: None, to_bssid: None })];
        assert!(!facts_of(other, HostAcc::default(), RouterEvents::default(), vec![]).roam_near);
    }

    #[test]
    fn host_throttling_and_router_reboot_use_their_windows() {
        let mut host = HostAcc::default();
        host.throttled_at.push(at(100 - HOST_NEAR_BEFORE_S));
        let ev = RouterEvents { reboots: vec![at(108 + ROUTER_REBOOT_WINDOW_S)], wan_down: vec![at(108 + ROUTER_WAN_DOWN_WINDOW_S + 1)] };
        let f = facts_of(vec![], host, ev, vec![]);
        assert!(f.throttled_near);
        assert!(f.router_reboot_near);
        assert!(!f.router_wan_down_near);
    }

    #[test]
    fn router_log_line_near_the_episode_is_a_hit() {
        let line = |s: i64| RouterLine { ts: at(s), priority: "Critical".into(), text: "T3 timeout".into() };
        assert!(facts_of(vec![], HostAcc::default(), RouterEvents::default(), vec![line(108 + ROUTER_LOG_WINDOW_S)]).router_hit);
        assert!(!facts_of(vec![], HostAcc::default(), RouterEvents::default(), vec![line(108 + ROUTER_LOG_WINDOW_S + 1)]).router_hit);
    }

    #[test]
    fn driver_reset_of_this_interface_gives_its_offset_from_the_start() {
        let reset = |s: i64, iface: &str| (at(s), EventKind::HostAlert { alert: HostAlertKind::DriverReset, detail: "iwlwifi".into(), iface: Some(iface.into()) });
        let f = facts_of(vec![reset(95, "wlo1"), reset(97, "wlo1"), reset(99, "wlan1")], HostAcc::default(), RouterEvents::default(), vec![]);
        assert_eq!(f.driver_reset_offset_s, Some(-5.0), "the earliest reset of this interface");
    }

    #[test]
    fn signal_and_busy_are_medians_around_the_episode() {
        let ep = episode("wlo1", IfaceRole::Wifi, 100, 8, PathState::LanDown);
        let mut ifs = BTreeMap::new();
        let a = IfAcc { signal: vec![(at(60), -60), (at(100), -70), (at(110), -80), (at(500), -30)], busy: vec![(at(105), 40.0)], ..Default::default() };
        ifs.insert("wlo1".to_string(), a);
        let (host, re) = (HostAcc::default(), RouterEvents::default());
        let inp = FactsInput { events: &[], host: &host, router_events: &re, router_log: &[], ifs: &ifs, tick_s: 1.0 };
        let f = incident_facts(&ep, &EpFlags::default(), &no_path(), &inp);
        assert_eq!(f.signal_dbm, Some(-70.0));
        assert_eq!(f.busy_pct, Some(40.0));
    }

    #[test]
    fn origin_follows_the_attribution_and_the_evidence() {
        let facts = attribution::IncidentFacts::new(IfaceRole::Wifi, 8);
        let observer = attribution::Finding { attribution: attribution::Attribution::ObserverConfirmed, ..Default::default() };
        assert_eq!(origin_of(Some(Verdict::WifiProblem), &observer, &facts, 0), IncidentOrigin::Observer);
        let network = attribution::Finding { attribution: attribution::Attribution::Network, ..Default::default() };
        assert_eq!(origin_of(Some(Verdict::SinglePath), &network, &facts, 0), IncidentOrigin::Unknown, "a lone path with no evidence stays unknown");
        assert_eq!(origin_of(Some(Verdict::WifiProblem), &network, &facts, 0), IncidentOrigin::Network);
        assert_eq!(origin_of(Some(Verdict::SinglePath), &network, &facts, 5), IncidentOrigin::Network, "host data shows the observer was healthy");
        let hit = attribution::IncidentFacts { router_hit: true, ..attribution::IncidentFacts::new(IfaceRole::Wifi, 8) };
        assert_eq!(origin_of(Some(Verdict::SinglePath), &network, &hit, 0), IncidentOrigin::Network);
    }

    #[test]
    fn attribute_all_sets_speedtest_flag_finding_and_origin() {
        let mut eps = [tracked(episode("wlo1", IfaceRole::Wifi, 100, 8, PathState::LanDown))];
        eps[0].1.speedtest = 3;
        eps[0].0.cause = Some(Verdict::WifiProblem);
        let ifs = BTreeMap::new();
        let (host, re) = (HostAcc::default(), RouterEvents::default());
        let inp = FactsInput { events: &[], host: &host, router_events: &re, router_log: &[], ifs: &ifs, tick_s: 1.0 };
        attribute_all(&mut eps, &[no_path()], &inp);
        assert!(eps[0].0.speedtest_active);
        assert_ne!(eps[0].0.origin, IncidentOrigin::Unknown);
    }
}
