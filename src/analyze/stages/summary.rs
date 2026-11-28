//! Stage `summary`: put the outputs of all stages into the [`Report`].
//!
//! The only rules here are the two that need the whole picture: the repeating patterns (over
//! network episodes) and the plain-language findings (over the finished report).

use super::super::detect::{findings, patterns};
use super::super::*;
use super::context::Notices;
use super::iface_report::IfaceSummary;
use super::incidents::{self, IncidentCounts};
use super::observer::Observer;

/// The outputs of the stages.
pub(in crate::analyze) struct Parts {
    pub from: Option<DateTime<Utc>>,
    pub to: Option<DateTime<Utc>>,
    pub tick_s: f64,
    pub micro_max_s: f64,
    /// Episodes sorted by start, with cause, origin, finding and context filled in.
    pub episodes: Vec<Episode>,
    pub ifaces: IfaceSummary,
    pub counts: IncidentCounts,
    pub notices: Notices,
    pub observer: Observer,
    pub blinds: Vec<SessionBlind>,
    pub router: Option<RouterReport>,
    pub lan: Option<LanReport>,
}

/// Length of the session in hours (0 without data).
pub(in crate::analyze) fn session_hours(from: Option<DateTime<Utc>>, to: Option<DateTime<Utc>>) -> f64 {
    match (from, to) {
        (Some(f), Some(t)) => (t - f).num_seconds() as f64 / 3600.0,
        _ => 0.0,
    }
}

pub(in crate::analyze) fn assemble(p: Parts) -> Report {
    let mut rep = Report {
        from: p.from,
        to: p.to,
        hours: session_hours(p.from, p.to),
        tick_s: p.tick_s,
        micro_max_s: p.micro_max_s,
        ifaces: p.ifaces.ifaces,
        anomalies: p.ifaces.anomalies,
        causes: incidents::cause_counts(&p.episodes),
        incidents: p.counts.by_cause,
        observer_incidents: p.counts.observer,
        network_incidents: p.counts.network,
        load_incidents: p.counts.load,
        router_log_matches: p.notices.router_log_matches,
        monitor_gaps: p.notices.monitor_gaps,
        security_events: p.notices.security_events,
        observer_trust: p.observer.trust,
        session_blinds: p.blinds,
        router: p.router,
        lan: p.lan,
        ..Default::default()
    };
    rep.observer_findings = texts(&p.observer.findings);
    rep.observer_findings_msg = p.observer.findings;
    let net_eps: Vec<Episode> = p.episodes.iter().filter(|e| e.origin != IncidentOrigin::Observer && !is_load_provoked(e)).cloned().collect();
    rep.patterns_msg = patterns(&net_eps, p.micro_max_s);
    rep.patterns = texts(&rep.patterns_msg);
    rep.episodes = p.episodes;
    rep.findings_msg = findings(&rep);
    rep.findings = texts(&rep.findings_msg);
    rep
}

#[cfg(test)]
mod tests {
    use super::super::fixtures::{episode, t0};
    use super::*;

    fn parts(episodes: Vec<Episode>) -> Parts {
        Parts {
            from: Some(t0()),
            to: Some(t0() + Duration::seconds(7200)),
            tick_s: 1.0,
            micro_max_s: 2.5,
            episodes,
            ifaces: IfaceSummary::default(),
            counts: IncidentCounts::default(),
            notices: Notices::default(),
            observer: Observer { findings: vec![], trust: ObserverTrust::default() },
            blinds: vec![],
            router: None,
            lan: None,
        }
    }

    #[test]
    fn session_length_is_the_span_of_the_data() {
        assert_eq!(session_hours(None, None), 0.0);
        assert_eq!(session_hours(Some(t0()), None), 0.0);
        assert!((session_hours(Some(t0()), Some(t0() + Duration::seconds(5400))) - 1.5).abs() < 1e-9);
    }

    #[test]
    fn the_report_carries_every_stage_output_and_texts_follow_messages() {
        let mut e = episode("eth0", IfaceRole::Ethernet, 100, 30, PathState::LanDown);
        e.cause = Some(Verdict::WiredProblem);
        e.origin = IncidentOrigin::Network;
        let mut p = parts(vec![e]);
        p.counts = IncidentCounts { observer: 1, load: 2, network: 3, by_cause: BTreeMap::from([("wired_problem".to_string(), 3)]) };
        p.notices = Notices { router_log_matches: vec!["r".into()], monitor_gaps: vec!["g".into()], security_events: vec!["s".into()] };
        p.observer.findings = vec![crate::msg!("o_ntp", "clock")];
        p.blinds = vec![SessionBlind { element: attribution::Element::Timing, by: attribution::BlindCause::MonitorGap, share_pct: 1.0, msg: Msg::default() }];
        let rep = assemble(p);
        assert!((rep.hours - 2.0).abs() < 1e-9);
        assert_eq!((rep.observer_incidents, rep.load_incidents, rep.network_incidents), (1, 2, 3));
        assert_eq!(rep.incidents.get("wired_problem"), Some(&3));
        assert_eq!(rep.causes.get("wired_problem"), Some(&1));
        assert_eq!(rep.observer_findings, vec!["clock".to_string()]);
        assert_eq!(rep.observer_findings_msg.len(), 1);
        assert_eq!((rep.router_log_matches.len(), rep.monitor_gaps.len(), rep.security_events.len()), (1, 1, 1));
        assert_eq!(rep.session_blinds.len(), 1);
        assert_eq!(rep.episodes.len(), 1);
        assert_eq!(rep.findings.len(), rep.findings_msg.len());
        assert_eq!(rep.patterns.len(), rep.patterns_msg.len());
    }

    #[test]
    fn observer_and_load_episodes_do_not_count_as_causes() {
        let mut obs = episode("eth0", IfaceRole::Ethernet, 100, 30, PathState::LanDown);
        obs.origin = IncidentOrigin::Observer;
        let mut load = episode("eth0", IfaceRole::Ethernet, 200, 10, PathState::LanDown);
        load.origin = IncidentOrigin::Network;
        load.speedtest_active = true;
        let rep = assemble(parts(vec![obs, load]));
        assert!(rep.causes.is_empty(), "{:?}", rep.causes);
        assert_eq!(rep.episodes.len(), 2, "they stay in the episode list");
    }
}
