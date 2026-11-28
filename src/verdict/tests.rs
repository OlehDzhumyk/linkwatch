//! Headline tests: every message code, the live override and the selection of the dominant
//! cause. The English texts are part of the web API, so they are compared in full.

use super::*;
use crate::analyze::attribution::Attribution;
use crate::analyze::{Episode, IfaceReport};
use crate::model::PathState;
use chrono::{DateTime, Duration, Utc};

fn t0() -> DateTime<Utc> {
    DateTime::from_timestamp(1_800_000_000, 0).unwrap()
}

fn ep(cause: Option<Verdict>, secs: i64, origin: IncidentOrigin, speedtest: bool) -> Episode {
    Episode {
        iface: "eth0".into(),
        role: IfaceRole::Ethernet,
        start: t0(),
        end: t0() + Duration::seconds(secs),
        duration_s: secs as f64,
        ticks: secs as u32,
        state: PathState::IspDown,
        onset_state: PathState::IspDown,
        cause,
        origin,
        band: None,
        speedtest_active: speedtest,
        context: vec![],
        context_msg: vec![],
        finding: Default::default(),
    }
}

fn net_ep(cause: Verdict, secs: i64) -> Episode {
    ep(Some(cause), secs, IncidentOrigin::Network, false)
}

fn iface(role: IfaceRole, signal_med: Option<f64>) -> IfaceReport {
    IfaceReport { iface: format!("{role:?}"), role: Some(role), signal_med, ..Default::default() }
}

fn report(ifaces: Vec<IfaceReport>, episodes: Vec<Episode>, net: u32, obs: u32) -> Report {
    Report { ifaces, episodes, network_incidents: net, observer_incidents: obs, ..Default::default() }
}

fn check(h: &Headline, code: &str, args: &[(&str, &str)], text: &str) {
    assert_eq!(h.code, code);
    let want: BTreeMap<String, String> = args.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect();
    assert_eq!(h.args, want, "args of {code}");
    assert_eq!(h.text, text, "text of {code}");
}

#[test]
fn all_ok_observer() {
    let r = report(vec![iface(IfaceRole::Ethernet, None), iface(IfaceRole::Wifi, None)], vec![], 0, 2);
    let h = headline(&r, Some(Verdict::AllOk));
    assert_eq!(h.verdict, Some(Verdict::AllOk));
    check(&h, "all_ok_observer", &[("n", "2")], "Network stayed healthy (2 observer-host incident(s) excluded).");
}

#[test]
fn all_ok_earlier() {
    let r = report(vec![iface(IfaceRole::Ethernet, None), iface(IfaceRole::Wifi, None)], vec![], 3, 1);
    let h = headline(&r, Some(Verdict::AllOk));
    check(&h, "all_ok_earlier", &[("n", "3")], "Paths are healthy right now; 3 earlier incident(s) recorded in this session.");
}

#[test]
fn all_ok_clean() {
    let r = report(vec![iface(IfaceRole::Ethernet, None), iface(IfaceRole::Wifi, None)], vec![], 0, 0);
    let h = headline(&r, None);
    assert_eq!(h.verdict, Some(Verdict::AllOk), "two interfaces and no cause fall back to AllOk");
    check(&h, "all_ok_clean", &[], "All monitored paths are healthy with no drops recorded.");
}

#[test]
fn wifi_weak_below_minus_75_dbm() {
    let r = report(vec![iface(IfaceRole::Ethernet, None), iface(IfaceRole::Wifi, Some(-80.4))], vec![net_ep(Verdict::WifiProblem, 20)], 1, 0);
    let h = headline(&r, None);
    assert_eq!(h.verdict, Some(Verdict::WifiProblem));
    check(&h, "wifi_weak", &[("dbm", "-80")], "Ethernet stayed stable while Wi-Fi failed — weak Wi-Fi signal (median -80 dBm).");
}

#[test]
fn wifi_with_good_unknown_or_boundary_signal() {
    let text = "Ethernet stayed stable while Wi-Fi failed — issue is on the wireless hop.";
    for sig in [Some(-60.0), None, Some(-75.0)] {
        let r = report(vec![iface(IfaceRole::Ethernet, None), iface(IfaceRole::Wifi, sig)], vec![net_ep(Verdict::WifiProblem, 20)], 1, 0);
        check(&headline(&r, None), "wifi", &[], text);
    }
}

#[test]
fn wifi_signal_comes_from_the_first_wifi_interface() {
    let r = report(vec![iface(IfaceRole::Ethernet, Some(-90.0)), iface(IfaceRole::Wifi, Some(-50.0))], vec![], 1, 0);
    check(&headline(&r, Some(Verdict::WifiProblem)), "wifi", &[], "Ethernet stayed stable while Wi-Fi failed — issue is on the wireless hop.");
}

#[test]
fn layer_causes_name_their_code() {
    let cases = [
        (Verdict::WiredProblem, "wired", "Wi-Fi stayed up while the wired path failed — check Ethernet cable or port."),
        (Verdict::RouterProblem, "router", "All monitored paths failed at the router — router rebooted, stalled, or LAN stopped responding."),
        (Verdict::LineProblem, "line", "All paths reached the router but failed at the ISP hop — issue is on the access line."),
        (Verdict::InternetProblem, "internet", "Local network and ISP hop answered, but external internet targets timed out."),
        (Verdict::Dns, "dns", "IP probes succeeded, but DNS name resolution failed."),
    ];
    for (cause, code, text) in cases {
        let r = report(vec![iface(IfaceRole::Ethernet, None)], vec![net_ep(cause, 30)], 1, 0);
        let h = headline(&r, None);
        assert_eq!(h.verdict, Some(cause));
        check(&h, code, &[], text);
    }
}

#[test]
fn single_path_clean() {
    let r = report(vec![iface(IfaceRole::Ethernet, None)], vec![], 0, 0);
    let h = headline(&r, None);
    assert_eq!(h.verdict, Some(Verdict::SinglePath));
    check(&h, "single_clean", &[], "Monitoring a single path cleanly (connect Ethernet alongside Wi-Fi to isolate Wi-Fi vs ISP faults).");
}

#[test]
fn single_path_with_incidents() {
    let r = report(vec![iface(IfaceRole::Ethernet, None)], vec![], 2, 0);
    let h = headline(&r, Some(Verdict::SinglePath));
    check(&h, "single_incidents", &[("n", "2")], "Single monitored path had 2 incident(s); add a second path to separate Wi-Fi from the line.");
}

#[test]
fn waiting_without_interfaces_or_with_unknown() {
    let text = "Waiting for enough samples to classify path health.";
    let h = headline(&Report::default(), None);
    assert_eq!(h.verdict, None);
    check(&h, "waiting", &[], text);
    let r = report(vec![iface(IfaceRole::Ethernet, None)], vec![], 0, 0);
    let h = headline(&r, Some(Verdict::Unknown));
    assert_eq!(h.verdict, Some(Verdict::Unknown));
    check(&h, "waiting", &[], text);
}

#[test]
fn live_verdict_wins_over_the_dominant_cause() {
    let r = report(vec![iface(IfaceRole::Ethernet, None)], vec![net_ep(Verdict::LineProblem, 60)], 1, 0);
    assert_eq!(headline(&r, None).code, "line");
    let h = headline(&r, Some(Verdict::Dns));
    assert_eq!(h.verdict, Some(Verdict::Dns));
    assert_eq!(h.code, "dns");
    let h = headline(&r, Some(Verdict::AllOk));
    assert_eq!(h.verdict, Some(Verdict::AllOk));
    assert_eq!(h.code, "all_ok_earlier");
}

#[test]
fn explain_puts_a_live_verdict_on_a_cached_report() {
    // The caller keeps the counts and the signal of the cached report; there is no fallback.
    check(&explain(Some(Verdict::RouterProblem), 5, 0, None), "router", &[], "All monitored paths failed at the router — router rebooted, stalled, or LAN stopped responding.");
    let h = explain(None, 5, 0, Some(-90.0));
    assert_eq!(h.verdict, None);
    assert_eq!(h.code, "waiting");
}

#[test]
fn dominant_cause_skips_observer_load_provoked_and_neutral_causes() {
    let eps = vec![
        ep(Some(Verdict::RouterProblem), 600, IncidentOrigin::Observer, false),
        ep(Some(Verdict::Dns), 30, IncidentOrigin::Network, true), // load-provoked: speed test, <= 45 s
        ep(Some(Verdict::AllOk), 300, IncidentOrigin::Network, false),
        ep(Some(Verdict::Unknown), 300, IncidentOrigin::Network, false),
        ep(None, 300, IncidentOrigin::Network, false),
        net_ep(Verdict::LineProblem, 10),
    ];
    assert_eq!(dominant_cause(&report(vec![], eps, 0, 0)), Some(Verdict::LineProblem));
    assert_eq!(dominant_cause(&Report::default()), None);
}

#[test]
fn a_long_episode_during_a_speed_test_still_counts() {
    let eps = vec![ep(Some(Verdict::Dns), 46, IncidentOrigin::Network, true)];
    assert_eq!(dominant_cause(&report(vec![], eps, 0, 0)), Some(Verdict::Dns));
}

#[test]
fn dominant_cause_prefers_count_then_duration() {
    // Two short line episodes beat one long router episode.
    let eps = vec![net_ep(Verdict::LineProblem, 5), net_ep(Verdict::LineProblem, 5), net_ep(Verdict::RouterProblem, 900)];
    assert_eq!(dominant_cause(&report(vec![], eps, 0, 0)), Some(Verdict::LineProblem));
    // Same count: the longer total wins.
    let eps = vec![net_ep(Verdict::LineProblem, 5), net_ep(Verdict::RouterProblem, 900)];
    assert_eq!(dominant_cause(&report(vec![], eps, 0, 0)), Some(Verdict::RouterProblem));
    // Same count and same total: the later verdict in key order wins.
    let eps = vec![net_ep(Verdict::RouterProblem, 10), net_ep(Verdict::Dns, 10)];
    assert_eq!(dominant_cause(&report(vec![], eps, 0, 0)), Some(Verdict::Dns));
}

#[test]
fn mixed_names_its_code_and_text() {
    let r = report(vec![iface(IfaceRole::Wifi, None), iface(IfaceRole::Ethernet, None)], vec![net_ep(Verdict::Mixed, 30)], 1, 0);
    let h = headline(&r, None);
    assert_eq!(h.verdict, Some(Verdict::Mixed));
    check(&h, "mixed", &[], "Paths failed at different points at the same time — see the incidents for each path.");
}

#[test]
fn mixed_loses_a_tie_to_a_concrete_layer() {
    // Same count and same total: the concrete layer wins; Mixed has the lowest key.
    let eps = vec![net_ep(Verdict::Mixed, 10), net_ep(Verdict::LineProblem, 10)];
    assert_eq!(dominant_cause(&report(vec![], eps, 0, 0)), Some(Verdict::LineProblem));
    // More Mixed episodes beat one concrete episode.
    let eps = vec![net_ep(Verdict::Mixed, 10), net_ep(Verdict::Mixed, 10), net_ep(Verdict::LineProblem, 10)];
    assert_eq!(dominant_cause(&report(vec![], eps, 0, 0)), Some(Verdict::Mixed));
}

fn attributed(cause: Verdict, secs: i64, attribution: Attribution) -> Episode {
    let mut e = net_ep(cause, secs);
    e.finding.attribution = attribution;
    e
}

#[test]
fn dominant_cause_counts_only_network_caused_attributions() {
    // The long line episode would win by duration. The short DNS episode is a plain network
    // incident. The line episode counts only when its attribution keeps it as a network incident.
    let cases = [
        (Attribution::Network, Verdict::LineProblem),
        (Attribution::NetworkDespiteHost, Verdict::LineProblem),
        (Attribution::Mixed, Verdict::LineProblem),
        (Attribution::ObserverLikely, Verdict::Dns),
        (Attribution::ObserverConfirmed, Verdict::Dns),
        (Attribution::Inconclusive, Verdict::Dns),
    ];
    for (attribution, want) in cases {
        let eps = vec![attributed(Verdict::LineProblem, 600, attribution), net_ep(Verdict::Dns, 10)];
        assert_eq!(dominant_cause(&report(vec![], eps, 0, 0)), Some(want), "attribution {attribution:?}");
    }
}

#[test]
fn only_excluded_attributions_leave_no_dominant_cause() {
    for attribution in [Attribution::ObserverLikely, Attribution::ObserverConfirmed, Attribution::Inconclusive] {
        let eps = vec![attributed(Verdict::RouterProblem, 300, attribution)];
        assert_eq!(dominant_cause(&report(vec![], eps.clone(), 1, 0)), None, "attribution {attribution:?}");
        // The headline then falls back to the interface count, not to the excluded cause.
        let r = report(vec![iface(IfaceRole::Wifi, None), iface(IfaceRole::Ethernet, None)], eps, 1, 0);
        let h = headline(&r, None);
        assert_eq!(h.verdict, Some(Verdict::AllOk), "attribution {attribution:?}");
        assert_eq!(h.code, "all_ok_earlier");
    }
}
