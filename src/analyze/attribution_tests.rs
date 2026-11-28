//! One test per scenario A1-A34 of docs/INCIDENT-ATTRIBUTION.md (section 7), plus end-to-end
//! tests through the `Analyzer` for A10, A21, A22, A28 and A31.

use super::attribution::*;
use super::*;

const TOL: f64 = 0.01;

fn wifi(ticks: u32) -> IncidentFacts {
    IncidentFacts::new(IfaceRole::Wifi, ticks)
}
fn eth(ticks: u32) -> IncidentFacts {
    IncidentFacts::new(IfaceRole::Ethernet, ticks)
}
/// Ethernet ok: one comparable path, none failed.
fn eth_ok(mut f: IncidentFacts) -> IncidentFacts {
    f.comparable_paths = 1;
    f
}
fn failed(iface: &str, role: IfaceRole, self_traffic: bool) -> OtherFailure {
    OtherFailure { iface: iface.into(), role, self_traffic }
}
/// The other path is out too.
fn both_out(mut f: IncidentFacts) -> IncidentFacts {
    let (name, role) = if f.role == IfaceRole::Wifi { ("eth0", IfaceRole::Ethernet) } else { ("wlo1", IfaceRole::Wifi) };
    f.other_failed = vec![failed(name, role, false)];
    f.comparable_paths = 1;
    f
}
fn near(a: f64, b: f64) -> bool {
    (a - b).abs() < TOL
}

#[test]
fn a01_scan_covers_short_wifi_drop() {
    let mut f = eth_ok(wifi(4));
    f.scan_ticks = 3;
    let r = attribute(&f);
    assert_eq!(r.attribution, Attribution::ObserverConfirmed, "{r:#?}");
}

#[test]
fn a02_scan_covers_only_part_of_long_outage() {
    let mut f = eth_ok(wifi(40));
    f.scan_ticks = 3;
    let r = attribute(&f);
    assert_eq!(r.attribution, Attribution::Mixed, "{r:#?}");
    assert!(near(r.host_s, 5.0), "{r:#?}");
    assert!(near(r.network_s, 35.0), "{r:#?}");
}

#[test]
fn a03_wifi_scan_cannot_break_ethernet() {
    let mut f = eth_ok(eth(10));
    f.scan_ticks = 5;
    let r = attribute(&f);
    assert_eq!(r.attribution, Attribution::Network, "{r:#?}");
}

#[test]
fn a04_suspend_explains_both_paths() {
    for f in [wifi(20), eth(20)] {
        let mut f = both_out(f);
        f.suspend_near = true;
        let r = attribute(&f);
        assert_eq!(r.attribution, Attribution::ObserverConfirmed, "{:?}: {r:#?}", f.role);
    }
}

#[test]
fn a05_throttling_with_router_log_is_network() {
    let mut f = wifi(20);
    f.throttled_near = true;
    f.router_hit = true;
    let r = attribute(&f);
    assert_eq!(r.attribution, Attribution::NetworkDespiteHost, "{r:#?}");
    assert_eq!(r.confidence, Confidence::High, "{r:#?}");
}

#[test]
fn a06_two_late_ticks_do_not_excuse_30s_outage() {
    let mut f = eth_ok(wifi(30));
    f.overrun_ticks = 2;
    let r = attribute(&f);
    assert_eq!(r.attribution, Attribution::NetworkDespiteHost, "{r:#?}");
}

#[test]
fn a07_mostly_late_ticks_confirm_observer() {
    let mut f = eth_ok(wifi(30));
    f.overrun_ticks = 25;
    let r = attribute(&f);
    assert_eq!(r.attribution, Attribution::ObserverConfirmed, "{r:#?}");
}

#[test]
fn a08_own_traffic_on_this_path_only() {
    let mut f = eth_ok(wifi(10));
    f.self_traffic_ticks = 10;
    let r = attribute(&f);
    assert_eq!(r.attribution, Attribution::ObserverConfirmed, "{r:#?}");
}

#[test]
fn a09_clean_path_failing_too_makes_it_mixed() {
    let mut f = both_out(wifi(10));
    f.self_traffic_ticks = 10;
    let r = attribute(&f);
    assert_eq!(r.attribution, Attribution::Mixed, "{r:#?}");
    assert_eq!(r.confidence, Confidence::High, "{r:#?}");
}

#[test]
fn a10_driver_reset_after_start_is_a_consequence() {
    let mut f = eth_ok(wifi(40));
    f.driver_reset_offset_s = Some(20.0);
    let r = attribute(&f);
    assert_eq!(r.attribution, Attribution::Network, "{r:#?}");
    assert!(r.evidence.iter().any(|e| e.msg.code == "a_driver_reset_after"), "{r:#?}");
}

#[test]
fn a11_driver_reset_first_confirms_observer() {
    let mut f = eth_ok(wifi(40));
    f.driver_reset_offset_s = Some(-2.0);
    let r = attribute(&f);
    assert_eq!(r.attribution, Attribution::ObserverConfirmed, "{r:#?}");
}

#[test]
fn a12_power_save_cannot_cause_15s_loss() {
    let mut f = eth_ok(wifi(15));
    f.power_save_on = true;
    let r = attribute(&f);
    assert_eq!(r.attribution, Attribution::NetworkDespiteHost, "{r:#?}");
    assert_eq!(r.confidence, Confidence::Medium, "{r:#?}");
}

#[test]
fn a13_power_save_explains_2s_drop() {
    let mut f = eth_ok(wifi(2));
    f.power_save_on = true;
    let r = attribute(&f);
    assert_eq!(r.attribution, Attribution::ObserverLikely, "{r:#?}");
}

#[test]
fn a14_short_speed_test_outage_is_observer() {
    let mut f = eth_ok(wifi(8));
    f.speedtest_ticks = 7;
    let r = attribute(&f);
    assert_eq!(r.attribution, Attribution::ObserverConfirmed, "{r:#?}");
}

#[test]
fn a15_both_out_during_speed_test_is_load_incident() {
    let mut f = both_out(wifi(6));
    f.speedtest_ticks = 6;
    let r = attribute(&f);
    assert_eq!(r.attribution, Attribution::Mixed, "{r:#?}");
    assert_eq!(r.main_suspect, Some(Suspect::SpeedTest), "{r:#?}");
    // Provoked by the host, failed in the network: both sides get the whole outage.
    assert!(near(r.network_s, 6.0) && near(r.host_s, 6.0), "{r:#?}");
}

#[test]
fn a16_nothing_on_the_host_single_path() {
    let r = attribute(&wifi(30));
    assert_eq!(r.attribution, Attribution::Network, "{r:#?}");
    assert_eq!(r.confidence, Confidence::Low, "{r:#?}");
}

#[test]
fn a17_scan_with_ap_deauth_is_mixed() {
    let mut f = eth_ok(wifi(12));
    f.scan_ticks = 3;
    f.ap_disconnect = true;
    let r = attribute(&f);
    assert_eq!(r.attribution, Attribution::Mixed, "{r:#?}");
    assert_eq!(r.confidence, Confidence::High, "{r:#?}");
    assert!(near(r.host_s, 5.0), "{r:#?}");
}

#[test]
fn a18_low_memory_explains_at_most_15s() {
    let mut f = eth_ok(wifi(20));
    f.low_memory_near = true;
    let r = attribute(&f);
    assert_eq!(r.attribution, Attribution::Mixed, "{r:#?}");
    assert!(near(r.host_s, 15.0), "{r:#?}");
    assert!(near(r.network_s, 5.0), "{r:#?}");
}

#[test]
fn a19_throttling_covers_short_outage() {
    let mut f = eth_ok(wifi(4));
    f.throttled_near = true;
    let r = attribute(&f);
    assert_eq!(r.attribution, Attribution::ObserverLikely, "{r:#?}");
}

#[test]
fn a20_weak_hint_does_not_outweigh_two_failing_paths() {
    let mut f = both_out(wifi(6));
    f.throttled_near = true;
    let r = attribute(&f);
    assert_eq!(r.attribution, Attribution::NetworkDespiteHost, "{r:#?}");
    assert_eq!(r.confidence, Confidence::High, "{r:#?}");
}

#[test]
fn a21_router_reboot_is_network() {
    for f in [wifi(90), eth(90)] {
        let mut f = both_out(f);
        f.router_reboot_near = true;
        let r = attribute(&f);
        assert_eq!(r.attribution, Attribution::Network, "{r:#?}");
        assert_eq!(r.confidence, Confidence::High, "{r:#?}");
        assert_eq!(r.network_causes.first(), Some(&NetworkCause::RouterReboot), "{r:#?}");
    }
}

#[test]
fn a22_channel_switch_is_network() {
    let mut f = eth_ok(wifi(6));
    f.channel_switch_near = true;
    let r = attribute(&f);
    assert_eq!(r.attribution, Attribution::Network, "{r:#?}");
    assert_eq!(r.confidence, Confidence::High, "{r:#?}");
    assert_eq!(r.network_causes.first(), Some(&NetworkCause::ChannelSwitch), "{r:#?}");
}

#[test]
fn a23_roam_is_only_a_hint() {
    let mut f = eth_ok(wifi(3));
    f.roam_near = true;
    let r = attribute(&f);
    assert_eq!(r.attribution, Attribution::Network, "{r:#?}");
    assert_eq!(r.confidence, Confidence::Medium, "{r:#?}");
    assert!(r.network_causes.contains(&NetworkCause::Roam), "{r:#?}");
}

#[test]
fn a24_roam_does_not_contradict_scan() {
    let mut f = eth_ok(wifi(3));
    f.roam_near = true;
    f.scan_ticks = 2;
    let r = attribute(&f);
    assert_eq!(r.attribution, Attribution::ObserverConfirmed, "{r:#?}");
}

#[test]
fn a25_weak_signal() {
    let mut f = eth_ok(wifi(20));
    f.signal_dbm = Some(-82.0);
    let r = attribute(&f);
    assert_eq!(r.attribution, Attribution::Network, "{r:#?}");
    assert_eq!(r.confidence, Confidence::Medium, "{r:#?}");
    assert!(r.network_causes.contains(&NetworkCause::WeakSignal), "{r:#?}");
}

#[test]
fn a26_busy_channel() {
    let mut f = eth_ok(wifi(10));
    f.busy_pct = Some(85.0);
    let r = attribute(&f);
    assert_eq!(r.attribution, Attribution::Network, "{r:#?}");
    assert_eq!(r.confidence, Confidence::Medium, "{r:#?}");
    assert!(r.network_causes.contains(&NetworkCause::BusyChannel), "{r:#?}");
}

#[test]
fn a27_no_ip_is_dhcp() {
    let mut f = eth_ok(wifi(30));
    f.no_ip = true;
    let r = attribute(&f);
    assert_eq!(r.attribution, Attribution::Network, "{r:#?}");
    assert_eq!(r.confidence, Confidence::Medium, "{r:#?}");
    assert!(r.network_causes.contains(&NetworkCause::Dhcp), "{r:#?}");
}

#[test]
fn a28_short_outage_with_clock_jump_is_observer() {
    for f in [wifi(4), eth(4)] {
        let mut f = both_out(f);
        f.clock_jump_near = true;
        let r = attribute(&f);
        assert_eq!(r.attribution, Attribution::ObserverConfirmed, "{r:#?}");
    }
}

#[test]
fn a29_clock_jump_explains_only_5s_of_60() {
    for f in [wifi(60), eth(60)] {
        let mut f = both_out(f);
        f.clock_jump_near = true;
        let r = attribute(&f);
        assert_eq!(r.attribution, Attribution::NetworkDespiteHost, "{r:#?}");
    }
}

#[test]
fn a30_scan_and_channel_change_is_mixed() {
    let mut f = eth_ok(wifi(8));
    f.scan_ticks = 3;
    f.channel_switch_near = true;
    let r = attribute(&f);
    assert_eq!(r.attribution, Attribution::Mixed, "{r:#?}");
    assert_eq!(r.confidence, Confidence::High, "{r:#?}");
    assert!(near(r.host_s, 5.0), "{r:#?}");
    assert!(r.network_causes.contains(&NetworkCause::ChannelSwitch), "{r:#?}");
}

#[test]
fn a31_carrier_loss_on_cable() {
    let mut f = eth_ok(eth(5));
    f.carrier_loss_near = true;
    let r = attribute(&f);
    assert_eq!(r.attribution, Attribution::Network, "{r:#?}");
    assert_eq!(r.confidence, Confidence::High, "{r:#?}");
    assert_eq!(r.network_causes.first(), Some(&NetworkCause::CarrierLoss), "{r:#?}");
}

#[test]
fn a32_strong_overrun_with_router_log_is_mixed() {
    let mut f = eth_ok(wifi(30));
    f.overrun_ticks = 15;
    f.router_hit = true;
    let r = attribute(&f);
    assert_eq!(r.attribution, Attribution::Mixed, "{r:#?}");
    assert_eq!(r.confidence, Confidence::High, "{r:#?}");
    assert!(near(r.host_s, 15.0), "{r:#?}");
}

#[test]
fn a33_own_traffic_on_both_paths_is_observer() {
    for f in [wifi(10), eth(10)] {
        let mut f = f;
        let (name, role) = if f.role == IfaceRole::Wifi { ("eth0", IfaceRole::Ethernet) } else { ("wlo1", IfaceRole::Wifi) };
        f.other_failed = vec![failed(name, role, true)];
        f.comparable_paths = 1;
        f.self_traffic_ticks = 10;
        let r = attribute(&f);
        assert_eq!(r.attribution, Attribution::ObserverConfirmed, "{:?}: {r:#?}", f.role);
    }
}

#[test]
fn a34_power_save_contradicted_by_channel_change() {
    let mut f = eth_ok(wifi(3));
    f.power_save_on = true;
    f.channel_switch_near = true;
    let r = attribute(&f);
    assert_eq!(r.attribution, Attribution::NetworkDespiteHost, "{r:#?}");
    assert_eq!(r.confidence, Confidence::High, "{r:#?}");
    assert!(r.network_causes.contains(&NetworkCause::ChannelSwitch), "{r:#?}");
}

// ---------------------------------------------------------------------------------------------
// End-to-end through the Analyzer.
// ---------------------------------------------------------------------------------------------

fn env(ts: DateTime<Utc>, rec: Record) -> Envelope {
    Envelope { v: 1, run: "r".into(), seq: 0, ts, mono_ns: 0, rec }
}
fn samp(iface: &str, role: IfaceRole, state: PathState, gw_rtt: f64) -> Record {
    Record::Sample(Sample {
        iface: iface.into(),
        role,
        link: LinkState::default(),
        gw: Some(if is_bad(state) { ProbeResult::fail("timeout") } else { ProbeResult::ok(gw_rtt) }),
        isp: None,
        net: MultiResult { ok: if is_bad(state) { 0 } else { 3 }, of: 3, rtt_ms: Some(15.0) },
        tcp: None,
        dns: None,
        rx_delta: 0,
        tx_delta: 0,
        state,
        speedtest_active: false,
        overrun: false,
        scan_active: false,
        t: None,
        freq_mhz: None,
        pkt_delta: None,
    })
}

fn t0() -> DateTime<Utc> {
    DateTime::from_timestamp(1_800_000_000, 0).unwrap()
}

/// 300 s of samples; `wifi_bad` and `eth_bad` are second ranges with state `bad`.
fn run(
    wifi_bad: std::ops::Range<i64>,
    eth_bad: std::ops::Range<i64>,
    bad: PathState,
    extra: Vec<(i64, Record)>,
) -> Report {
    let mut a = Analyzer::new(Opts::default());
    for i in 0..300 {
        let t = t0() + Duration::seconds(i);
        let w = if wifi_bad.contains(&i) { bad } else { PathState::Ok };
        let e = if eth_bad.contains(&i) { bad } else { PathState::Ok };
        a.push(&env(t, samp("wlo1", IfaceRole::Wifi, w, 3.0)));
        a.push(&env(t, samp("eth0", IfaceRole::Ethernet, e, 1.0)));
    }
    for (sec, rec) in extra {
        a.push(&env(t0() + Duration::seconds(sec), rec));
    }
    a.finish(&[])
}

fn ep<'a>(r: &'a Report, iface: &str) -> &'a Episode {
    let v: Vec<&Episode> = r.episodes.iter().filter(|e| e.iface == iface).collect();
    assert_eq!(v.len(), 1, "{iface}: {:#?}", r.episodes);
    v[0]
}

#[test]
fn a10_e2e_driver_reset_after_start() {
    let r = run(
        100..140,
        0..0,
        PathState::LanDown,
        vec![(120, Record::Event(EventKind::HostAlert { alert: HostAlertKind::DriverReset, detail: "wlo1: firmware restarted".into(), iface: None }))],
    );
    let f = &ep(&r, "wlo1").finding;
    assert_eq!(f.attribution, Attribution::Network, "{f:#?}");
    assert!(f.evidence.iter().any(|e| e.msg.code == "a_driver_reset_after"), "{f:#?}");
}

#[test]
fn a21_e2e_router_reboot() {
    let router = |up| Record::Router(RouterSample { uptime_s: Some(up), ..Default::default() });
    let r = run(100..190, 100..190, PathState::LanDown, vec![(50, router(5000)), (150, router(20))]);
    for iface in ["wlo1", "eth0"] {
        let f = &ep(&r, iface).finding;
        assert_eq!(f.attribution, Attribution::Network, "{iface}: {f:#?}");
        assert_eq!(f.confidence, Confidence::High, "{iface}: {f:#?}");
        assert_eq!(f.network_causes.first(), Some(&NetworkCause::RouterReboot), "{iface}: {f:#?}");
    }
}

#[test]
fn a22_e2e_channel_switch() {
    let r = run(
        100..106,
        0..0,
        PathState::LanDown,
        vec![(101, Record::Event(EventKind::ChannelChange { iface: "wlo1".into(), from_mhz: Some(5180), to_mhz: Some(5500) }))],
    );
    let f = &ep(&r, "wlo1").finding;
    assert_eq!(f.attribution, Attribution::Network, "{f:#?}");
    assert_eq!(f.confidence, Confidence::High, "{f:#?}");
    assert_eq!(f.network_causes.first(), Some(&NetworkCause::ChannelSwitch), "{f:#?}");
}

#[test]
fn a28_e2e_clock_jump() {
    let r = run(
        100..104,
        100..104,
        PathState::LanDown,
        vec![(101, Record::Event(EventKind::ClockJump { wall_delta_s: 30.0, mono_delta_s: 1.0 }))],
    );
    for iface in ["wlo1", "eth0"] {
        let f = &ep(&r, iface).finding;
        assert_eq!(f.attribution, Attribution::ObserverConfirmed, "{iface}: {f:#?}");
    }
}

#[test]
fn a31_e2e_carrier_loss() {
    let up = LinkState { present: true, up: true, carrier: true, ..Default::default() };
    let down = LinkState { present: true, up: true, carrier: false, ..Default::default() };
    let r = run(
        0..0,
        100..105,
        PathState::LanDown,
        vec![(100, Record::Event(EventKind::LinkChange { iface: "eth0".into(), from: up, to: down }))],
    );
    let f = &ep(&r, "eth0").finding;
    assert_eq!(f.attribution, Attribution::Network, "{f:#?}");
    assert_eq!(f.confidence, Confidence::High, "{f:#?}");
    assert_eq!(f.network_causes.first(), Some(&NetworkCause::CarrierLoss), "{f:#?}");
}
