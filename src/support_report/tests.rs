use super::*;
use crate::analyze::{BandStats, IfaceReport, LanReport, Msg, Report, RouterReport, parse_router_log};
use crate::compare::SessionView;
use crate::cve::CveItem;
use crate::model::{IncidentOrigin, IfaceRole, NetworkFingerprint, PathState, SessionMeta, Verdict};
use crate::router_audit::PortCheck;
use chrono::{Duration, Utc};
use std::collections::BTreeMap;
use std::net::Ipv4Addr;

fn base_fp() -> NetworkFingerprint {
    NetworkFingerprint {
        gateway_ip: Some(Ipv4Addr::new(192, 168, 0, 1)),
        gateway_mac: Some("aa:bb:cc:11:22:33".into()),
        subnet: Some("192.168.0.0/24".into()),
        bssids: vec!["aa:bb:cc:44:55:66".into()],
        isp_hop: Some(Ipv4Addr::new(198, 51, 100, 9)),
    }
}

fn mk_meta(id: &str, point: Option<&str>, label: Option<&str>, note: Option<&str>, sync: Option<bool>) -> SessionMeta {
    SessionMeta {
        v: 1,
        session: id.into(),
        started: DateTime::from_timestamp(1_800_000_000, 0).unwrap(),
        host: "probe-host-1".into(),
        version: "0.5.0".into(),
        point: point.map(String::from),
        label: label.map(String::from),
        note: note.map(String::from),
        config: serde_json::json!({}),
        host_id: None,
        tz_offset_s: Some(0),
        clock_synced: sync,
        network: Some(base_fp()),
    }
}

#[allow(clippy::too_many_arguments)]
fn mk_ep(iface: &str, role: IfaceRole, start: DateTime<Utc>, secs: i64, state: PathState, cause: Verdict, origin: IncidentOrigin, speedtest: bool) -> Episode {
    Episode {
        iface: iface.into(),
        role,
        start,
        end: start + Duration::seconds(secs),
        duration_s: secs as f64,
        ticks: secs as u32,
        state,
        cause: Some(cause),
        origin,
        band: (role == IfaceRole::Wifi).then(|| "5 GHz".into()),
        speedtest_active: speedtest,
        context: vec![],
        context_msg: vec![],
    }
}

fn mk_session(id: &str, label: &str, point: Option<&str>, hours: f64, ifaces: Vec<IfaceReport>, episodes: Vec<Episode>) -> SessionView {
    let t0 = DateTime::from_timestamp(1_800_000_000, 0).unwrap();
    let t1 = t0 + Duration::milliseconds((hours * 3_600_000.0) as i64);
    let mut net_inc = 0u32;
    let mut load_inc = 0u32;
    let mut obs_inc = 0u32;
    let mut incidents = BTreeMap::new();
    let mut causes = BTreeMap::new();
    for ep in &episodes {
        if ep.origin == IncidentOrigin::Observer {
            obs_inc += 1;
        } else if is_load_provoked(ep) {
            load_inc += 1;
        } else {
            net_inc += 1;
            let k = ep.cause.map_or("unknown", Verdict::as_str).to_string();
            *incidents.entry(k.clone()).or_default() += 1;
            *causes.entry(k).or_default() += 1;
        }
    }
    SessionView {
        id: id.into(),
        label: label.into(),
        meta: Some(mk_meta(id, point, Some(label), None, Some(true))),
        network: base_fp(),
        clock_synced: Some(true),
        clock_jumps: 0,
        gaps: vec![],
        report: Report {
            from: Some(t0),
            to: Some(t1),
            hours,
            ifaces,
            episodes,
            causes,
            incidents,
            tick_s: 1.0,
            micro_max_s: 2.0,
            observer_incidents: obs_inc,
            network_incidents: net_inc,
            load_incidents: load_inc,
            ..Default::default()
        },
    }
}

fn mk_iface(iface: &str, role: IfaceRole, avail: f64, ep: u32, sig: Option<f64>, retries: Option<f64>) -> IfaceReport {
    IfaceReport {
        iface: iface.into(),
        role: Some(role),
        ticks: 28_800,
        had_link: true,
        availability_pct: avail,
        episodes: ep,
        gw_rtt_med: Some(if role == IfaceRole::Ethernet { 1.2 } else { 4.5 }),
        net_rtt_med: Some(12.4),
        signal_med: sig,
        retry_rate_per_min: retries,
        speed_med_mbps: Some(320.0),
        bands: if role == IfaceRole::Wifi {
            vec![BandStats { band: "5 GHz".into(), ticks: 28_800, availability_pct: avail, signal_med: sig, ..Default::default() }]
        } else {
            Default::default()
        },
        ..Default::default()
    }
}

#[test]
fn s1_ideal_dual_path_isp_line_outage_and_docsis_match() {
    let t0 = DateTime::from_timestamp(1_800_000_000, 0).unwrap();
    let ep_ts = t0 + Duration::hours(2);
    let mut sv = mk_session(
        "s1",
        "kitchen",
        Some("B1/F1/K"),
        8.0,
        vec![
            mk_iface("eth0", IfaceRole::Ethernet, 98.5, 1, None, None),
            mk_iface("wlo1", IfaceRole::Wifi, 98.5, 1, Some(-52.0), Some(12.0)),
        ],
        vec![mk_ep("eth0", IfaceRole::Ethernet, ep_ts, 30, PathState::IspDown, Verdict::LineProblem, IncidentOrigin::Network, false)],
    );
    sv.report.router = Some(RouterReport { samples: 500, uptime_resets: 0, wan_down_samples: 3, ..Default::default() });
    let docsis_line = format!("{} Critical SYNC Timing Synchronization failure", ep_ts.with_timezone(&Local).format("%m/%d/%Y %H:%M:%S"));
    let router_log = parse_router_log(&docsis_line);

    let pack = build_pack(
        &SupportInput { sessions: &[sv], site: None, router_audit: None, cve: None, router_log: &router_log },
        &SupportOpts { audience: SupportAudience::Isp, lang: SupportLang::En, redaction: RedactionLevel::Standard, tolerance_s: 2.0 },
    );
    assert_eq!(pack.readiness.level, ReadinessLevel::High);
    assert!(!pack.readiness.do_not_file_isp_line_ticket);
    assert!(pack.ruled_out.wired_ethernet_tested);
    assert!(pack.ruled_out.router_zero_reboots);
    assert!(pack.asks.iter().any(|a| a.code == "isp_check_access_line"));
    assert_eq!(pack.incidents.len(), 1);
    assert!(pack.incidents[0].detail.contains("DOCSIS"));
    assert!(pack.short_text.contains("UTC"));
}

#[test]
fn s2_wifi_only_negative_gating_and_landlord_poe_advice() {
    let t0 = DateTime::from_timestamp(1_800_000_000, 0).unwrap();
    let mut sv_eth = mk_session(
        "k",
        "kitchen",
        Some("B1/F1/K"),
        8.0,
        vec![mk_iface("eth0", IfaceRole::Ethernet, 100.0, 0, None, None)],
        vec![],
    );
    sv_eth.report.findings_msg.push(Msg { code: "f_lan".into(), text: "Active LAN devices: median 10, peak 15, distinct seen 20 (across 8 sweep(s)).".into(), args: BTreeMap::new() });
    let sv_wifi = mk_session(
        "r2",
        "Bedroom 2",
        Some("B1/F1/R2"),
        8.0,
        vec![mk_iface("wlo1", IfaceRole::Wifi, 98.4, 3, Some(-73.0), Some(240.0))],
        vec![mk_ep("wlo1", IfaceRole::Wifi, t0 + Duration::hours(1), 8, PathState::LanDown, Verdict::WifiProblem, IncidentOrigin::Network, false)],
    );

    let sessions = [sv_eth, sv_wifi];
    let isp_pack = build_pack(
        &SupportInput { sessions: &sessions, site: None, router_audit: None, cve: None, router_log: &[] },
        &SupportOpts { audience: SupportAudience::Isp, ..Default::default() },
    );
    assert!(isp_pack.readiness.do_not_file_isp_line_ticket);
    assert_eq!(isp_pack.readiness.suggested_audience, Some(SupportAudience::Landlord));
    assert!(!isp_pack.asks.iter().any(|a| a.code == "isp_check_access_line"));

    let landlord_pack = build_pack(
        &SupportInput { sessions: &sessions, site: None, router_audit: None, cve: None, router_log: &[] },
        &SupportOpts { audience: SupportAudience::Landlord, ..Default::default() },
    );
    let poe = landlord_pack.asks.iter().find(|a| a.code == "landlord_wired_hallway_ap").expect("PoE ask present");
    assert!(poe.rationale.contains("PoE injector"));
    assert!(poe.rationale.contains("zero power socket"));
    assert!(landlord_pack.asks.iter().any(|a| a.code == "landlord_avoid_wireless_repeaters"));
}

#[test]
fn s3_speedtest_load_only_suppressed_from_unprovoked_isp_ticket() {
    let t0 = DateTime::from_timestamp(1_800_000_000, 0).unwrap();
    let mut eth = mk_iface("eth0", IfaceRole::Ethernet, 99.9, 0, None, None);
    eth.loaded_net_rtt_med = Some(320.0);
    eth.net_rtt_med = Some(12.0);
    let sv = mk_session(
        "s3",
        "kitchen",
        None,
        8.0,
        vec![eth],
        vec![mk_ep("eth0", IfaceRole::Ethernet, t0 + Duration::hours(1), 6, PathState::WanDown, Verdict::LineProblem, IncidentOrigin::Network, true)],
    );

    let pack = build_pack(
        &SupportInput { sessions: &[sv], site: None, router_audit: None, cve: None, router_log: &[] },
        &SupportOpts { audience: SupportAudience::Isp, ..Default::default() },
    );
    assert!(pack.readiness.do_not_file_isp_line_ticket);
    assert!(pack.asks.iter().any(|a| a.code == "sqm_or_bridge_mode"));
    assert!(!pack.asks.iter().any(|a| a.code == "isp_check_access_line"));
}

#[test]
fn s4_router_reboots_and_s5_household_surge_and_s6_dns() {
    let t0 = DateTime::from_timestamp(1_800_000_000, 0).unwrap();
    let mut sv = mk_session(
        "s4",
        "kitchen",
        None,
        8.0,
        vec![
            mk_iface("eth0", IfaceRole::Ethernet, 98.0, 2, None, None),
            mk_iface("wlo1", IfaceRole::Wifi, 98.0, 2, Some(-50.0), Some(10.0)),
        ],
        vec![
            mk_ep("eth0", IfaceRole::Ethernet, t0 + Duration::minutes(30), 15, PathState::LanDown, Verdict::RouterProblem, IncidentOrigin::Network, false),
            mk_ep("eth0", IfaceRole::Ethernet, t0 + Duration::minutes(90), 10, PathState::DnsDown, Verdict::Dns, IncidentOrigin::Network, false),
        ],
    );
    sv.report.router = Some(RouterReport { samples: 200, uptime_resets: 2, ..Default::default() });
    sv.report.findings_msg.push(Msg { code: "f_evening_rtt".into(), text: "eth0: evening internet RTT spikes".into(), args: BTreeMap::new() });
    sv.report.findings_msg.push(Msg { code: "f_lan_evening".into(), text: "Evening client count increases (median 12 vs 5).".into(), args: BTreeMap::new() });

    let pack = build_pack(
        &SupportInput { sessions: &[sv], site: None, router_audit: None, cve: None, router_log: &[] },
        &SupportOpts { audience: SupportAudience::Admin, ..Default::default() },
    );
    assert!(pack.asks.iter().any(|a| a.code == "replace_or_inspect_router"));
    assert!(pack.asks.iter().any(|a| a.code == "dns_resolver_check"));
    assert!(!pack.asks.iter().any(|a| a.code == "isp_evening_congestion"));
    assert!(pack.findings.iter().any(|f| f.contains("household device count")));
}

#[test]
fn s7_security_rogue_dhcp_cve_and_passive_scope() {
    let mut sv = mk_session("s7", "kitchen", None, 4.0, vec![mk_iface("eth0", IfaceRole::Ethernet, 100.0, 0, None, None)], vec![]);
    sv.report.security_events.push("12:00:00 [high] rogue_gateway (eth0): second DHCP at aa:bb:cc:11:22:99 (192.168.42.99)".into());

    let no_audit = build_pack(
        &SupportInput { sessions: &[sv.clone()], site: None, router_audit: None, cve: None, router_log: &[] },
        &SupportOpts { audience: SupportAudience::Isp, ..Default::default() },
    );
    assert!(no_audit.readiness.do_not_file_isp_line_ticket);
    assert!(no_audit.asks.iter().any(|a| a.code == "local_rogue_dhcp"));

    let admin_no_audit = build_pack(
        &SupportInput { sessions: &[sv.clone()], site: None, router_audit: None, cve: None, router_log: &[] },
        &SupportOpts { audience: SupportAudience::Admin, ..Default::default() },
    );
    assert!(admin_no_audit.security_notes.iter().any(|s| s.contains("passive")));

    let audit = RouterAudit {
        adapter_used: "upnp".into(),
        ports: vec![PortCheck { port: 23, service: "telnet".into(), open: true, risk: "high".into() }],
        ..Default::default()
    };
    let cve = CveLookupResponse {
        queried_at: Utc::now(),
        cached: false,
        source: "nvd".into(),
        query: "Router".into(),
        total: 1,
        kev_count: 1,
        items: vec![CveItem { id: "CVE-2025-0001".into(), severity: "CRITICAL".into(), cvss: Some(9.8), kev: true, summary: "rce".into(), published: None, url: "".into() }],
        note: None,
    };
    let with_audit = build_pack(
        &SupportInput { sessions: &[sv], site: None, router_audit: Some(&audit), cve: Some(&cve), router_log: &[] },
        &SupportOpts { audience: SupportAudience::Admin, ..Default::default() },
    );
    assert!(with_audit.asks.iter().any(|a| a.code == "admin_firmware_hardening"));
}

#[test]
fn s8_s9_s10_s11_s12_redaction_length_escaping_and_i18n() {
    let t0 = DateTime::from_timestamp(1_800_000_000, 0).unwrap();
    let mut eps = Vec::new();
    for i in 0..100 {
        eps.push(mk_ep("eth0", IfaceRole::Ethernet, t0 + Duration::seconds(i * 40), 5, PathState::IspDown, Verdict::LineProblem, IncidentOrigin::Network, false));
    }
    let mut s_early = mk_session(
        "early",
        "Living Room | Flat",
        Some("B1/F1/R1"),
        1.2, // S8 short run -> Low
        vec![mk_iface("eth0", IfaceRole::Ethernet, 95.0, 100, Some(-78.0), Some(150.0))],
        eps,
    );
    s_early.label = "Living Room | <script>alert(1)</script>".into();
    s_early.meta = Some(mk_meta("early", Some("B1/F1/R1"), Some("Living Room | <script>alert(1)</script>"), Some("token=secret123 path /home/alice/secret on 192.168.42.10 MAC aa:bb:cc:dd:ee:ff SSID \"MyPrivateWifi\""), Some(false)));
    s_early.clock_synced = Some(false);
    s_early.report.observer_findings_msg.push(Msg { code: "o_power_save".into(), text: "Wi-Fi power-save was ON".into(), args: BTreeMap::new() });
    s_early.report.findings_msg.push(Msg { code: "f_lan".into(), text: "Active LAN devices: median 9, peak 14".into(), args: BTreeMap::new() });
    s_early.report.lan = Some(LanReport { samples: 10, arp_alive_med: Some(9.0), arp_alive_max: Some(14), ..Default::default() });

    let mut s_late = mk_session(
        "late",
        "Living Room",
        Some("B1/F1/R1"),
        7.0,
        vec![mk_iface("eth0", IfaceRole::Ethernet, 99.9, 0, Some(-52.0), Some(12.0))],
        vec![],
    );
    s_late.report.from = Some(t0 + Duration::hours(24));
    s_late.report.to = Some(t0 + Duration::hours(31));

    // Standard: masks MAC/paths, omits LAN occupancy, keeps point name; Low readiness (S8/S11).
    let std_uk = build_pack(
        &SupportInput { sessions: &[s_early.clone(), s_late.clone()], site: None, router_audit: None, cve: None, router_log: &[] },
        &SupportOpts { audience: SupportAudience::Isp, lang: SupportLang::Uk, redaction: RedactionLevel::Standard, tolerance_s: 2.0 },
    );
    assert_eq!(std_uk.readiness.level, ReadinessLevel::Low);
    assert!(std_uk.short_text.chars().count() <= 2000, "len={}", std_uk.short_text.chars().count());
    assert!(std_uk.title.contains("провайдера"));
    assert!(std_uk.findings.iter().any(|f| f.contains("До / Після")));
    assert!(!std_uk.findings.iter().any(|f| f.contains("LAN devices")), "{:#?}", std_uk.findings);
    let md_uk = render_markdown(&std_uk);
    assert!(md_uk.contains("Living Room \\|"));
    assert!(!md_uk.contains("aa:bb:cc:dd:ee:ff"));
    assert!(md_uk.contains("xx:xx:xx:dd:ee:ff"));
    assert!(!md_uk.contains("/home/alice"));
    assert!(!md_uk.contains("token=secret123"));
    let html_uk = render_html(&std_uk);
    assert!(!html_uk.contains("<script>alert(1)</script>"));
    assert!(html_uk.contains("&lt;script&gt;"));
    assert!(!html_uk.contains("<script"));
    assert!(!html_uk.contains("http://") && !html_uk.contains("https://"));

    // Strict: strips IPs, SSIDs, hostnames, generalizes point labels.
    let strict_en = build_pack(
        &SupportInput { sessions: &[s_early], site: None, router_audit: None, cve: None, router_log: &[] },
        &SupportOpts { audience: SupportAudience::Admin, lang: SupportLang::En, redaction: RedactionLevel::Strict, tolerance_s: 2.0 },
    );
    assert_eq!(strict_en.points[0].label, "Point A");
    let joined_notes = strict_en.free_text_notes.join(" ");
    assert!(!joined_notes.contains("192.168.42.10"), "{joined_notes}");
    assert!(joined_notes.contains("192.0.2."));
    assert!(!joined_notes.contains("MyPrivateWifi"), "{joined_notes}");
    assert!(!joined_notes.contains("/home/alice"), "{joined_notes}");
}

#[test]
fn s11_different_networks_downgrade_readiness() {
    let s1 = mk_session("n1", "Flat 1", Some("B1/F1/R1"), 8.0, vec![mk_iface("eth0", IfaceRole::Ethernet, 99.0, 1, None, None)], vec![]);
    let mut s2 = mk_session("n2", "Flat 2", Some("B1/F2/R1"), 8.0, vec![mk_iface("eth0", IfaceRole::Ethernet, 99.0, 1, None, None)], vec![]);
    let diff_fp = NetworkFingerprint {
        gateway_mac: Some("11:22:33:44:55:99".into()),
        subnet: Some("10.20.0.0/24".into()),
        ..Default::default()
    };
    s2.network = diff_fp;

    let pack = build_pack(
        &SupportInput { sessions: &[s1, s2], site: None, router_audit: None, cve: None, router_log: &[] },
        &SupportOpts { audience: SupportAudience::Isp, ..Default::default() },
    );
    assert_eq!(pack.readiness.level, ReadinessLevel::Low);
    assert!(pack.readiness.warning_codes.contains(&"warn_network_mismatch".to_string()));
}

#[test]
fn polluted_observer_lowers_readiness() {
    let mut s = mk_session(
        "late-ticks",
        "Hall",
        Some("B1/F1/R1"),
        8.0,
        vec![mk_iface("eth0", IfaceRole::Ethernet, 99.9, 0, None, None), mk_iface("wlo1", IfaceRole::Wifi, 99.9, 0, Some(-55.0), Some(5.0))],
        vec![],
    );
    s.clock_synced = Some(true);
    s.meta = Some(mk_meta("late-ticks", Some("B1/F1/R1"), Some("Hall"), None, Some(true)));
    let opts = SupportOpts { audience: SupportAudience::Admin, lang: SupportLang::En, redaction: RedactionLevel::Standard, tolerance_s: 2.0 };
    let clean = build_pack(&SupportInput { sessions: std::slice::from_ref(&s), site: None, router_audit: None, cve: None, router_log: &[] }, &opts);
    assert!(!clean.readiness.warning_codes.iter().any(|c| c == "warn_observer_polluted"));
    s.report.observer_trust = crate::analyze::ObserverTrust {
        level: crate::analyze::TrustLevel::Polluted,
        reasons: vec![Msg { code: "t_overrun".into(), text: "2.0% of probe ticks were late".into(), args: BTreeMap::new() }],
    };
    let p = build_pack(&SupportInput { sessions: std::slice::from_ref(&s), site: None, router_audit: None, cve: None, router_log: &[] }, &opts);
    assert_eq!(p.readiness.level, ReadinessLevel::Low, "{:?}", p.readiness);
    assert!(p.readiness.warning_codes.iter().any(|c| c == "warn_observer_polluted"));
}
