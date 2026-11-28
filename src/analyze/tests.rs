use super::*;
use super::detect::*;
use super::engine::*;

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

#[test]
fn episodes_merge_and_cause() {
    let t0 = DateTime::from_timestamp(1_800_000_000, 0).unwrap();
    let mut a = Analyzer::new(Opts::default());
    for i in 0..600 {
        let t = t0 + Duration::seconds(i);
        // Wi-Fi: outage 100..110 and a blip at 300; cable always fine.
        let w = if (100..110).contains(&i) || i == 300 || i == 103 { PathState::LanDown } else { PathState::Ok };
        a.push(&env(t, samp("wlo1", IfaceRole::Wifi, w, 3.0)));
        // Cable: outage 400..420 together with Wi-Fi below.
        let c = if (400..420).contains(&i) { PathState::IspDown } else { PathState::Ok };
        a.push(&env(t, samp("eth0", IfaceRole::Ethernet, c, 1.0)));
        if (400..420).contains(&i) {
            // Overwrite Wi-Fi with line failure as well (second sample same tick is fine for the test).
            a.push(&env(t, samp("wlo1", IfaceRole::Wifi, PathState::IspDown, 3.0)));
        }
    }
    let r = a.finish(&[]);
    let w: Vec<&Episode> = r.episodes.iter().filter(|e| e.iface == "wlo1").collect();
    assert_eq!(w.len(), 3, "{w:#?}");
    assert_eq!(w[0].cause, Some(Verdict::WifiProblem));
    assert!((w[0].duration_s - 10.0).abs() < 1.1);
    assert_eq!(w[1].duration_s, 1.0); // micro-drop
    assert_eq!(w[2].cause, Some(Verdict::LineProblem));
    let wi = r.ifaces.iter().find(|i| i.iface == "wlo1").unwrap();
    assert_eq!(wi.micro_drops, 1);
    assert_eq!(wi.episodes, 2);
}

#[test]
fn unplugged_cable_is_not_an_outage_and_not_a_witness() {
    let t0 = DateTime::from_timestamp(1_800_000_000, 0).unwrap();
    let mut a = Analyzer::new(Opts::default());
    for i in 0..120 {
        let t = t0 + Duration::seconds(i);
        let w = if (50..60).contains(&i) { PathState::LanDown } else { PathState::Ok };
        a.push(&env(t, samp("wlo1", IfaceRole::Wifi, w, 3.0)));
        a.push(&env(t, samp("eth0", IfaceRole::Ethernet, PathState::LinkDown, 1.0)));
    }
    let r = a.finish(&[]);
    assert!(r.episodes.iter().all(|e| e.iface == "wlo1"));
    assert_eq!(r.episodes[0].cause, Some(Verdict::SinglePath));
    assert!(r.findings.iter().any(|f| f.contains("never had link")));
}

#[test]
fn wifi_disassociation_is_a_wifi_outage() {
    let t0 = DateTime::from_timestamp(1_800_000_000, 0).unwrap();
    let mut a = Analyzer::new(Opts::default());
    for i in 0..120 {
        let t = t0 + Duration::seconds(i);
        let w = if (50..60).contains(&i) { PathState::LinkDown } else { PathState::Ok };
        a.push(&env(t, samp("wlo1", IfaceRole::Wifi, w, 3.0)));
        a.push(&env(t, samp("eth0", IfaceRole::Ethernet, PathState::Ok, 1.0)));
    }
    let r = a.finish(&[]);
    assert_eq!(r.episodes.len(), 1, "{:?}", r.episodes);
    assert_eq!(r.episodes[0].cause, Some(Verdict::WifiProblem));
    assert_eq!(r.incidents.get("wifi_problem"), Some(&1));
}

#[test]
fn durations_follow_the_probe_interval() {
    let t0 = DateTime::from_timestamp(1_800_000_000, 0).unwrap();
    let meta = SessionMeta {
        v: 1,
        session: "s".into(),
        started: t0,
        host: "h".into(),
        version: "0".into(),
        point: None,
        label: None,
        note: None,
        config: serde_json::json!({"intervals": {"probe_ms": 5000}}),
        host_id: None,
        tz_offset_s: None,
        clock_synced: None,
        network: None,
    };
    let o = Opts::for_session(Some(&meta));
    assert_eq!(o.tick_s, 5.0);
    let mut a = Analyzer::new(o);
    for i in 0..40 {
        let t = t0 + Duration::seconds(i * 5);
        // Three bad ticks in a row = 15 s, not 11 s and not a micro-drop.
        let w = if (10..13).contains(&i) { PathState::LanDown } else { PathState::Ok };
        a.push(&env(t, samp("wlo1", IfaceRole::Wifi, w, 3.0)));
    }
    let r = a.finish(&[]);
    assert_eq!(r.episodes.len(), 1);
    assert!((r.episodes[0].duration_s - 15.0).abs() < 1e-6, "{:?}", r.episodes[0]);
    assert_eq!(r.ifaces[0].micro_drops, 0);
    assert!(r.findings.iter().any(|f| f.contains("Time resolution")));
}

#[test]
fn joint_outage_is_one_incident_and_blips_do_not_flip_cause() {
    let t0 = DateTime::from_timestamp(1_800_000_000, 0).unwrap();
    let mut a = Analyzer::new(Opts::default());
    for i in 0..200 {
        let t = t0 + Duration::seconds(i);
        let both = (50..70).contains(&i);
        let w = if both || (120..140).contains(&i) { PathState::IspDown } else { PathState::Ok };
        // Cable: the same line outage, plus a 1-tick blip inside the Wi-Fi-only outage.
        let c = if both { PathState::IspDown } else if i == 130 { PathState::LanDown } else { PathState::Ok };
        a.push(&env(t, samp("wlo1", IfaceRole::Wifi, if (120..140).contains(&i) { PathState::LanDown } else { w }, 3.0)));
        a.push(&env(t, samp("eth0", IfaceRole::Ethernet, c, 1.0)));
    }
    let r = a.finish(&[]);
    assert_eq!(r.incidents.get("line_problem"), Some(&1), "{:?}", r.incidents);
    let w2 = r.episodes.iter().find(|e| e.iface == "wlo1" && e.start > t0 + Duration::seconds(100)).unwrap();
    assert_eq!(w2.cause, Some(Verdict::WifiProblem));
}

#[test]
fn stalls_and_latency_under_load() {
    let t0 = DateTime::from_timestamp(1_800_000_000, 0).unwrap();
    let mut a = Analyzer::new(Opts::default());
    for i in 0..100 {
        let t = t0 + Duration::seconds(i);
        let rtt = if i == 40 || i == 41 { 600.0 } else { 3.0 };
        let mut rec = samp("wlo1", IfaceRole::Wifi, PathState::Ok, rtt);
        if let Record::Sample(s) = &mut rec
            && (70..80).contains(&i) {
                s.speedtest_active = true;
                s.net.rtt_ms = Some(400.0);
            }
        a.push(&env(t, rec));
    }
    let r = a.finish(&[]);
    assert_eq!(r.ifaces[0].stalls, 1);
    assert_eq!(r.ifaces[0].loaded_net_rtt_med, Some(400.0));
    assert!(r.findings.iter().any(|f| f.contains("bufferbloat")), "{:?}", r.findings);
}

#[test]
fn router_log_parsing_and_match() {
    let text = "1\t01/02/2026 03:04:05\t84000500\tCritical\tSYNC Timing Synchronization failure - Loss of Sync;CM-MAC=02:00:00:00:00:01\nno date here\n";
    let lines = parse_router_log(text);
    assert_eq!(lines.len(), 1);
    assert_eq!(lines[0].priority, "Critical");
    assert!(lines[0].text.starts_with("SYNC Timing"));
}

#[test]
fn anomalies_detected() {
    let t0 = DateTime::from_timestamp(1_800_000_000, 0).unwrap();
    let mut series: Vec<(DateTime<Utc>, f64)> = (0..120).map(|i| (t0 + Duration::minutes(i), 3.0 + (i % 3) as f64 * 0.2)).collect();
    series[60].1 = 80.0;
    series[61].1 = 90.0;
    let an = robust_anomalies("w", "router RTT ms", &series, 4.0, 1.0);
    assert_eq!(an.len(), 1);
    assert_eq!(an[0].peak, 90.0);
}

#[test]
fn periodic_pattern_found() {
    let t0 = DateTime::from_timestamp(1_800_000_000, 0).unwrap();
    let eps: Vec<Episode> = (0..6)
        .map(|i| Episode {
            iface: "w".into(),
            role: IfaceRole::Wifi,
            start: t0 + Duration::minutes(30 * i),
            end: t0 + Duration::minutes(30 * i) + Duration::seconds(5),
            duration_s: 5.0,
            ticks: 5,
            state: PathState::LanDown,
            cause: None,
            origin: IncidentOrigin::Network,
            band: None,
            speedtest_active: false,
            context: vec![],
            context_msg: vec![],
            finding: Default::default(),
        })
        .collect();
    let p = patterns(&eps, 2.5);
    assert!(p.iter().any(|x| x.text.contains("every 30 min")), "{p:?}");
}

#[test]
fn observer_incidents_excluded_and_disconnect_reason_recorded() {
    let t0 = DateTime::from_timestamp(1_800_000_000, 0).unwrap();
    let mut a = Analyzer::new(Opts::default());
    for i in 0..100 {
        let t = t0 + Duration::seconds(i);
        // Scan-induced 4s outage (observer) at i=20..24.
        let mut r = samp("wlo1", IfaceRole::Wifi, if (20..24).contains(&i) { PathState::LanDown } else { PathState::Ok }, 3.0);
        if let Record::Sample(s) = &mut r && (20..24).contains(&i) {
            s.scan_active = true;
        }
        a.push(&env(t, r));
        // Real network outage at i=60..66.
        let w2 = if (60..66).contains(&i) { PathState::LinkDown } else { PathState::Ok };
        a.push(&env(t, samp("wlo1", IfaceRole::Wifi, w2, 3.0)));
        a.push(&env(t, samp("eth0", IfaceRole::Ethernet, PathState::Ok, 1.0)));
    }
    a.push(&env(
        t0 + Duration::seconds(60),
        Record::Event(EventKind::WifiDisconnect {
            iface: "wlo1".into(),
            bssid: Some("02:00:00:00:00:01".into()),
            reason_code: Some(4),
            reason: Some("inactivity".into()),
            by_ap: Some(true),
            timed_out: false,
        }),
    ));
    let r = a.finish(&[]);
    assert_eq!(r.observer_incidents, 1, "{r:#?}");
    assert_eq!(r.network_incidents, 1, "{r:#?}");
    assert_eq!(r.incidents.get("wifi_problem"), Some(&1));
    let wlo1 = r.ifaces.iter().find(|i| i.iface == "wlo1").unwrap();
    assert_eq!(wlo1.episodes, 1, "observer scan must be excluded from IfaceReport.episodes");
    assert_eq!(wlo1.ticks, 196);
    assert!((wlo1.down_s - 6.0).abs() < 0.01);
    // 200 pushed wlo1 ticks total (2 per second in the loop): 4 scan ticks excluded -> 196 effective ticks, 6 real bad ticks.
    assert!((wlo1.availability_pct - (190.0 / 196.0 * 100.0)).abs() < 0.05, "avail={}", wlo1.availability_pct);
    let net_ep = r.episodes.iter().find(|e| e.origin == IncidentOrigin::Network).unwrap();
    assert!(net_ep.context.iter().any(|c| c.contains("reason 4 inactivity, by AP")), "{:?}", net_ep.context);
}

#[test]
fn per_band_stats_retry_rates_and_security() {
    let t0 = DateTime::from_timestamp(1_800_000_000, 0).unwrap();
    let mut a = Analyzer::new(Opts::default());
    for i in 0..40 {
        let t = t0 + Duration::seconds(i);
        let freq = if i < 20 { 2437 } else { 5180 };
        let mut rec = samp("wlo1", IfaceRole::Wifi, if i == 10 { PathState::LanDown } else { PathState::Ok }, 4.0);
        if let Record::Sample(s) = &mut rec {
            s.freq_mhz = Some(freq);
        }
        a.push(&env(t, rec));
    }
    // Retries across 20 s, including a counter reset in the middle.
    for (sec, retries, failed) in [(0, 100, 0), (10, 200, 2), (20, 50, 1)] {
        a.push(&env(
            t0 + Duration::seconds(sec),
            Record::Wifi(WifiStation {
                iface: "wlo1".into(),
                connected: true,
                freq_mhz: Some(5180),
                channel: Some(36),
                tx_retries: Some(retries),
                tx_failed: Some(failed),
                power_save: Some(true),
                ..Default::default()
            }),
        ));
    }
    a.push(&env(
        t0 + Duration::seconds(5),
        Record::Event(EventKind::Security {
            detector: "evil_twin".into(),
            severity: "medium".into(),
            iface: Some("wlo1".into()),
            detail: "unknown BSSID".into(),
        }),
    ));
    let r = a.finish(&[]);
    assert_eq!(r.ifaces[0].bands.len(), 2);
    assert_eq!(r.ifaces[0].tx_failed_total, 3);
    assert!(r.ifaces[0].retry_rate_per_min.unwrap() > 400.0);
    assert_eq!(r.security_events.len(), 1);
    assert!(r.observer_findings.iter().any(|f| f.contains("power-save")));
    assert!(r.findings.iter().any(|f| f.contains("per-band Wi-Fi comparison")));
}

#[test]
fn throttling_driver_reset_and_corroborated_outage_attribution() {
    let t0 = DateTime::from_timestamp(1_800_000_000, 0).unwrap();
    let mut a = Analyzer::new(Opts::default());
    for i in 0..150 {
        let t = t0 + Duration::seconds(i);
        let w_bad = (20..25).contains(&i) || (60..66).contains(&i) || (100..105).contains(&i);
        let e_bad = (60..66).contains(&i);
        a.push(&env(
            t,
            samp(
                "wlo1",
                IfaceRole::Wifi,
                if w_bad { PathState::WanDown } else { PathState::Ok },
                3.0,
            ),
        ));
        a.push(&env(
            t,
            samp(
                "eth0",
                IfaceRole::Ethernet,
                if e_bad { PathState::WanDown } else { PathState::Ok },
                1.0,
            ),
        ));
    }
    // Single-path throttling/undervoltage around i=20..25 -> Observer.
    a.push(&env(
        t0 + Duration::seconds(20),
        Record::Host(HostSample {
            throttled: true,
            temp_c: Some(96.0),
            rpi_throttled: Some(0x1),
            ..Default::default()
        }),
    ));
    a.push(&env(
        t0 + Duration::seconds(20),
        Record::Event(EventKind::HostAlert {
            alert: HostAlertKind::Undervoltage,
            detail: "rpi_throttled=0x1".into(),
            iface: None,
        }),
    ));
    // Corroborated dual-path WAN outage around i=60..66 while warm/throttled (not undervolt) -> stays Network!
    a.push(&env(
        t0 + Duration::seconds(62),
        Record::Host(HostSample {
            throttled: true,
            temp_c: Some(96.0),
            ..Default::default()
        }),
    ));
    // Unrelated eth0 driver_reset near i=100..105 must NOT mask wlo1 outage as Observer.
    a.push(&env(
        t0 + Duration::seconds(101),
        Record::Event(EventKind::HostAlert {
            alert: HostAlertKind::DriverReset,
            detail: "eth0: kernel ifindex changed 2 -> 5".into(),
            iface: None,
        }),
    ));
    let r = a.finish(&[]);
    assert_eq!(r.observer_incidents, 1, "{r:#?}");
    assert_eq!(r.network_incidents, 2, "{r:#?}");
    let wlo1 = r.ifaces.iter().find(|i| i.iface == "wlo1").unwrap();
    assert_eq!(wlo1.episodes, 2, "only the 2 real network episodes count");
    assert!(r.episodes.iter().any(|e| e.iface == "eth0" && e.origin == IncidentOrigin::Network));
}

#[test]
fn wifi_retry_rate_ignores_gaps_and_none_counters_and_backfills_band() {
    let t0 = DateTime::from_timestamp(1_800_000_000, 0).unwrap();
    let mut a = Analyzer::new(Opts::default());
    for i in 0..30 {
        let t = t0 + Duration::seconds(i);
        let mut rec = samp("wlo1", IfaceRole::Wifi, if (10..15).contains(&i) { PathState::LinkDown } else { PathState::Ok }, 4.0);
        if let Record::Sample(s) = &mut rec {
            // During LinkDown, Sample.freq_mhz is None; should inherit previous 5180 MHz!
            s.freq_mhz = if (10..15).contains(&i) { None } else { Some(5180) };
        }
        a.push(&env(t, rec));
    }
    // Backwards clock step episode test: last_bad < start should clamp cleanly.
    a.push(&env(t0 + Duration::seconds(200), samp("wlo1", IfaceRole::Wifi, PathState::LanDown, 4.0)));
    a.push(&env(t0 + Duration::seconds(197), samp("wlo1", IfaceRole::Wifi, PathState::LanDown, 4.0)));

    // Wifi counters separated by 300 s (> 120 s) and None tx_retries: must not inflate rate or report Some(0.0).
    for (sec, r) in [(0, None), (300, None), (310, Some(50))] {
        a.push(&env(
            t0 + Duration::seconds(sec),
            Record::Wifi(WifiStation {
                iface: "wlo1".into(),
                connected: true,
                freq_mhz: Some(5180),
                tx_retries: r,
                ..Default::default()
            }),
        ));
    }
    let rep = a.finish(&[]);
    assert_eq!(rep.ifaces[0].retry_rate_per_min, None);
    let down_ep = rep.episodes.iter().find(|e| e.state == PathState::LinkDown).unwrap();
    assert_eq!(down_ep.band.as_deref(), Some("5 GHz"));
    assert!(rep.episodes.iter().all(|e| e.duration_s >= 1.0), "{:#?}", rep.episodes);
}

#[test]
fn congestion_airtime_and_router_telemetry_findings() {
    let mut a = Analyzer::new(Opts::default());
    // Construct timestamps in local daytime (12:00) vs local evening (20:00) so peak vs off-peak check is timezone-safe.
    let today = Local::now().date_naive();
    let day_t0 = Local
        .from_local_datetime(&today.and_hms_opt(12, 0, 0).unwrap())
        .earliest()
        .unwrap()
        .with_timezone(&Utc);
    let peak_t0 = Local
        .from_local_datetime(&today.and_hms_opt(20, 0, 0).unwrap())
        .earliest()
        .unwrap()
        .with_timezone(&Utc);

    for i in 0..20 {
        let t = day_t0 + Duration::seconds(i);
        a.push(&env(t, samp("eth0", IfaceRole::Ethernet, PathState::Ok, 1.0)));
    }
    for i in 0..20 {
        let t = peak_t0 + Duration::seconds(i);
        let mut rec = samp("eth0", IfaceRole::Ethernet, PathState::Ok, 1.5);
        if let Record::Sample(s) = &mut rec {
            s.net.rtt_ms = Some(95.0);
        }
        a.push(&env(t, rec));
    }

    // Wi-Fi airtime saturation: 3 separated stalls with idle local link and busy channel.
    for s_idx in [0i64, 10, 20] {
        let t = day_t0 + Duration::seconds(s_idx);
        let mut rec = samp("wlo1", IfaceRole::Wifi, PathState::Ok, 240.0);
        if let Record::Sample(s) = &mut rec {
            s.rx_delta = 500;
            s.tx_delta = 500;
        }
        a.push(&env(t, rec));
        a.push(&env(
            t,
            Record::ChannelLoad(ChannelLoad {
                iface: "wlo1".into(),
                freq_mhz: 2437,
                busy_pct: 68.0,
                rx_pct: 48.0,
                tx_pct: 2.0,
                noise_dbm: None,
                interval_ms: 10_000,
            }),
        ));
    }

    // Router telemetry samples with 1 uptime reset and 1 non-connected sample.
    for (i, up, st) in [(0, 5000, "Connected"), (15, 10, "Disconnected"), (30, 25, "Connected")] {
        a.push(&env(
            day_t0 + Duration::seconds(i),
            Record::Router(RouterSample {
                source: Some("upnp_igd".into()),
                model: Some("Example GW".into()),
                phy_status: Some("Up".into()),
                wan_status: Some(st.into()),
                uptime_s: Some(up),
                wan_rx_pps: Some(420.0),
                wan_tx_pps: Some(80.0),
                bytes_saturated: true,
                ..Default::default()
            }),
        ));
    }

    let rep = a.finish(&[]);
    let eth = rep.ifaces.iter().find(|i| i.iface == "eth0").unwrap();
    assert!(eth.peak_net_rtt_p95.unwrap() > 80.0);
    assert!(eth.offpeak_net_rtt_p95.unwrap() < 20.0);
    let wlo1 = rep.ifaces.iter().find(|i| i.iface == "wlo1").unwrap();
    assert_eq!(wlo1.wifi_airtime_congestion_stalls, 3);
    let rr = rep.router.as_ref().unwrap();
    assert_eq!(rr.uptime_resets, 1);
    assert_eq!(rr.wan_down_samples, 1);
    assert!(rep.findings.iter().any(|f| f.contains("shared-line/ISP congestion")), "{:?}", rep.findings);
    assert!(rep.findings.iter().any(|f| f.contains("Wi-Fi airtime saturation")), "{:?}", rep.findings);
    assert!(rep.findings.iter().any(|f| f.contains("WAN uptime reset")), "{:?}", rep.findings);
}

#[test]
fn short_failure_during_own_speed_test_is_an_observer_incident() {
    let t0 = DateTime::from_timestamp(1_800_000_000, 0).unwrap();
    let mut a = Analyzer::new(Opts::default());
    for i in 0..60 {
        let t = t0 + Duration::seconds(i);
        let bad = (20..28).contains(&i);
        let mut r = samp("wlo1", IfaceRole::Wifi, if bad { PathState::DnsDown } else { PathState::Ok }, 3.0);
        if let Record::Sample(s) = &mut r
            && (18..27).contains(&i)
        {
            s.speedtest_active = true;
        }
        a.push(&env(t, r));
        a.push(&env(t, samp("eth0", IfaceRole::Ethernet, PathState::Ok, 1.0)));
    }
    let r = a.finish(&[]);
    assert_eq!(r.observer_incidents, 1, "{r:#?}");
    assert_eq!(r.network_incidents, 0, "{r:#?}");
}

#[test]
fn dual_path_drop_during_own_speed_test_is_load_incident() {
    let t0 = DateTime::from_timestamp(1_800_000_000, 0).unwrap();
    let mut a = Analyzer::new(Opts::default());
    for i in 0..60 {
        let t = t0 + Duration::seconds(i);
        let bad = (20..26).contains(&i);
        let st = if bad { PathState::WanDown } else { PathState::Ok };
        for (iface, role) in [("wlo1", IfaceRole::Wifi), ("eth0", IfaceRole::Ethernet)] {
            let mut r = samp(iface, role, st, 3.0);
            if let Record::Sample(s) = &mut r
                && (18..27).contains(&i)
            {
                s.speedtest_active = true;
            }
            a.push(&env(t, r));
        }
    }
    let r = a.finish(&[]);
    assert_eq!(r.observer_incidents, 0, "{r:#?}");
    assert_eq!(r.load_incidents, 1, "{r:#?}");
    assert_eq!(r.network_incidents, 0, "{r:#?}");
    assert!(r.causes.is_empty(), "{r:#?}");
    assert!(!r.episodes.is_empty());
    assert!(r.episodes.iter().all(|ep| ep.origin == IncidentOrigin::Network && ep.speedtest_active && is_load_provoked(ep)));
    assert!(r.findings_msg.iter().any(|m| m.code == "f_load_incidents"));
}

#[test]
fn lan_samples_summarize_and_annotate_outage_context() {
    use chrono::TimeZone;
    let day_t0 = Local.with_ymd_and_hms(2026, 6, 15, 11, 0, 0).unwrap().with_timezone(&Utc);
    let peak_t0 = Local.with_ymd_and_hms(2026, 6, 15, 20, 0, 0).unwrap().with_timezone(&Utc);
    let mut a = Analyzer::new(Opts::default());

    for i in 0..4 {
        a.push(&env(
            day_t0 + Duration::minutes(i * 10),
            Record::Lan(LanSample {
                iface: "eth0".into(),
                prefix_len: Some(24),
                probed: 253,
                ping_alive: 2,
                arp_alive: 4,
                unique_seen: 5,
            }),
        ));
    }
    for i in 0..4 {
        a.push(&env(
            peak_t0 + Duration::minutes(i * 10),
            Record::Lan(LanSample {
                iface: "eth0".into(),
                prefix_len: Some(24),
                probed: 253,
                ping_alive: 6,
                arp_alive: if i == 1 { 18 } else { 12 },
                unique_seen: 21,
            }),
        ));
    }
    for s_idx in 0..10 {
        let t = peak_t0 + Duration::minutes(10) + Duration::seconds(s_idx);
        let bad = (3..=6).contains(&s_idx);
        a.push(&env(t, samp("wlo1", IfaceRole::Wifi, if bad { PathState::LanDown } else { PathState::Ok }, 3.0)));
    }

    let rep = a.finish(&[]);
    let lr = rep.lan.as_ref().expect("lan report present");
    assert_eq!(lr.samples, 8);
    assert_eq!(lr.arp_alive_max, Some(18));
    assert_eq!(lr.unique_seen_max, Some(21));
    assert_eq!(lr.offpeak_arp_alive_med, Some(4.0));
    assert_eq!(lr.peak_arp_alive_med, Some(12.0));
    assert!(rep.findings.iter().any(|f| f.contains("Active LAN devices")), "{:?}", rep.findings);
    assert!(rep.findings.iter().any(|f| f.contains("Evening client count increases")), "{:?}", rep.findings);
    assert!(
        rep.episodes.iter().any(|e| e.context.iter().any(|c| c.contains("LAN devices active: 18"))),
        "{:?}",
        rep.episodes
    );
    let md = to_markdown(&rep);
    assert!(md.contains("## LAN devices"), "{md}");
    assert!(md.contains("Evening (18–24) median 12 vs off-peak 4"), "{md}");
}

#[test]
fn roam_channel_change_overrun_and_suspend_attribution() {
    let t0 = DateTime::from_timestamp(1_800_000_000, 0).unwrap();
    let mut a = Analyzer::new(Opts::default());

    for i in 0..90 {
        let t = t0 + Duration::seconds(i);
        // Outage 1 (15..25): roam + channel change nearby -> Wi-Fi context.
        let mut s_wifi = samp("wlo1", IfaceRole::Wifi, if (15..25).contains(&i) { PathState::LanDown } else { PathState::Ok }, 4.0);
        // Outage 2 (50..60): overrun on observer ticks -> Observer origin.
        if (50..60).contains(&i) {
            s_wifi = samp("wlo1", IfaceRole::Wifi, PathState::LanDown, 4.0);
            if let Record::Sample(ref mut inner) = s_wifi {
                inner.overrun = true;
            }
        }
        a.push(&env(t, s_wifi));
        a.push(&env(t, samp("eth0", IfaceRole::Ethernet, PathState::Ok, 1.0)));
    }
    a.push(&env(
        t0 + Duration::seconds(18),
        Record::Event(EventKind::Roam { iface: "wlo1".into(), from_bssid: Some("02:00:00:00:00:01".into()), to_bssid: Some("02:00:00:00:00:02".into()) }),
    ));
    a.push(&env(
        t0 + Duration::seconds(19),
        Record::Event(EventKind::ChannelChange { iface: "wlo1".into(), from_mhz: Some(5180), to_mhz: Some(5260) }),
    ));

    // Outage 3 (110..120): SuspendGap covers the episode -> Observer origin.
    for i in 100..130 {
        let t = t0 + Duration::seconds(i);
        a.push(&env(t, samp("wlo1", IfaceRole::Wifi, if (110..120).contains(&i) { PathState::WanDown } else { PathState::Ok }, 4.0)));
    }
    a.push(&env(t0 + Duration::seconds(120), Record::Event(EventKind::SuspendGap { secs: 12.0 })));

    let rep = a.finish(&[]);
    assert!(rep.findings.iter().any(|f| f.contains("roamed between access points")), "{:?}", rep.findings);
    let ep_roam = rep.episodes.iter().find(|e| e.origin == IncidentOrigin::Network).expect("network episode present");
    assert!(ep_roam.context.iter().any(|c| c.contains("roamed")), "{:?}", ep_roam.context);
    assert!(ep_roam.context.iter().any(|c| c.contains("channel changed")), "{:?}", ep_roam.context);
    assert_eq!(rep.network_incidents, 1, "{:#?}", rep.episodes);
    assert_eq!(rep.observer_incidents, 2, "{:#?}", rep.episodes);
}

#[test]
fn host_own_traffic_excludes_stalls_and_short_drops() {
    let t0 = DateTime::from_timestamp(1_800_000_000, 0).unwrap();
    let mut a = Analyzer::new(Opts::default());
    for i in 0..300 {
        let t = t0 + Duration::seconds(i);
        // 60..160: the host downloads at ~40 Mbit/s (5 MB/s); RTT rises, one short drop at 100..104.
        let load = (60..160).contains(&i);
        let bad = (100..104).contains(&i);
        let rtt = if load || i == 250 { 600.0 } else { 3.0 };
        let mut r = samp("wlo1", IfaceRole::Wifi, if bad { PathState::LanDown } else { PathState::Ok }, rtt);
        if let Record::Sample(s) = &mut r
            && load
            && !bad
        {
            s.rx_delta = 5_000_000;
        }
        a.push(&env(t, r));
        a.push(&env(t, samp("eth0", IfaceRole::Ethernet, PathState::Ok, 1.0)));
    }
    let r = a.finish(&[]);
    let w = r.ifaces.iter().find(|i| i.iface == "wlo1").unwrap();
    // Only the stall at 250 (no own traffic) counts.
    assert_eq!(w.stalls, 1, "{w:#?}");
    assert!(w.self_traffic_stalls >= 1, "{w:#?}");
    assert!((w.self_traffic_s - 96.0).abs() < 1.1, "{}", w.self_traffic_s);
    assert_eq!(r.observer_incidents, 1, "{r:#?}");
    assert_eq!(r.network_incidents, 0, "{r:#?}");
    assert!(r.observer_findings_msg.iter().any(|m| m.code == "o_self_traffic"), "{:?}", r.observer_findings);
}

#[test]
fn small_packet_storm_counts_as_host_traffic() {
    let t0 = DateTime::from_timestamp(1_800_000_000, 0).unwrap();
    let mut a = Analyzer::new(Opts::default());
    for i in 0..200 {
        let t = t0 + Duration::seconds(i);
        // 50..120: ~3 Mbit/s but 5000 packets/s (torrent/DHT); RTT high, no loss.
        let storm = (50..120).contains(&i);
        let mut r = samp("wlo1", IfaceRole::Wifi, PathState::Ok, if storm { 600.0 } else { 3.0 });
        if let Record::Sample(s) = &mut r {
            s.pkt_delta = Some(if storm { 5000 } else { 12 });
            if storm {
                s.rx_delta = 375_000;
            }
        }
        a.push(&env(t, r));
    }
    let r = a.finish(&[]);
    let w = &r.ifaces[0];
    assert_eq!(w.stalls, 0, "{w:#?}");
    assert_eq!(w.self_traffic_stalls, 1, "{w:#?}");
    assert!((w.self_traffic_s - 70.0).abs() < 1.1, "{}", w.self_traffic_s);
}


#[test]
fn observer_trust_levels() {
    let clean = observer_trust(&TrustInputs { host_samples: 100, ..Default::default() });
    assert_eq!(clean.level, TrustLevel::Clean);
    assert!(clean.reasons.is_empty());
    let caution = observer_trust(&TrustInputs { overrun_pct: 0.3, observer_incidents: 2, host_samples: 100, ..Default::default() });
    assert_eq!(caution.level, TrustLevel::Caution);
    assert_eq!(caution.reasons.iter().map(|m| m.code.as_str()).collect::<Vec<_>>(), ["t_overrun", "t_observer_incidents"]);
    let polluted = observer_trust(&TrustInputs { power_save_ifaces: vec!["wlo1".into()], clock_unsynced: true, ..Default::default() });
    assert_eq!(polluted.level, TrustLevel::Polluted);
    assert_eq!(polluted.reasons[0].code, "t_power_save");
    assert_eq!(polluted.reasons[1].code, "t_ntp");
    let thr = observer_trust(&TrustInputs { throttled_samples: 20, host_samples: 100, ..Default::default() });
    assert_eq!(thr.level, TrustLevel::Polluted);
}

#[test]
fn late_ticks_lower_observer_trust_in_report() {
    let t0 = DateTime::from_timestamp(1_800_000_000, 0).unwrap();
    let mut a = Analyzer::new(Opts::default());
    for i in 0..200 {
        let mut r = samp("wlo1", IfaceRole::Wifi, PathState::Ok, 3.0);
        if let Record::Sample(s) = &mut r {
            s.overrun = i % 50 == 0;
        }
        a.push(&env(t0 + Duration::seconds(i), r));
    }
    let r = a.finish(&[]);
    assert_eq!(r.observer_trust.level, TrustLevel::Polluted, "{:?}", r.observer_trust);
}

// ---------- masking phase 2: session-wide blinds (section 10: M4, M6, M9, M10, M13) ----------

fn evening_start() -> DateTime<Utc> {
    Local.with_ymd_and_hms(2026, 11, 20, 18, 5, 0).earliest().unwrap().with_timezone(&Utc)
}

fn host_ps(on: bool) -> Record {
    let mut h = HostSample::default();
    h.wifi_power_save.insert("wlo1".into(), on);
    Record::Host(h)
}

fn blind_codes(r: &Report) -> Vec<&str> {
    r.session_blinds.iter().map(|b| b.msg.code.as_str()).collect()
}

fn ps_report(on_samples: i64, total: i64) -> Report {
    let t0 = DateTime::from_timestamp(1_800_000_000, 0).unwrap();
    let mut a = Analyzer::new(Opts::default());
    for i in 0..total {
        let t = t0 + Duration::seconds(i);
        a.push(&env(t, samp("wlo1", IfaceRole::Wifi, PathState::Ok, 3.0)));
        a.push(&env(t, host_ps(i < on_samples)));
    }
    a.finish(&[])
}

#[test]
fn m4_power_save_share_blinds_latency_only_above_five_percent() {
    let r = ps_report(10, 100);
    let b = r.session_blinds.iter().find(|b| b.msg.code == "sb_power_save").expect("blind");
    assert_eq!(b.element, attribution::Element::Latency);
    assert_eq!(b.by, attribution::BlindCause::PowerSave);
    assert!((b.share_pct - 10.0).abs() < 0.01);
    // Rule 2: 4 % is tolerated.
    let r = ps_report(4, 100);
    assert!(!blind_codes(&r).contains(&"sb_power_save"), "{:?}", r.session_blinds);
}

#[test]
fn m9_monitor_gaps_are_one_session_blind_with_total_seconds() {
    let t0 = DateTime::from_timestamp(1_800_000_000, 0).unwrap();
    let mut a = Analyzer::new(Opts::default());
    for i in 0..200 {
        a.push(&env(t0 + Duration::seconds(i), samp("wlo1", IfaceRole::Wifi, PathState::Ok, 3.0)));
    }
    a.push(&env(t0 + Duration::seconds(50), Record::Event(EventKind::SuspendGap { secs: 40.0 })));
    a.push(&env(t0 + Duration::seconds(100), Record::Event(EventKind::Start { version: "x".into(), gap_s: Some(20.0), boot_id: "b".into(), prev_boot_id: None })));
    // A gap of 5 s or less is not a gap.
    a.push(&env(t0 + Duration::seconds(150), Record::Event(EventKind::Start { version: "x".into(), gap_s: Some(3.0), boot_id: "b".into(), prev_boot_id: None })));
    let r = a.finish(&[]);
    let b = r.session_blinds.iter().find(|b| b.msg.code == "sb_monitor_gap").expect("blind");
    assert_eq!(b.by, attribution::BlindCause::MonitorGap);
    assert_eq!(b.msg.args.get("secs").map(String::as_str), Some("60"), "{b:?}");
    // No gaps: no blind.
    let r = ps_report(0, 50);
    assert!(r.session_blinds.is_empty(), "{:?}", r.session_blinds);
}

#[test]
fn m10_polluted_observer_caps_confidence_and_adds_one_blind() {
    let t0 = DateTime::from_timestamp(1_800_000_000, 0).unwrap();
    let build = |late: bool| {
        let mut a = Analyzer::new(Opts::default());
        for i in 0..300 {
            let t = t0 + Duration::seconds(i);
            let bad = (100..130).contains(&i);
            // Both paths fail together: a line problem, the strongest network verdict.
            let st = if bad { PathState::IspDown } else { PathState::Ok };
            let mut w = samp("wlo1", IfaceRole::Wifi, st, 3.0);
            if let Record::Sample(s) = &mut w {
                s.overrun = late && i % 20 == 0 && !bad;
            }
            a.push(&env(t, w));
            a.push(&env(t, samp("eth0", IfaceRole::Ethernet, st, 1.0)));
        }
        a.finish(&[])
    };
    let clean = build(false);
    let polluted = build(true);
    assert_eq!(polluted.observer_trust.level, TrustLevel::Polluted);
    assert_eq!(blind_codes(&polluted).iter().filter(|c| **c == "sb_observer_polluted").count(), 1);
    let c = clean.episodes.iter().map(|e| e.finding.confidence).max().unwrap();
    assert!(c > attribution::Confidence::Medium, "baseline must be high for the cap to show: {c:?}");
    assert!(polluted.episodes.iter().all(|e| e.finding.confidence <= attribution::Confidence::Medium));
    assert!(!blind_codes(&clean).contains(&"sb_observer_polluted"));
}

fn evening_report(self_share_pct: i64, speed_tests: i64) -> Report {
    let t0 = evening_start();
    let mut a = Analyzer::new(Opts::default());
    for i in 0..1000 {
        let mut r = samp("wlo1", IfaceRole::Wifi, PathState::Ok, 3.0);
        if let Record::Sample(s) = &mut r
            && i % 100 < self_share_pct
        {
            s.rx_delta = 5_000_000;
        }
        a.push(&env(t0 + Duration::seconds(i), r));
    }
    for k in 0..speed_tests {
        let res = SpeedResult { iface: "wlo1".into(), url: "u".into(), bytes: 1, secs: 1.0, mbps: Some(50.0), mbps_all: None, warmup_excluded_s: None, err: None };
        a.push(&env(t0 + Duration::seconds(k * 10), Record::Speed(res)));
    }
    a.finish(&[])
}

#[test]
fn m13_evening_self_traffic_blinds_isp_from_ten_percent() {
    let r = evening_report(30, 0);
    let b = r.session_blinds.iter().find(|b| b.msg.code == "sb_self_traffic").expect("blind");
    assert_eq!((b.element, b.by), (attribution::Element::Isp, attribution::BlindCause::SelfTraffic));
    assert!(b.share_pct >= 25.0 && b.share_pct <= 35.0, "{}", b.share_pct);
    // Rule 2: 5 % is tolerated.
    let r = evening_report(5, 0);
    assert!(!blind_codes(&r).contains(&"sb_self_traffic"), "{:?}", r.session_blinds);
}

#[test]
fn m6_frequent_evening_speed_tests_blind_isp_and_rare_ones_do_not() {
    // 1000 s of evening, 3 tests: far more often than every 2 h.
    let r = evening_report(0, 3);
    let b = r.session_blinds.iter().find(|b| b.msg.code == "sb_own_speed_tests").expect("blind");
    assert_eq!((b.element, b.by), (attribution::Element::Isp, attribution::BlindCause::OwnSpeedTests));
    // Rule 2: one test, or none, blinds nothing.
    assert!(!blind_codes(&evening_report(0, 1)).contains(&"sb_own_speed_tests"));
    assert!(evening_report(0, 0).session_blinds.is_empty());
}

#[test]
fn short_power_save_is_caution_not_polluted() {
    let short = observer_trust(&TrustInputs { power_save_ifaces: vec!["wlo1".into()], power_save_pct: Some(2.0), host_samples: 100, ..Default::default() });
    assert_eq!(short.level, TrustLevel::Caution, "{short:?}");
    let long = observer_trust(&TrustInputs { power_save_ifaces: vec!["wlo1".into()], power_save_pct: Some(40.0), host_samples: 100, ..Default::default() });
    assert_eq!(long.level, TrustLevel::Polluted, "{long:?}");
}

#[test]
fn tie_between_states_picks_the_nearest_failure() {
    // One episode: 1 tick internet down, 1 tick gateway down (merged by the gap rule).
    let t0 = DateTime::from_timestamp(1_800_000_000, 0).unwrap();
    let mut a = Analyzer::new(Opts::default());
    for i in 0..60 {
        let st = match i {
            30 => PathState::WanDown,
            32 => PathState::LanDown,
            _ => PathState::Ok,
        };
        a.push(&env(t0 + Duration::seconds(i), samp("wlo1", IfaceRole::Wifi, st, 3.0)));
    }
    let r = a.finish(&[]);
    assert_eq!(r.episodes.len(), 1, "{:#?}", r.episodes);
    assert_eq!(r.episodes[0].state, PathState::LanDown);
}
