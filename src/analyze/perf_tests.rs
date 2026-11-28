//! Cost of one full analysis of a long session. Run on purpose:
//! `cargo test --release perf_tests -- --ignored --nocapture` (peak memory: Linux only).

use super::*;
use chrono::Duration;

fn env(ts: DateTime<Utc>, rec: Record) -> Envelope {
    Envelope { v: 1, run: "r".into(), seq: 0, ts, mono_ns: 0, rec }
}

fn samp(iface: &str, role: IfaceRole, state: PathState, gw_rtt: f64) -> Record {
    let bad = matches!(state, PathState::LanDown | PathState::IspDown);
    Record::Sample(Sample {
        iface: iface.into(),
        role,
        link: LinkState::default(),
        gw: Some(if bad { ProbeResult::fail("timeout") } else { ProbeResult::ok(gw_rtt) }),
        isp: None,
        net: MultiResult { ok: if bad { 0 } else { 3 }, of: 3, rtt_ms: Some(15.0) },
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

/// Peak resident memory (VmHWM) in kB; 0 when `/proc` is missing.
fn hwm_kb() -> u64 {
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| s.lines().find(|l| l.starts_with("VmHWM:")).and_then(|l| l.split_whitespace().nth(1).and_then(|v| v.parse().ok())))
        .unwrap_or(0)
}

#[test]
#[ignore = "perf measurement; run explicitly"]
fn week_long_session_two_ifaces() {
    const DAYS: i64 = 7;
    const SECS: i64 = DAYS * 86_400;
    const EPISODES: i64 = 200;
    let t0 = DateTime::from_timestamp(1_800_000_000, 0).unwrap();
    let before = hwm_kb();
    let started = std::time::Instant::now();
    let mut a = Analyzer::new(Opts::default());
    let (mut samples, mut events) = (0u64, 0u64);
    let step = SECS / EPISODES;
    let mut wifi_bad = false;
    for i in 0..SECS {
        let t = t0 + Duration::seconds(i);
        // One 8 s outage on Wi-Fi every `step` s; every 4th is a line outage seen on both paths.
        let k = i / step;
        let off = i % step;
        let line = k % 4 == 0;
        let bad_w = (1000..1008).contains(&off);
        let bad_e = line && bad_w;
        if bad_w != wifi_bad {
            wifi_bad = bad_w;
            let (from, to) = if bad_w { (PathState::Ok, PathState::LanDown) } else { (PathState::LanDown, PathState::Ok) };
            a.push(&env(t, Record::Event(EventKind::StateChange { iface: "wlo1".into(), from, to, prev_duration_s: 1000.0 })));
            events += 1;
        }
        let w = if bad_w {
            if line {
                PathState::IspDown
            } else {
                PathState::LanDown
            }
        } else {
            PathState::Ok
        };
        let e = if bad_e { PathState::IspDown } else { PathState::Ok };
        a.push(&env(t, samp("wlo1", IfaceRole::Wifi, w, 3.0 + (i % 7) as f64)));
        a.push(&env(t, samp("eth0", IfaceRole::Ethernet, e, 1.0)));
        samples += 2;
        if i % 10 == 0 {
            a.push(&env(t, Record::Host(HostSample { cpu_pct: Some(10.0 + (i % 13) as f64), mem_used_pct: Some(40.0), temp_c: Some(55.0), ..Default::default() })));
        }
        // Roams (~1 per 20 min) and host alerts (~1 per 40 min).
        if i % 1200 == 600 {
            a.push(&env(t, Record::Event(EventKind::Roam { iface: "wlo1".into(), from_bssid: Some("02:00:00:00:00:01".into()), to_bssid: Some("02:00:00:00:00:02".into()) })));
            events += 1;
        }
        if i % 2400 == 1800 {
            a.push(&env(t, Record::Event(EventKind::HostAlert { alert: HostAlertKind::HighCpu, detail: "cpu 95%".into(), iface: None })));
            events += 1;
        }
    }
    let pushed = started.elapsed();
    let rep = a.finish(&[]);
    let total = started.elapsed();
    let after = hwm_kb();
    println!(
        "perf: {samples} samples, {events} events, {} episodes; push {:.2}s, finish {:.2}s, total {:.2}s; VmHWM before {} kB, after {} kB, delta {} kB",
        rep.episodes.len(),
        pushed.as_secs_f64(),
        (total - pushed).as_secs_f64(),
        total.as_secs_f64(),
        before,
        after,
        after.saturating_sub(before),
    );
    assert!(!rep.episodes.is_empty());
}
