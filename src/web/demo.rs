//! Manual UI check (ignored test): serves synthetic data on 127.0.0.1:8099 for 10 minutes.
//! Run with `LINKWATCH_DEMO=1 cargo test demo_ui_server -- --ignored --nocapture`.
//!
//! The demo has a token (`DEMO_TOKEN`; open `/?token=<token>` once) so measurement control
//! can be tried: a fake run loop answers session switches. `LINKWATCH_DEMO_NOSITE=1` runs it
//! without a site file (free-text points); `LINKWATCH_DEMO_PORT` changes the port.

use super::*;
use crate::live::{IfaceLive, MinuteBucket};
use crate::model::*;
use chrono::{DurationRound, TimeDelta, Utc};

fn wifi_minutes(
    now: chrono::DateTime<Utc>,
    wifi: bool,
) -> std::collections::VecDeque<MinuteBucket> {
    (0..(72 * 60))
        .map(|m: i64| {
            let f = if wifi && m % 97 == 0 { 12 } else { 0 };
            MinuteBucket {
                t: (now - TimeDelta::minutes(72 * 60 - m))
                    .duration_trunc(TimeDelta::minutes(1))
                    .unwrap(),
                ticks: 60,
                gw_fail: f,
                net_fail: f,
                gw_rtt_avg: Some(if wifi {
                    4.0 + (m % 30) as f64 / 3.0
                } else {
                    0.6
                }),
                net_rtt_avg: Some(if wifi { 18.0 + (m % 50) as f64 } else { 14.0 }),
                signal_dbm: wifi.then_some(-55 - (m % 20) as i32),
                busy_pct: wifi.then_some(20.0 + (m % 40) as f64),
                ..Default::default()
            }
        })
        .collect()
}

fn sample(name: &str, role: IfaceRole) -> Sample {
    Sample {
        iface: name.into(),
        role,
        link: LinkState {
            present: true,
            up: true,
            carrier: true,
            ipv4: Some("192.168.1.20".parse().unwrap()),
            prefix_len: Some(24),
            gateway: Some("192.168.1.1".parse().unwrap()),
            ..Default::default()
        },
        gw: Some(ProbeResult::ok(3.2)),
        isp: None,
        net: MultiResult {
            ok: 3,
            of: 3,
            rtt_ms: Some(17.5),
        },
        tcp: None,
        dns: Some(ProbeResult::fail("timeout")),
        rx_delta: 0,
        tx_delta: 0,
        state: PathState::Ok,
        speedtest_active: false,
        overrun: false,
        scan_active: false,
        t: None,
        freq_mhz: None,
    }
}

/// Token of the demo server.
const DEMO_TOKEN: &str = "demo-token-0123456789";

/// Writes a finished (or running) session directory as the store would leave it.
pub(super) fn write_session(
    data_dir: &std::path::Path,
    meta: &SessionMeta,
    last_seen: chrono::DateTime<Utc>,
    summary: Option<serde_json::Value>,
) {
    let dir = data_dir.join(&meta.session);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("meta.json"), serde_json::to_vec_pretty(meta).unwrap()).unwrap();
    let hb = serde_json::json!({"ts": last_seen, "boot_id": "demo", "mono_ns": 0});
    std::fs::write(dir.join("heartbeat"), hb.to_string()).unwrap();
    if let Some(s) = summary {
        std::fs::write(dir.join("summary.json"), s.to_string()).unwrap();
    }
}

pub(super) fn demo_summary(avail: f64, verdict: &str, transitions: u64) -> serde_json::Value {
    serde_json::json!({"verdict": verdict, "availability_pct": avail, "transitions": {"wlan0": transitions}})
}

#[tokio::test]
#[ignore]
async fn demo_ui_server() {
    // A manual tool, not a test: serves a demo UI for 10 minutes on 127.0.0.1:8099.
    // Run it with LINKWATCH_DEMO=1 cargo test demo_ui_server -- --ignored --nocapture
    if std::env::var_os("LINKWATCH_DEMO").is_none() {
        eprintln!("demo_ui_server: set LINKWATCH_DEMO=1 to run the demo UI server");
        return;
    }
    let with_site = std::env::var_os("LINKWATCH_DEMO_NOSITE").is_none();
    let d = tempfile::tempdir().unwrap();
    let now = Utc::now();
    let pt = |site_id: &str, free: &str| Some(if with_site { site_id } else { free }.to_string());
    let meta = SessionMeta {
        v: 1,
        session: "demo".into(),
        started: now - TimeDelta::hours(3),
        host: "probe-1".into(),
        version: "0.1.0".into(),
        point: pt("B1/F2/R3", "Bedroom"),
        label: Some("Night 3".into()),
        note: Some("door closed".into()),
        config: serde_json::json!({}),
        host_id: None,
        tz_offset_s: None,
        clock_synced: Some(true),
        network: None,
    };
    // Earlier sessions: a done point, a partial one, an unplanned one, a tiny (hidden) one.
    let past = [
        ("s1", pt("B1/F2/K", "Living room"), 52, 9.0, Some(demo_summary(99.95, "all_ok", 2)), "Night 1", None),
        ("s2", pt("B1/F2/R1", "Office desk"), 40, 3.0, Some(demo_summary(98.4, "wifi_problem", 36)), "Night 2", Some("window open")),
        ("s3", pt("B2/F1/R2", "Hall"), 30, 5.0, Some(demo_summary(99.5, "isp_problem", 8)), "Neighbour test", None),
        ("s4", pt("B1/F2/R2", "Kitchen"), 20, 0.01, None, "Wrong room", None),
    ];
    for (id, point, ago_h, dur_h, summary, label, note) in past {
        let started = now - TimeDelta::hours(ago_h);
        let m = SessionMeta {
            session: id.into(),
            started,
            point,
            label: Some(label.into()),
            note: note.map(Into::into),
            ..meta.clone()
        };
        let last = started + TimeDelta::seconds((dur_h * 3600.0) as i64);
        write_session(d.path(), &m, last, summary);
    }
    write_session(d.path(), &meta, now, None);

    let live = Live::new();
    live.update(|s| {
        s.session = Some(meta.clone());
        s.started = Some(meta.started);
        s.verdict = Some(Verdict::WifiProblem);
        s.verdict_since = Some(now - TimeDelta::minutes(12));
        s.lan = Some(LanSample {
            iface: "eth0".into(),
            prefix_len: Some(24),
            probed: 253,
            ping_alive: 5,
            arp_alive: 11,
            unique_seen: 14,
        });
        for m in (0..(72 * 60)).step_by(5) {
            let arp = 7 + ((m / 60 + m / 15) % 8) as u32;
            s.lan_history.push_back(crate::live::LanPoint {
                t: (now - TimeDelta::minutes((72 * 60) - m))
                    .duration_trunc(TimeDelta::minutes(1))
                    .unwrap(),
                arp_alive: arp,
                ping_alive: arp.saturating_sub(3),
                unique_seen: 14,
            });
        }
        for (name, role) in [("wlan0", IfaceRole::Wifi), ("eth0", IfaceRole::Ethernet)] {
            let wifi = role == IfaceRole::Wifi;
            let mut i = IfaceLive {
                name: name.into(),
                role: Some(role),
                state: Some(if wifi {
                    PathState::LanDown
                } else {
                    PathState::Ok
                }),
                state_since: Some(now - TimeDelta::minutes(12)),
                ticks: 100_000,
                gw_fail: 420,
                net_fail: 450,
                down_s: 640.0,
                minutes: wifi_minutes(now, wifi),
                last: Some(sample(name, role)),
                ..Default::default()
            };
            if wifi {
                i.wifi = Some(WifiStation {
                    iface: name.into(),
                    connected: true,
                    channel: Some(36),
                    freq_mhz: Some(5180),
                    width_mhz: Some(80),
                    signal_dbm: Some(-67),
                    tx_bitrate_mbps: Some(390.0),
                    rx_bitrate_mbps: Some(433.0),
                    bssid: Some("02:00:00:00:00:01".into()),
                    ..Default::default()
                });
                i.channel_load = Some(ChannelLoad {
                    iface: name.into(),
                    freq_mhz: 5180,
                    busy_pct: 43.0,
                    ..Default::default()
                });
            }
            s.ifaces.insert(name.into(), i);
        }
        let bss = (0..8u32)
            .map(|n| ScanBss {
                bssid: format!("02:00:00:00:00:{:02x}", n + 1),
                ssid: (n != 3).then(|| format!("network-{n}")),
                freq_mhz: if n % 2 == 0 { 5180 } else { 2437 },
                channel: Some(if n % 2 == 0 { 36 } else { 6 }),
                width_mhz: Some(if n % 2 == 0 { 80 } else { 20 }),
                signal_dbm: Some(-40.0 - 6.0 * n as f64),
                associated: n == 0,
                ..Default::default()
            })
            .collect();
        s.last_scan.insert(
            "wlan0".into(),
            ScanReport {
                iface: "wlan0".into(),
                bss,
                fresh: true,
            },
        );
        s.speed.push_back((
            now - TimeDelta::minutes(50),
            SpeedResult {
                iface: "wlan0".into(),
                url: "http://speed.example.net/file.bin".into(),
                bytes: 52_428_800,
                secs: 9.3,
                mbps: Some(45.1),
                err: None,
                ..Default::default()
            },
        ));
        s.speed.push_back((
            now - TimeDelta::minutes(20),
            SpeedResult {
                iface: "eth0".into(),
                url: "http://speed.example.net/file.bin".into(),
                bytes: 1000,
                secs: 40.0,
                mbps: None,
                err: Some("timeout".into()),
                ..Default::default()
            },
        ));
        let evs = [
            EventKind::Start {
                version: "0.1.0".into(),
                gap_s: Some(3600.0),
                boot_id: "a".into(),
                prev_boot_id: Some("b".into()),
            },
            EventKind::StateChange {
                iface: "wlan0".into(),
                from: PathState::Ok,
                to: PathState::LanDown,
                prev_duration_s: 7200.0,
            },
            EventKind::VerdictChange {
                from: Verdict::AllOk,
                to: Verdict::WifiProblem,
                prev_duration_s: 7200.0,
            },
            EventKind::Roam {
                iface: "wlan0".into(),
                from_bssid: Some("02:00:00:00:00:01".into()),
                to_bssid: Some("02:00:00:00:00:02".into()),
            },
            EventKind::DroppedRecords { count: 3 },
        ];
        for (n, e) in evs.into_iter().enumerate() {
            s.events.push_back(Envelope {
                v: 1,
                run: "r".into(),
                seq: n as u64,
                ts: now - TimeDelta::minutes(30 - n as i64),
                mono_ns: 0,
                rec: Record::Event(e),
            });
        }
    });
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("examples/site.toml");
    let site = with_site.then(|| Arc::new(Site::load(&path).unwrap()));

    // A fake run loop for measurement control: a switch writes a new session directory and
    // replaces the session in the live state, as `run::run` does.
    let (ctl, mut ctl_rx) = crate::control::channel();
    let (l3, dd) = (live.clone(), d.path().to_path_buf());
    tokio::spawn(async move {
        let mut n = 0;
        while let Some(crate::control::Command::StartSession { req, reply }) = ctl_rx.recv().await {
            tokio::time::sleep(Duration::from_millis(800)).await;
            n += 1;
            let started = Utc::now();
            let id = format!("{}-demo{n}", started.format("%Y%m%dT%H%M%SZ"));
            let m = l3.read(|s| s.session.clone()).unwrap();
            let m = SessionMeta { session: id.clone(), started, point: req.point, label: req.label, note: req.note, ..m };
            write_session(&dd, &m, started, None);
            l3.update(|s| {
                s.session = Some(m.clone());
                s.started = Some(started);
            });
            let _ = l3.feed.send(Arc::new(Envelope {
                v: 1,
                run: "r".into(),
                seq: 0,
                ts: started,
                mono_ns: 0,
                rec: Record::Event(EventKind::Start { version: "0.1.0".into(), gap_s: None, boot_id: "demo".into(), prev_boot_id: None }),
            }));
            let _ = reply.send(Ok(id));
        }
    });
    let l2 = live.clone();
    tokio::spawn(async move {
        let mut seq = 100;
        loop {
            tokio::time::sleep(Duration::from_secs(5)).await;
            seq += 1;
            let _ = l2.feed.send(Arc::new(Envelope {
                v: 1,
                run: "r".into(),
                seq,
                ts: Utc::now(),
                mono_ns: 0,
                rec: Record::Event(EventKind::StateChange {
                    iface: "wlan0".into(),
                    from: PathState::LanDown,
                    to: PathState::Ok,
                    prev_duration_s: 5.0,
                }),
            }));
        }
    });
    let port: u16 = std::env::var("LINKWATCH_DEMO_PORT").ok().and_then(|p| p.parse().ok()).unwrap_or(8099);
    let listener = TcpListener::bind(("127.0.0.1", port)).await.unwrap();
    eprintln!("demo: http://127.0.0.1:{port}/?token={DEMO_TOKEN} (site file: {with_site})");
    serve_on(
        listener,
        live,
        d.path().to_path_buf(),
        site,
        Some(DEMO_TOKEN.into()),
        Some(ctl),
        tokio::time::sleep(Duration::from_secs(600)),
    )
    .await
    .unwrap();
}
