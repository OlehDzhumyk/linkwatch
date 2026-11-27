//! Web tests over a real local socket with a minimal HTTP/1.1 client.

use super::*;
use crate::live::{IfaceLive, MinuteBucket};
use crate::model::{Envelope, EventKind, Record, SessionMeta};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

async fn start(
    live: Live,
    data_dir: PathBuf,
    site: Option<Arc<Site>>,
) -> (SocketAddr, tokio::sync::oneshot::Sender<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (tx, rx) = tokio::sync::oneshot::channel::<()>();
    tokio::spawn(async move {
        serve_on(listener, live, data_dir, site, None, None, async move {
            let _ = rx.await;
        })
        .await
        .unwrap();
    });
    (addr, tx)
}

async fn get(addr: SocketAddr, path: &str) -> (u16, String) {
    let mut s = TcpStream::connect(addr).await.unwrap();
    s.write_all(format!("GET {path} HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n").as_bytes())
        .await
        .unwrap();
    let mut buf = Vec::new();
    tokio::time::timeout(Duration::from_secs(5), s.read_to_end(&mut buf))
        .await
        .unwrap()
        .unwrap();
    let text = String::from_utf8_lossy(&buf).into_owned();
    let (head, body) = text.split_once("\r\n\r\n").unwrap();
    let code = head.split(' ').nth(1).unwrap().parse().unwrap();
    (code, body.to_string())
}

fn json(body: &str) -> serde_json::Value {
    serde_json::from_str(body).unwrap_or_else(|e| panic!("bad json {e}: {body}"))
}

fn note_env(seq: u64, text: &str) -> Envelope {
    Envelope {
        v: 1,
        run: "r".into(),
        seq,
        ts: chrono::Utc::now(),
        mono_ns: 0,
        rec: Record::Event(EventKind::Note { text: text.into() }),
    }
}

#[tokio::test]
async fn static_and_status_endpoints() {
    let d = tempfile::tempdir().unwrap();
    let live = Live::new();
    live.update(|s| {
        s.host = Some(crate::model::HostSample {
            cpu_pct: Some(15.0),
            mem_used_pct: Some(42.0),
            temp_c: Some(41.5),
            clock_synced: Some(true),
            ..Default::default()
        });
        s.router = Some(crate::model::RouterSample {
            source: Some("upnp_igd".into()),
            model: Some("Example GW".into()),
            wan_status: Some("Connected".into()),
            phy_status: Some("Up".into()),
            uptime_s: Some(3600),
            wan_rx_pps: Some(420.0),
            wan_tx_pps: Some(90.0),
            bytes_saturated: true,
            ..Default::default()
        });
        s.lan = Some(crate::model::LanSample {
            iface: "eth0".into(),
            prefix_len: Some(24),
            probed: 253,
            ping_alive: 6,
            arp_alive: 14,
            unique_seen: 19,
        });
        s.lan_history.push_back(crate::live::LanPoint {
            t: chrono::Utc::now() - chrono::TimeDelta::minutes(90),
            arp_alive: 8,
            ping_alive: 3,
            unique_seen: 12,
        });
        s.lan_history.push_back(crate::live::LanPoint {
            t: chrono::Utc::now() - chrono::TimeDelta::minutes(10),
            arp_alive: 14,
            ping_alive: 6,
            unique_seen: 19,
        });
        let mut i = IfaceLive {
            name: "wlan0".into(),
            ..Default::default()
        };
        for m in 0..120 {
            i.minutes.push_back(MinuteBucket {
                t: chrono::Utc::now() - chrono::TimeDelta::minutes(120 - m),
                ticks: 60,
                ..Default::default()
            });
        }
        s.ifaces.insert("wlan0".into(), i);
        s.last_scan.insert(
            "wlan0".into(),
            crate::model::ScanReport {
                iface: "wlan0".into(),
                fresh: true,
                bss: vec![crate::model::ScanBss {
                    bssid: "02:00:00:00:00:10".into(),
                    ssid: Some("HomeNet".into()),
                    freq_mhz: 5180,
                    channel: Some(36),
                    width_mhz: Some(80),
                    signal_dbm: Some(-42.0),
                    associated: true,
                    seen_ms_ago: Some(100),
                    ..Default::default()
                }],
            },
        );
        if let Some(iface) = s.ifaces.get_mut("wlan0") {
            iface.wifi = Some(crate::model::WifiStation {
                iface: "wlan0".into(),
                connected: true,
                bssid: Some("02:00:00:00:00:10".into()),
                ssid: Some("HomeNet".into()),
                freq_mhz: Some(5180),
                channel: Some(36),
                ..Default::default()
            });
        }
        s.events.push_back(note_env(1, "a"));
        s.events.push_back(note_env(2, "b"));
        s.events.push_back(Envelope {
            v: 1,
            run: "r".into(),
            seq: 3,
            ts: chrono::Utc::now(),
            mono_ns: 0,
            rec: Record::Event(EventKind::Security {
                detector: "gateway_mac_change".into(),
                severity: "high".into(),
                iface: Some("wlan0".into()),
                detail: "test".into(),
            }),
        });
    });
    let (addr, stop) = start(live, d.path().to_path_buf(), None).await;

    let (c, body) = get(addr, "/").await;
    assert_eq!(c, 200);
    assert!(body.contains("<html"));
    assert!(body.contains(r#"<script type="module" src="/js/main.js"></script>"#));
    for (name, _) in UI_MODULES {
        let (c, js_body) = get(addr, &format!("/js/{name}")).await;
        assert_eq!(c, 200, "{name}");
        for bad in ["innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "eval("] {
            assert!(!js_body.contains(bad), "{name} uses {bad}");
        }
    }
    let r = raw(addr, "GET /js/main.js HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n").await.to_ascii_lowercase();
    assert!(r.contains("content-type: text/javascript; charset=utf-8"), "{r}");
    assert!(r.contains("content-security-policy: default-src 'self'"), "{r}");
    for path in ["/js/nope.js", "/js/..%2Fmod.rs", "/js/../index.html", "/js/", "/js/api/Envelope.js", "/app.js"] {
        assert_eq!(get(addr, path).await.0, 404, "{path}");
    }
    assert_eq!(get(addr, "/style.css").await.0, 200);
    assert_eq!(get(addr, "/nope").await.0, 404);

    let (c, body) = get(addr, "/api/status").await;
    assert_eq!(c, 200);
    let v = json(&body);
    assert!(v["ifaces"]["wlan0"].get("minutes").is_none());
    assert_eq!(v["ifaces"]["wlan0"]["minutes_count"], 120);
    assert_eq!(v["host"]["cpu_pct"], 15.0);
    assert_eq!(v["router"]["model"], "Example GW");
    assert_eq!(v["router"]["bytes_saturated"], true);
    assert_eq!(v["lan"]["arp_alive"], 14);
    assert_eq!(v["lan"]["unique_seen"], 19);

    let v = json(&get(addr, "/api/scan").await.1);
    assert_eq!(v["scan"]["wlan0"]["our_ssid"], "HomeNet");
    assert_eq!(v["scan"]["wlan0"]["our_bssid"], "02:00:00:00:00:10");
    assert_eq!(v["scan"]["wlan0"]["report"]["bss"][0]["width_mhz"], 80);

    let v = json(&get(addr, "/api/minutes?iface=wlan0&hours=1").await.1);
    assert_eq!(v["ifaces"]["wlan0"].as_array().unwrap().len(), 60);
    assert_eq!(v["lan"].as_array().unwrap().len(), 1);
    assert_eq!(v["lan"][0]["arp_alive"], 14);

    let v = json(&get(addr, "/api/events?limit=1").await.1);
    assert_eq!(v["events"][0]["seq"], 3);
    assert_eq!(v["events"][0]["kind"], "security");

    assert_eq!(get(addr, "/api/site").await.0, 404);
    assert_eq!(get(addr, "/api/sessions/..%2Fetc/summary").await.0, 400);
    assert_eq!(get(addr, "/api/sessions/missing/summary").await.0, 404);
    let _ = stop.send(());
}

#[tokio::test]
async fn session_history_from_disk() {
    let d = tempfile::tempdir().unwrap();
    let meta = SessionMeta {
        v: 1,
        session: "s1".into(),
        // Older than a minute: shorter sessions are not listed.
        started: chrono::Utc::now() - chrono::TimeDelta::hours(1),
        host: "h".into(),
        version: "0".into(),
        point: Some("B1/F1/R1".into()),
        label: Some("test".into()),
        note: None,
        config: serde_json::json!({}),
        host_id: None,
        tz_offset_s: None,
        clock_synced: None,
        network: None,
    };
    let (h, _) = crate::store::open(
        d.path(),
        meta,
        &crate::config::Storage::default(),
        Live::new(),
    )
    .await
    .unwrap();
    for i in 0..5 {
        h.send(Record::Event(EventKind::Note {
            text: format!("n{i}"),
        }));
    }
    h.send(Record::Heartbeat { uptime_s: 1.0 });
    h.close(serde_json::json!({"verdict": "all_ok"}))
        .await
        .unwrap();

    let (addr, stop) = start(Live::new(), d.path().to_path_buf(), None).await;
    let v = json(&get(addr, "/api/sessions").await.1);
    assert_eq!(v["sessions"][0]["id"], "s1");
    assert_eq!(v["sessions"][0]["point"], "B1/F1/R1");
    assert_eq!(v["sessions"][0]["summary"]["verdict"], "all_ok");
    assert!(v["sessions"][0]["last_seen"].is_string());

    let v = json(&get(addr, "/api/sessions/s1/events?limit=2").await.1);
    let ev = v["events"].as_array().unwrap();
    assert_eq!(ev.len(), 2);
    assert_eq!(ev[0]["text"], "n4");

    let (c, body) = get(addr, "/api/sessions/s1/summary").await;
    assert_eq!(c, 200);
    assert_eq!(json(&body)["verdict"], "all_ok");
    let v = json(&get(addr, "/api/minutes?session=s1").await.1);
    assert!(v["ifaces"].as_object().unwrap().is_empty());
    let _ = stop.send(());
}

#[tokio::test]
async fn site_endpoint_marks_current_point() {
    let d = tempfile::tempdir().unwrap();
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("examples/site.toml");
    let site = Arc::new(Site::load(&path).unwrap());
    let live = Live::new();
    live.update(|s| {
        s.session = Some(SessionMeta {
            v: 1,
            session: "x".into(),
            started: chrono::Utc::now(),
            host: "h".into(),
            version: "0".into(),
            point: Some("B2/F3/K".into()),
            label: None,
            note: None,
            config: serde_json::json!({}),
            host_id: None,
            tz_offset_s: None,
            clock_synced: None,
            network: None,
        })
    });
    let (addr, stop) = start(live, d.path().to_path_buf(), Some(site)).await;
    let v = json(&get(addr, "/api/site").await.1);
    assert_eq!(v["current_point"], "B2/F3/K");
    assert_eq!(v["buildings"][1]["name"], "Block B");
    let _ = stop.send(());
}

#[tokio::test]
async fn sse_streams_envelopes_and_ends_on_shutdown() {
    let d = tempfile::tempdir().unwrap();
    let live = Live::new();
    let (addr, stop) = start(live.clone(), d.path().to_path_buf(), None).await;
    let mut s = TcpStream::connect(addr).await.unwrap();
    s.write_all(b"GET /api/live HTTP/1.1\r\nHost: t\r\n\r\n")
        .await
        .unwrap();
    let mut got = String::new();
    let mut buf = [0u8; 4096];
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while !got.contains("hello-sse") {
        assert!(tokio::time::Instant::now() < deadline, "no SSE data: {got}");
        let _ = live.feed.send(Arc::new(note_env(1, "hello-sse")));
        if let Ok(Ok(n)) = tokio::time::timeout(Duration::from_millis(100), s.read(&mut buf)).await
        {
            assert!(n > 0, "connection closed early");
            got.push_str(&String::from_utf8_lossy(&buf[..n]));
        }
    }
    assert!(got.contains("text/event-stream"));
    let _ = stop.send(());
    // The stream ends after shutdown; the server closes the connection.
    let r = tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            match s.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(_) => {}
            }
        }
    })
    .await;
    assert!(r.is_ok(), "SSE connection still open after shutdown");
}

#[test]
fn example_config_parses() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("examples/linkwatch.toml");
    let cfg = crate::config::Config::load(Some(&path)).unwrap();
    assert_eq!(cfg.interfaces.len(), 2);
}

#[tokio::test]
async fn bind_failure_is_an_error() {
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = l.local_addr().unwrap();
    let r = serve(addr, Live::new(), PathBuf::from("/tmp"), None, None, None, async {}).await;
    let e = r.unwrap_err().to_string();
    assert!(e.contains("cannot listen"), "{e}");
}

async fn raw(addr: SocketAddr, req: &str) -> String {
    let mut s = TcpStream::connect(addr).await.unwrap();
    s.write_all(req.as_bytes()).await.unwrap();
    let mut buf = Vec::new();
    tokio::time::timeout(Duration::from_secs(5), s.read_to_end(&mut buf)).await.unwrap().unwrap();
    String::from_utf8_lossy(&buf).into_owned()
}

#[tokio::test]
async fn token_host_check_and_security_headers() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let tok = "abcdefghijklmnop1234".to_string();
    tokio::spawn(serve_on(listener, Live::new(), PathBuf::from("/nonexistent"), None, Some(tok.clone()), None, std::future::pending()));
    let r = raw(addr, "GET /api/status HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n").await;
    assert!(r.starts_with("HTTP/1.1 401"), "{r}");
    let r = raw(addr, &format!("GET /?token={tok} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")).await;
    assert!(r.starts_with("HTTP/1.1 200"), "{r}");
    assert!(r.to_ascii_lowercase().contains("set-cookie: linkwatch_token="), "{r}");
    assert!(r.to_ascii_lowercase().contains("content-security-policy"), "{r}");
    let r = raw(addr, &format!("GET /api/status HTTP/1.1\r\nHost: x\r\nCookie: a=b; linkwatch_token={tok}\r\nConnection: close\r\n\r\n")).await;
    assert!(r.starts_with("HTTP/1.1 200"), "{r}");
    let r = raw(addr, &format!("GET /api/status HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer {tok}\r\nConnection: close\r\n\r\n")).await;
    assert!(r.starts_with("HTTP/1.1 200"), "{r}");
    let r = raw(addr, "GET /api/status?token=wrongwrongwrongwrong HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n").await;
    assert!(r.starts_with("HTTP/1.1 401"), "{r}");
}

#[tokio::test]
async fn foreign_host_is_refused_without_token() {
    let (addr, _stop) = start(Live::new(), PathBuf::from("/nonexistent"), None).await;
    let r = raw(addr, "GET /api/status HTTP/1.1\r\nHost: evil.example.com\r\nConnection: close\r\n\r\n").await;
    assert!(r.starts_with("HTTP/1.1 403"), "{r}");
    for h in ["192.168.0.10:8080", "localhost:8080", "lab", "box.local", "[::1]:8080"] {
        assert!(host_allowed(h), "{h}");
    }
    assert!(!host_allowed("rebind.attacker.net:8080"));
    assert!(!host_allowed("[::1].evil.com"));
}

#[tokio::test]
async fn old_session_minutes_still_readable() {
    let d = tempfile::tempdir().unwrap();
    let sdir = d.path().join("old_sess");
    std::fs::create_dir_all(&sdir).unwrap();
    let old_t = chrono::DateTime::from_timestamp(1_700_000_000, 0).unwrap();
    let meta = SessionMeta {
        v: 1,
        session: "old_sess".into(),
        started: old_t,
        host: "h".into(),
        version: "0".into(),
        point: None,
        label: None,
        note: None,
        config: serde_json::json!({}),
        host_id: None,
        tz_offset_s: None,
        clock_synced: None,
        network: None,
    };
    std::fs::write(sdir.join("meta.json"), serde_json::to_vec(&meta).unwrap()).unwrap();
    let env = Envelope {
        v: 1,
        run: "r".into(),
        seq: 1,
        ts: old_t,
        mono_ns: 0,
        rec: Record::Sample(crate::model::Sample {
            iface: "wlo1".into(),
            role: crate::model::IfaceRole::Wifi,
            link: crate::model::LinkState::default(),
            gw: Some(crate::model::ProbeResult::ok(4.0)),
            isp: None,
            net: crate::model::MultiResult { ok: 3, of: 3, rtt_ms: Some(12.0) },
            tcp: None,
            dns: None,
            rx_delta: 0,
            tx_delta: 0,
            state: crate::model::PathState::Ok,
            speedtest_active: false,
            overrun: false,
            scan_active: false,
            t: Some(old_t),
            freq_mhz: Some(5180),
        }),
    };
    let day_name = format!("samples-{}.jsonl", old_t.format("%Y%m%d"));
    std::fs::write(sdir.join(day_name), format!("{}\n", serde_json::to_string(&env).unwrap())).unwrap();
    let lan_env = Envelope {
        v: 1,
        run: "r".into(),
        seq: 2,
        ts: old_t,
        mono_ns: 0,
        rec: Record::Lan(crate::model::LanSample {
            iface: "enp1s0".into(),
            prefix_len: Some(24),
            probed: 253,
            ping_alive: 4,
            arp_alive: 9,
            unique_seen: 9,
        }),
    };
    let host_name = format!("host-{}.jsonl", old_t.format("%Y%m%d"));
    std::fs::write(sdir.join(host_name), format!("{}\n", serde_json::to_string(&lan_env).unwrap())).unwrap();

    let (addr, stop) = start(Live::new(), d.path().to_path_buf(), None).await;
    let (c, body) = get(addr, "/api/minutes?session=old_sess&hours=6").await;
    assert_eq!(c, 200);
    let v = json(&body);
    assert_eq!(v["ifaces"]["wlo1"].as_array().unwrap().len(), 1);
    assert_eq!(v["lan"].as_array().unwrap().len(), 1);
    assert_eq!(v["lan"][0]["arp_alive"], 9);

    let (c, body) = get(addr, "/api/minutes?session=old_sess&minutes=15").await;
    assert_eq!(c, 200);
    assert_eq!(json(&body)["ifaces"]["wlo1"].as_array().unwrap().len(), 1);

    let (c, body) = get(addr, "/api/report?session=old_sess").await;
    assert_eq!(c, 200);
    let rep = json(&body);
    assert_eq!(rep["session"], "old_sess");
    assert_eq!(rep["ifaces"][0]["iface"], "wlo1");
    assert!(!rep["verdict_summary"].as_str().unwrap().is_empty());
    assert_eq!(rep["lan"]["arp_alive_max"], 9);
    let _ = stop.send(());
}

/// The served module table is exactly the compiled UI (src/web/ui/dist), each module comes from
/// a TypeScript source, and every relative import names a served module (with `.js`).
#[test]
fn ui_module_table_matches_dist() {
    use std::collections::BTreeSet;
    let ui = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/web/ui");
    let names = |dir: &str, ext: &str| -> BTreeSet<String> {
        std::fs::read_dir(ui.join(dir))
            .unwrap()
            .filter_map(|e| e.ok()?.file_name().into_string().ok())
            .filter_map(|n| n.strip_suffix(ext).map(str::to_string))
            .collect()
    };
    let served: BTreeSet<String> =
        UI_MODULES.iter().map(|(n, _)| n.strip_suffix(".js").unwrap().to_string()).collect();
    assert_eq!(served, names("dist", ".js"), "UI_MODULES in src/web/mod.rs vs src/web/ui/dist");
    assert_eq!(served, names("src", ".ts"), "src/web/ui/src/*.ts vs src/web/ui/dist (run `npm run build`)");
    assert!(served.contains("main"));
    for (name, body) in UI_MODULES {
        for line in body.lines().map(str::trim_start) {
            let Some(rest) = line.strip_prefix("import ").or_else(|| line.strip_prefix("export ")) else { continue };
            let Some((_, spec)) = rest.split_once(" from \"") else { continue };
            let spec = spec.split('"').next().unwrap();
            let target = spec.strip_prefix("./").unwrap_or_else(|| panic!("{name}: import {spec:?} is not ./<module>.js"));
            assert!(
                UI_MODULES.iter().any(|(n, _)| *n == target),
                "{name}: import {spec:?} is not a served module"
            );
        }
    }
}

/// Every file in src/web/ui/src/api/ is a binding of a type the API returns, and every such
/// binding is there. `cargo test` rewrites the bindings (ts-rs export tests) and CI fails on
/// `git diff` or untracked files. This test catches what those cannot: a stale file left
/// behind after a type was renamed or removed.
#[test]
fn ts_bindings_match_api_types() {
    use std::collections::BTreeSet;
    use std::path::Path;
    use ts_rs::TS;

    fn walk(root: &Path, dir: &Path, out: &mut BTreeSet<String>) {
        for e in std::fs::read_dir(dir).unwrap() {
            let p = e.unwrap().path();
            if p.is_dir() {
                walk(root, &p, out);
            } else if p.extension().is_some_and(|x| x == "ts") {
                out.insert(p.strip_prefix(root).unwrap().to_string_lossy().replace('\\', "/"));
            }
        }
    }
    fn files(root: &Path) -> BTreeSet<String> {
        let mut out = BTreeSet::new();
        walk(root, root, &mut out);
        out
    }

    let tmp = tempfile::tempdir().unwrap();
    let cfg = ts_rs::Config::from_env().with_out_dir(tmp.path());
    api::ErrorResponse::export_all(&cfg).unwrap();
    api::StatusResponse::<'static>::export_all(&cfg).unwrap();
    api::MinutesResponse::<'static>::export_all(&cfg).unwrap();
    api::EventsResponse::<'static>::export_all(&cfg).unwrap();
    api::SessionEventsResponse::export_all(&cfg).unwrap();
    api::SpeedResponse::<'static>::export_all(&cfg).unwrap();
    api::ScanResponse::<'static>::export_all(&cfg).unwrap();
    api::SiteResponse::<'static>::export_all(&cfg).unwrap();
    api::SessionsResponse::export_all(&cfg).unwrap();
    api::PlanResponse::export_all(&cfg).unwrap();
    api::ControlResponse::export_all(&cfg).unwrap();
    api::ControlSessionResponse::export_all(&cfg).unwrap();
    api::ReportResponse::export_all(&cfg).unwrap();
    crate::router_audit::RouterAudit::export_all(&cfg).unwrap();
    crate::cve::CveLookupResponse::export_all(&cfg).unwrap();
    crate::advice::AdviceResponse::export_all(&cfg).unwrap();
    crate::compare::CompareReport::export_all(&cfg).unwrap();
    // The live feed (SSE) sends envelopes; `Record` is inlined there (flattened) but exported too.
    Envelope::export_all(&cfg).unwrap();
    Record::export_all(&cfg).unwrap();

    let want = files(tmp.path());
    let have = files(&Path::new(env!("CARGO_MANIFEST_DIR")).join("src/web/ui/src/api"));
    assert!(want.contains("Envelope.ts") && want.contains("StatusResponse.ts"), "{want:?}");
    let missing: Vec<_> = want.difference(&have).collect();
    let stale: Vec<_> = have.difference(&want).collect();
    assert!(
        missing.is_empty() && stale.is_empty(),
        "src/web/ui/src/api is out of date: missing {missing:?}, stale {stale:?}. \
         Run `cargo test`, delete stale files, run `npm run build` and commit."
    );
}

// ---------- measurement control and plan ----------

use super::demo::{demo_summary, write_session};

const TOK: &str = "abcdefghijklmnop1234";
const AUTH: &str = "Authorization: Bearer abcdefghijklmnop1234";
const JSON: &str = "Content-Type: application/json";

fn meta_at(id: &str, point: Option<&str>, started: chrono::DateTime<chrono::Utc>) -> SessionMeta {
    SessionMeta {
        v: 1,
        session: id.into(),
        started,
        host: "h".into(),
        version: "0".into(),
        point: point.map(Into::into),
        label: None,
        note: None,
        config: serde_json::json!({}),
        host_id: None,
        tz_offset_s: None,
        clock_synced: None,
        network: None,
    }
}

type Counter = Arc<std::sync::atomic::AtomicUsize>;

/// Server with optional token and a fake run loop that answers every switch with `new-<n>-<point>`.
async fn start_control(site: Option<Arc<Site>>, token: Option<&str>) -> (SocketAddr, tempfile::TempDir, Counter) {
    let d = tempfile::tempdir().unwrap();
    let live = Live::new();
    live.update(|s| s.session = Some(meta_at("cur", Some("B1/F2/R3"), chrono::Utc::now())));
    let (ctl, mut rx) = crate::control::channel();
    let count: Counter = Arc::default();
    let c2 = count.clone();
    tokio::spawn(async move {
        while let Some(crate::control::Command::StartSession { req, reply }) = rx.recv().await {
            let n = c2.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1;
            let _ = reply.send(Ok(format!("new-{n}-{}", req.point.unwrap_or_default().replace(['/', ' '], "_"))));
        }
    });
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (dd, tok) = (d.path().to_path_buf(), token.map(str::to_string));
    tokio::spawn(serve_on(listener, live, dd, site, tok, Some(ctl), std::future::pending()));
    (addr, d, count)
}

fn status_and_body(text: &str) -> (u16, String) {
    let (head, body) = text.split_once("\r\n\r\n").unwrap();
    (head.split(' ').nth(1).unwrap().parse().unwrap(), body.to_string())
}

async fn post(addr: SocketAddr, path: &str, headers: &[&str], body: &str) -> (u16, String) {
    let mut req = format!("POST {path} HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\nContent-Length: {}\r\n", body.len());
    for h in headers {
        req.push_str(h);
        req.push_str("\r\n");
    }
    req.push_str("\r\n");
    req.push_str(body);
    status_and_body(&raw(addr, &req).await)
}

async fn get_auth(addr: SocketAddr, path: &str) -> (u16, String) {
    status_and_body(&raw(addr, &format!("GET {path} HTTP/1.1\r\nHost: {addr}\r\n{AUTH}\r\nConnection: close\r\n\r\n")).await)
}

fn example_site() -> Arc<Site> {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("examples/site.toml");
    Arc::new(Site::load(&path).unwrap())
}

fn switches(c: &Counter) -> usize {
    c.load(std::sync::atomic::Ordering::SeqCst)
}

#[tokio::test]
async fn control_is_off_without_token() {
    let (addr, _d, count) = start_control(None, None).await;
    let v = json(&get(addr, "/api/control").await.1);
    assert_eq!(v["enabled"], false);
    assert_eq!(v["reason"], "set [web] token to enable control");
    assert_eq!(v["point"], "B1/F2/R3");
    assert_eq!(v["site"], false);
    let (c, body) = post(addr, "/api/control/session", &[JSON], r#"{"point":"Hall"}"#).await;
    assert_eq!(c, 403, "{body}");
    assert!(json(&body)["error"].as_str().unwrap().contains("token"));
    assert_eq!(switches(&count), 0);
}

#[tokio::test]
async fn control_post_rules() {
    let (addr, _d, count) = start_control(Some(example_site()), Some(TOK)).await;
    let v = json(&get_auth(addr, "/api/control").await.1);
    assert_eq!(v["enabled"], true);
    assert!(v.get("reason").is_none());
    assert_eq!(v["site"], true);
    assert_eq!(v["min_interval_s"], 10);

    let ok = r#"{"point":"B1/F2/K","label":"night 4","note":"door open"}"#;
    let url = "/api/control/session";
    // Not authenticated: the token middleware refuses.
    assert_eq!(post(addr, url, &[JSON], ok).await.0, 401);
    // Not JSON.
    assert_eq!(post(addr, url, &[AUTH, "Content-Type: text/plain"], ok).await.0, 415);
    assert_eq!(post(addr, url, &[AUTH, "Content-Type: application/x-www-form-urlencoded"], ok).await.0, 415);
    assert_eq!(post(addr, url, &[AUTH], ok).await.0, 415);
    // Cross-origin.
    assert_eq!(post(addr, url, &[AUTH, JSON, "Origin: http://evil.example.com"], ok).await.0, 403);
    assert_eq!(post(addr, url, &[AUTH, JSON, "Origin: null"], ok).await.0, 403);
    assert_eq!(post(addr, url, &[AUTH, JSON, "Sec-Fetch-Site: cross-site"], ok).await.0, 403);
    // Unknown point, unknown field, control characters, too large.
    let (c, body) = post(addr, url, &[AUTH, JSON], r#"{"point":"B9/F1/R1"}"#).await;
    assert_eq!(c, 400);
    assert!(json(&body)["error"].as_str().unwrap().contains("not defined"), "{body}");
    assert_eq!(post(addr, url, &[AUTH, JSON], r#"{"point":"B1/F2/K","x":1}"#).await.0, 400);
    assert_eq!(post(addr, url, &[AUTH, JSON], r#"{"label":"a\u0007b"}"#).await.0, 400);
    assert_eq!(post(addr, url, &[AUTH, JSON], "not json").await.0, 400);
    let big = format!(r#"{{"note":"{}"}}"#, "x".repeat(5000));
    assert_eq!(post(addr, url, &[AUTH, JSON], &big).await.0, 413);
    assert_eq!(switches(&count), 0);

    // Same origin: accepted.
    let same = format!("Origin: http://{addr}");
    let (c, body) = post(addr, url, &[AUTH, JSON, &same], ok).await;
    assert_eq!(c, 200, "{body}");
    assert_eq!(json(&body)["session"], "new-1-B1_F2_K");
    // Rate limit: the next switch within 10 s is refused.
    let r = raw(addr, &format!("POST {url} HTTP/1.1\r\nHost: {addr}\r\n{AUTH}\r\n{JSON}\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{{}}")).await;
    assert!(r.starts_with("HTTP/1.1 429"), "{r}");
    assert!(r.to_ascii_lowercase().contains("retry-after:"), "{r}");
    assert_eq!(switches(&count), 1);
}

#[tokio::test]
async fn control_without_site_takes_free_text_points() {
    let (addr, d, _count) = start_control(None, Some(TOK)).await;
    let now = chrono::Utc::now();
    write_session(d.path(), &meta_at("old", Some("Office desk"), now - chrono::TimeDelta::hours(2)), now, None);
    let v = json(&get_auth(addr, "/api/control").await.1);
    assert_eq!(v["site"], false);
    assert_eq!(v["enabled"], true);
    assert_eq!(v["known_points"], serde_json::json!(["B1/F2/R3", "Office desk"]));
    let url = "/api/control/session";
    let (c, body) = post(addr, url, &[AUTH, JSON], r#"{"point":"x<script>"}"#).await;
    assert_eq!(c, 400, "{body}");
    let long = format!(r#"{{"point":"{}"}}"#, "p".repeat(65));
    assert_eq!(post(addr, url, &[AUTH, JSON], &long).await.0, 400);
    let (c, body) = post(addr, url, &[AUTH, JSON], r#"{"point":" Living room "}"#).await;
    assert_eq!(c, 200, "{body}");
    assert_eq!(json(&body)["session"], "new-1-Living_room");
}

#[tokio::test]
async fn sessions_hide_tiny_ones_and_report_duration() {
    let d = tempfile::tempdir().unwrap();
    let now = chrono::Utc::now();
    let h = chrono::TimeDelta::hours;
    let mut long = meta_at("long", Some("B1/F2/K"), now - h(5));
    long.note = Some("door open".into());
    write_session(d.path(), &long, now - h(1), Some(demo_summary(99.0, "wifi_problem", 8)));
    write_session(d.path(), &meta_at("tiny", Some("B1/F2/K"), now - h(3)), now - h(3) + chrono::TimeDelta::seconds(20), None);
    let no_hb = d.path().join("nohb");
    std::fs::create_dir_all(&no_hb).unwrap();
    std::fs::write(no_hb.join("meta.json"), serde_json::to_vec(&meta_at("nohb", None, now - h(2))).unwrap()).unwrap();
    // The running session is listed even when it has just started.
    write_session(d.path(), &meta_at("cur", Some("B1/F2/R3"), now), now, None);
    let live = Live::new();
    live.update(|s| s.session = Some(meta_at("cur", Some("B1/F2/R3"), now)));
    let (addr, stop) = start(live, d.path().to_path_buf(), None).await;
    let v = json(&get(addr, "/api/sessions").await.1);
    let ids: Vec<&str> = v["sessions"].as_array().unwrap().iter().map(|s| s["id"].as_str().unwrap()).collect();
    assert_eq!(ids, ["cur", "long"]);
    assert_eq!(v["sessions"][0]["current"], true);
    let l = &v["sessions"][1];
    assert_eq!(l["duration_s"], 4.0 * 3600.0);
    assert_eq!(l["note"], "door open");
    assert_eq!(l["availability_pct"], 99.0);
    assert_eq!(l["drops_per_h"], 1.0);
    assert_eq!(l["verdict"], "wifi_problem");
    // Served again from the index cache: same answer.
    assert_eq!(json(&get(addr, "/api/sessions").await.1)["sessions"].as_array().unwrap().len(), 2);
    let _ = stop.send(());
}

#[tokio::test]
async fn plan_progress_with_site() {
    let d = tempfile::tempdir().unwrap();
    let now = chrono::Utc::now();
    let h = chrono::TimeDelta::hours;
    // B1/F2/K: 5 h + 4 h of 8 h planned -> done; availability weighted by duration.
    write_session(d.path(), &meta_at("k1", Some("B1/F2/K"), now - h(30)), now - h(25), Some(demo_summary(99.0, "x", 10)));
    write_session(d.path(), &meta_at("k2", Some("B1/F2/K"), now - h(20)), now - h(16), Some(demo_summary(100.0, "all_ok", 0)));
    // B1/F2/R1: 2 h of 6 h -> partial; a tiny session does not count.
    write_session(d.path(), &meta_at("r1", Some("B1/F2/R1"), now - h(10)), now - h(8), None);
    write_session(d.path(), &meta_at("r1t", Some("B1/F2/R1"), now - h(7)), now - h(7) + chrono::TimeDelta::seconds(30), None);
    // A point that is not planned.
    write_session(d.path(), &meta_at("u", Some("B2/F1/R2"), now - h(6)), now - h(5), None);
    // Running session at B1/F2/R3 (8 h planned): active.
    write_session(d.path(), &meta_at("cur", Some("B1/F2/R3"), now - h(1)), now, None);
    let live = Live::new();
    live.update(|s| s.session = Some(meta_at("cur", Some("B1/F2/R3"), now - h(1))));
    let (addr, stop) = start(live, d.path().to_path_buf(), Some(example_site())).await;
    let v = json(&get(addr, "/api/plan").await.1);
    assert_eq!(v["site"], true);
    assert_eq!(v["current_point"], "B1/F2/R3");
    let items = v["items"].as_array().unwrap();
    let pts: Vec<&str> = items.iter().map(|i| i["point"].as_str().unwrap()).collect();
    assert_eq!(pts, ["B1/F2/R3", "B1/F2/K", "B1/F2/R1", "B2/F1/R2"]);
    let r3 = &items[0];
    assert_eq!((r3["status"].as_str(), r3["planned"].as_bool(), r3["sessions"].as_u64()), (Some("active"), Some(true), Some(1)));
    assert!((r3["measured_s"].as_f64().unwrap() - 3600.0).abs() < 5.0);
    assert_eq!(r3["name"], "Bedroom 3");
    assert_eq!(r3["building_name"], "Block A");
    assert_eq!(r3["unit_label"], "Flat 2");
    assert_eq!(r3["floor"], 0);
    assert_eq!(r3["target_s"], 8.0 * 3600.0);
    assert_eq!(r3["note"], "Bedroom far from the router");
    let k = &items[1];
    assert_eq!((k["status"].as_str(), k["sessions"].as_u64()), (Some("done"), Some(2)));
    assert_eq!(k["measured_s"], 9.0 * 3600.0);
    let avail = k["availability_pct"].as_f64().unwrap();
    assert!((avail - (99.0 * 5.0 + 100.0 * 4.0) / 9.0).abs() < 1e-9, "{avail}");
    assert!((k["drops_per_h"].as_f64().unwrap() - 5.0 / 9.0).abs() < 1e-9);
    assert_eq!(k["last_session"], "k2");
    let r1 = &items[2];
    assert_eq!((r1["status"].as_str(), r1["sessions"].as_u64()), (Some("partial"), Some(1)));
    assert_eq!(r1["measured_s"], 2.0 * 3600.0);
    assert!(r1["availability_pct"].is_null());
    let u = &items[3];
    assert_eq!((u["planned"].as_bool(), u["status"].as_str()), (Some(false), Some("partial")));
    assert!(u["target_s"].is_null());
    assert_eq!(u["name"], "Bedroom 2");
    let _ = stop.send(());
}

#[test]
fn plan_status_todo_and_done_at_target() {
    let site = example_site();
    let now = chrono::Utc::now();
    let s = |id: &str, point: &str, hours: f64| {
        Arc::new(api::IndexedSession {
            id: id.into(),
            started: now - chrono::TimeDelta::hours(30),
            host: "h".into(),
            version: "0".into(),
            point: Some(point.into()),
            label: None,
            note: None,
            last_seen: Some(now - chrono::TimeDelta::hours(30) + chrono::TimeDelta::seconds((hours * 3600.0) as i64)),
            summary: None,
        })
    };
    // Exactly the target counts as done; nothing measured is todo; no current session.
    let items = api::build_plan(Some(&site), &[s("a", "B1/F2/R1", 6.0)], None, now);
    let by = |p: &str| items.iter().find(|i| i.point == p).unwrap().status;
    assert_eq!(by("B1/F2/R1"), api::PlanStatus::Done);
    assert_eq!(by("B1/F2/K"), api::PlanStatus::Todo);
    assert_eq!(items.len(), 3);
}

#[tokio::test]
async fn plan_without_site_lists_measured_points() {
    let d = tempfile::tempdir().unwrap();
    let now = chrono::Utc::now();
    let h = chrono::TimeDelta::hours;
    write_session(d.path(), &meta_at("a", Some("Living room"), now - h(9)), now - h(6), None);
    write_session(d.path(), &meta_at("b", None, now - h(5)), now - h(4), None);
    let live = Live::new();
    live.update(|s| s.session = Some(meta_at("cur", Some("Hall"), now)));
    let (addr, stop) = start(live, d.path().to_path_buf(), None).await;
    let v = json(&get(addr, "/api/plan").await.1);
    assert_eq!(v["site"], false);
    let items = v["items"].as_array().unwrap();
    let pts: Vec<&str> = items.iter().map(|i| i["point"].as_str().unwrap()).collect();
    // The running point is listed even before it has a session directory.
    assert_eq!(pts, ["Hall", "Living room"]);
    let lr = &items[1];
    assert_eq!(lr["name"], "Living room");
    assert_eq!(lr["planned"], false);
    assert_eq!(lr["status"], "partial");
    assert_eq!(lr["measured_s"], 3.0 * 3600.0);
    assert!(lr["building"].is_null());
    assert_eq!(items[0]["status"], "active");
    let _ = stop.send(());
}

#[tokio::test]
async fn router_audit_advice_and_cve_rules() {
    let d = tempfile::tempdir().unwrap();
    let live = Live::new();
    let (addr, stop) = start(live, d.path().to_path_buf(), None).await;

    let (c, body) = get(addr, "/api/advice").await;
    assert_eq!(c, 200, "{body}");
    assert!(json(&body)["items"].is_array(), "{body}");

    let (c, body) = get(addr, "/api/router/audit").await;
    assert_eq!(c, 200, "{body}");
    let audit = json(&body);
    assert_eq!(audit["adapter_used"], "none");
    assert!(audit["gateway_ip"].is_null());

    // Without [web] token configured, active probe & external CVE lookup are refused (403).
    let (c, body) = post(addr, "/api/router/probe", &[JSON], r#"{"adapter":"auto"}"#).await;
    assert_eq!(c, 403, "{body}");
    let (c, body) = post(addr, "/api/router/cve", &[JSON], r#"{"model":"Archer C7"}"#).await;
    assert_eq!(c, 403, "{body}");
    let _ = stop.send(());

    let (addr_tok, _d2, _count) = start_control(None, Some(TOK)).await;
    assert_eq!(post(addr_tok, "/api/router/probe", &[JSON], r#"{"adapter":"auto"}"#).await.0, 401);
    assert_eq!(post(addr_tok, "/api/router/cve", &[JSON], r#"{"model":"Archer C7"}"#).await.0, 401);

    // Cross-origin refused (403).
    assert_eq!(
        post(addr_tok, "/api/router/probe", &[AUTH, JSON, "Origin: http://evil.example.com"], r#"{"adapter":"auto"}"#).await.0,
        403
    );

    // Non-local target rejected before rate limiting / network I/O (400).
    let (c, body) = post(addr_tok, "/api/router/probe", &[AUTH, JSON], r#"{"host":"8.8.8.8"}"#).await;
    assert_eq!(c, 400, "{body}");
    assert!(json(&body)["error"].as_str().unwrap().contains("non-local"), "{body}");

    // Empty model rejected (400).
    let (c, body) = post(addr_tok, "/api/router/cve", &[AUTH, JSON], r#"{"model":"   "}"#).await;
    assert_eq!(c, 400, "{body}");
}

#[tokio::test]
async fn report_export_and_compare_endpoints() {
    let d = tempfile::tempdir().unwrap();
    let now = chrono::Utc::now();
    let h = chrono::TimeDelta::hours;
    write_session(d.path(), &meta_at("s1", Some("Room 1"), now - h(8)), now - h(6), None);
    write_session(d.path(), &meta_at("s2", Some("Room 2"), now - h(4)), now - h(2), None);
    let (addr, stop) = start(Live::new(), d.path().to_path_buf(), None).await;

    let raw_md = raw(addr, &format!("GET /api/report/export?session=s1&format=md HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n\r\n")).await;
    assert!(raw_md.starts_with("HTTP/1.1 200"), "{raw_md}");
    assert!(raw_md.contains("filename=\"linkwatch-s1.md\""), "{raw_md}");
    assert!(raw_md.contains("# linkwatch"), "{raw_md}");

    let (c, body_json) = get(addr, "/api/report/export?session=s1&format=json").await;
    assert_eq!(c, 200, "{body_json}");
    assert!(json(&body_json)["ifaces"].is_array(), "{body_json}");

    assert_eq!(get(addr, "/api/compare?sessions=s1").await.0, 400);

    let (c, cmp_json) = get(addr, "/api/compare?sessions=s1,s2").await;
    assert_eq!(c, 200, "{cmp_json}");
    assert!(json(&cmp_json)["sessions"].as_array().is_some(), "{cmp_json}");

    let (c, cmp_md) = get(addr, "/api/compare?sessions=s1,s2&format=md").await;
    assert_eq!(c, 200, "{cmp_md}");
    assert!(cmp_md.contains("# linkwatch comparison report"), "{cmp_md}");
    let _ = stop.send(());
}

#[tokio::test]
async fn open_view_reads_without_token_but_changes_need_it() {
    let d = tempfile::tempdir().unwrap();
    let live = Live::new();
    live.update(|s| s.session = Some(meta_at("cur", Some("B1/F2/R3"), chrono::Utc::now())));
    let (ctl, _rx) = crate::control::channel();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let opts = WebRouterOpts { open_view: true, ..Default::default() };
    tokio::spawn(serve_on_with_opts(
        listener,
        live,
        d.path().to_path_buf(),
        None,
        Some(TOK.to_string()),
        Some(ctl),
        opts,
        std::future::pending(),
    ));

    // Viewing works without the token, and the UI learns that control is off for this client.
    let (c, body) = get(addr, "/api/status").await;
    assert_eq!(c, 200, "{body}");
    let v = json(&get(addr, "/api/control").await.1);
    assert_eq!(v["enabled"], false);
    assert!(v["reason"].as_str().unwrap().contains("read-only"), "{v}");
    // With the token the same client may control.
    assert_eq!(json(&get_auth(addr, "/api/control").await.1)["enabled"], true);

    // Every change still needs the token.
    assert_eq!(post(addr, "/api/control/session", &[JSON], r#"{"point":"B1/F2/R1"}"#).await.0, 401);
    assert_eq!(post(addr, "/api/router/probe", &[JSON], r#"{"adapter":"auto"}"#).await.0, 401);

    // Open view still refuses foreign Host names (DNS rebinding).
    let r = raw(addr, "GET /api/status HTTP/1.1\r\nHost: evil.example.com\r\nConnection: close\r\n\r\n").await;
    assert_eq!(status_and_body(&r).0, 403);
}
