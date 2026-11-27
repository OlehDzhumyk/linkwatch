//! Session switching in-process: the same process closes a session and opens the next one.

use super::*;
use crate::config::IfaceConfig;
use crate::model::Stream;

fn test_config(data_dir: &Path) -> Config {
    let mut cfg = Config {
        data_dir: data_dir.to_path_buf(),
        interfaces: vec![IfaceConfig { name: "lo".into(), role: Some(IfaceRole::Ethernet) }],
        ..Default::default()
    };
    cfg.targets.isp_hop_auto = false;
    cfg.targets.internet = vec![Ipv4Addr::LOCALHOST];
    cfg.targets.tcp = Vec::new();
    cfg.targets.dns_servers = vec![Ipv4Addr::LOCALHOST];
    cfg.speed.enabled = false;
    cfg.router.enabled = false;
    cfg.web.enabled = false;
    cfg.intervals.scan_s = 0;
    cfg.intervals.host_s = 0;
    cfg
}

async fn wait_session(live: &Live, not: Option<&str>) -> SessionMeta {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
    loop {
        if let Some(m) = live.read(|s| s.session.clone())
            && not != Some(m.session.as_str())
        {
            return m;
        }
        assert!(tokio::time::Instant::now() < deadline, "no session started");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

fn stop_reasons(dir: &Path) -> Vec<String> {
    store::read::iter(dir, Stream::Events)
        .filter_map(|e| match e.rec {
            Record::Event(EventKind::Stop { reason }) => Some(reason),
            _ => None,
        })
        .collect()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn switch_session_without_restart() {
    let d = tempfile::tempdir().unwrap();
    let cfg = test_config(d.path());
    let live = Live::new();
    let (ctl, ctl_rx) = control::channel();
    let (stop_tx, stop_rx) = mpsc::channel(1);
    let opts = RunOpts { point: Some("Hall".into()), ..Default::default() };
    let run = tokio::spawn(run_with(cfg.clone(), opts, live.clone(), (ctl.clone(), ctl_rx), stop_rx));
    let first = wait_session(&live, None).await;
    assert_eq!(first.point.as_deref(), Some("Hall"));
    let mut feed = live.feed.subscribe();

    // Free-text point (no site file), label and note.
    let req = SessionRequest { point: Some("Living room".into()), label: Some("night 2".into()), note: Some("door open".into()) };
    let id2 = ctl.start_session(req.clone()).await.unwrap();
    assert_ne!(id2, first.session);
    assert!(id2.ends_with("_Living_room"), "{id2}");

    // The old session was closed cleanly; the store opened the new one (lock released).
    let old_dir = d.path().join(&first.session);
    assert!(old_dir.join("summary.json").is_file());
    assert_eq!(stop_reasons(&old_dir), ["switch"]);
    let m = live.read(|s| s.session.clone()).unwrap();
    assert_eq!((m.session.as_str(), m.note.as_deref()), (id2.as_str(), Some("door open")));
    let meta: SessionMeta = serde_json::from_slice(&std::fs::read(d.path().join(&id2).join("meta.json")).unwrap()).unwrap();
    assert_eq!(meta.label.as_deref(), Some("night 2"));
    // The same feed carries the records of the new session.
    let got = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if let Ok(env) = feed.recv().await
                && matches!(env.rec, Record::Event(EventKind::Start { .. }))
            {
                return;
            }
        }
    })
    .await;
    assert!(got.is_ok(), "no start event on the live feed");

    // The choice is persisted.
    assert_eq!(control::load(d.path()), Some(req.clone()));

    stop_tx.send("test").await.unwrap();
    run.await.unwrap().unwrap();
    assert_eq!(stop_reasons(&d.path().join(&id2)), ["test"]);

    // Restart without flags: control.json wins over the config and the session continues.
    let mut cfg2 = cfg.clone();
    cfg2.site.point = Some("Config point".into());
    let live = Live::new();
    let (ctl, ctl_rx) = control::channel();
    let (stop_tx, stop_rx) = mpsc::channel(1);
    let run = tokio::spawn(run_with(cfg2.clone(), RunOpts::default(), live.clone(), (ctl.clone(), ctl_rx), stop_rx));
    let again = wait_session(&live, None).await;
    assert_eq!(again.point.as_deref(), Some("Living room"));
    stop_tx.send("test").await.unwrap();
    run.await.unwrap().unwrap();
    // config changed (site.point), so this is a new session at the persisted point
    assert_ne!(again.session, first.session);

    // Command-line flags win over control.json.
    let live = Live::new();
    let (ctl, ctl_rx) = control::channel();
    let (stop_tx, stop_rx) = mpsc::channel(1);
    let opts = RunOpts { point: Some("Cli point".into()), ..Default::default() };
    let run = tokio::spawn(run_with(cfg2, opts, live.clone(), (ctl, ctl_rx), stop_rx));
    let cli = wait_session(&live, None).await;
    assert_eq!(cli.point.as_deref(), Some("Cli point"));
    stop_tx.send("test").await.unwrap();
    run.await.unwrap().unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn restart_continues_the_switched_session() {
    let d = tempfile::tempdir().unwrap();
    let cfg = test_config(d.path());
    let live = Live::new();
    let (ctl, ctl_rx) = control::channel();
    let (stop_tx, stop_rx) = mpsc::channel(1);
    let run = tokio::spawn(run_with(cfg.clone(), RunOpts::default(), live.clone(), (ctl.clone(), ctl_rx), stop_rx));
    let first = wait_session(&live, None).await;
    assert_eq!(first.point, None);
    let id2 = ctl.start_session(SessionRequest { point: Some("Desk".into()), ..Default::default() }).await.unwrap();
    // Let the heartbeat of the new session reach the disk.
    tokio::time::sleep(Duration::from_millis(500)).await;
    stop_tx.send("test").await.unwrap();
    run.await.unwrap().unwrap();

    let live = Live::new();
    let (ctl, ctl_rx) = control::channel();
    let (stop_tx, stop_rx) = mpsc::channel(1);
    let run = tokio::spawn(run_with(cfg, RunOpts::default(), live.clone(), (ctl, ctl_rx), stop_rx));
    let again = wait_session(&live, None).await;
    assert_eq!(again.session, id2, "same point, label, note and config: the session continues");
    stop_tx.send("test").await.unwrap();
    run.await.unwrap().unwrap();
}
