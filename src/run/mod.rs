//! The `run` command: wires probes, classifier, Wi-Fi poller, speed tests, store and web together.
//! Every long-running part is a supervised task: an error or panic is recorded as an event and the
//! task restarts with backoff; the monitor as a whole keeps running.

mod background;
mod observer;
mod tick;
mod wifi_tasks;

use background::*;
use observer::*;
use tick::*;
use wifi_tasks::*;
use crate::agg::{self, BucketAcc};
use crate::classify::{self, PathClassifier};
use crate::config::Config;
use crate::control::{self, SessionRequest};
use crate::live::{IfaceLive, Live, LiveSnapshot};
use crate::model::*;
use crate::{host, lan, link, notify, probe, router, security, site, speed, store, web, wifi};
use anyhow::Context;
use futures::FutureExt;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::net::Ipv4Addr;
use std::panic::AssertUnwindSafe;
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;
use tokio::sync::{mpsc, watch};
use tracing::{error, info, warn};

#[derive(Debug, Clone, Default)]
pub struct RunOpts {
    pub point: Option<String>,
    pub label: Option<String>,
    pub new_session: bool,
    pub no_web: bool,
}

/// Shared handles for all tasks.
#[derive(Clone)]
struct Ctx {
    cfg: Arc<Config>,
    store: Arc<store::StoreHandle>,
    live: Live,
    ifaces: Arc<Vec<(String, IfaceRole)>>,
    isp_hop: Arc<RwLock<Option<Ipv4Addr>>>,
    speedtest_active: Arc<AtomicBool>,
    /// Interfaces currently running an active (off-channel) Wi-Fi scan.
    scanning_ifaces: Arc<Mutex<HashSet<String>>>,
    last_tick_mono: Arc<AtomicU64>,
    shutdown: watch::Receiver<bool>,
    started_mono: u64,
    security: Arc<Mutex<security::SecurityMonitor>>,
    fingerprint: Arc<Mutex<NetworkFingerprint>>,
    notifier: Option<notify::Notifier>,
}

impl Ctx {
    fn emit(&self, ev: EventKind) {
        if let (Some(tx), EventKind::Security { detector, severity, iface, detail }) = (&self.notifier, &ev)
            && self.cfg.alerts.security_events
        {
            tx.send(notify::AlertMsg {
                key: format!("security:{detector}"),
                title: format!("linkwatch security alert: {detector} ({severity})"),
                body: format!("{}{detail}", iface.as_deref().map_or(String::new(), |i| format!("[{i}] "))),
                urgent: severity == "high",
            });
        }
        self.store.send(Record::Event(ev));
    }
    fn emit_all(&self, evs: Vec<EventKind>) {
        for ev in evs {
            self.emit(ev);
        }
    }
    fn stopping(&self) -> bool {
        *self.shutdown.borrow()
    }
    fn isp(&self) -> Option<Ipv4Addr> {
        *self.isp_hop.read().unwrap_or_else(|e| e.into_inner())
    }
    fn update_fingerprint(&self, f: impl FnOnce(&mut NetworkFingerprint) -> bool) {
        let updated = {
            let mut fp = self.fingerprint.lock().unwrap_or_else(|e| e.into_inner());
            if f(&mut fp) { Some(fp.clone()) } else { None }
        };
        if let Some(fingerprint) = updated {
            self.emit(EventKind::NetworkInfo { fingerprint });
        }
    }
}

/// Sleep that ends early on shutdown. Returns true if shutdown was requested.
async fn sleep_or_stop(rx: &mut watch::Receiver<bool>, d: Duration) -> bool {
    if *rx.borrow() {
        return true;
    }
    tokio::select! {
        _ = tokio::time::sleep(d) => *rx.borrow(),
        r = rx.changed() => r.is_err() || *rx.borrow(),
    }
}

/// Run `make()` forever until shutdown, restarting after errors or panics with backoff.
async fn supervise<F, Fut>(name: &'static str, ctx: Ctx, make: F)
where
    F: Fn(Ctx) -> Fut,
    Fut: std::future::Future<Output = anyhow::Result<()>>,
{
    let mut backoff = Duration::from_secs(1);
    loop {
        let started = std::time::Instant::now();
        let res = AssertUnwindSafe(make(ctx.clone())).catch_unwind().await;
        if ctx.stopping() {
            return;
        }
        let err = match res {
            Ok(Ok(())) => "task ended".to_string(),
            Ok(Err(e)) => format!("{e:#}"),
            Err(p) => {
                let msg = p.downcast_ref::<&str>().map(|s| s.to_string()).or_else(|| p.downcast_ref::<String>().cloned());
                format!("panic: {}", msg.unwrap_or_else(|| "unknown".into()))
            }
        };
        error!(task = name, %err, "task stopped, restarting");
        ctx.emit(EventKind::TaskRestart { task: name.into(), error: err });
        if started.elapsed() > Duration::from_secs(60) {
            backoff = Duration::from_secs(1);
        }
        let mut rx = ctx.shutdown.clone();
        if sleep_or_stop(&mut rx, backoff).await {
            return;
        }
        backoff = (backoff * 2).min(Duration::from_secs(60));
    }
}

fn boot_id() -> String {
    std::fs::read_to_string("/proc/sys/kernel/random/boot_id").map(|s| s.trim().to_string()).unwrap_or_else(|_| "unknown".into())
}

fn hostname() -> String {
    std::fs::read_to_string("/proc/sys/kernel/hostname")
        .or_else(|_| std::fs::read_to_string("/etc/hostname"))
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|_| "unknown".into())
}

/// Resolve the interface list: configured ones, or auto-detected physical interfaces.
pub fn resolve_ifaces(cfg: &Config) -> Vec<(String, IfaceRole)> {
    if cfg.interfaces.is_empty() {
        link::list_candidates()
    } else {
        cfg.interfaces.iter().map(|i| (i.name.clone(), i.role.unwrap_or_else(|| link::detect_role(&i.name)))).collect()
    }
}

/// A stopped session is continued when the monitor restarts within this time
/// (reboot, package upgrade, crash) with the same point, label, note and configuration.
const CONTINUE_WITHIN_S: i64 = 12 * 3600;

/// Reuse the newest session with the same point/label/note/config when its last heartbeat is
/// recent (restart after crash, reboot or upgrade), otherwise create a new one.
fn choose_session(
    data_dir: &Path,
    params: &SessionRequest,
    new_session: bool,
    config: &serde_json::Value,
) -> (String, Option<chrono::DateTime<chrono::Utc>>) {
    let now = chrono::Utc::now();
    let mut sessions = store::read::sessions(data_dir);
    sessions.sort_by_key(|s| std::cmp::Reverse(s.1.started));
    if !new_session
        && let Some((dir, meta)) = sessions.first() {
            let recent = store::read::last_heartbeat(dir).is_some_and(|t| (now - t).num_seconds() < CONTINUE_WITHIN_S);
            let unfinished = !dir.join("summary.json").exists();
            if (unfinished || recent)
                && meta.point == params.point
                && meta.label == params.label
                && meta.note == params.note
                && &meta.config == config
            {
                return (meta.session.clone(), Some(meta.started));
            }
        }
    let mut id = now.format("%Y%m%dT%H%M%SZ").to_string();
    if let Some(p) = &params.point {
        let slug: String = p.chars().map(|c| if c.is_ascii_alphanumeric() || c == '-' { c } else { '_' }).collect();
        id.push('_');
        id.push_str(&slug);
    }
    // Never reuse the directory of an existing session by accident (two starts in one second).
    let base = id.clone();
    let mut n = 1;
    while data_dir.join(&id).exists() {
        n += 1;
        id = format!("{base}-{n}");
    }
    (id, None)
}

/// Parts that live as long as the process; sessions come and go inside.
struct Process {
    cfg: Arc<Config>,
    ifaces: Arc<Vec<(String, IfaceRole)>>,
    live: Live,
    config_json: serde_json::Value,
}

/// What ended a session.
enum SessionEnd {
    /// Signal (or test stop): the process exits.
    Stop(&'static str),
    /// Control command: close this session and start another one.
    Switch(SessionRequest, control::Reply),
}

/// Runs the monitor until SIGTERM/SIGINT/SIGHUP. The web UI may switch sessions meanwhile.
pub async fn run(cfg: Config, opts: RunOpts) -> anyhow::Result<()> {
    let (stop_tx, stop_rx) = mpsc::channel(4);
    tokio::spawn(signal_task(stop_tx));
    run_with(cfg, opts, Live::new(), control::channel(), stop_rx).await
}

/// [`run`] with injectable stop reasons and control channel (tests).
pub(crate) async fn run_with(
    cfg: Config,
    opts: RunOpts,
    live: Live,
    (ctl, mut ctl_rx): (control::ControlHandle, mpsc::Receiver<control::Command>),
    mut stop_rx: mpsc::Receiver<&'static str>,
) -> anyhow::Result<()> {
    let cfg = Arc::new(cfg);
    let ifaces = resolve_ifaces(&cfg);
    anyhow::ensure!(!ifaces.is_empty(), "no network interfaces to monitor (set [[interfaces]] in the config)");
    info!(?ifaces, "monitoring interfaces");

    // Optional site model; a bad point id is a configuration error.
    let site = match &cfg.site.file {
        Some(p) => Some(Arc::new(site::Site::load(p).with_context(|| format!("site file {}", p.display()))?)),
        None => None,
    };
    std::fs::create_dir_all(&cfg.data_dir).with_context(|| format!("cannot create {}", cfg.data_dir.display()))?;

    // Command line > control.json (last choice made in the web UI) > [site] in the config.
    let cli = SessionRequest { point: opts.point.clone(), label: opts.label.clone(), note: None };
    let from_config = SessionRequest { point: cfg.site.point.clone(), label: cfg.site.label.clone(), note: None };
    let (mut params, source) = control::initial(&cli, control::load(&cfg.data_dir), &from_config, site.as_deref());
    if let (Some(s), Some(p)) = (&site, &params.point) {
        anyhow::ensure!(s.point(p).is_some(), "point {p:?} is not defined in the site file");
    }
    info!(?source, point = ?params.point, label = ?params.label, "measurement");

    let p = Process {
        cfg: cfg.clone(),
        ifaces: Arc::new(ifaces),
        live: live.clone(),
        config_json: serde_json::to_value(&*cfg).unwrap_or(serde_json::Value::Null),
    };

    // The web server lives for the whole process: it keeps its clone of `live` and its SSE
    // clients across session switches.
    let (web_stop_tx, web_stop_rx) = watch::channel(false);
    let web_task = (cfg.web.enabled && !opts.no_web).then(|| {
        let (l, lv, dd, st, tok) = (cfg.web.listen, live.clone(), cfg.data_dir.clone(), site.clone(), cfg.web.token.clone());
        let router_opts = web::WebRouterOpts {
            upnp_url: cfg.router.upnp_url.clone(),
            nvd_api_key: cfg.router.nvd_api_key.clone(),
            open_view: cfg.web.view == crate::config::ViewAccess::Open,
        };
        let mut rx = web_stop_rx;
        let ctl = ctl.clone();
        tokio::spawn(async move {
            let stop = async move {
                let _ = rx.wait_for(|v| *v).await;
            };
            // A port conflict must not stop monitoring.
            if let Err(e) = web::serve_with_router(l, lv, dd, st, tok, Some(ctl), router_opts, stop).await {
                error!("web UI not available: {e:#}");
            }
        })
    });
    drop(ctl);

    let mut new_session = opts.new_session;
    let mut reply: Option<control::Reply> = None;
    let mut previous: Option<SessionRequest> = None;
    let res = loop {
        match run_session(&p, &params, new_session, &mut reply, &mut stop_rx, &mut ctl_rx).await {
            Ok(SessionEnd::Stop(_)) => break Ok(()),
            Ok(SessionEnd::Switch(req, r)) => {
                info!(point = ?req.point, label = ?req.label, "switching to a new session");
                previous = Some(std::mem::replace(&mut params, req));
                new_session = true;
                reply = Some(r);
            }
            Err(e) => match (reply.take(), previous.take()) {
                // The new session did not open: report it and go back to the previous parameters.
                (Some(r), Some(old)) => {
                    error!("cannot start the requested session: {e:#}");
                    let _ = r.send(Err(format!("cannot start the session: {e:#}")));
                    params = old;
                    new_session = false;
                }
                _ => break Err(e),
            },
        }
    };
    let _ = web_stop_tx.send(true);
    if let Some(t) = web_task {
        let _ = tokio::time::timeout(Duration::from_secs(7), t).await;
    }
    res
}

/// Feeds the systemd watchdog while `f` runs (a session switch stops the heartbeat task).
async fn with_watchdog<T>(f: impl std::future::Future<Output = T>) -> T {
    tokio::pin!(f);
    let mut every = tokio::time::interval(Duration::from_secs(5));
    loop {
        tokio::select! {
            r = &mut f => return r,
            _ = every.tick() => {
                let _ = sd_notify::notify(&[sd_notify::NotifyState::Watchdog]);
            }
        }
    }
}

/// One session: open the store, run all tasks, stop on a signal or a control command, close.
/// `reply` (set when this session comes from a switch) is answered once the store is open;
/// on an open error it is left for the caller.
async fn run_session(
    p: &Process,
    params: &SessionRequest,
    new_session: bool,
    reply: &mut Option<control::Reply>,
    stop_rx: &mut mpsc::Receiver<&'static str>,
    ctl_rx: &mut mpsc::Receiver<control::Command>,
) -> anyhow::Result<SessionEnd> {
    let cfg = &p.cfg;
    let live = &p.live;
    let (session, started) = choose_session(&cfg.data_dir, params, new_session, &p.config_json);
    let init_fp = initial_fingerprint(&p.ifaces, cfg);
    let meta = SessionMeta {
        v: SCHEMA_VERSION,
        session: session.clone(),
        started: started.unwrap_or_else(chrono::Utc::now),
        host: hostname(),
        version: env!("CARGO_PKG_VERSION").into(),
        point: params.point.clone(),
        label: params.label.clone(),
        note: params.note.clone(),
        config: p.config_json.clone(),
        host_id: host::stable_host_id(),
        tz_offset_s: Some(chrono::Local::now().offset().local_minus_utc()),
        clock_synced: Some(host::clock_sync_source().is_some()),
        network: init_fp.clone(),
    };
    // Same `Live` object (the web keeps its clone and the feed), fresh contents.
    live.update(|s| {
        *s = LiveSnapshot::default();
        s.session = Some(meta.clone());
        s.started = Some(meta.started);
        for (n, r) in p.ifaces.iter() {
            s.ifaces.insert(n.clone(), IfaceLive { name: n.clone(), role: Some(*r), ..Default::default() });
        }
    });
    let (store, info) = store::open(&cfg.data_dir, meta, &cfg.storage, live.clone()).await?;
    if let Some(r) = reply.take() {
        if let Err(e) = control::save(&cfg.data_dir, params) {
            warn!("cannot save {}: {e}; a restart goes back to the earlier point", control::CONTROL_FILE);
        }
        let _ = r.send(Ok(session.clone()));
    }
    let store = Arc::new(store);
    let boot = boot_id();
    store.send(Record::Event(EventKind::Start {
        version: env!("CARGO_PKG_VERSION").into(),
        gap_s: info.gap_s,
        boot_id: boot.clone(),
        prev_boot_id: info.prev_boot_id.clone(),
    }));
    if let Some(g) = info.gap_s {
        warn!(gap_s = g, "previous run of this session stopped; gap recorded");
    }

    let (stop_tx, stop_rx_tasks) = watch::channel(false);
    let (notifier, notify_rx) = if cfg.alerts.enabled {
        let (tx, rx) = notify::channel();
        (Some(tx), Some(rx))
    } else {
        (None, None)
    };
    let ctx = Ctx {
        cfg: cfg.clone(),
        store: store.clone(),
        live: live.clone(),
        ifaces: p.ifaces.clone(),
        isp_hop: Arc::new(RwLock::new(cfg.targets.isp_hop)),
        speedtest_active: Arc::new(AtomicBool::new(false)),
        scanning_ifaces: Arc::new(Mutex::new(HashSet::new())),
        last_tick_mono: Arc::new(AtomicU64::new(mono_ns())),
        shutdown: stop_rx_tasks,
        started_mono: mono_ns(),
        security: Arc::new(Mutex::new(security::SecurityMonitor::new())),
        fingerprint: Arc::new(Mutex::new(init_fp.unwrap_or_default())),
        notifier,
    };

    let mut tasks = tokio::task::JoinSet::new();
    if let Some(rx) = notify_rx {
        tasks.spawn(notify::run_loop(cfg.alerts.clone(), rx, ctx.shutdown.clone()));
    }
    let summary = Arc::new(Mutex::new(Summary::default()));
    {
        let s = summary.clone();
        tasks.spawn(supervise("probe", ctx.clone(), move |c| tick_loop(c, s.clone())));
    }
    let has_wifi = ctx.ifaces.iter().any(|(_, r)| *r == IfaceRole::Wifi);
    if has_wifi {
        tasks.spawn(supervise("wifi", ctx.clone(), wifi_loop));
        if cfg.intervals.scan_s > 0 {
            tasks.spawn(supervise("wifi_scan", ctx.clone(), wifi_scan_loop));
        }
        tasks.spawn(supervise("wifi_events", ctx.clone(), wifi_events_loop));
    }
    if cfg.intervals.host_s > 0 {
        tasks.spawn(supervise("host", ctx.clone(), host_loop));
    }
    if cfg.targets.isp_hop.is_none() && cfg.targets.isp_hop_auto {
        tasks.spawn(supervise("isp_discovery", ctx.clone(), isp_loop));
    }
    if cfg.speed.enabled {
        tasks.spawn(supervise("speed", ctx.clone(), speed_loop));
    }
    if cfg.router.enabled && cfg.router.upnp {
        tasks.spawn(supervise("router", ctx.clone(), router_loop));
    }
    if cfg.intervals.lan_s > 0 {
        tasks.spawn(supervise("lan", ctx.clone(), lan_loop));
    }
    tasks.spawn(supervise("heartbeat", ctx.clone(), heartbeat_loop));
    tasks.spawn(supervise("security", ctx.clone(), security_loop));

    let _ = sd_notify::notify(&[sd_notify::NotifyState::Ready]);
    info!(session, "monitor running");

    let end = tokio::select! {
        r = stop_rx.recv() => SessionEnd::Stop(r.unwrap_or("stop")),
        Some(control::Command::StartSession { req, reply }) = ctl_rx.recv() => SessionEnd::Switch(req, reply),
    };
    let reason = match &end {
        SessionEnd::Stop(r) => *r,
        SessionEnd::Switch(..) => "switch",
    };
    info!(reason, session, "stopping session");
    if matches!(end, SessionEnd::Stop(_)) {
        let _ = sd_notify::notify(&[sd_notify::NotifyState::Stopping]);
    }
    let _ = stop_tx.send(true);
    let closed = with_watchdog(async {
        // Give tasks a bounded time to finish (speed test or scan may be in flight).
        let _ = tokio::time::timeout(Duration::from_secs(10), async { while tasks.join_next().await.is_some() {} }).await;
        tasks.abort_all();
        while tasks.join_next().await.is_some() {}

        store.send(Record::Event(EventKind::Stop { reason: reason.into() }));
        let summary_json = summary.lock().unwrap_or_else(|e| e.into_inner()).to_json(&ctx);
        drop(ctx);
        // A blocking thread (scan, speed test) may still hold a handle. Closing a clone stops
        // the writer and releases the data-dir lock anyway; that thread's records are dropped.
        let handle = Arc::try_unwrap(store).unwrap_or_else(|arc| {
            warn!("store still referenced at session end; closing anyway");
            (*arc).clone()
        });
        handle.close(summary_json).await
    })
    .await;
    match (&end, closed) {
        (_, Ok(())) => {}
        (SessionEnd::Stop(_), Err(e)) => return Err(e),
        (SessionEnd::Switch(..), Err(e)) => error!("closing the session failed: {e:#}"),
    }
    Ok(end)
}

/// Sends a stop reason for every SIGTERM/SIGINT/SIGHUP. The handlers are installed once, so
/// no signal is lost between sessions.
async fn signal_task(tx: mpsc::Sender<&'static str>) {
    use tokio::signal::unix::{signal, SignalKind};
    let (Ok(mut term), Ok(mut int), Ok(mut hup)) =
        (signal(SignalKind::terminate()), signal(SignalKind::interrupt()), signal(SignalKind::hangup()))
    else {
        // Cannot install handlers: fall back to ctrl-c only.
        let _ = tokio::signal::ctrl_c().await;
        let _ = tx.send("interrupt").await;
        return;
    };
    loop {
        let r = tokio::select! {
            _ = term.recv() => "sigterm",
            _ = int.recv() => "sigint",
            _ = hup.recv() => "sighup",
        };
        if tx.send(r).await.is_err() {
            return;
        }
    }
}

/// Totals for summary.json.
#[derive(Default)]
struct Summary {
    ticks: u64,
    state_s: BTreeMap<String, BTreeMap<String, f64>>,
    verdict_s: BTreeMap<String, f64>,
    transitions: BTreeMap<String, u64>,
}

impl Summary {
    fn to_json(&self, ctx: &Ctx) -> serde_json::Value {
        let snap = ctx.live.snapshot();
        let total: f64 = self.verdict_s.values().sum();
        let ok: f64 = self.verdict_s.get("all_ok").copied().unwrap_or(0.0);
        // Worst verdict by time spent, excluding all_ok/unknown, for the site plan colour.
        let worst = self
            .verdict_s
            .iter()
            .filter(|(k, _)| k.as_str() != "all_ok" && k.as_str() != "unknown")
            .max_by(|a, b| a.1.total_cmp(b.1))
            .map(|(k, _)| k.clone())
            .unwrap_or_else(|| "all_ok".into());
        serde_json::json!({
            "v": SCHEMA_VERSION,
            "availability_pct": if total > 0.0 { 100.0 * ok / total } else { 0.0 },
            "verdict": worst,
            "ended": chrono::Utc::now(),
            "session": snap.session.as_ref().map(|s| s.session.clone()),
            "point": snap.session.as_ref().and_then(|s| s.point.clone()),
            "uptime_s": (mono_ns().saturating_sub(ctx.started_mono)) as f64 / 1e9,
            "ticks": self.ticks,
            "state_seconds": self.state_s,
            "verdict_seconds": self.verdict_s,
            "transitions": self.transitions,
            "speed": snap.speed.iter().map(|(t, r)| serde_json::json!({"ts": t, "result": r})).collect::<Vec<_>>(),
            "dropped_records": snap.dropped_records,
            "isp_hop": snap.isp_hop,
        })
    }
}

fn state_name(s: PathState) -> String {
    s.as_str().to_string()
}

fn initial_fingerprint(ifaces: &[(String, IfaceRole)], cfg: &Config) -> Option<NetworkFingerprint> {
    let mut fp = NetworkFingerprint {
        isp_hop: cfg.targets.isp_hop,
        ..Default::default()
    };
    let mut ordered: Vec<&(String, IfaceRole)> = ifaces.iter().collect();
    ordered.sort_by_key(|(_, r)| if *r == IfaceRole::Wifi { 1 } else { 0 });
    for (name, _) in ordered {
        let l = link::read(name);
        if l.carrier && l.ipv4.is_some() {
            let gw = cfg.targets.gateway.or(l.gateway);
            if fp.gateway_ip.is_none() {
                fp.gateway_ip = gw;
            }
            if fp.gateway_mac.is_none() {
                fp.gateway_mac = gw.and_then(|g| link::arp_mac(g, Some(name)).or_else(|| link::arp_mac(g, None)));
            }
            if fp.subnet.is_none() {
                fp.subnet = l.ipv4.zip(l.prefix_len).map(|(ip, p)| link::subnet_cidr(ip, p));
            }
        }
    }
    if let Ok(mut nl) = wifi::Nl80211::open() {
        for (name, role) in ifaces {
            if *role == IfaceRole::Wifi
                && let Ok(st) = nl.station(name)
                && st.connected
                && let Some(b) = st.bssid
                && !fp.bssids.contains(&b)
            {
                fp.bssids.push(b);
            }
        }
    }
    (fp != NetworkFingerprint::default()).then_some(fp)
}

fn sleep_blocking_until_stop(ctx: &Ctx, d: Duration) -> bool {
    let until = std::time::Instant::now() + d;
    while std::time::Instant::now() < until {
        if ctx.stopping() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    ctx.stopping()
}

#[cfg(test)]
mod tests;
