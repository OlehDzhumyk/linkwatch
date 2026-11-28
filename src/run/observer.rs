//! Observer host health and optional router (UPnP) telemetry.

use super::*;

/// Host health monitor (`host` stream) on a dedicated blocking thread.
pub(super) async fn host_loop(ctx: Ctx) -> anyhow::Result<()> {
    let c = ctx.clone();
    tokio::task::spawn_blocking(move || host_blocking(c)).await.context("host thread")?
}

pub(super) fn host_blocking(ctx: Ctx) -> anyhow::Result<()> {
    let mut mon = host::HostMonitor::with_accept(ctx.cfg.advisor.accept.clone());
    let every = Duration::from_secs(ctx.cfg.intervals.host_s.max(1));
    loop {
        if ctx.stopping() {
            return Ok(());
        }
        let wifi_ps: BTreeMap<String, bool> = ctx.live.read(|s| {
            s.ifaces
                .iter()
                .filter_map(|(n, il)| il.wifi.as_ref().and_then(|w| w.power_save).map(|ps| (n.clone(), ps)))
                .collect()
        });
        let (sample, alerts) = mon.sample(&ctx.cfg.data_dir, &ctx.ifaces, wifi_ps);
        ctx.live.update(|s| s.host = Some(sample.clone()));
        ctx.store.send(Record::Host(sample));
        if let Some(tx) = &ctx.notifier {
            for msg in alerts.iter().filter_map(advisor_alert) {
                tx.send(msg);
            }
        }
        ctx.emit_all(alerts);
        if sleep_blocking_until_stop(&ctx, every) {
            return Ok(());
        }
    }
}

/// Notifier message for an advisor event (start or clear). One key per condition and edge, so the
/// notifier cooldown never lets a repeat through.
fn advisor_alert(ev: &EventKind) -> Option<notify::AlertMsg> {
    match ev {
        EventKind::HostAlert { alert: alert @ (HostAlertKind::WifiPowerSave | HostAlertKind::ClockUnsynced), detail, iface } => Some(notify::AlertMsg {
            key: format!("advisor:{}:{}", alert.as_str(), iface.as_deref().unwrap_or("-")),
            title: format!("linkwatch: {}", alert.as_str()),
            body: detail.clone(),
            urgent: false,
        }),
        EventKind::Note { text } => {
            let rest = text.strip_prefix(host::ADVISOR_CLEARED_PREFIX)?;
            let code = rest.split_whitespace().next()?;
            Some(notify::AlertMsg { key: format!("advisor:{code}:cleared:{}", rest.len()), title: format!("linkwatch: {code} cleared"), body: rest.to_string(), urgent: false })
        }
        _ => None,
    }
}

pub(super) fn router_gateway(ctx: &Ctx) -> Option<Ipv4Addr> {
    if let Some(gw) = ctx.cfg.targets.gateway {
        return Some(gw);
    }
    let mut order: Vec<_> = ctx.ifaces.iter().collect();
    order.sort_by_key(|(_, r)| if *r == IfaceRole::Wifi { 1 } else { 0 });
    for (name, _) in order {
        let l = link::read(name);
        if l.carrier
            && let Some(gw) = l.gateway
        {
            return Some(gw);
        }
    }
    None
}

pub(super) async fn router_loop(ctx: Ctx) -> anyhow::Result<()> {
    let mut rx = ctx.shutdown.clone();
    let mut poller = router::Poller::new();
    let mut prev_uptime: Option<u64> = None;
    let mut err_logged = false;
    let every = Duration::from_secs(ctx.cfg.router.interval_s.max(5));

    loop {
        if let Some(gw) = router_gateway(&ctx) {
            match poller.poll(gw, &ctx.cfg.router).await {
                Ok(sample) => {
                    err_logged = false;
                    if let (Some(prev), Some(cur)) = (prev_uptime, sample.uptime_s)
                        && cur + 30 < prev
                    {
                        ctx.emit(EventKind::Note {
                            text: format!("router WAN uptime reset ({prev}s -> {cur}s)"),
                        });
                    }
                    if let Some(u) = sample.uptime_s {
                        prev_uptime = Some(u);
                    }
                    ctx.live.update(|s| s.router = Some(sample.clone()));
                    ctx.store.send(Record::Router(sample));
                }
                Err(e) => {
                    if !err_logged {
                        warn!(gateway = %gw, "router UPnP poll failed: {e:#}");
                        err_logged = true;
                    }
                }
            }
        }
        if sleep_or_stop(&mut rx, every).await {
            return Ok(());
        }
    }
}

pub(super) async fn lan_loop(ctx: Ctx) -> anyhow::Result<()> {
    let mut rx = ctx.shutdown.clone();
    let every = Duration::from_secs(ctx.cfg.intervals.lan_s.max(60));
    if sleep_or_stop(&mut rx, Duration::from_secs(20)).await {
        return Ok(());
    }
    let mut counters: HashMap<String, lan::DeviceCounter> = HashMap::new();

    loop {
        if ctx.speedtest_active.load(Ordering::Relaxed)
            || !ctx.scanning_ifaces.lock().unwrap_or_else(|e| e.into_inner()).is_empty()
        {
            if sleep_or_stop(&mut rx, Duration::from_secs(15)).await {
                return Ok(());
            }
            continue;
        }

        let mut order: Vec<_> = ctx.ifaces.iter().collect();
        order.sort_by_key(|(_, r)| if *r == IfaceRole::Wifi { 1 } else { 0 });

        let mut own_ips = Vec::new();
        let mut links = Vec::with_capacity(order.len());
        for (name, _) in order {
            let l = link::read(name);
            if let Some(ip) = l.ipv4 {
                own_ips.push(ip);
            }
            links.push((name.clone(), l));
        }

        let mut seen_subnets = HashSet::new();
        let mut targets = Vec::new();
        for (iface, l) in links {
            if l.carrier
                && let (Some(ip), Some(prefix)) = (l.ipv4, l.prefix_len)
                && (lan::MIN_PREFIX..=30).contains(&prefix)
            {
                let cidr = link::subnet_cidr(ip, prefix);
                if seen_subnets.insert(cidr.clone()) {
                    targets.push((iface, ip, prefix, cidr));
                }
            }
        }

        let mut deferred = false;
        for (iface, ip, prefix, cidr) in targets {
            if ctx.stopping() {
                return Ok(());
            }
            if ctx.speedtest_active.load(Ordering::Relaxed)
                || !ctx.scanning_ifaces.lock().unwrap_or_else(|e| e.into_inner()).is_empty()
            {
                deferred = true;
                break;
            }
            let counter = counters.entry(cidr).or_default();
            let res = tokio::select! {
                r = lan::count(&iface, ip, prefix, &own_ips, counter) => Some(r),
                _ = rx.wait_for(|v| *v) => None,
            };
            let Some(count) = res else {
                return Ok(());
            };
            if let Some(c) = count {
                let sample = LanSample {
                    iface: iface.clone(),
                    prefix_len: Some(prefix),
                    probed: c.probed,
                    ping_alive: c.ping_alive,
                    arp_alive: c.arp_alive,
                    unique_seen: c.unique_seen,
                };
                info!(
                    iface = %sample.iface,
                    arp_alive = sample.arp_alive,
                    ping_alive = sample.ping_alive,
                    unique_seen = sample.unique_seen,
                    "LAN device sweep"
                );
                ctx.live.update(|s| {
                    s.lan = Some(sample.clone());
                    s.lan_history.push_back(crate::live::LanPoint {
                        t: chrono::Utc::now(),
                        arp_alive: sample.arp_alive,
                        ping_alive: sample.ping_alive,
                        unique_seen: sample.unique_seen,
                    });
                    while s.lan_history.len() > crate::live::LAN_HISTORY_KEPT {
                        s.lan_history.pop_front();
                    }
                });
                ctx.store.send(Record::Lan(sample));
            }
        }

        let wait = if deferred { Duration::from_secs(15) } else { every };
        if sleep_or_stop(&mut rx, wait).await {
            return Ok(());
        }
    }
}
