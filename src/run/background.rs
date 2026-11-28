//! Periodic background tasks: security checks, heartbeat, ISP hop discovery, speed tests.

use super::*;

/// Gateway / DHCP-server / gateway-MAC checks and the network fingerprint, every few seconds.
/// Kept out of the per-second probe loop: it reads lease files and the ARP table.
pub(super) async fn security_loop(ctx: Ctx) -> anyhow::Result<()> {
    const EVERY: Duration = Duration::from_secs(5);
    let mut rx = ctx.shutdown.clone();
    loop {
        for (name, _) in ctx.ifaces.iter() {
            let l = link::read(name);
            if !(l.carrier && l.ipv4.is_some()) {
                continue;
            }
            let gw_ip = ctx.cfg.targets.gateway.or(l.gateway);
            let dhcp = link::dhcp_server(name);
            let mac = gw_ip.and_then(|g| link::arp_mac(g, Some(name)));
            let evs = {
                let mut sec = ctx.security.lock().unwrap_or_else(|e| e.into_inner());
                let mut evs = sec.check_gateway_dhcp(name, l.gateway, dhcp);
                if let (Some(g), Some(m)) = (gw_ip, mac.as_deref()) {
                    evs.extend(sec.check_gateway_mac(name, g, m));
                }
                evs
            };
            ctx.emit_all(evs);
            let sub = l.ipv4.zip(l.prefix_len).map(|(ip, p)| link::subnet_cidr(ip, p));
            ctx.update_fingerprint(|fp| {
                let mut ch = false;
                if fp.gateway_ip.is_none() && let Some(g) = gw_ip { fp.gateway_ip = Some(g); ch = true; }
                if fp.gateway_mac.is_none() && let Some(m) = mac.clone() { fp.gateway_mac = Some(m); ch = true; }
                if fp.subnet.is_none() && let Some(sb) = sub { fp.subnet = Some(sb); ch = true; }
                ch
            });
        }
        if sleep_or_stop(&mut rx, EVERY).await {
            return Ok(());
        }
    }
}

pub(super) async fn heartbeat_loop(ctx: Ctx) -> anyhow::Result<()> {
    let mut rx = ctx.shutdown.clone();
    let every = Duration::from_secs(ctx.cfg.intervals.heartbeat_s.max(1));
    loop {
        let up = mono_ns().saturating_sub(ctx.started_mono) as f64 / 1e9;
        ctx.store.send(Record::Heartbeat { uptime_s: up });
        // Feed the systemd watchdog only while the probe loop is alive.
        let since_tick = mono_ns().saturating_sub(ctx.last_tick_mono.load(Ordering::Relaxed));
        if !ctx.store.writer_alive() {
            error!("store writer stopped; not feeding watchdog so systemd restarts the monitor");
        } else if since_tick < 15_000_000_000 {
            let _ = sd_notify::notify(&[sd_notify::NotifyState::Watchdog]);
        } else {
            warn!(secs = since_tick / 1_000_000_000, "probe loop stalled; not feeding watchdog");
        }
        if sleep_or_stop(&mut rx, every).await {
            return Ok(());
        }
    }
}

pub(super) async fn isp_loop(ctx: Ctx) -> anyhow::Result<()> {
    let mut rx = ctx.shutdown.clone();
    loop {
        // Prefer a wired interface for discovery: it is the more stable path.
        let mut order: Vec<_> = ctx.ifaces.iter().collect();
        order.sort_by_key(|(_, r)| if *r == IfaceRole::Wifi { 1 } else { 0 });
        let mut found = None;
        for (name, _) in order {
            let l = link::read(name);
            if let Some(gw) = l.gateway.filter(|_| l.carrier) {
                found = probe::discover_isp_hop(name, gw, Duration::from_secs(2)).await;
                if found.is_some() {
                    break;
                }
            }
        }
        // `discover_isp_hop` returns only hops that answered echo; a silent or
        // private (second NAT) hop is logged there and leaves `isp_known = false`.
        let prev = ctx.isp();
        if let Some(h) = found
            && prev != Some(h) {
                info!(hop = %h, "ISP first hop");
                ctx.emit(EventKind::Note { text: format!("isp hop {} (was {:?})", h, prev) });
                *ctx.isp_hop.write().unwrap_or_else(|e| e.into_inner()) = Some(h);
                ctx.update_fingerprint(|fp| {
                    if fp.isp_hop != Some(h) {
                        fp.isp_hop = Some(h);
                        true
                    } else {
                        false
                    }
                });
            }
        // Retry soon while unknown, rarely once found.
        let wait = if ctx.isp().is_some() { ctx.cfg.intervals.isp_rediscover_s.max(60) } else { 30 };
        if sleep_or_stop(&mut rx, Duration::from_secs(wait)).await {
            return Ok(());
        }
    }
}

pub(super) async fn speed_loop(ctx: Ctx) -> anyhow::Result<()> {
    let mut rx = ctx.shutdown.clone();
    let started = chrono::Utc::now();
    let mut last: Option<chrono::DateTime<chrono::Utc>> = None;
    loop {
        let next = agg::next_speed_test(&ctx.cfg.speed, last, started);
        let wait = (next - chrono::Utc::now()).to_std().unwrap_or(Duration::ZERO);
        if sleep_or_stop(&mut rx, wait).await {
            return Ok(());
        }
        // One interface at a time, never in parallel.
        for (name, _) in ctx.ifaces.iter() {
            if ctx.stopping() {
                return Ok(());
            }
            let l = link::read(name);
            if !(l.carrier && l.ipv4.is_some()) {
                continue;
            }
            ctx.speedtest_active.store(true, Ordering::Relaxed);
            let sp = &ctx.cfg.speed;
            let opts = speed::Opts {
                max_bytes: sp.max_bytes,
                timeout: Duration::from_secs(sp.timeout_s),
                duration: Duration::from_secs(sp.duration_s),
                warmup: Duration::from_millis(sp.warmup_ms),
            };
            let r = tokio::select! {
                r = speed::download(name, &sp.urls, &opts) => Some(r),
                _ = rx.wait_for(|v| *v) => None,
            };
            ctx.speedtest_active.store(false, Ordering::Relaxed);
            let Some(r) = r else { return Ok(()) };
            info!(iface = %name, mbps = ?r.mbps, err = ?r.err, "speed test");
            ctx.live.update(|s| {
                s.speed.push_back((chrono::Utc::now(), r.clone()));
                while s.speed.len() > 500 {
                    s.speed.pop_front();
                }
            });
            ctx.store.send(Record::Speed(r));
            // Let the link settle before the next interface.
            if sleep_or_stop(&mut rx, Duration::from_secs(5)).await {
                return Ok(());
            }
        }
        last = Some(chrono::Utc::now());
    }
}
