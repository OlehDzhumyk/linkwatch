//! Per-tick probing of every interface, classification and live/state updates.

use super::*;

/// Comparable part of a link state (bytes counters excluded).
pub(super) fn link_key(l: &LinkState) -> (bool, bool, bool, Option<Ipv4Addr>, Option<u8>, Option<Ipv4Addr>) {
    (l.present, l.up, l.carrier, l.ipv4, l.prefix_len, l.gateway)
}

/// Record carrier of an interface. Returns true when the interface had link at some point in
/// this run, so that it may take part in the verdict.
pub(super) fn note_link(had_link: &mut HashSet<String>, iface: &str, carrier: bool) -> bool {
    if carrier && !had_link.contains(iface) {
        had_link.insert(iface.to_string());
    }
    had_link.contains(iface)
}

pub(super) async fn tick_loop(ctx: Ctx, summary: Arc<Mutex<Summary>>) -> anyhow::Result<()> {
    let cfg = ctx.cfg.clone();
    let period = Duration::from_millis(cfg.intervals.probe_ms);
    let timeout = Duration::from_millis(cfg.intervals.probe_timeout_ms);
    let mut ticker = tokio::time::interval(period);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut rx = ctx.shutdown.clone();

    let now = chrono::Utc::now();
    let mut classifiers: HashMap<String, PathClassifier> =
        ctx.ifaces.iter().map(|(n, _)| (n.clone(), PathClassifier::new(cfg.classify.clone(), now))).collect();
    let mut accs: HashMap<String, BucketAcc> = HashMap::new();
    let mut prev_links: HashMap<String, LinkState> = HashMap::new();
    let mut prev_pkts: HashMap<String, u64> = HashMap::new();
    let mut last_dns: HashMap<String, ProbeResult> = HashMap::new();
    // Consecutive failed DNS queries per interface: one lost UDP query is not an outage.
    let mut dns_fails: HashMap<String, u32> = HashMap::new();
    // Interfaces that had carrier at least once in this run. A path that never had link
    // (unused Ethernet port) takes no part in the verdict.
    let mut had_link: HashSet<String> = HashSet::new();
    let mut verdict = Verdict::Unknown;
    let mut verdict_since = now;
    let mut alert_sent_for: Option<Verdict> = None;
    let mut tick: u64 = 0;
    let (mut last_wall, mut last_mono, mut last_boot) = (chrono::Utc::now(), mono_ns(), boot_ns());
    let dns_every = (cfg.intervals.dns_s * 1000 / cfg.intervals.probe_ms).max(1);
    let tcp_every = (cfg.intervals.tcp_s * 1000 / cfg.intervals.probe_ms).max(1);

    loop {
        tokio::select! {
            _ = ticker.tick() => {},
            r = rx.changed() => { if r.is_err() || *rx.borrow() { return Ok(()); } continue; }
        }
        let tick_start_mono = mono_ns();
        let at = chrono::Utc::now();

        // Clock and suspend detection.
        let (wall_d, mono_d, boot_d) = (
            (at - last_wall).num_milliseconds() as f64 / 1000.0,
            tick_start_mono.saturating_sub(last_mono) as f64 / 1e9,
            boot_ns().saturating_sub(last_boot) as f64 / 1e9,
        );
        if tick > 0 {
            if boot_d - mono_d > 2.0 {
                ctx.emit(EventKind::SuspendGap { secs: boot_d - mono_d });
            } else if (wall_d - mono_d).abs() > 2.0 {
                ctx.emit(EventKind::ClockJump { wall_delta_s: wall_d, mono_delta_s: mono_d });
            }
        }
        let overrun = tick > 0 && mono_d > period.as_secs_f64() * 1.5;
        (last_wall, last_mono, last_boot) = (at, tick_start_mono, boot_ns());

        let do_dns = tick.is_multiple_of(dns_every);
        let do_tcp = tick.is_multiple_of(tcp_every);
        let isp = ctx.isp();
        let st_active = ctx.speedtest_active.load(Ordering::Relaxed);
        let scanning = ctx.scanning_ifaces.lock().unwrap_or_else(|e| e.into_inner()).clone();

        let plan = TickPlan { isp, do_dns, do_tcp, tick, dns_every, timeout };
        // Probe all interfaces concurrently.
        let mut futs = Vec::new();
        for (name, role) in ctx.ifaces.iter() {
            let l = link::read(name);
            if let Some(prev) = prev_links.get(name)
                && link_key(prev) != link_key(&l) {
                    ctx.emit(EventKind::LinkChange { iface: name.clone(), from: prev.clone(), to: l.clone() });
                }
            let rx_delta = prev_links.get(name).map_or(0, |p| l.rx_bytes.saturating_sub(p.rx_bytes));
            let tx_delta = prev_links.get(name).map_or(0, |p| l.tx_bytes.saturating_sub(p.tx_bytes));
            prev_links.insert(name.clone(), l.clone());
            let pkts = link::packets(name);
            let pkt_delta = match (pkts, prev_pkts.get(name)) {
                (Some(now), Some(prev)) => Some(now.saturating_sub(*prev)),
                _ => None,
            };
            if let Some(p) = pkts {
                prev_pkts.insert(name.clone(), p);
            }
            futs.push(probe_iface(ctx.cfg.clone(), plan, IfaceTick { iface: name.clone(), role: *role, link: l, rx_delta, tx_delta, pkt_delta }));
        }
        let samples = futures::future::join_all(futs).await;

        let mut states = Vec::new();
        let mut sum = summary.lock().unwrap_or_else(|e| e.into_inner());
        sum.ticks += 1;
        for (mut s, dns_ans) in samples {
            s.speedtest_active = st_active;
            s.scan_active = scanning.contains(&s.iface);
            s.overrun = overrun;
            s.t = Some(at);
            if let Some((srv, ans)) = dns_ans {
                let sec_evs = ctx
                    .security
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .check_dns(&s.iface, srv, &cfg.targets.dns_name, &ans);
                ctx.emit_all(sec_evs);
            }
            // A DNS query lost while we saturate the link (speed test) or scan off-channel is
            // our own doing: keep it in the sample, but do not let it count towards DnsDown.
            let own_activity = s.speedtest_active || s.scan_active;
            if let Some(d) = s.dns.as_ref().filter(|d| d.ok || !own_activity) {
                let f = dns_fails.entry(s.iface.clone()).or_default();
                *f = if d.ok { 0 } else { *f + 1 };
                last_dns.insert(s.iface.clone(), d.clone());
            }
            if !s.link.carrier {
                // A stale DNS result must not survive a link loss.
                last_dns.remove(&s.iface);
                dns_fails.remove(&s.iface);
            }
            let dns_for_state = match last_dns.get(&s.iface) {
                Some(d) if !d.ok && dns_fails.get(&s.iface).copied().unwrap_or(0) < 2 => None,
                other => other,
            };
            let Some(c) = classifiers.get_mut(&s.iface) else { continue };
            let (inst, tr) = c.feed(&s, isp.is_some(), dns_for_state, at);
            s.state = inst;
            if let Some(t) = &tr {
                ctx.emit(EventKind::StateChange { iface: s.iface.clone(), from: t.from, to: t.to, prev_duration_s: t.prev_duration_s });
                *sum.transitions.entry(s.iface.clone()).or_default() += 1;
            }
            let deb = c.state();
            *sum.state_s.entry(s.iface.clone()).or_default().entry(state_name(deb)).or_default() += period.as_secs_f64();
            if note_link(&mut had_link, &s.iface, s.link.carrier) {
                states.push((s.role, deb));
            }
            let acc = accs.entry(s.iface.clone()).or_default();
            ctx.live.update(|snap| {
                if let Some(il) = snap.ifaces.get_mut(&s.iface) {
                    s.freq_mhz = il.wifi.as_ref().filter(|w| w.connected).and_then(|w| w.freq_mhz);
                    agg::add_sample(&mut il.minutes, acc, &s, inst, at);
                    if let Some(b) = il.minutes.back_mut() {
                        b.signal_dbm = il.wifi.as_ref().and_then(|w| w.signal_dbm).or(b.signal_dbm);
                        b.busy_pct = il.channel_load.as_ref().map(|c| c.busy_pct).or(b.busy_pct);
                    }
                    il.ticks += 1;
                    if s.gw.as_ref().is_some_and(|g| !g.ok) {
                        il.gw_fail += 1;
                    }
                    if s.net.of > 0 && s.net.ok == 0 {
                        il.net_fail += 1;
                    }
                    if !matches!(deb, PathState::Ok | PathState::Degraded | PathState::Unknown) {
                        il.down_s += period.as_secs_f64();
                    }
                    il.state = Some(deb);
                    il.state_since = Some(c.since());
                    il.last = Some(s.clone());
                }
            });
            ctx.store.send(Record::Sample(s));
        }

        let v = classify::verdict(&states, isp.is_some());
        *sum.verdict_s.entry(v.as_str().to_string()).or_default() +=
            period.as_secs_f64();
        drop(sum);
        if v != verdict {
            ctx.emit(EventKind::VerdictChange { from: verdict, to: v, prev_duration_s: (at - verdict_since).num_milliseconds() as f64 / 1000.0 });
            verdict = v;
            verdict_since = at;
        }
        if let Some(tx) = &ctx.notifier {
            let is_bad = matches!(
                verdict,
                Verdict::WifiProblem
                    | Verdict::WiredProblem
                    | Verdict::RouterProblem
                    | Verdict::LineProblem
                    | Verdict::InternetProblem
                    | Verdict::Dns
                    // SinglePath is only returned when the single comparable path is failing.
                    | Verdict::SinglePath
            );
            if is_bad
                && alert_sent_for.is_none()
                && (at - verdict_since).num_seconds() >= cfg.alerts.min_outage_s as i64
            {
                let v_str = verdict.as_str();
                tx.send(notify::AlertMsg {
                    key: format!("outage:{v_str}"),
                    title: format!("linkwatch outage: {v_str}"),
                    body: format!("Verdict {v_str} persisted for >= {} s", cfg.alerts.min_outage_s),
                    urgent: true,
                });
                alert_sent_for = Some(verdict);
            } else if verdict == Verdict::AllOk
                && let Some(prev) = alert_sent_for.take()
            {
                tx.send(notify::AlertMsg {
                    key: "outage:recovery".into(),
                    title: "linkwatch recovered: all_ok".into(),
                    body: format!("Recovered from {}", prev.as_str()),
                    urgent: false,
                });
            }
        }
        ctx.live.update(|snap| {
            snap.verdict = Some(verdict);
            snap.verdict_since = Some(verdict_since);
            snap.isp_hop = isp;
        });
        ctx.last_tick_mono.store(mono_ns(), Ordering::Relaxed);
        tick += 1;
    }
}

/// What every interface probes in one tick (the same for all interfaces).
#[derive(Clone, Copy)]
pub(super) struct TickPlan {
    isp: Option<Ipv4Addr>,
    do_dns: bool,
    do_tcp: bool,
    tick: u64,
    dns_every: u64,
    timeout: Duration,
}

/// Per-interface input of one tick.
pub(super) struct IfaceTick {
    iface: String,
    role: IfaceRole,
    link: LinkState,
    rx_delta: u64,
    tx_delta: u64,
    pkt_delta: Option<u64>,
}

pub(super) async fn probe_iface(cfg: Arc<Config>, plan: TickPlan, it: IfaceTick) -> (Sample, Option<(Ipv4Addr, Vec<Ipv4Addr>)>) {
    let TickPlan { isp, do_dns, do_tcp, tick, dns_every, timeout } = plan;
    let IfaceTick { iface, role, link, rx_delta, tx_delta, pkt_delta } = it;
    let t = &cfg.targets;
    let usable = link.present && link.up && link.carrier && link.ipv4.is_some();
    let mut s = Sample {
        iface: iface.clone(),
        role,
        link: link.clone(),
        gw: None,
        isp: None,
        net: MultiResult { ok: 0, of: t.internet.len() as u8, rtt_ms: None },
        tcp: None,
        dns: None,
        rx_delta,
        tx_delta,
        state: PathState::Unknown,
        speedtest_active: false,
        overrun: false,
        scan_active: false,
        t: None,
        freq_mhz: None,
        pkt_delta,
    };
    if !usable {
        return (s, None);
    }
    let gw_target = t.gateway.or(link.gateway);
    let gw_f = async {
        match gw_target {
            Some(g) => Some(probe::icmp::ping(&iface, g, timeout).await),
            None => None,
        }
    };
    let isp_f = async {
        match isp {
            Some(h) => Some(probe::icmp::ping(&iface, h, timeout).await),
            None => None,
        }
    };
    let net_f = futures::future::join_all(t.internet.iter().map(|ip| probe::icmp::ping(&iface, *ip, timeout)));
    let tcp_f = async {
        if do_tcp && !t.tcp.is_empty() {
            Some(futures::future::join_all(t.tcp.iter().map(|a| probe::tcp::connect(&iface, *a, timeout))).await)
        } else {
            None
        }
    };
    let dns_f = async {
        if !do_dns {
            return None;
        }
        let servers = if t.dns_servers.is_empty() { link::resolv_conf_servers() } else { t.dns_servers.clone() };
        if servers.is_empty() {
            return None;
        }
        // Rotate across servers so one broken resolver is visible but not dominant.
        let srv = servers[(tick / dns_every.max(1)) as usize % servers.len()];
        let (res, ans) = probe::dns::query_with_answers(&iface, srv, &t.dns_name, timeout).await;
        Some((srv, res, ans))
    };
    let (gw, isp_r, net, tcp, dns) = tokio::join!(gw_f, isp_f, net_f, tcp_f, dns_f);
    s.gw = gw;
    s.isp = isp_r;
    s.net = multi(&net);
    s.tcp = tcp.as_deref().map(multi);
    let dns_ans = match dns {
        Some((srv, res, ans)) => {
            s.dns = Some(res);
            (!ans.is_empty()).then_some((srv, ans))
        }
        None => None,
    };
    (s, dns_ans)
}

pub(super) fn multi(rs: &[ProbeResult]) -> MultiResult {
    MultiResult {
        ok: rs.iter().filter(|r| r.ok).count() as u8,
        of: rs.len() as u8,
        rtt_ms: classify::median(rs.iter().filter_map(|r| r.rtt_ms).collect()),
    }
}

#[cfg(test)]
mod verdict_input_tests {
    use super::*;

    fn tick(had: &mut HashSet<String>, wifi: PathState, eth: PathState, wifi_c: bool, eth_c: bool) -> Verdict {
        let mut states = Vec::new();
        if note_link(had, "wlan0", wifi_c) {
            states.push((IfaceRole::Wifi, wifi));
        }
        if note_link(had, "eth0", eth_c) {
            states.push((IfaceRole::Ethernet, eth));
        }
        classify::verdict(&states, true)
    }

    #[test]
    fn unused_ethernet_port_does_not_make_router_problem() {
        let mut had = HashSet::new();
        assert_eq!(tick(&mut had, PathState::Ok, PathState::LinkDown, true, false), Verdict::AllOk);
        let v = tick(&mut had, PathState::LinkDown, PathState::LinkDown, false, false);
        assert_eq!(v, Verdict::SinglePath);
    }

    #[test]
    fn both_paths_had_link_and_lost_it_is_router_problem() {
        let mut had = HashSet::new();
        assert_eq!(tick(&mut had, PathState::Ok, PathState::Ok, true, true), Verdict::AllOk);
        let v = tick(&mut had, PathState::LinkDown, PathState::LinkDown, false, false);
        assert_eq!(v, Verdict::RouterProblem);
    }
}
