//! Wi-Fi tasks on blocking threads: station/survey polling, active scans, nl80211 events.

use super::*;

/// Wi-Fi station and survey polling on a dedicated blocking thread (never stalls on scans).
pub(super) async fn wifi_loop(ctx: Ctx) -> anyhow::Result<()> {
    let c = ctx.clone();
    tokio::task::spawn_blocking(move || wifi_blocking(c)).await.context("wifi thread")?
}

pub(super) fn wifi_blocking(ctx: Ctx) -> anyhow::Result<()> {
    let mut nl = wifi::Nl80211::open().context("cannot open nl80211")?;
    let wifis: Vec<String> = ctx.ifaces.iter().filter(|(_, r)| *r == IfaceRole::Wifi).map(|(n, _)| n.clone()).collect();
    let iv = &ctx.cfg.intervals;
    let mut prev_station: HashMap<String, WifiStation> = HashMap::new();
    let mut prev_survey: HashMap<String, SurveyEntry> = HashMap::new();
    let mut last_full_survey: Option<std::time::Instant> = None;
    let mut n: u64 = 0;
    let base = Duration::from_secs(iv.wifi_s.min(iv.survey_s).max(1));
    loop {
        if ctx.stopping() {
            return Ok(());
        }
        for w in &wifis {
            if n.is_multiple_of((iv.wifi_s / base.as_secs()).max(1)) {
                match nl.station(w) {
                    Ok(st) => {
                        if st.connected
                            && let Some(ref b) = st.bssid
                        {
                            ctx.update_fingerprint(|fp| {
                                if !fp.bssids.contains(b) {
                                    fp.bssids.push(b.clone());
                                    true
                                } else {
                                    false
                                }
                            });
                        }
                        if let Some(p) = prev_station.get(w).filter(|p| p.connected && st.connected) {
                            if p.bssid != st.bssid {
                                ctx.emit(EventKind::Roam { iface: w.clone(), from_bssid: p.bssid.clone(), to_bssid: st.bssid.clone() });
                            } else if let (Some(a), Some(b)) = (p.connected_s, st.connected_s)
                                && b < a
                            {
                                // Same AP, but the connection is younger than before: it re-associated
                                // between two polls (disassociation shorter than the poll interval).
                                ctx.emit(EventKind::Reconnect { iface: w.clone(), bssid: st.bssid.clone() });
                            }
                            if p.freq_mhz != st.freq_mhz {
                                ctx.emit(EventKind::ChannelChange { iface: w.clone(), from_mhz: p.freq_mhz, to_mhz: st.freq_mhz });
                            }
                        }
                        prev_station.insert(w.clone(), st.clone());
                        ctx.live.update(|s| {
                            if let Some(i) = s.ifaces.get_mut(w) {
                                i.wifi = Some(st.clone());
                            }
                        });
                        ctx.store.send(Record::Wifi(st));
                    }
                    Err(e) => warn!(iface = %w, "station read failed: {e:#}"),
                }
            }
            if n.is_multiple_of((iv.survey_s / base.as_secs()).max(1)) {
                match nl.survey(w) {
                    Ok(entries) => {
                        if let Some(cur) = entries.iter().find(|e| e.in_use) {
                            if let Some(load) = prev_survey.get(w).and_then(|p| wifi::channel_load(p, cur, w)) {
                                ctx.live.update(|s| {
                                    if let Some(i) = s.ifaces.get_mut(w) {
                                        i.channel_load = Some(load.clone());
                                    }
                                });
                                ctx.store.send(Record::ChannelLoad(load));
                            }
                            prev_survey.insert(w.clone(), cur.clone());
                        }
                        // Full survey (all frequencies) only rarely, to keep logs small.
                        let full_every = iv.scan_s.max(300);
                        if last_full_survey.is_none_or(|t| t.elapsed().as_secs() >= full_every) {
                            ctx.store.send(Record::Survey { iface: w.clone(), entries });
                            last_full_survey = Some(std::time::Instant::now());
                        }
                    }
                    Err(e) => warn!(iface = %w, "survey failed: {e:#}"),
                }
            }
        }
        n += 1;
        if sleep_blocking_until_stop(&ctx, base) {
            return Ok(());
        }
    }
}

pub(super) struct ScanGuard {
    set: Arc<Mutex<HashSet<String>>>,
    iface: String,
}

impl ScanGuard {
    fn enter(set: Arc<Mutex<HashSet<String>>>, iface: String) -> Self {
        set.lock().unwrap_or_else(|e| e.into_inner()).insert(iface.clone());
        Self { set, iface }
    }
}

impl Drop for ScanGuard {
    fn drop(&mut self) {
        self.set.lock().unwrap_or_else(|e| e.into_inner()).remove(&self.iface);
    }
}

/// Active Wi-Fi scan runs on its own blocking thread so the 6 s off-channel wait never blocks station/survey polling.
pub(super) async fn wifi_scan_loop(ctx: Ctx) -> anyhow::Result<()> {
    let c = ctx.clone();
    tokio::task::spawn_blocking(move || wifi_scan_blocking(c)).await.context("wifi_scan thread")?
}

pub(super) fn wifi_scan_blocking(ctx: Ctx) -> anyhow::Result<()> {
    let mut nl = wifi::Nl80211::open().context("cannot open nl80211 for scan")?;
    let wifis: Vec<String> = ctx.ifaces.iter().filter(|(_, r)| *r == IfaceRole::Wifi).map(|(n, _)| n.clone()).collect();
    let mut scan_denied_logged = false;
    if sleep_blocking_until_stop(&ctx, Duration::from_secs(30)) {
        return Ok(());
    }
    loop {
        if ctx.stopping() {
            return Ok(());
        }
        let scan_s = ctx.cfg.intervals.scan_s;
        if scan_s == 0 {
            return Ok(());
        }
        for w in &wifis {
            if ctx.stopping() {
                return Ok(());
            }
            if ctx.speedtest_active.load(Ordering::Relaxed) {
                continue;
            }
            let fresh = match nl.trigger_scan(w) {
                Ok(()) => {
                    let guard = ScanGuard::enter(ctx.scanning_ifaces.clone(), w.clone());
                    let stopped = sleep_blocking_until_stop(&ctx, Duration::from_secs(6));
                    drop(guard);
                    if stopped {
                        return Ok(());
                    }
                    true
                }
                Err(e) => {
                    if !scan_denied_logged {
                        warn!(iface = %w, "cannot trigger scan, using cached results: {e:#}");
                        scan_denied_logged = true;
                    }
                    false
                }
            };
            match nl.scan_results(w) {
                Ok(bss) => {
                    let rep = ScanReport { iface: w.clone(), bss, fresh };
                    let (our_ssid, our_bssid) = ctx.live.update(|s| {
                        let st = s.ifaces.get(w).and_then(|i| i.wifi.as_ref());
                        (st.and_then(|x| x.ssid.clone()), st.and_then(|x| x.bssid.clone()))
                    });
                    let sec_evs = ctx
                        .security
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .check_scan(w, our_ssid.as_deref(), our_bssid.as_deref(), &rep);
                    ctx.emit_all(sec_evs);
                    ctx.live.update(|s| {
                        s.last_scan.insert(w.clone(), rep.clone());
                    });
                    ctx.store.send(Record::Scan(rep));
                }
                Err(e) => warn!(iface = %w, "scan results failed: {e:#}"),
            }
        }
        if sleep_blocking_until_stop(&ctx, Duration::from_secs(scan_s)) {
            return Ok(());
        }
    }
}

/// Kernel nl80211 MLME multicast listener (captures disconnect reason codes & initiator).
pub(super) async fn wifi_events_loop(ctx: Ctx) -> anyhow::Result<()> {
    let c = ctx.clone();
    tokio::task::spawn_blocking(move || wifi_events_blocking(c)).await.context("wifi_events thread")?
}

pub(super) fn build_ifindex_map(ifaces: &[(String, IfaceRole)]) -> HashMap<u32, String> {
    let mut map = HashMap::new();
    for (name, role) in ifaces {
        if *role == IfaceRole::Wifi
            && let Some(idx) = link::ifindex_sysfs(name)
        {
            map.insert(idx, name.clone());
        }
    }
    map
}

pub(super) fn wifi_events_blocking(ctx: Ctx) -> anyhow::Result<()> {
    let mut evs = match wifi::Nl80211Events::open(Duration::from_millis(500)) {
        Ok(e) => e,
        Err(e) => {
            warn!("wifi_events listener disabled: {e:#}");
            while !ctx.stopping() {
                std::thread::sleep(Duration::from_millis(500));
            }
            return Ok(());
        }
    };
    let mut ifmap = build_ifindex_map(&ctx.ifaces);
    while !ctx.stopping() {
        let batch = match evs.next_events() {
            Ok(b) => b,
            Err(e) => {
                warn!("wifi_events read failed: {e:#}");
                return Err(e);
            }
        };
        for ev in batch {
            match ev {
                wifi::MlmeEvent::Disconnect { ifindex, bssid, reason_code, by_ap, timed_out } => {
                    if !ifmap.contains_key(&ifindex) {
                        ifmap = build_ifindex_map(&ctx.ifaces);
                    }
                    let Some(iface) = ifmap.get(&ifindex).cloned() else { continue };
                    let reason = reason_code.map(|c| wifi::nl80211::reason_name(c).to_string());
                    ctx.emit(EventKind::WifiDisconnect {
                        iface,
                        bssid,
                        reason_code,
                        reason,
                        by_ap,
                        timed_out,
                    });
                }
                wifi::MlmeEvent::ChannelSwitch { ifindex, freq_mhz } => {
                    if !ifmap.contains_key(&ifindex) {
                        ifmap = build_ifindex_map(&ctx.ifaces);
                    }
                    let Some(iface) = ifmap.get(&ifindex).cloned() else { continue };
                    ctx.emit(EventKind::ChannelChange {
                        iface,
                        from_mhz: None,
                        to_mhz: Some(freq_mhz),
                    });
                }
            }
        }
    }
    Ok(())
}
