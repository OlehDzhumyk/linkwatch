//! Streaming analyzer: consumes envelopes, builds episodes, per-interface and per-band statistics.

use super::*;
use super::detect::*;

// ---------- time windows (seconds) around an episode ----------

/// Host alerts (driver reset, throttling, low memory) count from this long before the episode.
const HOST_NEAR_BEFORE_S: i64 = 30;
/// Host alerts count up to this long after the episode ends (a reset can lag the loss).
const HOST_NEAR_AFTER_S: i64 = 15;
/// An AP-initiated disconnect or timeout this close to an episode explains it.
const AP_DISCONNECT_WINDOW_S: i64 = 15;
/// Router (DOCSIS) log lines this close to an episode are shown and count as router evidence.
const ROUTER_LOG_WINDOW_S: i64 = 120;
/// A host suspend gap this close to an episode means the observer slept.
const SUSPEND_WINDOW_S: i64 = 10;
/// A clock jump this close to an episode makes timing unreliable.
const CLOCK_JUMP_WINDOW_S: i64 = 5;
/// A channel change shortly before the loss is a likely cause; a little after is tolerated.
const CHANNEL_CHANGE_BEFORE_S: i64 = 15;
const CHANNEL_CHANGE_AFTER_S: i64 = 5;
/// A roam shortly before the loss is a likely cause; a little after is tolerated.
const ROAM_BEFORE_S: i64 = 10;
const ROAM_AFTER_S: i64 = 5;
/// A carrier loss on the interface this close to the episode is its cause.
const CARRIER_LOSS_WINDOW_S: i64 = 5;
/// A router reboot this close to an episode explains it (router uptime is polled slowly).
const ROUTER_REBOOT_WINDOW_S: i64 = 60;
/// A router WAN-down sample this close to an episode explains it.
const ROUTER_WAN_DOWN_WINDOW_S: i64 = 30;
/// Signal and busy-channel medians use samples this far around an episode.
const SIGNAL_WINDOW_S: i64 = 60;
/// A speed test that started this long before the context window can still load the link.
const SPEEDTEST_LEAD_S: i64 = 40;
/// LAN device activity is compared over this window around an episode.
const LAN_WINDOW_S: i64 = 600;
/// Backfill an episode band from a Wi-Fi frequency reading at most this far from its middle.
const BAND_BACKFILL_S: i64 = 120;

// ---------- streaming state ----------

#[derive(Default)]
pub(super) struct OpenEp {
    start: Option<DateTime<Utc>>,
    last_bad: Option<DateTime<Utc>>,
    ticks: u32,
    overrun_ticks: u32,
    states: BTreeMap<String, u32>,
    bands: BTreeMap<String, u32>,
    hour_ticks: [u32; 24],
    /// Bad ticks with that flag (dose for the attribution).
    scan: u32,
    speedtest: u32,
    self_traffic: u32,
}

#[derive(Default)]
pub(super) struct BandAcc {
    ticks: u64,
    bad_ticks: u64,
    gw: Vec<f32>,
    net: Vec<f32>,
    signal: Vec<i32>,
    channels: BTreeSet<u32>,
}

#[derive(Default)]
pub(super) struct MinuteAcc {
    gw: Vec<f64>,
    net: Vec<f64>,
}

#[derive(Clone, Copy)]
pub(super) struct PrevWifiCounters {
    ts: DateTime<Utc>,
    retries: Option<u32>,
    failed: Option<u32>,
    beacon_loss: Option<u32>,
}

#[derive(Default)]
pub(super) struct IfAcc {
    role: Option<IfaceRole>,
    ticks: u64,
    bad_ticks: u64,
    no_link_ticks: u64,
    /// Merged intervals without link or address.
    no_link: Vec<(DateTime<Utc>, DateTime<Utc>)>,
    open: OpenEp,
    gw_all: Vec<f32>,
    net_all: Vec<f32>,
    hour_ticks: [u64; 24],
    hour_loss: [u64; 24],
    hour_gw: [Vec<f32>; 24],
    hour_net: [Vec<f32>; 24],
    minutes: BTreeMap<DateTime<Utc>, MinuteAcc>,
    signal: Vec<(DateTime<Utc>, i32)>,
    busy: Vec<(DateTime<Utc>, f64)>,
    rx_busy: Vec<(DateTime<Utc>, f64)>,
    speed: Vec<(DateTime<Utc>, f64)>,
    roams: u32,
    reconnects: u32,
    stalls: u32,
    last_stall: Option<DateTime<Utc>>,
    overrun_ticks: u64,
    self_traffic_ticks: u64,
    self_traffic_stalls: u32,
    last_self_traffic: Option<DateTime<Utc>>,
    stall_events: Vec<(DateTime<Utc>, u64)>,
    loaded_gw: Vec<f32>,
    loaded_net: Vec<f32>,
    peak_net: Vec<f32>,
    offpeak_net: Vec<f32>,
    had_link: bool,
    last_freq_mhz: Option<u32>,
    wifi_freqs: Vec<(DateTime<Utc>, u32)>,
    bands: BTreeMap<String, BandAcc>,
    prev_wifi_counters: Option<PrevWifiCounters>,
    tx_retries_total: u64,
    tx_failed_total: u64,
    beacon_loss_total: u64,
    wifi_counter_secs: f64,
}

#[derive(Clone, Default)]
pub(super) struct EpFlags {
    scan: u32,
    speedtest: u32,
    self_traffic: u32,
    overrun_ticks: u32,
    bands: BTreeMap<String, u32>,
    hour_ticks: [u32; 24],
}

/// Close the open episode of one interface (if any) and reset its accumulator.
fn close_episode(a: &mut IfAcc, iface: &str, tick: Duration, tick_s: f64) -> Option<(Episode, EpFlags)> {
    let (Some(st), Some(lb)) = (a.open.start, a.open.last_bad) else { return None };
    let end_base = lb.max(st);
    let state = a.open.states.iter().max_by_key(|(_, c)| **c).and_then(|(k, _)| serde_json::from_value(serde_json::Value::String(k.clone())).ok()).unwrap_or(PathState::Unknown);
    let bands = std::mem::take(&mut a.open.bands);
    let dom_band = bands.iter().max_by_key(|(_, c)| **c).map(|(k, _)| k.clone());
    let flags = EpFlags {
        scan: a.open.scan,
        speedtest: a.open.speedtest,
        self_traffic: a.open.self_traffic,
        overrun_ticks: a.open.overrun_ticks,
        bands,
        hour_ticks: a.open.hour_ticks,
    };
    let ep = Episode {
        iface: iface.to_string(),
        role: a.role.unwrap_or(IfaceRole::Other),
        start: st,
        end: end_base + tick,
        duration_s: (end_base - st).num_milliseconds().max(0) as f64 / 1000.0 + tick_s,
        ticks: a.open.ticks,
        state,
        cause: None,
        origin: IncidentOrigin::Unknown,
        band: dom_band,
        speedtest_active: false,
        context: texts(&open_context(&a.open)),
        context_msg: open_context(&a.open),
        finding: Default::default(),
    };
    a.open = OpenEp::default();
    Some((ep, flags))
}

pub struct Analyzer {
    opts: Opts,
    ifs: BTreeMap<String, IfAcc>,
    episodes: Vec<(Episode, EpFlags)>,
    events: Vec<(DateTime<Utc>, EventKind)>,
    speedtests: Vec<(DateTime<Utc>, String)>,
    from: Option<DateTime<Utc>>,
    to: Option<DateTime<Utc>>,
    isp_seen: bool,
    host_samples: u64,
    host_throttled_at: Vec<DateTime<Utc>>,
    host_power_save_ifaces: BTreeSet<String>,
    host_clock_unsynced: bool,
    host_max_cpu: Option<f64>,
    host_max_temp: Option<f64>,
    router_samples: Vec<(DateTime<Utc>, RouterSample)>,
    lan_samples: Vec<(DateTime<Utc>, LanSample)>,
}

pub(super) fn pct(v: &mut [f32], p: f64) -> Option<f64> {
    if v.is_empty() {
        return None;
    }
    v.sort_by(|a, b| a.total_cmp(b));
    let idx = ((v.len() - 1) as f64 * p).round() as usize;
    Some(v[idx.min(v.len() - 1)] as f64)
}

pub(super) fn med64(v: &mut [f64]) -> Option<f64> {
    if v.is_empty() {
        return None;
    }
    v.sort_by(|a, b| a.total_cmp(b));
    let m = v.len() / 2;
    Some(if v.len().is_multiple_of(2) { (v[m - 1] + v[m]) / 2.0 } else { v[m] })
}

pub(super) fn minute(t: DateTime<Utc>) -> DateTime<Utc> {
    t.with_second(0).and_then(|t| t.with_nanosecond(0)).unwrap_or(t)
}

pub(super) fn local_hour(t: DateTime<Utc>) -> u32 {
    t.with_timezone(&Local).hour()
}

impl Analyzer {
    pub fn new(opts: Opts) -> Self {
        Self {
            opts,
            ifs: BTreeMap::new(),
            episodes: vec![],
            events: vec![],
            speedtests: vec![],
            from: None,
            to: None,
            isp_seen: false,
            host_samples: 0,
            host_throttled_at: vec![],
            host_power_save_ifaces: BTreeSet::new(),
            host_clock_unsynced: false,
            host_max_cpu: None,
            host_max_temp: None,
            router_samples: vec![],
            lan_samples: vec![],
        }
    }

    pub fn push(&mut self, e: &Envelope) {
        self.from = Some(self.from.map_or(e.ts, |f| f.min(e.ts)));
        self.to = Some(self.to.map_or(e.ts, |t| t.max(e.ts)));
        match &e.rec {
            Record::Sample(s) => self.sample(s.t.unwrap_or(e.ts), s),
            Record::Event(ev) => {
                match ev {
                    EventKind::Roam { iface, .. } => self.ifs.entry(iface.clone()).or_default().roams += 1,
                    EventKind::Reconnect { iface, .. } => self.ifs.entry(iface.clone()).or_default().reconnects += 1,
                    _ => {}
                }
                self.events.push((e.ts, ev.clone()));
            }
            Record::Wifi(w) => {
                if w.power_save == Some(true) {
                    self.host_power_save_ifaces.insert(w.iface.clone());
                }
                let a = self.ifs.entry(w.iface.clone()).or_default();
                if let Some(f) = w.freq_mhz {
                    a.last_freq_mhz = Some(f);
                    a.wifi_freqs.push((e.ts, f));
                }
                if let Some(sig) = w.signal_dbm {
                    a.signal.push((e.ts, sig));
                    if let Some(f) = w.freq_mhz {
                        a.bands.entry(wifi_band(f).into()).or_default().signal.push(sig);
                    }
                }
                if let (Some(ch), Some(f)) = (w.channel, w.freq_mhz) {
                    a.bands.entry(wifi_band(f).into()).or_default().channels.insert(ch);
                }
                if w.connected {
                    if let Some(prev) = a.prev_wifi_counters {
                        let dt = (e.ts - prev.ts).num_milliseconds() as f64 / 1000.0;
                        if dt > 0.0 && dt <= 120.0 {
                            if let (Some(r), Some(pr)) = (w.tx_retries, prev.retries) {
                                a.wifi_counter_secs += dt;
                                a.tx_retries_total += u64::from(if r >= pr { r - pr } else { r });
                            }
                            if let (Some(f), Some(pf)) = (w.tx_failed, prev.failed) {
                                a.tx_failed_total += u64::from(if f >= pf { f - pf } else { f });
                            }
                            if let (Some(bl), Some(pbl)) = (w.beacon_loss, prev.beacon_loss) {
                                a.beacon_loss_total += u64::from(if bl >= pbl { bl - pbl } else { bl });
                            }
                        }
                    }
                    a.prev_wifi_counters = Some(PrevWifiCounters {
                        ts: e.ts,
                        retries: w.tx_retries,
                        failed: w.tx_failed,
                        beacon_loss: w.beacon_loss,
                    });
                } else {
                    a.prev_wifi_counters = None;
                }
            }
            Record::ChannelLoad(c) => {
                let a = self.ifs.entry(c.iface.clone()).or_default();
                a.busy.push((e.ts, c.busy_pct));
                a.rx_busy.push((e.ts, c.rx_pct));
            }
            Record::Router(r) => self.router_samples.push((e.ts, r.clone())),
            Record::Lan(l) => self.lan_samples.push((e.ts, l.clone())),
            Record::Speed(r) => {
                self.speedtests.push((e.ts, r.iface.clone()));
                if let Some(m) = r.mbps {
                    self.ifs.entry(r.iface.clone()).or_default().speed.push((e.ts, m));
                }
            }
            Record::Host(h) => {
                self.host_samples += 1;
                if h.throttled {
                    self.host_throttled_at.push(e.ts);
                }
                if h.clock_synced == Some(false) {
                    self.host_clock_unsynced = true;
                }
                if let Some(c) = h.cpu_pct {
                    self.host_max_cpu = Some(self.host_max_cpu.map_or(c, |m| m.max(c)));
                }
                if let Some(t) = h.temp_c {
                    self.host_max_temp = Some(self.host_max_temp.map_or(t, |m| m.max(t)));
                }
                for (iface, &on) in &h.wifi_power_save {
                    if on {
                        self.host_power_save_ifaces.insert(iface.clone());
                    }
                }
            }
            _ => {}
        }
    }

    fn sample(&mut self, ts: DateTime<Utc>, s: &Sample) {
        let gap = self.opts.merge_gap_s;
        let tick = Duration::milliseconds((self.opts.tick_s * 1000.0) as i64);
        let tick_s = self.opts.tick_s;
        if s.isp.is_some() {
            self.isp_seen = true;
        }
        let a = self.ifs.entry(s.iface.clone()).or_default();
        a.role = Some(s.role);
        if s.link.carrier {
            a.had_link = true;
        }
        if is_no_link(s.role, s.state) {
            a.no_link_ticks += 1;
            match a.no_link.last_mut() {
                Some(iv) if (ts - iv.1).num_seconds() <= gap => iv.1 = ts + tick,
                _ => a.no_link.push((ts, ts + tick)),
            }
            return;
        }
        a.ticks += 1;
        a.overrun_ticks += u64::from(s.overrun);
        if let Some(f) = s.freq_mhz {
            a.last_freq_mhz = Some(f);
        }
        let freq = s.freq_mhz.or(a.last_freq_mhz);
        let band = (s.role == IfaceRole::Wifi).then(|| freq.map(|f| wifi_band(f).to_string())).flatten();
        // Stalls: the path answers, but so late that users notice a freeze.
        let gw_slow = s.gw.as_ref().and_then(|g| g.rtt_ms).is_some_and(|r| r > self.opts.stall_gw_ms);
        let net_slow = s.net.rtt_ms.is_some_and(|r| r > self.opts.stall_net_ms);
        // The host's own load (outside our speed test) on this interface. The previous tick
        // counts too: a path that just failed carries no bytes, but the load caused it.
        let heavy = !s.speedtest_active
            && (s.rx_delta.saturating_add(s.tx_delta) as f64 * 8.0 / tick_s.max(0.2) >= self.opts.self_traffic_bps
                || s.pkt_delta.is_some_and(|p| p as f64 / tick_s.max(0.2) >= self.opts.self_traffic_pps));
        if heavy {
            a.self_traffic_ticks += 1;
            a.last_self_traffic = Some(ts);
        }
        let self_traffic = heavy || a.last_self_traffic.is_some_and(|l| (ts - l).num_seconds() <= gap);
        if self_traffic && !s.speedtest_active && !s.scan_active && !is_bad(s.state) && (gw_slow || net_slow) {
            if a.last_stall.is_none_or(|l| (ts - l).num_seconds() > gap) {
                a.self_traffic_stalls += 1;
            }
            a.last_stall = Some(ts);
        } else if !s.speedtest_active && !s.scan_active && !is_bad(s.state) && (gw_slow || net_slow) {
            if a.last_stall.is_none_or(|l| (ts - l).num_seconds() > gap) {
                a.stalls += 1;
                a.stall_events.push((ts, s.rx_delta.saturating_add(s.tx_delta)));
            }
            a.last_stall = Some(ts);
        }
        if s.speedtest_active {
            if let Some(r) = s.gw.as_ref().and_then(|g| g.rtt_ms) {
                a.loaded_gw.push(r as f32);
            }
            if let Some(r) = s.net.rtt_ms {
                a.loaded_net.push(r as f32);
            }
        }
        let h = local_hour(ts) as usize;
        a.hour_ticks[h] += 1;
        let bad = is_bad(s.state);
        if bad {
            a.bad_ticks += 1;
            a.hour_loss[h] += 1;
        }
        if let Some(ref bname) = band {
            let ba = a.bands.entry(bname.clone()).or_default();
            ba.ticks += 1;
            if bad {
                ba.bad_ticks += 1;
            }
            if !s.speedtest_active {
                if let Some(r) = s.gw.as_ref().and_then(|g| g.rtt_ms) {
                    ba.gw.push(r as f32);
                }
                if let Some(r) = s.net.rtt_ms {
                    ba.net.push(r as f32);
                }
            }
            if let Some(ch) = freq.and_then(crate::wifi::freq_to_channel) {
                ba.channels.insert(ch);
            }
        }
        if !s.speedtest_active {
            if let Some(r) = s.gw.as_ref().and_then(|g| g.rtt_ms) {
                a.gw_all.push(r as f32);
                a.hour_gw[h].push(r as f32);
                a.minutes.entry(minute(ts)).or_default().gw.push(r);
            }
            if let Some(r) = s.net.rtt_ms {
                a.net_all.push(r as f32);
                a.hour_net[h].push(r as f32);
                a.minutes.entry(minute(ts)).or_default().net.push(r);
                if (18..24).contains(&h) {
                    a.peak_net.push(r as f32);
                } else {
                    a.offpeak_net.push(r as f32);
                }
            }
        }
        // Episode tracking.
        let close = |a: &mut IfAcc, iface: &str| close_episode(a, iface, tick, tick_s);
        if bad {
            if let Some(lb) = a.open.last_bad
                && (ts - lb).num_seconds() > gap
                    && let Some(ep) = close(a, &s.iface) {
                        self.episodes.push(ep);
                    }
            if let Some(a) = self.ifs.get_mut(&s.iface) {
                a.open.start.get_or_insert(ts);
                a.open.last_bad = Some(ts);
                a.open.ticks += 1;
                a.open.overrun_ticks += u32::from(s.overrun);
                a.open.scan += u32::from(s.scan_active);
                a.open.speedtest += u32::from(s.speedtest_active);
                a.open.self_traffic += u32::from(self_traffic);
                a.open.hour_ticks[h] += 1;
                if let Some(bname) = band {
                    *a.open.bands.entry(bname).or_default() += 1;
                }
                let key = s.state.as_str().to_string();
                *a.open.states.entry(key).or_default() += 1;
            }
        } else if a.open.last_bad.is_some_and(|lb| (ts - lb).num_seconds() > gap)
            && let Some(ep) = close(a, &s.iface) {
                self.episodes.push(ep);
            }
    }

    pub fn finish(mut self, router: &[RouterLine]) -> Report {
        let tick = Duration::milliseconds((self.opts.tick_s * 1000.0) as i64);
        let tick_s = self.opts.tick_s;
        let overrun_pct = self
            .ifs
            .values()
            .filter(|a| a.ticks > 0)
            .map(|a| a.overrun_ticks as f64 * 100.0 / a.ticks as f64)
            .fold(0.0, f64::max);
        // Close open episodes.
        for (n, a) in self.ifs.iter_mut() {
            if let Some(ep) = close_episode(a, n, tick, tick_s) {
                self.episodes.push(ep);
            }
        }
        // Backfill Wi-Fi episode band from Wifi stream if Samples lacked freq_mhz.
        for (ep, _) in self.episodes.iter_mut() {
            if ep.role == IfaceRole::Wifi
                && ep.band.is_none()
                && let Some(a) = self.ifs.get(&ep.iface)
                && !a.wifi_freqs.is_empty()
            {
                let mid = ep.start + Duration::milliseconds((ep.end - ep.start).num_milliseconds() / 2);
                let best = a
                    .wifi_freqs
                    .iter()
                    .map(|(t, f)| ((*t - mid).num_seconds().abs(), *f))
                    .filter(|(dt, _)| *dt <= BAND_BACKFILL_S)
                    .min_by_key(|(dt, _)| *dt);
                if let Some((_, f)) = best {
                    // Do not add backfilled ticks to flags.bands: sample() never added them to a.bands[b].
                    ep.band = Some(wifi_band(f).to_string());
                }
            }
        }
        self.episodes.sort_by_key(|(e, _)| e.start);

        // Cross-path cause: for each episode, what were the other interfaces doing?
        // Another path counts as failing too only when its outage covers a real part
        // (at least half, or 3 ticks) of this one; a 1-tick blip there must not flip the cause.
        let eps: Vec<(Episode, bool)> = self.episodes.iter().map(|(e, f)| (e.clone(), f.self_traffic > 0)).collect();
        // Router telemetry for the detective: reboots (uptime went back) and WAN-down samples.
        let mut router_reboots = Vec::new();
        let mut router_wan_down = Vec::new();
        {
            let mut rs: Vec<&(DateTime<Utc>, RouterSample)> = self.router_samples.iter().collect();
            rs.sort_by_key(|(t, _)| *t);
            let mut prev: Option<u64> = None;
            for (t, r) in rs {
                if let Some(u) = r.uptime_s {
                    if prev.is_some_and(|p| u + 30 < p) {
                        router_reboots.push(*t - Duration::seconds(u as i64));
                    }
                    prev = Some(u);
                }
                let wan_down = r.wan_down();
                if wan_down {
                    router_wan_down.push(*t);
                }
            }
        }
        let isp_known = self.isp_seen;
        for (ep, flags) in self.episodes.iter_mut() {
            let need = (ep.duration_s / 2.0).min(3.0 * tick_s).max(tick_s * 0.99);
            let others: Vec<(&Episode, bool)> = eps
                .iter()
                .map(|(o, st)| (o, *st))
                .filter(|(o, _)| o.iface != ep.iface && o.start < ep.end && ep.start < o.end)
                .filter(|(o, _)| (o.end.min(ep.end) - o.start.max(ep.start)).num_milliseconds() as f64 / 1000.0 >= need)
                .collect();
            // Other paths that were connected during this episode (with link, so comparable).
            let comparable = self
                .ifs
                .iter()
                .filter(|(n, a)| **n != ep.iface && a.ticks > 0)
                .filter(|(_, a)| !a.no_link.iter().any(|(s, e)| *s < ep.end && ep.start < *e))
                .count();
            ep.cause = Some(if comparable == 0 {
                Verdict::SinglePath
            } else if others.is_empty() {
                if ep.role == IfaceRole::Wifi { Verdict::WifiProblem } else { Verdict::WiredProblem }
            } else {
                let mut st: Vec<(IfaceRole, PathState)> = others.iter().map(|(o, _)| (o.role, o.state)).collect();
                st.push((ep.role, ep.state));
                crate::classify::verdict(&st, isp_known)
            });

            // Observer vs network incident attribution (docs/INCIDENT-ATTRIBUTION.md).
            let near = |t: &DateTime<Utc>| *t >= ep.start - Duration::seconds(HOST_NEAR_BEFORE_S) && *t <= ep.end + Duration::seconds(HOST_NEAR_AFTER_S);
            let ap_disconnect = self.events.iter().any(|(t, ev)| {
                matches!(ev, EventKind::WifiDisconnect { iface, by_ap, timed_out, .. } if *iface == ep.iface && (*by_ap == Some(true) || *timed_out))
                    && *t >= ep.start - Duration::seconds(AP_DISCONNECT_WINDOW_S)
                    && *t <= ep.end + Duration::seconds(AP_DISCONNECT_WINDOW_S)
            });
            let router_hit = router.iter().any(|r| {
                r.ts >= ep.start - Duration::seconds(ROUTER_LOG_WINDOW_S) && r.ts <= ep.end + Duration::seconds(ROUTER_LOG_WINDOW_S)
            });
            let facts = attribution::IncidentFacts {
                role: ep.role,
                duration_s: ep.duration_s,
                ticks: ep.ticks,
                tick_s,
                scan_ticks: flags.scan,
                speedtest_ticks: flags.speedtest,
                self_traffic_ticks: flags.self_traffic,
                overrun_ticks: flags.overrun_ticks,
                suspend_near: self.events.iter().any(|(t, ev)| {
                    matches!(ev, EventKind::SuspendGap { .. }) && *t >= ep.start - Duration::seconds(SUSPEND_WINDOW_S) && *t <= ep.end + Duration::seconds(SUSPEND_WINDOW_S)
                }),
                driver_reset_offset_s: self
                    .events
                    .iter()
                    .filter(|(t, ev)| near(t) && matches!(ev, EventKind::HostAlert { alert: HostAlertKind::DriverReset, detail, iface } if host_alert_iface(iface.as_deref(), detail) == Some(ep.iface.as_str())))
                    .map(|(t, _)| (*t - ep.start).num_milliseconds() as f64 / 1000.0)
                    .reduce(f64::min),
                throttled_near: self.host_throttled_at.iter().any(near),
                low_memory_near: self.events.iter().any(|(t, ev)| near(t) && matches!(ev, EventKind::HostAlert { alert: HostAlertKind::LowMemory, .. })),
                power_save_on: self.host_power_save_ifaces.contains(&ep.iface),
                other_failed: others
                    .iter()
                    .map(|(o, self_traffic)| attribution::OtherFailure { iface: o.iface.clone(), role: o.role, self_traffic: *self_traffic })
                    .collect(),
                comparable_paths: comparable as u32,
                router_hit,
                ap_disconnect,
                clock_jump_near: false,
                router_reboot_near: false,
                router_wan_down_near: false,
                channel_switch_near: false,
                roam_near: false,
                carrier_loss_near: false,
                no_ip: false,
                signal_dbm: None,
                busy_pct: None,
            };
            let ev_near = |s: i64, e: i64, pred: &dyn Fn(&EventKind) -> bool| {
                self.events.iter().any(|(t, ev)| *t >= ep.start - Duration::seconds(s) && *t <= ep.end + Duration::seconds(e) && pred(ev))
            };
            let mut facts = facts;
            facts.clock_jump_near = ev_near(CLOCK_JUMP_WINDOW_S, CLOCK_JUMP_WINDOW_S, &|ev| matches!(ev, EventKind::ClockJump { .. }));
            facts.channel_switch_near = ev_near(CHANNEL_CHANGE_BEFORE_S, CHANNEL_CHANGE_AFTER_S, &|ev| matches!(ev, EventKind::ChannelChange { iface, .. } if *iface == ep.iface));
            facts.roam_near = ev_near(ROAM_BEFORE_S, ROAM_AFTER_S, &|ev| matches!(ev, EventKind::Roam { iface, .. } if *iface == ep.iface));
            facts.carrier_loss_near = ev_near(CARRIER_LOSS_WINDOW_S, CARRIER_LOSS_WINDOW_S, &|ev| matches!(ev, EventKind::LinkChange { iface, from, to } if *iface == ep.iface && from.carrier && !to.carrier));
            facts.router_reboot_near = router_reboots.iter().any(|t| *t >= ep.start - Duration::seconds(ROUTER_REBOOT_WINDOW_S) && *t <= ep.end + Duration::seconds(ROUTER_REBOOT_WINDOW_S));
            facts.router_wan_down_near = router_wan_down.iter().any(|t| *t >= ep.start - Duration::seconds(ROUTER_WAN_DOWN_WINDOW_S) && *t <= ep.end + Duration::seconds(ROUTER_WAN_DOWN_WINDOW_S));
            facts.no_ip = ep.state == PathState::NoIp;
            if let Some(a) = self.ifs.get(&ep.iface) {
                let (w0, w1) = (ep.start - Duration::seconds(SIGNAL_WINDOW_S), ep.end + Duration::seconds(SIGNAL_WINDOW_S));
                facts.signal_dbm = med64(&mut a.signal.iter().filter(|(t, _)| *t >= w0 && *t <= w1).map(|(_, s)| f64::from(*s)).collect::<Vec<_>>());
                facts.busy_pct = med64(&mut a.busy.iter().filter(|(t, _)| *t >= w0 && *t <= w1).map(|(_, b)| *b).collect::<Vec<_>>());
            }
            let finding = attribution::attribute(&facts);
            ep.speedtest_active = flags.speedtest > 0;
            ep.origin = if finding.attribution.is_observer() {
                IncidentOrigin::Observer
            } else if finding.attribution != attribution::Attribution::Network
                || !matches!(ep.cause, None | Some(Verdict::SinglePath | Verdict::Unknown))
                || ap_disconnect
                || router_hit
                || self.host_samples > 0
            {
                IncidentOrigin::Network
            } else {
                IncidentOrigin::Unknown
            };
            ep.finding = finding;
        }

        // Context around episodes.
        let lan_med = (self.lan_samples.len() >= 4)
            .then(|| med64(&mut self.lan_samples.iter().map(|(_, l)| f64::from(l.arp_alive)).collect::<Vec<_>>()))
            .flatten();
        let ctx_s = self.opts.context_s;
        for (ep, _) in self.episodes.iter_mut() {
            let w0 = ep.start - Duration::seconds(ctx_s);
            let w1 = ep.end + Duration::seconds(ctx_s);
            for (t, ev) in &self.events {
                if *t < w0 || *t > w1 {
                    continue;
                }
                let at = t.with_timezone(&Local).format("%H:%M:%S").to_string();
                let line = match ev {
                    EventKind::Roam { iface, from_bssid, to_bssid } if *iface == ep.iface => Some(crate::msg!("c_roam", "{at} roamed {from} → {to}",
                        at = at, from = from_bssid.as_deref().unwrap_or("?"), to = to_bssid.as_deref().unwrap_or("?"))),
                    EventKind::Reconnect { iface, .. } if *iface == ep.iface => Some(crate::msg!("c_reconnect", "{at} Wi-Fi re-associated to the same AP", at = at)),
                    EventKind::WifiDisconnect { iface, reason_code, reason, by_ap, timed_out, .. } if *iface == ep.iface => {
                        let code = reason_code.map_or_else(|| "?".into(), |c| c.to_string());
                        let reason = reason.as_deref().unwrap_or("unknown");
                        Some(match (*by_ap, *timed_out) {
                            (Some(true), _) => crate::msg!("c_disc_ap", "{at} Wi-Fi disconnect (reason {code} {reason}, by AP)", at = at, code = code, reason = reason),
                            (Some(false), _) => crate::msg!("c_disc_client", "{at} Wi-Fi disconnect (reason {code} {reason}, by client)", at = at, code = code, reason = reason),
                            (None, true) => crate::msg!("c_disc_timeout", "{at} Wi-Fi disconnect (reason {code} {reason}, timed out)", at = at, code = code, reason = reason),
                            (None, false) => crate::msg!("c_disc_unknown", "{at} Wi-Fi disconnect (reason {code} {reason}, unknown initiator)", at = at, code = code, reason = reason),
                        })
                    }
                    EventKind::ChannelChange { iface, from_mhz, to_mhz } if *iface == ep.iface => Some(crate::msg!("c_channel", "{at} channel changed {from} → {to} MHz",
                        at = at, from = from_mhz.map_or_else(|| "?".into(), |f| f.to_string()), to = to_mhz.map_or_else(|| "?".into(), |f| f.to_string()))),
                    EventKind::LinkChange { iface, from, to } if *iface == ep.iface => Some(crate::msg!("c_link", "{at} link change: carrier {c1}→{c2}, ip {ip1}→{ip2}",
                        at = at, c1 = from.carrier, c2 = to.carrier, ip1 = from.ipv4.map_or("-".into(), |a| a.to_string()), ip2 = to.ipv4.map_or("-".into(), |a| a.to_string()))),
                    EventKind::SuspendGap { secs } => Some(crate::msg!("c_suspend", "{at} monitor host suspended {s}s", at = at, s = format!("{secs:.0}"))),
                    EventKind::ClockJump { wall_delta_s, .. } => Some(crate::msg!("c_clock", "{at} clock jump {s}s", at = at, s = format!("{wall_delta_s:.0}"))),
                    EventKind::HostAlert { alert, detail, .. } => Some(crate::msg!("c_host", "{at} host alert ({alert}): {detail}", at = at, alert = alert.as_str(), detail = detail)),
                    _ => None,
                };
                if let Some(m) = line {
                    ep.note(m);
                }
            }
            if ep.role == IfaceRole::Wifi {
                for (other_if, oa) in &self.ifs {
                    if *other_if != ep.iface
                        && oa.role == Some(IfaceRole::Wifi)
                        && oa.ticks > 0
                        && !oa.no_link.iter().any(|(s, e)| *s < ep.end && ep.start < *e)
                        && !eps.iter().any(|(o, _)| o.iface == *other_if && o.start < ep.end && ep.start < o.end)
                    {
                        let b = if oa.bands.is_empty() {
                            "unknown band".to_string()
                        } else {
                            oa.bands.keys().cloned().collect::<Vec<_>>().join("/")
                        };
                        ep.note(crate::msg!("c_other_wifi", "other Wi-Fi {other} ({band}) was OK", other = other_if, band = b));
                    }
                }
            }
            if self.speedtests.iter().any(|(t, _)| *t >= w0 - Duration::seconds(SPEEDTEST_LEAD_S) && *t <= w1) {
                ep.note(crate::msg!("c_speedtest", "speed test running nearby"));
            }
            if let Some(a) = self.ifs.get(&ep.iface) {
                let near: Vec<i32> = a.signal.iter().filter(|(t, _)| *t >= w0 && *t <= w1).map(|(_, s)| *s).collect();
                let mut all: Vec<f64> = a.signal.iter().map(|(_, s)| *s as f64).collect();
                if let (Some(min), Some(base)) = (near.iter().min(), med64(&mut all))
                    && (*min as f64) < base - 8.0 {
                        ep.note(crate::msg!("c_signal", "signal dropped to {min} dBm (usual {base})", min = min, base = format!("{base:.0}")));
                    }
                let busy: Vec<f64> = a.busy.iter().filter(|(t, _)| *t >= w0 && *t <= w1).map(|(_, b)| *b).collect();
                let mut ball: Vec<f64> = a.busy.iter().map(|(_, b)| *b).collect();
                if let (Some(mx), Some(base)) = (busy.iter().cloned().fold(None, |m: Option<f64>, x| Some(m.map_or(x, |m| m.max(x)))), med64(&mut ball))
                    && mx > (base + 25.0).max(60.0) {
                        ep.note(crate::msg!("c_busy", "channel busy {mx}% (usual {base}%)", mx = format!("{mx:.0}"), base = format!("{base:.0}")));
                    }
            }
            for r in router.iter().filter(|r| r.ts >= w0 - Duration::seconds(ROUTER_LOG_WINDOW_S) && r.ts <= w1 + Duration::seconds(ROUTER_LOG_WINDOW_S)) {
                ep.note(crate::msg!("c_router_log", "router log: {prio} {line}", prio = r.priority, line = r.text));
            }
            if let Some(base) = lan_med
                && let Some((_, l)) = self
                    .lan_samples
                    .iter()
                    .filter(|(t, _)| *t >= ep.start - Duration::seconds(LAN_WINDOW_S) && *t <= ep.end + Duration::seconds(LAN_WINDOW_S))
                    .max_by_key(|(_, l)| l.arp_alive)
                && f64::from(l.arp_alive) >= (base + 5.0).max(base * 1.5)
            {
                ep.note(crate::msg!("c_lan", "LAN devices active: {n} (usual {base})", n = l.arp_alive, base = format!("{base:.0}")));
            }
        }

        let ep_with_flags = self.episodes;
        let mut rep = Report { from: self.from, to: self.to, tick_s, micro_max_s: self.opts.micro_max_s, ..Default::default() };
        rep.hours = match (self.from, self.to) {
            (Some(f), Some(t)) => (t - f).num_seconds() as f64 / 3600.0,
            _ => 0.0,
        };

        // Router log lines vs episodes.
        for r in router {
            let hit = ep_with_flags.iter().map(|(e, _)| e).find(|e| r.ts >= e.start - Duration::seconds(ROUTER_LOG_WINDOW_S) && r.ts <= e.end + Duration::seconds(ROUTER_LOG_WINDOW_S));
            rep.router_log_matches.push(format!(
                "{} {} {} -> {}",
                r.ts.with_timezone(&Local).format("%m-%d %H:%M:%S"),
                r.priority,
                r.text,
                match hit {
                    Some(e) => format!("matches {} episode at {}", e.iface, e.start.with_timezone(&Local).format("%H:%M:%S")),
                    None => "no outage seen by linkwatch".into(),
                }
            ));
        }

        // Monitor gaps (restarts, suspend) and security events.
        for (t, ev) in &self.events {
            match ev {
                EventKind::Start { gap_s: Some(g), .. } if *g > 5.0 => rep.monitor_gaps.push(format!("{} monitor was not running for {:.0}s", t.with_timezone(&Local).format("%m-%d %H:%M"), g)),
                EventKind::SuspendGap { secs } => rep.monitor_gaps.push(format!("{} host suspended {:.0}s", t.with_timezone(&Local).format("%m-%d %H:%M"), secs)),
                EventKind::TaskRestart { task, error } => rep.monitor_gaps.push(format!("{} task {task} restarted: {error}", t.with_timezone(&Local).format("%m-%d %H:%M"))),
                EventKind::DroppedRecords { count } => rep.monitor_gaps.push(format!("{} {count} records dropped", t.with_timezone(&Local).format("%m-%d %H:%M"))),
                EventKind::Security { detector, severity, iface, detail } => {
                    let who = iface.as_deref().unwrap_or("-");
                    rep.security_events.push(format!("{} [{severity}] {detector} ({who}): {detail}", t.with_timezone(&Local).format("%m-%d %H:%M:%S")));
                }
                _ => {}
            }
        }

        // Per interface (excluding observer-origin incidents/ticks).
        let micro = self.opts.micro_max_s;
        for (name, a) in self.ifs.iter_mut() {
            let mut obs_ticks: u64 = 0;
            let mut obs_band_ticks: BTreeMap<String, u64> = BTreeMap::new();
            let mut obs_hour_ticks: [u64; 24] = [0; 24];
            for (e, f) in ep_with_flags.iter().filter(|(e, _)| e.iface == *name && e.origin == IncidentOrigin::Observer) {
                obs_ticks += u64::from(e.ticks);
                for (b, c) in &f.bands {
                    *obs_band_ticks.entry(b.clone()).or_default() += u64::from(*c);
                }
                for (slot, cnt) in obs_hour_ticks.iter_mut().zip(f.hour_ticks.iter()) {
                    *slot += u64::from(*cnt);
                }
            }
            let eps: Vec<&Episode> = ep_with_flags
                .iter()
                .map(|(e, _)| e)
                .filter(|e| e.iface == *name && e.origin != IncidentOrigin::Observer)
                .collect();
            let eff_ticks = a.ticks.saturating_sub(obs_ticks);
            let eff_bad = a.bad_ticks.saturating_sub(obs_ticks);
            let mut r = IfaceReport { iface: name.clone(), role: a.role, ticks: eff_ticks, no_link_ticks: a.no_link_ticks, had_link: a.had_link, ..Default::default() };
            r.reconnects = a.reconnects;
            r.stalls = a.stalls;
            r.loaded_gw_rtt_med = pct(&mut a.loaded_gw, 0.5);
            r.loaded_net_rtt_med = pct(&mut a.loaded_net, 0.5);
            r.availability_pct = if eff_ticks > 0 {
                100.0 * (1.0 - eff_bad as f64 / eff_ticks as f64)
            } else if a.ticks > 0 {
                100.0
            } else {
                0.0
            };
            r.micro_drops = eps.iter().filter(|e| e.duration_s <= micro).count() as u32;
            r.episodes = eps.len() as u32 - r.micro_drops;
            r.down_s = eps.iter().map(|e| e.duration_s).sum();
            r.longest_s = eps.iter().map(|e| e.duration_s).fold(0.0, f64::max);
            r.gw_rtt_med = pct(&mut a.gw_all, 0.5);
            r.net_rtt_med = pct(&mut a.net_all, 0.5);
            r.signal_med = med64(&mut a.signal.iter().map(|(_, s)| *s as f64).collect::<Vec<_>>());
            r.busy_med = med64(&mut a.busy.iter().map(|(_, b)| *b).collect::<Vec<_>>());
            r.rx_busy_med = med64(&mut a.rx_busy.iter().map(|(_, b)| *b).collect::<Vec<_>>());
            if a.peak_net.len() >= 10 {
                r.peak_net_rtt_p95 = pct(&mut a.peak_net, 0.95);
            }
            if a.offpeak_net.len() >= 10 {
                r.offpeak_net_rtt_p95 = pct(&mut a.offpeak_net, 0.95);
            }
            if a.role == Some(IfaceRole::Wifi) {
                r.wifi_airtime_congestion_stalls = a
                    .stall_events
                    .iter()
                    .filter(|(st_ts, local_bytes)| {
                        let local_bps = *local_bytes as f64 / tick_s.max(0.2);
                        local_bps < 125_000.0
                            && a.busy
                                .iter()
                                .any(|(bt, busy)| (*bt - *st_ts).num_seconds().abs() <= 30 && *busy >= 55.0)
                    })
                    .count() as u32;
            }
            r.speed_tests = a.speed.len() as u32;
            r.speed_med_mbps = med64(&mut a.speed.iter().map(|(_, m)| *m).collect::<Vec<_>>());
            r.speed_peak_med_mbps = med64(&mut a.speed.iter().filter(|(t, _)| (18..24).contains(&local_hour(*t))).map(|(_, m)| *m).collect::<Vec<_>>());
            r.roams = a.roams;
            r.self_traffic_s = a.self_traffic_ticks as f64 * tick_s;
            r.self_traffic_stalls = a.self_traffic_stalls;
            r.tx_failed_total = a.tx_failed_total;
            r.beacon_loss_total = a.beacon_loss_total;
            if a.wifi_counter_secs > 0.0 {
                r.retry_rate_per_min = Some(a.tx_retries_total as f64 / (a.wifi_counter_secs / 60.0));
            }
            for (bname, ba) in a.bands.iter_mut() {
                let obs_bt = obs_band_ticks.get(bname).copied().unwrap_or(0);
                let bt = ba.ticks.saturating_sub(obs_bt);
                if bt == 0 {
                    continue;
                }
                let bbad = ba.bad_ticks.saturating_sub(obs_bt);
                let beps: Vec<&&Episode> = eps.iter().filter(|e| e.band.as_deref() == Some(bname.as_str())).collect();
                let bmicro = beps.iter().filter(|e| e.duration_s <= micro).count() as u32;
                let bep = beps.len() as u32 - bmicro;
                let sig_med = med64(&mut ba.signal.iter().map(|s| *s as f64).collect::<Vec<_>>());
                r.bands.push(BandStats {
                    band: bname.clone(),
                    ticks: bt,
                    bad_ticks: bbad,
                    availability_pct: 100.0 * (1.0 - bbad as f64 / bt as f64),
                    episodes: bep,
                    micro_drops: bmicro,
                    gw_rtt_med: pct(&mut ba.gw, 0.5),
                    net_rtt_med: pct(&mut ba.net, 0.5),
                    signal_med: sig_med,
                    channels: ba.channels.iter().copied().collect(),
                });
            }
            for (h, &obs_ht) in obs_hour_ticks.iter().enumerate() {
                let ht = a.hour_ticks[h].saturating_sub(obs_ht);
                if ht == 0 {
                    continue;
                }
                let hloss = a.hour_loss[h].saturating_sub(obs_ht);
                let hu = h as u32;
                r.hours.push(HourRow {
                    hour: hu,
                    ticks: ht,
                    loss_pct: 100.0 * hloss as f64 / ht as f64,
                    gw_rtt_med: pct(&mut a.hour_gw[h], 0.5),
                    gw_rtt_p95: pct(&mut a.hour_gw[h], 0.95),
                    net_rtt_med: pct(&mut a.hour_net[h], 0.5),
                    net_rtt_p95: pct(&mut a.hour_net[h], 0.95),
                    episodes: eps.iter().filter(|e| e.duration_s > micro && local_hour(e.start) == hu).count() as u32,
                    micro_drops: eps.iter().filter(|e| e.duration_s <= micro && local_hour(e.start) == hu).count() as u32,
                });
            }
            // Anomalous minutes (robust z on per-minute medians).
            let gw_min: Vec<(DateTime<Utc>, f64)> = a.minutes.iter_mut().filter_map(|(t, m)| med64(&mut m.gw).map(|v| (*t, v))).collect();
            let net_min: Vec<(DateTime<Utc>, f64)> = a.minutes.iter_mut().filter_map(|(t, m)| med64(&mut m.net).map(|v| (*t, v))).collect();
            let sig: Vec<(DateTime<Utc>, f64)> = a.signal.iter().map(|(t, s)| (*t, -(*s as f64))).collect();
            let busy: Vec<(DateTime<Utc>, f64)> = a.busy.clone();
            for (metric, series, sign) in [("router RTT ms", gw_min, 1.0), ("internet RTT ms", net_min, 1.0), ("signal dBm (weaker)", sig, -1.0), ("channel busy %", busy, 1.0)] {
                rep.anomalies.extend(robust_anomalies(name, metric, &series, self.opts.z, sign));
            }
            rep.ifaces.push(r);
        }
        let episodes: Vec<Episode> = ep_with_flags.into_iter().map(|(e, _)| e).collect();

        let key = |v: Option<Verdict>| v.map_or("unknown", Verdict::as_str).to_string();
        for e in &episodes {
            if e.origin != IncidentOrigin::Observer && !is_load_provoked(e) {
                *rep.causes.entry(key(e.cause)).or_default() += 1;
            }
        }
        // Incidents: overlapping episodes of different interfaces are one real-world event.
        // Observer-origin and short speedtest-load incidents are counted separately and excluded
        // from unprovoked network verdicts.
        let mut cur: Option<(DateTime<Utc>, &Episode, bool, bool)> = None;
        let record_inc = |rep: &mut Report, longest: &Episode, all_obs: bool, has_unprovoked: bool| {
            if all_obs {
                rep.observer_incidents += 1;
            } else if !has_unprovoked {
                rep.load_incidents += 1;
            } else {
                rep.network_incidents += 1;
                *rep.incidents.entry(key(longest.cause)).or_default() += 1;
            }
        };
        for e in &episodes {
            let obs = e.origin == IncidentOrigin::Observer;
            let unprovoked = !obs && !is_load_provoked(e);
            match &mut cur {
                Some((end, longest, all_obs, has_unprovoked)) if e.start < *end => {
                    *end = (*end).max(e.end);
                    *all_obs &= obs;
                    *has_unprovoked |= unprovoked;
                    if e.duration_s > longest.duration_s {
                        *longest = e;
                    }
                }
                _ => {
                    if let Some((_, l, all_obs, has_unprovoked)) = cur.take() {
                        record_inc(&mut rep, l, all_obs, has_unprovoked);
                    }
                    cur = Some((e.end, e, obs, unprovoked));
                }
            }
        }
        if let Some((_, l, all_obs, has_unprovoked)) = cur {
            record_inc(&mut rep, l, all_obs, has_unprovoked);
        }
        if !self.host_power_save_ifaces.is_empty() {
            let names: Vec<_> = self.host_power_save_ifaces.iter().cloned().collect();
            rep.observer_findings_msg.push(crate::msg!("o_power_save", "Wi-Fi power-save was ON on {ifs} (can double RTT and add jitter; disable with `iw dev <if> set power_save off`)", ifs = names.join(", ")));
        }
        if self.host_clock_unsynced {
            rep.observer_findings_msg.push(crate::msg!("o_ntp", "Observer clock was not NTP-synchronized during part of the session; cross-device comparisons need care."));
        }
        if !self.host_throttled_at.is_empty() {
            rep.observer_findings_msg.push(crate::msg!("o_throttled", "Observer reported undervoltage or thermal throttling in {n} host samples.", n = self.host_throttled_at.len()));
        }
        if let Some(c) = self.host_max_cpu
            && c >= 85.0
        {
            rep.observer_findings_msg.push(crate::msg!("o_cpu", "Observer CPU peaked at {v}%.", v = format!("{c:.0}")));
        }
        if let Some(t) = self.host_max_temp
            && t >= 75.0
        {
            rep.observer_findings_msg.push(crate::msg!("o_temp", "Observer temperature peaked at {v}°C.", v = format!("{t:.1}")));
        }
        let busy: Vec<String> = rep
            .ifaces
            .iter()
            .filter(|i| i.self_traffic_s >= 60.0)
            .map(|i| format!("{} ({:.0} min)", i.iface, i.self_traffic_s / 60.0))
            .collect();
        if !busy.is_empty() {
            rep.observer_findings_msg.push(crate::msg!(
                "o_self_traffic",
                "The observer's own traffic was above {mbps} Mbit/s or {pps} packets/s outside speed tests on {ifs}; stalls and short drops in that time are not counted as network faults.",
                mbps = format!("{:.0}", self.opts.self_traffic_bps / 1e6),
                pps = format!("{:.0}", self.opts.self_traffic_pps),
                ifs = busy.join(", "),
            ));
        }
        if rep.observer_incidents > 0 {
            rep.observer_findings_msg.push(crate::msg!("o_incidents", "{n} incident(s) attributed to the observer device (scan/overrun/suspend/throttling) and excluded from network totals.", n = rep.observer_incidents));
        }
        rep.observer_findings = texts(&rep.observer_findings_msg);
        rep.observer_trust = observer_trust(&TrustInputs {
            power_save_ifaces: self.host_power_save_ifaces.iter().cloned().collect(),
            overrun_pct,
            throttled_samples: self.host_throttled_at.len() as u64,
            host_samples: self.host_samples,
            clock_unsynced: self.host_clock_unsynced,
            self_traffic_s: rep.ifaces.iter().map(|i| i.self_traffic_s).fold(0.0, f64::max),
            observer_incidents: rep.observer_incidents,
            max_cpu: self.host_max_cpu,
        });

        if !self.router_samples.is_empty() {
            self.router_samples.sort_by_key(|(t, _)| *t);
            let mut rr = RouterReport {
                samples: self.router_samples.len() as u64,
                model: self.router_samples.iter().rev().find_map(|(_, r)| r.model.clone()),
                link_down_mbps: self.router_samples.iter().rev().find_map(|(_, r)| r.link_down_mbps),
                bytes_saturated: self.router_samples.iter().any(|(_, r)| r.bytes_saturated),
                ..Default::default()
            };
            let mut prev_up: Option<u64> = None;
            let mut wan_rx_mbps = Vec::new();
            let mut wan_rx_pps = Vec::new();
            let mut wan_tx_pps = Vec::new();
            for (_, rs) in &self.router_samples {
                if rs.wan_down() {
                    rr.wan_down_samples += 1;
                }
                if let Some(u) = rs.uptime_s {
                    if let Some(p) = prev_up && u + 30 < p {
                        rr.uptime_resets += 1;
                    }
                    prev_up = Some(u);
                }
                if let Some(v) = rs.wan_rx_mbps {
                    wan_rx_mbps.push(v as f32);
                }
                if let Some(v) = rs.wan_rx_pps {
                    wan_rx_pps.push(v as f32);
                }
                if let Some(v) = rs.wan_tx_pps {
                    wan_tx_pps.push(v as f32);
                }
            }
            rr.wan_rx_mbps_med = pct(&mut wan_rx_mbps, 0.5);
            rr.wan_rx_mbps_p95 = pct(&mut wan_rx_mbps, 0.95);
            rr.wan_rx_pps_med = pct(&mut wan_rx_pps, 0.5);
            rr.wan_rx_pps_p95 = pct(&mut wan_rx_pps, 0.95);
            rr.wan_tx_pps_med = pct(&mut wan_tx_pps, 0.5);
            rr.wan_tx_pps_p95 = pct(&mut wan_tx_pps, 0.95);
            rep.router = Some(rr);
        }

        if !self.lan_samples.is_empty() {
            self.lan_samples.sort_by_key(|(t, _)| *t);
            let mut arp_all: Vec<f64> = Vec::with_capacity(self.lan_samples.len());
            let mut ping_all: Vec<f64> = Vec::with_capacity(self.lan_samples.len());
            let mut peak_arp: Vec<f64> = Vec::new();
            let mut offpeak_arp: Vec<f64> = Vec::new();
            let mut arp_max: Option<u32> = None;
            let mut unique_max: Option<u32> = None;
            for (ts, ls) in &self.lan_samples {
                let arp = f64::from(ls.arp_alive);
                arp_all.push(arp);
                ping_all.push(f64::from(ls.ping_alive));
                arp_max = Some(arp_max.map_or(ls.arp_alive, |m| m.max(ls.arp_alive)));
                unique_max = Some(unique_max.map_or(ls.unique_seen, |m| m.max(ls.unique_seen)));
                if (18..24).contains(&local_hour(*ts)) {
                    peak_arp.push(arp);
                } else {
                    offpeak_arp.push(arp);
                }
            }
            rep.lan = Some(LanReport {
                samples: self.lan_samples.len() as u64,
                arp_alive_med: med64(&mut arp_all),
                arp_alive_max: arp_max,
                ping_alive_med: med64(&mut ping_all),
                unique_seen_max: unique_max,
                peak_arp_alive_med: (peak_arp.len() >= 3).then(|| med64(&mut peak_arp)).flatten(),
                offpeak_arp_alive_med: (offpeak_arp.len() >= 3).then(|| med64(&mut offpeak_arp)).flatten(),
            });
        }

        let net_eps: Vec<Episode> = episodes
            .iter()
            .filter(|e| e.origin != IncidentOrigin::Observer && !is_load_provoked(e))
            .cloned()
            .collect();
        rep.patterns_msg = patterns(&net_eps, micro);
        rep.patterns = texts(&rep.patterns_msg);
        rep.episodes = episodes;
        rep.findings_msg = findings(&rep);
        rep.findings = texts(&rep.findings_msg);
        rep
    }
}

pub(super) fn open_context(o: &OpenEp) -> Vec<Msg> {
    let mut v = vec![];
    if o.scan > 0 {
        v.push(crate::msg!("c_own_scan", "monitor's own Wi-Fi scan was running (off-channel)"));
    }
    if o.speedtest > 0 {
        v.push(crate::msg!("c_own_speed", "monitor's own speed test was running"));
    }
    v
}

/// What [`observer_trust`] needs from a finished analysis.
#[derive(Debug, Default)]
pub(super) struct TrustInputs {
    pub power_save_ifaces: Vec<String>,
    /// Late ticks in percent of all ticks (worst interface).
    pub overrun_pct: f64,
    pub throttled_samples: u64,
    pub host_samples: u64,
    pub clock_unsynced: bool,
    /// Seconds of the host's own heavy traffic (worst interface).
    pub self_traffic_s: f64,
    pub observer_incidents: u32,
    pub max_cpu: Option<f64>,
}

/// Observer Trust Score: `polluted` when the host distorted much of the run, `caution` for
/// short host effects, `clean` otherwise. Every reason is a translatable message.
pub(super) fn observer_trust(i: &TrustInputs) -> ObserverTrust {
    let mut polluted = Vec::new();
    let mut caution = Vec::new();
    if !i.power_save_ifaces.is_empty() {
        polluted.push(crate::msg!("t_power_save", "Wi-Fi power-save was on ({ifs}) during the run: RTT and jitter are inflated.", ifs = i.power_save_ifaces.join(", ")));
    }
    let pct = format!("{:.1}", i.overrun_pct);
    if i.overrun_pct >= 1.0 {
        polluted.push(crate::msg!("t_overrun", "{pct}% of probe ticks were late (host CPU or disk stalls).", pct = pct));
    } else if i.overrun_pct >= 0.1 {
        caution.push(crate::msg!("t_overrun", "{pct}% of probe ticks were late (host CPU or disk stalls).", pct = pct));
    }
    if i.throttled_samples > 0 {
        let share = i.throttled_samples as f64 / i.host_samples.max(1) as f64;
        let m = crate::msg!("t_throttled", "Undervoltage or thermal throttling in {n} host sample(s).", n = i.throttled_samples);
        if share >= 0.1 { polluted.push(m) } else { caution.push(m) }
    }
    if i.clock_unsynced {
        caution.push(crate::msg!("t_ntp", "The clock was not NTP-synchronized for part of the run: compare times with other devices with care."));
    }
    if i.self_traffic_s >= 60.0 {
        caution.push(crate::msg!("t_self_traffic", "The host's own traffic was heavy for {min} min; stalls in that time are excluded.", min = format!("{:.0}", i.self_traffic_s / 60.0)));
    }
    if i.observer_incidents > 0 {
        caution.push(crate::msg!("t_observer_incidents", "{n} incident(s) were caused by the measuring device and are excluded.", n = i.observer_incidents));
    }
    if let Some(c) = i.max_cpu.filter(|c| *c >= 85.0) {
        caution.push(crate::msg!("t_cpu", "Host CPU peaked at {v}%.", v = format!("{c:.0}")));
    }
    let level = if !polluted.is_empty() {
        TrustLevel::Polluted
    } else if !caution.is_empty() {
        TrustLevel::Caution
    } else {
        TrustLevel::Clean
    };
    polluted.extend(caution);
    ObserverTrust { level, reasons: polluted }
}
