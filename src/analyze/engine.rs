//! Streaming analyzer: consumes envelopes (stage `ingest`) and runs the stages of
//! `Analyzer::finish` in order (docs/ARCHITECTURE.md §3.1, `stages/`).

use super::stages::*;
use super::*;
use episodes::{BadTick, OpenEp, Tracked};
use windows::EVENING_HOURS;

// ---------- streaming state ----------

#[derive(Default)]
pub(super) struct BandAcc {
    pub(super) ticks: u64,
    pub(super) bad_ticks: u64,
    pub(super) gw: Vec<f32>,
    pub(super) net: Vec<f32>,
    pub(super) signal: Vec<i32>,
    pub(super) channels: BTreeSet<u32>,
}

#[derive(Default)]
pub(super) struct MinuteAcc {
    pub(super) gw: Vec<f64>,
    pub(super) net: Vec<f64>,
}

#[derive(Clone, Copy)]
pub(super) struct PrevWifiCounters {
    pub(super) ts: DateTime<Utc>,
    pub(super) retries: Option<u32>,
    pub(super) failed: Option<u32>,
    pub(super) beacon_loss: Option<u32>,
}

/// `Degraded` ticks of one interface and the longest unbroken run of them.
#[derive(Default)]
pub(super) struct DegradedAcc {
    pub(super) ticks: u64,
    /// First and last tick of the open run.
    run: Option<(DateTime<Utc>, DateTime<Utc>)>,
    pub(super) longest_s: f64,
}

impl DegradedAcc {
    /// Feed one tick. A tick that is not degraded, or a gap longer than `gap_s`, ends the run.
    pub(super) fn feed(&mut self, ts: DateTime<Utc>, degraded: bool, gap_s: i64, tick: Duration) {
        if !degraded {
            self.run = None;
            return;
        }
        self.ticks += 1;
        let start = match self.run {
            Some((start, last)) if (ts - last).num_seconds() <= gap_s => start,
            _ => ts,
        };
        self.run = Some((start, ts));
        let len_s = ((ts - start) + tick).num_milliseconds() as f64 / 1000.0;
        self.longest_s = self.longest_s.max(len_s);
    }
}

#[derive(Default)]
pub(super) struct IfAcc {
    pub(super) role: Option<IfaceRole>,
    pub(super) ticks: u64,
    pub(super) bad_ticks: u64,
    pub(super) no_link_ticks: u64,
    /// Merged intervals without link or address.
    pub(super) no_link: Vec<(DateTime<Utc>, DateTime<Utc>)>,
    pub(super) degraded: DegradedAcc,
    pub(super) open: OpenEp,
    pub(super) gw_all: Vec<f32>,
    pub(super) net_all: Vec<f32>,
    pub(super) hour_ticks: [u64; 24],
    pub(super) hour_loss: [u64; 24],
    pub(super) hour_gw: [Vec<f32>; 24],
    pub(super) hour_net: [Vec<f32>; 24],
    pub(super) minutes: BTreeMap<DateTime<Utc>, MinuteAcc>,
    pub(super) signal: Vec<(DateTime<Utc>, i32)>,
    pub(super) busy: Vec<(DateTime<Utc>, f64)>,
    pub(super) rx_busy: Vec<(DateTime<Utc>, f64)>,
    pub(super) speed: Vec<(DateTime<Utc>, f64)>,
    pub(super) roams: u32,
    pub(super) reconnects: u32,
    pub(super) stalls: u32,
    pub(super) last_stall: Option<DateTime<Utc>>,
    pub(super) overrun_ticks: u64,
    pub(super) self_traffic_ticks: u64,
    /// Own heavy-traffic ticks in the evening hours (18-24 local).
    pub(super) evening_self_ticks: u64,
    pub(super) self_traffic_stalls: u32,
    pub(super) last_self_traffic: Option<DateTime<Utc>>,
    pub(super) stall_events: Vec<(DateTime<Utc>, u64)>,
    pub(super) loaded_gw: Vec<f32>,
    pub(super) loaded_net: Vec<f32>,
    pub(super) peak_net: Vec<f32>,
    pub(super) offpeak_net: Vec<f32>,
    pub(super) had_link: bool,
    pub(super) last_freq_mhz: Option<u32>,
    pub(super) wifi_freqs: Vec<(DateTime<Utc>, u32)>,
    pub(super) bands: BTreeMap<String, BandAcc>,
    pub(super) prev_wifi_counters: Option<PrevWifiCounters>,
    pub(super) tx_retries_total: u64,
    pub(super) tx_failed_total: u64,
    pub(super) beacon_loss_total: u64,
    pub(super) wifi_counter_secs: f64,
}

/// What the host (the measuring device) reported during the session.
#[derive(Default)]
pub(super) struct HostAcc {
    /// Host samples seen.
    pub(super) samples: u64,
    /// Time-sorted after `seal`.
    pub(super) throttled_at: Vec<DateTime<Utc>>,
    pub(super) power_save_ifaces: BTreeSet<String>,
    /// Readings of the power-save state, and how many of them said "on".
    pub(super) power_save_known: u64,
    pub(super) power_save_on: u64,
    pub(super) clock_unsynced: bool,
    pub(super) max_cpu: Option<f64>,
    pub(super) max_temp: Option<f64>,
}

pub struct Analyzer {
    opts: Opts,
    ifs: BTreeMap<String, IfAcc>,
    episodes: Vec<Tracked>,
    events: Vec<(DateTime<Utc>, EventKind)>,
    speedtests: Vec<(DateTime<Utc>, String)>,
    from: Option<DateTime<Utc>>,
    to: Option<DateTime<Utc>>,
    isp_seen: bool,
    host: HostAcc,
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
            host: HostAcc::default(),
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
                if let Some(ps) = w.power_save {
                    self.host.power_save_known += 1;
                    self.host.power_save_on += u64::from(ps);
                }
                if w.power_save == Some(true) {
                    self.host.power_save_ifaces.insert(w.iface.clone());
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
                self.host.samples += 1;
                if h.throttled {
                    self.host.throttled_at.push(e.ts);
                }
                if h.clock_synced == Some(false) {
                    self.host.clock_unsynced = true;
                }
                if let Some(c) = h.cpu_pct {
                    self.host.max_cpu = Some(self.host.max_cpu.map_or(c, |m| m.max(c)));
                }
                if let Some(t) = h.temp_c {
                    self.host.max_temp = Some(self.host.max_temp.map_or(t, |m| m.max(t)));
                }
                if !h.wifi_power_save.is_empty() {
                    self.host.power_save_known += 1;
                    self.host.power_save_on += u64::from(h.wifi_power_save.values().any(|&on| on));
                }
                for (iface, &on) in &h.wifi_power_save {
                    if on {
                        self.host.power_save_ifaces.insert(iface.clone());
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
            a.evening_self_ticks += u64::from(EVENING_HOURS.contains(&(local_hour(ts) as usize)));
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
        // Poor quality is a finding only when the network caused it, not our own load.
        let own_load = s.speedtest_active || s.scan_active || s.overrun || self_traffic;
        a.degraded.feed(ts, s.state == PathState::Degraded && !own_load, gap, tick);
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
        // Episode tracking: a long enough gap closes the open episode, a bad tick extends it.
        if a.open.is_stale(ts, gap)
            && let Some(ep) = a.open.close(&s.iface, a.role, tick, tick_s)
        {
            self.episodes.push(ep);
        }
        if bad {
            a.open.add_bad_tick(
                ts,
                BadTick {
                    state: s.state,
                    hour: h,
                    band,
                    overrun: s.overrun,
                    scan: s.scan_active,
                    speedtest: s.speedtest_active,
                    self_traffic,
                },
            );
        }
    }


    /// Time-order the lists that the stages search by binary search. Stable sorts, so equal
    /// timestamps keep their arrival order.
    fn seal(&mut self) {
        self.events.sort_by_key(|(t, _)| *t);
        self.host.throttled_at.sort();
        self.router_samples.sort_by_key(|(t, _)| *t);
        self.lan_samples.sort_by_key(|(t, _)| *t);
        for a in self.ifs.values_mut() {
            a.signal.sort_by_key(|(t, _)| *t);
            a.busy.sort_by_key(|(t, _)| *t);
        }
    }

    /// Run the stages in order and build the report.
    pub fn finish(mut self, router: &[RouterLine]) -> Report {
        self.seal();
        let (tick_s, micro_max_s) = (self.opts.tick_s, self.opts.micro_max_s);
        let tick = Duration::milliseconds((tick_s * 1000.0) as i64);
        let overrun_pct = observer::overrun_pct(&self.ifs);

        // 1. episodes
        let mut episodes = episodes::finalize(std::mem::take(&mut self.episodes), &mut self.ifs, tick, tick_s);

        // 2. cross_path: the episode cause
        let paths = cross_path::analyze(&episodes, &self.ifs, self.isp_seen, tick_s);
        for ((ep, _), path) in episodes.iter_mut().zip(&paths) {
            ep.cause = Some(path.cause);
        }

        // 3. facts + attribution: finding and origin
        let router_events = telemetry::router_events(&self.router_samples);
        facts::attribute_all(
            &mut episodes,
            &paths,
            &facts::FactsInput { events: &self.events, host: &self.host, router_events: &router_events, router_log: router, ifs: &self.ifs, tick_s },
        );

        // 4. context: notes, router log matches, monitor gaps, security events
        context::annotate(
            &mut episodes,
            &context::ContextInput {
                events: &self.events,
                ifs: &self.ifs,
                speedtests: &self.speedtests,
                router_log: router,
                lan_samples: &self.lan_samples,
                context_s: self.opts.context_s,
            },
        );
        let notices = context::notices(&episodes, &self.events, router);

        // 5. per-interface totals (observer incidents excluded)
        let ifaces = iface_report::build(&mut self.ifs, &episodes, &iface_report::IfaceParams { tick_s, micro_max_s, z: self.opts.z });
        let mut episodes: Vec<Episode> = episodes.into_iter().map(|(e, _)| e).collect();

        // 6. incidents: merge, observer/load split
        let counts = incidents::merge(&episodes);

        // 7. telemetry reports, 8. observer trust
        let router_report = telemetry::router_report(&self.router_samples);
        let lan_report = telemetry::lan_report(&self.lan_samples);
        let observer = observer::assess(&observer::ObserverInput {
            host: &self.host,
            ifaces: &ifaces.ifaces,
            observer_incidents: counts.observer,
            overrun_pct,
            self_traffic_bps: self.opts.self_traffic_bps,
            self_traffic_pps: self.opts.self_traffic_pps,
        });

        // 9. masking: session blinds and the confidence cap
        let blinds = masking::session_blinds(&masking::BlindInput {
            host: &self.host,
            events: &self.events,
            ifs: &self.ifs,
            speedtests: &self.speedtests,
            tick_s,
            session_hours: summary::session_hours(self.from, self.to),
            trust: observer.trust.level,
        });
        masking::cap_polluted(&mut episodes, observer.trust.level);

        // 10. summary
        summary::assemble(summary::Parts {
            from: self.from,
            to: self.to,
            tick_s,
            micro_max_s,
            episodes,
            ifaces,
            counts,
            notices,
            observer,
            blinds,
            router: router_report,
            lan: lan_report,
        })
    }
}
