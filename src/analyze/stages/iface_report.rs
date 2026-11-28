//! Stage `iface_report`: totals per interface, per band and per hour, and anomalous minutes.
//!
//! Observer-origin episodes and their ticks are left out of availability and of the per-band and
//! per-hour rows: the host failed there, not the network.

use super::super::detect::robust_anomalies;
use super::super::engine::{IfAcc, local_hour, med64, pct};
use super::super::*;
use super::episodes::Tracked;

/// A percentile needs at least this many samples; fewer are no distribution.
/// Engineering estimate: with fewer than ten values the 95th percentile is the maximum.
const PERCENTILE_MIN_SAMPLES: usize = 10;
/// A stall on a Wi-Fi link counts as airtime congestion only when the local traffic stays below
/// this rate (bytes/s, 1 Mbit/s): the link was idle, so the delay came from other devices.
const AIRTIME_LOCAL_MAX_BPS: f64 = 125_000.0;
/// ... and the channel was busy at least this much (%) ...
const AIRTIME_BUSY_PCT: f64 = 55.0;
/// ... within this many seconds of the stall.
const AIRTIME_BUSY_WINDOW_S: i64 = 30;

/// Options of the stage.
pub(in crate::analyze) struct IfaceParams {
    pub tick_s: f64,
    /// Episodes up to this length are micro-drops.
    pub micro_max_s: f64,
    /// Robust z-score threshold for anomalous minutes.
    pub z: f64,
}

#[derive(Default)]
pub(in crate::analyze) struct IfaceSummary {
    pub ifaces: Vec<IfaceReport>,
    pub anomalies: Vec<Anomaly>,
}

/// Ticks that belong to observer-origin episodes of one interface.
#[derive(Default)]
struct ObserverShare {
    ticks: u64,
    band_ticks: BTreeMap<String, u64>,
    hour_ticks: [u64; 24],
}

/// One report per interface, in the order of `ifs`. Sorts the per-interface sample lists in place.
pub(in crate::analyze) fn build(ifs: &mut BTreeMap<String, IfAcc>, episodes: &[Tracked], p: &IfaceParams) -> IfaceSummary {
    let mut out = IfaceSummary::default();
    for (name, a) in ifs.iter_mut() {
        let share = observer_share(episodes, name);
        let eps: Vec<&Episode> = episodes
            .iter()
            .map(|(e, _)| e)
            .filter(|e| e.iface == *name && e.origin != IncidentOrigin::Observer)
            .collect();
        let r = iface_report(name, a, &eps, &share, p);
        out.anomalies.extend(anomalies(name, a, p.z));
        out.ifaces.push(r);
    }
    out
}

fn observer_share(episodes: &[Tracked], name: &str) -> ObserverShare {
    let mut share = ObserverShare::default();
    for (e, f) in episodes.iter().filter(|(e, _)| e.iface == name && e.origin == IncidentOrigin::Observer) {
        share.ticks += u64::from(e.ticks);
        for (b, c) in &f.bands {
            *share.band_ticks.entry(b.clone()).or_default() += u64::from(*c);
        }
        for (slot, cnt) in share.hour_ticks.iter_mut().zip(f.hour_ticks.iter()) {
            *slot += u64::from(*cnt);
        }
    }
    share
}

fn iface_report(name: &str, a: &mut IfAcc, eps: &[&Episode], share: &ObserverShare, p: &IfaceParams) -> IfaceReport {
    let micro = p.micro_max_s;
    let eff_ticks = a.ticks.saturating_sub(share.ticks);
    let eff_bad = a.bad_ticks.saturating_sub(share.ticks);
    let mut r = IfaceReport { iface: name.to_string(), role: a.role, ticks: eff_ticks, no_link_ticks: a.no_link_ticks, had_link: a.had_link, ..Default::default() };
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
    if a.peak_net.len() >= PERCENTILE_MIN_SAMPLES {
        r.peak_net_rtt_p95 = pct(&mut a.peak_net, 0.95);
    }
    if a.offpeak_net.len() >= PERCENTILE_MIN_SAMPLES {
        r.offpeak_net_rtt_p95 = pct(&mut a.offpeak_net, 0.95);
    }
    if a.role == Some(IfaceRole::Wifi) {
        r.wifi_airtime_congestion_stalls = airtime_congestion_stalls(a, p.tick_s);
    }
    r.speed_tests = a.speed.len() as u32;
    r.speed_med_mbps = med64(&mut a.speed.iter().map(|(_, m)| *m).collect::<Vec<_>>());
    r.speed_peak_med_mbps = med64(&mut a.speed.iter().filter(|(t, _)| (18..24).contains(&local_hour(*t))).map(|(_, m)| *m).collect::<Vec<_>>());
    r.roams = a.roams;
    r.self_traffic_s = a.self_traffic_ticks as f64 * p.tick_s;
    r.self_traffic_stalls = a.self_traffic_stalls;
    r.tx_failed_total = a.tx_failed_total;
    r.beacon_loss_total = a.beacon_loss_total;
    if a.wifi_counter_secs > 0.0 {
        r.retry_rate_per_min = Some(a.tx_retries_total as f64 / (a.wifi_counter_secs / 60.0));
    }
    r.bands = band_rows(a, eps, share, micro);
    r.hours = hour_rows(a, eps, share, micro);
    r
}

/// Stalls on an idle local link that happened while the channel was busy.
fn airtime_congestion_stalls(a: &IfAcc, tick_s: f64) -> u32 {
    a.stall_events
        .iter()
        .filter(|(st_ts, local_bytes)| {
            let local_bps = *local_bytes as f64 / tick_s.max(0.2);
            local_bps < AIRTIME_LOCAL_MAX_BPS
                && a.busy.iter().any(|(bt, busy)| (*bt - *st_ts).num_seconds().abs() <= AIRTIME_BUSY_WINDOW_S && *busy >= AIRTIME_BUSY_PCT)
        })
        .count() as u32
}

fn band_rows(a: &mut IfAcc, eps: &[&Episode], share: &ObserverShare, micro: f64) -> Vec<BandStats> {
    let mut rows = Vec::new();
    for (bname, ba) in a.bands.iter_mut() {
        let obs_bt = share.band_ticks.get(bname).copied().unwrap_or(0);
        let bt = ba.ticks.saturating_sub(obs_bt);
        if bt == 0 {
            continue;
        }
        let bbad = ba.bad_ticks.saturating_sub(obs_bt);
        let beps: Vec<&&Episode> = eps.iter().filter(|e| e.band.as_deref() == Some(bname.as_str())).collect();
        let bmicro = beps.iter().filter(|e| e.duration_s <= micro).count() as u32;
        let bep = beps.len() as u32 - bmicro;
        let sig_med = med64(&mut ba.signal.iter().map(|s| *s as f64).collect::<Vec<_>>());
        rows.push(BandStats {
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
    rows
}

fn hour_rows(a: &mut IfAcc, eps: &[&Episode], share: &ObserverShare, micro: f64) -> Vec<HourRow> {
    let mut rows = Vec::new();
    for (h, &obs_ht) in share.hour_ticks.iter().enumerate() {
        let ht = a.hour_ticks[h].saturating_sub(obs_ht);
        if ht == 0 {
            continue;
        }
        let hloss = a.hour_loss[h].saturating_sub(obs_ht);
        let hu = h as u32;
        rows.push(HourRow {
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
    rows
}

/// Anomalous minutes (robust z on per-minute medians).
fn anomalies(name: &str, a: &mut IfAcc, z: f64) -> Vec<Anomaly> {
    let gw_min: Vec<(DateTime<Utc>, f64)> = a.minutes.iter_mut().filter_map(|(t, m)| med64(&mut m.gw).map(|v| (*t, v))).collect();
    let net_min: Vec<(DateTime<Utc>, f64)> = a.minutes.iter_mut().filter_map(|(t, m)| med64(&mut m.net).map(|v| (*t, v))).collect();
    let sig: Vec<(DateTime<Utc>, f64)> = a.signal.iter().map(|(t, s)| (*t, -(*s as f64))).collect();
    let busy: Vec<(DateTime<Utc>, f64)> = a.busy.clone();
    let mut out = Vec::new();
    for (metric, series, sign) in [("router RTT ms", gw_min, 1.0), ("internet RTT ms", net_min, 1.0), ("signal dBm (weaker)", sig, -1.0), ("channel busy %", busy, 1.0)] {
        out.extend(robust_anomalies(name, metric, &series, z, sign));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::super::episodes::EpFlags;
    use super::super::fixtures::{episode, t0};
    use super::super::super::engine::BandAcc;
    use super::*;

    fn params() -> IfaceParams {
        IfaceParams { tick_s: 1.0, micro_max_s: 2.5, z: 4.0 }
    }

    fn at(s: i64) -> DateTime<Utc> {
        t0() + Duration::seconds(s)
    }

    fn net(mut e: Episode) -> Tracked {
        e.origin = IncidentOrigin::Network;
        (e, EpFlags::default())
    }

    fn obs(mut e: Episode) -> Tracked {
        e.origin = IncidentOrigin::Observer;
        (e, EpFlags::default())
    }

    fn one_iface(ticks: u64, bad: u64) -> BTreeMap<String, IfAcc> {
        BTreeMap::from([("eth0".to_string(), IfAcc { role: Some(IfaceRole::Ethernet), ticks, bad_ticks: bad, ..Default::default() })])
    }

    #[test]
    fn availability_counts_bad_ticks_of_network_episodes_only() {
        let mut ifs = one_iface(1000, 60);
        // 10 s of the bad ticks came from the host.
        let eps = [
            net(episode("eth0", IfaceRole::Ethernet, 100, 50, PathState::LanDown)),
            obs(episode("eth0", IfaceRole::Ethernet, 500, 10, PathState::LanDown)),
        ];
        let s = build(&mut ifs, &eps, &params());
        let r = &s.ifaces[0];
        assert_eq!(r.ticks, 990, "observer ticks leave the denominator");
        assert!((r.availability_pct - 100.0 * (1.0 - 50.0 / 990.0)).abs() < 1e-9);
        assert_eq!((r.episodes, r.micro_drops), (1, 0));
        assert!((r.down_s - 50.0).abs() < 1e-9 && (r.longest_s - 50.0).abs() < 1e-9);
    }

    #[test]
    fn short_episodes_are_micro_drops() {
        let mut ifs = one_iface(100, 3);
        let eps = [net(episode("eth0", IfaceRole::Ethernet, 10, 2, PathState::LanDown)), net(episode("eth0", IfaceRole::Ethernet, 50, 3, PathState::LanDown))];
        let r = &build(&mut ifs, &eps, &params()).ifaces[0];
        assert_eq!((r.episodes, r.micro_drops), (1, 1), "2 s is at most the micro limit, 3 s is over it");
    }

    #[test]
    fn an_interface_without_ticks_has_zero_availability_and_all_ticks_observer_means_full() {
        let mut ifs = one_iface(0, 0);
        assert_eq!(build(&mut ifs, &[], &params()).ifaces[0].availability_pct, 0.0);
        let mut ifs = one_iface(10, 10);
        let eps = [obs(episode("eth0", IfaceRole::Ethernet, 0, 10, PathState::LanDown))];
        let r = &build(&mut ifs, &eps, &params()).ifaces[0];
        assert_eq!((r.ticks, r.availability_pct), (0, 100.0));
    }

    #[test]
    fn rtt_medians_and_percentile_floor() {
        let mut ifs = one_iface(20, 0);
        let a = ifs.get_mut("eth0").expect("iface");
        a.gw_all = vec![1.0, 3.0, 2.0];
        a.peak_net = (0..9).map(|i| i as f32).collect();
        a.offpeak_net = (0..10).map(|i| i as f32).collect();
        let r = &build(&mut ifs, &[], &params()).ifaces[0];
        assert_eq!(r.gw_rtt_med, Some(2.0));
        assert_eq!(r.peak_net_rtt_p95, None, "nine samples are no percentile");
        assert_eq!(r.offpeak_net_rtt_p95, Some(9.0));
    }

    #[test]
    fn band_rows_skip_bands_that_only_the_observer_saw_and_split_episodes_by_band() {
        let mut ifs = BTreeMap::new();
        let mut a = IfAcc { role: Some(IfaceRole::Wifi), ticks: 100, bad_ticks: 10, ..Default::default() };
        a.bands.insert("5 GHz".into(), BandAcc::default());
        a.bands.get_mut("5 GHz").expect("band").ticks = 90;
        a.bands.get_mut("5 GHz").expect("band").bad_ticks = 10;
        a.bands.insert("2.4 GHz".into(), BandAcc::default());
        a.bands.get_mut("2.4 GHz").expect("band").ticks = 10;
        ifs.insert("wlo1".to_string(), a);
        let mut e5 = episode("wlo1", IfaceRole::Wifi, 10, 10, PathState::LanDown);
        e5.band = Some("5 GHz".into());
        let mut eo = episode("wlo1", IfaceRole::Wifi, 100, 10, PathState::LanDown);
        eo.band = Some("2.4 GHz".into());
        let mut observer = obs(eo);
        observer.1.bands.insert("2.4 GHz".into(), 10);
        let s = build(&mut ifs, &[net(e5), observer], &params());
        let bands = &s.ifaces[0].bands;
        assert_eq!(bands.len(), 1, "all 2.4 GHz ticks belong to the observer episode");
        assert_eq!((bands[0].band.as_str(), bands[0].ticks, bands[0].episodes), ("5 GHz", 90, 1));
    }

    #[test]
    fn airtime_congestion_needs_an_idle_link_and_a_busy_channel() {
        let mut a = IfAcc {
            busy: vec![(at(100), 60.0)],
            stall_events: vec![(at(110), 1_000), (at(110), 500_000), (at(300), 1_000)],
            ..Default::default()
        };
        assert_eq!(airtime_congestion_stalls(&a, 1.0), 1, "heavy local traffic and a far-away stall do not count");
        a.busy = vec![(at(100), 54.0)];
        assert_eq!(airtime_congestion_stalls(&a, 1.0), 0);
    }
}
