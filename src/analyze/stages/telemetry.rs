//! Stage `telemetry`: what the router and the LAN scan reported.
//!
//! [`router_events`] turns router samples into the points in time that explain an episode (used
//! by the `facts` stage). [`router_report`] and [`lan_report`] summarize the same samples for the
//! `Report`. All inputs are sorted by time.

use super::super::engine::{local_hour, med64, pct};
use super::super::*;

/// A router uptime that goes back by more than this is a reboot (uptime is polled slowly, so a
/// small step back is a counter wobble).
/// Engineering estimate: the router poll interval is about 10 s.
const UPTIME_RESET_SLACK_S: u64 = 30;
/// A LAN peak or off-peak median needs at least this many samples.
/// Engineering estimate: fewer samples are one scan, not a pattern.
const LAN_MIN_SAMPLES_PER_PERIOD: usize = 3;

/// Points in time at which the router itself reported a problem.
#[derive(Debug, Default, PartialEq)]
pub(in crate::analyze) struct RouterEvents {
    /// Estimated boot times of router reboots (uptime went back).
    pub reboots: Vec<DateTime<Utc>>,
    /// Samples at which the router said its WAN was not up.
    pub wan_down: Vec<DateTime<Utc>>,
}

/// Reboots (uptime went back) and WAN-down samples of the router, as sorted timestamps.
pub(in crate::analyze) fn router_events(samples: &[(DateTime<Utc>, RouterSample)]) -> RouterEvents {
    let mut ev = RouterEvents::default();
    let mut prev: Option<u64> = None;
    for (t, r) in samples {
        if let Some(u) = r.uptime_s {
            if prev.is_some_and(|p| u + UPTIME_RESET_SLACK_S < p) {
                ev.reboots.push(*t - Duration::seconds(u as i64));
            }
            prev = Some(u);
        }
        if r.wan_down() {
            ev.wan_down.push(*t);
        }
    }
    ev.reboots.sort();
    ev
}

pub(in crate::analyze) fn router_report(samples: &[(DateTime<Utc>, RouterSample)]) -> Option<RouterReport> {
    if samples.is_empty() {
        return None;
    }
    let mut rr = RouterReport {
        samples: samples.len() as u64,
        model: samples.iter().rev().find_map(|(_, r)| r.model.clone()),
        link_down_mbps: samples.iter().rev().find_map(|(_, r)| r.link_down_mbps),
        bytes_saturated: samples.iter().any(|(_, r)| r.bytes_saturated),
        ..Default::default()
    };
    let mut prev_up: Option<u64> = None;
    let mut wan_rx_mbps = Vec::new();
    let mut wan_rx_pps = Vec::new();
    let mut wan_tx_pps = Vec::new();
    for (_, rs) in samples {
        if rs.wan_down() {
            rr.wan_down_samples += 1;
        }
        if let Some(u) = rs.uptime_s {
            if let Some(p) = prev_up
                && u + UPTIME_RESET_SLACK_S < p
            {
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
    Some(rr)
}

pub(in crate::analyze) fn lan_report(samples: &[(DateTime<Utc>, LanSample)]) -> Option<LanReport> {
    if samples.is_empty() {
        return None;
    }
    let mut arp_all: Vec<f64> = Vec::with_capacity(samples.len());
    let mut ping_all: Vec<f64> = Vec::with_capacity(samples.len());
    let mut peak_arp: Vec<f64> = Vec::new();
    let mut offpeak_arp: Vec<f64> = Vec::new();
    let mut arp_max: Option<u32> = None;
    let mut unique_max: Option<u32> = None;
    for (ts, ls) in samples {
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
    Some(LanReport {
        samples: samples.len() as u64,
        arp_alive_med: med64(&mut arp_all),
        arp_alive_max: arp_max,
        ping_alive_med: med64(&mut ping_all),
        unique_seen_max: unique_max,
        peak_arp_alive_med: (peak_arp.len() >= LAN_MIN_SAMPLES_PER_PERIOD).then(|| med64(&mut peak_arp)).flatten(),
        offpeak_arp_alive_med: (offpeak_arp.len() >= LAN_MIN_SAMPLES_PER_PERIOD).then(|| med64(&mut offpeak_arp)).flatten(),
    })
}

#[cfg(test)]
mod tests {
    use super::super::fixtures::t0;
    use super::*;

    fn at(s: i64) -> DateTime<Utc> {
        t0() + Duration::seconds(s)
    }

    fn rs(s: i64, uptime: Option<u64>, wan: Option<&str>) -> (DateTime<Utc>, RouterSample) {
        (at(s), RouterSample { uptime_s: uptime, wan_status: wan.map(Into::into), ..Default::default() })
    }

    #[test]
    fn uptime_going_back_is_a_reboot_at_its_estimated_boot_time() {
        let samples = [rs(0, Some(5000), None), rs(60, Some(5060), None), rs(120, Some(20), None), rs(180, Some(80), None)];
        let ev = router_events(&samples);
        assert_eq!(ev.reboots, vec![at(100)], "boot = sample time minus uptime");
        assert!(ev.wan_down.is_empty());
        assert_eq!(router_report(&samples).expect("report").uptime_resets, 1);
    }

    #[test]
    fn a_small_step_back_of_the_uptime_is_not_a_reboot() {
        let samples = [rs(0, Some(1000), None), rs(10, Some(980), None)];
        assert!(router_events(&samples).reboots.is_empty());
        assert_eq!(router_report(&samples).expect("report").uptime_resets, 0);
    }

    #[test]
    fn wan_down_samples_are_listed_and_counted() {
        let samples = [rs(0, None, Some("Connected")), rs(10, None, Some("Disconnected")), rs(20, None, Some("Connected")), rs(30, None, Some("Unconfigured"))];
        assert_eq!(router_events(&samples).wan_down, vec![at(10), at(30)]);
        assert_eq!(router_report(&samples).expect("report").wan_down_samples, 2);
    }

    #[test]
    fn router_report_takes_the_latest_model_and_medians() {
        let a = RouterSample { model: Some("A".into()), wan_rx_mbps: Some(10.0), link_down_mbps: Some(100.0), ..Default::default() };
        let b = RouterSample { wan_rx_mbps: Some(30.0), bytes_saturated: true, ..Default::default() };
        let rep = router_report(&[(at(0), a), (at(10), b)]).expect("report");
        assert_eq!(rep.samples, 2);
        assert_eq!(rep.model.as_deref(), Some("A"));
        assert_eq!(rep.link_down_mbps, Some(100.0));
        assert!(rep.bytes_saturated);
        assert_eq!(rep.wan_rx_mbps_med, Some(30.0), "median of two values picks the upper index (percentile rule)");
        assert!(router_report(&[]).is_none());
    }

    #[test]
    fn lan_report_summarizes_counts_and_needs_samples_for_a_period_median() {
        let ls = |arp, ping, uniq| LanSample { arp_alive: arp, ping_alive: ping, unique_seen: uniq, ..Default::default() };
        let samples = [(at(0), ls(4, 3, 10)), (at(60), ls(8, 5, 12))];
        let rep = lan_report(&samples).expect("report");
        assert_eq!(rep.samples, 2);
        assert_eq!(rep.arp_alive_med, Some(6.0));
        assert_eq!(rep.arp_alive_max, Some(8));
        assert_eq!(rep.ping_alive_med, Some(4.0));
        assert_eq!(rep.unique_seen_max, Some(12));
        assert_eq!((rep.peak_arp_alive_med, rep.offpeak_arp_alive_med), (None, None), "two samples are too few for a period median");
        assert!(lan_report(&[]).is_none());
    }
}
