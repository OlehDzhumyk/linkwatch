//! Minute buckets for the live view and pure scheduling helpers.

use crate::config::{parse_hhmm, Speed};
use crate::live::{MinuteBucket, MINUTES_KEPT};
use crate::model::{PathState, Sample};
use chrono::{DateTime, Duration, Local, NaiveTime, TimeZone, Timelike, Utc};
use std::collections::VecDeque;

/// Severity order for "worst state in this minute" (shared by live and disk buckets).
pub(crate) fn severity(s: PathState) -> u8 {
    match s {
        PathState::Unknown => 0,
        PathState::Ok => 1,
        PathState::Degraded => 2,
        PathState::DnsDown => 3,
        PathState::WanDown => 4,
        PathState::IspDown => 5,
        PathState::NoIp => 6,
        PathState::LanDown => 7,
        PathState::LinkDown => 8,
    }
}

fn minute_start(t: DateTime<Utc>) -> DateTime<Utc> {
    t.with_second(0).and_then(|t| t.with_nanosecond(0)).unwrap_or(t)
}

/// Running averages need sums; kept beside the public bucket.
#[derive(Debug, Default, Clone)]
pub struct BucketAcc {
    gw_sum: f64,
    gw_n: u32,
    net_sum: f64,
    net_n: u32,
}

/// Add a sample to the bucket list (creating a new minute when needed).
/// `state` is the instantaneous state of this tick.
pub fn add_sample(buckets: &mut VecDeque<MinuteBucket>, acc: &mut BucketAcc, s: &Sample, state: PathState, at: DateTime<Utc>) {
    let m = minute_start(at);
    let need_new = buckets.back().is_none_or(|b| b.t != m);
    if need_new {
        // A clock step backwards must not create out-of-order buckets: keep appending to the last one.
        if let Some(b) = buckets.back()
            && m < b.t {
                return add_to(buckets.back_mut(), acc, s, state);
            }
        buckets.push_back(MinuteBucket { t: m, ..Default::default() });
        *acc = BucketAcc::default();
        while buckets.len() > MINUTES_KEPT {
            buckets.pop_front();
        }
    }
    add_to(buckets.back_mut(), acc, s, state);
}

fn add_to(b: Option<&mut MinuteBucket>, acc: &mut BucketAcc, s: &Sample, state: PathState) {
    let Some(b) = b else { return };
    b.ticks += 1;
    // Same counting as the disk history (web::api::minutes_from_disk): a probe that was
    // not sent (no link) is not a router failure.
    if s.gw.as_ref().is_some_and(|g| !g.ok) {
        b.gw_fail += 1;
    }
    if s.isp.as_ref().is_some_and(|i| !i.ok) {
        b.isp_fail += 1;
    }
    if s.net.of > 0 && s.net.ok == 0 {
        b.net_fail += 1;
    }
    if let Some(r) = s.gw.as_ref().and_then(|g| g.rtt_ms) {
        acc.gw_sum += r;
        acc.gw_n += 1;
        b.gw_rtt_avg = Some(acc.gw_sum / acc.gw_n as f64);
        b.gw_rtt_max = Some(b.gw_rtt_max.map_or(r, |m| m.max(r)));
    }
    if let Some(r) = s.net.rtt_ms {
        acc.net_sum += r;
        acc.net_n += 1;
        b.net_rtt_avg = Some(acc.net_sum / acc.net_n as f64);
        b.net_rtt_max = Some(b.net_rtt_max.map_or(r, |m| m.max(r)));
    }
    if b.worst.is_none_or(|w| severity(state) > severity(w)) {
        b.worst = Some(state);
    }
    b.rx_bytes = b.rx_bytes.saturating_add(s.rx_delta);
    b.tx_bytes = b.tx_bytes.saturating_add(s.tx_delta);
}

/// Interval in minutes that applies at local time `now`.
pub fn speed_interval_min(cfg: &Speed, now: DateTime<Local>) -> u64 {
    let (Ok((sh, sm)), Ok((eh, em))) = (parse_hhmm(&cfg.peak_start), parse_hhmm(&cfg.peak_end)) else {
        return cfg.interval_min.max(1);
    };
    let t = now.time();
    let (Some(start), Some(end)) = (NaiveTime::from_hms_opt(sh, sm, 0), NaiveTime::from_hms_opt(eh, em, 0)) else {
        return cfg.interval_min.max(1);
    };
    let in_peak = if start == end {
        false
    } else if start < end {
        t >= start && t < end
    } else {
        // Window wraps midnight, e.g. 18:00 -> 00:00.
        t >= start || t < end
    };
    if in_peak { cfg.peak_interval_min.max(1) } else { cfg.interval_min.max(1) }
}

/// Next speed test time after a test finished at `last` (or the first one after start).
pub fn next_speed_test(cfg: &Speed, last: Option<DateTime<Utc>>, started: DateTime<Utc>) -> DateTime<Utc> {
    match last {
        None => started + Duration::seconds(cfg.first_after_s as i64),
        Some(l) => {
            let local = Local.from_utc_datetime(&l.naive_utc());
            l + Duration::minutes(speed_interval_min(cfg, local) as i64)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{IfaceRole, LinkState, MultiResult, ProbeResult};

    fn s(gw: Option<f64>) -> Sample {
        Sample {
            iface: "x".into(),
            role: IfaceRole::Ethernet,
            link: LinkState::default(),
            gw: Some(gw.map(ProbeResult::ok).unwrap_or_else(|| ProbeResult::fail("timeout"))),
            isp: None,
            net: MultiResult { ok: 3, of: 3, rtt_ms: Some(10.0) },
            tcp: None,
            dns: None,
            rx_delta: 100,
            tx_delta: 10,
            state: PathState::Ok,
            speedtest_active: false,
            overrun: false,
            scan_active: false,
            t: None,
            freq_mhz: None,
            pkt_delta: None,
        }
    }

    #[test]
    fn buckets_roll_by_minute_and_track_worst() {
        let t = DateTime::from_timestamp(1_800_000_000, 0).unwrap(); // :00 seconds? normalise below
        let base = minute_start(t);
        let mut b = VecDeque::new();
        let mut acc = BucketAcc::default();
        add_sample(&mut b, &mut acc, &s(Some(2.0)), PathState::Ok, base);
        add_sample(&mut b, &mut acc, &s(Some(4.0)), PathState::Ok, base + Duration::seconds(10));
        add_sample(&mut b, &mut acc, &s(None), PathState::LanDown, base + Duration::seconds(20));
        assert_eq!(b.len(), 1);
        assert_eq!(b[0].ticks, 3);
        assert_eq!(b[0].gw_fail, 1);
        assert_eq!(b[0].gw_rtt_avg, Some(3.0));
        assert_eq!(b[0].gw_rtt_max, Some(4.0));
        assert_eq!(b[0].worst, Some(PathState::LanDown));
        assert_eq!(b[0].rx_bytes, 300);
        add_sample(&mut b, &mut acc, &s(Some(8.0)), PathState::Ok, base + Duration::seconds(61));
        assert_eq!(b.len(), 2);
        assert_eq!(b[1].gw_rtt_avg, Some(8.0));
        // Clock stepped back: goes into the last bucket, no new bucket.
        add_sample(&mut b, &mut acc, &s(Some(8.0)), PathState::Ok, base - Duration::seconds(300));
        assert_eq!(b.len(), 2);
        assert_eq!(b[1].ticks, 2);
    }

    #[test]
    fn peak_window_wraps_midnight() {
        let cfg = Speed::default(); // 18:00-00:00 peak 30, else 60
        let at = |h, m| Local.with_ymd_and_hms(2026, 11, 26, h, m, 0).single().unwrap();
        assert_eq!(speed_interval_min(&cfg, at(12, 0)), 60);
        assert_eq!(speed_interval_min(&cfg, at(18, 0)), 30);
        assert_eq!(speed_interval_min(&cfg, at(23, 59)), 30);
        assert_eq!(speed_interval_min(&cfg, at(0, 0)), 60);
        let mut c2 = cfg.clone();
        c2.peak_start = "22:00".into();
        c2.peak_end = "02:00".into();
        assert_eq!(speed_interval_min(&c2, at(1, 0)), 30);
        assert_eq!(speed_interval_min(&c2, at(3, 0)), 60);
    }

    #[test]
    fn first_speed_test_delay() {
        let cfg = Speed::default();
        let t = DateTime::from_timestamp(1_800_000_000, 0).unwrap();
        assert_eq!(next_speed_test(&cfg, None, t), t + Duration::seconds(60));
        assert!(next_speed_test(&cfg, Some(t), t) > t);
    }
}
