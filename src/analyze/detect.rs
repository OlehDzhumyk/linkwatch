//! Detectors over finished data: robust anomalies, repeating patterns, plain findings.

use super::*;
use super::engine::*;
use super::limits;

/// Minutes whose value deviates more than `z` robust sigmas, merged into intervals.
pub(super) fn robust_anomalies(iface: &str, metric: &str, series: &[(DateTime<Utc>, f64)], z: f64, sign: f64) -> Vec<Anomaly> {
    if series.len() < 30 {
        return vec![];
    }
    let mut v: Vec<f64> = series.iter().map(|(_, x)| *x).collect();
    let Some(med) = med64(&mut v) else { return vec![] };
    let mut dev: Vec<f64> = series.iter().map(|(_, x)| (x - med).abs()).collect();
    let mad = med64(&mut dev).unwrap_or(0.0).max(1e-6) * 1.4826;
    let mut out: Vec<Anomaly> = vec![];
    for (t, x) in series {
        if (x - med) / mad <= z {
            continue;
        }
        // Ignore tiny absolute deviations (e.g. 1 ms on a 1 ms baseline).
        if (x - med).abs() < 5.0 {
            continue;
        }
        let shown = x * sign;
        match out.last_mut() {
            Some(a) if (*t - a.end).num_seconds() <= 180 => {
                a.end = *t + Duration::seconds(60);
                if shown * sign > a.peak * sign {
                    a.peak = shown;
                }
            }
            _ => out.push(Anomaly { iface: iface.into(), metric: metric.into(), start: *t, end: *t + Duration::seconds(60), peak: shown, baseline: med * sign }),
        }
    }
    out
}

pub(super) fn patterns(eps: &[Episode], micro: f64) -> Vec<Msg> {
    let mut out = vec![];
    let mut by_if: BTreeMap<&str, Vec<&Episode>> = BTreeMap::new();
    for e in eps {
        by_if.entry(e.iface.as_str()).or_default().push(e);
    }
    for (iface, es) in by_if {
        if es.len() >= 4 {
            let gaps: Vec<f64> = es.windows(2).map(|w| (w[1].start - w[0].start).num_seconds() as f64).collect();
            let mean = gaps.iter().sum::<f64>() / gaps.len() as f64;
            let sd = (gaps.iter().map(|g| (g - mean).powi(2)).sum::<f64>() / gaps.len() as f64).sqrt();
            if mean > 60.0 && sd / mean < 0.15 {
                out.push(crate::msg!("pt_timer", "{iface}: drops repeat about every {min} min (±{sd} s) — looks like a timer (DHCP lease, scan, power save)",
                    iface = iface, min = format!("{:.0}", mean / 60.0), sd = format!("{sd:.0}")));
            }
        }
        let mut hours = [0u32; 24];
        for e in es.iter().filter(|e| e.duration_s > micro) {
            hours[local_hour(e.start) as usize] += 1;
        }
        let total: u32 = hours.iter().sum();
        if total >= 4
            && let Some((h, c)) = hours.iter().enumerate().max_by_key(|(_, c)| **c)
                && *c as f64 / total as f64 >= 0.4 {
                    out.push(crate::msg!("pt_hour", "{iface}: {c} of {total} outages start between {h}:00 and {h}:59",
                        iface = iface, c = c, total = total, h = format!("{h:02}")));
                }
        let evening = es.iter().filter(|e| (18..24).contains(&local_hour(e.start))).count();
        if es.len() >= 5 && evening as f64 / es.len() as f64 > 0.6 {
            out.push(crate::msg!("pt_evening", "{iface}: {n} of {total} drops happen in the evening (18–24), when everyone is online",
                iface = iface, n = evening, total = es.len()));
        }
    }
    out
}

/// Whether the `Degraded` time of one interface is long enough to report: an unbroken run of at
/// least [`limits::DEGRADED_RUN_S`], or a share of at least [`limits::DEGRADED_SHARE_PCT`] of its
/// ticks that adds up to at least [`limits::DEGRADED_MIN_S`].
pub(super) fn degraded_is_finding(degraded_ticks: u64, ticks: u64, tick_s: f64, longest_s: f64) -> bool {
    if degraded_ticks == 0 || ticks == 0 {
        return false;
    }
    let share_pct = 100.0 * degraded_ticks as f64 / ticks as f64;
    let total_s = degraded_ticks as f64 * tick_s;
    longest_s >= limits::DEGRADED_RUN_S || (share_pct >= limits::DEGRADED_SHARE_PCT && total_s >= limits::DEGRADED_MIN_S)
}

pub(super) fn findings(r: &Report) -> Vec<Msg> {
    use crate::msg;
    let f1 = |v: Option<f64>| v.map_or("-".to_string(), |v| format!("{v:.1}"));
    let f0 = |v: Option<f64>| v.map_or("-".to_string(), |v| format!("{v:.0}"));
    let mut f = vec![];
    for i in r.ifaces.iter().filter(|i| i.ticks == 0) {
        if i.had_link {
            f.push(msg!("f_no_addr", "{iface}: had link but never an address with a gateway (no DHCP or no default route)", iface = i.iface));
        } else {
            f.push(msg!("f_never_link", "{iface}: never had link during this session (not connected)", iface = i.iface));
        }
    }
    if r.tick_s > 1.0 {
        f.push(msg!("f_resolution", "Time resolution: one probe every {s} s; drops shorter than that can be missed.", s = format!("{:.1}", r.tick_s)));
    }
    for i in r.ifaces.iter().filter(|i| i.ticks > 0) {
        let iface = i.iface.as_str();
        if i.no_link_ticks > 0 {
            f.push(msg!("f_no_link", "{iface}: no link or address for {n} ticks (unplugged, disconnected or no DHCP)", iface = iface, n = i.no_link_ticks));
        }
        let role = i.role.map(|r| format!("{r:?}")).unwrap_or_default().to_lowercase();
        if let Some(s) = i.signal_med {
            f.push(msg!("f_iface_sig",
                "{iface} ({role}): available {avail}%, {ep} outages, {micro} micro-drops, longest {longest}s, router RTT {gw} ms, internet RTT {net} ms, signal {sig} dBm",
                iface = iface, role = role, avail = format!("{:.3}", i.availability_pct), ep = i.episodes, micro = i.micro_drops,
                longest = format!("{:.0}", i.longest_s), gw = f1(i.gw_rtt_med), net = f1(i.net_rtt_med), sig = format!("{s:.0}")));
        } else {
            f.push(msg!("f_iface",
                "{iface} ({role}): available {avail}%, {ep} outages, {micro} micro-drops, longest {longest}s, router RTT {gw} ms, internet RTT {net} ms",
                iface = iface, role = role, avail = format!("{:.3}", i.availability_pct), ep = i.episodes, micro = i.micro_drops,
                longest = format!("{:.0}", i.longest_s), gw = f1(i.gw_rtt_med), net = f1(i.net_rtt_med)));
        }
        if let (Some(all), Some(peak)) = (i.speed_med_mbps, i.speed_peak_med_mbps)
            && peak < all * 0.6 {
                f.push(msg!("f_evening_speed", "{iface}: evening speed {peak} Mbit/s vs {all} overall — the line is congested in the evening",
                    iface = iface, peak = format!("{peak:.0}"), all = format!("{all:.0}")));
            }
        if let Some(b) = i.busy_med
            && b > 50.0 {
                f.push(msg!("f_busy", "{iface}: channel busy {b}% of the time (median) — strong co-channel interference", iface = iface, b = format!("{b:.0}")));
            }
        if i.stalls > 0 {
            f.push(msg!("f_stalls", "{iface}: {n} stalls (path answered, but very late: router > 200 ms or internet > 500 ms) — felt as freezes", iface = iface, n = i.stalls));
        }
        if degraded_is_finding(i.degraded_ticks, i.ticks, r.tick_s, i.degraded_longest_s) {
            let total_s = i.degraded_ticks as f64 * r.tick_s;
            f.push(msg!("f_degraded",
                "{iface}: degraded (loss or high latency, but not down) for {pct}% of the time ({total} min in total, longest run {run} min) — a quality problem, not an outage",
                iface = iface, pct = format!("{:.0}", 100.0 * i.degraded_ticks as f64 / i.ticks.max(1) as f64),
                total = format!("{:.0}", total_s / 60.0), run = format!("{:.0}", i.degraded_longest_s / 60.0)));
        }
        if i.reconnects > 0 {
            f.push(msg!("f_reconnects", "{iface}: re-associated to the same access point {n} times (short disconnects)", iface = iface, n = i.reconnects));
        }
        if let (Some(idle), Some(load)) = (i.net_rtt_med, i.loaded_net_rtt_med)
            && load > idle + 100.0 {
                f.push(msg!("f_bufferbloat", "{iface}: internet RTT {load} ms during speed tests vs {idle} ms idle — latency under load (bufferbloat)",
                    iface = iface, load = format!("{load:.0}"), idle = format!("{idle:.0}")));
            }
        let roam_eps = r
            .episodes
            .iter()
            .filter(|e| e.iface == i.iface && e.origin == IncidentOrigin::Network && e.context_msg.iter().any(|c| c.code == "c_roam"))
            .count();
        if roam_eps > 0 {
            f.push(msg!("f_roam_outages", "{iface}: {n} outage(s) happened while the client roamed between access points — check booster/AP handover", iface = iface, n = roam_eps));
        }
        if i.roams > 5 {
            f.push(msg!("f_roams", "{iface}: switched access point {n} times — a booster with the same name may be pulling the client", iface = iface, n = i.roams));
        }
        if let Some(rr) = i.retry_rate_per_min
            && rr > 60.0
        {
            f.push(msg!("f_retries", "{iface}: high Wi-Fi retries ({rate}/min) — co-channel interference or weak link", iface = iface, rate = format!("{rr:.0}")));
        }
        if i.tx_failed_total > 0 || i.beacon_loss_total > 0 {
            f.push(msg!("f_tx_failed", "{iface}: {tx} failed TX frames, {bl} beacon losses", iface = iface, tx = i.tx_failed_total, bl = i.beacon_loss_total));
        }
        if i.bands.len() >= 2 {
            let parts: Vec<String> = i.bands.iter().map(|b| format!("{} ({:.2}%, {})", b.band, b.availability_pct, b.episodes)).collect();
            f.push(msg!("f_bands", "{iface}: per-band Wi-Fi comparison (availability, outages): {list}", iface = iface, list = parts.join(" vs ")));
        }
        if i.wifi_airtime_congestion_stalls >= 3
            || (i.role == Some(IfaceRole::Wifi)
                && i.busy_med.is_some_and(|b| b > 50.0)
                && i.rx_busy_med.is_some_and(|rx| rx > 30.0))
        {
            f.push(msg!("f_airtime",
                "{iface}: Wi-Fi airtime saturation (median busy {busy}%, RX {rx}%, {n} stalls on idle local link) — other wireless devices are occupying the channel",
                iface = iface, busy = f0(i.busy_med), rx = f0(i.rx_busy_med), n = i.wifi_airtime_congestion_stalls));
        }
        if let (Some(peak), Some(off)) = (i.peak_net_rtt_p95, i.offpeak_net_rtt_p95)
            && peak >= off * 2.0
            && peak >= off + 25.0
            && i.gw_rtt_med.is_some_and(|g| g < 20.0)
        {
            f.push(msg!("f_evening_rtt",
                "{iface}: evening internet RTT p95 spikes to {peak} ms vs {off} ms off-peak while router RTT stays low ({gw} ms) — shared-line/ISP congestion rather than a local router fault",
                iface = iface, peak = format!("{peak:.0}"), off = format!("{off:.0}"), gw = format!("{:.1}", i.gw_rtt_med.unwrap_or(0.0))));
        }
    }
    if let Some(rr) = &r.router {
        if rr.uptime_resets > 0 || rr.wan_down_samples > 0 {
            f.push(msg!("f_router_resets", "Router telemetry: {resets} WAN uptime reset(s), {down} non-connected WAN sample(s) (out of {n} polls).",
                resets = rr.uptime_resets, down = rr.wan_down_samples, n = rr.samples));
        }
        if let Some(p95) = rr.wan_rx_mbps_p95 {
            f.push(msg!("f_wan_tput", "Router WAN throughput (whole network): median {med} Mbit/s, p95 {p95} Mbit/s, link {cap} Mbit/s.",
                med = format!("{:.1}", rr.wan_rx_mbps_med.unwrap_or(0.0)), p95 = format!("{p95:.1}"), cap = f0(rr.link_down_mbps)));
        } else if rr.bytes_saturated && let (Some(rxp), Some(txp)) = (rr.wan_rx_pps_p95, rr.wan_tx_pps_p95) {
            f.push(msg!("f_wan_pps", "Router WAN packet rate (byte counter clamped at 32-bit MAX): p95 {rx} pkt/s down, {tx} pkt/s up.",
                rx = format!("{rxp:.0}"), tx = format!("{txp:.0}")));
        }
    }
    if let Some(lr) = &r.lan {
        if let Some(med) = lr.arp_alive_med {
            f.push(msg!("f_lan", "Active LAN devices: median {med}, peak {peak}, distinct seen {seen} (across {n} sweep(s)).",
                med = format!("{med:.0}"), peak = lr.arp_alive_max.unwrap_or(0), seen = lr.unique_seen_max.unwrap_or(0), n = lr.samples));
        }
        if let (Some(peak), Some(off)) = (lr.peak_arp_alive_med, lr.offpeak_arp_alive_med)
            && peak >= off * 1.5
            && peak >= off + 3.0
        {
            f.push(msg!("f_lan_evening", "Evening client count increases (median {peak} active LAN devices vs {off} off-peak) — more local devices share the router/channel.",
                peak = format!("{peak:.0}"), off = format!("{off:.0}")));
        }
    }
    for o in &r.observer_findings_msg {
        let mut m = o.clone();
        m.text = format!("Observer: {}", o.text);
        f.push(m);
    }
    if !r.security_events.is_empty() {
        f.push(msg!("f_security", "Security: {n} event(s) detected (see Security events section).", n = r.security_events.len()));
    }
    let total: u32 = r.incidents.values().sum();
    if total > 0 {
        let g = |k: &str| r.incidents.get(k).copied().unwrap_or(0);
        f.push(msg!("f_incidents",
            "Of {total} network incidents (outages and micro-drops, merged across interfaces): {wifi} only on Wi-Fi (cable fine), {wired} only on cable, {router} router, {line} line/ISP, {inet} internet beyond the ISP, {dns} DNS, {mixed} paths failing at different points, {single} not comparable (one path only), {unclear} unclear.",
            total = total, wifi = g("wifi_problem"), wired = g("wired_problem"), router = g("router_problem"), line = g("line_problem"),
            inet = g("internet_problem"), dns = g("dns"), mixed = g("mixed"), single = g("single_path"), unclear = g("unknown") + g("all_ok")));
    }
    if r.load_incidents > 0 {
        f.push(msg!(
            "f_load_incidents",
            "{n} short incident(s) occurred during the monitor's own speed test and are excluded from unprovoked network outages.",
            n = r.load_incidents
        ));
    }
    f
}
