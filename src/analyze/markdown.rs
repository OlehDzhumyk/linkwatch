//! Markdown rendering of a report.

use super::*;

/// Markdown rendering for people and for handing to an assistant.
pub fn to_markdown(r: &Report) -> String {
    use std::fmt::Write;
    let mut s = String::new();
    let lt = |t: DateTime<Utc>| t.with_timezone(&Local).format("%Y-%m-%d %H:%M:%S").to_string();
    let _ = writeln!(s, "# linkwatch report\n");
    if let (Some(a), Some(b)) = (r.from, r.to) {
        let _ = writeln!(s, "Period: {} – {} ({:.1} h, local time)\n", lt(a), lt(b), r.hours);
    }
    let _ = writeln!(s, "## Findings\n");
    for x in &r.findings {
        let _ = writeln!(s, "- {x}");
    }
    if !r.patterns.is_empty() {
        let _ = writeln!(s, "\n## Patterns\n");
        for x in &r.patterns {
            let _ = writeln!(s, "- {x}");
        }
    }
    if r.ifaces.iter().any(|i| !i.bands.is_empty()) {
        let _ = writeln!(s, "\n## Per-band Wi-Fi breakdown\n");
        let _ = writeln!(s, "| iface | band | avail % | outages | micro | router RTT | internet RTT | signal | channels |\n|---|---|---|---|---|---|---|---|---|");
        for i in &r.ifaces {
            for b in &i.bands {
                let chs = if b.channels.is_empty() { "-".into() } else { b.channels.iter().map(|c| c.to_string()).collect::<Vec<_>>().join(",") };
                let _ = writeln!(
                    s,
                    "| {} | {} | {:.3}% | {} | {} | {} | {} | {} | {} |",
                    i.iface,
                    b.band,
                    b.availability_pct,
                    b.episodes,
                    b.micro_drops,
                    b.gw_rtt_med.map_or("-".into(), |v| format!("{v:.1} ms")),
                    b.net_rtt_med.map_or("-".into(), |v| format!("{v:.1} ms")),
                    b.signal_med.map_or("-".into(), |v| format!("{v:.0} dBm")),
                    chs,
                );
            }
        }
    }
    let _ = writeln!(s, "\n## Outages (longer than micro-drops)\n");
    let _ = writeln!(s, "| start | iface | duration | state | cause | origin | attribution | context |\n|---|---|---|---|---|---|---|---|");
    for e in r.episodes.iter().filter(|e| e.duration_s > r.micro_max_s).take(200) {
        let _ = writeln!(
            s,
            "| {} | {} | {:.0}s | {:?} | {:?} | {:?} | {} | {} |",
            lt(e.start),
            e.iface,
            e.duration_s,
            e.state,
            e.cause.unwrap_or(Verdict::Unknown),
            e.origin,
            attribution_cell(&e.finding),
            cell(&e.context.join("; "))
        );
    }
    let trust = &r.observer_trust;
    if !r.observer_findings.is_empty() || trust.level != TrustLevel::Clean {
        let _ = writeln!(s, "\n## Observer health\n");
        let level = match trust.level {
            TrustLevel::Clean => "clean",
            TrustLevel::Caution => "caution",
            TrustLevel::Polluted => "polluted",
        };
        let _ = writeln!(s, "Observer trust: **{level}**\n");
        for x in &trust.reasons {
            let _ = writeln!(s, "- {}", x.text);
        }
        if !trust.reasons.is_empty() && !r.observer_findings.is_empty() {
            let _ = writeln!(s);
        }
        for x in &r.observer_findings {
            let _ = writeln!(s, "- {x}");
        }
    }
    if !r.security_events.is_empty() {
        let _ = writeln!(s, "\n## Security events\n");
        for x in r.security_events.iter().take(200) {
            let _ = writeln!(s, "- {x}");
        }
        if r.security_events.len() > 200 {
            let _ = writeln!(s, "- … ({} additional security events omitted)", r.security_events.len() - 200);
        }
    }
    for i in &r.ifaces {
        let _ = writeln!(s, "\n## Hourly profile: {}\n", i.iface);
        let _ = writeln!(s, "| hour | loss % | router RTT med/p95 | internet RTT med/p95 | outages | micro |\n|---|---|---|---|---|---|");
        for h in &i.hours {
            let f = |v: Option<f64>| v.map_or("-".to_string(), |x| format!("{x:.1}"));
            let _ = writeln!(s, "| {:02} | {:.3} | {}/{} | {}/{} | {} | {} |", h.hour, h.loss_pct, f(h.gw_rtt_med), f(h.gw_rtt_p95), f(h.net_rtt_med), f(h.net_rtt_p95), h.episodes, h.micro_drops);
        }
    }
    if !r.anomalies.is_empty() {
        let _ = writeln!(s, "\n## Anomalous periods\n");
        for a in r.anomalies.iter().take(100) {
            let _ = writeln!(s, "- {} {} {}–{}: peak {:.1}, usual {:.1}", a.iface, a.metric, lt(a.start), a.end.with_timezone(&Local).format("%H:%M"), a.peak, a.baseline);
        }
    }
    if !r.router_log_matches.is_empty() {
        let _ = writeln!(s, "\n## Router log\n");
        for x in &r.router_log_matches {
            let _ = writeln!(s, "- {x}");
        }
    }
    if let Some(rr) = &r.router {
        let _ = writeln!(s, "\n## Router telemetry\n");
        let _ = writeln!(
            s,
            "- Model: {}, samples: {}, WAN resets: {}, non-connected polls: {}",
            rr.model.as_deref().unwrap_or("unknown"),
            rr.samples,
            rr.uptime_resets,
            rr.wan_down_samples
        );
        if let (Some(m), Some(p)) = (rr.wan_rx_mbps_med, rr.wan_rx_mbps_p95) {
            let _ = writeln!(s, "- WAN throughput: median {m:.1} Mbit/s, p95 {p:.1} Mbit/s");
        } else if let (Some(rxp), Some(txp)) = (rr.wan_rx_pps_p95, rr.wan_tx_pps_p95) {
            let _ = writeln!(s, "- WAN packet rate: p95 {rxp:.0} pkt/s down, {txp:.0} pkt/s up");
        }
    }
    if let Some(lr) = &r.lan {
        let _ = writeln!(s, "\n## LAN devices\n");
        let _ = writeln!(
            s,
            "- Sweeps: {}, active (ARP) median {}, max {}, ping-alive median {}, distinct seen {}",
            lr.samples,
            lr.arp_alive_med.map_or("-".into(), |v| format!("{v:.0}")),
            lr.arp_alive_max.map_or("-".into(), |v| v.to_string()),
            lr.ping_alive_med.map_or("-".into(), |v| format!("{v:.0}")),
            lr.unique_seen_max.map_or("-".into(), |v| v.to_string()),
        );
        if let (Some(peak), Some(off)) = (lr.peak_arp_alive_med, lr.offpeak_arp_alive_med) {
            let _ = writeln!(s, "- Evening (18–24) median {peak:.0} vs off-peak {off:.0}");
        }
    }
    if !r.monitor_gaps.is_empty() {
        let _ = writeln!(s, "\n## Monitor gaps (data missing)\n");
        for x in &r.monitor_gaps {
            let _ = writeln!(s, "- {x}");
        }
    }
    s
}

fn snake<T: serde::Serialize>(v: &T) -> String {
    serde_json::to_value(v).ok().and_then(|x| x.as_str().map(str::to_owned)).unwrap_or_default()
}

/// One table cell: `mixed (host 5 s)`, `observer_confirmed`, `network (high)`, plus the first network cause.
fn attribution_cell(f: &attribution::Finding) -> String {
    use attribution::Attribution as A;
    let mut out = snake(&f.attribution);
    match f.attribution {
        A::Mixed => out.push_str(&format!(" (host {:.0} s)", f.host_s)),
        A::Network | A::NetworkDespiteHost => out.push_str(&format!(" ({})", snake(&f.confidence))),
        A::ObserverLikely | A::ObserverConfirmed => {}
    }
    if let Some(c) = f.network_causes.first() {
        out.push_str(&format!("; {}", snake(c)));
    }
    out
}
