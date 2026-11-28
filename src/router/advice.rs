//! Pure rule-based configuration and security advisor: turns live Wi-Fi, scan, host,
//! and router diagnostics into concrete, actionable recommendations.

use super::RouterAudit;
use crate::live::LiveSnapshot;
use crate::model::Verdict;
use crate::wifi::freq_to_channel;
use chrono::{DateTime, Utc};
use serde::Serialize;
use std::collections::BTreeMap;

fn args(pairs: &[(&str, String)]) -> BTreeMap<String, String> {
    pairs.iter().map(|(k, v)| ((*k).to_string(), v.clone())).collect()
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[cfg_attr(test, derive(ts_rs::TS), ts(export))]
pub struct AdviceItem {
    pub id: String,
    /// Stable message code for translation (`advice.<code>.title|evidence|rec` in the UI);
    /// `title`, `evidence` and `recommendation` are the English fallback.
    pub code: String,
    /// Values for the message placeholders, e.g. `{"iface": "wlan0", "dbm": "-79"}`.
    pub args: BTreeMap<String, String>,
    /// "critical" | "warn" | "info" | "ok"
    pub severity: String,
    /// "network" | "wifi" | "security" | "router" | "observer"
    pub category: String,
    pub title: String,
    pub evidence: String,
    pub recommendation: String,
}

#[derive(Debug, Clone, Serialize)]
#[cfg_attr(test, derive(ts_rs::TS), ts(export))]
pub struct AdviceResponse {
    pub generated_at: DateTime<Utc>,
    pub items: Vec<AdviceItem>,
}

fn cleanest_channel(snap: &LiveSnapshot, iface: &str, band_5: bool, current_ch: Option<u32>) -> Option<(u32, usize)> {
    let report = snap.last_scan.get(iface)?;
    let candidates: &[u32] = if band_5 {
        &[36, 40, 44, 48, 149, 153, 157, 161]
    } else {
        &[1, 6, 11]
    };
    let mut best: Option<(u32, i32, usize)> = None;
    for &cand in candidates {
        let mut weight = 0i32;
        let mut count = 0usize;
        for b in &report.bss {
            if b.associated {
                continue;
            }
            let Some(bch) = b.channel.or_else(|| freq_to_channel(b.freq_mhz)) else { continue };
            let overlap = if band_5 {
                bch == cand
            } else {
                cand.abs_diff(bch) <= 4
            };
            if overlap {
                count += 1;
                let sig = b.signal_dbm.unwrap_or(-90.0).clamp(-95.0, -25.0);
                weight += (100.0 + sig) as i32;
            }
        }
        let better = match best {
            None => true,
            Some((b_ch, b_w, _)) => weight < b_w || (weight == b_w && Some(cand) == current_ch && b_ch != cand),
        };
        if better {
            best = Some((cand, weight, count));
        }
    }
    best.map(|(c, _, n)| (c, n))
}

pub fn evaluate(snap: &LiveSnapshot, audit: Option<&RouterAudit>) -> AdviceResponse {
    let mut items: Vec<AdviceItem> = Vec::new();

    for (name, st) in &snap.ifaces {
        if let Some(w) = &st.wifi
            && w.connected
        {
            let sig = w.signal_avg_dbm.or(w.signal_dbm);
            let ch = w.channel.or_else(|| w.freq_mhz.and_then(freq_to_channel));
            let is_24 = w.freq_mhz.is_some_and(|f| (2400..=2500).contains(&f));
            let is_5 = w.freq_mhz.is_some_and(|f| (4900..=5924).contains(&f));

            if let Some(s) = sig
                && s < -75
            {
                items.push(AdviceItem {
                    id: format!("wifi_weak_{name}"),
                    code: "wifi_weak".into(),
                    args: args(&[("iface", name.to_string()), ("dbm", s.to_string())]),
                    severity: "warn".into(),
                    category: "wifi".into(),
                    title: format!("{name}: weak Wi-Fi signal ({s} dBm)"),
                    evidence: format!("Average RSSI is {s} dBm (below −75 dBm usable threshold)"),
                    recommendation: "Move closer, use a wired AP/mesh node if drops isolate to Wi-Fi, or move the router clear of concrete walls and bathrooms.".into(),
                });
            }

            if w.power_save == Some(true) {
                items.push(AdviceItem {
                    id: format!("wifi_ps_{name}"),
                    code: "wifi_ps".into(),
                    args: args(&[("iface", name.to_string())]),
                    severity: "warn".into(),
                    category: "wifi".into(),
                    title: format!("{name}: Wi-Fi power save is ON"),
                    evidence: "power_save enabled in nl80211 interface state".into(),
                    recommendation: format!("Disable Wi-Fi power saving (`iw dev {name} set power_save off`) to prevent periodic 10–100 ms jitter spikes."),
                });
            }

            if is_24 {
                if let Some(c) = ch
                    && !matches!(c, 1 | 6 | 11)
                {
                    let alt = cleanest_channel(snap, name, false, Some(c))
                        .map_or("1, 6, or 11".to_string(), |(best, n)| format!("channel {best} ({n} overlapping APs)"));
                    items.push(AdviceItem {
                        id: format!("wifi_24_overlap_{name}"),
                        code: "wifi_24_overlap".into(),
                        args: args(&[("iface", name.to_string()), ("ch", c.to_string()), ("alt", alt.to_string())]),
                        severity: "warn".into(),
                        category: "wifi".into(),
                        title: format!("{name}: 2.4 GHz uses overlapping channel {c}"),
                        evidence: "Channels other than 1, 6, and 11 overlap both neighbouring channels".into(),
                        recommendation: format!("Switch 2.4 GHz radio to {alt} with 20 MHz width."),
                    });
                }
                if w.width_mhz == Some(40) {
                    items.push(AdviceItem {
                        id: format!("wifi_24_40mhz_{name}"),
                        code: "wifi_24_40mhz".into(),
                        args: args(&[("iface", name.to_string())]),
                        severity: "warn".into(),
                        category: "wifi".into(),
                        title: format!("{name}: 40 MHz channel width on 2.4 GHz"),
                        evidence: "40 MHz consumes two thirds of the 2.4 GHz band and increases collisions".into(),
                        recommendation: "Set 2.4 GHz channel width to 20 MHz in router wireless settings.".into(),
                    });
                }
            }

            if let Some(cl) = &st.channel_load
                && cl.busy_pct > 60.0
                && let Some(c) = ch
                && (is_24 || is_5)
                && let Some((best, cnt)) = cleanest_channel(snap, name, is_5, Some(c))
                && best != c
            {
                items.push(AdviceItem {
                    id: format!("wifi_congestion_{name}"),
                    code: "wifi_congestion".into(),
                    args: args(&[("iface", name.to_string()), ("ch", c.to_string()), ("busy", format!("{:.0}", cl.busy_pct)), ("best", best.to_string()), ("n", cnt.to_string())]),
                    severity: "warn".into(),
                    category: "wifi".into(),
                    title: format!("{name}: channel {c} is congested ({:.0}% busy)", cl.busy_pct),
                    evidence: format!("Airtime busy {:.1}% on ch {c}", cl.busy_pct),
                    recommendation: format!("Try switching to channel {best} ({cnt} nearby APs seen in scan)."),
                });
            }

            if let Some(scan) = snap.last_scan.get(name)
                && let Some(assoc) = scan.bss.iter().find(|b| b.associated || w.bssid.as_deref() == Some(b.bssid.as_str()))
            {
                if let Some(sec) = assoc.security.as_deref() {
                    if matches!(sec, "Open" | "WEP") {
                        items.push(AdviceItem {
                            id: format!("wifi_sec_{name}"),
                            code: "wifi_sec".into(),
                            args: args(&[("iface", name.to_string()), ("sec", sec.to_string()), ("bssid", assoc.bssid.clone())]),
                            severity: "critical".into(),
                            category: "security".into(),
                            title: format!("{name}: insecure Wi-Fi encryption ({sec})"),
                            evidence: format!("Connected BSS {} uses {sec}", assoc.bssid),
                            recommendation: "Switch Wi-Fi security to WPA2-PSK (AES) or WPA3-SAE immediately.".into(),
                        });
                    } else if matches!(sec, "WPA" | "WPA2-TKIP") {
                        items.push(AdviceItem {
                            id: format!("wifi_tkip_{name}"),
                            code: "wifi_tkip".into(),
                            args: args(&[("iface", name.to_string()), ("sec", sec.to_string()), ("bssid", assoc.bssid.clone())]),
                            severity: "warn".into(),
                            category: "security".into(),
                            title: format!("{name}: legacy cipher ({sec}) enabled"),
                            evidence: format!("Connected BSS {} still advertises legacy {sec}", assoc.bssid),
                            recommendation: "Disable TKIP / WPA1 and require AES-CCMP (WPA2) or WPA3.".into(),
                        });
                    }
                }
                if assoc.wps {
                    items.push(AdviceItem {
                        id: format!("wifi_wps_{name}"),
                        code: "wifi_wps".into(),
                        args: args(&[("iface", name.to_string()), ("bssid", assoc.bssid.clone())]),
                        severity: "warn".into(),
                        category: "security".into(),
                        title: format!("{name}: WPS advertised on AP"),
                        evidence: format!("WPS vendor IE present on {}", assoc.bssid),
                        recommendation: "Disable WPS in router Wi-Fi settings to block brute-force PIN attacks.".into(),
                    });
                }
            }
        }
    }

    if let Some(a) = audit {
        let gw = a.gateway_ip.as_deref().unwrap_or("gateway");
        for p in &a.ports {
            if p.risk == "high" {
                items.push(AdviceItem {
                    id: format!("port_high_{}", p.port),
                    code: "port_high".into(),
                    args: args(&[("service", p.service.clone()), ("port", p.port.to_string()), ("gw", gw.to_string())]),
                    severity: "critical".into(),
                    category: "security".into(),
                    title: format!("Insecure {} port ({}) open on {gw}", p.service, p.port),
                    evidence: format!("TCP connect succeeded to {gw}:{}", p.port),
                    recommendation: format!("Disable {} in router administration/services settings.", p.service),
                });
            } else if p.risk == "warn" {
                items.push(AdviceItem {
                    id: format!("port_http_{}", p.port),
                    code: "port_http".into(),
                    args: args(&[("port", p.port.to_string()), ("gw", gw.to_string())]),
                    severity: "warn".into(),
                    category: "security".into(),
                    title: format!("Plaintext HTTP admin ({}) without HTTPS on {gw}", p.port),
                    evidence: format!("Port {} answered while HTTPS (443) is closed", p.port),
                    recommendation: "Enable HTTPS management for the router admin UI if firmware supports it.".into(),
                });
            }
        }
    }

    if let Some(r) = &snap.router {
        if let Some(ws) = &r.wan_status
            && !ws.eq_ignore_ascii_case("connected")
        {
            items.push(AdviceItem {
                id: "router_wan_down".into(),
                code: "router_wan_down".into(),
                args: args(&[("status", ws.to_string())]),
                severity: "critical".into(),
                category: "router".into(),
                title: format!("Router WAN status is {ws}"),
                evidence: r.last_error.clone().unwrap_or_else(|| format!("UPnP WAN status: {ws}")),
                recommendation: "Problem is on the modem/ISP side; check coax/fibre cable and modem logs.".into(),
            });
        }
        let max_net_rtt = snap.ifaces.values().filter_map(|i| i.last.as_ref()?.net.rtt_ms).fold(0.0f64, f64::max);
        let wan_mbps = r.wan_rx_mbps.unwrap_or(0.0).max(r.wan_tx_mbps.unwrap_or(0.0));
        if wan_mbps > 50.0 && max_net_rtt > 80.0 {
            items.push(AdviceItem {
                id: "router_bufferbloat".into(),
                code: "router_bufferbloat".into(),
                args: args(&[("mbps", format!("{wan_mbps:.1}")), ("rtt", format!("{max_net_rtt:.0}"))]),
                severity: "warn".into(),
                category: "router".into(),
                title: "Possible router bufferbloat under load".into(),
                evidence: format!("WAN traffic {wan_mbps:.1} Mbit/s with {max_net_rtt:.0} ms internet RTT"),
                recommendation: "Enable SQM / Smart Queue Management or QoS bandwidth shaping on the router.".into(),
            });
        }
    }

    if let Some(h) = &snap.host {
        if h.throttled {
            items.push(AdviceItem {
                id: "host_throttled".into(),
                code: "host_throttled".into(),
                args: args(&[]),
                severity: "critical".into(),
                category: "observer".into(),
                title: "Observer host undervoltage / throttling".into(),
                evidence: "Host telemetry reported active throttling".into(),
                recommendation: "Use a stronger USB power supply on the monitoring device so measurements stay reliable.".into(),
            });
        }
        if h.clock_synced == Some(false) {
            items.push(AdviceItem {
                id: "host_ntp".into(),
                code: "host_ntp".into(),
                args: args(&[]),
                severity: "warn".into(),
                category: "observer".into(),
                title: "Observer system clock is not NTP-synced".into(),
                evidence: "timedatectl / NTP sync reported false".into(),
                recommendation: "Ensure NTP sync works so multi-room session comparisons stay aligned.".into(),
            });
        }
        if let Some(t) = h.temp_c
            && t >= 75.0
        {
            items.push(AdviceItem {
                id: "host_temp".into(),
                code: "host_temp".into(),
                args: args(&[("temp", format!("{t:.1}"))]),
                severity: if t >= 85.0 { "critical" } else { "warn" }.into(),
                category: "observer".into(),
                title: format!("High observer CPU temperature ({t:.1} °C)"),
                evidence: format!("Host thermal sensor reads {t:.1} °C"),
                recommendation: "Improve ventilation around the monitoring box.".into(),
            });
        }
    }

    // The live verdict leads: the advisor must never say "no issues" while paths are failing.
    if let Some(v) = snap.verdict {
        let (severity, title, rec) = match v {
            Verdict::WifiProblem => ("critical", "Wi-Fi is failing while the cable path works", "The fault is on the wireless hop: check signal, channel and interference for this room before blaming the line."),
            Verdict::WiredProblem => ("warn", "The wired path is failing while Wi-Fi works", "Check the Ethernet cable, the router port and the observer's network adapter."),
            Verdict::RouterProblem => ("critical", "All paths fail at the router", "The router stopped answering on the LAN: note the time, check its lights and logs, and whether it restarted."),
            Verdict::LineProblem => ("critical", "The line to the provider is failing", "The router answers but the provider's first hop does not: report the times to the ISP."),
            Verdict::InternetProblem => ("warn", "Internet targets fail beyond the provider", "The local network and the provider answer; the problem is further upstream."),
            Verdict::Dns => ("warn", "Name resolution (DNS) is failing", "Addresses answer but names do not resolve: check the DNS servers the router hands out."),
            Verdict::Mixed => ("warn", "Paths fail at different points", "Wi-Fi and the cable fail at different layers at the same time: check each path on its own before you look for one cause."),
            Verdict::AllOk | Verdict::SinglePath | Verdict::Unknown => ("", "", ""),
        };
        if !severity.is_empty() {
            let since = snap.verdict_since.map(|t| t.to_rfc3339()).unwrap_or_default();
            items.push(AdviceItem {
                id: format!("verdict_{}", v.as_str()),
                code: format!("verdict_{}", v.as_str()),
                args: args(&[("since", since)]),
                severity: severity.into(),
                category: "network".into(),
                title: title.into(),
                evidence: format!("Live verdict: {}", v.as_str()),
                recommendation: rec.into(),
            });
        }
    }

    items.sort_by_key(|i| match i.severity.as_str() {
        "critical" => 0,
        "warn" => 1,
        "info" => 2,
        _ => 3,
    });

    if items.is_empty() {
        items.push(AdviceItem {
            id: "all_clean".into(),
            code: "all_clean".into(),
            args: args(&[]),
            severity: "ok".into(),
            category: "wifi".into(),
            title: "No common configuration or security issues detected".into(),
            evidence: "Checked Wi-Fi channels, encryption, power save, host health, and gateway ports".into(),
            recommendation: "Keep monitoring across target rooms and check the report after overnight runs.".into(),
        });
    }

    AdviceResponse { generated_at: Utc::now(), items }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::live::IfaceLive;
    use crate::model::*;
    use crate::router::PortCheck;

    #[test]
    fn flags_classic_wifi_and_port_misconfigurations() {
        let mut snap = LiveSnapshot::default();
        snap.ifaces.insert("wlo1".into(), IfaceLive {
            name: "wlo1".into(),
            role: Some(IfaceRole::Wifi),
            wifi: Some(WifiStation {
                iface: "wlo1".into(),
                connected: true,
                bssid: Some("02:00:00:00:00:01".into()),
                freq_mhz: Some(2422),
                channel: Some(3),
                width_mhz: Some(40),
                signal_avg_dbm: Some(-79),
                power_save: Some(true),
                ..Default::default()
            }),
            ..Default::default()
        });
        snap.last_scan.insert("wlo1".into(), ScanReport {
            iface: "wlo1".into(),
            fresh: true,
            bss: vec![ScanBss {
                bssid: "02:00:00:00:00:01".into(),
                freq_mhz: 2422,
                channel: Some(3),
                security: Some("WEP".into()),
                wps: true,
                associated: true,
                ..Default::default()
            }],
        });
        let audit = RouterAudit {
            gateway_ip: Some("192.168.0.1".into()),
            ports: vec![PortCheck { port: 23, service: "Telnet".into(), open: true, risk: "high".into() }],
            ..Default::default()
        };

        let res = evaluate(&snap, Some(&audit));
        let ids: Vec<&str> = res.items.iter().map(|i| i.id.as_str()).collect();
        assert!(ids.contains(&"wifi_weak_wlo1"), "{ids:?}");
        assert!(ids.contains(&"wifi_ps_wlo1"), "{ids:?}");
        assert!(ids.contains(&"wifi_24_overlap_wlo1"), "{ids:?}");
        assert!(ids.contains(&"wifi_24_40mhz_wlo1"), "{ids:?}");
        assert!(ids.contains(&"wifi_sec_wlo1"), "{ids:?}");
        assert!(ids.contains(&"wifi_wps_wlo1"), "{ids:?}");
        assert!(ids.contains(&"port_high_23"), "{ids:?}");
    }

    #[test]
    fn failing_verdict_is_never_reported_as_clean() {
        let snap = LiveSnapshot { verdict: Some(Verdict::WifiProblem), ..Default::default() };
        let res = evaluate(&snap, None);
        assert_eq!(res.items[0].code, "verdict_wifi_problem");
        assert_eq!(res.items[0].severity, "critical");
        assert!(res.items.iter().all(|i| i.code != "all_clean"));
    }

    #[test]
    fn clean_snapshot_reports_ok_summary() {
        let snap = LiveSnapshot::default();
        let res = evaluate(&snap, None);
        assert_eq!(res.items.len(), 1);
        assert_eq!(res.items[0].severity, "ok");
    }
}
