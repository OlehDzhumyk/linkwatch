//! Passive security detectors running over already-collected network signals:
//! gateway MAC changes (ARP spoofing), rogue DHCP/gateway switches, same-SSID evil-twin APs,
//! and DNS answer anomalies. Pure state machine; bounded dedup sets; fully unit-tested.

use crate::model::{EventKind, ScanReport};
use std::collections::{HashMap, HashSet};
use std::hash::Hash;
use std::net::Ipv4Addr;

const CAP_TRANSITIONS: usize = 256;
const CAP_BSSIDS: usize = 1024;
const CAP_DNS_ALERTS: usize = 1024;
const CAP_DNS_PREFIXES: usize = 64;

fn insert_bounded<T: Eq + Hash>(set: &mut HashSet<T>, val: T, cap: usize) -> bool {
    if set.contains(&val) || set.len() >= cap {
        return false;
    }
    set.insert(val)
}

#[derive(Debug, Default)]
pub struct SecurityMonitor {
    gw_macs: HashMap<(String, Ipv4Addr), String>,
    gw_mac_alerted: HashSet<(String, Ipv4Addr, String, String)>,
    cross_iface_alerted: HashSet<(Ipv4Addr, String, String)>,
    iface_gw: HashMap<String, Ipv4Addr>,
    rogue_gw_alerted: HashSet<(String, Ipv4Addr, Ipv4Addr)>,
    iface_dhcp: HashMap<String, Ipv4Addr>,
    rogue_dhcp_alerted: HashSet<(String, Ipv4Addr, Ipv4Addr)>,
    known_ouis: HashMap<String, HashSet<[u8; 3]>>,
    alerted_bssids: HashSet<String>,
    dns_private_alerted: HashSet<(Ipv4Addr, Ipv4Addr)>,
    dns_prefixes: HashMap<String, HashMap<Ipv4Addr, HashSet<[u8; 2]>>>,
    dns_disjoint_streak: HashMap<(Ipv4Addr, Ipv4Addr, String), u32>,
    dns_mismatch_alerted: HashSet<(Ipv4Addr, Ipv4Addr, String)>,
}

impl SecurityMonitor {
    pub fn new() -> Self {
        Self::default()
    }

    /// Detects gateway MAC changes on one interface or conflicting MACs for the same gateway IP
    /// across different interfaces (deduplicated per transition).
    pub fn check_gateway_mac(
        &mut self,
        iface: &str,
        gw_ip: Ipv4Addr,
        mac: &str,
    ) -> Vec<EventKind> {
        let mac = mac.to_ascii_lowercase();
        let mut out = Vec::new();
        let key = (iface.to_string(), gw_ip);
        if let Some(prev) = self.gw_macs.get(&key)
            && prev != &mac
            && insert_bounded(
                &mut self.gw_mac_alerted,
                (iface.to_string(), gw_ip, prev.clone(), mac.clone()),
                CAP_TRANSITIONS,
            )
        {
            out.push(EventKind::Security {
                detector: "gateway_mac_change".into(),
                severity: "high".into(),
                iface: Some(iface.to_string()),
                detail: format!("gateway {gw_ip} MAC changed from {prev} to {mac}"),
            });
        }
        self.gw_macs.insert(key, mac.clone());

        for ((other_if, g), other_mac) in &self.gw_macs {
            if *g == gw_ip && other_if != iface && other_mac != &mac {
                let (a, b) = if other_mac < &mac {
                    (other_mac.clone(), mac.clone())
                } else {
                    (mac.clone(), other_mac.clone())
                };
                if insert_bounded(&mut self.cross_iface_alerted, (gw_ip, a, b), CAP_TRANSITIONS) {
                    out.push(EventKind::Security {
                        detector: "gateway_mac_change".into(),
                        severity: "high".into(),
                        iface: Some(iface.to_string()),
                        detail: format!(
                            "gateway {gw_ip} has different MACs across interfaces: {other_if}={other_mac} vs {iface}={mac}"
                        ),
                    });
                }
            }
        }
        out
    }

    /// Detects mid-session default-gateway IP or DHCP server changes (deduplicated per transition).
    pub fn check_gateway_dhcp(
        &mut self,
        iface: &str,
        gw_ip: Option<Ipv4Addr>,
        dhcp: Option<Ipv4Addr>,
    ) -> Vec<EventKind> {
        let mut out = Vec::new();
        if let Some(gw) = gw_ip {
            if let Some(&prev) = self.iface_gw.get(iface)
                && prev != gw
                && insert_bounded(
                    &mut self.rogue_gw_alerted,
                    (iface.to_string(), prev, gw),
                    CAP_TRANSITIONS,
                )
            {
                out.push(EventKind::Security {
                    detector: "rogue_gateway".into(),
                    severity: "high".into(),
                    iface: Some(iface.to_string()),
                    detail: format!("default gateway changed from {prev} to {gw}"),
                });
            }
            self.iface_gw.insert(iface.to_string(), gw);
        }
        if let Some(srv) = dhcp {
            if let Some(&prev) = self.iface_dhcp.get(iface)
                && prev != srv
                && insert_bounded(
                    &mut self.rogue_dhcp_alerted,
                    (iface.to_string(), prev, srv),
                    CAP_TRANSITIONS,
                )
            {
                out.push(EventKind::Security {
                    detector: "rogue_gateway".into(),
                    severity: "high".into(),
                    iface: Some(iface.to_string()),
                    detail: format!("DHCP server changed from {prev} to {srv}"),
                });
            }
            self.iface_dhcp.insert(iface.to_string(), srv);
        }
        out
    }

    /// Detects a new BSSID advertising our current SSID from an unknown vendor/OUI.
    pub fn check_scan(
        &mut self,
        iface: &str,
        our_ssid: Option<&str>,
        our_bssid: Option<&str>,
        rep: &ScanReport,
    ) -> Vec<EventKind> {
        let Some(ssid) = our_ssid.filter(|s| !s.is_empty()) else {
            return Vec::new();
        };
        let mut out = Vec::new();
        let first_seen = !self.known_ouis.contains_key(ssid);
        let ouis = self.known_ouis.entry(ssid.to_string()).or_default();
        if let Some(b) = our_bssid.and_then(oui_key) {
            ouis.insert(b);
        }
        if first_seen {
            for b in rep.bss.iter().filter(|b| b.ssid.as_deref() == Some(ssid)) {
                if let Some(o) = oui_key(&b.bssid) {
                    ouis.insert(o);
                }
            }
            return out;
        }
        for b in rep.bss.iter().filter(|b| b.ssid.as_deref() == Some(ssid)) {
            let Some(o) = oui_key(&b.bssid) else { continue };
            if !ouis.contains(&o) {
                let bssid_lc = b.bssid.to_ascii_lowercase();
                if insert_bounded(&mut self.alerted_bssids, bssid_lc.clone(), CAP_BSSIDS) {
                    out.push(EventKind::Security {
                        detector: "evil_twin".into(),
                        severity: "medium".into(),
                        iface: Some(iface.to_string()),
                        detail: format!(
                            "unknown BSSID {bssid_lc} (ch {:?}, {:?} dBm) advertising our SSID {ssid:?}",
                            b.channel, b.signal_dbm
                        ),
                    });
                }
            }
        }
        out
    }

    /// Detects private/CGNAT/loopback answers for public domains, and repeated completely disjoint
    /// /16 prefix sets across DNS servers (informational `low` severity after 3 checks to avoid CDN noise).
    pub fn check_dns(
        &mut self,
        iface: &str,
        server: Ipv4Addr,
        name: &str,
        answers: &[Ipv4Addr],
    ) -> Vec<EventKind> {
        if answers.is_empty() || !is_public_domain(name) {
            return Vec::new();
        }
        let mut out = Vec::new();
        let mut public_prefixes = HashSet::new();
        for &ip in answers {
            if is_non_public_v4(ip) {
                if insert_bounded(&mut self.dns_private_alerted, (server, ip), CAP_DNS_ALERTS) {
                    out.push(EventKind::Security {
                        detector: "dns_mismatch".into(),
                        severity: "high".into(),
                        iface: Some(iface.to_string()),
                        detail: format!("DNS {server} returned non-public IP {ip} for {name}"),
                    });
                }
            } else {
                let o = ip.octets();
                public_prefixes.insert([o[0], o[1]]);
            }
        }
        if !public_prefixes.is_empty() {
            let name_lc = name.trim_end_matches('.').to_ascii_lowercase();
            let by_srv = self.dns_prefixes.entry(name_lc.clone()).or_default();
            let srv_set = by_srv.entry(server).or_default();
            for p in public_prefixes {
                if srv_set.len() < CAP_DNS_PREFIXES {
                    srv_set.insert(p);
                }
            }
            let cur_set = by_srv.get(&server).cloned().unwrap_or_default();
            for (&other_srv, other_set) in by_srv.iter() {
                if other_srv == server || other_set.is_empty() || cur_set.is_empty() {
                    continue;
                }
                let (a, b) = if other_srv < server {
                    (other_srv, server)
                } else {
                    (server, other_srv)
                };
                let key = (a, b, name_lc.clone());
                if cur_set.is_disjoint(other_set) {
                    let n = self.dns_disjoint_streak.entry(key.clone()).or_default();
                    *n += 1;
                    if *n >= 3 && insert_bounded(&mut self.dns_mismatch_alerted, key, CAP_TRANSITIONS) {
                        out.push(EventKind::Security {
                            detector: "dns_mismatch".into(),
                            severity: "low".into(),
                            iface: Some(iface.to_string()),
                            detail: format!(
                                "DNS servers {a} and {b} persistently return disjoint IP prefixes for {name_lc} (could be CDN geo-DNS)"
                            ),
                        });
                    }
                } else {
                    self.dns_disjoint_streak.remove(&key);
                }
            }
        }
        out
    }
}

/// First 3 octets with the locally-administered U/L bit (`0x02`) cleared so dual-band
/// router VAPs with derived MACs match the same device.
fn oui_key(mac: &str) -> Option<[u8; 3]> {
    let mut it = mac.split(':');
    let b0 = u8::from_str_radix(it.next()?, 16).ok()? & !0x02;
    let b1 = u8::from_str_radix(it.next()?, 16).ok()?;
    let b2 = u8::from_str_radix(it.next()?, 16).ok()?;
    Some([b0, b1, b2])
}

fn is_public_domain(name: &str) -> bool {
    let n = name.trim_end_matches('.').to_ascii_lowercase();
    !n.is_empty()
        && n.contains('.')
        && ![".local", ".lan", ".home", ".home.arpa", ".internal", ".localhost", ".arpa"]
            .iter()
            .any(|s| n.ends_with(s))
}

fn is_non_public_v4(ip: Ipv4Addr) -> bool {
    let o = ip.octets();
    let cgnat = o[0] == 100 && (o[1] & 0xc0) == 64;
    ip.is_private()
        || ip.is_loopback()
        || ip.is_link_local()
        || ip.is_unspecified()
        || ip.is_multicast()
        || ip.is_broadcast()
        || cgnat
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::ScanBss;

    #[test]
    fn gateway_mac_change_dedup_and_cross_iface_conflict() {
        let mut m = SecurityMonitor::new();
        let gw = Ipv4Addr::new(192, 168, 0, 1);
        assert!(m.check_gateway_mac("wlo1", gw, "02:00:00:00:00:04").is_empty());
        assert!(m.check_gateway_mac("enp1s0", gw, "02:00:00:00:00:04").is_empty());
        let ev = m.check_gateway_mac("wlo1", gw, "02:00:00:00:00:99");
        assert_eq!(ev.len(), 2);
        assert!(matches!(&ev[0], EventKind::Security { detector, severity, .. } if detector == "gateway_mac_change" && severity == "high"));
        // Flapping back and forth must NOT flood duplicates once the transition is recorded.
        let ev_back = m.check_gateway_mac("wlo1", gw, "02:00:00:00:00:04");
        assert_eq!(ev_back.len(), 1);
        assert!(m.check_gateway_mac("wlo1", gw, "02:00:00:00:00:99").is_empty());
    }

    #[test]
    fn rogue_gateway_and_dhcp_change_dedup() {
        let mut m = SecurityMonitor::new();
        assert!(m.check_gateway_dhcp("wlo1", Some(Ipv4Addr::new(192, 168, 0, 1)), Some(Ipv4Addr::new(192, 168, 0, 1))).is_empty());
        let ev = m.check_gateway_dhcp("wlo1", Some(Ipv4Addr::new(192, 168, 0, 254)), Some(Ipv4Addr::new(192, 168, 0, 254)));
        assert_eq!(ev.len(), 2);
        assert!(ev.iter().all(|e| matches!(e, EventKind::Security { detector, .. } if detector == "rogue_gateway")));
        assert_eq!(m.check_gateway_dhcp("wlo1", Some(Ipv4Addr::new(192, 168, 0, 1)), Some(Ipv4Addr::new(192, 168, 0, 1))).len(), 2);
        assert!(m.check_gateway_dhcp("wlo1", Some(Ipv4Addr::new(192, 168, 0, 254)), Some(Ipv4Addr::new(192, 168, 0, 254))).is_empty());
    }

    #[test]
    fn evil_twin_allows_dual_band_ul_bit_and_flags_stranger() {
        let mut m = SecurityMonitor::new();
        let scan1 = ScanReport {
            iface: "wlo1".into(),
            fresh: true,
            bss: vec![ScanBss {
                bssid: "00:11:22:33:44:01".into(),
                ssid: Some("FlatNet".into()),
                freq_mhz: 5180,
                channel: Some(36),
                signal_dbm: Some(-50.0),
                ..Default::default()
            }],
        };
        assert!(m.check_scan("wlo1", Some("FlatNet"), Some("00:11:22:33:44:01"), &scan1).is_empty());

        let scan2 = ScanReport {
            iface: "wlo1".into(),
            fresh: true,
            bss: vec![
                ScanBss {
                    bssid: "02:11:22:33:44:02".into(),
                    ssid: Some("FlatNet".into()),
                    freq_mhz: 2437,
                    channel: Some(6),
                    signal_dbm: Some(-55.0),
                    ..Default::default()
                },
                ScanBss {
                    bssid: "02:aa:bb:cc:dd:ee".into(),
                    ssid: Some("FlatNet".into()),
                    freq_mhz: 2437,
                    channel: Some(6),
                    signal_dbm: Some(-42.0),
                    ..Default::default()
                },
            ],
        };
        let ev = m.check_scan("wlo1", Some("FlatNet"), Some("00:11:22:33:44:01"), &scan2);
        assert_eq!(ev.len(), 1);
        assert!(matches!(&ev[0], EventKind::Security { detector, .. } if detector == "evil_twin"));
        assert!(m.check_scan("wlo1", Some("FlatNet"), Some("00:11:22:33:44:01"), &scan2).is_empty());
    }

    #[test]
    fn dns_private_cgnat_and_persistent_disjoint_prefixes() {
        let mut m = SecurityMonitor::new();
        let s1 = Ipv4Addr::new(1, 1, 1, 1);
        let s2 = Ipv4Addr::new(8, 8, 8, 8);
        assert!(m.check_dns("wlo1", s1, "example.com", &[Ipv4Addr::new(93, 184, 216, 34)]).is_empty());
        // Private and CGNAT IPs trigger immediate high-severity dns_mismatch.
        let ev = m.check_dns("wlo1", s2, "example.com", &[Ipv4Addr::new(192, 168, 0, 50), Ipv4Addr::new(100, 64, 0, 1)]);
        assert_eq!(ev.len(), 2);
        assert!(matches!(&ev[0], EventKind::Security { detector, severity, .. } if detector == "dns_mismatch" && severity == "high"));
        // Single disjoint check does NOT alarm (avoids CDN GeoDNS false positive); 3 consecutive checks emit `low`.
        assert!(m.check_dns("wlo1", s2, "example.com", &[Ipv4Addr::new(198, 51, 100, 5)]).is_empty());
        assert!(m.check_dns("wlo1", s2, "example.com", &[Ipv4Addr::new(198, 51, 100, 5)]).is_empty());
        let ev2 = m.check_dns("wlo1", s2, "example.com", &[Ipv4Addr::new(198, 51, 100, 5)]);
        assert_eq!(ev2.len(), 1);
        assert!(matches!(&ev2[0], EventKind::Security { detector, severity, .. } if detector == "dns_mismatch" && severity == "low"));
    }
}
