//! How many devices are active on the local network: counts only.
//!
//! A sweep sends one ICMP echo to every address of a small subnet (unprivileged ping
//! sockets). Each echo makes the kernel resolve the address with ARP, so afterwards the
//! neighbour table lists every device that answered ARP, even devices that ignore ping.
//! Nothing that identifies a device leaves this module: MAC addresses are only hashed in
//! memory (with a random per-run salt) to count distinct devices over a session.

use crate::link;
use crate::probe::icmp;
use std::collections::HashSet;
use std::hash::{BuildHasher, Hasher, RandomState};
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Semaphore;

/// Largest subnet we sweep: a /22 (1022 hosts). Bigger networks are not a flat or a house.
pub const MIN_PREFIX: u8 = 22;
/// Echoes in flight at once; keeps the sweep gentle on a weak Wi-Fi link.
const IN_FLIGHT: usize = 32;

/// Result of one sweep on one interface.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct LanCount {
    /// Addresses probed.
    pub probed: u32,
    /// Devices that answered the ICMP echo.
    pub ping_alive: u32,
    /// Devices with a resolved (complete) ARP entry on this interface after the sweep,
    /// excluding our own addresses. Devices that drop ping are still counted here.
    pub arp_alive: u32,
    /// Distinct devices seen on this interface since the counter was created.
    pub unique_seen: u32,
}

/// Host addresses of `ip/prefix`, without the network and broadcast address and without
/// `ip` itself. Empty for subnets larger than /22 or for /31 and /32.
pub fn hosts(ip: Ipv4Addr, prefix: u8) -> Vec<Ipv4Addr> {
    if !(MIN_PREFIX..=30).contains(&prefix) {
        return Vec::new();
    }
    let mask = u32::MAX << (32 - u32::from(prefix));
    let net = u32::from(ip) & mask;
    let bcast = net | !mask;
    ((net + 1)..bcast).map(Ipv4Addr::from).filter(|a| *a != ip).collect()
}

/// Sends one echo to every host of the subnet of `iface` and returns how many answered.
pub async fn sweep(iface: &str, targets: &[Ipv4Addr], timeout: Duration) -> u32 {
    let sem = Arc::new(Semaphore::new(IN_FLIGHT));
    let mut tasks = tokio::task::JoinSet::new();
    for &dst in targets {
        let Ok(permit) = sem.clone().acquire_owned().await else { break };
        let iface = iface.to_string();
        tasks.spawn(async move {
            let r = icmp::ping(&iface, dst, timeout).await;
            drop(permit);
            r.ok
        });
    }
    let mut alive = 0;
    while let Some(r) = tasks.join_next().await {
        if matches!(r, Ok(true)) {
            alive += 1;
        }
    }
    alive
}

/// MAC addresses with a complete ARP entry on `iface`, from `/proc/net/arp` text (deduplicated).
pub fn neighbours(arp_text: &str, iface: &str, exclude: &[Ipv4Addr]) -> Vec<String> {
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    for (ip, mac, dev) in link::parse_arp_table(arp_text) {
        if dev == iface && !exclude.contains(&ip) && seen.insert(mac.to_ascii_lowercase()) {
            out.push(mac);
        }
    }
    out
}

/// Counts distinct devices over time without keeping their addresses.
pub struct DeviceCounter {
    salt: RandomState,
    seen: HashSet<u64>,
}

impl Default for DeviceCounter {
    fn default() -> Self {
        Self::new()
    }
}

impl DeviceCounter {
    /// Hard cap on remembered devices (a hash each), so memory stays bounded.
    pub const MAX_SEEN: usize = 4096;

    pub fn new() -> Self {
        Self { salt: RandomState::new(), seen: HashSet::new() }
    }

    /// Adds the devices of one sweep; returns the number of distinct devices seen so far.
    pub fn observe(&mut self, macs: &[String]) -> u32 {
        for m in macs {
            if self.seen.len() >= Self::MAX_SEEN {
                break;
            }
            let mut h = self.salt.build_hasher();
            h.write(m.to_ascii_lowercase().as_bytes());
            self.seen.insert(h.finish());
        }
        u32::try_from(self.seen.len()).unwrap_or(u32::MAX)
    }
}

/// One full measurement for an interface: sweep, read the neighbour table, update counts.
/// `exclude` lists additional local IPs on sibling interfaces so they are neither probed nor counted.
pub async fn count(
    iface: &str,
    ip: Ipv4Addr,
    prefix: u8,
    exclude: &[Ipv4Addr],
    counter: &mut DeviceCounter,
) -> Option<LanCount> {
    let mut targets = hosts(ip, prefix);
    targets.retain(|a| !exclude.contains(a));
    if targets.is_empty() {
        return None;
    }
    let ping_alive = sweep(iface, &targets, Duration::from_millis(800)).await;
    // ARP replies arrive within the echo timeout; read the table once the sweep is done.
    let text = tokio::fs::read_to_string("/proc/net/arp").await.ok()?;
    let mut all_exclude = Vec::with_capacity(exclude.len() + 1);
    all_exclude.push(ip);
    all_exclude.extend_from_slice(exclude);
    let macs = neighbours(&text, iface, &all_exclude);
    Some(LanCount {
        probed: u32::try_from(targets.len()).unwrap_or(u32::MAX),
        ping_alive,
        arp_alive: u32::try_from(macs.len()).unwrap_or(u32::MAX),
        unique_seen: counter.observe(&macs),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hosts_of_small_subnets_only() {
        let ip = Ipv4Addr::new(192, 168, 0, 10);
        let h = hosts(ip, 24);
        assert_eq!(h.len(), 253); // 254 hosts minus ourselves
        assert_eq!(h.first(), Some(&Ipv4Addr::new(192, 168, 0, 1)));
        assert_eq!(h.last(), Some(&Ipv4Addr::new(192, 168, 0, 254)));
        assert!(!h.contains(&ip));
        assert_eq!(hosts(ip, 30).len(), 1);
        assert!(hosts(ip, 16).is_empty(), "too big to sweep");
        assert!(hosts(ip, 31).is_empty());
        assert_eq!(hosts(Ipv4Addr::new(10, 0, 0, 5), 22).len(), 1021);
    }

    #[test]
    fn neighbours_filters_interface_incomplete_and_self() {
        let t = "IP address       HW type     Flags       HW address            Mask     Device\n\
                 192.168.0.1      0x1         0x2         02:00:00:00:00:01     *        wlan0\n\
                 192.168.0.2      0x1         0x2         02:00:00:00:00:01     *        wlan0\n\
                 192.168.0.7      0x1         0x0         00:00:00:00:00:00     *        wlan0\n\
                 192.168.0.9      0x1         0x2         02:00:00:00:00:09     *        eth0\n\
                 192.168.0.10     0x1         0x2         02:00:00:00:00:10     *        wlan0\n\
                 192.168.0.11     0x1         0x2         02:00:00:00:00:11     *        wlan0\n";
        let exclude = [Ipv4Addr::new(192, 168, 0, 10), Ipv4Addr::new(192, 168, 0, 11)];
        let n = neighbours(t, "wlan0", &exclude);
        assert_eq!(n, vec!["02:00:00:00:00:01".to_string()]);
    }

    #[test]
    fn counter_counts_distinct_devices_without_keeping_them() {
        let mut c = DeviceCounter::new();
        assert_eq!(c.observe(&["02:00:00:00:00:01".into(), "02:00:00:00:00:02".into()]), 2);
        assert_eq!(c.observe(&["02:00:00:00:00:01".into(), "02:00:00:00:00:03".into()]), 3);
        assert_eq!(c.observe(&["02:00:00:00:00:0A".into(), "02:00:00:00:00:0a".into()]), 4, "case-insensitive");
    }

    /// Real sweep of the subnet of the first interface with an IPv4 default route.
    #[tokio::test]
    #[ignore = "sends one echo to every address of the local /24"]
    async fn live_count() {
        let (name, _) = link::list_candidates()
            .into_iter()
            .find(|(n, _)| link::read(n).gateway.is_some())
            .expect("an interface with a gateway");
        let l = link::read(&name);
        let mut c = DeviceCounter::new();
        let r = count(&name, l.ipv4.unwrap(), l.prefix_len.unwrap(), &[], &mut c).await.unwrap();
        println!("{name}: {r:?}");
        assert!(r.arp_alive >= 1, "at least the router");
    }
}

