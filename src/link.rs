//! Interface link state from sysfs, procfs and `getifaddrs(3)`.
//!
//! Everything here is synchronous and cheap (a few small file reads), so it is
//! safe to call from async code once per tick. Nothing panics: a missing
//! interface or unreadable file gives `present = false` or default values.

use crate::model::{IfaceRole, LinkState};
use std::net::Ipv4Addr;
use std::path::Path;

const SYS_NET: &str = "/sys/class/net";
/// `IFF_UP` from `<net/if.h>`.
const IFF_UP: u32 = 0x1;

/// Reads the current layer-1/3 state of `iface`.
pub fn read(iface: &str) -> LinkState {
    if !valid_name(iface) {
        return LinkState::default();
    }
    let base = Path::new(SYS_NET).join(iface);
    if !base.exists() {
        return LinkState::default();
    }
    let operstate = read_trim(&base.join("operstate")).unwrap_or_default();
    let flags = read_trim(&base.join("flags"))
        .and_then(|s| parse_hex_u32(&s))
        .unwrap_or(0);
    // `carrier` returns EINVAL while the interface is administratively down.
    let carrier = read_trim(&base.join("carrier")).is_some_and(|s| s == "1");
    let up = flags & IFF_UP != 0 && operstate == "up";
    let gateway = std::fs::read_to_string("/proc/net/route")
        .ok()
        .and_then(|t| parse_route_gateway(&t, iface));
    let (ipv4, prefix_len) = match ipv4_of(iface, gateway) {
        Some((a, p)) => (Some(a), Some(p)),
        None => (None, None),
    };
    LinkState {
        present: true,
        up,
        carrier,
        ipv4,
        prefix_len,
        gateway,
        rx_bytes: read_u64(&base.join("statistics/rx_bytes")),
        tx_bytes: read_u64(&base.join("statistics/tx_bytes")),
    }
}

/// Wi-Fi if sysfs has `wireless` or `phy80211`, Ethernet if it is a physical
/// ARPHRD_ETHER device, otherwise Other.
pub fn detect_role(iface: &str) -> IfaceRole {
    if !valid_name(iface) {
        return IfaceRole::Other;
    }
    let base = Path::new(SYS_NET).join(iface);
    if base.join("wireless").exists() || base.join("phy80211").exists() {
        return IfaceRole::Wifi;
    }
    // type 1 = ARPHRD_ETHER; a `device` link means real hardware.
    let is_ether = read_trim(&base.join("type")).is_some_and(|t| t == "1");
    if is_ether && base.join("device").exists() {
        IfaceRole::Ethernet
    } else {
        IfaceRole::Other
    }
}

/// Physical interfaces that are worth monitoring, sorted by name.
pub fn list_candidates() -> Vec<(String, IfaceRole)> {
    let Ok(dir) = std::fs::read_dir(SYS_NET) else {
        return Vec::new();
    };
    let mut out: Vec<(String, IfaceRole)> = dir
        .filter_map(|e| e.ok())
        .filter_map(|e| e.file_name().into_string().ok())
        .filter(|n| !is_virtual_name(n))
        .filter(|n| Path::new(SYS_NET).join(n).join("device").exists())
        .map(|n| {
            let r = detect_role(&n);
            (n, r)
        })
        .collect();
    out.sort_by(|a, b| a.0.cmp(&b.0));
    out
}

/// IPv4 name servers from `/etc/resolv.conf`, plus the upstream servers of
/// systemd-resolved from `/run/systemd/resolve/resolv.conf`. Loopback
/// addresses (the 127.0.0.53 stub) are skipped. Order kept, duplicates removed.
pub fn resolv_conf_servers() -> Vec<Ipv4Addr> {
    let mut out = Vec::new();
    for p in ["/etc/resolv.conf", "/run/systemd/resolve/resolv.conf"] {
        if let Ok(t) = std::fs::read_to_string(p) {
            for a in parse_resolv_conf(&t) {
                if !out.contains(&a) {
                    out.push(a);
                }
            }
        }
    }
    out
}

fn parse_resolv_conf(text: &str) -> Vec<Ipv4Addr> {
    text.lines()
        .filter_map(|l| {
            let mut it = l.split_whitespace();
            (it.next() == Some("nameserver"))
                .then(|| it.next())
                .flatten()
        })
        .filter_map(|s| s.parse::<Ipv4Addr>().ok())
        .filter(|a| !a.is_loopback())
        .collect()
}

fn is_virtual_name(n: &str) -> bool {
    n == "lo"
        || [
            "docker", "veth", "br", "tun", "tap", "virbr", "wg", "vnet", "lxc",
        ]
        .iter()
        .any(|p| n.starts_with(p))
}

/// Interface names are at most 15 bytes and must not contain path parts.
fn valid_name(n: &str) -> bool {
    !n.is_empty() && n.len() < 16 && !n.contains('/') && n != "." && n != ".."
}

fn read_trim(p: &Path) -> Option<String> {
    std::fs::read_to_string(p)
        .ok()
        .map(|s| s.trim().to_string())
}

fn read_u64(p: &Path) -> u64 {
    read_trim(p).and_then(|s| s.parse().ok()).unwrap_or(0)
}

fn parse_hex_u32(s: &str) -> Option<u32> {
    u32::from_str_radix(s.trim_start_matches("0x"), 16).ok()
}

/// Finds the default route (destination 0, flag RTF_GATEWAY) of `iface` in
/// `/proc/net/route`. Addresses there are hex in host (little-endian) order.
fn parse_route_gateway(text: &str, iface: &str) -> Option<Ipv4Addr> {
    const RTF_UP: u32 = 0x1;
    const RTF_GATEWAY: u32 = 0x2;
    let mut best: Option<(u32, Ipv4Addr)> = None;
    for line in text.lines().skip(1) {
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() < 8 || f[0] != iface {
            continue;
        }
        let (Some(dst), Some(gw), Some(flags), Some(mask)) = (
            parse_hex_u32(f[1]),
            parse_hex_u32(f[2]),
            parse_hex_u32(f[3]),
            parse_hex_u32(f[7]),
        ) else {
            continue;
        };
        let metric: u32 = f[6].parse().unwrap_or(u32::MAX);
        if dst == 0 && mask == 0 && flags & RTF_UP != 0 && flags & RTF_GATEWAY != 0 && gw != 0 {
            let addr = Ipv4Addr::from(gw.to_le_bytes());
            if best.is_none_or(|(m, _)| metric < m) {
                best = Some((metric, addr));
            }
        }
    }
    best.map(|(_, a)| a)
}

fn prefix_from_mask(mask: Ipv4Addr) -> u8 {
    u32::from(mask).count_ones() as u8
}

fn pick_ipv4(addrs: &[(Ipv4Addr, u8)], gateway: Option<Ipv4Addr>) -> Option<(Ipv4Addr, u8)> {
    if let Some(gw) = gateway
        && let Some(hit) = addrs.iter().copied().find(|&(ip, p)| in_subnet(gw, ip, p))
    {
        return Some(hit);
    }
    addrs.first().copied()
}

/// Primary IPv4 address and prefix length of `iface` via `getifaddrs(3)`,
/// preferring the address whose subnet contains `gateway` when multiple addresses exist.
fn ipv4_of(iface: &str, gateway: Option<Ipv4Addr>) -> Option<(Ipv4Addr, u8)> {
    let addrs = nix::ifaddrs::getifaddrs().ok()?;
    let list: Vec<(Ipv4Addr, u8)> = addrs
        .filter(|a| a.interface_name == iface)
        .filter_map(|ifa| {
            let sin = ifa.address.as_ref().and_then(|a| a.as_sockaddr_in())?;
            let prefix = ifa
                .netmask
                .as_ref()
                .and_then(|m| m.as_sockaddr_in())
                .map_or(32, |m| prefix_from_mask(m.ip()));
            Some((sin.ip(), prefix))
        })
        .collect();
    pick_ipv4(&list, gateway)
}

/// True when `addr` is inside the subnet `net/prefix`.
pub fn in_subnet(addr: Ipv4Addr, net: Ipv4Addr, prefix: u8) -> bool {
    if prefix == 0 {
        return true;
    }
    let p = u32::from(prefix.min(32));
    let mask = u32::MAX << (32 - p);
    u32::from(addr) & mask == u32::from(net) & mask
}

/// Canonical CIDR string for `ip/prefix`, e.g. `"192.168.0.0/24"`.
pub fn subnet_cidr(ip: Ipv4Addr, prefix: u8) -> String {
    let p = prefix.min(32);
    let mask = if p == 0 { 0 } else { u32::MAX << (32 - u32::from(p)) };
    let net = Ipv4Addr::from(u32::from(ip) & mask);
    format!("{net}/{p}")
}

/// Interface kernel index from `/sys/class/net/<iface>/ifindex`.
pub fn ifindex_sysfs(iface: &str) -> Option<u32> {
    if !valid_name(iface) {
        return None;
    }
    read_trim(&Path::new(SYS_NET).join(iface).join("ifindex"))?.parse().ok()
}

/// Parses `/proc/net/arp` lines into `(ip, mac_lowercase, iface)` for valid complete entries.
pub fn parse_arp_table(text: &str) -> Vec<(Ipv4Addr, String, String)> {
    let mut out = Vec::new();
    for line in text.lines().skip(1) {
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() < 6 {
            continue;
        }
        let Ok(ip) = f[0].parse::<Ipv4Addr>() else { continue };
        let Some(flags) = parse_hex_u32(f[2]) else { continue };
        if flags & 0x2 == 0 {
            continue;
        }
        let mac = f[3].to_ascii_lowercase();
        if mac.len() != 17 || mac == "00:00:00:00:00:00" {
            continue;
        }
        out.push((ip, mac, f[5].to_string()));
    }
    out
}

/// MAC address of `ip` from `/proc/net/arp`, optionally filtered to `iface`.
pub fn arp_mac(ip: Ipv4Addr, iface: Option<&str>) -> Option<String> {
    let text = std::fs::read_to_string("/proc/net/arp").ok()?;
    parse_arp_table(&text)
        .into_iter()
        .find(|(a, _, dev)| *a == ip && iface.is_none_or(|i| i == dev))
        .map(|(_, mac, _)| mac)
}

/// Extracts `SERVER_ADDRESS=` from a systemd-networkd lease file.
pub fn parse_systemd_lease_server(text: &str) -> Option<Ipv4Addr> {
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some((k, v)) = line.split_once('=')
            && k.trim() == "SERVER_ADDRESS"
        {
            return v.trim().parse().ok();
        }
    }
    None
}

/// DHCP server address for `iface` from `/run/systemd/netif/leases/<ifindex>`, if readable.
pub fn dhcp_server(iface: &str) -> Option<Ipv4Addr> {
    let idx = ifindex_sysfs(iface)?;
    let path = Path::new("/run/systemd/netif/leases").join(idx.to_string());
    let text = std::fs::read_to_string(path).ok()?;
    parse_systemd_lease_server(&text)
}

#[cfg(test)]
mod tests {
    use super::*;

    const ROUTE: &str = "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n\
enp1s0\t00000000\t0101A8C0\t0003\t0\t0\t100\t00000000\t0\t0\t0\n\
wlo1\t00000000\t0100A8C0\t0003\t0\t0\t600\t00000000\t0\t0\t0\n\
wlo1\t0000A8C0\t00000000\t0001\t0\t0\t600\t00FFFFFF\t0\t0\t0\n\
wlo1\t00000000\t0200A8C0\t0003\t0\t0\t900\t00000000\t0\t0\t0\n\
bad line\n";

    #[test]
    fn route_gateway_per_iface() {
        assert_eq!(
            parse_route_gateway(ROUTE, "wlo1"),
            Some(Ipv4Addr::new(192, 168, 0, 1))
        );
        assert_eq!(
            parse_route_gateway(ROUTE, "enp1s0"),
            Some(Ipv4Addr::new(192, 168, 1, 1))
        );
        assert_eq!(parse_route_gateway(ROUTE, "eth9"), None);
        assert_eq!(parse_route_gateway("", "wlo1"), None);
    }

    #[test]
    fn resolv_conf_skips_stub_and_junk() {
        let t = "# comment\nnameserver 127.0.0.53\nnameserver 192.168.0.1\nnameserver ::1\nnameserver\nsearch lan\nnameserver 1.1.1.1 extra\n";
        assert_eq!(
            parse_resolv_conf(t),
            vec![Ipv4Addr::new(192, 168, 0, 1), Ipv4Addr::new(1, 1, 1, 1)]
        );
    }

    #[test]
    fn subnet_and_prefix() {
        assert_eq!(prefix_from_mask(Ipv4Addr::new(255, 255, 255, 0)), 24);
        assert!(in_subnet(
            Ipv4Addr::new(10, 0, 0, 5),
            Ipv4Addr::new(10, 0, 0, 1),
            24
        ));
        assert!(!in_subnet(
            Ipv4Addr::new(10, 0, 0, 1),
            Ipv4Addr::new(192, 168, 0, 1),
            24
        ));
        assert!(in_subnet(
            Ipv4Addr::new(1, 2, 3, 4),
            Ipv4Addr::new(9, 9, 9, 9),
            0
        ));
    }

    #[test]
    fn virtual_names() {
        for n in ["lo", "docker0", "veth12", "br-x", "tun0", "virbr0"] {
            assert!(is_virtual_name(n), "{n}");
        }
        assert!(!is_virtual_name("wlo1"));
        assert!(!valid_name("../x"));
        assert!(!read("does-not-exist0").present);
        assert!(!read("../../etc").present);
        assert!(ifindex_sysfs("../x").is_none());
    }

    #[test]
    fn arp_and_lease_and_cidr_parsing() {
        assert_eq!(subnet_cidr(Ipv4Addr::new(192, 168, 0, 118), 24), "192.168.0.0/24");
        assert_eq!(subnet_cidr(Ipv4Addr::new(10, 20, 30, 40), 0), "0.0.0.0/0");
        let arp = "\
IP address       HW type     Flags       HW address            Mask     Device
192.168.0.1      0x1         0x2         02:00:00:00:00:04     *        wlo1
1.1.1.1          0x1         0x0         00:00:00:00:00:00     *        enp1s0
192.168.0.1      0x1         0x2         02:00:00:00:00:04     *        enp1s0
bad line
";
        let entries = parse_arp_table(arp);
        assert_eq!(
            entries,
            vec![
                (Ipv4Addr::new(192, 168, 0, 1), "02:00:00:00:00:04".into(), "wlo1".into()),
                (Ipv4Addr::new(192, 168, 0, 1), "02:00:00:00:00:04".into(), "enp1s0".into()),
            ]
        );
        let lease = "# comment\nADDRESS=192.168.1.50\nSERVER_ADDRESS=192.168.0.1\n";
        assert_eq!(parse_systemd_lease_server(lease), Some(Ipv4Addr::new(192, 168, 0, 1)));
        assert_eq!(parse_systemd_lease_server("ADDRESS=192.168.1.50\n"), None);
    }

    #[test]
    fn pick_ipv4_prefers_gateway_subnet() {
        let addrs = [
            (Ipv4Addr::new(10, 10, 0, 2), 24),
            (Ipv4Addr::new(192, 168, 0, 250), 24),
        ];
        assert_eq!(
            pick_ipv4(&addrs, Some(Ipv4Addr::new(192, 168, 0, 1))),
            Some((Ipv4Addr::new(192, 168, 0, 250), 24))
        );
        assert_eq!(
            pick_ipv4(&addrs, Some(Ipv4Addr::new(172, 16, 0, 1))),
            Some((Ipv4Addr::new(10, 10, 0, 2), 24))
        );
        assert_eq!(pick_ipv4(&addrs, None), Some((Ipv4Addr::new(10, 10, 0, 2), 24)));
        assert_eq!(pick_ipv4(&[], Some(Ipv4Addr::new(192, 168, 0, 1))), None);
    }
}
