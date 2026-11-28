//! Host-isolation preflight checks (`H3`, `H7`–`H9`, `H13`–`H15`, `H17`, `H19`–`H21`, `H23` in
//! docs/HOST-ISOLATION-SCENARIOS.md): settings and background programs on the measuring host
//! that can look like a Wi-Fi, router or ISP fault.
//!
//! Only reads `/sys` and `/proc` (no root, no subprocesses). Every path is relative to `root`
//! so tests can run against a fake tree.

use crate::check::{Item, Level};
use crate::model::IfaceRole;
use std::path::{Path, PathBuf};

fn item(level: Level, name: impl Into<String>, detail: impl Into<String>, fix: Option<&str>) -> Item {
    Item { level, name: name.into(), detail: detail.into(), fix: fix.map(String::from) }
}

fn read_trim(p: &Path) -> Option<String> {
    std::fs::read_to_string(p).ok().map(|s| s.trim().to_string())
}

fn read_u64(p: &Path) -> Option<u64> {
    read_trim(p)?.parse().ok()
}

/// Inputs from the live probe that a sysfs read cannot give.
#[derive(Debug, Default, Clone)]
pub struct Ctx {
    /// At least one monitored Wi-Fi interface is associated on 2.4 GHz.
    pub wifi_on_24ghz: bool,
    /// Two monitored interfaces share one IPv4 subnet.
    pub shared_subnet: bool,
    /// `[targets] dns_servers` is set (DNS probes do not depend on resolv.conf).
    pub dns_servers_configured: bool,
}

pub fn checks(root: &Path, ifaces: &[(String, IfaceRole)], ctx: &Ctx) -> Vec<Item> {
    let mut out = Vec::new();
    let net = root.join("sys/class/net");
    for (name, role) in ifaces {
        let base = net.join(name);
        if !base.exists() {
            continue;
        }
        if ctx.shared_subnet {
            out.push(rp_filter(root, name));
        }
        if *role == IfaceRole::Ethernet {
            out.extend(wired_phy(&base, name));
        }
        out.extend(bus_power(root, &base, name));
        out.extend(mac_and_mtu(&base, name, *role));
    }
    out.extend(default_routes(root, ifaces));
    out.extend(local_resolver(root, ctx));
    out.extend(tunnels(&net, ifaces));
    out.extend(conntrack(root));
    out.extend(net_managers(root));
    out.extend(rfkill(root, ifaces, ctx));
    out
}

/// H8: Linux uses `max(conf/all, conf/<if>)` for `rp_filter`; strict (1) drops replies that
/// arrive on the second interface of a shared subnet.
fn rp_filter(root: &Path, iface: &str) -> Item {
    let conf = root.join("proc/sys/net/ipv4/conf");
    let all = read_u64(&conf.join("all/rp_filter")).unwrap_or(0);
    let dev = read_u64(&conf.join(iface).join("rp_filter")).unwrap_or(0);
    let eff = all.max(dev);
    item(
        if eff == 1 { Level::Fail } else { Level::Ok },
        format!("rp_filter {iface}"),
        format!("effective {eff} (all={all}, {iface}={dev})"),
        (eff == 1).then_some("strict mode drops replies on the second interface; set net.ipv4.conf.all.rp_filter=2 and the per-interface value to 0 or 2"),
    )
}

/// H9: a loose cable or bad jack renegotiates down or produces CRC errors; the wired reference
/// path then looks like a router fault.
fn wired_phy(base: &Path, iface: &str) -> Vec<Item> {
    let mut out = Vec::new();
    let speed = read_trim(&base.join("speed")).and_then(|s| s.parse::<i64>().ok());
    let duplex = read_trim(&base.join("duplex"));
    if let (Some(speed), Some(duplex)) = (speed, duplex.as_deref()) {
        if speed > 0 {
            let half = duplex != "full";
            let slow = speed < 1000;
            out.push(item(
                if half { Level::Fail } else if slow { Level::Warn } else { Level::Ok },
                format!("cable {iface}"),
                format!("{speed} Mbit/s, {duplex} duplex"),
                if half {
                    Some("half duplex means a bad cable or port; replace the patch cable or try another router port")
                } else if slow {
                    Some("100 Mbit/s on a gigabit NIC usually means a damaged cable pair; ignore if the router port is 100 Mbit/s")
                } else {
                    None
                },
            ));
        }
    }
    let stats = base.join("statistics");
    let crc = read_u64(&stats.join("rx_crc_errors")).unwrap_or(0);
    let frame = read_u64(&stats.join("rx_frame_errors")).unwrap_or(0);
    let changes = read_u64(&base.join("carrier_changes")).unwrap_or(0);
    let bad = crc + frame > 0;
    out.push(item(
        if bad { Level::Warn } else { Level::Ok },
        format!("nic errors {iface}"),
        format!("rx_crc_errors={crc} rx_frame_errors={frame} carrier_changes={changes} (since boot)"),
        bad.then_some("CRC/frame errors point to the cable, the jack or the NIC; replace the cable before a long run"),
    ));
    out
}

/// Bus type of the device behind a netdev: "usb", "pci", or other.
fn bus_of(base: &Path) -> Option<String> {
    let sub = std::fs::read_link(base.join("device/subsystem")).ok()?;
    sub.file_name().map(|s| s.to_string_lossy().into_owned())
}

/// H3 / H20: USB autosuspend and PCIe runtime power management add wake-up latency and
/// short carrier drops even when `iw power_save` is off.
fn bus_power(root: &Path, base: &Path, iface: &str) -> Option<Item> {
    let bus = bus_of(base)?;
    // A USB netdev's `device` is the USB interface; power control lives on its parent device.
    let ctl: PathBuf = match bus.as_str() {
        "usb" => base.join("device/../power/control"),
        "pci" => base.join("device/power/control"),
        _ => return None,
    };
    let v = read_trim(&ctl)?;
    let auto = v == "auto";
    let fix = if bus == "usb" {
        "USB autosuspend can drop carrier for seconds: echo on > /sys/class/net/<if>/device/../power/control, or boot with usbcore.autosuspend=-1"
    } else {
        "PCIe runtime PM adds wake-up jitter: echo on > /sys/class/net/<if>/device/power/control (and consider pcie_aspm=off)"
    };
    let mut detail = format!("{bus} power/control={v}");
    if bus == "pci" {
        if let Some(p) = read_trim(&root.join("sys/module/pcie_aspm/parameters/policy")).as_deref().and_then(aspm_policy) {
            detail.push_str(&format!(", aspm {p}"));
        }
    }
    Some(item(if auto { Level::Warn } else { Level::Ok }, format!("bus power {iface}"), detail, auto.then_some(fix)))
}

/// The active policy is the bracketed word: `[default] performance powersave`.
fn aspm_policy(text: &str) -> Option<&str> {
    text.split_whitespace().find_map(|w| w.strip_prefix('[')?.strip_suffix(']'))
}

/// H19 / H21: a random MAC re-keys DHCP/ARP on the router; a small MTU breaks big packets
/// while small ICMP probes still pass.
fn mac_and_mtu(base: &Path, iface: &str, role: IfaceRole) -> Vec<Item> {
    let mut out = Vec::new();
    // 0 = permanent, 1 = random, 2 = stolen, 3 = set by user.
    if let Some(t) = read_trim(&base.join("addr_assign_type")) {
        if t == "1" {
            out.push(item(
                Level::Warn,
                format!("mac {iface}"),
                "random MAC address (addr_assign_type=1)",
                Some(if role == IfaceRole::Wifi {
                    "a changing MAC resets DHCP/ARP on the router and splits device counts; set NetworkManager wifi.cloned-mac-address=permanent for this network"
                } else {
                    "a changing MAC resets DHCP/ARP on the router; set ethernet.cloned-mac-address=permanent"
                }),
            ));
        }
    }
    if let Some(mtu) = read_u64(&base.join("mtu")) {
        if mtu < 1500 {
            out.push(item(
                Level::Warn,
                format!("mtu {iface}"),
                format!("{mtu} (< 1500)"),
                Some("small probes pass but large TCP/DNS packets may be dropped; check PPPoE/VPN settings or set MTU 1500"),
            ));
        }
    }
    out
}

/// Default routes `(iface, metric)` from `/proc/net/route`.
fn parse_default_routes(text: &str) -> Vec<(String, u32)> {
    text.lines()
        .skip(1)
        .filter_map(|l| {
            let f: Vec<&str> = l.split_whitespace().collect();
            // Iface Destination Gateway Flags RefCnt Use Metric Mask ...
            (f.len() >= 8 && f[1] == "00000000" && f[7] == "00000000").then(|| (f[0].to_string(), f[6].parse().unwrap_or(0)))
        })
        .collect()
}

/// H21: two default routes with the same metric let the kernel move unbound traffic (and the
/// host's own downloads) between interfaces during a run.
fn default_routes(root: &Path, ifaces: &[(String, IfaceRole)]) -> Option<Item> {
    let text = std::fs::read_to_string(root.join("proc/net/route")).ok()?;
    let mut routes = parse_default_routes(&text);
    if routes.len() < 2 {
        return None;
    }
    routes.sort_by_key(|(_, m)| *m);
    let tie = routes.windows(2).any(|w| w[0].1 == w[1].1 && w[0].0 != w[1].0);
    let list: Vec<String> = routes.iter().map(|(i, m)| format!("{i}={m}")).collect();
    let primary = &routes[0].0;
    let monitored = ifaces.iter().any(|(n, _)| n == primary);
    Some(item(
        if tie { Level::Warn } else { Level::Ok },
        "default routes",
        format!("metrics {}{}", list.join(", "), if monitored { String::new() } else { format!("; primary {primary} is not monitored") }),
        tie.then_some("give each default route its own metric (e.g. Ethernet 100, Wi-Fi 600) so the host's own traffic does not jump between paths"),
    ))
}

/// H14: a local caching resolver (127.0.0.x) hides the upstream DNS server.
fn local_resolver(root: &Path, ctx: &Ctx) -> Option<Item> {
    let text = std::fs::read_to_string(root.join("etc/resolv.conf")).ok()?;
    let servers: Vec<std::net::IpAddr> = text
        .lines()
        .filter_map(|l| {
            let mut it = l.split_whitespace();
            (it.next() == Some("nameserver")).then(|| it.next()).flatten()
        })
        .filter_map(|s| s.parse().ok())
        .collect();
    let local = !servers.is_empty() && servers.iter().all(|a| a.is_loopback());
    if !local {
        return Some(item(Level::Ok, "dns resolver", format!("{} server(s) in resolv.conf", servers.len()), None));
    }
    let resolved_upstream = root.join("run/systemd/resolve/resolv.conf").exists();
    let warn = !resolved_upstream && !ctx.dns_servers_configured;
    Some(item(
        if warn { Level::Warn } else { Level::Ok },
        "dns resolver",
        if resolved_upstream {
            "local stub (systemd-resolved); probes use its upstream servers".to_string()
        } else if ctx.dns_servers_configured {
            "local resolver; probes use [targets] dns_servers".to_string()
        } else {
            "only a local resolver (dnsmasq/AdGuard/Pi-hole/dnscrypt?) and no upstream list".to_string()
        },
        warn.then_some("DNS probes are skipped or test only the local cache; set [targets] dns_servers to the router or ISP resolvers"),
    ))
}

/// H7: tunnel or VPN interfaces can take the default route away from the physical path.
fn tunnels(net: &Path, monitored: &[(String, IfaceRole)]) -> Option<Item> {
    let entries = std::fs::read_dir(net).ok()?;
    let mut found: Vec<String> = entries
        .filter_map(|e| e.ok())
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| !monitored.iter().any(|(m, _)| m == n))
        .filter(|n| {
            ["tun", "tap", "wg", "tailscale", "ppp", "zt", "nordlynx", "proton", "ipsec", "vti", "gpd"]
                .iter()
                .any(|p| n.starts_with(p))
        })
        .filter(|n| read_trim(&net.join(n).join("operstate")).is_none_or(|s| s != "down"))
        .collect();
    found.sort();
    Some(if found.is_empty() {
        item(Level::Ok, "vpn / tunnels", "none active", None)
    } else {
        item(
            Level::Warn,
            "vpn / tunnels",
            format!("active: {}", found.join(", ")),
            Some("a VPN can carry the internet probes instead of the monitored interface; stop it during the run or check `ip route get 1.1.1.1`"),
        )
    })
}

/// H15: a full conntrack table drops new flows silently inside the host kernel.
fn conntrack(root: &Path) -> Option<Item> {
    let nf = root.join("proc/sys/net/netfilter");
    let count = read_u64(&nf.join("nf_conntrack_count"))?;
    let max = read_u64(&nf.join("nf_conntrack_max")).filter(|m| *m > 0)?;
    let pct = count as f64 * 100.0 / max as f64;
    let net = root.join("sys/class/net");
    let mut virt: Vec<String> = std::fs::read_dir(&net)
        .map(|d| {
            d.filter_map(|e| e.ok())
                .map(|e| e.file_name().to_string_lossy().into_owned())
                .filter(|n| ["docker", "br-", "virbr", "podman", "cni", "lxc", "lxdbr", "veth"].iter().any(|p| n.starts_with(p)))
                .collect()
        })
        .unwrap_or_default();
    virt.sort();
    let veths = virt.iter().filter(|n| n.starts_with("veth")).count();
    virt.retain(|n| !n.starts_with("veth"));
    let mut detail = format!("{count}/{max} ({pct:.0}%)");
    if !virt.is_empty() || veths > 0 {
        detail.push_str(&format!("; container bridges: {}", virt.join(", ")));
        if veths > 0 {
            detail.push_str(&format!(" +{veths} veth"));
        }
    }
    let lvl = if pct >= 90.0 { Level::Fail } else if pct >= 70.0 { Level::Warn } else { Level::Ok };
    Some(item(
        lvl,
        "conntrack",
        detail,
        (lvl != Level::Ok).then_some("the host firewall table is almost full and drops new connections; raise net.netfilter.nf_conntrack_max or stop the busy service"),
    ))
}

/// Process names of a running `/proc` tree.
fn process_names(root: &Path) -> Vec<String> {
    let Ok(d) = std::fs::read_dir(root.join("proc")) else { return Vec::new() };
    d.filter_map(|e| e.ok())
        .filter(|e| e.file_name().to_string_lossy().bytes().all(|b| b.is_ascii_digit()))
        .filter_map(|e| read_trim(&e.path().join("comm")))
        .collect()
}

/// H13: two network managers fight over routes and DHCP leases (2–5 s gaps).
fn net_managers(root: &Path) -> Option<Item> {
    let procs = process_names(root);
    const MANAGERS: [(&str, &str); 6] = [
        ("NetworkManager", "NetworkManager"),
        ("systemd-network", "systemd-networkd"),
        ("dhcpcd", "dhcpcd"),
        ("connmand", "connman"),
        ("dhclient", "dhclient"),
        ("netplan", "netplan"),
    ];
    let found: Vec<&str> = MANAGERS.iter().filter(|(comm, _)| procs.iter().any(|p| p == comm)).map(|(_, n)| *n).collect();
    if procs.is_empty() {
        return None;
    }
    // NetworkManager starts dhclient itself in some setups; that pair is not a conflict.
    let conflict = found.iter().filter(|n| **n != "dhclient").count() >= 2;
    Some(item(
        if conflict { Level::Warn } else { Level::Ok },
        "network managers",
        if found.is_empty() { "none detected".into() } else { found.join(", ") },
        conflict.then_some("two managers can re-apply routes or renew DHCP at random; make sure each interface is managed by only one of them"),
    ))
}

/// H17 / H23: a soft-blocked radio, or Bluetooth active on a Wi-Fi+BT combo card at 2.4 GHz.
fn rfkill(root: &Path, ifaces: &[(String, IfaceRole)], ctx: &Ctx) -> Vec<Item> {
    let mut out = Vec::new();
    let Ok(d) = std::fs::read_dir(root.join("sys/class/rfkill")) else { return out };
    let mut bt_on = false;
    let mut wlan_blocked = Vec::new();
    for e in d.filter_map(|e| e.ok()) {
        let p = e.path();
        let kind = read_trim(&p.join("type")).unwrap_or_default();
        let soft = read_trim(&p.join("soft")).is_some_and(|s| s == "1");
        let hard = read_trim(&p.join("hard")).is_some_and(|s| s == "1");
        match kind.as_str() {
            "bluetooth" if !soft && !hard => bt_on = true,
            "wlan" if soft || hard => wlan_blocked.push(format!("{}{}", read_trim(&p.join("name")).unwrap_or_default(), if hard { " (hard)" } else { "" })),
            _ => {}
        }
    }
    let has_wifi = ifaces.iter().any(|(_, r)| *r == IfaceRole::Wifi);
    if has_wifi && !wlan_blocked.is_empty() {
        out.push(item(Level::Fail, "rfkill wlan", format!("blocked: {}", wlan_blocked.join(", ")), Some("rfkill unblock wifi (a hard block is a physical switch or BIOS setting)")));
    }
    if has_wifi && bt_on {
        out.push(item(
            if ctx.wifi_on_24ghz { Level::Warn } else { Level::Ok },
            "bluetooth",
            if ctx.wifi_on_24ghz { "radio on while Wi-Fi uses 2.4 GHz" } else { "radio on (Wi-Fi is not on 2.4 GHz)" },
            ctx.wifi_on_24ghz.then_some("combo Wi-Fi+BT cards share the 2.4 GHz antenna and add 50-150 ms RTT spikes; run `rfkill block bluetooth` during the test"),
        ));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn tree() -> PathBuf {
        let d = std::env::temp_dir().join(format!("lw-hostcheck-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&d).unwrap();
        d
    }

    fn w(root: &Path, rel: &str, v: &str) {
        let p = root.join(rel);
        fs::create_dir_all(p.parent().unwrap()).unwrap();
        fs::write(p, v).unwrap();
    }

    fn find<'a>(items: &'a [Item], name: &str) -> &'a Item {
        items.iter().find(|i| i.name == name).unwrap_or_else(|| panic!("no item {name}"))
    }

    #[test]
    fn rp_filter_uses_max_of_all_and_dev() {
        let r = tree();
        w(&r, "sys/class/net/wlo1/mtu", "1500");
        w(&r, "proc/sys/net/ipv4/conf/all/rp_filter", "0");
        w(&r, "proc/sys/net/ipv4/conf/wlo1/rp_filter", "1");
        let items = checks(&r, &[("wlo1".into(), IfaceRole::Wifi)], &Ctx { shared_subnet: true, ..Default::default() });
        assert_eq!(find(&items, "rp_filter wlo1").level, Level::Fail);
        w(&r, "proc/sys/net/ipv4/conf/all/rp_filter", "2");
        let items = checks(&r, &[("wlo1".into(), IfaceRole::Wifi)], &Ctx { shared_subnet: true, ..Default::default() });
        assert_eq!(find(&items, "rp_filter wlo1").level, Level::Ok);
        let _ = fs::remove_dir_all(r);
    }

    #[test]
    fn wired_half_duplex_and_crc() {
        let r = tree();
        w(&r, "sys/class/net/enp1s0/speed", "100");
        w(&r, "sys/class/net/enp1s0/duplex", "half");
        w(&r, "sys/class/net/enp1s0/statistics/rx_crc_errors", "12");
        w(&r, "sys/class/net/enp1s0/carrier_changes", "4");
        let items = checks(&r, &[("enp1s0".into(), IfaceRole::Ethernet)], &Ctx::default());
        assert_eq!(find(&items, "cable enp1s0").level, Level::Fail);
        assert_eq!(find(&items, "nic errors enp1s0").level, Level::Warn);
        w(&r, "sys/class/net/enp1s0/speed", "1000");
        w(&r, "sys/class/net/enp1s0/duplex", "full");
        w(&r, "sys/class/net/enp1s0/statistics/rx_crc_errors", "0");
        let items = checks(&r, &[("enp1s0".into(), IfaceRole::Ethernet)], &Ctx::default());
        assert_eq!(find(&items, "cable enp1s0").level, Level::Ok);
        assert_eq!(find(&items, "nic errors enp1s0").level, Level::Ok);
        let _ = fs::remove_dir_all(r);
    }

    #[test]
    fn random_mac_small_mtu_and_tunnels() {
        let r = tree();
        w(&r, "sys/class/net/wlo1/addr_assign_type", "1");
        w(&r, "sys/class/net/wlo1/mtu", "1400");
        w(&r, "sys/class/net/wg0/operstate", "unknown");
        w(&r, "sys/class/net/tun0/operstate", "down");
        let items = checks(&r, &[("wlo1".into(), IfaceRole::Wifi)], &Ctx::default());
        assert_eq!(find(&items, "mac wlo1").level, Level::Warn);
        assert_eq!(find(&items, "mtu wlo1").level, Level::Warn);
        let t = find(&items, "vpn / tunnels");
        assert_eq!(t.level, Level::Warn);
        assert!(t.detail.contains("wg0") && !t.detail.contains("tun0"), "{}", t.detail);
        let _ = fs::remove_dir_all(r);
    }

    #[test]
    fn conntrack_levels_and_bridges() {
        let r = tree();
        w(&r, "sys/class/net/docker0/mtu", "1500");
        w(&r, "sys/class/net/veth12ab/mtu", "1500");
        w(&r, "proc/sys/net/netfilter/nf_conntrack_count", "950");
        w(&r, "proc/sys/net/netfilter/nf_conntrack_max", "1000");
        let items = checks(&r, &[], &Ctx::default());
        let c = find(&items, "conntrack");
        assert_eq!(c.level, Level::Fail);
        assert!(c.detail.contains("docker0") && c.detail.contains("+1 veth"), "{}", c.detail);
        w(&r, "proc/sys/net/netfilter/nf_conntrack_count", "10");
        assert_eq!(find(&checks(&r, &[], &Ctx::default()), "conntrack").level, Level::Ok);
        let _ = fs::remove_dir_all(r);
    }

    #[test]
    fn two_network_managers_warn() {
        let r = tree();
        w(&r, "proc/101/comm", "NetworkManager\n");
        w(&r, "proc/102/comm", "dhclient\n");
        assert_eq!(find(&checks(&r, &[], &Ctx::default()), "network managers").level, Level::Ok);
        w(&r, "proc/103/comm", "systemd-network\n");
        let n = checks(&r, &[], &Ctx::default());
        let n = find(&n, "network managers");
        assert_eq!(n.level, Level::Warn);
        assert!(n.detail.contains("systemd-networkd"));
        let _ = fs::remove_dir_all(r);
    }

    #[test]
    fn rfkill_bluetooth_and_blocked_wlan() {
        let r = tree();
        w(&r, "sys/class/net/wlo1/mtu", "1500");
        w(&r, "sys/class/rfkill/rfkill0/type", "bluetooth");
        w(&r, "sys/class/rfkill/rfkill0/soft", "0");
        w(&r, "sys/class/rfkill/rfkill0/hard", "0");
        w(&r, "sys/class/rfkill/rfkill1/type", "wlan");
        w(&r, "sys/class/rfkill/rfkill1/name", "phy0");
        w(&r, "sys/class/rfkill/rfkill1/soft", "1");
        w(&r, "sys/class/rfkill/rfkill1/hard", "0");
        let wifi = [("wlo1".to_string(), IfaceRole::Wifi)];
        let items = checks(&r, &wifi, &Ctx { wifi_on_24ghz: true, ..Default::default() });
        assert_eq!(find(&items, "bluetooth").level, Level::Warn);
        assert_eq!(find(&items, "rfkill wlan").level, Level::Fail);
        let items = checks(&r, &wifi, &Ctx::default());
        assert_eq!(find(&items, "bluetooth").level, Level::Ok);
        let _ = fs::remove_dir_all(r);
    }

    #[test]
    fn equal_default_route_metrics_warn() {
        let r = tree();
        let hdr = "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT\n";
        w(&r, "proc/net/route", &format!("{hdr}enp1s0\t00000000\t0100A8C0\t0003\t0\t0\t100\t00000000\t0\t0\t0\nwlo1\t00000000\t0100A8C0\t0003\t0\t0\t100\t00000000\t0\t0\t0\nwlo1\t0000A8C0\t00000000\t0001\t0\t0\t600\t00FFFFFF\t0\t0\t0\n"));
        let ifs = [("wlo1".to_string(), IfaceRole::Wifi), ("enp1s0".to_string(), IfaceRole::Ethernet)];
        assert_eq!(find(&checks(&r, &ifs, &Ctx::default()), "default routes").level, Level::Warn);
        w(&r, "proc/net/route", &format!("{hdr}enp1s0\t00000000\t0100A8C0\t0003\t0\t0\t100\t00000000\t0\t0\t0\nwlo1\t00000000\t0100A8C0\t0003\t0\t0\t600\t00000000\t0\t0\t0\n"));
        let items = checks(&r, &ifs, &Ctx::default());
        let d = find(&items, "default routes");
        assert_eq!(d.level, Level::Ok);
        assert_eq!(d.detail, "metrics enp1s0=100, wlo1=600");
        let _ = fs::remove_dir_all(r);
    }

    #[test]
    fn local_resolver_without_upstream_warns() {
        let r = tree();
        w(&r, "etc/resolv.conf", "nameserver 127.0.0.1\n");
        assert_eq!(find(&checks(&r, &[], &Ctx::default()), "dns resolver").level, Level::Warn);
        let ctx = Ctx { dns_servers_configured: true, ..Default::default() };
        assert_eq!(find(&checks(&r, &[], &ctx), "dns resolver").level, Level::Ok);
        w(&r, "run/systemd/resolve/resolv.conf", "nameserver 192.168.0.1\n");
        assert_eq!(find(&checks(&r, &[], &Ctx::default()), "dns resolver").level, Level::Ok);
        let _ = fs::remove_dir_all(r);
    }

    #[test]
    fn aspm_policy_is_bracketed_word() {
        assert_eq!(aspm_policy("[default] performance powersave"), Some("default"));
        assert_eq!(aspm_policy("default performance [powersupersave]"), Some("powersupersave"));
        assert_eq!(aspm_policy("garbage"), None);
    }

    #[cfg(unix)]
    #[test]
    fn usb_autosuspend_warns() {
        let r = tree();
        // sys/class/net/wlx0/device -> usb interface dir; its parent holds power/control.
        w(&r, "sys/bus/usb/devices/1-1/power/control", "auto");
        fs::create_dir_all(r.join("sys/bus/usb/devices/1-1/1-1:1.0")).unwrap();
        fs::create_dir_all(r.join("sys/bus/usb_sub/usb")).unwrap();
        std::os::unix::fs::symlink(r.join("sys/bus/usb_sub/usb"), r.join("sys/bus/usb/devices/1-1/1-1:1.0/subsystem")).unwrap();
        fs::create_dir_all(r.join("sys/class/net/wlx0")).unwrap();
        std::os::unix::fs::symlink(r.join("sys/bus/usb/devices/1-1/1-1:1.0"), r.join("sys/class/net/wlx0/device")).unwrap();
        let items = checks(&r, &[("wlx0".into(), IfaceRole::Wifi)], &Ctx::default());
        let b = find(&items, "bus power wlx0");
        assert_eq!(b.level, Level::Warn);
        assert!(b.detail.starts_with("usb"), "{}", b.detail);
        let _ = fs::remove_dir_all(r);
    }
}
