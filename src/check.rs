//! `linkwatch check`: preflight before a multi-night run. Prints one line per check
//! and an explanation how to fix each problem. Exit code 1 when any check fails.

use crate::config::Config;
use crate::model::IfaceRole;
use crate::{host, link, probe, run, wifi};
use std::time::Duration;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Level {
    Ok,
    Warn,
    Fail,
}

pub struct Item {
    pub level: Level,
    pub name: String,
    pub detail: String,
    pub fix: Option<String>,
}

fn item(level: Level, name: impl Into<String>, detail: impl Into<String>, fix: Option<&str>) -> Item {
    Item { level, name: name.into(), detail: detail.into(), fix: fix.map(String::from) }
}

fn read_trim(p: &str) -> Option<String> {
    std::fs::read_to_string(p).ok().map(|s| s.trim().to_string())
}

pub async fn check(cfg: &Config) -> Vec<Item> {
    let mut out = Vec::new();
    let ifaces = run::resolve_ifaces(cfg);
    if ifaces.is_empty() {
        out.push(item(Level::Fail, "interfaces", "no interfaces found", Some("list them under [[interfaces]] in the config")));
        return out;
    }

    // Unprivileged ICMP.
    let gid = nix::unistd::getgid().as_raw();
    match read_trim("/proc/sys/net/ipv4/ping_group_range") {
        Some(r) => {
            let mut it = r.split_whitespace().filter_map(|x| x.parse::<u64>().ok());
            let (lo, hi) = (it.next().unwrap_or(1), it.next().unwrap_or(0));
            let ok = (lo..=hi).contains(&(gid as u64)) || nix::unistd::geteuid().is_root();
            out.push(item(
                if ok { Level::Ok } else { Level::Fail },
                "icmp permission",
                format!("ping_group_range {r}, gid {gid}"),
                (!ok).then_some("sysctl -w net.ipv4.ping_group_range='0 2147483647' (see deploy/90-linkwatch.conf)"),
            ));
        }
        None => out.push(item(Level::Warn, "icmp permission", "cannot read ping_group_range", None)),
    }

    // Interfaces, links, a real probe on each.
    let mut subnets = Vec::new();
    let mut first_gw = None;
    for (name, role) in &ifaces {
        let l = link::read(name);
        let label = format!("iface {name} ({role:?})");
        if !l.present {
            out.push(item(Level::Fail, label, "not present", Some("check the name with `ip link`")));
            continue;
        }
        if !l.carrier {
            let fix = if *role == IfaceRole::Wifi { "connect Wi-Fi to the network under test" } else { "plug the cable into a router LAN port" };
            out.push(item(Level::Warn, label, "no carrier / not associated", Some(fix)));
            continue;
        }
        let Some(ip) = l.ipv4 else {
            out.push(item(Level::Fail, label, "no IPv4 address", Some("enable DHCP on this interface")));
            continue;
        };
        if let (Some(p), true) = (l.prefix_len, true) {
            subnets.push((name.clone(), u32::from(ip) & (u32::MAX.checked_shl(32 - p as u32).unwrap_or(0))));
        }
        match l.gateway.or(cfg.targets.gateway) {
            Some(gw) => {
                if first_gw.is_none() {
                    first_gw = Some(gw);
                }
                let r = probe::icmp::ping(name, gw, Duration::from_millis(900)).await;
                out.push(item(
                    if r.ok { Level::Ok } else { Level::Fail },
                    label,
                    format!("{ip}, gateway {gw}: {}", if r.ok { format!("{:.1} ms", r.rtt_ms.unwrap_or(0.0)) } else { r.err.unwrap_or_default() }),
                    (!r.ok).then_some("if error is 'permission', see icmp permission; otherwise the router does not answer on this path"),
                ));
            }
            None => out.push(item(Level::Warn, label, format!("{ip}, no default route on this interface"), Some("the monitor needs a gateway per interface (a route with a higher metric is enough)"))),
        }
    }

    // Two interfaces in one subnet: ARP flux would mix up the paths.
    let mut same = false;
    for i in 0..subnets.len() {
        for j in i + 1..subnets.len() {
            same |= subnets[i].1 == subnets[j].1;
        }
    }
    if same {
        let ai = read_trim("/proc/sys/net/ipv4/conf/all/arp_ignore").unwrap_or_default();
        let aa = read_trim("/proc/sys/net/ipv4/conf/all/arp_announce").unwrap_or_default();
        let ok = ai == "1" && aa == "2";
        out.push(item(
            if ok { Level::Ok } else { Level::Fail },
            "arp (same subnet)",
            format!("arp_ignore={ai} arp_announce={aa}"),
            (!ok).then_some("install deploy/90-linkwatch.conf to /etc/sysctl.d and run `sysctl --system` (done by install.sh)"),
        ));
        let rp = read_trim("/proc/sys/net/ipv4/conf/all/rp_filter").unwrap_or_default();
        out.push(item(if rp == "1" { Level::Fail } else { Level::Ok }, "rp_filter", rp, Some("strict mode (1) drops replies on the second interface; use 2")));
    }

    // Wi-Fi via nl80211.
    for (name, role) in ifaces.iter().filter(|(_, r)| *r == IfaceRole::Wifi) {
        let _ = role;
        match wifi::Nl80211::open().and_then(|mut nl| nl.station(name).map(|s| (s, nl))) {
            Ok((st, mut nl)) => {
                out.push(item(
                    Level::Ok,
                    format!("wifi {name}"),
                    format!("ssid {:?}, {:?} MHz, signal {:?} dBm", st.ssid, st.freq_mhz, st.signal_dbm),
                    None,
                ));
                if st.power_save == Some(true) {
                    out.push(item(
                        Level::Warn,
                        format!("wifi power_save {name}"),
                        "power_save is ON (adds RTT jitter)",
                        Some(&format!("sudo iw dev {name} set power_save off (or set NetworkManager wifi.powersave = 2)")),
                    ));
                }
                let scan = nl.trigger_scan(name);
                out.push(item(
                    if scan.is_ok() { Level::Ok } else { Level::Warn },
                    format!("wifi scan {name}"),
                    match &scan { Ok(()) => "allowed".into(), Err(e) => format!("{e:#}") },
                    scan.is_err().then_some("needs CAP_NET_ADMIN (the systemd service has it); without it only cached scan results are used"),
                ));
            }
            Err(e) => out.push(item(Level::Warn, format!("wifi {name}"), format!("{e:#}"), Some("Wi-Fi statistics will be missing"))),
        }
    }

    // Storage.
    let dd = &cfg.data_dir;
    match std::fs::create_dir_all(dd).and_then(|_| tempfile_probe(dd)) {
        Ok(free) => {
            let lvl = if free < cfg.storage.min_free_bytes { Level::Warn } else { Level::Ok };
            out.push(item(lvl, "data dir", format!("{} writable, {:.1} GB free", dd.display(), free as f64 / 1e9), (lvl != Level::Ok).then_some("free space or set data_dir elsewhere")));
        }
        Err(e) => out.push(item(Level::Fail, "data dir", format!("{}: {e}", dd.display()), Some("create it and give the service user write access, or set data_dir"))),
    }

    // Time sync matters for correlating with router logs and multi-observer compare.
    let sync = host::clock_sync_source();
    out.push(item(
        if sync.is_some() { Level::Ok } else { Level::Warn },
        "clock",
        match sync {
            Some(src) => format!("NTP synchronized ({src})"),
            None => "sync state unknown".into(),
        },
        sync.is_none().then_some("enable chrony or systemd-timesyncd; timestamps are compared across observers and router logs"),
    ));

    // Web port.
    if cfg.web.enabled {
        match std::net::TcpListener::bind(cfg.web.listen) {
            Ok(_) => out.push(item(Level::Ok, "web port", cfg.web.listen.to_string(), None)),
            Err(e) => out.push(item(Level::Warn, "web port", format!("{}: {e}", cfg.web.listen), Some("change [web] listen; the monitor still runs without the UI"))),
        }
    }

    // Optional router LAN ports + UPnP IGD reachability.
    if let Some(gw) = first_gw {
        let ports = crate::router_audit::probe_gateway_ports(gw).await;
        let high: Vec<String> = ports.iter().filter(|p| p.open && p.risk == "high").map(|p| format!("{} ({})", p.port, p.service)).collect();
        let open_list: Vec<String> = ports.iter().filter(|p| p.open).map(|p| format!("{}/{}", p.port, p.service)).collect();
        if !high.is_empty() {
            out.push(item(
                Level::Warn,
                "gateway ports",
                format!("{gw} insecure open: {}", high.join(", ")),
                Some("disable Telnet/FTP in router administration settings"),
            ));
        } else {
            out.push(item(
                Level::Ok,
                "gateway ports",
                if open_list.is_empty() { format!("{gw}: no tested admin ports open") } else { format!("{gw} open: {}", open_list.join(", ")) },
                None,
            ));
        }
        if cfg.router.enabled && cfg.router.upnp {
            match crate::router::probe_upnp_meta(gw, cfg.router.upnp_url.as_deref()).await {
                Ok(m) => out.push(item(
                    Level::Ok,
                    "router UPnP",
                    format!("{} {} ({})", m.vendor.as_deref().unwrap_or("IGD"), m.model.as_deref().unwrap_or("router"), m.wan_status.as_deref().unwrap_or("ok")),
                    None,
                )),
                Err(e) => out.push(item(
                    Level::Warn,
                    "router UPnP",
                    format!("{gw}: {e}"),
                    Some("enable UPnP IGD on the router or set explicit [router] upnp_url"),
                )),
            }
        }
    }
    out
}

fn tempfile_probe(dir: &std::path::Path) -> std::io::Result<u64> {
    let p = dir.join(".linkwatch-write-test");
    std::fs::write(&p, b"x")?;
    std::fs::remove_file(&p)?;
    crate::store::free_bytes(dir).ok_or_else(|| std::io::Error::other("statvfs failed"))
}

pub fn print(items: &[Item]) -> bool {
    let mut ok = true;
    for i in items {
        let tag = match i.level {
            Level::Ok => "  ok ",
            Level::Warn => "WARN ",
            Level::Fail => "FAIL ",
        };
        println!("{tag} {:<22} {}", i.name, i.detail);
        if let (Some(f), true) = (&i.fix, i.level != Level::Ok) {
            println!("      {:<22} fix: {f}", "");
        }
        ok &= i.level != Level::Fail;
    }
    ok
}
